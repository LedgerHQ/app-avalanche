/*******************************************************************************
*   (c) 2018-2024 Zondax AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
use core::mem::MaybeUninit;

use crate::handlers::resources::{EthAccessors, ETH_UI};
use crate::parser::{ETH_MAINNET_ID, NONE_CHAIN_ID};
use crate::{handlers::eth::EthUi, parser::ParserError};
use bolos::{
    crypto::{bip32::BIP32Path, ecfp256::ECCInfo},
    hash::{Hasher, Keccak},
};
use zemu_sys::{Show, ViewError, Viewable};

use crate::{
    constants::{ApduError as Error, MAX_BIP32_PATH_DEPTH},
    crypto::{Curve, ECCInfoFlags},
    dispatcher::ApduHandler,
    handlers::resources::{
        StreamingAccessors, BUFFER, EXPECTED_BYTES, IS_LEGACY_TX, PATH, RECEIVED_BYTES,
        STREAMING_CHAIN_ID, STREAMING_HASHER, STREAMING_MODE, STREAMING_TAIL,
        STREAMING_TAIL_CAPACITY, STREAMING_TAIL_LEN, STREAMING_TX_TYPE,
    },
    parser::{
        bytes_to_u64, is_avax_chain_bytes, parse_rlp_item, DisplayableItem, EthTransaction,
        FromBytes, EIP1559_TX, EIP2930_TX, U32_SIZE, U64_SIZE,
    },
    sys,
    utils::{convert_der_to_rs, is_app_mode_blind_sign, ApduBufferRead},
};

use super::utils::get_tx_rlp_len;
use super::utils::parse_bip32_eth;
use super::verify_coreth_root_path;

/// Right-align a big-endian chain ID slice into a fixed 8-byte array, matching
/// `bytes_to_u64`'s layout. Right-alignment is required so chain IDs whose low
/// byte is zero (e.g. 256 = [0x01, 0x00]) survive the round trip — left-aligning
/// and then trimming trailing zeros would collapse them to a different value.
fn chain_id_to_array(chain_id_slice: &[u8]) -> Option<[u8; 8]> {
    if chain_id_slice.is_empty() {
        return None;
    }
    let mut array = [0u8; 8];
    let len = core::cmp::min(chain_id_slice.len(), 8);
    let src_start = chain_id_slice.len() - len;
    array[8 - len..].copy_from_slice(&chain_id_slice[src_start..]);
    Some(array)
}

pub struct Sign;

/// Check a chain ID with the rules the normal-mode parsers apply
fn checked_chain_id(id: &[u8], legacy: bool) -> Result<[u8; 8], ParserError> {
    if id.is_empty() || id.len() > U64_SIZE {
        return Err(ParserError::InvalidChainId);
    }

    // legacy wallets that do not follow EIP-155 may append the mainnet V
    // (1 * 2 + 35) instead of the chain ID
    let chain_id = bytes_to_u64(id)?;
    if chain_id == NONE_CHAIN_ID
        || chain_id == ETH_MAINNET_ID
        || (legacy && chain_id == ETH_MAINNET_ID * 2 + 35)
    {
        return Err(ParserError::InvalidChainId);
    }

    chain_id_to_array(id).ok_or(ParserError::InvalidChainId)
}

/// Next RLP string in `data`: a list where a field is expected is refused
fn rlp_string(data: &[u8]) -> Result<(&[u8], &[u8]), ParserError> {
    if *data.first().ok_or(ParserError::UnexpectedBufferEnd)? >= 0xC0 {
        return Err(ParserError::InvalidEthMessage);
    }

    Ok(parse_rlp_item(data)?)
}

/// Header of the RLP string at the start of `data`, without needing its
/// payload: (header length, payload length)
fn rlp_string_header(data: &[u8]) -> Result<(usize, u64), ParserError> {
    match *data.first().ok_or(ParserError::UnexpectedBufferEnd)? {
        0..=0x7F => Ok((0, 1)),
        short @ 0x80..=0xB7 => Ok((1, (short - 0x80) as u64)),
        long @ 0xB8..=0xBF => {
            let num_bytes = (long - 0xB7) as usize;
            let len = data
                .get(1..=num_bytes)
                .ok_or(ParserError::UnexpectedBufferEnd)?;
            Ok((1 + num_bytes, bytes_to_u64(len)?))
        }
        _ => Err(ParserError::InvalidEthMessage),
    }
}

/// Read what the first packet of a streamed transaction tells about it.
///
/// `tx` is the start of the transaction, whose RLP list payload starts at
/// `read` and is `to_read` bytes long. Returns whether it is typed, its
/// chain ID (for a typed transaction it is the first field) and, for a
/// legacy one, the length of what follows the data field: the chain ID, R
/// and S, which only arrive with the last chunks.
fn parse_stream_start(
    tx: &[u8],
    read: usize,
    to_read: u64,
) -> Result<(bool, Option<[u8; 8]>, u64), ParserError> {
    let body = tx.get(read..).ok_or(ParserError::UnexpectedBufferEnd)?;

    if matches!(tx.first(), Some(&EIP1559_TX) | Some(&EIP2930_TX)) {
        let (_, chain_id) = rlp_string(body)?;
        return Ok((true, Some(checked_chain_id(chain_id, false)?), 0));
    }

    // legacy: nonce, gas price, gas limit, to, value, data, [chain ID, R, S]
    let mut rem = body;
    for _ in 0..5 {
        (rem, _) = rlp_string(rem)?;
    }
    let (header_len, data_len) = rlp_string_header(rem)?;
    let data_end = ((body.len() - rem.len() + header_len) as u64)
        .checked_add(data_len)
        .ok_or(ParserError::ValueOutOfRange)?;

    let tail_len = to_read
        .checked_sub(data_end)
        .ok_or(ParserError::InvalidEthMessage)?;
    if tail_len == 0 {
        // no chain ID: pre-EIP-155, valid on every EVM chain
        return Err(ParserError::InvalidChainId);
    }
    if tail_len > STREAMING_TAIL_CAPACITY as u64 {
        return Err(ParserError::UnexpectedData);
    }

    Ok((false, None, tail_len))
}

/// Chain ID of a legacy transaction from its tail (chain ID, R, S)
fn legacy_tail_chain_id(tail: &[u8]) -> Result<[u8; 8], ParserError> {
    let (rem, chain_id) = rlp_string(tail)?;
    let (rem, r) = rlp_string(rem)?;
    let (rem, s) = rlp_string(rem)?;

    // an unsigned transaction carries an empty (or zero) R and S
    let unset = |v: &[u8]| v.is_empty() || v == [0];
    if !rem.is_empty() || !unset(r) || !unset(s) {
        return Err(ParserError::UnexpectedData);
    }

    checked_chain_id(chain_id, true)
}

impl Sign {
    pub const SIGN_HASH_SIZE: usize = Keccak::<32>::DIGEST_LEN;
    pub const BUFFER_CAPACITY: usize = 16384; // device max flash length

    fn get_derivation_info() -> Result<&'static BIP32Path<MAX_BIP32_PATH_DEPTH>, Error> {
        match unsafe { crate::lock_mut!(PATH).acquire(Self) } {
            Ok(Some(some)) => Ok(some),
            _ => Err(Error::ApduCodeConditionsNotSatisfied),
        }
    }

    //(actual_size, [u8; MAX_SIGNATURE_SIZE])
    #[inline(never)]
    pub fn sign<const LEN: usize>(
        path: &BIP32Path<LEN>,
        // data: &[u8],
    ) -> Result<(ECCInfoFlags, usize, [u8; 100]), Error> {
        let sk = Curve.to_secret(path);
        let buffer = unsafe { crate::lock_mut!(BUFFER).acquire(Self)? };
        let data = Self::digest(buffer.read_exact())?;

        let mut out = [0; 100];
        let (flags, sz) = sk
            .sign(&data, &mut out[..])
            .map_err(|_| Error::ExecutionError)?;

        Ok((flags, sz, out))
    }

    // Sign a pre-computed hash (for blind signing)
    #[inline(never)]
    pub fn sign_hash<const LEN: usize>(
        path: &BIP32Path<LEN>,
        hash: &[u8; Self::SIGN_HASH_SIZE],
    ) -> Result<(ECCInfoFlags, usize, [u8; 100]), Error> {
        let sk = Curve.to_secret(path);

        let mut out = [0; 100];
        let (flags, sz) = sk
            .sign(hash, &mut out[..])
            .map_err(|_| Error::ExecutionError)?;

        Ok((flags, sz, out))
    }

    #[inline(never)]
    fn digest(to_hash: &[u8]) -> Result<[u8; Self::SIGN_HASH_SIZE], Error> {
        let mut hasher = {
            let mut k = MaybeUninit::uninit();
            Keccak::<32>::new_gce(&mut k).map_err(|_| Error::Unknown)?;

            //safe: initialized
            unsafe { k.assume_init() }
        };

        hasher.update(to_hash).map_err(|_| Error::Unknown)?;
        hasher.finalize().map_err(|_| Error::Unknown)
    }

    #[inline(never)]
    pub fn start_sign(txdata: &'static [u8], flags: &mut u32) -> Result<u32, Error> {
        // The ERC721 parser might need access to the NFT_INFO resource
        // also during the review part
        #[cfg(feature = "erc721")]
        unsafe {
            crate::lock_mut!(crate::handlers::resources::NFT_INFO).lock(crate::parser::ERC721Info)
        };

        // now parse the transaction
        let mut tx = MaybeUninit::uninit();
        let _ = EthTransaction::from_bytes_into(txdata, &mut tx).map_err(|_| Error::DataInvalid)?;

        // This does not hold true
        // keep it for reference only
        // some applications might append data at the end of an encoded
        // transaction, so skip it to get the right hash.
        //
        // this would also include the tx type, as required by EIP-2718
        // since the tx type is at the start of the data
        // let to_hash = txdata.len() - rem.len();
        // let to_hash = &txdata[..to_hash];

        let unsigned_hash = Self::digest(txdata).map_err(|_| Error::DataInvalid)?;
        let tx = unsafe { tx.assume_init() };

        // Foreign EVM chain (not AVAX C-Chain): the device cannot resolve the
        // native ticker symbol — the value field would render as "???" — so
        // require blind-sign mode here, matching upstream Ledger Ethereum app
        // behavior. (Foreign-chain coverage on the streaming/oversize path is
        // transitive: that branch already gates on blind-sign for any chain.)
        if !is_avax_chain_bytes(tx.chain_id()) && !is_app_mode_blind_sign() {
            return Err(Error::ApduCodeConditionsNotSatisfied);
        }

        let ui = SignUI {
            hash: unsigned_hash,
            is_typed: tx.is_typed_tx(),
            chain_id: chain_id_to_array(tx.chain_id()),
            tx: Some(tx),
        };

        crate::show_ui!(unsafe { ui.show(flags) })
    }

    #[inline(never)]
    pub fn start_parse(txdata: &'static [u8]) -> Result<(), ParserError> {
        // The ERC721 parser might need access to the NFT_INFO resource
        // also during the review part
        #[cfg(feature = "erc721")]
        unsafe {
            crate::lock_mut!(crate::handlers::resources::NFT_INFO).lock(crate::parser::ERC721Info)
        };

        // now parse the transaction
        let mut tx = MaybeUninit::uninit();
        let _ = EthTransaction::from_bytes_into(txdata, &mut tx)?;

        // This does not hold true, keep it just for reference
        // some applications might append data at the end of an encoded
        // transaction, so skip it to get the right hash.
        //
        // this would also include the tx type, as required by EIP-2718
        // since the tx type is at the start of the data
        // let to_hash = txdata.len() - rem.len();
        // let to_hash = &txdata[..to_hash];
        let unsigned_hash = Self::digest(txdata).map_err(|_| ParserError::UnexpectedError)?;
        let tx = unsafe { tx.assume_init() };

        // Foreign EVM chain (not AVAX C-Chain): the device cannot resolve the
        // native ticker symbol — the value field would render as "???" — so
        // require blind-sign mode here, matching upstream Ledger Ethereum app
        // behavior. (Foreign-chain coverage on the streaming/oversize path is
        // transitive: that branch already gates on blind-sign for any chain.)
        if !is_avax_chain_bytes(tx.chain_id()) && !is_app_mode_blind_sign() {
            return Err(ParserError::BlindSignNotEnabled);
        }

        let ui = EthUi::Tx(SignUI {
            hash: unsigned_hash,
            is_typed: tx.is_typed_tx(),
            chain_id: chain_id_to_array(tx.chain_id()),
            tx: Some(tx),
        });

        unsafe {
            crate::lock_mut!(ETH_UI).lock(EthAccessors::Tx).replace(ui);
        }
        Ok(())
    }

    /// Hand the NFT info provided since the last request to this one, and
    /// drop any info an earlier request already used.
    #[cfg(feature = "erc721")]
    fn claim_nft_info() {
        use crate::handlers::{eth::provide_nft_info::Info, resources::NFT_INFO};

        unsafe {
            let nft_info = crate::lock_mut!(NFT_INFO);
            if nft_info.acquire(Info).is_ok() {
                nft_info.lock(Self);
            } else {
                nft_info.lock(Self).take();
            }
        }
    }

    /// Drop all the state of a streamed transaction
    fn reset_streaming() {
        unsafe {
            *crate::lock_mut!(STREAMING_MODE).lock(StreamingAccessors::EthSign) = false;
            crate::lock_mut!(STREAMING_HASHER)
                .lock(StreamingAccessors::EthSign)
                .take();
            let _ = crate::lock_mut!(STREAMING_HASHER).release(StreamingAccessors::EthSign);
            *crate::lock_mut!(EXPECTED_BYTES).lock(StreamingAccessors::EthSign) = 0;
            *crate::lock_mut!(RECEIVED_BYTES).lock(StreamingAccessors::EthSign) = 0;
            *crate::lock_mut!(STREAMING_TX_TYPE).lock(StreamingAccessors::EthSign) = false;
            *crate::lock_mut!(STREAMING_CHAIN_ID).lock(StreamingAccessors::EthSign) = None;
            *crate::lock_mut!(IS_LEGACY_TX).lock(StreamingAccessors::EthSign) = false;
            *crate::lock_mut!(STREAMING_TAIL).lock(StreamingAccessors::EthSign) =
                [0; STREAMING_TAIL_CAPACITY];
            *crate::lock_mut!(STREAMING_TAIL_LEN).lock(StreamingAccessors::EthSign) = 0;
        }
    }

    /// Hash the next bytes of a streamed transaction, which start at `offset`
    /// in its RLP list payload, and keep those that fall in a legacy tail
    fn stream_bytes(offset: u64, bytes: &[u8]) -> Result<(), ParserError> {
        unsafe {
            crate::lock_mut!(STREAMING_HASHER)
                .acquire(StreamingAccessors::EthSign)
                .map_err(|_| ParserError::UnexpectedError)?
                .as_mut()
                .ok_or(ParserError::UnexpectedError)?
                .update(bytes)
                .map_err(|_| ParserError::UnexpectedError)?;

            if !*crate::lock_mut!(IS_LEGACY_TX).lock(StreamingAccessors::EthSign) {
                return Ok(());
            }

            let expected = *crate::lock_mut!(EXPECTED_BYTES).lock(StreamingAccessors::EthSign);
            let tail_len = *crate::lock_mut!(STREAMING_TAIL_LEN).lock(StreamingAccessors::EthSign);
            let tail_start = expected.saturating_sub(tail_len);

            // callers never pass bytes past the end of the transaction
            let end = offset.saturating_add(bytes.len() as u64);
            if end <= tail_start {
                return Ok(());
            }
            let skip = tail_start.saturating_sub(offset) as usize;
            let at = (offset + skip as u64 - tail_start) as usize;
            let bytes = &bytes[skip..];

            crate::lock_mut!(STREAMING_TAIL)
                .lock(StreamingAccessors::EthSign)
                .get_mut(at..at + bytes.len())
                .ok_or(ParserError::UnexpectedError)?
                .copy_from_slice(bytes);
        }

        Ok(())
    }

    #[inline(never)]
    fn finalize_streaming_hash() -> Result<(), ParserError> {
        // The setting may have been turned off while the chunks were streamed
        if !is_app_mode_blind_sign() {
            return Err(ParserError::BlindSignNotEnabled);
        }

        let hasher = unsafe {
            crate::lock_mut!(STREAMING_HASHER)
                .acquire(StreamingAccessors::EthSign)
                .map_err(|_| ParserError::UnexpectedError)?
                .take()
                .ok_or(ParserError::UnexpectedError)?
        };

        let hash = hasher
            .finalize()
            .map_err(|_| ParserError::UnexpectedError)?;

        // Retrieve stored transaction metadata for V calculation
        let is_typed = unsafe {
            let stored_is_typed =
                *crate::lock_mut!(STREAMING_TX_TYPE).lock(StreamingAccessors::EthSign);
            stored_is_typed
        };

        // A legacy transaction carries its chain ID at the end
        let chain_id = unsafe {
            if *crate::lock_mut!(IS_LEGACY_TX).lock(StreamingAccessors::EthSign) {
                let tail_len =
                    *crate::lock_mut!(STREAMING_TAIL_LEN).lock(StreamingAccessors::EthSign);
                let tail = crate::lock_mut!(STREAMING_TAIL).lock(StreamingAccessors::EthSign);
                let tail = tail
                    .get(..tail_len as usize)
                    .ok_or(ParserError::UnexpectedError)?;

                Some(legacy_tail_chain_id(tail)?)
            } else {
                *crate::lock_mut!(STREAMING_CHAIN_ID).lock(StreamingAccessors::EthSign)
            }
        };

        // Create SignUI with the pre-computed hash and stored metadata
        let ui = EthUi::Tx(SignUI {
            hash,     // Use the pre-computed hash from streaming
            is_typed, // Transaction type from first packet
            chain_id, // Chain ID from first packet (for correct V calculation)
            tx: None, // Never parsed: reviewed as its hash only
        });

        // Store the UI for later signing
        unsafe {
            crate::lock_mut!(ETH_UI).lock(EthAccessors::Tx).replace(ui);
        }

        // Clean up streaming state
        Self::reset_streaming();

        // Return Ok - the hash has been computed successfully
        // and SignUI has been created for blind signing
        Ok(())
    }

    pub fn parse(buffer: ApduBufferRead<'_>) -> Result<bool, ParserError> {
        crate::zlog("EthSign::parse\x00");

        let res = Self::parse_packet(buffer);

        // A refused packet ends the session: nothing it started may carry
        // over into the next request
        if res.is_err() {
            let _ = cleanup_globals();
        }

        res
    }

    fn parse_packet(buffer: ApduBufferRead<'_>) -> Result<bool, ParserError> {
        // hw-app-eth encodes the packet type in p1
        // with 0x00 being init and 0x80 being next
        //
        // the end of the transmission is implicit based on the received data
        // an eth transaction is RLP encoded (https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/#definition)
        // with the first byte being the version (0x01 EIP2930 or 0x02 EIP1559 or legacy if neither/missing)
        // and then a RLP list
        //
        // therefore, the data received self-describes how many bytes the app can expect and
        // when all data has been received

        let packet_type = buffer.p1();

        match packet_type {
            //init
            0x00 => {
                // A new request starts from a clean state, whatever an
                // abandoned or failed session left behind
                Self::reset_streaming();
                unsafe {
                    crate::lock_mut!(ETH_UI).lock(EthAccessors::Tx).take();
                }
                #[cfg(feature = "erc721")]
                Self::claim_nft_info();

                let payload = buffer.payload().map_err(|_| ParserError::NoData)?;
                //parse path to verify it's the data we expect
                let (rest, bip32_path) =
                    parse_bip32_eth(payload).map_err(|_| ParserError::InvalidPath)?;
                verify_coreth_root_path(&bip32_path).map_err(|_| ParserError::InvalidPath)?;

                unsafe {
                    crate::lock_mut!(PATH).lock(Self).replace(bip32_path);
                }

                //parse the length of the RLP message
                let (read, to_read) =
                    get_tx_rlp_len(rest).map_err(|_| ParserError::UnexpectedBufferEnd)?;
                let total_size = (to_read as usize).saturating_add(read);

                // Check if transaction is too large for buffer
                if total_size > Self::BUFFER_CAPACITY {
                    // Verify blind signing is enabled
                    if !is_app_mode_blind_sign() {
                        return Err(ParserError::BlindSignNotEnabled);
                    }

                    // Apply the chain-ID policy of normal mode from the first
                    // packet (a legacy chain ID is checked when it arrives)
                    let (is_typed, chain_id_bytes, tail_len) =
                        parse_stream_start(rest, read, to_read)?;

                    // Initialize streaming hash mode, starting with the
                    // version and the list header
                    let mut hasher =
                        Keccak::<32>::new().map_err(|_| ParserError::UnexpectedError)?;
                    hasher
                        .update(&rest[..read])
                        .map_err(|_| ParserError::UnexpectedError)?;
                    let len = core::cmp::min(total_size, rest.len());

                    // Store state for subsequent packets
                    unsafe {
                        crate::lock_mut!(STREAMING_HASHER)
                            .lock(StreamingAccessors::EthSign)
                            .replace(hasher);
                        *crate::lock_mut!(STREAMING_MODE).lock(StreamingAccessors::EthSign) = true;
                        *crate::lock_mut!(EXPECTED_BYTES).lock(StreamingAccessors::EthSign) =
                            to_read;
                        *crate::lock_mut!(RECEIVED_BYTES).lock(StreamingAccessors::EthSign) =
                            (len as u64).saturating_sub(read as u64);

                        // Store transaction metadata for V calculation
                        *crate::lock_mut!(STREAMING_TX_TYPE).lock(StreamingAccessors::EthSign) =
                            is_typed;
                        *crate::lock_mut!(STREAMING_CHAIN_ID).lock(StreamingAccessors::EthSign) =
                            chain_id_bytes;
                        *crate::lock_mut!(IS_LEGACY_TX).lock(StreamingAccessors::EthSign) =
                            !is_typed;
                        *crate::lock_mut!(STREAMING_TAIL_LEN).lock(StreamingAccessors::EthSign) =
                            tail_len;
                    }

                    // Hash the data we have so far
                    Self::stream_bytes(0, &rest[read..len])?;

                    // Check if complete in first packet
                    if total_size <= rest.len() {
                        Self::finalize_streaming_hash()?;
                        return Ok(true);
                    }

                    return Ok(false); // Need more packets
                }

                // Normal path for small transactions
                let len = core::cmp::min(total_size, rest.len());
                let buffer = unsafe { crate::lock_mut!(BUFFER).lock(Self) };
                buffer.reset();

                buffer
                    .write(&rest[..len])
                    .map_err(|_| ParserError::UnexpectedError)?;

                //if the number of bytes read and the number of bytes to read
                // is the same as what we read...
                if (to_read as usize).saturating_add(read).saturating_sub(len) == 0 {
                    //then we actually had all bytes in this tx!
                    // we should sign directly
                    Self::start_parse(buffer.read_exact())?;

                    return Ok(true);
                }

                Ok(false)
            }
            //next
            0x80 => {
                let payload = buffer.payload().map_err(|_| ParserError::NoData)?;

                // Check if we're in streaming mode
                let streaming =
                    unsafe { *crate::lock_mut!(STREAMING_MODE).lock(StreamingAccessors::EthSign) };

                if streaming {
                    let received_bytes = unsafe {
                        crate::lock_mut!(RECEIVED_BYTES).lock(StreamingAccessors::EthSign)
                    };
                    let expected_bytes = unsafe {
                        *crate::lock_mut!(EXPECTED_BYTES).lock(StreamingAccessors::EthSign)
                    };

                    // Only the bytes of the transaction are hashed, as in
                    // normal mode: anything past its end is ignored
                    let missing = expected_bytes.saturating_sub(*received_bytes);
                    let len = core::cmp::min(missing, payload.len() as u64) as usize;
                    Self::stream_bytes(*received_bytes, &payload[..len])?;
                    *received_bytes = received_bytes.saturating_add(len as u64);

                    if *received_bytes >= expected_bytes {
                        Self::finalize_streaming_hash()?;
                        return Ok(true);
                    }

                    return Ok(false); // Need more packets
                }

                // Normal buffer append path
                let buffer = unsafe {
                    crate::lock_mut!(BUFFER)
                        .acquire(Self)
                        .map_err(|_| ParserError::UnexpectedError)?
                };

                //we could unwrap here as this data should be guaranteed correct
                // we read back what we wrote to see how many bytes we expect
                // to have to collect
                let (read, to_read) = get_tx_rlp_len(buffer.read_exact())
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;

                // let's ignore the little header at the start
                let rlp_read = buffer.read_exact().len() - read;

                //either the entire buffer of the remaining bytes we expect
                let missing = to_read as usize - rlp_read;
                let len = core::cmp::min(missing, payload.len());

                buffer
                    .write(&payload[..len])
                    .map_err(|_| ParserError::UnexpectedError)?;

                if missing - len == 0 {
                    //we read all the missing bytes so we can proceed with the signature
                    // nwo
                    Self::start_parse(buffer.read_exact())?;
                    return Ok(true);
                }

                Ok(false)
            }
            _ => Err(ParserError::UnexpectedData),
        }
    }
}

impl ApduHandler for Sign {
    #[inline(never)]
    fn handle(flags: &mut u32, tx: &mut u32, buffer: ApduBufferRead<'_>) -> Result<(), Error> {
        sys::zemu_log_stack("EthSign::handle\x00");

        *tx = 0;

        // hw-app-eth encodes the packet type in p1
        // with 0x00 being init and 0x80 being next
        //
        // the end of the transmission is implicit based on the received data
        // an eth transaction is RLP encoded (https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/#definition)
        // with the first byte being the version (0x01 EIP2930 or 0x02 EIP1559 or legacy if neither/missing)
        // and then a RLP list
        //
        // therefore, the data received self-describes how many bytes the app can expect and
        // when all data has been received

        let packet_type = buffer.p1();

        match packet_type {
            //init
            0x00 => {
                let payload = buffer.payload().map_err(|_| Error::WrongLength)?;
                //parse path to verify it's the data we expect
                let (rest, bip32_path) =
                    parse_bip32_eth(payload).map_err(|_| Error::DataInvalid)?;
                verify_coreth_root_path(&bip32_path)?;

                unsafe {
                    crate::lock_mut!(PATH).lock(Self).replace(bip32_path);
                }

                //parse the length of the RLP message
                let (read, to_read) = get_tx_rlp_len(rest)?;
                let len = core::cmp::min((to_read as usize).saturating_add(read), rest.len());

                //write the rest to the swapping buffer so we persist this data
                let buffer = unsafe { crate::lock_mut!(BUFFER).lock(Self) };
                buffer.reset();

                buffer
                    .write(&rest[..len])
                    .map_err(|_| Error::ExecutionError)?;

                //if the number of bytes read and the number of bytes to read
                // is the same as what we read...
                if (to_read as usize).saturating_add(read).saturating_sub(len) == 0 {
                    //then we actually had all bytes in this tx!
                    // we should sign directly
                    *tx = Self::start_sign(buffer.read_exact(), flags)?;
                }

                Ok(())
            }
            //next
            0x80 => {
                let payload = buffer.payload().map_err(|_| Error::WrongLength)?;

                let buffer = unsafe { crate::lock_mut!(BUFFER).acquire(Self)? };

                //we could unwrap here as this data should be guaranteed correct
                // we read back what we wrote to see how many bytes we expect
                // to have to collect
                let (read, to_read) = get_tx_rlp_len(buffer.read_exact())?;

                // let's ignore the little header at the start
                let rlp_read = buffer.read_exact().len() - read;

                //either the entire buffer of the remaining bytes we expect
                let missing = to_read as usize - rlp_read;
                let len = core::cmp::min(missing, payload.len());

                buffer
                    .write(&payload[..len])
                    .map_err(|_| Error::ExecutionError)?;

                if missing - len == 0 {
                    //we read all the missing bytes so we can proceed with the signature
                    // nwo
                    *tx = Self::start_sign(buffer.read_exact(), flags)?;
                }

                Ok(())
            }
            _ => Err(Error::InvalidP1P2),
        }
    }
}

pub(crate) struct SignUI {
    pub(crate) hash: [u8; Sign::SIGN_HASH_SIZE],
    // The parsed transaction, or None for a streamed one, which is never
    // parsed and is reviewed as its hash with the blind-signing UI
    pub(crate) tx: Option<EthTransaction<'static>>,
    pub(crate) is_typed: bool, // For correct V calculation in blind signing
    pub(crate) chain_id: Option<[u8; 8]>, // Store raw chain ID bytes for V calculation (fixed array)
}

impl SignUI {
    fn is_blind(&self) -> bool {
        self.tx.is_none()
    }
}

impl Viewable for SignUI {
    fn num_items(&mut self) -> Result<u8, ViewError> {
        self.tx.as_ref().ok_or(ViewError::NoData)?.num_items()
    }

    #[inline(never)]
    fn render_item(
        &mut self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        self.tx
            .as_ref()
            .ok_or(ViewError::NoData)?
            .render_item(item_n, title, message, page)
    }

    fn accept(&mut self, out: &mut [u8]) -> (usize, u16) {
        let res = self.sign_tx(out);

        // The review is over whatever the outcome: reset the globals on every
        // exit, so a failed signature leaves no session behind for the next
        // request
        let _ = cleanup_globals();

        res
    }

    fn reject(&mut self, _: &mut [u8]) -> (usize, u16) {
        let _ = cleanup_globals();
        (0, Error::CommandNotAllowed as _)
    }
}

impl SignUI {
    fn sign_tx(&self, out: &mut [u8]) -> (usize, u16) {
        let path = match Sign::get_derivation_info() {
            Err(e) => return (0, e as _),
            Ok(k) => k,
        };

        let (flags, sig_size, mut sig) = match Sign::sign_hash(path, &self.hash) {
            Err(e) => return (0, e as _),
            Ok(k) => k,
        };

        let mut tx = 0;

        //write signature as VRS

        // It is necessary to write the right V
        // component as it depends on the chainID(lowest byte) and the
        // parity of the last byte of the S component, this procedure is
        // defined by EIP-155.
        //
        // Check for typed transactions - use stored metadata if available
        // This ensures correct V calculation even in blind signing mode
        if self.is_typed {
            //write V, which is the oddity of the signature
            out[tx] = flags.contains(ECCInfo::ParityOdd) as u8;
            tx += 1;
        } else {
            // Use stored chain_id if available (for blind signing), otherwise get from tx
            let chain_id = self
                .chain_id
                .as_ref()
                .map(|v| {
                    // Stored array is right-aligned BE (see `chain_id_to_array`);
                    // skip leading zeros to recover the canonical slice. We must
                    // skip leading rather than trailing zeros so chain IDs whose
                    // low byte is zero (e.g. 256) are not collapsed to 1.
                    let mut start = 0;
                    while start < v.len() - 1 && v[start] == 0 {
                        start += 1;
                    }
                    &v[start..]
                })
                .or_else(|| self.tx.as_ref().map(|tx| tx.chain_id()))
                .unwrap_or_default();

            if chain_id.is_empty() {
                // A legacy transaction with no chain ID is pre-EIP-155 and
                // valid on every EVM chain. Both parsers refuse it, so this
                // is never reached; never sign one (V = 27/28) regardless.
                return (0, Error::DataInvalid as _);
            } else {
                // app-ethereum reads the first 4 bytes then cast it to an u8
                // this is not good but it relies on hw-eth-app lib from ledger
                // to recover the right chain_id from the V component being computed here, and
                // which is returned with the signature
                let len = core::cmp::min(U32_SIZE, chain_id.len());
                if let Ok(chain_id) = bytes_to_u64(&chain_id[..len]) {
                    // Verify chain_id
                    if chain_id == NONE_CHAIN_ID || chain_id == ETH_MAINNET_ID {
                        return (0, Error::DataInvalid as _);
                    }
                    let v = (35 + flags.contains(ECCInfo::ParityOdd) as u32)
                        .saturating_add((chain_id as u32) << 1);
                    out[tx] = v as u8;
                }
            }
            tx += 1;
        }

        //set to 0x30 for the DER conversion
        sig[0] = 0x30;
        {
            let mut r = [0; 33];
            let mut s = [0; 33];

            //write as R S (V written earlier)
            // this will write directly to buffer
            match convert_der_to_rs(&sig[..sig_size], &mut r, &mut s) {
                Ok(_) => {
                    //format R and S by only having 32 bytes each,
                    // skipping the first byte if necessary
                    // if we have less than 32 bytes we just have 0s at the start
                    // this is consistent with the fact that in `convert_der_to_rs`
                    // we put the bytes at the end of the buffer first
                    let r = &r[1..];
                    let s = &s[1..];

                    out[tx..][..32].copy_from_slice(r);
                    tx += 32;

                    out[tx..][..32].copy_from_slice(s);
                    tx += 32;
                }
                Err(_) => return (0, Error::ExecutionError as _),
            }
        }

        (tx, Error::Success as _)
    }
}

pub fn cleanup_globals() -> Result<(), Error> {
    unsafe {
        if let Ok(path) = crate::lock_mut!(PATH).acquire(Sign) {
            path.take();

            //let's release the lock for the future
            let _ = crate::lock_mut!(PATH).release(Sign);
        }

        if let Ok(buffer) = crate::lock_mut!(BUFFER).acquire(Sign) {
            buffer.reset();

            //let's release the lock for the future
            let _ = crate::lock_mut!(BUFFER).release(Sign);
        }

        Sign::reset_streaming();

        // Forcefully acquire the resource as it is not longer in use
        // transaction was rejected.
        #[cfg(feature = "erc721")]
        {
            crate::lock_mut!(crate::handlers::resources::NFT_INFO)
                .lock(Sign)
                .take();
            //let's release the lock for the future
            _ = crate::lock_mut!(crate::handlers::resources::NFT_INFO).release(Sign);
        }
    }

    //if we failed to aquire then someone else is using it anyways
    Ok(())
}

/// The streamed transaction under review, if the current ETH review is one.
///
/// Both the choice of the blind-signing UI and the hash it shows come from
/// the review the current request stored, the same object `accept` signs,
/// so they cannot disagree with it or outlive it.
unsafe fn blind_review() -> Option<&'static SignUI> {
    match crate::lock_mut!(ETH_UI).lock(EthAccessors::Tx) {
        Some(EthUi::Tx(ui)) if ui.is_blind() => Some(ui),
        _ => None,
    }
}

/// Check if streaming mode was used for the last ETH transaction
#[no_mangle]
pub unsafe extern "C" fn rs_eth_was_streaming_mode_used() -> bool {
    blind_review().is_some()
}

/// Get the computed hash from streaming mode (returns true if hash is available)
#[no_mangle]
pub unsafe extern "C" fn rs_eth_get_streaming_hash(hash_buffer: *mut u8, buffer_len: u16) -> bool {
    if buffer_len < 32 {
        return false;
    }

    if let Some(ui) = blind_review() {
        let buffer_slice = std::slice::from_raw_parts_mut(hash_buffer, 32);
        buffer_slice.copy_from_slice(&ui.hash);
        true
    } else {
        false
    }
}

/// Get the number of items for blind signing display (always returns 1)
#[no_mangle]
pub unsafe extern "C" fn _getNumItemsBlindSign(num_items: *mut u8) -> u32 {
    use crate::parser::ParserError;

    if num_items.is_null() {
        return ParserError::NoData as u32;
    }

    // For blind signing, we always show 1 item: the hash
    *num_items = 1;
    ParserError::ParserOk as u32
}

/// Get a specific item for blind signing display
#[no_mangle]
pub unsafe extern "C" fn _getItemBlindSign(
    display_idx: i8,
    out_key: *mut i8,
    out_key_len: u16,
    out_value: *mut i8,
    out_value_len: u16,
    page_idx: u8,
    page_count: *mut u8,
) -> u32 {
    use crate::handlers::handle_ui_message;
    use crate::parser::ParserError;
    use bolos::{pic_str, PIC};

    // Validate input parameters
    if out_key.is_null() || out_value.is_null() || page_count.is_null() {
        return ParserError::NoData as u32;
    }

    // We only have 1 item for blind signing
    if display_idx != 0 {
        return ParserError::DisplayIdxOutOfRange as u32;
    }

    crate::zlog("_getItemBlindSign\n");

    // Set the title using pic_str!
    let label = pic_str!(b"Transaction hash");
    let key_slice = std::slice::from_raw_parts_mut(out_key as *mut u8, out_key_len as usize);

    if (label.len() + 1) > out_key_len as usize {
        return ParserError::UnexpectedBufferEnd as u32;
    }

    key_slice[..label.len()].copy_from_slice(label);
    key_slice[label.len()] = 0; // null terminator

    // Get the actual transaction hash from streaming mode
    let mut hash_buffer = [0u8; 32];
    let hash_available = rs_eth_get_streaming_hash(hash_buffer.as_mut_ptr(), 32);

    if !hash_available {
        crate::zlog("_getItemBlindSign: No hash available\n");
        return ParserError::NoData as u32;
    }

    // Format hash as hex string: "0x" + 64 hex chars = 66 chars total
    let mut hex_string = [0u8; 66];
    hex_string[0] = b'0';
    hex_string[1] = b'x';

    // Convert each byte to 2 hex characters
    for (i, &byte) in hash_buffer.iter().enumerate() {
        let hex_pos = 2 + (i * 2);
        let high_nibble = (byte >> 4) & 0x0f;
        let low_nibble = byte & 0x0f;

        hex_string[hex_pos] = if high_nibble < 10 {
            b'0' + high_nibble
        } else {
            b'a' + (high_nibble - 10)
        };

        hex_string[hex_pos + 1] = if low_nibble < 10 {
            b'0' + low_nibble
        } else {
            b'a' + (low_nibble - 10)
        };
    }

    let value_slice = std::slice::from_raw_parts_mut(out_value as *mut u8, out_value_len as usize);

    // Use handle_ui_message to properly handle paging
    match handle_ui_message(&hex_string, value_slice, page_idx) {
        Ok(pages) => {
            *page_count = pages;
            ParserError::ParserOk as u32
        }
        Err(_) => ParserError::UnexpectedError as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::bytes_to_u64;

    #[test]
    fn rlp_decoder() {
        let data = hex::decode("02f878018402a8af41843b9aca00850d8c7b50e68303d090944a2962ac08962819a8a17661970e3c0db765565e8817addd0864728ae780c080a01e514f7fc78197c66589083cc8fd06376bae627a4080f5fb58d52d90c0df340da049b048717f215e622c93722ff5b1e38e1d1a4ab9e26a39183969a34a5f8dea75").unwrap();

        let (read, to_read) = get_tx_rlp_len(&data).expect("unable to minimally parse tx data");

        assert_eq!(read, 3);
        assert_eq!(to_read, 0x78);
    }

    /// Mirrors the leading-zero strip in `SignUI::accept` so we can round-trip
    /// `chain_id_to_array` in tests without spinning up a full SignUI.
    fn strip_leading_zeros(v: &[u8]) -> &[u8] {
        let mut start = 0;
        while start < v.len() - 1 && v[start] == 0 {
            start += 1;
        }
        &v[start..]
    }

    #[test]
    fn chain_id_round_trip_preserves_low_zero_byte() {
        // Regression: chain IDs whose low byte is 0x00 (e.g. 256 = [0x01, 0x00])
        // were collapsed to 1 by the old left-aligned packing + trailing-zero
        // strip in `accept`.
        for &expected in &[1u64, 256, 43113, 43114, u64::MAX] {
            let be = expected.to_be_bytes();
            // Trim leading zeros to mimic what `tx.chain_id()` returns.
            let mut i = 0;
            while i < be.len() - 1 && be[i] == 0 {
                i += 1;
            }
            let slice = &be[i..];

            let array = chain_id_to_array(slice).expect("non-empty slice");
            let recovered = strip_leading_zeros(&array);
            let value = bytes_to_u64(recovered).expect("fits in u64");
            assert_eq!(value, expected, "round trip failed for chain id {expected}");
        }
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;
    use crate::handlers::resources::PATHAccessors;
    use crate::parser::rlp_test_utils::{item, list, uint};
    use crate::parser::{AVAX_C_CHAIN_MAINNET_ID, EIP1559_TX};
    use serial_test::file_serial;
    use std::vec::Vec;

    const ETH_PATH: [u32; 5] = [0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0];

    fn apdu(p1: u8, payload: &[u8]) -> Result<bool, ParserError> {
        let mut buf = std::vec![0u8; 5 + payload.len()];
        buf[..5].copy_from_slice(&[0xE0, 0x04, p1, 0x00, payload.len() as u8]);
        buf[5..].copy_from_slice(payload);
        let rx = buf.len() as u32;
        Sign::parse(ApduBufferRead::new(&mut buf, rx).unwrap())
    }

    fn init_payload(chunk: &[u8]) -> Vec<u8> {
        let mut out = std::vec![ETH_PATH.len() as u8];
        for c in ETH_PATH {
            out.extend_from_slice(&c.to_be_bytes());
        }
        out.extend_from_slice(chunk);
        out
    }

    /// Send the INIT packet of `tx` (path + as many bytes as fit)
    /// and return the rest
    fn send_init(tx: &[u8]) -> (Result<bool, ParserError>, &[u8]) {
        let room = 255 - init_payload(&[]).len();
        let (head, rest) = tx.split_at(core::cmp::min(room, tx.len()));
        (apdu(0x00, &init_payload(head)), rest)
    }

    /// Send `tx` the way hw-app-eth does: INIT then 0x80 chunks
    fn send_tx(tx: &[u8]) -> Result<bool, ParserError> {
        let (res, mut rest) = send_init(tx);
        let mut done = res?;
        while !rest.is_empty() {
            let (chunk, r) = rest.split_at(core::cmp::min(255, rest.len()));
            done = apdu(0x80, chunk)?;
            rest = r;
        }
        Ok(done)
    }

    fn eip1559(chain_id: u64, data_len: usize) -> Vec<u8> {
        let mut tx = std::vec![EIP1559_TX];
        tx.extend(list(&[
            uint(chain_id as u128),
            uint(1),
            uint(1_000_000_000),
            uint(30_000_000_000),
            uint(100_000),
            item(&[0xa1; 20]),
            uint(0),
            item(&std::vec![0x5a; data_len]),
            list(&[]),
        ]));
        tx
    }

    fn keccak(data: &[u8]) -> [u8; 32] {
        Sign::digest(data).unwrap()
    }

    fn ui_hash() -> [u8; 32] {
        match unsafe { crate::lock_mut!(ETH_UI).lock(EthAccessors::Tx) } {
            Some(EthUi::Tx(ui)) => ui.hash,
            _ => panic!("no tx review stored"),
        }
    }

    fn blind_hash_shown() -> Option<[u8; 32]> {
        let mut hash = [0; 32];
        unsafe { rs_eth_get_streaming_hash(hash.as_mut_ptr(), 32) }.then_some(hash)
    }

    fn accept() -> u16 {
        let mut out = [0; 100];
        let ui = unsafe { crate::lock_mut!(ETH_UI).lock(EthAccessors::Tx) };
        ui.as_mut().expect("no review stored").accept(&mut out).1
    }

    fn reset() {
        let _ = cleanup_globals();
        unsafe {
            crate::lock_mut!(ETH_UI).lock(EthAccessors::Tx).take();
        }
    }

    // AVAX-05: an ETH accept that fails before cleanup must not leave the
    // blind-signing review of that stream behind for the next transaction.
    #[test]
    #[file_serial(path)]
    fn failed_accept_does_not_leak_blind_review() {
        reset();

        let big = eip1559(AVAX_C_CHAIN_MAINNET_ID, Sign::BUFFER_CAPACITY + 100);
        assert_eq!(send_tx(&big), Ok(true));
        assert!(unsafe { rs_eth_was_streaming_mode_used() });
        assert_eq!(blind_hash_shown(), Some(keccak(&big)));

        // another handler takes the path between chunks (e.g. 80 05)
        unsafe {
            crate::lock_mut!(PATH).lock(PATHAccessors::Sign);
        }
        assert_ne!(accept(), Error::Success as u16);

        // the host "retries" with a small transaction
        let small = eip1559(AVAX_C_CHAIN_MAINNET_ID, 10);
        assert_eq!(send_tx(&small), Ok(true));

        assert!(
            !unsafe { rs_eth_was_streaming_mode_used() },
            "small tx reviewed with the blind-sign UI"
        );
        assert_ne!(blind_hash_shown(), Some(keccak(&big)), "stale hash shown");
        assert_eq!(ui_hash(), keccak(&small));
        reset();
    }

    // Once answered, a review is dropped: nothing may be signed from it again.
    #[test]
    #[file_serial(path)]
    fn review_is_dropped_once_answered() {
        let stored = || unsafe { crate::lock_mut!(ETH_UI).lock(EthAccessors::Tx).is_some() };

        // accepted
        reset();
        assert_eq!(send_tx(&eip1559(AVAX_C_CHAIN_MAINNET_ID, 10)), Ok(true));
        let (mut tx, mut out) = (0u16, [0u8; 100]);
        let code = unsafe {
            crate::ffi::eth_tx::_accept_eth_tx(&mut tx, out.as_mut_ptr(), out.len() as u32)
        };
        assert_eq!(code, Error::Success as u16);
        assert!(!stored());

        // accept failed
        assert_eq!(send_tx(&eip1559(AVAX_C_CHAIN_MAINNET_ID, 10)), Ok(true));
        unsafe {
            crate::lock_mut!(PATH).lock(PATHAccessors::Sign);
        }
        let code = unsafe {
            crate::ffi::eth_tx::_accept_eth_tx(&mut tx, out.as_mut_ptr(), out.len() as u32)
        };
        assert_ne!(code, Error::Success as u16);
        assert!(!stored());

        // rejected
        assert_eq!(send_tx(&eip1559(AVAX_C_CHAIN_MAINNET_ID, 10)), Ok(true));
        unsafe { crate::ffi::sign_hash::_clean_up_eth() };
        assert!(!stored());
        reset();
    }

    // AVAX-18: an abandoned stream must not capture the chunks of the next
    // multi-chunk transaction.
    #[test]
    #[file_serial(path)]
    fn init_resets_abandoned_stream() {
        reset();

        let big = eip1559(AVAX_C_CHAIN_MAINNET_ID, Sign::BUFFER_CAPACITY + 100);
        let (res, _) = send_init(&big);
        assert_eq!(res, Ok(false));

        // normal-size tx that needs a few chunks
        let small = eip1559(AVAX_C_CHAIN_MAINNET_ID, 600);
        assert_eq!(send_tx(&small), Ok(true));
        assert!(!unsafe { rs_eth_was_streaming_mode_used() });
        assert_eq!(ui_hash(), keccak(&small));
        reset();
    }

    // AVAX-18: blind signing turned off while a stream is in flight must
    // stop it from being reviewed.
    #[test]
    #[file_serial(path)]
    fn stream_rechecks_blind_sign_at_finalize() {
        reset();

        let big = eip1559(AVAX_C_CHAIN_MAINNET_ID, Sign::BUFFER_CAPACITY + 100);
        let (res, rest) = send_init(&big);
        assert_eq!(res, Ok(false));

        crate::utils::set_blind_sign_for_test(false);
        let mut res = Ok(false);
        for chunk in rest.chunks(255) {
            res = apdu(0x80, chunk);
            if res.is_err() {
                break;
            }
        }
        crate::utils::set_blind_sign_for_test(true);

        assert_eq!(res, Err(ParserError::BlindSignNotEnabled));
        assert!(!unsafe { rs_eth_was_streaming_mode_used() });
        assert!(!unsafe { *crate::lock_mut!(STREAMING_MODE).lock(StreamingAccessors::EthSign) });
        reset();
    }

    // AVAX-17: NFT info serves the one request it was provided for; a later
    // request must not pick it up.
    #[test]
    #[cfg(feature = "erc721")]
    #[file_serial(path)]
    fn nft_info_is_claimed_by_one_request() {
        use crate::handlers::eth::provide_nft_info::Info;

        reset();

        const NFT: [u8; 20] = [0xa1; 20];
        let mut descriptor = std::vec![1u8, 1, 4];
        descriptor.extend_from_slice(b"Test");
        descriptor.extend_from_slice(&NFT);
        descriptor.extend_from_slice(&AVAX_C_CHAIN_MAINNET_ID.to_be_bytes());

        // transferFrom(0xc3.., 0xb2.., 1)
        let mut data = hex::decode("23b872dd").unwrap();
        data.extend_from_slice(&[0; 12]);
        data.extend_from_slice(&[0xc3; 20]);
        data.extend_from_slice(&[0; 12]);
        data.extend_from_slice(&[0xb2; 20]);
        let mut token_id = [0; 32];
        token_id[31] = 1;
        data.extend_from_slice(&token_id);

        let mut nft_tx = std::vec![EIP1559_TX];
        nft_tx.extend(list(&[
            uint(AVAX_C_CHAIN_MAINNET_ID as u128),
            uint(1),
            uint(1_000_000_000),
            uint(30_000_000_000),
            uint(100_000),
            item(&NFT),
            uint(0),
            item(&data),
            list(&[]),
        ]));

        let rendered = || {
            let ui = unsafe { crate::lock_mut!(ETH_UI).lock(EthAccessors::Tx) };
            let ui = ui.as_mut().expect("no review stored");
            let mut shown = std::string::String::new();
            for i in 0..ui.num_items().unwrap() {
                let (mut title, mut msg) = ([0u8; 64], [0u8; 256]);
                ui.render_item(i, &mut title, &mut msg, 0).unwrap();
                shown.push_str(std::str::from_utf8(&title).unwrap());
                shown.push_str(std::str::from_utf8(&msg).unwrap());
            }
            shown
        };

        // provided right before: the request uses it
        Info::process(&descriptor).unwrap();
        assert_eq!(send_tx(&nft_tx), Ok(true));
        assert!(rendered().contains("ERC-721"));

        // provided, then an abandoned multi-chunk request
        reset();
        Info::process(&descriptor).unwrap();
        let (res, _) = send_init(&eip1559(AVAX_C_CHAIN_MAINNET_ID, 600));
        assert_eq!(res, Ok(false));

        // the next request was not given NFT info
        assert_eq!(send_tx(&nft_tx), Ok(true));
        assert!(!rendered().contains("ERC-721"), "stale NFT info used");
        reset();
    }

    fn legacy(chain_id: Option<u64>, data_len: usize) -> Vec<u8> {
        let mut fields = std::vec![
            uint(1),
            uint(30_000_000_000),
            uint(100_000),
            item(&[0xa1; 20]),
            uint(0),
            item(&std::vec![0x5a; data_len]),
        ];
        if let Some(id) = chain_id {
            fields.extend([uint(id as u128), item(&[]), item(&[])]);
        }
        list(&fields)
    }

    /// Big legacy tx with the given nonce, chain ID and R items (S empty)
    fn legacy_fields(nonce: Vec<u8>, chain_id: Vec<u8>, r: Vec<u8>) -> Vec<u8> {
        list(&[
            nonce,
            uint(30_000_000_000),
            uint(100_000),
            item(&[0xa1; 20]),
            uint(0),
            item(&std::vec![0x5a; Sign::BUFFER_CAPACITY + 100]),
            chain_id,
            r,
            item(&[]),
        ])
    }

    fn eip1559_big(chain_id: u64) -> Vec<u8> {
        eip1559(chain_id, Sign::BUFFER_CAPACITY + 100)
    }

    fn legacy_big(chain_id: Option<u64>) -> Vec<u8> {
        legacy(chain_id, Sign::BUFFER_CAPACITY + 100)
    }

    fn ui_signing_info() -> (bool, Option<u64>) {
        match unsafe { crate::lock_mut!(ETH_UI).lock(EthAccessors::Tx) } {
            Some(EthUi::Tx(ui)) => (ui.is_typed, ui.chain_id.map(u64::from_be_bytes)),
            _ => panic!("no tx review stored"),
        }
    }

    // AVAX-32: a streamed typed transaction must be signed as typed, with
    // the chain ID it carries.
    #[test]
    #[file_serial(path)]
    fn streamed_tx_keeps_type_and_chain_id() {
        reset();
        let tx = eip1559_big(AVAX_C_CHAIN_MAINNET_ID);
        assert_eq!(send_tx(&tx), Ok(true));
        assert_eq!(ui_signing_info(), (true, Some(AVAX_C_CHAIN_MAINNET_ID)));
        assert_eq!(ui_hash(), keccak(&tx));

        for chain_id in [AVAX_C_CHAIN_MAINNET_ID, 256, 324846] {
            reset();
            let tx = legacy_big(Some(chain_id));
            assert_eq!(send_tx(&tx), Ok(true));
            assert_eq!(ui_signing_info(), (false, Some(chain_id)));
            assert_eq!(ui_hash(), keccak(&tx));
        }
        reset();
    }

    // AVAX-19: the chain-ID policy of normal mode applies to streamed
    // transactions too.
    #[test]
    #[file_serial(path)]
    fn streamed_tx_follows_chain_id_policy() {
        let accepted = [
            ("typed on chain 1", eip1559_big(1)),
            ("typed on chain 0", eip1559_big(0)),
            ("legacy on chain 1", legacy_big(Some(1))),
            ("legacy on chain 37", legacy_big(Some(37))),
            ("pre-EIP-155 legacy", legacy_big(None)),
            ("typed, chain ID as a list", {
                let mut tx = std::vec![EIP1559_TX];
                tx.extend(list(&[
                    list(&[uint(AVAX_C_CHAIN_MAINNET_ID as u128)]),
                    item(&std::vec![0x5a; Sign::BUFFER_CAPACITY + 100]),
                ]));
                tx
            }),
            (
                "legacy, chain ID as a list",
                legacy_fields(
                    list(&[]),
                    list(&[uint(AVAX_C_CHAIN_MAINNET_ID as u128)]),
                    item(&[]),
                ),
            ),
            (
                "legacy, R as a list",
                legacy_fields(list(&[]), uint(AVAX_C_CHAIN_MAINNET_ID as u128), list(&[])),
            ),
            (
                "legacy, a field as a list",
                legacy_fields(
                    list(&[uint(1)]),
                    uint(AVAX_C_CHAIN_MAINNET_ID as u128),
                    item(&[]),
                ),
            ),
        ]
        .into_iter()
        .filter(|(_, tx)| {
            reset();
            send_tx(tx).is_ok() || unsafe { rs_eth_was_streaming_mode_used() }
        })
        .map(|(name, _)| name)
        .collect::<Vec<_>>();
        reset();
        assert!(accepted.is_empty(), "accepted: {accepted:?}");
    }

    // The legacy chain ID is read from the end of the stream, however the
    // host splits the chunks.
    #[test]
    #[file_serial(path)]
    fn streamed_legacy_chain_id_survives_small_chunks() {
        reset();
        let tx = legacy_big(Some(AVAX_C_CHAIN_MAINNET_ID));
        let (res, rest) = send_init(&tx);
        assert_eq!(res, Ok(false));

        let (body, end) = rest.split_at(rest.len() - 6);
        for chunk in body.chunks(255) {
            assert_eq!(apdu(0x80, chunk), Ok(false));
        }
        let mut res = Ok(false);
        for byte in end.chunks(1) {
            res = apdu(0x80, byte);
        }
        assert_eq!(res, Ok(true));
        assert_eq!(ui_signing_info(), (false, Some(AVAX_C_CHAIN_MAINNET_ID)));
        assert_eq!(ui_hash(), keccak(&tx));
        reset();
    }

    // Bytes sent past the end of a streamed transaction are not signed,
    // as in normal mode.
    #[test]
    #[file_serial(path)]
    fn streamed_bytes_past_the_end_are_ignored() {
        reset();
        let tx = eip1559_big(AVAX_C_CHAIN_MAINNET_ID);
        let mut padded = tx.clone();
        padded.extend_from_slice(&[0xee; 7]);

        assert_eq!(send_tx(&padded), Ok(true));
        assert_eq!(ui_hash(), keccak(&tx));
        reset();
    }

    // A streamed transaction is stored without a parsed transaction, so its
    // review can only be rendered as a hash.
    #[test]
    #[file_serial(path)]
    fn streamed_review_holds_no_transaction() {
        reset();
        assert_eq!(send_tx(&eip1559_big(AVAX_C_CHAIN_MAINNET_ID)), Ok(true));

        let ui = unsafe { crate::lock_mut!(ETH_UI).lock(EthAccessors::Tx) };
        let ui = ui.as_mut().expect("no review stored");
        assert!(ui.num_items().is_err());
        let (mut title, mut msg) = ([0u8; 64], [0u8; 256]);
        assert!(ui.render_item(0, &mut title, &mut msg, 0).is_err());
        reset();
    }

    // A review with no chain ID for a legacy transaction is never signed,
    // whatever built it.
    #[test]
    #[file_serial(path)]
    fn legacy_review_without_chain_id_is_not_signed() {
        reset();
        let tx = eip1559(AVAX_C_CHAIN_MAINNET_ID, 10);
        assert_eq!(send_tx(&tx), Ok(true));

        let mut ui = SignUI {
            hash: keccak(&tx),
            tx: None,
            is_typed: false,
            chain_id: None,
        };
        let mut out = [0; 100];
        assert_eq!(ui.accept(&mut out), (0, Error::DataInvalid as u16));
        reset();
    }
}
