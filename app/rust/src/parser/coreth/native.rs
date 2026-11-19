/*******************************************************************************
*   (c) 2022 Zondax AG
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
use core::ptr::addr_of_mut;

use nom::bytes::complete::take;
use zemu_sys::ViewError;

use crate::{
    handlers::{eth::u256, handle_ui_message},
    parser::{
        intstr_to_fpstr_inplace, DisplayableItem, FromBytes, ParserError, AVAX_C_CHAIN_FUJI_ID,
        AVAX_C_CHAIN_LOCAL_ID, AVAX_C_CHAIN_MAINNET_ID, EIP1559_TX, EIP2930_TX, U64_FORMATTED_SIZE,
        U64_SIZE,
    },
};

mod legacy;
pub use legacy::Legacy;
mod base;
pub use base::BaseLegacy;
mod sign_msg;
pub use sign_msg::PersonalMsg;

mod eip1559;
pub use eip1559::Eip1559;
mod eip2930;
pub use eip2930::Eip2930;

/// Renders an u256 in bytes.
/// `input`: The big-indian bytes of the number to
/// be rendered
#[inline(never)]
pub fn render_u256(
    num: &[u8],
    decimal_point: usize,
    message: &mut [u8],
    page: u8,
) -> Result<u8, ViewError> {
    let mut u256_str = [0; u256::FORMATTED_SIZE_DECIMAL + 2];

    let amount = u256::pic_from_big_endian()(num);
    amount.to_lexical(&mut u256_str);

    let out =
        intstr_to_fpstr_inplace(&mut u256_str, decimal_point).map_err(|_| ViewError::Unknown)?;

    handle_ui_message(out, message, page)
}

/// Returns `true` when `chain_id` is one of the AVAX C-Chain EVM IDs
/// (43114 mainnet, 43113 Fuji, 43112 local devnet). Anything else is
/// treated as a foreign chain for ticker-symbol and blind-sign decisions.
pub fn is_avax_chain(chain_id: u64) -> bool {
    chain_id == AVAX_C_CHAIN_MAINNET_ID
        || chain_id == AVAX_C_CHAIN_FUJI_ID
        || chain_id == AVAX_C_CHAIN_LOCAL_ID
}

/// Big-endian RLP byte slice variant of `is_avax_chain`. Returns `false` on
/// parse failure (slice longer than 8 bytes), so callers conservatively treat
/// malformed input as foreign — the safer default for the display + blind-sign
/// gate.
pub fn is_avax_chain_bytes(chain_id: &[u8]) -> bool {
    bytes_to_u64(chain_id).map(is_avax_chain).unwrap_or(false)
}

// Converts an slice of bytes in big-endian
// to an u64 integer
pub fn bytes_to_u64(input: &[u8]) -> Result<u64, ParserError> {
    let mut raw = [0; U64_SIZE];

    if input.len() <= U64_SIZE {
        raw[U64_SIZE - input.len()..].copy_from_slice(input);
        return Ok(u64::from_be_bytes(raw));
    }
    Err(ParserError::ValueOutOfRange)
}

/// Returns the remaining bytes from data along with the bytes
/// representation of the found item
pub fn parse_rlp_item(data: &[u8]) -> Result<(&[u8], &[u8]), nom::Err<ParserError>> {
    let read = 0;

    let marker = *data.first().ok_or(ParserError::UnexpectedBufferEnd)?;

    let (read, to_read) = match marker {
        _num @ 0..=0x7F => return Ok((&data[1..], &data[0..1])),
        sstring @ 0x80..=0xB7 => (1, sstring as u64 - 0x80),
        string @ 0xB8..=0xBF => {
            // For strings longer than 55 bytes the length is encoded
            // differently.
            // The number of bytes that compose the length is encoded
            // in the marker
            // And then the length is just the number BE encoded
            let num_bytes = string as usize - 0xB7;
            let num = data
                .get(1..)
                .ok_or(ParserError::UnexpectedBufferEnd)?
                .get(..num_bytes)
                .ok_or(ParserError::UnexpectedBufferEnd)?;

            let mut array = [0; U64_SIZE];
            array[U64_SIZE - num_bytes..].copy_from_slice(num);

            let num = u64::from_be_bytes(array);
            (1 + num_bytes, num)
        }
        slist @ 0xC0..=0xF7 => (read + 1, slist as u64 - 0xC0),
        list @ 0xF8.. => {
            // For lists longer than 55 bytes the length is encoded
            // differently.
            // The number of bytes that compose the length is encoded
            // in the marker
            // And then the length is just the number BE encoded

            let num_bytes = list as usize - 0xF7;
            let num = data
                .get(1..)
                .ok_or(ParserError::UnexpectedBufferEnd)?
                .get(..num_bytes)
                .ok_or(ParserError::UnexpectedBufferEnd)?;

            let mut array = [0; U64_SIZE];
            array[U64_SIZE - num_bytes..].copy_from_slice(num);

            let num = u64::from_be_bytes(array);
            (1 + num_bytes, num)
        }
    };

    take(to_read as usize)(&data[read..])
}

pub fn render_chain_id(
    title: &mut [u8],
    message: &mut [u8],
    page: u8,
    chain_id: &[u8],
) -> Result<u8, ViewError> {

    let title_content = b"Chain ID";
    title[..title_content.len()].copy_from_slice(title_content);

    if chain_id.len() <= core::mem::size_of::<u64>() {
        let chain_id = bytes_to_u64(chain_id).map_err(|_| ViewError::NoData)?;
        let mut chain_id_str = [0u8; U64_FORMATTED_SIZE + 1];

        crate::parser::u64_to_str(chain_id, &mut chain_id_str).map_err(|_| ViewError::NoData)?;

        handle_ui_message(&chain_id_str, message, page)
    } else {
        render_u256(chain_id, 0, message, page)
    }
}

impl From<u8> for EthTransaction__Type {
    fn from(value: u8) -> Self {
        match value {
            EIP1559_TX => Self::Eip1559,
            EIP2930_TX => Self::Eip2930,
            // legacy is constructed
            _ => Self::Legacy,
        }
    }
}

impl EthTransaction__Type {
    fn from_bytes(input: &[u8]) -> Result<(&[u8], Self), ParserError> {
        if input.is_empty() {
            return Err(ParserError::UnexpectedBufferEnd);
        }

        let tx_type = input.first().ok_or(ParserError::UnexpectedBufferEnd)?;

        match *tx_type {
            EIP1559_TX => Ok((&input[1..], Self::Eip1559)),
            EIP2930_TX => Ok((&input[1..], Self::Eip2930)),
            // legacy transaction does not have a version so just parse
            // it, if it is not valid, the parser will error anyways
            _ => Ok((input, Self::Legacy)),
        }
    }
}

#[avalanche_app_derive::enum_init]
#[derive(Clone, Copy, PartialEq, Eq)]
// DO not change the representation
// as it would cause unalignment issues
// with the OutputType tag
#[cfg_attr(test, derive(Debug))]
pub enum EthTransaction<'b> {
    Legacy(Legacy<'b>),
    Eip1559(Eip1559<'b>),
    Eip2930(Eip2930<'b>),
}

impl EthTransaction<'_> {
    pub fn is_typed_tx(&self) -> bool {
        !matches!(self, EthTransaction::Legacy(_))
    }

    pub fn chain_id(&self) -> &[u8] {
        match self {
            Self::Legacy(t) => t.chain_id(),
            Self::Eip1559(t) => t.chain_id(),
            Self::Eip2930(t) => t.chain_id(),
        }
    }

    /// Whether the review of this transaction leaves signed bytes off the
    /// screen (see [`crate::parser::EthData::requires_blind_signing`]), so
    /// that it may only be signed with blind signing enabled.
    pub fn requires_blind_signing(&self) -> bool {
        let data = match self {
            Self::Legacy(t) => &t.base.data,
            Self::Eip1559(t) => t.data(),
            Self::Eip2930(t) => &t.base.data,
        };

        data.requires_blind_signing()
    }
}

impl<'b> FromBytes<'b> for EthTransaction<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        // get transaction data as the eip2718 defines transactions structure as follow:
        // version || rlp[tx_fields]
        // version for eip1559 = 2,
        // for eip2930 = 1,
        // for legacy it does not have a version
        let (rem, tx_type) = EthTransaction__Type::from_bytes(input)?;

        // parse rlp[] part in order to get the transaction bytes
        let (rem, tx_bytes) = parse_rlp_item(rem)?;

        if tx_bytes.is_empty() {
            return Err(ParserError::UnexpectedBufferEnd.into());
        }

        match tx_type {
            EthTransaction__Type::Legacy => {
                let out = out.as_mut_ptr() as *mut Legacy__Variant;

                let legacy = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                // read all the data as the contract deployment
                // we do not have a way to verify this data. in the worst scenario
                // the transaction would be rejected, and for this reason
                // It is shown on the screen(partially) for the user to review.
                _ = Legacy::from_bytes_into(tx_bytes, legacy)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(EthTransaction__Type::Legacy);
                }
            }
            EthTransaction__Type::Eip1559 => {
                let out = out.as_mut_ptr() as *mut Eip1559__Variant;

                let eip = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                // read all the data as the contract deployment
                // we do not have a way to verify this data. in the worst scenario
                // the transaction would be rejected, and for this reason
                // It is shown on the screen(partially) for the user to review.
                _ = Eip1559::from_bytes_into(tx_bytes, eip)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(EthTransaction__Type::Eip1559);
                }
            }
            EthTransaction__Type::Eip2930 => {
                let out = out.as_mut_ptr() as *mut Eip2930__Variant;

                let eip = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                // read all the data as the contract deployment
                // we do not have a way to verify this data. in the worst scenario
                // the transaction would be rejected, and for this reason
                // It is shown on the screen(partially) for the user to review.
                _ = Eip2930::from_bytes_into(tx_bytes, eip)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(EthTransaction__Type::Eip2930);
                }
            }
        }
        Ok(rem)
    }
}

impl DisplayableItem for EthTransaction<'_> {
    fn num_items(&self) -> Result<u8, ViewError> {
        match self {
            Self::Legacy(t) => t.num_items(),
            Self::Eip1559(t) => t.num_items(),
            Self::Eip2930(t) => t.num_items(),
        }
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        match self {
            Self::Legacy(t) => t.render_item(item_n, title, message, page),
            Self::Eip1559(t) => t.render_item(item_n, title, message, page),
            Self::Eip2930(t) => t.render_item(item_n, title, message, page),
        }
    }
}

/// Minimal RLP encoder used to build transactions in tests
#[cfg(test)]
pub(crate) mod rlp_test_utils {
    use std::vec::Vec;

    fn header(offset: u8, len: usize) -> Vec<u8> {
        if len <= 55 {
            std::vec![offset + len as u8]
        } else {
            let be = (len as u64).to_be_bytes();
            let skip = be.iter().take_while(|b| **b == 0).count();
            let mut out = std::vec![offset + 55 + (8 - skip) as u8];
            out.extend_from_slice(&be[skip..]);
            out
        }
    }

    /// Encode a byte string
    pub fn item(bytes: &[u8]) -> Vec<u8> {
        if bytes.len() == 1 && bytes[0] < 0x80 {
            return bytes.to_vec();
        }
        let mut out = header(0x80, bytes.len());
        out.extend_from_slice(bytes);
        out
    }

    /// Encode an unsigned integer (minimal big-endian)
    pub fn uint(v: u128) -> Vec<u8> {
        let be = v.to_be_bytes();
        let skip = be.iter().take_while(|b| **b == 0).count();
        item(&be[skip..])
    }

    /// Encode a list of already encoded items
    pub fn list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload: Vec<u8> = items.concat();
        let mut out = header(0xC0, payload.len());
        out.extend(payload);
        out
    }
}

#[cfg(test)]
mod tests {
    use std::prelude::v1::*;

    use zemu_sys::Viewable;

    use super::*;

    impl Viewable for EthTransaction<'static> {
        fn num_items(&mut self) -> Result<u8, zemu_sys::ViewError> {
            DisplayableItem::num_items(&*self)
        }

        fn render_item(
            &mut self,
            item_idx: u8,
            title: &mut [u8],
            message: &mut [u8],
            page_idx: u8,
        ) -> Result<u8, zemu_sys::ViewError> {
            DisplayableItem::render_item(&*self, item_idx, title, message, page_idx)
        }

        fn accept(&mut self, _: &mut [u8]) -> (usize, u16) {
            (0, 0)
        }

        fn reject(&mut self, _: &mut [u8]) -> (usize, u16) {
            (0, 0)
        }
    }

    #[test]
    fn is_avax_chain_classifies_known_ids() {
        assert!(is_avax_chain(AVAX_C_CHAIN_MAINNET_ID));
        assert!(is_avax_chain(AVAX_C_CHAIN_FUJI_ID));
        assert!(is_avax_chain(AVAX_C_CHAIN_LOCAL_ID));
        assert!(!is_avax_chain(0)); // NONE
        assert!(!is_avax_chain(1)); // ETH mainnet
        assert!(!is_avax_chain(2)); // synthetic test value
        assert!(!is_avax_chain(5)); // Goerli (foreign)
        assert!(!is_avax_chain(324846)); // Orange L1
    }

    #[test]
    fn is_avax_chain_bytes_handles_be_slices_and_garbage() {
        // 43114 = 0xA86A
        assert!(is_avax_chain_bytes(&[0xa8, 0x6a]));
        // 43113 = 0xA869
        assert!(is_avax_chain_bytes(&[0xa8, 0x69]));
        // 43112 = 0xA868 (local devnet)
        assert!(is_avax_chain_bytes(&[0xa8, 0x68]));
        // padded to 8 bytes still works
        assert!(is_avax_chain_bytes(&[0, 0, 0, 0, 0, 0, 0xa8, 0x6a]));
        // 1 = ETH mainnet → foreign
        assert!(!is_avax_chain_bytes(&[1]));
        // Empty slice → 0 → foreign (conservative default)
        assert!(!is_avax_chain_bytes(&[]));
        // 9 bytes → bytes_to_u64 errors → foreign (conservative default)
        assert!(!is_avax_chain_bytes(&[0, 0, 0, 0, 0, 0, 0, 0xa8, 0x6a]));
    }

    /// Parse `data` as an [`EthTransaction`] and return every rendered page
    /// as `"title: message"`.
    pub(crate) fn render_all(data: Vec<u8>) -> Vec<String> {
        use crate::parser::snapshots_common::{with_leaked, ReducedPage};

        unsafe {
            with_leaked(data, |data| {
                let (_, tx) = EthTransaction::from_bytes(data).expect("parse tx from data");

                let mut driver = zuit::MockDriver::<_, 18, 1024>::new(tx);
                driver.drive();

                driver
                    .out_ui()
                    .iter()
                    .flat_map(|item| {
                        item.iter()
                            .map(|p| std::format!("{}", ReducedPage::from(p)))
                    })
                    .collect()
            })
        }
    }

    const EOA: [u8; 20] = [0xa1; 20];
    const RECIPIENT: [u8; 20] = [0xb2; 20];
    // 100 AVAX in wei
    const HUNDRED_AVAX: u128 = 100_000_000_000_000_000_000;

    fn erc20_transfer_calldata() -> Vec<u8> {
        let mut data = hex::decode("a9059cbb").unwrap();
        data.extend_from_slice(&[0; 12]);
        data.extend_from_slice(&RECIPIENT);
        let mut amount = [0; 32];
        amount[31] = 1;
        data.extend_from_slice(&amount);
        data
    }

    fn eip1559_tx(chain_id: u64, to: &[u8], value: u128, data: &[u8]) -> Vec<u8> {
        use rlp_test_utils::*;
        let mut tx = std::vec![EIP1559_TX];
        tx.extend(list(&[
            uint(chain_id as u128),
            uint(1),
            uint(1_000_000_000),
            uint(30_000_000_000),
            uint(100_000),
            item(to),
            uint(value),
            item(data),
            list(&[]),
        ]));
        tx
    }

    fn legacy_tx(chain_id: u64, to: &[u8], value: u128, data: &[u8]) -> Vec<u8> {
        use rlp_test_utils::*;
        list(&[
            uint(1),
            uint(30_000_000_000),
            uint(100_000),
            item(to),
            uint(value),
            item(data),
            uint(chain_id as u128),
            item(&[]),
            item(&[]),
        ])
    }

    fn eip2930_tx(chain_id: u64, to: &[u8], value: u128, data: &[u8]) -> Vec<u8> {
        use rlp_test_utils::*;
        let mut tx = std::vec![EIP2930_TX];
        tx.extend(list(&[
            uint(chain_id as u128),
            uint(1),
            uint(30_000_000_000),
            uint(100_000),
            item(to),
            uint(value),
            item(data),
            list(&[]),
        ]));
        tx
    }

    fn shows_native_value(pages: &[String]) -> bool {
        pages.iter().any(|p| p == "\"Value\": \"AVAX 100\"")
    }

    // AVAX-04: a token-shaped call to an EOA that also carries native value
    // must put the native amount on screen.
    #[test]
    fn erc20_call_with_native_value_shows_value() {
        let data = erc20_transfer_calldata();
        let hidden: Vec<_> = [
            (
                "eip1559",
                eip1559_tx(AVAX_C_CHAIN_MAINNET_ID, &EOA, HUNDRED_AVAX, &data),
            ),
            (
                "eip2930",
                eip2930_tx(AVAX_C_CHAIN_MAINNET_ID, &EOA, HUNDRED_AVAX, &data),
            ),
            (
                "legacy",
                legacy_tx(AVAX_C_CHAIN_MAINNET_ID, &EOA, HUNDRED_AVAX, &data),
            ),
        ]
        .into_iter()
        .filter(|(_, tx)| {
            let pages = render_all(tx.clone());
            // the token view is kept, with the native value next to it
            !(shows_native_value(&pages)
                && pages.iter().any(|p| p == "\"ERC-20\": \"transfer\"")
                && pages.iter().any(|p| p == "\"Amount\": \"1\""))
        })
        .map(|(name, _)| name)
        .collect();
        assert!(hidden.is_empty(), "native value hidden for {hidden:?}");
    }

    /// The Smol Joes collection on the C-Chain, for which Ledger's NFT
    /// metadata service signs a descriptor
    #[cfg(feature = "erc721")]
    const SMOL_JOES: [u8; 20] = [
        0xc7, 0x0d, 0xf8, 0x7e, 0x1d, 0x98, 0xf6, 0xa5, 0x31, 0xc8, 0xe3, 0x24, 0xc9, 0xbc, 0xec,
        0x6f, 0xc8, 0x2b, 0x5e, 0x8d,
    ];

    /// Store `descriptor` as INS_PROVIDE_NFT_INFORMATION does, and return
    /// whether its signature verified.
    #[cfg(feature = "erc721")]
    fn provide_nft_descriptor(descriptor: &[u8]) -> bool {
        let info = crate::parser::SignedNftDescriptor::parse(descriptor)
            .and_then(|d| d.info())
            .unwrap();
        let verified = info.verified();
        crate::parser::ERC721Info::set_info(info).unwrap();
        verified
    }

    /// Store the Ledger-signed Smol Joes descriptor, as
    /// INS_PROVIDE_NFT_INFORMATION does.
    #[cfg(feature = "erc721")]
    fn provide_smol_joes_info() {
        let descriptor = hex::decode(crate::parser::nft_info_test_vectors::SMOL_JOES).unwrap();
        assert!(provide_nft_descriptor(&descriptor));
    }

    /// An NFT descriptor shaped like the JS SDK's provideNFTInformation
    /// builds it: the production key and algorithm ids, and 70 random bytes
    /// for a signature.
    #[cfg(feature = "erc721")]
    fn sdk_nft_descriptor(name: &[u8], contract: &[u8; 20]) -> Vec<u8> {
        let mut descriptor = std::vec![1u8, 1, name.len() as u8];
        descriptor.extend_from_slice(name);
        descriptor.extend_from_slice(contract);
        descriptor.extend_from_slice(&AVAX_C_CHAIN_MAINNET_ID.to_be_bytes());
        descriptor.extend_from_slice(&[1, 1, 70]);
        descriptor.extend((0..70u8).map(|i| i.wrapping_mul(97) ^ 0x5a));
        descriptor
    }

    /// transferFrom(0xc3.., RECIPIENT, 1)
    pub(crate) fn erc721_transfer_from_calldata() -> Vec<u8> {
        let mut data = hex::decode("23b872dd").unwrap();
        data.extend_from_slice(&[0; 12]);
        data.extend_from_slice(&[0xc3; 20]);
        data.extend_from_slice(&[0; 12]);
        data.extend_from_slice(&RECIPIENT);
        let mut token_id = [0; 32];
        token_id[31] = 1;
        data.extend_from_slice(&token_id);
        data
    }

    #[test]
    #[cfg(feature = "erc721")]
    #[serial_test::file_serial(path)]
    fn erc721_call_with_native_value_shows_value() {
        provide_smol_joes_info();
        let data = erc721_transfer_from_calldata();

        let hidden: Vec<_> = [
            (
                "eip1559",
                eip1559_tx(AVAX_C_CHAIN_MAINNET_ID, &SMOL_JOES, HUNDRED_AVAX, &data),
            ),
            (
                "legacy",
                legacy_tx(AVAX_C_CHAIN_MAINNET_ID, &SMOL_JOES, HUNDRED_AVAX, &data),
            ),
        ]
        .into_iter()
        .filter(|(_, tx)| {
            let pages = render_all(tx.clone());
            !(shows_native_value(&pages) && pages.iter().any(|p| p.contains("ERC-721")))
        })
        .map(|(name, _)| name)
        .collect();
        assert!(hidden.is_empty(), "native value hidden for {hidden:?}");
    }

    #[test]
    fn erc20_call_without_native_value_has_no_value_screen() {
        let pages = render_all(eip1559_tx(
            AVAX_C_CHAIN_MAINNET_ID,
            &EOA,
            0,
            &erc20_transfer_calldata(),
        ));
        assert!(pages.iter().any(|p| p.contains("ERC-20")), "{pages:#?}");
        assert!(!pages.iter().any(|p| p.contains("Value")), "{pages:#?}");
    }

    /// Selector the app does not decode, followed by two ABI words
    fn unknown_call_calldata() -> Vec<u8> {
        let mut data = hex::decode("deadbeef").unwrap();
        data.extend_from_slice(&[0x11; 64]);
        data
    }

    // V-028: a deployment or a call the app does not decode is only shown as
    // a preview of its data, in every transaction flavour; decoded data and
    // plain transfers are shown in full.
    #[test]
    fn opaque_data_requires_blind_signing() {
        // nativeAssetCall precompile: asset transfer (address, asset, amount)
        let mut asset_precompile = [0u8; 20];
        asset_precompile[0] = 0x01;
        asset_precompile[19] = 0x02;
        let mut asset_call = std::vec![0xc3; 20];
        asset_call.extend_from_slice(&[0x77; 32]);
        asset_call.extend_from_slice(&[0x01; 32]);

        let init_code = std::vec![0x60, 0x80, 0x60, 0x40, 0x52];

        // name, to, value, data, whether it is blind signing
        type Case<'a> = (&'a str, &'a [u8], u128, Vec<u8>, bool);
        let cases: [Case; 5] = [
            ("unknown call", &EOA, 0, unknown_call_calldata(), true),
            ("deploy", &[], 0, init_code, true),
            ("transfer", &RECIPIENT, HUNDRED_AVAX, std::vec![], false),
            ("erc20 transfer", &EOA, 0, erc20_transfer_calldata(), false),
            ("asset call", &asset_precompile, 0, asset_call, false),
        ];

        let mut wrong = Vec::new();
        for flavour in FLAVOURS {
            for (name, to, value, data, blind) in &cases {
                let res = requires_blind_signing_in(flavour, to, *value, data);
                if res != Ok(*blind) {
                    wrong.push(std::format!("{flavour} {name}: {res:?}"));
                }
            }
        }
        assert!(wrong.is_empty(), "misclassified: {wrong:?}");
    }

    /// A `flavour` transaction on the C-Chain
    fn c_chain_tx(flavour: &str, to: &[u8], value: u128, data: &[u8]) -> Vec<u8> {
        let id = AVAX_C_CHAIN_MAINNET_ID;
        match flavour {
            "legacy" => legacy_tx(id, to, value, data),
            "eip2930" => eip2930_tx(id, to, value, data),
            _ => eip1559_tx(id, to, value, data),
        }
    }

    // V-028: the data of a call the app does not decode, or of a deployment,
    // is reviewed by its selector (calls only), length and keccak-256 hash,
    // in every flavour, with and without native value; the fee stays the
    // last screen. render_all drives the review like the device does, so a
    // hole or an item count out of step with the screens fails it.
    #[test]
    fn opaque_data_shows_selector_length_and_hash() {
        use bolos::hash::{Hasher, Keccak};

        let call = unknown_call_calldata();
        let init_code = std::vec![0x60, 0x80, 0x60, 0x40, 0x52, 0x34, 0x80, 0x15];
        let screen =
            |title: &str, value: std::string::String| std::format!("\"{title}\": \"{value}\"");
        let hash = |data: &[u8]| {
            let h = Keccak::<32>::digest(data).unwrap();
            std::format!("0x{}", hex::encode(h))
        };

        let mut wrong = Vec::new();
        for flavour in FLAVOURS {
            for value in [0, HUNDRED_AVAX] {
                // name, to, data, the screens expected for the data
                type Case<'a> = (&'a str, &'a [u8], &'a [u8], Vec<String>);
                let cases: [Case; 2] = [
                    (
                        "call",
                        &EOA,
                        &call,
                        std::vec![
                            screen("Function", "0xdeadbeef".into()),
                            screen("Data Length", "68 bytes".into()),
                            screen("Data Hash", hash(&call)),
                        ],
                    ),
                    (
                        "deploy",
                        &[],
                        &init_code,
                        std::vec![
                            screen("Data Length", "8 bytes".into()),
                            screen("Data Hash", hash(&init_code)),
                        ],
                    ),
                ];
                for (name, to, data, expected) in cases {
                    let pages = render_all(c_chain_tx(flavour, to, value, data));
                    let start = pages.iter().position(|p| *p == expected[0]);
                    let shown = start.map(|i| &pages[i..]);
                    let ok = shown.is_some_and(|s| {
                        // the data screens, then the fee and nothing else
                        s.len() == expected.len() + 1
                            && s[..expected.len()] == expected[..]
                            && s[expected.len()].contains("Fee")
                    });
                    if !ok {
                        wrong.push(std::format!("{flavour} {name} value={value}: {pages:#?}"));
                    }
                }
            }
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    const FLAVOURS: [&str; 3] = ["legacy", "eip2930", "eip1559"];

    /// Parse a `flavour` transaction on the C-Chain and tell whether it
    /// requires blind signing
    fn requires_blind_signing_in(
        flavour: &str,
        to: &[u8],
        value: u128,
        data: &[u8],
    ) -> Result<bool, ParserError> {
        let id = AVAX_C_CHAIN_MAINNET_ID;
        let raw = match flavour {
            "legacy" => legacy_tx(id, to, value, data),
            "eip2930" => eip2930_tx(id, to, value, data),
            _ => eip1559_tx(id, to, value, data),
        };
        let (_, tx) = EthTransaction::from_bytes(&raw)?;
        Ok(tx.requires_blind_signing())
    }

    /// safeTransferFrom(0xc3.., RECIPIENT, 1), the 3-argument form
    #[cfg(feature = "erc721")]
    fn erc721_safe_transfer_from_calldata() -> Vec<u8> {
        let mut data = erc721_transfer_from_calldata();
        data[..4].copy_from_slice(&[0x42, 0x84, 0x2e, 0x0e]);
        data
    }

    /// safeTransferFrom(0xc3.., RECIPIENT, 1, `bytes`), the 4-argument form,
    /// followed by `tail`: the ABI encoding of the `bytes` argument
    #[cfg(feature = "erc721")]
    fn erc721_safe_transfer_from_with(tail: &[u8]) -> Vec<u8> {
        let mut data = erc721_transfer_from_calldata();
        data[..4].copy_from_slice(&[0xb8, 0x8d, 0x4f, 0xde]);
        data.extend_from_slice(tail);
        data
    }

    /// ABI encoding of a `bytes` argument after four head words
    #[cfg(feature = "erc721")]
    fn abi_bytes(content: &[u8]) -> Vec<u8> {
        let word = |v: usize| {
            let mut w = [0u8; 32];
            w[24..].copy_from_slice(&(v as u64).to_be_bytes());
            w
        };
        let mut out = word(4 * 32).to_vec();
        out.extend_from_slice(&word(content.len()));
        out.extend_from_slice(content);
        out.resize(64 + content.len().div_ceil(32) * 32, 0);
        out
    }

    // V-107: an amount using every digit of a uint256 is rendered, for a
    // token approval and for the native value alike.
    #[test]
    fn full_width_amounts_render() {
        use rlp_test_utils::*;
        const USDC_E: [u8; 20] = [
            0xA7, 0xD7, 0x07, 0x9B, 0x0F, 0xEA, 0xD9, 0x1F, 0x3E, 0x65, 0xF8, 0x6E, 0x89, 0x15,
            0xCB, 0x59, 0xC1, 0xA4, 0xC6, 0x64,
        ];

        // approve(RECIPIENT, MAX - 1)
        let mut data = hex::decode("095ea7b3").unwrap();
        data.extend_from_slice(&[0; 12]);
        data.extend_from_slice(&RECIPIENT);
        data.extend_from_slice(&[0xff; 31]);
        data.push(0xfe);
        let pages = render_all(eip1559_tx(AVAX_C_CHAIN_MAINNET_ID, &USDC_E, 0, &data));
        let amount = "\"Amount\": \"115792089237316195423570985008687907853269984665640564039457584007913129.639934 USDC.e\"";
        assert!(pages.iter().any(|p| p == amount), "{pages:#?}");

        // MAX wei sent to an EOA
        let mut tx = std::vec![EIP1559_TX];
        tx.extend(list(&[
            uint(AVAX_C_CHAIN_MAINNET_ID as u128),
            uint(1),
            uint(1_000_000_000),
            uint(30_000_000_000),
            uint(100_000),
            item(&RECIPIENT),
            item(&[0xff; 32]),
            item(&[]),
            list(&[]),
        ]));
        let pages = render_all(tx);
        let value =
            "AVAX 115792089237316195423570985008687907853269984665640564039457.584007913129639935";
        assert!(pages.iter().any(|p| p.contains(value)), "{pages:#?}");
    }

    // V-028: the ERC-721 parser decodes every call in full but the `bytes
    // data` of safeTransferFrom, which is not shown: passing any makes the
    // call blind signing, and the 3-argument form carries no more bytes.
    #[test]
    #[cfg(feature = "erc721")]
    #[serial_test::file_serial(path)]
    fn erc721_hidden_data_requires_blind_signing() {
        provide_smol_joes_info();

        let safe = erc721_safe_transfer_from_calldata();
        let mut safe_trailing_word = safe.clone();
        safe_trailing_word.extend_from_slice(&[0x11; 32]);
        let mut safe_trailing_byte = safe.clone();
        safe_trailing_byte.push(0x11);

        let mut non_canonical_empty = abi_bytes(&[]);
        non_canonical_empty[31] = 0xa0;
        non_canonical_empty.extend_from_slice(&[0; 32]);

        // the ERC-721 parser refuses bytes past the 3-argument form...
        for data in [&safe_trailing_word, &safe_trailing_byte] {
            let mut contract = core::mem::MaybeUninit::uninit();
            crate::parser::Address::from_bytes_into(&SMOL_JOES, &mut contract).unwrap();
            let contract = unsafe { contract.assume_init() };
            let mut call = core::mem::MaybeUninit::uninit();
            assert_eq!(
                crate::parser::coreth::data::ERC721::parse_into(&contract, data, &mut call),
                Err(ParserError::UnexpectedData)
            );
        }

        // ...so such a call is only a generic contract call
        let cases: [(&str, Vec<u8>, Result<bool, ParserError>); 8] = [
            ("transferFrom", erc721_transfer_from_calldata(), Ok(false)),
            ("safeTransferFrom", safe, Ok(false)),
            ("safeTransferFrom + word", safe_trailing_word, Ok(true)),
            ("safeTransferFrom + byte", safe_trailing_byte, Ok(true)),
            (
                "safeTransferFrom(bytes) empty",
                erc721_safe_transfer_from_with(&abi_bytes(&[])),
                Ok(false),
            ),
            (
                "safeTransferFrom(bytes) data",
                erc721_safe_transfer_from_with(&abi_bytes(&[0xde, 0xad, 0xbe, 0xef])),
                Ok(true),
            ),
            (
                "safeTransferFrom(bytes) empty, non-canonical",
                erc721_safe_transfer_from_with(&non_canonical_empty),
                Ok(true),
            ),
            (
                "safeTransferFrom(bytes) raw",
                erc721_safe_transfer_from_with(&[0x11; 7]),
                Ok(true),
            ),
        ];

        let mut wrong = Vec::new();
        for flavour in FLAVOURS {
            for (name, data, expected) in &cases {
                let res = requires_blind_signing_in(flavour, &SMOL_JOES, 0, data);
                if res != *expected {
                    wrong.push(std::format!("{flavour} {name}: {res:?}"));
                }
            }
        }
        assert!(wrong.is_empty(), "misclassified: {wrong:?}");
    }

    // AVAX-17: NFT info provided for an allow-listed ERC-20 must not turn a
    // token approve into an NFT approve.
    #[test]
    #[cfg(all(feature = "erc721", feature = "erc20"))]
    #[serial_test::file_serial(path)]
    fn allow_listed_erc20_never_renders_as_nft() {
        const USDC: [u8; 20] = [
            0xB9, 0x7E, 0xF9, 0xEF, 0x87, 0x34, 0xC7, 0x19, 0x04, 0xD8, 0x00, 0x2F, 0x8B, 0x6B,
            0xC6, 0x6D, 0xD9, 0xC4, 0x8A, 0x6E,
        ];
        // a host can send an unsigned descriptor naming any contract
        assert!(!provide_nft_descriptor(&sdk_nft_descriptor(b"Test", &USDC)));

        // approve(spender, MAX)
        let mut data = hex::decode("095ea7b3").unwrap();
        data.extend_from_slice(&[0; 12]);
        data.extend_from_slice(&RECIPIENT);
        data.extend_from_slice(&[0xff; 32]);

        let pages = render_all(eip1559_tx(AVAX_C_CHAIN_MAINNET_ID, &USDC, 0, &data));
        assert!(
            pages.iter().any(|p| p.contains("ERC-20")),
            "USDC approve not shown as ERC-20: {pages:#?}"
        );
        assert!(!pages.iter().any(|p| p.contains("ERC-721")), "{pages:#?}");
    }

    /// The ERC-721 calls that show the collection name: transferFrom,
    /// approve(RECIPIENT, 1) and setApprovalForAll(RECIPIENT, true)
    #[cfg(feature = "erc721")]
    fn erc721_named_calls() -> [(&'static str, Vec<u8>); 3] {
        let mut approve = hex::decode("095ea7b3").unwrap();
        approve.extend_from_slice(&[0; 12]);
        approve.extend_from_slice(&RECIPIENT);
        approve.extend_from_slice(&[0; 31]);
        approve.push(1);

        let mut approval_for_all = hex::decode("a22cb465").unwrap();
        approval_for_all.extend_from_slice(&[0; 12]);
        approval_for_all.extend_from_slice(&RECIPIENT);
        approval_for_all.extend_from_slice(&[0; 31]);
        approval_for_all.push(1);

        [
            ("transferFrom", erc721_transfer_from_calldata()),
            ("approve", approve),
            ("setApprovalForAll", approval_for_all),
        ]
    }

    /// The page each named call shows the collection name on
    #[cfg(feature = "erc721")]
    fn collection_name_pages(titles: [&str; 3], name: &str) -> [String; 3] {
        titles.map(|title| std::format!("\"{title}\": \"{name}\""))
    }

    // V-016: a Ledger-signed descriptor's collection name is shown under the
    // plain titles.
    #[test]
    #[cfg(feature = "erc721")]
    #[serial_test::file_serial(path)]
    fn nft_collection_name_shown() {
        let expected = collection_name_pages(
            ["Collection Name", "To Manage your", "To Manage ALL"],
            "Smol Joes",
        );
        for ((call, data), expected) in erc721_named_calls().into_iter().zip(expected) {
            provide_smol_joes_info();
            let pages = render_all(eip1559_tx(AVAX_C_CHAIN_MAINNET_ID, &SMOL_JOES, 0, &data));
            assert!(pages.contains(&expected), "{call}: {pages:#?}");
            assert!(!pages.iter().any(|p| p.contains("unverified")), "{call}");
        }
    }

    /// The descriptors Ledger did not sign, with the name each carries: the
    /// JS SDK's and a tampered one
    #[cfg(feature = "erc721")]
    fn unverified_descriptors() -> [(Vec<u8>, &'static str); 2] {
        let mut tampered = hex::decode(crate::parser::nft_info_test_vectors::SMOL_JOES).unwrap();
        let name = 3;
        tampered[name] = b'B';

        [
            (sdk_nft_descriptor(b"Smol Joes", &SMOL_JOES), "Smol Joes"),
            (tampered, "Bmol Joes"),
        ]
    }

    // V-016: a descriptor Ledger did not sign (the JS SDK's, a tampered one)
    // is still used for the calls only ERC-721 has, but its host-chosen name
    // is titled as unverified.
    #[test]
    #[cfg(feature = "erc721")]
    #[serial_test::file_serial(path)]
    fn unverified_nft_collection_name_marked() {
        let [_, _, (_, approval_for_all)] = erc721_named_calls();
        let calls = [
            (
                "safeTransferFrom",
                erc721_safe_transfer_from_calldata(),
                "NFT (unverified)",
            ),
            ("setApprovalForAll", approval_for_all, "ALL (unverified)"),
        ];

        for (descriptor, name) in unverified_descriptors() {
            for (call, data, title) in &calls {
                assert!(!provide_nft_descriptor(&descriptor));
                let pages = render_all(eip1559_tx(AVAX_C_CHAIN_MAINNET_ID, &SMOL_JOES, 0, data));
                let expected = std::format!("\"{title}\": \"{name}\"");
                assert!(pages.contains(&expected), "{call}: {pages:#?}");
                assert!(!pages.iter().any(|p| p.contains("Collection Name")), "{call}");
                assert!(!pages.iter().any(|p| p.contains("To Manage")), "{call}");
            }
        }
    }

    // V-016: approve and transferFrom are ERC-20 calls too, and only the NFT
    // info says which one the bytes are. A descriptor Ledger did not sign
    // cannot make that choice: the call is reviewed undecoded, as blind
    // signing, and never as an NFT call.
    #[test]
    #[cfg(feature = "erc721")]
    #[serial_test::file_serial(path)]
    fn unverified_nft_info_never_decodes_shared_selectors() {
        let [transfer_from, approve, _] = erc721_named_calls();

        // approve(spender, MAX) on a token outside the allow-list
        const TOKEN: [u8; 20] = [0x7e; 20];
        let mut approve_max = hex::decode("095ea7b3").unwrap();
        approve_max.extend_from_slice(&[0; 12]);
        approve_max.extend_from_slice(&RECIPIENT);
        approve_max.extend_from_slice(&[0xff; 32]);

        let mut wrong = Vec::new();
        for (descriptor, name) in unverified_descriptors() {
            let cases = [
                (transfer_from.0, descriptor.clone(), SMOL_JOES, &transfer_from.1),
                (approve.0, descriptor.clone(), SMOL_JOES, &approve.1),
                (
                    "token approve",
                    sdk_nft_descriptor(name.as_bytes(), &TOKEN),
                    TOKEN,
                    &approve_max,
                ),
            ];
            for (call, descriptor, contract, data) in cases {
                for flavour in FLAVOURS {
                    assert!(!provide_nft_descriptor(&descriptor));
                    let blind = requires_blind_signing_in(flavour, &contract, 0, data);
                    if blind != Ok(true) {
                        wrong.push(std::format!("{flavour} {call}: blind {blind:?}"));
                    }
                }

                assert!(!provide_nft_descriptor(&descriptor));
                let pages = render_all(eip1559_tx(AVAX_C_CHAIN_MAINNET_ID, &contract, 0, data));
                if pages
                    .iter()
                    .any(|p| p.contains("ERC-721") || p.contains(name) || p.contains("unverified"))
                {
                    wrong.push(std::format!("{call}: {pages:#?}"));
                }
            }
        }
        assert!(wrong.is_empty(), "decoded from unsigned NFT info: {wrong:#?}");

        // signed by Ledger, the same calls are still decoded
        for (call, data) in [transfer_from, approve] {
            provide_smol_joes_info();
            assert_eq!(
                requires_blind_signing_in("eip1559", &SMOL_JOES, 0, &data),
                Ok(false),
                "{call}"
            );
        }
    }

    #[test]
    #[cfg(feature = "full")]
    //isolation is enabled by defalt in miri
    // and this prevents opening files, amonst other things
    // we could either disable isolation or have miri
    // return errors on open & co.
    //
    // considering we aren't doing anything special in this test
    // we can just avoid having it run in miri directly
    #[cfg_attr(miri, ignore)]
    fn tx_eth_ui() {
        use crate::parser::snapshots_common::{with_leaked, ReducedPage};

        insta::glob!("eth_testvectors/*.json", |path| {
            std::println!("Running test for {path:?}");
            let file = std::fs::File::open(path)
                .unwrap_or_else(|e| panic!("Unable to open file {path:?}: {e:?}"));
            let input: Vec<u8> = serde_json::from_reader(file)
                .unwrap_or_else(|e| panic!("Unable to read file {path:?} as json: {e:?}"));

            let test = |data| {
                let (_, tx) = EthTransaction::from_bytes(data).expect("parse tx from data");

                let mut driver = zuit::MockDriver::<_, 18, 1024>::new(tx);
                driver.drive();

                let ui = driver.out_ui();

                let reduced = ui
                    .iter()
                    .flat_map(|item| item.iter().map(ReducedPage::from))
                    .collect::<Vec<_>>();

                insta::assert_debug_snapshot!(reduced);
            };

            unsafe { with_leaked(input, test) };
        });
    }
}
