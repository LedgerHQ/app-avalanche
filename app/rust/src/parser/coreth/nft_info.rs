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
use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{bytes::complete::take, number::streaming::be_u64};

use crate::{
    handlers::handle_ui_message,
    parser::{Address, FromBytes, OwnedAddress, ParserError, ADDRESS_LEN, COLLECTION_NAME_MAX_LEN},
};
use bolos::{pic_str, PIC};
use zemu_sys::ViewError;

// taken from app-ethereum implementation
const TYPE_SIZE: usize = 1;
const VERSION_SIZE: usize = 1;
const NAME_LENGTH_SIZE: usize = 1;
const CHAIN_ID_SIZE: usize = 8;
const KEY_ID_SIZE: usize = 1;
const ALGORITHM_ID_SIZE: usize = 1;
const SIGNATURE_LENGTH_SIZE: usize = 1;

/// The only descriptor type and version Ledger's NFT metadata service issues
const TYPE_1: u8 = 1;
const VERSION_1: u8 = 1;
/// Ledger's production NFT metadata key; a descriptor under the staging key
/// (0) is accepted but never verified
const PROD_NFT_METADATA_KEY: u8 = 1;
/// ECDSA over secp256k1 of the SHA-256 of the payload
const ALGORITHM_ID_1: u8 = 1;

const MIN_DER_SIG_SIZE: usize = 67;
const MAX_DER_SIG_SIZE: usize = 72;

/// Ledger's production NFT metadata public key (uncompressed secp256k1),
/// `LEDGER_NFT_METADATA_PUBLIC_KEY` in app-ethereum's `src/public_keys.h`.
/// The device checks against that header's copy, through the SDK; this one
/// lets host tests run the same check.
#[cfg(test)]
const LEDGER_NFT_METADATA_PUBLIC_KEY: [u8; 65] = [
    0x04, 0x98, 0x8d, 0xa6, 0xb2, 0x46, 0xf2, 0x8e, 0x77, 0xc1, 0xba, 0xb6, 0x75, 0xcb, 0x2a, 0x27,
    0x44, 0xf7, 0xf5, 0xce, 0xc5, 0x6a, 0xe6, 0xe0, 0x32, 0x23, 0x33, 0x7b, 0x57, 0x94, 0xcd, 0x6a,
    0xe0, 0x7d, 0x48, 0xb3, 0x0d, 0xb9, 0xcc, 0xb4, 0x0f, 0x5a, 0x02, 0xa1, 0x1a, 0x3a, 0xb9, 0x9d,
    0x5f, 0x59, 0x5a, 0x3d, 0x50, 0xa0, 0xe1, 0x30, 0x23, 0xfd, 0x0d, 0x95, 0x87, 0x92, 0xd7, 0x97,
    0x01,
];

#[cfg(not(any(unix, windows)))]
extern "C" {
    /// Checks `sig` (DER) over `hash` against Ledger's NFT metadata key
    fn crypto_verify_nft_metadata(hash: *const u8, sig: *const u8, sig_len: u16) -> bool;
}

/// Whether `signature` is Ledger's NFT metadata key's signature of `hash`.
fn nft_metadata_signature_valid(hash: &[u8; 32], signature: &[u8]) -> bool {
    cfg_if::cfg_if! {
        if #[cfg(not(any(unix, windows)))] {
            unsafe {
                crypto_verify_nft_metadata(
                    hash.as_ptr(),
                    signature.as_ptr(),
                    signature.len() as u16,
                )
            }
        } else if #[cfg(test)] {
            use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};

            let Ok(key) = VerifyingKey::from_sec1_bytes(&LEDGER_NFT_METADATA_PUBLIC_KEY) else {
                return false;
            };
            let Ok(sig) = Signature::from_der(signature) else {
                return false;
            };
            // the SDK accepts either S; k256 only the low one
            let sig = sig.normalize_s().unwrap_or(sig);
            key.verify_prehash(hash, &sig).is_ok()
        } else {
            let _ = (hash, signature);
            false
        }
    }
}

/// An NFT descriptor as INS_PROVIDE_NFT_INFORMATION carries it, the format
/// Ledger's NFT metadata service signs (app-ethereum's
/// provide_nft_information) and the JS SDK's provideNFTInformation builds:
///
/// `type | version | name_len | name | address | chain_id | key_id |
/// algorithm_id | sig_len | signature`
///
/// The signature covers every byte up to and including the algorithm id.
pub struct SignedNftDescriptor<'b> {
    payload: &'b [u8],
    signature: &'b [u8],
}

impl<'b> SignedNftDescriptor<'b> {
    /// Split `input` into the signed payload and its signature. Anything but
    /// exactly one descriptor -- a name longer than the app holds, a
    /// truncated payload or signature, trailing bytes -- is an error. The
    /// key id, algorithm id and signature are not checked here: a
    /// descriptor Ledger did not sign is still well formed.
    pub fn parse(input: &'b [u8]) -> Result<Self, ParserError> {
        let name_len = *input
            .get(TYPE_SIZE + VERSION_SIZE)
            .ok_or(ParserError::UnexpectedBufferEnd)? as usize;
        if name_len > COLLECTION_NAME_MAX_LEN {
            return Err(ParserError::ValueOutOfRange);
        }

        let payload_len = TYPE_SIZE
            + VERSION_SIZE
            + NAME_LENGTH_SIZE
            + name_len
            + ADDRESS_LEN
            + CHAIN_ID_SIZE
            + KEY_ID_SIZE
            + ALGORITHM_ID_SIZE;
        let payload = input
            .get(..payload_len)
            .ok_or(ParserError::UnexpectedBufferEnd)?;

        let sig_len = *input
            .get(payload_len)
            .ok_or(ParserError::UnexpectedBufferEnd)? as usize;

        let sig_start = payload_len + SIGNATURE_LENGTH_SIZE;
        let signature = input
            .get(sig_start..sig_start + sig_len)
            .ok_or(ParserError::UnexpectedBufferEnd)?;
        if input.len() != sig_start + sig_len {
            return Err(ParserError::UnexpectedData);
        }

        Ok(Self { payload, signature })
    }

    /// The descriptor's contents, with whether Ledger's production NFT
    /// metadata key signed them ([`NftInfo::verified`]).
    ///
    /// A descriptor that is not signed by Ledger (the JS SDK's
    /// provideNFTInformation fills the signature with random bytes) is
    /// still returned, marked unverified, so the review titles its
    /// collection name as such. A malformed payload -- unknown type or
    /// version, a non-printable name -- is an error.
    pub fn info(&self) -> Result<NftInfo, ParserError> {
        // FromBytes::from_bytes only exists in tests
        let mut info = MaybeUninit::uninit();
        let rem = NftInfo::from_bytes_into(self.payload, &mut info)
            .map_err(|_| ParserError::UnexpectedData)?;
        // only the key and algorithm ids follow the chain id
        let [key_id, algorithm_id] = rem else {
            return Err(ParserError::UnexpectedData);
        };
        let signed_by_ledger = *key_id == PROD_NFT_METADATA_KEY
            && *algorithm_id == ALGORITHM_ID_1
            && (MIN_DER_SIG_SIZE..=MAX_DER_SIG_SIZE).contains(&self.signature.len())
            && self.signature_valid();

        // Safety: from_bytes_into succeeded, so every field is written
        let mut info = unsafe { info.assume_init() };
        info.verified = signed_by_ledger;
        Ok(info)
    }

    /// Whether the signature is Ledger's NFT metadata key's over the payload
    fn signature_valid(&self) -> bool {
        use bolos::hash::{Hasher, Sha256};

        match Sha256::digest(self.payload) {
            Ok(hash) => nft_metadata_signature_valid(&hash, self.signature),
            Err(_) => false,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct NftInfo {
    contract_address: OwnedAddress,
    // plus null terminator
    collection_name: [u8; COLLECTION_NAME_MAX_LEN + 1],
    // chain id is constd as a u64 value
    pub chain_id: u64,
    name_len: u8,
    // whether Ledger's production NFT metadata key signed the descriptor
    verified: bool,
}

impl NftInfo {
    pub fn address(&self) -> Address<'_> {
        self.contract_address.address()
    }

    /// Whether Ledger's production NFT metadata key signed the descriptor
    /// this came from. The collection name of an unverified descriptor is
    /// whatever the host chose, so the review titles it as unverified.
    pub fn verified(&self) -> bool {
        self.verified
    }

    /// Render the collection name. Callers title it by [`Self::verified`].
    pub fn render_collection_name(&self, message: &mut [u8], page: u8) -> Result<u8, ViewError> {
        let not_found = pic_str!(b"Collection Name not provided?");

        if self.name_len > 0 {
            handle_ui_message(
                &self.collection_name[..self.name_len as usize],
                message,
                page,
            )
        } else {
            handle_ui_message(not_found, message, page)
        }
    }
}

impl<'b> FromBytes<'b> for NftInfo {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("NftInfo::from_bytes_into\x00");

        let offset = TYPE_SIZE + VERSION_SIZE;

        match input {
            [TYPE_1, VERSION_1, ..] => {}
            [_, _, ..] => return Err(ParserError::InvalidTypeId.into()),
            _ => return Err(ParserError::UnexpectedBufferEnd.into()),
        }

        let input = input
            .get(offset..)
            .ok_or(ParserError::UnexpectedBufferEnd)?;

        // get nft collection name
        if input.is_empty() {
            return Err(ParserError::ValueOutOfRange.into());
        }
        let name_len = input[0] as usize;
        if name_len > COLLECTION_NAME_MAX_LEN {
            return Err(ParserError::ValueOutOfRange.into());
        }

        let (rem, name) = take(name_len)(&input[1..])?;

        // only printable ascii: a NUL or control byte could blank or
        // rewrite what the screen shows
        if !name.iter().all(|c| (0x20..=0x7E).contains(c)) {
            return Err(ParserError::InvalidAsciiValue.into());
        }

        let (rem, address) = take(ADDRESS_LEN)(rem)?;

        let (rem, chain_id) = be_u64(rem)?;

        let out = out.as_mut_ptr();
        let owned = unsafe { &mut *addr_of_mut!((*out).contract_address).cast() };
        _ = OwnedAddress::from_bytes_into(address, owned)?;

        unsafe {
            // zero the whole array, not only the name, before it is assumed init
            let collection_name = addr_of_mut!((*out).collection_name).cast::<u8>();
            collection_name.write_bytes(0, COLLECTION_NAME_MAX_LEN + 1);
            collection_name.copy_from_nonoverlapping(name.as_ptr(), name.len());

            addr_of_mut!((*out).name_len).write(name_len as u8);
            addr_of_mut!((*out).chain_id).write(chain_id);
            // only SignedNftDescriptor::info marks a checked signature
            addr_of_mut!((*out).verified).write(false);
        }

        Ok(rem)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::prelude::v1::*;

    #[test]
    fn collection_name_is_fully_initialised() {
        let name = b"Collection";
        let mut data = std::vec![1u8, 1, name.len() as u8];
        data.extend_from_slice(name);
        data.extend_from_slice(&[0x11; ADDRESS_LEN]);
        data.extend_from_slice(&43114u64.to_be_bytes());

        // garbage stands in for uninitialised memory
        let mut out = MaybeUninit::<NftInfo>::uninit();
        unsafe {
            out.as_mut_ptr()
                .cast::<u8>()
                .write_bytes(0xFF, core::mem::size_of::<NftInfo>());
        }
        NftInfo::from_bytes_into(&data, &mut out).unwrap();
        let info = unsafe { out.assume_init() };

        assert_eq!(&info.collection_name[..name.len()], name);
        assert!(info.collection_name[name.len()..].iter().all(|b| *b == 0));
    }

    fn descriptor(name: &[u8]) -> std::vec::Vec<u8> {
        let mut out = std::vec![1u8, 1, name.len() as u8];
        out.extend_from_slice(name);
        out.extend_from_slice(&[0xa1; ADDRESS_LEN]);
        out.extend_from_slice(&43114u64.to_be_bytes());
        out
    }

    /// Descriptors served by Ledger's NFT metadata service
    /// (nft.api.live.ledger.com/v1/ethereum/43114/contracts/<address>),
    /// signed with the production key.
    pub(crate) const CHIKN: &str = "0101056368696b6e8927985b358692815e18f2138964679dca5d3b79000000000000a86a0101473045022041afd6ad3190221367dd6f70856fe97ba8216b0d43a48d8288a422459a93ffe8022100a287ee0bb2c535aac8022709d40234b5771a95b491eaf7cdecb4a3ed7a2d59dc";
    pub(crate) const SMOL_JOES: &str = "010109536d6f6c204a6f6573c70df87e1d98f6a531c8e324c9bcec6fc82b5e8d000000000000a86a0101473045022001c39a2422e6026be1283bf9fbb287373024c62a1fe76eb729fedaf6fce19993022100dc618cb328093bf01ab59f1857dfd4a84d3e5ab5307cdd345b268b73abbbedb0";

    fn info(data: &[u8]) -> Result<NftInfo, ParserError> {
        SignedNftDescriptor::parse(data)?.info()
    }

    #[test]
    fn ledger_signed_descriptor_is_verified() {
        for (hex, name, address) in [
            (
                CHIKN,
                &b"chikn"[..],
                "8927985b358692815e18f2138964679dca5d3b79",
            ),
            (
                SMOL_JOES,
                b"Smol Joes",
                "c70df87e1d98f6a531c8e324c9bcec6fc82b5e8d",
            ),
        ] {
            let info = info(&hex::decode(hex).unwrap()).unwrap();
            assert!(info.verified(), "{name:?} not verified");
            assert_eq!(&info.collection_name[..info.name_len as usize], name);
            assert_eq!(
                &info.address().raw_address()[..],
                &hex::decode(address).unwrap()[..]
            );
            assert_eq!(info.chain_id, 43114);
        }
    }

    /// Every signed byte is bound: changing the name, address, chain id or
    /// the type, version, key or algorithm ids, or the signature, never
    /// leaves a verified descriptor. It is either refused as malformed
    /// (type, version, lengths, a non-printable name) or kept unverified.
    #[test]
    fn tampered_descriptor_is_never_verified() {
        let good = hex::decode(SMOL_JOES).unwrap();
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0x01;
            if let Ok(info) = info(&bad) {
                assert!(!info.verified(), "byte {i} not covered");
            }
        }

        // a changed name or signature is still a well-formed descriptor
        let name = 3;
        let mut renamed = good.clone();
        renamed[name] = b'B';
        let renamed = info(&renamed).unwrap();
        assert!(!renamed.verified());
        assert_eq!(&renamed.collection_name[..9], b"Bmol Joes");

        let mut resigned = good.clone();
        *resigned.last_mut().unwrap() ^= 0x01;
        assert!(!info(&resigned).unwrap().verified());
    }

    #[test]
    fn malformed_descriptor_is_refused() {
        let good = hex::decode(SMOL_JOES).unwrap();
        let payload_len = 3 + 9 + ADDRESS_LEN + 8 + 2;

        // trailing byte, truncated signature, no signature at all
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(info(&trailing).is_err());
        assert!(info(&good[..good.len() - 1]).is_err());
        assert!(info(&good[..payload_len]).is_err());
        assert!(info(&good[..payload_len - 2]).is_err());
        assert!(info(&[]).is_err());

        // an unknown type or version, a name too long for the app
        for (at, value) in [(0, 0), (0, 2), (1, 0), (1, 2), (2, 0xff)] {
            let mut bad = good.clone();
            bad[at] = value;
            assert!(info(&bad).is_err(), "byte {at} = {value} accepted");
        }
    }

    /// The staging key, an unknown algorithm or a signature that cannot be
    /// DER still make a well-formed descriptor; it is only never verified.
    #[test]
    fn descriptor_not_under_the_production_key_is_unverified() {
        let good = hex::decode(SMOL_JOES).unwrap();
        let payload_len = 3 + 9 + ADDRESS_LEN + 8 + 2;

        let mut staging = good.clone();
        staging[payload_len - 2] = 0;
        let mut algorithm = good.clone();
        algorithm[payload_len - 1] = 2;
        let mut short_sig = good[..payload_len].to_vec();
        short_sig.push(8);
        short_sig.extend_from_slice(&[0x30; 8]);
        let mut no_sig = good[..payload_len].to_vec();
        no_sig.push(0);

        for (case, data) in [
            ("staging key", staging),
            ("algorithm", algorithm),
            ("short signature", short_sig),
            ("no signature", no_sig),
        ] {
            let info = info(&data).unwrap_or_else(|e| panic!("{case}: {e:?}"));
            assert!(!info.verified(), "{case} verified");
            assert_eq!(&info.collection_name[..9], b"Smol Joes", "{case}");
        }
    }

    /// What the JS SDK's provideNFTInformation sends: type 1, version 1,
    /// name, address, chain id, the production key id, algorithm 1, then a
    /// 70-byte signature of random bytes. It is accepted, unverified.
    #[test]
    fn js_sdk_descriptor_is_accepted_unverified() {
        let mut data = descriptor(b"Smol Joes");
        data.extend_from_slice(&[PROD_NFT_METADATA_KEY, ALGORITHM_ID_1, 70]);
        for seed in [0x5au8, 0x30, 0x00, 0xff] {
            let mut data = data.clone();
            data.extend((0..70u8).map(|i| i.wrapping_mul(37) ^ seed));
            let info = info(&data).unwrap();
            assert!(!info.verified());
            assert_eq!(&info.collection_name[..9], b"Smol Joes");
            assert_eq!(&info.address().raw_address()[..], &[0xa1; ADDRESS_LEN]);
            assert_eq!(info.chain_id, 43114);
        }
    }

    /// Info parsed straight from a payload, without the signature, is never
    /// verified.
    #[test]
    fn unsigned_payload_is_unverified() {
        assert!(!NftInfo::from_bytes(&descriptor(b"Lucid Labs"))
            .unwrap()
            .1
            .verified());
    }

    #[test]
    fn collection_name_must_be_printable() {
        assert!(NftInfo::from_bytes(&descriptor(b"Lucid Labs")).is_ok());

        for name in [&b"\0\0\0Lucid"[..], b"Lu\ncid", b"Lucid\x7f", b"\x1bLucid"] {
            assert!(
                NftInfo::from_bytes(&descriptor(name)).is_err(),
                "{name:?} accepted"
            );
        }
    }
}
