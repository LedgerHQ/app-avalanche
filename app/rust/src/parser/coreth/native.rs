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

    /// Store an NFT descriptor for `contract` on `chain_id`, as
    /// INS_PROVIDE_NFT_INFORMATION would.
    #[cfg(feature = "erc721")]
    pub(crate) fn provide_nft_info(contract: &[u8; 20], chain_id: u64) {
        let mut descriptor = std::vec![1u8, 1, 4];
        descriptor.extend_from_slice(b"Test");
        descriptor.extend_from_slice(contract);
        descriptor.extend_from_slice(&chain_id.to_be_bytes());

        let (_, info) = crate::parser::NftInfo::from_bytes(&descriptor).unwrap();
        crate::parser::ERC721Info::set_info(info).unwrap();
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
        provide_nft_info(&EOA, AVAX_C_CHAIN_MAINNET_ID);
        let data = erc721_transfer_from_calldata();

        let hidden: Vec<_> = [
            (
                "eip1559",
                eip1559_tx(AVAX_C_CHAIN_MAINNET_ID, &EOA, HUNDRED_AVAX, &data),
            ),
            (
                "legacy",
                legacy_tx(AVAX_C_CHAIN_MAINNET_ID, &EOA, HUNDRED_AVAX, &data),
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
        for flavour in ["legacy", "eip2930", "eip1559"] {
            for (name, to, value, data, blind) in &cases {
                let id = AVAX_C_CHAIN_MAINNET_ID;
                let raw = match flavour {
                    "legacy" => legacy_tx(id, to, *value, data),
                    "eip2930" => eip2930_tx(id, to, *value, data),
                    _ => eip1559_tx(id, to, *value, data),
                };
                let (_, tx) = EthTransaction::from_bytes(&raw)
                    .unwrap_or_else(|e| panic!("{flavour} {name}: {e:?}"));
                if tx.requires_blind_signing() != *blind {
                    wrong.push(std::format!("{flavour} {name}"));
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
        provide_nft_info(&USDC, AVAX_C_CHAIN_MAINNET_ID);

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

    // AVAX-17: the NFT descriptor is not authenticated, so its collection
    // name is labelled as such.
    #[test]
    #[cfg(feature = "erc721")]
    #[serial_test::file_serial(path)]
    fn nft_collection_name_marked_unverified() {
        provide_nft_info(&EOA, AVAX_C_CHAIN_MAINNET_ID);

        let pages = render_all(eip1559_tx(
            AVAX_C_CHAIN_MAINNET_ID,
            &EOA,
            0,
            &erc721_transfer_from_calldata(),
        ));
        assert!(
            pages
                .iter()
                .any(|p| p == "\"NFT (unverified)\": \"Test\""),
            "{pages:#?}"
        );
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
