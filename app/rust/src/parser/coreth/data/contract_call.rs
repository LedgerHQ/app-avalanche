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

use core::{mem::MaybeUninit, ptr::addr_of_mut};

use nom::number::complete::be_u32;
use zemu_sys::ViewError;

use super::opaque_data::{render_0x_hex, OpaqueData};
use crate::parser::{DisplayableItem, ParserError};

/// A contract call whose data none of the app's parsers (ERC-20, ERC-721,
/// asset call) decodes.
///
/// Signing it is blind signing: the review shows the 4-byte function
/// selector, then the length and the keccak-256 hash of the whole calldata,
/// so the user can check it against what the dApp sends.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "derive-debug"), derive(Debug))]
pub struct ContractCall<'b>(OpaqueData<'b>);

impl ContractCall<'_> {
    const SELECTOR_LEN: usize = 4;
}

impl<'b> ContractCall<'b> {
    pub fn parse_into(data: &'b [u8], output: &mut MaybeUninit<Self>) -> Result<(), ParserError> {
        let out = output.as_mut_ptr();
        // Contract call data is a 4-byte selector (the first bytes of the
        // sha3("method_signature")) followed by an arbitrary payload.
        //
        // Standard ABI encoding pads call arguments into 32-byte words, but we
        // must NOT require the payload to be a whole number of 32-byte words:
        // dapps are free to append a non-aligned suffix to the calldata. In
        // particular the Uniswap web interface appends a 10-byte analytics /
        // attribution tag to every UniversalRouter `execute(...)` call, so a
        // strict alignment check rejects every Uniswap-interface swap on the
        // C-Chain (the device returns 0x6984 and never shows a review screen).
        //
        // The trailing bytes are still covered by the transaction signing
        // hash, and the review shows the length and the hash of the whole
        // calldata, so accepting them is safe. We only require a full 4-byte
        // selector to be present.
        let _ = be_u32(data)?;

        let opaque = unsafe { &mut *addr_of_mut!((*out).0).cast() };
        OpaqueData::parse_into(data, opaque)
    }
}

impl DisplayableItem for ContractCall<'_> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // selector, data length and hash
        Ok(1 + OpaqueData::NUM_ITEMS)
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::{pic_str, PIC};

        match item_n {
            0 => {
                let label = pic_str!(b"Function");
                title[..label.len()].copy_from_slice(label);

                // parse_into checked the selector is there
                let selector = self
                    .0
                    .data()
                    .get(..Self::SELECTOR_LEN)
                    .ok_or(ViewError::Unknown)?;
                render_0x_hex(selector, message, page)
            }
            x => self.0.render_item(x - 1, title, message, page),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(data: &[u8]) -> Result<ContractCall<'_>, ParserError> {
        let mut out = MaybeUninit::<ContractCall>::uninit();
        ContractCall::parse_into(data, &mut out)?;
        Ok(unsafe { out.assume_init() })
    }

    // A bare 4-byte selector with no arguments is the minimal valid call.
    #[test]
    fn accepts_bare_selector() {
        let data = [0x12, 0x34, 0x56, 0x78];
        let cc = parse(&data).expect("bare selector should parse");
        assert_eq!(cc.0.data(), &data);
    }

    // Word-aligned ABI calldata (selector + N*32-byte words) still parses.
    #[test]
    fn accepts_word_aligned_args() {
        let mut data = std::vec![0xa9, 0x05, 0x9c, 0xbb];
        data.extend_from_slice(&[0u8; 64]);
        let cc = parse(&data).expect("aligned args should parse");
        assert_eq!(cc.0.data(), &data[..]);
    }

    // Regression: real Uniswap UniversalRouter calldata is the ABI-encoded
    // `execute(...)` arguments plus a 10-byte, non-32-aligned analytics suffix
    // appended by the Uniswap web interface. The old parser walked the payload
    // in strict 32-byte words and rejected this, so the device returned 0x6984
    // and never showed a review screen for any Uniswap-interface swap.
    #[test]
    fn accepts_non_word_aligned_suffix() {
        // execute() selector + one 32-byte word + 10-byte trailing suffix.
        let mut data = std::vec![0x35, 0x93, 0x56, 0x4c];
        data.extend_from_slice(&[0u8; 32]);
        data.extend_from_slice(&[0x75, 0x6e, 0x69, 0x78, 0, 0, 0, 0, 0, 0x0b]);
        assert_ne!((data.len() - 4) % 32, 0, "test data must be non-aligned");
        let cc = parse(&data).expect("trailing suffix must be accepted");
        // The whole calldata, suffix included, is retained for hashing/display.
        assert_eq!(cc.0.data(), &data[..]);
    }

    // Fewer than 4 bytes cannot contain a selector.
    #[test]
    fn rejects_truncated_selector() {
        assert!(parse(&[0x12, 0x34, 0x56]).is_err());
        assert!(parse(&[]).is_err());
    }
}
