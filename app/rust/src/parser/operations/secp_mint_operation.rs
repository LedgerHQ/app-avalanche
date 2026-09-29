/*******************************************************************************
*   (c) 2018 - 2022 Zondax AG
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

use crate::checked_add;
use crate::parser::{
    u64_to_str, DisplayableItem, SECPMintOutput, SECPTransferOutput, U64_FORMATTED_SIZE,
};

use crate::{
    handlers::handle_ui_message,
    parser::{FromBytes, ParserError},
    utils::ApduPanic,
};
use zemu_sys::ViewError;

use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{
    bytes::complete::{tag, take},
    number::complete::be_u32,
};

const U32_SIZE: usize = std::mem::size_of::<u32>();

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct SECPMintOperation<'b> {
    pub address_indices: &'b [[u8; U32_SIZE]],
    pub mint_output: SECPMintOutput<'b>,
    pub transfer_output: SECPTransferOutput<'b>,
}
impl SECPMintOperation<'_> {
    pub const TYPE_ID: u32 = 8;
}

impl<'b> FromBytes<'b> for SECPMintOperation<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("SECPMintOperation::from_bytes_into\x00");

        // // double check the type
        let (rem, _) = tag(Self::TYPE_ID.to_be_bytes())(input)?;

        let (rem, num_indices) = be_u32(rem)?;

        let indices_len = (num_indices as usize)
            .checked_mul(U32_SIZE)
            .ok_or(ParserError::ValueOutOfRange)?;
        let (rem, indices) = take(indices_len)(rem)?;
        let indices = bytemuck::try_cast_slice(indices).apdu_unwrap();

        let out = out.as_mut_ptr();
        let mint_output = unsafe { &mut *addr_of_mut!((*out).mint_output).cast() };
        let rem = SECPMintOutput::from_bytes_into(rem, mint_output)?;

        let transfer_output = unsafe { &mut *addr_of_mut!((*out).transfer_output).cast() };
        let rem = SECPTransferOutput::from_bytes_into(rem, transfer_output)?;

        //good ptr and no uninit reads
        unsafe {
            addr_of_mut!((*out).address_indices).write(indices);
        }

        Ok(rem)
    }
}

impl DisplayableItem for SECPMintOperation<'_> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // operation description, the transfer to the new owners, and the mint
        // output.
        //
        // The mint output was parsed and signed but never counted, so the one
        // thing this operation decides -- who may mint this asset again after
        // it completes -- was the one thing the review did not show.
        checked_add!(
            ViewError::Unknown,
            1u8,
            self.transfer_output.num_items()?,
            self.mint_output.num_items()?
        )
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        self.render_item_with_hrp("", item_n, title, message, page)
    }
}

impl SECPMintOperation<'_> {
    /// Same as the DisplayableItem rendering, but encodes the new owners' and
    /// the mint authority's addresses for `hrp`.
    pub fn render_item_with_hrp(
        &self,
        hrp: &str,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::{pic_str, PIC};

        if item_n == 0 {
            let title_content = pic_str!(b"SECPMint");
            title[..title_content.len()].copy_from_slice(title_content);

            return handle_ui_message(pic_str!(b"Operation"), message, page);
        }

        let item_n = item_n as usize - 1;
        let transfer_items = self.transfer_output.num_items()? as usize;
        let mint_items = self.mint_output.num_items()? as usize;

        match item_n {
            0 => {
                // this operation consumes mint and transfer new ones to
                // list of owners so change this title.
                let title_content = pic_str!(b"Transfer: ");
                title[..title_content.len()].copy_from_slice(title_content);

                // The minted asset is the operation's, shown on its Asset
                // screen, never AVAX: show raw units, not "<amount> AVAX".
                let units = pic_str!(b" units to "!);
                let mut buffer = [0; U64_FORMATTED_SIZE + 10];
                let len = u64_to_str(self.transfer_output.amount, &mut buffer[..])
                    .map_err(|_| ViewError::Unknown)?
                    .len();
                buffer[len..len + units.len()].copy_from_slice(&units[..]);
                handle_ui_message(&buffer[..len + units.len()], message, page)
            }
            x @ 1.. if x < transfer_items => {
                self.transfer_output
                    .render_item_with_hrp(hrp, x as _, title, message, page)
            }
            x if x < transfer_items + mint_items => self.mint_output.render_item_with_hrp(
                hrp,
                (x - transfer_items) as u8,
                title,
                message,
                page,
            ),
            _ => Err(ViewError::NoData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_secp256k1_mint_operation() {
        let raw_input = [
            0, 0, 0, 8, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 64, 0, 0, 0, 8, 0, 0, 0, 6, 0,
            0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 1, 0, 0, 0, 2, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7,
            144, 22, 174, 248, 92, 19, 23, 103, 242, 56, 22, 54, 119, 75, 103, 131, 141, 236, 22,
            225, 106, 182, 207, 172, 178, 27, 136, 195, 168, 97, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 39,
            16, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 1, 157, 31, 52, 188, 58, 111, 35, 6,
            202, 7, 144, 22, 174, 248, 92, 19, 23, 103, 242, 56,
        ];

        let secp_mint_operation = SECPMintOperation::from_bytes(&raw_input).unwrap().1;

        let address_bytes: &[[u8; 4]] = &[
            1_u32.to_be_bytes(),
            5_u32.to_be_bytes(),
            64_u32.to_be_bytes(),
            8_u32.to_be_bytes(),
        ];

        assert_eq!(secp_mint_operation.address_indices, address_bytes);
    }

    #[test]
    fn secp_mint_operation_shows_the_mint_authority() {
        let raw_input = [
            0, 0, 0, 8, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 64, 0, 0, 0, 8, 0, 0, 0, 6, 0,
            0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 1, 0, 0, 0, 2, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7,
            144, 22, 174, 248, 92, 19, 23, 103, 242, 56, 22, 54, 119, 75, 103, 131, 141, 236, 22,
            225, 106, 182, 207, 172, 178, 27, 136, 195, 168, 97, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 39,
            16, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 1, 157, 31, 52, 188, 58, 111, 35, 6,
            202, 7, 144, 22, 174, 248, 92, 19, 23, 103, 242, 56,
        ];

        let op = SECPMintOperation::from_bytes(&raw_input).unwrap().1;

        // The mint output decides who may mint this asset again once the
        // operation completes. It was parsed and signed but not counted, so
        // none of its screens were reachable.
        let mint_items = op.mint_output.num_items().expect("Overflow?");
        assert!(mint_items > 0);

        let items = op.num_items().expect("Overflow?");
        assert_eq!(
            items,
            1 + op.transfer_output.num_items().expect("Overflow?") + mint_items
        );

        let mut title = [0u8; 64];
        let mut message = [0u8; 256];
        for i in 0..items {
            assert!(
                op.render_item(i, &mut title, &mut message, 0).is_ok(),
                "counted item {} did not render",
                i
            );
        }

        // The mint authority's own screens sit after the transfer's.
        let first_mint = 1 + op.transfer_output.num_items().expect("Overflow?");
        title.iter_mut().for_each(|v| *v = 0);
        op.render_item(first_mint, &mut title, &mut message, 0)
            .unwrap();
        let mut expected = [0u8; 64];
        op.mint_output
            .render_item(0, &mut expected, &mut [0u8; 256], 0)
            .unwrap();
        assert_eq!(title, expected);

        assert!(op.render_item(items, &mut title, &mut message, 0).is_err());
    }

    #[test]
    fn minted_amount_is_not_labelled_avax() {
        use crate::parser::tx_builder::render_all;

        // The minted asset is the operation's own, never AVAX, but the
        // transfer's amount was shown as "<amount> AVAX to".
        let raw_input = [
            0, 0, 0, 8, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 64, 0, 0, 0, 8, 0, 0, 0, 6, 0,
            0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 1, 0, 0, 0, 2, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7,
            144, 22, 174, 248, 92, 19, 23, 103, 242, 56, 22, 54, 119, 75, 103, 131, 141, 236, 22,
            225, 106, 182, 207, 172, 178, 27, 136, 195, 168, 97, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 39,
            16, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 1, 157, 31, 52, 188, 58, 111, 35, 6,
            202, 7, 144, 22, 174, 248, 92, 19, 23, 103, 242, 56,
        ];
        let op = SECPMintOperation::from_bytes(&raw_input).unwrap().1;
        let screens = render_all(&op);
        assert_eq!(screens[1], "Transfer: : 10000 units to ");
    }

    #[test]
    fn secp_mint_operation_encodes_addresses_for_the_network() {
        let raw_input = [
            0, 0, 0, 8, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 64, 0, 0, 0, 8, 0, 0, 0, 6, 0,
            0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 1, 0, 0, 0, 2, 157, 31, 52, 188, 58, 111, 35, 6, 202, 7,
            144, 22, 174, 248, 92, 19, 23, 103, 242, 56, 22, 54, 119, 75, 103, 131, 141, 236, 22,
            225, 106, 182, 207, 172, 178, 27, 136, 195, 168, 97, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 39,
            16, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 1, 157, 31, 52, 188, 58, 111, 35, 6,
            202, 7, 144, 22, 174, 248, 92, 19, 23, 103, 242, 56,
        ];

        let op = SECPMintOperation::from_bytes(&raw_input).unwrap().1;
        let expected_addresses = op.transfer_output.num_addresses() + op.mint_output.num_addresses();

        // Every address screen -- the transfer's new owners and the mint
        // authority -- must carry the network's HRP. The previous test only
        // compared titles, which an HRP-less "1..." string passes.
        let mut address_screens = 0;
        for i in 0..op.num_items().expect("Overflow?") {
            let mut title = [0u8; 64];
            let mut message = [0u8; 256];
            op.render_item_with_hrp("fuji", i, &mut title, &mut message, 0)
                .unwrap();

            if title.starts_with(b"Address") {
                address_screens += 1;
                assert!(
                    message.starts_with(b"fuji1"),
                    "item {} rendered an address without the network HRP",
                    i
                );
            }
        }
        assert_eq!(address_screens, expected_addresses);
    }
}
