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
use nom::{
    bytes::complete::{tag, take},
    number::complete::{be_u32, be_u64},
    sequence::tuple,
};
use zemu_sys::ViewError;

use crate::{
    checked_add,
    handlers::handle_ui_message,
    parser::{
        outputs::{
            address_items, check_locktime, check_threshold, render_locktime, render_no_owner,
            render_threshold, shows_threshold,
        },
        u32_to_str, Address, DisplayableItem, FromBytes, ParserError, ADDRESS_LEN, MAX_ADDRESSES,
        U32_FORMATTED_SIZE,
    },
    utils::hex_encode,
};

const MAX_PAYLOAD_LEN: usize = 1024;

// avax-team requested to display at least X
// characters that correspond to the payload.
// lets set that limit to 50 characters,
// as the payload can be either an ascii string
// or raw bytes.
const SHOW_PAYLOAD_LEN: usize = 50;

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct NFTTransferOutput<'b> {
    group_id: u32,
    payload: &'b [u8],
    pub locktime: u64,
    pub threshold: u32,
    // list of addresses allowed to use this output
    pub addresses: &'b [[u8; ADDRESS_LEN]],
}

impl<'b> NFTTransferOutput<'b> {
    pub const TYPE_ID: u32 = 0x0000000b;

    pub fn get_address_at(&'b self, idx: usize) -> Option<Address<'b>> {
        let data = self.addresses.get(idx)?;
        let mut addr = MaybeUninit::uninit();
        Address::from_bytes_into(data, &mut addr)
            .map_err(|_| ViewError::Unknown)
            .ok()?;
        Some(unsafe { addr.assume_init() })
    }

    pub fn num_addresses(&self) -> usize {
        self.addresses.len()
    }

    pub fn into_without_type(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        let (rem, (group_id, payload_len)) = tuple((be_u32, be_u32))(input)?;

        if payload_len as usize > MAX_PAYLOAD_LEN {
            return Err(ParserError::ValueOutOfRange.into());
        }

        let (rem, (payload, locktime, threshold, addr_len)) =
            tuple((take(payload_len as usize), be_u64, be_u32, be_u32))(rem)?;

        if addr_len > MAX_ADDRESSES {
            return Err(ParserError::TooManyAddresses.into());
        }
        let addresses_len = (addr_len as usize)
            .checked_mul(ADDRESS_LEN)
            .ok_or(ParserError::ValueOutOfRange)?;
        let (rem, addresses) = take(addresses_len)(rem)?;

        let addresses =
            bytemuck::try_cast_slice(addresses).map_err(|_| ParserError::InvalidAddressLength)?;

        // threshold 0 is accepted and shown, see check_threshold
        check_threshold(threshold, addresses.len())?;

        // the locktime is shown as a date
        check_locktime(locktime)?;

        //good ptr and no uninit reads
        let out = out.as_mut_ptr();

        unsafe {
            addr_of_mut!((*out).group_id).write(group_id);
            addr_of_mut!((*out).payload).write(payload);
            addr_of_mut!((*out).locktime).write(locktime);
            addr_of_mut!((*out).threshold).write(threshold);
            addr_of_mut!((*out).addresses).write(addresses);
        }

        Ok(rem)
    }
}

impl<'b> FromBytes<'b> for NFTTransferOutput<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("NFTTransfOutput::from_bytes_into\x00");
        // double check the type
        let (rem, _) = tag(Self::TYPE_ID.to_be_bytes())(input)?;

        Self::into_without_type(rem, out)
    }
}

impl DisplayableItem for NFTTransferOutput<'_> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // group_id, payload, addresses (or the "anyone can spend" screen when
        // there is none) and, with several, the threshold, and when the NFT
        // is time-locked, the date it unlocks
        checked_add!(
            ViewError::Unknown,
            2u8,
            address_items(self.num_addresses()),
            shows_threshold(self.threshold, self.num_addresses()) as u8,
            (self.locktime != 0) as u8
        )
    }

    #[inline(never)]
    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        // No network context at this level; callers that have one should use
        // render_item_with_hrp so the owner address is encoded for the right
        // network instead of with an empty prefix.
        self.render_item_with_hrp("", item_n, title, message, page)
    }
}

impl NFTTransferOutput<'_> {
    pub fn render_item_with_hrp(
        &self,
        hrp: &str,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::{pic_str, PIC};

        let mut buffer = [0; U32_FORMATTED_SIZE + 2];
        let threshold_item_n = 2 + address_items(self.num_addresses()) as usize;
        let shows_threshold = shows_threshold(self.threshold, self.num_addresses());

        match item_n as usize {
            0 => {
                let title_content = pic_str!(b"GroupID: ");
                title[..title_content.len()].copy_from_slice(title_content);

                let group_id =
                    u32_to_str(self.group_id, &mut buffer[..]).map_err(|_| ViewError::Unknown)?;

                handle_ui_message(group_id, message, page)
            }
            1 => {
                let title_content = pic_str!(b"Payload: ");
                title[..title_content.len()].copy_from_slice(title_content);

                let suffix = pic_str!(b"...");
                let prefix = pic_str!(b"0x"!);
                let mut show_suffix = false;
                let mut buf = [0; SHOW_PAYLOAD_LEN + 4 + 2]; // suffix and preffix
                let mut len = self.payload.len();

                // Only printable ASCII goes through as text: a NUL used to
                // end the payload shown early, and control bytes reached the
                // screen raw. Anything else is shown as hex, 0x-prefixed, and
                // so is text starting with "0x", which would look like hex.
                let printable = self.payload.iter().all(|c| (0x20..0x7f).contains(c));
                if printable && !self.payload.starts_with(b"0x") {
                    if len > SHOW_PAYLOAD_LEN {
                        show_suffix = true;
                        len = SHOW_PAYLOAD_LEN;
                    }
                    buf[..len].copy_from_slice(&self.payload[..len]);
                } else {
                    // hex string for non ascii payloads.
                    if len * 2 > SHOW_PAYLOAD_LEN {
                        show_suffix = true;
                        len = SHOW_PAYLOAD_LEN / 2;
                    }

                    let prefix_len = prefix.len();
                    buf[..prefix_len].copy_from_slice(&prefix[..]);

                    len = hex_encode(&self.payload[..len], &mut buf[prefix_len..])
                        .map_err(|_| ViewError::Unknown)?
                        + prefix_len;
                }

                // add suffix indicating the payload being shown is just
                // a fraction of the total.
                if show_suffix {
                    buf[len..len + suffix.len()].copy_from_slice(&suffix[..]);
                    len += suffix.len();
                }
                handle_ui_message(&buf[..len], message, page)
            }
            // Threshold 0 with no address: anyone can take the NFT with no
            // signature.
            2 if self.addresses.is_empty() => render_no_owner(
                pic_str!(b"Owner: "),
                pic_str!(b"Anyone can spend"),
                title,
                message,
                page,
            ),
            x @ 2.. if x < threshold_item_n => {
                let idx = x - 2;
                if let Some(addr) = self.get_address_at(idx) {
                    let res = addr.render_with_hrp(hrp, title, message, page);
                    // render Owner instead of Address
                    title.iter_mut().for_each(|v| *v = 0);
                    let title_content = pic_str!(b"Owner: ");
                    title[..title_content.len()].copy_from_slice(title_content);
                    res
                } else {
                    Err(ViewError::NoData)
                }
            }
            x if x == threshold_item_n && shows_threshold => {
                render_threshold(self.threshold, self.num_addresses(), title, message, page)
            }
            // the NFT cannot move before this date; it used to go unshown
            x if x == threshold_item_n + shows_threshold as usize && self.locktime != 0 => {
                render_locktime(
                    pic_str!(b"Locked until"),
                    self.locktime,
                    title,
                    message,
                    page,
                )
            }
            _ => Err(ViewError::NoData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &[u8] = &[
        0, 0, 0, 11, 0, 0, 0, 10, 0, 0, 0, 20, 110, 102, 116, 95, 116, 114, 97, 110, 115, 102, 101,
        114, 95, 112, 97, 121, 108, 111, 97, 100, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 0, 0, 0, 0, 1,
        22, 54, 119, 75, 103, 131, 141, 236, 22, 225, 106, 182, 207, 172, 178, 27, 136, 195, 168,
        97,
    ];

    #[test]
    fn multisig_nft_output_shows_its_threshold() {
        use crate::parser::tx_builder::{render_all, ATTACKER, RECIPIENT};
        use std::prelude::v1::*;

        let mut data = vec![0, 0, 0, 11, 0, 0, 0, 1, 0, 0, 0, 2, b'h', b'i'];
        data.extend(0u64.to_be_bytes());
        data.extend(1u32.to_be_bytes());
        data.extend(2u32.to_be_bytes());
        data.extend(RECIPIENT);
        data.extend(ATTACKER);

        let out = NFTTransferOutput::from_bytes(&data).unwrap().1;
        assert_eq!(out.num_items().unwrap(), 5);
        assert_eq!(render_all(&out).last().unwrap(), "Threshold: 1 of 2");
    }

    #[test]
    fn payload_with_control_bytes_is_shown_as_hex() {
        use crate::parser::tx_builder::{render_all, RECIPIENT};
        use std::prelude::v1::*;

        // "ab\0cd": the NUL passed is_ascii and ended the payload shown at "ab"
        let mut data = vec![0, 0, 0, 11, 0, 0, 0, 1, 0, 0, 0, 5];
        data.extend(b"ab\0cd");
        data.extend(0u64.to_be_bytes());
        data.extend(1u32.to_be_bytes());
        data.extend(1u32.to_be_bytes());
        data.extend(RECIPIENT);

        let out = NFTTransferOutput::from_bytes(&data).unwrap().1;
        assert_eq!(render_all(&out)[1], "Payload: : 0x6162006364");

        // and text that looks like hex is shown as hex
        let mut data = vec![0, 0, 0, 11, 0, 0, 0, 1, 0, 0, 0, 4];
        data.extend(b"0x01");
        data.extend(0u64.to_be_bytes());
        data.extend(1u32.to_be_bytes());
        data.extend(1u32.to_be_bytes());
        data.extend(RECIPIENT);
        let out = NFTTransferOutput::from_bytes(&data).unwrap().1;
        assert_eq!(render_all(&out)[1], "Payload: : 0x30783031");
    }

    #[test]
    fn parse_nft_transf_output() {
        let out = NFTTransferOutput::from_bytes(DATA).unwrap().1;
        assert_eq!(out.locktime, 56);
        assert_eq!(out.group_id, 10);
        assert_eq!(out.addresses.len(), 1);
        assert_eq!(out.threshold, 0);
        assert_eq!(out.payload, "nft_transfer_payload".as_bytes());
        assert_eq!(out.addresses[0][..], DATA[(DATA.len() - 20)..]);
    }
}
