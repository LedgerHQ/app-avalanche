/*******************************************************************************
*   (c) 2018-2024 Zondax AG AG
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
        nano_avax_to_fp_str,
        outputs::{
            address_items, check_locktime, check_threshold, render_locktime, render_no_owner,
            render_threshold, shows_threshold,
        },
        Address, DisplayableItem, FromBytes, ParserError, ADDRESS_LEN, MAX_ADDRESSES,
        U64_FORMATTED_SIZE,
    },
};

const AVAX_TO_LEN: usize = 9; //b" AVAX to "

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct SECPTransferOutput<'b> {
    pub amount: u64,
    pub locktime: u64,
    pub threshold: u32,
    // list of addresses allowed to use this output
    pub addresses: &'b [[u8; ADDRESS_LEN]],
}

impl<'b> SECPTransferOutput<'b> {
    pub const TYPE_ID: u32 = 0x00000007;

    pub fn get_address_at(&'b self, idx: usize) -> Option<Address<'b>> {
        let data = self.addresses.get(idx)?;
        let mut addr = MaybeUninit::uninit();
        Address::from_bytes_into(data, &mut addr).ok()?;
        Some(unsafe { addr.assume_init() })
    }

    pub fn num_addresses(&self) -> usize {
        self.addresses.len()
    }
}

impl<'b> FromBytes<'b> for SECPTransferOutput<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("SECPTransferOutput::from_bytes_into\x00");
        // get owners type and check
        let (rem, _) = tag(Self::TYPE_ID.to_be_bytes())(input)?;

        let (rem, (amount, locktime, threshold, addr_len)) =
            tuple((be_u64, be_u64, be_u32, be_u32))(rem)?;

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

        // A non-zero locktime is shown as a date, so refuse one the date
        // formatter cannot represent here rather than failing to render it.
        check_locktime(locktime)?;

        //good ptr and no uninit reads
        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).amount).write(amount);
            addr_of_mut!((*out).locktime).write(locktime);
            addr_of_mut!((*out).threshold).write(threshold);
            addr_of_mut!((*out).addresses).write(addresses);
        }

        Ok(rem)
    }
}

impl DisplayableItem for SECPTransferOutput<'_> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // According to avalanche team, and to be "compatible" at presentation layer
        // we should summarize the items to show. As they suggested we only show the amount
        // and address. Legacy app errors if there is more than 1 address, in our case we dont yet.
        //
        // amount, addresses (or the "anyone can spend" screen when there is
        // none) and, with several addresses, the threshold, and when the
        // output is time-locked, the date it unlocks
        checked_add!(
            ViewError::Unknown,
            1u8,
            address_items(self.addresses.len()),
            shows_threshold(self.threshold, self.addresses.len()) as u8,
            (self.locktime != 0) as u8
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

impl SECPTransferOutput<'_> {
    /// Same as the DisplayableItem rendering, but encodes addresses for `hrp`.
    /// The empty HRP that render_item uses produces a string no wallet
    /// accepts, so any screen that knows the network should come through here.
    #[inline(never)]
    pub fn render_item_with_hrp(
        &self,
        hrp: &str,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::{pic_str, PIC};

        let mut buffer = [0; U64_FORMATTED_SIZE + 2 + AVAX_TO_LEN];
        // amount first, then the addresses, the threshold and the locktime
        let addr_item_n = 1u8;
        let threshold_item_n = addr_item_n + address_items(self.addresses.len());
        let shows_threshold = shows_threshold(self.threshold, self.addresses.len());
        let locktime_item_n = threshold_item_n + shows_threshold as u8;

        match item_n {
            0 => {
                let title_content = pic_str!(b"Amount");
                title[..title_content.len()].copy_from_slice(title_content);

                let avax_to = pic_str!(b" AVAX to ");

                // write the amount
                let len = nano_avax_to_fp_str(self.amount, &mut buffer[..])
                    .map_err(|_| ViewError::Unknown)?
                    .len();

                // write avax
                buffer[len..(len + avax_to.len())].copy_from_slice(avax_to);
                handle_ui_message(&buffer[..(len + avax_to.len())], message, page)
            }

            // Threshold 0 with no address: anyone can spend the output with no
            // signature. It used to show an amount with no recipient.
            1 if self.addresses.is_empty() => render_no_owner(
                pic_str!(b"Address"),
                pic_str!(b"Anyone can spend"),
                title,
                message,
                page,
            ),
            x @ 1.. if x < threshold_item_n => {
                let idx = x - addr_item_n;
                let addr = self.get_address_at(idx as usize).ok_or(ViewError::NoData)?;
                addr.render_with_hrp(hrp, title, message, page)
            }
            x if x == threshold_item_n && shows_threshold => {
                render_threshold(self.threshold, self.addresses.len(), title, message, page)
            }
            // The output cannot be spent before this date. Without the screen
            // funds sent to the user, or their change, could be locked for
            // years and the review would look the same.
            x if x == locktime_item_n && self.locktime != 0 => {
                render_locktime(pic_str!(b"Locked until"), self.locktime, title, message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_secp256k1_output() {
        let raw_output = [
            0, 0, 0, 7, 0, 0, 0, 0, 5, 215, 92, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
            1, 107, 106, 1, 167, 20, 122, 95, 155, 189, 52, 132, 21, 94, 230, 26, 133, 92, 231, 53,
            186, 0, 0, 0, 0, 0, 0, 0, 0, 127, 201, 61, 133, 198, 214, 44, 91, 42, 192, 181, 25,
            200, 112, 16, 234, 82, 148, 1, 45, 30, 64, 112, 48, 214, 172, 208, 2, 28, 172, 16, 213,
            0, 0, 0, 1, 71, 17, 128, 245, 190, 100, 113, 53, 172, 8, 240, 180, 27, 164, 33, 138,
            21, 117, 13, 78, 36, 121, 31, 186, 118, 70, 237, 151, 61, 204, 110, 123, 0, 0, 0, 0,
            61, 155, 218, 192, 237, 29, 118, 19, 48, 207, 104, 14, 253, 235, 26, 66, 21, 158, 179,
            135, 214, 210, 149, 12, 150, 247, 210, 143, 97, 187, 226, 170, 0, 0, 0, 5, 0, 0, 0, 0,
            5, 230, 158, 192, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 9, 0, 0, 0, 1, 69, 136,
            235, 111, 206, 248, 241, 99, 249, 22, 126, 93, 117, 195, 56, 35, 129, 23, 81, 11, 56,
            150, 186, 96, 172, 81, 75, 154, 159, 54, 203, 31, 16, 82, 38, 127, 166, 131, 153, 81,
            171, 12, 160, 85, 169, 248, 58, 101, 211, 76, 120, 5, 137, 18, 213, 222, 36, 191, 169,
            28, 203, 145, 255, 8, 0,
        ];

        // output SECP256K1TransferOutput { type_id: 7, amount: 98000000, locktime: 0, threshhold: 1, addresses: [Address { address_bytes: [107, 106, 1, 167, 20, 122, 95, 155, 189, 52, 132, 21, 94, 230, 26, 133, 92, 231, 53, 186], serialized_address: None }] }
        let output = SECPTransferOutput::from_bytes(&raw_output[..]).unwrap().1;

        assert_eq!(output.amount, 98000000);
        assert_eq!(output.locktime, 0);
        assert_eq!(output.threshold, 1);
        assert_eq!(output.addresses.len(), 1);
    }

    #[test]
    fn parse_secp256k1_output_invalid_threshold() {
        let raw_output = [
            0, 0, 0, 7, 0, 0, 0, 0, 5, 215, 92, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0,
            1, 107, 106, 1, 167, 20, 122, 95, 155, 189, 52, 132, 21, 94, 230, 26, 133, 92, 231, 53,
            186, 0, 0, 0, 0, 0, 0, 0, 0, 127, 201, 61, 133, 198, 214, 44, 91, 42, 192, 181, 25,
            200, 112, 16, 234, 82, 148, 1, 45, 30, 64, 112, 48, 214, 172, 208, 2, 28, 172, 16, 213,
            0, 0, 0, 1, 71, 17, 128, 245, 190, 100, 113, 53, 172, 8, 240, 180, 27, 164, 33, 138,
            21, 117, 13, 78, 36, 121, 31, 186, 118, 70, 237, 151, 61, 204, 110, 123, 0, 0, 0, 0,
            61, 155, 218, 192, 237, 29, 118, 19, 48, 207, 104, 14, 253, 235, 26, 66, 21, 158, 179,
            135, 214, 210, 149, 12, 150, 247, 210, 143, 97, 187, 226, 170, 0, 0, 0, 5, 0, 0, 0, 0,
            5, 230, 158, 192, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 9, 0, 0, 0, 1, 69, 136,
            235, 111, 206, 248, 241, 99, 249, 22, 126, 93, 117, 195, 56, 35, 129, 23, 81, 11, 56,
            150, 186, 96, 172, 81, 75, 154, 159, 54, 203, 31, 16, 82, 38, 127, 166, 131, 153, 81,
            171, 12, 160, 85, 169, 248, 58, 101, 211, 76, 120, 5, 137, 18, 213, 222, 36, 191, 169,
            28, 203, 145, 255, 8, 0,
        ];

        let output = SECPTransferOutput::from_bytes(&raw_output).unwrap_err();
        assert_eq!(output, ParserError::InvalidThreshold.into());
    }

    #[test]
    fn parse_secp256k1_output_accepts_threshold_zero() {
        use crate::parser::tx_builder::{render_all, secp_out, RECIPIENT};
        use std::prelude::v1::*;

        // No addresses: valid on-chain and anyone can spend it with no
        // signature. It is accepted, as it always was, and says so instead of
        // showing an amount with no recipient.
        let raw = secp_out(1_000_000_000, 4_102_444_800, 0, &[]);
        let (_, anyone) = SECPTransferOutput::from_bytes(&raw).unwrap();
        assert_eq!(
            render_all(&anyone),
            [
                "Amount: 1 AVAX to ",
                "Address: Anyone can spend",
                "Locked until: 2100-01-01 00:00:00 UTC",
            ]
        );

        // With addresses avalanchego refuses it as unoptimized; it was
        // accepted and still is, and its threshold is shown.
        let raw = secp_out(1_000, 0, 0, &[RECIPIENT]);
        let (_, zero_of_one) = SECPTransferOutput::from_bytes(&raw).unwrap();
        let screens = render_all(&zero_of_one);
        assert_eq!(screens.len(), 3, "{:#?}", screens);
        assert!(screens[1].starts_with("Address: "));
        assert_eq!(screens[2], "Threshold: 0 of 1");

        // a threshold no set of signatures can meet is still refused
        let err = SECPTransferOutput::from_bytes(&secp_out(1_000, 0, 1, &[])).unwrap_err();
        assert_eq!(err, ParserError::InvalidThreshold.into());
    }

    #[test]
    fn anyone_can_spend_output_is_shown_and_never_hidden() {
        use crate::parser::tx_builder::*;
        use crate::parser::{AvmOutput, Transaction, TransferableOutput};
        use std::prelude::v1::*;

        let anyone = transferable(&FUJI_AVAX, secp_out(89_999_000_000, 0, 0, &[]));
        let ins = [input(1, &FUJI_AVAX, 100_000_000_000)];
        let tx = x_transfer(&[out(10_000_000_000, RECIPIENT), anyone.clone()], &ins);

        assert!(Transaction::new(&tx).is_ok());
        // Not change, whatever the change address: change must be unlocked
        // AVAX with a single owner and threshold 1.
        let (_, output) = TransferableOutput::<AvmOutput>::from_bytes(&anyone).unwrap();
        for change in [CHANGE, RECIPIENT, [0; 20]] {
            assert!(!output.is_hideable_change(&change, Some(&FUJI_AVAX)));
        }

        // Shown, with its amount, whichever change addresses are filtered
        // (and even when every other output is hidden as change).
        for change in [&[][..], &[CHANGE], &[RECIPIENT], &[RECIPIENT, CHANGE]] {
            let shown = screens_with_change(&tx, change);
            let at = shown
                .iter()
                .position(|s| s == "Address: Anyone can spend")
                .unwrap_or_else(|| panic!("{:#?}", shown));
            assert!(shown[at - 1].ends_with(": 89.999 AVAX to "), "{:#?}", shown);
        }
    }

    #[test]
    fn anyone_can_spend_stake_output_shows_its_lock() {
        use crate::parser::tx_builder::*;
        use std::prelude::v1::*;

        // A stakeable-locked stake output nobody owns: amount, the "anyone"
        // screen, its locktime and the stakeable-lock date all show.
        let ins = [input(1, &FUJI_AVAX, 3_000_000_000_000)];
        let inner = secp_out(2_000_000_000_000, 1_000_000_000, 0, &[]);
        let stake = [transferable(
            &FUJI_AVAX,
            stakeable_locked(4_102_444_800, inner),
        )];
        let tx = add_delegator(&[], &ins, &stake, owners(0, 1, &[CHANGE]));
        let shown = screens(&tx, None);
        let at = shown
            .iter()
            .position(|s| s == "Address: Anyone can spend")
            .unwrap_or_else(|| panic!("{:#?}", shown));
        assert!(shown[at - 1].ends_with(": 2000 AVAX to "), "{:#?}", shown);
        assert_eq!(shown[at + 1], "Locked until: 2001-09-09 01:46:40 UTC");
        assert_eq!(
            shown[at + 2],
            "Funds locked: 2000 AVAX until 2100-01-01 00:00:00 UTC"
        );
    }

    #[test]
    fn multisig_output_shows_its_threshold() {
        use crate::parser::tx_builder::*;
        use std::prelude::v1::*;

        // A 1-of-2 output to [recipient, attacker] let the attacker spend it
        // alone, and looked exactly like the 2-of-2 one.
        let ins = [input(1, &FUJI_AVAX, 100_000_000_000)];
        let tx = |threshold| {
            x_transfer(
                &[transferable(
                    &FUJI_AVAX,
                    secp_out(10_000_000_000, 0, threshold, &[RECIPIENT, ATTACKER]),
                )],
                &ins,
            )
        };
        let one_of_two = screens(&tx(1), None);
        let two_of_two = screens(&tx(2), None);

        assert_ne!(one_of_two, two_of_two);
        assert!(one_of_two.contains(&"Threshold: 1 of 2".to_string()));
        assert!(two_of_two.contains(&"Threshold: 2 of 2".to_string()));

        // With a single address the threshold can only be 1: no screen.
        let single = x_transfer(&[out(10_000_000_000, RECIPIENT)], &ins);
        assert!(!screens(&single, None).iter().any(|s| s.starts_with("Threshold")));
    }

    #[test]
    fn parse_secp256k1_output_rejects_too_many_addresses() {
        // type_id(4) | amount(8) | locktime(8) | threshold(4) | addr_len(4) = 28 bytes
        let over_cap = (MAX_ADDRESSES + 1).to_be_bytes();
        let raw: [u8; 28] = [
            0, 0, 0, 7, // type_id
            0, 0, 0, 0, 0, 0, 0, 0, // amount
            0, 0, 0, 0, 0, 0, 0, 0, // locktime
            0, 0, 0, 0, // threshold
            over_cap[0], over_cap[1], over_cap[2], over_cap[3], // addr_len > cap
        ];
        // Address bytes deliberately omitted — parser must reject before `take`.
        let err = SECPTransferOutput::from_bytes(&raw).unwrap_err();
        assert_eq!(err, ParserError::TooManyAddresses.into());
    }
}
