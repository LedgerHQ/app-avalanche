use crate::checked_add;
use crate::parser::{nano_avax_to_fp_str, WarpMessage, ADDRESS_LEN};
use crate::utils::hex_encode;
use crate::{
    handlers::handle_ui_message,
    parser::{
        proof_of_possession::BLS_SIGNATURE_LEN, BaseTxFields, DisplayableItem, FromBytes, Header,
        ParserError, PvmOutput, PVM_REGISTER_L1_VALIDATOR, U64_FORMATTED_SIZE,
    },
};
use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{
    bytes::complete::{tag, take},
    number::complete::{be_u32, be_u64},
};
use zemu_sys::ViewError;

pub const FIXED_FIELDS_LEN: u8 = 5;
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct RegisterL1ValidatorTx<'b> {
    pub tx_header: Header<'b>,
    pub base_tx: BaseTxFields<'b, PvmOutput<'b>>,
    pub balance: u64,
    pub signer: &'b [u8; BLS_SIGNATURE_LEN],
    pub warp_message_size: u32,
    pub warp_message: WarpMessage<'b>,
}

impl<'b> FromBytes<'b> for RegisterL1ValidatorTx<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("RegisterL1ValidatorTx::from_bytes_into\x00");

        let (rem, _) = tag(PVM_REGISTER_L1_VALIDATOR.to_be_bytes())(input)?;

        let out = out.as_mut_ptr();

        // tx header
        let tx_header = unsafe { &mut *addr_of_mut!((*out).tx_header).cast() };
        let rem = Header::from_bytes_into(rem, tx_header)?;

        // base_tx
        let base_tx = unsafe { &mut *addr_of_mut!((*out).base_tx).cast() };
        let rem = BaseTxFields::<PvmOutput>::from_bytes_into(rem, base_tx)?;

        // balance
        let (rem, balance) = be_u64(rem)?;

        // signer
        let (rem, signer) = take(BLS_SIGNATURE_LEN)(rem)?;
        let signer = arrayref::array_ref!(signer, 0, BLS_SIGNATURE_LEN);

        // warp_message_size
        let (rem, warp_message_size) = be_u32(rem)?;

        // warp_message
        let warp_message_start = rem;
        // Bound the region to the declared size first. The previous check
        // compared warp_message_size against warp_message_start.len(), which is
        // "bytes to the end of the buffer" rather than "bytes this message
        // used", so inflating the declared size to match appended bytes
        // satisfied it. Slicing the region up front makes the declared size
        // load-bearing, and requiring the parse to account for all of it closes
        // the gap the old comparison left.
        let (rem, warp_region) = take(warp_message_size as usize)(warp_message_start)?;

        let warp_message = unsafe { &mut *addr_of_mut!((*out).warp_message).cast() };
        let leftover = WarpMessage::from_bytes_into(warp_region, warp_message)?;
        if !leftover.is_empty() {
            return Err(nom::Err::Error(ParserError::InvalidLength));
        }

        unsafe {
            addr_of_mut!((*out).warp_message_size).write(warp_message_size);
            addr_of_mut!((*out).balance).write(balance);
            addr_of_mut!((*out).signer).write(signer);
        }

        // Propagate the real remainder so Transaction::new_into's trailing-byte
        // check has something to act on.
        Ok(rem)
    }
}

impl<'b> RegisterL1ValidatorTx<'b> {
    pub fn disable_output_if(&mut self, address: &[u8]) {
        self.base_tx.disable_output_if(address);
    }

    // Info at https://github.com/ava-labs/avalanchejs/blob/master/src/utils/getBurnedAmountByTx.ts
    fn fee(&'b self) -> Result<u64, ParserError> {
        let sum_inputs = self.base_tx.sum_inputs_amount()?;

        let base_outputs = self.base_tx.sum_outputs_amount()?;

        let mut fee = sum_inputs
            .checked_sub(base_outputs)
            .ok_or(ParserError::OperationOverflows)?;

        fee = fee
            .checked_sub(self.balance)
            .ok_or(ParserError::OperationOverflows)?;

        Ok(fee)
    }
}

impl DisplayableItem for RegisterL1ValidatorTx<'_> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // tx_info, node_id, weight, balance, base outputs, fee,
        // remaining_balance_owner, disable_owner.
        // The base outputs were previously left out of the count entirely, so
        // where the transaction's change went was never on screen.
        if let crate::parser::AddressedCallPayload::RegisterL1Validator(ref msg) =
            self.warp_message.payload.payload
        {
            let n_addresses =
                msg.remaining_balance_owner.addresses.len() + msg.disable_owner.addresses.len();
            checked_add!(
                ViewError::Unknown,
                FIXED_FIELDS_LEN,
                self.base_tx.base_outputs_num_items()?,
                n_addresses as u8
            )
        } else {
            Err(ViewError::NoData)
        }
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use crate::sys::PIC;
        use bolos::pic_str;
        use itoa::Buffer;
        let mut itoa_buffer = Buffer::new();
        let mut buffer = [0; U64_FORMATTED_SIZE + 2];

        if let crate::parser::AddressedCallPayload::RegisterL1Validator(ref msg) =
            self.warp_message.payload.payload
        {
            let n_remain_addresses = msg.remaining_balance_owner.addresses.len();
            let n_disable_addresses = msg.disable_owner.addresses.len();
            let prefix = pic_str!(b"0x"!);

            // The base outputs sit between the balance and the fee, so the
            // owner addresses no longer start at a fixed index.
            const START_OUTPUTS: u8 = 4;
            let output_items = self.base_tx.base_outputs_num_items()?;
            let end_outputs = START_OUTPUTS
                .checked_add(output_items)
                .ok_or(ViewError::Unknown)?;
            let start_remain = end_outputs as usize + 1;
            let start_disable = start_remain + n_remain_addresses;
            let end_disable = start_disable + n_disable_addresses;

            match item_n {
                0 => {
                    let label = pic_str!(b"RegisterL1Val");
                    title[..label.len()].copy_from_slice(label);
                    let content = pic_str!(b"Transaction");
                    handle_ui_message(content, message, page)
                }
                1 => msg.node_id.render_item(0, title, message, page),

                2 => {
                    let label = pic_str!(b"Weight");
                    title[..label.len()].copy_from_slice(label);
                    let buffer = itoa_buffer.format(msg.weight);
                    handle_ui_message(buffer.as_bytes(), message, page)
                }
                3 => {
                    let label = pic_str!(b"Balance (AVAX)");
                    title[..label.len()].copy_from_slice(label);

                    let balance_buff = nano_avax_to_fp_str(self.balance, &mut buffer[..])
                        .map_err(|_| ViewError::Unknown)?;

                    handle_ui_message(balance_buff, message, page)
                }
                // render base outputs
                x if (START_OUTPUTS..end_outputs).contains(&x) => {
                    let hrp = self.tx_header.hrp().map_err(|_| ViewError::Unknown)?;
                    self.base_tx.render_base_output_with_hrp(
                        hrp,
                        x - START_OUTPUTS,
                        title,
                        message,
                        page,
                    )
                }
                x if x == end_outputs => {
                    let label = pic_str!(b"Fee(AVAX)");
                    title[..label.len()].copy_from_slice(label);

                    let fee = self.fee().map_err(|_| ViewError::Unknown)?;
                    let fee_buff = nano_avax_to_fp_str(fee, &mut buffer[..])
                        .map_err(|_| ViewError::Unknown)?;

                    handle_ui_message(fee_buff, message, page)
                }
                x if (start_remain..start_disable).contains(&(x as usize)) => {
                    let label = pic_str!(b"Rem Addr");
                    title[..label.len()].copy_from_slice(label);

                    let mut out = [0; ADDRESS_LEN * 2 + 2];
                    let mut sz = prefix.len();
                    out[..prefix.len()].copy_from_slice(&prefix[..]);

                    sz += hex_encode(
                        msg.remaining_balance_owner.addresses[x as usize - start_remain],
                        &mut out[prefix.len()..],
                    )
                    .map_err(|_| ViewError::Unknown)?;

                    handle_ui_message(&out[..sz], message, page)
                }
                x if (start_disable..end_disable).contains(&(x as usize)) => {
                    let label = pic_str!(b"Disabler");
                    title[..label.len()].copy_from_slice(label);

                    let mut out = [0; ADDRESS_LEN * 2 + 2];
                    let mut sz = prefix.len();
                    out[..prefix.len()].copy_from_slice(&prefix[..]);

                    sz += hex_encode(
                        msg.disable_owner.addresses[x as usize - start_disable],
                        &mut out[prefix.len()..],
                    )
                    .map_err(|_| ViewError::Unknown)?;

                    handle_ui_message(&out[..sz], message, page)
                }
                _ => Err(ViewError::NoData),
            }
        } else {
            Err(ViewError::NoData)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::snapshots_common::ReducedPage;
    use std::prelude::v1::*;
    use zuit::Page;

    const DATA: &[u8] = &[];

    include!("testvectors/register_l1_validator.rs");
    #[test]
    fn parse_register_l1_validator() {
        let remaining_balance_owner_address = [
            0xdd, 0x91, 0x03, 0xb6, 0x86, 0x29, 0x92, 0x95, 0xf5, 0x18, 0xf3, 0x3e, 0xa3, 0xb6,
            0xe7, 0x67, 0xd0, 0x6e, 0xad, 0x89,
        ];

        let disable_owner_address = [
            0xdd, 0x91, 0x03, 0xb6, 0x86, 0x29, 0x92, 0x95, 0xf5, 0x18, 0xf3, 0x3e, 0xa3, 0xb6,
            0xe7, 0x67, 0xd0, 0x6e, 0xad, 0x89,
        ];
        let (_, tx) = RegisterL1ValidatorTx::from_bytes(REGISTER_L1_VALIDATOR_DATA).unwrap();
        if let crate::parser::AddressedCallPayload::RegisterL1Validator(ref msg) =
            tx.warp_message.payload.payload
        {
            assert_eq!(
                msg.remaining_balance_owner.addresses[0],
                remaining_balance_owner_address
            );
            assert_eq!(msg.disable_owner.addresses[0], disable_owner_address);
            assert_eq!(msg.weight, 1);
        } else {
            panic!("Expected RegisterL1Validator payload");
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn ui_register_l1_validator() {
        let data = REGISTER_L1_VALIDATOR_DATA;
        println!("-------------------- Register L1 Validator TX ------------------------");
        let (_, tx) = RegisterL1ValidatorTx::from_bytes(data).unwrap();

        let items = tx.num_items().expect("Overflow?");

        let mut pages = Vec::<Page<18, 1024>>::with_capacity(items as usize);
        for i in 0..items {
            let mut page = Page::<18, 1024>::default();

            tx.render_item(i as _, &mut page.title, &mut page.message, 0)
                .unwrap();

            pages.push(page);
        }

        let reduced = pages.iter().map(ReducedPage::from).collect::<Vec<_>>();
        insta::assert_debug_snapshot!(reduced);
    }

    /// The declared warp size is the only thing bounding that region, so a host
    /// must not be able to append bytes and increment the size so the two agree
    /// again: those bytes are covered by the signing hash and reach no screen.
    fn warp_size_offset(data: &[u8]) -> usize {
        // The warp message is the last field, so its size field is the u32 whose
        // value runs exactly to the end of the transaction.
        (0..data.len() - 4)
            .find(|&off| {
                let v = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
                    as usize;
                v > 40 && off + 4 + v == data.len()
            })
            .expect("warp_message_size field not located")
    }

    #[test]
    fn register_l1_validator_rejects_bytes_smuggled_into_warp_region() {
        let data = REGISTER_L1_VALIDATOR_DATA;
        let off = warp_size_offset(data);
        let declared = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);

        // Baseline: untouched vector still parses.
        assert!(RegisterL1ValidatorTx::from_bytes(data).is_ok());

        let mut tampered = Vec::from(data);
        tampered.push(0x01);
        tampered[off..off + 4].copy_from_slice(&(declared + 1).to_be_bytes());

        assert!(
            RegisterL1ValidatorTx::from_bytes(&tampered).is_err(),
            "a byte appended inside the warp region was accepted"
        );
    }

    #[test]
    fn register_l1_validator_rejects_warp_size_larger_than_the_region() {
        let data = REGISTER_L1_VALIDATOR_DATA;
        let off = warp_size_offset(data);
        let declared = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);

        // Declared size overruns the buffer without any bytes being added.
        let mut tampered = Vec::from(data);
        tampered[off..off + 4].copy_from_slice(&(declared + 1).to_be_bytes());

        assert!(RegisterL1ValidatorTx::from_bytes(&tampered).is_err());
    }
}
