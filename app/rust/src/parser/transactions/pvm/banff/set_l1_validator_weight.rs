use crate::utils::hex_encode;
use crate::{
    handlers::handle_ui_message,
    parser::{
        nano_avax_to_fp_str, AddressedCallPayload, BaseTxFields, DisplayableItem, FromBytes,
        Header, ParserError, PvmOutput, WarpMessage, PVM_SET_L1_VALIDATOR_WEIGHT,
        U64_FORMATTED_SIZE,
    },
};
use bolos::PIC;
use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{
    bytes::complete::{tag, take},
    number::complete::be_u32,
};
use zemu_sys::ViewError;
pub const VALIDATION_ID_LEN: usize = 32;
pub const FIXED_FIELDS_LEN: u8 = 5;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct SetL1ValidatorWeightTx<'b> {
    pub tx_header: Header<'b>,
    pub base_tx: BaseTxFields<'b, PvmOutput<'b>>,
    pub warp_message_size: u32,
    pub warp_message: WarpMessage<'b>,
}

impl<'b> FromBytes<'b> for SetL1ValidatorWeightTx<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("SetL1ValidatorWeightTx::from_bytes_into\x00");

        let (rem, _) = tag(PVM_SET_L1_VALIDATOR_WEIGHT.to_be_bytes())(input)?;

        let out = out.as_mut_ptr();

        // tx header
        let tx_header = unsafe { &mut *addr_of_mut!((*out).tx_header).cast() };
        let rem = Header::from_bytes_into(rem, tx_header)?;

        // base_tx
        let base_tx = unsafe { &mut *addr_of_mut!((*out).base_tx).cast() };
        let rem = BaseTxFields::<PvmOutput>::from_bytes_into(rem, base_tx)?;

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
        }

        // Propagate the real remainder so Transaction::new_into's trailing-byte
        // check has something to act on.
        Ok(rem)
    }
}

impl<'b> SetL1ValidatorWeightTx<'b> {
    fn fee(&'b self) -> Result<u64, ParserError> {
        let base_outputs = self.base_tx.sum_outputs_amount()?;

        let sum_inputs = self.base_tx.sum_inputs_amount()?;

        let fee = sum_inputs
            .checked_sub(base_outputs)
            .ok_or(ParserError::OperationOverflows)?;
        Ok(fee)
    }
}

impl DisplayableItem for SetL1ValidatorWeightTx<'_> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // tx_info, validation_id, nonce, weight, fee
        Ok(FIXED_FIELDS_LEN)
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::pic_str;
        use itoa::Buffer;

        let mut itoa_buffer = Buffer::new();
        let mut buffer = [0; U64_FORMATTED_SIZE + 2];

        if let AddressedCallPayload::SetL1ValidatorWeight(ref msg) =
            self.warp_message.payload.payload
        {
            match item_n {
                0 => {
                    let label = pic_str!(b"SetL1ValWeight");
                    title[..label.len()].copy_from_slice(label);
                    let content = pic_str!(b"Transaction");
                    handle_ui_message(content, message, page)
                }
                1 => {
                    let prefix = pic_str!(b"0x"!);
                    let label = pic_str!(b"Validator");
                    title[..label.len()].copy_from_slice(label);

                    // prefix
                    let mut out = [0; VALIDATION_ID_LEN * 2 + 2];
                    let mut sz = prefix.len();
                    out[..prefix.len()].copy_from_slice(&prefix[..]);

                    sz += hex_encode(msg.validation_id, &mut out[prefix.len()..])
                        .map_err(|_| ViewError::Unknown)?;

                    handle_ui_message(&out[..sz], message, page)
                }
                2 => {
                    let label = pic_str!(b"Nonce");
                    title[..label.len()].copy_from_slice(label);
                    let buffer = itoa_buffer.format(msg.nonce);
                    handle_ui_message(buffer.as_bytes(), message, page)
                }
                3 => {
                    let label = pic_str!(b"Weight");
                    title[..label.len()].copy_from_slice(label);
                    let buffer = itoa_buffer.format(msg.weight);
                    handle_ui_message(buffer.as_bytes(), message, page)
                }
                4 => {
                    let label = pic_str!(b"Fee(AVAX)");
                    title[..label.len()].copy_from_slice(label);

                    let fee = self.fee().map_err(|_| ViewError::Unknown)?;
                    let fee_buff = nano_avax_to_fp_str(fee, &mut buffer[..])
                        .map_err(|_| ViewError::Unknown)?;

                    handle_ui_message(fee_buff, message, page)
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
    use std::prelude::v1::*;

    use crate::parser::snapshots_common::ReducedPage;
    use zuit::Page;

    const DATA: &[u8] = &[];

    include!("testvectors/set_l1_validator_weight.rs");
    #[test]
    fn parse_set_l1_validator_weight() {
        let validation_id = &[
            0x3d, 0x0a, 0xd1, 0x2b, 0x8e, 0xe8, 0x92, 0x8e, 0xdf, 0x24, 0x8c, 0xa9, 0x1c, 0xa5,
            0x56, 0x00, 0xfb, 0x38, 0x3f, 0x07, 0xc3, 0x2b, 0xff, 0x1d, 0x6d, 0xec, 0x47, 0x2b,
            0x25, 0xcf, 0x59, 0xa7,
        ];

        let (_, tx) = SetL1ValidatorWeightTx::from_bytes(SET_L1_VALIDATOR_WEIGHT_DATA).unwrap();

        if let AddressedCallPayload::SetL1ValidatorWeight(ref msg) = tx.warp_message.payload.payload
        {
            assert_eq!(msg.validation_id, validation_id);
            assert_eq!(msg.nonce, 42);
            assert_eq!(msg.weight, 2000);
        } else {
            panic!("Expected SetL1ValidatorWeight payload");
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn ui_set_l1_validator_weight() {
        println!("-------------------- Set L1 Validator Weight TX ------------------------");
        let (_, tx) = SetL1ValidatorWeightTx::from_bytes(SET_L1_VALIDATOR_WEIGHT_DATA).unwrap();

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
    fn set_l1_validator_weight_rejects_bytes_smuggled_into_warp_region() {
        let data = SET_L1_VALIDATOR_WEIGHT_DATA;
        let off = warp_size_offset(data);
        let declared = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);

        // Baseline: untouched vector still parses.
        assert!(SetL1ValidatorWeightTx::from_bytes(data).is_ok());

        let mut tampered = Vec::from(data);
        tampered.push(0x01);
        tampered[off..off + 4].copy_from_slice(&(declared + 1).to_be_bytes());

        assert!(
            SetL1ValidatorWeightTx::from_bytes(&tampered).is_err(),
            "a byte appended inside the warp region was accepted"
        );
    }

    #[test]
    fn set_l1_validator_weight_rejects_warp_size_larger_than_the_region() {
        let data = SET_L1_VALIDATOR_WEIGHT_DATA;
        let off = warp_size_offset(data);
        let declared = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);

        // Declared size overruns the buffer without any bytes being added.
        let mut tampered = Vec::from(data);
        tampered[off..off + 4].copy_from_slice(&(declared + 1).to_be_bytes());

        assert!(SetL1ValidatorWeightTx::from_bytes(&tampered).is_err());
    }
}
