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
use core::convert::TryFrom;
use core::ops::Deref;

use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{bytes::complete::take, number::complete::be_u32};
use zemu_sys::ViewError;

use crate::parser::{
    DisplayableItem, FromBytes, Header, NetworkId, ObjectList, Output, OutputIdx, ParserError,
    TransferableInput, TransferableOutput,
};

pub const MAX_MEMO_LEN: usize = 256;

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct BaseTxFields<'b, O>
where
    O: FromBytes<'b> + DisplayableItem + Deref<Target = Output<'b>> + 'b,
{
    // lazy parsing of inputs/outpus
    pub outputs: ObjectList<'b, TransferableOutput<'b, O>>,
    // a bit-wise idx that tells what outputs could be displayed
    // in the ui stage.
    // this is set during the parsing stage.
    renderable_out: OutputIdx,
    // inputs can be generic as well.
    // but so far, there is only one input
    // across all chains and their transactions.
    // if this change in the future, we can make
    // it generic over any input-type, in the maintenance cycle
    pub inputs: ObjectList<'b, TransferableInput<'b>>,
    pub memo: &'b [u8],
    // network id from the transaction header, to tell which outputs are AVAX
    network_id: u32,
}

impl<'b, O> BaseTxFields<'b, O>
where
    O: FromBytes<'b> + DisplayableItem + Deref<Target = Output<'b>> + 'b,
{
    /// The AVAX asset id on this transaction's network, if it is known.
    pub fn avax_asset_id(&self) -> Option<&'static [u8; 32]> {
        NetworkId::try_from(self.network_id).ok()?.avax_asset_id()
    }

    pub fn disable_output_if(&mut self, address: &[u8]) {
        // skip filtering out outputs if there is only one
        let num_outs = self.outputs.iter().count();
        if num_outs <= 1 {
            return;
        }

        self.force_disable_output(address);
    }

    // Omits the check if there is only one output, as there are
    // exceptions to this rule.
    pub fn force_disable_output(&mut self, address: &[u8]) {
        let mut idx = 0;
        let mut render = self.renderable_out;
        let avax = self.avax_asset_id();

        // outputs is define as an Object List of TransferableOutputs,
        // when parsing transactions we ensure that it is not longer than
        // 64, as we use that value as a limit for the bitwise operation,
        // this ensures that render ^= 1 << idx never overflows.
        self.outputs.iterate_with(|o| {
            if o.is_hideable_change(address, avax) {
                render ^= 1 << idx;
            }
            idx += 1;
        });
        self.renderable_out = render;
    }

    pub fn sum_inputs_amount(&self) -> Result<u64, ParserError> {
        self.inputs
            .iter()
            .map(|input| input.amount().ok_or(ParserError::UnexpectedError))
            .try_fold(0u64, |acc, x| {
                acc.checked_add(x?).ok_or(ParserError::OperationOverflows)
            })
    }

    pub fn sum_outputs_amount(&'b self) -> Result<u64, ParserError> {
        self.outputs
            .iter()
            .map(|output| (*output).amount().ok_or(ParserError::UnexpectedError))
            .try_fold(0u64, |acc, x| {
                acc.checked_add(x?).ok_or(ParserError::OperationOverflows)
            })
    }

    pub fn outputs(&'b self) -> &'b ObjectList<'b, TransferableOutput<'b, O>> {
        &self.outputs
    }

    pub fn inputs(&self) -> &ObjectList<'_, TransferableInput<'_>> {
        &self.inputs
    }

    pub fn base_outputs_num_items(&'b self) -> Result<u8, ViewError> {
        let mut items = 0;
        let mut idx = 0;

        // store an error during execution, specifically
        // if an overflows happens
        let mut err: Option<ViewError> = None;

        // outputs is defined as an Object List of TransferableOutputs,
        // when parsing transactions we ensure that it is not longer than
        // 64, as we use that value as a limit for the bitwise operation,
        // this ensures that render ^= 1 << idx never overflows.
        self.outputs.iterate_with(|o| {
            let render = self.renderable_out & (1 << idx);
            if render > 0 {
                match o
                    .num_items()
                    .and_then(|a| a.checked_add(items).ok_or(ViewError::Unknown))
                {
                    Ok(i) => items = i,
                    Err(_) => err = Some(ViewError::Unknown),
                }
            }
            idx += 1;
        });

        if err.is_some() {
            return Err(ViewError::Unknown);
        }
        Ok(items)
    }

    // Gets the obj that contain the item_n, along with the index
    // of the item. Returns an error otherwise
    pub fn base_output_with_item(
        &'b self,
        item_n: u8,
    ) -> Result<(TransferableOutput<'b, O>, u8), ParserError> {
        let mut count = 0usize;
        let mut obj_item_n = 0;

        // index to check for renderable outputs.
        // we can omit this and be "fancy" with iterators but
        // they consume a lot of stack.
        // causing stack overflows in nanos
        let mut idx = 0;
        // gets the output that contains item_n
        // and its corresponding index
        let filter = |o: &TransferableOutput<'b, O>| -> bool {
            // filter out
            let render = self.renderable_out & (1 << idx) > 0;
            idx += 1;

            if !render {
                return false;
            }

            let Ok(n) = o.num_items() else {
                return false;
            };

            for index in 0..n {
                obj_item_n = index;
                if count == item_n as usize {
                    return true;
                }
                count += 1;
            }
            false
        };

        let obj = self
            .outputs()
            .get_obj_if(filter)
            .ok_or(ParserError::DisplayIdxOutOfRange)?;

        Ok((obj, obj_item_n))
    }
}

impl<'b, O> BaseTxFields<'b, O>
where
    O: FromBytes<'b> + DisplayableItem + Deref<Target = Output<'b>> + 'b,
{
    /// Parse the base fields that follow `header` in a transaction.
    ///
    /// The header is needed to know the network, and so which asset is
    /// AVAX: only AVAX outputs may be hidden as change. There is deliberately
    /// no FromBytes impl, so no transaction can parse these fields without it.
    #[inline(never)]
    pub fn from_bytes_after(
        header: &Header<'_>,
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("BaseTxFields::from_bytes_into\x00");

        let out = out.as_mut_ptr();
        // check for the number of outputs before parsing then as now
        // it has to be checked for the outputIdx capacity which is used
        // to tell if an output should be rendered or not.
        let (_, num_outputs) = be_u32(input)?;
        if num_outputs > OutputIdx::BITS {
            return Err(ParserError::TooManyOutputs.into());
        }
        // get outputs
        let outputs = unsafe { &mut *addr_of_mut!((*out).outputs).cast() };
        let rem = ObjectList::<TransferableOutput<O>>::new_into(input, outputs)?;

        // inputs
        let inputs = unsafe { &mut *addr_of_mut!((*out).inputs).cast() };
        let rem = ObjectList::<TransferableInput>::new_into(rem, inputs)?;

        // memo
        let (rem, memo_len) = be_u32(rem)?;

        if memo_len as usize > MAX_MEMO_LEN {
            return Err(ParserError::ValueOutOfRange.into());
        }

        let (rem, memo) = take(memo_len as usize)(rem)?;

        //good ptr and no uninit reads
        unsafe {
            addr_of_mut!((*out).memo).write(memo);
            addr_of_mut!((*out).network_id).write(header.network_id);
            // by default all outputs are renderable
            addr_of_mut!((*out).renderable_out).write(OutputIdx::MAX);
        }

        Ok(rem)
    }
}

impl<'b, O> BaseTxFields<'b, O>
where
    O: FromBytes<'b> + DisplayableItem + Deref<Target = Output<'b>> + 'b,
{
    /// Render one item of one base output, encoding addresses with `hrp`.
    ///
    /// Several transactions carry base outputs that their own renderers
    /// never showed. They all need the same shape -- amount line, one screen
    /// per address, then the locked-funds line where the output type has one
    /// -- so it lives here rather than being copied into each of them. It is
    /// generic over the output type because the X-chain CreateAsset needs it
    /// as much as the P-chain types do.
    pub fn render_base_output_with_hrp(
        &'b self,
        hrp: &str,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        let (obj, obj_item_n) = self
            .base_output_with_item(item_n)
            .map_err(|_| ViewError::NoData)?;

        let inner: &Output<'_> = &obj.output;

        // Only secp_transfer outputs are supported, as in import/export.
        let _ = inner.secp_transfer().ok_or(ViewError::NoData)?;

        // Items of the inner output alone. A locked PvmOutput counts one more
        // (the locked-funds line), which its own render_item draws below.
        let num_inner_items = inner.num_items()?;

        match obj_item_n {
            0 => obj.render_item(obj_item_n, title, message, page),
            // addresses, then the threshold when there are several
            x @ 1.. if x < num_inner_items => {
                obj.render_item_with_hrp(hrp, x, title, message, page)
            }
            x if x == num_inner_items => obj.render_item(obj_item_n, title, message, page),
            _ => Err(ViewError::NoData),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::parser::tx_builder::*;
    use crate::parser::{ParserError, Transaction};
    use std::prelude::v1::*;

    // 2100-01-01 00:00:00 UTC
    const YEAR_2100: u64 = 4_102_444_800;

    fn ins() -> Vec<Vec<u8>> {
        vec![input(1, &FUJI_AVAX, 100_000_000_000)]
    }

    #[test]
    fn plain_change_is_hidden() {
        let tx = x_transfer(
            &[out(10_000_000_000, RECIPIENT), out(89_999_000_000, CHANGE)],
            &ins(),
        );
        let shown = screens(&tx, Some(CHANGE));
        assert!(!shown.iter().any(|s| s.contains("89.999")), "{:#?}", shown);
    }

    #[test]
    fn time_locked_change_is_shown() {
        // Honest transfer vs one whose change is locked until 2100: the change
        // used to be hidden either way, so both reviews were identical.
        let honest = x_transfer(
            &[out(10_000_000_000, RECIPIENT), out(89_999_000_000, CHANGE)],
            &ins(),
        );
        let locked = x_transfer(
            &[
                out(10_000_000_000, RECIPIENT),
                transferable(&FUJI_AVAX, secp_out(89_999_000_000, YEAR_2100, 1, &[CHANGE])),
            ],
            &ins(),
        );
        let honest = screens(&honest, Some(CHANGE));
        let locked = screens(&locked, Some(CHANGE));
        assert_ne!(honest, locked);
        assert!(locked.contains(&"Transfer: 89.999 AVAX to ".to_string()), "{:#?}", locked);
        assert!(locked.contains(&"Locked until: 2100-01-01 00:00:00 UTC".to_string()));
    }

    #[test]
    fn stakeable_locked_change_is_shown() {
        let locked = p_base(
            &[
                out(10_000_000_000, RECIPIENT),
                transferable(
                    &FUJI_AVAX,
                    stakeable_locked(YEAR_2100, secp_out(89_999_000_000, 0, 1, &[CHANGE])),
                ),
            ],
            &ins(),
        );
        let shown = screens(&locked, Some(CHANGE));
        assert!(
            shown.contains(&"Funds locked: 89.999 AVAX until 2100-01-01 00:00:00 UTC".to_string()),
            "{:#?}",
            shown
        );
    }

    #[test]
    fn change_in_another_asset_is_shown() {
        let tx = x_transfer(
            &[
                out(10_000_000_000, RECIPIENT),
                transferable(&OTHER_ASSET, secp_out(5, 0, 1, &[CHANGE])),
                out(89_999_000_000, CHANGE),
            ],
            &[input(1, &FUJI_AVAX, 100_000_000_000), input(2, &OTHER_ASSET, 5)],
        );
        let shown = screens(&tx, Some(CHANGE));
        // the AVAX change is hidden, the other asset's is not
        assert!(!shown.iter().any(|s| s.contains("89.999")), "{:#?}", shown);
        assert!(shown.iter().any(|s| s.starts_with("Transfer: 0.000000005")), "{:#?}", shown);
    }

    #[test]
    fn locktime_is_shown_on_every_output() {
        let tx = x_transfer(
            &[transferable(&FUJI_AVAX, secp_out(10_000_000_000, YEAR_2100, 1, &[RECIPIENT]))],
            &ins(),
        );
        assert!(screens(&tx, None).contains(&"Locked until: 2100-01-01 00:00:00 UTC".to_string()));
    }

    #[test]
    fn locktime_past_date_table_is_rejected() {
        let tx = x_transfer(
            &[transferable(&FUJI_AVAX, secp_out(10_000_000_000, u64::MAX, 1, &[RECIPIENT]))],
            &ins(),
        );
        assert_eq!(Transaction::new(&tx).unwrap_err(), ParserError::InvalidTimestamp);
    }
}
