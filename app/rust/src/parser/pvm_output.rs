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
use crate::{
    handlers::handle_ui_message,
    parser::{
        error::ParserError, nano_avax_to_fp_str, timestamp_to_date, timestamp_to_str_date, Address,
        DisplayableItem,
        FromBytes, Output, OutputLock, OutputType, SECPOutputOwners, SECPTransferOutput,
        FORMATTED_STR_DATE_LEN, U64_FORMATTED_SIZE
    },
};
use core::ops::Deref;

use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{
    bytes::complete::tag,
    number::complete::{be_u32, be_u64},
};
use zemu_sys::ViewError;

// This literal can be defined inline but, it is part of a big
// buffer on which we write other information so that we need
// its length to initialize such buffer and having the length defined as a constant and the
// literal inlined can lead to len mismatch which can cause overlapping.
const AVAX_UNTIL: &[u8; 12] = b" AVAX until ";

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct PvmOutput<'b> {
    pub locktime: Option<u64>,
    pub output: Output<'b>,
}

impl<'b> Deref for PvmOutput<'b> {
    type Target = Output<'b>;

    fn deref(&self) -> &Self::Target {
        &self.output
    }
}

impl OutputLock for PvmOutput<'_> {
    fn stakeable_locktime(&self) -> Option<u64> {
        self.locktime
    }
}

impl PvmOutput<'_> {
    const LOCKED_OUTPUT_TAG: u32 = 0x00000016;

    pub fn amount(&self) -> Option<u64> {
        self.output.amount()
    }

    pub fn is_locked(&self) -> bool {
        self.locktime.is_some()
    }

    pub fn num_inner_items(&self) -> Result<u8, ViewError> {
        self.output.num_items()
    }
}

impl<'b> FromBytes<'b> for PvmOutput<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        // initialize locktime
        let mut locktime = None;
        let output = out.as_mut_ptr();

        // check first if this output is locked
        let rem = if let Ok((r, _)) =
            tag::<_, _, ParserError>(Self::LOCKED_OUTPUT_TAG.to_be_bytes())(input)
        {
            // locked outputs should come with a locktime. It is a u64 on
            // the wire (stakeable.LockOut.Locktime) and has to be shown as a
            // date, so refuse one the date formatter cannot represent here
            // rather than failing when the screen is rendered.
            let (rem, raw_locktime) = be_u64(r)?;
            timestamp_to_date(raw_locktime).map_err(|_| ParserError::InvalidTimestamp)?;
            locktime = Some(raw_locktime);
            rem
        } else {
            input
        };

        // now parse the input
        let variant_type = Self::parse_output_type(rem)?;

        let data = unsafe { &mut *addr_of_mut!((*output).output).cast() };
        let rem = Output::from_bytes(rem, variant_type, data)?;

        // Safe write, pointer is valid
        unsafe {
            addr_of_mut!((*output).locktime).write(locktime);
        }

        Ok(rem)
    }
}

impl<'b> PvmOutput<'b> {
    fn parse_output_type(input: &[u8]) -> Result<OutputType, nom::Err<ParserError>> {
        let (_, variant_type) = be_u32(input)?;

        let v = match variant_type {
            SECPTransferOutput::TYPE_ID => OutputType::SECPTransfer,
            // by definition p-chain also uses this type, but the
            // ecosystem do not support this yet.
            SECPOutputOwners::TYPE_ID => OutputType::SECPOwners,

            _ => return Err(ParserError::InvalidTypeId.into()),
        };

        Ok(v)
    }

    pub fn get_address_at(&'b self, idx: usize) -> Option<Address<'b>> {
        match self.output {
            Output::SECPTransfer(ref o) => o.get_address_at(idx),
            Output::SECPOwners(ref o) => o.get_address_at(idx),
            _ => None,
        }
    }
}

impl DisplayableItem for PvmOutput<'_> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // check if output is locked, if so the number of items
        // includes the locked information
        let items = self.num_inner_items()?;

        items
            .checked_add(self.is_locked() as u8)
            .ok_or(ViewError::Unknown)
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::{pic_str, PIC};

        let num_inner_items = self.output.num_items()?;
        match item_n {
            // Use the default implementation, if transactions require to improve this they can do
            // separately in their ui implementation
            // title
            0 => self.output.render_item(item_n as _, title, message, page),
            // render inner output addresses or other info
            x @ 1.. if x < num_inner_items => {
                self.output.render_item(item_n as _, title, message, page)
            }
            // render "locked" informations which inner output DO not know nothing about
            // only after rendering all inner_output items
            x if x == num_inner_items && self.is_locked() => {
                // legacy app displays:
                // 'Funds locked', body: '0.5 AVAX until 2021-05-31 21:28:00 UTC'},
                // so lets do the same thing
                let t = pic_str!(b"Funds locked");
                title[..t.len()].copy_from_slice(t);

                let avax_until = PIC::new(AVAX_UNTIL).into_inner();
                let mut content = [0; AVAX_UNTIL.len()
                    + FORMATTED_STR_DATE_LEN
                    + U64_FORMATTED_SIZE
                    + 2];
                // write the amount
                let amount = self.amount().ok_or(ViewError::Unknown)?;
                let num_len = nano_avax_to_fp_str(amount, &mut content[..])
                    .map_err(|_| ViewError::Unknown)?
                    .len();
                // write avax until
                let mut total_len = num_len + avax_until.len();
                content[num_len..total_len].copy_from_slice(avax_until);
                // finally, write the date
                let locktime = self.locktime.ok_or(ViewError::NoData)?;
                let date_str = timestamp_to_str_date(locktime).map_err(|_| ViewError::Unknown)?;
                content[total_len..]
                    .iter_mut()
                    .zip(date_str.as_slice())
                    .take(date_str.len())
                    .for_each(|(d, s)| *d = *s);
                total_len += date_str.len();

                handle_ui_message(&content[..total_len], message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::prelude::v1::*;

    // stakeable.LockOut{locktime, SECPTransferOutput{1 AVAX, 0, 1, [addr]}}
    fn locked_output(locktime: u64) -> Vec<u8> {
        let mut v = PvmOutput::LOCKED_OUTPUT_TAG.to_be_bytes().to_vec();
        v.extend(locktime.to_be_bytes());
        v.extend(SECPTransferOutput::TYPE_ID.to_be_bytes());
        v.extend(1_000_000_000u64.to_be_bytes());
        v.extend(0u64.to_be_bytes());
        v.extend(1u32.to_be_bytes());
        v.extend(1u32.to_be_bytes());
        v.extend([0x63; 20]);
        v
    }

    fn locked_line(output: &PvmOutput) -> String {
        let item = output.num_items().unwrap() - 1;
        let mut title = [0u8; 18];
        let mut message = [0u8; 100];
        output.render_item(item, &mut title, &mut message, 0).unwrap();
        let end = message.iter().position(|&b| b == 0).unwrap();
        String::from_utf8(message[..end].to_vec()).unwrap()
    }

    #[test]
    fn stakeable_lock_renders_its_date() {
        // 2025-01-01 00:00:00 UTC
        let data = locked_output(1_735_689_600);
        let (_, output) = PvmOutput::from_bytes(&data).unwrap();
        assert_eq!(output.locktime, Some(1_735_689_600));
        assert_eq!(locked_line(&output), "1 AVAX until 2025-01-01 00:00:00 UTC");
    }

    #[test]
    fn stakeable_lock_beyond_date_table_is_rejected() {
        // About 11.76 million years out. The day count used to be truncated to
        // u32, so this printed as "until 2025-01-01 00:00:00 UTC".
        for locktime in [0x0001_5180_6774_8580u64, 1 << 63, u64::MAX] {
            let data = locked_output(locktime);
            assert_eq!(
                PvmOutput::from_bytes(&data).unwrap_err(),
                ParserError::InvalidTimestamp.into(),
                "locktime {:#x}",
                locktime
            );
        }
    }
}
