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
use crate::checked_add;
use crate::handlers::handle_ui_message;
use crate::parser::{timestamp_to_date, DisplayableItem, FromBytes, NodeId, ParserError};
use crate::sys::{ViewError, PIC};

use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::{number::complete::be_u64, sequence::tuple};

mod weight_type;
pub use weight_type::{Stake, Weight};
use weight_type::{StakeTrait, WeightTrait};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct Validator<'b, W = Stake> {
    pub node_id: NodeId<'b>,
    pub start_time: u64,
    pub endtime: u64,
    pub weight: W,
}

impl<W: StakeTrait> Validator<'_, W> {
    pub fn stake(&self) -> u64 {
        self.weight.stake()
    }
}

impl<W: WeightTrait> Validator<'_, W> {
    pub fn weight(&self) -> u64 {
        self.weight.weight()
    }
}

impl<'b, W: FromBytes<'b>> FromBytes<'b> for Validator<'b, W> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("Validator::from_bytes_into\x00");

        let out = out.as_mut_ptr();

        let node_id = unsafe { &mut *addr_of_mut!((*out).node_id).cast() };
        let rem = NodeId::from_bytes_into(input, node_id)?;

        // Both are u64 on the wire. Read as i64, anything past i64::MAX went
        // negative, and timestamp_to_date overflowed near i64::MIN.
        let (rem, (start_time, endtime)) = tuple((be_u64, be_u64))(rem)?;

        let weight = unsafe { &mut *addr_of_mut!((*out).weight).cast() };
        let rem = W::from_bytes_into(rem, weight)?;

        // check for appropiate timestamps
        if endtime <= start_time {
            return Err(ParserError::InvalidTimestamp.into());
        }

        // Both are shown as dates, so refuse what the formatter cannot
        // represent now instead of failing to render the screen later.
        for t in [start_time, endtime] {
            timestamp_to_date(t).map_err(|_| ParserError::InvalidTimestamp)?;
        }

        unsafe {
            addr_of_mut!((*out).start_time).write(start_time);
            addr_of_mut!((*out).endtime).write(endtime);
        }

        Ok(rem)
    }
}

impl<W: DisplayableItem> DisplayableItem for Validator<'_, W> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // node_id(1), start_time, endtime and weight(1)
        let items = self.node_id.num_items()?;
        let weight = self.weight.num_items()?;

        checked_add!(ViewError::Unknown, items, 2, weight)
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        use crate::parser::timestamp_to_str_date;
        use bolos::pic_str;

        match item_n {
            0 => self.node_id.render_item(0, title, message, page),
            1 => {
                let label = pic_str!(b"Start time");
                title[..label.len()].copy_from_slice(label);
                let time =
                    timestamp_to_str_date(self.start_time).map_err(|_| ViewError::Unknown)?;
                handle_ui_message(time.as_slice(), message, page)
            }
            2 => {
                let label = pic_str!(b"End time");
                title[..label.len()].copy_from_slice(label);
                let time = timestamp_to_str_date(self.endtime).map_err(|_| ViewError::Unknown)?;
                handle_ui_message(time.as_slice(), message, page)
            }
            3 => self.weight.render_item(0, title, message, page),
            _ => Err(ViewError::NoData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::prelude::v1::*;

    fn validator(start: u64, end: u64) -> Vec<u8> {
        let mut v = vec![0xe9; 20];
        v.extend(start.to_be_bytes());
        v.extend(end.to_be_bytes());
        v.extend(1_000_000_000u64.to_be_bytes());
        v
    }

    #[test]
    fn validator_times_render() {
        let data = validator(1_600_000_000, 1_602_000_000);
        let (_, v) = Validator::<Stake>::from_bytes(&data).unwrap();
        let mut title = [0u8; 18];
        let mut message = [0u8; 64];
        v.render_item(2, &mut title, &mut message, 0).unwrap();
        assert!(message.starts_with(b"2020-10-06 16:00:00 UTC"));
    }

    #[test]
    fn validator_times_past_date_table_are_rejected() {
        // Times were read as i64: 1 << 63 became i64::MIN, where the old
        // date arithmetic overflowed, and u64::MAX became -1. Now they are
        // u64, and everything from the first second past the year table
        // (2369-01-01) on is rejected.
        const END_OF_TABLE: u64 = 145_732 * 86_400;
        for (start, end) in [
            (1_600_000_000, 1u64 << 63),
            (1_600_000_000, u64::MAX),
            (1u64 << 40, (1u64 << 40) + 1),
            (1_600_000_000, END_OF_TABLE),
        ] {
            let data = validator(start, end);
            assert_eq!(
                Validator::<Stake>::from_bytes(&data).unwrap_err(),
                ParserError::InvalidTimestamp.into(),
                "{} .. {}",
                start,
                end
            );
        }

        // the last second of the table is still a valid end time
        let data = validator(1_600_000_000, END_OF_TABLE - 1);
        assert!(Validator::<Stake>::from_bytes(&data).is_ok());
    }
}
