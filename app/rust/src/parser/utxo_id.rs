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
use nom::bytes::complete::take;
use nom::number::complete::be_u32;
use zemu_sys::ViewError;

use crate::handlers::handle_ui_message;
use crate::parser::{
    asset_id::{cb58_encode_id, ASSET_ID_CB58_MAX_LEN},
    DisplayableItem, FromBytes, ParserError,
};

pub const TX_ID_LEN: usize = 32;

/// `<CB58 tx id>:<output index>`, the form avalanchego prints a UTXO id in:
/// the CB58 id, the separator and a u32 in decimal.
const UTXO_ID_STR_MAX_LEN: usize = ASSET_ID_CB58_MAX_LEN + 1 + 10;

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct UtxoId<'b> {
    tx_id: &'b [u8; TX_ID_LEN],
    out_idx: u32,
}

impl<'b> FromBytes<'b> for UtxoId<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("UtxoId::from_bytes_into\x00");

        let (rem, tx_id) = take(TX_ID_LEN)(input)?;
        // This would not fail as previous line ensures we take
        // the right amount of bytes, also the alignemnt is correct
        let tx_id = arrayref::array_ref!(tx_id, 0, TX_ID_LEN);

        // output index
        let (rem, out_idx) = be_u32(rem)?;

        //good ptr and no uninit reads
        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).tx_id).write(tx_id);
            addr_of_mut!((*out).out_idx).write(out_idx);
        }

        Ok(rem)
    }
}

impl DisplayableItem for UtxoId<'_> {
    fn num_items(&self) -> Result<u8, ViewError> {
        Ok(1)
    }

    /// One "UTXO" screen: the producing transaction's CB58 id and the output
    /// index within it, as `<tx id>:<index>`.
    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::{pic_str, PIC};

        if item_n != 0 {
            return Err(ViewError::NoData);
        }

        let label = pic_str!(b"UTXO");
        title[..label.len()].copy_from_slice(label);

        let mut encoded = [0; ASSET_ID_CB58_MAX_LEN];
        let id_len = cb58_encode_id(self.tx_id, &mut encoded)?;

        let mut itoa_buffer = itoa::Buffer::new();
        let index = itoa_buffer.format(self.out_idx).as_bytes();

        let mut out = [0; UTXO_ID_STR_MAX_LEN];
        let len = id_len + 1 + index.len();
        out[..id_len].copy_from_slice(&encoded[..id_len]);
        out[id_len] = b':';
        out[id_len + 1..len].copy_from_slice(index);

        handle_ui_message(&out[..len], message, page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::snapshots_common::ReducedPage;
    use std::prelude::v1::*;
    use zuit::Page;

    #[test]
    fn renders_cb58_tx_id_and_index() {
        let mut data = vec![0u8; TX_ID_LEN];
        data.extend_from_slice(&u32::MAX.to_be_bytes());
        let (_, id) = UtxoId::from_bytes(&data).unwrap();

        let mut page = Page::<18, 1024>::default();
        id.render_item(0, &mut page.title, &mut page.message, 0)
            .unwrap();
        // CB58 of the all-zero id, as avalanchego prints ids.Empty
        assert_eq!(
            format!("{}", ReducedPage::from(&page)),
            r#""UTXO": "11111111111111111111111111111111LpoYY:4294967295""#
        );
        assert!(id
            .render_item(1, &mut page.title, &mut page.message, 0)
            .is_err());
    }
}
