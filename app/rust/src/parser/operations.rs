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

mod nft_mint_operation;
mod nft_transfer_operation;
mod secp_mint_operation;

pub use nft_mint_operation::NFTMintOperation;
pub use nft_transfer_operation::NFTTransferOperation;
use nom::number::complete::be_u32;
pub use secp_mint_operation::SECPMintOperation;
use zemu_sys::ViewError;

use core::convert::TryFrom;
use core::{mem::MaybeUninit, ptr::addr_of_mut};

use crate::checked_add;
use crate::handlers::handle_ui_message;
use crate::parser::{
    asset_id::ASSET_ID_CB58_MAX_LEN, AssetId, DisplayableItem, FromBytes, ObjectList, UtxoId,
};

use super::ParserError;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct TransferableOp<'b> {
    asset_id: AssetId<'b>,
    utx_id: ObjectList<'b, UtxoId<'b>>,
    operation: Operation<'b>,
}

impl<'b> FromBytes<'b> for TransferableOp<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("TransferableOp::from_bytes\x00");
        let output = out.as_mut_ptr();

        let asset = unsafe { &mut *addr_of_mut!((*output).asset_id).cast() };
        let rem = AssetId::from_bytes_into(input, asset)?;

        let utx_id = unsafe { &mut *addr_of_mut!((*output).utx_id).cast() };
        let rem = ObjectList::<UtxoId>::new_into(rem, utx_id)?;

        let op = unsafe { &mut *addr_of_mut!((*output).operation).cast() };
        let rem = Operation::from_bytes_into(rem, op)?;

        Ok(rem)
    }
}

impl TransferableOp<'_> {
    /// How many UTXOs the operation consumes, each shown on its own screen.
    /// More than a review can count is an error, not a shorter review.
    fn utxo_items(&self) -> Result<u8, ViewError> {
        u8::try_from(self.utx_id.iter().count()).map_err(|_| ViewError::Unknown)
    }

    /// Items: the operation type, then the asset it operates on, then every
    /// UTXO it consumes, then the operation's own items with addresses
    /// encoded for `hrp`.
    ///
    /// The asset and the consumed UTXOs were never shown, so an operation on
    /// any NFT or mint authority the user holds reviewed the same as one on
    /// the object they meant: group id and payload are not unique, the UTXO
    /// id is what names the object being spent.
    pub fn render_item_with_hrp(
        &self,
        hrp: &str,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::{pic_str, PIC};

        let utxos = self.utxo_items()?;

        match item_n {
            0 => self
                .operation
                .render_item_with_hrp(hrp, 0, title, message, page),
            1 => {
                let label = pic_str!(b"Asset");
                title[..label.len()].copy_from_slice(label);

                let mut encoded = [0; ASSET_ID_CB58_MAX_LEN];
                let len = self.asset_id.cb58_into(&mut encoded)?;
                handle_ui_message(&encoded[..len], message, page)
            }
            x if x - 2 < utxos => self
                .utx_id
                .get((x - 2) as usize)
                .ok_or(ViewError::NoData)?
                .render_item(0, title, message, page),
            x => self
                .operation
                .render_item_with_hrp(hrp, x - 1 - utxos, title, message, page),
        }
    }
}

impl DisplayableItem for TransferableOp<'_> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // the operation's items, the asset and each consumed UTXO
        checked_add!(
            ViewError::Unknown,
            self.operation.num_items()?,
            1u8,
            self.utxo_items()?
        )
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        self.render_item_with_hrp("", item_n, title, message, page)
    }
}

// Important: do not change the repr attribute,
// as this type is use as the tag field
// for the Operation enum which has the same representation
// Variants share an `Op` suffix to mirror the Avalanche protocol op-codes
// (SECPMintOp, NFTTransferOp, NFTMintOp).
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
#[repr(u8)]
pub enum OpType {
    SECPMintOp,
    NFTTransferOp,
    NFTMintOp,
}

impl TryFrom<u32> for OpType {
    type Error = ParserError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        let t = match value {
            SECPMintOperation::TYPE_ID => Self::SECPMintOp,
            NFTMintOperation::TYPE_ID => Self::NFTMintOp,
            NFTTransferOperation::TYPE_ID => Self::NFTTransferOp,
            _ => return Err(ParserError::InvalidTypeId),
        };
        Ok(t)
    }
}

#[repr(C)]
struct SECPOpVariant<'b>(OpType, SECPMintOperation<'b>);

#[repr(C)]
struct NFTMintOpVariant<'b>(OpType, NFTMintOperation<'b>);

#[repr(C)]
struct NFTTransferOpVariant<'b>(OpType, NFTTransferOperation<'b>);

#[derive(Clone, Copy, PartialEq, Eq)]
// DO not change the representation
// as it would cause unalignment issues
// with the OutputType tag
#[repr(u8)]
#[cfg_attr(test, derive(Debug))]
pub enum Operation<'b> {
    SECPMint(SECPMintOperation<'b>),
    NFTTransfer(NFTTransferOperation<'b>),
    NFTMint(NFTMintOperation<'b>),
}

impl Operation<'_> {
    pub fn operation_name(&self) -> &'static str {
        use bolos::{pic_str, PIC};

        match self {
            Operation::SECPMint(_) => pic_str!("SECPMintOperation"),
            Operation::NFTTransfer(_) => pic_str!("NFTTransferOperation"),
            Operation::NFTMint(_) => pic_str!("NFTMintOperation"),
        }
    }
}

impl<'b> FromBytes<'b> for Operation<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("Operation::from_bytes\x00");

        let (_, id) = be_u32(input)?;
        let op_type = OpType::try_from(id)?;

        let rem = match op_type {
            OpType::SECPMintOp => {
                let out = out.as_mut_ptr() as *mut SECPOpVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = SECPMintOperation::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(op_type);
                }

                rem
            }
            OpType::NFTMintOp => {
                let out = out.as_mut_ptr() as *mut NFTMintOpVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = NFTMintOperation::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(op_type);
                }

                rem
            }
            OpType::NFTTransferOp => {
                let out = out.as_mut_ptr() as *mut NFTTransferOpVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = NFTTransferOperation::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(op_type);
                }

                rem
            }
        };
        Ok(rem)
    }
}

impl Operation<'_> {
    /// Same as the DisplayableItem rendering, but encodes every address it
    /// shows -- NFT owners, and the SECP mint operation's new owners and mint
    /// authority -- for `hrp`.
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
            let title_content = pic_str!(b"Op. Type:");
            title[..title_content.len()].copy_from_slice(title_content);

            let op_type = self.operation_name();

            return handle_ui_message(op_type.as_bytes(), message, page);
        }

        let item_n = item_n - 1;

        match self {
            Operation::NFTMint(op) => op.render_item_with_hrp(hrp, item_n, title, message, page),
            Operation::NFTTransfer(op) => {
                op.render_item_with_hrp(hrp, item_n, title, message, page)
            }
            Operation::SECPMint(op) => op.render_item_with_hrp(hrp, item_n, title, message, page),
        }
    }
}

impl DisplayableItem for Operation<'_> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // operation description
        // + operation items
        let items = match self {
            Operation::NFTMint(op) => op.num_items()?,
            Operation::NFTTransfer(op) => op.num_items()?,
            Operation::SECPMint(op) => op.num_items()?,
        };

        checked_add!(ViewError::Unknown, 1u8, items)
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::{pic_str, PIC};

        if item_n == 0 {
            let title_content = pic_str!(b"Op. Type:");
            title[..title_content.len()].copy_from_slice(title_content);

            let op_type = self.operation_name();

            return handle_ui_message(op_type.as_bytes(), message, page);
        }

        let item_n = item_n - 1;

        match self {
            Operation::NFTMint(op) => op.render_item(item_n, title, message, page),
            Operation::NFTTransfer(op) => op.render_item(item_n, title, message, page),
            Operation::SECPMint(op) => op.render_item(item_n, title, message, page),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::prelude::v1::*;

    const DATA: &[u8] = &[
        // assetID:
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, // number of utxoIDs:
        0x00, 0x00, 0x00, 0x01, // txID:
        0xf1, 0xe1, 0xd1, 0xc1, 0xb1, 0xa1, 0x91, 0x81, 0x71, 0x61, 0x51, 0x41, 0x31, 0x21, 0x11,
        0x01, 0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20,
        0x10, 0x00, // utxoIndex:
        0x00, 0x00, 0x00, 0x05, // op:
        0x00, 0x00, 0x00, 0x0d, // number of address indices:
        0x00, 0x00, 0x00, 0x02, // address index 0:
        0x00, 0x00, 0x00, 0x07, // address index 1:
        0x00, 0x00, 0x00, 0x03, // groupID:
        0x00, 0x00, 0x30, 0x39, // length of payload:
        0x00, 0x00, 0x00, 0x03, // payload:
        0x43, 0x11, 0x00, // locktime:
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0x31, // threshold:
        0x00, 0x00, 0x00, 0x01, // number of addresses:
        0x00, 0x00, 0x00, 0x02, // addrs[0]:
        0x51, 0x02, 0x5c, 0x61, 0xfb, 0xcf, 0xc0, 0x78, 0xf6, 0x93, 0x34, 0xf8, 0x34, 0xbe, 0x6d,
        0xd2, 0x6d, 0x55, 0xa9, 0x55, // addrs[1]:
        0xc3, 0x34, 0x41, 0x28, 0xe0, 0x60, 0x12, 0x8e, 0xde, 0x35, 0x23, 0xa2, 0x4a, 0x46, 0x1c,
        0x89, 0x43, 0xab, 0x08, 0x59,
    ];

    #[test]
    fn parse_transferable_operation() {
        let op = TransferableOp::from_bytes(DATA).unwrap().1;
        assert!(matches!(op.operation, Operation::NFTTransfer(..)));
    }

    /// Every screen of `op`, as `"title": "message"`, first page only.
    fn screens(op: &TransferableOp) -> Vec<String> {
        use crate::parser::snapshots_common::ReducedPage;
        use zuit::Page;

        (0..op.num_items().unwrap())
            .map(|i| {
                let mut page = Page::<18, 1024>::default();
                op.render_item_with_hrp("fuji", i, &mut page.title, &mut page.message, 0)
                    .unwrap_or_else(|e| panic!("item {} failed: {:?}", i, e));
                format!("{}", ReducedPage::from(&page))
            })
            .collect()
    }

    /// `DATA` with its single consumed UTXO replaced by `utxos`.
    fn with_utxos(utxos: &[([u8; 32], u32)]) -> Vec<u8> {
        let utxo_start = 32;
        let utxo_end = utxo_start + 4 + 36;
        let mut data = DATA[..utxo_start].to_vec();
        data.extend_from_slice(&(utxos.len() as u32).to_be_bytes());
        for (tx_id, idx) in utxos {
            data.extend_from_slice(tx_id);
            data.extend_from_slice(&idx.to_be_bytes());
        }
        data.extend_from_slice(&DATA[utxo_end..]);
        data
    }

    /// The UTXO an operation consumes names the NFT or mint authority being
    /// spent. Two operations that differ only in it must not review the same.
    #[test]
    fn operation_shows_every_consumed_utxo() {
        let a = [0x11; 32];
        let b = [0x22; 32];

        let one = with_utxos(&[(a, 5)]);
        let other_tx = with_utxos(&[(b, 5)]);
        let other_idx = with_utxos(&[(a, 6)]);
        let two = with_utxos(&[(a, 5), (b, 0)]);

        let one = screens(&TransferableOp::from_bytes(&one).unwrap().1);
        let other_tx = screens(&TransferableOp::from_bytes(&other_tx).unwrap().1);
        let other_idx = screens(&TransferableOp::from_bytes(&other_idx).unwrap().1);
        let two = screens(&TransferableOp::from_bytes(&two).unwrap().1);

        // op type, asset, then the UTXO, ahead of the operation's own fields
        assert_eq!(one[0], r#""Op. Type:": "NFTTransferOperation""#);
        assert!(one[1].starts_with(r#""Asset": "#));
        assert!(one[2].starts_with(r#""UTXO": "#) && one[2].ends_with(r#":5""#));
        assert_eq!(one[3], r#""GroupID: ": "12345""#);

        assert_ne!(one, other_tx);
        assert_ne!(one, other_idx);

        // every UTXO gets its own screen, in order
        assert_eq!(two.len(), one.len() + 1);
        assert_eq!(two[2], one[2]);
        assert!(two[3].starts_with(r#""UTXO": "#) && two[3].ends_with(r#":0""#));
        assert_eq!(two[4..], one[3..]);
    }

    /// More UTXOs than a review can count is refused, not cut short.
    #[test]
    fn operation_with_too_many_utxos_is_refused() {
        let utxos = vec![([0x33; 32], 0u32); 256];
        let data = with_utxos(&utxos);
        let op = TransferableOp::from_bytes(&data).unwrap().1;
        assert!(op.num_items().is_err());
    }
}
