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
use core::ops::Deref;

use crate::handlers::handle_ui_message;
use crate::parser::{
    asset_id::ASSET_ID_CB58_MAX_LEN, nano_avax_to_fp_str, timestamp_to_str_date, u64_to_str,
    Address, AssetId, DisplayableItem, FromBytes, ObjectList, ParserError, U64_FORMATTED_SIZE,
};
use crate::sys::ViewError;
use arrayvec::ArrayVec;
use core::{mem::MaybeUninit, ptr::addr_of_mut};

mod nft_mint_output;
mod nft_transfer_output;
mod secp_mint_output;
mod secp_output_owners;
mod secp_transfer_output;
pub use nft_mint_output::NFTMintOutput;
pub use nft_transfer_output::NFTTransferOutput;
pub use secp_mint_output::SECPMintOutput;
pub use secp_output_owners::SECPOutputOwners;
pub use secp_transfer_output::SECPTransferOutput;

/// Refuse at parse time a non-zero locktime the date formatter cannot show
/// (past the end of its year table, 2369), so that its screen always renders.
pub(crate) fn check_locktime(locktime: u64) -> Result<(), ParserError> {
    if locktime != 0 {
        crate::parser::timestamp_to_date(locktime).map_err(|_| ParserError::InvalidTimestamp)?;
    }
    Ok(())
}

/// Render a locktime screen titled `label`, with the locktime as a UTC date.
/// The locktime must have passed check_locktime.
pub(crate) fn render_locktime(
    label: &[u8],
    locktime: u64,
    title: &mut [u8],
    message: &mut [u8],
    page: u8,
) -> Result<u8, ViewError> {
    title[..label.len()].copy_from_slice(label);

    let date = crate::parser::timestamp_to_str_date(locktime).map_err(|_| ViewError::Unknown)?;
    crate::handlers::handle_ui_message(date.as_slice(), message, page)
}

/// Implemented by the chain-specific wrappers around an Output (AvmOutput,
/// PvmOutput, EOutput), for what the wrapper adds to it.
pub trait OutputLock {
    /// The locktime of the P-chain stakeable lock (stakeable.LockOut) around
    /// the output, if there is one.
    fn stakeable_locktime(&self) -> Option<u64> {
        None
    }
}

/// Sum the amounts of the outputs in `asset`, or of all of them when `asset`
/// is None (a network whose AVAX asset id is not known).
///
/// The fee is paid in AVAX, so it must only count AVAX: summing across
/// assets let one asset's inputs cover another's outputs and made the fee
/// shown meaningless.
pub fn sum_amounts_in<'b, O>(
    outputs: &ObjectList<'b, TransferableOutput<'b, O>>,
    asset: Option<&[u8; 32]>,
) -> Result<u64, ParserError>
where
    O: FromBytes<'b> + DisplayableItem + Deref<Target = Output<'b>> + OutputLock + 'b,
{
    outputs
        .iter()
        .filter(|output| asset.is_none() || asset == Some(output.asset_id().id()))
        .map(|output| output.amount().ok_or(ParserError::UnexpectedError))
        .try_fold(0u64, |acc, x| {
            acc.checked_add(x?).ok_or(ParserError::OperationOverflows)
        })
}

/// Whether an owner set needs a Threshold screen: with a single address the
/// only valid threshold is 1, so the screen would say nothing.
pub(crate) fn shows_threshold(num_addresses: usize) -> bool {
    num_addresses > 1
}

/// Render the "Threshold" screen of an owner set as "<threshold> of <n>".
///
/// Without it a 1-of-2 output looks exactly like a 2-of-2 one, so any of the
/// listed addresses, one of which may not be the user's, can spend it alone.
pub(crate) fn render_threshold(
    threshold: u32,
    num_addresses: usize,
    title: &mut [u8],
    message: &mut [u8],
    page: u8,
) -> Result<u8, ViewError> {
    use crate::parser::{u32_to_str, U32_FORMATTED_SIZE};
    use bolos::{pic_str, PIC};

    let label = pic_str!(b"Threshold");
    title[..label.len()].copy_from_slice(label);

    let of = pic_str!(b" of "!);
    let mut buffer = [0; 2 * U32_FORMATTED_SIZE + 4];
    let mut num = [0; U32_FORMATTED_SIZE];

    let t = u32_to_str(threshold, &mut num[..]).map_err(|_| ViewError::Unknown)?;
    let mut len = t.len();
    buffer[..len].copy_from_slice(t);
    buffer[len..len + of.len()].copy_from_slice(&of[..]);
    len += of.len();

    let n = u32_to_str(num_addresses as u32, &mut num[..]).map_err(|_| ViewError::Unknown)?;
    buffer[len..len + n.len()].copy_from_slice(n);
    len += n.len();

    crate::handlers::handle_ui_message(&buffer[..len], message, page)
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct TransferableOutput<'b, O>
where
    O: FromBytes<'b> + DisplayableItem + Deref<Target = Output<'b>> + OutputLock + 'b,
{
    asset_id: AssetId<'b>,
    pub output: O,
}

impl<'b, O> Deref for TransferableOutput<'b, O>
where
    O: FromBytes<'b> + DisplayableItem + Deref<Target = Output<'b>> + OutputLock + 'b,
{
    type Target = O::Target;

    fn deref(&self) -> &Self::Target {
        &self.output
    }
}

impl<'b, O> TransferableOutput<'b, O>
where
    O: FromBytes<'b> + DisplayableItem + Deref<Target = Output<'b>> + OutputLock + 'b,
{
    pub fn amount(&self) -> Option<u64> {
        (*self.output).amount()
    }

    pub fn asset_id(&self) -> &AssetId<'b> {
        &self.asset_id
    }

    pub fn output(&self) -> &Output<'b> {
        &self.output
    }

    pub fn num_addresses(&self) -> usize {
        self.output().num_addresses()
    }

    /// Render one counted item of this output, encoding addresses for `hrp`.
    ///
    /// `avax_asset` is the AVAX asset id of the transaction's network, None
    /// where it is not known. Only an output of that asset is labelled AVAX;
    /// any other shows its amount in raw units, since the device does not
    /// know the asset's denomination, and its asset id in CB58. The asset used
    /// to be ignored, so swapping it gave exactly the same screens.
    ///
    /// Items of an inner secp transfer output (addresses, threshold,
    /// locktime) go through its hrp-aware renderer, then the stakeable-lock
    /// line of a locked P-chain output.
    pub fn render_item_with_hrp(
        &self,
        hrp: &str,
        avax_asset: Option<&[u8; 32]>,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::{pic_str, PIC};

        let Some(secp) = self.output().secp_transfer() else {
            return self.output.render_item(item_n, title, message, page);
        };
        let inner_items = secp.num_items()?;
        let mut text = ArrayVec::<u8, 128>::new();

        match item_n {
            0 => {
                let label = pic_str!(b"Amount");
                title[..label.len()].copy_from_slice(label);

                self.write_amount(secp.amount, avax_asset, true, &mut text)?;
                push(&mut text, pic_str!(b" to "!))?;
                handle_ui_message(&text, message, page)
            }
            x if x < inner_items => secp.render_item_with_hrp(hrp, x, title, message, page),
            x if x == inner_items => {
                let locktime = self.output.stakeable_locktime().ok_or(ViewError::NoData)?;

                // legacy app displays:
                // 'Funds locked', body: '0.5 AVAX until 2021-05-31 21:28:00 UTC'
                let label = pic_str!(b"Funds locked");
                title[..label.len()].copy_from_slice(label);

                self.write_amount(secp.amount, avax_asset, false, &mut text)?;
                push(&mut text, pic_str!(b" until "!))?;
                let date = timestamp_to_str_date(locktime).map_err(|_| ViewError::Unknown)?;
                push(&mut text, date.as_slice())?;
                handle_ui_message(&text, message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }

    /// "<amount> AVAX" for AVAX, "<raw amount> units" otherwise, followed by
    /// " of asset <CB58 id>" if `with_asset`.
    fn write_amount(
        &self,
        amount: u64,
        avax_asset: Option<&[u8; 32]>,
        with_asset: bool,
        text: &mut ArrayVec<u8, 128>,
    ) -> Result<(), ViewError> {
        use bolos::{pic_str, PIC};

        let mut num = [0; U64_FORMATTED_SIZE + 2];

        if avax_asset == Some(self.asset_id.id()) {
            let n = nano_avax_to_fp_str(amount, &mut num[..]).map_err(|_| ViewError::Unknown)?;
            push(text, n)?;
            return push(text, pic_str!(b" AVAX"!));
        }

        let n = u64_to_str(amount, &mut num[..]).map_err(|_| ViewError::Unknown)?;
        push(text, n)?;
        push(text, pic_str!(b" units"!))?;

        if with_asset {
            push(text, pic_str!(b" of asset "!))?;
            let mut id = [0; ASSET_ID_CB58_MAX_LEN];
            let len = self.asset_id.cb58_into(&mut id)?;
            push(text, &id[..len])?;
        }
        Ok(())
    }

    /// Whether this output may be left off the review as change to
    /// `change_address`, on a network whose AVAX asset id is `avax_asset`.
    ///
    /// Only an output the user fully and immediately controls may go
    /// unreviewed: a plain secp transfer output (not wrapped in a
    /// stakeable lock), with locktime 0, threshold 1 and `change_address` as
    /// its only address, of the network's AVAX asset. Any of those being
    /// different is something the user has to see: funds locked for years,
    /// shared with another key, or in another asset.
    pub fn is_hideable_change(
        &self,
        change_address: &[u8],
        avax_asset: Option<&[u8; 32]>,
    ) -> bool {
        let Some(secp) = self.output().secp_transfer() else {
            return false;
        };

        self.output.stakeable_locktime().is_none()
            && secp.locktime == 0
            && secp.threshold == 1
            && secp.addresses.len() == 1
            && secp.addresses[0][..] == *change_address
            && avax_asset == Some(self.asset_id.id())
    }

}

impl<'b, O> FromBytes<'b> for TransferableOutput<'b, O>
where
    O: FromBytes<'b> + DisplayableItem + Deref<Target = Output<'b>> + OutputLock + 'b,
{
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("TransferableOutput::from_bytes_into\x00");

        let output = out.as_mut_ptr();
        //valid pointer
        let asset = unsafe { &mut *addr_of_mut!((*output).asset_id).cast() };
        let rem = AssetId::from_bytes_into(input, asset)?;

        //valid pointer
        let data = unsafe { &mut *addr_of_mut!((*output).output).cast() };
        let rem = O::from_bytes_into(rem, data)?;

        Ok(rem)
    }
}

impl<'b, O> DisplayableItem for TransferableOutput<'b, O>
where
    O: FromBytes<'b> + DisplayableItem + Deref<Target = Output<'b>> + OutputLock + 'b,
{
    fn num_items(&self) -> Result<u8, ViewError> {
        // the asset_id is not part of the summary we need from objects of this type,
        // but could give to higher level objects information to display such information.
        self.output.num_items()
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        self.output.render_item(item_n as _, title, message, page)
    }
}

fn push(text: &mut ArrayVec<u8, 128>, bytes: &[u8]) -> Result<(), ViewError> {
    text.try_extend_from_slice(bytes)
        .map_err(|_| ViewError::Unknown)
}

// Important: do not change the repr attribute,
// as this type is use as the tag field
// for the Output enum which has the same representation
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
#[repr(u8)]
pub enum OutputType {
    SECPTransfer,
    SECPMint,
    NFTTransfer,
    NFTMint,
    SECPOwners,
}

#[repr(C)]
struct SECPTransferVariant<'b>(OutputType, SECPTransferOutput<'b>);

#[repr(C)]
struct SECPMintVariant<'b>(OutputType, SECPMintOutput<'b>);

#[repr(C)]
struct NFTTransferVariant<'b>(OutputType, NFTTransferOutput<'b>);

#[repr(C)]
struct NFTMintVariant<'b>(OutputType, NFTMintOutput<'b>);

#[repr(C)]
struct SECPOwnersVariant<'b>(OutputType, SECPOutputOwners<'b>);

#[derive(Clone, Copy, PartialEq, Eq)]
// DO not change the representation
// as it would cause unalignment issues
// with the OutputType tag
#[repr(u8)]
#[cfg_attr(test, derive(Debug))]
pub enum Output<'b> {
    SECPTransfer(SECPTransferOutput<'b>),
    SECPMint(SECPMintOutput<'b>),
    NFTTransfer(NFTTransferOutput<'b>),
    NFTMint(NFTMintOutput<'b>),
    SECPOwners(SECPOutputOwners<'b>),
}

impl<'b> Output<'b> {
    pub fn num_addresses(&self) -> usize {
        match self {
            Self::SECPTransfer(t) => t.num_addresses(),
            Self::SECPMint(m) => m.num_addresses(),
            Self::NFTTransfer(t) => t.num_addresses(),
            Self::NFTMint(m) => m.num_addresses(),
            Self::SECPOwners(o) => o.num_addresses(),
        }
    }

    pub fn get_address(&'b self, idx: usize) -> Option<Address<'b>> {
        match self {
            Self::SECPTransfer(t) => t.get_address_at(idx),
            Self::SECPMint(m) => m.get_address_at(idx),
            Self::NFTTransfer(t) => t.get_address_at(idx),
            Self::NFTMint(m) => m.get_address_at(idx),
            Self::SECPOwners(o) => o.get_address_at(idx),
        }
    }

    pub fn secp_transfer(&self) -> Option<&SECPTransferOutput<'_>> {
        if let Self::SECPTransfer(ref secp) = self {
            Some(secp)
        } else {
            None
        }
    }
    pub fn amount(&self) -> Option<u64> {
        match self {
            Self::SECPTransfer(secp) => Some(secp.amount),
            _ => None,
        }
    }

    #[inline(never)]
    pub fn from_bytes(
        input: &'b [u8],
        variant: OutputType,
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("Output::from_bytes\x00");

        let rem = match variant {
            OutputType::SECPTransfer => {
                let out = out.as_mut_ptr() as *mut SECPTransferVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = SECPTransferOutput::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(OutputType::SECPTransfer);
                }

                rem
            }
            OutputType::SECPMint => {
                let out = out.as_mut_ptr() as *mut SECPMintVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = SECPMintOutput::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(OutputType::SECPMint);
                }

                rem
            }
            OutputType::NFTTransfer => {
                let out = out.as_mut_ptr() as *mut NFTTransferVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = NFTTransferOutput::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(OutputType::NFTTransfer);
                }
                rem
            }
            OutputType::NFTMint => {
                let out = out.as_mut_ptr() as *mut NFTMintVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = NFTMintOutput::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(OutputType::NFTMint);
                }
                rem
            }
            OutputType::SECPOwners => {
                let out = out.as_mut_ptr() as *mut SECPOwnersVariant;
                //valid pointer
                let data = unsafe { &mut *addr_of_mut!((*out).1).cast() };

                let rem = SECPOutputOwners::from_bytes_into(input, data)?;

                //pointer is valid
                unsafe {
                    addr_of_mut!((*out).0).write(OutputType::SECPOwners);
                }

                rem
            }
        };
        Ok(rem)
    }
}

impl DisplayableItem for Output<'_> {
    fn num_items(&self) -> Result<u8, ViewError> {
        match self {
            Self::SECPTransfer(t) => t.num_items(),
            Self::SECPMint(m) => m.num_items(),
            Self::NFTTransfer(t) => t.num_items(),
            Self::NFTMint(m) => m.num_items(),
            Self::SECPOwners(o) => o.num_items(),
        }
    }

    #[inline(never)]
    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        match self {
            Self::SECPTransfer(t) => t.render_item(item_n, title, message, page),
            Self::SECPMint(m) => m.render_item(item_n, title, message, page),
            Self::NFTTransfer(t) => t.render_item(item_n, title, message, page),
            Self::NFTMint(m) => m.render_item(item_n, title, message, page),
            Self::SECPOwners(o) => o.render_item(item_n, title, message, page),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{AvmOutput, PvmOutput};

    const DATA: &[u8] = &[
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 1, 0, 0, 0, 1, 22, 54,
        119, 75, 103, 131, 141, 236, 22, 225, 106, 182, 207, 172, 178, 27, 136, 195, 168, 97,
    ];

    const LOCKED_OUTPUT: &[u8] = &[
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x0, 0x0, 0x0, 0x8, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x01, 0xd1, 0xa9, 0x4a, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x3c, 0xb7, 0xd3, 0x84, 0x2e,
        0x8c, 0xee, 0x6a, 0x0e, 0xbd, 0x09, 0xf1, 0xfe, 0x88, 0x4f, 0x68, 0x61, 0xe1, 0xb2, 0x9c,
    ];

    #[test]
    fn parse_transferable_output_pvm_output() {
        let res = TransferableOutput::<PvmOutput>::from_bytes(DATA);
        // should faild as output for pvm only support secp_transfer and owners
        assert!(res.is_err());
    }

    #[test]
    fn parse_locked_output() {
        let output = TransferableOutput::<PvmOutput>::from_bytes(LOCKED_OUTPUT)
            .unwrap()
            .1;
        assert_eq!(output.output.locktime.unwrap(), 8);
    }

    #[test]
    fn mint_and_nft_outputs_reject_threshold_zero() {
        use std::prelude::v1::*;

        // owners part: locktime, threshold, addresses
        fn owners(threshold: u32, addrs: usize) -> Vec<u8> {
            let mut v = 0u64.to_be_bytes().to_vec();
            v.extend(threshold.to_be_bytes());
            v.extend((addrs as u32).to_be_bytes());
            v.extend(std::vec![0x63u8; 20 * addrs]);
            v
        }

        for (threshold, addrs) in [(0, 0), (0, 1), (1, 1)] {
            let mut secp_mint = SECPMintOutput::TYPE_ID.to_be_bytes().to_vec();
            secp_mint.extend(owners(threshold, addrs));

            let mut nft_mint = NFTMintOutput::TYPE_ID.to_be_bytes().to_vec();
            nft_mint.extend(7u32.to_be_bytes()); // group id
            nft_mint.extend(owners(threshold, addrs));

            let mut nft_transfer = NFTTransferOutput::TYPE_ID.to_be_bytes().to_vec();
            nft_transfer.extend(7u32.to_be_bytes()); // group id
            nft_transfer.extend(2u32.to_be_bytes()); // payload
            nft_transfer.extend(b"hi");
            nft_transfer.extend(owners(threshold, addrs));

            // threshold 0 with no addresses is anyone-can-spend (or mint),
            // with addresses it is not valid on-chain
            let valid = threshold != 0;
            assert_eq!(SECPMintOutput::from_bytes(&secp_mint).is_ok(), valid);
            assert_eq!(NFTMintOutput::from_bytes(&nft_mint).is_ok(), valid);
            assert_eq!(NFTTransferOutput::from_bytes(&nft_transfer).is_ok(), valid);
        }
    }

    #[test]
    fn nft_mint_and_owner_locktimes_are_dates() {
        use crate::parser::tx_builder::{render_all, RECIPIENT};
        use std::prelude::v1::*;

        // 2100-01-01 00:00:00 UTC
        const YEAR_2100: u64 = 4_102_444_800;
        const DATE: &str = "2100-01-01 00:00:00 UTC";

        fn owners(locktime: u64) -> Vec<u8> {
            let mut v = locktime.to_be_bytes().to_vec();
            v.extend(1u32.to_be_bytes());
            v.extend(1u32.to_be_bytes());
            v.extend(RECIPIENT);
            v
        }
        let with_type = |type_id: u32, group: Option<u32>, payload: bool, locktime: u64| {
            let mut v = type_id.to_be_bytes().to_vec();
            if let Some(g) = group {
                v.extend(g.to_be_bytes());
            }
            if payload {
                v.extend(2u32.to_be_bytes());
                v.extend(b"hi");
            }
            v.extend(owners(locktime));
            v
        };

        // An NFT transfer output's locktime was never shown at all
        let nft = with_type(NFTTransferOutput::TYPE_ID, Some(7), true, YEAR_2100);
        let screens = render_all(&NFTTransferOutput::from_bytes(&nft).unwrap().1);
        assert_eq!(screens.last().unwrap(), &format!("Locked until: {}", DATE));

        // mint outputs and owners showed it as a raw unix time
        let mint = with_type(SECPMintOutput::TYPE_ID, None, false, YEAR_2100);
        let screens = render_all(&SECPMintOutput::from_bytes(&mint).unwrap().1);
        assert!(screens.contains(&format!("Locktime: {}", DATE)), "{:#?}", screens);

        let nft_mint = with_type(NFTMintOutput::TYPE_ID, Some(7), false, YEAR_2100);
        let screens = render_all(&NFTMintOutput::from_bytes(&nft_mint).unwrap().1);
        assert!(screens.contains(&format!("Locktime: {}", DATE)), "{:#?}", screens);

        let owner = with_type(SECPOutputOwners::TYPE_ID, None, false, YEAR_2100);
        let screens = render_all(&SECPOutputOwners::from_bytes(&owner).unwrap().1);
        assert!(screens.contains(&format!("Locktime: {}", DATE)), "{:#?}", screens);

        // and a locktime the date formatter cannot show is refused by all four
        let nft = with_type(NFTTransferOutput::TYPE_ID, Some(7), true, u64::MAX);
        let mint = with_type(SECPMintOutput::TYPE_ID, None, false, u64::MAX);
        let nft_mint = with_type(NFTMintOutput::TYPE_ID, Some(7), false, u64::MAX);
        let owner = with_type(SECPOutputOwners::TYPE_ID, None, false, u64::MAX);
        for err in [
            NFTTransferOutput::from_bytes(&nft).map(|_| ()),
            SECPMintOutput::from_bytes(&mint).map(|_| ()),
            NFTMintOutput::from_bytes(&nft_mint).map(|_| ()),
            SECPOutputOwners::from_bytes(&owner).map(|_| ()),
        ] {
            assert_eq!(err.unwrap_err(), ParserError::InvalidTimestamp.into());
        }
    }

    #[test]
    fn parse_transferable_output_avm_output() {
        let t = TransferableOutput::<AvmOutput>::from_bytes(DATA).unwrap().1;
        assert!(matches!(t.output.0, Output::NFTMint(..)));
    }
}
