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
use nom::{bytes::complete::take, number::complete::be_u32, sequence::tuple};
use zemu_sys::ViewError;

use crate::handlers::handle_ui_message;
use crate::parser::{
    DisplayableItem, FromBytes, ParserError, SECPOutputOwners, ADDRESS_LEN, MAX_ADDRESSES,
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct PchainOwner<'b> {
    pub threshold: u32,
    pub addresses: &'b [[u8; ADDRESS_LEN]],
}

impl<'b> FromBytes<'b> for PchainOwner<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        let (rem, (threshold, addr_len)) = tuple((be_u32, be_u32))(input)?;

        if addr_len > MAX_ADDRESSES {
            return Err(ParserError::TooManyAddresses.into());
        }
        let addresses_len = (addr_len as usize)
            .checked_mul(ADDRESS_LEN)
            .ok_or(ParserError::ValueOutOfRange)?;
        let (rem, addresses) = take(addresses_len)(rem)?;
        // Check for invariants
        let addresses =
            bytemuck::try_cast_slice(addresses).map_err(|_| ParserError::InvalidAddressLength)?;

        if threshold as usize > addresses.len() {
            return Err(ParserError::InvalidThreshold.into());
        }

        // avalanchego's OutputOwners.Verify rejects a zero threshold over a
        // non-empty address set. An empty owner (threshold 0, no addresses)
        // is valid and in use: avalanche-cli leaves an L1 validator's
        // deactivation owner that way, and RegisterL1Validator owners come
        // inside a warp message the user cannot change. It needs no
        // signature, so it is rendered explicitly instead of being rejected.
        if threshold == 0 && !addresses.is_empty() {
            return Err(ParserError::InvalidThreshold.into());
        }

        //good ptr and no uninit reads
        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).threshold).write(threshold);
            addr_of_mut!((*out).addresses).write(addresses);
        }

        Ok(rem)
    }
}

impl<'b> PchainOwner<'b> {
    /// The same owner as an output-owners set. A P-Chain owner is a
    /// secp256k1fx OutputOwners without the locktime, so it is rendered by the
    /// same code as every other owner set rather than by a copy of it.
    pub fn as_output_owners(&self) -> SECPOutputOwners<'b> {
        SECPOutputOwners {
            locktime: 0,
            threshold: self.threshold,
            addresses: self.addresses,
        }
    }

    /// An owner with no addresses still gets one screen, saying that anyone
    /// can act in its place.
    pub fn num_items(&self) -> Result<u8, ViewError> {
        Ok(self.as_output_owners().num_items()?.max(1))
    }

    /// Render one of this owner's screens, encoding addresses under `hrp`.
    ///
    /// A transaction can carry several owners with different roles (who gets
    /// a validator's remaining balance, who may disable it), so the address
    /// screens are titled `label`; the owners renderer adds the Threshold
    /// screen when there are several addresses. An empty owner renders a
    /// single `label` screen showing `empty`.
    #[allow(clippy::too_many_arguments)]
    pub fn render_item_with_label(
        &self,
        hrp: &str,
        label: &[u8],
        empty: &[u8],
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        if self.addresses.is_empty() {
            if item_n != 0 {
                return Err(ViewError::NoData);
            }
            title[..label.len()].copy_from_slice(label);
            return handle_ui_message(empty, message, page);
        }

        self.as_output_owners()
            .render_item_with_label(hrp, label, item_n, title, message, page)
    }
}
