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
        u64_to_str, Address, DisplayableItem, FromBytes, ParserError, ADDRESS_LEN,
        MAX_ADDRESSES, MAX_ADDRESS_ENCODED_LEN, U64_FORMATTED_SIZE
    },
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct SECPOutputOwners<'b> {
    pub locktime: u64,
    pub threshold: u32,
    pub addresses: &'b [[u8; ADDRESS_LEN]],
}

impl<'b> SECPOutputOwners<'b> {
    pub const TYPE_ID: u32 = 0x0000000b;

    pub fn get_address_at(&'b self, idx: usize) -> Option<Address<'b>> {
        let data = self.addresses.get(idx)?;
        let mut addr = MaybeUninit::uninit();
        Address::from_bytes_into(data, &mut addr)
            .map_err(|_| ViewError::Unknown)
            .ok()?;
        Some(unsafe { addr.assume_init() })
    }

    pub fn num_addresses(&self) -> usize {
        self.addresses.len()
    }

    pub fn render_address_with_hrp(
        &self,
        hrp: &str,
        idx: usize,
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        if let Some(address) = self.get_address_at(idx) {
            let mut encoded = [0; MAX_ADDRESS_ENCODED_LEN];

            let len = address
                .encode_into(hrp, &mut encoded[..])
                .map_err(|_| ViewError::Unknown)?;

            handle_ui_message(&encoded[..len], message, page)
        } else {
            Err(ViewError::NoData)
        }
    }
}
impl<'b> FromBytes<'b> for SECPOutputOwners<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("SECPOutputOwners::from_bytes_into\x00");
        // get owners type and check
        let (rem, _) = tag(Self::TYPE_ID.to_be_bytes())(input)?;

        let (rem, (locktime, threshold, addr_len)) = tuple((be_u64, be_u32, be_u32))(rem)?;

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

        // threshold 0 is rejected outright. With no addresses avalanchego
        // accepts it and anyone can claim what these owners control (rewards,
        // a subnet) with no signature, while the review shows no owner at
        // all; with addresses it is not a valid owner set at all.
        if threshold == 0 || threshold as usize > addresses.len() {
            return Err(ParserError::InvalidThreshold.into());
        }

        //good ptr and no uninit reads
        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).locktime).write(locktime);
            addr_of_mut!((*out).threshold).write(threshold);
            addr_of_mut!((*out).addresses).write(addresses);
        }

        Ok(rem)
    }
}

impl SECPOutputOwners<'_> {
    /// Render one counted item, encoding addresses under `hrp`.
    ///
    /// num_items counts a Locktime screen ahead of the addresses whenever
    /// locktime is non-zero, so any caller that renders these items has to
    /// apply the same offset. Keeping that arithmetic here means a caller
    /// cannot get it wrong.
    pub fn render_item_with_hrp(
        &self,
        hrp: &str,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::{pic_str, PIC};

        let mut buffer = [0; U64_FORMATTED_SIZE + 2];

        let addr_items = self.addresses.len() as u8;
        let mut item_index = item_n;

        if self.locktime > 0 {
            if item_index == 0 {
                let title_content = pic_str!(b"Locktime");
                title[..title_content.len()].copy_from_slice(title_content);
                let buffer =
                    u64_to_str(self.locktime, &mut buffer).map_err(|_| ViewError::Unknown)?;
                return handle_ui_message(buffer, message, page);
            }
            item_index -= 1;
        }

        if item_index < addr_items {
            let label = pic_str!(b"Owner address");
            title[..label.len()].copy_from_slice(label);
            self.render_address_with_hrp(hrp, item_index as usize, message, page)
        } else {
            Err(ViewError::NoData)
        }
    }
}

impl DisplayableItem for SECPOutputOwners<'_> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // show an item for each address in the list
        let items = self.addresses.len() as u8;
        // show locktime only if it is higher than zero,
        // that is why we sum up this boolean
        checked_add!(ViewError::Unknown, items, (self.locktime > 0) as u8)
    }

    #[inline(never)]
    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        // No network context here; callers that have one should use
        // render_item_with_hrp.
        self.render_item_with_hrp("", item_n, title, message, page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &[u8] = &[
        0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 1, 22, 54, 119, 75, 103, 131,
        141, 236, 22, 225, 106, 182, 207, 172, 178, 27, 136, 195, 168, 97,
    ];

    #[test]
    fn parse_output_owners() {
        let (_, owner) = SECPOutputOwners::from_bytes(DATA).unwrap();
        assert_eq!(owner.locktime, 12);
        assert_eq!(owner.threshold, 1);
        assert_eq!(owner.addresses.len(), 1);
    }

    #[test]
    fn owners_with_threshold_zero_are_rejected() {
        use crate::parser::tx_builder::{owners, RECIPIENT};

        // No addresses means anyone can claim what they own (rewards, a
        // subnet) with no signature; with addresses it is not valid at all.
        for raw in [owners(0, 0, &[]), owners(0, 0, &[RECIPIENT])] {
            let err = SECPOutputOwners::from_bytes(&raw).unwrap_err();
            assert_eq!(err, ParserError::InvalidThreshold.into());
        }

        assert!(SECPOutputOwners::from_bytes(&owners(0, 1, &[RECIPIENT])).is_ok());
    }

    #[test]
    fn empty_rewards_owner_rejects_the_transaction() {
        use crate::parser::tx_builder::*;
        use crate::parser::Transaction;

        // The rewards owner contributed no screen at all, so the review looked
        // the same as one paying rewards to the user.
        let ins = [input(1, &FUJI_AVAX, 100_000_000_000)];
        let stake = [out(2_000_000_000_000, CHANGE)];
        let tx = add_delegator(&[], &ins, &stake, owners(0, 0, &[]));
        assert_eq!(
            Transaction::new(&tx).unwrap_err(),
            ParserError::InvalidThreshold
        );
    }

    #[test]
    fn owners_locktime_item_is_renderable() {
        // This vector carries locktime 12, so num_items counts a Locktime
        // screen ahead of the single address. Every counted item has to
        // render: the caller in CreateSubnet used to pass this index straight
        // through as an address index, which skipped Locktime and ran the last
        // index off the end of the address list.
        let (_, owners) = SECPOutputOwners::from_bytes(DATA).unwrap();
        assert!(owners.locktime > 0);

        let items = owners.num_items().expect("Overflow?");
        assert_eq!(items as usize, owners.num_addresses() + 1);

        let mut title = [0u8; 64];
        let mut message = [0u8; 256];
        for i in 0..items {
            assert!(
                owners
                    .render_item_with_hrp("fuji", i, &mut title, &mut message, 0)
                    .is_ok(),
                "counted item {} did not render",
                i
            );
        }

        // First screen is the locktime, not an address.
        owners
            .render_item_with_hrp("fuji", 0, &mut title, &mut message, 0)
            .unwrap();
        assert!(title.starts_with(b"Locktime"));

        // One past the end is an error rather than a stale screen.
        assert!(owners
            .render_item_with_hrp("fuji", items, &mut title, &mut message, 0)
            .is_err());
    }
}
