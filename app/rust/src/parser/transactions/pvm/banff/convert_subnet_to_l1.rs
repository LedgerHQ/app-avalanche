/*******************************************************************************
*   (c) 2023 Zondax AG
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
use bolos::{hex_encode, PIC};
use core::{mem::MaybeUninit, ptr::addr_of_mut};
use nom::bytes::complete::{tag, take};
use nom::number::complete::be_u32;
use zemu_sys::ViewError;

use crate::parser::u64_to_str;
use crate::checked_add;
use crate::parser::chain_id::ChainId;
use crate::{
    constants::CHAIN_ID_LEN,
    handlers::handle_ui_message,
    parser::{
        l1_validator::L1Validator, nano_avax_to_fp_str, BaseTxFields, DisplayableItem, FromBytes,
        Header, ObjectList, ParserError, PvmOutput, SubnetAuth, SubnetId, PVM_CONVERT_SUBNET_L1,
        U64_FORMATTED_SIZE,
    },
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct ConvertSubnetToL1Tx<'b> {
    pub tx_header: Header<'b>,
    pub base_tx: BaseTxFields<'b, PvmOutput<'b>>,
    pub subnet_id: SubnetId<'b>,
    pub chain_id: ChainId<'b>,
    pub address: &'b [u8],
    pub address_len: u32,
    pub validators: ObjectList<'b, L1Validator<'b>>,
    pub subnet_auth: SubnetAuth<'b>,
}

// description, chain_id, manager address, subnet_id, fee
pub const BASE_FIELDS_LEN: u8 = 5;

/// Node id, weight, balance and BLS public key: the fixed screens of each
/// validator, ahead of its two owners.
const VALIDATOR_FIXED_ITEMS: u8 = 4;

/// Screens contributed by one validator. They used to be the node id alone
/// outside expert mode, but the balance is AVAX the user pays into the L1 and
/// it is left out of the fee, so hiding it hid where that AVAX went. The
/// owners decide who gets the balance back and who may disable the validator,
/// so they are shown too, as is the BLS public key the validator will sign
/// warp messages with.
fn validator_items(validator: &L1Validator) -> Result<u8, ViewError> {
    checked_add!(
        ViewError::Unknown,
        VALIDATOR_FIXED_ITEMS,
        validator.remaining_balance_owner.num_items()?,
        validator.deactivation_owner.num_items()?
    )
}

impl<'b> ConvertSubnetToL1Tx<'b> {

    pub fn disable_output_if(&mut self, address: &[u8]) {
        self.base_tx.disable_output_if(address);
    }
    /// Sums the balances of all L1 validators in the list.
    fn sum_validators_balances(&self) -> Result<u64, ParserError> {
        let mut total_balance = 0u64;

        for validator in self.validators.iter() {
            total_balance = total_balance
                .checked_add(validator.balance)
                .ok_or(ParserError::OperationOverflows)?;
        }

        Ok(total_balance)
    }

    // Info at https://github.com/ava-labs/avalanchejs/blob/master/src/utils/getBurnedAmountByTx.ts
    fn fee(&'b self) -> Result<u64, ParserError> {
        let sum_inputs = self.base_tx.sum_inputs_amount()?;

        let base_outputs = self.base_tx.sum_outputs_amount()?;

        let mut fee = sum_inputs
            .checked_sub(base_outputs)
            .ok_or(ParserError::OperationOverflows)?;

        fee = fee
            .checked_sub(self.sum_validators_balances()?)
            .ok_or(ParserError::OperationOverflows)?;

        Ok(fee)
    }

    /// Screens contributed by all validators together.
    fn validators_items(&self) -> Result<u8, ViewError> {
        let mut items = 0u8;
        for validator in self.validators.iter() {
            items = items
                .checked_add(validator_items(&validator)?)
                .ok_or(ViewError::Unknown)?;
        }
        Ok(items)
    }

    fn render_validator(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::{pic_str, PIC};

        // Find the validator this item belongs to. Validators contribute a
        // variable number of screens, as their owners can hold several
        // addresses.
        let mut item_n = item_n;
        let mut found = None;
        for validator in self.validators.iter() {
            let n = validator_items(&validator)?;
            if item_n < n {
                found = Some(validator);
                break;
            }
            item_n -= n;
        }
        // An item index past the last validator is a caller error, not a
        // reason to abort the app.
        let validator = found.ok_or(ViewError::NoData)?;

        let mut buffer = [0; U64_FORMATTED_SIZE + 2];
        let remaining_items = validator.remaining_balance_owner.num_items()?;
        let hrp = self.tx_header.hrp().map_err(|_| ViewError::Unknown)?;

        match item_n {
            0 => validator.node_id.render_item(0, title, message, page),
            1 => {
                let label = pic_str!(b"Weight");
                title[..label.len()].copy_from_slice(label);
                let buf =
                    u64_to_str(validator.weight, &mut buffer).map_err(|_| ViewError::Unknown)?;
                handle_ui_message(buf, message, page)
            }
            2 => {
                let label = pic_str!(b"Balance (AVAX)");
                title[..label.len()].copy_from_slice(label);
                let buf = nano_avax_to_fp_str(validator.balance, &mut buffer[..])
                    .map_err(|_| ViewError::Unknown)?;
                handle_ui_message(buf, message, page)
            }
            3 => validator.signer.render_signer(title, message, page),
            x if x - VALIDATOR_FIXED_ITEMS < remaining_items => {
                validator.remaining_balance_owner.render_item_with_label(
                    hrp,
                    pic_str!(b"Rem Addr"),
                    pic_str!(b"Anyone (no owner)"),
                    x - VALIDATOR_FIXED_ITEMS,
                    title,
                    message,
                    page,
                )
            }
            x => validator.deactivation_owner.render_item_with_label(
                hrp,
                pic_str!(b"Disabler"),
                pic_str!(b"Anyone"),
                x - VALIDATOR_FIXED_ITEMS - remaining_items,
                title,
                message,
                page,
            ),
        }
    }
}

impl<'b> FromBytes<'b> for ConvertSubnetToL1Tx<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("ConvertSubnetToL1Tx::from_bytes_into\x00");

        let (rem, _) = tag(PVM_CONVERT_SUBNET_L1.to_be_bytes())(input)?;

        let out = out.as_mut_ptr();

        // tx header
        let tx_header = unsafe { &mut *addr_of_mut!((*out).tx_header).cast() };
        let rem = Header::from_bytes_into(rem, tx_header)?;

        // base_tx
        let base_tx = unsafe { &mut *addr_of_mut!((*out).base_tx).cast() };
        let rem = BaseTxFields::<PvmOutput>::from_bytes_after(
            unsafe { tx_header.assume_init_ref() },
            rem,
            base_tx,
        )?;

        // subnet_id
        let subnet_id = unsafe { &mut *addr_of_mut!((*out).subnet_id).cast() };
        let rem = SubnetId::from_bytes_into(rem, subnet_id)?;
        let subnet_id_ref = unsafe { subnet_id.assume_init_ref() }; // Get a reference to the initialized value

        if subnet_id_ref.is_primary_network() {
            return Err(ParserError::UnexpectedField.into());
        }

        // chain_id
        let chain_id = unsafe { &mut *addr_of_mut!((*out).chain_id).cast() };
        let rem = ChainId::from_bytes_into(rem, chain_id)?;

        // address
        let (rem, address_len) = be_u32(rem)?;
        let (rem, address) = take(address_len as usize)(rem)?;

        // validators
        let validators = unsafe { &mut *addr_of_mut!((*out).validators).cast() };
        let rem = ObjectList::<L1Validator>::new_into(rem, validators)?;

        // subnetAuth
        let subnet_auth = unsafe { &mut *addr_of_mut!((*out).subnet_auth).cast() };
        let rem = SubnetAuth::from_bytes_into(rem, subnet_auth)?;

        unsafe {
            addr_of_mut!((*out).address).write(address);
            addr_of_mut!((*out).address_len).write(address_len);
        }

        Ok(rem)
    }
}

impl DisplayableItem for ConvertSubnetToL1Tx<'_> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // tx description, chain_id, address, fee, validators, base outputs.
        // The base outputs were previously left out of the count entirely, so
        // where the transaction's funds went was never on screen.
        checked_add!(
            ViewError::Unknown,
            BASE_FIELDS_LEN,
            self.validators_items()?,
            self.base_tx.base_outputs_num_items()?
        )
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        use bolos::pic_str;
        let mut buffer = [0; U64_FORMATTED_SIZE + 2];
        let prefix = pic_str!(b"0x"!);
        let validator_screens = self.validators_items()?;
        match item_n {
            0 => {
                let label = pic_str!(b"ConvertSubnetToL1");
                title[..label.len()].copy_from_slice(label);
                let content = pic_str!(b"Transaction");
                handle_ui_message(content, message, page)
            }
            1 => self.chain_id.render_item(0, title, message, page),
            2 => {
                // This is the address of the contract that will manage the L1,
                // not a validator. It was labelled "Validator", which named the
                // wrong role for the one address the user is authorising here.
                let label = pic_str!(b"Manager");
                title[..label.len()].copy_from_slice(label);

                // prefix
                let mut out = [0; CHAIN_ID_LEN * 2 + 2];
                let mut sz = prefix.len();
                out[..prefix.len()].copy_from_slice(&prefix[..]);

                sz += hex_encode(self.address, &mut out[prefix.len()..])
                    .map_err(|_| ViewError::Unknown)?;

                handle_ui_message(&out[..sz], message, page)
            }
            3 => self.subnet_id.render_item(0, title, message, page),
            4 => {
                let label = pic_str!(b"Fee(AVAX)");
                title[..label.len()].copy_from_slice(label);

                let fee = self.fee().map_err(|_| ViewError::Unknown)?;
                let fee_buff =
                    nano_avax_to_fp_str(fee, &mut buffer[..]).map_err(|_| ViewError::Unknown)?;

                handle_ui_message(fee_buff, message, page)
            }
            x @ BASE_FIELDS_LEN.. if x - BASE_FIELDS_LEN < validator_screens => {
                self.render_validator(x - BASE_FIELDS_LEN, title, message, page)
            }
            x @ BASE_FIELDS_LEN.. => {
                let output_n = x - BASE_FIELDS_LEN - validator_screens;
                let hrp = self.tx_header.hrp().map_err(|_| ViewError::Unknown)?;
                self.base_tx
                    .render_base_output_with_hrp(hrp, output_n, title, message, page)
            }
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

    include!("testvectors/convert_subnet_to_l1.rs");
    #[test]
    fn parse_convert_subnet() {
        let subnet_id = SubnetId::new(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38,
        ]);
        let manager_chain_id = ChainId::new(&[
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
            0x27, 0x28, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
        ]);

        let manager_address = &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xde, 0xad,
        ];

        let (_, tx) = ConvertSubnetToL1Tx::from_bytes(SIMPLE_CONVERT_SUBNET).unwrap();
        assert_eq!(tx.subnet_id, subnet_id);
        assert_eq!(tx.chain_id, manager_chain_id);
        assert_eq!(tx.address, manager_address);

        let (_, tx) = ConvertSubnetToL1Tx::from_bytes(COMPLEX_CONVERT_SUBNET).unwrap();
        assert_eq!(tx.subnet_id, subnet_id);
        assert_eq!(tx.chain_id, manager_chain_id);
        assert_eq!(tx.address, manager_address);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn ui_convert_subnet_to_l1() {
        for (i, data) in [SIMPLE_CONVERT_SUBNET, COMPLEX_CONVERT_SUBNET]
            .iter()
            .enumerate()
        {
            println!("-------------------- Convert Subnet to L1 TX #{i} ------------------------");
            let (_, tx) = ConvertSubnetToL1Tx::from_bytes(data).unwrap();

            let items = tx.num_items().expect("Overflow?");

            let mut pages = Vec::<Page<18, 1024>>::with_capacity(items as usize);
            for i in 0..items {
                let mut page = Page::default();

                tx.render_item(i as _, &mut page.title, &mut page.message, 0)
                    .unwrap();

                pages.push(page);
            }

            let reduced = pages.iter().map(ReducedPage::from).collect::<Vec<_>>();
            insta::assert_debug_snapshot!(reduced);
        }
    }

    /// Every (title, message) pair the review shows, first page only.
    fn screens(tx: &ConvertSubnetToL1Tx) -> Vec<(String, String)> {
        let items = tx.num_items().expect("Overflow?");
        (0..items)
            .map(|i| {
                let mut page = Page::<18, 1024>::default();
                tx.render_item(i, &mut page.title, &mut page.message, 0)
                    .unwrap_or_else(|e| panic!("item {} failed: {:?}", i, e));
                let reduced = ReducedPage::from(&page);
                let text = format!("{:?}", reduced);
                let (title, message) = text.split_once(": ").unwrap();
                (
                    title.trim_matches('"').into(),
                    message.trim_matches('"').into(),
                )
            })
            .collect()
    }

    fn bech32(hrp: &str, raw: &[u8; crate::parser::ADDRESS_LEN]) -> String {
        use crate::parser::{Address, MAX_ADDRESS_ENCODED_LEN};
        let (_, address) = Address::from_bytes(&raw[..]).unwrap();
        let mut encoded = [0; MAX_ADDRESS_ENCODED_LEN];
        let len = address.encode_into(hrp, &mut encoded[..]).unwrap();
        String::from_utf8(encoded[..len].to_vec()).unwrap()
    }

    /// Each validator's balance is AVAX the user pays into the L1 and is left
    /// out of the fee, and its owners decide who gets that balance back and
    /// who can disable the validator. All of it has to be on screen: a host
    /// could otherwise route a large balance to an owner it controls while
    /// the review showed only a node id and a small fee.
    #[test]
    fn convert_subnet_to_l1_shows_validator_balance_and_owners() {
        // Outside expert mode, which is what a normal review runs in; the
        // host otherwise reports expert mode on.
        crate::utils::set_expert_for_test(false);

        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/parser/testvectors/convert_subnet_to_l1_validators.json"
        );
        let data: Vec<u8> = serde_json::from_reader(std::fs::File::open(path).unwrap()).unwrap();

        for data in [&data[2..], COMPLEX_CONVERT_SUBNET] {
            let (_, tx) = ConvertSubnetToL1Tx::from_bytes(data).unwrap();
            let hrp = tx.tx_header.hrp().unwrap();
            let shown = screens(&tx);
            assert!(tx.validators.iter().count() > 0);

            for validator in tx.validators.iter() {
                let mut weight = [0; U64_FORMATTED_SIZE + 2];
                let weight = u64_to_str(validator.weight, &mut weight).unwrap();
                let weight = core::str::from_utf8(weight).unwrap();
                assert!(
                    shown.contains(&("Weight".into(), weight.into())),
                    "weight not shown: {:#?}",
                    shown
                );

                let mut balance = [0; U64_FORMATTED_SIZE + 2];
                let balance = nano_avax_to_fp_str(validator.balance, &mut balance[..]).unwrap();
                let balance = core::str::from_utf8(balance).unwrap();
                assert!(
                    shown.contains(&("Balance (AVAX)".into(), balance.into())),
                    "balance not shown: {:#?}",
                    shown
                );

                for raw in validator.remaining_balance_owner.addresses {
                    assert!(
                        shown.contains(&("Rem Addr".into(), bech32(hrp, raw))),
                        "remaining balance owner not shown: {:#?}",
                        shown
                    );
                }
                for raw in validator.deactivation_owner.addresses {
                    assert!(
                        shown.contains(&("Disabler".into(), bech32(hrp, raw))),
                        "deactivation owner not shown: {:#?}",
                        shown
                    );
                }
            }
        }
        crate::utils::set_expert_for_test(true);
    }

    /// Each validator's BLS public key is the key it will sign warp messages
    /// with on the new L1. It is fixed by this transaction, so it has to be
    /// on screen in every mode, after the balance and ahead of the owners.
    #[test]
    fn convert_subnet_to_l1_shows_validator_bls_key() {
        crate::utils::set_expert_for_test(false);

        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/parser/testvectors/convert_subnet_to_l1_validators.json"
        );
        let data: Vec<u8> = serde_json::from_reader(std::fs::File::open(path).unwrap()).unwrap();

        for data in [&data[2..], COMPLEX_CONVERT_SUBNET] {
            let (_, tx) = ConvertSubnetToL1Tx::from_bytes(data).unwrap();
            let shown = screens(&tx);

            for validator in tx.validators.iter() {
                let key = format!("0x{}", hex::encode(validator.signer.public_key()));
                let at = shown
                    .iter()
                    .position(|s| *s == ("Signer".into(), key.clone()))
                    .unwrap_or_else(|| panic!("BLS key {} not shown: {:#?}", key, shown));
                assert_eq!(shown[at - 1].0, "Balance (AVAX)", "{:#?}", shown);
            }

            // a different key is a different review
            let first = tx.validators.iter().next().unwrap();
            let key = first.signer.public_key();
            let at = data.windows(key.len()).position(|w| w == &key[..]).unwrap();
            let mut tampered = data.to_vec();
            tampered[at] ^= 0x01;
            let (_, other) = ConvertSubnetToL1Tx::from_bytes(&tampered).unwrap();
            assert_ne!(shown, screens(&other));
        }
        crate::utils::set_expert_for_test(true);
    }

    /// The validator vector with both owners replaced by `owners`, the bytes
    /// of the remaining-balance owner followed by the deactivation owner.
    fn with_owners(owners: &[u8]) -> Vec<u8> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/parser/testvectors/convert_subnet_to_l1_validators.json"
        );
        let data: Vec<u8> = serde_json::from_reader(std::fs::File::open(path).unwrap()).unwrap();
        let data = &data[2..];
        assert!(ConvertSubnetToL1Tx::from_bytes(data).is_ok());

        // Both owners are threshold 1 over one address, and only the subnet
        // auth (type id + one signature index) follows them.
        let auth_len = 4 + 4 + 4;
        let owner_len = 4 + 4 + crate::parser::ADDRESS_LEN;
        let owners_end = data.len() - auth_len;
        let owners_start = owners_end - 2 * owner_len;

        let mut tampered = Vec::from(&data[..owners_start]);
        tampered.extend_from_slice(owners);
        tampered.extend_from_slice(&data[owners_end..]);
        tampered
    }

    /// An owner with threshold 0 and no addresses is valid on chain (it is
    /// what avalanche-cli leaves as the deactivation owner) and needs no
    /// signature, so the review says so rather than showing nothing.
    #[test]
    fn convert_subnet_to_l1_shows_empty_validator_owners() {
        crate::utils::set_expert_for_test(false);

        let data = with_owners(&[0; 16]);
        let (_, tx) = ConvertSubnetToL1Tx::from_bytes(&data).unwrap();
        let shown = screens(&tx);

        assert!(
            shown.contains(&("Rem Addr".into(), "Anyone (no owner)".into())),
            "{:#?}",
            shown
        );
        assert!(
            shown.contains(&("Disabler".into(), "Anyone".into())),
            "{:#?}",
            shown
        );
        crate::utils::set_expert_for_test(true);
    }

    /// A multi-address owner shows its threshold, so a 1-of-2 refund owner
    /// cannot pass for a 2-of-2 one.
    #[test]
    fn convert_subnet_to_l1_shows_owner_threshold() {
        let mut owners = Vec::new();
        owners.extend_from_slice(&1u32.to_be_bytes());
        owners.extend_from_slice(&2u32.to_be_bytes());
        owners.extend_from_slice(&[0x11; crate::parser::ADDRESS_LEN]);
        owners.extend_from_slice(&[0x22; crate::parser::ADDRESS_LEN]);
        owners.extend_from_slice(&1u32.to_be_bytes());
        owners.extend_from_slice(&1u32.to_be_bytes());
        owners.extend_from_slice(&[0x33; crate::parser::ADDRESS_LEN]);

        let data = with_owners(&owners);
        let (_, tx) = ConvertSubnetToL1Tx::from_bytes(&data).unwrap();
        let shown = screens(&tx);
        let titles = shown.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>();

        let rem = titles.iter().position(|t| *t == "Rem Addr").unwrap();
        assert_eq!(
            &titles[rem..rem + 4],
            &["Rem Addr", "Rem Addr", "Threshold", "Disabler"],
            "{:#?}",
            shown
        );
        assert_eq!(shown[rem + 2].1, "1 of 2");
    }

    /// avalanchego rejects a zero threshold over a non-empty address set.
    #[test]
    fn convert_subnet_to_l1_rejects_zero_threshold_with_addresses() {
        let owner = |threshold: u32| {
            let mut o = threshold.to_be_bytes().to_vec();
            o.extend_from_slice(&1u32.to_be_bytes());
            o.extend_from_slice(&[0x11; crate::parser::ADDRESS_LEN]);
            o
        };

        let mut good = owner(1);
        good.extend(owner(1));
        assert!(ConvertSubnetToL1Tx::from_bytes(&with_owners(&good)).is_ok());

        let mut zero = owner(1);
        zero.extend(owner(0));
        assert!(ConvertSubnetToL1Tx::from_bytes(&with_owners(&zero)).is_err());
    }

    #[test]
    fn convert_subnet_to_l1_out_of_range_item_is_an_error() {
        let mut title = [0u8; 64];
        let mut message = [0u8; 256];

        for data in [SIMPLE_CONVERT_SUBNET, COMPLEX_CONVERT_SUBNET] {
            let (_, tx) = ConvertSubnetToL1Tx::from_bytes(data).unwrap();
            let items = tx.num_items().expect("Overflow?");

            // Every advertised item renders.
            for i in 0..items {
                assert!(
                    tx.render_item(i, &mut title, &mut message, 0).is_ok(),
                    "advertised item {} should render",
                    i
                );
            }

            // The first index past the end must report NoData. The validator
            // arm is open-ended, so nothing else bounds it, and it used to
            // unwrap().
            assert!(tx.render_item(items, &mut title, &mut message, 0).is_err());
            assert!(tx
                .render_item(u8::MAX, &mut title, &mut message, 0)
                .is_err());
        }
    }

    #[test]
    fn every_field_is_initialised() {
        for data in [SIMPLE_CONVERT_SUBNET, COMPLEX_CONVERT_SUBNET] {
            // garbage stands in for uninitialised memory
            let mut out = MaybeUninit::<ConvertSubnetToL1Tx>::uninit();
            unsafe {
                out.as_mut_ptr()
                    .cast::<u8>()
                    .write_bytes(0xFF, core::mem::size_of::<ConvertSubnetToL1Tx>());
            }
            ConvertSubnetToL1Tx::from_bytes_into(data, &mut out).unwrap();
            let tx = unsafe { out.assume_init() };

            assert_eq!(tx.address_len as usize, tx.address.len());
        }
    }
}
