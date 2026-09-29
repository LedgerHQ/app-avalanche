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
use nom::bytes::complete::{tag, take};
use nom::number::complete::{be_u16, be_u8};
use zemu_sys::ViewError;

use crate::checked_add;
use crate::parser::{intstr_to_fpstr_inplace, nano_avax_to_fp_str, u64_to_str, ChainId, Output};
use crate::{
    handlers::handle_ui_message,
    parser::{
        u8_to_str, AvmOutput, BaseTxFields, DisplayableItem, FromBytes, Header, InitialState,
        ObjectList, ParserError, AVM_CREATE_ASSET_TX, U64_FORMATTED_SIZE, U8_FORMATTED_SIZE
    },
};

const MAX_NAME_LEN: usize = 128;
const MAX_SYMBOL_LEN: usize = 4;
// avalanchego rejects a larger denomination (maxDenomination in the AVM's
// syntactic verifier), and bounding it bounds the supply screen's buffer.
const MAX_DENOMINATION: u8 = 32;
// description, name, symbol, denomination
const START_STATES: u8 = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct CreateAssetTx<'b> {
    pub tx_header: Header<'b>,
    pub base_tx: BaseTxFields<'b, AvmOutput<'b>>,
    pub name: &'b [u8],
    pub sym: &'b [u8],
    pub denomination: u8,
    pub initial_states: ObjectList<'b, InitialState<'b>>,
}

impl<'b> CreateAssetTx<'b> {
    pub fn disable_output_if(&mut self, address: &[u8]) {
        self.base_tx.disable_output_if(address);
    }

    fn fee(&'b self) -> Result<u64, ParserError> {
        let sum_inputs = self.base_tx.sum_inputs_amount()?;

        let base_outputs = self.base_tx.sum_outputs_amount()?;

        let fee = sum_inputs
            .checked_sub(base_outputs)
            .ok_or(ParserError::OperationOverflows)?;
        Ok(fee)
    }

    /// Screens contributed by the initial-state outputs. These say who holds
    /// the new asset's supply and who may mint more of it, and are covered by
    /// the signature like everything else.
    fn initial_states_items(&self) -> Result<u8, ViewError> {
        let mut items = 0u8;
        for state in self.initial_states.iter() {
            for output in state.outputs().iter() {
                items = items
                    .checked_add(output.num_items()?)
                    .ok_or(ViewError::Unknown)?;
            }
        }
        Ok(items)
    }

    fn render_initial_state(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        let mut item_n = item_n;
        let mut found = None;
        'states: for state in self.initial_states.iter() {
            for output in state.outputs().iter() {
                let n = output.num_items()?;
                if item_n < n {
                    found = Some(output);
                    break 'states;
                }
                item_n -= n;
            }
        }
        let output = found.ok_or(ViewError::NoData)?;
        let hrp = self.tx_header.hrp().map_err(|_| ViewError::Unknown)?;

        match &output.0 {
            // The supply is an amount of the asset being created, not of
            // AVAX, so its first screen is written here with the asset's own
            // denomination and symbol. The rest (the holders) is the regular
            // transfer-output rendering.
            Output::SECPTransfer(out) if item_n == 0 => {
                self.render_supply(out.amount, title, message, page)
            }
            Output::SECPTransfer(out) => {
                out.render_item_with_hrp(hrp, item_n, title, message, page)
            }
            Output::SECPMint(out) => out.render_item_with_hrp(hrp, item_n, title, message, page),
            Output::NFTMint(out) => out.render_item_with_hrp(hrp, item_n, title, message, page),
            Output::NFTTransfer(out) => out.render_item_with_hrp(hrp, item_n, title, message, page),
            // AvmOutput never parses owners on their own.
            Output::SECPOwners(_) => Err(ViewError::NoData),
        }
    }

    fn render_supply(
        &self,
        amount: u64,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        use bolos::{pic_str, PIC};

        let label = pic_str!(b"Supply");
        title[..label.len()].copy_from_slice(label);

        // integer digits, a decimal point, a leading zero, the fraction, then
        // " " + symbol + " to "
        let mut buffer =
            [0u8; U64_FORMATTED_SIZE + 2 + MAX_DENOMINATION as usize + MAX_SYMBOL_LEN + 6];
        let num_len = U64_FORMATTED_SIZE + 2 + MAX_DENOMINATION as usize;
        u64_to_str(amount, &mut buffer[..num_len]).map_err(|_| ViewError::Unknown)?;
        let len = intstr_to_fpstr_inplace(&mut buffer[..num_len], self.denomination as usize)
            .map_err(|_| ViewError::Unknown)?
            .len();

        let mut sz = len;
        if !self.sym.is_empty() {
            buffer[sz] = b' ';
            sz += 1;
            buffer[sz..sz + self.sym.len()].copy_from_slice(self.sym);
            sz += self.sym.len();
        }
        let to = pic_str!(b" to ");
        buffer[sz..sz + to.len()].copy_from_slice(to);
        sz += to.len();

        handle_ui_message(&buffer[..sz], message, page)
    }
}

impl<'b> FromBytes<'b> for CreateAssetTx<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("CreateAssetTx::from_bytes_into\x00");

        let (rem, _) = tag(AVM_CREATE_ASSET_TX.to_be_bytes())(input)?;

        let out = out.as_mut_ptr();

        // tx header
        let tx_header = unsafe { &mut *addr_of_mut!((*out).tx_header).cast() };
        let rem = Header::from_bytes_into(rem, tx_header)?;

        // This transaction is only valid if comes from XChain
        let chain_id = unsafe { (*tx_header.as_ptr()).chain_id()? };
        if !matches!(chain_id, ChainId::XChain) {
            return Err(ParserError::InvalidChainId.into());
        }

        // base_tx
        let base_tx = unsafe { &mut *addr_of_mut!((*out).base_tx).cast() };
        let rem = BaseTxFields::<AvmOutput>::from_bytes_after(
            unsafe { tx_header.assume_init_ref() },
            rem,
            base_tx,
        )?;

        // name and symbol go straight to the screen, so they follow
        // avalanchego's syntactic rules (vms/avm/txs/executor): a name of
        // letters, digits and inner spaces, a symbol of upper-case letters.
        // Checking only for ASCII let control characters through.

        // name
        let (rem, name_len) = be_u16(rem)?;
        if name_len == 0 || name_len > MAX_NAME_LEN as _ {
            return Err(ParserError::ValueOutOfRange.into());
        }
        let (rem, name) = take(name_len as usize)(rem)?;
        if !name.iter().all(|c| c.is_ascii_alphanumeric() || *c == b' ')
            || name.first() == Some(&b' ')
            || name.last() == Some(&b' ')
        {
            return Err(ParserError::InvalidAsciiValue.into());
        }

        // symbol
        let (rem, sym_len) = be_u16(rem)?;
        if sym_len == 0 || sym_len > MAX_SYMBOL_LEN as _ {
            return Err(ParserError::ValueOutOfRange.into());
        }
        let (rem, sym) = take(sym_len as usize)(rem)?;
        if !sym.iter().all(u8::is_ascii_uppercase) {
            return Err(ParserError::InvalidAsciiValue.into());
        }

        let (rem, denomination) = be_u8(rem)?;
        if denomination > MAX_DENOMINATION {
            return Err(ParserError::ValueOutOfRange.into());
        }

        // initial_states
        let states = unsafe { &mut *addr_of_mut!((*out).initial_states).cast() };
        let rem = ObjectList::<InitialState>::new_into(rem, states)?;
        // avalanchego requires at least one (errNoFxs).
        if unsafe { states.assume_init_ref() }.iter().next().is_none() {
            return Err(ParserError::UnexpectedData.into());
        }

        unsafe {
            addr_of_mut!((*out).name).write(name);
            addr_of_mut!((*out).sym).write(sym);
            addr_of_mut!((*out).denomination).write(denomination);
        }
        Ok(rem)
    }
}

impl DisplayableItem for CreateAssetTx<'_> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // description + asset_name + asset_symbol + denomination
        // + initial states + base outputs + fee.
        // The base outputs were previously left out of the count entirely, so
        // where the transaction's change went was never on screen.
        checked_add!(
            ViewError::Unknown,
            5u8,
            self.initial_states_items()?,
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
        use bolos::{pic_str, PIC};

        let mut buffer = [0; U64_FORMATTED_SIZE + 2];

        let end_states = START_STATES
            .checked_add(self.initial_states_items()?)
            .ok_or(ViewError::Unknown)?;
        let start_outputs = end_states;
        let output_items = self.base_tx.base_outputs_num_items()?;
        let end_outputs = start_outputs
            .checked_add(output_items)
            .ok_or(ViewError::Unknown)?;

        match item_n {
            0 => {
                let label = pic_str!(b"CreateAsset");
                title[..label.len()].copy_from_slice(label);
                let content = pic_str!(b"Transaction");
                handle_ui_message(content, message, page)
            }
            1 => {
                let label = pic_str!(b"Asset Name");
                title[..label.len()].copy_from_slice(label);
                handle_ui_message(self.name, message, page)
            }
            2 => {
                let label = pic_str!(b"Asset symbol");
                title[..label.len()].copy_from_slice(label);
                handle_ui_message(self.sym, message, page)
            }
            3 => {
                let label = pic_str!(b"Denomination");
                title[..label.len()].copy_from_slice(label);

                let mut buffer = [0; U8_FORMATTED_SIZE + 2];
                let num = u8_to_str(self.denomination, &mut buffer[..])
                    .map_err(|_| ViewError::Unknown)?;

                handle_ui_message(num, message, page)
            }

            // render initial states
            x if (START_STATES..end_states).contains(&x) => {
                self.render_initial_state(x - START_STATES, title, message, page)
            }
            // render base outputs
            x if (start_outputs..end_outputs).contains(&x) => {
                let hrp = self.tx_header.hrp().map_err(|_| ViewError::Unknown)?;
                self.base_tx.render_base_output_with_hrp(
                    hrp,
                    x - start_outputs,
                    title,
                    message,
                    page,
                )
            }
            x if x == end_outputs => {
                let label = pic_str!(b"Fee(AVAX)");
                title[..label.len()].copy_from_slice(label);

                let fee = self.fee().map_err(|_| ViewError::Unknown)?;
                let fee_buff =
                    nano_avax_to_fp_str(fee, &mut buffer[..]).map_err(|_| ViewError::Unknown)?;

                handle_ui_message(fee_buff, message, page)
            }

            _ => Err(ViewError::NoData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::prelude::v1::*;

    const DATA: &[u8] = &[
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0xab, 0x68, 0xeb, 0x1e, 0xe1, 0x42, 0xa0,
        0x5c, 0xfe, 0x76, 0x8c, 0x36, 0xe1, 0x1f, 0x0b, 0x59, 0x6d, 0xb5, 0xa3, 0xc6, 0xc7, 0x7a,
        0xab, 0xe6, 0x65, 0xda, 0xd9, 0xe6, 0x38, 0xca, 0x94, 0xf7, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xd4, 0x31, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x51,
        0x02, 0x5c, 0x61, 0xfb, 0xcf, 0xc0, 0x78, 0xf6, 0x93, 0x34, 0xf8, 0x34, 0xbe, 0x6d, 0xd2,
        0x6d, 0x55, 0xa9, 0x55, 0xc3, 0x34, 0x41, 0x28, 0xe0, 0x60, 0x12, 0x8e, 0xde, 0x35, 0x23,
        0xa2, 0x4a, 0x46, 0x1c, 0x89, 0x43, 0xab, 0x08, 0x59, 0x00, 0x00, 0x00, 0x01, 0xf1, 0xe1,
        0xd1, 0xc1, 0xb1, 0xa1, 0x91, 0x81, 0x71, 0x61, 0x51, 0x41, 0x31, 0x21, 0x11, 0x01, 0xf0,
        0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x07,
        0x5b, 0xcd, 0x15, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x02, 0x03, 0x00, 0x10, 0x56, 0x6f, 0x6c, 0x61, 0x74,
        0x69, 0x6c, 0x69, 0x74, 0x79, 0x20, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x00, 0x03, 0x56, 0x49,
        0x58, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xd4, 0x31, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x51, 0x02, 0x5c,
        0x61, 0xfb, 0xcf, 0xc0, 0x78, 0xf6, 0x93, 0x34, 0xf8, 0x34, 0xbe, 0x6d, 0xd2, 0x6d, 0x55,
        0xa9, 0x55, 0xc3, 0x34, 0x41, 0x28, 0xe0, 0x60, 0x12, 0x8e, 0xde, 0x35, 0x23, 0xa2, 0x4a,
        0x46, 0x1c, 0x89, 0x43, 0xab, 0x08, 0x59,
    ];

    /// Every (title, message) pair the review shows, first page only.
    fn screens(tx: &CreateAssetTx) -> Vec<(String, String)> {
        let items = tx.num_items().unwrap();
        (0..items)
            .map(|i| {
                let mut title = [0u8; 18];
                let mut message = [0u8; 1024];
                tx.render_item(i, &mut title, &mut message, 0)
                    .unwrap_or_else(|e| panic!("item {} failed: {:?}", i, e));
                let end = |b: &[u8]| b.iter().position(|&c| c == 0).unwrap_or(b.len());
                (
                    String::from_utf8(title[..end(&title)].to_vec()).unwrap(),
                    String::from_utf8(message[..end(&message)].to_vec()).unwrap(),
                )
            })
            .collect()
    }

    /// The initial states say who receives the new asset's supply and who may
    /// mint more of it. They are signed, so every holder and minter address
    /// has to be on screen: replacing them used to leave the review unchanged.
    #[test]
    fn create_asset_shows_initial_states() {
        use crate::parser::{Output, MAX_ADDRESS_ENCODED_LEN};

        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/parser/testvectors/");
        for name in ["x_create_asset.json", "x_create_asset_mint.json"] {
            let file = std::fs::File::open(format!("{}{}", dir, name)).unwrap();
            let data: Vec<u8> = serde_json::from_reader(file).unwrap();
            let (_, tx) = CreateAssetTx::from_bytes(&data[2..]).unwrap();
            let hrp = tx.tx_header.hrp().unwrap();
            let shown = screens(&tx);

            let mut outputs = 0;
            for state in tx.initial_states.iter() {
                for output in state.outputs().iter() {
                    outputs += 1;
                    if let Output::SECPTransfer(t) = output.0 {
                        let mut num = [0u8; 64];
                        u64_to_str(t.amount, &mut num).unwrap();
                        let supply =
                            intstr_to_fpstr_inplace(&mut num, tx.denomination as usize).unwrap();
                        let supply = format!("{} VIX to ", core::str::from_utf8(supply).unwrap());
                        assert!(
                            shown.contains(&("Supply".into(), supply.clone())),
                            "{}: supply {} not shown: {:#?}",
                            name,
                            supply,
                            shown
                        );
                    }
                    for idx in 0..output.num_addresses() {
                        let address = output.get_address(idx).unwrap();
                        let mut encoded = [0; MAX_ADDRESS_ENCODED_LEN];
                        let len = address.encode_into(hrp, &mut encoded[..]).unwrap();
                        let encoded = core::str::from_utf8(&encoded[..len]).unwrap();
                        assert!(
                            shown.iter().any(|(_, m)| m == encoded),
                            "{}: initial-state address {} not shown: {:#?}",
                            name,
                            encoded,
                            shown
                        );
                    }
                }
            }
            assert!(outputs > 0);
        }
    }

    #[test]
    fn create_asset_rejects_denomination_above_avalanchego_max() {
        let (_, tx) = CreateAssetTx::from_bytes(DATA).unwrap();
        let denomination_at =
            DATA.len() - (4 + 4 + 4 + 4 + 8 + 8 + 4 + 4 + 2 * crate::parser::ADDRESS_LEN) - 1;
        assert_eq!(DATA[denomination_at], tx.denomination);

        let mut data = Vec::from(DATA);
        data[denomination_at] = MAX_DENOMINATION;
        assert!(CreateAssetTx::from_bytes(&data).is_ok());
        data[denomination_at] = MAX_DENOMINATION + 1;
        assert!(CreateAssetTx::from_bytes(&data).is_err());
    }

    /// Name and symbol reach the screen verbatim, so only what avalanchego
    /// accepts may parse: letters, digits and inner spaces for the name,
    /// one to four upper-case letters for the symbol.
    #[test]
    fn create_asset_enforces_name_and_symbol_rules() {
        // DATA carries "Volatility Index" / "VIX", each after its u16 length.
        let name_at = DATA
            .windows(16)
            .position(|w| w == b"Volatility Index")
            .unwrap();
        let sym_at = DATA.windows(3).position(|w| w == b"VIX").unwrap();
        assert!(CreateAssetTx::from_bytes(DATA).is_ok());

        let with = |at: usize, old_len: usize, new: &[u8]| {
            let mut d = Vec::from(&DATA[..at - 2]);
            d.extend_from_slice(&(new.len() as u16).to_be_bytes());
            d.extend_from_slice(new);
            d.extend_from_slice(&DATA[at + old_len..]);
            d
        };

        for name in [
            &b"Volatility\nIndex"[..],
            b"Vol\x00",
            b" Vol",
            b"Vol ",
            b"Vol-X",
            b"",
        ] {
            let d = with(name_at, 16, name);
            assert!(CreateAssetTx::from_bytes(&d).is_err(), "name {:?}", name);
        }
        assert!(CreateAssetTx::from_bytes(&with(name_at, 16, b"Vol Index 2")).is_ok());

        for sym in [&b"vix"[..], b"V1X", b"V X", b"\x1bX", b""] {
            let d = with(sym_at, 3, sym);
            assert!(CreateAssetTx::from_bytes(&d).is_err(), "symbol {:?}", sym);
        }
        assert!(CreateAssetTx::from_bytes(&with(sym_at, 3, b"ABCD")).is_ok());

        // No initial states at all: symbol, denomination, then an empty list.
        let mut d = Vec::from(&DATA[..sym_at + 3 + 1]);
        d.extend_from_slice(&0u32.to_be_bytes());
        assert!(CreateAssetTx::from_bytes(&d).is_err());
    }

    #[test]
    fn parse_create_asset() {
        let (_, tx) = CreateAssetTx::from_bytes(DATA).unwrap();
        let name = core::str::from_utf8(tx.name).unwrap();
        let symbol = core::str::from_utf8(tx.sym).unwrap();
        assert_eq!(name, "Volatility Index");
        assert_eq!(symbol, "VIX");
        assert_eq!(tx.denomination, 2);
    }
}
