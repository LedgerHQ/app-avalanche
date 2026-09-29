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
use cfg_if::cfg_if;
use core::{convert::TryFrom, mem::MaybeUninit};
use nom::{
    bytes::complete::take,
    combinator::peek,
    number::complete::{be_u16, be_u32},
    sequence::tuple,
};

mod base_export;
mod base_import;
mod base_tx_fields;
mod transfer;
mod tx_header;

pub use base_export::BaseExport;
pub use base_import::BaseImport;
pub use base_tx_fields::{output_visibility, BaseTxFields};
pub use transfer::Transfer;
pub use tx_header::{Header, BLOCKCHAIN_ID_LEN};

mod avm;
mod pvm;

use crate::checked_add;
use crate::handlers::handle_ui_message;
use crate::parser::transactions::base_tx_fields::MAX_MEMO_LEN;
use crate::parser::{
    DisplayableItem, ExportTx as EvmExport, ImportTx as EvmImport, ObjectList, Output,
    OutputLock, TransferableInput, TransferableOutput, EVM_IMPORT_TX, PVM_BASE_TX_TRANSFER,
    PVM_EXPORT_TX, PVM_IMPORT_TX,
};
use core::ops::Deref;
use crate::utils::hex_encode;
pub use avm::{AvmExportTx, AvmImportTx, OperationTx};
pub use pvm::{PvmExportTx, PvmImportTx};
use zemu_sys::ViewError;

#[cfg(feature = "create-asset")]
pub use avm::CreateAssetTx;

#[cfg(feature = "create-chain")]
pub use pvm::CreateChainTx;

#[cfg(feature = "add-subnet-validator")]
pub use pvm::AddSubnetValidatorTx;

#[cfg(feature = "create-subnet")]
pub use pvm::CreateSubnetTx;

#[cfg(feature = "add-delegator")]
pub use pvm::AddDelegatorTx;

#[cfg(feature = "add-validator")]
pub use pvm::AddValidatorTx;

cfg_if! {
    if #[cfg(feature = "banff")] {
        pub use pvm::{
            RemoveSubnetValidatorTx,
            TransformSubnetTx,
            AddPermissionlessValidatorTx,
            AddPermissionlessDelegatorTx,

            // ACP-77
            ConvertSubnetToL1Tx,
            RegisterL1ValidatorTx,
            SetL1ValidatorWeightTx,
            DisableL1ValidatorTx,
            IncreaseL1ValidatorBalanceTx,

            // ACP-236
            AddAutoRenewedValidatorTx,
            SetAutoRenewedValidatorConfigTx
        };
    }
}

use self::pvm::PvmBaseTx;

use super::{
    ChainId, FromBytes, NetworkInfo, ParserError, AVM_EXPORT_TX, AVM_IMPORT_TX, AVM_OPERATION_TX,
    EVM_EXPORT_TX, TRANSFER_TX,
};

#[cfg(feature = "create-asset")]
use super::AVM_CREATE_ASSET_TX;

#[cfg(feature = "create-chain")]
use super::PVM_CREATE_CHAIN;

#[cfg(feature = "create-subnet")]
use super::PVM_CREATE_SUBNET;

#[cfg(feature = "add-subnet-validator")]
use super::PVM_ADD_SUBNET_VALIDATOR;

#[cfg(feature = "add-validator")]
use super::PVM_ADD_VALIDATOR;

#[cfg(feature = "add-delegator")]
use super::PVM_ADD_DELEGATOR;

cfg_if! {
    if #[cfg(feature = "banff")] {
        use super::{
            PVM_ADD_PERMISSIONLESS_DELEGATOR, PVM_ADD_PERMISSIONLESS_VALIDATOR, PVM_TRANSFORM_SUBNET, PVM_REMOVE_SUBNET_VALIDATOR,
            PVM_CONVERT_SUBNET_L1, PVM_INCREASE_L1_VALIDATOR_BALANCE, PVM_DISABLE_L1_VALIDATOR, PVM_SET_L1_VALIDATOR_WEIGHT, PVM_REGISTER_L1_VALIDATOR,
            PVM_ADD_AUTO_RENEWED_VALIDATOR, PVM_SET_AUTO_RENEWED_VALIDATOR_CONFIG
        };
    }
}

impl TryFrom<(u32, NetworkInfo)> for Transaction__Type {
    type Error = ParserError;

    fn try_from(value: (u32, NetworkInfo)) -> Result<Self, Self::Error> {
        crate::sys::zemu_log_stack("TransactionType::TryFrom\x00");
        let tx_type = match value.0 {
            PVM_EXPORT_TX => Transaction__Type::PExport,
            PVM_IMPORT_TX => Transaction__Type::PImport,
            PVM_BASE_TX_TRANSFER => Transaction__Type::PBase,
            AVM_EXPORT_TX => Transaction__Type::XExport,
            AVM_IMPORT_TX => Transaction__Type::XImport,
            AVM_OPERATION_TX => Transaction__Type::XOperation,
            // avoid collision with evm_export tx in C-chain
            // avoid collision with createAsset tx in X-chain
            EVM_EXPORT_TX if matches!(value.1.chain_id, ChainId::CChain) => {
                Transaction__Type::CExport
            }
            // avoid collision with normal_transfer tx in X-chain/P-chain
            EVM_IMPORT_TX if matches!(value.1.chain_id, ChainId::CChain) => {
                Transaction__Type::CImport
            }
            TRANSFER_TX => Transaction__Type::Transfer,
            #[cfg(feature = "create-asset")]
            AVM_CREATE_ASSET_TX if matches!(value.1.chain_id, ChainId::XChain) => {
                Transaction__Type::XAsset
            }
            #[cfg(feature = "create-chain")]
            PVM_CREATE_CHAIN => Transaction__Type::CreateChain,
            #[cfg(feature = "add-delegator")]
            PVM_ADD_DELEGATOR => Transaction__Type::Delegator,
            #[cfg(feature = "create-subnet")]
            PVM_CREATE_SUBNET => Transaction__Type::CreateSubnet,
            #[cfg(feature = "add-validator")]
            PVM_ADD_VALIDATOR => Transaction__Type::Validator,
            #[cfg(feature = "add-subnet-validator")]
            PVM_ADD_SUBNET_VALIDATOR => Transaction__Type::SubnetValidator,
            #[cfg(feature = "banff")]
            PVM_REMOVE_SUBNET_VALIDATOR => Transaction__Type::RemoveSubnetValidator,
            #[cfg(feature = "banff")]
            PVM_TRANSFORM_SUBNET => Transaction__Type::TransformSubnet,
            #[cfg(feature = "banff")]
            PVM_ADD_PERMISSIONLESS_VALIDATOR => Transaction__Type::PermissionlessValidator,
            #[cfg(feature = "banff")]
            PVM_ADD_PERMISSIONLESS_DELEGATOR => Transaction__Type::PermissionlessDelegator,
            #[cfg(feature = "banff")]
            PVM_CONVERT_SUBNET_L1 => Transaction__Type::ConvertSubnetToL1,
            #[cfg(feature = "banff")]
            PVM_REGISTER_L1_VALIDATOR => Transaction__Type::RegisterL1Validator,
            #[cfg(feature = "banff")]
            PVM_SET_L1_VALIDATOR_WEIGHT => Transaction__Type::SetL1ValidatorWeight,
            #[cfg(feature = "banff")]
            PVM_DISABLE_L1_VALIDATOR => Transaction__Type::DisableL1Validator,
            #[cfg(feature = "banff")]
            PVM_INCREASE_L1_VALIDATOR_BALANCE => Transaction__Type::IncreaseL1ValidatorBalance,
            #[cfg(feature = "banff")]
            PVM_ADD_AUTO_RENEWED_VALIDATOR => Transaction__Type::AutoRenewedValidator,
            #[cfg(feature = "banff")]
            PVM_SET_AUTO_RENEWED_VALIDATOR_CONFIG => {
                Transaction__Type::SetAutoRenewedValidatorConfig
            }
            _ => return Err(ParserError::InvalidTransactionType),
        };

        Ok(tx_type)
    }
}

#[avalanche_app_derive::enum_init]
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum Transaction<'b> {
    XImport(AvmImportTx<'b>),
    XExport(AvmExportTx<'b>),
    XOperation(OperationTx<'b>),
    PBase(PvmBaseTx<'b>),
    PImport(PvmImportTx<'b>),
    PExport(PvmExportTx<'b>),
    CImport(EvmImport<'b>),
    CExport(EvmExport<'b>),
    Transfer(Transfer<'b>),
    #[cfg(feature = "create-asset")]
    XAsset(CreateAssetTx<'b>),
    #[cfg(feature = "add-validator")]
    Validator(AddValidatorTx<'b>),
    #[cfg(feature = "add-delegator")]
    Delegator(AddDelegatorTx<'b>),
    #[cfg(feature = "create-chain")]
    CreateChain(CreateChainTx<'b>),
    #[cfg(feature = "create-subnet")]
    CreateSubnet(CreateSubnetTx<'b>),
    #[cfg(feature = "add-subnet-validator")]
    SubnetValidator(AddSubnetValidatorTx<'b>),
    #[cfg(feature = "banff")]
    RemoveSubnetValidator(RemoveSubnetValidatorTx<'b>),
    #[cfg(feature = "banff")]
    TransformSubnet(TransformSubnetTx<'b>),
    #[cfg(feature = "banff")]
    PermissionlessValidator(AddPermissionlessValidatorTx<'b>),
    #[cfg(feature = "banff")]
    PermissionlessDelegator(AddPermissionlessDelegatorTx<'b>),
    #[cfg(feature = "banff")]
    ConvertSubnetToL1(ConvertSubnetToL1Tx<'b>),
    #[cfg(feature = "banff")]
    RegisterL1Validator(RegisterL1ValidatorTx<'b>),
    #[cfg(feature = "banff")]
    SetL1ValidatorWeight(SetL1ValidatorWeightTx<'b>),
    #[cfg(feature = "banff")]
    DisableL1Validator(DisableL1ValidatorTx<'b>),
    #[cfg(feature = "banff")]
    IncreaseL1ValidatorBalance(IncreaseL1ValidatorBalanceTx<'b>),
    #[cfg(feature = "banff")]
    AutoRenewedValidator(AddAutoRenewedValidatorTx<'b>),
    #[cfg(feature = "banff")]
    SetAutoRenewedValidatorConfig(SetAutoRenewedValidatorConfigTx<'b>),
}

impl<'b> Transaction<'b> {
    fn peek_transaction_info(input: &'b [u8]) -> Result<(u32, NetworkInfo), nom::Err<ParserError>> {
        // peek transaction type, network_id and blockchain_id
        let (_, (raw_tx_id, network_id, blockchain_id)) =
            peek(tuple((be_u32, be_u32, take(BLOCKCHAIN_ID_LEN))))(input)?;
        let blockchain_id = arrayref::array_ref!(blockchain_id, 0, BLOCKCHAIN_ID_LEN);
        let network_info = NetworkInfo::try_from((network_id, blockchain_id))?;
        Ok((raw_tx_id, network_info))
    }

    #[cfg(test)]
    pub fn new(input: &'b [u8]) -> Result<Self, ParserError> {
        let mut variant = MaybeUninit::uninit();
        Self::new_into(input, &mut variant)?;
        // Safe as parsing initializes it
        Ok(unsafe { variant.assume_init() })
    }

    pub fn new_into(input: &'b [u8], this: &mut MaybeUninit<Self>) -> Result<(), ParserError> {
        let (rem, codec) = be_u16(input)?;

        if codec != 0 {
            return Err(ParserError::InvalidCodec);
        }
        let rem = Self::parse(rem, this)?;

        // SAFETY: parse initialized it
        let tx = unsafe { this.assume_init_ref() };
        tx.check_non_avax_flows()?;

        // The P/X/C-chain unsigned transaction wire format is
        // `CodecID + UnsignedTx`. Credentials belong to the SignedTx wrapper
        // and must not be present in the bytes that the device hashes — the
        // review UI renders only the UnsignedTx portion, so any trailing
        // bytes would be signed without being surfaced to the user.
        if !rem.is_empty() {
            return Err(ParserError::UnexpectedData);
        }

        Ok(())
    }

    pub fn disable_output_if(&mut self, address: &[u8]) {
        match self {
            Self::XImport(tx) => tx.disable_output_if(address),
            Self::XExport(tx) => tx.disable_output_if(address),
            Self::XOperation(tx) => tx.disable_output_if(address),
            Self::PImport(tx) => tx.disable_output_if(address),
            Self::PExport(tx) => tx.disable_output_if(address),
            Self::Transfer(tx) => tx.disable_output_if(address),
            // CImport is deliberately absent: its outputs are EVM addresses,
            // which are a different construction from the AVAX key hash this
            // filter matches on, so a match can only ever be contrived. See
            // coreth/import_tx.rs. CExport too: an export has no change, see
            // coreth/export_tx.rs.
            Self::PBase(tx) => tx.disable_output_if(address),
            #[cfg(feature = "add-validator")]
            Self::Validator(tx) => tx.disable_output_if(address),
            #[cfg(feature = "add-delegator")]
            Self::Delegator(tx) => tx.disable_output_if(address),
            #[cfg(feature = "banff")]
            Self::PermissionlessValidator(tx) => tx.disable_output_if(address),
            #[cfg(feature = "banff")]
            Self::PermissionlessDelegator(tx) => tx.disable_output_if(address),
            #[cfg(feature = "banff")]
            Self::AutoRenewedValidator(tx) => tx.disable_output_if(address),
            // These five render their base outputs, so they need the same
            // change filtering as every other type that does. Without an arm
            // here they fell through to `_ => {}`, and a change output would
            // be shown in full on transactions that used to show no outputs
            // at all.
            Self::SubnetValidator(tx) => tx.disable_output_if(address),
            Self::CreateSubnet(tx) => tx.disable_output_if(address),
            Self::CreateChain(tx) => tx.disable_output_if(address),
            #[cfg(feature = "banff")]
            Self::RemoveSubnetValidator(tx) => tx.disable_output_if(address),
            #[cfg(feature = "banff")]
            Self::ConvertSubnetToL1(tx) => tx.disable_output_if(address),
            // And these seven, which had the same gap: base outputs that
            // were signed and never shown, and no arm here.
            #[cfg(feature = "create-asset")]
            Self::XAsset(tx) => tx.disable_output_if(address),
            #[cfg(feature = "banff")]
            Self::TransformSubnet(tx) => tx.disable_output_if(address),
            #[cfg(feature = "banff")]
            Self::RegisterL1Validator(tx) => tx.disable_output_if(address),
            #[cfg(feature = "banff")]
            Self::SetL1ValidatorWeight(tx) => tx.disable_output_if(address),
            #[cfg(feature = "banff")]
            Self::DisableL1Validator(tx) => tx.disable_output_if(address),
            #[cfg(feature = "banff")]
            Self::IncreaseL1ValidatorBalance(tx) => tx.disable_output_if(address),
            #[cfg(feature = "banff")]
            Self::SetAutoRenewedValidatorConfig(tx) => tx.disable_output_if(address),
            // CImport and CExport are the only types without an arm; see above.
            _ => {}
        }
    }

    /// Refuse a transaction that burns an asset other than AVAX.
    ///
    /// Inputs are not reviewed and the fee only counts AVAX, so for any other
    /// asset what the transaction consumes must be exactly what it produces:
    /// avalanchego burns any excess, and 1e12 units of a token spent into a
    /// transaction with only AVAX outputs reviewed like a plain AVAX transfer.
    /// The one legitimate burn, TransformSubnet's reward pool, is allowed.
    /// Only checked where the network's AVAX asset id is known.
    fn check_non_avax_flows(&self) -> Result<(), ParserError> {
        let Some(avax) = self.avax_asset_id() else {
            return Ok(());
        };

        let mut result = Ok(());
        self.visit_flows(&mut |_, asset, _| {
            if result.is_err() || asset == *avax {
                return;
            }

            // consumed and produced amounts of this asset, over every list
            let (mut consumed, mut produced) = (0u128, 0u128);
            self.visit_flows(&mut |is_input, other, amount| {
                if other == asset {
                    if is_input {
                        consumed += amount as u128;
                    } else {
                        produced += amount as u128;
                    }
                }
            });

            #[cfg(feature = "banff")]
            if let Self::TransformSubnet(tx) = self {
                let (reward_asset, burn) = tx.reward_burn();
                if *reward_asset == asset {
                    produced += burn as u128;
                }
            }

            if consumed != produced {
                result = Err(ParserError::UnexpectedType);
            }
        });
        result
    }

    // the AVAX asset id on the transaction's network, if known
    fn avax_asset_id(&self) -> Option<&'static [u8; 32]> {
        match self {
            Self::XImport(tx) => tx.0.base_tx.avax_asset_id(),
            Self::XExport(tx) => tx.0.base_tx.avax_asset_id(),
            Self::XOperation(tx) => tx.base_tx.avax_asset_id(),
            Self::PImport(tx) => tx.0.base_tx.avax_asset_id(),
            Self::PExport(tx) => tx.0.base_tx.avax_asset_id(),
            Self::CImport(tx) => tx.tx_header.avax_asset_id(),
            Self::CExport(tx) => tx.tx_header.avax_asset_id(),
            Self::Transfer(tx) => tx.base.avax_asset_id(),
            Self::PBase(tx) => tx.base.avax_asset_id(),
            #[cfg(feature = "create-asset")]
            Self::XAsset(tx) => tx.base_tx.avax_asset_id(),
            #[cfg(feature = "add-validator")]
            Self::Validator(tx) => tx.base_tx.avax_asset_id(),
            #[cfg(feature = "add-delegator")]
            Self::Delegator(tx) => tx.base_tx.avax_asset_id(),
            #[cfg(feature = "create-chain")]
            Self::CreateChain(tx) => tx.base_tx.avax_asset_id(),
            #[cfg(feature = "create-subnet")]
            Self::CreateSubnet(tx) => tx.base_tx.avax_asset_id(),
            #[cfg(feature = "add-subnet-validator")]
            Self::SubnetValidator(tx) => tx.base_tx.avax_asset_id(),
            #[cfg(feature = "banff")]
            Self::RemoveSubnetValidator(tx) => tx.base_tx.avax_asset_id(),
            #[cfg(feature = "banff")]
            Self::TransformSubnet(tx) => tx.base_tx.avax_asset_id(),
            #[cfg(feature = "banff")]
            Self::PermissionlessValidator(tx) => tx.base_tx.avax_asset_id(),
            #[cfg(feature = "banff")]
            Self::PermissionlessDelegator(tx) => tx.base_tx.avax_asset_id(),
            #[cfg(feature = "banff")]
            Self::ConvertSubnetToL1(tx) => tx.base_tx.avax_asset_id(),
            #[cfg(feature = "banff")]
            Self::RegisterL1Validator(tx) => tx.base_tx.avax_asset_id(),
            #[cfg(feature = "banff")]
            Self::SetL1ValidatorWeight(tx) => tx.base_tx.avax_asset_id(),
            #[cfg(feature = "banff")]
            Self::DisableL1Validator(tx) => tx.base_tx.avax_asset_id(),
            #[cfg(feature = "banff")]
            Self::IncreaseL1ValidatorBalance(tx) => tx.base_tx.avax_asset_id(),
            #[cfg(feature = "banff")]
            Self::AutoRenewedValidator(tx) => tx.base_tx.avax_asset_id(),
            #[cfg(feature = "banff")]
            Self::SetAutoRenewedValidatorConfig(tx) => tx.base_tx.avax_asset_id(),
        }
    }

    /// Call `f(is_input, asset, amount)` for every fungible input and output
    /// of the transaction: base inputs and outputs, and the imported, exported
    /// and stake lists where the type has them. NFT and mint outputs carry no
    /// amount and are skipped.
    fn visit_flows(&self, f: &mut dyn FnMut(bool, [u8; 32], u64)) {
        fn ins(list: &ObjectList<'_, TransferableInput<'_>>, f: &mut dyn FnMut(bool, [u8; 32], u64)) {
            list.iterate_with(|i| {
                if let Some(amount) = i.amount() {
                    f(true, *i.asset_id().id(), amount)
                }
            });
        }
        fn outs<'b, O>(list: &ObjectList<'b, TransferableOutput<'b, O>>, f: &mut dyn FnMut(bool, [u8; 32], u64))
        where
            O: FromBytes<'b> + DisplayableItem + Deref<Target = Output<'b>> + OutputLock + 'b,
        {
            list.iterate_with(|o| {
                if let Some(amount) = o.amount() {
                    f(false, *o.asset_id().id(), amount)
                }
            });
        }
        fn base<'b, O>(base: &BaseTxFields<'b, O>, f: &mut dyn FnMut(bool, [u8; 32], u64))
        where
            O: FromBytes<'b> + DisplayableItem + Deref<Target = Output<'b>> + OutputLock + 'b,
        {
            ins(&base.inputs, f);
            outs(&base.outputs, f);
        }

        match self {
            Self::XImport(tx) => {
                base(&tx.0.base_tx, f);
                ins(&tx.0.inputs, f);
            }
            Self::XExport(tx) => {
                base(&tx.0.base_tx, f);
                outs(&tx.0.outputs, f);
            }
            Self::XOperation(tx) => base(&tx.base_tx, f),
            Self::PImport(tx) => {
                base(&tx.0.base_tx, f);
                ins(&tx.0.inputs, f);
            }
            Self::PExport(tx) => {
                base(&tx.0.base_tx, f);
                outs(&tx.0.outputs, f);
            }
            Self::CImport(tx) => {
                ins(&tx.inputs, f);
                tx.outputs.iterate_with(|o| {
                    if let Some(amount) = o.amount() {
                        f(false, *o.asset_id().id(), amount)
                    }
                });
            }
            Self::CExport(tx) => {
                tx.inputs.iterate_with(|i| {
                    if let Some(amount) = i.amount() {
                        f(true, *i.asset_id().id(), amount)
                    }
                });
                outs(&tx.outputs, f);
            }
            Self::Transfer(tx) => base(&tx.base, f),
            Self::PBase(tx) => base(&tx.base, f),
            #[cfg(feature = "create-asset")]
            Self::XAsset(tx) => base(&tx.base_tx, f),
            #[cfg(feature = "add-validator")]
            Self::Validator(tx) => {
                base(&tx.base_tx, f);
                outs(&tx.stake, f);
            }
            #[cfg(feature = "add-delegator")]
            Self::Delegator(tx) => {
                base(&tx.base_tx, f);
                outs(&tx.stake, f);
            }
            #[cfg(feature = "create-chain")]
            Self::CreateChain(tx) => base(&tx.base_tx, f),
            #[cfg(feature = "create-subnet")]
            Self::CreateSubnet(tx) => base(&tx.base_tx, f),
            #[cfg(feature = "add-subnet-validator")]
            Self::SubnetValidator(tx) => base(&tx.base_tx, f),
            #[cfg(feature = "banff")]
            Self::RemoveSubnetValidator(tx) => base(&tx.base_tx, f),
            #[cfg(feature = "banff")]
            Self::TransformSubnet(tx) => base(&tx.base_tx, f),
            #[cfg(feature = "banff")]
            Self::PermissionlessValidator(tx) => {
                base(&tx.base_tx, f);
                outs(&tx.stake, f);
            }
            #[cfg(feature = "banff")]
            Self::PermissionlessDelegator(tx) => {
                base(&tx.base_tx, f);
                outs(&tx.stake, f);
            }
            #[cfg(feature = "banff")]
            Self::ConvertSubnetToL1(tx) => base(&tx.base_tx, f),
            #[cfg(feature = "banff")]
            Self::RegisterL1Validator(tx) => base(&tx.base_tx, f),
            #[cfg(feature = "banff")]
            Self::SetL1ValidatorWeight(tx) => base(&tx.base_tx, f),
            #[cfg(feature = "banff")]
            Self::DisableL1Validator(tx) => base(&tx.base_tx, f),
            #[cfg(feature = "banff")]
            Self::IncreaseL1ValidatorBalance(tx) => base(&tx.base_tx, f),
            #[cfg(feature = "banff")]
            Self::AutoRenewedValidator(tx) => {
                base(&tx.base_tx, f);
                outs(&tx.stake, f);
            }
            #[cfg(feature = "banff")]
            Self::SetAutoRenewedValidatorConfig(tx) => base(&tx.base_tx, f),
        }
    }

    /// Run after the change filter has been applied for every change path:
    /// if it hid every output of a transfer, show them all again.
    ///
    /// A transfer, import or export whose outputs all go back to the user's
    /// own paths would otherwise review with no output at all, and nothing
    /// would tell the user where the funds went. Staking, subnet, L1 and
    /// operation transactions are left alone: their purpose is on screen
    /// anyway, and an honest delegation, whose change and stake both return
    /// to the user, would otherwise always show every output.
    pub fn show_outputs_if_all_hidden(&mut self) {
        let (visible, total) = self.output_visibility();
        if total > 0 && visible == 0 {
            self.show_all_outputs();
        }
    }

    // (visible, total) outputs of the transfer types the rule above applies
    // to, (0, 0) for every other type
    fn output_visibility(&self) -> (usize, usize) {
        match self {
            Self::Transfer(tx) => tx.base.output_visibility(),
            Self::PBase(tx) => tx.base.output_visibility(),
            Self::XImport(tx) => tx.0.base_tx.output_visibility(),
            Self::PImport(tx) => tx.0.base_tx.output_visibility(),
            Self::XExport(tx) => tx.0.output_visibility(),
            Self::PExport(tx) => tx.0.output_visibility(),
            // CImport and CExport are not filtered at all
            _ => (0, 0),
        }
    }

    fn show_all_outputs(&mut self) {
        match self {
            Self::Transfer(tx) => tx.base.show_all_outputs(),
            Self::PBase(tx) => tx.base.show_all_outputs(),
            Self::XImport(tx) => tx.0.base_tx.show_all_outputs(),
            Self::PImport(tx) => tx.0.base_tx.show_all_outputs(),
            Self::XExport(tx) => tx.0.show_all_outputs(),
            Self::PExport(tx) => tx.0.show_all_outputs(),
            _ => {}
        }
    }

    fn parse(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        let info = Self::peek_transaction_info(input)?;

        let transaction_type = Transaction__Type::try_from(info)?;

        match transaction_type {
            Transaction__Type::PImport => {
                Self::init_as_p_import(|out| PvmImportTx::from_bytes_into(input, out), out)
            }
            Transaction__Type::PExport => {
                Self::init_as_p_export(|out| PvmExportTx::from_bytes_into(input, out), out)
            }
            Transaction__Type::PBase => {
                Self::init_as_p_base(|out| PvmBaseTx::from_bytes_into(input, out), out)
            }
            Transaction__Type::XImport => {
                Self::init_as_x_import(|out| AvmImportTx::from_bytes_into(input, out), out)
            }
            Transaction__Type::XExport => {
                Self::init_as_x_export(|out| AvmExportTx::from_bytes_into(input, out), out)
            }
            Transaction__Type::XOperation => {
                Self::init_as_x_operation(|out| OperationTx::from_bytes_into(input, out), out)
            }
            Transaction__Type::CExport => {
                Self::init_as_c_export(|out| EvmExport::from_bytes_into(input, out), out)
            }
            Transaction__Type::CImport => {
                Self::init_as_c_import(|out| EvmImport::from_bytes_into(input, out), out)
            }
            Transaction__Type::Transfer => {
                Self::init_as_transfer(|out| Transfer::from_bytes_into(input, out), out)
            }
            #[cfg(feature = "create-asset")]
            Transaction__Type::XAsset => {
                Self::init_as_x_asset(|out| CreateAssetTx::from_bytes_into(input, out), out)
            }
            #[cfg(feature = "create-chain")]
            Transaction__Type::CreateChain => {
                Self::init_as_create_chain(|out| CreateChainTx::from_bytes_into(input, out), out)
            }
            #[cfg(feature = "create-subnet")]
            Transaction__Type::CreateSubnet => {
                Self::init_as_create_subnet(|out| CreateSubnetTx::from_bytes_into(input, out), out)
            }
            #[cfg(feature = "add-validator")]
            Transaction__Type::Validator => {
                Self::init_as_validator(|out| AddValidatorTx::from_bytes_into(input, out), out)
            }
            #[cfg(feature = "add-delegator")]
            Transaction__Type::Delegator => {
                Self::init_as_delegator(|out| AddDelegatorTx::from_bytes_into(input, out), out)
            }
            #[cfg(feature = "add-subnet-validator")]
            Transaction__Type::SubnetValidator => Self::init_as_subnet_validator(
                |out| AddSubnetValidatorTx::from_bytes_into(input, out),
                out,
            ),
            #[cfg(feature = "banff")]
            Transaction__Type::RemoveSubnetValidator => Self::init_as_remove_subnet_validator(
                |out| RemoveSubnetValidatorTx::from_bytes_into(input, out),
                out,
            ),
            #[cfg(feature = "banff")]
            Transaction__Type::TransformSubnet => Self::init_as_transform_subnet(
                |out| TransformSubnetTx::from_bytes_into(input, out),
                out,
            ),
            #[cfg(feature = "banff")]
            Transaction__Type::PermissionlessValidator => Self::init_as_permissionless_validator(
                |out| AddPermissionlessValidatorTx::from_bytes_into(input, out),
                out,
            ),
            #[cfg(feature = "banff")]
            Transaction__Type::PermissionlessDelegator => Self::init_as_permissionless_delegator(
                |out| AddPermissionlessDelegatorTx::from_bytes_into(input, out),
                out,
            ),
            #[cfg(feature = "banff")]
            Transaction__Type::ConvertSubnetToL1 => Self::init_as_convert_subnet_to_l_1(
                |out| ConvertSubnetToL1Tx::from_bytes_into(input, out),
                out,
            ),
            #[cfg(feature = "banff")]
            Transaction__Type::RegisterL1Validator => Self::init_as_register_l_1_validator(
                |out| RegisterL1ValidatorTx::from_bytes_into(input, out),
                out,
            ),
            #[cfg(feature = "banff")]
            Transaction__Type::SetL1ValidatorWeight => Self::init_as_set_l_1_validator_weight(
                |out| SetL1ValidatorWeightTx::from_bytes_into(input, out),
                out,
            ),
            #[cfg(feature = "banff")]
            Transaction__Type::DisableL1Validator => Self::init_as_disable_l_1_validator(
                |out| DisableL1ValidatorTx::from_bytes_into(input, out),
                out,
            ),
            #[cfg(feature = "banff")]
            Transaction__Type::IncreaseL1ValidatorBalance => {
                Self::init_as_increase_l_1_validator_balance(
                    |out| IncreaseL1ValidatorBalanceTx::from_bytes_into(input, out),
                    out,
                )
            }
            #[cfg(feature = "banff")]
            Transaction__Type::AutoRenewedValidator => Self::init_as_auto_renewed_validator(
                |out| AddAutoRenewedValidatorTx::from_bytes_into(input, out),
                out,
            ),
            #[cfg(feature = "banff")]
            Transaction__Type::SetAutoRenewedValidatorConfig => {
                Self::init_as_set_auto_renewed_validator_config(
                    |out| SetAutoRenewedValidatorConfigTx::from_bytes_into(input, out),
                    out,
                )
            }
        }
    }

    // Returns True if transaction is one of the supported coreth transactions.
    pub fn is_eth(&self) -> bool {
        matches!(self, Self::CExport(_)) || matches!(self, Self::CImport(_))
    }
}

impl Transaction<'_> {
    fn inner_num_items(&self) -> Result<u8, zemu_sys::ViewError> {
        match self {
            Self::XImport(tx) => tx.num_items(),
            Self::XExport(tx) => tx.num_items(),
            Self::XOperation(tx) => tx.num_items(),
            Self::PImport(tx) => tx.num_items(),
            Self::PExport(tx) => tx.num_items(),
            Self::CImport(tx) => tx.num_items(),
            Self::CExport(tx) => tx.num_items(),
            Self::Transfer(tx) => tx.num_items(),
            Self::PBase(tx) => tx.num_items(),
            #[cfg(feature = "create-asset")]
            Self::XAsset(tx) => tx.num_items(),
            #[cfg(feature = "add-validator")]
            Self::Validator(tx) => tx.num_items(),
            #[cfg(feature = "add-subnet-validator")]
            Self::SubnetValidator(tx) => tx.num_items(),
            #[cfg(feature = "add-delegator")]
            Self::Delegator(tx) => tx.num_items(),
            #[cfg(feature = "create-chain")]
            Self::CreateChain(tx) => tx.num_items(),
            #[cfg(feature = "create-subnet")]
            Self::CreateSubnet(tx) => tx.num_items(),
            #[cfg(feature = "banff")]
            Self::RemoveSubnetValidator(tx) => tx.num_items(),
            #[cfg(feature = "banff")]
            Self::TransformSubnet(tx) => tx.num_items(),
            #[cfg(feature = "banff")]
            Self::PermissionlessValidator(tx) => tx.num_items(),
            #[cfg(feature = "banff")]
            Self::PermissionlessDelegator(tx) => tx.num_items(),
            #[cfg(feature = "banff")]
            Self::ConvertSubnetToL1(tx) => tx.num_items(),
            #[cfg(feature = "banff")]
            Self::IncreaseL1ValidatorBalance(tx) => tx.num_items(),
            #[cfg(feature = "banff")]
            Self::DisableL1Validator(tx) => tx.num_items(),
            #[cfg(feature = "banff")]
            Self::SetL1ValidatorWeight(tx) => tx.num_items(),
            #[cfg(feature = "banff")]
            Self::RegisterL1Validator(tx) => tx.num_items(),
            #[cfg(feature = "banff")]
            Self::AutoRenewedValidator(tx) => tx.num_items(),
            #[cfg(feature = "banff")]
            Self::SetAutoRenewedValidatorConfig(tx) => tx.num_items(),
        }
    }

    fn render_inner_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        match self {
            Self::XImport(tx) => tx.render_item(item_n, title, message, page),
            Self::XExport(tx) => tx.render_item(item_n, title, message, page),
            Self::XOperation(tx) => tx.render_item(item_n, title, message, page),
            Self::PImport(tx) => tx.render_item(item_n, title, message, page),
            Self::PExport(tx) => tx.render_item(item_n, title, message, page),
            Self::PBase(tx) => tx.render_item(item_n, title, message, page),
            Self::CImport(tx) => tx.render_item(item_n, title, message, page),
            Self::CExport(tx) => tx.render_item(item_n, title, message, page),
            Self::Transfer(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "create-asset")]
            Self::XAsset(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "add-validator")]
            Self::Validator(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "add-subnet-validator")]
            Self::SubnetValidator(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "add-delegator")]
            Self::Delegator(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "create-chain")]
            Self::CreateChain(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "create-subnet")]
            Self::CreateSubnet(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "banff")]
            Self::RemoveSubnetValidator(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "banff")]
            Self::TransformSubnet(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "banff")]
            Self::PermissionlessValidator(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "banff")]
            Self::PermissionlessDelegator(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "banff")]
            Self::ConvertSubnetToL1(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "banff")]
            Self::IncreaseL1ValidatorBalance(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "banff")]
            Self::DisableL1Validator(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "banff")]
            Self::SetL1ValidatorWeight(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "banff")]
            Self::RegisterL1Validator(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "banff")]
            Self::AutoRenewedValidator(tx) => tx.render_item(item_n, title, message, page),
            #[cfg(feature = "banff")]
            Self::SetAutoRenewedValidatorConfig(tx) => tx.render_item(item_n, title, message, page),
        }
    }

    /// The transaction's memo, when the type carries one.
    ///
    /// The field is parsed and covered by the signing hash but had no render
    /// site anywhere in the crate, so up to 256 bytes were signed without ever
    /// being shown. Coreth transactions have no memo field.
    fn memo(&self) -> Option<&[u8]> {
        match self {
            Self::XImport(tx) => Some(tx.0.base_tx.memo),
            Self::XExport(tx) => Some(tx.0.base_tx.memo),
            Self::XOperation(tx) => Some(tx.base_tx.memo),
            Self::PImport(tx) => Some(tx.0.base_tx.memo),
            Self::PExport(tx) => Some(tx.0.base_tx.memo),
            Self::CImport(_) => None,
            Self::CExport(_) => None,
            Self::Transfer(tx) => Some(tx.base.memo),
            Self::PBase(tx) => Some(tx.base.memo),
            #[cfg(feature = "create-asset")]
            Self::XAsset(tx) => Some(tx.base_tx.memo),
            #[cfg(feature = "add-validator")]
            Self::Validator(tx) => Some(tx.base_tx.memo),
            #[cfg(feature = "add-subnet-validator")]
            Self::SubnetValidator(tx) => Some(tx.base_tx.memo),
            #[cfg(feature = "add-delegator")]
            Self::Delegator(tx) => Some(tx.base_tx.memo),
            #[cfg(feature = "create-chain")]
            Self::CreateChain(tx) => Some(tx.base_tx.memo),
            #[cfg(feature = "create-subnet")]
            Self::CreateSubnet(tx) => Some(tx.base_tx.memo),
            #[cfg(feature = "banff")]
            Self::RemoveSubnetValidator(tx) => Some(tx.base_tx.memo),
            #[cfg(feature = "banff")]
            Self::TransformSubnet(tx) => Some(tx.base_tx.memo),
            #[cfg(feature = "banff")]
            Self::PermissionlessValidator(tx) => Some(tx.base_tx.memo),
            #[cfg(feature = "banff")]
            Self::PermissionlessDelegator(tx) => Some(tx.base_tx.memo),
            #[cfg(feature = "banff")]
            Self::ConvertSubnetToL1(tx) => Some(tx.base_tx.memo),
            #[cfg(feature = "banff")]
            Self::IncreaseL1ValidatorBalance(tx) => Some(tx.base_tx.memo),
            #[cfg(feature = "banff")]
            Self::DisableL1Validator(tx) => Some(tx.base_tx.memo),
            #[cfg(feature = "banff")]
            Self::SetL1ValidatorWeight(tx) => Some(tx.base_tx.memo),
            #[cfg(feature = "banff")]
            Self::RegisterL1Validator(tx) => Some(tx.base_tx.memo),
            #[cfg(feature = "banff")]
            Self::AutoRenewedValidator(tx) => Some(tx.base_tx.memo),
            #[cfg(feature = "banff")]
            Self::SetAutoRenewedValidatorConfig(tx) => Some(tx.base_tx.memo),
        }
    }

    fn memo_items(&self) -> u8 {
        match self.memo() {
            Some(memo) if !memo.is_empty() => 1,
            _ => 0,
        }
    }

    fn render_memo(
        &self,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        use bolos::{pic_str, PIC};

        let memo = self.memo().ok_or(ViewError::NoData)?;

        let label = pic_str!(b"Memo");
        title[..label.len()].copy_from_slice(label);

        // Memos are arbitrary host bytes. Printable ASCII goes through as text;
        // anything else is hex so control characters and bidi overrides cannot
        // reach the screen.
        if memo.iter().all(|c| (0x20..0x7f).contains(c)) {
            handle_ui_message(memo, message, page)
        } else {
            let mut hex = [0; MAX_MEMO_LEN * 2];
            let len = hex_encode(memo, &mut hex[..]).map_err(|_| ViewError::Unknown)?;
            handle_ui_message(&hex[..len], message, page)
        }
    }
}

impl DisplayableItem for Transaction<'_> {
    fn num_items(&self) -> Result<u8, zemu_sys::ViewError> {
        // The memo is a transaction-level field, so it is counted here rather
        // than in each of the twenty-two types that carry BaseTxFields.
        checked_add!(
            ViewError::Unknown,
            self.inner_num_items()?,
            self.memo_items()
        )
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, zemu_sys::ViewError> {
        let inner = self.inner_num_items()?;
        if self.memo_items() == 1 && item_n == inner {
            return self.render_memo(title, message, page);
        }
        self.render_inner_item(item_n, title, message, page)
    }
}

#[cfg(test)]
mod tests {
    use std::prelude::v1::*;

    use zemu_sys::Viewable;

    use super::*;

    /// This is only to be used for testing, hence why
    /// it's present inside the `mod test` block only
    impl Viewable for Transaction<'static> {
        fn num_items(&mut self) -> Result<u8, zemu_sys::ViewError> {
            DisplayableItem::num_items(&*self)
        }

        fn render_item(
            &mut self,
            item_idx: u8,
            title: &mut [u8],
            message: &mut [u8],
            page_idx: u8,
        ) -> Result<u8, zemu_sys::ViewError> {
            DisplayableItem::render_item(&*self, item_idx, title, message, page_idx)
        }

        fn accept(&mut self, _: &mut [u8]) -> (usize, u16) {
            (0, 0)
        }

        fn reject(&mut self, _: &mut [u8]) -> (usize, u16) {
            (0, 0)
        }
    }

    // Transfer transaction
    const DATA:&str = "00000000000000000005ab68eb1ee142a05cfe768c36e11f0b596db5a3c6c77aabe665dad9e638ca94f7000000023d9bdac0ed1d761330cf680efdeb1a42159eb387d6d2950c96f7d28f61bbe2aa00000007000000003b9aca0000000000000000000000000100000001636fb961b8bce4d0038796f5db330fecc8e36f723d9bdac0ed1d761330cf680efdeb1a42159eb387d6d2950c96f7d28f61bbe2aa0000000700000000f44284800000000000000000000000010000000107fe53d8ed2b004df3ac75175a4e727a6dd461d8000000023be4ead93aa5e6396d1f2c6e9587c7642b30d52d605f917d8a402e6823f965f2000000003d9bdac0ed1d761330cf680efdeb1a42159eb387d6d2950c96f7d28f61bbe2aa000000050000000005e69ec0000000010000000095aff4ba72647c2a6a41802c047a9f3a3919b35aefcf7da843d4cc34980c7102000000003d9bdac0ed1d761330cf680efdeb1a42159eb387d6d2950c96f7d28f61bbe2aa00000005000000012a05f200000000010000000000000000";

    // provided change_address
    const CHANGE_ADDRESS: &str = "07fe53d8ed2b004df3ac75175a4e727a6dd461d8";

    // Same Transfer transaction bytes as `DATA`, with a single `0x00` byte
    // appended. The whole buffer is hashed for signing, so any trailing byte
    // would be covered by the signature without being surfaced in the UI.
    #[test]
    fn parse_transaction_with_trailing_bytes_rejected() {
        let mut data = hex::decode(DATA).unwrap();
        data.push(0x00);

        assert!(Transaction::new(&data).is_err());
    }

    #[test]
    fn parse_transaction() {
        let data = hex::decode(DATA).unwrap();
        let change_address = hex::decode(CHANGE_ADDRESS).unwrap();

        let mut tx = Transaction::new(&data).unwrap();
        // get number of items with all active outputs
        let num_items = tx.num_items().expect("Overflow?");

        // disable one output.
        tx.disable_output_if(&change_address);

        //get again the number of outputs
        let num_items_hide = tx.num_items().expect("Overflows?");

        // ensure the number of items has changed
        // as there is now one output that is disable
        assert!(num_items > num_items_hide);

        assert!(matches!(tx, Transaction::Transfer(..)));
    }

    #[test]
    #[cfg(feature = "full")]
    //isolation is enabled by defalt in miri
    // and this prevents opening files, amonst other things
    // we could either disable isolation or have miri
    // return errors on open & co.
    //
    // considering we aren't doing anything special in this test
    // we can just avoid having it run in miri directly
    #[cfg_attr(miri, ignore)]
    fn tx_ui() {
        use crate::parser::snapshots_common::{with_leaked, ReducedPage};

        insta::glob!("testvectors/*.json", |path| {
            let file = std::fs::File::open(path)
                .unwrap_or_else(|e| panic!("Unable to open file {:?}: {:?}", path, e));
            let input: Vec<u8> = serde_json::from_reader(file)
                .unwrap_or_else(|e| panic!("Unable to read file {:?} as json: {:?}", path, e));

            let test = |data| {
                let tx = Transaction::new(data).expect("parse tx from data");

                let mut driver = zuit::MockDriver::<_, 18, 1024>::new(tx);
                driver.drive();

                let ui = driver.out_ui();

                let reduced = ui
                    .iter()
                    .flat_map(|item| item.iter().map(ReducedPage::from))
                    .collect::<Vec<_>>();

                insta::assert_debug_snapshot!(reduced);
            };

            unsafe { with_leaked(input, test) };
        });
    }

    /// Every address of every base output `tx` signs, encoded with `hrp`.
    /// Coreth transactions carry no BaseTxFields.
    #[cfg(feature = "full")]
    fn base_output_addresses(tx: &Transaction<'_>, hrp: &str) -> Vec<String> {
        use crate::parser::{BaseTxFields, FromBytes, Output, OutputLock, MAX_ADDRESS_ENCODED_LEN};
        use core::ops::Deref;

        fn collect<'b, O>(base: &BaseTxFields<'b, O>, hrp: &str, out: &mut Vec<String>)
        where
            O: FromBytes<'b> + DisplayableItem + Deref<Target = Output<'b>> + OutputLock + 'b,
        {
            base.outputs.iterate_with(|o| {
                let inner: &Output<'_> = &o.output;
                for idx in 0..inner.num_addresses() {
                    let address = inner.get_address(idx).expect("address in range");
                    let mut encoded = [0; MAX_ADDRESS_ENCODED_LEN];
                    let len = address
                        .encode_into(hrp, &mut encoded[..])
                        .expect("encodable address");
                    out.push(String::from_utf8(encoded[..len].to_vec()).expect("bech32 is ascii"));
                }
            });
        }

        let mut out = Vec::new();
        // No wildcard: a new transaction type must be added here explicitly.
        match tx {
            Transaction::XImport(tx) => collect(&tx.0.base_tx, hrp, &mut out),
            Transaction::XExport(tx) => collect(&tx.0.base_tx, hrp, &mut out),
            Transaction::PExport(tx) => collect(&tx.0.base_tx, hrp, &mut out),
            Transaction::XOperation(tx) => collect(&tx.base_tx, hrp, &mut out),
            Transaction::PBase(tx) => collect(&tx.base, hrp, &mut out),
            Transaction::PImport(tx) => collect(&tx.0.base_tx, hrp, &mut out),
            Transaction::CImport(_) | Transaction::CExport(_) => {}
            Transaction::Transfer(tx) => collect(&tx.base, hrp, &mut out),
            Transaction::XAsset(tx) => collect(&tx.base_tx, hrp, &mut out),
            Transaction::Validator(tx) => collect(&tx.base_tx, hrp, &mut out),
            Transaction::Delegator(tx) => collect(&tx.base_tx, hrp, &mut out),
            Transaction::CreateChain(tx) => collect(&tx.base_tx, hrp, &mut out),
            Transaction::CreateSubnet(tx) => collect(&tx.base_tx, hrp, &mut out),
            Transaction::SubnetValidator(tx) => collect(&tx.base_tx, hrp, &mut out),
            Transaction::RemoveSubnetValidator(tx) => collect(&tx.base_tx, hrp, &mut out),
            Transaction::TransformSubnet(tx) => collect(&tx.base_tx, hrp, &mut out),
            Transaction::PermissionlessValidator(tx) => collect(&tx.base_tx, hrp, &mut out),
            Transaction::PermissionlessDelegator(tx) => collect(&tx.base_tx, hrp, &mut out),
            Transaction::ConvertSubnetToL1(tx) => collect(&tx.base_tx, hrp, &mut out),
            Transaction::RegisterL1Validator(tx) => collect(&tx.base_tx, hrp, &mut out),
            Transaction::SetL1ValidatorWeight(tx) => collect(&tx.base_tx, hrp, &mut out),
            Transaction::DisableL1Validator(tx) => collect(&tx.base_tx, hrp, &mut out),
            Transaction::IncreaseL1ValidatorBalance(tx) => collect(&tx.base_tx, hrp, &mut out),
            Transaction::AutoRenewedValidator(tx) => collect(&tx.base_tx, hrp, &mut out),
            Transaction::SetAutoRenewedValidatorConfig(tx) => collect(&tx.base_tx, hrp, &mut out),
        }
        out
    }

    /// A base output the device signs must be on screen. The fee is
    /// sum(inputs) - sum(outputs), so it only depends on amounts: an output
    /// whose address is never rendered can be redirected with nothing on the
    /// review to show for it.
    ///
    /// Walks every vector, renders every page, and checks each base-output
    /// address appears -- with no change filter, and with one that matches
    /// none of the outputs (so nothing may be hidden).
    #[test]
    #[cfg(feature = "full")]
    #[cfg_attr(miri, ignore)]
    fn every_base_output_is_rendered() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/parser/testvectors");
        let mut paths = std::fs::read_dir(&dir)
            .expect("testvectors dir")
            .map(|entry| entry.expect("dir entry").path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .collect::<Vec<_>>();
        paths.sort();
        assert!(!paths.is_empty(), "no vectors found in {:?}", dir);

        for path in paths {
            let file = std::fs::File::open(&path).expect("open vector");
            let data: Vec<u8> = serde_json::from_reader(file).expect("vector is a byte array");

            for change_filter in [None, Some([0xa5u8; 20])] {
                let mut tx = Transaction::new(&data)
                    .unwrap_or_else(|e| panic!("{:?} does not parse: {:?}", path, e));
                if let Some(change) = change_filter {
                    tx.disable_output_if(&change);
                }

                // codec (2 bytes) and type id (4 bytes), then the network id
                let network_id = u32::from_be_bytes([data[6], data[7], data[8], data[9]]);
                let hrp = crate::parser::NetworkId::try_from(network_id)
                    .expect("valid network id")
                    .hrp();

                let mut screens = Vec::<String>::new();
                let items = DisplayableItem::num_items(&tx).expect("num_items");
                for item in 0..items {
                    let mut title = [0u8; 18];
                    let mut message = [0u8; 1024];
                    let pages = DisplayableItem::render_item(&tx, item, &mut title, &mut message, 0)
                        .unwrap_or_else(|e| panic!("{:?}: item {} failed: {:?}", path, item, e));

                    let mut text = String::new();
                    for page in 0..pages {
                        message.fill(0);
                        DisplayableItem::render_item(&tx, item, &mut title, &mut message, page)
                            .expect("page renders");
                        let end = message.iter().position(|&b| b == 0).unwrap_or(message.len());
                        text.push_str(core::str::from_utf8(&message[..end]).expect("ascii"));
                    }
                    screens.push(text);
                }

                for address in base_output_addresses(&tx, hrp) {
                    assert!(
                        screens.contains(&address),
                        "{:?}: base output address {} is signed but never shown (change filter: {:?})",
                        path,
                        address,
                        change_filter
                    );
                }
            }
        }
    }
}
