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
use core::convert::TryFrom;

use crate::constants::chain_alias_lookup;
use crate::parser::constants::*;
use crate::parser::ParserError;

pub use crate::parser::BLOCKCHAIN_ID_LEN;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[cfg_attr(test, derive(Debug))]
pub enum NetworkId {
    Mainnet,
    Fuji,
    Local,
    Custom,
    Devnet,
}

impl NetworkId {
    pub fn hrp(&self) -> &'static str {
        use bolos::PIC;

        match self {
            Self::Mainnet => PIC::new(HRP_MAINNET).into_inner(),
            Self::Fuji => PIC::new(HRP_TESTNET).into_inner(),
            Self::Local => PIC::new(HRP_LOCAL).into_inner(),
            Self::Custom => PIC::new(HRP_CUSTOM).into_inner(),
            Self::Devnet => PIC::new(HRP_DEVNET).into_inner(),
        }
    }
}

impl NetworkId {
    /// The AVAX asset id on this network, or None where it is not fixed.
    pub fn avax_asset_id(&self) -> Option<&'static [u8; 32]> {
        use bolos::PIC;

        match self {
            Self::Mainnet => Some(PIC::new(&AVAX_ASSET_ID_MAINNET).into_inner()),
            Self::Fuji => Some(PIC::new(&AVAX_ASSET_ID_FUJI).into_inner()),
            Self::Local => Some(PIC::new(&AVAX_ASSET_ID_LOCAL).into_inner()),
            Self::Custom | Self::Devnet => None,
        }
    }
}

impl TryFrom<u32> for NetworkId {
    type Error = ParserError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            NETWORK_ID_MAINNET => Ok(Self::Mainnet),
            NETWORK_ID_FUJI => Ok(Self::Fuji),
            NETWORK_ID_LOCAL => Ok(Self::Local),
            NETWORK_ID_CUSTOM => Ok(Self::Custom),
            NETWORK_ID_DEVNET => Ok(Self::Devnet),
            _ => Err(ParserError::InvalidNetworkId),
        }
    }
}

// bellow type defines the ID of supported
// chains, although in the protocol there is room for
// local networks, the current avalanche wallet does
// not support transactios from/to it
// Variants follow the Avalanche protocol naming convention (P-Chain, X-Chain,
// C-Chain) which intentionally shares a `Chain` suffix.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[cfg_attr(test, derive(Debug))]
pub enum ChainId {
    PChain,
    XChain,
    CChain,
}

impl TryFrom<&[u8; BLOCKCHAIN_ID_LEN]> for ChainId {
    type Error = ParserError;

    fn try_from(value: &[u8; BLOCKCHAIN_ID_LEN]) -> Result<Self, Self::Error> {
        match chain_alias_lookup(value).map(|a| a.as_bytes()) {
            Ok(b"X") => Ok(Self::XChain),
            Ok(b"P") => Ok(Self::PChain),
            Ok(b"C") => Ok(Self::CChain),
            _ => Err(ParserError::InvalidChainId),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct NetworkInfo {
    pub network_id: NetworkId,
    pub chain_id: ChainId,
}

impl TryFrom<(u32, &[u8; BLOCKCHAIN_ID_LEN])> for NetworkInfo {
    type Error = ParserError;

    fn try_from(value: (u32, &[u8; BLOCKCHAIN_ID_LEN])) -> Result<Self, Self::Error> {
        let network_id = NetworkId::try_from(value.0)?;
        let chain_id = ChainId::try_from(value.1)?;
        Ok(Self {
            network_id,
            chain_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::AssetId;
    use core::mem::MaybeUninit;
    use std::prelude::v1::*;

    #[test]
    fn avax_asset_ids_match_avalanchego() {
        // genesis TestAVAXAssetID in avalanchego
        for (network, expected) in [
            (NetworkId::Mainnet, "FvwEAhmxKfeiG8SnEvq42hc6whRyY3EFYAvebMqDNDGCgxN5Z"),
            (NetworkId::Fuji, "U8iRqJoiJm8xZHAacmvYyZVwqQx6uDNtQeP3CQ6fcgQk3JqnK"),
            (NetworkId::Local, "2fombhL7aGPwj3KH4bfrmJwW6PVnMobf9Y2fn9GwxiAAJyFDbe"),
        ] {
            let id = network.avax_asset_id().expect("known network");
            let mut asset = MaybeUninit::uninit();
            AssetId::from_bytes_into(&id[..], &mut asset).unwrap();
            let asset = unsafe { asset.assume_init() };

            let mut encoded = [0; crate::parser::asset_id::ASSET_ID_CB58_MAX_LEN];
            let len = asset.cb58_into(&mut encoded).unwrap();
            assert_eq!(core::str::from_utf8(&encoded[..len]).unwrap(), expected);
        }

        assert!(NetworkId::Custom.avax_asset_id().is_none());
        assert!(NetworkId::Devnet.avax_asset_id().is_none());
    }
}
