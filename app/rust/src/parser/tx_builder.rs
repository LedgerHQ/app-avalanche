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
//! Builders for hand-crafted X/P-chain transactions, and a renderer that
//! returns every screen as text, for regression tests that need a vector
//! the JSON test vectors do not cover.
#![allow(dead_code)]

use std::prelude::v1::*;

use crate::parser::{DisplayableItem, Transaction};

pub const FUJI: u32 = 5;
pub const MAINNET: u32 = 1;

/// AVAX asset id on Fuji, U8iRqJoiJm8xZHAacmvYyZVwqQx6uDNtQeP3CQ6fcgQk3JqnK
pub const FUJI_AVAX: [u8; 32] = [
    0x3d, 0x9b, 0xda, 0xc0, 0xed, 0x1d, 0x76, 0x13, 0x30, 0xcf, 0x68, 0x0e, 0xfd, 0xeb, 0x1a, 0x42,
    0x15, 0x9e, 0xb3, 0x87, 0xd6, 0xd2, 0x95, 0x0c, 0x96, 0xf7, 0xd2, 0x8f, 0x61, 0xbb, 0xe2, 0xaa,
];
/// Some asset that is not AVAX
pub const OTHER_ASSET: [u8; 32] = [0x5c; 32];

/// Fuji X-chain id, 2JVSBoinj9C2J33VntvzYtVJNZdN2NKiwwKjcumHUWEb5DbBrm
pub const FUJI_X_CHAIN: [u8; 32] = [
    0xab, 0x68, 0xeb, 0x1e, 0xe1, 0x42, 0xa0, 0x5c, 0xfe, 0x76, 0x8c, 0x36, 0xe1, 0x1f, 0x0b, 0x59,
    0x6d, 0xb5, 0xa3, 0xc6, 0xc7, 0x7a, 0xab, 0xe6, 0x65, 0xda, 0xd9, 0xe6, 0x38, 0xca, 0x94, 0xf7,
];
pub const P_CHAIN: [u8; 32] = [0; 32];

pub const RECIPIENT: [u8; 20] = [0x63; 20];
pub const CHANGE: [u8; 20] = [0x07; 20];
pub const ATTACKER: [u8; 20] = [0xa5; 20];
pub const NODE_ID: [u8; 20] = [0xe9; 20];

/// secp256k1fx.TransferOutput
pub fn secp_out(amount: u64, locktime: u64, threshold: u32, addrs: &[[u8; 20]]) -> Vec<u8> {
    let mut v = 7u32.to_be_bytes().to_vec();
    v.extend(amount.to_be_bytes());
    v.extend(locktime.to_be_bytes());
    v.extend(threshold.to_be_bytes());
    v.extend((addrs.len() as u32).to_be_bytes());
    for a in addrs {
        v.extend(a);
    }
    v
}

/// secp256k1fx.OutputOwners
pub fn owners(locktime: u64, threshold: u32, addrs: &[[u8; 20]]) -> Vec<u8> {
    let mut v = 0x0bu32.to_be_bytes().to_vec();
    v.extend(locktime.to_be_bytes());
    v.extend(threshold.to_be_bytes());
    v.extend((addrs.len() as u32).to_be_bytes());
    for a in addrs {
        v.extend(a);
    }
    v
}

/// stakeable.LockOut wrapping `inner`
pub fn stakeable_locked(locktime: u64, inner: Vec<u8>) -> Vec<u8> {
    let mut v = 0x16u32.to_be_bytes().to_vec();
    v.extend(locktime.to_be_bytes());
    v.extend(inner);
    v
}

/// avax.TransferableOutput
pub fn transferable(asset: &[u8; 32], inner: Vec<u8>) -> Vec<u8> {
    let mut v = asset.to_vec();
    v.extend(inner);
    v
}

/// A plain one-address AVAX output
pub fn out(amount: u64, addr: [u8; 20]) -> Vec<u8> {
    transferable(&FUJI_AVAX, secp_out(amount, 0, 1, &[addr]))
}

/// avax.TransferableInput spending `amount` of `asset`
pub fn input(txid: u8, asset: &[u8; 32], amount: u64) -> Vec<u8> {
    let mut v = vec![txid; 32];
    v.extend(0u32.to_be_bytes());
    v.extend(asset);
    v.extend(5u32.to_be_bytes());
    v.extend(amount.to_be_bytes());
    v.extend(1u32.to_be_bytes());
    v.extend(0u32.to_be_bytes());
    v
}

pub fn list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut v = (items.len() as u32).to_be_bytes().to_vec();
    for i in items {
        v.extend(i);
    }
    v
}

/// codec, type id, network id and blockchain id
pub fn header(type_id: u32, network: u32, chain: &[u8; 32]) -> Vec<u8> {
    let mut v = vec![0u8, 0];
    v.extend(type_id.to_be_bytes());
    v.extend(network.to_be_bytes());
    v.extend(chain);
    v
}

/// outputs, inputs and an empty memo
pub fn base_fields(outs: &[Vec<u8>], ins: &[Vec<u8>]) -> Vec<u8> {
    let mut v = list(outs);
    v.extend(list(ins));
    v.extend(0u32.to_be_bytes());
    v
}

/// X-chain BaseTx on Fuji
pub fn x_transfer(outs: &[Vec<u8>], ins: &[Vec<u8>]) -> Vec<u8> {
    let mut v = header(0, FUJI, &FUJI_X_CHAIN);
    v.extend(base_fields(outs, ins));
    v
}

/// P-chain BaseTx on Fuji
pub fn p_base(outs: &[Vec<u8>], ins: &[Vec<u8>]) -> Vec<u8> {
    let mut v = header(0x22, FUJI, &P_CHAIN);
    v.extend(base_fields(outs, ins));
    v
}

/// P-chain AddDelegatorTx on Fuji
pub fn add_delegator(
    outs: &[Vec<u8>],
    ins: &[Vec<u8>],
    stake: &[Vec<u8>],
    rewards_owner: Vec<u8>,
) -> Vec<u8> {
    let weight = stake_amount(stake);
    let mut v = header(0x0e, FUJI, &P_CHAIN);
    v.extend(base_fields(outs, ins));
    v.extend(NODE_ID);
    v.extend(1_600_000_000u64.to_be_bytes());
    v.extend(1_602_000_000u64.to_be_bytes());
    v.extend(weight.to_be_bytes());
    v.extend(list(stake));
    v.extend(rewards_owner);
    v
}

/// Sum of the amounts of stake outputs built with the helpers above
fn stake_amount(stake: &[Vec<u8>]) -> u64 {
    stake
        .iter()
        .map(|o| {
            // asset id, then an optional stakeable.LockOut, then type id 7
            let mut rest = &o[32..];
            if rest[..4] == 0x16u32.to_be_bytes() {
                rest = &rest[12..];
            }
            u64::from_be_bytes(rest[4..12].try_into().unwrap())
        })
        .sum()
}

/// Every counted item of `item`, all pages joined, as "title: message".
/// Stops at the first NUL like the C UI does, so a hidden tail shows up as
/// missing text rather than as an error.
pub fn render_all<T: DisplayableItem>(item: &T) -> Vec<String> {
    let n = item.num_items().expect("num_items");
    let mut screens = Vec::with_capacity(n as usize);
    for i in 0..n {
        let mut title = [0u8; 18];
        let mut message = [0u8; 1024];
        let pages = item
            .render_item(i, &mut title, &mut message, 0)
            .unwrap_or_else(|e| panic!("item {} failed to render: {:?}", i, e));

        let mut text = String::new();
        for page in 0..pages {
            title.fill(0);
            message.fill(0);
            item.render_item(i, &mut title, &mut message, page)
                .expect("page renders");
            let end = message.iter().position(|&b| b == 0).unwrap_or(message.len());
            text.push_str(&String::from_utf8_lossy(&message[..end]));
        }
        let end = title.iter().position(|&b| b == 0).unwrap_or(title.len());
        screens.push(format!("{}: {}", String::from_utf8_lossy(&title[..end]), text));
    }
    screens
}

/// Parse `data` as a transaction, apply the change filter for `change` if
/// given, and render every screen.
pub fn screens(data: &[u8], change: Option<[u8; 20]>) -> Vec<String> {
    let mut tx = Transaction::new(data).expect("transaction parses");
    if let Some(change) = change {
        tx.disable_output_if(&change);
    }
    render_all(&tx)
}
