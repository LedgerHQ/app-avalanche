/*******************************************************************************
*   (c) 2024 Zondax AG
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

use core::mem::{size_of, MaybeUninit};

use crate::constants::{BIP32_PATH_SUFFIX_DEPTH, SIGN_HASH_TX_SIZE};
use crate::handlers::avax::sign_hash::{Sign as SignHash, SignUI};
use crate::handlers::avax::signing::Sign;
use crate::parser::{parse_path_list, AvaxMessage, DisplayableItem, ObjectList, PathWrapper};
use crate::parser::{FromBytes, ParserError, Transaction};
use crate::ZxError;

pub mod context;
mod eth_tx;
pub mod ext_public_key;
pub mod nft_info;
pub mod public_key;
pub mod sign_hash;
pub mod wallet_id;
use context::{parser_context_t, Instruction};
use eth_tx::{get_eth_item, num_items_eth};

/// Size of `parser_buffer` in app/src/parser.c, the buffer C allocates and
/// hands over as `tx_obj.state`.
const PARSER_BUFFER_SIZE: usize = 256;

// Checked on the device only: pointers are 8 bytes on the host, where
// `Transaction` is larger and tests provide their own state buffer.
#[cfg(target_pointer_width = "32")]
const _: () = assert!(
    size_of::<Transaction>() <= PARSER_BUFFER_SIZE
        && size_of::<AvaxMessage>() <= PARSER_BUFFER_SIZE
);

/// Returns the buffer `tx_obj.state` points to as a `T`, provided it is not
/// null and is large enough and aligned for a `T`.
///
/// # Safety
///
/// `ctx` must be valid, and a non-null `tx_obj.state` must point to
/// `tx_obj.len` writable bytes that nothing else references.
unsafe fn state_as<'a, T>(
    ctx: *const parser_context_t,
) -> Result<&'a mut MaybeUninit<T>, ParserError> {
    let state = (*ctx).tx_obj.state;

    if state.is_null() {
        return Err(ParserError::NoData);
    }

    if ((*ctx).tx_obj.len as usize) < size_of::<T>() || !state.cast::<T>().is_aligned() {
        return Err(ParserError::ParserContextMismatch);
    }

    Ok(&mut *state.cast::<MaybeUninit<T>>())
}

// Innitialize internals for transaction processing
#[no_mangle]
pub unsafe extern "C" fn _parser_init(
    ctx: *mut parser_context_t,
    buffer: *const u8,
    len: usize,
    alloc_size: *mut u32,
) -> u32 {
    if ctx.is_null() || alloc_size.is_null() {
        return ParserError::ParserInitContextEmpty as u32;
    }

    let tx_type = (*ctx).ins;

    let Ok(ins) = Instruction::try_from(tx_type) else {
        return ParserError::InvalidTransactionType as u32;
    };

    // Lets the caller know how much memory we need for allocating
    // our global state
    let size = match ins {
        Instruction::SignAvaxTx => core::mem::size_of::<MaybeUninit<Transaction>>() as u32,
        // Instruction::SignEthTx => core::mem::size_of::<MaybeUninit<EthTransaction>>() as u32,
        Instruction::SignAvaxMsg => core::mem::size_of::<MaybeUninit<AvaxMessage>>() as u32,
        // Instruction::SignEthMsg => core::mem::size_of::<MaybeUninit<PersonalMsg>>() as u32,
        Instruction::SignAvaxHash => SIGN_HASH_TX_SIZE as u32,
        // Ingnore eth transactions as they would be handled by
        // either the app-ethereum application or full rust handler.
        _ => return ParserError::InvalidTransactionType as u32,
    };

    *alloc_size = size;

    parser_init_context(ctx, buffer, len) as u32
}

/// #Safety
/// Called after zb_allocate assign memory
/// to store the Transaction. This memory outlives
/// the parsed and is deallocated before signing
/// at such point the rust-parser is not used anymore
unsafe fn parser_init_context(
    ctx: *mut parser_context_t,
    buffer: *const u8,
    len: usize,
) -> ParserError {
    (*ctx).offset = 0;

    if len == 0 || buffer.is_null() {
        (*ctx).buffer = core::ptr::null_mut();
        (*ctx).buffer_len = 0;
        return ParserError::ParserInitContextEmpty;
    }

    (*ctx).buffer = buffer;
    // we are sure that len is less than u16::MAX
    (*ctx).buffer_len = len as u16;

    ParserError::ParserOk
}

/// Parses the transaction data from the provided context.
///
/// It interprets the transaction data based on the instruction type specified in the context
/// and performs the corresponding parsing operation.
///
/// # Safety
///
/// This function is unsafe because it performs raw pointer dereferencing and assumes the provided context pointer is valid.
/// The caller must ensure the context is properly initialized and that the memory pointed to remains valid for the duration of the function call.
///
/// # Arguments
///
/// * `ctx` - A pointer to the `parser_context_t` structure that contains the buffer and instruction type.
///
/// # Returns
///
/// Returns a `u32` indicating the result of the parse operation. The return value corresponds to values from the `ParserError` enum,
/// encoded as `u32`.
///
/// # Errors
///
/// Returns an error if:
/// * The context pointer is null.
/// * The instruction type is invalid or unsupported.
/// * Parsing the transaction type or specific transaction components fails.
#[no_mangle]
pub unsafe extern "C" fn _parser_read(ctx: *const parser_context_t) -> u32 {
    if ctx.is_null() {
        return ParserError::ParserContextMismatch as u32;
    };

    let data = core::slice::from_raw_parts((*ctx).buffer, (*ctx).buffer_len as _);

    let Ok(tx_type) = Instruction::try_from((*ctx).ins) else {
        return ParserError::InvalidTransactionType as u32;
    };

    match tx_type {
        Instruction::SignAvaxTx => {
            // then, get the change_path list.
            let mut path_list: MaybeUninit<ObjectList<PathWrapper<BIP32_PATH_SUFFIX_DEPTH>>> =
                MaybeUninit::uninit();

            let Ok(rem) = parse_path_list(&mut path_list, data) else {
                return ParserError::InvalidPath as u32;
            };

            let mut path_list = path_list.assume_init();

            let tx = match state_as::<Transaction>(ctx) {
                Ok(tx) => tx,
                Err(e) => return e as u32,
            };
            match Transaction::new_into(rem, tx) {
                Ok(_) => {
                    // now disable transaction outputs that match
                    // the change paths
                    let tx = tx.assume_init_mut();
                    // important to use the handlers::avax::signing::Sign module
                    let Ok(_) = Sign::disable_outputs(&mut path_list, tx) else {
                        return ParserError::InvalidPath as u32;
                    };

                    ParserError::ParserOk as u32
                }
                Err(e) => e as u32,
            }
        }

        Instruction::SignAvaxHash => {
            if let Err(e) = SignHash::parse_hash(data) {
                return e as u32;
            }
            ParserError::ParserOk as u32
        }

        Instruction::SignAvaxMsg => {
            let tx = match state_as::<AvaxMessage>(ctx) {
                Ok(tx) => tx,
                Err(e) => return e as u32,
            };
            match AvaxMessage::from_bytes_into(data, tx) {
                Ok(_) => ParserError::ParserOk as u32,
                Err(_) => ParserError::InvalidAvaxMessage as u32,
            }
        }
        // Ingnore eth transactions as they would be handled by
        // the app-ethereum application.
        _ => ParserError::InvalidTransactionType as u32,
    }
}

#[no_mangle]
pub unsafe extern "C" fn _getNumItems(ctx: *const parser_context_t, num_items: *mut u8) -> u32 {
    if num_items.is_null() || ctx.is_null() {
        return ParserError::NoData as u32;
    }

    let Ok(tx_type) = Instruction::try_from((*ctx).ins) else {
        return ParserError::InvalidTransactionType as u32;
    };

    let num_items = &mut *num_items;

    if tx_type.is_avax() {
        num_items_avax(ctx, num_items)
    } else {
        num_items_eth(ctx, num_items)
    }
}

#[inline(never)]
unsafe fn num_items_avax(ctx: *const parser_context_t, num_items: &mut u8) -> u32 {
    let Ok(tx_type) = Instruction::try_from((*ctx).ins) else {
        return ParserError::InvalidTransactionType as u32;
    };

    match tx_type {
        Instruction::SignAvaxTx => {
            let tx = match state_as::<Transaction>(ctx) {
                Ok(tx) => tx,
                Err(e) => return e as u32,
            };
            let obj = tx.assume_init_mut();
            match obj.num_items() {
                Ok(n) => {
                    *num_items = n;
                    ParserError::ParserOk as u32
                }
                Err(e) => e as u32,
            }
        }

        Instruction::SignAvaxHash => {
            *num_items = 1;
            ParserError::ParserOk as u32
        }

        Instruction::SignAvaxMsg => {
            *num_items = 1;
            ParserError::ParserOk as u32
        }
        _ => ParserError::InvalidTransactionType as u32,
    };

    ParserError::ParserOk as u32
}

#[no_mangle]
pub unsafe extern "C" fn _getItem(
    ctx: *const parser_context_t,
    display_idx: u8,
    out_key: *mut i8,
    key_len: u16,
    out_value: *mut i8,
    out_len: u16,
    page_idx: u8,
    page_count: *mut u8,
) -> u32 {
    *page_count = 0u8;

    let page_count = &mut *page_count;

    let key = core::slice::from_raw_parts_mut(out_key as *mut u8, key_len as usize);
    let value = core::slice::from_raw_parts_mut(out_value as *mut u8, out_len as usize);

    if ctx.is_null() {
        return ParserError::ParserContextMismatch as _;
    }

    let Ok(tx_type) = Instruction::try_from((*ctx).ins) else {
        return ParserError::InvalidTransactionType as u32;
    };

    if tx_type.is_avax() {
        get_avax_item(ctx, display_idx, key, value, page_idx, page_count)
    } else {
        get_eth_item(ctx, display_idx, key, value, page_idx, page_count)
    }
}

#[inline(never)]
unsafe fn get_avax_item(
    ctx: *const parser_context_t,
    display_idx: u8,
    key: &mut [u8],
    value: &mut [u8],
    page_idx: u8,
    page_count: &mut u8,
) -> u32 {
    *page_count = 0u8;

    let page_count = &mut *page_count;

    if ctx.is_null() {
        return ParserError::ParserContextMismatch as _;
    }

    let Ok(tx_type) = Instruction::try_from((*ctx).ins) else {
        return ParserError::InvalidTransactionType as u32;
    };

    match tx_type {
        Instruction::SignAvaxTx => {
            let tx = match state_as::<Transaction>(ctx) {
                Ok(tx) => tx,
                Err(e) => return e as u32,
            };
            let obj = tx.assume_init_mut();
            match obj.render_item(display_idx, key, value, page_idx) {
                Ok(page) => {
                    *page_count = page;
                    ParserError::ParserOk as _
                }
                Err(e) => e as _,
            }
        }

        Instruction::SignAvaxHash => {
            let state = (*ctx).tx_obj.state;

            if state.is_null() {
                return ParserError::NoData as u32;
            }

            let Ok(hash) = SignHash::get_hash() else {
                return ParserError::NoData as _;
            };
            let mut ui = SignUI::new(*hash);
            match zemu_sys::Viewable::render_item(&mut ui, display_idx, key, value, page_idx) {
                Ok(page) => {
                    *page_count = page;
                    ParserError::ParserOk as _
                }
                Err(e) => e as _,
            }
        }

        Instruction::SignAvaxMsg => {
            let msg = match state_as::<AvaxMessage>(ctx) {
                Ok(msg) => msg,
                Err(e) => return e as u32,
            };
            let obj = msg.assume_init_mut();
            match obj.render_item(display_idx, key, value, page_idx) {
                Ok(page) => {
                    *page_count = page;
                    ParserError::ParserOk as _
                }
                Err(e) => e as _,
            }
        }
        _ => ParserError::NoData as _,
    }
}

// Returns the offset at which transaction data starts.
// remember that this instruction comes with a list of change_path at the
// begining of the buffer. those paths needs to be ignored when
// computing transaction hash for signing.
// this is useful for avax transactions that takes a list of change paths.
#[no_mangle]
pub unsafe extern "C" fn _tx_data_offset(
    buffer: *const u8,
    buffer_len: u16,
    offset: *mut u16,
) -> u16 {
    if buffer.is_null() || offset.is_null() || buffer_len == 0 {
        return ZxError::NoData as _;
    }

    let data = core::slice::from_raw_parts(buffer, buffer_len as _);

    let mut path_list: MaybeUninit<ObjectList<PathWrapper<BIP32_PATH_SUFFIX_DEPTH>>> =
        MaybeUninit::uninit();

    let Ok(rem) = parse_path_list(&mut path_list, data) else {
        return ZxError::NoData as _;
    };

    if buffer_len < rem.len() as u16 {
        return ZxError::BufferTooSmall as _;
    }

    *offset = buffer_len - rem.len() as u16;

    ZxError::Ok as _
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use serial_test::file_serial;

    use super::context::{_set_root_path, parse_tx_t};
    use super::*;

    // Transfer transaction, same bytes as parser::transactions::tests::DATA
    const TRANSFER_TX: &str = "00000000000000000005ab68eb1ee142a05cfe768c36e11f0b596db5a3c6c77aabe665dad9e638ca94f7000000023d9bdac0ed1d761330cf680efdeb1a42159eb387d6d2950c96f7d28f61bbe2aa00000007000000003b9aca0000000000000000000000000100000001636fb961b8bce4d0038796f5db330fecc8e36f723d9bdac0ed1d761330cf680efdeb1a42159eb387d6d2950c96f7d28f61bbe2aa0000000700000000f44284800000000000000000000000010000000107fe53d8ed2b004df3ac75175a4e727a6dd461d8000000023be4ead93aa5e6396d1f2c6e9587c7642b30d52d605f917d8a402e6823f965f2000000003d9bdac0ed1d761330cf680efdeb1a42159eb387d6d2950c96f7d28f61bbe2aa000000050000000005e69ec0000000010000000095aff4ba72647c2a6a41802c047a9f3a3919b35aefcf7da843d4cc34980c7102000000003d9bdac0ed1d761330cf680efdeb1a42159eb387d6d2950c96f7d28f61bbe2aa00000005000000012a05f200000000010000000000000000";

    const CANARY: u8 = 0xAA;
    const STATE_SIZE: usize = 512;

    /// The C `parser_context_t` followed by a canary, so a write that lands
    /// on the context instead of the buffer `tx_obj.state` points to shows up.
    #[repr(C)]
    struct GuardedCtx {
        ctx: parser_context_t,
        canary: [u8; STATE_SIZE],
    }

    /// Stands in for `parser_buffer`, sized for the host `Transaction`.
    #[repr(C, align(8))]
    struct StateBuffer([u8; STATE_SIZE]);

    impl GuardedCtx {
        fn new(ins: Instruction, data: &[u8], state: &mut StateBuffer, len: usize) -> Self {
            Self {
                ctx: parser_context_t {
                    buffer: data.as_ptr(),
                    buffer_len: data.len() as u16,
                    offset: 0,
                    ins: ins as u8,
                    tx_obj: parse_tx_t {
                        state: state.0.as_mut_ptr(),
                        len: len as u32,
                    },
                },
                canary: [CANARY; STATE_SIZE],
            }
        }
    }

    fn set_avax_root_path() {
        // m/44'/9000'/0'
        let mut path = std::vec![3u8];
        for c in [0x8000_002c_u32, 0x8000_2328, 0x8000_0000] {
            path.extend_from_slice(&c.to_be_bytes());
        }
        let err = unsafe { _set_root_path(path.as_ptr(), path.len() as u16) };
        assert_eq!(err, ParserError::ParserOk as u32);
    }

    fn avax_tx_data() -> Vec<u8> {
        // no change paths, then the transaction
        let mut data = std::vec![0u8];
        data.extend(hex::decode(TRANSFER_TX).unwrap());
        data
    }

    fn avax_msg_data() -> Vec<u8> {
        let msg = b"Hello, Avalanche";
        let mut data = b"\x1AAvalanche Signed Message:\n".to_vec();
        data.extend_from_slice(&(msg.len() as u32).to_be_bytes());
        data.extend_from_slice(msg);
        data
    }

    /// Renders every item, as `parser_validate` does.
    fn render_all(ctx: *const parser_context_t) {
        let mut num_items = 0u8;
        assert_eq!(
            unsafe { _getNumItems(ctx, &mut num_items) },
            ParserError::ParserOk as u32
        );
        assert!(num_items > 0);

        let mut key = [0i8; 40];
        let mut value = [0i8; 40];
        for idx in 0..num_items {
            let mut page_count = 0u8;
            let err = unsafe {
                _getItem(
                    ctx,
                    idx,
                    key.as_mut_ptr(),
                    key.len() as u16,
                    value.as_mut_ptr(),
                    value.len() as u16,
                    0,
                    &mut page_count,
                )
            };
            assert_eq!(err, ParserError::ParserOk as u32, "item {idx}");
            assert!(page_count > 0, "item {idx}");
        }
    }

    fn assert_parsed_into_state(ins: Instruction, data: &[u8], len: usize) {
        let mut state = StateBuffer([0; STATE_SIZE]);
        let state_ptr = state.0.as_mut_ptr();
        let mut guarded = GuardedCtx::new(ins, data, &mut state, len);
        let ctx: *mut parser_context_t = &mut guarded.ctx;

        assert_eq!(unsafe { _parser_read(ctx) }, ParserError::ParserOk as u32);

        // the context and whatever follows it are untouched
        assert_eq!(guarded.ctx.tx_obj.state, state_ptr);
        assert_eq!(guarded.ctx.tx_obj.len, len as u32);
        assert!(guarded.canary.iter().all(|b| *b == CANARY));

        render_all(ctx);

        // the object was written into the state buffer
        assert!(state.0[..len].iter().any(|b| *b != 0));
    }

    #[test]
    #[cfg_attr(not(miri), file_serial(path))]
    fn avax_tx_is_parsed_into_state_buffer() {
        set_avax_root_path();
        assert_parsed_into_state(
            Instruction::SignAvaxTx,
            &avax_tx_data(),
            size_of::<Transaction>(),
        );
    }

    #[test]
    fn avax_msg_is_parsed_into_state_buffer() {
        assert_parsed_into_state(
            Instruction::SignAvaxMsg,
            &avax_msg_data(),
            size_of::<AvaxMessage>(),
        );
    }

    #[test]
    fn state_buffer_is_checked() {
        let data = avax_msg_data();
        let len = size_of::<AvaxMessage>();

        // too small
        let mut state = StateBuffer([0; STATE_SIZE]);
        let mut guarded = GuardedCtx::new(Instruction::SignAvaxMsg, &data, &mut state, len - 1);
        assert_eq!(
            unsafe { _parser_read(&guarded.ctx) },
            ParserError::ParserContextMismatch as u32
        );

        // misaligned
        guarded.ctx.tx_obj.state = unsafe { state.0.as_mut_ptr().add(1) };
        guarded.ctx.tx_obj.len = len as u32;
        assert_eq!(
            unsafe { _parser_read(&guarded.ctx) },
            ParserError::ParserContextMismatch as u32
        );

        // not allocated
        guarded.ctx.tx_obj.state = core::ptr::null_mut();
        assert_eq!(
            unsafe { _parser_read(&guarded.ctx) },
            ParserError::NoData as u32
        );
    }
}
