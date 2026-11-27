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

use crate::{
    constants::MAX_BIP32_PATH_DEPTH, handlers::avax::sign_hash::Sign, parser::ParserError, ZxError,
};

#[no_mangle]
pub unsafe extern "C" fn _get_hash(out: *mut u8, len: u16) -> u16 {
    if out.is_null() || len != Sign::SIGN_HASH_SIZE as u16 {
        return ZxError::BufferTooSmall as _;
    }

    let output = core::slice::from_raw_parts_mut(out, len as _);

    // Only a hash the user approved may be signed. The sign-hash flow stores
    // the requested hash before its review is answered.
    let Ok(hash) = Sign::get_approved_hash() else {
        return ZxError::NoData as _;
    };

    output.copy_from_slice(&hash[..]);

    ZxError::Ok as _
}

/// Called from the sign-hash review's approve callback: the hash stored by
/// `_parse_sign_hash_tx` becomes signable.
#[no_mangle]
pub unsafe extern "C" fn _approve_sign_hash() -> u16 {
    if Sign::get_hash().is_err() {
        return ZxError::NoData as _;
    }
    crate::handlers::avax::sign_hash::mark_hash_approved();
    ZxError::Ok as _
}

#[no_mangle]
pub unsafe extern "C" fn _get_signing_info(
    out: *mut u32,
    len: u16,
    input: *const u8,
    in_len: u16,
) -> u16 {
    if out.is_null() || len > MAX_BIP32_PATH_DEPTH as u16 || input.is_null() {
        return ZxError::BufferTooSmall as _;
    }

    let raw_path_suffix = core::slice::from_raw_parts(input, in_len as _);

    // our output path, the one to use for signing this hash
    let output = core::slice::from_raw_parts_mut(out, len as _);

    let Ok(path) = Sign::get_signing_info(raw_path_suffix) else {
        return ZxError::NoData as _;
    };

    let components = path.components();

    output[..components.len()].copy_from_slice(components);

    ZxError::Ok as _
}

#[no_mangle]
pub unsafe extern "C" fn _clean_up_hash() {
    _ = crate::handlers::avax::sign_hash::cleanup_globals();
}

/// Release the ETH signing globals, including the streaming hash and the flag
/// that selects the blind-signing review.
///
/// The Rust `reject` for the ETH flow already does this, but nothing on the C
/// side calls it: a refused review goes through `app_reject`, which returns to
/// the host without telling the Rust handler. That left the streaming state
/// set, so the next ETH review rendered the previous hash while signing the
/// new transaction -- the same shape as the sign-hash leak, on the other
/// handler.
#[no_mangle]
pub unsafe extern "C" fn _clean_up_eth() {
    _ = crate::handlers::eth::signing::cleanup_globals();

    // and the refused review itself
    crate::lock_mut!(crate::handlers::resources::ETH_UI)
        .lock(crate::handlers::resources::EthAccessors::Tx)
        .take();
}

#[no_mangle]
pub unsafe extern "C" fn _parse_sign_hash_tx(input: *const u8, len: u16) -> u32 {
    let data = core::slice::from_raw_parts(input, len as _);
    if let Err(e) = Sign::parse_hash(data) {
        // This is the device's FIRST_MESSAGE path. A request that fails to
        // parse starts no session, and must not leave an earlier one live.
        _ = crate::handlers::avax::sign_hash::cleanup_globals();
        return e as _;
    }
    ParserError::ParserOk as _
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use serial_test::file_serial;

    use super::*;

    /// m/44'/9000'/0' followed by `hash`, as INS_SIGN_HASH FIRST_MESSAGE sends it
    fn sign_hash_request(hash: &[u8; 32]) -> Vec<u8> {
        let mut data = std::vec![3u8];
        for c in [0x8000_002c_u32, 0x8000_2328, 0x8000_0000] {
            data.extend_from_slice(&c.to_be_bytes());
        }
        data.extend_from_slice(hash);
        data
    }

    fn get_hash() -> (u16, [u8; 32]) {
        let mut out = [0u8; 32];
        let err = unsafe { _get_hash(out.as_mut_ptr(), out.len() as u16) };
        (err, out)
    }

    #[test]
    // PATH and HASH are shared with the other ffi tests
    #[cfg_attr(not(miri), file_serial(path))]
    fn a_parsed_hash_is_not_signable_until_approved() {
        unsafe { _clean_up_hash() };
        let hash = [0x42u8; 32];
        let data = sign_hash_request(&hash);

        let err = unsafe { _parse_sign_hash_tx(data.as_ptr(), data.len() as u16) };
        assert_eq!(err, ParserError::ParserOk as u32);

        // the review is still on screen: a suffix request must not get the hash
        assert_eq!(get_hash().0, ZxError::NoData as u16);

        assert_eq!(unsafe { _approve_sign_hash() }, ZxError::Ok as u16);
        assert_eq!(get_hash(), (ZxError::Ok as u16, hash));

        // a new request withdraws the approval of the previous one
        let other = sign_hash_request(&[0x24u8; 32]);
        let err = unsafe { _parse_sign_hash_tx(other.as_ptr(), other.len() as u16) };
        assert_eq!(err, ParserError::ParserOk as u32);
        assert_eq!(get_hash().0, ZxError::NoData as u16);

        // and cleanup (reject, LAST_MESSAGE, errors) does too
        assert_eq!(unsafe { _approve_sign_hash() }, ZxError::Ok as u16);
        unsafe { _clean_up_hash() };
        assert_eq!(get_hash().0, ZxError::NoData as u16);
        assert_eq!(unsafe { _approve_sign_hash() }, ZxError::NoData as u16);
    }
}
