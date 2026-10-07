/*******************************************************************************
*   (c) 2026 Zondax AG
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

use bolos::{
    hash::{Hasher, Keccak},
    pic_str, PIC,
};
use zemu_sys::ViewError;

use crate::{handlers::handle_ui_message, parser::ParserError, utils::hex_encode};

const HASH_LEN: usize = Keccak::<32>::DIGEST_LEN;

/// Transaction data the app cannot decode (contract bytecode, or the
/// arguments of a call it has no parser for), reviewed by its length and its
/// keccak-256 hash.
///
/// Signing such data is blind signing: the user cannot read it on the
/// device, but can check that the length and the hash match the data the
/// dApp or wallet says it sends. The hash covers every byte, so two payloads
/// that differ anywhere (not just in their first bytes) show different
/// hashes.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "derive-debug"), derive(Debug))]
pub struct OpaqueData<'b> {
    data: &'b [u8],
    /// keccak-256 of `data`, computed once at parse time rather than on
    /// every page the review renders
    hash: [u8; HASH_LEN],
}

impl<'b> OpaqueData<'b> {
    /// Data Length and Data Hash
    pub const NUM_ITEMS: u8 = 2;

    #[inline(never)]
    pub fn parse_into(data: &'b [u8], output: &mut MaybeUninit<Self>) -> Result<(), ParserError> {
        crate::sys::zemu_log_stack("OpaqueData::parse_into\x00");
        let out = output.as_mut_ptr();

        // safe writes: the hash is zeroed before a reference to it is taken
        let hash = unsafe {
            addr_of_mut!((*out).hash).write([0; HASH_LEN]);
            &mut *addr_of_mut!((*out).hash)
        };
        Keccak::<32>::digest_into(data, hash).map_err(|_| ParserError::UnexpectedError)?;

        unsafe {
            addr_of_mut!((*out).data).write(data);
        }

        Ok(())
    }

    pub fn data(&self) -> &'b [u8] {
        self.data
    }

    pub fn hash(&self) -> &[u8; HASH_LEN] {
        &self.hash
    }

    /// Render "Data Length" (item 0) or "Data Hash" (item 1)
    #[inline(never)]
    pub fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        match item_n {
            0 => {
                let label = pic_str!(b"Data Length");
                title[..label.len()].copy_from_slice(label);

                let suffix = pic_str!(b" bytes");
                let mut itoa_buffer = itoa::Buffer::new();
                let len = itoa_buffer.format(self.data.len()).as_bytes();

                let mut out = [0; 20 + 6];
                let sz = len.len() + suffix.len();
                out[..len.len()].copy_from_slice(len);
                out[len.len()..sz].copy_from_slice(suffix);

                handle_ui_message(&out[..sz], message, page)
            }
            1 => {
                let label = pic_str!(b"Data Hash");
                title[..label.len()].copy_from_slice(label);

                render_0x_hex(&self.hash, message, page)
            }
            _ => Err(ViewError::NoData),
        }
    }
}

/// Render up to [`HASH_LEN`] bytes as a `0x`-prefixed hex string, paginated
pub fn render_0x_hex(bytes: &[u8], message: &mut [u8], page: u8) -> Result<u8, ViewError> {
    let prefix = pic_str!(b"0x"!);
    let mut out = [0; 2 + HASH_LEN * 2];
    out[..prefix.len()].copy_from_slice(&prefix[..]);

    let sz = hex_encode(bytes, &mut out[prefix.len()..]).map_err(|_| ViewError::Unknown)?;

    handle_ui_message(&out[..prefix.len() + sz], message, page)
}

#[cfg(test)]
mod tests {
    use std::prelude::v1::*;

    use super::*;

    fn parse(data: &[u8]) -> OpaqueData<'_> {
        let mut out = MaybeUninit::uninit();
        OpaqueData::parse_into(data, &mut out).unwrap();
        unsafe { out.assume_init() }
    }

    fn render(data: &OpaqueData, item_n: u8) -> (String, String) {
        let mut title = [0u8; 32];
        let mut message = [0u8; 128];
        data.render_item(item_n, &mut title, &mut message, 0)
            .unwrap();
        let s = |b: &[u8]| {
            let n = b.iter().position(|c| *c == 0).unwrap();
            String::from_utf8(b[..n].to_vec()).unwrap()
        };
        (s(&title), s(&message))
    }

    #[test]
    fn renders_length_and_keccak256() {
        // keccak-256 of the empty string and of "abc"
        let cases: [(&[u8], &str, &str); 2] = [
            (
                b"",
                "0 bytes",
                "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            ),
            (
                b"abc",
                "3 bytes",
                "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
            ),
        ];
        for (data, len, hash) in cases {
            let d = parse(data);
            assert_eq!(d.data(), data);
            assert_eq!(render(&d, 0), ("Data Length".into(), len.into()));
            assert_eq!(render(&d, 1), ("Data Hash".into(), hash.into()));
        }

        let mut title = [0u8; 32];
        let mut message = [0u8; 128];
        assert_eq!(
            parse(b"abc").render_item(OpaqueData::NUM_ITEMS, &mut title, &mut message, 0),
            Err(ViewError::NoData)
        );
    }

    // The hash covers every byte: a change at the very end of the data
    // changes the screen.
    #[test]
    fn hash_covers_every_byte() {
        let a = std::vec![0x11u8; 16 * 1024];
        let mut b = a.clone();
        *b.last_mut().unwrap() ^= 1;

        assert_eq!(render(&parse(&a), 0), render(&parse(&b), 0));
        assert_ne!(render(&parse(&a), 1), render(&parse(&b), 1));
        assert_eq!(render(&parse(&a), 0).1, "16384 bytes");
    }

    // On a small screen the hash is split over pages that put back together
    // give the whole hash.
    #[test]
    fn hash_paginates() {
        let d = parse(b"abc");
        let mut title = [0u8; 32];
        let mut pages = String::new();
        let mut page = 0;
        loop {
            let mut message = [0u8; 18];
            let n = d.render_item(1, &mut title, &mut message, page).unwrap();
            let len = message.iter().position(|c| *c == 0).unwrap();
            pages.push_str(core::str::from_utf8(&message[..len]).unwrap());
            page += 1;
            if page == n {
                break;
            }
        }
        assert_eq!(page, 4);
        assert_eq!(pages, render(&d, 1).1);
    }
}
