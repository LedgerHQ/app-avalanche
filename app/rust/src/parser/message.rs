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
    number::complete::be_u32,
};
use zemu_sys::ViewError;

use crate::{
    handlers::handle_ui_message,
    parser::{error::ParserError, DisplayableItem, FromBytes},
    utils::ApduPanic,
    zlog,
};
use bolos::{pic_str, PIC};

use super::MSG_MAX_CHUNK_LEN;

const HEX_REPR_LEN: usize = 4;

#[inline(never)]
fn u8_to_hex_array(value: u8) -> [u8; 4] {
    let mut result = *b"\\x00";

    let high_nibble = value >> 4;
    let low_nibble = value & 0x0F;

    result[2] = match high_nibble {
        0..=9 => b'0' + high_nibble,
        10..=15 => b'a' + (high_nibble - 10),
        _ => unreachable!(),
    };

    result[3] = match low_nibble {
        0..=9 => b'0' + low_nibble,
        10..=15 => b'a' + (low_nibble - 10),
        _ => unreachable!(),
    };

    result
}

/// Returns how `byte` is displayed and how many display characters that takes.
///
/// Only printable ASCII (0x20..=0x7E) is shown as is, and ASCII whitespace is
/// shown as a space. Every other byte is escaped as `\xNN`, so a NUL can not
/// end the displayed string early and control characters never reach the
/// screen raw.
#[inline(never)]
fn display_repr(byte: u8) -> ([u8; HEX_REPR_LEN], usize) {
    if byte.is_ascii_whitespace() {
        ([b' ', 0, 0, 0], 1)
    } else if (0x20..=0x7E).contains(&byte) {
        ([byte, 0, 0, 0], 1)
    } else {
        (u8_to_hex_array(byte), HEX_REPR_LEN)
    }
}

#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct Message<'b> {
    data: &'b [u8],
    chunk_count: u8,
}

impl Message<'_> {
    pub fn msg(&self) -> &[u8] {
        // wont panic as this check was done when parsing
        be_u32::<_, ParserError>(self.data)
            .map(|(msg, _)| msg)
            .apdu_unwrap()
    }

    /// Returns the number of bytes of `msg[start..]` that fit in one display
    /// chunk.
    ///
    /// This is the single place that decides where a chunk ends: counting,
    /// skipping to a chunk and rendering one all go through it, so they agree
    /// on every boundary. A byte whose display form does not fit in what is
    /// left of the chunk starts the next chunk instead of being dropped.
    fn chunk_span(msg: &[u8], start: usize) -> usize {
        let mut consumed = 0;
        let mut display_len = 0;

        for &byte in msg.iter().skip(start) {
            let (_, len) = display_repr(byte);
            if display_len + len > MSG_MAX_CHUNK_LEN {
                break;
            }
            display_len += len;
            consumed += 1;
        }

        consumed
    }

    fn get_chunk(&self, chunk_idx: usize, chunk: &mut [u8]) -> usize {
        if chunk.len() < MSG_MAX_CHUNK_LEN {
            return 0;
        }
        let msg = self.msg();

        // Skip the chunks before the requested one, using the same boundaries
        // `calculate_chunk_count` used to count them.
        let mut start = 0;
        for _ in 0..chunk_idx {
            let consumed = Self::chunk_span(msg, start);
            if consumed == 0 {
                return 0;
            }
            start += consumed;
        }

        // We must do the same as app-ethereum where, It has an auxiliary buffer where
        // data to be rendered is copied, this data is "modified" from the original
        // as follows:
        // 1. process the message character per character
        // 2. Printable ascii characters (0x20..=0x7E) are displayed as they are.
        // 3. Whitespace characters are displayed as a space
        // 4. every other byte, including NUL and the other control characters,
        // is displayed as a hex code: \x00 for example for the null character
        //
        // so we are going to do this for every current chunk of data
        // and for either eth PersonalMessage eip-191 or avax personal messages
        let consumed = Self::chunk_span(msg, start);
        let mut chunk_len = 0;
        for &byte in &msg[start..start + consumed] {
            let (repr, len) = display_repr(byte);
            chunk[chunk_len..chunk_len + len].copy_from_slice(&repr[..len]);
            chunk_len += len;
        }

        chunk_len
    }

    fn render_msg(&self, message: &mut [u8], item_n: u8, page: u8) -> Result<u8, ViewError> {
        let mut chunk = [0u8; MSG_MAX_CHUNK_LEN];
        let len = self.get_chunk(item_n as usize, &mut chunk);

        handle_ui_message(&chunk[..len], message, page)
    }

    pub fn is_ascii(&self) -> bool {
        self.data.iter().all(|c| c.is_ascii())
    }

    fn calculate_chunk_count(msg: &[u8]) -> Result<u8, ParserError> {
        let mut chunks = 0usize;
        let mut start = 0;
        while start < msg.len() {
            let consumed = Self::chunk_span(msg, start);
            // every byte's display form fits in an empty chunk, so this only
            // guards against looping forever
            if consumed == 0 {
                return Err(ParserError::InvalidMessageSize);
            }
            start += consumed;
            chunks += 1;
        }
        u8::try_from(chunks).map_err(|_| ParserError::InvalidMessageSize)
    }
}

impl<'b> FromBytes<'b> for Message<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<crate::parser::ParserError>> {
        zlog("Message::from_bytes_into\x00");

        if input.is_empty() {
            return Err(ParserError::InvalidEthMessage.into());
        }

        let (msg, len) = be_u32(input)?;

        if msg.len() != len as usize {
            return Err(ParserError::InvalidEthMessage.into());
        }

        let (rem, msg) = take(super::U32_SIZE + len as usize)(input)?;

        let out = out.as_mut_ptr();
        // omit the first 4-bytes which are use for the len
        let chunk_count = Self::calculate_chunk_count(&msg[4..])?;

        unsafe {
            addr_of_mut!((*out).data).write(msg);
            addr_of_mut!((*out).chunk_count).write(chunk_count);
        }

        Ok(rem)
    }
}

impl DisplayableItem for Message<'_> {
    fn num_items(&self) -> Result<u8, ViewError> {
        Ok(self.chunk_count)
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        zlog("Message::render_item\x00");
        let label = pic_str!(b"Message");
        title[..label.len()].copy_from_slice(label);
        self.render_msg(message, item_n, page)
    }
}

#[derive(Clone, PartialEq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct AvaxMessage<'b> {
    data: Message<'b>,
}

impl<'b> AvaxMessage<'b> {
    pub fn new(data: &'b [u8]) -> Result<Self, ParserError> {
        let mut this = MaybeUninit::uninit();
        let _ = Self::from_bytes_into(data, &mut this)?;
        Ok(unsafe { this.assume_init() })
    }

    pub fn msg(&self) -> &[u8] {
        self.data.msg()
    }

    /// Returns the len of the received message including the header
    pub fn msg_len(data: &'b [u8]) -> Result<u32, ParserError> {
        let mut uninit = MaybeUninit::uninit();
        let rem = Self::from_bytes_into(data, &mut uninit)?;
        Ok((data.len() - rem.len()) as u32)
    }
}

impl<'b> FromBytes<'b> for AvaxMessage<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        // Avax message structure: Header + 4-byte msg_len + msg
        // according to:
        // https://docs.avax.network/community/tutorials-contest/2021/red-dev-sig-verify-tutorial#1-hash-the-message
        let header = pic_str!(b"\x1AAvalanche Signed Message:\n"!);

        let (rem, _) = tag(header)(input)?;

        // read message len
        let out = out.as_mut_ptr();

        let msg = unsafe { &mut *addr_of_mut!((*out).data).cast() };
        let rem = Message::from_bytes_into(rem, msg)?;

        Ok(rem)
    }
}

impl DisplayableItem for AvaxMessage<'_> {
    fn num_items(&self) -> Result<u8, ViewError> {
        // Description + message
        let items = self.data.num_items()?;
        items.checked_add(1).ok_or(ViewError::Unknown)
    }

    fn render_item(
        &self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        match item_n {
            0 => {
                let label = pic_str!(b"Sign");
                title[..label.len()].copy_from_slice(label);
                let content = pic_str!("Avax Message");
                handle_ui_message(content.as_bytes(), message, page)
            }
            x @ 1.. => {
                let idx = x - 1;
                self.data.render_item(idx, title, message, page)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &str = "An AvalancheMessage to sign";
    const HEADER: &str = "\x1AAvalanche Signed Message:\n";

    fn construct_msg(msg: &str) -> std::vec::Vec<u8> {
        let mut vec = std::vec![];
        let msg_len = (DATA.len() as u32).to_be_bytes();
        vec.extend_from_slice(HEADER.as_bytes());
        vec.extend_from_slice(&msg_len[..]);
        vec.extend_from_slice(msg.as_bytes());
        vec
    }

    #[test]
    fn parse_avax_msg() {
        let msg = construct_msg(DATA);
        let (_, tx) = AvaxMessage::from_bytes(&msg).unwrap();
        let m = std::str::from_utf8(tx.msg()).unwrap();
        assert_eq!(m, DATA);
    }
}

#[cfg(test)]
mod tests_message_render {
    use std::vec;

    use super::*;
    use std::vec::Vec;

    fn create_message(content: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + content.len());
        data.extend_from_slice(&(content.len() as u32).to_be_bytes());
        data.extend_from_slice(content);
        data
    }

    fn msg_test1(chunk: &mut [u8]) {
        // Test Vector 1: Fits in two items exactly
        let msg1 = create_message(&[b'A'; 200]);
        let msg1 = Message::from_bytes(msg1.as_slice()).unwrap().1;
        // We expect three chunks
        assert_eq!(msg1.num_items().unwrap(), 2);

        let len1 = msg1.get_chunk(0, chunk);
        assert_eq!(len1, MSG_MAX_CHUNK_LEN);
        assert_eq!(&chunk[..len1], &[b'A'; MSG_MAX_CHUNK_LEN]);

        let len2 = msg1.get_chunk(1, chunk);
        assert_eq!(len2, MSG_MAX_CHUNK_LEN);
        assert_eq!(&chunk[..len2], &[b'A'; MSG_MAX_CHUNK_LEN]);
    }

    fn msg_test2(chunk: &mut [u8]) {
        // Test Vector 2: Uses 3 items, last one half full
        let msg2 = create_message(&[b'B'; 250]);
        let msg2 = Message::from_bytes(msg2.as_slice()).unwrap().1;
        assert_eq!(msg2.num_items().unwrap(), 3);

        let len1 = msg2.get_chunk(0, chunk);
        assert_eq!(len1, MSG_MAX_CHUNK_LEN);
        assert_eq!(&chunk[..len1], &[b'B'; MSG_MAX_CHUNK_LEN]);

        let len2 = msg2.get_chunk(1, chunk);
        assert_eq!(len2, MSG_MAX_CHUNK_LEN);
        assert_eq!(&chunk[..len2], &[b'B'; MSG_MAX_CHUNK_LEN]);

        let len3 = msg2.get_chunk(2, chunk);
        assert_eq!(len3, 50);
        assert_eq!(&chunk[..len3], &[b'B'; 50]);
    }

    fn msg_test3(chunk: &mut [u8]) {
        // Test Vector 3: Non-ASCII characters in the middle
        let mut msg3_content = vec![b'C'; 180];
        msg3_content.extend_from_slice(&[0x80, 0x81, 0x82, 0x83, 0x84]); // 5 non-ASCII chars
        msg3_content.extend_from_slice(&[b'D'; 15]);
        std::println!("msg3_content: {}", msg3_content.len());
        let msg3 = create_message(&msg3_content);
        std::println!("vec_len: {}", msg3.len());
        let msg3 = Message::from_bytes(msg3.as_slice()).unwrap().1;
        assert_eq!(msg3.num_items().unwrap(), 3);

        let len1 = msg3.get_chunk(0, chunk);
        assert_eq!(len1, MSG_MAX_CHUNK_LEN);
        assert_eq!(&chunk[..len1], &[b'C'; MSG_MAX_CHUNK_LEN]);

        let len2 = msg3.get_chunk(1, chunk);
        assert_eq!(len2, MSG_MAX_CHUNK_LEN);
        assert_eq!(&chunk[..80], &[b'C'; 80]);
        assert_eq!(&chunk[80..84], b"\\x80");
        assert_eq!(&chunk[84..88], b"\\x81");
        assert_eq!(&chunk[88..92], b"\\x82");
        assert_eq!(&chunk[92..96], b"\\x83");
        assert_eq!(&chunk[96..100], b"\\x84");

        let len3 = msg3.get_chunk(2, chunk);
        assert_eq!(len3, 15);
        assert_eq!(&chunk[..len3], &[b'D'; 15]);
    }

    fn msg_test4(chunk: &mut [u8]) {
        // Create a complex message with 236 bytes
        let mut msg_content = Vec::with_capacity(236);
        msg_content.extend_from_slice(b"Hello, ");
        msg_content.push(0x80); // non-ASCII
        msg_content.extend_from_slice(b"World! ");
        msg_content.push(0x81); // non-ASCII
        msg_content.extend_from_slice(b"This is a ");
        msg_content.push(0x82); // non-ASCII
        msg_content.extend_from_slice(b"complex ");
        msg_content.push(0x83); // non-ASCII
        msg_content.extend_from_slice(b"test ");
        msg_content.push(0x84); // non-ASCII
        msg_content.extend_from_slice(b"vector with ");
        msg_content.extend_from_slice(&[0x85, 0x86, 0x87]); // 3 non-ASCII
        msg_content.extend_from_slice(b" multiple non-ASCII ");
        msg_content.extend_from_slice(&[0x88, 0x89]); // 2 non-ASCII
        msg_content.extend_from_slice(b" characters ");
        msg_content.push(0x8A); // non-ASCII
        msg_content.extend_from_slice(b"scattered ");
        msg_content.push(0x8B); // non-ASCII
        msg_content.extend_from_slice(b"throughout. ");
        msg_content.extend_from_slice(&[0x8C, 0x8D, 0x8E, 0x8F]); // 4 non-ASCII
        msg_content.extend_from_slice(b"It should ");
        msg_content.push(0x90); // non-ASCII
        msg_content.extend_from_slice(b"properly ");
        msg_content.push(0x91); // non-ASCII
        msg_content.extend_from_slice(b"chunk ");
        msg_content.push(0x92); // non-ASCII
        msg_content.extend_from_slice(b"and format.");

        assert_eq!(msg_content.len(), 158);

        let msg = create_message(&msg_content);
        let msg = Message::from_bytes(msg.as_slice()).unwrap().1;

        // We expect 4 chunks due to the expansion of non-ASCII characters
        assert_eq!(msg.num_items().unwrap(), 3);

        // Check each chunk
        for i in 0..3 {
            let len = msg.get_chunk(i, chunk);
            let chunk_str = std::str::from_utf8(&chunk[..len]).unwrap();
            std::println!("Chunk {}: '{}'\nLength: {}", i + 1, chunk_str, len);

            // Verify that each chunk is not longer than MSG_MAX_CHUNK_LEN
            assert!(len <= MSG_MAX_CHUNK_LEN);

            // Verify that non-ASCII characters are properly formatted
            for j in 0..len {
                if chunk[j] == b'\\' && j + 3 < len {
                    assert_eq!(&chunk[j..j + 2], b"\\x");
                    assert!(chunk[j + 2].is_ascii_hexdigit());
                    assert!(chunk[j + 3].is_ascii_hexdigit());
                }
            }
        }

        // Verify the content of the last chunk
        let last_chunk_len = msg.get_chunk(1, chunk);
        assert!(std::str::from_utf8(&chunk[..last_chunk_len])
            .unwrap()
            .ends_with("91chunk "));

        let last_chunk_len = msg.get_chunk(2, chunk);
        assert!(std::str::from_utf8(&chunk[..last_chunk_len])
            .unwrap()
            .ends_with("and format."));
    }

    fn msg_test5(chunk: &mut [u8]) {
        // Test Vector 1: Fits in two items exactly
        let msg = b"Hello World";
        let msg1 = create_message(msg.as_ref());
        let msg1 = Message::from_bytes(msg1.as_slice()).unwrap().1;
        // We expect three chunks
        assert_eq!(msg1.num_items().unwrap(), 1);
        assert_eq!(msg1.chunk_count, 1);

        let len1 = msg1.get_chunk(0, chunk);
        assert_eq!(len1, msg.len());
        assert_eq!(&chunk[..len1], msg.as_ref());
    }

    #[test]
    fn test_message_chunking() {
        let mut chunk = [0u8; MSG_MAX_CHUNK_LEN + 1];

        msg_test1(&mut chunk);
        msg_test2(&mut chunk);
        msg_test3(&mut chunk);
        msg_test4(&mut chunk);
        msg_test5(&mut chunk);
    }

    // A message whose ASCII display would need more than 255 chunks must be
    // rejected, not silently truncated to the first 255 chunks.
    #[test]
    fn message_exceeds_chunk_budget_rejected() {
        // 255 * MSG_MAX_CHUNK_LEN ASCII bytes fit exactly; one more byte tips
        // the required chunk count to 256.
        let too_big = create_message(&vec![b'A'; 255 * MSG_MAX_CHUNK_LEN + 1]);
        let err = Message::from_bytes(too_big.as_slice()).unwrap_err();
        assert_eq!(err, ParserError::InvalidMessageSize.into());
    }

    // A non-ASCII message tips the budget sooner because each byte expands to
    // HEX_REPR_LEN display characters.
    #[test]
    fn non_ascii_message_exceeds_chunk_budget_rejected() {
        let limit_bytes = 255 * MSG_MAX_CHUNK_LEN / HEX_REPR_LEN;
        let too_big = create_message(&vec![0x80u8; limit_bytes + 1]);
        let err = Message::from_bytes(too_big.as_slice()).unwrap_err();
        assert_eq!(err, ParserError::InvalidMessageSize.into());
    }

    // Boundary: exactly 255 chunks worth of ASCII is still accepted.
    #[test]
    fn message_at_chunk_budget_accepted() {
        let at_limit = create_message(&vec![b'A'; 255 * MSG_MAX_CHUNK_LEN]);
        let msg = Message::from_bytes(at_limit.as_slice()).unwrap().1;
        assert_eq!(msg.chunk_count, 255);
    }

    fn render_all_chunks(msg: &Message) -> Vec<u8> {
        let mut out = Vec::new();
        let mut chunk = [0u8; MSG_MAX_CHUNK_LEN];
        for i in 0..msg.num_items().unwrap() {
            let len = msg.get_chunk(i as usize, &mut chunk);
            assert!(len > 0, "chunk {i} is empty");
            assert!(len <= MSG_MAX_CHUNK_LEN);
            out.extend_from_slice(&chunk[..len]);
        }
        out
    }

    fn escaped(content: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for &b in content {
            if b.is_ascii_whitespace() {
                out.push(b' ');
            } else if (0x20..=0x7E).contains(&b) {
                out.push(b);
            } else {
                out.extend_from_slice(std::format!("\\x{b:02x}").as_bytes());
            }
        }
        out
    }

    // A NUL used to be copied raw, ending the C string the device displays:
    // everything after it was signed but never shown.
    #[test]
    fn nul_and_control_bytes_are_escaped() {
        let content = b"Pay 1 AVAX\x00 and 1000 AVAX\x1b[2K\x07\x7f";
        let data = create_message(content);
        let msg = Message::from_bytes(data.as_slice()).unwrap().1;

        let shown = render_all_chunks(&msg);
        assert_eq!(
            shown.as_slice(),
            b"Pay 1 AVAX\\x00 and 1000 AVAX\\x1b[2K\\x07\\x7f".as_slice()
        );
        assert!(!shown.contains(&0));
        assert!(shown.iter().all(|b| (0x20..=0x7E).contains(b)));
    }

    // An escape that did not fit at the end of a chunk was dropped: the
    // render loop stopped before it, and the skip loop for the next chunk
    // counted it as consumed.
    #[test]
    fn escape_straddling_chunk_boundary_is_shown() {
        let mut content = vec![b'A'; MSG_MAX_CHUNK_LEN - 1];
        content.push(0x80);
        content.extend_from_slice(b"tail");
        let data = create_message(&content);
        let msg = Message::from_bytes(data.as_slice()).unwrap().1;

        assert_eq!(msg.num_items().unwrap(), 2);

        let mut chunk = [0u8; MSG_MAX_CHUNK_LEN];
        let len = msg.get_chunk(0, &mut chunk);
        assert_eq!(&chunk[..len], &content[..MSG_MAX_CHUNK_LEN - 1]);

        let len = msg.get_chunk(1, &mut chunk);
        assert_eq!(&chunk[..len], b"\\x80tail");
    }

    // Counting, skipping and rendering agree on every boundary: the chunks
    // put together are exactly the escaped message, for escapes landing at
    // every offset around the chunk edge.
    #[test]
    fn chunks_concatenate_to_whole_escaped_message() {
        for prefix in 90..=MSG_MAX_CHUNK_LEN + 5 {
            let mut content = vec![b'x'; prefix];
            content.extend_from_slice(&[0x00, 0xff, b'y', 0x01, b'\n', 0x9b]);
            content.extend_from_slice(&[0x80; 60]);
            content.extend_from_slice(b"end");
            let data = create_message(&content);
            let msg = Message::from_bytes(data.as_slice()).unwrap().1;

            assert_eq!(
                render_all_chunks(&msg),
                escaped(&content),
                "prefix {prefix}"
            );
            // one chunk past the end renders nothing
            let mut chunk = [0u8; MSG_MAX_CHUNK_LEN];
            assert_eq!(
                msg.get_chunk(msg.num_items().unwrap() as usize, &mut chunk),
                0
            );
        }
    }
}
