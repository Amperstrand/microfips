//! Fragmentation codec for carrying FMP frames over ESP-NOW.
//!
//! ESP-NOW payloads are capped at 250 bytes while FMP frames go up to
//! [`MAX_MESSAGE`] (2048). Each frame is split into chunks prefixed with a
//! 2-byte header:
//!
//! - byte 0: message id (wrapping counter, groups the chunks of one frame)
//! - byte 1: bit 7 = last-fragment flag, bits 0-6 = fragment index
//!
//! Fragments of one message are sent back-to-back and reassembled strictly
//! in order; any gap, duplicate, or source change drops the partial message.
//! The Noise/FMP layers above treat that as datagram loss and retry, so no
//! retransmission logic lives here.

/// ESP-NOW's maximum payload per frame (`ESP_NOW_MAX_DATA_LEN`).
pub const ESP_NOW_MAX_PAYLOAD: usize = 250;
pub const FRAG_HEADER_LEN: usize = 2;
/// Message bytes carried per ESP-NOW frame.
pub const MAX_CHUNK: usize = ESP_NOW_MAX_PAYLOAD - FRAG_HEADER_LEN;
/// Largest reassembled message; matches the protocol's frame buffer.
pub const MAX_MESSAGE: usize = microfips_protocol::node::MAX_FRAME_SIZE;

const LAST_FLAG: u8 = 0x80;
const IDX_MASK: u8 = 0x7f;

/// Splits messages into ESP-NOW-sized fragments, stamping a wrapping
/// message id so the receiver can detect torn messages.
pub struct Fragmenter {
    next_msg_id: u8,
}

impl Fragmenter {
    pub const fn new() -> Self {
        Self { next_msg_id: 0 }
    }

    /// Fragment `data`. Returns `None` if it exceeds [`MAX_MESSAGE`].
    /// An empty message still yields one (empty) fragment.
    pub fn fragments<'a>(&mut self, data: &'a [u8]) -> Option<FragmentIter<'a>> {
        if data.len() > MAX_MESSAGE {
            return None;
        }
        let msg_id = self.next_msg_id;
        self.next_msg_id = self.next_msg_id.wrapping_add(1);
        Some(FragmentIter {
            msg_id,
            data,
            idx: 0,
            done: false,
        })
    }
}

impl Default for Fragmenter {
    fn default() -> Self {
        Self::new()
    }
}

/// Yields `(header, chunk)` pairs; concatenate to build each ESP-NOW payload.
pub struct FragmentIter<'a> {
    msg_id: u8,
    data: &'a [u8],
    idx: u8,
    done: bool,
}

impl<'a> Iterator for FragmentIter<'a> {
    type Item = ([u8; FRAG_HEADER_LEN], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let take = self.data.len().min(MAX_CHUNK);
        let (chunk, rest) = self.data.split_at(take);
        self.data = rest;
        let last = rest.is_empty();
        let header = [
            self.msg_id,
            (self.idx & IDX_MASK) | if last { LAST_FLAG } else { 0 },
        ];
        self.idx += 1;
        self.done = last;
        Some((header, chunk))
    }
}

/// Reassembles fragments back into messages. Strictly in-order: fragment 0
/// starts a message (implicitly dropping any unfinished one), and any id or
/// index mismatch discards the partial message.
pub struct Reassembler {
    buf: [u8; MAX_MESSAGE],
    len: usize,
    msg_id: u8,
    next_idx: u8,
    active: bool,
}

impl Reassembler {
    pub const fn new() -> Self {
        Self {
            buf: [0u8; MAX_MESSAGE],
            len: 0,
            msg_id: 0,
            next_idx: 0,
            active: false,
        }
    }

    /// Drop any partial message.
    pub fn reset(&mut self) {
        self.active = false;
    }

    /// Feed one received ESP-NOW payload. Returns the completed message
    /// when its last fragment arrives.
    pub fn push(&mut self, payload: &[u8]) -> Option<&[u8]> {
        if payload.len() < FRAG_HEADER_LEN || payload.len() > ESP_NOW_MAX_PAYLOAD {
            self.active = false;
            return None;
        }
        let msg_id = payload[0];
        let last = payload[1] & LAST_FLAG != 0;
        let idx = payload[1] & IDX_MASK;
        let chunk = &payload[FRAG_HEADER_LEN..];

        if idx == 0 {
            self.msg_id = msg_id;
            self.len = 0;
            self.next_idx = 0;
            self.active = true;
        } else if !self.active || msg_id != self.msg_id || idx != self.next_idx {
            self.active = false;
            return None;
        }

        if self.len + chunk.len() > MAX_MESSAGE {
            self.active = false;
            return None;
        }
        self.buf[self.len..self.len + chunk.len()].copy_from_slice(chunk);
        self.len += chunk.len();
        self.next_idx = idx + 1;

        if last {
            self.active = false;
            Some(&self.buf[..self.len])
        } else {
            None
        }
    }
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

/// [`Reassembler`] that additionally tracks the sender's MAC: a fragment
/// from a different source than the in-progress message discards the
/// partial state instead of mixing two senders' chunks.
pub struct SrcReassembler {
    reassembler: Reassembler,
    src: Option<[u8; 6]>,
}

impl SrcReassembler {
    pub const fn new() -> Self {
        Self {
            reassembler: Reassembler::new(),
            src: None,
        }
    }

    /// Feed one payload received from `src`. Returns the completed message
    /// when its last fragment arrives.
    pub fn push(&mut self, src: [u8; 6], payload: &[u8]) -> Option<&[u8]> {
        if self.src != Some(src) {
            self.reassembler.reset();
            self.src = Some(src);
        }
        self.reassembler.push(payload)
    }
}

impl Default for SrcReassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(len: usize) {
        let data: alloc::vec::Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        let mut frag = Fragmenter::new();
        let mut reasm = Reassembler::new();
        let mut out = None;
        let mut count = 0usize;
        for (hdr, chunk) in frag.fragments(&data).unwrap() {
            assert!(FRAG_HEADER_LEN + chunk.len() <= ESP_NOW_MAX_PAYLOAD);
            let mut payload = alloc::vec::Vec::new();
            payload.extend_from_slice(&hdr);
            payload.extend_from_slice(chunk);
            assert!(out.is_none(), "message completed before last fragment");
            out = reasm.push(&payload).map(<[u8]>::to_vec);
            count += 1;
        }
        assert_eq!(out.as_deref(), Some(&data[..]));
        assert_eq!(count, len.div_ceil(MAX_CHUNK).max(1));
    }

    #[test]
    fn roundtrip_sizes() {
        for len in [
            0,
            1,
            MAX_CHUNK - 1,
            MAX_CHUNK,
            MAX_CHUNK + 1,
            500,
            1500,
            MAX_MESSAGE,
        ] {
            roundtrip(len);
        }
    }

    #[test]
    fn oversize_message_rejected() {
        let data = [0u8; MAX_MESSAGE + 1];
        assert!(Fragmenter::new().fragments(&data).is_none());
    }

    #[test]
    fn msg_id_advances() {
        let mut frag = Fragmenter::new();
        let a = frag.fragments(b"x").unwrap().next().unwrap().0[0];
        let b = frag.fragments(b"x").unwrap().next().unwrap().0[0];
        assert_eq!(b, a.wrapping_add(1));
    }

    #[test]
    fn lost_fragment_drops_message() {
        let data = [0xAAu8; MAX_CHUNK * 3];
        let mut frag = Fragmenter::new();
        let payloads: alloc::vec::Vec<alloc::vec::Vec<u8>> = frag
            .fragments(&data)
            .unwrap()
            .map(|(h, c)| {
                let mut p = alloc::vec::Vec::new();
                p.extend_from_slice(&h);
                p.extend_from_slice(c);
                p
            })
            .collect();
        assert_eq!(payloads.len(), 3);

        let mut reasm = Reassembler::new();
        assert!(reasm.push(&payloads[0]).is_none());
        // fragment 1 lost; fragment 2 must not complete the message
        assert!(reasm.push(&payloads[2]).is_none());
        // a fresh message still reassembles afterwards
        let mut frag2 = Fragmenter::new();
        let small: alloc::vec::Vec<u8> = frag2
            .fragments(b"hello")
            .unwrap()
            .flat_map(|(h, c)| {
                let mut p = alloc::vec::Vec::new();
                p.extend_from_slice(&h);
                p.extend_from_slice(c);
                p
            })
            .collect();
        assert_eq!(reasm.push(&small), Some(&b"hello"[..]));
    }

    #[test]
    fn duplicate_fragment_drops_message() {
        let data = [0x55u8; MAX_CHUNK * 2];
        let payloads: alloc::vec::Vec<alloc::vec::Vec<u8>> = Fragmenter::new()
            .fragments(&data)
            .unwrap()
            .map(|(h, c)| {
                let mut p = alloc::vec::Vec::new();
                p.extend_from_slice(&h);
                p.extend_from_slice(c);
                p
            })
            .collect();
        let mut reasm = Reassembler::new();
        assert!(reasm.push(&payloads[0]).is_none());
        assert!(reasm.push(&payloads[0]).is_none()); // duplicate of idx 0 restarts
        assert!(reasm.push(&payloads[1]).is_some()); // restart still completes
    }

    #[test]
    fn garbage_rejected() {
        let mut reasm = Reassembler::new();
        assert!(reasm.push(&[]).is_none());
        assert!(reasm.push(&[0x01]).is_none());
        assert!(reasm.push(&[0u8; ESP_NOW_MAX_PAYLOAD + 1]).is_none());
    }

    #[test]
    fn src_change_drops_partial() {
        let data = [0x77u8; MAX_CHUNK * 2];
        let payloads: alloc::vec::Vec<alloc::vec::Vec<u8>> = Fragmenter::new()
            .fragments(&data)
            .unwrap()
            .map(|(h, c)| {
                let mut p = alloc::vec::Vec::new();
                p.extend_from_slice(&h);
                p.extend_from_slice(c);
                p
            })
            .collect();
        let mac_a = [1u8; 6];
        let mac_b = [2u8; 6];
        let mut reasm = SrcReassembler::new();
        assert!(reasm.push(mac_a, &payloads[0]).is_none());
        // interloper resets the partial message even with a matching header
        assert!(reasm.push(mac_b, &payloads[1]).is_none());
        assert!(reasm.push(mac_a, &payloads[1]).is_none());
        // full message from one source still works
        assert!(reasm.push(mac_a, &payloads[0]).is_none());
        assert!(reasm.push(mac_a, &payloads[1]).is_some());
    }
}
