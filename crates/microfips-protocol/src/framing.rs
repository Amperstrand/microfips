/// Compact a buffer by moving remaining data to the front.
///
/// Used by the framing layer to reclaim space after consumed bytes.
/// Safe against overlapping copies via `copy_within`.
pub fn compact(buf: &mut [u8], pos: &mut usize, len: &mut usize) {
    if *pos > 0 && *pos < *len {
        let remaining = *len - *pos;
        buf.copy_within(*pos..*len, 0);
        *pos = 0;
        *len = remaining;
    }
}

/// Maximum frame payload size. Should match the FIPS MTU.
///
/// FIPS: maximum frame size is 1500 bytes (standard Ethernet MTU).
///
/// If a received frame declares a length > MAX_FRAME, the frame reader discards
/// all buffered data and waits for fresh input. This prevents buffer exhaustion
/// but may desynchronize the framing stream.
///
/// For the MCU's 2048-byte receive buffer, the maximum in-flight data is:
/// 2 (length prefix) + 1500 (payload) = 1502 bytes, fitting comfortably.
pub const MAX_FRAME: usize = 1500;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_moves_remaining_to_front() {
        let mut buf = [0u8; 16];
        buf[4..10].copy_from_slice(b"hello!");
        let mut pos = 4usize;
        let mut len = 10usize;
        compact(&mut buf, &mut pos, &mut len);
        assert_eq!(pos, 0);
        assert_eq!(len, 6);
        assert_eq!(&buf[..6], b"hello!");
    }

    #[test]
    fn compact_noop_when_pos_zero() {
        let mut buf = [0u8; 8];
        buf[..4].copy_from_slice(b"test");
        let mut pos = 0usize;
        let mut len = 4usize;
        compact(&mut buf, &mut pos, &mut len);
        assert_eq!(pos, 0);
        assert_eq!(len, 4);
        assert_eq!(&buf[..4], b"test");
    }
}
