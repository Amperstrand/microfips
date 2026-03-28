pub fn compact(buf: &mut [u8], pos: &mut usize, len: &mut usize) {
    if *pos > 0 && *pos < *len {
        let remaining = *len - *pos;
        buf.copy_within(*pos..*len, 0);
        *pos = 0;
        *len = remaining;
    }
}

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
