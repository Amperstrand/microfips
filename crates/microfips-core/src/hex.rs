//! microfips-only: const hex parser for compile-time key injection. No direct
//! fips equivalent; closest upstream helper: fips v0.4.0 `src/identity/mod.rs`
//! hex_encode.
//!
//! Deviation: upstream `hex_encode` is a runtime `&[u8] -> String` helper
//! requiring alloc; this module provides a `const fn` parser going the opposite
//! direction (`&str -> [u8; N]`) so keys can be baked in at compile time without
//! a heap.

//! microfips-only: const hex parser for compile-time key injection.
//! No direct fips equivalent; closest upstream helper: fips v0.4.0 `src/identity/mod.rs` hex_encode.

const fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("invalid hex nibble"),
    }
}

const fn hex_bytes_impl<const N: usize>(s: &str) -> [u8; N] {
    let bytes = s.as_bytes();
    assert!(bytes.len() == N * 2, "hex string length mismatch");
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (hex_nibble(bytes[i * 2]) << 4) | hex_nibble(bytes[i * 2 + 1]);
        i += 1;
    }
    out
}

pub const fn hex_bytes_16(s: &str) -> [u8; 16] {
    hex_bytes_impl(s)
}

pub const fn hex_bytes_32(s: &str) -> [u8; 32] {
    hex_bytes_impl(s)
}

pub const fn hex_bytes_33(s: &str) -> [u8; 33] {
    hex_bytes_impl(s)
}

/// Runtime lowercase hex encoder (no alloc; dst must hold `2 * src.len()`
/// bytes). Lowercase is contractual: the #175 keylog consumers match
/// `[0-9a-f]{64}`.
pub fn hex_encode(src: &[u8], dst: &mut [u8]) -> bool {
    if dst.len() < src.len() * 2 {
        return false;
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in src.iter().enumerate() {
        dst[i * 2] = HEX[usize::from(b >> 4)];
        dst[i * 2 + 1] = HEX[usize::from(b & 0x0f)];
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_roundtrip_lowercase() {
        let mut dst = [0u8; 8];
        assert!(hex_encode(&[0x00, 0x01, 0xab, 0xff], &mut dst));
        assert_eq!(&dst, b"0001abff");
    }

    #[test]
    fn encode_rejects_short_dst() {
        let mut dst = [0u8; 3];
        assert!(!hex_encode(&[0x01, 0x02], &mut dst));
    }

    #[test]
    fn encode_matches_const_parser() {
        let src = [0x5au8; 32];
        let mut dst = [0u8; 64];
        assert!(hex_encode(&src, &mut dst));
        let s = core::str::from_utf8(&dst).unwrap();
        assert_eq!(hex_bytes_32(s), src);
    }

    #[test]
    fn parse_32_bytes() {
        let s = "abababababababababababababababababababababababababababababababcd";
        let arr = hex_bytes_32(s);
        assert_eq!(arr[31], 0xcd);
        assert_eq!(arr[0], 0xab);
    }

    #[test]
    fn parse_33_bytes() {
        let s = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let arr = hex_bytes_33(s);
        assert_eq!(arr[0], 0x02);
        assert_eq!(arr.len(), 33);
    }

    #[test]
    fn parse_16_bytes() {
        let s = "132f39a98c31baaddba6525f5d43f295";
        let arr = hex_bytes_16(s);
        assert_eq!(arr[0], 0x13);
        assert_eq!(arr.len(), 16);
    }
}
