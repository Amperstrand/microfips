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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_32_bytes() {
        let s = "0000000000000000000000000000000000000000000000000000000000000001";
        let arr = hex_bytes_32(s);
        assert_eq!(arr[31], 0x01);
        assert_eq!(arr[0], 0x00);
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
