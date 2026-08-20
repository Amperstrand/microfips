//! Minimal bech32 (BIP-173) decoder for Nostr `npub` public keys.
//!
//! Decode-only, no_std, no alloc. FIPS mDNS adverts carry the daemon's
//! identity as a bech32 `npub1...` string in a TXT record; the firmware
//! needs the 32-byte x-only key to build the Noise IK pre-message.

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

/// Total length of a bech32-encoded npub: "npub1" + 52 data chars + 6 checksum chars.
pub const NPUB_BECH32_LEN: usize = 63;

fn charset_rev(c: u8) -> Option<u8> {
    CHARSET.iter().position(|&x| x == c).map(|p| p as u8)
}

fn polymod_step(chk: u32, value: u8) -> u32 {
    let top = chk >> 25;
    let mut chk = ((chk & 0x01ff_ffff) << 5) ^ (value as u32);
    for (i, g) in GEN.iter().enumerate() {
        if (top >> i) & 1 == 1 {
            chk ^= g;
        }
    }
    chk
}

/// Decode a bech32 `npub1...` string into the 32-byte x-only public key.
///
/// Verifies the human-readable part is exactly `npub`, the checksum is
/// valid (original bech32 constant, per NIP-19), and the payload is
/// exactly 32 bytes. Returns `None` on any mismatch.
pub fn npub_to_x_only(npub: &str) -> Option<[u8; 32]> {
    let s = npub.as_bytes();
    if s.len() != NPUB_BECH32_LEN || !s.starts_with(b"npub1") {
        return None;
    }

    // Checksum over expanded HRP ("npub") + all data values.
    let mut chk: u32 = 1;
    for &b in b"npub" {
        chk = polymod_step(chk, b >> 5);
    }
    chk = polymod_step(chk, 0);
    for &b in b"npub" {
        chk = polymod_step(chk, b & 0x1f);
    }

    let data = &s[5..];
    let mut values = [0u8; NPUB_BECH32_LEN - 5];
    for (i, &c) in data.iter().enumerate() {
        let v = charset_rev(c.to_ascii_lowercase())?;
        values[i] = v;
        chk = polymod_step(chk, v);
    }
    if chk != 1 {
        return None;
    }

    // Convert the 52 payload values (checksum excluded) from 5-bit to 8-bit.
    let payload = &values[..values.len() - 6];
    let mut out = [0u8; 32];
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut n = 0usize;
    for &v in payload {
        acc = (acc << 5) | (v as u32);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            if n == 32 {
                return None;
            }
            out[n] = ((acc >> bits) & 0xff) as u8;
            n += 1;
        }
    }
    // 52 * 5 = 260 bits: 256 payload bits + 4 padding bits, which must be zero.
    if n != 32 || (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

/// Encode a 32-byte x-only public key as a bech32 `npub1...` string
/// (NIP-19). Output is ASCII; use `core::str::from_utf8` on it.
pub fn x_only_to_npub(key: &[u8; 32]) -> [u8; NPUB_BECH32_LEN] {
    // 8-bit -> 5-bit (256 bits -> 52 values, last padded with 4 zero bits).
    let mut values = [0u8; 52];
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut n = 0usize;
    for &b in key {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            values[n] = ((acc >> bits) & 0x1f) as u8;
            n += 1;
        }
    }
    if bits > 0 {
        values[n] = ((acc << (5 - bits)) & 0x1f) as u8;
    }

    let mut chk: u32 = 1;
    for &b in b"npub" {
        chk = polymod_step(chk, b >> 5);
    }
    chk = polymod_step(chk, 0);
    for &b in b"npub" {
        chk = polymod_step(chk, b & 0x1f);
    }
    for &v in &values {
        chk = polymod_step(chk, v);
    }
    for _ in 0..6 {
        chk = polymod_step(chk, 0);
    }
    let pm = chk ^ 1;

    let mut out = [0u8; NPUB_BECH32_LEN];
    out[..5].copy_from_slice(b"npub1");
    for (i, &v) in values.iter().enumerate() {
        out[5 + i] = CHARSET[v as usize];
    }
    for i in 0..6 {
        out[5 + 52 + i] = CHARSET[((pm >> (5 * (5 - i))) & 0x1f) as usize];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn decodes_known_npubs() {
        // Linux FIPS daemon key (verified via live Noise IK handshake 2026-08-18).
        assert_eq!(
            npub_to_x_only("npub1vrkus89jjs030qz34df6e8nmrd96rwpde6c3ecwsafqehvw7m4aqt7p7mn"),
            Some(hex32(
                "60edc81cb2941f178051ab53ac9e7b1b4ba1b82dceb11ce1d0ea419bb1dedd7a"
            ))
        );
        assert_eq!(
            npub_to_x_only("npub12yu4dny6chzwghtq68ygmkyj7ugz93e403skz3y075mykjsheg7sp0yyzz"),
            Some(hex32(
                "513956cc9ac5c4e45d60d1c88dd892f71022c7357c6161448ff5364b4a17ca3d"
            ))
        );
    }

    #[test]
    fn rejects_corrupted_checksum() {
        // Last character flipped.
        assert_eq!(
            npub_to_x_only("npub1vrkus89jjs030qz34df6e8nmrd96rwpde6c3ecwsafqehvw7m4aqt7p7mq"),
            None
        );
        // Payload character flipped ("qz34" -> "qz43").
        assert_eq!(
            npub_to_x_only("npub1vrkus89jjs030qz43df6e8nmrd96rwpde6c3ecwsafqehvw7m4aqt7p7mn"),
            None
        );
    }

    #[test]
    fn rejects_wrong_shape() {
        assert_eq!(npub_to_x_only(""), None);
        assert_eq!(npub_to_x_only("npub1short"), None);
        // Right length, wrong prefix.
        assert_eq!(
            npub_to_x_only("nsec1vrkus89jjs030qz34df6e8nmrd96rwpde6c3ecwsafqehvw7m4aqt7p7mn"),
            None
        );
        // Invalid charset character ('b' is not in the bech32 charset).
        assert_eq!(
            npub_to_x_only("npub1brkus89jjs030qz34df6e8nmrd96rwpde6c3ecwsafqehvw7m4aqt7p7mn"),
            None
        );
    }

    #[test]
    fn encode_roundtrip_and_known_vector() {
        let key = hex32("2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4");
        let enc = x_only_to_npub(&key);
        let s = core::str::from_utf8(&enc).unwrap();
        assert_eq!(
            s,
            "npub1979aung6qusfx4d55ujs5hz39r5ghp9am3se4d7t4r2knvjqaljqevzcrp"
        );
        assert_eq!(npub_to_x_only(s), Some(key));
        for seed in [0u8, 1, 0x55, 0xff] {
            let k = [seed; 32];
            let e = x_only_to_npub(&k);
            assert_eq!(npub_to_x_only(core::str::from_utf8(&e).unwrap()), Some(k));
        }
    }
}
