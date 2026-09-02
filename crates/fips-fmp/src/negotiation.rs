//! FMP v1 protocol-negotiation payload codec (Noise XX wire, `noise-xx`).
//!
//! FIPS next `src/proto/fmp/wire.rs` (observed at upstream `next` commit
//! `e0cc0c86`): a negotiation payload is AEAD-encrypted by the Noise layer
//! (`encrypt_payload`/`decrypt_payload`, hash-chained before `finalize`) and
//! appended after the base XX msg2/msg3 handshake bytes. Each layer (FMP, FSP)
//! uses the same wire format with layer-specific version ranges and feature
//! catalogs; this module implements the FMP link-layer catalog.
//!
//! # Wire format
//!
//! ```text
//! byte 0:    format (must be 0)
//! byte 1:    [version_min:4 high][version_max:4 low]
//! bytes 2-9: feature bitfield (64 bits, LE)
//! bytes 10+: TLV entries, each: [field_num:2 LE][length:2 LE][value:N]
//! ```
//!
//! Presence is optional on receive (peers may omit the block entirely);
//! a present-but-malformed block is an error, never an absence.

use core::fmt;
use fips_noise as noise;

/// Size of the fixed negotiation header (format + version + features).
pub const NEGOTIATION_HEADER_SIZE: usize = 10;

/// Format byte value for the initial negotiation format.
pub const NEGOTIATION_FORMAT_V0: u8 = 0;

/// Largest payload this codec emits or accepts without structural error:
/// header + one rekey-marker TLV covers leaf needs with room to spare.
pub const NEGOTIATION_MAX_SIZE: usize = 64;

/// TLV field number for the rekey marker.
///
/// FIPS next: "Its value is the session index the *receiver* allocated for
/// the session this handshake replaces. Absence means the handshake is not
/// a rekey."
pub const TLV_REKEY_OF: u16 = 1;

/// Mask for the 3-bit node profile enum (bits 0-2).
pub const FMP_FEAT_PROFILE_MASK: u64 = 0x07;
/// Bit 3: can provide MMP sender reports.
pub const FMP_FEAT_PROVIDES_SR: u64 = 1 << 3;
/// Bit 4: can provide MMP receiver reports.
pub const FMP_FEAT_PROVIDES_RR: u64 = 1 << 4;
/// Bit 5: want MMP sender reports from peer.
pub const FMP_FEAT_WANTS_SR: u64 = 1 << 5;
/// Bit 6: want MMP receiver reports from peer.
pub const FMP_FEAT_WANTS_RR: u64 = 1 << 6;

/// Node profile advertised during FMP negotiation (bits 0-2).
///
/// Self-declared. At least one side of a link must be `Full` or the link
/// is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NodeProfile {
    /// Full routing node. Bloom filters, transit forwarding.
    Full = 0,
    /// Non-routing node. Tree participation, no transit forwarding.
    NonRouting = 1,
    /// Leaf node. Single upstream peer, no tree/bloom/transit.
    Leaf = 2,
}

impl NodeProfile {
    pub fn from_features(features: u64) -> Option<Self> {
        match (features & FMP_FEAT_PROFILE_MASK) as u8 {
            0 => Some(Self::Full),
            1 => Some(Self::NonRouting),
            2 => Some(Self::Leaf),
            _ => None,
        }
    }

    /// Pairing rule: at least one side must be `Full`.
    pub fn valid_pairing(ours: Self, theirs: Self) -> bool {
        ours == Self::Full || theirs == Self::Full
    }
}

impl fmt::Display for NodeProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => write!(f, "full"),
            Self::NonRouting => write!(f, "non-routing"),
            Self::Leaf => write!(f, "leaf"),
        }
    }
}

/// FMP feature bitfield for a profile, matching the FIPS `fmp()` defaults:
/// Full provides+wants SR/RR, NonRouting provides both and wants RR only,
/// Leaf provides RR only.
pub fn fmp_features(profile: NodeProfile) -> u64 {
    let bits = (profile as u8) as u64;
    match profile {
        NodeProfile::Full => {
            bits | FMP_FEAT_PROVIDES_SR
                | FMP_FEAT_PROVIDES_RR
                | FMP_FEAT_WANTS_SR
                | FMP_FEAT_WANTS_RR
        }
        NodeProfile::NonRouting => {
            bits | FMP_FEAT_PROVIDES_SR | FMP_FEAT_PROVIDES_RR | FMP_FEAT_WANTS_RR
        }
        NodeProfile::Leaf => bits | FMP_FEAT_PROVIDES_RR,
    }
}

/// Negotiation-block decode / validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiationError {
    TooShort,
    BadFormat,
    BadVersionRange,
    TruncatedTlv,
    BadRekeyMarker,
}

impl fmt::Display for NegotiationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "negotiation payload too short"),
            Self::BadFormat => write!(f, "unknown negotiation format"),
            Self::BadVersionRange => write!(f, "version_min > version_max"),
            Self::TruncatedTlv => write!(f, "truncated TLV"),
            Self::BadRekeyMarker => write!(f, "malformed rekey marker"),
        }
    }
}

/// Fixed header view over a negotiation payload (TLV region excluded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiationHeader {
    pub version_min: u8,
    pub version_max: u8,
    pub features: u64,
}

impl NegotiationHeader {
    pub fn parse(data: &[u8]) -> Result<Self, NegotiationError> {
        if data.len() < NEGOTIATION_HEADER_SIZE {
            return Err(NegotiationError::TooShort);
        }
        if data[0] != NEGOTIATION_FORMAT_V0 {
            return Err(NegotiationError::BadFormat);
        }
        let version_min = data[1] >> 4;
        let version_max = data[1] & 0x0F;
        if version_min > version_max {
            return Err(NegotiationError::BadVersionRange);
        }
        let features = u64::from_le_bytes(data[2..10].try_into().unwrap());
        Ok(Self {
            version_min,
            version_max,
            features,
        })
    }

    /// `min(our_max, their_max)`, rejecting if below either minimum.
    pub fn agree_version(&self, other: &Self) -> Result<u8, NegotiationError> {
        let agreed = self.version_max.min(other.version_max);
        if agreed < self.version_min || agreed < other.version_min {
            return Err(NegotiationError::BadVersionRange);
        }
        Ok(agreed)
    }

    pub fn node_profile(&self) -> Option<NodeProfile> {
        NodeProfile::from_features(self.features)
    }
}

/// Encode a negotiation payload: header + optional rekey-marker TLV.
///
/// This is the leaf's complete emission vocabulary; unknown TLVs are a
/// receive-side concern only.
pub fn encode_payload(
    out: &mut [u8],
    version_min: u8,
    version_max: u8,
    features: u64,
    rekey_of: Option<u32>,
) -> Option<usize> {
    let mut needed = NEGOTIATION_HEADER_SIZE;
    if rekey_of.is_some() {
        needed += 4 + 4;
    }
    if out.len() < needed {
        return None;
    }
    out[0] = NEGOTIATION_FORMAT_V0;
    out[1] = (version_min << 4) | (version_max & 0x0F);
    out[2..10].copy_from_slice(&features.to_le_bytes());
    let mut pos = NEGOTIATION_HEADER_SIZE;
    if let Some(idx) = rekey_of {
        out[pos..pos + 2].copy_from_slice(&TLV_REKEY_OF.to_le_bytes());
        out[pos + 2..pos + 4].copy_from_slice(&4u16.to_le_bytes());
        out[pos + 4..pos + 8].copy_from_slice(&idx.to_le_bytes());
        pos += 8;
    }
    Some(pos)
}

/// Locate `field_num` in the TLV region, validating structure while scanning.
///
/// `Ok(None)` = payload carries no such field. Malformed TLV structure is
/// `Err`, never `None`.
pub fn find_tlv(data: &[u8], field_num: u16) -> Result<Option<&[u8]>, NegotiationError> {
    if data.len() < NEGOTIATION_HEADER_SIZE {
        return Err(NegotiationError::TooShort);
    }
    let mut rest = &data[NEGOTIATION_HEADER_SIZE..];
    while !rest.is_empty() {
        if rest.len() < 4 {
            return Err(NegotiationError::TruncatedTlv);
        }
        let num = u16::from_le_bytes([rest[0], rest[1]]);
        let len = u16::from_le_bytes([rest[2], rest[3]]) as usize;
        if 4 + len > rest.len() {
            return Err(NegotiationError::TruncatedTlv);
        }
        let value = &rest[4..4 + len];
        if num == field_num {
            return Ok(Some(value));
        }
        rest = &rest[4 + len..];
    }
    Ok(None)
}

/// The session index this handshake declares it replaces, if any.
pub fn rekey_of(data: &[u8]) -> Result<Option<u32>, NegotiationError> {
    match find_tlv(data, TLV_REKEY_OF)? {
        Some(value) if value.len() == 4 => Ok(Some(u32::from_le_bytes(value.try_into().unwrap()))),
        Some(_) => Err(NegotiationError::BadRekeyMarker),
        None => Ok(None),
    }
}

/// Split an XX msg2 noise payload into (base, optional negotiation extra).
///
/// Bytes beyond the base XX message are the encrypted negotiation payload
/// (FIPS next `complete_handshake` split at `noise::HANDSHAKE_MSG2_SIZE`).
pub fn split_msg2_noise(payload: &[u8]) -> (&[u8], Option<&[u8]>) {
    split_handshake_noise(payload, noise::XX_HANDSHAKE_MSG2_SIZE)
}

/// Split an XX msg3 noise payload into (base, optional negotiation extra).
pub fn split_msg3_noise(payload: &[u8]) -> (&[u8], Option<&[u8]>) {
    split_handshake_noise(payload, noise::XX_HANDSHAKE_MSG3_SIZE)
}

fn split_handshake_noise(payload: &[u8], base_size: usize) -> (&[u8], Option<&[u8]>) {
    if payload.len() > base_size {
        (&payload[..base_size], Some(&payload[base_size..]))
    } else {
        (payload, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed-size test buffer: payload bytes + live length.
    struct Buf {
        bytes: [u8; 80],
        len: usize,
    }

    impl Buf {
        fn new(data: &[u8]) -> Self {
            let mut bytes = [0u8; 80];
            bytes[..data.len()].copy_from_slice(data);
            Self {
                bytes,
                len: data.len(),
            }
        }

        fn push(&mut self, data: &[u8]) {
            self.bytes[self.len..self.len + data.len()].copy_from_slice(data);
            self.len += data.len();
        }

        fn as_slice(&self) -> &[u8] {
            &self.bytes[..self.len]
        }
    }

    fn leaf_buf() -> Buf {
        let mut bytes = [0u8; 80];
        let n = encode_payload(&mut bytes, 1, 1, fmp_features(NodeProfile::Leaf), None).unwrap();
        Buf {
            bytes: {
                let mut b = [0u8; 80];
                b[..n].copy_from_slice(&bytes[..n]);
                b
            },
            len: n,
        }
    }

    #[test]
    fn header_layout_matches_spec() {
        let data = leaf_buf();
        assert_eq!(data.len, NEGOTIATION_HEADER_SIZE);
        assert_eq!(data.as_slice()[0], 0);
        assert_eq!(data.as_slice()[1], (1 << 4) | 1);
        assert_eq!(
            u64::from_le_bytes(data.as_slice()[2..10].try_into().unwrap()),
            fmp_features(NodeProfile::Leaf)
        );
    }

    #[test]
    fn roundtrip_leaf_header() {
        let h = NegotiationHeader::parse(leaf_buf().as_slice()).unwrap();
        assert_eq!(h.version_min, 1);
        assert_eq!(h.version_max, 1);
        assert_eq!(h.node_profile(), Some(NodeProfile::Leaf));
    }

    #[test]
    fn too_short_rejected() {
        assert_eq!(
            NegotiationHeader::parse(&[0u8; 5]),
            Err(NegotiationError::TooShort)
        );
        assert_eq!(rekey_of(&[0u8; 5]), Err(NegotiationError::TooShort));
    }

    #[test]
    fn bad_format_rejected() {
        let mut data = leaf_buf();
        data.bytes[0] = 1;
        assert_eq!(
            NegotiationHeader::parse(data.as_slice()),
            Err(NegotiationError::BadFormat)
        );
    }

    #[test]
    fn bad_version_range_rejected() {
        let mut data = leaf_buf();
        data.bytes[1] = (5 << 4) | 3;
        assert_eq!(
            NegotiationHeader::parse(data.as_slice()),
            Err(NegotiationError::BadVersionRange)
        );
    }

    #[test]
    fn agree_version_cases() {
        let mk = |mn: u8, mx: u8| NegotiationHeader {
            version_min: mn,
            version_max: mx,
            features: 0,
        };
        assert_eq!(mk(1, 1).agree_version(&mk(1, 1)), Ok(1));
        assert_eq!(mk(1, 3).agree_version(&mk(1, 2)), Ok(2));
        assert_eq!(mk(2, 5).agree_version(&mk(1, 4)), Ok(4));
        assert!(mk(3, 5).agree_version(&mk(1, 2)).is_err());
    }

    #[test]
    fn fmp_features_match_upstream_profile_defaults() {
        let full = fmp_features(NodeProfile::Full);
        assert_eq!(full & FMP_FEAT_PROFILE_MASK, 0);
        assert!(full & FMP_FEAT_PROVIDES_SR != 0);
        assert!(full & FMP_FEAT_PROVIDES_RR != 0);
        assert!(full & FMP_FEAT_WANTS_SR != 0);
        assert!(full & FMP_FEAT_WANTS_RR != 0);

        let nonr = fmp_features(NodeProfile::NonRouting);
        assert_eq!(nonr & FMP_FEAT_PROFILE_MASK, 1);
        assert!(nonr & FMP_FEAT_PROVIDES_SR != 0);
        assert!(nonr & FMP_FEAT_PROVIDES_RR != 0);
        assert!(nonr & FMP_FEAT_WANTS_SR == 0);
        assert!(nonr & FMP_FEAT_WANTS_RR != 0);

        let leaf = fmp_features(NodeProfile::Leaf);
        assert_eq!(leaf & FMP_FEAT_PROFILE_MASK, 2);
        assert!(leaf & FMP_FEAT_PROVIDES_SR == 0);
        assert!(leaf & FMP_FEAT_PROVIDES_RR != 0);
        assert!(leaf & FMP_FEAT_WANTS_SR == 0);
        assert!(leaf & FMP_FEAT_WANTS_RR == 0);
    }

    #[test]
    fn pairing_rule_requires_one_full() {
        assert!(NodeProfile::valid_pairing(
            NodeProfile::Full,
            NodeProfile::Leaf
        ));
        assert!(NodeProfile::valid_pairing(
            NodeProfile::Leaf,
            NodeProfile::Full
        ));
        assert!(NodeProfile::valid_pairing(
            NodeProfile::Full,
            NodeProfile::Full
        ));
        assert!(!NodeProfile::valid_pairing(
            NodeProfile::Leaf,
            NodeProfile::Leaf
        ));
        assert!(!NodeProfile::valid_pairing(
            NodeProfile::NonRouting,
            NodeProfile::Leaf
        ));
    }

    #[test]
    fn unknown_profile_bits_rejected() {
        let h = NegotiationHeader {
            version_min: 1,
            version_max: 1,
            features: 3,
        };
        assert_eq!(h.node_profile(), None);
    }

    #[test]
    fn rekey_marker_roundtrip() {
        let mut bytes = [0u8; 80];
        let n = encode_payload(&mut bytes, 1, 1, 0, Some(0xDEADBEEF)).unwrap();
        assert_eq!(n, NEGOTIATION_HEADER_SIZE + 4 + 4);
        assert_eq!(rekey_of(&bytes[..n]), Ok(Some(0xDEADBEEF)));

        let found = find_tlv(&bytes[..n], TLV_REKEY_OF).unwrap().unwrap();
        assert_eq!(found, &0xDEADBEEFu32.to_le_bytes()[..]);
    }

    #[test]
    fn rekey_marker_absent_is_none() {
        let data = leaf_buf();
        assert_eq!(rekey_of(data.as_slice()), Ok(None));
        assert_eq!(find_tlv(data.as_slice(), TLV_REKEY_OF), Ok(None));
    }

    #[test]
    fn rekey_marker_malformed_is_error_not_absence() {
        // Header + TLV header declaring 4 bytes but only 3 present.
        let mut data = leaf_buf();
        data.push(&TLV_REKEY_OF.to_le_bytes());
        data.push(&4u16.to_le_bytes());
        data.push(&[1, 2, 3]);
        assert_eq!(
            rekey_of(data.as_slice()),
            Err(NegotiationError::TruncatedTlv)
        );
    }

    #[test]
    fn rekey_marker_wrong_value_length_is_error() {
        let mut data = leaf_buf();
        data.push(&TLV_REKEY_OF.to_le_bytes());
        data.push(&3u16.to_le_bytes());
        data.push(&[1, 2, 3]);
        assert_eq!(
            rekey_of(data.as_slice()),
            Err(NegotiationError::BadRekeyMarker)
        );
    }

    #[test]
    fn unknown_tlv_field_forward_compatible() {
        // An unknown field is skipped without error; a known field after it
        // is still found.
        let mut data = leaf_buf();
        data.push(&9999u16.to_le_bytes());
        data.push(&3u16.to_le_bytes());
        data.push(&[0xFF, 0xFE, 0xFD]);
        data.push(&TLV_REKEY_OF.to_le_bytes());
        data.push(&4u16.to_le_bytes());
        data.push(&7u32.to_le_bytes());
        assert_eq!(
            find_tlv(data.as_slice(), 9999).unwrap().unwrap(),
            &[0xFF, 0xFE, 0xFD]
        );
        assert_eq!(rekey_of(data.as_slice()), Ok(Some(7)));
    }

    #[test]
    fn truncated_tlv_header_is_error() {
        let mut data = leaf_buf();
        data.push(&[0x01, 0x00]);
        assert_eq!(
            find_tlv(data.as_slice(), TLV_REKEY_OF),
            Err(NegotiationError::TruncatedTlv)
        );
    }

    #[test]
    fn encode_fits_declared_max() {
        let mut buf = [0u8; NEGOTIATION_MAX_SIZE];
        assert!(encode_payload(&mut buf, 1, 1, u64::MAX, Some(u32::MAX)).is_some());
        let mut tiny = [0u8; 9];
        assert!(encode_payload(&mut tiny, 1, 1, 0, None).is_none());
    }

    #[test]
    fn split_msg2_and_msg3() {
        // Base-only payloads: no extra.
        let base2 = [0u8; noise::XX_HANDSHAKE_MSG2_SIZE];
        let (b, extra) = split_msg2_noise(&base2);
        assert_eq!(b.len(), noise::XX_HANDSHAKE_MSG2_SIZE);
        assert!(extra.is_none());

        // Base + encrypted-negotiation-sized extra (10B payload + 16B tag).
        let mut with_extra = [0u8; noise::XX_HANDSHAKE_MSG2_SIZE + 26];
        with_extra[noise::XX_HANDSHAKE_MSG2_SIZE] = 0xA5;
        let (b, extra) = split_msg2_noise(&with_extra);
        assert_eq!(b.len(), noise::XX_HANDSHAKE_MSG2_SIZE);
        let extra = extra.unwrap();
        assert_eq!(extra.len(), 26);
        assert_eq!(extra[0], 0xA5);

        // Exactly base size: no extra (upstream splits only when len > base).
        let base3 = [0u8; noise::XX_HANDSHAKE_MSG3_SIZE];
        let (_, extra) = split_msg3_noise(&base3);
        assert!(extra.is_none());

        let with_one = [0u8; noise::XX_HANDSHAKE_MSG3_SIZE + 1];
        let (_, extra) = split_msg3_noise(&with_one);
        assert_eq!(extra.unwrap().len(), 1);
    }
}
