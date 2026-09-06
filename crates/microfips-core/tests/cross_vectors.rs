//! Cross-implementation protocol pins (P5 cross-vectors expansion).
//!
//! Canonical source: Amperstrand/fips-protocol-defs-mvp
//! `vectors/fips-v0-cross-vectors.json` (profile fips-v0-ik-xk @ jmcorgan/fips
//! v0.4.0). The values below are embedded copies of that file's vectors; when
//! the canonical file changes, the drift gate in `.github/workflows/
//! protocol-drift.yml` flags the vendored constants first — update both
//! together. The IK msg1 golden here must equal golden_vectors_ik.rs's
//! GOLDEN_MSG1_HEX (microfips is the generator of record for that vector).

use microfips_core::generated::fips_protocol_types::{
    LinkMessageType, COMMON_PREFIX_SIZE, ESTABLISHED_HEADER_SIZE, HANDSHAKE_MSG1_SIZE,
    HANDSHAKE_MSG2_SIZE, TAG_SIZE,
};

const CANONICAL_LINK_TYPES: &[(&str, u8)] = &[
    ("SessionDatagram", 0x00),
    ("SenderReport", 0x01),
    ("ReceiverReport", 0x02),
    ("TreeAnnounce", 0x10),
    ("FilterAnnounce", 0x20),
    ("LookupRequest", 0x30),
    ("LookupResponse", 0x31),
    ("Disconnect", 0x50),
    ("Heartbeat", 0x51),
];

fn discriminant(v: LinkMessageType) -> u8 {
    v as u8
}

#[test]
fn link_message_types_match_canonical_vectors() {
    let cases = [
        LinkMessageType::SessionDatagram,
        LinkMessageType::SenderReport,
        LinkMessageType::ReceiverReport,
        LinkMessageType::TreeAnnounce,
        LinkMessageType::FilterAnnounce,
        LinkMessageType::LookupRequest,
        LinkMessageType::LookupResponse,
        LinkMessageType::Disconnect,
        LinkMessageType::Heartbeat,
    ];
    assert_eq!(cases.len(), CANONICAL_LINK_TYPES.len());
    for (variant, (name, byte)) in cases.iter().zip(CANONICAL_LINK_TYPES) {
        assert_eq!(
            discriminant(*variant),
            *byte,
            "{name} drifted from canonical vectors"
        );
    }
}

#[test]
fn frame_layouts_match_canonical_vectors() {
    // fmp_frame_layouts vectors: msg1_wire = 4+4+106, msg2_wire = 4+4+4+57,
    // established_min = 16+16.
    assert_eq!(COMMON_PREFIX_SIZE + 4 + HANDSHAKE_MSG1_SIZE, 114);
    assert_eq!(COMMON_PREFIX_SIZE + 4 + 4 + HANDSHAKE_MSG2_SIZE, 69);
    assert_eq!(ESTABLISHED_HEADER_SIZE + TAG_SIZE, 32);
}

#[test]
fn ik_msg1_golden_matches_canonical() {
    const CANONICAL_MSG1_HEX: &str = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f8fbabc9585161aace9b5957f305bdb278db340ca4389a1367b62ebfef36a1562f8baf6b700e6982034fe68dfeecc1a39d50186304acbfef02b0128a140ebb783ecb92b6c938d87a4f7";
    let msg1 = hex::decode(CANONICAL_MSG1_HEX).unwrap();
    assert_eq!(msg1.len(), HANDSHAKE_MSG1_SIZE as usize);
    assert!(
        matches!(msg1[0], 0x02 | 0x03),
        "msg1 must lead with a compressed ephemeral pubkey"
    );
}
