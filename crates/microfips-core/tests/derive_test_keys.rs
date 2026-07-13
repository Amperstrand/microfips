use microfips_core::identity;

#[test]
fn test_derive_test_nsec_deterministic() {
    let a = identity::derive_test_nsec(b"stm32", 1);
    let b = identity::derive_test_nsec(b"stm32", 1);
    assert_eq!(a, b, "same inputs must produce same key");
}

#[test]
fn test_derive_test_nsec_different_roles() {
    let stm32 = identity::derive_test_nsec(b"stm32", 1);
    let esp32 = identity::derive_test_nsec(b"esp32", 1);
    assert_ne!(stm32, esp32, "different roles must produce different keys");
}

#[test]
fn test_derive_test_nsec_different_sequences() {
    let seq1 = identity::derive_test_nsec(b"stm32", 1);
    let seq2 = identity::derive_test_nsec(b"stm32", 2);
    assert_ne!(
        seq1, seq2,
        "different sequences must produce different keys"
    );
}

#[test]
fn test_derive_test_nsec_nonzero() {
    let nsec = identity::derive_test_nsec(b"vps", 1);
    assert!(
        nsec.iter().any(|&b| b != 0),
        "derived key must not be all zeros"
    );
}

#[test]
fn test_derive_test_npub_valid() {
    let npub = identity::derive_test_npub(b"esp32", 1);
    assert_eq!(npub.len(), 33, "compressed pubkey must be 33 bytes");
    assert!(
        npub[0] == 0x02 || npub[0] == 0x03,
        "must be a valid compressed pubkey prefix"
    );
}

#[test]
fn test_derive_test_node_addr_correct_length() {
    let addr = identity::derive_test_node_addr(b"stm32", 1);
    assert_eq!(addr.len(), 16, "node addr must be 16 bytes");
}
