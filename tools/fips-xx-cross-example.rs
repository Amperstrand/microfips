//! Cross-implementation probe: upstream Noise XX responder over stdio.
//!
//! REFERENCE COPY — the live version lives (uncommitted, disposable) as
//! `examples/xx_cross.rs` in a FIPS `next`-branch worktree, e.g.
//! `git -C /home/ubuntu/src/fips worktree add /tmp/opencode/fips-next jmcorgan/next --detach`.
//! This copy persists the source against /tmp cleanup so the opt-in cross
//! test stays reproducible (AGENTS.md "Protocol dialect on the bench"):
//!
//!   cd <fips-next-worktree> && mkdir -p examples && cp <microfips>/tools/fips-xx-cross-example.rs examples/xx_cross.rs
//!   cargo build --release --example xx_cross
//!   FIPS_NEXT_CROSS_BIN=<worktree>/target/release/examples/xx_cross \
//!     cargo test -p fips-noise --features std xx_cross_interop
//!
//! Pinned against fips next `f1ff410f` (0.6.0-dev) — re-check the
//! `fips::noise::HandshakeState` API when the branch moves.
//!
//! Protocol (hex lines):
//!   stdin  line 1: our msg1 (33B)        -> stdout line 1: msg2 + enc(neg2)
//!   stdin  line 2: msg3 + enc(neg3)      -> stdout line 2: "OK <neg3-hex>" or "ERR <stage>"

use fips::noise::HandshakeState;
use secp256k1::Keypair;
use std::io::{BufRead, Write};

fn keypair_from_scalar(n: u8) -> Keypair {
    let secp = secp256k1::Secp256k1::new();
    let mut secret = [0u8; 32];
    secret[31] = n;
    let sk = secp256k1::SecretKey::from_slice(&secret).unwrap();
    Keypair::from_secret_key(&secp, &sk)
}

fn main() {
    let responder_keypair = keypair_from_scalar(20);
    let responder_epoch = 9u64.to_le_bytes();

    let mut responder = HandshakeState::new_responder(responder_keypair);
    responder.set_local_epoch(responder_epoch);

    let stdin = std::io::stdin();
    let mut locked = stdin.lock();
    let mut stdout = std::io::stdout();

    // Line 1: our msg1
    let mut line = String::new();
    locked.read_line(&mut line).unwrap();
    let msg1 = hex::decode(line.trim()).unwrap();
    match responder.read_message_1(&msg1) {
        Ok(()) => {}
        Err(e) => {
            writeln!(stdout, "ERR read_message_1: {e}").unwrap();
            return;
        }
    }

    // Respond with msg2 + encrypted negotiation payload
    let neg2 = b"NEG2-PROBE".to_vec();
    let mut msg2 = responder.write_message_2().unwrap();
    let enc2 = responder.encrypt_payload(&neg2).unwrap();
    msg2.extend_from_slice(&enc2);
    writeln!(stdout, "{}", hex::encode(&msg2)).unwrap();
    stdout.flush().unwrap();

    // Line 2: our msg3 (base + optional negotiation extra)
    let mut line = String::new();
    locked.read_line(&mut line).unwrap();
    let msg3 = hex::decode(line.trim()).unwrap();
    let base_size = fips::noise::HANDSHAKE_MSG3_SIZE;
    let (base3, extra3): (&[u8], Option<&[u8]>) = if msg3.len() > base_size {
        let (b, e) = msg3.split_at(base_size);
        (b, Some(e))
    } else {
        (&msg3[..], None)
    };
    match responder.read_message_3(base3) {
        Ok(()) => {}
        Err(e) => {
            writeln!(stdout, "ERR read_message_3(base): {e}").unwrap();
            return;
        }
    }
    match extra3 {
        Some(enc3) => match responder.decrypt_payload(enc3) {
            Ok(plain) => writeln!(stdout, "OK {}", hex::encode(&plain)).unwrap(),
            Err(e) => {
                writeln!(stdout, "ERR decrypt_payload(msg3-extra): {e}").unwrap()
            }
        },
        None => writeln!(stdout, "OK no-extra").unwrap(),
    }
}
