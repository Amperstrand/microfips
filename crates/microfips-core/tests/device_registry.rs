//! Issue #134 Tier 1 guard: device-registry.json stays public-only.
//!
//! Four layers, all CI-enforced via `cargo test -p microfips-core`:
//! 1. semantic — every device identity is either a fenced vector key
//!    (generator·N, N in [1, 255]) or a `RETRIEVE_FROM_*` marker. A raw hex
//!    secret pasted next to the test entries fails the build — the slip class
//!    pattern hooks (`.secret-patterns.txt`) cannot catch.
//! 2. cryptographic — each vector key's recorded npub/node_addr actually
//!    derive from BE32(N), so the registry and the derivation cannot drift
//!    apart and firmware identities stay byte-identical to the pre-#134
//!    keys.json values.
//! 3. literal-absence — the retired secret literals stay retired. Git history
//!    is deliberately not scanned (issue #134 Tier 0: rotation, not rewrite).
//! 4. cross-encoding — every entry's key representations agree: node_addr
//!    matches sha256(pubkey_x)[..16], and any bech32 `npub` field decodes to
//!    the same key as `npub_hex`. Added 2026-09-02 after the `linux` entry's
//!    `npub_hex` drifted from its own bech32 `npub` (stale vs rotated daemon
//!    key) — every MSG1 was silently dropped with no daemon log at INFO.

use microfips_core::identity::bech32;
use microfips_core::identity::NodeAddr;
use microfips_core::noise;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

const RETRIEVE_PREFIX: &str = "RETRIEVE_FROM_";

fn repo_root() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    while dir.pop() {
        if dir.join("device-registry.json").is_file() {
            return dir;
        }
    }
    panic!(
        "device-registry.json not found above {}",
        env!("CARGO_MANIFEST_DIR")
    );
}

fn load_registry() -> Value {
    let path = repo_root().join("device-registry.json");
    let content =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&content).expect("device-registry.json parses")
}

fn vector_mul(entry: &Value) -> Option<u64> {
    entry
        .pointer("/vector_key/generator_mul")
        .and_then(Value::as_u64)
}

fn assert_hex(s: &str, want_len: usize, ctx: &str) {
    assert_eq!(s.len(), want_len, "{ctx}: {want_len} hex chars expected");
    assert!(
        s.bytes().all(|b| b.is_ascii_hexdigit()),
        "{ctx}: hex digits expected"
    );
}

fn vector_nsec(n: u64) -> [u8; 32] {
    let mut nsec = [0u8; 32];
    nsec[31] = n as u8;
    nsec
}

#[test]
fn registry_is_public_only() {
    let registry = load_registry();
    let devices = registry["devices"].as_object().expect("devices object");
    assert!(!devices.is_empty());

    let mut vector_devices = 0;
    for (name, entry) in devices {
        if let Some(nsec) = entry["nsec_hex"].as_str() {
            let marker_ok = nsec.starts_with(RETRIEVE_PREFIX)
                && nsec[RETRIEVE_PREFIX.len()..]
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c == '_');
            assert!(
                marker_ok,
                "{name}: raw nsec_hex is forbidden (issue #134) — use vector_key.generator_mul \
                 for test identities or a RETRIEVE_FROM_* marker"
            );
            assert!(
                entry.get("vector_key").is_none(),
                "{name}: nsec_hex and vector_key are mutually exclusive"
            );
            continue;
        }

        let n = vector_mul(entry).unwrap_or_else(|| {
            panic!("{name}: missing identity — set vector_key.generator_mul or nsec_hex")
        });
        assert!(
            (1..=255).contains(&n),
            "{name}: generator_mul {n} outside the fenced vector-key set [1, 255]"
        );
        vector_devices += 1;

        let npub = entry["npub_hex"]
            .as_str()
            .unwrap_or_else(|| panic!("{name}: vector device must record its public npub_hex"));
        assert_hex(npub, 66, "{name} npub_hex");
        assert!(
            npub.starts_with("02") || npub.starts_with("03"),
            "{name}: npub_hex must be a compressed pubkey"
        );
        let addr = entry["node_addr"]
            .as_str()
            .unwrap_or_else(|| panic!("{name}: vector device must record its node_addr"));
        assert_hex(addr, 32, "{name} node_addr");
    }
    assert!(vector_devices >= 1, "no vector devices left to cross-check");
}

#[test]
fn registry_vector_keys_derive_recorded_npubs() {
    let registry = load_registry();
    let devices = registry["devices"].as_object().expect("devices object");

    for (name, entry) in devices {
        let Some(n) = vector_mul(entry) else {
            continue;
        };
        let npub_hex = entry["npub_hex"]
            .as_str()
            .unwrap_or_else(|| panic!("{name}: vector device must record npub_hex"));
        let addr_hex = entry["node_addr"]
            .as_str()
            .unwrap_or_else(|| panic!("{name}: vector device must record node_addr"));

        let derived = noise::ecdh_pubkey(&vector_nsec(n))
            .unwrap_or_else(|e| panic!("{name}: BE32({n}) is not a valid scalar: {e:?}"));
        assert_eq!(
            hex::encode(derived),
            npub_hex.to_lowercase(),
            "{name}: npub_hex does not match ecdh_pubkey(generator·{n}) — registry drift"
        );

        let x_only: [u8; 32] = derived[1..].try_into().unwrap();
        let addr = NodeAddr::from_pubkey_x(&x_only);
        assert_eq!(
            hex::encode(addr.as_bytes()),
            addr_hex.to_lowercase(),
            "{name}: node_addr does not match sha256(pubkey_x)[..16]"
        );
    }
}

/// Layer 4: the same key, in every encoding the registry records, must agree —
/// for ALL entries, not just vector devices (host entries with
/// `RETRIEVE_FROM_*` secrets are the ones no derivation check can reach, and
/// they are exactly the ones that rotate out from under the registry).
#[test]
fn registry_entries_are_cross_encoding_consistent() {
    let registry = load_registry();
    let devices = registry["devices"].as_object().expect("devices object");

    for (name, entry) in devices {
        let Some(npub_hex) = entry["npub_hex"].as_str() else {
            continue; // esp32c3-style entries record no identity by design
        };
        if npub_hex.starts_with(RETRIEVE_PREFIX) {
            continue; // mac-style entries carry markers until the host key is recorded
        }
        assert_hex(npub_hex, 66, "{name} npub_hex");
        let addr_hex = entry["node_addr"]
            .as_str()
            .unwrap_or_else(|| panic!("{name}: npub_hex present but node_addr missing"));
        assert_hex(addr_hex, 32, "{name} node_addr");

        let bytes = hex::decode(npub_hex.to_lowercase())
            .unwrap_or_else(|e| panic!("{name}: npub_hex is not hex: {e}"));
        let x_only: [u8; 32] = bytes[1..]
            .try_into()
            .unwrap_or_else(|_| panic!("{name}: npub_hex payload is not 32 bytes"));

        assert_eq!(
            hex::encode(NodeAddr::from_pubkey_x(&x_only).as_bytes()),
            addr_hex.to_lowercase(),
            "{name}: node_addr does not match sha256(pubkey_x)[..16]"
        );

        if let Some(npub_bech32) = entry["npub"].as_str() {
            let decoded = bech32::npub_to_x_only(npub_bech32)
                .unwrap_or_else(|| panic!("{name}: bech32 npub field does not decode"));
            assert_eq!(
                decoded, x_only,
                "{name}: npub (bech32) and npub_hex encode different keys — registry drift"
            );
        }
    }
}

// Retired literals are assembled at runtime so this file itself never
// contains them as greppable strings.
//
// Two fences:
//  - generator·N scalars (the old keys.json values): forbidden anywhere in
//    the tree EXCEPT `tests/` fixture directories — the offline vector-key
//    set the issue keeps for cross-impl golden vectors
//    (crates/microfips-core/tests/golden_vectors.json is CI-pinned
//    byte-identical to the upstream FIPS copy and legitimately uses them).
//  - the stale doc secrets and the leaked linux nsec prefix: forbidden
//    everywhere, no exceptions.
fn generator_literals() -> Vec<String> {
    (1..=12u64).map(|n| format!("{n:064x}")).collect()
}

fn always_retired_literals() -> Vec<String> {
    vec![
        // Stale doc secrets (docs/architecture.md, pre-#134) — first removed by
        // this task's redaction.
        [
            "ac68", "af89", "462e", "7ed2", "6ff6", "70c1", "86b4", "eeb5", "3c4e", "82d7", "2c8e",
            "f6ce", "c4e6", "76c7", "843f", "832e",
        ]
        .concat(),
        [
            "123c", "2c30", "1a7b", "3733", "9c42", "32d8", "290a", "b47a", "0a30", "4b52", "2748",
            "ba83", "dbdd", "e39f", "ceda", "38d8",
        ]
        .concat(),
        // Prefix of the leaked linux nsec removed in 5036247 (Tier 0) — full
        // value was never re-recorded; the prefix keeps a re-paste out.
        ["bbc8", "9064"].concat(),
    ]
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            if !matches!(
                name,
                ".git"
                    | "target"
                    | ".omo"
                    | ".sisyphus"
                    | ".opencode"
                    | ".playwright-mcp"
                    | "node_modules"
            ) {
                collect_files(&path, out);
            }
        } else {
            out.push(path);
        }
    }
}

#[test]
fn retired_secret_literals_are_absent() {
    let generators: Vec<Vec<u8>> = generator_literals()
        .into_iter()
        .map(|s| s.into_bytes())
        .collect();
    let always: Vec<Vec<u8>> = always_retired_literals()
        .into_iter()
        .map(|s| s.into_bytes())
        .collect();

    let mut files = Vec::new();
    collect_files(&repo_root(), &mut files);
    assert!(!files.is_empty(), "tree walk found nothing to scan");

    let mut scanned = 0;
    for path in &files {
        let Ok(content) = fs::read(path) else {
            continue;
        };
        scanned += 1;
        for literal in &always {
            assert!(
                !contains_subslice(&content, literal),
                "retired secret literal (first-4 `{}`) still present in {} — issue #134",
                String::from_utf8_lossy(&literal[..4.min(literal.len())]),
                path.display()
            );
        }
        let is_test_fixture = path
            .components()
            .any(|c| c.as_os_str() == std::ffi::OsStr::new("tests"));
        if is_test_fixture {
            continue;
        }
        for literal in &generators {
            assert!(
                !contains_subslice(&content, literal),
                "generator·N scalar (first-4 `{}`) outside the fenced tests/ vector-key \
                 set in {} — derive it or move it into a test fixture (issue #134)",
                String::from_utf8_lossy(&literal[..4.min(literal.len())]),
                path.display()
            );
        }
    }
    assert!(scanned > 100, "suspiciously few files scanned: {scanned}");
}
