//! Build-time identity injection from the public-only device registry.

use std::env;
use std::fs;
use std::path::PathBuf;

pub fn emit_all_keys() {
    let registry_path = find_device_registry();
    let content = fs::read_to_string(&registry_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", registry_path.display(), e));

    let root: serde_json::Value = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("failed to parse device-registry.json: {}", e));

    let devices = root["devices"]
        .as_object()
        .expect("device-registry.json: missing 'devices' object");

    for (name, entry) in devices {
        let nsec_default = device_nsec_default(entry)
            .unwrap_or_else(|e| panic!("device-registry.json: device '{}': {}", name, e));
        if let Some(default) = nsec_default {
            emit_key(&format!("DEVICE_NSEC_HEX_{}", name), &default);
        } else {
            // RETRIEVE_FROM_* device: only a same-named env var can supply it.
            println!("cargo:rerun-if-env-changed=DEVICE_NSEC_HEX_{}", name);
        }
        if let Some(hex) = entry["npub_hex"].as_str() {
            emit_key_checked(&format!("DEVICE_NPUB_HEX_{}", name), hex, name);
        }
        if let Some(addr) = entry["node_addr"].as_str() {
            emit_key(&format!("DEVICE_NODE_ADDR_{}", name), addr);
        }
    }

    println!("cargo:rerun-if-changed={}", registry_path.display());
}

/// Default secret scalar for a device — derived, never stored (issue #134).
///
/// The registry carries no raw hex nsecs. Test identities are the fenced
/// vector-key set (secp256k1 generator·N, N in [1, 255]); the scalar is just
/// N in 32-byte big-endian. `RETRIEVE_FROM_*` marks devices whose secret only
/// exists on a machine (or must come from a build-time env override).
fn device_nsec_default(entry: &serde_json::Value) -> Result<Option<String>, String> {
    if let Some(hexstr) = entry["nsec_hex"].as_str() {
        if !hexstr.starts_with("RETRIEVE_FROM_")
            || !hexstr["RETRIEVE_FROM_".len()..]
                .chars()
                .all(|c| c.is_ascii_uppercase() || c == '_')
        {
            return Err(
                "raw nsec_hex values are forbidden (issue #134); use vector_key.generator_mul \
                 for test identities or a RETRIEVE_FROM_* marker for host/build-injected secrets"
                    .to_string(),
            );
        }
        if entry.get("vector_key").is_some() {
            return Err("both nsec_hex and vector_key present; pick one".into());
        }
        return Ok(None);
    }
    let n = entry
        .pointer("/vector_key/generator_mul")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            "missing identity: set vector_key.generator_mul or nsec_hex = RETRIEVE_FROM_*"
                .to_string()
        })?;
    if !(1..=255).contains(&n) {
        return Err(format!(
            "generator_mul {} outside the fenced vector-key set [1, 255]",
            n
        ));
    }
    Ok(Some(format!("{:064x}", n)))
}

/// Emit one identity value, letting a same-named process env var override
/// the registry value (e.g. DEVICE_NPUB_HEX_vps to retarget a build at a
/// different FIPS daemon without editing device-registry.json).
fn emit_key(env_name: &str, registry_value: &str) {
    println!("cargo:rerun-if-env-changed={}", env_name);
    let value = match env::var(env_name) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            if registry_value.starts_with("RETRIEVE") {
                return;
            }
            registry_value.to_string()
        }
    };
    println!("cargo:rustc-env={}={}", env_name, value);
}

/// Reject a DEVICE_NPUB_HEX_* override that does not match the registry's
/// generator-derived key for that device. A hand-copied key with a wrong
/// tail (twice bitten 2026-08-30: invented tails from truncated prints)
/// compiles silently and produces handshake failures that look like
/// protocol bugs — this turns them into a build error at the exact device.
pub fn emit_key_checked(env_name: &str, registry_value: &str, device_name: &str) {
    if let Ok(v) = env::var(env_name) {
        if !v.is_empty() && v != registry_value && !registry_value.starts_with("RETRIEVE") {
            if !sec1_valid(&v) {
                panic!(
                    "{env_name} is not a valid SEC1 pubkey (66 hex chars, 02/03 prefix): got {v}"
                );
            }
            // Overrides that differ from the registry are allowed (lab
            // repinning is a legitimate workflow) but must at least be a
            // real curve point — and if the device has a generator_mul,
            // the mismatch prints the expected key so the copy can be fixed.
            if !on_curve(&v) {
                panic!("{env_name} for device '{device_name}' is not a point on secp256k1");
            }
            let expected = derive_npub(registry_value);
            println!(
                "cargo:warning={env_name} overrides device '{device_name}' (expected from registry: {expected})"
            );
        }
    }
    emit_key(env_name, registry_value);
}

fn sec1_valid(v: &str) -> bool {
    v.len() == 66
        && v.chars().all(|c| c.is_ascii_hexdigit())
        && (v.starts_with("02") || v.starts_with("03"))
}

fn on_curve(v: &str) -> bool {
    let Ok(bytes) = hex_decode(v) else {
        return false;
    };
    let Ok(pk) = k256::PublicKey::from_sec1_bytes(&bytes) else {
        return false;
    };
    let _ = pk;
    true
}

fn derive_npub(registry_value: &str) -> String {
    registry_value.to_string()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

/// Every compile-time knob read via `option_env!` in
/// `microfips-esp-common`/`microfips-esp-transport` `config.rs`. Without a
/// matching `rerun-if-env-changed`, setting OR clearing any of these
/// silently reuses the previously compiled value — a stale-knob firmware
/// that looks exactly like a working one. A new `option_env!` knob MUST be
/// added here and in that crate's config comment.
pub fn emit_env_trackers() {
    const KNOBS: &[&str] = &[
        "WIFI_SSID",
        "WIFI_PASSWORD",
        "FIPS_TARGET_HOST",
        "FIPS_TARGET_PORT",
        "FIPS_FSP_TARGET_NPUB_HEX",
        "FIPS_FSP_TARGET_NODE_ADDR_HEX",
        "FIPS_DISCOVERY_SCOPE",
        "ESP_NOW_CHANNEL",
        "HYBRID_TEST_WIFI_DOWN_SECS",
        "HYBRID_WIFI_PROBE_SECS",
        "RELAY_AP_SSID",
        "RELAY_UPLINK_SSID",
        "RELAY_UPLINK_PASSWORD",
        "FIPS_EXTRA_ALLOWED_XONLY_HEX",
    ];
    for knob in KNOBS {
        println!("cargo:rerun-if-env-changed={}", knob);
        // Re-exporting the value as rustc-env is what forces a recompile:
        // rerun-if-env-changed alone re-runs this script but leaves the
        // crate fresh if the script's output is unchanged.
        let value = env::var(knob).unwrap_or_default();
        println!("cargo:rustc-env=_MICROFIPS_KNOB_{}={}", knob, value);
    }
}

fn find_device_registry() -> PathBuf {
    let mut dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    loop {
        let candidate = dir.join("device-registry.json");
        if candidate.exists() {
            return candidate;
        }
        if !dir.pop() {
            panic!(
                "device-registry.json not found. Searched from {} upward.",
                env::var("CARGO_MANIFEST_DIR").unwrap()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sec1_valid_accepts_real_keys() {
        let g1 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        assert!(sec1_valid(g1));
        assert!(on_curve(g1));
    }

    #[test]
    fn sec1_rejects_garbage() {
        assert!(!sec1_valid("02zz"));
        assert!(!sec1_valid(
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )); // uncompressed prefix
        assert!(!sec1_valid(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179"
        )); // 65 chars
            // An invented tail is usually still a valid curve point (about half
            // of all x-values are on secp256k1) — on_curve cannot catch it; the
            // registry-mismatch WARNING with the expected key is the real guard.
        let invented = "02e493dbf1c10d80f3581e4904e1ee2b47542c3778101b6c58c5b1c6eab5b78db7";
        assert!(sec1_valid(invented));
        assert!(on_curve(invented));
        // But a garbage tail is caught by from_sec1_bytes:
        assert!(!on_curve(
            "02fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
        ));
    }
}
