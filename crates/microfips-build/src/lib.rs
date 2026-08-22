//! Build-time key loading from keys.json for firmware identity injection.

use std::env;
use std::fs;
use std::path::PathBuf;

pub fn emit_all_keys() {
    let keys_path = find_keys_json();
    let content = fs::read_to_string(&keys_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", keys_path.display(), e));

    let root: serde_json::Value = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("failed to parse keys.json: {}", e));

    let devices = root["devices"]
        .as_object()
        .expect("keys.json: missing 'devices' object");

    for (name, entry) in devices {
        if let Some(hex) = entry["nsec_hex"].as_str() {
            emit_key(&format!("DEVICE_NSEC_HEX_{}", name), hex);
        }
        if let Some(hex) = entry["npub_hex"].as_str() {
            emit_key(&format!("DEVICE_NPUB_HEX_{}", name), hex);
        }
        if let Some(addr) = entry["node_addr"].as_str() {
            emit_key(&format!("DEVICE_NODE_ADDR_{}", name), addr);
        }
    }

    println!("cargo:rerun-if-changed={}", keys_path.display());
}

/// Emit one identity value, letting a same-named process env var override
/// the keys.json value (e.g. DEVICE_NPUB_HEX_vps to retarget a build at a
/// different FIPS daemon without editing keys.json).
fn emit_key(env_name: &str, keys_json_value: &str) {
    println!("cargo:rerun-if-env-changed={}", env_name);
    let value = match env::var(env_name) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            if keys_json_value.starts_with("RETRIEVE") {
                return;
            }
            keys_json_value.to_string()
        }
    };
    println!("cargo:rustc-env={}={}", env_name, value);
}

fn find_keys_json() -> PathBuf {
    let mut dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    loop {
        let candidate = dir.join("keys.json");
        if candidate.exists() {
            return candidate;
        }
        if !dir.pop() {
            panic!(
                "keys.json not found. Searched from {} upward.",
                env::var("CARGO_MANIFEST_DIR").unwrap()
            );
        }
    }
}
