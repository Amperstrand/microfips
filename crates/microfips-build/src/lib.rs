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
        "FIPS_DISCOVERY_SCOPE",
        "ESP_NOW_CHANNEL",
        "HYBRID_TEST_WIFI_DOWN_SECS",
        "HYBRID_WIFI_PROBE_SECS",
        "RELAY_AP_SSID",
        "RELAY_UPLINK_SSID",
        "RELAY_UPLINK_PASSWORD",
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
