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
            emit_key(&format!("DEVICE_NPUB_HEX_{}", name), hex);
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
