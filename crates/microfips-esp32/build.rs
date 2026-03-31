use std::env;
use std::fs;
use std::path::Path;

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn parse_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

fn format_hex_array(bytes: &[u8]) -> String {
    let items: Vec<String> = bytes.iter().map(|b| format!("0x{b:02X}")).collect();
    format!("[{}]", items.join(", "))
}

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("secrets.rs");

    let wifi_ssid = env_or("WIFI_SSID", "");
    let wifi_pass = env_or("WIFI_PASS", "");
    let fips_host = env_or("FIPS_HOST", "0.0.0.0");
    let fips_port: u16 = env_or("FIPS_PORT", "2121")
        .parse()
        .expect("FIPS_PORT must be a valid u16");

    let fips_pub_hex = env_or(
        "FIPS_PUB",
        "020e7a0da01a255cde106a202ef4f573676ef9e24f1c8176d03ae83a2a3a037d21",
    );
    let device_secret_hex = env_or(
        "DEVICE_SECRET",
        "0000000000000000000000000000000000000000000000000000000000000002",
    );

    let fips_pub_bytes = parse_hex(&fips_pub_hex);
    assert_eq!(
        fips_pub_bytes.len(),
        33,
        "FIPS_PUB must be 66 hex chars (33 bytes)"
    );

    let device_secret_bytes = parse_hex(&device_secret_hex);
    assert_eq!(
        device_secret_bytes.len(),
        32,
        "DEVICE_SECRET must be 64 hex chars (32 bytes)"
    );

    let fips_pub_array = format_hex_array(&fips_pub_bytes);
    let device_secret_array = format_hex_array(&device_secret_bytes);

    let content = format!(
        r#"pub const WIFI_SSID: &str = {wifi_ssid:?};
pub const WIFI_PASS: &str = {wifi_pass:?};
pub const FIPS_HOST: &str = {fips_host:?};
pub const FIPS_PORT: u16 = {fips_port};
pub const FIPS_PUB: [u8; 33] = {fips_pub_array};
pub const DEVICE_SECRET: [u8; 32] = {device_secret_array};
"#,
    );

    fs::write(&dest_path, &content).unwrap();
    println!("cargo:rerun-if-env-changed=WIFI_SSID");
    println!("cargo:rerun-if-env-changed=WIFI_PASS");
    println!("cargo:rerun-if-env-changed=FIPS_HOST");
    println!("cargo:rerun-if-env-changed=FIPS_PORT");
    println!("cargo:rerun-if-env-changed=FIPS_PUB");
    println!("cargo:rerun-if-env-changed=DEVICE_SECRET");
}
