fn main() {
    microfips_build::emit_all_keys();

    // Emit link-search for this crate's directory so the linker finds memory.x.
    // This replaces the old hardcoded path in .cargo/config.toml.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-search={manifest_dir}");

    // Track WiFi credential env vars so cargo rebuilds when they change.
    println!("cargo:rerun-if-env-changed=WIFI_SSID");
    println!("cargo:rerun-if-env-changed=WIFI_PASSWORD");
}
