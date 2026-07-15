fn main() {
    microfips_build::emit_all_keys();

    // Provide our memory.x to the linker BEFORE esp-hal's, so that
    // linkall.x's INCLUDE memory.x finds our version with the expanded
    // dram2_seg needed for WiFi/Bluetooth precompiled blobs.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-search={manifest_dir}");

    println!("cargo:rerun-if-env-changed=WIFI_SSID");
    println!("cargo:rerun-if-env-changed=WIFI_PASSWORD");
}
