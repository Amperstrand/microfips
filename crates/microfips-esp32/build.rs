fn main() {
    microfips_build::emit_all_keys();

    // Only the classic-ESP32 BTDM blob (ble/l2cap builds) references the
    // three ROM scan/page callbacks missing from esp-rom-sys 0.1.5; overlay
    // the ROM PROVIDEs (see ld/esp32-btdm-rom-callbacks.ld for provenance).
    if std::env::var("CARGO_FEATURE_BLE").is_ok()
        || std::env::var("CARGO_FEATURE_L2CAP").is_ok()
    {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir");
        let ld = std::path::Path::new(&manifest_dir)
            .join("ld/esp32-btdm-rom-callbacks.ld");
        println!("cargo:rustc-link-arg-bins=-T{}", ld.display());
    }
    println!(
        "cargo:rerun-if-changed=ld/esp32-btdm-rom-callbacks.ld"
    );
}
