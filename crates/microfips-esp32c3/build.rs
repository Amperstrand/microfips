fn main() {
    microfips_build::emit_all_keys();
    // Track WiFi credential env vars so cargo rebuilds when they change
    println!("cargo:rerun-if-env-changed=WIFI_SSID");
    println!("cargo:rerun-if-env-changed=WIFI_PASSWORD");

    // When espnow feature is enabled, explicitly link ESP-IDF WiFi/ESP-NOW
    // libraries. esp-wifi-sys-esp32c3 provides the .a files but its
    // cargo:rustc-link-lib directives don't propagate transitively through
    // esp-radio to the final binary when using raw FFI (not esp-radio's safe API).
    // The -L search path IS propagated; only the -l flags are missing.
    if std::env::var("CARGO_FEATURE_ESPNOW").is_ok() {
        // esp-radio's own static lib (provides __esp_radio_printf etc.)
        println!("cargo:rustc-link-lib=esp-radio");
        // ESP-IDF WiFi/ESP-NOW static libs from esp-wifi-sys-esp32c3
        for lib in [
            "espnow",
            "net80211",
            "phy",
            "pp",
            "coexist",
            "core",
            "wpa_supplicant",
            "mesh",
            "smartconfig",
            "wapi",
            "regulatory",
            "printf",
        ] {
            println!("cargo:rustc-link-lib={lib}");
        }
    }
}
