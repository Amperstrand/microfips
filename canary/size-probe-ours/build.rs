fn main() {
    // The esp (Xtensa) rustc target spec hard-injects `-Tlinkall.x`; normally
    // esp-hal's build script supplies that file. These probes deliberately
    // avoid esp-hal, so we provide our own generic linkall.x and put its
    // directory on the linker's script search path. Every other target gets
    // the same script directly via -T.
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if arch == "xtensa" {
        println!("cargo:rustc-link-arg=-Wl,-L{dir}");
    } else {
        println!("cargo:rustc-link-arg=-T{dir}/link-probe.ld");
    }
}
