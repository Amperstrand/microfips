use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo::rustc-link-arg-bins=--nmagic");
    println!("cargo::rustc-link-arg-bins=-Tlink.x");

    // When defmt is OFF, generate an empty defmt.x so -Tdefmt.x in
    // .cargo/config.toml doesn't fail. When defmt IS ON, skip generation
    // so the defmt crate's real defmt.x (with _defmt_timestamp PROVIDE)
    // is found via its own cargo:rustc-link-search.
    if env::var("CARGO_FEATURE_DEFMT").is_err() {
        let out_dir = env::var("OUT_DIR").unwrap();
        let defmt_x = Path::new(&out_dir).join("defmt.x");
        fs::write(defmt_x, "").unwrap();
        println!("cargo::rustc-link-search={out_dir}");
    }
}
