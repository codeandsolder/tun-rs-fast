fn main() {
    println!("cargo:rerun-if-env-changed=DOCS_RS");
    if std::env::var("DOCS_RS").is_ok() {
        println!("cargo:rustc-cfg=docsrs");
        return;
    }

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "windows" {
        #[cfg(feature = "bindgen")]
        if let Err(error) = build_wrapper_wintun() {
            eprintln!("failed to generate Wintun bindings: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(feature = "bindgen")]
fn build_wrapper_wintun() -> Result<(), String> {
    use std::{env, path::PathBuf};

    let header_path = "src/platform/windows/tun/wintun_functions.h";
    println!("cargo:rerun-if-changed={header_path}");

    let bindings = bindgen::Builder::default()
        .header(header_path)
        .allowlist_function("Wintun.*")
        .allowlist_type("WINTUN_.*")
        .dynamic_library_name("wintun")
        .dynamic_link_require_all(true)
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .map_err(|error| format!("unable to generate {header_path}: {error}"))?;

    let out_dir =
        env::var("OUT_DIR").map_err(|error| format!("OUT_DIR is unavailable: {error}"))?;
    println!("OUT_DIR = {out_dir}");
    bindings
        .write_to_file(PathBuf::from(out_dir).join("bindings.rs"))
        .map_err(|error| format!("unable to write bindings.rs: {error}"))
}
