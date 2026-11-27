fn main() {
    // Propagates the ESP-IDF build environment (link args, cfgs) from esp-idf-sys.
    embuild::espidf::sysenv::output();

    // Make the cargo profile visible to the firmware so benchmark logs identify their build.
    // OUT_DIR is <target>/<triple>/<profile>/build/<pkg>-<hash>/out.
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let profile = out_dir
        .ancestors()
        .nth(3)
        .and_then(|dir| dir.file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=FW_PROFILE={profile}");
    println!(
        "cargo:rustc-env=FW_OPT_LEVEL={}",
        std::env::var("OPT_LEVEL").unwrap_or_default()
    );
}
