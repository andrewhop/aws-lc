use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let workspace_dir = Path::new(&manifest_dir).parent().unwrap();
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let target_dir = workspace_dir.join("target").join(&profile);

    // Write metadata file so other crates can find this crate's build artifacts
    let metadata_file = target_dir.join("fips_core_metadata.txt");
    let content = format!("{}|{}", manifest_dir, profile);
    fs::write(&metadata_file, content).unwrap();

    // Standard build process will continue
    println!("cargo:rerun-if-changed=src/");
}
