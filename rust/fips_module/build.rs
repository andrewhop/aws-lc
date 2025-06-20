use std::env;
use std::fs::{self};
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // Get paths
    let target = env::var("TARGET").unwrap();
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let workspace_dir = Path::new(&manifest_dir).parent().unwrap();
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let target_dir = workspace_dir.join("target").join(&profile);
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = PathBuf::from(&out_dir);

    // Step 1: Compile start/end
    let start_lib = out_path.join("start.a");
    compile_marker_to_archive("markers/start.rs", &start_lib, &target);
    println!("cargo:warning=Created {}", start_lib.display());
    let end_lib = out_path.join("end.a");
    compile_marker_to_archive("markers/end.rs", &end_lib, &target);
    println!("cargo:warning=Created {}", end_lib.display());

    let temp_dir = target_dir.join("obj_temp");
    fs::create_dir_all(&temp_dir).unwrap();

    let lib_path = target_dir.join("libfips_core.a");
    if !lib_path.exists() {
        panic!("fips_core library not found at: {}", lib_path.display());
    }

    // Step 2: extract the fips_core, start, and end static archives
    println!("cargo:warning=Extracting object files from libfips_core.a...");
    extract_ar_contents(&lib_path, &temp_dir);
    extract_ar_contents(&start_lib, &temp_dir);
    extract_ar_contents(&end_lib, &temp_dir);

    // Step 3: Find the object file with our functions
    let fips_core = find_object_with_symbol(&temp_dir, "AWS_LC_FIPS_get_digest")
        .expect("Could not find object file with AWS_LC_FIPS_get_digest");
    println!(
        "cargo:warning=Found AWS_LC_FIPS_get_digest in {}",
        fips_core.display()
    );
    let start_object = find_object_with_symbol(&temp_dir, "AWS_LC_fips_text_start")
        .expect("Could not find object file with AWS_LC_fips_text_start");
    println!(
        "cargo:warning=Found AWS_LC_fips_text_start in {}",
        start_object.display()
    );
    let end_object = find_object_with_symbol(&temp_dir, "AWS_LC_fips_text_end")
        .expect("Could not find object file with AWS_LC_fips_text_end");
    println!(
        "cargo:warning=Found AWS_LC_fips_text_end in {}",
        end_object.display()
    );

    // Step 4: Combine object files into one FIPS oreo cookie: start - fips_core - end
    let combined_obj = target_dir.join("combined_fips_objects.o");
    println!(
        "cargo:warning=Combining object files into {}",
        combined_obj.display()
    );
    let status = Command::new("ld")
        .arg("-r")
        .arg(start_object)
        .arg(fips_core)
        .arg(end_object)
        .arg("-o")
        .arg(&combined_obj)
        .status()
        .expect("Failed to execute ld command");

    if !status.success() {
        panic!("cargo:warning=Failed to combine object files");
    }

    // Step 5: Link the combined object file back into a static archive so cargo will link it later
    cc::Build::new()
        .object(combined_obj)
        .compile("fips_objects");

    // Step 6: Tell cargo to link the fips_objects static archive
    println!("cargo:rustc-link-lib=static=fips_objects");

    // Clean up
    fs::remove_dir_all(temp_dir).unwrap();

    // Tell cargo when to rerun this script
    println!("cargo:rerun-if-changed={}", lib_path.display());
}

fn compile_marker_to_archive(source_file: &str, output_archive: &std::path::Path, target: &str) {
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());

    println!(
        "cargo:warning=Compiling {} to {}",
        source_file,
        output_archive.display()
    );

    let mut cmd = Command::new(&rustc);
    cmd.arg("--crate-type")
        .arg("staticlib")
        .arg("--target")
        .arg(target)
        .arg("-C")
        .arg("opt-level=2")
        .arg("-C")
        .arg("debuginfo=0")
        .arg("-o") // Use -o instead of --out-dir for direct output
        .arg(output_archive)
        .arg(source_file);

    println!("cargo:warning=Running: {:?}", cmd);

    let output = cmd.output().expect("Failed to execute rustc");

    if !output.status.success() {
        println!(
            "cargo:warning=rustc stdout: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        println!(
            "cargo:warning=rustc stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        panic!(
            "Failed to compile {}: {}",
            source_file,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Check if rustc created a lib-prefixed version and rename if needed
    let parent_dir = output_archive.parent().unwrap();
    let lib_prefixed = parent_dir.join(format!(
        "lib{}",
        output_archive.file_name().unwrap().to_str().unwrap()
    ));

    if lib_prefixed.exists() && lib_prefixed != *output_archive {
        println!(
            "cargo:warning=Renaming {} to {}",
            lib_prefixed.display(),
            output_archive.display()
        );
        std::fs::rename(&lib_prefixed, output_archive).expect("Failed to rename compiled library");
    }
}

// Function to extract contents of an ar archive
fn extract_ar_contents(archive_path: &Path, output_dir: &Path) {
    let status = Command::new("ar")
        .arg("x")
        .arg(archive_path)
        .current_dir(output_dir)
        .status()
        .expect("Failed to execute ar command");

    if !status.success() {
        panic!(
            "Failed to extract object files from {}",
            archive_path.display()
        );
    }
}

// Function to find object file containing a specific symbol
fn find_object_with_symbol(dir: &Path, symbol: &str) -> Option<PathBuf> {
    for entry in fs::read_dir(dir).expect("Failed to read directory") {
        let entry = entry.expect("Failed to read entry");
        let path = entry.path();

        if path.extension().map_or(false, |ext| ext == "o") {
            // Run nm on the object file
            let output = Command::new("nm")
                .arg("--defined-only")
                .arg(&path)
                .output()
                .expect("Failed to execute nm command");

            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.contains(symbol) {
                    return Some(path);
                }
            }
        }
    }

    None
}
