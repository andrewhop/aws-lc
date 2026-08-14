// Build script for the `fips_module` crate.
//
// This script assembles the FIPS integrity boundary. Rust/rustc offer no stable
// control over object-file placement or symbol ordering, so we impose the layout
// ourselves at the object-file level:
//
//   1. Compile the boundary markers (markers/start.rs, markers/end.rs) each as its
//      own staticlib, so each marker function lands in its own object file.
//   2. Extract the object files from libfips_core.a (the crypto code) and the two
//      marker archives with `ar x`.
//   3. Locate the objects that define the boundary/entry symbols with `nm`.
//   4. Concatenate them with `ld -r` in a fixed order -- start | fips_core | end --
//      producing one relocatable object whose .text runs contiguously from
//      AWS_LC_fips_text_start to AWS_LC_fips_text_end (the "FIPS oreo cookie").
//   5. Re-wrap that object as a static archive and tell cargo to link it.
//
// NOTE: this relies on a Unix-style binutils toolchain (`ar`, `nm`, `ld -r`) on
// PATH and is not portable to MSVC/Windows as written. See rust/FIPS_INTEGRITY.md
// for why this workaround exists and what compiler support would remove it.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let target = env::var("TARGET").unwrap();
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let workspace_dir = Path::new(&manifest_dir).parent().unwrap();
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let target_dir = workspace_dir.join("target").join(&profile);
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Step 1: compile the start/end boundary markers into their own archives.
    let start_lib = out_dir.join("start.a");
    compile_marker_to_archive("markers/start.rs", &start_lib, &target);
    let end_lib = out_dir.join("end.a");
    compile_marker_to_archive("markers/end.rs", &end_lib, &target);

    // All object-file surgery happens inside OUT_DIR so builds stay hermetic and
    // parallel builds do not race over a shared scratch directory.
    let temp_dir = out_dir.join("obj_temp");
    // Start from a clean scratch dir in case of an incremental rebuild.
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let lib_path = target_dir.join("libfips_core.a");
    if !lib_path.exists() {
        panic!(
            "fips_core static library not found at {}. It is produced by building \
             the fips_core crate in the same workspace; build the workspace with \
             `cargo build` so cargo emits libfips_core.a before fips_module links.",
            lib_path.display()
        );
    }

    // Step 2: extract the object files from each archive into the scratch dir.
    log(&format!("extracting object files from {}", lib_path.display()));
    extract_ar_contents(&lib_path, &temp_dir);
    extract_ar_contents(&start_lib, &temp_dir);
    extract_ar_contents(&end_lib, &temp_dir);

    // Step 3: find the object files that define the boundary/entry symbols.
    let fips_core = find_object_with_symbol(&temp_dir, "AWS_LC_FIPS_get_digest")
        .expect("could not find object file defining AWS_LC_FIPS_get_digest");
    let start_object = find_object_with_symbol(&temp_dir, "AWS_LC_fips_text_start")
        .expect("could not find object file defining AWS_LC_fips_text_start");
    let end_object = find_object_with_symbol(&temp_dir, "AWS_LC_fips_text_end")
        .expect("could not find object file defining AWS_LC_fips_text_end");

    // Step 4: relink into one object with a fixed section order: start | core | end.
    let combined_obj = out_dir.join("combined_fips_objects.o");
    log(&format!("combining object files into {}", combined_obj.display()));
    let status = Command::new("ld")
        .arg("-r")
        .arg(start_object)
        .arg(fips_core)
        .arg(end_object)
        .arg("-o")
        .arg(&combined_obj)
        .status()
        .expect("failed to execute ld");
    if !status.success() {
        panic!("ld -r failed to combine the FIPS object files");
    }

    // Step 5: wrap the combined object in a static archive and link it.
    cc::Build::new()
        .object(combined_obj)
        .compile("fips_objects");

    // Step 6: link the fips_objects static archive.
    println!("cargo:rustc-link-lib=static=fips_objects");

    // Rebuild when the fips_core archive changes.
    println!("cargo:rerun-if-changed={}", lib_path.display());
}

fn compile_marker_to_archive(source_file: &str, output_archive: &Path, target: &str) {
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    log(&format!(
        "compiling {} to {}",
        source_file,
        output_archive.display()
    ));

    let mut cmd = Command::new(&rustc);
    cmd.arg("--crate-type")
        .arg("staticlib")
        .arg("--target")
        .arg(target)
        .arg("-C")
        .arg("opt-level=2")
        .arg("-C")
        .arg("debuginfo=0")
        .arg("-o")
        .arg(output_archive)
        .arg(source_file);

    let output = cmd.output().expect("failed to execute rustc");
    if !output.status.success() {
        panic!(
            "failed to compile {}: {}",
            source_file,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // rustc may emit a `lib`-prefixed archive name; normalize it to what we asked for.
    let parent_dir = output_archive.parent().unwrap();
    let lib_prefixed = parent_dir.join(format!(
        "lib{}",
        output_archive.file_name().unwrap().to_str().unwrap()
    ));
    if lib_prefixed.exists() && lib_prefixed != *output_archive {
        fs::rename(&lib_prefixed, output_archive).expect("failed to rename compiled archive");
    }
}

// Extract the contents of an `ar` archive into `output_dir`.
fn extract_ar_contents(archive_path: &Path, output_dir: &Path) {
    let status = Command::new("ar")
        .arg("x")
        .arg(archive_path)
        .current_dir(output_dir)
        .status()
        .expect("failed to execute ar");
    if !status.success() {
        panic!("failed to extract object files from {}", archive_path.display());
    }
}

// Find the object file in `dir` that *defines* `symbol`. Matches whole symbol
// names from `nm` output rather than a substring, so a symbol whose name is a
// substring of another cannot produce a false match.
fn find_object_with_symbol(dir: &Path, symbol: &str) -> Option<PathBuf> {
    for entry in fs::read_dir(dir).expect("failed to read scratch directory") {
        let path = entry.expect("failed to read directory entry").path();
        if path.extension().map_or(false, |ext| ext == "o") {
            let output = Command::new("nm")
                .arg("--defined-only")
                .arg(&path)
                .output()
                .expect("failed to execute nm");
            if !output.status.success() {
                continue;
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            // nm lines look like: "<addr> T <symbol>" or "<addr> t <symbol>".
            // Some platforms prefix an underscore, so accept an exact match on the
            // symbol or its underscored form as the final whitespace-separated token.
            let underscored = format!("_{symbol}");
            let found = stdout.lines().any(|line| {
                line.split_whitespace()
                    .last()
                    .map_or(false, |name| name == symbol || name == underscored)
            });
            if found {
                return Some(path);
            }
        }
    }
    None
}

// Emit an informational build-script message. Plain stdout (not a `cargo:`
// directive) is shown only under `cargo build -vv`, so this does not spam
// ordinary builds the way `cargo:warning=` did.
fn log(message: &str) {
    println!("fips_module build: {message}");
}
