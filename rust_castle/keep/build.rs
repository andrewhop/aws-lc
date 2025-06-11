use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let linker_path = Path::new(&manifest_dir).join("fips_module_linker.ld");

    // Check if we're compiling for macOS
    if cfg!(target_os = "macos") {
        // Create an order file for section ordering
        let order_file = Path::new(&manifest_dir).join("section_order.txt");

        // Ensure the order_file exists and contains our section ordering
        if !order_file.exists() {
            let mut file = File::create(&order_file).unwrap();
            writeln!(file, "__TEXT,__fips_start").unwrap();
            writeln!(file, "__TEXT,__fips_text").unwrap();
            writeln!(file, "__TEXT,__fips_end").unwrap();
        }

        // Use the order file to control section placement
        println!(
            "cargo:rustc-link-arg=-Wl,-order_file,{}",
            order_file.to_str().unwrap()
        );

        // Create empty sections (optional, may not be necessary)
        println!("cargo:rustc-link-arg=-Wl,-sectcreate,__TEXT,__fips_start,/dev/null");
        println!("cargo:rustc-link-arg=-Wl,-sectcreate,__TEXT,__fips_text,/dev/null");
        println!("cargo:rustc-link-arg=-Wl,-sectcreate,__TEXT,__fips_end,/dev/null");
    } else {
        // For non-macOS (e.g., Linux), use the typical `-T` option
        println!(
            "cargo:rustc-link-arg=-Wl,-T,{}",
            linker_path.to_str().unwrap()
        );
    }

    // Make sure Cargo re-runs the build script if the linker script changes
    println!("cargo:rerun-if-changed={}", linker_path.to_str().unwrap());

    // Also rerun if we're on macOS and the order file changes
    if cfg!(target_os = "macos") {
        let order_file = Path::new(&manifest_dir).join("section_order.txt");
        println!("cargo:rerun-if-changed={}", order_file.to_str().unwrap());
    }
}
