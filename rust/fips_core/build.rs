fn main() {
    // Rebuild when any source file in this crate changes.
    println!("cargo:rerun-if-changed=src/");
}
