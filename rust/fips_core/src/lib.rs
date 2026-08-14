// fips_core is written in no_std, no-allocation style: the FIPS boundary must
// not depend on the Rust standard library or a heap allocator, and the non-test
// code holds to that (no std/alloc use outside `#[cfg(test)]`).
//
// The crate is not yet *compiled* as `#![no_std]`. Doing so on stable Rust
// requires `panic = "abort"` throughout, which in turn requires rebuilding
// `core` with `-Zbuild-std` on nightly (precompiled `core` is unwind-based).
// Rather than pin all of AWS-LC to nightly, the attribute stays disabled until
// the toolchain supports this on stable. See rust/FIPS_INTEGRITY.md.
// #![cfg_attr(not(test), no_std)]

pub mod digest;
pub mod ffi;
pub mod integrity;
