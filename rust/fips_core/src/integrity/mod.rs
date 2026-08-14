// Integrity check module for the fips_core crate.
//
// This module verifies the integrity of the FIPS module by:
//   1. checking that every critical function lies within the module's text
//      boundary [AWS_LC_fips_text_start, AWS_LC_fips_text_end), and
//   2. computing a SHA-256 digest over that contiguous code region.
//
// The boundary symbols are supplied by marker functions relinked around the
// module's code (see rust/fips_module/build.rs). A complete FIPS self-test also
// compares the digest against a known-good value. That comparison needs a
// post-link hash-injection step, which the Rust toolchain does not yet provide
// (see rust/FIPS_INTEGRITY.md); until then get_fips_digest exposes the computed
// digest for inspection rather than checking it against an embedded constant.

use crate::digest::{
    Digest, sha1,
    sha2::{self, SHA256_DIGEST_LEN as DIGEST_LEN, sha256_digest as digest},
};

unsafe extern "C" {
    fn AWS_LC_fips_text_start(a: u8, b: u8) -> bool;
    fn AWS_LC_fips_text_end(a: u8, b: u8) -> u8;
}

#[cfg(test)]
mod mock_externals {
    // Stand-in boundary symbols so the module's unit tests link without the
    // fips_module relink step. Their bodies are irrelevant; only their presence
    // as resolvable symbols matters.
    #[unsafe(no_mangle)]
    pub extern "C" fn AWS_LC_fips_text_start(_a: u8, _b: u8) -> bool {
        true
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn AWS_LC_fips_text_end(a: u8, b: u8) -> u8 {
        a & b
    }
}

// The critical functions that must reside inside the FIPS text boundary. The
// runtime check and the tests share this one list so they cannot drift apart.
fn fips_boundary_functions() -> [(&'static str, usize); 16] {
    [
        ("constant_time_eq", constant_time_eq as *const () as usize),
        ("verify_fips_integrity", verify_fips_integrity as *const () as usize),
        ("get_fips_digest", get_fips_digest as *const () as usize),
        ("is_in_fips_boundary", is_in_fips_boundary as *const () as usize),
        ("sha1::sha1_digest", sha1::sha1_digest as *const () as usize),
        ("sha1::State::reset", sha1::State::reset as *const () as usize),
        ("sha1::State::new", sha1::State::new as *const () as usize),
        ("sha1::State::update", sha1::State::update as *const () as usize),
        ("sha1::State::finalize", sha1::State::finalize as *const () as usize),
        ("sha2::sha256_digest", sha2::sha256_digest as *const () as usize),
        ("sha2::SHA224::new", sha2::SHA224::default as *const () as usize),
        ("sha2::SHA224::update", sha2::SHA224::update as *const () as usize),
        ("sha2::SHA224::finalize", sha2::SHA224::finalize as *const () as usize),
        ("sha2::SHA256::new", sha2::SHA256::default as *const () as usize),
        ("sha2::SHA256::update", sha2::SHA256::update as *const () as usize),
        ("sha2::SHA256::finalize", sha2::SHA256::finalize as *const () as usize),
    ]
}

/// Verify that every critical function lies within the FIPS text boundary.
///
/// Returns `true` when all functions are inside `[start, end)`, `false`
/// otherwise. This is the real pass/fail result of the boundary self-check.
pub fn verify_fips_integrity() -> bool {
    let start_addr = AWS_LC_fips_text_start as *const () as usize;
    let end_addr = AWS_LC_fips_text_end as *const () as usize;

    fips_boundary_functions()
        .iter()
        .all(|&(_, addr)| is_in_fips_boundary(addr, start_addr, end_addr))
}

/// Compute a SHA-256 digest over the module's contiguous text region.
///
/// See the module comment: comparing this against a known-good value awaits a
/// post-link hash-injection step, so this currently exposes the digest for
/// inspection rather than performing the comparison itself.
pub fn get_fips_digest() -> [u8; DIGEST_LEN] {
    let start_addr = AWS_LC_fips_text_start as *const () as usize;
    let end_addr = AWS_LC_fips_text_end as *const () as usize;

    let length = end_addr - start_addr;
    let mut computed_digest = [0u8; DIGEST_LEN];

    unsafe {
        let code_slice = core::slice::from_raw_parts(start_addr as *const u8, length);
        digest(code_slice, &mut computed_digest);
    }
    computed_digest
}

fn is_in_fips_boundary(func_addr: usize, start_addr: usize, end_addr: usize) -> bool {
    func_addr >= start_addr && func_addr < end_addr
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boundaries() {
        assert!(is_in_fips_boundary(100, 10, 300));
        assert!(!is_in_fips_boundary(100, 200, 300));
        assert!(!is_in_fips_boundary(300, 10, 300));
    }

    #[test]
    fn test_boundary_function_list_is_shared() {
        // Guards against the runtime check and tests drifting: the shared list
        // must cover the functions the module considers critical.
        let functions = fips_boundary_functions();
        assert_eq!(functions.len(), 16);
        assert!(functions.iter().all(|&(_, addr)| addr != 0));
    }
}
