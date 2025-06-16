// Integrity check module for the Keep crate.
//
// This module provides functions to verify the integrity of the FIPS module
// by checking that critical functions are within the expected memory region and
// calculating a hash of the memory region.

use crate::hash::sha2::{SHA256_DIGEST_LEN as DIGEST_LEN, sha256_digest as digest};

#[inline(never)]
pub fn fips_module_start(a: u8, b: u8) -> bool {
    a == b
}

pub fn verify_fips_integrity() -> bool {
    // Get boundary addresses
    let start_addr = &fips_module_start as *const _ as usize;
    let end_addr = &fips_module_end as *const _ as usize;

    // First verify that critical functions are within the FIPS boundary
    if !is_in_fips_boundary(digest as usize, start_addr, end_addr) {
        return false;
    }

    if !is_in_fips_boundary(is_in_fips_boundary as usize, start_addr, end_addr) {
        return false;
    }

    let computed_hmac = get_fips_digest();

    let expected = [0, 0, 0, 0];
    constant_time_eq(&computed_hmac, &expected)
}

pub fn verify_fips_functions_inside() {
    let start_addr = fips_module_start as usize;
    let end_addr = fips_module_end as usize;

    let fips_functions = &[
        ("constant_time_eq", constant_time_eq as usize),
        ("is_function_in_fips_boundary", is_in_fips_boundary as usize),
        ("verify_fips_integrity", verify_fips_integrity as usize),
        ("sha256::digest", digest as usize),
    ];
    for (name, func_addr) in fips_functions {
        if !is_in_fips_boundary(*func_addr, start_addr, end_addr) {
            panic!(
                "{} at {} is not within the FIPS boundary: {}-{}",
                name, func_addr, start_addr, end_addr
            );
        }
    }
}

pub fn get_fips_digest() -> [u8; DIGEST_LEN] {
    // Get boundary addresses
    let start_addr = fips_module_start as usize;
    let end_addr = fips_module_end as usize;

    let length = end_addr - start_addr;
    // TODO update to actually use HMAC
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

#[inline(never)]
fn fips_module_end(a: u8, b: u8) -> u8 {
    a ^ b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha2;

    #[test]
    fn test_boundaries() {
        assert!(is_in_fips_boundary(100, 10, 300));
        assert!(!is_in_fips_boundary(100, 200, 300));
        // This test should not panic if the boundary functions are within bounds
        let start = fips_module_start as usize;
        let end = fips_module_end as usize;
        println!("FIPS module size {} bytes", end - start);

        // Create a vector of (name, address) tuples
        let mut functions = vec![
            ("fips_module_start", start),
            ("fips_module_end", end),
            ("constant_time_eq", constant_time_eq as usize),
            ("verify_fips_integrity", verify_fips_integrity as usize),
            (
                "verify_fips_functions_inside",
                verify_fips_functions_inside as usize,
            ),
            ("get_fips_digest", get_fips_digest as usize),
            ("is_in_fips_boundary", is_in_fips_boundary as usize),
            ("sha2::sha256_digest", sha2::sha256_digest as usize),
            ("sha2::Context::reset", sha2::Context::reset as usize),
            (
                "sha2::Context::new_sha256",
                sha2::Context::new_sha256 as usize,
            ),
            (
                "sha2::Context::new_sha224",
                sha2::Context::new_sha224 as usize,
            ),
            ("sha2::Context::update", sha2::Context::update as usize),
            ("sha2::Context::finalize", sha2::Context::finalize as usize),
        ];

        // Sort by address
        functions.sort_by_key(|&(_, addr)| addr);

        // Print sorted functions
        for (name, addr) in functions {
            println!(
                "{:30}{:?} {:?}",
                name,
                addr,
                is_in_fips_boundary(addr, start, end)
            );
        }
        // TODO enforce this eventually
        // verify_fips_functions_inside();
    }

    #[test]
    fn test_digest() {
        println!("{:?}", get_fips_digest());
    }
}
