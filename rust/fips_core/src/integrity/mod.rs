// Integrity check module for the Keep crate.
//
// This module provides functions to verify the integrity of the FIPS module
// by checking that critical functions are within the expected memory region and
// calculating a hash of the memory region.

use crate::digest::{
    Digest, sha1,
    sha2::{self, SHA256_DIGEST_LEN as DIGEST_LEN, sha256_digest as digest},
};

pub static AWS_LC_RUST_CORE_TEXT_HASH: [u8; 32] = [
    0xae, 0x2c, 0xea, 0x2a, 0xbd, 0xa6, 0xf3, 0xec, 0x97, 0x7f, 0x9b, 0xf6, 0x94, 0x9a, 0xfc, 0x83,
    0x68, 0x27, 0xcb, 0xa0, 0xa0, 0x9f, 0x6b, 0x6f, 0xde, 0x52, 0xcd, 0xe2, 0xcd, 0xff, 0x31, 0x80,
];

unsafe extern "C" {
    fn AWS_LC_fips_text_start(a: u8, b: u8) -> bool;
    fn AWS_LC_fips_text_end(a: u8, b: u8) -> u8;
}

#[cfg(test)]
mod mock_externals {
    // Mock implementations for tests
    #[unsafe(no_mangle)]
    pub extern "C" fn AWS_LC_fips_text_start(a: u8, b: u8) -> bool {
        true
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn AWS_LC_fips_text_end(a: u8, b: u8) -> u8 {
        a & b
    }
}

pub fn verify_fips_integrity() -> usize {
    // Get boundary addresses
    let start_addr = AWS_LC_fips_text_start as usize;
    let end_addr = AWS_LC_fips_text_end as usize;
    println!(
        "Rust FIPS module goes from\nAWS_LC_fips_text_start: {:?}\nAWS_LC_fips_text_end:   {:?}",
        start_addr, end_addr
    );

    // First verify that critical functions are within the FIPS boundary
    let functions = vec![
        ("constant_time_eq", constant_time_eq as usize),
        ("verify_fips_integrity", verify_fips_integrity as usize),
        ("get_fips_digest", get_fips_digest as usize),
        ("is_in_fips_boundary", is_in_fips_boundary as usize),
        ("sha1::sha1_digest", sha1::sha1_digest as usize),
        ("sha1::State::reset", sha1::State::reset as usize),
        ("sha1::State::new", sha1::State::new as usize),
        ("sha1::State::update", sha1::State::update as usize),
        ("sha1::State::finalize", sha1::State::finalize as usize),
        ("sha2::sha256_digest", sha2::sha256_digest as usize),
        ("sha2::SHA224::new", sha2::SHA224::default as usize),
        ("sha2::SHA224::update", sha2::SHA224::update as usize),
        ("sha2::SHA224::finalize", sha2::SHA224::finalize as usize),
        ("sha2::SHA256::new", sha2::SHA256::default as usize),
        ("sha2::SHA256::update", sha2::SHA256::update as usize),
        ("sha2::SHA256::finalize", sha2::SHA256::finalize as usize),
    ];
    for (name, addr) in &functions {
        if !is_in_fips_boundary(*addr, start_addr, end_addr) {
            panic!(
                "{} at {} is not within the FIPS boundary: {}-{}",
                name, addr, start_addr, end_addr
            );
        }
        println!(
            "{:22} at {:?} is within the Rust FIPS boundary!",
            name, addr
        );
    }
    functions.len()
}

#[allow(unused)]
pub fn verify_fips_functions_inside() {
    let start_addr = AWS_LC_fips_text_start as usize;
    let end_addr = AWS_LC_fips_text_end as usize;

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
    let start_addr = AWS_LC_fips_text_start as usize;
    let end_addr = AWS_LC_fips_text_end as usize;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::sha2;

    #[test]
    fn test_boundaries() {
        assert!(is_in_fips_boundary(100, 10, 300));
        assert!(!is_in_fips_boundary(100, 200, 300));
        // This test should not panic if the boundary functions are within bounds
        let start = AWS_LC_fips_text_start as usize;
        let end = AWS_LC_fips_text_end as usize;
        println!("FIPS module size {} bytes", end - start);

        // Create a vector of (name, address) tuples
        let mut functions = vec![
            ("constant_time_eq", constant_time_eq as usize),
            ("verify_fips_integrity", verify_fips_integrity as usize),
            (
                "verify_fips_functions_inside",
                verify_fips_functions_inside as usize,
            ),
            ("get_fips_digest", get_fips_digest as usize),
            ("is_in_fips_boundary", is_in_fips_boundary as usize),
            ("sha1::sha1_digest", sha1::sha1_digest as usize),
            ("sha1::State::reset", sha1::State::reset as usize),
            ("sha1::State::new", sha1::State::new as usize),
            ("sha1::State::update", sha1::State::update as usize),
            ("sha1::State::finalize", sha1::State::finalize as usize),
            ("sha2::sha256_digest", sha2::sha256_digest as usize),
            ("sha2::SHA224::new", sha2::SHA224::default as usize),
            ("sha2::SHA224::update", sha2::SHA224::update as usize),
            ("sha2::SHA224::finalize", sha2::SHA224::finalize as usize),
            ("sha2::SHA256::new", sha2::SHA256::default as usize),
            ("sha2::SHA256::update", sha2::SHA256::update as usize),
            ("sha2::SHA256::finalize", sha2::SHA256::finalize as usize),
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
