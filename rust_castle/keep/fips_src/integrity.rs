// Integrity check module for the Keep crate.
//
// This module provides functions to verify the integrity of the SHA256 implementation
// by checking that critical functions are within the expected memory region and
// calculating a hash of the memory region.

use crate::hash::sha256;

#[cfg(target_os = "macos")]
#[inline(never)]
#[unsafe(no_mangle)]
#[unsafe(link_section = "__TEXT,__fips_start")]
pub extern "C" fn fips_module_start(input: usize) -> usize {
    // This function won't be called - it just serves as a marker
    input * 2
}

#[cfg(target_os = "macos")]
#[inline(never)]
#[unsafe(no_mangle)]
#[unsafe(link_section = "__TEXT,__fips_end")]
pub extern "C" fn fips_module_end() {
    // This function won't be called - it just serves as a marker
}

#[unsafe(link_section = "__TEXT,__fips_text")]
#[unsafe(no_mangle)]
pub fn verify_fips_integrity() -> bool {
    // Get boundary addresses
    let start_addr = &fips_module_start as *const _ as usize;
    let end_addr = &fips_module_end as *const _ as usize;

    // First verify that critical functions are within the FIPS boundary
    if !is_function_in_fips_boundary(sha256::digest as usize, start_addr, end_addr) {
        return false;
    }

    if !is_function_in_fips_boundary(is_function_in_fips_boundary as usize, start_addr, end_addr) {
        return false;
    }

    let computed_hmac = get_fips_digest();

    let expected = [0, 0, 0, 0];
    constant_time_eq(&computed_hmac, &expected)
}

#[unsafe(link_section = "__TEXT,__fips_text")]
#[unsafe(no_mangle)]
pub fn verify_fips_functions_inside() {
    // Get boundary addresses
    let start_addr = fips_module_start as usize;
    let end_addr = fips_module_end as usize;

    let fips_functions = &[
        ("constant_time_eq", constant_time_eq as usize),
        (
            "is_function_in_fips_boundary",
            is_function_in_fips_boundary as usize,
        ),
        ("verify_fips_integrity", verify_fips_integrity as usize),
        ("sha256::digest", sha256::digest as usize),
    ];
    for (name, func_addr) in fips_functions {
        if !is_function_in_fips_boundary(*func_addr, start_addr, end_addr) {
            panic!(
                "{} at {} is not within the FIPS boundary: {}-{}",
                name, func_addr, start_addr, end_addr
            );
        }
    }
}

#[unsafe(link_section = "__TEXT,__fips_text")]
#[unsafe(no_mangle)]
pub fn get_fips_digest() -> [u8; sha256::DIGEST_LEN] {
    // Get boundary addresses
    let start_addr = fips_module_start as usize;
    let end_addr = fips_module_end as usize;

    let length = end_addr - start_addr;
    // TODO update to actually use HMAC
    let mut computed_digest = [0u8; sha256::DIGEST_LEN];

    unsafe {
        let code_slice = core::slice::from_raw_parts(start_addr as *const u8, length);
        sha256::digest(code_slice, &mut computed_digest);
    }
    computed_digest
}

#[unsafe(link_section = "__TEXT,__fips_text")]
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

#[unsafe(link_section = "__TEXT,__fips_text")]
#[unsafe(no_mangle)]
fn is_function_in_fips_boundary(func_addr: usize, start_addr: usize, end_addr: usize) -> bool {
    // Check if the function address is within the FIPS boundary
    func_addr >= start_addr && func_addr < end_addr
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::println;

    #[test]
    fn test_boundaries() {
        assert!(is_function_in_fips_boundary(100, 10, 300));
        assert!(!is_function_in_fips_boundary(100, 200, 300));
        // This test should not panic if the boundary functions are within bounds
        let start = fips_module_start as usize;
        let end = fips_module_end as usize;
        println!("start {}", start);
        println!("end {}", end);
        println!("size {}", end - start);
        println!("constant_time_eq {:?}", constant_time_eq as usize);

        verify_fips_functions_inside();
    }

    #[test]
    fn test_digest() {
        println!("{:?}", get_fips_digest());
    }

    #[test]
    fn test_start() {
        assert_eq!(10, fips_module_start(5));
    }

    // #[test]
    // fn test_intergity() {
    //     // This test should not panic if the SHA256 functions are within bounds
    //     assert_eq!(true, verify_fips_integrity());
    // }
}
