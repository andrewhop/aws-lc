// Integrity check module for the Keep crate.
//
// This module provides functions to verify the integrity of the SHA256 implementation
// by checking that critical functions are within the expected memory region and
// calculating a hash of the memory region.

#[unsafe(link_section = "__TEXT,__fips_b")]
#[unsafe(no_mangle)]
pub fn verify_fips_integrity() -> bool {
    // Get boundary addresses
    let start_addr = &fips_module_start as *const _ as usize;
    let end_addr = &fips_module_end as *const _ as usize;

    // First verify that critical functions are within the FIPS boundary
    if !is_function_in_fips_boundary(digest as usize, start_addr, end_addr) {
        return false;
    }

    if !is_function_in_fips_boundary(is_function_in_fips_boundary as usize, start_addr, end_addr) {
        return false;
    }

    let computed_hmac = get_fips_digest();

    let expected = [0, 0, 0, 0];
    constant_time_eq(&computed_hmac, &expected)
}

#[unsafe(link_section = "__TEXT,__fips_b")]
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
        ("sha256::digest", digest as usize),
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

#[unsafe(link_section = "__TEXT,__fips_b")]
#[unsafe(no_mangle)]
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

#[unsafe(link_section = "__TEXT,__fips_b")]
#[unsafe(no_mangle)]
fn is_function_in_fips_boundary(func_addr: usize, start_addr: usize, end_addr: usize) -> bool {
    // Check if the function address is within the FIPS boundary
    func_addr >= start_addr && func_addr < end_addr
}

#[unsafe(link_section = "__TEXT,__fips_b")]
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

#[unsafe(link_section = "__TEXT,__fips_b")]
pub fn fips_end_for_real(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

#[cfg(target_os = "macos")]
#[inline(never)]
#[unsafe(no_mangle)]
#[unsafe(link_section = "__TEXT,__fips_c")]
pub extern "C" fn fips_module_end(input: u8) -> u8 {
    // This function won't be called - it just serves as a marker
    input + 1
}
