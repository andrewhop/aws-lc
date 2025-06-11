#![no_std]

#[cfg(test)]
extern crate std;
#[cfg(target_os = "macos")]
#[inline(never)]
#[unsafe(no_mangle)]
#[unsafe(link_section = "__TEXT,__fips_a")]
pub extern "C" fn fips_module_start(input: usize) -> usize {
    // This function won't be called - it just serves as a marker
    input * 2
}

pub const FIPS_START_ADDRESS: usize = 0;
pub const FIPS_END_ADDRESS: usize = 0;

include!("../fips_src/integrity.rs");
include!("../fips_src/zhash/zsha256.rs");

#[cfg(test)]
mod tests {
    use super::*;
    use std::{println, vec};

    #[test]
    fn test_boundaries() {
        assert!(is_function_in_fips_boundary(100, 10, 300));
        assert!(!is_function_in_fips_boundary(100, 200, 300));
        // This test should not panic if the boundary functions are within bounds
        let start = fips_module_start as usize;
        let end = fips_module_end as usize;
        println!("size {}", end - start);

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
            (
                "is_function_in_fips_boundary",
                is_function_in_fips_boundary as usize,
            ),
            ("fips_end_for_real", fips_end_for_real as usize),
        ];

        // Sort by address
        functions.sort_by_key(|&(_, addr)| addr);

        // Print sorted functions
        for (name, addr) in functions {
            println!("{} \t\t{:?}", name, addr);
        }
        // println!(
        //     "&fips_module_start as *const _ as usize; = {}",
        //     &fips_module_start as *const _ as usize
        // );
        // println!(
        //     "&fips_module_end as *const _ as usize; = {}",
        //     &fips_module_end as *const _ as usize
        // );
        // println!(
        //     "fips_module_start as usize; = {}",
        //     fips_module_start as usize
        // );
        // println!("fips_module_end as usize; = {}", fips_module_end as usize);

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
