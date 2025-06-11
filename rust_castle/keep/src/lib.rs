#![no_std]

#[cfg(test)]
extern crate std;

pub mod hash {
    pub mod sha256 {
        include!(concat!("../fips_src/hash/sha256.rs"));
    }
}
include!(concat!("../fips_src/integrity.rs"));
