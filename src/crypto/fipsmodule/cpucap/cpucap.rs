#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
#[unsafe(no_mangle)]
pub static mut OPENSSL_ia32cap_P: [uint32_t; 4] = [
    0 as libc::c_int as uint32_t,
    0,
    0,
    0,
];
#[unsafe(no_mangle)]
pub static mut BORINGSSL_function_hit: [uint8_t; 9] = [
    0 as libc::c_int as uint8_t,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
];
#[unsafe(no_mangle)]
pub static mut OPENSSL_cpucap_initialized: uint8_t = 0 as libc::c_int as uint8_t;
