#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
pub type __uint64_t = libc::c_ulong;
pub type uint64_t = __uint64_t;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn awslc_version_string() -> *const libc::c_char {
    return b"AWS-LC 1.52.1\0" as *const u8 as *const libc::c_char;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn is_fips_build() -> libc::c_int {
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn FIPS_service_indicator_before_call() -> uint64_t {
    return 0 as libc::c_int as uint64_t;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn FIPS_service_indicator_after_call() -> uint64_t {
    return 1 as libc::c_int as uint64_t;
}
