#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
pub type size_t = libc::c_ulong;
pub type fips_counter_t = libc::c_uint;
pub const fips_counter_max: fips_counter_t = 3;
pub const fips_counter_evp_aes_256_ctr: fips_counter_t = 3;
pub const fips_counter_evp_aes_128_ctr: fips_counter_t = 2;
pub const fips_counter_evp_aes_256_gcm: fips_counter_t = 1;
pub const fips_counter_evp_aes_128_gcm: fips_counter_t = 0;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn FIPS_mode() -> libc::c_int {
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn FIPS_is_entropy_cpu_jitter() -> libc::c_int {
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn FIPS_mode_set(mut on: libc::c_int) -> libc::c_int {
    return (on == FIPS_mode()) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn FIPS_read_counter(mut counter: fips_counter_t) -> size_t {
    return 0 as libc::c_int as size_t;
}
