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
pub type crypto_word_t = uint64_t;
#[no_mangle]
pub unsafe extern "C" fn ec_GFp_nistp_recode_scalar_bits(
    mut sign: *mut crypto_word_t,
    mut digit: *mut crypto_word_t,
    mut in_0: crypto_word_t,
) {
    let mut s: crypto_word_t = 0;
    let mut d: crypto_word_t = 0;
    s = !(in_0 >> 5 as libc::c_int).wrapping_sub(1 as libc::c_int as crypto_word_t);
    d = (((1 as libc::c_int) << 6 as libc::c_int) as crypto_word_t)
        .wrapping_sub(in_0)
        .wrapping_sub(1 as libc::c_int as crypto_word_t);
    d = d & s | in_0 & !s;
    d = (d >> 1 as libc::c_int).wrapping_add(d & 1 as libc::c_int as crypto_word_t);
    *sign = s & 1 as libc::c_int as crypto_word_t;
    *digit = d;
}
