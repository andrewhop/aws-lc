#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(asm, extern_types, label_break_value)]
use core::arch::asm;
unsafe extern "C" {
    pub type bignum_ctx;
    fn BN_copy(dest: *mut BIGNUM, src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_value_one() -> *const BIGNUM;
    fn BN_num_bits(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_CTX_new() -> *mut BN_CTX;
    fn BN_CTX_free(ctx: *mut BN_CTX);
    fn BN_CTX_start(ctx: *mut BN_CTX);
    fn BN_CTX_get(ctx: *mut BN_CTX) -> *mut BIGNUM;
    fn BN_CTX_end(ctx: *mut BN_CTX);
    fn BN_add(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_add_word(a: *mut BIGNUM, w: BN_ULONG) -> libc::c_int;
    fn BN_sub(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_sub_word(a: *mut BIGNUM, w: BN_ULONG) -> libc::c_int;
    fn BN_div(
        quotient: *mut BIGNUM,
        rem: *mut BIGNUM,
        numerator: *const BIGNUM,
        divisor: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_cmp_word(a: *const BIGNUM, b: BN_ULONG) -> libc::c_int;
    fn BN_equal_consttime(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_is_one(bn: *const BIGNUM) -> libc::c_int;
    fn BN_is_word(bn: *const BIGNUM, w: BN_ULONG) -> libc::c_int;
    fn BN_is_odd(bn: *const BIGNUM) -> libc::c_int;
    fn BN_lshift1(r: *mut BIGNUM, a: *const BIGNUM) -> libc::c_int;
    fn BN_rshift(r: *mut BIGNUM, a: *const BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_rshift1(r: *mut BIGNUM, a: *const BIGNUM) -> libc::c_int;
    fn BN_is_bit_set(a: *const BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_count_low_zero_bits(bn: *const BIGNUM) -> libc::c_int;
    fn BN_mod_mul(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        b: *const BIGNUM,
        m: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_rand(
        rnd: *mut BIGNUM,
        bits: libc::c_int,
        top: libc::c_int,
        bottom: libc::c_int,
    ) -> libc::c_int;
    fn BN_rand_range_ex(
        r: *mut BIGNUM,
        min_inclusive: BN_ULONG,
        max_exclusive: *const BIGNUM,
    ) -> libc::c_int;
    fn BN_gcd(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        b: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_MONT_CTX_new_for_modulus(
        mod_0: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> *mut BN_MONT_CTX;
    fn BN_MONT_CTX_new_consttime(
        mod_0: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> *mut BN_MONT_CTX;
    fn BN_MONT_CTX_free(mont: *mut BN_MONT_CTX);
    fn BN_to_montgomery(
        ret: *mut BIGNUM,
        a: *const BIGNUM,
        mont: *const BN_MONT_CTX,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_mod_mul_montgomery(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        b: *const BIGNUM,
        mont: *const BN_MONT_CTX,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_mod_exp_mont(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        p: *const BIGNUM,
        m: *const BIGNUM,
        ctx: *mut BN_CTX,
        mont: *const BN_MONT_CTX,
    ) -> libc::c_int;
    fn BN_mod_exp_mont_consttime(
        rr: *mut BIGNUM,
        a: *const BIGNUM,
        p: *const BIGNUM,
        m: *const BIGNUM,
        ctx: *mut BN_CTX,
        mont: *const BN_MONT_CTX,
    ) -> libc::c_int;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn bn_rand_secret_range(
        r: *mut BIGNUM,
        out_is_uniform: *mut libc::c_int,
        min_inclusive: BN_ULONG,
        max_exclusive: *const BIGNUM,
    ) -> libc::c_int;
    fn bn_one_to_montgomery(
        r: *mut BIGNUM,
        mont: *const BN_MONT_CTX,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn bn_mod_u16_consttime(bn: *const BIGNUM, d: uint16_t) -> uint16_t;
    fn bn_rshift_secret_shift(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        n: libc::c_uint,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn bn_usub_consttime(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        b: *const BIGNUM,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type BN_CTX = bignum_ctx;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bignum_st {
    pub d: *mut BN_ULONG,
    pub width: libc::c_int,
    pub dmax: libc::c_int,
    pub neg: libc::c_int,
    pub flags: libc::c_int,
}
pub type BN_ULONG = uint64_t;
pub type BIGNUM = bignum_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bn_gencb_st {
    pub type_0: uint8_t,
    pub arg: *mut libc::c_void,
    pub callback: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub new_style: Option::<
        unsafe extern "C" fn(libc::c_int, libc::c_int, *mut bn_gencb_st) -> libc::c_int,
    >,
    pub old_style: Option::<
        unsafe extern "C" fn(libc::c_int, libc::c_int, *mut libc::c_void) -> (),
    >,
}
pub type BN_GENCB = bn_gencb_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bn_mont_ctx_st {
    pub RR: BIGNUM,
    pub N: BIGNUM,
    pub n0: [BN_ULONG; 2],
}
pub type BN_MONT_CTX = bn_mont_ctx_st;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_552_error_is_int_is_not_the_same_size_as_uint32_t {
    #[bitfield(
        name = "static_assertion_at_line_552_error_is_int_is_not_the_same_size_as_uint32_t",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_552_error_is_int_is_not_the_same_size_as_uint32_t: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
pub type crypto_word_t = uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct BN_MILLER_RABIN {
    pub w1: *mut BIGNUM,
    pub m: *mut BIGNUM,
    pub one_mont: *mut BIGNUM,
    pub w1_mont: *mut BIGNUM,
    pub w_bits: libc::c_int,
    pub a: libc::c_int,
}
pub type bn_primality_result_t = libc::c_uint;
pub const bn_non_prime_power_composite: bn_primality_result_t = 2;
pub const bn_composite: bn_primality_result_t = 1;
pub const bn_probably_prime: bn_primality_result_t = 0;
#[inline]
unsafe extern "C" fn value_barrier_w(mut a: crypto_word_t) -> crypto_word_t {
    asm!("", inlateout(reg) a, options(preserves_flags, pure, readonly, att_syntax));
    return a;
}
#[inline]
unsafe extern "C" fn value_barrier_u32(mut a: uint32_t) -> uint32_t {
    asm!("", inlateout(reg) a, options(preserves_flags, pure, readonly, att_syntax));
    return a;
}
#[inline]
unsafe extern "C" fn constant_time_msb_w(mut a: crypto_word_t) -> crypto_word_t {
    return (0 as libc::c_uint as crypto_word_t)
        .wrapping_sub(
            a
                >> (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        );
}
#[inline]
unsafe extern "C" fn constant_time_lt_w(
    mut a: crypto_word_t,
    mut b: crypto_word_t,
) -> crypto_word_t {
    return constant_time_msb_w(a ^ (a ^ b | a.wrapping_sub(b) ^ a));
}
#[inline]
unsafe extern "C" fn constant_time_is_zero_w(mut a: crypto_word_t) -> crypto_word_t {
    return constant_time_msb_w(!a & a.wrapping_sub(1 as libc::c_int as crypto_word_t));
}
#[inline]
unsafe extern "C" fn constant_time_eq_w(
    mut a: crypto_word_t,
    mut b: crypto_word_t,
) -> crypto_word_t {
    return constant_time_is_zero_w(a ^ b);
}
#[inline]
unsafe extern "C" fn constant_time_eq_int(
    mut a: libc::c_int,
    mut b: libc::c_int,
) -> crypto_word_t {
    return constant_time_eq_w(a as crypto_word_t, b as crypto_word_t);
}
#[inline]
unsafe extern "C" fn constant_time_declassify_w(mut v: crypto_word_t) -> crypto_word_t {
    return value_barrier_w(v);
}
#[inline]
unsafe extern "C" fn constant_time_declassify_int(mut v: libc::c_int) -> libc::c_int {
    return value_barrier_u32(v as uint32_t) as libc::c_int;
}
static mut kPrimes: [uint16_t; 1024] = [
    2 as libc::c_int as uint16_t,
    3 as libc::c_int as uint16_t,
    5 as libc::c_int as uint16_t,
    7 as libc::c_int as uint16_t,
    11 as libc::c_int as uint16_t,
    13 as libc::c_int as uint16_t,
    17 as libc::c_int as uint16_t,
    19 as libc::c_int as uint16_t,
    23 as libc::c_int as uint16_t,
    29 as libc::c_int as uint16_t,
    31 as libc::c_int as uint16_t,
    37 as libc::c_int as uint16_t,
    41 as libc::c_int as uint16_t,
    43 as libc::c_int as uint16_t,
    47 as libc::c_int as uint16_t,
    53 as libc::c_int as uint16_t,
    59 as libc::c_int as uint16_t,
    61 as libc::c_int as uint16_t,
    67 as libc::c_int as uint16_t,
    71 as libc::c_int as uint16_t,
    73 as libc::c_int as uint16_t,
    79 as libc::c_int as uint16_t,
    83 as libc::c_int as uint16_t,
    89 as libc::c_int as uint16_t,
    97 as libc::c_int as uint16_t,
    101 as libc::c_int as uint16_t,
    103 as libc::c_int as uint16_t,
    107 as libc::c_int as uint16_t,
    109 as libc::c_int as uint16_t,
    113 as libc::c_int as uint16_t,
    127 as libc::c_int as uint16_t,
    131 as libc::c_int as uint16_t,
    137 as libc::c_int as uint16_t,
    139 as libc::c_int as uint16_t,
    149 as libc::c_int as uint16_t,
    151 as libc::c_int as uint16_t,
    157 as libc::c_int as uint16_t,
    163 as libc::c_int as uint16_t,
    167 as libc::c_int as uint16_t,
    173 as libc::c_int as uint16_t,
    179 as libc::c_int as uint16_t,
    181 as libc::c_int as uint16_t,
    191 as libc::c_int as uint16_t,
    193 as libc::c_int as uint16_t,
    197 as libc::c_int as uint16_t,
    199 as libc::c_int as uint16_t,
    211 as libc::c_int as uint16_t,
    223 as libc::c_int as uint16_t,
    227 as libc::c_int as uint16_t,
    229 as libc::c_int as uint16_t,
    233 as libc::c_int as uint16_t,
    239 as libc::c_int as uint16_t,
    241 as libc::c_int as uint16_t,
    251 as libc::c_int as uint16_t,
    257 as libc::c_int as uint16_t,
    263 as libc::c_int as uint16_t,
    269 as libc::c_int as uint16_t,
    271 as libc::c_int as uint16_t,
    277 as libc::c_int as uint16_t,
    281 as libc::c_int as uint16_t,
    283 as libc::c_int as uint16_t,
    293 as libc::c_int as uint16_t,
    307 as libc::c_int as uint16_t,
    311 as libc::c_int as uint16_t,
    313 as libc::c_int as uint16_t,
    317 as libc::c_int as uint16_t,
    331 as libc::c_int as uint16_t,
    337 as libc::c_int as uint16_t,
    347 as libc::c_int as uint16_t,
    349 as libc::c_int as uint16_t,
    353 as libc::c_int as uint16_t,
    359 as libc::c_int as uint16_t,
    367 as libc::c_int as uint16_t,
    373 as libc::c_int as uint16_t,
    379 as libc::c_int as uint16_t,
    383 as libc::c_int as uint16_t,
    389 as libc::c_int as uint16_t,
    397 as libc::c_int as uint16_t,
    401 as libc::c_int as uint16_t,
    409 as libc::c_int as uint16_t,
    419 as libc::c_int as uint16_t,
    421 as libc::c_int as uint16_t,
    431 as libc::c_int as uint16_t,
    433 as libc::c_int as uint16_t,
    439 as libc::c_int as uint16_t,
    443 as libc::c_int as uint16_t,
    449 as libc::c_int as uint16_t,
    457 as libc::c_int as uint16_t,
    461 as libc::c_int as uint16_t,
    463 as libc::c_int as uint16_t,
    467 as libc::c_int as uint16_t,
    479 as libc::c_int as uint16_t,
    487 as libc::c_int as uint16_t,
    491 as libc::c_int as uint16_t,
    499 as libc::c_int as uint16_t,
    503 as libc::c_int as uint16_t,
    509 as libc::c_int as uint16_t,
    521 as libc::c_int as uint16_t,
    523 as libc::c_int as uint16_t,
    541 as libc::c_int as uint16_t,
    547 as libc::c_int as uint16_t,
    557 as libc::c_int as uint16_t,
    563 as libc::c_int as uint16_t,
    569 as libc::c_int as uint16_t,
    571 as libc::c_int as uint16_t,
    577 as libc::c_int as uint16_t,
    587 as libc::c_int as uint16_t,
    593 as libc::c_int as uint16_t,
    599 as libc::c_int as uint16_t,
    601 as libc::c_int as uint16_t,
    607 as libc::c_int as uint16_t,
    613 as libc::c_int as uint16_t,
    617 as libc::c_int as uint16_t,
    619 as libc::c_int as uint16_t,
    631 as libc::c_int as uint16_t,
    641 as libc::c_int as uint16_t,
    643 as libc::c_int as uint16_t,
    647 as libc::c_int as uint16_t,
    653 as libc::c_int as uint16_t,
    659 as libc::c_int as uint16_t,
    661 as libc::c_int as uint16_t,
    673 as libc::c_int as uint16_t,
    677 as libc::c_int as uint16_t,
    683 as libc::c_int as uint16_t,
    691 as libc::c_int as uint16_t,
    701 as libc::c_int as uint16_t,
    709 as libc::c_int as uint16_t,
    719 as libc::c_int as uint16_t,
    727 as libc::c_int as uint16_t,
    733 as libc::c_int as uint16_t,
    739 as libc::c_int as uint16_t,
    743 as libc::c_int as uint16_t,
    751 as libc::c_int as uint16_t,
    757 as libc::c_int as uint16_t,
    761 as libc::c_int as uint16_t,
    769 as libc::c_int as uint16_t,
    773 as libc::c_int as uint16_t,
    787 as libc::c_int as uint16_t,
    797 as libc::c_int as uint16_t,
    809 as libc::c_int as uint16_t,
    811 as libc::c_int as uint16_t,
    821 as libc::c_int as uint16_t,
    823 as libc::c_int as uint16_t,
    827 as libc::c_int as uint16_t,
    829 as libc::c_int as uint16_t,
    839 as libc::c_int as uint16_t,
    853 as libc::c_int as uint16_t,
    857 as libc::c_int as uint16_t,
    859 as libc::c_int as uint16_t,
    863 as libc::c_int as uint16_t,
    877 as libc::c_int as uint16_t,
    881 as libc::c_int as uint16_t,
    883 as libc::c_int as uint16_t,
    887 as libc::c_int as uint16_t,
    907 as libc::c_int as uint16_t,
    911 as libc::c_int as uint16_t,
    919 as libc::c_int as uint16_t,
    929 as libc::c_int as uint16_t,
    937 as libc::c_int as uint16_t,
    941 as libc::c_int as uint16_t,
    947 as libc::c_int as uint16_t,
    953 as libc::c_int as uint16_t,
    967 as libc::c_int as uint16_t,
    971 as libc::c_int as uint16_t,
    977 as libc::c_int as uint16_t,
    983 as libc::c_int as uint16_t,
    991 as libc::c_int as uint16_t,
    997 as libc::c_int as uint16_t,
    1009 as libc::c_int as uint16_t,
    1013 as libc::c_int as uint16_t,
    1019 as libc::c_int as uint16_t,
    1021 as libc::c_int as uint16_t,
    1031 as libc::c_int as uint16_t,
    1033 as libc::c_int as uint16_t,
    1039 as libc::c_int as uint16_t,
    1049 as libc::c_int as uint16_t,
    1051 as libc::c_int as uint16_t,
    1061 as libc::c_int as uint16_t,
    1063 as libc::c_int as uint16_t,
    1069 as libc::c_int as uint16_t,
    1087 as libc::c_int as uint16_t,
    1091 as libc::c_int as uint16_t,
    1093 as libc::c_int as uint16_t,
    1097 as libc::c_int as uint16_t,
    1103 as libc::c_int as uint16_t,
    1109 as libc::c_int as uint16_t,
    1117 as libc::c_int as uint16_t,
    1123 as libc::c_int as uint16_t,
    1129 as libc::c_int as uint16_t,
    1151 as libc::c_int as uint16_t,
    1153 as libc::c_int as uint16_t,
    1163 as libc::c_int as uint16_t,
    1171 as libc::c_int as uint16_t,
    1181 as libc::c_int as uint16_t,
    1187 as libc::c_int as uint16_t,
    1193 as libc::c_int as uint16_t,
    1201 as libc::c_int as uint16_t,
    1213 as libc::c_int as uint16_t,
    1217 as libc::c_int as uint16_t,
    1223 as libc::c_int as uint16_t,
    1229 as libc::c_int as uint16_t,
    1231 as libc::c_int as uint16_t,
    1237 as libc::c_int as uint16_t,
    1249 as libc::c_int as uint16_t,
    1259 as libc::c_int as uint16_t,
    1277 as libc::c_int as uint16_t,
    1279 as libc::c_int as uint16_t,
    1283 as libc::c_int as uint16_t,
    1289 as libc::c_int as uint16_t,
    1291 as libc::c_int as uint16_t,
    1297 as libc::c_int as uint16_t,
    1301 as libc::c_int as uint16_t,
    1303 as libc::c_int as uint16_t,
    1307 as libc::c_int as uint16_t,
    1319 as libc::c_int as uint16_t,
    1321 as libc::c_int as uint16_t,
    1327 as libc::c_int as uint16_t,
    1361 as libc::c_int as uint16_t,
    1367 as libc::c_int as uint16_t,
    1373 as libc::c_int as uint16_t,
    1381 as libc::c_int as uint16_t,
    1399 as libc::c_int as uint16_t,
    1409 as libc::c_int as uint16_t,
    1423 as libc::c_int as uint16_t,
    1427 as libc::c_int as uint16_t,
    1429 as libc::c_int as uint16_t,
    1433 as libc::c_int as uint16_t,
    1439 as libc::c_int as uint16_t,
    1447 as libc::c_int as uint16_t,
    1451 as libc::c_int as uint16_t,
    1453 as libc::c_int as uint16_t,
    1459 as libc::c_int as uint16_t,
    1471 as libc::c_int as uint16_t,
    1481 as libc::c_int as uint16_t,
    1483 as libc::c_int as uint16_t,
    1487 as libc::c_int as uint16_t,
    1489 as libc::c_int as uint16_t,
    1493 as libc::c_int as uint16_t,
    1499 as libc::c_int as uint16_t,
    1511 as libc::c_int as uint16_t,
    1523 as libc::c_int as uint16_t,
    1531 as libc::c_int as uint16_t,
    1543 as libc::c_int as uint16_t,
    1549 as libc::c_int as uint16_t,
    1553 as libc::c_int as uint16_t,
    1559 as libc::c_int as uint16_t,
    1567 as libc::c_int as uint16_t,
    1571 as libc::c_int as uint16_t,
    1579 as libc::c_int as uint16_t,
    1583 as libc::c_int as uint16_t,
    1597 as libc::c_int as uint16_t,
    1601 as libc::c_int as uint16_t,
    1607 as libc::c_int as uint16_t,
    1609 as libc::c_int as uint16_t,
    1613 as libc::c_int as uint16_t,
    1619 as libc::c_int as uint16_t,
    1621 as libc::c_int as uint16_t,
    1627 as libc::c_int as uint16_t,
    1637 as libc::c_int as uint16_t,
    1657 as libc::c_int as uint16_t,
    1663 as libc::c_int as uint16_t,
    1667 as libc::c_int as uint16_t,
    1669 as libc::c_int as uint16_t,
    1693 as libc::c_int as uint16_t,
    1697 as libc::c_int as uint16_t,
    1699 as libc::c_int as uint16_t,
    1709 as libc::c_int as uint16_t,
    1721 as libc::c_int as uint16_t,
    1723 as libc::c_int as uint16_t,
    1733 as libc::c_int as uint16_t,
    1741 as libc::c_int as uint16_t,
    1747 as libc::c_int as uint16_t,
    1753 as libc::c_int as uint16_t,
    1759 as libc::c_int as uint16_t,
    1777 as libc::c_int as uint16_t,
    1783 as libc::c_int as uint16_t,
    1787 as libc::c_int as uint16_t,
    1789 as libc::c_int as uint16_t,
    1801 as libc::c_int as uint16_t,
    1811 as libc::c_int as uint16_t,
    1823 as libc::c_int as uint16_t,
    1831 as libc::c_int as uint16_t,
    1847 as libc::c_int as uint16_t,
    1861 as libc::c_int as uint16_t,
    1867 as libc::c_int as uint16_t,
    1871 as libc::c_int as uint16_t,
    1873 as libc::c_int as uint16_t,
    1877 as libc::c_int as uint16_t,
    1879 as libc::c_int as uint16_t,
    1889 as libc::c_int as uint16_t,
    1901 as libc::c_int as uint16_t,
    1907 as libc::c_int as uint16_t,
    1913 as libc::c_int as uint16_t,
    1931 as libc::c_int as uint16_t,
    1933 as libc::c_int as uint16_t,
    1949 as libc::c_int as uint16_t,
    1951 as libc::c_int as uint16_t,
    1973 as libc::c_int as uint16_t,
    1979 as libc::c_int as uint16_t,
    1987 as libc::c_int as uint16_t,
    1993 as libc::c_int as uint16_t,
    1997 as libc::c_int as uint16_t,
    1999 as libc::c_int as uint16_t,
    2003 as libc::c_int as uint16_t,
    2011 as libc::c_int as uint16_t,
    2017 as libc::c_int as uint16_t,
    2027 as libc::c_int as uint16_t,
    2029 as libc::c_int as uint16_t,
    2039 as libc::c_int as uint16_t,
    2053 as libc::c_int as uint16_t,
    2063 as libc::c_int as uint16_t,
    2069 as libc::c_int as uint16_t,
    2081 as libc::c_int as uint16_t,
    2083 as libc::c_int as uint16_t,
    2087 as libc::c_int as uint16_t,
    2089 as libc::c_int as uint16_t,
    2099 as libc::c_int as uint16_t,
    2111 as libc::c_int as uint16_t,
    2113 as libc::c_int as uint16_t,
    2129 as libc::c_int as uint16_t,
    2131 as libc::c_int as uint16_t,
    2137 as libc::c_int as uint16_t,
    2141 as libc::c_int as uint16_t,
    2143 as libc::c_int as uint16_t,
    2153 as libc::c_int as uint16_t,
    2161 as libc::c_int as uint16_t,
    2179 as libc::c_int as uint16_t,
    2203 as libc::c_int as uint16_t,
    2207 as libc::c_int as uint16_t,
    2213 as libc::c_int as uint16_t,
    2221 as libc::c_int as uint16_t,
    2237 as libc::c_int as uint16_t,
    2239 as libc::c_int as uint16_t,
    2243 as libc::c_int as uint16_t,
    2251 as libc::c_int as uint16_t,
    2267 as libc::c_int as uint16_t,
    2269 as libc::c_int as uint16_t,
    2273 as libc::c_int as uint16_t,
    2281 as libc::c_int as uint16_t,
    2287 as libc::c_int as uint16_t,
    2293 as libc::c_int as uint16_t,
    2297 as libc::c_int as uint16_t,
    2309 as libc::c_int as uint16_t,
    2311 as libc::c_int as uint16_t,
    2333 as libc::c_int as uint16_t,
    2339 as libc::c_int as uint16_t,
    2341 as libc::c_int as uint16_t,
    2347 as libc::c_int as uint16_t,
    2351 as libc::c_int as uint16_t,
    2357 as libc::c_int as uint16_t,
    2371 as libc::c_int as uint16_t,
    2377 as libc::c_int as uint16_t,
    2381 as libc::c_int as uint16_t,
    2383 as libc::c_int as uint16_t,
    2389 as libc::c_int as uint16_t,
    2393 as libc::c_int as uint16_t,
    2399 as libc::c_int as uint16_t,
    2411 as libc::c_int as uint16_t,
    2417 as libc::c_int as uint16_t,
    2423 as libc::c_int as uint16_t,
    2437 as libc::c_int as uint16_t,
    2441 as libc::c_int as uint16_t,
    2447 as libc::c_int as uint16_t,
    2459 as libc::c_int as uint16_t,
    2467 as libc::c_int as uint16_t,
    2473 as libc::c_int as uint16_t,
    2477 as libc::c_int as uint16_t,
    2503 as libc::c_int as uint16_t,
    2521 as libc::c_int as uint16_t,
    2531 as libc::c_int as uint16_t,
    2539 as libc::c_int as uint16_t,
    2543 as libc::c_int as uint16_t,
    2549 as libc::c_int as uint16_t,
    2551 as libc::c_int as uint16_t,
    2557 as libc::c_int as uint16_t,
    2579 as libc::c_int as uint16_t,
    2591 as libc::c_int as uint16_t,
    2593 as libc::c_int as uint16_t,
    2609 as libc::c_int as uint16_t,
    2617 as libc::c_int as uint16_t,
    2621 as libc::c_int as uint16_t,
    2633 as libc::c_int as uint16_t,
    2647 as libc::c_int as uint16_t,
    2657 as libc::c_int as uint16_t,
    2659 as libc::c_int as uint16_t,
    2663 as libc::c_int as uint16_t,
    2671 as libc::c_int as uint16_t,
    2677 as libc::c_int as uint16_t,
    2683 as libc::c_int as uint16_t,
    2687 as libc::c_int as uint16_t,
    2689 as libc::c_int as uint16_t,
    2693 as libc::c_int as uint16_t,
    2699 as libc::c_int as uint16_t,
    2707 as libc::c_int as uint16_t,
    2711 as libc::c_int as uint16_t,
    2713 as libc::c_int as uint16_t,
    2719 as libc::c_int as uint16_t,
    2729 as libc::c_int as uint16_t,
    2731 as libc::c_int as uint16_t,
    2741 as libc::c_int as uint16_t,
    2749 as libc::c_int as uint16_t,
    2753 as libc::c_int as uint16_t,
    2767 as libc::c_int as uint16_t,
    2777 as libc::c_int as uint16_t,
    2789 as libc::c_int as uint16_t,
    2791 as libc::c_int as uint16_t,
    2797 as libc::c_int as uint16_t,
    2801 as libc::c_int as uint16_t,
    2803 as libc::c_int as uint16_t,
    2819 as libc::c_int as uint16_t,
    2833 as libc::c_int as uint16_t,
    2837 as libc::c_int as uint16_t,
    2843 as libc::c_int as uint16_t,
    2851 as libc::c_int as uint16_t,
    2857 as libc::c_int as uint16_t,
    2861 as libc::c_int as uint16_t,
    2879 as libc::c_int as uint16_t,
    2887 as libc::c_int as uint16_t,
    2897 as libc::c_int as uint16_t,
    2903 as libc::c_int as uint16_t,
    2909 as libc::c_int as uint16_t,
    2917 as libc::c_int as uint16_t,
    2927 as libc::c_int as uint16_t,
    2939 as libc::c_int as uint16_t,
    2953 as libc::c_int as uint16_t,
    2957 as libc::c_int as uint16_t,
    2963 as libc::c_int as uint16_t,
    2969 as libc::c_int as uint16_t,
    2971 as libc::c_int as uint16_t,
    2999 as libc::c_int as uint16_t,
    3001 as libc::c_int as uint16_t,
    3011 as libc::c_int as uint16_t,
    3019 as libc::c_int as uint16_t,
    3023 as libc::c_int as uint16_t,
    3037 as libc::c_int as uint16_t,
    3041 as libc::c_int as uint16_t,
    3049 as libc::c_int as uint16_t,
    3061 as libc::c_int as uint16_t,
    3067 as libc::c_int as uint16_t,
    3079 as libc::c_int as uint16_t,
    3083 as libc::c_int as uint16_t,
    3089 as libc::c_int as uint16_t,
    3109 as libc::c_int as uint16_t,
    3119 as libc::c_int as uint16_t,
    3121 as libc::c_int as uint16_t,
    3137 as libc::c_int as uint16_t,
    3163 as libc::c_int as uint16_t,
    3167 as libc::c_int as uint16_t,
    3169 as libc::c_int as uint16_t,
    3181 as libc::c_int as uint16_t,
    3187 as libc::c_int as uint16_t,
    3191 as libc::c_int as uint16_t,
    3203 as libc::c_int as uint16_t,
    3209 as libc::c_int as uint16_t,
    3217 as libc::c_int as uint16_t,
    3221 as libc::c_int as uint16_t,
    3229 as libc::c_int as uint16_t,
    3251 as libc::c_int as uint16_t,
    3253 as libc::c_int as uint16_t,
    3257 as libc::c_int as uint16_t,
    3259 as libc::c_int as uint16_t,
    3271 as libc::c_int as uint16_t,
    3299 as libc::c_int as uint16_t,
    3301 as libc::c_int as uint16_t,
    3307 as libc::c_int as uint16_t,
    3313 as libc::c_int as uint16_t,
    3319 as libc::c_int as uint16_t,
    3323 as libc::c_int as uint16_t,
    3329 as libc::c_int as uint16_t,
    3331 as libc::c_int as uint16_t,
    3343 as libc::c_int as uint16_t,
    3347 as libc::c_int as uint16_t,
    3359 as libc::c_int as uint16_t,
    3361 as libc::c_int as uint16_t,
    3371 as libc::c_int as uint16_t,
    3373 as libc::c_int as uint16_t,
    3389 as libc::c_int as uint16_t,
    3391 as libc::c_int as uint16_t,
    3407 as libc::c_int as uint16_t,
    3413 as libc::c_int as uint16_t,
    3433 as libc::c_int as uint16_t,
    3449 as libc::c_int as uint16_t,
    3457 as libc::c_int as uint16_t,
    3461 as libc::c_int as uint16_t,
    3463 as libc::c_int as uint16_t,
    3467 as libc::c_int as uint16_t,
    3469 as libc::c_int as uint16_t,
    3491 as libc::c_int as uint16_t,
    3499 as libc::c_int as uint16_t,
    3511 as libc::c_int as uint16_t,
    3517 as libc::c_int as uint16_t,
    3527 as libc::c_int as uint16_t,
    3529 as libc::c_int as uint16_t,
    3533 as libc::c_int as uint16_t,
    3539 as libc::c_int as uint16_t,
    3541 as libc::c_int as uint16_t,
    3547 as libc::c_int as uint16_t,
    3557 as libc::c_int as uint16_t,
    3559 as libc::c_int as uint16_t,
    3571 as libc::c_int as uint16_t,
    3581 as libc::c_int as uint16_t,
    3583 as libc::c_int as uint16_t,
    3593 as libc::c_int as uint16_t,
    3607 as libc::c_int as uint16_t,
    3613 as libc::c_int as uint16_t,
    3617 as libc::c_int as uint16_t,
    3623 as libc::c_int as uint16_t,
    3631 as libc::c_int as uint16_t,
    3637 as libc::c_int as uint16_t,
    3643 as libc::c_int as uint16_t,
    3659 as libc::c_int as uint16_t,
    3671 as libc::c_int as uint16_t,
    3673 as libc::c_int as uint16_t,
    3677 as libc::c_int as uint16_t,
    3691 as libc::c_int as uint16_t,
    3697 as libc::c_int as uint16_t,
    3701 as libc::c_int as uint16_t,
    3709 as libc::c_int as uint16_t,
    3719 as libc::c_int as uint16_t,
    3727 as libc::c_int as uint16_t,
    3733 as libc::c_int as uint16_t,
    3739 as libc::c_int as uint16_t,
    3761 as libc::c_int as uint16_t,
    3767 as libc::c_int as uint16_t,
    3769 as libc::c_int as uint16_t,
    3779 as libc::c_int as uint16_t,
    3793 as libc::c_int as uint16_t,
    3797 as libc::c_int as uint16_t,
    3803 as libc::c_int as uint16_t,
    3821 as libc::c_int as uint16_t,
    3823 as libc::c_int as uint16_t,
    3833 as libc::c_int as uint16_t,
    3847 as libc::c_int as uint16_t,
    3851 as libc::c_int as uint16_t,
    3853 as libc::c_int as uint16_t,
    3863 as libc::c_int as uint16_t,
    3877 as libc::c_int as uint16_t,
    3881 as libc::c_int as uint16_t,
    3889 as libc::c_int as uint16_t,
    3907 as libc::c_int as uint16_t,
    3911 as libc::c_int as uint16_t,
    3917 as libc::c_int as uint16_t,
    3919 as libc::c_int as uint16_t,
    3923 as libc::c_int as uint16_t,
    3929 as libc::c_int as uint16_t,
    3931 as libc::c_int as uint16_t,
    3943 as libc::c_int as uint16_t,
    3947 as libc::c_int as uint16_t,
    3967 as libc::c_int as uint16_t,
    3989 as libc::c_int as uint16_t,
    4001 as libc::c_int as uint16_t,
    4003 as libc::c_int as uint16_t,
    4007 as libc::c_int as uint16_t,
    4013 as libc::c_int as uint16_t,
    4019 as libc::c_int as uint16_t,
    4021 as libc::c_int as uint16_t,
    4027 as libc::c_int as uint16_t,
    4049 as libc::c_int as uint16_t,
    4051 as libc::c_int as uint16_t,
    4057 as libc::c_int as uint16_t,
    4073 as libc::c_int as uint16_t,
    4079 as libc::c_int as uint16_t,
    4091 as libc::c_int as uint16_t,
    4093 as libc::c_int as uint16_t,
    4099 as libc::c_int as uint16_t,
    4111 as libc::c_int as uint16_t,
    4127 as libc::c_int as uint16_t,
    4129 as libc::c_int as uint16_t,
    4133 as libc::c_int as uint16_t,
    4139 as libc::c_int as uint16_t,
    4153 as libc::c_int as uint16_t,
    4157 as libc::c_int as uint16_t,
    4159 as libc::c_int as uint16_t,
    4177 as libc::c_int as uint16_t,
    4201 as libc::c_int as uint16_t,
    4211 as libc::c_int as uint16_t,
    4217 as libc::c_int as uint16_t,
    4219 as libc::c_int as uint16_t,
    4229 as libc::c_int as uint16_t,
    4231 as libc::c_int as uint16_t,
    4241 as libc::c_int as uint16_t,
    4243 as libc::c_int as uint16_t,
    4253 as libc::c_int as uint16_t,
    4259 as libc::c_int as uint16_t,
    4261 as libc::c_int as uint16_t,
    4271 as libc::c_int as uint16_t,
    4273 as libc::c_int as uint16_t,
    4283 as libc::c_int as uint16_t,
    4289 as libc::c_int as uint16_t,
    4297 as libc::c_int as uint16_t,
    4327 as libc::c_int as uint16_t,
    4337 as libc::c_int as uint16_t,
    4339 as libc::c_int as uint16_t,
    4349 as libc::c_int as uint16_t,
    4357 as libc::c_int as uint16_t,
    4363 as libc::c_int as uint16_t,
    4373 as libc::c_int as uint16_t,
    4391 as libc::c_int as uint16_t,
    4397 as libc::c_int as uint16_t,
    4409 as libc::c_int as uint16_t,
    4421 as libc::c_int as uint16_t,
    4423 as libc::c_int as uint16_t,
    4441 as libc::c_int as uint16_t,
    4447 as libc::c_int as uint16_t,
    4451 as libc::c_int as uint16_t,
    4457 as libc::c_int as uint16_t,
    4463 as libc::c_int as uint16_t,
    4481 as libc::c_int as uint16_t,
    4483 as libc::c_int as uint16_t,
    4493 as libc::c_int as uint16_t,
    4507 as libc::c_int as uint16_t,
    4513 as libc::c_int as uint16_t,
    4517 as libc::c_int as uint16_t,
    4519 as libc::c_int as uint16_t,
    4523 as libc::c_int as uint16_t,
    4547 as libc::c_int as uint16_t,
    4549 as libc::c_int as uint16_t,
    4561 as libc::c_int as uint16_t,
    4567 as libc::c_int as uint16_t,
    4583 as libc::c_int as uint16_t,
    4591 as libc::c_int as uint16_t,
    4597 as libc::c_int as uint16_t,
    4603 as libc::c_int as uint16_t,
    4621 as libc::c_int as uint16_t,
    4637 as libc::c_int as uint16_t,
    4639 as libc::c_int as uint16_t,
    4643 as libc::c_int as uint16_t,
    4649 as libc::c_int as uint16_t,
    4651 as libc::c_int as uint16_t,
    4657 as libc::c_int as uint16_t,
    4663 as libc::c_int as uint16_t,
    4673 as libc::c_int as uint16_t,
    4679 as libc::c_int as uint16_t,
    4691 as libc::c_int as uint16_t,
    4703 as libc::c_int as uint16_t,
    4721 as libc::c_int as uint16_t,
    4723 as libc::c_int as uint16_t,
    4729 as libc::c_int as uint16_t,
    4733 as libc::c_int as uint16_t,
    4751 as libc::c_int as uint16_t,
    4759 as libc::c_int as uint16_t,
    4783 as libc::c_int as uint16_t,
    4787 as libc::c_int as uint16_t,
    4789 as libc::c_int as uint16_t,
    4793 as libc::c_int as uint16_t,
    4799 as libc::c_int as uint16_t,
    4801 as libc::c_int as uint16_t,
    4813 as libc::c_int as uint16_t,
    4817 as libc::c_int as uint16_t,
    4831 as libc::c_int as uint16_t,
    4861 as libc::c_int as uint16_t,
    4871 as libc::c_int as uint16_t,
    4877 as libc::c_int as uint16_t,
    4889 as libc::c_int as uint16_t,
    4903 as libc::c_int as uint16_t,
    4909 as libc::c_int as uint16_t,
    4919 as libc::c_int as uint16_t,
    4931 as libc::c_int as uint16_t,
    4933 as libc::c_int as uint16_t,
    4937 as libc::c_int as uint16_t,
    4943 as libc::c_int as uint16_t,
    4951 as libc::c_int as uint16_t,
    4957 as libc::c_int as uint16_t,
    4967 as libc::c_int as uint16_t,
    4969 as libc::c_int as uint16_t,
    4973 as libc::c_int as uint16_t,
    4987 as libc::c_int as uint16_t,
    4993 as libc::c_int as uint16_t,
    4999 as libc::c_int as uint16_t,
    5003 as libc::c_int as uint16_t,
    5009 as libc::c_int as uint16_t,
    5011 as libc::c_int as uint16_t,
    5021 as libc::c_int as uint16_t,
    5023 as libc::c_int as uint16_t,
    5039 as libc::c_int as uint16_t,
    5051 as libc::c_int as uint16_t,
    5059 as libc::c_int as uint16_t,
    5077 as libc::c_int as uint16_t,
    5081 as libc::c_int as uint16_t,
    5087 as libc::c_int as uint16_t,
    5099 as libc::c_int as uint16_t,
    5101 as libc::c_int as uint16_t,
    5107 as libc::c_int as uint16_t,
    5113 as libc::c_int as uint16_t,
    5119 as libc::c_int as uint16_t,
    5147 as libc::c_int as uint16_t,
    5153 as libc::c_int as uint16_t,
    5167 as libc::c_int as uint16_t,
    5171 as libc::c_int as uint16_t,
    5179 as libc::c_int as uint16_t,
    5189 as libc::c_int as uint16_t,
    5197 as libc::c_int as uint16_t,
    5209 as libc::c_int as uint16_t,
    5227 as libc::c_int as uint16_t,
    5231 as libc::c_int as uint16_t,
    5233 as libc::c_int as uint16_t,
    5237 as libc::c_int as uint16_t,
    5261 as libc::c_int as uint16_t,
    5273 as libc::c_int as uint16_t,
    5279 as libc::c_int as uint16_t,
    5281 as libc::c_int as uint16_t,
    5297 as libc::c_int as uint16_t,
    5303 as libc::c_int as uint16_t,
    5309 as libc::c_int as uint16_t,
    5323 as libc::c_int as uint16_t,
    5333 as libc::c_int as uint16_t,
    5347 as libc::c_int as uint16_t,
    5351 as libc::c_int as uint16_t,
    5381 as libc::c_int as uint16_t,
    5387 as libc::c_int as uint16_t,
    5393 as libc::c_int as uint16_t,
    5399 as libc::c_int as uint16_t,
    5407 as libc::c_int as uint16_t,
    5413 as libc::c_int as uint16_t,
    5417 as libc::c_int as uint16_t,
    5419 as libc::c_int as uint16_t,
    5431 as libc::c_int as uint16_t,
    5437 as libc::c_int as uint16_t,
    5441 as libc::c_int as uint16_t,
    5443 as libc::c_int as uint16_t,
    5449 as libc::c_int as uint16_t,
    5471 as libc::c_int as uint16_t,
    5477 as libc::c_int as uint16_t,
    5479 as libc::c_int as uint16_t,
    5483 as libc::c_int as uint16_t,
    5501 as libc::c_int as uint16_t,
    5503 as libc::c_int as uint16_t,
    5507 as libc::c_int as uint16_t,
    5519 as libc::c_int as uint16_t,
    5521 as libc::c_int as uint16_t,
    5527 as libc::c_int as uint16_t,
    5531 as libc::c_int as uint16_t,
    5557 as libc::c_int as uint16_t,
    5563 as libc::c_int as uint16_t,
    5569 as libc::c_int as uint16_t,
    5573 as libc::c_int as uint16_t,
    5581 as libc::c_int as uint16_t,
    5591 as libc::c_int as uint16_t,
    5623 as libc::c_int as uint16_t,
    5639 as libc::c_int as uint16_t,
    5641 as libc::c_int as uint16_t,
    5647 as libc::c_int as uint16_t,
    5651 as libc::c_int as uint16_t,
    5653 as libc::c_int as uint16_t,
    5657 as libc::c_int as uint16_t,
    5659 as libc::c_int as uint16_t,
    5669 as libc::c_int as uint16_t,
    5683 as libc::c_int as uint16_t,
    5689 as libc::c_int as uint16_t,
    5693 as libc::c_int as uint16_t,
    5701 as libc::c_int as uint16_t,
    5711 as libc::c_int as uint16_t,
    5717 as libc::c_int as uint16_t,
    5737 as libc::c_int as uint16_t,
    5741 as libc::c_int as uint16_t,
    5743 as libc::c_int as uint16_t,
    5749 as libc::c_int as uint16_t,
    5779 as libc::c_int as uint16_t,
    5783 as libc::c_int as uint16_t,
    5791 as libc::c_int as uint16_t,
    5801 as libc::c_int as uint16_t,
    5807 as libc::c_int as uint16_t,
    5813 as libc::c_int as uint16_t,
    5821 as libc::c_int as uint16_t,
    5827 as libc::c_int as uint16_t,
    5839 as libc::c_int as uint16_t,
    5843 as libc::c_int as uint16_t,
    5849 as libc::c_int as uint16_t,
    5851 as libc::c_int as uint16_t,
    5857 as libc::c_int as uint16_t,
    5861 as libc::c_int as uint16_t,
    5867 as libc::c_int as uint16_t,
    5869 as libc::c_int as uint16_t,
    5879 as libc::c_int as uint16_t,
    5881 as libc::c_int as uint16_t,
    5897 as libc::c_int as uint16_t,
    5903 as libc::c_int as uint16_t,
    5923 as libc::c_int as uint16_t,
    5927 as libc::c_int as uint16_t,
    5939 as libc::c_int as uint16_t,
    5953 as libc::c_int as uint16_t,
    5981 as libc::c_int as uint16_t,
    5987 as libc::c_int as uint16_t,
    6007 as libc::c_int as uint16_t,
    6011 as libc::c_int as uint16_t,
    6029 as libc::c_int as uint16_t,
    6037 as libc::c_int as uint16_t,
    6043 as libc::c_int as uint16_t,
    6047 as libc::c_int as uint16_t,
    6053 as libc::c_int as uint16_t,
    6067 as libc::c_int as uint16_t,
    6073 as libc::c_int as uint16_t,
    6079 as libc::c_int as uint16_t,
    6089 as libc::c_int as uint16_t,
    6091 as libc::c_int as uint16_t,
    6101 as libc::c_int as uint16_t,
    6113 as libc::c_int as uint16_t,
    6121 as libc::c_int as uint16_t,
    6131 as libc::c_int as uint16_t,
    6133 as libc::c_int as uint16_t,
    6143 as libc::c_int as uint16_t,
    6151 as libc::c_int as uint16_t,
    6163 as libc::c_int as uint16_t,
    6173 as libc::c_int as uint16_t,
    6197 as libc::c_int as uint16_t,
    6199 as libc::c_int as uint16_t,
    6203 as libc::c_int as uint16_t,
    6211 as libc::c_int as uint16_t,
    6217 as libc::c_int as uint16_t,
    6221 as libc::c_int as uint16_t,
    6229 as libc::c_int as uint16_t,
    6247 as libc::c_int as uint16_t,
    6257 as libc::c_int as uint16_t,
    6263 as libc::c_int as uint16_t,
    6269 as libc::c_int as uint16_t,
    6271 as libc::c_int as uint16_t,
    6277 as libc::c_int as uint16_t,
    6287 as libc::c_int as uint16_t,
    6299 as libc::c_int as uint16_t,
    6301 as libc::c_int as uint16_t,
    6311 as libc::c_int as uint16_t,
    6317 as libc::c_int as uint16_t,
    6323 as libc::c_int as uint16_t,
    6329 as libc::c_int as uint16_t,
    6337 as libc::c_int as uint16_t,
    6343 as libc::c_int as uint16_t,
    6353 as libc::c_int as uint16_t,
    6359 as libc::c_int as uint16_t,
    6361 as libc::c_int as uint16_t,
    6367 as libc::c_int as uint16_t,
    6373 as libc::c_int as uint16_t,
    6379 as libc::c_int as uint16_t,
    6389 as libc::c_int as uint16_t,
    6397 as libc::c_int as uint16_t,
    6421 as libc::c_int as uint16_t,
    6427 as libc::c_int as uint16_t,
    6449 as libc::c_int as uint16_t,
    6451 as libc::c_int as uint16_t,
    6469 as libc::c_int as uint16_t,
    6473 as libc::c_int as uint16_t,
    6481 as libc::c_int as uint16_t,
    6491 as libc::c_int as uint16_t,
    6521 as libc::c_int as uint16_t,
    6529 as libc::c_int as uint16_t,
    6547 as libc::c_int as uint16_t,
    6551 as libc::c_int as uint16_t,
    6553 as libc::c_int as uint16_t,
    6563 as libc::c_int as uint16_t,
    6569 as libc::c_int as uint16_t,
    6571 as libc::c_int as uint16_t,
    6577 as libc::c_int as uint16_t,
    6581 as libc::c_int as uint16_t,
    6599 as libc::c_int as uint16_t,
    6607 as libc::c_int as uint16_t,
    6619 as libc::c_int as uint16_t,
    6637 as libc::c_int as uint16_t,
    6653 as libc::c_int as uint16_t,
    6659 as libc::c_int as uint16_t,
    6661 as libc::c_int as uint16_t,
    6673 as libc::c_int as uint16_t,
    6679 as libc::c_int as uint16_t,
    6689 as libc::c_int as uint16_t,
    6691 as libc::c_int as uint16_t,
    6701 as libc::c_int as uint16_t,
    6703 as libc::c_int as uint16_t,
    6709 as libc::c_int as uint16_t,
    6719 as libc::c_int as uint16_t,
    6733 as libc::c_int as uint16_t,
    6737 as libc::c_int as uint16_t,
    6761 as libc::c_int as uint16_t,
    6763 as libc::c_int as uint16_t,
    6779 as libc::c_int as uint16_t,
    6781 as libc::c_int as uint16_t,
    6791 as libc::c_int as uint16_t,
    6793 as libc::c_int as uint16_t,
    6803 as libc::c_int as uint16_t,
    6823 as libc::c_int as uint16_t,
    6827 as libc::c_int as uint16_t,
    6829 as libc::c_int as uint16_t,
    6833 as libc::c_int as uint16_t,
    6841 as libc::c_int as uint16_t,
    6857 as libc::c_int as uint16_t,
    6863 as libc::c_int as uint16_t,
    6869 as libc::c_int as uint16_t,
    6871 as libc::c_int as uint16_t,
    6883 as libc::c_int as uint16_t,
    6899 as libc::c_int as uint16_t,
    6907 as libc::c_int as uint16_t,
    6911 as libc::c_int as uint16_t,
    6917 as libc::c_int as uint16_t,
    6947 as libc::c_int as uint16_t,
    6949 as libc::c_int as uint16_t,
    6959 as libc::c_int as uint16_t,
    6961 as libc::c_int as uint16_t,
    6967 as libc::c_int as uint16_t,
    6971 as libc::c_int as uint16_t,
    6977 as libc::c_int as uint16_t,
    6983 as libc::c_int as uint16_t,
    6991 as libc::c_int as uint16_t,
    6997 as libc::c_int as uint16_t,
    7001 as libc::c_int as uint16_t,
    7013 as libc::c_int as uint16_t,
    7019 as libc::c_int as uint16_t,
    7027 as libc::c_int as uint16_t,
    7039 as libc::c_int as uint16_t,
    7043 as libc::c_int as uint16_t,
    7057 as libc::c_int as uint16_t,
    7069 as libc::c_int as uint16_t,
    7079 as libc::c_int as uint16_t,
    7103 as libc::c_int as uint16_t,
    7109 as libc::c_int as uint16_t,
    7121 as libc::c_int as uint16_t,
    7127 as libc::c_int as uint16_t,
    7129 as libc::c_int as uint16_t,
    7151 as libc::c_int as uint16_t,
    7159 as libc::c_int as uint16_t,
    7177 as libc::c_int as uint16_t,
    7187 as libc::c_int as uint16_t,
    7193 as libc::c_int as uint16_t,
    7207 as libc::c_int as uint16_t,
    7211 as libc::c_int as uint16_t,
    7213 as libc::c_int as uint16_t,
    7219 as libc::c_int as uint16_t,
    7229 as libc::c_int as uint16_t,
    7237 as libc::c_int as uint16_t,
    7243 as libc::c_int as uint16_t,
    7247 as libc::c_int as uint16_t,
    7253 as libc::c_int as uint16_t,
    7283 as libc::c_int as uint16_t,
    7297 as libc::c_int as uint16_t,
    7307 as libc::c_int as uint16_t,
    7309 as libc::c_int as uint16_t,
    7321 as libc::c_int as uint16_t,
    7331 as libc::c_int as uint16_t,
    7333 as libc::c_int as uint16_t,
    7349 as libc::c_int as uint16_t,
    7351 as libc::c_int as uint16_t,
    7369 as libc::c_int as uint16_t,
    7393 as libc::c_int as uint16_t,
    7411 as libc::c_int as uint16_t,
    7417 as libc::c_int as uint16_t,
    7433 as libc::c_int as uint16_t,
    7451 as libc::c_int as uint16_t,
    7457 as libc::c_int as uint16_t,
    7459 as libc::c_int as uint16_t,
    7477 as libc::c_int as uint16_t,
    7481 as libc::c_int as uint16_t,
    7487 as libc::c_int as uint16_t,
    7489 as libc::c_int as uint16_t,
    7499 as libc::c_int as uint16_t,
    7507 as libc::c_int as uint16_t,
    7517 as libc::c_int as uint16_t,
    7523 as libc::c_int as uint16_t,
    7529 as libc::c_int as uint16_t,
    7537 as libc::c_int as uint16_t,
    7541 as libc::c_int as uint16_t,
    7547 as libc::c_int as uint16_t,
    7549 as libc::c_int as uint16_t,
    7559 as libc::c_int as uint16_t,
    7561 as libc::c_int as uint16_t,
    7573 as libc::c_int as uint16_t,
    7577 as libc::c_int as uint16_t,
    7583 as libc::c_int as uint16_t,
    7589 as libc::c_int as uint16_t,
    7591 as libc::c_int as uint16_t,
    7603 as libc::c_int as uint16_t,
    7607 as libc::c_int as uint16_t,
    7621 as libc::c_int as uint16_t,
    7639 as libc::c_int as uint16_t,
    7643 as libc::c_int as uint16_t,
    7649 as libc::c_int as uint16_t,
    7669 as libc::c_int as uint16_t,
    7673 as libc::c_int as uint16_t,
    7681 as libc::c_int as uint16_t,
    7687 as libc::c_int as uint16_t,
    7691 as libc::c_int as uint16_t,
    7699 as libc::c_int as uint16_t,
    7703 as libc::c_int as uint16_t,
    7717 as libc::c_int as uint16_t,
    7723 as libc::c_int as uint16_t,
    7727 as libc::c_int as uint16_t,
    7741 as libc::c_int as uint16_t,
    7753 as libc::c_int as uint16_t,
    7757 as libc::c_int as uint16_t,
    7759 as libc::c_int as uint16_t,
    7789 as libc::c_int as uint16_t,
    7793 as libc::c_int as uint16_t,
    7817 as libc::c_int as uint16_t,
    7823 as libc::c_int as uint16_t,
    7829 as libc::c_int as uint16_t,
    7841 as libc::c_int as uint16_t,
    7853 as libc::c_int as uint16_t,
    7867 as libc::c_int as uint16_t,
    7873 as libc::c_int as uint16_t,
    7877 as libc::c_int as uint16_t,
    7879 as libc::c_int as uint16_t,
    7883 as libc::c_int as uint16_t,
    7901 as libc::c_int as uint16_t,
    7907 as libc::c_int as uint16_t,
    7919 as libc::c_int as uint16_t,
    7927 as libc::c_int as uint16_t,
    7933 as libc::c_int as uint16_t,
    7937 as libc::c_int as uint16_t,
    7949 as libc::c_int as uint16_t,
    7951 as libc::c_int as uint16_t,
    7963 as libc::c_int as uint16_t,
    7993 as libc::c_int as uint16_t,
    8009 as libc::c_int as uint16_t,
    8011 as libc::c_int as uint16_t,
    8017 as libc::c_int as uint16_t,
    8039 as libc::c_int as uint16_t,
    8053 as libc::c_int as uint16_t,
    8059 as libc::c_int as uint16_t,
    8069 as libc::c_int as uint16_t,
    8081 as libc::c_int as uint16_t,
    8087 as libc::c_int as uint16_t,
    8089 as libc::c_int as uint16_t,
    8093 as libc::c_int as uint16_t,
    8101 as libc::c_int as uint16_t,
    8111 as libc::c_int as uint16_t,
    8117 as libc::c_int as uint16_t,
    8123 as libc::c_int as uint16_t,
    8147 as libc::c_int as uint16_t,
    8161 as libc::c_int as uint16_t,
];
unsafe extern "C" fn BN_prime_checks_for_size(mut bits: libc::c_int) -> libc::c_int {
    if bits >= 3747 as libc::c_int {
        return 3 as libc::c_int;
    }
    if bits >= 1345 as libc::c_int {
        return 4 as libc::c_int;
    }
    if bits >= 476 as libc::c_int {
        return 5 as libc::c_int;
    }
    if bits >= 400 as libc::c_int {
        return 6 as libc::c_int;
    }
    if bits >= 347 as libc::c_int {
        return 7 as libc::c_int;
    }
    if bits >= 308 as libc::c_int {
        return 8 as libc::c_int;
    }
    if bits >= 55 as libc::c_int {
        return 27 as libc::c_int;
    }
    return 34 as libc::c_int;
}
unsafe extern "C" fn num_trial_division_primes(mut n: *const BIGNUM) -> size_t {
    if (*n).width * 64 as libc::c_int > 1024 as libc::c_int {
        return (::core::mem::size_of::<[uint16_t; 1024]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<uint16_t>() as libc::c_ulong);
    }
    return (::core::mem::size_of::<[uint16_t; 1024]>() as libc::c_ulong)
        .wrapping_div(::core::mem::size_of::<uint16_t>() as libc::c_ulong)
        .wrapping_div(2 as libc::c_int as libc::c_ulong);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_GENCB_new() -> *mut BN_GENCB {
    return OPENSSL_zalloc(::core::mem::size_of::<BN_GENCB>() as libc::c_ulong)
        as *mut BN_GENCB;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_GENCB_free(mut callback: *mut BN_GENCB) {
    OPENSSL_free(callback as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_GENCB_set(
    mut callback: *mut BN_GENCB,
    mut f: Option::<
        unsafe extern "C" fn(libc::c_int, libc::c_int, *mut bn_gencb_st) -> libc::c_int,
    >,
    mut arg: *mut libc::c_void,
) {
    (*callback).type_0 = 1 as libc::c_int as uint8_t;
    (*callback).callback.new_style = f;
    (*callback).arg = arg;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_GENCB_set_old(
    mut callback: *mut BN_GENCB,
    mut f: Option::<
        unsafe extern "C" fn(libc::c_int, libc::c_int, *mut libc::c_void) -> (),
    >,
    mut arg: *mut libc::c_void,
) {
    (*callback).type_0 = 2 as libc::c_int as uint8_t;
    (*callback).callback.old_style = f;
    (*callback).arg = arg;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_GENCB_call(
    mut callback: *mut BN_GENCB,
    mut event: libc::c_int,
    mut n: libc::c_int,
) -> libc::c_int {
    if callback.is_null() {
        return 1 as libc::c_int;
    }
    if (*callback).type_0 as libc::c_int == 1 as libc::c_int {
        return ((*callback).callback.new_style)
            .expect("non-null function pointer")(event, n, callback)
    } else if (*callback).type_0 as libc::c_int == 2 as libc::c_int {
        ((*callback).callback.old_style)
            .expect(
                "non-null function pointer",
            )(event, n, callback as *mut libc::c_void);
        return 1 as libc::c_int;
    } else {
        return 0 as libc::c_int
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_GENCB_get_arg(
    mut callback: *const BN_GENCB,
) -> *mut libc::c_void {
    return (*callback).arg;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_generate_prime_ex(
    mut ret: *mut BIGNUM,
    mut bits: libc::c_int,
    mut safe: libc::c_int,
    mut add: *const BIGNUM,
    mut rem: *const BIGNUM,
    mut cb: *mut BN_GENCB,
) -> libc::c_int {
    let mut current_block: u64;
    let mut t: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut found: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    let mut c1: libc::c_int = 0 as libc::c_int;
    let mut ctx: *mut BN_CTX = 0 as *mut BN_CTX;
    let mut checks: libc::c_int = BN_prime_checks_for_size(bits);
    if bits < 2 as libc::c_int {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            103 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/prime.c\0"
                as *const u8 as *const libc::c_char,
            408 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    } else if bits == 2 as libc::c_int && safe != 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            103 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/prime.c\0"
                as *const u8 as *const libc::c_char,
            412 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    ctx = BN_CTX_new();
    if !ctx.is_null() {
        BN_CTX_start(ctx);
        t = BN_CTX_get(ctx);
        if !t.is_null() {
            '_loop: loop {
                if add.is_null() {
                    if probable_prime(ret, bits) == 0 {
                        current_block = 12755824767588802570;
                        break;
                    }
                } else if safe != 0 {
                    if probable_prime_dh_safe(ret, bits, add, rem, ctx) == 0 {
                        current_block = 12755824767588802570;
                        break;
                    }
                } else if probable_prime_dh(ret, bits, add, rem, ctx) == 0 {
                    current_block = 12755824767588802570;
                    break;
                }
                let fresh0 = c1;
                c1 = c1 + 1;
                if BN_GENCB_call(cb, 0 as libc::c_int, fresh0) == 0 {
                    current_block = 12755824767588802570;
                    break;
                }
                if safe == 0 {
                    i = BN_is_prime_fasttest_ex(ret, checks, ctx, 0 as libc::c_int, cb);
                    if i == -(1 as libc::c_int) {
                        current_block = 12755824767588802570;
                        break;
                    }
                    if !(i == 0 as libc::c_int) {
                        current_block = 3934796541983872331;
                        break;
                    }
                } else {
                    if BN_rshift1(t, ret) == 0 {
                        current_block = 12755824767588802570;
                        break;
                    }
                    i = 0 as libc::c_int;
                    loop {
                        if !(i < checks) {
                            current_block = 3934796541983872331;
                            break '_loop;
                        }
                        j = BN_is_prime_fasttest_ex(
                            ret,
                            1 as libc::c_int,
                            ctx,
                            0 as libc::c_int,
                            0 as *mut BN_GENCB,
                        );
                        if j == -(1 as libc::c_int) {
                            current_block = 12755824767588802570;
                            break '_loop;
                        }
                        if j == 0 as libc::c_int {
                            break;
                        }
                        j = BN_is_prime_fasttest_ex(
                            t,
                            1 as libc::c_int,
                            ctx,
                            0 as libc::c_int,
                            0 as *mut BN_GENCB,
                        );
                        if j == -(1 as libc::c_int) {
                            current_block = 12755824767588802570;
                            break '_loop;
                        }
                        if j == 0 as libc::c_int {
                            break;
                        }
                        if BN_GENCB_call(cb, 1 as libc::c_int, i) == 0 {
                            current_block = 12755824767588802570;
                            break '_loop;
                        }
                        i += 1;
                        i;
                    }
                }
            }
            match current_block {
                12755824767588802570 => {}
                _ => {
                    found = 1 as libc::c_int;
                }
            }
        }
    }
    if !ctx.is_null() {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return found;
}
unsafe extern "C" fn bn_trial_division(
    mut out: *mut uint16_t,
    mut bn: *const BIGNUM,
) -> libc::c_int {
    let num_primes: size_t = num_trial_division_primes(bn);
    let mut i: size_t = 1 as libc::c_int as size_t;
    while i < num_primes {
        if constant_time_declassify_int(
            (bn_mod_u16_consttime(bn, kPrimes[i as usize]) as libc::c_int
                == 0 as libc::c_int) as libc::c_int,
        ) != 0
        {
            *out = kPrimes[i as usize];
            return 1 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_odd_number_is_obviously_composite(
    mut bn: *const BIGNUM,
) -> libc::c_int {
    let mut prime: uint16_t = 0;
    return (bn_trial_division(&mut prime, bn) != 0
        && BN_is_word(bn, prime as BN_ULONG) == 0) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_miller_rabin_init(
    mut miller_rabin: *mut BN_MILLER_RABIN,
    mut mont: *const BN_MONT_CTX,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut w: *const BIGNUM = &(*mont).N;
    (*miller_rabin).w1 = BN_CTX_get(ctx);
    (*miller_rabin).m = BN_CTX_get(ctx);
    (*miller_rabin).one_mont = BN_CTX_get(ctx);
    (*miller_rabin).w1_mont = BN_CTX_get(ctx);
    if ((*miller_rabin).w1).is_null() || ((*miller_rabin).m).is_null()
        || ((*miller_rabin).one_mont).is_null() || ((*miller_rabin).w1_mont).is_null()
    {
        return 0 as libc::c_int;
    }
    if bn_usub_consttime((*miller_rabin).w1, w, BN_value_one()) == 0 {
        return 0 as libc::c_int;
    }
    (*miller_rabin).a = BN_count_low_zero_bits((*miller_rabin).w1);
    if bn_rshift_secret_shift(
        (*miller_rabin).m,
        (*miller_rabin).w1,
        (*miller_rabin).a as libc::c_uint,
        ctx,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    (*miller_rabin).w_bits = BN_num_bits(w) as libc::c_int;
    if bn_one_to_montgomery((*miller_rabin).one_mont, mont, ctx) == 0
        || bn_usub_consttime((*miller_rabin).w1_mont, w, (*miller_rabin).one_mont) == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_miller_rabin_iteration(
    mut miller_rabin: *const BN_MILLER_RABIN,
    mut out_is_possibly_prime: *mut libc::c_int,
    mut b: *const BIGNUM,
    mut mont: *const BN_MONT_CTX,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut is_possibly_prime: crypto_word_t = 0;
    let mut current_block: u64;
    let mut ret: libc::c_int = 0 as libc::c_int;
    BN_CTX_start(ctx);
    let mut w: *const BIGNUM = &(*mont).N;
    let mut z: *mut BIGNUM = BN_CTX_get(ctx);
    if !(z.is_null()
        || BN_mod_exp_mont_consttime(z, b, (*miller_rabin).m, w, ctx, mont) == 0
        || BN_to_montgomery(z, z, mont, ctx) == 0)
    {
        is_possibly_prime = 0 as libc::c_int as crypto_word_t;
        is_possibly_prime = (BN_equal_consttime(z, (*miller_rabin).one_mont)
            | BN_equal_consttime(z, (*miller_rabin).w1_mont)) as crypto_word_t;
        is_possibly_prime = (0 as libc::c_int as crypto_word_t)
            .wrapping_sub(is_possibly_prime);
        let mut j: libc::c_int = 1 as libc::c_int;
        loop {
            if !(j < (*miller_rabin).w_bits) {
                current_block = 2979737022853876585;
                break;
            }
            if constant_time_declassify_w(
                constant_time_eq_int(j, (*miller_rabin).a) & !is_possibly_prime,
            ) != 0
            {
                current_block = 2979737022853876585;
                break;
            }
            if BN_mod_mul_montgomery(z, z, z, mont, ctx) == 0 {
                current_block = 7989263231718482758;
                break;
            }
            let mut z_is_w1_mont: crypto_word_t = BN_equal_consttime(
                z,
                (*miller_rabin).w1_mont,
            ) as crypto_word_t;
            z_is_w1_mont = (0 as libc::c_int as crypto_word_t)
                .wrapping_sub(z_is_w1_mont);
            is_possibly_prime |= z_is_w1_mont;
            if constant_time_declassify_w(
                BN_equal_consttime(z, (*miller_rabin).one_mont) as crypto_word_t
                    & !is_possibly_prime,
            ) != 0
            {
                current_block = 2979737022853876585;
                break;
            }
            j += 1;
            j;
        }
        match current_block {
            7989263231718482758 => {}
            _ => {
                *out_is_possibly_prime = (constant_time_declassify_w(is_possibly_prime)
                    & 1 as libc::c_int as crypto_word_t) as libc::c_int;
                ret = 1 as libc::c_int;
            }
        }
    }
    BN_CTX_end(ctx);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_primality_test(
    mut out_is_probably_prime: *mut libc::c_int,
    mut w: *const BIGNUM,
    mut checks: libc::c_int,
    mut ctx: *mut BN_CTX,
    mut do_trial_division: libc::c_int,
    mut cb: *mut BN_GENCB,
) -> libc::c_int {
    let mut uniform_iterations: crypto_word_t = 0;
    let mut current_block: u64;
    *out_is_probably_prime = 0 as libc::c_int;
    if BN_cmp(w, BN_value_one()) <= 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    if BN_is_odd(w) == 0 {
        *out_is_probably_prime = BN_is_word(w, 2 as libc::c_int as BN_ULONG);
        return 1 as libc::c_int;
    }
    if BN_is_word(w, 3 as libc::c_int as BN_ULONG) != 0 {
        *out_is_probably_prime = 1 as libc::c_int;
        return 1 as libc::c_int;
    }
    if do_trial_division != 0 {
        let mut prime: uint16_t = 0;
        if bn_trial_division(&mut prime, w) != 0 {
            *out_is_probably_prime = BN_is_word(w, prime as BN_ULONG);
            return 1 as libc::c_int;
        }
        if BN_GENCB_call(cb, 1 as libc::c_int, -(1 as libc::c_int)) == 0 {
            return 0 as libc::c_int;
        }
    }
    if checks == 0 as libc::c_int {
        checks = BN_prime_checks_for_size(BN_num_bits(w) as libc::c_int);
    }
    let mut new_ctx: *mut BN_CTX = 0 as *mut BN_CTX;
    if ctx.is_null() {
        new_ctx = BN_CTX_new();
        if new_ctx.is_null() {
            return 0 as libc::c_int;
        }
        ctx = new_ctx;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    BN_CTX_start(ctx);
    let mut b: *mut BIGNUM = BN_CTX_get(ctx);
    let mut mont: *mut BN_MONT_CTX = BN_MONT_CTX_new_consttime(w, ctx);
    let mut miller_rabin: BN_MILLER_RABIN = BN_MILLER_RABIN {
        w1: 0 as *mut BIGNUM,
        m: 0 as *mut BIGNUM,
        one_mont: 0 as *mut BIGNUM,
        w1_mont: 0 as *mut BIGNUM,
        w_bits: 0,
        a: 0,
    };
    if !(b.is_null() || mont.is_null()
        || bn_miller_rabin_init(&mut miller_rabin, mont, ctx) == 0)
    {
        uniform_iterations = 0 as libc::c_int as crypto_word_t;
        let mut i: libc::c_int = 1 as libc::c_int;
        loop {
            if !(constant_time_declassify_w(
                (i <= 16 as libc::c_int) as libc::c_int as crypto_word_t
                    | constant_time_lt_w(uniform_iterations, checks as crypto_word_t),
            ) != 0)
            {
                current_block = 11048769245176032998;
                break;
            }
            let mut is_uniform: libc::c_int = 0;
            if bn_rand_secret_range(
                b,
                &mut is_uniform,
                2 as libc::c_int as BN_ULONG,
                miller_rabin.w1,
            ) == 0
            {
                current_block = 16934468337314461219;
                break;
            }
            uniform_iterations = uniform_iterations
                .wrapping_add(is_uniform as crypto_word_t);
            let mut is_possibly_prime: libc::c_int = 0 as libc::c_int;
            if bn_miller_rabin_iteration(
                &mut miller_rabin,
                &mut is_possibly_prime,
                b,
                mont,
                ctx,
            ) == 0
            {
                current_block = 16934468337314461219;
                break;
            }
            if is_possibly_prime == 0 {
                *out_is_probably_prime = 0 as libc::c_int;
                ret = 1 as libc::c_int;
                current_block = 16934468337314461219;
                break;
            } else {
                if BN_GENCB_call(cb, 1 as libc::c_int, i - 1 as libc::c_int) == 0 {
                    current_block = 16934468337314461219;
                    break;
                }
                i += 1;
                i;
            }
        }
        match current_block {
            16934468337314461219 => {}
            _ => {
                if constant_time_declassify_int(
                    (uniform_iterations >= checks as crypto_word_t) as libc::c_int,
                ) != 0
                {} else {
                    __assert_fail(
                        b"constant_time_declassify_int(uniform_iterations >= (crypto_word_t)checks)\0"
                            as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/prime.c\0"
                            as *const u8 as *const libc::c_char,
                        791 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 77],
                            &[libc::c_char; 77],
                        >(
                            b"int BN_primality_test(int *, const BIGNUM *, int, BN_CTX *, int, BN_GENCB *)\0",
                        ))
                            .as_ptr(),
                    );
                }
                'c_5313: {
                    if constant_time_declassify_int(
                        (uniform_iterations >= checks as crypto_word_t) as libc::c_int,
                    ) != 0
                    {} else {
                        __assert_fail(
                            b"constant_time_declassify_int(uniform_iterations >= (crypto_word_t)checks)\0"
                                as *const u8 as *const libc::c_char,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/prime.c\0"
                                as *const u8 as *const libc::c_char,
                            791 as libc::c_int as libc::c_uint,
                            (*::core::mem::transmute::<
                                &[u8; 77],
                                &[libc::c_char; 77],
                            >(
                                b"int BN_primality_test(int *, const BIGNUM *, int, BN_CTX *, int, BN_GENCB *)\0",
                            ))
                                .as_ptr(),
                        );
                    }
                };
                *out_is_probably_prime = 1 as libc::c_int;
                ret = 1 as libc::c_int;
            }
        }
    }
    BN_MONT_CTX_free(mont);
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_is_prime_ex(
    mut candidate: *const BIGNUM,
    mut checks: libc::c_int,
    mut ctx: *mut BN_CTX,
    mut cb: *mut BN_GENCB,
) -> libc::c_int {
    return BN_is_prime_fasttest_ex(candidate, checks, ctx, 0 as libc::c_int, cb);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_is_prime_fasttest_ex(
    mut a: *const BIGNUM,
    mut checks: libc::c_int,
    mut ctx: *mut BN_CTX,
    mut do_trial_division: libc::c_int,
    mut cb: *mut BN_GENCB,
) -> libc::c_int {
    let mut is_probably_prime: libc::c_int = 0;
    if BN_primality_test(&mut is_probably_prime, a, checks, ctx, do_trial_division, cb)
        == 0
    {
        return -(1 as libc::c_int);
    }
    return is_probably_prime;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_enhanced_miller_rabin_primality_test(
    mut out_result: *mut bn_primality_result_t,
    mut w: *const BIGNUM,
    mut checks: libc::c_int,
    mut ctx: *mut BN_CTX,
    mut cb: *mut BN_GENCB,
) -> libc::c_int {
    let mut a: libc::c_int = 0;
    let mut m: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut b: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut g: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut z: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut x: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut x1: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut current_block: u64;
    if BN_is_odd(w) == 0
        || BN_cmp_word(w, 3 as libc::c_int as BN_ULONG) <= 0 as libc::c_int
    {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            119 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/prime.c\0"
                as *const u8 as *const libc::c_char,
            822 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if checks == 0 as libc::c_int {
        checks = BN_prime_checks_for_size(BN_num_bits(w) as libc::c_int);
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut mont: *mut BN_MONT_CTX = 0 as *mut BN_MONT_CTX;
    BN_CTX_start(ctx);
    let mut w1: *mut BIGNUM = BN_CTX_get(ctx);
    if !(w1.is_null() || (BN_copy(w1, w)).is_null()
        || BN_sub_word(w1, 1 as libc::c_int as BN_ULONG) == 0)
    {
        a = 0 as libc::c_int;
        while BN_is_bit_set(w1, a) == 0 {
            a += 1;
            a;
        }
        m = BN_CTX_get(ctx);
        if !(m.is_null() || BN_rshift(m, w1, a) == 0) {
            b = BN_CTX_get(ctx);
            g = BN_CTX_get(ctx);
            z = BN_CTX_get(ctx);
            x = BN_CTX_get(ctx);
            x1 = BN_CTX_get(ctx);
            if !(b.is_null() || g.is_null() || z.is_null() || x.is_null()
                || x1.is_null())
            {
                mont = BN_MONT_CTX_new_for_modulus(w, ctx);
                if !mont.is_null() {
                    let mut i: libc::c_int = 1 as libc::c_int;
                    's_94: loop {
                        if !(i <= checks) {
                            current_block = 3160140712158701372;
                            break;
                        }
                        if BN_rand_range_ex(b, 2 as libc::c_int as BN_ULONG, w1) == 0 {
                            current_block = 3489379733166332176;
                            break;
                        }
                        if BN_gcd(g, b, w, ctx) == 0 {
                            current_block = 3489379733166332176;
                            break;
                        }
                        if BN_cmp_word(g, 1 as libc::c_int as BN_ULONG)
                            > 0 as libc::c_int
                        {
                            *out_result = bn_composite;
                            ret = 1 as libc::c_int;
                            current_block = 3489379733166332176;
                            break;
                        } else {
                            if BN_mod_exp_mont(z, b, m, w, ctx, mont) == 0 {
                                current_block = 3489379733166332176;
                                break;
                            }
                            if !(BN_is_one(z) != 0 || BN_cmp(z, w1) == 0 as libc::c_int)
                            {
                                let mut j: libc::c_int = 1 as libc::c_int;
                                loop {
                                    if !(j < a) {
                                        current_block = 11385396242402735691;
                                        break;
                                    }
                                    if (BN_copy(x, z)).is_null()
                                        || BN_mod_mul(z, x, x, w, ctx) == 0
                                    {
                                        current_block = 3489379733166332176;
                                        break 's_94;
                                    }
                                    if BN_cmp(z, w1) == 0 as libc::c_int {
                                        current_block = 11521095184096720876;
                                        break;
                                    }
                                    if BN_is_one(z) != 0 {
                                        current_block = 4837798588838600042;
                                        break;
                                    }
                                    j += 1;
                                    j;
                                }
                                match current_block {
                                    11521095184096720876 => {}
                                    _ => {
                                        match current_block {
                                            11385396242402735691 => {
                                                if (BN_copy(x, z)).is_null()
                                                    || BN_mod_mul(z, x, x, w, ctx) == 0
                                                {
                                                    current_block = 3489379733166332176;
                                                    break;
                                                }
                                                if BN_is_one(z) == 0 && (BN_copy(x, z)).is_null() {
                                                    current_block = 3489379733166332176;
                                                    break;
                                                }
                                            }
                                            _ => {}
                                        }
                                        if (BN_copy(x1, x)).is_null()
                                            || BN_sub_word(x1, 1 as libc::c_int as BN_ULONG) == 0
                                            || BN_gcd(g, x1, w, ctx) == 0
                                        {
                                            current_block = 3489379733166332176;
                                            break;
                                        }
                                        if BN_cmp_word(g, 1 as libc::c_int as BN_ULONG)
                                            > 0 as libc::c_int
                                        {
                                            *out_result = bn_composite;
                                        } else {
                                            *out_result = bn_non_prime_power_composite;
                                        }
                                        ret = 1 as libc::c_int;
                                        current_block = 3489379733166332176;
                                        break;
                                    }
                                }
                            }
                            if BN_GENCB_call(cb, 1 as libc::c_int, i - 1 as libc::c_int)
                                == 0
                            {
                                current_block = 3489379733166332176;
                                break;
                            }
                            i += 1;
                            i;
                        }
                    }
                    match current_block {
                        3489379733166332176 => {}
                        _ => {
                            *out_result = bn_probably_prime;
                            ret = 1 as libc::c_int;
                        }
                    }
                }
            }
        }
    }
    BN_MONT_CTX_free(mont);
    BN_CTX_end(ctx);
    return ret;
}
unsafe extern "C" fn probable_prime(
    mut rnd: *mut BIGNUM,
    mut bits: libc::c_int,
) -> libc::c_int {
    loop {
        if BN_rand(rnd, bits, 1 as libc::c_int, 1 as libc::c_int) == 0 {
            return 0 as libc::c_int;
        }
        if !(bn_odd_number_is_obviously_composite(rnd) != 0) {
            break;
        }
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn probable_prime_dh(
    mut rnd: *mut BIGNUM,
    mut bits: libc::c_int,
    mut add: *const BIGNUM,
    mut rem: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut num_primes: size_t = 0;
    let mut current_block: u64;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut t1: *mut BIGNUM = 0 as *mut BIGNUM;
    BN_CTX_start(ctx);
    t1 = BN_CTX_get(ctx);
    if !t1.is_null() {
        if !(BN_rand(rnd, bits, 0 as libc::c_int, 1 as libc::c_int) == 0) {
            if !(BN_div(0 as *mut BIGNUM, t1, rnd, add, ctx) == 0) {
                if !(BN_sub(rnd, rnd, t1) == 0) {
                    if rem.is_null() {
                        if BN_add_word(rnd, 1 as libc::c_int as BN_ULONG) == 0 {
                            current_block = 4493101128126991132;
                        } else {
                            current_block = 12209867499936983673;
                        }
                    } else if BN_add(rnd, rnd, rem) == 0 {
                        current_block = 4493101128126991132;
                    } else {
                        current_block = 12209867499936983673;
                    }
                    match current_block {
                        4493101128126991132 => {}
                        _ => {
                            num_primes = num_trial_division_primes(rnd);
                            's_63: loop {
                                let mut i: size_t = 1 as libc::c_int as size_t;
                                while i < num_primes {
                                    if bn_mod_u16_consttime(rnd, kPrimes[i as usize])
                                        as libc::c_int <= 1 as libc::c_int
                                    {
                                        if BN_add(rnd, rnd, add) == 0 {
                                            break 's_63;
                                        } else {
                                            continue 's_63;
                                        }
                                    } else {
                                        i = i.wrapping_add(1);
                                        i;
                                    }
                                }
                                ret = 1 as libc::c_int;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    BN_CTX_end(ctx);
    return ret;
}
unsafe extern "C" fn probable_prime_dh_safe(
    mut p: *mut BIGNUM,
    mut bits: libc::c_int,
    mut padd: *const BIGNUM,
    mut rem: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut num_primes: size_t = 0;
    let mut current_block: u64;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut t1: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut qadd: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut q: *mut BIGNUM = 0 as *mut BIGNUM;
    bits -= 1;
    bits;
    BN_CTX_start(ctx);
    t1 = BN_CTX_get(ctx);
    q = BN_CTX_get(ctx);
    qadd = BN_CTX_get(ctx);
    if !qadd.is_null() {
        if !(BN_rshift1(qadd, padd) == 0) {
            if !(BN_rand(q, bits, 0 as libc::c_int, 1 as libc::c_int) == 0) {
                if !(BN_div(0 as *mut BIGNUM, t1, q, qadd, ctx) == 0) {
                    if !(BN_sub(q, q, t1) == 0) {
                        if rem.is_null() {
                            if BN_add_word(q, 1 as libc::c_int as BN_ULONG) == 0 {
                                current_block = 16393984576687740934;
                            } else {
                                current_block = 15976848397966268834;
                            }
                        } else if BN_rshift1(t1, rem) == 0 {
                            current_block = 16393984576687740934;
                        } else if BN_add(q, q, t1) == 0 {
                            current_block = 16393984576687740934;
                        } else {
                            current_block = 15976848397966268834;
                        }
                        match current_block {
                            16393984576687740934 => {}
                            _ => {
                                if !(BN_lshift1(p, q) == 0) {
                                    if !(BN_add_word(p, 1 as libc::c_int as BN_ULONG) == 0) {
                                        num_primes = num_trial_division_primes(p);
                                        's_103: loop {
                                            let mut i: size_t = 1 as libc::c_int as size_t;
                                            while i < num_primes {
                                                if bn_mod_u16_consttime(p, kPrimes[i as usize])
                                                    as libc::c_int == 0 as libc::c_int
                                                    || bn_mod_u16_consttime(q, kPrimes[i as usize])
                                                        as libc::c_int == 0 as libc::c_int
                                                {
                                                    if BN_add(p, p, padd) == 0 {
                                                        break 's_103;
                                                    }
                                                    if BN_add(q, q, qadd) == 0 {
                                                        break 's_103;
                                                    } else {
                                                        continue 's_103;
                                                    }
                                                } else {
                                                    i = i.wrapping_add(1);
                                                    i;
                                                }
                                            }
                                            ret = 1 as libc::c_int;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    BN_CTX_end(ctx);
    return ret;
}
