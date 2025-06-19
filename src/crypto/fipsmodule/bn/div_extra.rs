#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(asm, label_break_value)]
use core::arch::asm;
unsafe extern "C" {
    fn BN_num_bits_word(l: BN_ULONG) -> libc::c_uint;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
}
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
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
#[inline]
unsafe extern "C" fn value_barrier_u32(mut a: uint32_t) -> uint32_t {
    asm!("", inlateout(reg) a, options(preserves_flags, pure, readonly, att_syntax));
    return a;
}
#[inline]
unsafe extern "C" fn constant_time_declassify_int(mut v: libc::c_int) -> libc::c_int {
    return value_barrier_u32(v as uint32_t) as libc::c_int;
}
unsafe extern "C" fn mod_u16(
    mut n: uint32_t,
    mut d: uint16_t,
    mut p: uint32_t,
    mut m: uint32_t,
) -> uint16_t {
    let mut q: uint32_t = (m as uint64_t * n as uint64_t >> 32 as libc::c_int)
        as uint32_t;
    let mut t: uint32_t = (n.wrapping_sub(q) >> 1 as libc::c_int).wrapping_add(q);
    t = t >> p.wrapping_sub(1 as libc::c_int as uint32_t);
    n = n.wrapping_sub(d as uint32_t * t);
    if constant_time_declassify_int((n < d as uint32_t) as libc::c_int) != 0 {} else {
        __assert_fail(
            b"constant_time_declassify_int(n < d)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/div_extra.c\0"
                as *const u8 as *const libc::c_char,
            42 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 57],
                &[libc::c_char; 57],
            >(b"uint16_t mod_u16(uint32_t, uint16_t, uint32_t, uint32_t)\0"))
                .as_ptr(),
        );
    }
    'c_7496: {
        if constant_time_declassify_int((n < d as uint32_t) as libc::c_int) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(n < d)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/div_extra.c\0"
                    as *const u8 as *const libc::c_char,
                42 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 57],
                    &[libc::c_char; 57],
                >(b"uint16_t mod_u16(uint32_t, uint16_t, uint32_t, uint32_t)\0"))
                    .as_ptr(),
            );
        }
    };
    return n as uint16_t;
}
unsafe extern "C" fn shift_and_add_mod_u16(
    mut r: uint16_t,
    mut a: uint32_t,
    mut d: uint16_t,
    mut p: uint32_t,
    mut m: uint32_t,
) -> uint16_t {
    let mut t: uint32_t = r as uint32_t;
    t <<= 16 as libc::c_int;
    t |= a >> 16 as libc::c_int;
    t = mod_u16(t, d, p, m) as uint32_t;
    t <<= 16 as libc::c_int;
    t |= a & 0xffff as libc::c_int as uint32_t;
    t = mod_u16(t, d, p, m) as uint32_t;
    return t as uint16_t;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_mod_u16_consttime(
    mut bn: *const BIGNUM,
    mut d: uint16_t,
) -> uint16_t {
    if d as libc::c_int <= 1 as libc::c_int {
        return 0 as libc::c_int as uint16_t;
    }
    let mut p: uint32_t = BN_num_bits_word(
        (d as libc::c_int - 1 as libc::c_int) as BN_ULONG,
    );
    if p <= 16 as libc::c_int as uint32_t {} else {
        __assert_fail(
            b"p <= 16\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/div_extra.c\0"
                as *const u8 as *const libc::c_char,
            72 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 56],
                &[libc::c_char; 56],
            >(b"uint16_t bn_mod_u16_consttime(const BIGNUM *, uint16_t)\0"))
                .as_ptr(),
        );
    }
    'c_7648: {
        if p <= 16 as libc::c_int as uint32_t {} else {
            __assert_fail(
                b"p <= 16\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/div_extra.c\0"
                    as *const u8 as *const libc::c_char,
                72 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 56],
                    &[libc::c_char; 56],
                >(b"uint16_t bn_mod_u16_consttime(const BIGNUM *, uint16_t)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut m: uint32_t = ((1 as libc::c_ulong)
        << (32 as libc::c_int as uint32_t).wrapping_add(p))
        .wrapping_add(d as libc::c_ulong)
        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
        .wrapping_div(d as libc::c_ulong) as uint32_t;
    let mut ret: uint16_t = 0 as libc::c_int as uint16_t;
    let mut i: libc::c_int = (*bn).width - 1 as libc::c_int;
    while i >= 0 as libc::c_int {
        ret = shift_and_add_mod_u16(
            ret,
            (*((*bn).d).offset(i as isize) >> 32 as libc::c_int) as uint32_t,
            d,
            p,
            m,
        );
        ret = shift_and_add_mod_u16(
            ret,
            (*((*bn).d).offset(i as isize) & 0xffffffff as libc::c_uint as BN_ULONG)
                as uint32_t,
            d,
            p,
            m,
        );
        i -= 1;
        i;
    }
    return ret;
}
