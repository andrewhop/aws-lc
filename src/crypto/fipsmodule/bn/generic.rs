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
extern "C" {
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
}
pub type __uint128_t = u128;
pub type size_t = libc::c_ulong;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type BN_ULONG = uint64_t;
pub type uint128_t = __uint128_t;
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
#[inline]
unsafe extern "C" fn CRYPTO_addc_u64(
    mut x: uint64_t,
    mut y: uint64_t,
    mut carry: uint64_t,
    mut out_carry: *mut uint64_t,
) -> uint64_t {
    if constant_time_declassify_int(
        (carry <= 1 as libc::c_int as uint64_t) as libc::c_int,
    ) != 0
    {} else {
        __assert_fail(
            b"constant_time_declassify_int(carry <= 1)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/../../internal.h\0"
                as *const u8 as *const libc::c_char,
            1200 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 67],
                &[libc::c_char; 67],
            >(b"uint64_t CRYPTO_addc_u64(uint64_t, uint64_t, uint64_t, uint64_t *)\0"))
                .as_ptr(),
        );
    }
    'c_6526: {
        if constant_time_declassify_int(
            (carry <= 1 as libc::c_int as uint64_t) as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(carry <= 1)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/../../internal.h\0"
                    as *const u8 as *const libc::c_char,
                1200 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 67],
                    &[libc::c_char; 67],
                >(
                    b"uint64_t CRYPTO_addc_u64(uint64_t, uint64_t, uint64_t, uint64_t *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut ret: uint128_t = carry as uint128_t;
    ret = ret.wrapping_add((x as uint128_t).wrapping_add(y as uint128_t));
    *out_carry = (ret >> 64 as libc::c_int) as uint64_t;
    return ret as uint64_t;
}
#[inline]
unsafe extern "C" fn CRYPTO_subc_u64(
    mut x: uint64_t,
    mut y: uint64_t,
    mut borrow: uint64_t,
    mut out_borrow: *mut uint64_t,
) -> uint64_t {
    if constant_time_declassify_int(
        (borrow <= 1 as libc::c_int as uint64_t) as libc::c_int,
    ) != 0
    {} else {
        __assert_fail(
            b"constant_time_declassify_int(borrow <= 1)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/../../internal.h\0"
                as *const u8 as *const libc::c_char,
            1251 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 67],
                &[libc::c_char; 67],
            >(b"uint64_t CRYPTO_subc_u64(uint64_t, uint64_t, uint64_t, uint64_t *)\0"))
                .as_ptr(),
        );
    }
    'c_6703: {
        if constant_time_declassify_int(
            (borrow <= 1 as libc::c_int as uint64_t) as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(borrow <= 1)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/../../internal.h\0"
                    as *const u8 as *const libc::c_char,
                1251 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 67],
                    &[libc::c_char; 67],
                >(
                    b"uint64_t CRYPTO_subc_u64(uint64_t, uint64_t, uint64_t, uint64_t *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut ret: uint64_t = x.wrapping_sub(y).wrapping_sub(borrow);
    *out_borrow = (x < y) as libc::c_int as uint64_t
        | (x == y) as libc::c_int as uint64_t & borrow;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn bn_mul_add_words(
    mut rp: *mut BN_ULONG,
    mut ap: *const BN_ULONG,
    mut num: size_t,
    mut w: BN_ULONG,
) -> BN_ULONG {
    let mut c1: BN_ULONG = 0 as libc::c_int as BN_ULONG;
    if num == 0 as libc::c_int as size_t {
        return c1;
    }
    while num & !(3 as libc::c_int) as size_t != 0 {
        let mut t: uint128_t = 0;
        t = (w as uint128_t * *ap.offset(0 as libc::c_int as isize) as uint128_t)
            .wrapping_add(*rp.offset(0 as libc::c_int as isize) as uint128_t)
            .wrapping_add(c1 as uint128_t);
        *rp.offset(0 as libc::c_int as isize) = t as BN_ULONG;
        c1 = (t >> 64 as libc::c_int) as BN_ULONG;
        let mut t_0: uint128_t = 0;
        t_0 = (w as uint128_t * *ap.offset(1 as libc::c_int as isize) as uint128_t)
            .wrapping_add(*rp.offset(1 as libc::c_int as isize) as uint128_t)
            .wrapping_add(c1 as uint128_t);
        *rp.offset(1 as libc::c_int as isize) = t_0 as BN_ULONG;
        c1 = (t_0 >> 64 as libc::c_int) as BN_ULONG;
        let mut t_1: uint128_t = 0;
        t_1 = (w as uint128_t * *ap.offset(2 as libc::c_int as isize) as uint128_t)
            .wrapping_add(*rp.offset(2 as libc::c_int as isize) as uint128_t)
            .wrapping_add(c1 as uint128_t);
        *rp.offset(2 as libc::c_int as isize) = t_1 as BN_ULONG;
        c1 = (t_1 >> 64 as libc::c_int) as BN_ULONG;
        let mut t_2: uint128_t = 0;
        t_2 = (w as uint128_t * *ap.offset(3 as libc::c_int as isize) as uint128_t)
            .wrapping_add(*rp.offset(3 as libc::c_int as isize) as uint128_t)
            .wrapping_add(c1 as uint128_t);
        *rp.offset(3 as libc::c_int as isize) = t_2 as BN_ULONG;
        c1 = (t_2 >> 64 as libc::c_int) as BN_ULONG;
        ap = ap.offset(4 as libc::c_int as isize);
        rp = rp.offset(4 as libc::c_int as isize);
        num = num.wrapping_sub(4 as libc::c_int as size_t);
    }
    while num != 0 {
        let mut t_3: uint128_t = 0;
        t_3 = (w as uint128_t * *ap.offset(0 as libc::c_int as isize) as uint128_t)
            .wrapping_add(*rp.offset(0 as libc::c_int as isize) as uint128_t)
            .wrapping_add(c1 as uint128_t);
        *rp.offset(0 as libc::c_int as isize) = t_3 as BN_ULONG;
        c1 = (t_3 >> 64 as libc::c_int) as BN_ULONG;
        ap = ap.offset(1);
        ap;
        rp = rp.offset(1);
        rp;
        num = num.wrapping_sub(1);
        num;
    }
    return c1;
}
#[no_mangle]
pub unsafe extern "C" fn bn_mul_words(
    mut rp: *mut BN_ULONG,
    mut ap: *const BN_ULONG,
    mut num: size_t,
    mut w: BN_ULONG,
) -> BN_ULONG {
    let mut c1: BN_ULONG = 0 as libc::c_int as BN_ULONG;
    if num == 0 as libc::c_int as size_t {
        return c1;
    }
    while num & !(3 as libc::c_int) as size_t != 0 {
        let mut t: uint128_t = 0;
        t = (w as uint128_t * *ap.offset(0 as libc::c_int as isize) as uint128_t)
            .wrapping_add(c1 as uint128_t);
        *rp.offset(0 as libc::c_int as isize) = t as BN_ULONG;
        c1 = (t >> 64 as libc::c_int) as BN_ULONG;
        let mut t_0: uint128_t = 0;
        t_0 = (w as uint128_t * *ap.offset(1 as libc::c_int as isize) as uint128_t)
            .wrapping_add(c1 as uint128_t);
        *rp.offset(1 as libc::c_int as isize) = t_0 as BN_ULONG;
        c1 = (t_0 >> 64 as libc::c_int) as BN_ULONG;
        let mut t_1: uint128_t = 0;
        t_1 = (w as uint128_t * *ap.offset(2 as libc::c_int as isize) as uint128_t)
            .wrapping_add(c1 as uint128_t);
        *rp.offset(2 as libc::c_int as isize) = t_1 as BN_ULONG;
        c1 = (t_1 >> 64 as libc::c_int) as BN_ULONG;
        let mut t_2: uint128_t = 0;
        t_2 = (w as uint128_t * *ap.offset(3 as libc::c_int as isize) as uint128_t)
            .wrapping_add(c1 as uint128_t);
        *rp.offset(3 as libc::c_int as isize) = t_2 as BN_ULONG;
        c1 = (t_2 >> 64 as libc::c_int) as BN_ULONG;
        ap = ap.offset(4 as libc::c_int as isize);
        rp = rp.offset(4 as libc::c_int as isize);
        num = num.wrapping_sub(4 as libc::c_int as size_t);
    }
    while num != 0 {
        let mut t_3: uint128_t = 0;
        t_3 = (w as uint128_t * *ap.offset(0 as libc::c_int as isize) as uint128_t)
            .wrapping_add(c1 as uint128_t);
        *rp.offset(0 as libc::c_int as isize) = t_3 as BN_ULONG;
        c1 = (t_3 >> 64 as libc::c_int) as BN_ULONG;
        ap = ap.offset(1);
        ap;
        rp = rp.offset(1);
        rp;
        num = num.wrapping_sub(1);
        num;
    }
    return c1;
}
#[no_mangle]
pub unsafe extern "C" fn bn_sqr_words(
    mut r: *mut BN_ULONG,
    mut a: *const BN_ULONG,
    mut n: size_t,
) {
    if n == 0 as libc::c_int as size_t {
        return;
    }
    while n & !(3 as libc::c_int) as size_t != 0 {
        let mut t: uint128_t = 0;
        t = *a.offset(0 as libc::c_int as isize) as uint128_t
            * *a.offset(0 as libc::c_int as isize) as uint128_t;
        *r.offset(0 as libc::c_int as isize) = t as BN_ULONG;
        *r.offset(1 as libc::c_int as isize) = (t >> 64 as libc::c_int) as BN_ULONG;
        let mut t_0: uint128_t = 0;
        t_0 = *a.offset(1 as libc::c_int as isize) as uint128_t
            * *a.offset(1 as libc::c_int as isize) as uint128_t;
        *r.offset(2 as libc::c_int as isize) = t_0 as BN_ULONG;
        *r.offset(3 as libc::c_int as isize) = (t_0 >> 64 as libc::c_int) as BN_ULONG;
        let mut t_1: uint128_t = 0;
        t_1 = *a.offset(2 as libc::c_int as isize) as uint128_t
            * *a.offset(2 as libc::c_int as isize) as uint128_t;
        *r.offset(4 as libc::c_int as isize) = t_1 as BN_ULONG;
        *r.offset(5 as libc::c_int as isize) = (t_1 >> 64 as libc::c_int) as BN_ULONG;
        let mut t_2: uint128_t = 0;
        t_2 = *a.offset(3 as libc::c_int as isize) as uint128_t
            * *a.offset(3 as libc::c_int as isize) as uint128_t;
        *r.offset(6 as libc::c_int as isize) = t_2 as BN_ULONG;
        *r.offset(7 as libc::c_int as isize) = (t_2 >> 64 as libc::c_int) as BN_ULONG;
        a = a.offset(4 as libc::c_int as isize);
        r = r.offset(8 as libc::c_int as isize);
        n = n.wrapping_sub(4 as libc::c_int as size_t);
    }
    while n != 0 {
        let mut t_3: uint128_t = 0;
        t_3 = *a.offset(0 as libc::c_int as isize) as uint128_t
            * *a.offset(0 as libc::c_int as isize) as uint128_t;
        *r.offset(0 as libc::c_int as isize) = t_3 as BN_ULONG;
        *r.offset(1 as libc::c_int as isize) = (t_3 >> 64 as libc::c_int) as BN_ULONG;
        a = a.offset(1);
        a;
        r = r.offset(2 as libc::c_int as isize);
        n = n.wrapping_sub(1);
        n;
    }
}
#[no_mangle]
pub unsafe extern "C" fn bn_mul_comba8(
    mut r: *mut BN_ULONG,
    mut a: *const BN_ULONG,
    mut b: *const BN_ULONG,
) {
    let mut c1: BN_ULONG = 0;
    let mut c2: BN_ULONG = 0;
    let mut c3: BN_ULONG = 0;
    c1 = 0 as libc::c_int as BN_ULONG;
    c2 = 0 as libc::c_int as BN_ULONG;
    c3 = 0 as libc::c_int as BN_ULONG;
    let mut hi: BN_ULONG = 0;
    let mut t: uint128_t = *a.offset(0 as libc::c_int as isize) as uint128_t
        * *b.offset(0 as libc::c_int as isize) as uint128_t;
    t = t.wrapping_add(c1 as uint128_t);
    c1 = t as BN_ULONG;
    hi = (t >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi);
    c3 = c3.wrapping_add((c2 < hi) as libc::c_int as BN_ULONG);
    *r.offset(0 as libc::c_int as isize) = c1;
    c1 = 0 as libc::c_int as BN_ULONG;
    let mut hi_0: BN_ULONG = 0;
    let mut t_0: uint128_t = *a.offset(0 as libc::c_int as isize) as uint128_t
        * *b.offset(1 as libc::c_int as isize) as uint128_t;
    t_0 = t_0.wrapping_add(c2 as uint128_t);
    c2 = t_0 as BN_ULONG;
    hi_0 = (t_0 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_0);
    c1 = c1.wrapping_add((c3 < hi_0) as libc::c_int as BN_ULONG);
    let mut hi_1: BN_ULONG = 0;
    let mut t_1: uint128_t = *a.offset(1 as libc::c_int as isize) as uint128_t
        * *b.offset(0 as libc::c_int as isize) as uint128_t;
    t_1 = t_1.wrapping_add(c2 as uint128_t);
    c2 = t_1 as BN_ULONG;
    hi_1 = (t_1 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_1);
    c1 = c1.wrapping_add((c3 < hi_1) as libc::c_int as BN_ULONG);
    *r.offset(1 as libc::c_int as isize) = c2;
    c2 = 0 as libc::c_int as BN_ULONG;
    let mut hi_2: BN_ULONG = 0;
    let mut t_2: uint128_t = *a.offset(2 as libc::c_int as isize) as uint128_t
        * *b.offset(0 as libc::c_int as isize) as uint128_t;
    t_2 = t_2.wrapping_add(c3 as uint128_t);
    c3 = t_2 as BN_ULONG;
    hi_2 = (t_2 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_2);
    c2 = c2.wrapping_add((c1 < hi_2) as libc::c_int as BN_ULONG);
    let mut hi_3: BN_ULONG = 0;
    let mut t_3: uint128_t = *a.offset(1 as libc::c_int as isize) as uint128_t
        * *b.offset(1 as libc::c_int as isize) as uint128_t;
    t_3 = t_3.wrapping_add(c3 as uint128_t);
    c3 = t_3 as BN_ULONG;
    hi_3 = (t_3 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_3);
    c2 = c2.wrapping_add((c1 < hi_3) as libc::c_int as BN_ULONG);
    let mut hi_4: BN_ULONG = 0;
    let mut t_4: uint128_t = *a.offset(0 as libc::c_int as isize) as uint128_t
        * *b.offset(2 as libc::c_int as isize) as uint128_t;
    t_4 = t_4.wrapping_add(c3 as uint128_t);
    c3 = t_4 as BN_ULONG;
    hi_4 = (t_4 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_4);
    c2 = c2.wrapping_add((c1 < hi_4) as libc::c_int as BN_ULONG);
    *r.offset(2 as libc::c_int as isize) = c3;
    c3 = 0 as libc::c_int as BN_ULONG;
    let mut hi_5: BN_ULONG = 0;
    let mut t_5: uint128_t = *a.offset(0 as libc::c_int as isize) as uint128_t
        * *b.offset(3 as libc::c_int as isize) as uint128_t;
    t_5 = t_5.wrapping_add(c1 as uint128_t);
    c1 = t_5 as BN_ULONG;
    hi_5 = (t_5 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_5);
    c3 = c3.wrapping_add((c2 < hi_5) as libc::c_int as BN_ULONG);
    let mut hi_6: BN_ULONG = 0;
    let mut t_6: uint128_t = *a.offset(1 as libc::c_int as isize) as uint128_t
        * *b.offset(2 as libc::c_int as isize) as uint128_t;
    t_6 = t_6.wrapping_add(c1 as uint128_t);
    c1 = t_6 as BN_ULONG;
    hi_6 = (t_6 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_6);
    c3 = c3.wrapping_add((c2 < hi_6) as libc::c_int as BN_ULONG);
    let mut hi_7: BN_ULONG = 0;
    let mut t_7: uint128_t = *a.offset(2 as libc::c_int as isize) as uint128_t
        * *b.offset(1 as libc::c_int as isize) as uint128_t;
    t_7 = t_7.wrapping_add(c1 as uint128_t);
    c1 = t_7 as BN_ULONG;
    hi_7 = (t_7 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_7);
    c3 = c3.wrapping_add((c2 < hi_7) as libc::c_int as BN_ULONG);
    let mut hi_8: BN_ULONG = 0;
    let mut t_8: uint128_t = *a.offset(3 as libc::c_int as isize) as uint128_t
        * *b.offset(0 as libc::c_int as isize) as uint128_t;
    t_8 = t_8.wrapping_add(c1 as uint128_t);
    c1 = t_8 as BN_ULONG;
    hi_8 = (t_8 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_8);
    c3 = c3.wrapping_add((c2 < hi_8) as libc::c_int as BN_ULONG);
    *r.offset(3 as libc::c_int as isize) = c1;
    c1 = 0 as libc::c_int as BN_ULONG;
    let mut hi_9: BN_ULONG = 0;
    let mut t_9: uint128_t = *a.offset(4 as libc::c_int as isize) as uint128_t
        * *b.offset(0 as libc::c_int as isize) as uint128_t;
    t_9 = t_9.wrapping_add(c2 as uint128_t);
    c2 = t_9 as BN_ULONG;
    hi_9 = (t_9 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_9);
    c1 = c1.wrapping_add((c3 < hi_9) as libc::c_int as BN_ULONG);
    let mut hi_10: BN_ULONG = 0;
    let mut t_10: uint128_t = *a.offset(3 as libc::c_int as isize) as uint128_t
        * *b.offset(1 as libc::c_int as isize) as uint128_t;
    t_10 = t_10.wrapping_add(c2 as uint128_t);
    c2 = t_10 as BN_ULONG;
    hi_10 = (t_10 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_10);
    c1 = c1.wrapping_add((c3 < hi_10) as libc::c_int as BN_ULONG);
    let mut hi_11: BN_ULONG = 0;
    let mut t_11: uint128_t = *a.offset(2 as libc::c_int as isize) as uint128_t
        * *b.offset(2 as libc::c_int as isize) as uint128_t;
    t_11 = t_11.wrapping_add(c2 as uint128_t);
    c2 = t_11 as BN_ULONG;
    hi_11 = (t_11 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_11);
    c1 = c1.wrapping_add((c3 < hi_11) as libc::c_int as BN_ULONG);
    let mut hi_12: BN_ULONG = 0;
    let mut t_12: uint128_t = *a.offset(1 as libc::c_int as isize) as uint128_t
        * *b.offset(3 as libc::c_int as isize) as uint128_t;
    t_12 = t_12.wrapping_add(c2 as uint128_t);
    c2 = t_12 as BN_ULONG;
    hi_12 = (t_12 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_12);
    c1 = c1.wrapping_add((c3 < hi_12) as libc::c_int as BN_ULONG);
    let mut hi_13: BN_ULONG = 0;
    let mut t_13: uint128_t = *a.offset(0 as libc::c_int as isize) as uint128_t
        * *b.offset(4 as libc::c_int as isize) as uint128_t;
    t_13 = t_13.wrapping_add(c2 as uint128_t);
    c2 = t_13 as BN_ULONG;
    hi_13 = (t_13 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_13);
    c1 = c1.wrapping_add((c3 < hi_13) as libc::c_int as BN_ULONG);
    *r.offset(4 as libc::c_int as isize) = c2;
    c2 = 0 as libc::c_int as BN_ULONG;
    let mut hi_14: BN_ULONG = 0;
    let mut t_14: uint128_t = *a.offset(0 as libc::c_int as isize) as uint128_t
        * *b.offset(5 as libc::c_int as isize) as uint128_t;
    t_14 = t_14.wrapping_add(c3 as uint128_t);
    c3 = t_14 as BN_ULONG;
    hi_14 = (t_14 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_14);
    c2 = c2.wrapping_add((c1 < hi_14) as libc::c_int as BN_ULONG);
    let mut hi_15: BN_ULONG = 0;
    let mut t_15: uint128_t = *a.offset(1 as libc::c_int as isize) as uint128_t
        * *b.offset(4 as libc::c_int as isize) as uint128_t;
    t_15 = t_15.wrapping_add(c3 as uint128_t);
    c3 = t_15 as BN_ULONG;
    hi_15 = (t_15 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_15);
    c2 = c2.wrapping_add((c1 < hi_15) as libc::c_int as BN_ULONG);
    let mut hi_16: BN_ULONG = 0;
    let mut t_16: uint128_t = *a.offset(2 as libc::c_int as isize) as uint128_t
        * *b.offset(3 as libc::c_int as isize) as uint128_t;
    t_16 = t_16.wrapping_add(c3 as uint128_t);
    c3 = t_16 as BN_ULONG;
    hi_16 = (t_16 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_16);
    c2 = c2.wrapping_add((c1 < hi_16) as libc::c_int as BN_ULONG);
    let mut hi_17: BN_ULONG = 0;
    let mut t_17: uint128_t = *a.offset(3 as libc::c_int as isize) as uint128_t
        * *b.offset(2 as libc::c_int as isize) as uint128_t;
    t_17 = t_17.wrapping_add(c3 as uint128_t);
    c3 = t_17 as BN_ULONG;
    hi_17 = (t_17 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_17);
    c2 = c2.wrapping_add((c1 < hi_17) as libc::c_int as BN_ULONG);
    let mut hi_18: BN_ULONG = 0;
    let mut t_18: uint128_t = *a.offset(4 as libc::c_int as isize) as uint128_t
        * *b.offset(1 as libc::c_int as isize) as uint128_t;
    t_18 = t_18.wrapping_add(c3 as uint128_t);
    c3 = t_18 as BN_ULONG;
    hi_18 = (t_18 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_18);
    c2 = c2.wrapping_add((c1 < hi_18) as libc::c_int as BN_ULONG);
    let mut hi_19: BN_ULONG = 0;
    let mut t_19: uint128_t = *a.offset(5 as libc::c_int as isize) as uint128_t
        * *b.offset(0 as libc::c_int as isize) as uint128_t;
    t_19 = t_19.wrapping_add(c3 as uint128_t);
    c3 = t_19 as BN_ULONG;
    hi_19 = (t_19 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_19);
    c2 = c2.wrapping_add((c1 < hi_19) as libc::c_int as BN_ULONG);
    *r.offset(5 as libc::c_int as isize) = c3;
    c3 = 0 as libc::c_int as BN_ULONG;
    let mut hi_20: BN_ULONG = 0;
    let mut t_20: uint128_t = *a.offset(6 as libc::c_int as isize) as uint128_t
        * *b.offset(0 as libc::c_int as isize) as uint128_t;
    t_20 = t_20.wrapping_add(c1 as uint128_t);
    c1 = t_20 as BN_ULONG;
    hi_20 = (t_20 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_20);
    c3 = c3.wrapping_add((c2 < hi_20) as libc::c_int as BN_ULONG);
    let mut hi_21: BN_ULONG = 0;
    let mut t_21: uint128_t = *a.offset(5 as libc::c_int as isize) as uint128_t
        * *b.offset(1 as libc::c_int as isize) as uint128_t;
    t_21 = t_21.wrapping_add(c1 as uint128_t);
    c1 = t_21 as BN_ULONG;
    hi_21 = (t_21 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_21);
    c3 = c3.wrapping_add((c2 < hi_21) as libc::c_int as BN_ULONG);
    let mut hi_22: BN_ULONG = 0;
    let mut t_22: uint128_t = *a.offset(4 as libc::c_int as isize) as uint128_t
        * *b.offset(2 as libc::c_int as isize) as uint128_t;
    t_22 = t_22.wrapping_add(c1 as uint128_t);
    c1 = t_22 as BN_ULONG;
    hi_22 = (t_22 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_22);
    c3 = c3.wrapping_add((c2 < hi_22) as libc::c_int as BN_ULONG);
    let mut hi_23: BN_ULONG = 0;
    let mut t_23: uint128_t = *a.offset(3 as libc::c_int as isize) as uint128_t
        * *b.offset(3 as libc::c_int as isize) as uint128_t;
    t_23 = t_23.wrapping_add(c1 as uint128_t);
    c1 = t_23 as BN_ULONG;
    hi_23 = (t_23 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_23);
    c3 = c3.wrapping_add((c2 < hi_23) as libc::c_int as BN_ULONG);
    let mut hi_24: BN_ULONG = 0;
    let mut t_24: uint128_t = *a.offset(2 as libc::c_int as isize) as uint128_t
        * *b.offset(4 as libc::c_int as isize) as uint128_t;
    t_24 = t_24.wrapping_add(c1 as uint128_t);
    c1 = t_24 as BN_ULONG;
    hi_24 = (t_24 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_24);
    c3 = c3.wrapping_add((c2 < hi_24) as libc::c_int as BN_ULONG);
    let mut hi_25: BN_ULONG = 0;
    let mut t_25: uint128_t = *a.offset(1 as libc::c_int as isize) as uint128_t
        * *b.offset(5 as libc::c_int as isize) as uint128_t;
    t_25 = t_25.wrapping_add(c1 as uint128_t);
    c1 = t_25 as BN_ULONG;
    hi_25 = (t_25 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_25);
    c3 = c3.wrapping_add((c2 < hi_25) as libc::c_int as BN_ULONG);
    let mut hi_26: BN_ULONG = 0;
    let mut t_26: uint128_t = *a.offset(0 as libc::c_int as isize) as uint128_t
        * *b.offset(6 as libc::c_int as isize) as uint128_t;
    t_26 = t_26.wrapping_add(c1 as uint128_t);
    c1 = t_26 as BN_ULONG;
    hi_26 = (t_26 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_26);
    c3 = c3.wrapping_add((c2 < hi_26) as libc::c_int as BN_ULONG);
    *r.offset(6 as libc::c_int as isize) = c1;
    c1 = 0 as libc::c_int as BN_ULONG;
    let mut hi_27: BN_ULONG = 0;
    let mut t_27: uint128_t = *a.offset(0 as libc::c_int as isize) as uint128_t
        * *b.offset(7 as libc::c_int as isize) as uint128_t;
    t_27 = t_27.wrapping_add(c2 as uint128_t);
    c2 = t_27 as BN_ULONG;
    hi_27 = (t_27 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_27);
    c1 = c1.wrapping_add((c3 < hi_27) as libc::c_int as BN_ULONG);
    let mut hi_28: BN_ULONG = 0;
    let mut t_28: uint128_t = *a.offset(1 as libc::c_int as isize) as uint128_t
        * *b.offset(6 as libc::c_int as isize) as uint128_t;
    t_28 = t_28.wrapping_add(c2 as uint128_t);
    c2 = t_28 as BN_ULONG;
    hi_28 = (t_28 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_28);
    c1 = c1.wrapping_add((c3 < hi_28) as libc::c_int as BN_ULONG);
    let mut hi_29: BN_ULONG = 0;
    let mut t_29: uint128_t = *a.offset(2 as libc::c_int as isize) as uint128_t
        * *b.offset(5 as libc::c_int as isize) as uint128_t;
    t_29 = t_29.wrapping_add(c2 as uint128_t);
    c2 = t_29 as BN_ULONG;
    hi_29 = (t_29 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_29);
    c1 = c1.wrapping_add((c3 < hi_29) as libc::c_int as BN_ULONG);
    let mut hi_30: BN_ULONG = 0;
    let mut t_30: uint128_t = *a.offset(3 as libc::c_int as isize) as uint128_t
        * *b.offset(4 as libc::c_int as isize) as uint128_t;
    t_30 = t_30.wrapping_add(c2 as uint128_t);
    c2 = t_30 as BN_ULONG;
    hi_30 = (t_30 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_30);
    c1 = c1.wrapping_add((c3 < hi_30) as libc::c_int as BN_ULONG);
    let mut hi_31: BN_ULONG = 0;
    let mut t_31: uint128_t = *a.offset(4 as libc::c_int as isize) as uint128_t
        * *b.offset(3 as libc::c_int as isize) as uint128_t;
    t_31 = t_31.wrapping_add(c2 as uint128_t);
    c2 = t_31 as BN_ULONG;
    hi_31 = (t_31 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_31);
    c1 = c1.wrapping_add((c3 < hi_31) as libc::c_int as BN_ULONG);
    let mut hi_32: BN_ULONG = 0;
    let mut t_32: uint128_t = *a.offset(5 as libc::c_int as isize) as uint128_t
        * *b.offset(2 as libc::c_int as isize) as uint128_t;
    t_32 = t_32.wrapping_add(c2 as uint128_t);
    c2 = t_32 as BN_ULONG;
    hi_32 = (t_32 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_32);
    c1 = c1.wrapping_add((c3 < hi_32) as libc::c_int as BN_ULONG);
    let mut hi_33: BN_ULONG = 0;
    let mut t_33: uint128_t = *a.offset(6 as libc::c_int as isize) as uint128_t
        * *b.offset(1 as libc::c_int as isize) as uint128_t;
    t_33 = t_33.wrapping_add(c2 as uint128_t);
    c2 = t_33 as BN_ULONG;
    hi_33 = (t_33 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_33);
    c1 = c1.wrapping_add((c3 < hi_33) as libc::c_int as BN_ULONG);
    let mut hi_34: BN_ULONG = 0;
    let mut t_34: uint128_t = *a.offset(7 as libc::c_int as isize) as uint128_t
        * *b.offset(0 as libc::c_int as isize) as uint128_t;
    t_34 = t_34.wrapping_add(c2 as uint128_t);
    c2 = t_34 as BN_ULONG;
    hi_34 = (t_34 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_34);
    c1 = c1.wrapping_add((c3 < hi_34) as libc::c_int as BN_ULONG);
    *r.offset(7 as libc::c_int as isize) = c2;
    c2 = 0 as libc::c_int as BN_ULONG;
    let mut hi_35: BN_ULONG = 0;
    let mut t_35: uint128_t = *a.offset(7 as libc::c_int as isize) as uint128_t
        * *b.offset(1 as libc::c_int as isize) as uint128_t;
    t_35 = t_35.wrapping_add(c3 as uint128_t);
    c3 = t_35 as BN_ULONG;
    hi_35 = (t_35 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_35);
    c2 = c2.wrapping_add((c1 < hi_35) as libc::c_int as BN_ULONG);
    let mut hi_36: BN_ULONG = 0;
    let mut t_36: uint128_t = *a.offset(6 as libc::c_int as isize) as uint128_t
        * *b.offset(2 as libc::c_int as isize) as uint128_t;
    t_36 = t_36.wrapping_add(c3 as uint128_t);
    c3 = t_36 as BN_ULONG;
    hi_36 = (t_36 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_36);
    c2 = c2.wrapping_add((c1 < hi_36) as libc::c_int as BN_ULONG);
    let mut hi_37: BN_ULONG = 0;
    let mut t_37: uint128_t = *a.offset(5 as libc::c_int as isize) as uint128_t
        * *b.offset(3 as libc::c_int as isize) as uint128_t;
    t_37 = t_37.wrapping_add(c3 as uint128_t);
    c3 = t_37 as BN_ULONG;
    hi_37 = (t_37 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_37);
    c2 = c2.wrapping_add((c1 < hi_37) as libc::c_int as BN_ULONG);
    let mut hi_38: BN_ULONG = 0;
    let mut t_38: uint128_t = *a.offset(4 as libc::c_int as isize) as uint128_t
        * *b.offset(4 as libc::c_int as isize) as uint128_t;
    t_38 = t_38.wrapping_add(c3 as uint128_t);
    c3 = t_38 as BN_ULONG;
    hi_38 = (t_38 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_38);
    c2 = c2.wrapping_add((c1 < hi_38) as libc::c_int as BN_ULONG);
    let mut hi_39: BN_ULONG = 0;
    let mut t_39: uint128_t = *a.offset(3 as libc::c_int as isize) as uint128_t
        * *b.offset(5 as libc::c_int as isize) as uint128_t;
    t_39 = t_39.wrapping_add(c3 as uint128_t);
    c3 = t_39 as BN_ULONG;
    hi_39 = (t_39 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_39);
    c2 = c2.wrapping_add((c1 < hi_39) as libc::c_int as BN_ULONG);
    let mut hi_40: BN_ULONG = 0;
    let mut t_40: uint128_t = *a.offset(2 as libc::c_int as isize) as uint128_t
        * *b.offset(6 as libc::c_int as isize) as uint128_t;
    t_40 = t_40.wrapping_add(c3 as uint128_t);
    c3 = t_40 as BN_ULONG;
    hi_40 = (t_40 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_40);
    c2 = c2.wrapping_add((c1 < hi_40) as libc::c_int as BN_ULONG);
    let mut hi_41: BN_ULONG = 0;
    let mut t_41: uint128_t = *a.offset(1 as libc::c_int as isize) as uint128_t
        * *b.offset(7 as libc::c_int as isize) as uint128_t;
    t_41 = t_41.wrapping_add(c3 as uint128_t);
    c3 = t_41 as BN_ULONG;
    hi_41 = (t_41 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_41);
    c2 = c2.wrapping_add((c1 < hi_41) as libc::c_int as BN_ULONG);
    *r.offset(8 as libc::c_int as isize) = c3;
    c3 = 0 as libc::c_int as BN_ULONG;
    let mut hi_42: BN_ULONG = 0;
    let mut t_42: uint128_t = *a.offset(2 as libc::c_int as isize) as uint128_t
        * *b.offset(7 as libc::c_int as isize) as uint128_t;
    t_42 = t_42.wrapping_add(c1 as uint128_t);
    c1 = t_42 as BN_ULONG;
    hi_42 = (t_42 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_42);
    c3 = c3.wrapping_add((c2 < hi_42) as libc::c_int as BN_ULONG);
    let mut hi_43: BN_ULONG = 0;
    let mut t_43: uint128_t = *a.offset(3 as libc::c_int as isize) as uint128_t
        * *b.offset(6 as libc::c_int as isize) as uint128_t;
    t_43 = t_43.wrapping_add(c1 as uint128_t);
    c1 = t_43 as BN_ULONG;
    hi_43 = (t_43 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_43);
    c3 = c3.wrapping_add((c2 < hi_43) as libc::c_int as BN_ULONG);
    let mut hi_44: BN_ULONG = 0;
    let mut t_44: uint128_t = *a.offset(4 as libc::c_int as isize) as uint128_t
        * *b.offset(5 as libc::c_int as isize) as uint128_t;
    t_44 = t_44.wrapping_add(c1 as uint128_t);
    c1 = t_44 as BN_ULONG;
    hi_44 = (t_44 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_44);
    c3 = c3.wrapping_add((c2 < hi_44) as libc::c_int as BN_ULONG);
    let mut hi_45: BN_ULONG = 0;
    let mut t_45: uint128_t = *a.offset(5 as libc::c_int as isize) as uint128_t
        * *b.offset(4 as libc::c_int as isize) as uint128_t;
    t_45 = t_45.wrapping_add(c1 as uint128_t);
    c1 = t_45 as BN_ULONG;
    hi_45 = (t_45 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_45);
    c3 = c3.wrapping_add((c2 < hi_45) as libc::c_int as BN_ULONG);
    let mut hi_46: BN_ULONG = 0;
    let mut t_46: uint128_t = *a.offset(6 as libc::c_int as isize) as uint128_t
        * *b.offset(3 as libc::c_int as isize) as uint128_t;
    t_46 = t_46.wrapping_add(c1 as uint128_t);
    c1 = t_46 as BN_ULONG;
    hi_46 = (t_46 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_46);
    c3 = c3.wrapping_add((c2 < hi_46) as libc::c_int as BN_ULONG);
    let mut hi_47: BN_ULONG = 0;
    let mut t_47: uint128_t = *a.offset(7 as libc::c_int as isize) as uint128_t
        * *b.offset(2 as libc::c_int as isize) as uint128_t;
    t_47 = t_47.wrapping_add(c1 as uint128_t);
    c1 = t_47 as BN_ULONG;
    hi_47 = (t_47 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_47);
    c3 = c3.wrapping_add((c2 < hi_47) as libc::c_int as BN_ULONG);
    *r.offset(9 as libc::c_int as isize) = c1;
    c1 = 0 as libc::c_int as BN_ULONG;
    let mut hi_48: BN_ULONG = 0;
    let mut t_48: uint128_t = *a.offset(7 as libc::c_int as isize) as uint128_t
        * *b.offset(3 as libc::c_int as isize) as uint128_t;
    t_48 = t_48.wrapping_add(c2 as uint128_t);
    c2 = t_48 as BN_ULONG;
    hi_48 = (t_48 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_48);
    c1 = c1.wrapping_add((c3 < hi_48) as libc::c_int as BN_ULONG);
    let mut hi_49: BN_ULONG = 0;
    let mut t_49: uint128_t = *a.offset(6 as libc::c_int as isize) as uint128_t
        * *b.offset(4 as libc::c_int as isize) as uint128_t;
    t_49 = t_49.wrapping_add(c2 as uint128_t);
    c2 = t_49 as BN_ULONG;
    hi_49 = (t_49 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_49);
    c1 = c1.wrapping_add((c3 < hi_49) as libc::c_int as BN_ULONG);
    let mut hi_50: BN_ULONG = 0;
    let mut t_50: uint128_t = *a.offset(5 as libc::c_int as isize) as uint128_t
        * *b.offset(5 as libc::c_int as isize) as uint128_t;
    t_50 = t_50.wrapping_add(c2 as uint128_t);
    c2 = t_50 as BN_ULONG;
    hi_50 = (t_50 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_50);
    c1 = c1.wrapping_add((c3 < hi_50) as libc::c_int as BN_ULONG);
    let mut hi_51: BN_ULONG = 0;
    let mut t_51: uint128_t = *a.offset(4 as libc::c_int as isize) as uint128_t
        * *b.offset(6 as libc::c_int as isize) as uint128_t;
    t_51 = t_51.wrapping_add(c2 as uint128_t);
    c2 = t_51 as BN_ULONG;
    hi_51 = (t_51 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_51);
    c1 = c1.wrapping_add((c3 < hi_51) as libc::c_int as BN_ULONG);
    let mut hi_52: BN_ULONG = 0;
    let mut t_52: uint128_t = *a.offset(3 as libc::c_int as isize) as uint128_t
        * *b.offset(7 as libc::c_int as isize) as uint128_t;
    t_52 = t_52.wrapping_add(c2 as uint128_t);
    c2 = t_52 as BN_ULONG;
    hi_52 = (t_52 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_52);
    c1 = c1.wrapping_add((c3 < hi_52) as libc::c_int as BN_ULONG);
    *r.offset(10 as libc::c_int as isize) = c2;
    c2 = 0 as libc::c_int as BN_ULONG;
    let mut hi_53: BN_ULONG = 0;
    let mut t_53: uint128_t = *a.offset(4 as libc::c_int as isize) as uint128_t
        * *b.offset(7 as libc::c_int as isize) as uint128_t;
    t_53 = t_53.wrapping_add(c3 as uint128_t);
    c3 = t_53 as BN_ULONG;
    hi_53 = (t_53 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_53);
    c2 = c2.wrapping_add((c1 < hi_53) as libc::c_int as BN_ULONG);
    let mut hi_54: BN_ULONG = 0;
    let mut t_54: uint128_t = *a.offset(5 as libc::c_int as isize) as uint128_t
        * *b.offset(6 as libc::c_int as isize) as uint128_t;
    t_54 = t_54.wrapping_add(c3 as uint128_t);
    c3 = t_54 as BN_ULONG;
    hi_54 = (t_54 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_54);
    c2 = c2.wrapping_add((c1 < hi_54) as libc::c_int as BN_ULONG);
    let mut hi_55: BN_ULONG = 0;
    let mut t_55: uint128_t = *a.offset(6 as libc::c_int as isize) as uint128_t
        * *b.offset(5 as libc::c_int as isize) as uint128_t;
    t_55 = t_55.wrapping_add(c3 as uint128_t);
    c3 = t_55 as BN_ULONG;
    hi_55 = (t_55 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_55);
    c2 = c2.wrapping_add((c1 < hi_55) as libc::c_int as BN_ULONG);
    let mut hi_56: BN_ULONG = 0;
    let mut t_56: uint128_t = *a.offset(7 as libc::c_int as isize) as uint128_t
        * *b.offset(4 as libc::c_int as isize) as uint128_t;
    t_56 = t_56.wrapping_add(c3 as uint128_t);
    c3 = t_56 as BN_ULONG;
    hi_56 = (t_56 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_56);
    c2 = c2.wrapping_add((c1 < hi_56) as libc::c_int as BN_ULONG);
    *r.offset(11 as libc::c_int as isize) = c3;
    c3 = 0 as libc::c_int as BN_ULONG;
    let mut hi_57: BN_ULONG = 0;
    let mut t_57: uint128_t = *a.offset(7 as libc::c_int as isize) as uint128_t
        * *b.offset(5 as libc::c_int as isize) as uint128_t;
    t_57 = t_57.wrapping_add(c1 as uint128_t);
    c1 = t_57 as BN_ULONG;
    hi_57 = (t_57 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_57);
    c3 = c3.wrapping_add((c2 < hi_57) as libc::c_int as BN_ULONG);
    let mut hi_58: BN_ULONG = 0;
    let mut t_58: uint128_t = *a.offset(6 as libc::c_int as isize) as uint128_t
        * *b.offset(6 as libc::c_int as isize) as uint128_t;
    t_58 = t_58.wrapping_add(c1 as uint128_t);
    c1 = t_58 as BN_ULONG;
    hi_58 = (t_58 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_58);
    c3 = c3.wrapping_add((c2 < hi_58) as libc::c_int as BN_ULONG);
    let mut hi_59: BN_ULONG = 0;
    let mut t_59: uint128_t = *a.offset(5 as libc::c_int as isize) as uint128_t
        * *b.offset(7 as libc::c_int as isize) as uint128_t;
    t_59 = t_59.wrapping_add(c1 as uint128_t);
    c1 = t_59 as BN_ULONG;
    hi_59 = (t_59 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_59);
    c3 = c3.wrapping_add((c2 < hi_59) as libc::c_int as BN_ULONG);
    *r.offset(12 as libc::c_int as isize) = c1;
    c1 = 0 as libc::c_int as BN_ULONG;
    let mut hi_60: BN_ULONG = 0;
    let mut t_60: uint128_t = *a.offset(6 as libc::c_int as isize) as uint128_t
        * *b.offset(7 as libc::c_int as isize) as uint128_t;
    t_60 = t_60.wrapping_add(c2 as uint128_t);
    c2 = t_60 as BN_ULONG;
    hi_60 = (t_60 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_60);
    c1 = c1.wrapping_add((c3 < hi_60) as libc::c_int as BN_ULONG);
    let mut hi_61: BN_ULONG = 0;
    let mut t_61: uint128_t = *a.offset(7 as libc::c_int as isize) as uint128_t
        * *b.offset(6 as libc::c_int as isize) as uint128_t;
    t_61 = t_61.wrapping_add(c2 as uint128_t);
    c2 = t_61 as BN_ULONG;
    hi_61 = (t_61 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_61);
    c1 = c1.wrapping_add((c3 < hi_61) as libc::c_int as BN_ULONG);
    *r.offset(13 as libc::c_int as isize) = c2;
    c2 = 0 as libc::c_int as BN_ULONG;
    let mut hi_62: BN_ULONG = 0;
    let mut t_62: uint128_t = *a.offset(7 as libc::c_int as isize) as uint128_t
        * *b.offset(7 as libc::c_int as isize) as uint128_t;
    t_62 = t_62.wrapping_add(c3 as uint128_t);
    c3 = t_62 as BN_ULONG;
    hi_62 = (t_62 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_62);
    c2 = c2.wrapping_add((c1 < hi_62) as libc::c_int as BN_ULONG);
    *r.offset(14 as libc::c_int as isize) = c3;
    *r.offset(15 as libc::c_int as isize) = c1;
}
#[no_mangle]
pub unsafe extern "C" fn bn_mul_comba4(
    mut r: *mut BN_ULONG,
    mut a: *const BN_ULONG,
    mut b: *const BN_ULONG,
) {
    let mut c1: BN_ULONG = 0;
    let mut c2: BN_ULONG = 0;
    let mut c3: BN_ULONG = 0;
    c1 = 0 as libc::c_int as BN_ULONG;
    c2 = 0 as libc::c_int as BN_ULONG;
    c3 = 0 as libc::c_int as BN_ULONG;
    let mut hi: BN_ULONG = 0;
    let mut t: uint128_t = *a.offset(0 as libc::c_int as isize) as uint128_t
        * *b.offset(0 as libc::c_int as isize) as uint128_t;
    t = t.wrapping_add(c1 as uint128_t);
    c1 = t as BN_ULONG;
    hi = (t >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi);
    c3 = c3.wrapping_add((c2 < hi) as libc::c_int as BN_ULONG);
    *r.offset(0 as libc::c_int as isize) = c1;
    c1 = 0 as libc::c_int as BN_ULONG;
    let mut hi_0: BN_ULONG = 0;
    let mut t_0: uint128_t = *a.offset(0 as libc::c_int as isize) as uint128_t
        * *b.offset(1 as libc::c_int as isize) as uint128_t;
    t_0 = t_0.wrapping_add(c2 as uint128_t);
    c2 = t_0 as BN_ULONG;
    hi_0 = (t_0 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_0);
    c1 = c1.wrapping_add((c3 < hi_0) as libc::c_int as BN_ULONG);
    let mut hi_1: BN_ULONG = 0;
    let mut t_1: uint128_t = *a.offset(1 as libc::c_int as isize) as uint128_t
        * *b.offset(0 as libc::c_int as isize) as uint128_t;
    t_1 = t_1.wrapping_add(c2 as uint128_t);
    c2 = t_1 as BN_ULONG;
    hi_1 = (t_1 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_1);
    c1 = c1.wrapping_add((c3 < hi_1) as libc::c_int as BN_ULONG);
    *r.offset(1 as libc::c_int as isize) = c2;
    c2 = 0 as libc::c_int as BN_ULONG;
    let mut hi_2: BN_ULONG = 0;
    let mut t_2: uint128_t = *a.offset(2 as libc::c_int as isize) as uint128_t
        * *b.offset(0 as libc::c_int as isize) as uint128_t;
    t_2 = t_2.wrapping_add(c3 as uint128_t);
    c3 = t_2 as BN_ULONG;
    hi_2 = (t_2 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_2);
    c2 = c2.wrapping_add((c1 < hi_2) as libc::c_int as BN_ULONG);
    let mut hi_3: BN_ULONG = 0;
    let mut t_3: uint128_t = *a.offset(1 as libc::c_int as isize) as uint128_t
        * *b.offset(1 as libc::c_int as isize) as uint128_t;
    t_3 = t_3.wrapping_add(c3 as uint128_t);
    c3 = t_3 as BN_ULONG;
    hi_3 = (t_3 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_3);
    c2 = c2.wrapping_add((c1 < hi_3) as libc::c_int as BN_ULONG);
    let mut hi_4: BN_ULONG = 0;
    let mut t_4: uint128_t = *a.offset(0 as libc::c_int as isize) as uint128_t
        * *b.offset(2 as libc::c_int as isize) as uint128_t;
    t_4 = t_4.wrapping_add(c3 as uint128_t);
    c3 = t_4 as BN_ULONG;
    hi_4 = (t_4 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_4);
    c2 = c2.wrapping_add((c1 < hi_4) as libc::c_int as BN_ULONG);
    *r.offset(2 as libc::c_int as isize) = c3;
    c3 = 0 as libc::c_int as BN_ULONG;
    let mut hi_5: BN_ULONG = 0;
    let mut t_5: uint128_t = *a.offset(0 as libc::c_int as isize) as uint128_t
        * *b.offset(3 as libc::c_int as isize) as uint128_t;
    t_5 = t_5.wrapping_add(c1 as uint128_t);
    c1 = t_5 as BN_ULONG;
    hi_5 = (t_5 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_5);
    c3 = c3.wrapping_add((c2 < hi_5) as libc::c_int as BN_ULONG);
    let mut hi_6: BN_ULONG = 0;
    let mut t_6: uint128_t = *a.offset(1 as libc::c_int as isize) as uint128_t
        * *b.offset(2 as libc::c_int as isize) as uint128_t;
    t_6 = t_6.wrapping_add(c1 as uint128_t);
    c1 = t_6 as BN_ULONG;
    hi_6 = (t_6 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_6);
    c3 = c3.wrapping_add((c2 < hi_6) as libc::c_int as BN_ULONG);
    let mut hi_7: BN_ULONG = 0;
    let mut t_7: uint128_t = *a.offset(2 as libc::c_int as isize) as uint128_t
        * *b.offset(1 as libc::c_int as isize) as uint128_t;
    t_7 = t_7.wrapping_add(c1 as uint128_t);
    c1 = t_7 as BN_ULONG;
    hi_7 = (t_7 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_7);
    c3 = c3.wrapping_add((c2 < hi_7) as libc::c_int as BN_ULONG);
    let mut hi_8: BN_ULONG = 0;
    let mut t_8: uint128_t = *a.offset(3 as libc::c_int as isize) as uint128_t
        * *b.offset(0 as libc::c_int as isize) as uint128_t;
    t_8 = t_8.wrapping_add(c1 as uint128_t);
    c1 = t_8 as BN_ULONG;
    hi_8 = (t_8 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_8);
    c3 = c3.wrapping_add((c2 < hi_8) as libc::c_int as BN_ULONG);
    *r.offset(3 as libc::c_int as isize) = c1;
    c1 = 0 as libc::c_int as BN_ULONG;
    let mut hi_9: BN_ULONG = 0;
    let mut t_9: uint128_t = *a.offset(3 as libc::c_int as isize) as uint128_t
        * *b.offset(1 as libc::c_int as isize) as uint128_t;
    t_9 = t_9.wrapping_add(c2 as uint128_t);
    c2 = t_9 as BN_ULONG;
    hi_9 = (t_9 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_9);
    c1 = c1.wrapping_add((c3 < hi_9) as libc::c_int as BN_ULONG);
    let mut hi_10: BN_ULONG = 0;
    let mut t_10: uint128_t = *a.offset(2 as libc::c_int as isize) as uint128_t
        * *b.offset(2 as libc::c_int as isize) as uint128_t;
    t_10 = t_10.wrapping_add(c2 as uint128_t);
    c2 = t_10 as BN_ULONG;
    hi_10 = (t_10 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_10);
    c1 = c1.wrapping_add((c3 < hi_10) as libc::c_int as BN_ULONG);
    let mut hi_11: BN_ULONG = 0;
    let mut t_11: uint128_t = *a.offset(1 as libc::c_int as isize) as uint128_t
        * *b.offset(3 as libc::c_int as isize) as uint128_t;
    t_11 = t_11.wrapping_add(c2 as uint128_t);
    c2 = t_11 as BN_ULONG;
    hi_11 = (t_11 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_11);
    c1 = c1.wrapping_add((c3 < hi_11) as libc::c_int as BN_ULONG);
    *r.offset(4 as libc::c_int as isize) = c2;
    c2 = 0 as libc::c_int as BN_ULONG;
    let mut hi_12: BN_ULONG = 0;
    let mut t_12: uint128_t = *a.offset(2 as libc::c_int as isize) as uint128_t
        * *b.offset(3 as libc::c_int as isize) as uint128_t;
    t_12 = t_12.wrapping_add(c3 as uint128_t);
    c3 = t_12 as BN_ULONG;
    hi_12 = (t_12 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_12);
    c2 = c2.wrapping_add((c1 < hi_12) as libc::c_int as BN_ULONG);
    let mut hi_13: BN_ULONG = 0;
    let mut t_13: uint128_t = *a.offset(3 as libc::c_int as isize) as uint128_t
        * *b.offset(2 as libc::c_int as isize) as uint128_t;
    t_13 = t_13.wrapping_add(c3 as uint128_t);
    c3 = t_13 as BN_ULONG;
    hi_13 = (t_13 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_13);
    c2 = c2.wrapping_add((c1 < hi_13) as libc::c_int as BN_ULONG);
    *r.offset(5 as libc::c_int as isize) = c3;
    c3 = 0 as libc::c_int as BN_ULONG;
    let mut hi_14: BN_ULONG = 0;
    let mut t_14: uint128_t = *a.offset(3 as libc::c_int as isize) as uint128_t
        * *b.offset(3 as libc::c_int as isize) as uint128_t;
    t_14 = t_14.wrapping_add(c1 as uint128_t);
    c1 = t_14 as BN_ULONG;
    hi_14 = (t_14 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_14);
    c3 = c3.wrapping_add((c2 < hi_14) as libc::c_int as BN_ULONG);
    *r.offset(6 as libc::c_int as isize) = c1;
    *r.offset(7 as libc::c_int as isize) = c2;
}
#[no_mangle]
pub unsafe extern "C" fn bn_sqr_comba8(mut r: *mut BN_ULONG, mut a: *const BN_ULONG) {
    let mut c1: BN_ULONG = 0;
    let mut c2: BN_ULONG = 0;
    let mut c3: BN_ULONG = 0;
    c1 = 0 as libc::c_int as BN_ULONG;
    c2 = 0 as libc::c_int as BN_ULONG;
    c3 = 0 as libc::c_int as BN_ULONG;
    let mut hi: BN_ULONG = 0;
    let mut t: uint128_t = *a.offset(0 as libc::c_int as isize) as uint128_t
        * *a.offset(0 as libc::c_int as isize) as uint128_t;
    t = t.wrapping_add(c1 as uint128_t);
    c1 = t as BN_ULONG;
    hi = (t >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi);
    c3 = c3.wrapping_add((c2 < hi) as libc::c_int as BN_ULONG);
    *r.offset(0 as libc::c_int as isize) = c1;
    c1 = 0 as libc::c_int as BN_ULONG;
    let mut hi_0: BN_ULONG = 0;
    let mut t_0: uint128_t = *a.offset(1 as libc::c_int as isize) as uint128_t
        * *a.offset(0 as libc::c_int as isize) as uint128_t;
    let mut tt: uint128_t = t_0.wrapping_add(c2 as uint128_t);
    c2 = tt as BN_ULONG;
    hi_0 = (tt >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_0);
    c1 = c1.wrapping_add((c3 < hi_0) as libc::c_int as BN_ULONG);
    t_0 = t_0.wrapping_add(c2 as uint128_t);
    c2 = t_0 as BN_ULONG;
    hi_0 = (t_0 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_0);
    c1 = c1.wrapping_add((c3 < hi_0) as libc::c_int as BN_ULONG);
    *r.offset(1 as libc::c_int as isize) = c2;
    c2 = 0 as libc::c_int as BN_ULONG;
    let mut hi_1: BN_ULONG = 0;
    let mut t_1: uint128_t = *a.offset(1 as libc::c_int as isize) as uint128_t
        * *a.offset(1 as libc::c_int as isize) as uint128_t;
    t_1 = t_1.wrapping_add(c3 as uint128_t);
    c3 = t_1 as BN_ULONG;
    hi_1 = (t_1 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_1);
    c2 = c2.wrapping_add((c1 < hi_1) as libc::c_int as BN_ULONG);
    let mut hi_2: BN_ULONG = 0;
    let mut t_2: uint128_t = *a.offset(2 as libc::c_int as isize) as uint128_t
        * *a.offset(0 as libc::c_int as isize) as uint128_t;
    let mut tt_0: uint128_t = t_2.wrapping_add(c3 as uint128_t);
    c3 = tt_0 as BN_ULONG;
    hi_2 = (tt_0 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_2);
    c2 = c2.wrapping_add((c1 < hi_2) as libc::c_int as BN_ULONG);
    t_2 = t_2.wrapping_add(c3 as uint128_t);
    c3 = t_2 as BN_ULONG;
    hi_2 = (t_2 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_2);
    c2 = c2.wrapping_add((c1 < hi_2) as libc::c_int as BN_ULONG);
    *r.offset(2 as libc::c_int as isize) = c3;
    c3 = 0 as libc::c_int as BN_ULONG;
    let mut hi_3: BN_ULONG = 0;
    let mut t_3: uint128_t = *a.offset(3 as libc::c_int as isize) as uint128_t
        * *a.offset(0 as libc::c_int as isize) as uint128_t;
    let mut tt_1: uint128_t = t_3.wrapping_add(c1 as uint128_t);
    c1 = tt_1 as BN_ULONG;
    hi_3 = (tt_1 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_3);
    c3 = c3.wrapping_add((c2 < hi_3) as libc::c_int as BN_ULONG);
    t_3 = t_3.wrapping_add(c1 as uint128_t);
    c1 = t_3 as BN_ULONG;
    hi_3 = (t_3 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_3);
    c3 = c3.wrapping_add((c2 < hi_3) as libc::c_int as BN_ULONG);
    let mut hi_4: BN_ULONG = 0;
    let mut t_4: uint128_t = *a.offset(2 as libc::c_int as isize) as uint128_t
        * *a.offset(1 as libc::c_int as isize) as uint128_t;
    let mut tt_2: uint128_t = t_4.wrapping_add(c1 as uint128_t);
    c1 = tt_2 as BN_ULONG;
    hi_4 = (tt_2 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_4);
    c3 = c3.wrapping_add((c2 < hi_4) as libc::c_int as BN_ULONG);
    t_4 = t_4.wrapping_add(c1 as uint128_t);
    c1 = t_4 as BN_ULONG;
    hi_4 = (t_4 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_4);
    c3 = c3.wrapping_add((c2 < hi_4) as libc::c_int as BN_ULONG);
    *r.offset(3 as libc::c_int as isize) = c1;
    c1 = 0 as libc::c_int as BN_ULONG;
    let mut hi_5: BN_ULONG = 0;
    let mut t_5: uint128_t = *a.offset(2 as libc::c_int as isize) as uint128_t
        * *a.offset(2 as libc::c_int as isize) as uint128_t;
    t_5 = t_5.wrapping_add(c2 as uint128_t);
    c2 = t_5 as BN_ULONG;
    hi_5 = (t_5 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_5);
    c1 = c1.wrapping_add((c3 < hi_5) as libc::c_int as BN_ULONG);
    let mut hi_6: BN_ULONG = 0;
    let mut t_6: uint128_t = *a.offset(3 as libc::c_int as isize) as uint128_t
        * *a.offset(1 as libc::c_int as isize) as uint128_t;
    let mut tt_3: uint128_t = t_6.wrapping_add(c2 as uint128_t);
    c2 = tt_3 as BN_ULONG;
    hi_6 = (tt_3 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_6);
    c1 = c1.wrapping_add((c3 < hi_6) as libc::c_int as BN_ULONG);
    t_6 = t_6.wrapping_add(c2 as uint128_t);
    c2 = t_6 as BN_ULONG;
    hi_6 = (t_6 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_6);
    c1 = c1.wrapping_add((c3 < hi_6) as libc::c_int as BN_ULONG);
    let mut hi_7: BN_ULONG = 0;
    let mut t_7: uint128_t = *a.offset(4 as libc::c_int as isize) as uint128_t
        * *a.offset(0 as libc::c_int as isize) as uint128_t;
    let mut tt_4: uint128_t = t_7.wrapping_add(c2 as uint128_t);
    c2 = tt_4 as BN_ULONG;
    hi_7 = (tt_4 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_7);
    c1 = c1.wrapping_add((c3 < hi_7) as libc::c_int as BN_ULONG);
    t_7 = t_7.wrapping_add(c2 as uint128_t);
    c2 = t_7 as BN_ULONG;
    hi_7 = (t_7 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_7);
    c1 = c1.wrapping_add((c3 < hi_7) as libc::c_int as BN_ULONG);
    *r.offset(4 as libc::c_int as isize) = c2;
    c2 = 0 as libc::c_int as BN_ULONG;
    let mut hi_8: BN_ULONG = 0;
    let mut t_8: uint128_t = *a.offset(5 as libc::c_int as isize) as uint128_t
        * *a.offset(0 as libc::c_int as isize) as uint128_t;
    let mut tt_5: uint128_t = t_8.wrapping_add(c3 as uint128_t);
    c3 = tt_5 as BN_ULONG;
    hi_8 = (tt_5 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_8);
    c2 = c2.wrapping_add((c1 < hi_8) as libc::c_int as BN_ULONG);
    t_8 = t_8.wrapping_add(c3 as uint128_t);
    c3 = t_8 as BN_ULONG;
    hi_8 = (t_8 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_8);
    c2 = c2.wrapping_add((c1 < hi_8) as libc::c_int as BN_ULONG);
    let mut hi_9: BN_ULONG = 0;
    let mut t_9: uint128_t = *a.offset(4 as libc::c_int as isize) as uint128_t
        * *a.offset(1 as libc::c_int as isize) as uint128_t;
    let mut tt_6: uint128_t = t_9.wrapping_add(c3 as uint128_t);
    c3 = tt_6 as BN_ULONG;
    hi_9 = (tt_6 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_9);
    c2 = c2.wrapping_add((c1 < hi_9) as libc::c_int as BN_ULONG);
    t_9 = t_9.wrapping_add(c3 as uint128_t);
    c3 = t_9 as BN_ULONG;
    hi_9 = (t_9 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_9);
    c2 = c2.wrapping_add((c1 < hi_9) as libc::c_int as BN_ULONG);
    let mut hi_10: BN_ULONG = 0;
    let mut t_10: uint128_t = *a.offset(3 as libc::c_int as isize) as uint128_t
        * *a.offset(2 as libc::c_int as isize) as uint128_t;
    let mut tt_7: uint128_t = t_10.wrapping_add(c3 as uint128_t);
    c3 = tt_7 as BN_ULONG;
    hi_10 = (tt_7 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_10);
    c2 = c2.wrapping_add((c1 < hi_10) as libc::c_int as BN_ULONG);
    t_10 = t_10.wrapping_add(c3 as uint128_t);
    c3 = t_10 as BN_ULONG;
    hi_10 = (t_10 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_10);
    c2 = c2.wrapping_add((c1 < hi_10) as libc::c_int as BN_ULONG);
    *r.offset(5 as libc::c_int as isize) = c3;
    c3 = 0 as libc::c_int as BN_ULONG;
    let mut hi_11: BN_ULONG = 0;
    let mut t_11: uint128_t = *a.offset(3 as libc::c_int as isize) as uint128_t
        * *a.offset(3 as libc::c_int as isize) as uint128_t;
    t_11 = t_11.wrapping_add(c1 as uint128_t);
    c1 = t_11 as BN_ULONG;
    hi_11 = (t_11 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_11);
    c3 = c3.wrapping_add((c2 < hi_11) as libc::c_int as BN_ULONG);
    let mut hi_12: BN_ULONG = 0;
    let mut t_12: uint128_t = *a.offset(4 as libc::c_int as isize) as uint128_t
        * *a.offset(2 as libc::c_int as isize) as uint128_t;
    let mut tt_8: uint128_t = t_12.wrapping_add(c1 as uint128_t);
    c1 = tt_8 as BN_ULONG;
    hi_12 = (tt_8 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_12);
    c3 = c3.wrapping_add((c2 < hi_12) as libc::c_int as BN_ULONG);
    t_12 = t_12.wrapping_add(c1 as uint128_t);
    c1 = t_12 as BN_ULONG;
    hi_12 = (t_12 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_12);
    c3 = c3.wrapping_add((c2 < hi_12) as libc::c_int as BN_ULONG);
    let mut hi_13: BN_ULONG = 0;
    let mut t_13: uint128_t = *a.offset(5 as libc::c_int as isize) as uint128_t
        * *a.offset(1 as libc::c_int as isize) as uint128_t;
    let mut tt_9: uint128_t = t_13.wrapping_add(c1 as uint128_t);
    c1 = tt_9 as BN_ULONG;
    hi_13 = (tt_9 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_13);
    c3 = c3.wrapping_add((c2 < hi_13) as libc::c_int as BN_ULONG);
    t_13 = t_13.wrapping_add(c1 as uint128_t);
    c1 = t_13 as BN_ULONG;
    hi_13 = (t_13 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_13);
    c3 = c3.wrapping_add((c2 < hi_13) as libc::c_int as BN_ULONG);
    let mut hi_14: BN_ULONG = 0;
    let mut t_14: uint128_t = *a.offset(6 as libc::c_int as isize) as uint128_t
        * *a.offset(0 as libc::c_int as isize) as uint128_t;
    let mut tt_10: uint128_t = t_14.wrapping_add(c1 as uint128_t);
    c1 = tt_10 as BN_ULONG;
    hi_14 = (tt_10 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_14);
    c3 = c3.wrapping_add((c2 < hi_14) as libc::c_int as BN_ULONG);
    t_14 = t_14.wrapping_add(c1 as uint128_t);
    c1 = t_14 as BN_ULONG;
    hi_14 = (t_14 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_14);
    c3 = c3.wrapping_add((c2 < hi_14) as libc::c_int as BN_ULONG);
    *r.offset(6 as libc::c_int as isize) = c1;
    c1 = 0 as libc::c_int as BN_ULONG;
    let mut hi_15: BN_ULONG = 0;
    let mut t_15: uint128_t = *a.offset(7 as libc::c_int as isize) as uint128_t
        * *a.offset(0 as libc::c_int as isize) as uint128_t;
    let mut tt_11: uint128_t = t_15.wrapping_add(c2 as uint128_t);
    c2 = tt_11 as BN_ULONG;
    hi_15 = (tt_11 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_15);
    c1 = c1.wrapping_add((c3 < hi_15) as libc::c_int as BN_ULONG);
    t_15 = t_15.wrapping_add(c2 as uint128_t);
    c2 = t_15 as BN_ULONG;
    hi_15 = (t_15 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_15);
    c1 = c1.wrapping_add((c3 < hi_15) as libc::c_int as BN_ULONG);
    let mut hi_16: BN_ULONG = 0;
    let mut t_16: uint128_t = *a.offset(6 as libc::c_int as isize) as uint128_t
        * *a.offset(1 as libc::c_int as isize) as uint128_t;
    let mut tt_12: uint128_t = t_16.wrapping_add(c2 as uint128_t);
    c2 = tt_12 as BN_ULONG;
    hi_16 = (tt_12 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_16);
    c1 = c1.wrapping_add((c3 < hi_16) as libc::c_int as BN_ULONG);
    t_16 = t_16.wrapping_add(c2 as uint128_t);
    c2 = t_16 as BN_ULONG;
    hi_16 = (t_16 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_16);
    c1 = c1.wrapping_add((c3 < hi_16) as libc::c_int as BN_ULONG);
    let mut hi_17: BN_ULONG = 0;
    let mut t_17: uint128_t = *a.offset(5 as libc::c_int as isize) as uint128_t
        * *a.offset(2 as libc::c_int as isize) as uint128_t;
    let mut tt_13: uint128_t = t_17.wrapping_add(c2 as uint128_t);
    c2 = tt_13 as BN_ULONG;
    hi_17 = (tt_13 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_17);
    c1 = c1.wrapping_add((c3 < hi_17) as libc::c_int as BN_ULONG);
    t_17 = t_17.wrapping_add(c2 as uint128_t);
    c2 = t_17 as BN_ULONG;
    hi_17 = (t_17 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_17);
    c1 = c1.wrapping_add((c3 < hi_17) as libc::c_int as BN_ULONG);
    let mut hi_18: BN_ULONG = 0;
    let mut t_18: uint128_t = *a.offset(4 as libc::c_int as isize) as uint128_t
        * *a.offset(3 as libc::c_int as isize) as uint128_t;
    let mut tt_14: uint128_t = t_18.wrapping_add(c2 as uint128_t);
    c2 = tt_14 as BN_ULONG;
    hi_18 = (tt_14 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_18);
    c1 = c1.wrapping_add((c3 < hi_18) as libc::c_int as BN_ULONG);
    t_18 = t_18.wrapping_add(c2 as uint128_t);
    c2 = t_18 as BN_ULONG;
    hi_18 = (t_18 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_18);
    c1 = c1.wrapping_add((c3 < hi_18) as libc::c_int as BN_ULONG);
    *r.offset(7 as libc::c_int as isize) = c2;
    c2 = 0 as libc::c_int as BN_ULONG;
    let mut hi_19: BN_ULONG = 0;
    let mut t_19: uint128_t = *a.offset(4 as libc::c_int as isize) as uint128_t
        * *a.offset(4 as libc::c_int as isize) as uint128_t;
    t_19 = t_19.wrapping_add(c3 as uint128_t);
    c3 = t_19 as BN_ULONG;
    hi_19 = (t_19 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_19);
    c2 = c2.wrapping_add((c1 < hi_19) as libc::c_int as BN_ULONG);
    let mut hi_20: BN_ULONG = 0;
    let mut t_20: uint128_t = *a.offset(5 as libc::c_int as isize) as uint128_t
        * *a.offset(3 as libc::c_int as isize) as uint128_t;
    let mut tt_15: uint128_t = t_20.wrapping_add(c3 as uint128_t);
    c3 = tt_15 as BN_ULONG;
    hi_20 = (tt_15 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_20);
    c2 = c2.wrapping_add((c1 < hi_20) as libc::c_int as BN_ULONG);
    t_20 = t_20.wrapping_add(c3 as uint128_t);
    c3 = t_20 as BN_ULONG;
    hi_20 = (t_20 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_20);
    c2 = c2.wrapping_add((c1 < hi_20) as libc::c_int as BN_ULONG);
    let mut hi_21: BN_ULONG = 0;
    let mut t_21: uint128_t = *a.offset(6 as libc::c_int as isize) as uint128_t
        * *a.offset(2 as libc::c_int as isize) as uint128_t;
    let mut tt_16: uint128_t = t_21.wrapping_add(c3 as uint128_t);
    c3 = tt_16 as BN_ULONG;
    hi_21 = (tt_16 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_21);
    c2 = c2.wrapping_add((c1 < hi_21) as libc::c_int as BN_ULONG);
    t_21 = t_21.wrapping_add(c3 as uint128_t);
    c3 = t_21 as BN_ULONG;
    hi_21 = (t_21 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_21);
    c2 = c2.wrapping_add((c1 < hi_21) as libc::c_int as BN_ULONG);
    let mut hi_22: BN_ULONG = 0;
    let mut t_22: uint128_t = *a.offset(7 as libc::c_int as isize) as uint128_t
        * *a.offset(1 as libc::c_int as isize) as uint128_t;
    let mut tt_17: uint128_t = t_22.wrapping_add(c3 as uint128_t);
    c3 = tt_17 as BN_ULONG;
    hi_22 = (tt_17 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_22);
    c2 = c2.wrapping_add((c1 < hi_22) as libc::c_int as BN_ULONG);
    t_22 = t_22.wrapping_add(c3 as uint128_t);
    c3 = t_22 as BN_ULONG;
    hi_22 = (t_22 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_22);
    c2 = c2.wrapping_add((c1 < hi_22) as libc::c_int as BN_ULONG);
    *r.offset(8 as libc::c_int as isize) = c3;
    c3 = 0 as libc::c_int as BN_ULONG;
    let mut hi_23: BN_ULONG = 0;
    let mut t_23: uint128_t = *a.offset(7 as libc::c_int as isize) as uint128_t
        * *a.offset(2 as libc::c_int as isize) as uint128_t;
    let mut tt_18: uint128_t = t_23.wrapping_add(c1 as uint128_t);
    c1 = tt_18 as BN_ULONG;
    hi_23 = (tt_18 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_23);
    c3 = c3.wrapping_add((c2 < hi_23) as libc::c_int as BN_ULONG);
    t_23 = t_23.wrapping_add(c1 as uint128_t);
    c1 = t_23 as BN_ULONG;
    hi_23 = (t_23 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_23);
    c3 = c3.wrapping_add((c2 < hi_23) as libc::c_int as BN_ULONG);
    let mut hi_24: BN_ULONG = 0;
    let mut t_24: uint128_t = *a.offset(6 as libc::c_int as isize) as uint128_t
        * *a.offset(3 as libc::c_int as isize) as uint128_t;
    let mut tt_19: uint128_t = t_24.wrapping_add(c1 as uint128_t);
    c1 = tt_19 as BN_ULONG;
    hi_24 = (tt_19 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_24);
    c3 = c3.wrapping_add((c2 < hi_24) as libc::c_int as BN_ULONG);
    t_24 = t_24.wrapping_add(c1 as uint128_t);
    c1 = t_24 as BN_ULONG;
    hi_24 = (t_24 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_24);
    c3 = c3.wrapping_add((c2 < hi_24) as libc::c_int as BN_ULONG);
    let mut hi_25: BN_ULONG = 0;
    let mut t_25: uint128_t = *a.offset(5 as libc::c_int as isize) as uint128_t
        * *a.offset(4 as libc::c_int as isize) as uint128_t;
    let mut tt_20: uint128_t = t_25.wrapping_add(c1 as uint128_t);
    c1 = tt_20 as BN_ULONG;
    hi_25 = (tt_20 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_25);
    c3 = c3.wrapping_add((c2 < hi_25) as libc::c_int as BN_ULONG);
    t_25 = t_25.wrapping_add(c1 as uint128_t);
    c1 = t_25 as BN_ULONG;
    hi_25 = (t_25 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_25);
    c3 = c3.wrapping_add((c2 < hi_25) as libc::c_int as BN_ULONG);
    *r.offset(9 as libc::c_int as isize) = c1;
    c1 = 0 as libc::c_int as BN_ULONG;
    let mut hi_26: BN_ULONG = 0;
    let mut t_26: uint128_t = *a.offset(5 as libc::c_int as isize) as uint128_t
        * *a.offset(5 as libc::c_int as isize) as uint128_t;
    t_26 = t_26.wrapping_add(c2 as uint128_t);
    c2 = t_26 as BN_ULONG;
    hi_26 = (t_26 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_26);
    c1 = c1.wrapping_add((c3 < hi_26) as libc::c_int as BN_ULONG);
    let mut hi_27: BN_ULONG = 0;
    let mut t_27: uint128_t = *a.offset(6 as libc::c_int as isize) as uint128_t
        * *a.offset(4 as libc::c_int as isize) as uint128_t;
    let mut tt_21: uint128_t = t_27.wrapping_add(c2 as uint128_t);
    c2 = tt_21 as BN_ULONG;
    hi_27 = (tt_21 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_27);
    c1 = c1.wrapping_add((c3 < hi_27) as libc::c_int as BN_ULONG);
    t_27 = t_27.wrapping_add(c2 as uint128_t);
    c2 = t_27 as BN_ULONG;
    hi_27 = (t_27 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_27);
    c1 = c1.wrapping_add((c3 < hi_27) as libc::c_int as BN_ULONG);
    let mut hi_28: BN_ULONG = 0;
    let mut t_28: uint128_t = *a.offset(7 as libc::c_int as isize) as uint128_t
        * *a.offset(3 as libc::c_int as isize) as uint128_t;
    let mut tt_22: uint128_t = t_28.wrapping_add(c2 as uint128_t);
    c2 = tt_22 as BN_ULONG;
    hi_28 = (tt_22 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_28);
    c1 = c1.wrapping_add((c3 < hi_28) as libc::c_int as BN_ULONG);
    t_28 = t_28.wrapping_add(c2 as uint128_t);
    c2 = t_28 as BN_ULONG;
    hi_28 = (t_28 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_28);
    c1 = c1.wrapping_add((c3 < hi_28) as libc::c_int as BN_ULONG);
    *r.offset(10 as libc::c_int as isize) = c2;
    c2 = 0 as libc::c_int as BN_ULONG;
    let mut hi_29: BN_ULONG = 0;
    let mut t_29: uint128_t = *a.offset(7 as libc::c_int as isize) as uint128_t
        * *a.offset(4 as libc::c_int as isize) as uint128_t;
    let mut tt_23: uint128_t = t_29.wrapping_add(c3 as uint128_t);
    c3 = tt_23 as BN_ULONG;
    hi_29 = (tt_23 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_29);
    c2 = c2.wrapping_add((c1 < hi_29) as libc::c_int as BN_ULONG);
    t_29 = t_29.wrapping_add(c3 as uint128_t);
    c3 = t_29 as BN_ULONG;
    hi_29 = (t_29 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_29);
    c2 = c2.wrapping_add((c1 < hi_29) as libc::c_int as BN_ULONG);
    let mut hi_30: BN_ULONG = 0;
    let mut t_30: uint128_t = *a.offset(6 as libc::c_int as isize) as uint128_t
        * *a.offset(5 as libc::c_int as isize) as uint128_t;
    let mut tt_24: uint128_t = t_30.wrapping_add(c3 as uint128_t);
    c3 = tt_24 as BN_ULONG;
    hi_30 = (tt_24 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_30);
    c2 = c2.wrapping_add((c1 < hi_30) as libc::c_int as BN_ULONG);
    t_30 = t_30.wrapping_add(c3 as uint128_t);
    c3 = t_30 as BN_ULONG;
    hi_30 = (t_30 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_30);
    c2 = c2.wrapping_add((c1 < hi_30) as libc::c_int as BN_ULONG);
    *r.offset(11 as libc::c_int as isize) = c3;
    c3 = 0 as libc::c_int as BN_ULONG;
    let mut hi_31: BN_ULONG = 0;
    let mut t_31: uint128_t = *a.offset(6 as libc::c_int as isize) as uint128_t
        * *a.offset(6 as libc::c_int as isize) as uint128_t;
    t_31 = t_31.wrapping_add(c1 as uint128_t);
    c1 = t_31 as BN_ULONG;
    hi_31 = (t_31 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_31);
    c3 = c3.wrapping_add((c2 < hi_31) as libc::c_int as BN_ULONG);
    let mut hi_32: BN_ULONG = 0;
    let mut t_32: uint128_t = *a.offset(7 as libc::c_int as isize) as uint128_t
        * *a.offset(5 as libc::c_int as isize) as uint128_t;
    let mut tt_25: uint128_t = t_32.wrapping_add(c1 as uint128_t);
    c1 = tt_25 as BN_ULONG;
    hi_32 = (tt_25 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_32);
    c3 = c3.wrapping_add((c2 < hi_32) as libc::c_int as BN_ULONG);
    t_32 = t_32.wrapping_add(c1 as uint128_t);
    c1 = t_32 as BN_ULONG;
    hi_32 = (t_32 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_32);
    c3 = c3.wrapping_add((c2 < hi_32) as libc::c_int as BN_ULONG);
    *r.offset(12 as libc::c_int as isize) = c1;
    c1 = 0 as libc::c_int as BN_ULONG;
    let mut hi_33: BN_ULONG = 0;
    let mut t_33: uint128_t = *a.offset(7 as libc::c_int as isize) as uint128_t
        * *a.offset(6 as libc::c_int as isize) as uint128_t;
    let mut tt_26: uint128_t = t_33.wrapping_add(c2 as uint128_t);
    c2 = tt_26 as BN_ULONG;
    hi_33 = (tt_26 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_33);
    c1 = c1.wrapping_add((c3 < hi_33) as libc::c_int as BN_ULONG);
    t_33 = t_33.wrapping_add(c2 as uint128_t);
    c2 = t_33 as BN_ULONG;
    hi_33 = (t_33 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_33);
    c1 = c1.wrapping_add((c3 < hi_33) as libc::c_int as BN_ULONG);
    *r.offset(13 as libc::c_int as isize) = c2;
    c2 = 0 as libc::c_int as BN_ULONG;
    let mut hi_34: BN_ULONG = 0;
    let mut t_34: uint128_t = *a.offset(7 as libc::c_int as isize) as uint128_t
        * *a.offset(7 as libc::c_int as isize) as uint128_t;
    t_34 = t_34.wrapping_add(c3 as uint128_t);
    c3 = t_34 as BN_ULONG;
    hi_34 = (t_34 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_34);
    c2 = c2.wrapping_add((c1 < hi_34) as libc::c_int as BN_ULONG);
    *r.offset(14 as libc::c_int as isize) = c3;
    *r.offset(15 as libc::c_int as isize) = c1;
}
#[no_mangle]
pub unsafe extern "C" fn bn_sqr_comba4(mut r: *mut BN_ULONG, mut a: *const BN_ULONG) {
    let mut c1: BN_ULONG = 0;
    let mut c2: BN_ULONG = 0;
    let mut c3: BN_ULONG = 0;
    c1 = 0 as libc::c_int as BN_ULONG;
    c2 = 0 as libc::c_int as BN_ULONG;
    c3 = 0 as libc::c_int as BN_ULONG;
    let mut hi: BN_ULONG = 0;
    let mut t: uint128_t = *a.offset(0 as libc::c_int as isize) as uint128_t
        * *a.offset(0 as libc::c_int as isize) as uint128_t;
    t = t.wrapping_add(c1 as uint128_t);
    c1 = t as BN_ULONG;
    hi = (t >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi);
    c3 = c3.wrapping_add((c2 < hi) as libc::c_int as BN_ULONG);
    *r.offset(0 as libc::c_int as isize) = c1;
    c1 = 0 as libc::c_int as BN_ULONG;
    let mut hi_0: BN_ULONG = 0;
    let mut t_0: uint128_t = *a.offset(1 as libc::c_int as isize) as uint128_t
        * *a.offset(0 as libc::c_int as isize) as uint128_t;
    let mut tt: uint128_t = t_0.wrapping_add(c2 as uint128_t);
    c2 = tt as BN_ULONG;
    hi_0 = (tt >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_0);
    c1 = c1.wrapping_add((c3 < hi_0) as libc::c_int as BN_ULONG);
    t_0 = t_0.wrapping_add(c2 as uint128_t);
    c2 = t_0 as BN_ULONG;
    hi_0 = (t_0 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_0);
    c1 = c1.wrapping_add((c3 < hi_0) as libc::c_int as BN_ULONG);
    *r.offset(1 as libc::c_int as isize) = c2;
    c2 = 0 as libc::c_int as BN_ULONG;
    let mut hi_1: BN_ULONG = 0;
    let mut t_1: uint128_t = *a.offset(1 as libc::c_int as isize) as uint128_t
        * *a.offset(1 as libc::c_int as isize) as uint128_t;
    t_1 = t_1.wrapping_add(c3 as uint128_t);
    c3 = t_1 as BN_ULONG;
    hi_1 = (t_1 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_1);
    c2 = c2.wrapping_add((c1 < hi_1) as libc::c_int as BN_ULONG);
    let mut hi_2: BN_ULONG = 0;
    let mut t_2: uint128_t = *a.offset(2 as libc::c_int as isize) as uint128_t
        * *a.offset(0 as libc::c_int as isize) as uint128_t;
    let mut tt_0: uint128_t = t_2.wrapping_add(c3 as uint128_t);
    c3 = tt_0 as BN_ULONG;
    hi_2 = (tt_0 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_2);
    c2 = c2.wrapping_add((c1 < hi_2) as libc::c_int as BN_ULONG);
    t_2 = t_2.wrapping_add(c3 as uint128_t);
    c3 = t_2 as BN_ULONG;
    hi_2 = (t_2 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_2);
    c2 = c2.wrapping_add((c1 < hi_2) as libc::c_int as BN_ULONG);
    *r.offset(2 as libc::c_int as isize) = c3;
    c3 = 0 as libc::c_int as BN_ULONG;
    let mut hi_3: BN_ULONG = 0;
    let mut t_3: uint128_t = *a.offset(3 as libc::c_int as isize) as uint128_t
        * *a.offset(0 as libc::c_int as isize) as uint128_t;
    let mut tt_1: uint128_t = t_3.wrapping_add(c1 as uint128_t);
    c1 = tt_1 as BN_ULONG;
    hi_3 = (tt_1 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_3);
    c3 = c3.wrapping_add((c2 < hi_3) as libc::c_int as BN_ULONG);
    t_3 = t_3.wrapping_add(c1 as uint128_t);
    c1 = t_3 as BN_ULONG;
    hi_3 = (t_3 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_3);
    c3 = c3.wrapping_add((c2 < hi_3) as libc::c_int as BN_ULONG);
    let mut hi_4: BN_ULONG = 0;
    let mut t_4: uint128_t = *a.offset(2 as libc::c_int as isize) as uint128_t
        * *a.offset(1 as libc::c_int as isize) as uint128_t;
    let mut tt_2: uint128_t = t_4.wrapping_add(c1 as uint128_t);
    c1 = tt_2 as BN_ULONG;
    hi_4 = (tt_2 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_4);
    c3 = c3.wrapping_add((c2 < hi_4) as libc::c_int as BN_ULONG);
    t_4 = t_4.wrapping_add(c1 as uint128_t);
    c1 = t_4 as BN_ULONG;
    hi_4 = (t_4 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_4);
    c3 = c3.wrapping_add((c2 < hi_4) as libc::c_int as BN_ULONG);
    *r.offset(3 as libc::c_int as isize) = c1;
    c1 = 0 as libc::c_int as BN_ULONG;
    let mut hi_5: BN_ULONG = 0;
    let mut t_5: uint128_t = *a.offset(2 as libc::c_int as isize) as uint128_t
        * *a.offset(2 as libc::c_int as isize) as uint128_t;
    t_5 = t_5.wrapping_add(c2 as uint128_t);
    c2 = t_5 as BN_ULONG;
    hi_5 = (t_5 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_5);
    c1 = c1.wrapping_add((c3 < hi_5) as libc::c_int as BN_ULONG);
    let mut hi_6: BN_ULONG = 0;
    let mut t_6: uint128_t = *a.offset(3 as libc::c_int as isize) as uint128_t
        * *a.offset(1 as libc::c_int as isize) as uint128_t;
    let mut tt_3: uint128_t = t_6.wrapping_add(c2 as uint128_t);
    c2 = tt_3 as BN_ULONG;
    hi_6 = (tt_3 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_6);
    c1 = c1.wrapping_add((c3 < hi_6) as libc::c_int as BN_ULONG);
    t_6 = t_6.wrapping_add(c2 as uint128_t);
    c2 = t_6 as BN_ULONG;
    hi_6 = (t_6 >> 64 as libc::c_int) as BN_ULONG;
    c3 = c3.wrapping_add(hi_6);
    c1 = c1.wrapping_add((c3 < hi_6) as libc::c_int as BN_ULONG);
    *r.offset(4 as libc::c_int as isize) = c2;
    c2 = 0 as libc::c_int as BN_ULONG;
    let mut hi_7: BN_ULONG = 0;
    let mut t_7: uint128_t = *a.offset(3 as libc::c_int as isize) as uint128_t
        * *a.offset(2 as libc::c_int as isize) as uint128_t;
    let mut tt_4: uint128_t = t_7.wrapping_add(c3 as uint128_t);
    c3 = tt_4 as BN_ULONG;
    hi_7 = (tt_4 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_7);
    c2 = c2.wrapping_add((c1 < hi_7) as libc::c_int as BN_ULONG);
    t_7 = t_7.wrapping_add(c3 as uint128_t);
    c3 = t_7 as BN_ULONG;
    hi_7 = (t_7 >> 64 as libc::c_int) as BN_ULONG;
    c1 = c1.wrapping_add(hi_7);
    c2 = c2.wrapping_add((c1 < hi_7) as libc::c_int as BN_ULONG);
    *r.offset(5 as libc::c_int as isize) = c3;
    c3 = 0 as libc::c_int as BN_ULONG;
    let mut hi_8: BN_ULONG = 0;
    let mut t_8: uint128_t = *a.offset(3 as libc::c_int as isize) as uint128_t
        * *a.offset(3 as libc::c_int as isize) as uint128_t;
    t_8 = t_8.wrapping_add(c1 as uint128_t);
    c1 = t_8 as BN_ULONG;
    hi_8 = (t_8 >> 64 as libc::c_int) as BN_ULONG;
    c2 = c2.wrapping_add(hi_8);
    c3 = c3.wrapping_add((c2 < hi_8) as libc::c_int as BN_ULONG);
    *r.offset(6 as libc::c_int as isize) = c1;
    *r.offset(7 as libc::c_int as isize) = c2;
}
#[no_mangle]
pub unsafe extern "C" fn bn_add_words(
    mut r: *mut BN_ULONG,
    mut a: *const BN_ULONG,
    mut b: *const BN_ULONG,
    mut n: size_t,
) -> BN_ULONG {
    if n == 0 as libc::c_int as size_t {
        return 0 as libc::c_int as BN_ULONG;
    }
    let mut carry: BN_ULONG = 0 as libc::c_int as BN_ULONG;
    while n & !(3 as libc::c_int) as size_t != 0 {
        *r
            .offset(
                0 as libc::c_int as isize,
            ) = CRYPTO_addc_u64(
            *a.offset(0 as libc::c_int as isize),
            *b.offset(0 as libc::c_int as isize),
            carry,
            &mut carry,
        );
        *r
            .offset(
                1 as libc::c_int as isize,
            ) = CRYPTO_addc_u64(
            *a.offset(1 as libc::c_int as isize),
            *b.offset(1 as libc::c_int as isize),
            carry,
            &mut carry,
        );
        *r
            .offset(
                2 as libc::c_int as isize,
            ) = CRYPTO_addc_u64(
            *a.offset(2 as libc::c_int as isize),
            *b.offset(2 as libc::c_int as isize),
            carry,
            &mut carry,
        );
        *r
            .offset(
                3 as libc::c_int as isize,
            ) = CRYPTO_addc_u64(
            *a.offset(3 as libc::c_int as isize),
            *b.offset(3 as libc::c_int as isize),
            carry,
            &mut carry,
        );
        a = a.offset(4 as libc::c_int as isize);
        b = b.offset(4 as libc::c_int as isize);
        r = r.offset(4 as libc::c_int as isize);
        n = n.wrapping_sub(4 as libc::c_int as size_t);
    }
    while n != 0 {
        *r
            .offset(
                0 as libc::c_int as isize,
            ) = CRYPTO_addc_u64(
            *a.offset(0 as libc::c_int as isize),
            *b.offset(0 as libc::c_int as isize),
            carry,
            &mut carry,
        );
        a = a.offset(1);
        a;
        b = b.offset(1);
        b;
        r = r.offset(1);
        r;
        n = n.wrapping_sub(1);
        n;
    }
    return carry;
}
#[no_mangle]
pub unsafe extern "C" fn bn_sub_words(
    mut r: *mut BN_ULONG,
    mut a: *const BN_ULONG,
    mut b: *const BN_ULONG,
    mut n: size_t,
) -> BN_ULONG {
    if n == 0 as libc::c_int as size_t {
        return 0 as libc::c_int as BN_ULONG;
    }
    let mut borrow: BN_ULONG = 0 as libc::c_int as BN_ULONG;
    while n & !(3 as libc::c_int) as size_t != 0 {
        *r
            .offset(
                0 as libc::c_int as isize,
            ) = CRYPTO_subc_u64(
            *a.offset(0 as libc::c_int as isize),
            *b.offset(0 as libc::c_int as isize),
            borrow,
            &mut borrow,
        );
        *r
            .offset(
                1 as libc::c_int as isize,
            ) = CRYPTO_subc_u64(
            *a.offset(1 as libc::c_int as isize),
            *b.offset(1 as libc::c_int as isize),
            borrow,
            &mut borrow,
        );
        *r
            .offset(
                2 as libc::c_int as isize,
            ) = CRYPTO_subc_u64(
            *a.offset(2 as libc::c_int as isize),
            *b.offset(2 as libc::c_int as isize),
            borrow,
            &mut borrow,
        );
        *r
            .offset(
                3 as libc::c_int as isize,
            ) = CRYPTO_subc_u64(
            *a.offset(3 as libc::c_int as isize),
            *b.offset(3 as libc::c_int as isize),
            borrow,
            &mut borrow,
        );
        a = a.offset(4 as libc::c_int as isize);
        b = b.offset(4 as libc::c_int as isize);
        r = r.offset(4 as libc::c_int as isize);
        n = n.wrapping_sub(4 as libc::c_int as size_t);
    }
    while n != 0 {
        *r
            .offset(
                0 as libc::c_int as isize,
            ) = CRYPTO_subc_u64(
            *a.offset(0 as libc::c_int as isize),
            *b.offset(0 as libc::c_int as isize),
            borrow,
            &mut borrow,
        );
        a = a.offset(1);
        a;
        b = b.offset(1);
        b;
        r = r.offset(1);
        r;
        n = n.wrapping_sub(1);
        n;
    }
    return borrow;
}
