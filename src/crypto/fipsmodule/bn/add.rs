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
    fn BN_set_word(bn: *mut BIGNUM, value: BN_ULONG) -> libc::c_int;
    fn BN_set_negative(bn: *mut BIGNUM, sign: libc::c_int);
    fn BN_ucmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_is_zero(bn: *const BIGNUM) -> libc::c_int;
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
    fn bn_minimal_width(bn: *const BIGNUM) -> libc::c_int;
    fn bn_set_minimal_width(bn: *mut BIGNUM);
    fn bn_wexpand(bn: *mut BIGNUM, words: size_t) -> libc::c_int;
    fn bn_fits_in_words(bn: *const BIGNUM, num: size_t) -> libc::c_int;
    fn bn_add_words(
        rp: *mut BN_ULONG,
        ap: *const BN_ULONG,
        bp: *const BN_ULONG,
        num: size_t,
    ) -> BN_ULONG;
    fn bn_sub_words(
        rp: *mut BN_ULONG,
        ap: *const BN_ULONG,
        bp: *const BN_ULONG,
        num: size_t,
    ) -> BN_ULONG;
}
pub type __uint128_t = u128;
pub type size_t = libc::c_ulong;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
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
    'c_2126: {
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
    'c_2486: {
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
pub unsafe extern "C" fn BN_add(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
) -> libc::c_int {
    let mut tmp: *const BIGNUM = 0 as *const BIGNUM;
    let mut a_neg: libc::c_int = (*a).neg;
    let mut ret: libc::c_int = 0;
    if a_neg ^ (*b).neg != 0 {
        if a_neg != 0 {
            tmp = a;
            a = b;
            b = tmp;
        }
        if BN_ucmp(a, b) < 0 as libc::c_int {
            if BN_usub(r, b, a) == 0 {
                return 0 as libc::c_int;
            }
            (*r).neg = 1 as libc::c_int;
        } else {
            if BN_usub(r, a, b) == 0 {
                return 0 as libc::c_int;
            }
            (*r).neg = 0 as libc::c_int;
        }
        return 1 as libc::c_int;
    }
    ret = BN_uadd(r, a, b);
    (*r).neg = a_neg;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn bn_uadd_consttime(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
) -> libc::c_int {
    if (*a).width < (*b).width {
        let mut tmp: *const BIGNUM = a;
        a = b;
        b = tmp;
    }
    let mut max: libc::c_int = (*a).width;
    let mut min: libc::c_int = (*b).width;
    if bn_wexpand(r, (max + 1 as libc::c_int) as size_t) == 0 {
        return 0 as libc::c_int;
    }
    (*r).width = max + 1 as libc::c_int;
    let mut carry: BN_ULONG = bn_add_words((*r).d, (*a).d, (*b).d, min as size_t);
    let mut i: libc::c_int = min;
    while i < max {
        *((*r).d)
            .offset(
                i as isize,
            ) = CRYPTO_addc_u64(
            *((*a).d).offset(i as isize),
            0 as libc::c_int as uint64_t,
            carry,
            &mut carry,
        );
        i += 1;
        i;
    }
    *((*r).d).offset(max as isize) = carry;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn BN_uadd(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
) -> libc::c_int {
    if bn_uadd_consttime(r, a, b) == 0 {
        return 0 as libc::c_int;
    }
    bn_set_minimal_width(r);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn BN_add_word(
    mut a: *mut BIGNUM,
    mut w: BN_ULONG,
) -> libc::c_int {
    let mut l: BN_ULONG = 0;
    let mut i: libc::c_int = 0;
    if w == 0 {
        return 1 as libc::c_int;
    }
    if BN_is_zero(a) != 0 {
        return BN_set_word(a, w);
    }
    if (*a).neg != 0 {
        (*a).neg = 0 as libc::c_int;
        i = BN_sub_word(a, w);
        if BN_is_zero(a) == 0 {
            (*a).neg = ((*a).neg == 0) as libc::c_int;
        }
        return i;
    }
    i = 0 as libc::c_int;
    while w != 0 as libc::c_int as BN_ULONG && i < (*a).width {
        l = (*((*a).d).offset(i as isize)).wrapping_add(w);
        *((*a).d).offset(i as isize) = l;
        w = (if w > l { 1 as libc::c_int } else { 0 as libc::c_int }) as BN_ULONG;
        i += 1;
        i;
    }
    if w != 0 && i == (*a).width {
        if bn_wexpand(a, ((*a).width + 1 as libc::c_int) as size_t) == 0 {
            return 0 as libc::c_int;
        }
        (*a).width += 1;
        (*a).width;
        *((*a).d).offset(i as isize) = w;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn BN_sub(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
) -> libc::c_int {
    let mut add: libc::c_int = 0 as libc::c_int;
    let mut neg: libc::c_int = 0 as libc::c_int;
    let mut tmp: *const BIGNUM = 0 as *const BIGNUM;
    if (*a).neg != 0 {
        if (*b).neg != 0 {
            tmp = a;
            a = b;
            b = tmp;
        } else {
            add = 1 as libc::c_int;
            neg = 1 as libc::c_int;
        }
    } else if (*b).neg != 0 {
        add = 1 as libc::c_int;
        neg = 0 as libc::c_int;
    }
    if add != 0 {
        if BN_uadd(r, a, b) == 0 {
            return 0 as libc::c_int;
        }
        (*r).neg = neg;
        return 1 as libc::c_int;
    }
    if BN_ucmp(a, b) < 0 as libc::c_int {
        if BN_usub(r, b, a) == 0 {
            return 0 as libc::c_int;
        }
        (*r).neg = 1 as libc::c_int;
    } else {
        if BN_usub(r, a, b) == 0 {
            return 0 as libc::c_int;
        }
        (*r).neg = 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn bn_usub_consttime(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
) -> libc::c_int {
    let mut b_width: libc::c_int = (*b).width;
    if b_width > (*a).width {
        if bn_fits_in_words(b, (*a).width as size_t) == 0 {
            ERR_put_error(
                3 as libc::c_int,
                0 as libc::c_int,
                100 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/add.c\0"
                    as *const u8 as *const libc::c_char,
                229 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        b_width = (*a).width;
    }
    if bn_wexpand(r, (*a).width as size_t) == 0 {
        return 0 as libc::c_int;
    }
    let mut borrow: BN_ULONG = bn_sub_words((*r).d, (*a).d, (*b).d, b_width as size_t);
    let mut i: libc::c_int = b_width;
    while i < (*a).width {
        *((*r).d)
            .offset(
                i as isize,
            ) = CRYPTO_subc_u64(
            *((*a).d).offset(i as isize),
            0 as libc::c_int as uint64_t,
            borrow,
            &mut borrow,
        );
        i += 1;
        i;
    }
    if borrow != 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/add.c\0"
                as *const u8 as *const libc::c_char,
            245 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*r).width = (*a).width;
    (*r).neg = 0 as libc::c_int;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn BN_usub(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
) -> libc::c_int {
    if bn_usub_consttime(r, a, b) == 0 {
        return 0 as libc::c_int;
    }
    bn_set_minimal_width(r);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn BN_sub_word(
    mut a: *mut BIGNUM,
    mut w: BN_ULONG,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    if w == 0 {
        return 1 as libc::c_int;
    }
    if BN_is_zero(a) != 0 {
        i = BN_set_word(a, w);
        if i != 0 as libc::c_int {
            BN_set_negative(a, 1 as libc::c_int);
        }
        return i;
    }
    if (*a).neg != 0 {
        (*a).neg = 0 as libc::c_int;
        i = BN_add_word(a, w);
        (*a).neg = 1 as libc::c_int;
        return i;
    }
    if bn_minimal_width(a) == 1 as libc::c_int
        && *((*a).d).offset(0 as libc::c_int as isize) < w
    {
        *((*a).d)
            .offset(
                0 as libc::c_int as isize,
            ) = w.wrapping_sub(*((*a).d).offset(0 as libc::c_int as isize));
        (*a).neg = 1 as libc::c_int;
        return 1 as libc::c_int;
    }
    i = 0 as libc::c_int;
    loop {
        if *((*a).d).offset(i as isize) >= w {
            let ref mut fresh0 = *((*a).d).offset(i as isize);
            *fresh0 = (*fresh0).wrapping_sub(w);
            break;
        } else {
            let ref mut fresh1 = *((*a).d).offset(i as isize);
            *fresh1 = (*fresh1).wrapping_sub(w);
            i += 1;
            i;
            w = 1 as libc::c_int as BN_ULONG;
        }
    }
    if *((*a).d).offset(i as isize) == 0 as libc::c_int as BN_ULONG
        && i == (*a).width - 1 as libc::c_int
    {
        (*a).width -= 1;
        (*a).width;
    }
    return 1 as libc::c_int;
}
