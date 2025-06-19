#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(asm)]
use core::arch::asm;
unsafe extern "C" {
    fn BN_init(bn: *mut BIGNUM);
    fn bn_minimal_width(bn: *const BIGNUM) -> libc::c_int;
    fn bn_fits_in_words(bn: *const BIGNUM, num: size_t) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint64_t = libc::c_ulong;
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
pub type crypto_word_t = uint64_t;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_69_error_is_crypto_word_t_is_too_small {
    #[bitfield(
        name = "static_assertion_at_line_69_error_is_crypto_word_t_is_too_small",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_69_error_is_crypto_word_t_is_too_small: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[inline]
unsafe extern "C" fn value_barrier_w(mut a: crypto_word_t) -> crypto_word_t {
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
unsafe extern "C" fn constant_time_select_w(
    mut mask: crypto_word_t,
    mut a: crypto_word_t,
    mut b: crypto_word_t,
) -> crypto_word_t {
    return value_barrier_w(mask) & a | value_barrier_w(!mask) & b;
}
#[inline]
unsafe extern "C" fn constant_time_select_int(
    mut mask: crypto_word_t,
    mut a: libc::c_int,
    mut b: libc::c_int,
) -> libc::c_int {
    return constant_time_select_w(mask, a as crypto_word_t, b as crypto_word_t)
        as libc::c_int;
}
unsafe extern "C" fn bn_cmp_words_consttime(
    mut a: *const BN_ULONG,
    mut a_len: size_t,
    mut b: *const BN_ULONG,
    mut b_len: size_t,
) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut min: size_t = if a_len < b_len { a_len } else { b_len };
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < min {
        let mut eq: crypto_word_t = constant_time_eq_w(
            *a.offset(i as isize),
            *b.offset(i as isize),
        );
        let mut lt: crypto_word_t = constant_time_lt_w(
            *a.offset(i as isize),
            *b.offset(i as isize),
        );
        ret = constant_time_select_int(
            eq,
            ret,
            constant_time_select_int(lt, -(1 as libc::c_int), 1 as libc::c_int),
        );
        i = i.wrapping_add(1);
        i;
    }
    if a_len < b_len {
        let mut mask: crypto_word_t = 0 as libc::c_int as crypto_word_t;
        let mut i_0: size_t = a_len;
        while i_0 < b_len {
            mask |= *b.offset(i_0 as isize);
            i_0 = i_0.wrapping_add(1);
            i_0;
        }
        ret = constant_time_select_int(
            constant_time_is_zero_w(mask),
            ret,
            -(1 as libc::c_int),
        );
    } else if b_len < a_len {
        let mut mask_0: crypto_word_t = 0 as libc::c_int as crypto_word_t;
        let mut i_1: size_t = b_len;
        while i_1 < a_len {
            mask_0 |= *a.offset(i_1 as isize);
            i_1 = i_1.wrapping_add(1);
            i_1;
        }
        ret = constant_time_select_int(
            constant_time_is_zero_w(mask_0),
            ret,
            1 as libc::c_int,
        );
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_ucmp(
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
) -> libc::c_int {
    return bn_cmp_words_consttime(
        (*a).d,
        (*a).width as size_t,
        (*b).d,
        (*b).width as size_t,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_cmp(
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
) -> libc::c_int {
    if a.is_null() || b.is_null() {
        if !a.is_null() {
            return -(1 as libc::c_int)
        } else if !b.is_null() {
            return 1 as libc::c_int
        } else {
            return 0 as libc::c_int
        }
    }
    if (*a).neg != (*b).neg {
        if (*a).neg != 0 {
            return -(1 as libc::c_int);
        }
        return 1 as libc::c_int;
    }
    let mut ret: libc::c_int = BN_ucmp(a, b);
    return if (*a).neg != 0 { -ret } else { ret };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_less_than_words(
    mut a: *const BN_ULONG,
    mut b: *const BN_ULONG,
    mut len: size_t,
) -> libc::c_int {
    return (bn_cmp_words_consttime(a, len, b, len) < 0 as libc::c_int) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_abs_is_word(
    mut bn: *const BIGNUM,
    mut w: BN_ULONG,
) -> libc::c_int {
    if (*bn).width == 0 as libc::c_int {
        return (w == 0 as libc::c_int as BN_ULONG) as libc::c_int;
    }
    let mut mask: BN_ULONG = *((*bn).d).offset(0 as libc::c_int as isize) ^ w;
    let mut i: libc::c_int = 1 as libc::c_int;
    while i < (*bn).width {
        mask |= *((*bn).d).offset(i as isize);
        i += 1;
        i;
    }
    return (mask == 0 as libc::c_int as BN_ULONG) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_cmp_word(
    mut a: *const BIGNUM,
    mut b: BN_ULONG,
) -> libc::c_int {
    let mut b_bn: BIGNUM = bignum_st {
        d: 0 as *mut BN_ULONG,
        width: 0,
        dmax: 0,
        neg: 0,
        flags: 0,
    };
    BN_init(&mut b_bn);
    b_bn.d = &mut b;
    b_bn.width = (b > 0 as libc::c_int as BN_ULONG) as libc::c_int;
    b_bn.dmax = 1 as libc::c_int;
    b_bn.flags = 0x2 as libc::c_int;
    return BN_cmp(a, &mut b_bn);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_is_zero(mut bn: *const BIGNUM) -> libc::c_int {
    return bn_fits_in_words(bn, 0 as libc::c_int as size_t);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_is_one(mut bn: *const BIGNUM) -> libc::c_int {
    return ((*bn).neg == 0 as libc::c_int
        && BN_abs_is_word(bn, 1 as libc::c_int as BN_ULONG) != 0) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_is_word(
    mut bn: *const BIGNUM,
    mut w: BN_ULONG,
) -> libc::c_int {
    return (BN_abs_is_word(bn, w) != 0
        && (w == 0 as libc::c_int as BN_ULONG || (*bn).neg == 0 as libc::c_int))
        as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_is_odd(mut bn: *const BIGNUM) -> libc::c_int {
    return ((*bn).width > 0 as libc::c_int
        && *((*bn).d).offset(0 as libc::c_int as isize) & 1 as libc::c_int as BN_ULONG
            == 1 as libc::c_int as BN_ULONG) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_is_pow2(mut bn: *const BIGNUM) -> libc::c_int {
    let mut width: libc::c_int = bn_minimal_width(bn);
    if width == 0 as libc::c_int || (*bn).neg != 0 {
        return 0 as libc::c_int;
    }
    let mut i: libc::c_int = 0 as libc::c_int;
    while i < width - 1 as libc::c_int {
        if *((*bn).d).offset(i as isize) != 0 as libc::c_int as BN_ULONG {
            return 0 as libc::c_int;
        }
        i += 1;
        i;
    }
    return (0 as libc::c_int as BN_ULONG
        == *((*bn).d).offset((width - 1 as libc::c_int) as isize)
            & (*((*bn).d).offset((width - 1 as libc::c_int) as isize))
                .wrapping_sub(1 as libc::c_int as BN_ULONG)) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_equal_consttime(
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
) -> libc::c_int {
    let mut mask: BN_ULONG = 0 as libc::c_int as BN_ULONG;
    let mut i: libc::c_int = (*a).width;
    while i < (*b).width {
        mask |= *((*b).d).offset(i as isize);
        i += 1;
        i;
    }
    let mut i_0: libc::c_int = (*b).width;
    while i_0 < (*a).width {
        mask |= *((*a).d).offset(i_0 as isize);
        i_0 += 1;
        i_0;
    }
    let mut min: libc::c_int = if (*a).width < (*b).width {
        (*a).width
    } else {
        (*b).width
    };
    let mut i_1: libc::c_int = 0 as libc::c_int;
    while i_1 < min {
        mask |= *((*a).d).offset(i_1 as isize) ^ *((*b).d).offset(i_1 as isize);
        i_1 += 1;
        i_1;
    }
    mask |= ((*a).neg ^ (*b).neg) as BN_ULONG;
    return (mask == 0 as libc::c_int as BN_ULONG) as libc::c_int;
}
