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
extern "C" {
    pub type bignum_ctx;
    fn BN_copy(dest: *mut BIGNUM, src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_zero(bn: *mut BIGNUM);
    fn BN_one(bn: *mut BIGNUM) -> libc::c_int;
    fn BN_is_negative(bn: *const BIGNUM) -> libc::c_int;
    fn BN_CTX_start(ctx: *mut BN_CTX);
    fn BN_CTX_get(ctx: *mut BN_CTX) -> *mut BIGNUM;
    fn BN_CTX_end(ctx: *mut BN_CTX);
    fn BN_ucmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_is_zero(bn: *const BIGNUM) -> libc::c_int;
    fn BN_is_one(bn: *const BIGNUM) -> libc::c_int;
    fn BN_is_odd(bn: *const BIGNUM) -> libc::c_int;
    fn BN_lshift(r: *mut BIGNUM, a: *const BIGNUM, n: libc::c_int) -> libc::c_int;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn bn_resize_words(bn: *mut BIGNUM, words: size_t) -> libc::c_int;
    fn bn_select_words(
        r: *mut BN_ULONG,
        mask: BN_ULONG,
        a: *const BN_ULONG,
        b: *const BN_ULONG,
        num: size_t,
    );
    fn bn_set_words(bn: *mut BIGNUM, words: *const BN_ULONG, num: size_t) -> libc::c_int;
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
    fn bn_rshift1_words(r: *mut BN_ULONG, a: *const BN_ULONG, num: size_t);
    fn bn_rshift_secret_shift(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        n: libc::c_uint,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn bn_mul_consttime(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        b: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn bn_div_consttime(
        quotient: *mut BIGNUM,
        remainder: *mut BIGNUM,
        numerator: *const BIGNUM,
        divisor: *const BIGNUM,
        divisor_min_bits: libc::c_uint,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
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
unsafe extern "C" fn word_is_odd_mask(mut a: BN_ULONG) -> BN_ULONG {
    return (0 as libc::c_int as BN_ULONG).wrapping_sub(a & 1 as libc::c_int as BN_ULONG);
}
unsafe extern "C" fn maybe_rshift1_words(
    mut a: *mut BN_ULONG,
    mut mask: BN_ULONG,
    mut tmp: *mut BN_ULONG,
    mut num: size_t,
) {
    bn_rshift1_words(tmp, a, num);
    bn_select_words(a, mask, tmp, a, num);
}
unsafe extern "C" fn maybe_rshift1_words_carry(
    mut a: *mut BN_ULONG,
    mut carry: BN_ULONG,
    mut mask: BN_ULONG,
    mut tmp: *mut BN_ULONG,
    mut num: size_t,
) {
    maybe_rshift1_words(a, mask, tmp, num);
    if num != 0 as libc::c_int as size_t {
        carry &= mask;
        *a.offset(num.wrapping_sub(1 as libc::c_int as size_t) as isize)
            |= carry << 64 as libc::c_int - 1 as libc::c_int;
    }
}
unsafe extern "C" fn maybe_add_words(
    mut a: *mut BN_ULONG,
    mut mask: BN_ULONG,
    mut b: *const BN_ULONG,
    mut tmp: *mut BN_ULONG,
    mut num: size_t,
) -> BN_ULONG {
    let mut carry: BN_ULONG = bn_add_words(tmp, a, b, num);
    bn_select_words(a, mask, tmp, a, num);
    return carry & mask;
}
unsafe extern "C" fn bn_gcd_consttime(
    mut r: *mut BIGNUM,
    mut out_shift: *mut libc::c_uint,
    mut x: *const BIGNUM,
    mut y: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut x_bits: libc::c_uint = 0;
    let mut y_bits: libc::c_uint = 0;
    let mut num_iters: libc::c_uint = 0;
    let mut shift: libc::c_uint = 0;
    let mut width: size_t = (if (*x).width > (*y).width {
        (*x).width
    } else {
        (*y).width
    }) as size_t;
    if width == 0 as libc::c_int as size_t {
        *out_shift = 0 as libc::c_int as libc::c_uint;
        BN_zero(r);
        return 1 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    BN_CTX_start(ctx);
    let mut u: *mut BIGNUM = BN_CTX_get(ctx);
    let mut v: *mut BIGNUM = BN_CTX_get(ctx);
    let mut tmp: *mut BIGNUM = BN_CTX_get(ctx);
    if !(u.is_null() || v.is_null() || tmp.is_null() || (BN_copy(u, x)).is_null()
        || (BN_copy(v, y)).is_null() || bn_resize_words(u, width) == 0
        || bn_resize_words(v, width) == 0 || bn_resize_words(tmp, width) == 0)
    {
        x_bits = ((*x).width * 64 as libc::c_int) as libc::c_uint;
        y_bits = ((*y).width * 64 as libc::c_int) as libc::c_uint;
        num_iters = x_bits.wrapping_add(y_bits);
        if num_iters < x_bits {
            ERR_put_error(
                3 as libc::c_int,
                0 as libc::c_int,
                102 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/gcd_extra.c\0"
                    as *const u8 as *const libc::c_char,
                78 as libc::c_int as libc::c_uint,
            );
        } else {
            shift = 0 as libc::c_int as libc::c_uint;
            let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
            while i < num_iters {
                let mut both_odd: BN_ULONG = word_is_odd_mask(
                    *((*u).d).offset(0 as libc::c_int as isize),
                ) & word_is_odd_mask(*((*v).d).offset(0 as libc::c_int as isize));
                let mut u_less_than_v: BN_ULONG = (0 as libc::c_int as BN_ULONG)
                    .wrapping_sub(bn_sub_words((*tmp).d, (*u).d, (*v).d, width));
                bn_select_words(
                    (*u).d,
                    both_odd & !u_less_than_v,
                    (*tmp).d,
                    (*u).d,
                    width,
                );
                bn_sub_words((*tmp).d, (*v).d, (*u).d, width);
                bn_select_words(
                    (*v).d,
                    both_odd & u_less_than_v,
                    (*tmp).d,
                    (*v).d,
                    width,
                );
                let mut u_is_odd: BN_ULONG = word_is_odd_mask(
                    *((*u).d).offset(0 as libc::c_int as isize),
                );
                let mut v_is_odd: BN_ULONG = word_is_odd_mask(
                    *((*v).d).offset(0 as libc::c_int as isize),
                );
                if constant_time_declassify_int(
                    (u_is_odd & v_is_odd == 0) as libc::c_int,
                ) != 0
                {} else {
                    __assert_fail(
                        b"constant_time_declassify_int(!(u_is_odd & v_is_odd))\0"
                            as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/gcd_extra.c\0"
                            as *const u8 as *const libc::c_char,
                        96 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 89],
                            &[libc::c_char; 89],
                        >(
                            b"int bn_gcd_consttime(BIGNUM *, unsigned int *, const BIGNUM *, const BIGNUM *, BN_CTX *)\0",
                        ))
                            .as_ptr(),
                    );
                }
                'c_2625: {
                    if constant_time_declassify_int(
                        (u_is_odd & v_is_odd == 0) as libc::c_int,
                    ) != 0
                    {} else {
                        __assert_fail(
                            b"constant_time_declassify_int(!(u_is_odd & v_is_odd))\0"
                                as *const u8 as *const libc::c_char,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/gcd_extra.c\0"
                                as *const u8 as *const libc::c_char,
                            96 as libc::c_int as libc::c_uint,
                            (*::core::mem::transmute::<
                                &[u8; 89],
                                &[libc::c_char; 89],
                            >(
                                b"int bn_gcd_consttime(BIGNUM *, unsigned int *, const BIGNUM *, const BIGNUM *, BN_CTX *)\0",
                            ))
                                .as_ptr(),
                        );
                    }
                };
                shift = (shift as BN_ULONG)
                    .wrapping_add(1 as libc::c_int as BN_ULONG & (!u_is_odd & !v_is_odd))
                    as libc::c_uint as libc::c_uint;
                maybe_rshift1_words((*u).d, !u_is_odd, (*tmp).d, width);
                maybe_rshift1_words((*v).d, !v_is_odd, (*tmp).d, width);
                i = i.wrapping_add(1);
                i;
            }
            if constant_time_declassify_int(BN_is_zero(u) | BN_is_zero(v)) != 0 {} else {
                __assert_fail(
                    b"constant_time_declassify_int(BN_is_zero(u) | BN_is_zero(v))\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/gcd_extra.c\0"
                        as *const u8 as *const libc::c_char,
                    109 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 89],
                        &[libc::c_char; 89],
                    >(
                        b"int bn_gcd_consttime(BIGNUM *, unsigned int *, const BIGNUM *, const BIGNUM *, BN_CTX *)\0",
                    ))
                        .as_ptr(),
                );
            }
            'c_2371: {
                if constant_time_declassify_int(BN_is_zero(u) | BN_is_zero(v)) != 0
                {} else {
                    __assert_fail(
                        b"constant_time_declassify_int(BN_is_zero(u) | BN_is_zero(v))\0"
                            as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/gcd_extra.c\0"
                            as *const u8 as *const libc::c_char,
                        109 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 89],
                            &[libc::c_char; 89],
                        >(
                            b"int bn_gcd_consttime(BIGNUM *, unsigned int *, const BIGNUM *, const BIGNUM *, BN_CTX *)\0",
                        ))
                            .as_ptr(),
                    );
                }
            };
            let mut i_0: size_t = 0 as libc::c_int as size_t;
            while i_0 < width {
                *((*v).d).offset(i_0 as isize) |= *((*u).d).offset(i_0 as isize);
                i_0 = i_0.wrapping_add(1);
                i_0;
            }
            *out_shift = shift;
            ret = bn_set_words(r, (*v).d, width);
        }
    }
    BN_CTX_end(ctx);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn BN_gcd(
    mut r: *mut BIGNUM,
    mut x: *const BIGNUM,
    mut y: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut shift: libc::c_uint = 0;
    return (bn_gcd_consttime(r, &mut shift, x, y, ctx) != 0
        && BN_lshift(r, r, shift as libc::c_int) != 0) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn bn_is_relatively_prime(
    mut out_relatively_prime: *mut libc::c_int,
    mut x: *const BIGNUM,
    mut y: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    BN_CTX_start(ctx);
    let mut shift: libc::c_uint = 0;
    let mut gcd: *mut BIGNUM = BN_CTX_get(ctx);
    if !(gcd.is_null() || bn_gcd_consttime(gcd, &mut shift, x, y, ctx) == 0) {
        if (*gcd).width == 0 as libc::c_int {
            *out_relatively_prime = 0 as libc::c_int;
        } else {
            let mut mask: BN_ULONG = shift as BN_ULONG
                | *((*gcd).d).offset(0 as libc::c_int as isize)
                    ^ 1 as libc::c_int as BN_ULONG;
            let mut i: libc::c_int = 1 as libc::c_int;
            while i < (*gcd).width {
                mask |= *((*gcd).d).offset(i as isize);
                i += 1;
                i;
            }
            *out_relatively_prime = (mask == 0 as libc::c_int as BN_ULONG)
                as libc::c_int;
        }
        ret = 1 as libc::c_int;
    }
    BN_CTX_end(ctx);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn bn_lcm_consttime(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    BN_CTX_start(ctx);
    let mut shift: libc::c_uint = 0;
    let mut gcd: *mut BIGNUM = BN_CTX_get(ctx);
    let mut ret: libc::c_int = (!gcd.is_null() && bn_mul_consttime(r, a, b, ctx) != 0
        && bn_gcd_consttime(gcd, &mut shift, a, b, ctx) != 0
        && bn_div_consttime(
            r,
            0 as *mut BIGNUM,
            r,
            gcd,
            0 as libc::c_int as libc::c_uint,
            ctx,
        ) != 0 && bn_rshift_secret_shift(r, r, shift, ctx) != 0) as libc::c_int;
    BN_CTX_end(ctx);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn bn_mod_inverse_consttime(
    mut r: *mut BIGNUM,
    mut out_no_inverse: *mut libc::c_int,
    mut a: *const BIGNUM,
    mut n: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut a_bits: size_t = 0;
    let mut n_bits: size_t = 0;
    let mut num_iters: size_t = 0;
    *out_no_inverse = 0 as libc::c_int;
    if BN_is_negative(a) != 0 || BN_ucmp(a, n) >= 0 as libc::c_int {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            107 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/gcd_extra.c\0"
                as *const u8 as *const libc::c_char,
            174 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if BN_is_zero(a) != 0 {
        if BN_is_one(n) != 0 {
            BN_zero(r);
            return 1 as libc::c_int;
        }
        *out_no_inverse = 1 as libc::c_int;
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            112 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/gcd_extra.c\0"
                as *const u8 as *const libc::c_char,
            183 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if BN_is_odd(a) == 0 && BN_is_odd(n) == 0 {
        *out_no_inverse = 1 as libc::c_int;
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            112 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/gcd_extra.c\0"
                as *const u8 as *const libc::c_char,
            199 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut n_width: size_t = (*n).width as size_t;
    let mut a_width: size_t = (*a).width as size_t;
    if a_width > n_width {
        a_width = n_width;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    BN_CTX_start(ctx);
    let mut u: *mut BIGNUM = BN_CTX_get(ctx);
    let mut v: *mut BIGNUM = BN_CTX_get(ctx);
    let mut A: *mut BIGNUM = BN_CTX_get(ctx);
    let mut B: *mut BIGNUM = BN_CTX_get(ctx);
    let mut C: *mut BIGNUM = BN_CTX_get(ctx);
    let mut D: *mut BIGNUM = BN_CTX_get(ctx);
    let mut tmp: *mut BIGNUM = BN_CTX_get(ctx);
    let mut tmp2: *mut BIGNUM = BN_CTX_get(ctx);
    if !(u.is_null() || v.is_null() || A.is_null() || B.is_null() || C.is_null()
        || D.is_null() || tmp.is_null() || tmp2.is_null() || (BN_copy(u, a)).is_null()
        || (BN_copy(v, n)).is_null() || BN_one(A) == 0 || BN_one(D) == 0
        || bn_resize_words(u, n_width) == 0 || bn_resize_words(v, n_width) == 0
        || bn_resize_words(A, n_width) == 0 || bn_resize_words(C, n_width) == 0
        || bn_resize_words(B, a_width) == 0 || bn_resize_words(D, a_width) == 0
        || bn_resize_words(tmp, n_width) == 0 || bn_resize_words(tmp2, n_width) == 0)
    {
        a_bits = a_width * 64 as libc::c_int as size_t;
        n_bits = n_width * 64 as libc::c_int as size_t;
        num_iters = a_bits.wrapping_add(n_bits);
        if num_iters < a_bits {
            ERR_put_error(
                3 as libc::c_int,
                0 as libc::c_int,
                102 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/gcd_extra.c\0"
                    as *const u8 as *const libc::c_char,
                248 as libc::c_int as libc::c_uint,
            );
        } else {
            let mut i: size_t = 0 as libc::c_int as size_t;
            while i < num_iters {
                let mut both_odd: BN_ULONG = word_is_odd_mask(
                    *((*u).d).offset(0 as libc::c_int as isize),
                ) & word_is_odd_mask(*((*v).d).offset(0 as libc::c_int as isize));
                let mut v_less_than_u: BN_ULONG = (0 as libc::c_int as BN_ULONG)
                    .wrapping_sub(bn_sub_words((*tmp).d, (*v).d, (*u).d, n_width));
                bn_select_words(
                    (*v).d,
                    both_odd & !v_less_than_u,
                    (*tmp).d,
                    (*v).d,
                    n_width,
                );
                bn_sub_words((*tmp).d, (*u).d, (*v).d, n_width);
                bn_select_words(
                    (*u).d,
                    both_odd & v_less_than_u,
                    (*tmp).d,
                    (*u).d,
                    n_width,
                );
                let mut carry: BN_ULONG = bn_add_words(
                    (*tmp).d,
                    (*A).d,
                    (*C).d,
                    n_width,
                );
                carry = carry
                    .wrapping_sub(bn_sub_words((*tmp2).d, (*tmp).d, (*n).d, n_width));
                bn_select_words((*tmp).d, carry, (*tmp).d, (*tmp2).d, n_width);
                bn_select_words(
                    (*A).d,
                    both_odd & v_less_than_u,
                    (*tmp).d,
                    (*A).d,
                    n_width,
                );
                bn_select_words(
                    (*C).d,
                    both_odd & !v_less_than_u,
                    (*tmp).d,
                    (*C).d,
                    n_width,
                );
                bn_add_words((*tmp).d, (*B).d, (*D).d, a_width);
                bn_sub_words((*tmp2).d, (*tmp).d, (*a).d, a_width);
                bn_select_words((*tmp).d, carry, (*tmp).d, (*tmp2).d, a_width);
                bn_select_words(
                    (*B).d,
                    both_odd & v_less_than_u,
                    (*tmp).d,
                    (*B).d,
                    a_width,
                );
                bn_select_words(
                    (*D).d,
                    both_odd & !v_less_than_u,
                    (*tmp).d,
                    (*D).d,
                    a_width,
                );
                let mut u_is_even: BN_ULONG = !word_is_odd_mask(
                    *((*u).d).offset(0 as libc::c_int as isize),
                );
                let mut v_is_even: BN_ULONG = !word_is_odd_mask(
                    *((*v).d).offset(0 as libc::c_int as isize),
                );
                if constant_time_declassify_int((u_is_even != v_is_even) as libc::c_int)
                    != 0
                {} else {
                    __assert_fail(
                        b"constant_time_declassify_int(u_is_even != v_is_even)\0"
                            as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/gcd_extra.c\0"
                            as *const u8 as *const libc::c_char,
                        292 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 88],
                            &[libc::c_char; 88],
                        >(
                            b"int bn_mod_inverse_consttime(BIGNUM *, int *, const BIGNUM *, const BIGNUM *, BN_CTX *)\0",
                        ))
                            .as_ptr(),
                    );
                }
                'c_8966: {
                    if constant_time_declassify_int(
                        (u_is_even != v_is_even) as libc::c_int,
                    ) != 0
                    {} else {
                        __assert_fail(
                            b"constant_time_declassify_int(u_is_even != v_is_even)\0"
                                as *const u8 as *const libc::c_char,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/gcd_extra.c\0"
                                as *const u8 as *const libc::c_char,
                            292 as libc::c_int as libc::c_uint,
                            (*::core::mem::transmute::<
                                &[u8; 88],
                                &[libc::c_char; 88],
                            >(
                                b"int bn_mod_inverse_consttime(BIGNUM *, int *, const BIGNUM *, const BIGNUM *, BN_CTX *)\0",
                            ))
                                .as_ptr(),
                        );
                    }
                };
                maybe_rshift1_words((*u).d, u_is_even, (*tmp).d, n_width);
                let mut A_or_B_is_odd: BN_ULONG = word_is_odd_mask(
                    *((*A).d).offset(0 as libc::c_int as isize),
                ) | word_is_odd_mask(*((*B).d).offset(0 as libc::c_int as isize));
                let mut A_carry: BN_ULONG = maybe_add_words(
                    (*A).d,
                    A_or_B_is_odd & u_is_even,
                    (*n).d,
                    (*tmp).d,
                    n_width,
                );
                let mut B_carry: BN_ULONG = maybe_add_words(
                    (*B).d,
                    A_or_B_is_odd & u_is_even,
                    (*a).d,
                    (*tmp).d,
                    a_width,
                );
                maybe_rshift1_words_carry((*A).d, A_carry, u_is_even, (*tmp).d, n_width);
                maybe_rshift1_words_carry((*B).d, B_carry, u_is_even, (*tmp).d, a_width);
                maybe_rshift1_words((*v).d, v_is_even, (*tmp).d, n_width);
                let mut C_or_D_is_odd: BN_ULONG = word_is_odd_mask(
                    *((*C).d).offset(0 as libc::c_int as isize),
                ) | word_is_odd_mask(*((*D).d).offset(0 as libc::c_int as isize));
                let mut C_carry: BN_ULONG = maybe_add_words(
                    (*C).d,
                    C_or_D_is_odd & v_is_even,
                    (*n).d,
                    (*tmp).d,
                    n_width,
                );
                let mut D_carry: BN_ULONG = maybe_add_words(
                    (*D).d,
                    C_or_D_is_odd & v_is_even,
                    (*a).d,
                    (*tmp).d,
                    a_width,
                );
                maybe_rshift1_words_carry((*C).d, C_carry, v_is_even, (*tmp).d, n_width);
                maybe_rshift1_words_carry((*D).d, D_carry, v_is_even, (*tmp).d, a_width);
                i = i.wrapping_add(1);
                i;
            }
            if constant_time_declassify_int(BN_is_zero(v)) != 0 {} else {
                __assert_fail(
                    b"constant_time_declassify_int(BN_is_zero(v))\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/gcd_extra.c\0"
                        as *const u8 as *const libc::c_char,
                    316 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 88],
                        &[libc::c_char; 88],
                    >(
                        b"int bn_mod_inverse_consttime(BIGNUM *, int *, const BIGNUM *, const BIGNUM *, BN_CTX *)\0",
                    ))
                        .as_ptr(),
                );
            }
            'c_8486: {
                if constant_time_declassify_int(BN_is_zero(v)) != 0 {} else {
                    __assert_fail(
                        b"constant_time_declassify_int(BN_is_zero(v))\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/gcd_extra.c\0"
                            as *const u8 as *const libc::c_char,
                        316 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 88],
                            &[libc::c_char; 88],
                        >(
                            b"int bn_mod_inverse_consttime(BIGNUM *, int *, const BIGNUM *, const BIGNUM *, BN_CTX *)\0",
                        ))
                            .as_ptr(),
                    );
                }
            };
            if constant_time_declassify_int((BN_is_one(u) == 0) as libc::c_int) != 0 {
                *out_no_inverse = 1 as libc::c_int;
                ERR_put_error(
                    3 as libc::c_int,
                    0 as libc::c_int,
                    112 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/gcd_extra.c\0"
                        as *const u8 as *const libc::c_char,
                    322 as libc::c_int as libc::c_uint,
                );
            } else {
                ret = (BN_copy(r, A) != 0 as *mut libc::c_void as *mut BIGNUM)
                    as libc::c_int;
            }
        }
    }
    BN_CTX_end(ctx);
    return ret;
}
