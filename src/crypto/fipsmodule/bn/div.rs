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
    fn BN_free(bn: *mut BIGNUM);
    fn BN_dup(src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_copy(dest: *mut BIGNUM, src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_value_one() -> *const BIGNUM;
    fn BN_num_bits(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_zero(bn: *mut BIGNUM);
    fn BN_is_negative(bn: *const BIGNUM) -> libc::c_int;
    fn BN_CTX_new() -> *mut BN_CTX;
    fn BN_CTX_free(ctx: *mut BN_CTX);
    fn BN_CTX_start(ctx: *mut BN_CTX);
    fn BN_CTX_get(ctx: *mut BN_CTX) -> *mut BIGNUM;
    fn BN_CTX_end(ctx: *mut BN_CTX);
    fn BN_add(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_sub(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_mul(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        b: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_sqr(r: *mut BIGNUM, a: *const BIGNUM, ctx: *mut BN_CTX) -> libc::c_int;
    fn BN_is_zero(bn: *const BIGNUM) -> libc::c_int;
    fn BN_lshift(r: *mut BIGNUM, a: *const BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_lshift1(r: *mut BIGNUM, a: *const BIGNUM) -> libc::c_int;
    fn BN_rshift(r: *mut BIGNUM, a: *const BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_num_bits_word(l: BN_ULONG) -> libc::c_uint;
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
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn bn_minimal_width(bn: *const BIGNUM) -> libc::c_int;
    fn bn_set_minimal_width(bn: *mut BIGNUM);
    fn bn_wexpand(bn: *mut BIGNUM, words: size_t) -> libc::c_int;
    fn bn_resize_words(bn: *mut BIGNUM, words: size_t) -> libc::c_int;
    fn bn_select_words(
        r: *mut BN_ULONG,
        mask: BN_ULONG,
        a: *const BN_ULONG,
        b: *const BN_ULONG,
        num: size_t,
    );
    fn bn_fits_in_words(bn: *const BIGNUM, num: size_t) -> libc::c_int;
    fn bn_mul_words(
        rp: *mut BN_ULONG,
        ap: *const BN_ULONG,
        num: size_t,
        w: BN_ULONG,
    ) -> BN_ULONG;
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
unsafe extern "C" fn OPENSSL_memcpy(
    mut dst: *mut libc::c_void,
    mut src: *const libc::c_void,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return dst;
    }
    return memcpy(dst, src, n);
}
#[inline]
unsafe extern "C" fn OPENSSL_memset(
    mut dst: *mut libc::c_void,
    mut c: libc::c_int,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return dst;
    }
    return memset(dst, c, n);
}
#[inline]
unsafe extern "C" fn bn_div_rem_words(
    mut quotient_out: *mut BN_ULONG,
    mut rem_out: *mut BN_ULONG,
    mut n0: BN_ULONG,
    mut n1: BN_ULONG,
    mut d0: BN_ULONG,
) {
    let mut n: uint128_t = (n0 as uint128_t) << 64 as libc::c_int | n1 as uint128_t;
    *quotient_out = (n / d0 as uint128_t) as BN_ULONG;
    *rem_out = n1.wrapping_sub(*quotient_out * d0);
}
#[no_mangle]
pub unsafe extern "C" fn BN_div(
    mut quotient: *mut BIGNUM,
    mut rem: *mut BIGNUM,
    mut numerator: *const BIGNUM,
    mut divisor: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut numerator_neg: libc::c_int = 0;
    let mut current_block: u64;
    let mut norm_shift: libc::c_int = 0;
    let mut loop_0: libc::c_int = 0;
    let mut wnum: BIGNUM = bignum_st {
        d: 0 as *mut BN_ULONG,
        width: 0,
        dmax: 0,
        neg: 0,
        flags: 0,
    };
    let mut resp: *mut BN_ULONG = 0 as *mut BN_ULONG;
    let mut wnump: *mut BN_ULONG = 0 as *mut BN_ULONG;
    let mut d0: BN_ULONG = 0;
    let mut d1: BN_ULONG = 0;
    let mut num_n: libc::c_int = 0;
    let mut div_n: libc::c_int = 0;
    let mut numerator_width: libc::c_int = bn_minimal_width(numerator);
    let mut divisor_width: libc::c_int = bn_minimal_width(divisor);
    if numerator_width > 0 as libc::c_int
        && *((*numerator).d).offset((numerator_width - 1 as libc::c_int) as isize)
            == 0 as libc::c_int as BN_ULONG
        || divisor_width > 0 as libc::c_int
            && *((*divisor).d).offset((divisor_width - 1 as libc::c_int) as isize)
                == 0 as libc::c_int as BN_ULONG
    {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            111 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/div.c\0"
                as *const u8 as *const libc::c_char,
            212 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if BN_is_zero(divisor) != 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/div.c\0"
                as *const u8 as *const libc::c_char,
            217 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    BN_CTX_start(ctx);
    let mut tmp: *mut BIGNUM = BN_CTX_get(ctx);
    let mut snum: *mut BIGNUM = BN_CTX_get(ctx);
    let mut sdiv: *mut BIGNUM = BN_CTX_get(ctx);
    let mut res: *mut BIGNUM = 0 as *mut BIGNUM;
    if quotient.is_null() {
        res = BN_CTX_get(ctx);
    } else {
        res = quotient;
    }
    if !(sdiv.is_null() || res.is_null()) {
        norm_shift = (64 as libc::c_int as libc::c_uint)
            .wrapping_sub(
                (BN_num_bits(divisor)).wrapping_rem(64 as libc::c_int as libc::c_uint),
            ) as libc::c_int;
        if !(BN_lshift(sdiv, divisor, norm_shift) == 0) {
            bn_set_minimal_width(sdiv);
            (*sdiv).neg = 0 as libc::c_int;
            norm_shift += 64 as libc::c_int;
            if !(BN_lshift(snum, numerator, norm_shift) == 0) {
                bn_set_minimal_width(snum);
                (*snum).neg = 0 as libc::c_int;
                if (*snum).width <= (*sdiv).width + 1 as libc::c_int {
                    if bn_wexpand(snum, ((*sdiv).width + 2 as libc::c_int) as size_t)
                        == 0
                    {
                        current_block = 8564979239633264353;
                    } else {
                        let mut i: libc::c_int = (*snum).width;
                        while i < (*sdiv).width + 2 as libc::c_int {
                            *((*snum).d)
                                .offset(i as isize) = 0 as libc::c_int as BN_ULONG;
                            i += 1;
                            i;
                        }
                        (*snum).width = (*sdiv).width + 2 as libc::c_int;
                        current_block = 2891135413264362348;
                    }
                } else if bn_wexpand(snum, ((*snum).width + 1 as libc::c_int) as size_t)
                    == 0
                {
                    current_block = 8564979239633264353;
                } else {
                    *((*snum).d)
                        .offset((*snum).width as isize) = 0 as libc::c_int as BN_ULONG;
                    (*snum).width += 1;
                    (*snum).width;
                    current_block = 2891135413264362348;
                }
                match current_block {
                    8564979239633264353 => {}
                    _ => {
                        div_n = (*sdiv).width;
                        num_n = (*snum).width;
                        loop_0 = num_n - div_n;
                        wnum.neg = 0 as libc::c_int;
                        wnum
                            .d = &mut *((*snum).d).offset(loop_0 as isize)
                            as *mut BN_ULONG;
                        wnum.width = div_n;
                        wnum.dmax = (*snum).dmax - loop_0;
                        d0 = *((*sdiv).d).offset((div_n - 1 as libc::c_int) as isize);
                        d1 = if div_n == 1 as libc::c_int {
                            0 as libc::c_int as BN_ULONG
                        } else {
                            *((*sdiv).d).offset((div_n - 2 as libc::c_int) as isize)
                        };
                        wnump = &mut *((*snum).d)
                            .offset((num_n - 1 as libc::c_int) as isize)
                            as *mut BN_ULONG;
                        numerator_neg = (*numerator).neg;
                        (*res).neg = numerator_neg ^ (*divisor).neg;
                        if !(bn_wexpand(res, (loop_0 + 1 as libc::c_int) as size_t) == 0)
                        {
                            (*res).width = loop_0 - 1 as libc::c_int;
                            resp = &mut *((*res).d)
                                .offset((loop_0 - 1 as libc::c_int) as isize)
                                as *mut BN_ULONG;
                            if !(bn_wexpand(tmp, (div_n + 1 as libc::c_int) as size_t)
                                == 0)
                            {
                                if (*res).width == 0 as libc::c_int {
                                    (*res).neg = 0 as libc::c_int;
                                } else {
                                    resp = resp.offset(-1);
                                    resp;
                                }
                                let mut i_0: libc::c_int = 0 as libc::c_int;
                                while i_0 < loop_0 - 1 as libc::c_int {
                                    let mut q: BN_ULONG = 0;
                                    let mut l0: BN_ULONG = 0;
                                    let mut n0: BN_ULONG = 0;
                                    let mut n1: BN_ULONG = 0;
                                    let mut rm: BN_ULONG = 0 as libc::c_int as BN_ULONG;
                                    n0 = *wnump.offset(0 as libc::c_int as isize);
                                    n1 = *wnump.offset(-(1 as libc::c_int) as isize);
                                    if n0 == d0 {
                                        q = 0xffffffffffffffff as libc::c_ulong;
                                    } else {
                                        bn_div_rem_words(&mut q, &mut rm, n0, n1, d0);
                                        let mut t2: uint128_t = d1 as uint128_t * q as uint128_t;
                                        while !(t2
                                            <= (rm as uint128_t) << 64 as libc::c_int
                                                | *wnump.offset(-(2 as libc::c_int) as isize) as uint128_t)
                                        {
                                            q = q.wrapping_sub(1);
                                            q;
                                            rm = rm.wrapping_add(d0);
                                            if rm < d0 {
                                                break;
                                            }
                                            t2 = t2.wrapping_sub(d1 as uint128_t);
                                        }
                                    }
                                    l0 = bn_mul_words((*tmp).d, (*sdiv).d, div_n as size_t, q);
                                    *((*tmp).d).offset(div_n as isize) = l0;
                                    wnum.d = (wnum.d).offset(-1);
                                    wnum.d;
                                    if bn_sub_words(
                                        wnum.d,
                                        wnum.d,
                                        (*tmp).d,
                                        (div_n + 1 as libc::c_int) as size_t,
                                    ) != 0
                                    {
                                        q = q.wrapping_sub(1);
                                        q;
                                        if bn_add_words(wnum.d, wnum.d, (*sdiv).d, div_n as size_t)
                                            != 0
                                        {
                                            *wnump = (*wnump).wrapping_add(1);
                                            *wnump;
                                        }
                                    }
                                    *resp = q;
                                    i_0 += 1;
                                    i_0;
                                    wnump = wnump.offset(-1);
                                    wnump;
                                    resp = resp.offset(-1);
                                    resp;
                                }
                                bn_set_minimal_width(snum);
                                if !rem.is_null() {
                                    if BN_rshift(rem, snum, norm_shift) == 0 {
                                        current_block = 8564979239633264353;
                                    } else {
                                        if BN_is_zero(rem) == 0 {
                                            (*rem).neg = numerator_neg;
                                        }
                                        current_block = 11796148217846552555;
                                    }
                                } else {
                                    current_block = 11796148217846552555;
                                }
                                match current_block {
                                    8564979239633264353 => {}
                                    _ => {
                                        bn_set_minimal_width(res);
                                        BN_CTX_end(ctx);
                                        return 1 as libc::c_int;
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
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn BN_nnmod(
    mut r: *mut BIGNUM,
    mut m: *const BIGNUM,
    mut d: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if BN_div(0 as *mut BIGNUM, r, m, d, ctx) == 0 {
        return 0 as libc::c_int;
    }
    if (*r).neg == 0 {
        return 1 as libc::c_int;
    }
    return if (*d).neg != 0 {
        Some(
            BN_sub
                as unsafe extern "C" fn(
                    *mut BIGNUM,
                    *const BIGNUM,
                    *const BIGNUM,
                ) -> libc::c_int,
        )
    } else {
        Some(
            BN_add
                as unsafe extern "C" fn(
                    *mut BIGNUM,
                    *const BIGNUM,
                    *const BIGNUM,
                ) -> libc::c_int,
        )
    }
        .expect("non-null function pointer")(r, r, d);
}
#[no_mangle]
pub unsafe extern "C" fn bn_reduce_once(
    mut r: *mut BN_ULONG,
    mut a: *const BN_ULONG,
    mut carry: BN_ULONG,
    mut m: *const BN_ULONG,
    mut num: size_t,
) -> BN_ULONG {
    if r != a as *mut BN_ULONG {} else {
        __assert_fail(
            b"r != a\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/div.c\0"
                as *const u8 as *const libc::c_char,
            415 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 90],
                &[libc::c_char; 90],
            >(
                b"BN_ULONG bn_reduce_once(BN_ULONG *, const BN_ULONG *, BN_ULONG, const BN_ULONG *, size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_10258: {
        if r != a as *mut BN_ULONG {} else {
            __assert_fail(
                b"r != a\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/div.c\0"
                    as *const u8 as *const libc::c_char,
                415 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 90],
                    &[libc::c_char; 90],
                >(
                    b"BN_ULONG bn_reduce_once(BN_ULONG *, const BN_ULONG *, BN_ULONG, const BN_ULONG *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    carry = carry.wrapping_sub(bn_sub_words(r, a, m, num));
    if constant_time_declassify_int(
        (carry.wrapping_add(1 as libc::c_int as BN_ULONG)
            <= 1 as libc::c_int as BN_ULONG) as libc::c_int,
    ) != 0
    {} else {
        __assert_fail(
            b"constant_time_declassify_int(carry + 1 <= 1)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/div.c\0"
                as *const u8 as *const libc::c_char,
            428 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 90],
                &[libc::c_char; 90],
            >(
                b"BN_ULONG bn_reduce_once(BN_ULONG *, const BN_ULONG *, BN_ULONG, const BN_ULONG *, size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_10194: {
        if constant_time_declassify_int(
            (carry.wrapping_add(1 as libc::c_int as BN_ULONG)
                <= 1 as libc::c_int as BN_ULONG) as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(carry + 1 <= 1)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/div.c\0"
                    as *const u8 as *const libc::c_char,
                428 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 90],
                    &[libc::c_char; 90],
                >(
                    b"BN_ULONG bn_reduce_once(BN_ULONG *, const BN_ULONG *, BN_ULONG, const BN_ULONG *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    bn_select_words(r, carry, a, r, num);
    return carry;
}
#[no_mangle]
pub unsafe extern "C" fn bn_reduce_once_in_place(
    mut r: *mut BN_ULONG,
    mut carry: BN_ULONG,
    mut m: *const BN_ULONG,
    mut tmp: *mut BN_ULONG,
    mut num: size_t,
) -> BN_ULONG {
    carry = carry.wrapping_sub(bn_sub_words(tmp, r, m, num));
    if constant_time_declassify_int(
        (carry.wrapping_add(1 as libc::c_int as BN_ULONG)
            <= 1 as libc::c_int as BN_ULONG) as libc::c_int,
    ) != 0
    {} else {
        __assert_fail(
            b"constant_time_declassify_int(carry + 1 <= 1)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/div.c\0"
                as *const u8 as *const libc::c_char,
            437 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 93],
                &[libc::c_char; 93],
            >(
                b"BN_ULONG bn_reduce_once_in_place(BN_ULONG *, BN_ULONG, const BN_ULONG *, BN_ULONG *, size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_3986: {
        if constant_time_declassify_int(
            (carry.wrapping_add(1 as libc::c_int as BN_ULONG)
                <= 1 as libc::c_int as BN_ULONG) as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(carry + 1 <= 1)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/div.c\0"
                    as *const u8 as *const libc::c_char,
                437 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 93],
                    &[libc::c_char; 93],
                >(
                    b"BN_ULONG bn_reduce_once_in_place(BN_ULONG *, BN_ULONG, const BN_ULONG *, BN_ULONG *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    bn_select_words(r, carry, r, tmp, num);
    return carry;
}
#[no_mangle]
pub unsafe extern "C" fn bn_mod_sub_words(
    mut r: *mut BN_ULONG,
    mut a: *const BN_ULONG,
    mut b: *const BN_ULONG,
    mut m: *const BN_ULONG,
    mut tmp: *mut BN_ULONG,
    mut num: size_t,
) {
    let mut borrow: BN_ULONG = bn_sub_words(r, a, b, num);
    bn_add_words(tmp, r, m, num);
    bn_select_words(r, (0 as libc::c_int as BN_ULONG).wrapping_sub(borrow), tmp, r, num);
}
#[no_mangle]
pub unsafe extern "C" fn bn_mod_add_words(
    mut r: *mut BN_ULONG,
    mut a: *const BN_ULONG,
    mut b: *const BN_ULONG,
    mut m: *const BN_ULONG,
    mut tmp: *mut BN_ULONG,
    mut num: size_t,
) {
    let mut carry: BN_ULONG = bn_add_words(r, a, b, num);
    bn_reduce_once_in_place(r, carry, m, tmp, num);
}
#[no_mangle]
pub unsafe extern "C" fn bn_div_consttime(
    mut quotient: *mut BIGNUM,
    mut remainder: *mut BIGNUM,
    mut numerator: *const BIGNUM,
    mut divisor: *const BIGNUM,
    mut divisor_min_bits: libc::c_uint,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut initial_words: libc::c_int = 0;
    if BN_is_negative(numerator) != 0 || BN_is_negative(divisor) != 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/div.c\0"
                as *const u8 as *const libc::c_char,
            461 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if BN_is_zero(divisor) != 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/div.c\0"
                as *const u8 as *const libc::c_char,
            465 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    BN_CTX_start(ctx);
    let mut q: *mut BIGNUM = quotient;
    let mut r: *mut BIGNUM = remainder;
    if quotient.is_null() || quotient == numerator as *mut BIGNUM
        || quotient == divisor as *mut BIGNUM
    {
        q = BN_CTX_get(ctx);
    }
    if remainder.is_null() || remainder == numerator as *mut BIGNUM
        || remainder == divisor as *mut BIGNUM
    {
        r = BN_CTX_get(ctx);
    }
    let mut tmp: *mut BIGNUM = BN_CTX_get(ctx);
    if !(q.is_null() || r.is_null() || tmp.is_null()
        || bn_wexpand(q, (*numerator).width as size_t) == 0
        || bn_wexpand(r, (*divisor).width as size_t) == 0
        || bn_wexpand(tmp, (*divisor).width as size_t) == 0)
    {
        OPENSSL_memset(
            (*q).d as *mut libc::c_void,
            0 as libc::c_int,
            ((*numerator).width as libc::c_ulong)
                .wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
        );
        (*q).width = (*numerator).width;
        (*q).neg = 0 as libc::c_int;
        OPENSSL_memset(
            (*r).d as *mut libc::c_void,
            0 as libc::c_int,
            ((*divisor).width as libc::c_ulong)
                .wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
        );
        (*r).width = (*divisor).width;
        (*r).neg = 0 as libc::c_int;
        if constant_time_declassify_int(
            (divisor_min_bits <= BN_num_bits(divisor)) as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(divisor_min_bits <= BN_num_bits(divisor))\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/div.c\0"
                    as *const u8 as *const libc::c_char,
                507 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 97],
                    &[libc::c_char; 97],
                >(
                    b"int bn_div_consttime(BIGNUM *, BIGNUM *, const BIGNUM *, const BIGNUM *, unsigned int, BN_CTX *)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_10603: {
            if constant_time_declassify_int(
                (divisor_min_bits <= BN_num_bits(divisor)) as libc::c_int,
            ) != 0
            {} else {
                __assert_fail(
                    b"constant_time_declassify_int(divisor_min_bits <= BN_num_bits(divisor))\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/div.c\0"
                        as *const u8 as *const libc::c_char,
                    507 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 97],
                        &[libc::c_char; 97],
                    >(
                        b"int bn_div_consttime(BIGNUM *, BIGNUM *, const BIGNUM *, const BIGNUM *, unsigned int, BN_CTX *)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        initial_words = 0 as libc::c_int;
        if divisor_min_bits > 0 as libc::c_int as libc::c_uint {
            initial_words = divisor_min_bits
                .wrapping_sub(1 as libc::c_int as libc::c_uint)
                .wrapping_div(64 as libc::c_int as libc::c_uint) as libc::c_int;
            if initial_words > (*numerator).width {
                initial_words = (*numerator).width;
            }
            OPENSSL_memcpy(
                (*r).d as *mut libc::c_void,
                ((*numerator).d)
                    .offset((*numerator).width as isize)
                    .offset(-(initial_words as isize)) as *const libc::c_void,
                (initial_words as libc::c_ulong)
                    .wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
            );
        }
        let mut i: libc::c_int = (*numerator).width - initial_words - 1 as libc::c_int;
        while i >= 0 as libc::c_int {
            let mut bit: libc::c_int = 64 as libc::c_int - 1 as libc::c_int;
            while bit >= 0 as libc::c_int {
                let mut carry: BN_ULONG = bn_add_words(
                    (*r).d,
                    (*r).d,
                    (*r).d,
                    (*divisor).width as size_t,
                );
                *((*r).d).offset(0 as libc::c_int as isize)
                    |= *((*numerator).d).offset(i as isize) >> bit
                        & 1 as libc::c_int as BN_ULONG;
                let mut subtracted: BN_ULONG = bn_reduce_once_in_place(
                    (*r).d,
                    carry,
                    (*divisor).d,
                    (*tmp).d,
                    (*divisor).width as size_t,
                );
                *((*q).d).offset(i as isize)
                    |= (!subtracted & 1 as libc::c_int as BN_ULONG) << bit;
                bit -= 1;
                bit;
            }
            i -= 1;
            i;
        }
        if !(!quotient.is_null() && (BN_copy(quotient, q)).is_null()
            || !remainder.is_null() && (BN_copy(remainder, r)).is_null())
        {
            ret = 1 as libc::c_int;
        }
    }
    BN_CTX_end(ctx);
    return ret;
}
unsafe extern "C" fn bn_scratch_space_from_ctx(
    mut width: size_t,
    mut ctx: *mut BN_CTX,
) -> *mut BIGNUM {
    let mut ret: *mut BIGNUM = BN_CTX_get(ctx);
    if ret.is_null() || bn_wexpand(ret, width) == 0 {
        return 0 as *mut BIGNUM;
    }
    (*ret).neg = 0 as libc::c_int;
    (*ret).width = width as libc::c_int;
    return ret;
}
unsafe extern "C" fn bn_resized_from_ctx(
    mut bn: *const BIGNUM,
    mut width: size_t,
    mut ctx: *mut BN_CTX,
) -> *const BIGNUM {
    if (*bn).width as size_t >= width {
        if bn_fits_in_words(bn, width) != 0 {} else {
            __assert_fail(
                b"bn_fits_in_words(bn, width)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/div.c\0"
                    as *const u8 as *const libc::c_char,
                568 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 68],
                    &[libc::c_char; 68],
                >(
                    b"const BIGNUM *bn_resized_from_ctx(const BIGNUM *, size_t, BN_CTX *)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_4167: {
            if bn_fits_in_words(bn, width) != 0 {} else {
                __assert_fail(
                    b"bn_fits_in_words(bn, width)\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/div.c\0"
                        as *const u8 as *const libc::c_char,
                    568 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 68],
                        &[libc::c_char; 68],
                    >(
                        b"const BIGNUM *bn_resized_from_ctx(const BIGNUM *, size_t, BN_CTX *)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        return bn;
    }
    let mut ret: *mut BIGNUM = bn_scratch_space_from_ctx(width, ctx);
    if ret.is_null() || (BN_copy(ret, bn)).is_null() || bn_resize_words(ret, width) == 0
    {
        return 0 as *const BIGNUM;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn BN_mod_add(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
    mut m: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if BN_add(r, a, b) == 0 {
        return 0 as libc::c_int;
    }
    return BN_nnmod(r, r, m, ctx);
}
#[no_mangle]
pub unsafe extern "C" fn BN_mod_add_quick(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
    mut m: *const BIGNUM,
) -> libc::c_int {
    let mut ctx: *mut BN_CTX = BN_CTX_new();
    let mut ok: libc::c_int = (!ctx.is_null()
        && bn_mod_add_consttime(r, a, b, m, ctx) != 0) as libc::c_int;
    BN_CTX_free(ctx);
    return ok;
}
#[no_mangle]
pub unsafe extern "C" fn bn_mod_add_consttime(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
    mut m: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    BN_CTX_start(ctx);
    a = bn_resized_from_ctx(a, (*m).width as size_t, ctx);
    b = bn_resized_from_ctx(b, (*m).width as size_t, ctx);
    let mut tmp: *mut BIGNUM = bn_scratch_space_from_ctx((*m).width as size_t, ctx);
    let mut ok: libc::c_int = (!a.is_null() && !b.is_null() && !tmp.is_null()
        && bn_wexpand(r, (*m).width as size_t) != 0) as libc::c_int;
    if ok != 0 {
        bn_mod_add_words((*r).d, (*a).d, (*b).d, (*m).d, (*tmp).d, (*m).width as size_t);
        (*r).width = (*m).width;
        (*r).neg = 0 as libc::c_int;
    }
    BN_CTX_end(ctx);
    return ok;
}
#[no_mangle]
pub unsafe extern "C" fn BN_mod_sub(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
    mut m: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if BN_sub(r, a, b) == 0 {
        return 0 as libc::c_int;
    }
    return BN_nnmod(r, r, m, ctx);
}
#[no_mangle]
pub unsafe extern "C" fn bn_mod_sub_consttime(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
    mut m: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    BN_CTX_start(ctx);
    a = bn_resized_from_ctx(a, (*m).width as size_t, ctx);
    b = bn_resized_from_ctx(b, (*m).width as size_t, ctx);
    let mut tmp: *mut BIGNUM = bn_scratch_space_from_ctx((*m).width as size_t, ctx);
    let mut ok: libc::c_int = (!a.is_null() && !b.is_null() && !tmp.is_null()
        && bn_wexpand(r, (*m).width as size_t) != 0) as libc::c_int;
    if ok != 0 {
        bn_mod_sub_words((*r).d, (*a).d, (*b).d, (*m).d, (*tmp).d, (*m).width as size_t);
        (*r).width = (*m).width;
        (*r).neg = 0 as libc::c_int;
    }
    BN_CTX_end(ctx);
    return ok;
}
#[no_mangle]
pub unsafe extern "C" fn BN_mod_sub_quick(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
    mut m: *const BIGNUM,
) -> libc::c_int {
    let mut ctx: *mut BN_CTX = BN_CTX_new();
    let mut ok: libc::c_int = (!ctx.is_null()
        && bn_mod_sub_consttime(r, a, b, m, ctx) != 0) as libc::c_int;
    BN_CTX_free(ctx);
    return ok;
}
#[no_mangle]
pub unsafe extern "C" fn BN_mod_mul(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
    mut m: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut current_block: u64;
    let mut t: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut ret: libc::c_int = 0 as libc::c_int;
    BN_CTX_start(ctx);
    t = BN_CTX_get(ctx);
    if !t.is_null() {
        if a == b {
            if BN_sqr(t, a, ctx) == 0 {
                current_block = 13870892827929139795;
            } else {
                current_block = 14523784380283086299;
            }
        } else if BN_mul(t, a, b, ctx) == 0 {
            current_block = 13870892827929139795;
        } else {
            current_block = 14523784380283086299;
        }
        match current_block {
            13870892827929139795 => {}
            _ => {
                if !(BN_nnmod(r, t, m, ctx) == 0) {
                    ret = 1 as libc::c_int;
                }
            }
        }
    }
    BN_CTX_end(ctx);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn BN_mod_sqr(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut m: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if BN_sqr(r, a, ctx) == 0 {
        return 0 as libc::c_int;
    }
    return BN_div(0 as *mut BIGNUM, r, r, m, ctx);
}
#[no_mangle]
pub unsafe extern "C" fn BN_mod_lshift(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut n: libc::c_int,
    mut m: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut abs_m: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut ret: libc::c_int = 0;
    if BN_nnmod(r, a, m, ctx) == 0 {
        return 0 as libc::c_int;
    }
    if (*m).neg != 0 {
        abs_m = BN_dup(m);
        if abs_m.is_null() {
            return 0 as libc::c_int;
        }
        (*abs_m).neg = 0 as libc::c_int;
    }
    ret = bn_mod_lshift_consttime(
        r,
        r,
        n,
        if !abs_m.is_null() { abs_m as *const BIGNUM } else { m },
        ctx,
    );
    BN_free(abs_m);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn bn_mod_lshift_consttime(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut n: libc::c_int,
    mut m: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if (BN_copy(r, a)).is_null() || bn_resize_words(r, (*m).width as size_t) == 0 {
        return 0 as libc::c_int;
    }
    BN_CTX_start(ctx);
    let mut tmp: *mut BIGNUM = bn_scratch_space_from_ctx((*m).width as size_t, ctx);
    let mut ok: libc::c_int = (tmp != 0 as *mut libc::c_void as *mut BIGNUM)
        as libc::c_int;
    if ok != 0 {
        let mut i: libc::c_int = 0 as libc::c_int;
        while i < n {
            bn_mod_add_words(
                (*r).d,
                (*r).d,
                (*r).d,
                (*m).d,
                (*tmp).d,
                (*m).width as size_t,
            );
            i += 1;
            i;
        }
        (*r).neg = 0 as libc::c_int;
    }
    BN_CTX_end(ctx);
    return ok;
}
#[no_mangle]
pub unsafe extern "C" fn BN_mod_lshift_quick(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut n: libc::c_int,
    mut m: *const BIGNUM,
) -> libc::c_int {
    let mut ctx: *mut BN_CTX = BN_CTX_new();
    let mut ok: libc::c_int = (!ctx.is_null()
        && bn_mod_lshift_consttime(r, a, n, m, ctx) != 0) as libc::c_int;
    BN_CTX_free(ctx);
    return ok;
}
#[no_mangle]
pub unsafe extern "C" fn BN_mod_lshift1(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut m: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if BN_lshift1(r, a) == 0 {
        return 0 as libc::c_int;
    }
    return BN_nnmod(r, r, m, ctx);
}
#[no_mangle]
pub unsafe extern "C" fn bn_mod_lshift1_consttime(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut m: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    return bn_mod_add_consttime(r, a, a, m, ctx);
}
#[no_mangle]
pub unsafe extern "C" fn BN_mod_lshift1_quick(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut m: *const BIGNUM,
) -> libc::c_int {
    let mut ctx: *mut BN_CTX = BN_CTX_new();
    let mut ok: libc::c_int = (!ctx.is_null()
        && bn_mod_lshift1_consttime(r, a, m, ctx) != 0) as libc::c_int;
    BN_CTX_free(ctx);
    return ok;
}
#[no_mangle]
pub unsafe extern "C" fn BN_div_word(mut a: *mut BIGNUM, mut w: BN_ULONG) -> BN_ULONG {
    let mut ret: BN_ULONG = 0 as libc::c_int as BN_ULONG;
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    if w == 0 {
        return -(1 as libc::c_int) as BN_ULONG;
    }
    if (*a).width == 0 as libc::c_int {
        return 0 as libc::c_int as BN_ULONG;
    }
    j = (64 as libc::c_int as libc::c_uint).wrapping_sub(BN_num_bits_word(w))
        as libc::c_int;
    w <<= j;
    if BN_lshift(a, a, j) == 0 {
        return -(1 as libc::c_int) as BN_ULONG;
    }
    i = (*a).width - 1 as libc::c_int;
    while i >= 0 as libc::c_int {
        let mut l: BN_ULONG = *((*a).d).offset(i as isize);
        let mut d: BN_ULONG = 0;
        let mut unused_rem: BN_ULONG = 0;
        bn_div_rem_words(&mut d, &mut unused_rem, ret, l, w);
        ret = l.wrapping_sub(d * w);
        *((*a).d).offset(i as isize) = d;
        i -= 1;
        i;
    }
    bn_set_minimal_width(a);
    ret >>= j;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn BN_mod_word(mut a: *const BIGNUM, mut w: BN_ULONG) -> BN_ULONG {
    let mut ret: uint128_t = 0 as libc::c_int as uint128_t;
    let mut i: libc::c_int = 0;
    if w == 0 as libc::c_int as BN_ULONG {
        return -(1 as libc::c_int) as BN_ULONG;
    }
    i = (*a).width - 1 as libc::c_int;
    while i >= 0 as libc::c_int {
        ret = (ret << 64 as libc::c_int as uint128_t
            | *((*a).d).offset(i as isize) as uint128_t) % w as uint128_t;
        i -= 1;
        i;
    }
    return ret as BN_ULONG;
}
#[no_mangle]
pub unsafe extern "C" fn BN_mod_pow2(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut e: size_t,
) -> libc::c_int {
    if e == 0 as libc::c_int as size_t || (*a).width == 0 as libc::c_int {
        BN_zero(r);
        return 1 as libc::c_int;
    }
    let mut num_words: size_t = (1 as libc::c_int as size_t)
        .wrapping_add(
            e.wrapping_sub(1 as libc::c_int as size_t) / 64 as libc::c_int as size_t,
        );
    if ((*a).width as size_t) < num_words {
        return (BN_copy(r, a) != 0 as *mut libc::c_void as *mut BIGNUM) as libc::c_int;
    }
    if bn_wexpand(r, num_words) == 0 {
        return 0 as libc::c_int;
    }
    OPENSSL_memcpy(
        (*r).d as *mut libc::c_void,
        (*a).d as *const libc::c_void,
        num_words.wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    );
    let mut top_word_exponent: size_t = e
        .wrapping_rem(
            (::core::mem::size_of::<BN_ULONG>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong),
        );
    if top_word_exponent != 0 as libc::c_int as size_t {
        *((*r).d).offset(num_words.wrapping_sub(1 as libc::c_int as size_t) as isize)
            &= ((1 as libc::c_int as BN_ULONG) << top_word_exponent)
                .wrapping_sub(1 as libc::c_int as BN_ULONG);
    }
    (*r).neg = (*a).neg;
    (*r).width = num_words as libc::c_int;
    bn_set_minimal_width(r);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn BN_nnmod_pow2(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut e: size_t,
) -> libc::c_int {
    if BN_mod_pow2(r, a, e) == 0 {
        return 0 as libc::c_int;
    }
    if BN_is_zero(r) != 0 || (*r).neg == 0 {
        return 1 as libc::c_int;
    }
    let mut num_words: size_t = (1 as libc::c_int as size_t)
        .wrapping_add(
            e.wrapping_sub(1 as libc::c_int as size_t) / 64 as libc::c_int as size_t,
        );
    if bn_wexpand(r, num_words) == 0 {
        return 0 as libc::c_int;
    }
    OPENSSL_memset(
        &mut *((*r).d).offset((*r).width as isize) as *mut BN_ULONG as *mut libc::c_void,
        0 as libc::c_int,
        num_words.wrapping_sub((*r).width as size_t) * 8 as libc::c_int as size_t,
    );
    (*r).neg = 0 as libc::c_int;
    (*r).width = num_words as libc::c_int;
    let mut i: libc::c_int = 0 as libc::c_int;
    while i < (*r).width {
        *((*r).d).offset(i as isize) = !*((*r).d).offset(i as isize);
        i += 1;
        i;
    }
    let mut top_word_exponent: size_t = e % 64 as libc::c_int as size_t;
    if top_word_exponent != 0 as libc::c_int as size_t {
        *((*r).d).offset(((*r).width - 1 as libc::c_int) as isize)
            &= ((1 as libc::c_int as BN_ULONG) << top_word_exponent)
                .wrapping_sub(1 as libc::c_int as BN_ULONG);
    }
    bn_set_minimal_width(r);
    return BN_add(r, r, BN_value_one());
}
