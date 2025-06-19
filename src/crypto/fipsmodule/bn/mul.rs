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
    fn abort() -> !;
    fn BN_copy(dest: *mut BIGNUM, src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_zero(bn: *mut BIGNUM);
    fn BN_CTX_start(ctx: *mut BN_CTX);
    fn BN_CTX_get(ctx: *mut BN_CTX) -> *mut BIGNUM;
    fn BN_CTX_end(ctx: *mut BN_CTX);
    fn BN_num_bits_word(l: BN_ULONG) -> libc::c_uint;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn bn_set_minimal_width(bn: *mut BIGNUM);
    fn bn_wexpand(bn: *mut BIGNUM, words: size_t) -> libc::c_int;
    fn bn_select_words(
        r: *mut BN_ULONG,
        mask: BN_ULONG,
        a: *const BN_ULONG,
        b: *const BN_ULONG,
        num: size_t,
    );
    fn bn_mul_add_words(
        rp: *mut BN_ULONG,
        ap: *const BN_ULONG,
        num: size_t,
        w: BN_ULONG,
    ) -> BN_ULONG;
    fn bn_mul_words(
        rp: *mut BN_ULONG,
        ap: *const BN_ULONG,
        num: size_t,
        w: BN_ULONG,
    ) -> BN_ULONG;
    fn bn_sqr_words(rp: *mut BN_ULONG, ap: *const BN_ULONG, num: size_t);
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
    fn bn_mul_comba4(r: *mut BN_ULONG, a: *const BN_ULONG, b: *const BN_ULONG);
    fn bn_mul_comba8(r: *mut BN_ULONG, a: *const BN_ULONG, b: *const BN_ULONG);
    fn bn_sqr_comba8(r: *mut BN_ULONG, a: *const BN_ULONG);
    fn bn_sqr_comba4(r: *mut BN_ULONG, a: *const BN_ULONG);
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
pub type crypto_word_t = uint64_t;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_281_error_is_crypto_word_t_is_too_small {
    #[bitfield(
        name = "static_assertion_at_line_281_error_is_crypto_word_t_is_too_small",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_281_error_is_crypto_word_t_is_too_small: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_395_error_is_crypto_word_t_is_too_small {
    #[bitfield(
        name = "static_assertion_at_line_395_error_is_crypto_word_t_is_too_small",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_395_error_is_crypto_word_t_is_too_small: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
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
unsafe extern "C" fn constant_time_select_w(
    mut mask: crypto_word_t,
    mut a: crypto_word_t,
    mut b: crypto_word_t,
) -> crypto_word_t {
    return value_barrier_w(mask) & a | value_barrier_w(!mask) & b;
}
#[inline]
unsafe extern "C" fn constant_time_declassify_int(mut v: libc::c_int) -> libc::c_int {
    return value_barrier_u32(v as uint32_t) as libc::c_int;
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
    'c_2916: {
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
unsafe extern "C" fn bn_abs_sub_words(
    mut r: *mut BN_ULONG,
    mut a: *const BN_ULONG,
    mut b: *const BN_ULONG,
    mut num: size_t,
    mut tmp: *mut BN_ULONG,
) {
    let mut borrow: BN_ULONG = bn_sub_words(tmp, a, b, num);
    bn_sub_words(r, b, a, num);
    bn_select_words(r, (0 as libc::c_int as BN_ULONG).wrapping_sub(borrow), r, tmp, num);
}
unsafe extern "C" fn bn_mul_normal(
    mut r: *mut BN_ULONG,
    mut a: *const BN_ULONG,
    mut na: size_t,
    mut b: *const BN_ULONG,
    mut nb: size_t,
) {
    if na < nb {
        let mut itmp: size_t = na;
        na = nb;
        nb = itmp;
        let mut ltmp: *const BN_ULONG = a;
        a = b;
        b = ltmp;
    }
    let mut rr: *mut BN_ULONG = &mut *r.offset(na as isize) as *mut BN_ULONG;
    if nb == 0 as libc::c_int as size_t {
        OPENSSL_memset(
            r as *mut libc::c_void,
            0 as libc::c_int,
            na.wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
        );
        return;
    }
    *rr
        .offset(
            0 as libc::c_int as isize,
        ) = bn_mul_words(r, a, na, *b.offset(0 as libc::c_int as isize));
    loop {
        nb = nb.wrapping_sub(1);
        if nb == 0 as libc::c_int as size_t {
            return;
        }
        *rr
            .offset(
                1 as libc::c_int as isize,
            ) = bn_mul_add_words(
            &mut *r.offset(1 as libc::c_int as isize),
            a,
            na,
            *b.offset(1 as libc::c_int as isize),
        );
        nb = nb.wrapping_sub(1);
        if nb == 0 as libc::c_int as size_t {
            return;
        }
        *rr
            .offset(
                2 as libc::c_int as isize,
            ) = bn_mul_add_words(
            &mut *r.offset(2 as libc::c_int as isize),
            a,
            na,
            *b.offset(2 as libc::c_int as isize),
        );
        nb = nb.wrapping_sub(1);
        if nb == 0 as libc::c_int as size_t {
            return;
        }
        *rr
            .offset(
                3 as libc::c_int as isize,
            ) = bn_mul_add_words(
            &mut *r.offset(3 as libc::c_int as isize),
            a,
            na,
            *b.offset(3 as libc::c_int as isize),
        );
        nb = nb.wrapping_sub(1);
        if nb == 0 as libc::c_int as size_t {
            return;
        }
        *rr
            .offset(
                4 as libc::c_int as isize,
            ) = bn_mul_add_words(
            &mut *r.offset(4 as libc::c_int as isize),
            a,
            na,
            *b.offset(4 as libc::c_int as isize),
        );
        rr = rr.offset(4 as libc::c_int as isize);
        r = r.offset(4 as libc::c_int as isize);
        b = b.offset(4 as libc::c_int as isize);
    };
}
unsafe extern "C" fn bn_sub_part_words(
    mut r: *mut BN_ULONG,
    mut a: *const BN_ULONG,
    mut b: *const BN_ULONG,
    mut cl: libc::c_int,
    mut dl: libc::c_int,
) -> BN_ULONG {
    if cl >= 0 as libc::c_int {} else {
        __assert_fail(
            b"cl >= 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                as *const u8 as *const libc::c_char,
            132 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 85],
                &[libc::c_char; 85],
            >(
                b"BN_ULONG bn_sub_part_words(BN_ULONG *, const BN_ULONG *, const BN_ULONG *, int, int)\0",
            ))
                .as_ptr(),
        );
    }
    'c_3035: {
        if cl >= 0 as libc::c_int {} else {
            __assert_fail(
                b"cl >= 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                    as *const u8 as *const libc::c_char,
                132 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 85],
                    &[libc::c_char; 85],
                >(
                    b"BN_ULONG bn_sub_part_words(BN_ULONG *, const BN_ULONG *, const BN_ULONG *, int, int)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut borrow: BN_ULONG = bn_sub_words(r, a, b, cl as size_t);
    if dl == 0 as libc::c_int {
        return borrow;
    }
    r = r.offset(cl as isize);
    a = a.offset(cl as isize);
    b = b.offset(cl as isize);
    if dl < 0 as libc::c_int {
        dl = -dl;
        let mut i: libc::c_int = 0 as libc::c_int;
        while i < dl {
            *r
                .offset(
                    i as isize,
                ) = CRYPTO_subc_u64(
                0 as libc::c_int as uint64_t,
                *b.offset(i as isize),
                borrow,
                &mut borrow,
            );
            i += 1;
            i;
        }
    } else {
        let mut i_0: libc::c_int = 0 as libc::c_int;
        while i_0 < dl {
            *r
                .offset(
                    i_0 as isize,
                ) = CRYPTO_subc_u64(
                *a.offset(i_0 as isize),
                0 as libc::c_int as uint64_t,
                borrow,
                &mut borrow,
            );
            i_0 += 1;
            i_0;
        }
    }
    return borrow;
}
unsafe extern "C" fn bn_abs_sub_part_words(
    mut r: *mut BN_ULONG,
    mut a: *const BN_ULONG,
    mut b: *const BN_ULONG,
    mut cl: libc::c_int,
    mut dl: libc::c_int,
    mut tmp: *mut BN_ULONG,
) -> BN_ULONG {
    let mut borrow: BN_ULONG = bn_sub_part_words(tmp, a, b, cl, dl);
    bn_sub_part_words(r, b, a, cl, -dl);
    let mut r_len: libc::c_int = cl + (if dl < 0 as libc::c_int { -dl } else { dl });
    borrow = (0 as libc::c_int as BN_ULONG).wrapping_sub(borrow);
    bn_select_words(r, borrow, r, tmp, r_len as size_t);
    return borrow;
}
#[no_mangle]
pub unsafe extern "C" fn bn_abs_sub_consttime(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut cl: libc::c_int = if (*a).width < (*b).width {
        (*a).width
    } else {
        (*b).width
    };
    let mut dl: libc::c_int = (*a).width - (*b).width;
    let mut r_len: libc::c_int = if (*a).width < (*b).width {
        (*b).width
    } else {
        (*a).width
    };
    BN_CTX_start(ctx);
    let mut tmp: *mut BIGNUM = BN_CTX_get(ctx);
    let mut ok: libc::c_int = (!tmp.is_null() && bn_wexpand(r, r_len as size_t) != 0
        && bn_wexpand(tmp, r_len as size_t) != 0) as libc::c_int;
    if ok != 0 {
        bn_abs_sub_part_words((*r).d, (*a).d, (*b).d, cl, dl, (*tmp).d);
        (*r).width = r_len;
    }
    BN_CTX_end(ctx);
    return ok;
}
unsafe extern "C" fn bn_mul_recursive(
    mut r: *mut BN_ULONG,
    mut a: *const BN_ULONG,
    mut b: *const BN_ULONG,
    mut n2: libc::c_int,
    mut dna: libc::c_int,
    mut dnb: libc::c_int,
    mut t: *mut BN_ULONG,
) {
    if n2 != 0 as libc::c_int && n2 & n2 - 1 as libc::c_int == 0 as libc::c_int {} else {
        __assert_fail(
            b"n2 != 0 && (n2 & (n2 - 1)) == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                as *const u8 as *const libc::c_char,
            210 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 97],
                &[libc::c_char; 97],
            >(
                b"void bn_mul_recursive(BN_ULONG *, const BN_ULONG *, const BN_ULONG *, int, int, int, BN_ULONG *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_3678: {
        if n2 != 0 as libc::c_int && n2 & n2 - 1 as libc::c_int == 0 as libc::c_int
        {} else {
            __assert_fail(
                b"n2 != 0 && (n2 & (n2 - 1)) == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                    as *const u8 as *const libc::c_char,
                210 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 97],
                    &[libc::c_char; 97],
                >(
                    b"void bn_mul_recursive(BN_ULONG *, const BN_ULONG *, const BN_ULONG *, int, int, int, BN_ULONG *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if -(16 as libc::c_int) / 2 as libc::c_int <= dna && dna <= 0 as libc::c_int
    {} else {
        __assert_fail(
            b"-BN_MUL_RECURSIVE_SIZE_NORMAL/2 <= dna && dna <= 0\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                as *const u8 as *const libc::c_char,
            212 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 97],
                &[libc::c_char; 97],
            >(
                b"void bn_mul_recursive(BN_ULONG *, const BN_ULONG *, const BN_ULONG *, int, int, int, BN_ULONG *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_3626: {
        if -(16 as libc::c_int) / 2 as libc::c_int <= dna && dna <= 0 as libc::c_int
        {} else {
            __assert_fail(
                b"-BN_MUL_RECURSIVE_SIZE_NORMAL/2 <= dna && dna <= 0\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                    as *const u8 as *const libc::c_char,
                212 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 97],
                    &[libc::c_char; 97],
                >(
                    b"void bn_mul_recursive(BN_ULONG *, const BN_ULONG *, const BN_ULONG *, int, int, int, BN_ULONG *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if -(16 as libc::c_int) / 2 as libc::c_int <= dnb && dnb <= 0 as libc::c_int
    {} else {
        __assert_fail(
            b"-BN_MUL_RECURSIVE_SIZE_NORMAL/2 <= dnb && dnb <= 0\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                as *const u8 as *const libc::c_char,
            213 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 97],
                &[libc::c_char; 97],
            >(
                b"void bn_mul_recursive(BN_ULONG *, const BN_ULONG *, const BN_ULONG *, int, int, int, BN_ULONG *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_3573: {
        if -(16 as libc::c_int) / 2 as libc::c_int <= dnb && dnb <= 0 as libc::c_int
        {} else {
            __assert_fail(
                b"-BN_MUL_RECURSIVE_SIZE_NORMAL/2 <= dnb && dnb <= 0\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                    as *const u8 as *const libc::c_char,
                213 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 97],
                    &[libc::c_char; 97],
                >(
                    b"void bn_mul_recursive(BN_ULONG *, const BN_ULONG *, const BN_ULONG *, int, int, int, BN_ULONG *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if n2 == 8 as libc::c_int && dna == 0 as libc::c_int && dnb == 0 as libc::c_int {
        bn_mul_comba8(r, a, b);
        return;
    }
    if n2 < 16 as libc::c_int {
        bn_mul_normal(r, a, (n2 + dna) as size_t, b, (n2 + dnb) as size_t);
        if dna + dnb < 0 as libc::c_int {
            OPENSSL_memset(
                &mut *r.offset((2 as libc::c_int * n2 + dna + dnb) as isize)
                    as *mut BN_ULONG as *mut libc::c_void,
                0 as libc::c_int,
                (::core::mem::size_of::<BN_ULONG>() as libc::c_ulong)
                    .wrapping_mul(-(dna + dnb) as libc::c_ulong),
            );
        }
        return;
    }
    let mut n: libc::c_int = n2 / 2 as libc::c_int;
    let mut tna: libc::c_int = n + dna;
    let mut tnb: libc::c_int = n + dnb;
    let mut neg: BN_ULONG = bn_abs_sub_part_words(
        t,
        a,
        &*a.offset(n as isize),
        tna,
        n - tna,
        &mut *t.offset(n2 as isize),
    );
    neg
        ^= bn_abs_sub_part_words(
            &mut *t.offset(n as isize),
            &*b.offset(n as isize),
            b,
            tnb,
            tnb - n,
            &mut *t.offset(n2 as isize),
        );
    if n == 4 as libc::c_int && dna == 0 as libc::c_int && dnb == 0 as libc::c_int {
        bn_mul_comba4(
            &mut *t.offset(n2 as isize),
            t as *const BN_ULONG,
            &mut *t.offset(n as isize) as *mut BN_ULONG as *const BN_ULONG,
        );
        bn_mul_comba4(r, a, b);
        bn_mul_comba4(
            &mut *r.offset(n2 as isize),
            &*a.offset(n as isize),
            &*b.offset(n as isize),
        );
    } else if n == 8 as libc::c_int && dna == 0 as libc::c_int && dnb == 0 as libc::c_int
    {
        bn_mul_comba8(
            &mut *t.offset(n2 as isize),
            t as *const BN_ULONG,
            &mut *t.offset(n as isize) as *mut BN_ULONG as *const BN_ULONG,
        );
        bn_mul_comba8(r, a, b);
        bn_mul_comba8(
            &mut *r.offset(n2 as isize),
            &*a.offset(n as isize),
            &*b.offset(n as isize),
        );
    } else {
        let mut p: *mut BN_ULONG = &mut *t.offset((n2 * 2 as libc::c_int) as isize)
            as *mut BN_ULONG;
        bn_mul_recursive(
            &mut *t.offset(n2 as isize),
            t,
            &mut *t.offset(n as isize),
            n,
            0 as libc::c_int,
            0 as libc::c_int,
            p,
        );
        bn_mul_recursive(r, a, b, n, 0 as libc::c_int, 0 as libc::c_int, p);
        bn_mul_recursive(
            &mut *r.offset(n2 as isize),
            &*a.offset(n as isize),
            &*b.offset(n as isize),
            n,
            dna,
            dnb,
            p,
        );
    }
    let mut c: BN_ULONG = bn_add_words(t, r, &mut *r.offset(n2 as isize), n2 as size_t);
    let mut c_neg: BN_ULONG = c
        .wrapping_sub(
            bn_sub_words(
                &mut *t.offset((n2 * 2 as libc::c_int) as isize),
                t,
                &mut *t.offset(n2 as isize),
                n2 as size_t,
            ),
        );
    let mut c_pos: BN_ULONG = c
        .wrapping_add(
            bn_add_words(
                &mut *t.offset(n2 as isize),
                t,
                &mut *t.offset(n2 as isize),
                n2 as size_t,
            ),
        );
    bn_select_words(
        &mut *t.offset(n2 as isize),
        neg,
        &mut *t.offset((n2 * 2 as libc::c_int) as isize),
        &mut *t.offset(n2 as isize),
        n2 as size_t,
    );
    c = constant_time_select_w(neg, c_neg, c_pos);
    c = c
        .wrapping_add(
            bn_add_words(
                &mut *r.offset(n as isize),
                &mut *r.offset(n as isize),
                &mut *t.offset(n2 as isize),
                n2 as size_t,
            ),
        );
    let mut i: libc::c_int = n + n2;
    while i < n2 + n2 {
        let mut old: BN_ULONG = *r.offset(i as isize);
        *r.offset(i as isize) = old.wrapping_add(c);
        c = (*r.offset(i as isize) < old) as libc::c_int as BN_ULONG;
        i += 1;
        i;
    }
    if constant_time_declassify_int((c == 0 as libc::c_int as BN_ULONG) as libc::c_int)
        != 0
    {} else {
        __assert_fail(
            b"constant_time_declassify_int(c == 0)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                as *const u8 as *const libc::c_char,
            296 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 97],
                &[libc::c_char; 97],
            >(
                b"void bn_mul_recursive(BN_ULONG *, const BN_ULONG *, const BN_ULONG *, int, int, int, BN_ULONG *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2477: {
        if constant_time_declassify_int(
            (c == 0 as libc::c_int as BN_ULONG) as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(c == 0)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                    as *const u8 as *const libc::c_char,
                296 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 97],
                    &[libc::c_char; 97],
                >(
                    b"void bn_mul_recursive(BN_ULONG *, const BN_ULONG *, const BN_ULONG *, int, int, int, BN_ULONG *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn bn_mul_part_recursive(
    mut r: *mut BN_ULONG,
    mut a: *const BN_ULONG,
    mut b: *const BN_ULONG,
    mut n: libc::c_int,
    mut tna: libc::c_int,
    mut tnb: libc::c_int,
    mut t: *mut BN_ULONG,
) {
    if n != 0 as libc::c_int && n & n - 1 as libc::c_int == 0 as libc::c_int {} else {
        __assert_fail(
            b"n != 0 && (n & (n - 1)) == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                as *const u8 as *const libc::c_char,
            311 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 102],
                &[libc::c_char; 102],
            >(
                b"void bn_mul_part_recursive(BN_ULONG *, const BN_ULONG *, const BN_ULONG *, int, int, int, BN_ULONG *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_4659: {
        if n != 0 as libc::c_int && n & n - 1 as libc::c_int == 0 as libc::c_int
        {} else {
            __assert_fail(
                b"n != 0 && (n & (n - 1)) == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                    as *const u8 as *const libc::c_char,
                311 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 102],
                    &[libc::c_char; 102],
                >(
                    b"void bn_mul_part_recursive(BN_ULONG *, const BN_ULONG *, const BN_ULONG *, int, int, int, BN_ULONG *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if 0 as libc::c_int <= tna && tna < n {} else {
        __assert_fail(
            b"0 <= tna && tna < n\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                as *const u8 as *const libc::c_char,
            313 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 102],
                &[libc::c_char; 102],
            >(
                b"void bn_mul_part_recursive(BN_ULONG *, const BN_ULONG *, const BN_ULONG *, int, int, int, BN_ULONG *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_4611: {
        if 0 as libc::c_int <= tna && tna < n {} else {
            __assert_fail(
                b"0 <= tna && tna < n\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                    as *const u8 as *const libc::c_char,
                313 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 102],
                    &[libc::c_char; 102],
                >(
                    b"void bn_mul_part_recursive(BN_ULONG *, const BN_ULONG *, const BN_ULONG *, int, int, int, BN_ULONG *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if 0 as libc::c_int <= tnb && tnb < n {} else {
        __assert_fail(
            b"0 <= tnb && tnb < n\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                as *const u8 as *const libc::c_char,
            314 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 102],
                &[libc::c_char; 102],
            >(
                b"void bn_mul_part_recursive(BN_ULONG *, const BN_ULONG *, const BN_ULONG *, int, int, int, BN_ULONG *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_4562: {
        if 0 as libc::c_int <= tnb && tnb < n {} else {
            __assert_fail(
                b"0 <= tnb && tnb < n\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                    as *const u8 as *const libc::c_char,
                314 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 102],
                    &[libc::c_char; 102],
                >(
                    b"void bn_mul_part_recursive(BN_ULONG *, const BN_ULONG *, const BN_ULONG *, int, int, int, BN_ULONG *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if -(1 as libc::c_int) <= tna - tnb && tna - tnb <= 1 as libc::c_int {} else {
        __assert_fail(
            b"-1 <= tna - tnb && tna - tnb <= 1\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                as *const u8 as *const libc::c_char,
            315 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 102],
                &[libc::c_char; 102],
            >(
                b"void bn_mul_part_recursive(BN_ULONG *, const BN_ULONG *, const BN_ULONG *, int, int, int, BN_ULONG *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_4501: {
        if -(1 as libc::c_int) <= tna - tnb && tna - tnb <= 1 as libc::c_int {} else {
            __assert_fail(
                b"-1 <= tna - tnb && tna - tnb <= 1\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                    as *const u8 as *const libc::c_char,
                315 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 102],
                    &[libc::c_char; 102],
                >(
                    b"void bn_mul_part_recursive(BN_ULONG *, const BN_ULONG *, const BN_ULONG *, int, int, int, BN_ULONG *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut n2: libc::c_int = n * 2 as libc::c_int;
    if n < 8 as libc::c_int {
        bn_mul_normal(r, a, (n + tna) as size_t, b, (n + tnb) as size_t);
        OPENSSL_memset(
            r.offset(n2 as isize).offset(tna as isize).offset(tnb as isize)
                as *mut libc::c_void,
            0 as libc::c_int,
            (n2 - tna - tnb) as size_t,
        );
        return;
    }
    let mut neg: BN_ULONG = bn_abs_sub_part_words(
        t,
        a,
        &*a.offset(n as isize),
        tna,
        n - tna,
        &mut *t.offset(n2 as isize),
    );
    neg
        ^= bn_abs_sub_part_words(
            &mut *t.offset(n as isize),
            &*b.offset(n as isize),
            b,
            tnb,
            tnb - n,
            &mut *t.offset(n2 as isize),
        );
    if n == 8 as libc::c_int {
        bn_mul_comba8(
            &mut *t.offset(n2 as isize),
            t as *const BN_ULONG,
            &mut *t.offset(n as isize) as *mut BN_ULONG as *const BN_ULONG,
        );
        bn_mul_comba8(r, a, b);
        bn_mul_normal(
            &mut *r.offset(n2 as isize),
            &*a.offset(n as isize),
            tna as size_t,
            &*b.offset(n as isize),
            tnb as size_t,
        );
        OPENSSL_memset(
            &mut *r.offset((n2 + tna + tnb) as isize) as *mut BN_ULONG
                as *mut libc::c_void,
            0 as libc::c_int,
            (::core::mem::size_of::<BN_ULONG>() as libc::c_ulong)
                .wrapping_mul((n2 - tna - tnb) as libc::c_ulong),
        );
    } else {
        let mut p: *mut BN_ULONG = &mut *t.offset((n2 * 2 as libc::c_int) as isize)
            as *mut BN_ULONG;
        bn_mul_recursive(
            &mut *t.offset(n2 as isize),
            t,
            &mut *t.offset(n as isize),
            n,
            0 as libc::c_int,
            0 as libc::c_int,
            p,
        );
        bn_mul_recursive(r, a, b, n, 0 as libc::c_int, 0 as libc::c_int, p);
        OPENSSL_memset(
            &mut *r.offset(n2 as isize) as *mut BN_ULONG as *mut libc::c_void,
            0 as libc::c_int,
            (::core::mem::size_of::<BN_ULONG>() as libc::c_ulong)
                .wrapping_mul(n2 as libc::c_ulong),
        );
        if tna < 16 as libc::c_int && tnb < 16 as libc::c_int {
            bn_mul_normal(
                &mut *r.offset(n2 as isize),
                &*a.offset(n as isize),
                tna as size_t,
                &*b.offset(n as isize),
                tnb as size_t,
            );
        } else {
            let mut i: libc::c_int = n;
            loop {
                i /= 2 as libc::c_int;
                if i < tna || i < tnb {
                    bn_mul_part_recursive(
                        &mut *r.offset(n2 as isize),
                        &*a.offset(n as isize),
                        &*b.offset(n as isize),
                        i,
                        tna - i,
                        tnb - i,
                        p,
                    );
                    break;
                } else {
                    if !(i == tna || i == tnb) {
                        continue;
                    }
                    bn_mul_recursive(
                        &mut *r.offset(n2 as isize),
                        &*a.offset(n as isize),
                        &*b.offset(n as isize),
                        i,
                        tna - i,
                        tnb - i,
                        p,
                    );
                    break;
                }
            }
        }
    }
    let mut c: BN_ULONG = bn_add_words(t, r, &mut *r.offset(n2 as isize), n2 as size_t);
    let mut c_neg: BN_ULONG = c
        .wrapping_sub(
            bn_sub_words(
                &mut *t.offset((n2 * 2 as libc::c_int) as isize),
                t,
                &mut *t.offset(n2 as isize),
                n2 as size_t,
            ),
        );
    let mut c_pos: BN_ULONG = c
        .wrapping_add(
            bn_add_words(
                &mut *t.offset(n2 as isize),
                t,
                &mut *t.offset(n2 as isize),
                n2 as size_t,
            ),
        );
    bn_select_words(
        &mut *t.offset(n2 as isize),
        neg,
        &mut *t.offset((n2 * 2 as libc::c_int) as isize),
        &mut *t.offset(n2 as isize),
        n2 as size_t,
    );
    c = constant_time_select_w(neg, c_neg, c_pos);
    c = c
        .wrapping_add(
            bn_add_words(
                &mut *r.offset(n as isize),
                &mut *r.offset(n as isize),
                &mut *t.offset(n2 as isize),
                n2 as size_t,
            ),
        );
    let mut i_0: libc::c_int = n + n2;
    while i_0 < n2 + n2 {
        let mut old: BN_ULONG = *r.offset(i_0 as isize);
        *r.offset(i_0 as isize) = old.wrapping_add(c);
        c = (*r.offset(i_0 as isize) < old) as libc::c_int as BN_ULONG;
        i_0 += 1;
        i_0;
    }
    if constant_time_declassify_int((c == 0 as libc::c_int as BN_ULONG) as libc::c_int)
        != 0
    {} else {
        __assert_fail(
            b"constant_time_declassify_int(c == 0)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                as *const u8 as *const libc::c_char,
            410 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 102],
                &[libc::c_char; 102],
            >(
                b"void bn_mul_part_recursive(BN_ULONG *, const BN_ULONG *, const BN_ULONG *, int, int, int, BN_ULONG *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_3827: {
        if constant_time_declassify_int(
            (c == 0 as libc::c_int as BN_ULONG) as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(c == 0)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                    as *const u8 as *const libc::c_char,
                410 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 102],
                    &[libc::c_char; 102],
                >(
                    b"void bn_mul_part_recursive(BN_ULONG *, const BN_ULONG *, const BN_ULONG *, int, int, int, BN_ULONG *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn bn_mul_impl(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut top: libc::c_int = 0;
    static mut kMulNormalSize: libc::c_int = 16 as libc::c_int;
    let mut i: libc::c_int = 0;
    let mut current_block: u64;
    let mut al: libc::c_int = (*a).width;
    let mut bl: libc::c_int = (*b).width;
    if al == 0 as libc::c_int || bl == 0 as libc::c_int {
        BN_zero(r);
        return 1 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut rr: *mut BIGNUM = 0 as *mut BIGNUM;
    BN_CTX_start(ctx);
    if r == a as *mut BIGNUM || r == b as *mut BIGNUM {
        rr = BN_CTX_get(ctx);
        if rr.is_null() {
            current_block = 18365450753014027423;
        } else {
            current_block = 1394248824506584008;
        }
    } else {
        rr = r;
        current_block = 1394248824506584008;
    }
    match current_block {
        1394248824506584008 => {
            (*rr).neg = (*a).neg ^ (*b).neg;
            i = al - bl;
            if i == 0 as libc::c_int {
                if al == 8 as libc::c_int {
                    if bn_wexpand(rr, 16 as libc::c_int as size_t) == 0 {
                        current_block = 18365450753014027423;
                    } else {
                        (*rr).width = 16 as libc::c_int;
                        bn_mul_comba8(
                            (*rr).d,
                            (*a).d as *const BN_ULONG,
                            (*b).d as *const BN_ULONG,
                        );
                        current_block = 8940334344464777341;
                    }
                } else {
                    current_block = 1054647088692577877;
                }
            } else {
                current_block = 1054647088692577877;
            }
            match current_block {
                18365450753014027423 => {}
                _ => {
                    match current_block {
                        1054647088692577877 => {
                            top = al + bl;
                            if al >= kMulNormalSize && bl >= kMulNormalSize {
                                if -(1 as libc::c_int) <= i && i <= 1 as libc::c_int {
                                    let mut j: libc::c_int = 0;
                                    if i >= 0 as libc::c_int {
                                        j = BN_num_bits_word(al as BN_ULONG) as libc::c_int;
                                    } else {
                                        j = BN_num_bits_word(bl as BN_ULONG) as libc::c_int;
                                    }
                                    j = (1 as libc::c_int) << j - 1 as libc::c_int;
                                    if j <= al || j <= bl {} else {
                                        __assert_fail(
                                            b"j <= al || j <= bl\0" as *const u8 as *const libc::c_char,
                                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                                                as *const u8 as *const libc::c_char,
                                            462 as libc::c_int as libc::c_uint,
                                            (*::core::mem::transmute::<
                                                &[u8; 68],
                                                &[libc::c_char; 68],
                                            >(
                                                b"int bn_mul_impl(BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *)\0",
                                            ))
                                                .as_ptr(),
                                        );
                                    }
                                    'c_4817: {
                                        if j <= al || j <= bl {} else {
                                            __assert_fail(
                                                b"j <= al || j <= bl\0" as *const u8 as *const libc::c_char,
                                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                                                    as *const u8 as *const libc::c_char,
                                                462 as libc::c_int as libc::c_uint,
                                                (*::core::mem::transmute::<
                                                    &[u8; 68],
                                                    &[libc::c_char; 68],
                                                >(
                                                    b"int bn_mul_impl(BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *)\0",
                                                ))
                                                    .as_ptr(),
                                            );
                                        }
                                    };
                                    let mut t: *mut BIGNUM = BN_CTX_get(ctx);
                                    if t.is_null() {
                                        current_block = 18365450753014027423;
                                    } else {
                                        if al > j || bl > j {
                                            if al >= j && bl >= j {} else {
                                                __assert_fail(
                                                    b"al >= j && bl >= j\0" as *const u8 as *const libc::c_char,
                                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                                                        as *const u8 as *const libc::c_char,
                                                    474 as libc::c_int as libc::c_uint,
                                                    (*::core::mem::transmute::<
                                                        &[u8; 68],
                                                        &[libc::c_char; 68],
                                                    >(
                                                        b"int bn_mul_impl(BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *)\0",
                                                    ))
                                                        .as_ptr(),
                                                );
                                            }
                                            'c_4745: {
                                                if al >= j && bl >= j {} else {
                                                    __assert_fail(
                                                        b"al >= j && bl >= j\0" as *const u8 as *const libc::c_char,
                                                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                                                            as *const u8 as *const libc::c_char,
                                                        474 as libc::c_int as libc::c_uint,
                                                        (*::core::mem::transmute::<
                                                            &[u8; 68],
                                                            &[libc::c_char; 68],
                                                        >(
                                                            b"int bn_mul_impl(BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *)\0",
                                                        ))
                                                            .as_ptr(),
                                                    );
                                                }
                                            };
                                            if bn_wexpand(t, (j * 8 as libc::c_int) as size_t) == 0
                                                || bn_wexpand(rr, (j * 4 as libc::c_int) as size_t) == 0
                                            {
                                                current_block = 18365450753014027423;
                                            } else {
                                                bn_mul_part_recursive(
                                                    (*rr).d,
                                                    (*a).d,
                                                    (*b).d,
                                                    j,
                                                    al - j,
                                                    bl - j,
                                                    (*t).d,
                                                );
                                                current_block = 652864300344834934;
                                            }
                                        } else if bn_wexpand(t, (j * 4 as libc::c_int) as size_t)
                                            == 0
                                            || bn_wexpand(rr, (j * 2 as libc::c_int) as size_t) == 0
                                        {
                                            current_block = 18365450753014027423;
                                        } else {
                                            bn_mul_recursive(
                                                (*rr).d,
                                                (*a).d,
                                                (*b).d,
                                                j,
                                                al - j,
                                                bl - j,
                                                (*t).d,
                                            );
                                            current_block = 652864300344834934;
                                        }
                                        match current_block {
                                            18365450753014027423 => {}
                                            _ => {
                                                (*rr).width = top;
                                                current_block = 8940334344464777341;
                                            }
                                        }
                                    }
                                } else {
                                    current_block = 9853141518545631134;
                                }
                            } else {
                                current_block = 9853141518545631134;
                            }
                            match current_block {
                                8940334344464777341 => {}
                                18365450753014027423 => {}
                                _ => {
                                    if bn_wexpand(rr, top as size_t) == 0 {
                                        current_block = 18365450753014027423;
                                    } else {
                                        (*rr).width = top;
                                        bn_mul_normal(
                                            (*rr).d,
                                            (*a).d,
                                            al as size_t,
                                            (*b).d,
                                            bl as size_t,
                                        );
                                        current_block = 8940334344464777341;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                    match current_block {
                        18365450753014027423 => {}
                        _ => {
                            if !(r != rr && (BN_copy(r, rr)).is_null()) {
                                ret = 1 as libc::c_int;
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    BN_CTX_end(ctx);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn BN_mul(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if bn_mul_impl(r, a, b, ctx) == 0 {
        return 0 as libc::c_int;
    }
    bn_set_minimal_width(r);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn bn_mul_consttime(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if (*a).neg != 0 || (*b).neg != 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                as *const u8 as *const libc::c_char,
            525 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return bn_mul_impl(r, a, b, ctx);
}
#[no_mangle]
pub unsafe extern "C" fn bn_mul_small(
    mut r: *mut BN_ULONG,
    mut num_r: size_t,
    mut a: *const BN_ULONG,
    mut num_a: size_t,
    mut b: *const BN_ULONG,
    mut num_b: size_t,
) {
    if num_r != num_a.wrapping_add(num_b) {
        abort();
    }
    if num_a == 8 as libc::c_int as size_t && num_b == 8 as libc::c_int as size_t {
        bn_mul_comba8(r, a, b);
    } else {
        bn_mul_normal(r, a, num_a, b, num_b);
    };
}
unsafe extern "C" fn bn_sqr_normal(
    mut r: *mut BN_ULONG,
    mut a: *const BN_ULONG,
    mut n: size_t,
    mut tmp: *mut BN_ULONG,
) {
    if n == 0 as libc::c_int as size_t {
        return;
    }
    let mut max: size_t = n * 2 as libc::c_int as size_t;
    let mut ap: *const BN_ULONG = a;
    let mut rp: *mut BN_ULONG = r;
    let ref mut fresh0 = *rp
        .offset(max.wrapping_sub(1 as libc::c_int as size_t) as isize);
    *fresh0 = 0 as libc::c_int as BN_ULONG;
    *rp.offset(0 as libc::c_int as isize) = *fresh0;
    rp = rp.offset(1);
    rp;
    if n > 1 as libc::c_int as size_t {
        ap = ap.offset(1);
        ap;
        *rp
            .offset(
                n.wrapping_sub(1 as libc::c_int as size_t) as isize,
            ) = bn_mul_words(
            rp,
            ap,
            n.wrapping_sub(1 as libc::c_int as size_t),
            *ap.offset(-(1 as libc::c_int) as isize),
        );
        rp = rp.offset(2 as libc::c_int as isize);
    }
    if n > 2 as libc::c_int as size_t {
        let mut i: size_t = n.wrapping_sub(2 as libc::c_int as size_t);
        while i > 0 as libc::c_int as size_t {
            ap = ap.offset(1);
            ap;
            *rp
                .offset(
                    i as isize,
                ) = bn_mul_add_words(
                rp,
                ap,
                i,
                *ap.offset(-(1 as libc::c_int) as isize),
            );
            rp = rp.offset(2 as libc::c_int as isize);
            i = i.wrapping_sub(1);
            i;
        }
    }
    bn_add_words(r, r, r, max);
    bn_sqr_words(tmp, a, n);
    bn_add_words(r, r, tmp, max);
}
unsafe extern "C" fn bn_sqr_recursive(
    mut r: *mut BN_ULONG,
    mut a: *const BN_ULONG,
    mut n2: size_t,
    mut t: *mut BN_ULONG,
) {
    if n2 != 0 as libc::c_int as size_t
        && n2 & n2.wrapping_sub(1 as libc::c_int as size_t) == 0 as libc::c_int as size_t
    {} else {
        __assert_fail(
            b"n2 != 0 && (n2 & (n2 - 1)) == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                as *const u8 as *const libc::c_char,
            590 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 72],
                &[libc::c_char; 72],
            >(
                b"void bn_sqr_recursive(BN_ULONG *, const BN_ULONG *, size_t, BN_ULONG *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_5893: {
        if n2 != 0 as libc::c_int as size_t
            && n2 & n2.wrapping_sub(1 as libc::c_int as size_t)
                == 0 as libc::c_int as size_t
        {} else {
            __assert_fail(
                b"n2 != 0 && (n2 & (n2 - 1)) == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                    as *const u8 as *const libc::c_char,
                590 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 72],
                    &[libc::c_char; 72],
                >(
                    b"void bn_sqr_recursive(BN_ULONG *, const BN_ULONG *, size_t, BN_ULONG *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if n2 == 4 as libc::c_int as size_t {
        bn_sqr_comba4(r, a);
        return;
    }
    if n2 == 8 as libc::c_int as size_t {
        bn_sqr_comba8(r, a);
        return;
    }
    if n2 < 16 as libc::c_int as size_t {
        bn_sqr_normal(r, a, n2, t);
        return;
    }
    let mut n: size_t = n2 / 2 as libc::c_int as size_t;
    let mut t_recursive: *mut BN_ULONG = &mut *t
        .offset((n2 * 2 as libc::c_int as size_t) as isize) as *mut BN_ULONG;
    bn_abs_sub_words(t, a, &*a.offset(n as isize), n, &mut *t.offset(n as isize));
    bn_sqr_recursive(&mut *t.offset(n2 as isize), t, n, t_recursive);
    bn_sqr_recursive(r, a, n, t_recursive);
    bn_sqr_recursive(
        &mut *r.offset(n2 as isize),
        &*a.offset(n as isize),
        n,
        t_recursive,
    );
    let mut c: BN_ULONG = bn_add_words(t, r, &mut *r.offset(n2 as isize), n2);
    c = c
        .wrapping_sub(
            bn_sub_words(&mut *t.offset(n2 as isize), t, &mut *t.offset(n2 as isize), n2),
        );
    c = c
        .wrapping_add(
            bn_add_words(
                &mut *r.offset(n as isize),
                &mut *r.offset(n as isize),
                &mut *t.offset(n2 as isize),
                n2,
            ),
        );
    let mut i: size_t = n.wrapping_add(n2);
    while i < n2.wrapping_add(n2) {
        let mut old: BN_ULONG = *r.offset(i as isize);
        *r.offset(i as isize) = old.wrapping_add(c);
        c = (*r.offset(i as isize) < old) as libc::c_int as BN_ULONG;
        i = i.wrapping_add(1);
        i;
    }
    if c == 0 as libc::c_int as BN_ULONG {} else {
        __assert_fail(
            b"c == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                as *const u8 as *const libc::c_char,
            641 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 72],
                &[libc::c_char; 72],
            >(
                b"void bn_sqr_recursive(BN_ULONG *, const BN_ULONG *, size_t, BN_ULONG *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_5539: {
        if c == 0 as libc::c_int as BN_ULONG {} else {
            __assert_fail(
                b"c == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/mul.c\0"
                    as *const u8 as *const libc::c_char,
                641 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 72],
                    &[libc::c_char; 72],
                >(
                    b"void bn_sqr_recursive(BN_ULONG *, const BN_ULONG *, size_t, BN_ULONG *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn BN_mul_word(
    mut bn: *mut BIGNUM,
    mut w: BN_ULONG,
) -> libc::c_int {
    if (*bn).width == 0 {
        return 1 as libc::c_int;
    }
    if w == 0 as libc::c_int as BN_ULONG {
        BN_zero(bn);
        return 1 as libc::c_int;
    }
    let mut ll: BN_ULONG = bn_mul_words((*bn).d, (*bn).d, (*bn).width as size_t, w);
    if ll != 0 {
        if bn_wexpand(bn, ((*bn).width + 1 as libc::c_int) as size_t) == 0 {
            return 0 as libc::c_int;
        }
        let fresh1 = (*bn).width;
        (*bn).width = (*bn).width + 1;
        *((*bn).d).offset(fresh1 as isize) = ll;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn bn_sqr_consttime(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut max: libc::c_int = 0;
    let mut current_block: u64;
    let mut al: libc::c_int = (*a).width;
    if al <= 0 as libc::c_int {
        (*r).width = 0 as libc::c_int;
        (*r).neg = 0 as libc::c_int;
        return 1 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    BN_CTX_start(ctx);
    let mut rr: *mut BIGNUM = if a != r as *const BIGNUM { r } else { BN_CTX_get(ctx) };
    let mut tmp: *mut BIGNUM = BN_CTX_get(ctx);
    if !(rr.is_null() || tmp.is_null()) {
        max = 2 as libc::c_int * al;
        if !(bn_wexpand(rr, max as size_t) == 0) {
            if al == 4 as libc::c_int {
                bn_sqr_comba4((*rr).d, (*a).d as *const BN_ULONG);
                current_block = 11307063007268554308;
            } else if al == 8 as libc::c_int {
                bn_sqr_comba8((*rr).d, (*a).d as *const BN_ULONG);
                current_block = 11307063007268554308;
            } else if al < 16 as libc::c_int {
                let mut t: [BN_ULONG; 32] = [0; 32];
                bn_sqr_normal((*rr).d, (*a).d, al as size_t, t.as_mut_ptr());
                current_block = 11307063007268554308;
            } else if al != 0 as libc::c_int
                && al & al - 1 as libc::c_int == 0 as libc::c_int
            {
                if bn_wexpand(tmp, (al * 4 as libc::c_int) as size_t) == 0 {
                    current_block = 7970598267006209814;
                } else {
                    bn_sqr_recursive((*rr).d, (*a).d, al as size_t, (*tmp).d);
                    current_block = 11307063007268554308;
                }
            } else if bn_wexpand(tmp, max as size_t) == 0 {
                current_block = 7970598267006209814;
            } else {
                bn_sqr_normal((*rr).d, (*a).d, al as size_t, (*tmp).d);
                current_block = 11307063007268554308;
            }
            match current_block {
                7970598267006209814 => {}
                _ => {
                    (*rr).neg = 0 as libc::c_int;
                    (*rr).width = max;
                    if !(rr != r && (BN_copy(r, rr)).is_null()) {
                        ret = 1 as libc::c_int;
                    }
                }
            }
        }
    }
    BN_CTX_end(ctx);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn BN_sqr(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if bn_sqr_consttime(r, a, ctx) == 0 {
        return 0 as libc::c_int;
    }
    bn_set_minimal_width(r);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn bn_sqr_small(
    mut r: *mut BN_ULONG,
    mut num_r: size_t,
    mut a: *const BN_ULONG,
    mut num_a: size_t,
) {
    if num_r != 2 as libc::c_int as size_t * num_a || num_a > 9 as libc::c_int as size_t
    {
        abort();
    }
    if num_a == 4 as libc::c_int as size_t {
        bn_sqr_comba4(r, a);
    } else if num_a == 8 as libc::c_int as size_t {
        bn_sqr_comba8(r, a);
    } else {
        let mut tmp: [BN_ULONG; 18] = [0; 18];
        bn_sqr_normal(r, a, num_a, tmp.as_mut_ptr());
        OPENSSL_cleanse(
            tmp.as_mut_ptr() as *mut libc::c_void,
            (2 as libc::c_int as size_t * num_a)
                .wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
        );
    };
}
