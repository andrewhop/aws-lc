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
    fn BN_num_bits(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_zero(bn: *mut BIGNUM);
    fn BN_is_negative(bn: *const BIGNUM) -> libc::c_int;
    fn BN_is_zero(bn: *const BIGNUM) -> libc::c_int;
    fn BN_is_odd(bn: *const BIGNUM) -> libc::c_int;
    fn BN_set_bit(a: *mut BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_mod_mul_montgomery(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        b: *const BIGNUM,
        mont: *const BN_MONT_CTX,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn bn_minimal_width(bn: *const BIGNUM) -> libc::c_int;
    fn bn_resize_words(bn: *mut BIGNUM, words: size_t) -> libc::c_int;
    fn bn_mod_lshift_consttime(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        n: libc::c_int,
        m: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bn_mont_ctx_st {
    pub RR: BIGNUM,
    pub N: BIGNUM,
    pub n0: [BN_ULONG; 2],
}
pub type BN_MONT_CTX = bn_mont_ctx_st;
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_mont_n0(mut n: *const BIGNUM) -> uint64_t {
    if BN_is_zero(n) == 0 {} else {
        __assert_fail(
            b"!BN_is_zero(n)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                as *const u8 as *const libc::c_char,
            37 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 36],
                &[libc::c_char; 36],
            >(b"uint64_t bn_mont_n0(const BIGNUM *)\0"))
                .as_ptr(),
        );
    }
    'c_7756: {
        if BN_is_zero(n) == 0 {} else {
            __assert_fail(
                b"!BN_is_zero(n)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                    as *const u8 as *const libc::c_char,
                37 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 36],
                    &[libc::c_char; 36],
                >(b"uint64_t bn_mont_n0(const BIGNUM *)\0"))
                    .as_ptr(),
            );
        }
    };
    if BN_is_negative(n) == 0 {} else {
        __assert_fail(
            b"!BN_is_negative(n)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                as *const u8 as *const libc::c_char,
            38 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 36],
                &[libc::c_char; 36],
            >(b"uint64_t bn_mont_n0(const BIGNUM *)\0"))
                .as_ptr(),
        );
    }
    'c_7715: {
        if BN_is_negative(n) == 0 {} else {
            __assert_fail(
                b"!BN_is_negative(n)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                    as *const u8 as *const libc::c_char,
                38 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 36],
                    &[libc::c_char; 36],
                >(b"uint64_t bn_mont_n0(const BIGNUM *)\0"))
                    .as_ptr(),
            );
        }
    };
    if BN_is_odd(n) != 0 {} else {
        __assert_fail(
            b"BN_is_odd(n)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                as *const u8 as *const libc::c_char,
            39 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 36],
                &[libc::c_char; 36],
            >(b"uint64_t bn_mont_n0(const BIGNUM *)\0"))
                .as_ptr(),
        );
    }
    'c_7675: {
        if BN_is_odd(n) != 0 {} else {
            __assert_fail(
                b"BN_is_odd(n)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                    as *const u8 as *const libc::c_char,
                39 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 36],
                    &[libc::c_char; 36],
                >(b"uint64_t bn_mont_n0(const BIGNUM *)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut n_mod_r: uint64_t = *((*n).d).offset(0 as libc::c_int as isize);
    return bn_neg_inv_mod_r_u64(n_mod_r);
}
unsafe extern "C" fn bn_neg_inv_mod_r_u64(mut n: uint64_t) -> uint64_t {
    if n % 2 as libc::c_int as uint64_t == 1 as libc::c_int as uint64_t {} else {
        __assert_fail(
            b"n % 2 == 1\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                as *const u8 as *const libc::c_char,
            106 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 40],
                &[libc::c_char; 40],
            >(b"uint64_t bn_neg_inv_mod_r_u64(uint64_t)\0"))
                .as_ptr(),
        );
    }
    'c_7630: {
        if n % 2 as libc::c_int as uint64_t == 1 as libc::c_int as uint64_t {} else {
            __assert_fail(
                b"n % 2 == 1\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                    as *const u8 as *const libc::c_char,
                106 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 40],
                    &[libc::c_char; 40],
                >(b"uint64_t bn_neg_inv_mod_r_u64(uint64_t)\0"))
                    .as_ptr(),
            );
        }
    };
    static mut alpha: uint64_t = (1 as libc::c_ulong)
        << 1 as libc::c_int * 64 as libc::c_int - 1 as libc::c_int;
    let beta: uint64_t = n;
    let mut u: uint64_t = 1 as libc::c_int as uint64_t;
    let mut v: uint64_t = 0 as libc::c_int as uint64_t;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < (1 as libc::c_int * 64 as libc::c_int) as size_t {
        if (1 as libc::c_int as uint128_t)
            << ((1 as libc::c_int * 64 as libc::c_int) as size_t).wrapping_sub(i)
            == (u as uint128_t * 2 as libc::c_int as uint128_t * alpha as uint128_t)
                .wrapping_sub(v as uint128_t * beta as uint128_t)
        {} else {
            __assert_fail(
                b"(BN_ULLONG)(1) << (LG_LITTLE_R - i) == ((BN_ULLONG)u * 2 * alpha) - ((BN_ULLONG)v * beta)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                    as *const u8 as *const libc::c_char,
                121 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 40],
                    &[libc::c_char; 40],
                >(b"uint64_t bn_neg_inv_mod_r_u64(uint64_t)\0"))
                    .as_ptr(),
            );
        }
        'c_7522: {
            if (1 as libc::c_int as uint128_t)
                << ((1 as libc::c_int * 64 as libc::c_int) as size_t).wrapping_sub(i)
                == (u as uint128_t * 2 as libc::c_int as uint128_t * alpha as uint128_t)
                    .wrapping_sub(v as uint128_t * beta as uint128_t)
            {} else {
                __assert_fail(
                    b"(BN_ULLONG)(1) << (LG_LITTLE_R - i) == ((BN_ULLONG)u * 2 * alpha) - ((BN_ULLONG)v * beta)\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                        as *const u8 as *const libc::c_char,
                    121 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 40],
                        &[libc::c_char; 40],
                    >(b"uint64_t bn_neg_inv_mod_r_u64(uint64_t)\0"))
                        .as_ptr(),
                );
            }
        };
        let mut u_is_odd: uint64_t = (0 as libc::c_ulong)
            .wrapping_sub(u & 1 as libc::c_int as uint64_t);
        let mut beta_if_u_is_odd: uint64_t = beta & u_is_odd;
        u = ((u ^ beta_if_u_is_odd) >> 1 as libc::c_int)
            .wrapping_add(u & beta_if_u_is_odd);
        let mut alpha_if_u_is_odd: uint64_t = alpha & u_is_odd;
        v = (v >> 1 as libc::c_int).wrapping_add(alpha_if_u_is_odd);
        i = i.wrapping_add(1);
        i;
    }
    if constant_time_declassify_int(
        (1 as libc::c_int as uint128_t
            == (u as uint128_t * 2 as libc::c_int as uint128_t * alpha as uint128_t)
                .wrapping_sub(v as uint128_t * beta as uint128_t)) as libc::c_int,
    ) != 0
    {} else {
        __assert_fail(
            b"constant_time_declassify_int(1 == ((uint128_t)u * 2 * alpha) - ((uint128_t)v * beta))\0"
                as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                as *const u8 as *const libc::c_char,
            157 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 40],
                &[libc::c_char; 40],
            >(b"uint64_t bn_neg_inv_mod_r_u64(uint64_t)\0"))
                .as_ptr(),
        );
    }
    'c_7363: {
        if constant_time_declassify_int(
            (1 as libc::c_int as uint128_t
                == (u as uint128_t * 2 as libc::c_int as uint128_t * alpha as uint128_t)
                    .wrapping_sub(v as uint128_t * beta as uint128_t)) as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(1 == ((uint128_t)u * 2 * alpha) - ((uint128_t)v * beta))\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                    as *const u8 as *const libc::c_char,
                157 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 40],
                    &[libc::c_char; 40],
                >(b"uint64_t bn_neg_inv_mod_r_u64(uint64_t)\0"))
                    .as_ptr(),
            );
        }
    };
    return v;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_mont_ctx_set_RR_consttime(
    mut mont: *mut BN_MONT_CTX,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if BN_is_zero(&mut (*mont).N) == 0 {} else {
        __assert_fail(
            b"!BN_is_zero(&mont->N)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                as *const u8 as *const libc::c_char,
            164 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 58],
                &[libc::c_char; 58],
            >(b"int bn_mont_ctx_set_RR_consttime(BN_MONT_CTX *, BN_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_8258: {
        if BN_is_zero(&mut (*mont).N) == 0 {} else {
            __assert_fail(
                b"!BN_is_zero(&mont->N)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                    as *const u8 as *const libc::c_char,
                164 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 58],
                    &[libc::c_char; 58],
                >(b"int bn_mont_ctx_set_RR_consttime(BN_MONT_CTX *, BN_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    if BN_is_negative(&mut (*mont).N) == 0 {} else {
        __assert_fail(
            b"!BN_is_negative(&mont->N)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                as *const u8 as *const libc::c_char,
            165 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 58],
                &[libc::c_char; 58],
            >(b"int bn_mont_ctx_set_RR_consttime(BN_MONT_CTX *, BN_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_8211: {
        if BN_is_negative(&mut (*mont).N) == 0 {} else {
            __assert_fail(
                b"!BN_is_negative(&mont->N)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                    as *const u8 as *const libc::c_char,
                165 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 58],
                    &[libc::c_char; 58],
                >(b"int bn_mont_ctx_set_RR_consttime(BN_MONT_CTX *, BN_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    if BN_is_odd(&mut (*mont).N) != 0 {} else {
        __assert_fail(
            b"BN_is_odd(&mont->N)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                as *const u8 as *const libc::c_char,
            166 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 58],
                &[libc::c_char; 58],
            >(b"int bn_mont_ctx_set_RR_consttime(BN_MONT_CTX *, BN_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_8166: {
        if BN_is_odd(&mut (*mont).N) != 0 {} else {
            __assert_fail(
                b"BN_is_odd(&mont->N)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                    as *const u8 as *const libc::c_char,
                166 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 58],
                    &[libc::c_char; 58],
                >(b"int bn_mont_ctx_set_RR_consttime(BN_MONT_CTX *, BN_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    if bn_minimal_width(&mut (*mont).N) == (*mont).N.width {} else {
        __assert_fail(
            b"bn_minimal_width(&mont->N) == mont->N.width\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                as *const u8 as *const libc::c_char,
            167 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 58],
                &[libc::c_char; 58],
            >(b"int bn_mont_ctx_set_RR_consttime(BN_MONT_CTX *, BN_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_8109: {
        if bn_minimal_width(&mut (*mont).N) == (*mont).N.width {} else {
            __assert_fail(
                b"bn_minimal_width(&mont->N) == mont->N.width\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                    as *const u8 as *const libc::c_char,
                167 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 58],
                    &[libc::c_char; 58],
                >(b"int bn_mont_ctx_set_RR_consttime(BN_MONT_CTX *, BN_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut n_bits: libc::c_uint = BN_num_bits(&mut (*mont).N);
    if n_bits != 0 as libc::c_int as libc::c_uint {} else {
        __assert_fail(
            b"n_bits != 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                as *const u8 as *const libc::c_char,
            170 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 58],
                &[libc::c_char; 58],
            >(b"int bn_mont_ctx_set_RR_consttime(BN_MONT_CTX *, BN_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_8070: {
        if n_bits != 0 as libc::c_int as libc::c_uint {} else {
            __assert_fail(
                b"n_bits != 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                    as *const u8 as *const libc::c_char,
                170 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 58],
                    &[libc::c_char; 58],
                >(b"int bn_mont_ctx_set_RR_consttime(BN_MONT_CTX *, BN_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    if n_bits == 1 as libc::c_int as libc::c_uint {
        BN_zero(&mut (*mont).RR);
        return bn_resize_words(&mut (*mont).RR, (*mont).N.width as size_t);
    }
    let mut lgBigR: libc::c_uint = ((*mont).N.width * 64 as libc::c_int) as libc::c_uint;
    if lgBigR >= n_bits {} else {
        __assert_fail(
            b"lgBigR >= n_bits\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                as *const u8 as *const libc::c_char,
            177 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 58],
                &[libc::c_char; 58],
            >(b"int bn_mont_ctx_set_RR_consttime(BN_MONT_CTX *, BN_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_8002: {
        if lgBigR >= n_bits {} else {
            __assert_fail(
                b"lgBigR >= n_bits\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                    as *const u8 as *const libc::c_char,
                177 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 58],
                    &[libc::c_char; 58],
                >(b"int bn_mont_ctx_set_RR_consttime(BN_MONT_CTX *, BN_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut threshold: libc::c_int = (*mont).N.width;
    if BN_set_bit(
        &mut (*mont).RR,
        n_bits.wrapping_sub(1 as libc::c_int as libc::c_uint) as libc::c_int,
    ) == 0
        || bn_mod_lshift_consttime(
            &mut (*mont).RR,
            &mut (*mont).RR,
            (threshold as libc::c_uint)
                .wrapping_add(
                    lgBigR
                        .wrapping_sub(
                            n_bits.wrapping_sub(1 as libc::c_int as libc::c_uint),
                        ),
                ) as libc::c_int,
            &mut (*mont).N,
            ctx,
        ) == 0
    {
        return 0 as libc::c_int;
    }
    if threshold == (*mont).N.width {} else {
        __assert_fail(
            b"threshold == mont->N.width\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                as *const u8 as *const libc::c_char,
            215 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 58],
                &[libc::c_char; 58],
            >(b"int bn_mont_ctx_set_RR_consttime(BN_MONT_CTX *, BN_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_7870: {
        if threshold == (*mont).N.width {} else {
            __assert_fail(
                b"threshold == mont->N.width\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery_inv.c\0"
                    as *const u8 as *const libc::c_char,
                215 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 58],
                    &[libc::c_char; 58],
                >(b"int bn_mont_ctx_set_RR_consttime(BN_MONT_CTX *, BN_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while i < 6 as libc::c_int as libc::c_uint {
        if BN_mod_mul_montgomery(
            &mut (*mont).RR,
            &mut (*mont).RR,
            &mut (*mont).RR,
            mont,
            ctx,
        ) == 0
        {
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return bn_resize_words(&mut (*mont).RR, (*mont).N.width as size_t);
}
