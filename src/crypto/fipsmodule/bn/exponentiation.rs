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
    fn BN_init(bn: *mut BIGNUM);
    fn BN_free(bn: *mut BIGNUM);
    fn BN_copy(dest: *mut BIGNUM, src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_num_bits(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_zero(bn: *mut BIGNUM);
    fn BN_one(bn: *mut BIGNUM) -> libc::c_int;
    fn BN_set_word(bn: *mut BIGNUM, value: BN_ULONG) -> libc::c_int;
    fn BN_CTX_start(ctx: *mut BN_CTX);
    fn BN_CTX_get(ctx: *mut BN_CTX) -> *mut BIGNUM;
    fn BN_CTX_end(ctx: *mut BN_CTX);
    fn BN_add_word(a: *mut BIGNUM, w: BN_ULONG) -> libc::c_int;
    fn BN_usub(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_mul(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        b: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_sqr(r: *mut BIGNUM, a: *const BIGNUM, ctx: *mut BN_CTX) -> libc::c_int;
    fn BN_div(
        quotient: *mut BIGNUM,
        rem: *mut BIGNUM,
        numerator: *const BIGNUM,
        divisor: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_ucmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_abs_is_word(bn: *const BIGNUM, w: BN_ULONG) -> libc::c_int;
    fn BN_is_zero(bn: *const BIGNUM) -> libc::c_int;
    fn BN_is_odd(bn: *const BIGNUM) -> libc::c_int;
    fn BN_rshift(r: *mut BIGNUM, a: *const BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_set_bit(a: *mut BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_is_bit_set(a: *const BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_nnmod(
        rem: *mut BIGNUM,
        numerator: *const BIGNUM,
        divisor: *const BIGNUM,
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
    fn BN_from_montgomery(
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
    fn BN_num_bits_word(l: BN_ULONG) -> libc::c_uint;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
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
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn bn_minimal_width(bn: *const BIGNUM) -> libc::c_int;
    fn bn_wexpand(bn: *mut BIGNUM, words: size_t) -> libc::c_int;
    fn bn_resize_words(bn: *mut BIGNUM, words: size_t) -> libc::c_int;
    fn bn_copy_words(out: *mut BN_ULONG, num: size_t, bn: *const BIGNUM) -> libc::c_int;
    fn bn_is_bit_set_words(a: *const BN_ULONG, num: size_t, bit: size_t) -> libc::c_int;
    fn bn_one_to_montgomery(
        r: *mut BIGNUM,
        mont: *const BN_MONT_CTX,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn bn_from_montgomery_small(
        r: *mut BN_ULONG,
        num_r: size_t,
        a: *const BN_ULONG,
        num_a: size_t,
        mont: *const BN_MONT_CTX,
    );
    fn bn_mod_mul_montgomery_small(
        r: *mut BN_ULONG,
        a: *const BN_ULONG,
        b: *const BN_ULONG,
        num: size_t,
        mont: *const BN_MONT_CTX,
    );
}
pub type size_t = libc::c_ulong;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type uintptr_t = libc::c_ulong;
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
pub type BN_RECP_CTX = bn_recp_ctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bn_recp_ctx_st {
    pub N: BIGNUM,
    pub Nr: BIGNUM,
    pub num_bits: libc::c_int,
    pub shift: libc::c_int,
    pub flags: libc::c_int,
}
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
pub struct static_assertion_at_line_1013_error_is_powerbuf_len_may_overflow {
    #[bitfield(
        name = "static_assertion_at_line_1013_error_is_powerbuf_len_may_overflow",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_1013_error_is_powerbuf_len_may_overflow: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[inline]
unsafe extern "C" fn align_pointer(
    mut ptr: *mut libc::c_void,
    mut alignment: size_t,
) -> *mut libc::c_void {
    if alignment != 0 as libc::c_int as size_t
        && alignment & alignment.wrapping_sub(1 as libc::c_int as size_t)
            == 0 as libc::c_int as size_t
    {} else {
        __assert_fail(
            b"alignment != 0 && (alignment & (alignment - 1)) == 0\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/../../internal.h\0"
                as *const u8 as *const libc::c_char,
            264 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 36],
                &[libc::c_char; 36],
            >(b"void *align_pointer(void *, size_t)\0"))
                .as_ptr(),
        );
    }
    'c_5888: {
        if alignment != 0 as libc::c_int as size_t
            && alignment & alignment.wrapping_sub(1 as libc::c_int as size_t)
                == 0 as libc::c_int as size_t
        {} else {
            __assert_fail(
                b"alignment != 0 && (alignment & (alignment - 1)) == 0\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/../../internal.h\0"
                    as *const u8 as *const libc::c_char,
                264 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 36],
                    &[libc::c_char; 36],
                >(b"void *align_pointer(void *, size_t)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut offset: uintptr_t = (0 as libc::c_uint as uintptr_t)
        .wrapping_sub(ptr as uintptr_t)
        & alignment.wrapping_sub(1 as libc::c_int as size_t);
    ptr = (ptr as *mut libc::c_char).offset(offset as isize) as *mut libc::c_void;
    if ptr as uintptr_t & alignment.wrapping_sub(1 as libc::c_int as size_t)
        == 0 as libc::c_int as libc::c_ulong
    {} else {
        __assert_fail(
            b"((uintptr_t)ptr & (alignment - 1)) == 0\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/../../internal.h\0"
                as *const u8 as *const libc::c_char,
            272 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 36],
                &[libc::c_char; 36],
            >(b"void *align_pointer(void *, size_t)\0"))
                .as_ptr(),
        );
    }
    'c_5804: {
        if ptr as uintptr_t & alignment.wrapping_sub(1 as libc::c_int as size_t)
            == 0 as libc::c_int as libc::c_ulong
        {} else {
            __assert_fail(
                b"((uintptr_t)ptr & (alignment - 1)) == 0\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/../../internal.h\0"
                    as *const u8 as *const libc::c_char,
                272 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 36],
                    &[libc::c_char; 36],
                >(b"void *align_pointer(void *, size_t)\0"))
                    .as_ptr(),
            );
        }
    };
    return ptr;
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
unsafe extern "C" fn exponentiation_use_s2n_bignum() -> libc::c_int {
    return 0 as libc::c_int;
}
unsafe extern "C" fn exponentiation_s2n_bignum_copy_from_prebuf(
    mut dest: *mut BN_ULONG,
    mut width: libc::c_int,
    mut table: *const BN_ULONG,
    mut rowidx: libc::c_int,
    mut window: libc::c_int,
) {
    abort();
}
#[no_mangle]
pub unsafe extern "C" fn BN_exp(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut p: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut current_block: u64;
    let mut i: libc::c_int = 0;
    let mut bits: libc::c_int = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut v: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut rr: *mut BIGNUM = 0 as *mut BIGNUM;
    BN_CTX_start(ctx);
    if r == a as *mut BIGNUM || r == p as *mut BIGNUM {
        rr = BN_CTX_get(ctx);
    } else {
        rr = r;
    }
    v = BN_CTX_get(ctx);
    if !(rr.is_null() || v.is_null()) {
        if !(BN_copy(v, a)).is_null() {
            bits = BN_num_bits(p) as libc::c_int;
            if BN_is_odd(p) != 0 {
                if (BN_copy(rr, a)).is_null() {
                    current_block = 9683158756561451187;
                } else {
                    current_block = 12349973810996921269;
                }
            } else if BN_one(rr) == 0 {
                current_block = 9683158756561451187;
            } else {
                current_block = 12349973810996921269;
            }
            match current_block {
                9683158756561451187 => {}
                _ => {
                    i = 1 as libc::c_int;
                    loop {
                        if !(i < bits) {
                            current_block = 224731115979188411;
                            break;
                        }
                        if BN_sqr(v, v, ctx) == 0 {
                            current_block = 9683158756561451187;
                            break;
                        }
                        if BN_is_bit_set(p, i) != 0 {
                            if BN_mul(rr, rr, v, ctx) == 0 {
                                current_block = 9683158756561451187;
                                break;
                            }
                        }
                        i += 1;
                        i;
                    }
                    match current_block {
                        9683158756561451187 => {}
                        _ => {
                            if !(r != rr && (BN_copy(r, rr)).is_null()) {
                                ret = 1 as libc::c_int;
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
unsafe extern "C" fn BN_RECP_CTX_init(mut recp: *mut BN_RECP_CTX) {
    BN_init(&mut (*recp).N);
    BN_init(&mut (*recp).Nr);
    (*recp).num_bits = 0 as libc::c_int;
    (*recp).shift = 0 as libc::c_int;
    (*recp).flags = 0 as libc::c_int;
}
unsafe extern "C" fn BN_RECP_CTX_free(mut recp: *mut BN_RECP_CTX) {
    if recp.is_null() {
        return;
    }
    BN_free(&mut (*recp).N);
    BN_free(&mut (*recp).Nr);
}
unsafe extern "C" fn BN_RECP_CTX_set(
    mut recp: *mut BN_RECP_CTX,
    mut d: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if (BN_copy(&mut (*recp).N, d)).is_null() {
        return 0 as libc::c_int;
    }
    BN_zero(&mut (*recp).Nr);
    (*recp).num_bits = BN_num_bits(d) as libc::c_int;
    (*recp).shift = 0 as libc::c_int;
    return 1 as libc::c_int;
}
unsafe extern "C" fn BN_reciprocal(
    mut r: *mut BIGNUM,
    mut m: *const BIGNUM,
    mut len: libc::c_int,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut t: *mut BIGNUM = 0 as *mut BIGNUM;
    BN_CTX_start(ctx);
    t = BN_CTX_get(ctx);
    if !t.is_null() {
        if !(BN_set_bit(t, len) == 0) {
            if !(BN_div(r, 0 as *mut BIGNUM, t, m, ctx) == 0) {
                ret = len;
            }
        }
    }
    BN_CTX_end(ctx);
    return ret;
}
unsafe extern "C" fn BN_div_recp(
    mut dv: *mut BIGNUM,
    mut rem: *mut BIGNUM,
    mut m: *const BIGNUM,
    mut recp: *mut BN_RECP_CTX,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut current_block: u64;
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut a: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut b: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut d: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut r: *mut BIGNUM = 0 as *mut BIGNUM;
    BN_CTX_start(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    if !dv.is_null() {
        d = dv;
    } else {
        d = BN_CTX_get(ctx);
    }
    if !rem.is_null() {
        r = rem;
    } else {
        r = BN_CTX_get(ctx);
    }
    if !(a.is_null() || b.is_null() || d.is_null() || r.is_null()) {
        if BN_ucmp(m, &mut (*recp).N) < 0 as libc::c_int {
            BN_zero(d);
            if !(BN_copy(r, m)).is_null() {
                BN_CTX_end(ctx);
                return 1 as libc::c_int;
            }
        } else {
            i = BN_num_bits(m) as libc::c_int;
            j = (*recp).num_bits << 1 as libc::c_int;
            if j > i {
                i = j;
            }
            if i != (*recp).shift {
                (*recp).shift = BN_reciprocal(&mut (*recp).Nr, &mut (*recp).N, i, ctx);
            }
            if !((*recp).shift == -(1 as libc::c_int)) {
                if !(BN_rshift(a, m, (*recp).num_bits) == 0) {
                    if !(BN_mul(b, a, &mut (*recp).Nr, ctx) == 0) {
                        if !(BN_rshift(d, b, i - (*recp).num_bits) == 0) {
                            (*d).neg = 0 as libc::c_int;
                            if !(BN_mul(b, &mut (*recp).N, d, ctx) == 0) {
                                if !(BN_usub(r, m, b) == 0) {
                                    (*r).neg = 0 as libc::c_int;
                                    j = 0 as libc::c_int;
                                    loop {
                                        if !(BN_ucmp(r, &mut (*recp).N) >= 0 as libc::c_int) {
                                            current_block = 3123434771885419771;
                                            break;
                                        }
                                        let fresh0 = j;
                                        j = j + 1;
                                        if fresh0 > 2 as libc::c_int {
                                            ERR_put_error(
                                                3 as libc::c_int,
                                                0 as libc::c_int,
                                                101 as libc::c_int,
                                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                                                    as *const u8 as *const libc::c_char,
                                                367 as libc::c_int as libc::c_uint,
                                            );
                                            current_block = 1974849457875412718;
                                            break;
                                        } else {
                                            if BN_usub(r, r, &mut (*recp).N) == 0 {
                                                current_block = 1974849457875412718;
                                                break;
                                            }
                                            if BN_add_word(d, 1 as libc::c_int as BN_ULONG) == 0 {
                                                current_block = 1974849457875412718;
                                                break;
                                            }
                                        }
                                    }
                                    match current_block {
                                        1974849457875412718 => {}
                                        _ => {
                                            (*r)
                                                .neg = if BN_is_zero(r) != 0 {
                                                0 as libc::c_int
                                            } else {
                                                (*m).neg
                                            };
                                            (*d).neg = (*m).neg ^ (*recp).N.neg;
                                            ret = 1 as libc::c_int;
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
unsafe extern "C" fn BN_mod_mul_reciprocal(
    mut r: *mut BIGNUM,
    mut x: *const BIGNUM,
    mut y: *const BIGNUM,
    mut recp: *mut BN_RECP_CTX,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut a: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut ca: *const BIGNUM = 0 as *const BIGNUM;
    BN_CTX_start(ctx);
    a = BN_CTX_get(ctx);
    if !a.is_null() {
        if !y.is_null() {
            if x == y {
                if BN_sqr(a, x, ctx) == 0 {
                    current_block = 3655501900182555584;
                } else {
                    current_block = 13183875560443969876;
                }
            } else if BN_mul(a, x, y, ctx) == 0 {
                current_block = 3655501900182555584;
            } else {
                current_block = 13183875560443969876;
            }
            match current_block {
                3655501900182555584 => {}
                _ => {
                    ca = a;
                    current_block = 5399440093318478209;
                }
            }
        } else {
            ca = x;
            current_block = 5399440093318478209;
        }
        match current_block {
            3655501900182555584 => {}
            _ => {
                ret = BN_div_recp(0 as *mut BIGNUM, r, ca, recp, ctx);
            }
        }
    }
    BN_CTX_end(ctx);
    return ret;
}
unsafe extern "C" fn BN_window_bits_for_exponent_size(mut b: size_t) -> libc::c_int {
    if b > 671 as libc::c_int as size_t {
        return 6 as libc::c_int;
    }
    if b > 239 as libc::c_int as size_t {
        return 5 as libc::c_int;
    }
    if b > 79 as libc::c_int as size_t {
        return 4 as libc::c_int;
    }
    if b > 23 as libc::c_int as size_t {
        return 3 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn mod_exp_recp(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut p: *const BIGNUM,
    mut m: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut current_block: u64;
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut wstart: libc::c_int = 0;
    let mut window: libc::c_int = 0;
    let mut start: libc::c_int = 1 as libc::c_int;
    let mut aa: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut val: [*mut BIGNUM; 32] = [0 as *mut BIGNUM; 32];
    let mut recp: BN_RECP_CTX = bn_recp_ctx_st {
        N: bignum_st {
            d: 0 as *mut BN_ULONG,
            width: 0,
            dmax: 0,
            neg: 0,
            flags: 0,
        },
        Nr: bignum_st {
            d: 0 as *mut BN_ULONG,
            width: 0,
            dmax: 0,
            neg: 0,
            flags: 0,
        },
        num_bits: 0,
        shift: 0,
        flags: 0,
    };
    if BN_is_odd(m) == 0 {} else {
        __assert_fail(
            b"!BN_is_odd(m)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                as *const u8 as *const libc::c_char,
            484 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 85],
                &[libc::c_char; 85],
            >(
                b"int mod_exp_recp(BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_3891: {
        if BN_is_odd(m) == 0 {} else {
            __assert_fail(
                b"!BN_is_odd(m)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                    as *const u8 as *const libc::c_char,
                484 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 85],
                    &[libc::c_char; 85],
                >(
                    b"int mod_exp_recp(BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut bits: libc::c_int = BN_num_bits(p) as libc::c_int;
    if bits == 0 as libc::c_int {
        return BN_one(r);
    }
    BN_RECP_CTX_init(&mut recp);
    BN_CTX_start(ctx);
    aa = BN_CTX_get(ctx);
    val[0 as libc::c_int as usize] = BN_CTX_get(ctx);
    if !(aa.is_null() || (val[0 as libc::c_int as usize]).is_null()) {
        if (*m).neg != 0 {
            if (BN_copy(aa, m)).is_null() {
                current_block = 4596975409645118170;
            } else {
                (*aa).neg = 0 as libc::c_int;
                if BN_RECP_CTX_set(&mut recp, aa, ctx) <= 0 as libc::c_int {
                    current_block = 4596975409645118170;
                } else {
                    current_block = 17407779659766490442;
                }
            }
        } else if BN_RECP_CTX_set(&mut recp, m, ctx) <= 0 as libc::c_int {
            current_block = 4596975409645118170;
        } else {
            current_block = 17407779659766490442;
        }
        match current_block {
            4596975409645118170 => {}
            _ => {
                if !(BN_nnmod(val[0 as libc::c_int as usize], a, m, ctx) == 0) {
                    if BN_is_zero(val[0 as libc::c_int as usize]) != 0 {
                        BN_zero(r);
                        ret = 1 as libc::c_int;
                    } else {
                        window = BN_window_bits_for_exponent_size(bits as size_t);
                        if window > 1 as libc::c_int {
                            if BN_mod_mul_reciprocal(
                                aa,
                                val[0 as libc::c_int as usize],
                                val[0 as libc::c_int as usize],
                                &mut recp,
                                ctx,
                            ) == 0
                            {
                                current_block = 4596975409645118170;
                            } else {
                                j = (1 as libc::c_int) << window - 1 as libc::c_int;
                                i = 1 as libc::c_int;
                                loop {
                                    if !(i < j) {
                                        current_block = 15925075030174552612;
                                        break;
                                    }
                                    val[i as usize] = BN_CTX_get(ctx);
                                    if (val[i as usize]).is_null()
                                        || BN_mod_mul_reciprocal(
                                            val[i as usize],
                                            val[(i - 1 as libc::c_int) as usize],
                                            aa,
                                            &mut recp,
                                            ctx,
                                        ) == 0
                                    {
                                        current_block = 4596975409645118170;
                                        break;
                                    }
                                    i += 1;
                                    i;
                                }
                            }
                        } else {
                            current_block = 15925075030174552612;
                        }
                        match current_block {
                            4596975409645118170 => {}
                            _ => {
                                start = 1 as libc::c_int;
                                wstart = bits - 1 as libc::c_int;
                                if !(BN_one(r) == 0) {
                                    's_158: loop {
                                        let mut wvalue: libc::c_int = 0;
                                        let mut wend: libc::c_int = 0;
                                        if BN_is_bit_set(p, wstart) == 0 {
                                            if start == 0 {
                                                if BN_mod_mul_reciprocal(r, r, r, &mut recp, ctx) == 0 {
                                                    current_block = 4596975409645118170;
                                                    break;
                                                }
                                            }
                                            if wstart == 0 as libc::c_int {
                                                current_block = 9241535491006583629;
                                                break;
                                            }
                                            wstart -= 1;
                                            wstart;
                                        } else {
                                            wvalue = 1 as libc::c_int;
                                            wend = 0 as libc::c_int;
                                            i = 1 as libc::c_int;
                                            while i < window {
                                                if wstart - i < 0 as libc::c_int {
                                                    break;
                                                }
                                                if BN_is_bit_set(p, wstart - i) != 0 {
                                                    wvalue <<= i - wend;
                                                    wvalue |= 1 as libc::c_int;
                                                    wend = i;
                                                }
                                                i += 1;
                                                i;
                                            }
                                            j = wend + 1 as libc::c_int;
                                            if start == 0 {
                                                i = 0 as libc::c_int;
                                                while i < j {
                                                    if BN_mod_mul_reciprocal(r, r, r, &mut recp, ctx) == 0 {
                                                        current_block = 4596975409645118170;
                                                        break 's_158;
                                                    }
                                                    i += 1;
                                                    i;
                                                }
                                            }
                                            if BN_mod_mul_reciprocal(
                                                r,
                                                r,
                                                val[(wvalue >> 1 as libc::c_int) as usize],
                                                &mut recp,
                                                ctx,
                                            ) == 0
                                            {
                                                current_block = 4596975409645118170;
                                                break;
                                            }
                                            wstart -= wend + 1 as libc::c_int;
                                            start = 0 as libc::c_int;
                                            if wstart < 0 as libc::c_int {
                                                current_block = 9241535491006583629;
                                                break;
                                            }
                                        }
                                    }
                                    match current_block {
                                        4596975409645118170 => {}
                                        _ => {
                                            ret = 1 as libc::c_int;
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
    BN_RECP_CTX_free(&mut recp);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn BN_mod_exp(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut p: *const BIGNUM,
    mut m: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if (*m).neg != 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                as *const u8 as *const libc::c_char,
            614 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*a).neg != 0 || BN_ucmp(a, m) >= 0 as libc::c_int {
        if BN_nnmod(r, a, m, ctx) == 0 {
            return 0 as libc::c_int;
        }
        a = r;
    }
    if BN_is_odd(m) != 0 {
        return BN_mod_exp_mont(r, a, p, m, ctx, 0 as *const BN_MONT_CTX);
    }
    return mod_exp_recp(r, a, p, m, ctx);
}
#[no_mangle]
pub unsafe extern "C" fn BN_mod_exp_mont(
    mut rr: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut p: *const BIGNUM,
    mut m: *const BIGNUM,
    mut ctx: *mut BN_CTX,
    mut mont: *const BN_MONT_CTX,
) -> libc::c_int {
    let mut window: libc::c_int = 0;
    let mut r_is_one: libc::c_int = 0;
    let mut wstart: libc::c_int = 0;
    let mut current_block: u64;
    if BN_is_odd(m) == 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                as *const u8 as *const libc::c_char,
            634 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*m).neg != 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                as *const u8 as *const libc::c_char,
            638 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*a).neg != 0 || constant_time_declassify_int(BN_ucmp(a, m)) >= 0 as libc::c_int {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            107 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                as *const u8 as *const libc::c_char,
            643 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut bits: libc::c_int = BN_num_bits(p) as libc::c_int;
    if bits == 0 as libc::c_int {
        if BN_abs_is_word(m, 1 as libc::c_int as BN_ULONG) != 0 {
            BN_zero(rr);
            return 1 as libc::c_int;
        }
        return BN_one(rr);
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut val: [*mut BIGNUM; 32] = [0 as *mut BIGNUM; 32];
    let mut new_mont: *mut BN_MONT_CTX = 0 as *mut BN_MONT_CTX;
    BN_CTX_start(ctx);
    let mut r: *mut BIGNUM = BN_CTX_get(ctx);
    val[0 as libc::c_int as usize] = BN_CTX_get(ctx);
    if !(r.is_null() || (val[0 as libc::c_int as usize]).is_null()) {
        if mont.is_null() {
            new_mont = BN_MONT_CTX_new_consttime(m, ctx);
            if new_mont.is_null() {
                current_block = 6310214523724960630;
            } else {
                mont = new_mont;
                current_block = 12147880666119273379;
            }
        } else {
            current_block = 12147880666119273379;
        }
        match current_block {
            6310214523724960630 => {}
            _ => {
                window = BN_window_bits_for_exponent_size(bits as size_t);
                if !(BN_to_montgomery(val[0 as libc::c_int as usize], a, mont, ctx) == 0)
                {
                    if window > 1 as libc::c_int {
                        let mut d: *mut BIGNUM = BN_CTX_get(ctx);
                        if d.is_null()
                            || BN_mod_mul_montgomery(
                                d,
                                val[0 as libc::c_int as usize],
                                val[0 as libc::c_int as usize],
                                mont,
                                ctx,
                            ) == 0
                        {
                            current_block = 6310214523724960630;
                        } else {
                            let mut i: libc::c_int = 1 as libc::c_int;
                            loop {
                                if !(i < (1 as libc::c_int) << window - 1 as libc::c_int) {
                                    current_block = 11932355480408055363;
                                    break;
                                }
                                val[i as usize] = BN_CTX_get(ctx);
                                if (val[i as usize]).is_null()
                                    || BN_mod_mul_montgomery(
                                        val[i as usize],
                                        val[(i - 1 as libc::c_int) as usize],
                                        d,
                                        mont,
                                        ctx,
                                    ) == 0
                                {
                                    current_block = 6310214523724960630;
                                    break;
                                }
                                i += 1;
                                i;
                            }
                        }
                    } else {
                        current_block = 11932355480408055363;
                    }
                    match current_block {
                        6310214523724960630 => {}
                        _ => {
                            r_is_one = 1 as libc::c_int;
                            wstart = bits - 1 as libc::c_int;
                            's_162: loop {
                                if BN_is_bit_set(p, wstart) == 0 {
                                    if r_is_one == 0
                                        && BN_mod_mul_montgomery(r, r, r, mont, ctx) == 0
                                    {
                                        current_block = 6310214523724960630;
                                        break;
                                    }
                                    if wstart == 0 as libc::c_int {
                                        current_block = 6560072651652764009;
                                        break;
                                    }
                                    wstart -= 1;
                                    wstart;
                                } else {
                                    let mut wvalue: libc::c_int = 1 as libc::c_int;
                                    let mut wsize: libc::c_int = 0 as libc::c_int;
                                    let mut i_0: libc::c_int = 1 as libc::c_int;
                                    while i_0 < window && i_0 <= wstart {
                                        if BN_is_bit_set(p, wstart - i_0) != 0 {
                                            wvalue <<= i_0 - wsize;
                                            wvalue |= 1 as libc::c_int;
                                            wsize = i_0;
                                        }
                                        i_0 += 1;
                                        i_0;
                                    }
                                    if r_is_one == 0 {
                                        let mut i_1: libc::c_int = 0 as libc::c_int;
                                        while i_1 < wsize + 1 as libc::c_int {
                                            if BN_mod_mul_montgomery(r, r, r, mont, ctx) == 0 {
                                                current_block = 6310214523724960630;
                                                break 's_162;
                                            }
                                            i_1 += 1;
                                            i_1;
                                        }
                                    }
                                    if wvalue & 1 as libc::c_int != 0 {} else {
                                        __assert_fail(
                                            b"wvalue & 1\0" as *const u8 as *const libc::c_char,
                                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                                                as *const u8 as *const libc::c_char,
                                            736 as libc::c_int as libc::c_uint,
                                            (*::core::mem::transmute::<
                                                &[u8; 109],
                                                &[libc::c_char; 109],
                                            >(
                                                b"int BN_mod_exp_mont(BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *, const BN_MONT_CTX *)\0",
                                            ))
                                                .as_ptr(),
                                        );
                                    }
                                    'c_4224: {
                                        if wvalue & 1 as libc::c_int != 0 {} else {
                                            __assert_fail(
                                                b"wvalue & 1\0" as *const u8 as *const libc::c_char,
                                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                                                    as *const u8 as *const libc::c_char,
                                                736 as libc::c_int as libc::c_uint,
                                                (*::core::mem::transmute::<
                                                    &[u8; 109],
                                                    &[libc::c_char; 109],
                                                >(
                                                    b"int BN_mod_exp_mont(BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *, const BN_MONT_CTX *)\0",
                                                ))
                                                    .as_ptr(),
                                            );
                                        }
                                    };
                                    if wvalue < (1 as libc::c_int) << window {} else {
                                        __assert_fail(
                                            b"wvalue < (1 << window)\0" as *const u8
                                                as *const libc::c_char,
                                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                                                as *const u8 as *const libc::c_char,
                                            737 as libc::c_int as libc::c_uint,
                                            (*::core::mem::transmute::<
                                                &[u8; 109],
                                                &[libc::c_char; 109],
                                            >(
                                                b"int BN_mod_exp_mont(BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *, const BN_MONT_CTX *)\0",
                                            ))
                                                .as_ptr(),
                                        );
                                    }
                                    'c_4172: {
                                        if wvalue < (1 as libc::c_int) << window {} else {
                                            __assert_fail(
                                                b"wvalue < (1 << window)\0" as *const u8
                                                    as *const libc::c_char,
                                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                                                    as *const u8 as *const libc::c_char,
                                                737 as libc::c_int as libc::c_uint,
                                                (*::core::mem::transmute::<
                                                    &[u8; 109],
                                                    &[libc::c_char; 109],
                                                >(
                                                    b"int BN_mod_exp_mont(BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *, const BN_MONT_CTX *)\0",
                                                ))
                                                    .as_ptr(),
                                            );
                                        }
                                    };
                                    if r_is_one != 0 {
                                        if (BN_copy(r, val[(wvalue >> 1 as libc::c_int) as usize]))
                                            .is_null()
                                        {
                                            current_block = 6310214523724960630;
                                            break;
                                        }
                                    } else if BN_mod_mul_montgomery(
                                        r,
                                        r,
                                        val[(wvalue >> 1 as libc::c_int) as usize],
                                        mont,
                                        ctx,
                                    ) == 0
                                    {
                                        current_block = 6310214523724960630;
                                        break;
                                    }
                                    r_is_one = 0 as libc::c_int;
                                    if wstart == wsize {
                                        current_block = 6560072651652764009;
                                        break;
                                    }
                                    wstart -= wsize + 1 as libc::c_int;
                                }
                            }
                            match current_block {
                                6310214523724960630 => {}
                                _ => {
                                    if r_is_one == 0 {} else {
                                        __assert_fail(
                                            b"!r_is_one\0" as *const u8 as *const libc::c_char,
                                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                                                as *const u8 as *const libc::c_char,
                                            754 as libc::c_int as libc::c_uint,
                                            (*::core::mem::transmute::<
                                                &[u8; 109],
                                                &[libc::c_char; 109],
                                            >(
                                                b"int BN_mod_exp_mont(BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *, const BN_MONT_CTX *)\0",
                                            ))
                                                .as_ptr(),
                                        );
                                    }
                                    'c_4042: {
                                        if r_is_one == 0 {} else {
                                            __assert_fail(
                                                b"!r_is_one\0" as *const u8 as *const libc::c_char,
                                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                                                    as *const u8 as *const libc::c_char,
                                                754 as libc::c_int as libc::c_uint,
                                                (*::core::mem::transmute::<
                                                    &[u8; 109],
                                                    &[libc::c_char; 109],
                                                >(
                                                    b"int BN_mod_exp_mont(BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *, const BN_MONT_CTX *)\0",
                                                ))
                                                    .as_ptr(),
                                            );
                                        }
                                    };
                                    if !(BN_from_montgomery(rr, r, mont, ctx) == 0) {
                                        ret = 1 as libc::c_int;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    BN_MONT_CTX_free(new_mont);
    BN_CTX_end(ctx);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn bn_mod_exp_mont_small(
    mut r: *mut BN_ULONG,
    mut a: *const BN_ULONG,
    mut num: size_t,
    mut p: *const BN_ULONG,
    mut num_p: size_t,
    mut mont: *const BN_MONT_CTX,
) {
    if num != (*mont).N.width as size_t || num > 9 as libc::c_int as size_t
        || num_p
            > (18446744073709551615 as libc::c_ulong)
                .wrapping_div(64 as libc::c_int as libc::c_ulong)
    {
        abort();
    }
    if BN_is_odd(&(*mont).N) != 0 {} else {
        __assert_fail(
            b"BN_is_odd(&mont->N)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                as *const u8 as *const libc::c_char,
            774 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 112],
                &[libc::c_char; 112],
            >(
                b"void bn_mod_exp_mont_small(BN_ULONG *, const BN_ULONG *, size_t, const BN_ULONG *, size_t, const BN_MONT_CTX *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_11976: {
        if BN_is_odd(&(*mont).N) != 0 {} else {
            __assert_fail(
                b"BN_is_odd(&mont->N)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                    as *const u8 as *const libc::c_char,
                774 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 112],
                    &[libc::c_char; 112],
                >(
                    b"void bn_mod_exp_mont_small(BN_ULONG *, const BN_ULONG *, size_t, const BN_ULONG *, size_t, const BN_MONT_CTX *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    while num_p != 0 as libc::c_int as size_t
        && *p.offset(num_p.wrapping_sub(1 as libc::c_int as size_t) as isize)
            == 0 as libc::c_int as BN_ULONG
    {
        num_p = num_p.wrapping_sub(1);
        num_p;
    }
    if num_p == 0 as libc::c_int as size_t {
        bn_from_montgomery_small(r, num, (*mont).RR.d, num, mont);
        return;
    }
    let mut bits: size_t = (BN_num_bits_word(
        *p.offset(num_p.wrapping_sub(1 as libc::c_int as size_t) as isize),
    ) as size_t)
        .wrapping_add(
            num_p.wrapping_sub(1 as libc::c_int as size_t) * 64 as libc::c_int as size_t,
        );
    if bits != 0 as libc::c_int as size_t {} else {
        __assert_fail(
            b"bits != 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                as *const u8 as *const libc::c_char,
            786 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 112],
                &[libc::c_char; 112],
            >(
                b"void bn_mod_exp_mont_small(BN_ULONG *, const BN_ULONG *, size_t, const BN_ULONG *, size_t, const BN_MONT_CTX *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_11890: {
        if bits != 0 as libc::c_int as size_t {} else {
            __assert_fail(
                b"bits != 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                    as *const u8 as *const libc::c_char,
                786 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 112],
                    &[libc::c_char; 112],
                >(
                    b"void bn_mod_exp_mont_small(BN_ULONG *, const BN_ULONG *, size_t, const BN_ULONG *, size_t, const BN_MONT_CTX *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut window: libc::c_uint = BN_window_bits_for_exponent_size(bits)
        as libc::c_uint;
    if window > 5 as libc::c_int as libc::c_uint {
        window = 5 as libc::c_int as libc::c_uint;
    }
    let mut val: [[BN_ULONG; 9]; 16] = [[0; 9]; 16];
    OPENSSL_memcpy(
        (val[0 as libc::c_int as usize]).as_mut_ptr() as *mut libc::c_void,
        a as *const libc::c_void,
        num.wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    );
    if window > 1 as libc::c_int as libc::c_uint {
        let mut d: [BN_ULONG; 9] = [0; 9];
        bn_mod_mul_montgomery_small(
            d.as_mut_ptr(),
            (val[0 as libc::c_int as usize]).as_mut_ptr(),
            (val[0 as libc::c_int as usize]).as_mut_ptr(),
            num,
            mont,
        );
        let mut i: libc::c_uint = 1 as libc::c_int as libc::c_uint;
        while i
            < (1 as libc::c_uint)
                << window.wrapping_sub(1 as libc::c_int as libc::c_uint)
        {
            bn_mod_mul_montgomery_small(
                (val[i as usize]).as_mut_ptr(),
                (val[i.wrapping_sub(1 as libc::c_int as libc::c_uint) as usize])
                    .as_mut_ptr(),
                d.as_mut_ptr(),
                num,
                mont,
            );
            i = i.wrapping_add(1);
            i;
        }
    }
    let mut r_is_one: libc::c_int = 1 as libc::c_int;
    let mut wstart: size_t = bits.wrapping_sub(1 as libc::c_int as size_t);
    loop {
        if bn_is_bit_set_words(p, num_p, wstart) == 0 {
            if r_is_one == 0 {
                bn_mod_mul_montgomery_small(r, r, r, num, mont);
            }
            if wstart == 0 as libc::c_int as size_t {
                break;
            }
            wstart = wstart.wrapping_sub(1);
            wstart;
        } else {
            let mut wvalue: libc::c_uint = 1 as libc::c_int as libc::c_uint;
            let mut wsize: libc::c_uint = 0 as libc::c_int as libc::c_uint;
            let mut i_0: libc::c_uint = 1 as libc::c_int as libc::c_uint;
            while i_0 < window && i_0 as size_t <= wstart {
                if bn_is_bit_set_words(p, num_p, wstart.wrapping_sub(i_0 as size_t)) != 0
                {
                    wvalue <<= i_0.wrapping_sub(wsize);
                    wvalue |= 1 as libc::c_int as libc::c_uint;
                    wsize = i_0;
                }
                i_0 = i_0.wrapping_add(1);
                i_0;
            }
            if r_is_one == 0 {
                let mut i_1: libc::c_uint = 0 as libc::c_int as libc::c_uint;
                while i_1 < wsize.wrapping_add(1 as libc::c_int as libc::c_uint) {
                    bn_mod_mul_montgomery_small(r, r, r, num, mont);
                    i_1 = i_1.wrapping_add(1);
                    i_1;
                }
            }
            if wvalue & 1 as libc::c_int as libc::c_uint != 0 {} else {
                __assert_fail(
                    b"wvalue & 1\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                        as *const u8 as *const libc::c_char,
                    840 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 112],
                        &[libc::c_char; 112],
                    >(
                        b"void bn_mod_exp_mont_small(BN_ULONG *, const BN_ULONG *, size_t, const BN_ULONG *, size_t, const BN_MONT_CTX *)\0",
                    ))
                        .as_ptr(),
                );
            }
            'c_11614: {
                if wvalue & 1 as libc::c_int as libc::c_uint != 0 {} else {
                    __assert_fail(
                        b"wvalue & 1\0" as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                            as *const u8 as *const libc::c_char,
                        840 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 112],
                            &[libc::c_char; 112],
                        >(
                            b"void bn_mod_exp_mont_small(BN_ULONG *, const BN_ULONG *, size_t, const BN_ULONG *, size_t, const BN_MONT_CTX *)\0",
                        ))
                            .as_ptr(),
                    );
                }
            };
            if wvalue < (1 as libc::c_uint) << window {} else {
                __assert_fail(
                    b"wvalue < (1u << window)\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                        as *const u8 as *const libc::c_char,
                    841 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 112],
                        &[libc::c_char; 112],
                    >(
                        b"void bn_mod_exp_mont_small(BN_ULONG *, const BN_ULONG *, size_t, const BN_ULONG *, size_t, const BN_MONT_CTX *)\0",
                    ))
                        .as_ptr(),
                );
            }
            'c_11562: {
                if wvalue < (1 as libc::c_uint) << window {} else {
                    __assert_fail(
                        b"wvalue < (1u << window)\0" as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                            as *const u8 as *const libc::c_char,
                        841 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 112],
                            &[libc::c_char; 112],
                        >(
                            b"void bn_mod_exp_mont_small(BN_ULONG *, const BN_ULONG *, size_t, const BN_ULONG *, size_t, const BN_MONT_CTX *)\0",
                        ))
                            .as_ptr(),
                    );
                }
            };
            if r_is_one != 0 {
                OPENSSL_memcpy(
                    r as *mut libc::c_void,
                    (val[(wvalue >> 1 as libc::c_int) as usize]).as_mut_ptr()
                        as *const libc::c_void,
                    num.wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
                );
            } else {
                bn_mod_mul_montgomery_small(
                    r,
                    r,
                    (val[(wvalue >> 1 as libc::c_int) as usize]).as_mut_ptr(),
                    num,
                    mont,
                );
            }
            r_is_one = 0 as libc::c_int;
            if wstart == wsize as size_t {
                break;
            }
            wstart = wstart
                .wrapping_sub(
                    wsize.wrapping_add(1 as libc::c_int as libc::c_uint) as size_t,
                );
        }
    }
    if r_is_one == 0 {} else {
        __assert_fail(
            b"!r_is_one\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                as *const u8 as *const libc::c_char,
            855 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 112],
                &[libc::c_char; 112],
            >(
                b"void bn_mod_exp_mont_small(BN_ULONG *, const BN_ULONG *, size_t, const BN_ULONG *, size_t, const BN_MONT_CTX *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_11410: {
        if r_is_one == 0 {} else {
            __assert_fail(
                b"!r_is_one\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                    as *const u8 as *const libc::c_char,
                855 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 112],
                    &[libc::c_char; 112],
                >(
                    b"void bn_mod_exp_mont_small(BN_ULONG *, const BN_ULONG *, size_t, const BN_ULONG *, size_t, const BN_MONT_CTX *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    OPENSSL_cleanse(
        val.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[[BN_ULONG; 9]; 16]>() as libc::c_ulong,
    );
}
#[no_mangle]
pub unsafe extern "C" fn bn_mod_inverse0_prime_mont_small(
    mut r: *mut BN_ULONG,
    mut a: *const BN_ULONG,
    mut num: size_t,
    mut mont: *const BN_MONT_CTX,
) {
    if num != (*mont).N.width as size_t || num > 9 as libc::c_int as size_t {
        abort();
    }
    let mut p_minus_two: [BN_ULONG; 9] = [0; 9];
    let mut p: *const BN_ULONG = (*mont).N.d;
    OPENSSL_memcpy(
        p_minus_two.as_mut_ptr() as *mut libc::c_void,
        p as *const libc::c_void,
        num.wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    );
    if p_minus_two[0 as libc::c_int as usize] >= 2 as libc::c_int as BN_ULONG {
        p_minus_two[0 as libc::c_int
            as usize] = (p_minus_two[0 as libc::c_int as usize])
            .wrapping_sub(2 as libc::c_int as BN_ULONG);
    } else {
        p_minus_two[0 as libc::c_int
            as usize] = (p_minus_two[0 as libc::c_int as usize])
            .wrapping_sub(2 as libc::c_int as BN_ULONG);
        let mut i: size_t = 1 as libc::c_int as size_t;
        while i < num {
            let fresh1 = p_minus_two[i as usize];
            p_minus_two[i as usize] = (p_minus_two[i as usize]).wrapping_sub(1);
            if fresh1 != 0 as libc::c_int as BN_ULONG {
                break;
            }
            i = i.wrapping_add(1);
            i;
        }
    }
    bn_mod_exp_mont_small(r, a, num, p_minus_two.as_mut_ptr(), num, mont);
}
unsafe extern "C" fn copy_to_prebuf(
    mut b: *const BIGNUM,
    mut top: libc::c_int,
    mut table: *mut BN_ULONG,
    mut idx: libc::c_int,
    mut window: libc::c_int,
) {
    let mut ret: libc::c_int = bn_copy_words(
        table.offset((idx * top) as isize),
        top as size_t,
        b,
    );
    if ret != 0 {} else {
        __assert_fail(
            b"ret\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                as *const u8 as *const libc::c_char,
            886 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 63],
                &[libc::c_char; 63],
            >(b"void copy_to_prebuf(const BIGNUM *, int, BN_ULONG *, int, int)\0"))
                .as_ptr(),
        );
    }
    'c_5440: {
        if ret != 0 {} else {
            __assert_fail(
                b"ret\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                    as *const u8 as *const libc::c_char,
                886 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 63],
                    &[libc::c_char; 63],
                >(b"void copy_to_prebuf(const BIGNUM *, int, BN_ULONG *, int, int)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn copy_from_prebuf(
    mut b: *mut BIGNUM,
    mut top: libc::c_int,
    mut table: *const BN_ULONG,
    mut idx: libc::c_int,
    mut window: libc::c_int,
) -> libc::c_int {
    if bn_wexpand(b, top as size_t) == 0 {
        return 0 as libc::c_int;
    }
    if exponentiation_use_s2n_bignum() != 0 {
        exponentiation_s2n_bignum_copy_from_prebuf((*b).d, top, table, idx, window);
        (*b).width = top;
        return 1 as libc::c_int;
    }
    OPENSSL_memset(
        (*b).d as *mut libc::c_void,
        0 as libc::c_int,
        (::core::mem::size_of::<BN_ULONG>() as libc::c_ulong)
            .wrapping_mul(top as libc::c_ulong),
    );
    let width: libc::c_int = (1 as libc::c_int) << window;
    let mut i: libc::c_int = 0 as libc::c_int;
    while i < width {
        let mut mask: BN_ULONG = value_barrier_w(constant_time_eq_int(i, idx));
        let mut j: libc::c_int = 0 as libc::c_int;
        while j < top {
            *((*b).d).offset(j as isize) |= *table.offset(j as isize) & mask;
            j += 1;
            j;
        }
        i += 1;
        i;
        table = table.offset(top as isize);
    }
    (*b).width = top;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn BN_mod_exp_mont_consttime(
    mut rr: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut p: *const BIGNUM,
    mut m: *const BIGNUM,
    mut ctx: *mut BN_CTX,
    mut mont: *const BN_MONT_CTX,
) -> libc::c_int {
    let mut top: libc::c_int = 0;
    let mut window: libc::c_int = 0;
    let mut num_powers: libc::c_int = 0;
    let mut tmp: BIGNUM = bignum_st {
        d: 0 as *mut BN_ULONG,
        width: 0,
        dmax: 0,
        neg: 0,
        flags: 0,
    };
    let mut am: BIGNUM = bignum_st {
        d: 0 as *mut BN_ULONG,
        width: 0,
        dmax: 0,
        neg: 0,
        flags: 0,
    };
    let mut current_block: u64;
    let mut i: libc::c_int = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut wvalue: libc::c_int = 0;
    let mut new_mont: *mut BN_MONT_CTX = 0 as *mut BN_MONT_CTX;
    let mut powerbuf_free: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut powerbuf_len: size_t = 0 as libc::c_int as size_t;
    let mut powerbuf: *mut BN_ULONG = 0 as *mut BN_ULONG;
    if BN_is_odd(m) == 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                as *const u8 as *const libc::c_char,
            938 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*m).neg != 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                as *const u8 as *const libc::c_char,
            942 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*a).neg != 0
        || constant_time_declassify_int(
            (BN_ucmp(a, m) >= 0 as libc::c_int) as libc::c_int,
        ) != 0
    {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            107 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                as *const u8 as *const libc::c_char,
            948 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut max_bits: libc::c_int = (*p).width * 64 as libc::c_int;
    let mut bits: libc::c_int = max_bits;
    if bits == 0 as libc::c_int {
        if BN_abs_is_word(m, 1 as libc::c_int as BN_ULONG) != 0 {
            BN_zero(rr);
            return 1 as libc::c_int;
        }
        return BN_one(rr);
    }
    if mont.is_null() {
        new_mont = BN_MONT_CTX_new_consttime(m, ctx);
        if new_mont.is_null() {
            current_block = 8756284646351725734;
        } else {
            mont = new_mont;
            current_block = 2370887241019905314;
        }
    } else {
        current_block = 2370887241019905314;
    }
    match current_block {
        2370887241019905314 => {
            top = (*mont).N.width;
            window = 5 as libc::c_int;
            if top as size_t
                <= ((8 as libc::c_int * 1024 as libc::c_int) as libc::c_ulong)
                    .wrapping_div(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong)
            {} else {
                __assert_fail(
                    b"(size_t)top <= BN_MONTGOMERY_MAX_WORDS\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                        as *const u8 as *const libc::c_char,
                    1008 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 119],
                        &[libc::c_char; 119],
                    >(
                        b"int BN_mod_exp_mont_consttime(BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *, const BN_MONT_CTX *)\0",
                    ))
                        .as_ptr(),
                );
            }
            'c_6011: {
                if top as size_t
                    <= ((8 as libc::c_int * 1024 as libc::c_int) as libc::c_ulong)
                        .wrapping_div(
                            ::core::mem::size_of::<BN_ULONG>() as libc::c_ulong,
                        )
                {} else {
                    __assert_fail(
                        b"(size_t)top <= BN_MONTGOMERY_MAX_WORDS\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                            as *const u8 as *const libc::c_char,
                        1008 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 119],
                            &[libc::c_char; 119],
                        >(
                            b"int BN_mod_exp_mont_consttime(BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *, const BN_MONT_CTX *)\0",
                        ))
                            .as_ptr(),
                    );
                }
            };
            num_powers = (1 as libc::c_int) << window;
            powerbuf_len = (powerbuf_len as libc::c_ulong)
                .wrapping_add(
                    (::core::mem::size_of::<BN_ULONG>() as libc::c_ulong)
                        .wrapping_mul(top as libc::c_ulong)
                        .wrapping_mul((num_powers + 2 as libc::c_int) as libc::c_ulong),
                ) as size_t as size_t;
            if powerbuf.is_null() {
                powerbuf_free = OPENSSL_zalloc(
                    powerbuf_len.wrapping_add(64 as libc::c_int as size_t),
                ) as *mut libc::c_uchar;
                if powerbuf_free.is_null() {
                    current_block = 8756284646351725734;
                } else {
                    powerbuf = align_pointer(
                        powerbuf_free as *mut libc::c_void,
                        64 as libc::c_int as size_t,
                    ) as *mut BN_ULONG;
                    current_block = 15345278821338558188;
                }
            } else {
                OPENSSL_memset(
                    powerbuf as *mut libc::c_void,
                    0 as libc::c_int,
                    powerbuf_len,
                );
                current_block = 15345278821338558188;
            }
            match current_block {
                8756284646351725734 => {}
                _ => {
                    tmp = bignum_st {
                        d: 0 as *mut BN_ULONG,
                        width: 0,
                        dmax: 0,
                        neg: 0,
                        flags: 0,
                    };
                    am = bignum_st {
                        d: 0 as *mut BN_ULONG,
                        width: 0,
                        dmax: 0,
                        neg: 0,
                        flags: 0,
                    };
                    tmp.d = powerbuf.offset((top * num_powers) as isize);
                    am.d = (tmp.d).offset(top as isize);
                    am.width = 0 as libc::c_int;
                    tmp.width = am.width;
                    am.dmax = top;
                    tmp.dmax = am.dmax;
                    am.neg = 0 as libc::c_int;
                    tmp.neg = am.neg;
                    am.flags = 0x2 as libc::c_int;
                    tmp.flags = am.flags;
                    if !(bn_one_to_montgomery(&mut tmp, mont, ctx) == 0
                        || bn_resize_words(&mut tmp, top as size_t) == 0)
                    {
                        if (*a).neg == 0 {} else {
                            __assert_fail(
                                b"!a->neg\0" as *const u8 as *const libc::c_char,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                                    as *const u8 as *const libc::c_char,
                                1057 as libc::c_int as libc::c_uint,
                                (*::core::mem::transmute::<
                                    &[u8; 119],
                                    &[libc::c_char; 119],
                                >(
                                    b"int BN_mod_exp_mont_consttime(BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *, const BN_MONT_CTX *)\0",
                                ))
                                    .as_ptr(),
                            );
                        }
                        'c_5646: {
                            if (*a).neg == 0 {} else {
                                __assert_fail(
                                    b"!a->neg\0" as *const u8 as *const libc::c_char,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                                        as *const u8 as *const libc::c_char,
                                    1057 as libc::c_int as libc::c_uint,
                                    (*::core::mem::transmute::<
                                        &[u8; 119],
                                        &[libc::c_char; 119],
                                    >(
                                        b"int BN_mod_exp_mont_consttime(BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *, const BN_MONT_CTX *)\0",
                                    ))
                                        .as_ptr(),
                                );
                            }
                        };
                        if constant_time_declassify_int(
                            (BN_ucmp(a, m) < 0 as libc::c_int) as libc::c_int,
                        ) != 0
                        {} else {
                            __assert_fail(
                                b"constant_time_declassify_int(BN_ucmp(a, m) < 0)\0"
                                    as *const u8 as *const libc::c_char,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                                    as *const u8 as *const libc::c_char,
                                1058 as libc::c_int as libc::c_uint,
                                (*::core::mem::transmute::<
                                    &[u8; 119],
                                    &[libc::c_char; 119],
                                >(
                                    b"int BN_mod_exp_mont_consttime(BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *, const BN_MONT_CTX *)\0",
                                ))
                                    .as_ptr(),
                            );
                        }
                        'c_5592: {
                            if constant_time_declassify_int(
                                (BN_ucmp(a, m) < 0 as libc::c_int) as libc::c_int,
                            ) != 0
                            {} else {
                                __assert_fail(
                                    b"constant_time_declassify_int(BN_ucmp(a, m) < 0)\0"
                                        as *const u8 as *const libc::c_char,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                                        as *const u8 as *const libc::c_char,
                                    1058 as libc::c_int as libc::c_uint,
                                    (*::core::mem::transmute::<
                                        &[u8; 119],
                                        &[libc::c_char; 119],
                                    >(
                                        b"int BN_mod_exp_mont_consttime(BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *, const BN_MONT_CTX *)\0",
                                    ))
                                        .as_ptr(),
                                );
                            }
                        };
                        if !(BN_to_montgomery(&mut am, a, mont, ctx) == 0
                            || bn_resize_words(&mut am, top as size_t) == 0)
                        {
                            copy_to_prebuf(
                                &mut tmp,
                                top,
                                powerbuf,
                                0 as libc::c_int,
                                window,
                            );
                            copy_to_prebuf(
                                &mut am,
                                top,
                                powerbuf,
                                1 as libc::c_int,
                                window,
                            );
                            if window > 1 as libc::c_int {
                                if BN_mod_mul_montgomery(
                                    &mut tmp,
                                    &mut am,
                                    &mut am,
                                    mont,
                                    ctx,
                                ) == 0
                                {
                                    current_block = 8756284646351725734;
                                } else {
                                    copy_to_prebuf(
                                        &mut tmp,
                                        top,
                                        powerbuf,
                                        2 as libc::c_int,
                                        window,
                                    );
                                    i = 3 as libc::c_int;
                                    loop {
                                        if !(i < num_powers) {
                                            current_block = 16799951812150840583;
                                            break;
                                        }
                                        if BN_mod_mul_montgomery(
                                            &mut tmp,
                                            &mut am,
                                            &mut tmp,
                                            mont,
                                            ctx,
                                        ) == 0
                                        {
                                            current_block = 8756284646351725734;
                                            break;
                                        }
                                        copy_to_prebuf(&mut tmp, top, powerbuf, i, window);
                                        i += 1;
                                        i;
                                    }
                                }
                            } else {
                                current_block = 16799951812150840583;
                            }
                            match current_block {
                                8756284646351725734 => {}
                                _ => {
                                    bits -= 1;
                                    bits;
                                    wvalue = 0 as libc::c_int;
                                    i = bits % window;
                                    while i >= 0 as libc::c_int {
                                        wvalue = (wvalue << 1 as libc::c_int)
                                            + BN_is_bit_set(p, bits);
                                        i -= 1;
                                        i;
                                        bits -= 1;
                                        bits;
                                    }
                                    if !(copy_from_prebuf(
                                        &mut tmp,
                                        top,
                                        powerbuf,
                                        wvalue,
                                        window,
                                    ) == 0)
                                    {
                                        's_257: loop {
                                            if !(bits >= 0 as libc::c_int) {
                                                current_block = 7252614138838059896;
                                                break;
                                            }
                                            wvalue = 0 as libc::c_int;
                                            i = 0 as libc::c_int;
                                            while i < window {
                                                if BN_mod_mul_montgomery(
                                                    &mut tmp,
                                                    &mut tmp,
                                                    &mut tmp,
                                                    mont,
                                                    ctx,
                                                ) == 0
                                                {
                                                    current_block = 8756284646351725734;
                                                    break 's_257;
                                                }
                                                wvalue = (wvalue << 1 as libc::c_int)
                                                    + BN_is_bit_set(p, bits);
                                                i += 1;
                                                i;
                                                bits -= 1;
                                                bits;
                                            }
                                            if copy_from_prebuf(&mut am, top, powerbuf, wvalue, window)
                                                == 0
                                            {
                                                current_block = 8756284646351725734;
                                                break;
                                            }
                                            if BN_mod_mul_montgomery(
                                                &mut tmp,
                                                &mut tmp,
                                                &mut am,
                                                mont,
                                                ctx,
                                            ) == 0
                                            {
                                                current_block = 8756284646351725734;
                                                break;
                                            }
                                        }
                                        match current_block {
                                            8756284646351725734 => {}
                                            _ => {
                                                if !(BN_from_montgomery(rr, &mut tmp, mont, ctx) == 0) {
                                                    ret = 1 as libc::c_int;
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
        }
        _ => {}
    }
    BN_MONT_CTX_free(new_mont);
    if !powerbuf.is_null() && powerbuf_free.is_null() {
        OPENSSL_cleanse(powerbuf as *mut libc::c_void, powerbuf_len);
    }
    OPENSSL_free(powerbuf_free as *mut libc::c_void);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn BN_mod_exp_mont_consttime_x2(
    mut rr1: *mut BIGNUM,
    mut a1: *const BIGNUM,
    mut p1: *const BIGNUM,
    mut m1: *const BIGNUM,
    mut in_mont1: *const BN_MONT_CTX,
    mut rr2: *mut BIGNUM,
    mut a2: *const BIGNUM,
    mut p2: *const BIGNUM,
    mut m2: *const BIGNUM,
    mut in_mont2: *const BN_MONT_CTX,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    ret = BN_mod_exp_mont_consttime(rr1, a1, p1, m1, ctx, in_mont1);
    ret &= BN_mod_exp_mont_consttime(rr2, a2, p2, m2, ctx, in_mont2);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn BN_mod_exp_mont_word(
    mut rr: *mut BIGNUM,
    mut a: BN_ULONG,
    mut p: *const BIGNUM,
    mut m: *const BIGNUM,
    mut ctx: *mut BN_CTX,
    mut mont: *const BN_MONT_CTX,
) -> libc::c_int {
    let mut a_bignum: BIGNUM = bignum_st {
        d: 0 as *mut BN_ULONG,
        width: 0,
        dmax: 0,
        neg: 0,
        flags: 0,
    };
    BN_init(&mut a_bignum);
    let mut ret: libc::c_int = 0 as libc::c_int;
    if bn_minimal_width(m) == 1 as libc::c_int {
        a = a % *((*m).d).offset(0 as libc::c_int as isize);
    }
    if BN_set_word(&mut a_bignum, a) == 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            4 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/exponentiation.c\0"
                as *const u8 as *const libc::c_char,
            1368 as libc::c_int as libc::c_uint,
        );
    } else {
        ret = BN_mod_exp_mont(rr, &mut a_bignum, p, m, ctx, mont);
    }
    BN_free(&mut a_bignum);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn BN_mod_exp2_mont(
    mut rr: *mut BIGNUM,
    mut a1: *const BIGNUM,
    mut p1: *const BIGNUM,
    mut a2: *const BIGNUM,
    mut p2: *const BIGNUM,
    mut m: *const BIGNUM,
    mut ctx: *mut BN_CTX,
    mut mont: *const BN_MONT_CTX,
) -> libc::c_int {
    let mut current_block: u64;
    let mut tmp: BIGNUM = bignum_st {
        d: 0 as *mut BN_ULONG,
        width: 0,
        dmax: 0,
        neg: 0,
        flags: 0,
    };
    BN_init(&mut tmp);
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut new_mont: *mut BN_MONT_CTX = 0 as *mut BN_MONT_CTX;
    if mont.is_null() {
        new_mont = BN_MONT_CTX_new_for_modulus(m, ctx);
        if new_mont.is_null() {
            current_block = 10908144021377310831;
        } else {
            mont = new_mont;
            current_block = 15427931788582360902;
        }
    } else {
        current_block = 15427931788582360902;
    }
    match current_block {
        15427931788582360902 => {
            if !(BN_mod_exp_mont(rr, a1, p1, m, ctx, mont) == 0
                || BN_mod_exp_mont(&mut tmp, a2, p2, m, ctx, mont) == 0
                || BN_to_montgomery(rr, rr, mont, ctx) == 0
                || BN_mod_mul_montgomery(rr, rr, &mut tmp, mont, ctx) == 0)
            {
                ret = 1 as libc::c_int;
            }
        }
        _ => {}
    }
    BN_MONT_CTX_free(new_mont);
    BN_free(&mut tmp);
    return ret;
}
