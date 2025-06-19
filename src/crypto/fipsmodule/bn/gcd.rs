#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(asm, extern_types)]
use core::arch::asm;
extern "C" {
    pub type bignum_ctx;
    fn BN_new() -> *mut BIGNUM;
    fn BN_init(bn: *mut BIGNUM);
    fn BN_free(bn: *mut BIGNUM);
    fn BN_dup(src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_copy(dest: *mut BIGNUM, src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_zero(bn: *mut BIGNUM);
    fn BN_one(bn: *mut BIGNUM) -> libc::c_int;
    fn BN_is_negative(bn: *const BIGNUM) -> libc::c_int;
    fn BN_CTX_start(ctx: *mut BN_CTX);
    fn BN_CTX_get(ctx: *mut BN_CTX) -> *mut BIGNUM;
    fn BN_CTX_end(ctx: *mut BN_CTX);
    fn BN_uadd(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_sub(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_usub(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_sub_word(a: *mut BIGNUM, w: BN_ULONG) -> libc::c_int;
    fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_ucmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_is_zero(bn: *const BIGNUM) -> libc::c_int;
    fn BN_is_one(bn: *const BIGNUM) -> libc::c_int;
    fn BN_is_odd(bn: *const BIGNUM) -> libc::c_int;
    fn BN_rshift(r: *mut BIGNUM, a: *const BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_rshift1(r: *mut BIGNUM, a: *const BIGNUM) -> libc::c_int;
    fn BN_is_bit_set(a: *const BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_nnmod(
        rem: *mut BIGNUM,
        numerator: *const BIGNUM,
        divisor: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_rand_range_ex(
        r: *mut BIGNUM,
        min_inclusive: BN_ULONG,
        max_exclusive: *const BIGNUM,
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
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn bn_mod_inverse_consttime(
        r: *mut BIGNUM,
        out_no_inverse: *mut libc::c_int,
        a: *const BIGNUM,
        n: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
}
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
unsafe extern "C" fn bn_secret(mut bn: *mut BIGNUM) {}
#[inline]
unsafe extern "C" fn bn_declassify(mut bn: *mut BIGNUM) {}
#[no_mangle]
pub unsafe extern "C" fn BN_mod_inverse_odd(
    mut out: *mut BIGNUM,
    mut out_no_inverse: *mut libc::c_int,
    mut a: *const BIGNUM,
    mut n: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut R: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut shift: libc::c_int = 0;
    let mut current_block: u64;
    *out_no_inverse = 0 as libc::c_int;
    if BN_is_odd(n) == 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/gcd.c\0"
                as *const u8 as *const libc::c_char,
            121 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if BN_is_negative(a) != 0 || BN_cmp(a, n) >= 0 as libc::c_int {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            107 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/gcd.c\0"
                as *const u8 as *const libc::c_char,
            126 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut A: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut B: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut X: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut Y: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut sign: libc::c_int = 0;
    BN_CTX_start(ctx);
    A = BN_CTX_get(ctx);
    B = BN_CTX_get(ctx);
    X = BN_CTX_get(ctx);
    Y = BN_CTX_get(ctx);
    if !Y.is_null() {
        R = out;
        BN_zero(Y);
        if !(BN_one(X) == 0 || (BN_copy(B, a)).is_null() || (BN_copy(A, n)).is_null()) {
            (*A).neg = 0 as libc::c_int;
            sign = -(1 as libc::c_int);
            shift = 0;
            's_78: loop {
                if !(BN_is_zero(B) == 0) {
                    current_block = 3938820862080741272;
                    break;
                }
                shift = 0 as libc::c_int;
                while BN_is_bit_set(B, shift) == 0 {
                    shift += 1;
                    shift;
                    if BN_is_odd(X) != 0 {
                        if BN_uadd(X, X, n) == 0 {
                            current_block = 13334929174010615641;
                            break 's_78;
                        }
                    }
                    if BN_rshift1(X, X) == 0 {
                        current_block = 13334929174010615641;
                        break 's_78;
                    }
                }
                if shift > 0 as libc::c_int {
                    if BN_rshift(B, B, shift) == 0 {
                        current_block = 13334929174010615641;
                        break;
                    }
                }
                shift = 0 as libc::c_int;
                while BN_is_bit_set(A, shift) == 0 {
                    shift += 1;
                    shift;
                    if BN_is_odd(Y) != 0 {
                        if BN_uadd(Y, Y, n) == 0 {
                            current_block = 13334929174010615641;
                            break 's_78;
                        }
                    }
                    if BN_rshift1(Y, Y) == 0 {
                        current_block = 13334929174010615641;
                        break 's_78;
                    }
                }
                if shift > 0 as libc::c_int {
                    if BN_rshift(A, A, shift) == 0 {
                        current_block = 13334929174010615641;
                        break;
                    }
                }
                if BN_ucmp(B, A) >= 0 as libc::c_int {
                    if BN_uadd(X, X, Y) == 0 {
                        current_block = 13334929174010615641;
                        break;
                    }
                    if BN_usub(B, B, A) == 0 {
                        current_block = 13334929174010615641;
                        break;
                    }
                } else {
                    if BN_uadd(Y, Y, X) == 0 {
                        current_block = 13334929174010615641;
                        break;
                    }
                    if BN_usub(A, A, B) == 0 {
                        current_block = 13334929174010615641;
                        break;
                    }
                }
            }
            match current_block {
                13334929174010615641 => {}
                _ => {
                    if BN_is_one(A) == 0 {
                        *out_no_inverse = 1 as libc::c_int;
                        ERR_put_error(
                            3 as libc::c_int,
                            0 as libc::c_int,
                            112 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/gcd.c\0"
                                as *const u8 as *const libc::c_char,
                            248 as libc::c_int as libc::c_uint,
                        );
                    } else {
                        if sign < 0 as libc::c_int {
                            if BN_sub(Y, n, Y) == 0 {
                                current_block = 13334929174010615641;
                            } else {
                                current_block = 13619784596304402172;
                            }
                        } else {
                            current_block = 13619784596304402172;
                        }
                        match current_block {
                            13334929174010615641 => {}
                            _ => {
                                if (*Y).neg != 0 || BN_ucmp(Y, n) >= 0 as libc::c_int {
                                    if BN_nnmod(Y, Y, n, ctx) == 0 {
                                        current_block = 13334929174010615641;
                                    } else {
                                        current_block = 2516253395664191498;
                                    }
                                } else {
                                    current_block = 2516253395664191498;
                                }
                                match current_block {
                                    13334929174010615641 => {}
                                    _ => {
                                        if !(BN_copy(R, Y)).is_null() {
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
#[no_mangle]
pub unsafe extern "C" fn BN_mod_inverse(
    mut out: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut n: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> *mut BIGNUM {
    let mut no_inverse: libc::c_int = 0;
    let mut current_block: u64;
    let mut new_out: *mut BIGNUM = 0 as *mut BIGNUM;
    if out.is_null() {
        new_out = BN_new();
        if new_out.is_null() {
            return 0 as *mut BIGNUM;
        }
        out = new_out;
    }
    let mut ok: libc::c_int = 0 as libc::c_int;
    let mut a_reduced: *mut BIGNUM = 0 as *mut BIGNUM;
    if (*a).neg != 0 || BN_ucmp(a, n) >= 0 as libc::c_int {
        a_reduced = BN_dup(a);
        if a_reduced.is_null() {
            current_block = 6806921680430372177;
        } else if BN_nnmod(a_reduced, a_reduced, n, ctx) == 0 {
            current_block = 6806921680430372177;
        } else {
            a = a_reduced;
            current_block = 7746791466490516765;
        }
    } else {
        current_block = 7746791466490516765;
    }
    match current_block {
        7746791466490516765 => {
            no_inverse = 0;
            if BN_is_odd(n) == 0 {
                if bn_mod_inverse_consttime(out, &mut no_inverse, a, n, ctx) == 0 {
                    current_block = 6806921680430372177;
                } else {
                    current_block = 8831408221741692167;
                }
            } else if BN_mod_inverse_odd(out, &mut no_inverse, a, n, ctx) == 0 {
                current_block = 6806921680430372177;
            } else {
                current_block = 8831408221741692167;
            }
            match current_block {
                6806921680430372177 => {}
                _ => {
                    ok = 1 as libc::c_int;
                }
            }
        }
        _ => {}
    }
    if ok == 0 {
        BN_free(new_out);
        out = 0 as *mut BIGNUM;
    }
    BN_free(a_reduced);
    return out;
}
#[no_mangle]
pub unsafe extern "C" fn BN_mod_inverse_blinded(
    mut out: *mut BIGNUM,
    mut out_no_inverse: *mut libc::c_int,
    mut a: *const BIGNUM,
    mut mont: *const BN_MONT_CTX,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    *out_no_inverse = 0 as libc::c_int;
    if BN_is_negative(a) != 0
        || constant_time_declassify_int(
            (BN_cmp(a, &(*mont).N) >= 0 as libc::c_int) as libc::c_int,
        ) != 0
    {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            107 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/gcd.c\0"
                as *const u8 as *const libc::c_char,
            334 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut blinding_factor: BIGNUM = bignum_st {
        d: 0 as *mut BN_ULONG,
        width: 0,
        dmax: 0,
        neg: 0,
        flags: 0,
    };
    BN_init(&mut blinding_factor);
    if !(BN_rand_range_ex(&mut blinding_factor, 1 as libc::c_int as BN_ULONG, &(*mont).N)
        == 0)
    {
        bn_secret(&mut blinding_factor);
        if !(BN_mod_mul_montgomery(out, &mut blinding_factor, a, mont, ctx) == 0) {
            bn_declassify(out);
            if !(BN_mod_inverse_odd(out, out_no_inverse, out, &(*mont).N, ctx) == 0
                || BN_mod_mul_montgomery(out, &mut blinding_factor, out, mont, ctx) == 0)
            {
                ret = 1 as libc::c_int;
            }
        }
    }
    BN_free(&mut blinding_factor);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn bn_mod_inverse_prime(
    mut out: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut p: *const BIGNUM,
    mut ctx: *mut BN_CTX,
    mut mont_p: *const BN_MONT_CTX,
) -> libc::c_int {
    BN_CTX_start(ctx);
    let mut p_minus_2: *mut BIGNUM = BN_CTX_get(ctx);
    let mut ok: libc::c_int = (!p_minus_2.is_null() && !(BN_copy(p_minus_2, p)).is_null()
        && BN_sub_word(p_minus_2, 2 as libc::c_int as BN_ULONG) != 0
        && BN_mod_exp_mont(out, a, p_minus_2, p, ctx, mont_p) != 0) as libc::c_int;
    BN_CTX_end(ctx);
    return ok;
}
#[no_mangle]
pub unsafe extern "C" fn bn_mod_inverse_secret_prime(
    mut out: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut p: *const BIGNUM,
    mut ctx: *mut BN_CTX,
    mut mont_p: *const BN_MONT_CTX,
) -> libc::c_int {
    BN_CTX_start(ctx);
    let mut p_minus_2: *mut BIGNUM = BN_CTX_get(ctx);
    let mut ok: libc::c_int = (!p_minus_2.is_null() && !(BN_copy(p_minus_2, p)).is_null()
        && BN_sub_word(p_minus_2, 2 as libc::c_int as BN_ULONG) != 0
        && BN_mod_exp_mont_consttime(out, a, p_minus_2, p, ctx, mont_p) != 0)
        as libc::c_int;
    BN_CTX_end(ctx);
    return ok;
}
