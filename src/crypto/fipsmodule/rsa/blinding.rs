#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(extern_types)]
extern "C" {
    pub type bignum_ctx;
    fn BN_new() -> *mut BIGNUM;
    fn BN_free(bn: *mut BIGNUM);
    fn BN_rand_range_ex(
        r: *mut BIGNUM,
        min_inclusive: BN_ULONG,
        max_exclusive: *const BIGNUM,
    ) -> libc::c_int;
    fn BN_mod_inverse_blinded(
        out: *mut BIGNUM,
        out_no_inverse: *mut libc::c_int,
        a: *const BIGNUM,
        mont: *const BN_MONT_CTX,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
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
    fn BN_mod_exp_mont(
        r: *mut BIGNUM,
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
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
}
pub type size_t = libc::c_ulong;
pub type __uint64_t = libc::c_ulong;
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
pub type BN_BLINDING = bn_blinding_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bn_blinding_st {
    pub A: *mut BIGNUM,
    pub Ai: *mut BIGNUM,
    pub counter: libc::c_uint,
}
#[no_mangle]
pub unsafe extern "C" fn BN_BLINDING_new() -> *mut BN_BLINDING {
    let mut ret: *mut BN_BLINDING = OPENSSL_zalloc(
        ::core::mem::size_of::<BN_BLINDING>() as libc::c_ulong,
    ) as *mut BN_BLINDING;
    if ret.is_null() {
        return 0 as *mut BN_BLINDING;
    }
    (*ret).A = BN_new();
    if !((*ret).A).is_null() {
        (*ret).Ai = BN_new();
        if !((*ret).Ai).is_null() {
            (*ret).counter = (32 as libc::c_int - 1 as libc::c_int) as libc::c_uint;
            return ret;
        }
    }
    BN_BLINDING_free(ret);
    return 0 as *mut BN_BLINDING;
}
#[no_mangle]
pub unsafe extern "C" fn BN_BLINDING_free(mut r: *mut BN_BLINDING) {
    if r.is_null() {
        return;
    }
    BN_free((*r).A);
    BN_free((*r).Ai);
    OPENSSL_free(r as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn BN_BLINDING_invalidate(mut b: *mut BN_BLINDING) {
    (*b).counter = (32 as libc::c_int - 1 as libc::c_int) as libc::c_uint;
}
unsafe extern "C" fn bn_blinding_update(
    mut b: *mut BN_BLINDING,
    mut e: *const BIGNUM,
    mut mont: *const BN_MONT_CTX,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut current_block: u64;
    (*b).counter = ((*b).counter).wrapping_add(1);
    if (*b).counter == 32 as libc::c_int as libc::c_uint {
        if bn_blinding_create_param(b, e, mont, ctx) == 0 {
            current_block = 246589785114314855;
        } else {
            (*b).counter = 0 as libc::c_int as libc::c_uint;
            current_block = 15240798224410183470;
        }
    } else if BN_mod_mul_montgomery((*b).A, (*b).A, (*b).A, mont, ctx) == 0
        || BN_mod_mul_montgomery((*b).Ai, (*b).Ai, (*b).Ai, mont, ctx) == 0
    {
        current_block = 246589785114314855;
    } else {
        current_block = 15240798224410183470;
    }
    match current_block {
        15240798224410183470 => return 1 as libc::c_int,
        _ => {
            (*b).counter = (32 as libc::c_int - 1 as libc::c_int) as libc::c_uint;
            return 0 as libc::c_int;
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn BN_BLINDING_convert(
    mut n: *mut BIGNUM,
    mut b: *mut BN_BLINDING,
    mut e: *const BIGNUM,
    mut mont: *const BN_MONT_CTX,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if bn_blinding_update(b, e, mont, ctx) == 0
        || BN_mod_mul_montgomery(n, n, (*b).A, mont, ctx) == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn BN_BLINDING_invert(
    mut n: *mut BIGNUM,
    mut b: *const BN_BLINDING,
    mut mont: *mut BN_MONT_CTX,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    return BN_mod_mul_montgomery(n, n, (*b).Ai, mont, ctx);
}
unsafe extern "C" fn bn_blinding_create_param(
    mut b: *mut BN_BLINDING,
    mut e: *const BIGNUM,
    mut mont: *const BN_MONT_CTX,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut no_inverse: libc::c_int = 0;
    if BN_rand_range_ex((*b).A, 1 as libc::c_int as BN_ULONG, &(*mont).N) == 0
        || BN_from_montgomery((*b).Ai, (*b).A, mont, ctx) == 0
        || BN_mod_inverse_blinded((*b).Ai, &mut no_inverse, (*b).Ai, mont, ctx) == 0
        || BN_mod_exp_mont((*b).A, (*b).A, e, &(*mont).N, ctx, mont) == 0
        || BN_to_montgomery((*b).A, (*b).A, mont, ctx) == 0
    {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            4 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/blinding.c\0"
                as *const u8 as *const libc::c_char,
            236 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
