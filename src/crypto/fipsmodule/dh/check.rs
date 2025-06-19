#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
unsafe extern "C" {
    pub type bignum_ctx;
    fn BN_copy(dest: *mut BIGNUM, src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_value_one() -> *const BIGNUM;
    fn BN_num_bits(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_is_negative(bn: *const BIGNUM) -> libc::c_int;
    fn BN_CTX_new() -> *mut BN_CTX;
    fn BN_CTX_free(ctx: *mut BN_CTX);
    fn BN_CTX_start(ctx: *mut BN_CTX);
    fn BN_CTX_get(ctx: *mut BN_CTX) -> *mut BIGNUM;
    fn BN_CTX_end(ctx: *mut BN_CTX);
    fn BN_sub_word(a: *mut BIGNUM, w: BN_ULONG) -> libc::c_int;
    fn BN_div(
        quotient: *mut BIGNUM,
        rem: *mut BIGNUM,
        numerator: *const BIGNUM,
        divisor: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_ucmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_is_zero(bn: *const BIGNUM) -> libc::c_int;
    fn BN_is_one(bn: *const BIGNUM) -> libc::c_int;
    fn BN_is_odd(bn: *const BIGNUM) -> libc::c_int;
    fn BN_rshift1(r: *mut BIGNUM, a: *const BIGNUM) -> libc::c_int;
    fn BN_is_prime_ex(
        candidate: *const BIGNUM,
        checks: libc::c_int,
        ctx: *mut BN_CTX,
        cb: *mut BN_GENCB,
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
}
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
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
pub struct bn_gencb_st {
    pub type_0: uint8_t,
    pub arg: *mut libc::c_void,
    pub callback: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub new_style: Option::<
        unsafe extern "C" fn(libc::c_int, libc::c_int, *mut bn_gencb_st) -> libc::c_int,
    >,
    pub old_style: Option::<
        unsafe extern "C" fn(libc::c_int, libc::c_int, *mut libc::c_void) -> (),
    >,
}
pub type BN_GENCB = bn_gencb_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bn_mont_ctx_st {
    pub RR: BIGNUM,
    pub N: BIGNUM,
    pub n0: [BN_ULONG; 2],
}
pub type BN_MONT_CTX = bn_mont_ctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dh_st {
    pub p: *mut BIGNUM,
    pub g: *mut BIGNUM,
    pub q: *mut BIGNUM,
    pub pub_key: *mut BIGNUM,
    pub priv_key: *mut BIGNUM,
    pub priv_length: libc::c_uint,
    pub method_mont_p_lock: CRYPTO_MUTEX,
    pub method_mont_p: *mut BN_MONT_CTX,
    pub flags: libc::c_int,
    pub references: CRYPTO_refcount_t,
}
pub type CRYPTO_refcount_t = uint32_t;
pub type CRYPTO_MUTEX = crypto_mutex_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub union crypto_mutex_st {
    pub alignment: libc::c_double,
    pub padding: [uint8_t; 56],
}
pub type DH = dh_st;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dh_check_params_fast(mut dh: *const DH) -> libc::c_int {
    if BN_is_negative((*dh).p) != 0 || BN_is_odd((*dh).p) == 0
        || BN_num_bits((*dh).p) > 10000 as libc::c_int as libc::c_uint
    {
        ERR_put_error(
            5 as libc::c_int,
            0 as libc::c_int,
            107 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/dh/check.c\0"
                as *const u8 as *const libc::c_char,
            68 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if !((*dh).q).is_null()
        && (BN_is_negative((*dh).q) != 0 || BN_ucmp((*dh).q, (*dh).p) > 0 as libc::c_int)
    {
        ERR_put_error(
            5 as libc::c_int,
            0 as libc::c_int,
            107 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/dh/check.c\0"
                as *const u8 as *const libc::c_char,
            74 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if BN_is_negative((*dh).g) != 0 || BN_is_zero((*dh).g) != 0
        || BN_ucmp((*dh).g, (*dh).p) >= 0 as libc::c_int
    {
        ERR_put_error(
            5 as libc::c_int,
            0 as libc::c_int,
            107 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/dh/check.c\0"
                as *const u8 as *const libc::c_char,
            81 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DH_check_pub_key(
    mut dh: *const DH,
    mut pub_key: *const BIGNUM,
    mut out_flags: *mut libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    *out_flags = 0 as libc::c_int;
    if dh_check_params_fast(dh) == 0 {
        return 0 as libc::c_int;
    }
    let mut ctx: *mut BN_CTX = BN_CTX_new();
    if ctx.is_null() {
        return 0 as libc::c_int;
    }
    BN_CTX_start(ctx);
    let mut ok: libc::c_int = 0 as libc::c_int;
    if BN_cmp(pub_key, BN_value_one()) <= 0 as libc::c_int {
        *out_flags |= 0x1 as libc::c_int;
    }
    let mut tmp: *mut BIGNUM = BN_CTX_get(ctx);
    if !(tmp.is_null() || (BN_copy(tmp, (*dh).p)).is_null()
        || BN_sub_word(tmp, 1 as libc::c_int as BN_ULONG) == 0)
    {
        if BN_cmp(pub_key, tmp) >= 0 as libc::c_int {
            *out_flags |= 0x2 as libc::c_int;
        }
        if !((*dh).q).is_null() {
            if BN_mod_exp_mont(
                tmp,
                pub_key,
                (*dh).q,
                (*dh).p,
                ctx,
                0 as *const BN_MONT_CTX,
            ) == 0
            {
                current_block = 3939452976023930092;
            } else {
                if BN_is_one(tmp) == 0 {
                    *out_flags |= 0x4 as libc::c_int;
                }
                current_block = 17833034027772472439;
            }
        } else {
            current_block = 17833034027772472439;
        }
        match current_block {
            3939452976023930092 => {}
            _ => {
                ok = 1 as libc::c_int;
            }
        }
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ok;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DH_check(
    mut dh: *const DH,
    mut out_flags: *mut libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    *out_flags = 0 as libc::c_int;
    if dh_check_params_fast(dh) == 0 {
        return 0 as libc::c_int;
    }
    let mut ok: libc::c_int = 0 as libc::c_int;
    let mut r: libc::c_int = 0;
    let mut q_good: libc::c_int = 0 as libc::c_int;
    let mut ctx: *mut BN_CTX = 0 as *mut BN_CTX;
    let mut t1: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut t2: *mut BIGNUM = 0 as *mut BIGNUM;
    ctx = BN_CTX_new();
    if !ctx.is_null() {
        BN_CTX_start(ctx);
        t1 = BN_CTX_get(ctx);
        if !t1.is_null() {
            t2 = BN_CTX_get(ctx);
            if !t2.is_null() {
                if !((*dh).q).is_null() {
                    if BN_ucmp((*dh).p, (*dh).q) > 0 as libc::c_int {
                        q_good = 1 as libc::c_int;
                    } else {
                        *out_flags |= 0x20 as libc::c_int;
                    }
                }
                if q_good != 0 {
                    if BN_cmp((*dh).g, BN_value_one()) <= 0 as libc::c_int {
                        *out_flags |= 0x8 as libc::c_int;
                        current_block = 18386322304582297246;
                    } else if BN_cmp((*dh).g, (*dh).p) >= 0 as libc::c_int {
                        *out_flags |= 0x8 as libc::c_int;
                        current_block = 18386322304582297246;
                    } else if BN_mod_exp_mont(
                        t1,
                        (*dh).g,
                        (*dh).q,
                        (*dh).p,
                        ctx,
                        0 as *const BN_MONT_CTX,
                    ) == 0
                    {
                        current_block = 11320782220857468329;
                    } else {
                        if BN_is_one(t1) == 0 {
                            *out_flags |= 0x8 as libc::c_int;
                        }
                        current_block = 18386322304582297246;
                    }
                    match current_block {
                        11320782220857468329 => {}
                        _ => {
                            r = BN_is_prime_ex(
                                (*dh).q,
                                64 as libc::c_int,
                                ctx,
                                0 as *mut BN_GENCB,
                            );
                            if r < 0 as libc::c_int {
                                current_block = 11320782220857468329;
                            } else {
                                if r == 0 {
                                    *out_flags |= 0x10 as libc::c_int;
                                }
                                if BN_div(t1, t2, (*dh).p, (*dh).q, ctx) == 0 {
                                    current_block = 11320782220857468329;
                                } else {
                                    if BN_is_one(t2) == 0 {
                                        *out_flags |= 0x20 as libc::c_int;
                                    }
                                    current_block = 9520865839495247062;
                                }
                            }
                        }
                    }
                } else {
                    current_block = 9520865839495247062;
                }
                match current_block {
                    11320782220857468329 => {}
                    _ => {
                        r = BN_is_prime_ex(
                            (*dh).p,
                            64 as libc::c_int,
                            ctx,
                            0 as *mut BN_GENCB,
                        );
                        if !(r < 0 as libc::c_int) {
                            if r == 0 {
                                *out_flags |= 0x1 as libc::c_int;
                                current_block = 1434579379687443766;
                            } else if ((*dh).q).is_null() {
                                if BN_rshift1(t1, (*dh).p) == 0 {
                                    current_block = 11320782220857468329;
                                } else {
                                    r = BN_is_prime_ex(
                                        t1,
                                        64 as libc::c_int,
                                        ctx,
                                        0 as *mut BN_GENCB,
                                    );
                                    if r < 0 as libc::c_int {
                                        current_block = 11320782220857468329;
                                    } else {
                                        if r == 0 {
                                            *out_flags |= 0x2 as libc::c_int;
                                        }
                                        current_block = 1434579379687443766;
                                    }
                                }
                            } else {
                                current_block = 1434579379687443766;
                            }
                            match current_block {
                                11320782220857468329 => {}
                                _ => {
                                    ok = 1 as libc::c_int;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if !ctx.is_null() {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ok;
}
