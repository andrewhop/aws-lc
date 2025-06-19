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
    fn BN_new() -> *mut BIGNUM;
    fn BN_free(bn: *mut BIGNUM);
    fn BN_clear_free(bn: *mut BIGNUM);
    fn BN_copy(dest: *mut BIGNUM, src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_value_one() -> *const BIGNUM;
    fn BN_num_bits(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_zero(bn: *mut BIGNUM);
    fn BN_one(bn: *mut BIGNUM) -> libc::c_int;
    fn BN_set_word(bn: *mut BIGNUM, value: BN_ULONG) -> libc::c_int;
    fn BN_CTX_start(ctx: *mut BN_CTX);
    fn BN_CTX_get(ctx: *mut BN_CTX) -> *mut BIGNUM;
    fn BN_CTX_end(ctx: *mut BN_CTX);
    fn BN_add(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_add_word(a: *mut BIGNUM, w: BN_ULONG) -> libc::c_int;
    fn BN_sub(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_sub_word(a: *mut BIGNUM, w: BN_ULONG) -> libc::c_int;
    fn BN_sqr(r: *mut BIGNUM, a: *const BIGNUM, ctx: *mut BN_CTX) -> libc::c_int;
    fn BN_div(
        quotient: *mut BIGNUM,
        rem: *mut BIGNUM,
        numerator: *const BIGNUM,
        divisor: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_ucmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_abs_is_word(bn: *const BIGNUM, w: BN_ULONG) -> libc::c_int;
    fn BN_is_zero(bn: *const BIGNUM) -> libc::c_int;
    fn BN_is_one(bn: *const BIGNUM) -> libc::c_int;
    fn BN_is_odd(bn: *const BIGNUM) -> libc::c_int;
    fn BN_lshift(r: *mut BIGNUM, a: *const BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_rshift(r: *mut BIGNUM, a: *const BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_rshift1(r: *mut BIGNUM, a: *const BIGNUM) -> libc::c_int;
    fn BN_is_bit_set(a: *const BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_nnmod(
        rem: *mut BIGNUM,
        numerator: *const BIGNUM,
        divisor: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_mod_mul(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        b: *const BIGNUM,
        m: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_mod_sqr(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        m: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_pseudo_rand(
        rnd: *mut BIGNUM,
        bits: libc::c_int,
        top: libc::c_int,
        bottom: libc::c_int,
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
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn bn_jacobi(a: *const BIGNUM, b: *const BIGNUM, ctx: *mut BN_CTX) -> libc::c_int;
    fn bn_mod_lshift1_consttime(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        m: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
}
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_mod_sqrt(
    mut in_0: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut p: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> *mut BIGNUM {
    let mut current_block: u64;
    let mut ret: *mut BIGNUM = in_0;
    let mut err: libc::c_int = 1 as libc::c_int;
    let mut r: libc::c_int = 0;
    let mut A: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut b: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut q: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut t: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut x: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut y: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut e: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    if BN_is_odd(p) == 0 || BN_abs_is_word(p, 1 as libc::c_int as BN_ULONG) != 0 {
        if BN_abs_is_word(p, 2 as libc::c_int as BN_ULONG) != 0 {
            if ret.is_null() {
                ret = BN_new();
            }
            if ret.is_null()
                || BN_set_word(ret, BN_is_bit_set(a, 0 as libc::c_int) as BN_ULONG) == 0
            {
                if ret != in_0 {
                    BN_free(ret);
                }
                return 0 as *mut BIGNUM;
            }
            return ret;
        }
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            114 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/sqrt.c\0"
                as *const u8 as *const libc::c_char,
            89 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut BIGNUM;
    }
    if BN_is_zero(a) != 0 || BN_is_one(a) != 0 {
        if ret.is_null() {
            ret = BN_new();
        }
        if ret.is_null() || BN_set_word(ret, BN_is_one(a) as BN_ULONG) == 0 {
            if ret != in_0 {
                BN_free(ret);
            }
            return 0 as *mut BIGNUM;
        }
        return ret;
    }
    BN_CTX_start(ctx);
    A = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    q = BN_CTX_get(ctx);
    t = BN_CTX_get(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    if !y.is_null() {
        if ret.is_null() {
            ret = BN_new();
        }
        if !ret.is_null() {
            if !(BN_nnmod(A, a, p, ctx) == 0) {
                e = 1 as libc::c_int;
                while BN_is_bit_set(p, e) == 0 {
                    e += 1;
                    e;
                }
                if e == 1 as libc::c_int {
                    if BN_rshift(q, p, 2 as libc::c_int) == 0 {
                        current_block = 14240879022742187461;
                    } else {
                        (*q).neg = 0 as libc::c_int;
                        if BN_add_word(q, 1 as libc::c_int as BN_ULONG) == 0
                            || BN_mod_exp_mont(
                                ret,
                                A,
                                q,
                                p,
                                ctx,
                                0 as *const BN_MONT_CTX,
                            ) == 0
                        {
                            current_block = 14240879022742187461;
                        } else {
                            err = 0 as libc::c_int;
                            current_block = 17595787494827682478;
                        }
                    }
                } else if e == 2 as libc::c_int {
                    if bn_mod_lshift1_consttime(t, A, p, ctx) == 0 {
                        current_block = 14240879022742187461;
                    } else if BN_rshift(q, p, 3 as libc::c_int) == 0 {
                        current_block = 14240879022742187461;
                    } else {
                        (*q).neg = 0 as libc::c_int;
                        if BN_mod_exp_mont(b, t, q, p, ctx, 0 as *const BN_MONT_CTX) == 0
                        {
                            current_block = 14240879022742187461;
                        } else if BN_mod_sqr(y, b, p, ctx) == 0 {
                            current_block = 14240879022742187461;
                        } else if BN_mod_mul(t, t, y, p, ctx) == 0
                            || BN_sub_word(t, 1 as libc::c_int as BN_ULONG) == 0
                        {
                            current_block = 14240879022742187461;
                        } else if BN_mod_mul(x, A, b, p, ctx) == 0
                            || BN_mod_mul(x, x, t, p, ctx) == 0
                        {
                            current_block = 14240879022742187461;
                        } else if (BN_copy(ret, x)).is_null() {
                            current_block = 14240879022742187461;
                        } else {
                            err = 0 as libc::c_int;
                            current_block = 17595787494827682478;
                        }
                    }
                } else if (BN_copy(q, p)).is_null() {
                    current_block = 14240879022742187461;
                } else {
                    (*q).neg = 0 as libc::c_int;
                    i = 2 as libc::c_int;
                    loop {
                        if i < 22 as libc::c_int {
                            if BN_set_word(y, i as BN_ULONG) == 0 {
                                current_block = 14240879022742187461;
                                break;
                            }
                        } else {
                            if BN_pseudo_rand(
                                y,
                                BN_num_bits(p) as libc::c_int,
                                0 as libc::c_int,
                                0 as libc::c_int,
                            ) == 0
                            {
                                current_block = 14240879022742187461;
                                break;
                            }
                            if BN_ucmp(y, p) >= 0 as libc::c_int {
                                if if (*p).neg != 0 {
                                    Some(
                                        BN_add
                                            as unsafe extern "C" fn(
                                                *mut BIGNUM,
                                                *const BIGNUM,
                                                *const BIGNUM,
                                            ) -> libc::c_int,
                                    )
                                } else {
                                    Some(
                                        BN_sub
                                            as unsafe extern "C" fn(
                                                *mut BIGNUM,
                                                *const BIGNUM,
                                                *const BIGNUM,
                                            ) -> libc::c_int,
                                    )
                                }
                                    .expect("non-null function pointer")(y, y, p) == 0
                                {
                                    current_block = 14240879022742187461;
                                    break;
                                }
                            }
                            if BN_is_zero(y) != 0 {
                                if BN_set_word(y, i as BN_ULONG) == 0 {
                                    current_block = 14240879022742187461;
                                    break;
                                }
                            }
                        }
                        r = bn_jacobi(y, q, ctx);
                        if r < -(1 as libc::c_int) {
                            current_block = 14240879022742187461;
                            break;
                        }
                        if r == 0 as libc::c_int {
                            ERR_put_error(
                                3 as libc::c_int,
                                0 as libc::c_int,
                                114 as libc::c_int,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/sqrt.c\0"
                                    as *const u8 as *const libc::c_char,
                                258 as libc::c_int as libc::c_uint,
                            );
                            current_block = 14240879022742187461;
                            break;
                        } else if !(r == 1 as libc::c_int
                            && {
                                i += 1;
                                i < 82 as libc::c_int
                            })
                        {
                            current_block = 13910774313357589740;
                            break;
                        }
                    }
                    match current_block {
                        14240879022742187461 => {}
                        _ => {
                            if r != -(1 as libc::c_int) {
                                ERR_put_error(
                                    3 as libc::c_int,
                                    0 as libc::c_int,
                                    115 as libc::c_int,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/sqrt.c\0"
                                        as *const u8 as *const libc::c_char,
                                    268 as libc::c_int as libc::c_uint,
                                );
                                current_block = 14240879022742187461;
                            } else if BN_rshift(q, q, e) == 0 {
                                current_block = 14240879022742187461;
                            } else if BN_mod_exp_mont(
                                y,
                                y,
                                q,
                                p,
                                ctx,
                                0 as *const BN_MONT_CTX,
                            ) == 0
                            {
                                current_block = 14240879022742187461;
                            } else if BN_is_one(y) != 0 {
                                ERR_put_error(
                                    3 as libc::c_int,
                                    0 as libc::c_int,
                                    114 as libc::c_int,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/sqrt.c\0"
                                        as *const u8 as *const libc::c_char,
                                    283 as libc::c_int as libc::c_uint,
                                );
                                current_block = 14240879022742187461;
                            } else if BN_rshift1(t, q) == 0 {
                                current_block = 14240879022742187461;
                            } else {
                                if BN_is_zero(t) != 0 {
                                    if BN_nnmod(t, A, p, ctx) == 0 {
                                        current_block = 14240879022742187461;
                                    } else if BN_is_zero(t) != 0 {
                                        BN_zero(ret);
                                        err = 0 as libc::c_int;
                                        current_block = 14240879022742187461;
                                    } else if BN_one(x) == 0 {
                                        current_block = 14240879022742187461;
                                    } else {
                                        current_block = 2616667235040759262;
                                    }
                                } else if BN_mod_exp_mont(
                                    x,
                                    A,
                                    t,
                                    p,
                                    ctx,
                                    0 as *const BN_MONT_CTX,
                                ) == 0
                                {
                                    current_block = 14240879022742187461;
                                } else if BN_is_zero(x) != 0 {
                                    BN_zero(ret);
                                    err = 0 as libc::c_int;
                                    current_block = 14240879022742187461;
                                } else {
                                    current_block = 2616667235040759262;
                                }
                                match current_block {
                                    14240879022742187461 => {}
                                    _ => {
                                        if BN_mod_sqr(b, x, p, ctx) == 0
                                            || BN_mod_mul(b, b, A, p, ctx) == 0
                                        {
                                            current_block = 14240879022742187461;
                                        } else if BN_mod_mul(x, x, A, p, ctx) == 0 {
                                            current_block = 14240879022742187461;
                                        } else {
                                            's_482: loop {
                                                if BN_is_one(b) != 0 {
                                                    if (BN_copy(ret, x)).is_null() {
                                                        current_block = 14240879022742187461;
                                                        break;
                                                    }
                                                    err = 0 as libc::c_int;
                                                    current_block = 17595787494827682478;
                                                    break;
                                                } else {
                                                    i = 1 as libc::c_int;
                                                    while i < e {
                                                        if i == 1 as libc::c_int {
                                                            if BN_mod_sqr(t, b, p, ctx) == 0 {
                                                                current_block = 14240879022742187461;
                                                                break 's_482;
                                                            }
                                                        } else if BN_mod_mul(t, t, t, p, ctx) == 0 {
                                                            current_block = 14240879022742187461;
                                                            break 's_482;
                                                        }
                                                        if BN_is_one(t) != 0 {
                                                            break;
                                                        }
                                                        i += 1;
                                                        i;
                                                    }
                                                    if i >= e {
                                                        ERR_put_error(
                                                            3 as libc::c_int,
                                                            0 as libc::c_int,
                                                            110 as libc::c_int,
                                                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/sqrt.c\0"
                                                                as *const u8 as *const libc::c_char,
                                                            378 as libc::c_int as libc::c_uint,
                                                        );
                                                        current_block = 14240879022742187461;
                                                        break;
                                                    } else {
                                                        if (BN_copy(t, y)).is_null() {
                                                            current_block = 14240879022742187461;
                                                            break;
                                                        }
                                                        j = e - i - 1 as libc::c_int;
                                                        while j > 0 as libc::c_int {
                                                            if BN_mod_sqr(t, t, p, ctx) == 0 {
                                                                current_block = 14240879022742187461;
                                                                break 's_482;
                                                            }
                                                            j -= 1;
                                                            j;
                                                        }
                                                        if BN_mod_mul(y, t, t, p, ctx) == 0
                                                            || BN_mod_mul(x, x, t, p, ctx) == 0
                                                            || BN_mod_mul(b, b, y, p, ctx) == 0
                                                        {
                                                            current_block = 14240879022742187461;
                                                            break;
                                                        }
                                                        if i < e {} else {
                                                            __assert_fail(
                                                                b"i < e\0" as *const u8 as *const libc::c_char,
                                                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/sqrt.c\0"
                                                                    as *const u8 as *const libc::c_char,
                                                                398 as libc::c_int as libc::c_uint,
                                                                (*::core::mem::transmute::<
                                                                    &[u8; 72],
                                                                    &[libc::c_char; 72],
                                                                >(
                                                                    b"BIGNUM *BN_mod_sqrt(BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *)\0",
                                                                ))
                                                                    .as_ptr(),
                                                            );
                                                        }
                                                        'c_2627: {
                                                            if i < e {} else {
                                                                __assert_fail(
                                                                    b"i < e\0" as *const u8 as *const libc::c_char,
                                                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/sqrt.c\0"
                                                                        as *const u8 as *const libc::c_char,
                                                                    398 as libc::c_int as libc::c_uint,
                                                                    (*::core::mem::transmute::<
                                                                        &[u8; 72],
                                                                        &[libc::c_char; 72],
                                                                    >(
                                                                        b"BIGNUM *BN_mod_sqrt(BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *)\0",
                                                                    ))
                                                                        .as_ptr(),
                                                                );
                                                            }
                                                        };
                                                        e = i;
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
                match current_block {
                    14240879022742187461 => {}
                    _ => {
                        if err == 0 {
                            if BN_mod_sqr(x, ret, p, ctx) == 0 {
                                err = 1 as libc::c_int;
                            }
                            if err == 0 && 0 as libc::c_int != BN_cmp(x, A) {
                                ERR_put_error(
                                    3 as libc::c_int,
                                    0 as libc::c_int,
                                    110 as libc::c_int,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/sqrt.c\0"
                                        as *const u8 as *const libc::c_char,
                                    410 as libc::c_int as libc::c_uint,
                                );
                                err = 1 as libc::c_int;
                            }
                        }
                    }
                }
            }
        }
    }
    if err != 0 {
        if ret != in_0 {
            BN_clear_free(ret);
        }
        ret = 0 as *mut BIGNUM;
    }
    BN_CTX_end(ctx);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_sqrt(
    mut out_sqrt: *mut BIGNUM,
    mut in_0: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut current_block: u64;
    let mut estimate: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut tmp: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut delta: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut last_delta: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut tmp2: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut ok: libc::c_int = 0 as libc::c_int;
    let mut last_delta_valid: libc::c_int = 0 as libc::c_int;
    if (*in_0).neg != 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/sqrt.c\0"
                as *const u8 as *const libc::c_char,
            431 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if BN_is_zero(in_0) != 0 {
        BN_zero(out_sqrt);
        return 1 as libc::c_int;
    }
    BN_CTX_start(ctx);
    if out_sqrt == in_0 as *mut BIGNUM {
        estimate = BN_CTX_get(ctx);
    } else {
        estimate = out_sqrt;
    }
    tmp = BN_CTX_get(ctx);
    last_delta = BN_CTX_get(ctx);
    delta = BN_CTX_get(ctx);
    if !(estimate.is_null() || tmp.is_null() || last_delta.is_null() || delta.is_null())
    {
        if !(BN_lshift(
            estimate,
            BN_value_one(),
            (BN_num_bits(in_0)).wrapping_div(2 as libc::c_int as libc::c_uint)
                as libc::c_int,
        ) == 0)
        {
            loop {
                if BN_div(tmp, 0 as *mut BIGNUM, in_0, estimate, ctx) == 0
                    || BN_add(tmp, tmp, estimate) == 0 || BN_rshift1(estimate, tmp) == 0
                    || BN_sqr(tmp, estimate, ctx) == 0 || BN_sub(delta, in_0, tmp) == 0
                {
                    ERR_put_error(
                        3 as libc::c_int,
                        0 as libc::c_int,
                        3 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/sqrt.c\0"
                            as *const u8 as *const libc::c_char,
                        468 as libc::c_int as libc::c_uint,
                    );
                    current_block = 9512062279173845642;
                    break;
                } else {
                    (*delta).neg = 0 as libc::c_int;
                    if last_delta_valid != 0
                        && BN_cmp(delta, last_delta) >= 0 as libc::c_int
                    {
                        current_block = 11307063007268554308;
                        break;
                    }
                    last_delta_valid = 1 as libc::c_int;
                    tmp2 = last_delta;
                    last_delta = delta;
                    delta = tmp2;
                }
            }
            match current_block {
                9512062279173845642 => {}
                _ => {
                    if BN_cmp(tmp, in_0) != 0 as libc::c_int {
                        ERR_put_error(
                            3 as libc::c_int,
                            0 as libc::c_int,
                            110 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/sqrt.c\0"
                                as *const u8 as *const libc::c_char,
                            488 as libc::c_int as libc::c_uint,
                        );
                    } else {
                        ok = 1 as libc::c_int;
                    }
                }
            }
        }
    }
    if ok != 0 && out_sqrt == in_0 as *mut BIGNUM
        && (BN_copy(out_sqrt, estimate)).is_null()
    {
        ok = 0 as libc::c_int;
    }
    BN_CTX_end(ctx);
    return ok;
}
