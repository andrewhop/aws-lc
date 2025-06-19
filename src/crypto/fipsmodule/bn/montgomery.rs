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
    fn abort() -> !;
    fn BN_init(bn: *mut BIGNUM);
    fn BN_free(bn: *mut BIGNUM);
    fn BN_copy(dest: *mut BIGNUM, src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_zero(bn: *mut BIGNUM);
    fn BN_is_negative(bn: *const BIGNUM) -> libc::c_int;
    fn BN_CTX_new() -> *mut BN_CTX;
    fn BN_CTX_free(ctx: *mut BN_CTX);
    fn BN_CTX_start(ctx: *mut BN_CTX);
    fn BN_CTX_get(ctx: *mut BN_CTX) -> *mut BIGNUM;
    fn BN_CTX_end(ctx: *mut BN_CTX);
    fn BN_div(
        quotient: *mut BIGNUM,
        rem: *mut BIGNUM,
        numerator: *const BIGNUM,
        divisor: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_is_zero(bn: *const BIGNUM) -> libc::c_int;
    fn BN_is_odd(bn: *const BIGNUM) -> libc::c_int;
    fn BN_set_bit(a: *mut BIGNUM, n: libc::c_int) -> libc::c_int;
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
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn CRYPTO_MUTEX_lock_read(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_lock_write(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_unlock_read(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_unlock_write(lock: *mut CRYPTO_MUTEX);
    fn bn_set_minimal_width(bn: *mut BIGNUM);
    fn bn_wexpand(bn: *mut BIGNUM, words: size_t) -> libc::c_int;
    fn bn_resize_words(bn: *mut BIGNUM, words: size_t) -> libc::c_int;
    fn bn_fits_in_words(bn: *const BIGNUM, num: size_t) -> libc::c_int;
    fn bn_mul_add_words(
        rp: *mut BN_ULONG,
        ap: *const BN_ULONG,
        num: size_t,
        w: BN_ULONG,
    ) -> BN_ULONG;
    fn bn_mont_n0(n: *const BIGNUM) -> uint64_t;
    fn bn_mont_ctx_set_RR_consttime(
        mont: *mut BN_MONT_CTX,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn bn_reduce_once(
        r: *mut BN_ULONG,
        a: *const BN_ULONG,
        carry: BN_ULONG,
        m: *const BN_ULONG,
        num: size_t,
    ) -> BN_ULONG;
    fn bn_mul_consttime(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        b: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn bn_sqr_consttime(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn bn_mul_small(
        r: *mut BN_ULONG,
        num_r: size_t,
        a: *const BN_ULONG,
        num_a: size_t,
        b: *const BN_ULONG,
        num_b: size_t,
    );
    fn bn_sqr_small(r: *mut BN_ULONG, num_r: size_t, a: *const BN_ULONG, num_a: size_t);
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub union crypto_mutex_st {
    pub alignment: libc::c_double,
    pub padding: [uint8_t; 56],
}
pub type CRYPTO_MUTEX = crypto_mutex_st;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_240_error_is_uint64_t_is_insufficient_precision_for_n0 {
    #[bitfield(
        name = "static_assertion_at_line_240_error_is_uint64_t_is_insufficient_precision_for_n0",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_240_error_is_uint64_t_is_insufficient_precision_for_n0: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_237_error_is_BN_MONT_CTX_N0_LIMBS_value_is_invalid {
    #[bitfield(
        name = "static_assertion_at_line_237_error_is_BN_MONT_CTX_N0_LIMBS_value_is_invalid",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_237_error_is_BN_MONT_CTX_N0_LIMBS_value_is_invalid: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_mont_ctx_init(mut mont: *mut BN_MONT_CTX) {
    OPENSSL_memset(
        mont as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<BN_MONT_CTX>() as libc::c_ulong,
    );
    BN_init(&mut (*mont).RR);
    BN_init(&mut (*mont).N);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_mont_ctx_cleanup(mut mont: *mut BN_MONT_CTX) {
    BN_free(&mut (*mont).RR);
    BN_free(&mut (*mont).N);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_MONT_CTX_new() -> *mut BN_MONT_CTX {
    let mut ret: *mut BN_MONT_CTX = OPENSSL_malloc(
        ::core::mem::size_of::<BN_MONT_CTX>() as libc::c_ulong,
    ) as *mut BN_MONT_CTX;
    if ret.is_null() {
        return 0 as *mut BN_MONT_CTX;
    }
    bn_mont_ctx_init(ret);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_MONT_CTX_free(mut mont: *mut BN_MONT_CTX) {
    if mont.is_null() {
        return;
    }
    bn_mont_ctx_cleanup(mont);
    OPENSSL_free(mont as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_MONT_CTX_copy(
    mut to: *mut BN_MONT_CTX,
    mut from: *const BN_MONT_CTX,
) -> *mut BN_MONT_CTX {
    if to == from as *mut BN_MONT_CTX {
        return to;
    }
    if (BN_copy(&mut (*to).RR, &(*from).RR)).is_null()
        || (BN_copy(&mut (*to).N, &(*from).N)).is_null()
    {
        return 0 as *mut BN_MONT_CTX;
    }
    (*to).n0[0 as libc::c_int as usize] = (*from).n0[0 as libc::c_int as usize];
    (*to).n0[1 as libc::c_int as usize] = (*from).n0[1 as libc::c_int as usize];
    return to;
}
unsafe extern "C" fn bn_mont_ctx_set_N_and_n0(
    mut mont: *mut BN_MONT_CTX,
    mut mod_0: *const BIGNUM,
) -> libc::c_int {
    if BN_is_zero(mod_0) != 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery.c\0"
                as *const u8 as *const libc::c_char,
            204 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if BN_is_odd(mod_0) == 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery.c\0"
                as *const u8 as *const libc::c_char,
            208 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if BN_is_negative(mod_0) != 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery.c\0"
                as *const u8 as *const libc::c_char,
            212 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if bn_fits_in_words(
        mod_0,
        ((8 as libc::c_int * 1024 as libc::c_int) as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    ) == 0
    {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery.c\0"
                as *const u8 as *const libc::c_char,
            216 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (BN_copy(&mut (*mont).N, mod_0)).is_null() {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            4 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery.c\0"
                as *const u8 as *const libc::c_char,
            222 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    bn_set_minimal_width(&mut (*mont).N);
    let mut n0: uint64_t = bn_mont_n0(&mut (*mont).N);
    (*mont).n0[0 as libc::c_int as usize] = n0;
    (*mont).n0[1 as libc::c_int as usize] = 0 as libc::c_int as BN_ULONG;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_MONT_CTX_set(
    mut mont: *mut BN_MONT_CTX,
    mut mod_0: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if bn_mont_ctx_set_N_and_n0(mont, mod_0) == 0 {
        return 0 as libc::c_int;
    }
    let mut new_ctx: *mut BN_CTX = 0 as *mut BN_CTX;
    if ctx.is_null() {
        new_ctx = BN_CTX_new();
        if new_ctx.is_null() {
            return 0 as libc::c_int;
        }
        ctx = new_ctx;
    }
    let mut lgBigR: libc::c_uint = ((*mont).N.width * 64 as libc::c_int) as libc::c_uint;
    BN_zero(&mut (*mont).RR);
    let mut ok: libc::c_int = (BN_set_bit(
        &mut (*mont).RR,
        lgBigR.wrapping_mul(2 as libc::c_int as libc::c_uint) as libc::c_int,
    ) != 0
        && BN_div(
            0 as *mut BIGNUM,
            &mut (*mont).RR,
            &mut (*mont).RR,
            &mut (*mont).N,
            ctx,
        ) != 0 && bn_resize_words(&mut (*mont).RR, (*mont).N.width as size_t) != 0)
        as libc::c_int;
    BN_CTX_free(new_ctx);
    return ok;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_MONT_CTX_new_for_modulus(
    mut mod_0: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> *mut BN_MONT_CTX {
    let mut mont: *mut BN_MONT_CTX = BN_MONT_CTX_new();
    if mont.is_null() || BN_MONT_CTX_set(mont, mod_0, ctx) == 0 {
        BN_MONT_CTX_free(mont);
        return 0 as *mut BN_MONT_CTX;
    }
    return mont;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_MONT_CTX_new_consttime(
    mut mod_0: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> *mut BN_MONT_CTX {
    let mut mont: *mut BN_MONT_CTX = BN_MONT_CTX_new();
    if mont.is_null() || bn_mont_ctx_set_N_and_n0(mont, mod_0) == 0
        || bn_mont_ctx_set_RR_consttime(mont, ctx) == 0
    {
        BN_MONT_CTX_free(mont);
        return 0 as *mut BN_MONT_CTX;
    }
    return mont;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_MONT_CTX_set_locked(
    mut pmont: *mut *mut BN_MONT_CTX,
    mut lock: *mut CRYPTO_MUTEX,
    mut mod_0: *const BIGNUM,
    mut bn_ctx: *mut BN_CTX,
) -> libc::c_int {
    CRYPTO_MUTEX_lock_read(lock);
    let mut ctx: *mut BN_MONT_CTX = *pmont;
    CRYPTO_MUTEX_unlock_read(lock);
    if !ctx.is_null() {
        return 1 as libc::c_int;
    }
    CRYPTO_MUTEX_lock_write(lock);
    if (*pmont).is_null() {
        *pmont = BN_MONT_CTX_new_for_modulus(mod_0, bn_ctx);
    }
    let ok: libc::c_int = (*pmont != 0 as *mut libc::c_void as *mut BN_MONT_CTX)
        as libc::c_int;
    CRYPTO_MUTEX_unlock_write(lock);
    return ok;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_to_montgomery(
    mut ret: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut mont: *const BN_MONT_CTX,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    return BN_mod_mul_montgomery(ret, a, &(*mont).RR, mont, ctx);
}
unsafe extern "C" fn bn_from_montgomery_in_place(
    mut r: *mut BN_ULONG,
    mut num_r: size_t,
    mut a: *mut BN_ULONG,
    mut num_a: size_t,
    mut mont: *const BN_MONT_CTX,
) -> libc::c_int {
    let mut n: *const BN_ULONG = (*mont).N.d;
    let mut num_n: size_t = (*mont).N.width as size_t;
    if num_r != num_n || num_a != 2 as libc::c_int as size_t * num_n {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery.c\0"
                as *const u8 as *const libc::c_char,
            329 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut n0: BN_ULONG = (*mont).n0[0 as libc::c_int as usize];
    let mut carry: BN_ULONG = 0 as libc::c_int as BN_ULONG;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < num_n {
        let mut v: BN_ULONG = bn_mul_add_words(
            a.offset(i as isize),
            n,
            num_n,
            *a.offset(i as isize) * n0,
        );
        v = v
            .wrapping_add(carry.wrapping_add(*a.offset(i.wrapping_add(num_n) as isize)));
        carry
            |= (v != *a.offset(i.wrapping_add(num_n) as isize)) as libc::c_int
                as BN_ULONG;
        carry
            &= (v <= *a.offset(i.wrapping_add(num_n) as isize)) as libc::c_int
                as BN_ULONG;
        *a.offset(i.wrapping_add(num_n) as isize) = v;
        i = i.wrapping_add(1);
        i;
    }
    a = a.offset(num_n as isize);
    bn_reduce_once(r, a, carry, n, num_n);
    return 1 as libc::c_int;
}
unsafe extern "C" fn BN_from_montgomery_word(
    mut ret: *mut BIGNUM,
    mut r: *mut BIGNUM,
    mut mont: *const BN_MONT_CTX,
) -> libc::c_int {
    if (*r).neg != 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery.c\0"
                as *const u8 as *const libc::c_char,
            358 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut n: *const BIGNUM = &(*mont).N;
    if (*n).width == 0 as libc::c_int {
        (*ret).width = 0 as libc::c_int;
        return 1 as libc::c_int;
    }
    let mut max: libc::c_int = 2 as libc::c_int * (*n).width;
    if bn_resize_words(r, max as size_t) == 0
        || bn_wexpand(ret, (*n).width as size_t) == 0
    {
        return 0 as libc::c_int;
    }
    (*ret).width = (*n).width;
    (*ret).neg = 0 as libc::c_int;
    return bn_from_montgomery_in_place(
        (*ret).d,
        (*ret).width as size_t,
        (*r).d,
        (*r).width as size_t,
        mont,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_from_montgomery(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut mont: *const BN_MONT_CTX,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut t: *mut BIGNUM = 0 as *mut BIGNUM;
    BN_CTX_start(ctx);
    t = BN_CTX_get(ctx);
    if !(t.is_null() || (BN_copy(t, a)).is_null()) {
        ret = BN_from_montgomery_word(r, t, mont);
    }
    BN_CTX_end(ctx);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_one_to_montgomery(
    mut r: *mut BIGNUM,
    mut mont: *const BN_MONT_CTX,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut n: *const BIGNUM = &(*mont).N;
    if (*n).width > 0 as libc::c_int
        && *((*n).d).offset(((*n).width - 1 as libc::c_int) as isize)
            >> 64 as libc::c_int - 1 as libc::c_int != 0 as libc::c_int as BN_ULONG
    {
        if bn_wexpand(r, (*n).width as size_t) == 0 {
            return 0 as libc::c_int;
        }
        *((*r).d)
            .offset(
                0 as libc::c_int as isize,
            ) = (0 as libc::c_int as BN_ULONG)
            .wrapping_sub(*((*n).d).offset(0 as libc::c_int as isize));
        let mut i: libc::c_int = 1 as libc::c_int;
        while i < (*n).width {
            *((*r).d).offset(i as isize) = !*((*n).d).offset(i as isize);
            i += 1;
            i;
        }
        (*r).width = (*n).width;
        (*r).neg = 0 as libc::c_int;
        return 1 as libc::c_int;
    }
    return BN_from_montgomery(r, &(*mont).RR, mont, ctx);
}
unsafe extern "C" fn bn_mod_mul_montgomery_fallback(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
    mut mont: *const BN_MONT_CTX,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ret: libc::c_int = 0 as libc::c_int;
    BN_CTX_start(ctx);
    let mut tmp: *mut BIGNUM = BN_CTX_get(ctx);
    if !tmp.is_null() {
        if a == b {
            if bn_sqr_consttime(tmp, a, ctx) == 0 {
                current_block = 9206253704597994402;
            } else {
                current_block = 7815301370352969686;
            }
        } else if bn_mul_consttime(tmp, a, b, ctx) == 0 {
            current_block = 9206253704597994402;
        } else {
            current_block = 7815301370352969686;
        }
        match current_block {
            9206253704597994402 => {}
            _ => {
                if !(BN_from_montgomery_word(r, tmp, mont) == 0) {
                    ret = 1 as libc::c_int;
                }
            }
        }
    }
    BN_CTX_end(ctx);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_mod_mul_montgomery(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
    mut mont: *const BN_MONT_CTX,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if (*a).neg != 0 || (*b).neg != 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/montgomery.c\0"
                as *const u8 as *const libc::c_char,
            532 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return bn_mod_mul_montgomery_fallback(r, a, b, mont, ctx);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_less_than_montgomery_R(
    mut bn: *const BIGNUM,
    mut mont: *const BN_MONT_CTX,
) -> libc::c_int {
    return (BN_is_negative(bn) == 0
        && bn_fits_in_words(bn, (*mont).N.width as size_t) != 0) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_to_montgomery_small(
    mut r: *mut BN_ULONG,
    mut a: *const BN_ULONG,
    mut num: size_t,
    mut mont: *const BN_MONT_CTX,
) {
    bn_mod_mul_montgomery_small(r, a, (*mont).RR.d, num, mont);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_from_montgomery_small(
    mut r: *mut BN_ULONG,
    mut num_r: size_t,
    mut a: *const BN_ULONG,
    mut num_a: size_t,
    mut mont: *const BN_MONT_CTX,
) {
    if num_r != (*mont).N.width as size_t || num_r > 9 as libc::c_int as size_t
        || num_a > 2 as libc::c_int as size_t * num_r
    {
        abort();
    }
    let mut tmp: [BN_ULONG; 18] = [
        0 as libc::c_int as BN_ULONG,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    OPENSSL_memcpy(
        tmp.as_mut_ptr() as *mut libc::c_void,
        a as *const libc::c_void,
        num_a.wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    );
    if bn_from_montgomery_in_place(
        r,
        num_r,
        tmp.as_mut_ptr(),
        2 as libc::c_int as size_t * num_r,
        mont,
    ) == 0
    {
        abort();
    }
    OPENSSL_cleanse(
        tmp.as_mut_ptr() as *mut libc::c_void,
        (2 as libc::c_int as size_t * num_r)
            .wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_mod_mul_montgomery_small(
    mut r: *mut BN_ULONG,
    mut a: *const BN_ULONG,
    mut b: *const BN_ULONG,
    mut num: size_t,
    mut mont: *const BN_MONT_CTX,
) {
    if num != (*mont).N.width as size_t || num > 9 as libc::c_int as size_t {
        abort();
    }
    let mut tmp: [BN_ULONG; 18] = [0; 18];
    if a == b {
        bn_sqr_small(tmp.as_mut_ptr(), 2 as libc::c_int as size_t * num, a, num);
    } else {
        bn_mul_small(tmp.as_mut_ptr(), 2 as libc::c_int as size_t * num, a, num, b, num);
    }
    if bn_from_montgomery_in_place(
        r,
        num,
        tmp.as_mut_ptr(),
        2 as libc::c_int as size_t * num,
        mont,
    ) == 0
    {
        abort();
    }
    OPENSSL_cleanse(
        tmp.as_mut_ptr() as *mut libc::c_void,
        (2 as libc::c_int as size_t * num)
            .wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    );
}
