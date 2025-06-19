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
    pub type bn_blinding_st;
    pub type stack_st_void;
    pub type rsassa_pss_params_st;
    fn BN_new() -> *mut BIGNUM;
    fn BN_free(bn: *mut BIGNUM);
    fn BN_dup(src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_copy(dest: *mut BIGNUM, src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_value_one() -> *const BIGNUM;
    fn BN_num_bits(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_num_bytes(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_set_word(bn: *mut BIGNUM, value: BN_ULONG) -> libc::c_int;
    fn BN_bin2bn(in_0: *const uint8_t, len: size_t, ret: *mut BIGNUM) -> *mut BIGNUM;
    fn BN_bn2bin_padded(
        out: *mut uint8_t,
        len: size_t,
        in_0: *const BIGNUM,
    ) -> libc::c_int;
    fn BN_CTX_new() -> *mut BN_CTX;
    fn BN_CTX_free(ctx: *mut BN_CTX);
    fn BN_CTX_start(ctx: *mut BN_CTX);
    fn BN_CTX_get(ctx: *mut BN_CTX) -> *mut BIGNUM;
    fn BN_CTX_end(ctx: *mut BN_CTX);
    fn BN_add_word(a: *mut BIGNUM, w: BN_ULONG) -> libc::c_int;
    fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_ucmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_equal_consttime(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_is_word(bn: *const BIGNUM, w: BN_ULONG) -> libc::c_int;
    fn BN_is_pow2(a: *const BIGNUM) -> libc::c_int;
    fn BN_lshift(r: *mut BIGNUM, a: *const BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_rshift(r: *mut BIGNUM, a: *const BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_set_bit(a: *mut BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_is_bit_set(a: *const BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_rand(
        rnd: *mut BIGNUM,
        bits: libc::c_int,
        top: libc::c_int,
        bottom: libc::c_int,
    ) -> libc::c_int;
    fn BN_GENCB_call(
        callback: *mut BN_GENCB,
        event: libc::c_int,
        n: libc::c_int,
    ) -> libc::c_int;
    fn BN_primality_test(
        is_probably_prime: *mut libc::c_int,
        candidate: *const BIGNUM,
        checks: libc::c_int,
        ctx: *mut BN_CTX,
        do_trial_division: libc::c_int,
        cb: *mut BN_GENCB,
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
    fn BN_mod_exp_mont_consttime_x2(
        rr1: *mut BIGNUM,
        a1: *const BIGNUM,
        p1: *const BIGNUM,
        m1: *const BIGNUM,
        in_mont1: *const BN_MONT_CTX,
        rr2: *mut BIGNUM,
        a2: *const BIGNUM,
        p2: *const BIGNUM,
        m2: *const BIGNUM,
        in_mont2: *const BN_MONT_CTX,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_BLINDING_new() -> *mut BN_BLINDING;
    fn BN_BLINDING_free(b: *mut BN_BLINDING);
    fn BN_BLINDING_invalidate(b: *mut BN_BLINDING);
    fn BN_BLINDING_convert(
        n: *mut BIGNUM,
        b: *mut BN_BLINDING,
        e: *const BIGNUM,
        mont_ctx: *const BN_MONT_CTX,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_BLINDING_invert(
        n: *mut BIGNUM,
        b: *const BN_BLINDING,
        mont_ctx: *mut BN_MONT_CTX,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn RSA_padding_add_PKCS1_type_1(
        to: *mut uint8_t,
        to_len: size_t,
        from: *const uint8_t,
        from_len: size_t,
    ) -> libc::c_int;
    fn RSA_padding_check_PKCS1_type_1(
        out: *mut uint8_t,
        out_len: *mut size_t,
        max_out: size_t,
        from: *const uint8_t,
        from_len: size_t,
    ) -> libc::c_int;
    fn RSA_padding_add_none(
        to: *mut uint8_t,
        to_len: size_t,
        from: *const uint8_t,
        from_len: size_t,
    ) -> libc::c_int;
    fn rsa_private_transform_no_self_test(
        rsa: *mut RSA,
        out: *mut uint8_t,
        in_0: *const uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn is_public_component_of_rsa_key_good(key: *const RSA) -> libc::c_int;
    fn ERR_peek_error() -> uint32_t;
    fn ERR_clear_error();
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_calloc(num: size_t, size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn RSA_new() -> *mut RSA;
    fn RSA_free(rsa: *mut RSA);
    fn RSA_size(rsa: *const RSA) -> libc::c_uint;
    fn RSA_check_key(rsa: *const RSA) -> libc::c_int;
    fn RSA_check_fips(key: *mut RSA) -> libc::c_int;
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
    fn memchr(
        _: *const libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn CRYPTO_once(
        once: *mut CRYPTO_once_t,
        init: Option::<unsafe extern "C" fn() -> ()>,
    );
    fn CRYPTO_MUTEX_lock_read(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_lock_write(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_unlock_read(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_unlock_write(lock: *mut CRYPTO_MUTEX);
    fn bn_set_minimal_width(bn: *mut BIGNUM);
    fn bn_resize_words(bn: *mut BIGNUM, words: size_t) -> libc::c_int;
    fn bn_set_words(bn: *mut BIGNUM, words: *const BN_ULONG, num: size_t) -> libc::c_int;
    fn bn_assert_fits_in_bytes(bn: *const BIGNUM, num: size_t);
    fn bn_less_than_montgomery_R(
        bn: *const BIGNUM,
        mont: *const BN_MONT_CTX,
    ) -> libc::c_int;
    fn bn_odd_number_is_obviously_composite(bn: *const BIGNUM) -> libc::c_int;
    fn bn_uadd_consttime(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        b: *const BIGNUM,
    ) -> libc::c_int;
    fn bn_usub_consttime(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        b: *const BIGNUM,
    ) -> libc::c_int;
    fn bn_abs_sub_consttime(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        b: *const BIGNUM,
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
    fn bn_is_relatively_prime(
        out_relatively_prime: *mut libc::c_int,
        x: *const BIGNUM,
        y: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn bn_lcm_consttime(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        b: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn bn_mod_sub_consttime(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        b: *const BIGNUM,
        m: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn bn_mod_inverse_consttime(
        r: *mut BIGNUM,
        out_no_inverse: *mut libc::c_int,
        a: *const BIGNUM,
        n: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn bn_mod_inverse_secret_prime(
        out: *mut BIGNUM,
        a: *const BIGNUM,
        p: *const BIGNUM,
        ctx: *mut BN_CTX,
        mont_p: *const BN_MONT_CTX,
    ) -> libc::c_int;
    fn BN_MONT_CTX_set_locked(
        pmont: *mut *mut BN_MONT_CTX,
        lock: *mut CRYPTO_MUTEX,
        mod_0: *const BIGNUM,
        bn_ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn CRYPTO_get_fork_generation() -> uint64_t;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type pthread_once_t = libc::c_int;
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
pub struct rsa_meth_st {
    pub app_data: *mut libc::c_void,
    pub init: Option::<unsafe extern "C" fn(*mut RSA) -> libc::c_int>,
    pub finish: Option::<unsafe extern "C" fn(*mut RSA) -> libc::c_int>,
    pub size: Option::<unsafe extern "C" fn(*const RSA) -> size_t>,
    pub sign: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            libc::c_uint,
            *mut uint8_t,
            *mut libc::c_uint,
            *const RSA,
        ) -> libc::c_int,
    >,
    pub sign_raw: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            *mut uint8_t,
            *mut RSA,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub verify_raw: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            *mut uint8_t,
            *mut RSA,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub decrypt: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            *mut uint8_t,
            *mut RSA,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub encrypt: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            *mut uint8_t,
            *mut RSA,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub private_transform: Option::<
        unsafe extern "C" fn(
            *mut RSA,
            *mut uint8_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub flags: libc::c_int,
}
pub type RSA = rsa_st;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct rsa_st {
    pub meth: *const RSA_METHOD,
    pub n: *mut BIGNUM,
    pub e: *mut BIGNUM,
    pub d: *mut BIGNUM,
    pub p: *mut BIGNUM,
    pub q: *mut BIGNUM,
    pub dmp1: *mut BIGNUM,
    pub dmq1: *mut BIGNUM,
    pub iqmp: *mut BIGNUM,
    pub pss: *mut RSASSA_PSS_PARAMS,
    pub ex_data: CRYPTO_EX_DATA,
    pub references: CRYPTO_refcount_t,
    pub flags: libc::c_int,
    pub lock: CRYPTO_MUTEX,
    pub mont_n: *mut BN_MONT_CTX,
    pub mont_p: *mut BN_MONT_CTX,
    pub mont_q: *mut BN_MONT_CTX,
    pub d_fixed: *mut BIGNUM,
    pub dmp1_fixed: *mut BIGNUM,
    pub dmq1_fixed: *mut BIGNUM,
    pub iqmp_mont: *mut BIGNUM,
    pub num_blindings: size_t,
    pub blindings: *mut *mut BN_BLINDING,
    pub blindings_inuse: *mut libc::c_uchar,
    pub blinding_fork_generation: uint64_t,
    #[bitfield(name = "private_key_frozen", ty = "libc::c_uint", bits = "0..=0")]
    pub private_key_frozen: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
pub type BN_BLINDING = bn_blinding_st;
pub type CRYPTO_MUTEX = crypto_mutex_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub union crypto_mutex_st {
    pub alignment: libc::c_double,
    pub padding: [uint8_t; 56],
}
pub type CRYPTO_refcount_t = uint32_t;
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
pub type RSASSA_PSS_PARAMS = rsassa_pss_params_st;
pub type RSA_METHOD = rsa_meth_st;
pub type CRYPTO_once_t = pthread_once_t;
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
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_291_error_is_MAX_BLINDINGS_PER_RSA_too_large {
    #[bitfield(
        name = "static_assertion_at_line_291_error_is_MAX_BLINDINGS_PER_RSA_too_large",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_291_error_is_MAX_BLINDINGS_PER_RSA_too_large: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[inline]
unsafe extern "C" fn ERR_GET_LIB(mut packed_error: uint32_t) -> libc::c_int {
    return (packed_error >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as libc::c_int;
}
#[inline]
unsafe extern "C" fn ERR_GET_REASON(mut packed_error: uint32_t) -> libc::c_int {
    return (packed_error & 0xfff as libc::c_int as uint32_t) as libc::c_int;
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
unsafe extern "C" fn OPENSSL_memchr(
    mut s: *const libc::c_void,
    mut c: libc::c_int,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return 0 as *mut libc::c_void;
    }
    return memchr(s, c, n);
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
unsafe extern "C" fn boringssl_ensure_rsa_self_test() {}
#[inline]
unsafe extern "C" fn bn_secret(mut bn: *mut BIGNUM) {}
#[inline]
unsafe extern "C" fn bn_declassify(mut bn: *mut BIGNUM) {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_update_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_lock_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_unlock_state() {}
unsafe extern "C" fn ensure_fixed_copy(
    mut out: *mut *mut BIGNUM,
    mut in_0: *const BIGNUM,
    mut width: libc::c_int,
) -> libc::c_int {
    if !(*out).is_null() {
        return 1 as libc::c_int;
    }
    let mut copy: *mut BIGNUM = BN_dup(in_0);
    if copy.is_null() || bn_resize_words(copy, width as size_t) == 0 {
        BN_free(copy);
        return 0 as libc::c_int;
    }
    *out = copy;
    bn_secret(copy);
    return 1 as libc::c_int;
}
unsafe extern "C" fn freeze_private_key(
    mut rsa: *mut RSA,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut n_fixed: *const BIGNUM = 0 as *const BIGNUM;
    let mut current_block: u64;
    CRYPTO_MUTEX_lock_read(&mut (*rsa).lock);
    let mut frozen: libc::c_int = (*rsa).private_key_frozen() as libc::c_int;
    CRYPTO_MUTEX_unlock_read(&mut (*rsa).lock);
    if frozen != 0 {
        return 1 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    CRYPTO_MUTEX_lock_write(&mut (*rsa).lock);
    if (*rsa).private_key_frozen() != 0 {
        ret = 1 as libc::c_int;
    } else {
        if ((*rsa).mont_n).is_null() {
            (*rsa).mont_n = BN_MONT_CTX_new_for_modulus((*rsa).n, ctx);
            if ((*rsa).mont_n).is_null() {
                current_block = 14098799490698092701;
            } else {
                current_block = 3640593987805443782;
            }
        } else {
            current_block = 3640593987805443782;
        }
        match current_block {
            14098799490698092701 => {}
            _ => {
                n_fixed = &mut (*(*rsa).mont_n).N;
                if !(!((*rsa).d).is_null()
                    && ensure_fixed_copy(&mut (*rsa).d_fixed, (*rsa).d, (*n_fixed).width)
                        == 0)
                {
                    if !((*rsa).e).is_null() && !((*rsa).p).is_null()
                        && !((*rsa).q).is_null()
                    {
                        if ((*rsa).mont_p).is_null() {
                            (*rsa).mont_p = BN_MONT_CTX_new_consttime((*rsa).p, ctx);
                            if ((*rsa).mont_p).is_null() {
                                current_block = 14098799490698092701;
                            } else {
                                current_block = 17407779659766490442;
                            }
                        } else {
                            current_block = 17407779659766490442;
                        }
                        match current_block {
                            14098799490698092701 => {}
                            _ => {
                                let mut p_fixed: *const BIGNUM = &mut (*(*rsa).mont_p).N;
                                if ((*rsa).mont_q).is_null() {
                                    (*rsa).mont_q = BN_MONT_CTX_new_consttime((*rsa).q, ctx);
                                    if ((*rsa).mont_q).is_null() {
                                        current_block = 14098799490698092701;
                                    } else {
                                        current_block = 7175849428784450219;
                                    }
                                } else {
                                    current_block = 7175849428784450219;
                                }
                                match current_block {
                                    14098799490698092701 => {}
                                    _ => {
                                        let mut q_fixed: *const BIGNUM = &mut (*(*rsa).mont_q).N;
                                        if !((*rsa).dmp1).is_null() && !((*rsa).dmq1).is_null() {
                                            if ((*rsa).iqmp).is_null() {
                                                let mut iqmp: *mut BIGNUM = BN_new();
                                                if iqmp.is_null()
                                                    || bn_mod_inverse_secret_prime(
                                                        iqmp,
                                                        (*rsa).q,
                                                        (*rsa).p,
                                                        ctx,
                                                        (*rsa).mont_p,
                                                    ) == 0
                                                {
                                                    BN_free(iqmp);
                                                    current_block = 14098799490698092701;
                                                } else {
                                                    (*rsa).iqmp = iqmp;
                                                    current_block = 2719512138335094285;
                                                }
                                            } else {
                                                current_block = 2719512138335094285;
                                            }
                                            match current_block {
                                                14098799490698092701 => {}
                                                _ => {
                                                    if ensure_fixed_copy(
                                                        &mut (*rsa).dmp1_fixed,
                                                        (*rsa).dmp1,
                                                        (*p_fixed).width,
                                                    ) == 0
                                                        || ensure_fixed_copy(
                                                            &mut (*rsa).dmq1_fixed,
                                                            (*rsa).dmq1,
                                                            (*q_fixed).width,
                                                        ) == 0
                                                    {
                                                        current_block = 14098799490698092701;
                                                    } else if ((*rsa).iqmp_mont).is_null() {
                                                        let mut iqmp_mont: *mut BIGNUM = BN_new();
                                                        if iqmp_mont.is_null()
                                                            || BN_to_montgomery(
                                                                iqmp_mont,
                                                                (*rsa).iqmp,
                                                                (*rsa).mont_p,
                                                                ctx,
                                                            ) == 0
                                                        {
                                                            BN_free(iqmp_mont);
                                                            current_block = 14098799490698092701;
                                                        } else {
                                                            (*rsa).iqmp_mont = iqmp_mont;
                                                            bn_secret((*rsa).iqmp_mont);
                                                            current_block = 1538046216550696469;
                                                        }
                                                    } else {
                                                        current_block = 1538046216550696469;
                                                    }
                                                }
                                            }
                                        } else {
                                            current_block = 1538046216550696469;
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        current_block = 1538046216550696469;
                    }
                    match current_block {
                        14098799490698092701 => {}
                        _ => {
                            (*rsa)
                                .set_private_key_frozen(1 as libc::c_int as libc::c_uint);
                            ret = 1 as libc::c_int;
                        }
                    }
                }
            }
        }
    }
    CRYPTO_MUTEX_unlock_write(&mut (*rsa).lock);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn rsa_invalidate_key(mut rsa: *mut RSA) {
    (*rsa).set_private_key_frozen(0 as libc::c_int as libc::c_uint);
    BN_MONT_CTX_free((*rsa).mont_n);
    (*rsa).mont_n = 0 as *mut BN_MONT_CTX;
    BN_MONT_CTX_free((*rsa).mont_p);
    (*rsa).mont_p = 0 as *mut BN_MONT_CTX;
    BN_MONT_CTX_free((*rsa).mont_q);
    (*rsa).mont_q = 0 as *mut BN_MONT_CTX;
    BN_free((*rsa).d_fixed);
    (*rsa).d_fixed = 0 as *mut BIGNUM;
    BN_free((*rsa).dmp1_fixed);
    (*rsa).dmp1_fixed = 0 as *mut BIGNUM;
    BN_free((*rsa).dmq1_fixed);
    (*rsa).dmq1_fixed = 0 as *mut BIGNUM;
    BN_free((*rsa).iqmp_mont);
    (*rsa).iqmp_mont = 0 as *mut BIGNUM;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < (*rsa).num_blindings {
        BN_BLINDING_free(*((*rsa).blindings).offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
    OPENSSL_free((*rsa).blindings as *mut libc::c_void);
    (*rsa).blindings = 0 as *mut *mut BN_BLINDING;
    (*rsa).num_blindings = 0 as libc::c_int as size_t;
    OPENSSL_free((*rsa).blindings_inuse as *mut libc::c_void);
    (*rsa).blindings_inuse = 0 as *mut libc::c_uchar;
    (*rsa).blinding_fork_generation = 0 as libc::c_int as uint64_t;
}
#[no_mangle]
pub unsafe extern "C" fn rsa_default_size(mut rsa: *const RSA) -> size_t {
    return BN_num_bytes((*rsa).n) as size_t;
}
unsafe extern "C" fn rsa_blinding_get(
    mut rsa: *mut RSA,
    mut index_used: *mut size_t,
    mut ctx: *mut BN_CTX,
) -> *mut BN_BLINDING {
    let mut new_num_blindings: size_t = 0;
    let mut new_blindings: *mut *mut BN_BLINDING = 0 as *mut *mut BN_BLINDING;
    let mut new_blindings_inuse: *mut uint8_t = 0 as *mut uint8_t;
    let mut current_block: u64;
    if !ctx.is_null() {} else {
        __assert_fail(
            b"ctx != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                as *const u8 as *const libc::c_char,
            252 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 57],
                &[libc::c_char; 57],
            >(b"BN_BLINDING *rsa_blinding_get(RSA *, size_t *, BN_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_10965: {
        if !ctx.is_null() {} else {
            __assert_fail(
                b"ctx != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                    as *const u8 as *const libc::c_char,
                252 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 57],
                    &[libc::c_char; 57],
                >(b"BN_BLINDING *rsa_blinding_get(RSA *, size_t *, BN_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    if !((*rsa).mont_n).is_null() {} else {
        __assert_fail(
            b"rsa->mont_n != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                as *const u8 as *const libc::c_char,
            253 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 57],
                &[libc::c_char; 57],
            >(b"BN_BLINDING *rsa_blinding_get(RSA *, size_t *, BN_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_10918: {
        if !((*rsa).mont_n).is_null() {} else {
            __assert_fail(
                b"rsa->mont_n != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                    as *const u8 as *const libc::c_char,
                253 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 57],
                    &[libc::c_char; 57],
                >(b"BN_BLINDING *rsa_blinding_get(RSA *, size_t *, BN_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut ret: *mut BN_BLINDING = 0 as *mut BN_BLINDING;
    let fork_generation: uint64_t = CRYPTO_get_fork_generation();
    CRYPTO_MUTEX_lock_write(&mut (*rsa).lock);
    if (*rsa).blinding_fork_generation != fork_generation {
        let mut i: size_t = 0 as libc::c_int as size_t;
        while i < (*rsa).num_blindings {
            if *((*rsa).blindings_inuse).offset(i as isize) as libc::c_int
                == 0 as libc::c_int
            {} else {
                __assert_fail(
                    b"rsa->blindings_inuse[i] == 0\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                        as *const u8 as *const libc::c_char,
                    265 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 57],
                        &[libc::c_char; 57],
                    >(b"BN_BLINDING *rsa_blinding_get(RSA *, size_t *, BN_CTX *)\0"))
                        .as_ptr(),
                );
            }
            'c_10847: {
                if *((*rsa).blindings_inuse).offset(i as isize) as libc::c_int
                    == 0 as libc::c_int
                {} else {
                    __assert_fail(
                        b"rsa->blindings_inuse[i] == 0\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                            as *const u8 as *const libc::c_char,
                        265 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 57],
                            &[libc::c_char; 57],
                        >(b"BN_BLINDING *rsa_blinding_get(RSA *, size_t *, BN_CTX *)\0"))
                            .as_ptr(),
                    );
                }
            };
            BN_BLINDING_invalidate(*((*rsa).blindings).offset(i as isize));
            i = i.wrapping_add(1);
            i;
        }
        (*rsa).blinding_fork_generation = fork_generation;
    }
    let free_inuse_flag: *mut uint8_t = OPENSSL_memchr(
        (*rsa).blindings_inuse as *const libc::c_void,
        0 as libc::c_int,
        (*rsa).num_blindings,
    ) as *mut uint8_t;
    if !free_inuse_flag.is_null() {
        *free_inuse_flag = 1 as libc::c_int as uint8_t;
        *index_used = free_inuse_flag.offset_from((*rsa).blindings_inuse) as libc::c_long
            as size_t;
        ret = *((*rsa).blindings).offset(*index_used as isize);
    } else if (*rsa).num_blindings >= 1024 as libc::c_int as size_t {
        *index_used = 1024 as libc::c_int as size_t;
        ret = BN_BLINDING_new();
    } else {
        new_num_blindings = (*rsa).num_blindings * 2 as libc::c_int as size_t;
        if new_num_blindings == 0 as libc::c_int as size_t {
            new_num_blindings = 1 as libc::c_int as size_t;
        }
        if new_num_blindings > 1024 as libc::c_int as size_t {
            new_num_blindings = 1024 as libc::c_int as size_t;
        }
        if new_num_blindings > (*rsa).num_blindings {} else {
            __assert_fail(
                b"new_num_blindings > rsa->num_blindings\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                    as *const u8 as *const libc::c_char,
                300 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 57],
                    &[libc::c_char; 57],
                >(b"BN_BLINDING *rsa_blinding_get(RSA *, size_t *, BN_CTX *)\0"))
                    .as_ptr(),
            );
        }
        'c_10630: {
            if new_num_blindings > (*rsa).num_blindings {} else {
                __assert_fail(
                    b"new_num_blindings > rsa->num_blindings\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                        as *const u8 as *const libc::c_char,
                    300 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 57],
                        &[libc::c_char; 57],
                    >(b"BN_BLINDING *rsa_blinding_get(RSA *, size_t *, BN_CTX *)\0"))
                        .as_ptr(),
                );
            }
        };
        new_blindings = OPENSSL_calloc(
            new_num_blindings,
            ::core::mem::size_of::<*mut BN_BLINDING>() as libc::c_ulong,
        ) as *mut *mut BN_BLINDING;
        new_blindings_inuse = OPENSSL_malloc(new_num_blindings) as *mut uint8_t;
        if new_blindings.is_null() || new_blindings_inuse.is_null() {
            current_block = 1087621548514772499;
        } else {
            OPENSSL_memcpy(
                new_blindings as *mut libc::c_void,
                (*rsa).blindings as *const libc::c_void,
                (::core::mem::size_of::<*mut BN_BLINDING>() as libc::c_ulong)
                    .wrapping_mul((*rsa).num_blindings),
            );
            OPENSSL_memcpy(
                new_blindings_inuse as *mut libc::c_void,
                (*rsa).blindings_inuse as *const libc::c_void,
                (*rsa).num_blindings,
            );
            let mut i_0: size_t = (*rsa).num_blindings;
            loop {
                if !(i_0 < new_num_blindings) {
                    current_block = 3275366147856559585;
                    break;
                }
                let ref mut fresh0 = *new_blindings.offset(i_0 as isize);
                *fresh0 = BN_BLINDING_new();
                if (*new_blindings.offset(i_0 as isize)).is_null() {
                    let mut j: size_t = (*rsa).num_blindings;
                    while j < i_0 {
                        BN_BLINDING_free(*new_blindings.offset(j as isize));
                        j = j.wrapping_add(1);
                        j;
                    }
                    current_block = 1087621548514772499;
                    break;
                } else {
                    i_0 = i_0.wrapping_add(1);
                    i_0;
                }
            }
            match current_block {
                1087621548514772499 => {}
                _ => {
                    memset(
                        &mut *new_blindings_inuse.offset((*rsa).num_blindings as isize)
                            as *mut uint8_t as *mut libc::c_void,
                        0 as libc::c_int,
                        new_num_blindings.wrapping_sub((*rsa).num_blindings),
                    );
                    *new_blindings_inuse
                        .offset(
                            (*rsa).num_blindings as isize,
                        ) = 1 as libc::c_int as uint8_t;
                    *index_used = (*rsa).num_blindings;
                    if *index_used != 1024 as libc::c_int as size_t {} else {
                        __assert_fail(
                            b"*index_used != MAX_BLINDINGS_PER_RSA\0" as *const u8
                                as *const libc::c_char,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                                as *const u8 as *const libc::c_char,
                            327 as libc::c_int as libc::c_uint,
                            (*::core::mem::transmute::<
                                &[u8; 57],
                                &[libc::c_char; 57],
                            >(
                                b"BN_BLINDING *rsa_blinding_get(RSA *, size_t *, BN_CTX *)\0",
                            ))
                                .as_ptr(),
                        );
                    }
                    'c_10405: {
                        if *index_used != 1024 as libc::c_int as size_t {} else {
                            __assert_fail(
                                b"*index_used != MAX_BLINDINGS_PER_RSA\0" as *const u8
                                    as *const libc::c_char,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                                    as *const u8 as *const libc::c_char,
                                327 as libc::c_int as libc::c_uint,
                                (*::core::mem::transmute::<
                                    &[u8; 57],
                                    &[libc::c_char; 57],
                                >(
                                    b"BN_BLINDING *rsa_blinding_get(RSA *, size_t *, BN_CTX *)\0",
                                ))
                                    .as_ptr(),
                            );
                        }
                    };
                    ret = *new_blindings.offset((*rsa).num_blindings as isize);
                    OPENSSL_free((*rsa).blindings as *mut libc::c_void);
                    (*rsa).blindings = new_blindings;
                    OPENSSL_free((*rsa).blindings_inuse as *mut libc::c_void);
                    (*rsa).blindings_inuse = new_blindings_inuse;
                    (*rsa).num_blindings = new_num_blindings;
                    current_block = 396793461540351618;
                }
            }
        }
        match current_block {
            396793461540351618 => {}
            _ => {
                OPENSSL_free(new_blindings_inuse as *mut libc::c_void);
                OPENSSL_free(new_blindings as *mut libc::c_void);
            }
        }
    }
    CRYPTO_MUTEX_unlock_write(&mut (*rsa).lock);
    return ret;
}
unsafe extern "C" fn rsa_blinding_release(
    mut rsa: *mut RSA,
    mut blinding: *mut BN_BLINDING,
    mut blinding_index: size_t,
) {
    if blinding_index == 1024 as libc::c_int as size_t {
        BN_BLINDING_free(blinding);
        return;
    }
    CRYPTO_MUTEX_lock_write(&mut (*rsa).lock);
    *((*rsa).blindings_inuse)
        .offset(blinding_index as isize) = 0 as libc::c_int as libc::c_uchar;
    CRYPTO_MUTEX_unlock_write(&mut (*rsa).lock);
}
#[no_mangle]
pub unsafe extern "C" fn rsa_default_sign_raw(
    mut rsa: *mut RSA,
    mut out_len: *mut size_t,
    mut out: *mut uint8_t,
    mut max_out: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut padding: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let rsa_size: libc::c_uint = RSA_size(rsa);
    let mut buf: *mut uint8_t = 0 as *mut uint8_t;
    let mut i: libc::c_int = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    if max_out < rsa_size as size_t {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            135 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                as *const u8 as *const libc::c_char,
            371 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    buf = OPENSSL_malloc(rsa_size as size_t) as *mut uint8_t;
    if !buf.is_null() {
        match padding {
            1 => {
                i = RSA_padding_add_PKCS1_type_1(buf, rsa_size as size_t, in_0, in_len);
                current_block = 11650488183268122163;
            }
            3 => {
                i = RSA_padding_add_none(buf, rsa_size as size_t, in_0, in_len);
                current_block = 11650488183268122163;
            }
            _ => {
                ERR_put_error(
                    4 as libc::c_int,
                    0 as libc::c_int,
                    143 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                        as *const u8 as *const libc::c_char,
                    388 as libc::c_int as libc::c_uint,
                );
                current_block = 5364195455027207028;
            }
        }
        match current_block {
            5364195455027207028 => {}
            _ => {
                if !(i <= 0 as libc::c_int) {
                    if !(rsa_private_transform_no_self_test(
                        rsa,
                        out,
                        buf,
                        rsa_size as size_t,
                    ) == 0)
                    {
                        *out_len = rsa_size as size_t;
                        ret = 1 as libc::c_int;
                    }
                }
            }
        }
    }
    OPENSSL_free(buf as *mut libc::c_void);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn rsa_verify_raw_no_self_test(
    mut rsa: *mut RSA,
    mut out_len: *mut size_t,
    mut out: *mut uint8_t,
    mut max_out: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut padding: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    if !((*rsa).meth).is_null() && ((*(*rsa).meth).verify_raw).is_some() {
        let mut ret: libc::c_int = ((*(*rsa).meth).verify_raw)
            .expect(
                "non-null function pointer",
            )(max_out as libc::c_int, in_0, out, rsa, padding);
        if ret < 0 as libc::c_int {
            *out_len = 0 as libc::c_int as size_t;
            return 0 as libc::c_int;
        }
        *out_len = ret as size_t;
        return 1 as libc::c_int;
    }
    if ((*rsa).n).is_null() || ((*rsa).e).is_null() {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            144 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                as *const u8 as *const libc::c_char,
            434 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if is_public_component_of_rsa_key_good(rsa) == 0 {
        return 0 as libc::c_int;
    }
    let rsa_size: libc::c_uint = RSA_size(rsa);
    let mut f: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut result: *mut BIGNUM = 0 as *mut BIGNUM;
    if max_out < rsa_size as size_t {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            135 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                as *const u8 as *const libc::c_char,
            446 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if in_len != rsa_size as size_t {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            112 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                as *const u8 as *const libc::c_char,
            451 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ctx: *mut BN_CTX = BN_CTX_new();
    if ctx.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret_0: libc::c_int = 0 as libc::c_int;
    let mut buf: *mut uint8_t = 0 as *mut uint8_t;
    BN_CTX_start(ctx);
    f = BN_CTX_get(ctx);
    result = BN_CTX_get(ctx);
    if !(f.is_null() || result.is_null()) {
        if padding == 3 as libc::c_int {
            buf = out;
            current_block = 14763689060501151050;
        } else {
            buf = OPENSSL_malloc(rsa_size as size_t) as *mut uint8_t;
            if buf.is_null() {
                current_block = 17896074211589742093;
            } else {
                current_block = 14763689060501151050;
            }
        }
        match current_block {
            17896074211589742093 => {}
            _ => {
                if !(BN_bin2bn(in_0, in_len, f)).is_null() {
                    if BN_ucmp(f, (*rsa).n) >= 0 as libc::c_int {
                        ERR_put_error(
                            4 as libc::c_int,
                            0 as libc::c_int,
                            115 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                                as *const u8 as *const libc::c_char,
                            485 as libc::c_int as libc::c_uint,
                        );
                    } else if !(BN_MONT_CTX_set_locked(
                        &mut (*rsa).mont_n,
                        &mut (*rsa).lock,
                        (*rsa).n,
                        ctx,
                    ) == 0
                        || BN_mod_exp_mont(
                            result,
                            f,
                            (*rsa).e,
                            &mut (*(*rsa).mont_n).N,
                            ctx,
                            (*rsa).mont_n,
                        ) == 0)
                    {
                        if BN_bn2bin_padded(buf, rsa_size as size_t, result) == 0 {
                            ERR_put_error(
                                4 as libc::c_int,
                                0 as libc::c_int,
                                4 as libc::c_int | 64 as libc::c_int,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                                    as *const u8 as *const libc::c_char,
                                495 as libc::c_int as libc::c_uint,
                            );
                        } else {
                            match padding {
                                1 => {
                                    ret_0 = RSA_padding_check_PKCS1_type_1(
                                        out,
                                        out_len,
                                        rsa_size as size_t,
                                        buf,
                                        rsa_size as size_t,
                                    );
                                    current_block = 15090052786889560393;
                                }
                                3 => {
                                    ret_0 = 1 as libc::c_int;
                                    *out_len = rsa_size as size_t;
                                    current_block = 15090052786889560393;
                                }
                                _ => {
                                    ERR_put_error(
                                        4 as libc::c_int,
                                        0 as libc::c_int,
                                        143 as libc::c_int,
                                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                                            as *const u8 as *const libc::c_char,
                                        509 as libc::c_int as libc::c_uint,
                                    );
                                    current_block = 17896074211589742093;
                                }
                            }
                            match current_block {
                                17896074211589742093 => {}
                                _ => {
                                    if ret_0 == 0 {
                                        ERR_put_error(
                                            4 as libc::c_int,
                                            0 as libc::c_int,
                                            136 as libc::c_int,
                                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                                                as *const u8 as *const libc::c_char,
                                            514 as libc::c_int as libc::c_uint,
                                        );
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
    BN_CTX_free(ctx);
    if buf != out {
        OPENSSL_free(buf as *mut libc::c_void);
    }
    return ret_0;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_verify_raw(
    mut rsa: *mut RSA,
    mut out_len: *mut size_t,
    mut out: *mut uint8_t,
    mut max_out: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut padding: libc::c_int,
) -> libc::c_int {
    boringssl_ensure_rsa_self_test();
    return rsa_verify_raw_no_self_test(
        rsa,
        out_len,
        out,
        max_out,
        in_0,
        in_len,
        padding,
    );
}
#[no_mangle]
pub unsafe extern "C" fn rsa_default_private_transform(
    mut rsa: *mut RSA,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut do_blinding: libc::c_int = 0;
    let mut current_block: u64;
    if ((*rsa).n).is_null() || ((*rsa).d).is_null() {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            144 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                as *const u8 as *const libc::c_char,
            538 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut f: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut result: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut ctx: *mut BN_CTX = 0 as *mut BN_CTX;
    let mut blinding_index: size_t = 0 as libc::c_int as size_t;
    let mut blinding: *mut BN_BLINDING = 0 as *mut BN_BLINDING;
    let mut ret: libc::c_int = 0 as libc::c_int;
    ctx = BN_CTX_new();
    if !ctx.is_null() {
        BN_CTX_start(ctx);
        f = BN_CTX_get(ctx);
        result = BN_CTX_get(ctx);
        if !(f.is_null() || result.is_null()) {
            if len == BN_num_bytes((*rsa).n) as size_t {} else {
                __assert_fail(
                    b"len == BN_num_bytes(rsa->n)\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                        as *const u8 as *const libc::c_char,
                    561 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 77],
                        &[libc::c_char; 77],
                    >(
                        b"int rsa_default_private_transform(RSA *, uint8_t *, const uint8_t *, size_t)\0",
                    ))
                        .as_ptr(),
                );
            }
            'c_11102: {
                if len == BN_num_bytes((*rsa).n) as size_t {} else {
                    __assert_fail(
                        b"len == BN_num_bytes(rsa->n)\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                            as *const u8 as *const libc::c_char,
                        561 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 77],
                            &[libc::c_char; 77],
                        >(
                            b"int rsa_default_private_transform(RSA *, uint8_t *, const uint8_t *, size_t)\0",
                        ))
                            .as_ptr(),
                    );
                }
            };
            if !(BN_bin2bn(in_0, len, f)).is_null() {
                if constant_time_declassify_int(
                    (BN_ucmp(f, (*rsa).n) >= 0 as libc::c_int) as libc::c_int,
                ) != 0
                {
                    ERR_put_error(
                        4 as libc::c_int,
                        0 as libc::c_int,
                        115 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                            as *const u8 as *const libc::c_char,
                        570 as libc::c_int as libc::c_uint,
                    );
                } else if freeze_private_key(rsa, ctx) == 0 {
                    ERR_put_error(
                        4 as libc::c_int,
                        0 as libc::c_int,
                        4 as libc::c_int | 64 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                            as *const u8 as *const libc::c_char,
                        575 as libc::c_int as libc::c_uint,
                    );
                } else {
                    do_blinding = ((*rsa).flags
                        & (8 as libc::c_int | 0x40 as libc::c_int) == 0 as libc::c_int)
                        as libc::c_int;
                    if ((*rsa).e).is_null() && do_blinding != 0 {
                        ERR_put_error(
                            4 as libc::c_int,
                            0 as libc::c_int,
                            130 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                                as *const u8 as *const libc::c_char,
                            591 as libc::c_int as libc::c_uint,
                        );
                    } else {
                        if do_blinding != 0 {
                            blinding = rsa_blinding_get(rsa, &mut blinding_index, ctx);
                            if blinding.is_null() {
                                ERR_put_error(
                                    4 as libc::c_int,
                                    0 as libc::c_int,
                                    4 as libc::c_int | 64 as libc::c_int,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                                        as *const u8 as *const libc::c_char,
                                    598 as libc::c_int as libc::c_uint,
                                );
                                current_block = 5012522263950168875;
                            } else if BN_BLINDING_convert(
                                f,
                                blinding,
                                (*rsa).e,
                                (*rsa).mont_n,
                                ctx,
                            ) == 0
                            {
                                current_block = 5012522263950168875;
                            } else {
                                current_block = 11307063007268554308;
                            }
                        } else {
                            current_block = 11307063007268554308;
                        }
                        match current_block {
                            5012522263950168875 => {}
                            _ => {
                                if !((*rsa).p).is_null() && !((*rsa).q).is_null()
                                    && !((*rsa).e).is_null() && !((*rsa).dmp1).is_null()
                                    && !((*rsa).dmq1).is_null() && !((*rsa).iqmp).is_null()
                                    && bn_less_than_montgomery_R((*rsa).q, (*rsa).mont_p) != 0
                                    && bn_less_than_montgomery_R((*rsa).p, (*rsa).mont_q) != 0
                                {
                                    if mod_exp(result, f, rsa, ctx) == 0 {
                                        current_block = 5012522263950168875;
                                    } else {
                                        current_block = 13550086250199790493;
                                    }
                                } else if BN_mod_exp_mont_consttime(
                                    result,
                                    f,
                                    (*rsa).d_fixed,
                                    (*rsa).n,
                                    ctx,
                                    (*rsa).mont_n,
                                ) == 0
                                {
                                    current_block = 5012522263950168875;
                                } else {
                                    current_block = 13550086250199790493;
                                }
                                match current_block {
                                    5012522263950168875 => {}
                                    _ => {
                                        if !((*rsa).e).is_null() {
                                            let mut vrfy: *mut BIGNUM = BN_CTX_get(ctx);
                                            if vrfy.is_null()
                                                || BN_mod_exp_mont(
                                                    vrfy,
                                                    result,
                                                    (*rsa).e,
                                                    (*rsa).n,
                                                    ctx,
                                                    (*rsa).mont_n,
                                                ) == 0
                                                || constant_time_declassify_int(BN_equal_consttime(vrfy, f))
                                                    == 0
                                            {
                                                ERR_put_error(
                                                    4 as libc::c_int,
                                                    0 as libc::c_int,
                                                    4 as libc::c_int | 64 as libc::c_int,
                                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                                                        as *const u8 as *const libc::c_char,
                                                    637 as libc::c_int as libc::c_uint,
                                                );
                                                current_block = 5012522263950168875;
                                            } else {
                                                current_block = 15897653523371991391;
                                            }
                                        } else {
                                            current_block = 15897653523371991391;
                                        }
                                        match current_block {
                                            5012522263950168875 => {}
                                            _ => {
                                                if !(do_blinding != 0
                                                    && BN_BLINDING_invert(result, blinding, (*rsa).mont_n, ctx)
                                                        == 0)
                                                {
                                                    if (*result).width == (*(*rsa).mont_n).N.width {} else {
                                                        __assert_fail(
                                                            b"result->width == rsa->mont_n->N.width\0" as *const u8
                                                                as *const libc::c_char,
                                                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                                                                as *const u8 as *const libc::c_char,
                                                            652 as libc::c_int as libc::c_uint,
                                                            (*::core::mem::transmute::<
                                                                &[u8; 77],
                                                                &[libc::c_char; 77],
                                                            >(
                                                                b"int rsa_default_private_transform(RSA *, uint8_t *, const uint8_t *, size_t)\0",
                                                            ))
                                                                .as_ptr(),
                                                        );
                                                    }
                                                    'c_8948: {
                                                        if (*result).width == (*(*rsa).mont_n).N.width {} else {
                                                            __assert_fail(
                                                                b"result->width == rsa->mont_n->N.width\0" as *const u8
                                                                    as *const libc::c_char,
                                                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                                                                    as *const u8 as *const libc::c_char,
                                                                652 as libc::c_int as libc::c_uint,
                                                                (*::core::mem::transmute::<
                                                                    &[u8; 77],
                                                                    &[libc::c_char; 77],
                                                                >(
                                                                    b"int rsa_default_private_transform(RSA *, uint8_t *, const uint8_t *, size_t)\0",
                                                                ))
                                                                    .as_ptr(),
                                                            );
                                                        }
                                                    };
                                                    bn_assert_fits_in_bytes(result, len);
                                                    if BN_bn2bin_padded(out, len, result) == 0 {
                                                        ERR_put_error(
                                                            4 as libc::c_int,
                                                            0 as libc::c_int,
                                                            4 as libc::c_int | 64 as libc::c_int,
                                                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                                                                as *const u8 as *const libc::c_char,
                                                            655 as libc::c_int as libc::c_uint,
                                                        );
                                                    } else {
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
        }
    }
    if !ctx.is_null() {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if !blinding.is_null() {
        rsa_blinding_release(rsa, blinding, blinding_index);
    }
    return ret;
}
unsafe extern "C" fn mod_montgomery(
    mut r: *mut BIGNUM,
    mut I: *const BIGNUM,
    mut p: *const BIGNUM,
    mut mont_p: *const BN_MONT_CTX,
    mut q: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if bn_less_than_montgomery_R(q, mont_p) == 0 {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            4 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                as *const u8 as *const libc::c_char,
            682 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if BN_from_montgomery(r, I, mont_p, ctx) == 0
        || BN_to_montgomery(r, r, mont_p, ctx) == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn mod_exp(
    mut r0: *mut BIGNUM,
    mut I: *const BIGNUM,
    mut rsa: *mut RSA,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut n: *const BIGNUM = 0 as *const BIGNUM;
    let mut p: *const BIGNUM = 0 as *const BIGNUM;
    let mut q: *const BIGNUM = 0 as *const BIGNUM;
    if !ctx.is_null() {} else {
        __assert_fail(
            b"ctx != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                as *const u8 as *const libc::c_char,
            705 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 55],
                &[libc::c_char; 55],
            >(b"int mod_exp(BIGNUM *, const BIGNUM *, RSA *, BN_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_10069: {
        if !ctx.is_null() {} else {
            __assert_fail(
                b"ctx != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                    as *const u8 as *const libc::c_char,
                705 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 55],
                    &[libc::c_char; 55],
                >(b"int mod_exp(BIGNUM *, const BIGNUM *, RSA *, BN_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    if !((*rsa).n).is_null() {} else {
        __assert_fail(
            b"rsa->n != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                as *const u8 as *const libc::c_char,
            707 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 55],
                &[libc::c_char; 55],
            >(b"int mod_exp(BIGNUM *, const BIGNUM *, RSA *, BN_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_10023: {
        if !((*rsa).n).is_null() {} else {
            __assert_fail(
                b"rsa->n != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                    as *const u8 as *const libc::c_char,
                707 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 55],
                    &[libc::c_char; 55],
                >(b"int mod_exp(BIGNUM *, const BIGNUM *, RSA *, BN_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    if !((*rsa).e).is_null() {} else {
        __assert_fail(
            b"rsa->e != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                as *const u8 as *const libc::c_char,
            708 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 55],
                &[libc::c_char; 55],
            >(b"int mod_exp(BIGNUM *, const BIGNUM *, RSA *, BN_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_9977: {
        if !((*rsa).e).is_null() {} else {
            __assert_fail(
                b"rsa->e != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                    as *const u8 as *const libc::c_char,
                708 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 55],
                    &[libc::c_char; 55],
                >(b"int mod_exp(BIGNUM *, const BIGNUM *, RSA *, BN_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    if !((*rsa).d).is_null() {} else {
        __assert_fail(
            b"rsa->d != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                as *const u8 as *const libc::c_char,
            709 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 55],
                &[libc::c_char; 55],
            >(b"int mod_exp(BIGNUM *, const BIGNUM *, RSA *, BN_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_9931: {
        if !((*rsa).d).is_null() {} else {
            __assert_fail(
                b"rsa->d != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                    as *const u8 as *const libc::c_char,
                709 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 55],
                    &[libc::c_char; 55],
                >(b"int mod_exp(BIGNUM *, const BIGNUM *, RSA *, BN_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    if !((*rsa).p).is_null() {} else {
        __assert_fail(
            b"rsa->p != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                as *const u8 as *const libc::c_char,
            710 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 55],
                &[libc::c_char; 55],
            >(b"int mod_exp(BIGNUM *, const BIGNUM *, RSA *, BN_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_9885: {
        if !((*rsa).p).is_null() {} else {
            __assert_fail(
                b"rsa->p != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                    as *const u8 as *const libc::c_char,
                710 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 55],
                    &[libc::c_char; 55],
                >(b"int mod_exp(BIGNUM *, const BIGNUM *, RSA *, BN_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    if !((*rsa).q).is_null() {} else {
        __assert_fail(
            b"rsa->q != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                as *const u8 as *const libc::c_char,
            711 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 55],
                &[libc::c_char; 55],
            >(b"int mod_exp(BIGNUM *, const BIGNUM *, RSA *, BN_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_9838: {
        if !((*rsa).q).is_null() {} else {
            __assert_fail(
                b"rsa->q != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                    as *const u8 as *const libc::c_char,
                711 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 55],
                    &[libc::c_char; 55],
                >(b"int mod_exp(BIGNUM *, const BIGNUM *, RSA *, BN_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    if !((*rsa).dmp1).is_null() {} else {
        __assert_fail(
            b"rsa->dmp1 != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                as *const u8 as *const libc::c_char,
            712 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 55],
                &[libc::c_char; 55],
            >(b"int mod_exp(BIGNUM *, const BIGNUM *, RSA *, BN_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_9792: {
        if !((*rsa).dmp1).is_null() {} else {
            __assert_fail(
                b"rsa->dmp1 != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                    as *const u8 as *const libc::c_char,
                712 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 55],
                    &[libc::c_char; 55],
                >(b"int mod_exp(BIGNUM *, const BIGNUM *, RSA *, BN_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    if !((*rsa).dmq1).is_null() {} else {
        __assert_fail(
            b"rsa->dmq1 != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                as *const u8 as *const libc::c_char,
            713 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 55],
                &[libc::c_char; 55],
            >(b"int mod_exp(BIGNUM *, const BIGNUM *, RSA *, BN_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_9746: {
        if !((*rsa).dmq1).is_null() {} else {
            __assert_fail(
                b"rsa->dmq1 != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                    as *const u8 as *const libc::c_char,
                713 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 55],
                    &[libc::c_char; 55],
                >(b"int mod_exp(BIGNUM *, const BIGNUM *, RSA *, BN_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    if !((*rsa).iqmp).is_null() {} else {
        __assert_fail(
            b"rsa->iqmp != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                as *const u8 as *const libc::c_char,
            714 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 55],
                &[libc::c_char; 55],
            >(b"int mod_exp(BIGNUM *, const BIGNUM *, RSA *, BN_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_9699: {
        if !((*rsa).iqmp).is_null() {} else {
            __assert_fail(
                b"rsa->iqmp != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                    as *const u8 as *const libc::c_char,
                714 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 55],
                    &[libc::c_char; 55],
                >(b"int mod_exp(BIGNUM *, const BIGNUM *, RSA *, BN_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut r1: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut r2: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut m1: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut ret: libc::c_int = 0 as libc::c_int;
    BN_CTX_start(ctx);
    r1 = BN_CTX_get(ctx);
    r2 = BN_CTX_get(ctx);
    m1 = BN_CTX_get(ctx);
    if !(r1.is_null() || r2.is_null() || m1.is_null()) {
        if !(freeze_private_key(rsa, ctx) == 0) {
            n = &mut (*(*rsa).mont_n).N;
            p = &mut (*(*rsa).mont_p).N;
            q = &mut (*(*rsa).mont_q).N;
            if constant_time_declassify_int(
                (BN_ucmp(I, n) < 0 as libc::c_int) as libc::c_int,
            ) != 0
            {} else {
                __assert_fail(
                    b"constant_time_declassify_int(BN_ucmp(I, n) < 0)\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                        as *const u8 as *const libc::c_char,
                    742 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 55],
                        &[libc::c_char; 55],
                    >(b"int mod_exp(BIGNUM *, const BIGNUM *, RSA *, BN_CTX *)\0"))
                        .as_ptr(),
                );
            }
            'c_9586: {
                if constant_time_declassify_int(
                    (BN_ucmp(I, n) < 0 as libc::c_int) as libc::c_int,
                ) != 0
                {} else {
                    __assert_fail(
                        b"constant_time_declassify_int(BN_ucmp(I, n) < 0)\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                            as *const u8 as *const libc::c_char,
                        742 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 55],
                            &[libc::c_char; 55],
                        >(b"int mod_exp(BIGNUM *, const BIGNUM *, RSA *, BN_CTX *)\0"))
                            .as_ptr(),
                    );
                }
            };
            if !(mod_montgomery(r1, I, q, (*rsa).mont_q, p, ctx) == 0
                || mod_montgomery(r2, I, p, (*rsa).mont_p, q, ctx) == 0
                || BN_mod_exp_mont_consttime_x2(
                    m1,
                    r1,
                    (*rsa).dmq1_fixed,
                    q,
                    (*rsa).mont_q,
                    r0,
                    r2,
                    (*rsa).dmp1_fixed,
                    p,
                    (*rsa).mont_p,
                    ctx,
                ) == 0 || mod_montgomery(r1, m1, p, (*rsa).mont_p, q, ctx) == 0
                || bn_mod_sub_consttime(r0, r0, r1, p, ctx) == 0
                || BN_mod_mul_montgomery(r0, r0, (*rsa).iqmp_mont, (*rsa).mont_p, ctx)
                    == 0 || bn_mul_consttime(r0, r0, q, ctx) == 0
                || bn_uadd_consttime(r0, r0, m1) == 0)
            {
                if constant_time_declassify_int(
                    (BN_cmp(r0, n) < 0 as libc::c_int) as libc::c_int,
                ) != 0
                {} else {
                    __assert_fail(
                        b"constant_time_declassify_int(BN_cmp(r0, n) < 0)\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                            as *const u8 as *const libc::c_char,
                        777 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 55],
                            &[libc::c_char; 55],
                        >(b"int mod_exp(BIGNUM *, const BIGNUM *, RSA *, BN_CTX *)\0"))
                            .as_ptr(),
                    );
                }
                'c_9256: {
                    if constant_time_declassify_int(
                        (BN_cmp(r0, n) < 0 as libc::c_int) as libc::c_int,
                    ) != 0
                    {} else {
                        __assert_fail(
                            b"constant_time_declassify_int(BN_cmp(r0, n) < 0)\0"
                                as *const u8 as *const libc::c_char,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                                as *const u8 as *const libc::c_char,
                            777 as libc::c_int as libc::c_uint,
                            (*::core::mem::transmute::<
                                &[u8; 55],
                                &[libc::c_char; 55],
                            >(
                                b"int mod_exp(BIGNUM *, const BIGNUM *, RSA *, BN_CTX *)\0",
                            ))
                                .as_ptr(),
                        );
                    }
                };
                bn_assert_fits_in_bytes(r0, BN_num_bytes(n) as size_t);
                if !(bn_resize_words(r0, (*n).width as size_t) == 0) {
                    ret = 1 as libc::c_int;
                }
            }
        }
    }
    BN_CTX_end(ctx);
    return ret;
}
unsafe extern "C" fn ensure_bignum(mut out: *mut *mut BIGNUM) -> libc::c_int {
    if (*out).is_null() {
        *out = BN_new();
    }
    return (*out != 0 as *mut libc::c_void as *mut BIGNUM) as libc::c_int;
}
#[no_mangle]
pub static mut kBoringSSLRSASqrtTwo: [BN_ULONG; 32] = [
    (0x4d7c60a5 as libc::c_int as BN_ULONG) << 32 as libc::c_int
        | 0xe633e3e1 as libc::c_uint as BN_ULONG,
    (0x5fcf8f7b as libc::c_int as BN_ULONG) << 32 as libc::c_int
        | 0xca3ea33b as libc::c_uint as BN_ULONG,
    (0xc246785e as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0x92957023 as libc::c_uint as BN_ULONG,
    (0xf9acce41 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0x797f2805 as libc::c_int as BN_ULONG,
    (0xfdfe170f as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0xd3b1f780 as libc::c_uint as BN_ULONG,
    (0xd24f4a76 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0x3facb882 as libc::c_int as BN_ULONG,
    (0x18838a2e as libc::c_int as BN_ULONG) << 32 as libc::c_int
        | 0xaff5f3b2 as libc::c_uint as BN_ULONG,
    (0xc1fcbdde as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0xa2f7dc33 as libc::c_uint as BN_ULONG,
    (0xdea06241 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0xf7aa81c2 as libc::c_uint as BN_ULONG,
    (0xf6a1be3f as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0xca221307 as libc::c_uint as BN_ULONG,
    (0x332a5e9f as libc::c_int as BN_ULONG) << 32 as libc::c_int
        | 0x7bda1ebf as libc::c_int as BN_ULONG,
    (0x104dc01 as libc::c_int as BN_ULONG) << 32 as libc::c_int
        | 0xfe32352f as libc::c_uint as BN_ULONG,
    (0xb8cf341b as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0x6f8236c7 as libc::c_int as BN_ULONG,
    (0x4264dabc as libc::c_int as BN_ULONG) << 32 as libc::c_int
        | 0xd528b651 as libc::c_uint as BN_ULONG,
    (0xf4d3a02c as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0xebc93e0c as libc::c_uint as BN_ULONG,
    (0x81394ab6 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0xd8fd0efd as libc::c_uint as BN_ULONG,
    (0xeaa4a089 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0x9040ca4a as libc::c_uint as BN_ULONG,
    (0xf52f120f as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0x836e582e as libc::c_uint as BN_ULONG,
    (0xcb2a6343 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0x31f3c84d as libc::c_int as BN_ULONG,
    (0xc6d5a8a3 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0x8bb7e9dc as libc::c_uint as BN_ULONG,
    (0x460abc72 as libc::c_int as BN_ULONG) << 32 as libc::c_int
        | 0x2f7c4e33 as libc::c_int as BN_ULONG,
    (0xcab1bc91 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0x1688458a as libc::c_int as BN_ULONG,
    (0x53059c60 as libc::c_int as BN_ULONG) << 32 as libc::c_int
        | 0x11bc337b as libc::c_int as BN_ULONG,
    (0xd2202e87 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0x42af1f4e as libc::c_int as BN_ULONG,
    (0x78048736 as libc::c_int as BN_ULONG) << 32 as libc::c_int
        | 0x3dfa2768 as libc::c_int as BN_ULONG,
    (0xf74a85e as libc::c_int as BN_ULONG) << 32 as libc::c_int
        | 0x439c7b4a as libc::c_int as BN_ULONG,
    (0xa8b1fe6f as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0xdc83db39 as libc::c_uint as BN_ULONG,
    (0x4afc8304 as libc::c_int as BN_ULONG) << 32 as libc::c_int
        | 0x3ab8a2c3 as libc::c_int as BN_ULONG,
    (0xed17ac85 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0x83339915 as libc::c_uint as BN_ULONG,
    (0x1d6f60ba as libc::c_int as BN_ULONG) << 32 as libc::c_int
        | 0x893ba84c as libc::c_uint as BN_ULONG,
    (0x597d89b3 as libc::c_int as BN_ULONG) << 32 as libc::c_int
        | 0x754abe9f as libc::c_int as BN_ULONG,
    (0xb504f333 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0xf9de6484 as libc::c_uint as BN_ULONG,
];
#[no_mangle]
pub static mut kBoringSSLRSASqrtTwoLen: size_t = 0;
unsafe extern "C" fn generate_prime(
    mut out: *mut BIGNUM,
    mut bits: libc::c_int,
    mut e: *const BIGNUM,
    mut p: *const BIGNUM,
    mut sqrt2: *const BIGNUM,
    mut pow2_bits_100: *const BIGNUM,
    mut ctx: *mut BN_CTX,
    mut cb: *mut BN_GENCB,
) -> libc::c_int {
    let mut current_block: u64;
    if bits < 128 as libc::c_int || bits % 64 as libc::c_int != 0 as libc::c_int {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            4 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                as *const u8 as *const libc::c_char,
            874 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if BN_is_pow2(pow2_bits_100) != 0 {} else {
        __assert_fail(
            b"BN_is_pow2(pow2_bits_100)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                as *const u8 as *const libc::c_char,
            877 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 120],
                &[libc::c_char; 120],
            >(
                b"int generate_prime(BIGNUM *, int, const BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *, BN_GENCB *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_6518: {
        if BN_is_pow2(pow2_bits_100) != 0 {} else {
            __assert_fail(
                b"BN_is_pow2(pow2_bits_100)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                    as *const u8 as *const libc::c_char,
                877 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 120],
                    &[libc::c_char; 120],
                >(
                    b"int generate_prime(BIGNUM *, int, const BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *, BN_GENCB *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if BN_is_bit_set(pow2_bits_100, bits - 100 as libc::c_int) != 0 {} else {
        __assert_fail(
            b"BN_is_bit_set(pow2_bits_100, bits - 100)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                as *const u8 as *const libc::c_char,
            878 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 120],
                &[libc::c_char; 120],
            >(
                b"int generate_prime(BIGNUM *, int, const BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *, BN_GENCB *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_6470: {
        if BN_is_bit_set(pow2_bits_100, bits - 100 as libc::c_int) != 0 {} else {
            __assert_fail(
                b"BN_is_bit_set(pow2_bits_100, bits - 100)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                    as *const u8 as *const libc::c_char,
                878 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 120],
                    &[libc::c_char; 120],
                >(
                    b"int generate_prime(BIGNUM *, int, const BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *, BN_GENCB *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if bits >= 2147483647 as libc::c_int / 32 as libc::c_int {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            128 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                as *const u8 as *const libc::c_char,
            911 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut limit: libc::c_int = if BN_is_word(e, 3 as libc::c_int as BN_ULONG) != 0 {
        bits * 8 as libc::c_int
    } else {
        bits * 5 as libc::c_int
    };
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut tries: libc::c_int = 0 as libc::c_int;
    let mut rand_tries: libc::c_int = 0 as libc::c_int;
    BN_CTX_start(ctx);
    let mut tmp: *mut BIGNUM = BN_CTX_get(ctx);
    if tmp.is_null() {
        current_block = 16126065030456402031;
    } else {
        current_block = 2868539653012386629;
    }
    loop {
        match current_block {
            16126065030456402031 => {
                BN_CTX_end(ctx);
                break;
            }
            _ => {
                if BN_rand(out, bits, 0 as libc::c_int, 1 as libc::c_int) == 0
                    || {
                        let fresh1 = rand_tries;
                        rand_tries = rand_tries + 1;
                        BN_GENCB_call(cb, 0 as libc::c_int, fresh1) == 0
                    }
                {
                    current_block = 16126065030456402031;
                    continue;
                }
                if !p.is_null() {
                    if bn_abs_sub_consttime(tmp, out, p, ctx) == 0 {
                        current_block = 16126065030456402031;
                        continue;
                    }
                    if BN_cmp(tmp, pow2_bits_100) <= 0 as libc::c_int {
                        current_block = 2868539653012386629;
                        continue;
                    }
                }
                if constant_time_declassify_int(
                    (BN_cmp(out, sqrt2) <= 0 as libc::c_int) as libc::c_int,
                ) != 0
                {
                    current_block = 2868539653012386629;
                    continue;
                }
                if bn_odd_number_is_obviously_composite(out) == 0 {
                    let mut relatively_prime: libc::c_int = 0;
                    if bn_usub_consttime(tmp, out, BN_value_one()) == 0
                        || bn_is_relatively_prime(&mut relatively_prime, tmp, e, ctx)
                            == 0
                    {
                        current_block = 16126065030456402031;
                        continue;
                    }
                    if constant_time_declassify_int(relatively_prime) != 0 {
                        let mut is_probable_prime: libc::c_int = 0;
                        if BN_primality_test(
                            &mut is_probable_prime,
                            out,
                            0 as libc::c_int,
                            ctx,
                            0 as libc::c_int,
                            cb,
                        ) == 0
                        {
                            current_block = 16126065030456402031;
                            continue;
                        }
                        if is_probable_prime != 0 {
                            ret = 1 as libc::c_int;
                            current_block = 16126065030456402031;
                            continue;
                        }
                    }
                }
                tries += 1;
                tries;
                if tries >= limit {
                    ERR_put_error(
                        4 as libc::c_int,
                        0 as libc::c_int,
                        141 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                            as *const u8 as *const libc::c_char,
                        985 as libc::c_int as libc::c_uint,
                    );
                    current_block = 16126065030456402031;
                } else if BN_GENCB_call(cb, 2 as libc::c_int, tries) == 0 {
                    current_block = 16126065030456402031;
                } else {
                    current_block = 2868539653012386629;
                }
            }
        }
    }
    return ret;
}
unsafe extern "C" fn rsa_generate_key_impl(
    mut rsa: *mut RSA,
    mut bits: libc::c_int,
    mut e_value: *const BIGNUM,
    mut cb: *mut BN_GENCB,
) -> libc::c_int {
    let mut totient: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut pm1: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut qm1: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut sqrt2: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut pow2_prime_bits_100: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut pow2_prime_bits: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut sqrt2_bits: libc::c_int = 0;
    let mut current_block: u64;
    bits &= !(127 as libc::c_int);
    if bits < 256 as libc::c_int {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            126 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                as *const u8 as *const libc::c_char,
            1016 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if BN_num_bits(e_value) > 32 as libc::c_int as libc::c_uint {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                as *const u8 as *const libc::c_char,
            1027 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut prime_bits: libc::c_int = bits / 2 as libc::c_int;
    let mut ctx: *mut BN_CTX = BN_CTX_new();
    if ctx.is_null() {
        current_block = 13710560980087606204;
    } else {
        BN_CTX_start(ctx);
        totient = BN_CTX_get(ctx);
        pm1 = BN_CTX_get(ctx);
        qm1 = BN_CTX_get(ctx);
        sqrt2 = BN_CTX_get(ctx);
        pow2_prime_bits_100 = BN_CTX_get(ctx);
        pow2_prime_bits = BN_CTX_get(ctx);
        if totient.is_null() || pm1.is_null() || qm1.is_null() || sqrt2.is_null()
            || pow2_prime_bits_100.is_null() || pow2_prime_bits.is_null()
            || BN_set_bit(pow2_prime_bits_100, prime_bits - 100 as libc::c_int) == 0
            || BN_set_bit(pow2_prime_bits, prime_bits) == 0
        {
            current_block = 13710560980087606204;
        } else if ensure_bignum(&mut (*rsa).n) == 0 || ensure_bignum(&mut (*rsa).d) == 0
            || ensure_bignum(&mut (*rsa).e) == 0 || ensure_bignum(&mut (*rsa).p) == 0
            || ensure_bignum(&mut (*rsa).q) == 0 || ensure_bignum(&mut (*rsa).dmp1) == 0
            || ensure_bignum(&mut (*rsa).dmq1) == 0
        {
            current_block = 13710560980087606204;
        } else if (BN_copy((*rsa).e, e_value)).is_null() {
            current_block = 13710560980087606204;
        } else if bn_set_words(
            sqrt2,
            kBoringSSLRSASqrtTwo.as_ptr(),
            kBoringSSLRSASqrtTwoLen,
        ) == 0
        {
            current_block = 13710560980087606204;
        } else {
            sqrt2_bits = (kBoringSSLRSASqrtTwoLen * 64 as libc::c_int as size_t)
                as libc::c_int;
            if sqrt2_bits == BN_num_bits(sqrt2) as libc::c_int {} else {
                __assert_fail(
                    b"sqrt2_bits == (int)BN_num_bits(sqrt2)\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                        as *const u8 as *const libc::c_char,
                    1071 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 66],
                        &[libc::c_char; 66],
                    >(
                        b"int rsa_generate_key_impl(RSA *, int, const BIGNUM *, BN_GENCB *)\0",
                    ))
                        .as_ptr(),
                );
            }
            'c_7078: {
                if sqrt2_bits == BN_num_bits(sqrt2) as libc::c_int {} else {
                    __assert_fail(
                        b"sqrt2_bits == (int)BN_num_bits(sqrt2)\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                            as *const u8 as *const libc::c_char,
                        1071 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 66],
                            &[libc::c_char; 66],
                        >(
                            b"int rsa_generate_key_impl(RSA *, int, const BIGNUM *, BN_GENCB *)\0",
                        ))
                            .as_ptr(),
                    );
                }
            };
            if sqrt2_bits > prime_bits {
                if BN_rshift(sqrt2, sqrt2, sqrt2_bits - prime_bits) == 0 {
                    current_block = 13710560980087606204;
                } else {
                    current_block = 11298138898191919651;
                }
            } else if prime_bits > sqrt2_bits {
                if BN_add_word(sqrt2, 1 as libc::c_int as BN_ULONG) == 0
                    || BN_lshift(sqrt2, sqrt2, prime_bits - sqrt2_bits) == 0
                {
                    current_block = 13710560980087606204;
                } else {
                    current_block = 11298138898191919651;
                }
            } else {
                current_block = 11298138898191919651;
            }
            match current_block {
                13710560980087606204 => {}
                _ => {
                    if prime_bits == BN_num_bits(sqrt2) as libc::c_int {} else {
                        __assert_fail(
                            b"prime_bits == (int)BN_num_bits(sqrt2)\0" as *const u8
                                as *const libc::c_char,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                                as *const u8 as *const libc::c_char,
                            1086 as libc::c_int as libc::c_uint,
                            (*::core::mem::transmute::<
                                &[u8; 66],
                                &[libc::c_char; 66],
                            >(
                                b"int rsa_generate_key_impl(RSA *, int, const BIGNUM *, BN_GENCB *)\0",
                            ))
                                .as_ptr(),
                        );
                    }
                    'c_6624: {
                        if prime_bits == BN_num_bits(sqrt2) as libc::c_int {} else {
                            __assert_fail(
                                b"prime_bits == (int)BN_num_bits(sqrt2)\0" as *const u8
                                    as *const libc::c_char,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                                    as *const u8 as *const libc::c_char,
                                1086 as libc::c_int as libc::c_uint,
                                (*::core::mem::transmute::<
                                    &[u8; 66],
                                    &[libc::c_char; 66],
                                >(
                                    b"int rsa_generate_key_impl(RSA *, int, const BIGNUM *, BN_GENCB *)\0",
                                ))
                                    .as_ptr(),
                            );
                        }
                    };
                    loop {
                        if generate_prime(
                            (*rsa).p,
                            prime_bits,
                            (*rsa).e,
                            0 as *const BIGNUM,
                            sqrt2,
                            pow2_prime_bits_100,
                            ctx,
                            cb,
                        ) == 0
                            || BN_GENCB_call(cb, 3 as libc::c_int, 0 as libc::c_int) == 0
                            || generate_prime(
                                (*rsa).q,
                                prime_bits,
                                (*rsa).e,
                                (*rsa).p,
                                sqrt2,
                                pow2_prime_bits_100,
                                ctx,
                                cb,
                            ) == 0
                            || BN_GENCB_call(cb, 3 as libc::c_int, 1 as libc::c_int) == 0
                        {
                            current_block = 13710560980087606204;
                            break;
                        }
                        if BN_cmp((*rsa).p, (*rsa).q) < 0 as libc::c_int {
                            let mut tmp: *mut BIGNUM = (*rsa).p;
                            (*rsa).p = (*rsa).q;
                            (*rsa).q = tmp;
                        }
                        let mut no_inverse: libc::c_int = 0;
                        if bn_usub_consttime(pm1, (*rsa).p, BN_value_one()) == 0
                            || bn_usub_consttime(qm1, (*rsa).q, BN_value_one()) == 0
                            || bn_lcm_consttime(totient, pm1, qm1, ctx) == 0
                            || bn_mod_inverse_consttime(
                                (*rsa).d,
                                &mut no_inverse,
                                (*rsa).e,
                                totient,
                                ctx,
                            ) == 0
                        {
                            current_block = 13710560980087606204;
                            break;
                        }
                        if !(constant_time_declassify_int(
                            (BN_cmp((*rsa).d, pow2_prime_bits) <= 0 as libc::c_int)
                                as libc::c_int,
                        ) != 0)
                        {
                            current_block = 3275366147856559585;
                            break;
                        }
                    }
                    match current_block {
                        13710560980087606204 => {}
                        _ => {
                            if BN_num_bits(pm1) == prime_bits as libc::c_uint {} else {
                                __assert_fail(
                                    b"BN_num_bits(pm1) == (unsigned)prime_bits\0" as *const u8
                                        as *const libc::c_char,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                                        as *const u8 as *const libc::c_char,
                                    1129 as libc::c_int as libc::c_uint,
                                    (*::core::mem::transmute::<
                                        &[u8; 66],
                                        &[libc::c_char; 66],
                                    >(
                                        b"int rsa_generate_key_impl(RSA *, int, const BIGNUM *, BN_GENCB *)\0",
                                    ))
                                        .as_ptr(),
                                );
                            }
                            'c_5873: {
                                if BN_num_bits(pm1) == prime_bits as libc::c_uint {} else {
                                    __assert_fail(
                                        b"BN_num_bits(pm1) == (unsigned)prime_bits\0" as *const u8
                                            as *const libc::c_char,
                                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                                            as *const u8 as *const libc::c_char,
                                        1129 as libc::c_int as libc::c_uint,
                                        (*::core::mem::transmute::<
                                            &[u8; 66],
                                            &[libc::c_char; 66],
                                        >(
                                            b"int rsa_generate_key_impl(RSA *, int, const BIGNUM *, BN_GENCB *)\0",
                                        ))
                                            .as_ptr(),
                                    );
                                }
                            };
                            if BN_num_bits(qm1) == prime_bits as libc::c_uint {} else {
                                __assert_fail(
                                    b"BN_num_bits(qm1) == (unsigned)prime_bits\0" as *const u8
                                        as *const libc::c_char,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                                        as *const u8 as *const libc::c_char,
                                    1130 as libc::c_int as libc::c_uint,
                                    (*::core::mem::transmute::<
                                        &[u8; 66],
                                        &[libc::c_char; 66],
                                    >(
                                        b"int rsa_generate_key_impl(RSA *, int, const BIGNUM *, BN_GENCB *)\0",
                                    ))
                                        .as_ptr(),
                                );
                            }
                            'c_5815: {
                                if BN_num_bits(qm1) == prime_bits as libc::c_uint {} else {
                                    __assert_fail(
                                        b"BN_num_bits(qm1) == (unsigned)prime_bits\0" as *const u8
                                            as *const libc::c_char,
                                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                                            as *const u8 as *const libc::c_char,
                                        1130 as libc::c_int as libc::c_uint,
                                        (*::core::mem::transmute::<
                                            &[u8; 66],
                                            &[libc::c_char; 66],
                                        >(
                                            b"int rsa_generate_key_impl(RSA *, int, const BIGNUM *, BN_GENCB *)\0",
                                        ))
                                            .as_ptr(),
                                    );
                                }
                            };
                            if bn_mul_consttime((*rsa).n, (*rsa).p, (*rsa).q, ctx) == 0
                                || bn_div_consttime(
                                    0 as *mut BIGNUM,
                                    (*rsa).dmp1,
                                    (*rsa).d,
                                    pm1,
                                    prime_bits as libc::c_uint,
                                    ctx,
                                ) == 0
                                || bn_div_consttime(
                                    0 as *mut BIGNUM,
                                    (*rsa).dmq1,
                                    (*rsa).d,
                                    qm1,
                                    prime_bits as libc::c_uint,
                                    ctx,
                                ) == 0
                            {
                                current_block = 13710560980087606204;
                            } else {
                                bn_set_minimal_width((*rsa).n);
                                bn_declassify((*rsa).n);
                                if BN_num_bits((*rsa).n) != bits as libc::c_uint {
                                    ERR_put_error(
                                        4 as libc::c_int,
                                        0 as libc::c_int,
                                        4 as libc::c_int | 64 as libc::c_int,
                                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                                            as *const u8 as *const libc::c_char,
                                        1147 as libc::c_int as libc::c_uint,
                                    );
                                    current_block = 14287108022192462053;
                                } else if freeze_private_key(rsa, ctx) == 0 {
                                    current_block = 13710560980087606204;
                                } else if RSA_check_key(rsa) == 0 {
                                    ERR_put_error(
                                        4 as libc::c_int,
                                        0 as libc::c_int,
                                        124 as libc::c_int,
                                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                                            as *const u8 as *const libc::c_char,
                                        1161 as libc::c_int as libc::c_uint,
                                    );
                                    current_block = 14287108022192462053;
                                } else {
                                    ret = 1 as libc::c_int;
                                    current_block = 13710560980087606204;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    match current_block {
        13710560980087606204 => {
            if ret == 0 {
                ERR_put_error(
                    4 as libc::c_int,
                    0 as libc::c_int,
                    3 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                        as *const u8 as *const libc::c_char,
                    1169 as libc::c_int as libc::c_uint,
                );
            }
        }
        _ => {}
    }
    if !ctx.is_null() {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ret;
}
unsafe extern "C" fn replace_bignum(
    mut out: *mut *mut BIGNUM,
    mut in_0: *mut *mut BIGNUM,
) {
    BN_free(*out);
    *out = *in_0;
    *in_0 = 0 as *mut BIGNUM;
}
unsafe extern "C" fn replace_bn_mont_ctx(
    mut out: *mut *mut BN_MONT_CTX,
    mut in_0: *mut *mut BN_MONT_CTX,
) {
    BN_MONT_CTX_free(*out);
    *out = *in_0;
    *in_0 = 0 as *mut BN_MONT_CTX;
}
unsafe extern "C" fn RSA_generate_key_ex_maybe_fips(
    mut rsa: *mut RSA,
    mut bits: libc::c_int,
    mut e_value: *const BIGNUM,
    mut cb: *mut BN_GENCB,
    mut check_fips: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    boringssl_ensure_rsa_self_test();
    let mut tmp: *mut RSA = 0 as *mut RSA;
    let mut err: uint32_t = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut failures: libc::c_int = 0 as libc::c_int;
    loop {
        ERR_clear_error();
        tmp = RSA_new();
        if tmp.is_null() {
            current_block = 13530052627007110582;
            break;
        }
        if rsa_generate_key_impl(tmp, bits, e_value, cb) != 0 {
            current_block = 2868539653012386629;
            break;
        }
        err = ERR_peek_error();
        RSA_free(tmp);
        tmp = 0 as *mut RSA;
        failures += 1;
        failures;
        if !(failures < 4 as libc::c_int && ERR_GET_LIB(err) == 4 as libc::c_int
            && ERR_GET_REASON(err) == 141 as libc::c_int)
        {
            current_block = 2868539653012386629;
            break;
        }
    }
    match current_block {
        2868539653012386629 => {
            if !tmp.is_null() {
                if check_fips != 0 && RSA_check_fips(tmp) == 0 {
                    RSA_free(tmp);
                    return ret;
                }
                rsa_invalidate_key(rsa);
                replace_bignum(&mut (*rsa).n, &mut (*tmp).n);
                replace_bignum(&mut (*rsa).e, &mut (*tmp).e);
                replace_bignum(&mut (*rsa).d, &mut (*tmp).d);
                replace_bignum(&mut (*rsa).p, &mut (*tmp).p);
                replace_bignum(&mut (*rsa).q, &mut (*tmp).q);
                replace_bignum(&mut (*rsa).dmp1, &mut (*tmp).dmp1);
                replace_bignum(&mut (*rsa).dmq1, &mut (*tmp).dmq1);
                replace_bignum(&mut (*rsa).iqmp, &mut (*tmp).iqmp);
                replace_bn_mont_ctx(&mut (*rsa).mont_n, &mut (*tmp).mont_n);
                replace_bn_mont_ctx(&mut (*rsa).mont_p, &mut (*tmp).mont_p);
                replace_bn_mont_ctx(&mut (*rsa).mont_q, &mut (*tmp).mont_q);
                replace_bignum(&mut (*rsa).d_fixed, &mut (*tmp).d_fixed);
                replace_bignum(&mut (*rsa).dmp1_fixed, &mut (*tmp).dmp1_fixed);
                replace_bignum(&mut (*rsa).dmq1_fixed, &mut (*tmp).dmq1_fixed);
                replace_bignum(&mut (*rsa).iqmp_mont, &mut (*tmp).iqmp_mont);
                (*rsa).set_private_key_frozen((*tmp).private_key_frozen());
                ret = 1 as libc::c_int;
            }
        }
        _ => {}
    }
    RSA_free(tmp);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_generate_key_ex(
    mut rsa: *mut RSA,
    mut bits: libc::c_int,
    mut e_value: *const BIGNUM,
    mut cb: *mut BN_GENCB,
) -> libc::c_int {
    return RSA_generate_key_ex_maybe_fips(rsa, bits, e_value, cb, 0 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn RSA_generate_key_fips(
    mut rsa: *mut RSA,
    mut bits: libc::c_int,
    mut cb: *mut BN_GENCB,
) -> libc::c_int {
    if bits < 2048 as libc::c_int || bits % 128 as libc::c_int != 0 as libc::c_int {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa_impl.c\0"
                as *const u8 as *const libc::c_char,
            1277 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut e: *mut BIGNUM = BN_new();
    FIPS_service_indicator_lock_state();
    let mut ret: libc::c_int = (!e.is_null()
        && BN_set_word(e, 0x10001 as libc::c_int as BN_ULONG) != 0
        && RSA_generate_key_ex_maybe_fips(rsa, bits, e, cb, 1 as libc::c_int) != 0)
        as libc::c_int;
    FIPS_service_indicator_unlock_state();
    BN_free(e);
    if ret != 0 {
        FIPS_service_indicator_update_state();
    }
    return ret;
}
unsafe extern "C" fn RSA_get_default_method_init() {
    RSA_get_default_method_do_init(RSA_get_default_method_storage_bss_get());
}
unsafe extern "C" fn RSA_get_default_method_storage_bss_get() -> *mut RSA_METHOD {
    return &mut RSA_get_default_method_storage;
}
static mut RSA_get_default_method_storage: RSA_METHOD = rsa_meth_st {
    app_data: 0 as *const libc::c_void as *mut libc::c_void,
    init: None,
    finish: None,
    size: None,
    sign: None,
    sign_raw: None,
    verify_raw: None,
    decrypt: None,
    encrypt: None,
    private_transform: None,
    flags: 0,
};
#[no_mangle]
pub unsafe extern "C" fn RSA_get_default_method() -> *const RSA_METHOD {
    CRYPTO_once(
        RSA_get_default_method_once_bss_get(),
        Some(RSA_get_default_method_init as unsafe extern "C" fn() -> ()),
    );
    return RSA_get_default_method_storage_bss_get() as *const RSA_METHOD;
}
unsafe extern "C" fn RSA_get_default_method_do_init(mut out: *mut RSA_METHOD) {
    OPENSSL_memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<RSA_METHOD>() as libc::c_ulong,
    );
}
unsafe extern "C" fn RSA_get_default_method_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut RSA_get_default_method_once;
}
static mut RSA_get_default_method_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn run_static_initializers() {
    kBoringSSLRSASqrtTwoLen = (::core::mem::size_of::<[BN_ULONG; 32]>() as libc::c_ulong)
        .wrapping_div(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong);
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
