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
    pub type engine_st;
    pub type env_md_st;
    fn BN_new() -> *mut BIGNUM;
    fn BN_free(bn: *mut BIGNUM);
    fn BN_clear_free(bn: *mut BIGNUM);
    fn BN_copy(dest: *mut BIGNUM, src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_num_bits(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_num_bytes(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_set_word(bn: *mut BIGNUM, value: BN_ULONG) -> libc::c_int;
    fn BN_bn2bin(in_0: *const BIGNUM, out: *mut uint8_t) -> size_t;
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
    fn BN_sub_word(a: *mut BIGNUM, w: BN_ULONG) -> libc::c_int;
    fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_cmp_word(a: *const BIGNUM, b: BN_ULONG) -> libc::c_int;
    fn BN_rshift1(r: *mut BIGNUM, a: *const BIGNUM) -> libc::c_int;
    fn BN_set_bit(a: *mut BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_rand_range_ex(
        r: *mut BIGNUM,
        min_inclusive: BN_ULONG,
        max_exclusive: *const BIGNUM,
    ) -> libc::c_int;
    fn BN_MONT_CTX_free(mont: *mut BN_MONT_CTX);
    fn BN_mod_exp_mont_consttime(
        rr: *mut BIGNUM,
        a: *const BIGNUM,
        p: *const BIGNUM,
        m: *const BIGNUM,
        ctx: *mut BN_CTX,
        mont: *const BN_MONT_CTX,
    ) -> libc::c_int;
    fn dh_check_params_fast(dh: *const DH) -> libc::c_int;
    fn EVP_Digest(
        data: *const libc::c_void,
        len: size_t,
        md_out: *mut uint8_t,
        out_size: *mut libc::c_uint,
        type_0: *const EVP_MD,
        impl_0: *mut ENGINE,
    ) -> libc::c_int;
    fn EVP_MD_size(md: *const EVP_MD) -> size_t;
    fn DH_check_pub_key(
        dh: *const DH,
        pub_key: *const BIGNUM,
        out_flags: *mut libc::c_int,
    ) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn CRYPTO_refcount_inc(count: *mut CRYPTO_refcount_t);
    fn CRYPTO_refcount_dec_and_test_zero(count: *mut CRYPTO_refcount_t) -> libc::c_int;
    fn CRYPTO_MUTEX_init(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_cleanup(lock: *mut CRYPTO_MUTEX);
    fn bn_set_static_words(bn: *mut BIGNUM, words: *const BN_ULONG, num: size_t);
    fn BN_MONT_CTX_set_locked(
        pmont: *mut *mut BN_MONT_CTX,
        lock: *mut CRYPTO_MUTEX,
        mod_0: *const BIGNUM,
        bn_ctx: *mut BN_CTX,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
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
pub type ENGINE = engine_st;
pub type EVP_MD = env_md_st;
#[inline]
unsafe extern "C" fn boringssl_ensure_ffdh_self_test() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_lock_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_unlock_state() {}
#[no_mangle]
pub unsafe extern "C" fn DH_new() -> *mut DH {
    let mut dh: *mut DH = OPENSSL_zalloc(::core::mem::size_of::<DH>() as libc::c_ulong)
        as *mut DH;
    if dh.is_null() {
        return 0 as *mut DH;
    }
    CRYPTO_MUTEX_init(&mut (*dh).method_mont_p_lock);
    (*dh).references = 1 as libc::c_int as CRYPTO_refcount_t;
    return dh;
}
#[no_mangle]
pub unsafe extern "C" fn DH_new_by_nid(mut nid: libc::c_int) -> *mut DH {
    match nid {
        976 => return DH_get_rfc7919_2048(),
        983 => return DH_get_rfc7919_3072(),
        977 => return DH_get_rfc7919_4096(),
        984 => return DH_get_rfc7919_8192(),
        _ => {
            ERR_put_error(
                5 as libc::c_int,
                0 as libc::c_int,
                106 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/dh/dh.c\0"
                    as *const u8 as *const libc::c_char,
                96 as libc::c_int as libc::c_uint,
            );
            return 0 as *mut DH;
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn DH_free(mut dh: *mut DH) {
    if dh.is_null() {
        return;
    }
    if CRYPTO_refcount_dec_and_test_zero(&mut (*dh).references) == 0 {
        return;
    }
    BN_MONT_CTX_free((*dh).method_mont_p);
    BN_clear_free((*dh).p);
    BN_clear_free((*dh).g);
    BN_clear_free((*dh).q);
    BN_clear_free((*dh).pub_key);
    BN_clear_free((*dh).priv_key);
    CRYPTO_MUTEX_cleanup(&mut (*dh).method_mont_p_lock);
    OPENSSL_free(dh as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn DH_bits(mut dh: *const DH) -> libc::c_uint {
    return BN_num_bits((*dh).p);
}
#[no_mangle]
pub unsafe extern "C" fn DH_get0_pub_key(mut dh: *const DH) -> *const BIGNUM {
    return (*dh).pub_key;
}
#[no_mangle]
pub unsafe extern "C" fn DH_get0_priv_key(mut dh: *const DH) -> *const BIGNUM {
    return (*dh).priv_key;
}
#[no_mangle]
pub unsafe extern "C" fn DH_get0_p(mut dh: *const DH) -> *const BIGNUM {
    return (*dh).p;
}
#[no_mangle]
pub unsafe extern "C" fn DH_get0_q(mut dh: *const DH) -> *const BIGNUM {
    return (*dh).q;
}
#[no_mangle]
pub unsafe extern "C" fn DH_get0_g(mut dh: *const DH) -> *const BIGNUM {
    return (*dh).g;
}
#[no_mangle]
pub unsafe extern "C" fn DH_get0_key(
    mut dh: *const DH,
    mut out_pub_key: *mut *const BIGNUM,
    mut out_priv_key: *mut *const BIGNUM,
) {
    if !out_pub_key.is_null() {
        *out_pub_key = (*dh).pub_key;
    }
    if !out_priv_key.is_null() {
        *out_priv_key = (*dh).priv_key;
    }
}
#[no_mangle]
pub unsafe extern "C" fn DH_clear_flags(mut dh: *mut DH, mut flags: libc::c_int) {}
#[no_mangle]
pub unsafe extern "C" fn DH_set0_key(
    mut dh: *mut DH,
    mut pub_key: *mut BIGNUM,
    mut priv_key: *mut BIGNUM,
) -> libc::c_int {
    if !pub_key.is_null() {
        BN_free((*dh).pub_key);
        (*dh).pub_key = pub_key;
    }
    if !priv_key.is_null() {
        BN_free((*dh).priv_key);
        (*dh).priv_key = priv_key;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn DH_get0_pqg(
    mut dh: *const DH,
    mut out_p: *mut *const BIGNUM,
    mut out_q: *mut *const BIGNUM,
    mut out_g: *mut *const BIGNUM,
) {
    if !out_p.is_null() {
        *out_p = (*dh).p;
    }
    if !out_q.is_null() {
        *out_q = (*dh).q;
    }
    if !out_g.is_null() {
        *out_g = (*dh).g;
    }
}
#[no_mangle]
pub unsafe extern "C" fn DH_set0_pqg(
    mut dh: *mut DH,
    mut p: *mut BIGNUM,
    mut q: *mut BIGNUM,
    mut g: *mut BIGNUM,
) -> libc::c_int {
    if ((*dh).p).is_null() && p.is_null() || ((*dh).g).is_null() && g.is_null() {
        return 0 as libc::c_int;
    }
    if !p.is_null() {
        BN_free((*dh).p);
        (*dh).p = p;
    }
    if !q.is_null() {
        BN_free((*dh).q);
        (*dh).q = q;
    }
    if !g.is_null() {
        BN_free((*dh).g);
        (*dh).g = g;
    }
    BN_MONT_CTX_free((*dh).method_mont_p);
    (*dh).method_mont_p = 0 as *mut BN_MONT_CTX;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn DH_set_length(
    mut dh: *mut DH,
    mut priv_length: libc::c_uint,
) -> libc::c_int {
    (*dh).priv_length = priv_length;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn DH_generate_key(mut dh: *mut DH) -> libc::c_int {
    let mut current_block: u64;
    boringssl_ensure_ffdh_self_test();
    if dh_check_params_fast(dh) == 0 {
        return 0 as libc::c_int;
    }
    let mut ok: libc::c_int = 0 as libc::c_int;
    let mut generate_new_key: libc::c_int = 0 as libc::c_int;
    let mut ctx: *mut BN_CTX = 0 as *mut BN_CTX;
    let mut pub_key: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut priv_key: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut priv_key_limit: *mut BIGNUM = 0 as *mut BIGNUM;
    ctx = BN_CTX_new();
    if !ctx.is_null() {
        if ((*dh).priv_key).is_null() {
            priv_key = BN_new();
            if priv_key.is_null() {
                current_block = 14327968567707444973;
            } else {
                generate_new_key = 1 as libc::c_int;
                current_block = 5399440093318478209;
            }
        } else {
            priv_key = (*dh).priv_key;
            current_block = 5399440093318478209;
        }
        match current_block {
            14327968567707444973 => {}
            _ => {
                if ((*dh).pub_key).is_null() {
                    pub_key = BN_new();
                    if pub_key.is_null() {
                        current_block = 14327968567707444973;
                    } else {
                        current_block = 4956146061682418353;
                    }
                } else {
                    pub_key = (*dh).pub_key;
                    current_block = 4956146061682418353;
                }
                match current_block {
                    14327968567707444973 => {}
                    _ => {
                        if !(BN_MONT_CTX_set_locked(
                            &mut (*dh).method_mont_p,
                            &mut (*dh).method_mont_p_lock,
                            (*dh).p,
                            ctx,
                        ) == 0)
                        {
                            if generate_new_key != 0 {
                                if !((*dh).q).is_null() {
                                    if BN_rand_range_ex(
                                        priv_key,
                                        1 as libc::c_int as BN_ULONG,
                                        (*dh).q,
                                    ) == 0
                                    {
                                        current_block = 14327968567707444973;
                                    } else {
                                        current_block = 2891135413264362348;
                                    }
                                } else {
                                    priv_key_limit = BN_new();
                                    if priv_key_limit.is_null() {
                                        current_block = 14327968567707444973;
                                    } else {
                                        if (*dh).priv_length == 0 as libc::c_int as libc::c_uint
                                            || (*dh).priv_length
                                                >= (BN_num_bits((*dh).p))
                                                    .wrapping_sub(1 as libc::c_int as libc::c_uint)
                                        {
                                            if BN_rshift1(priv_key_limit, (*dh).p) == 0 {
                                                current_block = 14327968567707444973;
                                            } else {
                                                current_block = 16924917904204750491;
                                            }
                                        } else if BN_set_bit(
                                            priv_key_limit,
                                            (*dh).priv_length as libc::c_int,
                                        ) == 0
                                        {
                                            current_block = 14327968567707444973;
                                        } else {
                                            current_block = 16924917904204750491;
                                        }
                                        match current_block {
                                            14327968567707444973 => {}
                                            _ => {
                                                if BN_rand_range_ex(
                                                    priv_key,
                                                    1 as libc::c_int as BN_ULONG,
                                                    priv_key_limit,
                                                ) == 0
                                                {
                                                    current_block = 14327968567707444973;
                                                } else {
                                                    current_block = 2891135413264362348;
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                current_block = 2891135413264362348;
                            }
                            match current_block {
                                14327968567707444973 => {}
                                _ => {
                                    if !(BN_mod_exp_mont_consttime(
                                        pub_key,
                                        (*dh).g,
                                        priv_key,
                                        (*dh).p,
                                        ctx,
                                        (*dh).method_mont_p,
                                    ) == 0)
                                    {
                                        (*dh).pub_key = pub_key;
                                        (*dh).priv_key = priv_key;
                                        ok = 1 as libc::c_int;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if ok != 1 as libc::c_int {
        ERR_put_error(
            5 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/dh/dh.c\0" as *const u8
                as *const libc::c_char,
            330 as libc::c_int as libc::c_uint,
        );
    }
    if ((*dh).pub_key).is_null() {
        BN_free(pub_key);
    }
    if ((*dh).priv_key).is_null() {
        BN_free(priv_key);
    }
    BN_free(priv_key_limit);
    BN_CTX_free(ctx);
    return ok;
}
unsafe extern "C" fn dh_compute_key(
    mut dh: *mut DH,
    mut out_shared_key: *mut BIGNUM,
    mut peers_key: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if dh_check_params_fast(dh) == 0 {
        return 0 as libc::c_int;
    }
    if ((*dh).priv_key).is_null() {
        ERR_put_error(
            5 as libc::c_int,
            0 as libc::c_int,
            103 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/dh/dh.c\0" as *const u8
                as *const libc::c_char,
            351 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut check_result: libc::c_int = 0;
    if DH_check_pub_key(dh, peers_key, &mut check_result) == 0 || check_result != 0 {
        ERR_put_error(
            5 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/dh/dh.c\0" as *const u8
                as *const libc::c_char,
            357 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    BN_CTX_start(ctx);
    let mut p_minus_1: *mut BIGNUM = BN_CTX_get(ctx);
    if !(p_minus_1.is_null()
        || BN_MONT_CTX_set_locked(
            &mut (*dh).method_mont_p,
            &mut (*dh).method_mont_p_lock,
            (*dh).p,
            ctx,
        ) == 0)
    {
        if BN_mod_exp_mont_consttime(
            out_shared_key,
            peers_key,
            (*dh).priv_key,
            (*dh).p,
            ctx,
            (*dh).method_mont_p,
        ) == 0 || (BN_copy(p_minus_1, (*dh).p)).is_null()
            || BN_sub_word(p_minus_1, 1 as libc::c_int as BN_ULONG) == 0
        {
            ERR_put_error(
                5 as libc::c_int,
                0 as libc::c_int,
                3 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/dh/dh.c\0"
                    as *const u8 as *const libc::c_char,
                375 as libc::c_int as libc::c_uint,
            );
        } else if BN_cmp_word(out_shared_key, 1 as libc::c_int as BN_ULONG)
            <= 0 as libc::c_int || BN_cmp(out_shared_key, p_minus_1) == 0 as libc::c_int
        {
            ERR_put_error(
                5 as libc::c_int,
                0 as libc::c_int,
                101 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/dh/dh.c\0"
                    as *const u8 as *const libc::c_char,
                382 as libc::c_int as libc::c_uint,
            );
        } else {
            ret = 1 as libc::c_int;
        }
    }
    BN_CTX_end(ctx);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn dh_compute_key_padded_no_self_test(
    mut out: *mut libc::c_uchar,
    mut peers_key: *const BIGNUM,
    mut dh: *mut DH,
) -> libc::c_int {
    let mut ctx: *mut BN_CTX = BN_CTX_new();
    if ctx.is_null() {
        return -(1 as libc::c_int);
    }
    BN_CTX_start(ctx);
    let mut dh_size: libc::c_int = DH_size(dh);
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut shared_key: *mut BIGNUM = BN_CTX_get(ctx);
    if !shared_key.is_null() && dh_compute_key(dh, shared_key, peers_key, ctx) != 0
        && BN_bn2bin_padded(out, dh_size as size_t, shared_key) != 0
    {
        ret = dh_size;
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn DH_compute_key_padded(
    mut out: *mut libc::c_uchar,
    mut peers_key: *const BIGNUM,
    mut dh: *mut DH,
) -> libc::c_int {
    boringssl_ensure_ffdh_self_test();
    return dh_compute_key_padded_no_self_test(out, peers_key, dh);
}
#[no_mangle]
pub unsafe extern "C" fn DH_compute_key(
    mut out: *mut libc::c_uchar,
    mut peers_key: *const BIGNUM,
    mut dh: *mut DH,
) -> libc::c_int {
    boringssl_ensure_ffdh_self_test();
    let mut ctx: *mut BN_CTX = BN_CTX_new();
    if ctx.is_null() {
        return -(1 as libc::c_int);
    }
    BN_CTX_start(ctx);
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut shared_key: *mut BIGNUM = BN_CTX_get(ctx);
    if !shared_key.is_null() && dh_compute_key(dh, shared_key, peers_key, ctx) != 0 {
        ret = BN_bn2bin(shared_key, out) as libc::c_int;
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn DH_compute_key_hashed(
    mut dh: *mut DH,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
    mut max_out_len: size_t,
    mut peers_key: *const BIGNUM,
    mut digest: *const EVP_MD,
) -> libc::c_int {
    *out_len = 18446744073709551615 as libc::c_ulong;
    let digest_len: size_t = EVP_MD_size(digest);
    if digest_len > max_out_len {
        return 0 as libc::c_int;
    }
    FIPS_service_indicator_lock_state();
    let mut ret: libc::c_int = 0 as libc::c_int;
    let dh_len: size_t = DH_size(dh) as size_t;
    let mut shared_bytes: *mut uint8_t = OPENSSL_malloc(dh_len) as *mut uint8_t;
    let mut out_len_unsigned: libc::c_uint = 0;
    if !(shared_bytes.is_null()
        || DH_compute_key_padded(shared_bytes, peers_key, dh) != dh_len as libc::c_int
        || EVP_Digest(
            shared_bytes as *const libc::c_void,
            dh_len,
            out,
            &mut out_len_unsigned,
            digest,
            0 as *mut ENGINE,
        ) == 0 || out_len_unsigned as size_t != digest_len)
    {
        *out_len = digest_len;
        ret = 1 as libc::c_int;
    }
    FIPS_service_indicator_unlock_state();
    OPENSSL_free(shared_bytes as *mut libc::c_void);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn DH_size(mut dh: *const DH) -> libc::c_int {
    return BN_num_bytes((*dh).p) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn DH_num_bits(mut dh: *const DH) -> libc::c_uint {
    return BN_num_bits((*dh).p);
}
#[no_mangle]
pub unsafe extern "C" fn DH_up_ref(mut dh: *mut DH) -> libc::c_int {
    CRYPTO_refcount_inc(&mut (*dh).references);
    return 1 as libc::c_int;
}
unsafe extern "C" fn calculate_rfc7919_DH_from_p(
    mut data: *const BN_ULONG,
    mut data_len: size_t,
) -> *mut DH {
    let ffdhe_p: *mut BIGNUM = BN_new();
    let ffdhe_q: *mut BIGNUM = BN_new();
    let ffdhe_g: *mut BIGNUM = BN_new();
    let dh: *mut DH = DH_new();
    if !(ffdhe_p.is_null() || ffdhe_q.is_null() || ffdhe_g.is_null() || dh.is_null()) {
        bn_set_static_words(ffdhe_p, data, data_len);
        if !(BN_rshift1(ffdhe_q, ffdhe_p) == 0
            || BN_set_word(ffdhe_g, 2 as libc::c_int as BN_ULONG) == 0
            || DH_set0_pqg(dh, ffdhe_p, ffdhe_q, ffdhe_g) == 0)
        {
            return dh;
        }
    }
    BN_free(ffdhe_p);
    BN_free(ffdhe_q);
    BN_free(ffdhe_g);
    DH_free(dh);
    return 0 as *mut DH;
}
#[no_mangle]
pub unsafe extern "C" fn DH_get_rfc7919_2048() -> *mut DH {
    static mut kFFDHE2048Data: [BN_ULONG; 32] = [
        (0xffffffff as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xffffffff as libc::c_uint as BN_ULONG,
        (0x886b4238 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x61285c97 as libc::c_int as BN_ULONG,
        (0xc6f34a26 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xc1b2effa as libc::c_uint as BN_ULONG,
        (0xc58ef183 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7d1683b2 as libc::c_int as BN_ULONG,
        (0x3bb5fcbc as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x2ec22005 as libc::c_int as BN_ULONG,
        (0xc3fe3b1b as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x4c6fad73 as libc::c_int as BN_ULONG,
        (0x8e4f1232 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xeef28183 as libc::c_uint as BN_ULONG,
        (0x9172fe9c as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xe98583ff as libc::c_uint as BN_ULONG,
        (0xc03404cd as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x28342f61 as libc::c_int as BN_ULONG,
        (0x9e02fce1 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xcdf7e2ec as libc::c_uint as BN_ULONG,
        (0xb07a7c8 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xee0a6d70 as libc::c_uint as BN_ULONG,
        (0xae56ede7 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x6372bb19 as libc::c_int as BN_ULONG,
        (0x1d4f42a3 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xde394df4 as libc::c_uint as BN_ULONG,
        (0xb96adab7 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x60d7f468 as libc::c_int as BN_ULONG,
        (0xd108a94b as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xb2c8e3fb as libc::c_uint as BN_ULONG,
        (0xbc0ab182 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xb324fb61 as libc::c_uint as BN_ULONG,
        (0x30acca4f as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x483a797a as libc::c_int as BN_ULONG,
        (0x1df158a1 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x36ade735 as libc::c_int as BN_ULONG,
        (0xe2a689da as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xf3efe872 as libc::c_uint as BN_ULONG,
        (0x984f0c70 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xe0e68b77 as libc::c_uint as BN_ULONG,
        (0xb557135e as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7f57c935 as libc::c_int as BN_ULONG,
        (0x85636555 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x3ded1af3 as libc::c_int as BN_ULONG,
        (0x2433f51f as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x5f066ed0 as libc::c_int as BN_ULONG,
        (0xd3df1ed5 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xd5fd6561 as libc::c_uint as BN_ULONG,
        (0xf681b202 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xaec4617a as libc::c_uint as BN_ULONG,
        (0x7d2fe363 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x630c75d8 as libc::c_int as BN_ULONG,
        (0xcc939dce as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x249b3ef9 as libc::c_int as BN_ULONG,
        (0xa9e13641 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x146433fb as libc::c_int as BN_ULONG,
        (0xd8b9c583 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xce2d3695 as libc::c_uint as BN_ULONG,
        (0xafdc5620 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x273d3cf1 as libc::c_int as BN_ULONG,
        (0xadf85458 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa2bb4a9a as libc::c_uint as BN_ULONG,
        (0xffffffff as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xffffffff as libc::c_uint as BN_ULONG,
    ];
    return calculate_rfc7919_DH_from_p(
        kFFDHE2048Data.as_ptr(),
        (::core::mem::size_of::<[BN_ULONG; 32]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    );
}
#[no_mangle]
pub unsafe extern "C" fn DH_get_rfc7919_3072() -> *mut DH {
    static mut kFFDHE3072Data: [BN_ULONG; 48] = [
        (0xffffffff as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xffffffff as libc::c_uint as BN_ULONG,
        (0x25e41d2b as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x66c62e37 as libc::c_int as BN_ULONG,
        (0x3c1b20ee as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x3fd59d7c as libc::c_int as BN_ULONG,
        (0xabcd06b as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xfa53ddef as libc::c_uint as BN_ULONG,
        (0x1dbf9a42 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xd5c4484e as libc::c_uint as BN_ULONG,
        (0xabc52197 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x9b0deada as libc::c_uint as BN_ULONG,
        (0xe86d2bc5 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x22363a0d as libc::c_int as BN_ULONG,
        (0x5cae82ab as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x9c9df69e as libc::c_uint as BN_ULONG,
        (0x64f2e21e as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x71f54bff as libc::c_int as BN_ULONG,
        (0xf4fd4452 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xe2d74dd3 as libc::c_uint as BN_ULONG,
        (0xb4130c93 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xbc437944 as libc::c_uint as BN_ULONG,
        (0xaefe1309 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x85139270 as libc::c_uint as BN_ULONG,
        (0x598cb0fa as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xc186d91c as libc::c_uint as BN_ULONG,
        (0x7ad91d26 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x91f7f7ee as libc::c_uint as BN_ULONG,
        (0x61b46fc9 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xd6e6c907 as libc::c_uint as BN_ULONG,
        (0xbc34f4de as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xf99c0238 as libc::c_uint as BN_ULONG,
        (0xde355b3b as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x6519035b as libc::c_int as BN_ULONG,
        (0x886b4238 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x611fcfdc as libc::c_int as BN_ULONG,
        (0xc6f34a26 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xc1b2effa as libc::c_uint as BN_ULONG,
        (0xc58ef183 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7d1683b2 as libc::c_int as BN_ULONG,
        (0x3bb5fcbc as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x2ec22005 as libc::c_int as BN_ULONG,
        (0xc3fe3b1b as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x4c6fad73 as libc::c_int as BN_ULONG,
        (0x8e4f1232 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xeef28183 as libc::c_uint as BN_ULONG,
        (0x9172fe9c as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xe98583ff as libc::c_uint as BN_ULONG,
        (0xc03404cd as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x28342f61 as libc::c_int as BN_ULONG,
        (0x9e02fce1 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xcdf7e2ec as libc::c_uint as BN_ULONG,
        (0xb07a7c8 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xee0a6d70 as libc::c_uint as BN_ULONG,
        (0xae56ede7 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x6372bb19 as libc::c_int as BN_ULONG,
        (0x1d4f42a3 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xde394df4 as libc::c_uint as BN_ULONG,
        (0xb96adab7 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x60d7f468 as libc::c_int as BN_ULONG,
        (0xd108a94b as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xb2c8e3fb as libc::c_uint as BN_ULONG,
        (0xbc0ab182 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xb324fb61 as libc::c_uint as BN_ULONG,
        (0x30acca4f as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x483a797a as libc::c_int as BN_ULONG,
        (0x1df158a1 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x36ade735 as libc::c_int as BN_ULONG,
        (0xe2a689da as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xf3efe872 as libc::c_uint as BN_ULONG,
        (0x984f0c70 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xe0e68b77 as libc::c_uint as BN_ULONG,
        (0xb557135e as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7f57c935 as libc::c_int as BN_ULONG,
        (0x85636555 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x3ded1af3 as libc::c_int as BN_ULONG,
        (0x2433f51f as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x5f066ed0 as libc::c_int as BN_ULONG,
        (0xd3df1ed5 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xd5fd6561 as libc::c_uint as BN_ULONG,
        (0xf681b202 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xaec4617a as libc::c_uint as BN_ULONG,
        (0x7d2fe363 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x630c75d8 as libc::c_int as BN_ULONG,
        (0xcc939dce as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x249b3ef9 as libc::c_int as BN_ULONG,
        (0xa9e13641 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x146433fb as libc::c_int as BN_ULONG,
        (0xd8b9c583 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xce2d3695 as libc::c_uint as BN_ULONG,
        (0xafdc5620 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x273d3cf1 as libc::c_int as BN_ULONG,
        (0xadf85458 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa2bb4a9a as libc::c_uint as BN_ULONG,
        (0xffffffff as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xffffffff as libc::c_uint as BN_ULONG,
    ];
    return calculate_rfc7919_DH_from_p(
        kFFDHE3072Data.as_ptr(),
        (::core::mem::size_of::<[BN_ULONG; 48]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    );
}
#[no_mangle]
pub unsafe extern "C" fn DH_get_rfc7919_4096() -> *mut DH {
    static mut kFFDHE4096Data: [BN_ULONG; 64] = [
        (0xffffffff as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xffffffff as libc::c_uint as BN_ULONG,
        (0xc68a007e as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x5e655f6a as libc::c_int as BN_ULONG,
        (0x4db5a851 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xf44182e1 as libc::c_uint as BN_ULONG,
        (0x8ec9b55a as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7f88a46b as libc::c_int as BN_ULONG,
        (0xa8291cd as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xcec97dcf as libc::c_uint as BN_ULONG,
        (0x2a4ecea9 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xf98d0acc as libc::c_uint as BN_ULONG,
        (0x1a1db93d as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x7140003c as libc::c_int as BN_ULONG,
        (0x92999a3 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x33cb8b7a as libc::c_int as BN_ULONG,
        (0x6dc778f9 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x71ad0038 as libc::c_int as BN_ULONG,
        (0xa907600a as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x918130c4 as libc::c_uint as BN_ULONG,
        (0xed6a1e01 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x2d9e6832 as libc::c_int as BN_ULONG,
        (0x7135c886 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xefb4318a as libc::c_uint as BN_ULONG,
        (0x87f55ba5 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7e31cc7a as libc::c_int as BN_ULONG,
        (0x7763cf1d as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x55034004 as libc::c_int as BN_ULONG,
        (0xac7d5f42 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xd69f6d18 as libc::c_uint as BN_ULONG,
        (0x7930e9e4 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xe58857b6 as libc::c_uint as BN_ULONG,
        (0x6e6f52c3 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x164df4fb as libc::c_int as BN_ULONG,
        (0x25e41d2b as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x669e1ef1 as libc::c_int as BN_ULONG,
        (0x3c1b20ee as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x3fd59d7c as libc::c_int as BN_ULONG,
        (0xabcd06b as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xfa53ddef as libc::c_uint as BN_ULONG,
        (0x1dbf9a42 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xd5c4484e as libc::c_uint as BN_ULONG,
        (0xabc52197 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x9b0deada as libc::c_uint as BN_ULONG,
        (0xe86d2bc5 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x22363a0d as libc::c_int as BN_ULONG,
        (0x5cae82ab as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x9c9df69e as libc::c_uint as BN_ULONG,
        (0x64f2e21e as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x71f54bff as libc::c_int as BN_ULONG,
        (0xf4fd4452 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xe2d74dd3 as libc::c_uint as BN_ULONG,
        (0xb4130c93 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xbc437944 as libc::c_uint as BN_ULONG,
        (0xaefe1309 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x85139270 as libc::c_uint as BN_ULONG,
        (0x598cb0fa as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xc186d91c as libc::c_uint as BN_ULONG,
        (0x7ad91d26 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x91f7f7ee as libc::c_uint as BN_ULONG,
        (0x61b46fc9 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xd6e6c907 as libc::c_uint as BN_ULONG,
        (0xbc34f4de as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xf99c0238 as libc::c_uint as BN_ULONG,
        (0xde355b3b as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x6519035b as libc::c_int as BN_ULONG,
        (0x886b4238 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x611fcfdc as libc::c_int as BN_ULONG,
        (0xc6f34a26 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xc1b2effa as libc::c_uint as BN_ULONG,
        (0xc58ef183 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7d1683b2 as libc::c_int as BN_ULONG,
        (0x3bb5fcbc as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x2ec22005 as libc::c_int as BN_ULONG,
        (0xc3fe3b1b as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x4c6fad73 as libc::c_int as BN_ULONG,
        (0x8e4f1232 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xeef28183 as libc::c_uint as BN_ULONG,
        (0x9172fe9c as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xe98583ff as libc::c_uint as BN_ULONG,
        (0xc03404cd as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x28342f61 as libc::c_int as BN_ULONG,
        (0x9e02fce1 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xcdf7e2ec as libc::c_uint as BN_ULONG,
        (0xb07a7c8 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xee0a6d70 as libc::c_uint as BN_ULONG,
        (0xae56ede7 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x6372bb19 as libc::c_int as BN_ULONG,
        (0x1d4f42a3 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xde394df4 as libc::c_uint as BN_ULONG,
        (0xb96adab7 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x60d7f468 as libc::c_int as BN_ULONG,
        (0xd108a94b as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xb2c8e3fb as libc::c_uint as BN_ULONG,
        (0xbc0ab182 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xb324fb61 as libc::c_uint as BN_ULONG,
        (0x30acca4f as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x483a797a as libc::c_int as BN_ULONG,
        (0x1df158a1 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x36ade735 as libc::c_int as BN_ULONG,
        (0xe2a689da as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xf3efe872 as libc::c_uint as BN_ULONG,
        (0x984f0c70 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xe0e68b77 as libc::c_uint as BN_ULONG,
        (0xb557135e as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7f57c935 as libc::c_int as BN_ULONG,
        (0x85636555 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x3ded1af3 as libc::c_int as BN_ULONG,
        (0x2433f51f as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x5f066ed0 as libc::c_int as BN_ULONG,
        (0xd3df1ed5 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xd5fd6561 as libc::c_uint as BN_ULONG,
        (0xf681b202 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xaec4617a as libc::c_uint as BN_ULONG,
        (0x7d2fe363 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x630c75d8 as libc::c_int as BN_ULONG,
        (0xcc939dce as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x249b3ef9 as libc::c_int as BN_ULONG,
        (0xa9e13641 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x146433fb as libc::c_int as BN_ULONG,
        (0xd8b9c583 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xce2d3695 as libc::c_uint as BN_ULONG,
        (0xafdc5620 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x273d3cf1 as libc::c_int as BN_ULONG,
        (0xadf85458 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa2bb4a9a as libc::c_uint as BN_ULONG,
        (0xffffffff as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xffffffff as libc::c_uint as BN_ULONG,
    ];
    return calculate_rfc7919_DH_from_p(
        kFFDHE4096Data.as_ptr(),
        (::core::mem::size_of::<[BN_ULONG; 64]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    );
}
#[no_mangle]
pub unsafe extern "C" fn DH_get_rfc7919_8192() -> *mut DH {
    static mut kFFDHE8192Data: [BN_ULONG; 128] = [
        (0xffffffff as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xffffffff as libc::c_uint as BN_ULONG,
        (0xd68c8bb7 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xc5c6424c as libc::c_uint as BN_ULONG,
        (0x11e2a94 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x838ff88c as libc::c_uint as BN_ULONG,
        (0x822e506 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xa9f4614e as libc::c_uint as BN_ULONG,
        (0x97d11d49 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xf7a8443d as libc::c_uint as BN_ULONG,
        (0xa6bbfde5 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x30677f0d as libc::c_int as BN_ULONG,
        (0x2f741ef8 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xc1fe86fe as libc::c_uint as BN_ULONG,
        (0xfafabe1c as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x5d71a87e as libc::c_int as BN_ULONG,
        (0xded2fbab as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xfbe58a30 as libc::c_uint as BN_ULONG,
        (0xb6855dfe as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x72b0a66e as libc::c_int as BN_ULONG,
        (0x1efc8ce0 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xba8a4fe8 as libc::c_uint as BN_ULONG,
        (0x83f81d4a as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x3f2fa457 as libc::c_int as BN_ULONG,
        (0xa1fe3075 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa577e231 as libc::c_uint as BN_ULONG,
        (0xd5b80194 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x88d9c0a0 as libc::c_uint as BN_ULONG,
        (0x624816cd as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xad9a95f9 as libc::c_uint as BN_ULONG,
        (0x99e9e316 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x50c1217b as libc::c_int as BN_ULONG,
        (0x51aa691e as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xe423cfc as libc::c_int as BN_ULONG,
        (0x1c217e6c as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x3826e52c as libc::c_int as BN_ULONG,
        (0x51a8a931 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x9703fee as libc::c_int as BN_ULONG,
        (0xbb709987 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x6a460e74 as libc::c_int as BN_ULONG,
        (0x541fc68c as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x9c86b022 as libc::c_uint as BN_ULONG,
        (0x59160cc0 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x46fd8251 as libc::c_int as BN_ULONG,
        (0x2846c0ba as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x35c35f5c as libc::c_int as BN_ULONG,
        (0x54504ac7 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x8b758282 as libc::c_uint as BN_ULONG,
        (0x29388839 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xd2af05e4 as libc::c_uint as BN_ULONG,
        (0xcb2c0f1c as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xc01bd702 as libc::c_uint as BN_ULONG,
        (0x555b2f74 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x7c932665 as libc::c_int as BN_ULONG,
        (0x86b63142 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa3ab8829 as libc::c_uint as BN_ULONG,
        (0xb8cc3bd as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xf64b10ef as libc::c_uint as BN_ULONG,
        (0x687feb69 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xedd1cc5e as libc::c_uint as BN_ULONG,
        (0xfdb23fce as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xc9509d43 as libc::c_uint as BN_ULONG,
        (0x1e425a31 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xd951ae64 as libc::c_uint as BN_ULONG,
        (0x36ad004c as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xf600c838 as libc::c_uint as BN_ULONG,
        (0xa40e329c as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xcff46aaa as libc::c_uint as BN_ULONG,
        (0xa41d570d as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7938dad4 as libc::c_int as BN_ULONG,
        (0x62a69526 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xd43161c1 as libc::c_uint as BN_ULONG,
        (0x3fdd4a8e as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x9adb1e69 as libc::c_uint as BN_ULONG,
        (0x5b3b71f9 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xdc6b80d6 as libc::c_uint as BN_ULONG,
        (0xec9d1810 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xc6272b04 as libc::c_uint as BN_ULONG,
        (0x8ccf2dd5 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xcacef403 as libc::c_uint as BN_ULONG,
        (0xe49f5235 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xc95b9117 as libc::c_uint as BN_ULONG,
        (0x505dc82d as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xb854338a as libc::c_uint as BN_ULONG,
        (0x62292c31 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x1562a846 as libc::c_int as BN_ULONG,
        (0xd72b0374 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x6ae77f5e as libc::c_int as BN_ULONG,
        (0xf9c9091b as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x462d538c as libc::c_int as BN_ULONG,
        (0xae8db58 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x47a67cbe as libc::c_int as BN_ULONG,
        (0xb3a739c1 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x22611682 as libc::c_int as BN_ULONG,
        (0xeeaac023 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x2a281bf6 as libc::c_int as BN_ULONG,
        (0x94c6651e as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x77caf992 as libc::c_int as BN_ULONG,
        (0x763e4e4b as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x94b2bbc1 as libc::c_uint as BN_ULONG,
        (0x587e38da as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x77d9b4 as libc::c_int as BN_ULONG,
        (0x7fb29f8c as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x183023c3 as libc::c_int as BN_ULONG,
        (0xabec1ff as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xf9e3a26e as libc::c_uint as BN_ULONG,
        (0xa00ef092 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x350511e3 as libc::c_int as BN_ULONG,
        (0xb855322e as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xdb6340d8 as libc::c_uint as BN_ULONG,
        (0xa52471f7 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa9a96910 as libc::c_uint as BN_ULONG,
        (0x388147fb as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x4cfdb477 as libc::c_int as BN_ULONG,
        (0x9b1f5c3e as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x4e46041f as libc::c_int as BN_ULONG,
        (0xcdad0657 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xfccfec71 as libc::c_uint as BN_ULONG,
        (0xb38e8c33 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x4c701c3a as libc::c_int as BN_ULONG,
        (0x917bdd64 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xb1c0fd4c as libc::c_uint as BN_ULONG,
        (0x3bb45432 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x9b7624c8 as libc::c_uint as BN_ULONG,
        (0x23ba4442 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xcaf53ea6 as libc::c_uint as BN_ULONG,
        (0x4e677d2c as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x38532a3a as libc::c_int as BN_ULONG,
        (0xbfd64b6 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x45036c7a as libc::c_int as BN_ULONG,
        (0xc68a007e as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x5e0dd902 as libc::c_int as BN_ULONG,
        (0x4db5a851 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xf44182e1 as libc::c_uint as BN_ULONG,
        (0x8ec9b55a as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7f88a46b as libc::c_int as BN_ULONG,
        (0xa8291cd as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xcec97dcf as libc::c_uint as BN_ULONG,
        (0x2a4ecea9 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xf98d0acc as libc::c_uint as BN_ULONG,
        (0x1a1db93d as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x7140003c as libc::c_int as BN_ULONG,
        (0x92999a3 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x33cb8b7a as libc::c_int as BN_ULONG,
        (0x6dc778f9 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x71ad0038 as libc::c_int as BN_ULONG,
        (0xa907600a as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x918130c4 as libc::c_uint as BN_ULONG,
        (0xed6a1e01 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x2d9e6832 as libc::c_int as BN_ULONG,
        (0x7135c886 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xefb4318a as libc::c_uint as BN_ULONG,
        (0x87f55ba5 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7e31cc7a as libc::c_int as BN_ULONG,
        (0x7763cf1d as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x55034004 as libc::c_int as BN_ULONG,
        (0xac7d5f42 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xd69f6d18 as libc::c_uint as BN_ULONG,
        (0x7930e9e4 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xe58857b6 as libc::c_uint as BN_ULONG,
        (0x6e6f52c3 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x164df4fb as libc::c_int as BN_ULONG,
        (0x25e41d2b as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x669e1ef1 as libc::c_int as BN_ULONG,
        (0x3c1b20ee as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x3fd59d7c as libc::c_int as BN_ULONG,
        (0xabcd06b as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xfa53ddef as libc::c_uint as BN_ULONG,
        (0x1dbf9a42 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xd5c4484e as libc::c_uint as BN_ULONG,
        (0xabc52197 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x9b0deada as libc::c_uint as BN_ULONG,
        (0xe86d2bc5 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x22363a0d as libc::c_int as BN_ULONG,
        (0x5cae82ab as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x9c9df69e as libc::c_uint as BN_ULONG,
        (0x64f2e21e as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x71f54bff as libc::c_int as BN_ULONG,
        (0xf4fd4452 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xe2d74dd3 as libc::c_uint as BN_ULONG,
        (0xb4130c93 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xbc437944 as libc::c_uint as BN_ULONG,
        (0xaefe1309 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x85139270 as libc::c_uint as BN_ULONG,
        (0x598cb0fa as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xc186d91c as libc::c_uint as BN_ULONG,
        (0x7ad91d26 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x91f7f7ee as libc::c_uint as BN_ULONG,
        (0x61b46fc9 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xd6e6c907 as libc::c_uint as BN_ULONG,
        (0xbc34f4de as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xf99c0238 as libc::c_uint as BN_ULONG,
        (0xde355b3b as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x6519035b as libc::c_int as BN_ULONG,
        (0x886b4238 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x611fcfdc as libc::c_int as BN_ULONG,
        (0xc6f34a26 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xc1b2effa as libc::c_uint as BN_ULONG,
        (0xc58ef183 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7d1683b2 as libc::c_int as BN_ULONG,
        (0x3bb5fcbc as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x2ec22005 as libc::c_int as BN_ULONG,
        (0xc3fe3b1b as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x4c6fad73 as libc::c_int as BN_ULONG,
        (0x8e4f1232 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xeef28183 as libc::c_uint as BN_ULONG,
        (0x9172fe9c as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xe98583ff as libc::c_uint as BN_ULONG,
        (0xc03404cd as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x28342f61 as libc::c_int as BN_ULONG,
        (0x9e02fce1 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xcdf7e2ec as libc::c_uint as BN_ULONG,
        (0xb07a7c8 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xee0a6d70 as libc::c_uint as BN_ULONG,
        (0xae56ede7 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x6372bb19 as libc::c_int as BN_ULONG,
        (0x1d4f42a3 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xde394df4 as libc::c_uint as BN_ULONG,
        (0xb96adab7 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x60d7f468 as libc::c_int as BN_ULONG,
        (0xd108a94b as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xb2c8e3fb as libc::c_uint as BN_ULONG,
        (0xbc0ab182 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xb324fb61 as libc::c_uint as BN_ULONG,
        (0x30acca4f as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x483a797a as libc::c_int as BN_ULONG,
        (0x1df158a1 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x36ade735 as libc::c_int as BN_ULONG,
        (0xe2a689da as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xf3efe872 as libc::c_uint as BN_ULONG,
        (0x984f0c70 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xe0e68b77 as libc::c_uint as BN_ULONG,
        (0xb557135e as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7f57c935 as libc::c_int as BN_ULONG,
        (0x85636555 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x3ded1af3 as libc::c_int as BN_ULONG,
        (0x2433f51f as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x5f066ed0 as libc::c_int as BN_ULONG,
        (0xd3df1ed5 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xd5fd6561 as libc::c_uint as BN_ULONG,
        (0xf681b202 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xaec4617a as libc::c_uint as BN_ULONG,
        (0x7d2fe363 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x630c75d8 as libc::c_int as BN_ULONG,
        (0xcc939dce as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x249b3ef9 as libc::c_int as BN_ULONG,
        (0xa9e13641 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x146433fb as libc::c_int as BN_ULONG,
        (0xd8b9c583 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xce2d3695 as libc::c_uint as BN_ULONG,
        (0xafdc5620 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x273d3cf1 as libc::c_int as BN_ULONG,
        (0xadf85458 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa2bb4a9a as libc::c_uint as BN_ULONG,
        (0xffffffff as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xffffffff as libc::c_uint as BN_ULONG,
    ];
    return calculate_rfc7919_DH_from_p(
        kFFDHE8192Data.as_ptr(),
        (::core::mem::size_of::<[BN_ULONG; 128]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    );
}
