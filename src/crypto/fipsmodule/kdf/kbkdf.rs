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
    pub type engine_st;
    pub type env_md_st;
    pub type hmac_methods_st;
    fn HMAC_CTX_init(ctx: *mut HMAC_CTX);
    fn HMAC_CTX_cleanup(ctx: *mut HMAC_CTX);
    fn HMAC_Init_ex(
        ctx: *mut HMAC_CTX,
        key: *const libc::c_void,
        key_len: size_t,
        md: *const EVP_MD,
        impl_0: *mut ENGINE,
    ) -> libc::c_int;
    fn HMAC_Update(
        ctx: *mut HMAC_CTX,
        data: *const uint8_t,
        data_len: size_t,
    ) -> libc::c_int;
    fn HMAC_Final(
        ctx: *mut HMAC_CTX,
        out: *mut uint8_t,
        out_len: *mut libc::c_uint,
    ) -> libc::c_int;
    fn HMAC_size(ctx: *const HMAC_CTX) -> size_t;
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
}
pub type size_t = libc::c_ulong;
pub type __int8_t = libc::c_schar;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type int8_t = __int8_t;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type ENGINE = engine_st;
pub type EVP_MD = env_md_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hmac_ctx_st {
    pub md: *const EVP_MD,
    pub methods: *const HmacMethods,
    pub md_ctx: md_ctx_union,
    pub i_ctx: md_ctx_union,
    pub o_ctx: md_ctx_union,
    pub state: int8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union md_ctx_union {
    pub md5: MD5_CTX,
    pub sha1: SHA_CTX,
    pub sha256: SHA256_CTX,
    pub sha512: SHA512_CTX,
}
pub type SHA512_CTX = sha512_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sha512_state_st {
    pub h: [uint64_t; 8],
    pub Nl: uint64_t,
    pub Nh: uint64_t,
    pub p: [uint8_t; 128],
    pub num: libc::c_uint,
    pub md_len: libc::c_uint,
}
pub type SHA256_CTX = sha256_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sha256_state_st {
    pub h: [uint32_t; 8],
    pub Nl: uint32_t,
    pub Nh: uint32_t,
    pub data: [uint8_t; 64],
    pub num: libc::c_uint,
    pub md_len: libc::c_uint,
}
pub type SHA_CTX = sha_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sha_state_st {
    pub h: [uint32_t; 5],
    pub Nl: uint32_t,
    pub Nh: uint32_t,
    pub data: [uint8_t; 64],
    pub num: libc::c_uint,
}
pub type MD5_CTX = md5_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct md5_state_st {
    pub h: [uint32_t; 4],
    pub Nl: uint32_t,
    pub Nh: uint32_t,
    pub data: [uint8_t; 64],
    pub num: libc::c_uint,
}
pub type HmacMethods = hmac_methods_st;
pub type HMAC_CTX = hmac_ctx_st;
#[inline]
unsafe extern "C" fn CRYPTO_bswap4(mut x: uint32_t) -> uint32_t {
    return x.swap_bytes();
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
unsafe extern "C" fn CRYPTO_store_u32_be(mut out: *mut libc::c_void, mut v: uint32_t) {
    v = CRYPTO_bswap4(v);
    OPENSSL_memcpy(
        out,
        &mut v as *mut uint32_t as *const libc::c_void,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_lock_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_unlock_state() {}
#[inline]
unsafe extern "C" fn KBKDF_ctr_hmac_verify_service_indicator(
    mut dgst: *const EVP_MD,
    mut secret_len: size_t,
) {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn KBKDF_ctr_hmac(
    mut out_key: *mut uint8_t,
    mut out_len: size_t,
    mut digest: *const EVP_MD,
    mut secret: *const uint8_t,
    mut secret_len: size_t,
    mut info: *const uint8_t,
    mut info_len: size_t,
) -> libc::c_int {
    let mut h_output_bytes: size_t = 0;
    let mut n: uint64_t = 0;
    let mut out_key_i: [uint8_t; 64] = [0; 64];
    let mut counter: [uint8_t; 4] = [0; 4];
    let mut done: size_t = 0;
    let mut written: uint32_t = 0;
    let mut current_block: u64;
    FIPS_service_indicator_lock_state();
    let mut hmac_ctx: HMAC_CTX = hmac_ctx_st {
        md: 0 as *const EVP_MD,
        methods: 0 as *const HmacMethods,
        md_ctx: md_ctx_union {
            md5: md5_state_st {
                h: [0; 4],
                Nl: 0,
                Nh: 0,
                data: [0; 64],
                num: 0,
            },
        },
        i_ctx: md_ctx_union {
            md5: md5_state_st {
                h: [0; 4],
                Nl: 0,
                Nh: 0,
                data: [0; 64],
                num: 0,
            },
        },
        o_ctx: md_ctx_union {
            md5: md5_state_st {
                h: [0; 4],
                Nl: 0,
                Nh: 0,
                data: [0; 64],
                num: 0,
            },
        },
        state: 0,
    };
    let mut ret: libc::c_int = 0 as libc::c_int;
    if !(out_key.is_null() || out_len == 0 as libc::c_int as size_t || secret.is_null()
        || secret_len == 0 as libc::c_int as size_t)
    {
        HMAC_CTX_init(&mut hmac_ctx);
        if !(HMAC_Init_ex(
            &mut hmac_ctx,
            secret as *const libc::c_void,
            secret_len,
            digest,
            0 as *mut ENGINE,
        ) == 0)
        {
            h_output_bytes = HMAC_size(&mut hmac_ctx);
            if !(h_output_bytes == 0 as libc::c_int as size_t
                || h_output_bytes > 64 as libc::c_int as size_t)
            {
                if !(out_len
                    > (18446744073709551615 as libc::c_ulong)
                        .wrapping_sub(h_output_bytes))
                {
                    n = out_len
                        .wrapping_add(h_output_bytes)
                        .wrapping_sub(1 as libc::c_int as uint64_t) / h_output_bytes;
                    if !(n > 4294967295 as libc::c_uint as uint64_t) {
                        out_key_i = [0; 64];
                        counter = [0; 4];
                        done = 0 as libc::c_int as size_t;
                        written = 0 as libc::c_int as uint32_t;
                        let mut i: uint32_t = 0 as libc::c_int as uint32_t;
                        loop {
                            if !((i as uint64_t) < n) {
                                current_block = 26972500619410423;
                                break;
                            }
                            CRYPTO_store_u32_be(
                                &mut *counter.as_mut_ptr().offset(0 as libc::c_int as isize)
                                    as *mut uint8_t as *mut libc::c_void,
                                i.wrapping_add(1 as libc::c_int as uint32_t),
                            );
                            written = 0 as libc::c_int as uint32_t;
                            if HMAC_Init_ex(
                                &mut hmac_ctx,
                                0 as *const libc::c_void,
                                0 as libc::c_int as size_t,
                                0 as *const EVP_MD,
                                0 as *mut ENGINE,
                            ) == 0
                                || HMAC_Update(
                                    &mut hmac_ctx,
                                    &mut *counter
                                        .as_mut_ptr()
                                        .offset(0 as libc::c_int as isize),
                                    4 as libc::c_int as size_t,
                                ) == 0 || HMAC_Update(&mut hmac_ctx, info, info_len) == 0
                                || HMAC_Final(
                                    &mut hmac_ctx,
                                    out_key_i.as_mut_ptr(),
                                    &mut written,
                                ) == 0 || written as size_t != h_output_bytes
                            {
                                current_block = 6546087509913449933;
                                break;
                            }
                            if written as size_t > out_len.wrapping_sub(done) {
                                written = out_len.wrapping_sub(done) as uint32_t;
                            }
                            OPENSSL_memcpy(
                                out_key.offset(done as isize) as *mut libc::c_void,
                                out_key_i.as_mut_ptr() as *const libc::c_void,
                                written as size_t,
                            );
                            done = done.wrapping_add(written as size_t);
                            i = i.wrapping_add(1);
                            i;
                        }
                        match current_block {
                            6546087509913449933 => {}
                            _ => {
                                ret = 1 as libc::c_int;
                            }
                        }
                    }
                }
            }
        }
    }
    OPENSSL_cleanse(
        &mut *out_key_i.as_mut_ptr().offset(0 as libc::c_int as isize) as *mut uint8_t
            as *mut libc::c_void,
        64 as libc::c_int as size_t,
    );
    if ret <= 0 as libc::c_int && !out_key.is_null()
        && out_len > 0 as libc::c_int as size_t
    {
        OPENSSL_cleanse(out_key as *mut libc::c_void, out_len);
    }
    HMAC_CTX_cleanup(&mut hmac_ctx);
    FIPS_service_indicator_unlock_state();
    if ret != 0 {
        KBKDF_ctr_hmac_verify_service_indicator(digest, secret_len);
    }
    return ret;
}
