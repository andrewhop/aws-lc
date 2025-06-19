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
    fn EVP_MD_size(md: *const EVP_MD) -> size_t;
    fn HMAC(
        evp_md: *const EVP_MD,
        key: *const libc::c_void,
        key_len: size_t,
        data: *const uint8_t,
        data_len: size_t,
        out: *mut uint8_t,
        out_len: *mut libc::c_uint,
    ) -> *mut uint8_t;
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
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
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
unsafe extern "C" fn FIPS_service_indicator_lock_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_unlock_state() {}
#[inline]
unsafe extern "C" fn HKDF_verify_service_indicator(
    mut evp_md: *const EVP_MD,
    mut salt: *const uint8_t,
    mut salt_len: size_t,
    mut info_len: size_t,
) {}
#[inline]
unsafe extern "C" fn HKDFExpand_verify_service_indicator(mut evp_md: *const EVP_MD) {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn HKDF(
    mut out_key: *mut uint8_t,
    mut out_len: size_t,
    mut digest: *const EVP_MD,
    mut secret: *const uint8_t,
    mut secret_len: size_t,
    mut salt: *const uint8_t,
    mut salt_len: size_t,
    mut info: *const uint8_t,
    mut info_len: size_t,
) -> libc::c_int {
    let mut prk: [uint8_t; 64] = [0; 64];
    let mut prk_len: size_t = 0 as libc::c_int as size_t;
    let mut ret: libc::c_int = 0 as libc::c_int;
    FIPS_service_indicator_lock_state();
    if !(HKDF_extract(
        prk.as_mut_ptr(),
        &mut prk_len,
        digest,
        secret,
        secret_len,
        salt,
        salt_len,
    ) == 0
        || HKDF_expand(
            out_key,
            out_len,
            digest,
            prk.as_mut_ptr(),
            prk_len,
            info,
            info_len,
        ) == 0)
    {
        ret = 1 as libc::c_int;
    }
    OPENSSL_cleanse(prk.as_mut_ptr() as *mut libc::c_void, 64 as libc::c_int as size_t);
    FIPS_service_indicator_unlock_state();
    if ret == 1 as libc::c_int {
        HKDF_verify_service_indicator(digest, salt, salt_len, info_len);
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn HKDF_extract(
    mut out_key: *mut uint8_t,
    mut out_len: *mut size_t,
    mut digest: *const EVP_MD,
    mut secret: *const uint8_t,
    mut secret_len: size_t,
    mut salt: *const uint8_t,
    mut salt_len: size_t,
) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    FIPS_service_indicator_lock_state();
    let mut len: libc::c_uint = 0;
    if (HMAC(
        digest,
        salt as *const libc::c_void,
        salt_len,
        secret,
        secret_len,
        out_key,
        &mut len,
    ))
        .is_null()
    {
        ERR_put_error(
            31 as libc::c_int,
            0 as libc::c_int,
            28 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hkdf/hkdf.c\0"
                as *const u8 as *const libc::c_char,
            73 as libc::c_int as libc::c_uint,
        );
    } else {
        *out_len = len as size_t;
        if *out_len == EVP_MD_size(digest) {} else {
            __assert_fail(
                b"*out_len == EVP_MD_size(digest)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hkdf/hkdf.c\0"
                    as *const u8 as *const libc::c_char,
                78 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 104],
                    &[libc::c_char; 104],
                >(
                    b"int HKDF_extract(uint8_t *, size_t *, const EVP_MD *, const uint8_t *, size_t, const uint8_t *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_2999: {
            if *out_len == EVP_MD_size(digest) {} else {
                __assert_fail(
                    b"*out_len == EVP_MD_size(digest)\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hkdf/hkdf.c\0"
                        as *const u8 as *const libc::c_char,
                    78 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 104],
                        &[libc::c_char; 104],
                    >(
                        b"int HKDF_extract(uint8_t *, size_t *, const EVP_MD *, const uint8_t *, size_t, const uint8_t *, size_t)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        ret = 1 as libc::c_int;
    }
    FIPS_service_indicator_unlock_state();
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn HKDF_expand(
    mut out_key: *mut uint8_t,
    mut out_len: size_t,
    mut digest: *const EVP_MD,
    mut prk: *const uint8_t,
    mut prk_len: size_t,
    mut info: *const uint8_t,
    mut info_len: size_t,
) -> libc::c_int {
    let mut done: size_t = 0;
    let mut written: uint32_t = 0;
    let mut current_block: u64;
    let digest_len: size_t = EVP_MD_size(digest);
    let mut previous: [uint8_t; 64] = [0; 64];
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut hmac: HMAC_CTX = hmac_ctx_st {
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
    let mut n: size_t = out_len
        .wrapping_add(digest_len)
        .wrapping_sub(1 as libc::c_int as size_t) / digest_len;
    if out_len.wrapping_add(digest_len) < out_len || n > 255 as libc::c_int as size_t {
        ERR_put_error(
            31 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hkdf/hkdf.c\0"
                as *const u8 as *const libc::c_char,
            99 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    FIPS_service_indicator_lock_state();
    HMAC_CTX_init(&mut hmac);
    if !(HMAC_Init_ex(
        &mut hmac,
        prk as *const libc::c_void,
        prk_len,
        digest,
        0 as *mut ENGINE,
    ) == 0)
    {
        done = 0 as libc::c_int as size_t;
        written = 0 as libc::c_int as uint32_t;
        let mut i: size_t = 0 as libc::c_int as size_t;
        loop {
            if !(i < n) {
                current_block = 5689001924483802034;
                break;
            }
            let mut ctr: uint8_t = i.wrapping_add(1 as libc::c_int as size_t) as uint8_t;
            if i != 0 as libc::c_int as size_t
                && (HMAC_Init_ex(
                    &mut hmac,
                    0 as *const libc::c_void,
                    0 as libc::c_int as size_t,
                    0 as *const EVP_MD,
                    0 as *mut ENGINE,
                ) == 0 || HMAC_Update(&mut hmac, previous.as_mut_ptr(), digest_len) == 0)
            {
                current_block = 1900981020505028754;
                break;
            }
            written = 0 as libc::c_int as uint32_t;
            if HMAC_Update(&mut hmac, info, info_len) == 0
                || HMAC_Update(&mut hmac, &mut ctr, 1 as libc::c_int as size_t) == 0
                || HMAC_Final(&mut hmac, previous.as_mut_ptr(), &mut written) == 0
                || written as size_t != digest_len
            {
                current_block = 1900981020505028754;
                break;
            }
            if written as size_t > out_len.wrapping_sub(done) {
                written = out_len.wrapping_sub(done) as uint32_t;
            }
            OPENSSL_memcpy(
                out_key.offset(done as isize) as *mut libc::c_void,
                previous.as_mut_ptr() as *const libc::c_void,
                written as size_t,
            );
            done = done.wrapping_add(written as size_t);
            i = i.wrapping_add(1);
            i;
        }
        match current_block {
            1900981020505028754 => {}
            _ => {
                ret = 1 as libc::c_int;
            }
        }
    }
    OPENSSL_cleanse(
        previous.as_mut_ptr() as *mut libc::c_void,
        64 as libc::c_int as size_t,
    );
    HMAC_CTX_cleanup(&mut hmac);
    if ret != 1 as libc::c_int {
        ERR_put_error(
            31 as libc::c_int,
            0 as libc::c_int,
            28 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hkdf/hkdf.c\0"
                as *const u8 as *const libc::c_char,
            145 as libc::c_int as libc::c_uint,
        );
        OPENSSL_cleanse(out_key as *mut libc::c_void, out_len);
    }
    FIPS_service_indicator_unlock_state();
    if ret == 1 as libc::c_int {
        HKDFExpand_verify_service_indicator(digest);
    }
    return ret;
}
