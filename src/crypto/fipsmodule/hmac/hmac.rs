#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(extern_types, label_break_value)]
extern "C" {
    pub type engine_st;
    pub type env_md_st;
    fn EVP_md5() -> *const EVP_MD;
    fn EVP_sha1() -> *const EVP_MD;
    fn EVP_sha224() -> *const EVP_MD;
    fn EVP_sha256() -> *const EVP_MD;
    fn EVP_sha384() -> *const EVP_MD;
    fn EVP_sha512() -> *const EVP_MD;
    fn EVP_sha512_224() -> *const EVP_MD;
    fn EVP_sha512_256() -> *const EVP_MD;
    fn EVP_MD_size(md: *const EVP_MD) -> size_t;
    fn EVP_MD_block_size(md: *const EVP_MD) -> size_t;
    fn MD5_Init(md5: *mut MD5_CTX) -> libc::c_int;
    fn MD5_Update(
        md5: *mut MD5_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn MD5_Final(out: *mut uint8_t, md5: *mut MD5_CTX) -> libc::c_int;
    fn SHA1_Init(sha: *mut SHA_CTX) -> libc::c_int;
    fn SHA1_Update(
        sha: *mut SHA_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn SHA1_Final(out: *mut uint8_t, sha: *mut SHA_CTX) -> libc::c_int;
    fn SHA224_Init(sha: *mut SHA256_CTX) -> libc::c_int;
    fn SHA224_Update(
        sha: *mut SHA256_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn SHA224_Final(out: *mut uint8_t, sha: *mut SHA256_CTX) -> libc::c_int;
    fn SHA256_Init(sha: *mut SHA256_CTX) -> libc::c_int;
    fn SHA256_Update(
        sha: *mut SHA256_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn SHA256_Final(out: *mut uint8_t, sha: *mut SHA256_CTX) -> libc::c_int;
    fn SHA384_Init(sha: *mut SHA512_CTX) -> libc::c_int;
    fn SHA384_Update(
        sha: *mut SHA512_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn SHA384_Final(out: *mut uint8_t, sha: *mut SHA512_CTX) -> libc::c_int;
    fn SHA512_Init(sha: *mut SHA512_CTX) -> libc::c_int;
    fn SHA512_Update(
        sha: *mut SHA512_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn SHA512_Final(out: *mut uint8_t, sha: *mut SHA512_CTX) -> libc::c_int;
    fn SHA512_224_Init(sha: *mut SHA512_CTX) -> libc::c_int;
    fn SHA512_224_Update(
        sha: *mut SHA512_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn SHA512_224_Final(out: *mut uint8_t, sha: *mut SHA512_CTX) -> libc::c_int;
    fn SHA512_256_Init(sha: *mut SHA512_CTX) -> libc::c_int;
    fn SHA512_256_Update(
        sha: *mut SHA512_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn SHA512_256_Final(out: *mut uint8_t, sha: *mut SHA512_CTX) -> libc::c_int;
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
    fn CRYPTO_once(
        once: *mut CRYPTO_once_t,
        init: Option::<unsafe extern "C" fn() -> ()>,
    );
    fn MD5_Init_from_state(
        sha: *mut MD5_CTX,
        h: *const uint8_t,
        n: uint64_t,
    ) -> libc::c_int;
    fn MD5_get_state(
        ctx: *mut MD5_CTX,
        out_h: *mut uint8_t,
        out_n: *mut uint64_t,
    ) -> libc::c_int;
    fn SHA1_Init_from_state(
        sha: *mut SHA_CTX,
        h: *const uint8_t,
        n: uint64_t,
    ) -> libc::c_int;
    fn SHA224_Init_from_state(
        sha: *mut SHA256_CTX,
        h: *const uint8_t,
        n: uint64_t,
    ) -> libc::c_int;
    fn SHA256_Init_from_state(
        sha: *mut SHA256_CTX,
        h: *const uint8_t,
        n: uint64_t,
    ) -> libc::c_int;
    fn SHA384_Init_from_state(
        sha: *mut SHA512_CTX,
        h: *const uint8_t,
        n: uint64_t,
    ) -> libc::c_int;
    fn SHA512_Init_from_state(
        sha: *mut SHA512_CTX,
        h: *const uint8_t,
        n: uint64_t,
    ) -> libc::c_int;
    fn SHA512_224_Init_from_state(
        sha: *mut SHA512_CTX,
        h: *const uint8_t,
        n: uint64_t,
    ) -> libc::c_int;
    fn SHA512_256_Init_from_state(
        sha: *mut SHA512_CTX,
        h: *const uint8_t,
        n: uint64_t,
    ) -> libc::c_int;
    fn SHA1_get_state(
        ctx: *mut SHA_CTX,
        out_h: *mut uint8_t,
        out_n: *mut uint64_t,
    ) -> libc::c_int;
    fn SHA224_get_state(
        ctx: *mut SHA256_CTX,
        out_h: *mut uint8_t,
        out_n: *mut uint64_t,
    ) -> libc::c_int;
    fn SHA256_get_state(
        ctx: *mut SHA256_CTX,
        out_h: *mut uint8_t,
        out_n: *mut uint64_t,
    ) -> libc::c_int;
    fn SHA384_get_state(
        ctx: *mut SHA512_CTX,
        out_h: *mut uint8_t,
        out_n: *mut uint64_t,
    ) -> libc::c_int;
    fn SHA512_get_state(
        ctx: *mut SHA512_CTX,
        out_h: *mut uint8_t,
        out_n: *mut uint64_t,
    ) -> libc::c_int;
    fn SHA512_224_get_state(
        ctx: *mut SHA512_CTX,
        out_h: *mut uint8_t,
        out_n: *mut uint64_t,
    ) -> libc::c_int;
    fn SHA512_256_get_state(
        ctx: *mut SHA512_CTX,
        out_h: *mut uint8_t,
        out_n: *mut uint64_t,
    ) -> libc::c_int;
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
pub type pthread_once_t = libc::c_int;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hmac_methods_st {
    pub evp_md: *const EVP_MD,
    pub chaining_length: size_t,
    pub init: HashInit,
    pub update: HashUpdate,
    pub finalize: HashFinal,
    pub init_from_state: HashInitFromState,
    pub get_state: HashGetState,
}
pub type HashGetState = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *mut uint8_t, *mut uint64_t) -> libc::c_int,
>;
pub type HashInitFromState = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const uint8_t, uint64_t) -> libc::c_int,
>;
pub type HashFinal = Option::<
    unsafe extern "C" fn(*mut uint8_t, *mut libc::c_void) -> libc::c_int,
>;
pub type HashUpdate = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_void, size_t) -> libc::c_int,
>;
pub type HashInit = Option::<unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int>;
pub type HMAC_CTX = hmac_ctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hmac_method_array_st {
    pub methods: [HmacMethods; 8],
}
pub type CRYPTO_once_t = pthread_once_t;
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
unsafe extern "C" fn FIPS_service_indicator_lock_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_unlock_state() {}
#[inline]
unsafe extern "C" fn HMAC_verify_service_indicator(mut evp_md: *const EVP_MD) {}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_MD5_Init(
    mut ctx: *mut libc::c_void,
) -> libc::c_int {
    return MD5_Init(ctx as *mut MD5_CTX);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_MD5_get_state(
    mut ctx: *mut libc::c_void,
    mut out_h: *mut uint8_t,
    mut out_n: *mut uint64_t,
) -> libc::c_int {
    return MD5_get_state(ctx as *mut MD5_CTX, out_h, out_n);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_MD5_Init_from_state(
    mut ctx: *mut libc::c_void,
    mut h: *const uint8_t,
    mut n: uint64_t,
) -> libc::c_int {
    return MD5_Init_from_state(ctx as *mut MD5_CTX, h, n);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_MD5_Final(
    mut out: *mut uint8_t,
    mut ctx: *mut libc::c_void,
) -> libc::c_int {
    return MD5_Final(out, ctx as *mut MD5_CTX);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_MD5_Update(
    mut ctx: *mut libc::c_void,
    mut key: *const libc::c_void,
    mut key_len: size_t,
) -> libc::c_int {
    return MD5_Update(ctx as *mut MD5_CTX, key, key_len);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA1_Init(
    mut ctx: *mut libc::c_void,
) -> libc::c_int {
    return SHA1_Init(ctx as *mut SHA_CTX);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA1_Final(
    mut out: *mut uint8_t,
    mut ctx: *mut libc::c_void,
) -> libc::c_int {
    return SHA1_Final(out, ctx as *mut SHA_CTX);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA1_get_state(
    mut ctx: *mut libc::c_void,
    mut out_h: *mut uint8_t,
    mut out_n: *mut uint64_t,
) -> libc::c_int {
    return SHA1_get_state(ctx as *mut SHA_CTX, out_h, out_n);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA1_Init_from_state(
    mut ctx: *mut libc::c_void,
    mut h: *const uint8_t,
    mut n: uint64_t,
) -> libc::c_int {
    return SHA1_Init_from_state(ctx as *mut SHA_CTX, h, n);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA1_Update(
    mut ctx: *mut libc::c_void,
    mut key: *const libc::c_void,
    mut key_len: size_t,
) -> libc::c_int {
    return SHA1_Update(ctx as *mut SHA_CTX, key, key_len);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA224_get_state(
    mut ctx: *mut libc::c_void,
    mut out_h: *mut uint8_t,
    mut out_n: *mut uint64_t,
) -> libc::c_int {
    return SHA224_get_state(ctx as *mut SHA256_CTX, out_h, out_n);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA224_Update(
    mut ctx: *mut libc::c_void,
    mut key: *const libc::c_void,
    mut key_len: size_t,
) -> libc::c_int {
    return SHA224_Update(ctx as *mut SHA256_CTX, key, key_len);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA224_Init(
    mut ctx: *mut libc::c_void,
) -> libc::c_int {
    return SHA224_Init(ctx as *mut SHA256_CTX);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA224_Init_from_state(
    mut ctx: *mut libc::c_void,
    mut h: *const uint8_t,
    mut n: uint64_t,
) -> libc::c_int {
    return SHA224_Init_from_state(ctx as *mut SHA256_CTX, h, n);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA224_Final(
    mut out: *mut uint8_t,
    mut ctx: *mut libc::c_void,
) -> libc::c_int {
    return SHA224_Final(out, ctx as *mut SHA256_CTX);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA256_get_state(
    mut ctx: *mut libc::c_void,
    mut out_h: *mut uint8_t,
    mut out_n: *mut uint64_t,
) -> libc::c_int {
    return SHA256_get_state(ctx as *mut SHA256_CTX, out_h, out_n);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA256_Init(
    mut ctx: *mut libc::c_void,
) -> libc::c_int {
    return SHA256_Init(ctx as *mut SHA256_CTX);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA256_Init_from_state(
    mut ctx: *mut libc::c_void,
    mut h: *const uint8_t,
    mut n: uint64_t,
) -> libc::c_int {
    return SHA256_Init_from_state(ctx as *mut SHA256_CTX, h, n);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA256_Final(
    mut out: *mut uint8_t,
    mut ctx: *mut libc::c_void,
) -> libc::c_int {
    return SHA256_Final(out, ctx as *mut SHA256_CTX);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA256_Update(
    mut ctx: *mut libc::c_void,
    mut key: *const libc::c_void,
    mut key_len: size_t,
) -> libc::c_int {
    return SHA256_Update(ctx as *mut SHA256_CTX, key, key_len);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA384_get_state(
    mut ctx: *mut libc::c_void,
    mut out_h: *mut uint8_t,
    mut out_n: *mut uint64_t,
) -> libc::c_int {
    return SHA384_get_state(ctx as *mut SHA512_CTX, out_h, out_n);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA384_Final(
    mut out: *mut uint8_t,
    mut ctx: *mut libc::c_void,
) -> libc::c_int {
    return SHA384_Final(out, ctx as *mut SHA512_CTX);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA384_Update(
    mut ctx: *mut libc::c_void,
    mut key: *const libc::c_void,
    mut key_len: size_t,
) -> libc::c_int {
    return SHA384_Update(ctx as *mut SHA512_CTX, key, key_len);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA384_Init_from_state(
    mut ctx: *mut libc::c_void,
    mut h: *const uint8_t,
    mut n: uint64_t,
) -> libc::c_int {
    return SHA384_Init_from_state(ctx as *mut SHA512_CTX, h, n);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA384_Init(
    mut ctx: *mut libc::c_void,
) -> libc::c_int {
    return SHA384_Init(ctx as *mut SHA512_CTX);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA512_Init(
    mut ctx: *mut libc::c_void,
) -> libc::c_int {
    return SHA512_Init(ctx as *mut SHA512_CTX);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA512_Update(
    mut ctx: *mut libc::c_void,
    mut key: *const libc::c_void,
    mut key_len: size_t,
) -> libc::c_int {
    return SHA512_Update(ctx as *mut SHA512_CTX, key, key_len);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA512_get_state(
    mut ctx: *mut libc::c_void,
    mut out_h: *mut uint8_t,
    mut out_n: *mut uint64_t,
) -> libc::c_int {
    return SHA512_get_state(ctx as *mut SHA512_CTX, out_h, out_n);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA512_Init_from_state(
    mut ctx: *mut libc::c_void,
    mut h: *const uint8_t,
    mut n: uint64_t,
) -> libc::c_int {
    return SHA512_Init_from_state(ctx as *mut SHA512_CTX, h, n);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA512_Final(
    mut out: *mut uint8_t,
    mut ctx: *mut libc::c_void,
) -> libc::c_int {
    return SHA512_Final(out, ctx as *mut SHA512_CTX);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA512_224_Final(
    mut out: *mut uint8_t,
    mut ctx: *mut libc::c_void,
) -> libc::c_int {
    return SHA512_224_Final(out, ctx as *mut SHA512_CTX);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA512_224_get_state(
    mut ctx: *mut libc::c_void,
    mut out_h: *mut uint8_t,
    mut out_n: *mut uint64_t,
) -> libc::c_int {
    return SHA512_224_get_state(ctx as *mut SHA512_CTX, out_h, out_n);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA512_224_Update(
    mut ctx: *mut libc::c_void,
    mut key: *const libc::c_void,
    mut key_len: size_t,
) -> libc::c_int {
    return SHA512_224_Update(ctx as *mut SHA512_CTX, key, key_len);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA512_224_Init(
    mut ctx: *mut libc::c_void,
) -> libc::c_int {
    return SHA512_224_Init(ctx as *mut SHA512_CTX);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA512_224_Init_from_state(
    mut ctx: *mut libc::c_void,
    mut h: *const uint8_t,
    mut n: uint64_t,
) -> libc::c_int {
    return SHA512_224_Init_from_state(ctx as *mut SHA512_CTX, h, n);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA512_256_Init(
    mut ctx: *mut libc::c_void,
) -> libc::c_int {
    return SHA512_256_Init(ctx as *mut SHA512_CTX);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA512_256_Update(
    mut ctx: *mut libc::c_void,
    mut key: *const libc::c_void,
    mut key_len: size_t,
) -> libc::c_int {
    return SHA512_256_Update(ctx as *mut SHA512_CTX, key, key_len);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA512_256_Final(
    mut out: *mut uint8_t,
    mut ctx: *mut libc::c_void,
) -> libc::c_int {
    return SHA512_256_Final(out, ctx as *mut SHA512_CTX);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA512_256_get_state(
    mut ctx: *mut libc::c_void,
    mut out_h: *mut uint8_t,
    mut out_n: *mut uint64_t,
) -> libc::c_int {
    return SHA512_256_get_state(ctx as *mut SHA512_CTX, out_h, out_n);
}
unsafe extern "C" fn AWS_LC_TRAMPOLINE_SHA512_256_Init_from_state(
    mut ctx: *mut libc::c_void,
    mut h: *const uint8_t,
    mut n: uint64_t,
) -> libc::c_int {
    return SHA512_256_Init_from_state(ctx as *mut SHA512_CTX, h, n);
}
unsafe extern "C" fn AWSLC_hmac_in_place_methods_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut AWSLC_hmac_in_place_methods_once;
}
unsafe extern "C" fn AWSLC_hmac_in_place_methods_do_init(
    mut out: *mut hmac_method_array_st,
) {
    OPENSSL_memset(
        ((*out).methods).as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[HmacMethods; 8]>() as libc::c_ulong,
    );
    let mut idx: libc::c_int = 0 as libc::c_int;
    (*out).methods[idx as usize].evp_md = EVP_sha256();
    (*out).methods[idx as usize].chaining_length = 32 as libc::c_int as size_t;
    (*out)
        .methods[idx as usize]
        .init = Some(
        AWS_LC_TRAMPOLINE_SHA256_Init
            as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .update = Some(
        AWS_LC_TRAMPOLINE_SHA256_Update
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const libc::c_void,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .finalize = Some(
        AWS_LC_TRAMPOLINE_SHA256_Final
            as unsafe extern "C" fn(*mut uint8_t, *mut libc::c_void) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .init_from_state = Some(
        AWS_LC_TRAMPOLINE_SHA256_Init_from_state
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const uint8_t,
                uint64_t,
            ) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .get_state = Some(
        AWS_LC_TRAMPOLINE_SHA256_get_state
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *mut uint8_t,
                *mut uint64_t,
            ) -> libc::c_int,
    );
    idx += 1;
    idx;
    if idx <= 8 as libc::c_int {} else {
        __assert_fail(
            b"idx <= HMAC_METHOD_MAX\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                as *const u8 as *const libc::c_char,
            170 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 72],
                &[libc::c_char; 72],
            >(
                b"void AWSLC_hmac_in_place_methods_do_init(struct hmac_method_array_st *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_4215: {
        if idx <= 8 as libc::c_int {} else {
            __assert_fail(
                b"idx <= HMAC_METHOD_MAX\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                    as *const u8 as *const libc::c_char,
                170 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 72],
                    &[libc::c_char; 72],
                >(
                    b"void AWSLC_hmac_in_place_methods_do_init(struct hmac_method_array_st *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    (*out).methods[idx as usize].evp_md = EVP_sha1();
    (*out).methods[idx as usize].chaining_length = 20 as libc::c_int as size_t;
    (*out)
        .methods[idx as usize]
        .init = Some(
        AWS_LC_TRAMPOLINE_SHA1_Init
            as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .update = Some(
        AWS_LC_TRAMPOLINE_SHA1_Update
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const libc::c_void,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .finalize = Some(
        AWS_LC_TRAMPOLINE_SHA1_Final
            as unsafe extern "C" fn(*mut uint8_t, *mut libc::c_void) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .init_from_state = Some(
        AWS_LC_TRAMPOLINE_SHA1_Init_from_state
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const uint8_t,
                uint64_t,
            ) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .get_state = Some(
        AWS_LC_TRAMPOLINE_SHA1_get_state
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *mut uint8_t,
                *mut uint64_t,
            ) -> libc::c_int,
    );
    idx += 1;
    idx;
    if idx <= 8 as libc::c_int {} else {
        __assert_fail(
            b"idx <= HMAC_METHOD_MAX\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                as *const u8 as *const libc::c_char,
            171 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 72],
                &[libc::c_char; 72],
            >(
                b"void AWSLC_hmac_in_place_methods_do_init(struct hmac_method_array_st *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_4002: {
        if idx <= 8 as libc::c_int {} else {
            __assert_fail(
                b"idx <= HMAC_METHOD_MAX\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                    as *const u8 as *const libc::c_char,
                171 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 72],
                    &[libc::c_char; 72],
                >(
                    b"void AWSLC_hmac_in_place_methods_do_init(struct hmac_method_array_st *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    (*out).methods[idx as usize].evp_md = EVP_sha384();
    (*out).methods[idx as usize].chaining_length = 64 as libc::c_int as size_t;
    (*out)
        .methods[idx as usize]
        .init = Some(
        AWS_LC_TRAMPOLINE_SHA384_Init
            as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .update = Some(
        AWS_LC_TRAMPOLINE_SHA384_Update
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const libc::c_void,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .finalize = Some(
        AWS_LC_TRAMPOLINE_SHA384_Final
            as unsafe extern "C" fn(*mut uint8_t, *mut libc::c_void) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .init_from_state = Some(
        AWS_LC_TRAMPOLINE_SHA384_Init_from_state
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const uint8_t,
                uint64_t,
            ) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .get_state = Some(
        AWS_LC_TRAMPOLINE_SHA384_get_state
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *mut uint8_t,
                *mut uint64_t,
            ) -> libc::c_int,
    );
    idx += 1;
    idx;
    if idx <= 8 as libc::c_int {} else {
        __assert_fail(
            b"idx <= HMAC_METHOD_MAX\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                as *const u8 as *const libc::c_char,
            172 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 72],
                &[libc::c_char; 72],
            >(
                b"void AWSLC_hmac_in_place_methods_do_init(struct hmac_method_array_st *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_3796: {
        if idx <= 8 as libc::c_int {} else {
            __assert_fail(
                b"idx <= HMAC_METHOD_MAX\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                    as *const u8 as *const libc::c_char,
                172 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 72],
                    &[libc::c_char; 72],
                >(
                    b"void AWSLC_hmac_in_place_methods_do_init(struct hmac_method_array_st *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    (*out).methods[idx as usize].evp_md = EVP_sha512();
    (*out).methods[idx as usize].chaining_length = 64 as libc::c_int as size_t;
    (*out)
        .methods[idx as usize]
        .init = Some(
        AWS_LC_TRAMPOLINE_SHA512_Init
            as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .update = Some(
        AWS_LC_TRAMPOLINE_SHA512_Update
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const libc::c_void,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .finalize = Some(
        AWS_LC_TRAMPOLINE_SHA512_Final
            as unsafe extern "C" fn(*mut uint8_t, *mut libc::c_void) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .init_from_state = Some(
        AWS_LC_TRAMPOLINE_SHA512_Init_from_state
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const uint8_t,
                uint64_t,
            ) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .get_state = Some(
        AWS_LC_TRAMPOLINE_SHA512_get_state
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *mut uint8_t,
                *mut uint64_t,
            ) -> libc::c_int,
    );
    idx += 1;
    idx;
    if idx <= 8 as libc::c_int {} else {
        __assert_fail(
            b"idx <= HMAC_METHOD_MAX\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                as *const u8 as *const libc::c_char,
            173 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 72],
                &[libc::c_char; 72],
            >(
                b"void AWSLC_hmac_in_place_methods_do_init(struct hmac_method_array_st *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_3590: {
        if idx <= 8 as libc::c_int {} else {
            __assert_fail(
                b"idx <= HMAC_METHOD_MAX\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                    as *const u8 as *const libc::c_char,
                173 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 72],
                    &[libc::c_char; 72],
                >(
                    b"void AWSLC_hmac_in_place_methods_do_init(struct hmac_method_array_st *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    (*out).methods[idx as usize].evp_md = EVP_md5();
    (*out).methods[idx as usize].chaining_length = 16 as libc::c_int as size_t;
    (*out)
        .methods[idx as usize]
        .init = Some(
        AWS_LC_TRAMPOLINE_MD5_Init
            as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .update = Some(
        AWS_LC_TRAMPOLINE_MD5_Update
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const libc::c_void,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .finalize = Some(
        AWS_LC_TRAMPOLINE_MD5_Final
            as unsafe extern "C" fn(*mut uint8_t, *mut libc::c_void) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .init_from_state = Some(
        AWS_LC_TRAMPOLINE_MD5_Init_from_state
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const uint8_t,
                uint64_t,
            ) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .get_state = Some(
        AWS_LC_TRAMPOLINE_MD5_get_state
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *mut uint8_t,
                *mut uint64_t,
            ) -> libc::c_int,
    );
    idx += 1;
    idx;
    if idx <= 8 as libc::c_int {} else {
        __assert_fail(
            b"idx <= HMAC_METHOD_MAX\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                as *const u8 as *const libc::c_char,
            174 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 72],
                &[libc::c_char; 72],
            >(
                b"void AWSLC_hmac_in_place_methods_do_init(struct hmac_method_array_st *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_3377: {
        if idx <= 8 as libc::c_int {} else {
            __assert_fail(
                b"idx <= HMAC_METHOD_MAX\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                    as *const u8 as *const libc::c_char,
                174 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 72],
                    &[libc::c_char; 72],
                >(
                    b"void AWSLC_hmac_in_place_methods_do_init(struct hmac_method_array_st *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    (*out).methods[idx as usize].evp_md = EVP_sha224();
    (*out).methods[idx as usize].chaining_length = 32 as libc::c_int as size_t;
    (*out)
        .methods[idx as usize]
        .init = Some(
        AWS_LC_TRAMPOLINE_SHA224_Init
            as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .update = Some(
        AWS_LC_TRAMPOLINE_SHA224_Update
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const libc::c_void,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .finalize = Some(
        AWS_LC_TRAMPOLINE_SHA224_Final
            as unsafe extern "C" fn(*mut uint8_t, *mut libc::c_void) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .init_from_state = Some(
        AWS_LC_TRAMPOLINE_SHA224_Init_from_state
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const uint8_t,
                uint64_t,
            ) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .get_state = Some(
        AWS_LC_TRAMPOLINE_SHA224_get_state
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *mut uint8_t,
                *mut uint64_t,
            ) -> libc::c_int,
    );
    idx += 1;
    idx;
    if idx <= 8 as libc::c_int {} else {
        __assert_fail(
            b"idx <= HMAC_METHOD_MAX\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                as *const u8 as *const libc::c_char,
            175 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 72],
                &[libc::c_char; 72],
            >(
                b"void AWSLC_hmac_in_place_methods_do_init(struct hmac_method_array_st *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_3164: {
        if idx <= 8 as libc::c_int {} else {
            __assert_fail(
                b"idx <= HMAC_METHOD_MAX\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                    as *const u8 as *const libc::c_char,
                175 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 72],
                    &[libc::c_char; 72],
                >(
                    b"void AWSLC_hmac_in_place_methods_do_init(struct hmac_method_array_st *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    (*out).methods[idx as usize].evp_md = EVP_sha512_224();
    (*out).methods[idx as usize].chaining_length = 64 as libc::c_int as size_t;
    (*out)
        .methods[idx as usize]
        .init = Some(
        AWS_LC_TRAMPOLINE_SHA512_224_Init
            as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .update = Some(
        AWS_LC_TRAMPOLINE_SHA512_224_Update
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const libc::c_void,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .finalize = Some(
        AWS_LC_TRAMPOLINE_SHA512_224_Final
            as unsafe extern "C" fn(*mut uint8_t, *mut libc::c_void) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .init_from_state = Some(
        AWS_LC_TRAMPOLINE_SHA512_224_Init_from_state
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const uint8_t,
                uint64_t,
            ) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .get_state = Some(
        AWS_LC_TRAMPOLINE_SHA512_224_get_state
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *mut uint8_t,
                *mut uint64_t,
            ) -> libc::c_int,
    );
    idx += 1;
    idx;
    if idx <= 8 as libc::c_int {} else {
        __assert_fail(
            b"idx <= HMAC_METHOD_MAX\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                as *const u8 as *const libc::c_char,
            176 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 72],
                &[libc::c_char; 72],
            >(
                b"void AWSLC_hmac_in_place_methods_do_init(struct hmac_method_array_st *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2958: {
        if idx <= 8 as libc::c_int {} else {
            __assert_fail(
                b"idx <= HMAC_METHOD_MAX\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                    as *const u8 as *const libc::c_char,
                176 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 72],
                    &[libc::c_char; 72],
                >(
                    b"void AWSLC_hmac_in_place_methods_do_init(struct hmac_method_array_st *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    (*out).methods[idx as usize].evp_md = EVP_sha512_256();
    (*out).methods[idx as usize].chaining_length = 64 as libc::c_int as size_t;
    (*out)
        .methods[idx as usize]
        .init = Some(
        AWS_LC_TRAMPOLINE_SHA512_256_Init
            as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .update = Some(
        AWS_LC_TRAMPOLINE_SHA512_256_Update
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const libc::c_void,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .finalize = Some(
        AWS_LC_TRAMPOLINE_SHA512_256_Final
            as unsafe extern "C" fn(*mut uint8_t, *mut libc::c_void) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .init_from_state = Some(
        AWS_LC_TRAMPOLINE_SHA512_256_Init_from_state
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const uint8_t,
                uint64_t,
            ) -> libc::c_int,
    );
    (*out)
        .methods[idx as usize]
        .get_state = Some(
        AWS_LC_TRAMPOLINE_SHA512_256_get_state
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *mut uint8_t,
                *mut uint64_t,
            ) -> libc::c_int,
    );
    idx += 1;
    idx;
    if idx <= 8 as libc::c_int {} else {
        __assert_fail(
            b"idx <= HMAC_METHOD_MAX\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                as *const u8 as *const libc::c_char,
            177 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 72],
                &[libc::c_char; 72],
            >(
                b"void AWSLC_hmac_in_place_methods_do_init(struct hmac_method_array_st *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2735: {
        if idx <= 8 as libc::c_int {} else {
            __assert_fail(
                b"idx <= HMAC_METHOD_MAX\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                    as *const u8 as *const libc::c_char,
                177 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 72],
                    &[libc::c_char; 72],
                >(
                    b"void AWSLC_hmac_in_place_methods_do_init(struct hmac_method_array_st *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn AWSLC_hmac_in_place_methods_storage_bss_get() -> *mut hmac_method_array_st {
    return &mut AWSLC_hmac_in_place_methods_storage;
}
static mut AWSLC_hmac_in_place_methods_storage: hmac_method_array_st = hmac_method_array_st {
    methods: [hmac_methods_st {
        evp_md: 0 as *const EVP_MD,
        chaining_length: 0,
        init: None,
        update: None,
        finalize: None,
        init_from_state: None,
        get_state: None,
    }; 8],
};
unsafe extern "C" fn AWSLC_hmac_in_place_methods_init() {
    AWSLC_hmac_in_place_methods_do_init(AWSLC_hmac_in_place_methods_storage_bss_get());
}
unsafe extern "C" fn AWSLC_hmac_in_place_methods() -> *const hmac_method_array_st {
    CRYPTO_once(
        AWSLC_hmac_in_place_methods_once_bss_get(),
        Some(AWSLC_hmac_in_place_methods_init as unsafe extern "C" fn() -> ()),
    );
    return AWSLC_hmac_in_place_methods_storage_bss_get() as *const hmac_method_array_st;
}
static mut AWSLC_hmac_in_place_methods_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn GetInPlaceMethods(mut evp_md: *const EVP_MD) -> *const HmacMethods {
    let mut method_array: *const hmac_method_array_st = AWSLC_hmac_in_place_methods();
    let mut methods: *const HmacMethods = ((*method_array).methods).as_ptr();
    let mut idx: size_t = 0 as libc::c_int as size_t;
    while idx
        < (::core::mem::size_of::<[HmacMethods; 8]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<hmac_methods_st>() as libc::c_ulong)
    {
        if (*methods.offset(idx as isize)).evp_md == evp_md {
            return &*methods.offset(idx as isize) as *const HmacMethods;
        }
        idx = idx.wrapping_add(1);
        idx;
    }
    return 0 as *const HmacMethods;
}
#[no_mangle]
pub unsafe extern "C" fn HMAC(
    mut evp_md: *const EVP_MD,
    mut key: *const libc::c_void,
    mut key_len: size_t,
    mut data: *const uint8_t,
    mut data_len: size_t,
    mut out: *mut uint8_t,
    mut out_len: *mut libc::c_uint,
) -> *mut uint8_t {
    if out.is_null() {
        return 0 as *mut uint8_t;
    }
    let mut ctx: HMAC_CTX = hmac_ctx_st {
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
    OPENSSL_memset(
        &mut ctx as *mut HMAC_CTX as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<HMAC_CTX>() as libc::c_ulong,
    );
    let mut result: libc::c_int = 0;
    FIPS_service_indicator_lock_state();
    result = (HMAC_Init_ex(&mut ctx, key, key_len, evp_md, 0 as *mut ENGINE) != 0
        && HMAC_Update(&mut ctx, data, data_len) != 0
        && HMAC_Final(&mut ctx, out, out_len) != 0) as libc::c_int;
    FIPS_service_indicator_unlock_state();
    HMAC_CTX_cleanup(&mut ctx);
    if result != 0 {
        HMAC_verify_service_indicator(evp_md);
        return out;
    } else {
        OPENSSL_cleanse(out as *mut libc::c_void, EVP_MD_size(evp_md));
        return 0 as *mut uint8_t;
    };
}
#[no_mangle]
pub unsafe extern "C" fn HMAC_with_precompute(
    mut evp_md: *const EVP_MD,
    mut key: *const libc::c_void,
    mut key_len: size_t,
    mut data: *const uint8_t,
    mut data_len: size_t,
    mut out: *mut uint8_t,
    mut out_len: *mut libc::c_uint,
) -> *mut uint8_t {
    let mut ctx: HMAC_CTX = hmac_ctx_st {
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
    OPENSSL_memset(
        &mut ctx as *mut HMAC_CTX as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<HMAC_CTX>() as libc::c_ulong,
    );
    let mut result: libc::c_int = 0;
    FIPS_service_indicator_lock_state();
    let mut precomputed_key: [uint8_t; 128] = [0; 128];
    let mut precomputed_key_len: size_t = (2 as libc::c_int * 64 as libc::c_int)
        as size_t;
    result = (HMAC_Init_ex(&mut ctx, key, key_len, evp_md, 0 as *mut ENGINE) != 0
        && HMAC_set_precomputed_key_export(&mut ctx) != 0
        && HMAC_get_precomputed_key(
            &mut ctx,
            precomputed_key.as_mut_ptr(),
            &mut precomputed_key_len,
        ) != 0
        && HMAC_Init_from_precomputed_key(
            &mut ctx,
            precomputed_key.as_mut_ptr(),
            precomputed_key_len,
            evp_md,
        ) != 0 && HMAC_Update(&mut ctx, data, data_len) != 0
        && HMAC_Final(&mut ctx, out, out_len) != 0) as libc::c_int;
    FIPS_service_indicator_unlock_state();
    HMAC_CTX_cleanup(&mut ctx);
    OPENSSL_cleanse(
        precomputed_key.as_mut_ptr() as *mut libc::c_void,
        (2 as libc::c_int * 64 as libc::c_int) as size_t,
    );
    if result != 0 {
        return out
    } else {
        OPENSSL_cleanse(out as *mut libc::c_void, EVP_MD_size(evp_md));
        return 0 as *mut uint8_t;
    };
}
#[no_mangle]
pub unsafe extern "C" fn HMAC_CTX_init(mut ctx: *mut HMAC_CTX) {
    OPENSSL_memset(
        ctx as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<HMAC_CTX>() as libc::c_ulong,
    );
}
#[no_mangle]
pub unsafe extern "C" fn HMAC_CTX_new() -> *mut HMAC_CTX {
    let mut ctx: *mut HMAC_CTX = OPENSSL_zalloc(
        ::core::mem::size_of::<HMAC_CTX>() as libc::c_ulong,
    ) as *mut HMAC_CTX;
    !ctx.is_null();
    return ctx;
}
#[no_mangle]
pub unsafe extern "C" fn HMAC_CTX_cleanup(mut ctx: *mut HMAC_CTX) {
    OPENSSL_cleanse(
        ctx as *mut libc::c_void,
        ::core::mem::size_of::<HMAC_CTX>() as libc::c_ulong,
    );
}
#[no_mangle]
pub unsafe extern "C" fn HMAC_CTX_cleanse(mut ctx: *mut HMAC_CTX) {
    HMAC_CTX_cleanup(ctx);
}
#[no_mangle]
pub unsafe extern "C" fn HMAC_CTX_free(mut ctx: *mut HMAC_CTX) {
    if ctx.is_null() {
        return;
    }
    HMAC_CTX_cleanup(ctx);
    OPENSSL_free(ctx as *mut libc::c_void);
}
unsafe extern "C" fn hmac_ctx_set_md_methods(
    mut ctx: *mut HMAC_CTX,
    mut md: *const EVP_MD,
) -> libc::c_int {
    if !md.is_null()
        && (0 as libc::c_int == (*ctx).state as libc::c_int || (*ctx).md != md)
    {
        (*ctx).methods = GetInPlaceMethods(md);
        if ((*ctx).methods).is_null() {
            return 0 as libc::c_int;
        }
        (*ctx).md = md;
    } else if !(1 as libc::c_int == (*ctx).state as libc::c_int
        || 2 as libc::c_int == (*ctx).state as libc::c_int)
    {
        return 0 as libc::c_int
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn HMAC_Init_ex(
    mut ctx: *mut HMAC_CTX,
    mut key: *const libc::c_void,
    mut key_len: size_t,
    mut md: *const EVP_MD,
    mut impl_0: *mut ENGINE,
) -> libc::c_int {
    let mut current_block: u64;
    if impl_0.is_null() {} else {
        __assert_fail(
            b"impl == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                as *const u8 as *const libc::c_char,
            352 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 77],
                &[libc::c_char; 77],
            >(
                b"int HMAC_Init_ex(HMAC_CTX *, const void *, size_t, const EVP_MD *, ENGINE *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_4585: {
        if impl_0.is_null() {} else {
            __assert_fail(
                b"impl == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                    as *const u8 as *const libc::c_char,
                352 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 77],
                    &[libc::c_char; 77],
                >(
                    b"int HMAC_Init_ex(HMAC_CTX *, const void *, size_t, const EVP_MD *, ENGINE *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if 3 as libc::c_int == (*ctx).state as libc::c_int
        || 4 as libc::c_int == (*ctx).state as libc::c_int
    {
        (*ctx).state = 1 as libc::c_int as int8_t;
    }
    if 1 as libc::c_int == (*ctx).state as libc::c_int {
        if key.is_null() && (md.is_null() || md == (*ctx).md) {
            return 1 as libc::c_int;
        }
    }
    if hmac_ctx_set_md_methods(ctx, md) == 0 {
        return 0 as libc::c_int;
    }
    let mut methods: *const HmacMethods = (*ctx).methods;
    let mut block_size: size_t = EVP_MD_block_size((*methods).evp_md);
    if block_size % 8 as libc::c_int as size_t == 0 as libc::c_int as size_t {} else {
        __assert_fail(
            b"block_size % 8 == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                as *const u8 as *const libc::c_char,
            381 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 77],
                &[libc::c_char; 77],
            >(
                b"int HMAC_Init_ex(HMAC_CTX *, const void *, size_t, const EVP_MD *, ENGINE *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2506: {
        if block_size % 8 as libc::c_int as size_t == 0 as libc::c_int as size_t
        {} else {
            __assert_fail(
                b"block_size % 8 == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                    as *const u8 as *const libc::c_char,
                381 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 77],
                    &[libc::c_char; 77],
                >(
                    b"int HMAC_Init_ex(HMAC_CTX *, const void *, size_t, const EVP_MD *, ENGINE *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if block_size <= 128 as libc::c_int as size_t {} else {
        __assert_fail(
            b"block_size <= EVP_MAX_MD_BLOCK_SIZE\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                as *const u8 as *const libc::c_char,
            382 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 77],
                &[libc::c_char; 77],
            >(
                b"int HMAC_Init_ex(HMAC_CTX *, const void *, size_t, const EVP_MD *, ENGINE *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2467: {
        if block_size <= 128 as libc::c_int as size_t {} else {
            __assert_fail(
                b"block_size <= EVP_MAX_MD_BLOCK_SIZE\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                    as *const u8 as *const libc::c_char,
                382 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 77],
                    &[libc::c_char; 77],
                >(
                    b"int HMAC_Init_ex(HMAC_CTX *, const void *, size_t, const EVP_MD *, ENGINE *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    FIPS_service_indicator_lock_state();
    let mut result: libc::c_int = 0 as libc::c_int;
    let mut pad: [uint64_t; 16] = [
        0 as libc::c_int as uint64_t,
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
    let mut key_block: [uint64_t; 16] = [
        0 as libc::c_int as uint64_t,
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
    if block_size < key_len {
        if ((*methods).init)
            .expect(
                "non-null function pointer",
            )(&mut (*ctx).md_ctx as *mut md_ctx_union as *mut libc::c_void) == 0
            || ((*methods).update)
                .expect(
                    "non-null function pointer",
                )(
                &mut (*ctx).md_ctx as *mut md_ctx_union as *mut libc::c_void,
                key,
                key_len,
            ) == 0
            || ((*methods).finalize)
                .expect(
                    "non-null function pointer",
                )(
                key_block.as_mut_ptr() as *mut uint8_t,
                &mut (*ctx).md_ctx as *mut md_ctx_union as *mut libc::c_void,
            ) == 0
        {
            current_block = 4563124131506814892;
        } else {
            current_block = 15652330335145281839;
        }
    } else {
        if key_len <= ::core::mem::size_of::<[uint64_t; 16]>() as libc::c_ulong {} else {
            __assert_fail(
                b"key_len <= sizeof(key_block)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                    as *const u8 as *const libc::c_char,
                399 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 77],
                    &[libc::c_char; 77],
                >(
                    b"int HMAC_Init_ex(HMAC_CTX *, const void *, size_t, const EVP_MD *, ENGINE *)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_2364: {
            if key_len <= ::core::mem::size_of::<[uint64_t; 16]>() as libc::c_ulong
            {} else {
                __assert_fail(
                    b"key_len <= sizeof(key_block)\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                        as *const u8 as *const libc::c_char,
                    399 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 77],
                        &[libc::c_char; 77],
                    >(
                        b"int HMAC_Init_ex(HMAC_CTX *, const void *, size_t, const EVP_MD *, ENGINE *)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        OPENSSL_memcpy(key_block.as_mut_ptr() as *mut libc::c_void, key, key_len);
        current_block = 15652330335145281839;
    }
    match current_block {
        15652330335145281839 => {
            let mut i: size_t = 0 as libc::c_int as size_t;
            while i < block_size / 8 as libc::c_int as size_t {
                pad[i
                    as usize] = 0x3636363636363636 as libc::c_long as uint64_t
                    ^ key_block[i as usize];
                i = i.wrapping_add(1);
                i;
            }
            if !(((*methods).init)
                .expect(
                    "non-null function pointer",
                )(&mut (*ctx).i_ctx as *mut md_ctx_union as *mut libc::c_void) == 0
                || ((*methods).update)
                    .expect(
                        "non-null function pointer",
                    )(
                    &mut (*ctx).i_ctx as *mut md_ctx_union as *mut libc::c_void,
                    pad.as_mut_ptr() as *const libc::c_void,
                    block_size,
                ) == 0)
            {
                let mut i_0: size_t = 0 as libc::c_int as size_t;
                while i_0 < block_size / 8 as libc::c_int as size_t {
                    pad[i_0
                        as usize] = 0x5c5c5c5c5c5c5c5c as libc::c_long as uint64_t
                        ^ key_block[i_0 as usize];
                    i_0 = i_0.wrapping_add(1);
                    i_0;
                }
                if !(((*methods).init)
                    .expect(
                        "non-null function pointer",
                    )(&mut (*ctx).o_ctx as *mut md_ctx_union as *mut libc::c_void) == 0
                    || ((*methods).update)
                        .expect(
                            "non-null function pointer",
                        )(
                        &mut (*ctx).o_ctx as *mut md_ctx_union as *mut libc::c_void,
                        pad.as_mut_ptr() as *const libc::c_void,
                        block_size,
                    ) == 0)
                {
                    OPENSSL_memcpy(
                        &mut (*ctx).md_ctx as *mut md_ctx_union as *mut libc::c_void,
                        &mut (*ctx).i_ctx as *mut md_ctx_union as *const libc::c_void,
                        ::core::mem::size_of::<md_ctx_union>() as libc::c_ulong,
                    );
                    (*ctx).state = 1 as libc::c_int as int8_t;
                    result = 1 as libc::c_int;
                }
            }
        }
        _ => {}
    }
    OPENSSL_cleanse(pad.as_mut_ptr() as *mut libc::c_void, 128 as libc::c_int as size_t);
    OPENSSL_cleanse(
        key_block.as_mut_ptr() as *mut libc::c_void,
        128 as libc::c_int as size_t,
    );
    FIPS_service_indicator_unlock_state();
    if result != 1 as libc::c_int {
        HMAC_CTX_cleanup(ctx);
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn HMAC_Update(
    mut ctx: *mut HMAC_CTX,
    mut data: *const uint8_t,
    mut data_len: size_t,
) -> libc::c_int {
    if !(1 as libc::c_int == (*ctx).state as libc::c_int
        || 2 as libc::c_int == (*ctx).state as libc::c_int)
    {
        return 0 as libc::c_int;
    }
    (*ctx).state = 2 as libc::c_int as int8_t;
    return ((*(*ctx).methods).update)
        .expect(
            "non-null function pointer",
        )(
        &mut (*ctx).md_ctx as *mut md_ctx_union as *mut libc::c_void,
        data as *const libc::c_void,
        data_len,
    );
}
#[no_mangle]
pub unsafe extern "C" fn HMAC_Final(
    mut ctx: *mut HMAC_CTX,
    mut out: *mut uint8_t,
    mut out_len: *mut libc::c_uint,
) -> libc::c_int {
    if out.is_null() {
        return 0 as libc::c_int;
    }
    let mut methods: *const HmacMethods = (*ctx).methods;
    if !(1 as libc::c_int == (*ctx).state as libc::c_int
        || 2 as libc::c_int == (*ctx).state as libc::c_int)
    {
        return 0 as libc::c_int;
    }
    FIPS_service_indicator_lock_state();
    let mut result: libc::c_int = 0 as libc::c_int;
    let mut evp_md: *const EVP_MD = (*ctx).md;
    let mut hmac_len: libc::c_int = EVP_MD_size(evp_md) as libc::c_int;
    let mut tmp: [uint8_t; 64] = [0; 64];
    if !(((*methods).finalize)
        .expect(
            "non-null function pointer",
        )(tmp.as_mut_ptr(), &mut (*ctx).md_ctx as *mut md_ctx_union as *mut libc::c_void)
        == 0)
    {
        OPENSSL_memcpy(
            &mut (*ctx).md_ctx as *mut md_ctx_union as *mut libc::c_void,
            &mut (*ctx).o_ctx as *mut md_ctx_union as *const libc::c_void,
            ::core::mem::size_of::<md_ctx_union>() as libc::c_ulong,
        );
        if !(((*(*ctx).methods).update)
            .expect(
                "non-null function pointer",
            )(
            &mut (*ctx).md_ctx as *mut md_ctx_union as *mut libc::c_void,
            tmp.as_mut_ptr() as *const libc::c_void,
            hmac_len as size_t,
        ) == 0)
        {
            result = ((*methods).finalize)
                .expect(
                    "non-null function pointer",
                )(out, &mut (*ctx).md_ctx as *mut md_ctx_union as *mut libc::c_void);
            OPENSSL_memcpy(
                &mut (*ctx).md_ctx as *mut md_ctx_union as *mut libc::c_void,
                &mut (*ctx).i_ctx as *mut md_ctx_union as *const libc::c_void,
                ::core::mem::size_of::<md_ctx_union>() as libc::c_ulong,
            );
            (*ctx).state = 3 as libc::c_int as int8_t;
        }
    }
    FIPS_service_indicator_unlock_state();
    if result != 0 {
        HMAC_verify_service_indicator(evp_md);
        if !out_len.is_null() {
            *out_len = hmac_len as libc::c_uint;
        }
        return 1 as libc::c_int;
    } else {
        if !out_len.is_null() {
            *out_len = 0 as libc::c_int as libc::c_uint;
        }
        return 0 as libc::c_int;
    };
}
#[no_mangle]
pub unsafe extern "C" fn HMAC_size(mut ctx: *const HMAC_CTX) -> size_t {
    return EVP_MD_size((*ctx).md);
}
#[no_mangle]
pub unsafe extern "C" fn HMAC_CTX_get_md(mut ctx: *const HMAC_CTX) -> *const EVP_MD {
    return (*ctx).md;
}
#[no_mangle]
pub unsafe extern "C" fn HMAC_CTX_copy_ex(
    mut dest: *mut HMAC_CTX,
    mut src: *const HMAC_CTX,
) -> libc::c_int {
    OPENSSL_memcpy(
        dest as *mut libc::c_void,
        src as *const libc::c_void,
        ::core::mem::size_of::<HMAC_CTX>() as libc::c_ulong,
    );
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn HMAC_CTX_reset(mut ctx: *mut HMAC_CTX) {
    HMAC_CTX_cleanup(ctx);
}
#[no_mangle]
pub unsafe extern "C" fn HMAC_set_precomputed_key_export(
    mut ctx: *mut HMAC_CTX,
) -> libc::c_int {
    if 1 as libc::c_int != (*ctx).state as libc::c_int
        && 4 as libc::c_int != (*ctx).state as libc::c_int
    {
        ERR_put_error(
            28 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                as *const u8 as *const libc::c_char,
            501 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*ctx).state = 4 as libc::c_int as int8_t;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn HMAC_get_precomputed_key(
    mut ctx: *mut HMAC_CTX,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
) -> libc::c_int {
    if 4 as libc::c_int != (*ctx).state as libc::c_int {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            103 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                as *const u8 as *const libc::c_char,
            510 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if out_len.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                as *const u8 as *const libc::c_char,
            515 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let chaining_length: size_t = (*(*ctx).methods).chaining_length;
    let mut actual_out_len: size_t = chaining_length * 2 as libc::c_int as size_t;
    if actual_out_len <= (2 as libc::c_int * 64 as libc::c_int) as size_t {} else {
        __assert_fail(
            b"actual_out_len <= HMAC_MAX_PRECOMPUTED_KEY_SIZE\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                as *const u8 as *const libc::c_char,
            521 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 62],
                &[libc::c_char; 62],
            >(b"int HMAC_get_precomputed_key(HMAC_CTX *, uint8_t *, size_t *)\0"))
                .as_ptr(),
        );
    }
    'c_5097: {
        if actual_out_len <= (2 as libc::c_int * 64 as libc::c_int) as size_t {} else {
            __assert_fail(
                b"actual_out_len <= HMAC_MAX_PRECOMPUTED_KEY_SIZE\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                    as *const u8 as *const libc::c_char,
                521 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 62],
                    &[libc::c_char; 62],
                >(b"int HMAC_get_precomputed_key(HMAC_CTX *, uint8_t *, size_t *)\0"))
                    .as_ptr(),
            );
        }
    };
    if out.is_null() {
        *out_len = actual_out_len;
        return 1 as libc::c_int;
    }
    if *out_len < actual_out_len {
        ERR_put_error(
            28 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                as *const u8 as *const libc::c_char,
            531 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    *out_len = actual_out_len;
    let mut i_ctx_n: uint64_t = 0;
    let mut o_ctx_n: uint64_t = 0 as libc::c_int as uint64_t;
    let ok: libc::c_int = (((*(*ctx).methods).get_state)
        .expect(
            "non-null function pointer",
        )(&mut (*ctx).i_ctx as *mut md_ctx_union as *mut libc::c_void, out, &mut i_ctx_n)
        != 0
        && ((*(*ctx).methods).get_state)
            .expect(
                "non-null function pointer",
            )(
            &mut (*ctx).o_ctx as *mut md_ctx_union as *mut libc::c_void,
            out.offset(chaining_length as isize),
            &mut o_ctx_n,
        ) != 0) as libc::c_int;
    if ok != 0 {} else {
        __assert_fail(
            b"ok\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                as *const u8 as *const libc::c_char,
            547 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 62],
                &[libc::c_char; 62],
            >(b"int HMAC_get_precomputed_key(HMAC_CTX *, uint8_t *, size_t *)\0"))
                .as_ptr(),
        );
    }
    'c_5014: {
        if ok != 0 {} else {
            __assert_fail(
                b"ok\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                    as *const u8 as *const libc::c_char,
                547 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 62],
                    &[libc::c_char; 62],
                >(b"int HMAC_get_precomputed_key(HMAC_CTX *, uint8_t *, size_t *)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut block_size: size_t = EVP_MD_block_size((*ctx).md);
    if 8 as libc::c_int as size_t * block_size == i_ctx_n {} else {
        __assert_fail(
            b"8 * block_size == i_ctx_n\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                as *const u8 as *const libc::c_char,
            552 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 62],
                &[libc::c_char; 62],
            >(b"int HMAC_get_precomputed_key(HMAC_CTX *, uint8_t *, size_t *)\0"))
                .as_ptr(),
        );
    }
    'c_4922: {
        if 8 as libc::c_int as size_t * block_size == i_ctx_n {} else {
            __assert_fail(
                b"8 * block_size == i_ctx_n\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                    as *const u8 as *const libc::c_char,
                552 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 62],
                    &[libc::c_char; 62],
                >(b"int HMAC_get_precomputed_key(HMAC_CTX *, uint8_t *, size_t *)\0"))
                    .as_ptr(),
            );
        }
    };
    if 8 as libc::c_int as size_t * block_size == o_ctx_n {} else {
        __assert_fail(
            b"8 * block_size == o_ctx_n\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                as *const u8 as *const libc::c_char,
            553 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 62],
                &[libc::c_char; 62],
            >(b"int HMAC_get_precomputed_key(HMAC_CTX *, uint8_t *, size_t *)\0"))
                .as_ptr(),
        );
    }
    'c_4873: {
        if 8 as libc::c_int as size_t * block_size == o_ctx_n {} else {
            __assert_fail(
                b"8 * block_size == o_ctx_n\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                    as *const u8 as *const libc::c_char,
                553 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 62],
                    &[libc::c_char; 62],
                >(b"int HMAC_get_precomputed_key(HMAC_CTX *, uint8_t *, size_t *)\0"))
                    .as_ptr(),
            );
        }
    };
    (*ctx).state = 1 as libc::c_int as int8_t;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn HMAC_Init_from_precomputed_key(
    mut ctx: *mut HMAC_CTX,
    mut precomputed_key: *const uint8_t,
    mut precomputed_key_len: size_t,
    mut md: *const EVP_MD,
) -> libc::c_int {
    if 3 as libc::c_int == (*ctx).state as libc::c_int
        || 4 as libc::c_int == (*ctx).state as libc::c_int
    {
        (*ctx).state = 1 as libc::c_int as int8_t;
    }
    if 1 as libc::c_int == (*ctx).state as libc::c_int {
        if precomputed_key.is_null() && (md.is_null() || md == (*ctx).md) {
            return 1 as libc::c_int;
        }
    }
    if hmac_ctx_set_md_methods(ctx, md) == 0 {
        return 0 as libc::c_int;
    }
    let mut methods: *const HmacMethods = (*ctx).methods;
    let chaining_length: size_t = (*methods).chaining_length;
    let block_size: size_t = EVP_MD_block_size((*methods).evp_md);
    if block_size <= 128 as libc::c_int as size_t {} else {
        __assert_fail(
            b"block_size <= EVP_MAX_MD_BLOCK_SIZE\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                as *const u8 as *const libc::c_char,
            590 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 88],
                &[libc::c_char; 88],
            >(
                b"int HMAC_Init_from_precomputed_key(HMAC_CTX *, const uint8_t *, size_t, const EVP_MD *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_5410: {
        if block_size <= 128 as libc::c_int as size_t {} else {
            __assert_fail(
                b"block_size <= EVP_MAX_MD_BLOCK_SIZE\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                    as *const u8 as *const libc::c_char,
                590 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 88],
                    &[libc::c_char; 88],
                >(
                    b"int HMAC_Init_from_precomputed_key(HMAC_CTX *, const uint8_t *, size_t, const EVP_MD *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if 2 as libc::c_int as size_t * chaining_length
        <= (2 as libc::c_int * 64 as libc::c_int) as size_t
    {} else {
        __assert_fail(
            b"2 * chaining_length <= HMAC_MAX_PRECOMPUTED_KEY_SIZE\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                as *const u8 as *const libc::c_char,
            591 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 88],
                &[libc::c_char; 88],
            >(
                b"int HMAC_Init_from_precomputed_key(HMAC_CTX *, const uint8_t *, size_t, const EVP_MD *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_5356: {
        if 2 as libc::c_int as size_t * chaining_length
            <= (2 as libc::c_int * 64 as libc::c_int) as size_t
        {} else {
            __assert_fail(
                b"2 * chaining_length <= HMAC_MAX_PRECOMPUTED_KEY_SIZE\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                    as *const u8 as *const libc::c_char,
                591 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 88],
                    &[libc::c_char; 88],
                >(
                    b"int HMAC_Init_from_precomputed_key(HMAC_CTX *, const uint8_t *, size_t, const EVP_MD *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if 2 as libc::c_int as size_t * chaining_length != precomputed_key_len {
        return 0 as libc::c_int;
    }
    if precomputed_key.is_null() {
        ERR_put_error(
            28 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/hmac/hmac.c\0"
                as *const u8 as *const libc::c_char,
            599 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    FIPS_service_indicator_lock_state();
    let mut result: libc::c_int = 0 as libc::c_int;
    if !(((*methods).init_from_state)
        .expect(
            "non-null function pointer",
        )(
        &mut (*ctx).i_ctx as *mut md_ctx_union as *mut libc::c_void,
        precomputed_key,
        block_size * 8 as libc::c_int as size_t,
    ) == 0)
    {
        if !(((*methods).init_from_state)
            .expect(
                "non-null function pointer",
            )(
            &mut (*ctx).o_ctx as *mut md_ctx_union as *mut libc::c_void,
            precomputed_key.offset(chaining_length as isize),
            block_size * 8 as libc::c_int as size_t,
        ) == 0)
        {
            OPENSSL_memcpy(
                &mut (*ctx).md_ctx as *mut md_ctx_union as *mut libc::c_void,
                &mut (*ctx).i_ctx as *mut md_ctx_union as *const libc::c_void,
                ::core::mem::size_of::<md_ctx_union>() as libc::c_ulong,
            );
            (*ctx).state = 1 as libc::c_int as int8_t;
            result = 1 as libc::c_int;
        }
    }
    FIPS_service_indicator_unlock_state();
    if result != 1 as libc::c_int {
        HMAC_CTX_cleanup(ctx);
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn HMAC_Init(
    mut ctx: *mut HMAC_CTX,
    mut key: *const libc::c_void,
    mut key_len: libc::c_int,
    mut md: *const EVP_MD,
) -> libc::c_int {
    if !key.is_null() && !md.is_null() {
        HMAC_CTX_init(ctx);
    }
    return HMAC_Init_ex(ctx, key, key_len as size_t, md, 0 as *mut ENGINE);
}
#[no_mangle]
pub unsafe extern "C" fn HMAC_CTX_copy(
    mut dest: *mut HMAC_CTX,
    mut src: *const HMAC_CTX,
) -> libc::c_int {
    HMAC_CTX_init(dest);
    return HMAC_CTX_copy_ex(dest, src);
}
