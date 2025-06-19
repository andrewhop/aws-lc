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
    pub type evp_md_pctx_ops;
    pub type evp_pkey_ctx_st;
    pub type env_md_st;
    pub type hmac_methods_st;
    fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX;
    fn EVP_MD_CTX_free(ctx: *mut EVP_MD_CTX);
    fn EVP_MD_CTX_reset(ctx: *mut EVP_MD_CTX) -> libc::c_int;
    fn EVP_DigestInit_ex(
        ctx: *mut EVP_MD_CTX,
        type_0: *const EVP_MD,
        engine: *mut ENGINE,
    ) -> libc::c_int;
    fn EVP_DigestUpdate(
        ctx: *mut EVP_MD_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn EVP_DigestFinal(
        ctx: *mut EVP_MD_CTX,
        md_out: *mut uint8_t,
        out_size: *mut libc::c_uint,
    ) -> libc::c_int;
    fn EVP_MD_size(md: *const EVP_MD) -> size_t;
    fn HMAC_CTX_new() -> *mut HMAC_CTX;
    fn HMAC_CTX_free(ctx: *mut HMAC_CTX);
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
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn CRYPTO_once(
        once: *mut CRYPTO_once_t,
        init: Option::<unsafe extern "C" fn() -> ()>,
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
pub type pthread_once_t = libc::c_int;
pub type ENGINE = engine_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct env_md_ctx_st {
    pub digest: *const EVP_MD,
    pub md_data: *mut libc::c_void,
    pub update: Option::<
        unsafe extern "C" fn(*mut EVP_MD_CTX, *const libc::c_void, size_t) -> libc::c_int,
    >,
    pub pctx: *mut EVP_PKEY_CTX,
    pub pctx_ops: *const evp_md_pctx_ops,
    pub flags: libc::c_ulong,
}
pub type EVP_PKEY_CTX = evp_pkey_ctx_st;
pub type EVP_MD_CTX = env_md_ctx_st;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sskdf_variant_ctx {
    pub data: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sskdf_variant_digest_ctx {
    pub digest: *const EVP_MD,
    pub md_ctx: *mut EVP_MD_CTX,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sskdf_variant {
    pub h_output_bytes: Option::<unsafe extern "C" fn(*mut sskdf_variant_ctx) -> size_t>,
    pub compute: Option::<
        unsafe extern "C" fn(
            *mut sskdf_variant_ctx,
            *mut uint8_t,
            size_t,
            *const uint8_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
}
pub type CRYPTO_once_t = pthread_once_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sskdf_variant_hmac_ctx {
    pub hmac_ctx: *mut HMAC_CTX,
}
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
unsafe extern "C" fn SSKDF_digest_verify_service_indicator(mut dgst: *const EVP_MD) {}
#[inline]
unsafe extern "C" fn SSKDF_hmac_verify_service_indicator(mut dgst: *const EVP_MD) {}
unsafe extern "C" fn sskdf_variant_digest_ctx_init(
    mut ctx: *mut sskdf_variant_ctx,
    mut digest: *const EVP_MD,
) -> libc::c_int {
    let mut variant_ctx: *mut sskdf_variant_digest_ctx = 0
        as *mut sskdf_variant_digest_ctx;
    let mut md_ctx: *mut EVP_MD_CTX = 0 as *mut EVP_MD_CTX;
    let mut ret: libc::c_int = 0 as libc::c_int;
    if !(ctx.is_null() || !((*ctx).data).is_null() || digest.is_null()) {
        variant_ctx = OPENSSL_malloc(
            ::core::mem::size_of::<sskdf_variant_digest_ctx>() as libc::c_ulong,
        ) as *mut sskdf_variant_digest_ctx;
        if !variant_ctx.is_null() {
            md_ctx = EVP_MD_CTX_new();
            if !md_ctx.is_null() {
                ret = 1 as libc::c_int;
                (*variant_ctx).digest = digest;
                (*variant_ctx).md_ctx = md_ctx;
                (*ctx).data = variant_ctx as *mut libc::c_void;
                return ret;
            }
        }
    }
    EVP_MD_CTX_free(md_ctx);
    OPENSSL_free(variant_ctx as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn sskdf_variant_digest_ctx_cleanup(mut ctx: *mut sskdf_variant_ctx) {
    if ctx.is_null() || ((*ctx).data).is_null() {
        return;
    }
    let mut variant_ctx: *mut sskdf_variant_digest_ctx = (*ctx).data
        as *mut sskdf_variant_digest_ctx;
    EVP_MD_CTX_free((*variant_ctx).md_ctx);
    OPENSSL_free(variant_ctx as *mut libc::c_void);
    (*ctx).data = 0 as *mut libc::c_void;
}
unsafe extern "C" fn sskdf_variant_digest_output_size(
    mut ctx: *mut sskdf_variant_ctx,
) -> size_t {
    if ctx.is_null() || ((*ctx).data).is_null() {
        return 0 as libc::c_int as size_t;
    }
    let mut variant_ctx: *mut sskdf_variant_digest_ctx = (*ctx).data
        as *mut sskdf_variant_digest_ctx;
    return EVP_MD_size((*variant_ctx).digest);
}
unsafe extern "C" fn sskdf_variant_digest_compute(
    mut ctx: *mut sskdf_variant_ctx,
    mut out: *mut uint8_t,
    mut out_len: size_t,
    mut counter: *const uint8_t,
    mut secret: *const uint8_t,
    mut secret_len: size_t,
    mut info: *const uint8_t,
    mut info_len: size_t,
) -> libc::c_int {
    if ctx.is_null() || ((*ctx).data).is_null() || out.is_null() || counter.is_null()
        || secret.is_null()
    {
        return 0 as libc::c_int;
    }
    let mut variant_ctx: *mut sskdf_variant_digest_ctx = (*ctx).data
        as *mut sskdf_variant_digest_ctx;
    if ((*variant_ctx).md_ctx).is_null() || ((*variant_ctx).digest).is_null() {
        return 0 as libc::c_int;
    }
    let mut written: uint32_t = 0;
    if EVP_MD_CTX_reset((*variant_ctx).md_ctx) == 0
        || EVP_DigestInit_ex(
            (*variant_ctx).md_ctx,
            (*variant_ctx).digest,
            0 as *mut ENGINE,
        ) == 0
        || EVP_DigestUpdate(
            (*variant_ctx).md_ctx,
            &*counter.offset(0 as libc::c_int as isize) as *const uint8_t
                as *const libc::c_void,
            4 as libc::c_int as size_t,
        ) == 0
        || EVP_DigestUpdate(
            (*variant_ctx).md_ctx,
            secret as *const libc::c_void,
            secret_len,
        ) == 0
        || EVP_DigestUpdate((*variant_ctx).md_ctx, info as *const libc::c_void, info_len)
            == 0 || EVP_DigestFinal((*variant_ctx).md_ctx, out, &mut written) == 0
        || written as size_t != out_len
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn sskdf_variant_digest_storage_bss_get() -> *mut sskdf_variant {
    return &mut sskdf_variant_digest_storage;
}
unsafe extern "C" fn sskdf_variant_digest_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut sskdf_variant_digest_once;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sskdf_variant_digest() -> *const sskdf_variant {
    CRYPTO_once(
        sskdf_variant_digest_once_bss_get(),
        Some(sskdf_variant_digest_init as unsafe extern "C" fn() -> ()),
    );
    return sskdf_variant_digest_storage_bss_get() as *const sskdf_variant;
}
static mut sskdf_variant_digest_once: CRYPTO_once_t = 0 as libc::c_int;
static mut sskdf_variant_digest_storage: sskdf_variant = sskdf_variant {
    h_output_bytes: None,
    compute: None,
};
unsafe extern "C" fn sskdf_variant_digest_init() {
    sskdf_variant_digest_do_init(sskdf_variant_digest_storage_bss_get());
}
unsafe extern "C" fn sskdf_variant_digest_do_init(mut out: *mut sskdf_variant) {
    (*out)
        .h_output_bytes = Some(
        sskdf_variant_digest_output_size
            as unsafe extern "C" fn(*mut sskdf_variant_ctx) -> size_t,
    );
    (*out)
        .compute = Some(
        sskdf_variant_digest_compute
            as unsafe extern "C" fn(
                *mut sskdf_variant_ctx,
                *mut uint8_t,
                size_t,
                *const uint8_t,
                *const uint8_t,
                size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
}
unsafe extern "C" fn sskdf_variant_hmac_ctx_init(
    mut ctx: *mut sskdf_variant_ctx,
    mut digest: *const EVP_MD,
    mut salt: *const uint8_t,
    mut salt_len: size_t,
) -> libc::c_int {
    let mut variant_ctx: *mut sskdf_variant_hmac_ctx = 0 as *mut sskdf_variant_hmac_ctx;
    let mut hmac_ctx: *mut HMAC_CTX = 0 as *mut HMAC_CTX;
    let mut ret: libc::c_int = 0 as libc::c_int;
    if !(ctx.is_null() || !((*ctx).data).is_null() || digest.is_null()) {
        variant_ctx = OPENSSL_malloc(
            ::core::mem::size_of::<sskdf_variant_hmac_ctx>() as libc::c_ulong,
        ) as *mut sskdf_variant_hmac_ctx;
        if !variant_ctx.is_null() {
            hmac_ctx = HMAC_CTX_new();
            if !hmac_ctx.is_null() {
                if !(HMAC_Init_ex(
                    hmac_ctx,
                    salt as *const libc::c_void,
                    salt_len,
                    digest,
                    0 as *mut ENGINE,
                ) == 0)
                {
                    ret = 1 as libc::c_int;
                    (*variant_ctx).hmac_ctx = hmac_ctx;
                    (*ctx).data = variant_ctx as *mut libc::c_void;
                    return ret;
                }
            }
        }
    }
    HMAC_CTX_free(hmac_ctx);
    OPENSSL_free(variant_ctx as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn sskdf_variant_hmac_ctx_cleanup(mut ctx: *mut sskdf_variant_ctx) {
    if ctx.is_null() || ((*ctx).data).is_null() {
        return;
    }
    let mut variant_ctx: *mut sskdf_variant_hmac_ctx = (*ctx).data
        as *mut sskdf_variant_hmac_ctx;
    HMAC_CTX_free((*variant_ctx).hmac_ctx);
    OPENSSL_free(variant_ctx as *mut libc::c_void);
    (*ctx).data = 0 as *mut libc::c_void;
}
unsafe extern "C" fn sskdf_variant_hmac_output_size(
    mut ctx: *mut sskdf_variant_ctx,
) -> size_t {
    if ctx.is_null() || ((*ctx).data).is_null() {
        return 0 as libc::c_int as size_t;
    }
    let mut variant_ctx: *mut sskdf_variant_hmac_ctx = (*ctx).data
        as *mut sskdf_variant_hmac_ctx;
    if variant_ctx.is_null() {
        return 0 as libc::c_int as size_t;
    }
    return HMAC_size((*variant_ctx).hmac_ctx);
}
unsafe extern "C" fn sskdf_variant_hmac_compute(
    mut ctx: *mut sskdf_variant_ctx,
    mut out: *mut uint8_t,
    mut out_len: size_t,
    mut counter: *const uint8_t,
    mut secret: *const uint8_t,
    mut secret_len: size_t,
    mut info: *const uint8_t,
    mut info_len: size_t,
) -> libc::c_int {
    if ctx.is_null() || ((*ctx).data).is_null() || out.is_null() || counter.is_null()
        || secret.is_null()
    {
        return 0 as libc::c_int;
    }
    let mut variant_ctx: *mut sskdf_variant_hmac_ctx = (*ctx).data
        as *mut sskdf_variant_hmac_ctx;
    if ((*variant_ctx).hmac_ctx).is_null() {
        return 0 as libc::c_int;
    }
    let mut written: uint32_t = 0;
    if HMAC_Init_ex(
        (*variant_ctx).hmac_ctx,
        0 as *const libc::c_void,
        0 as libc::c_int as size_t,
        0 as *const EVP_MD,
        0 as *mut ENGINE,
    ) == 0
        || HMAC_Update(
            (*variant_ctx).hmac_ctx,
            &*counter.offset(0 as libc::c_int as isize),
            4 as libc::c_int as size_t,
        ) == 0 || HMAC_Update((*variant_ctx).hmac_ctx, secret, secret_len) == 0
        || HMAC_Update((*variant_ctx).hmac_ctx, info, info_len) == 0
        || HMAC_Final((*variant_ctx).hmac_ctx, out, &mut written) == 0
        || out_len != written as size_t
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sskdf_variant_hmac() -> *const sskdf_variant {
    CRYPTO_once(
        sskdf_variant_hmac_once_bss_get(),
        Some(sskdf_variant_hmac_init as unsafe extern "C" fn() -> ()),
    );
    return sskdf_variant_hmac_storage_bss_get() as *const sskdf_variant;
}
unsafe extern "C" fn sskdf_variant_hmac_storage_bss_get() -> *mut sskdf_variant {
    return &mut sskdf_variant_hmac_storage;
}
unsafe extern "C" fn sskdf_variant_hmac_do_init(mut out: *mut sskdf_variant) {
    (*out)
        .h_output_bytes = Some(
        sskdf_variant_hmac_output_size
            as unsafe extern "C" fn(*mut sskdf_variant_ctx) -> size_t,
    );
    (*out)
        .compute = Some(
        sskdf_variant_hmac_compute
            as unsafe extern "C" fn(
                *mut sskdf_variant_ctx,
                *mut uint8_t,
                size_t,
                *const uint8_t,
                *const uint8_t,
                size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
}
unsafe extern "C" fn sskdf_variant_hmac_init() {
    sskdf_variant_hmac_do_init(sskdf_variant_hmac_storage_bss_get());
}
unsafe extern "C" fn sskdf_variant_hmac_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut sskdf_variant_hmac_once;
}
static mut sskdf_variant_hmac_storage: sskdf_variant = sskdf_variant {
    h_output_bytes: None,
    compute: None,
};
static mut sskdf_variant_hmac_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn SSKDF(
    mut variant: *const sskdf_variant,
    mut ctx: *mut sskdf_variant_ctx,
    mut out_key: *mut uint8_t,
    mut out_len: size_t,
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
    let mut todo: size_t = 0;
    let mut current_block: u64;
    let mut ret: libc::c_int = 0 as libc::c_int;
    if ctx.is_null() || variant.is_null() {
        return 0 as libc::c_int;
    }
    if !(out_key.is_null() || out_len == 0 as libc::c_int as size_t
        || out_len > ((1 as libc::c_int) << 30 as libc::c_int) as size_t
        || secret.is_null() || secret_len == 0 as libc::c_int as size_t
        || secret_len > ((1 as libc::c_int) << 30 as libc::c_int) as size_t
        || info_len > ((1 as libc::c_int) << 30 as libc::c_int) as size_t)
    {
        h_output_bytes = ((*variant).h_output_bytes)
            .expect("non-null function pointer")(ctx);
        if !(h_output_bytes == 0 as libc::c_int as size_t
            || h_output_bytes > 64 as libc::c_int as size_t)
        {
            n = out_len
                .wrapping_add(h_output_bytes)
                .wrapping_sub(1 as libc::c_int as uint64_t) / h_output_bytes;
            if !(n > 4294967295 as libc::c_uint as uint64_t) {
                out_key_i = [0; 64];
                counter = [0; 4];
                done = 0 as libc::c_int as size_t;
                todo = h_output_bytes;
                let mut i: uint32_t = 0 as libc::c_int as uint32_t;
                loop {
                    if !((i as uint64_t) < n) {
                        current_block = 15652330335145281839;
                        break;
                    }
                    CRYPTO_store_u32_be(
                        &mut *counter.as_mut_ptr().offset(0 as libc::c_int as isize)
                            as *mut uint8_t as *mut libc::c_void,
                        i.wrapping_add(1 as libc::c_int as uint32_t),
                    );
                    if ((*variant).compute)
                        .expect(
                            "non-null function pointer",
                        )(
                        ctx,
                        &mut *out_key_i.as_mut_ptr().offset(0 as libc::c_int as isize),
                        h_output_bytes,
                        counter.as_mut_ptr() as *const uint8_t,
                        secret,
                        secret_len,
                        info,
                        info_len,
                    ) == 0
                    {
                        current_block = 17689180521615900624;
                        break;
                    }
                    todo = h_output_bytes;
                    if todo > out_len.wrapping_sub(done) {
                        todo = out_len.wrapping_sub(done);
                    }
                    OPENSSL_memcpy(
                        out_key.offset(done as isize) as *mut libc::c_void,
                        out_key_i.as_mut_ptr() as *const libc::c_void,
                        todo,
                    );
                    done = done.wrapping_add(todo);
                    i = i.wrapping_add(1);
                    i;
                }
                match current_block {
                    17689180521615900624 => {}
                    _ => {
                        ret = 1 as libc::c_int;
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
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SSKDF_digest(
    mut out_key: *mut uint8_t,
    mut out_len: size_t,
    mut digest: *const EVP_MD,
    mut secret: *const uint8_t,
    mut secret_len: size_t,
    mut info: *const uint8_t,
    mut info_len: size_t,
) -> libc::c_int {
    FIPS_service_indicator_lock_state();
    let mut ctx: sskdf_variant_ctx = {
        let mut init = sskdf_variant_ctx {
            data: 0 as *mut libc::c_void,
        };
        init
    };
    let mut ret: libc::c_int = 0 as libc::c_int;
    if sskdf_variant_digest_ctx_init(&mut ctx, digest) == 0 {
        FIPS_service_indicator_unlock_state();
        return 0 as libc::c_int;
    }
    if !(SSKDF(
        sskdf_variant_digest(),
        &mut ctx,
        out_key,
        out_len,
        secret,
        secret_len,
        info,
        info_len,
    ) == 0)
    {
        ret = 1 as libc::c_int;
    }
    sskdf_variant_digest_ctx_cleanup(&mut ctx);
    FIPS_service_indicator_unlock_state();
    if ret != 0 {
        SSKDF_digest_verify_service_indicator(digest);
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SSKDF_hmac(
    mut out_key: *mut uint8_t,
    mut out_len: size_t,
    mut digest: *const EVP_MD,
    mut secret: *const uint8_t,
    mut secret_len: size_t,
    mut info: *const uint8_t,
    mut info_len: size_t,
    mut salt: *const uint8_t,
    mut salt_len: size_t,
) -> libc::c_int {
    FIPS_service_indicator_lock_state();
    let mut ctx: sskdf_variant_ctx = {
        let mut init = sskdf_variant_ctx {
            data: 0 as *mut libc::c_void,
        };
        init
    };
    let mut ret: libc::c_int = 0 as libc::c_int;
    if sskdf_variant_hmac_ctx_init(&mut ctx, digest, salt, salt_len) == 0 {
        FIPS_service_indicator_unlock_state();
        return 0 as libc::c_int;
    }
    if !(SSKDF(
        sskdf_variant_hmac(),
        &mut ctx,
        out_key,
        out_len,
        secret,
        secret_len,
        info,
        info_len,
    ) == 0)
    {
        ret = 1 as libc::c_int;
    }
    sskdf_variant_hmac_ctx_cleanup(&mut ctx);
    FIPS_service_indicator_unlock_state();
    if ret != 0 {
        SSKDF_hmac_verify_service_indicator(digest);
    }
    return ret;
}
