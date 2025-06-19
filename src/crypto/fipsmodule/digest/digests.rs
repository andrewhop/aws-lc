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
    pub type evp_pkey_ctx_st;
    fn RIPEMD160_Init(ctx: *mut RIPEMD160_CTX) -> libc::c_int;
    fn RIPEMD160_Update(
        ctx: *mut RIPEMD160_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn RIPEMD160_Final(out: *mut uint8_t, ctx: *mut RIPEMD160_CTX) -> libc::c_int;
    fn MD4_Init(md4: *mut MD4_CTX) -> libc::c_int;
    fn MD4_Update(
        md4: *mut MD4_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn MD4_Final(out: *mut uint8_t, md4: *mut MD4_CTX) -> libc::c_int;
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
    fn CRYPTO_once(
        once: *mut CRYPTO_once_t,
        init: Option::<unsafe extern "C" fn() -> ()>,
    );
    fn SHA3_Init(ctx: *mut KECCAK1600_CTX, bitlen: size_t) -> libc::c_int;
    fn SHA3_Update(
        ctx: *mut KECCAK1600_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn SHA3_Final(md: *mut uint8_t, ctx: *mut KECCAK1600_CTX) -> libc::c_int;
    fn SHAKE_Init(ctx: *mut KECCAK1600_CTX, block_size: size_t) -> libc::c_int;
    fn SHAKE_Absorb(
        ctx: *mut KECCAK1600_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn SHAKE_Squeeze(
        md: *mut uint8_t,
        ctx: *mut KECCAK1600_CTX,
        len: size_t,
    ) -> libc::c_int;
    fn SHAKE_Final(
        md: *mut uint8_t,
        ctx: *mut KECCAK1600_CTX,
        len: size_t,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type pthread_once_t = libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct RIPEMD160state_st {
    pub h: [uint32_t; 5],
    pub Nl: uint32_t,
    pub Nh: uint32_t,
    pub data: [uint8_t; 64],
    pub num: libc::c_uint,
}
pub type RIPEMD160_CTX = RIPEMD160state_st;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_md_pctx_ops {
    pub free: Option::<unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> ()>,
    pub dup: Option::<unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> *mut EVP_PKEY_CTX>,
}
pub type EVP_PKEY_CTX = evp_pkey_ctx_st;
pub type EVP_MD_CTX = env_md_ctx_st;
pub type EVP_MD = env_md_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct env_md_st {
    pub type_0: libc::c_int,
    pub md_size: libc::c_uint,
    pub flags: uint32_t,
    pub init: Option::<unsafe extern "C" fn(*mut EVP_MD_CTX) -> ()>,
    pub update: Option::<
        unsafe extern "C" fn(*mut EVP_MD_CTX, *const libc::c_void, size_t) -> libc::c_int,
    >,
    pub final_0: Option::<unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t) -> ()>,
    pub block_size: libc::c_uint,
    pub ctx_size: libc::c_uint,
    pub finalXOF: Option::<
        unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t, size_t) -> libc::c_int,
    >,
    pub squeezeXOF: Option::<
        unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t, size_t) -> (),
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct md4_state_st {
    pub h: [uint32_t; 4],
    pub Nl: uint32_t,
    pub Nh: uint32_t,
    pub data: [uint8_t; 64],
    pub num: libc::c_uint,
}
pub type MD4_CTX = md4_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct md5_state_st {
    pub h: [uint32_t; 4],
    pub Nl: uint32_t,
    pub Nh: uint32_t,
    pub data: [uint8_t; 64],
    pub num: libc::c_uint,
}
pub type MD5_CTX = md5_state_st;
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
pub type SHA256_CTX = sha256_state_st;
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
pub type SHA512_CTX = sha512_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sha_state_st {
    pub h: [uint32_t; 5],
    pub Nl: uint32_t,
    pub Nh: uint32_t,
    pub data: [uint8_t; 64],
    pub num: libc::c_uint,
}
pub type SHA_CTX = sha_state_st;
pub type CRYPTO_once_t = pthread_once_t;
pub type KECCAK1600_CTX = keccak_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct keccak_st {
    pub A: [[uint64_t; 5]; 5],
    pub block_size: size_t,
    pub md_size: size_t,
    pub buf_load: size_t,
    pub buf: [uint8_t; 168],
    pub pad: uint8_t,
    pub state: uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct MD5_SHA1_CTX {
    pub md5: MD5_CTX,
    pub sha1: SHA_CTX,
}
unsafe extern "C" fn md4_init(mut ctx: *mut EVP_MD_CTX) {
    if MD4_Init((*ctx).md_data as *mut MD4_CTX) != 0 {} else {
        __assert_fail(
            b"MD4_Init(ctx->md_data)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            81 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 28],
                &[libc::c_char; 28],
            >(b"void md4_init(EVP_MD_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_1496: {
        if MD4_Init((*ctx).md_data as *mut MD4_CTX) != 0 {} else {
            __assert_fail(
                b"MD4_Init(ctx->md_data)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                81 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 28],
                    &[libc::c_char; 28],
                >(b"void md4_init(EVP_MD_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn md4_update(
    mut ctx: *mut EVP_MD_CTX,
    mut data: *const libc::c_void,
    mut count: size_t,
) -> libc::c_int {
    return MD4_Update((*ctx).md_data as *mut MD4_CTX, data, count);
}
unsafe extern "C" fn md4_final(mut ctx: *mut EVP_MD_CTX, mut out: *mut uint8_t) {
    if MD4_Final(out, (*ctx).md_data as *mut MD4_CTX) != 0 {} else {
        __assert_fail(
            b"MD4_Final(out, ctx->md_data)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            92 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 40],
                &[libc::c_char; 40],
            >(b"void md4_final(EVP_MD_CTX *, uint8_t *)\0"))
                .as_ptr(),
        );
    }
    'c_1388: {
        if MD4_Final(out, (*ctx).md_data as *mut MD4_CTX) != 0 {} else {
            __assert_fail(
                b"MD4_Final(out, ctx->md_data)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                92 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 40],
                    &[libc::c_char; 40],
                >(b"void md4_final(EVP_MD_CTX *, uint8_t *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn EVP_md4_do_init(mut out: *mut EVP_MD) {
    (*out).type_0 = 257 as libc::c_int;
    (*out).md_size = 16 as libc::c_int as libc::c_uint;
    (*out).flags = 0 as libc::c_int as uint32_t;
    (*out).init = Some(md4_init as unsafe extern "C" fn(*mut EVP_MD_CTX) -> ());
    (*out)
        .update = Some(
        md4_update
            as unsafe extern "C" fn(
                *mut EVP_MD_CTX,
                *const libc::c_void,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .final_0 = Some(
        md4_final as unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t) -> (),
    );
    (*out).squeezeXOF = None;
    (*out).finalXOF = None;
    (*out).block_size = 64 as libc::c_int as libc::c_uint;
    (*out).ctx_size = ::core::mem::size_of::<MD4_CTX>() as libc::c_ulong as libc::c_uint;
}
static mut EVP_md4_once: CRYPTO_once_t = 0 as libc::c_int;
static mut EVP_md4_storage: EVP_MD = env_md_st {
    type_0: 0,
    md_size: 0,
    flags: 0,
    init: None,
    update: None,
    final_0: None,
    block_size: 0,
    ctx_size: 0,
    finalXOF: None,
    squeezeXOF: None,
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_md4() -> *const EVP_MD {
    CRYPTO_once(
        EVP_md4_once_bss_get(),
        Some(EVP_md4_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_md4_storage_bss_get() as *const EVP_MD;
}
unsafe extern "C" fn EVP_md4_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_md4_once;
}
unsafe extern "C" fn EVP_md4_storage_bss_get() -> *mut EVP_MD {
    return &mut EVP_md4_storage;
}
unsafe extern "C" fn EVP_md4_init() {
    EVP_md4_do_init(EVP_md4_storage_bss_get());
}
unsafe extern "C" fn md5_init(mut ctx: *mut EVP_MD_CTX) {
    if MD5_Init((*ctx).md_data as *mut MD5_CTX) != 0 {} else {
        __assert_fail(
            b"MD5_Init(ctx->md_data)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            110 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 28],
                &[libc::c_char; 28],
            >(b"void md5_init(EVP_MD_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_1766: {
        if MD5_Init((*ctx).md_data as *mut MD5_CTX) != 0 {} else {
            __assert_fail(
                b"MD5_Init(ctx->md_data)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                110 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 28],
                    &[libc::c_char; 28],
                >(b"void md5_init(EVP_MD_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn md5_update(
    mut ctx: *mut EVP_MD_CTX,
    mut data: *const libc::c_void,
    mut count: size_t,
) -> libc::c_int {
    return MD5_Update((*ctx).md_data as *mut MD5_CTX, data, count);
}
unsafe extern "C" fn md5_final(mut ctx: *mut EVP_MD_CTX, mut out: *mut uint8_t) {
    if MD5_Final(out, (*ctx).md_data as *mut MD5_CTX) != 0 {} else {
        __assert_fail(
            b"MD5_Final(out, ctx->md_data)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            121 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 40],
                &[libc::c_char; 40],
            >(b"void md5_final(EVP_MD_CTX *, uint8_t *)\0"))
                .as_ptr(),
        );
    }
    'c_1672: {
        if MD5_Final(out, (*ctx).md_data as *mut MD5_CTX) != 0 {} else {
            __assert_fail(
                b"MD5_Final(out, ctx->md_data)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                121 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 40],
                    &[libc::c_char; 40],
                >(b"void md5_final(EVP_MD_CTX *, uint8_t *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn EVP_md5_init() {
    EVP_md5_do_init(EVP_md5_storage_bss_get());
}
static mut EVP_md5_storage: EVP_MD = env_md_st {
    type_0: 0,
    md_size: 0,
    flags: 0,
    init: None,
    update: None,
    final_0: None,
    block_size: 0,
    ctx_size: 0,
    finalXOF: None,
    squeezeXOF: None,
};
static mut EVP_md5_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EVP_md5_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_md5_once;
}
unsafe extern "C" fn EVP_md5_storage_bss_get() -> *mut EVP_MD {
    return &mut EVP_md5_storage;
}
unsafe extern "C" fn EVP_md5_do_init(mut out: *mut EVP_MD) {
    (*out).type_0 = 4 as libc::c_int;
    (*out).md_size = 16 as libc::c_int as libc::c_uint;
    (*out).flags = 0 as libc::c_int as uint32_t;
    (*out).init = Some(md5_init as unsafe extern "C" fn(*mut EVP_MD_CTX) -> ());
    (*out)
        .update = Some(
        md5_update
            as unsafe extern "C" fn(
                *mut EVP_MD_CTX,
                *const libc::c_void,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .final_0 = Some(
        md5_final as unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t) -> (),
    );
    (*out).squeezeXOF = None;
    (*out).finalXOF = None;
    (*out).block_size = 64 as libc::c_int as libc::c_uint;
    (*out).ctx_size = ::core::mem::size_of::<MD5_CTX>() as libc::c_ulong as libc::c_uint;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_md5() -> *const EVP_MD {
    CRYPTO_once(
        EVP_md5_once_bss_get(),
        Some(EVP_md5_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_md5_storage_bss_get() as *const EVP_MD;
}
unsafe extern "C" fn ripemd160_init(mut ctx: *mut EVP_MD_CTX) {
    if RIPEMD160_Init((*ctx).md_data as *mut RIPEMD160_CTX) != 0 {} else {
        __assert_fail(
            b"RIPEMD160_Init(ctx->md_data)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            139 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 34],
                &[libc::c_char; 34],
            >(b"void ripemd160_init(EVP_MD_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_2022: {
        if RIPEMD160_Init((*ctx).md_data as *mut RIPEMD160_CTX) != 0 {} else {
            __assert_fail(
                b"RIPEMD160_Init(ctx->md_data)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                139 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 34],
                    &[libc::c_char; 34],
                >(b"void ripemd160_init(EVP_MD_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn ripemd160_update(
    mut ctx: *mut EVP_MD_CTX,
    mut data: *const libc::c_void,
    mut count: size_t,
) -> libc::c_int {
    return RIPEMD160_Update((*ctx).md_data as *mut RIPEMD160_CTX, data, count);
}
unsafe extern "C" fn ripemd160_final(mut ctx: *mut EVP_MD_CTX, mut out: *mut uint8_t) {
    if RIPEMD160_Final(out, (*ctx).md_data as *mut RIPEMD160_CTX) != 0 {} else {
        __assert_fail(
            b"RIPEMD160_Final(out, ctx->md_data)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            150 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 46],
                &[libc::c_char; 46],
            >(b"void ripemd160_final(EVP_MD_CTX *, uint8_t *)\0"))
                .as_ptr(),
        );
    }
    'c_1925: {
        if RIPEMD160_Final(out, (*ctx).md_data as *mut RIPEMD160_CTX) != 0 {} else {
            __assert_fail(
                b"RIPEMD160_Final(out, ctx->md_data)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                150 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 46],
                    &[libc::c_char; 46],
                >(b"void ripemd160_final(EVP_MD_CTX *, uint8_t *)\0"))
                    .as_ptr(),
            );
        }
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_ripemd160() -> *const EVP_MD {
    CRYPTO_once(
        EVP_ripemd160_once_bss_get(),
        Some(EVP_ripemd160_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_ripemd160_storage_bss_get() as *const EVP_MD;
}
static mut EVP_ripemd160_storage: EVP_MD = env_md_st {
    type_0: 0,
    md_size: 0,
    flags: 0,
    init: None,
    update: None,
    final_0: None,
    block_size: 0,
    ctx_size: 0,
    finalXOF: None,
    squeezeXOF: None,
};
unsafe extern "C" fn EVP_ripemd160_storage_bss_get() -> *mut EVP_MD {
    return &mut EVP_ripemd160_storage;
}
unsafe extern "C" fn EVP_ripemd160_do_init(mut out: *mut EVP_MD) {
    (*out).type_0 = 117 as libc::c_int;
    (*out).md_size = 20 as libc::c_int as libc::c_uint;
    (*out).flags = 0 as libc::c_int as uint32_t;
    (*out).init = Some(ripemd160_init as unsafe extern "C" fn(*mut EVP_MD_CTX) -> ());
    (*out)
        .update = Some(
        ripemd160_update
            as unsafe extern "C" fn(
                *mut EVP_MD_CTX,
                *const libc::c_void,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .final_0 = Some(
        ripemd160_final as unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t) -> (),
    );
    (*out).squeezeXOF = None;
    (*out).finalXOF = None;
    (*out).block_size = 64 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<RIPEMD160_CTX>() as libc::c_ulong
        as libc::c_uint;
}
unsafe extern "C" fn EVP_ripemd160_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_ripemd160_once;
}
unsafe extern "C" fn EVP_ripemd160_init() {
    EVP_ripemd160_do_init(EVP_ripemd160_storage_bss_get());
}
static mut EVP_ripemd160_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn sha1_init(mut ctx: *mut EVP_MD_CTX) {
    if SHA1_Init((*ctx).md_data as *mut SHA_CTX) != 0 {} else {
        __assert_fail(
            b"SHA1_Init(ctx->md_data)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            168 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 29],
                &[libc::c_char; 29],
            >(b"void sha1_init(EVP_MD_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_2277: {
        if SHA1_Init((*ctx).md_data as *mut SHA_CTX) != 0 {} else {
            __assert_fail(
                b"SHA1_Init(ctx->md_data)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                168 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 29],
                    &[libc::c_char; 29],
                >(b"void sha1_init(EVP_MD_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn sha1_update(
    mut ctx: *mut EVP_MD_CTX,
    mut data: *const libc::c_void,
    mut count: size_t,
) -> libc::c_int {
    return SHA1_Update((*ctx).md_data as *mut SHA_CTX, data, count);
}
unsafe extern "C" fn sha1_final(mut ctx: *mut EVP_MD_CTX, mut md: *mut uint8_t) {
    if SHA1_Final(md, (*ctx).md_data as *mut SHA_CTX) != 0 {} else {
        __assert_fail(
            b"SHA1_Final(md, ctx->md_data)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            179 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 41],
                &[libc::c_char; 41],
            >(b"void sha1_final(EVP_MD_CTX *, uint8_t *)\0"))
                .as_ptr(),
        );
    }
    'c_2182: {
        if SHA1_Final(md, (*ctx).md_data as *mut SHA_CTX) != 0 {} else {
            __assert_fail(
                b"SHA1_Final(md, ctx->md_data)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                179 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 41],
                    &[libc::c_char; 41],
                >(b"void sha1_final(EVP_MD_CTX *, uint8_t *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn EVP_sha1_do_init(mut out: *mut EVP_MD) {
    (*out).type_0 = 64 as libc::c_int;
    (*out).md_size = 20 as libc::c_int as libc::c_uint;
    (*out).flags = 0 as libc::c_int as uint32_t;
    (*out).init = Some(sha1_init as unsafe extern "C" fn(*mut EVP_MD_CTX) -> ());
    (*out)
        .update = Some(
        sha1_update
            as unsafe extern "C" fn(
                *mut EVP_MD_CTX,
                *const libc::c_void,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .final_0 = Some(
        sha1_final as unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t) -> (),
    );
    (*out).squeezeXOF = None;
    (*out).finalXOF = None;
    (*out).block_size = 64 as libc::c_int as libc::c_uint;
    (*out).ctx_size = ::core::mem::size_of::<SHA_CTX>() as libc::c_ulong as libc::c_uint;
}
unsafe extern "C" fn EVP_sha1_init() {
    EVP_sha1_do_init(EVP_sha1_storage_bss_get());
}
unsafe extern "C" fn EVP_sha1_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_sha1_once;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_sha1() -> *const EVP_MD {
    CRYPTO_once(
        EVP_sha1_once_bss_get(),
        Some(EVP_sha1_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_sha1_storage_bss_get() as *const EVP_MD;
}
static mut EVP_sha1_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EVP_sha1_storage_bss_get() -> *mut EVP_MD {
    return &mut EVP_sha1_storage;
}
static mut EVP_sha1_storage: EVP_MD = env_md_st {
    type_0: 0,
    md_size: 0,
    flags: 0,
    init: None,
    update: None,
    final_0: None,
    block_size: 0,
    ctx_size: 0,
    finalXOF: None,
    squeezeXOF: None,
};
unsafe extern "C" fn sha224_init(mut ctx: *mut EVP_MD_CTX) {
    if SHA224_Init((*ctx).md_data as *mut SHA256_CTX) != 0 {} else {
        __assert_fail(
            b"SHA224_Init(ctx->md_data)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            197 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 31],
                &[libc::c_char; 31],
            >(b"void sha224_init(EVP_MD_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_2534: {
        if SHA224_Init((*ctx).md_data as *mut SHA256_CTX) != 0 {} else {
            __assert_fail(
                b"SHA224_Init(ctx->md_data)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                197 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 31],
                    &[libc::c_char; 31],
                >(b"void sha224_init(EVP_MD_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn sha224_update(
    mut ctx: *mut EVP_MD_CTX,
    mut data: *const libc::c_void,
    mut count: size_t,
) -> libc::c_int {
    return SHA224_Update((*ctx).md_data as *mut SHA256_CTX, data, count);
}
unsafe extern "C" fn sha224_final(mut ctx: *mut EVP_MD_CTX, mut md: *mut uint8_t) {
    if SHA224_Final(md, (*ctx).md_data as *mut SHA256_CTX) != 0 {} else {
        __assert_fail(
            b"SHA224_Final(md, ctx->md_data)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            208 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 43],
                &[libc::c_char; 43],
            >(b"void sha224_final(EVP_MD_CTX *, uint8_t *)\0"))
                .as_ptr(),
        );
    }
    'c_2437: {
        if SHA224_Final(md, (*ctx).md_data as *mut SHA256_CTX) != 0 {} else {
            __assert_fail(
                b"SHA224_Final(md, ctx->md_data)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                208 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 43],
                    &[libc::c_char; 43],
                >(b"void sha224_final(EVP_MD_CTX *, uint8_t *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn EVP_sha224_do_init(mut out: *mut EVP_MD) {
    (*out).type_0 = 675 as libc::c_int;
    (*out).md_size = 28 as libc::c_int as libc::c_uint;
    (*out).flags = 0 as libc::c_int as uint32_t;
    (*out).init = Some(sha224_init as unsafe extern "C" fn(*mut EVP_MD_CTX) -> ());
    (*out)
        .update = Some(
        sha224_update
            as unsafe extern "C" fn(
                *mut EVP_MD_CTX,
                *const libc::c_void,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .final_0 = Some(
        sha224_final as unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t) -> (),
    );
    (*out).squeezeXOF = None;
    (*out).finalXOF = None;
    (*out).block_size = 64 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<SHA256_CTX>() as libc::c_ulong
        as libc::c_uint;
}
unsafe extern "C" fn EVP_sha224_init() {
    EVP_sha224_do_init(EVP_sha224_storage_bss_get());
}
static mut EVP_sha224_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EVP_sha224_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_sha224_once;
}
static mut EVP_sha224_storage: EVP_MD = env_md_st {
    type_0: 0,
    md_size: 0,
    flags: 0,
    init: None,
    update: None,
    final_0: None,
    block_size: 0,
    ctx_size: 0,
    finalXOF: None,
    squeezeXOF: None,
};
unsafe extern "C" fn EVP_sha224_storage_bss_get() -> *mut EVP_MD {
    return &mut EVP_sha224_storage;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_sha224() -> *const EVP_MD {
    CRYPTO_once(
        EVP_sha224_once_bss_get(),
        Some(EVP_sha224_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_sha224_storage_bss_get() as *const EVP_MD;
}
unsafe extern "C" fn sha256_init(mut ctx: *mut EVP_MD_CTX) {
    if SHA256_Init((*ctx).md_data as *mut SHA256_CTX) != 0 {} else {
        __assert_fail(
            b"SHA256_Init(ctx->md_data)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            226 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 31],
                &[libc::c_char; 31],
            >(b"void sha256_init(EVP_MD_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_2784: {
        if SHA256_Init((*ctx).md_data as *mut SHA256_CTX) != 0 {} else {
            __assert_fail(
                b"SHA256_Init(ctx->md_data)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                226 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 31],
                    &[libc::c_char; 31],
                >(b"void sha256_init(EVP_MD_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn sha256_update(
    mut ctx: *mut EVP_MD_CTX,
    mut data: *const libc::c_void,
    mut count: size_t,
) -> libc::c_int {
    return SHA256_Update((*ctx).md_data as *mut SHA256_CTX, data, count);
}
unsafe extern "C" fn sha256_final(mut ctx: *mut EVP_MD_CTX, mut md: *mut uint8_t) {
    if SHA256_Final(md, (*ctx).md_data as *mut SHA256_CTX) != 0 {} else {
        __assert_fail(
            b"SHA256_Final(md, ctx->md_data)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            237 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 43],
                &[libc::c_char; 43],
            >(b"void sha256_final(EVP_MD_CTX *, uint8_t *)\0"))
                .as_ptr(),
        );
    }
    'c_2692: {
        if SHA256_Final(md, (*ctx).md_data as *mut SHA256_CTX) != 0 {} else {
            __assert_fail(
                b"SHA256_Final(md, ctx->md_data)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                237 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 43],
                    &[libc::c_char; 43],
                >(b"void sha256_final(EVP_MD_CTX *, uint8_t *)\0"))
                    .as_ptr(),
            );
        }
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_sha256() -> *const EVP_MD {
    CRYPTO_once(
        EVP_sha256_once_bss_get(),
        Some(EVP_sha256_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_sha256_storage_bss_get() as *const EVP_MD;
}
static mut EVP_sha256_storage: EVP_MD = env_md_st {
    type_0: 0,
    md_size: 0,
    flags: 0,
    init: None,
    update: None,
    final_0: None,
    block_size: 0,
    ctx_size: 0,
    finalXOF: None,
    squeezeXOF: None,
};
unsafe extern "C" fn EVP_sha256_init() {
    EVP_sha256_do_init(EVP_sha256_storage_bss_get());
}
unsafe extern "C" fn EVP_sha256_storage_bss_get() -> *mut EVP_MD {
    return &mut EVP_sha256_storage;
}
unsafe extern "C" fn EVP_sha256_do_init(mut out: *mut EVP_MD) {
    (*out).type_0 = 672 as libc::c_int;
    (*out).md_size = 32 as libc::c_int as libc::c_uint;
    (*out).flags = 0 as libc::c_int as uint32_t;
    (*out).init = Some(sha256_init as unsafe extern "C" fn(*mut EVP_MD_CTX) -> ());
    (*out)
        .update = Some(
        sha256_update
            as unsafe extern "C" fn(
                *mut EVP_MD_CTX,
                *const libc::c_void,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .final_0 = Some(
        sha256_final as unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t) -> (),
    );
    (*out).squeezeXOF = None;
    (*out).finalXOF = None;
    (*out).block_size = 64 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<SHA256_CTX>() as libc::c_ulong
        as libc::c_uint;
}
unsafe extern "C" fn EVP_sha256_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_sha256_once;
}
static mut EVP_sha256_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn sha384_init(mut ctx: *mut EVP_MD_CTX) {
    if SHA384_Init((*ctx).md_data as *mut SHA512_CTX) != 0 {} else {
        __assert_fail(
            b"SHA384_Init(ctx->md_data)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            255 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 31],
                &[libc::c_char; 31],
            >(b"void sha384_init(EVP_MD_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_3036: {
        if SHA384_Init((*ctx).md_data as *mut SHA512_CTX) != 0 {} else {
            __assert_fail(
                b"SHA384_Init(ctx->md_data)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                255 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 31],
                    &[libc::c_char; 31],
                >(b"void sha384_init(EVP_MD_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn sha384_update(
    mut ctx: *mut EVP_MD_CTX,
    mut data: *const libc::c_void,
    mut count: size_t,
) -> libc::c_int {
    return SHA384_Update((*ctx).md_data as *mut SHA512_CTX, data, count);
}
unsafe extern "C" fn sha384_final(mut ctx: *mut EVP_MD_CTX, mut md: *mut uint8_t) {
    if SHA384_Final(md, (*ctx).md_data as *mut SHA512_CTX) != 0 {} else {
        __assert_fail(
            b"SHA384_Final(md, ctx->md_data)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            266 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 43],
                &[libc::c_char; 43],
            >(b"void sha384_final(EVP_MD_CTX *, uint8_t *)\0"))
                .as_ptr(),
        );
    }
    'c_2941: {
        if SHA384_Final(md, (*ctx).md_data as *mut SHA512_CTX) != 0 {} else {
            __assert_fail(
                b"SHA384_Final(md, ctx->md_data)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                266 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 43],
                    &[libc::c_char; 43],
                >(b"void sha384_final(EVP_MD_CTX *, uint8_t *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn EVP_sha384_do_init(mut out: *mut EVP_MD) {
    (*out).type_0 = 673 as libc::c_int;
    (*out).md_size = 48 as libc::c_int as libc::c_uint;
    (*out).flags = 0 as libc::c_int as uint32_t;
    (*out).init = Some(sha384_init as unsafe extern "C" fn(*mut EVP_MD_CTX) -> ());
    (*out)
        .update = Some(
        sha384_update
            as unsafe extern "C" fn(
                *mut EVP_MD_CTX,
                *const libc::c_void,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .final_0 = Some(
        sha384_final as unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t) -> (),
    );
    (*out).squeezeXOF = None;
    (*out).finalXOF = None;
    (*out).block_size = 128 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<SHA512_CTX>() as libc::c_ulong
        as libc::c_uint;
}
unsafe extern "C" fn EVP_sha384_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_sha384_once;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_sha384() -> *const EVP_MD {
    CRYPTO_once(
        EVP_sha384_once_bss_get(),
        Some(EVP_sha384_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_sha384_storage_bss_get() as *const EVP_MD;
}
unsafe extern "C" fn EVP_sha384_storage_bss_get() -> *mut EVP_MD {
    return &mut EVP_sha384_storage;
}
static mut EVP_sha384_once: CRYPTO_once_t = 0 as libc::c_int;
static mut EVP_sha384_storage: EVP_MD = env_md_st {
    type_0: 0,
    md_size: 0,
    flags: 0,
    init: None,
    update: None,
    final_0: None,
    block_size: 0,
    ctx_size: 0,
    finalXOF: None,
    squeezeXOF: None,
};
unsafe extern "C" fn EVP_sha384_init() {
    EVP_sha384_do_init(EVP_sha384_storage_bss_get());
}
unsafe extern "C" fn sha512_init(mut ctx: *mut EVP_MD_CTX) {
    if SHA512_Init((*ctx).md_data as *mut SHA512_CTX) != 0 {} else {
        __assert_fail(
            b"SHA512_Init(ctx->md_data)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            284 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 31],
                &[libc::c_char; 31],
            >(b"void sha512_init(EVP_MD_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_3285: {
        if SHA512_Init((*ctx).md_data as *mut SHA512_CTX) != 0 {} else {
            __assert_fail(
                b"SHA512_Init(ctx->md_data)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                284 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 31],
                    &[libc::c_char; 31],
                >(b"void sha512_init(EVP_MD_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn sha512_update(
    mut ctx: *mut EVP_MD_CTX,
    mut data: *const libc::c_void,
    mut count: size_t,
) -> libc::c_int {
    return SHA512_Update((*ctx).md_data as *mut SHA512_CTX, data, count);
}
unsafe extern "C" fn sha512_final(mut ctx: *mut EVP_MD_CTX, mut md: *mut uint8_t) {
    if SHA512_Final(md, (*ctx).md_data as *mut SHA512_CTX) != 0 {} else {
        __assert_fail(
            b"SHA512_Final(md, ctx->md_data)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            294 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 43],
                &[libc::c_char; 43],
            >(b"void sha512_final(EVP_MD_CTX *, uint8_t *)\0"))
                .as_ptr(),
        );
    }
    'c_3193: {
        if SHA512_Final(md, (*ctx).md_data as *mut SHA512_CTX) != 0 {} else {
            __assert_fail(
                b"SHA512_Final(md, ctx->md_data)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                294 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 43],
                    &[libc::c_char; 43],
                >(b"void sha512_final(EVP_MD_CTX *, uint8_t *)\0"))
                    .as_ptr(),
            );
        }
    };
}
static mut EVP_sha512_storage: EVP_MD = env_md_st {
    type_0: 0,
    md_size: 0,
    flags: 0,
    init: None,
    update: None,
    final_0: None,
    block_size: 0,
    ctx_size: 0,
    finalXOF: None,
    squeezeXOF: None,
};
unsafe extern "C" fn EVP_sha512_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_sha512_once;
}
static mut EVP_sha512_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EVP_sha512_init() {
    EVP_sha512_do_init(EVP_sha512_storage_bss_get());
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_sha512() -> *const EVP_MD {
    CRYPTO_once(
        EVP_sha512_once_bss_get(),
        Some(EVP_sha512_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_sha512_storage_bss_get() as *const EVP_MD;
}
unsafe extern "C" fn EVP_sha512_do_init(mut out: *mut EVP_MD) {
    (*out).type_0 = 674 as libc::c_int;
    (*out).md_size = 64 as libc::c_int as libc::c_uint;
    (*out).flags = 0 as libc::c_int as uint32_t;
    (*out).init = Some(sha512_init as unsafe extern "C" fn(*mut EVP_MD_CTX) -> ());
    (*out)
        .update = Some(
        sha512_update
            as unsafe extern "C" fn(
                *mut EVP_MD_CTX,
                *const libc::c_void,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .final_0 = Some(
        sha512_final as unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t) -> (),
    );
    (*out).squeezeXOF = None;
    (*out).finalXOF = None;
    (*out).block_size = 128 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<SHA512_CTX>() as libc::c_ulong
        as libc::c_uint;
}
unsafe extern "C" fn EVP_sha512_storage_bss_get() -> *mut EVP_MD {
    return &mut EVP_sha512_storage;
}
unsafe extern "C" fn sha512_224_init(mut ctx: *mut EVP_MD_CTX) {
    if SHA512_224_Init((*ctx).md_data as *mut SHA512_CTX) != 0 {} else {
        __assert_fail(
            b"SHA512_224_Init(ctx->md_data)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            312 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 35],
                &[libc::c_char; 35],
            >(b"void sha512_224_init(EVP_MD_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_3514: {
        if SHA512_224_Init((*ctx).md_data as *mut SHA512_CTX) != 0 {} else {
            __assert_fail(
                b"SHA512_224_Init(ctx->md_data)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                312 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 35],
                    &[libc::c_char; 35],
                >(b"void sha512_224_init(EVP_MD_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn sha512_224_update(
    mut ctx: *mut EVP_MD_CTX,
    mut data: *const libc::c_void,
    mut count: size_t,
) -> libc::c_int {
    return SHA512_224_Update((*ctx).md_data as *mut SHA512_CTX, data, count);
}
unsafe extern "C" fn sha512_224_final(mut ctx: *mut EVP_MD_CTX, mut md: *mut uint8_t) {
    if SHA512_224_Final(md, (*ctx).md_data as *mut SHA512_CTX) != 0 {} else {
        __assert_fail(
            b"SHA512_224_Final(md, ctx->md_data)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            323 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 47],
                &[libc::c_char; 47],
            >(b"void sha512_224_final(EVP_MD_CTX *, uint8_t *)\0"))
                .as_ptr(),
        );
    }
    'c_3422: {
        if SHA512_224_Final(md, (*ctx).md_data as *mut SHA512_CTX) != 0 {} else {
            __assert_fail(
                b"SHA512_224_Final(md, ctx->md_data)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                323 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 47],
                    &[libc::c_char; 47],
                >(b"void sha512_224_final(EVP_MD_CTX *, uint8_t *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn EVP_sha512_224_storage_bss_get() -> *mut EVP_MD {
    return &mut EVP_sha512_224_storage;
}
static mut EVP_sha512_224_storage: EVP_MD = env_md_st {
    type_0: 0,
    md_size: 0,
    flags: 0,
    init: None,
    update: None,
    final_0: None,
    block_size: 0,
    ctx_size: 0,
    finalXOF: None,
    squeezeXOF: None,
};
unsafe extern "C" fn EVP_sha512_224_init() {
    EVP_sha512_224_do_init(EVP_sha512_224_storage_bss_get());
}
unsafe extern "C" fn EVP_sha512_224_do_init(mut out: *mut EVP_MD) {
    (*out).type_0 = 978 as libc::c_int;
    (*out).md_size = 28 as libc::c_int as libc::c_uint;
    (*out).flags = 0 as libc::c_int as uint32_t;
    (*out).init = Some(sha512_224_init as unsafe extern "C" fn(*mut EVP_MD_CTX) -> ());
    (*out)
        .update = Some(
        sha512_224_update
            as unsafe extern "C" fn(
                *mut EVP_MD_CTX,
                *const libc::c_void,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .final_0 = Some(
        sha512_224_final as unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t) -> (),
    );
    (*out).block_size = 128 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<SHA512_CTX>() as libc::c_ulong
        as libc::c_uint;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_sha512_224() -> *const EVP_MD {
    CRYPTO_once(
        EVP_sha512_224_once_bss_get(),
        Some(EVP_sha512_224_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_sha512_224_storage_bss_get() as *const EVP_MD;
}
unsafe extern "C" fn EVP_sha512_224_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_sha512_224_once;
}
static mut EVP_sha512_224_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn sha512_256_init(mut ctx: *mut EVP_MD_CTX) {
    if SHA512_256_Init((*ctx).md_data as *mut SHA512_CTX) != 0 {} else {
        __assert_fail(
            b"SHA512_256_Init(ctx->md_data)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            339 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 35],
                &[libc::c_char; 35],
            >(b"void sha512_256_init(EVP_MD_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_3761: {
        if SHA512_256_Init((*ctx).md_data as *mut SHA512_CTX) != 0 {} else {
            __assert_fail(
                b"SHA512_256_Init(ctx->md_data)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                339 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 35],
                    &[libc::c_char; 35],
                >(b"void sha512_256_init(EVP_MD_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn sha512_256_update(
    mut ctx: *mut EVP_MD_CTX,
    mut data: *const libc::c_void,
    mut count: size_t,
) -> libc::c_int {
    return SHA512_256_Update((*ctx).md_data as *mut SHA512_CTX, data, count);
}
unsafe extern "C" fn sha512_256_final(mut ctx: *mut EVP_MD_CTX, mut md: *mut uint8_t) {
    if SHA512_256_Final(md, (*ctx).md_data as *mut SHA512_CTX) != 0 {} else {
        __assert_fail(
            b"SHA512_256_Final(md, ctx->md_data)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            350 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 47],
                &[libc::c_char; 47],
            >(b"void sha512_256_final(EVP_MD_CTX *, uint8_t *)\0"))
                .as_ptr(),
        );
    }
    'c_3670: {
        if SHA512_256_Final(md, (*ctx).md_data as *mut SHA512_CTX) != 0 {} else {
            __assert_fail(
                b"SHA512_256_Final(md, ctx->md_data)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                350 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 47],
                    &[libc::c_char; 47],
                >(b"void sha512_256_final(EVP_MD_CTX *, uint8_t *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn EVP_sha512_256_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_sha512_256_once;
}
static mut EVP_sha512_256_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EVP_sha512_256_do_init(mut out: *mut EVP_MD) {
    (*out).type_0 = 962 as libc::c_int;
    (*out).md_size = 32 as libc::c_int as libc::c_uint;
    (*out).flags = 0 as libc::c_int as uint32_t;
    (*out).init = Some(sha512_256_init as unsafe extern "C" fn(*mut EVP_MD_CTX) -> ());
    (*out)
        .update = Some(
        sha512_256_update
            as unsafe extern "C" fn(
                *mut EVP_MD_CTX,
                *const libc::c_void,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .final_0 = Some(
        sha512_256_final as unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t) -> (),
    );
    (*out).squeezeXOF = None;
    (*out).finalXOF = None;
    (*out).block_size = 128 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<SHA512_CTX>() as libc::c_ulong
        as libc::c_uint;
}
static mut EVP_sha512_256_storage: EVP_MD = env_md_st {
    type_0: 0,
    md_size: 0,
    flags: 0,
    init: None,
    update: None,
    final_0: None,
    block_size: 0,
    ctx_size: 0,
    finalXOF: None,
    squeezeXOF: None,
};
unsafe extern "C" fn EVP_sha512_256_storage_bss_get() -> *mut EVP_MD {
    return &mut EVP_sha512_256_storage;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_sha512_256() -> *const EVP_MD {
    CRYPTO_once(
        EVP_sha512_256_once_bss_get(),
        Some(EVP_sha512_256_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_sha512_256_storage_bss_get() as *const EVP_MD;
}
unsafe extern "C" fn EVP_sha512_256_init() {
    EVP_sha512_256_do_init(EVP_sha512_256_storage_bss_get());
}
unsafe extern "C" fn sha3_224_init(mut ctx: *mut EVP_MD_CTX) {
    if SHA3_Init((*ctx).md_data as *mut KECCAK1600_CTX, 224 as libc::c_int as size_t)
        != 0
    {} else {
        __assert_fail(
            b"SHA3_Init(ctx->md_data, 224)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            368 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 33],
                &[libc::c_char; 33],
            >(b"void sha3_224_init(EVP_MD_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_4036: {
        if SHA3_Init((*ctx).md_data as *mut KECCAK1600_CTX, 224 as libc::c_int as size_t)
            != 0
        {} else {
            __assert_fail(
                b"SHA3_Init(ctx->md_data, 224)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                368 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 33],
                    &[libc::c_char; 33],
                >(b"void sha3_224_init(EVP_MD_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn sha3_224_update(
    mut ctx: *mut EVP_MD_CTX,
    mut data: *const libc::c_void,
    mut count: size_t,
) -> libc::c_int {
    return SHA3_Update((*ctx).md_data as *mut KECCAK1600_CTX, data, count);
}
unsafe extern "C" fn sha3_224_final(mut ctx: *mut EVP_MD_CTX, mut md: *mut uint8_t) {
    if SHA3_Final(md, (*ctx).md_data as *mut KECCAK1600_CTX) != 0 {} else {
        __assert_fail(
            b"SHA3_Final(md, ctx->md_data)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            377 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 45],
                &[libc::c_char; 45],
            >(b"void sha3_224_final(EVP_MD_CTX *, uint8_t *)\0"))
                .as_ptr(),
        );
    }
    'c_3941: {
        if SHA3_Final(md, (*ctx).md_data as *mut KECCAK1600_CTX) != 0 {} else {
            __assert_fail(
                b"SHA3_Final(md, ctx->md_data)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                377 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 45],
                    &[libc::c_char; 45],
                >(b"void sha3_224_final(EVP_MD_CTX *, uint8_t *)\0"))
                    .as_ptr(),
            );
        }
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_sha3_224() -> *const EVP_MD {
    CRYPTO_once(
        EVP_sha3_224_once_bss_get(),
        Some(EVP_sha3_224_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_sha3_224_storage_bss_get() as *const EVP_MD;
}
static mut EVP_sha3_224_storage: EVP_MD = env_md_st {
    type_0: 0,
    md_size: 0,
    flags: 0,
    init: None,
    update: None,
    final_0: None,
    block_size: 0,
    ctx_size: 0,
    finalXOF: None,
    squeezeXOF: None,
};
static mut EVP_sha3_224_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EVP_sha3_224_storage_bss_get() -> *mut EVP_MD {
    return &mut EVP_sha3_224_storage;
}
unsafe extern "C" fn EVP_sha3_224_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_sha3_224_once;
}
unsafe extern "C" fn EVP_sha3_224_init() {
    EVP_sha3_224_do_init(EVP_sha3_224_storage_bss_get());
}
unsafe extern "C" fn EVP_sha3_224_do_init(mut out: *mut EVP_MD) {
    (*out).type_0 = 965 as libc::c_int;
    (*out).md_size = 28 as libc::c_int as libc::c_uint;
    (*out).flags = 0 as libc::c_int as uint32_t;
    (*out).init = Some(sha3_224_init as unsafe extern "C" fn(*mut EVP_MD_CTX) -> ());
    (*out)
        .update = Some(
        sha3_224_update
            as unsafe extern "C" fn(
                *mut EVP_MD_CTX,
                *const libc::c_void,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .final_0 = Some(
        sha3_224_final as unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t) -> (),
    );
    (*out).squeezeXOF = None;
    (*out).finalXOF = None;
    (*out)
        .block_size = ((1600 as libc::c_int - 224 as libc::c_int * 2 as libc::c_int)
        / 8 as libc::c_int) as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<KECCAK1600_CTX>() as libc::c_ulong
        as libc::c_uint;
}
unsafe extern "C" fn sha3_256_init(mut ctx: *mut EVP_MD_CTX) {
    if SHA3_Init((*ctx).md_data as *mut KECCAK1600_CTX, 256 as libc::c_int as size_t)
        != 0
    {} else {
        __assert_fail(
            b"SHA3_Init(ctx->md_data, 256)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            395 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 33],
                &[libc::c_char; 33],
            >(b"void sha3_256_init(EVP_MD_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_4288: {
        if SHA3_Init((*ctx).md_data as *mut KECCAK1600_CTX, 256 as libc::c_int as size_t)
            != 0
        {} else {
            __assert_fail(
                b"SHA3_Init(ctx->md_data, 256)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                395 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 33],
                    &[libc::c_char; 33],
                >(b"void sha3_256_init(EVP_MD_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn sha3_256_update(
    mut ctx: *mut EVP_MD_CTX,
    mut data: *const libc::c_void,
    mut count: size_t,
) -> libc::c_int {
    return SHA3_Update((*ctx).md_data as *mut KECCAK1600_CTX, data, count);
}
unsafe extern "C" fn sha3_256_final(mut ctx: *mut EVP_MD_CTX, mut md: *mut uint8_t) {
    if SHA3_Final(md, (*ctx).md_data as *mut KECCAK1600_CTX) != 0 {} else {
        __assert_fail(
            b"SHA3_Final(md, ctx->md_data)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            404 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 45],
                &[libc::c_char; 45],
            >(b"void sha3_256_final(EVP_MD_CTX *, uint8_t *)\0"))
                .as_ptr(),
        );
    }
    'c_4206: {
        if SHA3_Final(md, (*ctx).md_data as *mut KECCAK1600_CTX) != 0 {} else {
            __assert_fail(
                b"SHA3_Final(md, ctx->md_data)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                404 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 45],
                    &[libc::c_char; 45],
                >(b"void sha3_256_final(EVP_MD_CTX *, uint8_t *)\0"))
                    .as_ptr(),
            );
        }
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_sha3_256() -> *const EVP_MD {
    CRYPTO_once(
        EVP_sha3_256_once_bss_get(),
        Some(EVP_sha3_256_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_sha3_256_storage_bss_get() as *const EVP_MD;
}
unsafe extern "C" fn EVP_sha3_256_storage_bss_get() -> *mut EVP_MD {
    return &mut EVP_sha3_256_storage;
}
unsafe extern "C" fn EVP_sha3_256_init() {
    EVP_sha3_256_do_init(EVP_sha3_256_storage_bss_get());
}
unsafe extern "C" fn EVP_sha3_256_do_init(mut out: *mut EVP_MD) {
    (*out).type_0 = 966 as libc::c_int;
    (*out).md_size = 32 as libc::c_int as libc::c_uint;
    (*out).flags = 0 as libc::c_int as uint32_t;
    (*out).init = Some(sha3_256_init as unsafe extern "C" fn(*mut EVP_MD_CTX) -> ());
    (*out)
        .update = Some(
        sha3_256_update
            as unsafe extern "C" fn(
                *mut EVP_MD_CTX,
                *const libc::c_void,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .final_0 = Some(
        sha3_256_final as unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t) -> (),
    );
    (*out).squeezeXOF = None;
    (*out).finalXOF = None;
    (*out)
        .block_size = ((1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
        / 8 as libc::c_int) as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<KECCAK1600_CTX>() as libc::c_ulong
        as libc::c_uint;
}
unsafe extern "C" fn EVP_sha3_256_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_sha3_256_once;
}
static mut EVP_sha3_256_once: CRYPTO_once_t = 0 as libc::c_int;
static mut EVP_sha3_256_storage: EVP_MD = env_md_st {
    type_0: 0,
    md_size: 0,
    flags: 0,
    init: None,
    update: None,
    final_0: None,
    block_size: 0,
    ctx_size: 0,
    finalXOF: None,
    squeezeXOF: None,
};
unsafe extern "C" fn sha3_384_init(mut ctx: *mut EVP_MD_CTX) {
    if SHA3_Init((*ctx).md_data as *mut KECCAK1600_CTX, 384 as libc::c_int as size_t)
        != 0
    {} else {
        __assert_fail(
            b"SHA3_Init(ctx->md_data, 384)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            422 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 33],
                &[libc::c_char; 33],
            >(b"void sha3_384_init(EVP_MD_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_4534: {
        if SHA3_Init((*ctx).md_data as *mut KECCAK1600_CTX, 384 as libc::c_int as size_t)
            != 0
        {} else {
            __assert_fail(
                b"SHA3_Init(ctx->md_data, 384)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                422 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 33],
                    &[libc::c_char; 33],
                >(b"void sha3_384_init(EVP_MD_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn sha3_384_update(
    mut ctx: *mut EVP_MD_CTX,
    mut data: *const libc::c_void,
    mut count: size_t,
) -> libc::c_int {
    return SHA3_Update((*ctx).md_data as *mut KECCAK1600_CTX, data, count);
}
unsafe extern "C" fn sha3_384_final(mut ctx: *mut EVP_MD_CTX, mut md: *mut uint8_t) {
    if SHA3_Final(md, (*ctx).md_data as *mut KECCAK1600_CTX) != 0 {} else {
        __assert_fail(
            b"SHA3_Final(md, ctx->md_data)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            431 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 45],
                &[libc::c_char; 45],
            >(b"void sha3_384_final(EVP_MD_CTX *, uint8_t *)\0"))
                .as_ptr(),
        );
    }
    'c_4452: {
        if SHA3_Final(md, (*ctx).md_data as *mut KECCAK1600_CTX) != 0 {} else {
            __assert_fail(
                b"SHA3_Final(md, ctx->md_data)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                431 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 45],
                    &[libc::c_char; 45],
                >(b"void sha3_384_final(EVP_MD_CTX *, uint8_t *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn EVP_sha3_384_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_sha3_384_once;
}
static mut EVP_sha3_384_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EVP_sha3_384_storage_bss_get() -> *mut EVP_MD {
    return &mut EVP_sha3_384_storage;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_sha3_384() -> *const EVP_MD {
    CRYPTO_once(
        EVP_sha3_384_once_bss_get(),
        Some(EVP_sha3_384_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_sha3_384_storage_bss_get() as *const EVP_MD;
}
static mut EVP_sha3_384_storage: EVP_MD = env_md_st {
    type_0: 0,
    md_size: 0,
    flags: 0,
    init: None,
    update: None,
    final_0: None,
    block_size: 0,
    ctx_size: 0,
    finalXOF: None,
    squeezeXOF: None,
};
unsafe extern "C" fn EVP_sha3_384_init() {
    EVP_sha3_384_do_init(EVP_sha3_384_storage_bss_get());
}
unsafe extern "C" fn EVP_sha3_384_do_init(mut out: *mut EVP_MD) {
    (*out).type_0 = 967 as libc::c_int;
    (*out).md_size = 48 as libc::c_int as libc::c_uint;
    (*out).flags = 0 as libc::c_int as uint32_t;
    (*out).init = Some(sha3_384_init as unsafe extern "C" fn(*mut EVP_MD_CTX) -> ());
    (*out)
        .update = Some(
        sha3_384_update
            as unsafe extern "C" fn(
                *mut EVP_MD_CTX,
                *const libc::c_void,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .final_0 = Some(
        sha3_384_final as unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t) -> (),
    );
    (*out).squeezeXOF = None;
    (*out).finalXOF = None;
    (*out)
        .block_size = ((1600 as libc::c_int - 384 as libc::c_int * 2 as libc::c_int)
        / 8 as libc::c_int) as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<KECCAK1600_CTX>() as libc::c_ulong
        as libc::c_uint;
}
unsafe extern "C" fn sha3_512_init(mut ctx: *mut EVP_MD_CTX) {
    if SHA3_Init((*ctx).md_data as *mut KECCAK1600_CTX, 512 as libc::c_int as size_t)
        != 0
    {} else {
        __assert_fail(
            b"SHA3_Init(ctx->md_data, 512)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            449 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 33],
                &[libc::c_char; 33],
            >(b"void sha3_512_init(EVP_MD_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_4780: {
        if SHA3_Init((*ctx).md_data as *mut KECCAK1600_CTX, 512 as libc::c_int as size_t)
            != 0
        {} else {
            __assert_fail(
                b"SHA3_Init(ctx->md_data, 512)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                449 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 33],
                    &[libc::c_char; 33],
                >(b"void sha3_512_init(EVP_MD_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn sha3_512_update(
    mut ctx: *mut EVP_MD_CTX,
    mut data: *const libc::c_void,
    mut count: size_t,
) -> libc::c_int {
    return SHA3_Update((*ctx).md_data as *mut KECCAK1600_CTX, data, count);
}
unsafe extern "C" fn sha3_512_final(mut ctx: *mut EVP_MD_CTX, mut md: *mut uint8_t) {
    if SHA3_Final(md, (*ctx).md_data as *mut KECCAK1600_CTX) != 0 {} else {
        __assert_fail(
            b"SHA3_Final(md, ctx->md_data)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            458 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 45],
                &[libc::c_char; 45],
            >(b"void sha3_512_final(EVP_MD_CTX *, uint8_t *)\0"))
                .as_ptr(),
        );
    }
    'c_4698: {
        if SHA3_Final(md, (*ctx).md_data as *mut KECCAK1600_CTX) != 0 {} else {
            __assert_fail(
                b"SHA3_Final(md, ctx->md_data)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                458 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 45],
                    &[libc::c_char; 45],
                >(b"void sha3_512_final(EVP_MD_CTX *, uint8_t *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn EVP_sha3_512_do_init(mut out: *mut EVP_MD) {
    (*out).type_0 = 968 as libc::c_int;
    (*out).md_size = 64 as libc::c_int as libc::c_uint;
    (*out).flags = 0 as libc::c_int as uint32_t;
    (*out).init = Some(sha3_512_init as unsafe extern "C" fn(*mut EVP_MD_CTX) -> ());
    (*out)
        .update = Some(
        sha3_512_update
            as unsafe extern "C" fn(
                *mut EVP_MD_CTX,
                *const libc::c_void,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .final_0 = Some(
        sha3_512_final as unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t) -> (),
    );
    (*out).squeezeXOF = None;
    (*out).finalXOF = None;
    (*out)
        .block_size = ((1600 as libc::c_int - 512 as libc::c_int * 2 as libc::c_int)
        / 8 as libc::c_int) as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<KECCAK1600_CTX>() as libc::c_ulong
        as libc::c_uint;
}
unsafe extern "C" fn EVP_sha3_512_storage_bss_get() -> *mut EVP_MD {
    return &mut EVP_sha3_512_storage;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_sha3_512() -> *const EVP_MD {
    CRYPTO_once(
        EVP_sha3_512_once_bss_get(),
        Some(EVP_sha3_512_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_sha3_512_storage_bss_get() as *const EVP_MD;
}
static mut EVP_sha3_512_storage: EVP_MD = env_md_st {
    type_0: 0,
    md_size: 0,
    flags: 0,
    init: None,
    update: None,
    final_0: None,
    block_size: 0,
    ctx_size: 0,
    finalXOF: None,
    squeezeXOF: None,
};
unsafe extern "C" fn EVP_sha3_512_init() {
    EVP_sha3_512_do_init(EVP_sha3_512_storage_bss_get());
}
static mut EVP_sha3_512_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EVP_sha3_512_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_sha3_512_once;
}
unsafe extern "C" fn shake128_init(mut ctx: *mut EVP_MD_CTX) {
    if SHAKE_Init(
        (*ctx).md_data as *mut KECCAK1600_CTX,
        ((1600 as libc::c_int - 128 as libc::c_int * 2 as libc::c_int)
            / 8 as libc::c_int) as size_t,
    ) != 0
    {} else {
        __assert_fail(
            b"SHAKE_Init(ctx->md_data, ((1600 - 128 * 2) / 8))\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            476 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 33],
                &[libc::c_char; 33],
            >(b"void shake128_init(EVP_MD_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_5067: {
        if SHAKE_Init(
            (*ctx).md_data as *mut KECCAK1600_CTX,
            ((1600 as libc::c_int - 128 as libc::c_int * 2 as libc::c_int)
                / 8 as libc::c_int) as size_t,
        ) != 0
        {} else {
            __assert_fail(
                b"SHAKE_Init(ctx->md_data, ((1600 - 128 * 2) / 8))\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                476 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 33],
                    &[libc::c_char; 33],
                >(b"void shake128_init(EVP_MD_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn shake128_update(
    mut ctx: *mut EVP_MD_CTX,
    mut data: *const libc::c_void,
    mut count: size_t,
) -> libc::c_int {
    return SHAKE_Absorb((*ctx).md_data as *mut KECCAK1600_CTX, data, count);
}
unsafe extern "C" fn shake128_final(
    mut ctx: *mut EVP_MD_CTX,
    mut md: *mut uint8_t,
    mut len: size_t,
) -> libc::c_int {
    return SHAKE_Final(md, (*ctx).md_data as *mut KECCAK1600_CTX, len);
}
unsafe extern "C" fn shake128_squeeze(
    mut ctx: *mut EVP_MD_CTX,
    mut md: *mut uint8_t,
    mut len: size_t,
) {
    if SHAKE_Squeeze(md, (*ctx).md_data as *mut KECCAK1600_CTX, len) != 0 {} else {
        __assert_fail(
            b"SHAKE_Squeeze(md, ctx->md_data, len)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            493 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 55],
                &[libc::c_char; 55],
            >(b"void shake128_squeeze(EVP_MD_CTX *, uint8_t *, size_t)\0"))
                .as_ptr(),
        );
    }
    'c_4963: {
        if SHAKE_Squeeze(md, (*ctx).md_data as *mut KECCAK1600_CTX, len) != 0 {} else {
            __assert_fail(
                b"SHAKE_Squeeze(md, ctx->md_data, len)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                493 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 55],
                    &[libc::c_char; 55],
                >(b"void shake128_squeeze(EVP_MD_CTX *, uint8_t *, size_t)\0"))
                    .as_ptr(),
            );
        }
    };
}
static mut EVP_shake128_storage: EVP_MD = env_md_st {
    type_0: 0,
    md_size: 0,
    flags: 0,
    init: None,
    update: None,
    final_0: None,
    block_size: 0,
    ctx_size: 0,
    finalXOF: None,
    squeezeXOF: None,
};
unsafe extern "C" fn EVP_shake128_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_shake128_once;
}
static mut EVP_shake128_once: CRYPTO_once_t = 0 as libc::c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_shake128() -> *const EVP_MD {
    CRYPTO_once(
        EVP_shake128_once_bss_get(),
        Some(EVP_shake128_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_shake128_storage_bss_get() as *const EVP_MD;
}
unsafe extern "C" fn EVP_shake128_storage_bss_get() -> *mut EVP_MD {
    return &mut EVP_shake128_storage;
}
unsafe extern "C" fn EVP_shake128_do_init(mut out: *mut EVP_MD) {
    (*out).type_0 = 979 as libc::c_int;
    (*out).md_size = 0 as libc::c_int as libc::c_uint;
    (*out).flags = 4 as libc::c_int as uint32_t;
    (*out).init = Some(shake128_init as unsafe extern "C" fn(*mut EVP_MD_CTX) -> ());
    (*out)
        .update = Some(
        shake128_update
            as unsafe extern "C" fn(
                *mut EVP_MD_CTX,
                *const libc::c_void,
                size_t,
            ) -> libc::c_int,
    );
    (*out).final_0 = None;
    (*out)
        .squeezeXOF = Some(
        shake128_squeeze
            as unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t, size_t) -> (),
    );
    (*out)
        .finalXOF = Some(
        shake128_final
            as unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t, size_t) -> libc::c_int,
    );
    (*out)
        .block_size = ((1600 as libc::c_int - 128 as libc::c_int * 2 as libc::c_int)
        / 8 as libc::c_int) as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<KECCAK1600_CTX>() as libc::c_ulong
        as libc::c_uint;
}
unsafe extern "C" fn EVP_shake128_init() {
    EVP_shake128_do_init(EVP_shake128_storage_bss_get());
}
unsafe extern "C" fn shake256_init(mut ctx: *mut EVP_MD_CTX) {
    if SHAKE_Init(
        (*ctx).md_data as *mut KECCAK1600_CTX,
        ((1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
            / 8 as libc::c_int) as size_t,
    ) != 0
    {} else {
        __assert_fail(
            b"SHAKE_Init(ctx->md_data, ((1600 - 256 * 2) / 8))\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            510 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 33],
                &[libc::c_char; 33],
            >(b"void shake256_init(EVP_MD_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_5356: {
        if SHAKE_Init(
            (*ctx).md_data as *mut KECCAK1600_CTX,
            ((1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
                / 8 as libc::c_int) as size_t,
        ) != 0
        {} else {
            __assert_fail(
                b"SHAKE_Init(ctx->md_data, ((1600 - 256 * 2) / 8))\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                510 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 33],
                    &[libc::c_char; 33],
                >(b"void shake256_init(EVP_MD_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn shake256_update(
    mut ctx: *mut EVP_MD_CTX,
    mut data: *const libc::c_void,
    mut count: size_t,
) -> libc::c_int {
    return SHAKE_Absorb((*ctx).md_data as *mut KECCAK1600_CTX, data, count);
}
unsafe extern "C" fn shake256_final(
    mut ctx: *mut EVP_MD_CTX,
    mut md: *mut uint8_t,
    mut len: size_t,
) -> libc::c_int {
    return SHAKE_Final(md, (*ctx).md_data as *mut KECCAK1600_CTX, len);
}
unsafe extern "C" fn shake256_squeeze(
    mut ctx: *mut EVP_MD_CTX,
    mut md: *mut uint8_t,
    mut len: size_t,
) {
    if SHAKE_Squeeze(md, (*ctx).md_data as *mut KECCAK1600_CTX, len) != 0 {} else {
        __assert_fail(
            b"SHAKE_Squeeze(md, ctx->md_data, len)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            527 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 55],
                &[libc::c_char; 55],
            >(b"void shake256_squeeze(EVP_MD_CTX *, uint8_t *, size_t)\0"))
                .as_ptr(),
        );
    }
    'c_5262: {
        if SHAKE_Squeeze(md, (*ctx).md_data as *mut KECCAK1600_CTX, len) != 0 {} else {
            __assert_fail(
                b"SHAKE_Squeeze(md, ctx->md_data, len)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                527 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 55],
                    &[libc::c_char; 55],
                >(b"void shake256_squeeze(EVP_MD_CTX *, uint8_t *, size_t)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn EVP_shake256_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_shake256_once;
}
static mut EVP_shake256_once: CRYPTO_once_t = 0 as libc::c_int;
static mut EVP_shake256_storage: EVP_MD = env_md_st {
    type_0: 0,
    md_size: 0,
    flags: 0,
    init: None,
    update: None,
    final_0: None,
    block_size: 0,
    ctx_size: 0,
    finalXOF: None,
    squeezeXOF: None,
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_shake256() -> *const EVP_MD {
    CRYPTO_once(
        EVP_shake256_once_bss_get(),
        Some(EVP_shake256_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_shake256_storage_bss_get() as *const EVP_MD;
}
unsafe extern "C" fn EVP_shake256_storage_bss_get() -> *mut EVP_MD {
    return &mut EVP_shake256_storage;
}
unsafe extern "C" fn EVP_shake256_do_init(mut out: *mut EVP_MD) {
    (*out).type_0 = 980 as libc::c_int;
    (*out).md_size = 0 as libc::c_int as libc::c_uint;
    (*out).flags = 4 as libc::c_int as uint32_t;
    (*out).init = Some(shake256_init as unsafe extern "C" fn(*mut EVP_MD_CTX) -> ());
    (*out)
        .update = Some(
        shake256_update
            as unsafe extern "C" fn(
                *mut EVP_MD_CTX,
                *const libc::c_void,
                size_t,
            ) -> libc::c_int,
    );
    (*out).final_0 = None;
    (*out)
        .squeezeXOF = Some(
        shake256_squeeze
            as unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t, size_t) -> (),
    );
    (*out)
        .finalXOF = Some(
        shake256_final
            as unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t, size_t) -> libc::c_int,
    );
    (*out)
        .block_size = ((1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
        / 8 as libc::c_int) as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<KECCAK1600_CTX>() as libc::c_ulong
        as libc::c_uint;
}
unsafe extern "C" fn EVP_shake256_init() {
    EVP_shake256_do_init(EVP_shake256_storage_bss_get());
}
unsafe extern "C" fn md5_sha1_init(mut md_ctx: *mut EVP_MD_CTX) {
    let mut ctx: *mut MD5_SHA1_CTX = (*md_ctx).md_data as *mut MD5_SHA1_CTX;
    if MD5_Init(&mut (*ctx).md5) != 0 && SHA1_Init(&mut (*ctx).sha1) != 0 {} else {
        __assert_fail(
            b"MD5_Init(&ctx->md5) && SHA1_Init(&ctx->sha1)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            550 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 33],
                &[libc::c_char; 33],
            >(b"void md5_sha1_init(EVP_MD_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_5673: {
        if MD5_Init(&mut (*ctx).md5) != 0 && SHA1_Init(&mut (*ctx).sha1) != 0 {} else {
            __assert_fail(
                b"MD5_Init(&ctx->md5) && SHA1_Init(&ctx->sha1)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                550 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 33],
                    &[libc::c_char; 33],
                >(b"void md5_sha1_init(EVP_MD_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn md5_sha1_update(
    mut md_ctx: *mut EVP_MD_CTX,
    mut data: *const libc::c_void,
    mut count: size_t,
) -> libc::c_int {
    let mut ctx: *mut MD5_SHA1_CTX = (*md_ctx).md_data as *mut MD5_SHA1_CTX;
    let mut ok: libc::c_int = (MD5_Update(&mut (*ctx).md5, data, count) != 0
        && SHA1_Update(&mut (*ctx).sha1, data, count) != 0) as libc::c_int;
    return ok;
}
unsafe extern "C" fn md5_sha1_final(mut md_ctx: *mut EVP_MD_CTX, mut out: *mut uint8_t) {
    let mut ctx: *mut MD5_SHA1_CTX = (*md_ctx).md_data as *mut MD5_SHA1_CTX;
    if MD5_Final(out, &mut (*ctx).md5) != 0
        && SHA1_Final(out.offset(16 as libc::c_int as isize), &mut (*ctx).sha1) != 0
    {} else {
        __assert_fail(
            b"MD5_Final(out, &ctx->md5) && SHA1_Final(out + 16, &ctx->sha1)\0"
                as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                as *const u8 as *const libc::c_char,
            567 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 45],
                &[libc::c_char; 45],
            >(b"void md5_sha1_final(EVP_MD_CTX *, uint8_t *)\0"))
                .as_ptr(),
        );
    }
    'c_5538: {
        if MD5_Final(out, &mut (*ctx).md5) != 0
            && SHA1_Final(out.offset(16 as libc::c_int as isize), &mut (*ctx).sha1) != 0
        {} else {
            __assert_fail(
                b"MD5_Final(out, &ctx->md5) && SHA1_Final(out + 16, &ctx->sha1)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digests.c\0"
                    as *const u8 as *const libc::c_char,
                567 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 45],
                    &[libc::c_char; 45],
                >(b"void md5_sha1_final(EVP_MD_CTX *, uint8_t *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn EVP_md5_sha1_init() {
    EVP_md5_sha1_do_init(EVP_md5_sha1_storage_bss_get());
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_md5_sha1() -> *const EVP_MD {
    CRYPTO_once(
        EVP_md5_sha1_once_bss_get(),
        Some(EVP_md5_sha1_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_md5_sha1_storage_bss_get() as *const EVP_MD;
}
static mut EVP_md5_sha1_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EVP_md5_sha1_do_init(mut out: *mut EVP_MD) {
    (*out).type_0 = 114 as libc::c_int;
    (*out).md_size = (16 as libc::c_int + 20 as libc::c_int) as libc::c_uint;
    (*out).flags = 0 as libc::c_int as uint32_t;
    (*out).init = Some(md5_sha1_init as unsafe extern "C" fn(*mut EVP_MD_CTX) -> ());
    (*out)
        .update = Some(
        md5_sha1_update
            as unsafe extern "C" fn(
                *mut EVP_MD_CTX,
                *const libc::c_void,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .final_0 = Some(
        md5_sha1_final as unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t) -> (),
    );
    (*out).squeezeXOF = None;
    (*out).finalXOF = None;
    (*out).block_size = 64 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<MD5_SHA1_CTX>() as libc::c_ulong
        as libc::c_uint;
}
unsafe extern "C" fn EVP_md5_sha1_storage_bss_get() -> *mut EVP_MD {
    return &mut EVP_md5_sha1_storage;
}
static mut EVP_md5_sha1_storage: EVP_MD = env_md_st {
    type_0: 0,
    md_size: 0,
    flags: 0,
    init: None,
    update: None,
    final_0: None,
    block_size: 0,
    ctx_size: 0,
    finalXOF: None,
    squeezeXOF: None,
};
unsafe extern "C" fn EVP_md5_sha1_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_md5_sha1_once;
}
