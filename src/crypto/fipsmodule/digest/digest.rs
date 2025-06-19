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
    pub type dh_st;
    pub type dsa_st;
    pub type ec_key_st;
    pub type engine_st;
    pub type pqdsa_key_st;
    pub type kem_key_st;
    pub type rsa_st;
    pub type hmac_methods_st;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn used_for_hmac(ctx: *mut EVP_MD_CTX) -> libc::c_int;
    fn HMAC_Init_ex(
        ctx: *mut HMAC_CTX,
        key: *const libc::c_void,
        key_len: size_t,
        md: *const EVP_MD,
        impl_0: *mut ENGINE,
    ) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
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
pub type CRYPTO_refcount_t = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cbb_st {
    pub child: *mut CBB,
    pub is_child: libc::c_char,
    pub u: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub base: cbb_buffer_st,
    pub child: cbb_child_st,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct cbb_child_st {
    pub base: *mut cbb_buffer_st,
    pub offset: size_t,
    pub pending_len_len: uint8_t,
    #[bitfield(name = "pending_is_asn1", ty = "libc::c_uint", bits = "0..=0")]
    pub pending_is_asn1: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 6],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct cbb_buffer_st {
    pub buf: *mut uint8_t,
    pub len: size_t,
    pub cap: size_t,
    #[bitfield(name = "can_resize", ty = "libc::c_uint", bits = "0..=0")]
    #[bitfield(name = "error", ty = "libc::c_uint", bits = "1..=1")]
    pub can_resize_error: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
pub type CBB = cbb_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cbs_st {
    pub data: *const uint8_t,
    pub len: size_t,
}
pub type CBS = cbs_st;
pub type DH = dh_st;
pub type DSA = dsa_st;
pub type EC_KEY = ec_key_st;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_md_pctx_ops {
    pub free: Option::<unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> ()>,
    pub dup: Option::<unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> *mut EVP_PKEY_CTX>,
}
pub type EVP_PKEY_CTX = evp_pkey_ctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_pkey_ctx_st {
    pub pmeth: *const EVP_PKEY_METHOD,
    pub engine: *mut ENGINE,
    pub pkey: *mut EVP_PKEY,
    pub peerkey: *mut EVP_PKEY,
    pub operation: libc::c_int,
    pub data: *mut libc::c_void,
    pub app_data: *mut libc::c_void,
    pub pkey_gencb: Option::<EVP_PKEY_gen_cb>,
    pub keygen_info: [libc::c_int; 2],
}
pub type EVP_PKEY_gen_cb = unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> libc::c_int;
pub type EVP_PKEY = evp_pkey_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_pkey_st {
    pub references: CRYPTO_refcount_t,
    pub type_0: libc::c_int,
    pub pkey: C2RustUnnamed_0,
    pub ameth: *const EVP_PKEY_ASN1_METHOD,
}
pub type EVP_PKEY_ASN1_METHOD = evp_pkey_asn1_method_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_pkey_asn1_method_st {
    pub pkey_id: libc::c_int,
    pub oid: [uint8_t; 11],
    pub oid_len: uint8_t,
    pub pem_str: *const libc::c_char,
    pub info: *const libc::c_char,
    pub pub_decode: Option::<
        unsafe extern "C" fn(*mut EVP_PKEY, *mut CBS, *mut CBS, *mut CBS) -> libc::c_int,
    >,
    pub pub_encode: Option::<
        unsafe extern "C" fn(*mut CBB, *const EVP_PKEY) -> libc::c_int,
    >,
    pub pub_cmp: Option::<
        unsafe extern "C" fn(*const EVP_PKEY, *const EVP_PKEY) -> libc::c_int,
    >,
    pub priv_decode: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY,
            *mut CBS,
            *mut CBS,
            *mut CBS,
            *mut CBS,
        ) -> libc::c_int,
    >,
    pub priv_encode: Option::<
        unsafe extern "C" fn(*mut CBB, *const EVP_PKEY) -> libc::c_int,
    >,
    pub priv_encode_v2: Option::<
        unsafe extern "C" fn(*mut CBB, *const EVP_PKEY) -> libc::c_int,
    >,
    pub set_priv_raw: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub set_pub_raw: Option::<
        unsafe extern "C" fn(*mut EVP_PKEY, *const uint8_t, size_t) -> libc::c_int,
    >,
    pub get_priv_raw: Option::<
        unsafe extern "C" fn(*const EVP_PKEY, *mut uint8_t, *mut size_t) -> libc::c_int,
    >,
    pub get_pub_raw: Option::<
        unsafe extern "C" fn(*const EVP_PKEY, *mut uint8_t, *mut size_t) -> libc::c_int,
    >,
    pub pkey_opaque: Option::<unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int>,
    pub pkey_size: Option::<unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int>,
    pub pkey_bits: Option::<unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int>,
    pub param_missing: Option::<unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int>,
    pub param_copy: Option::<
        unsafe extern "C" fn(*mut EVP_PKEY, *const EVP_PKEY) -> libc::c_int,
    >,
    pub param_cmp: Option::<
        unsafe extern "C" fn(*const EVP_PKEY, *const EVP_PKEY) -> libc::c_int,
    >,
    pub pkey_free: Option::<unsafe extern "C" fn(*mut EVP_PKEY) -> ()>,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub ptr: *mut libc::c_void,
    pub rsa: *mut RSA,
    pub dsa: *mut DSA,
    pub dh: *mut DH,
    pub ec: *mut EC_KEY,
    pub kem_key: *mut KEM_KEY,
    pub pqdsa_key: *mut PQDSA_KEY,
}
pub type PQDSA_KEY = pqdsa_key_st;
pub type KEM_KEY = kem_key_st;
pub type RSA = rsa_st;
pub type EVP_PKEY_METHOD = evp_pkey_method_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_pkey_method_st {
    pub pkey_id: libc::c_int,
    pub init: Option::<unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> libc::c_int>,
    pub copy: Option::<
        unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY_CTX) -> libc::c_int,
    >,
    pub cleanup: Option::<unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> ()>,
    pub keygen: Option::<
        unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY) -> libc::c_int,
    >,
    pub sign_init: Option::<unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> libc::c_int>,
    pub sign: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub sign_message: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub verify_init: Option::<unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> libc::c_int>,
    pub verify: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub verify_message: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub verify_recover: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub encrypt: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub decrypt: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub derive: Option::<
        unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut uint8_t, *mut size_t) -> libc::c_int,
    >,
    pub paramgen: Option::<
        unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY) -> libc::c_int,
    >,
    pub ctrl: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            libc::c_int,
            libc::c_int,
            *mut libc::c_void,
        ) -> libc::c_int,
    >,
    pub ctrl_str: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *const libc::c_char,
            *const libc::c_char,
        ) -> libc::c_int,
    >,
    pub keygen_deterministic: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut EVP_PKEY,
            *const uint8_t,
            *mut size_t,
        ) -> libc::c_int,
    >,
    pub encapsulate_deterministic: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut uint8_t,
            *mut size_t,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            *mut size_t,
        ) -> libc::c_int,
    >,
    pub encapsulate: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut uint8_t,
            *mut size_t,
            *mut uint8_t,
            *mut size_t,
        ) -> libc::c_int,
    >,
    pub decapsulate: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
}
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
pub struct HMAC_PKEY_CTX {
    pub md: *const EVP_MD,
    pub ctx: HMAC_CTX,
    pub ktmp: HMAC_KEY,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct HMAC_KEY {
    pub key: *mut uint8_t,
    pub key_len: size_t,
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
pub unsafe extern "C" fn EVP_MD_unstable_sha3_enable(mut enable: bool) {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_MD_unstable_sha3_is_enabled() -> bool {
    return 1 as libc::c_int != 0;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_MD_type(mut md: *const EVP_MD) -> libc::c_int {
    return (*md).type_0;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_MD_nid(mut md: *const EVP_MD) -> libc::c_int {
    return EVP_MD_type(md);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_MD_flags(mut md: *const EVP_MD) -> uint32_t {
    return (*md).flags;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_MD_size(mut md: *const EVP_MD) -> size_t {
    return (*md).md_size as size_t;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_MD_block_size(mut md: *const EVP_MD) -> size_t {
    return (*md).block_size as size_t;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_MD_CTX_init(mut ctx: *mut EVP_MD_CTX) {
    OPENSSL_memset(
        ctx as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_MD_CTX>() as libc::c_ulong,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX {
    let mut ctx: *mut EVP_MD_CTX = OPENSSL_zalloc(
        ::core::mem::size_of::<EVP_MD_CTX>() as libc::c_ulong,
    ) as *mut EVP_MD_CTX;
    !ctx.is_null();
    return ctx;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_MD_CTX_create() -> *mut EVP_MD_CTX {
    return EVP_MD_CTX_new();
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_MD_CTX_cleanup(mut ctx: *mut EVP_MD_CTX) -> libc::c_int {
    if ctx.is_null() {
        return 1 as libc::c_int;
    }
    OPENSSL_free((*ctx).md_data);
    if ((*ctx).pctx).is_null() || !((*ctx).pctx_ops).is_null() {} else {
        __assert_fail(
            b"ctx->pctx == NULL || ctx->pctx_ops != NULL\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digest.c\0"
                as *const u8 as *const libc::c_char,
            107 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 37],
                &[libc::c_char; 37],
            >(b"int EVP_MD_CTX_cleanup(EVP_MD_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_1920: {
        if ((*ctx).pctx).is_null() || !((*ctx).pctx_ops).is_null() {} else {
            __assert_fail(
                b"ctx->pctx == NULL || ctx->pctx_ops != NULL\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digest.c\0"
                    as *const u8 as *const libc::c_char,
                107 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 37],
                    &[libc::c_char; 37],
                >(b"int EVP_MD_CTX_cleanup(EVP_MD_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    if !((*ctx).pctx_ops).is_null()
        && (*ctx).flags & 0x400 as libc::c_int as libc::c_ulong == 0
    {
        ((*(*ctx).pctx_ops).free).expect("non-null function pointer")((*ctx).pctx);
    }
    EVP_MD_CTX_init(ctx);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_MD_CTX_cleanse(mut ctx: *mut EVP_MD_CTX) {
    if ctx.is_null() || ((*ctx).md_data).is_null() || ((*ctx).digest).is_null() {
        return;
    }
    OPENSSL_cleanse((*ctx).md_data, (*(*ctx).digest).ctx_size as size_t);
    EVP_MD_CTX_cleanup(ctx);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_MD_CTX_free(mut ctx: *mut EVP_MD_CTX) {
    if ctx.is_null() {
        return;
    }
    EVP_MD_CTX_cleanup(ctx);
    OPENSSL_free(ctx as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_MD_CTX_destroy(mut ctx: *mut EVP_MD_CTX) {
    EVP_MD_CTX_free(ctx);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_DigestFinalXOF(
    mut ctx: *mut EVP_MD_CTX,
    mut out: *mut uint8_t,
    mut len: size_t,
) -> libc::c_int {
    if ((*ctx).digest).is_null() {
        return 0 as libc::c_int;
    }
    if EVP_MD_flags((*ctx).digest) & 4 as libc::c_int as uint32_t
        == 0 as libc::c_int as uint32_t
    {
        ERR_put_error(
            29 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digest.c\0"
                as *const u8 as *const libc::c_char,
            148 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ok: libc::c_int = ((*(*ctx).digest).finalXOF)
        .expect("non-null function pointer")(ctx, out, len);
    EVP_MD_CTX_cleanse(ctx);
    return ok;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_DigestSqueeze(
    mut ctx: *mut EVP_MD_CTX,
    mut out: *mut uint8_t,
    mut len: size_t,
) -> libc::c_int {
    if ((*ctx).digest).is_null() {
        return 0 as libc::c_int;
    }
    if EVP_MD_flags((*ctx).digest) & 4 as libc::c_int as uint32_t
        == 0 as libc::c_int as uint32_t
    {
        ERR_put_error(
            29 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digest.c\0"
                as *const u8 as *const libc::c_char,
            164 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    ((*(*ctx).digest).squeezeXOF).expect("non-null function pointer")(ctx, out, len);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_MD_meth_get_flags(mut md: *const EVP_MD) -> uint32_t {
    return EVP_MD_flags(md);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_MD_CTX_set_flags(
    mut ctx: *mut EVP_MD_CTX,
    mut flags: libc::c_int,
) {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_MD_CTX_copy_ex(
    mut out: *mut EVP_MD_CTX,
    mut in_0: *const EVP_MD_CTX,
) -> libc::c_int {
    if in_0.is_null() || ((*in_0).pctx).is_null() && ((*in_0).digest).is_null() {
        ERR_put_error(
            29 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digest.c\0"
                as *const u8 as *const libc::c_char,
            179 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut pctx: *mut EVP_PKEY_CTX = 0 as *mut EVP_PKEY_CTX;
    if ((*in_0).pctx).is_null() || !((*in_0).pctx_ops).is_null() {} else {
        __assert_fail(
            b"in->pctx == NULL || in->pctx_ops != NULL\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digest.c\0"
                as *const u8 as *const libc::c_char,
            184 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 57],
                &[libc::c_char; 57],
            >(b"int EVP_MD_CTX_copy_ex(EVP_MD_CTX *, const EVP_MD_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_2476: {
        if ((*in_0).pctx).is_null() || !((*in_0).pctx_ops).is_null() {} else {
            __assert_fail(
                b"in->pctx == NULL || in->pctx_ops != NULL\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digest.c\0"
                    as *const u8 as *const libc::c_char,
                184 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 57],
                    &[libc::c_char; 57],
                >(b"int EVP_MD_CTX_copy_ex(EVP_MD_CTX *, const EVP_MD_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    if !((*in_0).pctx).is_null() {
        pctx = ((*(*in_0).pctx_ops).dup)
            .expect("non-null function pointer")((*in_0).pctx);
        if pctx.is_null() {
            return 0 as libc::c_int;
        }
    }
    let mut tmp_buf: *mut uint8_t = 0 as *mut uint8_t;
    if !((*in_0).digest).is_null() {
        if (*out).digest != (*in_0).digest {
            if (*(*in_0).digest).ctx_size != 0 as libc::c_int as libc::c_uint {} else {
                __assert_fail(
                    b"in->digest->ctx_size != 0\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digest.c\0"
                        as *const u8 as *const libc::c_char,
                    195 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 57],
                        &[libc::c_char; 57],
                    >(b"int EVP_MD_CTX_copy_ex(EVP_MD_CTX *, const EVP_MD_CTX *)\0"))
                        .as_ptr(),
                );
            }
            'c_2387: {
                if (*(*in_0).digest).ctx_size != 0 as libc::c_int as libc::c_uint
                {} else {
                    __assert_fail(
                        b"in->digest->ctx_size != 0\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digest.c\0"
                            as *const u8 as *const libc::c_char,
                        195 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 57],
                            &[libc::c_char; 57],
                        >(b"int EVP_MD_CTX_copy_ex(EVP_MD_CTX *, const EVP_MD_CTX *)\0"))
                            .as_ptr(),
                    );
                }
            };
            tmp_buf = OPENSSL_malloc((*(*in_0).digest).ctx_size as size_t)
                as *mut uint8_t;
            if tmp_buf.is_null() {
                if !pctx.is_null() {
                    ((*(*in_0).pctx_ops).free).expect("non-null function pointer")(pctx);
                }
                return 0 as libc::c_int;
            }
        } else {
            tmp_buf = (*out).md_data as *mut uint8_t;
            (*out).md_data = 0 as *mut libc::c_void;
        }
    }
    EVP_MD_CTX_cleanup(out);
    (*out).digest = (*in_0).digest;
    (*out).md_data = tmp_buf as *mut libc::c_void;
    if !((*in_0).digest).is_null() && !((*in_0).md_data).is_null() {
        OPENSSL_memcpy(
            (*out).md_data,
            (*in_0).md_data,
            (*(*in_0).digest).ctx_size as size_t,
        );
    }
    (*out).update = (*in_0).update;
    (*out).flags = (*in_0).flags;
    (*out).flags &= !(0x400 as libc::c_int) as libc::c_ulong;
    (*out).pctx = pctx;
    (*out).pctx_ops = (*in_0).pctx_ops;
    if ((*out).pctx).is_null() || !((*out).pctx_ops).is_null() {} else {
        __assert_fail(
            b"out->pctx == NULL || out->pctx_ops != NULL\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digest.c\0"
                as *const u8 as *const libc::c_char,
            226 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 57],
                &[libc::c_char; 57],
            >(b"int EVP_MD_CTX_copy_ex(EVP_MD_CTX *, const EVP_MD_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_2117: {
        if ((*out).pctx).is_null() || !((*out).pctx_ops).is_null() {} else {
            __assert_fail(
                b"out->pctx == NULL || out->pctx_ops != NULL\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digest.c\0"
                    as *const u8 as *const libc::c_char,
                226 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 57],
                    &[libc::c_char; 57],
                >(b"int EVP_MD_CTX_copy_ex(EVP_MD_CTX *, const EVP_MD_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_MD_CTX_move(
    mut out: *mut EVP_MD_CTX,
    mut in_0: *mut EVP_MD_CTX,
) {
    EVP_MD_CTX_cleanup(out);
    OPENSSL_memcpy(
        out as *mut libc::c_void,
        in_0 as *const libc::c_void,
        ::core::mem::size_of::<EVP_MD_CTX>() as libc::c_ulong,
    );
    EVP_MD_CTX_init(in_0);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_MD_CTX_copy(
    mut out: *mut EVP_MD_CTX,
    mut in_0: *const EVP_MD_CTX,
) -> libc::c_int {
    EVP_MD_CTX_init(out);
    return EVP_MD_CTX_copy_ex(out, in_0);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_MD_CTX_reset(mut ctx: *mut EVP_MD_CTX) -> libc::c_int {
    EVP_MD_CTX_cleanup(ctx);
    EVP_MD_CTX_init(ctx);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_DigestInit_ex(
    mut ctx: *mut EVP_MD_CTX,
    mut type_0: *const EVP_MD,
    mut engine: *mut ENGINE,
) -> libc::c_int {
    if (*ctx).digest != type_0 {
        (*ctx).digest = type_0;
        if used_for_hmac(ctx) == 0 {
            if (*type_0).ctx_size != 0 as libc::c_int as libc::c_uint {} else {
                __assert_fail(
                    b"type->ctx_size != 0\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digest.c\0"
                        as *const u8 as *const libc::c_char,
                    253 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 62],
                        &[libc::c_char; 62],
                    >(
                        b"int EVP_DigestInit_ex(EVP_MD_CTX *, const EVP_MD *, ENGINE *)\0",
                    ))
                        .as_ptr(),
                );
            }
            'c_2923: {
                if (*type_0).ctx_size != 0 as libc::c_int as libc::c_uint {} else {
                    __assert_fail(
                        b"type->ctx_size != 0\0" as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digest.c\0"
                            as *const u8 as *const libc::c_char,
                        253 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 62],
                            &[libc::c_char; 62],
                        >(
                            b"int EVP_DigestInit_ex(EVP_MD_CTX *, const EVP_MD *, ENGINE *)\0",
                        ))
                            .as_ptr(),
                    );
                }
            };
            (*ctx).update = (*type_0).update;
            let mut md_data: *mut uint8_t = OPENSSL_malloc((*type_0).ctx_size as size_t)
                as *mut uint8_t;
            if md_data.is_null() {
                return 0 as libc::c_int;
            }
            OPENSSL_free((*ctx).md_data);
            (*ctx).md_data = md_data as *mut libc::c_void;
        }
    }
    if ((*ctx).pctx).is_null() || !((*ctx).pctx_ops).is_null() {} else {
        __assert_fail(
            b"ctx->pctx == NULL || ctx->pctx_ops != NULL\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digest.c\0"
                as *const u8 as *const libc::c_char,
            264 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 62],
                &[libc::c_char; 62],
            >(b"int EVP_DigestInit_ex(EVP_MD_CTX *, const EVP_MD *, ENGINE *)\0"))
                .as_ptr(),
        );
    }
    'c_2802: {
        if ((*ctx).pctx).is_null() || !((*ctx).pctx_ops).is_null() {} else {
            __assert_fail(
                b"ctx->pctx == NULL || ctx->pctx_ops != NULL\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digest.c\0"
                    as *const u8 as *const libc::c_char,
                264 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 62],
                    &[libc::c_char; 62],
                >(b"int EVP_DigestInit_ex(EVP_MD_CTX *, const EVP_MD *, ENGINE *)\0"))
                    .as_ptr(),
            );
        }
    };
    if used_for_hmac(ctx) != 0 {
        if ((*ctx).pctx).is_null() || ((*(*ctx).pctx).data).is_null()
            || ((*(*ctx).pctx).pkey).is_null()
            || ((*(*(*ctx).pctx).pkey).pkey.ptr).is_null()
        {
            return 0 as libc::c_int;
        }
        let mut key: *const HMAC_KEY = (*(*(*ctx).pctx).pkey).pkey.ptr
            as *const HMAC_KEY;
        let mut hmac_pctx: *mut HMAC_PKEY_CTX = (*(*ctx).pctx).data
            as *mut HMAC_PKEY_CTX;
        if HMAC_Init_ex(
            &mut (*hmac_pctx).ctx,
            (*key).key as *const libc::c_void,
            (*key).key_len,
            (*hmac_pctx).md,
            (*(*ctx).pctx).engine,
        ) == 0
        {
            return 0 as libc::c_int;
        }
        return 1 as libc::c_int;
    }
    ((*(*ctx).digest).init).expect("non-null function pointer")(ctx);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_DigestInit(
    mut ctx: *mut EVP_MD_CTX,
    mut type_0: *const EVP_MD,
) -> libc::c_int {
    EVP_MD_CTX_init(ctx);
    return EVP_DigestInit_ex(ctx, type_0, 0 as *mut ENGINE);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_DigestUpdate(
    mut ctx: *mut EVP_MD_CTX,
    mut data: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    if ((*ctx).update).is_none() {
        return 0 as libc::c_int;
    }
    return ((*ctx).update).expect("non-null function pointer")(ctx, data, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_DigestFinal_ex(
    mut ctx: *mut EVP_MD_CTX,
    mut md_out: *mut uint8_t,
    mut size: *mut libc::c_uint,
) -> libc::c_int {
    if ((*ctx).digest).is_null() {
        return 0 as libc::c_int;
    }
    if EVP_MD_flags((*ctx).digest) & 4 as libc::c_int as uint32_t != 0 {
        ERR_put_error(
            29 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digest.c\0"
                as *const u8 as *const libc::c_char,
            304 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*(*ctx).digest).md_size <= 64 as libc::c_int as libc::c_uint {} else {
        __assert_fail(
            b"ctx->digest->md_size <= EVP_MAX_MD_SIZE\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digest.c\0"
                as *const u8 as *const libc::c_char,
            308 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 64],
                &[libc::c_char; 64],
            >(b"int EVP_DigestFinal_ex(EVP_MD_CTX *, uint8_t *, unsigned int *)\0"))
                .as_ptr(),
        );
    }
    'c_3095: {
        if (*(*ctx).digest).md_size <= 64 as libc::c_int as libc::c_uint {} else {
            __assert_fail(
                b"ctx->digest->md_size <= EVP_MAX_MD_SIZE\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digest.c\0"
                    as *const u8 as *const libc::c_char,
                308 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 64],
                    &[libc::c_char; 64],
                >(b"int EVP_DigestFinal_ex(EVP_MD_CTX *, uint8_t *, unsigned int *)\0"))
                    .as_ptr(),
            );
        }
    };
    ((*(*ctx).digest).final_0).expect("non-null function pointer")(ctx, md_out);
    if !size.is_null() {
        *size = (*(*ctx).digest).md_size;
    }
    OPENSSL_cleanse((*ctx).md_data, (*(*ctx).digest).ctx_size as size_t);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_DigestFinal(
    mut ctx: *mut EVP_MD_CTX,
    mut md: *mut uint8_t,
    mut size: *mut libc::c_uint,
) -> libc::c_int {
    let mut ok: libc::c_int = EVP_DigestFinal_ex(ctx, md, size);
    EVP_MD_CTX_cleanup(ctx);
    return ok;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_Digest(
    mut data: *const libc::c_void,
    mut count: size_t,
    mut out_md: *mut uint8_t,
    mut out_size: *mut libc::c_uint,
    mut type_0: *const EVP_MD,
    mut impl_0: *mut ENGINE,
) -> libc::c_int {
    let mut ctx: EVP_MD_CTX = env_md_ctx_st {
        digest: 0 as *const EVP_MD,
        md_data: 0 as *mut libc::c_void,
        update: None,
        pctx: 0 as *mut EVP_PKEY_CTX,
        pctx_ops: 0 as *const evp_md_pctx_ops,
        flags: 0,
    };
    let mut ret: libc::c_int = 0;
    if EVP_MD_flags(type_0) & 4 as libc::c_int as uint32_t != 0 && out_size.is_null() {
        ERR_put_error(
            29 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/digest/digest.c\0"
                as *const u8 as *const libc::c_char,
            329 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    EVP_MD_CTX_init(&mut ctx);
    ret = (EVP_DigestInit_ex(&mut ctx, type_0, impl_0) != 0
        && EVP_DigestUpdate(&mut ctx, data, count) != 0) as libc::c_int;
    if ret == 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if EVP_MD_flags(type_0) & 4 as libc::c_int as uint32_t != 0 {
        ret &= EVP_DigestFinalXOF(&mut ctx, out_md, *out_size as size_t);
    } else {
        ret &= EVP_DigestFinal(&mut ctx, out_md, out_size);
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_MD_CTX_md(mut ctx: *const EVP_MD_CTX) -> *const EVP_MD {
    if ctx.is_null() {
        return 0 as *const EVP_MD;
    }
    return (*ctx).digest;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_MD_CTX_size(mut ctx: *const EVP_MD_CTX) -> size_t {
    return EVP_MD_size(EVP_MD_CTX_md(ctx));
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_MD_CTX_block_size(mut ctx: *const EVP_MD_CTX) -> size_t {
    return EVP_MD_block_size(EVP_MD_CTX_md(ctx));
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_MD_CTX_type(mut ctx: *const EVP_MD_CTX) -> libc::c_int {
    return EVP_MD_type(EVP_MD_CTX_md(ctx));
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_add_digest(mut digest: *const EVP_MD) -> libc::c_int {
    return 1 as libc::c_int;
}
