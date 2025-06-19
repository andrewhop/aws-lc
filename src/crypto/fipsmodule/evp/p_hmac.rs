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
    pub type dh_st;
    pub type dsa_st;
    pub type ec_key_st;
    pub type engine_st;
    pub type evp_md_pctx_ops;
    pub type pqdsa_key_st;
    pub type kem_key_st;
    pub type rsa_st;
    pub type env_md_st;
    pub type hmac_methods_st;
    fn EVP_PKEY_CTX_ctrl(
        ctx: *mut EVP_PKEY_CTX,
        keytype: libc::c_int,
        optype: libc::c_int,
        cmd: libc::c_int,
        p1: libc::c_int,
        p2: *mut libc::c_void,
    ) -> libc::c_int;
    fn EVP_PKEY_assign(
        pkey: *mut EVP_PKEY,
        type_0: libc::c_int,
        key: *mut libc::c_void,
    ) -> libc::c_int;
    fn HMAC_CTX_init(ctx: *mut HMAC_CTX);
    fn HMAC_CTX_copy_ex(dest: *mut HMAC_CTX, src: *const HMAC_CTX) -> libc::c_int;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_strnlen(s: *const libc::c_char, len: size_t) -> size_t;
    fn OPENSSL_hexstr2buf(str: *const libc::c_char, len: *mut size_t) -> *mut uint8_t;
    fn OPENSSL_memdup(data: *const libc::c_void, size: size_t) -> *mut libc::c_void;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
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
pub struct HMAC_KEY {
    pub key: *mut uint8_t,
    pub key_len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct HMAC_PKEY_CTX {
    pub md: *const EVP_MD,
    pub ctx: HMAC_CTX,
    pub ktmp: HMAC_KEY,
}
pub type CRYPTO_once_t = pthread_once_t;
unsafe extern "C" fn hmac_init(mut ctx: *mut EVP_PKEY_CTX) -> libc::c_int {
    let mut hctx: *mut HMAC_PKEY_CTX = 0 as *mut HMAC_PKEY_CTX;
    hctx = OPENSSL_zalloc(::core::mem::size_of::<HMAC_PKEY_CTX>() as libc::c_ulong)
        as *mut HMAC_PKEY_CTX;
    if hctx.is_null() {
        return 0 as libc::c_int;
    }
    HMAC_CTX_init(&mut (*hctx).ctx);
    (*ctx).data = hctx as *mut libc::c_void;
    return 1 as libc::c_int;
}
unsafe extern "C" fn hmac_copy(
    mut dst: *mut EVP_PKEY_CTX,
    mut src: *mut EVP_PKEY_CTX,
) -> libc::c_int {
    let mut sctx: *mut HMAC_PKEY_CTX = 0 as *mut HMAC_PKEY_CTX;
    let mut dctx: *mut HMAC_PKEY_CTX = 0 as *mut HMAC_PKEY_CTX;
    if hmac_init(dst) == 0 {
        return 0 as libc::c_int;
    }
    sctx = (*src).data as *mut HMAC_PKEY_CTX;
    dctx = (*dst).data as *mut HMAC_PKEY_CTX;
    (*dctx).md = (*sctx).md;
    if !((*sctx).ktmp.key).is_null()
        && HMAC_KEY_copy(&mut (*sctx).ktmp, &mut (*dctx).ktmp) == 0
    {
        OPENSSL_free(dctx as *mut libc::c_void);
        return 0 as libc::c_int;
    }
    if HMAC_CTX_copy_ex(&mut (*dctx).ctx, &mut (*sctx).ctx) == 0 {
        OPENSSL_free(dctx as *mut libc::c_void);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn hmac_cleanup(mut ctx: *mut EVP_PKEY_CTX) {
    let mut hctx: *mut HMAC_PKEY_CTX = (*ctx).data as *mut HMAC_PKEY_CTX;
    OPENSSL_free((*hctx).ktmp.key as *mut libc::c_void);
    OPENSSL_free(hctx as *mut libc::c_void);
}
unsafe extern "C" fn hmac_ctrl(
    mut ctx: *mut EVP_PKEY_CTX,
    mut cmd: libc::c_int,
    mut p1: libc::c_int,
    mut p2: *mut libc::c_void,
) -> libc::c_int {
    let mut result: libc::c_int = -(2 as libc::c_int);
    let mut hctx: *mut HMAC_PKEY_CTX = (*ctx).data as *mut HMAC_PKEY_CTX;
    match cmd {
        4118 => {
            if p1 >= 0 as libc::c_int && p1 <= 32767 as libc::c_int {
                if HMAC_KEY_set(&mut (*hctx).ktmp, p2 as *const uint8_t, p1 as size_t)
                    != 0
                {
                    result = 1 as libc::c_int;
                } else {
                    result = 0 as libc::c_int;
                }
            }
        }
        1 => {
            (*hctx).md = p2 as *const EVP_MD;
            result = 1 as libc::c_int;
        }
        _ => {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                101 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_hmac.c\0"
                    as *const u8 as *const libc::c_char,
                125 as libc::c_int as libc::c_uint,
            );
        }
    }
    return result;
}
unsafe extern "C" fn hmac_ctrl_str(
    mut ctx: *mut EVP_PKEY_CTX,
    mut type_0: *const libc::c_char,
    mut value: *const libc::c_char,
) -> libc::c_int {
    if value.is_null() {
        return 0 as libc::c_int;
    }
    if strcmp(type_0, b"key\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        let keylen: size_t = OPENSSL_strnlen(value, 32767 as libc::c_int as size_t);
        return EVP_PKEY_CTX_ctrl(
            ctx,
            855 as libc::c_int,
            (1 as libc::c_int) << 2 as libc::c_int,
            0x1000 as libc::c_int + 22 as libc::c_int,
            keylen as libc::c_int,
            value as *mut libc::c_void,
        );
    }
    if strcmp(type_0, b"hexkey\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        let mut hex_keylen: size_t = 0 as libc::c_int as size_t;
        let mut key: *mut uint8_t = OPENSSL_hexstr2buf(value, &mut hex_keylen);
        if key.is_null() {
            return 0 as libc::c_int;
        }
        let mut result: libc::c_int = EVP_PKEY_CTX_ctrl(
            ctx,
            855 as libc::c_int,
            (1 as libc::c_int) << 2 as libc::c_int,
            0x1000 as libc::c_int + 22 as libc::c_int,
            hex_keylen as libc::c_int,
            key as *mut libc::c_void,
        );
        OPENSSL_free(key as *mut libc::c_void);
        return result;
    }
    return -(2 as libc::c_int);
}
unsafe extern "C" fn hmac_keygen(
    mut ctx: *mut EVP_PKEY_CTX,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    if pkey.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_hmac.c\0"
                as *const u8 as *const libc::c_char,
            157 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut hmac: *mut HMAC_KEY = 0 as *mut HMAC_KEY;
    let mut hctx: *mut HMAC_PKEY_CTX = (*ctx).data as *mut HMAC_PKEY_CTX;
    if hctx.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            126 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_hmac.c\0"
                as *const u8 as *const libc::c_char,
            161 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    hmac = HMAC_KEY_new();
    if hmac.is_null() {
        return 0 as libc::c_int;
    }
    if HMAC_KEY_copy(hmac, &mut (*hctx).ktmp) == 0
        || EVP_PKEY_assign(pkey, 855 as libc::c_int, hmac as *mut libc::c_void) == 0
    {
        OPENSSL_free((*hmac).key as *mut libc::c_void);
        OPENSSL_free(hmac as *mut libc::c_void);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
static mut EVP_PKEY_hmac_pkey_meth_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EVP_PKEY_hmac_pkey_meth_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_PKEY_hmac_pkey_meth_once;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_hmac_pkey_meth() -> *const EVP_PKEY_METHOD {
    CRYPTO_once(
        EVP_PKEY_hmac_pkey_meth_once_bss_get(),
        Some(EVP_PKEY_hmac_pkey_meth_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_PKEY_hmac_pkey_meth_storage_bss_get() as *const EVP_PKEY_METHOD;
}
unsafe extern "C" fn EVP_PKEY_hmac_pkey_meth_init() {
    EVP_PKEY_hmac_pkey_meth_do_init(EVP_PKEY_hmac_pkey_meth_storage_bss_get());
}
unsafe extern "C" fn EVP_PKEY_hmac_pkey_meth_storage_bss_get() -> *mut EVP_PKEY_METHOD {
    return &mut EVP_PKEY_hmac_pkey_meth_storage;
}
static mut EVP_PKEY_hmac_pkey_meth_storage: EVP_PKEY_METHOD = evp_pkey_method_st {
    pkey_id: 0,
    init: None,
    copy: None,
    cleanup: None,
    keygen: None,
    sign_init: None,
    sign: None,
    sign_message: None,
    verify_init: None,
    verify: None,
    verify_message: None,
    verify_recover: None,
    encrypt: None,
    decrypt: None,
    derive: None,
    paramgen: None,
    ctrl: None,
    ctrl_str: None,
    keygen_deterministic: None,
    encapsulate_deterministic: None,
    encapsulate: None,
    decapsulate: None,
};
unsafe extern "C" fn EVP_PKEY_hmac_pkey_meth_do_init(mut out: *mut EVP_PKEY_METHOD) {
    (*out).pkey_id = 855 as libc::c_int;
    (*out)
        .init = Some(
        hmac_init as unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> libc::c_int,
    );
    (*out)
        .copy = Some(
        hmac_copy
            as unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY_CTX) -> libc::c_int,
    );
    (*out).cleanup = Some(hmac_cleanup as unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> ());
    (*out)
        .keygen = Some(
        hmac_keygen
            as unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY) -> libc::c_int,
    );
    (*out)
        .ctrl = Some(
        hmac_ctrl
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                libc::c_int,
                libc::c_int,
                *mut libc::c_void,
            ) -> libc::c_int,
    );
    (*out)
        .ctrl_str = Some(
        hmac_ctrl_str
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *const libc::c_char,
                *const libc::c_char,
            ) -> libc::c_int,
    );
}
#[no_mangle]
pub unsafe extern "C" fn used_for_hmac(mut ctx: *mut EVP_MD_CTX) -> libc::c_int {
    return ((*ctx).flags == 0x800 as libc::c_int as libc::c_ulong
        && !((*ctx).pctx).is_null()) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn HMAC_KEY_new() -> *mut HMAC_KEY {
    let mut key: *mut HMAC_KEY = OPENSSL_zalloc(
        ::core::mem::size_of::<HMAC_KEY>() as libc::c_ulong,
    ) as *mut HMAC_KEY;
    if key.is_null() {
        return 0 as *mut HMAC_KEY;
    }
    return key;
}
#[no_mangle]
pub unsafe extern "C" fn HMAC_KEY_set(
    mut hmac_key: *mut HMAC_KEY,
    mut key: *const uint8_t,
    key_len: size_t,
) -> libc::c_int {
    if hmac_key.is_null() {
        return 0 as libc::c_int;
    }
    if key.is_null() || key_len == 0 as libc::c_int as size_t {
        (*hmac_key).key = 0 as *mut uint8_t;
        (*hmac_key).key_len = 0 as libc::c_int as size_t;
        return 1 as libc::c_int;
    }
    let mut new_key: *mut uint8_t = OPENSSL_memdup(key as *const libc::c_void, key_len)
        as *mut uint8_t;
    if new_key.is_null() {
        return 0 as libc::c_int;
    }
    OPENSSL_free((*hmac_key).key as *mut libc::c_void);
    (*hmac_key).key = new_key;
    (*hmac_key).key_len = key_len;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn HMAC_KEY_copy(
    mut dest: *mut HMAC_KEY,
    mut src: *mut HMAC_KEY,
) -> libc::c_int {
    if dest.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_hmac.c\0"
                as *const u8 as *const libc::c_char,
            222 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if src.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_hmac.c\0"
                as *const u8 as *const libc::c_char,
            223 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return HMAC_KEY_set(dest, (*src).key, (*src).key_len);
}
