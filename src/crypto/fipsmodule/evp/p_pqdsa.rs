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
    pub type kem_key_st;
    pub type rsa_st;
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn PQDSA_KEY_init(key: *mut PQDSA_KEY, pqdsa: *const PQDSA) -> libc::c_int;
    fn PQDSA_find_dsa_by_nid(nid: libc::c_int) -> *const PQDSA;
    fn PQDSA_KEY_get0_dsa(key: *mut PQDSA_KEY) -> *const PQDSA;
    fn PQDSA_KEY_new() -> *mut PQDSA_KEY;
    fn PQDSA_KEY_free(key: *mut PQDSA_KEY);
    fn PQDSA_KEY_set_raw_keypair_from_seed(
        key: *mut PQDSA_KEY,
        in_0: *mut CBS,
    ) -> libc::c_int;
    fn PQDSA_KEY_set_raw_public_key(key: *mut PQDSA_KEY, in_0: *mut CBS) -> libc::c_int;
    fn PQDSA_KEY_set_raw_private_key(key: *mut PQDSA_KEY, in_0: *mut CBS) -> libc::c_int;
    fn EVP_PKEY_new() -> *mut EVP_PKEY;
    fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
    fn EVP_PKEY_assign(
        pkey: *mut EVP_PKEY,
        type_0: libc::c_int,
        key: *mut libc::c_void,
    ) -> libc::c_int;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    static pqdsa_asn1_meth: EVP_PKEY_ASN1_METHOD;
    fn evp_pkey_set_method(pkey: *mut EVP_PKEY, method: *const EVP_PKEY_ASN1_METHOD);
    fn CRYPTO_once(
        once: *mut CRYPTO_once_t,
        init: Option::<unsafe extern "C" fn() -> ()>,
    );
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pqdsa_key_st {
    pub pqdsa: *const PQDSA,
    pub public_key: *mut uint8_t,
    pub private_key: *mut uint8_t,
    pub seed: *mut uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PQDSA {
    pub nid: libc::c_int,
    pub oid: *const uint8_t,
    pub oid_len: uint8_t,
    pub comment: *const libc::c_char,
    pub public_key_len: size_t,
    pub private_key_len: size_t,
    pub signature_len: size_t,
    pub keygen_seed_len: size_t,
    pub sign_seed_len: size_t,
    pub method: *const PQDSA_METHOD,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PQDSA_METHOD {
    pub pqdsa_keygen: Option::<
        unsafe extern "C" fn(*mut uint8_t, *mut uint8_t, *mut uint8_t) -> libc::c_int,
    >,
    pub pqdsa_keygen_internal: Option::<
        unsafe extern "C" fn(*mut uint8_t, *mut uint8_t, *const uint8_t) -> libc::c_int,
    >,
    pub pqdsa_sign_message: Option::<
        unsafe extern "C" fn(
            *const uint8_t,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub pqdsa_sign: Option::<
        unsafe extern "C" fn(
            *const uint8_t,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub pqdsa_verify_message: Option::<
        unsafe extern "C" fn(
            *const uint8_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub pqdsa_verify: Option::<
        unsafe extern "C" fn(
            *const uint8_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub pqdsa_pack_pk_from_sk: Option::<
        unsafe extern "C" fn(*mut uint8_t, *const uint8_t) -> libc::c_int,
    >,
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PQDSA_PKEY_CTX {
    pub pqdsa: *const PQDSA,
}
pub type CRYPTO_once_t = pthread_once_t;
unsafe extern "C" fn pkey_pqdsa_init(mut ctx: *mut EVP_PKEY_CTX) -> libc::c_int {
    let mut dctx: *mut PQDSA_PKEY_CTX = 0 as *mut PQDSA_PKEY_CTX;
    dctx = OPENSSL_zalloc(::core::mem::size_of::<PQDSA_PKEY_CTX>() as libc::c_ulong)
        as *mut PQDSA_PKEY_CTX;
    if dctx.is_null() {
        return 0 as libc::c_int;
    }
    (*ctx).data = dctx as *mut libc::c_void;
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_pqdsa_cleanup(mut ctx: *mut EVP_PKEY_CTX) {
    OPENSSL_free((*ctx).data);
}
unsafe extern "C" fn pkey_pqdsa_keygen(
    mut ctx: *mut EVP_PKEY_CTX,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    if ctx.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            37 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut dctx: *mut PQDSA_PKEY_CTX = (*ctx).data as *mut PQDSA_PKEY_CTX;
    if dctx.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            39 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut pqdsa: *const PQDSA = (*dctx).pqdsa;
    if pqdsa.is_null() {
        if ((*ctx).pkey).is_null() {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                124 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_pqdsa.c\0"
                    as *const u8 as *const libc::c_char,
                43 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        pqdsa = PQDSA_KEY_get0_dsa((*(*ctx).pkey).pkey.pqdsa_key);
    }
    let mut key: *mut PQDSA_KEY = PQDSA_KEY_new();
    if key.is_null() || PQDSA_KEY_init(key, pqdsa) == 0
        || ((*(*pqdsa).method).pqdsa_keygen)
            .expect(
                "non-null function pointer",
            )((*key).public_key, (*key).private_key, (*key).seed) == 0
        || EVP_PKEY_assign(pkey, 993 as libc::c_int, key as *mut libc::c_void) == 0
    {
        PQDSA_KEY_free(key);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_pqdsa_sign_generic(
    mut ctx: *mut EVP_PKEY_CTX,
    mut sig: *mut uint8_t,
    mut sig_len: *mut size_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut sign_digest: libc::c_int,
) -> libc::c_int {
    if sig_len.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            63 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut dctx: *mut PQDSA_PKEY_CTX = (*ctx).data as *mut PQDSA_PKEY_CTX;
    let mut pqdsa: *const PQDSA = (*dctx).pqdsa;
    if pqdsa.is_null() {
        if ((*ctx).pkey).is_null() {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                124 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_pqdsa.c\0"
                    as *const u8 as *const libc::c_char,
                69 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        pqdsa = PQDSA_KEY_get0_dsa((*(*ctx).pkey).pkey.pqdsa_key);
    }
    if sig.is_null() {
        *sig_len = (*pqdsa).signature_len;
        return 1 as libc::c_int;
    }
    if *sig_len != (*pqdsa).signature_len {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            82 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*ctx).pkey).is_null() || ((*(*ctx).pkey).pkey.pqdsa_key).is_null()
        || (*(*ctx).pkey).type_0 != 993 as libc::c_int
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            126 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            90 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut key: *mut PQDSA_KEY = (*(*ctx).pkey).pkey.pqdsa_key;
    if ((*key).private_key).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            120 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            96 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if sign_digest == 0 {
        if ((*(*pqdsa).method).pqdsa_sign_message)
            .expect(
                "non-null function pointer",
            )(
            (*key).private_key,
            sig,
            sig_len,
            message,
            message_len,
            0 as *const uint8_t,
            0 as libc::c_int as size_t,
        ) == 0
        {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                4 as libc::c_int | 64 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_pqdsa.c\0"
                    as *const u8 as *const libc::c_char,
                112 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    } else if ((*(*pqdsa).method).pqdsa_sign)
        .expect(
            "non-null function pointer",
        )((*key).private_key, sig, sig_len, message, message_len) == 0
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            4 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            119 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_pqdsa_sign(
    mut ctx: *mut EVP_PKEY_CTX,
    mut sig: *mut uint8_t,
    mut sig_len: *mut size_t,
    mut digest: *const uint8_t,
    mut digest_len: size_t,
) -> libc::c_int {
    return pkey_pqdsa_sign_generic(
        ctx,
        sig,
        sig_len,
        digest,
        digest_len,
        1 as libc::c_int,
    );
}
unsafe extern "C" fn pkey_pqdsa_sign_message(
    mut ctx: *mut EVP_PKEY_CTX,
    mut sig: *mut uint8_t,
    mut sig_len: *mut size_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
) -> libc::c_int {
    return pkey_pqdsa_sign_generic(
        ctx,
        sig,
        sig_len,
        message,
        message_len,
        0 as libc::c_int,
    );
}
unsafe extern "C" fn pkey_pqdsa_verify_generic(
    mut ctx: *mut EVP_PKEY_CTX,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut verify_digest: libc::c_int,
) -> libc::c_int {
    let mut dctx: *mut PQDSA_PKEY_CTX = (*ctx).data as *mut PQDSA_PKEY_CTX;
    let mut pqdsa: *const PQDSA = (*dctx).pqdsa;
    if sig.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            118 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            148 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if pqdsa.is_null() {
        if ((*ctx).pkey).is_null() {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                124 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_pqdsa.c\0"
                    as *const u8 as *const libc::c_char,
                154 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        pqdsa = PQDSA_KEY_get0_dsa((*(*ctx).pkey).pkey.pqdsa_key);
    }
    if ((*ctx).pkey).is_null() || ((*(*ctx).pkey).pkey.pqdsa_key).is_null()
        || (*(*ctx).pkey).type_0 != 993 as libc::c_int
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            126 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            164 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut key: *mut PQDSA_KEY = (*(*ctx).pkey).pkey.pqdsa_key;
    if verify_digest == 0 {
        if sig_len != (*pqdsa).signature_len
            || ((*(*pqdsa).method).pqdsa_verify_message)
                .expect(
                    "non-null function pointer",
                )(
                (*key).public_key,
                sig,
                sig_len,
                message,
                message_len,
                0 as *const uint8_t,
                0 as libc::c_int as size_t,
            ) == 0
        {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                131 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_pqdsa.c\0"
                    as *const u8 as *const libc::c_char,
                183 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    } else if sig_len != (*pqdsa).signature_len
        || ((*(*pqdsa).method).pqdsa_verify)
            .expect(
                "non-null function pointer",
            )((*key).public_key, sig, sig_len, message, message_len) == 0
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            131 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            191 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_pqdsa_verify(
    mut ctx: *mut EVP_PKEY_CTX,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
) -> libc::c_int {
    return pkey_pqdsa_verify_generic(
        ctx,
        sig,
        sig_len,
        message,
        message_len,
        1 as libc::c_int,
    );
}
unsafe extern "C" fn pkey_pqdsa_verify_message(
    mut ctx: *mut EVP_PKEY_CTX,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
) -> libc::c_int {
    return pkey_pqdsa_verify_generic(
        ctx,
        sig,
        sig_len,
        message,
        message_len,
        0 as libc::c_int,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_pqdsa_set_params(
    mut pkey: *mut EVP_PKEY,
    mut nid: libc::c_int,
) -> libc::c_int {
    let mut pqdsa: *const PQDSA = PQDSA_find_dsa_by_nid(nid);
    if pqdsa.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            128 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            220 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    evp_pkey_set_method(pkey, &pqdsa_asn1_meth);
    let mut key: *mut PQDSA_KEY = PQDSA_KEY_new();
    if key.is_null() {
        return 0 as libc::c_int;
    }
    (*key).pqdsa = pqdsa;
    (*pkey).pkey.pqdsa_key = key;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_pqdsa_set_params(
    mut ctx: *mut EVP_PKEY_CTX,
    mut nid: libc::c_int,
) -> libc::c_int {
    if ctx.is_null() || ((*ctx).data).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            242 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if !((*ctx).pkey).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            114 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            249 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut pqdsa: *const PQDSA = PQDSA_find_dsa_by_nid(nid);
    if pqdsa.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            128 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            255 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut dctx: *mut PQDSA_PKEY_CTX = (*ctx).data as *mut PQDSA_PKEY_CTX;
    (*dctx).pqdsa = pqdsa;
    return 1 as libc::c_int;
}
unsafe extern "C" fn EVP_PKEY_pqdsa_new(mut nid: libc::c_int) -> *mut EVP_PKEY {
    let mut ret: *mut EVP_PKEY = EVP_PKEY_new();
    if ret.is_null() || EVP_PKEY_pqdsa_set_params(ret, nid) == 0 {
        EVP_PKEY_free(ret);
        return 0 as *mut EVP_PKEY;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_pqdsa_new_raw_public_key(
    mut nid: libc::c_int,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> *mut EVP_PKEY {
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if in_0.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            279 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EVP_PKEY;
    }
    let mut ret: *mut EVP_PKEY = EVP_PKEY_pqdsa_new(nid);
    if !(ret.is_null() || ((*ret).pkey.pqdsa_key).is_null()) {
        cbs = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        CBS_init(&mut cbs, in_0, len);
        if !(PQDSA_KEY_set_raw_public_key((*ret).pkey.pqdsa_key, &mut cbs) == 0) {
            return ret;
        }
    }
    EVP_PKEY_free(ret);
    return 0 as *mut EVP_PKEY;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_pqdsa_new_raw_private_key(
    mut nid: libc::c_int,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> *mut EVP_PKEY {
    let mut pqdsa: *const PQDSA = 0 as *const PQDSA;
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut current_block: u64;
    if in_0.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            305 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EVP_PKEY;
    }
    let mut ret: *mut EVP_PKEY = EVP_PKEY_pqdsa_new(nid);
    if !(ret.is_null() || ((*ret).pkey.pqdsa_key).is_null()) {
        pqdsa = PQDSA_KEY_get0_dsa((*ret).pkey.pqdsa_key);
        if len != (*pqdsa).private_key_len && len != (*pqdsa).keygen_seed_len {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                137 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_pqdsa.c\0"
                    as *const u8 as *const libc::c_char,
                318 as libc::c_int as libc::c_uint,
            );
        } else {
            cbs = cbs_st {
                data: 0 as *const uint8_t,
                len: 0,
            };
            CBS_init(&mut cbs, in_0, len);
            if len == (*pqdsa).private_key_len {
                if PQDSA_KEY_set_raw_private_key((*ret).pkey.pqdsa_key, &mut cbs) == 0 {
                    current_block = 4258687016233775120;
                } else {
                    current_block = 12800627514080957624;
                }
            } else if len == (*pqdsa).keygen_seed_len {
                if PQDSA_KEY_set_raw_keypair_from_seed((*ret).pkey.pqdsa_key, &mut cbs)
                    == 0
                {
                    current_block = 4258687016233775120;
                } else {
                    current_block = 12800627514080957624;
                }
            } else {
                current_block = 12800627514080957624;
            }
            match current_block {
                4258687016233775120 => {}
                _ => return ret,
            }
        }
    }
    EVP_PKEY_free(ret);
    return 0 as *mut EVP_PKEY;
}
static mut EVP_PKEY_pqdsa_pkey_meth_once: CRYPTO_once_t = 0 as libc::c_int;
static mut EVP_PKEY_pqdsa_pkey_meth_storage: EVP_PKEY_METHOD = evp_pkey_method_st {
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
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_pqdsa_pkey_meth() -> *const EVP_PKEY_METHOD {
    CRYPTO_once(
        EVP_PKEY_pqdsa_pkey_meth_once_bss_get(),
        Some(EVP_PKEY_pqdsa_pkey_meth_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_PKEY_pqdsa_pkey_meth_storage_bss_get() as *const EVP_PKEY_METHOD;
}
unsafe extern "C" fn EVP_PKEY_pqdsa_pkey_meth_do_init(mut out: *mut EVP_PKEY_METHOD) {
    (*out).pkey_id = 993 as libc::c_int;
    (*out)
        .init = Some(
        pkey_pqdsa_init as unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> libc::c_int,
    );
    (*out).copy = None;
    (*out)
        .cleanup = Some(
        pkey_pqdsa_cleanup as unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> (),
    );
    (*out)
        .keygen = Some(
        pkey_pqdsa_keygen
            as unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY) -> libc::c_int,
    );
    (*out).sign_init = None;
    (*out)
        .sign = Some(
        pkey_pqdsa_sign
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .sign_message = Some(
        pkey_pqdsa_sign_message
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out).verify_init = None;
    (*out)
        .verify = Some(
        pkey_pqdsa_verify
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *const uint8_t,
                size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .verify_message = Some(
        pkey_pqdsa_verify_message
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *const uint8_t,
                size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out).verify_recover = None;
    (*out).encrypt = None;
    (*out).decrypt = None;
    (*out).derive = None;
    (*out).paramgen = None;
    (*out).ctrl = None;
    (*out).ctrl_str = None;
    (*out).keygen_deterministic = None;
    (*out).encapsulate_deterministic = None;
    (*out).encapsulate = None;
    (*out).decapsulate = None;
}
unsafe extern "C" fn EVP_PKEY_pqdsa_pkey_meth_init() {
    EVP_PKEY_pqdsa_pkey_meth_do_init(EVP_PKEY_pqdsa_pkey_meth_storage_bss_get());
}
unsafe extern "C" fn EVP_PKEY_pqdsa_pkey_meth_storage_bss_get() -> *mut EVP_PKEY_METHOD {
    return &mut EVP_PKEY_pqdsa_pkey_meth_storage;
}
unsafe extern "C" fn EVP_PKEY_pqdsa_pkey_meth_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_PKEY_pqdsa_pkey_meth_once;
}
