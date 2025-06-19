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
    pub type rsa_st;
    fn pkey_hkdf_derive(
        ctx: *mut EVP_PKEY_CTX,
        out: *mut uint8_t,
        out_len: *mut size_t,
    ) -> libc::c_int;
    fn KEM_find_kem_by_nid(nid: libc::c_int) -> *const KEM;
    fn KEM_KEY_new() -> *mut KEM_KEY;
    fn KEM_KEY_init(key: *mut KEM_KEY, kem: *const KEM) -> libc::c_int;
    fn KEM_KEY_free(key: *mut KEM_KEY);
    fn KEM_KEY_get0_kem(key: *mut KEM_KEY) -> *const KEM;
    fn KEM_KEY_set_raw_public_key(
        key: *mut KEM_KEY,
        in_0: *const uint8_t,
    ) -> libc::c_int;
    fn KEM_KEY_set_raw_secret_key(
        key: *mut KEM_KEY,
        in_0: *const uint8_t,
    ) -> libc::c_int;
    fn KEM_KEY_set_raw_key(
        key: *mut KEM_KEY,
        in_public: *const uint8_t,
        in_secret: *const uint8_t,
    ) -> libc::c_int;
    fn EVP_PKEY_new() -> *mut EVP_PKEY;
    fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
    fn EVP_PKEY_set_type(pkey: *mut EVP_PKEY, type_0: libc::c_int) -> libc::c_int;
    fn EVP_PKEY_CTX_new(pkey: *mut EVP_PKEY, e: *mut ENGINE) -> *mut EVP_PKEY_CTX;
    fn EVP_PKEY_CTX_free(ctx: *mut EVP_PKEY_CTX);
    fn EVP_PKEY_encapsulate(
        ctx: *mut EVP_PKEY_CTX,
        ciphertext: *mut uint8_t,
        ciphertext_len: *mut size_t,
        shared_secret: *mut uint8_t,
        shared_secret_len: *mut size_t,
    ) -> libc::c_int;
    fn EVP_PKEY_decapsulate(
        ctx: *mut EVP_PKEY_CTX,
        shared_secret: *mut uint8_t,
        shared_secret_len: *mut size_t,
        ciphertext: *const uint8_t,
        ciphertext_len: size_t,
    ) -> libc::c_int;
    fn EVP_PKEY_assign(
        pkey: *mut EVP_PKEY,
        type_0: libc::c_int,
        key: *mut libc::c_void,
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
    fn CRYPTO_once(
        once: *mut CRYPTO_once_t,
        init: Option::<unsafe extern "C" fn() -> ()>,
    );
    static kem_asn1_meth: EVP_PKEY_ASN1_METHOD;
    fn evp_pkey_set_method(pkey: *mut EVP_PKEY, method: *const EVP_PKEY_ASN1_METHOD);
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct kem_key_st {
    pub kem: *const KEM,
    pub public_key: *mut uint8_t,
    pub secret_key: *mut uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct KEM {
    pub nid: libc::c_int,
    pub oid: *const uint8_t,
    pub oid_len: uint8_t,
    pub comment: *const libc::c_char,
    pub public_key_len: size_t,
    pub secret_key_len: size_t,
    pub ciphertext_len: size_t,
    pub shared_secret_len: size_t,
    pub keygen_seed_len: size_t,
    pub encaps_seed_len: size_t,
    pub method: *const KEM_METHOD,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct KEM_METHOD {
    pub keygen_deterministic: Option::<
        unsafe extern "C" fn(
            *mut uint8_t,
            *mut size_t,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
        ) -> libc::c_int,
    >,
    pub keygen: Option::<
        unsafe extern "C" fn(
            *mut uint8_t,
            *mut size_t,
            *mut uint8_t,
            *mut size_t,
        ) -> libc::c_int,
    >,
    pub encaps_deterministic: Option::<
        unsafe extern "C" fn(
            *mut uint8_t,
            *mut size_t,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            *const uint8_t,
        ) -> libc::c_int,
    >,
    pub encaps: Option::<
        unsafe extern "C" fn(
            *mut uint8_t,
            *mut size_t,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
        ) -> libc::c_int,
    >,
    pub decaps: Option::<
        unsafe extern "C" fn(
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            *const uint8_t,
        ) -> libc::c_int,
    >,
}
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
pub struct KEM_PKEY_CTX {
    pub kem: *const KEM,
}
pub type crypto_word_t = uint64_t;
pub type CRYPTO_once_t = pthread_once_t;
#[inline]
unsafe extern "C" fn constant_time_msb_w(mut a: crypto_word_t) -> crypto_word_t {
    return (0 as libc::c_uint as crypto_word_t)
        .wrapping_sub(
            a
                >> (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        );
}
#[inline]
unsafe extern "C" fn constant_time_is_zero_w(mut a: crypto_word_t) -> crypto_word_t {
    return constant_time_msb_w(!a & a.wrapping_sub(1 as libc::c_int as crypto_word_t));
}
#[inline]
unsafe extern "C" fn constant_time_is_zero_8(mut a: crypto_word_t) -> uint8_t {
    return constant_time_is_zero_w(a) as uint8_t;
}
unsafe extern "C" fn pkey_kem_init(mut ctx: *mut EVP_PKEY_CTX) -> libc::c_int {
    let mut dctx: *mut KEM_PKEY_CTX = 0 as *mut KEM_PKEY_CTX;
    dctx = OPENSSL_zalloc(::core::mem::size_of::<KEM_PKEY_CTX>() as libc::c_ulong)
        as *mut KEM_PKEY_CTX;
    if dctx.is_null() {
        return 0 as libc::c_int;
    }
    (*ctx).data = dctx as *mut libc::c_void;
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_kem_cleanup(mut ctx: *mut EVP_PKEY_CTX) {
    OPENSSL_free((*ctx).data);
}
unsafe extern "C" fn pkey_kem_keygen_deterministic(
    mut ctx: *mut EVP_PKEY_CTX,
    mut pkey: *mut EVP_PKEY,
    mut seed: *const uint8_t,
    mut seed_len: *mut size_t,
) -> libc::c_int {
    if ctx.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            40 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut dctx: *mut KEM_PKEY_CTX = (*ctx).data as *mut KEM_PKEY_CTX;
    if dctx.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            42 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut kem: *const KEM = (*dctx).kem;
    if kem.is_null() {
        if ((*ctx).pkey).is_null() {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                124 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                    as *const u8 as *const libc::c_char,
                46 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        kem = KEM_KEY_get0_kem((*(*ctx).pkey).pkey.kem_key);
    }
    if seed_len.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            54 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if seed.is_null() {
        *seed_len = (*kem).keygen_seed_len;
        return 1 as libc::c_int;
    }
    if *seed_len != (*kem).keygen_seed_len {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            133 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            66 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut key: *mut KEM_KEY = KEM_KEY_new();
    let mut pubkey_len: size_t = (*kem).public_key_len;
    let mut secret_len: size_t = (*kem).secret_key_len;
    if key.is_null() || KEM_KEY_init(key, kem) == 0
        || ((*(*kem).method).keygen_deterministic)
            .expect(
                "non-null function pointer",
            )(
            (*key).public_key,
            &mut pubkey_len,
            (*key).secret_key,
            &mut secret_len,
            seed,
        ) == 0
        || EVP_PKEY_assign(pkey, 970 as libc::c_int, key as *mut libc::c_void) == 0
    {
        KEM_KEY_free(key);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_kem_keygen(
    mut ctx: *mut EVP_PKEY_CTX,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    if ctx.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            85 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut dctx: *mut KEM_PKEY_CTX = (*ctx).data as *mut KEM_PKEY_CTX;
    if dctx.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            87 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut kem: *const KEM = (*dctx).kem;
    if kem.is_null() {
        if ((*ctx).pkey).is_null() {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                124 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                    as *const u8 as *const libc::c_char,
                91 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        kem = KEM_KEY_get0_kem((*(*ctx).pkey).pkey.kem_key);
    }
    let mut key: *mut KEM_KEY = KEM_KEY_new();
    let mut pubkey_len: size_t = (*kem).public_key_len;
    let mut secret_len: size_t = (*kem).secret_key_len;
    if key.is_null() || KEM_KEY_init(key, kem) == 0
        || ((*(*kem).method).keygen)
            .expect(
                "non-null function pointer",
            )((*key).public_key, &mut pubkey_len, (*key).secret_key, &mut secret_len)
            == 0 || EVP_PKEY_set_type(pkey, 970 as libc::c_int) == 0
    {
        KEM_KEY_free(key);
        return 0 as libc::c_int;
    }
    (*pkey).pkey.kem_key = key;
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_kem_encapsulate_deterministic(
    mut ctx: *mut EVP_PKEY_CTX,
    mut ciphertext: *mut uint8_t,
    mut ciphertext_len: *mut size_t,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut seed: *const uint8_t,
    mut seed_len: *mut size_t,
) -> libc::c_int {
    if ctx.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            119 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut dctx: *mut KEM_PKEY_CTX = (*ctx).data as *mut KEM_PKEY_CTX;
    if dctx.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            121 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut kem: *const KEM = (*dctx).kem;
    if kem.is_null() {
        if ((*ctx).pkey).is_null() {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                124 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                    as *const u8 as *const libc::c_char,
                125 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        kem = KEM_KEY_get0_kem((*(*ctx).pkey).pkey.kem_key);
    }
    if ciphertext_len.is_null() || shared_secret_len.is_null() || seed_len.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            133 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ciphertext.is_null() && shared_secret.is_null() && seed.is_null() {
        *ciphertext_len = (*kem).ciphertext_len;
        *shared_secret_len = (*kem).shared_secret_len;
        *seed_len = (*kem).encaps_seed_len;
        return 1 as libc::c_int;
    }
    if ciphertext.is_null() || shared_secret.is_null() || seed.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            118 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            148 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if *ciphertext_len < (*kem).ciphertext_len
        || *shared_secret_len < (*kem).shared_secret_len
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            155 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if *seed_len != (*kem).encaps_seed_len {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            133 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            161 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*ctx).pkey).is_null() || ((*(*ctx).pkey).pkey.kem_key).is_null()
        || (*(*ctx).pkey).type_0 != 970 as libc::c_int
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            126 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            169 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut key: *mut KEM_KEY = (*(*ctx).pkey).pkey.kem_key;
    if ((*key).public_key).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            120 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            176 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*(*kem).method).encaps_deterministic)
        .expect(
            "non-null function pointer",
        )(
        ciphertext,
        ciphertext_len,
        shared_secret,
        shared_secret_len,
        (*key).public_key,
        seed,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    *ciphertext_len = (*kem).ciphertext_len;
    *shared_secret_len = (*kem).shared_secret_len;
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_kem_encapsulate(
    mut ctx: *mut EVP_PKEY_CTX,
    mut ciphertext: *mut uint8_t,
    mut ciphertext_len: *mut size_t,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
) -> libc::c_int {
    let mut dctx: *mut KEM_PKEY_CTX = (*ctx).data as *mut KEM_PKEY_CTX;
    let mut kem: *const KEM = (*dctx).kem;
    if kem.is_null() {
        if ((*ctx).pkey).is_null() {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                124 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                    as *const u8 as *const libc::c_char,
                201 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        kem = KEM_KEY_get0_kem((*(*ctx).pkey).pkey.kem_key);
    }
    if ciphertext.is_null() && shared_secret.is_null() {
        *ciphertext_len = (*kem).ciphertext_len;
        *shared_secret_len = (*kem).shared_secret_len;
        return 1 as libc::c_int;
    }
    if ciphertext.is_null() || shared_secret.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            118 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            217 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if *ciphertext_len < (*kem).ciphertext_len
        || *shared_secret_len < (*kem).shared_secret_len
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            224 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*ctx).pkey).is_null() || ((*(*ctx).pkey).pkey.kem_key).is_null()
        || (*(*ctx).pkey).type_0 != 970 as libc::c_int
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            126 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            232 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut key: *mut KEM_KEY = (*(*ctx).pkey).pkey.kem_key;
    if ((*key).public_key).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            120 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            239 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*(*kem).method).encaps)
        .expect(
            "non-null function pointer",
        )(
        ciphertext,
        ciphertext_len,
        shared_secret,
        shared_secret_len,
        (*key).public_key,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    *ciphertext_len = (*kem).ciphertext_len;
    *shared_secret_len = (*kem).shared_secret_len;
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_kem_decapsulate(
    mut ctx: *mut EVP_PKEY_CTX,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut ciphertext: *const uint8_t,
    mut ciphertext_len: size_t,
) -> libc::c_int {
    let mut dctx: *mut KEM_PKEY_CTX = (*ctx).data as *mut KEM_PKEY_CTX;
    let mut kem: *const KEM = (*dctx).kem;
    if kem.is_null() {
        if ((*ctx).pkey).is_null() {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                124 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                    as *const u8 as *const libc::c_char,
                264 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        kem = KEM_KEY_get0_kem((*(*ctx).pkey).pkey.kem_key);
    }
    if shared_secret.is_null() {
        *shared_secret_len = (*kem).shared_secret_len;
        return 1 as libc::c_int;
    }
    if ciphertext_len != (*kem).ciphertext_len
        || *shared_secret_len < (*kem).shared_secret_len
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            137 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            279 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*ctx).pkey).is_null() || ((*(*ctx).pkey).pkey.kem_key).is_null()
        || (*(*ctx).pkey).type_0 != 970 as libc::c_int
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            126 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            287 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut key: *mut KEM_KEY = (*(*ctx).pkey).pkey.kem_key;
    if ((*key).secret_key).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            120 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            294 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*(*kem).method).decaps)
        .expect(
            "non-null function pointer",
        )(shared_secret, shared_secret_len, ciphertext, (*key).secret_key) == 0
    {
        return 0 as libc::c_int;
    }
    *shared_secret_len = (*kem).shared_secret_len;
    return 1 as libc::c_int;
}
unsafe extern "C" fn EVP_PKEY_kem_pkey_meth_do_init(mut out: *mut EVP_PKEY_METHOD) {
    (*out).pkey_id = 970 as libc::c_int;
    (*out)
        .init = Some(
        pkey_kem_init as unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> libc::c_int,
    );
    (*out).copy = None;
    (*out)
        .cleanup = Some(
        pkey_kem_cleanup as unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> (),
    );
    (*out)
        .keygen = Some(
        pkey_kem_keygen
            as unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY) -> libc::c_int,
    );
    (*out).sign_init = None;
    (*out).sign = None;
    (*out).sign_message = None;
    (*out).verify_init = None;
    (*out).verify = None;
    (*out).verify_message = None;
    (*out).verify_recover = None;
    (*out).encrypt = None;
    (*out).decrypt = None;
    (*out)
        .derive = Some(
        pkey_hkdf_derive
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *mut uint8_t,
                *mut size_t,
            ) -> libc::c_int,
    );
    (*out).paramgen = None;
    (*out).ctrl = None;
    (*out).ctrl_str = None;
    (*out)
        .keygen_deterministic = Some(
        pkey_kem_keygen_deterministic
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *mut EVP_PKEY,
                *const uint8_t,
                *mut size_t,
            ) -> libc::c_int,
    );
    (*out)
        .encapsulate_deterministic = Some(
        pkey_kem_encapsulate_deterministic
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *mut uint8_t,
                *mut size_t,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
                *mut size_t,
            ) -> libc::c_int,
    );
    (*out)
        .encapsulate = Some(
        pkey_kem_encapsulate
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *mut uint8_t,
                *mut size_t,
                *mut uint8_t,
                *mut size_t,
            ) -> libc::c_int,
    );
    (*out)
        .decapsulate = Some(
        pkey_kem_decapsulate
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
}
unsafe extern "C" fn EVP_PKEY_kem_pkey_meth_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_PKEY_kem_pkey_meth_once;
}
static mut EVP_PKEY_kem_pkey_meth_once: CRYPTO_once_t = 0 as libc::c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_PKEY_kem_pkey_meth() -> *const EVP_PKEY_METHOD {
    CRYPTO_once(
        EVP_PKEY_kem_pkey_meth_once_bss_get(),
        Some(EVP_PKEY_kem_pkey_meth_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_PKEY_kem_pkey_meth_storage_bss_get() as *const EVP_PKEY_METHOD;
}
unsafe extern "C" fn EVP_PKEY_kem_pkey_meth_init() {
    EVP_PKEY_kem_pkey_meth_do_init(EVP_PKEY_kem_pkey_meth_storage_bss_get());
}
static mut EVP_PKEY_kem_pkey_meth_storage: EVP_PKEY_METHOD = evp_pkey_method_st {
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
unsafe extern "C" fn EVP_PKEY_kem_pkey_meth_storage_bss_get() -> *mut EVP_PKEY_METHOD {
    return &mut EVP_PKEY_kem_pkey_meth_storage;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_PKEY_CTX_kem_set_params(
    mut ctx: *mut EVP_PKEY_CTX,
    mut nid: libc::c_int,
) -> libc::c_int {
    if ctx.is_null() || ((*ctx).data).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            337 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if !((*ctx).pkey).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            114 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            344 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut kem: *const KEM = KEM_find_kem_by_nid(nid);
    if kem.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            128 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            350 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut dctx: *mut KEM_PKEY_CTX = (*ctx).data as *mut KEM_PKEY_CTX;
    (*dctx).kem = kem;
    return 1 as libc::c_int;
}
unsafe extern "C" fn EVP_PKEY_kem_set_params(
    mut pkey: *mut EVP_PKEY,
    mut nid: libc::c_int,
) -> libc::c_int {
    let mut kem: *const KEM = KEM_find_kem_by_nid(nid);
    if kem.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            128 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            365 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    evp_pkey_set_method(pkey, &kem_asn1_meth);
    let mut key: *mut KEM_KEY = KEM_KEY_new();
    if key.is_null() {
        return 0 as libc::c_int;
    }
    (*key).kem = kem;
    (*pkey).pkey.kem_key = key;
    return 1 as libc::c_int;
}
unsafe extern "C" fn EVP_PKEY_kem_new(mut nid: libc::c_int) -> *mut EVP_PKEY {
    let mut ret: *mut EVP_PKEY = EVP_PKEY_new();
    if ret.is_null() || EVP_PKEY_kem_set_params(ret, nid) == 0 {
        EVP_PKEY_free(ret);
        return 0 as *mut EVP_PKEY;
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_PKEY_kem_new_raw_public_key(
    mut nid: libc::c_int,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> *mut EVP_PKEY {
    let mut kem: *const KEM = 0 as *const KEM;
    if in_0.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            397 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EVP_PKEY;
    }
    let mut ret: *mut EVP_PKEY = EVP_PKEY_kem_new(nid);
    if !(ret.is_null() || ((*ret).pkey.kem_key).is_null()) {
        kem = KEM_KEY_get0_kem((*ret).pkey.kem_key);
        if (*kem).public_key_len != len {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                137 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                    as *const u8 as *const libc::c_char,
                409 as libc::c_int as libc::c_uint,
            );
        } else if !(KEM_KEY_set_raw_public_key((*ret).pkey.kem_key, in_0) == 0) {
            return ret
        }
    }
    EVP_PKEY_free(ret);
    return 0 as *mut EVP_PKEY;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_PKEY_kem_new_raw_secret_key(
    mut nid: libc::c_int,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> *mut EVP_PKEY {
    let mut kem: *const KEM = 0 as *const KEM;
    if in_0.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            427 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EVP_PKEY;
    }
    let mut ret: *mut EVP_PKEY = EVP_PKEY_kem_new(nid);
    if !(ret.is_null() || ((*ret).pkey.kem_key).is_null()) {
        kem = KEM_KEY_get0_kem((*ret).pkey.kem_key);
        if (*kem).secret_key_len != len {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                137 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                    as *const u8 as *const libc::c_char,
                439 as libc::c_int as libc::c_uint,
            );
        } else if !(KEM_KEY_set_raw_secret_key((*ret).pkey.kem_key, in_0) == 0) {
            return ret
        }
    }
    EVP_PKEY_free(ret);
    return 0 as *mut EVP_PKEY;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_PKEY_kem_new_raw_key(
    mut nid: libc::c_int,
    mut in_public: *const uint8_t,
    mut len_public: size_t,
    mut in_secret: *const uint8_t,
    mut len_secret: size_t,
) -> *mut EVP_PKEY {
    let mut kem: *const KEM = 0 as *const KEM;
    if in_public.is_null() || in_secret.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            459 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EVP_PKEY;
    }
    let mut ret: *mut EVP_PKEY = EVP_PKEY_kem_new(nid);
    if !(ret.is_null() || ((*ret).pkey.kem_key).is_null()) {
        kem = KEM_KEY_get0_kem((*ret).pkey.kem_key);
        if (*kem).public_key_len != len_public || (*kem).secret_key_len != len_secret {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                137 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                    as *const u8 as *const libc::c_char,
                471 as libc::c_int as libc::c_uint,
            );
        } else if !(KEM_KEY_set_raw_key((*ret).pkey.kem_key, in_public, in_secret) == 0)
        {
            return ret
        }
    }
    EVP_PKEY_free(ret);
    return 0 as *mut EVP_PKEY;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_PKEY_kem_check_key(mut key: *mut EVP_PKEY) -> libc::c_int {
    let mut res: uint8_t = 0;
    if key.is_null() || ((*key).pkey.kem_key).is_null()
        || ((*(*key).pkey.kem_key).public_key).is_null()
        || ((*(*key).pkey.kem_key).secret_key).is_null()
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            494 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ctx: *mut EVP_PKEY_CTX = EVP_PKEY_CTX_new(key, 0 as *mut ENGINE);
    if ctx.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            4 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            500 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut ct_len: size_t = 0;
    let mut ss_len: size_t = 0;
    let mut ct: *mut uint8_t = 0 as *mut uint8_t;
    let mut ss_a: *mut uint8_t = 0 as *mut uint8_t;
    let mut ss_b: *mut uint8_t = 0 as *mut uint8_t;
    if EVP_PKEY_encapsulate(
        ctx,
        0 as *mut uint8_t,
        &mut ct_len,
        0 as *mut uint8_t,
        &mut ss_len,
    ) == 0
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            4 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                as *const u8 as *const libc::c_char,
            510 as libc::c_int as libc::c_uint,
        );
    } else {
        ct = OPENSSL_malloc(ct_len) as *mut uint8_t;
        ss_a = OPENSSL_malloc(ss_len) as *mut uint8_t;
        ss_b = OPENSSL_malloc(ss_len) as *mut uint8_t;
        if ct.is_null() || ss_a.is_null() || ss_b.is_null() {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                4 as libc::c_int | 64 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                    as *const u8 as *const libc::c_char,
                517 as libc::c_int as libc::c_uint,
            );
        } else if EVP_PKEY_encapsulate(ctx, ct, &mut ct_len, ss_b, &mut ss_len) == 0
            || EVP_PKEY_decapsulate(ctx, ss_a, &mut ss_len, ct, ct_len) == 0
        {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                4 as libc::c_int | 64 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_kem.c\0"
                    as *const u8 as *const libc::c_char,
                524 as libc::c_int as libc::c_uint,
            );
        } else {
            res = 0 as libc::c_int as uint8_t;
            let mut i: size_t = 0 as libc::c_int as size_t;
            while i < ss_len {
                res = (res as libc::c_int
                    | *ss_a.offset(i as isize) as libc::c_int
                        ^ *ss_b.offset(i as isize) as libc::c_int) as uint8_t;
                i = i.wrapping_add(1);
                i;
            }
            ret = constant_time_is_zero_8(res as crypto_word_t) as libc::c_int
                & 1 as libc::c_int;
        }
    }
    OPENSSL_free(ct as *mut libc::c_void);
    OPENSSL_free(ss_a as *mut libc::c_void);
    OPENSSL_free(ss_b as *mut libc::c_void);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}
