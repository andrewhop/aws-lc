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
    pub type pqdsa_key_st;
    pub type kem_key_st;
    pub type rsa_st;
    fn HMAC_KEY_new() -> *mut HMAC_KEY;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_memdup(data: *const libc::c_void, size: size_t) -> *mut libc::c_void;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
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
unsafe extern "C" fn hmac_size(mut pkey: *const EVP_PKEY) -> libc::c_int {
    return 64 as libc::c_int;
}
unsafe extern "C" fn hmac_key_free(mut pkey: *mut EVP_PKEY) {
    let mut key: *mut HMAC_KEY = (*pkey).pkey.ptr as *mut HMAC_KEY;
    if !key.is_null() {
        OPENSSL_free((*key).key as *mut libc::c_void);
    }
    OPENSSL_free(key as *mut libc::c_void);
}
unsafe extern "C" fn hmac_set_key(
    mut pkey: *mut EVP_PKEY,
    mut priv_0: *const uint8_t,
    mut len: size_t,
    mut pubkey: *const uint8_t,
    mut pubkey_len: size_t,
) -> libc::c_int {
    if !((*pkey).pkey.ptr).is_null() {
        return 0 as libc::c_int;
    }
    let mut key: *mut HMAC_KEY = HMAC_KEY_new();
    if key.is_null() {
        return 0 as libc::c_int;
    }
    (*key).key = OPENSSL_memdup(priv_0 as *const libc::c_void, len) as *mut uint8_t;
    if ((*key).key).is_null() && len > 0 as libc::c_int as size_t {
        OPENSSL_free(key as *mut libc::c_void);
        return 0 as libc::c_int;
    }
    (*key).key_len = len;
    (*pkey).pkey.ptr = key as *mut libc::c_void;
    return 1 as libc::c_int;
}
unsafe extern "C" fn hmac_get_key(
    mut pkey: *const EVP_PKEY,
    mut priv_0: *mut uint8_t,
    mut len: *mut size_t,
) -> libc::c_int {
    let mut key: *mut HMAC_KEY = (*pkey).pkey.ptr as *mut HMAC_KEY;
    if key.is_null() || len.is_null() {
        return 0 as libc::c_int;
    }
    if priv_0.is_null() {
        *len = (*key).key_len;
        return 1 as libc::c_int;
    }
    if *len < (*key).key_len {
        return 0 as libc::c_int;
    }
    *len = (*key).key_len;
    OPENSSL_memcpy(
        priv_0 as *mut libc::c_void,
        (*key).key as *const libc::c_void,
        (*key).key_len,
    );
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub static mut hmac_asn1_meth: EVP_PKEY_ASN1_METHOD = unsafe {
    {
        let mut init = evp_pkey_asn1_method_st {
            pkey_id: 855 as libc::c_int,
            oid: [0xff as libc::c_int as uint8_t, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            oid_len: 0 as libc::c_int as uint8_t,
            pem_str: b"HMAC\0" as *const u8 as *const libc::c_char,
            info: b"OpenSSL HMAC method\0" as *const u8 as *const libc::c_char,
            pub_decode: None,
            pub_encode: None,
            pub_cmp: None,
            priv_decode: None,
            priv_encode: None,
            priv_encode_v2: None,
            set_priv_raw: Some(
                hmac_set_key
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY,
                        *const uint8_t,
                        size_t,
                        *const uint8_t,
                        size_t,
                    ) -> libc::c_int,
            ),
            set_pub_raw: None,
            get_priv_raw: Some(
                hmac_get_key
                    as unsafe extern "C" fn(
                        *const EVP_PKEY,
                        *mut uint8_t,
                        *mut size_t,
                    ) -> libc::c_int,
            ),
            get_pub_raw: None,
            pkey_opaque: None,
            pkey_size: Some(
                hmac_size as unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int,
            ),
            pkey_bits: None,
            param_missing: None,
            param_copy: None,
            param_cmp: None,
            pkey_free: Some(hmac_key_free as unsafe extern "C" fn(*mut EVP_PKEY) -> ()),
        };
        init
    }
};
