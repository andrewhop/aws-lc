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
    pub type rsa_st;
    fn KEM_KEY_free(key: *mut KEM_KEY);
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
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> libc::c_int;
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
#[inline]
unsafe extern "C" fn OPENSSL_memcmp(
    mut s1: *const libc::c_void,
    mut s2: *const libc::c_void,
    mut n: size_t,
) -> libc::c_int {
    if n == 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    return memcmp(s1, s2, n);
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
unsafe extern "C" fn kem_free(mut pkey: *mut EVP_PKEY) {
    KEM_KEY_free((*pkey).pkey.kem_key);
    (*pkey).pkey.kem_key = 0 as *mut KEM_KEY;
}
unsafe extern "C" fn kem_get_priv_raw(
    mut pkey: *const EVP_PKEY,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
) -> libc::c_int {
    if ((*pkey).pkey.kem_key).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            124 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_kem_asn1.c\0"
                as *const u8 as *const libc::c_char,
            21 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut key: *mut KEM_KEY = (*pkey).pkey.kem_key;
    let mut kem: *const KEM = (*key).kem;
    if kem.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            124 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_kem_asn1.c\0"
                as *const u8 as *const libc::c_char,
            28 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if out.is_null() {
        *out_len = (*kem).secret_key_len;
        return 1 as libc::c_int;
    }
    if *out_len < (*kem).secret_key_len {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_kem_asn1.c\0"
                as *const u8 as *const libc::c_char,
            38 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*key).secret_key).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            120 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_kem_asn1.c\0"
                as *const u8 as *const libc::c_char,
            43 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    OPENSSL_memcpy(
        out as *mut libc::c_void,
        (*key).secret_key as *const libc::c_void,
        (*kem).secret_key_len,
    );
    *out_len = (*kem).secret_key_len;
    return 1 as libc::c_int;
}
unsafe extern "C" fn kem_get_pub_raw(
    mut pkey: *const EVP_PKEY,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
) -> libc::c_int {
    if ((*pkey).pkey.kem_key).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            124 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_kem_asn1.c\0"
                as *const u8 as *const libc::c_char,
            56 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut key: *mut KEM_KEY = (*pkey).pkey.kem_key;
    let mut kem: *const KEM = (*key).kem;
    if kem.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            124 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_kem_asn1.c\0"
                as *const u8 as *const libc::c_char,
            63 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if out.is_null() {
        *out_len = (*kem).public_key_len;
        return 1 as libc::c_int;
    }
    if *out_len < (*kem).public_key_len {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_kem_asn1.c\0"
                as *const u8 as *const libc::c_char,
            73 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*key).public_key).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            120 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_kem_asn1.c\0"
                as *const u8 as *const libc::c_char,
            78 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    OPENSSL_memcpy(
        out as *mut libc::c_void,
        (*key).public_key as *const libc::c_void,
        (*kem).public_key_len,
    );
    *out_len = (*kem).public_key_len;
    return 1 as libc::c_int;
}
unsafe extern "C" fn kem_cmp_parameters(
    mut a: *const EVP_PKEY,
    mut b: *const EVP_PKEY,
) -> libc::c_int {
    let mut a_key: *const KEM_KEY = (*a).pkey.kem_key;
    let mut b_key: *const KEM_KEY = (*b).pkey.kem_key;
    if a_key.is_null() || b_key.is_null() {
        return -(2 as libc::c_int);
    }
    let mut a_kem: *const KEM = (*a_key).kem;
    let mut b_kem: *const KEM = (*b_key).kem;
    if a_kem.is_null() || b_kem.is_null() {
        return -(2 as libc::c_int);
    }
    return ((*a_kem).nid == (*b_kem).nid) as libc::c_int;
}
unsafe extern "C" fn kem_pub_cmp(
    mut a: *const EVP_PKEY,
    mut b: *const EVP_PKEY,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    ret = kem_cmp_parameters(a, b);
    if ret <= 0 as libc::c_int {
        return ret;
    }
    let mut a_key: *const KEM_KEY = (*a).pkey.kem_key;
    let mut b_key: *const KEM_KEY = (*b).pkey.kem_key;
    return (OPENSSL_memcmp(
        (*a_key).public_key as *const libc::c_void,
        (*b_key).public_key as *const libc::c_void,
        (*(*a_key).kem).public_key_len,
    ) == 0 as libc::c_int) as libc::c_int;
}
#[unsafe(no_mangle)]
pub static mut kem_asn1_meth: EVP_PKEY_ASN1_METHOD = unsafe {
    {
        let mut init = evp_pkey_asn1_method_st {
            pkey_id: 970 as libc::c_int,
            oid: [
                0xff as libc::c_int as uint8_t,
                0xff as libc::c_int as uint8_t,
                0xff as libc::c_int as uint8_t,
                0xff as libc::c_int as uint8_t,
                0xff as libc::c_int as uint8_t,
                0xff as libc::c_int as uint8_t,
                0xff as libc::c_int as uint8_t,
                0xff as libc::c_int as uint8_t,
                0xff as libc::c_int as uint8_t,
                0xff as libc::c_int as uint8_t,
                0xff as libc::c_int as uint8_t,
            ],
            oid_len: 11 as libc::c_int as uint8_t,
            pem_str: b"KEM\0" as *const u8 as *const libc::c_char,
            info: b"AWS-LC KEM method\0" as *const u8 as *const libc::c_char,
            pub_decode: None,
            pub_encode: None,
            pub_cmp: Some(
                kem_pub_cmp
                    as unsafe extern "C" fn(
                        *const EVP_PKEY,
                        *const EVP_PKEY,
                    ) -> libc::c_int,
            ),
            priv_decode: None,
            priv_encode: None,
            priv_encode_v2: None,
            set_priv_raw: None,
            set_pub_raw: None,
            get_priv_raw: Some(
                kem_get_priv_raw
                    as unsafe extern "C" fn(
                        *const EVP_PKEY,
                        *mut uint8_t,
                        *mut size_t,
                    ) -> libc::c_int,
            ),
            get_pub_raw: Some(
                kem_get_pub_raw
                    as unsafe extern "C" fn(
                        *const EVP_PKEY,
                        *mut uint8_t,
                        *mut size_t,
                    ) -> libc::c_int,
            ),
            pkey_opaque: None,
            pkey_size: None,
            pkey_bits: None,
            param_missing: None,
            param_copy: None,
            param_cmp: Some(
                kem_cmp_parameters
                    as unsafe extern "C" fn(
                        *const EVP_PKEY,
                        *const EVP_PKEY,
                    ) -> libc::c_int,
            ),
            pkey_free: Some(kem_free as unsafe extern "C" fn(*mut EVP_PKEY) -> ()),
        };
        init
    }
};
