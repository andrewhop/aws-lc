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
    pub type kem_key_st;
    pub type rsa_st;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_get_asn1(
        cbs: *mut CBS,
        out: *mut CBS,
        tag_value: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBS_peek_asn1_tag(cbs: *const CBS, tag_value: CBS_ASN1_TAG) -> libc::c_int;
    fn CBB_flush(cbb: *mut CBB) -> libc::c_int;
    fn CBB_add_asn1(
        cbb: *mut CBB,
        out_contents: *mut CBB,
        tag: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBB_add_bytes(cbb: *mut CBB, data: *const uint8_t, len: size_t) -> libc::c_int;
    fn CBB_add_u8(cbb: *mut CBB, value: uint8_t) -> libc::c_int;
    fn CBB_add_asn1_uint64(cbb: *mut CBB, value: uint64_t) -> libc::c_int;
    fn PQDSA_KEY_free(key: *mut PQDSA_KEY);
    fn EVP_PKEY_pqdsa_set_params(pkey: *mut EVP_PKEY, nid: libc::c_int) -> libc::c_int;
    fn PQDSA_KEY_set_raw_keypair_from_seed(
        key: *mut PQDSA_KEY,
        in_0: *mut CBS,
    ) -> libc::c_int;
    fn PQDSA_KEY_set_raw_keypair_from_both(
        key: *mut PQDSA_KEY,
        seed: *mut CBS,
        expanded_key: *mut CBS,
    ) -> libc::c_int;
    fn PQDSA_KEY_set_raw_public_key(key: *mut PQDSA_KEY, in_0: *mut CBS) -> libc::c_int;
    fn PQDSA_KEY_set_raw_private_key(key: *mut PQDSA_KEY, in_0: *mut CBS) -> libc::c_int;
    fn OBJ_cbs2nid(cbs: *const CBS) -> libc::c_int;
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
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type CBS_ASN1_TAG = uint32_t;
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
unsafe extern "C" fn pqdsa_free(mut pkey: *mut EVP_PKEY) {
    PQDSA_KEY_free((*pkey).pkey.pqdsa_key);
    (*pkey).pkey.pqdsa_key = 0 as *mut PQDSA_KEY;
}
unsafe extern "C" fn pqdsa_get_priv_raw(
    mut pkey: *const EVP_PKEY,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
) -> libc::c_int {
    if pkey.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            23 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if out_len.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            24 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*pkey).pkey.pqdsa_key).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            124 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            27 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut key: *mut PQDSA_KEY = (*pkey).pkey.pqdsa_key;
    let mut pqdsa: *const PQDSA = (*key).pqdsa;
    if ((*key).private_key).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            130 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            35 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if pqdsa.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            124 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            40 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if out.is_null() {
        *out_len = (*(*key).pqdsa).private_key_len;
        return 1 as libc::c_int;
    }
    if *out_len < (*(*key).pqdsa).private_key_len {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            50 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    OPENSSL_memcpy(
        out as *mut libc::c_void,
        (*key).private_key as *const libc::c_void,
        (*pqdsa).private_key_len,
    );
    *out_len = (*pqdsa).private_key_len;
    return 1 as libc::c_int;
}
unsafe extern "C" fn pqdsa_get_pub_raw(
    mut pkey: *const EVP_PKEY,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
) -> libc::c_int {
    if ((*pkey).pkey.pqdsa_key).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            124 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            62 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut key: *mut PQDSA_KEY = (*pkey).pkey.pqdsa_key;
    let mut pqdsa: *const PQDSA = (*key).pqdsa;
    if pqdsa.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            124 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            70 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*key).public_key).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            75 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if out.is_null() {
        *out_len = (*pqdsa).public_key_len;
        return 1 as libc::c_int;
    }
    if *out_len < (*(*key).pqdsa).public_key_len {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            85 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    OPENSSL_memcpy(
        out as *mut libc::c_void,
        (*key).public_key as *const libc::c_void,
        (*pqdsa).public_key_len,
    );
    *out_len = (*pqdsa).public_key_len;
    return 1 as libc::c_int;
}
unsafe extern "C" fn pqdsa_pub_decode(
    mut out: *mut EVP_PKEY,
    mut oid: *mut CBS,
    mut params: *mut CBS,
    mut key: *mut CBS,
) -> libc::c_int {
    if CBS_len(params) > 0 as libc::c_int as size_t {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            98 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if EVP_PKEY_pqdsa_set_params(out, OBJ_cbs2nid(oid)) == 0 {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            103 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return PQDSA_KEY_set_raw_public_key((*out).pkey.pqdsa_key, key);
}
unsafe extern "C" fn pqdsa_pub_encode(
    mut out: *mut CBB,
    mut pkey: *const EVP_PKEY,
) -> libc::c_int {
    let mut key: *mut PQDSA_KEY = (*pkey).pkey.pqdsa_key;
    let mut pqdsa: *const PQDSA = (*key).pqdsa;
    if ((*key).public_key).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            113 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut spki: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut algorithm: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut oid: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut key_bitstring: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    if CBB_add_asn1(
        out,
        &mut spki,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0
        || CBB_add_asn1(
            &mut spki,
            &mut algorithm,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0 || CBB_add_asn1(&mut algorithm, &mut oid, 0x6 as libc::c_uint) == 0
        || CBB_add_bytes(&mut oid, (*pqdsa).oid, (*pqdsa).oid_len as size_t) == 0
        || CBB_add_asn1(&mut spki, &mut key_bitstring, 0x3 as libc::c_uint) == 0
        || CBB_add_u8(&mut key_bitstring, 0 as libc::c_int as uint8_t) == 0
        || CBB_add_bytes(&mut key_bitstring, (*key).public_key, (*pqdsa).public_key_len)
            == 0 || CBB_flush(out) == 0
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            127 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn pqdsa_pub_cmp(
    mut a: *const EVP_PKEY,
    mut b: *const EVP_PKEY,
) -> libc::c_int {
    let mut a_key: *mut PQDSA_KEY = (*a).pkey.pqdsa_key;
    let mut b_key: *mut PQDSA_KEY = (*b).pkey.pqdsa_key;
    return (OPENSSL_memcmp(
        (*a_key).public_key as *const libc::c_void,
        (*b_key).public_key as *const libc::c_void,
        (*(*(*a).pkey.pqdsa_key).pqdsa).public_key_len,
    ) == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn pqdsa_priv_decode(
    mut out: *mut EVP_PKEY,
    mut oid: *mut CBS,
    mut params: *mut CBS,
    mut key: *mut CBS,
    mut pubkey: *mut CBS,
) -> libc::c_int {
    if CBS_len(params) > 0 as libc::c_int as size_t {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            147 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if EVP_PKEY_pqdsa_set_params(out, OBJ_cbs2nid(oid)) == 0 {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            153 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if CBS_peek_asn1_tag(
        key,
        (0x80 as libc::c_uint) << 24 as libc::c_int | 0 as libc::c_int as libc::c_uint,
    ) != 0
    {
        let mut seed: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        if CBS_get_asn1(
            key,
            &mut seed,
            (0x80 as libc::c_uint) << 24 as libc::c_int
                | 0 as libc::c_int as libc::c_uint,
        ) == 0
        {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                102 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                167 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        if CBS_len(&mut seed) != (*(*(*out).pkey.pqdsa_key).pqdsa).keygen_seed_len {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                137 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                172 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        return PQDSA_KEY_set_raw_keypair_from_seed((*out).pkey.pqdsa_key, &mut seed);
    } else if CBS_peek_asn1_tag(key, 0x4 as libc::c_uint) != 0 {
        let mut expanded_key: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        if CBS_get_asn1(key, &mut expanded_key, 0x4 as libc::c_uint) == 0 {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                102 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                181 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        if CBS_len(&mut expanded_key)
            != (*(*(*out).pkey.pqdsa_key).pqdsa).private_key_len
        {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                137 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                186 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        return PQDSA_KEY_set_raw_private_key((*out).pkey.pqdsa_key, &mut expanded_key);
    } else if CBS_peek_asn1_tag(
        key,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) != 0
    {
        let mut sequence: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        let mut seed_0: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        let mut expanded_key_0: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        if CBS_get_asn1(
            key,
            &mut sequence,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0 || CBS_get_asn1(&mut sequence, &mut seed_0, 0x4 as libc::c_uint) == 0
            || CBS_get_asn1(&mut sequence, &mut expanded_key_0, 0x4 as libc::c_uint) == 0
        {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                102 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                197 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        return PQDSA_KEY_set_raw_keypair_from_both(
            (*out).pkey.pqdsa_key,
            &mut seed_0,
            &mut expanded_key_0,
        );
    } else {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            203 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    };
}
unsafe extern "C" fn pqdsa_priv_encode(
    mut out: *mut CBB,
    mut pkey: *const EVP_PKEY,
) -> libc::c_int {
    let mut key: *mut PQDSA_KEY = (*pkey).pkey.pqdsa_key;
    let mut pqdsa: *const PQDSA = (*key).pqdsa;
    if ((*key).seed).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            130 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            212 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut pkcs8: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut algorithm: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut oid: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut private_key: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut seed_choice: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    if CBB_add_asn1(
        out,
        &mut pkcs8,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || CBB_add_asn1_uint64(&mut pkcs8, 0 as libc::c_int as uint64_t) == 0
        || CBB_add_asn1(
            &mut pkcs8,
            &mut algorithm,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0 || CBB_add_asn1(&mut algorithm, &mut oid, 0x6 as libc::c_uint) == 0
        || CBB_add_bytes(&mut oid, (*pqdsa).oid, (*pqdsa).oid_len as size_t) == 0
        || CBB_add_asn1(&mut pkcs8, &mut private_key, 0x4 as libc::c_uint) == 0
        || CBB_add_asn1(
            &mut private_key,
            &mut seed_choice,
            (0x80 as libc::c_uint) << 24 as libc::c_int
                | 0 as libc::c_int as libc::c_uint,
        ) == 0
        || CBB_add_bytes(&mut seed_choice, (*key).seed, (*pqdsa).keygen_seed_len) == 0
        || CBB_flush(out) == 0
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            226 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn pqdsa_size(mut pkey: *const EVP_PKEY) -> libc::c_int {
    if ((*pkey).pkey.pqdsa_key).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            124 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            235 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return (*(*(*pkey).pkey.pqdsa_key).pqdsa).signature_len as libc::c_int;
}
unsafe extern "C" fn pqdsa_bits(mut pkey: *const EVP_PKEY) -> libc::c_int {
    if ((*pkey).pkey.pqdsa_key).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            124 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            243 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return (8 as libc::c_int as size_t
        * (*(*(*pkey).pkey.pqdsa_key).pqdsa).public_key_len) as libc::c_int;
}
#[no_mangle]
pub static mut pqdsa_asn1_meth: EVP_PKEY_ASN1_METHOD = unsafe {
    {
        let mut init = evp_pkey_asn1_method_st {
            pkey_id: 993 as libc::c_int,
            oid: [
                0x60 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x65 as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0,
                0,
                0,
            ],
            oid_len: 8 as libc::c_int as uint8_t,
            pem_str: b"PQ DSA\0" as *const u8 as *const libc::c_char,
            info: b"AWS-LC PQ DSA method\0" as *const u8 as *const libc::c_char,
            pub_decode: Some(
                pqdsa_pub_decode
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY,
                        *mut CBS,
                        *mut CBS,
                        *mut CBS,
                    ) -> libc::c_int,
            ),
            pub_encode: Some(
                pqdsa_pub_encode
                    as unsafe extern "C" fn(*mut CBB, *const EVP_PKEY) -> libc::c_int,
            ),
            pub_cmp: Some(
                pqdsa_pub_cmp
                    as unsafe extern "C" fn(
                        *const EVP_PKEY,
                        *const EVP_PKEY,
                    ) -> libc::c_int,
            ),
            priv_decode: Some(
                pqdsa_priv_decode
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY,
                        *mut CBS,
                        *mut CBS,
                        *mut CBS,
                        *mut CBS,
                    ) -> libc::c_int,
            ),
            priv_encode: Some(
                pqdsa_priv_encode
                    as unsafe extern "C" fn(*mut CBB, *const EVP_PKEY) -> libc::c_int,
            ),
            priv_encode_v2: None,
            set_priv_raw: None,
            set_pub_raw: None,
            get_priv_raw: Some(
                pqdsa_get_priv_raw
                    as unsafe extern "C" fn(
                        *const EVP_PKEY,
                        *mut uint8_t,
                        *mut size_t,
                    ) -> libc::c_int,
            ),
            get_pub_raw: Some(
                pqdsa_get_pub_raw
                    as unsafe extern "C" fn(
                        *const EVP_PKEY,
                        *mut uint8_t,
                        *mut size_t,
                    ) -> libc::c_int,
            ),
            pkey_opaque: None,
            pkey_size: Some(
                pqdsa_size as unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int,
            ),
            pkey_bits: Some(
                pqdsa_bits as unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int,
            ),
            param_missing: None,
            param_copy: None,
            param_cmp: None,
            pkey_free: Some(pqdsa_free as unsafe extern "C" fn(*mut EVP_PKEY) -> ()),
        };
        init
    }
};
