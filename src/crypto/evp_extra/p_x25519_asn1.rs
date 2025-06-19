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
    pub type pqdsa_key_st;
    pub type kem_key_st;
    pub type rsa_st;
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_get_u8(cbs: *mut CBS, out: *mut uint8_t) -> libc::c_int;
    fn CBS_get_asn1(
        cbs: *mut CBS,
        out: *mut CBS,
        tag_value: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBB_flush(cbb: *mut CBB) -> libc::c_int;
    fn CBB_add_asn1(
        cbb: *mut CBB,
        out_contents: *mut CBB,
        tag: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBB_add_bytes(cbb: *mut CBB, data: *const uint8_t, len: size_t) -> libc::c_int;
    fn CBB_add_u8(cbb: *mut CBB, value: uint8_t) -> libc::c_int;
    fn CBB_add_asn1_uint64(cbb: *mut CBB, value: uint64_t) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn X25519_public_from_private(
        out_public_value: *mut uint8_t,
        private_key: *const uint8_t,
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
pub type KEM_KEY = kem_key_st;
pub type RSA = rsa_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X25519_KEY {
    pub pub_0: [uint8_t; 32],
    pub priv_0: [uint8_t; 32],
    pub has_private: libc::c_char,
}
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
unsafe extern "C" fn x25519_free(mut pkey: *mut EVP_PKEY) {
    OPENSSL_free((*pkey).pkey.ptr);
    (*pkey).pkey.ptr = 0 as *mut libc::c_void;
}
unsafe extern "C" fn x25519_set_priv_raw(
    mut pkey: *mut EVP_PKEY,
    mut privkey: *const uint8_t,
    mut privkey_len: size_t,
    mut pubkey: *const uint8_t,
    mut pubkey_len: size_t,
) -> libc::c_int {
    if privkey_len != 32 as libc::c_int as size_t {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_x25519_asn1.c\0"
                as *const u8 as *const libc::c_char,
            34 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if !pubkey.is_null() && pubkey_len != 32 as libc::c_int as size_t {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_x25519_asn1.c\0"
                as *const u8 as *const libc::c_char,
            39 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut key: *mut X25519_KEY = OPENSSL_malloc(
        ::core::mem::size_of::<X25519_KEY>() as libc::c_ulong,
    ) as *mut X25519_KEY;
    if key.is_null() {
        return 0 as libc::c_int;
    }
    OPENSSL_memcpy(
        ((*key).priv_0).as_mut_ptr() as *mut libc::c_void,
        privkey as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
    X25519_public_from_private(
        ((*key).pub_0).as_mut_ptr(),
        ((*key).priv_0).as_mut_ptr() as *const uint8_t,
    );
    (*key).has_private = 1 as libc::c_int as libc::c_char;
    if !pubkey.is_null()
        && OPENSSL_memcmp(
            ((*key).pub_0).as_mut_ptr() as *const libc::c_void,
            pubkey as *const libc::c_void,
            pubkey_len,
        ) != 0 as libc::c_int
    {
        OPENSSL_free(key as *mut libc::c_void);
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_x25519_asn1.c\0"
                as *const u8 as *const libc::c_char,
            55 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    x25519_free(pkey);
    (*pkey).pkey.ptr = key as *mut libc::c_void;
    return 1 as libc::c_int;
}
unsafe extern "C" fn x25519_set_pub_raw(
    mut pkey: *mut EVP_PKEY,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    if len != 32 as libc::c_int as size_t {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_x25519_asn1.c\0"
                as *const u8 as *const libc::c_char,
            66 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut key: *mut X25519_KEY = OPENSSL_malloc(
        ::core::mem::size_of::<X25519_KEY>() as libc::c_ulong,
    ) as *mut X25519_KEY;
    if key.is_null() {
        return 0 as libc::c_int;
    }
    OPENSSL_memcpy(
        ((*key).pub_0).as_mut_ptr() as *mut libc::c_void,
        in_0 as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
    (*key).has_private = 0 as libc::c_int as libc::c_char;
    x25519_free(pkey);
    (*pkey).pkey.ptr = key as *mut libc::c_void;
    return 1 as libc::c_int;
}
unsafe extern "C" fn x25519_get_priv_raw(
    mut pkey: *const EVP_PKEY,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
) -> libc::c_int {
    let mut key: *const X25519_KEY = (*pkey).pkey.ptr as *const X25519_KEY;
    if (*key).has_private == 0 {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            130 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_x25519_asn1.c\0"
                as *const u8 as *const libc::c_char,
            87 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if out.is_null() {
        *out_len = 32 as libc::c_int as size_t;
        return 1 as libc::c_int;
    }
    if *out_len < 32 as libc::c_int as size_t {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_x25519_asn1.c\0"
                as *const u8 as *const libc::c_char,
            97 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    OPENSSL_memcpy(
        out as *mut libc::c_void,
        ((*key).priv_0).as_ptr() as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
    *out_len = 32 as libc::c_int as size_t;
    return 1 as libc::c_int;
}
unsafe extern "C" fn x25519_get_pub_raw(
    mut pkey: *const EVP_PKEY,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
) -> libc::c_int {
    let mut key: *const X25519_KEY = (*pkey).pkey.ptr as *const X25519_KEY;
    if out.is_null() {
        *out_len = 32 as libc::c_int as size_t;
        return 1 as libc::c_int;
    }
    if *out_len < 32 as libc::c_int as size_t {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_x25519_asn1.c\0"
                as *const u8 as *const libc::c_char,
            115 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    OPENSSL_memcpy(
        out as *mut libc::c_void,
        ((*key).pub_0).as_ptr() as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
    *out_len = 32 as libc::c_int as size_t;
    return 1 as libc::c_int;
}
unsafe extern "C" fn x25519_pub_decode(
    mut out: *mut EVP_PKEY,
    mut oid: *mut CBS,
    mut params: *mut CBS,
    mut key: *mut CBS,
) -> libc::c_int {
    if CBS_len(params) != 0 as libc::c_int as size_t {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_x25519_asn1.c\0"
                as *const u8 as *const libc::c_char,
            129 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return x25519_set_pub_raw(out, CBS_data(key), CBS_len(key));
}
unsafe extern "C" fn x25519_pub_encode(
    mut out: *mut CBB,
    mut pkey: *const EVP_PKEY,
) -> libc::c_int {
    let mut key: *const X25519_KEY = (*pkey).pkey.ptr as *const X25519_KEY;
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
        || CBB_add_bytes(
            &mut oid,
            (x25519_asn1_meth.oid).as_ptr(),
            x25519_asn1_meth.oid_len as size_t,
        ) == 0 || CBB_add_asn1(&mut spki, &mut key_bitstring, 0x3 as libc::c_uint) == 0
        || CBB_add_u8(&mut key_bitstring, 0 as libc::c_int as uint8_t) == 0
        || CBB_add_bytes(
            &mut key_bitstring,
            ((*key).pub_0).as_ptr(),
            32 as libc::c_int as size_t,
        ) == 0 || CBB_flush(out) == 0
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_x25519_asn1.c\0"
                as *const u8 as *const libc::c_char,
            149 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn x25519_pub_cmp(
    mut a: *const EVP_PKEY,
    mut b: *const EVP_PKEY,
) -> libc::c_int {
    let mut a_key: *const X25519_KEY = (*a).pkey.ptr as *const X25519_KEY;
    let mut b_key: *const X25519_KEY = (*b).pkey.ptr as *const X25519_KEY;
    return (OPENSSL_memcmp(
        ((*a_key).pub_0).as_ptr() as *const libc::c_void,
        ((*b_key).pub_0).as_ptr() as *const libc::c_void,
        32 as libc::c_int as size_t,
    ) == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn x25519_priv_decode(
    mut out: *mut EVP_PKEY,
    mut oid: *mut CBS,
    mut params: *mut CBS,
    mut key: *mut CBS,
    mut pubkey: *mut CBS,
) -> libc::c_int {
    let mut inner: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_len(params) != 0 as libc::c_int as size_t
        || CBS_get_asn1(key, &mut inner, 0x4 as libc::c_uint) == 0
        || CBS_len(key) != 0 as libc::c_int as size_t
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_x25519_asn1.c\0"
                as *const u8 as *const libc::c_char,
            171 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut public: *const uint8_t = 0 as *const uint8_t;
    let mut public_len: size_t = 0 as libc::c_int as size_t;
    if !pubkey.is_null() {
        let mut padding: uint8_t = 0;
        if CBS_get_u8(pubkey, &mut padding) == 0
            || padding as libc::c_int != 0 as libc::c_int
        {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                102 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_x25519_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                180 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        public = CBS_data(pubkey);
        public_len = CBS_len(pubkey);
    }
    return x25519_set_priv_raw(
        out,
        CBS_data(&mut inner),
        CBS_len(&mut inner),
        public,
        public_len,
    );
}
unsafe extern "C" fn x25519_priv_encode(
    mut out: *mut CBB,
    mut pkey: *const EVP_PKEY,
) -> libc::c_int {
    let mut key: *mut X25519_KEY = (*pkey).pkey.ptr as *mut X25519_KEY;
    if (*key).has_private == 0 {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            130 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_x25519_asn1.c\0"
                as *const u8 as *const libc::c_char,
            193 as libc::c_int as libc::c_uint,
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
    let mut inner: CBB = cbb_st {
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
        || CBB_add_bytes(
            &mut oid,
            (x25519_asn1_meth.oid).as_ptr(),
            x25519_asn1_meth.oid_len as size_t,
        ) == 0 || CBB_add_asn1(&mut pkcs8, &mut private_key, 0x4 as libc::c_uint) == 0
        || CBB_add_asn1(&mut private_key, &mut inner, 0x4 as libc::c_uint) == 0
        || CBB_add_bytes(
            &mut inner,
            ((*key).priv_0).as_mut_ptr(),
            32 as libc::c_int as size_t,
        ) == 0 || CBB_flush(out) == 0
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_x25519_asn1.c\0"
                as *const u8 as *const libc::c_char,
            210 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn x25519_priv_encode_v2(
    mut out: *mut CBB,
    mut pkey: *const EVP_PKEY,
) -> libc::c_int {
    let mut key: *mut X25519_KEY = (*pkey).pkey.ptr as *mut X25519_KEY;
    if (*key).has_private == 0 {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            130 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_x25519_asn1.c\0"
                as *const u8 as *const libc::c_char,
            220 as libc::c_int as libc::c_uint,
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
    let mut inner: CBB = cbb_st {
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
    let mut public_key: CBB = cbb_st {
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
    ) == 0 || CBB_add_asn1_uint64(&mut pkcs8, 1 as libc::c_int as uint64_t) == 0
        || CBB_add_asn1(
            &mut pkcs8,
            &mut algorithm,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0 || CBB_add_asn1(&mut algorithm, &mut oid, 0x6 as libc::c_uint) == 0
        || CBB_add_bytes(
            &mut oid,
            (x25519_asn1_meth.oid).as_ptr(),
            x25519_asn1_meth.oid_len as size_t,
        ) == 0 || CBB_add_asn1(&mut pkcs8, &mut private_key, 0x4 as libc::c_uint) == 0
        || CBB_add_asn1(&mut private_key, &mut inner, 0x4 as libc::c_uint) == 0
        || CBB_add_bytes(
            &mut inner,
            ((*key).priv_0).as_mut_ptr(),
            32 as libc::c_int as size_t,
        ) == 0
        || CBB_add_asn1(
            &mut pkcs8,
            &mut public_key,
            (0x80 as libc::c_uint) << 24 as libc::c_int
                | 1 as libc::c_int as libc::c_uint,
        ) == 0 || CBB_add_u8(&mut public_key, 0 as libc::c_int as uint8_t) == 0
        || CBB_add_bytes(
            &mut public_key,
            ((*key).pub_0).as_mut_ptr(),
            32 as libc::c_int as size_t,
        ) == 0 || CBB_flush(out) == 0
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_x25519_asn1.c\0"
                as *const u8 as *const libc::c_char,
            240 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn x25519_size(mut pkey: *const EVP_PKEY) -> libc::c_int {
    return 32 as libc::c_int;
}
unsafe extern "C" fn x25519_bits(mut pkey: *const EVP_PKEY) -> libc::c_int {
    return 253 as libc::c_int;
}
#[no_mangle]
pub static mut x25519_asn1_meth: EVP_PKEY_ASN1_METHOD = unsafe {
    {
        let mut init = evp_pkey_asn1_method_st {
            pkey_id: 948 as libc::c_int,
            oid: [
                0x2b as libc::c_int as uint8_t,
                0x65 as libc::c_int as uint8_t,
                0x6e as libc::c_int as uint8_t,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            oid_len: 3 as libc::c_int as uint8_t,
            pem_str: b"X25519\0" as *const u8 as *const libc::c_char,
            info: b"OpenSSL X25519 algorithm\0" as *const u8 as *const libc::c_char,
            pub_decode: Some(
                x25519_pub_decode
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY,
                        *mut CBS,
                        *mut CBS,
                        *mut CBS,
                    ) -> libc::c_int,
            ),
            pub_encode: Some(
                x25519_pub_encode
                    as unsafe extern "C" fn(*mut CBB, *const EVP_PKEY) -> libc::c_int,
            ),
            pub_cmp: Some(
                x25519_pub_cmp
                    as unsafe extern "C" fn(
                        *const EVP_PKEY,
                        *const EVP_PKEY,
                    ) -> libc::c_int,
            ),
            priv_decode: Some(
                x25519_priv_decode
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY,
                        *mut CBS,
                        *mut CBS,
                        *mut CBS,
                        *mut CBS,
                    ) -> libc::c_int,
            ),
            priv_encode: Some(
                x25519_priv_encode
                    as unsafe extern "C" fn(*mut CBB, *const EVP_PKEY) -> libc::c_int,
            ),
            priv_encode_v2: Some(
                x25519_priv_encode_v2
                    as unsafe extern "C" fn(*mut CBB, *const EVP_PKEY) -> libc::c_int,
            ),
            set_priv_raw: Some(
                x25519_set_priv_raw
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY,
                        *const uint8_t,
                        size_t,
                        *const uint8_t,
                        size_t,
                    ) -> libc::c_int,
            ),
            set_pub_raw: Some(
                x25519_set_pub_raw
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY,
                        *const uint8_t,
                        size_t,
                    ) -> libc::c_int,
            ),
            get_priv_raw: Some(
                x25519_get_priv_raw
                    as unsafe extern "C" fn(
                        *const EVP_PKEY,
                        *mut uint8_t,
                        *mut size_t,
                    ) -> libc::c_int,
            ),
            get_pub_raw: Some(
                x25519_get_pub_raw
                    as unsafe extern "C" fn(
                        *const EVP_PKEY,
                        *mut uint8_t,
                        *mut size_t,
                    ) -> libc::c_int,
            ),
            pkey_opaque: None,
            pkey_size: Some(
                x25519_size as unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int,
            ),
            pkey_bits: Some(
                x25519_bits as unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int,
            ),
            param_missing: None,
            param_copy: None,
            param_cmp: None,
            pkey_free: Some(x25519_free as unsafe extern "C" fn(*mut EVP_PKEY) -> ()),
        };
        init
    }
};
