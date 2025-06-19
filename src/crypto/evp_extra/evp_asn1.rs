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
    pub type ec_group_st;
    pub type ec_key_st;
    pub type engine_st;
    pub type kem_key_st;
    pub type rsa_st;
    fn DSA_free(dsa: *mut DSA);
    fn DSA_parse_private_key(cbs: *mut CBS) -> *mut DSA;
    fn i2d_DSAPublicKey(in_0: *const DSA, outp: *mut *mut uint8_t) -> libc::c_int;
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_get_u8(cbs: *mut CBS, out: *mut uint8_t) -> libc::c_int;
    fn CBS_get_asn1(
        cbs: *mut CBS,
        out: *mut CBS,
        tag_value: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBS_peek_asn1_tag(cbs: *const CBS, tag_value: CBS_ASN1_TAG) -> libc::c_int;
    fn CBS_get_any_asn1_element(
        cbs: *mut CBS,
        out: *mut CBS,
        out_tag: *mut CBS_ASN1_TAG,
        out_header_len: *mut size_t,
    ) -> libc::c_int;
    fn CBS_get_asn1_uint64(cbs: *mut CBS, out: *mut uint64_t) -> libc::c_int;
    fn CBB_init(cbb: *mut CBB, initial_capacity: size_t) -> libc::c_int;
    fn CBB_cleanup(cbb: *mut CBB);
    fn PQDSA_find_asn1_by_nid(nid: libc::c_int) -> *const EVP_PKEY_ASN1_METHOD;
    fn EVP_PKEY_new() -> *mut EVP_PKEY;
    fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
    fn EVP_PKEY_set1_RSA(pkey: *mut EVP_PKEY, key: *mut RSA) -> libc::c_int;
    fn EVP_PKEY_assign_RSA(pkey: *mut EVP_PKEY, key: *mut RSA) -> libc::c_int;
    fn EVP_PKEY_get1_RSA(pkey: *const EVP_PKEY) -> *mut RSA;
    fn EVP_PKEY_set1_DSA(pkey: *mut EVP_PKEY, key: *mut DSA) -> libc::c_int;
    fn EVP_PKEY_assign_DSA(pkey: *mut EVP_PKEY, key: *mut DSA) -> libc::c_int;
    fn EVP_PKEY_get1_DSA(pkey: *const EVP_PKEY) -> *mut DSA;
    fn EVP_PKEY_set1_EC_KEY(pkey: *mut EVP_PKEY, key: *mut EC_KEY) -> libc::c_int;
    fn EVP_PKEY_assign_EC_KEY(pkey: *mut EVP_PKEY, key: *mut EC_KEY) -> libc::c_int;
    fn EVP_PKEY_get1_EC_KEY(pkey: *const EVP_PKEY) -> *mut EC_KEY;
    fn OBJ_cbs2nid(cbs: *const CBS) -> libc::c_int;
    fn OPENSSL_strnlen(s: *const libc::c_char, len: size_t) -> size_t;
    fn OPENSSL_strncasecmp(
        a: *const libc::c_char,
        b: *const libc::c_char,
        n: size_t,
    ) -> libc::c_int;
    fn ERR_clear_error();
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn EC_KEY_free(key: *mut EC_KEY);
    fn EC_KEY_parse_private_key(cbs: *mut CBS, group: *const EC_GROUP) -> *mut EC_KEY;
    fn i2o_ECPublicKey(key: *const EC_KEY, outp: *mut *mut libc::c_uchar) -> libc::c_int;
    fn RSA_free(rsa: *mut RSA);
    fn RSA_parse_public_key(cbs: *mut CBS) -> *mut RSA;
    fn RSA_parse_private_key(cbs: *mut CBS) -> *mut RSA;
    fn i2d_RSAPublicKey(in_0: *const RSA, outp: *mut *mut uint8_t) -> libc::c_int;
    fn CBB_finish_i2d(cbb: *mut CBB, outp: *mut *mut uint8_t) -> libc::c_int;
    static asn1_evp_pkey_methods_size: size_t;
    static asn1_evp_pkey_methods: [*const EVP_PKEY_ASN1_METHOD; 0];
    static rsa_asn1_meth: EVP_PKEY_ASN1_METHOD;
    fn evp_pkey_set_method(pkey: *mut EVP_PKEY, method: *const EVP_PKEY_ASN1_METHOD);
    fn AWSLC_non_fips_pkey_evp_asn1_methods() -> *const *const EVP_PKEY_ASN1_METHOD;
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
pub type EC_GROUP = ec_group_st;
pub type EC_KEY = ec_key_st;
pub type ENGINE = engine_st;
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
unsafe extern "C" fn parse_key_type(
    mut cbs: *mut CBS,
    mut out_oid: *mut CBS,
) -> *const EVP_PKEY_ASN1_METHOD {
    let mut oid: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_get_asn1(cbs, &mut oid, 0x6 as libc::c_uint) == 0 {
        return 0 as *const EVP_PKEY_ASN1_METHOD;
    }
    CBS_init(out_oid, CBS_data(&mut oid), CBS_len(&mut oid));
    let mut asn1_methods: *const *const EVP_PKEY_ASN1_METHOD = AWSLC_non_fips_pkey_evp_asn1_methods();
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < 11 as libc::c_int as size_t {
        let mut method: *const EVP_PKEY_ASN1_METHOD = *asn1_methods.offset(i as isize);
        if CBS_len(&mut oid) == (*method).oid_len as size_t
            && OPENSSL_memcmp(
                CBS_data(&mut oid) as *const libc::c_void,
                ((*method).oid).as_ptr() as *const libc::c_void,
                (*method).oid_len as size_t,
            ) == 0 as libc::c_int
        {
            return method;
        }
        i = i.wrapping_add(1);
        i;
    }
    if OBJ_cbs2nid(&mut oid) == 19 as libc::c_int {
        return &rsa_asn1_meth;
    }
    return PQDSA_find_asn1_by_nid(OBJ_cbs2nid(&mut oid));
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_parse_public_key(mut cbs: *mut CBS) -> *mut EVP_PKEY {
    let mut spki: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut algorithm: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut key: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut padding: uint8_t = 0;
    if CBS_get_asn1(
        cbs,
        &mut spki,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0
        || CBS_get_asn1(
            &mut spki,
            &mut algorithm,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0 || CBS_get_asn1(&mut spki, &mut key, 0x3 as libc::c_uint) == 0
        || CBS_len(&mut spki) != 0 as libc::c_int as size_t
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/evp_asn1.c\0"
                as *const u8 as *const libc::c_char,
            118 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EVP_PKEY;
    }
    let mut oid: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut method: *const EVP_PKEY_ASN1_METHOD = parse_key_type(
        &mut algorithm,
        &mut oid,
    );
    if method.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            128 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/evp_asn1.c\0"
                as *const u8 as *const libc::c_char,
            126 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EVP_PKEY;
    }
    if CBS_get_u8(&mut key, &mut padding) == 0
        || padding as libc::c_int != 0 as libc::c_int
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/evp_asn1.c\0"
                as *const u8 as *const libc::c_char,
            133 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EVP_PKEY;
    }
    let mut ret: *mut EVP_PKEY = EVP_PKEY_new();
    if !ret.is_null() {
        evp_pkey_set_method(ret, method);
        if ((*(*ret).ameth).pub_decode).is_none() {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                128 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/evp_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                146 as libc::c_int as libc::c_uint,
            );
        } else if !(((*(*ret).ameth).pub_decode)
            .expect("non-null function pointer")(ret, &mut oid, &mut algorithm, &mut key)
            == 0)
        {
            return ret
        }
    }
    EVP_PKEY_free(ret);
    return 0 as *mut EVP_PKEY;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_marshal_public_key(
    mut cbb: *mut CBB,
    mut key: *const EVP_PKEY,
) -> libc::c_int {
    if cbb.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/evp_asn1.c\0"
                as *const u8 as *const libc::c_char,
            161 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if key.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/evp_asn1.c\0"
                as *const u8 as *const libc::c_char,
            162 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*key).ameth).is_null() || ((*(*key).ameth).pub_encode).is_none() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            128 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/evp_asn1.c\0"
                as *const u8 as *const libc::c_char,
            164 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ((*(*key).ameth).pub_encode).expect("non-null function pointer")(cbb, key);
}
static mut kAttributesTag: libc::c_uint = (0x80 as libc::c_uint) << 24 as libc::c_int
    | 0 as libc::c_int as libc::c_uint;
static mut kPublicKeyTag: libc::c_uint = (0x80 as libc::c_uint) << 24 as libc::c_int
    | 1 as libc::c_int as libc::c_uint;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_parse_private_key(mut cbs: *mut CBS) -> *mut EVP_PKEY {
    let mut pkcs8: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut algorithm: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut key: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut public_key: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut version: uint64_t = 0;
    if CBS_get_asn1(
        cbs,
        &mut pkcs8,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || CBS_get_asn1_uint64(&mut pkcs8, &mut version) == 0
        || version > 1 as libc::c_int as uint64_t
        || CBS_get_asn1(
            &mut pkcs8,
            &mut algorithm,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0 || CBS_get_asn1(&mut pkcs8, &mut key, 0x4 as libc::c_uint) == 0
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/evp_asn1.c\0"
                as *const u8 as *const libc::c_char,
            186 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EVP_PKEY;
    }
    let mut oid: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut method: *const EVP_PKEY_ASN1_METHOD = parse_key_type(
        &mut algorithm,
        &mut oid,
    );
    if method.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            128 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/evp_asn1.c\0"
                as *const u8 as *const libc::c_char,
            194 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EVP_PKEY;
    }
    if CBS_peek_asn1_tag(&mut pkcs8, kAttributesTag) != 0 {
        if CBS_get_asn1(cbs, 0 as *mut CBS, kAttributesTag) == 0 {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                102 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/evp_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                202 as libc::c_int as libc::c_uint,
            );
            return 0 as *mut EVP_PKEY;
        }
    }
    let mut has_pub: libc::c_int = 0 as libc::c_int;
    if CBS_peek_asn1_tag(&mut pkcs8, kPublicKeyTag) != 0 {
        if version != 1 as libc::c_int as uint64_t
            || CBS_get_asn1(&mut pkcs8, &mut public_key, kPublicKeyTag) == 0
        {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                102 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/evp_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                214 as libc::c_int as libc::c_uint,
            );
            return 0 as *mut EVP_PKEY;
        }
        has_pub = 1 as libc::c_int;
    }
    let mut ret: *mut EVP_PKEY = EVP_PKEY_new();
    if !ret.is_null() {
        evp_pkey_set_method(ret, method);
        if ((*(*ret).ameth).priv_decode).is_none() {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                128 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/evp_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                229 as libc::c_int as libc::c_uint,
            );
        } else if !(((*(*ret).ameth).priv_decode)
            .expect(
                "non-null function pointer",
            )(
            ret,
            &mut oid,
            &mut algorithm,
            &mut key,
            if has_pub != 0 { &mut public_key } else { 0 as *mut CBS },
        ) == 0)
        {
            return ret
        }
    }
    EVP_PKEY_free(ret);
    return 0 as *mut EVP_PKEY;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_marshal_private_key(
    mut cbb: *mut CBB,
    mut key: *const EVP_PKEY,
) -> libc::c_int {
    if ((*key).ameth).is_null() || ((*(*key).ameth).priv_encode).is_none() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            128 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/evp_asn1.c\0"
                as *const u8 as *const libc::c_char,
            247 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ((*(*key).ameth).priv_encode).expect("non-null function pointer")(cbb, key);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_marshal_private_key_v2(
    mut cbb: *mut CBB,
    mut key: *const EVP_PKEY,
) -> libc::c_int {
    if ((*key).ameth).is_null() || ((*(*key).ameth).priv_encode_v2).is_none() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            128 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/evp_asn1.c\0"
                as *const u8 as *const libc::c_char,
            256 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ((*(*key).ameth).priv_encode_v2)
        .expect("non-null function pointer")(cbb, key);
}
unsafe extern "C" fn old_priv_decode(
    mut cbs: *mut CBS,
    mut type_0: libc::c_int,
) -> *mut EVP_PKEY {
    let mut ret: *mut EVP_PKEY = EVP_PKEY_new();
    if ret.is_null() {
        return 0 as *mut EVP_PKEY;
    }
    match type_0 {
        408 => {
            let mut ec_key: *mut EC_KEY = EC_KEY_parse_private_key(
                cbs,
                0 as *const EC_GROUP,
            );
            if ec_key.is_null() || EVP_PKEY_assign_EC_KEY(ret, ec_key) == 0 {
                EC_KEY_free(ec_key);
            } else {
                return ret
            }
        }
        116 => {
            let mut dsa: *mut DSA = DSA_parse_private_key(cbs);
            if dsa.is_null() || EVP_PKEY_assign_DSA(ret, dsa) == 0 {
                DSA_free(dsa);
            } else {
                return ret
            }
        }
        6 => {
            let mut rsa: *mut RSA = RSA_parse_private_key(cbs);
            if rsa.is_null() || EVP_PKEY_assign_RSA(ret, rsa) == 0 {
                RSA_free(rsa);
            } else {
                return ret
            }
        }
        _ => {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                127 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/evp_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                295 as libc::c_int as libc::c_uint,
            );
        }
    }
    EVP_PKEY_free(ret);
    return 0 as *mut EVP_PKEY;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_PrivateKey(
    mut type_0: libc::c_int,
    mut out: *mut *mut EVP_PKEY,
    mut inp: *mut *const uint8_t,
    mut len: libc::c_long,
) -> *mut EVP_PKEY {
    if len < 0 as libc::c_int as libc::c_long {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/evp_asn1.c\0"
                as *const u8 as *const libc::c_char,
            307 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EVP_PKEY;
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, *inp, len as size_t);
    let mut ret: *mut EVP_PKEY = old_priv_decode(&mut cbs, type_0);
    if ret.is_null() {
        ERR_clear_error();
        CBS_init(&mut cbs, *inp, len as size_t);
        ret = EVP_parse_private_key(&mut cbs);
        if ret.is_null() {
            return 0 as *mut EVP_PKEY;
        }
        if (*ret).type_0 != type_0 {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                103 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/evp_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                324 as libc::c_int as libc::c_uint,
            );
            EVP_PKEY_free(ret);
            return 0 as *mut EVP_PKEY;
        }
    }
    if !out.is_null() {
        EVP_PKEY_free(*out);
        *out = ret;
    }
    *inp = CBS_data(&mut cbs);
    return ret;
}
unsafe extern "C" fn num_elements(
    mut in_0: *const uint8_t,
    mut in_len: size_t,
) -> size_t {
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut sequence: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, in_0, in_len);
    if CBS_get_asn1(
        &mut cbs,
        &mut sequence,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0
    {
        return 0 as libc::c_int as size_t;
    }
    let mut count: size_t = 0 as libc::c_int as size_t;
    while CBS_len(&mut sequence) > 0 as libc::c_int as size_t {
        if CBS_get_any_asn1_element(
            &mut sequence,
            0 as *mut CBS,
            0 as *mut CBS_ASN1_TAG,
            0 as *mut size_t,
        ) == 0
        {
            return 0 as libc::c_int as size_t;
        }
        count = count.wrapping_add(1);
        count;
    }
    return count;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_AutoPrivateKey(
    mut out: *mut *mut EVP_PKEY,
    mut inp: *mut *const uint8_t,
    mut len: libc::c_long,
) -> *mut EVP_PKEY {
    if len < 0 as libc::c_int as libc::c_long {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/evp_asn1.c\0"
                as *const u8 as *const libc::c_char,
            362 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EVP_PKEY;
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, *inp, len as size_t);
    let mut ret: *mut EVP_PKEY = EVP_parse_private_key(&mut cbs);
    if !ret.is_null() {
        if !out.is_null() {
            EVP_PKEY_free(*out);
            *out = ret;
        }
        *inp = CBS_data(&mut cbs);
        return ret;
    }
    ERR_clear_error();
    match num_elements(*inp, len as size_t) {
        4 => return d2i_PrivateKey(408 as libc::c_int, out, inp, len),
        6 => return d2i_PrivateKey(116 as libc::c_int, out, inp, len),
        _ => return d2i_PrivateKey(6 as libc::c_int, out, inp, len),
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_PublicKey(
    mut key: *const EVP_PKEY,
    mut outp: *mut *mut uint8_t,
) -> libc::c_int {
    match (*key).type_0 {
        6 => return i2d_RSAPublicKey((*key).pkey.rsa, outp),
        116 => return i2d_DSAPublicKey((*key).pkey.dsa, outp),
        408 => return i2o_ECPublicKey((*key).pkey.ec, outp),
        _ => {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                129 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/evp_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                402 as libc::c_int as libc::c_uint,
            );
            return -(1 as libc::c_int);
        }
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_PublicKey(
    mut type_0: libc::c_int,
    mut out: *mut *mut EVP_PKEY,
    mut inp: *mut *const uint8_t,
    mut len: libc::c_long,
) -> *mut EVP_PKEY {
    let mut ret: *mut EVP_PKEY = EVP_PKEY_new();
    if ret.is_null() {
        return 0 as *mut EVP_PKEY;
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(
        &mut cbs,
        *inp,
        if len < 0 as libc::c_int as libc::c_long {
            0 as libc::c_int as size_t
        } else {
            len as size_t
        },
    );
    match type_0 {
        6 => {
            let mut rsa: *mut RSA = RSA_parse_public_key(&mut cbs);
            if rsa.is_null() || EVP_PKEY_assign_RSA(ret, rsa) == 0 {
                RSA_free(rsa);
            } else {
                *inp = CBS_data(&mut cbs);
                if !out.is_null() {
                    EVP_PKEY_free(*out);
                    *out = ret;
                }
                return ret;
            }
        }
        _ => {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                129 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/evp_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                432 as libc::c_int as libc::c_uint,
            );
        }
    }
    EVP_PKEY_free(ret);
    return 0 as *mut EVP_PKEY;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_PUBKEY(
    mut out: *mut *mut EVP_PKEY,
    mut inp: *mut *const uint8_t,
    mut len: libc::c_long,
) -> *mut EVP_PKEY {
    if len < 0 as libc::c_int as libc::c_long {
        return 0 as *mut EVP_PKEY;
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, *inp, len as size_t);
    let mut ret: *mut EVP_PKEY = EVP_parse_public_key(&mut cbs);
    if ret.is_null() {
        return 0 as *mut EVP_PKEY;
    }
    if !out.is_null() {
        EVP_PKEY_free(*out);
        *out = ret;
    }
    *inp = CBS_data(&mut cbs);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_PUBKEY(
    mut pkey: *const EVP_PKEY,
    mut outp: *mut *mut uint8_t,
) -> libc::c_int {
    if pkey.is_null() {
        return 0 as libc::c_int;
    }
    let mut cbb: CBB = cbb_st {
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
    if CBB_init(&mut cbb, 128 as libc::c_int as size_t) == 0
        || EVP_marshal_public_key(&mut cbb, pkey) == 0
    {
        CBB_cleanup(&mut cbb);
        return -(1 as libc::c_int);
    }
    return CBB_finish_i2d(&mut cbb, outp);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_RSA_PUBKEY(
    mut out: *mut *mut RSA,
    mut inp: *mut *const uint8_t,
    mut len: libc::c_long,
) -> *mut RSA {
    if len < 0 as libc::c_int as libc::c_long {
        return 0 as *mut RSA;
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, *inp, len as size_t);
    let mut pkey: *mut EVP_PKEY = EVP_parse_public_key(&mut cbs);
    if pkey.is_null() {
        return 0 as *mut RSA;
    }
    let mut rsa: *mut RSA = EVP_PKEY_get1_RSA(pkey);
    EVP_PKEY_free(pkey);
    if rsa.is_null() {
        return 0 as *mut RSA;
    }
    if !out.is_null() {
        RSA_free(*out);
        *out = rsa;
    }
    *inp = CBS_data(&mut cbs);
    return rsa;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_RSA_PUBKEY(
    mut rsa: *const RSA,
    mut outp: *mut *mut uint8_t,
) -> libc::c_int {
    if rsa.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut pkey: *mut EVP_PKEY = EVP_PKEY_new();
    if !(pkey.is_null() || EVP_PKEY_set1_RSA(pkey, rsa as *mut RSA) == 0) {
        ret = i2d_PUBKEY(pkey, outp);
    }
    EVP_PKEY_free(pkey);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_DSA_PUBKEY(
    mut out: *mut *mut DSA,
    mut inp: *mut *const uint8_t,
    mut len: libc::c_long,
) -> *mut DSA {
    if len < 0 as libc::c_int as libc::c_long {
        return 0 as *mut DSA;
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, *inp, len as size_t);
    let mut pkey: *mut EVP_PKEY = EVP_parse_public_key(&mut cbs);
    if pkey.is_null() {
        return 0 as *mut DSA;
    }
    let mut dsa: *mut DSA = EVP_PKEY_get1_DSA(pkey);
    EVP_PKEY_free(pkey);
    if dsa.is_null() {
        return 0 as *mut DSA;
    }
    if !out.is_null() {
        DSA_free(*out);
        *out = dsa;
    }
    *inp = CBS_data(&mut cbs);
    return dsa;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_DSA_PUBKEY(
    mut dsa: *const DSA,
    mut outp: *mut *mut uint8_t,
) -> libc::c_int {
    if dsa.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut pkey: *mut EVP_PKEY = EVP_PKEY_new();
    if !(pkey.is_null() || EVP_PKEY_set1_DSA(pkey, dsa as *mut DSA) == 0) {
        ret = i2d_PUBKEY(pkey, outp);
    }
    EVP_PKEY_free(pkey);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_EC_PUBKEY(
    mut out: *mut *mut EC_KEY,
    mut inp: *mut *const uint8_t,
    mut len: libc::c_long,
) -> *mut EC_KEY {
    if len < 0 as libc::c_int as libc::c_long {
        return 0 as *mut EC_KEY;
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, *inp, len as size_t);
    let mut pkey: *mut EVP_PKEY = EVP_parse_public_key(&mut cbs);
    if pkey.is_null() {
        return 0 as *mut EC_KEY;
    }
    let mut ec_key: *mut EC_KEY = EVP_PKEY_get1_EC_KEY(pkey);
    EVP_PKEY_free(pkey);
    if ec_key.is_null() {
        return 0 as *mut EC_KEY;
    }
    if !out.is_null() {
        EC_KEY_free(*out);
        *out = ec_key;
    }
    *inp = CBS_data(&mut cbs);
    return ec_key;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_EC_PUBKEY(
    mut ec_key: *const EC_KEY,
    mut outp: *mut *mut uint8_t,
) -> libc::c_int {
    if ec_key.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut pkey: *mut EVP_PKEY = EVP_PKEY_new();
    if !(pkey.is_null() || EVP_PKEY_set1_EC_KEY(pkey, ec_key as *mut EC_KEY) == 0) {
        ret = i2d_PUBKEY(pkey, outp);
    }
    EVP_PKEY_free(pkey);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_PKEY_asn1_get_count() -> libc::c_int {
    return asn1_evp_pkey_methods_size as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_PKEY_asn1_get0(
    mut idx: libc::c_int,
) -> *const EVP_PKEY_ASN1_METHOD {
    if idx < 0 as libc::c_int || idx >= EVP_PKEY_asn1_get_count() {
        return 0 as *const EVP_PKEY_ASN1_METHOD;
    }
    return *asn1_evp_pkey_methods.as_ptr().offset(idx as isize);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_PKEY_asn1_find(
    mut _pe: *mut *mut ENGINE,
    mut type_0: libc::c_int,
) -> *const EVP_PKEY_ASN1_METHOD {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < EVP_PKEY_asn1_get_count() as size_t {
        let mut ameth: *const EVP_PKEY_ASN1_METHOD = EVP_PKEY_asn1_get0(
            i as libc::c_int,
        );
        if (*ameth).pkey_id == type_0 {
            return ameth;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as *const EVP_PKEY_ASN1_METHOD;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_PKEY_asn1_find_str(
    mut _pe: *mut *mut ENGINE,
    mut name: *const libc::c_char,
    mut len: libc::c_int,
) -> *const EVP_PKEY_ASN1_METHOD {
    if len < 0 as libc::c_int {
        return 0 as *const EVP_PKEY_ASN1_METHOD;
    }
    let name_len: size_t = OPENSSL_strnlen(name, len as size_t);
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < EVP_PKEY_asn1_get_count() as size_t {
        let mut ameth: *const EVP_PKEY_ASN1_METHOD = EVP_PKEY_asn1_get0(
            i as libc::c_int,
        );
        let longest_pem_str_len: size_t = 10 as libc::c_int as size_t;
        let pem_str_len: size_t = OPENSSL_strnlen((*ameth).pem_str, longest_pem_str_len);
        let cmp_len: size_t = (1 as libc::c_int as size_t)
            .wrapping_add((if name_len < pem_str_len { name_len } else { pem_str_len }));
        if 0 as libc::c_int == OPENSSL_strncasecmp((*ameth).pem_str, name, cmp_len) {
            return ameth;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as *const EVP_PKEY_ASN1_METHOD;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_PKEY_asn1_get0_info(
    mut ppkey_id: *mut libc::c_int,
    mut pkey_base_id: *mut libc::c_int,
    mut ppkey_flags: *mut libc::c_int,
    mut pinfo: *mut *const libc::c_char,
    mut ppem_str: *mut *const libc::c_char,
    mut ameth: *const EVP_PKEY_ASN1_METHOD,
) -> libc::c_int {
    if ameth.is_null() {
        return 0 as libc::c_int;
    }
    if !ppkey_id.is_null() {
        *ppkey_id = (*ameth).pkey_id;
    }
    if !pkey_base_id.is_null() {
        *pkey_base_id = (*ameth).pkey_id;
    }
    if !ppkey_flags.is_null() {
        *ppkey_flags = 0 as libc::c_int;
    }
    if !pinfo.is_null() {
        *pinfo = (*ameth).info;
    }
    if !ppem_str.is_null() {
        *ppem_str = (*ameth).pem_str;
    }
    return 1 as libc::c_int;
}
