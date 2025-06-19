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
    pub type stack_st_void;
    pub type dh_st;
    pub type dsa_st;
    pub type ec_key_st;
    pub type pqdsa_key_st;
    pub type kem_key_st;
    pub type bn_blinding_st;
    fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn CBS_len(cbs: *const CBS) -> size_t;
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
    fn RSASSA_PSS_PARAMS_free(params: *mut RSASSA_PSS_PARAMS);
    fn RSASSA_PSS_parse_params(
        params: *mut CBS,
        pss: *mut *mut RSASSA_PSS_PARAMS,
    ) -> libc::c_int;
    fn EVP_PKEY_assign_RSA(pkey: *mut EVP_PKEY, key: *mut RSA) -> libc::c_int;
    fn EVP_PKEY_assign(
        pkey: *mut EVP_PKEY,
        type_0: libc::c_int,
        key: *mut libc::c_void,
    ) -> libc::c_int;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn RSA_free(rsa: *mut RSA);
    fn RSA_bits(rsa: *const RSA) -> libc::c_uint;
    fn RSA_size(rsa: *const RSA) -> libc::c_uint;
    fn RSA_is_opaque(rsa: *const RSA) -> libc::c_int;
    fn RSA_parse_public_key(cbs: *mut CBS) -> *mut RSA;
    fn RSA_marshal_public_key(cbb: *mut CBB, rsa: *const RSA) -> libc::c_int;
    fn RSA_parse_private_key(cbs: *mut CBS) -> *mut RSA;
    fn RSA_marshal_private_key(cbb: *mut CBB, rsa: *const RSA) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type int64_t = __int64_t;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type CBS_ASN1_TAG = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bignum_st {
    pub d: *mut BN_ULONG,
    pub width: libc::c_int,
    pub dmax: libc::c_int,
    pub neg: libc::c_int,
    pub flags: libc::c_int,
}
pub type BN_ULONG = uint64_t;
pub type BIGNUM = bignum_st;
pub type CRYPTO_refcount_t = uint32_t;
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bn_mont_ctx_st {
    pub RR: BIGNUM,
    pub N: BIGNUM,
    pub n0: [BN_ULONG; 2],
}
pub type BN_MONT_CTX = bn_mont_ctx_st;
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
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct rsa_st {
    pub meth: *const RSA_METHOD,
    pub n: *mut BIGNUM,
    pub e: *mut BIGNUM,
    pub d: *mut BIGNUM,
    pub p: *mut BIGNUM,
    pub q: *mut BIGNUM,
    pub dmp1: *mut BIGNUM,
    pub dmq1: *mut BIGNUM,
    pub iqmp: *mut BIGNUM,
    pub pss: *mut RSASSA_PSS_PARAMS,
    pub ex_data: CRYPTO_EX_DATA,
    pub references: CRYPTO_refcount_t,
    pub flags: libc::c_int,
    pub lock: CRYPTO_MUTEX,
    pub mont_n: *mut BN_MONT_CTX,
    pub mont_p: *mut BN_MONT_CTX,
    pub mont_q: *mut BN_MONT_CTX,
    pub d_fixed: *mut BIGNUM,
    pub dmp1_fixed: *mut BIGNUM,
    pub dmq1_fixed: *mut BIGNUM,
    pub iqmp_mont: *mut BIGNUM,
    pub num_blindings: size_t,
    pub blindings: *mut *mut BN_BLINDING,
    pub blindings_inuse: *mut libc::c_uchar,
    pub blinding_fork_generation: uint64_t,
    #[bitfield(name = "private_key_frozen", ty = "libc::c_uint", bits = "0..=0")]
    pub private_key_frozen: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
pub type BN_BLINDING = bn_blinding_st;
pub type CRYPTO_MUTEX = crypto_mutex_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub union crypto_mutex_st {
    pub alignment: libc::c_double,
    pub padding: [uint8_t; 56],
}
pub type RSASSA_PSS_PARAMS = rsassa_pss_params_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rsassa_pss_params_st {
    pub hash_algor: *mut RSA_ALGOR_IDENTIFIER,
    pub mask_gen_algor: *mut RSA_MGA_IDENTIFIER,
    pub salt_len: *mut RSA_INTEGER,
    pub trailer_field: *mut RSA_INTEGER,
}
pub type RSA_INTEGER = rsa_integer_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rsa_integer_st {
    pub value: int64_t,
}
pub type RSA_MGA_IDENTIFIER = rsa_mga_identifier_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rsa_mga_identifier_st {
    pub mask_gen: *mut RSA_ALGOR_IDENTIFIER,
    pub one_way_hash: *mut RSA_ALGOR_IDENTIFIER,
}
pub type RSA_ALGOR_IDENTIFIER = rsa_algor_identifier_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rsa_algor_identifier_st {
    pub nid: libc::c_int,
}
pub type RSA_METHOD = rsa_meth_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rsa_meth_st {
    pub app_data: *mut libc::c_void,
    pub init: Option::<unsafe extern "C" fn(*mut RSA) -> libc::c_int>,
    pub finish: Option::<unsafe extern "C" fn(*mut RSA) -> libc::c_int>,
    pub size: Option::<unsafe extern "C" fn(*const RSA) -> size_t>,
    pub sign: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            libc::c_uint,
            *mut uint8_t,
            *mut libc::c_uint,
            *const RSA,
        ) -> libc::c_int,
    >,
    pub sign_raw: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            *mut uint8_t,
            *mut RSA,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub verify_raw: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            *mut uint8_t,
            *mut RSA,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub decrypt: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            *mut uint8_t,
            *mut RSA,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub encrypt: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            *mut uint8_t,
            *mut RSA,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub private_transform: Option::<
        unsafe extern "C" fn(
            *mut RSA,
            *mut uint8_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub flags: libc::c_int,
}
unsafe extern "C" fn rsa_pub_encode(
    mut out: *mut CBB,
    mut key: *const EVP_PKEY,
) -> libc::c_int {
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
    let mut null: CBB = cbb_st {
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
            (rsa_asn1_meth.oid).as_ptr(),
            rsa_asn1_meth.oid_len as size_t,
        ) == 0 || CBB_add_asn1(&mut algorithm, &mut null, 0x5 as libc::c_uint) == 0
        || CBB_add_asn1(&mut spki, &mut key_bitstring, 0x3 as libc::c_uint) == 0
        || CBB_add_u8(&mut key_bitstring, 0 as libc::c_int as uint8_t) == 0
        || RSA_marshal_public_key(&mut key_bitstring, (*key).pkey.rsa) == 0
        || CBB_flush(out) == 0
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_rsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            81 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn rsa_pub_decode(
    mut out: *mut EVP_PKEY,
    mut oid: *mut CBS,
    mut params: *mut CBS,
    mut key: *mut CBS,
) -> libc::c_int {
    let mut rsa: *mut RSA = RSA_parse_public_key(key);
    if rsa.is_null() || CBS_len(key) != 0 as libc::c_int as size_t {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_rsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            99 as libc::c_int as libc::c_uint,
        );
        RSA_free(rsa);
        return 0 as libc::c_int;
    }
    EVP_PKEY_assign_RSA(out, rsa);
    return 1 as libc::c_int;
}
unsafe extern "C" fn rsa_pss_pub_decode(
    mut out: *mut EVP_PKEY,
    mut oid: *mut CBS,
    mut params: *mut CBS,
    mut key: *mut CBS,
) -> libc::c_int {
    let mut pss: *mut RSASSA_PSS_PARAMS = 0 as *mut RSASSA_PSS_PARAMS;
    if RSASSA_PSS_parse_params(params, &mut pss) == 0 {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_rsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            111 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut rsa: *mut RSA = RSA_parse_public_key(key);
    if !rsa.is_null() {
        (*rsa).pss = pss;
    } else {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_rsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            118 as libc::c_int as libc::c_uint,
        );
        RSASSA_PSS_PARAMS_free(pss);
        return 0 as libc::c_int;
    }
    if rsa.is_null() || CBS_len(key) != 0 as libc::c_int as size_t
        || EVP_PKEY_assign(out, 912 as libc::c_int, rsa as *mut libc::c_void) == 0
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_rsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            125 as libc::c_int as libc::c_uint,
        );
        RSA_free(rsa);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn rsa_pub_cmp(
    mut a: *const EVP_PKEY,
    mut b: *const EVP_PKEY,
) -> libc::c_int {
    return (BN_cmp((*(*b).pkey.rsa).n, (*(*a).pkey.rsa).n) == 0 as libc::c_int
        && BN_cmp((*(*b).pkey.rsa).e, (*(*a).pkey.rsa).e) == 0 as libc::c_int)
        as libc::c_int;
}
unsafe extern "C" fn rsa_priv_encode(
    mut out: *mut CBB,
    mut key: *const EVP_PKEY,
) -> libc::c_int {
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
    let mut null: CBB = cbb_st {
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
            (rsa_asn1_meth.oid).as_ptr(),
            rsa_asn1_meth.oid_len as size_t,
        ) == 0 || CBB_add_asn1(&mut algorithm, &mut null, 0x5 as libc::c_uint) == 0
        || CBB_add_asn1(&mut pkcs8, &mut private_key, 0x4 as libc::c_uint) == 0
        || RSA_marshal_private_key(&mut private_key, (*key).pkey.rsa) == 0
        || CBB_flush(out) == 0
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_rsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            148 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn rsa_priv_decode(
    mut out: *mut EVP_PKEY,
    mut oid: *mut CBS,
    mut params: *mut CBS,
    mut key: *mut CBS,
    mut pubkey: *mut CBS,
) -> libc::c_int {
    if !pubkey.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_rsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            157 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut null: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_get_asn1(params, &mut null, 0x5 as libc::c_uint) == 0
        || CBS_len(&mut null) != 0 as libc::c_int as size_t
        || CBS_len(params) != 0 as libc::c_int as size_t
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_rsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            166 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut rsa: *mut RSA = RSA_parse_private_key(key);
    if rsa.is_null() || CBS_len(key) != 0 as libc::c_int as size_t {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_rsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            172 as libc::c_int as libc::c_uint,
        );
        RSA_free(rsa);
        return 0 as libc::c_int;
    }
    EVP_PKEY_assign_RSA(out, rsa);
    return 1 as libc::c_int;
}
unsafe extern "C" fn rsa_pss_priv_decode(
    mut out: *mut EVP_PKEY,
    mut oid: *mut CBS,
    mut params: *mut CBS,
    mut key: *mut CBS,
    mut pubkey: *mut CBS,
) -> libc::c_int {
    let mut pss: *mut RSASSA_PSS_PARAMS = 0 as *mut RSASSA_PSS_PARAMS;
    if RSASSA_PSS_parse_params(params, &mut pss) == 0 {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_rsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            184 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut rsa: *mut RSA = RSA_parse_private_key(key);
    if !rsa.is_null() {
        (*rsa).pss = pss;
    } else {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_rsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            191 as libc::c_int as libc::c_uint,
        );
        RSASSA_PSS_PARAMS_free(pss);
        return 0 as libc::c_int;
    }
    if rsa.is_null() || CBS_len(key) != 0 as libc::c_int as size_t
        || EVP_PKEY_assign(out, 912 as libc::c_int, rsa as *mut libc::c_void) == 0
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_rsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            198 as libc::c_int as libc::c_uint,
        );
        RSA_free(rsa);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn rsa_opaque(mut pkey: *const EVP_PKEY) -> libc::c_int {
    return RSA_is_opaque((*pkey).pkey.rsa);
}
unsafe extern "C" fn int_rsa_size(mut pkey: *const EVP_PKEY) -> libc::c_int {
    return RSA_size((*pkey).pkey.rsa) as libc::c_int;
}
unsafe extern "C" fn rsa_bits(mut pkey: *const EVP_PKEY) -> libc::c_int {
    return RSA_bits((*pkey).pkey.rsa) as libc::c_int;
}
unsafe extern "C" fn int_rsa_free(mut pkey: *mut EVP_PKEY) {
    RSA_free((*pkey).pkey.rsa);
}
#[unsafe(no_mangle)]
pub static mut rsa_asn1_meth: EVP_PKEY_ASN1_METHOD = unsafe {
    {
        let mut init = evp_pkey_asn1_method_st {
            pkey_id: 6 as libc::c_int,
            oid: [
                0x2a as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0xf7 as libc::c_int as uint8_t,
                0xd as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0,
                0,
            ],
            oid_len: 9 as libc::c_int as uint8_t,
            pem_str: b"RSA\0" as *const u8 as *const libc::c_char,
            info: b"OpenSSL RSA method\0" as *const u8 as *const libc::c_char,
            pub_decode: Some(
                rsa_pub_decode
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY,
                        *mut CBS,
                        *mut CBS,
                        *mut CBS,
                    ) -> libc::c_int,
            ),
            pub_encode: Some(
                rsa_pub_encode
                    as unsafe extern "C" fn(*mut CBB, *const EVP_PKEY) -> libc::c_int,
            ),
            pub_cmp: Some(
                rsa_pub_cmp
                    as unsafe extern "C" fn(
                        *const EVP_PKEY,
                        *const EVP_PKEY,
                    ) -> libc::c_int,
            ),
            priv_decode: Some(
                rsa_priv_decode
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY,
                        *mut CBS,
                        *mut CBS,
                        *mut CBS,
                        *mut CBS,
                    ) -> libc::c_int,
            ),
            priv_encode: Some(
                rsa_priv_encode
                    as unsafe extern "C" fn(*mut CBB, *const EVP_PKEY) -> libc::c_int,
            ),
            priv_encode_v2: None,
            set_priv_raw: None,
            set_pub_raw: None,
            get_priv_raw: None,
            get_pub_raw: None,
            pkey_opaque: Some(
                rsa_opaque as unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int,
            ),
            pkey_size: Some(
                int_rsa_size as unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int,
            ),
            pkey_bits: Some(
                rsa_bits as unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int,
            ),
            param_missing: None,
            param_copy: None,
            param_cmp: None,
            pkey_free: Some(int_rsa_free as unsafe extern "C" fn(*mut EVP_PKEY) -> ()),
        };
        init
    }
};
#[unsafe(no_mangle)]
pub static mut rsa_pss_asn1_meth: EVP_PKEY_ASN1_METHOD = unsafe {
    {
        let mut init = evp_pkey_asn1_method_st {
            pkey_id: 912 as libc::c_int,
            oid: [
                0x2a as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0xf7 as libc::c_int as uint8_t,
                0xd as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0xa as libc::c_int as uint8_t,
                0,
                0,
            ],
            oid_len: 9 as libc::c_int as uint8_t,
            pem_str: b"RSA-PSS\0" as *const u8 as *const libc::c_char,
            info: b"OpenSSL RSA-PSS method\0" as *const u8 as *const libc::c_char,
            pub_decode: Some(
                rsa_pss_pub_decode
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY,
                        *mut CBS,
                        *mut CBS,
                        *mut CBS,
                    ) -> libc::c_int,
            ),
            pub_encode: None,
            pub_cmp: Some(
                rsa_pub_cmp
                    as unsafe extern "C" fn(
                        *const EVP_PKEY,
                        *const EVP_PKEY,
                    ) -> libc::c_int,
            ),
            priv_decode: Some(
                rsa_pss_priv_decode
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY,
                        *mut CBS,
                        *mut CBS,
                        *mut CBS,
                        *mut CBS,
                    ) -> libc::c_int,
            ),
            priv_encode: None,
            priv_encode_v2: None,
            set_priv_raw: None,
            set_pub_raw: None,
            get_priv_raw: None,
            get_pub_raw: None,
            pkey_opaque: Some(
                rsa_opaque as unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int,
            ),
            pkey_size: Some(
                int_rsa_size as unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int,
            ),
            pkey_bits: Some(
                rsa_bits as unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int,
            ),
            param_missing: None,
            param_copy: None,
            param_cmp: None,
            pkey_free: Some(int_rsa_free as unsafe extern "C" fn(*mut EVP_PKEY) -> ()),
        };
        init
    }
};
