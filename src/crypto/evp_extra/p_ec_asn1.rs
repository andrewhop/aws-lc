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
    pub type bignum_ctx;
    pub type dh_st;
    pub type dsa_st;
    pub type ec_group_st;
    pub type ec_key_st;
    pub type ec_point_st;
    pub type pqdsa_key_st;
    pub type kem_key_st;
    pub type rsa_st;
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBB_flush(cbb: *mut CBB) -> libc::c_int;
    fn CBB_add_asn1(
        cbb: *mut CBB,
        out_contents: *mut CBB,
        tag: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBB_add_bytes(cbb: *mut CBB, data: *const uint8_t, len: size_t) -> libc::c_int;
    fn CBB_add_u8(cbb: *mut CBB, value: uint8_t) -> libc::c_int;
    fn CBB_add_asn1_uint64(cbb: *mut CBB, value: uint64_t) -> libc::c_int;
    fn ECDSA_size(key: *const EC_KEY) -> size_t;
    fn EVP_PKEY_assign_EC_KEY(pkey: *mut EVP_PKEY, key: *mut EC_KEY) -> libc::c_int;
    fn ERR_clear_error();
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn EC_GROUP_cmp(
        a: *const EC_GROUP,
        b: *const EC_GROUP,
        ignored: *mut BN_CTX,
    ) -> libc::c_int;
    fn EC_GROUP_order_bits(group: *const EC_GROUP) -> libc::c_int;
    fn EC_POINT_new(group: *const EC_GROUP) -> *mut EC_POINT;
    fn EC_POINT_free(point: *mut EC_POINT);
    fn EC_POINT_cmp(
        group: *const EC_GROUP,
        a: *const EC_POINT,
        b: *const EC_POINT,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn EC_POINT_point2cbb(
        out: *mut CBB,
        group: *const EC_GROUP,
        point: *const EC_POINT,
        form: point_conversion_form_t,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn EC_POINT_oct2point(
        group: *const EC_GROUP,
        point: *mut EC_POINT,
        buf: *const uint8_t,
        len: size_t,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn EC_KEY_new() -> *mut EC_KEY;
    fn EC_KEY_free(key: *mut EC_KEY);
    fn EC_KEY_is_opaque(key: *const EC_KEY) -> libc::c_int;
    fn EC_KEY_get0_group(key: *const EC_KEY) -> *const EC_GROUP;
    fn EC_KEY_set_group(key: *mut EC_KEY, group: *const EC_GROUP) -> libc::c_int;
    fn EC_KEY_get0_public_key(key: *const EC_KEY) -> *const EC_POINT;
    fn EC_KEY_set_public_key(key: *mut EC_KEY, pub_0: *const EC_POINT) -> libc::c_int;
    fn EC_KEY_get_enc_flags(key: *const EC_KEY) -> libc::c_uint;
    fn EC_KEY_parse_private_key(cbs: *mut CBS, group: *const EC_GROUP) -> *mut EC_KEY;
    fn EC_KEY_marshal_private_key(
        cbb: *mut CBB,
        key: *const EC_KEY,
        enc_flags: libc::c_uint,
    ) -> libc::c_int;
    fn EC_KEY_parse_curve_name(cbs: *mut CBS) -> *mut EC_GROUP;
    fn EC_KEY_marshal_curve_name(cbb: *mut CBB, group: *const EC_GROUP) -> libc::c_int;
    fn EC_KEY_parse_parameters(cbs: *mut CBS) -> *mut EC_GROUP;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type CBS_ASN1_TAG = uint32_t;
pub type BN_CTX = bignum_ctx;
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
pub type EC_POINT = ec_point_st;
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
pub type point_conversion_form_t = libc::c_uint;
pub const POINT_CONVERSION_HYBRID: point_conversion_form_t = 6;
pub const POINT_CONVERSION_UNCOMPRESSED: point_conversion_form_t = 4;
pub const POINT_CONVERSION_COMPRESSED: point_conversion_form_t = 2;
unsafe extern "C" fn eckey_pub_encode(
    mut out: *mut CBB,
    mut key: *const EVP_PKEY,
) -> libc::c_int {
    let mut ec_key: *const EC_KEY = (*key).pkey.ec;
    let mut group: *const EC_GROUP = EC_KEY_get0_group(ec_key);
    let mut public_key: *const EC_POINT = EC_KEY_get0_public_key(ec_key);
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
            (ec_asn1_meth.oid).as_ptr(),
            ec_asn1_meth.oid_len as size_t,
        ) == 0 || EC_KEY_marshal_curve_name(&mut algorithm, group) == 0
        || CBB_add_asn1(&mut spki, &mut key_bitstring, 0x3 as libc::c_uint) == 0
        || CBB_add_u8(&mut key_bitstring, 0 as libc::c_int as uint8_t) == 0
        || EC_POINT_point2cbb(
            &mut key_bitstring,
            group,
            public_key,
            POINT_CONVERSION_UNCOMPRESSED,
            0 as *mut BN_CTX,
        ) == 0 || CBB_flush(out) == 0
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_ec_asn1.c\0"
                as *const u8 as *const libc::c_char,
            86 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn eckey_pub_decode(
    mut out: *mut EVP_PKEY,
    mut oid: *mut CBS,
    mut params: *mut CBS,
    mut key: *mut CBS,
) -> libc::c_int {
    let mut point: *mut EC_POINT = 0 as *mut EC_POINT;
    let mut eckey: *mut EC_KEY = 0 as *mut EC_KEY;
    let mut group: *const EC_GROUP = EC_KEY_parse_curve_name(params);
    if group.is_null() || CBS_len(params) != 0 as libc::c_int as size_t {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_ec_asn1.c\0"
                as *const u8 as *const libc::c_char,
            101 as libc::c_int as libc::c_uint,
        );
    } else {
        eckey = EC_KEY_new();
        if !(eckey.is_null() || EC_KEY_set_group(eckey, group) == 0) {
            point = EC_POINT_new(group);
            if !(point.is_null()
                || EC_POINT_oct2point(
                    group,
                    point,
                    CBS_data(key),
                    CBS_len(key),
                    0 as *mut BN_CTX,
                ) == 0 || EC_KEY_set_public_key(eckey, point) == 0)
            {
                EC_POINT_free(point);
                EVP_PKEY_assign_EC_KEY(out, eckey);
                return 1 as libc::c_int;
            }
        }
    }
    EC_POINT_free(point);
    EC_KEY_free(eckey);
    return 0 as libc::c_int;
}
unsafe extern "C" fn eckey_pub_cmp(
    mut a: *const EVP_PKEY,
    mut b: *const EVP_PKEY,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut group: *const EC_GROUP = EC_KEY_get0_group((*b).pkey.ec);
    let mut pa: *const EC_POINT = EC_KEY_get0_public_key((*a).pkey.ec);
    let mut pb: *const EC_POINT = EC_KEY_get0_public_key((*b).pkey.ec);
    r = EC_POINT_cmp(group, pa, pb, 0 as *mut BN_CTX);
    if r == 0 as libc::c_int {
        return 1 as libc::c_int
    } else if r == 1 as libc::c_int {
        return 0 as libc::c_int
    } else {
        return -(2 as libc::c_int)
    };
}
unsafe extern "C" fn eckey_priv_decode(
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
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_ec_asn1.c\0"
                as *const u8 as *const libc::c_char,
            145 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut group: *const EC_GROUP = EC_KEY_parse_parameters(params);
    if group.is_null() || CBS_len(params) != 0 as libc::c_int as size_t {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_ec_asn1.c\0"
                as *const u8 as *const libc::c_char,
            151 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ec_key: *mut EC_KEY = EC_KEY_parse_private_key(key, group);
    if ec_key.is_null() || CBS_len(key) != 0 as libc::c_int as size_t {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_ec_asn1.c\0"
                as *const u8 as *const libc::c_char,
            157 as libc::c_int as libc::c_uint,
        );
        EC_KEY_free(ec_key);
        return 0 as libc::c_int;
    }
    EVP_PKEY_assign_EC_KEY(out, ec_key);
    return 1 as libc::c_int;
}
unsafe extern "C" fn eckey_priv_encode(
    mut out: *mut CBB,
    mut key: *const EVP_PKEY,
) -> libc::c_int {
    let mut ec_key: *const EC_KEY = (*key).pkey.ec;
    let mut enc_flags: libc::c_uint = EC_KEY_get_enc_flags(ec_key)
        | 0x1 as libc::c_int as libc::c_uint;
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
            (ec_asn1_meth.oid).as_ptr(),
            ec_asn1_meth.oid_len as size_t,
        ) == 0
        || EC_KEY_marshal_curve_name(&mut algorithm, EC_KEY_get0_group(ec_key)) == 0
        || CBB_add_asn1(&mut pkcs8, &mut private_key, 0x4 as libc::c_uint) == 0
        || EC_KEY_marshal_private_key(&mut private_key, ec_key, enc_flags) == 0
        || CBB_flush(out) == 0
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_ec_asn1.c\0"
                as *const u8 as *const libc::c_char,
            186 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn int_ec_size(mut pkey: *const EVP_PKEY) -> libc::c_int {
    return ECDSA_size((*pkey).pkey.ec) as libc::c_int;
}
unsafe extern "C" fn ec_bits(mut pkey: *const EVP_PKEY) -> libc::c_int {
    let mut group: *const EC_GROUP = EC_KEY_get0_group((*pkey).pkey.ec);
    if group.is_null() {
        ERR_clear_error();
        return 0 as libc::c_int;
    }
    return EC_GROUP_order_bits(group);
}
unsafe extern "C" fn ec_missing_parameters(mut pkey: *const EVP_PKEY) -> libc::c_int {
    return (((*pkey).pkey.ec).is_null()
        || (EC_KEY_get0_group((*pkey).pkey.ec)).is_null()) as libc::c_int;
}
unsafe extern "C" fn ec_copy_parameters(
    mut to: *mut EVP_PKEY,
    mut from: *const EVP_PKEY,
) -> libc::c_int {
    if ((*from).pkey.ec).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            120 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_ec_asn1.c\0"
                as *const u8 as *const libc::c_char,
            212 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut group: *const EC_GROUP = EC_KEY_get0_group((*from).pkey.ec);
    if group.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            118 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_ec_asn1.c\0"
                as *const u8 as *const libc::c_char,
            217 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*to).pkey.ec).is_null() {
        (*to).pkey.ec = EC_KEY_new();
        if ((*to).pkey.ec).is_null() {
            return 0 as libc::c_int;
        }
    }
    return EC_KEY_set_group((*to).pkey.ec, group);
}
unsafe extern "C" fn ec_cmp_parameters(
    mut a: *const EVP_PKEY,
    mut b: *const EVP_PKEY,
) -> libc::c_int {
    if ((*a).pkey.ec).is_null() || ((*b).pkey.ec).is_null() {
        return -(2 as libc::c_int);
    }
    let mut group_a: *const EC_GROUP = EC_KEY_get0_group((*a).pkey.ec);
    let mut group_b: *const EC_GROUP = EC_KEY_get0_group((*b).pkey.ec);
    if group_a.is_null() || group_b.is_null() {
        return -(2 as libc::c_int);
    }
    if EC_GROUP_cmp(group_a, group_b, 0 as *mut BN_CTX) != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn int_ec_free(mut pkey: *mut EVP_PKEY) {
    EC_KEY_free((*pkey).pkey.ec);
}
unsafe extern "C" fn eckey_opaque(mut pkey: *const EVP_PKEY) -> libc::c_int {
    return EC_KEY_is_opaque((*pkey).pkey.ec);
}
#[no_mangle]
pub static mut ec_asn1_meth: EVP_PKEY_ASN1_METHOD = unsafe {
    {
        let mut init = evp_pkey_asn1_method_st {
            pkey_id: 408 as libc::c_int,
            oid: [
                0x2a as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0xce as libc::c_int as uint8_t,
                0x3d as libc::c_int as uint8_t,
                0x2 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0,
                0,
                0,
                0,
            ],
            oid_len: 7 as libc::c_int as uint8_t,
            pem_str: b"EC\0" as *const u8 as *const libc::c_char,
            info: b"OpenSSL EC algorithm\0" as *const u8 as *const libc::c_char,
            pub_decode: Some(
                eckey_pub_decode
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY,
                        *mut CBS,
                        *mut CBS,
                        *mut CBS,
                    ) -> libc::c_int,
            ),
            pub_encode: Some(
                eckey_pub_encode
                    as unsafe extern "C" fn(*mut CBB, *const EVP_PKEY) -> libc::c_int,
            ),
            pub_cmp: Some(
                eckey_pub_cmp
                    as unsafe extern "C" fn(
                        *const EVP_PKEY,
                        *const EVP_PKEY,
                    ) -> libc::c_int,
            ),
            priv_decode: Some(
                eckey_priv_decode
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY,
                        *mut CBS,
                        *mut CBS,
                        *mut CBS,
                        *mut CBS,
                    ) -> libc::c_int,
            ),
            priv_encode: Some(
                eckey_priv_encode
                    as unsafe extern "C" fn(*mut CBB, *const EVP_PKEY) -> libc::c_int,
            ),
            priv_encode_v2: None,
            set_priv_raw: None,
            set_pub_raw: None,
            get_priv_raw: None,
            get_pub_raw: None,
            pkey_opaque: Some(
                eckey_opaque as unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int,
            ),
            pkey_size: Some(
                int_ec_size as unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int,
            ),
            pkey_bits: Some(
                ec_bits as unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int,
            ),
            param_missing: Some(
                ec_missing_parameters
                    as unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int,
            ),
            param_copy: Some(
                ec_copy_parameters
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY,
                        *const EVP_PKEY,
                    ) -> libc::c_int,
            ),
            param_cmp: Some(
                ec_cmp_parameters
                    as unsafe extern "C" fn(
                        *const EVP_PKEY,
                        *const EVP_PKEY,
                    ) -> libc::c_int,
            ),
            pkey_free: Some(int_ec_free as unsafe extern "C" fn(*mut EVP_PKEY) -> ()),
        };
        init
    }
};
