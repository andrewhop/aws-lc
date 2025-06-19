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
    pub type pqdsa_key_st;
    pub type kem_key_st;
    pub type ec_key_st;
    pub type dsa_st;
    pub type rsa_st;
    fn BN_new() -> *mut BIGNUM;
    fn BN_free(bn: *mut BIGNUM);
    fn BN_dup(src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_parse_asn1_unsigned(cbs: *mut CBS, ret: *mut BIGNUM) -> libc::c_int;
    fn BN_marshal_asn1(cbb: *mut CBB, bn: *const BIGNUM) -> libc::c_int;
    fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBB_flush(cbb: *mut CBB) -> libc::c_int;
    fn CBB_add_asn1(
        cbb: *mut CBB,
        out_contents: *mut CBB,
        tag: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBB_add_bytes(cbb: *mut CBB, data: *const uint8_t, len: size_t) -> libc::c_int;
    fn CBB_add_u8(cbb: *mut CBB, value: uint8_t) -> libc::c_int;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn DH_free(dh: *mut DH);
    fn DH_up_ref(dh: *mut DH) -> libc::c_int;
    fn DH_bits(dh: *const DH) -> libc::c_uint;
    fn DH_get0_pub_key(dh: *const DH) -> *const BIGNUM;
    fn DH_get0_p(dh: *const DH) -> *const BIGNUM;
    fn DH_get0_q(dh: *const DH) -> *const BIGNUM;
    fn DH_get0_g(dh: *const DH) -> *const BIGNUM;
    fn DH_set0_pqg(
        dh: *mut DH,
        p: *mut BIGNUM,
        q: *mut BIGNUM,
        g: *mut BIGNUM,
    ) -> libc::c_int;
    fn DH_size(dh: *const DH) -> libc::c_int;
    fn DH_check_pub_key(
        dh: *const DH,
        pub_key: *const BIGNUM,
        out_flags: *mut libc::c_int,
    ) -> libc::c_int;
    fn DH_parse_parameters(cbs: *mut CBS) -> *mut DH;
    fn DH_marshal_parameters(cbb: *mut CBB, dh: *const DH) -> libc::c_int;
    fn evp_pkey_set_method(pkey: *mut EVP_PKEY, method: *const EVP_PKEY_ASN1_METHOD);
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type CBS_ASN1_TAG = uint32_t;
pub type BIGNUM = bignum_st;
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
pub type CBB = cbb_st;
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
pub type CBS = cbs_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cbs_st {
    pub data: *const uint8_t,
    pub len: size_t,
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
pub type EC_KEY = ec_key_st;
pub type DH = dh_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dh_st {
    pub p: *mut BIGNUM,
    pub g: *mut BIGNUM,
    pub q: *mut BIGNUM,
    pub pub_key: *mut BIGNUM,
    pub priv_key: *mut BIGNUM,
    pub priv_length: libc::c_uint,
    pub method_mont_p_lock: CRYPTO_MUTEX,
    pub method_mont_p: *mut BN_MONT_CTX,
    pub flags: libc::c_int,
    pub references: CRYPTO_refcount_t,
}
pub type CRYPTO_refcount_t = uint32_t;
pub type BN_MONT_CTX = bn_mont_ctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bn_mont_ctx_st {
    pub RR: BIGNUM,
    pub N: BIGNUM,
    pub n0: [BN_ULONG; 2],
}
pub type CRYPTO_MUTEX = crypto_mutex_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub union crypto_mutex_st {
    pub alignment: libc::c_double,
    pub padding: [uint8_t; 56],
}
pub type DSA = dsa_st;
pub type RSA = rsa_st;
unsafe extern "C" fn dh_pub_encode(
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
            (dh_asn1_meth.oid).as_ptr(),
            dh_asn1_meth.oid_len as size_t,
        ) == 0 || DH_marshal_parameters(&mut algorithm, (*key).pkey.dh) == 0
        || CBB_add_asn1(&mut spki, &mut key_bitstring, 0x3 as libc::c_uint) == 0
        || CBB_add_u8(&mut key_bitstring, 0 as libc::c_int as uint8_t) == 0
        || BN_marshal_asn1(&mut key_bitstring, (*(*key).pkey.dh).pub_key) == 0
        || CBB_flush(out) == 0
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dh_asn1.c\0"
                as *const u8 as *const libc::c_char,
            33 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn dh_pub_decode(
    mut out: *mut EVP_PKEY,
    mut oid: *mut CBS,
    mut params: *mut CBS,
    mut key: *mut CBS,
) -> libc::c_int {
    let mut out_flags: libc::c_int = 0;
    let mut pubkey: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut dh: *mut DH = 0 as *mut DH;
    if out.is_null() || params.is_null() || CBS_len(params) == 0 as libc::c_int as size_t
        || key.is_null() || CBS_len(key) == 0 as libc::c_int as size_t
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dh_asn1.c\0"
                as *const u8 as *const libc::c_char,
            46 as libc::c_int as libc::c_uint,
        );
    } else {
        dh = DH_parse_parameters(params);
        if dh.is_null() {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                102 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dh_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                52 as libc::c_int as libc::c_uint,
            );
        } else {
            pubkey = BN_new();
            if pubkey.is_null() || BN_parse_asn1_unsigned(key, pubkey) == 0 {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    102 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dh_asn1.c\0"
                        as *const u8 as *const libc::c_char,
                    58 as libc::c_int as libc::c_uint,
                );
            } else {
                out_flags = 0 as libc::c_int;
                if DH_check_pub_key(dh, pubkey, &mut out_flags) == 0
                    || out_flags != 0 as libc::c_int
                {
                    ERR_put_error(
                        6 as libc::c_int,
                        0 as libc::c_int,
                        102 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dh_asn1.c\0"
                            as *const u8 as *const libc::c_char,
                        64 as libc::c_int as libc::c_uint,
                    );
                } else {
                    (*dh).pub_key = pubkey;
                    if EVP_PKEY_assign_DH(out, dh) == 0 {
                        ERR_put_error(
                            6 as libc::c_int,
                            0 as libc::c_int,
                            102 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dh_asn1.c\0"
                                as *const u8 as *const libc::c_char,
                            70 as libc::c_int as libc::c_uint,
                        );
                    } else {
                        return 1 as libc::c_int
                    }
                }
            }
        }
    }
    DH_free(dh);
    BN_free(pubkey);
    return 0 as libc::c_int;
}
unsafe extern "C" fn dh_free(mut pkey: *mut EVP_PKEY) {
    DH_free((*pkey).pkey.dh);
    (*pkey).pkey.dh = 0 as *mut DH;
}
unsafe extern "C" fn dh_size(mut pkey: *const EVP_PKEY) -> libc::c_int {
    return DH_size((*pkey).pkey.dh);
}
unsafe extern "C" fn dh_bits(mut pkey: *const EVP_PKEY) -> libc::c_int {
    return DH_bits((*pkey).pkey.dh) as libc::c_int;
}
unsafe extern "C" fn dh_param_missing(mut pkey: *const EVP_PKEY) -> libc::c_int {
    let mut dh: *const DH = (*pkey).pkey.dh;
    return (dh.is_null() || (DH_get0_p(dh)).is_null() || (DH_get0_g(dh)).is_null())
        as libc::c_int;
}
unsafe extern "C" fn dh_param_copy(
    mut to: *mut EVP_PKEY,
    mut from: *const EVP_PKEY,
) -> libc::c_int {
    if dh_param_missing(from) != 0 {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            118 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dh_asn1.c\0"
                as *const u8 as *const libc::c_char,
            98 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut dh: *const DH = (*from).pkey.dh;
    let mut q_old: *const BIGNUM = DH_get0_q(dh);
    let mut p: *mut BIGNUM = BN_dup(DH_get0_p(dh));
    let mut q: *mut BIGNUM = if q_old.is_null() {
        0 as *mut BIGNUM
    } else {
        BN_dup(q_old)
    };
    let mut g: *mut BIGNUM = BN_dup(DH_get0_g(dh));
    if p.is_null() || !q_old.is_null() && q.is_null() || g.is_null()
        || DH_set0_pqg((*to).pkey.dh, p, q, g) == 0
    {
        BN_free(p);
        BN_free(q);
        BN_free(g);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn dh_param_cmp(
    mut a: *const EVP_PKEY,
    mut b: *const EVP_PKEY,
) -> libc::c_int {
    if dh_param_missing(a) != 0 || dh_param_missing(b) != 0 {
        return -(2 as libc::c_int);
    }
    let mut a_dh: *const DH = (*a).pkey.dh;
    let mut b_dh: *const DH = (*b).pkey.dh;
    return (BN_cmp(DH_get0_p(a_dh), DH_get0_p(b_dh)) == 0 as libc::c_int
        && BN_cmp(DH_get0_g(a_dh), DH_get0_g(b_dh)) == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn dh_pub_cmp(
    mut a: *const EVP_PKEY,
    mut b: *const EVP_PKEY,
) -> libc::c_int {
    if dh_param_cmp(a, b) <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut a_dh: *const DH = (*a).pkey.dh;
    let mut b_dh: *const DH = (*b).pkey.dh;
    return (BN_cmp(DH_get0_pub_key(a_dh), DH_get0_pub_key(b_dh)) == 0 as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub static mut dh_asn1_meth: EVP_PKEY_ASN1_METHOD = unsafe {
    {
        let mut init = evp_pkey_asn1_method_st {
            pkey_id: 28 as libc::c_int,
            oid: [
                0x2a as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0xf7 as libc::c_int as uint8_t,
                0xd as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0,
                0,
            ],
            oid_len: 9 as libc::c_int as uint8_t,
            pem_str: b"DH\0" as *const u8 as *const libc::c_char,
            info: b"OpenSSL PKCS#3 DH method\0" as *const u8 as *const libc::c_char,
            pub_decode: Some(
                dh_pub_decode
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY,
                        *mut CBS,
                        *mut CBS,
                        *mut CBS,
                    ) -> libc::c_int,
            ),
            pub_encode: Some(
                dh_pub_encode
                    as unsafe extern "C" fn(*mut CBB, *const EVP_PKEY) -> libc::c_int,
            ),
            pub_cmp: Some(
                dh_pub_cmp
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
            get_priv_raw: None,
            get_pub_raw: None,
            pkey_opaque: None,
            pkey_size: Some(
                dh_size as unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int,
            ),
            pkey_bits: Some(
                dh_bits as unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int,
            ),
            param_missing: Some(
                dh_param_missing as unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int,
            ),
            param_copy: Some(
                dh_param_copy
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY,
                        *const EVP_PKEY,
                    ) -> libc::c_int,
            ),
            param_cmp: Some(
                dh_param_cmp
                    as unsafe extern "C" fn(
                        *const EVP_PKEY,
                        *const EVP_PKEY,
                    ) -> libc::c_int,
            ),
            pkey_free: Some(dh_free as unsafe extern "C" fn(*mut EVP_PKEY) -> ()),
        };
        init
    }
};
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_set1_DH(
    mut pkey: *mut EVP_PKEY,
    mut key: *mut DH,
) -> libc::c_int {
    if EVP_PKEY_assign_DH(pkey, key) != 0 {
        DH_up_ref(key);
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_assign_DH(
    mut pkey: *mut EVP_PKEY,
    mut key: *mut DH,
) -> libc::c_int {
    evp_pkey_set_method(pkey, &dh_asn1_meth);
    (*pkey).pkey.dh = key;
    return (key != 0 as *mut libc::c_void as *mut DH) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get0_DH(mut pkey: *const EVP_PKEY) -> *mut DH {
    if (*pkey).type_0 != 28 as libc::c_int {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            139 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dh_asn1.c\0"
                as *const u8 as *const libc::c_char,
            182 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut DH;
    }
    return (*pkey).pkey.dh;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get1_DH(mut pkey: *const EVP_PKEY) -> *mut DH {
    let mut dh: *mut DH = EVP_PKEY_get0_DH(pkey);
    if !dh.is_null() {
        DH_up_ref(dh);
    }
    return dh;
}
