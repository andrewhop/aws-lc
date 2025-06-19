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
    pub type bignum_ctx;
    pub type stack_st_void;
    pub type dh_st;
    pub type ec_key_st;
    pub type pqdsa_key_st;
    pub type kem_key_st;
    pub type rsa_st;
    fn DSA_new() -> *mut DSA;
    fn DSA_free(dsa: *mut DSA);
    fn DSA_size(dsa: *const DSA) -> libc::c_int;
    fn DSA_parse_parameters(cbs: *mut CBS) -> *mut DSA;
    fn DSA_marshal_parameters(cbb: *mut CBB, dsa: *const DSA) -> libc::c_int;
    fn BN_new() -> *mut BIGNUM;
    fn BN_free(bn: *mut BIGNUM);
    fn BN_dup(src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_num_bits(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_parse_asn1_unsigned(cbs: *mut CBS, ret: *mut BIGNUM) -> libc::c_int;
    fn BN_marshal_asn1(cbb: *mut CBB, bn: *const BIGNUM) -> libc::c_int;
    fn BN_CTX_new() -> *mut BN_CTX;
    fn BN_CTX_free(ctx: *mut BN_CTX);
    fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_mod_exp_mont_consttime(
        rr: *mut BIGNUM,
        a: *const BIGNUM,
        p: *const BIGNUM,
        m: *const BIGNUM,
        ctx: *mut BN_CTX,
        mont: *const BN_MONT_CTX,
    ) -> libc::c_int;
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
    fn dsa_check_key(dsa: *const DSA) -> libc::c_int;
    fn EVP_PKEY_assign_DSA(pkey: *mut EVP_PKEY, key: *mut DSA) -> libc::c_int;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
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
pub type BN_CTX = bignum_ctx;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dsa_st {
    pub p: *mut BIGNUM,
    pub q: *mut BIGNUM,
    pub g: *mut BIGNUM,
    pub pub_key: *mut BIGNUM,
    pub priv_key: *mut BIGNUM,
    pub method_mont_lock: CRYPTO_MUTEX,
    pub method_mont_p: *mut BN_MONT_CTX,
    pub method_mont_q: *mut BN_MONT_CTX,
    pub references: CRYPTO_refcount_t,
    pub ex_data: CRYPTO_EX_DATA,
}
pub type CRYPTO_MUTEX = crypto_mutex_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub union crypto_mutex_st {
    pub alignment: libc::c_double,
    pub padding: [uint8_t; 56],
}
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
unsafe extern "C" fn dsa_pub_decode(
    mut out: *mut EVP_PKEY,
    mut oid: *mut CBS,
    mut params: *mut CBS,
    mut key: *mut CBS,
) -> libc::c_int {
    let mut current_block: u64;
    let mut dsa: *mut DSA = 0 as *mut DSA;
    if CBS_len(params) == 0 as libc::c_int as size_t {
        dsa = DSA_new();
        if dsa.is_null() {
            return 0 as libc::c_int;
        }
        current_block = 6937071982253665452;
    } else {
        dsa = DSA_parse_parameters(params);
        if dsa.is_null() || CBS_len(params) != 0 as libc::c_int as size_t {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                102 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                82 as libc::c_int as libc::c_uint,
            );
            current_block = 11816884181894971774;
        } else {
            current_block = 6937071982253665452;
        }
    }
    match current_block {
        6937071982253665452 => {
            (*dsa).pub_key = BN_new();
            if !((*dsa).pub_key).is_null() {
                if BN_parse_asn1_unsigned(key, (*dsa).pub_key) == 0
                    || CBS_len(key) != 0 as libc::c_int as size_t
                {
                    ERR_put_error(
                        6 as libc::c_int,
                        0 as libc::c_int,
                        102 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa_asn1.c\0"
                            as *const u8 as *const libc::c_char,
                        94 as libc::c_int as libc::c_uint,
                    );
                } else if 1 as libc::c_int == EVP_PKEY_assign_DSA(out, dsa) {
                    return 1 as libc::c_int
                }
            }
        }
        _ => {}
    }
    DSA_free(dsa);
    return 0 as libc::c_int;
}
unsafe extern "C" fn dsa_pub_encode(
    mut out: *mut CBB,
    mut key: *const EVP_PKEY,
) -> libc::c_int {
    let mut dsa: *const DSA = (*key).pkey.dsa;
    let has_params: libc::c_int = (!((*dsa).p).is_null() && !((*dsa).q).is_null()
        && !((*dsa).g).is_null()) as libc::c_int;
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
            (dsa_asn1_meth.oid).as_ptr(),
            dsa_asn1_meth.oid_len as size_t,
        ) == 0 || has_params != 0 && DSA_marshal_parameters(&mut algorithm, dsa) == 0
        || CBB_add_asn1(&mut spki, &mut key_bitstring, 0x3 as libc::c_uint) == 0
        || CBB_add_u8(&mut key_bitstring, 0 as libc::c_int as uint8_t) == 0
        || BN_marshal_asn1(&mut key_bitstring, (*dsa).pub_key) == 0
        || CBB_flush(out) == 0
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            123 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn dsa_priv_decode(
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
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            133 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ctx: *mut BN_CTX = 0 as *mut BN_CTX;
    let mut dsa: *mut DSA = DSA_parse_parameters(params);
    if dsa.is_null() || CBS_len(params) != 0 as libc::c_int as size_t {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            141 as libc::c_int as libc::c_uint,
        );
    } else {
        (*dsa).priv_key = BN_new();
        if !((*dsa).priv_key).is_null() {
            if BN_parse_asn1_unsigned(key, (*dsa).priv_key) == 0
                || CBS_len(key) != 0 as libc::c_int as size_t
            {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    102 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa_asn1.c\0"
                        as *const u8 as *const libc::c_char,
                    151 as libc::c_int as libc::c_uint,
                );
            } else if dsa_check_key(dsa) == 0 {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    102 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa_asn1.c\0"
                        as *const u8 as *const libc::c_char,
                    159 as libc::c_int as libc::c_uint,
                );
            } else {
                ctx = BN_CTX_new();
                (*dsa).pub_key = BN_new();
                if !(ctx.is_null() || ((*dsa).pub_key).is_null()
                    || BN_mod_exp_mont_consttime(
                        (*dsa).pub_key,
                        (*dsa).g,
                        (*dsa).priv_key,
                        (*dsa).p,
                        ctx,
                        0 as *const BN_MONT_CTX,
                    ) == 0)
                {
                    if 1 as libc::c_int == EVP_PKEY_assign_DSA(out, dsa) {
                        BN_CTX_free(ctx);
                        return 1 as libc::c_int;
                    }
                }
            }
        }
    }
    BN_CTX_free(ctx);
    DSA_free(dsa);
    return 0 as libc::c_int;
}
unsafe extern "C" fn dsa_priv_encode(
    mut out: *mut CBB,
    mut key: *const EVP_PKEY,
) -> libc::c_int {
    let mut dsa: *const DSA = (*key).pkey.dsa;
    if dsa.is_null() || ((*dsa).priv_key).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            118 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            186 as libc::c_int as libc::c_uint,
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
            (dsa_asn1_meth.oid).as_ptr(),
            dsa_asn1_meth.oid_len as size_t,
        ) == 0 || DSA_marshal_parameters(&mut algorithm, dsa) == 0
        || CBB_add_asn1(&mut pkcs8, &mut private_key, 0x4 as libc::c_uint) == 0
        || BN_marshal_asn1(&mut private_key, (*dsa).priv_key) == 0 || CBB_flush(out) == 0
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            201 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn int_dsa_size(mut pkey: *const EVP_PKEY) -> libc::c_int {
    return DSA_size((*pkey).pkey.dsa);
}
unsafe extern "C" fn dsa_bits(mut pkey: *const EVP_PKEY) -> libc::c_int {
    return BN_num_bits((*(*pkey).pkey.dsa).p) as libc::c_int;
}
unsafe extern "C" fn dsa_missing_parameters(mut pkey: *const EVP_PKEY) -> libc::c_int {
    let mut dsa: *mut DSA = 0 as *mut DSA;
    dsa = (*pkey).pkey.dsa;
    if ((*dsa).p).is_null() || ((*dsa).q).is_null() || ((*dsa).g).is_null() {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn dup_bn_into(
    mut out: *mut *mut BIGNUM,
    mut src: *mut BIGNUM,
) -> libc::c_int {
    let mut a: *mut BIGNUM = 0 as *mut BIGNUM;
    a = BN_dup(src);
    if a.is_null() {
        return 0 as libc::c_int;
    }
    BN_free(*out);
    *out = a;
    return 1 as libc::c_int;
}
unsafe extern "C" fn dsa_copy_parameters(
    mut to: *mut EVP_PKEY,
    mut from: *const EVP_PKEY,
) -> libc::c_int {
    if dup_bn_into(&mut (*(*to).pkey.dsa).p, (*(*from).pkey.dsa).p) == 0
        || dup_bn_into(&mut (*(*to).pkey.dsa).q, (*(*from).pkey.dsa).q) == 0
        || dup_bn_into(&mut (*(*to).pkey.dsa).g, (*(*from).pkey.dsa).g) == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn dsa_cmp_parameters(
    mut a: *const EVP_PKEY,
    mut b: *const EVP_PKEY,
) -> libc::c_int {
    return (BN_cmp((*(*a).pkey.dsa).p, (*(*b).pkey.dsa).p) == 0 as libc::c_int
        && BN_cmp((*(*a).pkey.dsa).q, (*(*b).pkey.dsa).q) == 0 as libc::c_int
        && BN_cmp((*(*a).pkey.dsa).g, (*(*b).pkey.dsa).g) == 0 as libc::c_int)
        as libc::c_int;
}
unsafe extern "C" fn dsa_pub_cmp(
    mut a: *const EVP_PKEY,
    mut b: *const EVP_PKEY,
) -> libc::c_int {
    return (BN_cmp((*(*b).pkey.dsa).pub_key, (*(*a).pkey.dsa).pub_key)
        == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn int_dsa_free(mut pkey: *mut EVP_PKEY) {
    DSA_free((*pkey).pkey.dsa);
}
#[unsafe(no_mangle)]
pub static mut dsa_asn1_meth: EVP_PKEY_ASN1_METHOD = unsafe {
    {
        let mut init = evp_pkey_asn1_method_st {
            pkey_id: 116 as libc::c_int,
            oid: [
                0x2a as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0xce as libc::c_int as uint8_t,
                0x38 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0,
                0,
                0,
                0,
            ],
            oid_len: 7 as libc::c_int as uint8_t,
            pem_str: b"DSA\0" as *const u8 as *const libc::c_char,
            info: b"OpenSSL DSA method\0" as *const u8 as *const libc::c_char,
            pub_decode: Some(
                dsa_pub_decode
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY,
                        *mut CBS,
                        *mut CBS,
                        *mut CBS,
                    ) -> libc::c_int,
            ),
            pub_encode: Some(
                dsa_pub_encode
                    as unsafe extern "C" fn(*mut CBB, *const EVP_PKEY) -> libc::c_int,
            ),
            pub_cmp: Some(
                dsa_pub_cmp
                    as unsafe extern "C" fn(
                        *const EVP_PKEY,
                        *const EVP_PKEY,
                    ) -> libc::c_int,
            ),
            priv_decode: Some(
                dsa_priv_decode
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY,
                        *mut CBS,
                        *mut CBS,
                        *mut CBS,
                        *mut CBS,
                    ) -> libc::c_int,
            ),
            priv_encode: Some(
                dsa_priv_encode
                    as unsafe extern "C" fn(*mut CBB, *const EVP_PKEY) -> libc::c_int,
            ),
            priv_encode_v2: None,
            set_priv_raw: None,
            set_pub_raw: None,
            get_priv_raw: None,
            get_pub_raw: None,
            pkey_opaque: None,
            pkey_size: Some(
                int_dsa_size as unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int,
            ),
            pkey_bits: Some(
                dsa_bits as unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int,
            ),
            param_missing: Some(
                dsa_missing_parameters
                    as unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int,
            ),
            param_copy: Some(
                dsa_copy_parameters
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY,
                        *const EVP_PKEY,
                    ) -> libc::c_int,
            ),
            param_cmp: Some(
                dsa_cmp_parameters
                    as unsafe extern "C" fn(
                        *const EVP_PKEY,
                        *const EVP_PKEY,
                    ) -> libc::c_int,
            ),
            pkey_free: Some(int_dsa_free as unsafe extern "C" fn(*mut EVP_PKEY) -> ()),
        };
        init
    }
};
