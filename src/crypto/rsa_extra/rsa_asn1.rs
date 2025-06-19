#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(extern_types, label_break_value)]
extern "C" {
    pub type bn_blinding_st;
    pub type stack_st_void;
    pub type rsassa_pss_params_st;
    fn BN_new() -> *mut BIGNUM;
    fn BN_free(bn: *mut BIGNUM);
    fn BN_parse_asn1_unsigned(cbs: *mut CBS, ret: *mut BIGNUM) -> libc::c_int;
    fn BN_marshal_asn1(cbb: *mut CBB, bn: *const BIGNUM) -> libc::c_int;
    fn BN_is_zero(bn: *const BIGNUM) -> libc::c_int;
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_get_asn1(
        cbs: *mut CBS,
        out: *mut CBS,
        tag_value: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBS_get_asn1_uint64(cbs: *mut CBS, out: *mut uint64_t) -> libc::c_int;
    fn CBB_zero(cbb: *mut CBB);
    fn CBB_init(cbb: *mut CBB, initial_capacity: size_t) -> libc::c_int;
    fn CBB_cleanup(cbb: *mut CBB);
    fn CBB_finish(
        cbb: *mut CBB,
        out_data: *mut *mut uint8_t,
        out_len: *mut size_t,
    ) -> libc::c_int;
    fn CBB_flush(cbb: *mut CBB) -> libc::c_int;
    fn CBB_add_asn1(
        cbb: *mut CBB,
        out_contents: *mut CBB,
        tag: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBB_add_asn1_uint64(cbb: *mut CBB, value: uint64_t) -> libc::c_int;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn RSA_new() -> *mut RSA;
    fn RSA_free(rsa: *mut RSA);
    fn RSA_check_key(rsa: *const RSA) -> libc::c_int;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn CBB_finish_i2d(cbb: *mut CBB, outp: *mut *mut uint8_t) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
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
pub type CRYPTO_refcount_t = uint32_t;
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
pub type RSASSA_PSS_PARAMS = rsassa_pss_params_st;
pub type RSA_METHOD = rsa_meth_st;
unsafe extern "C" fn parse_integer(
    mut cbs: *mut CBS,
    mut out: *mut *mut BIGNUM,
) -> libc::c_int {
    if (*out).is_null() {} else {
        __assert_fail(
            b"*out == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            73 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 36],
                &[libc::c_char; 36],
            >(b"int parse_integer(CBS *, BIGNUM **)\0"))
                .as_ptr(),
        );
    }
    'c_4543: {
        if (*out).is_null() {} else {
            __assert_fail(
                b"*out == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                73 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 36],
                    &[libc::c_char; 36],
                >(b"int parse_integer(CBS *, BIGNUM **)\0"))
                    .as_ptr(),
            );
        }
    };
    *out = BN_new();
    if (*out).is_null() {
        return 0 as libc::c_int;
    }
    return BN_parse_asn1_unsigned(cbs, *out);
}
unsafe extern "C" fn marshal_integer(
    mut cbb: *mut CBB,
    mut bn: *mut BIGNUM,
) -> libc::c_int {
    if bn.is_null() {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            144 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            84 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return BN_marshal_asn1(cbb, bn);
}
#[no_mangle]
pub unsafe extern "C" fn RSA_parse_public_key(mut cbs: *mut CBS) -> *mut RSA {
    let mut ret: *mut RSA = RSA_new();
    if ret.is_null() {
        return 0 as *mut RSA;
    }
    let mut child: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_get_asn1(
        cbs,
        &mut child,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || parse_integer(&mut child, &mut (*ret).n) == 0
        || parse_integer(&mut child, &mut (*ret).e) == 0
        || CBS_len(&mut child) != 0 as libc::c_int as size_t
    {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            100 as libc::c_int as libc::c_uint,
        );
        RSA_free(ret);
        return 0 as *mut RSA;
    }
    if RSA_check_key(ret) == 0 {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            106 as libc::c_int as libc::c_uint,
        );
        RSA_free(ret);
        return 0 as *mut RSA;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_public_key_from_bytes(
    mut in_0: *const uint8_t,
    mut in_len: size_t,
) -> *mut RSA {
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, in_0, in_len);
    let mut ret: *mut RSA = RSA_parse_public_key(&mut cbs);
    if ret.is_null() || CBS_len(&mut cbs) != 0 as libc::c_int as size_t {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            119 as libc::c_int as libc::c_uint,
        );
        RSA_free(ret);
        return 0 as *mut RSA;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_marshal_public_key(
    mut cbb: *mut CBB,
    mut rsa: *const RSA,
) -> libc::c_int {
    let mut child: CBB = cbb_st {
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
        cbb,
        &mut child,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || marshal_integer(&mut child, (*rsa).n) == 0
        || marshal_integer(&mut child, (*rsa).e) == 0 || CBB_flush(cbb) == 0
    {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            121 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            132 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_public_key_to_bytes(
    mut out_bytes: *mut *mut uint8_t,
    mut out_len: *mut size_t,
    mut rsa: *const RSA,
) -> libc::c_int {
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
    CBB_zero(&mut cbb);
    if CBB_init(&mut cbb, 0 as libc::c_int as size_t) == 0
        || RSA_marshal_public_key(&mut cbb, rsa) == 0
        || CBB_finish(&mut cbb, out_bytes, out_len) == 0
    {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            121 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            145 as libc::c_int as libc::c_uint,
        );
        CBB_cleanup(&mut cbb);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
static mut kVersionTwoPrime: uint64_t = 0 as libc::c_int as uint64_t;
unsafe extern "C" fn detect_stripped_jca_private_key(mut key: *mut RSA) {
    if BN_is_zero((*key).d) == 0 && BN_is_zero((*key).n) == 0
        && BN_is_zero((*key).e) != 0 && BN_is_zero((*key).iqmp) != 0
        && BN_is_zero((*key).p) != 0 && BN_is_zero((*key).q) != 0
        && BN_is_zero((*key).dmp1) != 0 && BN_is_zero((*key).dmq1) != 0
    {
        BN_free((*key).e);
        BN_free((*key).p);
        BN_free((*key).q);
        BN_free((*key).dmp1);
        BN_free((*key).dmq1);
        BN_free((*key).iqmp);
        (*key).e = 0 as *mut BIGNUM;
        (*key).p = 0 as *mut BIGNUM;
        (*key).q = 0 as *mut BIGNUM;
        (*key).dmp1 = 0 as *mut BIGNUM;
        (*key).dmq1 = 0 as *mut BIGNUM;
        (*key).iqmp = 0 as *mut BIGNUM;
        (*key).flags |= 0x40 as libc::c_int;
    }
}
#[no_mangle]
pub unsafe extern "C" fn RSA_parse_private_key(mut cbs: *mut CBS) -> *mut RSA {
    let mut ret: *mut RSA = RSA_new();
    if ret.is_null() {
        return 0 as *mut RSA;
    }
    let mut child: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut version: uint64_t = 0;
    if CBS_get_asn1(
        cbs,
        &mut child,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || CBS_get_asn1_uint64(&mut child, &mut version) == 0
    {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            191 as libc::c_int as libc::c_uint,
        );
    } else if version != kVersionTwoPrime {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            196 as libc::c_int as libc::c_uint,
        );
    } else if !(parse_integer(&mut child, &mut (*ret).n) == 0
        || parse_integer(&mut child, &mut (*ret).e) == 0
        || parse_integer(&mut child, &mut (*ret).d) == 0
        || parse_integer(&mut child, &mut (*ret).p) == 0
        || parse_integer(&mut child, &mut (*ret).q) == 0
        || parse_integer(&mut child, &mut (*ret).dmp1) == 0
        || parse_integer(&mut child, &mut (*ret).dmq1) == 0
        || parse_integer(&mut child, &mut (*ret).iqmp) == 0)
    {
        if CBS_len(&mut child) != 0 as libc::c_int as size_t {
            ERR_put_error(
                4 as libc::c_int,
                0 as libc::c_int,
                100 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                212 as libc::c_int as libc::c_uint,
            );
        } else {
            detect_stripped_jca_private_key(ret);
            if RSA_check_key(ret) == 0 {
                ERR_put_error(
                    4 as libc::c_int,
                    0 as libc::c_int,
                    104 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_asn1.c\0"
                        as *const u8 as *const libc::c_char,
                    219 as libc::c_int as libc::c_uint,
                );
            } else {
                return ret
            }
        }
    }
    RSA_free(ret);
    return 0 as *mut RSA;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_private_key_from_bytes(
    mut in_0: *const uint8_t,
    mut in_len: size_t,
) -> *mut RSA {
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, in_0, in_len);
    let mut ret: *mut RSA = RSA_parse_private_key(&mut cbs);
    if ret.is_null() || CBS_len(&mut cbs) != 0 as libc::c_int as size_t {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            235 as libc::c_int as libc::c_uint,
        );
        RSA_free(ret);
        return 0 as *mut RSA;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_marshal_private_key(
    mut cbb: *mut CBB,
    mut rsa: *const RSA,
) -> libc::c_int {
    let mut child: CBB = cbb_st {
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
        cbb,
        &mut child,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || CBB_add_asn1_uint64(&mut child, kVersionTwoPrime) == 0
        || marshal_integer(&mut child, (*rsa).n) == 0
        || marshal_integer(&mut child, (*rsa).e) == 0
        || marshal_integer(&mut child, (*rsa).d) == 0
        || marshal_integer(&mut child, (*rsa).p) == 0
        || marshal_integer(&mut child, (*rsa).q) == 0
        || marshal_integer(&mut child, (*rsa).dmp1) == 0
        || marshal_integer(&mut child, (*rsa).dmq1) == 0
        || marshal_integer(&mut child, (*rsa).iqmp) == 0 || CBB_flush(cbb) == 0
    {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            121 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            255 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_private_key_to_bytes(
    mut out_bytes: *mut *mut uint8_t,
    mut out_len: *mut size_t,
    mut rsa: *const RSA,
) -> libc::c_int {
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
    CBB_zero(&mut cbb);
    if CBB_init(&mut cbb, 0 as libc::c_int as size_t) == 0
        || RSA_marshal_private_key(&mut cbb, rsa) == 0
        || CBB_finish(&mut cbb, out_bytes, out_len) == 0
    {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            121 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_asn1.c\0"
                as *const u8 as *const libc::c_char,
            268 as libc::c_int as libc::c_uint,
        );
        CBB_cleanup(&mut cbb);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn d2i_RSAPublicKey(
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
    let mut ret: *mut RSA = RSA_parse_public_key(&mut cbs);
    if ret.is_null() {
        return 0 as *mut RSA;
    }
    if !out.is_null() {
        RSA_free(*out);
        *out = ret;
    }
    *inp = CBS_data(&mut cbs);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn i2d_RSAPublicKey(
    mut in_0: *const RSA,
    mut outp: *mut *mut uint8_t,
) -> libc::c_int {
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
    if CBB_init(&mut cbb, 0 as libc::c_int as size_t) == 0
        || RSA_marshal_public_key(&mut cbb, in_0) == 0
    {
        CBB_cleanup(&mut cbb);
        return -(1 as libc::c_int);
    }
    return CBB_finish_i2d(&mut cbb, outp);
}
#[no_mangle]
pub unsafe extern "C" fn d2i_RSAPrivateKey(
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
    let mut ret: *mut RSA = RSA_parse_private_key(&mut cbs);
    if ret.is_null() {
        return 0 as *mut RSA;
    }
    if !out.is_null() {
        RSA_free(*out);
        *out = ret;
    }
    *inp = CBS_data(&mut cbs);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn i2d_RSAPrivateKey(
    mut in_0: *const RSA,
    mut outp: *mut *mut uint8_t,
) -> libc::c_int {
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
    if CBB_init(&mut cbb, 0 as libc::c_int as size_t) == 0
        || RSA_marshal_private_key(&mut cbb, in_0) == 0
    {
        CBB_cleanup(&mut cbb);
        return -(1 as libc::c_int);
    }
    return CBB_finish_i2d(&mut cbb, outp);
}
#[no_mangle]
pub unsafe extern "C" fn RSAPublicKey_dup(mut rsa: *const RSA) -> *mut RSA {
    let mut der: *mut uint8_t = 0 as *mut uint8_t;
    let mut der_len: size_t = 0;
    if RSA_public_key_to_bytes(&mut der, &mut der_len, rsa) == 0 {
        return 0 as *mut RSA;
    }
    let mut ret: *mut RSA = RSA_public_key_from_bytes(der, der_len);
    OPENSSL_free(der as *mut libc::c_void);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn RSAPrivateKey_dup(mut rsa: *const RSA) -> *mut RSA {
    let mut der: *mut uint8_t = 0 as *mut uint8_t;
    let mut der_len: size_t = 0;
    if RSA_private_key_to_bytes(&mut der, &mut der_len, rsa) == 0 {
        return 0 as *mut RSA;
    }
    let mut ret: *mut RSA = RSA_private_key_from_bytes(der, der_len);
    OPENSSL_free(der as *mut libc::c_void);
    return ret;
}
