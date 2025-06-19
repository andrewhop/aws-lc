#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(asm, extern_types, label_break_value)]
use core::arch::asm;
unsafe extern "C" {
    pub type stack_st_void;
    fn DSA_new() -> *mut DSA;
    fn DSA_free(dsa: *mut DSA);
    fn DSA_SIG_new() -> *mut DSA_SIG;
    fn DSA_SIG_free(sig: *mut DSA_SIG);
    fn BN_new() -> *mut BIGNUM;
    fn BN_num_bits(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_is_negative(bn: *const BIGNUM) -> libc::c_int;
    fn BN_parse_asn1_unsigned(cbs: *mut CBS, ret: *mut BIGNUM) -> libc::c_int;
    fn BN_marshal_asn1(cbb: *mut CBB, bn: *const BIGNUM) -> libc::c_int;
    fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_is_zero(bn: *const BIGNUM) -> libc::c_int;
    fn BN_is_odd(bn: *const BIGNUM) -> libc::c_int;
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_get_asn1(
        cbs: *mut CBS,
        out: *mut CBS,
        tag_value: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBS_get_asn1_uint64(cbs: *mut CBS, out: *mut uint64_t) -> libc::c_int;
    fn CBB_init(cbb: *mut CBB, initial_capacity: size_t) -> libc::c_int;
    fn CBB_cleanup(cbb: *mut CBB);
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
pub struct DSA_SIG_st {
    pub r: *mut BIGNUM,
    pub s: *mut BIGNUM,
}
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
pub type DSA_SIG = DSA_SIG_st;
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
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
pub type CRYPTO_refcount_t = uint32_t;
pub type CRYPTO_MUTEX = crypto_mutex_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub union crypto_mutex_st {
    pub alignment: libc::c_double,
    pub padding: [uint8_t; 56],
}
pub type DSA = dsa_st;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_552_error_is_int_is_not_the_same_size_as_uint32_t {
    #[bitfield(
        name = "static_assertion_at_line_552_error_is_int_is_not_the_same_size_as_uint32_t",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_552_error_is_int_is_not_the_same_size_as_uint32_t: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[inline]
unsafe extern "C" fn value_barrier_u32(mut a: uint32_t) -> uint32_t {
    asm!("", inlateout(reg) a, options(preserves_flags, pure, readonly, att_syntax));
    return a;
}
#[inline]
unsafe extern "C" fn constant_time_declassify_int(mut v: libc::c_int) -> libc::c_int {
    return value_barrier_u32(v as uint32_t) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dsa_check_key(mut dsa: *const DSA) -> libc::c_int {
    if ((*dsa).p).is_null() || ((*dsa).q).is_null() || ((*dsa).g).is_null() {
        ERR_put_error(
            10 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa_asn1.c\0" as *const u8
                as *const libc::c_char,
            74 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if BN_is_negative((*dsa).p) != 0 || BN_is_negative((*dsa).q) != 0
        || BN_is_zero((*dsa).p) != 0 || BN_is_zero((*dsa).q) != 0
        || BN_is_odd((*dsa).p) == 0 || BN_is_odd((*dsa).q) == 0
        || BN_cmp((*dsa).q, (*dsa).p) >= 0 as libc::c_int
        || BN_is_negative((*dsa).g) != 0 || BN_is_zero((*dsa).g) != 0
        || BN_cmp((*dsa).g, (*dsa).p) >= 0 as libc::c_int
    {
        ERR_put_error(
            10 as libc::c_int,
            0 as libc::c_int,
            107 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa_asn1.c\0" as *const u8
                as *const libc::c_char,
            91 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut q_bits: libc::c_uint = BN_num_bits((*dsa).q);
    if q_bits != 160 as libc::c_int as libc::c_uint
        && q_bits != 224 as libc::c_int as libc::c_uint
        && q_bits != 256 as libc::c_int as libc::c_uint
    {
        ERR_put_error(
            10 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa_asn1.c\0" as *const u8
                as *const libc::c_char,
            98 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if BN_num_bits((*dsa).p) > 10000 as libc::c_int as libc::c_uint {
        ERR_put_error(
            10 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa_asn1.c\0" as *const u8
                as *const libc::c_char,
            105 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if !((*dsa).pub_key).is_null() {
        if BN_is_negative((*dsa).pub_key) != 0 || BN_is_zero((*dsa).pub_key) != 0
            || BN_cmp((*dsa).pub_key, (*dsa).p) >= 0 as libc::c_int
        {
            ERR_put_error(
                10 as libc::c_int,
                0 as libc::c_int,
                107 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa_asn1.c\0" as *const u8
                    as *const libc::c_char,
                113 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    }
    if !((*dsa).priv_key).is_null() {
        if BN_is_negative((*dsa).priv_key) != 0
            || constant_time_declassify_int(BN_is_zero((*dsa).priv_key)) != 0
            || constant_time_declassify_int(
                (BN_cmp((*dsa).priv_key, (*dsa).q) >= 0 as libc::c_int) as libc::c_int,
            ) != 0
        {
            ERR_put_error(
                10 as libc::c_int,
                0 as libc::c_int,
                107 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa_asn1.c\0" as *const u8
                    as *const libc::c_char,
                124 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn parse_integer(
    mut cbs: *mut CBS,
    mut out: *mut *mut BIGNUM,
) -> libc::c_int {
    if (*out).is_null() {} else {
        __assert_fail(
            b"*out == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa_asn1.c\0" as *const u8
                as *const libc::c_char,
            133 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 36],
                &[libc::c_char; 36],
            >(b"int parse_integer(CBS *, BIGNUM **)\0"))
                .as_ptr(),
        );
    }
    'c_3679: {
        if (*out).is_null() {} else {
            __assert_fail(
                b"*out == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa_asn1.c\0" as *const u8
                    as *const libc::c_char,
                133 as libc::c_int as libc::c_uint,
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
            10 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa_asn1.c\0" as *const u8
                as *const libc::c_char,
            144 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return BN_marshal_asn1(cbb, bn);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_SIG_parse(mut cbs: *mut CBS) -> *mut DSA_SIG {
    let mut ret: *mut DSA_SIG = DSA_SIG_new();
    if ret.is_null() {
        return 0 as *mut DSA_SIG;
    }
    let mut child: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_get_asn1(
        cbs,
        &mut child,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || parse_integer(&mut child, &mut (*ret).r) == 0
        || parse_integer(&mut child, &mut (*ret).s) == 0
        || CBS_len(&mut child) != 0 as libc::c_int as size_t
    {
        ERR_put_error(
            10 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa_asn1.c\0" as *const u8
                as *const libc::c_char,
            160 as libc::c_int as libc::c_uint,
        );
        DSA_SIG_free(ret);
        return 0 as *mut DSA_SIG;
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_SIG_marshal(
    mut cbb: *mut CBB,
    mut sig: *const DSA_SIG,
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
    ) == 0 || marshal_integer(&mut child, (*sig).r) == 0
        || marshal_integer(&mut child, (*sig).s) == 0 || CBB_flush(cbb) == 0
    {
        ERR_put_error(
            10 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa_asn1.c\0" as *const u8
                as *const libc::c_char,
            173 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_parse_public_key(mut cbs: *mut CBS) -> *mut DSA {
    let mut ret: *mut DSA = DSA_new();
    if ret.is_null() {
        return 0 as *mut DSA;
    }
    let mut child: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_get_asn1(
        cbs,
        &mut child,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || parse_integer(&mut child, &mut (*ret).pub_key) == 0
        || parse_integer(&mut child, &mut (*ret).p) == 0
        || parse_integer(&mut child, &mut (*ret).q) == 0
        || parse_integer(&mut child, &mut (*ret).g) == 0
        || CBS_len(&mut child) != 0 as libc::c_int as size_t
    {
        ERR_put_error(
            10 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa_asn1.c\0" as *const u8
                as *const libc::c_char,
            191 as libc::c_int as libc::c_uint,
        );
    } else if !(dsa_check_key(ret) == 0) {
        return ret
    }
    DSA_free(ret);
    return 0 as *mut DSA;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_marshal_public_key(
    mut cbb: *mut CBB,
    mut dsa: *const DSA,
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
    ) == 0 || marshal_integer(&mut child, (*dsa).pub_key) == 0
        || marshal_integer(&mut child, (*dsa).p) == 0
        || marshal_integer(&mut child, (*dsa).q) == 0
        || marshal_integer(&mut child, (*dsa).g) == 0 || CBB_flush(cbb) == 0
    {
        ERR_put_error(
            10 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa_asn1.c\0" as *const u8
                as *const libc::c_char,
            212 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_parse_parameters(mut cbs: *mut CBS) -> *mut DSA {
    let mut ret: *mut DSA = DSA_new();
    if ret.is_null() {
        return 0 as *mut DSA;
    }
    let mut child: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_get_asn1(
        cbs,
        &mut child,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || parse_integer(&mut child, &mut (*ret).p) == 0
        || parse_integer(&mut child, &mut (*ret).q) == 0
        || parse_integer(&mut child, &mut (*ret).g) == 0
        || CBS_len(&mut child) != 0 as libc::c_int as size_t
    {
        ERR_put_error(
            10 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa_asn1.c\0" as *const u8
                as *const libc::c_char,
            229 as libc::c_int as libc::c_uint,
        );
    } else if !(dsa_check_key(ret) == 0) {
        return ret
    }
    DSA_free(ret);
    return 0 as *mut DSA;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_marshal_parameters(
    mut cbb: *mut CBB,
    mut dsa: *const DSA,
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
    ) == 0 || marshal_integer(&mut child, (*dsa).p) == 0
        || marshal_integer(&mut child, (*dsa).q) == 0
        || marshal_integer(&mut child, (*dsa).g) == 0 || CBB_flush(cbb) == 0
    {
        ERR_put_error(
            10 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa_asn1.c\0" as *const u8
                as *const libc::c_char,
            249 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_parse_private_key(mut cbs: *mut CBS) -> *mut DSA {
    let mut ret: *mut DSA = DSA_new();
    if ret.is_null() {
        return 0 as *mut DSA;
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
            10 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa_asn1.c\0" as *const u8
                as *const libc::c_char,
            265 as libc::c_int as libc::c_uint,
        );
    } else if version != 0 as libc::c_int as uint64_t {
        ERR_put_error(
            10 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa_asn1.c\0" as *const u8
                as *const libc::c_char,
            270 as libc::c_int as libc::c_uint,
        );
    } else if parse_integer(&mut child, &mut (*ret).p) == 0
        || parse_integer(&mut child, &mut (*ret).q) == 0
        || parse_integer(&mut child, &mut (*ret).g) == 0
        || parse_integer(&mut child, &mut (*ret).pub_key) == 0
        || parse_integer(&mut child, &mut (*ret).priv_key) == 0
        || CBS_len(&mut child) != 0 as libc::c_int as size_t
    {
        ERR_put_error(
            10 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa_asn1.c\0" as *const u8
                as *const libc::c_char,
            280 as libc::c_int as libc::c_uint,
        );
    } else if !(dsa_check_key(ret) == 0) {
        return ret
    }
    DSA_free(ret);
    return 0 as *mut DSA;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_marshal_private_key(
    mut cbb: *mut CBB,
    mut dsa: *const DSA,
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
    ) == 0 || CBB_add_asn1_uint64(&mut child, 0 as libc::c_int as uint64_t) == 0
        || marshal_integer(&mut child, (*dsa).p) == 0
        || marshal_integer(&mut child, (*dsa).q) == 0
        || marshal_integer(&mut child, (*dsa).g) == 0
        || marshal_integer(&mut child, (*dsa).pub_key) == 0
        || marshal_integer(&mut child, (*dsa).priv_key) == 0 || CBB_flush(cbb) == 0
    {
        ERR_put_error(
            10 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa_asn1.c\0" as *const u8
                as *const libc::c_char,
            304 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_DSA_SIG(
    mut out_sig: *mut *mut DSA_SIG,
    mut inp: *mut *const uint8_t,
    mut len: libc::c_long,
) -> *mut DSA_SIG {
    if len < 0 as libc::c_int as libc::c_long {
        return 0 as *mut DSA_SIG;
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, *inp, len as size_t);
    let mut ret: *mut DSA_SIG = DSA_SIG_parse(&mut cbs);
    if ret.is_null() {
        return 0 as *mut DSA_SIG;
    }
    if !out_sig.is_null() {
        DSA_SIG_free(*out_sig);
        *out_sig = ret;
    }
    *inp = CBS_data(&mut cbs);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_DSA_SIG(
    mut in_0: *const DSA_SIG,
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
        || DSA_SIG_marshal(&mut cbb, in_0) == 0
    {
        CBB_cleanup(&mut cbb);
        return -(1 as libc::c_int);
    }
    return CBB_finish_i2d(&mut cbb, outp);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_DSAPublicKey(
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
    let mut ret: *mut DSA = DSA_parse_public_key(&mut cbs);
    if ret.is_null() {
        return 0 as *mut DSA;
    }
    if !out.is_null() {
        DSA_free(*out);
        *out = ret;
    }
    *inp = CBS_data(&mut cbs);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_DSAPublicKey(
    mut in_0: *const DSA,
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
        || DSA_marshal_public_key(&mut cbb, in_0) == 0
    {
        CBB_cleanup(&mut cbb);
        return -(1 as libc::c_int);
    }
    return CBB_finish_i2d(&mut cbb, outp);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_DSAPrivateKey(
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
    let mut ret: *mut DSA = DSA_parse_private_key(&mut cbs);
    if ret.is_null() {
        return 0 as *mut DSA;
    }
    if !out.is_null() {
        DSA_free(*out);
        *out = ret;
    }
    *inp = CBS_data(&mut cbs);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_DSAPrivateKey(
    mut in_0: *const DSA,
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
        || DSA_marshal_private_key(&mut cbb, in_0) == 0
    {
        CBB_cleanup(&mut cbb);
        return -(1 as libc::c_int);
    }
    return CBB_finish_i2d(&mut cbb, outp);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_DSAparams(
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
    let mut ret: *mut DSA = DSA_parse_parameters(&mut cbs);
    if ret.is_null() {
        return 0 as *mut DSA;
    }
    if !out.is_null() {
        DSA_free(*out);
        *out = ret;
    }
    *inp = CBS_data(&mut cbs);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_DSAparams(
    mut in_0: *const DSA,
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
        || DSA_marshal_parameters(&mut cbb, in_0) == 0
    {
        CBB_cleanup(&mut cbb);
        return -(1 as libc::c_int);
    }
    return CBB_finish_i2d(&mut cbb, outp);
}
