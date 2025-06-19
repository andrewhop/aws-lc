#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(label_break_value)]
extern "C" {
    fn BN_new() -> *mut BIGNUM;
    fn BN_parse_asn1_unsigned(cbs: *mut CBS, ret: *mut BIGNUM) -> libc::c_int;
    fn BN_marshal_asn1(cbb: *mut CBB, bn: *const BIGNUM) -> libc::c_int;
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
    fn dh_check_params_fast(dh: *const DH) -> libc::c_int;
    fn DH_new() -> *mut DH;
    fn DH_free(dh: *mut DH);
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
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
pub type CRYPTO_MUTEX = crypto_mutex_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub union crypto_mutex_st {
    pub alignment: libc::c_double,
    pub padding: [uint8_t; 56],
}
pub type DH = dh_st;
unsafe extern "C" fn parse_integer(
    mut cbs: *mut CBS,
    mut out: *mut *mut BIGNUM,
) -> libc::c_int {
    if (*out).is_null() {} else {
        __assert_fail(
            b"*out == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dh_extra/dh_asn1.c\0" as *const u8
                as *const libc::c_char,
            70 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 36],
                &[libc::c_char; 36],
            >(b"int parse_integer(CBS *, BIGNUM **)\0"))
                .as_ptr(),
        );
    }
    'c_1715: {
        if (*out).is_null() {} else {
            __assert_fail(
                b"*out == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/dh_extra/dh_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                70 as libc::c_int as libc::c_uint,
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
            5 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dh_extra/dh_asn1.c\0" as *const u8
                as *const libc::c_char,
            81 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return BN_marshal_asn1(cbb, bn);
}
#[no_mangle]
pub unsafe extern "C" fn DH_parse_parameters(mut cbs: *mut CBS) -> *mut DH {
    let mut priv_length: uint64_t = 0;
    let mut current_block: u64;
    let mut ret: *mut DH = DH_new();
    if ret.is_null() {
        return 0 as *mut DH;
    }
    let mut child: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if !(CBS_get_asn1(
        cbs,
        &mut child,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || parse_integer(&mut child, &mut (*ret).p) == 0
        || parse_integer(&mut child, &mut (*ret).g) == 0)
    {
        priv_length = 0;
        if CBS_len(&mut child) != 0 as libc::c_int as size_t {
            if CBS_get_asn1_uint64(&mut child, &mut priv_length) == 0
                || priv_length
                    > (2147483647 as libc::c_int as libc::c_uint)
                        .wrapping_mul(2 as libc::c_uint)
                        .wrapping_add(1 as libc::c_uint) as uint64_t
            {
                current_block = 2192481876272239737;
            } else {
                (*ret).priv_length = priv_length as libc::c_uint;
                current_block = 6937071982253665452;
            }
        } else {
            current_block = 6937071982253665452;
        }
        match current_block {
            2192481876272239737 => {}
            _ => {
                if !(CBS_len(&mut child) != 0 as libc::c_int as size_t) {
                    if !(dh_check_params_fast(ret) == 0) {
                        return ret;
                    }
                }
            }
        }
    }
    ERR_put_error(
        5 as libc::c_int,
        0 as libc::c_int,
        104 as libc::c_int,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/dh_extra/dh_asn1.c\0" as *const u8
            as *const libc::c_char,
        120 as libc::c_int as libc::c_uint,
    );
    DH_free(ret);
    return 0 as *mut DH;
}
#[no_mangle]
pub unsafe extern "C" fn DH_marshal_parameters(
    mut cbb: *mut CBB,
    mut dh: *const DH,
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
    ) == 0 || marshal_integer(&mut child, (*dh).p) == 0
        || marshal_integer(&mut child, (*dh).g) == 0
        || (*dh).priv_length != 0 as libc::c_int as libc::c_uint
            && CBB_add_asn1_uint64(&mut child, (*dh).priv_length as uint64_t) == 0
        || CBB_flush(cbb) == 0
    {
        ERR_put_error(
            5 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dh_extra/dh_asn1.c\0" as *const u8
                as *const libc::c_char,
            133 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn d2i_DHparams(
    mut out: *mut *mut DH,
    mut inp: *mut *const uint8_t,
    mut len: libc::c_long,
) -> *mut DH {
    if len < 0 as libc::c_int as libc::c_long {
        return 0 as *mut DH;
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, *inp, len as size_t);
    let mut ret: *mut DH = DH_parse_parameters(&mut cbs);
    if ret.is_null() {
        return 0 as *mut DH;
    }
    if !out.is_null() {
        DH_free(*out);
        *out = ret;
    }
    *inp = CBS_data(&mut cbs);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn i2d_DHparams(
    mut in_0: *const DH,
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
        || DH_marshal_parameters(&mut cbb, in_0) == 0
    {
        CBB_cleanup(&mut cbb);
        return -(1 as libc::c_int);
    }
    return CBB_finish_i2d(&mut cbb, outp);
}
