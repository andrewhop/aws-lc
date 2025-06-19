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
    fn BN_num_bits(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_num_bytes(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_is_negative(bn: *const BIGNUM) -> libc::c_int;
    fn BN_bin2bn(in_0: *const uint8_t, len: size_t, ret: *mut BIGNUM) -> *mut BIGNUM;
    fn BN_bn2cbb_padded(out: *mut CBB, len: size_t, in_0: *const BIGNUM) -> libc::c_int;
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_get_asn1(
        cbs: *mut CBS,
        out: *mut CBS,
        tag_value: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBS_is_valid_asn1_integer(
        cbs: *const CBS,
        out_is_negative: *mut libc::c_int,
    ) -> libc::c_int;
    fn CBB_flush(cbb: *mut CBB) -> libc::c_int;
    fn CBB_add_asn1(
        cbb: *mut CBB,
        out_contents: *mut CBB,
        tag: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBB_add_u8(cbb: *mut CBB, value: uint8_t) -> libc::c_int;
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_parse_asn1_unsigned(
    mut cbs: *mut CBS,
    mut ret: *mut BIGNUM,
) -> libc::c_int {
    let mut child: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut is_negative: libc::c_int = 0;
    if CBS_get_asn1(cbs, &mut child, 0x2 as libc::c_uint) == 0
        || CBS_is_valid_asn1_integer(&mut child, &mut is_negative) == 0
    {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            117 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bn_extra/bn_asn1.c\0" as *const u8
                as *const libc::c_char,
            26 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if is_negative != 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bn_extra/bn_asn1.c\0" as *const u8
                as *const libc::c_char,
            31 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return (BN_bin2bn(CBS_data(&mut child), CBS_len(&mut child), ret)
        != 0 as *mut libc::c_void as *mut BIGNUM) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_marshal_asn1(
    mut cbb: *mut CBB,
    mut bn: *const BIGNUM,
) -> libc::c_int {
    if BN_is_negative(bn) != 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bn_extra/bn_asn1.c\0" as *const u8
                as *const libc::c_char,
            41 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
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
    if CBB_add_asn1(cbb, &mut child, 0x2 as libc::c_uint) == 0
        || (BN_num_bits(bn)).wrapping_rem(8 as libc::c_int as libc::c_uint)
            == 0 as libc::c_int as libc::c_uint
            && CBB_add_u8(&mut child, 0 as libc::c_int as uint8_t) == 0
        || BN_bn2cbb_padded(&mut child, BN_num_bytes(bn) as size_t, bn) == 0
        || CBB_flush(cbb) == 0
    {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            118 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bn_extra/bn_asn1.c\0" as *const u8
                as *const libc::c_char,
            52 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
