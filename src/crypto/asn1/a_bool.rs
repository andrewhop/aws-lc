#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
extern "C" {
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_get_asn1_bool(cbs: *mut CBS, out: *mut libc::c_int) -> libc::c_int;
    fn CBB_init(cbb: *mut CBB, initial_capacity: size_t) -> libc::c_int;
    fn CBB_cleanup(cbb: *mut CBB);
    fn CBB_add_asn1_bool(cbb: *mut CBB, value: libc::c_int) -> libc::c_int;
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
pub type uint8_t = __uint8_t;
pub type ASN1_BOOLEAN = libc::c_int;
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
#[no_mangle]
pub unsafe extern "C" fn i2d_ASN1_BOOLEAN(
    mut a: ASN1_BOOLEAN,
    mut outp: *mut *mut libc::c_uchar,
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
    if CBB_init(&mut cbb, 3 as libc::c_int as size_t) == 0
        || CBB_add_asn1_bool(&mut cbb, (a != 0 as libc::c_int) as libc::c_int) == 0
    {
        CBB_cleanup(&mut cbb);
        return -(1 as libc::c_int);
    }
    return CBB_finish_i2d(&mut cbb, outp);
}
#[no_mangle]
pub unsafe extern "C" fn d2i_ASN1_BOOLEAN(
    mut out: *mut ASN1_BOOLEAN,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> ASN1_BOOLEAN {
    if len < 0 as libc::c_int as libc::c_long {
        return -(1 as libc::c_int);
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, *inp, len as size_t);
    let mut val: libc::c_int = 0;
    if CBS_get_asn1_bool(&mut cbs, &mut val) == 0 {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_bool.c\0" as *const u8
                as *const libc::c_char,
            85 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    let mut ret: ASN1_BOOLEAN = if val != 0 {
        0xff as libc::c_int
    } else {
        0 as libc::c_int
    };
    if !out.is_null() {
        *out = ret;
    }
    *inp = CBS_data(&mut cbs);
    return ret;
}
