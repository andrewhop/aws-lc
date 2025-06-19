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
    fn CBS_get_u8(cbs: *mut CBS, out: *mut uint8_t) -> libc::c_int;
    fn CBS_get_u16(cbs: *mut CBS, out: *mut uint16_t) -> libc::c_int;
    fn CBS_get_u32(cbs: *mut CBS, out: *mut uint32_t) -> libc::c_int;
    fn CBB_add_u8(cbb: *mut CBB, value: uint8_t) -> libc::c_int;
    fn CBB_add_u16(cbb: *mut CBB, value: uint16_t) -> libc::c_int;
    fn CBB_add_u32(cbb: *mut CBB, value: uint32_t) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
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
unsafe extern "C" fn is_valid_code_point(mut v: uint32_t) -> libc::c_int {
    if v > 0x10ffff as libc::c_int as uint32_t
        || v & 0xfffe as libc::c_int as uint32_t == 0xfffe as libc::c_int as uint32_t
        || v >= 0xfdd0 as libc::c_int as uint32_t
            && v <= 0xfdef as libc::c_int as uint32_t
        || v >= 0xd800 as libc::c_int as uint32_t
            && v <= 0xdfff as libc::c_int as uint32_t
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbs_get_utf8(
    mut cbs: *mut CBS,
    mut out: *mut uint32_t,
) -> libc::c_int {
    let mut c: uint8_t = 0;
    if CBS_get_u8(cbs, &mut c) == 0 {
        return 0 as libc::c_int;
    }
    if c as libc::c_int <= 0x7f as libc::c_int {
        *out = c as uint32_t;
        return 1 as libc::c_int;
    }
    let mut v: uint32_t = 0;
    let mut lower_bound: uint32_t = 0;
    let mut len: size_t = 0;
    if c as libc::c_int
        & !(((1 as libc::c_uint) << 8 as libc::c_int - 3 as libc::c_int)
            .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t as libc::c_int)
            as uint8_t as libc::c_int
        == !(((1 as libc::c_uint) << 8 as libc::c_int - 2 as libc::c_int)
            .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t as libc::c_int)
            as uint8_t as libc::c_int
    {
        v = (c as libc::c_int
            & ((1 as libc::c_uint) << 5 as libc::c_int)
                .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t
                as libc::c_int) as uint32_t;
        len = 1 as libc::c_int as size_t;
        lower_bound = 0x80 as libc::c_int as uint32_t;
    } else if c as libc::c_int
        & !(((1 as libc::c_uint) << 8 as libc::c_int - 4 as libc::c_int)
            .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t as libc::c_int)
            as uint8_t as libc::c_int
        == !(((1 as libc::c_uint) << 8 as libc::c_int - 3 as libc::c_int)
            .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t as libc::c_int)
            as uint8_t as libc::c_int
    {
        v = (c as libc::c_int
            & ((1 as libc::c_uint) << 4 as libc::c_int)
                .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t
                as libc::c_int) as uint32_t;
        len = 2 as libc::c_int as size_t;
        lower_bound = 0x800 as libc::c_int as uint32_t;
    } else if c as libc::c_int
        & !(((1 as libc::c_uint) << 8 as libc::c_int - 5 as libc::c_int)
            .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t as libc::c_int)
            as uint8_t as libc::c_int
        == !(((1 as libc::c_uint) << 8 as libc::c_int - 4 as libc::c_int)
            .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t as libc::c_int)
            as uint8_t as libc::c_int
    {
        v = (c as libc::c_int
            & ((1 as libc::c_uint) << 3 as libc::c_int)
                .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t
                as libc::c_int) as uint32_t;
        len = 3 as libc::c_int as size_t;
        lower_bound = 0x10000 as libc::c_int as uint32_t;
    } else {
        return 0 as libc::c_int
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < len {
        if CBS_get_u8(cbs, &mut c) == 0
            || c as libc::c_int
                & !(((1 as libc::c_uint) << 8 as libc::c_int - 2 as libc::c_int)
                    .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t
                    as libc::c_int) as uint8_t as libc::c_int
                != !(((1 as libc::c_uint) << 8 as libc::c_int - 1 as libc::c_int)
                    .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t
                    as libc::c_int) as uint8_t as libc::c_int
        {
            return 0 as libc::c_int;
        }
        v <<= 6 as libc::c_int;
        v
            |= (c as libc::c_int
                & ((1 as libc::c_uint) << 6 as libc::c_int)
                    .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t
                    as libc::c_int) as uint32_t;
        i = i.wrapping_add(1);
        i;
    }
    if is_valid_code_point(v) == 0 || v < lower_bound {
        return 0 as libc::c_int;
    }
    *out = v;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbs_get_latin1(
    mut cbs: *mut CBS,
    mut out: *mut uint32_t,
) -> libc::c_int {
    let mut c: uint8_t = 0;
    if CBS_get_u8(cbs, &mut c) == 0 {
        return 0 as libc::c_int;
    }
    *out = c as uint32_t;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbs_get_ucs2_be(
    mut cbs: *mut CBS,
    mut out: *mut uint32_t,
) -> libc::c_int {
    let mut c: uint16_t = 0;
    if CBS_get_u16(cbs, &mut c) == 0 || is_valid_code_point(c as uint32_t) == 0 {
        return 0 as libc::c_int;
    }
    *out = c as uint32_t;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbs_get_utf32_be(
    mut cbs: *mut CBS,
    mut out: *mut uint32_t,
) -> libc::c_int {
    return (CBS_get_u32(cbs, out) != 0 && is_valid_code_point(*out) != 0) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_get_utf8_len(mut u: uint32_t) -> size_t {
    if u <= 0x7f as libc::c_int as uint32_t {
        return 1 as libc::c_int as size_t;
    }
    if u <= 0x7ff as libc::c_int as uint32_t {
        return 2 as libc::c_int as size_t;
    }
    if u <= 0xffff as libc::c_int as uint32_t {
        return 3 as libc::c_int as size_t;
    }
    return 4 as libc::c_int as size_t;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_add_utf8(
    mut cbb: *mut CBB,
    mut u: uint32_t,
) -> libc::c_int {
    if is_valid_code_point(u) == 0 {
        return 0 as libc::c_int;
    }
    if u <= 0x7f as libc::c_int as uint32_t {
        return CBB_add_u8(cbb, u as uint8_t);
    }
    if u <= 0x7ff as libc::c_int as uint32_t {
        return (CBB_add_u8(
            cbb,
            (!(((1 as libc::c_uint) << 8 as libc::c_int - 2 as libc::c_int)
                .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t
                as libc::c_int) as uint8_t as uint32_t | u >> 6 as libc::c_int)
                as uint8_t,
        ) != 0
            && CBB_add_u8(
                cbb,
                (!(((1 as libc::c_uint) << 8 as libc::c_int - 1 as libc::c_int)
                    .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t
                    as libc::c_int) as uint8_t as uint32_t
                    | u
                        & ((1 as libc::c_uint) << 6 as libc::c_int)
                            .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t
                            as uint32_t) as uint8_t,
            ) != 0) as libc::c_int;
    }
    if u <= 0xffff as libc::c_int as uint32_t {
        return (CBB_add_u8(
            cbb,
            (!(((1 as libc::c_uint) << 8 as libc::c_int - 3 as libc::c_int)
                .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t
                as libc::c_int) as uint8_t as uint32_t | u >> 12 as libc::c_int)
                as uint8_t,
        ) != 0
            && CBB_add_u8(
                cbb,
                (!(((1 as libc::c_uint) << 8 as libc::c_int - 1 as libc::c_int)
                    .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t
                    as libc::c_int) as uint8_t as uint32_t
                    | u >> 6 as libc::c_int
                        & ((1 as libc::c_uint) << 6 as libc::c_int)
                            .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t
                            as uint32_t) as uint8_t,
            ) != 0
            && CBB_add_u8(
                cbb,
                (!(((1 as libc::c_uint) << 8 as libc::c_int - 1 as libc::c_int)
                    .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t
                    as libc::c_int) as uint8_t as uint32_t
                    | u
                        & ((1 as libc::c_uint) << 6 as libc::c_int)
                            .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t
                            as uint32_t) as uint8_t,
            ) != 0) as libc::c_int;
    }
    if u <= 0x10ffff as libc::c_int as uint32_t {
        return (CBB_add_u8(
            cbb,
            (!(((1 as libc::c_uint) << 8 as libc::c_int - 4 as libc::c_int)
                .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t
                as libc::c_int) as uint8_t as uint32_t | u >> 18 as libc::c_int)
                as uint8_t,
        ) != 0
            && CBB_add_u8(
                cbb,
                (!(((1 as libc::c_uint) << 8 as libc::c_int - 1 as libc::c_int)
                    .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t
                    as libc::c_int) as uint8_t as uint32_t
                    | u >> 12 as libc::c_int
                        & ((1 as libc::c_uint) << 6 as libc::c_int)
                            .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t
                            as uint32_t) as uint8_t,
            ) != 0
            && CBB_add_u8(
                cbb,
                (!(((1 as libc::c_uint) << 8 as libc::c_int - 1 as libc::c_int)
                    .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t
                    as libc::c_int) as uint8_t as uint32_t
                    | u >> 6 as libc::c_int
                        & ((1 as libc::c_uint) << 6 as libc::c_int)
                            .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t
                            as uint32_t) as uint8_t,
            ) != 0
            && CBB_add_u8(
                cbb,
                (!(((1 as libc::c_uint) << 8 as libc::c_int - 1 as libc::c_int)
                    .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t
                    as libc::c_int) as uint8_t as uint32_t
                    | u
                        & ((1 as libc::c_uint) << 6 as libc::c_int)
                            .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint8_t
                            as uint32_t) as uint8_t,
            ) != 0) as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_add_latin1(
    mut cbb: *mut CBB,
    mut u: uint32_t,
) -> libc::c_int {
    return (u <= 0xff as libc::c_int as uint32_t && CBB_add_u8(cbb, u as uint8_t) != 0)
        as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_add_ucs2_be(
    mut cbb: *mut CBB,
    mut u: uint32_t,
) -> libc::c_int {
    return (u <= 0xffff as libc::c_int as uint32_t && is_valid_code_point(u) != 0
        && CBB_add_u16(cbb, u as uint16_t) != 0) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_add_utf32_be(
    mut cbb: *mut CBB,
    mut u: uint32_t,
) -> libc::c_int {
    return (is_valid_code_point(u) != 0 && CBB_add_u32(cbb, u) != 0) as libc::c_int;
}
