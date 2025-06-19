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
unsafe extern "C" {
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_skip(cbs: *mut CBS, len: size_t) -> libc::c_int;
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_get_asn1(
        cbs: *mut CBS,
        out: *mut CBS,
        tag_value: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBS_peek_asn1_tag(cbs: *const CBS, tag_value: CBS_ASN1_TAG) -> libc::c_int;
    fn CBS_get_any_asn1_element(
        cbs: *mut CBS,
        out: *mut CBS,
        out_tag: *mut CBS_ASN1_TAG,
        out_header_len: *mut size_t,
    ) -> libc::c_int;
    fn CBS_get_any_ber_asn1_element(
        cbs: *mut CBS,
        out: *mut CBS,
        out_tag: *mut CBS_ASN1_TAG,
        out_header_len: *mut size_t,
        out_ber_found: *mut libc::c_int,
        out_indefinite: *mut libc::c_int,
    ) -> libc::c_int;
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
    fn CBB_add_bytes(cbb: *mut CBB, data: *const uint8_t, len: size_t) -> libc::c_int;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type CBS_ASN1_TAG = uint32_t;
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
static mut kMaxDepth: uint32_t = 128 as libc::c_int as uint32_t;
unsafe extern "C" fn is_string_type(mut tag: CBS_ASN1_TAG) -> libc::c_int {
    match tag & !((0x20 as libc::c_uint) << 24 as libc::c_int) {
        4 | 12 | 18 | 19 | 20 | 21 | 22 | 25 | 26 | 27 | 28 | 30 => {
            return 1 as libc::c_int;
        }
        _ => return 0 as libc::c_int,
    };
}
unsafe extern "C" fn cbs_find_ber(
    mut orig_in: *const CBS,
    mut ber_found: *mut libc::c_int,
    mut depth: uint32_t,
) -> libc::c_int {
    if depth > kMaxDepth {
        return 0 as libc::c_int;
    }
    let mut in_0: CBS = *orig_in;
    *ber_found = 0 as libc::c_int;
    while CBS_len(&mut in_0) > 0 as libc::c_int as size_t {
        let mut contents: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        let mut tag: CBS_ASN1_TAG = 0;
        let mut header_len: size_t = 0;
        let mut indefinite: libc::c_int = 0;
        if CBS_get_any_ber_asn1_element(
            &mut in_0,
            &mut contents,
            &mut tag,
            &mut header_len,
            ber_found,
            &mut indefinite,
        ) == 0
        {
            return 0 as libc::c_int;
        }
        if *ber_found != 0 {
            return 1 as libc::c_int;
        }
        if tag & (0x20 as libc::c_uint) << 24 as libc::c_int != 0 {
            if is_string_type(tag) != 0 {
                *ber_found = 1 as libc::c_int;
                return 1 as libc::c_int;
            }
            if CBS_skip(&mut contents, header_len) == 0
                || cbs_find_ber(
                    &mut contents,
                    ber_found,
                    depth.wrapping_add(1 as libc::c_int as uint32_t),
                ) == 0
            {
                return 0 as libc::c_int;
            }
            if *ber_found != 0 {
                return 1 as libc::c_int;
            }
        }
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn cbs_get_eoc(mut cbs: *mut CBS) -> libc::c_int {
    if CBS_len(cbs) >= 2 as libc::c_int as size_t
        && *(CBS_data(cbs)).offset(0 as libc::c_int as isize) as libc::c_int
            == 0 as libc::c_int
        && *(CBS_data(cbs)).offset(1 as libc::c_int as isize) as libc::c_int
            == 0 as libc::c_int
    {
        return CBS_skip(cbs, 2 as libc::c_int as size_t);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn cbs_convert_ber(
    mut in_0: *mut CBS,
    mut out: *mut CBB,
    mut string_tag: CBS_ASN1_TAG,
    mut looking_for_eoc: libc::c_int,
    mut depth: uint32_t,
) -> libc::c_int {
    if string_tag & (0x20 as libc::c_uint) << 24 as libc::c_int == 0 {} else {
        __assert_fail(
            b"!(string_tag & CBS_ASN1_CONSTRUCTED)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/ber.c\0" as *const u8
                as *const libc::c_char,
            114 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 63],
                &[libc::c_char; 63],
            >(b"int cbs_convert_ber(CBS *, CBB *, CBS_ASN1_TAG, int, uint32_t)\0"))
                .as_ptr(),
        );
    }
    'c_2453: {
        if string_tag & (0x20 as libc::c_uint) << 24 as libc::c_int == 0 {} else {
            __assert_fail(
                b"!(string_tag & CBS_ASN1_CONSTRUCTED)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/ber.c\0"
                    as *const u8 as *const libc::c_char,
                114 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 63],
                    &[libc::c_char; 63],
                >(b"int cbs_convert_ber(CBS *, CBB *, CBS_ASN1_TAG, int, uint32_t)\0"))
                    .as_ptr(),
            );
        }
    };
    if depth > kMaxDepth {
        return 0 as libc::c_int;
    }
    while CBS_len(in_0) > 0 as libc::c_int as size_t {
        if looking_for_eoc != 0 && cbs_get_eoc(in_0) != 0 {
            return 1 as libc::c_int;
        }
        let mut contents: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        let mut tag: CBS_ASN1_TAG = 0;
        let mut child_string_tag: CBS_ASN1_TAG = string_tag;
        let mut header_len: size_t = 0;
        let mut indefinite: libc::c_int = 0;
        let mut out_contents: *mut CBB = 0 as *mut CBB;
        let mut out_contents_storage: CBB = cbb_st {
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
        if CBS_get_any_ber_asn1_element(
            in_0,
            &mut contents,
            &mut tag,
            &mut header_len,
            0 as *mut libc::c_int,
            &mut indefinite,
        ) == 0
        {
            return 0 as libc::c_int;
        }
        if string_tag != 0 as libc::c_int as CBS_ASN1_TAG {
            if tag & !((0x20 as libc::c_uint) << 24 as libc::c_int) != string_tag {
                return 0 as libc::c_int;
            }
            out_contents = out;
        } else {
            let mut out_tag: CBS_ASN1_TAG = tag;
            if tag & (0x20 as libc::c_uint) << 24 as libc::c_int != 0
                && is_string_type(tag) != 0
            {
                out_tag &= !((0x20 as libc::c_uint) << 24 as libc::c_int);
                child_string_tag = out_tag;
            }
            if CBB_add_asn1(out, &mut out_contents_storage, out_tag) == 0 {
                return 0 as libc::c_int;
            }
            out_contents = &mut out_contents_storage;
        }
        if indefinite != 0 {
            if cbs_convert_ber(
                in_0,
                out_contents,
                child_string_tag,
                1 as libc::c_int,
                depth.wrapping_add(1 as libc::c_int as uint32_t),
            ) == 0 || CBB_flush(out) == 0
            {
                return 0 as libc::c_int;
            }
        } else {
            if CBS_skip(&mut contents, header_len) == 0 {
                return 0 as libc::c_int;
            }
            if tag & (0x20 as libc::c_uint) << 24 as libc::c_int != 0 {
                if cbs_convert_ber(
                    &mut contents,
                    out_contents,
                    child_string_tag,
                    0 as libc::c_int,
                    depth.wrapping_add(1 as libc::c_int as uint32_t),
                ) == 0
                {
                    return 0 as libc::c_int;
                }
            } else if CBB_add_bytes(
                out_contents,
                CBS_data(&mut contents),
                CBS_len(&mut contents),
            ) == 0
            {
                return 0 as libc::c_int
            }
            if CBB_flush(out) == 0 {
                return 0 as libc::c_int;
            }
        }
    }
    return (looking_for_eoc == 0 as libc::c_int) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_asn1_ber_to_der(
    mut in_0: *mut CBS,
    mut out: *mut CBS,
    mut out_storage: *mut *mut uint8_t,
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
    let mut conversion_needed: libc::c_int = 0;
    if cbs_find_ber(in_0, &mut conversion_needed, 0 as libc::c_int as uint32_t) == 0 {
        return 0 as libc::c_int;
    }
    if conversion_needed == 0 {
        if CBS_get_any_asn1_element(in_0, out, 0 as *mut CBS_ASN1_TAG, 0 as *mut size_t)
            == 0
        {
            return 0 as libc::c_int;
        }
        *out_storage = 0 as *mut uint8_t;
        return 1 as libc::c_int;
    }
    let mut len: size_t = 0;
    if CBB_init(&mut cbb, CBS_len(in_0)) == 0
        || cbs_convert_ber(
            in_0,
            &mut cbb,
            0 as libc::c_int as CBS_ASN1_TAG,
            0 as libc::c_int,
            0 as libc::c_int as uint32_t,
        ) == 0 || CBB_finish(&mut cbb, out_storage, &mut len) == 0
    {
        CBB_cleanup(&mut cbb);
        return 0 as libc::c_int;
    }
    CBS_init(out, *out_storage, len);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_asn1_implicit_string(
    mut in_0: *mut CBS,
    mut out: *mut CBS,
    mut out_storage: *mut *mut uint8_t,
    mut outer_tag: CBS_ASN1_TAG,
    mut inner_tag: CBS_ASN1_TAG,
) -> libc::c_int {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = 0;
    let mut current_block: u64;
    if outer_tag & (0x20 as libc::c_uint) << 24 as libc::c_int == 0 {} else {
        __assert_fail(
            b"!(outer_tag & CBS_ASN1_CONSTRUCTED)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/ber.c\0" as *const u8
                as *const libc::c_char,
            225 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 87],
                &[libc::c_char; 87],
            >(
                b"int CBS_get_asn1_implicit_string(CBS *, CBS *, uint8_t **, CBS_ASN1_TAG, CBS_ASN1_TAG)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2958: {
        if outer_tag & (0x20 as libc::c_uint) << 24 as libc::c_int == 0 {} else {
            __assert_fail(
                b"!(outer_tag & CBS_ASN1_CONSTRUCTED)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/ber.c\0"
                    as *const u8 as *const libc::c_char,
                225 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 87],
                    &[libc::c_char; 87],
                >(
                    b"int CBS_get_asn1_implicit_string(CBS *, CBS *, uint8_t **, CBS_ASN1_TAG, CBS_ASN1_TAG)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if inner_tag & (0x20 as libc::c_uint) << 24 as libc::c_int == 0 {} else {
        __assert_fail(
            b"!(inner_tag & CBS_ASN1_CONSTRUCTED)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/ber.c\0" as *const u8
                as *const libc::c_char,
            226 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 87],
                &[libc::c_char; 87],
            >(
                b"int CBS_get_asn1_implicit_string(CBS *, CBS *, uint8_t **, CBS_ASN1_TAG, CBS_ASN1_TAG)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2911: {
        if inner_tag & (0x20 as libc::c_uint) << 24 as libc::c_int == 0 {} else {
            __assert_fail(
                b"!(inner_tag & CBS_ASN1_CONSTRUCTED)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/ber.c\0"
                    as *const u8 as *const libc::c_char,
                226 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 87],
                    &[libc::c_char; 87],
                >(
                    b"int CBS_get_asn1_implicit_string(CBS *, CBS *, uint8_t **, CBS_ASN1_TAG, CBS_ASN1_TAG)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if is_string_type(inner_tag) != 0 {} else {
        __assert_fail(
            b"is_string_type(inner_tag)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/ber.c\0" as *const u8
                as *const libc::c_char,
            227 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 87],
                &[libc::c_char; 87],
            >(
                b"int CBS_get_asn1_implicit_string(CBS *, CBS *, uint8_t **, CBS_ASN1_TAG, CBS_ASN1_TAG)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2871: {
        if is_string_type(inner_tag) != 0 {} else {
            __assert_fail(
                b"is_string_type(inner_tag)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/ber.c\0"
                    as *const u8 as *const libc::c_char,
                227 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 87],
                    &[libc::c_char; 87],
                >(
                    b"int CBS_get_asn1_implicit_string(CBS *, CBS *, uint8_t **, CBS_ASN1_TAG, CBS_ASN1_TAG)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if CBS_peek_asn1_tag(in_0, outer_tag) != 0 {
        *out_storage = 0 as *mut uint8_t;
        return CBS_get_asn1(in_0, out, outer_tag);
    }
    let mut result: CBB = cbb_st {
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
    let mut child: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBB_init(&mut result, CBS_len(in_0)) == 0
        || CBS_get_asn1(
            in_0,
            &mut child,
            outer_tag | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0
    {
        current_block = 17741533767351163160;
    } else {
        current_block = 2473556513754201174;
    }
    loop {
        match current_block {
            17741533767351163160 => {
                CBB_cleanup(&mut result);
                return 0 as libc::c_int;
            }
            _ => {
                if CBS_len(&mut child) > 0 as libc::c_int as size_t {
                    let mut chunk: CBS = cbs_st {
                        data: 0 as *const uint8_t,
                        len: 0,
                    };
                    if CBS_get_asn1(&mut child, &mut chunk, inner_tag) == 0
                        || CBB_add_bytes(
                            &mut result,
                            CBS_data(&mut chunk),
                            CBS_len(&mut chunk),
                        ) == 0
                    {
                        current_block = 17741533767351163160;
                    } else {
                        current_block = 2473556513754201174;
                    }
                } else {
                    data = 0 as *mut uint8_t;
                    len = 0;
                    if CBB_finish(&mut result, &mut data, &mut len) == 0 {
                        current_block = 17741533767351163160;
                        continue;
                    }
                    CBS_init(out, data, len);
                    *out_storage = data;
                    return 1 as libc::c_int;
                }
            }
        }
    };
}
