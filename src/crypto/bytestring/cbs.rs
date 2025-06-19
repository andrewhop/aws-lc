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
    fn OPENSSL_gmtime_adj(
        tm: *mut tm,
        offset_day: libc::c_int,
        offset_sec: int64_t,
    ) -> libc::c_int;
    fn CBB_init(cbb: *mut CBB, initial_capacity: size_t) -> libc::c_int;
    fn CBB_cleanup(cbb: *mut CBB);
    fn CBB_finish(
        cbb: *mut CBB,
        out_data: *mut *mut uint8_t,
        out_len: *mut size_t,
    ) -> libc::c_int;
    fn CBB_add_bytes(cbb: *mut CBB, data: *const uint8_t, len: size_t) -> libc::c_int;
    fn CBB_add_u8(cbb: *mut CBB, value: uint8_t) -> libc::c_int;
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn CRYPTO_memcmp(
        a: *const libc::c_void,
        b: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn OPENSSL_isdigit(c: libc::c_int) -> libc::c_int;
    fn OPENSSL_strndup(str: *const libc::c_char, size: size_t) -> *mut libc::c_char;
    fn OPENSSL_memdup(data: *const libc::c_void, size: size_t) -> *mut libc::c_void;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memchr(
        _: *const libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type int64_t = __int64_t;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct tm {
    pub tm_sec: libc::c_int,
    pub tm_min: libc::c_int,
    pub tm_hour: libc::c_int,
    pub tm_mday: libc::c_int,
    pub tm_mon: libc::c_int,
    pub tm_year: libc::c_int,
    pub tm_wday: libc::c_int,
    pub tm_yday: libc::c_int,
    pub tm_isdst: libc::c_int,
    pub __tm_gmtoff: libc::c_long,
    pub __tm_zone: *const libc::c_char,
}
#[inline]
unsafe extern "C" fn CRYPTO_bswap2(mut x: uint16_t) -> uint16_t {
    return x.swap_bytes();
}
#[inline]
unsafe extern "C" fn CRYPTO_bswap4(mut x: uint32_t) -> uint32_t {
    return x.swap_bytes();
}
#[inline]
unsafe extern "C" fn CRYPTO_bswap8(mut x: uint64_t) -> uint64_t {
    return x.swap_bytes();
}
#[inline]
unsafe extern "C" fn OPENSSL_memchr(
    mut s: *const libc::c_void,
    mut c: libc::c_int,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return 0 as *mut libc::c_void;
    }
    return memchr(s, c, n);
}
#[inline]
unsafe extern "C" fn OPENSSL_memcpy(
    mut dst: *mut libc::c_void,
    mut src: *const libc::c_void,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return dst;
    }
    return memcpy(dst, src, n);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_init(
    mut cbs: *mut CBS,
    mut data: *const uint8_t,
    mut len: size_t,
) {
    (*cbs).data = data;
    (*cbs).len = len;
}
unsafe extern "C" fn cbs_get(
    mut cbs: *mut CBS,
    mut p: *mut *const uint8_t,
    mut n: size_t,
) -> libc::c_int {
    if (*cbs).len < n {
        return 0 as libc::c_int;
    }
    *p = (*cbs).data;
    (*cbs).data = ((*cbs).data).offset(n as isize);
    (*cbs).len = ((*cbs).len).wrapping_sub(n);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_skip(mut cbs: *mut CBS, mut len: size_t) -> libc::c_int {
    let mut dummy: *const uint8_t = 0 as *const uint8_t;
    return cbs_get(cbs, &mut dummy, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_data(mut cbs: *const CBS) -> *const uint8_t {
    return (*cbs).data;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_len(mut cbs: *const CBS) -> size_t {
    return (*cbs).len;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_stow(
    mut cbs: *const CBS,
    mut out_ptr: *mut *mut uint8_t,
    mut out_len: *mut size_t,
) -> libc::c_int {
    OPENSSL_free(*out_ptr as *mut libc::c_void);
    *out_ptr = 0 as *mut uint8_t;
    *out_len = 0 as libc::c_int as size_t;
    if (*cbs).len == 0 as libc::c_int as size_t {
        return 1 as libc::c_int;
    }
    *out_ptr = OPENSSL_memdup((*cbs).data as *const libc::c_void, (*cbs).len)
        as *mut uint8_t;
    if (*out_ptr).is_null() {
        return 0 as libc::c_int;
    }
    *out_len = (*cbs).len;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_strdup(
    mut cbs: *const CBS,
    mut out_ptr: *mut *mut libc::c_char,
) -> libc::c_int {
    if !(*out_ptr).is_null() {
        OPENSSL_free(*out_ptr as *mut libc::c_void);
    }
    *out_ptr = OPENSSL_strndup((*cbs).data as *const libc::c_char, (*cbs).len);
    return (*out_ptr != 0 as *mut libc::c_void as *mut libc::c_char) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_contains_zero_byte(mut cbs: *const CBS) -> libc::c_int {
    return (OPENSSL_memchr(
        (*cbs).data as *const libc::c_void,
        0 as libc::c_int,
        (*cbs).len,
    ) != 0 as *mut libc::c_void) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_mem_equal(
    mut cbs: *const CBS,
    mut data: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    if len != (*cbs).len {
        return 0 as libc::c_int;
    }
    return (CRYPTO_memcmp(
        (*cbs).data as *const libc::c_void,
        data as *const libc::c_void,
        len,
    ) == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn cbs_get_u(
    mut cbs: *mut CBS,
    mut out: *mut uint64_t,
    mut len: size_t,
) -> libc::c_int {
    let mut result: uint64_t = 0 as libc::c_int as uint64_t;
    let mut data: *const uint8_t = 0 as *const uint8_t;
    if cbs_get(cbs, &mut data, len) == 0 {
        return 0 as libc::c_int;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < len {
        result <<= 8 as libc::c_int;
        result |= *data.offset(i as isize) as uint64_t;
        i = i.wrapping_add(1);
        i;
    }
    *out = result;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_u8(
    mut cbs: *mut CBS,
    mut out: *mut uint8_t,
) -> libc::c_int {
    let mut v: *const uint8_t = 0 as *const uint8_t;
    if cbs_get(cbs, &mut v, 1 as libc::c_int as size_t) == 0 {
        return 0 as libc::c_int;
    }
    *out = *v;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_u16(
    mut cbs: *mut CBS,
    mut out: *mut uint16_t,
) -> libc::c_int {
    let mut v: uint64_t = 0;
    if cbs_get_u(cbs, &mut v, 2 as libc::c_int as size_t) == 0 {
        return 0 as libc::c_int;
    }
    *out = v as uint16_t;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_u16le(
    mut cbs: *mut CBS,
    mut out: *mut uint16_t,
) -> libc::c_int {
    if CBS_get_u16(cbs, out) == 0 {
        return 0 as libc::c_int;
    }
    *out = CRYPTO_bswap2(*out);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_u24(
    mut cbs: *mut CBS,
    mut out: *mut uint32_t,
) -> libc::c_int {
    let mut v: uint64_t = 0;
    if cbs_get_u(cbs, &mut v, 3 as libc::c_int as size_t) == 0 {
        return 0 as libc::c_int;
    }
    *out = v as uint32_t;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_u32(
    mut cbs: *mut CBS,
    mut out: *mut uint32_t,
) -> libc::c_int {
    let mut v: uint64_t = 0;
    if cbs_get_u(cbs, &mut v, 4 as libc::c_int as size_t) == 0 {
        return 0 as libc::c_int;
    }
    *out = v as uint32_t;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_u32le(
    mut cbs: *mut CBS,
    mut out: *mut uint32_t,
) -> libc::c_int {
    if CBS_get_u32(cbs, out) == 0 {
        return 0 as libc::c_int;
    }
    *out = CRYPTO_bswap4(*out);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_u64(
    mut cbs: *mut CBS,
    mut out: *mut uint64_t,
) -> libc::c_int {
    return cbs_get_u(cbs, out, 8 as libc::c_int as size_t);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_u64le(
    mut cbs: *mut CBS,
    mut out: *mut uint64_t,
) -> libc::c_int {
    if cbs_get_u(cbs, out, 8 as libc::c_int as size_t) == 0 {
        return 0 as libc::c_int;
    }
    *out = CRYPTO_bswap8(*out);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_last_u8(
    mut cbs: *mut CBS,
    mut out: *mut uint8_t,
) -> libc::c_int {
    if (*cbs).len == 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    *out = *((*cbs).data)
        .offset(((*cbs).len).wrapping_sub(1 as libc::c_int as size_t) as isize);
    (*cbs).len = ((*cbs).len).wrapping_sub(1);
    (*cbs).len;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_bytes(
    mut cbs: *mut CBS,
    mut out: *mut CBS,
    mut len: size_t,
) -> libc::c_int {
    let mut v: *const uint8_t = 0 as *const uint8_t;
    if cbs_get(cbs, &mut v, len) == 0 {
        return 0 as libc::c_int;
    }
    CBS_init(out, v, len);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_copy_bytes(
    mut cbs: *mut CBS,
    mut out: *mut uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut v: *const uint8_t = 0 as *const uint8_t;
    if cbs_get(cbs, &mut v, len) == 0 {
        return 0 as libc::c_int;
    }
    OPENSSL_memcpy(out as *mut libc::c_void, v as *const libc::c_void, len);
    return 1 as libc::c_int;
}
unsafe extern "C" fn cbs_get_length_prefixed(
    mut cbs: *mut CBS,
    mut out: *mut CBS,
    mut len_len: size_t,
) -> libc::c_int {
    let mut len: uint64_t = 0;
    if cbs_get_u(cbs, &mut len, len_len) == 0 {
        return 0 as libc::c_int;
    }
    if len_len <= 3 as libc::c_int as size_t {} else {
        __assert_fail(
            b"len_len <= 3\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbs.c\0" as *const u8
                as *const libc::c_char,
            205 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 50],
                &[libc::c_char; 50],
            >(b"int cbs_get_length_prefixed(CBS *, CBS *, size_t)\0"))
                .as_ptr(),
        );
    }
    'c_9519: {
        if len_len <= 3 as libc::c_int as size_t {} else {
            __assert_fail(
                b"len_len <= 3\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbs.c\0"
                    as *const u8 as *const libc::c_char,
                205 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 50],
                    &[libc::c_char; 50],
                >(b"int cbs_get_length_prefixed(CBS *, CBS *, size_t)\0"))
                    .as_ptr(),
            );
        }
    };
    return CBS_get_bytes(cbs, out, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_u8_length_prefixed(
    mut cbs: *mut CBS,
    mut out: *mut CBS,
) -> libc::c_int {
    return cbs_get_length_prefixed(cbs, out, 1 as libc::c_int as size_t);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_u16_length_prefixed(
    mut cbs: *mut CBS,
    mut out: *mut CBS,
) -> libc::c_int {
    return cbs_get_length_prefixed(cbs, out, 2 as libc::c_int as size_t);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_u24_length_prefixed(
    mut cbs: *mut CBS,
    mut out: *mut CBS,
) -> libc::c_int {
    return cbs_get_length_prefixed(cbs, out, 3 as libc::c_int as size_t);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_until_first(
    mut cbs: *mut CBS,
    mut out: *mut CBS,
    mut c: uint8_t,
) -> libc::c_int {
    let mut split: *const uint8_t = OPENSSL_memchr(
        CBS_data(cbs) as *const libc::c_void,
        c as libc::c_int,
        CBS_len(cbs),
    ) as *const uint8_t;
    if split.is_null() {
        return 0 as libc::c_int;
    }
    return CBS_get_bytes(
        cbs,
        out,
        split.offset_from(CBS_data(cbs)) as libc::c_long as size_t,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_u64_decimal(
    mut cbs: *mut CBS,
    mut out: *mut uint64_t,
) -> libc::c_int {
    let mut v: uint64_t = 0 as libc::c_int as uint64_t;
    let mut seen_digit: libc::c_int = 0 as libc::c_int;
    while CBS_len(cbs) != 0 as libc::c_int as size_t {
        let mut c: uint8_t = *(CBS_data(cbs)).offset(0 as libc::c_int as isize);
        if OPENSSL_isdigit(c as libc::c_int) == 0 {
            break;
        }
        CBS_skip(cbs, 1 as libc::c_int as size_t);
        if v == 0 as libc::c_int as uint64_t && seen_digit != 0
            || v
                > (18446744073709551615 as libc::c_ulong)
                    .wrapping_div(10 as libc::c_int as libc::c_ulong)
            || v * 10 as libc::c_int as uint64_t
                > (18446744073709551615 as libc::c_ulong)
                    .wrapping_sub((c as libc::c_int - '0' as i32) as libc::c_ulong)
        {
            return 0 as libc::c_int;
        }
        v = (v * 10 as libc::c_int as uint64_t)
            .wrapping_add((c as libc::c_int - '0' as i32) as uint64_t);
        seen_digit = 1 as libc::c_int;
    }
    *out = v;
    return seen_digit;
}
unsafe extern "C" fn parse_base128_integer(
    mut cbs: *mut CBS,
    mut out: *mut uint64_t,
) -> libc::c_int {
    let mut v: uint64_t = 0 as libc::c_int as uint64_t;
    let mut b: uint8_t = 0;
    loop {
        if CBS_get_u8(cbs, &mut b) == 0 {
            return 0 as libc::c_int;
        }
        if v >> 64 as libc::c_int - 7 as libc::c_int != 0 as libc::c_int as uint64_t {
            return 0 as libc::c_int;
        }
        if v == 0 as libc::c_int as uint64_t && b as libc::c_int == 0x80 as libc::c_int {
            return 0 as libc::c_int;
        }
        v = v << 7 as libc::c_int | (b as libc::c_int & 0x7f as libc::c_int) as uint64_t;
        if !(b as libc::c_int & 0x80 as libc::c_int != 0) {
            break;
        }
    }
    *out = v;
    return 1 as libc::c_int;
}
unsafe extern "C" fn parse_asn1_tag(
    mut cbs: *mut CBS,
    mut out: *mut CBS_ASN1_TAG,
    mut universal_tag_ok: libc::c_int,
) -> libc::c_int {
    let mut tag_byte: uint8_t = 0;
    if CBS_get_u8(cbs, &mut tag_byte) == 0 {
        return 0 as libc::c_int;
    }
    let mut tag: CBS_ASN1_TAG = (tag_byte as CBS_ASN1_TAG
        & 0xe0 as libc::c_int as CBS_ASN1_TAG) << 24 as libc::c_int;
    let mut tag_number: CBS_ASN1_TAG = (tag_byte as libc::c_int & 0x1f as libc::c_int)
        as CBS_ASN1_TAG;
    if tag_number == 0x1f as libc::c_int as CBS_ASN1_TAG {
        let mut v: uint64_t = 0;
        if parse_base128_integer(cbs, &mut v) == 0
            || v
                > ((1 as libc::c_uint) << 5 as libc::c_int + 24 as libc::c_int)
                    .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint64_t
            || v < 0x1f as libc::c_int as uint64_t
        {
            return 0 as libc::c_int;
        }
        tag_number = v as CBS_ASN1_TAG;
    }
    tag |= tag_number;
    if universal_tag_ok == 0
        && tag & !((0x20 as libc::c_uint) << 24 as libc::c_int)
            == 0 as libc::c_int as libc::c_uint
    {
        return 0 as libc::c_int;
    }
    *out = tag;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbs_get_any_asn1_element(
    mut cbs: *mut CBS,
    mut out: *mut CBS,
    mut out_tag: *mut CBS_ASN1_TAG,
    mut out_header_len: *mut size_t,
    mut out_ber_found: *mut libc::c_int,
    mut out_indefinite: *mut libc::c_int,
    mut ber_ok: libc::c_int,
    mut universal_tag_ok: libc::c_int,
) -> libc::c_int {
    let mut header: CBS = *cbs;
    let mut throwaway: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if out.is_null() {
        out = &mut throwaway;
    }
    if ber_ok != 0 {
        *out_ber_found = 0 as libc::c_int;
        *out_indefinite = 0 as libc::c_int;
    } else {
        if out_ber_found.is_null() {} else {
            __assert_fail(
                b"out_ber_found == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbs.c\0"
                    as *const u8 as *const libc::c_char,
                332 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 93],
                    &[libc::c_char; 93],
                >(
                    b"int cbs_get_any_asn1_element(CBS *, CBS *, CBS_ASN1_TAG *, size_t *, int *, int *, int, int)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_10516: {
            if out_ber_found.is_null() {} else {
                __assert_fail(
                    b"out_ber_found == NULL\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbs.c\0"
                        as *const u8 as *const libc::c_char,
                    332 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 93],
                        &[libc::c_char; 93],
                    >(
                        b"int cbs_get_any_asn1_element(CBS *, CBS *, CBS_ASN1_TAG *, size_t *, int *, int *, int, int)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        if out_indefinite.is_null() {} else {
            __assert_fail(
                b"out_indefinite == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbs.c\0"
                    as *const u8 as *const libc::c_char,
                333 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 93],
                    &[libc::c_char; 93],
                >(
                    b"int cbs_get_any_asn1_element(CBS *, CBS *, CBS_ASN1_TAG *, size_t *, int *, int *, int, int)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_10472: {
            if out_indefinite.is_null() {} else {
                __assert_fail(
                    b"out_indefinite == NULL\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbs.c\0"
                        as *const u8 as *const libc::c_char,
                    333 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 93],
                        &[libc::c_char; 93],
                    >(
                        b"int cbs_get_any_asn1_element(CBS *, CBS *, CBS_ASN1_TAG *, size_t *, int *, int *, int, int)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
    }
    let mut tag: CBS_ASN1_TAG = 0;
    if parse_asn1_tag(&mut header, &mut tag, universal_tag_ok) == 0 {
        return 0 as libc::c_int;
    }
    if !out_tag.is_null() {
        *out_tag = tag;
    }
    let mut length_byte: uint8_t = 0;
    if CBS_get_u8(&mut header, &mut length_byte) == 0 {
        return 0 as libc::c_int;
    }
    let mut header_len: size_t = (CBS_len(cbs)).wrapping_sub(CBS_len(&mut header));
    let mut len: size_t = 0;
    if length_byte as libc::c_int & 0x80 as libc::c_int == 0 as libc::c_int {
        len = (length_byte as size_t).wrapping_add(header_len);
        if !out_header_len.is_null() {
            *out_header_len = header_len;
        }
    } else {
        let num_bytes: size_t = (length_byte as libc::c_int & 0x7f as libc::c_int)
            as size_t;
        let mut len64: uint64_t = 0;
        if ber_ok != 0
            && tag & (0x20 as libc::c_uint) << 24 as libc::c_int
                != 0 as libc::c_int as libc::c_uint
            && num_bytes == 0 as libc::c_int as size_t
        {
            if !out_header_len.is_null() {
                *out_header_len = header_len;
            }
            *out_ber_found = 1 as libc::c_int;
            *out_indefinite = 1 as libc::c_int;
            return CBS_get_bytes(cbs, out, header_len);
        }
        if num_bytes == 0 as libc::c_int as size_t
            || num_bytes > 4 as libc::c_int as size_t
        {
            return 0 as libc::c_int;
        }
        if cbs_get_u(&mut header, &mut len64, num_bytes) == 0 {
            return 0 as libc::c_int;
        }
        if len64 < 128 as libc::c_int as uint64_t {
            if ber_ok != 0 {
                *out_ber_found = 1 as libc::c_int;
            } else {
                return 0 as libc::c_int
            }
        }
        if len64
            >> num_bytes.wrapping_sub(1 as libc::c_int as size_t)
                * 8 as libc::c_int as size_t == 0 as libc::c_int as uint64_t
        {
            if ber_ok != 0 {
                *out_ber_found = 1 as libc::c_int;
            } else {
                return 0 as libc::c_int
            }
        }
        len = len64;
        if len.wrapping_add(header_len).wrapping_add(num_bytes) < len {
            return 0 as libc::c_int;
        }
        len = len.wrapping_add(header_len.wrapping_add(num_bytes));
        if !out_header_len.is_null() {
            *out_header_len = header_len.wrapping_add(num_bytes);
        }
    }
    return CBS_get_bytes(cbs, out, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_any_asn1(
    mut cbs: *mut CBS,
    mut out: *mut CBS,
    mut out_tag: *mut CBS_ASN1_TAG,
) -> libc::c_int {
    let mut header_len: size_t = 0;
    if CBS_get_any_asn1_element(cbs, out, out_tag, &mut header_len) == 0 {
        return 0 as libc::c_int;
    }
    if CBS_skip(out, header_len) == 0 {
        __assert_fail(
            b"0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbs.c\0" as *const u8
                as *const libc::c_char,
            427 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 51],
                &[libc::c_char; 51],
            >(b"int CBS_get_any_asn1(CBS *, CBS *, CBS_ASN1_TAG *)\0"))
                .as_ptr(),
        );
        'c_10660: {
            __assert_fail(
                b"0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbs.c\0"
                    as *const u8 as *const libc::c_char,
                427 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 51],
                    &[libc::c_char; 51],
                >(b"int CBS_get_any_asn1(CBS *, CBS *, CBS_ASN1_TAG *)\0"))
                    .as_ptr(),
            );
        };
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_any_asn1_element(
    mut cbs: *mut CBS,
    mut out: *mut CBS,
    mut out_tag: *mut CBS_ASN1_TAG,
    mut out_header_len: *mut size_t,
) -> libc::c_int {
    return cbs_get_any_asn1_element(
        cbs,
        out,
        out_tag,
        out_header_len,
        0 as *mut libc::c_int,
        0 as *mut libc::c_int,
        0 as libc::c_int,
        0 as libc::c_int,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_any_ber_asn1_element(
    mut cbs: *mut CBS,
    mut out: *mut CBS,
    mut out_tag: *mut CBS_ASN1_TAG,
    mut out_header_len: *mut size_t,
    mut out_ber_found: *mut libc::c_int,
    mut out_indefinite: *mut libc::c_int,
) -> libc::c_int {
    let mut ber_found_temp: libc::c_int = 0;
    return cbs_get_any_asn1_element(
        cbs,
        out,
        out_tag,
        out_header_len,
        if !out_ber_found.is_null() { out_ber_found } else { &mut ber_found_temp },
        out_indefinite,
        1 as libc::c_int,
        0 as libc::c_int,
    );
}
unsafe extern "C" fn cbs_get_asn1(
    mut cbs: *mut CBS,
    mut out: *mut CBS,
    mut tag_value: CBS_ASN1_TAG,
    mut skip_header: libc::c_int,
) -> libc::c_int {
    let mut header_len: size_t = 0;
    let mut tag: CBS_ASN1_TAG = 0;
    let mut throwaway: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if out.is_null() {
        out = &mut throwaway;
    }
    if CBS_get_any_asn1_element(cbs, out, &mut tag, &mut header_len) == 0
        || tag != tag_value
    {
        return 0 as libc::c_int;
    }
    if skip_header != 0 && CBS_skip(out, header_len) == 0 {
        __assert_fail(
            b"0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbs.c\0" as *const u8
                as *const libc::c_char,
            466 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 50],
                &[libc::c_char; 50],
            >(b"int cbs_get_asn1(CBS *, CBS *, CBS_ASN1_TAG, int)\0"))
                .as_ptr(),
        );
        'c_9831: {
            __assert_fail(
                b"0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbs.c\0"
                    as *const u8 as *const libc::c_char,
                466 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 50],
                    &[libc::c_char; 50],
                >(b"int cbs_get_asn1(CBS *, CBS *, CBS_ASN1_TAG, int)\0"))
                    .as_ptr(),
            );
        };
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_asn1(
    mut cbs: *mut CBS,
    mut out: *mut CBS,
    mut tag_value: CBS_ASN1_TAG,
) -> libc::c_int {
    return cbs_get_asn1(cbs, out, tag_value, 1 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_asn1_element(
    mut cbs: *mut CBS,
    mut out: *mut CBS,
    mut tag_value: CBS_ASN1_TAG,
) -> libc::c_int {
    return cbs_get_asn1(cbs, out, tag_value, 0 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_peek_asn1_tag(
    mut cbs: *const CBS,
    mut tag_value: CBS_ASN1_TAG,
) -> libc::c_int {
    let mut copy: CBS = *cbs;
    let mut actual_tag: CBS_ASN1_TAG = 0;
    return (parse_asn1_tag(&mut copy, &mut actual_tag, 0 as libc::c_int) != 0
        && tag_value == actual_tag) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_asn1_uint64(
    mut cbs: *mut CBS,
    mut out: *mut uint64_t,
) -> libc::c_int {
    let mut bytes: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_get_asn1(cbs, &mut bytes, 0x2 as libc::c_uint) == 0
        || CBS_is_unsigned_asn1_integer(&mut bytes) == 0
    {
        return 0 as libc::c_int;
    }
    *out = 0 as libc::c_int as uint64_t;
    let mut data: *const uint8_t = CBS_data(&mut bytes);
    let mut len: size_t = CBS_len(&mut bytes);
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < len {
        if *out >> 56 as libc::c_int != 0 as libc::c_int as uint64_t {
            return 0 as libc::c_int;
        }
        *out <<= 8 as libc::c_int;
        *out |= *data.offset(i as isize) as uint64_t;
        i = i.wrapping_add(1);
        i;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_asn1_int64(
    mut cbs: *mut CBS,
    mut out: *mut int64_t,
) -> libc::c_int {
    let mut is_negative: libc::c_int = 0;
    let mut bytes: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_get_asn1(cbs, &mut bytes, 0x2 as libc::c_uint) == 0
        || CBS_is_valid_asn1_integer(&mut bytes, &mut is_negative) == 0
    {
        return 0 as libc::c_int;
    }
    let mut data: *const uint8_t = CBS_data(&mut bytes);
    let len: size_t = CBS_len(&mut bytes);
    if len > ::core::mem::size_of::<int64_t>() as libc::c_ulong {
        return 0 as libc::c_int;
    }
    let mut sign_extend: [uint8_t; 8] = [0; 8];
    memset(
        sign_extend.as_mut_ptr() as *mut libc::c_void,
        if is_negative != 0 { 0xff as libc::c_int } else { 0 as libc::c_int },
        ::core::mem::size_of::<[uint8_t; 8]>() as libc::c_ulong,
    );
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < len && i < ::core::mem::size_of::<int64_t>() as libc::c_ulong {
        sign_extend[i
            as usize] = *data
            .offset(
                len.wrapping_sub(i).wrapping_sub(1 as libc::c_int as size_t) as isize,
            );
        i = i.wrapping_add(1);
        i;
    }
    memcpy(
        out as *mut libc::c_void,
        sign_extend.as_mut_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint8_t; 8]>() as libc::c_ulong,
    );
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_asn1_bool(
    mut cbs: *mut CBS,
    mut out: *mut libc::c_int,
) -> libc::c_int {
    let mut bytes: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_get_asn1(cbs, &mut bytes, 0x1 as libc::c_uint) == 0
        || CBS_len(&mut bytes) != 1 as libc::c_int as size_t
    {
        return 0 as libc::c_int;
    }
    let value: uint8_t = *CBS_data(&mut bytes);
    if value as libc::c_int != 0 as libc::c_int
        && value as libc::c_int != 0xff as libc::c_int
    {
        return 0 as libc::c_int;
    }
    *out = (value != 0) as libc::c_int;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_optional_asn1(
    mut cbs: *mut CBS,
    mut out: *mut CBS,
    mut out_present: *mut libc::c_int,
    mut tag: CBS_ASN1_TAG,
) -> libc::c_int {
    let mut present: libc::c_int = 0 as libc::c_int;
    if CBS_peek_asn1_tag(cbs, tag) != 0 {
        if CBS_get_asn1(cbs, out, tag) == 0 {
            return 0 as libc::c_int;
        }
        present = 1 as libc::c_int;
    }
    if !out_present.is_null() {
        *out_present = present;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_optional_asn1_octet_string(
    mut cbs: *mut CBS,
    mut out: *mut CBS,
    mut out_present: *mut libc::c_int,
    mut tag: CBS_ASN1_TAG,
) -> libc::c_int {
    let mut child: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut present: libc::c_int = 0;
    if CBS_get_optional_asn1(cbs, &mut child, &mut present, tag) == 0 {
        return 0 as libc::c_int;
    }
    if present != 0 {
        if !out.is_null() {} else {
            __assert_fail(
                b"out\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbs.c\0"
                    as *const u8 as *const libc::c_char,
                582 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 74],
                    &[libc::c_char; 74],
                >(
                    b"int CBS_get_optional_asn1_octet_string(CBS *, CBS *, int *, CBS_ASN1_TAG)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_11284: {
            if !out.is_null() {} else {
                __assert_fail(
                    b"out\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbs.c\0"
                        as *const u8 as *const libc::c_char,
                    582 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 74],
                        &[libc::c_char; 74],
                    >(
                        b"int CBS_get_optional_asn1_octet_string(CBS *, CBS *, int *, CBS_ASN1_TAG)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        if CBS_get_asn1(&mut child, out, 0x4 as libc::c_uint) == 0
            || CBS_len(&mut child) != 0 as libc::c_int as size_t
        {
            return 0 as libc::c_int;
        }
    } else {
        CBS_init(out, 0 as *const uint8_t, 0 as libc::c_int as size_t);
    }
    if !out_present.is_null() {
        *out_present = present;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_optional_asn1_uint64(
    mut cbs: *mut CBS,
    mut out: *mut uint64_t,
    mut tag: CBS_ASN1_TAG,
    mut default_value: uint64_t,
) -> libc::c_int {
    let mut child: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut present: libc::c_int = 0;
    if CBS_get_optional_asn1(cbs, &mut child, &mut present, tag) == 0 {
        return 0 as libc::c_int;
    }
    if present != 0 {
        if CBS_get_asn1_uint64(&mut child, out) == 0
            || CBS_len(&mut child) != 0 as libc::c_int as size_t
        {
            return 0 as libc::c_int;
        }
    } else {
        *out = default_value;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_optional_asn1_bool(
    mut cbs: *mut CBS,
    mut out: *mut libc::c_int,
    mut tag: CBS_ASN1_TAG,
    mut default_value: libc::c_int,
) -> libc::c_int {
    let mut child: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut child2: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut present: libc::c_int = 0;
    if CBS_get_optional_asn1(cbs, &mut child, &mut present, tag) == 0 {
        return 0 as libc::c_int;
    }
    if present != 0 {
        let mut boolean: uint8_t = 0;
        if CBS_get_asn1(&mut child, &mut child2, 0x1 as libc::c_uint) == 0
            || CBS_len(&mut child2) != 1 as libc::c_int as size_t
            || CBS_len(&mut child) != 0 as libc::c_int as size_t
        {
            return 0 as libc::c_int;
        }
        boolean = *(CBS_data(&mut child2)).offset(0 as libc::c_int as isize);
        if boolean as libc::c_int == 0 as libc::c_int {
            *out = 0 as libc::c_int;
        } else if boolean as libc::c_int == 0xff as libc::c_int {
            *out = 1 as libc::c_int;
        } else {
            return 0 as libc::c_int
        }
    } else {
        *out = default_value;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_is_valid_asn1_bitstring(
    mut cbs: *const CBS,
) -> libc::c_int {
    let mut in_0: CBS = *cbs;
    let mut num_unused_bits: uint8_t = 0;
    if CBS_get_u8(&mut in_0, &mut num_unused_bits) == 0
        || num_unused_bits as libc::c_int > 7 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    if num_unused_bits as libc::c_int == 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    let mut last: uint8_t = 0;
    if CBS_get_last_u8(&mut in_0, &mut last) == 0
        || last as libc::c_int
            & ((1 as libc::c_int) << num_unused_bits as libc::c_int) - 1 as libc::c_int
            != 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_asn1_bitstring_has_bit(
    mut cbs: *const CBS,
    mut bit: libc::c_uint,
) -> libc::c_int {
    if CBS_is_valid_asn1_bitstring(cbs) == 0 {
        return 0 as libc::c_int;
    }
    let byte_num: libc::c_uint = (bit >> 3 as libc::c_int)
        .wrapping_add(1 as libc::c_int as libc::c_uint);
    let bit_num: libc::c_uint = (7 as libc::c_int as libc::c_uint)
        .wrapping_sub(bit & 7 as libc::c_int as libc::c_uint);
    return ((byte_num as size_t) < CBS_len(cbs)
        && *(CBS_data(cbs)).offset(byte_num as isize) as libc::c_int
            & (1 as libc::c_int) << bit_num != 0 as libc::c_int) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_is_valid_asn1_integer(
    mut cbs: *const CBS,
    mut out_is_negative: *mut libc::c_int,
) -> libc::c_int {
    let mut copy: CBS = *cbs;
    let mut first_byte: uint8_t = 0;
    let mut second_byte: uint8_t = 0;
    if CBS_get_u8(&mut copy, &mut first_byte) == 0 {
        return 0 as libc::c_int;
    }
    if !out_is_negative.is_null() {
        *out_is_negative = (first_byte as libc::c_int & 0x80 as libc::c_int
            != 0 as libc::c_int) as libc::c_int;
    }
    if CBS_get_u8(&mut copy, &mut second_byte) == 0 {
        return 1 as libc::c_int;
    }
    if first_byte as libc::c_int == 0 as libc::c_int
        && second_byte as libc::c_int & 0x80 as libc::c_int == 0 as libc::c_int
        || first_byte as libc::c_int == 0xff as libc::c_int
            && second_byte as libc::c_int & 0x80 as libc::c_int != 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_is_unsigned_asn1_integer(
    mut cbs: *const CBS,
) -> libc::c_int {
    let mut is_negative: libc::c_int = 0;
    return (CBS_is_valid_asn1_integer(cbs, &mut is_negative) != 0 && is_negative == 0)
        as libc::c_int;
}
unsafe extern "C" fn add_decimal(mut out: *mut CBB, mut v: uint64_t) -> libc::c_int {
    let mut buf: [libc::c_char; 24] = [0; 24];
    snprintf(
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 24]>() as libc::c_ulong,
        b"%lu\0" as *const u8 as *const libc::c_char,
        v,
    );
    return CBB_add_bytes(
        out,
        buf.as_mut_ptr() as *const uint8_t,
        strlen(buf.as_mut_ptr()),
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_is_valid_asn1_oid(mut cbs: *const CBS) -> libc::c_int {
    if CBS_len(cbs) == 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    let mut copy: CBS = *cbs;
    let mut v: uint8_t = 0;
    let mut prev: uint8_t = 0 as libc::c_int as uint8_t;
    while CBS_get_u8(&mut copy, &mut v) != 0 {
        if prev as libc::c_int & 0x80 as libc::c_int == 0 as libc::c_int
            && v as libc::c_int == 0x80 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        prev = v;
    }
    return (prev as libc::c_int & 0x80 as libc::c_int == 0 as libc::c_int)
        as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_asn1_oid_to_text(mut cbs: *const CBS) -> *mut libc::c_char {
    let mut copy: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut v: uint64_t = 0;
    let mut txt: *mut uint8_t = 0 as *mut uint8_t;
    let mut txt_len: size_t = 0;
    let mut current_block: u64;
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
    if !(CBB_init(&mut cbb, 32 as libc::c_int as size_t) == 0) {
        copy = *cbs;
        v = 0;
        if !(parse_base128_integer(&mut copy, &mut v) == 0) {
            if v >= 80 as libc::c_int as uint64_t {
                if CBB_add_bytes(
                    &mut cbb,
                    b"2.\0" as *const u8 as *const libc::c_char as *const uint8_t,
                    2 as libc::c_int as size_t,
                ) == 0
                    || add_decimal(
                        &mut cbb,
                        v.wrapping_sub(80 as libc::c_int as uint64_t),
                    ) == 0
                {
                    current_block = 2254092431940427851;
                } else {
                    current_block = 17216689946888361452;
                }
            } else if add_decimal(&mut cbb, v / 40 as libc::c_int as uint64_t) == 0
                || CBB_add_u8(&mut cbb, '.' as i32 as uint8_t) == 0
                || add_decimal(&mut cbb, v % 40 as libc::c_int as uint64_t) == 0
            {
                current_block = 2254092431940427851;
            } else {
                current_block = 17216689946888361452;
            }
            match current_block {
                2254092431940427851 => {}
                _ => {
                    loop {
                        if !(CBS_len(&mut copy) != 0 as libc::c_int as size_t) {
                            current_block = 17965632435239708295;
                            break;
                        }
                        if parse_base128_integer(&mut copy, &mut v) == 0
                            || CBB_add_u8(&mut cbb, '.' as i32 as uint8_t) == 0
                            || add_decimal(&mut cbb, v) == 0
                        {
                            current_block = 2254092431940427851;
                            break;
                        }
                    }
                    match current_block {
                        2254092431940427851 => {}
                        _ => {
                            txt = 0 as *mut uint8_t;
                            txt_len = 0;
                            if !(CBB_add_u8(&mut cbb, '\0' as i32 as uint8_t) == 0
                                || CBB_finish(&mut cbb, &mut txt, &mut txt_len) == 0)
                            {
                                return txt as *mut libc::c_char;
                            }
                        }
                    }
                }
            }
        }
    }
    CBB_cleanup(&mut cbb);
    return 0 as *mut libc::c_char;
}
unsafe extern "C" fn cbs_get_two_digits(
    mut cbs: *mut CBS,
    mut out: *mut libc::c_int,
) -> libc::c_int {
    let mut first_digit: uint8_t = 0;
    let mut second_digit: uint8_t = 0;
    if CBS_get_u8(cbs, &mut first_digit) == 0 {
        return 0 as libc::c_int;
    }
    if OPENSSL_isdigit(first_digit as libc::c_int) == 0 {
        return 0 as libc::c_int;
    }
    if CBS_get_u8(cbs, &mut second_digit) == 0 {
        return 0 as libc::c_int;
    }
    if OPENSSL_isdigit(second_digit as libc::c_int) == 0 {
        return 0 as libc::c_int;
    }
    *out = (first_digit as libc::c_int - '0' as i32) * 10 as libc::c_int
        + (second_digit as libc::c_int - '0' as i32);
    return 1 as libc::c_int;
}
unsafe extern "C" fn is_valid_day(
    mut year: libc::c_int,
    mut month: libc::c_int,
    mut day: libc::c_int,
) -> libc::c_int {
    if day < 1 as libc::c_int {
        return 0 as libc::c_int;
    }
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => return (day <= 31 as libc::c_int) as libc::c_int,
        4 | 6 | 9 | 11 => return (day <= 30 as libc::c_int) as libc::c_int,
        2 => {
            if year % 4 as libc::c_int == 0 as libc::c_int
                && year % 100 as libc::c_int != 0 as libc::c_int
                || year % 400 as libc::c_int == 0 as libc::c_int
            {
                return (day <= 29 as libc::c_int) as libc::c_int
            } else {
                return (day <= 28 as libc::c_int) as libc::c_int
            }
        }
        _ => return 0 as libc::c_int,
    };
}
unsafe extern "C" fn CBS_parse_rfc5280_time_internal(
    mut cbs: *const CBS,
    mut is_gentime: libc::c_int,
    mut allow_timezone_offset: libc::c_int,
    mut out_tm: *mut tm,
) -> libc::c_int {
    let mut year: libc::c_int = 0;
    let mut month: libc::c_int = 0;
    let mut day: libc::c_int = 0;
    let mut hour: libc::c_int = 0;
    let mut min: libc::c_int = 0;
    let mut sec: libc::c_int = 0;
    let mut tmp: libc::c_int = 0;
    let mut copy: CBS = *cbs;
    let mut tz: uint8_t = 0;
    if is_gentime != 0 {
        if cbs_get_two_digits(&mut copy, &mut tmp) == 0 {
            return 0 as libc::c_int;
        }
        year = tmp * 100 as libc::c_int;
        if cbs_get_two_digits(&mut copy, &mut tmp) == 0 {
            return 0 as libc::c_int;
        }
        year += tmp;
    } else {
        year = 1900 as libc::c_int;
        if cbs_get_two_digits(&mut copy, &mut tmp) == 0 {
            return 0 as libc::c_int;
        }
        year += tmp;
        if year < 1950 as libc::c_int {
            year += 100 as libc::c_int;
        }
        if year >= 2050 as libc::c_int {
            return 0 as libc::c_int;
        }
    }
    if cbs_get_two_digits(&mut copy, &mut month) == 0 || month < 1 as libc::c_int
        || month > 12 as libc::c_int || cbs_get_two_digits(&mut copy, &mut day) == 0
        || is_valid_day(year, month, day) == 0
        || cbs_get_two_digits(&mut copy, &mut hour) == 0 || hour > 23 as libc::c_int
        || cbs_get_two_digits(&mut copy, &mut min) == 0 || min > 59 as libc::c_int
        || cbs_get_two_digits(&mut copy, &mut sec) == 0 || sec > 59 as libc::c_int
        || CBS_get_u8(&mut copy, &mut tz) == 0
    {
        return 0 as libc::c_int;
    }
    let mut offset_sign: libc::c_int = 0 as libc::c_int;
    match tz as libc::c_int {
        90 => {}
        43 => {
            offset_sign = 1 as libc::c_int;
        }
        45 => {
            offset_sign = -(1 as libc::c_int);
        }
        _ => return 0 as libc::c_int,
    }
    let mut offset_seconds: libc::c_int = 0 as libc::c_int;
    if offset_sign != 0 as libc::c_int {
        if allow_timezone_offset == 0 {
            return 0 as libc::c_int;
        }
        let mut offset_hours: libc::c_int = 0;
        let mut offset_minutes: libc::c_int = 0;
        if cbs_get_two_digits(&mut copy, &mut offset_hours) == 0
            || offset_hours > 23 as libc::c_int
            || cbs_get_two_digits(&mut copy, &mut offset_minutes) == 0
            || offset_minutes > 59 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        offset_seconds = offset_sign
            * (offset_hours * 3600 as libc::c_int + offset_minutes * 60 as libc::c_int);
    }
    if CBS_len(&mut copy) != 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    if !out_tm.is_null() {
        (*out_tm).tm_year = year - 1900 as libc::c_int;
        (*out_tm).tm_mon = month - 1 as libc::c_int;
        (*out_tm).tm_mday = day;
        (*out_tm).tm_hour = hour;
        (*out_tm).tm_min = min;
        (*out_tm).tm_sec = sec;
        if offset_seconds != 0
            && OPENSSL_gmtime_adj(out_tm, 0 as libc::c_int, offset_seconds as int64_t)
                == 0
        {
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_parse_generalized_time(
    mut cbs: *const CBS,
    mut out_tm: *mut tm,
    mut allow_timezone_offset: libc::c_int,
) -> libc::c_int {
    return CBS_parse_rfc5280_time_internal(
        cbs,
        1 as libc::c_int,
        allow_timezone_offset,
        out_tm,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_parse_utc_time(
    mut cbs: *const CBS,
    mut out_tm: *mut tm,
    mut allow_timezone_offset: libc::c_int,
) -> libc::c_int {
    return CBS_parse_rfc5280_time_internal(
        cbs,
        0 as libc::c_int,
        allow_timezone_offset,
        out_tm,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBS_get_optional_asn1_int64(
    mut cbs: *mut CBS,
    mut out: *mut int64_t,
    mut tag: CBS_ASN1_TAG,
    mut default_value: int64_t,
) -> libc::c_int {
    let mut child: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut present: libc::c_int = 0;
    if CBS_get_optional_asn1(cbs, &mut child, &mut present, tag) == 0 {
        return 0 as libc::c_int;
    }
    if present != 0 {
        if CBS_get_asn1_int64(&mut child, out) == 0
            || CBS_len(&mut child) != 0 as libc::c_int as size_t
        {
            return 0 as libc::c_int;
        }
    } else {
        *out = default_value;
    }
    return 1 as libc::c_int;
}
