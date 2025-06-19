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
    fn asn1_bit_string_length(
        str: *const ASN1_BIT_STRING,
        out_padding_bits: *mut uint8_t,
    ) -> libc::c_int;
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_skip(cbs: *mut CBS, len: size_t) -> libc::c_int;
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_realloc(ptr: *mut libc::c_void, new_size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn cbs_get_any_asn1_element(
        cbs: *mut CBS,
        out: *mut CBS,
        out_tag: *mut CBS_ASN1_TAG,
        out_header_len: *mut size_t,
        out_ber_found: *mut libc::c_int,
        out_indefinite: *mut libc::c_int,
        ber_ok: libc::c_int,
        universal_tag_ok: libc::c_int,
    ) -> libc::c_int;
}
pub type ptrdiff_t = libc::c_long;
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type ossl_ssize_t = ptrdiff_t;
pub type CBS_ASN1_TAG = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_string_st {
    pub length: libc::c_int,
    pub type_0: libc::c_int,
    pub data: *mut libc::c_uchar,
    pub flags: libc::c_long,
}
pub type ASN1_BIT_STRING = asn1_string_st;
pub type ASN1_STRING = asn1_string_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cbs_st {
    pub data: *const uint8_t,
    pub len: size_t,
}
pub type CBS = cbs_st;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_316_error_is_len_will_not_overflow_int {
    #[bitfield(
        name = "static_assertion_at_line_316_error_is_len_will_not_overflow_int",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_316_error_is_len_will_not_overflow_int: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[inline]
unsafe extern "C" fn OPENSSL_memcmp(
    mut s1: *const libc::c_void,
    mut s2: *const libc::c_void,
    mut n: size_t,
) -> libc::c_int {
    if n == 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    return memcmp(s1, s2, n);
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
pub unsafe extern "C" fn ASN1_get_object(
    mut inp: *mut *const libc::c_uchar,
    mut out_len: *mut libc::c_long,
    mut out_tag: *mut libc::c_int,
    mut out_class: *mut libc::c_int,
    mut in_len: libc::c_long,
) -> libc::c_int {
    if in_len < 0 as libc::c_int as libc::c_long {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            123 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/asn1_lib.c\0" as *const u8
                as *const libc::c_char,
            133 as libc::c_int as libc::c_uint,
        );
        return 0x80 as libc::c_int;
    }
    let mut tag: CBS_ASN1_TAG = 0;
    let mut header_len: size_t = 0;
    let mut indefinite: libc::c_int = 0;
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut body: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, *inp, in_len as size_t);
    let mut ber_found_temp: libc::c_int = 0;
    if cbs_get_any_asn1_element(
        &mut cbs,
        &mut body,
        &mut tag,
        &mut header_len,
        &mut ber_found_temp,
        &mut indefinite,
        1 as libc::c_int,
        1 as libc::c_int,
    ) == 0 || CBS_skip(&mut body, header_len) == 0
        || CBS_len(&mut body) > (2147483647 as libc::c_int / 2 as libc::c_int) as size_t
    {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            123 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/asn1_lib.c\0" as *const u8
                as *const libc::c_char,
            157 as libc::c_int as libc::c_uint,
        );
        return 0x80 as libc::c_int;
    }
    let mut tag_class: libc::c_int = ((tag & (0xc0 as libc::c_uint) << 24 as libc::c_int)
        >> 24 as libc::c_int) as libc::c_int;
    let mut constructed: libc::c_int = ((if indefinite != 0 {
        1 as libc::c_int
    } else {
        0 as libc::c_int
    }) as libc::c_uint
        | (tag & (0x20 as libc::c_uint) << 24 as libc::c_int) >> 24 as libc::c_int)
        as libc::c_int;
    let mut tag_number: libc::c_int = (tag
        & ((1 as libc::c_uint) << 5 as libc::c_int + 24 as libc::c_int)
            .wrapping_sub(1 as libc::c_int as libc::c_uint)) as libc::c_int;
    if tag_class == 0 as libc::c_int && tag_number > 0xff as libc::c_int {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            123 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/asn1_lib.c\0" as *const u8
                as *const libc::c_char,
            170 as libc::c_int as libc::c_uint,
        );
        return 0x80 as libc::c_int;
    }
    *inp = CBS_data(&mut body);
    *out_len = CBS_len(&mut body) as libc::c_long;
    *out_tag = tag_number;
    *out_class = tag_class;
    return constructed;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_put_object(
    mut pp: *mut *mut libc::c_uchar,
    mut constructed: libc::c_int,
    mut length: libc::c_int,
    mut tag: libc::c_int,
    mut xclass: libc::c_int,
) {
    let mut p: *mut libc::c_uchar = *pp;
    let mut i: libc::c_int = 0;
    let mut ttag: libc::c_int = 0;
    i = if constructed != 0 { 0x20 as libc::c_int } else { 0 as libc::c_int };
    i |= xclass & 0xc0 as libc::c_int;
    if tag < 31 as libc::c_int {
        let fresh0 = p;
        p = p.offset(1);
        *fresh0 = (i | tag & 0x1f as libc::c_int) as libc::c_uchar;
    } else {
        let fresh1 = p;
        p = p.offset(1);
        *fresh1 = (i | 0x1f as libc::c_int) as libc::c_uchar;
        i = 0 as libc::c_int;
        ttag = tag;
        while ttag > 0 as libc::c_int {
            ttag >>= 7 as libc::c_int;
            i += 1;
            i;
        }
        ttag = i;
        loop {
            let fresh2 = i;
            i = i - 1;
            if !(fresh2 > 0 as libc::c_int) {
                break;
            }
            *p.offset(i as isize) = (tag & 0x7f as libc::c_int) as libc::c_uchar;
            if i != ttag - 1 as libc::c_int {
                let ref mut fresh3 = *p.offset(i as isize);
                *fresh3 = (*fresh3 as libc::c_int | 0x80 as libc::c_int)
                    as libc::c_uchar;
            }
            tag >>= 7 as libc::c_int;
        }
        p = p.offset(ttag as isize);
    }
    if constructed == 2 as libc::c_int {
        let fresh4 = p;
        p = p.offset(1);
        *fresh4 = 0x80 as libc::c_int as libc::c_uchar;
    } else {
        asn1_put_length(&mut p, length);
    }
    *pp = p;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_put_eoc(mut pp: *mut *mut libc::c_uchar) -> libc::c_int {
    let mut p: *mut libc::c_uchar = *pp;
    let fresh5 = p;
    p = p.offset(1);
    *fresh5 = 0 as libc::c_int as libc::c_uchar;
    let fresh6 = p;
    p = p.offset(1);
    *fresh6 = 0 as libc::c_int as libc::c_uchar;
    *pp = p;
    return 2 as libc::c_int;
}
unsafe extern "C" fn asn1_put_length(
    mut pp: *mut *mut libc::c_uchar,
    mut length: libc::c_int,
) {
    let mut p: *mut libc::c_uchar = *pp;
    let mut i: libc::c_int = 0;
    let mut l: libc::c_int = 0;
    if length <= 127 as libc::c_int {
        let fresh7 = p;
        p = p.offset(1);
        *fresh7 = length as libc::c_uchar;
    } else {
        l = length;
        i = 0 as libc::c_int;
        while l > 0 as libc::c_int {
            l >>= 8 as libc::c_int;
            i += 1;
            i;
        }
        let fresh8 = p;
        p = p.offset(1);
        *fresh8 = (i | 0x80 as libc::c_int) as libc::c_uchar;
        l = i;
        loop {
            let fresh9 = i;
            i = i - 1;
            if !(fresh9 > 0 as libc::c_int) {
                break;
            }
            *p.offset(i as isize) = (length & 0xff as libc::c_int) as libc::c_uchar;
            length >>= 8 as libc::c_int;
        }
        p = p.offset(l as isize);
    }
    *pp = p;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_object_size(
    mut constructed: libc::c_int,
    mut length: libc::c_int,
    mut tag: libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = 1 as libc::c_int;
    if length < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    if tag >= 31 as libc::c_int {
        while tag > 0 as libc::c_int {
            tag >>= 7 as libc::c_int;
            ret += 1;
            ret;
        }
    }
    if constructed == 2 as libc::c_int {
        ret += 3 as libc::c_int;
    } else {
        ret += 1;
        ret;
        if length > 127 as libc::c_int {
            let mut tmplen: libc::c_int = length;
            while tmplen > 0 as libc::c_int {
                tmplen >>= 8 as libc::c_int;
                ret += 1;
                ret;
            }
        }
    }
    if ret >= 2147483647 as libc::c_int - length {
        return -(1 as libc::c_int);
    }
    return ret + length;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_STRING_copy(
    mut dst: *mut ASN1_STRING,
    mut str: *const ASN1_STRING,
) -> libc::c_int {
    if str.is_null() {
        return 0 as libc::c_int;
    }
    if ASN1_STRING_set(
        dst,
        (*str).data as *const libc::c_void,
        (*str).length as ossl_ssize_t,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    (*dst).type_0 = (*str).type_0;
    (*dst).flags = (*str).flags;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_STRING_dup(
    mut str: *const ASN1_STRING,
) -> *mut ASN1_STRING {
    let mut ret: *mut ASN1_STRING = 0 as *mut ASN1_STRING;
    if str.is_null() {
        return 0 as *mut ASN1_STRING;
    }
    ret = ASN1_STRING_new();
    if ret.is_null() {
        return 0 as *mut ASN1_STRING;
    }
    if ASN1_STRING_copy(ret, str) == 0 {
        ASN1_STRING_free(ret);
        return 0 as *mut ASN1_STRING;
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_STRING_set(
    mut str: *mut ASN1_STRING,
    mut _data: *const libc::c_void,
    mut len_s: ossl_ssize_t,
) -> libc::c_int {
    let mut data: *const libc::c_char = _data as *const libc::c_char;
    let mut len: size_t = 0;
    if len_s < 0 as libc::c_int as ossl_ssize_t {
        if data.is_null() {
            return 0 as libc::c_int;
        }
        len = strlen(data);
    } else {
        len = len_s as size_t;
    }
    if len > (64 as libc::c_int * 1024 as libc::c_int * 1024 as libc::c_int) as size_t {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/asn1_lib.c\0" as *const u8
                as *const libc::c_char,
            318 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*str).length <= len as libc::c_int || ((*str).data).is_null() {
        let mut c: *mut libc::c_uchar = (*str).data;
        if c.is_null() {
            (*str)
                .data = OPENSSL_malloc(len.wrapping_add(1 as libc::c_int as size_t))
                as *mut libc::c_uchar;
        } else {
            (*str)
                .data = OPENSSL_realloc(
                c as *mut libc::c_void,
                len.wrapping_add(1 as libc::c_int as size_t),
            ) as *mut libc::c_uchar;
        }
        if ((*str).data).is_null() {
            (*str).data = c;
            return 0 as libc::c_int;
        }
    }
    (*str).length = len as libc::c_int;
    if !data.is_null() {
        OPENSSL_memcpy(
            (*str).data as *mut libc::c_void,
            data as *const libc::c_void,
            len,
        );
        *((*str).data).offset(len as isize) = '\0' as i32 as libc::c_uchar;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_STRING_set0(
    mut str: *mut ASN1_STRING,
    mut data: *mut libc::c_void,
    mut len: libc::c_int,
) {
    OPENSSL_free((*str).data as *mut libc::c_void);
    (*str).data = data as *mut libc::c_uchar;
    (*str).length = len;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_STRING_new() -> *mut ASN1_STRING {
    return ASN1_STRING_type_new(4 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_STRING_type_new(
    mut type_0: libc::c_int,
) -> *mut ASN1_STRING {
    let mut ret: *mut ASN1_STRING = 0 as *mut ASN1_STRING;
    ret = OPENSSL_zalloc(::core::mem::size_of::<ASN1_STRING>() as libc::c_ulong)
        as *mut ASN1_STRING;
    if ret.is_null() {
        return 0 as *mut ASN1_STRING;
    }
    (*ret).type_0 = type_0;
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_STRING_free(mut str: *mut ASN1_STRING) {
    if str.is_null() {
        return;
    }
    OPENSSL_free((*str).data as *mut libc::c_void);
    OPENSSL_free(str as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_STRING_clear_free(mut str: *mut ASN1_STRING) {
    ASN1_STRING_free(str);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_STRING_cmp(
    mut a: *const ASN1_STRING,
    mut b: *const ASN1_STRING,
) -> libc::c_int {
    let mut a_length: libc::c_int = (*a).length;
    let mut b_length: libc::c_int = (*b).length;
    let mut a_padding: uint8_t = 0 as libc::c_int as uint8_t;
    let mut b_padding: uint8_t = 0 as libc::c_int as uint8_t;
    if (*a).type_0 == 3 as libc::c_int {
        a_length = asn1_bit_string_length(a, &mut a_padding);
    }
    if (*b).type_0 == 3 as libc::c_int {
        b_length = asn1_bit_string_length(b, &mut b_padding);
    }
    if a_length < b_length {
        return -(1 as libc::c_int);
    }
    if a_length > b_length {
        return 1 as libc::c_int;
    }
    if a_padding as libc::c_int > b_padding as libc::c_int {
        return -(1 as libc::c_int);
    }
    if (a_padding as libc::c_int) < b_padding as libc::c_int {
        return 1 as libc::c_int;
    }
    let mut ret: libc::c_int = OPENSSL_memcmp(
        (*a).data as *const libc::c_void,
        (*b).data as *const libc::c_void,
        a_length as size_t,
    );
    if ret != 0 as libc::c_int {
        return ret;
    }
    if (*a).type_0 < (*b).type_0 {
        return -(1 as libc::c_int);
    }
    if (*a).type_0 > (*b).type_0 {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_STRING_length(mut str: *const ASN1_STRING) -> libc::c_int {
    return (*str).length;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_STRING_type(mut str: *const ASN1_STRING) -> libc::c_int {
    return (*str).type_0;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_STRING_data(
    mut str: *mut ASN1_STRING,
) -> *mut libc::c_uchar {
    return (*str).data;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_STRING_get0_data(
    mut str: *const ASN1_STRING,
) -> *const libc::c_uchar {
    return (*str).data;
}
