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
    fn ASN1_STRING_type_new(type_0: libc::c_int) -> *mut ASN1_STRING;
    fn ASN1_STRING_free(str: *mut ASN1_STRING);
    fn ASN1_STRING_set(
        str: *mut ASN1_STRING,
        data: *const libc::c_void,
        len: ossl_ssize_t,
    ) -> libc::c_int;
    fn ASN1_STRING_set0(
        str: *mut ASN1_STRING,
        data: *mut libc::c_void,
        len: libc::c_int,
    );
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBB_zero(cbb: *mut CBB);
    fn CBB_init(cbb: *mut CBB, initial_capacity: size_t) -> libc::c_int;
    fn CBB_cleanup(cbb: *mut CBB);
    fn CBB_finish(
        cbb: *mut CBB,
        out_data: *mut *mut uint8_t,
        out_len: *mut size_t,
    ) -> libc::c_int;
    fn CBB_add_u8(cbb: *mut CBB, value: uint8_t) -> libc::c_int;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_isalnum(c: libc::c_int) -> libc::c_int;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn ERR_add_error_dataf(format: *const libc::c_char, _: ...);
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn cbs_get_utf8(cbs: *mut CBS, out: *mut uint32_t) -> libc::c_int;
    fn cbs_get_latin1(cbs: *mut CBS, out: *mut uint32_t) -> libc::c_int;
    fn cbs_get_ucs2_be(cbs: *mut CBS, out: *mut uint32_t) -> libc::c_int;
    fn cbs_get_utf32_be(cbs: *mut CBS, out: *mut uint32_t) -> libc::c_int;
    fn cbb_get_utf8_len(u: uint32_t) -> size_t;
    fn cbb_add_utf8(cbb: *mut CBB, u: uint32_t) -> libc::c_int;
    fn cbb_add_latin1(cbb: *mut CBB, u: uint32_t) -> libc::c_int;
    fn cbb_add_ucs2_be(cbb: *mut CBB, u: uint32_t) -> libc::c_int;
    fn cbb_add_utf32_be(cbb: *mut CBB, u: uint32_t) -> libc::c_int;
}
pub type ptrdiff_t = libc::c_long;
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type ossl_ssize_t = ptrdiff_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_string_st {
    pub length: libc::c_int,
    pub type_0: libc::c_int,
    pub data: *mut libc::c_uchar,
    pub flags: libc::c_long,
}
pub type ASN1_STRING = asn1_string_st;
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
pub unsafe extern "C" fn ASN1_mbstring_copy(
    mut out: *mut *mut ASN1_STRING,
    mut in_0: *const libc::c_uchar,
    mut len: ossl_ssize_t,
    mut inform: libc::c_int,
    mut mask: libc::c_ulong,
) -> libc::c_int {
    return ASN1_mbstring_ncopy(
        out,
        in_0,
        len,
        inform,
        mask,
        0 as libc::c_int as ossl_ssize_t,
        0 as libc::c_int as ossl_ssize_t,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_mbstring_ncopy(
    mut out: *mut *mut ASN1_STRING,
    mut in_0: *const libc::c_uchar,
    mut len: ossl_ssize_t,
    mut inform: libc::c_int,
    mut mask: libc::c_ulong,
    mut minsize: ossl_ssize_t,
    mut maxsize: ossl_ssize_t,
) -> libc::c_int {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut data_len: size_t = 0;
    let mut current_block: u64;
    if len == -(1 as libc::c_int) as ossl_ssize_t {
        len = strlen(in_0 as *const libc::c_char) as ossl_ssize_t;
    }
    if mask == 0 {
        mask = (0x2 as libc::c_int | 0x4 as libc::c_int | 0x800 as libc::c_int
            | 0x2000 as libc::c_int) as libc::c_ulong;
    }
    let mut decode_func: Option::<
        unsafe extern "C" fn(*mut CBS, *mut uint32_t) -> libc::c_int,
    > = None;
    let mut error: libc::c_int = 0;
    match inform {
        4098 => {
            decode_func = Some(
                cbs_get_ucs2_be
                    as unsafe extern "C" fn(*mut CBS, *mut uint32_t) -> libc::c_int,
            );
            error = 142 as libc::c_int;
        }
        4100 => {
            decode_func = Some(
                cbs_get_utf32_be
                    as unsafe extern "C" fn(*mut CBS, *mut uint32_t) -> libc::c_int,
            );
            error = 149 as libc::c_int;
        }
        4096 => {
            decode_func = Some(
                cbs_get_utf8
                    as unsafe extern "C" fn(*mut CBS, *mut uint32_t) -> libc::c_int,
            );
            error = 150 as libc::c_int;
        }
        4097 => {
            decode_func = Some(
                cbs_get_latin1
                    as unsafe extern "C" fn(*mut CBS, *mut uint32_t) -> libc::c_int,
            );
            error = 4 as libc::c_int | 64 as libc::c_int;
        }
        _ => {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                182 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_mbstr.c\0" as *const u8
                    as *const libc::c_char,
                120 as libc::c_int as libc::c_uint,
            );
            return -(1 as libc::c_int);
        }
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, in_0, len as size_t);
    let mut utf8_len: size_t = 0 as libc::c_int as size_t;
    let mut nchar: size_t = 0 as libc::c_int as size_t;
    while CBS_len(&mut cbs) != 0 as libc::c_int as size_t {
        let mut c: uint32_t = 0;
        if decode_func.expect("non-null function pointer")(&mut cbs, &mut c) == 0 {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                error,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_mbstr.c\0" as *const u8
                    as *const libc::c_char,
                131 as libc::c_int as libc::c_uint,
            );
            return -(1 as libc::c_int);
        }
        if nchar == 0 as libc::c_int as size_t
            && (inform == 0x1000 as libc::c_int | 2 as libc::c_int
                || inform == 0x1000 as libc::c_int | 4 as libc::c_int)
            && c == 0xfeff as libc::c_int as uint32_t
        {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                126 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_mbstr.c\0" as *const u8
                    as *const libc::c_char,
                142 as libc::c_int as libc::c_uint,
            );
            return -(1 as libc::c_int);
        }
        if mask & 0x2 as libc::c_int as libc::c_ulong != 0 && asn1_is_printable(c) == 0 {
            mask &= !(0x2 as libc::c_int) as libc::c_ulong;
        }
        if mask & 0x10 as libc::c_int as libc::c_ulong != 0
            && c > 127 as libc::c_int as uint32_t
        {
            mask &= !(0x10 as libc::c_int) as libc::c_ulong;
        }
        if mask & 0x4 as libc::c_int as libc::c_ulong != 0
            && c > 0xff as libc::c_int as uint32_t
        {
            mask &= !(0x4 as libc::c_int) as libc::c_ulong;
        }
        if mask & 0x800 as libc::c_int as libc::c_ulong != 0
            && c > 0xffff as libc::c_int as uint32_t
        {
            mask &= !(0x800 as libc::c_int) as libc::c_ulong;
        }
        if mask == 0 {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                126 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_mbstr.c\0" as *const u8
                    as *const libc::c_char,
                160 as libc::c_int as libc::c_uint,
            );
            return -(1 as libc::c_int);
        }
        nchar = nchar.wrapping_add(1);
        nchar;
        utf8_len = utf8_len.wrapping_add(cbb_get_utf8_len(c));
        if maxsize > 0 as libc::c_int as ossl_ssize_t && nchar > maxsize as size_t {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                173 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_mbstr.c\0" as *const u8
                    as *const libc::c_char,
                167 as libc::c_int as libc::c_uint,
            );
            ERR_add_error_dataf(
                b"maxsize=%zu\0" as *const u8 as *const libc::c_char,
                maxsize as size_t,
            );
            return -(1 as libc::c_int);
        }
    }
    if minsize > 0 as libc::c_int as ossl_ssize_t && nchar < minsize as size_t {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            174 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_mbstr.c\0" as *const u8
                as *const libc::c_char,
            178 as libc::c_int as libc::c_uint,
        );
        ERR_add_error_dataf(
            b"minsize=%zu\0" as *const u8 as *const libc::c_char,
            minsize as size_t,
        );
        return -(1 as libc::c_int);
    }
    let mut str_type: libc::c_int = 0;
    let mut encode_func: Option::<
        unsafe extern "C" fn(*mut CBB, uint32_t) -> libc::c_int,
    > = Some(cbb_add_latin1 as unsafe extern "C" fn(*mut CBB, uint32_t) -> libc::c_int);
    let mut size_estimate: size_t = nchar;
    let mut outform: libc::c_int = 0x1000 as libc::c_int | 1 as libc::c_int;
    if mask & 0x2 as libc::c_int as libc::c_ulong != 0 {
        str_type = 19 as libc::c_int;
    } else if mask & 0x10 as libc::c_int as libc::c_ulong != 0 {
        str_type = 22 as libc::c_int;
    } else if mask & 0x4 as libc::c_int as libc::c_ulong != 0 {
        str_type = 20 as libc::c_int;
    } else if mask & 0x800 as libc::c_int as libc::c_ulong != 0 {
        str_type = 30 as libc::c_int;
        outform = 0x1000 as libc::c_int | 2 as libc::c_int;
        encode_func = Some(
            cbb_add_ucs2_be as unsafe extern "C" fn(*mut CBB, uint32_t) -> libc::c_int,
        );
        size_estimate = 2 as libc::c_int as size_t * nchar;
    } else if mask & 0x100 as libc::c_int as libc::c_ulong != 0 {
        str_type = 28 as libc::c_int;
        encode_func = Some(
            cbb_add_utf32_be as unsafe extern "C" fn(*mut CBB, uint32_t) -> libc::c_int,
        );
        size_estimate = 4 as libc::c_int as size_t * nchar;
        outform = 0x1000 as libc::c_int | 4 as libc::c_int;
    } else if mask & 0x2000 as libc::c_int as libc::c_ulong != 0 {
        str_type = 12 as libc::c_int;
        outform = 0x1000 as libc::c_int;
        encode_func = Some(
            cbb_add_utf8 as unsafe extern "C" fn(*mut CBB, uint32_t) -> libc::c_int,
        );
        size_estimate = utf8_len;
    } else {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            126 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_mbstr.c\0" as *const u8
                as *const libc::c_char,
            214 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    if out.is_null() {
        return str_type;
    }
    let mut free_dest: libc::c_int = 0 as libc::c_int;
    let mut dest: *mut ASN1_STRING = 0 as *mut ASN1_STRING;
    if !(*out).is_null() {
        dest = *out;
    } else {
        free_dest = 1 as libc::c_int;
        dest = ASN1_STRING_type_new(str_type);
        if dest.is_null() {
            return -(1 as libc::c_int);
        }
    }
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
    if inform == outform {
        if !(ASN1_STRING_set(dest, in_0 as *const libc::c_void, len) == 0) {
            (*dest).type_0 = str_type;
            *out = dest;
            return str_type;
        }
    } else if !(CBB_init(
        &mut cbb,
        size_estimate.wrapping_add(1 as libc::c_int as size_t),
    ) == 0)
    {
        CBS_init(&mut cbs, in_0, len as size_t);
        loop {
            if !(CBS_len(&mut cbs) != 0 as libc::c_int as size_t) {
                current_block = 11869735117417356968;
                break;
            }
            let mut c_0: uint32_t = 0;
            if !(decode_func.expect("non-null function pointer")(&mut cbs, &mut c_0) == 0
                || encode_func.expect("non-null function pointer")(&mut cbb, c_0) == 0)
            {
                continue;
            }
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                4 as libc::c_int | 64 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_mbstr.c\0" as *const u8
                    as *const libc::c_char,
                252 as libc::c_int as libc::c_uint,
            );
            current_block = 11306593555525889978;
            break;
        }
        match current_block {
            11306593555525889978 => {}
            _ => {
                data = 0 as *mut uint8_t;
                data_len = 0;
                if CBB_add_u8(&mut cbb, 0 as libc::c_int as uint8_t) == 0
                    || CBB_finish(&mut cbb, &mut data, &mut data_len) == 0
                    || data_len < 1 as libc::c_int as size_t
                    || data_len > 2147483647 as libc::c_int as size_t
                {
                    ERR_put_error(
                        12 as libc::c_int,
                        0 as libc::c_int,
                        4 as libc::c_int | 64 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_mbstr.c\0"
                            as *const u8 as *const libc::c_char,
                        262 as libc::c_int as libc::c_uint,
                    );
                    OPENSSL_free(data as *mut libc::c_void);
                } else {
                    (*dest).type_0 = str_type;
                    ASN1_STRING_set0(
                        dest,
                        data as *mut libc::c_void,
                        data_len as libc::c_int - 1 as libc::c_int,
                    );
                    *out = dest;
                    return str_type;
                }
            }
        }
    }
    if free_dest != 0 {
        ASN1_STRING_free(dest);
    }
    CBB_cleanup(&mut cbb);
    return -(1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn asn1_is_printable(mut value: uint32_t) -> libc::c_int {
    if value > 0x7f as libc::c_int as uint32_t {
        return 0 as libc::c_int;
    }
    return (OPENSSL_isalnum(value as libc::c_int) != 0 || value == ' ' as i32 as uint32_t
        || value == '\'' as i32 as uint32_t || value == '(' as i32 as uint32_t
        || value == ')' as i32 as uint32_t || value == '+' as i32 as uint32_t
        || value == ',' as i32 as uint32_t || value == '-' as i32 as uint32_t
        || value == '.' as i32 as uint32_t || value == '/' as i32 as uint32_t
        || value == ':' as i32 as uint32_t || value == '=' as i32 as uint32_t
        || value == '?' as i32 as uint32_t) as libc::c_int;
}
