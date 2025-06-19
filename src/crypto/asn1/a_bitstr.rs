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
    fn ASN1_STRING_set(
        str: *mut ASN1_STRING,
        data: *const libc::c_void,
        len: ossl_ssize_t,
    ) -> libc::c_int;
    fn ASN1_BIT_STRING_new() -> *mut ASN1_BIT_STRING;
    fn ASN1_BIT_STRING_free(str: *mut ASN1_BIT_STRING);
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_realloc(ptr: *mut libc::c_void, new_size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_memdup(data: *const libc::c_void, size: size_t) -> *mut libc::c_void;
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
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
}
pub type ptrdiff_t = libc::c_long;
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type uint8_t = __uint8_t;
pub type ossl_ssize_t = ptrdiff_t;
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
#[inline]
unsafe extern "C" fn OPENSSL_memset(
    mut dst: *mut libc::c_void,
    mut c: libc::c_int,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return dst;
    }
    return memset(dst, c, n);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_BIT_STRING_set(
    mut x: *mut ASN1_BIT_STRING,
    mut d: *const libc::c_uchar,
    mut len: ossl_ssize_t,
) -> libc::c_int {
    return ASN1_STRING_set(x, d as *const libc::c_void, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asn1_bit_string_length(
    mut str: *const ASN1_BIT_STRING,
    mut out_padding_bits: *mut uint8_t,
) -> libc::c_int {
    let mut len: libc::c_int = (*str).length;
    if (*str).flags & 0x8 as libc::c_int as libc::c_long != 0 {
        *out_padding_bits = (if len == 0 as libc::c_int {
            0 as libc::c_int as libc::c_long
        } else {
            (*str).flags & 0x7 as libc::c_int as libc::c_long
        }) as uint8_t;
        return len;
    }
    while len > 0 as libc::c_int
        && *((*str).data).offset((len - 1 as libc::c_int) as isize) as libc::c_int
            == 0 as libc::c_int
    {
        len -= 1;
        len;
    }
    let mut padding_bits: uint8_t = 0 as libc::c_int as uint8_t;
    if len > 0 as libc::c_int {
        let mut last: uint8_t = *((*str).data).offset((len - 1 as libc::c_int) as isize);
        if last as libc::c_int != 0 as libc::c_int {} else {
            __assert_fail(
                b"last != 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_bitstr.c\0"
                    as *const u8 as *const libc::c_char,
                91 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 63],
                    &[libc::c_char; 63],
                >(b"int asn1_bit_string_length(const ASN1_BIT_STRING *, uint8_t *)\0"))
                    .as_ptr(),
            );
        }
        'c_7246: {
            if last as libc::c_int != 0 as libc::c_int {} else {
                __assert_fail(
                    b"last != 0\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_bitstr.c\0"
                        as *const u8 as *const libc::c_char,
                    91 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 63],
                        &[libc::c_char; 63],
                    >(
                        b"int asn1_bit_string_length(const ASN1_BIT_STRING *, uint8_t *)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        while (padding_bits as libc::c_int) < 7 as libc::c_int {
            if last as libc::c_int & (1 as libc::c_int) << padding_bits as libc::c_int
                != 0
            {
                break;
            }
            padding_bits = padding_bits.wrapping_add(1);
            padding_bits;
        }
    }
    *out_padding_bits = padding_bits;
    return len;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_BIT_STRING_num_bytes(
    mut str: *const ASN1_BIT_STRING,
    mut out: *mut size_t,
) -> libc::c_int {
    let mut padding_bits: uint8_t = 0;
    let mut len: libc::c_int = asn1_bit_string_length(str, &mut padding_bits);
    if padding_bits as libc::c_int != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    *out = len as size_t;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2c_ASN1_BIT_STRING(
    mut a: *const ASN1_BIT_STRING,
    mut pp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    if a.is_null() {
        return 0 as libc::c_int;
    }
    let mut bits: uint8_t = 0;
    let mut len: libc::c_int = asn1_bit_string_length(a, &mut bits);
    if len > 2147483647 as libc::c_int - 1 as libc::c_int {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_bitstr.c\0" as *const u8
                as *const libc::c_char,
            120 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 1 as libc::c_int + len;
    if pp.is_null() {
        return ret;
    }
    let mut p: *mut uint8_t = *pp;
    let fresh0 = p;
    p = p.offset(1);
    *fresh0 = bits;
    OPENSSL_memcpy(
        p as *mut libc::c_void,
        (*a).data as *const libc::c_void,
        len as size_t,
    );
    if len > 0 as libc::c_int {
        let ref mut fresh1 = *p.offset((len - 1 as libc::c_int) as isize);
        *fresh1 = (*fresh1 as libc::c_int & (0xff as libc::c_int) << bits as libc::c_int)
            as uint8_t;
    }
    p = p.offset(len as isize);
    *pp = p;
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c2i_ASN1_BIT_STRING(
    mut a: *mut *mut ASN1_BIT_STRING,
    mut pp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_BIT_STRING {
    let mut padding_mask: uint8_t = 0;
    let mut current_block: u64;
    let mut ret: *mut ASN1_BIT_STRING = 0 as *mut ASN1_BIT_STRING;
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut s: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut padding: libc::c_int = 0;
    if len < 1 as libc::c_int as libc::c_long {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            174 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_bitstr.c\0" as *const u8
                as *const libc::c_char,
            147 as libc::c_int as libc::c_uint,
        );
    } else if len > 2147483647 as libc::c_int as libc::c_long {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            173 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_bitstr.c\0" as *const u8
                as *const libc::c_char,
            152 as libc::c_int as libc::c_uint,
        );
    } else {
        if a.is_null() || (*a).is_null() {
            ret = ASN1_BIT_STRING_new();
            if ret.is_null() {
                return 0 as *mut ASN1_BIT_STRING;
            }
        } else {
            ret = *a;
        }
        p = *pp;
        let fresh2 = p;
        p = p.offset(1);
        padding = *fresh2 as libc::c_int;
        len -= 1;
        len;
        if padding > 7 as libc::c_int {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                141 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_bitstr.c\0"
                    as *const u8 as *const libc::c_char,
                168 as libc::c_int as libc::c_uint,
            );
        } else {
            padding_mask = (((1 as libc::c_int) << padding) - 1 as libc::c_int)
                as uint8_t;
            if padding != 0 as libc::c_int
                && (len < 1 as libc::c_int as libc::c_long
                    || *p.offset((len - 1 as libc::c_int as libc::c_long) as isize)
                        as libc::c_int & padding_mask as libc::c_int != 0 as libc::c_int)
            {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    194 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_bitstr.c\0"
                        as *const u8 as *const libc::c_char,
                    175 as libc::c_int as libc::c_uint,
                );
            } else {
                (*ret).flags
                    &= !(0x8 as libc::c_int | 0x7 as libc::c_int) as libc::c_long;
                (*ret).flags |= (0x8 as libc::c_int | padding) as libc::c_long;
                if len > 0 as libc::c_int as libc::c_long {
                    s = OPENSSL_memdup(p as *const libc::c_void, len as size_t)
                        as *mut libc::c_uchar;
                    if s.is_null() {
                        current_block = 10612692660337572761;
                    } else {
                        p = p.offset(len as isize);
                        current_block = 10652014663920648156;
                    }
                } else {
                    s = 0 as *mut libc::c_uchar;
                    current_block = 10652014663920648156;
                }
                match current_block {
                    10612692660337572761 => {}
                    _ => {
                        (*ret).length = len as libc::c_int;
                        OPENSSL_free((*ret).data as *mut libc::c_void);
                        (*ret).data = s;
                        (*ret).type_0 = 3 as libc::c_int;
                        if !a.is_null() {
                            *a = ret;
                        }
                        *pp = p;
                        return ret;
                    }
                }
            }
        }
    }
    if !ret.is_null() && (a.is_null() || *a != ret) {
        ASN1_BIT_STRING_free(ret);
    }
    return 0 as *mut ASN1_BIT_STRING;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_BIT_STRING_set_bit(
    mut a: *mut ASN1_BIT_STRING,
    mut n: libc::c_int,
    mut value: libc::c_int,
) -> libc::c_int {
    let mut w: libc::c_int = 0;
    let mut v: libc::c_int = 0;
    let mut iv: libc::c_int = 0;
    let mut c: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    w = n / 8 as libc::c_int;
    v = (1 as libc::c_int) << 7 as libc::c_int - (n & 0x7 as libc::c_int);
    iv = !v;
    if value == 0 {
        v = 0 as libc::c_int;
    }
    if a.is_null() {
        return 0 as libc::c_int;
    }
    (*a).flags &= !(0x8 as libc::c_int | 0x7 as libc::c_int) as libc::c_long;
    if (*a).length < w + 1 as libc::c_int || ((*a).data).is_null() {
        if value == 0 {
            return 1 as libc::c_int;
        }
        if ((*a).data).is_null() {
            c = OPENSSL_malloc((w + 1 as libc::c_int) as size_t) as *mut libc::c_uchar;
        } else {
            c = OPENSSL_realloc(
                (*a).data as *mut libc::c_void,
                (w + 1 as libc::c_int) as size_t,
            ) as *mut libc::c_uchar;
        }
        if c.is_null() {
            return 0 as libc::c_int;
        }
        if w + 1 as libc::c_int - (*a).length > 0 as libc::c_int {
            OPENSSL_memset(
                c.offset((*a).length as isize) as *mut libc::c_void,
                0 as libc::c_int,
                (w + 1 as libc::c_int - (*a).length) as size_t,
            );
        }
        (*a).data = c;
        (*a).length = w + 1 as libc::c_int;
    }
    *((*a).data)
        .offset(
            w as isize,
        ) = (*((*a).data).offset(w as isize) as libc::c_int & iv | v) as libc::c_uchar;
    while (*a).length > 0 as libc::c_int
        && *((*a).data).offset(((*a).length - 1 as libc::c_int) as isize) as libc::c_int
            == 0 as libc::c_int
    {
        (*a).length -= 1;
        (*a).length;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_BIT_STRING_get_bit(
    mut a: *const ASN1_BIT_STRING,
    mut n: libc::c_int,
) -> libc::c_int {
    let mut w: libc::c_int = 0;
    let mut v: libc::c_int = 0;
    w = n / 8 as libc::c_int;
    v = (1 as libc::c_int) << 7 as libc::c_int - (n & 0x7 as libc::c_int);
    if a.is_null() || (*a).length < w + 1 as libc::c_int || ((*a).data).is_null() {
        return 0 as libc::c_int;
    }
    return (*((*a).data).offset(w as isize) as libc::c_int & v != 0 as libc::c_int)
        as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_BIT_STRING_check(
    mut a: *const ASN1_BIT_STRING,
    mut flags: *const libc::c_uchar,
    mut flags_len: libc::c_int,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut ok: libc::c_int = 0;
    if a.is_null() || ((*a).data).is_null() {
        return 1 as libc::c_int;
    }
    ok = 1 as libc::c_int;
    i = 0 as libc::c_int;
    while i < (*a).length && ok != 0 {
        let mut mask: libc::c_uchar = (if i < flags_len {
            !(*flags.offset(i as isize) as libc::c_int)
        } else {
            0xff as libc::c_int
        }) as libc::c_uchar;
        ok = (*((*a).data).offset(i as isize) as libc::c_int & mask as libc::c_int
            == 0 as libc::c_int) as libc::c_int;
        i += 1;
        i;
    }
    return ok;
}
