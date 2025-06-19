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
    fn ASN1_STRING_type_new(type_0: libc::c_int) -> *mut ASN1_STRING;
    fn ASN1_STRING_free(str: *mut ASN1_STRING);
    fn ASN1_STRING_dup(str: *const ASN1_STRING) -> *mut ASN1_STRING;
    fn ASN1_STRING_cmp(a: *const ASN1_STRING, b: *const ASN1_STRING) -> libc::c_int;
    fn ASN1_STRING_set(
        str: *mut ASN1_STRING,
        data: *const libc::c_void,
        len: ossl_ssize_t,
    ) -> libc::c_int;
    fn ASN1_INTEGER_new() -> *mut ASN1_INTEGER;
    fn ASN1_INTEGER_free(str: *mut ASN1_INTEGER);
    fn BN_num_bytes(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_set_negative(bn: *mut BIGNUM, sign: libc::c_int);
    fn BN_is_negative(bn: *const BIGNUM) -> libc::c_int;
    fn BN_bin2bn(in_0: *const uint8_t, len: size_t, ret: *mut BIGNUM) -> *mut BIGNUM;
    fn BN_bn2bin_padded(
        out: *mut uint8_t,
        len: size_t,
        in_0: *const BIGNUM,
    ) -> libc::c_int;
    fn BN_is_zero(bn: *const BIGNUM) -> libc::c_int;
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_skip(cbs: *mut CBS, len: size_t) -> libc::c_int;
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_get_u8(cbs: *mut CBS, out: *mut uint8_t) -> libc::c_int;
    fn CBS_is_valid_asn1_integer(
        cbs: *const CBS,
        out_is_negative: *mut libc::c_int,
    ) -> libc::c_int;
    fn ERR_clear_error();
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
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type int64_t = __int64_t;
pub type uint8_t = __uint8_t;
pub type uint64_t = __uint64_t;
pub type ossl_ssize_t = ptrdiff_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_string_st {
    pub length: libc::c_int,
    pub type_0: libc::c_int,
    pub data: *mut libc::c_uchar,
    pub flags: libc::c_long,
}
pub type ASN1_ENUMERATED = asn1_string_st;
pub type ASN1_INTEGER = asn1_string_st;
pub type ASN1_STRING = asn1_string_st;
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
pub struct cbs_st {
    pub data: *const uint8_t,
    pub len: size_t,
}
pub type CBS = cbs_st;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_278_error_is_long_fits_in_int64_t {
    #[bitfield(
        name = "static_assertion_at_line_278_error_is_long_fits_in_int64_t",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_278_error_is_long_fits_in_int64_t: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_283_error_is_long_fits_in_int64_t {
    #[bitfield(
        name = "static_assertion_at_line_283_error_is_long_fits_in_int64_t",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_283_error_is_long_fits_in_int64_t: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[inline]
unsafe extern "C" fn CRYPTO_bswap8(mut x: uint64_t) -> uint64_t {
    return x.swap_bytes();
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
#[inline]
unsafe extern "C" fn CRYPTO_load_u64_be(mut ptr: *const libc::c_void) -> uint64_t {
    let mut ret: uint64_t = 0;
    OPENSSL_memcpy(
        &mut ret as *mut uint64_t as *mut libc::c_void,
        ptr,
        ::core::mem::size_of::<uint64_t>() as libc::c_ulong,
    );
    return CRYPTO_bswap8(ret);
}
#[inline]
unsafe extern "C" fn CRYPTO_store_u64_be(mut out: *mut libc::c_void, mut v: uint64_t) {
    v = CRYPTO_bswap8(v);
    OPENSSL_memcpy(
        out,
        &mut v as *mut uint64_t as *const libc::c_void,
        ::core::mem::size_of::<uint64_t>() as libc::c_ulong,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_INTEGER_dup(
    mut x: *const ASN1_INTEGER,
) -> *mut ASN1_INTEGER {
    return ASN1_STRING_dup(x);
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_INTEGER_cmp(
    mut x: *const ASN1_INTEGER,
    mut y: *const ASN1_INTEGER,
) -> libc::c_int {
    let mut neg: libc::c_int = (*x).type_0 & 0x100 as libc::c_int;
    if neg != (*y).type_0 & 0x100 as libc::c_int {
        return if neg != 0 { -(1 as libc::c_int) } else { 1 as libc::c_int };
    }
    let mut ret: libc::c_int = ASN1_STRING_cmp(x, y);
    if neg != 0 {
        if ret < 0 as libc::c_int {
            return 1 as libc::c_int
        } else if ret > 0 as libc::c_int {
            return -(1 as libc::c_int)
        } else {
            return 0 as libc::c_int
        }
    }
    return ret;
}
unsafe extern "C" fn negate_twos_complement(mut buf: *mut uint8_t, mut len: size_t) {
    let mut borrow: uint8_t = 0 as libc::c_int as uint8_t;
    let mut i: size_t = len.wrapping_sub(1 as libc::c_int as size_t);
    while i < len {
        let mut t: uint8_t = *buf.offset(i as isize);
        *buf
            .offset(
                i as isize,
            ) = (0 as libc::c_uint)
            .wrapping_sub(borrow as libc::c_uint)
            .wrapping_sub(t as libc::c_uint) as uint8_t;
        borrow = (borrow as libc::c_int
            | (t as libc::c_int != 0 as libc::c_int) as libc::c_int) as uint8_t;
        i = i.wrapping_sub(1);
        i;
    }
}
unsafe extern "C" fn is_all_zeros(
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < len {
        if *in_0.offset(i as isize) as libc::c_int != 0 as libc::c_int {
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn i2c_ASN1_INTEGER(
    mut in_0: *const ASN1_INTEGER,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    if in_0.is_null() {
        return 0 as libc::c_int;
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, (*in_0).data, (*in_0).length as size_t);
    while CBS_len(&mut cbs) > 0 as libc::c_int as size_t
        && *(CBS_data(&mut cbs)).offset(0 as libc::c_int as isize) as libc::c_int
            == 0 as libc::c_int
    {
        CBS_skip(&mut cbs, 1 as libc::c_int as size_t);
    }
    let mut is_negative: libc::c_int = ((*in_0).type_0 & 0x100 as libc::c_int
        != 0 as libc::c_int) as libc::c_int;
    let mut pad: size_t = 0;
    let mut copy: CBS = cbs;
    let mut msb: uint8_t = 0;
    if CBS_get_u8(&mut copy, &mut msb) == 0 {
        is_negative = 0 as libc::c_int;
        pad = 1 as libc::c_int as size_t;
    } else if is_negative != 0 {
        pad = (msb as libc::c_int > 0x80 as libc::c_int
            || msb as libc::c_int == 0x80 as libc::c_int
                && is_all_zeros(CBS_data(&mut copy), CBS_len(&mut copy)) == 0)
            as libc::c_int as size_t;
    } else {
        pad = (msb as libc::c_int & 0x80 as libc::c_int != 0 as libc::c_int)
            as libc::c_int as size_t;
    }
    if CBS_len(&mut cbs) > (2147483647 as libc::c_int as size_t).wrapping_sub(pad) {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_int.c\0" as *const u8
                as *const libc::c_char,
            153 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut len: libc::c_int = pad.wrapping_add(CBS_len(&mut cbs)) as libc::c_int;
    if len > 0 as libc::c_int {} else {
        __assert_fail(
            b"len > 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_int.c\0" as *const u8
                as *const libc::c_char,
            157 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 61],
                &[libc::c_char; 61],
            >(b"int i2c_ASN1_INTEGER(const ASN1_INTEGER *, unsigned char **)\0"))
                .as_ptr(),
        );
    }
    'c_8149: {
        if len > 0 as libc::c_int {} else {
            __assert_fail(
                b"len > 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_int.c\0" as *const u8
                    as *const libc::c_char,
                157 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 61],
                    &[libc::c_char; 61],
                >(b"int i2c_ASN1_INTEGER(const ASN1_INTEGER *, unsigned char **)\0"))
                    .as_ptr(),
            );
        }
    };
    if outp.is_null() {
        return len;
    }
    if pad != 0 {
        *(*outp).offset(0 as libc::c_int as isize) = 0 as libc::c_int as libc::c_uchar;
    }
    OPENSSL_memcpy(
        (*outp).offset(pad as isize) as *mut libc::c_void,
        CBS_data(&mut cbs) as *const libc::c_void,
        CBS_len(&mut cbs),
    );
    if is_negative != 0 {
        negate_twos_complement(*outp, len as size_t);
        if *(*outp).offset(0 as libc::c_int as isize) as libc::c_int
            >= 0x80 as libc::c_int
        {} else {
            __assert_fail(
                b"(*outp)[0] >= 0x80\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_int.c\0" as *const u8
                    as *const libc::c_char,
                168 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 61],
                    &[libc::c_char; 61],
                >(b"int i2c_ASN1_INTEGER(const ASN1_INTEGER *, unsigned char **)\0"))
                    .as_ptr(),
            );
        }
        'c_7995: {
            if *(*outp).offset(0 as libc::c_int as isize) as libc::c_int
                >= 0x80 as libc::c_int
            {} else {
                __assert_fail(
                    b"(*outp)[0] >= 0x80\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_int.c\0"
                        as *const u8 as *const libc::c_char,
                    168 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 61],
                        &[libc::c_char; 61],
                    >(b"int i2c_ASN1_INTEGER(const ASN1_INTEGER *, unsigned char **)\0"))
                        .as_ptr(),
                );
            }
        };
    } else {
        if (*(*outp).offset(0 as libc::c_int as isize) as libc::c_int)
            < 0x80 as libc::c_int
        {} else {
            __assert_fail(
                b"(*outp)[0] < 0x80\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_int.c\0" as *const u8
                    as *const libc::c_char,
                170 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 61],
                    &[libc::c_char; 61],
                >(b"int i2c_ASN1_INTEGER(const ASN1_INTEGER *, unsigned char **)\0"))
                    .as_ptr(),
            );
        }
        'c_7941: {
            if (*(*outp).offset(0 as libc::c_int as isize) as libc::c_int)
                < 0x80 as libc::c_int
            {} else {
                __assert_fail(
                    b"(*outp)[0] < 0x80\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_int.c\0"
                        as *const u8 as *const libc::c_char,
                    170 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 61],
                        &[libc::c_char; 61],
                    >(b"int i2c_ASN1_INTEGER(const ASN1_INTEGER *, unsigned char **)\0"))
                        .as_ptr(),
                );
            }
        };
    }
    *outp = (*outp).offset(len as isize);
    return len;
}
#[no_mangle]
pub unsafe extern "C" fn c2i_ASN1_INTEGER(
    mut out: *mut *mut ASN1_INTEGER,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_INTEGER {
    if len < 0 as libc::c_int as libc::c_long
        || len > (2147483647 as libc::c_int / 2 as libc::c_int) as libc::c_long
    {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            177 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_int.c\0" as *const u8
                as *const libc::c_char,
            182 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut ASN1_INTEGER;
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, *inp, len as size_t);
    let mut is_negative: libc::c_int = 0;
    if CBS_is_valid_asn1_integer(&mut cbs, &mut is_negative) == 0 {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            196 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_int.c\0" as *const u8
                as *const libc::c_char,
            190 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut ASN1_INTEGER;
    }
    let mut ret: *mut ASN1_INTEGER = 0 as *mut ASN1_INTEGER;
    if out.is_null() || (*out).is_null() {
        ret = ASN1_INTEGER_new();
        if ret.is_null() {
            return 0 as *mut ASN1_INTEGER;
        }
    } else {
        ret = *out;
    }
    if is_negative != 0 {
        if CBS_len(&mut cbs) > 0 as libc::c_int as size_t
            && *(CBS_data(&mut cbs)).offset(0 as libc::c_int as isize) as libc::c_int
                == 0xff as libc::c_int
            && is_all_zeros(
                (CBS_data(&mut cbs)).offset(1 as libc::c_int as isize),
                (CBS_len(&mut cbs)).wrapping_sub(1 as libc::c_int as size_t),
            ) == 0
        {
            CBS_skip(&mut cbs, 1 as libc::c_int as size_t);
        }
    } else if CBS_len(&mut cbs) > 0 as libc::c_int as size_t
        && *(CBS_data(&mut cbs)).offset(0 as libc::c_int as isize) as libc::c_int
            == 0 as libc::c_int
    {
        CBS_skip(&mut cbs, 1 as libc::c_int as size_t);
    }
    if ASN1_STRING_set(
        ret,
        CBS_data(&mut cbs) as *const libc::c_void,
        CBS_len(&mut cbs) as ossl_ssize_t,
    ) == 0
    {
        if !ret.is_null() && (out.is_null() || *out != ret) {
            ASN1_INTEGER_free(ret);
        }
        return 0 as *mut ASN1_INTEGER;
    } else {
        if is_negative != 0 {
            (*ret).type_0 = 2 as libc::c_int | 0x100 as libc::c_int;
            negate_twos_complement((*ret).data, (*ret).length as size_t);
        } else {
            (*ret).type_0 = 2 as libc::c_int;
        }
        if (*ret).length == 0 as libc::c_int
            || *((*ret).data).offset(0 as libc::c_int as isize) as libc::c_int
                != 0 as libc::c_int
        {} else {
            __assert_fail(
                b"ret->length == 0 || ret->data[0] != 0\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_int.c\0" as *const u8
                    as *const libc::c_char,
                234 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 78],
                    &[libc::c_char; 78],
                >(
                    b"ASN1_INTEGER *c2i_ASN1_INTEGER(ASN1_INTEGER **, const unsigned char **, long)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_7446: {
            if (*ret).length == 0 as libc::c_int
                || *((*ret).data).offset(0 as libc::c_int as isize) as libc::c_int
                    != 0 as libc::c_int
            {} else {
                __assert_fail(
                    b"ret->length == 0 || ret->data[0] != 0\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_int.c\0"
                        as *const u8 as *const libc::c_char,
                    234 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 78],
                        &[libc::c_char; 78],
                    >(
                        b"ASN1_INTEGER *c2i_ASN1_INTEGER(ASN1_INTEGER **, const unsigned char **, long)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        if is_negative == 0 || (*ret).length > 0 as libc::c_int {} else {
            __assert_fail(
                b"!is_negative || ret->length > 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_int.c\0" as *const u8
                    as *const libc::c_char,
                236 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 78],
                    &[libc::c_char; 78],
                >(
                    b"ASN1_INTEGER *c2i_ASN1_INTEGER(ASN1_INTEGER **, const unsigned char **, long)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_7386: {
            if is_negative == 0 || (*ret).length > 0 as libc::c_int {} else {
                __assert_fail(
                    b"!is_negative || ret->length > 0\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_int.c\0"
                        as *const u8 as *const libc::c_char,
                    236 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 78],
                        &[libc::c_char; 78],
                    >(
                        b"ASN1_INTEGER *c2i_ASN1_INTEGER(ASN1_INTEGER **, const unsigned char **, long)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        *inp = (*inp).offset(len as isize);
        if !out.is_null() {
            *out = ret;
        }
        return ret;
    };
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_INTEGER_set_int64(
    mut a: *mut ASN1_INTEGER,
    mut v: int64_t,
) -> libc::c_int {
    if v >= 0 as libc::c_int as int64_t {
        return ASN1_INTEGER_set_uint64(a, v as uint64_t);
    }
    if ASN1_INTEGER_set_uint64(
        a,
        (0 as libc::c_int as uint64_t).wrapping_sub(v as uint64_t),
    ) == 0
    {
        return 0 as libc::c_int;
    }
    (*a).type_0 = 2 as libc::c_int | 0x100 as libc::c_int;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_ENUMERATED_set_int64(
    mut a: *mut ASN1_ENUMERATED,
    mut v: int64_t,
) -> libc::c_int {
    if v >= 0 as libc::c_int as int64_t {
        return ASN1_ENUMERATED_set_uint64(a, v as uint64_t);
    }
    if ASN1_ENUMERATED_set_uint64(
        a,
        (0 as libc::c_int as uint64_t).wrapping_sub(v as uint64_t),
    ) == 0
    {
        return 0 as libc::c_int;
    }
    (*a).type_0 = 10 as libc::c_int | 0x100 as libc::c_int;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_INTEGER_set(
    mut a: *mut ASN1_INTEGER,
    mut v: libc::c_long,
) -> libc::c_int {
    return ASN1_INTEGER_set_int64(a, v);
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_ENUMERATED_set(
    mut a: *mut ASN1_ENUMERATED,
    mut v: libc::c_long,
) -> libc::c_int {
    return ASN1_ENUMERATED_set_int64(a, v);
}
unsafe extern "C" fn asn1_string_set_uint64(
    mut out: *mut ASN1_STRING,
    mut v: uint64_t,
    mut type_0: libc::c_int,
) -> libc::c_int {
    let mut buf: [uint8_t; 8] = [0; 8];
    CRYPTO_store_u64_be(buf.as_mut_ptr() as *mut libc::c_void, v);
    let mut leading_zeros: size_t = 0;
    leading_zeros = 0 as libc::c_int as size_t;
    while leading_zeros < ::core::mem::size_of::<[uint8_t; 8]>() as libc::c_ulong {
        if buf[leading_zeros as usize] as libc::c_int != 0 as libc::c_int {
            break;
        }
        leading_zeros = leading_zeros.wrapping_add(1);
        leading_zeros;
    }
    if ASN1_STRING_set(
        out,
        buf.as_mut_ptr().offset(leading_zeros as isize) as *const libc::c_void,
        (::core::mem::size_of::<[uint8_t; 8]>() as libc::c_ulong)
            .wrapping_sub(leading_zeros) as ossl_ssize_t,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    (*out).type_0 = type_0;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_INTEGER_set_uint64(
    mut out: *mut ASN1_INTEGER,
    mut v: uint64_t,
) -> libc::c_int {
    return asn1_string_set_uint64(out, v, 2 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_ENUMERATED_set_uint64(
    mut out: *mut ASN1_ENUMERATED,
    mut v: uint64_t,
) -> libc::c_int {
    return asn1_string_set_uint64(out, v, 10 as libc::c_int);
}
unsafe extern "C" fn asn1_string_get_abs_uint64(
    mut out: *mut uint64_t,
    mut a: *const ASN1_STRING,
    mut type_0: libc::c_int,
) -> libc::c_int {
    if (*a).type_0 & !(0x100 as libc::c_int) != type_0 {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            195 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_int.c\0" as *const u8
                as *const libc::c_char,
            315 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut buf: [uint8_t; 8] = [0 as libc::c_int as uint8_t, 0, 0, 0, 0, 0, 0, 0];
    if (*a).length
        > ::core::mem::size_of::<[uint8_t; 8]>() as libc::c_ulong as libc::c_int
    {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            196 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_int.c\0" as *const u8
                as *const libc::c_char,
            320 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    OPENSSL_memcpy(
        buf
            .as_mut_ptr()
            .offset(::core::mem::size_of::<[uint8_t; 8]>() as libc::c_ulong as isize)
            .offset(-((*a).length as isize)) as *mut libc::c_void,
        (*a).data as *const libc::c_void,
        (*a).length as size_t,
    );
    *out = CRYPTO_load_u64_be(buf.as_mut_ptr() as *const libc::c_void);
    return 1 as libc::c_int;
}
unsafe extern "C" fn asn1_string_get_uint64(
    mut out: *mut uint64_t,
    mut a: *const ASN1_STRING,
    mut type_0: libc::c_int,
) -> libc::c_int {
    if asn1_string_get_abs_uint64(out, a, type_0) == 0 {
        return 0 as libc::c_int;
    }
    if (*a).type_0 & 0x100 as libc::c_int != 0 {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            196 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_int.c\0" as *const u8
                as *const libc::c_char,
            334 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_INTEGER_get_uint64(
    mut out: *mut uint64_t,
    mut a: *const ASN1_INTEGER,
) -> libc::c_int {
    return asn1_string_get_uint64(out, a, 2 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_ENUMERATED_get_uint64(
    mut out: *mut uint64_t,
    mut a: *const ASN1_ENUMERATED,
) -> libc::c_int {
    return asn1_string_get_uint64(out, a, 10 as libc::c_int);
}
unsafe extern "C" fn asn1_string_get_int64(
    mut out: *mut int64_t,
    mut a: *const ASN1_STRING,
    mut type_0: libc::c_int,
) -> libc::c_int {
    let mut v: uint64_t = 0;
    if asn1_string_get_abs_uint64(&mut v, a, type_0) == 0 {
        return 0 as libc::c_int;
    }
    let mut i64: int64_t = 0;
    let mut fits_in_i64: libc::c_int = 0;
    if (*a).type_0 & 0x100 as libc::c_int != 0 && v != 0 as libc::c_int as uint64_t {
        i64 = (0 as libc::c_uint as uint64_t).wrapping_sub(v) as int64_t;
        fits_in_i64 = (i64 < 0 as libc::c_int as int64_t) as libc::c_int;
    } else {
        i64 = v as int64_t;
        fits_in_i64 = (i64 >= 0 as libc::c_int as int64_t) as libc::c_int;
    }
    if fits_in_i64 == 0 {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            196 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_int.c\0" as *const u8
                as *const libc::c_char,
            364 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    *out = i64;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_INTEGER_get_int64(
    mut out: *mut int64_t,
    mut a: *const ASN1_INTEGER,
) -> libc::c_int {
    return asn1_string_get_int64(out, a, 2 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_ENUMERATED_get_int64(
    mut out: *mut int64_t,
    mut a: *const ASN1_ENUMERATED,
) -> libc::c_int {
    return asn1_string_get_int64(out, a, 10 as libc::c_int);
}
unsafe extern "C" fn asn1_string_get_long(
    mut a: *const ASN1_STRING,
    mut type_0: libc::c_int,
) -> libc::c_long {
    if a.is_null() {
        return 0 as libc::c_int as libc::c_long;
    }
    let mut v: int64_t = 0;
    if asn1_string_get_int64(&mut v, a, type_0) == 0
        || v < -(9223372036854775807 as libc::c_long) - 1 as libc::c_long
        || v > 9223372036854775807 as libc::c_long
    {
        ERR_clear_error();
        return -(1 as libc::c_int) as libc::c_long;
    }
    return v;
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_INTEGER_get(mut a: *const ASN1_INTEGER) -> libc::c_long {
    return asn1_string_get_long(a, 2 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_ENUMERATED_get(
    mut a: *const ASN1_ENUMERATED,
) -> libc::c_long {
    return asn1_string_get_long(a, 10 as libc::c_int);
}
unsafe extern "C" fn bn_to_asn1_string(
    mut bn: *const BIGNUM,
    mut ai: *mut ASN1_STRING,
    mut type_0: libc::c_int,
) -> *mut ASN1_STRING {
    let mut len: libc::c_int = 0;
    let mut ret: *mut ASN1_INTEGER = 0 as *mut ASN1_INTEGER;
    if ai.is_null() {
        ret = ASN1_STRING_type_new(type_0);
    } else {
        ret = ai;
    }
    if ret.is_null() {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            158 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_int.c\0" as *const u8
                as *const libc::c_char,
            412 as libc::c_int as libc::c_uint,
        );
    } else {
        if BN_is_negative(bn) != 0 && BN_is_zero(bn) == 0 {
            (*ret).type_0 = type_0 | 0x100 as libc::c_int;
        } else {
            (*ret).type_0 = type_0;
        }
        len = BN_num_bytes(bn) as libc::c_int;
        if !(ASN1_STRING_set(ret, 0 as *const libc::c_void, len as ossl_ssize_t) == 0
            || BN_bn2bin_padded((*ret).data, len as size_t, bn) == 0)
        {
            return ret;
        }
    }
    if ret != ai {
        ASN1_STRING_free(ret);
    }
    return 0 as *mut ASN1_STRING;
}
#[no_mangle]
pub unsafe extern "C" fn BN_to_ASN1_INTEGER(
    mut bn: *const BIGNUM,
    mut ai: *mut ASN1_INTEGER,
) -> *mut ASN1_INTEGER {
    return bn_to_asn1_string(bn, ai, 2 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn BN_to_ASN1_ENUMERATED(
    mut bn: *const BIGNUM,
    mut ai: *mut ASN1_ENUMERATED,
) -> *mut ASN1_ENUMERATED {
    return bn_to_asn1_string(bn, ai, 10 as libc::c_int);
}
unsafe extern "C" fn asn1_string_to_bn(
    mut ai: *const ASN1_STRING,
    mut bn: *mut BIGNUM,
    mut type_0: libc::c_int,
) -> *mut BIGNUM {
    if (*ai).type_0 & !(0x100 as libc::c_int) != type_0 {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            195 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_int.c\0" as *const u8
                as *const libc::c_char,
            446 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut BIGNUM;
    }
    let mut ret: *mut BIGNUM = 0 as *mut BIGNUM;
    ret = BN_bin2bn((*ai).data, (*ai).length as size_t, bn);
    if ret.is_null() {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_int.c\0" as *const u8
                as *const libc::c_char,
            452 as libc::c_int as libc::c_uint,
        );
    } else if (*ai).type_0 & 0x100 as libc::c_int != 0 {
        BN_set_negative(ret, 1 as libc::c_int);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_INTEGER_to_BN(
    mut ai: *const ASN1_INTEGER,
    mut bn: *mut BIGNUM,
) -> *mut BIGNUM {
    return asn1_string_to_bn(ai, bn, 2 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_ENUMERATED_to_BN(
    mut ai: *const ASN1_ENUMERATED,
    mut bn: *mut BIGNUM,
) -> *mut BIGNUM {
    return asn1_string_to_bn(ai, bn, 10 as libc::c_int);
}
