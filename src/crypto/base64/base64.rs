#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(asm, label_break_value)]
use core::arch::asm;
unsafe extern "C" {
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
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_encode_ctx_st {
    pub data_used: libc::c_uint,
    pub data: [uint8_t; 48],
    pub eof_seen: libc::c_char,
    pub error_encountered: libc::c_char,
}
pub type EVP_ENCODE_CTX = evp_encode_ctx_st;
pub type crypto_word_t = uint64_t;
#[inline]
unsafe extern "C" fn value_barrier_w(mut a: crypto_word_t) -> crypto_word_t {
    asm!("", inlateout(reg) a, options(preserves_flags, pure, readonly, att_syntax));
    return a;
}
#[inline]
unsafe extern "C" fn constant_time_msb_w(mut a: crypto_word_t) -> crypto_word_t {
    return (0 as libc::c_uint as crypto_word_t)
        .wrapping_sub(
            a
                >> (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        );
}
#[inline]
unsafe extern "C" fn constant_time_is_zero_w(mut a: crypto_word_t) -> crypto_word_t {
    return constant_time_msb_w(!a & a.wrapping_sub(1 as libc::c_int as crypto_word_t));
}
#[inline]
unsafe extern "C" fn constant_time_eq_w(
    mut a: crypto_word_t,
    mut b: crypto_word_t,
) -> crypto_word_t {
    return constant_time_is_zero_w(a ^ b);
}
#[inline]
unsafe extern "C" fn constant_time_eq_8(
    mut a: crypto_word_t,
    mut b: crypto_word_t,
) -> uint8_t {
    return constant_time_eq_w(a, b) as uint8_t;
}
#[inline]
unsafe extern "C" fn constant_time_select_w(
    mut mask: crypto_word_t,
    mut a: crypto_word_t,
    mut b: crypto_word_t,
) -> crypto_word_t {
    return value_barrier_w(mask) & a | value_barrier_w(!mask) & b;
}
#[inline]
unsafe extern "C" fn constant_time_select_8(
    mut mask: uint8_t,
    mut a: uint8_t,
    mut b: uint8_t,
) -> uint8_t {
    return constant_time_select_w(
        mask as crypto_word_t,
        a as crypto_word_t,
        b as crypto_word_t,
    ) as uint8_t;
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
#[inline]
unsafe extern "C" fn constant_time_lt_args_8(mut a: uint8_t, mut b: uint8_t) -> uint8_t {
    let mut aw: crypto_word_t = a as crypto_word_t;
    let mut bw: crypto_word_t = b as crypto_word_t;
    return constant_time_msb_w(aw.wrapping_sub(bw)) as uint8_t;
}
#[inline]
unsafe extern "C" fn constant_time_in_range_8(
    mut a: uint8_t,
    mut min: uint8_t,
    mut max: uint8_t,
) -> uint8_t {
    a = (a as libc::c_int - min as libc::c_int) as uint8_t;
    return constant_time_lt_args_8(
        a,
        (max as libc::c_int - min as libc::c_int + 1 as libc::c_int) as uint8_t,
    );
}
unsafe extern "C" fn conv_bin2ascii(mut a: uint8_t) -> uint8_t {
    a = (a as libc::c_int & 0x3f as libc::c_int) as uint8_t;
    let mut ret: uint8_t = constant_time_select_8(
        constant_time_eq_8(a as crypto_word_t, 62 as libc::c_int as crypto_word_t),
        '+' as i32 as uint8_t,
        '/' as i32 as uint8_t,
    );
    ret = constant_time_select_8(
        constant_time_lt_args_8(a, 62 as libc::c_int as uint8_t),
        (a as libc::c_int - 52 as libc::c_int + '0' as i32) as uint8_t,
        ret,
    );
    ret = constant_time_select_8(
        constant_time_lt_args_8(a, 52 as libc::c_int as uint8_t),
        (a as libc::c_int - 26 as libc::c_int + 'a' as i32) as uint8_t,
        ret,
    );
    ret = constant_time_select_8(
        constant_time_lt_args_8(a, 26 as libc::c_int as uint8_t),
        (a as libc::c_int + 'A' as i32) as uint8_t,
        ret,
    );
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_EncodedLength(
    mut out_len: *mut size_t,
    mut len: size_t,
) -> libc::c_int {
    if len.wrapping_add(2 as libc::c_int as size_t) < len {
        return 0 as libc::c_int;
    }
    len = len.wrapping_add(2 as libc::c_int as size_t);
    len = len / 3 as libc::c_int as size_t;
    if len << 2 as libc::c_int >> 2 as libc::c_int != len {
        return 0 as libc::c_int;
    }
    len <<= 2 as libc::c_int;
    if len.wrapping_add(1 as libc::c_int as size_t) < len {
        return 0 as libc::c_int;
    }
    len = len.wrapping_add(1);
    len;
    *out_len = len;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_ENCODE_CTX_new() -> *mut EVP_ENCODE_CTX {
    return OPENSSL_zalloc(::core::mem::size_of::<EVP_ENCODE_CTX>() as libc::c_ulong)
        as *mut EVP_ENCODE_CTX;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_ENCODE_CTX_free(mut ctx: *mut EVP_ENCODE_CTX) {
    OPENSSL_free(ctx as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_EncodeInit(mut ctx: *mut EVP_ENCODE_CTX) {
    OPENSSL_memset(
        ctx as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_ENCODE_CTX>() as libc::c_ulong,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_EncodeUpdate(
    mut ctx: *mut EVP_ENCODE_CTX,
    mut out: *mut uint8_t,
    mut out_len: *mut libc::c_int,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
) -> libc::c_int {
    let mut total: size_t = 0 as libc::c_int as size_t;
    *out_len = 0 as libc::c_int;
    if in_len == 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    if ((*ctx).data_used as libc::c_ulong)
        < ::core::mem::size_of::<[uint8_t; 48]>() as libc::c_ulong
    {} else {
        __assert_fail(
            b"ctx->data_used < sizeof(ctx->data)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/base64/base64.c\0" as *const u8
                as *const libc::c_char,
            146 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 82],
                &[libc::c_char; 82],
            >(
                b"int EVP_EncodeUpdate(EVP_ENCODE_CTX *, uint8_t *, int *, const uint8_t *, size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2821: {
        if ((*ctx).data_used as libc::c_ulong)
            < ::core::mem::size_of::<[uint8_t; 48]>() as libc::c_ulong
        {} else {
            __assert_fail(
                b"ctx->data_used < sizeof(ctx->data)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/base64/base64.c\0"
                    as *const u8 as *const libc::c_char,
                146 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 82],
                    &[libc::c_char; 82],
                >(
                    b"int EVP_EncodeUpdate(EVP_ENCODE_CTX *, uint8_t *, int *, const uint8_t *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if (::core::mem::size_of::<[uint8_t; 48]>() as libc::c_ulong)
        .wrapping_sub((*ctx).data_used as libc::c_ulong) > in_len
    {
        OPENSSL_memcpy(
            &mut *((*ctx).data).as_mut_ptr().offset((*ctx).data_used as isize)
                as *mut uint8_t as *mut libc::c_void,
            in_0 as *const libc::c_void,
            in_len,
        );
        (*ctx).data_used = ((*ctx).data_used).wrapping_add(in_len as libc::c_uint);
        return 1 as libc::c_int;
    }
    if (*ctx).data_used != 0 as libc::c_int as libc::c_uint {
        let todo: size_t = (::core::mem::size_of::<[uint8_t; 48]>() as libc::c_ulong)
            .wrapping_sub((*ctx).data_used as libc::c_ulong);
        OPENSSL_memcpy(
            &mut *((*ctx).data).as_mut_ptr().offset((*ctx).data_used as isize)
                as *mut uint8_t as *mut libc::c_void,
            in_0 as *const libc::c_void,
            todo,
        );
        in_0 = in_0.offset(todo as isize);
        in_len = in_len.wrapping_sub(todo);
        let mut encoded: size_t = EVP_EncodeBlock(
            out,
            ((*ctx).data).as_mut_ptr(),
            ::core::mem::size_of::<[uint8_t; 48]>() as libc::c_ulong,
        );
        (*ctx).data_used = 0 as libc::c_int as libc::c_uint;
        out = out.offset(encoded as isize);
        let fresh0 = out;
        out = out.offset(1);
        *fresh0 = '\n' as i32 as uint8_t;
        *out = '\0' as i32 as uint8_t;
        total = encoded.wrapping_add(1 as libc::c_int as size_t);
    }
    while in_len >= ::core::mem::size_of::<[uint8_t; 48]>() as libc::c_ulong {
        let mut encoded_0: size_t = EVP_EncodeBlock(
            out,
            in_0,
            ::core::mem::size_of::<[uint8_t; 48]>() as libc::c_ulong,
        );
        in_0 = in_0
            .offset(::core::mem::size_of::<[uint8_t; 48]>() as libc::c_ulong as isize);
        in_len = (in_len as libc::c_ulong)
            .wrapping_sub(::core::mem::size_of::<[uint8_t; 48]>() as libc::c_ulong)
            as size_t as size_t;
        out = out.offset(encoded_0 as isize);
        let fresh1 = out;
        out = out.offset(1);
        *fresh1 = '\n' as i32 as uint8_t;
        *out = '\0' as i32 as uint8_t;
        if total.wrapping_add(encoded_0).wrapping_add(1 as libc::c_int as size_t) < total
        {
            *out_len = 0 as libc::c_int;
            return 0 as libc::c_int;
        }
        total = total.wrapping_add(encoded_0.wrapping_add(1 as libc::c_int as size_t));
    }
    if in_len != 0 as libc::c_int as size_t {
        OPENSSL_memcpy(
            ((*ctx).data).as_mut_ptr() as *mut libc::c_void,
            in_0 as *const libc::c_void,
            in_len,
        );
    }
    (*ctx).data_used = in_len as libc::c_uint;
    if total > 2147483647 as libc::c_int as size_t {
        *out_len = 0 as libc::c_int;
        return 0 as libc::c_int;
    }
    *out_len = total as libc::c_int;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_EncodeFinal(
    mut ctx: *mut EVP_ENCODE_CTX,
    mut out: *mut uint8_t,
    mut out_len: *mut libc::c_int,
) {
    if (*ctx).data_used == 0 as libc::c_int as libc::c_uint {
        *out_len = 0 as libc::c_int;
        return;
    }
    let mut encoded: size_t = EVP_EncodeBlock(
        out,
        ((*ctx).data).as_mut_ptr(),
        (*ctx).data_used as size_t,
    );
    let fresh2 = encoded;
    encoded = encoded.wrapping_add(1);
    *out.offset(fresh2 as isize) = '\n' as i32 as uint8_t;
    *out.offset(encoded as isize) = '\0' as i32 as uint8_t;
    (*ctx).data_used = 0 as libc::c_int as libc::c_uint;
    if encoded <= 2147483647 as libc::c_int as size_t {} else {
        __assert_fail(
            b"encoded <= INT_MAX\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/base64/base64.c\0" as *const u8
                as *const libc::c_char,
            217 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 57],
                &[libc::c_char; 57],
            >(b"void EVP_EncodeFinal(EVP_ENCODE_CTX *, uint8_t *, int *)\0"))
                .as_ptr(),
        );
    }
    'c_2931: {
        if encoded <= 2147483647 as libc::c_int as size_t {} else {
            __assert_fail(
                b"encoded <= INT_MAX\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/base64/base64.c\0"
                    as *const u8 as *const libc::c_char,
                217 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 57],
                    &[libc::c_char; 57],
                >(b"void EVP_EncodeFinal(EVP_ENCODE_CTX *, uint8_t *, int *)\0"))
                    .as_ptr(),
            );
        }
    };
    *out_len = encoded as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_EncodeBlock(
    mut dst: *mut uint8_t,
    mut src: *const uint8_t,
    mut src_len: size_t,
) -> size_t {
    let mut l: uint32_t = 0;
    let mut remaining: size_t = src_len;
    let mut ret: size_t = 0 as libc::c_int as size_t;
    while remaining != 0 {
        if remaining >= 3 as libc::c_int as size_t {
            l = (*src.offset(0 as libc::c_int as isize) as uint32_t)
                << 16 as libc::c_long
                | (*src.offset(1 as libc::c_int as isize) as uint32_t)
                    << 8 as libc::c_long
                | *src.offset(2 as libc::c_int as isize) as uint32_t;
            let fresh3 = dst;
            dst = dst.offset(1);
            *fresh3 = conv_bin2ascii((l >> 18 as libc::c_long) as uint8_t);
            let fresh4 = dst;
            dst = dst.offset(1);
            *fresh4 = conv_bin2ascii((l >> 12 as libc::c_long) as uint8_t);
            let fresh5 = dst;
            dst = dst.offset(1);
            *fresh5 = conv_bin2ascii((l >> 6 as libc::c_long) as uint8_t);
            let fresh6 = dst;
            dst = dst.offset(1);
            *fresh6 = conv_bin2ascii(l as uint8_t);
            remaining = remaining.wrapping_sub(3 as libc::c_int as size_t);
        } else {
            l = (*src.offset(0 as libc::c_int as isize) as uint32_t)
                << 16 as libc::c_long;
            if remaining == 2 as libc::c_int as size_t {
                l
                    |= (*src.offset(1 as libc::c_int as isize) as uint32_t)
                        << 8 as libc::c_long;
            }
            let fresh7 = dst;
            dst = dst.offset(1);
            *fresh7 = conv_bin2ascii((l >> 18 as libc::c_long) as uint8_t);
            let fresh8 = dst;
            dst = dst.offset(1);
            *fresh8 = conv_bin2ascii((l >> 12 as libc::c_long) as uint8_t);
            let fresh9 = dst;
            dst = dst.offset(1);
            *fresh9 = (if remaining == 1 as libc::c_int as size_t {
                '=' as i32
            } else {
                conv_bin2ascii((l >> 6 as libc::c_long) as uint8_t) as libc::c_int
            }) as uint8_t;
            let fresh10 = dst;
            dst = dst.offset(1);
            *fresh10 = '=' as i32 as uint8_t;
            remaining = 0 as libc::c_int as size_t;
        }
        ret = ret.wrapping_add(4 as libc::c_int as size_t);
        src = src.offset(3 as libc::c_int as isize);
    }
    *dst = '\0' as i32 as uint8_t;
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_DecodedLength(
    mut out_len: *mut size_t,
    mut len: size_t,
) -> libc::c_int {
    if len % 4 as libc::c_int as size_t != 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    *out_len = len / 4 as libc::c_int as size_t * 3 as libc::c_int as size_t;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_DecodeInit(mut ctx: *mut EVP_ENCODE_CTX) {
    OPENSSL_memset(
        ctx as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_ENCODE_CTX>() as libc::c_ulong,
    );
}
unsafe extern "C" fn base64_ascii_to_bin(mut a: uint8_t) -> uint8_t {
    let is_upper: uint8_t = constant_time_in_range_8(
        a,
        'A' as i32 as uint8_t,
        'Z' as i32 as uint8_t,
    );
    let is_lower: uint8_t = constant_time_in_range_8(
        a,
        'a' as i32 as uint8_t,
        'z' as i32 as uint8_t,
    );
    let is_digit: uint8_t = constant_time_in_range_8(
        a,
        '0' as i32 as uint8_t,
        '9' as i32 as uint8_t,
    );
    let is_plus: uint8_t = constant_time_eq_8(
        a as crypto_word_t,
        '+' as i32 as crypto_word_t,
    );
    let is_slash: uint8_t = constant_time_eq_8(
        a as crypto_word_t,
        '/' as i32 as crypto_word_t,
    );
    let is_equals: uint8_t = constant_time_eq_8(
        a as crypto_word_t,
        '=' as i32 as crypto_word_t,
    );
    let mut ret: uint8_t = 0 as libc::c_int as uint8_t;
    ret = (ret as libc::c_int | is_upper as libc::c_int & a as libc::c_int - 'A' as i32)
        as uint8_t;
    ret = (ret as libc::c_int
        | is_lower as libc::c_int & a as libc::c_int - 'a' as i32 + 26 as libc::c_int)
        as uint8_t;
    ret = (ret as libc::c_int
        | is_digit as libc::c_int & a as libc::c_int - '0' as i32 + 52 as libc::c_int)
        as uint8_t;
    ret = (ret as libc::c_int | is_plus as libc::c_int & 62 as libc::c_int) as uint8_t;
    ret = (ret as libc::c_int | is_slash as libc::c_int & 63 as libc::c_int) as uint8_t;
    let is_valid: uint8_t = (is_upper as libc::c_int | is_lower as libc::c_int
        | is_digit as libc::c_int | is_plus as libc::c_int | is_slash as libc::c_int
        | is_equals as libc::c_int) as uint8_t;
    ret = (ret as libc::c_int | !(is_valid as libc::c_int)) as uint8_t;
    return ret;
}
unsafe extern "C" fn base64_decode_quad(
    mut out: *mut uint8_t,
    mut out_num_bytes: *mut size_t,
    mut in_0: *const uint8_t,
) -> libc::c_int {
    let a: uint8_t = base64_ascii_to_bin(*in_0.offset(0 as libc::c_int as isize));
    let b: uint8_t = base64_ascii_to_bin(*in_0.offset(1 as libc::c_int as isize));
    let c: uint8_t = base64_ascii_to_bin(*in_0.offset(2 as libc::c_int as isize));
    let d: uint8_t = base64_ascii_to_bin(*in_0.offset(3 as libc::c_int as isize));
    if a as libc::c_int == 0xff as libc::c_int || b as libc::c_int == 0xff as libc::c_int
        || c as libc::c_int == 0xff as libc::c_int
        || d as libc::c_int == 0xff as libc::c_int
    {
        return 0 as libc::c_int;
    }
    let v: uint32_t = (a as uint32_t) << 18 as libc::c_int
        | (b as uint32_t) << 12 as libc::c_int | (c as uint32_t) << 6 as libc::c_int
        | d as uint32_t;
    let padding_pattern: libc::c_uint = (((*in_0.offset(0 as libc::c_int as isize)
        as libc::c_int == '=' as i32) as libc::c_int) << 3 as libc::c_int
        | ((*in_0.offset(1 as libc::c_int as isize) as libc::c_int == '=' as i32)
            as libc::c_int) << 2 as libc::c_int
        | ((*in_0.offset(2 as libc::c_int as isize) as libc::c_int == '=' as i32)
            as libc::c_int) << 1 as libc::c_int
        | (*in_0.offset(3 as libc::c_int as isize) as libc::c_int == '=' as i32)
            as libc::c_int) as libc::c_uint;
    match padding_pattern {
        0 => {
            *out_num_bytes = 3 as libc::c_int as size_t;
            *out.offset(0 as libc::c_int as isize) = (v >> 16 as libc::c_int) as uint8_t;
            *out.offset(1 as libc::c_int as isize) = (v >> 8 as libc::c_int) as uint8_t;
            *out.offset(2 as libc::c_int as isize) = v as uint8_t;
        }
        1 => {
            *out_num_bytes = 2 as libc::c_int as size_t;
            *out.offset(0 as libc::c_int as isize) = (v >> 16 as libc::c_int) as uint8_t;
            *out.offset(1 as libc::c_int as isize) = (v >> 8 as libc::c_int) as uint8_t;
        }
        3 => {
            *out_num_bytes = 1 as libc::c_int as size_t;
            *out.offset(0 as libc::c_int as isize) = (v >> 16 as libc::c_int) as uint8_t;
        }
        _ => return 0 as libc::c_int,
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_DecodeUpdate(
    mut ctx: *mut EVP_ENCODE_CTX,
    mut out: *mut uint8_t,
    mut out_len: *mut libc::c_int,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
) -> libc::c_int {
    *out_len = 0 as libc::c_int;
    if (*ctx).error_encountered != 0 {
        return -(1 as libc::c_int);
    }
    let mut bytes_out: size_t = 0 as libc::c_int as size_t;
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < in_len {
        let c: libc::c_char = *in_0.offset(i as isize) as libc::c_char;
        match c as libc::c_int {
            32 | 9 | 13 | 10 => {}
            _ => {
                if (*ctx).eof_seen != 0 {
                    (*ctx).error_encountered = 1 as libc::c_int as libc::c_char;
                    return -(1 as libc::c_int);
                }
                let fresh11 = (*ctx).data_used;
                (*ctx).data_used = ((*ctx).data_used).wrapping_add(1);
                (*ctx).data[fresh11 as usize] = c as uint8_t;
                if (*ctx).data_used == 4 as libc::c_int as libc::c_uint {
                    let mut num_bytes_resulting: size_t = 0;
                    if base64_decode_quad(
                        out,
                        &mut num_bytes_resulting,
                        ((*ctx).data).as_mut_ptr(),
                    ) == 0
                    {
                        (*ctx).error_encountered = 1 as libc::c_int as libc::c_char;
                        return -(1 as libc::c_int);
                    }
                    (*ctx).data_used = 0 as libc::c_int as libc::c_uint;
                    bytes_out = bytes_out.wrapping_add(num_bytes_resulting);
                    out = out.offset(num_bytes_resulting as isize);
                    if num_bytes_resulting < 3 as libc::c_int as size_t {
                        (*ctx).eof_seen = 1 as libc::c_int as libc::c_char;
                    }
                }
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    if bytes_out > 2147483647 as libc::c_int as size_t {
        (*ctx).error_encountered = 1 as libc::c_int as libc::c_char;
        *out_len = 0 as libc::c_int;
        return -(1 as libc::c_int);
    }
    *out_len = bytes_out as libc::c_int;
    if (*ctx).eof_seen != 0 {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_DecodeFinal(
    mut ctx: *mut EVP_ENCODE_CTX,
    mut out: *mut uint8_t,
    mut out_len: *mut libc::c_int,
) -> libc::c_int {
    *out_len = 0 as libc::c_int;
    if (*ctx).error_encountered as libc::c_int != 0
        || (*ctx).data_used != 0 as libc::c_int as libc::c_uint
    {
        return -(1 as libc::c_int);
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_DecodeBase64(
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
    mut max_out: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
) -> libc::c_int {
    *out_len = 0 as libc::c_int as size_t;
    if in_len % 4 as libc::c_int as size_t != 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    let mut max_len: size_t = 0;
    if EVP_DecodedLength(&mut max_len, in_len) == 0 || max_out < max_len {
        return 0 as libc::c_int;
    }
    let mut i: size_t = 0;
    let mut bytes_out: size_t = 0 as libc::c_int as size_t;
    i = 0 as libc::c_int as size_t;
    while i < in_len {
        let mut num_bytes_resulting: size_t = 0;
        if base64_decode_quad(out, &mut num_bytes_resulting, &*in_0.offset(i as isize))
            == 0
        {
            return 0 as libc::c_int;
        }
        bytes_out = bytes_out.wrapping_add(num_bytes_resulting);
        out = out.offset(num_bytes_resulting as isize);
        if num_bytes_resulting != 3 as libc::c_int as size_t
            && i != in_len.wrapping_sub(4 as libc::c_int as size_t)
        {
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(4 as libc::c_int as size_t);
    }
    *out_len = bytes_out;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_DecodeBlock(
    mut dst: *mut uint8_t,
    mut src: *const uint8_t,
    mut src_len: size_t,
) -> libc::c_int {
    while src_len > 0 as libc::c_int as size_t {
        if *src.offset(0 as libc::c_int as isize) as libc::c_int != ' ' as i32
            && *src.offset(0 as libc::c_int as isize) as libc::c_int != '\t' as i32
        {
            break;
        }
        src = src.offset(1);
        src;
        src_len = src_len.wrapping_sub(1);
        src_len;
    }
    while src_len > 0 as libc::c_int as size_t {
        match *src.offset(src_len.wrapping_sub(1 as libc::c_int as size_t) as isize)
            as libc::c_int
        {
            32 | 9 | 13 | 10 => {}
            _ => {
                break;
            }
        }
        src_len = src_len.wrapping_sub(1);
        src_len;
    }
    let mut dst_len: size_t = 0;
    if EVP_DecodedLength(&mut dst_len, src_len) == 0
        || dst_len > 2147483647 as libc::c_int as size_t
        || EVP_DecodeBase64(dst, &mut dst_len, dst_len, src, src_len) == 0
    {
        return -(1 as libc::c_int);
    }
    while dst_len % 3 as libc::c_int as size_t != 0 as libc::c_int as size_t {
        let fresh12 = dst_len;
        dst_len = dst_len.wrapping_add(1);
        *dst.offset(fresh12 as isize) = '\0' as i32 as uint8_t;
    }
    if dst_len <= 2147483647 as libc::c_int as size_t {} else {
        __assert_fail(
            b"dst_len <= INT_MAX\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/base64/base64.c\0" as *const u8
                as *const libc::c_char,
            477 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 56],
                &[libc::c_char; 56],
            >(b"int EVP_DecodeBlock(uint8_t *, const uint8_t *, size_t)\0"))
                .as_ptr(),
        );
    }
    'c_3274: {
        if dst_len <= 2147483647 as libc::c_int as size_t {} else {
            __assert_fail(
                b"dst_len <= INT_MAX\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/base64/base64.c\0"
                    as *const u8 as *const libc::c_char,
                477 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 56],
                    &[libc::c_char; 56],
                >(b"int EVP_DecodeBlock(uint8_t *, const uint8_t *, size_t)\0"))
                    .as_ptr(),
            );
        }
    };
    return dst_len as libc::c_int;
}
