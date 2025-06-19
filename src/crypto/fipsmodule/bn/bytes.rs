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
    fn abort() -> !;
    fn BN_new() -> *mut BIGNUM;
    fn BN_free(bn: *mut BIGNUM);
    fn BN_num_bytes(bn: *const BIGNUM) -> libc::c_uint;
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
    fn bn_minimal_width(bn: *const BIGNUM) -> libc::c_int;
    fn bn_wexpand(bn: *mut BIGNUM, words: size_t) -> libc::c_int;
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
pub struct bignum_st {
    pub d: *mut BN_ULONG,
    pub width: libc::c_int,
    pub dmax: libc::c_int,
    pub neg: libc::c_int,
    pub flags: libc::c_int,
}
pub type BN_ULONG = uint64_t;
pub type BIGNUM = bignum_st;
pub type crypto_word_t = uint64_t;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_552_error_is_int_is_not_the_same_size_as_uint32_t {
    #[bitfield(
        name = "static_assertion_at_line_552_error_is_int_is_not_the_same_size_as_uint32_t",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_552_error_is_int_is_not_the_same_size_as_uint32_t: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[inline]
unsafe extern "C" fn value_barrier_u32(mut a: uint32_t) -> uint32_t {
    asm!("", inlateout(reg) a, options(preserves_flags, pure, readonly, att_syntax));
    return a;
}
#[inline]
unsafe extern "C" fn constant_time_declassify_int(mut v: libc::c_int) -> libc::c_int {
    return value_barrier_u32(v as uint32_t) as libc::c_int;
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
unsafe extern "C" fn CRYPTO_load_word_be(
    mut in_0: *const libc::c_void,
) -> crypto_word_t {
    let mut v: crypto_word_t = 0;
    OPENSSL_memcpy(
        &mut v as *mut crypto_word_t as *mut libc::c_void,
        in_0,
        ::core::mem::size_of::<crypto_word_t>() as libc::c_ulong,
    );
    if ::core::mem::size_of::<crypto_word_t>() as libc::c_ulong
        == 8 as libc::c_int as libc::c_ulong
    {} else {
        __assert_fail(
            b"sizeof(v) == 8\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/../../internal.h\0"
                as *const u8 as *const libc::c_char,
            1110 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 48],
                &[libc::c_char; 48],
            >(b"crypto_word_t CRYPTO_load_word_be(const void *)\0"))
                .as_ptr(),
        );
    }
    'c_2025: {
        if ::core::mem::size_of::<crypto_word_t>() as libc::c_ulong
            == 8 as libc::c_int as libc::c_ulong
        {} else {
            __assert_fail(
                b"sizeof(v) == 8\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/../../internal.h\0"
                    as *const u8 as *const libc::c_char,
                1110 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 48],
                    &[libc::c_char; 48],
                >(b"crypto_word_t CRYPTO_load_word_be(const void *)\0"))
                    .as_ptr(),
            );
        }
    };
    return CRYPTO_bswap8(v);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_big_endian_to_words(
    mut out: *mut BN_ULONG,
    mut out_len: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
) {
    if !(in_len
        <= out_len.wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong))
    {
        abort();
    }
    while in_len >= ::core::mem::size_of::<BN_ULONG>() as libc::c_ulong {
        in_len = (in_len as libc::c_ulong)
            .wrapping_sub(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong) as size_t
            as size_t;
        *out
            .offset(
                0 as libc::c_int as isize,
            ) = CRYPTO_load_word_be(in_0.offset(in_len as isize) as *const libc::c_void);
        out = out.offset(1);
        out;
        out_len = out_len.wrapping_sub(1);
        out_len;
    }
    if in_len != 0 as libc::c_int as size_t {
        let mut word: BN_ULONG = 0 as libc::c_int as BN_ULONG;
        let mut i: size_t = 0 as libc::c_int as size_t;
        while i < in_len {
            word = word << 8 as libc::c_int | *in_0.offset(i as isize) as BN_ULONG;
            i = i.wrapping_add(1);
            i;
        }
        *out.offset(0 as libc::c_int as isize) = word;
        out = out.offset(1);
        out;
        out_len = out_len.wrapping_sub(1);
        out_len;
    }
    OPENSSL_memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        out_len.wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_bin2bn(
    mut in_0: *const uint8_t,
    mut len: size_t,
    mut ret: *mut BIGNUM,
) -> *mut BIGNUM {
    let mut bn: *mut BIGNUM = 0 as *mut BIGNUM;
    if ret.is_null() {
        bn = BN_new();
        if bn.is_null() {
            return 0 as *mut BIGNUM;
        }
        ret = bn;
    }
    if len == 0 as libc::c_int as size_t {
        (*ret).width = 0 as libc::c_int;
        return ret;
    }
    let mut num_words: size_t = (len.wrapping_sub(1 as libc::c_int as size_t)
        / 8 as libc::c_int as size_t)
        .wrapping_add(1 as libc::c_int as size_t);
    if bn_wexpand(ret, num_words) == 0 {
        BN_free(bn);
        return 0 as *mut BIGNUM;
    }
    if num_words <= 2147483647 as libc::c_int as size_t {} else {
        __assert_fail(
            b"num_words <= INT_MAX\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/bytes.c\0"
                as *const u8 as *const libc::c_char,
            116 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 53],
                &[libc::c_char; 53],
            >(b"BIGNUM *BN_bin2bn(const uint8_t *, size_t, BIGNUM *)\0"))
                .as_ptr(),
        );
    }
    'c_2175: {
        if num_words <= 2147483647 as libc::c_int as size_t {} else {
            __assert_fail(
                b"num_words <= INT_MAX\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/bytes.c\0"
                    as *const u8 as *const libc::c_char,
                116 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 53],
                    &[libc::c_char; 53],
                >(b"BIGNUM *BN_bin2bn(const uint8_t *, size_t, BIGNUM *)\0"))
                    .as_ptr(),
            );
        }
    };
    (*ret).width = num_words as libc::c_int;
    (*ret).neg = 0 as libc::c_int;
    bn_big_endian_to_words((*ret).d, (*ret).width as size_t, in_0, len);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_le2bn(
    mut in_0: *const uint8_t,
    mut len: size_t,
    mut ret: *mut BIGNUM,
) -> *mut BIGNUM {
    let mut bn: *mut BIGNUM = 0 as *mut BIGNUM;
    if ret.is_null() {
        bn = BN_new();
        if bn.is_null() {
            return 0 as *mut BIGNUM;
        }
        ret = bn;
    }
    if len == 0 as libc::c_int as size_t {
        (*ret).width = 0 as libc::c_int;
        (*ret).neg = 0 as libc::c_int;
        return ret;
    }
    let mut num_words: size_t = (len.wrapping_sub(1 as libc::c_int as size_t)
        / 8 as libc::c_int as size_t)
        .wrapping_add(1 as libc::c_int as size_t);
    if bn_wexpand(ret, num_words) == 0 {
        BN_free(bn);
        return 0 as *mut BIGNUM;
    }
    (*ret).width = num_words as libc::c_int;
    bn_little_endian_to_words((*ret).d, (*ret).width as size_t, in_0, len);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_little_endian_to_words(
    mut out: *mut BN_ULONG,
    mut out_len: size_t,
    mut in_0: *const uint8_t,
    in_len: size_t,
) {
    if out_len > 0 as libc::c_int as size_t {} else {
        __assert_fail(
            b"out_len > 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/bytes.c\0"
                as *const u8 as *const libc::c_char,
            154 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 82],
                &[libc::c_char; 82],
            >(
                b"void bn_little_endian_to_words(BN_ULONG *, size_t, const uint8_t *, const size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2618: {
        if out_len > 0 as libc::c_int as size_t {} else {
            __assert_fail(
                b"out_len > 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/bytes.c\0"
                    as *const u8 as *const libc::c_char,
                154 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 82],
                    &[libc::c_char; 82],
                >(
                    b"void bn_little_endian_to_words(BN_ULONG *, size_t, const uint8_t *, const size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    OPENSSL_memcpy(out as *mut libc::c_void, in_0 as *const libc::c_void, in_len);
    OPENSSL_memset(
        (out as *mut uint8_t).offset(in_len as isize) as *mut libc::c_void,
        0 as libc::c_int,
        (::core::mem::size_of::<BN_ULONG>() as libc::c_ulong)
            .wrapping_mul(out_len)
            .wrapping_sub(in_len),
    );
}
unsafe extern "C" fn fits_in_bytes(
    mut words: *const BN_ULONG,
    mut num_words: size_t,
    mut num_bytes: size_t,
) -> libc::c_int {
    let mut mask: uint8_t = 0 as libc::c_int as uint8_t;
    let mut bytes: *const uint8_t = words as *const uint8_t;
    let mut tot_bytes: size_t = num_words
        .wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong);
    let mut i: size_t = num_bytes;
    while i < tot_bytes {
        mask = (mask as libc::c_int | *bytes.offset(i as isize) as libc::c_int)
            as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
    return (mask as libc::c_int == 0 as libc::c_int) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_assert_fits_in_bytes(
    mut bn: *const BIGNUM,
    mut num: size_t,
) {
    let mut bytes: *const uint8_t = (*bn).d as *const uint8_t;
    let mut tot_bytes: size_t = ((*bn).width as libc::c_ulong)
        .wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong);
    if tot_bytes > num {
        let mut i: size_t = num;
        while i < tot_bytes {
            if *bytes.offset(i as isize) as libc::c_int == 0 as libc::c_int {} else {
                __assert_fail(
                    b"bytes[i] == 0\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/bytes.c\0"
                        as *const u8 as *const libc::c_char,
                    238 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 53],
                        &[libc::c_char; 53],
                    >(b"void bn_assert_fits_in_bytes(const BIGNUM *, size_t)\0"))
                        .as_ptr(),
                );
            }
            'c_8246: {
                if *bytes.offset(i as isize) as libc::c_int == 0 as libc::c_int {} else {
                    __assert_fail(
                        b"bytes[i] == 0\0" as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/bytes.c\0"
                            as *const u8 as *const libc::c_char,
                        238 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 53],
                            &[libc::c_char; 53],
                        >(b"void bn_assert_fits_in_bytes(const BIGNUM *, size_t)\0"))
                            .as_ptr(),
                    );
                }
            };
            i = i.wrapping_add(1);
            i;
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_words_to_big_endian(
    mut out: *mut uint8_t,
    mut out_len: size_t,
    mut in_0: *const BN_ULONG,
    mut in_len: size_t,
) {
    if constant_time_declassify_int(fits_in_bytes(in_0, in_len, out_len)) != 0 {} else {
        __assert_fail(
            b"constant_time_declassify_int(fits_in_bytes(in, in_len, out_len))\0"
                as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/bytes.c\0"
                as *const u8 as *const libc::c_char,
            249 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 73],
                &[libc::c_char; 73],
            >(
                b"void bn_words_to_big_endian(uint8_t *, size_t, const BN_ULONG *, size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2411: {
        if constant_time_declassify_int(fits_in_bytes(in_0, in_len, out_len)) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(fits_in_bytes(in, in_len, out_len))\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/bytes.c\0"
                    as *const u8 as *const libc::c_char,
                249 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 73],
                    &[libc::c_char; 73],
                >(
                    b"void bn_words_to_big_endian(uint8_t *, size_t, const BN_ULONG *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut num_bytes: size_t = in_len
        .wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong);
    if out_len < num_bytes {
        num_bytes = out_len;
    }
    let mut bytes: *const uint8_t = in_0 as *const uint8_t;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < num_bytes {
        *out
            .offset(
                out_len.wrapping_sub(i).wrapping_sub(1 as libc::c_int as size_t) as isize,
            ) = *bytes.offset(i as isize);
        i = i.wrapping_add(1);
        i;
    }
    OPENSSL_memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        out_len.wrapping_sub(num_bytes),
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_bn2bin(
    mut in_0: *const BIGNUM,
    mut out: *mut uint8_t,
) -> size_t {
    let mut n: size_t = BN_num_bytes(in_0) as size_t;
    bn_words_to_big_endian(out, n, (*in_0).d, (*in_0).width as size_t);
    return n;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_words_to_little_endian(
    mut out: *mut uint8_t,
    mut out_len: size_t,
    mut in_0: *const BN_ULONG,
    in_len: size_t,
) {
    if fits_in_bytes(in_0, in_len, out_len) != 0 {} else {
        __assert_fail(
            b"fits_in_bytes(in, in_len, out_len)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/bytes.c\0"
                as *const u8 as *const libc::c_char,
            278 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 82],
                &[libc::c_char; 82],
            >(
                b"void bn_words_to_little_endian(uint8_t *, size_t, const BN_ULONG *, const size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2845: {
        if fits_in_bytes(in_0, in_len, out_len) != 0 {} else {
            __assert_fail(
                b"fits_in_bytes(in, in_len, out_len)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/bytes.c\0"
                    as *const u8 as *const libc::c_char,
                278 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 82],
                    &[libc::c_char; 82],
                >(
                    b"void bn_words_to_little_endian(uint8_t *, size_t, const BN_ULONG *, const size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut num_bytes: size_t = in_len
        .wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong);
    if out_len < num_bytes {
        num_bytes = out_len;
    }
    let mut bytes: *const uint8_t = in_0 as *const uint8_t;
    OPENSSL_memcpy(out as *mut libc::c_void, bytes as *const libc::c_void, num_bytes);
    OPENSSL_memset(
        out.offset(num_bytes as isize) as *mut libc::c_void,
        0 as libc::c_int,
        out_len.wrapping_sub(num_bytes),
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_bn2le_padded(
    mut out: *mut uint8_t,
    mut len: size_t,
    mut in_0: *const BIGNUM,
) -> libc::c_int {
    if fits_in_bytes((*in_0).d, (*in_0).width as size_t, len) == 0 {
        return 0 as libc::c_int;
    }
    bn_words_to_little_endian(out, len, (*in_0).d, (*in_0).width as size_t);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_bn2bin_padded(
    mut out: *mut uint8_t,
    mut len: size_t,
    mut in_0: *const BIGNUM,
) -> libc::c_int {
    if fits_in_bytes((*in_0).d, (*in_0).width as size_t, len) == 0 {
        return 0 as libc::c_int;
    }
    bn_words_to_big_endian(out, len, (*in_0).d, (*in_0).width as size_t);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_get_word(mut bn: *const BIGNUM) -> BN_ULONG {
    match bn_minimal_width(bn) {
        0 => return 0 as libc::c_int as BN_ULONG,
        1 => return *((*bn).d).offset(0 as libc::c_int as isize),
        _ => return 0xffffffffffffffff as libc::c_ulong,
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_get_u64(
    mut bn: *const BIGNUM,
    mut out: *mut uint64_t,
) -> libc::c_int {
    match bn_minimal_width(bn) {
        0 => {
            *out = 0 as libc::c_int as uint64_t;
            return 1 as libc::c_int;
        }
        1 => {
            *out = *((*bn).d).offset(0 as libc::c_int as isize);
            return 1 as libc::c_int;
        }
        _ => return 0 as libc::c_int,
    };
}
