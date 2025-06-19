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
extern "C" {
    fn AES_encrypt(in_0: *const uint8_t, out: *mut uint8_t, key: *const AES_KEY);
    fn AES_decrypt(in_0: *const uint8_t, out: *mut uint8_t, key: *const AES_KEY);
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
    fn memmove(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn CRYPTO_memcmp(
        a: *const libc::c_void,
        b: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
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
pub struct aes_key_st {
    pub rd_key: [uint32_t; 60],
    pub rounds: libc::c_uint,
}
pub type AES_KEY = aes_key_st;
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
unsafe extern "C" fn constant_time_lt_w(
    mut a: crypto_word_t,
    mut b: crypto_word_t,
) -> crypto_word_t {
    return constant_time_msb_w(a ^ (a ^ b | a.wrapping_sub(b) ^ a));
}
#[inline]
unsafe extern "C" fn constant_time_ge_w(
    mut a: crypto_word_t,
    mut b: crypto_word_t,
) -> crypto_word_t {
    return !constant_time_lt_w(a, b);
}
#[inline]
unsafe extern "C" fn constant_time_ge_8(
    mut a: crypto_word_t,
    mut b: crypto_word_t,
) -> uint8_t {
    return constant_time_ge_w(a, b) as uint8_t;
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
unsafe extern "C" fn constant_time_eq_int(
    mut a: libc::c_int,
    mut b: libc::c_int,
) -> crypto_word_t {
    return constant_time_eq_w(a as crypto_word_t, b as crypto_word_t);
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
unsafe extern "C" fn CRYPTO_bswap4(mut x: uint32_t) -> uint32_t {
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
unsafe extern "C" fn OPENSSL_memmove(
    mut dst: *mut libc::c_void,
    mut src: *const libc::c_void,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return dst;
    }
    return memmove(dst, src, n);
}
#[inline]
unsafe extern "C" fn CRYPTO_load_u32_be(mut in_0: *const libc::c_void) -> uint32_t {
    let mut v: uint32_t = 0;
    OPENSSL_memcpy(
        &mut v as *mut uint32_t as *mut libc::c_void,
        in_0,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
    return CRYPTO_bswap4(v);
}
#[inline]
unsafe extern "C" fn CRYPTO_store_u32_be(mut out: *mut libc::c_void, mut v: uint32_t) {
    v = CRYPTO_bswap4(v);
    OPENSSL_memcpy(
        out,
        &mut v as *mut uint32_t as *const libc::c_void,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_update_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_lock_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_unlock_state() {}
static mut kDefaultIV: [uint8_t; 8] = [
    0xa6 as libc::c_int as uint8_t,
    0xa6 as libc::c_int as uint8_t,
    0xa6 as libc::c_int as uint8_t,
    0xa6 as libc::c_int as uint8_t,
    0xa6 as libc::c_int as uint8_t,
    0xa6 as libc::c_int as uint8_t,
    0xa6 as libc::c_int as uint8_t,
    0xa6 as libc::c_int as uint8_t,
];
static mut kBound: libc::c_uint = 6 as libc::c_int as libc::c_uint;
#[no_mangle]
pub unsafe extern "C" fn AES_wrap_key(
    mut key: *const AES_KEY,
    mut iv: *const uint8_t,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
) -> libc::c_int {
    if in_len > (2147483647 as libc::c_int - 8 as libc::c_int) as size_t
        || in_len < 16 as libc::c_int as size_t
        || in_len % 8 as libc::c_int as size_t != 0 as libc::c_int as size_t
    {
        return -(1 as libc::c_int);
    }
    if iv.is_null() {
        iv = kDefaultIV.as_ptr();
    }
    OPENSSL_memmove(
        out.offset(8 as libc::c_int as isize) as *mut libc::c_void,
        in_0 as *const libc::c_void,
        in_len,
    );
    let mut A: [uint8_t; 16] = [0; 16];
    OPENSSL_memcpy(
        A.as_mut_ptr() as *mut libc::c_void,
        iv as *const libc::c_void,
        8 as libc::c_int as size_t,
    );
    let mut n: size_t = in_len / 8 as libc::c_int as size_t;
    let mut j: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while j < kBound {
        let mut i: size_t = 1 as libc::c_int as size_t;
        while i <= n {
            OPENSSL_memcpy(
                A.as_mut_ptr().offset(8 as libc::c_int as isize) as *mut libc::c_void,
                out.offset((8 as libc::c_int as size_t * i) as isize)
                    as *const libc::c_void,
                8 as libc::c_int as size_t,
            );
            AES_encrypt(A.as_mut_ptr(), A.as_mut_ptr(), key);
            let mut t: uint32_t = (n * j as size_t).wrapping_add(i) as uint32_t;
            A[7 as libc::c_int
                as usize] = (A[7 as libc::c_int as usize] as uint32_t
                ^ t & 0xff as libc::c_int as uint32_t) as uint8_t;
            A[6 as libc::c_int
                as usize] = (A[6 as libc::c_int as usize] as uint32_t
                ^ t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t) as uint8_t;
            A[5 as libc::c_int
                as usize] = (A[5 as libc::c_int as usize] as uint32_t
                ^ t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t) as uint8_t;
            A[4 as libc::c_int
                as usize] = (A[4 as libc::c_int as usize] as uint32_t
                ^ t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t) as uint8_t;
            OPENSSL_memcpy(
                out.offset((8 as libc::c_int as size_t * i) as isize)
                    as *mut libc::c_void,
                A.as_mut_ptr().offset(8 as libc::c_int as isize) as *const libc::c_void,
                8 as libc::c_int as size_t,
            );
            i = i.wrapping_add(1);
            i;
        }
        j = j.wrapping_add(1);
        j;
    }
    OPENSSL_memcpy(
        out as *mut libc::c_void,
        A.as_mut_ptr() as *const libc::c_void,
        8 as libc::c_int as size_t,
    );
    FIPS_service_indicator_update_state();
    return in_len as libc::c_int + 8 as libc::c_int;
}
unsafe extern "C" fn aes_unwrap_key_inner(
    mut key: *const AES_KEY,
    mut out: *mut uint8_t,
    mut out_iv: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
) -> libc::c_int {
    if in_len > 2147483647 as libc::c_int as size_t
        || in_len < 24 as libc::c_int as size_t
        || in_len % 8 as libc::c_int as size_t != 0 as libc::c_int as size_t
    {
        return 0 as libc::c_int;
    }
    let mut A: [uint8_t; 16] = [0; 16];
    OPENSSL_memcpy(
        A.as_mut_ptr() as *mut libc::c_void,
        in_0 as *const libc::c_void,
        8 as libc::c_int as size_t,
    );
    OPENSSL_memmove(
        out as *mut libc::c_void,
        in_0.offset(8 as libc::c_int as isize) as *const libc::c_void,
        in_len.wrapping_sub(8 as libc::c_int as size_t),
    );
    let mut n: size_t = (in_len / 8 as libc::c_int as size_t)
        .wrapping_sub(1 as libc::c_int as size_t);
    let mut j: libc::c_uint = kBound.wrapping_sub(1 as libc::c_int as libc::c_uint);
    while j < kBound {
        let mut i: size_t = n;
        while i > 0 as libc::c_int as size_t {
            let mut t: uint32_t = (n * j as size_t).wrapping_add(i) as uint32_t;
            A[7 as libc::c_int
                as usize] = (A[7 as libc::c_int as usize] as uint32_t
                ^ t & 0xff as libc::c_int as uint32_t) as uint8_t;
            A[6 as libc::c_int
                as usize] = (A[6 as libc::c_int as usize] as uint32_t
                ^ t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t) as uint8_t;
            A[5 as libc::c_int
                as usize] = (A[5 as libc::c_int as usize] as uint32_t
                ^ t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t) as uint8_t;
            A[4 as libc::c_int
                as usize] = (A[4 as libc::c_int as usize] as uint32_t
                ^ t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t) as uint8_t;
            OPENSSL_memcpy(
                A.as_mut_ptr().offset(8 as libc::c_int as isize) as *mut libc::c_void,
                out
                    .offset(
                        (8 as libc::c_int as size_t
                            * i.wrapping_sub(1 as libc::c_int as size_t)) as isize,
                    ) as *const libc::c_void,
                8 as libc::c_int as size_t,
            );
            AES_decrypt(A.as_mut_ptr(), A.as_mut_ptr(), key);
            OPENSSL_memcpy(
                out
                    .offset(
                        (8 as libc::c_int as size_t
                            * i.wrapping_sub(1 as libc::c_int as size_t)) as isize,
                    ) as *mut libc::c_void,
                A.as_mut_ptr().offset(8 as libc::c_int as isize) as *const libc::c_void,
                8 as libc::c_int as size_t,
            );
            i = i.wrapping_sub(1);
            i;
        }
        j = j.wrapping_sub(1);
        j;
    }
    memcpy(
        out_iv as *mut libc::c_void,
        A.as_mut_ptr() as *const libc::c_void,
        8 as libc::c_int as libc::c_ulong,
    );
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn AES_unwrap_key(
    mut key: *const AES_KEY,
    mut iv: *const uint8_t,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
) -> libc::c_int {
    let mut calculated_iv: [uint8_t; 8] = [0; 8];
    if aes_unwrap_key_inner(key, out, calculated_iv.as_mut_ptr(), in_0, in_len) == 0 {
        return -(1 as libc::c_int);
    }
    if iv.is_null() {
        iv = kDefaultIV.as_ptr();
    }
    if CRYPTO_memcmp(
        calculated_iv.as_mut_ptr() as *const libc::c_void,
        iv as *const libc::c_void,
        8 as libc::c_int as size_t,
    ) != 0 as libc::c_int
    {
        return -(1 as libc::c_int);
    }
    FIPS_service_indicator_update_state();
    return in_len as libc::c_int - 8 as libc::c_int;
}
static mut kPaddingConstant: [uint8_t; 4] = [
    0xa6 as libc::c_int as uint8_t,
    0x59 as libc::c_int as uint8_t,
    0x59 as libc::c_int as uint8_t,
    0xa6 as libc::c_int as uint8_t,
];
#[no_mangle]
pub unsafe extern "C" fn AES_wrap_key_padded(
    mut key: *const AES_KEY,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
    mut max_out: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
) -> libc::c_int {
    let mut block: [uint8_t; 16] = [0; 16];
    let mut padded_in: *mut uint8_t = 0 as *mut uint8_t;
    let mut out_length: libc::c_int = 0;
    FIPS_service_indicator_lock_state();
    let in_len64: uint64_t = in_len;
    let padded_len: size_t = in_len.wrapping_add(7 as libc::c_int as size_t)
        & !(7 as libc::c_int) as size_t;
    let mut ret: libc::c_int = 0 as libc::c_int;
    *out_len = 0 as libc::c_int as size_t;
    if !(in_len == 0 as libc::c_int as size_t
        || in_len64 > 0xffffffff as libc::c_uint as uint64_t
        || in_len.wrapping_add(7 as libc::c_int as size_t) < in_len
        || padded_len.wrapping_add(8 as libc::c_int as size_t) < padded_len
        || max_out < padded_len.wrapping_add(8 as libc::c_int as size_t))
    {
        block = [0; 16];
        memcpy(
            block.as_mut_ptr() as *mut libc::c_void,
            kPaddingConstant.as_ptr() as *const libc::c_void,
            ::core::mem::size_of::<[uint8_t; 4]>() as libc::c_ulong,
        );
        CRYPTO_store_u32_be(
            block.as_mut_ptr().offset(4 as libc::c_int as isize) as *mut libc::c_void,
            in_len as uint32_t,
        );
        if in_len <= 8 as libc::c_int as size_t {
            memset(
                block.as_mut_ptr().offset(8 as libc::c_int as isize)
                    as *mut libc::c_void,
                0 as libc::c_int,
                8 as libc::c_int as libc::c_ulong,
            );
            memcpy(
                block.as_mut_ptr().offset(8 as libc::c_int as isize)
                    as *mut libc::c_void,
                in_0 as *const libc::c_void,
                in_len,
            );
            AES_encrypt(block.as_mut_ptr(), out, key);
            *out_len = 16 as libc::c_int as size_t;
            ret = 1 as libc::c_int;
        } else {
            padded_in = OPENSSL_malloc(padded_len) as *mut uint8_t;
            if !padded_in.is_null() {
                if padded_len >= 8 as libc::c_int as size_t {} else {
                    __assert_fail(
                        b"padded_len >= 8\0" as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/aes/key_wrap.c\0"
                            as *const u8 as *const libc::c_char,
                        197 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 95],
                            &[libc::c_char; 95],
                        >(
                            b"int AES_wrap_key_padded(const AES_KEY *, uint8_t *, size_t *, size_t, const uint8_t *, size_t)\0",
                        ))
                            .as_ptr(),
                    );
                }
                'c_2142: {
                    if padded_len >= 8 as libc::c_int as size_t {} else {
                        __assert_fail(
                            b"padded_len >= 8\0" as *const u8 as *const libc::c_char,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/aes/key_wrap.c\0"
                                as *const u8 as *const libc::c_char,
                            197 as libc::c_int as libc::c_uint,
                            (*::core::mem::transmute::<
                                &[u8; 95],
                                &[libc::c_char; 95],
                            >(
                                b"int AES_wrap_key_padded(const AES_KEY *, uint8_t *, size_t *, size_t, const uint8_t *, size_t)\0",
                            ))
                                .as_ptr(),
                        );
                    }
                };
                memset(
                    padded_in
                        .offset(padded_len as isize)
                        .offset(-(8 as libc::c_int as isize)) as *mut libc::c_void,
                    0 as libc::c_int,
                    8 as libc::c_int as libc::c_ulong,
                );
                memcpy(
                    padded_in as *mut libc::c_void,
                    in_0 as *const libc::c_void,
                    in_len,
                );
                out_length = AES_wrap_key(
                    key,
                    block.as_mut_ptr(),
                    out,
                    padded_in,
                    padded_len,
                );
                OPENSSL_free(padded_in as *mut libc::c_void);
                if !(out_length < 0 as libc::c_int) {
                    *out_len = out_length as size_t;
                    ret = 1 as libc::c_int;
                }
            }
        }
    }
    FIPS_service_indicator_unlock_state();
    if ret != 0 {
        FIPS_service_indicator_update_state();
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn AES_unwrap_key_padded(
    mut key: *const AES_KEY,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
    mut max_out: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
) -> libc::c_int {
    *out_len = 0 as libc::c_int as size_t;
    if in_len < 16 as libc::c_int as size_t
        || max_out < in_len.wrapping_sub(8 as libc::c_int as size_t)
    {
        return 0 as libc::c_int;
    }
    let mut iv: [uint8_t; 8] = [0; 8];
    if in_len == 16 as libc::c_int as size_t {
        let mut block: [uint8_t; 16] = [0; 16];
        AES_decrypt(in_0, block.as_mut_ptr(), key);
        memcpy(
            iv.as_mut_ptr() as *mut libc::c_void,
            block.as_mut_ptr() as *const libc::c_void,
            ::core::mem::size_of::<[uint8_t; 8]>() as libc::c_ulong,
        );
        memcpy(
            out as *mut libc::c_void,
            block.as_mut_ptr().offset(8 as libc::c_int as isize) as *const libc::c_void,
            8 as libc::c_int as libc::c_ulong,
        );
    } else if aes_unwrap_key_inner(key, out, iv.as_mut_ptr(), in_0, in_len) == 0 {
        return 0 as libc::c_int
    }
    if in_len % 8 as libc::c_int as size_t == 0 as libc::c_int as size_t {} else {
        __assert_fail(
            b"in_len % 8 == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/aes/key_wrap.c\0"
                as *const u8 as *const libc::c_char,
            232 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 97],
                &[libc::c_char; 97],
            >(
                b"int AES_unwrap_key_padded(const AES_KEY *, uint8_t *, size_t *, size_t, const uint8_t *, size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2732: {
        if in_len % 8 as libc::c_int as size_t == 0 as libc::c_int as size_t {} else {
            __assert_fail(
                b"in_len % 8 == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/aes/key_wrap.c\0"
                    as *const u8 as *const libc::c_char,
                232 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 97],
                    &[libc::c_char; 97],
                >(
                    b"int AES_unwrap_key_padded(const AES_KEY *, uint8_t *, size_t *, size_t, const uint8_t *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut ok: crypto_word_t = constant_time_eq_int(
        CRYPTO_memcmp(
            iv.as_mut_ptr() as *const libc::c_void,
            kPaddingConstant.as_ptr() as *const libc::c_void,
            ::core::mem::size_of::<[uint8_t; 4]>() as libc::c_ulong,
        ),
        0 as libc::c_int,
    );
    let claimed_len: size_t = CRYPTO_load_u32_be(
        iv.as_mut_ptr().offset(4 as libc::c_int as isize) as *const libc::c_void,
    ) as size_t;
    ok &= !constant_time_is_zero_w(claimed_len);
    ok
        &= constant_time_eq_w(
            claimed_len.wrapping_sub(1 as libc::c_int as size_t) >> 3 as libc::c_int,
            in_len.wrapping_sub(9 as libc::c_int as size_t) >> 3 as libc::c_int,
        );
    let mut i: size_t = in_len.wrapping_sub(15 as libc::c_int as size_t);
    while i < in_len.wrapping_sub(8 as libc::c_int as size_t) {
        ok
            &= constant_time_is_zero_w(
                (constant_time_ge_8(i, claimed_len) as libc::c_int
                    & *out.offset(i as isize) as libc::c_int) as crypto_word_t,
            );
        i = i.wrapping_add(1);
        i;
    }
    *out_len = constant_time_select_w(
        ok,
        claimed_len,
        0 as libc::c_int as crypto_word_t,
    );
    let ret: libc::c_int = (ok & 1 as libc::c_int as crypto_word_t) as libc::c_int;
    if ret != 0 {
        FIPS_service_indicator_update_state();
    }
    return ret;
}
