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
    fn CRYPTO_ghash_init(
        out_mult: *mut gmult_func,
        out_hash: *mut ghash_func,
        out_table: *mut u128_0,
        out_is_avx: *mut libc::c_int,
        gcm_key: *const uint8_t,
    );
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint64_t = __uint64_t;
pub type crypto_word_t = uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct u128_0 {
    pub hi: uint64_t,
    pub lo: uint64_t,
}
pub type gmult_func = Option::<unsafe extern "C" fn(*mut uint8_t, *const u128_0) -> ()>;
pub type ghash_func = Option::<
    unsafe extern "C" fn(*mut uint8_t, *const u128_0, *const uint8_t, size_t) -> (),
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct polyval_ctx {
    pub S: [uint8_t; 16],
    pub Htable: [u128_0; 16],
    pub gmult: gmult_func,
    pub ghash: ghash_func,
}
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
unsafe extern "C" fn constant_time_select_w(
    mut mask: crypto_word_t,
    mut a: crypto_word_t,
    mut b: crypto_word_t,
) -> crypto_word_t {
    return value_barrier_w(mask) & a | value_barrier_w(!mask) & b;
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
unsafe extern "C" fn CRYPTO_load_u64_le(mut in_0: *const libc::c_void) -> uint64_t {
    let mut v: uint64_t = 0;
    OPENSSL_memcpy(
        &mut v as *mut uint64_t as *mut libc::c_void,
        in_0,
        ::core::mem::size_of::<uint64_t>() as libc::c_ulong,
    );
    return v;
}
#[inline]
unsafe extern "C" fn CRYPTO_store_u64_le(mut out: *mut libc::c_void, mut v: uint64_t) {
    OPENSSL_memcpy(
        out,
        &mut v as *mut uint64_t as *const libc::c_void,
        ::core::mem::size_of::<uint64_t>() as libc::c_ulong,
    );
}
unsafe extern "C" fn byte_reverse(mut b: *mut uint8_t) {
    let mut hi: uint64_t = CRYPTO_load_u64_le(b as *const libc::c_void);
    let mut lo: uint64_t = CRYPTO_load_u64_le(
        b.offset(8 as libc::c_int as isize) as *const libc::c_void,
    );
    CRYPTO_store_u64_le(b as *mut libc::c_void, CRYPTO_bswap8(lo));
    CRYPTO_store_u64_le(
        b.offset(8 as libc::c_int as isize) as *mut libc::c_void,
        CRYPTO_bswap8(hi),
    );
}
unsafe extern "C" fn reverse_and_mulX_ghash(mut b: *mut uint8_t) {
    let mut hi: uint64_t = CRYPTO_load_u64_le(b as *const libc::c_void);
    let mut lo: uint64_t = CRYPTO_load_u64_le(
        b.offset(8 as libc::c_int as isize) as *const libc::c_void,
    );
    let carry: crypto_word_t = constant_time_eq_w(
        hi & 1 as libc::c_int as uint64_t,
        1 as libc::c_int as crypto_word_t,
    );
    hi >>= 1 as libc::c_int;
    hi |= lo << 63 as libc::c_int;
    lo >>= 1 as libc::c_int;
    lo
        ^= constant_time_select_w(
            carry,
            0xe1 as libc::c_int as crypto_word_t,
            0 as libc::c_int as crypto_word_t,
        ) << 56 as libc::c_int;
    CRYPTO_store_u64_le(b as *mut libc::c_void, CRYPTO_bswap8(lo));
    CRYPTO_store_u64_le(
        b.offset(8 as libc::c_int as isize) as *mut libc::c_void,
        CRYPTO_bswap8(hi),
    );
}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_POLYVAL_init(
    mut ctx: *mut polyval_ctx,
    mut key: *const uint8_t,
) {
    let mut H: [uint8_t; 16] = [0; 16];
    OPENSSL_memcpy(
        H.as_mut_ptr() as *mut libc::c_void,
        key as *const libc::c_void,
        16 as libc::c_int as size_t,
    );
    reverse_and_mulX_ghash(H.as_mut_ptr());
    let mut is_avx: libc::c_int = 0;
    CRYPTO_ghash_init(
        &mut (*ctx).gmult,
        &mut (*ctx).ghash,
        ((*ctx).Htable).as_mut_ptr(),
        &mut is_avx,
        H.as_mut_ptr() as *const uint8_t,
    );
    OPENSSL_memset(
        &mut (*ctx).S as *mut [uint8_t; 16] as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong,
    );
}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_POLYVAL_update_blocks(
    mut ctx: *mut polyval_ctx,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
) {
    if in_len & 15 as libc::c_int as size_t == 0 as libc::c_int as size_t {} else {
        __assert_fail(
            b"(in_len & 15) == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/polyval.c\0"
                as *const u8 as *const libc::c_char,
            66 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 81],
                &[libc::c_char; 81],
            >(
                b"void CRYPTO_POLYVAL_update_blocks(struct polyval_ctx *, const uint8_t *, size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_7305: {
        if in_len & 15 as libc::c_int as size_t == 0 as libc::c_int as size_t {} else {
            __assert_fail(
                b"(in_len & 15) == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/polyval.c\0"
                    as *const u8 as *const libc::c_char,
                66 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 81],
                    &[libc::c_char; 81],
                >(
                    b"void CRYPTO_POLYVAL_update_blocks(struct polyval_ctx *, const uint8_t *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut buf: [uint8_t; 512] = [0; 512];
    while in_len > 0 as libc::c_int as size_t {
        let mut todo: size_t = in_len;
        if todo > ::core::mem::size_of::<[uint8_t; 512]>() as libc::c_ulong {
            todo = ::core::mem::size_of::<[uint8_t; 512]>() as libc::c_ulong;
        }
        OPENSSL_memcpy(
            buf.as_mut_ptr() as *mut libc::c_void,
            in_0 as *const libc::c_void,
            todo,
        );
        in_0 = in_0.offset(todo as isize);
        in_len = in_len.wrapping_sub(todo);
        let mut blocks: size_t = todo / 16 as libc::c_int as size_t;
        let mut i: size_t = 0 as libc::c_int as size_t;
        while i < blocks {
            byte_reverse(
                buf.as_mut_ptr().offset((16 as libc::c_int as size_t * i) as isize),
            );
            i = i.wrapping_add(1);
            i;
        }
        ((*ctx).ghash)
            .expect(
                "non-null function pointer",
            )(
            ((*ctx).S).as_mut_ptr(),
            ((*ctx).Htable).as_mut_ptr() as *const u128_0,
            buf.as_mut_ptr(),
            todo,
        );
    }
}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_POLYVAL_finish(
    mut ctx: *const polyval_ctx,
    mut out: *mut uint8_t,
) {
    OPENSSL_memcpy(
        out as *mut libc::c_void,
        &(*ctx).S as *const [uint8_t; 16] as *const libc::c_void,
        16 as libc::c_int as size_t,
    );
    byte_reverse(out);
}
