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
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uintptr_t = libc::c_ulong;
#[inline]
unsafe extern "C" fn buffers_alias(
    mut a: *const uint8_t,
    mut a_len: size_t,
    mut b: *const uint8_t,
    mut b_len: size_t,
) -> libc::c_int {
    let mut a_u: uintptr_t = a as uintptr_t;
    let mut b_u: uintptr_t = b as uintptr_t;
    return (a_u.wrapping_add(a_len) > b_u && b_u.wrapping_add(b_len) > a_u)
        as libc::c_int;
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
unsafe extern "C" fn CRYPTO_load_u32_le(mut in_0: *const libc::c_void) -> uint32_t {
    let mut v: uint32_t = 0;
    OPENSSL_memcpy(
        &mut v as *mut uint32_t as *mut libc::c_void,
        in_0,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
    return v;
}
#[inline]
unsafe extern "C" fn CRYPTO_store_u32_le(mut out: *mut libc::c_void, mut v: uint32_t) {
    OPENSSL_memcpy(
        out,
        &mut v as *mut uint32_t as *const libc::c_void,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
}
#[inline]
unsafe extern "C" fn CRYPTO_rotl_u32(
    mut value: uint32_t,
    mut shift: libc::c_int,
) -> uint32_t {
    return value << shift | value >> (-shift & 31 as libc::c_int);
}
static mut sigma_words: [uint32_t; 4] = [
    0x61707865 as libc::c_int as uint32_t,
    0x3320646e as libc::c_int as uint32_t,
    0x79622d32 as libc::c_int as uint32_t,
    0x6b206574 as libc::c_int as uint32_t,
];
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_hchacha20(
    mut out: *mut uint8_t,
    mut key: *const uint8_t,
    mut nonce: *const uint8_t,
) {
    let mut x: [uint32_t; 16] = [0; 16];
    OPENSSL_memcpy(
        x.as_mut_ptr() as *mut libc::c_void,
        sigma_words.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint32_t; 4]>() as libc::c_ulong,
    );
    OPENSSL_memcpy(
        &mut *x.as_mut_ptr().offset(4 as libc::c_int as isize) as *mut uint32_t
            as *mut libc::c_void,
        key as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
    OPENSSL_memcpy(
        &mut *x.as_mut_ptr().offset(12 as libc::c_int as isize) as *mut uint32_t
            as *mut libc::c_void,
        nonce as *const libc::c_void,
        16 as libc::c_int as size_t,
    );
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < 20 as libc::c_int as size_t {
        x[0 as libc::c_int
            as usize] = (x[0 as libc::c_int as usize])
            .wrapping_add(x[4 as libc::c_int as usize]);
        x[12 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[12 as libc::c_int as usize] ^ x[0 as libc::c_int as usize],
            16 as libc::c_int,
        );
        x[8 as libc::c_int
            as usize] = (x[8 as libc::c_int as usize])
            .wrapping_add(x[12 as libc::c_int as usize]);
        x[4 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[4 as libc::c_int as usize] ^ x[8 as libc::c_int as usize],
            12 as libc::c_int,
        );
        x[0 as libc::c_int
            as usize] = (x[0 as libc::c_int as usize])
            .wrapping_add(x[4 as libc::c_int as usize]);
        x[12 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[12 as libc::c_int as usize] ^ x[0 as libc::c_int as usize],
            8 as libc::c_int,
        );
        x[8 as libc::c_int
            as usize] = (x[8 as libc::c_int as usize])
            .wrapping_add(x[12 as libc::c_int as usize]);
        x[4 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[4 as libc::c_int as usize] ^ x[8 as libc::c_int as usize],
            7 as libc::c_int,
        );
        x[1 as libc::c_int
            as usize] = (x[1 as libc::c_int as usize])
            .wrapping_add(x[5 as libc::c_int as usize]);
        x[13 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[13 as libc::c_int as usize] ^ x[1 as libc::c_int as usize],
            16 as libc::c_int,
        );
        x[9 as libc::c_int
            as usize] = (x[9 as libc::c_int as usize])
            .wrapping_add(x[13 as libc::c_int as usize]);
        x[5 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[5 as libc::c_int as usize] ^ x[9 as libc::c_int as usize],
            12 as libc::c_int,
        );
        x[1 as libc::c_int
            as usize] = (x[1 as libc::c_int as usize])
            .wrapping_add(x[5 as libc::c_int as usize]);
        x[13 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[13 as libc::c_int as usize] ^ x[1 as libc::c_int as usize],
            8 as libc::c_int,
        );
        x[9 as libc::c_int
            as usize] = (x[9 as libc::c_int as usize])
            .wrapping_add(x[13 as libc::c_int as usize]);
        x[5 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[5 as libc::c_int as usize] ^ x[9 as libc::c_int as usize],
            7 as libc::c_int,
        );
        x[2 as libc::c_int
            as usize] = (x[2 as libc::c_int as usize])
            .wrapping_add(x[6 as libc::c_int as usize]);
        x[14 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[14 as libc::c_int as usize] ^ x[2 as libc::c_int as usize],
            16 as libc::c_int,
        );
        x[10 as libc::c_int
            as usize] = (x[10 as libc::c_int as usize])
            .wrapping_add(x[14 as libc::c_int as usize]);
        x[6 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[6 as libc::c_int as usize] ^ x[10 as libc::c_int as usize],
            12 as libc::c_int,
        );
        x[2 as libc::c_int
            as usize] = (x[2 as libc::c_int as usize])
            .wrapping_add(x[6 as libc::c_int as usize]);
        x[14 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[14 as libc::c_int as usize] ^ x[2 as libc::c_int as usize],
            8 as libc::c_int,
        );
        x[10 as libc::c_int
            as usize] = (x[10 as libc::c_int as usize])
            .wrapping_add(x[14 as libc::c_int as usize]);
        x[6 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[6 as libc::c_int as usize] ^ x[10 as libc::c_int as usize],
            7 as libc::c_int,
        );
        x[3 as libc::c_int
            as usize] = (x[3 as libc::c_int as usize])
            .wrapping_add(x[7 as libc::c_int as usize]);
        x[15 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[15 as libc::c_int as usize] ^ x[3 as libc::c_int as usize],
            16 as libc::c_int,
        );
        x[11 as libc::c_int
            as usize] = (x[11 as libc::c_int as usize])
            .wrapping_add(x[15 as libc::c_int as usize]);
        x[7 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[7 as libc::c_int as usize] ^ x[11 as libc::c_int as usize],
            12 as libc::c_int,
        );
        x[3 as libc::c_int
            as usize] = (x[3 as libc::c_int as usize])
            .wrapping_add(x[7 as libc::c_int as usize]);
        x[15 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[15 as libc::c_int as usize] ^ x[3 as libc::c_int as usize],
            8 as libc::c_int,
        );
        x[11 as libc::c_int
            as usize] = (x[11 as libc::c_int as usize])
            .wrapping_add(x[15 as libc::c_int as usize]);
        x[7 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[7 as libc::c_int as usize] ^ x[11 as libc::c_int as usize],
            7 as libc::c_int,
        );
        x[0 as libc::c_int
            as usize] = (x[0 as libc::c_int as usize])
            .wrapping_add(x[5 as libc::c_int as usize]);
        x[15 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[15 as libc::c_int as usize] ^ x[0 as libc::c_int as usize],
            16 as libc::c_int,
        );
        x[10 as libc::c_int
            as usize] = (x[10 as libc::c_int as usize])
            .wrapping_add(x[15 as libc::c_int as usize]);
        x[5 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[5 as libc::c_int as usize] ^ x[10 as libc::c_int as usize],
            12 as libc::c_int,
        );
        x[0 as libc::c_int
            as usize] = (x[0 as libc::c_int as usize])
            .wrapping_add(x[5 as libc::c_int as usize]);
        x[15 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[15 as libc::c_int as usize] ^ x[0 as libc::c_int as usize],
            8 as libc::c_int,
        );
        x[10 as libc::c_int
            as usize] = (x[10 as libc::c_int as usize])
            .wrapping_add(x[15 as libc::c_int as usize]);
        x[5 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[5 as libc::c_int as usize] ^ x[10 as libc::c_int as usize],
            7 as libc::c_int,
        );
        x[1 as libc::c_int
            as usize] = (x[1 as libc::c_int as usize])
            .wrapping_add(x[6 as libc::c_int as usize]);
        x[12 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[12 as libc::c_int as usize] ^ x[1 as libc::c_int as usize],
            16 as libc::c_int,
        );
        x[11 as libc::c_int
            as usize] = (x[11 as libc::c_int as usize])
            .wrapping_add(x[12 as libc::c_int as usize]);
        x[6 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[6 as libc::c_int as usize] ^ x[11 as libc::c_int as usize],
            12 as libc::c_int,
        );
        x[1 as libc::c_int
            as usize] = (x[1 as libc::c_int as usize])
            .wrapping_add(x[6 as libc::c_int as usize]);
        x[12 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[12 as libc::c_int as usize] ^ x[1 as libc::c_int as usize],
            8 as libc::c_int,
        );
        x[11 as libc::c_int
            as usize] = (x[11 as libc::c_int as usize])
            .wrapping_add(x[12 as libc::c_int as usize]);
        x[6 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[6 as libc::c_int as usize] ^ x[11 as libc::c_int as usize],
            7 as libc::c_int,
        );
        x[2 as libc::c_int
            as usize] = (x[2 as libc::c_int as usize])
            .wrapping_add(x[7 as libc::c_int as usize]);
        x[13 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[13 as libc::c_int as usize] ^ x[2 as libc::c_int as usize],
            16 as libc::c_int,
        );
        x[8 as libc::c_int
            as usize] = (x[8 as libc::c_int as usize])
            .wrapping_add(x[13 as libc::c_int as usize]);
        x[7 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[7 as libc::c_int as usize] ^ x[8 as libc::c_int as usize],
            12 as libc::c_int,
        );
        x[2 as libc::c_int
            as usize] = (x[2 as libc::c_int as usize])
            .wrapping_add(x[7 as libc::c_int as usize]);
        x[13 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[13 as libc::c_int as usize] ^ x[2 as libc::c_int as usize],
            8 as libc::c_int,
        );
        x[8 as libc::c_int
            as usize] = (x[8 as libc::c_int as usize])
            .wrapping_add(x[13 as libc::c_int as usize]);
        x[7 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[7 as libc::c_int as usize] ^ x[8 as libc::c_int as usize],
            7 as libc::c_int,
        );
        x[3 as libc::c_int
            as usize] = (x[3 as libc::c_int as usize])
            .wrapping_add(x[4 as libc::c_int as usize]);
        x[14 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[14 as libc::c_int as usize] ^ x[3 as libc::c_int as usize],
            16 as libc::c_int,
        );
        x[9 as libc::c_int
            as usize] = (x[9 as libc::c_int as usize])
            .wrapping_add(x[14 as libc::c_int as usize]);
        x[4 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[4 as libc::c_int as usize] ^ x[9 as libc::c_int as usize],
            12 as libc::c_int,
        );
        x[3 as libc::c_int
            as usize] = (x[3 as libc::c_int as usize])
            .wrapping_add(x[4 as libc::c_int as usize]);
        x[14 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[14 as libc::c_int as usize] ^ x[3 as libc::c_int as usize],
            8 as libc::c_int,
        );
        x[9 as libc::c_int
            as usize] = (x[9 as libc::c_int as usize])
            .wrapping_add(x[14 as libc::c_int as usize]);
        x[4 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[4 as libc::c_int as usize] ^ x[9 as libc::c_int as usize],
            7 as libc::c_int,
        );
        i = i.wrapping_add(2 as libc::c_int as size_t);
    }
    OPENSSL_memcpy(
        out as *mut libc::c_void,
        &mut *x.as_mut_ptr().offset(0 as libc::c_int as isize) as *mut uint32_t
            as *const libc::c_void,
        (::core::mem::size_of::<uint32_t>() as libc::c_ulong)
            .wrapping_mul(4 as libc::c_int as libc::c_ulong),
    );
    OPENSSL_memcpy(
        &mut *out.offset(16 as libc::c_int as isize) as *mut uint8_t
            as *mut libc::c_void,
        &mut *x.as_mut_ptr().offset(12 as libc::c_int as isize) as *mut uint32_t
            as *const libc::c_void,
        (::core::mem::size_of::<uint32_t>() as libc::c_ulong)
            .wrapping_mul(4 as libc::c_int as libc::c_ulong),
    );
}
unsafe extern "C" fn chacha_core(mut output: *mut uint8_t, mut input: *const uint32_t) {
    let mut x: [uint32_t; 16] = [0; 16];
    let mut i: libc::c_int = 0;
    OPENSSL_memcpy(
        x.as_mut_ptr() as *mut libc::c_void,
        input as *const libc::c_void,
        (::core::mem::size_of::<uint32_t>() as libc::c_ulong)
            .wrapping_mul(16 as libc::c_int as libc::c_ulong),
    );
    i = 20 as libc::c_int;
    while i > 0 as libc::c_int {
        x[0 as libc::c_int
            as usize] = (x[0 as libc::c_int as usize])
            .wrapping_add(x[4 as libc::c_int as usize]);
        x[12 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[12 as libc::c_int as usize] ^ x[0 as libc::c_int as usize],
            16 as libc::c_int,
        );
        x[8 as libc::c_int
            as usize] = (x[8 as libc::c_int as usize])
            .wrapping_add(x[12 as libc::c_int as usize]);
        x[4 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[4 as libc::c_int as usize] ^ x[8 as libc::c_int as usize],
            12 as libc::c_int,
        );
        x[0 as libc::c_int
            as usize] = (x[0 as libc::c_int as usize])
            .wrapping_add(x[4 as libc::c_int as usize]);
        x[12 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[12 as libc::c_int as usize] ^ x[0 as libc::c_int as usize],
            8 as libc::c_int,
        );
        x[8 as libc::c_int
            as usize] = (x[8 as libc::c_int as usize])
            .wrapping_add(x[12 as libc::c_int as usize]);
        x[4 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[4 as libc::c_int as usize] ^ x[8 as libc::c_int as usize],
            7 as libc::c_int,
        );
        x[1 as libc::c_int
            as usize] = (x[1 as libc::c_int as usize])
            .wrapping_add(x[5 as libc::c_int as usize]);
        x[13 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[13 as libc::c_int as usize] ^ x[1 as libc::c_int as usize],
            16 as libc::c_int,
        );
        x[9 as libc::c_int
            as usize] = (x[9 as libc::c_int as usize])
            .wrapping_add(x[13 as libc::c_int as usize]);
        x[5 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[5 as libc::c_int as usize] ^ x[9 as libc::c_int as usize],
            12 as libc::c_int,
        );
        x[1 as libc::c_int
            as usize] = (x[1 as libc::c_int as usize])
            .wrapping_add(x[5 as libc::c_int as usize]);
        x[13 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[13 as libc::c_int as usize] ^ x[1 as libc::c_int as usize],
            8 as libc::c_int,
        );
        x[9 as libc::c_int
            as usize] = (x[9 as libc::c_int as usize])
            .wrapping_add(x[13 as libc::c_int as usize]);
        x[5 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[5 as libc::c_int as usize] ^ x[9 as libc::c_int as usize],
            7 as libc::c_int,
        );
        x[2 as libc::c_int
            as usize] = (x[2 as libc::c_int as usize])
            .wrapping_add(x[6 as libc::c_int as usize]);
        x[14 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[14 as libc::c_int as usize] ^ x[2 as libc::c_int as usize],
            16 as libc::c_int,
        );
        x[10 as libc::c_int
            as usize] = (x[10 as libc::c_int as usize])
            .wrapping_add(x[14 as libc::c_int as usize]);
        x[6 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[6 as libc::c_int as usize] ^ x[10 as libc::c_int as usize],
            12 as libc::c_int,
        );
        x[2 as libc::c_int
            as usize] = (x[2 as libc::c_int as usize])
            .wrapping_add(x[6 as libc::c_int as usize]);
        x[14 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[14 as libc::c_int as usize] ^ x[2 as libc::c_int as usize],
            8 as libc::c_int,
        );
        x[10 as libc::c_int
            as usize] = (x[10 as libc::c_int as usize])
            .wrapping_add(x[14 as libc::c_int as usize]);
        x[6 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[6 as libc::c_int as usize] ^ x[10 as libc::c_int as usize],
            7 as libc::c_int,
        );
        x[3 as libc::c_int
            as usize] = (x[3 as libc::c_int as usize])
            .wrapping_add(x[7 as libc::c_int as usize]);
        x[15 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[15 as libc::c_int as usize] ^ x[3 as libc::c_int as usize],
            16 as libc::c_int,
        );
        x[11 as libc::c_int
            as usize] = (x[11 as libc::c_int as usize])
            .wrapping_add(x[15 as libc::c_int as usize]);
        x[7 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[7 as libc::c_int as usize] ^ x[11 as libc::c_int as usize],
            12 as libc::c_int,
        );
        x[3 as libc::c_int
            as usize] = (x[3 as libc::c_int as usize])
            .wrapping_add(x[7 as libc::c_int as usize]);
        x[15 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[15 as libc::c_int as usize] ^ x[3 as libc::c_int as usize],
            8 as libc::c_int,
        );
        x[11 as libc::c_int
            as usize] = (x[11 as libc::c_int as usize])
            .wrapping_add(x[15 as libc::c_int as usize]);
        x[7 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[7 as libc::c_int as usize] ^ x[11 as libc::c_int as usize],
            7 as libc::c_int,
        );
        x[0 as libc::c_int
            as usize] = (x[0 as libc::c_int as usize])
            .wrapping_add(x[5 as libc::c_int as usize]);
        x[15 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[15 as libc::c_int as usize] ^ x[0 as libc::c_int as usize],
            16 as libc::c_int,
        );
        x[10 as libc::c_int
            as usize] = (x[10 as libc::c_int as usize])
            .wrapping_add(x[15 as libc::c_int as usize]);
        x[5 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[5 as libc::c_int as usize] ^ x[10 as libc::c_int as usize],
            12 as libc::c_int,
        );
        x[0 as libc::c_int
            as usize] = (x[0 as libc::c_int as usize])
            .wrapping_add(x[5 as libc::c_int as usize]);
        x[15 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[15 as libc::c_int as usize] ^ x[0 as libc::c_int as usize],
            8 as libc::c_int,
        );
        x[10 as libc::c_int
            as usize] = (x[10 as libc::c_int as usize])
            .wrapping_add(x[15 as libc::c_int as usize]);
        x[5 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[5 as libc::c_int as usize] ^ x[10 as libc::c_int as usize],
            7 as libc::c_int,
        );
        x[1 as libc::c_int
            as usize] = (x[1 as libc::c_int as usize])
            .wrapping_add(x[6 as libc::c_int as usize]);
        x[12 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[12 as libc::c_int as usize] ^ x[1 as libc::c_int as usize],
            16 as libc::c_int,
        );
        x[11 as libc::c_int
            as usize] = (x[11 as libc::c_int as usize])
            .wrapping_add(x[12 as libc::c_int as usize]);
        x[6 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[6 as libc::c_int as usize] ^ x[11 as libc::c_int as usize],
            12 as libc::c_int,
        );
        x[1 as libc::c_int
            as usize] = (x[1 as libc::c_int as usize])
            .wrapping_add(x[6 as libc::c_int as usize]);
        x[12 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[12 as libc::c_int as usize] ^ x[1 as libc::c_int as usize],
            8 as libc::c_int,
        );
        x[11 as libc::c_int
            as usize] = (x[11 as libc::c_int as usize])
            .wrapping_add(x[12 as libc::c_int as usize]);
        x[6 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[6 as libc::c_int as usize] ^ x[11 as libc::c_int as usize],
            7 as libc::c_int,
        );
        x[2 as libc::c_int
            as usize] = (x[2 as libc::c_int as usize])
            .wrapping_add(x[7 as libc::c_int as usize]);
        x[13 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[13 as libc::c_int as usize] ^ x[2 as libc::c_int as usize],
            16 as libc::c_int,
        );
        x[8 as libc::c_int
            as usize] = (x[8 as libc::c_int as usize])
            .wrapping_add(x[13 as libc::c_int as usize]);
        x[7 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[7 as libc::c_int as usize] ^ x[8 as libc::c_int as usize],
            12 as libc::c_int,
        );
        x[2 as libc::c_int
            as usize] = (x[2 as libc::c_int as usize])
            .wrapping_add(x[7 as libc::c_int as usize]);
        x[13 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[13 as libc::c_int as usize] ^ x[2 as libc::c_int as usize],
            8 as libc::c_int,
        );
        x[8 as libc::c_int
            as usize] = (x[8 as libc::c_int as usize])
            .wrapping_add(x[13 as libc::c_int as usize]);
        x[7 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[7 as libc::c_int as usize] ^ x[8 as libc::c_int as usize],
            7 as libc::c_int,
        );
        x[3 as libc::c_int
            as usize] = (x[3 as libc::c_int as usize])
            .wrapping_add(x[4 as libc::c_int as usize]);
        x[14 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[14 as libc::c_int as usize] ^ x[3 as libc::c_int as usize],
            16 as libc::c_int,
        );
        x[9 as libc::c_int
            as usize] = (x[9 as libc::c_int as usize])
            .wrapping_add(x[14 as libc::c_int as usize]);
        x[4 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[4 as libc::c_int as usize] ^ x[9 as libc::c_int as usize],
            12 as libc::c_int,
        );
        x[3 as libc::c_int
            as usize] = (x[3 as libc::c_int as usize])
            .wrapping_add(x[4 as libc::c_int as usize]);
        x[14 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[14 as libc::c_int as usize] ^ x[3 as libc::c_int as usize],
            8 as libc::c_int,
        );
        x[9 as libc::c_int
            as usize] = (x[9 as libc::c_int as usize])
            .wrapping_add(x[14 as libc::c_int as usize]);
        x[4 as libc::c_int
            as usize] = CRYPTO_rotl_u32(
            x[4 as libc::c_int as usize] ^ x[9 as libc::c_int as usize],
            7 as libc::c_int,
        );
        i -= 2 as libc::c_int;
    }
    i = 0 as libc::c_int;
    while i < 16 as libc::c_int {
        x[i as usize] = (x[i as usize]).wrapping_add(*input.offset(i as isize));
        i += 1;
        i;
    }
    i = 0 as libc::c_int;
    while i < 16 as libc::c_int {
        CRYPTO_store_u32_le(
            output.offset((4 as libc::c_int * i) as isize) as *mut libc::c_void,
            x[i as usize],
        );
        i += 1;
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_chacha_20(
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut key: *const uint8_t,
    mut nonce: *const uint8_t,
    mut counter: uint32_t,
) {
    if buffers_alias(out, in_len, in_0, in_len) == 0 || in_0 == out as *const uint8_t
    {} else {
        __assert_fail(
            b"!buffers_alias(out, in_len, in, in_len) || in == out\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/chacha/chacha.c\0" as *const u8
                as *const libc::c_char,
            202 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 102],
                &[libc::c_char; 102],
            >(
                b"void CRYPTO_chacha_20(uint8_t *, const uint8_t *, size_t, const uint8_t *, const uint8_t *, uint32_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2780: {
        if buffers_alias(out, in_len, in_0, in_len) == 0 || in_0 == out as *const uint8_t
        {} else {
            __assert_fail(
                b"!buffers_alias(out, in_len, in, in_len) || in == out\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/chacha/chacha.c\0"
                    as *const u8 as *const libc::c_char,
                202 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 102],
                    &[libc::c_char; 102],
                >(
                    b"void CRYPTO_chacha_20(uint8_t *, const uint8_t *, size_t, const uint8_t *, const uint8_t *, uint32_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut input: [uint32_t; 16] = [0; 16];
    let mut buf: [uint8_t; 64] = [0; 64];
    let mut todo: size_t = 0;
    let mut i: size_t = 0;
    input[0 as libc::c_int as usize] = sigma_words[0 as libc::c_int as usize];
    input[1 as libc::c_int as usize] = sigma_words[1 as libc::c_int as usize];
    input[2 as libc::c_int as usize] = sigma_words[2 as libc::c_int as usize];
    input[3 as libc::c_int as usize] = sigma_words[3 as libc::c_int as usize];
    input[4 as libc::c_int
        as usize] = CRYPTO_load_u32_le(
        key.offset(0 as libc::c_int as isize) as *const libc::c_void,
    );
    input[5 as libc::c_int
        as usize] = CRYPTO_load_u32_le(
        key.offset(4 as libc::c_int as isize) as *const libc::c_void,
    );
    input[6 as libc::c_int
        as usize] = CRYPTO_load_u32_le(
        key.offset(8 as libc::c_int as isize) as *const libc::c_void,
    );
    input[7 as libc::c_int
        as usize] = CRYPTO_load_u32_le(
        key.offset(12 as libc::c_int as isize) as *const libc::c_void,
    );
    input[8 as libc::c_int
        as usize] = CRYPTO_load_u32_le(
        key.offset(16 as libc::c_int as isize) as *const libc::c_void,
    );
    input[9 as libc::c_int
        as usize] = CRYPTO_load_u32_le(
        key.offset(20 as libc::c_int as isize) as *const libc::c_void,
    );
    input[10 as libc::c_int
        as usize] = CRYPTO_load_u32_le(
        key.offset(24 as libc::c_int as isize) as *const libc::c_void,
    );
    input[11 as libc::c_int
        as usize] = CRYPTO_load_u32_le(
        key.offset(28 as libc::c_int as isize) as *const libc::c_void,
    );
    input[12 as libc::c_int as usize] = counter;
    input[13 as libc::c_int
        as usize] = CRYPTO_load_u32_le(
        nonce.offset(0 as libc::c_int as isize) as *const libc::c_void,
    );
    input[14 as libc::c_int
        as usize] = CRYPTO_load_u32_le(
        nonce.offset(4 as libc::c_int as isize) as *const libc::c_void,
    );
    input[15 as libc::c_int
        as usize] = CRYPTO_load_u32_le(
        nonce.offset(8 as libc::c_int as isize) as *const libc::c_void,
    );
    while in_len > 0 as libc::c_int as size_t {
        todo = ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong;
        if in_len < todo {
            todo = in_len;
        }
        chacha_core(buf.as_mut_ptr(), input.as_mut_ptr() as *const uint32_t);
        i = 0 as libc::c_int as size_t;
        while i < todo {
            *out
                .offset(
                    i as isize,
                ) = (*in_0.offset(i as isize) as libc::c_int
                ^ buf[i as usize] as libc::c_int) as uint8_t;
            i = i.wrapping_add(1);
            i;
        }
        out = out.offset(todo as isize);
        in_0 = in_0.offset(todo as isize);
        in_len = in_len.wrapping_sub(todo);
        input[12 as libc::c_int
            as usize] = (input[12 as libc::c_int as usize]).wrapping_add(1);
        input[12 as libc::c_int as usize];
    }
}
