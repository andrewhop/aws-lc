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
    fn SHA256_Init(sha: *mut SHA256_CTX) -> libc::c_int;
    fn SHA256_Update(
        sha: *mut SHA256_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn SHA256_Final(out: *mut uint8_t, sha: *mut SHA256_CTX) -> libc::c_int;
    fn RAND_bytes(buf: *mut uint8_t, len: size_t) -> libc::c_int;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn CRYPTO_memcmp(
        a: *const libc::c_void,
        b: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
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
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __int16_t = libc::c_short;
pub type __uint16_t = libc::c_ushort;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type int16_t = __int16_t;
pub type int32_t = __int32_t;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type uintptr_t = libc::c_ulong;
pub type SHA256_CTX = sha256_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sha256_state_st {
    pub h: [uint32_t; 8],
    pub Nl: uint32_t,
    pub Nh: uint32_t,
    pub data: [uint8_t; 64],
    pub num: libc::c_uint,
    pub md_len: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct HRSS_private_key {
    pub opaque: [uint8_t; 1808],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct HRSS_public_key {
    pub opaque: [uint8_t; 1424],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct poly {
    pub v: [uint16_t; 704],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct private_key {
    pub f: poly3,
    pub f_inverse: poly3,
    pub ph_inverse: poly,
    pub hmac_key: [uint8_t; 32],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct poly3 {
    pub s: poly2,
    pub a: poly2,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct poly2 {
    pub v: [crypto_word_t; 11],
}
pub type crypto_word_t = uint64_t;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_1964_error_is_HRSS_private_key_too_small {
    #[bitfield(
        name = "static_assertion_at_line_1964_error_is_HRSS_private_key_too_small",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_1964_error_is_HRSS_private_key_too_small: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct vars {
    pub scratch: POLY_MUL_SCRATCH,
    pub f: poly,
    pub pg_phi1: poly,
    pub pfg_phi1: poly,
    pub pfg_phi1_inverse: poly,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct POLY_MUL_SCRATCH {
    pub u: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub novec: C2RustUnnamed_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub prod: [uint16_t; 1402],
    pub scratch: [uint16_t; 1318],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct public_key {
    pub ph: poly,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_1952_error_is_HRSS_public_key_too_small {
    #[bitfield(
        name = "static_assertion_at_line_1952_error_is_HRSS_public_key_too_small",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_1952_error_is_HRSS_public_key_too_small: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_1781_error_is_HRSS_SAMPLE_BYTES_incorrect {
    #[bitfield(
        name = "static_assertion_at_line_1781_error_is_HRSS_SAMPLE_BYTES_incorrect",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_1781_error_is_HRSS_SAMPLE_BYTES_incorrect: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct vars_0 {
    pub scratch: POLY_MUL_SCRATCH,
    pub m: poly,
    pub r: poly,
    pub m_lifted: poly,
    pub prh_plus_m: poly,
    pub hash_ctx: SHA256_CTX,
    pub m_bytes: [uint8_t; 140],
    pub r_bytes: [uint8_t; 140],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct vars_1 {
    pub scratch: POLY_MUL_SCRATCH,
    pub masked_key: [uint8_t; 64],
    pub hash_ctx: SHA256_CTX,
    pub c: poly,
    pub f: poly,
    pub cf: poly,
    pub cf3: poly3,
    pub m3: poly3,
    pub m: poly,
    pub m_lifted: poly,
    pub r: poly,
    pub r3: poly3,
    pub expected_ciphertext: [uint8_t; 1138],
    pub m_bytes: [uint8_t; 140],
    pub r_bytes: [uint8_t; 140],
    pub shared_key: [uint8_t; 32],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_2218_error_is_ciphertext_is_the_wrong_size {
    #[bitfield(
        name = "static_assertion_at_line_2218_error_is_ciphertext_is_the_wrong_size",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_2218_error_is_ciphertext_is_the_wrong_size: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct poly3_span {
    pub s: *mut crypto_word_t,
    pub a: *mut crypto_word_t,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_2164_error_is_HRSS_shared_key_length_incorrect {
    #[bitfield(
        name = "static_assertion_at_line_2164_error_is_HRSS_shared_key_length_incorrect",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_2164_error_is_HRSS_shared_key_length_incorrect: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_2140_error_is_HRSS_HMAC_key_larger_than_SHA_256_block_size {
    #[bitfield(
        name = "static_assertion_at_line_2140_error_is_HRSS_HMAC_key_larger_than_SHA_256_block_size",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_2140_error_is_HRSS_HMAC_key_larger_than_SHA_256_block_size: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[inline]
unsafe extern "C" fn align_pointer(
    mut ptr: *mut libc::c_void,
    mut alignment: size_t,
) -> *mut libc::c_void {
    if alignment != 0 as libc::c_int as size_t
        && alignment & alignment.wrapping_sub(1 as libc::c_int as size_t)
            == 0 as libc::c_int as size_t
    {} else {
        __assert_fail(
            b"alignment != 0 && (alignment & (alignment - 1)) == 0\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hrss/../internal.h\0" as *const u8
                as *const libc::c_char,
            264 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 36],
                &[libc::c_char; 36],
            >(b"void *align_pointer(void *, size_t)\0"))
                .as_ptr(),
        );
    }
    'c_1557: {
        if alignment != 0 as libc::c_int as size_t
            && alignment & alignment.wrapping_sub(1 as libc::c_int as size_t)
                == 0 as libc::c_int as size_t
        {} else {
            __assert_fail(
                b"alignment != 0 && (alignment & (alignment - 1)) == 0\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/hrss/../internal.h\0"
                    as *const u8 as *const libc::c_char,
                264 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 36],
                    &[libc::c_char; 36],
                >(b"void *align_pointer(void *, size_t)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut offset: uintptr_t = (0 as libc::c_uint as uintptr_t)
        .wrapping_sub(ptr as uintptr_t)
        & alignment.wrapping_sub(1 as libc::c_int as size_t);
    ptr = (ptr as *mut libc::c_char).offset(offset as isize) as *mut libc::c_void;
    if ptr as uintptr_t & alignment.wrapping_sub(1 as libc::c_int as size_t)
        == 0 as libc::c_int as libc::c_ulong
    {} else {
        __assert_fail(
            b"((uintptr_t)ptr & (alignment - 1)) == 0\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hrss/../internal.h\0" as *const u8
                as *const libc::c_char,
            272 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 36],
                &[libc::c_char; 36],
            >(b"void *align_pointer(void *, size_t)\0"))
                .as_ptr(),
        );
    }
    'c_1464: {
        if ptr as uintptr_t & alignment.wrapping_sub(1 as libc::c_int as size_t)
            == 0 as libc::c_int as libc::c_ulong
        {} else {
            __assert_fail(
                b"((uintptr_t)ptr & (alignment - 1)) == 0\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/hrss/../internal.h\0"
                    as *const u8 as *const libc::c_char,
                272 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 36],
                    &[libc::c_char; 36],
                >(b"void *align_pointer(void *, size_t)\0"))
                    .as_ptr(),
            );
        }
    };
    return ptr;
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
unsafe extern "C" fn constant_time_select_int(
    mut mask: crypto_word_t,
    mut a: libc::c_int,
    mut b: libc::c_int,
) -> libc::c_int {
    return constant_time_select_w(mask, a as crypto_word_t, b as crypto_word_t)
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
unsafe extern "C" fn poly2_zero(mut p: *mut poly2) {
    OPENSSL_memset(
        &mut *((*p).v).as_mut_ptr().offset(0 as libc::c_int as isize)
            as *mut crypto_word_t as *mut libc::c_void,
        0 as libc::c_int,
        (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
            .wrapping_mul(
                (701 as libc::c_int as libc::c_ulong)
                    .wrapping_add(
                        (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                            .wrapping_mul(8 as libc::c_int as libc::c_ulong),
                    )
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                    .wrapping_div(
                        (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                            .wrapping_mul(8 as libc::c_int as libc::c_ulong),
                    ),
            ),
    );
}
unsafe extern "C" fn word_reverse(mut in_0: crypto_word_t) -> crypto_word_t {
    static mut kMasks: [crypto_word_t; 6] = [
        0x5555555555555555 as libc::c_ulong,
        0x3333333333333333 as libc::c_ulong,
        0xf0f0f0f0f0f0f0f as libc::c_ulong,
        0xff00ff00ff00ff as libc::c_ulong,
        0xffff0000ffff as libc::c_ulong,
        0xffffffff as libc::c_ulong,
    ];
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (::core::mem::size_of::<[crypto_word_t; 6]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
    {
        in_0 = in_0 >> ((1 as libc::c_int) << i) & kMasks[i as usize]
            | (in_0 & kMasks[i as usize]) << ((1 as libc::c_int) << i);
        i = i.wrapping_add(1);
        i;
    }
    return in_0;
}
unsafe extern "C" fn lsb_to_all(mut v: crypto_word_t) -> crypto_word_t {
    return (0 as libc::c_uint as crypto_word_t)
        .wrapping_sub(v & 1 as libc::c_int as crypto_word_t);
}
unsafe extern "C" fn poly2_mod_phiN(mut p: *mut poly2) {
    let m: crypto_word_t = lsb_to_all(
        (*p)
            .v[(701 as libc::c_int as libc::c_ulong)
            .wrapping_add(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_div(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
            .wrapping_sub(1 as libc::c_int as libc::c_ulong) as usize]
            >> (701 as libc::c_int as libc::c_ulong)
                .wrapping_rem(
                    (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                        .wrapping_mul(8 as libc::c_int as libc::c_ulong),
                )
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
    );
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (701 as libc::c_int as libc::c_ulong)
            .wrapping_add(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_div(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
    {
        (*p).v[i as usize] ^= m;
        i = i.wrapping_add(1);
        i;
    }
    (*p)
        .v[(701 as libc::c_int as libc::c_ulong)
        .wrapping_add(
            (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong),
        )
        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
        .wrapping_div(
            (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong),
        )
        .wrapping_sub(1 as libc::c_int as libc::c_ulong) as usize]
        &= ((1 as libc::c_ulong)
            << (701 as libc::c_int as libc::c_ulong)
                .wrapping_rem(
                    (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                        .wrapping_mul(8 as libc::c_int as libc::c_ulong),
                )
                .wrapping_sub(1 as libc::c_int as libc::c_ulong))
            .wrapping_sub(1 as libc::c_int as libc::c_ulong);
}
static mut shift: size_t = 0;
unsafe extern "C" fn poly2_reverse_700(mut out: *mut poly2, mut in_0: *const poly2) {
    let mut t: poly2 = poly2 { v: [0; 11] };
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (701 as libc::c_int as libc::c_ulong)
            .wrapping_add(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_div(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
    {
        t.v[i as usize] = word_reverse((*in_0).v[i as usize]);
        i = i.wrapping_add(1);
        i;
    }
    let mut i_0: size_t = 0 as libc::c_int as size_t;
    while i_0
        < (701 as libc::c_int as libc::c_ulong)
            .wrapping_add(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_div(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
    {
        (*out)
            .v[i_0
            as usize] = t
            .v[(701 as libc::c_int as libc::c_ulong)
            .wrapping_add(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_div(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_sub(i_0) as usize] >> shift;
        (*out).v[i_0 as usize]
            |= t
                .v[(701 as libc::c_int as libc::c_ulong)
                .wrapping_add(
                    (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                        .wrapping_mul(8 as libc::c_int as libc::c_ulong),
                )
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                .wrapping_div(
                    (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                        .wrapping_mul(8 as libc::c_int as libc::c_ulong),
                )
                .wrapping_sub(2 as libc::c_int as libc::c_ulong)
                .wrapping_sub(i_0) as usize]
                << (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                    .wrapping_sub(shift);
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
    (*out)
        .v[(701 as libc::c_int as libc::c_ulong)
        .wrapping_add(
            (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong),
        )
        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
        .wrapping_div(
            (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong),
        )
        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
        as usize] = t.v[0 as libc::c_int as usize] >> shift;
}
unsafe extern "C" fn poly2_cswap(
    mut a: *mut poly2,
    mut b: *mut poly2,
    mut swap: crypto_word_t,
) {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (701 as libc::c_int as libc::c_ulong)
            .wrapping_add(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_div(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
    {
        let sum: crypto_word_t = swap & ((*a).v[i as usize] ^ (*b).v[i as usize]);
        (*a).v[i as usize] ^= sum;
        (*b).v[i as usize] ^= sum;
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn poly2_fmadd(
    mut out: *mut poly2,
    mut in_0: *const poly2,
    mut m: crypto_word_t,
) {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (701 as libc::c_int as libc::c_ulong)
            .wrapping_add(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_div(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
    {
        (*out).v[i as usize] ^= (*in_0).v[i as usize] & m;
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn poly2_lshift1(mut p: *mut poly2) {
    let mut carry: crypto_word_t = 0 as libc::c_int as crypto_word_t;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (701 as libc::c_int as libc::c_ulong)
            .wrapping_add(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_div(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
    {
        let next_carry: crypto_word_t = (*p).v[i as usize]
            >> (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong);
        (*p).v[i as usize] <<= 1 as libc::c_int;
        (*p).v[i as usize] |= carry;
        carry = next_carry;
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn poly2_rshift1(mut p: *mut poly2) {
    let mut carry: crypto_word_t = 0 as libc::c_int as crypto_word_t;
    let mut i: size_t = (701 as libc::c_int as libc::c_ulong)
        .wrapping_add(
            (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong),
        )
        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
        .wrapping_div(
            (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong),
        )
        .wrapping_sub(1 as libc::c_int as libc::c_ulong);
    while i
        < (701 as libc::c_int as libc::c_ulong)
            .wrapping_add(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_div(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
    {
        let next_carry: crypto_word_t = (*p).v[i as usize]
            & 1 as libc::c_int as crypto_word_t;
        (*p).v[i as usize] >>= 1 as libc::c_int;
        (*p).v[i as usize]
            |= carry
                << (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong);
        carry = next_carry;
        i = i.wrapping_sub(1);
        i;
    }
}
unsafe extern "C" fn poly2_clear_top_bits(mut p: *mut poly2) {
    (*p)
        .v[(701 as libc::c_int as libc::c_ulong)
        .wrapping_add(
            (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong),
        )
        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
        .wrapping_div(
            (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong),
        )
        .wrapping_sub(1 as libc::c_int as libc::c_ulong) as usize]
        &= ((1 as libc::c_ulong)
            << (701 as libc::c_int as libc::c_ulong)
                .wrapping_rem(
                    (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                        .wrapping_mul(8 as libc::c_int as libc::c_ulong),
                ))
            .wrapping_sub(1 as libc::c_int as libc::c_ulong);
}
unsafe extern "C" fn poly3_zero(mut p: *mut poly3) {
    poly2_zero(&mut (*p).s);
    poly2_zero(&mut (*p).a);
}
unsafe extern "C" fn poly3_reverse_700(mut out: *mut poly3, mut in_0: *const poly3) {
    poly2_reverse_700(&mut (*out).a, &(*in_0).a);
    poly2_reverse_700(&mut (*out).s, &(*in_0).s);
}
unsafe extern "C" fn poly3_word_mul(
    mut out_s: *mut crypto_word_t,
    mut out_a: *mut crypto_word_t,
    s1: crypto_word_t,
    a1: crypto_word_t,
    s2: crypto_word_t,
    a2: crypto_word_t,
) {
    *out_a = a1 & a2;
    *out_s = (s1 ^ s2) & *out_a;
}
unsafe extern "C" fn poly3_word_add(
    mut out_s: *mut crypto_word_t,
    mut out_a: *mut crypto_word_t,
    s1: crypto_word_t,
    a1: crypto_word_t,
    s2: crypto_word_t,
    a2: crypto_word_t,
) {
    let t: crypto_word_t = s1 ^ a2;
    *out_s = t & (s2 ^ a1);
    *out_a = a1 ^ a2 | t ^ s2;
}
unsafe extern "C" fn poly3_word_sub(
    mut out_s: *mut crypto_word_t,
    mut out_a: *mut crypto_word_t,
    s1: crypto_word_t,
    a1: crypto_word_t,
    s2: crypto_word_t,
    a2: crypto_word_t,
) {
    let t: crypto_word_t = a1 ^ a2;
    *out_s = (s1 ^ a2) & (t ^ s2);
    *out_a = t | s1 ^ s2;
}
unsafe extern "C" fn poly3_mul_const(
    mut p: *mut poly3,
    mut ms: crypto_word_t,
    mut ma: crypto_word_t,
) {
    ms = lsb_to_all(ms);
    ma = lsb_to_all(ma);
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (701 as libc::c_int as libc::c_ulong)
            .wrapping_add(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_div(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
    {
        poly3_word_mul(
            &mut *((*p).s.v).as_mut_ptr().offset(i as isize),
            &mut *((*p).a.v).as_mut_ptr().offset(i as isize),
            (*p).s.v[i as usize],
            (*p).a.v[i as usize],
            ms,
            ma,
        );
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn poly3_fmsub(
    mut out: *mut poly3,
    mut in_0: *const poly3,
    mut ms: crypto_word_t,
    mut ma: crypto_word_t,
) {
    let mut product_s: crypto_word_t = 0;
    let mut product_a: crypto_word_t = 0;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (701 as libc::c_int as libc::c_ulong)
            .wrapping_add(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_div(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
    {
        poly3_word_mul(
            &mut product_s,
            &mut product_a,
            (*in_0).s.v[i as usize],
            (*in_0).a.v[i as usize],
            ms,
            ma,
        );
        poly3_word_sub(
            &mut *((*out).s.v).as_mut_ptr().offset(i as isize),
            &mut *((*out).a.v).as_mut_ptr().offset(i as isize),
            (*out).s.v[i as usize],
            (*out).a.v[i as usize],
            product_s,
            product_a,
        );
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn final_bit_to_all(mut v: crypto_word_t) -> crypto_word_t {
    return lsb_to_all(
        v
            >> (701 as libc::c_int as libc::c_ulong)
                .wrapping_rem(
                    (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                        .wrapping_mul(8 as libc::c_int as libc::c_ulong),
                )
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
    );
}
unsafe extern "C" fn poly3_mod_phiN(mut p: *mut poly3) {
    let factor_s: crypto_word_t = final_bit_to_all(
        (*p)
            .s
            .v[(701 as libc::c_int as libc::c_ulong)
            .wrapping_add(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_div(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
            .wrapping_sub(1 as libc::c_int as libc::c_ulong) as usize],
    );
    let factor_a: crypto_word_t = final_bit_to_all(
        (*p)
            .a
            .v[(701 as libc::c_int as libc::c_ulong)
            .wrapping_add(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_div(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
            .wrapping_sub(1 as libc::c_int as libc::c_ulong) as usize],
    );
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (701 as libc::c_int as libc::c_ulong)
            .wrapping_add(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_div(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
    {
        poly3_word_sub(
            &mut *((*p).s.v).as_mut_ptr().offset(i as isize),
            &mut *((*p).a.v).as_mut_ptr().offset(i as isize),
            (*p).s.v[i as usize],
            (*p).a.v[i as usize],
            factor_s,
            factor_a,
        );
        i = i.wrapping_add(1);
        i;
    }
    poly2_clear_top_bits(&mut (*p).s);
    poly2_clear_top_bits(&mut (*p).a);
}
unsafe extern "C" fn poly3_cswap(
    mut a: *mut poly3,
    mut b: *mut poly3,
    mut swap: crypto_word_t,
) {
    poly2_cswap(&mut (*a).s, &mut (*b).s, swap);
    poly2_cswap(&mut (*a).a, &mut (*b).a, swap);
}
unsafe extern "C" fn poly3_lshift1(mut p: *mut poly3) {
    poly2_lshift1(&mut (*p).s);
    poly2_lshift1(&mut (*p).a);
}
unsafe extern "C" fn poly3_rshift1(mut p: *mut poly3) {
    poly2_rshift1(&mut (*p).s);
    poly2_rshift1(&mut (*p).a);
}
unsafe extern "C" fn poly3_span_add(
    mut out: *const poly3_span,
    mut a: *const poly3_span,
    mut b: *const poly3_span,
    mut n: size_t,
) {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < n {
        poly3_word_add(
            &mut *((*out).s).offset(i as isize),
            &mut *((*out).a).offset(i as isize),
            *((*a).s).offset(i as isize),
            *((*a).a).offset(i as isize),
            *((*b).s).offset(i as isize),
            *((*b).a).offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn poly3_span_sub(
    mut a: *const poly3_span,
    mut b: *const poly3_span,
    mut n: size_t,
) {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < n {
        poly3_word_sub(
            &mut *((*a).s).offset(i as isize),
            &mut *((*a).a).offset(i as isize),
            *((*a).s).offset(i as isize),
            *((*a).a).offset(i as isize),
            *((*b).s).offset(i as isize),
            *((*b).a).offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn poly3_mul_aux(
    mut out: *const poly3_span,
    mut scratch: *const poly3_span,
    mut a: *const poly3_span,
    mut b: *const poly3_span,
    mut n: size_t,
) {
    if n == 1 as libc::c_int as size_t {
        let mut r_s_low: crypto_word_t = 0 as libc::c_int as crypto_word_t;
        let mut r_s_high: crypto_word_t = 0 as libc::c_int as crypto_word_t;
        let mut r_a_low: crypto_word_t = 0 as libc::c_int as crypto_word_t;
        let mut r_a_high: crypto_word_t = 0 as libc::c_int as crypto_word_t;
        let mut b_s: crypto_word_t = *((*b).s).offset(0 as libc::c_int as isize);
        let mut b_a: crypto_word_t = *((*b).a).offset(0 as libc::c_int as isize);
        let a_s: crypto_word_t = *((*a).s).offset(0 as libc::c_int as isize);
        let a_a: crypto_word_t = *((*a).a).offset(0 as libc::c_int as isize);
        let mut i: size_t = 0 as libc::c_int as size_t;
        while i
            < (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong)
        {
            let mut m_s: crypto_word_t = 0;
            let mut m_a: crypto_word_t = 0;
            poly3_word_mul(
                &mut m_s,
                &mut m_a,
                a_s,
                a_a,
                lsb_to_all(b_s),
                lsb_to_all(b_a),
            );
            b_s >>= 1 as libc::c_int;
            b_a >>= 1 as libc::c_int;
            if i == 0 as libc::c_int as size_t {
                r_s_low = m_s;
                r_a_low = m_a;
            } else {
                let m_s_low: crypto_word_t = m_s << i;
                let m_s_high: crypto_word_t = m_s
                    >> (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                        .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                        .wrapping_sub(i);
                let m_a_low: crypto_word_t = m_a << i;
                let m_a_high: crypto_word_t = m_a
                    >> (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                        .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                        .wrapping_sub(i);
                poly3_word_add(
                    &mut r_s_low,
                    &mut r_a_low,
                    r_s_low,
                    r_a_low,
                    m_s_low,
                    m_a_low,
                );
                poly3_word_add(
                    &mut r_s_high,
                    &mut r_a_high,
                    r_s_high,
                    r_a_high,
                    m_s_high,
                    m_a_high,
                );
            }
            i = i.wrapping_add(1);
            i;
        }
        *((*out).s).offset(0 as libc::c_int as isize) = r_s_low;
        *((*out).s).offset(1 as libc::c_int as isize) = r_s_high;
        *((*out).a).offset(0 as libc::c_int as isize) = r_a_low;
        *((*out).a).offset(1 as libc::c_int as isize) = r_a_high;
        return;
    }
    let low_len: size_t = n / 2 as libc::c_int as size_t;
    let high_len: size_t = n.wrapping_sub(low_len);
    let a_high: poly3_span = {
        let mut init = poly3_span {
            s: &mut *((*a).s).offset(low_len as isize) as *mut crypto_word_t,
            a: &mut *((*a).a).offset(low_len as isize) as *mut crypto_word_t,
        };
        init
    };
    let b_high: poly3_span = {
        let mut init = poly3_span {
            s: &mut *((*b).s).offset(low_len as isize) as *mut crypto_word_t,
            a: &mut *((*b).a).offset(low_len as isize) as *mut crypto_word_t,
        };
        init
    };
    let a_cross_sum: poly3_span = *out;
    let b_cross_sum: poly3_span = {
        let mut init = poly3_span {
            s: &mut *((*out).s).offset(high_len as isize) as *mut crypto_word_t,
            a: &mut *((*out).a).offset(high_len as isize) as *mut crypto_word_t,
        };
        init
    };
    poly3_span_add(&a_cross_sum, a, &a_high, low_len);
    poly3_span_add(&b_cross_sum, b, &b_high, low_len);
    if high_len != low_len {
        *(a_cross_sum.s).offset(low_len as isize) = *(a_high.s).offset(low_len as isize);
        *(a_cross_sum.a).offset(low_len as isize) = *(a_high.a).offset(low_len as isize);
        *(b_cross_sum.s).offset(low_len as isize) = *(b_high.s).offset(low_len as isize);
        *(b_cross_sum.a).offset(low_len as isize) = *(b_high.a).offset(low_len as isize);
    }
    let child_scratch: poly3_span = {
        let mut init = poly3_span {
            s: &mut *((*scratch).s)
                .offset((2 as libc::c_int as size_t * high_len) as isize)
                as *mut crypto_word_t,
            a: &mut *((*scratch).a)
                .offset((2 as libc::c_int as size_t * high_len) as isize)
                as *mut crypto_word_t,
        };
        init
    };
    let out_mid: poly3_span = {
        let mut init = poly3_span {
            s: &mut *((*out).s).offset(low_len as isize) as *mut crypto_word_t,
            a: &mut *((*out).a).offset(low_len as isize) as *mut crypto_word_t,
        };
        init
    };
    let out_high: poly3_span = {
        let mut init = poly3_span {
            s: &mut *((*out).s).offset((2 as libc::c_int as size_t * low_len) as isize)
                as *mut crypto_word_t,
            a: &mut *((*out).a).offset((2 as libc::c_int as size_t * low_len) as isize)
                as *mut crypto_word_t,
        };
        init
    };
    poly3_mul_aux(scratch, &child_scratch, &a_cross_sum, &b_cross_sum, high_len);
    poly3_mul_aux(&out_high, &child_scratch, &a_high, &b_high, high_len);
    poly3_mul_aux(out, &child_scratch, a, b, low_len);
    poly3_span_sub(scratch, out, low_len * 2 as libc::c_int as size_t);
    poly3_span_sub(scratch, &out_high, high_len * 2 as libc::c_int as size_t);
    poly3_span_add(&out_mid, &out_mid, scratch, high_len * 2 as libc::c_int as size_t);
}
#[no_mangle]
pub unsafe extern "C" fn HRSS_poly3_mul(
    mut out: *mut poly3,
    mut x: *const poly3,
    mut y: *const poly3,
) {
    let mut prod_s: [crypto_word_t; 22] = [0; 22];
    let mut prod_a: [crypto_word_t; 22] = [0; 22];
    let mut scratch_s: [crypto_word_t; 24] = [0; 24];
    let mut scratch_a: [crypto_word_t; 24] = [0; 24];
    let prod_span: poly3_span = {
        let mut init = poly3_span {
            s: prod_s.as_mut_ptr(),
            a: prod_a.as_mut_ptr(),
        };
        init
    };
    let scratch_span: poly3_span = {
        let mut init = poly3_span {
            s: scratch_s.as_mut_ptr(),
            a: scratch_a.as_mut_ptr(),
        };
        init
    };
    let x_span: poly3_span = {
        let mut init = poly3_span {
            s: ((*x).s.v).as_ptr() as *mut crypto_word_t,
            a: ((*x).a.v).as_ptr() as *mut crypto_word_t,
        };
        init
    };
    let y_span: poly3_span = {
        let mut init = poly3_span {
            s: ((*y).s.v).as_ptr() as *mut crypto_word_t,
            a: ((*y).a.v).as_ptr() as *mut crypto_word_t,
        };
        init
    };
    poly3_mul_aux(
        &prod_span,
        &scratch_span,
        &x_span,
        &y_span,
        (701 as libc::c_int as libc::c_ulong)
            .wrapping_add(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_div(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            ),
    );
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (701 as libc::c_int as libc::c_ulong)
            .wrapping_add(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_div(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
    {
        let mut v_s: crypto_word_t = prod_s[(701 as libc::c_int as libc::c_ulong)
            .wrapping_add(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_div(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
            .wrapping_add(i)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong) as usize]
            >> (701 as libc::c_int as libc::c_ulong)
                .wrapping_rem(
                    (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                        .wrapping_mul(8 as libc::c_int as libc::c_ulong),
                );
        v_s
            |= prod_s[(701 as libc::c_int as libc::c_ulong)
                .wrapping_add(
                    (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                        .wrapping_mul(8 as libc::c_int as libc::c_ulong),
                )
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                .wrapping_div(
                    (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                        .wrapping_mul(8 as libc::c_int as libc::c_ulong),
                )
                .wrapping_add(i) as usize]
                << (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                    .wrapping_sub(
                        (701 as libc::c_int as libc::c_ulong)
                            .wrapping_rem(
                                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
                            ),
                    );
        let mut v_a: crypto_word_t = prod_a[(701 as libc::c_int as libc::c_ulong)
            .wrapping_add(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_div(
                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
            )
            .wrapping_add(i)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong) as usize]
            >> (701 as libc::c_int as libc::c_ulong)
                .wrapping_rem(
                    (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                        .wrapping_mul(8 as libc::c_int as libc::c_ulong),
                );
        v_a
            |= prod_a[(701 as libc::c_int as libc::c_ulong)
                .wrapping_add(
                    (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                        .wrapping_mul(8 as libc::c_int as libc::c_ulong),
                )
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                .wrapping_div(
                    (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                        .wrapping_mul(8 as libc::c_int as libc::c_ulong),
                )
                .wrapping_add(i) as usize]
                << (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                    .wrapping_sub(
                        (701 as libc::c_int as libc::c_ulong)
                            .wrapping_rem(
                                (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                                    .wrapping_mul(8 as libc::c_int as libc::c_ulong),
                            ),
                    );
        poly3_word_add(
            &mut *((*out).s.v).as_mut_ptr().offset(i as isize),
            &mut *((*out).a.v).as_mut_ptr().offset(i as isize),
            prod_s[i as usize],
            prod_a[i as usize],
            v_s,
            v_a,
        );
        i = i.wrapping_add(1);
        i;
    }
    poly3_mod_phiN(out);
}
#[no_mangle]
pub unsafe extern "C" fn HRSS_poly3_invert(mut out: *mut poly3, mut in_0: *const poly3) {
    let mut v: poly3 = poly3 {
        s: poly2 { v: [0; 11] },
        a: poly2 { v: [0; 11] },
    };
    let mut r: poly3 = poly3 {
        s: poly2 { v: [0; 11] },
        a: poly2 { v: [0; 11] },
    };
    let mut f: poly3 = poly3 {
        s: poly2 { v: [0; 11] },
        a: poly2 { v: [0; 11] },
    };
    let mut g: poly3 = poly3 {
        s: poly2 { v: [0; 11] },
        a: poly2 { v: [0; 11] },
    };
    poly3_zero(&mut v);
    poly3_zero(&mut r);
    r.a.v[0 as libc::c_int as usize] = 1 as libc::c_int as crypto_word_t;
    OPENSSL_memset(
        &mut f.s as *mut poly2 as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<poly2>() as libc::c_ulong,
    );
    OPENSSL_memset(
        &mut f.a as *mut poly2 as *mut libc::c_void,
        0xff as libc::c_int,
        ::core::mem::size_of::<poly2>() as libc::c_ulong,
    );
    f
        .a
        .v[(701 as libc::c_int as libc::c_ulong)
        .wrapping_add(
            (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong),
        )
        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
        .wrapping_div(
            (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong),
        )
        .wrapping_sub(1 as libc::c_int as libc::c_ulong) as usize]
        >>= (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
            .wrapping_mul(8 as libc::c_int as libc::c_ulong)
            .wrapping_sub(
                (701 as libc::c_int as libc::c_ulong)
                    .wrapping_rem(
                        (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                            .wrapping_mul(8 as libc::c_int as libc::c_ulong),
                    ),
            );
    poly3_reverse_700(&mut g, in_0);
    let mut delta: libc::c_int = 1 as libc::c_int;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (2 as libc::c_int * (701 as libc::c_int - 1 as libc::c_int) - 1 as libc::c_int)
            as size_t
    {
        poly3_lshift1(&mut v);
        let delta_sign_bit: crypto_word_t = (delta
            >> (::core::mem::size_of::<libc::c_int>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong) & 1 as libc::c_int)
            as crypto_word_t;
        let delta_is_non_negative: crypto_word_t = delta_sign_bit
            .wrapping_sub(1 as libc::c_int as crypto_word_t);
        let delta_is_non_zero: crypto_word_t = !constant_time_is_zero_w(
            delta as crypto_word_t,
        );
        let g_has_constant_term: crypto_word_t = lsb_to_all(
            g.a.v[0 as libc::c_int as usize],
        );
        let mask: crypto_word_t = g_has_constant_term & delta_is_non_negative
            & delta_is_non_zero;
        let mut c_s: crypto_word_t = 0;
        let mut c_a: crypto_word_t = 0;
        poly3_word_mul(
            &mut c_s,
            &mut c_a,
            f.s.v[0 as libc::c_int as usize],
            f.a.v[0 as libc::c_int as usize],
            g.s.v[0 as libc::c_int as usize],
            g.a.v[0 as libc::c_int as usize],
        );
        c_s = lsb_to_all(c_s);
        c_a = lsb_to_all(c_a);
        delta = constant_time_select_int(mask, -delta, delta);
        delta += 1;
        delta;
        poly3_cswap(&mut f, &mut g, mask);
        poly3_fmsub(&mut g, &mut f, c_s, c_a);
        poly3_rshift1(&mut g);
        poly3_cswap(&mut v, &mut r, mask);
        poly3_fmsub(&mut r, &mut v, c_s, c_a);
        i = i.wrapping_add(1);
        i;
    }
    if delta == 0 as libc::c_int {} else {
        __assert_fail(
            b"delta == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hrss/hrss.c\0" as *const u8
                as *const libc::c_char,
            905 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 61],
                &[libc::c_char; 61],
            >(b"void HRSS_poly3_invert(struct poly3 *, const struct poly3 *)\0"))
                .as_ptr(),
        );
    }
    'c_4964: {
        if delta == 0 as libc::c_int {} else {
            __assert_fail(
                b"delta == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/hrss/hrss.c\0" as *const u8
                    as *const libc::c_char,
                905 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 61],
                    &[libc::c_char; 61],
                >(b"void HRSS_poly3_invert(struct poly3 *, const struct poly3 *)\0"))
                    .as_ptr(),
            );
        }
    };
    poly3_mul_const(
        &mut v,
        f.s.v[0 as libc::c_int as usize],
        f.a.v[0 as libc::c_int as usize],
    );
    poly3_reverse_700(out, &mut v);
}
unsafe extern "C" fn poly_normalize(mut x: *mut poly) {
    OPENSSL_memset(
        &mut *((*x).v).as_mut_ptr().offset(701 as libc::c_int as isize) as *mut uint16_t
            as *mut libc::c_void,
        0 as libc::c_int,
        (3 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::core::mem::size_of::<uint16_t>() as libc::c_ulong),
    );
}
unsafe extern "C" fn poly_assert_normalized(mut x: *const poly) {
    if (*x).v[701 as libc::c_int as usize] as libc::c_int == 0 as libc::c_int {} else {
        __assert_fail(
            b"x->v[N] == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hrss/hrss.c\0" as *const u8
                as *const libc::c_char,
            957 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 49],
                &[libc::c_char; 49],
            >(b"void poly_assert_normalized(const struct poly *)\0"))
                .as_ptr(),
        );
    }
    'c_1902: {
        if (*x).v[701 as libc::c_int as usize] as libc::c_int == 0 as libc::c_int
        {} else {
            __assert_fail(
                b"x->v[N] == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/hrss/hrss.c\0" as *const u8
                    as *const libc::c_char,
                957 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 49],
                    &[libc::c_char; 49],
                >(b"void poly_assert_normalized(const struct poly *)\0"))
                    .as_ptr(),
            );
        }
    };
    if (*x).v[(701 as libc::c_int + 1 as libc::c_int) as usize] as libc::c_int
        == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"x->v[N + 1] == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hrss/hrss.c\0" as *const u8
                as *const libc::c_char,
            958 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 49],
                &[libc::c_char; 49],
            >(b"void poly_assert_normalized(const struct poly *)\0"))
                .as_ptr(),
        );
    }
    'c_1850: {
        if (*x).v[(701 as libc::c_int + 1 as libc::c_int) as usize] as libc::c_int
            == 0 as libc::c_int
        {} else {
            __assert_fail(
                b"x->v[N + 1] == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/hrss/hrss.c\0" as *const u8
                    as *const libc::c_char,
                958 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 49],
                    &[libc::c_char; 49],
                >(b"void poly_assert_normalized(const struct poly *)\0"))
                    .as_ptr(),
            );
        }
    };
    if (*x).v[(701 as libc::c_int + 2 as libc::c_int) as usize] as libc::c_int
        == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"x->v[N + 2] == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hrss/hrss.c\0" as *const u8
                as *const libc::c_char,
            959 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 49],
                &[libc::c_char; 49],
            >(b"void poly_assert_normalized(const struct poly *)\0"))
                .as_ptr(),
        );
    }
    'c_1795: {
        if (*x).v[(701 as libc::c_int + 2 as libc::c_int) as usize] as libc::c_int
            == 0 as libc::c_int
        {} else {
            __assert_fail(
                b"x->v[N + 2] == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/hrss/hrss.c\0" as *const u8
                    as *const libc::c_char,
                959 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 49],
                    &[libc::c_char; 49],
                >(b"void poly_assert_normalized(const struct poly *)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn poly_mul_novec_aux(
    mut out: *mut uint16_t,
    mut scratch: *mut uint16_t,
    mut a: *const uint16_t,
    mut b: *const uint16_t,
    mut n: size_t,
) {
    static mut kSchoolbookLimit: size_t = 64 as libc::c_int as size_t;
    if n < kSchoolbookLimit {
        OPENSSL_memset(
            out as *mut libc::c_void,
            0 as libc::c_int,
            (::core::mem::size_of::<uint16_t>() as libc::c_ulong)
                .wrapping_mul(n)
                .wrapping_mul(2 as libc::c_int as libc::c_ulong),
        );
        let mut i: size_t = 0 as libc::c_int as size_t;
        while i < n {
            let mut j: size_t = 0 as libc::c_int as size_t;
            while j < n {
                let ref mut fresh0 = *out.offset(i.wrapping_add(j) as isize);
                *fresh0 = (*fresh0 as libc::c_uint)
                    .wrapping_add(
                        (*a.offset(i as isize) as libc::c_uint)
                            .wrapping_mul(*b.offset(j as isize) as libc::c_uint),
                    ) as uint16_t as uint16_t;
                j = j.wrapping_add(1);
                j;
            }
            i = i.wrapping_add(1);
            i;
        }
        return;
    }
    let low_len: size_t = n / 2 as libc::c_int as size_t;
    let high_len: size_t = n.wrapping_sub(low_len);
    let a_high: *const uint16_t = &*a.offset(low_len as isize) as *const uint16_t;
    let b_high: *const uint16_t = &*b.offset(low_len as isize) as *const uint16_t;
    let mut i_0: size_t = 0 as libc::c_int as size_t;
    while i_0 < low_len {
        *out
            .offset(
                i_0 as isize,
            ) = (*a_high.offset(i_0 as isize) as libc::c_int
            + *a.offset(i_0 as isize) as libc::c_int) as uint16_t;
        *out
            .offset(
                high_len.wrapping_add(i_0) as isize,
            ) = (*b_high.offset(i_0 as isize) as libc::c_int
            + *b.offset(i_0 as isize) as libc::c_int) as uint16_t;
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
    if high_len != low_len {
        *out.offset(low_len as isize) = *a_high.offset(low_len as isize);
        *out
            .offset(
                high_len.wrapping_add(low_len) as isize,
            ) = *b_high.offset(low_len as isize);
    }
    let child_scratch: *mut uint16_t = &mut *scratch
        .offset((2 as libc::c_int as size_t * high_len) as isize) as *mut uint16_t;
    poly_mul_novec_aux(
        scratch,
        child_scratch,
        out,
        &mut *out.offset(high_len as isize),
        high_len,
    );
    poly_mul_novec_aux(
        &mut *out.offset((low_len * 2 as libc::c_int as size_t) as isize),
        child_scratch,
        a_high,
        b_high,
        high_len,
    );
    poly_mul_novec_aux(out, child_scratch, a, b, low_len);
    let mut i_1: size_t = 0 as libc::c_int as size_t;
    while i_1 < low_len * 2 as libc::c_int as size_t {
        let ref mut fresh1 = *scratch.offset(i_1 as isize);
        *fresh1 = (*fresh1 as libc::c_int
            - (*out.offset(i_1 as isize) as libc::c_int
                + *out
                    .offset(
                        (low_len * 2 as libc::c_int as size_t).wrapping_add(i_1) as isize,
                    ) as libc::c_int)) as uint16_t;
        i_1 = i_1.wrapping_add(1);
        i_1;
    }
    if low_len != high_len {
        let ref mut fresh2 = *scratch
            .offset((low_len * 2 as libc::c_int as size_t) as isize);
        *fresh2 = (*fresh2 as libc::c_int
            - *out.offset((low_len * 4 as libc::c_int as size_t) as isize)
                as libc::c_int) as uint16_t;
        if *out
            .offset(
                (low_len * 4 as libc::c_int as size_t)
                    .wrapping_add(1 as libc::c_int as size_t) as isize,
            ) as libc::c_int == 0 as libc::c_int
        {} else {
            __assert_fail(
                b"out[low_len * 4 + 1] == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/hrss/hrss.c\0" as *const u8
                    as *const libc::c_char,
                1332 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 92],
                    &[libc::c_char; 92],
                >(
                    b"void poly_mul_novec_aux(uint16_t *, uint16_t *, const uint16_t *, const uint16_t *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_2166: {
            if *out
                .offset(
                    (low_len * 4 as libc::c_int as size_t)
                        .wrapping_add(1 as libc::c_int as size_t) as isize,
                ) as libc::c_int == 0 as libc::c_int
            {} else {
                __assert_fail(
                    b"out[low_len * 4 + 1] == 0\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/hrss/hrss.c\0"
                        as *const u8 as *const libc::c_char,
                    1332 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 92],
                        &[libc::c_char; 92],
                    >(
                        b"void poly_mul_novec_aux(uint16_t *, uint16_t *, const uint16_t *, const uint16_t *, size_t)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
    }
    let mut i_2: size_t = 0 as libc::c_int as size_t;
    while i_2 < high_len * 2 as libc::c_int as size_t {
        let ref mut fresh3 = *out.offset(low_len.wrapping_add(i_2) as isize);
        *fresh3 = (*fresh3 as libc::c_int + *scratch.offset(i_2 as isize) as libc::c_int)
            as uint16_t;
        i_2 = i_2.wrapping_add(1);
        i_2;
    }
}
unsafe extern "C" fn poly_mul_novec(
    mut scratch: *mut POLY_MUL_SCRATCH,
    mut out: *mut poly,
    mut x: *const poly,
    mut y: *const poly,
) {
    let prod: *mut uint16_t = ((*scratch).u.novec.prod).as_mut_ptr();
    let aux_scratch: *mut uint16_t = ((*scratch).u.novec.scratch).as_mut_ptr();
    poly_mul_novec_aux(
        prod,
        aux_scratch,
        ((*x).v).as_ptr(),
        ((*y).v).as_ptr(),
        701 as libc::c_int as size_t,
    );
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < 701 as libc::c_int as size_t {
        (*out)
            .v[i
            as usize] = (*prod.offset(i as isize) as libc::c_int
            + *prod.offset(i.wrapping_add(701 as libc::c_int as size_t) as isize)
                as libc::c_int) as uint16_t;
        i = i.wrapping_add(1);
        i;
    }
    OPENSSL_memset(
        &mut *((*out).v).as_mut_ptr().offset(701 as libc::c_int as isize)
            as *mut uint16_t as *mut libc::c_void,
        0 as libc::c_int,
        (3 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::core::mem::size_of::<uint16_t>() as libc::c_ulong),
    );
}
unsafe extern "C" fn poly_mul(
    mut scratch: *mut POLY_MUL_SCRATCH,
    mut r: *mut poly,
    mut a: *const poly,
    mut b: *const poly,
) {
    poly_mul_novec(scratch, r, a, b);
    poly_assert_normalized(r);
}
unsafe extern "C" fn poly_mul_x_minus_1(mut p: *mut poly) {
    let orig_final_coefficient: uint16_t = (*p)
        .v[(701 as libc::c_int - 1 as libc::c_int) as usize];
    let mut i: size_t = (701 as libc::c_int - 1 as libc::c_int) as size_t;
    while i > 0 as libc::c_int as size_t {
        (*p)
            .v[i
            as usize] = ((*p).v[i.wrapping_sub(1 as libc::c_int as size_t) as usize]
            as libc::c_int - (*p).v[i as usize] as libc::c_int) as uint16_t;
        i = i.wrapping_sub(1);
        i;
    }
    (*p)
        .v[0 as libc::c_int
        as usize] = (orig_final_coefficient as libc::c_int
        - (*p).v[0 as libc::c_int as usize] as libc::c_int) as uint16_t;
}
unsafe extern "C" fn poly_mod_phiN(mut p: *mut poly) {
    let coeff700: uint16_t = (*p).v[(701 as libc::c_int - 1 as libc::c_int) as usize];
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while i < 701 as libc::c_int as libc::c_uint {
        (*p)
            .v[i
            as usize] = ((*p).v[i as usize] as libc::c_int - coeff700 as libc::c_int)
            as uint16_t;
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn poly_clamp(mut p: *mut poly) {
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while i < 701 as libc::c_int as libc::c_uint {
        (*p)
            .v[i
            as usize] = ((*p).v[i as usize] as libc::c_int
            & 8192 as libc::c_int - 1 as libc::c_int) as uint16_t;
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn poly2_from_poly(mut out: *mut poly2, mut in_0: *const poly) {
    let mut words: *mut crypto_word_t = ((*out).v).as_mut_ptr();
    let mut shift_0: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut word: crypto_word_t = 0 as libc::c_int as crypto_word_t;
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while i < 701 as libc::c_int as libc::c_uint {
        word >>= 1 as libc::c_int;
        word
            |= (((*in_0).v[i as usize] as libc::c_int & 1 as libc::c_int)
                as crypto_word_t)
                << (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong);
        shift_0 = shift_0.wrapping_add(1);
        shift_0;
        if shift_0 as libc::c_ulong
            == (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong)
        {
            *words = word;
            words = words.offset(1);
            words;
            word = 0 as libc::c_int as crypto_word_t;
            shift_0 = 0 as libc::c_int as libc::c_uint;
        }
        i = i.wrapping_add(1);
        i;
    }
    word
        >>= (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
            .wrapping_mul(8 as libc::c_int as libc::c_ulong)
            .wrapping_sub(shift_0 as libc::c_ulong);
    *words = word;
}
unsafe extern "C" fn mod3(mut a: int16_t) -> uint16_t {
    let q: int16_t = (a as int32_t * 21845 as libc::c_int >> 16 as libc::c_int)
        as int16_t;
    let mut ret: int16_t = (a as libc::c_int - 3 as libc::c_int * q as libc::c_int)
        as int16_t;
    return (ret as libc::c_int
        & (ret as libc::c_int & ret as libc::c_int >> 1 as libc::c_int)
            - 1 as libc::c_int) as uint16_t;
}
unsafe extern "C" fn poly3_from_poly(mut out: *mut poly3, mut in_0: *const poly) {
    let mut words_s: *mut crypto_word_t = ((*out).s.v).as_mut_ptr();
    let mut words_a: *mut crypto_word_t = ((*out).a.v).as_mut_ptr();
    let mut s: crypto_word_t = 0 as libc::c_int as crypto_word_t;
    let mut a: crypto_word_t = 0 as libc::c_int as crypto_word_t;
    let mut shift_0: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while i < 701 as libc::c_int as libc::c_uint {
        let v: uint16_t = mod3(
            ((((*in_0).v[i as usize] as libc::c_int) << 3 as libc::c_int) as int16_t
                as libc::c_int >> 3 as libc::c_int) as int16_t,
        );
        s >>= 1 as libc::c_int;
        let s_bit: crypto_word_t = ((v as libc::c_int & 2 as libc::c_int)
            as crypto_word_t)
            << (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                .wrapping_sub(2 as libc::c_int as libc::c_ulong);
        s |= s_bit;
        a >>= 1 as libc::c_int;
        a
            |= s_bit
                | ((v as libc::c_int & 1 as libc::c_int) as crypto_word_t)
                    << (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                        .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong);
        shift_0 = shift_0.wrapping_add(1);
        shift_0;
        if shift_0 as libc::c_ulong
            == (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong)
        {
            *words_s = s;
            words_s = words_s.offset(1);
            words_s;
            *words_a = a;
            words_a = words_a.offset(1);
            words_a;
            a = 0 as libc::c_int as crypto_word_t;
            s = a;
            shift_0 = 0 as libc::c_int as libc::c_uint;
        }
        i = i.wrapping_add(1);
        i;
    }
    s
        >>= (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
            .wrapping_mul(8 as libc::c_int as libc::c_ulong)
            .wrapping_sub(shift_0 as libc::c_ulong);
    a
        >>= (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
            .wrapping_mul(8 as libc::c_int as libc::c_ulong)
            .wrapping_sub(shift_0 as libc::c_ulong);
    *words_s = s;
    *words_a = a;
}
unsafe extern "C" fn poly3_from_poly_checked(
    mut out: *mut poly3,
    mut in_0: *const poly,
) -> crypto_word_t {
    let mut words_s: *mut crypto_word_t = ((*out).s.v).as_mut_ptr();
    let mut words_a: *mut crypto_word_t = ((*out).a.v).as_mut_ptr();
    let mut s: crypto_word_t = 0 as libc::c_int as crypto_word_t;
    let mut a: crypto_word_t = 0 as libc::c_int as crypto_word_t;
    let mut shift_0: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut ok: crypto_word_t = !(0 as libc::c_int as crypto_word_t);
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while i < 701 as libc::c_int as libc::c_uint {
        let v: uint16_t = (*in_0).v[i as usize];
        let mut mod3_0: uint16_t = (v as libc::c_int & 3 as libc::c_int) as uint16_t;
        mod3_0 = (mod3_0 as libc::c_int ^ mod3_0 as libc::c_int >> 1 as libc::c_int)
            as uint16_t;
        let expected: uint16_t = ((!((mod3_0 as libc::c_int >> 1 as libc::c_int)
            - 1 as libc::c_int) | mod3_0 as libc::c_int) as uint16_t as libc::c_int
            % 8192 as libc::c_int) as uint16_t;
        ok &= constant_time_eq_w(v as crypto_word_t, expected as crypto_word_t);
        s >>= 1 as libc::c_int;
        let s_bit: crypto_word_t = ((mod3_0 as libc::c_int & 2 as libc::c_int)
            as crypto_word_t)
            << (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                .wrapping_sub(2 as libc::c_int as libc::c_ulong);
        s |= s_bit;
        a >>= 1 as libc::c_int;
        a
            |= s_bit
                | ((mod3_0 as libc::c_int & 1 as libc::c_int) as crypto_word_t)
                    << (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                        .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong);
        shift_0 = shift_0.wrapping_add(1);
        shift_0;
        if shift_0 as libc::c_ulong
            == (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong)
        {
            *words_s = s;
            words_s = words_s.offset(1);
            words_s;
            *words_a = a;
            words_a = words_a.offset(1);
            words_a;
            a = 0 as libc::c_int as crypto_word_t;
            s = a;
            shift_0 = 0 as libc::c_int as libc::c_uint;
        }
        i = i.wrapping_add(1);
        i;
    }
    s
        >>= (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
            .wrapping_mul(8 as libc::c_int as libc::c_ulong)
            .wrapping_sub(shift_0 as libc::c_ulong);
    a
        >>= (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
            .wrapping_mul(8 as libc::c_int as libc::c_ulong)
            .wrapping_sub(shift_0 as libc::c_ulong);
    *words_s = s;
    *words_a = a;
    return ok;
}
unsafe extern "C" fn poly_from_poly2(mut out: *mut poly, mut in_0: *const poly2) {
    let mut words: *const crypto_word_t = ((*in_0).v).as_ptr();
    let mut shift_0: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut word: crypto_word_t = *words;
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while i < 701 as libc::c_int as libc::c_uint {
        (*out).v[i as usize] = (word & 1 as libc::c_int as crypto_word_t) as uint16_t;
        word >>= 1 as libc::c_int;
        shift_0 = shift_0.wrapping_add(1);
        shift_0;
        if shift_0 as libc::c_ulong
            == (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong)
        {
            words = words.offset(1);
            words;
            word = *words;
            shift_0 = 0 as libc::c_int as libc::c_uint;
        }
        i = i.wrapping_add(1);
        i;
    }
    poly_normalize(out);
}
unsafe extern "C" fn poly_from_poly3(mut out: *mut poly, mut in_0: *const poly3) {
    let mut words_s: *const crypto_word_t = ((*in_0).s.v).as_ptr();
    let mut words_a: *const crypto_word_t = ((*in_0).a.v).as_ptr();
    let mut word_s: crypto_word_t = !*words_s;
    let mut word_a: crypto_word_t = *words_a;
    let mut shift_0: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while i < 701 as libc::c_int as libc::c_uint {
        (*out)
            .v[i
            as usize] = ((word_s & 1 as libc::c_int as crypto_word_t) as uint16_t
            as libc::c_int - 1 as libc::c_int) as uint16_t;
        (*out)
            .v[i
            as usize] = ((*out).v[i as usize] as crypto_word_t
            | word_a & 1 as libc::c_int as crypto_word_t) as uint16_t;
        word_s >>= 1 as libc::c_int;
        word_a >>= 1 as libc::c_int;
        shift_0 = shift_0.wrapping_add(1);
        shift_0;
        if shift_0 as libc::c_ulong
            == (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong)
        {
            words_s = words_s.offset(1);
            words_s;
            words_a = words_a.offset(1);
            words_a;
            word_s = !*words_s;
            word_a = *words_a;
            shift_0 = 0 as libc::c_int as libc::c_uint;
        }
        i = i.wrapping_add(1);
        i;
    }
    poly_normalize(out);
}
unsafe extern "C" fn poly_invert_mod2(mut out: *mut poly, mut in_0: *const poly) {
    let mut v: poly2 = poly2 { v: [0; 11] };
    let mut r: poly2 = poly2 { v: [0; 11] };
    let mut f: poly2 = poly2 { v: [0; 11] };
    let mut g: poly2 = poly2 { v: [0; 11] };
    poly2_zero(&mut v);
    poly2_zero(&mut r);
    r.v[0 as libc::c_int as usize] = 1 as libc::c_int as crypto_word_t;
    OPENSSL_memset(
        &mut f as *mut poly2 as *mut libc::c_void,
        0xff as libc::c_int,
        ::core::mem::size_of::<poly2>() as libc::c_ulong,
    );
    f
        .v[(701 as libc::c_int as libc::c_ulong)
        .wrapping_add(
            (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong),
        )
        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
        .wrapping_div(
            (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong),
        )
        .wrapping_sub(1 as libc::c_int as libc::c_ulong) as usize]
        >>= (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
            .wrapping_mul(8 as libc::c_int as libc::c_ulong)
            .wrapping_sub(
                (701 as libc::c_int as libc::c_ulong)
                    .wrapping_rem(
                        (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                            .wrapping_mul(8 as libc::c_int as libc::c_ulong),
                    ),
            );
    poly2_from_poly(&mut g, in_0);
    poly2_mod_phiN(&mut g);
    poly2_reverse_700(&mut g, &mut g);
    let mut delta: libc::c_int = 1 as libc::c_int;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (2 as libc::c_int * (701 as libc::c_int - 1 as libc::c_int) - 1 as libc::c_int)
            as size_t
    {
        poly2_lshift1(&mut v);
        let delta_sign_bit: crypto_word_t = (delta
            >> (::core::mem::size_of::<libc::c_int>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong) & 1 as libc::c_int)
            as crypto_word_t;
        let delta_is_non_negative: crypto_word_t = delta_sign_bit
            .wrapping_sub(1 as libc::c_int as crypto_word_t);
        let delta_is_non_zero: crypto_word_t = !constant_time_is_zero_w(
            delta as crypto_word_t,
        );
        let g_has_constant_term: crypto_word_t = lsb_to_all(
            g.v[0 as libc::c_int as usize],
        );
        let mask: crypto_word_t = g_has_constant_term & delta_is_non_negative
            & delta_is_non_zero;
        let c: crypto_word_t = lsb_to_all(
            f.v[0 as libc::c_int as usize] & g.v[0 as libc::c_int as usize],
        );
        delta = constant_time_select_int(mask, -delta, delta);
        delta += 1;
        delta;
        poly2_cswap(&mut f, &mut g, mask);
        poly2_fmadd(&mut g, &mut f, c);
        poly2_rshift1(&mut g);
        poly2_cswap(&mut v, &mut r, mask);
        poly2_fmadd(&mut r, &mut v, c);
        i = i.wrapping_add(1);
        i;
    }
    if delta == 0 as libc::c_int {} else {
        __assert_fail(
            b"delta == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hrss/hrss.c\0" as *const u8
                as *const libc::c_char,
            1615 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 58],
                &[libc::c_char; 58],
            >(b"void poly_invert_mod2(struct poly *, const struct poly *)\0"))
                .as_ptr(),
        );
    }
    'c_3267: {
        if delta == 0 as libc::c_int {} else {
            __assert_fail(
                b"delta == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/hrss/hrss.c\0" as *const u8
                    as *const libc::c_char,
                1615 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 58],
                    &[libc::c_char; 58],
                >(b"void poly_invert_mod2(struct poly *, const struct poly *)\0"))
                    .as_ptr(),
            );
        }
    };
    if f.v[0 as libc::c_int as usize] & 1 as libc::c_int as crypto_word_t != 0 {} else {
        __assert_fail(
            b"f.v[0] & 1\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hrss/hrss.c\0" as *const u8
                as *const libc::c_char,
            1616 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 58],
                &[libc::c_char; 58],
            >(b"void poly_invert_mod2(struct poly *, const struct poly *)\0"))
                .as_ptr(),
        );
    }
    'c_3218: {
        if f.v[0 as libc::c_int as usize] & 1 as libc::c_int as crypto_word_t != 0
        {} else {
            __assert_fail(
                b"f.v[0] & 1\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/hrss/hrss.c\0" as *const u8
                    as *const libc::c_char,
                1616 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 58],
                    &[libc::c_char; 58],
                >(b"void poly_invert_mod2(struct poly *, const struct poly *)\0"))
                    .as_ptr(),
            );
        }
    };
    poly2_reverse_700(&mut v, &mut v);
    poly_from_poly2(out, &mut v);
    poly_assert_normalized(out);
}
unsafe extern "C" fn poly_invert(
    mut scratch: *mut POLY_MUL_SCRATCH,
    mut out: *mut poly,
    mut in_0: *const poly,
) {
    let mut a: poly = poly { v: [0; 704] };
    let mut b: *mut poly = 0 as *mut poly;
    let mut tmp: poly = poly { v: [0; 704] };
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while i < 701 as libc::c_int as libc::c_uint {
        a.v[i as usize] = -((*in_0).v[i as usize] as libc::c_int) as uint16_t;
        i = i.wrapping_add(1);
        i;
    }
    poly_normalize(&mut a);
    b = out;
    poly_invert_mod2(b, in_0);
    let mut i_0: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while i_0 < 4 as libc::c_int as libc::c_uint {
        poly_mul(scratch, &mut tmp, &mut a, b);
        tmp
            .v[0 as libc::c_int
            as usize] = (tmp.v[0 as libc::c_int as usize] as libc::c_int
            + 2 as libc::c_int) as uint16_t;
        poly_mul(scratch, b, b, &mut tmp);
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
    poly_assert_normalized(out);
}
unsafe extern "C" fn poly_marshal(mut out: *mut uint8_t, mut in_0: *const poly) {
    let mut p: *const uint16_t = ((*in_0).v).as_ptr();
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < (701 as libc::c_int / 8 as libc::c_int) as size_t {
        *out
            .offset(
                0 as libc::c_int as isize,
            ) = *p.offset(0 as libc::c_int as isize) as uint8_t;
        *out
            .offset(
                1 as libc::c_int as isize,
            ) = (0x1f as libc::c_int
            & *p.offset(0 as libc::c_int as isize) as libc::c_int >> 8 as libc::c_int
            | (*p.offset(1 as libc::c_int as isize) as libc::c_int & 0x7 as libc::c_int)
                << 5 as libc::c_int) as uint8_t;
        *out
            .offset(
                2 as libc::c_int as isize,
            ) = (*p.offset(1 as libc::c_int as isize) as libc::c_int >> 3 as libc::c_int)
            as uint8_t;
        *out
            .offset(
                3 as libc::c_int as isize,
            ) = (3 as libc::c_int
            & *p.offset(1 as libc::c_int as isize) as libc::c_int >> 11 as libc::c_int
            | (*p.offset(2 as libc::c_int as isize) as libc::c_int & 0x3f as libc::c_int)
                << 2 as libc::c_int) as uint8_t;
        *out
            .offset(
                4 as libc::c_int as isize,
            ) = (0x7f as libc::c_int
            & *p.offset(2 as libc::c_int as isize) as libc::c_int >> 6 as libc::c_int
            | (*p.offset(3 as libc::c_int as isize) as libc::c_int & 0x1 as libc::c_int)
                << 7 as libc::c_int) as uint8_t;
        *out
            .offset(
                5 as libc::c_int as isize,
            ) = (*p.offset(3 as libc::c_int as isize) as libc::c_int >> 1 as libc::c_int)
            as uint8_t;
        *out
            .offset(
                6 as libc::c_int as isize,
            ) = (0xf as libc::c_int
            & *p.offset(3 as libc::c_int as isize) as libc::c_int >> 9 as libc::c_int
            | (*p.offset(4 as libc::c_int as isize) as libc::c_int & 0xf as libc::c_int)
                << 4 as libc::c_int) as uint8_t;
        *out
            .offset(
                7 as libc::c_int as isize,
            ) = (*p.offset(4 as libc::c_int as isize) as libc::c_int >> 4 as libc::c_int)
            as uint8_t;
        *out
            .offset(
                8 as libc::c_int as isize,
            ) = (1 as libc::c_int
            & *p.offset(4 as libc::c_int as isize) as libc::c_int >> 12 as libc::c_int
            | (*p.offset(5 as libc::c_int as isize) as libc::c_int & 0x7f as libc::c_int)
                << 1 as libc::c_int) as uint8_t;
        *out
            .offset(
                9 as libc::c_int as isize,
            ) = (0x3f as libc::c_int
            & *p.offset(5 as libc::c_int as isize) as libc::c_int >> 7 as libc::c_int
            | (*p.offset(6 as libc::c_int as isize) as libc::c_int & 0x3 as libc::c_int)
                << 6 as libc::c_int) as uint8_t;
        *out
            .offset(
                10 as libc::c_int as isize,
            ) = (*p.offset(6 as libc::c_int as isize) as libc::c_int >> 2 as libc::c_int)
            as uint8_t;
        *out
            .offset(
                11 as libc::c_int as isize,
            ) = (7 as libc::c_int
            & *p.offset(6 as libc::c_int as isize) as libc::c_int >> 10 as libc::c_int
            | (*p.offset(7 as libc::c_int as isize) as libc::c_int & 0x1f as libc::c_int)
                << 3 as libc::c_int) as uint8_t;
        *out
            .offset(
                12 as libc::c_int as isize,
            ) = (*p.offset(7 as libc::c_int as isize) as libc::c_int >> 5 as libc::c_int)
            as uint8_t;
        p = p.offset(8 as libc::c_int as isize);
        out = out.offset(13 as libc::c_int as isize);
        i = i.wrapping_add(1);
        i;
    }
    *out
        .offset(
            0 as libc::c_int as isize,
        ) = *p.offset(0 as libc::c_int as isize) as uint8_t;
    *out
        .offset(
            1 as libc::c_int as isize,
        ) = (0x1f as libc::c_int
        & *p.offset(0 as libc::c_int as isize) as libc::c_int >> 8 as libc::c_int
        | (*p.offset(1 as libc::c_int as isize) as libc::c_int & 0x7 as libc::c_int)
            << 5 as libc::c_int) as uint8_t;
    *out
        .offset(
            2 as libc::c_int as isize,
        ) = (*p.offset(1 as libc::c_int as isize) as libc::c_int >> 3 as libc::c_int)
        as uint8_t;
    *out
        .offset(
            3 as libc::c_int as isize,
        ) = (3 as libc::c_int
        & *p.offset(1 as libc::c_int as isize) as libc::c_int >> 11 as libc::c_int
        | (*p.offset(2 as libc::c_int as isize) as libc::c_int & 0x3f as libc::c_int)
            << 2 as libc::c_int) as uint8_t;
    *out
        .offset(
            4 as libc::c_int as isize,
        ) = (0x7f as libc::c_int
        & *p.offset(2 as libc::c_int as isize) as libc::c_int >> 6 as libc::c_int
        | (*p.offset(3 as libc::c_int as isize) as libc::c_int & 0x1 as libc::c_int)
            << 7 as libc::c_int) as uint8_t;
    *out
        .offset(
            5 as libc::c_int as isize,
        ) = (*p.offset(3 as libc::c_int as isize) as libc::c_int >> 1 as libc::c_int)
        as uint8_t;
    *out
        .offset(
            6 as libc::c_int as isize,
        ) = (0xf as libc::c_int
        & *p.offset(3 as libc::c_int as isize) as libc::c_int >> 9 as libc::c_int)
        as uint8_t;
}
unsafe extern "C" fn poly_unmarshal(
    mut out: *mut poly,
    mut in_0: *const uint8_t,
) -> libc::c_int {
    let mut p: *mut uint16_t = ((*out).v).as_mut_ptr();
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < (701 as libc::c_int / 8 as libc::c_int) as size_t {
        *p
            .offset(
                0 as libc::c_int as isize,
            ) = (*in_0.offset(0 as libc::c_int as isize) as uint16_t as libc::c_int
            | ((*in_0.offset(1 as libc::c_int as isize) as libc::c_int
                & 0x1f as libc::c_int) as uint16_t as libc::c_int) << 8 as libc::c_int)
            as uint16_t;
        *p
            .offset(
                1 as libc::c_int as isize,
            ) = ((*in_0.offset(1 as libc::c_int as isize) as libc::c_int
            >> 5 as libc::c_int) as uint16_t as libc::c_int
            | (*in_0.offset(2 as libc::c_int as isize) as uint16_t as libc::c_int)
                << 3 as libc::c_int
            | ((*in_0.offset(3 as libc::c_int as isize) as libc::c_int
                & 3 as libc::c_int) as uint16_t as libc::c_int) << 11 as libc::c_int)
            as uint16_t;
        *p
            .offset(
                2 as libc::c_int as isize,
            ) = ((*in_0.offset(3 as libc::c_int as isize) as libc::c_int
            >> 2 as libc::c_int) as uint16_t as libc::c_int
            | ((*in_0.offset(4 as libc::c_int as isize) as libc::c_int
                & 0x7f as libc::c_int) as uint16_t as libc::c_int) << 6 as libc::c_int)
            as uint16_t;
        *p
            .offset(
                3 as libc::c_int as isize,
            ) = ((*in_0.offset(4 as libc::c_int as isize) as libc::c_int
            >> 7 as libc::c_int) as uint16_t as libc::c_int
            | (*in_0.offset(5 as libc::c_int as isize) as uint16_t as libc::c_int)
                << 1 as libc::c_int
            | ((*in_0.offset(6 as libc::c_int as isize) as libc::c_int
                & 0xf as libc::c_int) as uint16_t as libc::c_int) << 9 as libc::c_int)
            as uint16_t;
        *p
            .offset(
                4 as libc::c_int as isize,
            ) = ((*in_0.offset(6 as libc::c_int as isize) as libc::c_int
            >> 4 as libc::c_int) as uint16_t as libc::c_int
            | (*in_0.offset(7 as libc::c_int as isize) as uint16_t as libc::c_int)
                << 4 as libc::c_int
            | ((*in_0.offset(8 as libc::c_int as isize) as libc::c_int
                & 1 as libc::c_int) as uint16_t as libc::c_int) << 12 as libc::c_int)
            as uint16_t;
        *p
            .offset(
                5 as libc::c_int as isize,
            ) = ((*in_0.offset(8 as libc::c_int as isize) as libc::c_int
            >> 1 as libc::c_int) as uint16_t as libc::c_int
            | ((*in_0.offset(9 as libc::c_int as isize) as libc::c_int
                & 0x3f as libc::c_int) as uint16_t as libc::c_int) << 7 as libc::c_int)
            as uint16_t;
        *p
            .offset(
                6 as libc::c_int as isize,
            ) = ((*in_0.offset(9 as libc::c_int as isize) as libc::c_int
            >> 6 as libc::c_int) as uint16_t as libc::c_int
            | (*in_0.offset(10 as libc::c_int as isize) as uint16_t as libc::c_int)
                << 2 as libc::c_int
            | ((*in_0.offset(11 as libc::c_int as isize) as libc::c_int
                & 7 as libc::c_int) as uint16_t as libc::c_int) << 10 as libc::c_int)
            as uint16_t;
        *p
            .offset(
                7 as libc::c_int as isize,
            ) = ((*in_0.offset(11 as libc::c_int as isize) as libc::c_int
            >> 3 as libc::c_int) as uint16_t as libc::c_int
            | (*in_0.offset(12 as libc::c_int as isize) as uint16_t as libc::c_int)
                << 5 as libc::c_int) as uint16_t;
        p = p.offset(8 as libc::c_int as isize);
        in_0 = in_0.offset(13 as libc::c_int as isize);
        i = i.wrapping_add(1);
        i;
    }
    *p
        .offset(
            0 as libc::c_int as isize,
        ) = (*in_0.offset(0 as libc::c_int as isize) as uint16_t as libc::c_int
        | ((*in_0.offset(1 as libc::c_int as isize) as libc::c_int & 0x1f as libc::c_int)
            as uint16_t as libc::c_int) << 8 as libc::c_int) as uint16_t;
    *p
        .offset(
            1 as libc::c_int as isize,
        ) = ((*in_0.offset(1 as libc::c_int as isize) as libc::c_int >> 5 as libc::c_int)
        as uint16_t as libc::c_int
        | (*in_0.offset(2 as libc::c_int as isize) as uint16_t as libc::c_int)
            << 3 as libc::c_int
        | ((*in_0.offset(3 as libc::c_int as isize) as libc::c_int & 3 as libc::c_int)
            as uint16_t as libc::c_int) << 11 as libc::c_int) as uint16_t;
    *p
        .offset(
            2 as libc::c_int as isize,
        ) = ((*in_0.offset(3 as libc::c_int as isize) as libc::c_int >> 2 as libc::c_int)
        as uint16_t as libc::c_int
        | ((*in_0.offset(4 as libc::c_int as isize) as libc::c_int & 0x7f as libc::c_int)
            as uint16_t as libc::c_int) << 6 as libc::c_int) as uint16_t;
    *p
        .offset(
            3 as libc::c_int as isize,
        ) = ((*in_0.offset(4 as libc::c_int as isize) as libc::c_int >> 7 as libc::c_int)
        as uint16_t as libc::c_int
        | (*in_0.offset(5 as libc::c_int as isize) as uint16_t as libc::c_int)
            << 1 as libc::c_int
        | ((*in_0.offset(6 as libc::c_int as isize) as libc::c_int & 0xf as libc::c_int)
            as uint16_t as libc::c_int) << 9 as libc::c_int) as uint16_t;
    let mut i_0: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while i_0 < (701 as libc::c_int - 1 as libc::c_int) as libc::c_uint {
        (*out)
            .v[i_0
            as usize] = ((((*out).v[i_0 as usize] as libc::c_int) << 3 as libc::c_int)
            as int16_t as libc::c_int >> 3 as libc::c_int) as uint16_t;
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
    if *in_0.offset(6 as libc::c_int as isize) as libc::c_int & 0xf0 as libc::c_int
        != 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    let mut sum: uint32_t = 0 as libc::c_int as uint32_t;
    let mut i_1: size_t = 0 as libc::c_int as size_t;
    while i_1 < (701 as libc::c_int - 1 as libc::c_int) as size_t {
        sum = sum.wrapping_add((*out).v[i_1 as usize] as uint32_t);
        i_1 = i_1.wrapping_add(1);
        i_1;
    }
    (*out)
        .v[(701 as libc::c_int - 1 as libc::c_int)
        as usize] = (0 as libc::c_uint).wrapping_sub(sum) as uint16_t;
    poly_normalize(out);
    return 1 as libc::c_int;
}
unsafe extern "C" fn mod3_from_modQ(mut v: uint16_t) -> uint16_t {
    v = (v as libc::c_int & 3 as libc::c_int) as uint16_t;
    return (v as libc::c_int ^ v as libc::c_int >> 1 as libc::c_int) as uint16_t;
}
unsafe extern "C" fn poly_marshal_mod3(mut out: *mut uint8_t, mut in_0: *const poly) {
    let mut coeffs: *const uint16_t = ((*in_0).v).as_ptr();
    if *coeffs.offset((701 as libc::c_int - 1 as libc::c_int) as isize) as libc::c_int
        == 0 as libc::c_int
    {} else {
        __assert_fail(
            b"coeffs[N-1] == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hrss/hrss.c\0" as *const u8
                as *const libc::c_char,
            1757 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 55],
                &[libc::c_char; 55],
            >(b"void poly_marshal_mod3(uint8_t *, const struct poly *)\0"))
                .as_ptr(),
        );
    }
    'c_6177: {
        if *coeffs.offset((701 as libc::c_int - 1 as libc::c_int) as isize)
            as libc::c_int == 0 as libc::c_int
        {} else {
            __assert_fail(
                b"coeffs[N-1] == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/hrss/hrss.c\0" as *const u8
                    as *const libc::c_char,
                1757 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 55],
                    &[libc::c_char; 55],
                >(b"void poly_marshal_mod3(uint8_t *, const struct poly *)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < 140 as libc::c_int as size_t {
        let coeffs0: uint16_t = mod3_from_modQ(
            *coeffs.offset(0 as libc::c_int as isize),
        );
        let coeffs1: uint16_t = mod3_from_modQ(
            *coeffs.offset(1 as libc::c_int as isize),
        );
        let coeffs2: uint16_t = mod3_from_modQ(
            *coeffs.offset(2 as libc::c_int as isize),
        );
        let coeffs3: uint16_t = mod3_from_modQ(
            *coeffs.offset(3 as libc::c_int as isize),
        );
        let coeffs4: uint16_t = mod3_from_modQ(
            *coeffs.offset(4 as libc::c_int as isize),
        );
        *out
            .offset(
                i as isize,
            ) = (coeffs0 as libc::c_int + coeffs1 as libc::c_int * 3 as libc::c_int
            + coeffs2 as libc::c_int * 9 as libc::c_int
            + coeffs3 as libc::c_int * 27 as libc::c_int
            + coeffs4 as libc::c_int * 81 as libc::c_int) as uint8_t;
        coeffs = coeffs.offset(5 as libc::c_int as isize);
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn poly_short_sample(mut out: *mut poly, mut in_0: *const uint8_t) {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < (701 as libc::c_int - 1 as libc::c_int) as size_t {
        let mut v: uint16_t = mod3(*in_0.offset(i as isize) as int16_t);
        v = (v as libc::c_int
            | (v as libc::c_int >> 1 as libc::c_int ^ 1 as libc::c_int)
                - 1 as libc::c_int) as uint16_t;
        (*out).v[i as usize] = v;
        i = i.wrapping_add(1);
        i;
    }
    (*out)
        .v[(701 as libc::c_int - 1 as libc::c_int)
        as usize] = 0 as libc::c_int as uint16_t;
    poly_normalize(out);
}
unsafe extern "C" fn poly_short_sample_plus(
    mut out: *mut poly,
    mut in_0: *const uint8_t,
) {
    poly_short_sample(out, in_0);
    let mut sum: uint16_t = 0 as libc::c_int as uint16_t;
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while i < (701 as libc::c_int - 2 as libc::c_int) as libc::c_uint {
        sum = (sum as libc::c_uint)
            .wrapping_add(
                ((*out).v[i as usize] as libc::c_uint)
                    .wrapping_mul(
                        (*out)
                            .v[i.wrapping_add(1 as libc::c_int as libc::c_uint) as usize]
                            as libc::c_uint,
                    ),
            ) as uint16_t as uint16_t;
        i = i.wrapping_add(1);
        i;
    }
    sum = (sum as int16_t as libc::c_int >> 15 as libc::c_int) as uint16_t;
    let scale: uint16_t = (sum as libc::c_int | !(sum as libc::c_int) & 1 as libc::c_int)
        as uint16_t;
    let mut i_0: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while i_0 < 701 as libc::c_int as libc::c_uint {
        (*out)
            .v[i_0
            as usize] = ((*out).v[i_0 as usize] as libc::c_uint)
            .wrapping_mul(scale as libc::c_uint) as uint16_t;
        i_0 = i_0.wrapping_add(2 as libc::c_int as libc::c_uint);
    }
    poly_assert_normalized(out);
}
unsafe extern "C" fn poly_lift(mut out: *mut poly, mut a: *const poly) {
    (*out)
        .v[0 as libc::c_int
        as usize] = ((*a).v[0 as libc::c_int as usize] as libc::c_int
        + (*a).v[2 as libc::c_int as usize] as libc::c_int) as uint16_t;
    (*out).v[1 as libc::c_int as usize] = (*a).v[1 as libc::c_int as usize];
    (*out)
        .v[2 as libc::c_int
        as usize] = (-((*a).v[0 as libc::c_int as usize] as libc::c_int)
        + (*a).v[2 as libc::c_int as usize] as libc::c_int) as uint16_t;
    let mut s0: uint16_t = 0 as libc::c_int as uint16_t;
    let mut s2: uint16_t = 0 as libc::c_int as uint16_t;
    let mut i: size_t = 3 as libc::c_int as size_t;
    while i < 699 as libc::c_int as size_t {
        s0 = (s0 as libc::c_int
            + (-((*a).v[i as usize] as libc::c_int)
                + (*a).v[i.wrapping_add(2 as libc::c_int as size_t) as usize]
                    as libc::c_int)) as uint16_t;
        s2 = (s2 as libc::c_int
            + ((*a).v[i.wrapping_add(1 as libc::c_int as size_t) as usize] as libc::c_int
                - (*a).v[i.wrapping_add(2 as libc::c_int as size_t) as usize]
                    as libc::c_int)) as uint16_t;
        i = i.wrapping_add(3 as libc::c_int as size_t);
    }
    s0 = (s0 as libc::c_int - (*a).v[699 as libc::c_int as usize] as libc::c_int)
        as uint16_t;
    s2 = (s2 as libc::c_int + (*a).v[700 as libc::c_int as usize] as libc::c_int)
        as uint16_t;
    (*out)
        .v[0 as libc::c_int
        as usize] = ((*out).v[0 as libc::c_int as usize] as libc::c_int
        + s0 as libc::c_int) as uint16_t;
    (*out)
        .v[1 as libc::c_int
        as usize] = ((*out).v[1 as libc::c_int as usize] as libc::c_int
        - (s0 as libc::c_int + s2 as libc::c_int)) as uint16_t;
    (*out)
        .v[2 as libc::c_int
        as usize] = ((*out).v[2 as libc::c_int as usize] as libc::c_int
        + s2 as libc::c_int) as uint16_t;
    let mut i_0: size_t = 3 as libc::c_int as size_t;
    while i_0 < 701 as libc::c_int as size_t {
        (*out)
            .v[i_0
            as usize] = ((*out).v[i_0.wrapping_sub(3 as libc::c_int as size_t) as usize]
            as libc::c_int
            - ((*a).v[i_0.wrapping_sub(2 as libc::c_int as size_t) as usize]
                as libc::c_int
                + (*a).v[i_0.wrapping_sub(1 as libc::c_int as size_t) as usize]
                    as libc::c_int + (*a).v[i_0 as usize] as libc::c_int)) as uint16_t;
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
    let v: crypto_word_t = (*out).v[700 as libc::c_int as usize] as crypto_word_t;
    let mut i_1: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while i_1 < 701 as libc::c_int as libc::c_uint {
        let vi_mod3: uint16_t = mod3(
            ((*out).v[i_1 as usize] as crypto_word_t).wrapping_sub(v) as int16_t,
        );
        (*out)
            .v[i_1
            as usize] = (!((vi_mod3 as libc::c_int >> 1 as libc::c_int)
            - 1 as libc::c_int) | vi_mod3 as libc::c_int) as uint16_t;
        i_1 = i_1.wrapping_add(1);
        i_1;
    }
    poly_mul_x_minus_1(out);
    poly_normalize(out);
}
unsafe extern "C" fn public_key_from_external(
    mut ext: *mut HRSS_public_key,
) -> *mut public_key {
    return align_pointer(
        ((*ext).opaque).as_mut_ptr() as *mut libc::c_void,
        16 as libc::c_int as size_t,
    ) as *mut public_key;
}
unsafe extern "C" fn private_key_from_external(
    mut ext: *mut HRSS_private_key,
) -> *mut private_key {
    return align_pointer(
        ((*ext).opaque).as_mut_ptr() as *mut libc::c_void,
        16 as libc::c_int as size_t,
    ) as *mut private_key;
}
unsafe extern "C" fn malloc_align32(
    mut out_ptr: *mut *mut libc::c_void,
    mut size: size_t,
) -> *mut libc::c_void {
    let mut ptr: *mut libc::c_void = OPENSSL_malloc(
        size.wrapping_add(31 as libc::c_int as size_t),
    );
    if ptr.is_null() {
        *out_ptr = 0 as *mut libc::c_void;
        return 0 as *mut libc::c_void;
    }
    *out_ptr = ptr;
    return align_pointer(ptr, 32 as libc::c_int as size_t);
}
#[no_mangle]
pub unsafe extern "C" fn HRSS_generate_key(
    mut out_pub: *mut HRSS_public_key,
    mut out_priv: *mut HRSS_private_key,
    mut in_0: *const uint8_t,
) -> libc::c_int {
    let mut pub_0: *mut public_key = public_key_from_external(out_pub);
    let mut priv_0: *mut private_key = private_key_from_external(out_priv);
    let mut malloc_ptr: *mut libc::c_void = 0 as *mut libc::c_void;
    let vars_0: *mut vars = malloc_align32(
        &mut malloc_ptr,
        ::core::mem::size_of::<vars>() as libc::c_ulong,
    ) as *mut vars;
    if vars_0.is_null() {
        memset(
            out_pub as *mut libc::c_void,
            0 as libc::c_int,
            ::core::mem::size_of::<HRSS_public_key>() as libc::c_ulong,
        );
        RAND_bytes(
            out_priv as *mut uint8_t,
            ::core::mem::size_of::<HRSS_private_key>() as libc::c_ulong,
        );
        return 0 as libc::c_int;
    }
    OPENSSL_memset(
        vars_0 as *mut libc::c_void,
        0xff as libc::c_int,
        ::core::mem::size_of::<vars>() as libc::c_ulong,
    );
    OPENSSL_memcpy(
        ((*priv_0).hmac_key).as_mut_ptr() as *mut libc::c_void,
        in_0
            .offset(
                (2 as libc::c_int * (701 as libc::c_int - 1 as libc::c_int)) as isize,
            ) as *const libc::c_void,
        ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
    );
    poly_short_sample_plus(&mut (*vars_0).f, in_0);
    poly3_from_poly(&mut (*priv_0).f, &mut (*vars_0).f);
    HRSS_poly3_invert(&mut (*priv_0).f_inverse, &mut (*priv_0).f);
    poly_short_sample_plus(
        &mut (*vars_0).pg_phi1,
        in_0.offset((701 as libc::c_int - 1 as libc::c_int) as isize),
    );
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while i < 701 as libc::c_int as libc::c_uint {
        (*vars_0)
            .pg_phi1
            .v[i
            as usize] = ((*vars_0).pg_phi1.v[i as usize] as libc::c_int
            * 3 as libc::c_int) as uint16_t;
        i = i.wrapping_add(1);
        i;
    }
    poly_mul_x_minus_1(&mut (*vars_0).pg_phi1);
    poly_mul(
        &mut (*vars_0).scratch,
        &mut (*vars_0).pfg_phi1,
        &mut (*vars_0).f,
        &mut (*vars_0).pg_phi1,
    );
    poly_invert(
        &mut (*vars_0).scratch,
        &mut (*vars_0).pfg_phi1_inverse,
        &mut (*vars_0).pfg_phi1,
    );
    poly_mul(
        &mut (*vars_0).scratch,
        &mut (*pub_0).ph,
        &mut (*vars_0).pfg_phi1_inverse,
        &mut (*vars_0).pg_phi1,
    );
    poly_mul(
        &mut (*vars_0).scratch,
        &mut (*pub_0).ph,
        &mut (*pub_0).ph,
        &mut (*vars_0).pg_phi1,
    );
    poly_clamp(&mut (*pub_0).ph);
    poly_mul(
        &mut (*vars_0).scratch,
        &mut (*priv_0).ph_inverse,
        &mut (*vars_0).pfg_phi1_inverse,
        &mut (*vars_0).f,
    );
    poly_mul(
        &mut (*vars_0).scratch,
        &mut (*priv_0).ph_inverse,
        &mut (*priv_0).ph_inverse,
        &mut (*vars_0).f,
    );
    poly_clamp(&mut (*priv_0).ph_inverse);
    OPENSSL_free(malloc_ptr);
    return 1 as libc::c_int;
}
static mut kSharedKey: [libc::c_char; 11] = unsafe {
    *::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"shared key\0")
};
#[no_mangle]
pub unsafe extern "C" fn HRSS_encap(
    mut out_ciphertext: *mut uint8_t,
    mut out_shared_key: *mut uint8_t,
    mut in_pub: *const HRSS_public_key,
    mut in_0: *const uint8_t,
) -> libc::c_int {
    let mut pub_0: *const public_key = public_key_from_external(
        in_pub as *mut HRSS_public_key,
    );
    let mut malloc_ptr: *mut libc::c_void = 0 as *mut libc::c_void;
    let vars_0: *mut vars_0 = malloc_align32(
        &mut malloc_ptr,
        ::core::mem::size_of::<vars_0>() as libc::c_ulong,
    ) as *mut vars_0;
    if vars_0.is_null() {
        memset(
            out_ciphertext as *mut libc::c_void,
            0 as libc::c_int,
            1138 as libc::c_int as libc::c_ulong,
        );
        RAND_bytes(out_shared_key, 32 as libc::c_int as size_t);
        return 0 as libc::c_int;
    }
    OPENSSL_memset(
        vars_0 as *mut libc::c_void,
        0xff as libc::c_int,
        ::core::mem::size_of::<vars_0>() as libc::c_ulong,
    );
    poly_short_sample(&mut (*vars_0).m, in_0);
    poly_short_sample(
        &mut (*vars_0).r,
        in_0.offset((701 as libc::c_int - 1 as libc::c_int) as isize),
    );
    poly_lift(&mut (*vars_0).m_lifted, &mut (*vars_0).m);
    poly_mul(
        &mut (*vars_0).scratch,
        &mut (*vars_0).prh_plus_m,
        &mut (*vars_0).r,
        &(*pub_0).ph,
    );
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while i < 701 as libc::c_int as libc::c_uint {
        (*vars_0)
            .prh_plus_m
            .v[i
            as usize] = ((*vars_0).prh_plus_m.v[i as usize] as libc::c_int
            + (*vars_0).m_lifted.v[i as usize] as libc::c_int) as uint16_t;
        i = i.wrapping_add(1);
        i;
    }
    poly_marshal(out_ciphertext, &mut (*vars_0).prh_plus_m);
    poly_marshal_mod3(((*vars_0).m_bytes).as_mut_ptr(), &mut (*vars_0).m);
    poly_marshal_mod3(((*vars_0).r_bytes).as_mut_ptr(), &mut (*vars_0).r);
    SHA256_Init(&mut (*vars_0).hash_ctx);
    SHA256_Update(
        &mut (*vars_0).hash_ctx,
        kSharedKey.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[libc::c_char; 11]>() as libc::c_ulong,
    );
    SHA256_Update(
        &mut (*vars_0).hash_ctx,
        ((*vars_0).m_bytes).as_mut_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint8_t; 140]>() as libc::c_ulong,
    );
    SHA256_Update(
        &mut (*vars_0).hash_ctx,
        ((*vars_0).r_bytes).as_mut_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint8_t; 140]>() as libc::c_ulong,
    );
    SHA256_Update(
        &mut (*vars_0).hash_ctx,
        out_ciphertext as *const libc::c_void,
        1138 as libc::c_int as size_t,
    );
    SHA256_Final(out_shared_key, &mut (*vars_0).hash_ctx);
    OPENSSL_free(malloc_ptr);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn HRSS_decap(
    mut out_shared_key: *mut uint8_t,
    mut in_priv: *const HRSS_private_key,
    mut ciphertext: *const uint8_t,
    mut ciphertext_len: size_t,
) -> libc::c_int {
    let mut ok: crypto_word_t = 0;
    let mut priv_0: *const private_key = private_key_from_external(
        in_priv as *mut HRSS_private_key,
    );
    let mut malloc_ptr: *mut libc::c_void = 0 as *mut libc::c_void;
    let vars_0: *mut vars_1 = malloc_align32(
        &mut malloc_ptr,
        ::core::mem::size_of::<vars_1>() as libc::c_ulong,
    ) as *mut vars_1;
    if vars_0.is_null() {
        RAND_bytes(out_shared_key, 32 as libc::c_int as size_t);
        return 0 as libc::c_int;
    }
    OPENSSL_memset(
        vars_0 as *mut libc::c_void,
        0xff as libc::c_int,
        ::core::mem::size_of::<vars_1>() as libc::c_ulong,
    );
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong {
        (*vars_0)
            .masked_key[i
            as usize] = ((*priv_0).hmac_key[i as usize] as libc::c_int
            ^ 0x36 as libc::c_int) as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
    OPENSSL_memset(
        ((*vars_0).masked_key)
            .as_mut_ptr()
            .offset(::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong as isize)
            as *mut libc::c_void,
        0x36 as libc::c_int,
        (::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong)
            .wrapping_sub(::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong),
    );
    SHA256_Init(&mut (*vars_0).hash_ctx);
    SHA256_Update(
        &mut (*vars_0).hash_ctx,
        ((*vars_0).masked_key).as_mut_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    SHA256_Update(
        &mut (*vars_0).hash_ctx,
        ciphertext as *const libc::c_void,
        ciphertext_len,
    );
    let mut inner_digest: [uint8_t; 32] = [0; 32];
    SHA256_Final(inner_digest.as_mut_ptr(), &mut (*vars_0).hash_ctx);
    let mut i_0: size_t = 0 as libc::c_int as size_t;
    while i_0 < ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong {
        (*vars_0)
            .masked_key[i_0
            as usize] = ((*vars_0).masked_key[i_0 as usize] as libc::c_int
            ^ (0x5c as libc::c_int ^ 0x36 as libc::c_int)) as uint8_t;
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
    OPENSSL_memset(
        ((*vars_0).masked_key)
            .as_mut_ptr()
            .offset(::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong as isize)
            as *mut libc::c_void,
        0x5c as libc::c_int,
        (::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong)
            .wrapping_sub(::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong),
    );
    SHA256_Init(&mut (*vars_0).hash_ctx);
    SHA256_Update(
        &mut (*vars_0).hash_ctx,
        ((*vars_0).masked_key).as_mut_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    SHA256_Update(
        &mut (*vars_0).hash_ctx,
        inner_digest.as_mut_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
    );
    SHA256_Final(out_shared_key, &mut (*vars_0).hash_ctx);
    if !(ciphertext_len != 1138 as libc::c_int as size_t
        || poly_unmarshal(&mut (*vars_0).c, ciphertext) == 0)
    {
        poly_from_poly3(&mut (*vars_0).f, &(*priv_0).f);
        poly_mul(
            &mut (*vars_0).scratch,
            &mut (*vars_0).cf,
            &mut (*vars_0).c,
            &mut (*vars_0).f,
        );
        poly3_from_poly(&mut (*vars_0).cf3, &mut (*vars_0).cf);
        HRSS_poly3_mul(&mut (*vars_0).m3, &mut (*vars_0).cf3, &(*priv_0).f_inverse);
        poly_from_poly3(&mut (*vars_0).m, &mut (*vars_0).m3);
        poly_lift(&mut (*vars_0).m_lifted, &mut (*vars_0).m);
        let mut i_1: libc::c_uint = 0 as libc::c_int as libc::c_uint;
        while i_1 < 701 as libc::c_int as libc::c_uint {
            (*vars_0)
                .r
                .v[i_1
                as usize] = ((*vars_0).c.v[i_1 as usize] as libc::c_int
                - (*vars_0).m_lifted.v[i_1 as usize] as libc::c_int) as uint16_t;
            i_1 = i_1.wrapping_add(1);
            i_1;
        }
        poly_normalize(&mut (*vars_0).r);
        poly_mul(
            &mut (*vars_0).scratch,
            &mut (*vars_0).r,
            &mut (*vars_0).r,
            &(*priv_0).ph_inverse,
        );
        poly_mod_phiN(&mut (*vars_0).r);
        poly_clamp(&mut (*vars_0).r);
        ok = poly3_from_poly_checked(&mut (*vars_0).r3, &mut (*vars_0).r);
        if ciphertext_len == ::core::mem::size_of::<[uint8_t; 1138]>() as libc::c_ulong
        {} else {
            __assert_fail(
                b"ciphertext_len == sizeof(vars->expected_ciphertext)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/hrss/hrss.c\0" as *const u8
                    as *const libc::c_char,
                2219 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 84],
                    &[libc::c_char; 84],
                >(
                    b"int HRSS_decap(uint8_t *, const struct HRSS_private_key *, const uint8_t *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_7825: {
            if ciphertext_len
                == ::core::mem::size_of::<[uint8_t; 1138]>() as libc::c_ulong
            {} else {
                __assert_fail(
                    b"ciphertext_len == sizeof(vars->expected_ciphertext)\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/hrss/hrss.c\0"
                        as *const u8 as *const libc::c_char,
                    2219 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 84],
                        &[libc::c_char; 84],
                    >(
                        b"int HRSS_decap(uint8_t *, const struct HRSS_private_key *, const uint8_t *, size_t)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        poly_marshal(((*vars_0).expected_ciphertext).as_mut_ptr(), &mut (*vars_0).c);
        poly_marshal_mod3(((*vars_0).m_bytes).as_mut_ptr(), &mut (*vars_0).m);
        poly_marshal_mod3(((*vars_0).r_bytes).as_mut_ptr(), &mut (*vars_0).r);
        ok
            &= constant_time_is_zero_w(
                CRYPTO_memcmp(
                    ciphertext as *const libc::c_void,
                    ((*vars_0).expected_ciphertext).as_mut_ptr() as *const libc::c_void,
                    ::core::mem::size_of::<[uint8_t; 1138]>() as libc::c_ulong,
                ) as crypto_word_t,
            );
        SHA256_Init(&mut (*vars_0).hash_ctx);
        SHA256_Update(
            &mut (*vars_0).hash_ctx,
            kSharedKey.as_ptr() as *const libc::c_void,
            ::core::mem::size_of::<[libc::c_char; 11]>() as libc::c_ulong,
        );
        SHA256_Update(
            &mut (*vars_0).hash_ctx,
            ((*vars_0).m_bytes).as_mut_ptr() as *const libc::c_void,
            ::core::mem::size_of::<[uint8_t; 140]>() as libc::c_ulong,
        );
        SHA256_Update(
            &mut (*vars_0).hash_ctx,
            ((*vars_0).r_bytes).as_mut_ptr() as *const libc::c_void,
            ::core::mem::size_of::<[uint8_t; 140]>() as libc::c_ulong,
        );
        SHA256_Update(
            &mut (*vars_0).hash_ctx,
            ((*vars_0).expected_ciphertext).as_mut_ptr() as *const libc::c_void,
            ::core::mem::size_of::<[uint8_t; 1138]>() as libc::c_ulong,
        );
        SHA256_Final(((*vars_0).shared_key).as_mut_ptr(), &mut (*vars_0).hash_ctx);
        let mut i_2: libc::c_uint = 0 as libc::c_int as libc::c_uint;
        while (i_2 as libc::c_ulong)
            < ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong
        {
            *out_shared_key
                .offset(
                    i_2 as isize,
                ) = constant_time_select_8(
                ok as uint8_t,
                (*vars_0).shared_key[i_2 as usize],
                *out_shared_key.offset(i_2 as isize),
            );
            i_2 = i_2.wrapping_add(1);
            i_2;
        }
    }
    OPENSSL_free(malloc_ptr);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn HRSS_marshal_public_key(
    mut out: *mut uint8_t,
    mut in_pub: *const HRSS_public_key,
) {
    let mut pub_0: *const public_key = public_key_from_external(
        in_pub as *mut HRSS_public_key,
    );
    poly_marshal(out, &(*pub_0).ph);
}
#[no_mangle]
pub unsafe extern "C" fn HRSS_parse_public_key(
    mut out: *mut HRSS_public_key,
    mut in_0: *const uint8_t,
) -> libc::c_int {
    let mut pub_0: *mut public_key = public_key_from_external(out);
    if poly_unmarshal(&mut (*pub_0).ph, in_0) == 0 {
        return 0 as libc::c_int;
    }
    OPENSSL_memset(
        &mut *((*pub_0).ph.v).as_mut_ptr().offset(701 as libc::c_int as isize)
            as *mut uint16_t as *mut libc::c_void,
        0 as libc::c_int,
        (3 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::core::mem::size_of::<uint16_t>() as libc::c_ulong),
    );
    return 1 as libc::c_int;
}
unsafe extern "C" fn run_static_initializers() {
    shift = (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
        .wrapping_mul(8 as libc::c_int as libc::c_ulong)
        .wrapping_sub(
            ((701 as libc::c_int - 1 as libc::c_int) as libc::c_ulong)
                .wrapping_rem(
                    (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                        .wrapping_mul(8 as libc::c_int as libc::c_ulong),
                ),
        );
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
