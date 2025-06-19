#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(asm, extern_types, label_break_value)]
use core::arch::asm;
unsafe extern "C" {
    pub type env_md_st;
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
    fn EVP_MD_type(md: *const EVP_MD) -> libc::c_int;
    fn SHA1_Init(sha: *mut SHA_CTX) -> libc::c_int;
    fn SHA1_Update(
        sha: *mut SHA_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn SHA1_Final(out: *mut uint8_t, sha: *mut SHA_CTX) -> libc::c_int;
    fn SHA1_Transform(sha: *mut SHA_CTX, block: *const uint8_t);
    fn SHA256_Init(sha: *mut SHA256_CTX) -> libc::c_int;
    fn SHA256_Update(
        sha: *mut SHA256_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn SHA256_Final(out: *mut uint8_t, sha: *mut SHA256_CTX) -> libc::c_int;
    fn SHA256_Transform(sha: *mut SHA256_CTX, block: *const uint8_t);
    fn SHA384_Init(sha: *mut SHA512_CTX) -> libc::c_int;
    fn SHA384_Update(
        sha: *mut SHA512_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn SHA384_Final(out: *mut uint8_t, sha: *mut SHA512_CTX) -> libc::c_int;
    fn SHA512_Transform(sha: *mut SHA512_CTX, block: *const uint8_t);
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type EVP_MD = env_md_st;
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
pub type SHA256_CTX = sha256_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sha512_state_st {
    pub h: [uint64_t; 8],
    pub Nl: uint64_t,
    pub Nh: uint64_t,
    pub p: [uint8_t; 128],
    pub num: libc::c_uint,
    pub md_len: libc::c_uint,
}
pub type SHA512_CTX = sha512_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sha_state_st {
    pub h: [uint32_t; 5],
    pub Nl: uint32_t,
    pub Nh: uint32_t,
    pub data: [uint8_t; 64],
    pub num: libc::c_uint,
}
pub type SHA_CTX = sha_state_st;
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
unsafe extern "C" fn value_barrier_w(mut a: crypto_word_t) -> crypto_word_t {
    asm!("", inlateout(reg) a, options(preserves_flags, pure, readonly, att_syntax));
    return a;
}
#[inline]
unsafe extern "C" fn value_barrier_u32(mut a: uint32_t) -> uint32_t {
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
unsafe extern "C" fn constant_time_lt_8(
    mut a: crypto_word_t,
    mut b: crypto_word_t,
) -> uint8_t {
    return constant_time_lt_w(a, b) as uint8_t;
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
unsafe extern "C" fn constant_time_declassify_int(mut v: libc::c_int) -> libc::c_int {
    return value_barrier_u32(v as uint32_t) as libc::c_int;
}
#[inline]
unsafe extern "C" fn CRYPTO_bswap4(mut x: uint32_t) -> uint32_t {
    return x.swap_bytes();
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
unsafe extern "C" fn CRYPTO_store_u32_be(mut out: *mut libc::c_void, mut v: uint32_t) {
    v = CRYPTO_bswap4(v);
    OPENSSL_memcpy(
        out,
        &mut v as *mut uint32_t as *const libc::c_void,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_tls_cbc_remove_padding(
    mut out_padding_ok: *mut crypto_word_t,
    mut out_len: *mut size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut block_size: size_t,
    mut mac_size: size_t,
) -> libc::c_int {
    let overhead: size_t = (1 as libc::c_int as size_t).wrapping_add(mac_size);
    if overhead > in_len {
        return 0 as libc::c_int;
    }
    let mut padding_length: size_t = *in_0
        .offset(in_len.wrapping_sub(1 as libc::c_int as size_t) as isize) as size_t;
    let mut good: crypto_word_t = constant_time_ge_w(
        in_len,
        overhead.wrapping_add(padding_length),
    );
    let mut to_check: size_t = 256 as libc::c_int as size_t;
    if to_check > in_len {
        to_check = in_len;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < to_check {
        let mut mask: uint8_t = constant_time_ge_8(padding_length, i);
        let mut b: uint8_t = *in_0
            .offset(
                in_len.wrapping_sub(1 as libc::c_int as size_t).wrapping_sub(i) as isize,
            );
        good &= !(mask as size_t & (padding_length ^ b as size_t));
        i = i.wrapping_add(1);
        i;
    }
    good = constant_time_eq_w(
        0xff as libc::c_int as crypto_word_t,
        good & 0xff as libc::c_int as crypto_word_t,
    );
    padding_length = good & padding_length.wrapping_add(1 as libc::c_int as size_t);
    *out_len = in_len.wrapping_sub(padding_length);
    *out_padding_ok = good;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_tls_cbc_copy_mac(
    mut out: *mut uint8_t,
    mut md_size: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut orig_len: size_t,
) {
    let mut rotated_mac1: [uint8_t; 64] = [0; 64];
    let mut rotated_mac2: [uint8_t; 64] = [0; 64];
    let mut rotated_mac: *mut uint8_t = rotated_mac1.as_mut_ptr();
    let mut rotated_mac_tmp: *mut uint8_t = rotated_mac2.as_mut_ptr();
    let mut mac_end: size_t = in_len;
    let mut mac_start: size_t = mac_end.wrapping_sub(md_size);
    if constant_time_declassify_int((orig_len >= in_len) as libc::c_int) != 0 {} else {
        __assert_fail(
            b"constant_time_declassify_int(orig_len >= in_len)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/tls_cbc.c\0"
                as *const u8 as *const libc::c_char,
            126 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 78],
                &[libc::c_char; 78],
            >(
                b"void EVP_tls_cbc_copy_mac(uint8_t *, size_t, const uint8_t *, size_t, size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_7686: {
        if constant_time_declassify_int((orig_len >= in_len) as libc::c_int) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(orig_len >= in_len)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/tls_cbc.c\0"
                    as *const u8 as *const libc::c_char,
                126 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 78],
                    &[libc::c_char; 78],
                >(
                    b"void EVP_tls_cbc_copy_mac(uint8_t *, size_t, const uint8_t *, size_t, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if constant_time_declassify_int((in_len >= md_size) as libc::c_int) != 0 {} else {
        __assert_fail(
            b"constant_time_declassify_int(in_len >= md_size)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/tls_cbc.c\0"
                as *const u8 as *const libc::c_char,
            127 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 78],
                &[libc::c_char; 78],
            >(
                b"void EVP_tls_cbc_copy_mac(uint8_t *, size_t, const uint8_t *, size_t, size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_7642: {
        if constant_time_declassify_int((in_len >= md_size) as libc::c_int) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(in_len >= md_size)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/tls_cbc.c\0"
                    as *const u8 as *const libc::c_char,
                127 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 78],
                    &[libc::c_char; 78],
                >(
                    b"void EVP_tls_cbc_copy_mac(uint8_t *, size_t, const uint8_t *, size_t, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if md_size <= 64 as libc::c_int as size_t {} else {
        __assert_fail(
            b"md_size <= EVP_MAX_MD_SIZE\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/tls_cbc.c\0"
                as *const u8 as *const libc::c_char,
            128 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 78],
                &[libc::c_char; 78],
            >(
                b"void EVP_tls_cbc_copy_mac(uint8_t *, size_t, const uint8_t *, size_t, size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_7603: {
        if md_size <= 64 as libc::c_int as size_t {} else {
            __assert_fail(
                b"md_size <= EVP_MAX_MD_SIZE\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/tls_cbc.c\0"
                    as *const u8 as *const libc::c_char,
                128 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 78],
                    &[libc::c_char; 78],
                >(
                    b"void EVP_tls_cbc_copy_mac(uint8_t *, size_t, const uint8_t *, size_t, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if md_size > 0 as libc::c_int as size_t {} else {
        __assert_fail(
            b"md_size > 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/tls_cbc.c\0"
                as *const u8 as *const libc::c_char,
            129 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 78],
                &[libc::c_char; 78],
            >(
                b"void EVP_tls_cbc_copy_mac(uint8_t *, size_t, const uint8_t *, size_t, size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_7561: {
        if md_size > 0 as libc::c_int as size_t {} else {
            __assert_fail(
                b"md_size > 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/tls_cbc.c\0"
                    as *const u8 as *const libc::c_char,
                129 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 78],
                    &[libc::c_char; 78],
                >(
                    b"void EVP_tls_cbc_copy_mac(uint8_t *, size_t, const uint8_t *, size_t, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut scan_start: size_t = 0 as libc::c_int as size_t;
    if orig_len
        > md_size
            .wrapping_add(255 as libc::c_int as size_t)
            .wrapping_add(1 as libc::c_int as size_t)
    {
        scan_start = orig_len
            .wrapping_sub(
                md_size
                    .wrapping_add(255 as libc::c_int as size_t)
                    .wrapping_add(1 as libc::c_int as size_t),
            );
    }
    let mut rotate_offset: size_t = 0 as libc::c_int as size_t;
    let mut mac_started: uint8_t = 0 as libc::c_int as uint8_t;
    OPENSSL_memset(rotated_mac as *mut libc::c_void, 0 as libc::c_int, md_size);
    let mut i: size_t = scan_start;
    let mut j: size_t = 0 as libc::c_int as size_t;
    while i < orig_len {
        if j >= md_size {
            j = j.wrapping_sub(md_size);
        }
        let mut is_mac_start: crypto_word_t = constant_time_eq_w(i, mac_start);
        mac_started = (mac_started as crypto_word_t | is_mac_start) as uint8_t;
        let mut mac_ended: uint8_t = constant_time_ge_8(i, mac_end);
        let ref mut fresh0 = *rotated_mac.offset(j as isize);
        *fresh0 = (*fresh0 as libc::c_int
            | *in_0.offset(i as isize) as libc::c_int & mac_started as libc::c_int
                & !(mac_ended as libc::c_int)) as uint8_t;
        rotate_offset |= j & is_mac_start;
        i = i.wrapping_add(1);
        i;
        j = j.wrapping_add(1);
        j;
    }
    let mut offset: size_t = 1 as libc::c_int as size_t;
    while offset < md_size {
        let skip_rotate: uint8_t = (rotate_offset & 1 as libc::c_int as size_t)
            .wrapping_sub(1 as libc::c_int as size_t) as uint8_t;
        let mut i_0: size_t = 0 as libc::c_int as size_t;
        let mut j_0: size_t = offset;
        while i_0 < md_size {
            if j_0 >= md_size {
                j_0 = j_0.wrapping_sub(md_size);
            }
            *rotated_mac_tmp
                .offset(
                    i_0 as isize,
                ) = constant_time_select_8(
                skip_rotate,
                *rotated_mac.offset(i_0 as isize),
                *rotated_mac.offset(j_0 as isize),
            );
            i_0 = i_0.wrapping_add(1);
            i_0;
            j_0 = j_0.wrapping_add(1);
            j_0;
        }
        let mut tmp: *mut uint8_t = rotated_mac;
        rotated_mac = rotated_mac_tmp;
        rotated_mac_tmp = tmp;
        offset <<= 1 as libc::c_int;
        rotate_offset >>= 1 as libc::c_int;
    }
    OPENSSL_memcpy(
        out as *mut libc::c_void,
        rotated_mac as *const libc::c_void,
        md_size,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_final_with_secret_suffix_sha1(
    mut ctx: *mut SHA_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
    mut max_len: size_t,
) -> libc::c_int {
    let mut max_len_bits: size_t = max_len << 3 as libc::c_int;
    if (*ctx).Nh != 0 as libc::c_int as uint32_t
        || max_len_bits >> 3 as libc::c_int != max_len
        || ((*ctx).Nl as size_t).wrapping_add(max_len_bits) < max_len_bits
        || ((*ctx).Nl as size_t).wrapping_add(max_len_bits)
            > 4294967295 as libc::c_uint as size_t
    {
        return 0 as libc::c_int;
    }
    let mut num_blocks: size_t = ((*ctx).num as size_t)
        .wrapping_add(len)
        .wrapping_add(1 as libc::c_int as size_t)
        .wrapping_add(8 as libc::c_int as size_t)
        .wrapping_add(64 as libc::c_int as size_t)
        .wrapping_sub(1 as libc::c_int as size_t) >> 6 as libc::c_int;
    let mut last_block: size_t = num_blocks.wrapping_sub(1 as libc::c_int as size_t);
    let mut max_blocks: size_t = ((*ctx).num as size_t)
        .wrapping_add(max_len)
        .wrapping_add(1 as libc::c_int as size_t)
        .wrapping_add(8 as libc::c_int as size_t)
        .wrapping_add(64 as libc::c_int as size_t)
        .wrapping_sub(1 as libc::c_int as size_t) >> 6 as libc::c_int;
    let mut total_bits: size_t = ((*ctx).Nl as size_t)
        .wrapping_add(len << 3 as libc::c_int);
    let mut length_bytes: [uint8_t; 4] = [0; 4];
    length_bytes[0 as libc::c_int
        as usize] = (total_bits >> 24 as libc::c_int) as uint8_t;
    length_bytes[1 as libc::c_int
        as usize] = (total_bits >> 16 as libc::c_int) as uint8_t;
    length_bytes[2 as libc::c_int
        as usize] = (total_bits >> 8 as libc::c_int) as uint8_t;
    length_bytes[3 as libc::c_int as usize] = total_bits as uint8_t;
    let mut block: [uint8_t; 64] = [
        0 as libc::c_int as uint8_t,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    let mut result: [uint32_t; 5] = [0 as libc::c_int as uint32_t, 0, 0, 0, 0];
    let mut input_idx: size_t = 0 as libc::c_int as size_t;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < max_blocks {
        let mut block_start: size_t = 0 as libc::c_int as size_t;
        if i == 0 as libc::c_int as size_t {
            OPENSSL_memcpy(
                block.as_mut_ptr() as *mut libc::c_void,
                ((*ctx).data).as_mut_ptr() as *const libc::c_void,
                (*ctx).num as size_t,
            );
            block_start = (*ctx).num as size_t;
        }
        if input_idx < max_len {
            let mut to_copy: size_t = (64 as libc::c_int as size_t)
                .wrapping_sub(block_start);
            if to_copy > max_len.wrapping_sub(input_idx) {
                to_copy = max_len.wrapping_sub(input_idx);
            }
            OPENSSL_memcpy(
                block.as_mut_ptr().offset(block_start as isize) as *mut libc::c_void,
                in_0.offset(input_idx as isize) as *const libc::c_void,
                to_copy,
            );
        }
        let mut j: size_t = block_start;
        while j < 64 as libc::c_int as size_t {
            let mut idx: size_t = input_idx.wrapping_add(j).wrapping_sub(block_start);
            let mut is_in_bounds: uint8_t = constant_time_lt_8(
                idx,
                value_barrier_w(len),
            );
            let mut is_padding_byte: uint8_t = constant_time_eq_8(
                idx,
                value_barrier_w(len),
            );
            block[j
                as usize] = (block[j as usize] as libc::c_int
                & is_in_bounds as libc::c_int) as uint8_t;
            block[j
                as usize] = (block[j as usize] as libc::c_int
                | 0x80 as libc::c_int & is_padding_byte as libc::c_int) as uint8_t;
            j = j.wrapping_add(1);
            j;
        }
        input_idx = input_idx
            .wrapping_add((64 as libc::c_int as size_t).wrapping_sub(block_start));
        let mut is_last_block: crypto_word_t = constant_time_eq_w(i, last_block);
        let mut j_0: size_t = 0 as libc::c_int as size_t;
        while j_0 < 4 as libc::c_int as size_t {
            block[((64 as libc::c_int - 4 as libc::c_int) as size_t).wrapping_add(j_0)
                as usize] = (block[((64 as libc::c_int - 4 as libc::c_int) as size_t)
                .wrapping_add(j_0) as usize] as crypto_word_t
                | is_last_block & length_bytes[j_0 as usize] as crypto_word_t)
                as uint8_t;
            j_0 = j_0.wrapping_add(1);
            j_0;
        }
        SHA1_Transform(ctx, block.as_mut_ptr() as *const uint8_t);
        let mut j_1: size_t = 0 as libc::c_int as size_t;
        while j_1 < 5 as libc::c_int as size_t {
            result[j_1
                as usize] = (result[j_1 as usize] as crypto_word_t
                | is_last_block & (*ctx).h[j_1 as usize] as crypto_word_t) as uint32_t;
            j_1 = j_1.wrapping_add(1);
            j_1;
        }
        i = i.wrapping_add(1);
        i;
    }
    let mut i_0: size_t = 0 as libc::c_int as size_t;
    while i_0 < 5 as libc::c_int as size_t {
        CRYPTO_store_u32_be(
            out.offset((4 as libc::c_int as size_t * i_0) as isize) as *mut libc::c_void,
            result[i_0 as usize],
        );
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn EVP_tls_cbc_digest_record_sha1(
    mut md_out: *mut uint8_t,
    mut md_out_size: *mut size_t,
    mut header: *const uint8_t,
    mut data: *const uint8_t,
    mut data_size: size_t,
    mut data_plus_mac_plus_padding_size: size_t,
    mut mac_secret: *const uint8_t,
    mut mac_secret_length: libc::c_uint,
) -> libc::c_int {
    if mac_secret_length > 64 as libc::c_int as libc::c_uint {
        __assert_fail(
            b"0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/tls_cbc.c\0"
                as *const u8 as *const libc::c_char,
            280 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 137],
                &[libc::c_char; 137],
            >(
                b"int EVP_tls_cbc_digest_record_sha1(uint8_t *, size_t *, const uint8_t *, const uint8_t *, size_t, size_t, const uint8_t *, unsigned int)\0",
            ))
                .as_ptr(),
        );
        'c_10170: {
            __assert_fail(
                b"0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/tls_cbc.c\0"
                    as *const u8 as *const libc::c_char,
                280 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 137],
                    &[libc::c_char; 137],
                >(
                    b"int EVP_tls_cbc_digest_record_sha1(uint8_t *, size_t *, const uint8_t *, const uint8_t *, size_t, size_t, const uint8_t *, unsigned int)\0",
                ))
                    .as_ptr(),
            );
        };
        return 0 as libc::c_int;
    }
    let mut hmac_pad: [uint8_t; 64] = [0; 64];
    OPENSSL_memset(
        hmac_pad.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    OPENSSL_memcpy(
        hmac_pad.as_mut_ptr() as *mut libc::c_void,
        mac_secret as *const libc::c_void,
        mac_secret_length as size_t,
    );
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < 64 as libc::c_int as size_t {
        hmac_pad[i
            as usize] = (hmac_pad[i as usize] as libc::c_int ^ 0x36 as libc::c_int)
            as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
    let mut ctx: SHA_CTX = sha_state_st {
        h: [0; 5],
        Nl: 0,
        Nh: 0,
        data: [0; 64],
        num: 0,
    };
    SHA1_Init(&mut ctx);
    SHA1_Update(
        &mut ctx,
        hmac_pad.as_mut_ptr() as *const libc::c_void,
        64 as libc::c_int as size_t,
    );
    SHA1_Update(&mut ctx, header as *const libc::c_void, 13 as libc::c_int as size_t);
    let mut min_data_size: size_t = 0 as libc::c_int as size_t;
    if data_plus_mac_plus_padding_size
        > (20 as libc::c_int + 256 as libc::c_int) as size_t
    {
        min_data_size = data_plus_mac_plus_padding_size
            .wrapping_sub(20 as libc::c_int as size_t)
            .wrapping_sub(256 as libc::c_int as size_t);
    }
    SHA1_Update(&mut ctx, data as *const libc::c_void, min_data_size);
    let mut mac_out: [uint8_t; 20] = [0; 20];
    if EVP_final_with_secret_suffix_sha1(
        &mut ctx,
        mac_out.as_mut_ptr(),
        data.offset(min_data_size as isize),
        data_size.wrapping_sub(min_data_size),
        data_plus_mac_plus_padding_size.wrapping_sub(min_data_size),
    ) == 0
    {
        return 0 as libc::c_int;
    }
    SHA1_Init(&mut ctx);
    let mut i_0: size_t = 0 as libc::c_int as size_t;
    while i_0 < 64 as libc::c_int as size_t {
        hmac_pad[i_0
            as usize] = (hmac_pad[i_0 as usize] as libc::c_int ^ 0x6a as libc::c_int)
            as uint8_t;
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
    SHA1_Update(
        &mut ctx,
        hmac_pad.as_mut_ptr() as *const libc::c_void,
        64 as libc::c_int as size_t,
    );
    SHA1_Update(
        &mut ctx,
        mac_out.as_mut_ptr() as *const libc::c_void,
        20 as libc::c_int as size_t,
    );
    SHA1_Final(md_out, &mut ctx);
    *md_out_size = 20 as libc::c_int as size_t;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_final_with_secret_suffix_sha256(
    mut ctx: *mut SHA256_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
    mut max_len: size_t,
) -> libc::c_int {
    let mut max_len_bits: size_t = max_len << 3 as libc::c_int;
    if (*ctx).Nh != 0 as libc::c_int as uint32_t
        || max_len_bits >> 3 as libc::c_int != max_len
        || ((*ctx).Nl as size_t).wrapping_add(max_len_bits) < max_len_bits
        || ((*ctx).Nl as size_t).wrapping_add(max_len_bits)
            > 4294967295 as libc::c_uint as size_t
    {
        return 0 as libc::c_int;
    }
    let mut num_blocks: size_t = ((*ctx).num as size_t)
        .wrapping_add(len)
        .wrapping_add(1 as libc::c_int as size_t)
        .wrapping_add(8 as libc::c_int as size_t)
        .wrapping_add(64 as libc::c_int as size_t)
        .wrapping_sub(1 as libc::c_int as size_t) >> 6 as libc::c_int;
    let mut last_block: size_t = num_blocks.wrapping_sub(1 as libc::c_int as size_t);
    let mut max_blocks: size_t = ((*ctx).num as size_t)
        .wrapping_add(max_len)
        .wrapping_add(1 as libc::c_int as size_t)
        .wrapping_add(8 as libc::c_int as size_t)
        .wrapping_add(64 as libc::c_int as size_t)
        .wrapping_sub(1 as libc::c_int as size_t) >> 6 as libc::c_int;
    let mut total_bits: size_t = ((*ctx).Nl as size_t)
        .wrapping_add(len << 3 as libc::c_int);
    let mut length_bytes: [uint8_t; 4] = [0; 4];
    length_bytes[0 as libc::c_int
        as usize] = (total_bits >> 24 as libc::c_int) as uint8_t;
    length_bytes[1 as libc::c_int
        as usize] = (total_bits >> 16 as libc::c_int) as uint8_t;
    length_bytes[2 as libc::c_int
        as usize] = (total_bits >> 8 as libc::c_int) as uint8_t;
    length_bytes[3 as libc::c_int as usize] = total_bits as uint8_t;
    let mut block: [uint8_t; 64] = [
        0 as libc::c_int as uint8_t,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    let mut result: [uint32_t; 8] = [0 as libc::c_int as uint32_t, 0, 0, 0, 0, 0, 0, 0];
    let mut input_idx: size_t = 0 as libc::c_int as size_t;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < max_blocks {
        let mut block_start: size_t = 0 as libc::c_int as size_t;
        if i == 0 as libc::c_int as size_t {
            OPENSSL_memcpy(
                block.as_mut_ptr() as *mut libc::c_void,
                ((*ctx).data).as_mut_ptr() as *const libc::c_void,
                (*ctx).num as size_t,
            );
            block_start = (*ctx).num as size_t;
        }
        if input_idx < max_len {
            let mut to_copy: size_t = (64 as libc::c_int as size_t)
                .wrapping_sub(block_start);
            if to_copy > max_len.wrapping_sub(input_idx) {
                to_copy = max_len.wrapping_sub(input_idx);
            }
            OPENSSL_memcpy(
                block.as_mut_ptr().offset(block_start as isize) as *mut libc::c_void,
                in_0.offset(input_idx as isize) as *const libc::c_void,
                to_copy,
            );
        }
        let mut j: size_t = block_start;
        while j < 64 as libc::c_int as size_t {
            let mut idx: size_t = input_idx.wrapping_add(j).wrapping_sub(block_start);
            let mut is_in_bounds: uint8_t = constant_time_lt_8(
                idx,
                value_barrier_w(len),
            );
            let mut is_padding_byte: uint8_t = constant_time_eq_8(
                idx,
                value_barrier_w(len),
            );
            block[j
                as usize] = (block[j as usize] as libc::c_int
                & is_in_bounds as libc::c_int) as uint8_t;
            block[j
                as usize] = (block[j as usize] as libc::c_int
                | 0x80 as libc::c_int & is_padding_byte as libc::c_int) as uint8_t;
            j = j.wrapping_add(1);
            j;
        }
        input_idx = input_idx
            .wrapping_add((64 as libc::c_int as size_t).wrapping_sub(block_start));
        let mut is_last_block: crypto_word_t = constant_time_eq_w(i, last_block);
        let mut j_0: size_t = 0 as libc::c_int as size_t;
        while j_0 < 4 as libc::c_int as size_t {
            block[((64 as libc::c_int - 4 as libc::c_int) as size_t).wrapping_add(j_0)
                as usize] = (block[((64 as libc::c_int - 4 as libc::c_int) as size_t)
                .wrapping_add(j_0) as usize] as crypto_word_t
                | is_last_block & length_bytes[j_0 as usize] as crypto_word_t)
                as uint8_t;
            j_0 = j_0.wrapping_add(1);
            j_0;
        }
        SHA256_Transform(ctx, block.as_mut_ptr() as *const uint8_t);
        let mut j_1: size_t = 0 as libc::c_int as size_t;
        while j_1 < 8 as libc::c_int as size_t {
            result[j_1
                as usize] = (result[j_1 as usize] as crypto_word_t
                | is_last_block & (*ctx).h[j_1 as usize] as crypto_word_t) as uint32_t;
            j_1 = j_1.wrapping_add(1);
            j_1;
        }
        i = i.wrapping_add(1);
        i;
    }
    let mut i_0: size_t = 0 as libc::c_int as size_t;
    while i_0 < 8 as libc::c_int as size_t {
        CRYPTO_store_u32_be(
            out.offset((4 as libc::c_int as size_t * i_0) as isize) as *mut libc::c_void,
            result[i_0 as usize],
        );
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn EVP_tls_cbc_digest_record_sha256(
    mut md_out: *mut uint8_t,
    mut md_out_size: *mut size_t,
    mut header: *const uint8_t,
    mut data: *const uint8_t,
    mut data_size: size_t,
    mut data_plus_mac_plus_padding_size: size_t,
    mut mac_secret: *const uint8_t,
    mut mac_secret_length: libc::c_uint,
) -> libc::c_int {
    if mac_secret_length > 64 as libc::c_int as libc::c_uint {
        __assert_fail(
            b"0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/tls_cbc.c\0"
                as *const u8 as *const libc::c_char,
            430 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 139],
                &[libc::c_char; 139],
            >(
                b"int EVP_tls_cbc_digest_record_sha256(uint8_t *, size_t *, const uint8_t *, const uint8_t *, size_t, size_t, const uint8_t *, unsigned int)\0",
            ))
                .as_ptr(),
        );
        'c_9880: {
            __assert_fail(
                b"0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/tls_cbc.c\0"
                    as *const u8 as *const libc::c_char,
                430 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 139],
                    &[libc::c_char; 139],
                >(
                    b"int EVP_tls_cbc_digest_record_sha256(uint8_t *, size_t *, const uint8_t *, const uint8_t *, size_t, size_t, const uint8_t *, unsigned int)\0",
                ))
                    .as_ptr(),
            );
        };
        return 0 as libc::c_int;
    }
    let mut hmac_pad: [uint8_t; 64] = [0; 64];
    OPENSSL_memset(
        hmac_pad.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    OPENSSL_memcpy(
        hmac_pad.as_mut_ptr() as *mut libc::c_void,
        mac_secret as *const libc::c_void,
        mac_secret_length as size_t,
    );
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < 64 as libc::c_int as size_t {
        hmac_pad[i
            as usize] = (hmac_pad[i as usize] as libc::c_int ^ 0x36 as libc::c_int)
            as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
    let mut ctx: SHA256_CTX = sha256_state_st {
        h: [0; 8],
        Nl: 0,
        Nh: 0,
        data: [0; 64],
        num: 0,
        md_len: 0,
    };
    SHA256_Init(&mut ctx);
    SHA256_Update(
        &mut ctx,
        hmac_pad.as_mut_ptr() as *const libc::c_void,
        64 as libc::c_int as size_t,
    );
    SHA256_Update(&mut ctx, header as *const libc::c_void, 13 as libc::c_int as size_t);
    let mut min_data_size: size_t = 0 as libc::c_int as size_t;
    if data_plus_mac_plus_padding_size
        > (32 as libc::c_int + 256 as libc::c_int) as size_t
    {
        min_data_size = data_plus_mac_plus_padding_size
            .wrapping_sub(32 as libc::c_int as size_t)
            .wrapping_sub(256 as libc::c_int as size_t);
    }
    SHA256_Update(&mut ctx, data as *const libc::c_void, min_data_size);
    let mut mac_out: [uint8_t; 32] = [0; 32];
    if EVP_final_with_secret_suffix_sha256(
        &mut ctx,
        mac_out.as_mut_ptr(),
        data.offset(min_data_size as isize),
        data_size.wrapping_sub(min_data_size),
        data_plus_mac_plus_padding_size.wrapping_sub(min_data_size),
    ) == 0
    {
        return 0 as libc::c_int;
    }
    SHA256_Init(&mut ctx);
    let mut i_0: size_t = 0 as libc::c_int as size_t;
    while i_0 < 64 as libc::c_int as size_t {
        hmac_pad[i_0
            as usize] = (hmac_pad[i_0 as usize] as libc::c_int ^ 0x6a as libc::c_int)
            as uint8_t;
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
    SHA256_Update(
        &mut ctx,
        hmac_pad.as_mut_ptr() as *const libc::c_void,
        64 as libc::c_int as size_t,
    );
    SHA256_Update(
        &mut ctx,
        mac_out.as_mut_ptr() as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
    SHA256_Final(md_out, &mut ctx);
    *md_out_size = 32 as libc::c_int as size_t;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_final_with_secret_suffix_sha384(
    mut ctx: *mut SHA512_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
    mut max_len: size_t,
) -> libc::c_int {
    let mut max_len_bits: size_t = max_len << 3 as libc::c_int;
    if (*ctx).Nh != 0 as libc::c_int as uint64_t
        || max_len_bits >> 3 as libc::c_int != max_len
        || ((*ctx).Nl).wrapping_add(max_len_bits) < max_len_bits
        || ((*ctx).Nl).wrapping_add(max_len_bits)
            > 4294967295 as libc::c_uint as libc::c_ulong
    {
        return 0 as libc::c_int;
    }
    let mut num_blocks: size_t = ((*ctx).num as size_t)
        .wrapping_add(len)
        .wrapping_add(1 as libc::c_int as size_t)
        .wrapping_add(16 as libc::c_int as size_t)
        .wrapping_add(128 as libc::c_int as size_t)
        .wrapping_sub(1 as libc::c_int as size_t) >> 7 as libc::c_int;
    let mut last_block: size_t = num_blocks.wrapping_sub(1 as libc::c_int as size_t);
    let mut max_blocks: size_t = ((*ctx).num as size_t)
        .wrapping_add(max_len)
        .wrapping_add(1 as libc::c_int as size_t)
        .wrapping_add(16 as libc::c_int as size_t)
        .wrapping_add(128 as libc::c_int as size_t)
        .wrapping_sub(1 as libc::c_int as size_t) >> 7 as libc::c_int;
    let mut total_bits: size_t = ((*ctx).Nl).wrapping_add(len << 3 as libc::c_int);
    let mut length_bytes: [uint8_t; 4] = [0; 4];
    length_bytes[0 as libc::c_int
        as usize] = (total_bits >> 24 as libc::c_int) as uint8_t;
    length_bytes[1 as libc::c_int
        as usize] = (total_bits >> 16 as libc::c_int) as uint8_t;
    length_bytes[2 as libc::c_int
        as usize] = (total_bits >> 8 as libc::c_int) as uint8_t;
    length_bytes[3 as libc::c_int as usize] = total_bits as uint8_t;
    let mut block: [uint8_t; 128] = [
        0 as libc::c_int as uint8_t,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    let mut result: [uint64_t; 8] = [0 as libc::c_int as uint64_t, 0, 0, 0, 0, 0, 0, 0];
    let mut input_idx: size_t = 0 as libc::c_int as size_t;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < max_blocks {
        let mut block_start: size_t = 0 as libc::c_int as size_t;
        if i == 0 as libc::c_int as size_t {
            OPENSSL_memcpy(
                block.as_mut_ptr() as *mut libc::c_void,
                ((*ctx).p).as_mut_ptr() as *const libc::c_void,
                (*ctx).num as size_t,
            );
            block_start = (*ctx).num as size_t;
        }
        if input_idx < max_len {
            let mut to_copy: size_t = (128 as libc::c_int as size_t)
                .wrapping_sub(block_start);
            if to_copy > max_len.wrapping_sub(input_idx) {
                to_copy = max_len.wrapping_sub(input_idx);
            }
            OPENSSL_memcpy(
                block.as_mut_ptr().offset(block_start as isize) as *mut libc::c_void,
                in_0.offset(input_idx as isize) as *const libc::c_void,
                to_copy,
            );
        }
        let mut j: size_t = block_start;
        while j < 128 as libc::c_int as size_t {
            let mut idx: size_t = input_idx.wrapping_add(j).wrapping_sub(block_start);
            let mut is_in_bounds: uint8_t = constant_time_lt_8(
                idx,
                value_barrier_w(len),
            );
            let mut is_padding_byte: uint8_t = constant_time_eq_8(
                idx,
                value_barrier_w(len),
            );
            block[j
                as usize] = (block[j as usize] as libc::c_int
                & is_in_bounds as libc::c_int) as uint8_t;
            block[j
                as usize] = (block[j as usize] as libc::c_int
                | 0x80 as libc::c_int & is_padding_byte as libc::c_int) as uint8_t;
            j = j.wrapping_add(1);
            j;
        }
        input_idx = input_idx
            .wrapping_add((128 as libc::c_int as size_t).wrapping_sub(block_start));
        let mut is_last_block: crypto_word_t = constant_time_eq_w(i, last_block);
        let mut j_0: size_t = 0 as libc::c_int as size_t;
        while j_0 < 4 as libc::c_int as size_t {
            block[((128 as libc::c_int - 4 as libc::c_int) as size_t).wrapping_add(j_0)
                as usize] = (block[((128 as libc::c_int - 4 as libc::c_int) as size_t)
                .wrapping_add(j_0) as usize] as crypto_word_t
                | is_last_block & length_bytes[j_0 as usize] as crypto_word_t)
                as uint8_t;
            j_0 = j_0.wrapping_add(1);
            j_0;
        }
        if 128 as libc::c_int == 128 as libc::c_int {} else {
            __assert_fail(
                b"SHA384_CBLOCK == SHA512_CBLOCK\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/tls_cbc.c\0"
                    as *const u8 as *const libc::c_char,
                571 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 98],
                    &[libc::c_char; 98],
                >(
                    b"int EVP_final_with_secret_suffix_sha384(SHA512_CTX *, uint8_t *, const uint8_t *, size_t, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_8913: {
            if 128 as libc::c_int == 128 as libc::c_int {} else {
                __assert_fail(
                    b"SHA384_CBLOCK == SHA512_CBLOCK\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/tls_cbc.c\0"
                        as *const u8 as *const libc::c_char,
                    571 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 98],
                        &[libc::c_char; 98],
                    >(
                        b"int EVP_final_with_secret_suffix_sha384(SHA512_CTX *, uint8_t *, const uint8_t *, size_t, size_t)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        SHA512_Transform(ctx, block.as_mut_ptr() as *const uint8_t);
        let mut mask: uint64_t = is_last_block;
        let mut j_1: size_t = 0 as libc::c_int as size_t;
        while j_1 < 8 as libc::c_int as size_t {
            result[j_1 as usize] |= mask & (*ctx).h[j_1 as usize];
            j_1 = j_1.wrapping_add(1);
            j_1;
        }
        i = i.wrapping_add(1);
        i;
    }
    let mut i_0: size_t = 0 as libc::c_int as size_t;
    while i_0 < 6 as libc::c_int as size_t {
        CRYPTO_store_u64_be(
            out.offset((8 as libc::c_int as size_t * i_0) as isize) as *mut libc::c_void,
            result[i_0 as usize],
        );
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn EVP_tls_cbc_digest_record_sha384(
    mut md_out: *mut uint8_t,
    mut md_out_size: *mut size_t,
    mut header: *const uint8_t,
    mut data: *const uint8_t,
    mut data_size: size_t,
    mut data_plus_mac_plus_padding_size: size_t,
    mut mac_secret: *const uint8_t,
    mut mac_secret_length: libc::c_uint,
) -> libc::c_int {
    if mac_secret_length > 128 as libc::c_int as libc::c_uint {
        __assert_fail(
            b"0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/tls_cbc.c\0"
                as *const u8 as *const libc::c_char,
            603 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 139],
                &[libc::c_char; 139],
            >(
                b"int EVP_tls_cbc_digest_record_sha384(uint8_t *, size_t *, const uint8_t *, const uint8_t *, size_t, size_t, const uint8_t *, unsigned int)\0",
            ))
                .as_ptr(),
        );
        'c_9590: {
            __assert_fail(
                b"0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/tls_cbc.c\0"
                    as *const u8 as *const libc::c_char,
                603 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 139],
                    &[libc::c_char; 139],
                >(
                    b"int EVP_tls_cbc_digest_record_sha384(uint8_t *, size_t *, const uint8_t *, const uint8_t *, size_t, size_t, const uint8_t *, unsigned int)\0",
                ))
                    .as_ptr(),
            );
        };
        return 0 as libc::c_int;
    }
    let mut hmac_pad: [uint8_t; 128] = [0; 128];
    OPENSSL_memset(
        hmac_pad.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[uint8_t; 128]>() as libc::c_ulong,
    );
    OPENSSL_memcpy(
        hmac_pad.as_mut_ptr() as *mut libc::c_void,
        mac_secret as *const libc::c_void,
        mac_secret_length as size_t,
    );
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < 128 as libc::c_int as size_t {
        hmac_pad[i
            as usize] = (hmac_pad[i as usize] as libc::c_int ^ 0x36 as libc::c_int)
            as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
    let mut ctx: SHA512_CTX = sha512_state_st {
        h: [0; 8],
        Nl: 0,
        Nh: 0,
        p: [0; 128],
        num: 0,
        md_len: 0,
    };
    SHA384_Init(&mut ctx);
    SHA384_Update(
        &mut ctx,
        hmac_pad.as_mut_ptr() as *const libc::c_void,
        128 as libc::c_int as size_t,
    );
    SHA384_Update(&mut ctx, header as *const libc::c_void, 13 as libc::c_int as size_t);
    let mut min_data_size: size_t = 0 as libc::c_int as size_t;
    if data_plus_mac_plus_padding_size
        > (48 as libc::c_int + 256 as libc::c_int) as size_t
    {
        min_data_size = data_plus_mac_plus_padding_size
            .wrapping_sub(48 as libc::c_int as size_t)
            .wrapping_sub(256 as libc::c_int as size_t);
    }
    SHA384_Update(&mut ctx, data as *const libc::c_void, min_data_size);
    let mut mac_out: [uint8_t; 48] = [0; 48];
    if EVP_final_with_secret_suffix_sha384(
        &mut ctx,
        mac_out.as_mut_ptr(),
        data.offset(min_data_size as isize),
        data_size.wrapping_sub(min_data_size),
        data_plus_mac_plus_padding_size.wrapping_sub(min_data_size),
    ) == 0
    {
        return 0 as libc::c_int;
    }
    SHA384_Init(&mut ctx);
    let mut i_0: size_t = 0 as libc::c_int as size_t;
    while i_0 < 128 as libc::c_int as size_t {
        hmac_pad[i_0
            as usize] = (hmac_pad[i_0 as usize] as libc::c_int ^ 0x6a as libc::c_int)
            as uint8_t;
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
    SHA384_Update(
        &mut ctx,
        hmac_pad.as_mut_ptr() as *const libc::c_void,
        128 as libc::c_int as size_t,
    );
    SHA384_Update(
        &mut ctx,
        mac_out.as_mut_ptr() as *const libc::c_void,
        48 as libc::c_int as size_t,
    );
    SHA384_Final(md_out, &mut ctx);
    *md_out_size = 48 as libc::c_int as size_t;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_tls_cbc_record_digest_supported(
    mut md: *const EVP_MD,
) -> libc::c_int {
    return (EVP_MD_type(md) == 64 as libc::c_int || EVP_MD_type(md) == 672 as libc::c_int
        || EVP_MD_type(md) == 673 as libc::c_int) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_tls_cbc_digest_record(
    mut md: *const EVP_MD,
    mut md_out: *mut uint8_t,
    mut md_out_size: *mut size_t,
    mut header: *const uint8_t,
    mut data: *const uint8_t,
    mut data_size: size_t,
    mut data_plus_mac_plus_padding_size: size_t,
    mut mac_secret: *const uint8_t,
    mut mac_secret_length: libc::c_uint,
) -> libc::c_int {
    if EVP_MD_type(md) == 64 as libc::c_int {
        return EVP_tls_cbc_digest_record_sha1(
            md_out,
            md_out_size,
            header,
            data,
            data_size,
            data_plus_mac_plus_padding_size,
            mac_secret,
            mac_secret_length,
        )
    } else if EVP_MD_type(md) == 672 as libc::c_int {
        return EVP_tls_cbc_digest_record_sha256(
            md_out,
            md_out_size,
            header,
            data,
            data_size,
            data_plus_mac_plus_padding_size,
            mac_secret,
            mac_secret_length,
        )
    } else if EVP_MD_type(md) == 673 as libc::c_int {
        return EVP_tls_cbc_digest_record_sha384(
            md_out,
            md_out_size,
            header,
            data,
            data_size,
            data_plus_mac_plus_padding_size,
            mac_secret,
            mac_secret_length,
        )
    }
    __assert_fail(
        b"0\0" as *const u8 as *const libc::c_char,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/tls_cbc.c\0" as *const u8
            as *const libc::c_char,
        683 as libc::c_int as libc::c_uint,
        (*::core::mem::transmute::<
            &[u8; 148],
            &[libc::c_char; 148],
        >(
            b"int EVP_tls_cbc_digest_record(const EVP_MD *, uint8_t *, size_t *, const uint8_t *, const uint8_t *, size_t, size_t, const uint8_t *, unsigned int)\0",
        ))
            .as_ptr(),
    );
    'c_9297: {
        __assert_fail(
            b"0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/tls_cbc.c\0"
                as *const u8 as *const libc::c_char,
            683 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 148],
                &[libc::c_char; 148],
            >(
                b"int EVP_tls_cbc_digest_record(const EVP_MD *, uint8_t *, size_t *, const uint8_t *, const uint8_t *, size_t, size_t, const uint8_t *, unsigned int)\0",
            ))
                .as_ptr(),
        );
    };
    *md_out_size = 0 as libc::c_int as size_t;
    return 0 as libc::c_int;
}
