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
pub type block128_f = Option::<
    unsafe extern "C" fn(*const uint8_t, *mut uint8_t, *const AES_KEY) -> (),
>;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_90_error_is_block_cannot_be_evenly_divided_into_crypto_word_t {
    #[bitfield(
        name = "static_assertion_at_line_90_error_is_block_cannot_be_evenly_divided_into_crypto_word_t",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_90_error_is_block_cannot_be_evenly_divided_into_crypto_word_t: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
pub type ctr128_f = Option::<
    unsafe extern "C" fn(
        *const uint8_t,
        *mut uint8_t,
        size_t,
        *const AES_KEY,
        *const uint8_t,
    ) -> (),
>;
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
unsafe extern "C" fn CRYPTO_load_word_le(
    mut in_0: *const libc::c_void,
) -> crypto_word_t {
    let mut v: crypto_word_t = 0;
    OPENSSL_memcpy(
        &mut v as *mut crypto_word_t as *mut libc::c_void,
        in_0,
        ::core::mem::size_of::<crypto_word_t>() as libc::c_ulong,
    );
    return v;
}
#[inline]
unsafe extern "C" fn CRYPTO_store_word_le(
    mut out: *mut libc::c_void,
    mut v: crypto_word_t,
) {
    OPENSSL_memcpy(
        out,
        &mut v as *mut crypto_word_t as *const libc::c_void,
        ::core::mem::size_of::<crypto_word_t>() as libc::c_ulong,
    );
}
#[inline]
unsafe extern "C" fn CRYPTO_xor16(
    mut out: *mut uint8_t,
    mut a: *const uint8_t,
    mut b: *const uint8_t,
) {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < 16 as libc::c_int as size_t {
        CRYPTO_store_word_le(
            out.offset(i as isize) as *mut libc::c_void,
            CRYPTO_load_word_le(a.offset(i as isize) as *const libc::c_void)
                ^ CRYPTO_load_word_le(b.offset(i as isize) as *const libc::c_void),
        );
        i = (i as libc::c_ulong)
            .wrapping_add(::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
            as size_t as size_t;
    }
}
unsafe extern "C" fn ctr128_inc(mut counter: *mut uint8_t) {
    let mut n: uint32_t = 16 as libc::c_int as uint32_t;
    let mut c: uint32_t = 1 as libc::c_int as uint32_t;
    loop {
        n = n.wrapping_sub(1);
        n;
        c = c.wrapping_add(*counter.offset(n as isize) as uint32_t);
        *counter.offset(n as isize) = c as uint8_t;
        c >>= 8 as libc::c_int;
        if !(n != 0) {
            break;
        }
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_ctr128_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut len: size_t,
    mut key: *const AES_KEY,
    mut ivec: *mut uint8_t,
    mut ecount_buf: *mut uint8_t,
    mut num: *mut libc::c_uint,
    mut block: block128_f,
) {
    let mut n: libc::c_uint = 0;
    if !key.is_null() && !ecount_buf.is_null() && !num.is_null() {} else {
        __assert_fail(
            b"key && ecount_buf && num\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/ctr.c\0"
                as *const u8 as *const libc::c_char,
            92 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 130],
                &[libc::c_char; 130],
            >(
                b"void CRYPTO_ctr128_encrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, uint8_t *, unsigned int *, block128_f)\0",
            ))
                .as_ptr(),
        );
    }
    'c_7052: {
        if !key.is_null() && !ecount_buf.is_null() && !num.is_null() {} else {
            __assert_fail(
                b"key && ecount_buf && num\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/ctr.c\0"
                    as *const u8 as *const libc::c_char,
                92 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 130],
                    &[libc::c_char; 130],
                >(
                    b"void CRYPTO_ctr128_encrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, uint8_t *, unsigned int *, block128_f)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if len == 0 as libc::c_int as size_t || !in_0.is_null() && !out.is_null() {} else {
        __assert_fail(
            b"len == 0 || (in && out)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/ctr.c\0"
                as *const u8 as *const libc::c_char,
            93 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 130],
                &[libc::c_char; 130],
            >(
                b"void CRYPTO_ctr128_encrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, uint8_t *, unsigned int *, block128_f)\0",
            ))
                .as_ptr(),
        );
    }
    'c_6999: {
        if len == 0 as libc::c_int as size_t || !in_0.is_null() && !out.is_null()
        {} else {
            __assert_fail(
                b"len == 0 || (in && out)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/ctr.c\0"
                    as *const u8 as *const libc::c_char,
                93 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 130],
                    &[libc::c_char; 130],
                >(
                    b"void CRYPTO_ctr128_encrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, uint8_t *, unsigned int *, block128_f)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if *num < 16 as libc::c_int as libc::c_uint {} else {
        __assert_fail(
            b"*num < 16\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/ctr.c\0"
                as *const u8 as *const libc::c_char,
            94 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 130],
                &[libc::c_char; 130],
            >(
                b"void CRYPTO_ctr128_encrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, uint8_t *, unsigned int *, block128_f)\0",
            ))
                .as_ptr(),
        );
    }
    'c_6954: {
        if *num < 16 as libc::c_int as libc::c_uint {} else {
            __assert_fail(
                b"*num < 16\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/ctr.c\0"
                    as *const u8 as *const libc::c_char,
                94 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 130],
                    &[libc::c_char; 130],
                >(
                    b"void CRYPTO_ctr128_encrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, uint8_t *, unsigned int *, block128_f)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    n = *num;
    while n != 0 && len != 0 {
        let fresh0 = in_0;
        in_0 = in_0.offset(1);
        let fresh1 = out;
        out = out.offset(1);
        *fresh1 = (*fresh0 as libc::c_int
            ^ *ecount_buf.offset(n as isize) as libc::c_int) as uint8_t;
        len = len.wrapping_sub(1);
        len;
        n = n
            .wrapping_add(1 as libc::c_int as libc::c_uint)
            .wrapping_rem(16 as libc::c_int as libc::c_uint);
    }
    while len >= 16 as libc::c_int as size_t {
        (Some(block.expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )(ivec as *const uint8_t, ecount_buf, key);
        ctr128_inc(ivec);
        CRYPTO_xor16(out, in_0, ecount_buf as *const uint8_t);
        len = len.wrapping_sub(16 as libc::c_int as size_t);
        out = out.offset(16 as libc::c_int as isize);
        in_0 = in_0.offset(16 as libc::c_int as isize);
        n = 0 as libc::c_int as libc::c_uint;
    }
    if len != 0 {
        (Some(block.expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )(ivec as *const uint8_t, ecount_buf, key);
        ctr128_inc(ivec);
        loop {
            let fresh2 = len;
            len = len.wrapping_sub(1);
            if !(fresh2 != 0) {
                break;
            }
            *out
                .offset(
                    n as isize,
                ) = (*in_0.offset(n as isize) as libc::c_int
                ^ *ecount_buf.offset(n as isize) as libc::c_int) as uint8_t;
            n = n.wrapping_add(1);
            n;
        }
    }
    *num = n;
}
unsafe extern "C" fn ctr96_inc(mut counter: *mut uint8_t) {
    let mut n: uint32_t = 12 as libc::c_int as uint32_t;
    let mut c: uint32_t = 1 as libc::c_int as uint32_t;
    loop {
        n = n.wrapping_sub(1);
        n;
        c = c.wrapping_add(*counter.offset(n as isize) as uint32_t);
        *counter.offset(n as isize) = c as uint8_t;
        c >>= 8 as libc::c_int;
        if !(n != 0) {
            break;
        }
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_ctr128_encrypt_ctr32(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut len: size_t,
    mut key: *const AES_KEY,
    mut ivec: *mut uint8_t,
    mut ecount_buf: *mut uint8_t,
    mut num: *mut libc::c_uint,
    mut func: ctr128_f,
) {
    let mut n: libc::c_uint = 0;
    let mut ctr32: libc::c_uint = 0;
    if !key.is_null() && !ecount_buf.is_null() && !num.is_null() {} else {
        __assert_fail(
            b"key && ecount_buf && num\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/ctr.c\0"
                as *const u8 as *const libc::c_char,
            141 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 134],
                &[libc::c_char; 134],
            >(
                b"void CRYPTO_ctr128_encrypt_ctr32(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, uint8_t *, unsigned int *, ctr128_f)\0",
            ))
                .as_ptr(),
        );
    }
    'c_7536: {
        if !key.is_null() && !ecount_buf.is_null() && !num.is_null() {} else {
            __assert_fail(
                b"key && ecount_buf && num\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/ctr.c\0"
                    as *const u8 as *const libc::c_char,
                141 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 134],
                    &[libc::c_char; 134],
                >(
                    b"void CRYPTO_ctr128_encrypt_ctr32(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, uint8_t *, unsigned int *, ctr128_f)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if len == 0 as libc::c_int as size_t || !in_0.is_null() && !out.is_null() {} else {
        __assert_fail(
            b"len == 0 || (in && out)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/ctr.c\0"
                as *const u8 as *const libc::c_char,
            142 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 134],
                &[libc::c_char; 134],
            >(
                b"void CRYPTO_ctr128_encrypt_ctr32(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, uint8_t *, unsigned int *, ctr128_f)\0",
            ))
                .as_ptr(),
        );
    }
    'c_7484: {
        if len == 0 as libc::c_int as size_t || !in_0.is_null() && !out.is_null()
        {} else {
            __assert_fail(
                b"len == 0 || (in && out)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/ctr.c\0"
                    as *const u8 as *const libc::c_char,
                142 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 134],
                    &[libc::c_char; 134],
                >(
                    b"void CRYPTO_ctr128_encrypt_ctr32(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, uint8_t *, unsigned int *, ctr128_f)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if *num < 16 as libc::c_int as libc::c_uint {} else {
        __assert_fail(
            b"*num < 16\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/ctr.c\0"
                as *const u8 as *const libc::c_char,
            143 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 134],
                &[libc::c_char; 134],
            >(
                b"void CRYPTO_ctr128_encrypt_ctr32(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, uint8_t *, unsigned int *, ctr128_f)\0",
            ))
                .as_ptr(),
        );
    }
    'c_7441: {
        if *num < 16 as libc::c_int as libc::c_uint {} else {
            __assert_fail(
                b"*num < 16\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/ctr.c\0"
                    as *const u8 as *const libc::c_char,
                143 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 134],
                    &[libc::c_char; 134],
                >(
                    b"void CRYPTO_ctr128_encrypt_ctr32(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, uint8_t *, unsigned int *, ctr128_f)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    n = *num;
    while n != 0 && len != 0 {
        let fresh3 = in_0;
        in_0 = in_0.offset(1);
        let fresh4 = out;
        out = out.offset(1);
        *fresh4 = (*fresh3 as libc::c_int
            ^ *ecount_buf.offset(n as isize) as libc::c_int) as uint8_t;
        len = len.wrapping_sub(1);
        len;
        n = n
            .wrapping_add(1 as libc::c_int as libc::c_uint)
            .wrapping_rem(16 as libc::c_int as libc::c_uint);
    }
    ctr32 = CRYPTO_load_u32_be(
        ivec.offset(12 as libc::c_int as isize) as *const libc::c_void,
    );
    while len >= 16 as libc::c_int as size_t {
        let mut blocks: size_t = len / 16 as libc::c_int as size_t;
        if ::core::mem::size_of::<size_t>() as libc::c_ulong
            > ::core::mem::size_of::<libc::c_uint>() as libc::c_ulong
            && blocks > ((1 as libc::c_uint) << 28 as libc::c_int) as size_t
        {
            blocks = ((1 as libc::c_uint) << 28 as libc::c_int) as size_t;
        }
        ctr32 = ctr32.wrapping_add(blocks as uint32_t);
        if (ctr32 as size_t) < blocks {
            blocks = blocks.wrapping_sub(ctr32 as size_t);
            ctr32 = 0 as libc::c_int as libc::c_uint;
        }
        (Some(func.expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )(in_0, out, blocks, key, ivec as *const uint8_t);
        CRYPTO_store_u32_be(
            ivec.offset(12 as libc::c_int as isize) as *mut libc::c_void,
            ctr32,
        );
        if ctr32 == 0 as libc::c_int as libc::c_uint {
            ctr96_inc(ivec);
        }
        blocks = blocks * 16 as libc::c_int as size_t;
        len = len.wrapping_sub(blocks);
        out = out.offset(blocks as isize);
        in_0 = in_0.offset(blocks as isize);
    }
    if len != 0 {
        OPENSSL_memset(
            ecount_buf as *mut libc::c_void,
            0 as libc::c_int,
            16 as libc::c_int as size_t,
        );
        (Some(func.expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )(
            ecount_buf as *const uint8_t,
            ecount_buf,
            1 as libc::c_int as size_t,
            key,
            ivec as *const uint8_t,
        );
        ctr32 = ctr32.wrapping_add(1);
        ctr32;
        CRYPTO_store_u32_be(
            ivec.offset(12 as libc::c_int as isize) as *mut libc::c_void,
            ctr32,
        );
        if ctr32 == 0 as libc::c_int as libc::c_uint {
            ctr96_inc(ivec);
        }
        loop {
            let fresh5 = len;
            len = len.wrapping_sub(1);
            if !(fresh5 != 0) {
                break;
            }
            *out
                .offset(
                    n as isize,
                ) = (*in_0.offset(n as isize) as libc::c_int
                ^ *ecount_buf.offset(n as isize) as libc::c_int) as uint8_t;
            n = n.wrapping_add(1);
            n;
        }
    }
    *num = n;
}
