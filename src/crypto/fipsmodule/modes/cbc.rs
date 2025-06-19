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
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type uintptr_t = libc::c_ulong;
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
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_126_error_is_block_cannot_be_evenly_divided_into_crypto_word_t {
    #[bitfield(
        name = "static_assertion_at_line_126_error_is_block_cannot_be_evenly_divided_into_crypto_word_t",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_126_error_is_block_cannot_be_evenly_divided_into_crypto_word_t: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_cbc128_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut len: size_t,
    mut key: *const AES_KEY,
    mut ivec: *mut uint8_t,
    mut block: block128_f,
) {
    if !key.is_null() && !ivec.is_null() {} else {
        __assert_fail(
            b"key != NULL && ivec != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/cbc.c\0"
                as *const u8 as *const libc::c_char,
            61 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 103],
                &[libc::c_char; 103],
            >(
                b"void CRYPTO_cbc128_encrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, block128_f)\0",
            ))
                .as_ptr(),
        );
    }
    'c_7154: {
        if !key.is_null() && !ivec.is_null() {} else {
            __assert_fail(
                b"key != NULL && ivec != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/cbc.c\0"
                    as *const u8 as *const libc::c_char,
                61 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 103],
                    &[libc::c_char; 103],
                >(
                    b"void CRYPTO_cbc128_encrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, block128_f)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if len == 0 as libc::c_int as size_t {
        return;
    }
    if !in_0.is_null() && !out.is_null() {} else {
        __assert_fail(
            b"in != NULL && out != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/cbc.c\0"
                as *const u8 as *const libc::c_char,
            67 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 103],
                &[libc::c_char; 103],
            >(
                b"void CRYPTO_cbc128_encrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, block128_f)\0",
            ))
                .as_ptr(),
        );
    }
    'c_7086: {
        if !in_0.is_null() && !out.is_null() {} else {
            __assert_fail(
                b"in != NULL && out != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/cbc.c\0"
                    as *const u8 as *const libc::c_char,
                67 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 103],
                    &[libc::c_char; 103],
                >(
                    b"void CRYPTO_cbc128_encrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, block128_f)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut n: size_t = 0;
    let mut iv: *const uint8_t = ivec as *const uint8_t;
    while len >= 16 as libc::c_int as size_t {
        CRYPTO_xor16(out, in_0, iv);
        (Some(block.expect("non-null function pointer")))
            .expect("non-null function pointer")(out as *const uint8_t, out, key);
        iv = out;
        len = len.wrapping_sub(16 as libc::c_int as size_t);
        in_0 = in_0.offset(16 as libc::c_int as isize);
        out = out.offset(16 as libc::c_int as isize);
    }
    if len > 0 as libc::c_int as size_t {
        n = 0 as libc::c_int as size_t;
        while n < 16 as libc::c_int as size_t && n < len {
            *out
                .offset(
                    n as isize,
                ) = (*in_0.offset(n as isize) as libc::c_int
                ^ *iv.offset(n as isize) as libc::c_int) as uint8_t;
            n = n.wrapping_add(1);
            n;
        }
        while n < 16 as libc::c_int as size_t {
            *out.offset(n as isize) = *iv.offset(n as isize);
            n = n.wrapping_add(1);
            n;
        }
        (Some(block.expect("non-null function pointer")))
            .expect("non-null function pointer")(out as *const uint8_t, out, key);
        iv = out;
    }
    OPENSSL_memcpy(
        ivec as *mut libc::c_void,
        iv as *const libc::c_void,
        16 as libc::c_int as size_t,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_cbc128_decrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut len: size_t,
    mut key: *const AES_KEY,
    mut ivec: *mut uint8_t,
    mut block: block128_f,
) {
    if !key.is_null() && !ivec.is_null() {} else {
        __assert_fail(
            b"key != NULL && ivec != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/cbc.c\0"
                as *const u8 as *const libc::c_char,
            96 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 103],
                &[libc::c_char; 103],
            >(
                b"void CRYPTO_cbc128_decrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, block128_f)\0",
            ))
                .as_ptr(),
        );
    }
    'c_7679: {
        if !key.is_null() && !ivec.is_null() {} else {
            __assert_fail(
                b"key != NULL && ivec != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/cbc.c\0"
                    as *const u8 as *const libc::c_char,
                96 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 103],
                    &[libc::c_char; 103],
                >(
                    b"void CRYPTO_cbc128_decrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, block128_f)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if len == 0 as libc::c_int as size_t {
        return;
    }
    if !in_0.is_null() && !out.is_null() {} else {
        __assert_fail(
            b"in != NULL && out != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/cbc.c\0"
                as *const u8 as *const libc::c_char,
            102 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 103],
                &[libc::c_char; 103],
            >(
                b"void CRYPTO_cbc128_decrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, block128_f)\0",
            ))
                .as_ptr(),
        );
    }
    'c_7614: {
        if !in_0.is_null() && !out.is_null() {} else {
            __assert_fail(
                b"in != NULL && out != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/cbc.c\0"
                    as *const u8 as *const libc::c_char,
                102 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 103],
                    &[libc::c_char; 103],
                >(
                    b"void CRYPTO_cbc128_decrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, block128_f)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let inptr: uintptr_t = in_0 as uintptr_t;
    let outptr: uintptr_t = out as uintptr_t;
    if inptr >= outptr || inptr.wrapping_add(len) <= outptr {} else {
        __assert_fail(
            b"inptr >= outptr || inptr + len <= outptr\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/cbc.c\0"
                as *const u8 as *const libc::c_char,
            107 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 103],
                &[libc::c_char; 103],
            >(
                b"void CRYPTO_cbc128_decrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, block128_f)\0",
            ))
                .as_ptr(),
        );
    }
    'c_7558: {
        if inptr >= outptr || inptr.wrapping_add(len) <= outptr {} else {
            __assert_fail(
                b"inptr >= outptr || inptr + len <= outptr\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/cbc.c\0"
                    as *const u8 as *const libc::c_char,
                107 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 103],
                    &[libc::c_char; 103],
                >(
                    b"void CRYPTO_cbc128_decrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, block128_f)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut n: size_t = 0;
    let mut tmp: [uint8_t; 16] = [0; 16];
    if inptr >= 32 as libc::c_int as uintptr_t
        && outptr <= inptr.wrapping_sub(32 as libc::c_int as uintptr_t) || inptr < outptr
    {
        let mut iv: *const uint8_t = ivec as *const uint8_t;
        while len >= 16 as libc::c_int as size_t {
            (Some(block.expect("non-null function pointer")))
                .expect("non-null function pointer")(in_0, out, key);
            CRYPTO_xor16(out, out as *const uint8_t, iv);
            iv = in_0;
            len = len.wrapping_sub(16 as libc::c_int as size_t);
            in_0 = in_0.offset(16 as libc::c_int as isize);
            out = out.offset(16 as libc::c_int as isize);
        }
        OPENSSL_memcpy(
            ivec as *mut libc::c_void,
            iv as *const libc::c_void,
            16 as libc::c_int as size_t,
        );
    } else {
        while len >= 16 as libc::c_int as size_t {
            (Some(block.expect("non-null function pointer")))
                .expect("non-null function pointer")(in_0, tmp.as_mut_ptr(), key);
            n = 0 as libc::c_int as size_t;
            while n < 16 as libc::c_int as size_t {
                let mut c: crypto_word_t = CRYPTO_load_word_le(
                    in_0.offset(n as isize) as *const libc::c_void,
                );
                CRYPTO_store_word_le(
                    out.offset(n as isize) as *mut libc::c_void,
                    CRYPTO_load_word_le(
                        tmp.as_mut_ptr().offset(n as isize) as *const libc::c_void,
                    )
                        ^ CRYPTO_load_word_le(
                            ivec.offset(n as isize) as *const libc::c_void,
                        ),
                );
                CRYPTO_store_word_le(ivec.offset(n as isize) as *mut libc::c_void, c);
                n = (n as libc::c_ulong)
                    .wrapping_add(
                        ::core::mem::size_of::<crypto_word_t>() as libc::c_ulong,
                    ) as size_t as size_t;
            }
            len = len.wrapping_sub(16 as libc::c_int as size_t);
            in_0 = in_0.offset(16 as libc::c_int as isize);
            out = out.offset(16 as libc::c_int as isize);
        }
    }
    while len != 0 {
        let mut c_0: uint8_t = 0;
        (Some(block.expect("non-null function pointer")))
            .expect("non-null function pointer")(in_0, tmp.as_mut_ptr(), key);
        n = 0 as libc::c_int as size_t;
        while n < 16 as libc::c_int as size_t && n < len {
            c_0 = *in_0.offset(n as isize);
            *out
                .offset(
                    n as isize,
                ) = (tmp[n as usize] as libc::c_int
                ^ *ivec.offset(n as isize) as libc::c_int) as uint8_t;
            *ivec.offset(n as isize) = c_0;
            n = n.wrapping_add(1);
            n;
        }
        if len <= 16 as libc::c_int as size_t {
            while n < 16 as libc::c_int as size_t {
                *ivec.offset(n as isize) = *in_0.offset(n as isize);
                n = n.wrapping_add(1);
                n;
            }
            break;
        } else {
            len = len.wrapping_sub(16 as libc::c_int as size_t);
            in_0 = in_0.offset(16 as libc::c_int as isize);
            out = out.offset(16 as libc::c_int as isize);
        }
    }
}
