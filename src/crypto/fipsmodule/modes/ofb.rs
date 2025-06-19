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
pub unsafe extern "C" fn CRYPTO_ofb128_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut len: size_t,
    mut key: *const AES_KEY,
    mut ivec: *mut uint8_t,
    mut num: *mut libc::c_uint,
    mut block: block128_f,
) {
    if !key.is_null() && !ivec.is_null() && !num.is_null() {} else {
        __assert_fail(
            b"key != NULL && ivec != NULL && num != NULL\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/ofb.c\0"
                as *const u8 as *const libc::c_char,
            63 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 119],
                &[libc::c_char; 119],
            >(
                b"void CRYPTO_ofb128_encrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, unsigned int *, block128_f)\0",
            ))
                .as_ptr(),
        );
    }
    'c_7168: {
        if !key.is_null() && !ivec.is_null() && !num.is_null() {} else {
            __assert_fail(
                b"key != NULL && ivec != NULL && num != NULL\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/ofb.c\0"
                    as *const u8 as *const libc::c_char,
                63 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 119],
                    &[libc::c_char; 119],
                >(
                    b"void CRYPTO_ofb128_encrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, unsigned int *, block128_f)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if len == 0 as libc::c_int as size_t || !in_0.is_null() && !out.is_null() {} else {
        __assert_fail(
            b"len == 0 || (in != NULL && out != NULL)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/ofb.c\0"
                as *const u8 as *const libc::c_char,
            64 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 119],
                &[libc::c_char; 119],
            >(
                b"void CRYPTO_ofb128_encrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, unsigned int *, block128_f)\0",
            ))
                .as_ptr(),
        );
    }
    'c_7094: {
        if len == 0 as libc::c_int as size_t || !in_0.is_null() && !out.is_null()
        {} else {
            __assert_fail(
                b"len == 0 || (in != NULL && out != NULL)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/ofb.c\0"
                    as *const u8 as *const libc::c_char,
                64 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 119],
                    &[libc::c_char; 119],
                >(
                    b"void CRYPTO_ofb128_encrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, unsigned int *, block128_f)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut n: libc::c_uint = *num;
    while n != 0 && len != 0 {
        let fresh0 = in_0;
        in_0 = in_0.offset(1);
        let fresh1 = out;
        out = out.offset(1);
        *fresh1 = (*fresh0 as libc::c_int ^ *ivec.offset(n as isize) as libc::c_int)
            as uint8_t;
        len = len.wrapping_sub(1);
        len;
        n = n
            .wrapping_add(1 as libc::c_int as libc::c_uint)
            .wrapping_rem(16 as libc::c_int as libc::c_uint);
    }
    while len >= 16 as libc::c_int as size_t {
        (Some(block.expect("non-null function pointer")))
            .expect("non-null function pointer")(ivec as *const uint8_t, ivec, key);
        CRYPTO_xor16(out, in_0, ivec as *const uint8_t);
        len = len.wrapping_sub(16 as libc::c_int as size_t);
        out = out.offset(16 as libc::c_int as isize);
        in_0 = in_0.offset(16 as libc::c_int as isize);
        n = 0 as libc::c_int as libc::c_uint;
    }
    if len != 0 {
        (Some(block.expect("non-null function pointer")))
            .expect("non-null function pointer")(ivec as *const uint8_t, ivec, key);
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
                ^ *ivec.offset(n as isize) as libc::c_int) as uint8_t;
            n = n.wrapping_add(1);
            n;
        }
    }
    *num = n;
}
