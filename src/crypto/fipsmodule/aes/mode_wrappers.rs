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
    fn abort() -> !;
    fn AES_encrypt(in_0: *const uint8_t, out: *mut uint8_t, key: *const AES_KEY);
    fn AES_decrypt(in_0: *const uint8_t, out: *mut uint8_t, key: *const AES_KEY);
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn aes_nohw_ctr32_encrypt_blocks(
        in_0: *const uint8_t,
        out: *mut uint8_t,
        blocks: size_t,
        key: *const AES_KEY,
        ivec: *const uint8_t,
    );
    fn aes_nohw_cbc_encrypt(
        in_0: *const uint8_t,
        out: *mut uint8_t,
        len: size_t,
        key: *const AES_KEY,
        ivec: *mut uint8_t,
        enc: libc::c_int,
    );
    fn CRYPTO_ctr128_encrypt(
        in_0: *const uint8_t,
        out: *mut uint8_t,
        len: size_t,
        key: *const AES_KEY,
        ivec: *mut uint8_t,
        ecount_buf: *mut uint8_t,
        num: *mut libc::c_uint,
        block: block128_f,
    );
    fn CRYPTO_ctr128_encrypt_ctr32(
        in_0: *const uint8_t,
        out: *mut uint8_t,
        len: size_t,
        key: *const AES_KEY,
        ivec: *mut uint8_t,
        ecount_buf: *mut uint8_t,
        num: *mut libc::c_uint,
        ctr: ctr128_f,
    );
    fn CRYPTO_cbc128_encrypt(
        in_0: *const uint8_t,
        out: *mut uint8_t,
        len: size_t,
        key: *const AES_KEY,
        ivec: *mut uint8_t,
        block: block128_f,
    );
    fn CRYPTO_cbc128_decrypt(
        in_0: *const uint8_t,
        out: *mut uint8_t,
        len: size_t,
        key: *const AES_KEY,
        ivec: *mut uint8_t,
        block: block128_f,
    );
    fn CRYPTO_ofb128_encrypt(
        in_0: *const uint8_t,
        out: *mut uint8_t,
        len: size_t,
        key: *const AES_KEY,
        ivec: *mut uint8_t,
        num: *mut libc::c_uint,
        block: block128_f,
    );
    fn CRYPTO_cfb128_encrypt(
        in_0: *const uint8_t,
        out: *mut uint8_t,
        len: size_t,
        key: *const AES_KEY,
        ivec: *mut uint8_t,
        num: *mut libc::c_uint,
        enc: libc::c_int,
        block: block128_f,
    );
    fn CRYPTO_cfb128_8_encrypt(
        in_0: *const uint8_t,
        out: *mut uint8_t,
        len: size_t,
        key: *const AES_KEY,
        ivec: *mut uint8_t,
        num: *mut libc::c_uint,
        enc: libc::c_int,
        block: block128_f,
    );
    fn CRYPTO_cfb128_1_encrypt(
        in_0: *const uint8_t,
        out: *mut uint8_t,
        bits: size_t,
        key: *const AES_KEY,
        ivec: *mut uint8_t,
        num: *mut libc::c_uint,
        enc: libc::c_int,
        block: block128_f,
    );
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct aes_key_st {
    pub rd_key: [uint32_t; 60],
    pub rounds: libc::c_uint,
}
pub type AES_KEY = aes_key_st;
pub type ctr128_f = Option::<
    unsafe extern "C" fn(
        *const uint8_t,
        *mut uint8_t,
        size_t,
        *const AES_KEY,
        *const uint8_t,
    ) -> (),
>;
pub type block128_f = Option::<
    unsafe extern "C" fn(*const uint8_t, *mut uint8_t, *const AES_KEY) -> (),
>;
#[inline]
unsafe extern "C" fn FIPS_service_indicator_update_state() {}
#[inline]
unsafe extern "C" fn hwaes_capable() -> libc::c_int {
    return 0 as libc::c_int;
}
#[inline]
unsafe extern "C" fn aes_hw_cbc_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut length: size_t,
    mut key: *const AES_KEY,
    mut ivec: *mut uint8_t,
    mut enc: libc::c_int,
) {
    abort();
}
#[inline]
unsafe extern "C" fn aes_hw_ctr32_encrypt_blocks(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut len: size_t,
    mut key: *const AES_KEY,
    mut ivec: *const uint8_t,
) {
    abort();
}
#[inline]
unsafe extern "C" fn vpaes_capable() -> libc::c_char {
    return 0 as libc::c_int as libc::c_char;
}
#[inline]
unsafe extern "C" fn vpaes_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut key: *const AES_KEY,
) {
    abort();
}
#[inline]
unsafe extern "C" fn aes_hw_ctr32_encrypt_blocks_wrapper(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut len: size_t,
    mut key: *const AES_KEY,
    mut ivec: *const uint8_t,
) {
    aes_hw_ctr32_encrypt_blocks(in_0, out, len, key, ivec);
}
#[inline]
unsafe extern "C" fn vpaes_encrypt_wrapper(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut key: *const AES_KEY,
) {
    vpaes_encrypt(in_0, out, key);
}
#[no_mangle]
pub unsafe extern "C" fn AES_ctr128_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut len: size_t,
    mut key: *const AES_KEY,
    mut ivec: *mut uint8_t,
    mut ecount_buf: *mut uint8_t,
    mut num: *mut libc::c_uint,
) {
    if hwaes_capable() != 0 {
        CRYPTO_ctr128_encrypt_ctr32(
            in_0,
            out,
            len,
            key,
            ivec,
            ecount_buf,
            num,
            Some(
                aes_hw_ctr32_encrypt_blocks_wrapper
                    as unsafe extern "C" fn(
                        *const uint8_t,
                        *mut uint8_t,
                        size_t,
                        *const AES_KEY,
                        *const uint8_t,
                    ) -> (),
            ),
        );
    } else if vpaes_capable() != 0 {
        CRYPTO_ctr128_encrypt(
            in_0,
            out,
            len,
            key,
            ivec,
            ecount_buf,
            num,
            Some(
                vpaes_encrypt_wrapper
                    as unsafe extern "C" fn(
                        *const uint8_t,
                        *mut uint8_t,
                        *const AES_KEY,
                    ) -> (),
            ),
        );
    } else {
        CRYPTO_ctr128_encrypt_ctr32(
            in_0,
            out,
            len,
            key,
            ivec,
            ecount_buf,
            num,
            Some(
                aes_nohw_ctr32_encrypt_blocks
                    as unsafe extern "C" fn(
                        *const uint8_t,
                        *mut uint8_t,
                        size_t,
                        *const AES_KEY,
                        *const uint8_t,
                    ) -> (),
            ),
        );
    }
    FIPS_service_indicator_update_state();
}
#[no_mangle]
pub unsafe extern "C" fn AES_ecb_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut key: *const AES_KEY,
    enc: libc::c_int,
) {
    if !in_0.is_null() && !out.is_null() && !key.is_null() {} else {
        __assert_fail(
            b"in && out && key\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/aes/mode_wrappers.c\0"
                as *const u8 as *const libc::c_char,
            109 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 77],
                &[libc::c_char; 77],
            >(
                b"void AES_ecb_encrypt(const uint8_t *, uint8_t *, const AES_KEY *, const int)\0",
            ))
                .as_ptr(),
        );
    }
    'c_1694: {
        if !in_0.is_null() && !out.is_null() && !key.is_null() {} else {
            __assert_fail(
                b"in && out && key\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/aes/mode_wrappers.c\0"
                    as *const u8 as *const libc::c_char,
                109 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 77],
                    &[libc::c_char; 77],
                >(
                    b"void AES_ecb_encrypt(const uint8_t *, uint8_t *, const AES_KEY *, const int)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if 1 as libc::c_int == enc || 0 as libc::c_int == enc {} else {
        __assert_fail(
            b"(AES_ENCRYPT == enc) || (AES_DECRYPT == enc)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/aes/mode_wrappers.c\0"
                as *const u8 as *const libc::c_char,
            110 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 77],
                &[libc::c_char; 77],
            >(
                b"void AES_ecb_encrypt(const uint8_t *, uint8_t *, const AES_KEY *, const int)\0",
            ))
                .as_ptr(),
        );
    }
    'c_1633: {
        if 1 as libc::c_int == enc || 0 as libc::c_int == enc {} else {
            __assert_fail(
                b"(AES_ENCRYPT == enc) || (AES_DECRYPT == enc)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/aes/mode_wrappers.c\0"
                    as *const u8 as *const libc::c_char,
                110 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 77],
                    &[libc::c_char; 77],
                >(
                    b"void AES_ecb_encrypt(const uint8_t *, uint8_t *, const AES_KEY *, const int)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if 1 as libc::c_int == enc {
        AES_encrypt(in_0, out, key);
    } else {
        AES_decrypt(in_0, out, key);
    }
    FIPS_service_indicator_update_state();
}
#[no_mangle]
pub unsafe extern "C" fn AES_cbc_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut len: size_t,
    mut key: *const AES_KEY,
    mut ivec: *mut uint8_t,
    enc: libc::c_int,
) {
    if hwaes_capable() != 0 {
        aes_hw_cbc_encrypt(in_0, out, len, key, ivec, enc);
    } else if vpaes_capable() == 0 {
        aes_nohw_cbc_encrypt(in_0, out, len, key, ivec, enc);
    } else if enc != 0 {
        CRYPTO_cbc128_encrypt(
            in_0,
            out,
            len,
            key,
            ivec,
            Some(
                AES_encrypt
                    as unsafe extern "C" fn(
                        *const uint8_t,
                        *mut uint8_t,
                        *const AES_KEY,
                    ) -> (),
            ),
        );
    } else {
        CRYPTO_cbc128_decrypt(
            in_0,
            out,
            len,
            key,
            ivec,
            Some(
                AES_decrypt
                    as unsafe extern "C" fn(
                        *const uint8_t,
                        *mut uint8_t,
                        *const AES_KEY,
                    ) -> (),
            ),
        );
    }
    FIPS_service_indicator_update_state();
}
#[no_mangle]
pub unsafe extern "C" fn AES_ofb128_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut length: size_t,
    mut key: *const AES_KEY,
    mut ivec: *mut uint8_t,
    mut num: *mut libc::c_int,
) {
    let mut num_u: libc::c_uint = *num as libc::c_uint;
    CRYPTO_ofb128_encrypt(
        in_0,
        out,
        length,
        key,
        ivec,
        &mut num_u,
        Some(
            AES_encrypt
                as unsafe extern "C" fn(
                    *const uint8_t,
                    *mut uint8_t,
                    *const AES_KEY,
                ) -> (),
        ),
    );
    *num = num_u as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn AES_cfb1_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut bits: size_t,
    mut key: *const AES_KEY,
    mut ivec: *mut uint8_t,
    mut num: *mut libc::c_int,
    mut enc: libc::c_int,
) {
    let mut num_u: libc::c_uint = *num as libc::c_uint;
    CRYPTO_cfb128_1_encrypt(
        in_0,
        out,
        bits,
        key,
        ivec,
        &mut num_u,
        enc,
        Some(
            AES_encrypt
                as unsafe extern "C" fn(
                    *const uint8_t,
                    *mut uint8_t,
                    *const AES_KEY,
                ) -> (),
        ),
    );
    *num = num_u as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn AES_cfb8_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut length: size_t,
    mut key: *const AES_KEY,
    mut ivec: *mut uint8_t,
    mut num: *mut libc::c_int,
    mut enc: libc::c_int,
) {
    let mut num_u: libc::c_uint = *num as libc::c_uint;
    CRYPTO_cfb128_8_encrypt(
        in_0,
        out,
        length,
        key,
        ivec,
        &mut num_u,
        enc,
        Some(
            AES_encrypt
                as unsafe extern "C" fn(
                    *const uint8_t,
                    *mut uint8_t,
                    *const AES_KEY,
                ) -> (),
        ),
    );
    *num = num_u as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn AES_cfb128_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut length: size_t,
    mut key: *const AES_KEY,
    mut ivec: *mut uint8_t,
    mut num: *mut libc::c_int,
    mut enc: libc::c_int,
) {
    let mut num_u: libc::c_uint = *num as libc::c_uint;
    CRYPTO_cfb128_encrypt(
        in_0,
        out,
        length,
        key,
        ivec,
        &mut num_u,
        enc,
        Some(
            AES_encrypt
                as unsafe extern "C" fn(
                    *const uint8_t,
                    *mut uint8_t,
                    *const AES_KEY,
                ) -> (),
        ),
    );
    *num = num_u as libc::c_int;
}
