#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(extern_types, label_break_value)]
extern "C" {
    pub type engine_st;
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
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_memdup(data: *const libc::c_void, size: size_t) -> *mut libc::c_void;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OBJ_nid2sn(nid: libc::c_int) -> *const libc::c_char;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type ENGINE = engine_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_cipher_ctx_st {
    pub cipher: *const EVP_CIPHER,
    pub app_data: *mut libc::c_void,
    pub cipher_data: *mut libc::c_void,
    pub key_len: libc::c_uint,
    pub encrypt: libc::c_int,
    pub flags: uint32_t,
    pub oiv: [uint8_t; 16],
    pub iv: [uint8_t; 16],
    pub buf: [uint8_t; 32],
    pub buf_len: libc::c_int,
    pub num: libc::c_uint,
    pub final_used: libc::c_int,
    pub final_0: [uint8_t; 32],
    pub poisoned: libc::c_int,
}
pub type EVP_CIPHER = evp_cipher_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_cipher_st {
    pub nid: libc::c_int,
    pub block_size: libc::c_uint,
    pub key_len: libc::c_uint,
    pub iv_len: libc::c_uint,
    pub ctx_size: libc::c_uint,
    pub flags: uint32_t,
    pub init: Option::<
        unsafe extern "C" fn(
            *mut EVP_CIPHER_CTX,
            *const uint8_t,
            *const uint8_t,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub cipher: Option::<
        unsafe extern "C" fn(
            *mut EVP_CIPHER_CTX,
            *mut uint8_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub cleanup: Option::<unsafe extern "C" fn(*mut EVP_CIPHER_CTX) -> ()>,
    pub ctrl: Option::<
        unsafe extern "C" fn(
            *mut EVP_CIPHER_CTX,
            libc::c_int,
            libc::c_int,
            *mut libc::c_void,
        ) -> libc::c_int,
    >,
}
pub type EVP_CIPHER_CTX = evp_cipher_ctx_st;
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
unsafe extern "C" fn EVP_Cipher_verify_service_indicator(
    mut ctx: *const EVP_CIPHER_CTX,
) {}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_init(mut ctx: *mut EVP_CIPHER_CTX) {
    OPENSSL_memset(
        ctx as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_CIPHER_CTX>() as libc::c_ulong,
    );
    (*ctx).poisoned = 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_new() -> *mut EVP_CIPHER_CTX {
    let mut ctx: *mut EVP_CIPHER_CTX = OPENSSL_zalloc(
        ::core::mem::size_of::<EVP_CIPHER_CTX>() as libc::c_ulong,
    ) as *mut EVP_CIPHER_CTX;
    if !ctx.is_null() {
        (*ctx).poisoned = 1 as libc::c_int;
    }
    return ctx;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_cleanup(
    mut c: *mut EVP_CIPHER_CTX,
) -> libc::c_int {
    if c.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            89 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if !((*c).cipher).is_null() && ((*(*c).cipher).cleanup).is_some() {
        ((*(*c).cipher).cleanup).expect("non-null function pointer")(c);
    }
    OPENSSL_free((*c).cipher_data);
    OPENSSL_memset(
        c as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_CIPHER_CTX>() as libc::c_ulong,
    );
    (*c).poisoned = 1 as libc::c_int;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_free(mut ctx: *mut EVP_CIPHER_CTX) {
    if !ctx.is_null() {
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_free(ctx as *mut libc::c_void);
    }
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_copy(
    mut out: *mut EVP_CIPHER_CTX,
    mut in_0: *const EVP_CIPHER_CTX,
) -> libc::c_int {
    if in_0.is_null() || ((*in_0).cipher).is_null() {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            108 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            110 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*in_0).poisoned != 0 {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            115 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if out.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            118 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    EVP_CIPHER_CTX_cleanup(out);
    OPENSSL_memcpy(
        out as *mut libc::c_void,
        in_0 as *const libc::c_void,
        ::core::mem::size_of::<EVP_CIPHER_CTX>() as libc::c_ulong,
    );
    if !((*in_0).cipher_data).is_null() && (*(*in_0).cipher).ctx_size != 0 {
        (*out)
            .cipher_data = OPENSSL_memdup(
            (*in_0).cipher_data,
            (*(*in_0).cipher).ctx_size as size_t,
        );
        if ((*out).cipher_data).is_null() {
            (*out).cipher = 0 as *const EVP_CIPHER;
            return 0 as libc::c_int;
        }
    }
    if (*(*in_0).cipher).flags & 0x1000 as libc::c_int as uint32_t != 0 {
        if ((*(*in_0).cipher).ctrl)
            .expect(
                "non-null function pointer",
            )(
            in_0 as *mut EVP_CIPHER_CTX,
            0x8 as libc::c_int,
            0 as libc::c_int,
            out as *mut libc::c_void,
        ) == 0
        {
            (*out).cipher = 0 as *const EVP_CIPHER;
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_reset(
    mut ctx: *mut EVP_CIPHER_CTX,
) -> libc::c_int {
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_init(ctx);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CipherInit_ex(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut cipher: *const EVP_CIPHER,
    mut engine: *mut ENGINE,
    mut key: *const uint8_t,
    mut iv: *const uint8_t,
    mut enc: libc::c_int,
) -> libc::c_int {
    if ctx.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            151 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if enc == -(1 as libc::c_int) {
        enc = (*ctx).encrypt;
    } else {
        if enc != 0 {
            enc = 1 as libc::c_int;
        }
        (*ctx).encrypt = enc;
    }
    if !cipher.is_null() {
        if !((*ctx).cipher).is_null() {
            EVP_CIPHER_CTX_cleanup(ctx);
            (*ctx).encrypt = enc;
        }
        (*ctx).cipher = cipher;
        if (*(*ctx).cipher).ctx_size != 0 {
            (*ctx).cipher_data = OPENSSL_malloc((*(*ctx).cipher).ctx_size as size_t);
            if ((*ctx).cipher_data).is_null() {
                (*ctx).cipher = 0 as *const EVP_CIPHER;
                return 0 as libc::c_int;
            }
        } else {
            (*ctx).cipher_data = 0 as *mut libc::c_void;
        }
        (*ctx).key_len = (*cipher).key_len;
        (*ctx).flags = 0 as libc::c_int as uint32_t;
        if (*(*ctx).cipher).flags & 0x200 as libc::c_int as uint32_t != 0 {
            if EVP_CIPHER_CTX_ctrl(
                ctx,
                0 as libc::c_int,
                0 as libc::c_int,
                0 as *mut libc::c_void,
            ) == 0
            {
                (*ctx).cipher = 0 as *const EVP_CIPHER;
                ERR_put_error(
                    30 as libc::c_int,
                    0 as libc::c_int,
                    107 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                        as *const u8 as *const libc::c_char,
                    188 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
        }
    } else if ((*ctx).cipher).is_null() {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            114 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            193 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*(*ctx).cipher).block_size == 1 as libc::c_int as libc::c_uint
        || (*(*ctx).cipher).block_size == 8 as libc::c_int as libc::c_uint
        || (*(*ctx).cipher).block_size == 16 as libc::c_int as libc::c_uint
    {} else {
        __assert_fail(
            b"ctx->cipher->block_size == 1 || ctx->cipher->block_size == 8 || ctx->cipher->block_size == 16\0"
                as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            199 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 109],
                &[libc::c_char; 109],
            >(
                b"int EVP_CipherInit_ex(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *, const uint8_t *, const uint8_t *, int)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2345: {
        if (*(*ctx).cipher).block_size == 1 as libc::c_int as libc::c_uint
            || (*(*ctx).cipher).block_size == 8 as libc::c_int as libc::c_uint
            || (*(*ctx).cipher).block_size == 16 as libc::c_int as libc::c_uint
        {} else {
            __assert_fail(
                b"ctx->cipher->block_size == 1 || ctx->cipher->block_size == 8 || ctx->cipher->block_size == 16\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                    as *const u8 as *const libc::c_char,
                199 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 109],
                    &[libc::c_char; 109],
                >(
                    b"int EVP_CipherInit_ex(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *, const uint8_t *, const uint8_t *, int)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if EVP_CIPHER_CTX_flags(ctx) & 0x100 as libc::c_int as uint32_t == 0 {
        let mut current_block_56: u64;
        match EVP_CIPHER_CTX_mode(ctx) {
            0 | 1 => {
                current_block_56 = 2122094917359643297;
            }
            3 => {
                (*ctx).num = 0 as libc::c_int as libc::c_uint;
                current_block_56 = 1303875563744752071;
            }
            2 => {
                current_block_56 = 1303875563744752071;
            }
            5 | 4 => {
                (*ctx).num = 0 as libc::c_int as libc::c_uint;
                if !iv.is_null() {
                    OPENSSL_memcpy(
                        ((*ctx).iv).as_mut_ptr() as *mut libc::c_void,
                        iv as *const libc::c_void,
                        EVP_CIPHER_CTX_iv_length(ctx) as size_t,
                    );
                }
                current_block_56 = 2122094917359643297;
            }
            _ => return 0 as libc::c_int,
        }
        match current_block_56 {
            1303875563744752071 => {
                if EVP_CIPHER_CTX_iv_length(ctx) as libc::c_ulong
                    <= ::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong
                {} else {
                    __assert_fail(
                        b"EVP_CIPHER_CTX_iv_length(ctx) <= sizeof(ctx->iv)\0"
                            as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                            as *const u8 as *const libc::c_char,
                        212 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 109],
                            &[libc::c_char; 109],
                        >(
                            b"int EVP_CipherInit_ex(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *, const uint8_t *, const uint8_t *, int)\0",
                        ))
                            .as_ptr(),
                    );
                }
                'c_2211: {
                    if EVP_CIPHER_CTX_iv_length(ctx) as libc::c_ulong
                        <= ::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong
                    {} else {
                        __assert_fail(
                            b"EVP_CIPHER_CTX_iv_length(ctx) <= sizeof(ctx->iv)\0"
                                as *const u8 as *const libc::c_char,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                                as *const u8 as *const libc::c_char,
                            212 as libc::c_int as libc::c_uint,
                            (*::core::mem::transmute::<
                                &[u8; 109],
                                &[libc::c_char; 109],
                            >(
                                b"int EVP_CipherInit_ex(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *, const uint8_t *, const uint8_t *, int)\0",
                            ))
                                .as_ptr(),
                        );
                    }
                };
                if !iv.is_null() {
                    OPENSSL_memcpy(
                        ((*ctx).oiv).as_mut_ptr() as *mut libc::c_void,
                        iv as *const libc::c_void,
                        EVP_CIPHER_CTX_iv_length(ctx) as size_t,
                    );
                }
                OPENSSL_memcpy(
                    ((*ctx).iv).as_mut_ptr() as *mut libc::c_void,
                    ((*ctx).oiv).as_mut_ptr() as *const libc::c_void,
                    EVP_CIPHER_CTX_iv_length(ctx) as size_t,
                );
            }
            _ => {}
        }
    }
    if !key.is_null() || (*(*ctx).cipher).flags & 0x80 as libc::c_int as uint32_t != 0 {
        if ((*(*ctx).cipher).init).expect("non-null function pointer")(ctx, key, iv, enc)
            == 0
        {
            return 0 as libc::c_int;
        }
    }
    (*ctx).buf_len = 0 as libc::c_int;
    (*ctx).final_used = 0 as libc::c_int;
    (*ctx).poisoned = 0 as libc::c_int;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_EncryptInit_ex(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut cipher: *const EVP_CIPHER,
    mut impl_0: *mut ENGINE,
    mut key: *const uint8_t,
    mut iv: *const uint8_t,
) -> libc::c_int {
    return EVP_CipherInit_ex(ctx, cipher, impl_0, key, iv, 1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_DecryptInit_ex(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut cipher: *const EVP_CIPHER,
    mut impl_0: *mut ENGINE,
    mut key: *const uint8_t,
    mut iv: *const uint8_t,
) -> libc::c_int {
    return EVP_CipherInit_ex(ctx, cipher, impl_0, key, iv, 0 as libc::c_int);
}
unsafe extern "C" fn block_remainder(
    mut ctx: *const EVP_CIPHER_CTX,
    mut len: libc::c_int,
) -> libc::c_int {
    if (*(*ctx).cipher).block_size != 0 as libc::c_int as libc::c_uint {} else {
        __assert_fail(
            b"ctx->cipher->block_size != 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            261 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 49],
                &[libc::c_char; 49],
            >(b"int block_remainder(const EVP_CIPHER_CTX *, int)\0"))
                .as_ptr(),
        );
    }
    'c_2913: {
        if (*(*ctx).cipher).block_size != 0 as libc::c_int as libc::c_uint {} else {
            __assert_fail(
                b"ctx->cipher->block_size != 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                    as *const u8 as *const libc::c_char,
                261 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 49],
                    &[libc::c_char; 49],
                >(b"int block_remainder(const EVP_CIPHER_CTX *, int)\0"))
                    .as_ptr(),
            );
        }
    };
    if (*(*ctx).cipher).block_size
        & ((*(*ctx).cipher).block_size).wrapping_sub(1 as libc::c_int as libc::c_uint)
        == 0 as libc::c_int as libc::c_uint
    {} else {
        __assert_fail(
            b"(ctx->cipher->block_size & (ctx->cipher->block_size - 1)) == 0\0"
                as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            262 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 49],
                &[libc::c_char; 49],
            >(b"int block_remainder(const EVP_CIPHER_CTX *, int)\0"))
                .as_ptr(),
        );
    }
    'c_2842: {
        if (*(*ctx).cipher).block_size
            & ((*(*ctx).cipher).block_size)
                .wrapping_sub(1 as libc::c_int as libc::c_uint)
            == 0 as libc::c_int as libc::c_uint
        {} else {
            __assert_fail(
                b"(ctx->cipher->block_size & (ctx->cipher->block_size - 1)) == 0\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                    as *const u8 as *const libc::c_char,
                262 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 49],
                    &[libc::c_char; 49],
                >(b"int block_remainder(const EVP_CIPHER_CTX *, int)\0"))
                    .as_ptr(),
            );
        }
    };
    return (len as libc::c_uint
        & ((*(*ctx).cipher).block_size).wrapping_sub(1 as libc::c_int as libc::c_uint))
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_EncryptUpdate(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut out_len: *mut libc::c_int,
    mut in_0: *const uint8_t,
    mut in_len: libc::c_int,
) -> libc::c_int {
    if ctx.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            269 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*ctx).poisoned != 0 {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            271 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*ctx).poisoned = 1 as libc::c_int;
    if ((*ctx).cipher).is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            281 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut bl: libc::c_int = (*(*ctx).cipher).block_size as libc::c_int;
    if bl > 1 as libc::c_int && in_len > 2147483647 as libc::c_int - bl {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            284 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*(*ctx).cipher).flags & 0x400 as libc::c_int as uint32_t != 0 {
        let mut ret: libc::c_int = ((*(*ctx).cipher).cipher)
            .expect("non-null function pointer")(ctx, out, in_0, in_len as size_t);
        if ret < 0 as libc::c_int {
            return 0 as libc::c_int
        } else {
            *out_len = ret;
        }
        (*ctx).poisoned = 0 as libc::c_int;
        return 1 as libc::c_int;
    }
    if in_len <= 0 as libc::c_int {
        *out_len = 0 as libc::c_int;
        if in_len == 0 as libc::c_int {
            (*ctx).poisoned = 0 as libc::c_int;
            return 1 as libc::c_int;
        }
        return 0 as libc::c_int;
    }
    if (*ctx).buf_len == 0 as libc::c_int
        && block_remainder(ctx, in_len) == 0 as libc::c_int
    {
        if ((*(*ctx).cipher).cipher)
            .expect("non-null function pointer")(ctx, out, in_0, in_len as size_t) != 0
        {
            *out_len = in_len;
            (*ctx).poisoned = 0 as libc::c_int;
            return 1 as libc::c_int;
        } else {
            *out_len = 0 as libc::c_int;
            return 0 as libc::c_int;
        }
    }
    let mut i: libc::c_int = (*ctx).buf_len;
    if bl <= ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong as libc::c_int
    {} else {
        __assert_fail(
            b"bl <= (int)sizeof(ctx->buf)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            320 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 80],
                &[libc::c_char; 80],
            >(
                b"int EVP_EncryptUpdate(EVP_CIPHER_CTX *, uint8_t *, int *, const uint8_t *, int)\0",
            ))
                .as_ptr(),
        );
    }
    'c_3103: {
        if bl <= ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong as libc::c_int
        {} else {
            __assert_fail(
                b"bl <= (int)sizeof(ctx->buf)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                    as *const u8 as *const libc::c_char,
                320 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 80],
                    &[libc::c_char; 80],
                >(
                    b"int EVP_EncryptUpdate(EVP_CIPHER_CTX *, uint8_t *, int *, const uint8_t *, int)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if i != 0 as libc::c_int {
        if bl - i > in_len {
            OPENSSL_memcpy(
                &mut *((*ctx).buf).as_mut_ptr().offset(i as isize) as *mut uint8_t
                    as *mut libc::c_void,
                in_0 as *const libc::c_void,
                in_len as size_t,
            );
            (*ctx).buf_len += in_len;
            *out_len = 0 as libc::c_int;
            (*ctx).poisoned = 0 as libc::c_int;
            return 1 as libc::c_int;
        } else {
            let mut j: libc::c_int = bl - i;
            OPENSSL_memcpy(
                &mut *((*ctx).buf).as_mut_ptr().offset(i as isize) as *mut uint8_t
                    as *mut libc::c_void,
                in_0 as *const libc::c_void,
                j as size_t,
            );
            if ((*(*ctx).cipher).cipher)
                .expect(
                    "non-null function pointer",
                )(ctx, out, ((*ctx).buf).as_mut_ptr(), bl as size_t) == 0
            {
                return 0 as libc::c_int;
            }
            in_len -= j;
            in_0 = in_0.offset(j as isize);
            out = out.offset(bl as isize);
            *out_len = bl;
        }
    } else {
        *out_len = 0 as libc::c_int;
    }
    i = block_remainder(ctx, in_len);
    in_len -= i;
    if in_len > 0 as libc::c_int {
        if ((*(*ctx).cipher).cipher)
            .expect("non-null function pointer")(ctx, out, in_0, in_len as size_t) == 0
        {
            return 0 as libc::c_int;
        }
        *out_len += in_len;
    }
    if i != 0 as libc::c_int {
        OPENSSL_memcpy(
            ((*ctx).buf).as_mut_ptr() as *mut libc::c_void,
            &*in_0.offset(in_len as isize) as *const uint8_t as *const libc::c_void,
            i as size_t,
        );
    }
    (*ctx).buf_len = i;
    (*ctx).poisoned = 0 as libc::c_int;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_EncryptFinal_ex(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut out_len: *mut libc::c_int,
) -> libc::c_int {
    let mut n: libc::c_int = 0;
    let mut i: libc::c_uint = 0;
    let mut b: libc::c_uint = 0;
    let mut bl: libc::c_uint = 0;
    if ctx.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            364 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*ctx).poisoned != 0 {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            367 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*ctx).cipher).is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            370 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*(*ctx).cipher).flags & 0x400 as libc::c_int as uint32_t != 0 {
        let num_bytes: libc::c_int = ((*(*ctx).cipher).cipher)
            .expect(
                "non-null function pointer",
            )(ctx, out, 0 as *const uint8_t, 0 as libc::c_int as size_t);
        if num_bytes < 0 as libc::c_int {
            return 0 as libc::c_int;
        }
        *out_len = num_bytes;
    } else {
        b = (*(*ctx).cipher).block_size;
        if b as libc::c_ulong <= ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong
        {} else {
            __assert_fail(
                b"b <= sizeof(ctx->buf)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                    as *const u8 as *const libc::c_char,
                384 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 60],
                    &[libc::c_char; 60],
                >(b"int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *, uint8_t *, int *)\0"))
                    .as_ptr(),
            );
        }
        'c_3567: {
            if b as libc::c_ulong
                <= ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong
            {} else {
                __assert_fail(
                    b"b <= sizeof(ctx->buf)\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                        as *const u8 as *const libc::c_char,
                    384 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 60],
                        &[libc::c_char; 60],
                    >(b"int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *, uint8_t *, int *)\0"))
                        .as_ptr(),
                );
            }
        };
        if b == 1 as libc::c_int as libc::c_uint {
            *out_len = 0 as libc::c_int;
        } else {
            bl = (*ctx).buf_len as libc::c_uint;
            if (*ctx).flags & 0x800 as libc::c_int as uint32_t != 0 {
                if bl != 0 {
                    ERR_put_error(
                        30 as libc::c_int,
                        0 as libc::c_int,
                        106 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                            as *const u8 as *const libc::c_char,
                        393 as libc::c_int as libc::c_uint,
                    );
                    return 0 as libc::c_int;
                }
                *out_len = 0 as libc::c_int;
            } else {
                n = b.wrapping_sub(bl) as libc::c_int;
                i = bl;
                while i < b {
                    (*ctx).buf[i as usize] = n as uint8_t;
                    i = i.wrapping_add(1);
                    i;
                }
                if ((*(*ctx).cipher).cipher)
                    .expect(
                        "non-null function pointer",
                    )(ctx, out, ((*ctx).buf).as_mut_ptr(), b as size_t) == 0
                {
                    return 0 as libc::c_int;
                }
                *out_len = b as libc::c_int;
            }
        }
    }
    EVP_Cipher_verify_service_indicator(ctx);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_DecryptUpdate(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut out_len: *mut libc::c_int,
    mut in_0: *const uint8_t,
    mut in_len: libc::c_int,
) -> libc::c_int {
    if ctx.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            417 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*ctx).poisoned != 0 {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            419 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*ctx).cipher).is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            426 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut b: libc::c_uint = (*(*ctx).cipher).block_size;
    if b > 1 as libc::c_int as libc::c_uint
        && in_len > 2147483647 as libc::c_int - b as libc::c_int
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            429 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*(*ctx).cipher).flags & 0x400 as libc::c_int as uint32_t != 0 {
        let mut r: libc::c_int = ((*(*ctx).cipher).cipher)
            .expect("non-null function pointer")(ctx, out, in_0, in_len as size_t);
        if r < 0 as libc::c_int {
            *out_len = 0 as libc::c_int;
            return 0 as libc::c_int;
        } else {
            *out_len = r;
        }
        return 1 as libc::c_int;
    }
    if in_len <= 0 as libc::c_int {
        *out_len = 0 as libc::c_int;
        return (in_len == 0 as libc::c_int) as libc::c_int;
    }
    if (*ctx).flags & 0x800 as libc::c_int as uint32_t != 0 {
        return EVP_EncryptUpdate(ctx, out, out_len, in_0, in_len);
    }
    if b as libc::c_ulong <= ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong
    {} else {
        __assert_fail(
            b"b <= sizeof(ctx->final)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            453 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 80],
                &[libc::c_char; 80],
            >(
                b"int EVP_DecryptUpdate(EVP_CIPHER_CTX *, uint8_t *, int *, const uint8_t *, int)\0",
            ))
                .as_ptr(),
        );
    }
    'c_3894: {
        if b as libc::c_ulong <= ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong
        {} else {
            __assert_fail(
                b"b <= sizeof(ctx->final)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                    as *const u8 as *const libc::c_char,
                453 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 80],
                    &[libc::c_char; 80],
                >(
                    b"int EVP_DecryptUpdate(EVP_CIPHER_CTX *, uint8_t *, int *, const uint8_t *, int)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut fix_len: libc::c_int = 0 as libc::c_int;
    if (*ctx).final_used != 0 {
        OPENSSL_memcpy(
            out as *mut libc::c_void,
            ((*ctx).final_0).as_mut_ptr() as *const libc::c_void,
            b as size_t,
        );
        out = out.offset(b as isize);
        fix_len = 1 as libc::c_int;
    }
    if EVP_EncryptUpdate(ctx, out, out_len, in_0, in_len) == 0 {
        return 0 as libc::c_int;
    }
    if b > 1 as libc::c_int as libc::c_uint && (*ctx).buf_len == 0 {
        *out_len = (*out_len as libc::c_uint).wrapping_sub(b) as libc::c_int
            as libc::c_int;
        (*ctx).final_used = 1 as libc::c_int;
        OPENSSL_memcpy(
            ((*ctx).final_0).as_mut_ptr() as *mut libc::c_void,
            &mut *out.offset(*out_len as isize) as *mut uint8_t as *const libc::c_void,
            b as size_t,
        );
    } else {
        (*ctx).final_used = 0 as libc::c_int;
    }
    if fix_len != 0 {
        *out_len = (*out_len as libc::c_uint).wrapping_add(b) as libc::c_int
            as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_DecryptFinal_ex(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut libc::c_uchar,
    mut out_len: *mut libc::c_int,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut n: libc::c_int = 0;
    let mut b: libc::c_uint = 0;
    *out_len = 0 as libc::c_int;
    if ctx.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            487 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*ctx).poisoned != 0 {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            494 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*ctx).cipher).is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            497 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*(*ctx).cipher).flags & 0x400 as libc::c_int as uint32_t != 0 {
        i = ((*(*ctx).cipher).cipher)
            .expect(
                "non-null function pointer",
            )(ctx, out, 0 as *const uint8_t, 0 as libc::c_int as size_t);
        if i < 0 as libc::c_int {
            return 0 as libc::c_int
        } else {
            *out_len = i;
        }
    } else {
        b = (*(*ctx).cipher).block_size;
        if (*ctx).flags & 0x800 as libc::c_int as uint32_t != 0 {
            if (*ctx).buf_len != 0 {
                ERR_put_error(
                    30 as libc::c_int,
                    0 as libc::c_int,
                    106 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                        as *const u8 as *const libc::c_char,
                    511 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            *out_len = 0 as libc::c_int;
        } else if b > 1 as libc::c_int as libc::c_uint {
            if (*ctx).buf_len != 0 || (*ctx).final_used == 0 {
                ERR_put_error(
                    30 as libc::c_int,
                    0 as libc::c_int,
                    123 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                        as *const u8 as *const libc::c_char,
                    520 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            if b as libc::c_ulong
                <= ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong
            {} else {
                __assert_fail(
                    b"b <= sizeof(ctx->final)\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                        as *const u8 as *const libc::c_char,
                    523 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 66],
                        &[libc::c_char; 66],
                    >(
                        b"int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *, unsigned char *, int *)\0",
                    ))
                        .as_ptr(),
                );
            }
            'c_4316: {
                if b as libc::c_ulong
                    <= ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong
                {} else {
                    __assert_fail(
                        b"b <= sizeof(ctx->final)\0" as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                            as *const u8 as *const libc::c_char,
                        523 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 66],
                            &[libc::c_char; 66],
                        >(
                            b"int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *, unsigned char *, int *)\0",
                        ))
                            .as_ptr(),
                    );
                }
            };
            n = (*ctx).final_0[b.wrapping_sub(1 as libc::c_int as libc::c_uint) as usize]
                as libc::c_int;
            if n == 0 as libc::c_int || n > b as libc::c_int {
                ERR_put_error(
                    30 as libc::c_int,
                    0 as libc::c_int,
                    101 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                        as *const u8 as *const libc::c_char,
                    529 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            i = 0 as libc::c_int;
            while i < n {
                b = b.wrapping_sub(1);
                if (*ctx).final_0[b as usize] as libc::c_int != n {
                    ERR_put_error(
                        30 as libc::c_int,
                        0 as libc::c_int,
                        101 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                            as *const u8 as *const libc::c_char,
                        535 as libc::c_int as libc::c_uint,
                    );
                    return 0 as libc::c_int;
                }
                i += 1;
                i;
            }
            n = ((*(*ctx).cipher).block_size).wrapping_sub(n as libc::c_uint)
                as libc::c_int;
            i = 0 as libc::c_int;
            while i < n {
                *out.offset(i as isize) = (*ctx).final_0[i as usize];
                i += 1;
                i;
            }
            *out_len = n;
        } else {
            *out_len = 0 as libc::c_int;
        }
    }
    EVP_Cipher_verify_service_indicator(ctx);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_Cipher(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
) -> libc::c_int {
    if ctx.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            557 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*ctx).cipher).is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            558 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let ret: libc::c_int = ((*(*ctx).cipher).cipher)
        .expect("non-null function pointer")(ctx, out, in_0, in_len);
    if (*(*ctx).cipher).flags & 0x400 as libc::c_int as uint32_t == 0 && ret != 0 {
        EVP_Cipher_verify_service_indicator(ctx);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CipherUpdate(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut out_len: *mut libc::c_int,
    mut in_0: *const uint8_t,
    mut in_len: libc::c_int,
) -> libc::c_int {
    if ctx.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            581 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*ctx).encrypt != 0 {
        return EVP_EncryptUpdate(ctx, out, out_len, in_0, in_len)
    } else {
        return EVP_DecryptUpdate(ctx, out, out_len, in_0, in_len)
    };
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CipherFinal_ex(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut out_len: *mut libc::c_int,
) -> libc::c_int {
    if ctx.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            590 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*ctx).encrypt != 0 {
        return EVP_EncryptFinal_ex(ctx, out, out_len)
    } else {
        return EVP_DecryptFinal_ex(ctx, out, out_len)
    };
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_cipher(
    mut ctx: *const EVP_CIPHER_CTX,
) -> *const EVP_CIPHER {
    return (*ctx).cipher;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_nid(
    mut ctx: *const EVP_CIPHER_CTX,
) -> libc::c_int {
    return (*(*ctx).cipher).nid;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_encrypting(
    mut ctx: *const EVP_CIPHER_CTX,
) -> libc::c_int {
    return (*ctx).encrypt;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_block_size(
    mut ctx: *const EVP_CIPHER_CTX,
) -> libc::c_uint {
    return (*(*ctx).cipher).block_size;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_key_length(
    mut ctx: *const EVP_CIPHER_CTX,
) -> libc::c_uint {
    return (*ctx).key_len;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_iv_length(
    mut ctx: *const EVP_CIPHER_CTX,
) -> libc::c_uint {
    if EVP_CIPHER_mode((*ctx).cipher) == 0x6 as libc::c_int as uint32_t
        || EVP_CIPHER_mode((*ctx).cipher) == 0x8 as libc::c_int as uint32_t
    {
        let mut length: libc::c_int = 0;
        let mut res: libc::c_int = EVP_CIPHER_CTX_ctrl(
            ctx as *mut EVP_CIPHER_CTX,
            0x19 as libc::c_int,
            0 as libc::c_int,
            &mut length as *mut libc::c_int as *mut libc::c_void,
        );
        if res == 1 as libc::c_int {
            return length as libc::c_uint;
        }
    }
    return (*(*ctx).cipher).iv_len;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_get_app_data(
    mut ctx: *const EVP_CIPHER_CTX,
) -> *mut libc::c_void {
    return (*ctx).app_data;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_set_app_data(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut data: *mut libc::c_void,
) {
    (*ctx).app_data = data;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_flags(
    mut ctx: *const EVP_CIPHER_CTX,
) -> uint32_t {
    return (*(*ctx).cipher).flags & !(0x3f as libc::c_int) as uint32_t;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_mode(
    mut ctx: *const EVP_CIPHER_CTX,
) -> uint32_t {
    return (*(*ctx).cipher).flags & 0x3f as libc::c_int as uint32_t;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_ctrl(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut command: libc::c_int,
    mut arg: libc::c_int,
    mut ptr: *mut libc::c_void,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    if ((*ctx).cipher).is_null() {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            114 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            652 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*(*ctx).cipher).ctrl).is_none() {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            657 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    ret = ((*(*ctx).cipher).ctrl)
        .expect("non-null function pointer")(ctx, command, arg, ptr);
    if ret == -(1 as libc::c_int) {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            663 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_set_padding(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut pad: libc::c_int,
) -> libc::c_int {
    if pad != 0 {
        (*ctx).flags &= !(0x800 as libc::c_int) as uint32_t;
    } else {
        (*ctx).flags |= 0x800 as libc::c_int as uint32_t;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_set_key_length(
    mut c: *mut EVP_CIPHER_CTX,
    mut key_len: libc::c_uint,
) -> libc::c_int {
    if (*c).key_len == key_len {
        return 1 as libc::c_int;
    }
    if key_len == 0 as libc::c_int as libc::c_uint
        || (*(*c).cipher).flags & 0x40 as libc::c_int as uint32_t == 0
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            110 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/cipher.c\0"
                as *const u8 as *const libc::c_char,
            685 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*c).key_len = key_len;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_nid(mut cipher: *const EVP_CIPHER) -> libc::c_int {
    if !cipher.is_null() {
        return (*cipher).nid;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_block_size(
    mut cipher: *const EVP_CIPHER,
) -> libc::c_uint {
    if !cipher.is_null() {
        return (*cipher).block_size;
    }
    return 0 as libc::c_int as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_key_length(
    mut cipher: *const EVP_CIPHER,
) -> libc::c_uint {
    if !cipher.is_null() {
        return (*cipher).key_len;
    }
    return 0 as libc::c_int as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_iv_length(
    mut cipher: *const EVP_CIPHER,
) -> libc::c_uint {
    if !cipher.is_null() {
        return (*cipher).iv_len;
    }
    return 0 as libc::c_int as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_flags(mut cipher: *const EVP_CIPHER) -> uint32_t {
    return (*cipher).flags & !(0x3f as libc::c_int) as uint32_t;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_mode(mut cipher: *const EVP_CIPHER) -> uint32_t {
    return (*cipher).flags & 0x3f as libc::c_int as uint32_t;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_name(
    mut cipher: *const EVP_CIPHER,
) -> *const libc::c_char {
    if !cipher.is_null() {
        return OBJ_nid2sn((*cipher).nid);
    }
    return 0 as *const libc::c_char;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CipherInit(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut cipher: *const EVP_CIPHER,
    mut key: *const uint8_t,
    mut iv: *const uint8_t,
    mut enc: libc::c_int,
) -> libc::c_int {
    if !cipher.is_null() {
        EVP_CIPHER_CTX_init(ctx);
    }
    return EVP_CipherInit_ex(ctx, cipher, 0 as *mut ENGINE, key, iv, enc);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_EncryptInit(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut cipher: *const EVP_CIPHER,
    mut key: *const uint8_t,
    mut iv: *const uint8_t,
) -> libc::c_int {
    return EVP_CipherInit(ctx, cipher, key, iv, 1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_DecryptInit(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut cipher: *const EVP_CIPHER,
    mut key: *const uint8_t,
    mut iv: *const uint8_t,
) -> libc::c_int {
    return EVP_CipherInit(ctx, cipher, key, iv, 0 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CipherFinal(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut out_len: *mut libc::c_int,
) -> libc::c_int {
    return EVP_CipherFinal_ex(ctx, out, out_len);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_EncryptFinal(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut out_len: *mut libc::c_int,
) -> libc::c_int {
    return EVP_EncryptFinal_ex(ctx, out, out_len);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_DecryptFinal(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut out_len: *mut libc::c_int,
) -> libc::c_int {
    return EVP_DecryptFinal_ex(ctx, out, out_len);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_add_cipher_alias(
    mut a: *const libc::c_char,
    mut b: *const libc::c_char,
) -> libc::c_int {
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_set_flags(
    mut ctx: *const EVP_CIPHER_CTX,
    mut flags: uint32_t,
) {}
