#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
unsafe extern "C" {
    pub type evp_cipher_st;
    pub type engine_st;
    fn EVP_aes_128_cbc() -> *const EVP_CIPHER;
    fn EVP_aes_256_cbc() -> *const EVP_CIPHER;
    fn EVP_CIPHER_CTX_init(ctx: *mut EVP_CIPHER_CTX);
    fn EVP_CIPHER_CTX_cleanup(ctx: *mut EVP_CIPHER_CTX) -> libc::c_int;
    fn EVP_CIPHER_CTX_copy(
        out: *mut EVP_CIPHER_CTX,
        in_0: *const EVP_CIPHER_CTX,
    ) -> libc::c_int;
    fn EVP_EncryptInit_ex(
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        impl_0: *mut ENGINE,
        key: *const uint8_t,
        iv: *const uint8_t,
    ) -> libc::c_int;
    fn EVP_CIPHER_CTX_block_size(ctx: *const EVP_CIPHER_CTX) -> libc::c_uint;
    fn EVP_CIPHER_block_size(cipher: *const EVP_CIPHER) -> libc::c_uint;
    fn EVP_CIPHER_key_length(cipher: *const EVP_CIPHER) -> libc::c_uint;
    fn EVP_Cipher(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut uint8_t,
        in_0: *const uint8_t,
        in_len: size_t,
    ) -> libc::c_int;
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
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cmac_ctx_st {
    pub cipher_ctx: EVP_CIPHER_CTX,
    pub k1: [uint8_t; 16],
    pub k2: [uint8_t; 16],
    pub block: [uint8_t; 16],
    pub block_used: libc::c_uint,
}
pub type EVP_CIPHER_CTX = evp_cipher_ctx_st;
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
pub type CMAC_CTX = cmac_ctx_st;
pub type ENGINE = engine_st;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_273_error_is_EVP_MAX_BLOCK_LENGTH_is_too_large {
    #[bitfield(
        name = "static_assertion_at_line_273_error_is_EVP_MAX_BLOCK_LENGTH_is_too_large",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_273_error_is_EVP_MAX_BLOCK_LENGTH_is_too_large: [u8; 1],
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
unsafe extern "C" fn FIPS_service_indicator_lock_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_unlock_state() {}
#[inline]
unsafe extern "C" fn AES_CMAC_verify_service_indicator(mut ctx: *const CMAC_CTX) {}
unsafe extern "C" fn CMAC_CTX_init(mut ctx: *mut CMAC_CTX) {
    EVP_CIPHER_CTX_init(&mut (*ctx).cipher_ctx);
}
unsafe extern "C" fn CMAC_CTX_cleanup(mut ctx: *mut CMAC_CTX) {
    EVP_CIPHER_CTX_cleanup(&mut (*ctx).cipher_ctx);
    OPENSSL_cleanse(
        ((*ctx).k1).as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        ((*ctx).k2).as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        ((*ctx).block).as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn AES_CMAC(
    mut out: *mut uint8_t,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
) -> libc::c_int {
    let mut cipher: *const EVP_CIPHER = 0 as *const EVP_CIPHER;
    match key_len {
        16 => {
            cipher = EVP_aes_128_cbc();
        }
        32 => {
            cipher = EVP_aes_256_cbc();
        }
        _ => return 0 as libc::c_int,
    }
    FIPS_service_indicator_lock_state();
    let mut scratch_out_len: size_t = 0;
    let mut ctx: CMAC_CTX = cmac_ctx_st {
        cipher_ctx: evp_cipher_ctx_st {
            cipher: 0 as *const EVP_CIPHER,
            app_data: 0 as *mut libc::c_void,
            cipher_data: 0 as *mut libc::c_void,
            key_len: 0,
            encrypt: 0,
            flags: 0,
            oiv: [0; 16],
            iv: [0; 16],
            buf: [0; 32],
            buf_len: 0,
            num: 0,
            final_used: 0,
            final_0: [0; 32],
            poisoned: 0,
        },
        k1: [0; 16],
        k2: [0; 16],
        block: [0; 16],
        block_used: 0,
    };
    CMAC_CTX_init(&mut ctx);
    let ok: libc::c_int = (CMAC_Init(
        &mut ctx,
        key as *const libc::c_void,
        key_len,
        cipher,
        0 as *mut ENGINE,
    ) != 0 && CMAC_Update(&mut ctx, in_0, in_len) != 0
        && CMAC_Final(&mut ctx, out, &mut scratch_out_len) != 0) as libc::c_int;
    FIPS_service_indicator_unlock_state();
    if ok != 0 {
        AES_CMAC_verify_service_indicator(&mut ctx);
    }
    CMAC_CTX_cleanup(&mut ctx);
    return ok;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CMAC_CTX_new() -> *mut CMAC_CTX {
    let mut ctx: *mut CMAC_CTX = OPENSSL_zalloc(
        ::core::mem::size_of::<CMAC_CTX>() as libc::c_ulong,
    ) as *mut CMAC_CTX;
    !ctx.is_null();
    return ctx;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CMAC_CTX_free(mut ctx: *mut CMAC_CTX) {
    if ctx.is_null() {
        return;
    }
    CMAC_CTX_cleanup(ctx);
    OPENSSL_free(ctx as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CMAC_CTX_copy(
    mut out: *mut CMAC_CTX,
    mut in_0: *const CMAC_CTX,
) -> libc::c_int {
    if EVP_CIPHER_CTX_copy(&mut (*out).cipher_ctx, &(*in_0).cipher_ctx) == 0 {
        return 0 as libc::c_int;
    }
    OPENSSL_memcpy(
        ((*out).k1).as_mut_ptr() as *mut libc::c_void,
        ((*in_0).k1).as_ptr() as *const libc::c_void,
        16 as libc::c_int as size_t,
    );
    OPENSSL_memcpy(
        ((*out).k2).as_mut_ptr() as *mut libc::c_void,
        ((*in_0).k2).as_ptr() as *const libc::c_void,
        16 as libc::c_int as size_t,
    );
    OPENSSL_memcpy(
        ((*out).block).as_mut_ptr() as *mut libc::c_void,
        ((*in_0).block).as_ptr() as *const libc::c_void,
        16 as libc::c_int as size_t,
    );
    (*out).block_used = (*in_0).block_used;
    return 1 as libc::c_int;
}
unsafe extern "C" fn binary_field_mul_x_128(
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 15 as libc::c_int as libc::c_uint {
        *out
            .offset(
                i as isize,
            ) = ((*in_0.offset(i as isize) as libc::c_int) << 1 as libc::c_int
            | *in_0.offset(i.wrapping_add(1 as libc::c_int as libc::c_uint) as isize)
                as libc::c_int >> 7 as libc::c_int) as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
    let carry: uint8_t = (*in_0.offset(0 as libc::c_int as isize) as libc::c_int
        >> 7 as libc::c_int) as uint8_t;
    *out
        .offset(
            i as isize,
        ) = ((*in_0.offset(i as isize) as libc::c_int) << 1 as libc::c_int
        ^ 0 as libc::c_int - carry as libc::c_int & 0x87 as libc::c_int) as uint8_t;
}
unsafe extern "C" fn binary_field_mul_x_64(
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 7 as libc::c_int as libc::c_uint {
        *out
            .offset(
                i as isize,
            ) = ((*in_0.offset(i as isize) as libc::c_int) << 1 as libc::c_int
            | *in_0.offset(i.wrapping_add(1 as libc::c_int as libc::c_uint) as isize)
                as libc::c_int >> 7 as libc::c_int) as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
    let carry: uint8_t = (*in_0.offset(0 as libc::c_int as isize) as libc::c_int
        >> 7 as libc::c_int) as uint8_t;
    *out
        .offset(
            i as isize,
        ) = ((*in_0.offset(i as isize) as libc::c_int) << 1 as libc::c_int
        ^ 0 as libc::c_int - carry as libc::c_int & 0x1b as libc::c_int) as uint8_t;
}
static mut kZeroIV: [uint8_t; 16] = [
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
];
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CMAC_Init(
    mut ctx: *mut CMAC_CTX,
    mut key: *const libc::c_void,
    mut key_len: size_t,
    mut cipher: *const EVP_CIPHER,
    mut engine: *mut ENGINE,
) -> libc::c_int {
    FIPS_service_indicator_lock_state();
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut scratch: [uint8_t; 16] = [0; 16];
    let mut block_size: size_t = EVP_CIPHER_block_size(cipher) as size_t;
    if !(block_size != 16 as libc::c_int as size_t
        && block_size != 8 as libc::c_int as size_t
        || EVP_CIPHER_key_length(cipher) as size_t != key_len
        || EVP_EncryptInit_ex(
            &mut (*ctx).cipher_ctx,
            cipher,
            0 as *mut ENGINE,
            key as *const uint8_t,
            kZeroIV.as_ptr(),
        ) == 0
        || EVP_Cipher(
            &mut (*ctx).cipher_ctx,
            scratch.as_mut_ptr(),
            kZeroIV.as_ptr(),
            block_size,
        ) == 0
        || EVP_EncryptInit_ex(
            &mut (*ctx).cipher_ctx,
            0 as *const EVP_CIPHER,
            0 as *mut ENGINE,
            0 as *const uint8_t,
            kZeroIV.as_ptr(),
        ) == 0)
    {
        if block_size == 16 as libc::c_int as size_t {
            binary_field_mul_x_128(
                ((*ctx).k1).as_mut_ptr(),
                scratch.as_mut_ptr() as *const uint8_t,
            );
            binary_field_mul_x_128(
                ((*ctx).k2).as_mut_ptr(),
                ((*ctx).k1).as_mut_ptr() as *const uint8_t,
            );
        } else {
            binary_field_mul_x_64(
                ((*ctx).k1).as_mut_ptr(),
                scratch.as_mut_ptr() as *const uint8_t,
            );
            binary_field_mul_x_64(
                ((*ctx).k2).as_mut_ptr(),
                ((*ctx).k1).as_mut_ptr() as *const uint8_t,
            );
        }
        (*ctx).block_used = 0 as libc::c_int as libc::c_uint;
        ret = 1 as libc::c_int;
    }
    FIPS_service_indicator_unlock_state();
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CMAC_Reset(mut ctx: *mut CMAC_CTX) -> libc::c_int {
    (*ctx).block_used = 0 as libc::c_int as libc::c_uint;
    return EVP_EncryptInit_ex(
        &mut (*ctx).cipher_ctx,
        0 as *const EVP_CIPHER,
        0 as *mut ENGINE,
        0 as *const uint8_t,
        kZeroIV.as_ptr(),
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CMAC_Update(
    mut ctx: *mut CMAC_CTX,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ret: libc::c_int = 0 as libc::c_int;
    FIPS_service_indicator_lock_state();
    let mut block_size: size_t = EVP_CIPHER_CTX_block_size(&mut (*ctx).cipher_ctx)
        as size_t;
    if block_size <= 16 as libc::c_int as size_t {} else {
        __assert_fail(
            b"block_size <= AES_BLOCK_SIZE\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cmac/cmac.c\0"
                as *const u8 as *const libc::c_char,
            230 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 53],
                &[libc::c_char; 53],
            >(b"int CMAC_Update(CMAC_CTX *, const uint8_t *, size_t)\0"))
                .as_ptr(),
        );
    }
    'c_1897: {
        if block_size <= 16 as libc::c_int as size_t {} else {
            __assert_fail(
                b"block_size <= AES_BLOCK_SIZE\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cmac/cmac.c\0"
                    as *const u8 as *const libc::c_char,
                230 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 53],
                    &[libc::c_char; 53],
                >(b"int CMAC_Update(CMAC_CTX *, const uint8_t *, size_t)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut scratch: [uint8_t; 16] = [0; 16];
    if (*ctx).block_used > 0 as libc::c_int as libc::c_uint {
        let mut todo: size_t = block_size.wrapping_sub((*ctx).block_used as size_t);
        if in_len < todo {
            todo = in_len;
        }
        OPENSSL_memcpy(
            ((*ctx).block).as_mut_ptr().offset((*ctx).block_used as isize)
                as *mut libc::c_void,
            in_0 as *const libc::c_void,
            todo,
        );
        in_0 = in_0.offset(todo as isize);
        in_len = in_len.wrapping_sub(todo);
        (*ctx)
            .block_used = ((*ctx).block_used as size_t).wrapping_add(todo)
            as libc::c_uint as libc::c_uint;
        if in_len == 0 as libc::c_int as size_t {
            ret = 1 as libc::c_int;
            current_block = 2107719957520439143;
        } else {
            if (*ctx).block_used as size_t == block_size {} else {
                __assert_fail(
                    b"ctx->block_used == block_size\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cmac/cmac.c\0"
                        as *const u8 as *const libc::c_char,
                    254 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 53],
                        &[libc::c_char; 53],
                    >(b"int CMAC_Update(CMAC_CTX *, const uint8_t *, size_t)\0"))
                        .as_ptr(),
                );
            }
            'c_1782: {
                if (*ctx).block_used as size_t == block_size {} else {
                    __assert_fail(
                        b"ctx->block_used == block_size\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cmac/cmac.c\0"
                            as *const u8 as *const libc::c_char,
                        254 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 53],
                            &[libc::c_char; 53],
                        >(b"int CMAC_Update(CMAC_CTX *, const uint8_t *, size_t)\0"))
                            .as_ptr(),
                    );
                }
            };
            if EVP_Cipher(
                &mut (*ctx).cipher_ctx,
                scratch.as_mut_ptr(),
                ((*ctx).block).as_mut_ptr(),
                block_size,
            ) == 0
            {
                current_block = 2107719957520439143;
            } else {
                current_block = 11050875288958768710;
            }
        }
    } else {
        current_block = 11050875288958768710;
    }
    loop {
        match current_block {
            2107719957520439143 => {
                FIPS_service_indicator_unlock_state();
                break;
            }
            _ => {
                if in_len > block_size {
                    if EVP_Cipher(
                        &mut (*ctx).cipher_ctx,
                        scratch.as_mut_ptr(),
                        in_0,
                        block_size,
                    ) == 0
                    {
                        current_block = 2107719957520439143;
                        continue;
                    }
                    in_0 = in_0.offset(block_size as isize);
                    in_len = in_len.wrapping_sub(block_size);
                    current_block = 11050875288958768710;
                } else {
                    OPENSSL_memcpy(
                        ((*ctx).block).as_mut_ptr() as *mut libc::c_void,
                        in_0 as *const libc::c_void,
                        in_len,
                    );
                    (*ctx).block_used = in_len as libc::c_uint;
                    ret = 1 as libc::c_int;
                    current_block = 2107719957520439143;
                }
            }
        }
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CMAC_Final(
    mut ctx: *mut CMAC_CTX,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
) -> libc::c_int {
    let mut mask: *const uint8_t = 0 as *const uint8_t;
    FIPS_service_indicator_lock_state();
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut block_size: size_t = EVP_CIPHER_CTX_block_size(&mut (*ctx).cipher_ctx)
        as size_t;
    if block_size <= 16 as libc::c_int as size_t {} else {
        __assert_fail(
            b"block_size <= AES_BLOCK_SIZE\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cmac/cmac.c\0"
                as *const u8 as *const libc::c_char,
            288 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 48],
                &[libc::c_char; 48],
            >(b"int CMAC_Final(CMAC_CTX *, uint8_t *, size_t *)\0"))
                .as_ptr(),
        );
    }
    'c_1554: {
        if block_size <= 16 as libc::c_int as size_t {} else {
            __assert_fail(
                b"block_size <= AES_BLOCK_SIZE\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cmac/cmac.c\0"
                    as *const u8 as *const libc::c_char,
                288 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 48],
                    &[libc::c_char; 48],
                >(b"int CMAC_Final(CMAC_CTX *, uint8_t *, size_t *)\0"))
                    .as_ptr(),
            );
        }
    };
    *out_len = block_size;
    if out.is_null() {
        ret = 1 as libc::c_int;
    } else {
        mask = ((*ctx).k1).as_mut_ptr();
        if (*ctx).block_used as size_t != block_size {
            (*ctx).block[(*ctx).block_used as usize] = 0x80 as libc::c_int as uint8_t;
            OPENSSL_memset(
                ((*ctx).block)
                    .as_mut_ptr()
                    .offset((*ctx).block_used as isize)
                    .offset(1 as libc::c_int as isize) as *mut libc::c_void,
                0 as libc::c_int,
                block_size
                    .wrapping_sub(
                        ((*ctx).block_used)
                            .wrapping_add(1 as libc::c_int as libc::c_uint) as size_t,
                    ),
            );
            mask = ((*ctx).k2).as_mut_ptr();
        }
        let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
        while (i as size_t) < block_size {
            *out
                .offset(
                    i as isize,
                ) = ((*ctx).block[i as usize] as libc::c_int
                ^ *mask.offset(i as isize) as libc::c_int) as uint8_t;
            i = i.wrapping_add(1);
            i;
        }
        ret = EVP_Cipher(&mut (*ctx).cipher_ctx, out, out, block_size);
    }
    FIPS_service_indicator_unlock_state();
    if ret != 0 {
        AES_CMAC_verify_service_indicator(ctx);
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CMAC_CTX_get0_cipher_ctx(
    mut ctx: *mut CMAC_CTX,
) -> *mut EVP_CIPHER_CTX {
    return &mut (*ctx).cipher_ctx;
}
