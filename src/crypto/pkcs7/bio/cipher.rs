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
    pub type stack_st_void;
    pub type engine_st;
    fn BIO_read(bio: *mut BIO, data: *mut libc::c_void, len: libc::c_int) -> libc::c_int;
    fn BIO_write(
        bio: *mut BIO,
        data: *const libc::c_void,
        len: libc::c_int,
    ) -> libc::c_int;
    fn BIO_ctrl(
        bio: *mut BIO,
        cmd: libc::c_int,
        larg: libc::c_long,
        parg: *mut libc::c_void,
    ) -> libc::c_long;
    fn BIO_eof(bio: *mut BIO) -> libc::c_int;
    fn BIO_should_retry(bio: *const BIO) -> libc::c_int;
    fn BIO_next(bio: *mut BIO) -> *mut BIO;
    fn BIO_copy_next_retry(bio: *mut BIO);
    fn BIO_set_data(bio: *mut BIO, ptr: *mut libc::c_void);
    fn BIO_get_data(bio: *mut BIO) -> *mut libc::c_void;
    fn BIO_set_init(bio: *mut BIO, init: libc::c_int);
    fn EVP_des_ede3_cbc() -> *const EVP_CIPHER;
    fn EVP_aes_128_cbc() -> *const EVP_CIPHER;
    fn EVP_aes_128_ctr() -> *const EVP_CIPHER;
    fn EVP_aes_128_ofb() -> *const EVP_CIPHER;
    fn EVP_aes_256_cbc() -> *const EVP_CIPHER;
    fn EVP_aes_256_ctr() -> *const EVP_CIPHER;
    fn EVP_aes_256_ofb() -> *const EVP_CIPHER;
    fn EVP_chacha20_poly1305() -> *const EVP_CIPHER;
    fn EVP_CIPHER_CTX_new() -> *mut EVP_CIPHER_CTX;
    fn EVP_CIPHER_CTX_free(ctx: *mut EVP_CIPHER_CTX);
    fn EVP_CipherInit_ex(
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        engine: *mut ENGINE,
        key: *const uint8_t,
        iv: *const uint8_t,
        enc: libc::c_int,
    ) -> libc::c_int;
    fn EVP_EncryptUpdate(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut uint8_t,
        out_len: *mut libc::c_int,
        in_0: *const uint8_t,
        in_len: libc::c_int,
    ) -> libc::c_int;
    fn EVP_EncryptFinal_ex(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut uint8_t,
        out_len: *mut libc::c_int,
    ) -> libc::c_int;
    fn EVP_DecryptUpdate(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut uint8_t,
        out_len: *mut libc::c_int,
        in_0: *const uint8_t,
        in_len: libc::c_int,
    ) -> libc::c_int;
    fn EVP_DecryptFinal_ex(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut uint8_t,
        out_len: *mut libc::c_int,
    ) -> libc::c_int;
    fn EVP_CIPHER_CTX_encrypting(ctx: *const EVP_CIPHER_CTX) -> libc::c_int;
    fn EVP_CIPHER_CTX_block_size(ctx: *const EVP_CIPHER_CTX) -> libc::c_uint;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
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
pub struct bio_method_st {
    pub type_0: libc::c_int,
    pub name: *const libc::c_char,
    pub bwrite: Option::<
        unsafe extern "C" fn(*mut BIO, *const libc::c_char, libc::c_int) -> libc::c_int,
    >,
    pub bread: Option::<
        unsafe extern "C" fn(*mut BIO, *mut libc::c_char, libc::c_int) -> libc::c_int,
    >,
    pub bputs: Option::<
        unsafe extern "C" fn(*mut BIO, *const libc::c_char) -> libc::c_int,
    >,
    pub bgets: Option::<
        unsafe extern "C" fn(*mut BIO, *mut libc::c_char, libc::c_int) -> libc::c_int,
    >,
    pub ctrl: Option::<
        unsafe extern "C" fn(
            *mut BIO,
            libc::c_int,
            libc::c_long,
            *mut libc::c_void,
        ) -> libc::c_long,
    >,
    pub create: Option::<unsafe extern "C" fn(*mut BIO) -> libc::c_int>,
    pub destroy: Option::<unsafe extern "C" fn(*mut BIO) -> libc::c_int>,
    pub callback_ctrl: Option::<
        unsafe extern "C" fn(*mut BIO, libc::c_int, bio_info_cb) -> libc::c_long,
    >,
}
pub type bio_info_cb = Option::<
    unsafe extern "C" fn(*mut BIO, libc::c_int, libc::c_int) -> libc::c_long,
>;
pub type BIO = bio_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bio_st {
    pub method: *const BIO_METHOD,
    pub ex_data: CRYPTO_EX_DATA,
    pub callback_ex: BIO_callback_fn_ex,
    pub callback: BIO_callback_fn,
    pub cb_arg: *mut libc::c_char,
    pub init: libc::c_int,
    pub shutdown: libc::c_int,
    pub flags: libc::c_int,
    pub retry_reason: libc::c_int,
    pub num: libc::c_int,
    pub references: CRYPTO_refcount_t,
    pub ptr: *mut libc::c_void,
    pub next_bio: *mut BIO,
    pub num_read: uint64_t,
    pub num_write: uint64_t,
}
pub type CRYPTO_refcount_t = uint32_t;
pub type BIO_callback_fn = Option::<
    unsafe extern "C" fn(
        *mut BIO,
        libc::c_int,
        *const libc::c_char,
        libc::c_int,
        libc::c_long,
        libc::c_long,
    ) -> libc::c_long,
>;
pub type BIO_callback_fn_ex = Option::<
    unsafe extern "C" fn(
        *mut BIO,
        libc::c_int,
        *const libc::c_char,
        size_t,
        libc::c_int,
        libc::c_long,
        libc::c_int,
        *mut size_t,
    ) -> libc::c_long,
>;
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
pub type BIO_METHOD = bio_method_st;
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
pub type BIO_ENC_CTX = enc_struct;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct enc_struct {
    pub done: uint8_t,
    pub ok: uint8_t,
    pub buf_off: libc::c_int,
    pub buf_len: libc::c_int,
    pub cipher: *mut EVP_CIPHER_CTX,
    pub buf: [uint8_t; 4096],
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
unsafe extern "C" fn enc_new(mut b: *mut BIO) -> libc::c_int {
    let mut ctx: *mut BIO_ENC_CTX = 0 as *mut BIO_ENC_CTX;
    if b.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/cipher.c\0" as *const u8
                as *const libc::c_char,
            24 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    ctx = OPENSSL_zalloc(::core::mem::size_of::<BIO_ENC_CTX>() as libc::c_ulong)
        as *mut BIO_ENC_CTX;
    if ctx.is_null() {
        return 0 as libc::c_int;
    }
    (*ctx).cipher = EVP_CIPHER_CTX_new();
    if ((*ctx).cipher).is_null() {
        OPENSSL_free(ctx as *mut libc::c_void);
        return 0 as libc::c_int;
    }
    (*ctx).done = 0 as libc::c_int as uint8_t;
    (*ctx).ok = 1 as libc::c_int as uint8_t;
    (*ctx).buf_off = 0 as libc::c_int;
    (*ctx).buf_len = 0 as libc::c_int;
    BIO_set_data(b, ctx as *mut libc::c_void);
    BIO_set_init(b, 1 as libc::c_int);
    return 1 as libc::c_int;
}
unsafe extern "C" fn enc_free(mut b: *mut BIO) -> libc::c_int {
    if b.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/cipher.c\0" as *const u8
                as *const libc::c_char,
            46 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ctx: *mut BIO_ENC_CTX = BIO_get_data(b) as *mut BIO_ENC_CTX;
    if ctx.is_null() {
        return 0 as libc::c_int;
    }
    EVP_CIPHER_CTX_free((*ctx).cipher);
    OPENSSL_free(ctx as *mut libc::c_void);
    BIO_set_data(b, 0 as *mut libc::c_void);
    BIO_set_init(b, 0 as libc::c_int);
    return 1 as libc::c_int;
}
unsafe extern "C" fn enc_read(
    mut b: *mut BIO,
    mut out: *mut libc::c_char,
    mut outl: libc::c_int,
) -> libc::c_int {
    if b.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/cipher.c\0" as *const u8
                as *const libc::c_char,
            62 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if out.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/cipher.c\0" as *const u8
                as *const libc::c_char,
            63 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ctx: *mut BIO_ENC_CTX = BIO_get_data(b) as *mut BIO_ENC_CTX;
    if ctx.is_null() || ((*ctx).cipher).is_null() || (*ctx).ok == 0
        || outl <= 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    let mut next: *mut BIO = BIO_next(b);
    if next.is_null() {
        return 0 as libc::c_int;
    }
    let mut bytes_output: libc::c_int = 0 as libc::c_int;
    let mut remaining: libc::c_int = outl;
    let mut read_buf: [uint8_t; 4096] = [0; 4096];
    let cipher_block_size: libc::c_int = EVP_CIPHER_CTX_block_size((*ctx).cipher)
        as libc::c_int;
    while ((*ctx).done == 0 || (*ctx).buf_len > 0 as libc::c_int)
        && remaining > 0 as libc::c_int
    {
        if bytes_output + remaining == outl {} else {
            __assert_fail(
                b"bytes_output + remaining == outl\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/cipher.c\0"
                    as *const u8 as *const libc::c_char,
                78 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 33],
                    &[libc::c_char; 33],
                >(b"int enc_read(BIO *, char *, int)\0"))
                    .as_ptr(),
            );
        }
        'c_17087: {
            if bytes_output + remaining == outl {} else {
                __assert_fail(
                    b"bytes_output + remaining == outl\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/cipher.c\0"
                        as *const u8 as *const libc::c_char,
                    78 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 33],
                        &[libc::c_char; 33],
                    >(b"int enc_read(BIO *, char *, int)\0"))
                        .as_ptr(),
                );
            }
        };
        if (*ctx).buf_len > 0 as libc::c_int {
            let mut out_pos: *mut uint8_t = (out as *mut uint8_t)
                .offset(bytes_output as isize);
            let mut to_copy: libc::c_int = if remaining > (*ctx).buf_len {
                (*ctx).buf_len
            } else {
                remaining
            };
            OPENSSL_memcpy(
                out_pos as *mut libc::c_void,
                &mut *((*ctx).buf).as_mut_ptr().offset((*ctx).buf_off as isize)
                    as *mut uint8_t as *const libc::c_void,
                to_copy as size_t,
            );
            (*ctx).buf_len -= to_copy;
            (*ctx).buf_off += to_copy;
            bytes_output += to_copy;
            remaining -= to_copy;
        } else {
            (*ctx).buf_len = 0 as libc::c_int;
            (*ctx).buf_off = 0 as libc::c_int;
            let mut to_read: libc::c_int = ::core::mem::size_of::<[uint8_t; 4096]>()
                as libc::c_ulong as libc::c_int - cipher_block_size + 1 as libc::c_int;
            let mut bytes_read: libc::c_int = BIO_read(
                next,
                read_buf.as_mut_ptr() as *mut libc::c_void,
                to_read,
            );
            if bytes_read > 0 as libc::c_int {
                (*ctx)
                    .ok = EVP_DecryptUpdate(
                    (*ctx).cipher,
                    ((*ctx).buf).as_mut_ptr(),
                    &mut (*ctx).buf_len,
                    read_buf.as_mut_ptr(),
                    bytes_read,
                ) as uint8_t;
            } else if BIO_eof(next) != 0 {
                (*ctx)
                    .ok = EVP_DecryptFinal_ex(
                    (*ctx).cipher,
                    ((*ctx).buf).as_mut_ptr(),
                    &mut (*ctx).buf_len,
                ) as uint8_t;
                (*ctx).done = 1 as libc::c_int as uint8_t;
            } else {
                if bytes_read < 0 as libc::c_int && BIO_should_retry(next) == 0 {
                    (*ctx).done = 1 as libc::c_int as uint8_t;
                    (*ctx).ok = 0 as libc::c_int as uint8_t;
                }
                BIO_copy_next_retry(b);
                break;
            }
            if (*ctx).ok == 0 {
                (*ctx).done = 1 as libc::c_int as uint8_t;
            }
        }
    }
    return bytes_output;
}
unsafe extern "C" fn enc_flush(
    mut b: *mut BIO,
    mut next: *mut BIO,
    mut ctx: *mut BIO_ENC_CTX,
) -> libc::c_int {
    if b.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/cipher.c\0" as *const u8
                as *const libc::c_char,
            124 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if next.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/cipher.c\0" as *const u8
                as *const libc::c_char,
            125 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ctx.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/cipher.c\0" as *const u8
                as *const libc::c_char,
            126 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    while (*ctx).ok as libc::c_int > 0 as libc::c_int
        && ((*ctx).buf_len > 0 as libc::c_int || (*ctx).done == 0)
    {
        let mut bytes_written: libc::c_int = BIO_write(
            next,
            &mut *((*ctx).buf).as_mut_ptr().offset((*ctx).buf_off as isize)
                as *mut uint8_t as *const libc::c_void,
            (*ctx).buf_len,
        );
        if (*ctx).buf_len > 0 as libc::c_int && bytes_written <= 0 as libc::c_int {
            if bytes_written < 0 as libc::c_int && BIO_should_retry(next) == 0 {
                (*ctx).done = 1 as libc::c_int as uint8_t;
                (*ctx).ok = 0 as libc::c_int as uint8_t;
            }
            BIO_copy_next_retry(b);
            return 0 as libc::c_int;
        }
        (*ctx).buf_off += bytes_written;
        (*ctx).buf_len -= bytes_written;
        if (*ctx).buf_len == 0 as libc::c_int && (*ctx).done == 0 {
            (*ctx).done = 1 as libc::c_int as uint8_t;
            (*ctx).buf_off = 0 as libc::c_int;
            (*ctx)
                .ok = EVP_EncryptFinal_ex(
                (*ctx).cipher,
                ((*ctx).buf).as_mut_ptr(),
                &mut (*ctx).buf_len,
            ) as uint8_t;
        }
    }
    return (*ctx).ok as libc::c_int;
}
unsafe extern "C" fn enc_write(
    mut b: *mut BIO,
    mut in_0: *const libc::c_char,
    mut inl: libc::c_int,
) -> libc::c_int {
    if b.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/cipher.c\0" as *const u8
                as *const libc::c_char,
            149 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if in_0.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/cipher.c\0" as *const u8
                as *const libc::c_char,
            150 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ctx: *mut BIO_ENC_CTX = BIO_get_data(b) as *mut BIO_ENC_CTX;
    if ctx.is_null() || ((*ctx).cipher).is_null() || (*ctx).done as libc::c_int != 0
        || (*ctx).ok == 0 || inl <= 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    let mut next: *mut BIO = BIO_next(b);
    if next.is_null() {
        return 0 as libc::c_int;
    }
    let mut bytes_consumed: libc::c_int = 0 as libc::c_int;
    let mut remaining: libc::c_int = inl;
    let max_crypt_size: libc::c_int = (::core::mem::size_of::<[uint8_t; 4096]>()
        as libc::c_ulong as libc::c_int as libc::c_uint)
        .wrapping_sub(EVP_CIPHER_CTX_block_size((*ctx).cipher))
        .wrapping_add(1 as libc::c_int as libc::c_uint) as libc::c_int;
    while ((*ctx).done == 0 || (*ctx).buf_len > 0 as libc::c_int)
        && remaining > 0 as libc::c_int
    {
        if bytes_consumed + remaining == inl {} else {
            __assert_fail(
                b"bytes_consumed + remaining == inl\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/cipher.c\0"
                    as *const u8 as *const libc::c_char,
                165 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 40],
                    &[libc::c_char; 40],
                >(b"int enc_write(BIO *, const char *, int)\0"))
                    .as_ptr(),
            );
        }
        'c_17470: {
            if bytes_consumed + remaining == inl {} else {
                __assert_fail(
                    b"bytes_consumed + remaining == inl\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/cipher.c\0"
                        as *const u8 as *const libc::c_char,
                    165 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 40],
                        &[libc::c_char; 40],
                    >(b"int enc_write(BIO *, const char *, int)\0"))
                        .as_ptr(),
                );
            }
        };
        if (*ctx).buf_len == 0 as libc::c_int {
            (*ctx).buf_off = 0 as libc::c_int;
            let mut to_encrypt: libc::c_int = if remaining < max_crypt_size {
                remaining
            } else {
                max_crypt_size
            };
            let mut in_pos: *mut uint8_t = (in_0 as *mut uint8_t)
                .offset(bytes_consumed as isize);
            (*ctx)
                .ok = EVP_EncryptUpdate(
                (*ctx).cipher,
                ((*ctx).buf).as_mut_ptr(),
                &mut (*ctx).buf_len,
                in_pos,
                to_encrypt,
            ) as uint8_t;
            if (*ctx).ok == 0 {
                break;
            }
            bytes_consumed += to_encrypt;
            remaining -= to_encrypt;
        }
        let mut bytes_written: libc::c_int = BIO_write(
            next,
            &mut *((*ctx).buf).as_mut_ptr().offset((*ctx).buf_off as isize)
                as *mut uint8_t as *const libc::c_void,
            (*ctx).buf_len,
        );
        if bytes_written <= 0 as libc::c_int {
            if bytes_written < 0 as libc::c_int && BIO_should_retry(next) == 0 {
                (*ctx).done = 1 as libc::c_int as uint8_t;
                (*ctx).ok = 0 as libc::c_int as uint8_t;
            }
            BIO_copy_next_retry(b);
            break;
        } else {
            (*ctx).buf_off += bytes_written;
            (*ctx).buf_len -= bytes_written;
        }
    }
    return bytes_consumed;
}
unsafe extern "C" fn enc_ctrl(
    mut b: *mut BIO,
    mut cmd: libc::c_int,
    mut num: libc::c_long,
    mut ptr: *mut libc::c_void,
) -> libc::c_long {
    if b.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/cipher.c\0" as *const u8
                as *const libc::c_char,
            194 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int as libc::c_long;
    }
    let mut ret: libc::c_long = 1 as libc::c_int as libc::c_long;
    let mut ctx: *mut BIO_ENC_CTX = BIO_get_data(b) as *mut BIO_ENC_CTX;
    let mut cipher_ctx: *mut *mut EVP_CIPHER_CTX = 0 as *mut *mut EVP_CIPHER_CTX;
    let mut next: *mut BIO = BIO_next(b);
    if ctx.is_null() {
        return 0 as libc::c_int as libc::c_long;
    }
    match cmd {
        1 => {
            (*ctx).done = 0 as libc::c_int as uint8_t;
            (*ctx).ok = 1 as libc::c_int as uint8_t;
            (*ctx).buf_off = 0 as libc::c_int;
            (*ctx).buf_len = 0 as libc::c_int;
            OPENSSL_cleanse(
                ((*ctx).buf).as_mut_ptr() as *mut libc::c_void,
                ::core::mem::size_of::<[uint8_t; 4096]>() as libc::c_ulong,
            );
            if EVP_CipherInit_ex(
                (*ctx).cipher,
                0 as *const EVP_CIPHER,
                0 as *mut ENGINE,
                0 as *const uint8_t,
                0 as *const uint8_t,
                EVP_CIPHER_CTX_encrypting((*ctx).cipher),
            ) == 0
            {
                return 0 as libc::c_int as libc::c_long;
            }
            ret = BIO_ctrl(next, cmd, num, ptr);
        }
        2 => {
            if (*ctx).done != 0 {
                ret = 1 as libc::c_int as libc::c_long;
            } else {
                ret = BIO_ctrl(next, cmd, num, ptr);
            }
        }
        13 | 10 => {
            ret = (*ctx).buf_len as libc::c_long;
            if ret <= 0 as libc::c_int as libc::c_long {
                ret = BIO_ctrl(next, cmd, num, ptr);
            }
        }
        11 => {
            ret = enc_flush(b, next, ctx) as libc::c_long;
            if !(ret <= 0 as libc::c_int as libc::c_long) {
                ret = BIO_ctrl(next, cmd, num, ptr);
                BIO_copy_next_retry(b);
            }
        }
        113 => {
            ret = (*ctx).ok as libc::c_long;
        }
        129 => {
            cipher_ctx = ptr as *mut *mut EVP_CIPHER_CTX;
            if cipher_ctx.is_null() {
                ret = 0 as libc::c_int as libc::c_long;
            } else {
                *cipher_ctx = (*ctx).cipher;
                BIO_set_init(b, 1 as libc::c_int);
            }
        }
        12 | 15 | 14 | 101 => {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                17 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/cipher.c\0"
                    as *const u8 as *const libc::c_char,
                261 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int as libc::c_long;
        }
        _ => {
            ret = BIO_ctrl(next, cmd, num, ptr);
        }
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn BIO_set_cipher(
    mut b: *mut BIO,
    mut c: *const EVP_CIPHER,
    mut key: *const libc::c_uchar,
    mut iv: *const libc::c_uchar,
    mut enc: libc::c_int,
) -> libc::c_int {
    if b.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/cipher.c\0" as *const u8
                as *const libc::c_char,
            272 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if c.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/cipher.c\0" as *const u8
                as *const libc::c_char,
            273 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ctx: *mut BIO_ENC_CTX = BIO_get_data(b) as *mut BIO_ENC_CTX;
    if ctx.is_null() {
        return 0 as libc::c_int;
    }
    let mut kSupportedCiphers: [*const EVP_CIPHER; 8] = [
        EVP_aes_128_cbc(),
        EVP_aes_128_ctr(),
        EVP_aes_128_ofb(),
        EVP_aes_256_cbc(),
        EVP_aes_256_ctr(),
        EVP_aes_256_ofb(),
        EVP_chacha20_poly1305(),
        EVP_des_ede3_cbc(),
    ];
    let kSupportedCiphersCount: size_t = (::core::mem::size_of::<
        [*const EVP_CIPHER; 8],
    >() as libc::c_ulong)
        .wrapping_div(::core::mem::size_of::<*mut EVP_CIPHER>() as libc::c_ulong);
    let mut supported: libc::c_int = 0 as libc::c_int;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < kSupportedCiphersCount {
        if c == kSupportedCiphers[i as usize] {
            supported = 1 as libc::c_int;
            break;
        } else {
            i = i.wrapping_add(1);
            i;
        }
    }
    if supported == 0 {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            17 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/cipher.c\0" as *const u8
                as *const libc::c_char,
            298 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if EVP_CipherInit_ex((*ctx).cipher, c, 0 as *mut ENGINE, key, iv, enc) == 0 {
        return 0 as libc::c_int;
    }
    BIO_set_init(b, 1 as libc::c_int);
    return 1 as libc::c_int;
}
static mut methods_enc: BIO_METHOD = unsafe {
    {
        let mut init = bio_method_st {
            type_0: 10 as libc::c_int | 0x200 as libc::c_int,
            name: b"cipher\0" as *const u8 as *const libc::c_char,
            bwrite: Some(
                enc_write
                    as unsafe extern "C" fn(
                        *mut BIO,
                        *const libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            bread: Some(
                enc_read
                    as unsafe extern "C" fn(
                        *mut BIO,
                        *mut libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            bputs: None,
            bgets: None,
            ctrl: Some(
                enc_ctrl
                    as unsafe extern "C" fn(
                        *mut BIO,
                        libc::c_int,
                        libc::c_long,
                        *mut libc::c_void,
                    ) -> libc::c_long,
            ),
            create: Some(enc_new as unsafe extern "C" fn(*mut BIO) -> libc::c_int),
            destroy: Some(enc_free as unsafe extern "C" fn(*mut BIO) -> libc::c_int),
            callback_ctrl: None,
        };
        init
    }
};
#[no_mangle]
pub unsafe extern "C" fn BIO_f_cipher() -> *const BIO_METHOD {
    return &methods_enc;
}
#[no_mangle]
pub unsafe extern "C" fn BIO_get_cipher_ctx(
    mut b: *mut BIO,
    mut ctx: *mut *mut EVP_CIPHER_CTX,
) -> libc::c_int {
    return BIO_ctrl(
        b,
        129 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        ctx as *mut libc::c_void,
    ) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn BIO_get_cipher_status(mut b: *mut BIO) -> libc::c_int {
    return BIO_ctrl(
        b,
        113 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        0 as *mut libc::c_void,
    ) as libc::c_int;
}
