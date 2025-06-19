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
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type evp_cipher_st;
    pub type stack_st_void;
    pub type engine_st;
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
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strncmp(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn EVP_des_cbc() -> *const EVP_CIPHER;
    fn EVP_des_ede3_cbc() -> *const EVP_CIPHER;
    fn EVP_aes_128_cbc() -> *const EVP_CIPHER;
    fn EVP_aes_256_cbc() -> *const EVP_CIPHER;
    fn EVP_CIPHER_CTX_init(ctx: *mut EVP_CIPHER_CTX);
    fn EVP_CIPHER_CTX_cleanup(ctx: *mut EVP_CIPHER_CTX) -> libc::c_int;
    fn EVP_EncryptInit_ex(
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        impl_0: *mut ENGINE,
        key: *const uint8_t,
        iv: *const uint8_t,
    ) -> libc::c_int;
    fn EVP_DecryptInit_ex(
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        impl_0: *mut ENGINE,
        key: *const uint8_t,
        iv: *const uint8_t,
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
    fn EVP_CIPHER_nid(cipher: *const EVP_CIPHER) -> libc::c_int;
    fn EVP_CIPHER_iv_length(cipher: *const EVP_CIPHER) -> libc::c_uint;
    fn EVP_BytesToKey(
        type_0: *const EVP_CIPHER,
        md: *const EVP_MD,
        salt: *const uint8_t,
        data: *const uint8_t,
        data_len: size_t,
        count: libc::c_uint,
        key: *mut uint8_t,
        iv: *mut uint8_t,
    ) -> libc::c_int;
    fn EVP_aes_192_cbc() -> *const EVP_CIPHER;
    fn BIO_free(bio: *mut BIO) -> libc::c_int;
    fn BIO_gets(bio: *mut BIO, buf: *mut libc::c_char, size: libc::c_int) -> libc::c_int;
    fn BIO_write(
        bio: *mut BIO,
        data: *const libc::c_void,
        len: libc::c_int,
    ) -> libc::c_int;
    fn BIO_new_fp(stream: *mut FILE, close_flag: libc::c_int) -> *mut BIO;
    fn BUF_MEM_new() -> *mut BUF_MEM;
    fn BUF_MEM_free(buf: *mut BUF_MEM);
    fn BUF_MEM_grow(buf: *mut BUF_MEM, len: size_t) -> size_t;
    fn BUF_MEM_grow_clean(buf: *mut BUF_MEM, len: size_t) -> size_t;
    fn EVP_md5() -> *const EVP_MD;
    fn EVP_EncodeInit(ctx: *mut EVP_ENCODE_CTX);
    fn EVP_EncodeUpdate(
        ctx: *mut EVP_ENCODE_CTX,
        out: *mut uint8_t,
        out_len: *mut libc::c_int,
        in_0: *const uint8_t,
        in_len: size_t,
    ) -> libc::c_int;
    fn EVP_EncodeFinal(
        ctx: *mut EVP_ENCODE_CTX,
        out: *mut uint8_t,
        out_len: *mut libc::c_int,
    );
    fn EVP_DecodeInit(ctx: *mut EVP_ENCODE_CTX);
    fn EVP_DecodeUpdate(
        ctx: *mut EVP_ENCODE_CTX,
        out: *mut uint8_t,
        out_len: *mut libc::c_int,
        in_0: *const uint8_t,
        in_len: size_t,
    ) -> libc::c_int;
    fn EVP_DecodeFinal(
        ctx: *mut EVP_ENCODE_CTX,
        out: *mut uint8_t,
        out_len: *mut libc::c_int,
    ) -> libc::c_int;
    fn RAND_bytes(buf: *mut uint8_t, len: size_t) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn OPENSSL_isdigit(c: libc::c_int) -> libc::c_int;
    fn OPENSSL_fromxdigit(out: *mut uint8_t, c: libc::c_int) -> libc::c_int;
    fn OPENSSL_strlcpy(
        dst: *mut libc::c_char,
        src: *const libc::c_char,
        dst_size: size_t,
    ) -> size_t;
    fn OPENSSL_strlcat(
        dst: *mut libc::c_char,
        src: *const libc::c_char,
        dst_size: size_t,
    ) -> size_t;
    fn ERR_peek_error() -> uint32_t;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn ERR_add_error_data(count: libc::c_uint, _: ...);
    fn OBJ_nid2sn(nid: libc::c_int) -> *const libc::c_char;
    fn PEM_ASN1_read_bio(
        d2i: Option::<d2i_of_void>,
        name: *const libc::c_char,
        bp: *mut BIO,
        x: *mut *mut libc::c_void,
        cb: Option::<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> *mut libc::c_void;
}
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type size_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type EVP_CIPHER_INFO = evp_cipher_info_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_cipher_info_st {
    pub cipher: *const EVP_CIPHER,
    pub iv: [libc::c_uchar; 16],
}
pub type EVP_CIPHER = evp_cipher_st;
pub type CRYPTO_refcount_t = uint32_t;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct buf_mem_st {
    pub length: size_t,
    pub data: *mut libc::c_char,
    pub max: size_t,
}
pub type BUF_MEM = buf_mem_st;
pub type ENGINE = engine_st;
pub type EVP_MD = env_md_st;
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
pub type EVP_CIPHER_CTX = evp_cipher_ctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_encode_ctx_st {
    pub data_used: libc::c_uint,
    pub data: [uint8_t; 48],
    pub eof_seen: libc::c_char,
    pub error_encountered: libc::c_char,
}
pub type EVP_ENCODE_CTX = evp_encode_ctx_st;
pub type d2i_of_void = unsafe extern "C" fn(
    *mut *mut libc::c_void,
    *mut *const libc::c_uchar,
    libc::c_long,
) -> *mut libc::c_void;
pub type i2d_of_void = unsafe extern "C" fn(
    *const libc::c_void,
    *mut *mut libc::c_uchar,
) -> libc::c_int;
pub type pem_password_cb = unsafe extern "C" fn(
    *mut libc::c_char,
    libc::c_int,
    libc::c_int,
    *mut libc::c_void,
) -> libc::c_int;
#[inline]
unsafe extern "C" fn ERR_GET_LIB(mut packed_error: uint32_t) -> libc::c_int {
    return (packed_error >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as libc::c_int;
}
#[inline]
unsafe extern "C" fn ERR_GET_REASON(mut packed_error: uint32_t) -> libc::c_int {
    return (packed_error & 0xfff as libc::c_int as uint32_t) as libc::c_int;
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_proc_type(
    mut buf: *mut libc::c_char,
    mut type_0: libc::c_int,
) {
    let mut str: *const libc::c_char = 0 as *const libc::c_char;
    if type_0 == 10 as libc::c_int {
        str = b"ENCRYPTED\0" as *const u8 as *const libc::c_char;
    } else if type_0 == 30 as libc::c_int {
        str = b"MIC-CLEAR\0" as *const u8 as *const libc::c_char;
    } else if type_0 == 20 as libc::c_int {
        str = b"MIC-ONLY\0" as *const u8 as *const libc::c_char;
    } else {
        str = b"BAD-TYPE\0" as *const u8 as *const libc::c_char;
    }
    OPENSSL_strlcat(
        buf,
        b"Proc-Type: 4,\0" as *const u8 as *const libc::c_char,
        1024 as libc::c_int as size_t,
    );
    OPENSSL_strlcat(buf, str, 1024 as libc::c_int as size_t);
    OPENSSL_strlcat(
        buf,
        b"\n\0" as *const u8 as *const libc::c_char,
        1024 as libc::c_int as size_t,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_dek_info(
    mut buf: *mut libc::c_char,
    mut type_0: *const libc::c_char,
    mut len: size_t,
    mut str: *mut libc::c_char,
) {
    static mut map: [libc::c_uchar; 17] = unsafe {
        *::core::mem::transmute::<&[u8; 17], &[libc::c_uchar; 17]>(b"0123456789ABCDEF\0")
    };
    OPENSSL_strlcat(
        buf,
        b"DEK-Info: \0" as *const u8 as *const libc::c_char,
        1024 as libc::c_int as size_t,
    );
    OPENSSL_strlcat(buf, type_0, 1024 as libc::c_int as size_t);
    OPENSSL_strlcat(
        buf,
        b",\0" as *const u8 as *const libc::c_char,
        1024 as libc::c_int as size_t,
    );
    let mut buf_len: size_t = strlen(buf as *const libc::c_char);
    if len
        > (1024 as libc::c_int as size_t)
            .wrapping_sub(buf_len)
            .wrapping_sub(2 as libc::c_int as size_t) / 2 as libc::c_int as size_t
    {
        return;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < len {
        *buf
            .offset(
                buf_len.wrapping_add(i * 2 as libc::c_int as size_t) as isize,
            ) = map[(*str.offset(i as isize) as libc::c_int >> 4 as libc::c_int
            & 0xf as libc::c_int) as usize] as libc::c_char;
        *buf
            .offset(
                buf_len
                    .wrapping_add(i * 2 as libc::c_int as size_t)
                    .wrapping_add(1 as libc::c_int as size_t) as isize,
            ) = map[(*str.offset(i as isize) as libc::c_int & 0xf as libc::c_int)
            as usize] as libc::c_char;
        i = i.wrapping_add(1);
        i;
    }
    *buf
        .offset(
            buf_len.wrapping_add(len * 2 as libc::c_int as size_t) as isize,
        ) = '\n' as i32 as libc::c_char;
    *buf
        .offset(
            buf_len
                .wrapping_add(len * 2 as libc::c_int as size_t)
                .wrapping_add(1 as libc::c_int as size_t) as isize,
        ) = '\0' as i32 as libc::c_char;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_ASN1_read(
    mut d2i: Option::<d2i_of_void>,
    mut name: *const libc::c_char,
    mut fp: *mut FILE,
    mut x: *mut *mut libc::c_void,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut libc::c_void {
    let mut b: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if b.is_null() {
        ERR_put_error(
            9 as libc::c_int,
            0 as libc::c_int,
            7 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0" as *const u8
                as *const libc::c_char,
            126 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut libc::c_void;
    }
    let mut ret: *mut libc::c_void = PEM_ASN1_read_bio(d2i, name, b, x, cb, u);
    BIO_free(b);
    return ret;
}
unsafe extern "C" fn check_pem(
    mut nm: *const libc::c_char,
    mut name: *const libc::c_char,
) -> libc::c_int {
    if strcmp(nm, name) == 0 {
        return 1 as libc::c_int;
    }
    if strcmp(name, b"ANY PRIVATE KEY\0" as *const u8 as *const libc::c_char) == 0 {
        return (strcmp(
            nm,
            b"ENCRYPTED PRIVATE KEY\0" as *const u8 as *const libc::c_char,
        ) == 0 || strcmp(nm, b"PRIVATE KEY\0" as *const u8 as *const libc::c_char) == 0
            || strcmp(nm, b"RSA PRIVATE KEY\0" as *const u8 as *const libc::c_char) == 0
            || strcmp(nm, b"EC PRIVATE KEY\0" as *const u8 as *const libc::c_char) == 0
            || strcmp(nm, b"DSA PRIVATE KEY\0" as *const u8 as *const libc::c_char) == 0)
            as libc::c_int;
    }
    if strcmp(name, b"PARAMETERS\0" as *const u8 as *const libc::c_char) == 0 {
        return (strcmp(nm, b"EC PARAMETERS\0" as *const u8 as *const libc::c_char) == 0
            || strcmp(nm, b"DSA PARAMETERS\0" as *const u8 as *const libc::c_char) == 0
            || strcmp(nm, b"DH PARAMETERS\0" as *const u8 as *const libc::c_char) == 0)
            as libc::c_int;
    }
    if strcmp(nm, b"X509 CERTIFICATE\0" as *const u8 as *const libc::c_char) == 0
        && strcmp(name, b"CERTIFICATE\0" as *const u8 as *const libc::c_char) == 0
    {
        return 1 as libc::c_int;
    }
    if strcmp(nm, b"NEW CERTIFICATE REQUEST\0" as *const u8 as *const libc::c_char) == 0
        && strcmp(name, b"CERTIFICATE REQUEST\0" as *const u8 as *const libc::c_char)
            == 0
    {
        return 1 as libc::c_int;
    }
    if strcmp(nm, b"CERTIFICATE\0" as *const u8 as *const libc::c_char) == 0
        && strcmp(name, b"TRUSTED CERTIFICATE\0" as *const u8 as *const libc::c_char)
            == 0
    {
        return 1 as libc::c_int;
    }
    if strcmp(nm, b"X509 CERTIFICATE\0" as *const u8 as *const libc::c_char) == 0
        && strcmp(name, b"TRUSTED CERTIFICATE\0" as *const u8 as *const libc::c_char)
            == 0
    {
        return 1 as libc::c_int;
    }
    if strcmp(nm, b"CERTIFICATE\0" as *const u8 as *const libc::c_char) == 0
        && strcmp(name, b"PKCS7\0" as *const u8 as *const libc::c_char) == 0
    {
        return 1 as libc::c_int;
    }
    if strcmp(nm, b"PKCS #7 SIGNED DATA\0" as *const u8 as *const libc::c_char) == 0
        && strcmp(name, b"PKCS7\0" as *const u8 as *const libc::c_char) == 0
    {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn cipher_by_name(mut name: *const libc::c_char) -> *const EVP_CIPHER {
    if 0 as libc::c_int == strcmp(name, b"DES-CBC\0" as *const u8 as *const libc::c_char)
    {
        return EVP_des_cbc()
    } else if 0 as libc::c_int
        == strcmp(name, b"DES-EDE3-CBC\0" as *const u8 as *const libc::c_char)
    {
        return EVP_des_ede3_cbc()
    } else if 0 as libc::c_int
        == strcmp(name, b"AES-128-CBC\0" as *const u8 as *const libc::c_char)
    {
        return EVP_aes_128_cbc()
    } else if 0 as libc::c_int
        == strcmp(name, b"AES-192-CBC\0" as *const u8 as *const libc::c_char)
    {
        return EVP_aes_192_cbc()
    } else if 0 as libc::c_int
        == strcmp(name, b"AES-256-CBC\0" as *const u8 as *const libc::c_char)
    {
        return EVP_aes_256_cbc()
    } else {
        return 0 as *const EVP_CIPHER
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_bytes_read_bio(
    mut pdata: *mut *mut libc::c_uchar,
    mut plen: *mut libc::c_long,
    mut pnm: *mut *mut libc::c_char,
    mut name: *const libc::c_char,
    mut bp: *mut BIO,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> libc::c_int {
    let mut cipher: EVP_CIPHER_INFO = evp_cipher_info_st {
        cipher: 0 as *const EVP_CIPHER,
        iv: [0; 16],
    };
    let mut nm: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut header: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut data: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut len: libc::c_long = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    loop {
        if PEM_read_bio(bp, &mut nm, &mut header, &mut data, &mut len) == 0 {
            let mut error: uint32_t = ERR_peek_error();
            if ERR_GET_LIB(error) == 9 as libc::c_int
                && ERR_GET_REASON(error) == 110 as libc::c_int
            {
                ERR_add_error_data(
                    2 as libc::c_int as libc::c_uint,
                    b"Expecting: \0" as *const u8 as *const libc::c_char,
                    name,
                );
            }
            return 0 as libc::c_int;
        }
        if check_pem(nm, name) != 0 {
            break;
        }
        OPENSSL_free(nm as *mut libc::c_void);
        OPENSSL_free(header as *mut libc::c_void);
        OPENSSL_free(data as *mut libc::c_void);
    }
    if !(PEM_get_EVP_CIPHER_INFO(header, &mut cipher) == 0) {
        if !(PEM_do_header(&mut cipher, data, &mut len, cb, u) == 0) {
            *pdata = data;
            *plen = len;
            if !pnm.is_null() {
                *pnm = nm;
            }
            ret = 1 as libc::c_int;
        }
    }
    if ret == 0 || pnm.is_null() {
        OPENSSL_free(nm as *mut libc::c_void);
    }
    OPENSSL_free(header as *mut libc::c_void);
    if ret == 0 {
        OPENSSL_free(data as *mut libc::c_void);
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_ASN1_write(
    mut i2d: Option::<i2d_of_void>,
    mut name: *const libc::c_char,
    mut fp: *mut FILE,
    mut x: *mut libc::c_void,
    mut enc: *const EVP_CIPHER,
    mut pass: *const libc::c_uchar,
    mut pass_len: libc::c_int,
    mut callback: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> libc::c_int {
    let mut b: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if b.is_null() {
        ERR_put_error(
            9 as libc::c_int,
            0 as libc::c_int,
            7 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0" as *const u8
                as *const libc::c_char,
            274 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = PEM_ASN1_write_bio(
        i2d,
        name,
        b,
        x,
        enc,
        pass,
        pass_len,
        callback,
        u,
    );
    BIO_free(b);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_ASN1_write_bio(
    mut i2d: Option::<i2d_of_void>,
    mut name: *const libc::c_char,
    mut bp: *mut BIO,
    mut x: *mut libc::c_void,
    mut enc: *const EVP_CIPHER,
    mut pass: *const libc::c_uchar,
    mut pass_len: libc::c_int,
    mut callback: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> libc::c_int {
    let mut dsize: libc::c_int = 0;
    let mut current_block: u64;
    let mut ctx: EVP_CIPHER_CTX = evp_cipher_ctx_st {
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
    };
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut p: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut data: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut objstr: *const libc::c_char = 0 as *const libc::c_char;
    let mut buf: [libc::c_char; 1024] = [0; 1024];
    let mut key: [libc::c_uchar; 64] = [0; 64];
    let mut iv: [libc::c_uchar; 16] = [0; 16];
    if !enc.is_null() {
        objstr = OBJ_nid2sn(EVP_CIPHER_nid(enc));
        if objstr.is_null() || (cipher_by_name(objstr)).is_null()
            || EVP_CIPHER_iv_length(enc) < 8 as libc::c_int as libc::c_uint
        {
            ERR_put_error(
                9 as libc::c_int,
                0 as libc::c_int,
                113 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0" as *const u8
                    as *const libc::c_char,
                298 as libc::c_int as libc::c_uint,
            );
            current_block = 14023112239668288903;
        } else {
            current_block = 2473556513754201174;
        }
    } else {
        current_block = 2473556513754201174;
    }
    match current_block {
        2473556513754201174 => {
            dsize = i2d
                .expect("non-null function pointer")(x, 0 as *mut *mut libc::c_uchar);
            if dsize < 0 as libc::c_int {
                ERR_put_error(
                    9 as libc::c_int,
                    0 as libc::c_int,
                    12 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0"
                        as *const u8 as *const libc::c_char,
                    305 as libc::c_int as libc::c_uint,
                );
                OPENSSL_cleanse(
                    &mut dsize as *mut libc::c_int as *mut libc::c_void,
                    ::core::mem::size_of::<libc::c_int>() as libc::c_ulong,
                );
            } else {
                data = OPENSSL_malloc(
                    (dsize as libc::c_uint)
                        .wrapping_add(20 as libc::c_int as libc::c_uint) as size_t,
                ) as *mut libc::c_uchar;
                if !data.is_null() {
                    p = data;
                    i = i2d.expect("non-null function pointer")(x, &mut p);
                    if !enc.is_null() {
                        let iv_len: libc::c_uint = EVP_CIPHER_iv_length(enc);
                        if pass.is_null() {
                            if callback.is_none() {
                                callback = Some(
                                    PEM_def_callback
                                        as unsafe extern "C" fn(
                                            *mut libc::c_char,
                                            libc::c_int,
                                            libc::c_int,
                                            *mut libc::c_void,
                                        ) -> libc::c_int,
                                );
                            }
                            pass_len = (Some(
                                callback.expect("non-null function pointer"),
                            ))
                                .expect(
                                    "non-null function pointer",
                                )(
                                buf.as_mut_ptr(),
                                1024 as libc::c_int,
                                1 as libc::c_int,
                                u,
                            );
                            if pass_len <= 0 as libc::c_int {
                                ERR_put_error(
                                    9 as libc::c_int,
                                    0 as libc::c_int,
                                    111 as libc::c_int,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0"
                                        as *const u8 as *const libc::c_char,
                                    327 as libc::c_int as libc::c_uint,
                                );
                                current_block = 14023112239668288903;
                            } else {
                                pass = buf.as_mut_ptr() as *const libc::c_uchar;
                                current_block = 224731115979188411;
                            }
                        } else {
                            current_block = 224731115979188411;
                        }
                        match current_block {
                            14023112239668288903 => {}
                            _ => {
                                if iv_len as libc::c_ulong
                                    <= ::core::mem::size_of::<[libc::c_uchar; 16]>()
                                        as libc::c_ulong
                                {} else {
                                    __assert_fail(
                                        b"iv_len <= sizeof(iv)\0" as *const u8
                                            as *const libc::c_char,
                                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0"
                                            as *const u8 as *const libc::c_char,
                                        332 as libc::c_int as libc::c_uint,
                                        (*::core::mem::transmute::<
                                            &[u8; 142],
                                            &[libc::c_char; 142],
                                        >(
                                            b"int PEM_ASN1_write_bio(i2d_of_void *, const char *, BIO *, void *, const EVP_CIPHER *, const unsigned char *, int, pem_password_cb *, void *)\0",
                                        ))
                                            .as_ptr(),
                                    );
                                }
                                'c_29958: {
                                    if iv_len as libc::c_ulong
                                        <= ::core::mem::size_of::<[libc::c_uchar; 16]>()
                                            as libc::c_ulong
                                    {} else {
                                        __assert_fail(
                                            b"iv_len <= sizeof(iv)\0" as *const u8
                                                as *const libc::c_char,
                                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0"
                                                as *const u8 as *const libc::c_char,
                                            332 as libc::c_int as libc::c_uint,
                                            (*::core::mem::transmute::<
                                                &[u8; 142],
                                                &[libc::c_char; 142],
                                            >(
                                                b"int PEM_ASN1_write_bio(i2d_of_void *, const char *, BIO *, void *, const EVP_CIPHER *, const unsigned char *, int, pem_password_cb *, void *)\0",
                                            ))
                                                .as_ptr(),
                                        );
                                    }
                                };
                                if RAND_bytes(iv.as_mut_ptr(), iv_len as size_t) == 0 {
                                    current_block = 14023112239668288903;
                                } else if EVP_BytesToKey(
                                    enc,
                                    EVP_md5(),
                                    iv.as_mut_ptr(),
                                    pass,
                                    pass_len as size_t,
                                    1 as libc::c_int as libc::c_uint,
                                    key.as_mut_ptr(),
                                    0 as *mut uint8_t,
                                ) == 0
                                {
                                    current_block = 14023112239668288903;
                                } else {
                                    if pass == buf.as_mut_ptr() as *const libc::c_uchar {
                                        OPENSSL_cleanse(
                                            buf.as_mut_ptr() as *mut libc::c_void,
                                            1024 as libc::c_int as size_t,
                                        );
                                    }
                                    if (strlen(objstr))
                                        .wrapping_add(23 as libc::c_int as libc::c_ulong)
                                        .wrapping_add(
                                            (2 as libc::c_int as libc::c_uint).wrapping_mul(iv_len)
                                                as libc::c_ulong,
                                        )
                                        .wrapping_add(13 as libc::c_int as libc::c_ulong)
                                        <= ::core::mem::size_of::<[libc::c_char; 1024]>()
                                            as libc::c_ulong
                                    {} else {
                                        __assert_fail(
                                            b"strlen(objstr) + 23 + 2 * iv_len + 13 <= sizeof(buf)\0"
                                                as *const u8 as *const libc::c_char,
                                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0"
                                                as *const u8 as *const libc::c_char,
                                            346 as libc::c_int as libc::c_uint,
                                            (*::core::mem::transmute::<
                                                &[u8; 142],
                                                &[libc::c_char; 142],
                                            >(
                                                b"int PEM_ASN1_write_bio(i2d_of_void *, const char *, BIO *, void *, const EVP_CIPHER *, const unsigned char *, int, pem_password_cb *, void *)\0",
                                            ))
                                                .as_ptr(),
                                        );
                                    }
                                    'c_29826: {
                                        if (strlen(objstr))
                                            .wrapping_add(23 as libc::c_int as libc::c_ulong)
                                            .wrapping_add(
                                                (2 as libc::c_int as libc::c_uint).wrapping_mul(iv_len)
                                                    as libc::c_ulong,
                                            )
                                            .wrapping_add(13 as libc::c_int as libc::c_ulong)
                                            <= ::core::mem::size_of::<[libc::c_char; 1024]>()
                                                as libc::c_ulong
                                        {} else {
                                            __assert_fail(
                                                b"strlen(objstr) + 23 + 2 * iv_len + 13 <= sizeof(buf)\0"
                                                    as *const u8 as *const libc::c_char,
                                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0"
                                                    as *const u8 as *const libc::c_char,
                                                346 as libc::c_int as libc::c_uint,
                                                (*::core::mem::transmute::<
                                                    &[u8; 142],
                                                    &[libc::c_char; 142],
                                                >(
                                                    b"int PEM_ASN1_write_bio(i2d_of_void *, const char *, BIO *, void *, const EVP_CIPHER *, const unsigned char *, int, pem_password_cb *, void *)\0",
                                                ))
                                                    .as_ptr(),
                                            );
                                        }
                                    };
                                    buf[0 as libc::c_int
                                        as usize] = '\0' as i32 as libc::c_char;
                                    PEM_proc_type(buf.as_mut_ptr(), 10 as libc::c_int);
                                    PEM_dek_info(
                                        buf.as_mut_ptr(),
                                        objstr,
                                        iv_len as size_t,
                                        iv.as_mut_ptr() as *mut libc::c_char,
                                    );
                                    EVP_CIPHER_CTX_init(&mut ctx);
                                    ret = 1 as libc::c_int;
                                    if EVP_EncryptInit_ex(
                                        &mut ctx,
                                        enc,
                                        0 as *mut ENGINE,
                                        key.as_mut_ptr(),
                                        iv.as_mut_ptr(),
                                    ) == 0
                                        || EVP_EncryptUpdate(&mut ctx, data, &mut j, data, i) == 0
                                        || EVP_EncryptFinal_ex(
                                            &mut ctx,
                                            &mut *data.offset(j as isize),
                                            &mut i,
                                        ) == 0
                                    {
                                        ret = 0 as libc::c_int;
                                    } else {
                                        i += j;
                                    }
                                    EVP_CIPHER_CTX_cleanup(&mut ctx);
                                    if ret == 0 as libc::c_int {
                                        current_block = 14023112239668288903;
                                    } else {
                                        current_block = 13131896068329595644;
                                    }
                                }
                            }
                        }
                    } else {
                        ret = 1 as libc::c_int;
                        buf[0 as libc::c_int as usize] = '\0' as i32 as libc::c_char;
                        current_block = 13131896068329595644;
                    }
                    match current_block {
                        14023112239668288903 => {}
                        _ => {
                            i = PEM_write_bio(
                                bp,
                                name,
                                buf.as_mut_ptr(),
                                data,
                                i as libc::c_long,
                            );
                            if i <= 0 as libc::c_int {
                                ret = 0 as libc::c_int;
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    OPENSSL_cleanse(
        key.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[libc::c_uchar; 64]>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        iv.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[libc::c_uchar; 16]>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut ctx as *mut EVP_CIPHER_CTX as *mut libc::c_char as *mut libc::c_void,
        ::core::mem::size_of::<EVP_CIPHER_CTX>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        buf.as_mut_ptr() as *mut libc::c_void,
        1024 as libc::c_int as size_t,
    );
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_do_header(
    mut cipher: *mut EVP_CIPHER_INFO,
    mut data: *mut libc::c_uchar,
    mut plen: *mut libc::c_long,
    mut callback: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> libc::c_int {
    let mut i: libc::c_int = 0 as libc::c_int;
    let mut j: libc::c_int = 0;
    let mut o: libc::c_int = 0;
    let mut pass_len: libc::c_int = 0;
    let mut len: libc::c_long = 0;
    let mut ctx: EVP_CIPHER_CTX = evp_cipher_ctx_st {
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
    };
    let mut key: [libc::c_uchar; 64] = [0; 64];
    let mut buf: [libc::c_char; 1024] = [0; 1024];
    len = *plen;
    if ((*cipher).cipher).is_null() {
        return 1 as libc::c_int;
    }
    if callback.is_none() {
        callback = Some(
            PEM_def_callback
                as unsafe extern "C" fn(
                    *mut libc::c_char,
                    libc::c_int,
                    libc::c_int,
                    *mut libc::c_void,
                ) -> libc::c_int,
        );
    }
    pass_len = callback
        .expect(
            "non-null function pointer",
        )(buf.as_mut_ptr(), 1024 as libc::c_int, 0 as libc::c_int, u);
    if pass_len <= 0 as libc::c_int {
        ERR_put_error(
            9 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0" as *const u8
                as *const libc::c_char,
            402 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if EVP_BytesToKey(
        (*cipher).cipher,
        EVP_md5(),
        &mut *((*cipher).iv).as_mut_ptr().offset(0 as libc::c_int as isize),
        buf.as_mut_ptr() as *mut libc::c_uchar,
        pass_len as size_t,
        1 as libc::c_int as libc::c_uint,
        key.as_mut_ptr(),
        0 as *mut uint8_t,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    j = len as libc::c_int;
    EVP_CIPHER_CTX_init(&mut ctx);
    o = EVP_DecryptInit_ex(
        &mut ctx,
        (*cipher).cipher,
        0 as *mut ENGINE,
        key.as_mut_ptr(),
        &mut *((*cipher).iv).as_mut_ptr().offset(0 as libc::c_int as isize),
    );
    if o != 0 {
        o = EVP_DecryptUpdate(&mut ctx, data, &mut i, data, j);
    }
    if o != 0 {
        o = EVP_DecryptFinal_ex(&mut ctx, &mut *data.offset(i as isize), &mut j);
    }
    EVP_CIPHER_CTX_cleanup(&mut ctx);
    OPENSSL_cleanse(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        key.as_mut_ptr() as *mut libc::c_char as *mut libc::c_void,
        ::core::mem::size_of::<[libc::c_uchar; 64]>() as libc::c_ulong,
    );
    if o == 0 {
        ERR_put_error(
            9 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0" as *const u8
                as *const libc::c_char,
            424 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    j += i;
    *plen = j as libc::c_long;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_get_EVP_CIPHER_INFO(
    mut header: *mut libc::c_char,
    mut cipher: *mut EVP_CIPHER_INFO,
) -> libc::c_int {
    let mut enc: *const EVP_CIPHER = 0 as *const EVP_CIPHER;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut c: libc::c_char = 0;
    let mut header_pp: *mut *mut libc::c_char = &mut header;
    (*cipher).cipher = 0 as *const EVP_CIPHER;
    OPENSSL_memset(
        ((*cipher).iv).as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[libc::c_uchar; 16]>() as libc::c_ulong,
    );
    if header.is_null() || *header as libc::c_int == '\0' as i32
        || *header as libc::c_int == '\n' as i32
    {
        return 1 as libc::c_int;
    }
    if strncmp(
        header,
        b"Proc-Type: \0" as *const u8 as *const libc::c_char,
        11 as libc::c_int as libc::c_ulong,
    ) != 0 as libc::c_int
    {
        ERR_put_error(
            9 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0" as *const u8
                as *const libc::c_char,
            443 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    header = header.offset(11 as libc::c_int as isize);
    if *header as libc::c_int != '4' as i32 {
        return 0 as libc::c_int;
    }
    header = header.offset(1);
    header;
    if *header as libc::c_int != ',' as i32 {
        return 0 as libc::c_int;
    }
    header = header.offset(1);
    header;
    if strncmp(
        header,
        b"ENCRYPTED\0" as *const u8 as *const libc::c_char,
        9 as libc::c_int as libc::c_ulong,
    ) != 0 as libc::c_int
    {
        ERR_put_error(
            9 as libc::c_int,
            0 as libc::c_int,
            108 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0" as *const u8
                as *const libc::c_char,
            456 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    while *header as libc::c_int != '\n' as i32 && *header as libc::c_int != '\0' as i32
    {
        header = header.offset(1);
        header;
    }
    if *header as libc::c_int == '\0' as i32 {
        ERR_put_error(
            9 as libc::c_int,
            0 as libc::c_int,
            112 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0" as *const u8
                as *const libc::c_char,
            463 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    header = header.offset(1);
    header;
    if strncmp(
        header,
        b"DEK-Info: \0" as *const u8 as *const libc::c_char,
        10 as libc::c_int as libc::c_ulong,
    ) != 0 as libc::c_int
    {
        ERR_put_error(
            9 as libc::c_int,
            0 as libc::c_int,
            107 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0" as *const u8
                as *const libc::c_char,
            468 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    header = header.offset(10 as libc::c_int as isize);
    p = header;
    loop {
        c = *header;
        if !(c as libc::c_int >= 'A' as i32 && c as libc::c_int <= 'Z' as i32
            || c as libc::c_int == '-' as i32 || OPENSSL_isdigit(c as libc::c_int) != 0)
        {
            break;
        }
        header = header.offset(1);
        header;
    }
    *header = '\0' as i32 as libc::c_char;
    enc = cipher_by_name(p);
    (*cipher).cipher = enc;
    *header = c;
    header = header.offset(1);
    header;
    if enc.is_null() {
        ERR_put_error(
            9 as libc::c_int,
            0 as libc::c_int,
            114 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0" as *const u8
                as *const libc::c_char,
            488 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if EVP_CIPHER_iv_length(enc) < 8 as libc::c_int as libc::c_uint {
        __assert_fail(
            b"0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0" as *const u8
                as *const libc::c_char,
            494 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 55],
                &[libc::c_char; 55],
            >(b"int PEM_get_EVP_CIPHER_INFO(char *, EVP_CIPHER_INFO *)\0"))
                .as_ptr(),
        );
        'c_26613: {
            __assert_fail(
                b"0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0" as *const u8
                    as *const libc::c_char,
                494 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 55],
                    &[libc::c_char; 55],
                >(b"int PEM_get_EVP_CIPHER_INFO(char *, EVP_CIPHER_INFO *)\0"))
                    .as_ptr(),
            );
        };
        ERR_put_error(
            9 as libc::c_int,
            0 as libc::c_int,
            114 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0" as *const u8
                as *const libc::c_char,
            495 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if load_iv(
        header_pp,
        &mut *((*cipher).iv).as_mut_ptr().offset(0 as libc::c_int as isize),
        EVP_CIPHER_iv_length(enc) as size_t,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn load_iv(
    mut fromp: *mut *mut libc::c_char,
    mut to: *mut libc::c_uchar,
    mut num: size_t,
) -> libc::c_int {
    let mut v: uint8_t = 0;
    let mut from: *mut libc::c_char = 0 as *mut libc::c_char;
    from = *fromp;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < num {
        *to.offset(i as isize) = 0 as libc::c_int as libc::c_uchar;
        i = i.wrapping_add(1);
        i;
    }
    num = num * 2 as libc::c_int as size_t;
    let mut i_0: size_t = 0 as libc::c_int as size_t;
    while i_0 < num {
        if OPENSSL_fromxdigit(&mut v, *from as libc::c_int) == 0 {
            ERR_put_error(
                9 as libc::c_int,
                0 as libc::c_int,
                103 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0" as *const u8
                    as *const libc::c_char,
                516 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        from = from.offset(1);
        from;
        let ref mut fresh0 = *to.offset((i_0 / 2 as libc::c_int as size_t) as isize);
        *fresh0 = (*fresh0 as libc::c_int
            | (v as libc::c_int)
                << (i_0 & 1 as libc::c_int as size_t == 0) as libc::c_int
                    * 4 as libc::c_int) as libc::c_uchar;
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
    *fromp = from;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_write(
    mut fp: *mut FILE,
    mut name: *const libc::c_char,
    mut header: *const libc::c_char,
    mut data: *const libc::c_uchar,
    mut len: libc::c_long,
) -> libc::c_int {
    let mut b: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if b.is_null() {
        ERR_put_error(
            9 as libc::c_int,
            0 as libc::c_int,
            7 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0" as *const u8
                as *const libc::c_char,
            531 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = PEM_write_bio(b, name, header, data, len);
    BIO_free(b);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_write_bio(
    mut bp: *mut BIO,
    mut name: *const libc::c_char,
    mut header: *const libc::c_char,
    mut data: *const libc::c_uchar,
    mut len: libc::c_long,
) -> libc::c_int {
    let mut current_block: u64;
    let mut nlen: libc::c_int = 0;
    let mut n: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    let mut outl: libc::c_int = 0;
    let mut buf: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut ctx: EVP_ENCODE_CTX = evp_encode_ctx_st {
        data_used: 0,
        data: [0; 48],
        eof_seen: 0,
        error_encountered: 0,
    };
    let mut reason: libc::c_int = 7 as libc::c_int;
    EVP_EncodeInit(&mut ctx);
    nlen = strlen(name) as libc::c_int;
    if !(BIO_write(
        bp,
        b"-----BEGIN \0" as *const u8 as *const libc::c_char as *const libc::c_void,
        11 as libc::c_int,
    ) != 11 as libc::c_int || BIO_write(bp, name as *const libc::c_void, nlen) != nlen
        || BIO_write(
            bp,
            b"-----\n\0" as *const u8 as *const libc::c_char as *const libc::c_void,
            6 as libc::c_int,
        ) != 6 as libc::c_int)
    {
        i = (if !header.is_null() {
            strlen(header)
        } else {
            0 as libc::c_int as libc::c_ulong
        }) as libc::c_int;
        if i > 0 as libc::c_int {
            if BIO_write(bp, header as *const libc::c_void, i) != i
                || BIO_write(
                    bp,
                    b"\n\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                    1 as libc::c_int,
                ) != 1 as libc::c_int
            {
                current_block = 14906436230598744621;
            } else {
                current_block = 7351195479953500246;
            }
        } else {
            current_block = 7351195479953500246;
        }
        match current_block {
            14906436230598744621 => {}
            _ => {
                buf = OPENSSL_malloc((1024 as libc::c_int * 8 as libc::c_int) as size_t)
                    as *mut libc::c_uchar;
                if !buf.is_null() {
                    j = 0 as libc::c_int;
                    i = j;
                    loop {
                        if !(len > 0 as libc::c_int as libc::c_long) {
                            current_block = 5143058163439228106;
                            break;
                        }
                        n = (if len
                            > (1024 as libc::c_int * 5 as libc::c_int) as libc::c_long
                        {
                            (1024 as libc::c_int * 5 as libc::c_int) as libc::c_long
                        } else {
                            len
                        }) as libc::c_int;
                        if EVP_EncodeUpdate(
                            &mut ctx,
                            buf,
                            &mut outl,
                            &*data.offset(j as isize),
                            n as size_t,
                        ) == 0
                        {
                            current_block = 14906436230598744621;
                            break;
                        }
                        if outl != 0
                            && BIO_write(
                                bp,
                                buf as *mut libc::c_char as *const libc::c_void,
                                outl,
                            ) != outl
                        {
                            current_block = 14906436230598744621;
                            break;
                        }
                        i += outl;
                        len -= n as libc::c_long;
                        j += n;
                    }
                    match current_block {
                        14906436230598744621 => {}
                        _ => {
                            EVP_EncodeFinal(&mut ctx, buf, &mut outl);
                            if !(outl > 0 as libc::c_int
                                && BIO_write(
                                    bp,
                                    buf as *mut libc::c_char as *const libc::c_void,
                                    outl,
                                ) != outl)
                            {
                                OPENSSL_free(buf as *mut libc::c_void);
                                buf = 0 as *mut libc::c_uchar;
                                if !(BIO_write(
                                    bp,
                                    b"-----END \0" as *const u8 as *const libc::c_char
                                        as *const libc::c_void,
                                    9 as libc::c_int,
                                ) != 9 as libc::c_int
                                    || BIO_write(bp, name as *const libc::c_void, nlen) != nlen
                                    || BIO_write(
                                        bp,
                                        b"-----\n\0" as *const u8 as *const libc::c_char
                                            as *const libc::c_void,
                                        6 as libc::c_int,
                                    ) != 6 as libc::c_int)
                                {
                                    return i + outl;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if !buf.is_null() {
        OPENSSL_free(buf as *mut libc::c_void);
    }
    ERR_put_error(
        9 as libc::c_int,
        0 as libc::c_int,
        reason,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0" as *const u8
            as *const libc::c_char,
        596 as libc::c_int as libc::c_uint,
    );
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_read(
    mut fp: *mut FILE,
    mut name: *mut *mut libc::c_char,
    mut header: *mut *mut libc::c_char,
    mut data: *mut *mut libc::c_uchar,
    mut len: *mut libc::c_long,
) -> libc::c_int {
    let mut b: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if b.is_null() {
        ERR_put_error(
            9 as libc::c_int,
            0 as libc::c_int,
            7 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0" as *const u8
                as *const libc::c_char,
            604 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = PEM_read_bio(b, name, header, data, len);
    BIO_free(b);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_read_bio(
    mut bp: *mut BIO,
    mut name: *mut *mut libc::c_char,
    mut header: *mut *mut libc::c_char,
    mut data: *mut *mut libc::c_uchar,
    mut len: *mut libc::c_long,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ctx: EVP_ENCODE_CTX = evp_encode_ctx_st {
        data_used: 0,
        data: [0; 48],
        eof_seen: 0,
        error_encountered: 0,
    };
    let mut end: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_int = 0;
    let mut k: libc::c_int = 0;
    let mut bl: libc::c_int = 0 as libc::c_int;
    let mut hl: libc::c_int = 0 as libc::c_int;
    let mut nohead: libc::c_int = 0 as libc::c_int;
    let mut buf: [libc::c_char; 256] = [0; 256];
    let mut nameB: *mut BUF_MEM = 0 as *mut BUF_MEM;
    let mut headerB: *mut BUF_MEM = 0 as *mut BUF_MEM;
    let mut dataB: *mut BUF_MEM = 0 as *mut BUF_MEM;
    let mut tmpB: *mut BUF_MEM = 0 as *mut BUF_MEM;
    nameB = BUF_MEM_new();
    headerB = BUF_MEM_new();
    dataB = BUF_MEM_new();
    if nameB.is_null() || headerB.is_null() || dataB.is_null() {
        BUF_MEM_free(nameB);
        BUF_MEM_free(headerB);
        BUF_MEM_free(dataB);
        return 0 as libc::c_int;
    }
    buf[254 as libc::c_int as usize] = '\0' as i32 as libc::c_char;
    loop {
        i = BIO_gets(bp, buf.as_mut_ptr(), 254 as libc::c_int);
        if i <= 0 as libc::c_int {
            ERR_put_error(
                9 as libc::c_int,
                0 as libc::c_int,
                110 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0" as *const u8
                    as *const libc::c_char,
                636 as libc::c_int as libc::c_uint,
            );
            current_block = 5824641454446601787;
            break;
        } else {
            while i >= 0 as libc::c_int && buf[i as usize] as libc::c_int <= ' ' as i32 {
                i -= 1;
                i;
            }
            i += 1;
            buf[i as usize] = '\n' as i32 as libc::c_char;
            i += 1;
            buf[i as usize] = '\0' as i32 as libc::c_char;
            if !(strncmp(
                buf.as_mut_ptr(),
                b"-----BEGIN \0" as *const u8 as *const libc::c_char,
                11 as libc::c_int as libc::c_ulong,
            ) == 0 as libc::c_int)
            {
                continue;
            }
            i = strlen(&mut *buf.as_mut_ptr().offset(11 as libc::c_int as isize))
                as libc::c_int;
            if strncmp(
                &mut *buf
                    .as_mut_ptr()
                    .offset((11 as libc::c_int + i - 6 as libc::c_int) as isize),
                b"-----\n\0" as *const u8 as *const libc::c_char,
                6 as libc::c_int as libc::c_ulong,
            ) != 0 as libc::c_int
            {
                continue;
            }
            if BUF_MEM_grow(nameB, (i + 9 as libc::c_int) as size_t) == 0 {
                current_block = 5824641454446601787;
                break;
            }
            OPENSSL_memcpy(
                (*nameB).data as *mut libc::c_void,
                &mut *buf.as_mut_ptr().offset(11 as libc::c_int as isize)
                    as *mut libc::c_char as *const libc::c_void,
                (i - 6 as libc::c_int) as size_t,
            );
            *((*nameB).data)
                .offset((i - 6 as libc::c_int) as isize) = '\0' as i32 as libc::c_char;
            current_block = 1109700713171191020;
            break;
        }
    }
    match current_block {
        1109700713171191020 => {
            hl = 0 as libc::c_int;
            if !(BUF_MEM_grow(headerB, 256 as libc::c_int as size_t) == 0) {
                *((*headerB).data)
                    .offset(0 as libc::c_int as isize) = '\0' as i32 as libc::c_char;
                loop {
                    i = BIO_gets(bp, buf.as_mut_ptr(), 254 as libc::c_int);
                    if i <= 0 as libc::c_int {
                        current_block = 11743904203796629665;
                        break;
                    }
                    while i >= 0 as libc::c_int
                        && buf[i as usize] as libc::c_int <= ' ' as i32
                    {
                        i -= 1;
                        i;
                    }
                    i += 1;
                    buf[i as usize] = '\n' as i32 as libc::c_char;
                    i += 1;
                    buf[i as usize] = '\0' as i32 as libc::c_char;
                    if buf[0 as libc::c_int as usize] as libc::c_int == '\n' as i32 {
                        current_block = 11743904203796629665;
                        break;
                    }
                    if BUF_MEM_grow(headerB, (hl + i + 9 as libc::c_int) as size_t) == 0
                    {
                        current_block = 5824641454446601787;
                        break;
                    }
                    if strncmp(
                        buf.as_mut_ptr(),
                        b"-----END \0" as *const u8 as *const libc::c_char,
                        9 as libc::c_int as libc::c_ulong,
                    ) == 0 as libc::c_int
                    {
                        nohead = 1 as libc::c_int;
                        current_block = 11743904203796629665;
                        break;
                    } else {
                        OPENSSL_memcpy(
                            &mut *((*headerB).data).offset(hl as isize)
                                as *mut libc::c_char as *mut libc::c_void,
                            buf.as_mut_ptr() as *const libc::c_void,
                            i as size_t,
                        );
                        *((*headerB).data)
                            .offset((hl + i) as isize) = '\0' as i32 as libc::c_char;
                        hl += i;
                    }
                }
                match current_block {
                    5824641454446601787 => {}
                    _ => {
                        bl = 0 as libc::c_int;
                        if !(BUF_MEM_grow(dataB, 1024 as libc::c_int as size_t) == 0) {
                            *((*dataB).data)
                                .offset(
                                    0 as libc::c_int as isize,
                                ) = '\0' as i32 as libc::c_char;
                            if nohead == 0 {
                                loop {
                                    i = BIO_gets(bp, buf.as_mut_ptr(), 254 as libc::c_int);
                                    if i <= 0 as libc::c_int {
                                        current_block = 15462640364611497761;
                                        break;
                                    }
                                    while i >= 0 as libc::c_int
                                        && buf[i as usize] as libc::c_int <= ' ' as i32
                                    {
                                        i -= 1;
                                        i;
                                    }
                                    i += 1;
                                    buf[i as usize] = '\n' as i32 as libc::c_char;
                                    i += 1;
                                    buf[i as usize] = '\0' as i32 as libc::c_char;
                                    if i != 65 as libc::c_int {
                                        end = 1 as libc::c_int;
                                    }
                                    if strncmp(
                                        buf.as_mut_ptr(),
                                        b"-----END \0" as *const u8 as *const libc::c_char,
                                        9 as libc::c_int as libc::c_ulong,
                                    ) == 0 as libc::c_int
                                    {
                                        current_block = 15462640364611497761;
                                        break;
                                    }
                                    if i > 65 as libc::c_int {
                                        current_block = 15462640364611497761;
                                        break;
                                    }
                                    if BUF_MEM_grow_clean(
                                        dataB,
                                        (i + bl + 9 as libc::c_int) as size_t,
                                    ) == 0
                                    {
                                        current_block = 5824641454446601787;
                                        break;
                                    }
                                    OPENSSL_memcpy(
                                        &mut *((*dataB).data).offset(bl as isize)
                                            as *mut libc::c_char as *mut libc::c_void,
                                        buf.as_mut_ptr() as *const libc::c_void,
                                        i as size_t,
                                    );
                                    *((*dataB).data)
                                        .offset((bl + i) as isize) = '\0' as i32 as libc::c_char;
                                    bl += i;
                                    if !(end != 0) {
                                        continue;
                                    }
                                    buf[0 as libc::c_int
                                        as usize] = '\0' as i32 as libc::c_char;
                                    i = BIO_gets(bp, buf.as_mut_ptr(), 254 as libc::c_int);
                                    if i <= 0 as libc::c_int {
                                        current_block = 15462640364611497761;
                                        break;
                                    }
                                    while i >= 0 as libc::c_int
                                        && buf[i as usize] as libc::c_int <= ' ' as i32
                                    {
                                        i -= 1;
                                        i;
                                    }
                                    i += 1;
                                    buf[i as usize] = '\n' as i32 as libc::c_char;
                                    i += 1;
                                    buf[i as usize] = '\0' as i32 as libc::c_char;
                                    current_block = 15462640364611497761;
                                    break;
                                }
                            } else {
                                tmpB = headerB;
                                headerB = dataB;
                                dataB = tmpB;
                                bl = hl;
                                current_block = 15462640364611497761;
                            }
                            match current_block {
                                5824641454446601787 => {}
                                _ => {
                                    i = strlen((*nameB).data) as libc::c_int;
                                    if strncmp(
                                        buf.as_mut_ptr(),
                                        b"-----END \0" as *const u8 as *const libc::c_char,
                                        9 as libc::c_int as libc::c_ulong,
                                    ) != 0 as libc::c_int
                                        || strncmp(
                                            (*nameB).data,
                                            &mut *buf.as_mut_ptr().offset(9 as libc::c_int as isize),
                                            i as libc::c_ulong,
                                        ) != 0 as libc::c_int
                                        || strncmp(
                                            &mut *buf
                                                .as_mut_ptr()
                                                .offset((9 as libc::c_int + i) as isize),
                                            b"-----\n\0" as *const u8 as *const libc::c_char,
                                            6 as libc::c_int as libc::c_ulong,
                                        ) != 0 as libc::c_int
                                    {
                                        ERR_put_error(
                                            9 as libc::c_int,
                                            0 as libc::c_int,
                                            102 as libc::c_int,
                                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0"
                                                as *const u8 as *const libc::c_char,
                                            751 as libc::c_int as libc::c_uint,
                                        );
                                    } else {
                                        EVP_DecodeInit(&mut ctx);
                                        i = EVP_DecodeUpdate(
                                            &mut ctx,
                                            (*dataB).data as *mut libc::c_uchar,
                                            &mut bl,
                                            (*dataB).data as *mut libc::c_uchar,
                                            bl as size_t,
                                        );
                                        if i < 0 as libc::c_int {
                                            ERR_put_error(
                                                9 as libc::c_int,
                                                0 as libc::c_int,
                                                100 as libc::c_int,
                                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0"
                                                    as *const u8 as *const libc::c_char,
                                                759 as libc::c_int as libc::c_uint,
                                            );
                                        } else {
                                            i = EVP_DecodeFinal(
                                                &mut ctx,
                                                &mut *((*dataB).data).offset(bl as isize)
                                                    as *mut libc::c_char as *mut libc::c_uchar,
                                                &mut k,
                                            );
                                            if i < 0 as libc::c_int {
                                                ERR_put_error(
                                                    9 as libc::c_int,
                                                    0 as libc::c_int,
                                                    100 as libc::c_int,
                                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_lib.c\0"
                                                        as *const u8 as *const libc::c_char,
                                                    764 as libc::c_int as libc::c_uint,
                                                );
                                            } else {
                                                bl += k;
                                                if !(bl == 0 as libc::c_int) {
                                                    *name = (*nameB).data;
                                                    *header = (*headerB).data;
                                                    *data = (*dataB).data as *mut libc::c_uchar;
                                                    *len = bl as libc::c_long;
                                                    OPENSSL_free(nameB as *mut libc::c_void);
                                                    OPENSSL_free(headerB as *mut libc::c_void);
                                                    OPENSSL_free(dataB as *mut libc::c_void);
                                                    return 1 as libc::c_int;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    BUF_MEM_free(nameB);
    BUF_MEM_free(headerB);
    BUF_MEM_free(dataB);
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_def_callback(
    mut buf: *mut libc::c_char,
    mut size: libc::c_int,
    mut rwflag: libc::c_int,
    mut userdata: *mut libc::c_void,
) -> libc::c_int {
    if buf.is_null() || userdata.is_null() || size < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut len: size_t = strlen(userdata as *mut libc::c_char);
    if len >= size as size_t {
        return 0 as libc::c_int;
    }
    OPENSSL_strlcpy(buf, userdata as *const libc::c_char, size as size_t);
    return len as libc::c_int;
}
