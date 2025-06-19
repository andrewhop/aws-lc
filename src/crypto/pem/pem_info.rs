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
    pub type X509_crl_st;
    pub type evp_cipher_st;
    pub type evp_pkey_st;
    pub type x509_st;
    pub type stack_st_void;
    pub type rsa_st;
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type stack_st;
    pub type stack_st_X509_INFO;
    fn X509_free(x509: *mut X509);
    fn d2i_X509(
        out: *mut *mut X509,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut X509;
    fn d2i_X509_AUX(
        x509: *mut *mut X509,
        inp: *mut *const uint8_t,
        length: libc::c_long,
    ) -> *mut X509;
    fn X509_CRL_free(crl: *mut X509_CRL);
    fn d2i_X509_CRL(
        out: *mut *mut X509_CRL,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut X509_CRL;
    fn EVP_CIPHER_nid(cipher: *const EVP_CIPHER) -> libc::c_int;
    fn EVP_CIPHER_iv_length(cipher: *const EVP_CIPHER) -> libc::c_uint;
    fn BIO_free(bio: *mut BIO) -> libc::c_int;
    fn BIO_new_fp(stream: *mut FILE, close_flag: libc::c_int) -> *mut BIO;
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_free(sk: *mut OPENSSL_STACK);
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn OPENSSL_sk_pop(sk: *mut OPENSSL_STACK) -> *mut libc::c_void;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn ERR_peek_last_error() -> uint32_t;
    fn ERR_clear_error();
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OBJ_nid2sn(nid: libc::c_int) -> *const libc::c_char;
    fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
    fn EVP_PKEY_get0_RSA(pkey: *const EVP_PKEY) -> *mut RSA;
    fn d2i_PrivateKey(
        type_0: libc::c_int,
        out: *mut *mut EVP_PKEY,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut EVP_PKEY;
    fn PEM_get_EVP_CIPHER_INFO(
        header: *mut libc::c_char,
        cipher: *mut EVP_CIPHER_INFO,
    ) -> libc::c_int;
    fn PEM_do_header(
        cipher: *mut EVP_CIPHER_INFO,
        data: *mut libc::c_uchar,
        len: *mut libc::c_long,
        callback: Option::<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> libc::c_int;
    fn PEM_read_bio(
        bp: *mut BIO,
        name: *mut *mut libc::c_char,
        header: *mut *mut libc::c_char,
        data: *mut *mut libc::c_uchar,
        len: *mut libc::c_long,
    ) -> libc::c_int;
    fn PEM_write_bio(
        bp: *mut BIO,
        name: *const libc::c_char,
        hdr: *const libc::c_char,
        data: *const libc::c_uchar,
        len: libc::c_long,
    ) -> libc::c_int;
    fn PEM_write_bio_X509(bp: *mut BIO, x: *mut X509) -> libc::c_int;
    fn PEM_write_bio_RSAPrivateKey(
        bp: *mut BIO,
        x: *mut RSA,
        enc: *const EVP_CIPHER,
        pass: *const libc::c_uchar,
        pass_len: libc::c_int,
        cb: Option::<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> libc::c_int;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn PEM_proc_type(buf: *mut libc::c_char, type_0: libc::c_int);
    fn PEM_dek_info(
        buf: *mut libc::c_char,
        type_0: *const libc::c_char,
        len: size_t,
        str: *mut libc::c_char,
    );
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type X509_CRL = X509_crl_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_info_st {
    pub x509: *mut X509,
    pub crl: *mut X509_CRL,
    pub x_pkey: *mut X509_PKEY,
    pub enc_cipher: EVP_CIPHER_INFO,
    pub enc_len: libc::c_int,
    pub enc_data: *mut libc::c_char,
}
pub type EVP_CIPHER_INFO = evp_cipher_info_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_cipher_info_st {
    pub cipher: *const EVP_CIPHER,
    pub iv: [libc::c_uchar; 16],
}
pub type EVP_CIPHER = evp_cipher_st;
pub type X509_PKEY = private_key_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct private_key_st {
    pub dec_pkey: *mut EVP_PKEY,
}
pub type EVP_PKEY = evp_pkey_st;
pub type X509 = x509_st;
pub type X509_INFO = X509_info_st;
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
pub type RSA = rsa_st;
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
pub type OPENSSL_STACK = stack_st;
pub type pem_password_cb = unsafe extern "C" fn(
    *mut libc::c_char,
    libc::c_int,
    libc::c_int,
    *mut libc::c_void,
) -> libc::c_int;
pub const parse_ok: parse_result_t = 0;
pub type parse_result_t = libc::c_uint;
pub const parse_new_entry: parse_result_t = 2;
pub const parse_error: parse_result_t = 1;
#[inline]
unsafe extern "C" fn sk_X509_INFO_new_null() -> *mut stack_st_X509_INFO {
    return OPENSSL_sk_new_null() as *mut stack_st_X509_INFO;
}
#[inline]
unsafe extern "C" fn sk_X509_INFO_num(mut sk: *const stack_st_X509_INFO) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_INFO_free(mut sk: *mut stack_st_X509_INFO) {
    OPENSSL_sk_free(sk as *mut OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_INFO_push(
    mut sk: *mut stack_st_X509_INFO,
    mut p: *mut X509_INFO,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_X509_INFO_pop(
    mut sk: *mut stack_st_X509_INFO,
) -> *mut X509_INFO {
    return OPENSSL_sk_pop(sk as *mut OPENSSL_STACK) as *mut X509_INFO;
}
#[inline]
unsafe extern "C" fn ERR_GET_LIB(mut packed_error: uint32_t) -> libc::c_int {
    return (packed_error >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as libc::c_int;
}
#[inline]
unsafe extern "C" fn ERR_GET_REASON(mut packed_error: uint32_t) -> libc::c_int {
    return (packed_error & 0xfff as libc::c_int as uint32_t) as libc::c_int;
}
unsafe extern "C" fn X509_PKEY_new() -> *mut X509_PKEY {
    return OPENSSL_zalloc(::core::mem::size_of::<X509_PKEY>() as libc::c_ulong)
        as *mut X509_PKEY;
}
unsafe extern "C" fn X509_PKEY_free(mut x: *mut X509_PKEY) {
    if x.is_null() {
        return;
    }
    EVP_PKEY_free((*x).dec_pkey);
    OPENSSL_free(x as *mut libc::c_void);
}
unsafe extern "C" fn X509_INFO_new() -> *mut X509_INFO {
    return OPENSSL_zalloc(::core::mem::size_of::<X509_INFO>() as libc::c_ulong)
        as *mut X509_INFO;
}
#[no_mangle]
pub unsafe extern "C" fn X509_INFO_free(mut x: *mut X509_INFO) {
    if x.is_null() {
        return;
    }
    X509_free((*x).x509);
    X509_CRL_free((*x).crl);
    X509_PKEY_free((*x).x_pkey);
    OPENSSL_free((*x).enc_data as *mut libc::c_void);
    OPENSSL_free(x as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn PEM_X509_INFO_read(
    mut fp: *mut FILE,
    mut sk: *mut stack_st_X509_INFO,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut stack_st_X509_INFO {
    let mut b: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if b.is_null() {
        ERR_put_error(
            9 as libc::c_int,
            0 as libc::c_int,
            7 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_info.c\0" as *const u8
                as *const libc::c_char,
            108 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut stack_st_X509_INFO;
    }
    let mut ret: *mut stack_st_X509_INFO = PEM_X509_INFO_read_bio(b, sk, cb, u);
    BIO_free(b);
    return ret;
}
unsafe extern "C" fn parse_x509(
    mut info: *mut X509_INFO,
    mut data: *const uint8_t,
    mut len: size_t,
    mut key_type: libc::c_int,
) -> parse_result_t {
    if !((*info).x509).is_null() {
        return parse_new_entry;
    }
    (*info).x509 = d2i_X509(0 as *mut *mut X509, &mut data, len as libc::c_long);
    return (if !((*info).x509).is_null() {
        parse_ok as libc::c_int
    } else {
        parse_error as libc::c_int
    }) as parse_result_t;
}
unsafe extern "C" fn parse_x509_aux(
    mut info: *mut X509_INFO,
    mut data: *const uint8_t,
    mut len: size_t,
    mut key_type: libc::c_int,
) -> parse_result_t {
    if !((*info).x509).is_null() {
        return parse_new_entry;
    }
    (*info).x509 = d2i_X509_AUX(0 as *mut *mut X509, &mut data, len as libc::c_long);
    return (if !((*info).x509).is_null() {
        parse_ok as libc::c_int
    } else {
        parse_error as libc::c_int
    }) as parse_result_t;
}
unsafe extern "C" fn parse_crl(
    mut info: *mut X509_INFO,
    mut data: *const uint8_t,
    mut len: size_t,
    mut key_type: libc::c_int,
) -> parse_result_t {
    if !((*info).crl).is_null() {
        return parse_new_entry;
    }
    (*info).crl = d2i_X509_CRL(0 as *mut *mut X509_CRL, &mut data, len as libc::c_long);
    return (if !((*info).crl).is_null() {
        parse_ok as libc::c_int
    } else {
        parse_error as libc::c_int
    }) as parse_result_t;
}
unsafe extern "C" fn parse_key(
    mut info: *mut X509_INFO,
    mut data: *const uint8_t,
    mut len: size_t,
    mut key_type: libc::c_int,
) -> parse_result_t {
    if !((*info).x_pkey).is_null() {
        return parse_new_entry;
    }
    (*info).x_pkey = X509_PKEY_new();
    if ((*info).x_pkey).is_null() {
        return parse_error;
    }
    (*(*info).x_pkey)
        .dec_pkey = d2i_PrivateKey(
        key_type,
        0 as *mut *mut EVP_PKEY,
        &mut data,
        len as libc::c_long,
    );
    return (if !((*(*info).x_pkey).dec_pkey).is_null() {
        parse_ok as libc::c_int
    } else {
        parse_error as libc::c_int
    }) as parse_result_t;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_X509_INFO_read_bio(
    mut bp: *mut BIO,
    mut sk: *mut stack_st_X509_INFO,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut stack_st_X509_INFO {
    let mut current_block: u64;
    let mut info: *mut X509_INFO = 0 as *mut X509_INFO;
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut header: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut data: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut len: libc::c_long = 0;
    let mut ok: libc::c_int = 0 as libc::c_int;
    let mut ret: *mut stack_st_X509_INFO = 0 as *mut stack_st_X509_INFO;
    if sk.is_null() {
        ret = sk_X509_INFO_new_null();
        if ret.is_null() {
            return 0 as *mut stack_st_X509_INFO;
        }
    } else {
        ret = sk;
    }
    let mut orig_num: size_t = sk_X509_INFO_num(ret);
    info = X509_INFO_new();
    if info.is_null() {
        current_block = 2091151710964252922;
    } else {
        current_block = 12209867499936983673;
    }
    loop {
        match current_block {
            2091151710964252922 => {
                X509_INFO_free(info);
                break;
            }
            _ => {
                if PEM_read_bio(bp, &mut name, &mut header, &mut data, &mut len) == 0 {
                    let mut error: uint32_t = ERR_peek_last_error();
                    if !(ERR_GET_LIB(error) == 9 as libc::c_int
                        && ERR_GET_REASON(error) == 110 as libc::c_int)
                    {
                        current_block = 2091151710964252922;
                        continue;
                    }
                    ERR_clear_error();
                    if !((*info).x509).is_null() || !((*info).crl).is_null()
                        || !((*info).x_pkey).is_null() || !((*info).enc_data).is_null()
                    {
                        if sk_X509_INFO_push(ret, info) == 0 {
                            current_block = 2091151710964252922;
                            continue;
                        }
                        info = 0 as *mut X509_INFO;
                    }
                    ok = 1 as libc::c_int;
                    current_block = 2091151710964252922;
                } else {
                    let mut parse_function: Option::<
                        unsafe extern "C" fn(
                            *mut X509_INFO,
                            *const uint8_t,
                            size_t,
                            libc::c_int,
                        ) -> parse_result_t,
                    > = None;
                    let mut key_type: libc::c_int = 0 as libc::c_int;
                    if strcmp(name, b"CERTIFICATE\0" as *const u8 as *const libc::c_char)
                        == 0 as libc::c_int
                        || strcmp(
                            name,
                            b"X509 CERTIFICATE\0" as *const u8 as *const libc::c_char,
                        ) == 0 as libc::c_int
                    {
                        parse_function = Some(
                            parse_x509
                                as unsafe extern "C" fn(
                                    *mut X509_INFO,
                                    *const uint8_t,
                                    size_t,
                                    libc::c_int,
                                ) -> parse_result_t,
                        );
                    } else if strcmp(
                        name,
                        b"TRUSTED CERTIFICATE\0" as *const u8 as *const libc::c_char,
                    ) == 0 as libc::c_int
                    {
                        parse_function = Some(
                            parse_x509_aux
                                as unsafe extern "C" fn(
                                    *mut X509_INFO,
                                    *const uint8_t,
                                    size_t,
                                    libc::c_int,
                                ) -> parse_result_t,
                        );
                    } else if strcmp(
                        name,
                        b"X509 CRL\0" as *const u8 as *const libc::c_char,
                    ) == 0 as libc::c_int
                    {
                        parse_function = Some(
                            parse_crl
                                as unsafe extern "C" fn(
                                    *mut X509_INFO,
                                    *const uint8_t,
                                    size_t,
                                    libc::c_int,
                                ) -> parse_result_t,
                        );
                    } else if strcmp(
                        name,
                        b"RSA PRIVATE KEY\0" as *const u8 as *const libc::c_char,
                    ) == 0 as libc::c_int
                    {
                        parse_function = Some(
                            parse_key
                                as unsafe extern "C" fn(
                                    *mut X509_INFO,
                                    *const uint8_t,
                                    size_t,
                                    libc::c_int,
                                ) -> parse_result_t,
                        );
                        key_type = 6 as libc::c_int;
                    } else if strcmp(
                        name,
                        b"DSA PRIVATE KEY\0" as *const u8 as *const libc::c_char,
                    ) == 0 as libc::c_int
                    {
                        parse_function = Some(
                            parse_key
                                as unsafe extern "C" fn(
                                    *mut X509_INFO,
                                    *const uint8_t,
                                    size_t,
                                    libc::c_int,
                                ) -> parse_result_t,
                        );
                        key_type = 116 as libc::c_int;
                    } else if strcmp(
                        name,
                        b"EC PRIVATE KEY\0" as *const u8 as *const libc::c_char,
                    ) == 0 as libc::c_int
                    {
                        parse_function = Some(
                            parse_key
                                as unsafe extern "C" fn(
                                    *mut X509_INFO,
                                    *const uint8_t,
                                    size_t,
                                    libc::c_int,
                                ) -> parse_result_t,
                        );
                        key_type = 408 as libc::c_int;
                    }
                    if key_type != 0 as libc::c_int
                        && strlen(header) > 10 as libc::c_int as libc::c_ulong
                    {
                        if !((*info).x_pkey).is_null() {
                            if sk_X509_INFO_push(ret, info) == 0 {
                                current_block = 2091151710964252922;
                                continue;
                            }
                            info = X509_INFO_new();
                            if info.is_null() {
                                current_block = 2091151710964252922;
                                continue;
                            }
                        }
                        (*info).x_pkey = X509_PKEY_new();
                        if ((*info).x_pkey).is_null()
                            || PEM_get_EVP_CIPHER_INFO(header, &mut (*info).enc_cipher)
                                == 0
                        {
                            current_block = 2091151710964252922;
                            continue;
                        }
                        (*info).enc_data = data as *mut libc::c_char;
                        (*info).enc_len = len as libc::c_int;
                        data = 0 as *mut libc::c_uchar;
                    } else if parse_function.is_some() {
                        let mut cipher: EVP_CIPHER_INFO = evp_cipher_info_st {
                            cipher: 0 as *const EVP_CIPHER,
                            iv: [0; 16],
                        };
                        if PEM_get_EVP_CIPHER_INFO(header, &mut cipher) == 0
                            || PEM_do_header(&mut cipher, data, &mut len, cb, u) == 0
                        {
                            current_block = 2091151710964252922;
                            continue;
                        }
                        let mut result: parse_result_t = parse_function
                            .expect(
                                "non-null function pointer",
                            )(info, data, len as size_t, key_type);
                        if result as libc::c_uint
                            == parse_new_entry as libc::c_int as libc::c_uint
                        {
                            if sk_X509_INFO_push(ret, info) == 0 {
                                current_block = 2091151710964252922;
                                continue;
                            }
                            info = X509_INFO_new();
                            if info.is_null() {
                                current_block = 2091151710964252922;
                                continue;
                            }
                            result = parse_function
                                .expect(
                                    "non-null function pointer",
                                )(info, data, len as size_t, key_type);
                        }
                        if result as libc::c_uint
                            != parse_ok as libc::c_int as libc::c_uint
                        {
                            ERR_put_error(
                                9 as libc::c_int,
                                0 as libc::c_int,
                                12 as libc::c_int,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_info.c\0"
                                    as *const u8 as *const libc::c_char,
                                256 as libc::c_int as libc::c_uint,
                            );
                            current_block = 2091151710964252922;
                            continue;
                        }
                    }
                    OPENSSL_free(name as *mut libc::c_void);
                    OPENSSL_free(header as *mut libc::c_void);
                    OPENSSL_free(data as *mut libc::c_void);
                    name = 0 as *mut libc::c_char;
                    header = 0 as *mut libc::c_char;
                    data = 0 as *mut libc::c_uchar;
                    current_block = 12209867499936983673;
                }
            }
        }
    }
    if ok == 0 {
        while sk_X509_INFO_num(ret) > orig_num {
            X509_INFO_free(sk_X509_INFO_pop(ret));
        }
        if ret != sk {
            sk_X509_INFO_free(ret);
        }
        ret = 0 as *mut stack_st_X509_INFO;
    }
    OPENSSL_free(name as *mut libc::c_void);
    OPENSSL_free(header as *mut libc::c_void);
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_X509_INFO_write_bio(
    mut bp: *mut BIO,
    mut xi: *mut X509_INFO,
    mut enc: *mut EVP_CIPHER,
    mut kstr: *mut libc::c_uchar,
    mut klen: libc::c_int,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> libc::c_int {
    let mut current_block: u64;
    let mut i: libc::c_int = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut data: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut objstr: *const libc::c_char = 0 as *const libc::c_char;
    let mut buf: [libc::c_char; 1024] = [0; 1024];
    let mut iv: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut iv_len: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    if !enc.is_null() {
        iv_len = EVP_CIPHER_iv_length(enc);
        objstr = OBJ_nid2sn(EVP_CIPHER_nid(enc));
        if objstr.is_null() {
            ERR_put_error(
                9 as libc::c_int,
                0 as libc::c_int,
                113 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_info.c\0" as *const u8
                    as *const libc::c_char,
                312 as libc::c_int as libc::c_uint,
            );
            current_block = 9149780774785635679;
        } else {
            current_block = 4906268039856690917;
        }
    } else {
        current_block = 4906268039856690917;
    }
    match current_block {
        4906268039856690917 => {
            if !xi.is_null() {
                if !((*xi).x_pkey).is_null() {
                    if !((*xi).enc_data).is_null() && (*xi).enc_len > 0 as libc::c_int {
                        if enc.is_null() {
                            ERR_put_error(
                                9 as libc::c_int,
                                0 as libc::c_int,
                                105 as libc::c_int,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_info.c\0"
                                    as *const u8 as *const libc::c_char,
                                327 as libc::c_int as libc::c_uint,
                            );
                            current_block = 9149780774785635679;
                        } else {
                            iv = ((*xi).enc_cipher.iv).as_mut_ptr();
                            data = (*xi).enc_data as *mut libc::c_uchar;
                            i = (*xi).enc_len;
                            objstr = OBJ_nid2sn(EVP_CIPHER_nid((*xi).enc_cipher.cipher));
                            if objstr.is_null() {
                                ERR_put_error(
                                    9 as libc::c_int,
                                    0 as libc::c_int,
                                    113 as libc::c_int,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_info.c\0"
                                        as *const u8 as *const libc::c_char,
                                    341 as libc::c_int as libc::c_uint,
                                );
                                current_block = 9149780774785635679;
                            } else {
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
                                        b"strlen(objstr) + 23 + 2 * iv_len + 13 <= sizeof buf\0"
                                            as *const u8 as *const libc::c_char,
                                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_info.c\0"
                                            as *const u8 as *const libc::c_char,
                                        350 as libc::c_int as libc::c_uint,
                                        (*::core::mem::transmute::<
                                            &[u8; 111],
                                            &[libc::c_char; 111],
                                        >(
                                            b"int PEM_X509_INFO_write_bio(BIO *, X509_INFO *, EVP_CIPHER *, unsigned char *, int, pem_password_cb *, void *)\0",
                                        ))
                                            .as_ptr(),
                                    );
                                }
                                'c_27204: {
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
                                            b"strlen(objstr) + 23 + 2 * iv_len + 13 <= sizeof buf\0"
                                                as *const u8 as *const libc::c_char,
                                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_info.c\0"
                                                as *const u8 as *const libc::c_char,
                                            350 as libc::c_int as libc::c_uint,
                                            (*::core::mem::transmute::<
                                                &[u8; 111],
                                                &[libc::c_char; 111],
                                            >(
                                                b"int PEM_X509_INFO_write_bio(BIO *, X509_INFO *, EVP_CIPHER *, unsigned char *, int, pem_password_cb *, void *)\0",
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
                                    iv as *mut libc::c_char,
                                );
                                i = PEM_write_bio(
                                    bp,
                                    b"RSA PRIVATE KEY\0" as *const u8 as *const libc::c_char,
                                    buf.as_mut_ptr(),
                                    data,
                                    i as libc::c_long,
                                );
                                if i <= 0 as libc::c_int {
                                    current_block = 9149780774785635679;
                                } else {
                                    current_block = 2719512138335094285;
                                }
                            }
                        }
                    } else if !((*(*xi).x_pkey).dec_pkey).is_null() {
                        if PEM_write_bio_RSAPrivateKey(
                            bp,
                            EVP_PKEY_get0_RSA((*(*xi).x_pkey).dec_pkey),
                            enc,
                            kstr,
                            klen,
                            cb,
                            u,
                        ) <= 0 as libc::c_int
                        {
                            current_block = 9149780774785635679;
                        } else {
                            current_block = 2719512138335094285;
                        }
                    } else {
                        current_block = 2719512138335094285;
                    }
                } else {
                    current_block = 2719512138335094285;
                }
                match current_block {
                    9149780774785635679 => {}
                    _ => {
                        if !(!((*xi).x509).is_null()
                            && PEM_write_bio_X509(bp, (*xi).x509) <= 0 as libc::c_int)
                        {
                            ret = 1 as libc::c_int;
                        }
                    }
                }
            }
        }
        _ => {}
    }
    OPENSSL_cleanse(
        buf.as_mut_ptr() as *mut libc::c_void,
        1024 as libc::c_int as size_t,
    );
    return ret;
}
