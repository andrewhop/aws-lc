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
    pub type evp_pkey_st;
    pub type X509_sig_st;
    pub type stack_st_void;
    pub type pkcs8_priv_key_info_st;
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn PKCS8_PRIV_KEY_INFO_free(key: *mut PKCS8_PRIV_KEY_INFO);
    fn d2i_PKCS8_PRIV_KEY_INFO(
        out: *mut *mut PKCS8_PRIV_KEY_INFO,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut PKCS8_PRIV_KEY_INFO;
    fn i2d_PKCS8_PRIV_KEY_INFO(
        key: *const PKCS8_PRIV_KEY_INFO,
        outp: *mut *mut uint8_t,
    ) -> libc::c_int;
    fn EVP_PKCS82PKEY(p8: *const PKCS8_PRIV_KEY_INFO) -> *mut EVP_PKEY;
    fn EVP_PKEY2PKCS8(pkey: *const EVP_PKEY) -> *mut PKCS8_PRIV_KEY_INFO;
    fn X509_SIG_free(key: *mut X509_SIG);
    fn d2i_X509_SIG(
        out: *mut *mut X509_SIG,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut X509_SIG;
    fn i2d_X509_SIG(sig: *const X509_SIG, outp: *mut *mut uint8_t) -> libc::c_int;
    fn d2i_PKCS8_bio(bp: *mut BIO, p8: *mut *mut X509_SIG) -> *mut X509_SIG;
    fn i2d_PKCS8_bio(bp: *mut BIO, p8: *mut X509_SIG) -> libc::c_int;
    fn i2d_PKCS8_PRIV_KEY_INFO_bio(
        bp: *mut BIO,
        p8inf: *mut PKCS8_PRIV_KEY_INFO,
    ) -> libc::c_int;
    fn BIO_free(bio: *mut BIO) -> libc::c_int;
    fn BIO_new_fp(stream: *mut FILE, close_flag: libc::c_int) -> *mut BIO;
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
    fn PEM_ASN1_read_bio(
        d2i: Option::<d2i_of_void>,
        name: *const libc::c_char,
        bp: *mut BIO,
        x: *mut *mut libc::c_void,
        cb: Option::<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> *mut libc::c_void;
    fn PEM_ASN1_write_bio(
        i2d: Option::<i2d_of_void>,
        name: *const libc::c_char,
        bp: *mut BIO,
        x: *mut libc::c_void,
        enc: *const EVP_CIPHER,
        pass: *const libc::c_uchar,
        pass_len: libc::c_int,
        cb: Option::<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> libc::c_int;
    fn PEM_ASN1_read(
        d2i: Option::<d2i_of_void>,
        name: *const libc::c_char,
        fp: *mut FILE,
        x: *mut *mut libc::c_void,
        cb: Option::<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> *mut libc::c_void;
    fn PEM_ASN1_write(
        i2d: Option::<i2d_of_void>,
        name: *const libc::c_char,
        fp: *mut FILE,
        x: *mut libc::c_void,
        enc: *const EVP_CIPHER,
        pass: *const libc::c_uchar,
        pass_len: libc::c_int,
        callback: Option::<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> libc::c_int;
    fn PEM_def_callback(
        buf: *mut libc::c_char,
        size: libc::c_int,
        rwflag: libc::c_int,
        userdata: *mut libc::c_void,
    ) -> libc::c_int;
    fn PKCS8_encrypt(
        pbe_nid: libc::c_int,
        cipher: *const EVP_CIPHER,
        pass: *const libc::c_char,
        pass_len: libc::c_int,
        salt: *const uint8_t,
        salt_len: size_t,
        iterations: libc::c_int,
        p8inf: *mut PKCS8_PRIV_KEY_INFO,
    ) -> *mut X509_SIG;
    fn PKCS8_decrypt(
        pkcs8: *mut X509_SIG,
        pass: *const libc::c_char,
        pass_len: libc::c_int,
    ) -> *mut PKCS8_PRIV_KEY_INFO;
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
pub type EVP_CIPHER = evp_cipher_st;
pub type EVP_PKEY = evp_pkey_st;
pub type X509_SIG = X509_sig_st;
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
pub type PKCS8_PRIV_KEY_INFO = pkcs8_priv_key_info_st;
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_write_bio_PKCS8PrivateKey_nid(
    mut bp: *mut BIO,
    mut x: *const EVP_PKEY,
    mut nid: libc::c_int,
    mut pass: *const libc::c_char,
    mut pass_len: libc::c_int,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> libc::c_int {
    return do_pk8pkey(
        bp,
        x,
        0 as libc::c_int,
        nid,
        0 as *const EVP_CIPHER,
        pass,
        pass_len,
        cb,
        u,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_write_bio_PKCS8PrivateKey(
    mut bp: *mut BIO,
    mut x: *const EVP_PKEY,
    mut enc: *const EVP_CIPHER,
    mut pass: *const libc::c_char,
    mut pass_len: libc::c_int,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> libc::c_int {
    return do_pk8pkey(
        bp,
        x,
        0 as libc::c_int,
        -(1 as libc::c_int),
        enc,
        pass,
        pass_len,
        cb,
        u,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_PKCS8PrivateKey_bio(
    mut bp: *mut BIO,
    mut x: *const EVP_PKEY,
    mut enc: *const EVP_CIPHER,
    mut pass: *const libc::c_char,
    mut pass_len: libc::c_int,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> libc::c_int {
    return do_pk8pkey(
        bp,
        x,
        1 as libc::c_int,
        -(1 as libc::c_int),
        enc,
        pass,
        pass_len,
        cb,
        u,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_PKCS8PrivateKey_nid_bio(
    mut bp: *mut BIO,
    mut x: *const EVP_PKEY,
    mut nid: libc::c_int,
    mut pass: *const libc::c_char,
    mut pass_len: libc::c_int,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> libc::c_int {
    return do_pk8pkey(
        bp,
        x,
        1 as libc::c_int,
        nid,
        0 as *const EVP_CIPHER,
        pass,
        pass_len,
        cb,
        u,
    );
}
unsafe extern "C" fn do_pk8pkey(
    mut bp: *mut BIO,
    mut x: *const EVP_PKEY,
    mut isder: libc::c_int,
    mut nid: libc::c_int,
    mut enc: *const EVP_CIPHER,
    mut pass: *const libc::c_char,
    mut pass_len: libc::c_int,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> libc::c_int {
    let mut p8: *mut X509_SIG = 0 as *mut X509_SIG;
    let mut p8inf: *mut PKCS8_PRIV_KEY_INFO = 0 as *mut PKCS8_PRIV_KEY_INFO;
    let mut buf: [libc::c_char; 1024] = [0; 1024];
    let mut ret: libc::c_int = 0;
    p8inf = EVP_PKEY2PKCS8(x);
    if p8inf.is_null() {
        ERR_put_error(
            9 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_pk8.c\0" as *const u8
                as *const libc::c_char,
            111 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if !enc.is_null() || nid != -(1 as libc::c_int) {
        if pass.is_null() {
            if cb.is_none() {
                cb = Some(
                    PEM_def_callback
                        as unsafe extern "C" fn(
                            *mut libc::c_char,
                            libc::c_int,
                            libc::c_int,
                            *mut libc::c_void,
                        ) -> libc::c_int,
                );
            }
            pass_len = cb
                .expect(
                    "non-null function pointer",
                )(buf.as_mut_ptr(), 1024 as libc::c_int, 1 as libc::c_int, u);
            if pass_len <= 0 as libc::c_int {
                ERR_put_error(
                    9 as libc::c_int,
                    0 as libc::c_int,
                    111 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_pk8.c\0"
                        as *const u8 as *const libc::c_char,
                    121 as libc::c_int as libc::c_uint,
                );
                PKCS8_PRIV_KEY_INFO_free(p8inf);
                return 0 as libc::c_int;
            }
            pass = buf.as_mut_ptr();
        }
        p8 = PKCS8_encrypt(
            nid,
            enc,
            pass,
            pass_len,
            0 as *const uint8_t,
            0 as libc::c_int as size_t,
            0 as libc::c_int,
            p8inf,
        );
        if pass == buf.as_mut_ptr() as *const libc::c_char {
            OPENSSL_cleanse(buf.as_mut_ptr() as *mut libc::c_void, pass_len as size_t);
        }
        PKCS8_PRIV_KEY_INFO_free(p8inf);
        if isder != 0 {
            ret = i2d_PKCS8_bio(bp, p8);
        } else {
            ret = PEM_write_bio_PKCS8(bp, p8);
        }
        X509_SIG_free(p8);
        return ret;
    } else {
        if isder != 0 {
            ret = i2d_PKCS8_PRIV_KEY_INFO_bio(bp, p8inf);
        } else {
            ret = PEM_write_bio_PKCS8_PRIV_KEY_INFO(bp, p8inf);
        }
        PKCS8_PRIV_KEY_INFO_free(p8inf);
        return ret;
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_PKCS8PrivateKey_bio(
    mut bp: *mut BIO,
    mut x: *mut *mut EVP_PKEY,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut EVP_PKEY {
    let mut p8inf: *mut PKCS8_PRIV_KEY_INFO = 0 as *mut PKCS8_PRIV_KEY_INFO;
    let mut p8: *mut X509_SIG = 0 as *mut X509_SIG;
    let mut pass_len: libc::c_int = 0;
    let mut ret: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
    let mut psbuf: [libc::c_char; 1024] = [0; 1024];
    p8 = d2i_PKCS8_bio(bp, 0 as *mut *mut X509_SIG);
    if p8.is_null() {
        return 0 as *mut EVP_PKEY;
    }
    if cb.is_none() {
        cb = Some(
            PEM_def_callback
                as unsafe extern "C" fn(
                    *mut libc::c_char,
                    libc::c_int,
                    libc::c_int,
                    *mut libc::c_void,
                ) -> libc::c_int,
        );
    }
    pass_len = cb
        .expect(
            "non-null function pointer",
        )(psbuf.as_mut_ptr(), 1024 as libc::c_int, 0 as libc::c_int, u);
    if pass_len <= 0 as libc::c_int {
        ERR_put_error(
            9 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_pk8.c\0" as *const u8
                as *const libc::c_char,
            168 as libc::c_int as libc::c_uint,
        );
        X509_SIG_free(p8);
        return 0 as *mut EVP_PKEY;
    }
    p8inf = PKCS8_decrypt(p8, psbuf.as_mut_ptr(), pass_len);
    X509_SIG_free(p8);
    OPENSSL_cleanse(psbuf.as_mut_ptr() as *mut libc::c_void, pass_len as size_t);
    if p8inf.is_null() {
        return 0 as *mut EVP_PKEY;
    }
    ret = EVP_PKCS82PKEY(p8inf);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    if ret.is_null() {
        return 0 as *mut EVP_PKEY;
    }
    if !x.is_null() {
        if !(*x).is_null() {
            EVP_PKEY_free(*x);
        }
        *x = ret;
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_PKCS8PrivateKey_fp(
    mut fp: *mut FILE,
    mut x: *const EVP_PKEY,
    mut enc: *const EVP_CIPHER,
    mut pass: *const libc::c_char,
    mut pass_len: libc::c_int,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> libc::c_int {
    return do_pk8pkey_fp(
        fp,
        x,
        1 as libc::c_int,
        -(1 as libc::c_int),
        enc,
        pass,
        pass_len,
        cb,
        u,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_PKCS8PrivateKey_nid_fp(
    mut fp: *mut FILE,
    mut x: *const EVP_PKEY,
    mut nid: libc::c_int,
    mut pass: *const libc::c_char,
    mut pass_len: libc::c_int,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> libc::c_int {
    return do_pk8pkey_fp(
        fp,
        x,
        1 as libc::c_int,
        nid,
        0 as *const EVP_CIPHER,
        pass,
        pass_len,
        cb,
        u,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_write_PKCS8PrivateKey_nid(
    mut fp: *mut FILE,
    mut x: *const EVP_PKEY,
    mut nid: libc::c_int,
    mut pass: *const libc::c_char,
    mut pass_len: libc::c_int,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> libc::c_int {
    return do_pk8pkey_fp(
        fp,
        x,
        0 as libc::c_int,
        nid,
        0 as *const EVP_CIPHER,
        pass,
        pass_len,
        cb,
        u,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_write_PKCS8PrivateKey(
    mut fp: *mut FILE,
    mut x: *const EVP_PKEY,
    mut enc: *const EVP_CIPHER,
    mut pass: *const libc::c_char,
    mut pass_len: libc::c_int,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> libc::c_int {
    return do_pk8pkey_fp(
        fp,
        x,
        0 as libc::c_int,
        -(1 as libc::c_int),
        enc,
        pass,
        pass_len,
        cb,
        u,
    );
}
unsafe extern "C" fn do_pk8pkey_fp(
    mut fp: *mut FILE,
    mut x: *const EVP_PKEY,
    mut isder: libc::c_int,
    mut nid: libc::c_int,
    mut enc: *const EVP_CIPHER,
    mut pass: *const libc::c_char,
    mut pass_len: libc::c_int,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> libc::c_int {
    let mut bp: *mut BIO = 0 as *mut BIO;
    let mut ret: libc::c_int = 0;
    bp = BIO_new_fp(fp, 0 as libc::c_int);
    if bp.is_null() {
        ERR_put_error(
            9 as libc::c_int,
            0 as libc::c_int,
            7 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_pk8.c\0" as *const u8
                as *const libc::c_char,
            223 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    ret = do_pk8pkey(bp, x, isder, nid, enc, pass, pass_len, cb, u);
    BIO_free(bp);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_PKCS8PrivateKey_fp(
    mut fp: *mut FILE,
    mut x: *mut *mut EVP_PKEY,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut EVP_PKEY {
    let mut bp: *mut BIO = 0 as *mut BIO;
    let mut ret: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
    bp = BIO_new_fp(fp, 0 as libc::c_int);
    if bp.is_null() {
        ERR_put_error(
            9 as libc::c_int,
            0 as libc::c_int,
            7 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_pk8.c\0" as *const u8
                as *const libc::c_char,
            236 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EVP_PKEY;
    }
    ret = d2i_PKCS8PrivateKey_bio(bp, x, cb, u);
    BIO_free(bp);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_write_PKCS8(
    mut fp: *mut FILE,
    mut x: *mut X509_SIG,
) -> libc::c_int {
    return PEM_ASN1_write(
        Some(
            pem_write_PKCS8_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"ENCRYPTED PRIVATE KEY\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_write_bio_PKCS8(
    mut bp: *mut BIO,
    mut x: *mut X509_SIG,
) -> libc::c_int {
    return PEM_ASN1_write_bio(
        Some(
            pem_write_bio_PKCS8_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"ENCRYPTED PRIVATE KEY\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
unsafe extern "C" fn pem_write_PKCS8_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_X509_SIG(x as *mut X509_SIG, outp);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_read_bio_PKCS8(
    mut bp: *mut BIO,
    mut x: *mut *mut X509_SIG,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut X509_SIG {
    return PEM_ASN1_read_bio(
        Some(
            pem_read_bio_PKCS8_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"ENCRYPTED PRIVATE KEY\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut X509_SIG;
}
unsafe extern "C" fn pem_read_bio_PKCS8_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_X509_SIG(x as *mut *mut X509_SIG, inp, len) as *mut libc::c_void;
}
unsafe extern "C" fn pem_read_PKCS8_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_X509_SIG(x as *mut *mut X509_SIG, inp, len) as *mut libc::c_void;
}
unsafe extern "C" fn pem_write_bio_PKCS8_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_X509_SIG(x as *mut X509_SIG, outp);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_read_PKCS8(
    mut fp: *mut FILE,
    mut x: *mut *mut X509_SIG,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut X509_SIG {
    return PEM_ASN1_read(
        Some(
            pem_read_PKCS8_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"ENCRYPTED PRIVATE KEY\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut X509_SIG;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_write_bio_PKCS8_PRIV_KEY_INFO(
    mut bp: *mut BIO,
    mut x: *mut PKCS8_PRIV_KEY_INFO,
) -> libc::c_int {
    return PEM_ASN1_write_bio(
        Some(
            pem_write_bio_PKCS8_PRIV_KEY_INFO_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"PRIVATE KEY\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_read_PKCS8_PRIV_KEY_INFO(
    mut fp: *mut FILE,
    mut x: *mut *mut PKCS8_PRIV_KEY_INFO,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut PKCS8_PRIV_KEY_INFO {
    return PEM_ASN1_read(
        Some(
            pem_read_PKCS8_PRIV_KEY_INFO_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"PRIVATE KEY\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut PKCS8_PRIV_KEY_INFO;
}
unsafe extern "C" fn pem_read_PKCS8_PRIV_KEY_INFO_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_PKCS8_PRIV_KEY_INFO(x as *mut *mut PKCS8_PRIV_KEY_INFO, inp, len)
        as *mut libc::c_void;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_write_PKCS8_PRIV_KEY_INFO(
    mut fp: *mut FILE,
    mut x: *mut PKCS8_PRIV_KEY_INFO,
) -> libc::c_int {
    return PEM_ASN1_write(
        Some(
            pem_write_PKCS8_PRIV_KEY_INFO_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"PRIVATE KEY\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
unsafe extern "C" fn pem_write_PKCS8_PRIV_KEY_INFO_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_PKCS8_PRIV_KEY_INFO(x as *mut PKCS8_PRIV_KEY_INFO, outp);
}
unsafe extern "C" fn pem_write_bio_PKCS8_PRIV_KEY_INFO_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_PKCS8_PRIV_KEY_INFO(x as *mut PKCS8_PRIV_KEY_INFO, outp);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_read_bio_PKCS8_PRIV_KEY_INFO(
    mut bp: *mut BIO,
    mut x: *mut *mut PKCS8_PRIV_KEY_INFO,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut PKCS8_PRIV_KEY_INFO {
    return PEM_ASN1_read_bio(
        Some(
            pem_read_bio_PKCS8_PRIV_KEY_INFO_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"PRIVATE KEY\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut PKCS8_PRIV_KEY_INFO;
}
unsafe extern "C" fn pem_read_bio_PKCS8_PRIV_KEY_INFO_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_PKCS8_PRIV_KEY_INFO(x as *mut *mut PKCS8_PRIV_KEY_INFO, inp, len)
        as *mut libc::c_void;
}
