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
    pub type x509_st;
    pub type stack_st_void;
    fn i2d_X509_AUX(x509: *mut X509, outp: *mut *mut uint8_t) -> libc::c_int;
    fn d2i_X509_AUX(
        x509: *mut *mut X509,
        inp: *mut *const uint8_t,
        length: libc::c_long,
    ) -> *mut X509;
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
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
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
pub type EVP_CIPHER = evp_cipher_st;
pub type X509 = x509_st;
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
unsafe extern "C" fn pem_write_bio_X509_AUX_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_X509_AUX(x as *mut X509, outp);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_read_bio_X509_AUX(
    mut bp: *mut BIO,
    mut x: *mut *mut X509,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut X509 {
    return PEM_ASN1_read_bio(
        Some(
            pem_read_bio_X509_AUX_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"TRUSTED CERTIFICATE\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut X509;
}
unsafe extern "C" fn pem_write_X509_AUX_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_X509_AUX(x as *mut X509, outp);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_write_X509_AUX(
    mut fp: *mut FILE,
    mut x: *mut X509,
) -> libc::c_int {
    return PEM_ASN1_write(
        Some(
            pem_write_X509_AUX_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"TRUSTED CERTIFICATE\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
unsafe extern "C" fn pem_read_bio_X509_AUX_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_X509_AUX(x as *mut *mut X509, inp, len) as *mut libc::c_void;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_read_X509_AUX(
    mut fp: *mut FILE,
    mut x: *mut *mut X509,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut X509 {
    return PEM_ASN1_read(
        Some(
            pem_read_X509_AUX_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"TRUSTED CERTIFICATE\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut X509;
}
unsafe extern "C" fn pem_read_X509_AUX_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_X509_AUX(x as *mut *mut X509, inp, len) as *mut libc::c_void;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PEM_write_bio_X509_AUX(
    mut bp: *mut BIO,
    mut x: *mut X509,
) -> libc::c_int {
    return PEM_ASN1_write_bio(
        Some(
            pem_write_bio_X509_AUX_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"TRUSTED CERTIFICATE\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
