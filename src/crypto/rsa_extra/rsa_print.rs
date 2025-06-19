#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(extern_types)]
extern "C" {
    pub type asn1_pctx_st;
    pub type stack_st_void;
    pub type evp_pkey_st;
    pub type rsa_st;
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn BIO_new(method: *const BIO_METHOD) -> *mut BIO;
    fn BIO_free(bio: *mut BIO) -> libc::c_int;
    fn BIO_s_file() -> *const BIO_METHOD;
    fn BIO_set_fp(
        bio: *mut BIO,
        file: *mut FILE,
        close_flag: libc::c_int,
    ) -> libc::c_int;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn EVP_PKEY_new() -> *mut EVP_PKEY;
    fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
    fn EVP_PKEY_set1_RSA(pkey: *mut EVP_PKEY, key: *mut RSA) -> libc::c_int;
    fn EVP_PKEY_print_private(
        out: *mut BIO,
        pkey: *const EVP_PKEY,
        indent: libc::c_int,
        pctx: *mut ASN1_PCTX,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type ASN1_PCTX = asn1_pctx_st;
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
pub type EVP_PKEY = evp_pkey_st;
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
#[no_mangle]
pub unsafe extern "C" fn RSA_print(
    mut bio: *mut BIO,
    mut rsa: *const RSA,
    mut indent: libc::c_int,
) -> libc::c_int {
    let mut pkey: *mut EVP_PKEY = EVP_PKEY_new();
    let mut ret: libc::c_int = (!pkey.is_null()
        && EVP_PKEY_set1_RSA(pkey, rsa as *mut RSA) != 0
        && EVP_PKEY_print_private(bio, pkey, indent, 0 as *mut ASN1_PCTX) != 0)
        as libc::c_int;
    EVP_PKEY_free(pkey);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_print_fp(
    mut fp: *mut FILE,
    mut rsa: *const RSA,
    mut indent: libc::c_int,
) -> libc::c_int {
    let mut bio: *mut BIO = BIO_new(BIO_s_file());
    if bio.is_null() {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            7 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_print.c\0"
                as *const u8 as *const libc::c_char,
            29 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    BIO_set_fp(bio, fp, 0 as libc::c_int);
    let mut ret: libc::c_int = RSA_print(bio, rsa, indent);
    BIO_free(bio);
    return ret;
}
