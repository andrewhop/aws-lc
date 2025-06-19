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
    pub type ASN1_ITEM_st;
    pub type ASN1_VALUE_st;
    pub type stack_st_void;
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn ASN1_item_i2d(
        val: *mut ASN1_VALUE,
        outp: *mut *mut libc::c_uchar,
        it: *const ASN1_ITEM,
    ) -> libc::c_int;
    fn BIO_free(bio: *mut BIO) -> libc::c_int;
    fn BIO_write_all(
        bio: *mut BIO,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn BIO_new_fp(stream: *mut FILE, close_flag: libc::c_int) -> *mut BIO;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
}
pub type size_t = libc::c_ulong;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type ASN1_ITEM = ASN1_ITEM_st;
pub type ASN1_VALUE = ASN1_VALUE_st;
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
pub type i2d_of_void = unsafe extern "C" fn(
    *const libc::c_void,
    *mut *mut libc::c_uchar,
) -> libc::c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_i2d_bio(
    mut i2d: Option::<i2d_of_void>,
    mut out: *mut BIO,
    mut in_0: *mut libc::c_void,
) -> libc::c_int {
    if i2d.is_none() || out.is_null() || in_0.is_null() {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_i2d_fp.c\0" as *const u8
                as *const libc::c_char,
            68 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut size: libc::c_int = i2d
        .expect("non-null function pointer")(in_0, 0 as *mut *mut libc::c_uchar);
    if size <= 0 as libc::c_int {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            4 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_i2d_fp.c\0" as *const u8
                as *const libc::c_char,
            74 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut buffer: *mut libc::c_uchar = OPENSSL_malloc(size as size_t)
        as *mut libc::c_uchar;
    if buffer.is_null() {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            1 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_i2d_fp.c\0" as *const u8
                as *const libc::c_char,
            80 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut outp: *mut libc::c_uchar = buffer;
    let mut ret: libc::c_int = i2d.expect("non-null function pointer")(in_0, &mut outp);
    if ret < 0 as libc::c_int || ret > size {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            107 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_i2d_fp.c\0" as *const u8
                as *const libc::c_char,
            87 as libc::c_int as libc::c_uint,
        );
        OPENSSL_free(buffer as *mut libc::c_void);
        return 0 as libc::c_int;
    }
    ret = BIO_write_all(out, buffer as *const libc::c_void, size as size_t);
    OPENSSL_free(buffer as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_item_i2d_fp(
    mut it: *const ASN1_ITEM,
    mut out: *mut FILE,
    mut x: *mut libc::c_void,
) -> libc::c_int {
    let mut b: *mut BIO = BIO_new_fp(out, 0 as libc::c_int);
    if b.is_null() {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            7 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_i2d_fp.c\0" as *const u8
                as *const libc::c_char,
            100 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = ASN1_item_i2d_bio(it, b, x);
    BIO_free(b);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_item_i2d_bio(
    mut it: *const ASN1_ITEM,
    mut out: *mut BIO,
    mut x: *mut libc::c_void,
) -> libc::c_int {
    let mut b: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut n: libc::c_int = ASN1_item_i2d(x as *mut ASN1_VALUE, &mut b, it);
    if b.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = BIO_write_all(out, b as *const libc::c_void, n as size_t);
    OPENSSL_free(b as *mut libc::c_void);
    return ret;
}
