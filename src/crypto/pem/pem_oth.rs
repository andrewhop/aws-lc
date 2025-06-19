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
    pub type stack_st_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn PEM_bytes_read_bio(
        pdata: *mut *mut libc::c_uchar,
        plen: *mut libc::c_long,
        pnm: *mut *mut libc::c_char,
        name: *const libc::c_char,
        bp: *mut BIO,
        cb: Option::<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
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
pub type d2i_of_void = unsafe extern "C" fn(
    *mut *mut libc::c_void,
    *mut *const libc::c_uchar,
    libc::c_long,
) -> *mut libc::c_void;
pub type pem_password_cb = unsafe extern "C" fn(
    *mut libc::c_char,
    libc::c_int,
    libc::c_int,
    *mut libc::c_void,
) -> libc::c_int;
#[no_mangle]
pub unsafe extern "C" fn PEM_ASN1_read_bio(
    mut d2i: Option::<d2i_of_void>,
    mut name: *const libc::c_char,
    mut bp: *mut BIO,
    mut x: *mut *mut libc::c_void,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut libc::c_void {
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut data: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut len: libc::c_long = 0;
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    if PEM_bytes_read_bio(
        &mut data,
        &mut len,
        0 as *mut *mut libc::c_char,
        name,
        bp,
        cb,
        u,
    ) == 0
    {
        return 0 as *mut libc::c_void;
    }
    p = data;
    ret = d2i.expect("non-null function pointer")(x, &mut p, len) as *mut libc::c_char;
    if ret.is_null() {
        ERR_put_error(
            9 as libc::c_int,
            0 as libc::c_int,
            12 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_oth.c\0" as *const u8
                as *const libc::c_char,
            83 as libc::c_int as libc::c_uint,
        );
    }
    OPENSSL_free(data as *mut libc::c_void);
    return ret as *mut libc::c_void;
}
