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
    pub type lhash_st_CONF_VALUE;
    pub type lhash_st;
    pub type stack_st;
    pub type stack_st_CONF_VALUE;
    fn BIO_free(bio: *mut BIO) -> libc::c_int;
    fn BIO_gets(bio: *mut BIO, buf: *mut libc::c_char, size: libc::c_int) -> libc::c_int;
    fn BIO_new_file(
        filename: *const libc::c_char,
        mode: *const libc::c_char,
    ) -> *mut BIO;
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_free(sk: *mut OPENSSL_STACK);
    fn OPENSSL_sk_delete_ptr(
        sk: *mut OPENSSL_STACK,
        p: *const libc::c_void,
    ) -> *mut libc::c_void;
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn BUF_MEM_new() -> *mut BUF_MEM;
    fn BUF_MEM_free(buf: *mut BUF_MEM);
    fn BUF_MEM_grow(buf: *mut BUF_MEM, len: size_t) -> size_t;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_strhash(s: *const libc::c_char) -> uint32_t;
    fn OPENSSL_strdup(s: *const libc::c_char) -> *mut libc::c_char;
    fn OPENSSL_isspace(c: libc::c_int) -> libc::c_int;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn ERR_add_error_data(count: libc::c_uint, _: ...);
    fn OPENSSL_lh_new(hash: lhash_hash_func, comp: lhash_cmp_func) -> *mut _LHASH;
    fn OPENSSL_lh_free(lh: *mut _LHASH);
    fn OPENSSL_lh_retrieve(
        lh: *const _LHASH,
        data: *const libc::c_void,
        call_hash_func: lhash_hash_func_helper,
        call_cmp_func: lhash_cmp_func_helper,
    ) -> *mut libc::c_void;
    fn OPENSSL_lh_insert(
        lh: *mut _LHASH,
        old_data: *mut *mut libc::c_void,
        data: *mut libc::c_void,
        call_hash_func: lhash_hash_func_helper,
        call_cmp_func: lhash_cmp_func_helper,
    ) -> libc::c_int;
    fn OPENSSL_lh_doall_arg(
        lh: *mut _LHASH,
        func: Option::<unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void) -> ()>,
        arg: *mut libc::c_void,
    );
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct buf_mem_st {
    pub length: size_t,
    pub data: *mut libc::c_char,
    pub max: size_t,
}
pub type BUF_MEM = buf_mem_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct conf_st {
    pub data: *mut lhash_st_CONF_VALUE,
}
pub type CONF = conf_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct conf_value_st {
    pub section: *mut libc::c_char,
    pub name: *mut libc::c_char,
    pub value: *mut libc::c_char,
}
pub type CONF_VALUE = conf_value_st;
pub type _LHASH = lhash_st;
pub type OPENSSL_STACK = stack_st;
pub type lhash_CONF_VALUE_cmp_func = Option::<
    unsafe extern "C" fn(*const CONF_VALUE, *const CONF_VALUE) -> libc::c_int,
>;
pub type lhash_CONF_VALUE_hash_func = Option::<
    unsafe extern "C" fn(*const CONF_VALUE) -> uint32_t,
>;
pub type lhash_cmp_func = Option::<
    unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> libc::c_int,
>;
pub type lhash_hash_func = Option::<
    unsafe extern "C" fn(*const libc::c_void) -> uint32_t,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct LHASH_DOALL_CONF_VALUE {
    pub doall_arg: Option::<
        unsafe extern "C" fn(*mut CONF_VALUE, *mut libc::c_void) -> (),
    >,
    pub arg: *mut libc::c_void,
}
pub type lhash_cmp_func_helper = Option::<
    unsafe extern "C" fn(
        lhash_cmp_func,
        *const libc::c_void,
        *const libc::c_void,
    ) -> libc::c_int,
>;
pub type lhash_hash_func_helper = Option::<
    unsafe extern "C" fn(lhash_hash_func, *const libc::c_void) -> uint32_t,
>;
#[inline]
unsafe extern "C" fn sk_CONF_VALUE_new_null() -> *mut stack_st_CONF_VALUE {
    return OPENSSL_sk_new_null() as *mut stack_st_CONF_VALUE;
}
#[inline]
unsafe extern "C" fn sk_CONF_VALUE_free(mut sk: *mut stack_st_CONF_VALUE) {
    OPENSSL_sk_free(sk as *mut OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_CONF_VALUE_delete_ptr(
    mut sk: *mut stack_st_CONF_VALUE,
    mut p: *const CONF_VALUE,
) -> *mut CONF_VALUE {
    return OPENSSL_sk_delete_ptr(sk as *mut OPENSSL_STACK, p as *const libc::c_void)
        as *mut CONF_VALUE;
}
#[inline]
unsafe extern "C" fn sk_CONF_VALUE_push(
    mut sk: *mut stack_st_CONF_VALUE,
    mut p: *mut CONF_VALUE,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
static mut CONF_type_default: [libc::c_ushort; 256] = [
    0x8 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0x10 as libc::c_int as libc::c_ushort,
    0x10 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0x10 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0x10 as libc::c_int as libc::c_ushort,
    0x200 as libc::c_int as libc::c_ushort,
    0x40 as libc::c_int as libc::c_ushort,
    0x80 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0x200 as libc::c_int as libc::c_ushort,
    0x200 as libc::c_int as libc::c_ushort,
    0x40 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0x200 as libc::c_int as libc::c_ushort,
    0x200 as libc::c_int as libc::c_ushort,
    0x200 as libc::c_int as libc::c_ushort,
    0x200 as libc::c_int as libc::c_ushort,
    0x200 as libc::c_int as libc::c_ushort,
    0x200 as libc::c_int as libc::c_ushort,
    0x1 as libc::c_int as libc::c_ushort,
    0x1 as libc::c_int as libc::c_ushort,
    0x1 as libc::c_int as libc::c_ushort,
    0x1 as libc::c_int as libc::c_ushort,
    0x1 as libc::c_int as libc::c_ushort,
    0x1 as libc::c_int as libc::c_ushort,
    0x1 as libc::c_int as libc::c_ushort,
    0x1 as libc::c_int as libc::c_ushort,
    0x1 as libc::c_int as libc::c_ushort,
    0x1 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0x200 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0x200 as libc::c_int as libc::c_ushort,
    0x200 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0x2 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0x20 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0x200 as libc::c_int as libc::c_ushort,
    0x100 as libc::c_int as libc::c_ushort,
    0x40 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0x4 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0x200 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0x200 as libc::c_int as libc::c_ushort,
    0 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
    0x1000 as libc::c_int as libc::c_ushort,
];
#[inline]
unsafe extern "C" fn lh_CONF_VALUE_doall_arg(
    mut lh: *mut lhash_st_CONF_VALUE,
    mut func: Option::<unsafe extern "C" fn(*mut CONF_VALUE, *mut libc::c_void) -> ()>,
    mut arg: *mut libc::c_void,
) {
    let mut cb: LHASH_DOALL_CONF_VALUE = {
        let mut init = LHASH_DOALL_CONF_VALUE {
            doall_arg: func,
            arg: arg,
        };
        init
    };
    OPENSSL_lh_doall_arg(
        lh as *mut _LHASH,
        Some(
            lh_CONF_VALUE_call_doall_arg
                as unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void) -> (),
        ),
        &mut cb as *mut LHASH_DOALL_CONF_VALUE as *mut libc::c_void,
    );
}
#[inline]
unsafe extern "C" fn lh_CONF_VALUE_new(
    mut hash: lhash_CONF_VALUE_hash_func,
    mut comp: lhash_CONF_VALUE_cmp_func,
) -> *mut lhash_st_CONF_VALUE {
    return OPENSSL_lh_new(
        ::core::mem::transmute::<lhash_CONF_VALUE_hash_func, lhash_hash_func>(hash),
        ::core::mem::transmute::<lhash_CONF_VALUE_cmp_func, lhash_cmp_func>(comp),
    ) as *mut lhash_st_CONF_VALUE;
}
#[inline]
unsafe extern "C" fn lh_CONF_VALUE_call_hash_func(
    mut func: lhash_hash_func,
    mut a: *const libc::c_void,
) -> uint32_t {
    return (::core::mem::transmute::<lhash_hash_func, lhash_CONF_VALUE_hash_func>(func))
        .expect("non-null function pointer")(a as *const CONF_VALUE);
}
#[inline]
unsafe extern "C" fn lh_CONF_VALUE_insert(
    mut lh: *mut lhash_st_CONF_VALUE,
    mut old_data: *mut *mut CONF_VALUE,
    mut data: *mut CONF_VALUE,
) -> libc::c_int {
    let mut old_data_void: *mut libc::c_void = 0 as *mut libc::c_void;
    let mut ret: libc::c_int = OPENSSL_lh_insert(
        lh as *mut _LHASH,
        &mut old_data_void,
        data as *mut libc::c_void,
        Some(
            lh_CONF_VALUE_call_hash_func
                as unsafe extern "C" fn(lhash_hash_func, *const libc::c_void) -> uint32_t,
        ),
        Some(
            lh_CONF_VALUE_call_cmp_func
                as unsafe extern "C" fn(
                    lhash_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
    *old_data = old_data_void as *mut CONF_VALUE;
    return ret;
}
#[inline]
unsafe extern "C" fn lh_CONF_VALUE_free(mut lh: *mut lhash_st_CONF_VALUE) {
    OPENSSL_lh_free(lh as *mut _LHASH);
}
#[inline]
unsafe extern "C" fn lh_CONF_VALUE_retrieve(
    mut lh: *const lhash_st_CONF_VALUE,
    mut data: *const CONF_VALUE,
) -> *mut CONF_VALUE {
    return OPENSSL_lh_retrieve(
        lh as *const _LHASH,
        data as *const libc::c_void,
        Some(
            lh_CONF_VALUE_call_hash_func
                as unsafe extern "C" fn(lhash_hash_func, *const libc::c_void) -> uint32_t,
        ),
        Some(
            lh_CONF_VALUE_call_cmp_func
                as unsafe extern "C" fn(
                    lhash_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    ) as *mut CONF_VALUE;
}
#[inline]
unsafe extern "C" fn lh_CONF_VALUE_call_cmp_func(
    mut func: lhash_cmp_func,
    mut a: *const libc::c_void,
    mut b: *const libc::c_void,
) -> libc::c_int {
    return (::core::mem::transmute::<lhash_cmp_func, lhash_CONF_VALUE_cmp_func>(func))
        .expect(
            "non-null function pointer",
        )(a as *const CONF_VALUE, b as *const CONF_VALUE);
}
#[inline]
unsafe extern "C" fn lh_CONF_VALUE_call_doall_arg(
    mut value: *mut libc::c_void,
    mut arg: *mut libc::c_void,
) {
    let mut cb: *const LHASH_DOALL_CONF_VALUE = arg as *const LHASH_DOALL_CONF_VALUE;
    ((*cb).doall_arg)
        .expect("non-null function pointer")(value as *mut CONF_VALUE, (*cb).arg);
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
static mut kDefaultSectionName: [libc::c_char; 8] = unsafe {
    *::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"default\0")
};
unsafe extern "C" fn conf_value_hash(mut v: *const CONF_VALUE) -> uint32_t {
    let section_hash: uint32_t = if !((*v).section).is_null() {
        OPENSSL_strhash((*v).section)
    } else {
        0 as libc::c_int as uint32_t
    };
    let name_hash: uint32_t = if !((*v).name).is_null() {
        OPENSSL_strhash((*v).name)
    } else {
        0 as libc::c_int as uint32_t
    };
    return section_hash << 2 as libc::c_int ^ name_hash;
}
unsafe extern "C" fn conf_value_cmp(
    mut a: *const CONF_VALUE,
    mut b: *const CONF_VALUE,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    if (*a).section != (*b).section {
        i = strcmp((*a).section, (*b).section);
        if i != 0 {
            return i;
        }
    }
    if !((*a).name).is_null() && !((*b).name).is_null() {
        return strcmp((*a).name, (*b).name)
    } else if (*a).name == (*b).name {
        return 0 as libc::c_int
    } else {
        return if ((*a).name).is_null() { -(1 as libc::c_int) } else { 1 as libc::c_int }
    };
}
#[no_mangle]
pub unsafe extern "C" fn NCONF_new(mut method: *mut libc::c_void) -> *mut CONF {
    let mut conf: *mut CONF = 0 as *mut CONF;
    if !method.is_null() {
        return 0 as *mut CONF;
    }
    conf = OPENSSL_malloc(::core::mem::size_of::<CONF>() as libc::c_ulong) as *mut CONF;
    if conf.is_null() {
        return 0 as *mut CONF;
    }
    (*conf)
        .data = lh_CONF_VALUE_new(
        Some(conf_value_hash as unsafe extern "C" fn(*const CONF_VALUE) -> uint32_t),
        Some(
            conf_value_cmp
                as unsafe extern "C" fn(
                    *const CONF_VALUE,
                    *const CONF_VALUE,
                ) -> libc::c_int,
        ),
    );
    if ((*conf).data).is_null() {
        OPENSSL_free(conf as *mut libc::c_void);
        return 0 as *mut CONF;
    }
    return conf;
}
#[no_mangle]
pub unsafe extern "C" fn CONF_VALUE_new() -> *mut CONF_VALUE {
    return OPENSSL_zalloc(::core::mem::size_of::<CONF_VALUE>() as libc::c_ulong)
        as *mut CONF_VALUE;
}
unsafe extern "C" fn value_free_contents(mut value: *mut CONF_VALUE) {
    OPENSSL_free((*value).section as *mut libc::c_void);
    if !((*value).name).is_null() {
        OPENSSL_free((*value).name as *mut libc::c_void);
        OPENSSL_free((*value).value as *mut libc::c_void);
    } else {
        sk_CONF_VALUE_free((*value).value as *mut stack_st_CONF_VALUE);
    };
}
unsafe extern "C" fn value_free(mut value: *mut CONF_VALUE) {
    if !value.is_null() {
        value_free_contents(value);
        OPENSSL_free(value as *mut libc::c_void);
    }
}
unsafe extern "C" fn value_free_arg(
    mut value: *mut CONF_VALUE,
    mut arg: *mut libc::c_void,
) {
    value_free(value);
}
#[no_mangle]
pub unsafe extern "C" fn NCONF_free(mut conf: *mut CONF) {
    if conf.is_null() || ((*conf).data).is_null() {
        return;
    }
    lh_CONF_VALUE_doall_arg(
        (*conf).data,
        Some(
            value_free_arg
                as unsafe extern "C" fn(*mut CONF_VALUE, *mut libc::c_void) -> (),
        ),
        0 as *mut libc::c_void,
    );
    lh_CONF_VALUE_free((*conf).data);
    OPENSSL_free(conf as *mut libc::c_void);
}
unsafe extern "C" fn NCONF_new_section(
    mut conf: *const CONF,
    mut section: *const libc::c_char,
) -> *mut CONF_VALUE {
    let mut sk: *mut stack_st_CONF_VALUE = 0 as *mut stack_st_CONF_VALUE;
    let mut ok: libc::c_int = 0 as libc::c_int;
    let mut v: *mut CONF_VALUE = 0 as *mut CONF_VALUE;
    let mut old_value: *mut CONF_VALUE = 0 as *mut CONF_VALUE;
    sk = sk_CONF_VALUE_new_null();
    v = CONF_VALUE_new();
    if !(sk.is_null() || v.is_null()) {
        (*v).section = OPENSSL_strdup(section);
        if !((*v).section).is_null() {
            (*v).name = 0 as *mut libc::c_char;
            (*v).value = sk as *mut libc::c_char;
            if !(lh_CONF_VALUE_insert((*conf).data, &mut old_value, v) == 0) {
                value_free(old_value);
                ok = 1 as libc::c_int;
            }
        }
    }
    if ok == 0 {
        sk_CONF_VALUE_free(sk);
        OPENSSL_free(v as *mut libc::c_void);
        v = 0 as *mut CONF_VALUE;
    }
    return v;
}
unsafe extern "C" fn str_copy(
    mut conf: *mut CONF,
    mut section: *mut libc::c_char,
    mut pto: *mut *mut libc::c_char,
    mut from: *mut libc::c_char,
) -> libc::c_int {
    let mut current_block: u64;
    let mut q: libc::c_int = 0;
    let mut to: libc::c_int = 0 as libc::c_int;
    let mut len: libc::c_int = 0 as libc::c_int;
    let mut v: libc::c_char = 0;
    let mut buf: *mut BUF_MEM = 0 as *mut BUF_MEM;
    buf = BUF_MEM_new();
    if buf.is_null() {
        return 0 as libc::c_int;
    }
    len = (strlen(from)).wrapping_add(1 as libc::c_int as libc::c_ulong) as libc::c_int;
    if BUF_MEM_grow(buf, len as size_t) == 0 {
        current_block = 12044929297505654478;
    } else {
        current_block = 4906268039856690917;
    }
    loop {
        match current_block {
            12044929297505654478 => {
                BUF_MEM_free(buf);
                return 0 as libc::c_int;
            }
            _ => {
                if CONF_type_default[(*from as libc::c_int & 0xff as libc::c_int)
                    as usize] as libc::c_int & 64 as libc::c_int != 0
                {
                    q = *from as libc::c_int;
                    from = from.offset(1);
                    from;
                    while CONF_type_default[(*from as libc::c_int & 0xff as libc::c_int)
                        as usize] as libc::c_int & 8 as libc::c_int == 0
                        && *from as libc::c_int != q
                    {
                        if CONF_type_default[(*from as libc::c_int & 0xff as libc::c_int)
                            as usize] as libc::c_int & 32 as libc::c_int != 0
                        {
                            from = from.offset(1);
                            from;
                            if CONF_type_default[(*from as libc::c_int
                                & 0xff as libc::c_int) as usize] as libc::c_int
                                & 8 as libc::c_int != 0
                            {
                                break;
                            }
                        }
                        let fresh0 = from;
                        from = from.offset(1);
                        let fresh1 = to;
                        to = to + 1;
                        *((*buf).data).offset(fresh1 as isize) = *fresh0;
                    }
                    if *from as libc::c_int == q {
                        from = from.offset(1);
                        from;
                    }
                    current_block = 4906268039856690917;
                } else if CONF_type_default[(*from as libc::c_int & 0xff as libc::c_int)
                    as usize] as libc::c_int & 32 as libc::c_int != 0
                {
                    from = from.offset(1);
                    from;
                    let fresh2 = from;
                    from = from.offset(1);
                    v = *fresh2;
                    if CONF_type_default[(v as libc::c_int & 0xff as libc::c_int)
                        as usize] as libc::c_int & 8 as libc::c_int != 0
                    {
                        break;
                    }
                    if v as libc::c_int == 'r' as i32 {
                        v = '\r' as i32 as libc::c_char;
                    } else if v as libc::c_int == 'n' as i32 {
                        v = '\n' as i32 as libc::c_char;
                    } else if v as libc::c_int == 'b' as i32 {
                        v = '\u{8}' as i32 as libc::c_char;
                    } else if v as libc::c_int == 't' as i32 {
                        v = '\t' as i32 as libc::c_char;
                    }
                    let fresh3 = to;
                    to = to + 1;
                    *((*buf).data).offset(fresh3 as isize) = v;
                    current_block = 4906268039856690917;
                } else {
                    if CONF_type_default[(*from as libc::c_int & 0xff as libc::c_int)
                        as usize] as libc::c_int & 8 as libc::c_int != 0
                    {
                        break;
                    }
                    if *from as libc::c_int == '$' as i32 {
                        ERR_put_error(
                            13 as libc::c_int,
                            0 as libc::c_int,
                            107 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/conf/conf.c\0"
                                as *const u8 as *const libc::c_char,
                            239 as libc::c_int as libc::c_uint,
                        );
                        current_block = 12044929297505654478;
                    } else {
                        let fresh4 = from;
                        from = from.offset(1);
                        let fresh5 = to;
                        to = to + 1;
                        *((*buf).data).offset(fresh5 as isize) = *fresh4;
                        current_block = 4906268039856690917;
                    }
                }
            }
        }
    }
    *((*buf).data).offset(to as isize) = '\0' as i32 as libc::c_char;
    OPENSSL_free(*pto as *mut libc::c_void);
    *pto = (*buf).data;
    OPENSSL_free(buf as *mut libc::c_void);
    return 1 as libc::c_int;
}
unsafe extern "C" fn get_section(
    mut conf: *const CONF,
    mut section: *const libc::c_char,
) -> *mut CONF_VALUE {
    let mut template: CONF_VALUE = conf_value_st {
        section: 0 as *mut libc::c_char,
        name: 0 as *mut libc::c_char,
        value: 0 as *mut libc::c_char,
    };
    OPENSSL_memset(
        &mut template as *mut CONF_VALUE as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<CONF_VALUE>() as libc::c_ulong,
    );
    template.section = section as *mut libc::c_char;
    return lh_CONF_VALUE_retrieve((*conf).data, &mut template);
}
#[no_mangle]
pub unsafe extern "C" fn NCONF_get_section(
    mut conf: *const CONF,
    mut section: *const libc::c_char,
) -> *const stack_st_CONF_VALUE {
    let mut section_value: *const CONF_VALUE = get_section(conf, section);
    if section_value.is_null() {
        return 0 as *const stack_st_CONF_VALUE;
    }
    return (*section_value).value as *mut stack_st_CONF_VALUE;
}
#[no_mangle]
pub unsafe extern "C" fn NCONF_get_string(
    mut conf: *const CONF,
    mut section: *const libc::c_char,
    mut name: *const libc::c_char,
) -> *const libc::c_char {
    let mut template: CONF_VALUE = conf_value_st {
        section: 0 as *mut libc::c_char,
        name: 0 as *mut libc::c_char,
        value: 0 as *mut libc::c_char,
    };
    let mut value: *mut CONF_VALUE = 0 as *mut CONF_VALUE;
    if section.is_null() {
        section = kDefaultSectionName.as_ptr();
    }
    OPENSSL_memset(
        &mut template as *mut CONF_VALUE as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<CONF_VALUE>() as libc::c_ulong,
    );
    template.section = section as *mut libc::c_char;
    template.name = name as *mut libc::c_char;
    value = lh_CONF_VALUE_retrieve((*conf).data, &mut template);
    if value.is_null() {
        return 0 as *const libc::c_char;
    }
    return (*value).value;
}
unsafe extern "C" fn add_string(
    mut conf: *const CONF,
    mut section: *mut CONF_VALUE,
    mut value: *mut CONF_VALUE,
) -> libc::c_int {
    let mut section_stack: *mut stack_st_CONF_VALUE = (*section).value
        as *mut stack_st_CONF_VALUE;
    let mut old_value: *mut CONF_VALUE = 0 as *mut CONF_VALUE;
    (*value).section = OPENSSL_strdup((*section).section);
    if sk_CONF_VALUE_push(section_stack, value) == 0 {
        return 0 as libc::c_int;
    }
    if lh_CONF_VALUE_insert((*conf).data, &mut old_value, value) == 0 {
        return 0 as libc::c_int;
    }
    if !old_value.is_null() {
        sk_CONF_VALUE_delete_ptr(section_stack, old_value);
        value_free(old_value);
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn eat_ws(
    mut conf: *mut CONF,
    mut p: *mut libc::c_char,
) -> *mut libc::c_char {
    while CONF_type_default[(*p as libc::c_int & 0xff as libc::c_int) as usize]
        as libc::c_int & 16 as libc::c_int != 0
        && CONF_type_default[(*p as libc::c_int & 0xff as libc::c_int) as usize]
            as libc::c_int & 8 as libc::c_int == 0
    {
        p = p.offset(1);
        p;
    }
    return p;
}
unsafe extern "C" fn eat_alpha_numeric(
    mut conf: *mut CONF,
    mut p: *mut libc::c_char,
) -> *mut libc::c_char {
    loop {
        if CONF_type_default[(*p as libc::c_int & 0xff as libc::c_int) as usize]
            as libc::c_int & 32 as libc::c_int != 0
        {
            p = if CONF_type_default[(*p.offset(1 as libc::c_int as isize) as libc::c_int
                & 0xff as libc::c_int) as usize] as libc::c_int & 8 as libc::c_int != 0
            {
                p.offset(1 as libc::c_int as isize)
            } else {
                p.offset(2 as libc::c_int as isize)
            };
        } else {
            if CONF_type_default[(*p as libc::c_int & 0xff as libc::c_int) as usize]
                as libc::c_int
                & (2 as libc::c_int | 4 as libc::c_int | 1 as libc::c_int
                    | 256 as libc::c_int | 512 as libc::c_int) == 0
            {
                return p;
            }
            p = p.offset(1);
            p;
        }
    };
}
unsafe extern "C" fn scan_quote(
    mut conf: *mut CONF,
    mut p: *mut libc::c_char,
) -> *mut libc::c_char {
    let mut q: libc::c_int = *p as libc::c_int;
    p = p.offset(1);
    p;
    while CONF_type_default[(*p as libc::c_int & 0xff as libc::c_int) as usize]
        as libc::c_int & 8 as libc::c_int == 0 && *p as libc::c_int != q
    {
        if CONF_type_default[(*p as libc::c_int & 0xff as libc::c_int) as usize]
            as libc::c_int & 32 as libc::c_int != 0
        {
            p = p.offset(1);
            p;
            if CONF_type_default[(*p as libc::c_int & 0xff as libc::c_int) as usize]
                as libc::c_int & 8 as libc::c_int != 0
            {
                return p;
            }
        }
        p = p.offset(1);
        p;
    }
    if *p as libc::c_int == q {
        p = p.offset(1);
        p;
    }
    return p;
}
unsafe extern "C" fn clear_comments(mut conf: *mut CONF, mut p: *mut libc::c_char) {
    while !(CONF_type_default[(*p as libc::c_int & 0xff as libc::c_int) as usize]
        as libc::c_int & 16 as libc::c_int == 0)
    {
        p = p.offset(1);
        p;
    }
    loop {
        if CONF_type_default[(*p as libc::c_int & 0xff as libc::c_int) as usize]
            as libc::c_int & 128 as libc::c_int != 0
        {
            *p = '\0' as i32 as libc::c_char;
            return;
        }
        if CONF_type_default[(*p as libc::c_int & 0xff as libc::c_int) as usize]
            as libc::c_int & 64 as libc::c_int != 0
        {
            p = scan_quote(conf, p);
        } else if CONF_type_default[(*p as libc::c_int & 0xff as libc::c_int) as usize]
            as libc::c_int & 32 as libc::c_int != 0
        {
            p = if CONF_type_default[(*p.offset(1 as libc::c_int as isize) as libc::c_int
                & 0xff as libc::c_int) as usize] as libc::c_int & 8 as libc::c_int != 0
            {
                p.offset(1 as libc::c_int as isize)
            } else {
                p.offset(2 as libc::c_int as isize)
            };
        } else if CONF_type_default[(*p as libc::c_int & 0xff as libc::c_int) as usize]
            as libc::c_int & 8 as libc::c_int != 0
        {
            return
        } else {
            p = p.offset(1);
            p;
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn NCONF_load_bio(
    mut conf: *mut CONF,
    mut in_0: *mut BIO,
    mut out_error_line: *mut libc::c_long,
) -> libc::c_int {
    let mut current_block: u64;
    static mut CONFBUFSIZE: size_t = 512 as libc::c_int as size_t;
    let mut bufnum: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_int = 0;
    let mut ii: libc::c_int = 0;
    let mut buff: *mut BUF_MEM = 0 as *mut BUF_MEM;
    let mut s: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut end: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut again: libc::c_int = 0;
    let mut eline: libc::c_long = 0 as libc::c_int as libc::c_long;
    let mut btmp: [libc::c_char; 24] = [0; 24];
    let mut v: *mut CONF_VALUE = 0 as *mut CONF_VALUE;
    let mut tv: *mut CONF_VALUE = 0 as *mut CONF_VALUE;
    let mut sv: *mut CONF_VALUE = 0 as *mut CONF_VALUE;
    let mut section: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut buf: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut start: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut psection: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pname: *mut libc::c_char = 0 as *mut libc::c_char;
    buff = BUF_MEM_new();
    if buff.is_null() {
        ERR_put_error(
            13 as libc::c_int,
            0 as libc::c_int,
            7 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/conf/conf.c\0" as *const u8
                as *const libc::c_char,
            397 as libc::c_int as libc::c_uint,
        );
    } else {
        section = OPENSSL_strdup(kDefaultSectionName.as_ptr());
        if !section.is_null() {
            sv = NCONF_new_section(conf, section);
            if sv.is_null() {
                ERR_put_error(
                    13 as libc::c_int,
                    0 as libc::c_int,
                    104 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/conf/conf.c\0"
                        as *const u8 as *const libc::c_char,
                    408 as libc::c_int as libc::c_uint,
                );
            } else {
                bufnum = 0 as libc::c_int;
                again = 0 as libc::c_int;
                's_67: loop {
                    if BUF_MEM_grow(buff, (bufnum as size_t).wrapping_add(CONFBUFSIZE))
                        == 0
                    {
                        ERR_put_error(
                            13 as libc::c_int,
                            0 as libc::c_int,
                            7 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/conf/conf.c\0"
                                as *const u8 as *const libc::c_char,
                            416 as libc::c_int as libc::c_uint,
                        );
                        current_block = 11722694036604996786;
                        break;
                    } else {
                        p = &mut *((*buff).data).offset(bufnum as isize)
                            as *mut libc::c_char;
                        *p = '\0' as i32 as libc::c_char;
                        BIO_gets(
                            in_0,
                            p,
                            CONFBUFSIZE.wrapping_sub(1 as libc::c_int as size_t)
                                as libc::c_int,
                        );
                        *p
                            .offset(
                                CONFBUFSIZE.wrapping_sub(1 as libc::c_int as size_t)
                                    as isize,
                            ) = '\0' as i32 as libc::c_char;
                        i = strlen(p) as libc::c_int;
                        ii = i;
                        if i == 0 as libc::c_int && again == 0 {
                            current_block = 7301440000599063274;
                            break;
                        }
                        again = 0 as libc::c_int;
                        while i > 0 as libc::c_int {
                            if *p.offset((i - 1 as libc::c_int) as isize) as libc::c_int
                                != '\r' as i32
                                && *p.offset((i - 1 as libc::c_int) as isize) as libc::c_int
                                    != '\n' as i32
                            {
                                break;
                            }
                            i -= 1;
                            i;
                        }
                        if ii != 0 && i == ii {
                            again = 1 as libc::c_int;
                        } else {
                            *p.offset(i as isize) = '\0' as i32 as libc::c_char;
                            eline += 1;
                            eline;
                        }
                        bufnum += i;
                        v = 0 as *mut CONF_VALUE;
                        if bufnum >= 1 as libc::c_int {
                            p = &mut *((*buff).data)
                                .offset((bufnum - 1 as libc::c_int) as isize)
                                as *mut libc::c_char;
                            if CONF_type_default[(*p.offset(0 as libc::c_int as isize)
                                as libc::c_int & 0xff as libc::c_int) as usize]
                                as libc::c_int & 32 as libc::c_int != 0
                                && (bufnum <= 1 as libc::c_int
                                    || CONF_type_default[(*p
                                        .offset(-(1 as libc::c_int) as isize) as libc::c_int
                                        & 0xff as libc::c_int) as usize] as libc::c_int
                                        & 32 as libc::c_int == 0)
                            {
                                bufnum -= 1;
                                bufnum;
                                again = 1 as libc::c_int;
                            }
                        }
                        if again != 0 {
                            continue;
                        }
                        bufnum = 0 as libc::c_int;
                        buf = (*buff).data;
                        clear_comments(conf, buf);
                        s = eat_ws(conf, buf);
                        if CONF_type_default[(*s as libc::c_int & 0xff as libc::c_int)
                            as usize] as libc::c_int & 8 as libc::c_int != 0
                        {
                            continue;
                        }
                        if *s as libc::c_int == '[' as i32 {
                            let mut ss: *mut libc::c_char = 0 as *mut libc::c_char;
                            s = s.offset(1);
                            s;
                            start = eat_ws(conf, s);
                            ss = start;
                            loop {
                                end = eat_alpha_numeric(conf, ss);
                                p = eat_ws(conf, end);
                                if *p as libc::c_int != ']' as i32 {
                                    if *p as libc::c_int != '\0' as i32 && ss != p {
                                        ss = p;
                                    } else {
                                        ERR_put_error(
                                            13 as libc::c_int,
                                            0 as libc::c_int,
                                            101 as libc::c_int,
                                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/conf/conf.c\0"
                                                as *const u8 as *const libc::c_char,
                                            485 as libc::c_int as libc::c_uint,
                                        );
                                        current_block = 11722694036604996786;
                                        break 's_67;
                                    }
                                } else {
                                    *end = '\0' as i32 as libc::c_char;
                                    if str_copy(
                                        conf,
                                        0 as *mut libc::c_char,
                                        &mut section,
                                        start,
                                    ) == 0
                                    {
                                        current_block = 11722694036604996786;
                                        break 's_67;
                                    }
                                    sv = get_section(conf, section);
                                    if sv.is_null() {
                                        sv = NCONF_new_section(conf, section);
                                    }
                                    if !sv.is_null() {
                                        break;
                                    }
                                    ERR_put_error(
                                        13 as libc::c_int,
                                        0 as libc::c_int,
                                        104 as libc::c_int,
                                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/conf/conf.c\0"
                                            as *const u8 as *const libc::c_char,
                                        496 as libc::c_int as libc::c_uint,
                                    );
                                    current_block = 11722694036604996786;
                                    break 's_67;
                                }
                            }
                        } else {
                            pname = s;
                            psection = 0 as *mut libc::c_char;
                            end = eat_alpha_numeric(conf, s);
                            if *end.offset(0 as libc::c_int as isize) as libc::c_int
                                == ':' as i32
                                && *end.offset(1 as libc::c_int as isize) as libc::c_int
                                    == ':' as i32
                            {
                                *end = '\0' as i32 as libc::c_char;
                                end = end.offset(2 as libc::c_int as isize);
                                psection = pname;
                                pname = end;
                                end = eat_alpha_numeric(conf, end);
                            }
                            p = eat_ws(conf, end);
                            if *p as libc::c_int != '=' as i32 {
                                ERR_put_error(
                                    13 as libc::c_int,
                                    0 as libc::c_int,
                                    102 as libc::c_int,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/conf/conf.c\0"
                                        as *const u8 as *const libc::c_char,
                                    513 as libc::c_int as libc::c_uint,
                                );
                                current_block = 11722694036604996786;
                                break;
                            } else {
                                *end = '\0' as i32 as libc::c_char;
                                p = p.offset(1);
                                p;
                                start = eat_ws(conf, p);
                                while CONF_type_default[(*p as libc::c_int
                                    & 0xff as libc::c_int) as usize] as libc::c_int
                                    & 8 as libc::c_int == 0
                                {
                                    p = p.offset(1);
                                    p;
                                }
                                p = p.offset(-1);
                                p;
                                while p != start
                                    && CONF_type_default[(*p as libc::c_int
                                        & 0xff as libc::c_int) as usize] as libc::c_int
                                        & 16 as libc::c_int != 0
                                {
                                    p = p.offset(-1);
                                    p;
                                }
                                p = p.offset(1);
                                p;
                                *p = '\0' as i32 as libc::c_char;
                                v = CONF_VALUE_new();
                                if v.is_null() {
                                    current_block = 11722694036604996786;
                                    break;
                                }
                                if psection.is_null() {
                                    psection = section;
                                }
                                (*v).name = OPENSSL_strdup(pname);
                                if ((*v).name).is_null() {
                                    current_block = 11722694036604996786;
                                    break;
                                }
                                if str_copy(conf, psection, &mut (*v).value, start) == 0 {
                                    current_block = 11722694036604996786;
                                    break;
                                }
                                if strcmp(psection, section) != 0 as libc::c_int {
                                    tv = get_section(conf, psection);
                                    if tv.is_null() {
                                        tv = NCONF_new_section(conf, psection);
                                    }
                                    if tv.is_null() {
                                        ERR_put_error(
                                            13 as libc::c_int,
                                            0 as libc::c_int,
                                            104 as libc::c_int,
                                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/conf/conf.c\0"
                                                as *const u8 as *const libc::c_char,
                                            548 as libc::c_int as libc::c_uint,
                                        );
                                        current_block = 11722694036604996786;
                                        break;
                                    }
                                } else {
                                    tv = sv;
                                }
                                if add_string(conf, tv, v) == 0 as libc::c_int {
                                    current_block = 11722694036604996786;
                                    break;
                                }
                                v = 0 as *mut CONF_VALUE;
                            }
                        }
                    }
                }
                match current_block {
                    11722694036604996786 => {}
                    _ => {
                        BUF_MEM_free(buff);
                        OPENSSL_free(section as *mut libc::c_void);
                        return 1 as libc::c_int;
                    }
                }
            }
        }
    }
    BUF_MEM_free(buff);
    OPENSSL_free(section as *mut libc::c_void);
    if !out_error_line.is_null() {
        *out_error_line = eline;
    }
    snprintf(
        btmp.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 24]>() as libc::c_ulong,
        b"%ld\0" as *const u8 as *const libc::c_char,
        eline,
    );
    ERR_add_error_data(
        2 as libc::c_int as libc::c_uint,
        b"line \0" as *const u8 as *const libc::c_char,
        btmp.as_mut_ptr(),
    );
    if !v.is_null() {
        OPENSSL_free((*v).name as *mut libc::c_void);
        OPENSSL_free((*v).value as *mut libc::c_void);
        OPENSSL_free(v as *mut libc::c_void);
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn NCONF_load(
    mut conf: *mut CONF,
    mut filename: *const libc::c_char,
    mut out_error_line: *mut libc::c_long,
) -> libc::c_int {
    let mut in_0: *mut BIO = BIO_new_file(
        filename,
        b"rb\0" as *const u8 as *const libc::c_char,
    );
    let mut ret: libc::c_int = 0;
    if in_0.is_null() {
        ERR_put_error(
            13 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/conf/conf.c\0" as *const u8
                as *const libc::c_char,
            586 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    ret = NCONF_load_bio(conf, in_0, out_error_line);
    BIO_free(in_0);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn CONF_parse_list(
    mut list: *const libc::c_char,
    mut sep: libc::c_char,
    mut remove_whitespace: libc::c_int,
    mut list_cb: Option::<
        unsafe extern "C" fn(
            *const libc::c_char,
            size_t,
            *mut libc::c_void,
        ) -> libc::c_int,
    >,
    mut arg: *mut libc::c_void,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    let mut lstart: *const libc::c_char = 0 as *const libc::c_char;
    let mut tmpend: *const libc::c_char = 0 as *const libc::c_char;
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    if list.is_null() {
        ERR_put_error(
            13 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/conf/conf.c\0" as *const u8
                as *const libc::c_char,
            603 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    lstart = list;
    loop {
        if remove_whitespace != 0 {
            while *lstart as libc::c_int != 0
                && OPENSSL_isspace(*lstart as libc::c_uchar as libc::c_int) != 0
            {
                lstart = lstart.offset(1);
                lstart;
            }
        }
        p = strchr(lstart, sep as libc::c_int);
        if p == lstart || *lstart == 0 {
            ret = list_cb
                .expect(
                    "non-null function pointer",
                )(0 as *const libc::c_char, 0 as libc::c_int as size_t, arg);
        } else {
            if !p.is_null() {
                tmpend = p.offset(-(1 as libc::c_int as isize));
            } else {
                tmpend = lstart
                    .offset(strlen(lstart) as isize)
                    .offset(-(1 as libc::c_int as isize));
            }
            if remove_whitespace != 0 {
                while OPENSSL_isspace(*tmpend as libc::c_uchar as libc::c_int) != 0 {
                    tmpend = tmpend.offset(-1);
                    tmpend;
                }
            }
            ret = list_cb
                .expect(
                    "non-null function pointer",
                )(
                lstart,
                (tmpend.offset_from(lstart) as libc::c_long
                    + 1 as libc::c_int as libc::c_long) as size_t,
                arg,
            );
        }
        if ret <= 0 as libc::c_int {
            return ret;
        }
        if p.is_null() {
            return 1 as libc::c_int;
        }
        lstart = p.offset(1 as libc::c_int as isize);
    };
}
#[no_mangle]
pub unsafe extern "C" fn CONF_modules_load_file(
    mut filename: *const libc::c_char,
    mut appname: *const libc::c_char,
    mut flags: libc::c_ulong,
) -> libc::c_int {
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn CONF_get1_default_config_file() -> *mut libc::c_char {
    return OPENSSL_strdup(
        b"No support for Config files in AWS-LC.\0" as *const u8 as *const libc::c_char,
    );
}
#[no_mangle]
pub unsafe extern "C" fn CONF_modules_free() {}
#[no_mangle]
pub unsafe extern "C" fn CONF_modules_unload(mut all: libc::c_int) {}
#[no_mangle]
pub unsafe extern "C" fn CONF_modules_finish() {}
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_config(mut config_name: *const libc::c_char) {}
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_no_config() {}
