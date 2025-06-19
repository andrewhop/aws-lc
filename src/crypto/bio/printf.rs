#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(c_variadic, extern_types, label_break_value)]
unsafe extern "C" {
    pub type stack_st_void;
    fn BIO_write(
        bio: *mut BIO,
        data: *const libc::c_void,
        len: libc::c_int,
    ) -> libc::c_int;
    fn vsnprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ::core::ffi::VaList,
    ) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
}
pub type __builtin_va_list = [__va_list_tag; 1];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __va_list_tag {
    pub gp_offset: libc::c_uint,
    pub fp_offset: libc::c_uint,
    pub overflow_arg_area: *mut libc::c_void,
    pub reg_save_area: *mut libc::c_void,
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
pub type __gnuc_va_list = __builtin_va_list;
pub type va_list = __gnuc_va_list;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_printf(
    mut bio: *mut BIO,
    mut format: *const libc::c_char,
    mut args: ...
) -> libc::c_int {
    let mut args_0: ::core::ffi::VaListImpl;
    let mut buf: [libc::c_char; 256] = [0; 256];
    let mut out: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut out_malloced: libc::c_char = 0 as libc::c_int as libc::c_char;
    let mut out_len: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    args_0 = args.clone();
    out_len = vsnprintf(
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
        format,
        args_0.as_va_list(),
    );
    if out_len < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    if out_len as size_t
        >= ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong
    {
        let requested_len: size_t = out_len as size_t;
        out = OPENSSL_malloc(requested_len.wrapping_add(1 as libc::c_int as size_t))
            as *mut libc::c_char;
        out_malloced = 1 as libc::c_int as libc::c_char;
        if out.is_null() {
            return -(1 as libc::c_int);
        }
        args_0 = args.clone();
        out_len = vsnprintf(
            out,
            requested_len.wrapping_add(1 as libc::c_int as size_t),
            format,
            args_0.as_va_list(),
        );
        if out_len == requested_len as libc::c_int {} else {
            __assert_fail(
                b"out_len == (int)requested_len\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/printf.c\0" as *const u8
                    as *const libc::c_char,
                90 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 41],
                    &[libc::c_char; 41],
                >(b"int BIO_printf(BIO *, const char *, ...)\0"))
                    .as_ptr(),
            );
        }
        'c_5216: {
            if out_len == requested_len as libc::c_int {} else {
                __assert_fail(
                    b"out_len == (int)requested_len\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/printf.c\0"
                        as *const u8 as *const libc::c_char,
                    90 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 41],
                        &[libc::c_char; 41],
                    >(b"int BIO_printf(BIO *, const char *, ...)\0"))
                        .as_ptr(),
                );
            }
        };
    } else {
        out = buf.as_mut_ptr();
    }
    ret = BIO_write(bio, out as *const libc::c_void, out_len);
    if out_malloced != 0 {
        OPENSSL_free(out as *mut libc::c_void);
    }
    return ret;
}
