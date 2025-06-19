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
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn fputs(__s: *const libc::c_char, __stream: *mut FILE) -> libc::c_int;
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn free(_: *mut libc::c_void);
    fn abort() -> !;
    fn bsearch(
        __key: *const libc::c_void,
        __base: *const libc::c_void,
        __nmemb: size_t,
        __size: size_t,
        __compar: __compar_fn_t,
    ) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_strlcat(
        dst: *mut libc::c_char,
        src: *const libc::c_char,
        dst_size: size_t,
    ) -> size_t;
    fn __errno_location() -> *mut libc::c_int;
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
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    fn CRYPTO_STATIC_MUTEX_lock_write(lock: *mut CRYPTO_STATIC_MUTEX);
    fn CRYPTO_STATIC_MUTEX_unlock_write(lock: *mut CRYPTO_STATIC_MUTEX);
    fn CRYPTO_get_thread_local(value: thread_local_data_t) -> *mut libc::c_void;
    fn CRYPTO_set_thread_local(
        index: thread_local_data_t,
        value: *mut libc::c_void,
        destructor: thread_local_destructor_t,
    ) -> libc::c_int;
    fn OPENSSL_vasprintf_internal(
        str: *mut *mut libc::c_char,
        format: *const libc::c_char,
        args: ::core::ffi::VaList,
        system_malloc: libc::c_int,
    ) -> libc::c_int;
    static kOpenSSLReasonValues: [uint32_t; 0];
    static kOpenSSLReasonValuesLen: size_t;
    static kOpenSSLReasonStringData: [libc::c_char; 0];
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
pub type __gnuc_va_list = __builtin_va_list;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
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
pub type va_list = __gnuc_va_list;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uintptr_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_rwlock_arch_t {
    pub __readers: libc::c_uint,
    pub __writers: libc::c_uint,
    pub __wrphase_futex: libc::c_uint,
    pub __writers_futex: libc::c_uint,
    pub __pad3: libc::c_uint,
    pub __pad4: libc::c_uint,
    pub __cur_writer: libc::c_int,
    pub __shared: libc::c_int,
    pub __rwelision: libc::c_schar,
    pub __pad1: [libc::c_uchar; 7],
    pub __pad2: libc::c_ulong,
    pub __flags: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_rwlock_t {
    pub __data: __pthread_rwlock_arch_t,
    pub __size: [libc::c_char; 56],
    pub __align: libc::c_long,
}
pub type __compar_fn_t = Option::<
    unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> libc::c_int,
>;
pub type CRYPTO_THREADID = libc::c_int;
pub type ERR_STATE = err_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct err_state_st {
    pub errors: [err_error_st; 16],
    pub top: libc::c_uint,
    pub bottom: libc::c_uint,
    pub to_free: *mut libc::c_void,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct err_error_st {
    pub file: *const libc::c_char,
    pub data: *mut libc::c_char,
    pub packed: uint32_t,
    pub line: uint16_t,
    #[bitfield(name = "mark", ty = "libc::c_uint", bits = "0..=0")]
    pub mark: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 1],
}
pub type thread_local_data_t = libc::c_uint;
pub const NUM_OPENSSL_THREAD_LOCALS: thread_local_data_t = 5;
pub const OPENSSL_THREAD_LOCAL_TEST: thread_local_data_t = 4;
pub const AWSLC_THREAD_LOCAL_FIPS_SERVICE_INDICATOR_STATE: thread_local_data_t = 3;
pub const OPENSSL_THREAD_LOCAL_FIPS_COUNTERS: thread_local_data_t = 2;
pub const OPENSSL_THREAD_LOCAL_RAND: thread_local_data_t = 1;
pub const OPENSSL_THREAD_LOCAL_ERR: thread_local_data_t = 0;
pub type thread_local_destructor_t = Option::<
    unsafe extern "C" fn(*mut libc::c_void) -> (),
>;
pub type ERR_print_errors_callback_t = Option::<
    unsafe extern "C" fn(*const libc::c_char, size_t, *mut libc::c_void) -> libc::c_int,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CRYPTO_STATIC_MUTEX {
    pub lock: pthread_rwlock_t,
}
pub const PTHREAD_RWLOCK_DEFAULT_NP: C2RustUnnamed = 0;
pub type C2RustUnnamed = libc::c_uint;
pub const PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP: C2RustUnnamed = 2;
pub const PTHREAD_RWLOCK_PREFER_WRITER_NP: C2RustUnnamed = 1;
pub const PTHREAD_RWLOCK_PREFER_READER_NP: C2RustUnnamed = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct err_save_state_st {
    pub errors: *mut err_error_st,
    pub num_errors: size_t,
}
pub type ERR_SAVE_STATE = err_save_state_st;
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
unsafe extern "C" fn strdup_libc_malloc(
    mut str: *const libc::c_char,
) -> *mut libc::c_char {
    let mut len: size_t = strlen(str);
    let mut ret: *mut libc::c_char = malloc(len.wrapping_add(1 as libc::c_int as size_t))
        as *mut libc::c_char;
    if !ret.is_null() {
        memcpy(
            ret as *mut libc::c_void,
            str as *const libc::c_void,
            len.wrapping_add(1 as libc::c_int as size_t),
        );
    }
    return ret;
}
unsafe extern "C" fn err_clear(mut error: *mut err_error_st) {
    free((*error).data as *mut libc::c_void);
    OPENSSL_memset(
        error as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<err_error_st>() as libc::c_ulong,
    );
}
unsafe extern "C" fn err_copy(mut dst: *mut err_error_st, mut src: *const err_error_st) {
    err_clear(dst);
    (*dst).file = (*src).file;
    if !((*src).data).is_null() {
        (*dst).data = strdup_libc_malloc((*src).data);
    }
    (*dst).packed = (*src).packed;
    (*dst).line = (*src).line;
}
static mut global_next_library: libc::c_int = 34 as libc::c_int;
static mut global_next_library_mutex: CRYPTO_STATIC_MUTEX = {
    let mut init = CRYPTO_STATIC_MUTEX {
        lock: pthread_rwlock_t {
            __data: {
                let mut init = __pthread_rwlock_arch_t {
                    __readers: 0 as libc::c_int as libc::c_uint,
                    __writers: 0 as libc::c_int as libc::c_uint,
                    __wrphase_futex: 0 as libc::c_int as libc::c_uint,
                    __writers_futex: 0 as libc::c_int as libc::c_uint,
                    __pad3: 0 as libc::c_int as libc::c_uint,
                    __pad4: 0 as libc::c_int as libc::c_uint,
                    __cur_writer: 0 as libc::c_int,
                    __shared: 0 as libc::c_int,
                    __rwelision: 0 as libc::c_int as libc::c_schar,
                    __pad1: [
                        0 as libc::c_int as libc::c_uchar,
                        0 as libc::c_int as libc::c_uchar,
                        0 as libc::c_int as libc::c_uchar,
                        0 as libc::c_int as libc::c_uchar,
                        0 as libc::c_int as libc::c_uchar,
                        0 as libc::c_int as libc::c_uchar,
                        0 as libc::c_int as libc::c_uchar,
                    ],
                    __pad2: 0 as libc::c_int as libc::c_ulong,
                    __flags: PTHREAD_RWLOCK_DEFAULT_NP as libc::c_int as libc::c_uint,
                };
                init
            },
        },
    };
    init
};
unsafe extern "C" fn err_state_free(mut statep: *mut libc::c_void) {
    let mut state: *mut ERR_STATE = statep as *mut ERR_STATE;
    if state.is_null() {
        return;
    }
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while i < 16 as libc::c_int as libc::c_uint {
        err_clear(&mut *((*state).errors).as_mut_ptr().offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
    free((*state).to_free);
    free(state as *mut libc::c_void);
}
unsafe extern "C" fn err_get_state() -> *mut ERR_STATE {
    let mut state: *mut ERR_STATE = CRYPTO_get_thread_local(OPENSSL_THREAD_LOCAL_ERR)
        as *mut ERR_STATE;
    if state.is_null() {
        state = malloc(::core::mem::size_of::<ERR_STATE>() as libc::c_ulong)
            as *mut ERR_STATE;
        if state.is_null() {
            return 0 as *mut ERR_STATE;
        }
        OPENSSL_memset(
            state as *mut libc::c_void,
            0 as libc::c_int,
            ::core::mem::size_of::<ERR_STATE>() as libc::c_ulong,
        );
        if CRYPTO_set_thread_local(
            OPENSSL_THREAD_LOCAL_ERR,
            state as *mut libc::c_void,
            Some(err_state_free as unsafe extern "C" fn(*mut libc::c_void) -> ()),
        ) == 0
        {
            return 0 as *mut ERR_STATE;
        }
    }
    return state;
}
unsafe extern "C" fn get_error_values(
    mut inc: libc::c_int,
    mut top: libc::c_int,
    mut file: *mut *const libc::c_char,
    mut line: *mut libc::c_int,
    mut data: *mut *const libc::c_char,
    mut flags: *mut libc::c_int,
) -> uint32_t {
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut state: *mut ERR_STATE = 0 as *mut ERR_STATE;
    let mut error: *mut err_error_st = 0 as *mut err_error_st;
    let mut ret: uint32_t = 0;
    state = err_get_state();
    if state.is_null() || (*state).bottom == (*state).top {
        return 0 as libc::c_int as uint32_t;
    }
    if top != 0 {
        if inc == 0 {} else {
            __assert_fail(
                b"!inc\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/err/err.c\0" as *const u8
                    as *const libc::c_char,
                264 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 80],
                    &[libc::c_char; 80],
                >(
                    b"uint32_t get_error_values(int, int, const char **, int *, const char **, int *)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_2485: {
            if inc == 0 {} else {
                __assert_fail(
                    b"!inc\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/err/err.c\0" as *const u8
                        as *const libc::c_char,
                    264 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 80],
                        &[libc::c_char; 80],
                    >(
                        b"uint32_t get_error_values(int, int, const char **, int *, const char **, int *)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        i = (*state).top;
    } else {
        i = ((*state).bottom)
            .wrapping_add(1 as libc::c_int as libc::c_uint)
            .wrapping_rem(16 as libc::c_int as libc::c_uint);
    }
    error = &mut *((*state).errors).as_mut_ptr().offset(i as isize) as *mut err_error_st;
    ret = (*error).packed;
    if !file.is_null() && !line.is_null() {
        if ((*error).file).is_null() {
            *file = b"NA\0" as *const u8 as *const libc::c_char;
            *line = 0 as libc::c_int;
        } else {
            *file = (*error).file;
            *line = (*error).line as libc::c_int;
        }
    }
    if !data.is_null() {
        if ((*error).data).is_null() {
            *data = b"\0" as *const u8 as *const libc::c_char;
            if !flags.is_null() {
                *flags = 0 as libc::c_int;
            }
        } else {
            *data = (*error).data;
            if !flags.is_null() {
                *flags = 1 as libc::c_int | 2 as libc::c_int;
            }
            if inc != 0 {
                if !((*error).data).is_null() {
                    free((*state).to_free);
                    (*state).to_free = (*error).data as *mut libc::c_void;
                }
                (*error).data = 0 as *mut libc::c_char;
            }
        }
    }
    if inc != 0 {
        if top == 0 {} else {
            __assert_fail(
                b"!top\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/err/err.c\0" as *const u8
                    as *const libc::c_char,
                314 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 80],
                    &[libc::c_char; 80],
                >(
                    b"uint32_t get_error_values(int, int, const char **, int *, const char **, int *)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_2222: {
            if top == 0 {} else {
                __assert_fail(
                    b"!top\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/err/err.c\0" as *const u8
                        as *const libc::c_char,
                    314 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 80],
                        &[libc::c_char; 80],
                    >(
                        b"uint32_t get_error_values(int, int, const char **, int *, const char **, int *)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        err_clear(error);
        (*state).bottom = i;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn ERR_get_error() -> uint32_t {
    return get_error_values(
        1 as libc::c_int,
        0 as libc::c_int,
        0 as *mut *const libc::c_char,
        0 as *mut libc::c_int,
        0 as *mut *const libc::c_char,
        0 as *mut libc::c_int,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ERR_get_error_line(
    mut file: *mut *const libc::c_char,
    mut line: *mut libc::c_int,
) -> uint32_t {
    return get_error_values(
        1 as libc::c_int,
        0 as libc::c_int,
        file,
        line,
        0 as *mut *const libc::c_char,
        0 as *mut libc::c_int,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ERR_get_error_line_data(
    mut file: *mut *const libc::c_char,
    mut line: *mut libc::c_int,
    mut data: *mut *const libc::c_char,
    mut flags: *mut libc::c_int,
) -> uint32_t {
    return get_error_values(1 as libc::c_int, 0 as libc::c_int, file, line, data, flags);
}
#[no_mangle]
pub unsafe extern "C" fn ERR_peek_error() -> uint32_t {
    return get_error_values(
        0 as libc::c_int,
        0 as libc::c_int,
        0 as *mut *const libc::c_char,
        0 as *mut libc::c_int,
        0 as *mut *const libc::c_char,
        0 as *mut libc::c_int,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ERR_peek_error_line(
    mut file: *mut *const libc::c_char,
    mut line: *mut libc::c_int,
) -> uint32_t {
    return get_error_values(
        0 as libc::c_int,
        0 as libc::c_int,
        file,
        line,
        0 as *mut *const libc::c_char,
        0 as *mut libc::c_int,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ERR_peek_error_line_data(
    mut file: *mut *const libc::c_char,
    mut line: *mut libc::c_int,
    mut data: *mut *const libc::c_char,
    mut flags: *mut libc::c_int,
) -> uint32_t {
    return get_error_values(0 as libc::c_int, 0 as libc::c_int, file, line, data, flags);
}
#[no_mangle]
pub unsafe extern "C" fn ERR_peek_last_error() -> uint32_t {
    return get_error_values(
        0 as libc::c_int,
        1 as libc::c_int,
        0 as *mut *const libc::c_char,
        0 as *mut libc::c_int,
        0 as *mut *const libc::c_char,
        0 as *mut libc::c_int,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ERR_peek_last_error_line(
    mut file: *mut *const libc::c_char,
    mut line: *mut libc::c_int,
) -> uint32_t {
    return get_error_values(
        0 as libc::c_int,
        1 as libc::c_int,
        file,
        line,
        0 as *mut *const libc::c_char,
        0 as *mut libc::c_int,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ERR_peek_last_error_line_data(
    mut file: *mut *const libc::c_char,
    mut line: *mut libc::c_int,
    mut data: *mut *const libc::c_char,
    mut flags: *mut libc::c_int,
) -> uint32_t {
    return get_error_values(0 as libc::c_int, 1 as libc::c_int, file, line, data, flags);
}
#[no_mangle]
pub unsafe extern "C" fn ERR_clear_error() {
    let state: *mut ERR_STATE = err_get_state();
    let mut i: libc::c_uint = 0;
    if state.is_null() {
        return;
    }
    i = 0 as libc::c_int as libc::c_uint;
    while i < 16 as libc::c_int as libc::c_uint {
        err_clear(&mut *((*state).errors).as_mut_ptr().offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
    free((*state).to_free);
    (*state).to_free = 0 as *mut libc::c_void;
    (*state).bottom = 0 as libc::c_int as libc::c_uint;
    (*state).top = (*state).bottom;
}
#[no_mangle]
pub unsafe extern "C" fn ERR_remove_thread_state(mut tid: *const CRYPTO_THREADID) {
    if !tid.is_null() {
        __assert_fail(
            b"0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/err/err.c\0" as *const u8
                as *const libc::c_char,
            381 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 54],
                &[libc::c_char; 54],
            >(b"void ERR_remove_thread_state(const CRYPTO_THREADID *)\0"))
                .as_ptr(),
        );
        'c_4114: {
            __assert_fail(
                b"0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/err/err.c\0" as *const u8
                    as *const libc::c_char,
                381 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 54],
                    &[libc::c_char; 54],
                >(b"void ERR_remove_thread_state(const CRYPTO_THREADID *)\0"))
                    .as_ptr(),
            );
        };
        return;
    }
    ERR_clear_error();
}
#[no_mangle]
pub unsafe extern "C" fn ERR_get_next_error_library() -> libc::c_int {
    let mut ret: libc::c_int = 0;
    CRYPTO_STATIC_MUTEX_lock_write(&mut global_next_library_mutex);
    let fresh0 = global_next_library;
    global_next_library = global_next_library + 1;
    ret = fresh0;
    CRYPTO_STATIC_MUTEX_unlock_write(&mut global_next_library_mutex);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn ERR_remove_state(mut pid: libc::c_ulong) {
    ERR_clear_error();
}
#[no_mangle]
pub unsafe extern "C" fn ERR_clear_system_error() {
    *__errno_location() = 0 as libc::c_int;
}
unsafe extern "C" fn err_string_cmp(
    mut a: *const libc::c_void,
    mut b: *const libc::c_void,
) -> libc::c_int {
    let a_key: uint32_t = *(a as *const uint32_t) >> 15 as libc::c_int;
    let b_key: uint32_t = *(b as *const uint32_t) >> 15 as libc::c_int;
    if a_key < b_key {
        return -(1 as libc::c_int)
    } else if a_key > b_key {
        return 1 as libc::c_int
    } else {
        return 0 as libc::c_int
    };
}
unsafe extern "C" fn err_string_lookup(
    mut lib: uint32_t,
    mut key: uint32_t,
    mut values: *const uint32_t,
    mut num_values: size_t,
    mut string_data: *const libc::c_char,
) -> *const libc::c_char {
    if lib >= ((1 as libc::c_int) << 6 as libc::c_int) as uint32_t
        || key >= ((1 as libc::c_int) << 11 as libc::c_int) as uint32_t
    {
        return 0 as *const libc::c_char;
    }
    let mut search_key: uint32_t = lib << 26 as libc::c_int | key << 15 as libc::c_int;
    let mut result: *const uint32_t = bsearch(
        &mut search_key as *mut uint32_t as *const libc::c_void,
        values as *const libc::c_void,
        num_values,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
        Some(
            err_string_cmp
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    ) as *const uint32_t;
    if result.is_null() {
        return 0 as *const libc::c_char;
    }
    return &*string_data.offset((*result & 0x7fff as libc::c_int as uint32_t) as isize)
        as *const libc::c_char;
}
static mut kLibraryNames: [*const libc::c_char; 34] = [
    b"invalid library (0)\0" as *const u8 as *const libc::c_char,
    b"unknown library\0" as *const u8 as *const libc::c_char,
    b"system library\0" as *const u8 as *const libc::c_char,
    b"bignum routines\0" as *const u8 as *const libc::c_char,
    b"RSA routines\0" as *const u8 as *const libc::c_char,
    b"Diffie-Hellman routines\0" as *const u8 as *const libc::c_char,
    b"public key routines\0" as *const u8 as *const libc::c_char,
    b"memory buffer routines\0" as *const u8 as *const libc::c_char,
    b"object identifier routines\0" as *const u8 as *const libc::c_char,
    b"PEM routines\0" as *const u8 as *const libc::c_char,
    b"DSA routines\0" as *const u8 as *const libc::c_char,
    b"X.509 certificate routines\0" as *const u8 as *const libc::c_char,
    b"ASN.1 encoding routines\0" as *const u8 as *const libc::c_char,
    b"configuration file routines\0" as *const u8 as *const libc::c_char,
    b"common libcrypto routines\0" as *const u8 as *const libc::c_char,
    b"elliptic curve routines\0" as *const u8 as *const libc::c_char,
    b"SSL routines\0" as *const u8 as *const libc::c_char,
    b"BIO routines\0" as *const u8 as *const libc::c_char,
    b"PKCS7 routines\0" as *const u8 as *const libc::c_char,
    b"PKCS8 routines\0" as *const u8 as *const libc::c_char,
    b"X509 V3 routines\0" as *const u8 as *const libc::c_char,
    b"random number generator\0" as *const u8 as *const libc::c_char,
    b"ENGINE routines\0" as *const u8 as *const libc::c_char,
    b"OCSP routines\0" as *const u8 as *const libc::c_char,
    b"UI routines\0" as *const u8 as *const libc::c_char,
    b"COMP routines\0" as *const u8 as *const libc::c_char,
    b"ECDSA routines\0" as *const u8 as *const libc::c_char,
    b"ECDH routines\0" as *const u8 as *const libc::c_char,
    b"HMAC routines\0" as *const u8 as *const libc::c_char,
    b"Digest functions\0" as *const u8 as *const libc::c_char,
    b"Cipher functions\0" as *const u8 as *const libc::c_char,
    b"HKDF functions\0" as *const u8 as *const libc::c_char,
    b"Trust Token functions\0" as *const u8 as *const libc::c_char,
    b"User defined functions\0" as *const u8 as *const libc::c_char,
];
unsafe extern "C" fn err_lib_error_string(
    mut packed_error: uint32_t,
) -> *const libc::c_char {
    let lib: uint32_t = ERR_GET_LIB(packed_error) as uint32_t;
    if lib >= 34 as libc::c_int as uint32_t {
        return 0 as *const libc::c_char;
    }
    return kLibraryNames[lib as usize];
}
#[no_mangle]
pub unsafe extern "C" fn ERR_lib_error_string(
    mut packed_error: uint32_t,
) -> *const libc::c_char {
    let mut ret: *const libc::c_char = err_lib_error_string(packed_error);
    return if ret.is_null() {
        b"unknown library\0" as *const u8 as *const libc::c_char
    } else {
        ret
    };
}
#[no_mangle]
pub unsafe extern "C" fn ERR_func_error_string(
    mut packed_error: uint32_t,
) -> *const libc::c_char {
    return b"OPENSSL_internal\0" as *const u8 as *const libc::c_char;
}
unsafe extern "C" fn err_reason_error_string(
    mut packed_error: uint32_t,
) -> *const libc::c_char {
    let lib: uint32_t = ERR_GET_LIB(packed_error) as uint32_t;
    let reason: uint32_t = ERR_GET_REASON(packed_error) as uint32_t;
    if lib == 2 as libc::c_int as uint32_t {
        if reason < 127 as libc::c_int as uint32_t {
            return strerror(reason as libc::c_int);
        }
        return 0 as *const libc::c_char;
    }
    if reason < 34 as libc::c_int as uint32_t {
        return kLibraryNames[reason as usize];
    }
    if reason < 100 as libc::c_int as uint32_t {
        match reason {
            65 => return b"malloc failure\0" as *const u8 as *const libc::c_char,
            66 => {
                return b"function should not have been called\0" as *const u8
                    as *const libc::c_char;
            }
            67 => return b"passed a null parameter\0" as *const u8 as *const libc::c_char,
            68 => return b"internal error\0" as *const u8 as *const libc::c_char,
            69 => return b"overflow\0" as *const u8 as *const libc::c_char,
            _ => return 0 as *const libc::c_char,
        }
    }
    return err_string_lookup(
        lib,
        reason,
        kOpenSSLReasonValues.as_ptr(),
        kOpenSSLReasonValuesLen,
        kOpenSSLReasonStringData.as_ptr(),
    );
}
#[no_mangle]
pub unsafe extern "C" fn ERR_reason_error_string(
    mut packed_error: uint32_t,
) -> *const libc::c_char {
    let mut ret: *const libc::c_char = err_reason_error_string(packed_error);
    return if ret.is_null() {
        b"unknown error\0" as *const u8 as *const libc::c_char
    } else {
        ret
    };
}
#[no_mangle]
pub unsafe extern "C" fn ERR_error_string(
    mut packed_error: uint32_t,
    mut ret: *mut libc::c_char,
) -> *mut libc::c_char {
    static mut buf: [libc::c_char; 120] = [0; 120];
    if ret.is_null() {
        ret = buf.as_mut_ptr();
    }
    OPENSSL_memset(
        ret as *mut libc::c_void,
        0 as libc::c_int,
        120 as libc::c_int as size_t,
    );
    return ERR_error_string_n(packed_error, ret, 120 as libc::c_int as size_t);
}
#[no_mangle]
pub unsafe extern "C" fn ERR_error_string_n(
    mut packed_error: uint32_t,
    mut buf: *mut libc::c_char,
    mut len: size_t,
) -> *mut libc::c_char {
    if len == 0 as libc::c_int as size_t {
        return 0 as *mut libc::c_char;
    }
    let mut lib: libc::c_uint = ERR_GET_LIB(packed_error) as libc::c_uint;
    let mut reason: libc::c_uint = ERR_GET_REASON(packed_error) as libc::c_uint;
    let mut lib_str: *const libc::c_char = err_lib_error_string(packed_error);
    let mut reason_str: *const libc::c_char = err_reason_error_string(packed_error);
    let mut lib_buf: [libc::c_char; 32] = [0; 32];
    let mut reason_buf: [libc::c_char; 32] = [0; 32];
    if lib_str.is_null() {
        snprintf(
            lib_buf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong,
            b"lib(%u)\0" as *const u8 as *const libc::c_char,
            lib,
        );
        lib_str = lib_buf.as_mut_ptr();
    }
    if reason_str.is_null() {
        snprintf(
            reason_buf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong,
            b"reason(%u)\0" as *const u8 as *const libc::c_char,
            reason,
        );
        reason_str = reason_buf.as_mut_ptr();
    }
    let mut ret: libc::c_int = snprintf(
        buf,
        len,
        b"error:%08x:%s:OPENSSL_internal:%s\0" as *const u8 as *const libc::c_char,
        packed_error,
        lib_str,
        reason_str,
    );
    if ret >= 0 as libc::c_int && ret as size_t >= len {
        static mut num_colons: libc::c_uint = 4 as libc::c_int as libc::c_uint;
        let mut i: libc::c_uint = 0;
        let mut s: *mut libc::c_char = buf;
        if len <= num_colons as size_t {
            return buf;
        }
        i = 0 as libc::c_int as libc::c_uint;
        while i < num_colons {
            let mut colon: *mut libc::c_char = strchr(s, ':' as i32);
            let mut last_pos: *mut libc::c_char = (&mut *buf
                .offset(len.wrapping_sub(1 as libc::c_int as size_t) as isize)
                as *mut libc::c_char)
                .offset(-(num_colons as isize))
                .offset(i as isize);
            if colon.is_null() || colon > last_pos {
                OPENSSL_memset(
                    last_pos as *mut libc::c_void,
                    ':' as i32,
                    num_colons.wrapping_sub(i) as size_t,
                );
                break;
            } else {
                s = colon.offset(1 as libc::c_int as isize);
                i = i.wrapping_add(1);
                i;
            }
        }
    }
    return buf;
}
#[no_mangle]
pub unsafe extern "C" fn ERR_print_errors_cb(
    mut callback: ERR_print_errors_callback_t,
    mut ctx: *mut libc::c_void,
) {
    let mut buf: [libc::c_char; 120] = [0; 120];
    let mut buf2: [libc::c_char; 1024] = [0; 1024];
    let mut file: *const libc::c_char = 0 as *const libc::c_char;
    let mut data: *const libc::c_char = 0 as *const libc::c_char;
    let mut line: libc::c_int = 0;
    let mut flags: libc::c_int = 0;
    let mut packed_error: uint32_t = 0;
    let thread_hash: libc::c_ulong = err_get_state() as uintptr_t;
    loop {
        packed_error = ERR_get_error_line_data(
            &mut file,
            &mut line,
            &mut data,
            &mut flags,
        );
        if packed_error == 0 as libc::c_int as uint32_t {
            break;
        }
        ERR_error_string_n(
            packed_error,
            buf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 120]>() as libc::c_ulong,
        );
        snprintf(
            buf2.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
            b"%lu:%s:%s:%d:%s\n\0" as *const u8 as *const libc::c_char,
            thread_hash,
            buf.as_mut_ptr(),
            file,
            line,
            if flags & 1 as libc::c_int != 0 {
                data
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
        );
        if callback
            .expect(
                "non-null function pointer",
            )(buf2.as_mut_ptr(), strlen(buf2.as_mut_ptr()), ctx) <= 0 as libc::c_int
        {
            break;
        }
    };
}
unsafe extern "C" fn print_errors_to_file(
    mut msg: *const libc::c_char,
    mut msg_len: size_t,
    mut ctx: *mut libc::c_void,
) -> libc::c_int {
    if *msg.offset(msg_len as isize) as libc::c_int == '\0' as i32 {} else {
        __assert_fail(
            b"msg[msg_len] == '\\0'\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/err/err.c\0" as *const u8
                as *const libc::c_char,
            650 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 55],
                &[libc::c_char; 55],
            >(b"int print_errors_to_file(const char *, size_t, void *)\0"))
                .as_ptr(),
        );
    }
    'c_3752: {
        if *msg.offset(msg_len as isize) as libc::c_int == '\0' as i32 {} else {
            __assert_fail(
                b"msg[msg_len] == '\\0'\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/err/err.c\0" as *const u8
                    as *const libc::c_char,
                650 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 55],
                    &[libc::c_char; 55],
                >(b"int print_errors_to_file(const char *, size_t, void *)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut fp: *mut FILE = ctx as *mut FILE;
    let mut res: libc::c_int = fputs(msg, fp);
    return if res < 0 as libc::c_int { 0 as libc::c_int } else { 1 as libc::c_int };
}
#[no_mangle]
pub unsafe extern "C" fn ERR_print_errors_fp(mut file: *mut FILE) {
    ERR_print_errors_cb(
        Some(
            print_errors_to_file
                as unsafe extern "C" fn(
                    *const libc::c_char,
                    size_t,
                    *mut libc::c_void,
                ) -> libc::c_int,
        ),
        file as *mut libc::c_void,
    );
}
unsafe extern "C" fn err_set_error_data(mut data: *mut libc::c_char) {
    let state: *mut ERR_STATE = err_get_state();
    let mut error: *mut err_error_st = 0 as *mut err_error_st;
    if state.is_null() || (*state).top == (*state).bottom {
        free(data as *mut libc::c_void);
        return;
    }
    error = &mut *((*state).errors).as_mut_ptr().offset((*state).top as isize)
        as *mut err_error_st;
    free((*error).data as *mut libc::c_void);
    (*error).data = data;
}
#[no_mangle]
pub unsafe extern "C" fn ERR_put_error(
    mut library: libc::c_int,
    mut unused: libc::c_int,
    mut reason: libc::c_int,
    mut file: *const libc::c_char,
    mut line: libc::c_uint,
) {
    let state: *mut ERR_STATE = err_get_state();
    let mut error: *mut err_error_st = 0 as *mut err_error_st;
    if state.is_null() {
        return;
    }
    if library == 2 as libc::c_int && reason == 0 as libc::c_int {
        reason = *__errno_location();
    }
    (*state)
        .top = ((*state).top)
        .wrapping_add(1 as libc::c_int as libc::c_uint)
        .wrapping_rem(16 as libc::c_int as libc::c_uint);
    if (*state).top == (*state).bottom {
        (*state)
            .bottom = ((*state).bottom)
            .wrapping_add(1 as libc::c_int as libc::c_uint)
            .wrapping_rem(16 as libc::c_int as libc::c_uint);
    }
    error = &mut *((*state).errors).as_mut_ptr().offset((*state).top as isize)
        as *mut err_error_st;
    err_clear(error);
    (*error).file = file;
    (*error).line = line as uint16_t;
    (*error)
        .packed = (library as uint32_t & 0xff as libc::c_int as uint32_t)
        << 24 as libc::c_int | reason as uint32_t & 0xfff as libc::c_int as uint32_t;
}
unsafe extern "C" fn err_add_error_vdata(
    mut num: libc::c_uint,
    mut args: ::core::ffi::VaList,
) {
    let mut total_size: size_t = 0 as libc::c_int as size_t;
    let mut substr: *const libc::c_char = 0 as *const libc::c_char;
    let mut buf: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut args_copy: ::core::ffi::VaListImpl;
    args_copy = args.clone();
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < num as size_t {
        substr = args_copy.arg::<*const libc::c_char>();
        if !substr.is_null() {
            let mut substr_len: size_t = strlen(substr);
            if (18446744073709551615 as libc::c_ulong).wrapping_sub(total_size)
                < substr_len
            {
                return;
            }
            total_size = total_size.wrapping_add(substr_len);
        }
        i = i.wrapping_add(1);
        i;
    }
    if total_size == 18446744073709551615 as libc::c_ulong {
        return;
    }
    total_size = total_size.wrapping_add(1 as libc::c_int as size_t);
    buf = malloc(total_size) as *mut libc::c_char;
    if buf.is_null() {
        return;
    }
    *buf.offset(0 as libc::c_int as isize) = '\0' as i32 as libc::c_char;
    let mut i_0: size_t = 0 as libc::c_int as size_t;
    while i_0 < num as size_t {
        substr = args.arg::<*const libc::c_char>();
        if !substr.is_null() {
            if OPENSSL_strlcat(buf, substr, total_size) >= total_size {
                __assert_fail(
                    b"0\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/err/err.c\0" as *const u8
                        as *const libc::c_char,
                    742 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 63],
                        &[libc::c_char; 63],
                    >(
                        b"void err_add_error_vdata(unsigned int, struct __va_list_tag *)\0",
                    ))
                        .as_ptr(),
                );
                'c_4504: {
                    __assert_fail(
                        b"0\0" as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/err/err.c\0"
                            as *const u8 as *const libc::c_char,
                        742 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 63],
                            &[libc::c_char; 63],
                        >(
                            b"void err_add_error_vdata(unsigned int, struct __va_list_tag *)\0",
                        ))
                            .as_ptr(),
                    );
                };
            }
        }
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
    err_set_error_data(buf);
}
#[no_mangle]
pub unsafe extern "C" fn ERR_add_error_data(mut count: libc::c_uint, mut args: ...) {
    let mut args_0: ::core::ffi::VaListImpl;
    args_0 = args.clone();
    err_add_error_vdata(count, args_0.as_va_list());
}
#[no_mangle]
pub unsafe extern "C" fn ERR_add_error_dataf(
    mut format: *const libc::c_char,
    mut args: ...
) {
    let mut buf: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ap: ::core::ffi::VaListImpl;
    ap = args.clone();
    if OPENSSL_vasprintf_internal(&mut buf, format, ap.as_va_list(), 1 as libc::c_int)
        == -(1 as libc::c_int)
    {
        return;
    }
    err_set_error_data(buf);
}
#[no_mangle]
pub unsafe extern "C" fn ERR_set_error_data(
    mut data: *mut libc::c_char,
    mut flags: libc::c_int,
) {
    if flags & 1 as libc::c_int == 0 {
        __assert_fail(
            b"0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/err/err.c\0" as *const u8
                as *const libc::c_char,
            772 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 37],
                &[libc::c_char; 37],
            >(b"void ERR_set_error_data(char *, int)\0"))
                .as_ptr(),
        );
        'c_4857: {
            __assert_fail(
                b"0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/err/err.c\0" as *const u8
                    as *const libc::c_char,
                772 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 37],
                    &[libc::c_char; 37],
                >(b"void ERR_set_error_data(char *, int)\0"))
                    .as_ptr(),
            );
        };
        return;
    }
    let mut copy: *mut libc::c_char = strdup_libc_malloc(data);
    if !copy.is_null() {
        err_set_error_data(copy);
    }
    if flags & 2 as libc::c_int != 0 {
        OPENSSL_free(data as *mut libc::c_void);
    }
}
#[no_mangle]
pub unsafe extern "C" fn ERR_set_mark() -> libc::c_int {
    let state: *mut ERR_STATE = err_get_state();
    if state.is_null() || (*state).bottom == (*state).top {
        return 0 as libc::c_int;
    }
    ((*state).errors[(*state).top as usize]).set_mark(1 as libc::c_int as libc::c_uint);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ERR_pop_to_mark() -> libc::c_int {
    let state: *mut ERR_STATE = err_get_state();
    if state.is_null() {
        return 0 as libc::c_int;
    }
    while (*state).bottom != (*state).top {
        let mut error: *mut err_error_st = &mut *((*state).errors)
            .as_mut_ptr()
            .offset((*state).top as isize) as *mut err_error_st;
        if (*error).mark() != 0 {
            (*error).set_mark(0 as libc::c_int as libc::c_uint);
            return 1 as libc::c_int;
        }
        err_clear(error);
        if (*state).top == 0 as libc::c_int as libc::c_uint {
            (*state).top = (16 as libc::c_int - 1 as libc::c_int) as libc::c_uint;
        } else {
            (*state).top = ((*state).top).wrapping_sub(1);
            (*state).top;
        }
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ERR_load_CRYPTO_strings() {}
#[no_mangle]
pub unsafe extern "C" fn ERR_load_crypto_strings() {}
#[no_mangle]
pub unsafe extern "C" fn ERR_free_strings() {}
#[no_mangle]
pub unsafe extern "C" fn ERR_load_BIO_strings() {}
#[no_mangle]
pub unsafe extern "C" fn ERR_load_ERR_strings() {}
#[no_mangle]
pub unsafe extern "C" fn ERR_load_RAND_strings() {}
#[no_mangle]
pub unsafe extern "C" fn ERR_SAVE_STATE_free(mut state: *mut ERR_SAVE_STATE) {
    if state.is_null() {
        return;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < (*state).num_errors {
        err_clear(&mut *((*state).errors).offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
    free((*state).errors as *mut libc::c_void);
    free(state as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn ERR_save_state() -> *mut ERR_SAVE_STATE {
    let state: *mut ERR_STATE = err_get_state();
    if state.is_null() || (*state).top == (*state).bottom {
        return 0 as *mut ERR_SAVE_STATE;
    }
    let mut ret: *mut ERR_SAVE_STATE = malloc(
        ::core::mem::size_of::<ERR_SAVE_STATE>() as libc::c_ulong,
    ) as *mut ERR_SAVE_STATE;
    if ret.is_null() {
        return 0 as *mut ERR_SAVE_STATE;
    }
    let mut num_errors: size_t = (if (*state).top >= (*state).bottom {
        ((*state).top).wrapping_sub((*state).bottom)
    } else {
        (16 as libc::c_int as libc::c_uint)
            .wrapping_add((*state).top)
            .wrapping_sub((*state).bottom)
    }) as size_t;
    if num_errors < 16 as libc::c_int as size_t {} else {
        __assert_fail(
            b"num_errors < ERR_NUM_ERRORS\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/err/err.c\0" as *const u8
                as *const libc::c_char,
            867 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 37],
                &[libc::c_char; 37],
            >(b"ERR_SAVE_STATE *ERR_save_state(void)\0"))
                .as_ptr(),
        );
    }
    'c_9082: {
        if num_errors < 16 as libc::c_int as size_t {} else {
            __assert_fail(
                b"num_errors < ERR_NUM_ERRORS\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/err/err.c\0" as *const u8
                    as *const libc::c_char,
                867 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 37],
                    &[libc::c_char; 37],
                >(b"ERR_SAVE_STATE *ERR_save_state(void)\0"))
                    .as_ptr(),
            );
        }
    };
    (*ret)
        .errors = malloc(
        num_errors.wrapping_mul(::core::mem::size_of::<err_error_st>() as libc::c_ulong),
    ) as *mut err_error_st;
    if ((*ret).errors).is_null() {
        free(ret as *mut libc::c_void);
        return 0 as *mut ERR_SAVE_STATE;
    }
    OPENSSL_memset(
        (*ret).errors as *mut libc::c_void,
        0 as libc::c_int,
        num_errors.wrapping_mul(::core::mem::size_of::<err_error_st>() as libc::c_ulong),
    );
    (*ret).num_errors = num_errors;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < num_errors {
        let mut j: size_t = ((*state).bottom as size_t)
            .wrapping_add(i)
            .wrapping_add(1 as libc::c_int as size_t) % 16 as libc::c_int as size_t;
        err_copy(
            &mut *((*ret).errors).offset(i as isize),
            &mut *((*state).errors).as_mut_ptr().offset(j as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn ERR_restore_state(mut state: *const ERR_SAVE_STATE) {
    if state.is_null() || (*state).num_errors == 0 as libc::c_int as size_t {
        ERR_clear_error();
        return;
    }
    if (*state).num_errors >= 16 as libc::c_int as size_t {
        abort();
    }
    let dst: *mut ERR_STATE = err_get_state();
    if dst.is_null() {
        return;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < (*state).num_errors {
        err_copy(
            &mut *((*dst).errors).as_mut_ptr().offset(i as isize),
            &mut *((*state).errors).offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
    (*dst)
        .top = ((*state).num_errors).wrapping_sub(1 as libc::c_int as size_t)
        as libc::c_uint;
    (*dst).bottom = (16 as libc::c_int - 1 as libc::c_int) as libc::c_uint;
}
