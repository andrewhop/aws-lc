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
    pub type stack_st_void;
    pub type stack_st_CRYPTO_EX_DATA_FUNCS;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_realloc(ptr: *mut libc::c_void, new_size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_print_errors_cb(
        callback: ERR_print_errors_callback_t,
        ctx: *mut libc::c_void,
    );
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
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
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn CRYPTO_refcount_inc(count: *mut CRYPTO_refcount_t);
    fn CRYPTO_refcount_dec_and_test_zero(count: *mut CRYPTO_refcount_t) -> libc::c_int;
    fn CRYPTO_STATIC_MUTEX_lock_write(lock: *mut CRYPTO_STATIC_MUTEX);
    fn CRYPTO_STATIC_MUTEX_unlock_write(lock: *mut CRYPTO_STATIC_MUTEX);
    fn CRYPTO_get_ex_new_index(
        ex_data_class: *mut CRYPTO_EX_DATA_CLASS,
        out_index: *mut libc::c_int,
        argl: libc::c_long,
        argp: *mut libc::c_void,
        free_func: Option::<CRYPTO_EX_free>,
    ) -> libc::c_int;
    fn CRYPTO_set_ex_data(
        ad: *mut CRYPTO_EX_DATA,
        index: libc::c_int,
        val: *mut libc::c_void,
    ) -> libc::c_int;
    fn CRYPTO_get_ex_data(
        ad: *const CRYPTO_EX_DATA,
        index: libc::c_int,
    ) -> *mut libc::c_void;
    fn CRYPTO_new_ex_data(ad: *mut CRYPTO_EX_DATA);
    fn CRYPTO_free_ex_data(
        ex_data_class: *mut CRYPTO_EX_DATA_CLASS,
        obj: *mut libc::c_void,
        ad: *mut CRYPTO_EX_DATA,
    );
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
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
pub type ERR_print_errors_callback_t = Option::<
    unsafe extern "C" fn(*const libc::c_char, size_t, *mut libc::c_void) -> libc::c_int,
>;
pub type CRYPTO_EX_free = unsafe extern "C" fn(
    *mut libc::c_void,
    *mut libc::c_void,
    *mut CRYPTO_EX_DATA,
    libc::c_int,
    libc::c_long,
    *mut libc::c_void,
) -> ();
pub type CRYPTO_EX_dup = unsafe extern "C" fn(
    *mut CRYPTO_EX_DATA,
    *const CRYPTO_EX_DATA,
    *mut *mut libc::c_void,
    libc::c_int,
    libc::c_long,
    *mut libc::c_void,
) -> libc::c_int;
pub type CRYPTO_EX_unused = libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CRYPTO_EX_DATA_CLASS {
    pub lock: CRYPTO_STATIC_MUTEX,
    pub meth: *mut stack_st_CRYPTO_EX_DATA_FUNCS,
    pub num_reserved: uint8_t,
}
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
unsafe extern "C" fn callback_fn_wrap_ex(
    mut bio: *mut BIO,
    mut oper: libc::c_int,
    mut argp: *const libc::c_char,
    mut len: size_t,
    mut argi: libc::c_int,
    mut argl: libc::c_long,
    mut bio_ret: libc::c_int,
    mut processed: *mut size_t,
) -> libc::c_long {
    if !bio.is_null() {} else {
        __assert_fail(
            b"bio != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                as *const libc::c_char,
            83 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 85],
                &[libc::c_char; 85],
            >(
                b"long callback_fn_wrap_ex(BIO *, int, const char *, size_t, int, long, int, size_t *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_5662: {
        if !bio.is_null() {} else {
            __assert_fail(
                b"bio != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                    as *const libc::c_char,
                83 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 85],
                    &[libc::c_char; 85],
                >(
                    b"long callback_fn_wrap_ex(BIO *, int, const char *, size_t, int, long, int, size_t *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if ((*bio).callback).is_some() {} else {
        __assert_fail(
            b"bio->callback != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                as *const libc::c_char,
            84 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 85],
                &[libc::c_char; 85],
            >(
                b"long callback_fn_wrap_ex(BIO *, int, const char *, size_t, int, long, int, size_t *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_5615: {
        if ((*bio).callback).is_some() {} else {
            __assert_fail(
                b"bio->callback != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                    as *const libc::c_char,
                84 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 85],
                    &[libc::c_char; 85],
                >(
                    b"long callback_fn_wrap_ex(BIO *, int, const char *, size_t, int, long, int, size_t *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if ((*bio).callback_ex).is_none() {} else {
        __assert_fail(
            b"bio->callback_ex == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                as *const libc::c_char,
            85 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 85],
                &[libc::c_char; 85],
            >(
                b"long callback_fn_wrap_ex(BIO *, int, const char *, size_t, int, long, int, size_t *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_5558: {
        if ((*bio).callback_ex).is_none() {} else {
            __assert_fail(
                b"bio->callback_ex == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                    as *const libc::c_char,
                85 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 85],
                    &[libc::c_char; 85],
                >(
                    b"long callback_fn_wrap_ex(BIO *, int, const char *, size_t, int, long, int, size_t *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut bareoper: libc::c_int = oper & !(0x80 as libc::c_int);
    if bareoper == 0x2 as libc::c_int || bareoper == 0x3 as libc::c_int
        || bareoper == 0x5 as libc::c_int
    {
        if len > 2147483647 as libc::c_int as size_t {
            return -(1 as libc::c_int) as libc::c_long;
        }
        argi = len as libc::c_int;
    }
    if bio_ret > 0 as libc::c_int && oper & 0x80 as libc::c_int != 0
        && bareoper != 0x6 as libc::c_int
    {
        if *processed > 2147483647 as libc::c_int as size_t {
            return -(1 as libc::c_int) as libc::c_long;
        }
        bio_ret = *processed as libc::c_int;
    }
    let mut ret: libc::c_long = ((*bio).callback)
        .expect(
            "non-null function pointer",
        )(bio, oper, argp, argi, argl, bio_ret as libc::c_long);
    if ret > 0 as libc::c_int as libc::c_long && oper & 0x80 as libc::c_int != 0
        && bareoper != 0x6 as libc::c_int
    {
        *processed = ret as size_t;
        ret = 1 as libc::c_int as libc::c_long;
    }
    return ret;
}
unsafe extern "C" fn get_callback(mut bio: *mut BIO) -> BIO_callback_fn_ex {
    if !bio.is_null() {} else {
        __assert_fail(
            b"bio != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                as *const libc::c_char,
            129 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 39],
                &[libc::c_char; 39],
            >(b"BIO_callback_fn_ex get_callback(BIO *)\0"))
                .as_ptr(),
        );
    }
    'c_5728: {
        if !bio.is_null() {} else {
            __assert_fail(
                b"bio != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                    as *const libc::c_char,
                129 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 39],
                    &[libc::c_char; 39],
                >(b"BIO_callback_fn_ex get_callback(BIO *)\0"))
                    .as_ptr(),
            );
        }
    };
    if ((*bio).callback_ex).is_some() {
        return (*bio).callback_ex;
    }
    if ((*bio).callback).is_some() {
        return Some(
            callback_fn_wrap_ex
                as unsafe extern "C" fn(
                    *mut BIO,
                    libc::c_int,
                    *const libc::c_char,
                    size_t,
                    libc::c_int,
                    libc::c_long,
                    libc::c_int,
                    *mut size_t,
                ) -> libc::c_long,
        );
    }
    return None;
}
unsafe extern "C" fn handle_callback_return(
    mut bio: *mut BIO,
    mut oper: libc::c_int,
    mut buf: *const libc::c_void,
    mut len: libc::c_int,
    mut ret: libc::c_int,
) -> libc::c_int {
    let mut processed: size_t = 0 as libc::c_int as size_t;
    if ret > 0 as libc::c_int {
        if oper == 0x2 as libc::c_int || oper == 0x5 as libc::c_int {
            (*bio).num_read = ((*bio).num_read).wrapping_add(ret as uint64_t);
        } else if oper == 0x3 as libc::c_int || oper == 0x4 as libc::c_int {
            (*bio).num_write = ((*bio).num_write).wrapping_add(ret as uint64_t);
        }
        processed = ret as size_t;
        ret = 1 as libc::c_int;
    }
    let mut cb: BIO_callback_fn_ex = get_callback(bio);
    if cb.is_some() {
        let mut callback_ret: libc::c_long = cb
            .expect(
                "non-null function pointer",
            )(
            bio,
            oper | 0x80 as libc::c_int,
            buf as *const libc::c_char,
            len as size_t,
            0 as libc::c_int,
            0 as libc::c_long,
            ret,
            &mut processed,
        );
        if callback_ret > 2147483647 as libc::c_int as libc::c_long
            || callback_ret
                < (-(2147483647 as libc::c_int) - 1 as libc::c_int) as libc::c_long
        {
            return -(1 as libc::c_int);
        }
        ret = callback_ret as libc::c_int;
    }
    if ret > 0 as libc::c_int {
        if processed > 2147483647 as libc::c_int as size_t {
            ret = -(1 as libc::c_int);
        } else {
            ret = processed as libc::c_int;
        }
    }
    return ret;
}
static mut g_ex_data_class: CRYPTO_EX_DATA_CLASS = {
    let mut init = CRYPTO_EX_DATA_CLASS {
        lock: {
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
                            __flags: PTHREAD_RWLOCK_DEFAULT_NP as libc::c_int
                                as libc::c_uint,
                        };
                        init
                    },
                },
            };
            init
        },
        meth: 0 as *const stack_st_CRYPTO_EX_DATA_FUNCS
            as *mut stack_st_CRYPTO_EX_DATA_FUNCS,
        num_reserved: 1 as libc::c_int as uint8_t,
    };
    init
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_new(mut method: *const BIO_METHOD) -> *mut BIO {
    let mut ret: *mut BIO = OPENSSL_zalloc(
        ::core::mem::size_of::<BIO>() as libc::c_ulong,
    ) as *mut BIO;
    if ret.is_null() {
        return 0 as *mut BIO;
    }
    (*ret).method = method;
    (*ret).shutdown = 1 as libc::c_int;
    (*ret).references = 1 as libc::c_int as CRYPTO_refcount_t;
    (*ret).callback_ex = None;
    (*ret).callback = None;
    CRYPTO_new_ex_data(&mut (*ret).ex_data);
    if ((*method).create).is_some()
        && ((*method).create).expect("non-null function pointer")(ret) == 0
    {
        OPENSSL_free(ret as *mut libc::c_void);
        return 0 as *mut BIO;
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_free(mut bio: *mut BIO) -> libc::c_int {
    let mut next_bio: *mut BIO = 0 as *mut BIO;
    while !bio.is_null() {
        if CRYPTO_refcount_dec_and_test_zero(&mut (*bio).references) == 0 {
            return 0 as libc::c_int;
        }
        next_bio = BIO_pop(bio);
        if !((*bio).method).is_null() && ((*(*bio).method).destroy).is_some() {
            ((*(*bio).method).destroy).expect("non-null function pointer")(bio);
        }
        let mut cb: BIO_callback_fn_ex = get_callback(bio);
        if cb.is_some() {
            let mut ret: libc::c_long = cb
                .expect(
                    "non-null function pointer",
                )(
                bio,
                0x1 as libc::c_int,
                0 as *const libc::c_char,
                0 as libc::c_int as size_t,
                0 as libc::c_int,
                0 as libc::c_long,
                1 as libc::c_long as libc::c_int,
                0 as *mut size_t,
            );
            if ret <= 0 as libc::c_int as libc::c_long {
                if ret
                    >= (-(2147483647 as libc::c_int) - 1 as libc::c_int) as libc::c_long
                {
                    return ret as libc::c_int;
                }
                return -(2147483647 as libc::c_int) - 1 as libc::c_int;
            }
        }
        CRYPTO_free_ex_data(
            &mut g_ex_data_class,
            bio as *mut libc::c_void,
            &mut (*bio).ex_data,
        );
        OPENSSL_free(bio as *mut libc::c_void);
        bio = next_bio;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_up_ref(mut bio: *mut BIO) -> libc::c_int {
    CRYPTO_refcount_inc(&mut (*bio).references);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_vfree(mut bio: *mut BIO) {
    BIO_free(bio);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_free_all(mut bio: *mut BIO) {
    BIO_free(bio);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_read(
    mut bio: *mut BIO,
    mut buf: *mut libc::c_void,
    mut len: libc::c_int,
) -> libc::c_int {
    if bio.is_null() || ((*bio).method).is_null() || ((*(*bio).method).bread).is_none() {
        ERR_put_error(
            17 as libc::c_int,
            0 as libc::c_int,
            115 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                as *const libc::c_char,
            253 as libc::c_int as libc::c_uint,
        );
        return -(2 as libc::c_int);
    }
    if len <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut cb: BIO_callback_fn_ex = get_callback(bio);
    if cb.is_some() {
        let mut callback_ret: libc::c_long = cb
            .expect(
                "non-null function pointer",
            )(
            bio,
            0x2 as libc::c_int,
            buf as *const libc::c_char,
            len as size_t,
            0 as libc::c_int,
            0 as libc::c_long,
            1 as libc::c_long as libc::c_int,
            0 as *mut size_t,
        );
        if callback_ret <= 0 as libc::c_int as libc::c_long {
            if callback_ret
                >= (-(2147483647 as libc::c_int) - 1 as libc::c_int) as libc::c_long
            {
                return callback_ret as libc::c_int;
            }
            return -(2147483647 as libc::c_int) - 1 as libc::c_int;
        }
    }
    if (*bio).init == 0 {
        ERR_put_error(
            17 as libc::c_int,
            0 as libc::c_int,
            114 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                as *const libc::c_char,
            272 as libc::c_int as libc::c_uint,
        );
        return -(2 as libc::c_int);
    }
    let mut ret: libc::c_int = ((*(*bio).method).bread)
        .expect("non-null function pointer")(bio, buf as *mut libc::c_char, len);
    return handle_callback_return(bio, 0x2 as libc::c_int, buf, len, ret);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_read_ex(
    mut bio: *mut BIO,
    mut data: *mut libc::c_void,
    mut data_len: size_t,
    mut read_bytes: *mut size_t,
) -> libc::c_int {
    if bio.is_null() || read_bytes.is_null() {
        ERR_put_error(
            17 as libc::c_int,
            0 as libc::c_int,
            111 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                as *const libc::c_char,
            282 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut read_len: libc::c_int = data_len as libc::c_int;
    if data_len > 2147483647 as libc::c_int as size_t {
        read_len = 2147483647 as libc::c_int;
    }
    let mut ret: libc::c_int = BIO_read(bio, data, read_len);
    if ret > 0 as libc::c_int {
        *read_bytes = ret as size_t;
        return 1 as libc::c_int;
    } else {
        *read_bytes = 0 as libc::c_int as size_t;
        return 0 as libc::c_int;
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_gets(
    mut bio: *mut BIO,
    mut buf: *mut libc::c_char,
    mut len: libc::c_int,
) -> libc::c_int {
    if bio.is_null() || ((*bio).method).is_null() || ((*(*bio).method).bgets).is_none() {
        ERR_put_error(
            17 as libc::c_int,
            0 as libc::c_int,
            115 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                as *const libc::c_char,
            303 as libc::c_int as libc::c_uint,
        );
        return -(2 as libc::c_int);
    }
    if len <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut cb: BIO_callback_fn_ex = get_callback(bio);
    if cb.is_some() {
        let mut callback_ret: libc::c_long = cb
            .expect(
                "non-null function pointer",
            )(
            bio,
            0x5 as libc::c_int,
            buf,
            len as size_t,
            0 as libc::c_int,
            0 as libc::c_long,
            1 as libc::c_long as libc::c_int,
            0 as *mut size_t,
        );
        if callback_ret <= 0 as libc::c_int as libc::c_long {
            if callback_ret
                >= (-(2147483647 as libc::c_int) - 1 as libc::c_int) as libc::c_long
            {
                return callback_ret as libc::c_int;
            }
            return -(2147483647 as libc::c_int) - 1 as libc::c_int;
        }
    }
    if (*bio).init == 0 {
        ERR_put_error(
            17 as libc::c_int,
            0 as libc::c_int,
            114 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                as *const libc::c_char,
            322 as libc::c_int as libc::c_uint,
        );
        return -(2 as libc::c_int);
    }
    let mut ret: libc::c_int = ((*(*bio).method).bgets)
        .expect("non-null function pointer")(bio, buf, len);
    return handle_callback_return(
        bio,
        0x5 as libc::c_int,
        buf as *const libc::c_void,
        len,
        ret,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_write(
    mut bio: *mut BIO,
    mut in_0: *const libc::c_void,
    mut inl: libc::c_int,
) -> libc::c_int {
    if bio.is_null() || ((*bio).method).is_null() || ((*(*bio).method).bwrite).is_none()
    {
        ERR_put_error(
            17 as libc::c_int,
            0 as libc::c_int,
            115 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                as *const libc::c_char,
            333 as libc::c_int as libc::c_uint,
        );
        return -(2 as libc::c_int);
    }
    if inl <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut cb: BIO_callback_fn_ex = get_callback(bio);
    if cb.is_some() {
        let mut callback_ret: libc::c_long = cb
            .expect(
                "non-null function pointer",
            )(
            bio,
            0x3 as libc::c_int,
            in_0 as *const libc::c_char,
            inl as size_t,
            0 as libc::c_int,
            0 as libc::c_long,
            1 as libc::c_long as libc::c_int,
            0 as *mut size_t,
        );
        if callback_ret <= 0 as libc::c_int as libc::c_long {
            if callback_ret
                >= (-(2147483647 as libc::c_int) - 1 as libc::c_int) as libc::c_long
            {
                return callback_ret as libc::c_int;
            }
            return -(2147483647 as libc::c_int) - 1 as libc::c_int;
        }
    }
    if (*bio).init == 0 {
        ERR_put_error(
            17 as libc::c_int,
            0 as libc::c_int,
            114 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                as *const libc::c_char,
            352 as libc::c_int as libc::c_uint,
        );
        return -(2 as libc::c_int);
    }
    let mut ret: libc::c_int = ((*(*bio).method).bwrite)
        .expect("non-null function pointer")(bio, in_0 as *const libc::c_char, inl);
    return handle_callback_return(bio, 0x3 as libc::c_int, in_0, inl, ret);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_write_ex(
    mut bio: *mut BIO,
    mut data: *const libc::c_void,
    mut data_len: size_t,
    mut written_bytes: *mut size_t,
) -> libc::c_int {
    if bio.is_null() {
        ERR_put_error(
            17 as libc::c_int,
            0 as libc::c_int,
            111 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                as *const libc::c_char,
            362 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut write_len: libc::c_int = data_len as libc::c_int;
    if data_len > 2147483647 as libc::c_int as size_t {
        write_len = 2147483647 as libc::c_int;
    }
    let mut ret: libc::c_int = BIO_write(bio, data, write_len);
    if ret > 0 as libc::c_int {
        if !written_bytes.is_null() {
            *written_bytes = ret as size_t;
        }
        return 1 as libc::c_int;
    } else {
        if !written_bytes.is_null() {
            *written_bytes = 0 as libc::c_int as size_t;
        }
        return 0 as libc::c_int;
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_write_all(
    mut bio: *mut BIO,
    mut data: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    let mut data_u8: *const uint8_t = data as *const uint8_t;
    while len > 0 as libc::c_int as size_t {
        let write_len: libc::c_int = if len > 2147483647 as libc::c_int as size_t {
            2147483647 as libc::c_int
        } else {
            len as libc::c_int
        };
        let mut ret: libc::c_int = BIO_write(
            bio,
            data_u8 as *const libc::c_void,
            write_len,
        );
        if ret <= write_len {} else {
            __assert_fail(
                b"ret <= write_len\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                    as *const libc::c_char,
                390 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 47],
                    &[libc::c_char; 47],
                >(b"int BIO_write_all(BIO *, const void *, size_t)\0"))
                    .as_ptr(),
            );
        }
        'c_6875: {
            if ret <= write_len {} else {
                __assert_fail(
                    b"ret <= write_len\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                        as *const libc::c_char,
                    390 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 47],
                        &[libc::c_char; 47],
                    >(b"int BIO_write_all(BIO *, const void *, size_t)\0"))
                        .as_ptr(),
                );
            }
        };
        if ret <= 0 as libc::c_int {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                107 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                    as *const libc::c_char,
                392 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        data_u8 = data_u8.offset(ret as isize);
        len = len.wrapping_sub(ret as size_t);
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_puts(
    mut bio: *mut BIO,
    mut in_0: *const libc::c_char,
) -> libc::c_int {
    if bio.is_null() || ((*bio).method).is_null()
        || ((*(*bio).method).bwrite).is_none() && ((*(*bio).method).bputs).is_none()
    {
        ERR_put_error(
            17 as libc::c_int,
            0 as libc::c_int,
            115 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                as *const libc::c_char,
            405 as libc::c_int as libc::c_uint,
        );
        return -(2 as libc::c_int);
    }
    let mut cb: BIO_callback_fn_ex = get_callback(bio);
    if cb.is_some() {
        let mut callback_ret: libc::c_long = cb
            .expect(
                "non-null function pointer",
            )(
            bio,
            0x4 as libc::c_int,
            in_0,
            0 as libc::c_int as size_t,
            0 as libc::c_int,
            0 as libc::c_long,
            1 as libc::c_long as libc::c_int,
            0 as *mut size_t,
        );
        if callback_ret <= 0 as libc::c_int as libc::c_long {
            if callback_ret
                >= (-(2147483647 as libc::c_int) - 1 as libc::c_int) as libc::c_long
            {
                return callback_ret as libc::c_int;
            }
            return -(2147483647 as libc::c_int) - 1 as libc::c_int;
        }
    }
    if (*bio).init == 0 {
        ERR_put_error(
            17 as libc::c_int,
            0 as libc::c_int,
            114 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                as *const libc::c_char,
            421 as libc::c_int as libc::c_uint,
        );
        return -(2 as libc::c_int);
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    if ((*(*bio).method).bputs).is_some() {
        ret = ((*(*bio).method).bputs).expect("non-null function pointer")(bio, in_0);
    } else {
        let len: size_t = strlen(in_0);
        if len > 2147483647 as libc::c_int as size_t {
            ERR_put_error(
                17 as libc::c_int,
                0 as libc::c_int,
                5 as libc::c_int | 64 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                    as *const libc::c_char,
                432 as libc::c_int as libc::c_uint,
            );
            return -(1 as libc::c_int);
        }
        ret = ((*(*bio).method).bwrite)
            .expect("non-null function pointer")(bio, in_0, len as libc::c_int);
    }
    return handle_callback_return(
        bio,
        0x4 as libc::c_int,
        in_0 as *const libc::c_void,
        0 as libc::c_int,
        ret,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_flush(mut bio: *mut BIO) -> libc::c_int {
    return BIO_ctrl(
        bio,
        11 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        0 as *mut libc::c_void,
    ) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_ctrl(
    mut bio: *mut BIO,
    mut cmd: libc::c_int,
    mut larg: libc::c_long,
    mut parg: *mut libc::c_void,
) -> libc::c_long {
    if bio.is_null() {
        return 0 as libc::c_int as libc::c_long;
    }
    if ((*bio).method).is_null() || ((*(*bio).method).ctrl).is_none() {
        ERR_put_error(
            17 as libc::c_int,
            0 as libc::c_int,
            115 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                as *const libc::c_char,
            451 as libc::c_int as libc::c_uint,
        );
        return -(2 as libc::c_int) as libc::c_long;
    }
    let mut ret: libc::c_long = 0 as libc::c_int as libc::c_long;
    let mut cb: BIO_callback_fn_ex = get_callback(bio);
    if cb.is_some() {
        ret = cb
            .expect(
                "non-null function pointer",
            )(
            bio,
            0x6 as libc::c_int,
            parg as *const libc::c_char,
            0 as libc::c_int as size_t,
            cmd,
            larg,
            1 as libc::c_long as libc::c_int,
            0 as *mut size_t,
        );
        if ret <= 0 as libc::c_int as libc::c_long {
            return ret;
        }
    }
    ret = ((*(*bio).method).ctrl)
        .expect("non-null function pointer")(bio, cmd, larg, parg);
    cb = get_callback(bio);
    if cb.is_some() {
        ret = cb
            .expect(
                "non-null function pointer",
            )(
            bio,
            0x6 as libc::c_int | 0x80 as libc::c_int,
            parg as *const libc::c_char,
            0 as libc::c_int as size_t,
            cmd,
            larg,
            ret as libc::c_int,
            0 as *mut size_t,
        );
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_ptr_ctrl(
    mut b: *mut BIO,
    mut cmd: libc::c_int,
    mut larg: libc::c_long,
) -> *mut libc::c_char {
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    if BIO_ctrl(b, cmd, larg, &mut p as *mut *mut libc::c_char as *mut libc::c_void)
        <= 0 as libc::c_int as libc::c_long
    {
        return 0 as *mut libc::c_char;
    }
    return p;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_int_ctrl(
    mut b: *mut BIO,
    mut cmd: libc::c_int,
    mut larg: libc::c_long,
    mut iarg: libc::c_int,
) -> libc::c_long {
    let mut i: libc::c_int = iarg;
    return BIO_ctrl(b, cmd, larg, &mut i as *mut libc::c_int as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_reset(mut bio: *mut BIO) -> libc::c_int {
    return BIO_ctrl(
        bio,
        1 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        0 as *mut libc::c_void,
    ) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_eof(mut bio: *mut BIO) -> libc::c_int {
    return BIO_ctrl(
        bio,
        2 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        0 as *mut libc::c_void,
    ) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_set_flags(mut bio: *mut BIO, mut flags: libc::c_int) {
    (*bio).flags |= flags;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_test_flags(
    mut bio: *const BIO,
    mut flags: libc::c_int,
) -> libc::c_int {
    return (*bio).flags & flags;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_should_read(mut bio: *const BIO) -> libc::c_int {
    return BIO_test_flags(bio, 0x1 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_should_write(mut bio: *const BIO) -> libc::c_int {
    return BIO_test_flags(bio, 0x2 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_should_retry(mut bio: *const BIO) -> libc::c_int {
    return BIO_test_flags(bio, 0x8 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_should_io_special(mut bio: *const BIO) -> libc::c_int {
    return BIO_test_flags(bio, 0x4 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_get_retry_reason(mut bio: *const BIO) -> libc::c_int {
    return (*bio).retry_reason;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_set_retry_reason(
    mut bio: *mut BIO,
    mut reason: libc::c_int,
) {
    (*bio).retry_reason = reason;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_clear_flags(mut bio: *mut BIO, mut flags: libc::c_int) {
    (*bio).flags &= !flags;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_set_retry_read(mut bio: *mut BIO) {
    (*bio).flags |= 0x1 as libc::c_int | 0x8 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_set_retry_write(mut bio: *mut BIO) {
    (*bio).flags |= 0x2 as libc::c_int | 0x8 as libc::c_int;
}
static mut kRetryFlags: libc::c_int = 0x1 as libc::c_int | 0x2 as libc::c_int
    | 0x4 as libc::c_int | 0x8 as libc::c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_get_retry_flags(mut bio: *mut BIO) -> libc::c_int {
    return (*bio).flags & kRetryFlags;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_clear_retry_flags(mut bio: *mut BIO) {
    (*bio).flags &= !kRetryFlags;
    (*bio).retry_reason = 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_method_type(mut bio: *const BIO) -> libc::c_int {
    return (*(*bio).method).type_0;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_method_name(mut bio: *const BIO) -> *const libc::c_char {
    return (*(*bio).method).name;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_copy_next_retry(mut bio: *mut BIO) {
    BIO_clear_retry_flags(bio);
    BIO_set_flags(bio, BIO_get_retry_flags((*bio).next_bio));
    (*bio).retry_reason = (*(*bio).next_bio).retry_reason;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_callback_ctrl(
    mut bio: *mut BIO,
    mut cmd: libc::c_int,
    mut fp: bio_info_cb,
) -> libc::c_long {
    if bio.is_null() {
        return 0 as libc::c_int as libc::c_long;
    }
    if ((*bio).method).is_null() || ((*(*bio).method).callback_ctrl).is_none() {
        ERR_put_error(
            17 as libc::c_int,
            0 as libc::c_int,
            115 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                as *const libc::c_char,
            567 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int as libc::c_long;
    }
    return ((*(*bio).method).callback_ctrl)
        .expect("non-null function pointer")(bio, cmd, fp);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_pending(mut bio: *const BIO) -> size_t {
    let r: libc::c_long = BIO_ctrl(
        bio as *mut BIO,
        10 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        0 as *mut libc::c_void,
    );
    if r >= 0 as libc::c_int as libc::c_long {} else {
        __assert_fail(
            b"r >= 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                as *const libc::c_char,
            576 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 32],
                &[libc::c_char; 32],
            >(b"size_t BIO_pending(const BIO *)\0"))
                .as_ptr(),
        );
    }
    'c_7735: {
        if r >= 0 as libc::c_int as libc::c_long {} else {
            __assert_fail(
                b"r >= 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                    as *const libc::c_char,
                576 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 32],
                    &[libc::c_char; 32],
                >(b"size_t BIO_pending(const BIO *)\0"))
                    .as_ptr(),
            );
        }
    };
    if r < 0 as libc::c_int as libc::c_long {
        return 0 as libc::c_int as size_t;
    }
    return r as size_t;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_ctrl_pending(mut bio: *const BIO) -> size_t {
    return BIO_pending(bio);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_wpending(mut bio: *const BIO) -> size_t {
    let r: libc::c_long = BIO_ctrl(
        bio as *mut BIO,
        13 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        0 as *mut libc::c_void,
    );
    if r >= 0 as libc::c_int as libc::c_long {} else {
        __assert_fail(
            b"r >= 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                as *const libc::c_char,
            590 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 33],
                &[libc::c_char; 33],
            >(b"size_t BIO_wpending(const BIO *)\0"))
                .as_ptr(),
        );
    }
    'c_7818: {
        if r >= 0 as libc::c_int as libc::c_long {} else {
            __assert_fail(
                b"r >= 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                    as *const libc::c_char,
                590 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 33],
                    &[libc::c_char; 33],
                >(b"size_t BIO_wpending(const BIO *)\0"))
                    .as_ptr(),
            );
        }
    };
    if r < 0 as libc::c_int as libc::c_long {
        return 0 as libc::c_int as size_t;
    }
    return r as size_t;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_set_close(
    mut bio: *mut BIO,
    mut close_flag: libc::c_int,
) -> libc::c_int {
    return BIO_ctrl(
        bio,
        9 as libc::c_int,
        close_flag as libc::c_long,
        0 as *mut libc::c_void,
    ) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_get_close(mut bio: *mut BIO) -> libc::c_int {
    return BIO_ctrl(
        bio,
        8 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        0 as *mut libc::c_void,
    ) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_number_read(mut bio: *const BIO) -> uint64_t {
    return (*bio).num_read;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_number_written(mut bio: *const BIO) -> uint64_t {
    return (*bio).num_write;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_push(
    mut bio: *mut BIO,
    mut appended_bio: *mut BIO,
) -> *mut BIO {
    let mut last_bio: *mut BIO = 0 as *mut BIO;
    if bio.is_null() {
        return bio;
    }
    last_bio = bio;
    while !((*last_bio).next_bio).is_null() {
        last_bio = (*last_bio).next_bio;
    }
    (*last_bio).next_bio = appended_bio;
    return bio;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_pop(mut bio: *mut BIO) -> *mut BIO {
    let mut ret: *mut BIO = 0 as *mut BIO;
    if bio.is_null() {
        return 0 as *mut BIO;
    }
    ret = (*bio).next_bio;
    (*bio).next_bio = 0 as *mut BIO;
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_next(mut bio: *mut BIO) -> *mut BIO {
    if bio.is_null() {
        return 0 as *mut BIO;
    }
    return (*bio).next_bio;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_find_type(
    mut bio: *mut BIO,
    mut type_0: libc::c_int,
) -> *mut BIO {
    let mut method_type: libc::c_int = 0;
    let mut mask: libc::c_int = 0;
    if bio.is_null() {
        return 0 as *mut BIO;
    }
    mask = type_0 & 0xff as libc::c_int;
    loop {
        if !((*bio).method).is_null() {
            method_type = (*(*bio).method).type_0;
            if mask == 0 {
                if method_type & type_0 != 0 {
                    return bio;
                }
            } else if method_type == type_0 {
                return bio
            }
        }
        bio = (*bio).next_bio;
        if bio.is_null() {
            break;
        }
    }
    return 0 as *mut BIO;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_indent(
    mut bio: *mut BIO,
    mut indent: libc::c_uint,
    mut max_indent: libc::c_uint,
) -> libc::c_int {
    if indent > max_indent {
        indent = max_indent;
    }
    loop {
        let fresh0 = indent;
        indent = indent.wrapping_sub(1);
        if !(fresh0 != 0) {
            break;
        }
        if BIO_puts(bio, b" \0" as *const u8 as *const libc::c_char) != 1 as libc::c_int
        {
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn print_bio(
    mut str: *const libc::c_char,
    mut len: size_t,
    mut bio: *mut libc::c_void,
) -> libc::c_int {
    return BIO_write_all(bio as *mut BIO, str as *const libc::c_void, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ERR_print_errors(mut bio: *mut BIO) {
    ERR_print_errors_cb(
        Some(
            print_bio
                as unsafe extern "C" fn(
                    *const libc::c_char,
                    size_t,
                    *mut libc::c_void,
                ) -> libc::c_int,
        ),
        bio as *mut libc::c_void,
    );
}
unsafe extern "C" fn bio_read_all(
    mut bio: *mut BIO,
    mut out: *mut *mut uint8_t,
    mut out_len: *mut size_t,
    mut prefix: *const uint8_t,
    mut prefix_len: size_t,
    mut max_len: size_t,
) -> libc::c_int {
    static mut kChunkSize: size_t = 4096 as libc::c_int as size_t;
    let mut len: size_t = prefix_len.wrapping_add(kChunkSize);
    if len > max_len {
        len = max_len;
    }
    if len < prefix_len {
        return 0 as libc::c_int;
    }
    *out = OPENSSL_malloc(len) as *mut uint8_t;
    if (*out).is_null() {
        return 0 as libc::c_int;
    }
    OPENSSL_memcpy(*out as *mut libc::c_void, prefix as *const libc::c_void, prefix_len);
    let mut done: size_t = prefix_len;
    loop {
        if done == len {
            OPENSSL_free(*out as *mut libc::c_void);
            return 0 as libc::c_int;
        }
        let mut todo: size_t = len.wrapping_sub(done);
        if todo > 2147483647 as libc::c_int as size_t {
            todo = 2147483647 as libc::c_int as size_t;
        }
        let n: libc::c_int = BIO_read(
            bio,
            (*out).offset(done as isize) as *mut libc::c_void,
            todo as libc::c_int,
        );
        if n == 0 as libc::c_int {
            *out_len = done;
            return 1 as libc::c_int;
        } else if n == -(1 as libc::c_int) {
            OPENSSL_free(*out as *mut libc::c_void);
            return 0 as libc::c_int;
        }
        done = done.wrapping_add(n as size_t);
        if len < max_len
            && len.wrapping_sub(done) < kChunkSize / 2 as libc::c_int as size_t
        {
            len = len.wrapping_add(kChunkSize);
            if len < kChunkSize || len > max_len {
                len = max_len;
            }
            let mut new_buf: *mut uint8_t = OPENSSL_realloc(
                *out as *mut libc::c_void,
                len,
            ) as *mut uint8_t;
            if new_buf.is_null() {
                OPENSSL_free(*out as *mut libc::c_void);
                return 0 as libc::c_int;
            }
            *out = new_buf;
        }
    };
}
unsafe extern "C" fn bio_read_full(
    mut bio: *mut BIO,
    mut out: *mut uint8_t,
    mut out_eof_on_first_read: *mut libc::c_int,
    mut len: size_t,
) -> libc::c_int {
    let mut first_read: libc::c_int = 1 as libc::c_int;
    while len > 0 as libc::c_int as size_t {
        let mut todo: libc::c_int = if len <= 2147483647 as libc::c_int as size_t {
            len as libc::c_int
        } else {
            2147483647 as libc::c_int
        };
        let mut ret: libc::c_int = BIO_read(bio, out as *mut libc::c_void, todo);
        if ret <= 0 as libc::c_int {
            if !out_eof_on_first_read.is_null() {
                *out_eof_on_first_read = (first_read != 0 && ret == 0 as libc::c_int)
                    as libc::c_int;
            }
            return 0 as libc::c_int;
        }
        out = out.offset(ret as isize);
        len = len.wrapping_sub(ret as size_t);
        first_read = 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_read_asn1(
    mut bio: *mut BIO,
    mut out: *mut *mut uint8_t,
    mut out_len: *mut size_t,
    mut max_len: size_t,
) -> libc::c_int {
    let mut header: [uint8_t; 6] = [0; 6];
    static mut kInitialHeaderLen: size_t = 2 as libc::c_int as size_t;
    let mut eof_on_first_read: libc::c_int = 0;
    if bio_read_full(bio, header.as_mut_ptr(), &mut eof_on_first_read, kInitialHeaderLen)
        == 0
    {
        if eof_on_first_read != 0 {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                123 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                    as *const libc::c_char,
                798 as libc::c_int as libc::c_uint,
            );
        } else {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                162 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                    as *const libc::c_char,
                800 as libc::c_int as libc::c_uint,
            );
        }
        return 0 as libc::c_int;
    }
    let tag: uint8_t = header[0 as libc::c_int as usize];
    let length_byte: uint8_t = header[1 as libc::c_int as usize];
    if tag as libc::c_int & 0x1f as libc::c_int == 0x1f as libc::c_int {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                as *const libc::c_char,
            810 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut len: size_t = 0;
    let mut header_len: size_t = 0;
    if length_byte as libc::c_int & 0x80 as libc::c_int == 0 as libc::c_int {
        len = length_byte as size_t;
        header_len = kInitialHeaderLen;
    } else {
        let num_bytes: size_t = (length_byte as libc::c_int & 0x7f as libc::c_int)
            as size_t;
        if tag as libc::c_int & 0x20 as libc::c_int != 0 as libc::c_int
            && num_bytes == 0 as libc::c_int as size_t
        {
            if bio_read_all(
                bio,
                out,
                out_len,
                header.as_mut_ptr(),
                kInitialHeaderLen,
                max_len,
            ) == 0
            {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    162 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                        as *const libc::c_char,
                    826 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            return 1 as libc::c_int;
        }
        if num_bytes == 0 as libc::c_int as size_t
            || num_bytes > 4 as libc::c_int as size_t
        {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                109 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                    as *const libc::c_char,
                833 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        if bio_read_full(
            bio,
            header.as_mut_ptr().offset(kInitialHeaderLen as isize),
            0 as *mut libc::c_int,
            num_bytes,
        ) == 0
        {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                162 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                    as *const libc::c_char,
                838 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        header_len = kInitialHeaderLen.wrapping_add(num_bytes);
        let mut len32: uint32_t = 0 as libc::c_int as uint32_t;
        let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
        while (i as size_t) < num_bytes {
            len32 <<= 8 as libc::c_int;
            len32
                |= header[kInitialHeaderLen.wrapping_add(i as size_t) as usize]
                    as uint32_t;
            i = i.wrapping_add(1);
            i;
        }
        if len32 < 128 as libc::c_int as uint32_t {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                109 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                    as *const libc::c_char,
                851 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        if len32
            >> num_bytes.wrapping_sub(1 as libc::c_int as size_t)
                * 8 as libc::c_int as size_t == 0 as libc::c_int as uint32_t
        {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                109 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                    as *const libc::c_char,
                857 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        len = len32 as size_t;
    }
    if len.wrapping_add(header_len) < len || len.wrapping_add(header_len) > max_len
        || len > 2147483647 as libc::c_int as size_t
    {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            177 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                as *const libc::c_char,
            867 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    len = len.wrapping_add(header_len);
    *out_len = len;
    *out = OPENSSL_malloc(len) as *mut uint8_t;
    if (*out).is_null() {
        return 0 as libc::c_int;
    }
    OPENSSL_memcpy(
        *out as *mut libc::c_void,
        header.as_mut_ptr() as *const libc::c_void,
        header_len,
    );
    if bio_read_full(
        bio,
        (*out).offset(header_len as isize),
        0 as *mut libc::c_int,
        len.wrapping_sub(header_len),
    ) == 0
    {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            162 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio.c\0" as *const u8
                as *const libc::c_char,
            879 as libc::c_int as libc::c_uint,
        );
        OPENSSL_free(*out as *mut libc::c_void);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_set_retry_special(mut bio: *mut BIO) {
    (*bio).flags |= 0x1 as libc::c_int | 0x4 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_set_write_buffer_size(
    mut bio: *mut BIO,
    mut buffer_size: libc::c_int,
) -> libc::c_int {
    return 0 as libc::c_int;
}
static mut g_index_lock: CRYPTO_STATIC_MUTEX = {
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
static mut g_index: libc::c_int = 128 as libc::c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_get_new_index() -> libc::c_int {
    CRYPTO_STATIC_MUTEX_lock_write(&mut g_index_lock);
    let mut ret: libc::c_int = if g_index > 255 as libc::c_int {
        -(1 as libc::c_int)
    } else {
        let fresh1 = g_index;
        g_index = g_index + 1;
        fresh1
    };
    CRYPTO_STATIC_MUTEX_unlock_write(&mut g_index_lock);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_meth_new(
    mut type_0: libc::c_int,
    mut name: *const libc::c_char,
) -> *mut BIO_METHOD {
    let mut method: *mut BIO_METHOD = OPENSSL_zalloc(
        ::core::mem::size_of::<BIO_METHOD>() as libc::c_ulong,
    ) as *mut BIO_METHOD;
    if method.is_null() {
        return 0 as *mut BIO_METHOD;
    }
    (*method).type_0 = type_0;
    (*method).name = name;
    return method;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_meth_free(mut method: *mut BIO_METHOD) {
    OPENSSL_free(method as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_meth_set_create(
    mut method: *mut BIO_METHOD,
    mut create: Option::<unsafe extern "C" fn(*mut BIO) -> libc::c_int>,
) -> libc::c_int {
    (*method).create = create;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_meth_get_create(
    mut method: *const BIO_METHOD,
) -> Option::<unsafe extern "C" fn(*mut BIO) -> libc::c_int> {
    return (*method).create;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_meth_set_destroy(
    mut method: *mut BIO_METHOD,
    mut destroy: Option::<unsafe extern "C" fn(*mut BIO) -> libc::c_int>,
) -> libc::c_int {
    (*method).destroy = destroy;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_meth_get_destroy(
    mut method: *const BIO_METHOD,
) -> Option::<unsafe extern "C" fn(*mut BIO) -> libc::c_int> {
    return (*method).destroy;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_meth_set_write(
    mut method: *mut BIO_METHOD,
    mut write: Option::<
        unsafe extern "C" fn(*mut BIO, *const libc::c_char, libc::c_int) -> libc::c_int,
    >,
) -> libc::c_int {
    (*method).bwrite = write;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_meth_set_read(
    mut method: *mut BIO_METHOD,
    mut read: Option::<
        unsafe extern "C" fn(*mut BIO, *mut libc::c_char, libc::c_int) -> libc::c_int,
    >,
) -> libc::c_int {
    (*method).bread = read;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_meth_set_gets(
    mut method: *mut BIO_METHOD,
    mut gets: Option::<
        unsafe extern "C" fn(*mut BIO, *mut libc::c_char, libc::c_int) -> libc::c_int,
    >,
) -> libc::c_int {
    (*method).bgets = gets;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_meth_get_gets(
    mut method: *const BIO_METHOD,
) -> Option::<
    unsafe extern "C" fn(*mut BIO, *mut libc::c_char, libc::c_int) -> libc::c_int,
> {
    return (*method).bgets;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_meth_set_ctrl(
    mut method: *mut BIO_METHOD,
    mut ctrl: Option::<
        unsafe extern "C" fn(
            *mut BIO,
            libc::c_int,
            libc::c_long,
            *mut libc::c_void,
        ) -> libc::c_long,
    >,
) -> libc::c_int {
    (*method).ctrl = ctrl;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_meth_get_ctrl(
    mut method: *const BIO_METHOD,
) -> Option::<
    unsafe extern "C" fn(
        *mut BIO,
        libc::c_int,
        libc::c_long,
        *mut libc::c_void,
    ) -> libc::c_long,
> {
    return (*method).ctrl;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_meth_set_callback_ctrl(
    mut method: *mut BIO_METHOD,
    mut callback_ctrl: Option::<
        unsafe extern "C" fn(*mut BIO, libc::c_int, bio_info_cb) -> libc::c_long,
    >,
) -> libc::c_int {
    (*method).callback_ctrl = callback_ctrl;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_meth_get_callback_ctrl(
    mut method: *const BIO_METHOD,
) -> Option::<unsafe extern "C" fn(*mut BIO, libc::c_int, bio_info_cb) -> libc::c_long> {
    return (*method).callback_ctrl;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_set_data(mut bio: *mut BIO, mut ptr: *mut libc::c_void) {
    (*bio).ptr = ptr;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_get_data(mut bio: *mut BIO) -> *mut libc::c_void {
    return (*bio).ptr;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_set_init(mut bio: *mut BIO, mut init: libc::c_int) {
    (*bio).init = init;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_get_init(mut bio: *mut BIO) -> libc::c_int {
    return (*bio).init;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_set_shutdown(mut bio: *mut BIO, mut shutdown: libc::c_int) {
    (*bio).shutdown = shutdown;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_get_shutdown(mut bio: *mut BIO) -> libc::c_int {
    return (*bio).shutdown;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_meth_set_puts(
    mut method: *mut BIO_METHOD,
    mut puts: Option::<
        unsafe extern "C" fn(*mut BIO, *const libc::c_char) -> libc::c_int,
    >,
) -> libc::c_int {
    (*method).bputs = puts;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_meth_get_puts(
    mut method: *const BIO_METHOD,
) -> Option::<unsafe extern "C" fn(*mut BIO, *const libc::c_char) -> libc::c_int> {
    return (*method).bputs;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_set_callback_ex(
    mut bio: *mut BIO,
    mut callback: BIO_callback_fn_ex,
) {
    (*bio).callback_ex = callback;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_set_callback(
    mut bio: *mut BIO,
    mut callback: BIO_callback_fn,
) {
    (*bio).callback = callback;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_set_callback_arg(
    mut bio: *mut BIO,
    mut arg: *mut libc::c_char,
) {
    (*bio).cb_arg = arg;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_get_callback_arg(mut bio: *const BIO) -> *mut libc::c_char {
    return (*bio).cb_arg;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_get_ex_new_index(
    mut argl: libc::c_long,
    mut argp: *mut libc::c_void,
    mut unused: *mut CRYPTO_EX_unused,
    mut dup_unused: Option::<CRYPTO_EX_dup>,
    mut free_func: Option::<CRYPTO_EX_free>,
) -> libc::c_int {
    let mut index: libc::c_int = 0;
    if CRYPTO_get_ex_new_index(&mut g_ex_data_class, &mut index, argl, argp, free_func)
        == 0
    {
        return -(1 as libc::c_int);
    }
    return index;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_set_ex_data(
    mut bio: *mut BIO,
    mut idx: libc::c_int,
    mut data: *mut libc::c_void,
) -> libc::c_int {
    return CRYPTO_set_ex_data(&mut (*bio).ex_data, idx, data);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_get_ex_data(
    mut bio: *const BIO,
    mut idx: libc::c_int,
) -> *mut libc::c_void {
    return CRYPTO_get_ex_data(&(*bio).ex_data, idx);
}
