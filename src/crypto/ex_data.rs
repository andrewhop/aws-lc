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
    pub type stack_st;
    pub type stack_st_void;
    pub type stack_st_CRYPTO_EX_DATA_FUNCS;
    fn abort() -> !;
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_set(
        sk: *mut OPENSSL_STACK,
        i: size_t,
        p: *mut libc::c_void,
    ) -> *mut libc::c_void;
    fn OPENSSL_sk_free(sk: *mut OPENSSL_STACK);
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn OPENSSL_sk_dup(sk: *const OPENSSL_STACK) -> *mut OPENSSL_STACK;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn CRYPTO_STATIC_MUTEX_lock_read(lock: *mut CRYPTO_STATIC_MUTEX);
    fn CRYPTO_STATIC_MUTEX_lock_write(lock: *mut CRYPTO_STATIC_MUTEX);
    fn CRYPTO_STATIC_MUTEX_unlock_read(lock: *mut CRYPTO_STATIC_MUTEX);
    fn CRYPTO_STATIC_MUTEX_unlock_write(lock: *mut CRYPTO_STATIC_MUTEX);
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type uint8_t = __uint8_t;
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
pub type OPENSSL_STACK = stack_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
pub type CRYPTO_EX_free = unsafe extern "C" fn(
    *mut libc::c_void,
    *mut libc::c_void,
    *mut CRYPTO_EX_DATA,
    libc::c_int,
    libc::c_long,
    *mut libc::c_void,
) -> ();
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CRYPTO_STATIC_MUTEX {
    pub lock: pthread_rwlock_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_func_st {
    pub argl: libc::c_long,
    pub argp: *mut libc::c_void,
    pub free_func: Option::<CRYPTO_EX_free>,
}
pub type CRYPTO_EX_DATA_FUNCS = crypto_ex_data_func_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CRYPTO_EX_DATA_CLASS {
    pub lock: CRYPTO_STATIC_MUTEX,
    pub meth: *mut stack_st_CRYPTO_EX_DATA_FUNCS,
    pub num_reserved: uint8_t,
}
#[inline]
unsafe extern "C" fn sk_void_new_null() -> *mut stack_st_void {
    return OPENSSL_sk_new_null() as *mut stack_st_void;
}
#[inline]
unsafe extern "C" fn sk_void_num(mut sk: *const stack_st_void) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_void_value(
    mut sk: *const stack_st_void,
    mut i: size_t,
) -> *mut libc::c_void {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i);
}
#[inline]
unsafe extern "C" fn sk_void_set(
    mut sk: *mut stack_st_void,
    mut i: size_t,
    mut p: *mut libc::c_void,
) -> *mut libc::c_void {
    return OPENSSL_sk_set(sk as *mut OPENSSL_STACK, i, p);
}
#[inline]
unsafe extern "C" fn sk_void_free(mut sk: *mut stack_st_void) {
    OPENSSL_sk_free(sk as *mut OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_void_push(
    mut sk: *mut stack_st_void,
    mut p: *mut libc::c_void,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p);
}
#[inline]
unsafe extern "C" fn sk_CRYPTO_EX_DATA_FUNCS_push(
    mut sk: *mut stack_st_CRYPTO_EX_DATA_FUNCS,
    mut p: *mut CRYPTO_EX_DATA_FUNCS,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_CRYPTO_EX_DATA_FUNCS_free(
    mut sk: *mut stack_st_CRYPTO_EX_DATA_FUNCS,
) {
    OPENSSL_sk_free(sk as *mut OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_CRYPTO_EX_DATA_FUNCS_value(
    mut sk: *const stack_st_CRYPTO_EX_DATA_FUNCS,
    mut i: size_t,
) -> *mut CRYPTO_EX_DATA_FUNCS {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut CRYPTO_EX_DATA_FUNCS;
}
#[inline]
unsafe extern "C" fn sk_CRYPTO_EX_DATA_FUNCS_new_null() -> *mut stack_st_CRYPTO_EX_DATA_FUNCS {
    return OPENSSL_sk_new_null() as *mut stack_st_CRYPTO_EX_DATA_FUNCS;
}
#[inline]
unsafe extern "C" fn sk_CRYPTO_EX_DATA_FUNCS_dup(
    mut sk: *const stack_st_CRYPTO_EX_DATA_FUNCS,
) -> *mut stack_st_CRYPTO_EX_DATA_FUNCS {
    return OPENSSL_sk_dup(sk as *const OPENSSL_STACK)
        as *mut stack_st_CRYPTO_EX_DATA_FUNCS;
}
#[inline]
unsafe extern "C" fn sk_CRYPTO_EX_DATA_FUNCS_num(
    mut sk: *const stack_st_CRYPTO_EX_DATA_FUNCS,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_get_ex_new_index(
    mut ex_data_class: *mut CRYPTO_EX_DATA_CLASS,
    mut out_index: *mut libc::c_int,
    mut argl: libc::c_long,
    mut argp: *mut libc::c_void,
    mut free_func: Option::<CRYPTO_EX_free>,
) -> libc::c_int {
    let mut funcs: *mut CRYPTO_EX_DATA_FUNCS = 0 as *mut CRYPTO_EX_DATA_FUNCS;
    let mut ret: libc::c_int = 0 as libc::c_int;
    funcs = OPENSSL_malloc(
        ::core::mem::size_of::<CRYPTO_EX_DATA_FUNCS>() as libc::c_ulong,
    ) as *mut CRYPTO_EX_DATA_FUNCS;
    if funcs.is_null() {
        return 0 as libc::c_int;
    }
    (*funcs).argl = argl;
    (*funcs).argp = argp;
    (*funcs).free_func = free_func;
    CRYPTO_STATIC_MUTEX_lock_write(&mut (*ex_data_class).lock);
    if ((*ex_data_class).meth).is_null() {
        (*ex_data_class).meth = sk_CRYPTO_EX_DATA_FUNCS_new_null();
    }
    if !((*ex_data_class).meth).is_null() {
        if sk_CRYPTO_EX_DATA_FUNCS_num((*ex_data_class).meth)
            > (2147483647 as libc::c_int - (*ex_data_class).num_reserved as libc::c_int)
                as size_t
        {
            ERR_put_error(
                14 as libc::c_int,
                0 as libc::c_int,
                5 as libc::c_int | 64 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/ex_data.c\0" as *const u8
                    as *const libc::c_char,
                160 as libc::c_int as libc::c_uint,
            );
        } else if !(sk_CRYPTO_EX_DATA_FUNCS_push((*ex_data_class).meth, funcs) == 0) {
            funcs = 0 as *mut CRYPTO_EX_DATA_FUNCS;
            *out_index = sk_CRYPTO_EX_DATA_FUNCS_num((*ex_data_class).meth)
                as libc::c_int - 1 as libc::c_int
                + (*ex_data_class).num_reserved as libc::c_int;
            ret = 1 as libc::c_int;
        }
    }
    CRYPTO_STATIC_MUTEX_unlock_write(&mut (*ex_data_class).lock);
    OPENSSL_free(funcs as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_set_ex_data(
    mut ad: *mut CRYPTO_EX_DATA,
    mut index: libc::c_int,
    mut val: *mut libc::c_void,
) -> libc::c_int {
    if index < 0 as libc::c_int {
        abort();
    }
    if ((*ad).sk).is_null() {
        (*ad).sk = sk_void_new_null();
        if ((*ad).sk).is_null() {
            return 0 as libc::c_int;
        }
    }
    let mut i: size_t = sk_void_num((*ad).sk);
    while i <= index as size_t {
        if sk_void_push((*ad).sk, 0 as *mut libc::c_void) == 0 {
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(1);
    }
    sk_void_set((*ad).sk, index as size_t, val);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_get_ex_data(
    mut ad: *const CRYPTO_EX_DATA,
    mut idx: libc::c_int,
) -> *mut libc::c_void {
    if ((*ad).sk).is_null() || idx < 0 as libc::c_int
        || idx as size_t >= sk_void_num((*ad).sk)
    {
        return 0 as *mut libc::c_void;
    }
    return sk_void_value((*ad).sk, idx as size_t);
}
unsafe extern "C" fn get_func_pointers(
    mut out: *mut *mut stack_st_CRYPTO_EX_DATA_FUNCS,
    mut ex_data_class: *mut CRYPTO_EX_DATA_CLASS,
) -> libc::c_int {
    let mut n: size_t = 0;
    *out = 0 as *mut stack_st_CRYPTO_EX_DATA_FUNCS;
    CRYPTO_STATIC_MUTEX_lock_read(&mut (*ex_data_class).lock);
    n = sk_CRYPTO_EX_DATA_FUNCS_num((*ex_data_class).meth);
    if n > 0 as libc::c_int as size_t {
        *out = sk_CRYPTO_EX_DATA_FUNCS_dup((*ex_data_class).meth);
    }
    CRYPTO_STATIC_MUTEX_unlock_read(&mut (*ex_data_class).lock);
    if n > 0 as libc::c_int as size_t && (*out).is_null() {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_new_ex_data(mut ad: *mut CRYPTO_EX_DATA) {
    (*ad).sk = 0 as *mut stack_st_void;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_free_ex_data(
    mut ex_data_class: *mut CRYPTO_EX_DATA_CLASS,
    mut obj: *mut libc::c_void,
    mut ad: *mut CRYPTO_EX_DATA,
) {
    if ((*ad).sk).is_null() {
        return;
    }
    let mut func_pointers: *mut stack_st_CRYPTO_EX_DATA_FUNCS = 0
        as *mut stack_st_CRYPTO_EX_DATA_FUNCS;
    if get_func_pointers(&mut func_pointers, ex_data_class) == 0 {
        return;
    }
    if sk_CRYPTO_EX_DATA_FUNCS_num(func_pointers)
        <= (2147483647 as libc::c_int - (*ex_data_class).num_reserved as libc::c_int)
            as size_t
    {} else {
        __assert_fail(
            b"sk_CRYPTO_EX_DATA_FUNCS_num(func_pointers) <= (size_t)(INT_MAX - ex_data_class->num_reserved)\0"
                as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ex_data.c\0" as *const u8
                as *const libc::c_char,
            258 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 75],
                &[libc::c_char; 75],
            >(
                b"void CRYPTO_free_ex_data(CRYPTO_EX_DATA_CLASS *, void *, CRYPTO_EX_DATA *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_5634: {
        if sk_CRYPTO_EX_DATA_FUNCS_num(func_pointers)
            <= (2147483647 as libc::c_int - (*ex_data_class).num_reserved as libc::c_int)
                as size_t
        {} else {
            __assert_fail(
                b"sk_CRYPTO_EX_DATA_FUNCS_num(func_pointers) <= (size_t)(INT_MAX - ex_data_class->num_reserved)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/ex_data.c\0" as *const u8
                    as *const libc::c_char,
                258 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 75],
                    &[libc::c_char; 75],
                >(
                    b"void CRYPTO_free_ex_data(CRYPTO_EX_DATA_CLASS *, void *, CRYPTO_EX_DATA *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut i: libc::c_int = 0 as libc::c_int;
    while i < sk_CRYPTO_EX_DATA_FUNCS_num(func_pointers) as libc::c_int {
        let mut func_pointer: *mut CRYPTO_EX_DATA_FUNCS = sk_CRYPTO_EX_DATA_FUNCS_value(
            func_pointers,
            i as size_t,
        );
        if ((*func_pointer).free_func).is_some() {
            let mut ptr: *mut libc::c_void = CRYPTO_get_ex_data(
                ad,
                i + (*ex_data_class).num_reserved as libc::c_int,
            );
            ((*func_pointer).free_func)
                .expect(
                    "non-null function pointer",
                )(
                obj,
                ptr,
                ad,
                i + (*ex_data_class).num_reserved as libc::c_int,
                (*func_pointer).argl,
                (*func_pointer).argp,
            );
        }
        i += 1;
    }
    sk_CRYPTO_EX_DATA_FUNCS_free(func_pointers);
    sk_void_free((*ad).sk);
    (*ad).sk = 0 as *mut stack_st_void;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_cleanup_all_ex_data() {}
