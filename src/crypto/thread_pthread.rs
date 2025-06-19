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
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn free(_: *mut libc::c_void);
    fn abort() -> !;
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
    fn pthread_once(
        __once_control: *mut pthread_once_t,
        __init_routine: Option::<unsafe extern "C" fn() -> ()>,
    ) -> libc::c_int;
    fn pthread_mutex_lock(__mutex: *mut pthread_mutex_t) -> libc::c_int;
    fn pthread_mutex_unlock(__mutex: *mut pthread_mutex_t) -> libc::c_int;
    fn pthread_rwlock_init(
        __rwlock: *mut pthread_rwlock_t,
        __attr: *const pthread_rwlockattr_t,
    ) -> libc::c_int;
    fn pthread_rwlock_destroy(__rwlock: *mut pthread_rwlock_t) -> libc::c_int;
    fn pthread_rwlock_rdlock(__rwlock: *mut pthread_rwlock_t) -> libc::c_int;
    fn pthread_rwlock_wrlock(__rwlock: *mut pthread_rwlock_t) -> libc::c_int;
    fn pthread_rwlock_unlock(__rwlock: *mut pthread_rwlock_t) -> libc::c_int;
    fn pthread_key_create(
        __key: *mut pthread_key_t,
        __destr_function: Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>,
    ) -> libc::c_int;
    fn pthread_key_delete(__key: pthread_key_t) -> libc::c_int;
    fn pthread_getspecific(__key: pthread_key_t) -> *mut libc::c_void;
    fn pthread_setspecific(
        __key: pthread_key_t,
        __pointer: *const libc::c_void,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type uint8_t = __uint8_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_internal_list {
    pub __prev: *mut __pthread_internal_list,
    pub __next: *mut __pthread_internal_list,
}
pub type __pthread_list_t = __pthread_internal_list;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_mutex_s {
    pub __lock: libc::c_int,
    pub __count: libc::c_uint,
    pub __owner: libc::c_int,
    pub __nusers: libc::c_uint,
    pub __kind: libc::c_int,
    pub __spins: libc::c_short,
    pub __elision: libc::c_short,
    pub __list: __pthread_list_t,
}
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
pub type pthread_key_t = libc::c_uint;
pub type pthread_once_t = libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_mutex_t {
    pub __data: __pthread_mutex_s,
    pub __size: [libc::c_char; 40],
    pub __align: libc::c_long,
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
pub union pthread_rwlockattr_t {
    pub __size: [libc::c_char; 8],
    pub __align: libc::c_long,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union crypto_mutex_st {
    pub alignment: libc::c_double,
    pub padding: [uint8_t; 56],
}
pub type CRYPTO_MUTEX = crypto_mutex_st;
pub type thread_local_destructor_t = Option::<
    unsafe extern "C" fn(*mut libc::c_void) -> (),
>;
pub const NUM_OPENSSL_THREAD_LOCALS: thread_local_data_t = 5;
pub const PTHREAD_MUTEX_TIMED_NP: C2RustUnnamed = 0;
pub type C2RustUnnamed = libc::c_uint;
pub const PTHREAD_MUTEX_DEFAULT: C2RustUnnamed = 0;
pub const PTHREAD_MUTEX_ERRORCHECK: C2RustUnnamed = 2;
pub const PTHREAD_MUTEX_RECURSIVE: C2RustUnnamed = 1;
pub const PTHREAD_MUTEX_NORMAL: C2RustUnnamed = 0;
pub const PTHREAD_MUTEX_ADAPTIVE_NP: C2RustUnnamed = 3;
pub const PTHREAD_MUTEX_ERRORCHECK_NP: C2RustUnnamed = 2;
pub const PTHREAD_MUTEX_RECURSIVE_NP: C2RustUnnamed = 1;
pub type CRYPTO_once_t = pthread_once_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CRYPTO_STATIC_MUTEX {
    pub lock: pthread_rwlock_t,
}
pub type pthread_rwlock_func_ptr = Option::<
    unsafe extern "C" fn(*mut pthread_rwlock_t) -> libc::c_int,
>;
pub type thread_local_data_t = libc::c_uint;
pub const OPENSSL_THREAD_LOCAL_TEST: thread_local_data_t = 4;
pub const AWSLC_THREAD_LOCAL_FIPS_SERVICE_INDICATOR_STATE: thread_local_data_t = 3;
pub const OPENSSL_THREAD_LOCAL_FIPS_COUNTERS: thread_local_data_t = 2;
pub const OPENSSL_THREAD_LOCAL_RAND: thread_local_data_t = 1;
pub const OPENSSL_THREAD_LOCAL_ERR: thread_local_data_t = 0;
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_MUTEX_init(mut lock: *mut CRYPTO_MUTEX) {
    if pthread_rwlock_init(
        lock as *mut pthread_rwlock_t,
        0 as *const pthread_rwlockattr_t,
    ) != 0 as libc::c_int
    {
        abort();
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_MUTEX_lock_read(mut lock: *mut CRYPTO_MUTEX) {
    if pthread_rwlock_rdlock(lock as *mut pthread_rwlock_t) != 0 as libc::c_int {
        abort();
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_MUTEX_lock_write(mut lock: *mut CRYPTO_MUTEX) {
    if pthread_rwlock_wrlock(lock as *mut pthread_rwlock_t) != 0 as libc::c_int {
        abort();
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_MUTEX_unlock_read(mut lock: *mut CRYPTO_MUTEX) {
    if pthread_rwlock_unlock(lock as *mut pthread_rwlock_t) != 0 as libc::c_int {
        abort();
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_MUTEX_unlock_write(mut lock: *mut CRYPTO_MUTEX) {
    if pthread_rwlock_unlock(lock as *mut pthread_rwlock_t) != 0 as libc::c_int {
        abort();
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_MUTEX_cleanup(mut lock: *mut CRYPTO_MUTEX) {
    pthread_rwlock_destroy(lock as *mut pthread_rwlock_t);
}
unsafe extern "C" fn rwlock_EINVAL_fallback_retry(
    func_ptr: pthread_rwlock_func_ptr,
    mut lock: *mut pthread_rwlock_t,
) -> libc::c_int {
    let mut result: libc::c_int = 22 as libc::c_int;
    return result;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_STATIC_MUTEX_lock_read(
    mut lock: *mut CRYPTO_STATIC_MUTEX,
) {
    let result: libc::c_int = pthread_rwlock_rdlock(&mut (*lock).lock);
    if result != 0 as libc::c_int {
        if result == 22 as libc::c_int
            && 0 as libc::c_int
                == rwlock_EINVAL_fallback_retry(
                    Some(
                        pthread_rwlock_rdlock
                            as unsafe extern "C" fn(*mut pthread_rwlock_t) -> libc::c_int,
                    ),
                    &mut (*lock).lock,
                )
        {
            return;
        }
        abort();
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_STATIC_MUTEX_lock_write(
    mut lock: *mut CRYPTO_STATIC_MUTEX,
) {
    let result: libc::c_int = pthread_rwlock_wrlock(&mut (*lock).lock);
    if result != 0 as libc::c_int {
        if result == 22 as libc::c_int
            && 0 as libc::c_int
                == rwlock_EINVAL_fallback_retry(
                    Some(
                        pthread_rwlock_wrlock
                            as unsafe extern "C" fn(*mut pthread_rwlock_t) -> libc::c_int,
                    ),
                    &mut (*lock).lock,
                )
        {
            return;
        }
        abort();
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_STATIC_MUTEX_unlock_read(
    mut lock: *mut CRYPTO_STATIC_MUTEX,
) {
    if pthread_rwlock_unlock(&mut (*lock).lock) != 0 as libc::c_int {
        abort();
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_STATIC_MUTEX_unlock_write(
    mut lock: *mut CRYPTO_STATIC_MUTEX,
) {
    if pthread_rwlock_unlock(&mut (*lock).lock) != 0 as libc::c_int {
        abort();
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_once(
    mut once: *mut CRYPTO_once_t,
    mut init: Option::<unsafe extern "C" fn() -> ()>,
) {
    if pthread_once(once, init) != 0 as libc::c_int {
        abort();
    }
}
static mut g_destructors_lock: pthread_mutex_t = pthread_mutex_t {
    __data: {
        let mut init = __pthread_mutex_s {
            __lock: 0 as libc::c_int,
            __count: 0 as libc::c_int as libc::c_uint,
            __owner: 0 as libc::c_int,
            __nusers: 0 as libc::c_int as libc::c_uint,
            __kind: PTHREAD_MUTEX_TIMED_NP as libc::c_int,
            __spins: 0 as libc::c_int as libc::c_short,
            __elision: 0 as libc::c_int as libc::c_short,
            __list: {
                let mut init = __pthread_internal_list {
                    __prev: 0 as *const __pthread_internal_list
                        as *mut __pthread_internal_list,
                    __next: 0 as *const __pthread_internal_list
                        as *mut __pthread_internal_list,
                };
                init
            },
        };
        init
    },
};
static mut g_destructors: [thread_local_destructor_t; 5] = [None; 5];
unsafe extern "C" fn thread_local_destructor(mut arg: *mut libc::c_void) {
    if arg.is_null() {
        return;
    }
    let mut destructors: [thread_local_destructor_t; 5] = [None; 5];
    if pthread_mutex_lock(&mut g_destructors_lock) != 0 as libc::c_int {
        return;
    }
    OPENSSL_memcpy(
        destructors.as_mut_ptr() as *mut libc::c_void,
        g_destructors.as_mut_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[thread_local_destructor_t; 5]>() as libc::c_ulong,
    );
    pthread_mutex_unlock(&mut g_destructors_lock);
    let mut i: libc::c_uint = 0;
    let mut pointers: *mut *mut libc::c_void = arg as *mut *mut libc::c_void;
    i = 0 as libc::c_int as libc::c_uint;
    while i < NUM_OPENSSL_THREAD_LOCALS as libc::c_int as libc::c_uint {
        if (destructors[i as usize]).is_some() {
            (destructors[i as usize])
                .expect("non-null function pointer")(*pointers.offset(i as isize));
        }
        i = i.wrapping_add(1);
        i;
    }
    free(pointers as *mut libc::c_void);
}
static mut g_thread_local_init_once: pthread_once_t = 0 as libc::c_int;
static mut g_thread_local_key: pthread_key_t = 0;
static mut g_thread_local_key_created: libc::c_int = 0 as libc::c_int;
unsafe extern "C" fn thread_local_init() {
    g_thread_local_key_created = (pthread_key_create(
        &mut g_thread_local_key,
        Some(thread_local_destructor as unsafe extern "C" fn(*mut libc::c_void) -> ()),
    ) == 0 as libc::c_int) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_get_thread_local(
    mut index: thread_local_data_t,
) -> *mut libc::c_void {
    CRYPTO_once(
        &mut g_thread_local_init_once,
        Some(thread_local_init as unsafe extern "C" fn() -> ()),
    );
    if g_thread_local_key_created == 0 {
        return 0 as *mut libc::c_void;
    }
    let mut pointers: *mut *mut libc::c_void = pthread_getspecific(g_thread_local_key)
        as *mut *mut libc::c_void;
    if pointers.is_null() {
        return 0 as *mut libc::c_void;
    }
    return *pointers.offset(index as isize);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_set_thread_local(
    mut index: thread_local_data_t,
    mut value: *mut libc::c_void,
    mut destructor: thread_local_destructor_t,
) -> libc::c_int {
    CRYPTO_once(
        &mut g_thread_local_init_once,
        Some(thread_local_init as unsafe extern "C" fn() -> ()),
    );
    if g_thread_local_key_created == 0 {
        destructor.expect("non-null function pointer")(value);
        return 0 as libc::c_int;
    }
    let mut pointers: *mut *mut libc::c_void = pthread_getspecific(g_thread_local_key)
        as *mut *mut libc::c_void;
    if pointers.is_null() {
        pointers = malloc(
            (::core::mem::size_of::<*mut libc::c_void>() as libc::c_ulong)
                .wrapping_mul(NUM_OPENSSL_THREAD_LOCALS as libc::c_int as libc::c_ulong),
        ) as *mut *mut libc::c_void;
        if pointers.is_null() {
            destructor.expect("non-null function pointer")(value);
            return 0 as libc::c_int;
        }
        OPENSSL_memset(
            pointers as *mut libc::c_void,
            0 as libc::c_int,
            (::core::mem::size_of::<*mut libc::c_void>() as libc::c_ulong)
                .wrapping_mul(NUM_OPENSSL_THREAD_LOCALS as libc::c_int as libc::c_ulong),
        );
        if pthread_setspecific(g_thread_local_key, pointers as *const libc::c_void)
            != 0 as libc::c_int
        {
            free(pointers as *mut libc::c_void);
            destructor.expect("non-null function pointer")(value);
            return 0 as libc::c_int;
        }
    }
    if pthread_mutex_lock(&mut g_destructors_lock) != 0 as libc::c_int {
        destructor.expect("non-null function pointer")(value);
        return 0 as libc::c_int;
    }
    g_destructors[index as usize] = destructor;
    pthread_mutex_unlock(&mut g_destructors_lock);
    let ref mut fresh0 = *pointers.offset(index as isize);
    *fresh0 = value;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn AWSLC_thread_local_clear() -> libc::c_int {
    if g_thread_local_key_created == 0 {
        return 1 as libc::c_int;
    }
    let mut pointers: *mut libc::c_void = pthread_getspecific(g_thread_local_key);
    thread_local_destructor(pointers);
    if 0 as libc::c_int
        != pthread_setspecific(g_thread_local_key, 0 as *const libc::c_void)
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn AWSLC_thread_local_shutdown() -> libc::c_int {
    if g_thread_local_key_created == 0 {
        return 1 as libc::c_int;
    }
    if 0 as libc::c_int != pthread_key_delete(g_thread_local_key) {
        return 0 as libc::c_int;
    }
    g_thread_local_key_created = 0 as libc::c_int;
    return 1 as libc::c_int;
}
