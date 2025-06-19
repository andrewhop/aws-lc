#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
extern "C" {
    fn abort() -> !;
    fn CRYPTO_STATIC_MUTEX_lock_write(lock: *mut CRYPTO_STATIC_MUTEX);
    fn CRYPTO_STATIC_MUTEX_unlock_write(lock: *mut CRYPTO_STATIC_MUTEX);
}
pub type __uint32_t = libc::c_uint;
pub type uint32_t = __uint32_t;
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
pub type CRYPTO_refcount_t = uint32_t;
pub type C2RustUnnamed = libc::c_uint;
pub const PTHREAD_RWLOCK_DEFAULT_NP: C2RustUnnamed = 0;
pub const PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP: C2RustUnnamed = 2;
pub const PTHREAD_RWLOCK_PREFER_WRITER_NP: C2RustUnnamed = 1;
pub const PTHREAD_RWLOCK_PREFER_READER_NP: C2RustUnnamed = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CRYPTO_STATIC_MUTEX {
    pub lock: pthread_rwlock_t,
}
static mut g_refcount_lock: CRYPTO_STATIC_MUTEX = {
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
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_refcount_inc(mut count: *mut CRYPTO_refcount_t) {
    CRYPTO_STATIC_MUTEX_lock_write(&mut g_refcount_lock);
    if *count < 0xffffffff as libc::c_uint {
        *count = (*count).wrapping_add(1);
        *count;
    }
    CRYPTO_STATIC_MUTEX_unlock_write(&mut g_refcount_lock);
}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_refcount_dec_and_test_zero(
    mut count: *mut CRYPTO_refcount_t,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    CRYPTO_STATIC_MUTEX_lock_write(&mut g_refcount_lock);
    if *count == 0 as libc::c_int as CRYPTO_refcount_t {
        abort();
    }
    if *count < 0xffffffff as libc::c_uint {
        *count = (*count).wrapping_sub(1);
        *count;
    }
    ret = (*count == 0 as libc::c_int as CRYPTO_refcount_t) as libc::c_int;
    CRYPTO_STATIC_MUTEX_unlock_write(&mut g_refcount_lock);
    return ret;
}
