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
    pub type CRYPTO_dynlock_value;
}
pub type CRYPTO_THREADID = libc::c_int;
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_num_locks() -> libc::c_int {
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_set_locking_callback(
    mut func: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            libc::c_int,
            *const libc::c_char,
            libc::c_int,
        ) -> (),
    >,
) {}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_get_locking_callback() -> Option::<
    unsafe extern "C" fn(
        libc::c_int,
        libc::c_int,
        *const libc::c_char,
        libc::c_int,
    ) -> (),
> {
    return None;
}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_set_add_lock_callback(
    mut func: Option::<
        unsafe extern "C" fn(
            *mut libc::c_int,
            libc::c_int,
            libc::c_int,
            *const libc::c_char,
            libc::c_int,
        ) -> libc::c_int,
    >,
) {}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_get_lock_name(
    mut lock_num: libc::c_int,
) -> *const libc::c_char {
    return b"No old-style OpenSSL locks anymore\0" as *const u8 as *const libc::c_char;
}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_THREADID_set_callback(
    mut func: Option::<unsafe extern "C" fn(*mut CRYPTO_THREADID) -> ()>,
) -> libc::c_int {
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_THREADID_set_numeric(
    mut id: *mut CRYPTO_THREADID,
    mut val: libc::c_ulong,
) {}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_THREADID_set_pointer(
    mut id: *mut CRYPTO_THREADID,
    mut ptr: *mut libc::c_void,
) {}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_THREADID_current(mut id: *mut CRYPTO_THREADID) {}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_set_id_callback(
    mut func: Option::<unsafe extern "C" fn() -> libc::c_ulong>,
) {}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_set_dynlock_create_callback(
    mut dyn_create_function: Option::<
        unsafe extern "C" fn(
            *const libc::c_char,
            libc::c_int,
        ) -> *mut CRYPTO_dynlock_value,
    >,
) {}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_set_dynlock_lock_callback(
    mut dyn_lock_function: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *mut CRYPTO_dynlock_value,
            *const libc::c_char,
            libc::c_int,
        ) -> (),
    >,
) {}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_set_dynlock_destroy_callback(
    mut dyn_destroy_function: Option::<
        unsafe extern "C" fn(
            *mut CRYPTO_dynlock_value,
            *const libc::c_char,
            libc::c_int,
        ) -> (),
    >,
) {}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_get_dynlock_create_callback() -> Option::<
    unsafe extern "C" fn(*const libc::c_char, libc::c_int) -> *mut CRYPTO_dynlock_value,
> {
    return None;
}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_get_dynlock_lock_callback() -> Option::<
    unsafe extern "C" fn(
        libc::c_int,
        *mut CRYPTO_dynlock_value,
        *const libc::c_char,
        libc::c_int,
    ) -> (),
> {
    return None;
}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_get_dynlock_destroy_callback() -> Option::<
    unsafe extern "C" fn(
        *mut CRYPTO_dynlock_value,
        *const libc::c_char,
        libc::c_int,
    ) -> (),
> {
    return None;
}
