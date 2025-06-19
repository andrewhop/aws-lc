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
    fn RAND_bytes(buf: *mut uint8_t, len: size_t) -> libc::c_int;
    fn RAND_pseudo_bytes(buf: *mut uint8_t, len: size_t) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type uint8_t = __uint8_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rand_meth_st {
    pub seed: Option::<unsafe extern "C" fn(*const libc::c_void, libc::c_int) -> ()>,
    pub bytes: Option::<unsafe extern "C" fn(*mut uint8_t, size_t) -> libc::c_int>,
    pub cleanup: Option::<unsafe extern "C" fn() -> ()>,
    pub add: Option::<
        unsafe extern "C" fn(*const libc::c_void, libc::c_int, libc::c_double) -> (),
    >,
    pub pseudorand: Option::<unsafe extern "C" fn(*mut uint8_t, size_t) -> libc::c_int>,
    pub status: Option::<unsafe extern "C" fn() -> libc::c_int>,
}
pub type RAND_METHOD = rand_meth_st;
#[no_mangle]
pub unsafe extern "C" fn RAND_seed(mut buf: *const libc::c_void, mut num: libc::c_int) {
    let mut unused: uint8_t = 0;
    RAND_bytes(&mut unused, ::core::mem::size_of::<uint8_t>() as libc::c_ulong);
}
#[no_mangle]
pub unsafe extern "C" fn RAND_load_file(
    mut path: *const libc::c_char,
    mut num: libc::c_long,
) -> libc::c_int {
    if num < 0 as libc::c_int as libc::c_long {
        return 1 as libc::c_int
    } else if num <= 2147483647 as libc::c_int as libc::c_long {
        return num as libc::c_int
    } else {
        return 2147483647 as libc::c_int
    };
}
#[no_mangle]
pub unsafe extern "C" fn RAND_write_file(mut file: *const libc::c_char) -> libc::c_int {
    return -(1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn RAND_file_name(
    mut buf: *mut libc::c_char,
    mut num: size_t,
) -> *const libc::c_char {
    return 0 as *const libc::c_char;
}
#[no_mangle]
pub unsafe extern "C" fn RAND_add(
    mut buf: *const libc::c_void,
    mut num: libc::c_int,
    mut entropy: libc::c_double,
) {}
#[no_mangle]
pub unsafe extern "C" fn RAND_egd(mut path: *const libc::c_char) -> libc::c_int {
    return 255 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RAND_egd_bytes(
    mut path: *const libc::c_char,
    mut bytes: libc::c_int,
) -> libc::c_int {
    return bytes;
}
#[no_mangle]
pub unsafe extern "C" fn RAND_poll() -> libc::c_int {
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RAND_status() -> libc::c_int {
    return 1 as libc::c_int;
}
static mut kSSLeayMethod: rand_meth_st = unsafe {
    {
        let mut init = rand_meth_st {
            seed: Some(
                RAND_seed as unsafe extern "C" fn(*const libc::c_void, libc::c_int) -> (),
            ),
            bytes: Some(
                RAND_bytes as unsafe extern "C" fn(*mut uint8_t, size_t) -> libc::c_int,
            ),
            cleanup: Some(RAND_cleanup as unsafe extern "C" fn() -> ()),
            add: Some(
                RAND_add
                    as unsafe extern "C" fn(
                        *const libc::c_void,
                        libc::c_int,
                        libc::c_double,
                    ) -> (),
            ),
            pseudorand: Some(
                RAND_pseudo_bytes
                    as unsafe extern "C" fn(*mut uint8_t, size_t) -> libc::c_int,
            ),
            status: Some(RAND_status as unsafe extern "C" fn() -> libc::c_int),
        };
        init
    }
};
#[no_mangle]
pub unsafe extern "C" fn RAND_SSLeay() -> *mut RAND_METHOD {
    return &kSSLeayMethod as *const rand_meth_st as *mut RAND_METHOD;
}
#[no_mangle]
pub unsafe extern "C" fn RAND_OpenSSL() -> *mut RAND_METHOD {
    return RAND_SSLeay();
}
#[no_mangle]
pub unsafe extern "C" fn RAND_get_rand_method() -> *const RAND_METHOD {
    return RAND_SSLeay();
}
#[no_mangle]
pub unsafe extern "C" fn RAND_set_rand_method(
    mut method: *const RAND_METHOD,
) -> libc::c_int {
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RAND_keep_random_devices_open(mut a: libc::c_int) {}
#[no_mangle]
pub unsafe extern "C" fn RAND_cleanup() {}
