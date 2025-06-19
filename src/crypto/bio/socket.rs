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
    fn BIO_new(method: *const BIO_METHOD) -> *mut BIO;
    fn BIO_set_retry_read(bio: *mut BIO);
    fn BIO_set_retry_write(bio: *mut BIO);
    fn BIO_clear_retry_flags(bio: *mut BIO);
    fn BIO_set_fd(
        bio: *mut BIO,
        fd: libc::c_int,
        close_flag: libc::c_int,
    ) -> libc::c_int;
    fn close(__fd: libc::c_int) -> libc::c_int;
    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    fn bio_clear_socket_error(sock: libc::c_int);
    fn bio_socket_should_retry(return_value: libc::c_int) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __ssize_t = libc::c_long;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type ssize_t = __ssize_t;
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
unsafe extern "C" fn closesocket(mut sock: libc::c_int) -> libc::c_int {
    return close(sock);
}
unsafe extern "C" fn sock_free(mut bio: *mut BIO) -> libc::c_int {
    if (*bio).shutdown != 0 {
        if (*bio).init != 0 {
            closesocket((*bio).num);
        }
        (*bio).init = 0 as libc::c_int;
        (*bio).flags = 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn sock_read(
    mut b: *mut BIO,
    mut out: *mut libc::c_char,
    mut outl: libc::c_int,
) -> libc::c_int {
    if out.is_null() {
        return 0 as libc::c_int;
    }
    bio_clear_socket_error((*b).num);
    let mut ret: libc::c_int = read((*b).num, out as *mut libc::c_void, outl as size_t)
        as libc::c_int;
    BIO_clear_retry_flags(b);
    if ret <= 0 as libc::c_int {
        if bio_socket_should_retry(ret) != 0 {
            BIO_set_retry_read(b);
        }
    }
    return ret;
}
unsafe extern "C" fn sock_write(
    mut b: *mut BIO,
    mut in_0: *const libc::c_char,
    mut inl: libc::c_int,
) -> libc::c_int {
    bio_clear_socket_error((*b).num);
    let mut ret: libc::c_int = write(
        (*b).num,
        in_0 as *const libc::c_void,
        inl as size_t,
    ) as libc::c_int;
    BIO_clear_retry_flags(b);
    if ret <= 0 as libc::c_int {
        if bio_socket_should_retry(ret) != 0 {
            BIO_set_retry_write(b);
        }
    }
    return ret;
}
unsafe extern "C" fn sock_ctrl(
    mut b: *mut BIO,
    mut cmd: libc::c_int,
    mut num: libc::c_long,
    mut ptr: *mut libc::c_void,
) -> libc::c_long {
    let mut ret: libc::c_long = 1 as libc::c_int as libc::c_long;
    let mut ip: *mut libc::c_int = 0 as *mut libc::c_int;
    match cmd {
        104 => {
            sock_free(b);
            (*b).num = *(ptr as *mut libc::c_int);
            (*b).shutdown = num as libc::c_int;
            (*b).init = 1 as libc::c_int;
        }
        105 => {
            if (*b).init != 0 {
                ip = ptr as *mut libc::c_int;
                if !ip.is_null() {
                    *ip = (*b).num;
                }
                ret = (*b).num as libc::c_long;
            } else {
                ret = -(1 as libc::c_int) as libc::c_long;
            }
        }
        8 => {
            ret = (*b).shutdown as libc::c_long;
        }
        9 => {
            (*b).shutdown = num as libc::c_int;
        }
        11 => {
            ret = 1 as libc::c_int as libc::c_long;
        }
        _ => {
            ret = 0 as libc::c_int as libc::c_long;
        }
    }
    return ret;
}
static mut methods_sockp: BIO_METHOD = unsafe {
    {
        let mut init = bio_method_st {
            type_0: 5 as libc::c_int | 0x400 as libc::c_int | 0x100 as libc::c_int,
            name: b"socket\0" as *const u8 as *const libc::c_char,
            bwrite: Some(
                sock_write
                    as unsafe extern "C" fn(
                        *mut BIO,
                        *const libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            bread: Some(
                sock_read
                    as unsafe extern "C" fn(
                        *mut BIO,
                        *mut libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            bputs: None,
            bgets: None,
            ctrl: Some(
                sock_ctrl
                    as unsafe extern "C" fn(
                        *mut BIO,
                        libc::c_int,
                        libc::c_long,
                        *mut libc::c_void,
                    ) -> libc::c_long,
            ),
            create: None,
            destroy: Some(sock_free as unsafe extern "C" fn(*mut BIO) -> libc::c_int),
            callback_ctrl: None,
        };
        init
    }
};
#[no_mangle]
pub unsafe extern "C" fn BIO_s_socket() -> *const BIO_METHOD {
    return &methods_sockp;
}
#[no_mangle]
pub unsafe extern "C" fn BIO_new_socket(
    mut fd: libc::c_int,
    mut close_flag: libc::c_int,
) -> *mut BIO {
    let mut ret: *mut BIO = 0 as *mut BIO;
    ret = BIO_new(BIO_s_socket());
    if ret.is_null() {
        return 0 as *mut BIO;
    }
    BIO_set_fd(ret, fd, close_flag);
    return ret;
}
