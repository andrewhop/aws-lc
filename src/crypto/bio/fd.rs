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
    fn BIO_new(method: *const BIO_METHOD) -> *mut BIO;
    fn BIO_ctrl(
        bio: *mut BIO,
        cmd: libc::c_int,
        larg: libc::c_long,
        parg: *mut libc::c_void,
    ) -> libc::c_long;
    fn BIO_int_ctrl(
        bp: *mut BIO,
        cmd: libc::c_int,
        larg: libc::c_long,
        iarg: libc::c_int,
    ) -> libc::c_long;
    fn BIO_set_retry_read(bio: *mut BIO);
    fn BIO_set_retry_write(bio: *mut BIO);
    fn BIO_clear_retry_flags(bio: *mut BIO);
    fn lseek(__fd: libc::c_int, __offset: __off_t, __whence: libc::c_int) -> __off_t;
    fn close(__fd: libc::c_int) -> libc::c_int;
    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    fn bio_errno_should_retry(return_value: libc::c_int) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_new_fd(
    mut fd: libc::c_int,
    mut close_flag: libc::c_int,
) -> *mut BIO {
    let mut ret: *mut BIO = BIO_new(BIO_s_fd());
    if ret.is_null() {
        return 0 as *mut BIO;
    }
    BIO_set_fd(ret, fd, close_flag);
    return ret;
}
unsafe extern "C" fn fd_new(mut bio: *mut BIO) -> libc::c_int {
    (*bio).num = -(1 as libc::c_int);
    return 1 as libc::c_int;
}
unsafe extern "C" fn fd_free(mut bio: *mut BIO) -> libc::c_int {
    if (*bio).shutdown != 0 {
        if (*bio).init != 0 {
            close((*bio).num);
        }
        (*bio).init = 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn fd_read(
    mut b: *mut BIO,
    mut out: *mut libc::c_char,
    mut outl: libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    ret = read((*b).num, out as *mut libc::c_void, outl as size_t) as libc::c_int;
    BIO_clear_retry_flags(b);
    if ret <= 0 as libc::c_int {
        if bio_errno_should_retry(ret) != 0 {
            BIO_set_retry_read(b);
        }
    }
    return ret;
}
unsafe extern "C" fn fd_write(
    mut b: *mut BIO,
    mut in_0: *const libc::c_char,
    mut inl: libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = write(
        (*b).num,
        in_0 as *const libc::c_void,
        inl as size_t,
    ) as libc::c_int;
    BIO_clear_retry_flags(b);
    if ret <= 0 as libc::c_int {
        if bio_errno_should_retry(ret) != 0 {
            BIO_set_retry_write(b);
        }
    }
    return ret;
}
unsafe extern "C" fn fd_ctrl(
    mut b: *mut BIO,
    mut cmd: libc::c_int,
    mut num: libc::c_long,
    mut ptr: *mut libc::c_void,
) -> libc::c_long {
    let mut ret: libc::c_long = 1 as libc::c_int as libc::c_long;
    let mut ip: *mut libc::c_int = 0 as *mut libc::c_int;
    let mut current_block_27: u64;
    match cmd {
        1 => {
            num = 0 as libc::c_int as libc::c_long;
            current_block_27 = 11894659824225936647;
        }
        128 => {
            current_block_27 = 11894659824225936647;
        }
        133 | 3 => {
            ret = 0 as libc::c_int as libc::c_long;
            if (*b).init != 0 {
                ret = lseek((*b).num, 0 as libc::c_int as __off_t, 1 as libc::c_int);
            }
            current_block_27 = 16924917904204750491;
        }
        104 => {
            fd_free(b);
            (*b).num = *(ptr as *mut libc::c_int);
            (*b).shutdown = num as libc::c_int;
            (*b).init = 1 as libc::c_int;
            current_block_27 = 16924917904204750491;
        }
        105 => {
            if (*b).init != 0 {
                ip = ptr as *mut libc::c_int;
                if !ip.is_null() {
                    *ip = (*b).num;
                }
                return (*b).num as libc::c_long;
            } else {
                ret = -(1 as libc::c_int) as libc::c_long;
            }
            current_block_27 = 16924917904204750491;
        }
        8 => {
            ret = (*b).shutdown as libc::c_long;
            current_block_27 = 16924917904204750491;
        }
        9 => {
            (*b).shutdown = num as libc::c_int;
            current_block_27 = 16924917904204750491;
        }
        10 | 13 => {
            ret = 0 as libc::c_int as libc::c_long;
            current_block_27 = 16924917904204750491;
        }
        11 => {
            ret = 1 as libc::c_int as libc::c_long;
            current_block_27 = 16924917904204750491;
        }
        _ => {
            ret = 0 as libc::c_int as libc::c_long;
            current_block_27 = 16924917904204750491;
        }
    }
    match current_block_27 {
        11894659824225936647 => {
            ret = 0 as libc::c_int as libc::c_long;
            if (*b).init != 0 {
                ret = lseek((*b).num, num, 0 as libc::c_int);
            }
        }
        _ => {}
    }
    return ret;
}
unsafe extern "C" fn fd_gets(
    mut bp: *mut BIO,
    mut buf: *mut libc::c_char,
    mut size: libc::c_int,
) -> libc::c_int {
    if size <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut ptr: *mut libc::c_char = buf;
    let mut end: *mut libc::c_char = buf
        .offset(size as isize)
        .offset(-(1 as libc::c_int as isize));
    while ptr < end && fd_read(bp, ptr, 1 as libc::c_int) > 0 as libc::c_int {
        let mut c: libc::c_char = *ptr.offset(0 as libc::c_int as isize);
        ptr = ptr.offset(1);
        ptr;
        if c as libc::c_int == '\n' as i32 {
            break;
        }
    }
    *ptr.offset(0 as libc::c_int as isize) = '\0' as i32 as libc::c_char;
    return ptr.offset_from(buf) as libc::c_long as libc::c_int;
}
static mut methods_fdp: BIO_METHOD = unsafe {
    {
        let mut init = bio_method_st {
            type_0: 4 as libc::c_int | 0x400 as libc::c_int | 0x100 as libc::c_int,
            name: b"file descriptor\0" as *const u8 as *const libc::c_char,
            bwrite: Some(
                fd_write
                    as unsafe extern "C" fn(
                        *mut BIO,
                        *const libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            bread: Some(
                fd_read
                    as unsafe extern "C" fn(
                        *mut BIO,
                        *mut libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            bputs: None,
            bgets: Some(
                fd_gets
                    as unsafe extern "C" fn(
                        *mut BIO,
                        *mut libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            ctrl: Some(
                fd_ctrl
                    as unsafe extern "C" fn(
                        *mut BIO,
                        libc::c_int,
                        libc::c_long,
                        *mut libc::c_void,
                    ) -> libc::c_long,
            ),
            create: Some(fd_new as unsafe extern "C" fn(*mut BIO) -> libc::c_int),
            destroy: Some(fd_free as unsafe extern "C" fn(*mut BIO) -> libc::c_int),
            callback_ctrl: None,
        };
        init
    }
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_s_fd() -> *const BIO_METHOD {
    return &methods_fdp;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_set_fd(
    mut bio: *mut BIO,
    mut fd: libc::c_int,
    mut close_flag: libc::c_int,
) -> libc::c_int {
    return BIO_int_ctrl(bio, 104 as libc::c_int, close_flag as libc::c_long, fd)
        as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_get_fd(
    mut bio: *mut BIO,
    mut out_fd: *mut libc::c_int,
) -> libc::c_int {
    return BIO_ctrl(
        bio,
        105 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        out_fd as *mut libc::c_char as *mut libc::c_void,
    ) as libc::c_int;
}
