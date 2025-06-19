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
    fn abort() -> !;
    fn open(__file: *const libc::c_char, __oflag: libc::c_int, _: ...) -> libc::c_int;
    fn mmap(
        __addr: *mut libc::c_void,
        __len: size_t,
        __prot: libc::c_int,
        __flags: libc::c_int,
        __fd: libc::c_int,
        __offset: __off_t,
    ) -> *mut libc::c_void;
    fn stat(__file: *const libc::c_char, __buf: *mut stat) -> libc::c_int;
    fn close(__fd: libc::c_int) -> libc::c_int;
    fn CRYPTO_once(
        once: *mut CRYPTO_once_t,
        init: Option::<unsafe extern "C" fn() -> ()>,
    );
}
pub type size_t = libc::c_ulong;
pub type __uint32_t = libc::c_uint;
pub type __dev_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __ino_t = libc::c_ulong;
pub type __mode_t = libc::c_uint;
pub type __nlink_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type uint32_t = __uint32_t;
pub type pthread_once_t = libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct stat {
    pub st_dev: __dev_t,
    pub st_ino: __ino_t,
    pub st_nlink: __nlink_t,
    pub st_mode: __mode_t,
    pub st_uid: __uid_t,
    pub st_gid: __gid_t,
    pub __pad0: libc::c_int,
    pub st_rdev: __dev_t,
    pub st_size: __off_t,
    pub st_blksize: __blksize_t,
    pub st_blocks: __blkcnt_t,
    pub st_atim: timespec,
    pub st_mtim: timespec,
    pub st_ctim: timespec,
    pub __glibc_reserved: [__syscall_slong_t; 3],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: __time_t,
    pub tv_nsec: __syscall_slong_t,
}
pub type CRYPTO_once_t = pthread_once_t;
unsafe extern "C" fn aws_snapsafe_init_bss_get() -> *mut CRYPTO_once_t {
    return &mut aws_snapsafe_init;
}
static mut aws_snapsafe_init: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn sgc_addr_bss_get() -> *mut *mut uint32_t {
    return &mut sgc_addr;
}
static mut sgc_addr: *mut uint32_t = 0 as *const uint32_t as *mut uint32_t;
unsafe extern "C" fn snapsafety_state_bss_get() -> *mut libc::c_int {
    return &mut snapsafety_state;
}
static mut snapsafety_state: libc::c_int = 0;
unsafe extern "C" fn do_aws_snapsafe_init() {
    let ref mut fresh0 = *sgc_addr_bss_get();
    *fresh0 = 0 as *mut uint32_t;
    *snapsafety_state_bss_get() = 0x2 as libc::c_int;
    let mut buff: stat = stat {
        st_dev: 0,
        st_ino: 0,
        st_nlink: 0,
        st_mode: 0,
        st_uid: 0,
        st_gid: 0,
        __pad0: 0,
        st_rdev: 0,
        st_size: 0,
        st_blksize: 0,
        st_blocks: 0,
        st_atim: timespec { tv_sec: 0, tv_nsec: 0 },
        st_mtim: timespec { tv_sec: 0, tv_nsec: 0 },
        st_ctim: timespec { tv_sec: 0, tv_nsec: 0 },
        __glibc_reserved: [0; 3],
    };
    if stat(CRYPTO_get_sysgenid_path(), &mut buff) != 0 as libc::c_int {
        return;
    }
    *snapsafety_state_bss_get() = 0 as libc::c_int;
    let mut fd_sgc: libc::c_int = open(CRYPTO_get_sysgenid_path(), 0 as libc::c_int);
    if fd_sgc < 0 as libc::c_int {
        return;
    }
    let mut addr: *mut libc::c_void = mmap(
        0 as *mut libc::c_void,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
        0x1 as libc::c_int,
        0x1 as libc::c_int,
        fd_sgc,
        0 as libc::c_int as __off_t,
    );
    close(fd_sgc);
    if addr == -(1 as libc::c_int) as *mut libc::c_void {
        return;
    }
    let ref mut fresh1 = *sgc_addr_bss_get();
    *fresh1 = addr as *mut uint32_t;
    *snapsafety_state_bss_get() = 0x1 as libc::c_int;
}
unsafe extern "C" fn aws_snapsafe_read_sgn() -> uint32_t {
    if *snapsafety_state_bss_get() == 0x1 as libc::c_int {
        return **sgc_addr_bss_get();
    }
    return 0 as libc::c_int as uint32_t;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_get_snapsafe_generation(
    mut snapsafe_generation_number: *mut uint32_t,
) -> libc::c_int {
    CRYPTO_once(
        aws_snapsafe_init_bss_get(),
        Some(do_aws_snapsafe_init as unsafe extern "C" fn() -> ()),
    );
    let mut state: libc::c_int = *snapsafety_state_bss_get();
    match state {
        2 => {
            *snapsafe_generation_number = 0 as libc::c_int as uint32_t;
            return 1 as libc::c_int;
        }
        1 => {
            *snapsafe_generation_number = aws_snapsafe_read_sgn();
            return 1 as libc::c_int;
        }
        0 => {
            *snapsafe_generation_number = 0 as libc::c_int as uint32_t;
            return 0 as libc::c_int;
        }
        _ => {
            abort();
        }
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_get_snapsafe_active() -> libc::c_int {
    CRYPTO_once(
        aws_snapsafe_init_bss_get(),
        Some(do_aws_snapsafe_init as unsafe extern "C" fn() -> ()),
    );
    if *snapsafety_state_bss_get() == 0x1 as libc::c_int {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_get_snapsafe_supported() -> libc::c_int {
    CRYPTO_once(
        aws_snapsafe_init_bss_get(),
        Some(do_aws_snapsafe_init as unsafe extern "C" fn() -> ()),
    );
    if *snapsafety_state_bss_get() == 0x2 as libc::c_int {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_get_sysgenid_path() -> *const libc::c_char {
    return b"/dev/sysgenid\0" as *const u8 as *const libc::c_char;
}
