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
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn abort() -> !;
    static mut stderr: *mut FILE;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn perror(__s: *const libc::c_char);
    fn __errno_location() -> *mut libc::c_int;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn nanosleep(
        __requested_time: *const timespec,
        __remaining: *mut timespec,
    ) -> libc::c_int;
    fn CRYPTO_once(
        once: *mut CRYPTO_once_t,
        init: Option::<unsafe extern "C" fn() -> ()>,
    );
    fn fcntl(__fd: libc::c_int, __cmd: libc::c_int, _: ...) -> libc::c_int;
    fn open(__file: *const libc::c_char, __oflag: libc::c_int, _: ...) -> libc::c_int;
    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn syscall(__sysno: libc::c_long, _: ...) -> libc::c_long;
    fn getauxval(__type: libc::c_ulong) -> libc::c_ulong;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type uint8_t = __uint8_t;
pub type ssize_t = __ssize_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: __time_t,
    pub tv_nsec: __syscall_slong_t,
}
pub type pthread_once_t = libc::c_int;
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
pub type CRYPTO_once_t = pthread_once_t;
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
unsafe extern "C" fn handle_rare_urandom_error(mut backoff: *mut libc::c_long) {
    let mut sleep_time: timespec = {
        let mut init = timespec {
            tv_sec: 0 as libc::c_int as __time_t,
            tv_nsec: 0 as libc::c_int as __syscall_slong_t,
        };
        init
    };
    *backoff = if (*backoff * 10 as libc::c_int as libc::c_long)
        < 1000000000 as libc::c_long - 1 as libc::c_int as libc::c_long
    {
        *backoff * 10 as libc::c_int as libc::c_long
    } else {
        1000000000 as libc::c_long - 1 as libc::c_int as libc::c_long
    };
    sleep_time.tv_nsec = *backoff;
    nanosleep(&mut sleep_time, &mut sleep_time);
}
unsafe extern "C" fn boringssl_getrandom(
    mut buf: *mut libc::c_void,
    mut buf_len: size_t,
    mut flags: libc::c_uint,
) -> ssize_t {
    let mut ret: ssize_t = 0;
    let mut backoff: libc::c_long = 1 as libc::c_int as libc::c_long;
    let mut retry_counter: size_t = 0 as libc::c_int as size_t;
    loop {
        ret = syscall(318 as libc::c_int as libc::c_long, buf, buf_len, flags);
        if ret == -(1 as libc::c_int) as ssize_t
            && *__errno_location() != 4 as libc::c_int
        {
            if flags & 1 as libc::c_int as libc::c_uint
                != 0 as libc::c_int as libc::c_uint
                || retry_counter >= 9 as libc::c_int as size_t
            {
                break;
            }
            handle_rare_urandom_error(&mut backoff);
            retry_counter = retry_counter.wrapping_add(1 as libc::c_int as size_t);
        }
        if !(ret == -(1 as libc::c_int) as ssize_t) {
            break;
        }
    }
    return ret;
}
static mut kHaveGetrandom: libc::c_int = -(3 as libc::c_int);
unsafe extern "C" fn urandom_fd_bss_get() -> *mut libc::c_int {
    return &mut urandom_fd;
}
static mut urandom_fd: libc::c_int = 0;
unsafe extern "C" fn getrandom_ready_bss_get() -> *mut libc::c_int {
    return &mut getrandom_ready;
}
static mut getrandom_ready: libc::c_int = 0;
unsafe extern "C" fn extra_getrandom_flags_for_seed_bss_get() -> *mut libc::c_int {
    return &mut extra_getrandom_flags_for_seed;
}
static mut extra_getrandom_flags_for_seed: libc::c_int = 0;
unsafe extern "C" fn maybe_set_extra_getrandom_flags() {}
unsafe extern "C" fn rand_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut rand_once;
}
static mut rand_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn init_once() {
    let mut have_getrandom: libc::c_int = 0;
    let mut dummy: uint8_t = 0;
    let mut getrandom_ret: ssize_t = boringssl_getrandom(
        &mut dummy as *mut uint8_t as *mut libc::c_void,
        ::core::mem::size_of::<uint8_t>() as libc::c_ulong,
        1 as libc::c_int as libc::c_uint,
    );
    if getrandom_ret == 1 as libc::c_int as ssize_t {
        *getrandom_ready_bss_get() = 1 as libc::c_int;
        have_getrandom = 1 as libc::c_int;
    } else if getrandom_ret == -(1 as libc::c_int) as ssize_t
        && *__errno_location() == 11 as libc::c_int
    {
        have_getrandom = 1 as libc::c_int;
    } else if getrandom_ret == -(1 as libc::c_int) as ssize_t
        && *__errno_location() == 38 as libc::c_int
    {
        have_getrandom = 0 as libc::c_int;
    } else {
        perror(b"getrandom\0" as *const u8 as *const libc::c_char);
        abort();
    }
    if have_getrandom != 0 {
        *urandom_fd_bss_get() = kHaveGetrandom;
        maybe_set_extra_getrandom_flags();
        return;
    }
    let mut fd: libc::c_int = 0;
    loop {
        fd = open(
            b"/dev/urandom\0" as *const u8 as *const libc::c_char,
            0 as libc::c_int,
        );
        if !(fd == -(1 as libc::c_int) && *__errno_location() == 4 as libc::c_int) {
            break;
        }
    }
    if fd < 0 as libc::c_int {
        perror(b"failed to open /dev/urandom\0" as *const u8 as *const libc::c_char);
        abort();
    }
    let mut flags: libc::c_int = fcntl(fd, 1 as libc::c_int);
    if flags == -(1 as libc::c_int) {
        if *__errno_location() != 38 as libc::c_int {
            perror(
                b"failed to get flags from urandom fd\0" as *const u8
                    as *const libc::c_char,
            );
            abort();
        }
    } else {
        flags |= 1 as libc::c_int;
        if fcntl(fd, 2 as libc::c_int, flags) == -(1 as libc::c_int) {
            perror(
                b"failed to set FD_CLOEXEC on urandom fd\0" as *const u8
                    as *const libc::c_char,
            );
            abort();
        }
    }
    *urandom_fd_bss_get() = fd;
}
unsafe extern "C" fn wait_for_entropy_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut wait_for_entropy_once;
}
static mut wait_for_entropy_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn wait_for_entropy() {
    let mut fd: libc::c_int = *urandom_fd_bss_get();
    if fd == kHaveGetrandom {
        if *getrandom_ready_bss_get() != 0 {
            return;
        }
        let mut dummy: uint8_t = 0;
        let mut getrandom_ret: ssize_t = boringssl_getrandom(
            &mut dummy as *mut uint8_t as *mut libc::c_void,
            ::core::mem::size_of::<uint8_t>() as libc::c_ulong,
            1 as libc::c_int as libc::c_uint,
        );
        if getrandom_ret == -(1 as libc::c_int) as ssize_t
            && *__errno_location() == 11 as libc::c_int
        {
            let mut current_process: *const libc::c_char = b"<unknown>\0" as *const u8
                as *const libc::c_char;
            let getauxval_ret: libc::c_ulong = getauxval(
                31 as libc::c_int as libc::c_ulong,
            );
            if getauxval_ret != 0 as libc::c_int as libc::c_ulong {
                current_process = getauxval_ret as *const libc::c_char;
            }
            fprintf(
                stderr,
                b"%s: getrandom indicates that the entropy pool has not been initialized. Rather than continue with poor entropy, this process will block until entropy is available.\n\0"
                    as *const u8 as *const libc::c_char,
                current_process,
            );
            getrandom_ret = boringssl_getrandom(
                &mut dummy as *mut uint8_t as *mut libc::c_void,
                ::core::mem::size_of::<uint8_t>() as libc::c_ulong,
                0 as libc::c_int as libc::c_uint,
            );
        }
        if getrandom_ret != 1 as libc::c_int as ssize_t {
            perror(b"getrandom\0" as *const u8 as *const libc::c_char);
            abort();
        }
        return;
    }
}
unsafe extern "C" fn fill_with_entropy(
    mut out: *mut uint8_t,
    mut len: size_t,
    mut block: libc::c_int,
    mut seed: libc::c_int,
) -> libc::c_int {
    if len == 0 as libc::c_int as size_t {
        return 1 as libc::c_int;
    }
    let mut getrandom_flags: libc::c_int = 0 as libc::c_int;
    if block == 0 {
        getrandom_flags |= 1 as libc::c_int;
    }
    if seed != 0 {
        getrandom_flags |= *extra_getrandom_flags_for_seed_bss_get();
    }
    CRYPTO_init_sysrand();
    if block != 0 {
        CRYPTO_once(
            wait_for_entropy_once_bss_get(),
            Some(wait_for_entropy as unsafe extern "C" fn() -> ()),
        );
    }
    *__errno_location() = 0 as libc::c_int;
    while len > 0 as libc::c_int as size_t {
        let mut r: ssize_t = 0;
        if *urandom_fd_bss_get() == kHaveGetrandom {
            r = boringssl_getrandom(
                out as *mut libc::c_void,
                len,
                getrandom_flags as libc::c_uint,
            );
        } else {
            let mut retry_counter: size_t = 0 as libc::c_int as size_t;
            let mut backoff: libc::c_long = 1 as libc::c_int as libc::c_long;
            loop {
                r = read(*urandom_fd_bss_get(), out as *mut libc::c_void, len);
                if r == -(1 as libc::c_int) as ssize_t
                    && *__errno_location() != 4 as libc::c_int
                {
                    if retry_counter >= 9 as libc::c_int as size_t {
                        break;
                    }
                    handle_rare_urandom_error(&mut backoff);
                    retry_counter = retry_counter
                        .wrapping_add(1 as libc::c_int as size_t);
                }
                if !(r == -(1 as libc::c_int) as ssize_t) {
                    break;
                }
            }
        }
        if r <= 0 as libc::c_int as ssize_t {
            return 0 as libc::c_int;
        }
        out = out.offset(r as isize);
        len = len.wrapping_sub(r as size_t);
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_init_sysrand() {
    CRYPTO_once(rand_once_bss_get(), Some(init_once as unsafe extern "C" fn() -> ()));
}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_sysrand(mut out: *mut uint8_t, mut requested: size_t) {
    if fill_with_entropy(out, requested, 1 as libc::c_int, 0 as libc::c_int) == 0 {
        perror(b"entropy fill failed\0" as *const u8 as *const libc::c_char);
        abort();
    }
}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_sysrand_for_seed(
    mut out: *mut uint8_t,
    mut requested: size_t,
) {
    if fill_with_entropy(out, requested, 1 as libc::c_int, 1 as libc::c_int) == 0 {
        perror(b"entropy fill failed\0" as *const u8 as *const libc::c_char);
        abort();
    }
}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_sysrand_if_available(
    mut out: *mut uint8_t,
    mut requested: size_t,
) -> libc::c_int {
    if fill_with_entropy(out, requested, 0 as libc::c_int, 0 as libc::c_int) != 0 {
        return 1 as libc::c_int
    } else if *__errno_location() == 11 as libc::c_int {
        OPENSSL_memset(out as *mut libc::c_void, 0 as libc::c_int, requested);
        return 0 as libc::c_int;
    } else {
        perror(
            b"opportunistic entropy fill failed\0" as *const u8 as *const libc::c_char,
        );
        abort();
    };
}
