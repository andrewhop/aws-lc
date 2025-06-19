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
    fn BIO_free(bio: *mut BIO) -> libc::c_int;
    fn BIO_ctrl(
        bio: *mut BIO,
        cmd: libc::c_int,
        larg: libc::c_long,
        parg: *mut libc::c_void,
    ) -> libc::c_long;
    fn BIO_set_retry_read(bio: *mut BIO);
    fn BIO_set_retry_write(bio: *mut BIO);
    fn BIO_clear_retry_flags(bio: *mut BIO);
    fn BIO_set_fd(
        bio: *mut BIO,
        fd: libc::c_int,
        close_flag: libc::c_int,
    ) -> libc::c_int;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn OPENSSL_strnlen(s: *const libc::c_char, len: size_t) -> size_t;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn send(
        __fd: libc::c_int,
        __buf: *const libc::c_void,
        __n: size_t,
        __flags: libc::c_int,
    ) -> ssize_t;
    fn sendto(
        __fd: libc::c_int,
        __buf: *const libc::c_void,
        __n: size_t,
        __flags: libc::c_int,
        __addr: *const sockaddr,
        __addr_len: socklen_t,
    ) -> ssize_t;
    fn recvfrom(
        __fd: libc::c_int,
        __buf: *mut libc::c_void,
        __n: size_t,
        __flags: libc::c_int,
        __addr: *mut sockaddr,
        __addr_len: *mut socklen_t,
    ) -> ssize_t;
    fn close(__fd: libc::c_int) -> libc::c_int;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn bio_clear_socket_error(sock: libc::c_int);
    fn bio_sock_error_get_and_clear(sock: libc::c_int) -> libc::c_int;
    fn bio_socket_should_retry(return_value: libc::c_int) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __ssize_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
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
pub type socklen_t = __socklen_t;
pub type sa_family_t = libc::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [libc::c_char; 14],
}
pub type in_addr_t = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}
pub type in_port_t = uint16_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in6_addr {
    pub __in6_u: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub __u6_addr8: [uint8_t; 16],
    pub __u6_addr16: [uint16_t; 8],
    pub __u6_addr32: [uint32_t; 4],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [libc::c_uchar; 8],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in6 {
    pub sin6_family: sa_family_t,
    pub sin6_port: in_port_t,
    pub sin6_flowinfo: uint32_t,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_un {
    pub sun_family: sa_family_t,
    pub sun_path: [libc::c_char; 108],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union bio_addr_st {
    pub sa: sockaddr,
    pub s_in6: sockaddr_in6,
    pub s_in: sockaddr_in,
    pub s_un: sockaddr_un,
}
pub type BIO_ADDR = bio_addr_st;
pub type bio_dgram_data = bio_dgram_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bio_dgram_data_st {
    pub peer: BIO_ADDR,
    pub connected: libc::c_uint,
    pub _errno: libc::c_uint,
}
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
unsafe extern "C" fn closesocket(sock: libc::c_int) -> libc::c_int {
    return close(sock);
}
unsafe extern "C" fn BIO_ADDR_make(
    mut bap: *mut BIO_ADDR,
    mut sap: *const sockaddr,
) -> libc::c_int {
    if bap.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0" as *const u8
                as *const libc::c_char,
            42 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if sap.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0" as *const u8
                as *const libc::c_char,
            43 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*sap).sa_family as libc::c_int == 2 as libc::c_int {
        OPENSSL_memcpy(
            &mut (*bap).s_in as *mut sockaddr_in as *mut libc::c_void,
            sap as *const libc::c_void,
            ::core::mem::size_of::<sockaddr_in>() as libc::c_ulong,
        );
        return 1 as libc::c_int;
    }
    if (*sap).sa_family as libc::c_int == 10 as libc::c_int {
        OPENSSL_memcpy(
            &mut (*bap).s_in6 as *mut sockaddr_in6 as *mut libc::c_void,
            sap as *const libc::c_void,
            ::core::mem::size_of::<sockaddr_in6>() as libc::c_ulong,
        );
        return 1 as libc::c_int;
    }
    if (*sap).sa_family as libc::c_int == 1 as libc::c_int {
        OPENSSL_memcpy(
            &mut (*bap).s_un as *mut sockaddr_un as *mut libc::c_void,
            sap as *const libc::c_void,
            ::core::mem::size_of::<sockaddr_un>() as libc::c_ulong,
        );
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn BIO_ADDR_sockaddr_size(mut bap: *const BIO_ADDR) -> socklen_t {
    if bap.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0" as *const u8
                as *const libc::c_char,
            71 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int as socklen_t;
    }
    if (*bap).sa.sa_family as libc::c_int == 2 as libc::c_int {
        return ::core::mem::size_of::<sockaddr_in>() as libc::c_ulong as socklen_t;
    }
    if (*bap).sa.sa_family as libc::c_int == 10 as libc::c_int {
        return ::core::mem::size_of::<sockaddr_in6>() as libc::c_ulong as socklen_t;
    }
    if (*bap).sa.sa_family as libc::c_int == 1 as libc::c_int {
        return ::core::mem::size_of::<sockaddr_un>() as libc::c_ulong as socklen_t;
    }
    return ::core::mem::size_of::<BIO_ADDR>() as libc::c_ulong as socklen_t;
}
unsafe extern "C" fn BIO_ADDR_sockaddr_noconst(mut bap: *mut BIO_ADDR) -> *mut sockaddr {
    if bap.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0" as *const u8
                as *const libc::c_char,
            89 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut sockaddr;
    }
    return &mut (*bap).sa;
}
unsafe extern "C" fn BIO_ADDR_sockaddr(mut bap: *const BIO_ADDR) -> *const sockaddr {
    if bap.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0" as *const u8
                as *const libc::c_char,
            94 as libc::c_int as libc::c_uint,
        );
        return 0 as *const sockaddr;
    }
    return &(*bap).sa;
}
unsafe extern "C" fn dgram_write(
    mut bp: *mut BIO,
    mut in_0: *const libc::c_char,
    in_len: libc::c_int,
) -> libc::c_int {
    if bp.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0" as *const u8
                as *const libc::c_char,
            99 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if in_0.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0" as *const u8
                as *const libc::c_char,
            100 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut result: ssize_t = 0;
    let mut data: *mut bio_dgram_data = (*bp).ptr as *mut bio_dgram_data;
    if data.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0" as *const u8
                as *const libc::c_char,
            104 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if in_len < 0 as libc::c_int {
        ERR_put_error(
            17 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0" as *const u8
                as *const libc::c_char,
            107 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    bio_clear_socket_error((*bp).num);
    if (*data).connected != 0 {
        result = send(
            (*bp).num,
            in_0 as *const libc::c_void,
            in_len as size_t,
            0 as libc::c_int,
        );
    } else {
        let peerlen: socklen_t = BIO_ADDR_sockaddr_size(&mut (*data).peer);
        result = sendto(
            (*bp).num,
            in_0 as *const libc::c_void,
            in_len as size_t,
            0 as libc::c_int,
            BIO_ADDR_sockaddr(&mut (*data).peer),
            peerlen,
        );
    }
    if result < (-(2147483647 as libc::c_int) - 1 as libc::c_int) as ssize_t
        || result > 2147483647 as libc::c_int as ssize_t
    {
        ERR_put_error(
            17 as libc::c_int,
            0 as libc::c_int,
            112 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0" as *const u8
                as *const libc::c_char,
            124 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    let ret: libc::c_int = result as libc::c_int;
    BIO_clear_retry_flags(bp);
    if ret <= 0 as libc::c_int && bio_socket_should_retry(ret) != 0 {
        BIO_set_retry_write(bp);
        (*data)._errno = bio_sock_error_get_and_clear((*bp).num) as libc::c_uint;
    }
    return ret;
}
unsafe extern "C" fn dgram_read(
    mut bp: *mut BIO,
    mut out: *mut libc::c_char,
    out_len: libc::c_int,
) -> libc::c_int {
    if bp.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0" as *const u8
                as *const libc::c_char,
            138 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if out.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0" as *const u8
                as *const libc::c_char,
            139 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*bp).ptr).is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0" as *const u8
                as *const libc::c_char,
            140 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut peer: BIO_ADDR = bio_addr_st {
        sa: sockaddr {
            sa_family: 0,
            sa_data: [0; 14],
        },
    };
    let mut len: socklen_t = ::core::mem::size_of::<BIO_ADDR>() as libc::c_ulong
        as socklen_t;
    let mut data: *mut bio_dgram_data = (*bp).ptr as *mut bio_dgram_data;
    bio_clear_socket_error((*bp).num);
    if out_len < 0 as libc::c_int {
        ERR_put_error(
            17 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0" as *const u8
                as *const libc::c_char,
            151 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    let result: ssize_t = recvfrom(
        (*bp).num,
        out as *mut libc::c_void,
        out_len as size_t,
        0 as libc::c_int,
        BIO_ADDR_sockaddr_noconst(&mut peer),
        &mut len,
    );
    if result < (-(2147483647 as libc::c_int) - 1 as libc::c_int) as ssize_t
        || result > 2147483647 as libc::c_int as ssize_t
    {
        ERR_put_error(
            17 as libc::c_int,
            0 as libc::c_int,
            112 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0" as *const u8
                as *const libc::c_char,
            161 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    let ret: libc::c_int = result as libc::c_int;
    if (*data).connected == 0 && ret >= 0 as libc::c_int {
        1 as libc::c_int != BIO_dgram_set_peer(bp, &mut peer);
    }
    BIO_clear_retry_flags(bp);
    if ret < 0 as libc::c_int && bio_socket_should_retry(ret) != 0 {
        BIO_set_retry_read(bp);
        (*data)._errno = bio_sock_error_get_and_clear((*bp).num) as libc::c_uint;
    }
    return ret;
}
unsafe extern "C" fn dgram_puts(
    mut bp: *mut BIO,
    mut str: *const libc::c_char,
) -> libc::c_int {
    if bp.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0" as *const u8
                as *const libc::c_char,
            182 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if str.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0" as *const u8
                as *const libc::c_char,
            183 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let len: libc::c_int = OPENSSL_strnlen(str, 2147483647 as libc::c_int as size_t)
        as libc::c_int;
    return dgram_write(bp, str, len);
}
unsafe extern "C" fn dgram_free(mut bp: *mut BIO) -> libc::c_int {
    if bp.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0" as *const u8
                as *const libc::c_char,
            190 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*bp).shutdown != 0 && (*bp).init != 0 {
        0 as libc::c_int != closesocket((*bp).num);
    }
    (*bp).init = 0 as libc::c_int;
    (*bp).num = -(1 as libc::c_int);
    (*bp).flags = 0 as libc::c_int;
    OPENSSL_free((*bp).ptr);
    (*bp).ptr = 0 as *mut libc::c_void;
    return 1 as libc::c_int;
}
unsafe extern "C" fn dgram_new(mut bio: *mut BIO) -> libc::c_int {
    (*bio).init = 0 as libc::c_int;
    (*bio).num = -(1 as libc::c_int);
    (*bio)
        .ptr = OPENSSL_zalloc(::core::mem::size_of::<bio_dgram_data>() as libc::c_ulong);
    return ((*bio).ptr != 0 as *mut libc::c_void) as libc::c_int;
}
unsafe extern "C" fn dgram_ctrl(
    mut bp: *mut BIO,
    cmd: libc::c_int,
    num: libc::c_long,
    mut ptr: *mut libc::c_void,
) -> libc::c_long {
    if bp.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0" as *const u8
                as *const libc::c_char,
            212 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int as libc::c_long;
    }
    let mut data: *mut bio_dgram_data = (*bp).ptr as *mut bio_dgram_data;
    let mut ret: libc::c_long = 1 as libc::c_int as libc::c_long;
    let mut fd: libc::c_int = 0;
    match cmd {
        104 => {
            if ptr.is_null() {
                ERR_put_error(
                    14 as libc::c_int,
                    0 as libc::c_int,
                    3 as libc::c_int | 64 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0"
                        as *const u8 as *const libc::c_char,
                    219 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int as libc::c_long;
            }
            fd = *(ptr as *mut libc::c_int);
            if fd < 0 as libc::c_int {
                ERR_put_error(
                    17 as libc::c_int,
                    0 as libc::c_int,
                    104 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0"
                        as *const u8 as *const libc::c_char,
                    223 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int as libc::c_long;
            }
            dgram_free(bp);
            dgram_new(bp);
            (*bp).num = fd;
            (*bp).shutdown = num as libc::c_int;
            (*bp).init = 1 as libc::c_int;
        }
        105 => {
            if (*bp).init != 0 {
                let mut ip: *mut libc::c_int = ptr as *mut libc::c_int;
                if !ip.is_null() {
                    *ip = (*bp).num;
                }
                ret = (*bp).num as libc::c_long;
            } else {
                ret = -(1 as libc::c_int) as libc::c_long;
            }
        }
        8 => {
            ret = (*bp).shutdown as libc::c_long;
        }
        9 => {
            (*bp).shutdown = (num != 0 as libc::c_int as libc::c_long) as libc::c_int;
        }
        11 => {
            ret = 1 as libc::c_int as libc::c_long;
        }
        32 => {
            if data.is_null() {
                ERR_put_error(
                    14 as libc::c_int,
                    0 as libc::c_int,
                    3 as libc::c_int | 64 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0"
                        as *const u8 as *const libc::c_char,
                    253 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int as libc::c_long;
            }
            if !ptr.is_null() {
                (*data).connected = 1 as libc::c_int as libc::c_uint;
                ret = BIO_ADDR_make(
                    &mut (*data).peer,
                    BIO_ADDR_sockaddr(ptr as *const BIO_ADDR),
                ) as libc::c_long;
            } else {
                (*data).connected = 0 as libc::c_int as libc::c_uint;
                OPENSSL_cleanse(
                    &mut (*data).peer as *mut BIO_ADDR as *mut libc::c_void,
                    ::core::mem::size_of::<BIO_ADDR>() as libc::c_ulong,
                );
                ret = 1 as libc::c_int as libc::c_long;
            }
        }
        46 => {
            if data.is_null() {
                ERR_put_error(
                    14 as libc::c_int,
                    0 as libc::c_int,
                    3 as libc::c_int | 64 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0"
                        as *const u8 as *const libc::c_char,
                    264 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int as libc::c_long;
            }
            if ptr.is_null() {
                ERR_put_error(
                    14 as libc::c_int,
                    0 as libc::c_int,
                    3 as libc::c_int | 64 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0"
                        as *const u8 as *const libc::c_char,
                    265 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int as libc::c_long;
            }
            let size: socklen_t = BIO_ADDR_sockaddr_size(&mut (*data).peer);
            if num == 0 as libc::c_int as libc::c_long || num >= size as libc::c_long {
                OPENSSL_memcpy(
                    ptr,
                    &mut (*data).peer as *mut BIO_ADDR as *const libc::c_void,
                    size as size_t,
                );
                ret = size as libc::c_long;
            } else {
                ret = 0 as libc::c_int as libc::c_long;
            }
        }
        31 | 44 => {
            if data.is_null() {
                ERR_put_error(
                    14 as libc::c_int,
                    0 as libc::c_int,
                    3 as libc::c_int | 64 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0"
                        as *const u8 as *const libc::c_char,
                    277 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int as libc::c_long;
            }
            if ptr.is_null() {
                ERR_put_error(
                    14 as libc::c_int,
                    0 as libc::c_int,
                    3 as libc::c_int | 64 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0"
                        as *const u8 as *const libc::c_char,
                    278 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int as libc::c_long;
            }
            ret = BIO_ADDR_make(
                &mut (*data).peer,
                BIO_ADDR_sockaddr(ptr as *const BIO_ADDR),
            ) as libc::c_long;
        }
        38 | 37 => {
            if data.is_null() {
                ERR_put_error(
                    14 as libc::c_int,
                    0 as libc::c_int,
                    3 as libc::c_int | 64 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/dgram.c\0"
                        as *const u8 as *const libc::c_char,
                    283 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int as libc::c_long;
            }
            let mut d_errno: libc::c_int = 0 as libc::c_int;
            d_errno = ((*data)._errno == 11 as libc::c_int as libc::c_uint
                || (*data)._errno == 11 as libc::c_int as libc::c_uint
                || (*data)._errno == 115 as libc::c_int as libc::c_uint) as libc::c_int;
            if d_errno != 0 {
                ret = 1 as libc::c_int as libc::c_long;
                (*data)._errno = 0 as libc::c_int as libc::c_uint;
            } else {
                ret = 0 as libc::c_int as libc::c_long;
            }
        }
        _ => {
            ret = 0 as libc::c_int as libc::c_long;
        }
    }
    return ret;
}
static mut methods_dgramp: BIO_METHOD = unsafe {
    {
        let mut init = bio_method_st {
            type_0: 21 as libc::c_int | 0x400 as libc::c_int | 0x100 as libc::c_int,
            name: b"datagram socket\0" as *const u8 as *const libc::c_char,
            bwrite: Some(
                dgram_write
                    as unsafe extern "C" fn(
                        *mut BIO,
                        *const libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            bread: Some(
                dgram_read
                    as unsafe extern "C" fn(
                        *mut BIO,
                        *mut libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            bputs: Some(
                dgram_puts
                    as unsafe extern "C" fn(*mut BIO, *const libc::c_char) -> libc::c_int,
            ),
            bgets: None,
            ctrl: Some(
                dgram_ctrl
                    as unsafe extern "C" fn(
                        *mut BIO,
                        libc::c_int,
                        libc::c_long,
                        *mut libc::c_void,
                    ) -> libc::c_long,
            ),
            create: Some(dgram_new as unsafe extern "C" fn(*mut BIO) -> libc::c_int),
            destroy: Some(dgram_free as unsafe extern "C" fn(*mut BIO) -> libc::c_int),
            callback_ctrl: None,
        };
        init
    }
};
#[no_mangle]
pub unsafe extern "C" fn BIO_s_datagram() -> *const BIO_METHOD {
    return &methods_dgramp;
}
#[no_mangle]
pub unsafe extern "C" fn BIO_new_dgram(
    mut fd: libc::c_int,
    mut close_flag: libc::c_int,
) -> *mut BIO {
    let mut ret: *mut BIO = BIO_new(BIO_s_datagram());
    if ret.is_null() {
        return 0 as *mut BIO;
    }
    let mut result: libc::c_int = BIO_set_fd(ret, fd, close_flag);
    if result <= 0 as libc::c_int {
        BIO_free(ret);
        return 0 as *mut BIO;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn BIO_ctrl_dgram_connect(
    mut bp: *mut BIO,
    mut peer: *const BIO_ADDR,
) -> libc::c_int {
    let ret: libc::c_long = BIO_ctrl(
        bp,
        31 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        peer as *mut BIO_ADDR as *mut libc::c_void,
    );
    if ret < (-(2147483647 as libc::c_int) - 1 as libc::c_int) as libc::c_long
        || ret > 2147483647 as libc::c_int as libc::c_long
    {
        return 0 as libc::c_int;
    }
    return ret as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn BIO_ctrl_set_connected(
    mut bp: *mut BIO,
    mut peer: *const BIO_ADDR,
) -> libc::c_int {
    let ret: libc::c_long = BIO_ctrl(
        bp,
        32 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        peer as *mut BIO_ADDR as *mut libc::c_void,
    );
    if ret < (-(2147483647 as libc::c_int) - 1 as libc::c_int) as libc::c_long
        || ret > 2147483647 as libc::c_int as libc::c_long
    {
        return 0 as libc::c_int;
    }
    return ret as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn BIO_dgram_recv_timedout(mut bp: *mut BIO) -> libc::c_int {
    let ret: libc::c_long = BIO_ctrl(
        bp,
        37 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        0 as *mut libc::c_void,
    );
    if ret < (-(2147483647 as libc::c_int) - 1 as libc::c_int) as libc::c_long
        || ret > 2147483647 as libc::c_int as libc::c_long
    {
        return 0 as libc::c_int;
    }
    return ret as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn BIO_dgram_send_timedout(mut bp: *mut BIO) -> libc::c_int {
    let ret: libc::c_long = BIO_ctrl(
        bp,
        38 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        0 as *mut libc::c_void,
    );
    if ret < (-(2147483647 as libc::c_int) - 1 as libc::c_int) as libc::c_long
        || ret > 2147483647 as libc::c_int as libc::c_long
    {
        return 0 as libc::c_int;
    }
    return ret as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn BIO_dgram_get_peer(
    mut bp: *mut BIO,
    mut peer: *mut BIO_ADDR,
) -> libc::c_int {
    let ret: libc::c_long = BIO_ctrl(
        bp,
        46 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        peer as *mut libc::c_void,
    );
    if ret < (-(2147483647 as libc::c_int) - 1 as libc::c_int) as libc::c_long
        || ret > 2147483647 as libc::c_int as libc::c_long
    {
        return 0 as libc::c_int;
    }
    return ret as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn BIO_dgram_set_peer(
    mut bp: *mut BIO,
    mut peer: *const BIO_ADDR,
) -> libc::c_int {
    let ret: libc::c_long = BIO_ctrl(
        bp,
        44 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        peer as *mut BIO_ADDR as *mut libc::c_void,
    );
    if ret < (-(2147483647 as libc::c_int) - 1 as libc::c_int) as libc::c_long
        || ret > 2147483647 as libc::c_int as libc::c_long
    {
        return 0 as libc::c_int;
    }
    return ret as libc::c_int;
}
