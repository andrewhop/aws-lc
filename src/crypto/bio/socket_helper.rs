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
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn ERR_add_error_data(count: libc::c_uint, _: ...);
    fn socket(
        __domain: libc::c_int,
        __type: libc::c_int,
        __protocol: libc::c_int,
    ) -> libc::c_int;
    fn getsockopt(
        __fd: libc::c_int,
        __level: libc::c_int,
        __optname: libc::c_int,
        __optval: *mut libc::c_void,
        __optlen: *mut socklen_t,
    ) -> libc::c_int;
    fn fcntl(__fd: libc::c_int, __cmd: libc::c_int, _: ...) -> libc::c_int;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn getaddrinfo(
        __name: *const libc::c_char,
        __service: *const libc::c_char,
        __req: *const addrinfo,
        __pai: *mut *mut addrinfo,
    ) -> libc::c_int;
    fn freeaddrinfo(__ai: *mut addrinfo);
    fn gai_strerror(__ecode: libc::c_int) -> *const libc::c_char;
    fn bio_errno_should_retry(return_value: libc::c_int) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __socklen_t = libc::c_uint;
pub type socklen_t = __socklen_t;
pub type __socket_type = libc::c_uint;
pub const SOCK_NONBLOCK: __socket_type = 2048;
pub const SOCK_CLOEXEC: __socket_type = 524288;
pub const SOCK_PACKET: __socket_type = 10;
pub const SOCK_DCCP: __socket_type = 6;
pub const SOCK_SEQPACKET: __socket_type = 5;
pub const SOCK_RDM: __socket_type = 4;
pub const SOCK_RAW: __socket_type = 3;
pub const SOCK_DGRAM: __socket_type = 2;
pub const SOCK_STREAM: __socket_type = 1;
pub type sa_family_t = libc::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [libc::c_char; 14],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_storage {
    pub ss_family: sa_family_t,
    pub __ss_padding: [libc::c_char; 118],
    pub __ss_align: libc::c_ulong,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct addrinfo {
    pub ai_flags: libc::c_int,
    pub ai_family: libc::c_int,
    pub ai_socktype: libc::c_int,
    pub ai_protocol: libc::c_int,
    pub ai_addrlen: socklen_t,
    pub ai_addr: *mut sockaddr,
    pub ai_canonname: *mut libc::c_char,
    pub ai_next: *mut addrinfo,
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
#[no_mangle]
pub unsafe extern "C" fn bio_ip_and_port_to_socket_and_addr(
    mut out_sock: *mut libc::c_int,
    mut out_addr: *mut sockaddr_storage,
    mut out_addr_length: *mut socklen_t,
    mut hostname: *const libc::c_char,
    mut port_str: *const libc::c_char,
) -> libc::c_int {
    let mut hint: addrinfo = addrinfo {
        ai_flags: 0,
        ai_family: 0,
        ai_socktype: 0,
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_addr: 0 as *mut sockaddr,
        ai_canonname: 0 as *mut libc::c_char,
        ai_next: 0 as *mut addrinfo,
    };
    let mut result: *mut addrinfo = 0 as *mut addrinfo;
    let mut cur: *mut addrinfo = 0 as *mut addrinfo;
    let mut ret: libc::c_int = 0;
    *out_sock = -(1 as libc::c_int);
    OPENSSL_cleanse(
        &mut hint as *mut addrinfo as *mut libc::c_void,
        ::core::mem::size_of::<addrinfo>() as libc::c_ulong,
    );
    hint.ai_family = 0 as libc::c_int;
    hint.ai_socktype = SOCK_STREAM as libc::c_int;
    ret = getaddrinfo(hostname, port_str, &mut hint, &mut result);
    if ret != 0 as libc::c_int {
        ERR_put_error(
            2 as libc::c_int,
            0 as libc::c_int,
            0 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/socket_helper.c\0"
                as *const u8 as *const libc::c_char,
            60 as libc::c_int as libc::c_uint,
        );
        ERR_add_error_data(1 as libc::c_int as libc::c_uint, gai_strerror(ret));
        return 0 as libc::c_int;
    }
    ret = 0 as libc::c_int;
    cur = result;
    while !cur.is_null() {
        if (*cur).ai_addrlen as size_t
            > ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong
        {
            cur = (*cur).ai_next;
        } else {
            OPENSSL_cleanse(
                out_addr as *mut libc::c_void,
                ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong,
            );
            OPENSSL_memcpy(
                out_addr as *mut libc::c_void,
                (*cur).ai_addr as *const libc::c_void,
                (*cur).ai_addrlen as size_t,
            );
            *out_addr_length = (*cur).ai_addrlen;
            *out_sock = socket((*cur).ai_family, (*cur).ai_socktype, (*cur).ai_protocol);
            if *out_sock < 0 as libc::c_int {
                ERR_put_error(
                    2 as libc::c_int,
                    0 as libc::c_int,
                    0 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/socket_helper.c\0"
                        as *const u8 as *const libc::c_char,
                    81 as libc::c_int as libc::c_uint,
                );
                break;
            } else {
                ret = 1 as libc::c_int;
                break;
            }
        }
    }
    freeaddrinfo(result);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn bio_socket_nbio(
    mut sock: libc::c_int,
    mut on: libc::c_int,
) -> libc::c_int {
    let mut flags: libc::c_int = fcntl(sock, 3 as libc::c_int, 0 as libc::c_int);
    if flags < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if on == 0 {
        flags &= !(0o4000 as libc::c_int);
    } else {
        flags |= 0o4000 as libc::c_int;
    }
    return (fcntl(sock, 4 as libc::c_int, flags) == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn bio_clear_socket_error(mut sock: libc::c_int) {
    bio_sock_error_get_and_clear(sock);
}
#[no_mangle]
pub unsafe extern "C" fn bio_sock_error_get_and_clear(
    mut sock: libc::c_int,
) -> libc::c_int {
    let mut error: libc::c_int = 0;
    let mut error_size: socklen_t = ::core::mem::size_of::<libc::c_int>()
        as libc::c_ulong as socklen_t;
    if getsockopt(
        sock,
        1 as libc::c_int,
        4 as libc::c_int,
        &mut error as *mut libc::c_int as *mut libc::c_char as *mut libc::c_void,
        &mut error_size,
    ) < 0 as libc::c_int
    {
        return 1 as libc::c_int;
    }
    return error;
}
#[no_mangle]
pub unsafe extern "C" fn bio_socket_should_retry(
    mut return_value: libc::c_int,
) -> libc::c_int {
    return bio_errno_should_retry(return_value);
}
