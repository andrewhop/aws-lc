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
    fn BIO_free(bio: *mut BIO) -> libc::c_int;
    fn BIO_ctrl(
        bio: *mut BIO,
        cmd: libc::c_int,
        larg: libc::c_long,
        parg: *mut libc::c_void,
    ) -> libc::c_long;
    fn BIO_set_flags(bio: *mut BIO, flags: libc::c_int);
    fn BIO_set_retry_read(bio: *mut BIO);
    fn BIO_set_retry_write(bio: *mut BIO);
    fn BIO_clear_retry_flags(bio: *mut BIO);
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_strdup(s: *const libc::c_char) -> *mut libc::c_char;
    fn OPENSSL_strndup(str: *const libc::c_char, size: size_t) -> *mut libc::c_char;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn ERR_add_error_data(count: libc::c_uint, _: ...);
    fn connect(
        __fd: libc::c_int,
        __addr: *const sockaddr,
        __len: socklen_t,
    ) -> libc::c_int;
    fn send(
        __fd: libc::c_int,
        __buf: *const libc::c_void,
        __n: size_t,
        __flags: libc::c_int,
    ) -> ssize_t;
    fn recv(
        __fd: libc::c_int,
        __buf: *mut libc::c_void,
        __n: size_t,
        __flags: libc::c_int,
    ) -> ssize_t;
    fn setsockopt(
        __fd: libc::c_int,
        __level: libc::c_int,
        __optname: libc::c_int,
        __optval: *const libc::c_void,
        __optlen: socklen_t,
    ) -> libc::c_int;
    fn shutdown(__fd: libc::c_int, __how: libc::c_int) -> libc::c_int;
    fn close(__fd: libc::c_int) -> libc::c_int;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn bio_ip_and_port_to_socket_and_addr(
        out_sock: *mut libc::c_int,
        out_addr: *mut sockaddr_storage,
        out_addr_length: *mut socklen_t,
        hostname: *const libc::c_char,
        port_str: *const libc::c_char,
    ) -> libc::c_int;
    fn bio_socket_nbio(sock: libc::c_int, on: libc::c_int) -> libc::c_int;
    fn bio_clear_socket_error(sock: libc::c_int);
    fn bio_sock_error_get_and_clear(sock: libc::c_int) -> libc::c_int;
    fn bio_socket_should_retry(return_value: libc::c_int) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __ssize_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_storage {
    pub ss_family: sa_family_t,
    pub __ss_padding: [libc::c_char; 118],
    pub __ss_align: libc::c_ulong,
}
pub type BIO_CONNECT = bio_connect_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bio_connect_st {
    pub state: libc::c_int,
    pub param_hostname: *mut libc::c_char,
    pub param_port: *mut libc::c_char,
    pub nbio: libc::c_int,
    pub port: libc::c_ushort,
    pub them: sockaddr_storage,
    pub them_length: socklen_t,
    pub info_callback: bio_info_cb,
}
pub const BIO_CONN_S_OK: C2RustUnnamed = 2;
pub const BIO_CONN_S_BEFORE: C2RustUnnamed = 0;
pub const BIO_CONN_S_BLOCKED_CONNECT: C2RustUnnamed = 1;
pub type C2RustUnnamed = libc::c_uint;
unsafe extern "C" fn closesocket(mut sock: libc::c_int) -> libc::c_int {
    return close(sock);
}
unsafe extern "C" fn split_host_and_port(
    mut out_host: *mut *mut libc::c_char,
    mut out_port: *mut *mut libc::c_char,
    mut name: *const libc::c_char,
) -> libc::c_int {
    let mut host: *const libc::c_char = 0 as *const libc::c_char;
    let mut port: *const libc::c_char = 0 as *const libc::c_char;
    let mut host_len: size_t = 0 as libc::c_int as size_t;
    *out_host = 0 as *mut libc::c_char;
    *out_port = 0 as *mut libc::c_char;
    if *name.offset(0 as libc::c_int as isize) as libc::c_int == '[' as i32 {
        let mut close_0: *const libc::c_char = strchr(name, ']' as i32);
        if close_0.is_null() {
            return 0 as libc::c_int;
        }
        host = name.offset(1 as libc::c_int as isize);
        host_len = close_0.offset_from(host) as libc::c_long as size_t;
        if *close_0.offset(1 as libc::c_int as isize) as libc::c_int == ':' as i32 {
            port = close_0.offset(2 as libc::c_int as isize);
        } else if *close_0.offset(1 as libc::c_int as isize) as libc::c_int
            != 0 as libc::c_int
        {
            return 0 as libc::c_int
        }
    } else {
        let mut colon: *const libc::c_char = strchr(name, ':' as i32);
        if colon.is_null()
            || !(strchr(colon.offset(1 as libc::c_int as isize), ':' as i32)).is_null()
        {
            host = name;
            host_len = strlen(name);
        } else {
            host = name;
            host_len = colon.offset_from(name) as libc::c_long as size_t;
            port = colon.offset(1 as libc::c_int as isize);
        }
    }
    *out_host = OPENSSL_strndup(host, host_len);
    if (*out_host).is_null() {
        return 0 as libc::c_int;
    }
    if port.is_null() {
        *out_port = 0 as *mut libc::c_char;
        return 1 as libc::c_int;
    }
    *out_port = OPENSSL_strdup(port);
    if (*out_port).is_null() {
        OPENSSL_free(*out_host as *mut libc::c_void);
        *out_host = 0 as *mut libc::c_char;
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn conn_state(
    mut bio: *mut BIO,
    mut c: *mut BIO_CONNECT,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut i: libc::c_int = 0;
    let mut cb: bio_info_cb = None;
    if ((*c).info_callback).is_some() {
        cb = (*c).info_callback;
    }
    loop {
        match (*c).state {
            0 => {
                if ((*c).param_hostname).is_null() {
                    ERR_put_error(
                        17 as libc::c_int,
                        0 as libc::c_int,
                        108 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/connect.c\0"
                            as *const u8 as *const libc::c_char,
                        185 as libc::c_int as libc::c_uint,
                    );
                    current_block = 11738046884734774141;
                    break;
                } else {
                    if ((*c).param_port).is_null() {
                        let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
                        let mut port: *mut libc::c_char = 0 as *mut libc::c_char;
                        if split_host_and_port(&mut host, &mut port, (*c).param_hostname)
                            == 0 || port.is_null()
                        {
                            OPENSSL_free(host as *mut libc::c_void);
                            OPENSSL_free(port as *mut libc::c_void);
                            ERR_put_error(
                                17 as libc::c_int,
                                0 as libc::c_int,
                                109 as libc::c_int,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/connect.c\0"
                                    as *const u8 as *const libc::c_char,
                                195 as libc::c_int as libc::c_uint,
                            );
                            ERR_add_error_data(
                                2 as libc::c_int as libc::c_uint,
                                b"host=\0" as *const u8 as *const libc::c_char,
                                (*c).param_hostname,
                            );
                            current_block = 11738046884734774141;
                            break;
                        } else {
                            OPENSSL_free((*c).param_port as *mut libc::c_void);
                            (*c).param_port = port;
                            OPENSSL_free((*c).param_hostname as *mut libc::c_void);
                            (*c).param_hostname = host;
                        }
                    }
                    if bio_ip_and_port_to_socket_and_addr(
                        &mut (*bio).num,
                        &mut (*c).them,
                        &mut (*c).them_length,
                        (*c).param_hostname,
                        (*c).param_port,
                    ) == 0
                    {
                        ERR_put_error(
                            17 as libc::c_int,
                            0 as libc::c_int,
                            113 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/connect.c\0"
                                as *const u8 as *const libc::c_char,
                            209 as libc::c_int as libc::c_uint,
                        );
                        ERR_add_error_data(
                            4 as libc::c_int as libc::c_uint,
                            b"host=\0" as *const u8 as *const libc::c_char,
                            (*c).param_hostname,
                            b":\0" as *const u8 as *const libc::c_char,
                            (*c).param_port,
                        );
                        current_block = 11738046884734774141;
                        break;
                    } else {
                        if (*c).nbio != 0 {
                            if bio_socket_nbio((*bio).num, 1 as libc::c_int) == 0 {
                                ERR_put_error(
                                    17 as libc::c_int,
                                    0 as libc::c_int,
                                    103 as libc::c_int,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/connect.c\0"
                                        as *const u8 as *const libc::c_char,
                                    216 as libc::c_int as libc::c_uint,
                                );
                                ERR_add_error_data(
                                    4 as libc::c_int as libc::c_uint,
                                    b"host=\0" as *const u8 as *const libc::c_char,
                                    (*c).param_hostname,
                                    b":\0" as *const u8 as *const libc::c_char,
                                    (*c).param_port,
                                );
                                current_block = 11738046884734774141;
                                break;
                            }
                        }
                        i = 1 as libc::c_int;
                        ret = setsockopt(
                            (*bio).num,
                            1 as libc::c_int,
                            9 as libc::c_int,
                            &mut i as *mut libc::c_int as *mut libc::c_char
                                as *const libc::c_void,
                            ::core::mem::size_of::<libc::c_int>() as libc::c_ulong
                                as socklen_t,
                        );
                        if ret < 0 as libc::c_int {
                            ERR_put_error(
                                2 as libc::c_int,
                                0 as libc::c_int,
                                0 as libc::c_int,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/connect.c\0"
                                    as *const u8 as *const libc::c_char,
                                227 as libc::c_int as libc::c_uint,
                            );
                            ERR_put_error(
                                17 as libc::c_int,
                                0 as libc::c_int,
                                106 as libc::c_int,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/connect.c\0"
                                    as *const u8 as *const libc::c_char,
                                228 as libc::c_int as libc::c_uint,
                            );
                            ERR_add_error_data(
                                4 as libc::c_int as libc::c_uint,
                                b"host=\0" as *const u8 as *const libc::c_char,
                                (*c).param_hostname,
                                b":\0" as *const u8 as *const libc::c_char,
                                (*c).param_port,
                            );
                            current_block = 11738046884734774141;
                            break;
                        } else {
                            BIO_clear_retry_flags(bio);
                            ret = connect(
                                (*bio).num,
                                &mut (*c).them as *mut sockaddr_storage as *mut sockaddr,
                                (*c).them_length,
                            );
                            if ret < 0 as libc::c_int {
                                if bio_socket_should_retry(ret) != 0 {
                                    BIO_set_flags(bio, 0x4 as libc::c_int | 0x8 as libc::c_int);
                                    (*c).state = BIO_CONN_S_BLOCKED_CONNECT as libc::c_int;
                                    (*bio).retry_reason = 0x2 as libc::c_int;
                                } else {
                                    ERR_put_error(
                                        2 as libc::c_int,
                                        0 as libc::c_int,
                                        0 as libc::c_int,
                                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/connect.c\0"
                                            as *const u8 as *const libc::c_char,
                                        241 as libc::c_int as libc::c_uint,
                                    );
                                    ERR_put_error(
                                        17 as libc::c_int,
                                        0 as libc::c_int,
                                        102 as libc::c_int,
                                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/connect.c\0"
                                            as *const u8 as *const libc::c_char,
                                        242 as libc::c_int as libc::c_uint,
                                    );
                                    ERR_add_error_data(
                                        4 as libc::c_int as libc::c_uint,
                                        b"host=\0" as *const u8 as *const libc::c_char,
                                        (*c).param_hostname,
                                        b":\0" as *const u8 as *const libc::c_char,
                                        (*c).param_port,
                                    );
                                }
                                current_block = 11738046884734774141;
                                break;
                            } else {
                                (*c).state = BIO_CONN_S_OK as libc::c_int;
                            }
                        }
                    }
                }
            }
            1 => {
                i = bio_sock_error_get_and_clear((*bio).num);
                if i != 0 {
                    if bio_socket_should_retry(ret) != 0 {
                        BIO_set_flags(bio, 0x4 as libc::c_int | 0x8 as libc::c_int);
                        (*c).state = BIO_CONN_S_BLOCKED_CONNECT as libc::c_int;
                        (*bio).retry_reason = 0x2 as libc::c_int;
                        ret = -(1 as libc::c_int);
                    } else {
                        BIO_clear_retry_flags(bio);
                        ERR_put_error(
                            2 as libc::c_int,
                            0 as libc::c_int,
                            0 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/connect.c\0"
                                as *const u8 as *const libc::c_char,
                            262 as libc::c_int as libc::c_uint,
                        );
                        ERR_put_error(
                            17 as libc::c_int,
                            0 as libc::c_int,
                            107 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/connect.c\0"
                                as *const u8 as *const libc::c_char,
                            263 as libc::c_int as libc::c_uint,
                        );
                        ERR_add_error_data(
                            4 as libc::c_int as libc::c_uint,
                            b"host=\0" as *const u8 as *const libc::c_char,
                            (*c).param_hostname,
                            b":\0" as *const u8 as *const libc::c_char,
                            (*c).param_port,
                        );
                        ret = 0 as libc::c_int;
                    }
                    current_block = 11738046884734774141;
                    break;
                } else {
                    (*c).state = BIO_CONN_S_OK as libc::c_int;
                }
            }
            2 => {
                ret = 1 as libc::c_int;
                current_block = 11738046884734774141;
                break;
            }
            _ => {
                __assert_fail(
                    b"0\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/connect.c\0"
                        as *const u8 as *const libc::c_char,
                    277 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 37],
                        &[libc::c_char; 37],
                    >(b"int conn_state(BIO *, BIO_CONNECT *)\0"))
                        .as_ptr(),
                );
                'c_5957: {
                    __assert_fail(
                        b"0\0" as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/connect.c\0"
                            as *const u8 as *const libc::c_char,
                        277 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 37],
                            &[libc::c_char; 37],
                        >(b"int conn_state(BIO *, BIO_CONNECT *)\0"))
                            .as_ptr(),
                    );
                };
                current_block = 11738046884734774141;
                break;
            }
        }
        if !cb.is_some() {
            continue;
        }
        ret = cb.expect("non-null function pointer")(bio, (*c).state, ret)
            as libc::c_int;
        if ret == 0 as libc::c_int {
            current_block = 14952600875841957798;
            break;
        }
    }
    match current_block {
        11738046884734774141 => {
            if cb.is_some() {
                ret = cb.expect("non-null function pointer")(bio, (*c).state, ret)
                    as libc::c_int;
            }
        }
        _ => {}
    }
    return ret;
}
unsafe extern "C" fn BIO_CONNECT_new() -> *mut BIO_CONNECT {
    let mut ret: *mut BIO_CONNECT = OPENSSL_zalloc(
        ::core::mem::size_of::<BIO_CONNECT>() as libc::c_ulong,
    ) as *mut BIO_CONNECT;
    if ret.is_null() {
        return 0 as *mut BIO_CONNECT;
    }
    (*ret).state = BIO_CONN_S_BEFORE as libc::c_int;
    return ret;
}
unsafe extern "C" fn BIO_CONNECT_free(mut c: *mut BIO_CONNECT) {
    if c.is_null() {
        return;
    }
    OPENSSL_free((*c).param_hostname as *mut libc::c_void);
    OPENSSL_free((*c).param_port as *mut libc::c_void);
    OPENSSL_free(c as *mut libc::c_void);
}
unsafe extern "C" fn conn_new(mut bio: *mut BIO) -> libc::c_int {
    (*bio).init = 0 as libc::c_int;
    (*bio).num = -(1 as libc::c_int);
    (*bio).flags = 0 as libc::c_int;
    (*bio).ptr = BIO_CONNECT_new() as *mut libc::c_void;
    return ((*bio).ptr != 0 as *mut libc::c_void) as libc::c_int;
}
unsafe extern "C" fn conn_close_socket(mut bio: *mut BIO) {
    let mut c: *mut BIO_CONNECT = (*bio).ptr as *mut BIO_CONNECT;
    if (*bio).num == -(1 as libc::c_int) {
        return;
    }
    if (*c).state == BIO_CONN_S_OK as libc::c_int {
        shutdown((*bio).num, 2 as libc::c_int);
    }
    closesocket((*bio).num);
    (*bio).num = -(1 as libc::c_int);
}
unsafe extern "C" fn conn_free(mut bio: *mut BIO) -> libc::c_int {
    if (*bio).shutdown != 0 {
        conn_close_socket(bio);
    }
    BIO_CONNECT_free((*bio).ptr as *mut BIO_CONNECT);
    return 1 as libc::c_int;
}
unsafe extern "C" fn conn_read(
    mut bio: *mut BIO,
    mut out: *mut libc::c_char,
    mut out_len: libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut data: *mut BIO_CONNECT = 0 as *mut BIO_CONNECT;
    data = (*bio).ptr as *mut BIO_CONNECT;
    if (*data).state != BIO_CONN_S_OK as libc::c_int {
        ret = conn_state(bio, data);
        if ret <= 0 as libc::c_int {
            return ret;
        }
    }
    bio_clear_socket_error((*bio).num);
    ret = recv((*bio).num, out as *mut libc::c_void, out_len as size_t, 0 as libc::c_int)
        as libc::c_int;
    BIO_clear_retry_flags(bio);
    if ret <= 0 as libc::c_int {
        if bio_socket_should_retry(ret) != 0 {
            BIO_set_retry_read(bio);
        }
    }
    return ret;
}
unsafe extern "C" fn conn_write(
    mut bio: *mut BIO,
    mut in_0: *const libc::c_char,
    mut in_len: libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    let mut data: *mut BIO_CONNECT = 0 as *mut BIO_CONNECT;
    data = (*bio).ptr as *mut BIO_CONNECT;
    if (*data).state != BIO_CONN_S_OK as libc::c_int {
        ret = conn_state(bio, data);
        if ret <= 0 as libc::c_int {
            return ret;
        }
    }
    bio_clear_socket_error((*bio).num);
    ret = send(
        (*bio).num,
        in_0 as *const libc::c_void,
        in_len as size_t,
        0 as libc::c_int,
    ) as libc::c_int;
    BIO_clear_retry_flags(bio);
    if ret <= 0 as libc::c_int {
        if bio_socket_should_retry(ret) != 0 {
            BIO_set_retry_write(bio);
        }
    }
    return ret;
}
unsafe extern "C" fn conn_ctrl(
    mut bio: *mut BIO,
    mut cmd: libc::c_int,
    mut num: libc::c_long,
    mut ptr: *mut libc::c_void,
) -> libc::c_long {
    let mut ip: *mut libc::c_int = 0 as *mut libc::c_int;
    let mut ret: libc::c_long = 1 as libc::c_int as libc::c_long;
    let mut data: *mut BIO_CONNECT = 0 as *mut BIO_CONNECT;
    data = (*bio).ptr as *mut BIO_CONNECT;
    match cmd {
        1 => {
            ret = 0 as libc::c_int as libc::c_long;
            (*data).state = BIO_CONN_S_BEFORE as libc::c_int;
            conn_close_socket(bio);
            (*bio).flags = 0 as libc::c_int;
        }
        101 => {
            if (*data).state != BIO_CONN_S_OK as libc::c_int {
                ret = conn_state(bio, data) as libc::c_long;
            } else {
                ret = 1 as libc::c_int as libc::c_long;
            }
        }
        100 => {
            if !ptr.is_null() {
                (*bio).init = 1 as libc::c_int;
                if num == 0 as libc::c_int as libc::c_long {
                    OPENSSL_free((*data).param_hostname as *mut libc::c_void);
                    (*data).param_hostname = OPENSSL_strdup(ptr as *const libc::c_char);
                    if ((*data).param_hostname).is_null() {
                        ret = 0 as libc::c_int as libc::c_long;
                    }
                } else if num == 1 as libc::c_int as libc::c_long {
                    OPENSSL_free((*data).param_port as *mut libc::c_void);
                    (*data).param_port = OPENSSL_strdup(ptr as *const libc::c_char);
                    if ((*data).param_port).is_null() {
                        ret = 0 as libc::c_int as libc::c_long;
                    }
                } else {
                    ret = 0 as libc::c_int as libc::c_long;
                }
            }
        }
        102 => {
            (*data).nbio = num as libc::c_int;
        }
        105 => {
            if (*bio).init != 0 {
                ip = ptr as *mut libc::c_int;
                if !ip.is_null() {
                    *ip = (*bio).num;
                }
                ret = (*bio).num as libc::c_long;
            } else {
                ret = -(1 as libc::c_int) as libc::c_long;
            }
        }
        8 => {
            ret = (*bio).shutdown as libc::c_long;
        }
        9 => {
            (*bio).shutdown = num as libc::c_int;
        }
        10 | 13 => {
            ret = 0 as libc::c_int as libc::c_long;
        }
        11 => {}
        15 => {
            let mut fptr: *mut bio_info_cb = ptr as *mut bio_info_cb;
            *fptr = (*data).info_callback;
        }
        _ => {
            ret = 0 as libc::c_int as libc::c_long;
        }
    }
    return ret;
}
unsafe extern "C" fn conn_callback_ctrl(
    mut bio: *mut BIO,
    mut cmd: libc::c_int,
    mut fp: bio_info_cb,
) -> libc::c_long {
    let mut ret: libc::c_long = 1 as libc::c_int as libc::c_long;
    let mut data: *mut BIO_CONNECT = 0 as *mut BIO_CONNECT;
    data = (*bio).ptr as *mut BIO_CONNECT;
    match cmd {
        14 => {
            (*data).info_callback = fp;
        }
        _ => {
            ret = 0 as libc::c_int as libc::c_long;
        }
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_new_connect(mut hostname: *const libc::c_char) -> *mut BIO {
    let mut ret: *mut BIO = 0 as *mut BIO;
    ret = BIO_new(BIO_s_connect());
    if ret.is_null() {
        return 0 as *mut BIO;
    }
    if BIO_set_conn_hostname(ret, hostname) == 0 {
        BIO_free(ret);
        return 0 as *mut BIO;
    }
    return ret;
}
static mut methods_connectp: BIO_METHOD = unsafe {
    {
        let mut init = bio_method_st {
            type_0: 12 as libc::c_int | 0x400 as libc::c_int | 0x100 as libc::c_int,
            name: b"socket connect\0" as *const u8 as *const libc::c_char,
            bwrite: Some(
                conn_write
                    as unsafe extern "C" fn(
                        *mut BIO,
                        *const libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            bread: Some(
                conn_read
                    as unsafe extern "C" fn(
                        *mut BIO,
                        *mut libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            bputs: None,
            bgets: None,
            ctrl: Some(
                conn_ctrl
                    as unsafe extern "C" fn(
                        *mut BIO,
                        libc::c_int,
                        libc::c_long,
                        *mut libc::c_void,
                    ) -> libc::c_long,
            ),
            create: Some(conn_new as unsafe extern "C" fn(*mut BIO) -> libc::c_int),
            destroy: Some(conn_free as unsafe extern "C" fn(*mut BIO) -> libc::c_int),
            callback_ctrl: Some(
                conn_callback_ctrl
                    as unsafe extern "C" fn(
                        *mut BIO,
                        libc::c_int,
                        bio_info_cb,
                    ) -> libc::c_long,
            ),
        };
        init
    }
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_s_connect() -> *const BIO_METHOD {
    return &methods_connectp;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_set_conn_hostname(
    mut bio: *mut BIO,
    mut name: *const libc::c_char,
) -> libc::c_int {
    return BIO_ctrl(
        bio,
        100 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        name as *mut libc::c_void,
    ) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_set_conn_port(
    mut bio: *mut BIO,
    mut port_str: *const libc::c_char,
) -> libc::c_int {
    return BIO_ctrl(
        bio,
        100 as libc::c_int,
        1 as libc::c_int as libc::c_long,
        port_str as *mut libc::c_void,
    ) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_set_conn_int_port(
    mut bio: *mut BIO,
    mut port: *const libc::c_int,
) -> libc::c_int {
    let mut buf: [libc::c_char; 13] = [0; 13];
    snprintf(
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 13]>() as libc::c_ulong,
        b"%d\0" as *const u8 as *const libc::c_char,
        *port,
    );
    return BIO_set_conn_port(bio, buf.as_mut_ptr());
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_set_nbio(
    mut bio: *mut BIO,
    mut on: libc::c_int,
) -> libc::c_int {
    return BIO_ctrl(bio, 102 as libc::c_int, on as libc::c_long, 0 as *mut libc::c_void)
        as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_do_connect(mut bio: *mut BIO) -> libc::c_int {
    return BIO_ctrl(
        bio,
        101 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        0 as *mut libc::c_void,
    ) as libc::c_int;
}
