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
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_realloc(ptr: *mut libc::c_void, new_size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_strdup(s: *const libc::c_char) -> *mut libc::c_char;
    fn OPENSSL_strnlen(s: *const libc::c_char, len: size_t) -> size_t;
    fn OPENSSL_strndup(str: *const libc::c_char, size: size_t) -> *mut libc::c_char;
    fn OPENSSL_memdup(data: *const libc::c_void, size: size_t) -> *mut libc::c_void;
    fn OPENSSL_strlcpy(
        dst: *mut libc::c_char,
        src: *const libc::c_char,
        dst_size: size_t,
    ) -> size_t;
    fn OPENSSL_strlcat(
        dst: *mut libc::c_char,
        src: *const libc::c_char,
        dst_size: size_t,
    ) -> size_t;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
}
pub type size_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct buf_mem_st {
    pub length: size_t,
    pub data: *mut libc::c_char,
    pub max: size_t,
}
pub type BUF_MEM = buf_mem_st;
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
#[no_mangle]
pub unsafe extern "C" fn BUF_MEM_new() -> *mut BUF_MEM {
    return OPENSSL_zalloc(::core::mem::size_of::<BUF_MEM>() as libc::c_ulong)
        as *mut BUF_MEM;
}
#[no_mangle]
pub unsafe extern "C" fn BUF_MEM_free(mut buf: *mut BUF_MEM) {
    if buf.is_null() {
        return;
    }
    OPENSSL_free((*buf).data as *mut libc::c_void);
    OPENSSL_free(buf as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn BUF_MEM_reserve(
    mut buf: *mut BUF_MEM,
    mut cap: size_t,
) -> libc::c_int {
    if (*buf).max >= cap {
        return 1 as libc::c_int;
    }
    let mut n: size_t = cap.wrapping_add(3 as libc::c_int as size_t);
    if n < cap {
        ERR_put_error(
            7 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/buf/buf.c\0" as *const u8
                as *const libc::c_char,
            85 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    n = n / 3 as libc::c_int as size_t;
    let mut alloc_size: size_t = n * 4 as libc::c_int as size_t;
    if alloc_size / 4 as libc::c_int as size_t != n {
        ERR_put_error(
            7 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/buf/buf.c\0" as *const u8
                as *const libc::c_char,
            91 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut new_buf: *mut libc::c_char = OPENSSL_realloc(
        (*buf).data as *mut libc::c_void,
        alloc_size,
    ) as *mut libc::c_char;
    if new_buf.is_null() {
        return 0 as libc::c_int;
    }
    (*buf).data = new_buf;
    (*buf).max = alloc_size;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn BUF_MEM_grow(mut buf: *mut BUF_MEM, mut len: size_t) -> size_t {
    if BUF_MEM_reserve(buf, len) == 0 {
        return 0 as libc::c_int as size_t;
    }
    if (*buf).length < len {
        OPENSSL_memset(
            &mut *((*buf).data).offset((*buf).length as isize) as *mut libc::c_char
                as *mut libc::c_void,
            0 as libc::c_int,
            len.wrapping_sub((*buf).length),
        );
    }
    (*buf).length = len;
    return len;
}
#[no_mangle]
pub unsafe extern "C" fn BUF_MEM_grow_clean(
    mut buf: *mut BUF_MEM,
    mut len: size_t,
) -> size_t {
    return BUF_MEM_grow(buf, len);
}
#[no_mangle]
pub unsafe extern "C" fn BUF_MEM_append(
    mut buf: *mut BUF_MEM,
    mut in_0: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    if len == 0 as libc::c_int as size_t {
        return 1 as libc::c_int;
    }
    let mut new_len: size_t = ((*buf).length).wrapping_add(len);
    if new_len < len {
        ERR_put_error(
            7 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/buf/buf.c\0" as *const u8
                as *const libc::c_char,
            127 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if BUF_MEM_reserve(buf, new_len) == 0 {
        return 0 as libc::c_int;
    }
    OPENSSL_memcpy(
        ((*buf).data).offset((*buf).length as isize) as *mut libc::c_void,
        in_0,
        len,
    );
    (*buf).length = new_len;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn BUF_strdup(mut str: *const libc::c_char) -> *mut libc::c_char {
    return OPENSSL_strdup(str);
}
#[no_mangle]
pub unsafe extern "C" fn BUF_strnlen(
    mut str: *const libc::c_char,
    mut max_len: size_t,
) -> size_t {
    return OPENSSL_strnlen(str, max_len);
}
#[no_mangle]
pub unsafe extern "C" fn BUF_strndup(
    mut str: *const libc::c_char,
    mut size: size_t,
) -> *mut libc::c_char {
    return OPENSSL_strndup(str, size);
}
#[no_mangle]
pub unsafe extern "C" fn BUF_strlcpy(
    mut dst: *mut libc::c_char,
    mut src: *const libc::c_char,
    mut dst_size: size_t,
) -> size_t {
    return OPENSSL_strlcpy(dst, src, dst_size);
}
#[no_mangle]
pub unsafe extern "C" fn BUF_strlcat(
    mut dst: *mut libc::c_char,
    mut src: *const libc::c_char,
    mut dst_size: size_t,
) -> size_t {
    return OPENSSL_strlcat(dst, src, dst_size);
}
#[no_mangle]
pub unsafe extern "C" fn BUF_memdup(
    mut data: *const libc::c_void,
    mut size: size_t,
) -> *mut libc::c_void {
    return OPENSSL_memdup(data, size);
}
