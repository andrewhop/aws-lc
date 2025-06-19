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
    fn BIO_ctrl(
        bio: *mut BIO,
        cmd: libc::c_int,
        larg: libc::c_long,
        parg: *mut libc::c_void,
    ) -> libc::c_long;
    fn BIO_set_retry_read(bio: *mut BIO);
    fn BIO_clear_retry_flags(bio: *mut BIO);
    fn BUF_MEM_new() -> *mut BUF_MEM;
    fn BUF_MEM_free(buf: *mut BUF_MEM);
    fn BUF_MEM_append(
        buf: *mut BUF_MEM,
        in_0: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memmove(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memchr(
        _: *const libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
}
pub type ptrdiff_t = libc::c_long;
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type ossl_ssize_t = ptrdiff_t;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct buf_mem_st {
    pub length: size_t,
    pub data: *mut libc::c_char,
    pub max: size_t,
}
pub type BUF_MEM = buf_mem_st;
#[inline]
unsafe extern "C" fn OPENSSL_memchr(
    mut s: *const libc::c_void,
    mut c: libc::c_int,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return 0 as *mut libc::c_void;
    }
    return memchr(s, c, n);
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
#[inline]
unsafe extern "C" fn OPENSSL_memmove(
    mut dst: *mut libc::c_void,
    mut src: *const libc::c_void,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return dst;
    }
    return memmove(dst, src, n);
}
#[no_mangle]
pub unsafe extern "C" fn BIO_new_mem_buf(
    mut buf: *const libc::c_void,
    mut len: ossl_ssize_t,
) -> *mut BIO {
    let mut ret: *mut BIO = 0 as *mut BIO;
    let mut b: *mut BUF_MEM = 0 as *mut BUF_MEM;
    if buf.is_null() && len != 0 as libc::c_int as ossl_ssize_t {
        ERR_put_error(
            17 as libc::c_int,
            0 as libc::c_int,
            111 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio_mem.c\0" as *const u8
                as *const libc::c_char,
            74 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut BIO;
    }
    let size: size_t = if len < 0 as libc::c_int as ossl_ssize_t {
        strlen(buf as *mut libc::c_char)
    } else {
        len as size_t
    };
    ret = BIO_new(BIO_s_mem());
    if ret.is_null() {
        return 0 as *mut BIO;
    }
    b = (*ret).ptr as *mut BUF_MEM;
    (*b).data = buf as *mut libc::c_void as *mut libc::c_char;
    (*b).length = size;
    (*b).max = size;
    (*ret).flags |= 0x200 as libc::c_int;
    (*ret).num = 0 as libc::c_int;
    return ret;
}
unsafe extern "C" fn mem_new(mut bio: *mut BIO) -> libc::c_int {
    let mut b: *mut BUF_MEM = 0 as *mut BUF_MEM;
    b = BUF_MEM_new();
    if b.is_null() {
        return 0 as libc::c_int;
    }
    (*bio).shutdown = 1 as libc::c_int;
    (*bio).init = 1 as libc::c_int;
    (*bio).num = -(1 as libc::c_int);
    (*bio).ptr = b as *mut libc::c_char as *mut libc::c_void;
    return 1 as libc::c_int;
}
unsafe extern "C" fn mem_free(mut bio: *mut BIO) -> libc::c_int {
    if (*bio).shutdown == 0 || (*bio).init == 0 || ((*bio).ptr).is_null() {
        return 1 as libc::c_int;
    }
    let mut b: *mut BUF_MEM = (*bio).ptr as *mut BUF_MEM;
    if (*bio).flags & 0x200 as libc::c_int != 0 {
        (*b).data = 0 as *mut libc::c_char;
    }
    BUF_MEM_free(b);
    (*bio).ptr = 0 as *mut libc::c_void;
    return 1 as libc::c_int;
}
unsafe extern "C" fn mem_read(
    mut bio: *mut BIO,
    mut out: *mut libc::c_char,
    mut outl: libc::c_int,
) -> libc::c_int {
    BIO_clear_retry_flags(bio);
    if outl <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut b: *mut BUF_MEM = (*bio).ptr as *mut BUF_MEM;
    let mut ret: libc::c_int = outl;
    if ret as size_t > (*b).length {
        ret = (*b).length as libc::c_int;
    }
    if ret > 0 as libc::c_int {
        OPENSSL_memcpy(
            out as *mut libc::c_void,
            (*b).data as *const libc::c_void,
            ret as size_t,
        );
        (*b).length = ((*b).length).wrapping_sub(ret as size_t);
        if (*bio).flags & 0x200 as libc::c_int != 0 {
            (*b).data = ((*b).data).offset(ret as isize);
        } else {
            OPENSSL_memmove(
                (*b).data as *mut libc::c_void,
                &mut *((*b).data).offset(ret as isize) as *mut libc::c_char
                    as *const libc::c_void,
                (*b).length,
            );
        }
    } else if (*b).length == 0 as libc::c_int as size_t {
        ret = (*bio).num;
        if ret != 0 as libc::c_int {
            BIO_set_retry_read(bio);
        }
    }
    return ret;
}
unsafe extern "C" fn mem_write(
    mut bio: *mut BIO,
    mut in_0: *const libc::c_char,
    mut inl: libc::c_int,
) -> libc::c_int {
    BIO_clear_retry_flags(bio);
    if inl <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if (*bio).flags & 0x200 as libc::c_int != 0 {
        ERR_put_error(
            17 as libc::c_int,
            0 as libc::c_int,
            116 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/bio_mem.c\0" as *const u8
                as *const libc::c_char,
            169 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    let mut b: *mut BUF_MEM = (*bio).ptr as *mut BUF_MEM;
    if BUF_MEM_append(b, in_0 as *const libc::c_void, inl as size_t) == 0 {
        return -(1 as libc::c_int);
    }
    return inl;
}
unsafe extern "C" fn mem_gets(
    mut bio: *mut BIO,
    mut buf: *mut libc::c_char,
    mut size: libc::c_int,
) -> libc::c_int {
    BIO_clear_retry_flags(bio);
    if size <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut b: *mut BUF_MEM = (*bio).ptr as *mut BUF_MEM;
    let mut ret: libc::c_int = size - 1 as libc::c_int;
    if ret as size_t > (*b).length {
        ret = (*b).length as libc::c_int;
    }
    let mut newline: *const libc::c_char = OPENSSL_memchr(
        (*b).data as *const libc::c_void,
        '\n' as i32,
        ret as size_t,
    ) as *const libc::c_char;
    if !newline.is_null() {
        ret = (newline.offset_from((*b).data) as libc::c_long
            + 1 as libc::c_int as libc::c_long) as libc::c_int;
    }
    ret = mem_read(bio, buf, ret);
    if ret >= 0 as libc::c_int {
        *buf.offset(ret as isize) = '\0' as i32 as libc::c_char;
    }
    return ret;
}
unsafe extern "C" fn mem_ctrl(
    mut bio: *mut BIO,
    mut cmd: libc::c_int,
    mut num: libc::c_long,
    mut ptr: *mut libc::c_void,
) -> libc::c_long {
    let mut ret: libc::c_long = 1 as libc::c_int as libc::c_long;
    let mut b: *mut BUF_MEM = (*bio).ptr as *mut BUF_MEM;
    match cmd {
        1 => {
            if !((*b).data).is_null() {
                if (*bio).flags & 0x200 as libc::c_int != 0 {
                    (*b)
                        .data = ((*b).data)
                        .offset(-(((*b).max).wrapping_sub((*b).length) as isize));
                    (*b).length = (*b).max;
                } else {
                    OPENSSL_cleanse((*b).data as *mut libc::c_void, (*b).max);
                    (*b).length = 0 as libc::c_int as size_t;
                }
            }
        }
        2 => {
            ret = ((*b).length == 0 as libc::c_int as size_t) as libc::c_int
                as libc::c_long;
        }
        130 => {
            (*bio).num = num as libc::c_int;
        }
        3 => {
            ret = (*b).length as libc::c_long;
            if !ptr.is_null() {
                let mut pptr: *mut *mut libc::c_char = ptr as *mut *mut libc::c_char;
                *pptr = (*b).data;
            }
        }
        114 => {
            mem_free(bio);
            (*bio).shutdown = num as libc::c_int;
            (*bio).ptr = ptr;
        }
        115 => {
            if !ptr.is_null() {
                let mut pptr_0: *mut *mut BUF_MEM = ptr as *mut *mut BUF_MEM;
                *pptr_0 = b;
            }
        }
        8 => {
            ret = (*bio).shutdown as libc::c_long;
        }
        9 => {
            (*bio).shutdown = num as libc::c_int;
        }
        13 => {
            ret = 0 as libc::c_long;
        }
        10 => {
            ret = (*b).length as libc::c_long;
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
static mut mem_method: BIO_METHOD = unsafe {
    {
        let mut init = bio_method_st {
            type_0: 1 as libc::c_int | 0x400 as libc::c_int,
            name: b"memory buffer\0" as *const u8 as *const libc::c_char,
            bwrite: Some(
                mem_write
                    as unsafe extern "C" fn(
                        *mut BIO,
                        *const libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            bread: Some(
                mem_read
                    as unsafe extern "C" fn(
                        *mut BIO,
                        *mut libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            bputs: None,
            bgets: Some(
                mem_gets
                    as unsafe extern "C" fn(
                        *mut BIO,
                        *mut libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            ctrl: Some(
                mem_ctrl
                    as unsafe extern "C" fn(
                        *mut BIO,
                        libc::c_int,
                        libc::c_long,
                        *mut libc::c_void,
                    ) -> libc::c_long,
            ),
            create: Some(mem_new as unsafe extern "C" fn(*mut BIO) -> libc::c_int),
            destroy: Some(mem_free as unsafe extern "C" fn(*mut BIO) -> libc::c_int),
            callback_ctrl: None,
        };
        init
    }
};
#[no_mangle]
pub unsafe extern "C" fn BIO_s_mem() -> *const BIO_METHOD {
    return &mem_method;
}
#[no_mangle]
pub unsafe extern "C" fn BIO_mem_contents(
    mut bio: *const BIO,
    mut out_contents: *mut *const uint8_t,
    mut out_len: *mut size_t,
) -> libc::c_int {
    let mut b: *const BUF_MEM = 0 as *const BUF_MEM;
    if bio.is_null() || (*bio).method != &mem_method as *const BIO_METHOD {
        return 0 as libc::c_int;
    }
    b = (*bio).ptr as *mut BUF_MEM;
    if !out_contents.is_null() {
        *out_contents = (*b).data as *mut uint8_t;
    }
    if !out_len.is_null() {
        *out_len = (*b).length;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn BIO_get_mem_ptr(
    mut bio: *mut BIO,
    mut out: *mut *mut BUF_MEM,
) -> libc::c_int {
    return BIO_ctrl(
        bio,
        115 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        out as *mut libc::c_void,
    ) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn BIO_set_mem_buf(
    mut bio: *mut BIO,
    mut b: *mut BUF_MEM,
    mut take_ownership: libc::c_int,
) -> libc::c_int {
    return BIO_ctrl(
        bio,
        114 as libc::c_int,
        take_ownership as libc::c_long,
        b as *mut libc::c_void,
    ) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn BIO_set_mem_eof_return(
    mut bio: *mut BIO,
    mut eof_value: libc::c_int,
) -> libc::c_int {
    return BIO_ctrl(
        bio,
        130 as libc::c_int,
        eof_value as libc::c_long,
        0 as *mut libc::c_void,
    ) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn BIO_s_secmem() -> *const BIO_METHOD {
    return BIO_s_mem();
}
