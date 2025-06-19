#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(extern_types, label_break_value)]
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
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
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
pub struct bio_bio_st {
    pub peer: *mut BIO,
    pub closed: libc::c_int,
    pub len: size_t,
    pub offset: size_t,
    pub size: size_t,
    pub buf: *mut uint8_t,
    pub request: size_t,
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
unsafe extern "C" fn bio_new(mut bio: *mut BIO) -> libc::c_int {
    let mut b: *mut bio_bio_st = OPENSSL_zalloc(
        ::core::mem::size_of::<bio_bio_st>() as libc::c_ulong,
    ) as *mut bio_bio_st;
    if b.is_null() {
        return 0 as libc::c_int;
    }
    (*b).size = (17 as libc::c_int * 1024 as libc::c_int) as size_t;
    (*bio).ptr = b as *mut libc::c_void;
    return 1 as libc::c_int;
}
unsafe extern "C" fn bio_destroy_pair(mut bio: *mut BIO) {
    let mut b: *mut bio_bio_st = (*bio).ptr as *mut bio_bio_st;
    let mut peer_bio: *mut BIO = 0 as *mut BIO;
    let mut peer_b: *mut bio_bio_st = 0 as *mut bio_bio_st;
    if b.is_null() {
        return;
    }
    peer_bio = (*b).peer;
    if peer_bio.is_null() {
        return;
    }
    peer_b = (*peer_bio).ptr as *mut bio_bio_st;
    if !peer_b.is_null() {} else {
        __assert_fail(
            b"peer_b != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                as *const libc::c_char,
            110 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 29],
                &[libc::c_char; 29],
            >(b"void bio_destroy_pair(BIO *)\0"))
                .as_ptr(),
        );
    }
    'c_5651: {
        if !peer_b.is_null() {} else {
            __assert_fail(
                b"peer_b != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                    as *const libc::c_char,
                110 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 29],
                    &[libc::c_char; 29],
                >(b"void bio_destroy_pair(BIO *)\0"))
                    .as_ptr(),
            );
        }
    };
    if (*peer_b).peer == bio {} else {
        __assert_fail(
            b"peer_b->peer == bio\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                as *const libc::c_char,
            111 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 29],
                &[libc::c_char; 29],
            >(b"void bio_destroy_pair(BIO *)\0"))
                .as_ptr(),
        );
    }
    'c_5609: {
        if (*peer_b).peer == bio {} else {
            __assert_fail(
                b"peer_b->peer == bio\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                    as *const libc::c_char,
                111 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 29],
                    &[libc::c_char; 29],
                >(b"void bio_destroy_pair(BIO *)\0"))
                    .as_ptr(),
            );
        }
    };
    (*peer_b).peer = 0 as *mut BIO;
    (*peer_bio).init = 0 as libc::c_int;
    if !((*peer_b).buf).is_null() {} else {
        __assert_fail(
            b"peer_b->buf != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                as *const libc::c_char,
            115 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 29],
                &[libc::c_char; 29],
            >(b"void bio_destroy_pair(BIO *)\0"))
                .as_ptr(),
        );
    }
    'c_5548: {
        if !((*peer_b).buf).is_null() {} else {
            __assert_fail(
                b"peer_b->buf != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                    as *const libc::c_char,
                115 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 29],
                    &[libc::c_char; 29],
                >(b"void bio_destroy_pair(BIO *)\0"))
                    .as_ptr(),
            );
        }
    };
    (*peer_b).len = 0 as libc::c_int as size_t;
    (*peer_b).offset = 0 as libc::c_int as size_t;
    (*b).peer = 0 as *mut BIO;
    (*bio).init = 0 as libc::c_int;
    if !((*b).buf).is_null() {} else {
        __assert_fail(
            b"b->buf != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                as *const libc::c_char,
            121 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 29],
                &[libc::c_char; 29],
            >(b"void bio_destroy_pair(BIO *)\0"))
                .as_ptr(),
        );
    }
    'c_5465: {
        if !((*b).buf).is_null() {} else {
            __assert_fail(
                b"b->buf != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                    as *const libc::c_char,
                121 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 29],
                    &[libc::c_char; 29],
                >(b"void bio_destroy_pair(BIO *)\0"))
                    .as_ptr(),
            );
        }
    };
    (*b).len = 0 as libc::c_int as size_t;
    (*b).offset = 0 as libc::c_int as size_t;
}
unsafe extern "C" fn bio_free(mut bio: *mut BIO) -> libc::c_int {
    let mut b: *mut bio_bio_st = (*bio).ptr as *mut bio_bio_st;
    if !b.is_null() {} else {
        __assert_fail(
            b"b != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                as *const libc::c_char,
            129 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 20],
                &[libc::c_char; 20],
            >(b"int bio_free(BIO *)\0"))
                .as_ptr(),
        );
    }
    'c_5727: {
        if !b.is_null() {} else {
            __assert_fail(
                b"b != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                    as *const libc::c_char,
                129 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 20],
                    &[libc::c_char; 20],
                >(b"int bio_free(BIO *)\0"))
                    .as_ptr(),
            );
        }
    };
    if !((*b).peer).is_null() {
        bio_destroy_pair(bio);
    }
    OPENSSL_free((*b).buf as *mut libc::c_void);
    OPENSSL_free(b as *mut libc::c_void);
    return 1 as libc::c_int;
}
unsafe extern "C" fn bio_read(
    mut bio: *mut BIO,
    mut buf: *mut libc::c_char,
    mut size_: libc::c_int,
) -> libc::c_int {
    let mut size: size_t = size_ as size_t;
    let mut rest: size_t = 0;
    let mut b: *mut bio_bio_st = 0 as *mut bio_bio_st;
    let mut peer_b: *mut bio_bio_st = 0 as *mut bio_bio_st;
    BIO_clear_retry_flags(bio);
    if (*bio).init == 0 {
        return 0 as libc::c_int;
    }
    b = (*bio).ptr as *mut bio_bio_st;
    if !b.is_null() {} else {
        __assert_fail(
            b"b != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                as *const libc::c_char,
            153 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 33],
                &[libc::c_char; 33],
            >(b"int bio_read(BIO *, char *, int)\0"))
                .as_ptr(),
        );
    }
    'c_6833: {
        if !b.is_null() {} else {
            __assert_fail(
                b"b != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                    as *const libc::c_char,
                153 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 33],
                    &[libc::c_char; 33],
                >(b"int bio_read(BIO *, char *, int)\0"))
                    .as_ptr(),
            );
        }
    };
    if !((*b).peer).is_null() {} else {
        __assert_fail(
            b"b->peer != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                as *const libc::c_char,
            154 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 33],
                &[libc::c_char; 33],
            >(b"int bio_read(BIO *, char *, int)\0"))
                .as_ptr(),
        );
    }
    'c_6786: {
        if !((*b).peer).is_null() {} else {
            __assert_fail(
                b"b->peer != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                    as *const libc::c_char,
                154 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 33],
                    &[libc::c_char; 33],
                >(b"int bio_read(BIO *, char *, int)\0"))
                    .as_ptr(),
            );
        }
    };
    peer_b = (*(*b).peer).ptr as *mut bio_bio_st;
    if !peer_b.is_null() {} else {
        __assert_fail(
            b"peer_b != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                as *const libc::c_char,
            156 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 33],
                &[libc::c_char; 33],
            >(b"int bio_read(BIO *, char *, int)\0"))
                .as_ptr(),
        );
    }
    'c_6734: {
        if !peer_b.is_null() {} else {
            __assert_fail(
                b"peer_b != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                    as *const libc::c_char,
                156 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 33],
                    &[libc::c_char; 33],
                >(b"int bio_read(BIO *, char *, int)\0"))
                    .as_ptr(),
            );
        }
    };
    if !((*peer_b).buf).is_null() {} else {
        __assert_fail(
            b"peer_b->buf != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                as *const libc::c_char,
            157 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 33],
                &[libc::c_char; 33],
            >(b"int bio_read(BIO *, char *, int)\0"))
                .as_ptr(),
        );
    }
    'c_6688: {
        if !((*peer_b).buf).is_null() {} else {
            __assert_fail(
                b"peer_b->buf != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                    as *const libc::c_char,
                157 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 33],
                    &[libc::c_char; 33],
                >(b"int bio_read(BIO *, char *, int)\0"))
                    .as_ptr(),
            );
        }
    };
    (*peer_b).request = 0 as libc::c_int as size_t;
    if buf.is_null() || size == 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    if (*peer_b).len == 0 as libc::c_int as size_t {
        if (*peer_b).closed != 0 {
            return 0 as libc::c_int
        } else {
            BIO_set_retry_read(bio);
            if size <= (*peer_b).size {
                (*peer_b).request = size;
            } else {
                (*peer_b).request = (*peer_b).size;
            }
            return -(1 as libc::c_int);
        }
    }
    if (*peer_b).len < size {
        size = (*peer_b).len;
    }
    rest = size;
    if rest > 0 as libc::c_int as size_t {} else {
        __assert_fail(
            b"rest > 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                as *const libc::c_char,
            189 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 33],
                &[libc::c_char; 33],
            >(b"int bio_read(BIO *, char *, int)\0"))
                .as_ptr(),
        );
    }
    'c_6556: {
        if rest > 0 as libc::c_int as size_t {} else {
            __assert_fail(
                b"rest > 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                    as *const libc::c_char,
                189 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 33],
                    &[libc::c_char; 33],
                >(b"int bio_read(BIO *, char *, int)\0"))
                    .as_ptr(),
            );
        }
    };
    loop {
        let mut chunk: size_t = 0;
        if rest <= (*peer_b).len {} else {
            __assert_fail(
                b"rest <= peer_b->len\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                    as *const libc::c_char,
                194 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 33],
                    &[libc::c_char; 33],
                >(b"int bio_read(BIO *, char *, int)\0"))
                    .as_ptr(),
            );
        }
        'c_6514: {
            if rest <= (*peer_b).len {} else {
                __assert_fail(
                    b"rest <= peer_b->len\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                        as *const libc::c_char,
                    194 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 33],
                        &[libc::c_char; 33],
                    >(b"int bio_read(BIO *, char *, int)\0"))
                        .as_ptr(),
                );
            }
        };
        if ((*peer_b).offset).wrapping_add(rest) <= (*peer_b).size {
            chunk = rest;
        } else {
            chunk = ((*peer_b).size).wrapping_sub((*peer_b).offset);
        }
        if ((*peer_b).offset).wrapping_add(chunk) <= (*peer_b).size {} else {
            __assert_fail(
                b"peer_b->offset + chunk <= peer_b->size\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                    as *const libc::c_char,
                201 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 33],
                    &[libc::c_char; 33],
                >(b"int bio_read(BIO *, char *, int)\0"))
                    .as_ptr(),
            );
        }
        'c_6430: {
            if ((*peer_b).offset).wrapping_add(chunk) <= (*peer_b).size {} else {
                __assert_fail(
                    b"peer_b->offset + chunk <= peer_b->size\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                        as *const libc::c_char,
                    201 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 33],
                        &[libc::c_char; 33],
                    >(b"int bio_read(BIO *, char *, int)\0"))
                        .as_ptr(),
                );
            }
        };
        OPENSSL_memcpy(
            buf as *mut libc::c_void,
            ((*peer_b).buf).offset((*peer_b).offset as isize) as *const libc::c_void,
            chunk,
        );
        (*peer_b).len = ((*peer_b).len).wrapping_sub(chunk);
        if (*peer_b).len != 0 {
            (*peer_b).offset = ((*peer_b).offset).wrapping_add(chunk);
            if (*peer_b).offset <= (*peer_b).size {} else {
                __assert_fail(
                    b"peer_b->offset <= peer_b->size\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                        as *const libc::c_char,
                    208 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 33],
                        &[libc::c_char; 33],
                    >(b"int bio_read(BIO *, char *, int)\0"))
                        .as_ptr(),
                );
            }
            'c_6317: {
                if (*peer_b).offset <= (*peer_b).size {} else {
                    __assert_fail(
                        b"peer_b->offset <= peer_b->size\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0"
                            as *const u8 as *const libc::c_char,
                        208 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 33],
                            &[libc::c_char; 33],
                        >(b"int bio_read(BIO *, char *, int)\0"))
                            .as_ptr(),
                    );
                }
            };
            if (*peer_b).offset == (*peer_b).size {
                (*peer_b).offset = 0 as libc::c_int as size_t;
            }
            buf = buf.offset(chunk as isize);
        } else {
            if chunk == rest {} else {
                __assert_fail(
                    b"chunk == rest\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                        as *const libc::c_char,
                    215 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 33],
                        &[libc::c_char; 33],
                    >(b"int bio_read(BIO *, char *, int)\0"))
                        .as_ptr(),
                );
            }
            'c_6252: {
                if chunk == rest {} else {
                    __assert_fail(
                        b"chunk == rest\0" as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0"
                            as *const u8 as *const libc::c_char,
                        215 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 33],
                            &[libc::c_char; 33],
                        >(b"int bio_read(BIO *, char *, int)\0"))
                            .as_ptr(),
                    );
                }
            };
            (*peer_b).offset = 0 as libc::c_int as size_t;
        }
        rest = rest.wrapping_sub(chunk);
        if !(rest != 0) {
            break;
        }
    }
    return size as libc::c_int;
}
unsafe extern "C" fn bio_write(
    mut bio: *mut BIO,
    mut buf: *const libc::c_char,
    mut num_: libc::c_int,
) -> libc::c_int {
    let mut num: size_t = num_ as size_t;
    let mut rest: size_t = 0;
    let mut b: *mut bio_bio_st = 0 as *mut bio_bio_st;
    BIO_clear_retry_flags(bio);
    if (*bio).init == 0 || buf.is_null() || num == 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    b = (*bio).ptr as *mut bio_bio_st;
    if !b.is_null() {} else {
        __assert_fail(
            b"b != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                as *const libc::c_char,
            237 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 40],
                &[libc::c_char; 40],
            >(b"int bio_write(BIO *, const char *, int)\0"))
                .as_ptr(),
        );
    }
    'c_7379: {
        if !b.is_null() {} else {
            __assert_fail(
                b"b != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                    as *const libc::c_char,
                237 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 40],
                    &[libc::c_char; 40],
                >(b"int bio_write(BIO *, const char *, int)\0"))
                    .as_ptr(),
            );
        }
    };
    if !((*b).peer).is_null() {} else {
        __assert_fail(
            b"b->peer != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                as *const libc::c_char,
            238 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 40],
                &[libc::c_char; 40],
            >(b"int bio_write(BIO *, const char *, int)\0"))
                .as_ptr(),
        );
    }
    'c_7333: {
        if !((*b).peer).is_null() {} else {
            __assert_fail(
                b"b->peer != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                    as *const libc::c_char,
                238 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 40],
                    &[libc::c_char; 40],
                >(b"int bio_write(BIO *, const char *, int)\0"))
                    .as_ptr(),
            );
        }
    };
    if !((*b).buf).is_null() {} else {
        __assert_fail(
            b"b->buf != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                as *const libc::c_char,
            239 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 40],
                &[libc::c_char; 40],
            >(b"int bio_write(BIO *, const char *, int)\0"))
                .as_ptr(),
        );
    }
    'c_7287: {
        if !((*b).buf).is_null() {} else {
            __assert_fail(
                b"b->buf != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                    as *const libc::c_char,
                239 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 40],
                    &[libc::c_char; 40],
                >(b"int bio_write(BIO *, const char *, int)\0"))
                    .as_ptr(),
            );
        }
    };
    (*b).request = 0 as libc::c_int as size_t;
    if (*b).closed != 0 {
        ERR_put_error(
            17 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                as *const libc::c_char,
            244 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    if (*b).len <= (*b).size {} else {
        __assert_fail(
            b"b->len <= b->size\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                as *const libc::c_char,
            248 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 40],
                &[libc::c_char; 40],
            >(b"int bio_write(BIO *, const char *, int)\0"))
                .as_ptr(),
        );
    }
    'c_7214: {
        if (*b).len <= (*b).size {} else {
            __assert_fail(
                b"b->len <= b->size\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                    as *const libc::c_char,
                248 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 40],
                    &[libc::c_char; 40],
                >(b"int bio_write(BIO *, const char *, int)\0"))
                    .as_ptr(),
            );
        }
    };
    if (*b).len == (*b).size {
        BIO_set_retry_write(bio);
        return -(1 as libc::c_int);
    }
    if num > ((*b).size).wrapping_sub((*b).len) {
        num = ((*b).size).wrapping_sub((*b).len);
    }
    rest = num;
    if rest > 0 as libc::c_int as size_t {} else {
        __assert_fail(
            b"rest > 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                as *const libc::c_char,
            263 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 40],
                &[libc::c_char; 40],
            >(b"int bio_write(BIO *, const char *, int)\0"))
                .as_ptr(),
        );
    }
    'c_7128: {
        if rest > 0 as libc::c_int as size_t {} else {
            __assert_fail(
                b"rest > 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                    as *const libc::c_char,
                263 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 40],
                    &[libc::c_char; 40],
                >(b"int bio_write(BIO *, const char *, int)\0"))
                    .as_ptr(),
            );
        }
    };
    loop {
        let mut write_offset: size_t = 0;
        let mut chunk: size_t = 0;
        if ((*b).len).wrapping_add(rest) <= (*b).size {} else {
            __assert_fail(
                b"b->len + rest <= b->size\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                    as *const libc::c_char,
                269 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 40],
                    &[libc::c_char; 40],
                >(b"int bio_write(BIO *, const char *, int)\0"))
                    .as_ptr(),
            );
        }
        'c_7075: {
            if ((*b).len).wrapping_add(rest) <= (*b).size {} else {
                __assert_fail(
                    b"b->len + rest <= b->size\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                        as *const libc::c_char,
                    269 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 40],
                        &[libc::c_char; 40],
                    >(b"int bio_write(BIO *, const char *, int)\0"))
                        .as_ptr(),
                );
            }
        };
        write_offset = ((*b).offset).wrapping_add((*b).len);
        if write_offset >= (*b).size {
            write_offset = write_offset.wrapping_sub((*b).size);
        }
        if write_offset.wrapping_add(rest) <= (*b).size {
            chunk = rest;
        } else {
            chunk = ((*b).size).wrapping_sub(write_offset);
        }
        OPENSSL_memcpy(
            ((*b).buf).offset(write_offset as isize) as *mut libc::c_void,
            buf as *const libc::c_void,
            chunk,
        );
        (*b).len = ((*b).len).wrapping_add(chunk);
        if (*b).len <= (*b).size {} else {
            __assert_fail(
                b"b->len <= b->size\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                    as *const libc::c_char,
                288 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 40],
                    &[libc::c_char; 40],
                >(b"int bio_write(BIO *, const char *, int)\0"))
                    .as_ptr(),
            );
        }
        'c_6951: {
            if (*b).len <= (*b).size {} else {
                __assert_fail(
                    b"b->len <= b->size\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                        as *const libc::c_char,
                    288 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 40],
                        &[libc::c_char; 40],
                    >(b"int bio_write(BIO *, const char *, int)\0"))
                        .as_ptr(),
                );
            }
        };
        rest = rest.wrapping_sub(chunk);
        buf = buf.offset(chunk as isize);
        if !(rest != 0) {
            break;
        }
    }
    return num as libc::c_int;
}
unsafe extern "C" fn bio_make_pair(
    mut bio1: *mut BIO,
    mut bio2: *mut BIO,
    mut writebuf1_len: size_t,
    mut writebuf2_len: size_t,
) -> libc::c_int {
    let mut b1: *mut bio_bio_st = 0 as *mut bio_bio_st;
    let mut b2: *mut bio_bio_st = 0 as *mut bio_bio_st;
    if !bio1.is_null() {} else {
        __assert_fail(
            b"bio1 != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                as *const libc::c_char,
            302 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 48],
                &[libc::c_char; 48],
            >(b"int bio_make_pair(BIO *, BIO *, size_t, size_t)\0"))
                .as_ptr(),
        );
    }
    'c_7810: {
        if !bio1.is_null() {} else {
            __assert_fail(
                b"bio1 != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                    as *const libc::c_char,
                302 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 48],
                    &[libc::c_char; 48],
                >(b"int bio_make_pair(BIO *, BIO *, size_t, size_t)\0"))
                    .as_ptr(),
            );
        }
    };
    if !bio2.is_null() {} else {
        __assert_fail(
            b"bio2 != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                as *const libc::c_char,
            303 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 48],
                &[libc::c_char; 48],
            >(b"int bio_make_pair(BIO *, BIO *, size_t, size_t)\0"))
                .as_ptr(),
        );
    }
    'c_7766: {
        if !bio2.is_null() {} else {
            __assert_fail(
                b"bio2 != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                    as *const libc::c_char,
                303 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 48],
                    &[libc::c_char; 48],
                >(b"int bio_make_pair(BIO *, BIO *, size_t, size_t)\0"))
                    .as_ptr(),
            );
        }
    };
    b1 = (*bio1).ptr as *mut bio_bio_st;
    b2 = (*bio2).ptr as *mut bio_bio_st;
    if !((*b1).peer).is_null() || !((*b2).peer).is_null() {
        ERR_put_error(
            17 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                as *const libc::c_char,
            309 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*b1).buf).is_null() {
        if writebuf1_len != 0 {
            (*b1).size = writebuf1_len;
        }
        (*b1).buf = OPENSSL_malloc((*b1).size) as *mut uint8_t;
        if ((*b1).buf).is_null() {
            return 0 as libc::c_int;
        }
        (*b1).len = 0 as libc::c_int as size_t;
        (*b1).offset = 0 as libc::c_int as size_t;
    }
    if ((*b2).buf).is_null() {
        if writebuf2_len != 0 {
            (*b2).size = writebuf2_len;
        }
        (*b2).buf = OPENSSL_malloc((*b2).size) as *mut uint8_t;
        if ((*b2).buf).is_null() {
            return 0 as libc::c_int;
        }
        (*b2).len = 0 as libc::c_int as size_t;
        (*b2).offset = 0 as libc::c_int as size_t;
    }
    (*b1).peer = bio2;
    (*b1).closed = 0 as libc::c_int;
    (*b1).request = 0 as libc::c_int as size_t;
    (*b2).peer = bio1;
    (*b2).closed = 0 as libc::c_int;
    (*b2).request = 0 as libc::c_int as size_t;
    (*bio1).init = 1 as libc::c_int;
    (*bio2).init = 1 as libc::c_int;
    return 1 as libc::c_int;
}
unsafe extern "C" fn bio_ctrl(
    mut bio: *mut BIO,
    mut cmd: libc::c_int,
    mut num: libc::c_long,
    mut ptr: *mut libc::c_void,
) -> libc::c_long {
    let mut ret: libc::c_long = 0;
    let mut b: *mut bio_bio_st = (*bio).ptr as *mut bio_bio_st;
    if !b.is_null() {} else {
        __assert_fail(
            b"b != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                as *const libc::c_char,
            354 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 40],
                &[libc::c_char; 40],
            >(b"long bio_ctrl(BIO *, int, long, void *)\0"))
                .as_ptr(),
        );
    }
    'c_6142: {
        if !b.is_null() {} else {
            __assert_fail(
                b"b != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0" as *const u8
                    as *const libc::c_char,
                354 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 40],
                    &[libc::c_char; 40],
                >(b"long bio_ctrl(BIO *, int, long, void *)\0"))
                    .as_ptr(),
            );
        }
    };
    match cmd {
        137 => {
            ret = (*b).size as libc::c_long;
        }
        140 => {
            if ((*b).peer).is_null() || (*b).closed != 0 {
                ret = 0 as libc::c_int as libc::c_long;
            } else {
                ret = ((*b).size as libc::c_long as size_t).wrapping_sub((*b).len)
                    as libc::c_long;
            }
        }
        141 => {
            ret = (*b).request as libc::c_long;
        }
        147 => {
            (*b).request = 0 as libc::c_int as size_t;
            ret = 1 as libc::c_int as libc::c_long;
        }
        142 => {
            (*b).closed = 1 as libc::c_int;
            ret = 1 as libc::c_int as libc::c_long;
        }
        8 => {
            ret = (*bio).shutdown as libc::c_long;
        }
        9 => {
            (*bio).shutdown = num as libc::c_int;
            ret = 1 as libc::c_int as libc::c_long;
        }
        10 => {
            if !((*b).peer).is_null() {
                let mut peer_b: *mut bio_bio_st = (*(*b).peer).ptr as *mut bio_bio_st;
                ret = (*peer_b).len as libc::c_long;
            } else {
                ret = 0 as libc::c_int as libc::c_long;
            }
        }
        13 => {
            ret = 0 as libc::c_int as libc::c_long;
            if !((*b).buf).is_null() {
                ret = (*b).len as libc::c_long;
            }
        }
        11 => {
            ret = 1 as libc::c_int as libc::c_long;
        }
        2 => {
            ret = 1 as libc::c_int as libc::c_long;
            if !((*b).peer).is_null() {
                let mut peer_b_0: *mut bio_bio_st = (*(*b).peer).ptr as *mut bio_bio_st;
                if !peer_b_0.is_null() {} else {
                    __assert_fail(
                        b"peer_b != NULL\0" as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0"
                            as *const u8 as *const libc::c_char,
                        430 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 40],
                            &[libc::c_char; 40],
                        >(b"long bio_ctrl(BIO *, int, long, void *)\0"))
                            .as_ptr(),
                    );
                }
                'c_5903: {
                    if !peer_b_0.is_null() {} else {
                        __assert_fail(
                            b"peer_b != NULL\0" as *const u8 as *const libc::c_char,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/pair.c\0"
                                as *const u8 as *const libc::c_char,
                            430 as libc::c_int as libc::c_uint,
                            (*::core::mem::transmute::<
                                &[u8; 40],
                                &[libc::c_char; 40],
                            >(b"long bio_ctrl(BIO *, int, long, void *)\0"))
                                .as_ptr(),
                        );
                    }
                };
                ret = ((*peer_b_0).len == 0 as libc::c_int as size_t
                    && (*peer_b_0).closed != 0) as libc::c_int as libc::c_long;
            }
        }
        _ => {
            ret = 0 as libc::c_int as libc::c_long;
        }
    }
    return ret;
}
static mut methods_biop: BIO_METHOD = unsafe {
    {
        let mut init = bio_method_st {
            type_0: 19 as libc::c_int | 0x400 as libc::c_int,
            name: b"BIO pair\0" as *const u8 as *const libc::c_char,
            bwrite: Some(
                bio_write
                    as unsafe extern "C" fn(
                        *mut BIO,
                        *const libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            bread: Some(
                bio_read
                    as unsafe extern "C" fn(
                        *mut BIO,
                        *mut libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            bputs: None,
            bgets: None,
            ctrl: Some(
                bio_ctrl
                    as unsafe extern "C" fn(
                        *mut BIO,
                        libc::c_int,
                        libc::c_long,
                        *mut libc::c_void,
                    ) -> libc::c_long,
            ),
            create: Some(bio_new as unsafe extern "C" fn(*mut BIO) -> libc::c_int),
            destroy: Some(bio_free as unsafe extern "C" fn(*mut BIO) -> libc::c_int),
            callback_ctrl: None,
        };
        init
    }
};
unsafe extern "C" fn bio_s_bio() -> *const BIO_METHOD {
    return &methods_biop;
}
#[no_mangle]
pub unsafe extern "C" fn BIO_new_bio_pair(
    mut bio1_p: *mut *mut BIO,
    mut writebuf1_len: size_t,
    mut bio2_p: *mut *mut BIO,
    mut writebuf2_len: size_t,
) -> libc::c_int {
    let mut bio1: *mut BIO = BIO_new(bio_s_bio());
    let mut bio2: *mut BIO = BIO_new(bio_s_bio());
    if bio1.is_null() || bio2.is_null()
        || bio_make_pair(bio1, bio2, writebuf1_len, writebuf2_len) == 0
    {
        BIO_free(bio1);
        BIO_free(bio2);
        *bio1_p = 0 as *mut BIO;
        *bio2_p = 0 as *mut BIO;
        return 0 as libc::c_int;
    }
    *bio1_p = bio1;
    *bio2_p = bio2;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn BIO_destroy_bio_pair(mut b: *mut BIO) -> libc::c_int {
    if b.is_null() {
        return 0 as libc::c_int;
    }
    bio_destroy_pair(b);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn BIO_ctrl_get_read_request(mut bio: *mut BIO) -> size_t {
    return BIO_ctrl(
        bio,
        141 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        0 as *mut libc::c_void,
    ) as size_t;
}
#[no_mangle]
pub unsafe extern "C" fn BIO_ctrl_get_write_guarantee(mut bio: *mut BIO) -> size_t {
    return BIO_ctrl(
        bio,
        140 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        0 as *mut libc::c_void,
    ) as size_t;
}
#[no_mangle]
pub unsafe extern "C" fn BIO_shutdown_wr(mut bio: *mut BIO) -> libc::c_int {
    return BIO_ctrl(
        bio,
        142 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        0 as *mut libc::c_void,
    ) as libc::c_int;
}
