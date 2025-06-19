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
    fn memmove(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn BIO_read(bio: *mut BIO, data: *mut libc::c_void, len: libc::c_int) -> libc::c_int;
    fn BIO_write(
        bio: *mut BIO,
        data: *const libc::c_void,
        len: libc::c_int,
    ) -> libc::c_int;
    fn BIO_ctrl(
        bio: *mut BIO,
        cmd: libc::c_int,
        larg: libc::c_long,
        parg: *mut libc::c_void,
    ) -> libc::c_long;
    fn BIO_test_flags(bio: *const BIO, flags: libc::c_int) -> libc::c_int;
    fn BIO_should_retry(bio: *const BIO) -> libc::c_int;
    fn BIO_clear_retry_flags(bio: *mut BIO);
    fn BIO_callback_ctrl(
        bio: *mut BIO,
        cmd: libc::c_int,
        fp: bio_info_cb,
    ) -> libc::c_long;
    fn BIO_copy_next_retry(bio: *mut BIO);
    fn EVP_EncodeBlock(
        dst: *mut uint8_t,
        src: *const uint8_t,
        src_len: size_t,
    ) -> size_t;
    fn EVP_EncodeInit(ctx: *mut EVP_ENCODE_CTX);
    fn EVP_EncodeUpdate(
        ctx: *mut EVP_ENCODE_CTX,
        out: *mut uint8_t,
        out_len: *mut libc::c_int,
        in_0: *const uint8_t,
        in_len: size_t,
    ) -> libc::c_int;
    fn EVP_EncodeFinal(
        ctx: *mut EVP_ENCODE_CTX,
        out: *mut uint8_t,
        out_len: *mut libc::c_int,
    );
    fn EVP_DecodeInit(ctx: *mut EVP_ENCODE_CTX);
    fn EVP_DecodeUpdate(
        ctx: *mut EVP_ENCODE_CTX,
        out: *mut uint8_t,
        out_len: *mut libc::c_int,
        in_0: *const uint8_t,
        in_len: size_t,
    ) -> libc::c_int;
    fn EVP_DecodeBlock(
        dst: *mut uint8_t,
        src: *const uint8_t,
        src_len: size_t,
    ) -> libc::c_int;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
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
pub struct evp_encode_ctx_st {
    pub data_used: libc::c_uint,
    pub data: [uint8_t; 48],
    pub eof_seen: libc::c_char,
    pub error_encountered: libc::c_char,
}
pub type EVP_ENCODE_CTX = evp_encode_ctx_st;
pub type BIO_B64_CTX = b64_struct;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct b64_struct {
    pub buf_len: libc::c_int,
    pub buf_off: libc::c_int,
    pub tmp_len: libc::c_int,
    pub tmp_nl: libc::c_int,
    pub encode: libc::c_int,
    pub start: libc::c_int,
    pub cont: libc::c_int,
    pub base64: EVP_ENCODE_CTX,
    pub buf: [libc::c_char; 1502],
    pub tmp: [libc::c_char; 1024],
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
unsafe extern "C" fn b64_new(mut bio: *mut BIO) -> libc::c_int {
    let mut ctx: *mut BIO_B64_CTX = 0 as *mut BIO_B64_CTX;
    ctx = OPENSSL_zalloc(::core::mem::size_of::<BIO_B64_CTX>() as libc::c_ulong)
        as *mut BIO_B64_CTX;
    if ctx.is_null() {
        return 0 as libc::c_int;
    }
    (*ctx).cont = 1 as libc::c_int;
    (*ctx).start = 1 as libc::c_int;
    (*bio).init = 1 as libc::c_int;
    (*bio).ptr = ctx as *mut libc::c_char as *mut libc::c_void;
    return 1 as libc::c_int;
}
unsafe extern "C" fn b64_free(mut bio: *mut BIO) -> libc::c_int {
    if bio.is_null() {
        return 0 as libc::c_int;
    }
    OPENSSL_free((*bio).ptr);
    (*bio).ptr = 0 as *mut libc::c_void;
    (*bio).init = 0 as libc::c_int;
    (*bio).flags = 0 as libc::c_int;
    return 1 as libc::c_int;
}
unsafe extern "C" fn b64_read(
    mut b: *mut BIO,
    mut out: *mut libc::c_char,
    mut outl: libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_int = 0;
    let mut ii: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    let mut k: libc::c_int = 0;
    let mut x: libc::c_int = 0;
    let mut n: libc::c_int = 0;
    let mut num: libc::c_int = 0;
    let mut ret_code: libc::c_int = 0 as libc::c_int;
    let mut ctx: *mut BIO_B64_CTX = 0 as *mut BIO_B64_CTX;
    let mut p: *mut uint8_t = 0 as *mut uint8_t;
    let mut q: *mut uint8_t = 0 as *mut uint8_t;
    if out.is_null() {
        return 0 as libc::c_int;
    }
    ctx = (*b).ptr as *mut BIO_B64_CTX;
    if ctx.is_null() || ((*b).next_bio).is_null() {
        return 0 as libc::c_int;
    }
    BIO_clear_retry_flags(b);
    if (*ctx).encode != 2 as libc::c_int {
        (*ctx).encode = 2 as libc::c_int;
        (*ctx).buf_len = 0 as libc::c_int;
        (*ctx).buf_off = 0 as libc::c_int;
        (*ctx).tmp_len = 0 as libc::c_int;
        EVP_DecodeInit(&mut (*ctx).base64);
    }
    if (*ctx).buf_len > 0 as libc::c_int {
        if (*ctx).buf_len >= (*ctx).buf_off {} else {
            __assert_fail(
                b"ctx->buf_len >= ctx->buf_off\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                    as *const u8 as *const libc::c_char,
                144 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 33],
                    &[libc::c_char; 33],
                >(b"int b64_read(BIO *, char *, int)\0"))
                    .as_ptr(),
            );
        }
        'c_8886: {
            if (*ctx).buf_len >= (*ctx).buf_off {} else {
                __assert_fail(
                    b"ctx->buf_len >= ctx->buf_off\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                        as *const u8 as *const libc::c_char,
                    144 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 33],
                        &[libc::c_char; 33],
                    >(b"int b64_read(BIO *, char *, int)\0"))
                        .as_ptr(),
                );
            }
        };
        i = (*ctx).buf_len - (*ctx).buf_off;
        if i > outl {
            i = outl;
        }
        if (*ctx).buf_off + i
            < ::core::mem::size_of::<[libc::c_char; 1502]>() as libc::c_ulong
                as libc::c_int
        {} else {
            __assert_fail(
                b"ctx->buf_off + i < (int)sizeof(ctx->buf)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                    as *const u8 as *const libc::c_char,
                149 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 33],
                    &[libc::c_char; 33],
                >(b"int b64_read(BIO *, char *, int)\0"))
                    .as_ptr(),
            );
        }
        'c_8806: {
            if (*ctx).buf_off + i
                < ::core::mem::size_of::<[libc::c_char; 1502]>() as libc::c_ulong
                    as libc::c_int
            {} else {
                __assert_fail(
                    b"ctx->buf_off + i < (int)sizeof(ctx->buf)\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                        as *const u8 as *const libc::c_char,
                    149 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 33],
                        &[libc::c_char; 33],
                    >(b"int b64_read(BIO *, char *, int)\0"))
                        .as_ptr(),
                );
            }
        };
        OPENSSL_memcpy(
            out as *mut libc::c_void,
            &mut *((*ctx).buf).as_mut_ptr().offset((*ctx).buf_off as isize)
                as *mut libc::c_char as *const libc::c_void,
            i as size_t,
        );
        ret = i;
        out = out.offset(i as isize);
        outl -= i;
        (*ctx).buf_off += i;
        if (*ctx).buf_len == (*ctx).buf_off {
            (*ctx).buf_len = 0 as libc::c_int;
            (*ctx).buf_off = 0 as libc::c_int;
        }
    }
    ret_code = 0 as libc::c_int;
    while outl > 0 as libc::c_int {
        if (*ctx).cont <= 0 as libc::c_int {
            break;
        }
        i = BIO_read(
            (*b).next_bio,
            &mut *((*ctx).tmp).as_mut_ptr().offset((*ctx).tmp_len as isize)
                as *mut libc::c_char as *mut libc::c_void,
            1024 as libc::c_int - (*ctx).tmp_len,
        );
        if i <= 0 as libc::c_int {
            ret_code = i;
            if !(BIO_should_retry((*b).next_bio) == 0) {
                break;
            }
            (*ctx).cont = i;
            if (*ctx).tmp_len == 0 as libc::c_int {
                break;
            }
            i = 0 as libc::c_int;
        }
        i += (*ctx).tmp_len;
        (*ctx).tmp_len = i;
        if (*ctx).start != 0 && BIO_test_flags(b, 0x100 as libc::c_int) != 0 {
            (*ctx).tmp_len = 0 as libc::c_int;
        } else if (*ctx).start != 0 {
            p = ((*ctx).tmp).as_mut_ptr() as *mut uint8_t;
            q = p;
            num = 0 as libc::c_int;
            j = 0 as libc::c_int;
            while j < i {
                let fresh0 = q;
                q = q.offset(1);
                if !(*fresh0 as libc::c_int != '\n' as i32) {
                    if (*ctx).tmp_nl != 0 {
                        p = q;
                        (*ctx).tmp_nl = 0 as libc::c_int;
                    } else {
                        k = EVP_DecodeUpdate(
                            &mut (*ctx).base64,
                            ((*ctx).buf).as_mut_ptr() as *mut uint8_t,
                            &mut num,
                            p,
                            q.offset_from(p) as libc::c_long as size_t,
                        );
                        if k <= 0 as libc::c_int && num == 0 as libc::c_int
                            && (*ctx).start != 0
                        {
                            EVP_DecodeInit(&mut (*ctx).base64);
                            p = q;
                        } else {
                            if p
                                != &mut *((*ctx).tmp)
                                    .as_mut_ptr()
                                    .offset(0 as libc::c_int as isize) as *mut libc::c_char
                                    as *mut uint8_t
                            {
                                i = (i as libc::c_long
                                    - p
                                        .offset_from(
                                            &mut *((*ctx).tmp)
                                                .as_mut_ptr()
                                                .offset(0 as libc::c_int as isize) as *mut libc::c_char
                                                as *mut uint8_t,
                                        ) as libc::c_long) as libc::c_int;
                                x = 0 as libc::c_int;
                                while x < i {
                                    (*ctx)
                                        .tmp[x as usize] = *p.offset(x as isize) as libc::c_char;
                                    x += 1;
                                    x;
                                }
                            }
                            EVP_DecodeInit(&mut (*ctx).base64);
                            (*ctx).start = 0 as libc::c_int;
                            break;
                        }
                    }
                }
                j += 1;
                j;
            }
            if j == i && num == 0 as libc::c_int {
                if p
                    == &mut *((*ctx).tmp).as_mut_ptr().offset(0 as libc::c_int as isize)
                        as *mut libc::c_char as *mut uint8_t
                {
                    if i == 1024 as libc::c_int {
                        (*ctx).tmp_nl = 1 as libc::c_int;
                        (*ctx).tmp_len = 0 as libc::c_int;
                    }
                } else if p != q {
                    n = q.offset_from(p) as libc::c_long as libc::c_int;
                    ii = 0 as libc::c_int;
                    while ii < n {
                        (*ctx).tmp[ii as usize] = *p.offset(ii as isize) as libc::c_char;
                        ii += 1;
                        ii;
                    }
                    (*ctx).tmp_len = n;
                }
                continue;
            } else {
                (*ctx).tmp_len = 0 as libc::c_int;
            }
        } else if i < 1024 as libc::c_int && (*ctx).cont > 0 as libc::c_int {
            continue;
        }
        if BIO_test_flags(b, 0x100 as libc::c_int) != 0 {
            let mut z: libc::c_int = 0;
            let mut jj: libc::c_int = 0;
            jj = i & !(3 as libc::c_int);
            z = EVP_DecodeBlock(
                ((*ctx).buf).as_mut_ptr() as *mut uint8_t,
                ((*ctx).tmp).as_mut_ptr() as *mut uint8_t,
                jj as size_t,
            );
            if jj > 2 as libc::c_int {
                if (*ctx).tmp[(jj - 1 as libc::c_int) as usize] as libc::c_int
                    == '=' as i32
                {
                    z -= 1;
                    z;
                    if (*ctx).tmp[(jj - 2 as libc::c_int) as usize] as libc::c_int
                        == '=' as i32
                    {
                        z -= 1;
                        z;
                    }
                }
            }
            if jj != i {
                OPENSSL_memmove(
                    ((*ctx).tmp).as_mut_ptr() as *mut libc::c_void,
                    &mut *((*ctx).tmp).as_mut_ptr().offset(jj as isize)
                        as *mut libc::c_char as *const libc::c_void,
                    (i - jj) as size_t,
                );
                (*ctx).tmp_len = i - jj;
            }
            (*ctx).buf_len = 0 as libc::c_int;
            if z > 0 as libc::c_int {
                (*ctx).buf_len = z;
            }
            i = z;
        } else {
            i = EVP_DecodeUpdate(
                &mut (*ctx).base64,
                ((*ctx).buf).as_mut_ptr() as *mut uint8_t,
                &mut (*ctx).buf_len,
                ((*ctx).tmp).as_mut_ptr() as *mut uint8_t,
                i as size_t,
            );
            (*ctx).tmp_len = 0 as libc::c_int;
        }
        (*ctx).buf_off = 0 as libc::c_int;
        if i < 0 as libc::c_int {
            ret_code = 0 as libc::c_int;
            (*ctx).buf_len = 0 as libc::c_int;
            break;
        } else {
            if (*ctx).buf_len <= outl {
                i = (*ctx).buf_len;
            } else {
                i = outl;
            }
            OPENSSL_memcpy(
                out as *mut libc::c_void,
                ((*ctx).buf).as_mut_ptr() as *const libc::c_void,
                i as size_t,
            );
            ret += i;
            (*ctx).buf_off = i;
            if (*ctx).buf_off == (*ctx).buf_len {
                (*ctx).buf_len = 0 as libc::c_int;
                (*ctx).buf_off = 0 as libc::c_int;
            }
            outl -= i;
            out = out.offset(i as isize);
        }
    }
    BIO_copy_next_retry(b);
    return if ret == 0 as libc::c_int { ret_code } else { ret };
}
unsafe extern "C" fn b64_write(
    mut b: *mut BIO,
    mut in_0: *const libc::c_char,
    mut inl: libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut n: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    let mut ctx: *mut BIO_B64_CTX = 0 as *mut BIO_B64_CTX;
    ctx = (*b).ptr as *mut BIO_B64_CTX;
    BIO_clear_retry_flags(b);
    if (*ctx).encode != 1 as libc::c_int {
        (*ctx).encode = 1 as libc::c_int;
        (*ctx).buf_len = 0 as libc::c_int;
        (*ctx).buf_off = 0 as libc::c_int;
        (*ctx).tmp_len = 0 as libc::c_int;
        EVP_EncodeInit(&mut (*ctx).base64);
    }
    if (*ctx).buf_off
        < ::core::mem::size_of::<[libc::c_char; 1502]>() as libc::c_ulong as libc::c_int
    {} else {
        __assert_fail(
            b"ctx->buf_off < (int)sizeof(ctx->buf)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                as *const u8 as *const libc::c_char,
            333 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 40],
                &[libc::c_char; 40],
            >(b"int b64_write(BIO *, const char *, int)\0"))
                .as_ptr(),
        );
    }
    'c_7446: {
        if (*ctx).buf_off
            < ::core::mem::size_of::<[libc::c_char; 1502]>() as libc::c_ulong
                as libc::c_int
        {} else {
            __assert_fail(
                b"ctx->buf_off < (int)sizeof(ctx->buf)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                    as *const u8 as *const libc::c_char,
                333 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 40],
                    &[libc::c_char; 40],
                >(b"int b64_write(BIO *, const char *, int)\0"))
                    .as_ptr(),
            );
        }
    };
    if (*ctx).buf_len
        <= ::core::mem::size_of::<[libc::c_char; 1502]>() as libc::c_ulong as libc::c_int
    {} else {
        __assert_fail(
            b"ctx->buf_len <= (int)sizeof(ctx->buf)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                as *const u8 as *const libc::c_char,
            334 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 40],
                &[libc::c_char; 40],
            >(b"int b64_write(BIO *, const char *, int)\0"))
                .as_ptr(),
        );
    }
    'c_7396: {
        if (*ctx).buf_len
            <= ::core::mem::size_of::<[libc::c_char; 1502]>() as libc::c_ulong
                as libc::c_int
        {} else {
            __assert_fail(
                b"ctx->buf_len <= (int)sizeof(ctx->buf)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                    as *const u8 as *const libc::c_char,
                334 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 40],
                    &[libc::c_char; 40],
                >(b"int b64_write(BIO *, const char *, int)\0"))
                    .as_ptr(),
            );
        }
    };
    if (*ctx).buf_len >= (*ctx).buf_off {} else {
        __assert_fail(
            b"ctx->buf_len >= ctx->buf_off\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                as *const u8 as *const libc::c_char,
            335 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 40],
                &[libc::c_char; 40],
            >(b"int b64_write(BIO *, const char *, int)\0"))
                .as_ptr(),
        );
    }
    'c_7350: {
        if (*ctx).buf_len >= (*ctx).buf_off {} else {
            __assert_fail(
                b"ctx->buf_len >= ctx->buf_off\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                    as *const u8 as *const libc::c_char,
                335 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 40],
                    &[libc::c_char; 40],
                >(b"int b64_write(BIO *, const char *, int)\0"))
                    .as_ptr(),
            );
        }
    };
    n = (*ctx).buf_len - (*ctx).buf_off;
    while n > 0 as libc::c_int {
        i = BIO_write(
            (*b).next_bio,
            &mut *((*ctx).buf).as_mut_ptr().offset((*ctx).buf_off as isize)
                as *mut libc::c_char as *const libc::c_void,
            n,
        );
        if i <= 0 as libc::c_int {
            BIO_copy_next_retry(b);
            return i;
        }
        if i <= n {} else {
            __assert_fail(
                b"i <= n\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                    as *const u8 as *const libc::c_char,
                344 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 40],
                    &[libc::c_char; 40],
                >(b"int b64_write(BIO *, const char *, int)\0"))
                    .as_ptr(),
            );
        }
        'c_7261: {
            if i <= n {} else {
                __assert_fail(
                    b"i <= n\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                        as *const u8 as *const libc::c_char,
                    344 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 40],
                        &[libc::c_char; 40],
                    >(b"int b64_write(BIO *, const char *, int)\0"))
                        .as_ptr(),
                );
            }
        };
        (*ctx).buf_off += i;
        if (*ctx).buf_off
            <= ::core::mem::size_of::<[libc::c_char; 1502]>() as libc::c_ulong
                as libc::c_int
        {} else {
            __assert_fail(
                b"ctx->buf_off <= (int)sizeof(ctx->buf)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                    as *const u8 as *const libc::c_char,
                346 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 40],
                    &[libc::c_char; 40],
                >(b"int b64_write(BIO *, const char *, int)\0"))
                    .as_ptr(),
            );
        }
        'c_7205: {
            if (*ctx).buf_off
                <= ::core::mem::size_of::<[libc::c_char; 1502]>() as libc::c_ulong
                    as libc::c_int
            {} else {
                __assert_fail(
                    b"ctx->buf_off <= (int)sizeof(ctx->buf)\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                        as *const u8 as *const libc::c_char,
                    346 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 40],
                        &[libc::c_char; 40],
                    >(b"int b64_write(BIO *, const char *, int)\0"))
                        .as_ptr(),
                );
            }
        };
        if (*ctx).buf_len >= (*ctx).buf_off {} else {
            __assert_fail(
                b"ctx->buf_len >= ctx->buf_off\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                    as *const u8 as *const libc::c_char,
                347 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 40],
                    &[libc::c_char; 40],
                >(b"int b64_write(BIO *, const char *, int)\0"))
                    .as_ptr(),
            );
        }
        'c_7159: {
            if (*ctx).buf_len >= (*ctx).buf_off {} else {
                __assert_fail(
                    b"ctx->buf_len >= ctx->buf_off\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                        as *const u8 as *const libc::c_char,
                    347 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 40],
                        &[libc::c_char; 40],
                    >(b"int b64_write(BIO *, const char *, int)\0"))
                        .as_ptr(),
                );
            }
        };
        n -= i;
    }
    (*ctx).buf_off = 0 as libc::c_int;
    (*ctx).buf_len = 0 as libc::c_int;
    if in_0.is_null() || inl <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    while inl > 0 as libc::c_int {
        n = if inl > 1024 as libc::c_int { 1024 as libc::c_int } else { inl };
        if BIO_test_flags(b, 0x100 as libc::c_int) != 0 {
            if (*ctx).tmp_len > 0 as libc::c_int {
                if (*ctx).tmp_len <= 3 as libc::c_int {} else {
                    __assert_fail(
                        b"ctx->tmp_len <= 3\0" as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                            as *const u8 as *const libc::c_char,
                        364 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 40],
                            &[libc::c_char; 40],
                        >(b"int b64_write(BIO *, const char *, int)\0"))
                            .as_ptr(),
                    );
                }
                'c_7052: {
                    if (*ctx).tmp_len <= 3 as libc::c_int {} else {
                        __assert_fail(
                            b"ctx->tmp_len <= 3\0" as *const u8 as *const libc::c_char,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                                as *const u8 as *const libc::c_char,
                            364 as libc::c_int as libc::c_uint,
                            (*::core::mem::transmute::<
                                &[u8; 40],
                                &[libc::c_char; 40],
                            >(b"int b64_write(BIO *, const char *, int)\0"))
                                .as_ptr(),
                        );
                    }
                };
                n = 3 as libc::c_int - (*ctx).tmp_len;
                if n > inl {
                    n = inl;
                }
                OPENSSL_memcpy(
                    &mut *((*ctx).tmp).as_mut_ptr().offset((*ctx).tmp_len as isize)
                        as *mut libc::c_char as *mut libc::c_void,
                    in_0 as *const libc::c_void,
                    n as size_t,
                );
                (*ctx).tmp_len += n;
                ret += n;
                if (*ctx).tmp_len < 3 as libc::c_int {
                    break;
                }
                (*ctx)
                    .buf_len = EVP_EncodeBlock(
                    ((*ctx).buf).as_mut_ptr() as *mut uint8_t,
                    ((*ctx).tmp).as_mut_ptr() as *mut uint8_t,
                    (*ctx).tmp_len as size_t,
                ) as libc::c_int;
                if (*ctx).buf_len
                    <= ::core::mem::size_of::<[libc::c_char; 1502]>() as libc::c_ulong
                        as libc::c_int
                {} else {
                    __assert_fail(
                        b"ctx->buf_len <= (int)sizeof(ctx->buf)\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                            as *const u8 as *const libc::c_char,
                        378 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 40],
                            &[libc::c_char; 40],
                        >(b"int b64_write(BIO *, const char *, int)\0"))
                            .as_ptr(),
                    );
                }
                'c_6920: {
                    if (*ctx).buf_len
                        <= ::core::mem::size_of::<[libc::c_char; 1502]>()
                            as libc::c_ulong as libc::c_int
                    {} else {
                        __assert_fail(
                            b"ctx->buf_len <= (int)sizeof(ctx->buf)\0" as *const u8
                                as *const libc::c_char,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                                as *const u8 as *const libc::c_char,
                            378 as libc::c_int as libc::c_uint,
                            (*::core::mem::transmute::<
                                &[u8; 40],
                                &[libc::c_char; 40],
                            >(b"int b64_write(BIO *, const char *, int)\0"))
                                .as_ptr(),
                        );
                    }
                };
                if (*ctx).buf_len >= (*ctx).buf_off {} else {
                    __assert_fail(
                        b"ctx->buf_len >= ctx->buf_off\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                            as *const u8 as *const libc::c_char,
                        379 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 40],
                            &[libc::c_char; 40],
                        >(b"int b64_write(BIO *, const char *, int)\0"))
                            .as_ptr(),
                    );
                }
                'c_6874: {
                    if (*ctx).buf_len >= (*ctx).buf_off {} else {
                        __assert_fail(
                            b"ctx->buf_len >= ctx->buf_off\0" as *const u8
                                as *const libc::c_char,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                                as *const u8 as *const libc::c_char,
                            379 as libc::c_int as libc::c_uint,
                            (*::core::mem::transmute::<
                                &[u8; 40],
                                &[libc::c_char; 40],
                            >(b"int b64_write(BIO *, const char *, int)\0"))
                                .as_ptr(),
                        );
                    }
                };
                (*ctx).tmp_len = 0 as libc::c_int;
            } else if n < 3 as libc::c_int {
                OPENSSL_memcpy(
                    ((*ctx).tmp).as_mut_ptr() as *mut libc::c_void,
                    in_0 as *const libc::c_void,
                    n as size_t,
                );
                (*ctx).tmp_len = n;
                ret += n;
                break;
            } else {
                n -= n % 3 as libc::c_int;
                (*ctx)
                    .buf_len = EVP_EncodeBlock(
                    ((*ctx).buf).as_mut_ptr() as *mut uint8_t,
                    in_0 as *const uint8_t,
                    n as size_t,
                ) as libc::c_int;
                if (*ctx).buf_len
                    <= ::core::mem::size_of::<[libc::c_char; 1502]>() as libc::c_ulong
                        as libc::c_int
                {} else {
                    __assert_fail(
                        b"ctx->buf_len <= (int)sizeof(ctx->buf)\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                            as *const u8 as *const libc::c_char,
                        394 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 40],
                            &[libc::c_char; 40],
                        >(b"int b64_write(BIO *, const char *, int)\0"))
                            .as_ptr(),
                    );
                }
                'c_6721: {
                    if (*ctx).buf_len
                        <= ::core::mem::size_of::<[libc::c_char; 1502]>()
                            as libc::c_ulong as libc::c_int
                    {} else {
                        __assert_fail(
                            b"ctx->buf_len <= (int)sizeof(ctx->buf)\0" as *const u8
                                as *const libc::c_char,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                                as *const u8 as *const libc::c_char,
                            394 as libc::c_int as libc::c_uint,
                            (*::core::mem::transmute::<
                                &[u8; 40],
                                &[libc::c_char; 40],
                            >(b"int b64_write(BIO *, const char *, int)\0"))
                                .as_ptr(),
                        );
                    }
                };
                if (*ctx).buf_len >= (*ctx).buf_off {} else {
                    __assert_fail(
                        b"ctx->buf_len >= ctx->buf_off\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                            as *const u8 as *const libc::c_char,
                        395 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 40],
                            &[libc::c_char; 40],
                        >(b"int b64_write(BIO *, const char *, int)\0"))
                            .as_ptr(),
                    );
                }
                'c_6675: {
                    if (*ctx).buf_len >= (*ctx).buf_off {} else {
                        __assert_fail(
                            b"ctx->buf_len >= ctx->buf_off\0" as *const u8
                                as *const libc::c_char,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                                as *const u8 as *const libc::c_char,
                            395 as libc::c_int as libc::c_uint,
                            (*::core::mem::transmute::<
                                &[u8; 40],
                                &[libc::c_char; 40],
                            >(b"int b64_write(BIO *, const char *, int)\0"))
                                .as_ptr(),
                        );
                    }
                };
                ret += n;
            }
        } else {
            if EVP_EncodeUpdate(
                &mut (*ctx).base64,
                ((*ctx).buf).as_mut_ptr() as *mut uint8_t,
                &mut (*ctx).buf_len,
                in_0 as *mut uint8_t,
                n as size_t,
            ) == 0
            {
                return if ret == 0 as libc::c_int { -(1 as libc::c_int) } else { ret };
            }
            if (*ctx).buf_len
                <= ::core::mem::size_of::<[libc::c_char; 1502]>() as libc::c_ulong
                    as libc::c_int
            {} else {
                __assert_fail(
                    b"ctx->buf_len <= (int)sizeof(ctx->buf)\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                        as *const u8 as *const libc::c_char,
                    403 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 40],
                        &[libc::c_char; 40],
                    >(b"int b64_write(BIO *, const char *, int)\0"))
                        .as_ptr(),
                );
            }
            'c_6572: {
                if (*ctx).buf_len
                    <= ::core::mem::size_of::<[libc::c_char; 1502]>() as libc::c_ulong
                        as libc::c_int
                {} else {
                    __assert_fail(
                        b"ctx->buf_len <= (int)sizeof(ctx->buf)\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                            as *const u8 as *const libc::c_char,
                        403 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 40],
                            &[libc::c_char; 40],
                        >(b"int b64_write(BIO *, const char *, int)\0"))
                            .as_ptr(),
                    );
                }
            };
            if (*ctx).buf_len >= (*ctx).buf_off {} else {
                __assert_fail(
                    b"ctx->buf_len >= ctx->buf_off\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                        as *const u8 as *const libc::c_char,
                    404 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 40],
                        &[libc::c_char; 40],
                    >(b"int b64_write(BIO *, const char *, int)\0"))
                        .as_ptr(),
                );
            }
            'c_6526: {
                if (*ctx).buf_len >= (*ctx).buf_off {} else {
                    __assert_fail(
                        b"ctx->buf_len >= ctx->buf_off\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                            as *const u8 as *const libc::c_char,
                        404 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 40],
                            &[libc::c_char; 40],
                        >(b"int b64_write(BIO *, const char *, int)\0"))
                            .as_ptr(),
                    );
                }
            };
            ret += n;
        }
        inl -= n;
        in_0 = in_0.offset(n as isize);
        (*ctx).buf_off = 0 as libc::c_int;
        n = (*ctx).buf_len;
        while n > 0 as libc::c_int {
            i = BIO_write(
                (*b).next_bio,
                &mut *((*ctx).buf).as_mut_ptr().offset((*ctx).buf_off as isize)
                    as *mut libc::c_char as *const libc::c_void,
                n,
            );
            if i <= 0 as libc::c_int {
                BIO_copy_next_retry(b);
                return if ret == 0 as libc::c_int { i } else { ret };
            }
            if i <= n {} else {
                __assert_fail(
                    b"i <= n\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                        as *const u8 as *const libc::c_char,
                    419 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 40],
                        &[libc::c_char; 40],
                    >(b"int b64_write(BIO *, const char *, int)\0"))
                        .as_ptr(),
                );
            }
            'c_6409: {
                if i <= n {} else {
                    __assert_fail(
                        b"i <= n\0" as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                            as *const u8 as *const libc::c_char,
                        419 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 40],
                            &[libc::c_char; 40],
                        >(b"int b64_write(BIO *, const char *, int)\0"))
                            .as_ptr(),
                    );
                }
            };
            n -= i;
            (*ctx).buf_off += i;
            if (*ctx).buf_off
                <= ::core::mem::size_of::<[libc::c_char; 1502]>() as libc::c_ulong
                    as libc::c_int
            {} else {
                __assert_fail(
                    b"ctx->buf_off <= (int)sizeof(ctx->buf)\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                        as *const u8 as *const libc::c_char,
                    422 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 40],
                        &[libc::c_char; 40],
                    >(b"int b64_write(BIO *, const char *, int)\0"))
                        .as_ptr(),
                );
            }
            'c_6346: {
                if (*ctx).buf_off
                    <= ::core::mem::size_of::<[libc::c_char; 1502]>() as libc::c_ulong
                        as libc::c_int
                {} else {
                    __assert_fail(
                        b"ctx->buf_off <= (int)sizeof(ctx->buf)\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                            as *const u8 as *const libc::c_char,
                        422 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 40],
                            &[libc::c_char; 40],
                        >(b"int b64_write(BIO *, const char *, int)\0"))
                            .as_ptr(),
                    );
                }
            };
            if (*ctx).buf_len >= (*ctx).buf_off {} else {
                __assert_fail(
                    b"ctx->buf_len >= ctx->buf_off\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                        as *const u8 as *const libc::c_char,
                    423 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 40],
                        &[libc::c_char; 40],
                    >(b"int b64_write(BIO *, const char *, int)\0"))
                        .as_ptr(),
                );
            }
            'c_6295: {
                if (*ctx).buf_len >= (*ctx).buf_off {} else {
                    __assert_fail(
                        b"ctx->buf_len >= ctx->buf_off\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                            as *const u8 as *const libc::c_char,
                        423 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 40],
                            &[libc::c_char; 40],
                        >(b"int b64_write(BIO *, const char *, int)\0"))
                            .as_ptr(),
                    );
                }
            };
        }
        (*ctx).buf_len = 0 as libc::c_int;
        (*ctx).buf_off = 0 as libc::c_int;
    }
    return ret;
}
unsafe extern "C" fn b64_ctrl(
    mut b: *mut BIO,
    mut cmd: libc::c_int,
    mut num: libc::c_long,
    mut ptr: *mut libc::c_void,
) -> libc::c_long {
    let mut ctx: *mut BIO_B64_CTX = 0 as *mut BIO_B64_CTX;
    let mut ret: libc::c_long = 1 as libc::c_int as libc::c_long;
    let mut i: libc::c_int = 0;
    ctx = (*b).ptr as *mut BIO_B64_CTX;
    match cmd {
        1 => {
            (*ctx).cont = 1 as libc::c_int;
            (*ctx).start = 1 as libc::c_int;
            (*ctx).encode = 0 as libc::c_int;
            ret = BIO_ctrl((*b).next_bio, cmd, num, ptr);
        }
        2 => {
            if (*ctx).cont <= 0 as libc::c_int {
                ret = 1 as libc::c_int as libc::c_long;
            } else {
                ret = BIO_ctrl((*b).next_bio, cmd, num, ptr);
            }
        }
        13 => {
            if (*ctx).buf_len >= (*ctx).buf_off {} else {
                __assert_fail(
                    b"ctx->buf_len >= ctx->buf_off\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                        as *const u8 as *const libc::c_char,
                    455 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 40],
                        &[libc::c_char; 40],
                    >(b"long b64_ctrl(BIO *, int, long, void *)\0"))
                        .as_ptr(),
                );
            }
            'c_7805: {
                if (*ctx).buf_len >= (*ctx).buf_off {} else {
                    __assert_fail(
                        b"ctx->buf_len >= ctx->buf_off\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                            as *const u8 as *const libc::c_char,
                        455 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 40],
                            &[libc::c_char; 40],
                        >(b"long b64_ctrl(BIO *, int, long, void *)\0"))
                            .as_ptr(),
                    );
                }
            };
            ret = ((*ctx).buf_len - (*ctx).buf_off) as libc::c_long;
            if ret == 0 as libc::c_int as libc::c_long
                && (*ctx).encode != 0 as libc::c_int
                && (*ctx).base64.data_used != 0 as libc::c_int as libc::c_uint
            {
                ret = 1 as libc::c_int as libc::c_long;
            } else if ret <= 0 as libc::c_int as libc::c_long {
                ret = BIO_ctrl((*b).next_bio, cmd, num, ptr);
            }
        }
        10 => {
            if (*ctx).buf_len >= (*ctx).buf_off {} else {
                __assert_fail(
                    b"ctx->buf_len >= ctx->buf_off\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                        as *const u8 as *const libc::c_char,
                    465 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 40],
                        &[libc::c_char; 40],
                    >(b"long b64_ctrl(BIO *, int, long, void *)\0"))
                        .as_ptr(),
                );
            }
            'c_7690: {
                if (*ctx).buf_len >= (*ctx).buf_off {} else {
                    __assert_fail(
                        b"ctx->buf_len >= ctx->buf_off\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/bio/base64_bio.c\0"
                            as *const u8 as *const libc::c_char,
                        465 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 40],
                            &[libc::c_char; 40],
                        >(b"long b64_ctrl(BIO *, int, long, void *)\0"))
                            .as_ptr(),
                    );
                }
            };
            ret = ((*ctx).buf_len - (*ctx).buf_off) as libc::c_long;
            if ret <= 0 as libc::c_int as libc::c_long {
                ret = BIO_ctrl((*b).next_bio, cmd, num, ptr);
            }
        }
        11 => {
            loop {
                while (*ctx).buf_len != (*ctx).buf_off {
                    i = b64_write(b, 0 as *const libc::c_char, 0 as libc::c_int);
                    if i < 0 as libc::c_int {
                        return i as libc::c_long;
                    }
                }
                if BIO_test_flags(b, 0x100 as libc::c_int) != 0 {
                    if !((*ctx).tmp_len != 0 as libc::c_int) {
                        break;
                    }
                    (*ctx)
                        .buf_len = EVP_EncodeBlock(
                        ((*ctx).buf).as_mut_ptr() as *mut uint8_t,
                        ((*ctx).tmp).as_mut_ptr() as *mut uint8_t,
                        (*ctx).tmp_len as size_t,
                    ) as libc::c_int;
                    (*ctx).buf_off = 0 as libc::c_int;
                    (*ctx).tmp_len = 0 as libc::c_int;
                } else {
                    if !((*ctx).encode != 0 as libc::c_int
                        && (*ctx).base64.data_used != 0 as libc::c_int as libc::c_uint)
                    {
                        break;
                    }
                    (*ctx).buf_off = 0 as libc::c_int;
                    EVP_EncodeFinal(
                        &mut (*ctx).base64,
                        ((*ctx).buf).as_mut_ptr() as *mut uint8_t,
                        &mut (*ctx).buf_len,
                    );
                }
            }
            ret = BIO_ctrl((*b).next_bio, cmd, num, ptr);
        }
        101 => {
            BIO_clear_retry_flags(b);
            ret = BIO_ctrl((*b).next_bio, cmd, num, ptr);
            BIO_copy_next_retry(b);
        }
        3 | 5 | 4 | _ => {
            ret = BIO_ctrl((*b).next_bio, cmd, num, ptr);
        }
    }
    return ret;
}
unsafe extern "C" fn b64_callback_ctrl(
    mut b: *mut BIO,
    mut cmd: libc::c_int,
    mut fp: bio_info_cb,
) -> libc::c_long {
    if ((*b).next_bio).is_null() {
        return 0 as libc::c_int as libc::c_long;
    }
    return BIO_callback_ctrl((*b).next_bio, cmd, fp);
}
static mut b64_method: BIO_METHOD = unsafe {
    {
        let mut init = bio_method_st {
            type_0: 11 as libc::c_int | 0x200 as libc::c_int,
            name: b"base64 encoding\0" as *const u8 as *const libc::c_char,
            bwrite: Some(
                b64_write
                    as unsafe extern "C" fn(
                        *mut BIO,
                        *const libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            bread: Some(
                b64_read
                    as unsafe extern "C" fn(
                        *mut BIO,
                        *mut libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            bputs: None,
            bgets: None,
            ctrl: Some(
                b64_ctrl
                    as unsafe extern "C" fn(
                        *mut BIO,
                        libc::c_int,
                        libc::c_long,
                        *mut libc::c_void,
                    ) -> libc::c_long,
            ),
            create: Some(b64_new as unsafe extern "C" fn(*mut BIO) -> libc::c_int),
            destroy: Some(b64_free as unsafe extern "C" fn(*mut BIO) -> libc::c_int),
            callback_ctrl: Some(
                b64_callback_ctrl
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
pub unsafe extern "C" fn BIO_f_base64() -> *const BIO_METHOD {
    return &b64_method;
}
