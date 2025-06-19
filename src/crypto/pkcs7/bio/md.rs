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
    pub type engine_st;
    pub type evp_md_pctx_ops;
    pub type evp_pkey_ctx_st;
    pub type env_md_st;
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
    fn BIO_clear_retry_flags(bio: *mut BIO);
    fn BIO_next(bio: *mut BIO) -> *mut BIO;
    fn BIO_copy_next_retry(bio: *mut BIO);
    fn BIO_set_data(bio: *mut BIO, ptr: *mut libc::c_void);
    fn BIO_get_data(bio: *mut BIO) -> *mut libc::c_void;
    fn BIO_set_init(bio: *mut BIO, init: libc::c_int);
    fn BIO_get_init(bio: *mut BIO) -> libc::c_int;
    fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX;
    fn EVP_MD_CTX_free(ctx: *mut EVP_MD_CTX);
    fn EVP_DigestInit_ex(
        ctx: *mut EVP_MD_CTX,
        type_0: *const EVP_MD,
        engine: *mut ENGINE,
    ) -> libc::c_int;
    fn EVP_DigestUpdate(
        ctx: *mut EVP_MD_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn EVP_DigestFinal_ex(
        ctx: *mut EVP_MD_CTX,
        md_out: *mut uint8_t,
        out_size: *mut libc::c_uint,
    ) -> libc::c_int;
    fn EVP_MD_CTX_md(ctx: *const EVP_MD_CTX) -> *const EVP_MD;
    fn EVP_MD_CTX_size(ctx: *const EVP_MD_CTX) -> size_t;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
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
pub type ENGINE = engine_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct env_md_ctx_st {
    pub digest: *const EVP_MD,
    pub md_data: *mut libc::c_void,
    pub update: Option::<
        unsafe extern "C" fn(*mut EVP_MD_CTX, *const libc::c_void, size_t) -> libc::c_int,
    >,
    pub pctx: *mut EVP_PKEY_CTX,
    pub pctx_ops: *const evp_md_pctx_ops,
    pub flags: libc::c_ulong,
}
pub type EVP_PKEY_CTX = evp_pkey_ctx_st;
pub type EVP_MD_CTX = env_md_ctx_st;
pub type EVP_MD = env_md_st;
unsafe extern "C" fn md_new(mut b: *mut BIO) -> libc::c_int {
    if b.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/md.c\0" as *const u8
                as *const libc::c_char,
            14 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ctx: *mut EVP_MD_CTX = 0 as *mut EVP_MD_CTX;
    ctx = EVP_MD_CTX_new();
    if ctx.is_null() {
        return 0 as libc::c_int;
    }
    BIO_set_data(b, ctx as *mut libc::c_void);
    return 1 as libc::c_int;
}
unsafe extern "C" fn md_free(mut b: *mut BIO) -> libc::c_int {
    if b.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/md.c\0" as *const u8
                as *const libc::c_char,
            28 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    EVP_MD_CTX_free(BIO_get_data(b) as *mut EVP_MD_CTX);
    BIO_set_data(b, 0 as *mut libc::c_void);
    BIO_set_init(b, 0 as libc::c_int);
    return 1 as libc::c_int;
}
unsafe extern "C" fn md_read(
    mut b: *mut BIO,
    mut out: *mut libc::c_char,
    mut outl: libc::c_int,
) -> libc::c_int {
    if b.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/md.c\0" as *const u8
                as *const libc::c_char,
            37 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if out.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/md.c\0" as *const u8
                as *const libc::c_char,
            38 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut ctx: *mut EVP_MD_CTX = 0 as *mut EVP_MD_CTX;
    let mut next: *mut BIO = 0 as *mut BIO;
    ctx = BIO_get_data(b) as *mut EVP_MD_CTX;
    next = BIO_next(b);
    if ctx.is_null() || next.is_null() || outl <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    ret = BIO_read(next, out as *mut libc::c_void, outl);
    if ret > 0 as libc::c_int {
        if EVP_DigestUpdate(
            ctx,
            out as *mut libc::c_uchar as *const libc::c_void,
            ret as size_t,
        ) <= 0 as libc::c_int
        {
            ret = -(1 as libc::c_int);
        }
    }
    BIO_clear_retry_flags(b);
    BIO_copy_next_retry(b);
    return ret;
}
unsafe extern "C" fn md_write(
    mut b: *mut BIO,
    mut in_0: *const libc::c_char,
    mut inl: libc::c_int,
) -> libc::c_int {
    if b.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/md.c\0" as *const u8
                as *const libc::c_char,
            63 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if in_0.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/md.c\0" as *const u8
                as *const libc::c_char,
            64 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut ctx: *mut EVP_MD_CTX = 0 as *mut EVP_MD_CTX;
    let mut next: *mut BIO = 0 as *mut BIO;
    ctx = BIO_get_data(b) as *mut EVP_MD_CTX;
    next = BIO_next(b);
    if ctx.is_null() || next.is_null() || inl <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    ret = BIO_write(next, in_0 as *const libc::c_void, inl);
    if ret > 0 as libc::c_int {
        if EVP_DigestUpdate(
            ctx,
            in_0 as *const libc::c_uchar as *const libc::c_void,
            ret as size_t,
        ) <= 0 as libc::c_int
        {
            ret = -(1 as libc::c_int);
        }
    }
    BIO_clear_retry_flags(b);
    BIO_copy_next_retry(b);
    return ret;
}
unsafe extern "C" fn md_ctrl(
    mut b: *mut BIO,
    mut cmd: libc::c_int,
    mut num: libc::c_long,
    mut ptr: *mut libc::c_void,
) -> libc::c_long {
    if b.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/md.c\0" as *const u8
                as *const libc::c_char,
            89 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int as libc::c_long;
    }
    let mut ctx: *mut EVP_MD_CTX = 0 as *mut EVP_MD_CTX;
    let mut pctx: *mut *mut EVP_MD_CTX = 0 as *mut *mut EVP_MD_CTX;
    let mut md: *mut EVP_MD = 0 as *mut EVP_MD;
    let mut ret: libc::c_long = 1 as libc::c_int as libc::c_long;
    let mut next: *mut BIO = 0 as *mut BIO;
    ctx = BIO_get_data(b) as *mut EVP_MD_CTX;
    next = BIO_next(b);
    match cmd {
        1 => {
            if BIO_get_init(b) != 0 {
                ret = EVP_DigestInit_ex(ctx, EVP_MD_CTX_md(ctx), 0 as *mut ENGINE)
                    as libc::c_long;
            } else {
                ret = 0 as libc::c_int as libc::c_long;
            }
            if ret > 0 as libc::c_int as libc::c_long {
                ret = BIO_ctrl(next, cmd, num, ptr);
            }
        }
        120 => {
            pctx = ptr as *mut *mut EVP_MD_CTX;
            *pctx = ctx;
            BIO_set_init(b, 1 as libc::c_int);
        }
        111 => {
            if ptr.is_null() {
                ERR_put_error(
                    14 as libc::c_int,
                    0 as libc::c_int,
                    3 as libc::c_int | 64 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/md.c\0"
                        as *const u8 as *const libc::c_char,
                    115 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int as libc::c_long;
            }
            md = ptr as *mut EVP_MD;
            ret = EVP_DigestInit_ex(ctx, md, 0 as *mut ENGINE) as libc::c_long;
            if ret > 0 as libc::c_int as libc::c_long {
                BIO_set_init(b, 1 as libc::c_int);
            }
        }
        112 | 148 | 101 | 12 | 15 | 14 => {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                17 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/md.c\0" as *const u8
                    as *const libc::c_char,
                132 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int as libc::c_long;
        }
        _ => {
            ret = BIO_ctrl(next, cmd, num, ptr);
        }
    }
    return ret;
}
unsafe extern "C" fn md_gets(
    mut b: *mut BIO,
    mut buf: *mut libc::c_char,
    mut size: libc::c_int,
) -> libc::c_int {
    if b.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/md.c\0" as *const u8
                as *const libc::c_char,
            142 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if buf.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/bio/md.c\0" as *const u8
                as *const libc::c_char,
            143 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ctx: *mut EVP_MD_CTX = 0 as *mut EVP_MD_CTX;
    let mut ret: libc::c_uint = 0;
    ctx = BIO_get_data(b) as *mut EVP_MD_CTX;
    if (size as size_t) < EVP_MD_CTX_size(ctx) {
        return 0 as libc::c_int;
    }
    if EVP_DigestFinal_ex(ctx, buf as *mut libc::c_uchar, &mut ret) <= 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    return ret as libc::c_int;
}
static mut methods_md: BIO_METHOD = unsafe {
    {
        let mut init = bio_method_st {
            type_0: 8 as libc::c_int | 0x200 as libc::c_int,
            name: b"message digest\0" as *const u8 as *const libc::c_char,
            bwrite: Some(
                md_write
                    as unsafe extern "C" fn(
                        *mut BIO,
                        *const libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            bread: Some(
                md_read
                    as unsafe extern "C" fn(
                        *mut BIO,
                        *mut libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            bputs: None,
            bgets: Some(
                md_gets
                    as unsafe extern "C" fn(
                        *mut BIO,
                        *mut libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            ctrl: Some(
                md_ctrl
                    as unsafe extern "C" fn(
                        *mut BIO,
                        libc::c_int,
                        libc::c_long,
                        *mut libc::c_void,
                    ) -> libc::c_long,
            ),
            create: Some(md_new as unsafe extern "C" fn(*mut BIO) -> libc::c_int),
            destroy: Some(md_free as unsafe extern "C" fn(*mut BIO) -> libc::c_int),
            callback_ctrl: None,
        };
        init
    }
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_f_md() -> *const BIO_METHOD {
    return &methods_md;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_get_md_ctx(
    mut b: *mut BIO,
    mut ctx: *mut *mut EVP_MD_CTX,
) -> libc::c_int {
    return BIO_ctrl(
        b,
        120 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        ctx as *mut libc::c_void,
    ) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_set_md(
    mut b: *mut BIO,
    mut md: *const EVP_MD,
) -> libc::c_int {
    return BIO_ctrl(
        b,
        111 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        md as *mut EVP_MD as *mut libc::c_void,
    ) as libc::c_int;
}
