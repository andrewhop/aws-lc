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
    fn BIO_write(
        bio: *mut BIO,
        data: *const libc::c_void,
        len: libc::c_int,
    ) -> libc::c_int;
    fn BIO_indent(
        bio: *mut BIO,
        indent: libc::c_uint,
        max_indent: libc::c_uint,
    ) -> libc::c_int;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_mem_contents(
        bio: *const BIO,
        out_contents: *mut *const uint8_t,
        out_len: *mut size_t,
    ) -> libc::c_int;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
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
pub struct hexdump_ctx {
    pub bio: *mut BIO,
    pub right_chars: [libc::c_char; 18],
    pub used: libc::c_uint,
    pub n: size_t,
    pub indent: libc::c_uint,
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
unsafe extern "C" fn hexbyte(mut out: *mut libc::c_char, mut b: uint8_t) {
    static mut hextable: [libc::c_char; 17] = unsafe {
        *::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"0123456789abcdef\0")
    };
    *out
        .offset(
            0 as libc::c_int as isize,
        ) = hextable[(b as libc::c_int >> 4 as libc::c_int) as usize];
    *out
        .offset(
            1 as libc::c_int as isize,
        ) = hextable[(b as libc::c_int & 0xf as libc::c_int) as usize];
}
unsafe extern "C" fn to_char(mut b: uint8_t) -> libc::c_char {
    if (b as libc::c_int) < 32 as libc::c_int || b as libc::c_int > 126 as libc::c_int {
        return '.' as i32 as libc::c_char;
    }
    return b as libc::c_char;
}
unsafe extern "C" fn hexdump_write(
    mut ctx: *mut hexdump_ctx,
    mut data: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut buf: [libc::c_char; 10] = [0; 10];
    let mut l: libc::c_uint = 0;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < len {
        if (*ctx).used == 0 as libc::c_int as libc::c_uint {
            if BIO_indent(
                (*ctx).bio,
                (*ctx).indent,
                (2147483647 as libc::c_int as libc::c_uint)
                    .wrapping_mul(2 as libc::c_uint)
                    .wrapping_add(1 as libc::c_uint),
            ) == 0
            {
                return 0 as libc::c_int;
            }
            hexbyte(
                &mut *buf.as_mut_ptr().offset(0 as libc::c_int as isize),
                ((*ctx).n >> 24 as libc::c_int) as uint8_t,
            );
            hexbyte(
                &mut *buf.as_mut_ptr().offset(2 as libc::c_int as isize),
                ((*ctx).n >> 16 as libc::c_int) as uint8_t,
            );
            hexbyte(
                &mut *buf.as_mut_ptr().offset(4 as libc::c_int as isize),
                ((*ctx).n >> 8 as libc::c_int) as uint8_t,
            );
            hexbyte(
                &mut *buf.as_mut_ptr().offset(6 as libc::c_int as isize),
                (*ctx).n as uint8_t,
            );
            buf[9 as libc::c_int as usize] = ' ' as i32 as libc::c_char;
            buf[8 as libc::c_int as usize] = buf[9 as libc::c_int as usize];
            if BIO_write(
                (*ctx).bio,
                buf.as_mut_ptr() as *const libc::c_void,
                10 as libc::c_int,
            ) < 0 as libc::c_int
            {
                return 0 as libc::c_int;
            }
        }
        hexbyte(buf.as_mut_ptr(), *data.offset(i as isize));
        buf[2 as libc::c_int as usize] = ' ' as i32 as libc::c_char;
        l = 3 as libc::c_int as libc::c_uint;
        if (*ctx).used == 7 as libc::c_int as libc::c_uint {
            buf[3 as libc::c_int as usize] = ' ' as i32 as libc::c_char;
            l = 4 as libc::c_int as libc::c_uint;
        } else if (*ctx).used == 15 as libc::c_int as libc::c_uint {
            buf[3 as libc::c_int as usize] = ' ' as i32 as libc::c_char;
            buf[4 as libc::c_int as usize] = '|' as i32 as libc::c_char;
            l = 5 as libc::c_int as libc::c_uint;
        }
        if BIO_write(
            (*ctx).bio,
            buf.as_mut_ptr() as *const libc::c_void,
            l as libc::c_int,
        ) < 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        (*ctx).right_chars[(*ctx).used as usize] = to_char(*data.offset(i as isize));
        (*ctx).used = ((*ctx).used).wrapping_add(1);
        (*ctx).used;
        (*ctx).n = ((*ctx).n).wrapping_add(1);
        (*ctx).n;
        if (*ctx).used == 16 as libc::c_int as libc::c_uint {
            (*ctx).right_chars[16 as libc::c_int as usize] = '|' as i32 as libc::c_char;
            (*ctx).right_chars[17 as libc::c_int as usize] = '\n' as i32 as libc::c_char;
            if BIO_write(
                (*ctx).bio,
                ((*ctx).right_chars).as_mut_ptr() as *const libc::c_void,
                ::core::mem::size_of::<[libc::c_char; 18]>() as libc::c_ulong
                    as libc::c_int,
            ) < 0 as libc::c_int
            {
                return 0 as libc::c_int;
            }
            (*ctx).used = 0 as libc::c_int as libc::c_uint;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn finish(mut ctx: *mut hexdump_ctx) -> libc::c_int {
    let n_bytes: libc::c_uint = (*ctx).used;
    let mut l: libc::c_uint = 0;
    let mut buf: [libc::c_char; 5] = [0; 5];
    if n_bytes == 0 as libc::c_int as libc::c_uint {
        return 1 as libc::c_int;
    }
    OPENSSL_memset(
        buf.as_mut_ptr() as *mut libc::c_void,
        ' ' as i32,
        4 as libc::c_int as size_t,
    );
    buf[4 as libc::c_int as usize] = '|' as i32 as libc::c_char;
    while (*ctx).used < 16 as libc::c_int as libc::c_uint {
        l = 3 as libc::c_int as libc::c_uint;
        if (*ctx).used == 7 as libc::c_int as libc::c_uint {
            l = 4 as libc::c_int as libc::c_uint;
        } else if (*ctx).used == 15 as libc::c_int as libc::c_uint {
            l = 5 as libc::c_int as libc::c_uint;
        }
        if BIO_write(
            (*ctx).bio,
            buf.as_mut_ptr() as *const libc::c_void,
            l as libc::c_int,
        ) < 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        (*ctx).used = ((*ctx).used).wrapping_add(1);
        (*ctx).used;
    }
    (*ctx).right_chars[n_bytes as usize] = '|' as i32 as libc::c_char;
    (*ctx)
        .right_chars[n_bytes.wrapping_add(1 as libc::c_int as libc::c_uint)
        as usize] = '\n' as i32 as libc::c_char;
    if BIO_write(
        (*ctx).bio,
        ((*ctx).right_chars).as_mut_ptr() as *const libc::c_void,
        n_bytes.wrapping_add(2 as libc::c_int as libc::c_uint) as libc::c_int,
    ) < 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_hexdump(
    mut bio: *mut BIO,
    mut data: *const uint8_t,
    mut len: size_t,
    mut indent: libc::c_uint,
) -> libc::c_int {
    let mut ctx: hexdump_ctx = hexdump_ctx {
        bio: 0 as *mut BIO,
        right_chars: [0; 18],
        used: 0,
        n: 0,
        indent: 0,
    };
    OPENSSL_memset(
        &mut ctx as *mut hexdump_ctx as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<hexdump_ctx>() as libc::c_ulong,
    );
    ctx.bio = bio;
    ctx.indent = indent;
    if hexdump_write(&mut ctx, data, len) == 0 || finish(&mut ctx) == 0 {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_dump(
    mut bio: *mut BIO,
    mut data: *const libc::c_void,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut contents: *const uint8_t = 0 as *const uint8_t;
    let mut content_len: size_t = 0;
    if bio.is_null() || data.is_null() || len < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut mbio: *mut BIO = BIO_new(BIO_s_mem());
    if mbio.is_null() {
        return -(1 as libc::c_int);
    }
    if !(BIO_hexdump(
        mbio,
        data as *const uint8_t,
        len as size_t,
        0 as libc::c_int as libc::c_uint,
    ) == 0)
    {
        contents = 0 as *const uint8_t;
        content_len = 0 as libc::c_int as size_t;
        if !(BIO_mem_contents(mbio, &mut contents, &mut content_len) == 0) {
            ret = BIO_write(
                bio,
                contents as *const libc::c_void,
                content_len as libc::c_int,
            );
        }
    }
    BIO_free(mbio);
    return ret;
}
