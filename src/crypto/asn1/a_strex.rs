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
    pub type ASN1_VALUE_st;
    pub type stack_st_void;
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn ASN1_tag2str(tag: libc::c_int) -> *const libc::c_char;
    fn ASN1_mbstring_copy(
        out: *mut *mut ASN1_STRING,
        in_0: *const uint8_t,
        len: ossl_ssize_t,
        inform: libc::c_int,
        mask: libc::c_ulong,
    ) -> libc::c_int;
    fn i2d_ASN1_TYPE(in_0: *const ASN1_TYPE, outp: *mut *mut uint8_t) -> libc::c_int;
    fn UTF8_getc(
        str: *const libc::c_uchar,
        len: libc::c_int,
        val: *mut uint32_t,
    ) -> libc::c_int;
    fn UTF8_putc(
        str: *mut libc::c_uchar,
        len: libc::c_int,
        value: uint32_t,
    ) -> libc::c_int;
    fn asn1_type_set0_string(a: *mut ASN1_TYPE, str: *mut ASN1_STRING);
    fn BIO_free(bio: *mut BIO) -> libc::c_int;
    fn BIO_write(
        bio: *mut BIO,
        data: *const libc::c_void,
        len: libc::c_int,
    ) -> libc::c_int;
    fn BIO_puts(bio: *mut BIO, buf: *const libc::c_char) -> libc::c_int;
    fn BIO_printf(bio: *mut BIO, format: *const libc::c_char, _: ...) -> libc::c_int;
    fn BIO_new_fp(stream: *mut FILE, close_flag: libc::c_int) -> *mut BIO;
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_parse_generalized_time(
        cbs: *const CBS,
        out_tm: *mut tm,
        allow_timezone_offset: libc::c_int,
    ) -> libc::c_int;
    fn CBS_parse_utc_time(
        cbs: *const CBS,
        out_tm: *mut tm,
        allow_timezone_offset: libc::c_int,
    ) -> libc::c_int;
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
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
    fn memset(
        _: *mut libc::c_void,
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
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type ossl_ssize_t = ptrdiff_t;
pub type ASN1_BOOLEAN = libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_object_st {
    pub sn: *const libc::c_char,
    pub ln: *const libc::c_char,
    pub nid: libc::c_int,
    pub length: libc::c_int,
    pub data: *const libc::c_uchar,
    pub flags: libc::c_int,
}
pub type ASN1_OBJECT = asn1_object_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_string_st {
    pub length: libc::c_int,
    pub type_0: libc::c_int,
    pub data: *mut libc::c_uchar,
    pub flags: libc::c_long,
}
pub type ASN1_BIT_STRING = asn1_string_st;
pub type ASN1_BMPSTRING = asn1_string_st;
pub type ASN1_ENUMERATED = asn1_string_st;
pub type ASN1_GENERALIZEDTIME = asn1_string_st;
pub type ASN1_GENERALSTRING = asn1_string_st;
pub type ASN1_IA5STRING = asn1_string_st;
pub type ASN1_INTEGER = asn1_string_st;
pub type ASN1_OCTET_STRING = asn1_string_st;
pub type ASN1_PRINTABLESTRING = asn1_string_st;
pub type ASN1_STRING = asn1_string_st;
pub type ASN1_T61STRING = asn1_string_st;
pub type ASN1_TIME = asn1_string_st;
pub type ASN1_UNIVERSALSTRING = asn1_string_st;
pub type ASN1_UTCTIME = asn1_string_st;
pub type ASN1_UTF8STRING = asn1_string_st;
pub type ASN1_VISIBLESTRING = asn1_string_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_type_st {
    pub type_0: libc::c_int,
    pub value: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub ptr: *mut libc::c_char,
    pub boolean: ASN1_BOOLEAN,
    pub asn1_string: *mut ASN1_STRING,
    pub object: *mut ASN1_OBJECT,
    pub integer: *mut ASN1_INTEGER,
    pub enumerated: *mut ASN1_ENUMERATED,
    pub bit_string: *mut ASN1_BIT_STRING,
    pub octet_string: *mut ASN1_OCTET_STRING,
    pub printablestring: *mut ASN1_PRINTABLESTRING,
    pub t61string: *mut ASN1_T61STRING,
    pub ia5string: *mut ASN1_IA5STRING,
    pub generalstring: *mut ASN1_GENERALSTRING,
    pub bmpstring: *mut ASN1_BMPSTRING,
    pub universalstring: *mut ASN1_UNIVERSALSTRING,
    pub utctime: *mut ASN1_UTCTIME,
    pub generalizedtime: *mut ASN1_GENERALIZEDTIME,
    pub visiblestring: *mut ASN1_VISIBLESTRING,
    pub utf8string: *mut ASN1_UTF8STRING,
    pub set: *mut ASN1_STRING,
    pub sequence: *mut ASN1_STRING,
    pub asn1_value: *mut ASN1_VALUE,
}
pub type ASN1_VALUE = ASN1_VALUE_st;
pub type ASN1_TYPE = asn1_type_st;
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
pub struct cbs_st {
    pub data: *const uint8_t,
    pub len: size_t,
}
pub type CBS = cbs_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct tm {
    pub tm_sec: libc::c_int,
    pub tm_min: libc::c_int,
    pub tm_hour: libc::c_int,
    pub tm_mday: libc::c_int,
    pub tm_mon: libc::c_int,
    pub tm_year: libc::c_int,
    pub tm_wday: libc::c_int,
    pub tm_yday: libc::c_int,
    pub tm_isdst: libc::c_int,
    pub __tm_gmtoff: libc::c_long,
    pub __tm_zone: *const libc::c_char,
}
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
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_126_error_is_len_may_not_fit_in_int {
    #[bitfield(
        name = "static_assertion_at_line_126_error_is_len_may_not_fit_in_int",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_126_error_is_len_may_not_fit_in_int: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
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
unsafe extern "C" fn maybe_write(
    mut out: *mut BIO,
    mut buf: *const libc::c_void,
    mut len: libc::c_int,
) -> libc::c_int {
    return (out.is_null() || BIO_write(out, buf, len) == len) as libc::c_int;
}
unsafe extern "C" fn is_control_character(mut c: libc::c_uchar) -> libc::c_int {
    return ((c as libc::c_int) < 32 as libc::c_int
        || c as libc::c_int == 127 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn do_esc_char(
    mut c: uint32_t,
    mut flags: libc::c_ulong,
    mut do_quotes: *mut libc::c_char,
    mut out: *mut BIO,
    mut is_first: libc::c_int,
    mut is_last: libc::c_int,
) -> libc::c_int {
    let mut buf: [libc::c_char; 16] = [0; 16];
    let mut u8: libc::c_uchar = c as libc::c_uchar;
    if c > 0xffff as libc::c_int as uint32_t {
        snprintf(
            buf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 16]>() as libc::c_ulong,
            b"\\W%08X\0" as *const u8 as *const libc::c_char,
            c,
        );
    } else if c > 0xff as libc::c_int as uint32_t {
        snprintf(
            buf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 16]>() as libc::c_ulong,
            b"\\U%04X\0" as *const u8 as *const libc::c_char,
            c,
        );
    } else if flags & 4 as libc::c_ulong != 0 && c > 0x7f as libc::c_int as uint32_t {
        snprintf(
            buf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 16]>() as libc::c_ulong,
            b"\\%02X\0" as *const u8 as *const libc::c_char,
            c,
        );
    } else if flags & 2 as libc::c_ulong != 0
        && is_control_character(c as libc::c_uchar) != 0
    {
        snprintf(
            buf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 16]>() as libc::c_ulong,
            b"\\%02X\0" as *const u8 as *const libc::c_char,
            c,
        );
    } else if flags & 1 as libc::c_ulong != 0 {
        if c == '\\' as i32 as uint32_t || c == '"' as i32 as uint32_t {
            snprintf(
                buf.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 16]>() as libc::c_ulong,
                b"\\%c\0" as *const u8 as *const libc::c_char,
                c as libc::c_int,
            );
        } else if c == ',' as i32 as uint32_t || c == '+' as i32 as uint32_t
            || c == '<' as i32 as uint32_t || c == '>' as i32 as uint32_t
            || c == ';' as i32 as uint32_t
            || is_first != 0
                && (c == ' ' as i32 as uint32_t || c == '#' as i32 as uint32_t)
            || is_last != 0 && c == ' ' as i32 as uint32_t
        {
            if flags & 8 as libc::c_ulong != 0 {
                if !do_quotes.is_null() {
                    *do_quotes = 1 as libc::c_int as libc::c_char;
                }
                return if maybe_write(
                    out,
                    &mut u8 as *mut libc::c_uchar as *const libc::c_void,
                    1 as libc::c_int,
                ) != 0
                {
                    1 as libc::c_int
                } else {
                    -(1 as libc::c_int)
                };
            }
            snprintf(
                buf.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 16]>() as libc::c_ulong,
                b"\\%c\0" as *const u8 as *const libc::c_char,
                c as libc::c_int,
            );
        } else {
            return if maybe_write(
                out,
                &mut u8 as *mut libc::c_uchar as *const libc::c_void,
                1 as libc::c_int,
            ) != 0
            {
                1 as libc::c_int
            } else {
                -(1 as libc::c_int)
            }
        }
    } else if flags
        & (1 as libc::c_ulong | 8 as libc::c_ulong | 2 as libc::c_ulong
            | 4 as libc::c_ulong) != 0 && c == '\\' as i32 as uint32_t
    {
        snprintf(
            buf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 16]>() as libc::c_ulong,
            b"\\%c\0" as *const u8 as *const libc::c_char,
            c as libc::c_int,
        );
    } else {
        return if maybe_write(
            out,
            &mut u8 as *mut libc::c_uchar as *const libc::c_void,
            1 as libc::c_int,
        ) != 0
        {
            1 as libc::c_int
        } else {
            -(1 as libc::c_int)
        }
    }
    let mut len: libc::c_int = strlen(buf.as_mut_ptr()) as libc::c_int;
    return if maybe_write(out, buf.as_mut_ptr() as *const libc::c_void, len) != 0 {
        len
    } else {
        -(1 as libc::c_int)
    };
}
unsafe extern "C" fn do_buf(
    mut buf: *const libc::c_uchar,
    mut buflen: libc::c_int,
    mut encoding: libc::c_int,
    mut utf8_convert: libc::c_int,
    mut flags: libc::c_ulong,
    mut quotes: *mut libc::c_char,
    mut out: *mut BIO,
) -> libc::c_int {
    match encoding {
        4100 => {
            if buflen & 3 as libc::c_int != 0 {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    149 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_strex.c\0"
                        as *const u8 as *const libc::c_char,
                    142 as libc::c_int as libc::c_uint,
                );
                return -(1 as libc::c_int);
            }
        }
        4098 => {
            if buflen & 1 as libc::c_int != 0 {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    142 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_strex.c\0"
                        as *const u8 as *const libc::c_char,
                    148 as libc::c_int as libc::c_uint,
                );
                return -(1 as libc::c_int);
            }
        }
        _ => {}
    }
    let mut p: *const libc::c_uchar = buf;
    let mut q: *const libc::c_uchar = buf.offset(buflen as isize);
    let mut outlen: libc::c_int = 0 as libc::c_int;
    while p != q {
        let is_first: libc::c_int = (p == buf) as libc::c_int;
        let mut c: uint32_t = 0;
        match encoding {
            4100 => {
                let fresh0 = p;
                p = p.offset(1);
                c = (*fresh0 as uint32_t) << 24 as libc::c_int;
                let fresh1 = p;
                p = p.offset(1);
                c |= (*fresh1 as uint32_t) << 16 as libc::c_int;
                let fresh2 = p;
                p = p.offset(1);
                c |= (*fresh2 as uint32_t) << 8 as libc::c_int;
                let fresh3 = p;
                p = p.offset(1);
                c |= *fresh3 as uint32_t;
            }
            4098 => {
                let fresh4 = p;
                p = p.offset(1);
                c = (*fresh4 as uint32_t) << 8 as libc::c_int;
                let fresh5 = p;
                p = p.offset(1);
                c |= *fresh5 as uint32_t;
            }
            4097 => {
                let fresh6 = p;
                p = p.offset(1);
                c = *fresh6 as uint32_t;
            }
            4096 => {
                let mut consumed: libc::c_int = UTF8_getc(p, buflen, &mut c);
                if consumed < 0 as libc::c_int {
                    return -(1 as libc::c_int);
                }
                buflen -= consumed;
                p = p.offset(consumed as isize);
            }
            _ => {
                __assert_fail(
                    b"0\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_strex.c\0"
                        as *const u8 as *const libc::c_char,
                    192 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 79],
                        &[libc::c_char; 79],
                    >(
                        b"int do_buf(const unsigned char *, int, int, int, unsigned long, char *, BIO *)\0",
                    ))
                        .as_ptr(),
                );
                'c_9861: {
                    __assert_fail(
                        b"0\0" as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_strex.c\0"
                            as *const u8 as *const libc::c_char,
                        192 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 79],
                            &[libc::c_char; 79],
                        >(
                            b"int do_buf(const unsigned char *, int, int, int, unsigned long, char *, BIO *)\0",
                        ))
                            .as_ptr(),
                    );
                };
                return -(1 as libc::c_int);
            }
        }
        let is_last: libc::c_int = (p == q) as libc::c_int;
        if utf8_convert != 0 {
            let mut utfbuf: [libc::c_uchar; 6] = [0; 6];
            let mut utflen: libc::c_int = 0;
            utflen = UTF8_putc(
                utfbuf.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_uchar; 6]>() as libc::c_ulong
                    as libc::c_int,
                c,
            );
            let mut i: libc::c_int = 0 as libc::c_int;
            while i < utflen {
                let mut len: libc::c_int = do_esc_char(
                    utfbuf[i as usize] as uint32_t,
                    flags,
                    quotes,
                    out,
                    (is_first != 0 && i == 0 as libc::c_int) as libc::c_int,
                    (is_last != 0 && i == utflen - 1 as libc::c_int) as libc::c_int,
                );
                if len < 0 as libc::c_int {
                    return -(1 as libc::c_int);
                }
                outlen += len;
                i += 1;
                i;
            }
        } else {
            let mut len_0: libc::c_int = do_esc_char(
                c,
                flags,
                quotes,
                out,
                is_first,
                is_last,
            );
            if len_0 < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            outlen += len_0;
        }
    }
    return outlen;
}
unsafe extern "C" fn do_hex_dump(
    mut out: *mut BIO,
    mut buf: *mut libc::c_uchar,
    mut buflen: libc::c_int,
) -> libc::c_int {
    static mut hexdig: [libc::c_char; 17] = unsafe {
        *::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"0123456789ABCDEF\0")
    };
    let mut p: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut q: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut hextmp: [libc::c_char; 2] = [0; 2];
    if !out.is_null() {
        p = buf;
        q = buf.offset(buflen as isize);
        while p != q {
            hextmp[0 as libc::c_int
                as usize] = hexdig[(*p as libc::c_int >> 4 as libc::c_int) as usize];
            hextmp[1 as libc::c_int
                as usize] = hexdig[(*p as libc::c_int & 0xf as libc::c_int) as usize];
            if maybe_write(
                out,
                hextmp.as_mut_ptr() as *const libc::c_void,
                2 as libc::c_int,
            ) == 0
            {
                return -(1 as libc::c_int);
            }
            p = p.offset(1);
            p;
        }
    }
    return buflen << 1 as libc::c_int;
}
unsafe extern "C" fn do_dump(
    mut flags: libc::c_ulong,
    mut out: *mut BIO,
    mut str: *const ASN1_STRING,
) -> libc::c_int {
    if maybe_write(
        out,
        b"#\0" as *const u8 as *const libc::c_char as *const libc::c_void,
        1 as libc::c_int,
    ) == 0
    {
        return -(1 as libc::c_int);
    }
    if flags & 0x200 as libc::c_ulong == 0 {
        let mut outlen: libc::c_int = do_hex_dump(out, (*str).data, (*str).length);
        if outlen < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        return outlen + 1 as libc::c_int;
    }
    let mut t: ASN1_TYPE = asn1_type_st {
        type_0: 0,
        value: C2RustUnnamed {
            ptr: 0 as *mut libc::c_char,
        },
    };
    OPENSSL_memset(
        &mut t as *mut ASN1_TYPE as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<ASN1_TYPE>() as libc::c_ulong,
    );
    asn1_type_set0_string(&mut t, str as *mut ASN1_STRING);
    let mut der_buf: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut der_len: libc::c_int = i2d_ASN1_TYPE(&mut t, &mut der_buf);
    if der_len < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    let mut outlen_0: libc::c_int = do_hex_dump(out, der_buf, der_len);
    OPENSSL_free(der_buf as *mut libc::c_void);
    if outlen_0 < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    return outlen_0 + 1 as libc::c_int;
}
unsafe extern "C" fn string_type_to_encoding(mut type_0: libc::c_int) -> libc::c_int {
    match type_0 {
        12 => return 0x1000 as libc::c_int,
        18 | 19 | 20 | 22 | 23 | 24 | 26 => {
            return 0x1000 as libc::c_int | 1 as libc::c_int;
        }
        28 => return 0x1000 as libc::c_int | 4 as libc::c_int,
        30 => return 0x1000 as libc::c_int | 2 as libc::c_int,
        _ => {}
    }
    return -(1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_STRING_print_ex(
    mut out: *mut BIO,
    mut str: *const ASN1_STRING,
    mut flags: libc::c_ulong,
) -> libc::c_int {
    let mut type_0: libc::c_int = (*str).type_0;
    let mut outlen: libc::c_int = 0 as libc::c_int;
    if flags & 0x40 as libc::c_ulong != 0 {
        let mut tagname: *const libc::c_char = ASN1_tag2str(type_0);
        outlen = (outlen as libc::c_ulong).wrapping_add(strlen(tagname)) as libc::c_int
            as libc::c_int;
        if maybe_write(out, tagname as *const libc::c_void, outlen) == 0
            || maybe_write(
                out,
                b":\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                1 as libc::c_int,
            ) == 0
        {
            return -(1 as libc::c_int);
        }
        outlen += 1;
        outlen;
    }
    let mut encoding: libc::c_int = 0;
    if flags & 0x80 as libc::c_ulong != 0 {
        encoding = -(1 as libc::c_int);
    } else if flags & 0x20 as libc::c_ulong != 0 {
        encoding = 0x1000 as libc::c_int | 1 as libc::c_int;
    } else {
        encoding = string_type_to_encoding(type_0);
        if encoding == -(1 as libc::c_int)
            && flags & 0x100 as libc::c_ulong == 0 as libc::c_int as libc::c_ulong
        {
            encoding = 0x1000 as libc::c_int | 1 as libc::c_int;
        }
    }
    if encoding == -(1 as libc::c_int) {
        let mut len: libc::c_int = do_dump(flags, out, str);
        if len < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        outlen += len;
        return outlen;
    }
    let mut utf8_convert: libc::c_int = 0 as libc::c_int;
    if flags & 0x10 as libc::c_ulong != 0 {
        if encoding == 0x1000 as libc::c_int {
            encoding = 0x1000 as libc::c_int | 1 as libc::c_int;
        } else {
            utf8_convert = 1 as libc::c_int;
        }
    }
    let mut quotes: libc::c_char = 0 as libc::c_int as libc::c_char;
    let mut len_0: libc::c_int = do_buf(
        (*str).data,
        (*str).length,
        encoding,
        utf8_convert,
        flags,
        &mut quotes,
        0 as *mut BIO,
    );
    if len_0 < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    outlen += len_0;
    if quotes != 0 {
        outlen += 2 as libc::c_int;
    }
    if out.is_null() {
        return outlen;
    }
    if quotes as libc::c_int != 0
        && maybe_write(
            out,
            b"\"\0" as *const u8 as *const libc::c_char as *const libc::c_void,
            1 as libc::c_int,
        ) == 0
        || do_buf(
            (*str).data,
            (*str).length,
            encoding,
            utf8_convert,
            flags,
            0 as *mut libc::c_char,
            out,
        ) < 0 as libc::c_int
        || quotes as libc::c_int != 0
            && maybe_write(
                out,
                b"\"\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                1 as libc::c_int,
            ) == 0
    {
        return -(1 as libc::c_int);
    }
    return outlen;
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_STRING_print_ex_fp(
    mut fp: *mut FILE,
    mut str: *const ASN1_STRING,
    mut flags: libc::c_ulong,
) -> libc::c_int {
    let mut bio: *mut BIO = 0 as *mut BIO;
    if !fp.is_null() {
        bio = BIO_new_fp(fp, 0 as libc::c_int);
        if bio.is_null() {
            return -(1 as libc::c_int);
        }
    }
    let mut ret: libc::c_int = ASN1_STRING_print_ex(bio, str, flags);
    BIO_free(bio);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_STRING_to_UTF8(
    mut out: *mut *mut libc::c_uchar,
    mut in_0: *const ASN1_STRING,
) -> libc::c_int {
    if in_0.is_null() {
        return -(1 as libc::c_int);
    }
    let mut mbflag: libc::c_int = string_type_to_encoding((*in_0).type_0);
    if mbflag == -(1 as libc::c_int) {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            185 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_strex.c\0" as *const u8
                as *const libc::c_char,
            404 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    let mut stmp: ASN1_STRING = asn1_string_st {
        length: 0,
        type_0: 0,
        data: 0 as *mut libc::c_uchar,
        flags: 0,
    };
    let mut str: *mut ASN1_STRING = &mut stmp;
    stmp.data = 0 as *mut libc::c_uchar;
    stmp.length = 0 as libc::c_int;
    stmp.flags = 0 as libc::c_int as libc::c_long;
    let mut ret: libc::c_int = ASN1_mbstring_copy(
        &mut str,
        (*in_0).data,
        (*in_0).length as ossl_ssize_t,
        mbflag,
        0x2000 as libc::c_int as libc::c_ulong,
    );
    if ret < 0 as libc::c_int {
        return ret;
    }
    *out = stmp.data;
    return stmp.length;
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_STRING_print(
    mut bp: *mut BIO,
    mut v: *const ASN1_STRING,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut n: libc::c_int = 0;
    let mut buf: [libc::c_char; 80] = [0; 80];
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    if v.is_null() {
        return 0 as libc::c_int;
    }
    n = 0 as libc::c_int;
    p = (*v).data as *const libc::c_char;
    i = 0 as libc::c_int;
    while i < (*v).length {
        if *p.offset(i as isize) as libc::c_int > '~' as i32
            || (*p.offset(i as isize) as libc::c_int) < ' ' as i32
                && *p.offset(i as isize) as libc::c_int != '\n' as i32
                && *p.offset(i as isize) as libc::c_int != '\r' as i32
        {
            buf[n as usize] = '.' as i32 as libc::c_char;
        } else {
            buf[n as usize] = *p.offset(i as isize);
        }
        n += 1;
        n;
        if n >= 80 as libc::c_int {
            if BIO_write(bp, buf.as_mut_ptr() as *const libc::c_void, n)
                <= 0 as libc::c_int
            {
                return 0 as libc::c_int;
            }
            n = 0 as libc::c_int;
        }
        i += 1;
        i;
    }
    if n > 0 as libc::c_int {
        if BIO_write(bp, buf.as_mut_ptr() as *const libc::c_void, n) <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_TIME_print(
    mut bp: *mut BIO,
    mut tm: *const ASN1_TIME,
) -> libc::c_int {
    if (*tm).type_0 == 23 as libc::c_int {
        return ASN1_UTCTIME_print(bp, tm);
    }
    if (*tm).type_0 == 24 as libc::c_int {
        return ASN1_GENERALIZEDTIME_print(bp, tm);
    }
    BIO_puts(bp, b"Bad time value\0" as *const u8 as *const libc::c_char);
    return 0 as libc::c_int;
}
static mut mon: [*const libc::c_char; 12] = [
    b"Jan\0" as *const u8 as *const libc::c_char,
    b"Feb\0" as *const u8 as *const libc::c_char,
    b"Mar\0" as *const u8 as *const libc::c_char,
    b"Apr\0" as *const u8 as *const libc::c_char,
    b"May\0" as *const u8 as *const libc::c_char,
    b"Jun\0" as *const u8 as *const libc::c_char,
    b"Jul\0" as *const u8 as *const libc::c_char,
    b"Aug\0" as *const u8 as *const libc::c_char,
    b"Sep\0" as *const u8 as *const libc::c_char,
    b"Oct\0" as *const u8 as *const libc::c_char,
    b"Nov\0" as *const u8 as *const libc::c_char,
    b"Dec\0" as *const u8 as *const libc::c_char,
];
#[no_mangle]
pub unsafe extern "C" fn ASN1_GENERALIZEDTIME_print(
    mut bp: *mut BIO,
    mut tm: *const ASN1_GENERALIZEDTIME,
) -> libc::c_int {
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, (*tm).data, (*tm).length as size_t);
    let mut utc: tm = tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 0,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        __tm_gmtoff: 0,
        __tm_zone: 0 as *const libc::c_char,
    };
    if CBS_parse_generalized_time(&mut cbs, &mut utc, 0 as libc::c_int) == 0 {
        BIO_puts(bp, b"Bad time value\0" as *const u8 as *const libc::c_char);
        return 0 as libc::c_int;
    }
    return (BIO_printf(
        bp,
        b"%s %2d %02d:%02d:%02d %d GMT\0" as *const u8 as *const libc::c_char,
        mon[utc.tm_mon as usize],
        utc.tm_mday,
        utc.tm_hour,
        utc.tm_min,
        utc.tm_sec,
        utc.tm_year + 1900 as libc::c_int,
    ) > 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_UTCTIME_print(
    mut bp: *mut BIO,
    mut tm: *const ASN1_UTCTIME,
) -> libc::c_int {
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, (*tm).data, (*tm).length as size_t);
    let mut utc: tm = tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 0,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        __tm_gmtoff: 0,
        __tm_zone: 0 as *const libc::c_char,
    };
    if CBS_parse_utc_time(&mut cbs, &mut utc, 0 as libc::c_int) == 0 {
        BIO_puts(bp, b"Bad time value\0" as *const u8 as *const libc::c_char);
        return 0 as libc::c_int;
    }
    return (BIO_printf(
        bp,
        b"%s %2d %02d:%02d:%02d %d GMT\0" as *const u8 as *const libc::c_char,
        mon[utc.tm_mon as usize],
        utc.tm_mday,
        utc.tm_hour,
        utc.tm_min,
        utc.tm_sec,
        utc.tm_year + 1900 as libc::c_int,
    ) > 0 as libc::c_int) as libc::c_int;
}
