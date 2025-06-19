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
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn BN_new() -> *mut BIGNUM;
    fn BN_free(bn: *mut BIGNUM);
    fn BN_dup(src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_num_bits(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_zero(bn: *mut BIGNUM);
    fn BN_is_negative(bn: *const BIGNUM) -> libc::c_int;
    fn BN_bin2bn(in_0: *const uint8_t, len: size_t, ret: *mut BIGNUM) -> *mut BIGNUM;
    fn BN_bn2bin(in_0: *const BIGNUM, out: *mut uint8_t) -> size_t;
    fn BN_bn2bin_padded(
        out: *mut uint8_t,
        len: size_t,
        in_0: *const BIGNUM,
    ) -> libc::c_int;
    fn BN_add_word(a: *mut BIGNUM, w: BN_ULONG) -> libc::c_int;
    fn BN_mul_word(bn: *mut BIGNUM, w: BN_ULONG) -> libc::c_int;
    fn BN_div_word(numerator: *mut BIGNUM, divisor: BN_ULONG) -> BN_ULONG;
    fn BN_is_zero(bn: *const BIGNUM) -> libc::c_int;
    fn BN_clear_bit(a: *mut BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BIO_free(bio: *mut BIO) -> libc::c_int;
    fn BIO_write(
        bio: *mut BIO,
        data: *const libc::c_void,
        len: libc::c_int,
    ) -> libc::c_int;
    fn BIO_new_fp(stream: *mut FILE, close_flag: libc::c_int) -> *mut BIO;
    fn CBB_init(cbb: *mut CBB, initial_capacity: size_t) -> libc::c_int;
    fn CBB_cleanup(cbb: *mut CBB);
    fn CBB_finish(
        cbb: *mut CBB,
        out_data: *mut *mut uint8_t,
        out_len: *mut size_t,
    ) -> libc::c_int;
    fn CBB_add_space(
        cbb: *mut CBB,
        out_data: *mut *mut uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn CBB_add_u8(cbb: *mut CBB, value: uint8_t) -> libc::c_int;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_isdigit(c: libc::c_int) -> libc::c_int;
    fn OPENSSL_isxdigit(c: libc::c_int) -> libc::c_int;
    fn OPENSSL_fromxdigit(out: *mut uint8_t, c: libc::c_int) -> libc::c_int;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn bn_minimal_width(bn: *const BIGNUM) -> libc::c_int;
    fn bn_set_minimal_width(bn: *mut BIGNUM);
    fn bn_expand(bn: *mut BIGNUM, bits: size_t) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bignum_st {
    pub d: *mut BN_ULONG,
    pub width: libc::c_int,
    pub dmax: libc::c_int,
    pub neg: libc::c_int,
    pub flags: libc::c_int,
}
pub type BN_ULONG = uint64_t;
pub type BIGNUM = bignum_st;
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
pub struct cbb_st {
    pub child: *mut CBB,
    pub is_child: libc::c_char,
    pub u: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub base: cbb_buffer_st,
    pub child: cbb_child_st,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct cbb_child_st {
    pub base: *mut cbb_buffer_st,
    pub offset: size_t,
    pub pending_len_len: uint8_t,
    #[bitfield(name = "pending_is_asn1", ty = "libc::c_uint", bits = "0..=0")]
    pub pending_is_asn1: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 6],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct cbb_buffer_st {
    pub buf: *mut uint8_t,
    pub len: size_t,
    pub cap: size_t,
    #[bitfield(name = "can_resize", ty = "libc::c_uint", bits = "0..=0")]
    #[bitfield(name = "error", ty = "libc::c_uint", bits = "1..=1")]
    pub can_resize_error: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
pub type CBB = cbb_st;
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
pub type char_test_func = Option::<unsafe extern "C" fn(libc::c_int) -> libc::c_int>;
pub type decode_func = Option::<
    unsafe extern "C" fn(*mut BIGNUM, *const libc::c_char, libc::c_int) -> libc::c_int,
>;
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_bn2cbb_padded(
    mut out: *mut CBB,
    mut len: size_t,
    mut in_0: *const BIGNUM,
) -> libc::c_int {
    let mut ptr: *mut uint8_t = 0 as *mut uint8_t;
    return (CBB_add_space(out, &mut ptr, len) != 0
        && BN_bn2bin_padded(ptr, len, in_0) != 0) as libc::c_int;
}
static mut hextable: [libc::c_char; 17] = unsafe {
    *::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"0123456789ABCDEF\0")
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_bn2hex(mut bn: *const BIGNUM) -> *mut libc::c_char {
    let mut width: libc::c_int = bn_minimal_width(bn);
    let mut buf: *mut libc::c_char = OPENSSL_zalloc(
        (1 as libc::c_int + 1 as libc::c_int
            + width * 8 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as size_t,
    ) as *mut libc::c_char;
    if buf.is_null() {
        return 0 as *mut libc::c_char;
    }
    let mut p: *mut libc::c_char = buf;
    if (*bn).neg != 0 {
        let fresh0 = p;
        p = p.offset(1);
        *fresh0 = '-' as i32 as libc::c_char;
    }
    if BN_is_zero(bn) != 0 {
        let fresh1 = p;
        p = p.offset(1);
        *fresh1 = '0' as i32 as libc::c_char;
    }
    let mut z: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_int = width - 1 as libc::c_int;
    while i >= 0 as libc::c_int {
        let mut j: libc::c_int = 64 as libc::c_int - 8 as libc::c_int;
        while j >= 0 as libc::c_int {
            let mut v: libc::c_int = (*((*bn).d).offset(i as isize) >> j as libc::c_long)
                as libc::c_int & 0xff as libc::c_int;
            if z != 0 || v != 0 as libc::c_int {
                let fresh2 = p;
                p = p.offset(1);
                *fresh2 = hextable[(v >> 4 as libc::c_int) as usize];
                let fresh3 = p;
                p = p.offset(1);
                *fresh3 = hextable[(v & 0xf as libc::c_int) as usize];
                z = 1 as libc::c_int;
            }
            j -= 8 as libc::c_int;
        }
        i -= 1;
        i;
    }
    if *p as libc::c_int == '\0' as i32 {} else {
        __assert_fail(
            b"*p == '\\0'\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bn_extra/convert.c\0" as *const u8
                as *const libc::c_char,
            108 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 32],
                &[libc::c_char; 32],
            >(b"char *BN_bn2hex(const BIGNUM *)\0"))
                .as_ptr(),
        );
    }
    'c_2045: {
        if *p as libc::c_int == '\0' as i32 {} else {
            __assert_fail(
                b"*p == '\\0'\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bn_extra/convert.c\0"
                    as *const u8 as *const libc::c_char,
                108 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 32],
                    &[libc::c_char; 32],
                >(b"char *BN_bn2hex(const BIGNUM *)\0"))
                    .as_ptr(),
            );
        }
    };
    return buf;
}
unsafe extern "C" fn decode_hex(
    mut bn: *mut BIGNUM,
    mut in_0: *const libc::c_char,
    mut in_len: libc::c_int,
) -> libc::c_int {
    if in_len > 2147483647 as libc::c_int / 4 as libc::c_int {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bn_extra/convert.c\0" as *const u8
                as *const libc::c_char,
            116 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if bn_expand(bn, (in_len * 4 as libc::c_int) as size_t) == 0 {
        return 0 as libc::c_int;
    }
    let mut i: libc::c_int = 0 as libc::c_int;
    while in_len > 0 as libc::c_int {
        let mut todo: libc::c_int = 8 as libc::c_int * 2 as libc::c_int;
        if todo > in_len {
            todo = in_len;
        }
        let mut word: BN_ULONG = 0 as libc::c_int as BN_ULONG;
        let mut j: libc::c_int = 0;
        j = todo;
        while j > 0 as libc::c_int {
            let mut hex: uint8_t = 0 as libc::c_int as uint8_t;
            if OPENSSL_fromxdigit(
                &mut hex,
                *in_0.offset((in_len - j) as isize) as libc::c_int,
            ) == 0
            {
                __assert_fail(
                    b"0\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bn_extra/convert.c\0"
                        as *const u8 as *const libc::c_char,
                    138 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 44],
                        &[libc::c_char; 44],
                    >(b"int decode_hex(BIGNUM *, const char *, int)\0"))
                        .as_ptr(),
                );
                'c_2376: {
                    __assert_fail(
                        b"0\0" as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/bn_extra/convert.c\0"
                            as *const u8 as *const libc::c_char,
                        138 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 44],
                            &[libc::c_char; 44],
                        >(b"int decode_hex(BIGNUM *, const char *, int)\0"))
                            .as_ptr(),
                    );
                };
            }
            word = word << 4 as libc::c_int | hex as BN_ULONG;
            j -= 1;
            j;
        }
        let fresh4 = i;
        i = i + 1;
        *((*bn).d).offset(fresh4 as isize) = word;
        in_len -= todo;
    }
    if i <= (*bn).dmax {} else {
        __assert_fail(
            b"i <= bn->dmax\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bn_extra/convert.c\0" as *const u8
                as *const libc::c_char,
            146 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 44],
                &[libc::c_char; 44],
            >(b"int decode_hex(BIGNUM *, const char *, int)\0"))
                .as_ptr(),
        );
    }
    'c_2278: {
        if i <= (*bn).dmax {} else {
            __assert_fail(
                b"i <= bn->dmax\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bn_extra/convert.c\0"
                    as *const u8 as *const libc::c_char,
                146 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 44],
                    &[libc::c_char; 44],
                >(b"int decode_hex(BIGNUM *, const char *, int)\0"))
                    .as_ptr(),
            );
        }
    };
    (*bn).width = i;
    return 1 as libc::c_int;
}
unsafe extern "C" fn decode_dec(
    mut bn: *mut BIGNUM,
    mut in_0: *const libc::c_char,
    mut in_len: libc::c_int,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    let mut l: BN_ULONG = 0 as libc::c_int as BN_ULONG;
    j = 19 as libc::c_int - in_len % 19 as libc::c_int;
    if j == 19 as libc::c_int {
        j = 0 as libc::c_int;
    }
    l = 0 as libc::c_int as BN_ULONG;
    i = 0 as libc::c_int;
    while i < in_len {
        l = l * 10 as libc::c_int as BN_ULONG;
        l = l
            .wrapping_add(
                (*in_0.offset(i as isize) as libc::c_int - '0' as i32) as BN_ULONG,
            );
        j += 1;
        if j == 19 as libc::c_int {
            if BN_mul_word(bn, 10000000000000000000 as libc::c_ulong) == 0
                || BN_add_word(bn, l) == 0
            {
                return 0 as libc::c_int;
            }
            l = 0 as libc::c_int as BN_ULONG;
            j = 0 as libc::c_int;
        }
        i += 1;
        i;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn bn_x2bn(
    mut outp: *mut *mut BIGNUM,
    mut in_0: *const libc::c_char,
    mut decode: decode_func,
    mut want_char: char_test_func,
) -> libc::c_int {
    let mut ret: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut neg: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_int = 0;
    let mut num: libc::c_int = 0;
    if in_0.is_null() || *in_0 as libc::c_int == 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if *in_0 as libc::c_int == '-' as i32 {
        neg = 1 as libc::c_int;
        in_0 = in_0.offset(1);
        in_0;
    }
    i = 0 as libc::c_int;
    while want_char
        .expect(
            "non-null function pointer",
        )(*in_0.offset(i as isize) as libc::c_uchar as libc::c_int) != 0
        && i + neg < 2147483647 as libc::c_int
    {
        i += 1;
        i;
    }
    if i == 0 as libc::c_int {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            119 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bn_extra/convert.c\0" as *const u8
                as *const libc::c_char,
            197 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    num = i + neg;
    if outp.is_null() {
        return num;
    }
    if (*outp).is_null() {
        ret = BN_new();
        if ret.is_null() {
            return 0 as libc::c_int;
        }
    } else {
        ret = *outp;
        BN_zero(ret);
    }
    if decode.expect("non-null function pointer")(ret, in_0, i) == 0 {
        if (*outp).is_null() {
            BN_free(ret);
        }
        return 0 as libc::c_int;
    } else {
        bn_set_minimal_width(ret);
        if BN_is_zero(ret) == 0 {
            (*ret).neg = neg;
        }
        *outp = ret;
        return num;
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_hex2bn(
    mut outp: *mut *mut BIGNUM,
    mut in_0: *const libc::c_char,
) -> libc::c_int {
    return bn_x2bn(
        outp,
        in_0,
        Some(
            decode_hex
                as unsafe extern "C" fn(
                    *mut BIGNUM,
                    *const libc::c_char,
                    libc::c_int,
                ) -> libc::c_int,
        ),
        Some(OPENSSL_isxdigit as unsafe extern "C" fn(libc::c_int) -> libc::c_int),
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_bn2dec(mut a: *const BIGNUM) -> *mut libc::c_char {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = 0;
    let mut current_block: u64;
    let mut copy: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut cbb: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    if !(CBB_init(&mut cbb, 16 as libc::c_int as size_t) == 0
        || CBB_add_u8(&mut cbb, 0 as libc::c_int as uint8_t) == 0)
    {
        if BN_is_zero(a) != 0 {
            if CBB_add_u8(&mut cbb, '0' as i32 as uint8_t) == 0 {
                current_block = 2259778826565158224;
            } else {
                current_block = 12039483399334584727;
            }
        } else {
            copy = BN_dup(a);
            if copy.is_null() {
                current_block = 2259778826565158224;
            } else {
                's_36: loop {
                    if !(BN_is_zero(copy) == 0) {
                        current_block = 12039483399334584727;
                        break;
                    }
                    let mut word: BN_ULONG = BN_div_word(
                        copy,
                        10000000000000000000 as libc::c_ulong,
                    );
                    if word == -(1 as libc::c_int) as BN_ULONG {
                        current_block = 2259778826565158224;
                        break;
                    }
                    let add_leading_zeros: libc::c_int = (BN_is_zero(copy) == 0)
                        as libc::c_int;
                    let mut i: libc::c_int = 0 as libc::c_int;
                    while i < 19 as libc::c_int
                        && (add_leading_zeros != 0
                            || word != 0 as libc::c_int as BN_ULONG)
                    {
                        if CBB_add_u8(
                            &mut cbb,
                            ('0' as i32 as BN_ULONG)
                                .wrapping_add(word % 10 as libc::c_int as BN_ULONG)
                                as uint8_t,
                        ) == 0
                        {
                            current_block = 2259778826565158224;
                            break 's_36;
                        }
                        word = word / 10 as libc::c_int as BN_ULONG;
                        i += 1;
                        i;
                    }
                    if word == 0 as libc::c_int as BN_ULONG {} else {
                        __assert_fail(
                            b"word == 0\0" as *const u8 as *const libc::c_char,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bn_extra/convert.c\0"
                                as *const u8 as *const libc::c_char,
                            274 as libc::c_int as libc::c_uint,
                            (*::core::mem::transmute::<
                                &[u8; 32],
                                &[libc::c_char; 32],
                            >(b"char *BN_bn2dec(const BIGNUM *)\0"))
                                .as_ptr(),
                        );
                    }
                    'c_2906: {
                        if word == 0 as libc::c_int as BN_ULONG {} else {
                            __assert_fail(
                                b"word == 0\0" as *const u8 as *const libc::c_char,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bn_extra/convert.c\0"
                                    as *const u8 as *const libc::c_char,
                                274 as libc::c_int as libc::c_uint,
                                (*::core::mem::transmute::<
                                    &[u8; 32],
                                    &[libc::c_char; 32],
                                >(b"char *BN_bn2dec(const BIGNUM *)\0"))
                                    .as_ptr(),
                            );
                        }
                    };
                }
            }
        }
        match current_block {
            2259778826565158224 => {}
            _ => {
                if !(BN_is_negative(a) != 0
                    && CBB_add_u8(&mut cbb, '-' as i32 as uint8_t) == 0)
                {
                    data = 0 as *mut uint8_t;
                    len = 0;
                    if !(CBB_finish(&mut cbb, &mut data, &mut len) == 0) {
                        let mut i_0: size_t = 0 as libc::c_int as size_t;
                        while i_0 < len / 2 as libc::c_int as size_t {
                            let mut tmp: uint8_t = *data.offset(i_0 as isize);
                            *data
                                .offset(
                                    i_0 as isize,
                                ) = *data
                                .offset(
                                    len
                                        .wrapping_sub(1 as libc::c_int as size_t)
                                        .wrapping_sub(i_0) as isize,
                                );
                            *data
                                .offset(
                                    len
                                        .wrapping_sub(1 as libc::c_int as size_t)
                                        .wrapping_sub(i_0) as isize,
                                ) = tmp;
                            i_0 = i_0.wrapping_add(1);
                            i_0;
                        }
                        BN_free(copy);
                        return data as *mut libc::c_char;
                    }
                }
            }
        }
    }
    BN_free(copy);
    CBB_cleanup(&mut cbb);
    return 0 as *mut libc::c_char;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_dec2bn(
    mut outp: *mut *mut BIGNUM,
    mut in_0: *const libc::c_char,
) -> libc::c_int {
    return bn_x2bn(
        outp,
        in_0,
        Some(
            decode_dec
                as unsafe extern "C" fn(
                    *mut BIGNUM,
                    *const libc::c_char,
                    libc::c_int,
                ) -> libc::c_int,
        ),
        Some(OPENSSL_isdigit as unsafe extern "C" fn(libc::c_int) -> libc::c_int),
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_asc2bn(
    mut outp: *mut *mut BIGNUM,
    mut in_0: *const libc::c_char,
) -> libc::c_int {
    let orig_in: *const libc::c_char = in_0;
    if *in_0 as libc::c_int == '-' as i32 {
        in_0 = in_0.offset(1);
        in_0;
    }
    if *in_0.offset(0 as libc::c_int as isize) as libc::c_int == '0' as i32
        && (*in_0.offset(1 as libc::c_int as isize) as libc::c_int == 'X' as i32
            || *in_0.offset(1 as libc::c_int as isize) as libc::c_int == 'x' as i32)
    {
        if BN_hex2bn(outp, in_0.offset(2 as libc::c_int as isize)) == 0 {
            return 0 as libc::c_int;
        }
    } else if BN_dec2bn(outp, in_0) == 0 {
        return 0 as libc::c_int
    }
    if *orig_in as libc::c_int == '-' as i32 && BN_is_zero(*outp) == 0 {
        (**outp).neg = 1 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_print(
    mut bp: *mut BIO,
    mut a: *const BIGNUM,
) -> libc::c_int {
    let mut current_block: u64;
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    let mut v: libc::c_int = 0;
    let mut z: libc::c_int = 0 as libc::c_int;
    let mut ret: libc::c_int = 0 as libc::c_int;
    if !((*a).neg != 0
        && BIO_write(
            bp,
            b"-\0" as *const u8 as *const libc::c_char as *const libc::c_void,
            1 as libc::c_int,
        ) != 1 as libc::c_int)
    {
        if !(BN_is_zero(a) != 0
            && BIO_write(
                bp,
                b"0\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                1 as libc::c_int,
            ) != 1 as libc::c_int)
        {
            i = bn_minimal_width(a) - 1 as libc::c_int;
            's_20: loop {
                if !(i >= 0 as libc::c_int) {
                    current_block = 1856101646708284338;
                    break;
                }
                j = 64 as libc::c_int - 4 as libc::c_int;
                while j >= 0 as libc::c_int {
                    v = (*((*a).d).offset(i as isize) >> j as libc::c_long)
                        as libc::c_int & 0xf as libc::c_int;
                    if z != 0 || v != 0 as libc::c_int {
                        if BIO_write(
                            bp,
                            &*hextable.as_ptr().offset(v as isize) as *const libc::c_char
                                as *const libc::c_void,
                            1 as libc::c_int,
                        ) != 1 as libc::c_int
                        {
                            current_block = 5339354993463637614;
                            break 's_20;
                        }
                        z = 1 as libc::c_int;
                    }
                    j -= 4 as libc::c_int;
                }
                i -= 1;
                i;
            }
            match current_block {
                5339354993463637614 => {}
                _ => {
                    ret = 1 as libc::c_int;
                }
            }
        }
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_print_fp(
    mut fp: *mut FILE,
    mut a: *const BIGNUM,
) -> libc::c_int {
    let mut b: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if b.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = BN_print(b, a);
    BIO_free(b);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_bn2mpi(
    mut in_0: *const BIGNUM,
    mut out: *mut uint8_t,
) -> size_t {
    let bits: size_t = BN_num_bits(in_0) as size_t;
    let bytes: size_t = bits.wrapping_add(7 as libc::c_int as size_t)
        / 8 as libc::c_int as size_t;
    let mut extend: libc::c_int = 0 as libc::c_int;
    if bytes != 0 as libc::c_int as size_t
        && bits & 0x7 as libc::c_int as size_t == 0 as libc::c_int as size_t
    {
        extend = 1 as libc::c_int;
    }
    let len: size_t = bytes.wrapping_add(extend as size_t);
    if len < bytes || (4 as libc::c_int as size_t).wrapping_add(len) < len
        || len & 0xffffffff as libc::c_uint as size_t != len
    {
        if !out.is_null() {
            OPENSSL_memset(
                out as *mut libc::c_void,
                0 as libc::c_int,
                4 as libc::c_int as size_t,
            );
        }
        return 4 as libc::c_int as size_t;
    }
    if out.is_null() {
        return (4 as libc::c_int as size_t).wrapping_add(len);
    }
    *out.offset(0 as libc::c_int as isize) = (len >> 24 as libc::c_int) as uint8_t;
    *out.offset(1 as libc::c_int as isize) = (len >> 16 as libc::c_int) as uint8_t;
    *out.offset(2 as libc::c_int as isize) = (len >> 8 as libc::c_int) as uint8_t;
    *out.offset(3 as libc::c_int as isize) = len as uint8_t;
    if extend != 0 {
        *out.offset(4 as libc::c_int as isize) = 0 as libc::c_int as uint8_t;
    }
    BN_bn2bin(in_0, out.offset(4 as libc::c_int as isize).offset(extend as isize));
    if (*in_0).neg != 0 && len > 0 as libc::c_int as size_t {
        let ref mut fresh5 = *out.offset(4 as libc::c_int as isize);
        *fresh5 = (*fresh5 as libc::c_int | 0x80 as libc::c_int) as uint8_t;
    }
    return len.wrapping_add(4 as libc::c_int as size_t);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_mpi2bn(
    mut in_0: *const uint8_t,
    mut len: size_t,
    mut out: *mut BIGNUM,
) -> *mut BIGNUM {
    if len < 4 as libc::c_int as size_t {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            117 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bn_extra/convert.c\0" as *const u8
                as *const libc::c_char,
            416 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut BIGNUM;
    }
    let in_len: size_t = (*in_0.offset(0 as libc::c_int as isize) as size_t)
        << 24 as libc::c_int
        | (*in_0.offset(1 as libc::c_int as isize) as size_t) << 16 as libc::c_int
        | (*in_0.offset(2 as libc::c_int as isize) as size_t) << 8 as libc::c_int
        | *in_0.offset(3 as libc::c_int as isize) as size_t;
    if in_len != len.wrapping_sub(4 as libc::c_int as size_t) {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            117 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bn_extra/convert.c\0" as *const u8
                as *const libc::c_char,
            424 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut BIGNUM;
    }
    let mut out_is_alloced: libc::c_int = 0 as libc::c_int;
    if out.is_null() {
        out = BN_new();
        if out.is_null() {
            return 0 as *mut BIGNUM;
        }
        out_is_alloced = 1 as libc::c_int;
    }
    if in_len == 0 as libc::c_int as size_t {
        BN_zero(out);
        return out;
    }
    in_0 = in_0.offset(4 as libc::c_int as isize);
    if (BN_bin2bn(in_0, in_len, out)).is_null() {
        if out_is_alloced != 0 {
            BN_free(out);
        }
        return 0 as *mut BIGNUM;
    }
    (*out)
        .neg = (*in_0 as libc::c_int & 0x80 as libc::c_int != 0 as libc::c_int)
        as libc::c_int;
    if (*out).neg != 0 {
        let mut num_bits: libc::c_uint = BN_num_bits(out);
        if num_bits >= 2147483647 as libc::c_int as libc::c_uint {
            if out_is_alloced != 0 {
                BN_free(out);
            }
            return 0 as *mut BIGNUM;
        }
        BN_clear_bit(out, num_bits as libc::c_int - 1 as libc::c_int);
    }
    return out;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_bn2binpad(
    mut in_0: *const BIGNUM,
    mut out: *mut uint8_t,
    mut len: libc::c_int,
) -> libc::c_int {
    if len < 0 as libc::c_int || BN_bn2bin_padded(out, len as size_t, in_0) == 0 {
        return -(1 as libc::c_int);
    }
    return len;
}
