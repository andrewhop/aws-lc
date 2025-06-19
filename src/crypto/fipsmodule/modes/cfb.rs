#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(label_break_value)]
extern "C" {
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
pub struct aes_key_st {
    pub rd_key: [uint32_t; 60],
    pub rounds: libc::c_uint,
}
pub type AES_KEY = aes_key_st;
pub type crypto_word_t = uint64_t;
pub type block128_f = Option::<
    unsafe extern "C" fn(*const uint8_t, *mut uint8_t, *const AES_KEY) -> (),
>;
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
unsafe extern "C" fn CRYPTO_load_word_le(
    mut in_0: *const libc::c_void,
) -> crypto_word_t {
    let mut v: crypto_word_t = 0;
    OPENSSL_memcpy(
        &mut v as *mut crypto_word_t as *mut libc::c_void,
        in_0,
        ::core::mem::size_of::<crypto_word_t>() as libc::c_ulong,
    );
    return v;
}
#[inline]
unsafe extern "C" fn CRYPTO_store_word_le(
    mut out: *mut libc::c_void,
    mut v: crypto_word_t,
) {
    OPENSSL_memcpy(
        out,
        &mut v as *mut crypto_word_t as *const libc::c_void,
        ::core::mem::size_of::<crypto_word_t>() as libc::c_ulong,
    );
}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_cfb128_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut len: size_t,
    mut key: *const AES_KEY,
    mut ivec: *mut uint8_t,
    mut num: *mut libc::c_uint,
    mut enc: libc::c_int,
    mut block: block128_f,
) {
    if !in_0.is_null() && !out.is_null() && !key.is_null() && !ivec.is_null()
        && !num.is_null()
    {} else {
        __assert_fail(
            b"in && out && key && ivec && num\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/cfb.c\0"
                as *const u8 as *const libc::c_char,
            63 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 124],
                &[libc::c_char; 124],
            >(
                b"void CRYPTO_cfb128_encrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, unsigned int *, int, block128_f)\0",
            ))
                .as_ptr(),
        );
    }
    'c_7367: {
        if !in_0.is_null() && !out.is_null() && !key.is_null() && !ivec.is_null()
            && !num.is_null()
        {} else {
            __assert_fail(
                b"in && out && key && ivec && num\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/cfb.c\0"
                    as *const u8 as *const libc::c_char,
                63 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 124],
                    &[libc::c_char; 124],
                >(
                    b"void CRYPTO_cfb128_encrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, unsigned int *, int, block128_f)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut n: libc::c_uint = *num;
    if enc != 0 {
        while n != 0 && len != 0 {
            let fresh0 = in_0;
            in_0 = in_0.offset(1);
            let ref mut fresh1 = *ivec.offset(n as isize);
            *fresh1 = (*fresh1 as libc::c_int ^ *fresh0 as libc::c_int) as uint8_t;
            let fresh2 = out;
            out = out.offset(1);
            *fresh2 = *fresh1;
            len = len.wrapping_sub(1);
            len;
            n = n
                .wrapping_add(1 as libc::c_int as libc::c_uint)
                .wrapping_rem(16 as libc::c_int as libc::c_uint);
        }
        while len >= 16 as libc::c_int as size_t {
            (Some(block.expect("non-null function pointer")))
                .expect("non-null function pointer")(ivec as *const uint8_t, ivec, key);
            while n < 16 as libc::c_int as libc::c_uint {
                let mut tmp: crypto_word_t = CRYPTO_load_word_le(
                    ivec.offset(n as isize) as *const libc::c_void,
                ) ^ CRYPTO_load_word_le(in_0.offset(n as isize) as *const libc::c_void);
                CRYPTO_store_word_le(ivec.offset(n as isize) as *mut libc::c_void, tmp);
                CRYPTO_store_word_le(out.offset(n as isize) as *mut libc::c_void, tmp);
                n = (n as libc::c_ulong)
                    .wrapping_add(
                        ::core::mem::size_of::<crypto_word_t>() as libc::c_ulong,
                    ) as libc::c_uint as libc::c_uint;
            }
            len = len.wrapping_sub(16 as libc::c_int as size_t);
            out = out.offset(16 as libc::c_int as isize);
            in_0 = in_0.offset(16 as libc::c_int as isize);
            n = 0 as libc::c_int as libc::c_uint;
        }
        if len != 0 {
            (Some(block.expect("non-null function pointer")))
                .expect("non-null function pointer")(ivec as *const uint8_t, ivec, key);
            loop {
                let fresh3 = len;
                len = len.wrapping_sub(1);
                if !(fresh3 != 0) {
                    break;
                }
                let ref mut fresh4 = *ivec.offset(n as isize);
                *fresh4 = (*fresh4 as libc::c_int
                    ^ *in_0.offset(n as isize) as libc::c_int) as uint8_t;
                *out.offset(n as isize) = *fresh4;
                n = n.wrapping_add(1);
                n;
            }
        }
        *num = n;
        return;
    } else {
        while n != 0 && len != 0 {
            let mut c: uint8_t = 0;
            let fresh5 = in_0;
            in_0 = in_0.offset(1);
            c = *fresh5;
            let fresh6 = out;
            out = out.offset(1);
            *fresh6 = (*ivec.offset(n as isize) as libc::c_int ^ c as libc::c_int)
                as uint8_t;
            *ivec.offset(n as isize) = c;
            len = len.wrapping_sub(1);
            len;
            n = n
                .wrapping_add(1 as libc::c_int as libc::c_uint)
                .wrapping_rem(16 as libc::c_int as libc::c_uint);
        }
        while len >= 16 as libc::c_int as size_t {
            (Some(block.expect("non-null function pointer")))
                .expect("non-null function pointer")(ivec as *const uint8_t, ivec, key);
            while n < 16 as libc::c_int as libc::c_uint {
                let mut t: crypto_word_t = CRYPTO_load_word_le(
                    in_0.offset(n as isize) as *const libc::c_void,
                );
                CRYPTO_store_word_le(
                    out.offset(n as isize) as *mut libc::c_void,
                    CRYPTO_load_word_le(ivec.offset(n as isize) as *const libc::c_void)
                        ^ t,
                );
                CRYPTO_store_word_le(ivec.offset(n as isize) as *mut libc::c_void, t);
                n = (n as libc::c_ulong)
                    .wrapping_add(
                        ::core::mem::size_of::<crypto_word_t>() as libc::c_ulong,
                    ) as libc::c_uint as libc::c_uint;
            }
            len = len.wrapping_sub(16 as libc::c_int as size_t);
            out = out.offset(16 as libc::c_int as isize);
            in_0 = in_0.offset(16 as libc::c_int as isize);
            n = 0 as libc::c_int as libc::c_uint;
        }
        if len != 0 {
            (Some(block.expect("non-null function pointer")))
                .expect("non-null function pointer")(ivec as *const uint8_t, ivec, key);
            loop {
                let fresh7 = len;
                len = len.wrapping_sub(1);
                if !(fresh7 != 0) {
                    break;
                }
                let mut c_0: uint8_t = 0;
                c_0 = *in_0.offset(n as isize);
                *out
                    .offset(
                        n as isize,
                    ) = (*ivec.offset(n as isize) as libc::c_int ^ c_0 as libc::c_int)
                    as uint8_t;
                *ivec.offset(n as isize) = c_0;
                n = n.wrapping_add(1);
                n;
            }
        }
        *num = n;
        return;
    };
}
unsafe extern "C" fn cfbr_encrypt_block(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut nbits: libc::c_uint,
    mut key: *const AES_KEY,
    mut ivec: *mut uint8_t,
    mut enc: libc::c_int,
    mut block: block128_f,
) {
    let mut n: libc::c_int = 0;
    let mut rem: libc::c_int = 0;
    let mut num: libc::c_int = 0;
    let mut ovec: [uint8_t; 33] = [0; 33];
    if nbits <= 0 as libc::c_int as libc::c_uint
        || nbits > 128 as libc::c_int as libc::c_uint
    {
        return;
    }
    OPENSSL_memcpy(
        ovec.as_mut_ptr() as *mut libc::c_void,
        ivec as *const libc::c_void,
        16 as libc::c_int as size_t,
    );
    (Some(block.expect("non-null function pointer")))
        .expect("non-null function pointer")(ivec as *const uint8_t, ivec, key);
    num = nbits
        .wrapping_add(7 as libc::c_int as libc::c_uint)
        .wrapping_div(8 as libc::c_int as libc::c_uint) as libc::c_int;
    if enc != 0 {
        n = 0 as libc::c_int;
        while n < num {
            ovec[(16 as libc::c_int + n)
                as usize] = (*in_0.offset(n as isize) as libc::c_int
                ^ *ivec.offset(n as isize) as libc::c_int) as uint8_t;
            *out.offset(n as isize) = ovec[(16 as libc::c_int + n) as usize];
            n += 1;
            n;
        }
    } else {
        n = 0 as libc::c_int;
        while n < num {
            ovec[(16 as libc::c_int + n) as usize] = *in_0.offset(n as isize);
            *out
                .offset(
                    n as isize,
                ) = (ovec[(16 as libc::c_int + n) as usize] as libc::c_int
                ^ *ivec.offset(n as isize) as libc::c_int) as uint8_t;
            n += 1;
            n;
        }
    }
    rem = nbits.wrapping_rem(8 as libc::c_int as libc::c_uint) as libc::c_int;
    num = nbits.wrapping_div(8 as libc::c_int as libc::c_uint) as libc::c_int;
    if rem == 0 as libc::c_int {
        OPENSSL_memcpy(
            ivec as *mut libc::c_void,
            ovec.as_mut_ptr().offset(num as isize) as *const libc::c_void,
            16 as libc::c_int as size_t,
        );
    } else {
        n = 0 as libc::c_int;
        while n < 16 as libc::c_int {
            *ivec
                .offset(
                    n as isize,
                ) = ((ovec[(n + num) as usize] as libc::c_int) << rem
                | ovec[(n + num + 1 as libc::c_int) as usize] as libc::c_int
                    >> 8 as libc::c_int - rem) as uint8_t;
            n += 1;
            n;
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_cfb128_1_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut bits: size_t,
    mut key: *const AES_KEY,
    mut ivec: *mut uint8_t,
    mut num: *mut libc::c_uint,
    mut enc: libc::c_int,
    mut block: block128_f,
) {
    let mut n: size_t = 0;
    let mut c: [uint8_t; 1] = [0; 1];
    let mut d: [uint8_t; 1] = [0; 1];
    if !in_0.is_null() && !out.is_null() && !key.is_null() && !ivec.is_null()
        && !num.is_null()
    {} else {
        __assert_fail(
            b"in && out && key && ivec && num\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/cfb.c\0"
                as *const u8 as *const libc::c_char,
            180 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 126],
                &[libc::c_char; 126],
            >(
                b"void CRYPTO_cfb128_1_encrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, unsigned int *, int, block128_f)\0",
            ))
                .as_ptr(),
        );
    }
    'c_8025: {
        if !in_0.is_null() && !out.is_null() && !key.is_null() && !ivec.is_null()
            && !num.is_null()
        {} else {
            __assert_fail(
                b"in && out && key && ivec && num\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/cfb.c\0"
                    as *const u8 as *const libc::c_char,
                180 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 126],
                    &[libc::c_char; 126],
                >(
                    b"void CRYPTO_cfb128_1_encrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, unsigned int *, int, block128_f)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if *num == 0 as libc::c_int as libc::c_uint {} else {
        __assert_fail(
            b"*num == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/cfb.c\0"
                as *const u8 as *const libc::c_char,
            181 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 126],
                &[libc::c_char; 126],
            >(
                b"void CRYPTO_cfb128_1_encrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, unsigned int *, int, block128_f)\0",
            ))
                .as_ptr(),
        );
    }
    'c_7982: {
        if *num == 0 as libc::c_int as libc::c_uint {} else {
            __assert_fail(
                b"*num == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/cfb.c\0"
                    as *const u8 as *const libc::c_char,
                181 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 126],
                    &[libc::c_char; 126],
                >(
                    b"void CRYPTO_cfb128_1_encrypt(const uint8_t *, uint8_t *, size_t, const AES_KEY *, uint8_t *, unsigned int *, int, block128_f)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    n = 0 as libc::c_int as size_t;
    while n < bits {
        c[0 as libc::c_int
            as usize] = (if *in_0.offset((n / 8 as libc::c_int as size_t) as isize)
            as libc::c_int
            & (1 as libc::c_int)
                << (7 as libc::c_int as size_t)
                    .wrapping_sub(n % 8 as libc::c_int as size_t) != 0
        {
            0x80 as libc::c_int
        } else {
            0 as libc::c_int
        }) as uint8_t;
        cfbr_encrypt_block(
            c.as_mut_ptr(),
            d.as_mut_ptr(),
            1 as libc::c_int as libc::c_uint,
            key,
            ivec,
            enc,
            block,
        );
        *out
            .offset(
                (n / 8 as libc::c_int as size_t) as isize,
            ) = (*out.offset((n / 8 as libc::c_int as size_t) as isize) as libc::c_int
            & !((1 as libc::c_int)
                << (7 as libc::c_int as size_t)
                    .wrapping_sub(n % 8 as libc::c_int as size_t) as libc::c_uint)
            | (d[0 as libc::c_int as usize] as libc::c_int & 0x80 as libc::c_int)
                >> (n % 8 as libc::c_int as size_t) as libc::c_uint) as uint8_t;
        n = n.wrapping_add(1);
        n;
    }
}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_cfb128_8_encrypt(
    mut in_0: *const libc::c_uchar,
    mut out: *mut libc::c_uchar,
    mut length: size_t,
    mut key: *const AES_KEY,
    mut ivec: *mut libc::c_uchar,
    mut num: *mut libc::c_uint,
    mut enc: libc::c_int,
    mut block: block128_f,
) {
    let mut n: size_t = 0;
    if !in_0.is_null() && !out.is_null() && !key.is_null() && !ivec.is_null()
        && !num.is_null()
    {} else {
        __assert_fail(
            b"in && out && key && ivec && num\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/cfb.c\0"
                as *const u8 as *const libc::c_char,
            197 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 144],
                &[libc::c_char; 144],
            >(
                b"void CRYPTO_cfb128_8_encrypt(const unsigned char *, unsigned char *, size_t, const AES_KEY *, unsigned char *, unsigned int *, int, block128_f)\0",
            ))
                .as_ptr(),
        );
    }
    'c_7785: {
        if !in_0.is_null() && !out.is_null() && !key.is_null() && !ivec.is_null()
            && !num.is_null()
        {} else {
            __assert_fail(
                b"in && out && key && ivec && num\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/cfb.c\0"
                    as *const u8 as *const libc::c_char,
                197 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 144],
                    &[libc::c_char; 144],
                >(
                    b"void CRYPTO_cfb128_8_encrypt(const unsigned char *, unsigned char *, size_t, const AES_KEY *, unsigned char *, unsigned int *, int, block128_f)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if *num == 0 as libc::c_int as libc::c_uint {} else {
        __assert_fail(
            b"*num == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/cfb.c\0"
                as *const u8 as *const libc::c_char,
            198 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 144],
                &[libc::c_char; 144],
            >(
                b"void CRYPTO_cfb128_8_encrypt(const unsigned char *, unsigned char *, size_t, const AES_KEY *, unsigned char *, unsigned int *, int, block128_f)\0",
            ))
                .as_ptr(),
        );
    }
    'c_7741: {
        if *num == 0 as libc::c_int as libc::c_uint {} else {
            __assert_fail(
                b"*num == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/modes/cfb.c\0"
                    as *const u8 as *const libc::c_char,
                198 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 144],
                    &[libc::c_char; 144],
                >(
                    b"void CRYPTO_cfb128_8_encrypt(const unsigned char *, unsigned char *, size_t, const AES_KEY *, unsigned char *, unsigned int *, int, block128_f)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    n = 0 as libc::c_int as size_t;
    while n < length {
        cfbr_encrypt_block(
            &*in_0.offset(n as isize),
            &mut *out.offset(n as isize),
            8 as libc::c_int as libc::c_uint,
            key,
            ivec,
            enc,
            block,
        );
        n = n.wrapping_add(1);
        n;
    }
}
