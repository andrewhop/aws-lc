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
unsafe extern "C" {
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
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_cipher_ctx_st {
    pub cipher: *const EVP_CIPHER,
    pub app_data: *mut libc::c_void,
    pub cipher_data: *mut libc::c_void,
    pub key_len: libc::c_uint,
    pub encrypt: libc::c_int,
    pub flags: uint32_t,
    pub oiv: [uint8_t; 16],
    pub iv: [uint8_t; 16],
    pub buf: [uint8_t; 32],
    pub buf_len: libc::c_int,
    pub num: libc::c_uint,
    pub final_used: libc::c_int,
    pub final_0: [uint8_t; 32],
    pub poisoned: libc::c_int,
}
pub type EVP_CIPHER = evp_cipher_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_cipher_st {
    pub nid: libc::c_int,
    pub block_size: libc::c_uint,
    pub key_len: libc::c_uint,
    pub iv_len: libc::c_uint,
    pub ctx_size: libc::c_uint,
    pub flags: uint32_t,
    pub init: Option::<
        unsafe extern "C" fn(
            *mut EVP_CIPHER_CTX,
            *const uint8_t,
            *const uint8_t,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub cipher: Option::<
        unsafe extern "C" fn(
            *mut EVP_CIPHER_CTX,
            *mut uint8_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub cleanup: Option::<unsafe extern "C" fn(*mut EVP_CIPHER_CTX) -> ()>,
    pub ctrl: Option::<
        unsafe extern "C" fn(
            *mut EVP_CIPHER_CTX,
            libc::c_int,
            libc::c_int,
            *mut libc::c_void,
        ) -> libc::c_int,
    >,
}
pub type EVP_CIPHER_CTX = evp_cipher_ctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bf_key_st {
    pub P: [uint32_t; 18],
    pub S: [uint32_t; 1024],
}
pub type BF_KEY = bf_key_st;
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BF_encrypt(mut data: *mut uint32_t, mut key: *const BF_KEY) {
    let mut l: uint32_t = 0;
    let mut r: uint32_t = 0;
    let mut p: *const uint32_t = 0 as *const uint32_t;
    let mut s: *const uint32_t = 0 as *const uint32_t;
    p = ((*key).P).as_ptr();
    s = &*((*key).S).as_ptr().offset(0 as libc::c_int as isize) as *const uint32_t;
    l = *data.offset(0 as libc::c_int as isize);
    r = *data.offset(1 as libc::c_int as isize);
    l ^= *p.offset(0 as libc::c_int as isize);
    r ^= *p.offset(1 as libc::c_int as isize);
    r = (r as libc::c_long
        ^ ((*s
            .offset(
                ((l >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((l >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((l >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (l as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    l ^= *p.offset(2 as libc::c_int as isize);
    l = (l as libc::c_long
        ^ ((*s
            .offset(
                ((r >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((r >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((r >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (r as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    r ^= *p.offset(3 as libc::c_int as isize);
    r = (r as libc::c_long
        ^ ((*s
            .offset(
                ((l >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((l >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((l >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (l as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    l ^= *p.offset(4 as libc::c_int as isize);
    l = (l as libc::c_long
        ^ ((*s
            .offset(
                ((r >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((r >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((r >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (r as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    r ^= *p.offset(5 as libc::c_int as isize);
    r = (r as libc::c_long
        ^ ((*s
            .offset(
                ((l >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((l >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((l >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (l as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    l ^= *p.offset(6 as libc::c_int as isize);
    l = (l as libc::c_long
        ^ ((*s
            .offset(
                ((r >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((r >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((r >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (r as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    r ^= *p.offset(7 as libc::c_int as isize);
    r = (r as libc::c_long
        ^ ((*s
            .offset(
                ((l >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((l >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((l >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (l as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    l ^= *p.offset(8 as libc::c_int as isize);
    l = (l as libc::c_long
        ^ ((*s
            .offset(
                ((r >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((r >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((r >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (r as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    r ^= *p.offset(9 as libc::c_int as isize);
    r = (r as libc::c_long
        ^ ((*s
            .offset(
                ((l >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((l >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((l >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (l as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    l ^= *p.offset(10 as libc::c_int as isize);
    l = (l as libc::c_long
        ^ ((*s
            .offset(
                ((r >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((r >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((r >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (r as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    r ^= *p.offset(11 as libc::c_int as isize);
    r = (r as libc::c_long
        ^ ((*s
            .offset(
                ((l >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((l >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((l >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (l as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    l ^= *p.offset(12 as libc::c_int as isize);
    l = (l as libc::c_long
        ^ ((*s
            .offset(
                ((r >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((r >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((r >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (r as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    r ^= *p.offset(13 as libc::c_int as isize);
    r = (r as libc::c_long
        ^ ((*s
            .offset(
                ((l >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((l >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((l >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (l as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    l ^= *p.offset(14 as libc::c_int as isize);
    l = (l as libc::c_long
        ^ ((*s
            .offset(
                ((r >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((r >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((r >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (r as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    r ^= *p.offset(15 as libc::c_int as isize);
    r = (r as libc::c_long
        ^ ((*s
            .offset(
                ((l >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((l >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((l >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (l as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    l ^= *p.offset(16 as libc::c_int as isize);
    l = (l as libc::c_long
        ^ ((*s
            .offset(
                ((r >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((r >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((r >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (r as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    r ^= *p.offset((16 as libc::c_int + 1 as libc::c_int) as isize);
    *data
        .offset(
            1 as libc::c_int as isize,
        ) = (l as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    *data
        .offset(
            0 as libc::c_int as isize,
        ) = (r as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BF_decrypt(mut data: *mut uint32_t, mut key: *const BF_KEY) {
    let mut l: uint32_t = 0;
    let mut r: uint32_t = 0;
    let mut p: *const uint32_t = 0 as *const uint32_t;
    let mut s: *const uint32_t = 0 as *const uint32_t;
    p = ((*key).P).as_ptr();
    s = &*((*key).S).as_ptr().offset(0 as libc::c_int as isize) as *const uint32_t;
    l = *data.offset(0 as libc::c_int as isize);
    r = *data.offset(1 as libc::c_int as isize);
    l ^= *p.offset((16 as libc::c_int + 1 as libc::c_int) as isize);
    r ^= *p.offset(16 as libc::c_int as isize);
    r = (r as libc::c_long
        ^ ((*s
            .offset(
                ((l >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((l >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((l >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (l as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    l ^= *p.offset(15 as libc::c_int as isize);
    l = (l as libc::c_long
        ^ ((*s
            .offset(
                ((r >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((r >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((r >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (r as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    r ^= *p.offset(14 as libc::c_int as isize);
    r = (r as libc::c_long
        ^ ((*s
            .offset(
                ((l >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((l >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((l >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (l as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    l ^= *p.offset(13 as libc::c_int as isize);
    l = (l as libc::c_long
        ^ ((*s
            .offset(
                ((r >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((r >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((r >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (r as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    r ^= *p.offset(12 as libc::c_int as isize);
    r = (r as libc::c_long
        ^ ((*s
            .offset(
                ((l >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((l >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((l >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (l as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    l ^= *p.offset(11 as libc::c_int as isize);
    l = (l as libc::c_long
        ^ ((*s
            .offset(
                ((r >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((r >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((r >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (r as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    r ^= *p.offset(10 as libc::c_int as isize);
    r = (r as libc::c_long
        ^ ((*s
            .offset(
                ((l >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((l >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((l >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (l as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    l ^= *p.offset(9 as libc::c_int as isize);
    l = (l as libc::c_long
        ^ ((*s
            .offset(
                ((r >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((r >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((r >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (r as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    r ^= *p.offset(8 as libc::c_int as isize);
    r = (r as libc::c_long
        ^ ((*s
            .offset(
                ((l >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((l >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((l >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (l as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    l ^= *p.offset(7 as libc::c_int as isize);
    l = (l as libc::c_long
        ^ ((*s
            .offset(
                ((r >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((r >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((r >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (r as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    r ^= *p.offset(6 as libc::c_int as isize);
    r = (r as libc::c_long
        ^ ((*s
            .offset(
                ((l >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((l >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((l >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (l as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    l ^= *p.offset(5 as libc::c_int as isize);
    l = (l as libc::c_long
        ^ ((*s
            .offset(
                ((r >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((r >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((r >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (r as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    r ^= *p.offset(4 as libc::c_int as isize);
    r = (r as libc::c_long
        ^ ((*s
            .offset(
                ((l >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((l >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((l >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (l as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    l ^= *p.offset(3 as libc::c_int as isize);
    l = (l as libc::c_long
        ^ ((*s
            .offset(
                ((r >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((r >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((r >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (r as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    r ^= *p.offset(2 as libc::c_int as isize);
    r = (r as libc::c_long
        ^ ((*s
            .offset(
                ((l >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((l >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((l >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (l as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    l ^= *p.offset(1 as libc::c_int as isize);
    l = (l as libc::c_long
        ^ ((*s
            .offset(
                ((r >> 24 as libc::c_int) as libc::c_int & 0xff as libc::c_int) as isize,
            ))
            .wrapping_add(
                *s
                    .offset(
                        (0x100 as libc::c_int
                            + ((r >> 16 as libc::c_int) as libc::c_int
                                & 0xff as libc::c_int)) as isize,
                    ),
            )
            ^ *s
                .offset(
                    (0x200 as libc::c_int
                        + ((r >> 8 as libc::c_int) as libc::c_int & 0xff as libc::c_int))
                        as isize,
                ))
            .wrapping_add(
                *s
                    .offset(
                        (0x300 as libc::c_int + (r as libc::c_int & 0xff as libc::c_int))
                            as isize,
                    ),
            ) as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    r ^= *p.offset(0 as libc::c_int as isize);
    *data
        .offset(
            1 as libc::c_int as isize,
        ) = (l as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    *data
        .offset(
            0 as libc::c_int as isize,
        ) = (r as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BF_ecb_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut key: *const BF_KEY,
    mut encrypt: libc::c_int,
) {
    let mut d: [uint32_t; 2] = [0; 2];
    let fresh0 = in_0;
    in_0 = in_0.offset(1);
    d[0 as libc::c_int as usize] = (*fresh0 as uint32_t) << 24 as libc::c_long;
    let fresh1 = in_0;
    in_0 = in_0.offset(1);
    d[0 as libc::c_int as usize] |= (*fresh1 as uint32_t) << 16 as libc::c_long;
    let fresh2 = in_0;
    in_0 = in_0.offset(1);
    d[0 as libc::c_int as usize] |= (*fresh2 as uint32_t) << 8 as libc::c_long;
    let fresh3 = in_0;
    in_0 = in_0.offset(1);
    d[0 as libc::c_int as usize] |= *fresh3 as uint32_t;
    let fresh4 = in_0;
    in_0 = in_0.offset(1);
    d[1 as libc::c_int as usize] = (*fresh4 as uint32_t) << 24 as libc::c_long;
    let fresh5 = in_0;
    in_0 = in_0.offset(1);
    d[1 as libc::c_int as usize] |= (*fresh5 as uint32_t) << 16 as libc::c_long;
    let fresh6 = in_0;
    in_0 = in_0.offset(1);
    d[1 as libc::c_int as usize] |= (*fresh6 as uint32_t) << 8 as libc::c_long;
    let fresh7 = in_0;
    in_0 = in_0.offset(1);
    d[1 as libc::c_int as usize] |= *fresh7 as uint32_t;
    if encrypt != 0 {
        BF_encrypt(d.as_mut_ptr(), key);
    } else {
        BF_decrypt(d.as_mut_ptr(), key);
    }
    let fresh8 = out;
    out = out.offset(1);
    *fresh8 = (d[0 as libc::c_int as usize] >> 24 as libc::c_long
        & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
    let fresh9 = out;
    out = out.offset(1);
    *fresh9 = (d[0 as libc::c_int as usize] >> 16 as libc::c_long
        & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
    let fresh10 = out;
    out = out.offset(1);
    *fresh10 = (d[0 as libc::c_int as usize] >> 8 as libc::c_long
        & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
    let fresh11 = out;
    out = out.offset(1);
    *fresh11 = (d[0 as libc::c_int as usize] & 0xff as libc::c_int as uint32_t)
        as libc::c_uchar;
    let fresh12 = out;
    out = out.offset(1);
    *fresh12 = (d[1 as libc::c_int as usize] >> 24 as libc::c_long
        & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
    let fresh13 = out;
    out = out.offset(1);
    *fresh13 = (d[1 as libc::c_int as usize] >> 16 as libc::c_long
        & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
    let fresh14 = out;
    out = out.offset(1);
    *fresh14 = (d[1 as libc::c_int as usize] >> 8 as libc::c_long
        & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
    let fresh15 = out;
    out = out.offset(1);
    *fresh15 = (d[1 as libc::c_int as usize] & 0xff as libc::c_int as uint32_t)
        as libc::c_uchar;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BF_cbc_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut length: size_t,
    mut schedule: *const BF_KEY,
    mut ivec: *mut uint8_t,
    mut encrypt: libc::c_int,
) {
    let mut tin0: uint32_t = 0;
    let mut tin1: uint32_t = 0;
    let mut tout0: uint32_t = 0;
    let mut tout1: uint32_t = 0;
    let mut xor0: uint32_t = 0;
    let mut xor1: uint32_t = 0;
    let mut l: size_t = length;
    let mut tin: [uint32_t; 2] = [0; 2];
    if encrypt != 0 {
        let fresh16 = ivec;
        ivec = ivec.offset(1);
        tout0 = (*fresh16 as uint32_t) << 24 as libc::c_long;
        let fresh17 = ivec;
        ivec = ivec.offset(1);
        tout0 |= (*fresh17 as uint32_t) << 16 as libc::c_long;
        let fresh18 = ivec;
        ivec = ivec.offset(1);
        tout0 |= (*fresh18 as uint32_t) << 8 as libc::c_long;
        let fresh19 = ivec;
        ivec = ivec.offset(1);
        tout0 |= *fresh19 as uint32_t;
        let fresh20 = ivec;
        ivec = ivec.offset(1);
        tout1 = (*fresh20 as uint32_t) << 24 as libc::c_long;
        let fresh21 = ivec;
        ivec = ivec.offset(1);
        tout1 |= (*fresh21 as uint32_t) << 16 as libc::c_long;
        let fresh22 = ivec;
        ivec = ivec.offset(1);
        tout1 |= (*fresh22 as uint32_t) << 8 as libc::c_long;
        let fresh23 = ivec;
        ivec = ivec.offset(1);
        tout1 |= *fresh23 as uint32_t;
        ivec = ivec.offset(-(8 as libc::c_int as isize));
        while l >= 8 as libc::c_int as size_t {
            let fresh24 = in_0;
            in_0 = in_0.offset(1);
            tin0 = (*fresh24 as uint32_t) << 24 as libc::c_long;
            let fresh25 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh25 as uint32_t) << 16 as libc::c_long;
            let fresh26 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh26 as uint32_t) << 8 as libc::c_long;
            let fresh27 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= *fresh27 as uint32_t;
            let fresh28 = in_0;
            in_0 = in_0.offset(1);
            tin1 = (*fresh28 as uint32_t) << 24 as libc::c_long;
            let fresh29 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh29 as uint32_t) << 16 as libc::c_long;
            let fresh30 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh30 as uint32_t) << 8 as libc::c_long;
            let fresh31 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= *fresh31 as uint32_t;
            tin0 ^= tout0;
            tin1 ^= tout1;
            tin[0 as libc::c_int as usize] = tin0;
            tin[1 as libc::c_int as usize] = tin1;
            BF_encrypt(tin.as_mut_ptr(), schedule);
            tout0 = tin[0 as libc::c_int as usize];
            tout1 = tin[1 as libc::c_int as usize];
            let fresh32 = out;
            out = out.offset(1);
            *fresh32 = (tout0 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh33 = out;
            out = out.offset(1);
            *fresh33 = (tout0 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh34 = out;
            out = out.offset(1);
            *fresh34 = (tout0 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh35 = out;
            out = out.offset(1);
            *fresh35 = (tout0 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
            let fresh36 = out;
            out = out.offset(1);
            *fresh36 = (tout1 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh37 = out;
            out = out.offset(1);
            *fresh37 = (tout1 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh38 = out;
            out = out.offset(1);
            *fresh38 = (tout1 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh39 = out;
            out = out.offset(1);
            *fresh39 = (tout1 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
            l = l.wrapping_sub(8 as libc::c_int as size_t);
        }
        if l != 0 as libc::c_int as size_t {
            in_0 = in_0.offset(l as isize);
            tin1 = 0 as libc::c_int as uint32_t;
            tin0 = tin1;
            let mut current_block_33: u64;
            match l {
                8 => {
                    in_0 = in_0.offset(-1);
                    tin1 = *in_0 as uint32_t;
                    current_block_33 = 14288244254501244872;
                }
                7 => {
                    current_block_33 = 14288244254501244872;
                }
                6 => {
                    current_block_33 = 5822401977883119538;
                }
                5 => {
                    current_block_33 = 8866822359449587361;
                }
                4 => {
                    current_block_33 = 10487254568932816404;
                }
                3 => {
                    current_block_33 = 2335874976616023681;
                }
                2 => {
                    current_block_33 = 13549375070572378437;
                }
                1 => {
                    current_block_33 = 11826707980157276219;
                }
                _ => {
                    current_block_33 = 1608152415753874203;
                }
            }
            match current_block_33 {
                14288244254501244872 => {
                    in_0 = in_0.offset(-1);
                    tin1 |= (*in_0 as uint32_t) << 8 as libc::c_int;
                    current_block_33 = 5822401977883119538;
                }
                _ => {}
            }
            match current_block_33 {
                5822401977883119538 => {
                    in_0 = in_0.offset(-1);
                    tin1 |= (*in_0 as uint32_t) << 16 as libc::c_int;
                    current_block_33 = 8866822359449587361;
                }
                _ => {}
            }
            match current_block_33 {
                8866822359449587361 => {
                    in_0 = in_0.offset(-1);
                    tin1 |= (*in_0 as uint32_t) << 24 as libc::c_int;
                    current_block_33 = 10487254568932816404;
                }
                _ => {}
            }
            match current_block_33 {
                10487254568932816404 => {
                    in_0 = in_0.offset(-1);
                    tin0 = *in_0 as uint32_t;
                    current_block_33 = 2335874976616023681;
                }
                _ => {}
            }
            match current_block_33 {
                2335874976616023681 => {
                    in_0 = in_0.offset(-1);
                    tin0 |= (*in_0 as uint32_t) << 8 as libc::c_int;
                    current_block_33 = 13549375070572378437;
                }
                _ => {}
            }
            match current_block_33 {
                13549375070572378437 => {
                    in_0 = in_0.offset(-1);
                    tin0 |= (*in_0 as uint32_t) << 16 as libc::c_int;
                    current_block_33 = 11826707980157276219;
                }
                _ => {}
            }
            match current_block_33 {
                11826707980157276219 => {
                    in_0 = in_0.offset(-1);
                    tin0 |= (*in_0 as uint32_t) << 24 as libc::c_int;
                }
                _ => {}
            }
            tin0 ^= tout0;
            tin1 ^= tout1;
            tin[0 as libc::c_int as usize] = tin0;
            tin[1 as libc::c_int as usize] = tin1;
            BF_encrypt(tin.as_mut_ptr(), schedule);
            tout0 = tin[0 as libc::c_int as usize];
            tout1 = tin[1 as libc::c_int as usize];
            let fresh40 = out;
            out = out.offset(1);
            *fresh40 = (tout0 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh41 = out;
            out = out.offset(1);
            *fresh41 = (tout0 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh42 = out;
            out = out.offset(1);
            *fresh42 = (tout0 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh43 = out;
            out = out.offset(1);
            *fresh43 = (tout0 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
            let fresh44 = out;
            out = out.offset(1);
            *fresh44 = (tout1 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh45 = out;
            out = out.offset(1);
            *fresh45 = (tout1 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh46 = out;
            out = out.offset(1);
            *fresh46 = (tout1 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh47 = out;
            out = out.offset(1);
            *fresh47 = (tout1 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
        }
        let fresh48 = ivec;
        ivec = ivec.offset(1);
        *fresh48 = (tout0 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh49 = ivec;
        ivec = ivec.offset(1);
        *fresh49 = (tout0 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh50 = ivec;
        ivec = ivec.offset(1);
        *fresh50 = (tout0 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh51 = ivec;
        ivec = ivec.offset(1);
        *fresh51 = (tout0 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
        let fresh52 = ivec;
        ivec = ivec.offset(1);
        *fresh52 = (tout1 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh53 = ivec;
        ivec = ivec.offset(1);
        *fresh53 = (tout1 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh54 = ivec;
        ivec = ivec.offset(1);
        *fresh54 = (tout1 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh55 = ivec;
        ivec = ivec.offset(1);
        *fresh55 = (tout1 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
    } else {
        let fresh56 = ivec;
        ivec = ivec.offset(1);
        xor0 = (*fresh56 as uint32_t) << 24 as libc::c_long;
        let fresh57 = ivec;
        ivec = ivec.offset(1);
        xor0 |= (*fresh57 as uint32_t) << 16 as libc::c_long;
        let fresh58 = ivec;
        ivec = ivec.offset(1);
        xor0 |= (*fresh58 as uint32_t) << 8 as libc::c_long;
        let fresh59 = ivec;
        ivec = ivec.offset(1);
        xor0 |= *fresh59 as uint32_t;
        let fresh60 = ivec;
        ivec = ivec.offset(1);
        xor1 = (*fresh60 as uint32_t) << 24 as libc::c_long;
        let fresh61 = ivec;
        ivec = ivec.offset(1);
        xor1 |= (*fresh61 as uint32_t) << 16 as libc::c_long;
        let fresh62 = ivec;
        ivec = ivec.offset(1);
        xor1 |= (*fresh62 as uint32_t) << 8 as libc::c_long;
        let fresh63 = ivec;
        ivec = ivec.offset(1);
        xor1 |= *fresh63 as uint32_t;
        ivec = ivec.offset(-(8 as libc::c_int as isize));
        while l >= 8 as libc::c_int as size_t {
            let fresh64 = in_0;
            in_0 = in_0.offset(1);
            tin0 = (*fresh64 as uint32_t) << 24 as libc::c_long;
            let fresh65 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh65 as uint32_t) << 16 as libc::c_long;
            let fresh66 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh66 as uint32_t) << 8 as libc::c_long;
            let fresh67 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= *fresh67 as uint32_t;
            let fresh68 = in_0;
            in_0 = in_0.offset(1);
            tin1 = (*fresh68 as uint32_t) << 24 as libc::c_long;
            let fresh69 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh69 as uint32_t) << 16 as libc::c_long;
            let fresh70 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh70 as uint32_t) << 8 as libc::c_long;
            let fresh71 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= *fresh71 as uint32_t;
            tin[0 as libc::c_int as usize] = tin0;
            tin[1 as libc::c_int as usize] = tin1;
            BF_decrypt(tin.as_mut_ptr(), schedule);
            tout0 = tin[0 as libc::c_int as usize] ^ xor0;
            tout1 = tin[1 as libc::c_int as usize] ^ xor1;
            let fresh72 = out;
            out = out.offset(1);
            *fresh72 = (tout0 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh73 = out;
            out = out.offset(1);
            *fresh73 = (tout0 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh74 = out;
            out = out.offset(1);
            *fresh74 = (tout0 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh75 = out;
            out = out.offset(1);
            *fresh75 = (tout0 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
            let fresh76 = out;
            out = out.offset(1);
            *fresh76 = (tout1 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh77 = out;
            out = out.offset(1);
            *fresh77 = (tout1 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh78 = out;
            out = out.offset(1);
            *fresh78 = (tout1 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh79 = out;
            out = out.offset(1);
            *fresh79 = (tout1 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
            xor0 = tin0;
            xor1 = tin1;
            l = l.wrapping_sub(8 as libc::c_int as size_t);
        }
        if l != 0 as libc::c_int as size_t {
            let fresh80 = in_0;
            in_0 = in_0.offset(1);
            tin0 = (*fresh80 as uint32_t) << 24 as libc::c_long;
            let fresh81 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh81 as uint32_t) << 16 as libc::c_long;
            let fresh82 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh82 as uint32_t) << 8 as libc::c_long;
            let fresh83 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= *fresh83 as uint32_t;
            let fresh84 = in_0;
            in_0 = in_0.offset(1);
            tin1 = (*fresh84 as uint32_t) << 24 as libc::c_long;
            let fresh85 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh85 as uint32_t) << 16 as libc::c_long;
            let fresh86 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh86 as uint32_t) << 8 as libc::c_long;
            let fresh87 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= *fresh87 as uint32_t;
            tin[0 as libc::c_int as usize] = tin0;
            tin[1 as libc::c_int as usize] = tin1;
            BF_decrypt(tin.as_mut_ptr(), schedule);
            tout0 = tin[0 as libc::c_int as usize] ^ xor0;
            tout1 = tin[1 as libc::c_int as usize] ^ xor1;
            out = out.offset(l as isize);
            let mut current_block_90: u64;
            match l {
                8 => {
                    out = out.offset(-1);
                    *out = (tout1 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
                    current_block_90 = 376170632861612492;
                }
                7 => {
                    current_block_90 = 376170632861612492;
                }
                6 => {
                    current_block_90 = 4827924720363186879;
                }
                5 => {
                    current_block_90 = 7004810845821414308;
                }
                4 => {
                    current_block_90 = 8504720985255075214;
                }
                3 => {
                    current_block_90 = 11143943660196273353;
                }
                2 => {
                    current_block_90 = 3961239128618364832;
                }
                1 => {
                    current_block_90 = 8314094705052393391;
                }
                _ => {
                    current_block_90 = 4216521074440650966;
                }
            }
            match current_block_90 {
                376170632861612492 => {
                    out = out.offset(-1);
                    *out = (tout1 >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
                        as libc::c_uchar;
                    current_block_90 = 4827924720363186879;
                }
                _ => {}
            }
            match current_block_90 {
                4827924720363186879 => {
                    out = out.offset(-1);
                    *out = (tout1 >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
                        as libc::c_uchar;
                    current_block_90 = 7004810845821414308;
                }
                _ => {}
            }
            match current_block_90 {
                7004810845821414308 => {
                    out = out.offset(-1);
                    *out = (tout1 >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
                        as libc::c_uchar;
                    current_block_90 = 8504720985255075214;
                }
                _ => {}
            }
            match current_block_90 {
                8504720985255075214 => {
                    out = out.offset(-1);
                    *out = (tout0 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
                    current_block_90 = 11143943660196273353;
                }
                _ => {}
            }
            match current_block_90 {
                11143943660196273353 => {
                    out = out.offset(-1);
                    *out = (tout0 >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
                        as libc::c_uchar;
                    current_block_90 = 3961239128618364832;
                }
                _ => {}
            }
            match current_block_90 {
                3961239128618364832 => {
                    out = out.offset(-1);
                    *out = (tout0 >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
                        as libc::c_uchar;
                    current_block_90 = 8314094705052393391;
                }
                _ => {}
            }
            match current_block_90 {
                8314094705052393391 => {
                    out = out.offset(-1);
                    *out = (tout0 >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
                        as libc::c_uchar;
                }
                _ => {}
            }
            xor0 = tin0;
            xor1 = tin1;
        }
        let fresh88 = ivec;
        ivec = ivec.offset(1);
        *fresh88 = (xor0 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh89 = ivec;
        ivec = ivec.offset(1);
        *fresh89 = (xor0 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh90 = ivec;
        ivec = ivec.offset(1);
        *fresh90 = (xor0 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh91 = ivec;
        ivec = ivec.offset(1);
        *fresh91 = (xor0 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
        let fresh92 = ivec;
        ivec = ivec.offset(1);
        *fresh92 = (xor1 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh93 = ivec;
        ivec = ivec.offset(1);
        *fresh93 = (xor1 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh94 = ivec;
        ivec = ivec.offset(1);
        *fresh94 = (xor1 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh95 = ivec;
        ivec = ivec.offset(1);
        *fresh95 = (xor1 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
    }
    OPENSSL_cleanse(
        &mut tin0 as *mut uint32_t as *mut libc::c_void,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut tin1 as *mut uint32_t as *mut libc::c_void,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut tout0 as *mut uint32_t as *mut libc::c_void,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut tout1 as *mut uint32_t as *mut libc::c_void,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut xor0 as *mut uint32_t as *mut libc::c_void,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut xor1 as *mut uint32_t as *mut libc::c_void,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut tin as *mut [uint32_t; 2] as *mut libc::c_void,
        ::core::mem::size_of::<[uint32_t; 2]>() as libc::c_ulong,
    );
}
static mut bf_init: BF_KEY = {
    let mut init = bf_key_st {
        P: [
            0x243f6a88 as libc::c_long as uint32_t,
            0x85a308d3 as libc::c_long as uint32_t,
            0x13198a2e as libc::c_long as uint32_t,
            0x3707344 as libc::c_long as uint32_t,
            0xa4093822 as libc::c_long as uint32_t,
            0x299f31d0 as libc::c_long as uint32_t,
            0x82efa98 as libc::c_long as uint32_t,
            0xec4e6c89 as libc::c_long as uint32_t,
            0x452821e6 as libc::c_long as uint32_t,
            0x38d01377 as libc::c_long as uint32_t,
            0xbe5466cf as libc::c_long as uint32_t,
            0x34e90c6c as libc::c_long as uint32_t,
            0xc0ac29b7 as libc::c_long as uint32_t,
            0xc97c50dd as libc::c_long as uint32_t,
            0x3f84d5b5 as libc::c_long as uint32_t,
            0xb5470917 as libc::c_long as uint32_t,
            0x9216d5d9 as libc::c_long as uint32_t,
            0x8979fb1b as libc::c_uint,
        ],
        S: [
            0xd1310ba6 as libc::c_long as uint32_t,
            0x98dfb5ac as libc::c_long as uint32_t,
            0x2ffd72db as libc::c_long as uint32_t,
            0xd01adfb7 as libc::c_long as uint32_t,
            0xb8e1afed as libc::c_long as uint32_t,
            0x6a267e96 as libc::c_long as uint32_t,
            0xba7c9045 as libc::c_long as uint32_t,
            0xf12c7f99 as libc::c_long as uint32_t,
            0x24a19947 as libc::c_long as uint32_t,
            0xb3916cf7 as libc::c_long as uint32_t,
            0x801f2e2 as libc::c_long as uint32_t,
            0x858efc16 as libc::c_long as uint32_t,
            0x636920d8 as libc::c_long as uint32_t,
            0x71574e69 as libc::c_long as uint32_t,
            0xa458fea3 as libc::c_long as uint32_t,
            0xf4933d7e as libc::c_long as uint32_t,
            0xd95748f as libc::c_long as uint32_t,
            0x728eb658 as libc::c_long as uint32_t,
            0x718bcd58 as libc::c_long as uint32_t,
            0x82154aee as libc::c_long as uint32_t,
            0x7b54a41d as libc::c_long as uint32_t,
            0xc25a59b5 as libc::c_long as uint32_t,
            0x9c30d539 as libc::c_long as uint32_t,
            0x2af26013 as libc::c_long as uint32_t,
            0xc5d1b023 as libc::c_long as uint32_t,
            0x286085f0 as libc::c_long as uint32_t,
            0xca417918 as libc::c_long as uint32_t,
            0xb8db38ef as libc::c_long as uint32_t,
            0x8e79dcb0 as libc::c_long as uint32_t,
            0x603a180e as libc::c_long as uint32_t,
            0x6c9e0e8b as libc::c_long as uint32_t,
            0xb01e8a3e as libc::c_long as uint32_t,
            0xd71577c1 as libc::c_long as uint32_t,
            0xbd314b27 as libc::c_long as uint32_t,
            0x78af2fda as libc::c_long as uint32_t,
            0x55605c60 as libc::c_long as uint32_t,
            0xe65525f3 as libc::c_long as uint32_t,
            0xaa55ab94 as libc::c_long as uint32_t,
            0x57489862 as libc::c_long as uint32_t,
            0x63e81440 as libc::c_long as uint32_t,
            0x55ca396a as libc::c_long as uint32_t,
            0x2aab10b6 as libc::c_long as uint32_t,
            0xb4cc5c34 as libc::c_long as uint32_t,
            0x1141e8ce as libc::c_long as uint32_t,
            0xa15486af as libc::c_long as uint32_t,
            0x7c72e993 as libc::c_long as uint32_t,
            0xb3ee1411 as libc::c_long as uint32_t,
            0x636fbc2a as libc::c_long as uint32_t,
            0x2ba9c55d as libc::c_long as uint32_t,
            0x741831f6 as libc::c_long as uint32_t,
            0xce5c3e16 as libc::c_long as uint32_t,
            0x9b87931e as libc::c_long as uint32_t,
            0xafd6ba33 as libc::c_long as uint32_t,
            0x6c24cf5c as libc::c_long as uint32_t,
            0x7a325381 as libc::c_long as uint32_t,
            0x28958677 as libc::c_long as uint32_t,
            0x3b8f4898 as libc::c_long as uint32_t,
            0x6b4bb9af as libc::c_long as uint32_t,
            0xc4bfe81b as libc::c_long as uint32_t,
            0x66282193 as libc::c_long as uint32_t,
            0x61d809cc as libc::c_long as uint32_t,
            0xfb21a991 as libc::c_long as uint32_t,
            0x487cac60 as libc::c_long as uint32_t,
            0x5dec8032 as libc::c_long as uint32_t,
            0xef845d5d as libc::c_long as uint32_t,
            0xe98575b1 as libc::c_long as uint32_t,
            0xdc262302 as libc::c_long as uint32_t,
            0xeb651b88 as libc::c_long as uint32_t,
            0x23893e81 as libc::c_long as uint32_t,
            0xd396acc5 as libc::c_long as uint32_t,
            0xf6d6ff3 as libc::c_long as uint32_t,
            0x83f44239 as libc::c_long as uint32_t,
            0x2e0b4482 as libc::c_long as uint32_t,
            0xa4842004 as libc::c_long as uint32_t,
            0x69c8f04a as libc::c_long as uint32_t,
            0x9e1f9b5e as libc::c_long as uint32_t,
            0x21c66842 as libc::c_long as uint32_t,
            0xf6e96c9a as libc::c_long as uint32_t,
            0x670c9c61 as libc::c_long as uint32_t,
            0xabd388f0 as libc::c_long as uint32_t,
            0x6a51a0d2 as libc::c_long as uint32_t,
            0xd8542f68 as libc::c_long as uint32_t,
            0x960fa728 as libc::c_long as uint32_t,
            0xab5133a3 as libc::c_long as uint32_t,
            0x6eef0b6c as libc::c_long as uint32_t,
            0x137a3be4 as libc::c_long as uint32_t,
            0xba3bf050 as libc::c_long as uint32_t,
            0x7efb2a98 as libc::c_long as uint32_t,
            0xa1f1651d as libc::c_long as uint32_t,
            0x39af0176 as libc::c_long as uint32_t,
            0x66ca593e as libc::c_long as uint32_t,
            0x82430e88 as libc::c_long as uint32_t,
            0x8cee8619 as libc::c_long as uint32_t,
            0x456f9fb4 as libc::c_long as uint32_t,
            0x7d84a5c3 as libc::c_long as uint32_t,
            0x3b8b5ebe as libc::c_long as uint32_t,
            0xe06f75d8 as libc::c_long as uint32_t,
            0x85c12073 as libc::c_long as uint32_t,
            0x401a449f as libc::c_long as uint32_t,
            0x56c16aa6 as libc::c_long as uint32_t,
            0x4ed3aa62 as libc::c_long as uint32_t,
            0x363f7706 as libc::c_long as uint32_t,
            0x1bfedf72 as libc::c_long as uint32_t,
            0x429b023d as libc::c_long as uint32_t,
            0x37d0d724 as libc::c_long as uint32_t,
            0xd00a1248 as libc::c_long as uint32_t,
            0xdb0fead3 as libc::c_long as uint32_t,
            0x49f1c09b as libc::c_long as uint32_t,
            0x75372c9 as libc::c_long as uint32_t,
            0x80991b7b as libc::c_long as uint32_t,
            0x25d479d8 as libc::c_long as uint32_t,
            0xf6e8def7 as libc::c_long as uint32_t,
            0xe3fe501a as libc::c_long as uint32_t,
            0xb6794c3b as libc::c_long as uint32_t,
            0x976ce0bd as libc::c_long as uint32_t,
            0x4c006ba as libc::c_long as uint32_t,
            0xc1a94fb6 as libc::c_long as uint32_t,
            0x409f60c4 as libc::c_long as uint32_t,
            0x5e5c9ec2 as libc::c_long as uint32_t,
            0x196a2463 as libc::c_long as uint32_t,
            0x68fb6faf as libc::c_long as uint32_t,
            0x3e6c53b5 as libc::c_long as uint32_t,
            0x1339b2eb as libc::c_long as uint32_t,
            0x3b52ec6f as libc::c_long as uint32_t,
            0x6dfc511f as libc::c_long as uint32_t,
            0x9b30952c as libc::c_long as uint32_t,
            0xcc814544 as libc::c_long as uint32_t,
            0xaf5ebd09 as libc::c_long as uint32_t,
            0xbee3d004 as libc::c_long as uint32_t,
            0xde334afd as libc::c_long as uint32_t,
            0x660f2807 as libc::c_long as uint32_t,
            0x192e4bb3 as libc::c_long as uint32_t,
            0xc0cba857 as libc::c_long as uint32_t,
            0x45c8740f as libc::c_long as uint32_t,
            0xd20b5f39 as libc::c_long as uint32_t,
            0xb9d3fbdb as libc::c_long as uint32_t,
            0x5579c0bd as libc::c_long as uint32_t,
            0x1a60320a as libc::c_long as uint32_t,
            0xd6a100c6 as libc::c_long as uint32_t,
            0x402c7279 as libc::c_long as uint32_t,
            0x679f25fe as libc::c_long as uint32_t,
            0xfb1fa3cc as libc::c_long as uint32_t,
            0x8ea5e9f8 as libc::c_long as uint32_t,
            0xdb3222f8 as libc::c_long as uint32_t,
            0x3c7516df as libc::c_long as uint32_t,
            0xfd616b15 as libc::c_long as uint32_t,
            0x2f501ec8 as libc::c_long as uint32_t,
            0xad0552ab as libc::c_long as uint32_t,
            0x323db5fa as libc::c_long as uint32_t,
            0xfd238760 as libc::c_long as uint32_t,
            0x53317b48 as libc::c_long as uint32_t,
            0x3e00df82 as libc::c_long as uint32_t,
            0x9e5c57bb as libc::c_long as uint32_t,
            0xca6f8ca0 as libc::c_long as uint32_t,
            0x1a87562e as libc::c_long as uint32_t,
            0xdf1769db as libc::c_long as uint32_t,
            0xd542a8f6 as libc::c_long as uint32_t,
            0x287effc3 as libc::c_long as uint32_t,
            0xac6732c6 as libc::c_long as uint32_t,
            0x8c4f5573 as libc::c_long as uint32_t,
            0x695b27b0 as libc::c_long as uint32_t,
            0xbbca58c8 as libc::c_long as uint32_t,
            0xe1ffa35d as libc::c_long as uint32_t,
            0xb8f011a0 as libc::c_long as uint32_t,
            0x10fa3d98 as libc::c_long as uint32_t,
            0xfd2183b8 as libc::c_long as uint32_t,
            0x4afcb56c as libc::c_long as uint32_t,
            0x2dd1d35b as libc::c_long as uint32_t,
            0x9a53e479 as libc::c_long as uint32_t,
            0xb6f84565 as libc::c_long as uint32_t,
            0xd28e49bc as libc::c_long as uint32_t,
            0x4bfb9790 as libc::c_long as uint32_t,
            0xe1ddf2da as libc::c_long as uint32_t,
            0xa4cb7e33 as libc::c_long as uint32_t,
            0x62fb1341 as libc::c_long as uint32_t,
            0xcee4c6e8 as libc::c_long as uint32_t,
            0xef20cada as libc::c_long as uint32_t,
            0x36774c01 as libc::c_long as uint32_t,
            0xd07e9efe as libc::c_long as uint32_t,
            0x2bf11fb4 as libc::c_long as uint32_t,
            0x95dbda4d as libc::c_long as uint32_t,
            0xae909198 as libc::c_long as uint32_t,
            0xeaad8e71 as libc::c_long as uint32_t,
            0x6b93d5a0 as libc::c_long as uint32_t,
            0xd08ed1d0 as libc::c_long as uint32_t,
            0xafc725e0 as libc::c_long as uint32_t,
            0x8e3c5b2f as libc::c_long as uint32_t,
            0x8e7594b7 as libc::c_long as uint32_t,
            0x8ff6e2fb as libc::c_long as uint32_t,
            0xf2122b64 as libc::c_long as uint32_t,
            0x8888b812 as libc::c_long as uint32_t,
            0x900df01c as libc::c_long as uint32_t,
            0x4fad5ea0 as libc::c_long as uint32_t,
            0x688fc31c as libc::c_long as uint32_t,
            0xd1cff191 as libc::c_long as uint32_t,
            0xb3a8c1ad as libc::c_long as uint32_t,
            0x2f2f2218 as libc::c_long as uint32_t,
            0xbe0e1777 as libc::c_long as uint32_t,
            0xea752dfe as libc::c_long as uint32_t,
            0x8b021fa1 as libc::c_long as uint32_t,
            0xe5a0cc0f as libc::c_long as uint32_t,
            0xb56f74e8 as libc::c_long as uint32_t,
            0x18acf3d6 as libc::c_long as uint32_t,
            0xce89e299 as libc::c_long as uint32_t,
            0xb4a84fe0 as libc::c_long as uint32_t,
            0xfd13e0b7 as libc::c_long as uint32_t,
            0x7cc43b81 as libc::c_long as uint32_t,
            0xd2ada8d9 as libc::c_long as uint32_t,
            0x165fa266 as libc::c_long as uint32_t,
            0x80957705 as libc::c_long as uint32_t,
            0x93cc7314 as libc::c_long as uint32_t,
            0x211a1477 as libc::c_long as uint32_t,
            0xe6ad2065 as libc::c_long as uint32_t,
            0x77b5fa86 as libc::c_long as uint32_t,
            0xc75442f5 as libc::c_long as uint32_t,
            0xfb9d35cf as libc::c_long as uint32_t,
            0xebcdaf0c as libc::c_long as uint32_t,
            0x7b3e89a0 as libc::c_long as uint32_t,
            0xd6411bd3 as libc::c_long as uint32_t,
            0xae1e7e49 as libc::c_long as uint32_t,
            0x250e2d as libc::c_long as uint32_t,
            0x2071b35e as libc::c_long as uint32_t,
            0x226800bb as libc::c_long as uint32_t,
            0x57b8e0af as libc::c_long as uint32_t,
            0x2464369b as libc::c_long as uint32_t,
            0xf009b91e as libc::c_long as uint32_t,
            0x5563911d as libc::c_long as uint32_t,
            0x59dfa6aa as libc::c_long as uint32_t,
            0x78c14389 as libc::c_long as uint32_t,
            0xd95a537f as libc::c_long as uint32_t,
            0x207d5ba2 as libc::c_long as uint32_t,
            0x2e5b9c5 as libc::c_long as uint32_t,
            0x83260376 as libc::c_long as uint32_t,
            0x6295cfa9 as libc::c_long as uint32_t,
            0x11c81968 as libc::c_long as uint32_t,
            0x4e734a41 as libc::c_long as uint32_t,
            0xb3472dca as libc::c_long as uint32_t,
            0x7b14a94a as libc::c_long as uint32_t,
            0x1b510052 as libc::c_long as uint32_t,
            0x9a532915 as libc::c_long as uint32_t,
            0xd60f573f as libc::c_long as uint32_t,
            0xbc9bc6e4 as libc::c_long as uint32_t,
            0x2b60a476 as libc::c_long as uint32_t,
            0x81e67400 as libc::c_long as uint32_t,
            0x8ba6fb5 as libc::c_long as uint32_t,
            0x571be91f as libc::c_long as uint32_t,
            0xf296ec6b as libc::c_long as uint32_t,
            0x2a0dd915 as libc::c_long as uint32_t,
            0xb6636521 as libc::c_long as uint32_t,
            0xe7b9f9b6 as libc::c_long as uint32_t,
            0xff34052e as libc::c_long as uint32_t,
            0xc5855664 as libc::c_long as uint32_t,
            0x53b02d5d as libc::c_long as uint32_t,
            0xa99f8fa1 as libc::c_long as uint32_t,
            0x8ba4799 as libc::c_long as uint32_t,
            0x6e85076a as libc::c_long as uint32_t,
            0x4b7a70e9 as libc::c_long as uint32_t,
            0xb5b32944 as libc::c_long as uint32_t,
            0xdb75092e as libc::c_long as uint32_t,
            0xc4192623 as libc::c_long as uint32_t,
            0xad6ea6b0 as libc::c_long as uint32_t,
            0x49a7df7d as libc::c_long as uint32_t,
            0x9cee60b8 as libc::c_long as uint32_t,
            0x8fedb266 as libc::c_long as uint32_t,
            0xecaa8c71 as libc::c_long as uint32_t,
            0x699a17ff as libc::c_long as uint32_t,
            0x5664526c as libc::c_long as uint32_t,
            0xc2b19ee1 as libc::c_long as uint32_t,
            0x193602a5 as libc::c_long as uint32_t,
            0x75094c29 as libc::c_long as uint32_t,
            0xa0591340 as libc::c_long as uint32_t,
            0xe4183a3e as libc::c_long as uint32_t,
            0x3f54989a as libc::c_long as uint32_t,
            0x5b429d65 as libc::c_long as uint32_t,
            0x6b8fe4d6 as libc::c_long as uint32_t,
            0x99f73fd6 as libc::c_long as uint32_t,
            0xa1d29c07 as libc::c_long as uint32_t,
            0xefe830f5 as libc::c_long as uint32_t,
            0x4d2d38e6 as libc::c_long as uint32_t,
            0xf0255dc1 as libc::c_long as uint32_t,
            0x4cdd2086 as libc::c_long as uint32_t,
            0x8470eb26 as libc::c_long as uint32_t,
            0x6382e9c6 as libc::c_long as uint32_t,
            0x21ecc5e as libc::c_long as uint32_t,
            0x9686b3f as libc::c_long as uint32_t,
            0x3ebaefc9 as libc::c_long as uint32_t,
            0x3c971814 as libc::c_long as uint32_t,
            0x6b6a70a1 as libc::c_long as uint32_t,
            0x687f3584 as libc::c_long as uint32_t,
            0x52a0e286 as libc::c_long as uint32_t,
            0xb79c5305 as libc::c_long as uint32_t,
            0xaa500737 as libc::c_long as uint32_t,
            0x3e07841c as libc::c_long as uint32_t,
            0x7fdeae5c as libc::c_long as uint32_t,
            0x8e7d44ec as libc::c_long as uint32_t,
            0x5716f2b8 as libc::c_long as uint32_t,
            0xb03ada37 as libc::c_long as uint32_t,
            0xf0500c0d as libc::c_long as uint32_t,
            0xf01c1f04 as libc::c_long as uint32_t,
            0x200b3ff as libc::c_long as uint32_t,
            0xae0cf51a as libc::c_long as uint32_t,
            0x3cb574b2 as libc::c_long as uint32_t,
            0x25837a58 as libc::c_long as uint32_t,
            0xdc0921bd as libc::c_long as uint32_t,
            0xd19113f9 as libc::c_long as uint32_t,
            0x7ca92ff6 as libc::c_long as uint32_t,
            0x94324773 as libc::c_long as uint32_t,
            0x22f54701 as libc::c_long as uint32_t,
            0x3ae5e581 as libc::c_long as uint32_t,
            0x37c2dadc as libc::c_long as uint32_t,
            0xc8b57634 as libc::c_long as uint32_t,
            0x9af3dda7 as libc::c_long as uint32_t,
            0xa9446146 as libc::c_long as uint32_t,
            0xfd0030e as libc::c_long as uint32_t,
            0xecc8c73e as libc::c_long as uint32_t,
            0xa4751e41 as libc::c_long as uint32_t,
            0xe238cd99 as libc::c_long as uint32_t,
            0x3bea0e2f as libc::c_long as uint32_t,
            0x3280bba1 as libc::c_long as uint32_t,
            0x183eb331 as libc::c_long as uint32_t,
            0x4e548b38 as libc::c_long as uint32_t,
            0x4f6db908 as libc::c_long as uint32_t,
            0x6f420d03 as libc::c_long as uint32_t,
            0xf60a04bf as libc::c_long as uint32_t,
            0x2cb81290 as libc::c_long as uint32_t,
            0x24977c79 as libc::c_long as uint32_t,
            0x5679b072 as libc::c_long as uint32_t,
            0xbcaf89af as libc::c_long as uint32_t,
            0xde9a771f as libc::c_long as uint32_t,
            0xd9930810 as libc::c_long as uint32_t,
            0xb38bae12 as libc::c_long as uint32_t,
            0xdccf3f2e as libc::c_long as uint32_t,
            0x5512721f as libc::c_long as uint32_t,
            0x2e6b7124 as libc::c_long as uint32_t,
            0x501adde6 as libc::c_long as uint32_t,
            0x9f84cd87 as libc::c_long as uint32_t,
            0x7a584718 as libc::c_long as uint32_t,
            0x7408da17 as libc::c_long as uint32_t,
            0xbc9f9abc as libc::c_long as uint32_t,
            0xe94b7d8c as libc::c_long as uint32_t,
            0xec7aec3a as libc::c_long as uint32_t,
            0xdb851dfa as libc::c_long as uint32_t,
            0x63094366 as libc::c_long as uint32_t,
            0xc464c3d2 as libc::c_long as uint32_t,
            0xef1c1847 as libc::c_long as uint32_t,
            0x3215d908 as libc::c_long as uint32_t,
            0xdd433b37 as libc::c_long as uint32_t,
            0x24c2ba16 as libc::c_long as uint32_t,
            0x12a14d43 as libc::c_long as uint32_t,
            0x2a65c451 as libc::c_long as uint32_t,
            0x50940002 as libc::c_long as uint32_t,
            0x133ae4dd as libc::c_long as uint32_t,
            0x71dff89e as libc::c_long as uint32_t,
            0x10314e55 as libc::c_long as uint32_t,
            0x81ac77d6 as libc::c_long as uint32_t,
            0x5f11199b as libc::c_long as uint32_t,
            0x43556f1 as libc::c_long as uint32_t,
            0xd7a3c76b as libc::c_long as uint32_t,
            0x3c11183b as libc::c_long as uint32_t,
            0x5924a509 as libc::c_long as uint32_t,
            0xf28fe6ed as libc::c_long as uint32_t,
            0x97f1fbfa as libc::c_long as uint32_t,
            0x9ebabf2c as libc::c_long as uint32_t,
            0x1e153c6e as libc::c_long as uint32_t,
            0x86e34570 as libc::c_long as uint32_t,
            0xeae96fb1 as libc::c_long as uint32_t,
            0x860e5e0a as libc::c_long as uint32_t,
            0x5a3e2ab3 as libc::c_long as uint32_t,
            0x771fe71c as libc::c_long as uint32_t,
            0x4e3d06fa as libc::c_long as uint32_t,
            0x2965dcb9 as libc::c_long as uint32_t,
            0x99e71d0f as libc::c_long as uint32_t,
            0x803e89d6 as libc::c_long as uint32_t,
            0x5266c825 as libc::c_long as uint32_t,
            0x2e4cc978 as libc::c_long as uint32_t,
            0x9c10b36a as libc::c_long as uint32_t,
            0xc6150eba as libc::c_long as uint32_t,
            0x94e2ea78 as libc::c_long as uint32_t,
            0xa5fc3c53 as libc::c_long as uint32_t,
            0x1e0a2df4 as libc::c_long as uint32_t,
            0xf2f74ea7 as libc::c_long as uint32_t,
            0x361d2b3d as libc::c_long as uint32_t,
            0x1939260f as libc::c_long as uint32_t,
            0x19c27960 as libc::c_long as uint32_t,
            0x5223a708 as libc::c_long as uint32_t,
            0xf71312b6 as libc::c_long as uint32_t,
            0xebadfe6e as libc::c_long as uint32_t,
            0xeac31f66 as libc::c_long as uint32_t,
            0xe3bc4595 as libc::c_long as uint32_t,
            0xa67bc883 as libc::c_long as uint32_t,
            0xb17f37d1 as libc::c_long as uint32_t,
            0x18cff28 as libc::c_long as uint32_t,
            0xc332ddef as libc::c_long as uint32_t,
            0xbe6c5aa5 as libc::c_long as uint32_t,
            0x65582185 as libc::c_long as uint32_t,
            0x68ab9802 as libc::c_long as uint32_t,
            0xeecea50f as libc::c_long as uint32_t,
            0xdb2f953b as libc::c_long as uint32_t,
            0x2aef7dad as libc::c_long as uint32_t,
            0x5b6e2f84 as libc::c_long as uint32_t,
            0x1521b628 as libc::c_long as uint32_t,
            0x29076170 as libc::c_long as uint32_t,
            0xecdd4775 as libc::c_long as uint32_t,
            0x619f1510 as libc::c_long as uint32_t,
            0x13cca830 as libc::c_long as uint32_t,
            0xeb61bd96 as libc::c_long as uint32_t,
            0x334fe1e as libc::c_long as uint32_t,
            0xaa0363cf as libc::c_long as uint32_t,
            0xb5735c90 as libc::c_long as uint32_t,
            0x4c70a239 as libc::c_long as uint32_t,
            0xd59e9e0b as libc::c_long as uint32_t,
            0xcbaade14 as libc::c_long as uint32_t,
            0xeecc86bc as libc::c_long as uint32_t,
            0x60622ca7 as libc::c_long as uint32_t,
            0x9cab5cab as libc::c_long as uint32_t,
            0xb2f3846e as libc::c_long as uint32_t,
            0x648b1eaf as libc::c_long as uint32_t,
            0x19bdf0ca as libc::c_long as uint32_t,
            0xa02369b9 as libc::c_long as uint32_t,
            0x655abb50 as libc::c_long as uint32_t,
            0x40685a32 as libc::c_long as uint32_t,
            0x3c2ab4b3 as libc::c_long as uint32_t,
            0x319ee9d5 as libc::c_long as uint32_t,
            0xc021b8f7 as libc::c_long as uint32_t,
            0x9b540b19 as libc::c_long as uint32_t,
            0x875fa099 as libc::c_long as uint32_t,
            0x95f7997e as libc::c_long as uint32_t,
            0x623d7da8 as libc::c_long as uint32_t,
            0xf837889a as libc::c_long as uint32_t,
            0x97e32d77 as libc::c_long as uint32_t,
            0x11ed935f as libc::c_long as uint32_t,
            0x16681281 as libc::c_long as uint32_t,
            0xe358829 as libc::c_long as uint32_t,
            0xc7e61fd6 as libc::c_long as uint32_t,
            0x96dedfa1 as libc::c_long as uint32_t,
            0x7858ba99 as libc::c_long as uint32_t,
            0x57f584a5 as libc::c_long as uint32_t,
            0x1b227263 as libc::c_long as uint32_t,
            0x9b83c3ff as libc::c_long as uint32_t,
            0x1ac24696 as libc::c_long as uint32_t,
            0xcdb30aeb as libc::c_long as uint32_t,
            0x532e3054 as libc::c_long as uint32_t,
            0x8fd948e4 as libc::c_long as uint32_t,
            0x6dbc3128 as libc::c_long as uint32_t,
            0x58ebf2ef as libc::c_long as uint32_t,
            0x34c6ffea as libc::c_long as uint32_t,
            0xfe28ed61 as libc::c_long as uint32_t,
            0xee7c3c73 as libc::c_long as uint32_t,
            0x5d4a14d9 as libc::c_long as uint32_t,
            0xe864b7e3 as libc::c_long as uint32_t,
            0x42105d14 as libc::c_long as uint32_t,
            0x203e13e0 as libc::c_long as uint32_t,
            0x45eee2b6 as libc::c_long as uint32_t,
            0xa3aaabea as libc::c_long as uint32_t,
            0xdb6c4f15 as libc::c_long as uint32_t,
            0xfacb4fd0 as libc::c_long as uint32_t,
            0xc742f442 as libc::c_long as uint32_t,
            0xef6abbb5 as libc::c_long as uint32_t,
            0x654f3b1d as libc::c_long as uint32_t,
            0x41cd2105 as libc::c_long as uint32_t,
            0xd81e799e as libc::c_long as uint32_t,
            0x86854dc7 as libc::c_long as uint32_t,
            0xe44b476a as libc::c_long as uint32_t,
            0x3d816250 as libc::c_long as uint32_t,
            0xcf62a1f2 as libc::c_long as uint32_t,
            0x5b8d2646 as libc::c_long as uint32_t,
            0xfc8883a0 as libc::c_long as uint32_t,
            0xc1c7b6a3 as libc::c_long as uint32_t,
            0x7f1524c3 as libc::c_long as uint32_t,
            0x69cb7492 as libc::c_long as uint32_t,
            0x47848a0b as libc::c_long as uint32_t,
            0x5692b285 as libc::c_long as uint32_t,
            0x95bbf00 as libc::c_long as uint32_t,
            0xad19489d as libc::c_long as uint32_t,
            0x1462b174 as libc::c_long as uint32_t,
            0x23820e00 as libc::c_long as uint32_t,
            0x58428d2a as libc::c_long as uint32_t,
            0xc55f5ea as libc::c_long as uint32_t,
            0x1dadf43e as libc::c_long as uint32_t,
            0x233f7061 as libc::c_long as uint32_t,
            0x3372f092 as libc::c_long as uint32_t,
            0x8d937e41 as libc::c_long as uint32_t,
            0xd65fecf1 as libc::c_long as uint32_t,
            0x6c223bdb as libc::c_long as uint32_t,
            0x7cde3759 as libc::c_long as uint32_t,
            0xcbee7460 as libc::c_long as uint32_t,
            0x4085f2a7 as libc::c_long as uint32_t,
            0xce77326e as libc::c_long as uint32_t,
            0xa6078084 as libc::c_long as uint32_t,
            0x19f8509e as libc::c_long as uint32_t,
            0xe8efd855 as libc::c_long as uint32_t,
            0x61d99735 as libc::c_long as uint32_t,
            0xa969a7aa as libc::c_long as uint32_t,
            0xc50c06c2 as libc::c_long as uint32_t,
            0x5a04abfc as libc::c_long as uint32_t,
            0x800bcadc as libc::c_long as uint32_t,
            0x9e447a2e as libc::c_long as uint32_t,
            0xc3453484 as libc::c_long as uint32_t,
            0xfdd56705 as libc::c_long as uint32_t,
            0xe1e9ec9 as libc::c_long as uint32_t,
            0xdb73dbd3 as libc::c_long as uint32_t,
            0x105588cd as libc::c_long as uint32_t,
            0x675fda79 as libc::c_long as uint32_t,
            0xe3674340 as libc::c_long as uint32_t,
            0xc5c43465 as libc::c_long as uint32_t,
            0x713e38d8 as libc::c_long as uint32_t,
            0x3d28f89e as libc::c_long as uint32_t,
            0xf16dff20 as libc::c_long as uint32_t,
            0x153e21e7 as libc::c_long as uint32_t,
            0x8fb03d4a as libc::c_long as uint32_t,
            0xe6e39f2b as libc::c_long as uint32_t,
            0xdb83adf7 as libc::c_long as uint32_t,
            0xe93d5a68 as libc::c_long as uint32_t,
            0x948140f7 as libc::c_long as uint32_t,
            0xf64c261c as libc::c_long as uint32_t,
            0x94692934 as libc::c_long as uint32_t,
            0x411520f7 as libc::c_long as uint32_t,
            0x7602d4f7 as libc::c_long as uint32_t,
            0xbcf46b2e as libc::c_long as uint32_t,
            0xd4a20068 as libc::c_long as uint32_t,
            0xd4082471 as libc::c_long as uint32_t,
            0x3320f46a as libc::c_long as uint32_t,
            0x43b7d4b7 as libc::c_long as uint32_t,
            0x500061af as libc::c_long as uint32_t,
            0x1e39f62e as libc::c_long as uint32_t,
            0x97244546 as libc::c_long as uint32_t,
            0x14214f74 as libc::c_long as uint32_t,
            0xbf8b8840 as libc::c_long as uint32_t,
            0x4d95fc1d as libc::c_long as uint32_t,
            0x96b591af as libc::c_long as uint32_t,
            0x70f4ddd3 as libc::c_long as uint32_t,
            0x66a02f45 as libc::c_long as uint32_t,
            0xbfbc09ec as libc::c_long as uint32_t,
            0x3bd9785 as libc::c_long as uint32_t,
            0x7fac6dd0 as libc::c_long as uint32_t,
            0x31cb8504 as libc::c_long as uint32_t,
            0x96eb27b3 as libc::c_long as uint32_t,
            0x55fd3941 as libc::c_long as uint32_t,
            0xda2547e6 as libc::c_long as uint32_t,
            0xabca0a9a as libc::c_long as uint32_t,
            0x28507825 as libc::c_long as uint32_t,
            0x530429f4 as libc::c_long as uint32_t,
            0xa2c86da as libc::c_long as uint32_t,
            0xe9b66dfb as libc::c_long as uint32_t,
            0x68dc1462 as libc::c_long as uint32_t,
            0xd7486900 as libc::c_long as uint32_t,
            0x680ec0a4 as libc::c_long as uint32_t,
            0x27a18dee as libc::c_long as uint32_t,
            0x4f3ffea2 as libc::c_long as uint32_t,
            0xe887ad8c as libc::c_long as uint32_t,
            0xb58ce006 as libc::c_long as uint32_t,
            0x7af4d6b6 as libc::c_long as uint32_t,
            0xaace1e7c as libc::c_long as uint32_t,
            0xd3375fec as libc::c_long as uint32_t,
            0xce78a399 as libc::c_long as uint32_t,
            0x406b2a42 as libc::c_long as uint32_t,
            0x20fe9e35 as libc::c_long as uint32_t,
            0xd9f385b9 as libc::c_long as uint32_t,
            0xee39d7ab as libc::c_long as uint32_t,
            0x3b124e8b as libc::c_long as uint32_t,
            0x1dc9faf7 as libc::c_long as uint32_t,
            0x4b6d1856 as libc::c_long as uint32_t,
            0x26a36631 as libc::c_long as uint32_t,
            0xeae397b2 as libc::c_long as uint32_t,
            0x3a6efa74 as libc::c_long as uint32_t,
            0xdd5b4332 as libc::c_long as uint32_t,
            0x6841e7f7 as libc::c_long as uint32_t,
            0xca7820fb as libc::c_long as uint32_t,
            0xfb0af54e as libc::c_long as uint32_t,
            0xd8feb397 as libc::c_long as uint32_t,
            0x454056ac as libc::c_long as uint32_t,
            0xba489527 as libc::c_long as uint32_t,
            0x55533a3a as libc::c_long as uint32_t,
            0x20838d87 as libc::c_long as uint32_t,
            0xfe6ba9b7 as libc::c_long as uint32_t,
            0xd096954b as libc::c_long as uint32_t,
            0x55a867bc as libc::c_long as uint32_t,
            0xa1159a58 as libc::c_long as uint32_t,
            0xcca92963 as libc::c_long as uint32_t,
            0x99e1db33 as libc::c_long as uint32_t,
            0xa62a4a56 as libc::c_long as uint32_t,
            0x3f3125f9 as libc::c_long as uint32_t,
            0x5ef47e1c as libc::c_long as uint32_t,
            0x9029317c as libc::c_long as uint32_t,
            0xfdf8e802 as libc::c_long as uint32_t,
            0x4272f70 as libc::c_long as uint32_t,
            0x80bb155c as libc::c_long as uint32_t,
            0x5282ce3 as libc::c_long as uint32_t,
            0x95c11548 as libc::c_long as uint32_t,
            0xe4c66d22 as libc::c_long as uint32_t,
            0x48c1133f as libc::c_long as uint32_t,
            0xc70f86dc as libc::c_long as uint32_t,
            0x7f9c9ee as libc::c_long as uint32_t,
            0x41041f0f as libc::c_long as uint32_t,
            0x404779a4 as libc::c_long as uint32_t,
            0x5d886e17 as libc::c_long as uint32_t,
            0x325f51eb as libc::c_long as uint32_t,
            0xd59bc0d1 as libc::c_long as uint32_t,
            0xf2bcc18f as libc::c_long as uint32_t,
            0x41113564 as libc::c_long as uint32_t,
            0x257b7834 as libc::c_long as uint32_t,
            0x602a9c60 as libc::c_long as uint32_t,
            0xdff8e8a3 as libc::c_long as uint32_t,
            0x1f636c1b as libc::c_long as uint32_t,
            0xe12b4c2 as libc::c_long as uint32_t,
            0x2e1329e as libc::c_long as uint32_t,
            0xaf664fd1 as libc::c_long as uint32_t,
            0xcad18115 as libc::c_long as uint32_t,
            0x6b2395e0 as libc::c_long as uint32_t,
            0x333e92e1 as libc::c_long as uint32_t,
            0x3b240b62 as libc::c_long as uint32_t,
            0xeebeb922 as libc::c_long as uint32_t,
            0x85b2a20e as libc::c_long as uint32_t,
            0xe6ba0d99 as libc::c_long as uint32_t,
            0xde720c8c as libc::c_long as uint32_t,
            0x2da2f728 as libc::c_long as uint32_t,
            0xd0127845 as libc::c_long as uint32_t,
            0x95b794fd as libc::c_long as uint32_t,
            0x647d0862 as libc::c_long as uint32_t,
            0xe7ccf5f0 as libc::c_long as uint32_t,
            0x5449a36f as libc::c_long as uint32_t,
            0x877d48fa as libc::c_long as uint32_t,
            0xc39dfd27 as libc::c_long as uint32_t,
            0xf33e8d1e as libc::c_long as uint32_t,
            0xa476341 as libc::c_long as uint32_t,
            0x992eff74 as libc::c_long as uint32_t,
            0x3a6f6eab as libc::c_long as uint32_t,
            0xf4f8fd37 as libc::c_long as uint32_t,
            0xa812dc60 as libc::c_long as uint32_t,
            0xa1ebddf8 as libc::c_long as uint32_t,
            0x991be14c as libc::c_long as uint32_t,
            0xdb6e6b0d as libc::c_long as uint32_t,
            0xc67b5510 as libc::c_long as uint32_t,
            0x6d672c37 as libc::c_long as uint32_t,
            0x2765d43b as libc::c_long as uint32_t,
            0xdcd0e804 as libc::c_long as uint32_t,
            0xf1290dc7 as libc::c_long as uint32_t,
            0xcc00ffa3 as libc::c_long as uint32_t,
            0xb5390f92 as libc::c_long as uint32_t,
            0x690fed0b as libc::c_long as uint32_t,
            0x667b9ffb as libc::c_long as uint32_t,
            0xcedb7d9c as libc::c_long as uint32_t,
            0xa091cf0b as libc::c_long as uint32_t,
            0xd9155ea3 as libc::c_long as uint32_t,
            0xbb132f88 as libc::c_long as uint32_t,
            0x515bad24 as libc::c_long as uint32_t,
            0x7b9479bf as libc::c_long as uint32_t,
            0x763bd6eb as libc::c_long as uint32_t,
            0x37392eb3 as libc::c_long as uint32_t,
            0xcc115979 as libc::c_long as uint32_t,
            0x8026e297 as libc::c_long as uint32_t,
            0xf42e312d as libc::c_long as uint32_t,
            0x6842ada7 as libc::c_long as uint32_t,
            0xc66a2b3b as libc::c_long as uint32_t,
            0x12754ccc as libc::c_long as uint32_t,
            0x782ef11c as libc::c_long as uint32_t,
            0x6a124237 as libc::c_long as uint32_t,
            0xb79251e7 as libc::c_long as uint32_t,
            0x6a1bbe6 as libc::c_long as uint32_t,
            0x4bfb6350 as libc::c_long as uint32_t,
            0x1a6b1018 as libc::c_long as uint32_t,
            0x11caedfa as libc::c_long as uint32_t,
            0x3d25bdd8 as libc::c_long as uint32_t,
            0xe2e1c3c9 as libc::c_long as uint32_t,
            0x44421659 as libc::c_long as uint32_t,
            0xa121386 as libc::c_long as uint32_t,
            0xd90cec6e as libc::c_long as uint32_t,
            0xd5abea2a as libc::c_long as uint32_t,
            0x64af674e as libc::c_long as uint32_t,
            0xda86a85f as libc::c_long as uint32_t,
            0xbebfe988 as libc::c_long as uint32_t,
            0x64e4c3fe as libc::c_long as uint32_t,
            0x9dbc8057 as libc::c_long as uint32_t,
            0xf0f7c086 as libc::c_long as uint32_t,
            0x60787bf8 as libc::c_long as uint32_t,
            0x6003604d as libc::c_long as uint32_t,
            0xd1fd8346 as libc::c_long as uint32_t,
            0xf6381fb0 as libc::c_long as uint32_t,
            0x7745ae04 as libc::c_long as uint32_t,
            0xd736fccc as libc::c_long as uint32_t,
            0x83426b33 as libc::c_long as uint32_t,
            0xf01eab71 as libc::c_long as uint32_t,
            0xb0804187 as libc::c_long as uint32_t,
            0x3c005e5f as libc::c_long as uint32_t,
            0x77a057be as libc::c_long as uint32_t,
            0xbde8ae24 as libc::c_long as uint32_t,
            0x55464299 as libc::c_long as uint32_t,
            0xbf582e61 as libc::c_long as uint32_t,
            0x4e58f48f as libc::c_long as uint32_t,
            0xf2ddfda2 as libc::c_long as uint32_t,
            0xf474ef38 as libc::c_long as uint32_t,
            0x8789bdc2 as libc::c_long as uint32_t,
            0x5366f9c3 as libc::c_long as uint32_t,
            0xc8b38e74 as libc::c_long as uint32_t,
            0xb475f255 as libc::c_long as uint32_t,
            0x46fcd9b9 as libc::c_long as uint32_t,
            0x7aeb2661 as libc::c_long as uint32_t,
            0x8b1ddf84 as libc::c_long as uint32_t,
            0x846a0e79 as libc::c_long as uint32_t,
            0x915f95e2 as libc::c_long as uint32_t,
            0x466e598e as libc::c_long as uint32_t,
            0x20b45770 as libc::c_long as uint32_t,
            0x8cd55591 as libc::c_long as uint32_t,
            0xc902de4c as libc::c_long as uint32_t,
            0xb90bace1 as libc::c_long as uint32_t,
            0xbb8205d0 as libc::c_long as uint32_t,
            0x11a86248 as libc::c_long as uint32_t,
            0x7574a99e as libc::c_long as uint32_t,
            0xb77f19b6 as libc::c_long as uint32_t,
            0xe0a9dc09 as libc::c_long as uint32_t,
            0x662d09a1 as libc::c_long as uint32_t,
            0xc4324633 as libc::c_long as uint32_t,
            0xe85a1f02 as libc::c_long as uint32_t,
            0x9f0be8c as libc::c_long as uint32_t,
            0x4a99a025 as libc::c_long as uint32_t,
            0x1d6efe10 as libc::c_long as uint32_t,
            0x1ab93d1d as libc::c_long as uint32_t,
            0xba5a4df as libc::c_long as uint32_t,
            0xa186f20f as libc::c_long as uint32_t,
            0x2868f169 as libc::c_long as uint32_t,
            0xdcb7da83 as libc::c_long as uint32_t,
            0x573906fe as libc::c_long as uint32_t,
            0xa1e2ce9b as libc::c_long as uint32_t,
            0x4fcd7f52 as libc::c_long as uint32_t,
            0x50115e01 as libc::c_long as uint32_t,
            0xa70683fa as libc::c_long as uint32_t,
            0xa002b5c4 as libc::c_long as uint32_t,
            0xde6d027 as libc::c_long as uint32_t,
            0x9af88c27 as libc::c_long as uint32_t,
            0x773f8641 as libc::c_long as uint32_t,
            0xc3604c06 as libc::c_long as uint32_t,
            0x61a806b5 as libc::c_long as uint32_t,
            0xf0177a28 as libc::c_long as uint32_t,
            0xc0f586e0 as libc::c_long as uint32_t,
            0x6058aa as libc::c_long as uint32_t,
            0x30dc7d62 as libc::c_long as uint32_t,
            0x11e69ed7 as libc::c_long as uint32_t,
            0x2338ea63 as libc::c_long as uint32_t,
            0x53c2dd94 as libc::c_long as uint32_t,
            0xc2c21634 as libc::c_long as uint32_t,
            0xbbcbee56 as libc::c_long as uint32_t,
            0x90bcb6de as libc::c_long as uint32_t,
            0xebfc7da1 as libc::c_long as uint32_t,
            0xce591d76 as libc::c_long as uint32_t,
            0x6f05e409 as libc::c_long as uint32_t,
            0x4b7c0188 as libc::c_long as uint32_t,
            0x39720a3d as libc::c_long as uint32_t,
            0x7c927c24 as libc::c_long as uint32_t,
            0x86e3725f as libc::c_long as uint32_t,
            0x724d9db9 as libc::c_long as uint32_t,
            0x1ac15bb4 as libc::c_long as uint32_t,
            0xd39eb8fc as libc::c_long as uint32_t,
            0xed545578 as libc::c_long as uint32_t,
            0x8fca5b5 as libc::c_long as uint32_t,
            0xd83d7cd3 as libc::c_long as uint32_t,
            0x4dad0fc4 as libc::c_long as uint32_t,
            0x1e50ef5e as libc::c_long as uint32_t,
            0xb161e6f8 as libc::c_long as uint32_t,
            0xa28514d9 as libc::c_long as uint32_t,
            0x6c51133c as libc::c_long as uint32_t,
            0x6fd5c7e7 as libc::c_long as uint32_t,
            0x56e14ec4 as libc::c_long as uint32_t,
            0x362abfce as libc::c_long as uint32_t,
            0xddc6c837 as libc::c_long as uint32_t,
            0xd79a3234 as libc::c_long as uint32_t,
            0x92638212 as libc::c_long as uint32_t,
            0x670efa8e as libc::c_long as uint32_t,
            0x406000e0 as libc::c_long as uint32_t,
            0x3a39ce37 as libc::c_long as uint32_t,
            0xd3faf5cf as libc::c_long as uint32_t,
            0xabc27737 as libc::c_long as uint32_t,
            0x5ac52d1b as libc::c_long as uint32_t,
            0x5cb0679e as libc::c_long as uint32_t,
            0x4fa33742 as libc::c_long as uint32_t,
            0xd3822740 as libc::c_long as uint32_t,
            0x99bc9bbe as libc::c_long as uint32_t,
            0xd5118e9d as libc::c_long as uint32_t,
            0xbf0f7315 as libc::c_long as uint32_t,
            0xd62d1c7e as libc::c_long as uint32_t,
            0xc700c47b as libc::c_long as uint32_t,
            0xb78c1b6b as libc::c_long as uint32_t,
            0x21a19045 as libc::c_long as uint32_t,
            0xb26eb1be as libc::c_long as uint32_t,
            0x6a366eb4 as libc::c_long as uint32_t,
            0x5748ab2f as libc::c_long as uint32_t,
            0xbc946e79 as libc::c_long as uint32_t,
            0xc6a376d2 as libc::c_long as uint32_t,
            0x6549c2c8 as libc::c_long as uint32_t,
            0x530ff8ee as libc::c_long as uint32_t,
            0x468dde7d as libc::c_long as uint32_t,
            0xd5730a1d as libc::c_long as uint32_t,
            0x4cd04dc6 as libc::c_long as uint32_t,
            0x2939bbdb as libc::c_long as uint32_t,
            0xa9ba4650 as libc::c_long as uint32_t,
            0xac9526e8 as libc::c_long as uint32_t,
            0xbe5ee304 as libc::c_long as uint32_t,
            0xa1fad5f0 as libc::c_long as uint32_t,
            0x6a2d519a as libc::c_long as uint32_t,
            0x63ef8ce2 as libc::c_long as uint32_t,
            0x9a86ee22 as libc::c_long as uint32_t,
            0xc089c2b8 as libc::c_long as uint32_t,
            0x43242ef6 as libc::c_long as uint32_t,
            0xa51e03aa as libc::c_long as uint32_t,
            0x9cf2d0a4 as libc::c_long as uint32_t,
            0x83c061ba as libc::c_long as uint32_t,
            0x9be96a4d as libc::c_long as uint32_t,
            0x8fe51550 as libc::c_long as uint32_t,
            0xba645bd6 as libc::c_long as uint32_t,
            0x2826a2f9 as libc::c_long as uint32_t,
            0xa73a3ae1 as libc::c_long as uint32_t,
            0x4ba99586 as libc::c_long as uint32_t,
            0xef5562e9 as libc::c_long as uint32_t,
            0xc72fefd3 as libc::c_long as uint32_t,
            0xf752f7da as libc::c_long as uint32_t,
            0x3f046f69 as libc::c_long as uint32_t,
            0x77fa0a59 as libc::c_long as uint32_t,
            0x80e4a915 as libc::c_long as uint32_t,
            0x87b08601 as libc::c_long as uint32_t,
            0x9b09e6ad as libc::c_long as uint32_t,
            0x3b3ee593 as libc::c_long as uint32_t,
            0xe990fd5a as libc::c_long as uint32_t,
            0x9e34d797 as libc::c_long as uint32_t,
            0x2cf0b7d9 as libc::c_long as uint32_t,
            0x22b8b51 as libc::c_long as uint32_t,
            0x96d5ac3a as libc::c_long as uint32_t,
            0x17da67d as libc::c_long as uint32_t,
            0xd1cf3ed6 as libc::c_long as uint32_t,
            0x7c7d2d28 as libc::c_long as uint32_t,
            0x1f9f25cf as libc::c_long as uint32_t,
            0xadf2b89b as libc::c_long as uint32_t,
            0x5ad6b472 as libc::c_long as uint32_t,
            0x5a88f54c as libc::c_long as uint32_t,
            0xe029ac71 as libc::c_long as uint32_t,
            0xe019a5e6 as libc::c_long as uint32_t,
            0x47b0acfd as libc::c_long as uint32_t,
            0xed93fa9b as libc::c_long as uint32_t,
            0xe8d3c48d as libc::c_long as uint32_t,
            0x283b57cc as libc::c_long as uint32_t,
            0xf8d56629 as libc::c_long as uint32_t,
            0x79132e28 as libc::c_long as uint32_t,
            0x785f0191 as libc::c_long as uint32_t,
            0xed756055 as libc::c_long as uint32_t,
            0xf7960e44 as libc::c_long as uint32_t,
            0xe3d35e8c as libc::c_long as uint32_t,
            0x15056dd4 as libc::c_long as uint32_t,
            0x88f46dba as libc::c_long as uint32_t,
            0x3a16125 as libc::c_long as uint32_t,
            0x564f0bd as libc::c_long as uint32_t,
            0xc3eb9e15 as libc::c_long as uint32_t,
            0x3c9057a2 as libc::c_long as uint32_t,
            0x97271aec as libc::c_long as uint32_t,
            0xa93a072a as libc::c_long as uint32_t,
            0x1b3f6d9b as libc::c_long as uint32_t,
            0x1e6321f5 as libc::c_long as uint32_t,
            0xf59c66fb as libc::c_long as uint32_t,
            0x26dcf319 as libc::c_long as uint32_t,
            0x7533d928 as libc::c_long as uint32_t,
            0xb155fdf5 as libc::c_long as uint32_t,
            0x3563482 as libc::c_long as uint32_t,
            0x8aba3cbb as libc::c_long as uint32_t,
            0x28517711 as libc::c_long as uint32_t,
            0xc20ad9f8 as libc::c_long as uint32_t,
            0xabcc5167 as libc::c_long as uint32_t,
            0xccad925f as libc::c_long as uint32_t,
            0x4de81751 as libc::c_long as uint32_t,
            0x3830dc8e as libc::c_long as uint32_t,
            0x379d5862 as libc::c_long as uint32_t,
            0x9320f991 as libc::c_long as uint32_t,
            0xea7a90c2 as libc::c_long as uint32_t,
            0xfb3e7bce as libc::c_long as uint32_t,
            0x5121ce64 as libc::c_long as uint32_t,
            0x774fbe32 as libc::c_long as uint32_t,
            0xa8b6e37e as libc::c_long as uint32_t,
            0xc3293d46 as libc::c_long as uint32_t,
            0x48de5369 as libc::c_long as uint32_t,
            0x6413e680 as libc::c_long as uint32_t,
            0xa2ae0810 as libc::c_long as uint32_t,
            0xdd6db224 as libc::c_long as uint32_t,
            0x69852dfd as libc::c_long as uint32_t,
            0x9072166 as libc::c_long as uint32_t,
            0xb39a460a as libc::c_long as uint32_t,
            0x6445c0dd as libc::c_long as uint32_t,
            0x586cdecf as libc::c_long as uint32_t,
            0x1c20c8ae as libc::c_long as uint32_t,
            0x5bbef7dd as libc::c_long as uint32_t,
            0x1b588d40 as libc::c_long as uint32_t,
            0xccd2017f as libc::c_long as uint32_t,
            0x6bb4e3bb as libc::c_long as uint32_t,
            0xdda26a7e as libc::c_long as uint32_t,
            0x3a59ff45 as libc::c_long as uint32_t,
            0x3e350a44 as libc::c_long as uint32_t,
            0xbcb4cdd5 as libc::c_long as uint32_t,
            0x72eacea8 as libc::c_long as uint32_t,
            0xfa6484bb as libc::c_long as uint32_t,
            0x8d6612ae as libc::c_long as uint32_t,
            0xbf3c6f47 as libc::c_long as uint32_t,
            0xd29be463 as libc::c_long as uint32_t,
            0x542f5d9e as libc::c_long as uint32_t,
            0xaec2771b as libc::c_long as uint32_t,
            0xf64e6370 as libc::c_long as uint32_t,
            0x740e0d8d as libc::c_long as uint32_t,
            0xe75b1357 as libc::c_long as uint32_t,
            0xf8721671 as libc::c_long as uint32_t,
            0xaf537d5d as libc::c_long as uint32_t,
            0x4040cb08 as libc::c_long as uint32_t,
            0x4eb4e2cc as libc::c_long as uint32_t,
            0x34d2466a as libc::c_long as uint32_t,
            0x115af84 as libc::c_long as uint32_t,
            0xe1b00428 as libc::c_long as uint32_t,
            0x95983a1d as libc::c_long as uint32_t,
            0x6b89fb4 as libc::c_long as uint32_t,
            0xce6ea048 as libc::c_long as uint32_t,
            0x6f3f3b82 as libc::c_long as uint32_t,
            0x3520ab82 as libc::c_long as uint32_t,
            0x11a1d4b as libc::c_long as uint32_t,
            0x277227f8 as libc::c_long as uint32_t,
            0x611560b1 as libc::c_long as uint32_t,
            0xe7933fdc as libc::c_long as uint32_t,
            0xbb3a792b as libc::c_long as uint32_t,
            0x344525bd as libc::c_long as uint32_t,
            0xa08839e1 as libc::c_long as uint32_t,
            0x51ce794b as libc::c_long as uint32_t,
            0x2f32c9b7 as libc::c_long as uint32_t,
            0xa01fbac9 as libc::c_long as uint32_t,
            0xe01cc87e as libc::c_long as uint32_t,
            0xbcc7d1f6 as libc::c_long as uint32_t,
            0xcf0111c3 as libc::c_long as uint32_t,
            0xa1e8aac7 as libc::c_long as uint32_t,
            0x1a908749 as libc::c_long as uint32_t,
            0xd44fbd9a as libc::c_long as uint32_t,
            0xd0dadecb as libc::c_long as uint32_t,
            0xd50ada38 as libc::c_long as uint32_t,
            0x339c32a as libc::c_long as uint32_t,
            0xc6913667 as libc::c_long as uint32_t,
            0x8df9317c as libc::c_long as uint32_t,
            0xe0b12b4f as libc::c_long as uint32_t,
            0xf79e59b7 as libc::c_long as uint32_t,
            0x43f5bb3a as libc::c_long as uint32_t,
            0xf2d519ff as libc::c_long as uint32_t,
            0x27d9459c as libc::c_long as uint32_t,
            0xbf97222c as libc::c_long as uint32_t,
            0x15e6fc2a as libc::c_long as uint32_t,
            0xf91fc71 as libc::c_long as uint32_t,
            0x9b941525 as libc::c_long as uint32_t,
            0xfae59361 as libc::c_long as uint32_t,
            0xceb69ceb as libc::c_long as uint32_t,
            0xc2a86459 as libc::c_long as uint32_t,
            0x12baa8d1 as libc::c_long as uint32_t,
            0xb6c1075e as libc::c_long as uint32_t,
            0xe3056a0c as libc::c_long as uint32_t,
            0x10d25065 as libc::c_long as uint32_t,
            0xcb03a442 as libc::c_long as uint32_t,
            0xe0ec6e0e as libc::c_long as uint32_t,
            0x1698db3b as libc::c_long as uint32_t,
            0x4c98a0be as libc::c_long as uint32_t,
            0x3278e964 as libc::c_long as uint32_t,
            0x9f1f9532 as libc::c_long as uint32_t,
            0xe0d392df as libc::c_long as uint32_t,
            0xd3a0342b as libc::c_long as uint32_t,
            0x8971f21e as libc::c_long as uint32_t,
            0x1b0a7441 as libc::c_long as uint32_t,
            0x4ba3348c as libc::c_long as uint32_t,
            0xc5be7120 as libc::c_long as uint32_t,
            0xc37632d8 as libc::c_long as uint32_t,
            0xdf359f8d as libc::c_long as uint32_t,
            0x9b992f2e as libc::c_long as uint32_t,
            0xe60b6f47 as libc::c_long as uint32_t,
            0xfe3f11d as libc::c_long as uint32_t,
            0xe54cda54 as libc::c_long as uint32_t,
            0x1edad891 as libc::c_long as uint32_t,
            0xce6279cf as libc::c_long as uint32_t,
            0xcd3e7e6f as libc::c_long as uint32_t,
            0x1618b166 as libc::c_long as uint32_t,
            0xfd2c1d05 as libc::c_long as uint32_t,
            0x848fd2c5 as libc::c_long as uint32_t,
            0xf6fb2299 as libc::c_long as uint32_t,
            0xf523f357 as libc::c_long as uint32_t,
            0xa6327623 as libc::c_long as uint32_t,
            0x93a83531 as libc::c_long as uint32_t,
            0x56cccd02 as libc::c_long as uint32_t,
            0xacf08162 as libc::c_long as uint32_t,
            0x5a75ebb5 as libc::c_long as uint32_t,
            0x6e163697 as libc::c_long as uint32_t,
            0x88d273cc as libc::c_long as uint32_t,
            0xde966292 as libc::c_long as uint32_t,
            0x81b949d0 as libc::c_long as uint32_t,
            0x4c50901b as libc::c_long as uint32_t,
            0x71c65614 as libc::c_long as uint32_t,
            0xe6c6c7bd as libc::c_long as uint32_t,
            0x327a140a as libc::c_long as uint32_t,
            0x45e1d006 as libc::c_long as uint32_t,
            0xc3f27b9a as libc::c_long as uint32_t,
            0xc9aa53fd as libc::c_long as uint32_t,
            0x62a80f00 as libc::c_long as uint32_t,
            0xbb25bfe2 as libc::c_long as uint32_t,
            0x35bdd2f6 as libc::c_long as uint32_t,
            0x71126905 as libc::c_long as uint32_t,
            0xb2040222 as libc::c_long as uint32_t,
            0xb6cbcf7c as libc::c_long as uint32_t,
            0xcd769c2b as libc::c_long as uint32_t,
            0x53113ec0 as libc::c_long as uint32_t,
            0x1640e3d3 as libc::c_long as uint32_t,
            0x38abbd60 as libc::c_long as uint32_t,
            0x2547adf0 as libc::c_long as uint32_t,
            0xba38209c as libc::c_long as uint32_t,
            0xf746ce76 as libc::c_long as uint32_t,
            0x77afa1c5 as libc::c_long as uint32_t,
            0x20756060 as libc::c_long as uint32_t,
            0x85cbfe4e as libc::c_long as uint32_t,
            0x8ae88dd8 as libc::c_long as uint32_t,
            0x7aaaf9b0 as libc::c_long as uint32_t,
            0x4cf9aa7e as libc::c_long as uint32_t,
            0x1948c25c as libc::c_long as uint32_t,
            0x2fb8a8c as libc::c_long as uint32_t,
            0x1c36ae4 as libc::c_long as uint32_t,
            0xd6ebe1f9 as libc::c_long as uint32_t,
            0x90d4f869 as libc::c_long as uint32_t,
            0xa65cdea0 as libc::c_long as uint32_t,
            0x3f09252d as libc::c_long as uint32_t,
            0xc208e69f as libc::c_long as uint32_t,
            0xb74e6132 as libc::c_long as uint32_t,
            0xce77e25b as libc::c_long as uint32_t,
            0x578fdfe3 as libc::c_long as uint32_t,
            0x3ac372e6 as libc::c_long as uint32_t,
        ],
    };
    init
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BF_set_key(
    mut key: *mut BF_KEY,
    mut len: size_t,
    mut data: *const uint8_t,
) {
    let mut i: libc::c_int = 0;
    let mut p: *mut uint32_t = 0 as *mut uint32_t;
    let mut ri: uint32_t = 0;
    let mut in_0: [uint32_t; 2] = [0; 2];
    let mut d: *const uint8_t = 0 as *const uint8_t;
    let mut end: *const uint8_t = 0 as *const uint8_t;
    OPENSSL_memcpy(
        key as *mut libc::c_void,
        &bf_init as *const BF_KEY as *const libc::c_void,
        ::core::mem::size_of::<BF_KEY>() as libc::c_ulong,
    );
    p = ((*key).P).as_mut_ptr();
    if len > ((16 as libc::c_int + 2 as libc::c_int) * 4 as libc::c_int) as size_t {
        len = ((16 as libc::c_int + 2 as libc::c_int) * 4 as libc::c_int) as size_t;
    }
    d = data;
    end = &*data.offset(len as isize) as *const uint8_t;
    i = 0 as libc::c_int;
    while i < 16 as libc::c_int + 2 as libc::c_int {
        let fresh96 = d;
        d = d.offset(1);
        ri = *fresh96 as uint32_t;
        if d >= end {
            d = data;
        }
        ri <<= 8 as libc::c_int;
        let fresh97 = d;
        d = d.offset(1);
        ri |= *fresh97 as uint32_t;
        if d >= end {
            d = data;
        }
        ri <<= 8 as libc::c_int;
        let fresh98 = d;
        d = d.offset(1);
        ri |= *fresh98 as uint32_t;
        if d >= end {
            d = data;
        }
        ri <<= 8 as libc::c_int;
        let fresh99 = d;
        d = d.offset(1);
        ri |= *fresh99 as uint32_t;
        if d >= end {
            d = data;
        }
        *p.offset(i as isize) ^= ri;
        i += 1;
        i;
    }
    in_0[0 as libc::c_int as usize] = 0 as libc::c_long as uint32_t;
    in_0[1 as libc::c_int as usize] = 0 as libc::c_long as uint32_t;
    i = 0 as libc::c_int;
    while i < 16 as libc::c_int + 2 as libc::c_int {
        BF_encrypt(in_0.as_mut_ptr(), key);
        *p.offset(i as isize) = in_0[0 as libc::c_int as usize];
        *p.offset((i + 1 as libc::c_int) as isize) = in_0[1 as libc::c_int as usize];
        i += 2 as libc::c_int;
    }
    p = ((*key).S).as_mut_ptr();
    i = 0 as libc::c_int;
    while i < 4 as libc::c_int * 256 as libc::c_int {
        BF_encrypt(in_0.as_mut_ptr(), key);
        *p.offset(i as isize) = in_0[0 as libc::c_int as usize];
        *p.offset((i + 1 as libc::c_int) as isize) = in_0[1 as libc::c_int as usize];
        i += 2 as libc::c_int;
    }
}
unsafe extern "C" fn BF_cfb64_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut length: size_t,
    mut schedule: *const BF_KEY,
    mut ivec: *mut uint8_t,
    mut num: *mut libc::c_int,
    mut encrypt: libc::c_int,
) {
    let mut v0: uint32_t = 0;
    let mut v1: uint32_t = 0;
    let mut t: uint32_t = 0;
    let mut n: libc::c_int = *num;
    let mut l: size_t = length;
    let mut ti: [uint32_t; 2] = [0; 2];
    let mut c: uint8_t = 0;
    let mut cc: uint8_t = 0;
    let mut iv: *mut uint8_t = ivec;
    if encrypt != 0 {
        loop {
            let fresh100 = l;
            l = l.wrapping_sub(1);
            if !(fresh100 != 0) {
                break;
            }
            if n == 0 as libc::c_int {
                let fresh101 = iv;
                iv = iv.offset(1);
                v0 = (*fresh101 as uint32_t) << 24 as libc::c_long;
                let fresh102 = iv;
                iv = iv.offset(1);
                v0 |= (*fresh102 as uint32_t) << 16 as libc::c_long;
                let fresh103 = iv;
                iv = iv.offset(1);
                v0 |= (*fresh103 as uint32_t) << 8 as libc::c_long;
                let fresh104 = iv;
                iv = iv.offset(1);
                v0 |= *fresh104 as uint32_t;
                ti[0 as libc::c_int as usize] = v0;
                let fresh105 = iv;
                iv = iv.offset(1);
                v1 = (*fresh105 as uint32_t) << 24 as libc::c_long;
                let fresh106 = iv;
                iv = iv.offset(1);
                v1 |= (*fresh106 as uint32_t) << 16 as libc::c_long;
                let fresh107 = iv;
                iv = iv.offset(1);
                v1 |= (*fresh107 as uint32_t) << 8 as libc::c_long;
                let fresh108 = iv;
                iv = iv.offset(1);
                v1 |= *fresh108 as uint32_t;
                ti[1 as libc::c_int as usize] = v1;
                BF_encrypt(ti.as_mut_ptr(), schedule);
                iv = ivec;
                t = ti[0 as libc::c_int as usize];
                let fresh109 = iv;
                iv = iv.offset(1);
                *fresh109 = (t >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                    as libc::c_uchar;
                let fresh110 = iv;
                iv = iv.offset(1);
                *fresh110 = (t >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                    as libc::c_uchar;
                let fresh111 = iv;
                iv = iv.offset(1);
                *fresh111 = (t >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                    as libc::c_uchar;
                let fresh112 = iv;
                iv = iv.offset(1);
                *fresh112 = (t & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
                t = ti[1 as libc::c_int as usize];
                let fresh113 = iv;
                iv = iv.offset(1);
                *fresh113 = (t >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                    as libc::c_uchar;
                let fresh114 = iv;
                iv = iv.offset(1);
                *fresh114 = (t >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                    as libc::c_uchar;
                let fresh115 = iv;
                iv = iv.offset(1);
                *fresh115 = (t >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                    as libc::c_uchar;
                let fresh116 = iv;
                iv = iv.offset(1);
                *fresh116 = (t & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
                iv = ivec;
            }
            let fresh117 = in_0;
            in_0 = in_0.offset(1);
            c = (*fresh117 as libc::c_int ^ *iv.offset(n as isize) as libc::c_int)
                as uint8_t;
            let fresh118 = out;
            out = out.offset(1);
            *fresh118 = c;
            *iv.offset(n as isize) = c;
            n = n + 1 as libc::c_int & 0x7 as libc::c_int;
        }
    } else {
        loop {
            let fresh119 = l;
            l = l.wrapping_sub(1);
            if !(fresh119 != 0) {
                break;
            }
            if n == 0 as libc::c_int {
                let fresh120 = iv;
                iv = iv.offset(1);
                v0 = (*fresh120 as uint32_t) << 24 as libc::c_long;
                let fresh121 = iv;
                iv = iv.offset(1);
                v0 |= (*fresh121 as uint32_t) << 16 as libc::c_long;
                let fresh122 = iv;
                iv = iv.offset(1);
                v0 |= (*fresh122 as uint32_t) << 8 as libc::c_long;
                let fresh123 = iv;
                iv = iv.offset(1);
                v0 |= *fresh123 as uint32_t;
                ti[0 as libc::c_int as usize] = v0;
                let fresh124 = iv;
                iv = iv.offset(1);
                v1 = (*fresh124 as uint32_t) << 24 as libc::c_long;
                let fresh125 = iv;
                iv = iv.offset(1);
                v1 |= (*fresh125 as uint32_t) << 16 as libc::c_long;
                let fresh126 = iv;
                iv = iv.offset(1);
                v1 |= (*fresh126 as uint32_t) << 8 as libc::c_long;
                let fresh127 = iv;
                iv = iv.offset(1);
                v1 |= *fresh127 as uint32_t;
                ti[1 as libc::c_int as usize] = v1;
                BF_encrypt(ti.as_mut_ptr(), schedule);
                iv = ivec;
                t = ti[0 as libc::c_int as usize];
                let fresh128 = iv;
                iv = iv.offset(1);
                *fresh128 = (t >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                    as libc::c_uchar;
                let fresh129 = iv;
                iv = iv.offset(1);
                *fresh129 = (t >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                    as libc::c_uchar;
                let fresh130 = iv;
                iv = iv.offset(1);
                *fresh130 = (t >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                    as libc::c_uchar;
                let fresh131 = iv;
                iv = iv.offset(1);
                *fresh131 = (t & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
                t = ti[1 as libc::c_int as usize];
                let fresh132 = iv;
                iv = iv.offset(1);
                *fresh132 = (t >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                    as libc::c_uchar;
                let fresh133 = iv;
                iv = iv.offset(1);
                *fresh133 = (t >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                    as libc::c_uchar;
                let fresh134 = iv;
                iv = iv.offset(1);
                *fresh134 = (t >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                    as libc::c_uchar;
                let fresh135 = iv;
                iv = iv.offset(1);
                *fresh135 = (t & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
                iv = ivec;
            }
            let fresh136 = in_0;
            in_0 = in_0.offset(1);
            cc = *fresh136;
            c = *iv.offset(n as isize);
            *iv.offset(n as isize) = cc;
            let fresh137 = out;
            out = out.offset(1);
            *fresh137 = (c as libc::c_int ^ cc as libc::c_int) as uint8_t;
            n = n + 1 as libc::c_int & 0x7 as libc::c_int;
        }
    }
    *num = n;
}
unsafe extern "C" fn bf_init_key(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut key: *const uint8_t,
    mut iv: *const uint8_t,
    mut enc: libc::c_int,
) -> libc::c_int {
    let mut bf_key: *mut BF_KEY = (*ctx).cipher_data as *mut BF_KEY;
    BF_set_key(bf_key, (*ctx).key_len as size_t, key);
    return 1 as libc::c_int;
}
unsafe extern "C" fn bf_ecb_cipher(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut bf_key: *mut BF_KEY = (*ctx).cipher_data as *mut BF_KEY;
    while len >= 8 as libc::c_int as size_t {
        BF_ecb_encrypt(in_0, out, bf_key, (*ctx).encrypt);
        in_0 = in_0.offset(8 as libc::c_int as isize);
        out = out.offset(8 as libc::c_int as isize);
        len = len.wrapping_sub(8 as libc::c_int as size_t);
    }
    if len == 0 as libc::c_int as size_t {} else {
        __assert_fail(
            b"len == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/blowfish/blowfish.c\0"
                as *const u8 as *const libc::c_char,
            580 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 72],
                &[libc::c_char; 72],
            >(
                b"int bf_ecb_cipher(EVP_CIPHER_CTX *, uint8_t *, const uint8_t *, size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_9063: {
        if len == 0 as libc::c_int as size_t {} else {
            __assert_fail(
                b"len == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/blowfish/blowfish.c\0"
                    as *const u8 as *const libc::c_char,
                580 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 72],
                    &[libc::c_char; 72],
                >(
                    b"int bf_ecb_cipher(EVP_CIPHER_CTX *, uint8_t *, const uint8_t *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    return 1 as libc::c_int;
}
unsafe extern "C" fn bf_cbc_cipher(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut bf_key: *mut BF_KEY = (*ctx).cipher_data as *mut BF_KEY;
    BF_cbc_encrypt(in_0, out, len, bf_key, ((*ctx).iv).as_mut_ptr(), (*ctx).encrypt);
    return 1 as libc::c_int;
}
unsafe extern "C" fn bf_cfb_cipher(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut bf_key: *mut BF_KEY = (*ctx).cipher_data as *mut BF_KEY;
    let mut num: libc::c_int = (*ctx).num as libc::c_int;
    BF_cfb64_encrypt(
        in_0,
        out,
        len,
        bf_key,
        ((*ctx).iv).as_mut_ptr(),
        &mut num,
        (*ctx).encrypt,
    );
    (*ctx).num = num as libc::c_uint;
    return 1 as libc::c_int;
}
static mut bf_ecb: EVP_CIPHER = unsafe {
    {
        let mut init = evp_cipher_st {
            nid: 92 as libc::c_int,
            block_size: 8 as libc::c_int as libc::c_uint,
            key_len: 16 as libc::c_int as libc::c_uint,
            iv_len: 8 as libc::c_int as libc::c_uint,
            ctx_size: ::core::mem::size_of::<BF_KEY>() as libc::c_ulong as libc::c_uint,
            flags: (0x1 as libc::c_int | 0x40 as libc::c_int) as uint32_t,
            init: Some(
                bf_init_key
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *const uint8_t,
                        *const uint8_t,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            cipher: Some(
                bf_ecb_cipher
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *mut uint8_t,
                        *const uint8_t,
                        size_t,
                    ) -> libc::c_int,
            ),
            cleanup: None,
            ctrl: None,
        };
        init
    }
};
static mut bf_cbc: EVP_CIPHER = unsafe {
    {
        let mut init = evp_cipher_st {
            nid: 91 as libc::c_int,
            block_size: 8 as libc::c_int as libc::c_uint,
            key_len: 16 as libc::c_int as libc::c_uint,
            iv_len: 8 as libc::c_int as libc::c_uint,
            ctx_size: ::core::mem::size_of::<BF_KEY>() as libc::c_ulong as libc::c_uint,
            flags: (0x2 as libc::c_int | 0x40 as libc::c_int) as uint32_t,
            init: Some(
                bf_init_key
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *const uint8_t,
                        *const uint8_t,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            cipher: Some(
                bf_cbc_cipher
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *mut uint8_t,
                        *const uint8_t,
                        size_t,
                    ) -> libc::c_int,
            ),
            cleanup: None,
            ctrl: None,
        };
        init
    }
};
static mut bf_cfb: EVP_CIPHER = unsafe {
    {
        let mut init = evp_cipher_st {
            nid: 93 as libc::c_int,
            block_size: 1 as libc::c_int as libc::c_uint,
            key_len: 16 as libc::c_int as libc::c_uint,
            iv_len: 8 as libc::c_int as libc::c_uint,
            ctx_size: ::core::mem::size_of::<BF_KEY>() as libc::c_ulong as libc::c_uint,
            flags: (0x3 as libc::c_int | 0x40 as libc::c_int) as uint32_t,
            init: Some(
                bf_init_key
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *const uint8_t,
                        *const uint8_t,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            cipher: Some(
                bf_cfb_cipher
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *mut uint8_t,
                        *const uint8_t,
                        size_t,
                    ) -> libc::c_int,
            ),
            cleanup: None,
            ctrl: None,
        };
        init
    }
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_bf_ecb() -> *const EVP_CIPHER {
    return &bf_ecb;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_bf_cbc() -> *const EVP_CIPHER {
    return &bf_cbc;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_bf_cfb() -> *const EVP_CIPHER {
    return &bf_cfb;
}
