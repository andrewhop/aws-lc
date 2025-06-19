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
    static CAST_S_table0: [uint32_t; 256];
    static CAST_S_table1: [uint32_t; 256];
    static CAST_S_table2: [uint32_t; 256];
    static CAST_S_table3: [uint32_t; 256];
    static CAST_S_table4: [uint32_t; 256];
    static CAST_S_table5: [uint32_t; 256];
    static CAST_S_table6: [uint32_t; 256];
    static CAST_S_table7: [uint32_t; 256];
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cast_key_st {
    pub data: [uint32_t; 32],
    pub short_key: libc::c_int,
}
pub type CAST_KEY = cast_key_st;
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CAST_ecb_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut ks: *const CAST_KEY,
    mut enc: libc::c_int,
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
    if enc != 0 {
        CAST_encrypt(d.as_mut_ptr(), ks);
    } else {
        CAST_decrypt(d.as_mut_ptr(), ks);
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
pub unsafe extern "C" fn CAST_encrypt(
    mut data: *mut uint32_t,
    mut key: *const CAST_KEY,
) {
    let mut l: uint32_t = 0;
    let mut r: uint32_t = 0;
    let mut t: uint32_t = 0;
    let mut k: *const uint32_t = 0 as *const uint32_t;
    k = &*((*key).data).as_ptr().offset(0 as libc::c_int as isize) as *const uint32_t;
    l = *data.offset(0 as libc::c_int as isize);
    r = *data.offset(1 as libc::c_int as isize);
    let mut a: uint32_t = 0;
    let mut b: uint32_t = 0;
    let mut c: uint32_t = 0;
    let mut d: uint32_t = 0;
    t = (*k.offset((0 as libc::c_int * 2 as libc::c_int) as isize)).wrapping_add(r)
        & 0xffffffff as libc::c_uint;
    t = ((t
        << *k.offset((0 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize)
        | t
            >> ((*k
                .offset(
                    (0 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                ))
                .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
        & 0xffffffff as libc::c_long) as uint32_t;
    a = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    b = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
    c = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    d = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    l = (l as libc::c_long
        ^ (((a ^ b) as libc::c_long & 0xffffffff as libc::c_long) - c as libc::c_long
            & 0xffffffff as libc::c_long) + d as libc::c_long
            & 0xffffffff as libc::c_long) as uint32_t;
    let mut a_0: uint32_t = 0;
    let mut b_0: uint32_t = 0;
    let mut c_0: uint32_t = 0;
    let mut d_0: uint32_t = 0;
    t = (*k.offset((1 as libc::c_int * 2 as libc::c_int) as isize) ^ l)
        & 0xffffffff as libc::c_uint;
    t = ((t
        << *k.offset((1 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize)
        | t
            >> ((*k
                .offset(
                    (1 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                ))
                .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
        & 0xffffffff as libc::c_long) as uint32_t;
    a_0 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    b_0 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
    c_0 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    d_0 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    r = (r as libc::c_long
        ^ ((a_0.wrapping_sub(b_0) as libc::c_long & 0xffffffff as libc::c_long)
            + c_0 as libc::c_long & 0xffffffff as libc::c_long ^ d_0 as libc::c_long)
            & 0xffffffff as libc::c_long) as uint32_t;
    let mut a_1: uint32_t = 0;
    let mut b_1: uint32_t = 0;
    let mut c_1: uint32_t = 0;
    let mut d_1: uint32_t = 0;
    t = (*k.offset((2 as libc::c_int * 2 as libc::c_int) as isize)).wrapping_sub(r)
        & 0xffffffff as libc::c_uint;
    t = ((t
        << *k.offset((2 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize)
        | t
            >> ((*k
                .offset(
                    (2 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                ))
                .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
        & 0xffffffff as libc::c_long) as uint32_t;
    a_1 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    b_1 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
    c_1 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    d_1 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    l = (l as libc::c_long
        ^ ((a_1.wrapping_add(b_1) as libc::c_long & 0xffffffff as libc::c_long
            ^ c_1 as libc::c_long) & 0xffffffff as libc::c_long) - d_1 as libc::c_long
            & 0xffffffff as libc::c_long) as uint32_t;
    let mut a_2: uint32_t = 0;
    let mut b_2: uint32_t = 0;
    let mut c_2: uint32_t = 0;
    let mut d_2: uint32_t = 0;
    t = (*k.offset((3 as libc::c_int * 2 as libc::c_int) as isize)).wrapping_add(l)
        & 0xffffffff as libc::c_uint;
    t = ((t
        << *k.offset((3 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize)
        | t
            >> ((*k
                .offset(
                    (3 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                ))
                .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
        & 0xffffffff as libc::c_long) as uint32_t;
    a_2 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    b_2 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
    c_2 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    d_2 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    r = (r as libc::c_long
        ^ (((a_2 ^ b_2) as libc::c_long & 0xffffffff as libc::c_long)
            - c_2 as libc::c_long & 0xffffffff as libc::c_long) + d_2 as libc::c_long
            & 0xffffffff as libc::c_long) as uint32_t;
    let mut a_3: uint32_t = 0;
    let mut b_3: uint32_t = 0;
    let mut c_3: uint32_t = 0;
    let mut d_3: uint32_t = 0;
    t = (*k.offset((4 as libc::c_int * 2 as libc::c_int) as isize) ^ r)
        & 0xffffffff as libc::c_uint;
    t = ((t
        << *k.offset((4 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize)
        | t
            >> ((*k
                .offset(
                    (4 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                ))
                .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
        & 0xffffffff as libc::c_long) as uint32_t;
    a_3 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    b_3 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
    c_3 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    d_3 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    l = (l as libc::c_long
        ^ ((a_3.wrapping_sub(b_3) as libc::c_long & 0xffffffff as libc::c_long)
            + c_3 as libc::c_long & 0xffffffff as libc::c_long ^ d_3 as libc::c_long)
            & 0xffffffff as libc::c_long) as uint32_t;
    let mut a_4: uint32_t = 0;
    let mut b_4: uint32_t = 0;
    let mut c_4: uint32_t = 0;
    let mut d_4: uint32_t = 0;
    t = (*k.offset((5 as libc::c_int * 2 as libc::c_int) as isize)).wrapping_sub(l)
        & 0xffffffff as libc::c_uint;
    t = ((t
        << *k.offset((5 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize)
        | t
            >> ((*k
                .offset(
                    (5 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                ))
                .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
        & 0xffffffff as libc::c_long) as uint32_t;
    a_4 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    b_4 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
    c_4 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    d_4 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    r = (r as libc::c_long
        ^ ((a_4.wrapping_add(b_4) as libc::c_long & 0xffffffff as libc::c_long
            ^ c_4 as libc::c_long) & 0xffffffff as libc::c_long) - d_4 as libc::c_long
            & 0xffffffff as libc::c_long) as uint32_t;
    let mut a_5: uint32_t = 0;
    let mut b_5: uint32_t = 0;
    let mut c_5: uint32_t = 0;
    let mut d_5: uint32_t = 0;
    t = (*k.offset((6 as libc::c_int * 2 as libc::c_int) as isize)).wrapping_add(r)
        & 0xffffffff as libc::c_uint;
    t = ((t
        << *k.offset((6 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize)
        | t
            >> ((*k
                .offset(
                    (6 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                ))
                .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
        & 0xffffffff as libc::c_long) as uint32_t;
    a_5 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    b_5 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
    c_5 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    d_5 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    l = (l as libc::c_long
        ^ (((a_5 ^ b_5) as libc::c_long & 0xffffffff as libc::c_long)
            - c_5 as libc::c_long & 0xffffffff as libc::c_long) + d_5 as libc::c_long
            & 0xffffffff as libc::c_long) as uint32_t;
    let mut a_6: uint32_t = 0;
    let mut b_6: uint32_t = 0;
    let mut c_6: uint32_t = 0;
    let mut d_6: uint32_t = 0;
    t = (*k.offset((7 as libc::c_int * 2 as libc::c_int) as isize) ^ l)
        & 0xffffffff as libc::c_uint;
    t = ((t
        << *k.offset((7 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize)
        | t
            >> ((*k
                .offset(
                    (7 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                ))
                .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
        & 0xffffffff as libc::c_long) as uint32_t;
    a_6 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    b_6 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
    c_6 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    d_6 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    r = (r as libc::c_long
        ^ ((a_6.wrapping_sub(b_6) as libc::c_long & 0xffffffff as libc::c_long)
            + c_6 as libc::c_long & 0xffffffff as libc::c_long ^ d_6 as libc::c_long)
            & 0xffffffff as libc::c_long) as uint32_t;
    let mut a_7: uint32_t = 0;
    let mut b_7: uint32_t = 0;
    let mut c_7: uint32_t = 0;
    let mut d_7: uint32_t = 0;
    t = (*k.offset((8 as libc::c_int * 2 as libc::c_int) as isize)).wrapping_sub(r)
        & 0xffffffff as libc::c_uint;
    t = ((t
        << *k.offset((8 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize)
        | t
            >> ((*k
                .offset(
                    (8 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                ))
                .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
        & 0xffffffff as libc::c_long) as uint32_t;
    a_7 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    b_7 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
    c_7 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    d_7 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    l = (l as libc::c_long
        ^ ((a_7.wrapping_add(b_7) as libc::c_long & 0xffffffff as libc::c_long
            ^ c_7 as libc::c_long) & 0xffffffff as libc::c_long) - d_7 as libc::c_long
            & 0xffffffff as libc::c_long) as uint32_t;
    let mut a_8: uint32_t = 0;
    let mut b_8: uint32_t = 0;
    let mut c_8: uint32_t = 0;
    let mut d_8: uint32_t = 0;
    t = (*k.offset((9 as libc::c_int * 2 as libc::c_int) as isize)).wrapping_add(l)
        & 0xffffffff as libc::c_uint;
    t = ((t
        << *k.offset((9 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize)
        | t
            >> ((*k
                .offset(
                    (9 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                ))
                .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
        & 0xffffffff as libc::c_long) as uint32_t;
    a_8 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    b_8 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
    c_8 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    d_8 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    r = (r as libc::c_long
        ^ (((a_8 ^ b_8) as libc::c_long & 0xffffffff as libc::c_long)
            - c_8 as libc::c_long & 0xffffffff as libc::c_long) + d_8 as libc::c_long
            & 0xffffffff as libc::c_long) as uint32_t;
    let mut a_9: uint32_t = 0;
    let mut b_9: uint32_t = 0;
    let mut c_9: uint32_t = 0;
    let mut d_9: uint32_t = 0;
    t = (*k.offset((10 as libc::c_int * 2 as libc::c_int) as isize) ^ r)
        & 0xffffffff as libc::c_uint;
    t = ((t
        << *k.offset((10 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize)
        | t
            >> ((*k
                .offset(
                    (10 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                ))
                .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
        & 0xffffffff as libc::c_long) as uint32_t;
    a_9 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    b_9 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
    c_9 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    d_9 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    l = (l as libc::c_long
        ^ ((a_9.wrapping_sub(b_9) as libc::c_long & 0xffffffff as libc::c_long)
            + c_9 as libc::c_long & 0xffffffff as libc::c_long ^ d_9 as libc::c_long)
            & 0xffffffff as libc::c_long) as uint32_t;
    let mut a_10: uint32_t = 0;
    let mut b_10: uint32_t = 0;
    let mut c_10: uint32_t = 0;
    let mut d_10: uint32_t = 0;
    t = (*k.offset((11 as libc::c_int * 2 as libc::c_int) as isize)).wrapping_sub(l)
        & 0xffffffff as libc::c_uint;
    t = ((t
        << *k.offset((11 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize)
        | t
            >> ((*k
                .offset(
                    (11 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                ))
                .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
        & 0xffffffff as libc::c_long) as uint32_t;
    a_10 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    b_10 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
    c_10 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    d_10 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    r = (r as libc::c_long
        ^ ((a_10.wrapping_add(b_10) as libc::c_long & 0xffffffff as libc::c_long
            ^ c_10 as libc::c_long) & 0xffffffff as libc::c_long) - d_10 as libc::c_long
            & 0xffffffff as libc::c_long) as uint32_t;
    if (*key).short_key == 0 {
        let mut a_11: uint32_t = 0;
        let mut b_11: uint32_t = 0;
        let mut c_11: uint32_t = 0;
        let mut d_11: uint32_t = 0;
        t = (*k.offset((12 as libc::c_int * 2 as libc::c_int) as isize)).wrapping_add(r)
            & 0xffffffff as libc::c_uint;
        t = ((t
            << *k
                .offset(
                    (12 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                )
            | t
                >> ((*k
                    .offset(
                        (12 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int)
                            as isize,
                    ))
                    .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
            & 0xffffffff as libc::c_long) as uint32_t;
        a_11 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
            as usize];
        b_11 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
        c_11 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
            as usize];
        d_11 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
            as usize];
        l = (l as libc::c_long
            ^ (((a_11 ^ b_11) as libc::c_long & 0xffffffff as libc::c_long)
                - c_11 as libc::c_long & 0xffffffff as libc::c_long)
                + d_11 as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
        let mut a_12: uint32_t = 0;
        let mut b_12: uint32_t = 0;
        let mut c_12: uint32_t = 0;
        let mut d_12: uint32_t = 0;
        t = (*k.offset((13 as libc::c_int * 2 as libc::c_int) as isize) ^ l)
            & 0xffffffff as libc::c_uint;
        t = ((t
            << *k
                .offset(
                    (13 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                )
            | t
                >> ((*k
                    .offset(
                        (13 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int)
                            as isize,
                    ))
                    .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
            & 0xffffffff as libc::c_long) as uint32_t;
        a_12 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
            as usize];
        b_12 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
        c_12 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
            as usize];
        d_12 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
            as usize];
        r = (r as libc::c_long
            ^ ((a_12.wrapping_sub(b_12) as libc::c_long & 0xffffffff as libc::c_long)
                + c_12 as libc::c_long & 0xffffffff as libc::c_long
                ^ d_12 as libc::c_long) & 0xffffffff as libc::c_long) as uint32_t;
        let mut a_13: uint32_t = 0;
        let mut b_13: uint32_t = 0;
        let mut c_13: uint32_t = 0;
        let mut d_13: uint32_t = 0;
        t = (*k.offset((14 as libc::c_int * 2 as libc::c_int) as isize)).wrapping_sub(r)
            & 0xffffffff as libc::c_uint;
        t = ((t
            << *k
                .offset(
                    (14 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                )
            | t
                >> ((*k
                    .offset(
                        (14 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int)
                            as isize,
                    ))
                    .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
            & 0xffffffff as libc::c_long) as uint32_t;
        a_13 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
            as usize];
        b_13 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
        c_13 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
            as usize];
        d_13 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
            as usize];
        l = (l as libc::c_long
            ^ ((a_13.wrapping_add(b_13) as libc::c_long & 0xffffffff as libc::c_long
                ^ c_13 as libc::c_long) & 0xffffffff as libc::c_long)
                - d_13 as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
        let mut a_14: uint32_t = 0;
        let mut b_14: uint32_t = 0;
        let mut c_14: uint32_t = 0;
        let mut d_14: uint32_t = 0;
        t = (*k.offset((15 as libc::c_int * 2 as libc::c_int) as isize)).wrapping_add(l)
            & 0xffffffff as libc::c_uint;
        t = ((t
            << *k
                .offset(
                    (15 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                )
            | t
                >> ((*k
                    .offset(
                        (15 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int)
                            as isize,
                    ))
                    .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
            & 0xffffffff as libc::c_long) as uint32_t;
        a_14 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
            as usize];
        b_14 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
        c_14 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
            as usize];
        d_14 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
            as usize];
        r = (r as libc::c_long
            ^ (((a_14 ^ b_14) as libc::c_long & 0xffffffff as libc::c_long)
                - c_14 as libc::c_long & 0xffffffff as libc::c_long)
                + d_14 as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
    }
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
pub unsafe extern "C" fn CAST_decrypt(
    mut data: *mut uint32_t,
    mut key: *const CAST_KEY,
) {
    let mut l: uint32_t = 0;
    let mut r: uint32_t = 0;
    let mut t: uint32_t = 0;
    let mut k: *const uint32_t = 0 as *const uint32_t;
    k = &*((*key).data).as_ptr().offset(0 as libc::c_int as isize) as *const uint32_t;
    l = *data.offset(0 as libc::c_int as isize);
    r = *data.offset(1 as libc::c_int as isize);
    if (*key).short_key == 0 {
        let mut a: uint32_t = 0;
        let mut b: uint32_t = 0;
        let mut c: uint32_t = 0;
        let mut d: uint32_t = 0;
        t = (*k.offset((15 as libc::c_int * 2 as libc::c_int) as isize)).wrapping_add(r)
            & 0xffffffff as libc::c_uint;
        t = ((t
            << *k
                .offset(
                    (15 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                )
            | t
                >> ((*k
                    .offset(
                        (15 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int)
                            as isize,
                    ))
                    .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
            & 0xffffffff as libc::c_long) as uint32_t;
        a = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
            as usize];
        b = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
        c = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
            as usize];
        d = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
            as usize];
        l = (l as libc::c_long
            ^ (((a ^ b) as libc::c_long & 0xffffffff as libc::c_long) - c as libc::c_long
                & 0xffffffff as libc::c_long) + d as libc::c_long
                & 0xffffffff as libc::c_long) as uint32_t;
        let mut a_0: uint32_t = 0;
        let mut b_0: uint32_t = 0;
        let mut c_0: uint32_t = 0;
        let mut d_0: uint32_t = 0;
        t = (*k.offset((14 as libc::c_int * 2 as libc::c_int) as isize)).wrapping_sub(l)
            & 0xffffffff as libc::c_uint;
        t = ((t
            << *k
                .offset(
                    (14 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                )
            | t
                >> ((*k
                    .offset(
                        (14 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int)
                            as isize,
                    ))
                    .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
            & 0xffffffff as libc::c_long) as uint32_t;
        a_0 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
            as usize];
        b_0 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
        c_0 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
            as usize];
        d_0 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
            as usize];
        r = (r as libc::c_long
            ^ ((a_0.wrapping_add(b_0) as libc::c_long & 0xffffffff as libc::c_long
                ^ c_0 as libc::c_long) & 0xffffffff as libc::c_long)
                - d_0 as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
        let mut a_1: uint32_t = 0;
        let mut b_1: uint32_t = 0;
        let mut c_1: uint32_t = 0;
        let mut d_1: uint32_t = 0;
        t = (*k.offset((13 as libc::c_int * 2 as libc::c_int) as isize) ^ r)
            & 0xffffffff as libc::c_uint;
        t = ((t
            << *k
                .offset(
                    (13 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                )
            | t
                >> ((*k
                    .offset(
                        (13 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int)
                            as isize,
                    ))
                    .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
            & 0xffffffff as libc::c_long) as uint32_t;
        a_1 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
            as usize];
        b_1 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
        c_1 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
            as usize];
        d_1 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
            as usize];
        l = (l as libc::c_long
            ^ ((a_1.wrapping_sub(b_1) as libc::c_long & 0xffffffff as libc::c_long)
                + c_1 as libc::c_long & 0xffffffff as libc::c_long ^ d_1 as libc::c_long)
                & 0xffffffff as libc::c_long) as uint32_t;
        let mut a_2: uint32_t = 0;
        let mut b_2: uint32_t = 0;
        let mut c_2: uint32_t = 0;
        let mut d_2: uint32_t = 0;
        t = (*k.offset((12 as libc::c_int * 2 as libc::c_int) as isize)).wrapping_add(l)
            & 0xffffffff as libc::c_uint;
        t = ((t
            << *k
                .offset(
                    (12 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                )
            | t
                >> ((*k
                    .offset(
                        (12 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int)
                            as isize,
                    ))
                    .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
            & 0xffffffff as libc::c_long) as uint32_t;
        a_2 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
            as usize];
        b_2 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
        c_2 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
            as usize];
        d_2 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
            as usize];
        r = (r as libc::c_long
            ^ (((a_2 ^ b_2) as libc::c_long & 0xffffffff as libc::c_long)
                - c_2 as libc::c_long & 0xffffffff as libc::c_long) + d_2 as libc::c_long
                & 0xffffffff as libc::c_long) as uint32_t;
    }
    let mut a_3: uint32_t = 0;
    let mut b_3: uint32_t = 0;
    let mut c_3: uint32_t = 0;
    let mut d_3: uint32_t = 0;
    t = (*k.offset((11 as libc::c_int * 2 as libc::c_int) as isize)).wrapping_sub(r)
        & 0xffffffff as libc::c_uint;
    t = ((t
        << *k.offset((11 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize)
        | t
            >> ((*k
                .offset(
                    (11 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                ))
                .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
        & 0xffffffff as libc::c_long) as uint32_t;
    a_3 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    b_3 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
    c_3 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    d_3 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    l = (l as libc::c_long
        ^ ((a_3.wrapping_add(b_3) as libc::c_long & 0xffffffff as libc::c_long
            ^ c_3 as libc::c_long) & 0xffffffff as libc::c_long) - d_3 as libc::c_long
            & 0xffffffff as libc::c_long) as uint32_t;
    let mut a_4: uint32_t = 0;
    let mut b_4: uint32_t = 0;
    let mut c_4: uint32_t = 0;
    let mut d_4: uint32_t = 0;
    t = (*k.offset((10 as libc::c_int * 2 as libc::c_int) as isize) ^ l)
        & 0xffffffff as libc::c_uint;
    t = ((t
        << *k.offset((10 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize)
        | t
            >> ((*k
                .offset(
                    (10 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                ))
                .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
        & 0xffffffff as libc::c_long) as uint32_t;
    a_4 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    b_4 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
    c_4 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    d_4 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    r = (r as libc::c_long
        ^ ((a_4.wrapping_sub(b_4) as libc::c_long & 0xffffffff as libc::c_long)
            + c_4 as libc::c_long & 0xffffffff as libc::c_long ^ d_4 as libc::c_long)
            & 0xffffffff as libc::c_long) as uint32_t;
    let mut a_5: uint32_t = 0;
    let mut b_5: uint32_t = 0;
    let mut c_5: uint32_t = 0;
    let mut d_5: uint32_t = 0;
    t = (*k.offset((9 as libc::c_int * 2 as libc::c_int) as isize)).wrapping_add(r)
        & 0xffffffff as libc::c_uint;
    t = ((t
        << *k.offset((9 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize)
        | t
            >> ((*k
                .offset(
                    (9 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                ))
                .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
        & 0xffffffff as libc::c_long) as uint32_t;
    a_5 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    b_5 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
    c_5 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    d_5 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    l = (l as libc::c_long
        ^ (((a_5 ^ b_5) as libc::c_long & 0xffffffff as libc::c_long)
            - c_5 as libc::c_long & 0xffffffff as libc::c_long) + d_5 as libc::c_long
            & 0xffffffff as libc::c_long) as uint32_t;
    let mut a_6: uint32_t = 0;
    let mut b_6: uint32_t = 0;
    let mut c_6: uint32_t = 0;
    let mut d_6: uint32_t = 0;
    t = (*k.offset((8 as libc::c_int * 2 as libc::c_int) as isize)).wrapping_sub(l)
        & 0xffffffff as libc::c_uint;
    t = ((t
        << *k.offset((8 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize)
        | t
            >> ((*k
                .offset(
                    (8 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                ))
                .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
        & 0xffffffff as libc::c_long) as uint32_t;
    a_6 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    b_6 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
    c_6 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    d_6 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    r = (r as libc::c_long
        ^ ((a_6.wrapping_add(b_6) as libc::c_long & 0xffffffff as libc::c_long
            ^ c_6 as libc::c_long) & 0xffffffff as libc::c_long) - d_6 as libc::c_long
            & 0xffffffff as libc::c_long) as uint32_t;
    let mut a_7: uint32_t = 0;
    let mut b_7: uint32_t = 0;
    let mut c_7: uint32_t = 0;
    let mut d_7: uint32_t = 0;
    t = (*k.offset((7 as libc::c_int * 2 as libc::c_int) as isize) ^ r)
        & 0xffffffff as libc::c_uint;
    t = ((t
        << *k.offset((7 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize)
        | t
            >> ((*k
                .offset(
                    (7 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                ))
                .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
        & 0xffffffff as libc::c_long) as uint32_t;
    a_7 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    b_7 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
    c_7 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    d_7 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    l = (l as libc::c_long
        ^ ((a_7.wrapping_sub(b_7) as libc::c_long & 0xffffffff as libc::c_long)
            + c_7 as libc::c_long & 0xffffffff as libc::c_long ^ d_7 as libc::c_long)
            & 0xffffffff as libc::c_long) as uint32_t;
    let mut a_8: uint32_t = 0;
    let mut b_8: uint32_t = 0;
    let mut c_8: uint32_t = 0;
    let mut d_8: uint32_t = 0;
    t = (*k.offset((6 as libc::c_int * 2 as libc::c_int) as isize)).wrapping_add(l)
        & 0xffffffff as libc::c_uint;
    t = ((t
        << *k.offset((6 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize)
        | t
            >> ((*k
                .offset(
                    (6 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                ))
                .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
        & 0xffffffff as libc::c_long) as uint32_t;
    a_8 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    b_8 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
    c_8 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    d_8 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    r = (r as libc::c_long
        ^ (((a_8 ^ b_8) as libc::c_long & 0xffffffff as libc::c_long)
            - c_8 as libc::c_long & 0xffffffff as libc::c_long) + d_8 as libc::c_long
            & 0xffffffff as libc::c_long) as uint32_t;
    let mut a_9: uint32_t = 0;
    let mut b_9: uint32_t = 0;
    let mut c_9: uint32_t = 0;
    let mut d_9: uint32_t = 0;
    t = (*k.offset((5 as libc::c_int * 2 as libc::c_int) as isize)).wrapping_sub(r)
        & 0xffffffff as libc::c_uint;
    t = ((t
        << *k.offset((5 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize)
        | t
            >> ((*k
                .offset(
                    (5 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                ))
                .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
        & 0xffffffff as libc::c_long) as uint32_t;
    a_9 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    b_9 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
    c_9 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    d_9 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    l = (l as libc::c_long
        ^ ((a_9.wrapping_add(b_9) as libc::c_long & 0xffffffff as libc::c_long
            ^ c_9 as libc::c_long) & 0xffffffff as libc::c_long) - d_9 as libc::c_long
            & 0xffffffff as libc::c_long) as uint32_t;
    let mut a_10: uint32_t = 0;
    let mut b_10: uint32_t = 0;
    let mut c_10: uint32_t = 0;
    let mut d_10: uint32_t = 0;
    t = (*k.offset((4 as libc::c_int * 2 as libc::c_int) as isize) ^ l)
        & 0xffffffff as libc::c_uint;
    t = ((t
        << *k.offset((4 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize)
        | t
            >> ((*k
                .offset(
                    (4 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                ))
                .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
        & 0xffffffff as libc::c_long) as uint32_t;
    a_10 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    b_10 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
    c_10 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    d_10 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    r = (r as libc::c_long
        ^ ((a_10.wrapping_sub(b_10) as libc::c_long & 0xffffffff as libc::c_long)
            + c_10 as libc::c_long & 0xffffffff as libc::c_long ^ d_10 as libc::c_long)
            & 0xffffffff as libc::c_long) as uint32_t;
    let mut a_11: uint32_t = 0;
    let mut b_11: uint32_t = 0;
    let mut c_11: uint32_t = 0;
    let mut d_11: uint32_t = 0;
    t = (*k.offset((3 as libc::c_int * 2 as libc::c_int) as isize)).wrapping_add(r)
        & 0xffffffff as libc::c_uint;
    t = ((t
        << *k.offset((3 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize)
        | t
            >> ((*k
                .offset(
                    (3 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                ))
                .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
        & 0xffffffff as libc::c_long) as uint32_t;
    a_11 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    b_11 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
    c_11 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    d_11 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    l = (l as libc::c_long
        ^ (((a_11 ^ b_11) as libc::c_long & 0xffffffff as libc::c_long)
            - c_11 as libc::c_long & 0xffffffff as libc::c_long) + d_11 as libc::c_long
            & 0xffffffff as libc::c_long) as uint32_t;
    let mut a_12: uint32_t = 0;
    let mut b_12: uint32_t = 0;
    let mut c_12: uint32_t = 0;
    let mut d_12: uint32_t = 0;
    t = (*k.offset((2 as libc::c_int * 2 as libc::c_int) as isize)).wrapping_sub(l)
        & 0xffffffff as libc::c_uint;
    t = ((t
        << *k.offset((2 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize)
        | t
            >> ((*k
                .offset(
                    (2 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                ))
                .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
        & 0xffffffff as libc::c_long) as uint32_t;
    a_12 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    b_12 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
    c_12 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    d_12 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    r = (r as libc::c_long
        ^ ((a_12.wrapping_add(b_12) as libc::c_long & 0xffffffff as libc::c_long
            ^ c_12 as libc::c_long) & 0xffffffff as libc::c_long) - d_12 as libc::c_long
            & 0xffffffff as libc::c_long) as uint32_t;
    let mut a_13: uint32_t = 0;
    let mut b_13: uint32_t = 0;
    let mut c_13: uint32_t = 0;
    let mut d_13: uint32_t = 0;
    t = (*k.offset((1 as libc::c_int * 2 as libc::c_int) as isize) ^ r)
        & 0xffffffff as libc::c_uint;
    t = ((t
        << *k.offset((1 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize)
        | t
            >> ((*k
                .offset(
                    (1 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                ))
                .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
        & 0xffffffff as libc::c_long) as uint32_t;
    a_13 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    b_13 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
    c_13 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    d_13 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    l = (l as libc::c_long
        ^ ((a_13.wrapping_sub(b_13) as libc::c_long & 0xffffffff as libc::c_long)
            + c_13 as libc::c_long & 0xffffffff as libc::c_long ^ d_13 as libc::c_long)
            & 0xffffffff as libc::c_long) as uint32_t;
    let mut a_14: uint32_t = 0;
    let mut b_14: uint32_t = 0;
    let mut c_14: uint32_t = 0;
    let mut d_14: uint32_t = 0;
    t = (*k.offset((0 as libc::c_int * 2 as libc::c_int) as isize)).wrapping_add(l)
        & 0xffffffff as libc::c_uint;
    t = ((t
        << *k.offset((0 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize)
        | t
            >> ((*k
                .offset(
                    (0 as libc::c_int * 2 as libc::c_int + 1 as libc::c_int) as isize,
                ))
                .wrapping_neg() & 31 as libc::c_int as uint32_t)) as libc::c_long
        & 0xffffffff as libc::c_long) as uint32_t;
    a_14 = CAST_S_table0[(t >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    b_14 = CAST_S_table1[(t & 0xff as libc::c_int as uint32_t) as usize];
    c_14 = CAST_S_table2[(t >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    d_14 = CAST_S_table3[(t >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as usize];
    r = (r as libc::c_long
        ^ (((a_14 ^ b_14) as libc::c_long & 0xffffffff as libc::c_long)
            - c_14 as libc::c_long & 0xffffffff as libc::c_long) + d_14 as libc::c_long
            & 0xffffffff as libc::c_long) as uint32_t;
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
pub unsafe extern "C" fn CAST_cbc_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut length: size_t,
    mut ks: *const CAST_KEY,
    mut iv: *mut uint8_t,
    mut enc: libc::c_int,
) {
    let mut tin0: uint32_t = 0;
    let mut tin1: uint32_t = 0;
    let mut tout0: uint32_t = 0;
    let mut tout1: uint32_t = 0;
    let mut xor0: uint32_t = 0;
    let mut xor1: uint32_t = 0;
    let mut l: size_t = length;
    let mut tin: [uint32_t; 2] = [0; 2];
    if enc != 0 {
        let fresh16 = iv;
        iv = iv.offset(1);
        tout0 = (*fresh16 as uint32_t) << 24 as libc::c_long;
        let fresh17 = iv;
        iv = iv.offset(1);
        tout0 |= (*fresh17 as uint32_t) << 16 as libc::c_long;
        let fresh18 = iv;
        iv = iv.offset(1);
        tout0 |= (*fresh18 as uint32_t) << 8 as libc::c_long;
        let fresh19 = iv;
        iv = iv.offset(1);
        tout0 |= *fresh19 as uint32_t;
        let fresh20 = iv;
        iv = iv.offset(1);
        tout1 = (*fresh20 as uint32_t) << 24 as libc::c_long;
        let fresh21 = iv;
        iv = iv.offset(1);
        tout1 |= (*fresh21 as uint32_t) << 16 as libc::c_long;
        let fresh22 = iv;
        iv = iv.offset(1);
        tout1 |= (*fresh22 as uint32_t) << 8 as libc::c_long;
        let fresh23 = iv;
        iv = iv.offset(1);
        tout1 |= *fresh23 as uint32_t;
        iv = iv.offset(-(8 as libc::c_int as isize));
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
            CAST_encrypt(tin.as_mut_ptr(), ks);
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
                    current_block_33 = 9688531613091283371;
                }
                7 => {
                    current_block_33 = 9688531613091283371;
                }
                6 => {
                    current_block_33 = 3425815108616652110;
                }
                5 => {
                    current_block_33 = 15440825804306115713;
                }
                4 => {
                    current_block_33 = 17220199905596865363;
                }
                3 => {
                    current_block_33 = 322669159951527645;
                }
                2 => {
                    current_block_33 = 13133319464457553044;
                }
                1 => {
                    current_block_33 = 9536396861727289318;
                }
                _ => {
                    current_block_33 = 1608152415753874203;
                }
            }
            match current_block_33 {
                9688531613091283371 => {
                    in_0 = in_0.offset(-1);
                    tin1 |= (*in_0 as uint32_t) << 8 as libc::c_int;
                    current_block_33 = 3425815108616652110;
                }
                _ => {}
            }
            match current_block_33 {
                3425815108616652110 => {
                    in_0 = in_0.offset(-1);
                    tin1 |= (*in_0 as uint32_t) << 16 as libc::c_int;
                    current_block_33 = 15440825804306115713;
                }
                _ => {}
            }
            match current_block_33 {
                15440825804306115713 => {
                    in_0 = in_0.offset(-1);
                    tin1 |= (*in_0 as uint32_t) << 24 as libc::c_int;
                    current_block_33 = 17220199905596865363;
                }
                _ => {}
            }
            match current_block_33 {
                17220199905596865363 => {
                    in_0 = in_0.offset(-1);
                    tin0 = *in_0 as uint32_t;
                    current_block_33 = 322669159951527645;
                }
                _ => {}
            }
            match current_block_33 {
                322669159951527645 => {
                    in_0 = in_0.offset(-1);
                    tin0 |= (*in_0 as uint32_t) << 8 as libc::c_int;
                    current_block_33 = 13133319464457553044;
                }
                _ => {}
            }
            match current_block_33 {
                13133319464457553044 => {
                    in_0 = in_0.offset(-1);
                    tin0 |= (*in_0 as uint32_t) << 16 as libc::c_int;
                    current_block_33 = 9536396861727289318;
                }
                _ => {}
            }
            match current_block_33 {
                9536396861727289318 => {
                    in_0 = in_0.offset(-1);
                    tin0 |= (*in_0 as uint32_t) << 24 as libc::c_int;
                }
                _ => {}
            }
            tin0 ^= tout0;
            tin1 ^= tout1;
            tin[0 as libc::c_int as usize] = tin0;
            tin[1 as libc::c_int as usize] = tin1;
            CAST_encrypt(tin.as_mut_ptr(), ks);
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
        let fresh48 = iv;
        iv = iv.offset(1);
        *fresh48 = (tout0 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh49 = iv;
        iv = iv.offset(1);
        *fresh49 = (tout0 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh50 = iv;
        iv = iv.offset(1);
        *fresh50 = (tout0 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh51 = iv;
        iv = iv.offset(1);
        *fresh51 = (tout0 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
        let fresh52 = iv;
        iv = iv.offset(1);
        *fresh52 = (tout1 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh53 = iv;
        iv = iv.offset(1);
        *fresh53 = (tout1 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh54 = iv;
        iv = iv.offset(1);
        *fresh54 = (tout1 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh55 = iv;
        iv = iv.offset(1);
        *fresh55 = (tout1 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
    } else {
        let fresh56 = iv;
        iv = iv.offset(1);
        xor0 = (*fresh56 as uint32_t) << 24 as libc::c_long;
        let fresh57 = iv;
        iv = iv.offset(1);
        xor0 |= (*fresh57 as uint32_t) << 16 as libc::c_long;
        let fresh58 = iv;
        iv = iv.offset(1);
        xor0 |= (*fresh58 as uint32_t) << 8 as libc::c_long;
        let fresh59 = iv;
        iv = iv.offset(1);
        xor0 |= *fresh59 as uint32_t;
        let fresh60 = iv;
        iv = iv.offset(1);
        xor1 = (*fresh60 as uint32_t) << 24 as libc::c_long;
        let fresh61 = iv;
        iv = iv.offset(1);
        xor1 |= (*fresh61 as uint32_t) << 16 as libc::c_long;
        let fresh62 = iv;
        iv = iv.offset(1);
        xor1 |= (*fresh62 as uint32_t) << 8 as libc::c_long;
        let fresh63 = iv;
        iv = iv.offset(1);
        xor1 |= *fresh63 as uint32_t;
        iv = iv.offset(-(8 as libc::c_int as isize));
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
            CAST_decrypt(tin.as_mut_ptr(), ks);
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
            CAST_decrypt(tin.as_mut_ptr(), ks);
            tout0 = tin[0 as libc::c_int as usize] ^ xor0;
            tout1 = tin[1 as libc::c_int as usize] ^ xor1;
            out = out.offset(l as isize);
            let mut current_block_90: u64;
            match l {
                8 => {
                    out = out.offset(-1);
                    *out = (tout1 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
                    current_block_90 = 10252139691671703884;
                }
                7 => {
                    current_block_90 = 10252139691671703884;
                }
                6 => {
                    current_block_90 = 10437147361951898503;
                }
                5 => {
                    current_block_90 = 13749393263452075147;
                }
                4 => {
                    current_block_90 = 14468854097041571522;
                }
                3 => {
                    current_block_90 = 2563886018583028020;
                }
                2 => {
                    current_block_90 = 10754629375275961719;
                }
                1 => {
                    current_block_90 = 11913332242446893268;
                }
                _ => {
                    current_block_90 = 4216521074440650966;
                }
            }
            match current_block_90 {
                10252139691671703884 => {
                    out = out.offset(-1);
                    *out = (tout1 >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
                        as libc::c_uchar;
                    current_block_90 = 10437147361951898503;
                }
                _ => {}
            }
            match current_block_90 {
                10437147361951898503 => {
                    out = out.offset(-1);
                    *out = (tout1 >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
                        as libc::c_uchar;
                    current_block_90 = 13749393263452075147;
                }
                _ => {}
            }
            match current_block_90 {
                13749393263452075147 => {
                    out = out.offset(-1);
                    *out = (tout1 >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
                        as libc::c_uchar;
                    current_block_90 = 14468854097041571522;
                }
                _ => {}
            }
            match current_block_90 {
                14468854097041571522 => {
                    out = out.offset(-1);
                    *out = (tout0 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
                    current_block_90 = 2563886018583028020;
                }
                _ => {}
            }
            match current_block_90 {
                2563886018583028020 => {
                    out = out.offset(-1);
                    *out = (tout0 >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t)
                        as libc::c_uchar;
                    current_block_90 = 10754629375275961719;
                }
                _ => {}
            }
            match current_block_90 {
                10754629375275961719 => {
                    out = out.offset(-1);
                    *out = (tout0 >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t)
                        as libc::c_uchar;
                    current_block_90 = 11913332242446893268;
                }
                _ => {}
            }
            match current_block_90 {
                11913332242446893268 => {
                    out = out.offset(-1);
                    *out = (tout0 >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
                        as libc::c_uchar;
                }
                _ => {}
            }
            xor0 = tin0;
            xor1 = tin1;
        }
        let fresh88 = iv;
        iv = iv.offset(1);
        *fresh88 = (xor0 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh89 = iv;
        iv = iv.offset(1);
        *fresh89 = (xor0 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh90 = iv;
        iv = iv.offset(1);
        *fresh90 = (xor0 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh91 = iv;
        iv = iv.offset(1);
        *fresh91 = (xor0 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
        let fresh92 = iv;
        iv = iv.offset(1);
        *fresh92 = (xor1 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh93 = iv;
        iv = iv.offset(1);
        *fresh93 = (xor1 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh94 = iv;
        iv = iv.offset(1);
        *fresh94 = (xor1 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh95 = iv;
        iv = iv.offset(1);
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CAST_set_key(
    mut key: *mut CAST_KEY,
    mut len: size_t,
    mut data: *const uint8_t,
) {
    let mut x: [uint32_t; 16] = [0; 16];
    let mut z: [uint32_t; 16] = [0; 16];
    let mut k: [uint32_t; 32] = [0; 32];
    let mut X: [uint32_t; 4] = [0; 4];
    let mut Z: [uint32_t; 4] = [0; 4];
    let mut l: uint32_t = 0;
    let mut K: *mut uint32_t = 0 as *mut uint32_t;
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < 16 as libc::c_int as size_t {
        x[i as usize] = 0 as libc::c_int as uint32_t;
        i = i.wrapping_add(1);
        i;
    }
    if len > 16 as libc::c_int as size_t {
        len = 16 as libc::c_int as size_t;
    }
    i = 0 as libc::c_int as size_t;
    while i < len {
        x[i as usize] = *data.offset(i as isize) as uint32_t;
        i = i.wrapping_add(1);
        i;
    }
    if len <= 10 as libc::c_int as size_t {
        (*key).short_key = 1 as libc::c_int;
    } else {
        (*key).short_key = 0 as libc::c_int;
    }
    K = &mut *k.as_mut_ptr().offset(0 as libc::c_int as isize) as *mut uint32_t;
    X[0 as libc::c_int
        as usize] = ((x[0 as libc::c_int as usize] << 24 as libc::c_int
        | x[1 as libc::c_int as usize] << 16 as libc::c_int
        | x[2 as libc::c_int as usize] << 8 as libc::c_int
        | x[3 as libc::c_int as usize]) as libc::c_long & 0xffffffff as libc::c_long)
        as uint32_t;
    X[1 as libc::c_int
        as usize] = ((x[4 as libc::c_int as usize] << 24 as libc::c_int
        | x[5 as libc::c_int as usize] << 16 as libc::c_int
        | x[6 as libc::c_int as usize] << 8 as libc::c_int
        | x[7 as libc::c_int as usize]) as libc::c_long & 0xffffffff as libc::c_long)
        as uint32_t;
    X[2 as libc::c_int
        as usize] = ((x[8 as libc::c_int as usize] << 24 as libc::c_int
        | x[9 as libc::c_int as usize] << 16 as libc::c_int
        | x[10 as libc::c_int as usize] << 8 as libc::c_int
        | x[11 as libc::c_int as usize]) as libc::c_long & 0xffffffff as libc::c_long)
        as uint32_t;
    X[3 as libc::c_int
        as usize] = ((x[12 as libc::c_int as usize] << 24 as libc::c_int
        | x[13 as libc::c_int as usize] << 16 as libc::c_int
        | x[14 as libc::c_int as usize] << 8 as libc::c_int
        | x[15 as libc::c_int as usize]) as libc::c_long & 0xffffffff as libc::c_long)
        as uint32_t;
    loop {
        l = X[0 as libc::c_int as usize]
            ^ CAST_S_table4[x[13 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[x[15 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[x[12 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[x[14 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[x[8 as libc::c_int as usize] as usize];
        Z[(0 as libc::c_int / 4 as libc::c_int) as usize] = l;
        z[(0 as libc::c_int + 3 as libc::c_int)
            as usize] = l & 0xff as libc::c_int as uint32_t;
        z[(0 as libc::c_int + 2 as libc::c_int)
            as usize] = l >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t;
        z[(0 as libc::c_int + 1 as libc::c_int)
            as usize] = l >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t;
        z[(0 as libc::c_int + 0 as libc::c_int)
            as usize] = l >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t;
        l = X[2 as libc::c_int as usize]
            ^ CAST_S_table4[z[0 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[z[2 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[z[1 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[z[3 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[x[10 as libc::c_int as usize] as usize];
        Z[(4 as libc::c_int / 4 as libc::c_int) as usize] = l;
        z[(4 as libc::c_int + 3 as libc::c_int)
            as usize] = l & 0xff as libc::c_int as uint32_t;
        z[(4 as libc::c_int + 2 as libc::c_int)
            as usize] = l >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t;
        z[(4 as libc::c_int + 1 as libc::c_int)
            as usize] = l >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t;
        z[(4 as libc::c_int + 0 as libc::c_int)
            as usize] = l >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t;
        l = X[3 as libc::c_int as usize]
            ^ CAST_S_table4[z[7 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[z[6 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[z[5 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[z[4 as libc::c_int as usize] as usize]
            ^ CAST_S_table4[x[9 as libc::c_int as usize] as usize];
        Z[(8 as libc::c_int / 4 as libc::c_int) as usize] = l;
        z[(8 as libc::c_int + 3 as libc::c_int)
            as usize] = l & 0xff as libc::c_int as uint32_t;
        z[(8 as libc::c_int + 2 as libc::c_int)
            as usize] = l >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t;
        z[(8 as libc::c_int + 1 as libc::c_int)
            as usize] = l >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t;
        z[(8 as libc::c_int + 0 as libc::c_int)
            as usize] = l >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t;
        l = X[1 as libc::c_int as usize]
            ^ CAST_S_table4[z[10 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[z[9 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[z[11 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[z[8 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[x[11 as libc::c_int as usize] as usize];
        Z[(12 as libc::c_int / 4 as libc::c_int) as usize] = l;
        z[(12 as libc::c_int + 3 as libc::c_int)
            as usize] = l & 0xff as libc::c_int as uint32_t;
        z[(12 as libc::c_int + 2 as libc::c_int)
            as usize] = l >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t;
        z[(12 as libc::c_int + 1 as libc::c_int)
            as usize] = l >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t;
        z[(12 as libc::c_int + 0 as libc::c_int)
            as usize] = l >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t;
        *K
            .offset(
                0 as libc::c_int as isize,
            ) = CAST_S_table4[z[8 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[z[9 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[z[7 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[z[6 as libc::c_int as usize] as usize]
            ^ CAST_S_table4[z[2 as libc::c_int as usize] as usize];
        *K
            .offset(
                1 as libc::c_int as isize,
            ) = CAST_S_table4[z[10 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[z[11 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[z[5 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[z[4 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[z[6 as libc::c_int as usize] as usize];
        *K
            .offset(
                2 as libc::c_int as isize,
            ) = CAST_S_table4[z[12 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[z[13 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[z[3 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[z[2 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[z[9 as libc::c_int as usize] as usize];
        *K
            .offset(
                3 as libc::c_int as isize,
            ) = CAST_S_table4[z[14 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[z[15 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[z[1 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[z[0 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[z[12 as libc::c_int as usize] as usize];
        l = Z[2 as libc::c_int as usize]
            ^ CAST_S_table4[z[5 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[z[7 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[z[4 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[z[6 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[z[0 as libc::c_int as usize] as usize];
        X[(0 as libc::c_int / 4 as libc::c_int) as usize] = l;
        x[(0 as libc::c_int + 3 as libc::c_int)
            as usize] = l & 0xff as libc::c_int as uint32_t;
        x[(0 as libc::c_int + 2 as libc::c_int)
            as usize] = l >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t;
        x[(0 as libc::c_int + 1 as libc::c_int)
            as usize] = l >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t;
        x[(0 as libc::c_int + 0 as libc::c_int)
            as usize] = l >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t;
        l = Z[0 as libc::c_int as usize]
            ^ CAST_S_table4[x[0 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[x[2 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[x[1 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[x[3 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[z[2 as libc::c_int as usize] as usize];
        X[(4 as libc::c_int / 4 as libc::c_int) as usize] = l;
        x[(4 as libc::c_int + 3 as libc::c_int)
            as usize] = l & 0xff as libc::c_int as uint32_t;
        x[(4 as libc::c_int + 2 as libc::c_int)
            as usize] = l >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t;
        x[(4 as libc::c_int + 1 as libc::c_int)
            as usize] = l >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t;
        x[(4 as libc::c_int + 0 as libc::c_int)
            as usize] = l >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t;
        l = Z[1 as libc::c_int as usize]
            ^ CAST_S_table4[x[7 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[x[6 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[x[5 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[x[4 as libc::c_int as usize] as usize]
            ^ CAST_S_table4[z[1 as libc::c_int as usize] as usize];
        X[(8 as libc::c_int / 4 as libc::c_int) as usize] = l;
        x[(8 as libc::c_int + 3 as libc::c_int)
            as usize] = l & 0xff as libc::c_int as uint32_t;
        x[(8 as libc::c_int + 2 as libc::c_int)
            as usize] = l >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t;
        x[(8 as libc::c_int + 1 as libc::c_int)
            as usize] = l >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t;
        x[(8 as libc::c_int + 0 as libc::c_int)
            as usize] = l >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t;
        l = Z[3 as libc::c_int as usize]
            ^ CAST_S_table4[x[10 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[x[9 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[x[11 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[x[8 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[z[3 as libc::c_int as usize] as usize];
        X[(12 as libc::c_int / 4 as libc::c_int) as usize] = l;
        x[(12 as libc::c_int + 3 as libc::c_int)
            as usize] = l & 0xff as libc::c_int as uint32_t;
        x[(12 as libc::c_int + 2 as libc::c_int)
            as usize] = l >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t;
        x[(12 as libc::c_int + 1 as libc::c_int)
            as usize] = l >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t;
        x[(12 as libc::c_int + 0 as libc::c_int)
            as usize] = l >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t;
        *K
            .offset(
                4 as libc::c_int as isize,
            ) = CAST_S_table4[x[3 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[x[2 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[x[12 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[x[13 as libc::c_int as usize] as usize]
            ^ CAST_S_table4[x[8 as libc::c_int as usize] as usize];
        *K
            .offset(
                5 as libc::c_int as isize,
            ) = CAST_S_table4[x[1 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[x[0 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[x[14 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[x[15 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[x[13 as libc::c_int as usize] as usize];
        *K
            .offset(
                6 as libc::c_int as isize,
            ) = CAST_S_table4[x[7 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[x[6 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[x[8 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[x[9 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[x[3 as libc::c_int as usize] as usize];
        *K
            .offset(
                7 as libc::c_int as isize,
            ) = CAST_S_table4[x[5 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[x[4 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[x[10 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[x[11 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[x[7 as libc::c_int as usize] as usize];
        l = X[0 as libc::c_int as usize]
            ^ CAST_S_table4[x[13 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[x[15 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[x[12 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[x[14 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[x[8 as libc::c_int as usize] as usize];
        Z[(0 as libc::c_int / 4 as libc::c_int) as usize] = l;
        z[(0 as libc::c_int + 3 as libc::c_int)
            as usize] = l & 0xff as libc::c_int as uint32_t;
        z[(0 as libc::c_int + 2 as libc::c_int)
            as usize] = l >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t;
        z[(0 as libc::c_int + 1 as libc::c_int)
            as usize] = l >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t;
        z[(0 as libc::c_int + 0 as libc::c_int)
            as usize] = l >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t;
        l = X[2 as libc::c_int as usize]
            ^ CAST_S_table4[z[0 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[z[2 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[z[1 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[z[3 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[x[10 as libc::c_int as usize] as usize];
        Z[(4 as libc::c_int / 4 as libc::c_int) as usize] = l;
        z[(4 as libc::c_int + 3 as libc::c_int)
            as usize] = l & 0xff as libc::c_int as uint32_t;
        z[(4 as libc::c_int + 2 as libc::c_int)
            as usize] = l >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t;
        z[(4 as libc::c_int + 1 as libc::c_int)
            as usize] = l >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t;
        z[(4 as libc::c_int + 0 as libc::c_int)
            as usize] = l >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t;
        l = X[3 as libc::c_int as usize]
            ^ CAST_S_table4[z[7 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[z[6 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[z[5 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[z[4 as libc::c_int as usize] as usize]
            ^ CAST_S_table4[x[9 as libc::c_int as usize] as usize];
        Z[(8 as libc::c_int / 4 as libc::c_int) as usize] = l;
        z[(8 as libc::c_int + 3 as libc::c_int)
            as usize] = l & 0xff as libc::c_int as uint32_t;
        z[(8 as libc::c_int + 2 as libc::c_int)
            as usize] = l >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t;
        z[(8 as libc::c_int + 1 as libc::c_int)
            as usize] = l >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t;
        z[(8 as libc::c_int + 0 as libc::c_int)
            as usize] = l >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t;
        l = X[1 as libc::c_int as usize]
            ^ CAST_S_table4[z[10 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[z[9 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[z[11 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[z[8 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[x[11 as libc::c_int as usize] as usize];
        Z[(12 as libc::c_int / 4 as libc::c_int) as usize] = l;
        z[(12 as libc::c_int + 3 as libc::c_int)
            as usize] = l & 0xff as libc::c_int as uint32_t;
        z[(12 as libc::c_int + 2 as libc::c_int)
            as usize] = l >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t;
        z[(12 as libc::c_int + 1 as libc::c_int)
            as usize] = l >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t;
        z[(12 as libc::c_int + 0 as libc::c_int)
            as usize] = l >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t;
        *K
            .offset(
                8 as libc::c_int as isize,
            ) = CAST_S_table4[z[3 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[z[2 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[z[12 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[z[13 as libc::c_int as usize] as usize]
            ^ CAST_S_table4[z[9 as libc::c_int as usize] as usize];
        *K
            .offset(
                9 as libc::c_int as isize,
            ) = CAST_S_table4[z[1 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[z[0 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[z[14 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[z[15 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[z[12 as libc::c_int as usize] as usize];
        *K
            .offset(
                10 as libc::c_int as isize,
            ) = CAST_S_table4[z[7 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[z[6 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[z[8 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[z[9 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[z[2 as libc::c_int as usize] as usize];
        *K
            .offset(
                11 as libc::c_int as isize,
            ) = CAST_S_table4[z[5 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[z[4 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[z[10 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[z[11 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[z[6 as libc::c_int as usize] as usize];
        l = Z[2 as libc::c_int as usize]
            ^ CAST_S_table4[z[5 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[z[7 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[z[4 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[z[6 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[z[0 as libc::c_int as usize] as usize];
        X[(0 as libc::c_int / 4 as libc::c_int) as usize] = l;
        x[(0 as libc::c_int + 3 as libc::c_int)
            as usize] = l & 0xff as libc::c_int as uint32_t;
        x[(0 as libc::c_int + 2 as libc::c_int)
            as usize] = l >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t;
        x[(0 as libc::c_int + 1 as libc::c_int)
            as usize] = l >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t;
        x[(0 as libc::c_int + 0 as libc::c_int)
            as usize] = l >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t;
        l = Z[0 as libc::c_int as usize]
            ^ CAST_S_table4[x[0 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[x[2 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[x[1 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[x[3 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[z[2 as libc::c_int as usize] as usize];
        X[(4 as libc::c_int / 4 as libc::c_int) as usize] = l;
        x[(4 as libc::c_int + 3 as libc::c_int)
            as usize] = l & 0xff as libc::c_int as uint32_t;
        x[(4 as libc::c_int + 2 as libc::c_int)
            as usize] = l >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t;
        x[(4 as libc::c_int + 1 as libc::c_int)
            as usize] = l >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t;
        x[(4 as libc::c_int + 0 as libc::c_int)
            as usize] = l >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t;
        l = Z[1 as libc::c_int as usize]
            ^ CAST_S_table4[x[7 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[x[6 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[x[5 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[x[4 as libc::c_int as usize] as usize]
            ^ CAST_S_table4[z[1 as libc::c_int as usize] as usize];
        X[(8 as libc::c_int / 4 as libc::c_int) as usize] = l;
        x[(8 as libc::c_int + 3 as libc::c_int)
            as usize] = l & 0xff as libc::c_int as uint32_t;
        x[(8 as libc::c_int + 2 as libc::c_int)
            as usize] = l >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t;
        x[(8 as libc::c_int + 1 as libc::c_int)
            as usize] = l >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t;
        x[(8 as libc::c_int + 0 as libc::c_int)
            as usize] = l >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t;
        l = Z[3 as libc::c_int as usize]
            ^ CAST_S_table4[x[10 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[x[9 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[x[11 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[x[8 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[z[3 as libc::c_int as usize] as usize];
        X[(12 as libc::c_int / 4 as libc::c_int) as usize] = l;
        x[(12 as libc::c_int + 3 as libc::c_int)
            as usize] = l & 0xff as libc::c_int as uint32_t;
        x[(12 as libc::c_int + 2 as libc::c_int)
            as usize] = l >> 8 as libc::c_int & 0xff as libc::c_int as uint32_t;
        x[(12 as libc::c_int + 1 as libc::c_int)
            as usize] = l >> 16 as libc::c_int & 0xff as libc::c_int as uint32_t;
        x[(12 as libc::c_int + 0 as libc::c_int)
            as usize] = l >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t;
        *K
            .offset(
                12 as libc::c_int as isize,
            ) = CAST_S_table4[x[8 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[x[9 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[x[7 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[x[6 as libc::c_int as usize] as usize]
            ^ CAST_S_table4[x[3 as libc::c_int as usize] as usize];
        *K
            .offset(
                13 as libc::c_int as isize,
            ) = CAST_S_table4[x[10 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[x[11 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[x[5 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[x[4 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[x[7 as libc::c_int as usize] as usize];
        *K
            .offset(
                14 as libc::c_int as isize,
            ) = CAST_S_table4[x[12 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[x[13 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[x[3 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[x[2 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[x[8 as libc::c_int as usize] as usize];
        *K
            .offset(
                15 as libc::c_int as isize,
            ) = CAST_S_table4[x[14 as libc::c_int as usize] as usize]
            ^ CAST_S_table5[x[15 as libc::c_int as usize] as usize]
            ^ CAST_S_table6[x[1 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[x[0 as libc::c_int as usize] as usize]
            ^ CAST_S_table7[x[13 as libc::c_int as usize] as usize];
        if K != k.as_mut_ptr() {
            break;
        }
        K = K.offset(16 as libc::c_int as isize);
    }
    i = 0 as libc::c_int as size_t;
    while i < 16 as libc::c_int as size_t {
        (*key).data[(i * 2 as libc::c_int as size_t) as usize] = k[i as usize];
        (*key)
            .data[(i * 2 as libc::c_int as size_t)
            .wrapping_add(1 as libc::c_int as size_t)
            as usize] = (k[i.wrapping_add(16 as libc::c_int as size_t) as usize])
            .wrapping_add(16 as libc::c_int as uint32_t)
            & 0x1f as libc::c_int as uint32_t;
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn cast_init_key(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut key: *const uint8_t,
    mut iv: *const uint8_t,
    mut enc: libc::c_int,
) -> libc::c_int {
    let mut cast_key: *mut CAST_KEY = (*ctx).cipher_data as *mut CAST_KEY;
    CAST_set_key(cast_key, (*ctx).key_len as size_t, key);
    return 1 as libc::c_int;
}
unsafe extern "C" fn cast_ecb_cipher(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut cast_key: *mut CAST_KEY = (*ctx).cipher_data as *mut CAST_KEY;
    if len % 8 as libc::c_int as size_t == 0 as libc::c_int as size_t {} else {
        __assert_fail(
            b"len % CAST_BLOCK == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/cast/cast.c\0"
                as *const u8 as *const libc::c_char,
            371 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 74],
                &[libc::c_char; 74],
            >(
                b"int cast_ecb_cipher(EVP_CIPHER_CTX *, uint8_t *, const uint8_t *, size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_7255: {
        if len % 8 as libc::c_int as size_t == 0 as libc::c_int as size_t {} else {
            __assert_fail(
                b"len % CAST_BLOCK == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/cast/cast.c\0"
                    as *const u8 as *const libc::c_char,
                371 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 74],
                    &[libc::c_char; 74],
                >(
                    b"int cast_ecb_cipher(EVP_CIPHER_CTX *, uint8_t *, const uint8_t *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    while len >= 8 as libc::c_int as size_t {
        CAST_ecb_encrypt(in_0, out, cast_key, (*ctx).encrypt);
        in_0 = in_0.offset(8 as libc::c_int as isize);
        out = out.offset(8 as libc::c_int as isize);
        len = len.wrapping_sub(8 as libc::c_int as size_t);
    }
    if len == 0 as libc::c_int as size_t {} else {
        __assert_fail(
            b"len == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/cast/cast.c\0"
                as *const u8 as *const libc::c_char,
            379 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 74],
                &[libc::c_char; 74],
            >(
                b"int cast_ecb_cipher(EVP_CIPHER_CTX *, uint8_t *, const uint8_t *, size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_1661: {
        if len == 0 as libc::c_int as size_t {} else {
            __assert_fail(
                b"len == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/cast/cast.c\0"
                    as *const u8 as *const libc::c_char,
                379 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 74],
                    &[libc::c_char; 74],
                >(
                    b"int cast_ecb_cipher(EVP_CIPHER_CTX *, uint8_t *, const uint8_t *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    return 1 as libc::c_int;
}
unsafe extern "C" fn cast_cbc_cipher(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut cast_key: *mut CAST_KEY = (*ctx).cipher_data as *mut CAST_KEY;
    CAST_cbc_encrypt(in_0, out, len, cast_key, ((*ctx).iv).as_mut_ptr(), (*ctx).encrypt);
    return 1 as libc::c_int;
}
static mut cast5_ecb: EVP_CIPHER = unsafe {
    {
        let mut init = evp_cipher_st {
            nid: 109 as libc::c_int,
            block_size: 8 as libc::c_int as libc::c_uint,
            key_len: 16 as libc::c_int as libc::c_uint,
            iv_len: 8 as libc::c_int as libc::c_uint,
            ctx_size: ::core::mem::size_of::<CAST_KEY>() as libc::c_ulong
                as libc::c_uint,
            flags: (0x1 as libc::c_int | 0x40 as libc::c_int) as uint32_t,
            init: Some(
                cast_init_key
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *const uint8_t,
                        *const uint8_t,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            cipher: Some(
                cast_ecb_cipher
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
static mut cast5_cbc: EVP_CIPHER = unsafe {
    {
        let mut init = evp_cipher_st {
            nid: 108 as libc::c_int,
            block_size: 8 as libc::c_int as libc::c_uint,
            key_len: 16 as libc::c_int as libc::c_uint,
            iv_len: 8 as libc::c_int as libc::c_uint,
            ctx_size: ::core::mem::size_of::<CAST_KEY>() as libc::c_ulong
                as libc::c_uint,
            flags: (0x2 as libc::c_int | 0x40 as libc::c_int) as uint32_t,
            init: Some(
                cast_init_key
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *const uint8_t,
                        *const uint8_t,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            cipher: Some(
                cast_cbc_cipher
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
pub unsafe extern "C" fn EVP_cast5_ecb() -> *const EVP_CIPHER {
    return &cast5_ecb;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_cast5_cbc() -> *const EVP_CIPHER {
    return &cast5_cbc;
}
