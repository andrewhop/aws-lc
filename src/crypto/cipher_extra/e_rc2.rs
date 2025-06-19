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
    fn EVP_CIPHER_CTX_key_length(ctx: *const EVP_CIPHER_CTX) -> libc::c_uint;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
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
pub struct EVP_RC2_KEY {
    pub key_bits: libc::c_int,
    pub ks: RC2_KEY,
}
pub type RC2_KEY = rc2_key_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rc2_key_st {
    pub data: [uint16_t; 64],
}
unsafe extern "C" fn RC2_encrypt(mut d: *mut uint32_t, mut key: *mut RC2_KEY) {
    let mut i: libc::c_int = 0;
    let mut n: libc::c_int = 0;
    let mut p0: *mut uint16_t = 0 as *mut uint16_t;
    let mut p1: *mut uint16_t = 0 as *mut uint16_t;
    let mut x0: uint16_t = 0;
    let mut x1: uint16_t = 0;
    let mut x2: uint16_t = 0;
    let mut x3: uint16_t = 0;
    let mut t: uint16_t = 0;
    let mut l: uint32_t = 0;
    l = *d.offset(0 as libc::c_int as isize);
    x0 = (l as uint16_t as libc::c_int & 0xffff as libc::c_int) as uint16_t;
    x1 = (l >> 16 as libc::c_long) as uint16_t;
    l = *d.offset(1 as libc::c_int as isize);
    x2 = (l as uint16_t as libc::c_int & 0xffff as libc::c_int) as uint16_t;
    x3 = (l >> 16 as libc::c_long) as uint16_t;
    n = 3 as libc::c_int;
    i = 5 as libc::c_int;
    p1 = &mut *((*key).data).as_mut_ptr().offset(0 as libc::c_int as isize)
        as *mut uint16_t;
    p0 = p1;
    loop {
        let fresh0 = p0;
        p0 = p0.offset(1);
        t = (x0 as libc::c_int + (x1 as libc::c_int & !(x3 as libc::c_int))
            + (x2 as libc::c_int & x3 as libc::c_int) + *fresh0 as libc::c_int
            & 0xffff as libc::c_int) as uint16_t;
        x0 = ((t as libc::c_int) << 1 as libc::c_int
            | t as libc::c_int >> 15 as libc::c_int) as uint16_t;
        let fresh1 = p0;
        p0 = p0.offset(1);
        t = (x1 as libc::c_int + (x2 as libc::c_int & !(x0 as libc::c_int))
            + (x3 as libc::c_int & x0 as libc::c_int) + *fresh1 as libc::c_int
            & 0xffff as libc::c_int) as uint16_t;
        x1 = ((t as libc::c_int) << 2 as libc::c_int
            | t as libc::c_int >> 14 as libc::c_int) as uint16_t;
        let fresh2 = p0;
        p0 = p0.offset(1);
        t = (x2 as libc::c_int + (x3 as libc::c_int & !(x1 as libc::c_int))
            + (x0 as libc::c_int & x1 as libc::c_int) + *fresh2 as libc::c_int
            & 0xffff as libc::c_int) as uint16_t;
        x2 = ((t as libc::c_int) << 3 as libc::c_int
            | t as libc::c_int >> 13 as libc::c_int) as uint16_t;
        let fresh3 = p0;
        p0 = p0.offset(1);
        t = (x3 as libc::c_int + (x0 as libc::c_int & !(x2 as libc::c_int))
            + (x1 as libc::c_int & x2 as libc::c_int) + *fresh3 as libc::c_int
            & 0xffff as libc::c_int) as uint16_t;
        x3 = ((t as libc::c_int) << 5 as libc::c_int
            | t as libc::c_int >> 11 as libc::c_int) as uint16_t;
        i -= 1;
        if !(i == 0 as libc::c_int) {
            continue;
        }
        n -= 1;
        if n == 0 as libc::c_int {
            break;
        }
        i = if n == 2 as libc::c_int { 6 as libc::c_int } else { 5 as libc::c_int };
        x0 = (x0 as libc::c_int
            + *p1.offset((x3 as libc::c_int & 0x3f as libc::c_int) as isize)
                as libc::c_int) as uint16_t;
        x1 = (x1 as libc::c_int
            + *p1.offset((x0 as libc::c_int & 0x3f as libc::c_int) as isize)
                as libc::c_int) as uint16_t;
        x2 = (x2 as libc::c_int
            + *p1.offset((x1 as libc::c_int & 0x3f as libc::c_int) as isize)
                as libc::c_int) as uint16_t;
        x3 = (x3 as libc::c_int
            + *p1.offset((x2 as libc::c_int & 0x3f as libc::c_int) as isize)
                as libc::c_int) as uint16_t;
    }
    *d
        .offset(
            0 as libc::c_int as isize,
        ) = (x0 as libc::c_int & 0xffff as libc::c_int) as uint32_t
        | ((x1 as libc::c_int & 0xffff as libc::c_int) as uint32_t)
            << 16 as libc::c_long;
    *d
        .offset(
            1 as libc::c_int as isize,
        ) = (x2 as libc::c_int & 0xffff as libc::c_int) as uint32_t
        | ((x3 as libc::c_int & 0xffff as libc::c_int) as uint32_t)
            << 16 as libc::c_long;
}
unsafe extern "C" fn RC2_decrypt(mut d: *mut uint32_t, mut key: *mut RC2_KEY) {
    let mut i: libc::c_int = 0;
    let mut n: libc::c_int = 0;
    let mut p0: *mut uint16_t = 0 as *mut uint16_t;
    let mut p1: *mut uint16_t = 0 as *mut uint16_t;
    let mut x0: uint16_t = 0;
    let mut x1: uint16_t = 0;
    let mut x2: uint16_t = 0;
    let mut x3: uint16_t = 0;
    let mut t: uint16_t = 0;
    let mut l: uint32_t = 0;
    l = *d.offset(0 as libc::c_int as isize);
    x0 = (l as uint16_t as libc::c_int & 0xffff as libc::c_int) as uint16_t;
    x1 = (l >> 16 as libc::c_long) as uint16_t;
    l = *d.offset(1 as libc::c_int as isize);
    x2 = (l as uint16_t as libc::c_int & 0xffff as libc::c_int) as uint16_t;
    x3 = (l >> 16 as libc::c_long) as uint16_t;
    n = 3 as libc::c_int;
    i = 5 as libc::c_int;
    p0 = &mut *((*key).data).as_mut_ptr().offset(63 as libc::c_int as isize)
        as *mut uint16_t;
    p1 = &mut *((*key).data).as_mut_ptr().offset(0 as libc::c_int as isize)
        as *mut uint16_t;
    loop {
        t = (((x3 as libc::c_int) << 11 as libc::c_int
            | x3 as libc::c_int >> 5 as libc::c_int) & 0xffff as libc::c_int)
            as uint16_t;
        let fresh4 = p0;
        p0 = p0.offset(-1);
        x3 = (t as libc::c_int - (x0 as libc::c_int & !(x2 as libc::c_int))
            - (x1 as libc::c_int & x2 as libc::c_int) - *fresh4 as libc::c_int
            & 0xffff as libc::c_int) as uint16_t;
        t = (((x2 as libc::c_int) << 13 as libc::c_int
            | x2 as libc::c_int >> 3 as libc::c_int) & 0xffff as libc::c_int)
            as uint16_t;
        let fresh5 = p0;
        p0 = p0.offset(-1);
        x2 = (t as libc::c_int - (x3 as libc::c_int & !(x1 as libc::c_int))
            - (x0 as libc::c_int & x1 as libc::c_int) - *fresh5 as libc::c_int
            & 0xffff as libc::c_int) as uint16_t;
        t = (((x1 as libc::c_int) << 14 as libc::c_int
            | x1 as libc::c_int >> 2 as libc::c_int) & 0xffff as libc::c_int)
            as uint16_t;
        let fresh6 = p0;
        p0 = p0.offset(-1);
        x1 = (t as libc::c_int - (x2 as libc::c_int & !(x0 as libc::c_int))
            - (x3 as libc::c_int & x0 as libc::c_int) - *fresh6 as libc::c_int
            & 0xffff as libc::c_int) as uint16_t;
        t = (((x0 as libc::c_int) << 15 as libc::c_int
            | x0 as libc::c_int >> 1 as libc::c_int) & 0xffff as libc::c_int)
            as uint16_t;
        let fresh7 = p0;
        p0 = p0.offset(-1);
        x0 = (t as libc::c_int - (x1 as libc::c_int & !(x3 as libc::c_int))
            - (x2 as libc::c_int & x3 as libc::c_int) - *fresh7 as libc::c_int
            & 0xffff as libc::c_int) as uint16_t;
        i -= 1;
        if !(i == 0 as libc::c_int) {
            continue;
        }
        n -= 1;
        if n == 0 as libc::c_int {
            break;
        }
        i = if n == 2 as libc::c_int { 6 as libc::c_int } else { 5 as libc::c_int };
        x3 = (x3 as libc::c_int
            - *p1.offset((x2 as libc::c_int & 0x3f as libc::c_int) as isize)
                as libc::c_int & 0xffff as libc::c_int) as uint16_t;
        x2 = (x2 as libc::c_int
            - *p1.offset((x1 as libc::c_int & 0x3f as libc::c_int) as isize)
                as libc::c_int & 0xffff as libc::c_int) as uint16_t;
        x1 = (x1 as libc::c_int
            - *p1.offset((x0 as libc::c_int & 0x3f as libc::c_int) as isize)
                as libc::c_int & 0xffff as libc::c_int) as uint16_t;
        x0 = (x0 as libc::c_int
            - *p1.offset((x3 as libc::c_int & 0x3f as libc::c_int) as isize)
                as libc::c_int & 0xffff as libc::c_int) as uint16_t;
    }
    *d
        .offset(
            0 as libc::c_int as isize,
        ) = (x0 as libc::c_int & 0xffff as libc::c_int) as uint32_t
        | ((x1 as libc::c_int & 0xffff as libc::c_int) as uint32_t)
            << 16 as libc::c_long;
    *d
        .offset(
            1 as libc::c_int as isize,
        ) = (x2 as libc::c_int & 0xffff as libc::c_int) as uint32_t
        | ((x3 as libc::c_int & 0xffff as libc::c_int) as uint32_t)
            << 16 as libc::c_long;
}
unsafe extern "C" fn RC2_cbc_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut length: size_t,
    mut ks: *mut RC2_KEY,
    mut iv: *mut uint8_t,
    mut encrypt: libc::c_int,
) {
    let mut tin0: uint32_t = 0;
    let mut tin1: uint32_t = 0;
    let mut tout0: uint32_t = 0;
    let mut tout1: uint32_t = 0;
    let mut xor0: uint32_t = 0;
    let mut xor1: uint32_t = 0;
    let mut l: libc::c_long = length as libc::c_long;
    let mut tin: [uint32_t; 2] = [0; 2];
    if encrypt != 0 {
        let fresh8 = iv;
        iv = iv.offset(1);
        tout0 = *fresh8 as uint32_t;
        let fresh9 = iv;
        iv = iv.offset(1);
        tout0 |= (*fresh9 as uint32_t) << 8 as libc::c_long;
        let fresh10 = iv;
        iv = iv.offset(1);
        tout0 |= (*fresh10 as uint32_t) << 16 as libc::c_long;
        let fresh11 = iv;
        iv = iv.offset(1);
        tout0 |= (*fresh11 as uint32_t) << 24 as libc::c_long;
        let fresh12 = iv;
        iv = iv.offset(1);
        tout1 = *fresh12 as uint32_t;
        let fresh13 = iv;
        iv = iv.offset(1);
        tout1 |= (*fresh13 as uint32_t) << 8 as libc::c_long;
        let fresh14 = iv;
        iv = iv.offset(1);
        tout1 |= (*fresh14 as uint32_t) << 16 as libc::c_long;
        let fresh15 = iv;
        iv = iv.offset(1);
        tout1 |= (*fresh15 as uint32_t) << 24 as libc::c_long;
        iv = iv.offset(-(8 as libc::c_int as isize));
        l -= 8 as libc::c_int as libc::c_long;
        while l >= 0 as libc::c_int as libc::c_long {
            let fresh16 = in_0;
            in_0 = in_0.offset(1);
            tin0 = *fresh16 as uint32_t;
            let fresh17 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh17 as uint32_t) << 8 as libc::c_long;
            let fresh18 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh18 as uint32_t) << 16 as libc::c_long;
            let fresh19 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh19 as uint32_t) << 24 as libc::c_long;
            let fresh20 = in_0;
            in_0 = in_0.offset(1);
            tin1 = *fresh20 as uint32_t;
            let fresh21 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh21 as uint32_t) << 8 as libc::c_long;
            let fresh22 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh22 as uint32_t) << 16 as libc::c_long;
            let fresh23 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh23 as uint32_t) << 24 as libc::c_long;
            tin0 ^= tout0;
            tin1 ^= tout1;
            tin[0 as libc::c_int as usize] = tin0;
            tin[1 as libc::c_int as usize] = tin1;
            RC2_encrypt(tin.as_mut_ptr(), ks);
            tout0 = tin[0 as libc::c_int as usize];
            let fresh24 = out;
            out = out.offset(1);
            *fresh24 = (tout0 & 0xff as libc::c_int as uint32_t) as uint8_t;
            let fresh25 = out;
            out = out.offset(1);
            *fresh25 = (tout0 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as uint8_t;
            let fresh26 = out;
            out = out.offset(1);
            *fresh26 = (tout0 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as uint8_t;
            let fresh27 = out;
            out = out.offset(1);
            *fresh27 = (tout0 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as uint8_t;
            tout1 = tin[1 as libc::c_int as usize];
            let fresh28 = out;
            out = out.offset(1);
            *fresh28 = (tout1 & 0xff as libc::c_int as uint32_t) as uint8_t;
            let fresh29 = out;
            out = out.offset(1);
            *fresh29 = (tout1 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as uint8_t;
            let fresh30 = out;
            out = out.offset(1);
            *fresh30 = (tout1 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as uint8_t;
            let fresh31 = out;
            out = out.offset(1);
            *fresh31 = (tout1 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as uint8_t;
            l -= 8 as libc::c_int as libc::c_long;
        }
        if l != -(8 as libc::c_int) as libc::c_long {
            in_0 = in_0.offset((l + 8 as libc::c_int as libc::c_long) as isize);
            tin1 = 0 as libc::c_int as uint32_t;
            tin0 = tin1;
            let mut current_block_63: u64;
            match l + 8 as libc::c_int as libc::c_long {
                8 => {
                    in_0 = in_0.offset(-1);
                    tin1 = (*in_0 as uint32_t) << 24 as libc::c_long;
                    current_block_63 = 14460722427517220191;
                }
                7 => {
                    current_block_63 = 14460722427517220191;
                }
                6 => {
                    current_block_63 = 11741899136554949298;
                }
                5 => {
                    current_block_63 = 14876129812070712977;
                }
                4 => {
                    current_block_63 = 1856533575870289582;
                }
                3 => {
                    current_block_63 = 13746585799314518584;
                }
                2 => {
                    current_block_63 = 6946901454672453991;
                }
                1 => {
                    current_block_63 = 8165732153684068821;
                }
                _ => {
                    current_block_63 = 2516253395664191498;
                }
            }
            match current_block_63 {
                14460722427517220191 => {
                    in_0 = in_0.offset(-1);
                    tin1 |= (*in_0 as uint32_t) << 16 as libc::c_long;
                    current_block_63 = 11741899136554949298;
                }
                _ => {}
            }
            match current_block_63 {
                11741899136554949298 => {
                    in_0 = in_0.offset(-1);
                    tin1 |= (*in_0 as uint32_t) << 8 as libc::c_long;
                    current_block_63 = 14876129812070712977;
                }
                _ => {}
            }
            match current_block_63 {
                14876129812070712977 => {
                    in_0 = in_0.offset(-1);
                    tin1 |= *in_0 as uint32_t;
                    current_block_63 = 1856533575870289582;
                }
                _ => {}
            }
            match current_block_63 {
                1856533575870289582 => {
                    in_0 = in_0.offset(-1);
                    tin0 = (*in_0 as uint32_t) << 24 as libc::c_long;
                    current_block_63 = 13746585799314518584;
                }
                _ => {}
            }
            match current_block_63 {
                13746585799314518584 => {
                    in_0 = in_0.offset(-1);
                    tin0 |= (*in_0 as uint32_t) << 16 as libc::c_long;
                    current_block_63 = 6946901454672453991;
                }
                _ => {}
            }
            match current_block_63 {
                6946901454672453991 => {
                    in_0 = in_0.offset(-1);
                    tin0 |= (*in_0 as uint32_t) << 8 as libc::c_long;
                    current_block_63 = 8165732153684068821;
                }
                _ => {}
            }
            match current_block_63 {
                8165732153684068821 => {
                    in_0 = in_0.offset(-1);
                    tin0 |= *in_0 as uint32_t;
                }
                _ => {}
            }
            tin0 ^= tout0;
            tin1 ^= tout1;
            tin[0 as libc::c_int as usize] = tin0;
            tin[1 as libc::c_int as usize] = tin1;
            RC2_encrypt(tin.as_mut_ptr(), ks);
            tout0 = tin[0 as libc::c_int as usize];
            let fresh32 = out;
            out = out.offset(1);
            *fresh32 = (tout0 & 0xff as libc::c_int as uint32_t) as uint8_t;
            let fresh33 = out;
            out = out.offset(1);
            *fresh33 = (tout0 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as uint8_t;
            let fresh34 = out;
            out = out.offset(1);
            *fresh34 = (tout0 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as uint8_t;
            let fresh35 = out;
            out = out.offset(1);
            *fresh35 = (tout0 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as uint8_t;
            tout1 = tin[1 as libc::c_int as usize];
            let fresh36 = out;
            out = out.offset(1);
            *fresh36 = (tout1 & 0xff as libc::c_int as uint32_t) as uint8_t;
            let fresh37 = out;
            out = out.offset(1);
            *fresh37 = (tout1 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as uint8_t;
            let fresh38 = out;
            out = out.offset(1);
            *fresh38 = (tout1 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as uint8_t;
            let fresh39 = out;
            out = out.offset(1);
            *fresh39 = (tout1 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as uint8_t;
        }
        let fresh40 = iv;
        iv = iv.offset(1);
        *fresh40 = (tout0 & 0xff as libc::c_int as uint32_t) as uint8_t;
        let fresh41 = iv;
        iv = iv.offset(1);
        *fresh41 = (tout0 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as uint8_t;
        let fresh42 = iv;
        iv = iv.offset(1);
        *fresh42 = (tout0 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as uint8_t;
        let fresh43 = iv;
        iv = iv.offset(1);
        *fresh43 = (tout0 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as uint8_t;
        let fresh44 = iv;
        iv = iv.offset(1);
        *fresh44 = (tout1 & 0xff as libc::c_int as uint32_t) as uint8_t;
        let fresh45 = iv;
        iv = iv.offset(1);
        *fresh45 = (tout1 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as uint8_t;
        let fresh46 = iv;
        iv = iv.offset(1);
        *fresh46 = (tout1 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as uint8_t;
        let fresh47 = iv;
        iv = iv.offset(1);
        *fresh47 = (tout1 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as uint8_t;
    } else {
        let fresh48 = iv;
        iv = iv.offset(1);
        xor0 = *fresh48 as uint32_t;
        let fresh49 = iv;
        iv = iv.offset(1);
        xor0 |= (*fresh49 as uint32_t) << 8 as libc::c_long;
        let fresh50 = iv;
        iv = iv.offset(1);
        xor0 |= (*fresh50 as uint32_t) << 16 as libc::c_long;
        let fresh51 = iv;
        iv = iv.offset(1);
        xor0 |= (*fresh51 as uint32_t) << 24 as libc::c_long;
        let fresh52 = iv;
        iv = iv.offset(1);
        xor1 = *fresh52 as uint32_t;
        let fresh53 = iv;
        iv = iv.offset(1);
        xor1 |= (*fresh53 as uint32_t) << 8 as libc::c_long;
        let fresh54 = iv;
        iv = iv.offset(1);
        xor1 |= (*fresh54 as uint32_t) << 16 as libc::c_long;
        let fresh55 = iv;
        iv = iv.offset(1);
        xor1 |= (*fresh55 as uint32_t) << 24 as libc::c_long;
        iv = iv.offset(-(8 as libc::c_int as isize));
        l -= 8 as libc::c_int as libc::c_long;
        while l >= 0 as libc::c_int as libc::c_long {
            let fresh56 = in_0;
            in_0 = in_0.offset(1);
            tin0 = *fresh56 as uint32_t;
            let fresh57 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh57 as uint32_t) << 8 as libc::c_long;
            let fresh58 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh58 as uint32_t) << 16 as libc::c_long;
            let fresh59 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh59 as uint32_t) << 24 as libc::c_long;
            tin[0 as libc::c_int as usize] = tin0;
            let fresh60 = in_0;
            in_0 = in_0.offset(1);
            tin1 = *fresh60 as uint32_t;
            let fresh61 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh61 as uint32_t) << 8 as libc::c_long;
            let fresh62 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh62 as uint32_t) << 16 as libc::c_long;
            let fresh63 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh63 as uint32_t) << 24 as libc::c_long;
            tin[1 as libc::c_int as usize] = tin1;
            RC2_decrypt(tin.as_mut_ptr(), ks);
            tout0 = tin[0 as libc::c_int as usize] ^ xor0;
            tout1 = tin[1 as libc::c_int as usize] ^ xor1;
            let fresh64 = out;
            out = out.offset(1);
            *fresh64 = (tout0 & 0xff as libc::c_int as uint32_t) as uint8_t;
            let fresh65 = out;
            out = out.offset(1);
            *fresh65 = (tout0 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as uint8_t;
            let fresh66 = out;
            out = out.offset(1);
            *fresh66 = (tout0 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as uint8_t;
            let fresh67 = out;
            out = out.offset(1);
            *fresh67 = (tout0 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as uint8_t;
            let fresh68 = out;
            out = out.offset(1);
            *fresh68 = (tout1 & 0xff as libc::c_int as uint32_t) as uint8_t;
            let fresh69 = out;
            out = out.offset(1);
            *fresh69 = (tout1 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as uint8_t;
            let fresh70 = out;
            out = out.offset(1);
            *fresh70 = (tout1 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as uint8_t;
            let fresh71 = out;
            out = out.offset(1);
            *fresh71 = (tout1 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as uint8_t;
            xor0 = tin0;
            xor1 = tin1;
            l -= 8 as libc::c_int as libc::c_long;
        }
        if l != -(8 as libc::c_int) as libc::c_long {
            let fresh72 = in_0;
            in_0 = in_0.offset(1);
            tin0 = *fresh72 as uint32_t;
            let fresh73 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh73 as uint32_t) << 8 as libc::c_long;
            let fresh74 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh74 as uint32_t) << 16 as libc::c_long;
            let fresh75 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh75 as uint32_t) << 24 as libc::c_long;
            tin[0 as libc::c_int as usize] = tin0;
            let fresh76 = in_0;
            in_0 = in_0.offset(1);
            tin1 = *fresh76 as uint32_t;
            let fresh77 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh77 as uint32_t) << 8 as libc::c_long;
            let fresh78 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh78 as uint32_t) << 16 as libc::c_long;
            let fresh79 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh79 as uint32_t) << 24 as libc::c_long;
            tin[1 as libc::c_int as usize] = tin1;
            RC2_decrypt(tin.as_mut_ptr(), ks);
            tout0 = tin[0 as libc::c_int as usize] ^ xor0;
            tout1 = tin[1 as libc::c_int as usize] ^ xor1;
            out = out.offset((l + 8 as libc::c_int as libc::c_long) as isize);
            let mut current_block_180: u64;
            match l + 8 as libc::c_int as libc::c_long {
                8 => {
                    out = out.offset(-1);
                    *out = (tout1 >> 24 as libc::c_long
                        & 0xff as libc::c_int as uint32_t) as uint8_t;
                    current_block_180 = 17715235826465125181;
                }
                7 => {
                    current_block_180 = 17715235826465125181;
                }
                6 => {
                    current_block_180 = 12829583498950112760;
                }
                5 => {
                    current_block_180 = 7576181696500390230;
                }
                4 => {
                    current_block_180 = 7129756179271091329;
                }
                3 => {
                    current_block_180 = 8315115059463376523;
                }
                2 => {
                    current_block_180 = 1190707932123529832;
                }
                1 => {
                    current_block_180 = 17938178955365237574;
                }
                _ => {
                    current_block_180 = 9343041660989783267;
                }
            }
            match current_block_180 {
                17715235826465125181 => {
                    out = out.offset(-1);
                    *out = (tout1 >> 16 as libc::c_long
                        & 0xff as libc::c_int as uint32_t) as uint8_t;
                    current_block_180 = 12829583498950112760;
                }
                _ => {}
            }
            match current_block_180 {
                12829583498950112760 => {
                    out = out.offset(-1);
                    *out = (tout1 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                        as uint8_t;
                    current_block_180 = 7576181696500390230;
                }
                _ => {}
            }
            match current_block_180 {
                7576181696500390230 => {
                    out = out.offset(-1);
                    *out = (tout1 & 0xff as libc::c_int as uint32_t) as uint8_t;
                    current_block_180 = 7129756179271091329;
                }
                _ => {}
            }
            match current_block_180 {
                7129756179271091329 => {
                    out = out.offset(-1);
                    *out = (tout0 >> 24 as libc::c_long
                        & 0xff as libc::c_int as uint32_t) as uint8_t;
                    current_block_180 = 8315115059463376523;
                }
                _ => {}
            }
            match current_block_180 {
                8315115059463376523 => {
                    out = out.offset(-1);
                    *out = (tout0 >> 16 as libc::c_long
                        & 0xff as libc::c_int as uint32_t) as uint8_t;
                    current_block_180 = 1190707932123529832;
                }
                _ => {}
            }
            match current_block_180 {
                1190707932123529832 => {
                    out = out.offset(-1);
                    *out = (tout0 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                        as uint8_t;
                    current_block_180 = 17938178955365237574;
                }
                _ => {}
            }
            match current_block_180 {
                17938178955365237574 => {
                    out = out.offset(-1);
                    *out = (tout0 & 0xff as libc::c_int as uint32_t) as uint8_t;
                }
                _ => {}
            }
            xor0 = tin0;
            xor1 = tin1;
        }
        let fresh80 = iv;
        iv = iv.offset(1);
        *fresh80 = (xor0 & 0xff as libc::c_int as uint32_t) as uint8_t;
        let fresh81 = iv;
        iv = iv.offset(1);
        *fresh81 = (xor0 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as uint8_t;
        let fresh82 = iv;
        iv = iv.offset(1);
        *fresh82 = (xor0 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as uint8_t;
        let fresh83 = iv;
        iv = iv.offset(1);
        *fresh83 = (xor0 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as uint8_t;
        let fresh84 = iv;
        iv = iv.offset(1);
        *fresh84 = (xor1 & 0xff as libc::c_int as uint32_t) as uint8_t;
        let fresh85 = iv;
        iv = iv.offset(1);
        *fresh85 = (xor1 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as uint8_t;
        let fresh86 = iv;
        iv = iv.offset(1);
        *fresh86 = (xor1 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as uint8_t;
        let fresh87 = iv;
        iv = iv.offset(1);
        *fresh87 = (xor1 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as uint8_t;
    }
    tin[1 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    tin[0 as libc::c_int as usize] = tin[1 as libc::c_int as usize];
}
static mut key_table: [uint8_t; 256] = [
    0xd9 as libc::c_int as uint8_t,
    0x78 as libc::c_int as uint8_t,
    0xf9 as libc::c_int as uint8_t,
    0xc4 as libc::c_int as uint8_t,
    0x19 as libc::c_int as uint8_t,
    0xdd as libc::c_int as uint8_t,
    0xb5 as libc::c_int as uint8_t,
    0xed as libc::c_int as uint8_t,
    0x28 as libc::c_int as uint8_t,
    0xe9 as libc::c_int as uint8_t,
    0xfd as libc::c_int as uint8_t,
    0x79 as libc::c_int as uint8_t,
    0x4a as libc::c_int as uint8_t,
    0xa0 as libc::c_int as uint8_t,
    0xd8 as libc::c_int as uint8_t,
    0x9d as libc::c_int as uint8_t,
    0xc6 as libc::c_int as uint8_t,
    0x7e as libc::c_int as uint8_t,
    0x37 as libc::c_int as uint8_t,
    0x83 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x76 as libc::c_int as uint8_t,
    0x53 as libc::c_int as uint8_t,
    0x8e as libc::c_int as uint8_t,
    0x62 as libc::c_int as uint8_t,
    0x4c as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0x88 as libc::c_int as uint8_t,
    0x44 as libc::c_int as uint8_t,
    0x8b as libc::c_int as uint8_t,
    0xfb as libc::c_int as uint8_t,
    0xa2 as libc::c_int as uint8_t,
    0x17 as libc::c_int as uint8_t,
    0x9a as libc::c_int as uint8_t,
    0x59 as libc::c_int as uint8_t,
    0xf5 as libc::c_int as uint8_t,
    0x87 as libc::c_int as uint8_t,
    0xb3 as libc::c_int as uint8_t,
    0x4f as libc::c_int as uint8_t,
    0x13 as libc::c_int as uint8_t,
    0x61 as libc::c_int as uint8_t,
    0x45 as libc::c_int as uint8_t,
    0x6d as libc::c_int as uint8_t,
    0x8d as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0x7d as libc::c_int as uint8_t,
    0x32 as libc::c_int as uint8_t,
    0xbd as libc::c_int as uint8_t,
    0x8f as libc::c_int as uint8_t,
    0x40 as libc::c_int as uint8_t,
    0xeb as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xb7 as libc::c_int as uint8_t,
    0x7b as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0xf0 as libc::c_int as uint8_t,
    0x95 as libc::c_int as uint8_t,
    0x21 as libc::c_int as uint8_t,
    0x22 as libc::c_int as uint8_t,
    0x5c as libc::c_int as uint8_t,
    0x6b as libc::c_int as uint8_t,
    0x4e as libc::c_int as uint8_t,
    0x82 as libc::c_int as uint8_t,
    0x54 as libc::c_int as uint8_t,
    0xd6 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x60 as libc::c_int as uint8_t,
    0xb2 as libc::c_int as uint8_t,
    0x1c as libc::c_int as uint8_t,
    0x73 as libc::c_int as uint8_t,
    0x56 as libc::c_int as uint8_t,
    0xc0 as libc::c_int as uint8_t,
    0x14 as libc::c_int as uint8_t,
    0xa7 as libc::c_int as uint8_t,
    0x8c as libc::c_int as uint8_t,
    0xf1 as libc::c_int as uint8_t,
    0xdc as libc::c_int as uint8_t,
    0x12 as libc::c_int as uint8_t,
    0x75 as libc::c_int as uint8_t,
    0xca as libc::c_int as uint8_t,
    0x1f as libc::c_int as uint8_t,
    0x3b as libc::c_int as uint8_t,
    0xbe as libc::c_int as uint8_t,
    0xe4 as libc::c_int as uint8_t,
    0xd1 as libc::c_int as uint8_t,
    0x42 as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0xd4 as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0xa3 as libc::c_int as uint8_t,
    0x3c as libc::c_int as uint8_t,
    0xb6 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x6f as libc::c_int as uint8_t,
    0xbf as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0xda as libc::c_int as uint8_t,
    0x46 as libc::c_int as uint8_t,
    0x69 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x57 as libc::c_int as uint8_t,
    0x27 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0x9b as libc::c_int as uint8_t,
    0xbc as libc::c_int as uint8_t,
    0x94 as libc::c_int as uint8_t,
    0x43 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0xf8 as libc::c_int as uint8_t,
    0x11 as libc::c_int as uint8_t,
    0xc7 as libc::c_int as uint8_t,
    0xf6 as libc::c_int as uint8_t,
    0x90 as libc::c_int as uint8_t,
    0xef as libc::c_int as uint8_t,
    0x3e as libc::c_int as uint8_t,
    0xe7 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0xc3 as libc::c_int as uint8_t,
    0xd5 as libc::c_int as uint8_t,
    0x2f as libc::c_int as uint8_t,
    0xc8 as libc::c_int as uint8_t,
    0x66 as libc::c_int as uint8_t,
    0x1e as libc::c_int as uint8_t,
    0xd7 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0xe8 as libc::c_int as uint8_t,
    0xea as libc::c_int as uint8_t,
    0xde as libc::c_int as uint8_t,
    0x80 as libc::c_int as uint8_t,
    0x52 as libc::c_int as uint8_t,
    0xee as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0x84 as libc::c_int as uint8_t,
    0xaa as libc::c_int as uint8_t,
    0x72 as libc::c_int as uint8_t,
    0xac as libc::c_int as uint8_t,
    0x35 as libc::c_int as uint8_t,
    0x4d as libc::c_int as uint8_t,
    0x6a as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x96 as libc::c_int as uint8_t,
    0x1a as libc::c_int as uint8_t,
    0xd2 as libc::c_int as uint8_t,
    0x71 as libc::c_int as uint8_t,
    0x5a as libc::c_int as uint8_t,
    0x15 as libc::c_int as uint8_t,
    0x49 as libc::c_int as uint8_t,
    0x74 as libc::c_int as uint8_t,
    0x4b as libc::c_int as uint8_t,
    0x9f as libc::c_int as uint8_t,
    0xd0 as libc::c_int as uint8_t,
    0x5e as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x18 as libc::c_int as uint8_t,
    0xa4 as libc::c_int as uint8_t,
    0xec as libc::c_int as uint8_t,
    0xc2 as libc::c_int as uint8_t,
    0xe0 as libc::c_int as uint8_t,
    0x41 as libc::c_int as uint8_t,
    0x6e as libc::c_int as uint8_t,
    0xf as libc::c_int as uint8_t,
    0x51 as libc::c_int as uint8_t,
    0xcb as libc::c_int as uint8_t,
    0xcc as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x91 as libc::c_int as uint8_t,
    0xaf as libc::c_int as uint8_t,
    0x50 as libc::c_int as uint8_t,
    0xa1 as libc::c_int as uint8_t,
    0xf4 as libc::c_int as uint8_t,
    0x70 as libc::c_int as uint8_t,
    0x39 as libc::c_int as uint8_t,
    0x99 as libc::c_int as uint8_t,
    0x7c as libc::c_int as uint8_t,
    0x3a as libc::c_int as uint8_t,
    0x85 as libc::c_int as uint8_t,
    0x23 as libc::c_int as uint8_t,
    0xb8 as libc::c_int as uint8_t,
    0xb4 as libc::c_int as uint8_t,
    0x7a as libc::c_int as uint8_t,
    0xfc as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x36 as libc::c_int as uint8_t,
    0x5b as libc::c_int as uint8_t,
    0x25 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x97 as libc::c_int as uint8_t,
    0x31 as libc::c_int as uint8_t,
    0x2d as libc::c_int as uint8_t,
    0x5d as libc::c_int as uint8_t,
    0xfa as libc::c_int as uint8_t,
    0x98 as libc::c_int as uint8_t,
    0xe3 as libc::c_int as uint8_t,
    0x8a as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0xae as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0xdf as libc::c_int as uint8_t,
    0x29 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x6c as libc::c_int as uint8_t,
    0xba as libc::c_int as uint8_t,
    0xc9 as libc::c_int as uint8_t,
    0xd3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0xe6 as libc::c_int as uint8_t,
    0xcf as libc::c_int as uint8_t,
    0xe1 as libc::c_int as uint8_t,
    0x9e as libc::c_int as uint8_t,
    0xa8 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x63 as libc::c_int as uint8_t,
    0x16 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3f as libc::c_int as uint8_t,
    0x58 as libc::c_int as uint8_t,
    0xe2 as libc::c_int as uint8_t,
    0x89 as libc::c_int as uint8_t,
    0xa9 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x38 as libc::c_int as uint8_t,
    0x34 as libc::c_int as uint8_t,
    0x1b as libc::c_int as uint8_t,
    0xab as libc::c_int as uint8_t,
    0x33 as libc::c_int as uint8_t,
    0xff as libc::c_int as uint8_t,
    0xb0 as libc::c_int as uint8_t,
    0xbb as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x5f as libc::c_int as uint8_t,
    0xb9 as libc::c_int as uint8_t,
    0xb1 as libc::c_int as uint8_t,
    0xcd as libc::c_int as uint8_t,
    0x2e as libc::c_int as uint8_t,
    0xc5 as libc::c_int as uint8_t,
    0xf3 as libc::c_int as uint8_t,
    0xdb as libc::c_int as uint8_t,
    0x47 as libc::c_int as uint8_t,
    0xe5 as libc::c_int as uint8_t,
    0xa5 as libc::c_int as uint8_t,
    0x9c as libc::c_int as uint8_t,
    0x77 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0xa6 as libc::c_int as uint8_t,
    0x20 as libc::c_int as uint8_t,
    0x68 as libc::c_int as uint8_t,
    0xfe as libc::c_int as uint8_t,
    0x7f as libc::c_int as uint8_t,
    0xc1 as libc::c_int as uint8_t,
    0xad as libc::c_int as uint8_t,
];
unsafe extern "C" fn RC2_set_key(
    mut key: *mut RC2_KEY,
    mut len: libc::c_int,
    mut data: *const uint8_t,
    mut bits: libc::c_int,
) {
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    let mut k: *mut uint8_t = 0 as *mut uint8_t;
    let mut ki: *mut uint16_t = 0 as *mut uint16_t;
    let mut c: libc::c_uint = 0;
    let mut d: libc::c_uint = 0;
    k = &mut *((*key).data).as_mut_ptr().offset(0 as libc::c_int as isize)
        as *mut uint16_t as *mut uint8_t;
    *k = 0 as libc::c_int as uint8_t;
    if len > 128 as libc::c_int {
        len = 128 as libc::c_int;
    }
    if bits <= 0 as libc::c_int {
        bits = 1024 as libc::c_int;
    }
    if bits > 1024 as libc::c_int {
        bits = 1024 as libc::c_int;
    }
    i = 0 as libc::c_int;
    while i < len {
        *k.offset(i as isize) = *data.offset(i as isize);
        i += 1;
        i;
    }
    d = *k.offset((len - 1 as libc::c_int) as isize) as libc::c_uint;
    j = 0 as libc::c_int;
    i = len;
    while i < 128 as libc::c_int {
        d = key_table[((*k.offset(j as isize) as libc::c_uint).wrapping_add(d)
            & 0xff as libc::c_int as libc::c_uint) as usize] as libc::c_uint;
        *k.offset(i as isize) = d as uint8_t;
        i += 1;
        i;
        j += 1;
        j;
    }
    j = bits + 7 as libc::c_int >> 3 as libc::c_int;
    i = 128 as libc::c_int - j;
    c = (0xff as libc::c_int >> (-bits & 0x7 as libc::c_int)) as libc::c_uint;
    d = key_table[(*k.offset(i as isize) as libc::c_uint & c) as usize] as libc::c_uint;
    *k.offset(i as isize) = d as uint8_t;
    loop {
        let fresh88 = i;
        i = i - 1;
        if !(fresh88 != 0) {
            break;
        }
        d = key_table[(*k.offset((i + j) as isize) as libc::c_uint ^ d) as usize]
            as libc::c_uint;
        *k.offset(i as isize) = d as uint8_t;
    }
    ki = &mut *((*key).data).as_mut_ptr().offset(63 as libc::c_int as isize)
        as *mut uint16_t;
    i = 127 as libc::c_int;
    while i >= 0 as libc::c_int {
        let fresh89 = ki;
        ki = ki.offset(-1);
        *fresh89 = (((*k.offset(i as isize) as libc::c_int) << 8 as libc::c_int
            | *k.offset((i - 1 as libc::c_int) as isize) as libc::c_int)
            & 0xffff as libc::c_int) as uint16_t;
        i -= 2 as libc::c_int;
    }
}
unsafe extern "C" fn rc2_init_key(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut key: *const uint8_t,
    mut iv: *const uint8_t,
    mut enc: libc::c_int,
) -> libc::c_int {
    let mut rc2_key: *mut EVP_RC2_KEY = (*ctx).cipher_data as *mut EVP_RC2_KEY;
    RC2_set_key(
        &mut (*rc2_key).ks,
        EVP_CIPHER_CTX_key_length(ctx) as libc::c_int,
        key,
        (*rc2_key).key_bits,
    );
    return 1 as libc::c_int;
}
unsafe extern "C" fn rc2_cbc_cipher(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut inl: size_t,
) -> libc::c_int {
    let mut key: *mut EVP_RC2_KEY = (*ctx).cipher_data as *mut EVP_RC2_KEY;
    static mut kChunkSize: size_t = 0x10000 as libc::c_int as size_t;
    while inl >= kChunkSize {
        RC2_cbc_encrypt(
            in_0,
            out,
            kChunkSize,
            &mut (*key).ks,
            ((*ctx).iv).as_mut_ptr(),
            (*ctx).encrypt,
        );
        inl = inl.wrapping_sub(kChunkSize);
        in_0 = in_0.offset(kChunkSize as isize);
        out = out.offset(kChunkSize as isize);
    }
    if inl != 0 {
        RC2_cbc_encrypt(
            in_0,
            out,
            inl,
            &mut (*key).ks,
            ((*ctx).iv).as_mut_ptr(),
            (*ctx).encrypt,
        );
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn rc2_ctrl(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut type_0: libc::c_int,
    mut arg: libc::c_int,
    mut ptr: *mut libc::c_void,
) -> libc::c_int {
    let mut key: *mut EVP_RC2_KEY = (*ctx).cipher_data as *mut EVP_RC2_KEY;
    match type_0 {
        0 => {
            (*key)
                .key_bits = (EVP_CIPHER_CTX_key_length(ctx))
                .wrapping_mul(8 as libc::c_int as libc::c_uint) as libc::c_int;
            return 1 as libc::c_int;
        }
        3 => {
            (*key).key_bits = arg;
            return 1 as libc::c_int;
        }
        _ => return -(1 as libc::c_int),
    };
}
static mut rc2_40_cbc: EVP_CIPHER = unsafe {
    {
        let mut init = evp_cipher_st {
            nid: 98 as libc::c_int,
            block_size: 8 as libc::c_int as libc::c_uint,
            key_len: 5 as libc::c_int as libc::c_uint,
            iv_len: 8 as libc::c_int as libc::c_uint,
            ctx_size: ::core::mem::size_of::<EVP_RC2_KEY>() as libc::c_ulong
                as libc::c_uint,
            flags: (0x2 as libc::c_int | 0x40 as libc::c_int | 0x200 as libc::c_int)
                as uint32_t,
            init: Some(
                rc2_init_key
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *const uint8_t,
                        *const uint8_t,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            cipher: Some(
                rc2_cbc_cipher
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *mut uint8_t,
                        *const uint8_t,
                        size_t,
                    ) -> libc::c_int,
            ),
            cleanup: None,
            ctrl: Some(
                rc2_ctrl
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        libc::c_int,
                        libc::c_int,
                        *mut libc::c_void,
                    ) -> libc::c_int,
            ),
        };
        init
    }
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_rc2_40_cbc() -> *const EVP_CIPHER {
    return &rc2_40_cbc;
}
static mut rc2_cbc: EVP_CIPHER = unsafe {
    {
        let mut init = evp_cipher_st {
            nid: 37 as libc::c_int,
            block_size: 8 as libc::c_int as libc::c_uint,
            key_len: 16 as libc::c_int as libc::c_uint,
            iv_len: 8 as libc::c_int as libc::c_uint,
            ctx_size: ::core::mem::size_of::<EVP_RC2_KEY>() as libc::c_ulong
                as libc::c_uint,
            flags: (0x2 as libc::c_int | 0x40 as libc::c_int | 0x200 as libc::c_int)
                as uint32_t,
            init: Some(
                rc2_init_key
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *const uint8_t,
                        *const uint8_t,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            cipher: Some(
                rc2_cbc_cipher
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *mut uint8_t,
                        *const uint8_t,
                        size_t,
                    ) -> libc::c_int,
            ),
            cleanup: None,
            ctrl: Some(
                rc2_ctrl
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        libc::c_int,
                        libc::c_int,
                        *mut libc::c_void,
                    ) -> libc::c_int,
            ),
        };
        init
    }
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_rc2_cbc() -> *const EVP_CIPHER {
    return &rc2_cbc;
}
