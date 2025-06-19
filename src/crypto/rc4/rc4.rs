#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rc4_key_st {
    pub x: uint32_t,
    pub y: uint32_t,
    pub data: [uint32_t; 256],
}
pub type RC4_KEY = rc4_key_st;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn RC4(
    mut key: *mut RC4_KEY,
    mut len: size_t,
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
) {
    let mut x: uint32_t = (*key).x;
    let mut y: uint32_t = (*key).y;
    let mut d: *mut uint32_t = ((*key).data).as_mut_ptr();
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < len {
        x = x.wrapping_add(1 as libc::c_int as uint32_t)
            & 0xff as libc::c_int as uint32_t;
        let mut tx: uint32_t = *d.offset(x as isize);
        y = tx.wrapping_add(y) & 0xff as libc::c_int as uint32_t;
        let mut ty: uint32_t = *d.offset(y as isize);
        *d.offset(x as isize) = ty;
        *d.offset(y as isize) = tx;
        *out
            .offset(
                i as isize,
            ) = (*d
            .offset((tx.wrapping_add(ty) & 0xff as libc::c_int as uint32_t) as isize)
            ^ *in_0.offset(i as isize) as uint32_t) as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
    (*key).x = x;
    (*key).y = y;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn RC4_set_key(
    mut rc4key: *mut RC4_KEY,
    mut len: libc::c_uint,
    mut key: *const uint8_t,
) {
    let mut d: *mut uint32_t = &mut *((*rc4key).data)
        .as_mut_ptr()
        .offset(0 as libc::c_int as isize) as *mut uint32_t;
    (*rc4key).x = 0 as libc::c_int as uint32_t;
    (*rc4key).y = 0 as libc::c_int as uint32_t;
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while i < 256 as libc::c_int as libc::c_uint {
        *d.offset(i as isize) = i;
        i = i.wrapping_add(1);
        i;
    }
    let mut id1: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut id2: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut i_0: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while i_0 < 256 as libc::c_int as libc::c_uint {
        let mut tmp: uint32_t = *d.offset(i_0 as isize);
        id2 = (*key.offset(id1 as isize) as uint32_t).wrapping_add(tmp).wrapping_add(id2)
            & 0xff as libc::c_int as libc::c_uint;
        id1 = id1.wrapping_add(1);
        if id1 == len {
            id1 = 0 as libc::c_int as libc::c_uint;
        }
        *d.offset(i_0 as isize) = *d.offset(id2 as isize);
        *d.offset(id2 as isize) = tmp;
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
}
