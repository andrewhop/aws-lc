#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
pub type __uint32_t = libc::c_uint;
pub type uint32_t = __uint32_t;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn UTF8_getc(
    mut str: *const libc::c_uchar,
    mut len: libc::c_int,
    mut val: *mut uint32_t,
) -> libc::c_int {
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut value: uint32_t = 0;
    let mut ret: libc::c_int = 0;
    if len <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    p = str;
    if *p as libc::c_int & 0x80 as libc::c_int == 0 as libc::c_int {
        let fresh0 = p;
        p = p.offset(1);
        value = (*fresh0 as libc::c_int & 0x7f as libc::c_int) as uint32_t;
        ret = 1 as libc::c_int;
    } else if *p as libc::c_int & 0xe0 as libc::c_int == 0xc0 as libc::c_int {
        if len < 2 as libc::c_int {
            return -(1 as libc::c_int);
        }
        if *p.offset(1 as libc::c_int as isize) as libc::c_int & 0xc0 as libc::c_int
            != 0x80 as libc::c_int
        {
            return -(3 as libc::c_int);
        }
        let fresh1 = p;
        p = p.offset(1);
        value = ((*fresh1 as libc::c_int & 0x1f as libc::c_int) << 6 as libc::c_int)
            as uint32_t;
        let fresh2 = p;
        p = p.offset(1);
        value |= (*fresh2 as libc::c_int & 0x3f as libc::c_int) as uint32_t;
        if value < 0x80 as libc::c_int as uint32_t {
            return -(4 as libc::c_int);
        }
        ret = 2 as libc::c_int;
    } else if *p as libc::c_int & 0xf0 as libc::c_int == 0xe0 as libc::c_int {
        if len < 3 as libc::c_int {
            return -(1 as libc::c_int);
        }
        if *p.offset(1 as libc::c_int as isize) as libc::c_int & 0xc0 as libc::c_int
            != 0x80 as libc::c_int
            || *p.offset(2 as libc::c_int as isize) as libc::c_int & 0xc0 as libc::c_int
                != 0x80 as libc::c_int
        {
            return -(3 as libc::c_int);
        }
        let fresh3 = p;
        p = p.offset(1);
        value = ((*fresh3 as libc::c_int & 0xf as libc::c_int) << 12 as libc::c_int)
            as uint32_t;
        let fresh4 = p;
        p = p.offset(1);
        value
            |= ((*fresh4 as libc::c_int & 0x3f as libc::c_int) << 6 as libc::c_int)
                as uint32_t;
        let fresh5 = p;
        p = p.offset(1);
        value |= (*fresh5 as libc::c_int & 0x3f as libc::c_int) as uint32_t;
        if value < 0x800 as libc::c_int as uint32_t {
            return -(4 as libc::c_int);
        }
        ret = 3 as libc::c_int;
    } else if *p as libc::c_int & 0xf8 as libc::c_int == 0xf0 as libc::c_int {
        if len < 4 as libc::c_int {
            return -(1 as libc::c_int);
        }
        if *p.offset(1 as libc::c_int as isize) as libc::c_int & 0xc0 as libc::c_int
            != 0x80 as libc::c_int
            || *p.offset(2 as libc::c_int as isize) as libc::c_int & 0xc0 as libc::c_int
                != 0x80 as libc::c_int
            || *p.offset(3 as libc::c_int as isize) as libc::c_int & 0xc0 as libc::c_int
                != 0x80 as libc::c_int
        {
            return -(3 as libc::c_int);
        }
        let fresh6 = p;
        p = p.offset(1);
        value = ((*fresh6 as libc::c_int & 0x7 as libc::c_int) as uint32_t)
            << 18 as libc::c_int;
        let fresh7 = p;
        p = p.offset(1);
        value
            |= ((*fresh7 as libc::c_int & 0x3f as libc::c_int) << 12 as libc::c_int)
                as uint32_t;
        let fresh8 = p;
        p = p.offset(1);
        value
            |= ((*fresh8 as libc::c_int & 0x3f as libc::c_int) << 6 as libc::c_int)
                as uint32_t;
        let fresh9 = p;
        p = p.offset(1);
        value |= (*fresh9 as libc::c_int & 0x3f as libc::c_int) as uint32_t;
        if value < 0x10000 as libc::c_int as uint32_t {
            return -(4 as libc::c_int);
        }
        ret = 4 as libc::c_int;
    } else if *p as libc::c_int & 0xfc as libc::c_int == 0xf8 as libc::c_int {
        if len < 5 as libc::c_int {
            return -(1 as libc::c_int);
        }
        if *p.offset(1 as libc::c_int as isize) as libc::c_int & 0xc0 as libc::c_int
            != 0x80 as libc::c_int
            || *p.offset(2 as libc::c_int as isize) as libc::c_int & 0xc0 as libc::c_int
                != 0x80 as libc::c_int
            || *p.offset(3 as libc::c_int as isize) as libc::c_int & 0xc0 as libc::c_int
                != 0x80 as libc::c_int
            || *p.offset(4 as libc::c_int as isize) as libc::c_int & 0xc0 as libc::c_int
                != 0x80 as libc::c_int
        {
            return -(3 as libc::c_int);
        }
        let fresh10 = p;
        p = p.offset(1);
        value = ((*fresh10 as libc::c_int & 0x3 as libc::c_int) as uint32_t)
            << 24 as libc::c_int;
        let fresh11 = p;
        p = p.offset(1);
        value
            |= ((*fresh11 as libc::c_int & 0x3f as libc::c_int) as uint32_t)
                << 18 as libc::c_int;
        let fresh12 = p;
        p = p.offset(1);
        value
            |= ((*fresh12 as libc::c_int & 0x3f as libc::c_int) as uint32_t)
                << 12 as libc::c_int;
        let fresh13 = p;
        p = p.offset(1);
        value
            |= ((*fresh13 as libc::c_int & 0x3f as libc::c_int) << 6 as libc::c_int)
                as uint32_t;
        let fresh14 = p;
        p = p.offset(1);
        value |= (*fresh14 as libc::c_int & 0x3f as libc::c_int) as uint32_t;
        if value < 0x200000 as libc::c_int as uint32_t {
            return -(4 as libc::c_int);
        }
        ret = 5 as libc::c_int;
    } else if *p as libc::c_int & 0xfe as libc::c_int == 0xfc as libc::c_int {
        if len < 6 as libc::c_int {
            return -(1 as libc::c_int);
        }
        if *p.offset(1 as libc::c_int as isize) as libc::c_int & 0xc0 as libc::c_int
            != 0x80 as libc::c_int
            || *p.offset(2 as libc::c_int as isize) as libc::c_int & 0xc0 as libc::c_int
                != 0x80 as libc::c_int
            || *p.offset(3 as libc::c_int as isize) as libc::c_int & 0xc0 as libc::c_int
                != 0x80 as libc::c_int
            || *p.offset(4 as libc::c_int as isize) as libc::c_int & 0xc0 as libc::c_int
                != 0x80 as libc::c_int
            || *p.offset(5 as libc::c_int as isize) as libc::c_int & 0xc0 as libc::c_int
                != 0x80 as libc::c_int
        {
            return -(3 as libc::c_int);
        }
        let fresh15 = p;
        p = p.offset(1);
        value = ((*fresh15 as libc::c_int & 0x1 as libc::c_int) as uint32_t)
            << 30 as libc::c_int;
        let fresh16 = p;
        p = p.offset(1);
        value
            |= ((*fresh16 as libc::c_int & 0x3f as libc::c_int) as uint32_t)
                << 24 as libc::c_int;
        let fresh17 = p;
        p = p.offset(1);
        value
            |= ((*fresh17 as libc::c_int & 0x3f as libc::c_int) as uint32_t)
                << 18 as libc::c_int;
        let fresh18 = p;
        p = p.offset(1);
        value
            |= ((*fresh18 as libc::c_int & 0x3f as libc::c_int) as uint32_t)
                << 12 as libc::c_int;
        let fresh19 = p;
        p = p.offset(1);
        value
            |= ((*fresh19 as libc::c_int & 0x3f as libc::c_int) << 6 as libc::c_int)
                as uint32_t;
        let fresh20 = p;
        p = p.offset(1);
        value |= (*fresh20 as libc::c_int & 0x3f as libc::c_int) as uint32_t;
        if value < 0x4000000 as libc::c_int as uint32_t {
            return -(4 as libc::c_int);
        }
        ret = 6 as libc::c_int;
    } else {
        return -(2 as libc::c_int)
    }
    *val = value;
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn UTF8_putc(
    mut str: *mut libc::c_uchar,
    mut len: libc::c_int,
    mut value: uint32_t,
) -> libc::c_int {
    if str.is_null() {
        len = 6 as libc::c_int;
    } else if len <= 0 as libc::c_int {
        return -(1 as libc::c_int)
    }
    if value < 0x80 as libc::c_int as uint32_t {
        if !str.is_null() {
            *str = value as libc::c_uchar;
        }
        return 1 as libc::c_int;
    }
    if value < 0x800 as libc::c_int as uint32_t {
        if len < 2 as libc::c_int {
            return -(1 as libc::c_int);
        }
        if !str.is_null() {
            let fresh21 = str;
            str = str.offset(1);
            *fresh21 = (value >> 6 as libc::c_int & 0x1f as libc::c_int as uint32_t
                | 0xc0 as libc::c_int as uint32_t) as libc::c_uchar;
            *str = (value & 0x3f as libc::c_int as uint32_t
                | 0x80 as libc::c_int as uint32_t) as libc::c_uchar;
        }
        return 2 as libc::c_int;
    }
    if value < 0x10000 as libc::c_int as uint32_t {
        if len < 3 as libc::c_int {
            return -(1 as libc::c_int);
        }
        if !str.is_null() {
            let fresh22 = str;
            str = str.offset(1);
            *fresh22 = (value >> 12 as libc::c_int & 0xf as libc::c_int as uint32_t
                | 0xe0 as libc::c_int as uint32_t) as libc::c_uchar;
            let fresh23 = str;
            str = str.offset(1);
            *fresh23 = (value >> 6 as libc::c_int & 0x3f as libc::c_int as uint32_t
                | 0x80 as libc::c_int as uint32_t) as libc::c_uchar;
            *str = (value & 0x3f as libc::c_int as uint32_t
                | 0x80 as libc::c_int as uint32_t) as libc::c_uchar;
        }
        return 3 as libc::c_int;
    }
    if value < 0x200000 as libc::c_int as uint32_t {
        if len < 4 as libc::c_int {
            return -(1 as libc::c_int);
        }
        if !str.is_null() {
            let fresh24 = str;
            str = str.offset(1);
            *fresh24 = (value >> 18 as libc::c_int & 0x7 as libc::c_int as uint32_t
                | 0xf0 as libc::c_int as uint32_t) as libc::c_uchar;
            let fresh25 = str;
            str = str.offset(1);
            *fresh25 = (value >> 12 as libc::c_int & 0x3f as libc::c_int as uint32_t
                | 0x80 as libc::c_int as uint32_t) as libc::c_uchar;
            let fresh26 = str;
            str = str.offset(1);
            *fresh26 = (value >> 6 as libc::c_int & 0x3f as libc::c_int as uint32_t
                | 0x80 as libc::c_int as uint32_t) as libc::c_uchar;
            *str = (value & 0x3f as libc::c_int as uint32_t
                | 0x80 as libc::c_int as uint32_t) as libc::c_uchar;
        }
        return 4 as libc::c_int;
    }
    if value < 0x4000000 as libc::c_int as uint32_t {
        if len < 5 as libc::c_int {
            return -(1 as libc::c_int);
        }
        if !str.is_null() {
            let fresh27 = str;
            str = str.offset(1);
            *fresh27 = (value >> 24 as libc::c_int & 0x3 as libc::c_int as uint32_t
                | 0xf8 as libc::c_int as uint32_t) as libc::c_uchar;
            let fresh28 = str;
            str = str.offset(1);
            *fresh28 = (value >> 18 as libc::c_int & 0x3f as libc::c_int as uint32_t
                | 0x80 as libc::c_int as uint32_t) as libc::c_uchar;
            let fresh29 = str;
            str = str.offset(1);
            *fresh29 = (value >> 12 as libc::c_int & 0x3f as libc::c_int as uint32_t
                | 0x80 as libc::c_int as uint32_t) as libc::c_uchar;
            let fresh30 = str;
            str = str.offset(1);
            *fresh30 = (value >> 6 as libc::c_int & 0x3f as libc::c_int as uint32_t
                | 0x80 as libc::c_int as uint32_t) as libc::c_uchar;
            *str = (value & 0x3f as libc::c_int as uint32_t
                | 0x80 as libc::c_int as uint32_t) as libc::c_uchar;
        }
        return 5 as libc::c_int;
    }
    if len < 6 as libc::c_int {
        return -(1 as libc::c_int);
    }
    if !str.is_null() {
        let fresh31 = str;
        str = str.offset(1);
        *fresh31 = (value >> 30 as libc::c_int & 0x1 as libc::c_int as uint32_t
            | 0xfc as libc::c_int as uint32_t) as libc::c_uchar;
        let fresh32 = str;
        str = str.offset(1);
        *fresh32 = (value >> 24 as libc::c_int & 0x3f as libc::c_int as uint32_t
            | 0x80 as libc::c_int as uint32_t) as libc::c_uchar;
        let fresh33 = str;
        str = str.offset(1);
        *fresh33 = (value >> 18 as libc::c_int & 0x3f as libc::c_int as uint32_t
            | 0x80 as libc::c_int as uint32_t) as libc::c_uchar;
        let fresh34 = str;
        str = str.offset(1);
        *fresh34 = (value >> 12 as libc::c_int & 0x3f as libc::c_int as uint32_t
            | 0x80 as libc::c_int as uint32_t) as libc::c_uchar;
        let fresh35 = str;
        str = str.offset(1);
        *fresh35 = (value >> 6 as libc::c_int & 0x3f as libc::c_int as uint32_t
            | 0x80 as libc::c_int as uint32_t) as libc::c_uchar;
        *str = (value & 0x3f as libc::c_int as uint32_t
            | 0x80 as libc::c_int as uint32_t) as libc::c_uchar;
    }
    return 6 as libc::c_int;
}
