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
    fn qsort(
        __base: *mut libc::c_void,
        __nmemb: size_t,
        __size: size_t,
        __compar: __compar_fn_t,
    );
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_get_u8(cbs: *mut CBS, out: *mut uint8_t) -> libc::c_int;
    fn CBS_get_u64_decimal(cbs: *mut CBS, out: *mut uint64_t) -> libc::c_int;
    fn CBS_get_any_asn1_element(
        cbs: *mut CBS,
        out: *mut CBS,
        out_tag: *mut CBS_ASN1_TAG,
        out_header_len: *mut size_t,
    ) -> libc::c_int;
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
    fn memmove(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_calloc(num: size_t, size: size_t) -> *mut libc::c_void;
    fn OPENSSL_realloc(ptr: *mut libc::c_void, new_size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_memdup(data: *const libc::c_void, size: size_t) -> *mut libc::c_void;
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
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type int64_t = __int64_t;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type __compar_fn_t = Option::<
    unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> libc::c_int,
>;
pub type CBS_ASN1_TAG = uint32_t;
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
pub struct cbs_st {
    pub data: *const uint8_t,
    pub len: size_t,
}
pub type CBS = cbs_st;
#[inline]
unsafe extern "C" fn CRYPTO_bswap2(mut x: uint16_t) -> uint16_t {
    return x.swap_bytes();
}
#[inline]
unsafe extern "C" fn CRYPTO_bswap4(mut x: uint32_t) -> uint32_t {
    return x.swap_bytes();
}
#[inline]
unsafe extern "C" fn CRYPTO_bswap8(mut x: uint64_t) -> uint64_t {
    return x.swap_bytes();
}
#[inline]
unsafe extern "C" fn OPENSSL_memcmp(
    mut s1: *const libc::c_void,
    mut s2: *const libc::c_void,
    mut n: size_t,
) -> libc::c_int {
    if n == 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    return memcmp(s1, s2, n);
}
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
unsafe extern "C" fn OPENSSL_memmove(
    mut dst: *mut libc::c_void,
    mut src: *const libc::c_void,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return dst;
    }
    return memmove(dst, src, n);
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_zero(mut cbb: *mut CBB) {
    OPENSSL_memset(
        cbb as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<CBB>() as libc::c_ulong,
    );
}
unsafe extern "C" fn cbb_init(
    mut cbb: *mut CBB,
    mut buf: *mut uint8_t,
    mut cap: size_t,
    mut can_resize: libc::c_int,
) {
    (*cbb).is_child = 0 as libc::c_int as libc::c_char;
    (*cbb).child = 0 as *mut CBB;
    (*cbb).u.base.buf = buf;
    (*cbb).u.base.len = 0 as libc::c_int as size_t;
    (*cbb).u.base.cap = cap;
    ((*cbb).u.base).set_can_resize(can_resize as libc::c_uint);
    ((*cbb).u.base).set_error(0 as libc::c_int as libc::c_uint);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_init(
    mut cbb: *mut CBB,
    mut initial_capacity: size_t,
) -> libc::c_int {
    CBB_zero(cbb);
    let mut buf: *mut uint8_t = OPENSSL_malloc(initial_capacity) as *mut uint8_t;
    if initial_capacity > 0 as libc::c_int as size_t && buf.is_null() {
        return 0 as libc::c_int;
    }
    cbb_init(cbb, buf, initial_capacity, 1 as libc::c_int);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_init_fixed(
    mut cbb: *mut CBB,
    mut buf: *mut uint8_t,
    mut len: size_t,
) -> libc::c_int {
    CBB_zero(cbb);
    cbb_init(cbb, buf, len, 0 as libc::c_int);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_cleanup(mut cbb: *mut CBB) {
    if (*cbb).is_child == 0 {} else {
        __assert_fail(
            b"!cbb->is_child\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0" as *const u8
                as *const libc::c_char,
            62 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 24],
                &[libc::c_char; 24],
            >(b"void CBB_cleanup(CBB *)\0"))
                .as_ptr(),
        );
    }
    'c_1884: {
        if (*cbb).is_child == 0 {} else {
            __assert_fail(
                b"!cbb->is_child\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0"
                    as *const u8 as *const libc::c_char,
                62 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 24],
                    &[libc::c_char; 24],
                >(b"void CBB_cleanup(CBB *)\0"))
                    .as_ptr(),
            );
        }
    };
    if (*cbb).is_child != 0 {
        return;
    }
    if ((*cbb).u.base).can_resize() != 0 {
        OPENSSL_free((*cbb).u.base.buf as *mut libc::c_void);
    }
}
unsafe extern "C" fn cbb_buffer_reserve(
    mut base: *mut cbb_buffer_st,
    mut out: *mut *mut uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut current_block: u64;
    if base.is_null() {
        return 0 as libc::c_int;
    }
    let mut newlen: size_t = ((*base).len).wrapping_add(len);
    if newlen < (*base).len {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0" as *const u8
                as *const libc::c_char,
            81 as libc::c_int as libc::c_uint,
        );
    } else {
        if newlen > (*base).cap {
            if (*base).can_resize() == 0 {
                ERR_put_error(
                    14 as libc::c_int,
                    0 as libc::c_int,
                    5 as libc::c_int | 64 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0"
                        as *const u8 as *const libc::c_char,
                    87 as libc::c_int as libc::c_uint,
                );
                current_block = 9183633434687261800;
            } else {
                let mut newcap: size_t = (*base).cap * 2 as libc::c_int as size_t;
                if newcap < (*base).cap || newcap < newlen {
                    newcap = newlen;
                }
                let mut newbuf: *mut uint8_t = OPENSSL_realloc(
                    (*base).buf as *mut libc::c_void,
                    newcap,
                ) as *mut uint8_t;
                if newbuf.is_null() {
                    current_block = 9183633434687261800;
                } else {
                    (*base).buf = newbuf;
                    (*base).cap = newcap;
                    current_block = 12800627514080957624;
                }
            }
        } else {
            current_block = 12800627514080957624;
        }
        match current_block {
            9183633434687261800 => {}
            _ => {
                if !out.is_null() {
                    *out = ((*base).buf).offset((*base).len as isize);
                }
                return 1 as libc::c_int;
            }
        }
    }
    (*base).set_error(1 as libc::c_int as libc::c_uint);
    return 0 as libc::c_int;
}
unsafe extern "C" fn cbb_buffer_add(
    mut base: *mut cbb_buffer_st,
    mut out: *mut *mut uint8_t,
    mut len: size_t,
) -> libc::c_int {
    if cbb_buffer_reserve(base, out, len) == 0 {
        return 0 as libc::c_int;
    }
    (*base).len = ((*base).len).wrapping_add(len);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_finish(
    mut cbb: *mut CBB,
    mut out_data: *mut *mut uint8_t,
    mut out_len: *mut size_t,
) -> libc::c_int {
    if (*cbb).is_child != 0 {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0" as *const u8
                as *const libc::c_char,
            127 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if CBB_flush(cbb) == 0 {
        return 0 as libc::c_int;
    }
    if ((*cbb).u.base).can_resize() as libc::c_int != 0
        && (out_data.is_null() || out_len.is_null())
    {
        return 0 as libc::c_int;
    }
    if !out_data.is_null() {
        *out_data = (*cbb).u.base.buf;
    }
    if !out_len.is_null() {
        *out_len = (*cbb).u.base.len;
    }
    (*cbb).u.base.buf = 0 as *mut uint8_t;
    CBB_cleanup(cbb);
    return 1 as libc::c_int;
}
unsafe extern "C" fn cbb_get_base(mut cbb: *mut CBB) -> *mut cbb_buffer_st {
    if (*cbb).is_child != 0 {
        return (*cbb).u.child.base;
    }
    return &mut (*cbb).u.base;
}
unsafe extern "C" fn cbb_on_error(mut cbb: *mut CBB) {
    let ref mut fresh0 = *cbb_get_base(cbb);
    (*fresh0).set_error(1 as libc::c_int as libc::c_uint);
    (*cbb).child = 0 as *mut CBB;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_flush(mut cbb: *mut CBB) -> libc::c_int {
    let mut len: size_t = 0;
    let mut current_block: u64;
    let mut base: *mut cbb_buffer_st = cbb_get_base(cbb);
    if base.is_null() || (*base).error() as libc::c_int != 0 {
        return 0 as libc::c_int;
    }
    if ((*cbb).child).is_null() {
        return 1 as libc::c_int;
    }
    if (*(*cbb).child).is_child != 0 {} else {
        __assert_fail(
            b"cbb->child->is_child\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0" as *const u8
                as *const libc::c_char,
            198 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 21],
                &[libc::c_char; 21],
            >(b"int CBB_flush(CBB *)\0"))
                .as_ptr(),
        );
    }
    'c_2796: {
        if (*(*cbb).child).is_child != 0 {} else {
            __assert_fail(
                b"cbb->child->is_child\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0"
                    as *const u8 as *const libc::c_char,
                198 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 21],
                    &[libc::c_char; 21],
                >(b"int CBB_flush(CBB *)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut child: *mut cbb_child_st = &mut (*(*cbb).child).u.child;
    if (*child).base == base {} else {
        __assert_fail(
            b"child->base == base\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0" as *const u8
                as *const libc::c_char,
            200 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 21],
                &[libc::c_char; 21],
            >(b"int CBB_flush(CBB *)\0"))
                .as_ptr(),
        );
    }
    'c_2753: {
        if (*child).base == base {} else {
            __assert_fail(
                b"child->base == base\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0"
                    as *const u8 as *const libc::c_char,
                200 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 21],
                    &[libc::c_char; 21],
                >(b"int CBB_flush(CBB *)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut child_start: size_t = ((*child).offset)
        .wrapping_add((*child).pending_len_len as size_t);
    if !(CBB_flush((*cbb).child) == 0 || child_start < (*child).offset
        || (*base).len < child_start)
    {
        len = ((*base).len).wrapping_sub(child_start);
        if (*child).pending_is_asn1() != 0 {
            let mut len_len: uint8_t = 0;
            let mut initial_length_byte: uint8_t = 0;
            if (*child).pending_len_len as libc::c_int == 1 as libc::c_int {} else {
                __assert_fail(
                    b"child->pending_len_len == 1\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0"
                        as *const u8 as *const libc::c_char,
                    218 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 21],
                        &[libc::c_char; 21],
                    >(b"int CBB_flush(CBB *)\0"))
                        .as_ptr(),
                );
            }
            'c_2680: {
                if (*child).pending_len_len as libc::c_int == 1 as libc::c_int {} else {
                    __assert_fail(
                        b"child->pending_len_len == 1\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0"
                            as *const u8 as *const libc::c_char,
                        218 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 21],
                            &[libc::c_char; 21],
                        >(b"int CBB_flush(CBB *)\0"))
                            .as_ptr(),
                    );
                }
            };
            if len > 0xfffffffe as libc::c_uint as size_t {
                ERR_put_error(
                    14 as libc::c_int,
                    0 as libc::c_int,
                    5 as libc::c_int | 64 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0"
                        as *const u8 as *const libc::c_char,
                    221 as libc::c_int as libc::c_uint,
                );
                current_block = 16809624722846540950;
            } else {
                if len > 0xffffff as libc::c_int as size_t {
                    len_len = 5 as libc::c_int as uint8_t;
                    initial_length_byte = (0x80 as libc::c_int | 4 as libc::c_int)
                        as uint8_t;
                } else if len > 0xffff as libc::c_int as size_t {
                    len_len = 4 as libc::c_int as uint8_t;
                    initial_length_byte = (0x80 as libc::c_int | 3 as libc::c_int)
                        as uint8_t;
                } else if len > 0xff as libc::c_int as size_t {
                    len_len = 3 as libc::c_int as uint8_t;
                    initial_length_byte = (0x80 as libc::c_int | 2 as libc::c_int)
                        as uint8_t;
                } else if len > 0x7f as libc::c_int as size_t {
                    len_len = 2 as libc::c_int as uint8_t;
                    initial_length_byte = (0x80 as libc::c_int | 1 as libc::c_int)
                        as uint8_t;
                } else {
                    len_len = 1 as libc::c_int as uint8_t;
                    initial_length_byte = len as uint8_t;
                    len = 0 as libc::c_int as size_t;
                }
                if len_len as libc::c_int != 1 as libc::c_int {
                    let mut extra_bytes: size_t = (len_len as libc::c_int
                        - 1 as libc::c_int) as size_t;
                    if cbb_buffer_add(base, 0 as *mut *mut uint8_t, extra_bytes) == 0 {
                        current_block = 16809624722846540950;
                    } else {
                        OPENSSL_memmove(
                            ((*base).buf)
                                .offset(child_start as isize)
                                .offset(extra_bytes as isize) as *mut libc::c_void,
                            ((*base).buf).offset(child_start as isize)
                                as *const libc::c_void,
                            len,
                        );
                        current_block = 17281240262373992796;
                    }
                } else {
                    current_block = 17281240262373992796;
                }
                match current_block {
                    16809624722846540950 => {}
                    _ => {
                        let fresh1 = (*child).offset;
                        (*child).offset = ((*child).offset).wrapping_add(1);
                        *((*base).buf).offset(fresh1 as isize) = initial_length_byte;
                        (*child)
                            .pending_len_len = (len_len as libc::c_int
                            - 1 as libc::c_int) as uint8_t;
                        current_block = 8704759739624374314;
                    }
                }
            }
        } else {
            current_block = 8704759739624374314;
        }
        match current_block {
            16809624722846540950 => {}
            _ => {
                let mut i: size_t = ((*child).pending_len_len as libc::c_int
                    - 1 as libc::c_int) as size_t;
                while i < (*child).pending_len_len as size_t {
                    *((*base).buf)
                        .offset(
                            ((*child).offset).wrapping_add(i) as isize,
                        ) = len as uint8_t;
                    len >>= 8 as libc::c_int;
                    i = i.wrapping_sub(1);
                    i;
                }
                if len != 0 as libc::c_int as size_t {
                    ERR_put_error(
                        14 as libc::c_int,
                        0 as libc::c_int,
                        5 as libc::c_int | 64 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0"
                            as *const u8 as *const libc::c_char,
                        260 as libc::c_int as libc::c_uint,
                    );
                } else {
                    (*child).base = 0 as *mut cbb_buffer_st;
                    (*cbb).child = 0 as *mut CBB;
                    return 1 as libc::c_int;
                }
            }
        }
    }
    cbb_on_error(cbb);
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_data(mut cbb: *const CBB) -> *const uint8_t {
    if ((*cbb).child).is_null() {} else {
        __assert_fail(
            b"cbb->child == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0" as *const u8
                as *const libc::c_char,
            275 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 37],
                &[libc::c_char; 37],
            >(b"const uint8_t *CBB_data(const CBB *)\0"))
                .as_ptr(),
        );
    }
    'c_2931: {
        if ((*cbb).child).is_null() {} else {
            __assert_fail(
                b"cbb->child == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0"
                    as *const u8 as *const libc::c_char,
                275 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 37],
                    &[libc::c_char; 37],
                >(b"const uint8_t *CBB_data(const CBB *)\0"))
                    .as_ptr(),
            );
        }
    };
    if (*cbb).is_child != 0 {
        return ((*(*cbb).u.child.base).buf)
            .offset((*cbb).u.child.offset as isize)
            .offset((*cbb).u.child.pending_len_len as libc::c_int as isize);
    }
    return (*cbb).u.base.buf;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_len(mut cbb: *const CBB) -> size_t {
    if ((*cbb).child).is_null() {} else {
        __assert_fail(
            b"cbb->child == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0" as *const u8
                as *const libc::c_char,
            284 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 28],
                &[libc::c_char; 28],
            >(b"size_t CBB_len(const CBB *)\0"))
                .as_ptr(),
        );
    }
    'c_3097: {
        if ((*cbb).child).is_null() {} else {
            __assert_fail(
                b"cbb->child == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0"
                    as *const u8 as *const libc::c_char,
                284 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 28],
                    &[libc::c_char; 28],
                >(b"size_t CBB_len(const CBB *)\0"))
                    .as_ptr(),
            );
        }
    };
    if (*cbb).is_child != 0 {
        if ((*cbb).u.child.offset).wrapping_add((*cbb).u.child.pending_len_len as size_t)
            <= (*(*cbb).u.child.base).len
        {} else {
            __assert_fail(
                b"cbb->u.child.offset + cbb->u.child.pending_len_len <= cbb->u.child.base->len\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0"
                    as *const u8 as *const libc::c_char,
                287 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 28],
                    &[libc::c_char; 28],
                >(b"size_t CBB_len(const CBB *)\0"))
                    .as_ptr(),
            );
        }
        'c_3019: {
            if ((*cbb).u.child.offset)
                .wrapping_add((*cbb).u.child.pending_len_len as size_t)
                <= (*(*cbb).u.child.base).len
            {} else {
                __assert_fail(
                    b"cbb->u.child.offset + cbb->u.child.pending_len_len <= cbb->u.child.base->len\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0"
                        as *const u8 as *const libc::c_char,
                    287 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 28],
                        &[libc::c_char; 28],
                    >(b"size_t CBB_len(const CBB *)\0"))
                        .as_ptr(),
                );
            }
        };
        return ((*(*cbb).u.child.base).len)
            .wrapping_sub((*cbb).u.child.offset)
            .wrapping_sub((*cbb).u.child.pending_len_len as size_t);
    }
    return (*cbb).u.base.len;
}
unsafe extern "C" fn cbb_add_child(
    mut cbb: *mut CBB,
    mut out_child: *mut CBB,
    mut len_len: uint8_t,
    mut is_asn1: libc::c_int,
) -> libc::c_int {
    if ((*cbb).child).is_null() {} else {
        __assert_fail(
            b"cbb->child == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0" as *const u8
                as *const libc::c_char,
            296 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 46],
                &[libc::c_char; 46],
            >(b"int cbb_add_child(CBB *, CBB *, uint8_t, int)\0"))
                .as_ptr(),
        );
    }
    'c_3335: {
        if ((*cbb).child).is_null() {} else {
            __assert_fail(
                b"cbb->child == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0"
                    as *const u8 as *const libc::c_char,
                296 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 46],
                    &[libc::c_char; 46],
                >(b"int cbb_add_child(CBB *, CBB *, uint8_t, int)\0"))
                    .as_ptr(),
            );
        }
    };
    if is_asn1 == 0 || len_len as libc::c_int == 1 as libc::c_int {} else {
        __assert_fail(
            b"!is_asn1 || len_len == 1\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0" as *const u8
                as *const libc::c_char,
            297 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 46],
                &[libc::c_char; 46],
            >(b"int cbb_add_child(CBB *, CBB *, uint8_t, int)\0"))
                .as_ptr(),
        );
    }
    'c_3287: {
        if is_asn1 == 0 || len_len as libc::c_int == 1 as libc::c_int {} else {
            __assert_fail(
                b"!is_asn1 || len_len == 1\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0"
                    as *const u8 as *const libc::c_char,
                297 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 46],
                    &[libc::c_char; 46],
                >(b"int cbb_add_child(CBB *, CBB *, uint8_t, int)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut base: *mut cbb_buffer_st = cbb_get_base(cbb);
    let mut offset: size_t = (*base).len;
    let mut prefix_bytes: *mut uint8_t = 0 as *mut uint8_t;
    if cbb_buffer_add(base, &mut prefix_bytes, len_len as size_t) == 0 {
        return 0 as libc::c_int;
    }
    OPENSSL_memset(
        prefix_bytes as *mut libc::c_void,
        0 as libc::c_int,
        len_len as size_t,
    );
    CBB_zero(out_child);
    (*out_child).is_child = 1 as libc::c_int as libc::c_char;
    (*out_child).u.child.base = base;
    (*out_child).u.child.offset = offset;
    (*out_child).u.child.pending_len_len = len_len;
    ((*out_child).u.child).set_pending_is_asn1(is_asn1 as libc::c_uint);
    (*cbb).child = out_child;
    return 1 as libc::c_int;
}
unsafe extern "C" fn cbb_add_length_prefixed(
    mut cbb: *mut CBB,
    mut out_contents: *mut CBB,
    mut len_len: uint8_t,
) -> libc::c_int {
    if CBB_flush(cbb) == 0 {
        return 0 as libc::c_int;
    }
    return cbb_add_child(cbb, out_contents, len_len, 0 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_add_u8_length_prefixed(
    mut cbb: *mut CBB,
    mut out_contents: *mut CBB,
) -> libc::c_int {
    return cbb_add_length_prefixed(cbb, out_contents, 1 as libc::c_int as uint8_t);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_add_u16_length_prefixed(
    mut cbb: *mut CBB,
    mut out_contents: *mut CBB,
) -> libc::c_int {
    return cbb_add_length_prefixed(cbb, out_contents, 2 as libc::c_int as uint8_t);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_add_u24_length_prefixed(
    mut cbb: *mut CBB,
    mut out_contents: *mut CBB,
) -> libc::c_int {
    return cbb_add_length_prefixed(cbb, out_contents, 3 as libc::c_int as uint8_t);
}
unsafe extern "C" fn add_base128_integer(
    mut cbb: *mut CBB,
    mut v: uint64_t,
) -> libc::c_int {
    let mut len_len: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut copy: uint64_t = v;
    while copy > 0 as libc::c_int as uint64_t {
        len_len = len_len.wrapping_add(1);
        len_len;
        copy >>= 7 as libc::c_int;
    }
    if len_len == 0 as libc::c_int as libc::c_uint {
        len_len = 1 as libc::c_int as libc::c_uint;
    }
    let mut i: libc::c_uint = len_len.wrapping_sub(1 as libc::c_int as libc::c_uint);
    while i < len_len {
        let mut byte: uint8_t = (v >> (7 as libc::c_int as libc::c_uint).wrapping_mul(i)
            & 0x7f as libc::c_int as uint64_t) as uint8_t;
        if i != 0 as libc::c_int as libc::c_uint {
            byte = (byte as libc::c_int | 0x80 as libc::c_int) as uint8_t;
        }
        if CBB_add_u8(cbb, byte) == 0 {
            return 0 as libc::c_int;
        }
        i = i.wrapping_sub(1);
        i;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_add_asn1(
    mut cbb: *mut CBB,
    mut out_contents: *mut CBB,
    mut tag: CBS_ASN1_TAG,
) -> libc::c_int {
    if CBB_flush(cbb) == 0 {
        return 0 as libc::c_int;
    }
    let mut tag_bits: uint8_t = (tag >> 24 as libc::c_int
        & 0xe0 as libc::c_int as CBS_ASN1_TAG) as uint8_t;
    let mut tag_number: CBS_ASN1_TAG = tag
        & ((1 as libc::c_uint) << 5 as libc::c_int + 24 as libc::c_int)
            .wrapping_sub(1 as libc::c_int as libc::c_uint);
    if tag_number >= 0x1f as libc::c_int as CBS_ASN1_TAG {
        if CBB_add_u8(cbb, (tag_bits as libc::c_int | 0x1f as libc::c_int) as uint8_t)
            == 0 || add_base128_integer(cbb, tag_number as uint64_t) == 0
        {
            return 0 as libc::c_int;
        }
    } else if CBB_add_u8(cbb, (tag_bits as CBS_ASN1_TAG | tag_number) as uint8_t) == 0 {
        return 0 as libc::c_int
    }
    return cbb_add_child(
        cbb,
        out_contents,
        1 as libc::c_int as uint8_t,
        1 as libc::c_int,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_add_bytes(
    mut cbb: *mut CBB,
    mut data: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut out: *mut uint8_t = 0 as *mut uint8_t;
    if CBB_add_space(cbb, &mut out, len) == 0 {
        return 0 as libc::c_int;
    }
    OPENSSL_memcpy(out as *mut libc::c_void, data as *const libc::c_void, len);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_add_zeros(
    mut cbb: *mut CBB,
    mut len: size_t,
) -> libc::c_int {
    let mut out: *mut uint8_t = 0 as *mut uint8_t;
    if CBB_add_space(cbb, &mut out, len) == 0 {
        return 0 as libc::c_int;
    }
    OPENSSL_memset(out as *mut libc::c_void, 0 as libc::c_int, len);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_add_space(
    mut cbb: *mut CBB,
    mut out_data: *mut *mut uint8_t,
    mut len: size_t,
) -> libc::c_int {
    if CBB_flush(cbb) == 0 || cbb_buffer_add(cbb_get_base(cbb), out_data, len) == 0 {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_reserve(
    mut cbb: *mut CBB,
    mut out_data: *mut *mut uint8_t,
    mut len: size_t,
) -> libc::c_int {
    if CBB_flush(cbb) == 0 || cbb_buffer_reserve(cbb_get_base(cbb), out_data, len) == 0 {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_did_write(
    mut cbb: *mut CBB,
    mut len: size_t,
) -> libc::c_int {
    let mut base: *mut cbb_buffer_st = cbb_get_base(cbb);
    let mut newlen: size_t = ((*base).len).wrapping_add(len);
    if !((*cbb).child).is_null() || newlen < (*base).len || newlen > (*base).cap {
        return 0 as libc::c_int;
    }
    (*base).len = newlen;
    return 1 as libc::c_int;
}
unsafe extern "C" fn cbb_add_u(
    mut cbb: *mut CBB,
    mut v: uint64_t,
    mut len_len: size_t,
) -> libc::c_int {
    let mut buf: *mut uint8_t = 0 as *mut uint8_t;
    if CBB_add_space(cbb, &mut buf, len_len) == 0 {
        return 0 as libc::c_int;
    }
    let mut i: size_t = len_len.wrapping_sub(1 as libc::c_int as size_t);
    while i < len_len {
        *buf.offset(i as isize) = v as uint8_t;
        v >>= 8 as libc::c_int;
        i = i.wrapping_sub(1);
        i;
    }
    if v != 0 as libc::c_int as uint64_t {
        cbb_on_error(cbb);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_add_u8(
    mut cbb: *mut CBB,
    mut value: uint8_t,
) -> libc::c_int {
    return cbb_add_u(cbb, value as uint64_t, 1 as libc::c_int as size_t);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_add_u16(
    mut cbb: *mut CBB,
    mut value: uint16_t,
) -> libc::c_int {
    return cbb_add_u(cbb, value as uint64_t, 2 as libc::c_int as size_t);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_add_u16le(
    mut cbb: *mut CBB,
    mut value: uint16_t,
) -> libc::c_int {
    return CBB_add_u16(cbb, CRYPTO_bswap2(value));
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_add_u24(
    mut cbb: *mut CBB,
    mut value: uint32_t,
) -> libc::c_int {
    return cbb_add_u(cbb, value as uint64_t, 3 as libc::c_int as size_t);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_add_u32(
    mut cbb: *mut CBB,
    mut value: uint32_t,
) -> libc::c_int {
    return cbb_add_u(cbb, value as uint64_t, 4 as libc::c_int as size_t);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_add_u32le(
    mut cbb: *mut CBB,
    mut value: uint32_t,
) -> libc::c_int {
    return CBB_add_u32(cbb, CRYPTO_bswap4(value));
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_add_u64(
    mut cbb: *mut CBB,
    mut value: uint64_t,
) -> libc::c_int {
    return cbb_add_u(cbb, value, 8 as libc::c_int as size_t);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_add_u64le(
    mut cbb: *mut CBB,
    mut value: uint64_t,
) -> libc::c_int {
    return CBB_add_u64(cbb, CRYPTO_bswap8(value));
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_discard_child(mut cbb: *mut CBB) {
    if ((*cbb).child).is_null() {
        return;
    }
    let mut base: *mut cbb_buffer_st = cbb_get_base(cbb);
    if (*(*cbb).child).is_child != 0 {} else {
        __assert_fail(
            b"cbb->child->is_child\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0" as *const u8
                as *const libc::c_char,
            491 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 30],
                &[libc::c_char; 30],
            >(b"void CBB_discard_child(CBB *)\0"))
                .as_ptr(),
        );
    }
    'c_4128: {
        if (*(*cbb).child).is_child != 0 {} else {
            __assert_fail(
                b"cbb->child->is_child\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0"
                    as *const u8 as *const libc::c_char,
                491 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 30],
                    &[libc::c_char; 30],
                >(b"void CBB_discard_child(CBB *)\0"))
                    .as_ptr(),
            );
        }
    };
    (*base).len = (*(*cbb).child).u.child.offset;
    (*(*cbb).child).u.child.base = 0 as *mut cbb_buffer_st;
    (*cbb).child = 0 as *mut CBB;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_add_asn1_uint64(
    mut cbb: *mut CBB,
    mut value: uint64_t,
) -> libc::c_int {
    return CBB_add_asn1_uint64_with_tag(cbb, value, 0x2 as libc::c_uint);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_add_asn1_uint64_with_tag(
    mut cbb: *mut CBB,
    mut value: uint64_t,
    mut tag: CBS_ASN1_TAG,
) -> libc::c_int {
    let mut started: libc::c_int = 0;
    let mut current_block: u64;
    let mut child: CBB = cbb_st {
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
    if !(CBB_add_asn1(cbb, &mut child, tag) == 0) {
        started = 0 as libc::c_int;
        let mut i: size_t = 0 as libc::c_int as size_t;
        loop {
            if !(i < 8 as libc::c_int as size_t) {
                current_block = 13536709405535804910;
                break;
            }
            let mut byte: uint8_t = (value
                >> 8 as libc::c_int as size_t
                    * (7 as libc::c_int as size_t).wrapping_sub(i)
                & 0xff as libc::c_int as uint64_t) as uint8_t;
            if started == 0 {
                if byte as libc::c_int == 0 as libc::c_int {
                    current_block = 14155750587950065367;
                } else {
                    if byte as libc::c_int & 0x80 as libc::c_int != 0
                        && CBB_add_u8(&mut child, 0 as libc::c_int as uint8_t) == 0
                    {
                        current_block = 2347419518545282166;
                        break;
                    }
                    started = 1 as libc::c_int;
                    current_block = 13513818773234778473;
                }
            } else {
                current_block = 13513818773234778473;
            }
            match current_block {
                13513818773234778473 => {
                    if CBB_add_u8(&mut child, byte) == 0 {
                        current_block = 2347419518545282166;
                        break;
                    }
                }
                _ => {}
            }
            i = i.wrapping_add(1);
            i;
        }
        match current_block {
            2347419518545282166 => {}
            _ => {
                if !(started == 0
                    && CBB_add_u8(&mut child, 0 as libc::c_int as uint8_t) == 0)
                {
                    return CBB_flush(cbb);
                }
            }
        }
    }
    cbb_on_error(cbb);
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_add_asn1_int64(
    mut cbb: *mut CBB,
    mut value: int64_t,
) -> libc::c_int {
    return CBB_add_asn1_int64_with_tag(cbb, value, 0x2 as libc::c_uint);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_add_asn1_int64_with_tag(
    mut cbb: *mut CBB,
    mut value: int64_t,
    mut tag: CBS_ASN1_TAG,
) -> libc::c_int {
    let mut current_block: u64;
    if value >= 0 as libc::c_int as int64_t {
        return CBB_add_asn1_uint64_with_tag(cbb, value as uint64_t, tag);
    }
    let mut bytes: [uint8_t; 8] = [0; 8];
    memcpy(
        bytes.as_mut_ptr() as *mut libc::c_void,
        &mut value as *mut int64_t as *const libc::c_void,
        ::core::mem::size_of::<int64_t>() as libc::c_ulong,
    );
    let mut start: libc::c_int = 7 as libc::c_int;
    while start > 0 as libc::c_int
        && (bytes[start as usize] as libc::c_int == 0xff as libc::c_int
            && bytes[(start - 1 as libc::c_int) as usize] as libc::c_int
                & 0x80 as libc::c_int != 0)
    {
        start -= 1;
        start;
    }
    let mut child: CBB = cbb_st {
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
    if !(CBB_add_asn1(cbb, &mut child, tag) == 0) {
        let mut i: libc::c_int = start;
        loop {
            if !(i >= 0 as libc::c_int) {
                current_block = 7746791466490516765;
                break;
            }
            if CBB_add_u8(&mut child, bytes[i as usize]) == 0 {
                current_block = 9161022509039375040;
                break;
            }
            i -= 1;
            i;
        }
        match current_block {
            9161022509039375040 => {}
            _ => return CBB_flush(cbb),
        }
    }
    cbb_on_error(cbb);
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_add_asn1_octet_string(
    mut cbb: *mut CBB,
    mut data: *const uint8_t,
    mut data_len: size_t,
) -> libc::c_int {
    let mut child: CBB = cbb_st {
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
    if CBB_add_asn1(cbb, &mut child, 0x4 as libc::c_uint) == 0
        || CBB_add_bytes(&mut child, data, data_len) == 0 || CBB_flush(cbb) == 0
    {
        cbb_on_error(cbb);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_add_asn1_bool(
    mut cbb: *mut CBB,
    mut value: libc::c_int,
) -> libc::c_int {
    let mut child: CBB = cbb_st {
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
    if CBB_add_asn1(cbb, &mut child, 0x1 as libc::c_uint) == 0
        || CBB_add_u8(
            &mut child,
            (if value != 0 as libc::c_int {
                0xff as libc::c_int
            } else {
                0 as libc::c_int
            }) as uint8_t,
        ) == 0 || CBB_flush(cbb) == 0
    {
        cbb_on_error(cbb);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn parse_dotted_decimal(
    mut cbs: *mut CBS,
    mut out: *mut uint64_t,
) -> libc::c_int {
    if CBS_get_u64_decimal(cbs, out) == 0 {
        return 0 as libc::c_int;
    }
    let mut dot: uint8_t = 0;
    return (CBS_get_u8(cbs, &mut dot) == 0
        || dot as libc::c_int == '.' as i32 && CBS_len(cbs) > 0 as libc::c_int as size_t)
        as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_add_asn1_oid_from_text(
    mut cbb: *mut CBB,
    mut text: *const libc::c_char,
    mut len: size_t,
) -> libc::c_int {
    if CBB_flush(cbb) == 0 {
        return 0 as libc::c_int;
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, text as *const uint8_t, len);
    let mut a: uint64_t = 0;
    let mut b: uint64_t = 0;
    if parse_dotted_decimal(&mut cbs, &mut a) == 0
        || parse_dotted_decimal(&mut cbs, &mut b) == 0
    {
        return 0 as libc::c_int;
    }
    if a > 2 as libc::c_int as uint64_t
        || a < 2 as libc::c_int as uint64_t && b > 39 as libc::c_int as uint64_t
        || b
            > (18446744073709551615 as libc::c_ulong)
                .wrapping_sub(80 as libc::c_int as libc::c_ulong)
        || add_base128_integer(cbb, (40 as libc::c_uint as uint64_t * a).wrapping_add(b))
            == 0
    {
        return 0 as libc::c_int;
    }
    while CBS_len(&mut cbs) > 0 as libc::c_int as size_t {
        if parse_dotted_decimal(&mut cbs, &mut a) == 0
            || add_base128_integer(cbb, a) == 0
        {
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn compare_set_of_element(
    mut a_ptr: *const libc::c_void,
    mut b_ptr: *const libc::c_void,
) -> libc::c_int {
    let mut a: *const CBS = a_ptr as *const CBS;
    let mut b: *const CBS = b_ptr as *const CBS;
    let mut a_len: size_t = CBS_len(a);
    let mut b_len: size_t = CBS_len(b);
    let mut min_len: size_t = if a_len < b_len { a_len } else { b_len };
    let mut ret: libc::c_int = OPENSSL_memcmp(
        CBS_data(a) as *const libc::c_void,
        CBS_data(b) as *const libc::c_void,
        min_len,
    );
    if ret != 0 as libc::c_int {
        return ret;
    }
    if a_len == b_len {
        return 0 as libc::c_int;
    }
    return if a_len < b_len { -(1 as libc::c_int) } else { 1 as libc::c_int };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CBB_flush_asn1_set_of(mut cbb: *mut CBB) -> libc::c_int {
    let mut out: *mut uint8_t = 0 as *mut uint8_t;
    let mut offset: size_t = 0;
    let mut current_block: u64;
    if CBB_flush(cbb) == 0 {
        return 0 as libc::c_int;
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut num_children: size_t = 0 as libc::c_int as size_t;
    CBS_init(&mut cbs, CBB_data(cbb), CBB_len(cbb));
    while CBS_len(&mut cbs) != 0 as libc::c_int as size_t {
        if CBS_get_any_asn1_element(
            &mut cbs,
            0 as *mut CBS,
            0 as *mut CBS_ASN1_TAG,
            0 as *mut size_t,
        ) == 0
        {
            ERR_put_error(
                14 as libc::c_int,
                0 as libc::c_int,
                2 as libc::c_int | 64 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0"
                    as *const u8 as *const libc::c_char,
                686 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        num_children = num_children.wrapping_add(1);
        num_children;
    }
    if num_children < 2 as libc::c_int as size_t {
        return 1 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut buf_len: size_t = CBB_len(cbb);
    let mut buf: *mut uint8_t = OPENSSL_memdup(
        CBB_data(cbb) as *const libc::c_void,
        buf_len,
    ) as *mut uint8_t;
    let mut children: *mut CBS = OPENSSL_calloc(
        num_children,
        ::core::mem::size_of::<CBS>() as libc::c_ulong,
    ) as *mut CBS;
    if !(buf.is_null() || children.is_null()) {
        CBS_init(&mut cbs, buf, buf_len);
        let mut i: size_t = 0 as libc::c_int as size_t;
        loop {
            if !(i < num_children) {
                current_block = 8457315219000651999;
                break;
            }
            if CBS_get_any_asn1_element(
                &mut cbs,
                &mut *children.offset(i as isize),
                0 as *mut CBS_ASN1_TAG,
                0 as *mut size_t,
            ) == 0
            {
                current_block = 1886257160843159826;
                break;
            }
            i = i.wrapping_add(1);
            i;
        }
        match current_block {
            1886257160843159826 => {}
            _ => {
                qsort(
                    children as *mut libc::c_void,
                    num_children,
                    ::core::mem::size_of::<CBS>() as libc::c_ulong,
                    Some(
                        compare_set_of_element
                            as unsafe extern "C" fn(
                                *const libc::c_void,
                                *const libc::c_void,
                            ) -> libc::c_int,
                    ),
                );
                out = CBB_data(cbb) as *mut uint8_t;
                offset = 0 as libc::c_int as size_t;
                let mut i_0: size_t = 0 as libc::c_int as size_t;
                while i_0 < num_children {
                    OPENSSL_memcpy(
                        out.offset(offset as isize) as *mut libc::c_void,
                        CBS_data(&mut *children.offset(i_0 as isize))
                            as *const libc::c_void,
                        CBS_len(&mut *children.offset(i_0 as isize)),
                    );
                    offset = offset
                        .wrapping_add(CBS_len(&mut *children.offset(i_0 as isize)));
                    i_0 = i_0.wrapping_add(1);
                    i_0;
                }
                if offset == buf_len {} else {
                    __assert_fail(
                        b"offset == buf_len\0" as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0"
                            as *const u8 as *const libc::c_char,
                        720 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 33],
                            &[libc::c_char; 33],
                        >(b"int CBB_flush_asn1_set_of(CBB *)\0"))
                            .as_ptr(),
                    );
                }
                'c_4847: {
                    if offset == buf_len {} else {
                        __assert_fail(
                            b"offset == buf_len\0" as *const u8 as *const libc::c_char,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/cbb.c\0"
                                as *const u8 as *const libc::c_char,
                            720 as libc::c_int as libc::c_uint,
                            (*::core::mem::transmute::<
                                &[u8; 33],
                                &[libc::c_char; 33],
                            >(b"int CBB_flush_asn1_set_of(CBB *)\0"))
                                .as_ptr(),
                        );
                    }
                };
                ret = 1 as libc::c_int;
            }
        }
    }
    OPENSSL_free(buf as *mut libc::c_void);
    OPENSSL_free(children as *mut libc::c_void);
    return ret;
}
