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
    fn CBB_cleanup(cbb: *mut CBB);
    fn CBB_finish(
        cbb: *mut CBB,
        out_data: *mut *mut uint8_t,
        out_len: *mut size_t,
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
    fn OPENSSL_free(ptr: *mut libc::c_void);
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type uint8_t = __uint8_t;
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
pub unsafe extern "C" fn CBB_finish_i2d(
    mut cbb: *mut CBB,
    mut outp: *mut *mut uint8_t,
) -> libc::c_int {
    if (*cbb).is_child == 0 {} else {
        __assert_fail(
            b"!cbb->is_child\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/asn1_compat.c\0"
                as *const u8 as *const libc::c_char,
            29 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 38],
                &[libc::c_char; 38],
            >(b"int CBB_finish_i2d(CBB *, uint8_t **)\0"))
                .as_ptr(),
        );
    }
    'c_2362: {
        if (*cbb).is_child == 0 {} else {
            __assert_fail(
                b"!cbb->is_child\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/asn1_compat.c\0"
                    as *const u8 as *const libc::c_char,
                29 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 38],
                    &[libc::c_char; 38],
                >(b"int CBB_finish_i2d(CBB *, uint8_t **)\0"))
                    .as_ptr(),
            );
        }
    };
    if ((*cbb).u.base).can_resize() != 0 {} else {
        __assert_fail(
            b"cbb->u.base.can_resize\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/asn1_compat.c\0"
                as *const u8 as *const libc::c_char,
            30 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 38],
                &[libc::c_char; 38],
            >(b"int CBB_finish_i2d(CBB *, uint8_t **)\0"))
                .as_ptr(),
        );
    }
    'c_2316: {
        if ((*cbb).u.base).can_resize() != 0 {} else {
            __assert_fail(
                b"cbb->u.base.can_resize\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bytestring/asn1_compat.c\0"
                    as *const u8 as *const libc::c_char,
                30 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 38],
                    &[libc::c_char; 38],
                >(b"int CBB_finish_i2d(CBB *, uint8_t **)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut der: *mut uint8_t = 0 as *mut uint8_t;
    let mut der_len: size_t = 0;
    if CBB_finish(cbb, &mut der, &mut der_len) == 0 {
        CBB_cleanup(cbb);
        return -(1 as libc::c_int);
    }
    if der_len > 2147483647 as libc::c_int as size_t {
        OPENSSL_free(der as *mut libc::c_void);
        return -(1 as libc::c_int);
    }
    if !outp.is_null() {
        if (*outp).is_null() {
            *outp = der;
            der = 0 as *mut uint8_t;
        } else {
            OPENSSL_memcpy(
                *outp as *mut libc::c_void,
                der as *const libc::c_void,
                der_len,
            );
            *outp = (*outp).offset(der_len as isize);
        }
    }
    OPENSSL_free(der as *mut libc::c_void);
    return der_len as libc::c_int;
}
