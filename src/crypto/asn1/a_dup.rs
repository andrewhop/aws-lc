#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(extern_types)]
extern "C" {
    pub type ASN1_ITEM_st;
    pub type ASN1_VALUE_st;
    fn ASN1_item_d2i(
        out: *mut *mut ASN1_VALUE,
        inp: *mut *const libc::c_uchar,
        len: libc::c_long,
        it: *const ASN1_ITEM,
    ) -> *mut ASN1_VALUE;
    fn ASN1_item_i2d(
        val: *mut ASN1_VALUE,
        outp: *mut *mut libc::c_uchar,
        it: *const ASN1_ITEM,
    ) -> libc::c_int;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
}
pub type ASN1_ITEM = ASN1_ITEM_st;
pub type ASN1_VALUE = ASN1_VALUE_st;
pub type d2i_of_void = unsafe extern "C" fn(
    *mut *mut libc::c_void,
    *mut *const libc::c_uchar,
    libc::c_long,
) -> *mut libc::c_void;
pub type i2d_of_void = unsafe extern "C" fn(
    *const libc::c_void,
    *mut *mut libc::c_uchar,
) -> libc::c_int;
#[no_mangle]
pub unsafe extern "C" fn ASN1_dup(
    mut i2d: Option::<i2d_of_void>,
    mut d2i: Option::<d2i_of_void>,
    mut input: *mut libc::c_void,
) -> *mut libc::c_void {
    if i2d.is_none() || d2i.is_none() || input.is_null() {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_dup.c\0" as *const u8
                as *const libc::c_char,
            64 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut libc::c_void;
    }
    let mut buf: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut buf_len: libc::c_int = i2d
        .expect("non-null function pointer")(input, &mut buf);
    if buf.is_null() || buf_len < 0 as libc::c_int {
        return 0 as *mut libc::c_void;
    }
    let mut temp_input: *const libc::c_uchar = buf;
    let mut ret: *mut libc::c_char = d2i
        .expect(
            "non-null function pointer",
        )(0 as *mut *mut libc::c_void, &mut temp_input, buf_len as libc::c_long)
        as *mut libc::c_char;
    OPENSSL_free(buf as *mut libc::c_void);
    return ret as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_dup(
    mut it: *const ASN1_ITEM,
    mut x: *mut libc::c_void,
) -> *mut libc::c_void {
    let mut b: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut i: libc::c_long = 0;
    let mut ret: *mut libc::c_void = 0 as *mut libc::c_void;
    if x.is_null() {
        return 0 as *mut libc::c_void;
    }
    i = ASN1_item_i2d(x as *mut ASN1_VALUE, &mut b, it) as libc::c_long;
    if b.is_null() {
        return 0 as *mut libc::c_void;
    }
    p = b;
    ret = ASN1_item_d2i(0 as *mut *mut ASN1_VALUE, &mut p, i, it) as *mut libc::c_void;
    OPENSSL_free(b as *mut libc::c_void);
    return ret;
}
