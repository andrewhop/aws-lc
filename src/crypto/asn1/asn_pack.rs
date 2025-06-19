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
    fn ASN1_item_free(val: *mut ASN1_VALUE, it: *const ASN1_ITEM);
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
    fn ASN1_STRING_new() -> *mut ASN1_STRING;
    fn ASN1_STRING_set0(
        str: *mut ASN1_STRING,
        data: *mut libc::c_void,
        len: libc::c_int,
    );
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
}
pub type __uint8_t = libc::c_uchar;
pub type uint8_t = __uint8_t;
pub type ASN1_ITEM = ASN1_ITEM_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_string_st {
    pub length: libc::c_int,
    pub type_0: libc::c_int,
    pub data: *mut libc::c_uchar,
    pub flags: libc::c_long,
}
pub type ASN1_STRING = asn1_string_st;
pub type ASN1_VALUE = ASN1_VALUE_st;
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_pack(
    mut obj: *mut libc::c_void,
    mut it: *const ASN1_ITEM,
    mut out: *mut *mut ASN1_STRING,
) -> *mut ASN1_STRING {
    let mut new_data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: libc::c_int = ASN1_item_i2d(obj as *mut ASN1_VALUE, &mut new_data, it);
    if len <= 0 as libc::c_int {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            112 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/asn_pack.c\0" as *const u8
                as *const libc::c_char,
            67 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut ASN1_STRING;
    }
    let mut ret: *mut ASN1_STRING = 0 as *mut ASN1_STRING;
    if out.is_null() || (*out).is_null() {
        ret = ASN1_STRING_new();
        if ret.is_null() {
            OPENSSL_free(new_data as *mut libc::c_void);
            return 0 as *mut ASN1_STRING;
        }
    } else {
        ret = *out;
    }
    ASN1_STRING_set0(ret, new_data as *mut libc::c_void, len);
    if !out.is_null() {
        *out = ret;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_unpack(
    mut oct: *const ASN1_STRING,
    mut it: *const ASN1_ITEM,
) -> *mut libc::c_void {
    let mut p: *const libc::c_uchar = (*oct).data;
    let mut ret: *mut libc::c_void = ASN1_item_d2i(
        0 as *mut *mut ASN1_VALUE,
        &mut p,
        (*oct).length as libc::c_long,
        it,
    ) as *mut libc::c_void;
    if ret.is_null()
        || p != ((*oct).data).offset((*oct).length as isize) as *const libc::c_uchar
    {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/asn_pack.c\0" as *const u8
                as *const libc::c_char,
            93 as libc::c_int as libc::c_uint,
        );
        ASN1_item_free(ret as *mut ASN1_VALUE, it);
        return 0 as *mut libc::c_void;
    }
    return ret;
}
