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
    fn ASN1_STRING_dup(str: *const ASN1_STRING) -> *mut ASN1_STRING;
    fn ASN1_STRING_cmp(a: *const ASN1_STRING, b: *const ASN1_STRING) -> libc::c_int;
    fn ASN1_STRING_set(
        str: *mut ASN1_STRING,
        data: *const libc::c_void,
        len: ossl_ssize_t,
    ) -> libc::c_int;
}
pub type ptrdiff_t = libc::c_long;
pub type ossl_ssize_t = ptrdiff_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_string_st {
    pub length: libc::c_int,
    pub type_0: libc::c_int,
    pub data: *mut libc::c_uchar,
    pub flags: libc::c_long,
}
pub type ASN1_OCTET_STRING = asn1_string_st;
pub type ASN1_STRING = asn1_string_st;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_OCTET_STRING_dup(
    mut x: *const ASN1_OCTET_STRING,
) -> *mut ASN1_OCTET_STRING {
    return ASN1_STRING_dup(x);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_OCTET_STRING_cmp(
    mut a: *const ASN1_OCTET_STRING,
    mut b: *const ASN1_OCTET_STRING,
) -> libc::c_int {
    return ASN1_STRING_cmp(a, b);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_OCTET_STRING_set(
    mut x: *mut ASN1_OCTET_STRING,
    mut d: *const libc::c_uchar,
    mut len: libc::c_int,
) -> libc::c_int {
    return ASN1_STRING_set(x, d as *const libc::c_void, len as ossl_ssize_t);
}
