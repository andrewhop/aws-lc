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
    pub type engine_st;
    pub type env_md_st;
    fn ASN1_item_i2d(
        val: *mut ASN1_VALUE,
        outp: *mut *mut libc::c_uchar,
        it: *const ASN1_ITEM,
    ) -> libc::c_int;
    fn EVP_Digest(
        data: *const libc::c_void,
        len: size_t,
        md_out: *mut uint8_t,
        out_size: *mut libc::c_uint,
        type_0: *const EVP_MD,
        impl_0: *mut ENGINE,
    ) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type uint8_t = __uint8_t;
pub type ASN1_ITEM = ASN1_ITEM_st;
pub type ASN1_VALUE = ASN1_VALUE_st;
pub type ENGINE = engine_st;
pub type EVP_MD = env_md_st;
pub type i2d_of_void = unsafe extern "C" fn(
    *const libc::c_void,
    *mut *mut libc::c_uchar,
) -> libc::c_int;
#[no_mangle]
pub unsafe extern "C" fn ASN1_digest(
    mut i2d: Option::<i2d_of_void>,
    mut type_0: *const EVP_MD,
    mut data: *mut libc::c_char,
    mut md: *mut libc::c_uchar,
    mut len: *mut libc::c_uint,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    let mut str: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut p: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    i = i2d
        .expect(
            "non-null function pointer",
        )(data as *const libc::c_void, 0 as *mut *mut libc::c_uchar);
    str = OPENSSL_malloc(i as size_t) as *mut libc::c_uchar;
    if str.is_null() {
        return 0 as libc::c_int;
    }
    p = str;
    i2d.expect("non-null function pointer")(data as *const libc::c_void, &mut p);
    ret = EVP_Digest(
        str as *const libc::c_void,
        i as size_t,
        md,
        len,
        type_0,
        0 as *mut ENGINE,
    );
    OPENSSL_free(str as *mut libc::c_void);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_digest(
    mut it: *const ASN1_ITEM,
    mut type_0: *const EVP_MD,
    mut asn: *mut libc::c_void,
    mut md: *mut libc::c_uchar,
    mut len: *mut libc::c_uint,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    let mut str: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    i = ASN1_item_i2d(asn as *mut ASN1_VALUE, &mut str, it);
    if str.is_null() {
        return 0 as libc::c_int;
    }
    ret = EVP_Digest(
        str as *const libc::c_void,
        i as size_t,
        md,
        len,
        type_0,
        0 as *mut ENGINE,
    );
    OPENSSL_free(str as *mut libc::c_void);
    return ret;
}
