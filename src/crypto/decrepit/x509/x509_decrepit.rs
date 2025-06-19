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
    pub type X509_crl_st;
    pub type X509_extension_st;
    pub type x509_st;
    pub type X509_req_st;
    pub type lhash_st_CONF_VALUE;
    fn X509V3_EXT_nconf(
        conf: *const CONF,
        ctx: *const X509V3_CTX,
        name: *const libc::c_char,
        value: *const libc::c_char,
    ) -> *mut X509_EXTENSION;
    fn X509V3_EXT_nconf_nid(
        conf: *const CONF,
        ctx: *const X509V3_CTX,
        ext_nid: libc::c_int,
        value: *const libc::c_char,
    ) -> *mut X509_EXTENSION;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
}
pub type X509_CRL = X509_crl_st;
pub type X509_EXTENSION = X509_extension_st;
pub type X509 = x509_st;
pub type X509_REQ = X509_req_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct conf_st {
    pub data: *mut lhash_st_CONF_VALUE,
}
pub type CONF = conf_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct v3_ext_ctx {
    pub flags: libc::c_int,
    pub issuer_cert: *const X509,
    pub subject_cert: *const X509,
    pub subject_req: *const X509_REQ,
    pub crl: *const X509_CRL,
    pub db: *const CONF,
}
pub type X509V3_CTX = v3_ext_ctx;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509V3_EXT_conf_nid(
    mut conf: *mut lhash_st_CONF_VALUE,
    mut ctx: *const X509V3_CTX,
    mut ext_nid: libc::c_int,
    mut value: *const libc::c_char,
) -> *mut X509_EXTENSION {
    if conf.is_null() {} else {
        __assert_fail(
            b"conf == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/x509/x509_decrepit.c\0"
                as *const u8 as *const libc::c_char,
            25 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 105],
                &[libc::c_char; 105],
            >(
                b"X509_EXTENSION *X509V3_EXT_conf_nid(struct lhash_st_CONF_VALUE *, const X509V3_CTX *, int, const char *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_21601: {
        if conf.is_null() {} else {
            __assert_fail(
                b"conf == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/x509/x509_decrepit.c\0"
                    as *const u8 as *const libc::c_char,
                25 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 105],
                    &[libc::c_char; 105],
                >(
                    b"X509_EXTENSION *X509V3_EXT_conf_nid(struct lhash_st_CONF_VALUE *, const X509V3_CTX *, int, const char *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    return X509V3_EXT_nconf_nid(0 as *const CONF, ctx, ext_nid, value);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509V3_EXT_conf(
    mut conf: *mut lhash_st_CONF_VALUE,
    mut ctx: *mut X509V3_CTX,
    mut name: *const libc::c_char,
    mut value: *const libc::c_char,
) -> *mut X509_EXTENSION {
    if conf.is_null() {} else {
        __assert_fail(
            b"conf == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/x509/x509_decrepit.c\0"
                as *const u8 as *const libc::c_char,
            31 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 104],
                &[libc::c_char; 104],
            >(
                b"X509_EXTENSION *X509V3_EXT_conf(struct lhash_st_CONF_VALUE *, X509V3_CTX *, const char *, const char *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_21702: {
        if conf.is_null() {} else {
            __assert_fail(
                b"conf == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/x509/x509_decrepit.c\0"
                    as *const u8 as *const libc::c_char,
                31 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 104],
                    &[libc::c_char; 104],
                >(
                    b"X509_EXTENSION *X509V3_EXT_conf(struct lhash_st_CONF_VALUE *, X509V3_CTX *, const char *, const char *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    return X509V3_EXT_nconf(0 as *const CONF, ctx, name, value);
}
