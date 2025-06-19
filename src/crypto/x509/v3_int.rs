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
    pub type X509_crl_st;
    pub type x509_st;
    pub type X509_req_st;
    pub type stack_st_void;
    pub type lhash_st_CONF_VALUE;
    pub type stack_st_CONF_VALUE;
    static ASN1_INTEGER_it: ASN1_ITEM;
    fn i2s_ASN1_INTEGER(
        method: *const X509V3_EXT_METHOD,
        aint: *const ASN1_INTEGER,
    ) -> *mut libc::c_char;
    fn s2i_ASN1_INTEGER(
        method: *const X509V3_EXT_METHOD,
        value: *const libc::c_char,
    ) -> *mut ASN1_INTEGER;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type ASN1_ITEM = ASN1_ITEM_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_string_st {
    pub length: libc::c_int,
    pub type_0: libc::c_int,
    pub data: *mut libc::c_uchar,
    pub flags: libc::c_long,
}
pub type ASN1_INTEGER = asn1_string_st;
pub type X509_CRL = X509_crl_st;
pub type X509 = x509_st;
pub type X509_REQ = X509_req_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bio_method_st {
    pub type_0: libc::c_int,
    pub name: *const libc::c_char,
    pub bwrite: Option::<
        unsafe extern "C" fn(*mut BIO, *const libc::c_char, libc::c_int) -> libc::c_int,
    >,
    pub bread: Option::<
        unsafe extern "C" fn(*mut BIO, *mut libc::c_char, libc::c_int) -> libc::c_int,
    >,
    pub bputs: Option::<
        unsafe extern "C" fn(*mut BIO, *const libc::c_char) -> libc::c_int,
    >,
    pub bgets: Option::<
        unsafe extern "C" fn(*mut BIO, *mut libc::c_char, libc::c_int) -> libc::c_int,
    >,
    pub ctrl: Option::<
        unsafe extern "C" fn(
            *mut BIO,
            libc::c_int,
            libc::c_long,
            *mut libc::c_void,
        ) -> libc::c_long,
    >,
    pub create: Option::<unsafe extern "C" fn(*mut BIO) -> libc::c_int>,
    pub destroy: Option::<unsafe extern "C" fn(*mut BIO) -> libc::c_int>,
    pub callback_ctrl: Option::<
        unsafe extern "C" fn(*mut BIO, libc::c_int, bio_info_cb) -> libc::c_long,
    >,
}
pub type bio_info_cb = Option::<
    unsafe extern "C" fn(*mut BIO, libc::c_int, libc::c_int) -> libc::c_long,
>;
pub type BIO = bio_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bio_st {
    pub method: *const BIO_METHOD,
    pub ex_data: CRYPTO_EX_DATA,
    pub callback_ex: BIO_callback_fn_ex,
    pub callback: BIO_callback_fn,
    pub cb_arg: *mut libc::c_char,
    pub init: libc::c_int,
    pub shutdown: libc::c_int,
    pub flags: libc::c_int,
    pub retry_reason: libc::c_int,
    pub num: libc::c_int,
    pub references: CRYPTO_refcount_t,
    pub ptr: *mut libc::c_void,
    pub next_bio: *mut BIO,
    pub num_read: uint64_t,
    pub num_write: uint64_t,
}
pub type CRYPTO_refcount_t = uint32_t;
pub type BIO_callback_fn = Option::<
    unsafe extern "C" fn(
        *mut BIO,
        libc::c_int,
        *const libc::c_char,
        libc::c_int,
        libc::c_long,
        libc::c_long,
    ) -> libc::c_long,
>;
pub type BIO_callback_fn_ex = Option::<
    unsafe extern "C" fn(
        *mut BIO,
        libc::c_int,
        *const libc::c_char,
        size_t,
        libc::c_int,
        libc::c_long,
        libc::c_int,
        *mut size_t,
    ) -> libc::c_long,
>;
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
pub type BIO_METHOD = bio_method_st;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct v3_ext_method {
    pub ext_nid: libc::c_int,
    pub ext_flags: libc::c_int,
    pub it: *const ASN1_ITEM_EXP,
    pub ext_new: X509V3_EXT_NEW,
    pub ext_free: X509V3_EXT_FREE,
    pub d2i: X509V3_EXT_D2I,
    pub i2d: X509V3_EXT_I2D,
    pub i2s: X509V3_EXT_I2S,
    pub s2i: X509V3_EXT_S2I,
    pub i2v: X509V3_EXT_I2V,
    pub v2i: X509V3_EXT_V2I,
    pub i2r: X509V3_EXT_I2R,
    pub r2i: X509V3_EXT_R2I,
    pub usr_data: *mut libc::c_void,
}
pub type X509V3_EXT_R2I = Option::<
    unsafe extern "C" fn(
        *const X509V3_EXT_METHOD,
        *const X509V3_CTX,
        *const libc::c_char,
    ) -> *mut libc::c_void,
>;
pub type X509V3_EXT_METHOD = v3_ext_method;
pub type X509V3_EXT_I2R = Option::<
    unsafe extern "C" fn(
        *const X509V3_EXT_METHOD,
        *mut libc::c_void,
        *mut BIO,
        libc::c_int,
    ) -> libc::c_int,
>;
pub type X509V3_EXT_V2I = Option::<
    unsafe extern "C" fn(
        *const X509V3_EXT_METHOD,
        *const X509V3_CTX,
        *const stack_st_CONF_VALUE,
    ) -> *mut libc::c_void,
>;
pub type X509V3_EXT_I2V = Option::<
    unsafe extern "C" fn(
        *const X509V3_EXT_METHOD,
        *mut libc::c_void,
        *mut stack_st_CONF_VALUE,
    ) -> *mut stack_st_CONF_VALUE,
>;
pub type X509V3_EXT_S2I = Option::<
    unsafe extern "C" fn(
        *const X509V3_EXT_METHOD,
        *const X509V3_CTX,
        *const libc::c_char,
    ) -> *mut libc::c_void,
>;
pub type X509V3_EXT_I2S = Option::<
    unsafe extern "C" fn(
        *const X509V3_EXT_METHOD,
        *mut libc::c_void,
    ) -> *mut libc::c_char,
>;
pub type X509V3_EXT_I2D = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *mut *mut uint8_t) -> libc::c_int,
>;
pub type X509V3_EXT_D2I = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *mut *const uint8_t,
        libc::c_long,
    ) -> *mut libc::c_void,
>;
pub type X509V3_EXT_FREE = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type X509V3_EXT_NEW = Option::<unsafe extern "C" fn() -> *mut libc::c_void>;
pub type ASN1_ITEM_EXP = ASN1_ITEM;
unsafe extern "C" fn i2s_ASN1_INTEGER_cb(
    mut method: *const X509V3_EXT_METHOD,
    mut ext: *mut libc::c_void,
) -> *mut libc::c_char {
    return i2s_ASN1_INTEGER(method, ext as *const ASN1_INTEGER);
}
unsafe extern "C" fn s2i_asn1_int(
    mut meth: *const X509V3_EXT_METHOD,
    mut ctx: *const X509V3_CTX,
    mut value: *const libc::c_char,
) -> *mut libc::c_void {
    return s2i_ASN1_INTEGER(meth, value) as *mut libc::c_void;
}
#[no_mangle]
pub static mut v3_crl_num: X509V3_EXT_METHOD = unsafe {
    {
        let mut init = v3_ext_method {
            ext_nid: 88 as libc::c_int,
            ext_flags: 0 as libc::c_int,
            it: &ASN1_INTEGER_it as *const ASN1_ITEM,
            ext_new: None,
            ext_free: None,
            d2i: None,
            i2d: None,
            i2s: Some(
                i2s_ASN1_INTEGER_cb
                    as unsafe extern "C" fn(
                        *const X509V3_EXT_METHOD,
                        *mut libc::c_void,
                    ) -> *mut libc::c_char,
            ),
            s2i: None,
            i2v: None,
            v2i: None,
            i2r: None,
            r2i: None,
            usr_data: 0 as *const libc::c_void as *mut libc::c_void,
        };
        init
    }
};
#[no_mangle]
pub static mut v3_delta_crl: X509V3_EXT_METHOD = unsafe {
    {
        let mut init = v3_ext_method {
            ext_nid: 140 as libc::c_int,
            ext_flags: 0 as libc::c_int,
            it: &ASN1_INTEGER_it as *const ASN1_ITEM,
            ext_new: None,
            ext_free: None,
            d2i: None,
            i2d: None,
            i2s: Some(
                i2s_ASN1_INTEGER_cb
                    as unsafe extern "C" fn(
                        *const X509V3_EXT_METHOD,
                        *mut libc::c_void,
                    ) -> *mut libc::c_char,
            ),
            s2i: None,
            i2v: None,
            v2i: None,
            i2r: None,
            r2i: None,
            usr_data: 0 as *const libc::c_void as *mut libc::c_void,
        };
        init
    }
};
#[no_mangle]
pub static mut v3_inhibit_anyp: X509V3_EXT_METHOD = unsafe {
    {
        let mut init = v3_ext_method {
            ext_nid: 748 as libc::c_int,
            ext_flags: 0 as libc::c_int,
            it: &ASN1_INTEGER_it as *const ASN1_ITEM,
            ext_new: None,
            ext_free: None,
            d2i: None,
            i2d: None,
            i2s: Some(
                i2s_ASN1_INTEGER_cb
                    as unsafe extern "C" fn(
                        *const X509V3_EXT_METHOD,
                        *mut libc::c_void,
                    ) -> *mut libc::c_char,
            ),
            s2i: Some(
                s2i_asn1_int
                    as unsafe extern "C" fn(
                        *const X509V3_EXT_METHOD,
                        *const X509V3_CTX,
                        *const libc::c_char,
                    ) -> *mut libc::c_void,
            ),
            i2v: None,
            v2i: None,
            i2r: None,
            r2i: None,
            usr_data: 0 as *const libc::c_void as *mut libc::c_void,
        };
        init
    }
};
