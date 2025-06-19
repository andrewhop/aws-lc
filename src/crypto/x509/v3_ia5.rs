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
    pub type ASN1_ITEM_st;
    pub type X509_crl_st;
    pub type x509_st;
    pub type X509_req_st;
    pub type stack_st_void;
    pub type lhash_st_CONF_VALUE;
    pub type stack_st_CONF_VALUE;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn ASN1_STRING_set(
        str: *mut ASN1_STRING,
        data: *const libc::c_void,
        len: ossl_ssize_t,
    ) -> libc::c_int;
    fn ASN1_IA5STRING_new() -> *mut ASN1_IA5STRING;
    fn ASN1_IA5STRING_free(str: *mut ASN1_IA5STRING);
    static ASN1_IA5STRING_it: ASN1_ITEM;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
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
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type ptrdiff_t = libc::c_long;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type ossl_ssize_t = ptrdiff_t;
pub type ASN1_ITEM = ASN1_ITEM_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_string_st {
    pub length: libc::c_int,
    pub type_0: libc::c_int,
    pub data: *mut libc::c_uchar,
    pub flags: libc::c_long,
}
pub type ASN1_IA5STRING = asn1_string_st;
pub type ASN1_STRING = asn1_string_st;
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
unsafe extern "C" fn i2s_ASN1_IA5STRING(
    mut method: *const X509V3_EXT_METHOD,
    mut ext: *mut libc::c_void,
) -> *mut libc::c_char {
    let mut ia5: *const ASN1_IA5STRING = ext as *const ASN1_IA5STRING;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    if ia5.is_null() || (*ia5).length == 0 {
        return 0 as *mut libc::c_char;
    }
    tmp = OPENSSL_malloc(((*ia5).length + 1 as libc::c_int) as size_t)
        as *mut libc::c_char;
    if tmp.is_null() {
        return 0 as *mut libc::c_char;
    }
    OPENSSL_memcpy(
        tmp as *mut libc::c_void,
        (*ia5).data as *const libc::c_void,
        (*ia5).length as size_t,
    );
    *tmp.offset((*ia5).length as isize) = 0 as libc::c_int as libc::c_char;
    return tmp;
}
unsafe extern "C" fn s2i_ASN1_IA5STRING(
    mut method: *const X509V3_EXT_METHOD,
    mut ctx: *const X509V3_CTX,
    mut str: *const libc::c_char,
) -> *mut libc::c_void {
    let mut ia5: *mut ASN1_IA5STRING = 0 as *mut ASN1_IA5STRING;
    if str.is_null() {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            124 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_ia5.c\0" as *const u8
                as *const libc::c_char,
            90 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut libc::c_void;
    }
    ia5 = ASN1_IA5STRING_new();
    if !ia5.is_null() {
        if ASN1_STRING_set(ia5, str as *const libc::c_void, strlen(str) as ossl_ssize_t)
            == 0
        {
            ASN1_IA5STRING_free(ia5);
        } else {
            return ia5 as *mut libc::c_void
        }
    }
    return 0 as *mut libc::c_void;
}
#[unsafe(no_mangle)]
pub static mut v3_ns_ia5_list: [X509V3_EXT_METHOD; 8] = unsafe {
    [
        {
            let mut init = v3_ext_method {
                ext_nid: 72 as libc::c_int,
                ext_flags: 0 as libc::c_int,
                it: &ASN1_IA5STRING_it as *const ASN1_ITEM,
                ext_new: None,
                ext_free: None,
                d2i: None,
                i2d: None,
                i2s: Some(
                    i2s_ASN1_IA5STRING
                        as unsafe extern "C" fn(
                            *const X509V3_EXT_METHOD,
                            *mut libc::c_void,
                        ) -> *mut libc::c_char,
                ),
                s2i: Some(
                    s2i_ASN1_IA5STRING
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
        },
        {
            let mut init = v3_ext_method {
                ext_nid: 73 as libc::c_int,
                ext_flags: 0 as libc::c_int,
                it: &ASN1_IA5STRING_it as *const ASN1_ITEM,
                ext_new: None,
                ext_free: None,
                d2i: None,
                i2d: None,
                i2s: Some(
                    i2s_ASN1_IA5STRING
                        as unsafe extern "C" fn(
                            *const X509V3_EXT_METHOD,
                            *mut libc::c_void,
                        ) -> *mut libc::c_char,
                ),
                s2i: Some(
                    s2i_ASN1_IA5STRING
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
        },
        {
            let mut init = v3_ext_method {
                ext_nid: 74 as libc::c_int,
                ext_flags: 0 as libc::c_int,
                it: &ASN1_IA5STRING_it as *const ASN1_ITEM,
                ext_new: None,
                ext_free: None,
                d2i: None,
                i2d: None,
                i2s: Some(
                    i2s_ASN1_IA5STRING
                        as unsafe extern "C" fn(
                            *const X509V3_EXT_METHOD,
                            *mut libc::c_void,
                        ) -> *mut libc::c_char,
                ),
                s2i: Some(
                    s2i_ASN1_IA5STRING
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
        },
        {
            let mut init = v3_ext_method {
                ext_nid: 75 as libc::c_int,
                ext_flags: 0 as libc::c_int,
                it: &ASN1_IA5STRING_it as *const ASN1_ITEM,
                ext_new: None,
                ext_free: None,
                d2i: None,
                i2d: None,
                i2s: Some(
                    i2s_ASN1_IA5STRING
                        as unsafe extern "C" fn(
                            *const X509V3_EXT_METHOD,
                            *mut libc::c_void,
                        ) -> *mut libc::c_char,
                ),
                s2i: Some(
                    s2i_ASN1_IA5STRING
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
        },
        {
            let mut init = v3_ext_method {
                ext_nid: 76 as libc::c_int,
                ext_flags: 0 as libc::c_int,
                it: &ASN1_IA5STRING_it as *const ASN1_ITEM,
                ext_new: None,
                ext_free: None,
                d2i: None,
                i2d: None,
                i2s: Some(
                    i2s_ASN1_IA5STRING
                        as unsafe extern "C" fn(
                            *const X509V3_EXT_METHOD,
                            *mut libc::c_void,
                        ) -> *mut libc::c_char,
                ),
                s2i: Some(
                    s2i_ASN1_IA5STRING
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
        },
        {
            let mut init = v3_ext_method {
                ext_nid: 77 as libc::c_int,
                ext_flags: 0 as libc::c_int,
                it: &ASN1_IA5STRING_it as *const ASN1_ITEM,
                ext_new: None,
                ext_free: None,
                d2i: None,
                i2d: None,
                i2s: Some(
                    i2s_ASN1_IA5STRING
                        as unsafe extern "C" fn(
                            *const X509V3_EXT_METHOD,
                            *mut libc::c_void,
                        ) -> *mut libc::c_char,
                ),
                s2i: Some(
                    s2i_ASN1_IA5STRING
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
        },
        {
            let mut init = v3_ext_method {
                ext_nid: 78 as libc::c_int,
                ext_flags: 0 as libc::c_int,
                it: &ASN1_IA5STRING_it as *const ASN1_ITEM,
                ext_new: None,
                ext_free: None,
                d2i: None,
                i2d: None,
                i2s: Some(
                    i2s_ASN1_IA5STRING
                        as unsafe extern "C" fn(
                            *const X509V3_EXT_METHOD,
                            *mut libc::c_void,
                        ) -> *mut libc::c_char,
                ),
                s2i: Some(
                    s2i_ASN1_IA5STRING
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
        },
        {
            let mut init = v3_ext_method {
                ext_nid: -(1 as libc::c_int),
                ext_flags: 0 as libc::c_int,
                it: 0 as *const ASN1_ITEM_EXP,
                ext_new: None,
                ext_free: None,
                d2i: None,
                i2d: None,
                i2s: None,
                s2i: None,
                i2v: None,
                v2i: None,
                i2r: None,
                r2i: None,
                usr_data: 0 as *const libc::c_void as *mut libc::c_void,
            };
            init
        },
    ]
};
