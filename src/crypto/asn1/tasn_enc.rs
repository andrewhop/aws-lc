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
    pub type asn1_pctx_st;
    pub type ASN1_VALUE_st;
    pub type stack_st_void;
    pub type stack_st;
    pub type stack_st_ASN1_VALUE;
    pub type ASN1_TLC_st;
    fn qsort(
        __base: *mut libc::c_void,
        __nmemb: size_t,
        __size: size_t,
        __compar: __compar_fn_t,
    );
    fn i2c_ASN1_BIT_STRING(
        in_0: *const ASN1_BIT_STRING,
        outp: *mut *mut uint8_t,
    ) -> libc::c_int;
    fn i2c_ASN1_INTEGER(
        in_0: *const ASN1_INTEGER,
        outp: *mut *mut uint8_t,
    ) -> libc::c_int;
    fn ASN1_put_object(
        outp: *mut *mut libc::c_uchar,
        constructed: libc::c_int,
        length: libc::c_int,
        tag: libc::c_int,
        xclass: libc::c_int,
    );
    fn ASN1_object_size(
        constructed: libc::c_int,
        length: libc::c_int,
        tag: libc::c_int,
    ) -> libc::c_int;
    fn asn1_get_choice_selector(
        pval: *mut *mut ASN1_VALUE,
        it: *const ASN1_ITEM,
    ) -> libc::c_int;
    fn asn1_get_field_ptr(
        pval: *mut *mut ASN1_VALUE,
        tt: *const ASN1_TEMPLATE,
    ) -> *mut *mut ASN1_VALUE;
    fn asn1_do_adb(
        pval: *mut *mut ASN1_VALUE,
        tt: *const ASN1_TEMPLATE,
        nullerr: libc::c_int,
    ) -> *const ASN1_TEMPLATE;
    fn asn1_enc_restore(
        len: *mut libc::c_int,
        out: *mut *mut libc::c_uchar,
        pval: *mut *mut ASN1_VALUE,
        it: *const ASN1_ITEM,
    ) -> libc::c_int;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_calloc(num: size_t, size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
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
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type __compar_fn_t = Option::<
    unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> libc::c_int,
>;
pub type ASN1_BOOLEAN = libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ASN1_ITEM_st {
    pub itype: libc::c_char,
    pub utype: libc::c_int,
    pub templates: *const ASN1_TEMPLATE,
    pub tcount: libc::c_long,
    pub funcs: *const libc::c_void,
    pub size: libc::c_long,
    pub sname: *const libc::c_char,
}
pub type ASN1_TEMPLATE = ASN1_TEMPLATE_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ASN1_TEMPLATE_st {
    pub flags: uint32_t,
    pub tag: libc::c_int,
    pub offset: libc::c_ulong,
    pub field_name: *const libc::c_char,
    pub item: *const ASN1_ITEM_EXP,
}
pub type ASN1_ITEM_EXP = ASN1_ITEM;
pub type ASN1_ITEM = ASN1_ITEM_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_object_st {
    pub sn: *const libc::c_char,
    pub ln: *const libc::c_char,
    pub nid: libc::c_int,
    pub length: libc::c_int,
    pub data: *const libc::c_uchar,
    pub flags: libc::c_int,
}
pub type ASN1_OBJECT = asn1_object_st;
pub type ASN1_PCTX = asn1_pctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_string_st {
    pub length: libc::c_int,
    pub type_0: libc::c_int,
    pub data: *mut libc::c_uchar,
    pub flags: libc::c_long,
}
pub type ASN1_BIT_STRING = asn1_string_st;
pub type ASN1_BMPSTRING = asn1_string_st;
pub type ASN1_ENUMERATED = asn1_string_st;
pub type ASN1_GENERALIZEDTIME = asn1_string_st;
pub type ASN1_GENERALSTRING = asn1_string_st;
pub type ASN1_IA5STRING = asn1_string_st;
pub type ASN1_INTEGER = asn1_string_st;
pub type ASN1_OCTET_STRING = asn1_string_st;
pub type ASN1_PRINTABLESTRING = asn1_string_st;
pub type ASN1_STRING = asn1_string_st;
pub type ASN1_T61STRING = asn1_string_st;
pub type ASN1_UNIVERSALSTRING = asn1_string_st;
pub type ASN1_UTCTIME = asn1_string_st;
pub type ASN1_UTF8STRING = asn1_string_st;
pub type ASN1_VISIBLESTRING = asn1_string_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_type_st {
    pub type_0: libc::c_int,
    pub value: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub ptr: *mut libc::c_char,
    pub boolean: ASN1_BOOLEAN,
    pub asn1_string: *mut ASN1_STRING,
    pub object: *mut ASN1_OBJECT,
    pub integer: *mut ASN1_INTEGER,
    pub enumerated: *mut ASN1_ENUMERATED,
    pub bit_string: *mut ASN1_BIT_STRING,
    pub octet_string: *mut ASN1_OCTET_STRING,
    pub printablestring: *mut ASN1_PRINTABLESTRING,
    pub t61string: *mut ASN1_T61STRING,
    pub ia5string: *mut ASN1_IA5STRING,
    pub generalstring: *mut ASN1_GENERALSTRING,
    pub bmpstring: *mut ASN1_BMPSTRING,
    pub universalstring: *mut ASN1_UNIVERSALSTRING,
    pub utctime: *mut ASN1_UTCTIME,
    pub generalizedtime: *mut ASN1_GENERALIZEDTIME,
    pub visiblestring: *mut ASN1_VISIBLESTRING,
    pub utf8string: *mut ASN1_UTF8STRING,
    pub set: *mut ASN1_STRING,
    pub sequence: *mut ASN1_STRING,
    pub asn1_value: *mut ASN1_VALUE,
}
pub type ASN1_VALUE = ASN1_VALUE_st;
pub type ASN1_TYPE = asn1_type_st;
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
pub type OPENSSL_STACK = stack_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct DER_ENC {
    pub data: *mut libc::c_uchar,
    pub length: libc::c_int,
}
pub type ASN1_ex_i2d = unsafe extern "C" fn(
    *mut *mut ASN1_VALUE,
    *mut *mut libc::c_uchar,
    *const ASN1_ITEM,
    libc::c_int,
    libc::c_int,
) -> libc::c_int;
pub type ASN1_EXTERN_FUNCS = ASN1_EXTERN_FUNCS_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ASN1_EXTERN_FUNCS_st {
    pub app_data: *mut libc::c_void,
    pub asn1_ex_new: Option::<ASN1_ex_new_func>,
    pub asn1_ex_free: Option::<ASN1_ex_free_func>,
    pub asn1_ex_d2i: Option::<ASN1_ex_d2i>,
    pub asn1_ex_i2d: Option::<ASN1_ex_i2d>,
    pub asn1_ex_print: Option::<ASN1_ex_print_func>,
}
pub type ASN1_ex_print_func = unsafe extern "C" fn(
    *mut BIO,
    *mut *mut ASN1_VALUE,
    libc::c_int,
    *const libc::c_char,
    *const ASN1_PCTX,
) -> libc::c_int;
pub type ASN1_ex_d2i = unsafe extern "C" fn(
    *mut *mut ASN1_VALUE,
    *mut *const libc::c_uchar,
    libc::c_long,
    *const ASN1_ITEM,
    libc::c_int,
    libc::c_int,
    libc::c_char,
    *mut ASN1_TLC,
) -> libc::c_int;
pub type ASN1_TLC = ASN1_TLC_st;
pub type ASN1_ex_free_func = unsafe extern "C" fn(
    *mut *mut ASN1_VALUE,
    *const ASN1_ITEM,
) -> ();
pub type ASN1_ex_new_func = unsafe extern "C" fn(
    *mut *mut ASN1_VALUE,
    *const ASN1_ITEM,
) -> libc::c_int;
#[inline]
unsafe extern "C" fn sk_ASN1_VALUE_num(mut sk: *const stack_st_ASN1_VALUE) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_ASN1_VALUE_value(
    mut sk: *const stack_st_ASN1_VALUE,
    mut i: size_t,
) -> *mut ASN1_VALUE {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut ASN1_VALUE;
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_item_i2d(
    mut val: *mut ASN1_VALUE,
    mut out: *mut *mut libc::c_uchar,
    mut it: *const ASN1_ITEM,
) -> libc::c_int {
    if !out.is_null() && (*out).is_null() {
        let mut p: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
        let mut buf: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
        let mut len: libc::c_int = ASN1_item_ex_i2d(
            &mut val,
            0 as *mut *mut libc::c_uchar,
            it,
            -(1 as libc::c_int),
            0 as libc::c_int,
        );
        if len <= 0 as libc::c_int {
            return len;
        }
        buf = OPENSSL_malloc(len as size_t) as *mut libc::c_uchar;
        if buf.is_null() {
            return -(1 as libc::c_int);
        }
        p = buf;
        let mut len2: libc::c_int = ASN1_item_ex_i2d(
            &mut val,
            &mut p,
            it,
            -(1 as libc::c_int),
            0 as libc::c_int,
        );
        if len2 <= 0 as libc::c_int {
            OPENSSL_free(buf as *mut libc::c_void);
            return len2;
        }
        if len == len2 {} else {
            __assert_fail(
                b"len == len2\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                    as *const u8 as *const libc::c_char,
                103 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 69],
                    &[libc::c_char; 69],
                >(
                    b"int ASN1_item_i2d(ASN1_VALUE *, unsigned char **, const ASN1_ITEM *)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_9598: {
            if len == len2 {} else {
                __assert_fail(
                    b"len == len2\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                        as *const u8 as *const libc::c_char,
                    103 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 69],
                        &[libc::c_char; 69],
                    >(
                        b"int ASN1_item_i2d(ASN1_VALUE *, unsigned char **, const ASN1_ITEM *)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        *out = buf;
        return len;
    }
    return ASN1_item_ex_i2d(&mut val, out, it, -(1 as libc::c_int), 0 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_item_ex_i2d(
    mut pval: *mut *mut ASN1_VALUE,
    mut out: *mut *mut libc::c_uchar,
    mut it: *const ASN1_ITEM,
    mut tag: libc::c_int,
    mut aclass: libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = asn1_item_ex_i2d_opt(
        pval,
        out,
        it,
        tag,
        aclass,
        0 as libc::c_int,
    );
    if ret != 0 as libc::c_int {} else {
        __assert_fail(
            b"ret != 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0" as *const u8
                as *const libc::c_char,
            117 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 83],
                &[libc::c_char; 83],
            >(
                b"int ASN1_item_ex_i2d(ASN1_VALUE **, unsigned char **, const ASN1_ITEM *, int, int)\0",
            ))
                .as_ptr(),
        );
    }
    'c_9523: {
        if ret != 0 as libc::c_int {} else {
            __assert_fail(
                b"ret != 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                    as *const u8 as *const libc::c_char,
                117 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 83],
                    &[libc::c_char; 83],
                >(
                    b"int ASN1_item_ex_i2d(ASN1_VALUE **, unsigned char **, const ASN1_ITEM *, int, int)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    return ret;
}
unsafe extern "C" fn asn1_item_ex_i2d_opt(
    mut pval: *mut *mut ASN1_VALUE,
    mut out: *mut *mut libc::c_uchar,
    mut it: *const ASN1_ITEM,
    mut tag: libc::c_int,
    mut aclass: libc::c_int,
    mut optional: libc::c_int,
) -> libc::c_int {
    let mut tt: *const ASN1_TEMPLATE = 0 as *const ASN1_TEMPLATE;
    let mut i: libc::c_int = 0;
    let mut seqcontlen: libc::c_int = 0;
    let mut seqlen: libc::c_int = 0;
    if aclass & (0x3 as libc::c_int) << 6 as libc::c_int == aclass {} else {
        __assert_fail(
            b"(aclass & ASN1_TFLG_TAG_CLASS) == aclass\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0" as *const u8
                as *const libc::c_char,
            131 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 92],
                &[libc::c_char; 92],
            >(
                b"int asn1_item_ex_i2d_opt(ASN1_VALUE **, unsigned char **, const ASN1_ITEM *, int, int, int)\0",
            ))
                .as_ptr(),
        );
    }
    'c_9473: {
        if aclass & (0x3 as libc::c_int) << 6 as libc::c_int == aclass {} else {
            __assert_fail(
                b"(aclass & ASN1_TFLG_TAG_CLASS) == aclass\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                    as *const u8 as *const libc::c_char,
                131 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 92],
                    &[libc::c_char; 92],
                >(
                    b"int asn1_item_ex_i2d_opt(ASN1_VALUE **, unsigned char **, const ASN1_ITEM *, int, int, int)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if tag != -(1 as libc::c_int) || aclass == 0 as libc::c_int {} else {
        __assert_fail(
            b"tag != -1 || aclass == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0" as *const u8
                as *const libc::c_char,
            133 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 92],
                &[libc::c_char; 92],
            >(
                b"int asn1_item_ex_i2d_opt(ASN1_VALUE **, unsigned char **, const ASN1_ITEM *, int, int, int)\0",
            ))
                .as_ptr(),
        );
    }
    'c_9424: {
        if tag != -(1 as libc::c_int) || aclass == 0 as libc::c_int {} else {
            __assert_fail(
                b"tag != -1 || aclass == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                    as *const u8 as *const libc::c_char,
                133 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 92],
                    &[libc::c_char; 92],
                >(
                    b"int asn1_item_ex_i2d_opt(ASN1_VALUE **, unsigned char **, const ASN1_ITEM *, int, int, int)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if (*it).itype as libc::c_int != 0 as libc::c_int && (*pval).is_null() {
        if optional != 0 {
            return 0 as libc::c_int;
        }
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            155 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0" as *const u8
                as *const libc::c_char,
            141 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    match (*it).itype as libc::c_int {
        0 => {
            if !((*it).templates).is_null() {
                if (*(*it).templates).flags & 0x1 as libc::c_int as uint32_t != 0 {
                    ERR_put_error(
                        12 as libc::c_int,
                        0 as libc::c_int,
                        193 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                            as *const u8 as *const libc::c_char,
                        150 as libc::c_int as libc::c_uint,
                    );
                    return -(1 as libc::c_int);
                }
                return asn1_template_ex_i2d(
                    pval,
                    out,
                    (*it).templates,
                    tag,
                    aclass,
                    optional,
                );
            }
            return asn1_i2d_ex_primitive(pval, out, it, tag, aclass, optional);
        }
        5 => {
            if tag != -(1 as libc::c_int) {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    193 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                        as *const u8 as *const libc::c_char,
                    162 as libc::c_int as libc::c_uint,
                );
                return -(1 as libc::c_int);
            }
            return asn1_i2d_ex_primitive(
                pval,
                out,
                it,
                -(1 as libc::c_int),
                0 as libc::c_int,
                optional,
            );
        }
        2 => {
            if tag != -(1 as libc::c_int) {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    193 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                        as *const u8 as *const libc::c_char,
                    171 as libc::c_int as libc::c_uint,
                );
                return -(1 as libc::c_int);
            }
            i = asn1_get_choice_selector(pval, it);
            if i < 0 as libc::c_int || i as libc::c_long >= (*it).tcount {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    163 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                        as *const u8 as *const libc::c_char,
                    176 as libc::c_int as libc::c_uint,
                );
                return -(1 as libc::c_int);
            }
            let mut chtt: *const ASN1_TEMPLATE = ((*it).templates).offset(i as isize);
            if (*chtt).flags & 0x1 as libc::c_int as uint32_t != 0 {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    193 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                        as *const u8 as *const libc::c_char,
                    181 as libc::c_int as libc::c_uint,
                );
                return -(1 as libc::c_int);
            }
            let mut pchval: *mut *mut ASN1_VALUE = asn1_get_field_ptr(pval, chtt);
            return asn1_template_ex_i2d(
                pchval,
                out,
                chtt,
                -(1 as libc::c_int),
                0 as libc::c_int,
                0 as libc::c_int,
            );
        }
        4 => {
            let mut ef: *const ASN1_EXTERN_FUNCS = (*it).funcs
                as *const ASN1_EXTERN_FUNCS;
            let mut ret: libc::c_int = ((*ef).asn1_ex_i2d)
                .expect("non-null function pointer")(pval, out, it, tag, aclass);
            if ret == 0 as libc::c_int {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    4 as libc::c_int | 64 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                        as *const u8 as *const libc::c_char,
                    196 as libc::c_int as libc::c_uint,
                );
                return -(1 as libc::c_int);
            }
            return ret;
        }
        1 => {
            i = asn1_enc_restore(&mut seqcontlen, out, pval, it);
            if i < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            if i > 0 as libc::c_int {
                return seqcontlen;
            }
            seqcontlen = 0 as libc::c_int;
            if tag == -(1 as libc::c_int) {
                tag = 16 as libc::c_int;
                aclass = 0 as libc::c_int;
            }
            i = 0 as libc::c_int;
            tt = (*it).templates;
            while (i as libc::c_long) < (*it).tcount {
                let mut seqtt: *const ASN1_TEMPLATE = 0 as *const ASN1_TEMPLATE;
                let mut pseqval: *mut *mut ASN1_VALUE = 0 as *mut *mut ASN1_VALUE;
                let mut tmplen: libc::c_int = 0;
                seqtt = asn1_do_adb(pval, tt, 1 as libc::c_int);
                if seqtt.is_null() {
                    return -(1 as libc::c_int);
                }
                pseqval = asn1_get_field_ptr(pval, seqtt);
                tmplen = asn1_template_ex_i2d(
                    pseqval,
                    0 as *mut *mut libc::c_uchar,
                    seqtt,
                    -(1 as libc::c_int),
                    0 as libc::c_int,
                    0 as libc::c_int,
                );
                if tmplen == -(1 as libc::c_int)
                    || tmplen > 2147483647 as libc::c_int - seqcontlen
                {
                    return -(1 as libc::c_int);
                }
                seqcontlen += tmplen;
                tt = tt.offset(1);
                tt;
                i += 1;
                i;
            }
            seqlen = ASN1_object_size(1 as libc::c_int, seqcontlen, tag);
            if out.is_null() || seqlen == -(1 as libc::c_int) {
                return seqlen;
            }
            ASN1_put_object(out, 1 as libc::c_int, seqcontlen, tag, aclass);
            i = 0 as libc::c_int;
            tt = (*it).templates;
            while (i as libc::c_long) < (*it).tcount {
                let mut seqtt_0: *const ASN1_TEMPLATE = 0 as *const ASN1_TEMPLATE;
                let mut pseqval_0: *mut *mut ASN1_VALUE = 0 as *mut *mut ASN1_VALUE;
                seqtt_0 = asn1_do_adb(pval, tt, 1 as libc::c_int);
                if seqtt_0.is_null() {
                    return -(1 as libc::c_int);
                }
                pseqval_0 = asn1_get_field_ptr(pval, seqtt_0);
                if asn1_template_ex_i2d(
                    pseqval_0,
                    out,
                    seqtt_0,
                    -(1 as libc::c_int),
                    0 as libc::c_int,
                    0 as libc::c_int,
                ) < 0 as libc::c_int
                {
                    return -(1 as libc::c_int);
                }
                tt = tt.offset(1);
                tt;
                i += 1;
                i;
            }
            return seqlen;
        }
        _ => {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                193 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                    as *const u8 as *const libc::c_char,
                260 as libc::c_int as libc::c_uint,
            );
            return -(1 as libc::c_int);
        }
    };
}
unsafe extern "C" fn asn1_template_ex_i2d(
    mut pval: *mut *mut ASN1_VALUE,
    mut out: *mut *mut libc::c_uchar,
    mut tt: *const ASN1_TEMPLATE,
    mut tag: libc::c_int,
    mut iclass: libc::c_int,
    mut optional: libc::c_int,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    let mut ttag: libc::c_int = 0;
    let mut tclass: libc::c_int = 0;
    let mut j: size_t = 0;
    let mut flags: uint32_t = (*tt).flags;
    if iclass & (0x3 as libc::c_int) << 6 as libc::c_int == iclass {} else {
        __assert_fail(
            b"(iclass & ASN1_TFLG_TAG_CLASS) == iclass\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0" as *const u8
                as *const libc::c_char,
            277 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 96],
                &[libc::c_char; 96],
            >(
                b"int asn1_template_ex_i2d(ASN1_VALUE **, unsigned char **, const ASN1_TEMPLATE *, int, int, int)\0",
            ))
                .as_ptr(),
        );
    }
    'c_7857: {
        if iclass & (0x3 as libc::c_int) << 6 as libc::c_int == iclass {} else {
            __assert_fail(
                b"(iclass & ASN1_TFLG_TAG_CLASS) == iclass\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                    as *const u8 as *const libc::c_char,
                277 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 96],
                    &[libc::c_char; 96],
                >(
                    b"int asn1_template_ex_i2d(ASN1_VALUE **, unsigned char **, const ASN1_TEMPLATE *, int, int, int)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if tag != -(1 as libc::c_int) || iclass == 0 as libc::c_int {} else {
        __assert_fail(
            b"tag != -1 || iclass == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0" as *const u8
                as *const libc::c_char,
            279 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 96],
                &[libc::c_char; 96],
            >(
                b"int asn1_template_ex_i2d(ASN1_VALUE **, unsigned char **, const ASN1_TEMPLATE *, int, int, int)\0",
            ))
                .as_ptr(),
        );
    }
    'c_7808: {
        if tag != -(1 as libc::c_int) || iclass == 0 as libc::c_int {} else {
            __assert_fail(
                b"tag != -1 || iclass == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                    as *const u8 as *const libc::c_char,
                279 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 96],
                    &[libc::c_char; 96],
                >(
                    b"int asn1_template_ex_i2d(ASN1_VALUE **, unsigned char **, const ASN1_TEMPLATE *, int, int, int)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if flags & ((0x3 as libc::c_int) << 3 as libc::c_int) as uint32_t != 0 {
        if tag != -(1 as libc::c_int) {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                193 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                    as *const u8 as *const libc::c_char,
                287 as libc::c_int as libc::c_uint,
            );
            return -(1 as libc::c_int);
        }
        ttag = (*tt).tag;
        tclass = (flags & ((0x3 as libc::c_int) << 6 as libc::c_int) as uint32_t)
            as libc::c_int;
    } else if tag != -(1 as libc::c_int) {
        ttag = tag;
        tclass = iclass & (0x3 as libc::c_int) << 6 as libc::c_int;
    } else {
        ttag = -(1 as libc::c_int);
        tclass = 0 as libc::c_int;
    }
    if optional == 0
        || flags & 0x1 as libc::c_int as uint32_t == 0 as libc::c_int as uint32_t
    {} else {
        __assert_fail(
            b"!optional || (flags & ASN1_TFLG_OPTIONAL) == 0\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0" as *const u8
                as *const libc::c_char,
            306 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 96],
                &[libc::c_char; 96],
            >(
                b"int asn1_template_ex_i2d(ASN1_VALUE **, unsigned char **, const ASN1_TEMPLATE *, int, int, int)\0",
            ))
                .as_ptr(),
        );
    }
    'c_7668: {
        if optional == 0
            || flags & 0x1 as libc::c_int as uint32_t == 0 as libc::c_int as uint32_t
        {} else {
            __assert_fail(
                b"!optional || (flags & ASN1_TFLG_OPTIONAL) == 0\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                    as *const u8 as *const libc::c_char,
                306 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 96],
                    &[libc::c_char; 96],
                >(
                    b"int asn1_template_ex_i2d(ASN1_VALUE **, unsigned char **, const ASN1_TEMPLATE *, int, int, int)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    optional = (optional != 0
        || flags & 0x1 as libc::c_int as uint32_t != 0 as libc::c_int as uint32_t)
        as libc::c_int;
    if flags & ((0x3 as libc::c_int) << 1 as libc::c_int) as uint32_t != 0 {
        let mut sk: *mut stack_st_ASN1_VALUE = *pval as *mut stack_st_ASN1_VALUE;
        let mut isset: libc::c_int = 0;
        let mut sktag: libc::c_int = 0;
        let mut skaclass: libc::c_int = 0;
        let mut skcontlen: libc::c_int = 0;
        let mut sklen: libc::c_int = 0;
        let mut skitem: *mut ASN1_VALUE = 0 as *mut ASN1_VALUE;
        if (*pval).is_null() {
            if optional != 0 {
                return 0 as libc::c_int;
            }
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                155 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                    as *const u8 as *const libc::c_char,
                323 as libc::c_int as libc::c_uint,
            );
            return -(1 as libc::c_int);
        }
        if flags & ((0x1 as libc::c_int) << 1 as libc::c_int) as uint32_t != 0 {
            isset = 1 as libc::c_int;
            if flags & ((0x2 as libc::c_int) << 1 as libc::c_int) as uint32_t
                == 0 as libc::c_int as uint32_t
            {} else {
                __assert_fail(
                    b"(flags & ASN1_TFLG_SEQUENCE_OF) == 0\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                        as *const u8 as *const libc::c_char,
                    331 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 96],
                        &[libc::c_char; 96],
                    >(
                        b"int asn1_template_ex_i2d(ASN1_VALUE **, unsigned char **, const ASN1_TEMPLATE *, int, int, int)\0",
                    ))
                        .as_ptr(),
                );
            }
            'c_7553: {
                if flags & ((0x2 as libc::c_int) << 1 as libc::c_int) as uint32_t
                    == 0 as libc::c_int as uint32_t
                {} else {
                    __assert_fail(
                        b"(flags & ASN1_TFLG_SEQUENCE_OF) == 0\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                            as *const u8 as *const libc::c_char,
                        331 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 96],
                            &[libc::c_char; 96],
                        >(
                            b"int asn1_template_ex_i2d(ASN1_VALUE **, unsigned char **, const ASN1_TEMPLATE *, int, int, int)\0",
                        ))
                            .as_ptr(),
                    );
                }
            };
        } else {
            isset = 0 as libc::c_int;
        }
        if ttag != -(1 as libc::c_int)
            && flags & ((0x2 as libc::c_int) << 3 as libc::c_int) as uint32_t == 0
        {
            sktag = ttag;
            skaclass = tclass;
        } else {
            skaclass = 0 as libc::c_int;
            if isset != 0 {
                sktag = 17 as libc::c_int;
            } else {
                sktag = 16 as libc::c_int;
            }
        }
        skcontlen = 0 as libc::c_int;
        j = 0 as libc::c_int as size_t;
        while j < sk_ASN1_VALUE_num(sk) {
            let mut tmplen: libc::c_int = 0;
            skitem = sk_ASN1_VALUE_value(sk, j);
            tmplen = ASN1_item_ex_i2d(
                &mut skitem,
                0 as *mut *mut libc::c_uchar,
                (*tt).item,
                -(1 as libc::c_int),
                0 as libc::c_int,
            );
            if tmplen == -(1 as libc::c_int)
                || skcontlen > 2147483647 as libc::c_int - tmplen
            {
                return -(1 as libc::c_int);
            }
            skcontlen += tmplen;
            j = j.wrapping_add(1);
            j;
        }
        sklen = ASN1_object_size(1 as libc::c_int, skcontlen, sktag);
        if sklen == -(1 as libc::c_int) {
            return -(1 as libc::c_int);
        }
        if flags & ((0x2 as libc::c_int) << 3 as libc::c_int) as uint32_t != 0 {
            ret = ASN1_object_size(1 as libc::c_int, sklen, ttag);
        } else {
            ret = sklen;
        }
        if out.is_null() || ret == -(1 as libc::c_int) {
            return ret;
        }
        if flags & ((0x2 as libc::c_int) << 3 as libc::c_int) as uint32_t != 0 {
            ASN1_put_object(out, 1 as libc::c_int, sklen, ttag, tclass);
        }
        ASN1_put_object(out, 1 as libc::c_int, skcontlen, sktag, skaclass);
        if asn1_set_seq_out(sk, out, skcontlen, (*tt).item, isset) == 0 {
            return -(1 as libc::c_int);
        }
        return ret;
    }
    if flags & ((0x2 as libc::c_int) << 3 as libc::c_int) as uint32_t != 0 {
        i = asn1_item_ex_i2d_opt(
            pval,
            0 as *mut *mut libc::c_uchar,
            (*tt).item,
            -(1 as libc::c_int),
            0 as libc::c_int,
            optional,
        );
        if i <= 0 as libc::c_int {
            return i;
        }
        ret = ASN1_object_size(1 as libc::c_int, i, ttag);
        if !out.is_null() && ret != -(1 as libc::c_int) {
            ASN1_put_object(out, 1 as libc::c_int, i, ttag, tclass);
            if ASN1_item_ex_i2d(
                pval,
                out,
                (*tt).item,
                -(1 as libc::c_int),
                0 as libc::c_int,
            ) < 0 as libc::c_int
            {
                return -(1 as libc::c_int);
            }
        }
        return ret;
    }
    return asn1_item_ex_i2d_opt(pval, out, (*tt).item, ttag, tclass, optional);
}
unsafe extern "C" fn der_cmp(
    mut a: *const libc::c_void,
    mut b: *const libc::c_void,
) -> libc::c_int {
    let mut d1: *const DER_ENC = a as *const DER_ENC;
    let mut d2: *const DER_ENC = b as *const DER_ENC;
    let mut cmplen: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    cmplen = if (*d1).length < (*d2).length { (*d1).length } else { (*d2).length };
    i = OPENSSL_memcmp(
        (*d1).data as *const libc::c_void,
        (*d2).data as *const libc::c_void,
        cmplen as size_t,
    );
    if i != 0 {
        return i;
    }
    return (*d1).length - (*d2).length;
}
unsafe extern "C" fn asn1_set_seq_out(
    mut sk: *mut stack_st_ASN1_VALUE,
    mut out: *mut *mut libc::c_uchar,
    mut skcontlen: libc::c_int,
    mut item: *const ASN1_ITEM,
    mut do_sort: libc::c_int,
) -> libc::c_int {
    let mut p: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut current_block: u64;
    if do_sort == 0 || sk_ASN1_VALUE_num(sk) < 2 as libc::c_int as size_t {
        let mut i: size_t = 0 as libc::c_int as size_t;
        while i < sk_ASN1_VALUE_num(sk) {
            let mut skitem: *mut ASN1_VALUE = sk_ASN1_VALUE_value(sk, i);
            if ASN1_item_ex_i2d(
                &mut skitem,
                out,
                item,
                -(1 as libc::c_int),
                0 as libc::c_int,
            ) < 0 as libc::c_int
            {
                return 0 as libc::c_int;
            }
            i = i.wrapping_add(1);
            i;
        }
        return 1 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let buf: *mut libc::c_uchar = OPENSSL_malloc(skcontlen as size_t)
        as *mut libc::c_uchar;
    let mut encoded: *mut DER_ENC = OPENSSL_calloc(
        sk_ASN1_VALUE_num(sk),
        ::core::mem::size_of::<DER_ENC>() as libc::c_ulong,
    ) as *mut DER_ENC;
    if !(encoded.is_null() || buf.is_null()) {
        p = buf;
        let mut i_0: size_t = 0 as libc::c_int as size_t;
        loop {
            if !(i_0 < sk_ASN1_VALUE_num(sk)) {
                current_block = 1054647088692577877;
                break;
            }
            let mut skitem_0: *mut ASN1_VALUE = sk_ASN1_VALUE_value(sk, i_0);
            let ref mut fresh0 = (*encoded.offset(i_0 as isize)).data;
            *fresh0 = p;
            (*encoded.offset(i_0 as isize))
                .length = ASN1_item_ex_i2d(
                &mut skitem_0,
                &mut p,
                item,
                -(1 as libc::c_int),
                0 as libc::c_int,
            );
            if (*encoded.offset(i_0 as isize)).length < 0 as libc::c_int {
                current_block = 17135680227202577361;
                break;
            }
            if p.offset_from(buf) as libc::c_long <= skcontlen as libc::c_long {} else {
                __assert_fail(
                    b"p - buf <= skcontlen\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                        as *const u8 as *const libc::c_char,
                    467 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 98],
                        &[libc::c_char; 98],
                    >(
                        b"int asn1_set_seq_out(struct stack_st_ASN1_VALUE *, unsigned char **, int, const ASN1_ITEM *, int)\0",
                    ))
                        .as_ptr(),
                );
            }
            'c_7111: {
                if p.offset_from(buf) as libc::c_long <= skcontlen as libc::c_long
                {} else {
                    __assert_fail(
                        b"p - buf <= skcontlen\0" as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                            as *const u8 as *const libc::c_char,
                        467 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 98],
                            &[libc::c_char; 98],
                        >(
                            b"int asn1_set_seq_out(struct stack_st_ASN1_VALUE *, unsigned char **, int, const ASN1_ITEM *, int)\0",
                        ))
                            .as_ptr(),
                    );
                }
            };
            i_0 = i_0.wrapping_add(1);
            i_0;
        }
        match current_block {
            17135680227202577361 => {}
            _ => {
                qsort(
                    encoded as *mut libc::c_void,
                    sk_ASN1_VALUE_num(sk),
                    ::core::mem::size_of::<DER_ENC>() as libc::c_ulong,
                    Some(
                        der_cmp
                            as unsafe extern "C" fn(
                                *const libc::c_void,
                                *const libc::c_void,
                            ) -> libc::c_int,
                    ),
                );
                p = *out;
                let mut i_1: size_t = 0 as libc::c_int as size_t;
                while i_1 < sk_ASN1_VALUE_num(sk) {
                    OPENSSL_memcpy(
                        p as *mut libc::c_void,
                        (*encoded.offset(i_1 as isize)).data as *const libc::c_void,
                        (*encoded.offset(i_1 as isize)).length as size_t,
                    );
                    p = p.offset((*encoded.offset(i_1 as isize)).length as isize);
                    i_1 = i_1.wrapping_add(1);
                    i_1;
                }
                *out = p;
                ret = 1 as libc::c_int;
            }
        }
    }
    OPENSSL_free(encoded as *mut libc::c_void);
    OPENSSL_free(buf as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn asn1_i2d_ex_primitive(
    mut pval: *mut *mut ASN1_VALUE,
    mut out: *mut *mut libc::c_uchar,
    mut it: *const ASN1_ITEM,
    mut tag: libc::c_int,
    mut aclass: libc::c_int,
    mut optional: libc::c_int,
) -> libc::c_int {
    let mut omit: libc::c_int = 0;
    let mut utype: libc::c_int = (*it).utype;
    let mut len: libc::c_int = asn1_ex_i2c(
        pval,
        0 as *mut libc::c_uchar,
        &mut omit,
        &mut utype,
        it,
    );
    if len < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    if omit != 0 {
        if optional != 0 {
            return 0 as libc::c_int;
        }
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            155 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0" as *const u8
                as *const libc::c_char,
            504 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    let mut usetag: libc::c_int = (utype != 16 as libc::c_int
        && utype != 17 as libc::c_int && utype != -(3 as libc::c_int)) as libc::c_int;
    if tag == -(1 as libc::c_int) {
        tag = utype;
    }
    if !out.is_null() {
        if usetag != 0 {
            ASN1_put_object(out, 0 as libc::c_int, len, tag, aclass);
        }
        let mut len2: libc::c_int = asn1_ex_i2c(pval, *out, &mut omit, &mut utype, it);
        if len2 < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        if len == len2 {} else {
            __assert_fail(
                b"len == len2\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                    as *const u8 as *const libc::c_char,
                528 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 93],
                    &[libc::c_char; 93],
                >(
                    b"int asn1_i2d_ex_primitive(ASN1_VALUE **, unsigned char **, const ASN1_ITEM *, int, int, int)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_9173: {
            if len == len2 {} else {
                __assert_fail(
                    b"len == len2\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                        as *const u8 as *const libc::c_char,
                    528 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 93],
                        &[libc::c_char; 93],
                    >(
                        b"int asn1_i2d_ex_primitive(ASN1_VALUE **, unsigned char **, const ASN1_ITEM *, int, int, int)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        if omit == 0 {} else {
            __assert_fail(
                b"!omit\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                    as *const u8 as *const libc::c_char,
                529 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 93],
                    &[libc::c_char; 93],
                >(
                    b"int asn1_i2d_ex_primitive(ASN1_VALUE **, unsigned char **, const ASN1_ITEM *, int, int, int)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_9137: {
            if omit == 0 {} else {
                __assert_fail(
                    b"!omit\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                        as *const u8 as *const libc::c_char,
                    529 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 93],
                        &[libc::c_char; 93],
                    >(
                        b"int asn1_i2d_ex_primitive(ASN1_VALUE **, unsigned char **, const ASN1_ITEM *, int, int, int)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        *out = (*out).offset(len as isize);
    }
    if usetag != 0 {
        return ASN1_object_size(0 as libc::c_int, len, tag);
    }
    return len;
}
unsafe extern "C" fn asn1_ex_i2c(
    mut pval: *mut *mut ASN1_VALUE,
    mut cout: *mut libc::c_uchar,
    mut out_omit: *mut libc::c_int,
    mut putype: *mut libc::c_int,
    mut it: *const ASN1_ITEM,
) -> libc::c_int {
    let mut tbool: *mut ASN1_BOOLEAN = 0 as *mut ASN1_BOOLEAN;
    let mut strtmp: *mut ASN1_STRING = 0 as *mut ASN1_STRING;
    let mut otmp: *mut ASN1_OBJECT = 0 as *mut ASN1_OBJECT;
    let mut utype: libc::c_int = 0;
    let mut cont: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut c: libc::c_uchar = 0;
    let mut len: libc::c_int = 0;
    if ((*it).funcs).is_null() {} else {
        __assert_fail(
            b"it->funcs == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0" as *const u8
                as *const libc::c_char,
            567 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 81],
                &[libc::c_char; 81],
            >(
                b"int asn1_ex_i2c(ASN1_VALUE **, unsigned char *, int *, int *, const ASN1_ITEM *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_9046: {
        if ((*it).funcs).is_null() {} else {
            __assert_fail(
                b"it->funcs == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                    as *const u8 as *const libc::c_char,
                567 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 81],
                    &[libc::c_char; 81],
                >(
                    b"int asn1_ex_i2c(ASN1_VALUE **, unsigned char *, int *, int *, const ASN1_ITEM *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    *out_omit = 0 as libc::c_int;
    if (*it).itype as libc::c_int != 0 as libc::c_int || (*it).utype != 1 as libc::c_int
    {
        if (*pval).is_null() {
            *out_omit = 1 as libc::c_int;
            return 0 as libc::c_int;
        }
    }
    if (*it).itype as libc::c_int == 0x5 as libc::c_int {
        strtmp = *pval as *mut ASN1_STRING;
        utype = (*strtmp).type_0;
        if utype < 0 as libc::c_int && utype != -(3 as libc::c_int) {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                191 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                    as *const u8 as *const libc::c_char,
                585 as libc::c_int as libc::c_uint,
            );
            return -(1 as libc::c_int);
        }
        if utype == 2 as libc::c_int | 0x100 as libc::c_int {
            utype = 2 as libc::c_int;
        } else if utype == 10 as libc::c_int | 0x100 as libc::c_int {
            utype = 10 as libc::c_int;
        }
        *putype = utype;
    } else if (*it).utype == -(4 as libc::c_int) {
        let mut typ: *mut ASN1_TYPE = 0 as *mut ASN1_TYPE;
        typ = *pval as *mut ASN1_TYPE;
        utype = (*typ).type_0;
        if utype < 0 as libc::c_int && utype != -(3 as libc::c_int) {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                191 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                    as *const u8 as *const libc::c_char,
                610 as libc::c_int as libc::c_uint,
            );
            return -(1 as libc::c_int);
        }
        *putype = utype;
        pval = &mut (*typ).value.asn1_value;
    } else {
        utype = *putype;
    }
    match utype {
        6 => {
            otmp = *pval as *mut ASN1_OBJECT;
            cont = (*otmp).data;
            len = (*otmp).length;
            if len == 0 as libc::c_int {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    134 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_enc.c\0"
                        as *const u8 as *const libc::c_char,
                    626 as libc::c_int as libc::c_uint,
                );
                return -(1 as libc::c_int);
            }
        }
        5 => {
            cont = 0 as *const libc::c_uchar;
            len = 0 as libc::c_int;
        }
        1 => {
            tbool = pval as *mut ASN1_BOOLEAN;
            if *tbool == -(1 as libc::c_int) {
                *out_omit = 1 as libc::c_int;
                return 0 as libc::c_int;
            }
            if (*it).utype != -(4 as libc::c_int) {
                if *tbool != 0 && (*it).size > 0 as libc::c_int as libc::c_long
                    || *tbool == 0 && (*it).size == 0
                {
                    *out_omit = 1 as libc::c_int;
                    return 0 as libc::c_int;
                }
            }
            c = (if *tbool != 0 { 0xff as libc::c_int } else { 0 as libc::c_int })
                as libc::c_uchar;
            cont = &mut c;
            len = 1 as libc::c_int;
        }
        3 => {
            let mut ret: libc::c_int = i2c_ASN1_BIT_STRING(
                *pval as *mut ASN1_BIT_STRING,
                if !cout.is_null() { &mut cout } else { 0 as *mut *mut libc::c_uchar },
            );
            return if ret <= 0 as libc::c_int { -(1 as libc::c_int) } else { ret };
        }
        2 | 10 => {
            let mut ret_0: libc::c_int = i2c_ASN1_INTEGER(
                *pval as *mut ASN1_INTEGER,
                if !cout.is_null() { &mut cout } else { 0 as *mut *mut libc::c_uchar },
            );
            return if ret_0 <= 0 as libc::c_int { -(1 as libc::c_int) } else { ret_0 };
        }
        4 | 18 | 19 | 20 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 30 | 12 | 16 | 17
        | _ => {
            strtmp = *pval as *mut ASN1_STRING;
            cont = (*strtmp).data;
            len = (*strtmp).length;
        }
    }
    if !cout.is_null() && len != 0 {
        OPENSSL_memcpy(
            cout as *mut libc::c_void,
            cont as *const libc::c_void,
            len as size_t,
        );
    }
    return len;
}
