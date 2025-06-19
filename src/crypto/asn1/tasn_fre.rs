#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(extern_types, label_break_value)]
extern "C" {
    pub type asn1_pctx_st;
    pub type ASN1_VALUE_st;
    pub type stack_st_void;
    pub type stack_st;
    pub type stack_st_ASN1_VALUE;
    pub type ASN1_TLC_st;
    fn ASN1_STRING_free(str: *mut ASN1_STRING);
    fn ASN1_OBJECT_free(a: *mut ASN1_OBJECT);
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
    fn asn1_refcount_dec_and_test_zero(
        pval: *mut *mut ASN1_VALUE,
        it: *const ASN1_ITEM,
    ) -> libc::c_int;
    fn asn1_enc_free(pval: *mut *mut ASN1_VALUE, it: *const ASN1_ITEM);
    fn asn1_type_cleanup(a: *mut ASN1_TYPE);
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_free(sk: *mut OPENSSL_STACK);
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
}
pub type size_t = libc::c_ulong;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
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
pub type ASN1_aux_cb = unsafe extern "C" fn(
    libc::c_int,
    *mut *mut ASN1_VALUE,
    *const ASN1_ITEM,
    *mut libc::c_void,
) -> libc::c_int;
pub type ASN1_AUX = ASN1_AUX_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ASN1_AUX_st {
    pub app_data: *mut libc::c_void,
    pub flags: uint32_t,
    pub ref_offset: libc::c_int,
    pub asn1_cb: Option::<ASN1_aux_cb>,
    pub enc_offset: libc::c_int,
}
pub type ASN1_ex_free_func = unsafe extern "C" fn(
    *mut *mut ASN1_VALUE,
    *const ASN1_ITEM,
) -> ();
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
pub type ASN1_ex_i2d = unsafe extern "C" fn(
    *mut *mut ASN1_VALUE,
    *mut *mut libc::c_uchar,
    *const ASN1_ITEM,
    libc::c_int,
    libc::c_int,
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
pub type ASN1_ex_new_func = unsafe extern "C" fn(
    *mut *mut ASN1_VALUE,
    *const ASN1_ITEM,
) -> libc::c_int;
#[inline]
unsafe extern "C" fn sk_ASN1_VALUE_free(mut sk: *mut stack_st_ASN1_VALUE) {
    OPENSSL_sk_free(sk as *mut OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_ASN1_VALUE_value(
    mut sk: *const stack_st_ASN1_VALUE,
    mut i: size_t,
) -> *mut ASN1_VALUE {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut ASN1_VALUE;
}
#[inline]
unsafe extern "C" fn sk_ASN1_VALUE_num(mut sk: *const stack_st_ASN1_VALUE) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_free(
    mut val: *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
) {
    asn1_item_combine_free(&mut val, it, 0 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_ex_free(
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
) {
    asn1_item_combine_free(pval, it, 0 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn asn1_item_combine_free(
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
    mut combine: libc::c_int,
) {
    let mut tt: *const ASN1_TEMPLATE = 0 as *const ASN1_TEMPLATE;
    let mut seqtt: *const ASN1_TEMPLATE = 0 as *const ASN1_TEMPLATE;
    let mut ef: *const ASN1_EXTERN_FUNCS = 0 as *const ASN1_EXTERN_FUNCS;
    let mut i: libc::c_int = 0;
    if pval.is_null() || it.is_null() {
        return;
    }
    if (*it).itype as libc::c_int != 0 as libc::c_int && (*pval).is_null() {
        return;
    }
    match (*it).itype as libc::c_int {
        0 => {
            if !((*it).templates).is_null() {
                ASN1_template_free(pval, (*it).templates);
            } else {
                ASN1_primitive_free(pval, it);
            }
        }
        5 => {
            ASN1_primitive_free(pval, it);
        }
        2 => {
            let mut aux: *const ASN1_AUX = (*it).funcs as *const ASN1_AUX;
            let mut asn1_cb: Option::<ASN1_aux_cb> = if !aux.is_null() {
                (*aux).asn1_cb
            } else {
                None
            };
            if asn1_cb.is_some() {
                i = asn1_cb
                    .expect(
                        "non-null function pointer",
                    )(2 as libc::c_int, pval, it, 0 as *mut libc::c_void);
                if i == 2 as libc::c_int {
                    return;
                }
            }
            i = asn1_get_choice_selector(pval, it);
            if i >= 0 as libc::c_int && (i as libc::c_long) < (*it).tcount {
                let mut pchval: *mut *mut ASN1_VALUE = 0 as *mut *mut ASN1_VALUE;
                tt = ((*it).templates).offset(i as isize);
                pchval = asn1_get_field_ptr(pval, tt);
                ASN1_template_free(pchval, tt);
            }
            if asn1_cb.is_some() {
                asn1_cb
                    .expect(
                        "non-null function pointer",
                    )(3 as libc::c_int, pval, it, 0 as *mut libc::c_void);
            }
            if combine == 0 {
                OPENSSL_free(*pval as *mut libc::c_void);
                *pval = 0 as *mut ASN1_VALUE;
            }
        }
        4 => {
            ef = (*it).funcs as *const ASN1_EXTERN_FUNCS;
            if !ef.is_null() && ((*ef).asn1_ex_free).is_some() {
                ((*ef).asn1_ex_free).expect("non-null function pointer")(pval, it);
            }
        }
        1 => {
            if asn1_refcount_dec_and_test_zero(pval, it) == 0 {
                return;
            }
            let mut aux_0: *const ASN1_AUX = (*it).funcs as *const ASN1_AUX;
            let mut asn1_cb_0: Option::<ASN1_aux_cb> = if !aux_0.is_null() {
                (*aux_0).asn1_cb
            } else {
                None
            };
            if asn1_cb_0.is_some() {
                i = asn1_cb_0
                    .expect(
                        "non-null function pointer",
                    )(2 as libc::c_int, pval, it, 0 as *mut libc::c_void);
                if i == 2 as libc::c_int {
                    return;
                }
            }
            asn1_enc_free(pval, it);
            tt = ((*it).templates)
                .offset((*it).tcount as isize)
                .offset(-(1 as libc::c_int as isize));
            i = 0 as libc::c_int;
            while (i as libc::c_long) < (*it).tcount {
                let mut pseqval: *mut *mut ASN1_VALUE = 0 as *mut *mut ASN1_VALUE;
                seqtt = asn1_do_adb(pval, tt, 0 as libc::c_int);
                if !seqtt.is_null() {
                    pseqval = asn1_get_field_ptr(pval, seqtt);
                    ASN1_template_free(pseqval, seqtt);
                }
                tt = tt.offset(-1);
                tt;
                i += 1;
                i;
            }
            if asn1_cb_0.is_some() {
                asn1_cb_0
                    .expect(
                        "non-null function pointer",
                    )(3 as libc::c_int, pval, it, 0 as *mut libc::c_void);
            }
            if combine == 0 {
                OPENSSL_free(*pval as *mut libc::c_void);
                *pval = 0 as *mut ASN1_VALUE;
            }
        }
        _ => {}
    };
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_template_free(
    mut pval: *mut *mut ASN1_VALUE,
    mut tt: *const ASN1_TEMPLATE,
) {
    if (*tt).flags & ((0x3 as libc::c_int) << 1 as libc::c_int) as uint32_t != 0 {
        let mut sk: *mut stack_st_ASN1_VALUE = *pval as *mut stack_st_ASN1_VALUE;
        let mut i: size_t = 0 as libc::c_int as size_t;
        while i < sk_ASN1_VALUE_num(sk) {
            let mut vtmp: *mut ASN1_VALUE = sk_ASN1_VALUE_value(sk, i);
            ASN1_item_ex_free(&mut vtmp, (*tt).item);
            i = i.wrapping_add(1);
            i;
        }
        sk_ASN1_VALUE_free(sk);
        *pval = 0 as *mut ASN1_VALUE;
    } else {
        asn1_item_combine_free(
            pval,
            (*tt).item,
            ((*tt).flags & ((0x1 as libc::c_int) << 10 as libc::c_int) as uint32_t)
                as libc::c_int,
        );
    };
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_primitive_free(
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
) {
    if ((*it).funcs).is_null() {} else {
        __assert_fail(
            b"it->funcs == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_fre.c\0" as *const u8
                as *const libc::c_char,
            190 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 59],
                &[libc::c_char; 59],
            >(b"void ASN1_primitive_free(ASN1_VALUE **, const ASN1_ITEM *)\0"))
                .as_ptr(),
        );
    }
    'c_7247: {
        if ((*it).funcs).is_null() {} else {
            __assert_fail(
                b"it->funcs == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_fre.c\0"
                    as *const u8 as *const libc::c_char,
                190 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 59],
                    &[libc::c_char; 59],
                >(b"void ASN1_primitive_free(ASN1_VALUE **, const ASN1_ITEM *)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut utype: libc::c_int = if (*it).itype as libc::c_int == 0x5 as libc::c_int {
        -(1 as libc::c_int)
    } else {
        (*it).utype
    };
    match utype {
        6 => {
            ASN1_OBJECT_free(*pval as *mut ASN1_OBJECT);
        }
        1 => {
            if !it.is_null() {
                *(pval as *mut ASN1_BOOLEAN) = (*it).size as ASN1_BOOLEAN;
            } else {
                *(pval as *mut ASN1_BOOLEAN) = -(1 as libc::c_int);
            }
            return;
        }
        5 => {}
        -4 => {
            if !(*pval).is_null() {
                asn1_type_cleanup(*pval as *mut ASN1_TYPE);
                OPENSSL_free(*pval as *mut libc::c_void);
            }
        }
        _ => {
            ASN1_STRING_free(*pval as *mut ASN1_STRING);
            *pval = 0 as *mut ASN1_VALUE;
        }
    }
    *pval = 0 as *mut ASN1_VALUE;
}
