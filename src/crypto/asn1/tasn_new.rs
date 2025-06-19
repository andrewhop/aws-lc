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
    fn ASN1_STRING_type_new(type_0: libc::c_int) -> *mut ASN1_STRING;
    fn asn1_item_combine_free(
        pval: *mut *mut ASN1_VALUE,
        it: *const ASN1_ITEM,
        combine: libc::c_int,
    );
    fn asn1_set_choice_selector(
        pval: *mut *mut ASN1_VALUE,
        value: libc::c_int,
        it: *const ASN1_ITEM,
    ) -> libc::c_int;
    fn asn1_get_field_ptr(
        pval: *mut *mut ASN1_VALUE,
        tt: *const ASN1_TEMPLATE,
    ) -> *mut *mut ASN1_VALUE;
    fn asn1_refcount_set_one(pval: *mut *mut ASN1_VALUE, it: *const ASN1_ITEM);
    fn asn1_enc_init(pval: *mut *mut ASN1_VALUE, it: *const ASN1_ITEM);
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OBJ_get_undef() -> *const ASN1_OBJECT;
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
pub type ASN1_ex_new_func = unsafe extern "C" fn(
    *mut *mut ASN1_VALUE,
    *const ASN1_ITEM,
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
pub type ASN1_ex_free_func = unsafe extern "C" fn(
    *mut *mut ASN1_VALUE,
    *const ASN1_ITEM,
) -> ();
#[inline]
unsafe extern "C" fn sk_ASN1_VALUE_new_null() -> *mut stack_st_ASN1_VALUE {
    return OPENSSL_sk_new_null() as *mut stack_st_ASN1_VALUE;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_item_new(mut it: *const ASN1_ITEM) -> *mut ASN1_VALUE {
    let mut ret: *mut ASN1_VALUE = 0 as *mut ASN1_VALUE;
    if ASN1_item_ex_new(&mut ret, it) > 0 as libc::c_int {
        return ret;
    }
    return 0 as *mut ASN1_VALUE;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_item_ex_new(
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
) -> libc::c_int {
    return asn1_item_ex_combine_new(pval, it, 0 as libc::c_int);
}
unsafe extern "C" fn asn1_item_ex_combine_new(
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
    mut combine: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut tt: *const ASN1_TEMPLATE = 0 as *const ASN1_TEMPLATE;
    let mut ef: *const ASN1_EXTERN_FUNCS = 0 as *const ASN1_EXTERN_FUNCS;
    let mut pseqval: *mut *mut ASN1_VALUE = 0 as *mut *mut ASN1_VALUE;
    let mut i: libc::c_int = 0;
    match (*it).itype as libc::c_int {
        4 => {
            ef = (*it).funcs as *const ASN1_EXTERN_FUNCS;
            if !ef.is_null() && ((*ef).asn1_ex_new).is_some() {
                if ((*ef).asn1_ex_new).expect("non-null function pointer")(pval, it) == 0
                {
                    current_block = 15904309807018920420;
                } else {
                    current_block = 1356832168064818221;
                }
            } else {
                current_block = 1356832168064818221;
            }
        }
        0 => {
            if !((*it).templates).is_null() {
                if ASN1_template_new(pval, (*it).templates) == 0 {
                    current_block = 15904309807018920420;
                } else {
                    current_block = 1356832168064818221;
                }
            } else if ASN1_primitive_new(pval, it) == 0 {
                current_block = 15904309807018920420;
            } else {
                current_block = 1356832168064818221;
            }
        }
        5 => {
            if ASN1_primitive_new(pval, it) == 0 {
                current_block = 15904309807018920420;
            } else {
                current_block = 1356832168064818221;
            }
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
                    )(0 as libc::c_int, pval, it, 0 as *mut libc::c_void);
                if i == 0 {
                    current_block = 68375906047501243;
                } else {
                    if i == 2 as libc::c_int {
                        return 1 as libc::c_int;
                    }
                    current_block = 13797916685926291137;
                }
            } else {
                current_block = 13797916685926291137;
            }
            match current_block {
                68375906047501243 => {}
                _ => {
                    if combine == 0 {
                        *pval = OPENSSL_zalloc((*it).size as size_t) as *mut ASN1_VALUE;
                        if (*pval).is_null() {
                            current_block = 15904309807018920420;
                        } else {
                            current_block = 11307063007268554308;
                        }
                    } else {
                        current_block = 11307063007268554308;
                    }
                    match current_block {
                        15904309807018920420 => {}
                        _ => {
                            asn1_set_choice_selector(pval, -(1 as libc::c_int), it);
                            if asn1_cb.is_some()
                                && asn1_cb
                                    .expect(
                                        "non-null function pointer",
                                    )(1 as libc::c_int, pval, it, 0 as *mut libc::c_void) == 0
                            {
                                current_block = 11265358857239353424;
                            } else {
                                current_block = 1356832168064818221;
                            }
                        }
                    }
                }
            }
        }
        1 => {
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
                    )(0 as libc::c_int, pval, it, 0 as *mut libc::c_void);
                if i == 0 {
                    current_block = 68375906047501243;
                } else {
                    if i == 2 as libc::c_int {
                        return 1 as libc::c_int;
                    }
                    current_block = 18377268871191777778;
                }
            } else {
                current_block = 18377268871191777778;
            }
            match current_block {
                68375906047501243 => {}
                _ => {
                    if combine == 0 {
                        *pval = OPENSSL_zalloc((*it).size as size_t) as *mut ASN1_VALUE;
                        if (*pval).is_null() {
                            current_block = 15904309807018920420;
                        } else {
                            asn1_refcount_set_one(pval, it);
                            asn1_enc_init(pval, it);
                            current_block = 8845338526596852646;
                        }
                    } else {
                        current_block = 8845338526596852646;
                    }
                    match current_block {
                        15904309807018920420 => {}
                        _ => {
                            i = 0 as libc::c_int;
                            tt = (*it).templates;
                            loop {
                                if !((i as libc::c_long) < (*it).tcount) {
                                    current_block = 12199444798915819164;
                                    break;
                                }
                                pseqval = asn1_get_field_ptr(pval, tt);
                                if ASN1_template_new(pseqval, tt) == 0 {
                                    current_block = 9785169420404199828;
                                    break;
                                }
                                tt = tt.offset(1);
                                tt;
                                i += 1;
                                i;
                            }
                            match current_block {
                                9785169420404199828 => {
                                    asn1_item_combine_free(pval, it, combine);
                                    current_block = 15904309807018920420;
                                }
                                _ => {
                                    if asn1_cb_0.is_some()
                                        && asn1_cb_0
                                            .expect(
                                                "non-null function pointer",
                                            )(1 as libc::c_int, pval, it, 0 as *mut libc::c_void) == 0
                                    {
                                        current_block = 11265358857239353424;
                                    } else {
                                        current_block = 1356832168064818221;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {
            current_block = 1356832168064818221;
        }
    }
    match current_block {
        1356832168064818221 => return 1 as libc::c_int,
        15904309807018920420 => return 0 as libc::c_int,
        11265358857239353424 => {
            asn1_item_combine_free(pval, it, combine);
        }
        _ => {}
    }
    ERR_put_error(
        12 as libc::c_int,
        0 as libc::c_int,
        101 as libc::c_int,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_new.c\0" as *const u8
            as *const libc::c_char,
        192 as libc::c_int as libc::c_uint,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn asn1_item_clear(
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
) {
    match (*it).itype as libc::c_int {
        4 => {
            *pval = 0 as *mut ASN1_VALUE;
        }
        0 => {
            if !((*it).templates).is_null() {
                asn1_template_clear(pval, (*it).templates);
            } else {
                asn1_primitive_clear(pval, it);
            }
        }
        5 => {
            asn1_primitive_clear(pval, it);
        }
        2 | 1 => {
            *pval = 0 as *mut ASN1_VALUE;
        }
        _ => {}
    };
}
unsafe extern "C" fn ASN1_template_new(
    mut pval: *mut *mut ASN1_VALUE,
    mut tt: *const ASN1_TEMPLATE,
) -> libc::c_int {
    let mut it: *const ASN1_ITEM = (*tt).item;
    let mut ret: libc::c_int = 0;
    if (*tt).flags & 0x1 as libc::c_int as uint32_t != 0 {
        asn1_template_clear(pval, tt);
        return 1 as libc::c_int;
    }
    if (*tt).flags & ((0x3 as libc::c_int) << 8 as libc::c_int) as uint32_t != 0 {
        *pval = 0 as *mut ASN1_VALUE;
        return 1 as libc::c_int;
    }
    if (*tt).flags & ((0x3 as libc::c_int) << 1 as libc::c_int) as uint32_t != 0 {
        let mut skval: *mut stack_st_ASN1_VALUE = 0 as *mut stack_st_ASN1_VALUE;
        skval = sk_ASN1_VALUE_new_null();
        if skval.is_null() {
            ret = 0 as libc::c_int;
        } else {
            *pval = skval as *mut ASN1_VALUE;
            ret = 1 as libc::c_int;
        }
    } else {
        ret = asn1_item_ex_combine_new(
            pval,
            it,
            ((*tt).flags & ((0x1 as libc::c_int) << 10 as libc::c_int) as uint32_t)
                as libc::c_int,
        );
    }
    return ret;
}
unsafe extern "C" fn asn1_template_clear(
    mut pval: *mut *mut ASN1_VALUE,
    mut tt: *const ASN1_TEMPLATE,
) {
    if (*tt).flags
        & ((0x3 as libc::c_int) << 8 as libc::c_int
            | (0x3 as libc::c_int) << 1 as libc::c_int) as uint32_t != 0
    {
        *pval = 0 as *mut ASN1_VALUE;
    } else {
        asn1_item_clear(pval, (*tt).item);
    };
}
unsafe extern "C" fn ASN1_primitive_new(
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
) -> libc::c_int {
    if it.is_null() {
        return 0 as libc::c_int;
    }
    if ((*it).funcs).is_null() {} else {
        __assert_fail(
            b"it->funcs == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_new.c\0" as *const u8
                as *const libc::c_char,
            271 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 57],
                &[libc::c_char; 57],
            >(b"int ASN1_primitive_new(ASN1_VALUE **, const ASN1_ITEM *)\0"))
                .as_ptr(),
        );
    }
    'c_7462: {
        if ((*it).funcs).is_null() {} else {
            __assert_fail(
                b"it->funcs == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_new.c\0"
                    as *const u8 as *const libc::c_char,
                271 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 57],
                    &[libc::c_char; 57],
                >(b"int ASN1_primitive_new(ASN1_VALUE **, const ASN1_ITEM *)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut utype: libc::c_int = 0;
    if (*it).itype as libc::c_int == 0x5 as libc::c_int {
        utype = -(1 as libc::c_int);
    } else {
        utype = (*it).utype;
    }
    match utype {
        6 => {
            *pval = OBJ_get_undef() as *mut ASN1_VALUE;
            return 1 as libc::c_int;
        }
        1 => {
            *(pval as *mut ASN1_BOOLEAN) = (*it).size as ASN1_BOOLEAN;
            return 1 as libc::c_int;
        }
        5 => {
            *pval = 1 as libc::c_int as *mut ASN1_VALUE;
            return 1 as libc::c_int;
        }
        -4 => {
            let mut typ: *mut ASN1_TYPE = OPENSSL_zalloc(
                ::core::mem::size_of::<ASN1_TYPE>() as libc::c_ulong,
            ) as *mut ASN1_TYPE;
            if typ.is_null() {
                return 0 as libc::c_int;
            }
            (*typ).type_0 = -(1 as libc::c_int);
            *pval = typ as *mut ASN1_VALUE;
        }
        _ => {
            *pval = ASN1_STRING_type_new(utype) as *mut ASN1_VALUE;
        }
    }
    if !(*pval).is_null() {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn asn1_primitive_clear(
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
) {
    let mut utype: libc::c_int = 0;
    if it.is_null() || ((*it).funcs).is_null() {} else {
        __assert_fail(
            b"it == NULL || it->funcs == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_new.c\0" as *const u8
                as *const libc::c_char,
            316 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 60],
                &[libc::c_char; 60],
            >(b"void asn1_primitive_clear(ASN1_VALUE **, const ASN1_ITEM *)\0"))
                .as_ptr(),
        );
    }
    'c_6912: {
        if it.is_null() || ((*it).funcs).is_null() {} else {
            __assert_fail(
                b"it == NULL || it->funcs == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_new.c\0"
                    as *const u8 as *const libc::c_char,
                316 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 60],
                    &[libc::c_char; 60],
                >(b"void asn1_primitive_clear(ASN1_VALUE **, const ASN1_ITEM *)\0"))
                    .as_ptr(),
            );
        }
    };
    if it.is_null() || (*it).itype as libc::c_int == 0x5 as libc::c_int {
        utype = -(1 as libc::c_int);
    } else {
        utype = (*it).utype;
    }
    if utype == 1 as libc::c_int {
        *(pval as *mut ASN1_BOOLEAN) = (*it).size as ASN1_BOOLEAN;
    } else {
        *pval = 0 as *mut ASN1_VALUE;
    };
}
