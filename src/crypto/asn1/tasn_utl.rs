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
    pub type ASN1_VALUE_st;
    pub type asn1_must_be_null_st;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_memdup(data: *const libc::c_void, size: size_t) -> *mut libc::c_void;
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
    fn OBJ_obj2nid(obj: *const ASN1_OBJECT) -> libc::c_int;
    fn CRYPTO_refcount_dec_and_test_zero(count: *mut CRYPTO_refcount_t) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
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
pub type ASN1_VALUE = ASN1_VALUE_st;
pub type CRYPTO_refcount_t = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ASN1_ADB_TABLE_st {
    pub value: libc::c_int,
    pub tt: ASN1_TEMPLATE,
}
pub type ASN1_ADB_TABLE = ASN1_ADB_TABLE_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ASN1_ADB_st {
    pub flags: uint32_t,
    pub offset: libc::c_ulong,
    pub unused: *mut ASN1_MUST_BE_NULL,
    pub tbl: *const ASN1_ADB_TABLE,
    pub tblcount: libc::c_long,
    pub default_tt: *const ASN1_TEMPLATE,
    pub null_tt: *const ASN1_TEMPLATE,
}
pub type ASN1_MUST_BE_NULL = asn1_must_be_null_st;
pub type ASN1_ADB = ASN1_ADB_st;
pub type ASN1_aux_cb = unsafe extern "C" fn(
    libc::c_int,
    *mut *mut ASN1_VALUE,
    *const ASN1_ITEM,
    *mut libc::c_void,
) -> libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ASN1_AUX_st {
    pub app_data: *mut libc::c_void,
    pub flags: uint32_t,
    pub ref_offset: libc::c_int,
    pub asn1_cb: Option::<ASN1_aux_cb>,
    pub enc_offset: libc::c_int,
}
pub type ASN1_AUX = ASN1_AUX_st;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct ASN1_ENCODING_st {
    pub enc: *mut libc::c_uchar,
    pub len: libc::c_long,
    #[bitfield(name = "alias_only", ty = "libc::c_uint", bits = "0..=0")]
    #[bitfield(name = "alias_only_on_next_parse", ty = "libc::c_uint", bits = "1..=1")]
    pub alias_only_alias_only_on_next_parse: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
pub type ASN1_ENCODING = ASN1_ENCODING_st;
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
pub unsafe extern "C" fn asn1_get_choice_selector(
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
) -> libc::c_int {
    let mut sel: *mut libc::c_int = (*pval as *mut libc::c_char)
        .offset((*it).utype as isize) as *mut libc::c_void as *mut libc::c_int;
    return *sel;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asn1_set_choice_selector(
    mut pval: *mut *mut ASN1_VALUE,
    mut value: libc::c_int,
    mut it: *const ASN1_ITEM,
) -> libc::c_int {
    let mut sel: *mut libc::c_int = 0 as *mut libc::c_int;
    let mut ret: libc::c_int = 0;
    sel = (*pval as *mut libc::c_char).offset((*it).utype as isize) as *mut libc::c_void
        as *mut libc::c_int;
    ret = *sel;
    *sel = value;
    return ret;
}
unsafe extern "C" fn asn1_get_references(
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
) -> *mut CRYPTO_refcount_t {
    if (*it).itype as libc::c_int != 0x1 as libc::c_int {
        return 0 as *mut CRYPTO_refcount_t;
    }
    let mut aux: *const ASN1_AUX = (*it).funcs as *const ASN1_AUX;
    if aux.is_null() || (*aux).flags & 1 as libc::c_int as uint32_t == 0 {
        return 0 as *mut CRYPTO_refcount_t;
    }
    return (*pval as *mut libc::c_char).offset((*aux).ref_offset as isize)
        as *mut libc::c_void as *mut CRYPTO_refcount_t;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asn1_refcount_set_one(
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
) {
    let mut references: *mut CRYPTO_refcount_t = asn1_get_references(pval, it);
    if !references.is_null() {
        *references = 1 as libc::c_int as CRYPTO_refcount_t;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asn1_refcount_dec_and_test_zero(
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
) -> libc::c_int {
    let mut references: *mut CRYPTO_refcount_t = asn1_get_references(pval, it);
    if !references.is_null() {
        return CRYPTO_refcount_dec_and_test_zero(references);
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn asn1_get_enc_ptr(
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
) -> *mut ASN1_ENCODING {
    if (*it).itype as libc::c_int == 0x1 as libc::c_int {} else {
        __assert_fail(
            b"it->itype == ASN1_ITYPE_SEQUENCE\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_utl.c\0" as *const u8
                as *const libc::c_char,
            121 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 66],
                &[libc::c_char; 66],
            >(b"ASN1_ENCODING *asn1_get_enc_ptr(ASN1_VALUE **, const ASN1_ITEM *)\0"))
                .as_ptr(),
        );
    }
    'c_12929: {
        if (*it).itype as libc::c_int == 0x1 as libc::c_int {} else {
            __assert_fail(
                b"it->itype == ASN1_ITYPE_SEQUENCE\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_utl.c\0"
                    as *const u8 as *const libc::c_char,
                121 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 66],
                    &[libc::c_char; 66],
                >(
                    b"ASN1_ENCODING *asn1_get_enc_ptr(ASN1_VALUE **, const ASN1_ITEM *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut aux: *const ASN1_AUX = 0 as *const ASN1_AUX;
    if pval.is_null() || (*pval).is_null() {
        return 0 as *mut ASN1_ENCODING;
    }
    aux = (*it).funcs as *const ASN1_AUX;
    if aux.is_null() || (*aux).flags & 2 as libc::c_int as uint32_t == 0 {
        return 0 as *mut ASN1_ENCODING;
    }
    return (*pval as *mut libc::c_char).offset((*aux).enc_offset as isize)
        as *mut libc::c_void as *mut ASN1_ENCODING;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asn1_enc_init(
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
) {
    let mut enc: *mut ASN1_ENCODING = asn1_get_enc_ptr(pval, it);
    if !enc.is_null() {
        (*enc).enc = 0 as *mut libc::c_uchar;
        (*enc).len = 0 as libc::c_int as libc::c_long;
        (*enc).set_alias_only(0 as libc::c_int as libc::c_uint);
        (*enc).set_alias_only_on_next_parse(0 as libc::c_int as libc::c_uint);
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asn1_enc_free(
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
) {
    let mut enc: *mut ASN1_ENCODING = asn1_get_enc_ptr(pval, it);
    if !enc.is_null() {
        asn1_encoding_clear(enc);
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asn1_enc_save(
    mut pval: *mut *mut ASN1_VALUE,
    mut in_0: *const libc::c_uchar,
    mut inlen: libc::c_int,
    mut it: *const ASN1_ITEM,
) -> libc::c_int {
    let mut enc: *mut ASN1_ENCODING = 0 as *mut ASN1_ENCODING;
    enc = asn1_get_enc_ptr(pval, it);
    if enc.is_null() {
        return 1 as libc::c_int;
    }
    if (*enc).alias_only() == 0 {
        OPENSSL_free((*enc).enc as *mut libc::c_void);
    }
    (*enc).set_alias_only((*enc).alias_only_on_next_parse());
    (*enc).set_alias_only_on_next_parse(0 as libc::c_int as libc::c_uint);
    if (*enc).alias_only() != 0 {
        (*enc).enc = in_0 as *mut uint8_t;
    } else {
        (*enc)
            .enc = OPENSSL_memdup(in_0 as *const libc::c_void, inlen as size_t)
            as *mut libc::c_uchar;
        if ((*enc).enc).is_null() {
            return 0 as libc::c_int;
        }
    }
    (*enc).len = inlen as libc::c_long;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asn1_encoding_clear(mut enc: *mut ASN1_ENCODING) {
    if (*enc).alias_only() == 0 {
        OPENSSL_free((*enc).enc as *mut libc::c_void);
    }
    (*enc).enc = 0 as *mut libc::c_uchar;
    (*enc).len = 0 as libc::c_int as libc::c_long;
    (*enc).set_alias_only(0 as libc::c_int as libc::c_uint);
    (*enc).set_alias_only_on_next_parse(0 as libc::c_int as libc::c_uint);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asn1_enc_restore(
    mut len: *mut libc::c_int,
    mut out: *mut *mut libc::c_uchar,
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
) -> libc::c_int {
    let mut enc: *mut ASN1_ENCODING = asn1_get_enc_ptr(pval, it);
    if enc.is_null() || (*enc).len == 0 as libc::c_int as libc::c_long {
        return 0 as libc::c_int;
    }
    if !out.is_null() {
        OPENSSL_memcpy(
            *out as *mut libc::c_void,
            (*enc).enc as *const libc::c_void,
            (*enc).len as size_t,
        );
        *out = (*out).offset((*enc).len as isize);
    }
    if !len.is_null() {
        *len = (*enc).len as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asn1_get_field_ptr(
    mut pval: *mut *mut ASN1_VALUE,
    mut tt: *const ASN1_TEMPLATE,
) -> *mut *mut ASN1_VALUE {
    let mut pvaltmp: *mut *mut ASN1_VALUE = 0 as *mut *mut ASN1_VALUE;
    if (*tt).flags & ((0x1 as libc::c_int) << 10 as libc::c_int) as uint32_t != 0 {
        return pval;
    }
    pvaltmp = (*pval as *mut libc::c_char).offset((*tt).offset as isize)
        as *mut libc::c_void as *mut *mut ASN1_VALUE;
    return pvaltmp;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asn1_do_adb(
    mut pval: *mut *mut ASN1_VALUE,
    mut tt: *const ASN1_TEMPLATE,
    mut nullerr: libc::c_int,
) -> *const ASN1_TEMPLATE {
    let mut selector: libc::c_int = 0;
    let mut adb: *const ASN1_ADB = 0 as *const ASN1_ADB;
    let mut atbl: *const ASN1_ADB_TABLE = 0 as *const ASN1_ADB_TABLE;
    let mut sfld: *mut *mut ASN1_VALUE = 0 as *mut *mut ASN1_VALUE;
    let mut i: libc::c_int = 0;
    if (*tt).flags & ((0x3 as libc::c_int) << 8 as libc::c_int) as uint32_t == 0 {
        return tt;
    }
    adb = (*tt).item as *const ASN1_ADB;
    sfld = (*pval as *mut libc::c_char).offset((*adb).offset as isize)
        as *mut libc::c_void as *mut *mut ASN1_VALUE;
    if (*sfld).is_null() {
        if !((*adb).null_tt).is_null() {
            return (*adb).null_tt;
        }
    } else {
        if (*tt).flags & ((0x1 as libc::c_int) << 8 as libc::c_int) as uint32_t != 0
        {} else {
            __assert_fail(
                b"tt->flags & ASN1_TFLG_ADB_OID\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_utl.c\0"
                    as *const u8 as *const libc::c_char,
                245 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 76],
                    &[libc::c_char; 76],
                >(
                    b"const ASN1_TEMPLATE *asn1_do_adb(ASN1_VALUE **, const ASN1_TEMPLATE *, int)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_12582: {
            if (*tt).flags & ((0x1 as libc::c_int) << 8 as libc::c_int) as uint32_t != 0
            {} else {
                __assert_fail(
                    b"tt->flags & ASN1_TFLG_ADB_OID\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_utl.c\0"
                        as *const u8 as *const libc::c_char,
                    245 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 76],
                        &[libc::c_char; 76],
                    >(
                        b"const ASN1_TEMPLATE *asn1_do_adb(ASN1_VALUE **, const ASN1_TEMPLATE *, int)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        selector = OBJ_obj2nid(*sfld as *mut ASN1_OBJECT);
        atbl = (*adb).tbl;
        i = 0 as libc::c_int;
        while (i as libc::c_long) < (*adb).tblcount {
            if (*atbl).value == selector {
                return &(*atbl).tt;
            }
            i += 1;
            i;
            atbl = atbl.offset(1);
            atbl;
        }
        if !((*adb).default_tt).is_null() {
            return (*adb).default_tt;
        }
    }
    if nullerr != 0 {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            186 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_utl.c\0" as *const u8
                as *const libc::c_char,
            270 as libc::c_int as libc::c_uint,
        );
    }
    return 0 as *const ASN1_TEMPLATE;
}
