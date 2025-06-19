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
    pub type ASN1_VALUE_st;
    pub type stack_st_ASN1_TYPE;
    pub type stack_st;
    fn ASN1_STRING_type_new(type_0: libc::c_int) -> *mut ASN1_STRING;
    fn ASN1_STRING_free(str: *mut ASN1_STRING);
    fn ASN1_STRING_set(
        str: *mut ASN1_STRING,
        data: *const libc::c_void,
        len: ossl_ssize_t,
    ) -> libc::c_int;
    fn ASN1_STRING_set_by_NID(
        out: *mut *mut ASN1_STRING,
        in_0: *const libc::c_uchar,
        len: ossl_ssize_t,
        inform: libc::c_int,
        nid: libc::c_int,
    ) -> *mut ASN1_STRING;
    fn ASN1_OBJECT_free(a: *mut ASN1_OBJECT);
    fn ASN1_TYPE_new() -> *mut ASN1_TYPE;
    fn ASN1_TYPE_free(a: *mut ASN1_TYPE);
    fn ASN1_TYPE_get(a: *const ASN1_TYPE) -> libc::c_int;
    fn ASN1_TYPE_set1(
        a: *mut ASN1_TYPE,
        type_0: libc::c_int,
        value: *const libc::c_void,
    ) -> libc::c_int;
    fn asn1_type_value_as_pointer(a: *const ASN1_TYPE) -> *const libc::c_void;
    fn asn1_type_set0_string(a: *mut ASN1_TYPE, str: *mut ASN1_STRING);
    fn X509_ATTRIBUTE_new() -> *mut X509_ATTRIBUTE;
    fn X509_ATTRIBUTE_free(attr: *mut X509_ATTRIBUTE);
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn ERR_add_error_data(count: libc::c_uint, _: ...);
    fn OBJ_dup(obj: *const ASN1_OBJECT) -> *mut ASN1_OBJECT;
    fn OBJ_obj2nid(obj: *const ASN1_OBJECT) -> libc::c_int;
    fn OBJ_nid2obj(nid: libc::c_int) -> *mut ASN1_OBJECT;
    fn OBJ_txt2obj(
        s: *const libc::c_char,
        dont_search_names: libc::c_int,
    ) -> *mut ASN1_OBJECT;
}
pub type ptrdiff_t = libc::c_long;
pub type size_t = libc::c_ulong;
pub type ossl_ssize_t = ptrdiff_t;
pub type ASN1_BOOLEAN = libc::c_int;
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
pub struct x509_attributes_st {
    pub object: *mut ASN1_OBJECT,
    pub set: *mut stack_st_ASN1_TYPE,
}
pub type X509_ATTRIBUTE = x509_attributes_st;
pub type OPENSSL_STACK = stack_st;
#[inline]
unsafe extern "C" fn sk_ASN1_TYPE_num(mut sk: *const stack_st_ASN1_TYPE) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_ASN1_TYPE_value(
    mut sk: *const stack_st_ASN1_TYPE,
    mut i: size_t,
) -> *mut ASN1_TYPE {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut ASN1_TYPE;
}
#[inline]
unsafe extern "C" fn sk_ASN1_TYPE_push(
    mut sk: *mut stack_st_ASN1_TYPE,
    mut p: *mut ASN1_TYPE,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn X509_ATTRIBUTE_create_by_NID(
    mut attr: *mut *mut X509_ATTRIBUTE,
    mut nid: libc::c_int,
    mut attrtype: libc::c_int,
    mut data: *const libc::c_void,
    mut len: libc::c_int,
) -> *mut X509_ATTRIBUTE {
    let mut obj: *const ASN1_OBJECT = 0 as *const ASN1_OBJECT;
    obj = OBJ_nid2obj(nid);
    if obj.is_null() {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            129 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_att.c\0" as *const u8
                as *const libc::c_char,
            73 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut X509_ATTRIBUTE;
    }
    return X509_ATTRIBUTE_create_by_OBJ(attr, obj, attrtype, data, len);
}
#[no_mangle]
pub unsafe extern "C" fn X509_ATTRIBUTE_create_by_OBJ(
    mut attr: *mut *mut X509_ATTRIBUTE,
    mut obj: *const ASN1_OBJECT,
    mut attrtype: libc::c_int,
    mut data: *const libc::c_void,
    mut len: libc::c_int,
) -> *mut X509_ATTRIBUTE {
    let mut ret: *mut X509_ATTRIBUTE = 0 as *mut X509_ATTRIBUTE;
    if attr.is_null() || (*attr).is_null() {
        ret = X509_ATTRIBUTE_new();
        if ret.is_null() {
            return 0 as *mut X509_ATTRIBUTE;
        }
    } else {
        ret = *attr;
    }
    if !(X509_ATTRIBUTE_set1_object(ret, obj) == 0) {
        if !(X509_ATTRIBUTE_set1_data(ret, attrtype, data, len) == 0) {
            if !attr.is_null() && (*attr).is_null() {
                *attr = ret;
            }
            return ret;
        }
    }
    if attr.is_null() || ret != *attr {
        X509_ATTRIBUTE_free(ret);
    }
    return 0 as *mut X509_ATTRIBUTE;
}
#[no_mangle]
pub unsafe extern "C" fn X509_ATTRIBUTE_create_by_txt(
    mut attr: *mut *mut X509_ATTRIBUTE,
    mut attrname: *const libc::c_char,
    mut type_0: libc::c_int,
    mut bytes: *const libc::c_uchar,
    mut len: libc::c_int,
) -> *mut X509_ATTRIBUTE {
    let mut obj: *mut ASN1_OBJECT = 0 as *mut ASN1_OBJECT;
    let mut nattr: *mut X509_ATTRIBUTE = 0 as *mut X509_ATTRIBUTE;
    obj = OBJ_txt2obj(attrname, 0 as libc::c_int);
    if obj.is_null() {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            111 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_att.c\0" as *const u8
                as *const libc::c_char,
            120 as libc::c_int as libc::c_uint,
        );
        ERR_add_error_data(
            2 as libc::c_int as libc::c_uint,
            b"name=\0" as *const u8 as *const libc::c_char,
            attrname,
        );
        return 0 as *mut X509_ATTRIBUTE;
    }
    nattr = X509_ATTRIBUTE_create_by_OBJ(
        attr,
        obj,
        type_0,
        bytes as *const libc::c_void,
        len,
    );
    ASN1_OBJECT_free(obj);
    return nattr;
}
#[no_mangle]
pub unsafe extern "C" fn X509_ATTRIBUTE_set1_object(
    mut attr: *mut X509_ATTRIBUTE,
    mut obj: *const ASN1_OBJECT,
) -> libc::c_int {
    if attr.is_null() || obj.is_null() {
        return 0 as libc::c_int;
    }
    ASN1_OBJECT_free((*attr).object);
    (*attr).object = OBJ_dup(obj);
    return ((*attr).object != 0 as *mut libc::c_void as *mut ASN1_OBJECT) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_ATTRIBUTE_set1_data(
    mut attr: *mut X509_ATTRIBUTE,
    mut attrtype: libc::c_int,
    mut data: *const libc::c_void,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    if attr.is_null() {
        return 0 as libc::c_int;
    }
    if attrtype == 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    let mut typ: *mut ASN1_TYPE = ASN1_TYPE_new();
    if typ.is_null() {
        return 0 as libc::c_int;
    }
    if attrtype & 0x1000 as libc::c_int != 0 {
        let mut str: *mut ASN1_STRING = ASN1_STRING_set_by_NID(
            0 as *mut *mut ASN1_STRING,
            data as *const libc::c_uchar,
            len as ossl_ssize_t,
            attrtype,
            OBJ_obj2nid((*attr).object),
        );
        if str.is_null() {
            ERR_put_error(
                11 as libc::c_int,
                0 as libc::c_int,
                12 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_att.c\0"
                    as *const u8 as *const libc::c_char,
                163 as libc::c_int as libc::c_uint,
            );
            current_block = 2726795725324713963;
        } else {
            asn1_type_set0_string(typ, str);
            current_block = 15652330335145281839;
        }
    } else if len != -(1 as libc::c_int) {
        let mut str_0: *mut ASN1_STRING = ASN1_STRING_type_new(attrtype);
        if str_0.is_null() || ASN1_STRING_set(str_0, data, len as ossl_ssize_t) == 0 {
            ASN1_STRING_free(str_0);
            current_block = 2726795725324713963;
        } else {
            asn1_type_set0_string(typ, str_0);
            current_block = 15652330335145281839;
        }
    } else if ASN1_TYPE_set1(typ, attrtype, data) == 0 {
        current_block = 2726795725324713963;
    } else {
        current_block = 15652330335145281839;
    }
    match current_block {
        15652330335145281839 => {
            if !(sk_ASN1_TYPE_push((*attr).set, typ) == 0) {
                return 1 as libc::c_int;
            }
        }
        _ => {}
    }
    ASN1_TYPE_free(typ);
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_ATTRIBUTE_count(
    mut attr: *const X509_ATTRIBUTE,
) -> libc::c_int {
    if attr.is_null() {
        return 0 as libc::c_int;
    }
    return sk_ASN1_TYPE_num((*attr).set) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_ATTRIBUTE_get0_object(
    mut attr: *mut X509_ATTRIBUTE,
) -> *mut ASN1_OBJECT {
    if attr.is_null() {
        return 0 as *mut ASN1_OBJECT;
    }
    return (*attr).object;
}
#[no_mangle]
pub unsafe extern "C" fn X509_ATTRIBUTE_get0_data(
    mut attr: *mut X509_ATTRIBUTE,
    mut idx: libc::c_int,
    mut attrtype: libc::c_int,
    mut unused: *mut libc::c_void,
) -> *mut libc::c_void {
    let mut ttmp: *mut ASN1_TYPE = 0 as *mut ASN1_TYPE;
    ttmp = X509_ATTRIBUTE_get0_type(attr, idx);
    if ttmp.is_null() {
        return 0 as *mut libc::c_void;
    }
    if attrtype != ASN1_TYPE_get(ttmp) {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            134 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_att.c\0" as *const u8
                as *const libc::c_char,
            216 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut libc::c_void;
    }
    return asn1_type_value_as_pointer(ttmp) as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn X509_ATTRIBUTE_get0_type(
    mut attr: *mut X509_ATTRIBUTE,
    mut idx: libc::c_int,
) -> *mut ASN1_TYPE {
    if attr.is_null() {
        return 0 as *mut ASN1_TYPE;
    }
    if idx >= X509_ATTRIBUTE_count(attr) {
        return 0 as *mut ASN1_TYPE;
    }
    return sk_ASN1_TYPE_value((*attr).set, idx as size_t);
}
