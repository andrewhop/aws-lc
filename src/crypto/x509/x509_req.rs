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
    pub type stack_st_X509_NAME_ENTRY;
    pub type evp_pkey_st;
    pub type stack_st_X509_EXTENSION;
    pub type stack_st_X509_ATTRIBUTE;
    pub type stack_st_ASN1_TYPE;
    pub type stack_st;
    fn ASN1_item_d2i(
        out: *mut *mut ASN1_VALUE,
        inp: *mut *const libc::c_uchar,
        len: libc::c_long,
        it: *const ASN1_ITEM,
    ) -> *mut ASN1_VALUE;
    fn ASN1_item_i2d(
        val: *mut ASN1_VALUE,
        outp: *mut *mut libc::c_uchar,
        it: *const ASN1_ITEM,
    ) -> libc::c_int;
    fn ASN1_INTEGER_get(a: *const ASN1_INTEGER) -> libc::c_long;
    fn asn1_encoding_clear(enc: *mut ASN1_ENCODING);
    fn X509_PUBKEY_get0(key: *const X509_PUBKEY) -> *mut EVP_PKEY;
    fn X509_PUBKEY_get(key: *const X509_PUBKEY) -> *mut EVP_PKEY;
    static X509_EXTENSIONS_it: ASN1_ITEM;
    fn X509_ATTRIBUTE_dup(attr: *const X509_ATTRIBUTE) -> *mut X509_ATTRIBUTE;
    fn X509_ATTRIBUTE_free(attr: *mut X509_ATTRIBUTE);
    fn X509_ATTRIBUTE_create_by_NID(
        attr: *mut *mut X509_ATTRIBUTE,
        nid: libc::c_int,
        attrtype: libc::c_int,
        data: *const libc::c_void,
        len: libc::c_int,
    ) -> *mut X509_ATTRIBUTE;
    fn X509_ATTRIBUTE_create_by_OBJ(
        attr: *mut *mut X509_ATTRIBUTE,
        obj: *const ASN1_OBJECT,
        attrtype: libc::c_int,
        data: *const libc::c_void,
        len: libc::c_int,
    ) -> *mut X509_ATTRIBUTE;
    fn X509_ATTRIBUTE_create_by_txt(
        attr: *mut *mut X509_ATTRIBUTE,
        attrname: *const libc::c_char,
        type_0: libc::c_int,
        bytes: *const libc::c_uchar,
        len: libc::c_int,
    ) -> *mut X509_ATTRIBUTE;
    fn X509_ATTRIBUTE_get0_type(
        attr: *mut X509_ATTRIBUTE,
        idx: libc::c_int,
    ) -> *mut ASN1_TYPE;
    fn i2d_X509_REQ_INFO(
        a: *mut X509_REQ_INFO,
        out: *mut *mut libc::c_uchar,
    ) -> libc::c_int;
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_delete(sk: *mut OPENSSL_STACK, where_0: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OBJ_cmp(a: *const ASN1_OBJECT, b: *const ASN1_OBJECT) -> libc::c_int;
    fn OBJ_obj2nid(obj: *const ASN1_OBJECT) -> libc::c_int;
    fn OBJ_nid2obj(nid: libc::c_int) -> *mut ASN1_OBJECT;
    fn EVP_PKEY_cmp(a: *const EVP_PKEY, b: *const EVP_PKEY) -> libc::c_int;
    fn EVP_PKEY_id(pkey: *const EVP_PKEY) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
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
pub type X509_NAME = X509_name_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_name_st {
    pub entries: *mut stack_st_X509_NAME_ENTRY,
    pub modified: libc::c_int,
    pub bytes: *mut BUF_MEM,
    pub canon_enc: *mut libc::c_uchar,
    pub canon_enclen: libc::c_int,
}
pub type BUF_MEM = buf_mem_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct buf_mem_st {
    pub length: size_t,
    pub data: *mut libc::c_char,
    pub max: size_t,
}
pub type X509_PUBKEY = X509_pubkey_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_pubkey_st {
    pub algor: *mut X509_ALGOR,
    pub public_key: *mut ASN1_BIT_STRING,
    pub pkey: *mut EVP_PKEY,
}
pub type EVP_PKEY = evp_pkey_st;
pub type X509_ALGOR = X509_algor_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_algor_st {
    pub algorithm: *mut ASN1_OBJECT,
    pub parameter: *mut ASN1_TYPE,
}
pub type ASN1_ENCODING = ASN1_ENCODING_st;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_req_st {
    pub req_info: *mut X509_REQ_INFO,
    pub sig_alg: *mut X509_ALGOR,
    pub signature: *mut ASN1_BIT_STRING,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_REQ_INFO {
    pub enc: ASN1_ENCODING,
    pub version: *mut ASN1_INTEGER,
    pub subject: *mut X509_NAME,
    pub pubkey: *mut X509_PUBKEY,
    pub attributes: *mut stack_st_X509_ATTRIBUTE,
}
pub type X509_REQ = X509_req_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_attributes_st {
    pub object: *mut ASN1_OBJECT,
    pub set: *mut stack_st_ASN1_TYPE,
}
pub type X509_ATTRIBUTE = x509_attributes_st;
pub type OPENSSL_STACK = stack_st;
#[inline]
unsafe extern "C" fn sk_X509_ATTRIBUTE_num(
    mut sk: *const stack_st_X509_ATTRIBUTE,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_ATTRIBUTE_value(
    mut sk: *const stack_st_X509_ATTRIBUTE,
    mut i: size_t,
) -> *mut X509_ATTRIBUTE {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509_ATTRIBUTE;
}
#[inline]
unsafe extern "C" fn sk_X509_ATTRIBUTE_delete(
    mut sk: *mut stack_st_X509_ATTRIBUTE,
    mut where_0: size_t,
) -> *mut X509_ATTRIBUTE {
    return OPENSSL_sk_delete(sk as *mut OPENSSL_STACK, where_0) as *mut X509_ATTRIBUTE;
}
#[inline]
unsafe extern "C" fn sk_X509_ATTRIBUTE_push(
    mut sk: *mut stack_st_X509_ATTRIBUTE,
    mut p: *mut X509_ATTRIBUTE,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_X509_ATTRIBUTE_new_null() -> *mut stack_st_X509_ATTRIBUTE {
    return OPENSSL_sk_new_null() as *mut stack_st_X509_ATTRIBUTE;
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_get_version(mut req: *const X509_REQ) -> libc::c_long {
    return ASN1_INTEGER_get((*(*req).req_info).version);
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_get_subject_name(
    mut req: *const X509_REQ,
) -> *mut X509_NAME {
    return (*(*req).req_info).subject;
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_get_pubkey(mut req: *const X509_REQ) -> *mut EVP_PKEY {
    if req.is_null() || ((*req).req_info).is_null() {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_req.c\0" as *const u8
                as *const libc::c_char,
            81 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EVP_PKEY;
    }
    return X509_PUBKEY_get((*(*req).req_info).pubkey);
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_get0_pubkey(
    mut req: *const X509_REQ,
) -> *mut EVP_PKEY {
    if req.is_null() || ((*req).req_info).is_null() {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_req.c\0" as *const u8
                as *const libc::c_char,
            89 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EVP_PKEY;
    }
    return X509_PUBKEY_get0((*(*req).req_info).pubkey);
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_check_private_key(
    mut x: *const X509_REQ,
    mut k: *const EVP_PKEY,
) -> libc::c_int {
    let mut xk: *const EVP_PKEY = X509_REQ_get0_pubkey(x);
    if xk.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = EVP_PKEY_cmp(xk, k);
    if ret > 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    match ret {
        0 => {
            ERR_put_error(
                11 as libc::c_int,
                0 as libc::c_int,
                116 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_req.c\0"
                    as *const u8 as *const libc::c_char,
                108 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        -1 => {
            ERR_put_error(
                11 as libc::c_int,
                0 as libc::c_int,
                115 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_req.c\0"
                    as *const u8 as *const libc::c_char,
                111 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        -2 => {
            if EVP_PKEY_id(k) == 408 as libc::c_int {
                ERR_put_error(
                    11 as libc::c_int,
                    0 as libc::c_int,
                    15 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_req.c\0"
                        as *const u8 as *const libc::c_char,
                    115 as libc::c_int as libc::c_uint,
                );
            } else {
                ERR_put_error(
                    11 as libc::c_int,
                    0 as libc::c_int,
                    128 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_req.c\0"
                        as *const u8 as *const libc::c_char,
                    117 as libc::c_int as libc::c_uint,
                );
            }
            return 0 as libc::c_int;
        }
        _ => {}
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_extension_nid(
    mut req_nid: libc::c_int,
) -> libc::c_int {
    return (req_nid == 172 as libc::c_int || req_nid == 171 as libc::c_int)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_get_extensions(
    mut req: *const X509_REQ,
) -> *mut stack_st_X509_EXTENSION {
    if req.is_null() || ((*req).req_info).is_null() {
        return 0 as *mut stack_st_X509_EXTENSION;
    }
    let mut idx: libc::c_int = X509_REQ_get_attr_by_NID(
        req,
        172 as libc::c_int,
        -(1 as libc::c_int),
    );
    if idx == -(1 as libc::c_int) {
        idx = X509_REQ_get_attr_by_NID(req, 171 as libc::c_int, -(1 as libc::c_int));
    }
    if idx == -(1 as libc::c_int) {
        return 0 as *mut stack_st_X509_EXTENSION;
    }
    let mut attr: *const X509_ATTRIBUTE = X509_REQ_get_attr(req, idx);
    let mut ext: *const ASN1_TYPE = X509_ATTRIBUTE_get0_type(
        attr as *mut X509_ATTRIBUTE,
        0 as libc::c_int,
    );
    if ext.is_null() || (*ext).type_0 != 16 as libc::c_int {
        return 0 as *mut stack_st_X509_EXTENSION;
    }
    let mut p: *const libc::c_uchar = (*(*ext).value.sequence).data;
    return ASN1_item_d2i(
        0 as *mut *mut ASN1_VALUE,
        &mut p,
        (*(*ext).value.sequence).length as libc::c_long,
        &X509_EXTENSIONS_it,
    ) as *mut stack_st_X509_EXTENSION;
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_add_extensions_nid(
    mut req: *mut X509_REQ,
    mut exts: *const stack_st_X509_EXTENSION,
    mut nid: libc::c_int,
) -> libc::c_int {
    let mut ext: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut ext_len: libc::c_int = ASN1_item_i2d(
        exts as *mut ASN1_VALUE,
        &mut ext,
        &X509_EXTENSIONS_it,
    );
    if ext_len <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = X509_REQ_add1_attr_by_NID(
        req,
        nid,
        16 as libc::c_int,
        ext,
        ext_len,
    );
    OPENSSL_free(ext as *mut libc::c_void);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_add_extensions(
    mut req: *mut X509_REQ,
    mut exts: *const stack_st_X509_EXTENSION,
) -> libc::c_int {
    return X509_REQ_add_extensions_nid(req, exts, 172 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_get_attr_count(
    mut req: *const X509_REQ,
) -> libc::c_int {
    return sk_X509_ATTRIBUTE_num((*(*req).req_info).attributes) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_get_attr_by_NID(
    mut req: *const X509_REQ,
    mut nid: libc::c_int,
    mut lastpos: libc::c_int,
) -> libc::c_int {
    let mut obj: *const ASN1_OBJECT = OBJ_nid2obj(nid);
    if obj.is_null() {
        return -(1 as libc::c_int);
    }
    return X509_REQ_get_attr_by_OBJ(req, obj, lastpos);
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_get_attr_by_OBJ(
    mut req: *const X509_REQ,
    mut obj: *const ASN1_OBJECT,
    mut lastpos: libc::c_int,
) -> libc::c_int {
    if ((*(*req).req_info).attributes).is_null() {
        return -(1 as libc::c_int);
    }
    lastpos += 1;
    lastpos;
    if lastpos < 0 as libc::c_int {
        lastpos = 0 as libc::c_int;
    }
    let mut n: libc::c_int = sk_X509_ATTRIBUTE_num((*(*req).req_info).attributes)
        as libc::c_int;
    while lastpos < n {
        let mut attr: *const X509_ATTRIBUTE = sk_X509_ATTRIBUTE_value(
            (*(*req).req_info).attributes,
            lastpos as size_t,
        );
        if attr.is_null() {
            return -(1 as libc::c_int);
        }
        if OBJ_cmp((*attr).object, obj) == 0 as libc::c_int {
            return lastpos;
        }
        lastpos += 1;
        lastpos;
    }
    return -(1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_get_attr(
    mut req: *const X509_REQ,
    mut loc: libc::c_int,
) -> *mut X509_ATTRIBUTE {
    if ((*(*req).req_info).attributes).is_null() || loc < 0 as libc::c_int
        || sk_X509_ATTRIBUTE_num((*(*req).req_info).attributes) <= loc as size_t
    {
        return 0 as *mut X509_ATTRIBUTE;
    }
    return sk_X509_ATTRIBUTE_value((*(*req).req_info).attributes, loc as size_t);
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_delete_attr(
    mut req: *mut X509_REQ,
    mut loc: libc::c_int,
) -> *mut X509_ATTRIBUTE {
    if ((*(*req).req_info).attributes).is_null() || loc < 0 as libc::c_int
        || sk_X509_ATTRIBUTE_num((*(*req).req_info).attributes) <= loc as size_t
    {
        return 0 as *mut X509_ATTRIBUTE;
    }
    return sk_X509_ATTRIBUTE_delete((*(*req).req_info).attributes, loc as size_t);
}
unsafe extern "C" fn X509_REQ_add0_attr(
    mut req: *mut X509_REQ,
    mut attr: *mut X509_ATTRIBUTE,
) -> libc::c_int {
    if ((*(*req).req_info).attributes).is_null() {
        (*(*req).req_info).attributes = sk_X509_ATTRIBUTE_new_null();
    }
    if ((*(*req).req_info).attributes).is_null()
        || sk_X509_ATTRIBUTE_push((*(*req).req_info).attributes, attr) == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_add1_attr(
    mut req: *mut X509_REQ,
    mut attr: *const X509_ATTRIBUTE,
) -> libc::c_int {
    let mut new_attr: *mut X509_ATTRIBUTE = X509_ATTRIBUTE_dup(attr);
    if new_attr.is_null() || X509_REQ_add0_attr(req, new_attr) == 0 {
        X509_ATTRIBUTE_free(new_attr);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_add1_attr_by_OBJ(
    mut req: *mut X509_REQ,
    mut obj: *const ASN1_OBJECT,
    mut attrtype: libc::c_int,
    mut data: *const libc::c_uchar,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut attr: *mut X509_ATTRIBUTE = X509_ATTRIBUTE_create_by_OBJ(
        0 as *mut *mut X509_ATTRIBUTE,
        obj,
        attrtype,
        data as *const libc::c_void,
        len,
    );
    if attr.is_null() || X509_REQ_add0_attr(req, attr) == 0 {
        X509_ATTRIBUTE_free(attr);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_add1_attr_by_NID(
    mut req: *mut X509_REQ,
    mut nid: libc::c_int,
    mut attrtype: libc::c_int,
    mut data: *const libc::c_uchar,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut attr: *mut X509_ATTRIBUTE = X509_ATTRIBUTE_create_by_NID(
        0 as *mut *mut X509_ATTRIBUTE,
        nid,
        attrtype,
        data as *const libc::c_void,
        len,
    );
    if attr.is_null() || X509_REQ_add0_attr(req, attr) == 0 {
        X509_ATTRIBUTE_free(attr);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_add1_attr_by_txt(
    mut req: *mut X509_REQ,
    mut attrname: *const libc::c_char,
    mut attrtype: libc::c_int,
    mut data: *const libc::c_uchar,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut attr: *mut X509_ATTRIBUTE = X509_ATTRIBUTE_create_by_txt(
        0 as *mut *mut X509_ATTRIBUTE,
        attrname,
        attrtype,
        data,
        len,
    );
    if attr.is_null() || X509_REQ_add0_attr(req, attr) == 0 {
        X509_ATTRIBUTE_free(attr);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_get0_signature(
    mut req: *const X509_REQ,
    mut psig: *mut *const ASN1_BIT_STRING,
    mut palg: *mut *const X509_ALGOR,
) {
    if !psig.is_null() {
        *psig = (*req).signature;
    }
    if !palg.is_null() {
        *palg = (*req).sig_alg;
    }
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_get_signature_nid(
    mut req: *const X509_REQ,
) -> libc::c_int {
    return OBJ_obj2nid((*(*req).sig_alg).algorithm);
}
#[no_mangle]
pub unsafe extern "C" fn i2d_re_X509_REQ_tbs(
    mut req: *mut X509_REQ,
    mut pp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    asn1_encoding_clear(&mut (*(*req).req_info).enc);
    return i2d_X509_REQ_INFO((*req).req_info, pp);
}
