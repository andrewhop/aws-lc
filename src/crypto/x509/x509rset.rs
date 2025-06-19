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
    pub type stack_st_X509_ATTRIBUTE;
    fn ASN1_STRING_set(
        str: *mut ASN1_STRING,
        data: *const libc::c_void,
        len: ossl_ssize_t,
    ) -> libc::c_int;
    fn ASN1_INTEGER_set_int64(out: *mut ASN1_INTEGER, v: int64_t) -> libc::c_int;
    fn X509_NAME_set(xn: *mut *mut X509_NAME, name: *mut X509_NAME) -> libc::c_int;
    fn X509_PUBKEY_set(x: *mut *mut X509_PUBKEY, pkey: *mut EVP_PKEY) -> libc::c_int;
    fn X509_ALGOR_dup(alg: *const X509_ALGOR) -> *mut X509_ALGOR;
    fn X509_ALGOR_free(alg: *mut X509_ALGOR);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
}
pub type ptrdiff_t = libc::c_long;
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __int64_t = libc::c_long;
pub type int64_t = __int64_t;
pub type uint8_t = __uint8_t;
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
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_set_version(
    mut x: *mut X509_REQ,
    mut version: libc::c_long,
) -> libc::c_int {
    if x.is_null() {
        return 0 as libc::c_int;
    }
    if version != 0 as libc::c_int as libc::c_long {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            140 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509rset.c\0" as *const u8
                as *const libc::c_char,
            70 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ASN1_INTEGER_set_int64((*(*x).req_info).version, version);
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_set_subject_name(
    mut x: *mut X509_REQ,
    mut name: *mut X509_NAME,
) -> libc::c_int {
    if x.is_null() || ((*x).req_info).is_null() {
        return 0 as libc::c_int;
    }
    return X509_NAME_set(&mut (*(*x).req_info).subject, name);
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_set_pubkey(
    mut x: *mut X509_REQ,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    if x.is_null() || ((*x).req_info).is_null() {
        return 0 as libc::c_int;
    }
    return X509_PUBKEY_set(&mut (*(*x).req_info).pubkey, pkey);
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_set1_signature_algo(
    mut req: *mut X509_REQ,
    mut algo: *const X509_ALGOR,
) -> libc::c_int {
    let mut copy: *mut X509_ALGOR = X509_ALGOR_dup(algo);
    if copy.is_null() {
        return 0 as libc::c_int;
    }
    X509_ALGOR_free((*req).sig_alg);
    (*req).sig_alg = copy;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_set1_signature_value(
    mut req: *mut X509_REQ,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
) -> libc::c_int {
    if ASN1_STRING_set(
        (*req).signature,
        sig as *const libc::c_void,
        sig_len as ossl_ssize_t,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    (*(*req).signature).flags
        &= !(0x8 as libc::c_int | 0x7 as libc::c_int) as libc::c_long;
    (*(*req).signature).flags |= 0x8 as libc::c_int as libc::c_long;
    return 1 as libc::c_int;
}
