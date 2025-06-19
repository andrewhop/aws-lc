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
    pub type stack_st_GENERAL_NAME;
    pub type stack_st_X509_NAME_ENTRY;
    pub type stack_st_GENERAL_SUBTREE;
    pub type evp_pkey_st;
    pub type stack_st_ASN1_OBJECT;
    pub type stack_st_X509_EXTENSION;
    pub type stack_st_X509_REVOKED;
    pub type crypto_buffer_st;
    pub type stack_st_DIST_POINT;
    pub type stack_st_void;
    fn X509v3_get_ext_count(x: *const stack_st_X509_EXTENSION) -> libc::c_int;
    fn X509v3_get_ext_by_NID(
        x: *const stack_st_X509_EXTENSION,
        nid: libc::c_int,
        lastpos: libc::c_int,
    ) -> libc::c_int;
    fn X509v3_get_ext_by_OBJ(
        x: *const stack_st_X509_EXTENSION,
        obj: *const ASN1_OBJECT,
        lastpos: libc::c_int,
    ) -> libc::c_int;
    fn X509v3_get_ext_by_critical(
        x: *const stack_st_X509_EXTENSION,
        crit: libc::c_int,
        lastpos: libc::c_int,
    ) -> libc::c_int;
    fn X509v3_get_ext(
        x: *const stack_st_X509_EXTENSION,
        loc: libc::c_int,
    ) -> *mut X509_EXTENSION;
    fn X509v3_delete_ext(
        x: *mut stack_st_X509_EXTENSION,
        loc: libc::c_int,
    ) -> *mut X509_EXTENSION;
    fn X509v3_add_ext(
        x: *mut *mut stack_st_X509_EXTENSION,
        ex: *const X509_EXTENSION,
        loc: libc::c_int,
    ) -> *mut stack_st_X509_EXTENSION;
    fn X509V3_get_d2i(
        extensions: *const stack_st_X509_EXTENSION,
        nid: libc::c_int,
        out_critical: *mut libc::c_int,
        out_idx: *mut libc::c_int,
    ) -> *mut libc::c_void;
    fn X509V3_add1_i2d(
        x: *mut *mut stack_st_X509_EXTENSION,
        nid: libc::c_int,
        value: *mut libc::c_void,
        crit: libc::c_int,
        flags: libc::c_ulong,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
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
pub type ASN1_TIME = asn1_string_st;
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
pub struct AUTHORITY_KEYID_st {
    pub keyid: *mut ASN1_OCTET_STRING,
    pub issuer: *mut GENERAL_NAMES,
    pub serial: *mut ASN1_INTEGER,
}
pub type GENERAL_NAMES = stack_st_GENERAL_NAME;
pub type AUTHORITY_KEYID = AUTHORITY_KEYID_st;
pub type DIST_POINT_NAME = DIST_POINT_NAME_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct DIST_POINT_NAME_st {
    pub type_0: libc::c_int,
    pub name: C2RustUnnamed_0,
    pub dpname: *mut X509_NAME,
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub fullname: *mut GENERAL_NAMES,
    pub relativename: *mut stack_st_X509_NAME_ENTRY,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ISSUING_DIST_POINT_st {
    pub distpoint: *mut DIST_POINT_NAME,
    pub onlyuser: ASN1_BOOLEAN,
    pub onlyCA: ASN1_BOOLEAN,
    pub onlysomereasons: *mut ASN1_BIT_STRING,
    pub indirectCRL: ASN1_BOOLEAN,
    pub onlyattr: ASN1_BOOLEAN,
}
pub type ISSUING_DIST_POINT = ISSUING_DIST_POINT_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct NAME_CONSTRAINTS_st {
    pub permittedSubtrees: *mut stack_st_GENERAL_SUBTREE,
    pub excludedSubtrees: *mut stack_st_GENERAL_SUBTREE,
}
pub type NAME_CONSTRAINTS = NAME_CONSTRAINTS_st;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_crl_st {
    pub crl: *mut X509_CRL_INFO,
    pub sig_alg: *mut X509_ALGOR,
    pub signature: *mut ASN1_BIT_STRING,
    pub references: CRYPTO_refcount_t,
    pub flags: libc::c_int,
    pub akid: *mut AUTHORITY_KEYID,
    pub idp: *mut ISSUING_DIST_POINT,
    pub idp_flags: libc::c_int,
    pub crl_hash: [libc::c_uchar; 32],
}
pub type CRYPTO_refcount_t = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_CRL_INFO {
    pub version: *mut ASN1_INTEGER,
    pub sig_alg: *mut X509_ALGOR,
    pub issuer: *mut X509_NAME,
    pub lastUpdate: *mut ASN1_TIME,
    pub nextUpdate: *mut ASN1_TIME,
    pub revoked: *mut stack_st_X509_REVOKED,
    pub extensions: *mut stack_st_X509_EXTENSION,
    pub enc: ASN1_ENCODING,
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
pub type X509_CRL = X509_crl_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_extension_st {
    pub object: *mut ASN1_OBJECT,
    pub critical: ASN1_BOOLEAN,
    pub value: *mut ASN1_OCTET_STRING,
}
pub type X509_EXTENSION = X509_extension_st;
pub type X509 = x509_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_st {
    pub cert_info: *mut X509_CINF,
    pub sig_alg: *mut X509_ALGOR,
    pub signature: *mut ASN1_BIT_STRING,
    pub sig_info: X509_SIG_INFO,
    pub references: CRYPTO_refcount_t,
    pub ex_data: CRYPTO_EX_DATA,
    pub ex_pathlen: libc::c_long,
    pub ex_flags: uint32_t,
    pub ex_kusage: uint32_t,
    pub ex_xkusage: uint32_t,
    pub ex_nscert: uint32_t,
    pub skid: *mut ASN1_OCTET_STRING,
    pub akid: *mut AUTHORITY_KEYID,
    pub crldp: *mut stack_st_DIST_POINT,
    pub altname: *mut stack_st_GENERAL_NAME,
    pub nc: *mut NAME_CONSTRAINTS,
    pub cert_hash: [libc::c_uchar; 32],
    pub aux: *mut X509_CERT_AUX,
    pub buf: *mut CRYPTO_BUFFER,
    pub lock: CRYPTO_MUTEX,
}
pub type CRYPTO_MUTEX = crypto_mutex_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub union crypto_mutex_st {
    pub alignment: libc::c_double,
    pub padding: [uint8_t; 56],
}
pub type CRYPTO_BUFFER = crypto_buffer_st;
pub type X509_CERT_AUX = x509_cert_aux_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_cert_aux_st {
    pub trust: *mut stack_st_ASN1_OBJECT,
    pub reject: *mut stack_st_ASN1_OBJECT,
    pub alias: *mut ASN1_UTF8STRING,
    pub keyid: *mut ASN1_OCTET_STRING,
}
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
pub type X509_SIG_INFO = x509_sig_info_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_sig_info_st {
    pub digest_nid: libc::c_int,
    pub pubkey_nid: libc::c_int,
    pub sec_bits: libc::c_int,
    pub flags: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_CINF {
    pub version: *mut ASN1_INTEGER,
    pub serialNumber: *mut ASN1_INTEGER,
    pub signature: *mut X509_ALGOR,
    pub issuer: *mut X509_NAME,
    pub validity: *mut X509_VAL,
    pub subject: *mut X509_NAME,
    pub key: *mut X509_PUBKEY,
    pub issuerUID: *mut ASN1_BIT_STRING,
    pub subjectUID: *mut ASN1_BIT_STRING,
    pub extensions: *mut stack_st_X509_EXTENSION,
    pub enc: ASN1_ENCODING,
}
pub type X509_VAL = X509_val_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_val_st {
    pub notBefore: *mut ASN1_TIME,
    pub notAfter: *mut ASN1_TIME,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_revoked_st {
    pub serialNumber: *mut ASN1_INTEGER,
    pub revocationDate: *mut ASN1_TIME,
    pub extensions: *mut stack_st_X509_EXTENSION,
    pub reason: libc::c_int,
}
pub type X509_REVOKED = x509_revoked_st;
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get_ext_count(mut x: *const X509_CRL) -> libc::c_int {
    return X509v3_get_ext_count((*(*x).crl).extensions);
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get_ext_by_NID(
    mut x: *const X509_CRL,
    mut nid: libc::c_int,
    mut lastpos: libc::c_int,
) -> libc::c_int {
    return X509v3_get_ext_by_NID((*(*x).crl).extensions, nid, lastpos);
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get_ext_by_OBJ(
    mut x: *const X509_CRL,
    mut obj: *const ASN1_OBJECT,
    mut lastpos: libc::c_int,
) -> libc::c_int {
    return X509v3_get_ext_by_OBJ((*(*x).crl).extensions, obj, lastpos);
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get_ext_by_critical(
    mut x: *const X509_CRL,
    mut crit: libc::c_int,
    mut lastpos: libc::c_int,
) -> libc::c_int {
    return X509v3_get_ext_by_critical((*(*x).crl).extensions, crit, lastpos);
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get_ext(
    mut x: *const X509_CRL,
    mut loc: libc::c_int,
) -> *mut X509_EXTENSION {
    return X509v3_get_ext((*(*x).crl).extensions, loc);
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_delete_ext(
    mut x: *mut X509_CRL,
    mut loc: libc::c_int,
) -> *mut X509_EXTENSION {
    return X509v3_delete_ext((*(*x).crl).extensions, loc);
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get_ext_d2i(
    mut crl: *const X509_CRL,
    mut nid: libc::c_int,
    mut out_critical: *mut libc::c_int,
    mut out_idx: *mut libc::c_int,
) -> *mut libc::c_void {
    return X509V3_get_d2i((*(*crl).crl).extensions, nid, out_critical, out_idx);
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_add1_ext_i2d(
    mut x: *mut X509_CRL,
    mut nid: libc::c_int,
    mut value: *mut libc::c_void,
    mut crit: libc::c_int,
    mut flags: libc::c_ulong,
) -> libc::c_int {
    return X509V3_add1_i2d(&mut (*(*x).crl).extensions, nid, value, crit, flags);
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_add_ext(
    mut x: *mut X509_CRL,
    mut ex: *const X509_EXTENSION,
    mut loc: libc::c_int,
) -> libc::c_int {
    return (X509v3_add_ext(&mut (*(*x).crl).extensions, ex, loc)
        != 0 as *mut libc::c_void as *mut stack_st_X509_EXTENSION) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_get_ext_count(mut x: *const X509) -> libc::c_int {
    return X509v3_get_ext_count((*(*x).cert_info).extensions);
}
#[no_mangle]
pub unsafe extern "C" fn X509_get_ext_by_NID(
    mut x: *const X509,
    mut nid: libc::c_int,
    mut lastpos: libc::c_int,
) -> libc::c_int {
    return X509v3_get_ext_by_NID((*(*x).cert_info).extensions, nid, lastpos);
}
#[no_mangle]
pub unsafe extern "C" fn X509_get_ext_by_OBJ(
    mut x: *const X509,
    mut obj: *const ASN1_OBJECT,
    mut lastpos: libc::c_int,
) -> libc::c_int {
    return X509v3_get_ext_by_OBJ((*(*x).cert_info).extensions, obj, lastpos);
}
#[no_mangle]
pub unsafe extern "C" fn X509_get_ext_by_critical(
    mut x: *const X509,
    mut crit: libc::c_int,
    mut lastpos: libc::c_int,
) -> libc::c_int {
    return X509v3_get_ext_by_critical((*(*x).cert_info).extensions, crit, lastpos);
}
#[no_mangle]
pub unsafe extern "C" fn X509_get_ext(
    mut x: *const X509,
    mut loc: libc::c_int,
) -> *mut X509_EXTENSION {
    return X509v3_get_ext((*(*x).cert_info).extensions, loc);
}
#[no_mangle]
pub unsafe extern "C" fn X509_delete_ext(
    mut x: *mut X509,
    mut loc: libc::c_int,
) -> *mut X509_EXTENSION {
    return X509v3_delete_ext((*(*x).cert_info).extensions, loc);
}
#[no_mangle]
pub unsafe extern "C" fn X509_add_ext(
    mut x: *mut X509,
    mut ex: *const X509_EXTENSION,
    mut loc: libc::c_int,
) -> libc::c_int {
    return (X509v3_add_ext(&mut (*(*x).cert_info).extensions, ex, loc)
        != 0 as *mut libc::c_void as *mut stack_st_X509_EXTENSION) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_get_ext_d2i(
    mut x509: *const X509,
    mut nid: libc::c_int,
    mut out_critical: *mut libc::c_int,
    mut out_idx: *mut libc::c_int,
) -> *mut libc::c_void {
    return X509V3_get_d2i((*(*x509).cert_info).extensions, nid, out_critical, out_idx);
}
#[no_mangle]
pub unsafe extern "C" fn X509_add1_ext_i2d(
    mut x: *mut X509,
    mut nid: libc::c_int,
    mut value: *mut libc::c_void,
    mut crit: libc::c_int,
    mut flags: libc::c_ulong,
) -> libc::c_int {
    return X509V3_add1_i2d(&mut (*(*x).cert_info).extensions, nid, value, crit, flags);
}
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_get_ext_count(
    mut x: *const X509_REVOKED,
) -> libc::c_int {
    return X509v3_get_ext_count((*x).extensions);
}
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_get_ext_by_NID(
    mut x: *const X509_REVOKED,
    mut nid: libc::c_int,
    mut lastpos: libc::c_int,
) -> libc::c_int {
    return X509v3_get_ext_by_NID((*x).extensions, nid, lastpos);
}
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_get_ext_by_OBJ(
    mut x: *const X509_REVOKED,
    mut obj: *const ASN1_OBJECT,
    mut lastpos: libc::c_int,
) -> libc::c_int {
    return X509v3_get_ext_by_OBJ((*x).extensions, obj, lastpos);
}
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_get_ext_by_critical(
    mut x: *const X509_REVOKED,
    mut crit: libc::c_int,
    mut lastpos: libc::c_int,
) -> libc::c_int {
    return X509v3_get_ext_by_critical((*x).extensions, crit, lastpos);
}
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_get_ext(
    mut x: *const X509_REVOKED,
    mut loc: libc::c_int,
) -> *mut X509_EXTENSION {
    return X509v3_get_ext((*x).extensions, loc);
}
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_delete_ext(
    mut x: *mut X509_REVOKED,
    mut loc: libc::c_int,
) -> *mut X509_EXTENSION {
    return X509v3_delete_ext((*x).extensions, loc);
}
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_add_ext(
    mut x: *mut X509_REVOKED,
    mut ex: *const X509_EXTENSION,
    mut loc: libc::c_int,
) -> libc::c_int {
    return (X509v3_add_ext(&mut (*x).extensions, ex, loc)
        != 0 as *mut libc::c_void as *mut stack_st_X509_EXTENSION) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_get_ext_d2i(
    mut revoked: *const X509_REVOKED,
    mut nid: libc::c_int,
    mut out_critical: *mut libc::c_int,
    mut out_idx: *mut libc::c_int,
) -> *mut libc::c_void {
    return X509V3_get_d2i((*revoked).extensions, nid, out_critical, out_idx);
}
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_add1_ext_i2d(
    mut x: *mut X509_REVOKED,
    mut nid: libc::c_int,
    mut value: *mut libc::c_void,
    mut crit: libc::c_int,
    mut flags: libc::c_ulong,
) -> libc::c_int {
    return X509V3_add1_i2d(&mut (*x).extensions, nid, value, crit, flags);
}
