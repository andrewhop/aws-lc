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
    pub type stack_st_X509;
    pub type stack_st;
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
    fn ASN1_INTEGER_cmp(x: *const ASN1_INTEGER, y: *const ASN1_INTEGER) -> libc::c_int;
    fn X509_up_ref(x509: *mut X509) -> libc::c_int;
    fn i2d_X509_NAME(in_0: *mut X509_NAME, outp: *mut *mut uint8_t) -> libc::c_int;
    fn X509_PUBKEY_get0(key: *const X509_PUBKEY) -> *mut EVP_PKEY;
    fn X509_PUBKEY_get(key: *const X509_PUBKEY) -> *mut EVP_PKEY;
    fn x509v3_cache_extensions(x: *mut X509) -> libc::c_int;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_dup(sk: *const OPENSSL_STACK) -> *mut OPENSSL_STACK;
    fn MD5(data: *const uint8_t, len: size_t, out: *mut uint8_t) -> *mut uint8_t;
    fn SHA1(data: *const uint8_t, len: size_t, out: *mut uint8_t) -> *mut uint8_t;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn EVP_PKEY_cmp(a: *const EVP_PKEY, b: *const EVP_PKEY) -> libc::c_int;
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
pub type OPENSSL_STACK = stack_st;
#[inline]
unsafe extern "C" fn sk_X509_dup(mut sk: *const stack_st_X509) -> *mut stack_st_X509 {
    return OPENSSL_sk_dup(sk as *const OPENSSL_STACK) as *mut stack_st_X509;
}
#[inline]
unsafe extern "C" fn sk_X509_num(mut sk: *const stack_st_X509) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_value(
    mut sk: *const stack_st_X509,
    mut i: size_t,
) -> *mut X509 {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509;
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
#[inline]
unsafe extern "C" fn CRYPTO_load_u32_le(mut in_0: *const libc::c_void) -> uint32_t {
    let mut v: uint32_t = 0;
    OPENSSL_memcpy(
        &mut v as *mut uint32_t as *mut libc::c_void,
        in_0,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
    return v;
}
#[no_mangle]
pub unsafe extern "C" fn X509_issuer_name_cmp(
    mut a: *const X509,
    mut b: *const X509,
) -> libc::c_int {
    return X509_NAME_cmp((*(*a).cert_info).issuer, (*(*b).cert_info).issuer);
}
#[no_mangle]
pub unsafe extern "C" fn X509_subject_name_cmp(
    mut a: *const X509,
    mut b: *const X509,
) -> libc::c_int {
    return X509_NAME_cmp((*(*a).cert_info).subject, (*(*b).cert_info).subject);
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_cmp(
    mut a: *const X509_CRL,
    mut b: *const X509_CRL,
) -> libc::c_int {
    return X509_NAME_cmp((*(*a).crl).issuer, (*(*b).crl).issuer);
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_match(
    mut a: *const X509_CRL,
    mut b: *const X509_CRL,
) -> libc::c_int {
    return OPENSSL_memcmp(
        ((*a).crl_hash).as_ptr() as *const libc::c_void,
        ((*b).crl_hash).as_ptr() as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
}
#[no_mangle]
pub unsafe extern "C" fn X509_get_issuer_name(mut a: *const X509) -> *mut X509_NAME {
    return (*(*a).cert_info).issuer;
}
#[no_mangle]
pub unsafe extern "C" fn X509_issuer_name_hash(mut x: *mut X509) -> uint32_t {
    return X509_NAME_hash((*(*x).cert_info).issuer);
}
#[no_mangle]
pub unsafe extern "C" fn X509_issuer_name_hash_old(mut x: *mut X509) -> uint32_t {
    return X509_NAME_hash_old((*(*x).cert_info).issuer);
}
#[no_mangle]
pub unsafe extern "C" fn X509_get_subject_name(mut a: *const X509) -> *mut X509_NAME {
    return (*(*a).cert_info).subject;
}
#[no_mangle]
pub unsafe extern "C" fn X509_get_serialNumber(mut a: *mut X509) -> *mut ASN1_INTEGER {
    return (*(*a).cert_info).serialNumber;
}
#[no_mangle]
pub unsafe extern "C" fn X509_get0_serialNumber(
    mut x509: *const X509,
) -> *const ASN1_INTEGER {
    return (*(*x509).cert_info).serialNumber;
}
#[no_mangle]
pub unsafe extern "C" fn X509_subject_name_hash(mut x: *mut X509) -> uint32_t {
    return X509_NAME_hash((*(*x).cert_info).subject);
}
#[no_mangle]
pub unsafe extern "C" fn X509_subject_name_hash_old(mut x: *mut X509) -> uint32_t {
    return X509_NAME_hash_old((*(*x).cert_info).subject);
}
#[no_mangle]
pub unsafe extern "C" fn X509_cmp(
    mut a: *const X509,
    mut b: *const X509,
) -> libc::c_int {
    x509v3_cache_extensions(a as *mut X509);
    x509v3_cache_extensions(b as *mut X509);
    return OPENSSL_memcmp(
        ((*a).cert_hash).as_ptr() as *const libc::c_void,
        ((*b).cert_hash).as_ptr() as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_cmp(
    mut a: *const X509_NAME,
    mut b: *const X509_NAME,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    if ((*a).canon_enc).is_null() || (*a).modified != 0 {
        ret = i2d_X509_NAME(a as *mut X509_NAME, 0 as *mut *mut uint8_t);
        if ret < 0 as libc::c_int {
            return -(2 as libc::c_int);
        }
    }
    if ((*b).canon_enc).is_null() || (*b).modified != 0 {
        ret = i2d_X509_NAME(b as *mut X509_NAME, 0 as *mut *mut uint8_t);
        if ret < 0 as libc::c_int {
            return -(2 as libc::c_int);
        }
    }
    ret = (*a).canon_enclen - (*b).canon_enclen;
    if ret != 0 {
        return ret;
    }
    return OPENSSL_memcmp(
        (*a).canon_enc as *const libc::c_void,
        (*b).canon_enc as *const libc::c_void,
        (*a).canon_enclen as size_t,
    );
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_hash(mut x: *mut X509_NAME) -> uint32_t {
    if i2d_X509_NAME(x, 0 as *mut *mut uint8_t) < 0 as libc::c_int {
        return 0 as libc::c_int as uint32_t;
    }
    let mut md: [uint8_t; 20] = [0; 20];
    SHA1((*x).canon_enc, (*x).canon_enclen as size_t, md.as_mut_ptr());
    return CRYPTO_load_u32_le(md.as_mut_ptr() as *const libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_hash_old(mut x: *mut X509_NAME) -> uint32_t {
    if i2d_X509_NAME(x, 0 as *mut *mut uint8_t) < 0 as libc::c_int {
        return 0 as libc::c_int as uint32_t;
    }
    let mut md: [uint8_t; 20] = [0; 20];
    MD5((*(*x).bytes).data as *const uint8_t, (*(*x).bytes).length, md.as_mut_ptr());
    return CRYPTO_load_u32_le(md.as_mut_ptr() as *const libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn X509_find_by_issuer_and_serial(
    mut sk: *const stack_st_X509,
    mut name: *mut X509_NAME,
    mut serial: *const ASN1_INTEGER,
) -> *mut X509 {
    if (*serial).type_0 != 2 as libc::c_int
        && (*serial).type_0 != 2 as libc::c_int | 0x100 as libc::c_int
    {
        return 0 as *mut X509;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_X509_num(sk) {
        let mut x509: *mut X509 = sk_X509_value(sk, i);
        if ASN1_INTEGER_cmp(X509_get0_serialNumber(x509), serial) == 0 as libc::c_int
            && X509_NAME_cmp(X509_get_issuer_name(x509), name) == 0 as libc::c_int
        {
            return x509;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as *mut X509;
}
#[no_mangle]
pub unsafe extern "C" fn X509_find_by_subject(
    mut sk: *const stack_st_X509,
    mut name: *mut X509_NAME,
) -> *mut X509 {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_X509_num(sk) {
        let mut x509: *mut X509 = sk_X509_value(sk, i);
        if X509_NAME_cmp(X509_get_subject_name(x509), name) == 0 as libc::c_int {
            return x509;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as *mut X509;
}
#[no_mangle]
pub unsafe extern "C" fn X509_get0_pubkey(mut x: *const X509) -> *mut EVP_PKEY {
    if x.is_null() {
        return 0 as *mut EVP_PKEY;
    }
    return X509_PUBKEY_get0((*(*x).cert_info).key);
}
#[no_mangle]
pub unsafe extern "C" fn X509_get_pubkey(mut x: *const X509) -> *mut EVP_PKEY {
    if x.is_null() {
        return 0 as *mut EVP_PKEY;
    }
    return X509_PUBKEY_get((*(*x).cert_info).key);
}
#[no_mangle]
pub unsafe extern "C" fn X509_get0_pubkey_bitstr(
    mut x: *const X509,
) -> *mut ASN1_BIT_STRING {
    if x.is_null() {
        return 0 as *mut ASN1_BIT_STRING;
    }
    return (*(*(*x).cert_info).key).public_key;
}
#[no_mangle]
pub unsafe extern "C" fn X509_check_private_key(
    mut x: *const X509,
    mut k: *const EVP_PKEY,
) -> libc::c_int {
    let mut xk: *const EVP_PKEY = X509_get0_pubkey(x);
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
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_cmp.c\0"
                    as *const u8 as *const libc::c_char,
                255 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        -1 => {
            ERR_put_error(
                11 as libc::c_int,
                0 as libc::c_int,
                115 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_cmp.c\0"
                    as *const u8 as *const libc::c_char,
                258 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        -2 => {
            ERR_put_error(
                11 as libc::c_int,
                0 as libc::c_int,
                128 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_cmp.c\0"
                    as *const u8 as *const libc::c_char,
                261 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        _ => {}
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_chain_up_ref(
    mut chain: *mut stack_st_X509,
) -> *mut stack_st_X509 {
    let mut ret: *mut stack_st_X509 = sk_X509_dup(chain);
    if ret.is_null() {
        return 0 as *mut stack_st_X509;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_X509_num(ret) {
        X509_up_ref(sk_X509_value(ret, i));
        i = i.wrapping_add(1);
        i;
    }
    return ret;
}
