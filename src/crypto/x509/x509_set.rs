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
    pub type stack_st_GENERAL_NAME;
    pub type stack_st_X509_NAME_ENTRY;
    pub type stack_st_GENERAL_SUBTREE;
    pub type evp_pkey_st;
    pub type stack_st_ASN1_OBJECT;
    pub type stack_st_X509_EXTENSION;
    pub type crypto_buffer_st;
    pub type stack_st_DIST_POINT;
    pub type stack_st_void;
    pub type env_md_st;
    fn ASN1_STRING_dup(str: *const ASN1_STRING) -> *mut ASN1_STRING;
    fn ASN1_INTEGER_new() -> *mut ASN1_INTEGER;
    fn ASN1_INTEGER_free(str: *mut ASN1_INTEGER);
    fn ASN1_INTEGER_dup(x: *const ASN1_INTEGER) -> *mut ASN1_INTEGER;
    fn ASN1_INTEGER_set_int64(out: *mut ASN1_INTEGER, v: int64_t) -> libc::c_int;
    fn ASN1_TIME_free(str: *mut ASN1_TIME);
    fn ASN1_INTEGER_get(a: *const ASN1_INTEGER) -> libc::c_long;
    fn X509_NAME_set(xn: *mut *mut X509_NAME, name: *mut X509_NAME) -> libc::c_int;
    fn X509_PUBKEY_set(x: *mut *mut X509_PUBKEY, pkey: *mut EVP_PKEY) -> libc::c_int;
    fn x509v3_cache_extensions(x: *mut X509) -> libc::c_int;
    fn EVP_get_digestbynid(nid: libc::c_int) -> *const EVP_MD;
    fn EVP_MD_size(md: *const EVP_MD) -> size_t;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OBJ_obj2nid(obj: *const ASN1_OBJECT) -> libc::c_int;
    fn OBJ_find_sigid_algs(
        sign_nid: libc::c_int,
        out_digest_nid: *mut libc::c_int,
        out_pkey_nid: *mut libc::c_int,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type int64_t = __int64_t;
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
pub type CRYPTO_refcount_t = uint32_t;
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
pub type EVP_MD = env_md_st;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_get_version(mut x509: *const X509) -> libc::c_long {
    if ((*(*x509).cert_info).version).is_null() {
        return 0 as libc::c_int as libc::c_long;
    }
    return ASN1_INTEGER_get((*(*x509).cert_info).version);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_set_version(
    mut x: *mut X509,
    mut version: libc::c_long,
) -> libc::c_int {
    if x.is_null() {
        return 0 as libc::c_int;
    }
    if version < 0 as libc::c_int as libc::c_long
        || version > 2 as libc::c_int as libc::c_long
    {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            140 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_set.c\0" as *const u8
                as *const libc::c_char,
            81 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if version == 0 as libc::c_int as libc::c_long {
        ASN1_INTEGER_free((*(*x).cert_info).version);
        (*(*x).cert_info).version = 0 as *mut ASN1_INTEGER;
        return 1 as libc::c_int;
    }
    if ((*(*x).cert_info).version).is_null() {
        (*(*x).cert_info).version = ASN1_INTEGER_new();
        if ((*(*x).cert_info).version).is_null() {
            return 0 as libc::c_int;
        }
    }
    return ASN1_INTEGER_set_int64((*(*x).cert_info).version, version);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_set_serialNumber(
    mut x: *mut X509,
    mut serial: *const ASN1_INTEGER,
) -> libc::c_int {
    if (*serial).type_0 != 2 as libc::c_int
        && (*serial).type_0 != 2 as libc::c_int | 0x100 as libc::c_int
    {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            191 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_set.c\0" as *const u8
                as *const libc::c_char,
            103 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut in_0: *mut ASN1_INTEGER = 0 as *mut ASN1_INTEGER;
    if x.is_null() {
        return 0 as libc::c_int;
    }
    in_0 = (*(*x).cert_info).serialNumber;
    if in_0 != serial as *mut ASN1_INTEGER {
        in_0 = ASN1_INTEGER_dup(serial);
        if !in_0.is_null() {
            ASN1_INTEGER_free((*(*x).cert_info).serialNumber);
            (*(*x).cert_info).serialNumber = in_0;
        }
    }
    return (in_0 != 0 as *mut libc::c_void as *mut ASN1_INTEGER) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_set_issuer_name(
    mut x: *mut X509,
    mut name: *mut X509_NAME,
) -> libc::c_int {
    if x.is_null() || ((*x).cert_info).is_null() {
        return 0 as libc::c_int;
    }
    return X509_NAME_set(&mut (*(*x).cert_info).issuer, name);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_set_subject_name(
    mut x: *mut X509,
    mut name: *mut X509_NAME,
) -> libc::c_int {
    if x.is_null() || ((*x).cert_info).is_null() {
        return 0 as libc::c_int;
    }
    return X509_NAME_set(&mut (*(*x).cert_info).subject, name);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_set1_notBefore(
    mut x: *mut X509,
    mut tm: *const ASN1_TIME,
) -> libc::c_int {
    let mut in_0: *mut ASN1_TIME = 0 as *mut ASN1_TIME;
    if x.is_null() || ((*(*x).cert_info).validity).is_null() {
        return 0 as libc::c_int;
    }
    in_0 = (*(*(*x).cert_info).validity).notBefore;
    if in_0 != tm as *mut ASN1_TIME {
        in_0 = ASN1_STRING_dup(tm);
        if !in_0.is_null() {
            ASN1_TIME_free((*(*(*x).cert_info).validity).notBefore);
            (*(*(*x).cert_info).validity).notBefore = in_0;
        }
    }
    return (in_0 != 0 as *mut libc::c_void as *mut ASN1_TIME) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_set_notBefore(
    mut x: *mut X509,
    mut tm: *const ASN1_TIME,
) -> libc::c_int {
    return X509_set1_notBefore(x, tm);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_get0_notBefore(mut x: *const X509) -> *const ASN1_TIME {
    return (*(*(*x).cert_info).validity).notBefore;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_getm_notBefore(mut x: *mut X509) -> *mut ASN1_TIME {
    return (*(*(*x).cert_info).validity).notBefore;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_get_notBefore(mut x509: *const X509) -> *mut ASN1_TIME {
    return (*(*(*x509).cert_info).validity).notBefore;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_set1_notAfter(
    mut x: *mut X509,
    mut tm: *const ASN1_TIME,
) -> libc::c_int {
    let mut in_0: *mut ASN1_TIME = 0 as *mut ASN1_TIME;
    if x.is_null() || ((*(*x).cert_info).validity).is_null() {
        return 0 as libc::c_int;
    }
    in_0 = (*(*(*x).cert_info).validity).notAfter;
    if in_0 != tm as *mut ASN1_TIME {
        in_0 = ASN1_STRING_dup(tm);
        if !in_0.is_null() {
            ASN1_TIME_free((*(*(*x).cert_info).validity).notAfter);
            (*(*(*x).cert_info).validity).notAfter = in_0;
        }
    }
    return (in_0 != 0 as *mut libc::c_void as *mut ASN1_TIME) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_set_notAfter(
    mut x: *mut X509,
    mut tm: *const ASN1_TIME,
) -> libc::c_int {
    return X509_set1_notAfter(x, tm);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_get0_notAfter(mut x: *const X509) -> *const ASN1_TIME {
    return (*(*(*x).cert_info).validity).notAfter;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_getm_notAfter(mut x: *mut X509) -> *mut ASN1_TIME {
    return (*(*(*x).cert_info).validity).notAfter;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_get_notAfter(mut x509: *const X509) -> *mut ASN1_TIME {
    return (*(*(*x509).cert_info).validity).notAfter;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_get0_uids(
    mut x509: *const X509,
    mut out_issuer_uid: *mut *const ASN1_BIT_STRING,
    mut out_subject_uid: *mut *const ASN1_BIT_STRING,
) {
    if !out_issuer_uid.is_null() {
        *out_issuer_uid = (*(*x509).cert_info).issuerUID;
    }
    if !out_subject_uid.is_null() {
        *out_subject_uid = (*(*x509).cert_info).subjectUID;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_set_pubkey(
    mut x: *mut X509,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    if x.is_null() || ((*x).cert_info).is_null() {
        return 0 as libc::c_int;
    }
    return X509_PUBKEY_set(&mut (*(*x).cert_info).key, pkey);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_get0_extensions(
    mut x: *const X509,
) -> *const stack_st_X509_EXTENSION {
    return (*(*x).cert_info).extensions;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_get0_tbs_sigalg(mut x: *const X509) -> *const X509_ALGOR {
    return (*(*x).cert_info).signature;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_get_X509_PUBKEY(
    mut x509: *const X509,
) -> *mut X509_PUBKEY {
    return (*(*x509).cert_info).key;
}
unsafe extern "C" fn X509_SIG_INFO_get(
    mut sig_info: *const X509_SIG_INFO,
    mut digest_nid: *mut libc::c_int,
    mut pubkey_nid: *mut libc::c_int,
    mut sec_bits: *mut libc::c_int,
    mut flags: *mut uint32_t,
) -> libc::c_int {
    if sig_info.is_null() {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_set.c\0" as *const u8
                as *const libc::c_char,
            246 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if !digest_nid.is_null() {
        *digest_nid = (*sig_info).digest_nid;
    }
    if !pubkey_nid.is_null() {
        *pubkey_nid = (*sig_info).pubkey_nid;
    }
    if !sec_bits.is_null() {
        *sec_bits = (*sig_info).sec_bits;
    }
    if !flags.is_null() {
        *flags = (*sig_info).flags;
    }
    return ((*sig_info).flags & 0x1 as libc::c_int as uint32_t
        != 0 as libc::c_int as uint32_t) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_get_signature_info(
    mut x509: *mut X509,
    mut digest_nid: *mut libc::c_int,
    mut pubkey_nid: *mut libc::c_int,
    mut sec_bits: *mut libc::c_int,
    mut flags: *mut uint32_t,
) -> libc::c_int {
    if x509.is_null() {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_set.c\0" as *const u8
                as *const libc::c_char,
            268 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    x509v3_cache_extensions(x509);
    return X509_SIG_INFO_get(
        &mut (*x509).sig_info,
        digest_nid,
        pubkey_nid,
        sec_bits,
        flags,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn x509_init_signature_info(mut x509: *mut X509) -> libc::c_int {
    let mut pubkey_nid: libc::c_int = 0;
    let mut digest_nid: libc::c_int = 0;
    let mut md: *const EVP_MD = 0 as *const EVP_MD;
    (*x509).sig_info.digest_nid = 0 as libc::c_int;
    (*x509).sig_info.pubkey_nid = 0 as libc::c_int;
    (*x509).sig_info.sec_bits = -(1 as libc::c_int);
    (*x509).sig_info.flags = 0 as libc::c_int as uint32_t;
    if OBJ_find_sigid_algs(
        OBJ_obj2nid((*(*x509).sig_alg).algorithm),
        &mut digest_nid,
        &mut pubkey_nid,
    ) == 0 || pubkey_nid == 0 as libc::c_int
    {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            145 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_set.c\0" as *const u8
                as *const libc::c_char,
            291 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*x509).sig_info.pubkey_nid = pubkey_nid;
    (*x509).sig_info.digest_nid = digest_nid;
    (*x509).sig_info.flags |= 0x1 as libc::c_int as uint32_t;
    md = EVP_get_digestbynid(digest_nid);
    if md.is_null() {
        return 1 as libc::c_int;
    }
    (*x509).sig_info.sec_bits = EVP_MD_size(md) as libc::c_int * 4 as libc::c_int;
    match digest_nid {
        64 | 672 | 673 | 674 => {
            (*x509).sig_info.flags |= 0x2 as libc::c_int as uint32_t;
        }
        _ => {}
    }
    return 1 as libc::c_int;
}
