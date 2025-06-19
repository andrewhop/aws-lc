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
    pub type crypto_buffer_st;
    pub type stack_st_DIST_POINT;
    pub type stack_st_void;
    pub type env_md_st;
    pub type stack_st;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn ASN1_OCTET_STRING_cmp(
        a: *const ASN1_OCTET_STRING,
        b: *const ASN1_OCTET_STRING,
    ) -> libc::c_int;
    fn ASN1_BIT_STRING_free(str: *mut ASN1_BIT_STRING);
    fn ASN1_INTEGER_cmp(x: *const ASN1_INTEGER, y: *const ASN1_INTEGER) -> libc::c_int;
    fn ASN1_OBJECT_free(a: *mut ASN1_OBJECT);
    fn ASN1_INTEGER_get(a: *const ASN1_INTEGER) -> libc::c_long;
    fn X509_get_version(x509: *const X509) -> libc::c_long;
    fn X509_get_issuer_name(x509: *const X509) -> *mut X509_NAME;
    fn X509_get_subject_name(x509: *const X509) -> *mut X509_NAME;
    fn X509_get_ext_count(x: *const X509) -> libc::c_int;
    fn X509_get_ext_by_NID(
        x: *const X509,
        nid: libc::c_int,
        lastpos: libc::c_int,
    ) -> libc::c_int;
    fn X509_get_ext(x: *const X509, loc: libc::c_int) -> *mut X509_EXTENSION;
    fn X509_get_ext_d2i(
        x509: *const X509,
        nid: libc::c_int,
        out_critical: *mut libc::c_int,
        out_idx: *mut libc::c_int,
    ) -> *mut libc::c_void;
    fn X509_NAME_cmp(a: *const X509_NAME, b: *const X509_NAME) -> libc::c_int;
    fn X509_EXTENSION_get_object(ex: *const X509_EXTENSION) -> *mut ASN1_OBJECT;
    fn X509_EXTENSION_get_critical(ex: *const X509_EXTENSION) -> libc::c_int;
    fn X509_digest(
        x509: *const X509,
        md: *const EVP_MD,
        out: *mut uint8_t,
        out_len: *mut libc::c_uint,
    ) -> libc::c_int;
    fn X509_get_serialNumber(x509: *mut X509) -> *mut ASN1_INTEGER;
    fn BASIC_CONSTRAINTS_free(bcons: *mut BASIC_CONSTRAINTS);
    fn x509_init_signature_info(x509: *mut X509) -> libc::c_int;
    fn DIST_POINT_set_dpname(
        dpn: *mut DIST_POINT_NAME,
        iname: *mut X509_NAME,
    ) -> libc::c_int;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_pop_free_ex(
        sk: *mut OPENSSL_STACK,
        call_free_func: OPENSSL_sk_call_free_func,
        free_func: OPENSSL_sk_free_func,
    );
    fn EVP_sha256() -> *const EVP_MD;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OBJ_obj2nid(obj: *const ASN1_OBJECT) -> libc::c_int;
    fn CRYPTO_MUTEX_lock_read(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_lock_write(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_unlock_read(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_unlock_write(lock: *mut CRYPTO_MUTEX);
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct BASIC_CONSTRAINTS_st {
    pub ca: ASN1_BOOLEAN,
    pub pathlen: *mut ASN1_INTEGER,
}
pub type BASIC_CONSTRAINTS = BASIC_CONSTRAINTS_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct DIST_POINT_st {
    pub distpoint: *mut DIST_POINT_NAME,
    pub reasons: *mut ASN1_BIT_STRING,
    pub CRLissuer: *mut GENERAL_NAMES,
}
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
pub type DIST_POINT = DIST_POINT_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct GENERAL_NAME_st {
    pub type_0: libc::c_int,
    pub d: C2RustUnnamed_1,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_1 {
    pub ptr: *mut libc::c_char,
    pub otherName: *mut OTHERNAME,
    pub rfc822Name: *mut ASN1_IA5STRING,
    pub dNSName: *mut ASN1_IA5STRING,
    pub x400Address: *mut ASN1_STRING,
    pub directoryName: *mut X509_NAME,
    pub ediPartyName: *mut EDIPARTYNAME,
    pub uniformResourceIdentifier: *mut ASN1_IA5STRING,
    pub iPAddress: *mut ASN1_OCTET_STRING,
    pub registeredID: *mut ASN1_OBJECT,
    pub ip: *mut ASN1_OCTET_STRING,
    pub dirn: *mut X509_NAME,
    pub ia5: *mut ASN1_IA5STRING,
    pub rid: *mut ASN1_OBJECT,
}
pub type EDIPARTYNAME = EDIPartyName_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EDIPartyName_st {
    pub nameAssigner: *mut ASN1_STRING,
    pub partyName: *mut ASN1_STRING,
}
pub type OTHERNAME = otherName_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct otherName_st {
    pub type_id: *mut ASN1_OBJECT,
    pub value: *mut ASN1_TYPE,
}
pub type GENERAL_NAME = GENERAL_NAME_st;
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
pub type EVP_MD = env_md_st;
pub type OPENSSL_sk_free_func = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type OPENSSL_sk_call_free_func = Option::<
    unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
>;
pub type OPENSSL_STACK = stack_st;
pub type sk_ASN1_OBJECT_free_func = Option::<
    unsafe extern "C" fn(*mut ASN1_OBJECT) -> (),
>;
pub type EXTENDED_KEY_USAGE = stack_st_ASN1_OBJECT;
pub type X509_PURPOSE = x509_purpose_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_purpose_st {
    pub purpose: libc::c_int,
    pub trust: libc::c_int,
    pub flags: libc::c_int,
    pub check_purpose: Option::<
        unsafe extern "C" fn(
            *const x509_purpose_st,
            *const X509,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub name: *mut libc::c_char,
    pub sname: *mut libc::c_char,
    pub usr_data: *mut libc::c_void,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_177_error_is_indices_must_fit_in_int {
    #[bitfield(
        name = "static_assertion_at_line_177_error_is_indices_must_fit_in_int",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_177_error_is_indices_must_fit_in_int: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<OPENSSL_sk_free_func, sk_ASN1_OBJECT_free_func>(free_func))
        .expect("non-null function pointer")(ptr as *mut ASN1_OBJECT);
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_num(mut sk: *const stack_st_ASN1_OBJECT) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_value(
    mut sk: *const stack_st_ASN1_OBJECT,
    mut i: size_t,
) -> *mut ASN1_OBJECT {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut ASN1_OBJECT;
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_pop_free(
    mut sk: *mut stack_st_ASN1_OBJECT,
    mut free_func: sk_ASN1_OBJECT_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_ASN1_OBJECT_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_ASN1_OBJECT_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_GENERAL_NAME_value(
    mut sk: *const stack_st_GENERAL_NAME,
    mut i: size_t,
) -> *mut GENERAL_NAME {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut GENERAL_NAME;
}
#[inline]
unsafe extern "C" fn sk_GENERAL_NAME_num(
    mut sk: *const stack_st_GENERAL_NAME,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_DIST_POINT_value(
    mut sk: *const stack_st_DIST_POINT,
    mut i: size_t,
) -> *mut DIST_POINT {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut DIST_POINT;
}
#[inline]
unsafe extern "C" fn sk_DIST_POINT_num(mut sk: *const stack_st_DIST_POINT) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
static mut xstandard: [X509_PURPOSE; 9] = unsafe {
    [
        {
            let mut init = x509_purpose_st {
                purpose: 1 as libc::c_int,
                trust: 2 as libc::c_int,
                flags: 0 as libc::c_int,
                check_purpose: Some(
                    check_purpose_ssl_client
                        as unsafe extern "C" fn(
                            *const X509_PURPOSE,
                            *const X509,
                            libc::c_int,
                        ) -> libc::c_int,
                ),
                name: b"SSL client\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                sname: b"sslclient\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                usr_data: 0 as *const libc::c_void as *mut libc::c_void,
            };
            init
        },
        {
            let mut init = x509_purpose_st {
                purpose: 2 as libc::c_int,
                trust: 3 as libc::c_int,
                flags: 0 as libc::c_int,
                check_purpose: Some(
                    check_purpose_ssl_server
                        as unsafe extern "C" fn(
                            *const X509_PURPOSE,
                            *const X509,
                            libc::c_int,
                        ) -> libc::c_int,
                ),
                name: b"SSL server\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                sname: b"sslserver\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                usr_data: 0 as *const libc::c_void as *mut libc::c_void,
            };
            init
        },
        {
            let mut init = x509_purpose_st {
                purpose: 3 as libc::c_int,
                trust: 3 as libc::c_int,
                flags: 0 as libc::c_int,
                check_purpose: Some(
                    check_purpose_ns_ssl_server
                        as unsafe extern "C" fn(
                            *const X509_PURPOSE,
                            *const X509,
                            libc::c_int,
                        ) -> libc::c_int,
                ),
                name: b"Netscape SSL server\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                sname: b"nssslserver\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                usr_data: 0 as *const libc::c_void as *mut libc::c_void,
            };
            init
        },
        {
            let mut init = x509_purpose_st {
                purpose: 4 as libc::c_int,
                trust: 4 as libc::c_int,
                flags: 0 as libc::c_int,
                check_purpose: Some(
                    check_purpose_smime_sign
                        as unsafe extern "C" fn(
                            *const X509_PURPOSE,
                            *const X509,
                            libc::c_int,
                        ) -> libc::c_int,
                ),
                name: b"S/MIME signing\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                sname: b"smimesign\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                usr_data: 0 as *const libc::c_void as *mut libc::c_void,
            };
            init
        },
        {
            let mut init = x509_purpose_st {
                purpose: 5 as libc::c_int,
                trust: 4 as libc::c_int,
                flags: 0 as libc::c_int,
                check_purpose: Some(
                    check_purpose_smime_encrypt
                        as unsafe extern "C" fn(
                            *const X509_PURPOSE,
                            *const X509,
                            libc::c_int,
                        ) -> libc::c_int,
                ),
                name: b"S/MIME encryption\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                sname: b"smimeencrypt\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                usr_data: 0 as *const libc::c_void as *mut libc::c_void,
            };
            init
        },
        {
            let mut init = x509_purpose_st {
                purpose: 6 as libc::c_int,
                trust: 1 as libc::c_int,
                flags: 0 as libc::c_int,
                check_purpose: Some(
                    check_purpose_crl_sign
                        as unsafe extern "C" fn(
                            *const X509_PURPOSE,
                            *const X509,
                            libc::c_int,
                        ) -> libc::c_int,
                ),
                name: b"CRL signing\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                sname: b"crlsign\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                usr_data: 0 as *const libc::c_void as *mut libc::c_void,
            };
            init
        },
        {
            let mut init = x509_purpose_st {
                purpose: 7 as libc::c_int,
                trust: -(1 as libc::c_int),
                flags: 0 as libc::c_int,
                check_purpose: Some(
                    no_check
                        as unsafe extern "C" fn(
                            *const X509_PURPOSE,
                            *const X509,
                            libc::c_int,
                        ) -> libc::c_int,
                ),
                name: b"Any Purpose\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                sname: b"any\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                usr_data: 0 as *const libc::c_void as *mut libc::c_void,
            };
            init
        },
        {
            let mut init = x509_purpose_st {
                purpose: 8 as libc::c_int,
                trust: 1 as libc::c_int,
                flags: 0 as libc::c_int,
                check_purpose: Some(
                    ocsp_helper
                        as unsafe extern "C" fn(
                            *const X509_PURPOSE,
                            *const X509,
                            libc::c_int,
                        ) -> libc::c_int,
                ),
                name: b"OCSP helper\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                sname: b"ocsphelper\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                usr_data: 0 as *const libc::c_void as *mut libc::c_void,
            };
            init
        },
        {
            let mut init = x509_purpose_st {
                purpose: 9 as libc::c_int,
                trust: 8 as libc::c_int,
                flags: 0 as libc::c_int,
                check_purpose: Some(
                    check_purpose_timestamp_sign
                        as unsafe extern "C" fn(
                            *const X509_PURPOSE,
                            *const X509,
                            libc::c_int,
                        ) -> libc::c_int,
                ),
                name: b"Time Stamp signing\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                sname: b"timestampsign\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                usr_data: 0 as *const libc::c_void as *mut libc::c_void,
            };
            init
        },
    ]
};
#[no_mangle]
pub unsafe extern "C" fn X509_check_purpose(
    mut x: *mut X509,
    mut id: libc::c_int,
    mut ca: libc::c_int,
) -> libc::c_int {
    if x509v3_cache_extensions(x) == 0 {
        return 0 as libc::c_int;
    }
    if id == -(1 as libc::c_int) {
        return 1 as libc::c_int;
    }
    let mut idx: libc::c_int = X509_PURPOSE_get_by_id(id);
    if idx == -(1 as libc::c_int) {
        return 0 as libc::c_int;
    }
    let mut pt: *const X509_PURPOSE = X509_PURPOSE_get0(idx);
    return ((*pt).check_purpose).expect("non-null function pointer")(pt, x, ca);
}
#[no_mangle]
pub unsafe extern "C" fn X509_PURPOSE_set(
    mut p: *mut libc::c_int,
    mut purpose: libc::c_int,
) -> libc::c_int {
    if X509_PURPOSE_get_by_id(purpose) == -(1 as libc::c_int) {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            133 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_purp.c\0" as *const u8
                as *const libc::c_char,
            146 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    *p = purpose;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_PURPOSE_get_count() -> libc::c_int {
    return (::core::mem::size_of::<[X509_PURPOSE; 9]>() as libc::c_ulong)
        .wrapping_div(::core::mem::size_of::<X509_PURPOSE>() as libc::c_ulong)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_PURPOSE_get0(mut idx: libc::c_int) -> *const X509_PURPOSE {
    if idx < 0 as libc::c_int
        || idx as size_t
            >= (::core::mem::size_of::<[X509_PURPOSE; 9]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<X509_PURPOSE>() as libc::c_ulong)
    {
        return 0 as *const X509_PURPOSE;
    }
    return xstandard.as_ptr().offset(idx as isize);
}
#[no_mangle]
pub unsafe extern "C" fn X509_PURPOSE_get_by_sname(
    mut sname: *const libc::c_char,
) -> libc::c_int {
    let mut xptmp: *const X509_PURPOSE = 0 as *const X509_PURPOSE;
    let mut i: libc::c_int = 0 as libc::c_int;
    while i < X509_PURPOSE_get_count() {
        xptmp = X509_PURPOSE_get0(i);
        if strcmp((*xptmp).sname, sname) == 0 {
            return i;
        }
        i += 1;
        i;
    }
    return -(1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn X509_PURPOSE_get_by_id(
    mut purpose: libc::c_int,
) -> libc::c_int {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (::core::mem::size_of::<[X509_PURPOSE; 9]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<X509_PURPOSE>() as libc::c_ulong)
    {
        if xstandard[i as usize].purpose == purpose {
            return i as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return -(1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn X509_PURPOSE_get_id(
    mut xp: *const X509_PURPOSE,
) -> libc::c_int {
    return (*xp).purpose;
}
#[no_mangle]
pub unsafe extern "C" fn X509_PURPOSE_get0_name(
    mut xp: *const X509_PURPOSE,
) -> *mut libc::c_char {
    return (*xp).name;
}
#[no_mangle]
pub unsafe extern "C" fn X509_PURPOSE_get0_sname(
    mut xp: *const X509_PURPOSE,
) -> *mut libc::c_char {
    return (*xp).sname;
}
#[no_mangle]
pub unsafe extern "C" fn X509_PURPOSE_get_trust(
    mut xp: *const X509_PURPOSE,
) -> libc::c_int {
    return (*xp).trust;
}
#[no_mangle]
pub unsafe extern "C" fn X509_supported_extension(
    mut ex: *const X509_EXTENSION,
) -> libc::c_int {
    let mut nid: libc::c_int = OBJ_obj2nid(X509_EXTENSION_get_object(ex));
    return (nid == 71 as libc::c_int || nid == 83 as libc::c_int
        || nid == 85 as libc::c_int || nid == 87 as libc::c_int
        || nid == 89 as libc::c_int || nid == 126 as libc::c_int
        || nid == 401 as libc::c_int || nid == 666 as libc::c_int
        || nid == 747 as libc::c_int || nid == 748 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn setup_dp(mut x: *mut X509, mut dp: *mut DIST_POINT) -> libc::c_int {
    if ((*dp).distpoint).is_null() || (*(*dp).distpoint).type_0 != 1 as libc::c_int {
        return 1 as libc::c_int;
    }
    let mut iname: *mut X509_NAME = 0 as *mut X509_NAME;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_GENERAL_NAME_num((*dp).CRLissuer) {
        let mut gen: *mut GENERAL_NAME = sk_GENERAL_NAME_value((*dp).CRLissuer, i);
        if (*gen).type_0 == 4 as libc::c_int {
            iname = (*gen).d.directoryName;
            break;
        } else {
            i = i.wrapping_add(1);
            i;
        }
    }
    if iname.is_null() {
        iname = X509_get_issuer_name(x);
    }
    return DIST_POINT_set_dpname((*dp).distpoint, iname);
}
unsafe extern "C" fn setup_crldp(mut x: *mut X509) -> libc::c_int {
    let mut j: libc::c_int = 0;
    (*x)
        .crldp = X509_get_ext_d2i(x, 103 as libc::c_int, &mut j, 0 as *mut libc::c_int)
        as *mut stack_st_DIST_POINT;
    if ((*x).crldp).is_null() && j != -(1 as libc::c_int) {
        return 0 as libc::c_int;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_DIST_POINT_num((*x).crldp) {
        if setup_dp(x, sk_DIST_POINT_value((*x).crldp, i)) == 0 {
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn x509v3_cache_extensions(mut x: *mut X509) -> libc::c_int {
    let mut bs: *mut BASIC_CONSTRAINTS = 0 as *mut BASIC_CONSTRAINTS;
    let mut usage: *mut ASN1_BIT_STRING = 0 as *mut ASN1_BIT_STRING;
    let mut ns: *mut ASN1_BIT_STRING = 0 as *mut ASN1_BIT_STRING;
    let mut extusage: *mut EXTENDED_KEY_USAGE = 0 as *mut EXTENDED_KEY_USAGE;
    let mut i: size_t = 0;
    let mut j: libc::c_int = 0;
    CRYPTO_MUTEX_lock_read(&mut (*x).lock);
    let is_set: libc::c_int = ((*x).ex_flags & 0x100 as libc::c_int as uint32_t)
        as libc::c_int;
    CRYPTO_MUTEX_unlock_read(&mut (*x).lock);
    if is_set != 0 {
        return ((*x).ex_flags & 0x80 as libc::c_int as uint32_t
            == 0 as libc::c_int as uint32_t) as libc::c_int;
    }
    CRYPTO_MUTEX_lock_write(&mut (*x).lock);
    if (*x).ex_flags & 0x100 as libc::c_int as uint32_t != 0 {
        CRYPTO_MUTEX_unlock_write(&mut (*x).lock);
        return ((*x).ex_flags & 0x80 as libc::c_int as uint32_t
            == 0 as libc::c_int as uint32_t) as libc::c_int;
    }
    if X509_digest(
        x,
        EVP_sha256(),
        ((*x).cert_hash).as_mut_ptr(),
        0 as *mut libc::c_uint,
    ) == 0
    {
        (*x).ex_flags |= 0x80 as libc::c_int as uint32_t;
    }
    if X509_get_version(x) == 0 as libc::c_int as libc::c_long {
        (*x).ex_flags |= 0x40 as libc::c_int as uint32_t;
    }
    bs = X509_get_ext_d2i(x, 87 as libc::c_int, &mut j, 0 as *mut libc::c_int)
        as *mut BASIC_CONSTRAINTS;
    if !bs.is_null() {
        if (*bs).ca != 0 {
            (*x).ex_flags |= 0x10 as libc::c_int as uint32_t;
        }
        if !((*bs).pathlen).is_null() {
            if (*(*bs).pathlen).type_0 == 2 as libc::c_int | 0x100 as libc::c_int
                || (*bs).ca == 0
            {
                (*x).ex_flags |= 0x80 as libc::c_int as uint32_t;
                (*x).ex_pathlen = 0 as libc::c_int as libc::c_long;
            } else {
                (*x).ex_pathlen = ASN1_INTEGER_get((*bs).pathlen);
            }
        } else {
            (*x).ex_pathlen = -(1 as libc::c_int) as libc::c_long;
        }
        BASIC_CONSTRAINTS_free(bs);
        (*x).ex_flags |= 0x1 as libc::c_int as uint32_t;
    } else if j != -(1 as libc::c_int) {
        (*x).ex_flags |= 0x80 as libc::c_int as uint32_t;
    }
    usage = X509_get_ext_d2i(x, 83 as libc::c_int, &mut j, 0 as *mut libc::c_int)
        as *mut ASN1_BIT_STRING;
    if !usage.is_null() {
        if (*usage).length > 0 as libc::c_int {
            (*x)
                .ex_kusage = *((*usage).data).offset(0 as libc::c_int as isize)
                as uint32_t;
            if (*usage).length > 1 as libc::c_int {
                (*x).ex_kusage
                    |= ((*((*usage).data).offset(1 as libc::c_int as isize)
                        as libc::c_int) << 8 as libc::c_int) as uint32_t;
            }
        } else {
            (*x).ex_kusage = 0 as libc::c_int as uint32_t;
        }
        (*x).ex_flags |= 0x2 as libc::c_int as uint32_t;
        ASN1_BIT_STRING_free(usage);
    } else if j != -(1 as libc::c_int) {
        (*x).ex_flags |= 0x80 as libc::c_int as uint32_t;
    }
    (*x).ex_xkusage = 0 as libc::c_int as uint32_t;
    extusage = X509_get_ext_d2i(x, 126 as libc::c_int, &mut j, 0 as *mut libc::c_int)
        as *mut EXTENDED_KEY_USAGE;
    if !extusage.is_null() {
        (*x).ex_flags |= 0x4 as libc::c_int as uint32_t;
        i = 0 as libc::c_int as size_t;
        while i < sk_ASN1_OBJECT_num(extusage) {
            match OBJ_obj2nid(sk_ASN1_OBJECT_value(extusage, i)) {
                129 => {
                    (*x).ex_xkusage |= 0x1 as libc::c_int as uint32_t;
                }
                130 => {
                    (*x).ex_xkusage |= 0x2 as libc::c_int as uint32_t;
                }
                132 => {
                    (*x).ex_xkusage |= 0x4 as libc::c_int as uint32_t;
                }
                131 => {
                    (*x).ex_xkusage |= 0x8 as libc::c_int as uint32_t;
                }
                137 | 139 => {
                    (*x).ex_xkusage |= 0x10 as libc::c_int as uint32_t;
                }
                180 => {
                    (*x).ex_xkusage |= 0x20 as libc::c_int as uint32_t;
                }
                133 => {
                    (*x).ex_xkusage |= 0x40 as libc::c_int as uint32_t;
                }
                297 => {
                    (*x).ex_xkusage |= 0x80 as libc::c_int as uint32_t;
                }
                910 => {
                    (*x).ex_xkusage |= 0x100 as libc::c_int as uint32_t;
                }
                _ => {}
            }
            i = i.wrapping_add(1);
            i;
        }
        sk_ASN1_OBJECT_pop_free(
            extusage,
            Some(ASN1_OBJECT_free as unsafe extern "C" fn(*mut ASN1_OBJECT) -> ()),
        );
    } else if j != -(1 as libc::c_int) {
        (*x).ex_flags |= 0x80 as libc::c_int as uint32_t;
    }
    ns = X509_get_ext_d2i(x, 71 as libc::c_int, &mut j, 0 as *mut libc::c_int)
        as *mut ASN1_BIT_STRING;
    if !ns.is_null() {
        if (*ns).length > 0 as libc::c_int {
            (*x).ex_nscert = *((*ns).data).offset(0 as libc::c_int as isize) as uint32_t;
        } else {
            (*x).ex_nscert = 0 as libc::c_int as uint32_t;
        }
        (*x).ex_flags |= 0x8 as libc::c_int as uint32_t;
        ASN1_BIT_STRING_free(ns);
    } else if j != -(1 as libc::c_int) {
        (*x).ex_flags |= 0x80 as libc::c_int as uint32_t;
    }
    (*x)
        .skid = X509_get_ext_d2i(x, 82 as libc::c_int, &mut j, 0 as *mut libc::c_int)
        as *mut ASN1_OCTET_STRING;
    if ((*x).skid).is_null() && j != -(1 as libc::c_int) {
        (*x).ex_flags |= 0x80 as libc::c_int as uint32_t;
    }
    (*x)
        .akid = X509_get_ext_d2i(x, 90 as libc::c_int, &mut j, 0 as *mut libc::c_int)
        as *mut AUTHORITY_KEYID;
    if ((*x).akid).is_null() && j != -(1 as libc::c_int) {
        (*x).ex_flags |= 0x80 as libc::c_int as uint32_t;
    }
    if X509_NAME_cmp(X509_get_subject_name(x), X509_get_issuer_name(x)) == 0 {
        (*x).ex_flags |= 0x20 as libc::c_int as uint32_t;
        if X509_check_akid(x, (*x).akid) == 0 as libc::c_int
            && !((*x).ex_flags & 0x2 as libc::c_int as uint32_t != 0
                && (*x).ex_kusage & 0x4 as libc::c_int as uint32_t == 0)
        {
            (*x).ex_flags |= 0x2000 as libc::c_int as uint32_t;
        }
    }
    (*x)
        .altname = X509_get_ext_d2i(x, 85 as libc::c_int, &mut j, 0 as *mut libc::c_int)
        as *mut stack_st_GENERAL_NAME;
    if ((*x).altname).is_null() && j != -(1 as libc::c_int) {
        (*x).ex_flags |= 0x80 as libc::c_int as uint32_t;
    }
    (*x)
        .nc = X509_get_ext_d2i(x, 666 as libc::c_int, &mut j, 0 as *mut libc::c_int)
        as *mut NAME_CONSTRAINTS;
    if ((*x).nc).is_null() && j != -(1 as libc::c_int) {
        (*x).ex_flags |= 0x80 as libc::c_int as uint32_t;
    }
    if setup_crldp(x) == 0 {
        (*x).ex_flags |= 0x80 as libc::c_int as uint32_t;
    }
    j = 0 as libc::c_int;
    while j < X509_get_ext_count(x) {
        let mut ex: *const X509_EXTENSION = X509_get_ext(x, j);
        if !(X509_EXTENSION_get_critical(ex) == 0) {
            if X509_supported_extension(ex) == 0 {
                (*x).ex_flags |= 0x200 as libc::c_int as uint32_t;
                break;
            }
        }
        j += 1;
        j;
    }
    x509_init_signature_info(x);
    (*x).ex_flags |= 0x100 as libc::c_int as uint32_t;
    CRYPTO_MUTEX_unlock_write(&mut (*x).lock);
    return ((*x).ex_flags & 0x80 as libc::c_int as uint32_t
        == 0 as libc::c_int as uint32_t) as libc::c_int;
}
unsafe extern "C" fn check_ca(mut x: *const X509) -> libc::c_int {
    if (*x).ex_flags & 0x2 as libc::c_int as uint32_t != 0
        && (*x).ex_kusage & 0x4 as libc::c_int as uint32_t == 0
    {
        return 0 as libc::c_int;
    }
    if (*x).ex_flags & (0x40 as libc::c_int | 0x2000 as libc::c_int) as uint32_t
        == (0x40 as libc::c_int | 0x2000 as libc::c_int) as uint32_t
    {
        return 1 as libc::c_int;
    }
    return ((*x).ex_flags & 0x1 as libc::c_int as uint32_t != 0
        && (*x).ex_flags & 0x10 as libc::c_int as uint32_t != 0) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_check_ca(mut x: *mut X509) -> libc::c_int {
    if x509v3_cache_extensions(x) == 0 {
        return 0 as libc::c_int;
    }
    return check_ca(x);
}
unsafe extern "C" fn check_purpose_ssl_client(
    mut xp: *const X509_PURPOSE,
    mut x: *const X509,
    mut ca: libc::c_int,
) -> libc::c_int {
    if (*x).ex_flags & 0x4 as libc::c_int as uint32_t != 0
        && (*x).ex_xkusage & 0x2 as libc::c_int as uint32_t == 0
    {
        return 0 as libc::c_int;
    }
    if ca != 0 {
        return check_ca(x);
    }
    if (*x).ex_flags & 0x2 as libc::c_int as uint32_t != 0
        && (*x).ex_kusage & (0x80 as libc::c_int | 0x8 as libc::c_int) as uint32_t == 0
    {
        return 0 as libc::c_int;
    }
    if (*x).ex_flags & 0x8 as libc::c_int as uint32_t != 0
        && (*x).ex_nscert & 0x80 as libc::c_int as uint32_t == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn check_purpose_ssl_server(
    mut xp: *const X509_PURPOSE,
    mut x: *const X509,
    mut ca: libc::c_int,
) -> libc::c_int {
    if (*x).ex_flags & 0x4 as libc::c_int as uint32_t != 0
        && (*x).ex_xkusage & 0x1 as libc::c_int as uint32_t == 0
    {
        return 0 as libc::c_int;
    }
    if ca != 0 {
        return check_ca(x);
    }
    if (*x).ex_flags & 0x8 as libc::c_int as uint32_t != 0
        && (*x).ex_nscert & 0x40 as libc::c_int as uint32_t == 0
    {
        return 0 as libc::c_int;
    }
    if (*x).ex_flags & 0x2 as libc::c_int as uint32_t != 0
        && (*x).ex_kusage
            & (0x80 as libc::c_int | 0x20 as libc::c_int | 0x8 as libc::c_int)
                as uint32_t == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn check_purpose_ns_ssl_server(
    mut xp: *const X509_PURPOSE,
    mut x: *const X509,
    mut ca: libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = check_purpose_ssl_server(xp, x, ca);
    if ret == 0 || ca != 0 {
        return ret;
    }
    if (*x).ex_flags & 0x2 as libc::c_int as uint32_t != 0
        && (*x).ex_kusage & 0x20 as libc::c_int as uint32_t == 0
    {
        return 0 as libc::c_int;
    }
    return ret;
}
unsafe extern "C" fn purpose_smime(
    mut x: *const X509,
    mut ca: libc::c_int,
) -> libc::c_int {
    if (*x).ex_flags & 0x4 as libc::c_int as uint32_t != 0
        && (*x).ex_xkusage & 0x4 as libc::c_int as uint32_t == 0
    {
        return 0 as libc::c_int;
    }
    if ca != 0 {
        if (*x).ex_flags & 0x8 as libc::c_int as uint32_t != 0
            && (*x).ex_nscert & 0x2 as libc::c_int as uint32_t
                == 0 as libc::c_int as uint32_t
        {
            return 0 as libc::c_int;
        }
        return check_ca(x);
    }
    if (*x).ex_flags & 0x8 as libc::c_int as uint32_t != 0 {
        return ((*x).ex_nscert & 0x20 as libc::c_int as uint32_t
            == 0x20 as libc::c_int as uint32_t) as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn check_purpose_smime_sign(
    mut xp: *const X509_PURPOSE,
    mut x: *const X509,
    mut ca: libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = purpose_smime(x, ca);
    if ret == 0 || ca != 0 {
        return ret;
    }
    if (*x).ex_flags & 0x2 as libc::c_int as uint32_t != 0
        && (*x).ex_kusage & (0x80 as libc::c_int | 0x40 as libc::c_int) as uint32_t == 0
    {
        return 0 as libc::c_int;
    }
    return ret;
}
unsafe extern "C" fn check_purpose_smime_encrypt(
    mut xp: *const X509_PURPOSE,
    mut x: *const X509,
    mut ca: libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = purpose_smime(x, ca);
    if ret == 0 || ca != 0 {
        return ret;
    }
    if (*x).ex_flags & 0x2 as libc::c_int as uint32_t != 0
        && (*x).ex_kusage & 0x20 as libc::c_int as uint32_t == 0
    {
        return 0 as libc::c_int;
    }
    return ret;
}
unsafe extern "C" fn check_purpose_crl_sign(
    mut xp: *const X509_PURPOSE,
    mut x: *const X509,
    mut ca: libc::c_int,
) -> libc::c_int {
    if ca != 0 {
        return check_ca(x);
    }
    if (*x).ex_flags & 0x2 as libc::c_int as uint32_t != 0
        && (*x).ex_kusage & 0x2 as libc::c_int as uint32_t == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn ocsp_helper(
    mut xp: *const X509_PURPOSE,
    mut x: *const X509,
    mut ca: libc::c_int,
) -> libc::c_int {
    if ca != 0 {
        return check_ca(x);
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn check_purpose_timestamp_sign(
    mut xp: *const X509_PURPOSE,
    mut x: *const X509,
    mut ca: libc::c_int,
) -> libc::c_int {
    if ca != 0 {
        return check_ca(x);
    }
    if (*x).ex_flags & 0x2 as libc::c_int as uint32_t != 0
        && ((*x).ex_kusage & !(0x40 as libc::c_int | 0x80 as libc::c_int) as uint32_t
            != 0
            || (*x).ex_kusage & (0x40 as libc::c_int | 0x80 as libc::c_int) as uint32_t
                == 0)
    {
        return 0 as libc::c_int;
    }
    if (*x).ex_flags & 0x4 as libc::c_int as uint32_t == 0
        || (*x).ex_xkusage != 0x40 as libc::c_int as uint32_t
    {
        return 0 as libc::c_int;
    }
    let mut i_ext: libc::c_int = X509_get_ext_by_NID(
        x,
        126 as libc::c_int,
        -(1 as libc::c_int),
    );
    if i_ext >= 0 as libc::c_int {
        let mut ext: *const X509_EXTENSION = X509_get_ext(x, i_ext);
        if X509_EXTENSION_get_critical(ext) == 0 {
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn no_check(
    mut xp: *const X509_PURPOSE,
    mut x: *const X509,
    mut ca: libc::c_int,
) -> libc::c_int {
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_check_issued(
    mut issuer: *mut X509,
    mut subject: *mut X509,
) -> libc::c_int {
    if X509_NAME_cmp(X509_get_subject_name(issuer), X509_get_issuer_name(subject)) != 0 {
        return 29 as libc::c_int;
    }
    if x509v3_cache_extensions(issuer) == 0 || x509v3_cache_extensions(subject) == 0 {
        return 1 as libc::c_int;
    }
    if !((*subject).akid).is_null() {
        let mut ret: libc::c_int = X509_check_akid(issuer, (*subject).akid);
        if ret != 0 as libc::c_int {
            return ret;
        }
    }
    if (*issuer).ex_flags & 0x2 as libc::c_int as uint32_t != 0
        && (*issuer).ex_kusage & 0x4 as libc::c_int as uint32_t == 0
    {
        return 32 as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_check_akid(
    mut issuer: *mut X509,
    mut akid: *const AUTHORITY_KEYID,
) -> libc::c_int {
    if akid.is_null() {
        return 0 as libc::c_int;
    }
    if !((*akid).keyid).is_null() && !((*issuer).skid).is_null()
        && ASN1_OCTET_STRING_cmp((*akid).keyid, (*issuer).skid) != 0
    {
        return 30 as libc::c_int;
    }
    if !((*akid).serial).is_null()
        && ASN1_INTEGER_cmp(X509_get_serialNumber(issuer), (*akid).serial) != 0
    {
        return 31 as libc::c_int;
    }
    if !((*akid).issuer).is_null() {
        let mut gens: *mut GENERAL_NAMES = 0 as *mut GENERAL_NAMES;
        let mut gen: *mut GENERAL_NAME = 0 as *mut GENERAL_NAME;
        let mut nm: *mut X509_NAME = 0 as *mut X509_NAME;
        let mut i: size_t = 0;
        gens = (*akid).issuer;
        i = 0 as libc::c_int as size_t;
        while i < sk_GENERAL_NAME_num(gens) {
            gen = sk_GENERAL_NAME_value(gens, i);
            if (*gen).type_0 == 4 as libc::c_int {
                nm = (*gen).d.dirn;
                break;
            } else {
                i = i.wrapping_add(1);
                i;
            }
        }
        if !nm.is_null() && X509_NAME_cmp(nm, X509_get_issuer_name(issuer)) != 0 {
            return 31 as libc::c_int;
        }
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_get_extension_flags(mut x: *mut X509) -> uint32_t {
    x509v3_cache_extensions(x);
    return (*x).ex_flags;
}
#[no_mangle]
pub unsafe extern "C" fn X509_get_key_usage(mut x: *mut X509) -> uint32_t {
    if x509v3_cache_extensions(x) == 0 {
        return 0 as libc::c_int as uint32_t;
    }
    if (*x).ex_flags & 0x2 as libc::c_int as uint32_t != 0 {
        return (*x).ex_kusage;
    }
    return 4294967295 as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn X509_get_extended_key_usage(mut x: *mut X509) -> uint32_t {
    if x509v3_cache_extensions(x) == 0 {
        return 0 as libc::c_int as uint32_t;
    }
    if (*x).ex_flags & 0x4 as libc::c_int as uint32_t != 0 {
        return (*x).ex_xkusage;
    }
    return 4294967295 as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn X509_get0_subject_key_id(
    mut x509: *mut X509,
) -> *const ASN1_OCTET_STRING {
    if x509v3_cache_extensions(x509) == 0 {
        return 0 as *const ASN1_OCTET_STRING;
    }
    return (*x509).skid;
}
#[no_mangle]
pub unsafe extern "C" fn X509_get0_authority_key_id(
    mut x509: *mut X509,
) -> *const ASN1_OCTET_STRING {
    if x509v3_cache_extensions(x509) == 0 {
        return 0 as *const ASN1_OCTET_STRING;
    }
    return if !((*x509).akid).is_null() {
        (*(*x509).akid).keyid
    } else {
        0 as *mut ASN1_OCTET_STRING
    };
}
#[no_mangle]
pub unsafe extern "C" fn X509_get0_authority_issuer(
    mut x509: *mut X509,
) -> *const GENERAL_NAMES {
    if x509v3_cache_extensions(x509) == 0 {
        return 0 as *const GENERAL_NAMES;
    }
    return if !((*x509).akid).is_null() {
        (*(*x509).akid).issuer
    } else {
        0 as *mut GENERAL_NAMES
    };
}
#[no_mangle]
pub unsafe extern "C" fn X509_get0_authority_serial(
    mut x509: *mut X509,
) -> *const ASN1_INTEGER {
    if x509v3_cache_extensions(x509) == 0 {
        return 0 as *const ASN1_INTEGER;
    }
    return if !((*x509).akid).is_null() {
        (*(*x509).akid).serial
    } else {
        0 as *mut ASN1_INTEGER
    };
}
#[no_mangle]
pub unsafe extern "C" fn X509_get_pathlen(mut x509: *mut X509) -> libc::c_long {
    if x509v3_cache_extensions(x509) == 0
        || (*x509).ex_flags & 0x1 as libc::c_int as uint32_t
            == 0 as libc::c_int as uint32_t
    {
        return -(1 as libc::c_int) as libc::c_long;
    }
    return (*x509).ex_pathlen;
}
