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
    pub type stack_st_X509_ATTRIBUTE;
    pub type lhash_st_CONF_VALUE;
    pub type stack_st_CONF_VALUE;
    pub type stack_st;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn ASN1_OCTET_STRING_free(str: *mut ASN1_OCTET_STRING);
    fn ASN1_INTEGER_free(str: *mut ASN1_INTEGER);
    fn ASN1_INTEGER_dup(x: *const ASN1_INTEGER) -> *mut ASN1_INTEGER;
    fn X509_get0_serialNumber(x509: *const X509) -> *const ASN1_INTEGER;
    fn X509_get_issuer_name(x509: *const X509) -> *mut X509_NAME;
    fn X509_get_ext_by_NID(
        x: *const X509,
        nid: libc::c_int,
        lastpos: libc::c_int,
    ) -> libc::c_int;
    fn X509_get_ext(x: *const X509, loc: libc::c_int) -> *mut X509_EXTENSION;
    fn X509_NAME_free(name: *mut X509_NAME);
    fn X509_NAME_dup(name: *mut X509_NAME) -> *mut X509_NAME;
    fn X509V3_EXT_d2i(ext: *const X509_EXTENSION) -> *mut libc::c_void;
    fn GENERAL_NAME_new() -> *mut GENERAL_NAME;
    fn X509V3_conf_free(val: *mut CONF_VALUE);
    fn i2v_GENERAL_NAMES(
        method: *const X509V3_EXT_METHOD,
        gen: *const GENERAL_NAMES,
        extlist: *mut stack_st_CONF_VALUE,
    ) -> *mut stack_st_CONF_VALUE;
    static AUTHORITY_KEYID_it: ASN1_ITEM;
    fn AUTHORITY_KEYID_new() -> *mut AUTHORITY_KEYID;
    fn x509v3_bytes_to_hex(in_0: *const uint8_t, len: size_t) -> *mut libc::c_char;
    fn X509V3_add_value(
        name: *const libc::c_char,
        value: *const libc::c_char,
        extlist: *mut *mut stack_st_CONF_VALUE,
    ) -> libc::c_int;
    fn X509V3_add_value_int(
        name: *const libc::c_char,
        aint: *const ASN1_INTEGER,
        extlist: *mut *mut stack_st_CONF_VALUE,
    ) -> libc::c_int;
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_pop_free_ex(
        sk: *mut OPENSSL_STACK,
        call_free_func: OPENSSL_sk_call_free_func,
        free_func: OPENSSL_sk_free_func,
    );
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn ERR_add_error_data(count: libc::c_uint, _: ...);
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
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
pub type BIO_METHOD = bio_method_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct conf_st {
    pub data: *mut lhash_st_CONF_VALUE,
}
pub type CONF = conf_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct conf_value_st {
    pub section: *mut libc::c_char,
    pub name: *mut libc::c_char,
    pub value: *mut libc::c_char,
}
pub type CONF_VALUE = conf_value_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct v3_ext_ctx {
    pub flags: libc::c_int,
    pub issuer_cert: *const X509,
    pub subject_cert: *const X509,
    pub subject_req: *const X509_REQ,
    pub crl: *const X509_CRL,
    pub db: *const CONF,
}
pub type X509V3_CTX = v3_ext_ctx;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct v3_ext_method {
    pub ext_nid: libc::c_int,
    pub ext_flags: libc::c_int,
    pub it: *const ASN1_ITEM_EXP,
    pub ext_new: X509V3_EXT_NEW,
    pub ext_free: X509V3_EXT_FREE,
    pub d2i: X509V3_EXT_D2I,
    pub i2d: X509V3_EXT_I2D,
    pub i2s: X509V3_EXT_I2S,
    pub s2i: X509V3_EXT_S2I,
    pub i2v: X509V3_EXT_I2V,
    pub v2i: X509V3_EXT_V2I,
    pub i2r: X509V3_EXT_I2R,
    pub r2i: X509V3_EXT_R2I,
    pub usr_data: *mut libc::c_void,
}
pub type X509V3_EXT_R2I = Option::<
    unsafe extern "C" fn(
        *const X509V3_EXT_METHOD,
        *const X509V3_CTX,
        *const libc::c_char,
    ) -> *mut libc::c_void,
>;
pub type X509V3_EXT_METHOD = v3_ext_method;
pub type X509V3_EXT_I2R = Option::<
    unsafe extern "C" fn(
        *const X509V3_EXT_METHOD,
        *mut libc::c_void,
        *mut BIO,
        libc::c_int,
    ) -> libc::c_int,
>;
pub type X509V3_EXT_V2I = Option::<
    unsafe extern "C" fn(
        *const X509V3_EXT_METHOD,
        *const X509V3_CTX,
        *const stack_st_CONF_VALUE,
    ) -> *mut libc::c_void,
>;
pub type X509V3_EXT_I2V = Option::<
    unsafe extern "C" fn(
        *const X509V3_EXT_METHOD,
        *mut libc::c_void,
        *mut stack_st_CONF_VALUE,
    ) -> *mut stack_st_CONF_VALUE,
>;
pub type X509V3_EXT_S2I = Option::<
    unsafe extern "C" fn(
        *const X509V3_EXT_METHOD,
        *const X509V3_CTX,
        *const libc::c_char,
    ) -> *mut libc::c_void,
>;
pub type X509V3_EXT_I2S = Option::<
    unsafe extern "C" fn(
        *const X509V3_EXT_METHOD,
        *mut libc::c_void,
    ) -> *mut libc::c_char,
>;
pub type X509V3_EXT_I2D = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *mut *mut uint8_t) -> libc::c_int,
>;
pub type X509V3_EXT_D2I = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *mut *const uint8_t,
        libc::c_long,
    ) -> *mut libc::c_void,
>;
pub type X509V3_EXT_FREE = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type X509V3_EXT_NEW = Option::<unsafe extern "C" fn() -> *mut libc::c_void>;
pub type OPENSSL_sk_free_func = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type OPENSSL_sk_call_free_func = Option::<
    unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
>;
pub type OPENSSL_STACK = stack_st;
pub type sk_CONF_VALUE_free_func = Option::<unsafe extern "C" fn(*mut CONF_VALUE) -> ()>;
#[inline]
unsafe extern "C" fn sk_GENERAL_NAME_push(
    mut sk: *mut stack_st_GENERAL_NAME,
    mut p: *mut GENERAL_NAME,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_GENERAL_NAME_new_null() -> *mut stack_st_GENERAL_NAME {
    return OPENSSL_sk_new_null() as *mut stack_st_GENERAL_NAME;
}
#[inline]
unsafe extern "C" fn sk_CONF_VALUE_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<OPENSSL_sk_free_func, sk_CONF_VALUE_free_func>(free_func))
        .expect("non-null function pointer")(ptr as *mut CONF_VALUE);
}
#[inline]
unsafe extern "C" fn sk_CONF_VALUE_num(mut sk: *const stack_st_CONF_VALUE) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_CONF_VALUE_value(
    mut sk: *const stack_st_CONF_VALUE,
    mut i: size_t,
) -> *mut CONF_VALUE {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut CONF_VALUE;
}
#[inline]
unsafe extern "C" fn sk_CONF_VALUE_pop_free(
    mut sk: *mut stack_st_CONF_VALUE,
    mut free_func: sk_CONF_VALUE_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_CONF_VALUE_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_CONF_VALUE_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[no_mangle]
pub static mut v3_akey_id: X509V3_EXT_METHOD = unsafe {
    {
        let mut init = v3_ext_method {
            ext_nid: 90 as libc::c_int,
            ext_flags: 0x4 as libc::c_int,
            it: &AUTHORITY_KEYID_it as *const ASN1_ITEM,
            ext_new: None,
            ext_free: None,
            d2i: None,
            i2d: None,
            i2s: None,
            s2i: None,
            i2v: Some(
                i2v_AUTHORITY_KEYID
                    as unsafe extern "C" fn(
                        *const X509V3_EXT_METHOD,
                        *mut libc::c_void,
                        *mut stack_st_CONF_VALUE,
                    ) -> *mut stack_st_CONF_VALUE,
            ),
            v2i: Some(
                v2i_AUTHORITY_KEYID
                    as unsafe extern "C" fn(
                        *const X509V3_EXT_METHOD,
                        *const X509V3_CTX,
                        *const stack_st_CONF_VALUE,
                    ) -> *mut libc::c_void,
            ),
            i2r: None,
            r2i: None,
            usr_data: 0 as *const libc::c_void as *mut libc::c_void,
        };
        init
    }
};
unsafe extern "C" fn i2v_AUTHORITY_KEYID(
    mut method: *const X509V3_EXT_METHOD,
    mut ext: *mut libc::c_void,
    mut extlist: *mut stack_st_CONF_VALUE,
) -> *mut stack_st_CONF_VALUE {
    let mut current_block: u64;
    let mut akeyid: *const AUTHORITY_KEYID = ext as *const AUTHORITY_KEYID;
    let mut extlist_was_null: libc::c_int = (extlist
        == 0 as *mut libc::c_void as *mut stack_st_CONF_VALUE) as libc::c_int;
    if !((*akeyid).keyid).is_null() {
        let mut tmp: *mut libc::c_char = x509v3_bytes_to_hex(
            (*(*akeyid).keyid).data,
            (*(*akeyid).keyid).length as size_t,
        );
        let mut ok: libc::c_int = (!tmp.is_null()
            && X509V3_add_value(
                b"keyid\0" as *const u8 as *const libc::c_char,
                tmp,
                &mut extlist,
            ) != 0) as libc::c_int;
        OPENSSL_free(tmp as *mut libc::c_void);
        if ok == 0 {
            current_block = 5460280372479148914;
        } else {
            current_block = 7502529970979898288;
        }
    } else {
        current_block = 7502529970979898288;
    }
    match current_block {
        7502529970979898288 => {
            if !((*akeyid).issuer).is_null() {
                let mut tmpextlist: *mut stack_st_CONF_VALUE = i2v_GENERAL_NAMES(
                    0 as *const X509V3_EXT_METHOD,
                    (*akeyid).issuer,
                    extlist,
                );
                if tmpextlist.is_null() {
                    current_block = 5460280372479148914;
                } else {
                    extlist = tmpextlist;
                    current_block = 8515828400728868193;
                }
            } else {
                current_block = 8515828400728868193;
            }
            match current_block {
                5460280372479148914 => {}
                _ => {
                    if !((*akeyid).serial).is_null() {
                        if X509V3_add_value_int(
                            b"serial\0" as *const u8 as *const libc::c_char,
                            (*akeyid).serial,
                            &mut extlist,
                        ) == 0
                        {
                            current_block = 5460280372479148914;
                        } else {
                            current_block = 7746791466490516765;
                        }
                    } else {
                        current_block = 7746791466490516765;
                    }
                    match current_block {
                        5460280372479148914 => {}
                        _ => return extlist,
                    }
                }
            }
        }
        _ => {}
    }
    if extlist_was_null != 0 {
        sk_CONF_VALUE_pop_free(
            extlist,
            Some(X509V3_conf_free as unsafe extern "C" fn(*mut CONF_VALUE) -> ()),
        );
    }
    return 0 as *mut stack_st_CONF_VALUE;
}
unsafe extern "C" fn v2i_AUTHORITY_KEYID(
    mut method: *const X509V3_EXT_METHOD,
    mut ctx: *const X509V3_CTX,
    mut values: *const stack_st_CONF_VALUE,
) -> *mut libc::c_void {
    let mut current_block: u64;
    let mut keyid: libc::c_char = 0 as libc::c_int as libc::c_char;
    let mut issuer: libc::c_char = 0 as libc::c_int as libc::c_char;
    let mut j: libc::c_int = 0;
    let mut ikeyid: *mut ASN1_OCTET_STRING = 0 as *mut ASN1_OCTET_STRING;
    let mut isname: *mut X509_NAME = 0 as *mut X509_NAME;
    let mut gens: *mut GENERAL_NAMES = 0 as *mut GENERAL_NAMES;
    let mut gen: *mut GENERAL_NAME = 0 as *mut GENERAL_NAME;
    let mut serial: *mut ASN1_INTEGER = 0 as *mut ASN1_INTEGER;
    let mut cert: *const X509 = 0 as *const X509;
    let mut akeyid: *mut AUTHORITY_KEYID = 0 as *mut AUTHORITY_KEYID;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_CONF_VALUE_num(values) {
        let mut cnf: *const CONF_VALUE = sk_CONF_VALUE_value(values, i);
        if strcmp((*cnf).name, b"keyid\0" as *const u8 as *const libc::c_char) == 0 {
            keyid = 1 as libc::c_int as libc::c_char;
            if !((*cnf).value).is_null()
                && strcmp((*cnf).value, b"always\0" as *const u8 as *const libc::c_char)
                    == 0
            {
                keyid = 2 as libc::c_int as libc::c_char;
            }
        } else if strcmp((*cnf).name, b"issuer\0" as *const u8 as *const libc::c_char)
            == 0
        {
            issuer = 1 as libc::c_int as libc::c_char;
            if !((*cnf).value).is_null()
                && strcmp((*cnf).value, b"always\0" as *const u8 as *const libc::c_char)
                    == 0
            {
                issuer = 2 as libc::c_int as libc::c_char;
            }
        } else {
            ERR_put_error(
                20 as libc::c_int,
                0 as libc::c_int,
                159 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_akey.c\0" as *const u8
                    as *const libc::c_char,
                160 as libc::c_int as libc::c_uint,
            );
            ERR_add_error_data(
                2 as libc::c_int as libc::c_uint,
                b"name=\0" as *const u8 as *const libc::c_char,
                (*cnf).name,
            );
            return 0 as *mut libc::c_void;
        }
        i = i.wrapping_add(1);
        i;
    }
    if ctx.is_null() || ((*ctx).issuer_cert).is_null() {
        if !ctx.is_null() && (*ctx).flags == 0x1 as libc::c_int {
            return AUTHORITY_KEYID_new() as *mut libc::c_void;
        }
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            140 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_akey.c\0" as *const u8
                as *const libc::c_char,
            170 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut libc::c_void;
    }
    cert = (*ctx).issuer_cert;
    if keyid != 0 {
        j = X509_get_ext_by_NID(cert, 82 as libc::c_int, -(1 as libc::c_int));
        let mut ext: *const X509_EXTENSION = 0 as *const X509_EXTENSION;
        if j >= 0 as libc::c_int
            && {
                ext = X509_get_ext(cert, j);
                !ext.is_null()
            }
        {
            ikeyid = X509V3_EXT_d2i(ext) as *mut ASN1_OCTET_STRING;
        }
        if keyid as libc::c_int == 2 as libc::c_int && ikeyid.is_null() {
            ERR_put_error(
                20 as libc::c_int,
                0 as libc::c_int,
                155 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_akey.c\0" as *const u8
                    as *const libc::c_char,
                183 as libc::c_int as libc::c_uint,
            );
            return 0 as *mut libc::c_void;
        }
    }
    if issuer as libc::c_int != 0 && ikeyid.is_null()
        || issuer as libc::c_int == 2 as libc::c_int
    {
        isname = X509_NAME_dup(X509_get_issuer_name(cert));
        serial = ASN1_INTEGER_dup(X509_get0_serialNumber(cert));
        if isname.is_null() || serial.is_null() {
            ERR_put_error(
                20 as libc::c_int,
                0 as libc::c_int,
                154 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_akey.c\0" as *const u8
                    as *const libc::c_char,
                192 as libc::c_int as libc::c_uint,
            );
            current_block = 2014313839112821172;
        } else {
            current_block = 1836292691772056875;
        }
    } else {
        current_block = 1836292691772056875;
    }
    match current_block {
        1836292691772056875 => {
            akeyid = AUTHORITY_KEYID_new();
            if !akeyid.is_null() {
                if !isname.is_null() {
                    gens = sk_GENERAL_NAME_new_null();
                    if gens.is_null()
                        || {
                            gen = GENERAL_NAME_new();
                            gen.is_null()
                        } || sk_GENERAL_NAME_push(gens, gen) == 0
                    {
                        current_block = 2014313839112821172;
                    } else {
                        (*gen).type_0 = 4 as libc::c_int;
                        (*gen).d.dirn = isname;
                        current_block = 12199444798915819164;
                    }
                } else {
                    current_block = 12199444798915819164;
                }
                match current_block {
                    2014313839112821172 => {}
                    _ => {
                        (*akeyid).issuer = gens;
                        (*akeyid).serial = serial;
                        (*akeyid).keyid = ikeyid;
                        return akeyid as *mut libc::c_void;
                    }
                }
            }
        }
        _ => {}
    }
    X509_NAME_free(isname);
    ASN1_INTEGER_free(serial);
    ASN1_OCTET_STRING_free(ikeyid);
    return 0 as *mut libc::c_void;
}
