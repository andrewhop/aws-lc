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
    pub type stack_st_X509_REVOKED;
    pub type crypto_buffer_st;
    pub type stack_st_DIST_POINT;
    pub type stack_st_void;
    pub type stack_st_X509_ATTRIBUTE;
    pub type lhash_st_CONF_VALUE;
    pub type stack_st_CONF_VALUE;
    pub type stack_st;
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn strncmp(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn ASN1_item_new(it: *const ASN1_ITEM) -> *mut ASN1_VALUE;
    fn ASN1_item_free(val: *mut ASN1_VALUE, it: *const ASN1_ITEM);
    static ASN1_INTEGER_it: ASN1_ITEM;
    fn X509_get_subject_name(x509: *const X509) -> *mut X509_NAME;
    fn i2d_X509_NAME(in_0: *mut X509_NAME, outp: *mut *mut uint8_t) -> libc::c_int;
    fn X509_NAME_entry_count(name: *const X509_NAME) -> libc::c_int;
    fn X509_NAME_get_index_by_NID(
        name: *const X509_NAME,
        nid: libc::c_int,
        lastpos: libc::c_int,
    ) -> libc::c_int;
    fn X509_NAME_get_entry(
        name: *const X509_NAME,
        loc: libc::c_int,
    ) -> *mut X509_NAME_ENTRY;
    fn X509_NAME_ENTRY_get_data(entry: *const X509_NAME_ENTRY) -> *mut ASN1_STRING;
    fn GENERAL_NAME_print(out: *mut BIO, gen: *const GENERAL_NAME) -> libc::c_int;
    static GENERAL_NAME_it: ASN1_ITEM;
    fn v2i_GENERAL_NAME_ex(
        out: *mut GENERAL_NAME,
        method: *const X509V3_EXT_METHOD,
        ctx: *const X509V3_CTX,
        cnf: *const CONF_VALUE,
        is_nc: libc::c_int,
    ) -> *mut GENERAL_NAME;
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn BIO_puts(bio: *mut BIO, buf: *const libc::c_char) -> libc::c_int;
    fn BIO_printf(bio: *mut BIO, format: *const libc::c_char, _: ...) -> libc::c_int;
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_skip(cbs: *mut CBS, len: size_t) -> libc::c_int;
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_mem_equal(cbs: *const CBS, data: *const uint8_t, len: size_t) -> libc::c_int;
    fn CBS_get_u8(cbs: *mut CBS, out: *mut uint8_t) -> libc::c_int;
    fn CBS_get_until_first(cbs: *mut CBS, out: *mut CBS, c: uint8_t) -> libc::c_int;
    fn OPENSSL_tolower(c: libc::c_int) -> libc::c_int;
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
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
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
pub struct X509_name_entry_st {
    pub object: *mut ASN1_OBJECT,
    pub value: *mut ASN1_STRING,
    pub set: libc::c_int,
}
pub type X509_NAME_ENTRY = X509_name_entry_st;
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
pub struct cbs_st {
    pub data: *const uint8_t,
    pub len: size_t,
}
pub type CBS = cbs_st;
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
pub type OPENSSL_STACK = stack_st;
pub type GENERAL_SUBTREE = GENERAL_SUBTREE_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct GENERAL_SUBTREE_st {
    pub base: *mut GENERAL_NAME,
    pub minimum: *mut ASN1_INTEGER,
    pub maximum: *mut ASN1_INTEGER,
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
unsafe extern "C" fn sk_GENERAL_SUBTREE_push(
    mut sk: *mut stack_st_GENERAL_SUBTREE,
    mut p: *mut GENERAL_SUBTREE,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_GENERAL_SUBTREE_value(
    mut sk: *const stack_st_GENERAL_SUBTREE,
    mut i: size_t,
) -> *mut GENERAL_SUBTREE {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut GENERAL_SUBTREE;
}
#[inline]
unsafe extern "C" fn sk_GENERAL_SUBTREE_num(
    mut sk: *const stack_st_GENERAL_SUBTREE,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_GENERAL_SUBTREE_new_null() -> *mut stack_st_GENERAL_SUBTREE {
    return OPENSSL_sk_new_null() as *mut stack_st_GENERAL_SUBTREE;
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
#[unsafe(no_mangle)]
pub static mut v3_name_constraints: X509V3_EXT_METHOD = unsafe {
    {
        let mut init = v3_ext_method {
            ext_nid: 666 as libc::c_int,
            ext_flags: 0 as libc::c_int,
            it: &NAME_CONSTRAINTS_it as *const ASN1_ITEM,
            ext_new: None,
            ext_free: None,
            d2i: None,
            i2d: None,
            i2s: None,
            s2i: None,
            i2v: None,
            v2i: Some(
                v2i_NAME_CONSTRAINTS
                    as unsafe extern "C" fn(
                        *const X509V3_EXT_METHOD,
                        *const X509V3_CTX,
                        *const stack_st_CONF_VALUE,
                    ) -> *mut libc::c_void,
            ),
            i2r: Some(
                i2r_NAME_CONSTRAINTS
                    as unsafe extern "C" fn(
                        *const X509V3_EXT_METHOD,
                        *mut libc::c_void,
                        *mut BIO,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            r2i: None,
            usr_data: 0 as *const libc::c_void as *mut libc::c_void,
        };
        init
    }
};
static mut GENERAL_SUBTREE_seq_tt: [ASN1_TEMPLATE; 3] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"base\0" as *const u8 as *const libc::c_char,
                item: &GENERAL_NAME_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"minimum\0" as *const u8 as *const libc::c_char,
                item: &ASN1_INTEGER_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 1 as libc::c_int,
                offset: 16 as libc::c_ulong,
                field_name: b"maximum\0" as *const u8 as *const libc::c_char,
                item: &ASN1_INTEGER_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[unsafe(no_mangle)]
pub static mut GENERAL_SUBTREE_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
static mut NAME_CONSTRAINTS_seq_tt: [ASN1_TEMPLATE; 2] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int
                    | (0x2 as libc::c_int) << 1 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"permittedSubtrees\0" as *const u8 as *const libc::c_char,
                item: &GENERAL_SUBTREE_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int
                    | (0x2 as libc::c_int) << 1 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 1 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"excludedSubtrees\0" as *const u8 as *const libc::c_char,
                item: &GENERAL_SUBTREE_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[unsafe(no_mangle)]
pub static mut NAME_CONSTRAINTS_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn GENERAL_SUBTREE_free(mut a: *mut GENERAL_SUBTREE) {
    ASN1_item_free(a as *mut ASN1_VALUE, &GENERAL_SUBTREE_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn GENERAL_SUBTREE_new() -> *mut GENERAL_SUBTREE {
    return ASN1_item_new(&GENERAL_SUBTREE_it) as *mut GENERAL_SUBTREE;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NAME_CONSTRAINTS_free(mut a: *mut NAME_CONSTRAINTS) {
    ASN1_item_free(a as *mut ASN1_VALUE, &NAME_CONSTRAINTS_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NAME_CONSTRAINTS_new() -> *mut NAME_CONSTRAINTS {
    return ASN1_item_new(&NAME_CONSTRAINTS_it) as *mut NAME_CONSTRAINTS;
}
unsafe extern "C" fn v2i_NAME_CONSTRAINTS(
    mut method: *const X509V3_EXT_METHOD,
    mut ctx: *const X509V3_CTX,
    mut nval: *const stack_st_CONF_VALUE,
) -> *mut libc::c_void {
    let mut current_block: u64;
    let mut ptree: *mut *mut stack_st_GENERAL_SUBTREE = 0
        as *mut *mut stack_st_GENERAL_SUBTREE;
    let mut ncons: *mut NAME_CONSTRAINTS = 0 as *mut NAME_CONSTRAINTS;
    let mut sub: *mut GENERAL_SUBTREE = 0 as *mut GENERAL_SUBTREE;
    ncons = NAME_CONSTRAINTS_new();
    if !ncons.is_null() {
        let mut i: size_t = 0 as libc::c_int as size_t;
        loop {
            if !(i < sk_CONF_VALUE_num(nval)) {
                current_block = 26972500619410423;
                break;
            }
            let mut val: *const CONF_VALUE = sk_CONF_VALUE_value(nval, i);
            let mut tval: CONF_VALUE = conf_value_st {
                section: 0 as *mut libc::c_char,
                name: 0 as *mut libc::c_char,
                value: 0 as *mut libc::c_char,
            };
            if strncmp(
                (*val).name,
                b"permitted\0" as *const u8 as *const libc::c_char,
                9 as libc::c_int as libc::c_ulong,
            ) == 0
                && *((*val).name).offset(9 as libc::c_int as isize) as libc::c_int != 0
            {
                ptree = &mut (*ncons).permittedSubtrees;
                tval.name = ((*val).name).offset(10 as libc::c_int as isize);
            } else if strncmp(
                (*val).name,
                b"excluded\0" as *const u8 as *const libc::c_char,
                8 as libc::c_int as libc::c_ulong,
            ) == 0
                && *((*val).name).offset(8 as libc::c_int as isize) as libc::c_int != 0
            {
                ptree = &mut (*ncons).excludedSubtrees;
                tval.name = ((*val).name).offset(9 as libc::c_int as isize);
            } else {
                ERR_put_error(
                    20 as libc::c_int,
                    0 as libc::c_int,
                    135 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_ncons.c\0"
                        as *const u8 as *const libc::c_char,
                    142 as libc::c_int as libc::c_uint,
                );
                current_block = 7798461434908048298;
                break;
            }
            tval.value = (*val).value;
            sub = GENERAL_SUBTREE_new();
            if (v2i_GENERAL_NAME_ex(
                (*sub).base,
                method,
                ctx,
                &mut tval,
                1 as libc::c_int,
            ))
                .is_null()
            {
                current_block = 7798461434908048298;
                break;
            }
            if (*ptree).is_null() {
                *ptree = sk_GENERAL_SUBTREE_new_null();
            }
            if (*ptree).is_null() || sk_GENERAL_SUBTREE_push(*ptree, sub) == 0 {
                current_block = 7798461434908048298;
                break;
            }
            sub = 0 as *mut GENERAL_SUBTREE;
            i = i.wrapping_add(1);
            i;
        }
        match current_block {
            7798461434908048298 => {}
            _ => return ncons as *mut libc::c_void,
        }
    }
    NAME_CONSTRAINTS_free(ncons);
    GENERAL_SUBTREE_free(sub);
    return 0 as *mut libc::c_void;
}
unsafe extern "C" fn i2r_NAME_CONSTRAINTS(
    mut method: *const X509V3_EXT_METHOD,
    mut a: *mut libc::c_void,
    mut bp: *mut BIO,
    mut ind: libc::c_int,
) -> libc::c_int {
    let mut ncons: *mut NAME_CONSTRAINTS = a as *mut NAME_CONSTRAINTS;
    do_i2r_name_constraints(
        method,
        (*ncons).permittedSubtrees,
        bp,
        ind,
        b"Permitted\0" as *const u8 as *const libc::c_char,
    );
    do_i2r_name_constraints(
        method,
        (*ncons).excludedSubtrees,
        bp,
        ind,
        b"Excluded\0" as *const u8 as *const libc::c_char,
    );
    return 1 as libc::c_int;
}
unsafe extern "C" fn do_i2r_name_constraints(
    mut method: *const X509V3_EXT_METHOD,
    mut trees: *mut stack_st_GENERAL_SUBTREE,
    mut bp: *mut BIO,
    mut ind: libc::c_int,
    mut name: *const libc::c_char,
) -> libc::c_int {
    let mut tree: *mut GENERAL_SUBTREE = 0 as *mut GENERAL_SUBTREE;
    let mut i: size_t = 0;
    if sk_GENERAL_SUBTREE_num(trees) > 0 as libc::c_int as size_t {
        BIO_printf(
            bp,
            b"%*s%s:\n\0" as *const u8 as *const libc::c_char,
            ind,
            b"\0" as *const u8 as *const libc::c_char,
            name,
        );
    }
    i = 0 as libc::c_int as size_t;
    while i < sk_GENERAL_SUBTREE_num(trees) {
        tree = sk_GENERAL_SUBTREE_value(trees, i);
        BIO_printf(
            bp,
            b"%*s\0" as *const u8 as *const libc::c_char,
            ind + 2 as libc::c_int,
            b"\0" as *const u8 as *const libc::c_char,
        );
        if tree.is_null() {
            return 0 as libc::c_int;
        }
        if (*(*tree).base).type_0 == 7 as libc::c_int {
            print_nc_ipadd(bp, (*(*tree).base).d.ip);
        } else {
            GENERAL_NAME_print(bp, (*tree).base);
        }
        BIO_puts(bp, b"\n\0" as *const u8 as *const libc::c_char);
        i = i.wrapping_add(1);
        i;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn print_nc_ipadd(
    mut bp: *mut BIO,
    mut ip: *const ASN1_OCTET_STRING,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    let mut p: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    p = (*ip).data;
    len = (*ip).length;
    BIO_puts(bp, b"IP:\0" as *const u8 as *const libc::c_char);
    if len == 8 as libc::c_int {
        BIO_printf(
            bp,
            b"%d.%d.%d.%d/%d.%d.%d.%d\0" as *const u8 as *const libc::c_char,
            *p.offset(0 as libc::c_int as isize) as libc::c_int,
            *p.offset(1 as libc::c_int as isize) as libc::c_int,
            *p.offset(2 as libc::c_int as isize) as libc::c_int,
            *p.offset(3 as libc::c_int as isize) as libc::c_int,
            *p.offset(4 as libc::c_int as isize) as libc::c_int,
            *p.offset(5 as libc::c_int as isize) as libc::c_int,
            *p.offset(6 as libc::c_int as isize) as libc::c_int,
            *p.offset(7 as libc::c_int as isize) as libc::c_int,
        );
    } else if len == 32 as libc::c_int {
        i = 0 as libc::c_int;
        while i < 16 as libc::c_int {
            let mut v: uint16_t = ((*p.offset(0 as libc::c_int as isize) as uint16_t
                as libc::c_int) << 8 as libc::c_int
                | *p.offset(1 as libc::c_int as isize) as libc::c_int) as uint16_t;
            BIO_printf(
                bp,
                b"%X\0" as *const u8 as *const libc::c_char,
                v as libc::c_int,
            );
            p = p.offset(2 as libc::c_int as isize);
            if i == 7 as libc::c_int {
                BIO_puts(bp, b"/\0" as *const u8 as *const libc::c_char);
            } else if i != 15 as libc::c_int {
                BIO_puts(bp, b":\0" as *const u8 as *const libc::c_char);
            }
            i += 1;
            i;
        }
    } else {
        BIO_printf(bp, b"IP Address:<invalid>\0" as *const u8 as *const libc::c_char);
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NAME_CONSTRAINTS_check(
    mut x: *mut X509,
    mut nc: *mut NAME_CONSTRAINTS,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    let mut j: size_t = 0;
    let mut nm: *mut X509_NAME = 0 as *mut X509_NAME;
    nm = X509_get_subject_name(x);
    let mut name_count: size_t = (X509_NAME_entry_count(nm) as size_t)
        .wrapping_add(sk_GENERAL_NAME_num((*x).altname));
    let mut constraint_count: size_t = (sk_GENERAL_SUBTREE_num((*nc).permittedSubtrees))
        .wrapping_add(sk_GENERAL_SUBTREE_num((*nc).excludedSubtrees));
    let mut check_count: size_t = constraint_count * name_count;
    if name_count < X509_NAME_entry_count(nm) as size_t
        || constraint_count < sk_GENERAL_SUBTREE_num((*nc).permittedSubtrees)
        || constraint_count != 0 && check_count / constraint_count != name_count
        || check_count > ((1 as libc::c_int) << 20 as libc::c_int) as size_t
    {
        return 1 as libc::c_int;
    }
    if X509_NAME_entry_count(nm) > 0 as libc::c_int {
        let mut gntmp: GENERAL_NAME = GENERAL_NAME_st {
            type_0: 0,
            d: C2RustUnnamed_1 {
                ptr: 0 as *mut libc::c_char,
            },
        };
        gntmp.type_0 = 4 as libc::c_int;
        gntmp.d.directoryName = nm;
        r = nc_match(&mut gntmp, nc);
        if r != 0 as libc::c_int {
            return r;
        }
        gntmp.type_0 = 1 as libc::c_int;
        i = -(1 as libc::c_int);
        loop {
            i = X509_NAME_get_index_by_NID(nm, 48 as libc::c_int, i);
            if i == -(1 as libc::c_int) {
                break;
            }
            let mut ne: *const X509_NAME_ENTRY = X509_NAME_get_entry(nm, i);
            gntmp.d.rfc822Name = X509_NAME_ENTRY_get_data(ne);
            if (*gntmp.d.rfc822Name).type_0 != 22 as libc::c_int {
                return 53 as libc::c_int;
            }
            r = nc_match(&mut gntmp, nc);
            if r != 0 as libc::c_int {
                return r;
            }
        }
    }
    j = 0 as libc::c_int as size_t;
    while j < sk_GENERAL_NAME_num((*x).altname) {
        let mut gen: *mut GENERAL_NAME = sk_GENERAL_NAME_value((*x).altname, j);
        r = nc_match(gen, nc);
        if r != 0 as libc::c_int {
            return r;
        }
        j = j.wrapping_add(1);
        j;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn nc_match(
    mut gen: *mut GENERAL_NAME,
    mut nc: *mut NAME_CONSTRAINTS,
) -> libc::c_int {
    let mut sub: *mut GENERAL_SUBTREE = 0 as *mut GENERAL_SUBTREE;
    let mut r: libc::c_int = 0;
    let mut match_0: libc::c_int = 0 as libc::c_int;
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < sk_GENERAL_SUBTREE_num((*nc).permittedSubtrees) {
        sub = sk_GENERAL_SUBTREE_value((*nc).permittedSubtrees, i);
        if !((*gen).type_0 != (*(*sub).base).type_0) {
            if !((*sub).minimum).is_null() || !((*sub).maximum).is_null() {
                return 49 as libc::c_int;
            }
            if !(match_0 == 2 as libc::c_int) {
                if match_0 == 0 as libc::c_int {
                    match_0 = 1 as libc::c_int;
                }
                r = nc_match_single(gen, (*sub).base);
                if r == 0 as libc::c_int {
                    match_0 = 2 as libc::c_int;
                } else if r != 47 as libc::c_int {
                    return r
                }
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    if match_0 == 1 as libc::c_int {
        return 47 as libc::c_int;
    }
    i = 0 as libc::c_int as size_t;
    while i < sk_GENERAL_SUBTREE_num((*nc).excludedSubtrees) {
        sub = sk_GENERAL_SUBTREE_value((*nc).excludedSubtrees, i);
        if !((*gen).type_0 != (*(*sub).base).type_0) {
            if !((*sub).minimum).is_null() || !((*sub).maximum).is_null() {
                return 49 as libc::c_int;
            }
            r = nc_match_single(gen, (*sub).base);
            if r == 0 as libc::c_int {
                return 48 as libc::c_int
            } else if r != 47 as libc::c_int {
                return r
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn nc_match_single(
    mut gen: *mut GENERAL_NAME,
    mut base: *mut GENERAL_NAME,
) -> libc::c_int {
    match (*base).type_0 {
        4 => return nc_dn((*gen).d.directoryName, (*base).d.directoryName),
        2 => return nc_dns((*gen).d.dNSName, (*base).d.dNSName),
        1 => return nc_email((*gen).d.rfc822Name, (*base).d.rfc822Name),
        6 => {
            return nc_uri(
                (*gen).d.uniformResourceIdentifier,
                (*base).d.uniformResourceIdentifier,
            );
        }
        _ => return 51 as libc::c_int,
    };
}
unsafe extern "C" fn nc_dn(
    mut nm: *mut X509_NAME,
    mut base: *mut X509_NAME,
) -> libc::c_int {
    if (*nm).modified != 0
        && i2d_X509_NAME(nm, 0 as *mut *mut uint8_t) < 0 as libc::c_int
    {
        return 17 as libc::c_int;
    }
    if (*base).modified != 0
        && i2d_X509_NAME(base, 0 as *mut *mut uint8_t) < 0 as libc::c_int
    {
        return 17 as libc::c_int;
    }
    if (*base).canon_enclen > (*nm).canon_enclen {
        return 47 as libc::c_int;
    }
    if OPENSSL_memcmp(
        (*base).canon_enc as *const libc::c_void,
        (*nm).canon_enc as *const libc::c_void,
        (*base).canon_enclen as size_t,
    ) != 0
    {
        return 47 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn starts_with(mut cbs: *const CBS, mut c: uint8_t) -> libc::c_int {
    return (CBS_len(cbs) > 0 as libc::c_int as size_t
        && *(CBS_data(cbs)).offset(0 as libc::c_int as isize) as libc::c_int
            == c as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn equal_case(mut a: *const CBS, mut b: *const CBS) -> libc::c_int {
    if CBS_len(a) != CBS_len(b) {
        return 0 as libc::c_int;
    }
    let mut a_data: *const uint8_t = CBS_data(a);
    let mut b_data: *const uint8_t = CBS_data(b);
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < CBS_len(a) {
        if OPENSSL_tolower(*a_data.offset(i as isize) as libc::c_int)
            != OPENSSL_tolower(*b_data.offset(i as isize) as libc::c_int)
        {
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn has_suffix_case(
    mut a: *const CBS,
    mut b: *const CBS,
) -> libc::c_int {
    if CBS_len(a) < CBS_len(b) {
        return 0 as libc::c_int;
    }
    let mut copy: CBS = *a;
    CBS_skip(&mut copy, (CBS_len(a)).wrapping_sub(CBS_len(b)));
    return equal_case(&mut copy, b);
}
unsafe extern "C" fn nc_dns(
    mut dns: *const ASN1_IA5STRING,
    mut base: *const ASN1_IA5STRING,
) -> libc::c_int {
    let mut dns_cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut base_cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut dns_cbs, (*dns).data, (*dns).length as size_t);
    CBS_init(&mut base_cbs, (*base).data, (*base).length as size_t);
    if CBS_len(&mut base_cbs) == 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    if starts_with(&mut base_cbs, '.' as i32 as uint8_t) != 0 {
        if has_suffix_case(&mut dns_cbs, &mut base_cbs) != 0 {
            return 0 as libc::c_int;
        }
        return 47 as libc::c_int;
    }
    if CBS_len(&mut dns_cbs) > CBS_len(&mut base_cbs) {
        let mut dot: uint8_t = 0;
        if CBS_skip(
            &mut dns_cbs,
            (CBS_len(&mut dns_cbs))
                .wrapping_sub(CBS_len(&mut base_cbs))
                .wrapping_sub(1 as libc::c_int as size_t),
        ) == 0 || CBS_get_u8(&mut dns_cbs, &mut dot) == 0
            || dot as libc::c_int != '.' as i32
        {
            return 47 as libc::c_int;
        }
    }
    if equal_case(&mut dns_cbs, &mut base_cbs) == 0 {
        return 47 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn nc_email(
    mut eml: *const ASN1_IA5STRING,
    mut base: *const ASN1_IA5STRING,
) -> libc::c_int {
    let mut eml_cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut base_cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut eml_cbs, (*eml).data, (*eml).length as size_t);
    CBS_init(&mut base_cbs, (*base).data, (*base).length as size_t);
    let mut eml_local: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut base_local: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_get_until_first(&mut eml_cbs, &mut eml_local, '@' as i32 as uint8_t) == 0 {
        return 53 as libc::c_int;
    }
    let mut base_has_at: libc::c_int = CBS_get_until_first(
        &mut base_cbs,
        &mut base_local,
        '@' as i32 as uint8_t,
    );
    if base_has_at == 0 && starts_with(&mut base_cbs, '.' as i32 as uint8_t) != 0 {
        if has_suffix_case(&mut eml_cbs, &mut base_cbs) != 0 {
            return 0 as libc::c_int;
        }
        return 47 as libc::c_int;
    }
    if base_has_at != 0 {
        if CBS_len(&mut base_local) > 0 as libc::c_int as size_t {
            if CBS_mem_equal(
                &mut base_local,
                CBS_data(&mut eml_local),
                CBS_len(&mut eml_local),
            ) == 0
            {
                return 47 as libc::c_int;
            }
        }
        if starts_with(&mut base_cbs, '@' as i32 as uint8_t) != 0 {} else {
            __assert_fail(
                b"starts_with(&base_cbs, '@')\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_ncons.c\0"
                    as *const u8 as *const libc::c_char,
                502 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 61],
                    &[libc::c_char; 61],
                >(b"int nc_email(const ASN1_IA5STRING *, const ASN1_IA5STRING *)\0"))
                    .as_ptr(),
            );
        }
        'c_22646: {
            if starts_with(&mut base_cbs, '@' as i32 as uint8_t) != 0 {} else {
                __assert_fail(
                    b"starts_with(&base_cbs, '@')\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_ncons.c\0"
                        as *const u8 as *const libc::c_char,
                    502 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 61],
                        &[libc::c_char; 61],
                    >(b"int nc_email(const ASN1_IA5STRING *, const ASN1_IA5STRING *)\0"))
                        .as_ptr(),
                );
            }
        };
        CBS_skip(&mut base_cbs, 1 as libc::c_int as size_t);
    }
    if starts_with(&mut eml_cbs, '@' as i32 as uint8_t) != 0 {} else {
        __assert_fail(
            b"starts_with(&eml_cbs, '@')\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_ncons.c\0" as *const u8
                as *const libc::c_char,
            507 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 61],
                &[libc::c_char; 61],
            >(b"int nc_email(const ASN1_IA5STRING *, const ASN1_IA5STRING *)\0"))
                .as_ptr(),
        );
    }
    'c_22579: {
        if starts_with(&mut eml_cbs, '@' as i32 as uint8_t) != 0 {} else {
            __assert_fail(
                b"starts_with(&eml_cbs, '@')\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_ncons.c\0"
                    as *const u8 as *const libc::c_char,
                507 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 61],
                    &[libc::c_char; 61],
                >(b"int nc_email(const ASN1_IA5STRING *, const ASN1_IA5STRING *)\0"))
                    .as_ptr(),
            );
        }
    };
    CBS_skip(&mut eml_cbs, 1 as libc::c_int as size_t);
    if equal_case(&mut base_cbs, &mut eml_cbs) == 0 {
        return 47 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn nc_uri(
    mut uri: *const ASN1_IA5STRING,
    mut base: *const ASN1_IA5STRING,
) -> libc::c_int {
    let mut uri_cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut base_cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut uri_cbs, (*uri).data, (*uri).length as size_t);
    CBS_init(&mut base_cbs, (*base).data, (*base).length as size_t);
    let mut scheme: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut byte: uint8_t = 0;
    if CBS_get_until_first(&mut uri_cbs, &mut scheme, ':' as i32 as uint8_t) == 0
        || CBS_skip(&mut uri_cbs, 1 as libc::c_int as size_t) == 0
        || CBS_get_u8(&mut uri_cbs, &mut byte) == 0 || byte as libc::c_int != '/' as i32
        || CBS_get_u8(&mut uri_cbs, &mut byte) == 0 || byte as libc::c_int != '/' as i32
    {
        return 53 as libc::c_int;
    }
    let mut host: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_get_until_first(&mut uri_cbs, &mut host, ':' as i32 as uint8_t) == 0
        && CBS_get_until_first(&mut uri_cbs, &mut host, '/' as i32 as uint8_t) == 0
    {
        host = uri_cbs;
    }
    if CBS_len(&mut host) == 0 as libc::c_int as size_t {
        return 53 as libc::c_int;
    }
    if starts_with(&mut base_cbs, '.' as i32 as uint8_t) != 0 {
        if has_suffix_case(&mut host, &mut base_cbs) != 0 {
            return 0 as libc::c_int;
        }
        return 47 as libc::c_int;
    }
    if equal_case(&mut base_cbs, &mut host) == 0 {
        return 47 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn run_static_initializers() {
    GENERAL_SUBTREE_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: GENERAL_SUBTREE_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 3]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<GENERAL_SUBTREE>() as libc::c_ulong
                as libc::c_long,
            sname: b"GENERAL_SUBTREE\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    NAME_CONSTRAINTS_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: NAME_CONSTRAINTS_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 2]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<NAME_CONSTRAINTS>() as libc::c_ulong
                as libc::c_long,
            sname: b"NAME_CONSTRAINTS\0" as *const u8 as *const libc::c_char,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
