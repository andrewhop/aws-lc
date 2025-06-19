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
    pub type stack_st_ASN1_INTEGER;
    pub type asn1_must_be_null_st;
    pub type stack_st_POLICYQUALINFO;
    pub type stack_st_POLICYINFO;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn ASN1_item_new(it: *const ASN1_ITEM) -> *mut ASN1_VALUE;
    fn ASN1_item_free(val: *mut ASN1_VALUE, it: *const ASN1_ITEM);
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
    fn ASN1_STRING_set(
        str: *mut ASN1_STRING,
        data: *const libc::c_void,
        len: ossl_ssize_t,
    ) -> libc::c_int;
    fn ASN1_IA5STRING_new() -> *mut ASN1_IA5STRING;
    fn ASN1_VISIBLESTRING_new() -> *mut ASN1_VISIBLESTRING;
    static ASN1_IA5STRING_it: ASN1_ITEM;
    static DISPLAYTEXT_it: ASN1_ITEM;
    fn ASN1_INTEGER_free(str: *mut ASN1_INTEGER);
    static ASN1_INTEGER_it: ASN1_ITEM;
    fn ASN1_OBJECT_free(a: *mut ASN1_OBJECT);
    static ASN1_OBJECT_it: ASN1_ITEM;
    static ASN1_ANY_it: ASN1_ITEM;
    fn i2a_ASN1_OBJECT(bp: *mut BIO, a: *const ASN1_OBJECT) -> libc::c_int;
    fn i2s_ASN1_INTEGER(
        method: *const X509V3_EXT_METHOD,
        aint: *const ASN1_INTEGER,
    ) -> *mut libc::c_char;
    fn s2i_ASN1_INTEGER(
        method: *const X509V3_EXT_METHOD,
        value: *const libc::c_char,
    ) -> *mut ASN1_INTEGER;
    fn X509V3_conf_free(val: *mut CONF_VALUE);
    fn X509V3_parse_list(line: *const libc::c_char) -> *mut stack_st_CONF_VALUE;
    fn x509v3_conf_name_matches(
        name: *const libc::c_char,
        cmp: *const libc::c_char,
    ) -> libc::c_int;
    fn X509V3_get_section(
        ctx: *const X509V3_CTX,
        section: *const libc::c_char,
    ) -> *const stack_st_CONF_VALUE;
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_pop_free_ex(
        sk: *mut OPENSSL_STACK,
        call_free_func: OPENSSL_sk_call_free_func,
        free_func: OPENSSL_sk_free_func,
    );
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn BIO_puts(bio: *mut BIO, buf: *const libc::c_char) -> libc::c_int;
    fn BIO_printf(bio: *mut BIO, format: *const libc::c_char, _: ...) -> libc::c_int;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn ERR_add_error_data(count: libc::c_uint, _: ...);
    fn OBJ_obj2nid(obj: *const ASN1_OBJECT) -> libc::c_int;
    fn OBJ_nid2obj(nid: libc::c_int) -> *mut ASN1_OBJECT;
    fn OBJ_txt2obj(
        s: *const libc::c_char,
        dont_search_names: libc::c_int,
    ) -> *mut ASN1_OBJECT;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type ptrdiff_t = libc::c_long;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type ossl_ssize_t = ptrdiff_t;
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
pub type sk_CONF_VALUE_free_func = Option::<unsafe extern "C" fn(*mut CONF_VALUE) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct NOTICEREF_st {
    pub organization: *mut ASN1_STRING,
    pub noticenos: *mut stack_st_ASN1_INTEGER,
}
pub type NOTICEREF = NOTICEREF_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct USERNOTICE_st {
    pub noticeref: *mut NOTICEREF,
    pub exptext: *mut ASN1_STRING,
}
pub type USERNOTICE = USERNOTICE_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct POLICYQUALINFO_st {
    pub pqualid: *mut ASN1_OBJECT,
    pub d: C2RustUnnamed_1,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_1 {
    pub cpsuri: *mut ASN1_IA5STRING,
    pub usernotice: *mut USERNOTICE,
    pub other: *mut ASN1_TYPE,
}
pub type POLICYQUALINFO = POLICYQUALINFO_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct POLICYINFO_st {
    pub policyid: *mut ASN1_OBJECT,
    pub qualifiers: *mut stack_st_POLICYQUALINFO,
}
pub type POLICYINFO = POLICYINFO_st;
pub type CERTIFICATEPOLICIES = stack_st_POLICYINFO;
pub type sk_POLICYINFO_free_func = Option::<unsafe extern "C" fn(*mut POLICYINFO) -> ()>;
#[inline]
unsafe extern "C" fn sk_ASN1_INTEGER_value(
    mut sk: *const stack_st_ASN1_INTEGER,
    mut i: size_t,
) -> *mut ASN1_INTEGER {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut ASN1_INTEGER;
}
#[inline]
unsafe extern "C" fn sk_ASN1_INTEGER_num(
    mut sk: *const stack_st_ASN1_INTEGER,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_ASN1_INTEGER_push(
    mut sk: *mut stack_st_ASN1_INTEGER,
    mut p: *mut ASN1_INTEGER,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_POLICYQUALINFO_push(
    mut sk: *mut stack_st_POLICYQUALINFO,
    mut p: *mut POLICYQUALINFO,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_POLICYQUALINFO_new_null() -> *mut stack_st_POLICYQUALINFO {
    return OPENSSL_sk_new_null() as *mut stack_st_POLICYQUALINFO;
}
#[inline]
unsafe extern "C" fn sk_POLICYQUALINFO_num(
    mut sk: *const stack_st_POLICYQUALINFO,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_POLICYQUALINFO_value(
    mut sk: *const stack_st_POLICYQUALINFO,
    mut i: size_t,
) -> *mut POLICYQUALINFO {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut POLICYQUALINFO;
}
#[inline]
unsafe extern "C" fn sk_POLICYINFO_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<OPENSSL_sk_free_func, sk_POLICYINFO_free_func>(free_func))
        .expect("non-null function pointer")(ptr as *mut POLICYINFO);
}
#[inline]
unsafe extern "C" fn sk_POLICYINFO_push(
    mut sk: *mut stack_st_POLICYINFO,
    mut p: *mut POLICYINFO,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_POLICYINFO_new_null() -> *mut stack_st_POLICYINFO {
    return OPENSSL_sk_new_null() as *mut stack_st_POLICYINFO;
}
#[inline]
unsafe extern "C" fn sk_POLICYINFO_num(mut sk: *const stack_st_POLICYINFO) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_POLICYINFO_value(
    mut sk: *const stack_st_POLICYINFO,
    mut i: size_t,
) -> *mut POLICYINFO {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut POLICYINFO;
}
#[inline]
unsafe extern "C" fn sk_POLICYINFO_pop_free(
    mut sk: *mut stack_st_POLICYINFO,
    mut free_func: sk_POLICYINFO_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_POLICYINFO_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_POLICYINFO_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
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
#[no_mangle]
pub static mut v3_cpols: X509V3_EXT_METHOD = unsafe {
    {
        let mut init = v3_ext_method {
            ext_nid: 89 as libc::c_int,
            ext_flags: 0 as libc::c_int,
            it: &CERTIFICATEPOLICIES_it as *const ASN1_ITEM,
            ext_new: None,
            ext_free: None,
            d2i: None,
            i2d: None,
            i2s: None,
            s2i: None,
            i2v: None,
            v2i: None,
            i2r: Some(
                i2r_certpol
                    as unsafe extern "C" fn(
                        *const X509V3_EXT_METHOD,
                        *mut libc::c_void,
                        *mut BIO,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            r2i: Some(
                r2i_certpol
                    as unsafe extern "C" fn(
                        *const X509V3_EXT_METHOD,
                        *const X509V3_CTX,
                        *const libc::c_char,
                    ) -> *mut libc::c_void,
            ),
            usr_data: 0 as *const libc::c_void as *mut libc::c_void,
        };
        init
    }
};
static mut CERTIFICATEPOLICIES_item_tt: ASN1_TEMPLATE = unsafe {
    {
        let mut init = ASN1_TEMPLATE_st {
            flags: ((0x2 as libc::c_int) << 1 as libc::c_int) as uint32_t,
            tag: 0 as libc::c_int,
            offset: 0 as libc::c_int as libc::c_ulong,
            field_name: b"CERTIFICATEPOLICIES\0" as *const u8 as *const libc::c_char,
            item: &POLICYINFO_it as *const ASN1_ITEM,
        };
        init
    }
};
#[no_mangle]
pub static mut CERTIFICATEPOLICIES_it: ASN1_ITEM = unsafe {
    {
        let mut init = ASN1_ITEM_st {
            itype: 0 as libc::c_int as libc::c_char,
            utype: -(1 as libc::c_int),
            templates: &CERTIFICATEPOLICIES_item_tt as *const ASN1_TEMPLATE,
            tcount: 0 as libc::c_int as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: 0 as libc::c_int as libc::c_long,
            sname: b"CERTIFICATEPOLICIES\0" as *const u8 as *const libc::c_char,
        };
        init
    }
};
#[no_mangle]
pub unsafe extern "C" fn CERTIFICATEPOLICIES_free(mut a: *mut CERTIFICATEPOLICIES) {
    ASN1_item_free(a as *mut ASN1_VALUE, &CERTIFICATEPOLICIES_it);
}
#[no_mangle]
pub unsafe extern "C" fn i2d_CERTIFICATEPOLICIES(
    mut a: *const CERTIFICATEPOLICIES,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &CERTIFICATEPOLICIES_it);
}
#[no_mangle]
pub unsafe extern "C" fn CERTIFICATEPOLICIES_new() -> *mut CERTIFICATEPOLICIES {
    return ASN1_item_new(&CERTIFICATEPOLICIES_it) as *mut CERTIFICATEPOLICIES;
}
#[no_mangle]
pub unsafe extern "C" fn d2i_CERTIFICATEPOLICIES(
    mut a: *mut *mut CERTIFICATEPOLICIES,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut CERTIFICATEPOLICIES {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &CERTIFICATEPOLICIES_it)
        as *mut CERTIFICATEPOLICIES;
}
static mut POLICYINFO_seq_tt: [ASN1_TEMPLATE; 2] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"policyid\0" as *const u8 as *const libc::c_char,
                item: &ASN1_OBJECT_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 1 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"qualifiers\0" as *const u8 as *const libc::c_char,
                item: &POLICYQUALINFO_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut POLICYINFO_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[no_mangle]
pub unsafe extern "C" fn POLICYINFO_free(mut a: *mut POLICYINFO) {
    ASN1_item_free(a as *mut ASN1_VALUE, &POLICYINFO_it);
}
#[no_mangle]
pub unsafe extern "C" fn POLICYINFO_new() -> *mut POLICYINFO {
    return ASN1_item_new(&POLICYINFO_it) as *mut POLICYINFO;
}
static mut policydefault_tt: ASN1_TEMPLATE = unsafe {
    {
        let mut init = ASN1_TEMPLATE_st {
            flags: 0 as libc::c_int as uint32_t,
            tag: 0 as libc::c_int,
            offset: 8 as libc::c_ulong,
            field_name: b"d.other\0" as *const u8 as *const libc::c_char,
            item: &ASN1_ANY_it as *const ASN1_ITEM,
        };
        init
    }
};
static mut POLICYQUALINFO_adbtbl: [ASN1_ADB_TABLE; 2] = unsafe {
    [
        {
            let mut init = ASN1_ADB_TABLE_st {
                value: 164 as libc::c_int,
                tt: {
                    let mut init = ASN1_TEMPLATE_st {
                        flags: 0 as libc::c_int as uint32_t,
                        tag: 0 as libc::c_int,
                        offset: 8 as libc::c_ulong,
                        field_name: b"d.cpsuri\0" as *const u8 as *const libc::c_char,
                        item: &ASN1_IA5STRING_it as *const ASN1_ITEM,
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ASN1_ADB_TABLE_st {
                value: 165 as libc::c_int,
                tt: {
                    let mut init = ASN1_TEMPLATE_st {
                        flags: 0 as libc::c_int as uint32_t,
                        tag: 0 as libc::c_int,
                        offset: 8 as libc::c_ulong,
                        field_name: b"d.usernotice\0" as *const u8
                            as *const libc::c_char,
                        item: &USERNOTICE_it as *const ASN1_ITEM,
                    };
                    init
                },
            };
            init
        },
    ]
};
static mut POLICYQUALINFO_adb: ASN1_ADB = ASN1_ADB_st {
    flags: 0,
    offset: 0,
    unused: 0 as *const ASN1_MUST_BE_NULL as *mut ASN1_MUST_BE_NULL,
    tbl: 0 as *const ASN1_ADB_TABLE,
    tblcount: 0,
    default_tt: 0 as *const ASN1_TEMPLATE,
    null_tt: 0 as *const ASN1_TEMPLATE,
};
static mut POLICYQUALINFO_seq_tt: [ASN1_TEMPLATE; 2] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"pqualid\0" as *const u8 as *const libc::c_char,
                item: &ASN1_OBJECT_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 8 as libc::c_int) as uint32_t,
                tag: -(1 as libc::c_int),
                offset: 0 as libc::c_int as libc::c_ulong,
                field_name: b"POLICYQUALINFO\0" as *const u8 as *const libc::c_char,
                item: &POLICYQUALINFO_adb as *const ASN1_ADB as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut POLICYQUALINFO_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[no_mangle]
pub unsafe extern "C" fn POLICYQUALINFO_free(mut a: *mut POLICYQUALINFO) {
    ASN1_item_free(a as *mut ASN1_VALUE, &POLICYQUALINFO_it);
}
#[no_mangle]
pub unsafe extern "C" fn POLICYQUALINFO_new() -> *mut POLICYQUALINFO {
    return ASN1_item_new(&POLICYQUALINFO_it) as *mut POLICYQUALINFO;
}
static mut USERNOTICE_seq_tt: [ASN1_TEMPLATE; 2] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0x1 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"noticeref\0" as *const u8 as *const libc::c_char,
                item: &NOTICEREF_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0x1 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"exptext\0" as *const u8 as *const libc::c_char,
                item: &DISPLAYTEXT_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut USERNOTICE_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[no_mangle]
pub unsafe extern "C" fn USERNOTICE_free(mut a: *mut USERNOTICE) {
    ASN1_item_free(a as *mut ASN1_VALUE, &USERNOTICE_it);
}
#[no_mangle]
pub unsafe extern "C" fn USERNOTICE_new() -> *mut USERNOTICE {
    return ASN1_item_new(&USERNOTICE_it) as *mut USERNOTICE;
}
static mut NOTICEREF_seq_tt: [ASN1_TEMPLATE; 2] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"organization\0" as *const u8 as *const libc::c_char,
                item: &DISPLAYTEXT_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 1 as libc::c_int) as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"noticenos\0" as *const u8 as *const libc::c_char,
                item: &ASN1_INTEGER_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut NOTICEREF_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[no_mangle]
pub unsafe extern "C" fn NOTICEREF_free(mut a: *mut NOTICEREF) {
    ASN1_item_free(a as *mut ASN1_VALUE, &NOTICEREF_it);
}
#[no_mangle]
pub unsafe extern "C" fn NOTICEREF_new() -> *mut NOTICEREF {
    return ASN1_item_new(&NOTICEREF_it) as *mut NOTICEREF;
}
unsafe extern "C" fn r2i_certpol(
    mut method: *const X509V3_EXT_METHOD,
    mut ctx: *const X509V3_CTX,
    mut value: *const libc::c_char,
) -> *mut libc::c_void {
    let mut ia5org: libc::c_int = 0;
    let mut current_block: u64;
    let mut pols: *mut stack_st_POLICYINFO = sk_POLICYINFO_new_null();
    if pols.is_null() {
        return 0 as *mut libc::c_void;
    }
    let mut vals: *mut stack_st_CONF_VALUE = X509V3_parse_list(value);
    if vals.is_null() {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            20 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_cpols.c\0" as *const u8
                as *const libc::c_char,
            165 as libc::c_int as libc::c_uint,
        );
    } else {
        ia5org = 0 as libc::c_int;
        let mut i: size_t = 0 as libc::c_int as size_t;
        loop {
            if !(i < sk_CONF_VALUE_num(vals)) {
                current_block = 8693738493027456495;
                break;
            }
            let mut cnf: *const CONF_VALUE = sk_CONF_VALUE_value(vals, i);
            if !((*cnf).value).is_null() || ((*cnf).name).is_null() {
                ERR_put_error(
                    20 as libc::c_int,
                    0 as libc::c_int,
                    131 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_cpols.c\0"
                        as *const u8 as *const libc::c_char,
                    172 as libc::c_int as libc::c_uint,
                );
                ERR_add_error_data(
                    6 as libc::c_int as libc::c_uint,
                    b"section:\0" as *const u8 as *const libc::c_char,
                    (*cnf).section,
                    b",name:\0" as *const u8 as *const libc::c_char,
                    (*cnf).name,
                    b",value:\0" as *const u8 as *const libc::c_char,
                    (*cnf).value,
                );
                current_block = 9292422440559454854;
                break;
            } else {
                let mut pol: *mut POLICYINFO = 0 as *mut POLICYINFO;
                let mut pstr: *const libc::c_char = (*cnf).name;
                if strcmp(pstr, b"ia5org\0" as *const u8 as *const libc::c_char) == 0 {
                    ia5org = 1 as libc::c_int;
                } else {
                    if *pstr as libc::c_int == '@' as i32 {
                        let mut polsect: *const stack_st_CONF_VALUE = X509V3_get_section(
                            ctx,
                            pstr.offset(1 as libc::c_int as isize),
                        );
                        if polsect.is_null() {
                            ERR_put_error(
                                20 as libc::c_int,
                                0 as libc::c_int,
                                134 as libc::c_int,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_cpols.c\0"
                                    as *const u8 as *const libc::c_char,
                                184 as libc::c_int as libc::c_uint,
                            );
                            ERR_add_error_data(
                                6 as libc::c_int as libc::c_uint,
                                b"section:\0" as *const u8 as *const libc::c_char,
                                (*cnf).section,
                                b",name:\0" as *const u8 as *const libc::c_char,
                                (*cnf).name,
                                b",value:\0" as *const u8 as *const libc::c_char,
                                (*cnf).value,
                            );
                            current_block = 9292422440559454854;
                            break;
                        } else {
                            pol = policy_section(ctx, polsect, ia5org);
                            if pol.is_null() {
                                current_block = 9292422440559454854;
                                break;
                            }
                        }
                    } else {
                        let mut pobj: *mut ASN1_OBJECT = OBJ_txt2obj(
                            (*cnf).name,
                            0 as libc::c_int,
                        );
                        if pobj.is_null() {
                            ERR_put_error(
                                20 as libc::c_int,
                                0 as libc::c_int,
                                129 as libc::c_int,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_cpols.c\0"
                                    as *const u8 as *const libc::c_char,
                                196 as libc::c_int as libc::c_uint,
                            );
                            ERR_add_error_data(
                                6 as libc::c_int as libc::c_uint,
                                b"section:\0" as *const u8 as *const libc::c_char,
                                (*cnf).section,
                                b",name:\0" as *const u8 as *const libc::c_char,
                                (*cnf).name,
                                b",value:\0" as *const u8 as *const libc::c_char,
                                (*cnf).value,
                            );
                            current_block = 9292422440559454854;
                            break;
                        } else {
                            pol = POLICYINFO_new();
                            if pol.is_null() {
                                ASN1_OBJECT_free(pobj);
                                current_block = 9292422440559454854;
                                break;
                            } else {
                                (*pol).policyid = pobj;
                            }
                        }
                    }
                    if sk_POLICYINFO_push(pols, pol) == 0 {
                        POLICYINFO_free(pol);
                        current_block = 9292422440559454854;
                        break;
                    }
                }
                i = i.wrapping_add(1);
                i;
            }
        }
        match current_block {
            9292422440559454854 => {}
            _ => {
                sk_CONF_VALUE_pop_free(
                    vals,
                    Some(X509V3_conf_free as unsafe extern "C" fn(*mut CONF_VALUE) -> ()),
                );
                return pols as *mut libc::c_void;
            }
        }
    }
    sk_CONF_VALUE_pop_free(
        vals,
        Some(X509V3_conf_free as unsafe extern "C" fn(*mut CONF_VALUE) -> ()),
    );
    sk_POLICYINFO_pop_free(
        pols,
        Some(POLICYINFO_free as unsafe extern "C" fn(*mut POLICYINFO) -> ()),
    );
    return 0 as *mut libc::c_void;
}
unsafe extern "C" fn policy_section(
    mut ctx: *const X509V3_CTX,
    mut polstrs: *const stack_st_CONF_VALUE,
    mut ia5org: libc::c_int,
) -> *mut POLICYINFO {
    let mut current_block: u64;
    let mut pol: *mut POLICYINFO = 0 as *mut POLICYINFO;
    let mut qual: *mut POLICYQUALINFO = 0 as *mut POLICYQUALINFO;
    pol = POLICYINFO_new();
    if !pol.is_null() {
        let mut i: size_t = 0 as libc::c_int as size_t;
        loop {
            if !(i < sk_CONF_VALUE_num(polstrs)) {
                current_block = 15090052786889560393;
                break;
            }
            let mut cnf: *const CONF_VALUE = sk_CONF_VALUE_value(polstrs, i);
            if strcmp(
                (*cnf).name,
                b"policyIdentifier\0" as *const u8 as *const libc::c_char,
            ) == 0
            {
                let mut pobj: *mut ASN1_OBJECT = 0 as *mut ASN1_OBJECT;
                pobj = OBJ_txt2obj((*cnf).value, 0 as libc::c_int);
                if pobj.is_null() {
                    ERR_put_error(
                        20 as libc::c_int,
                        0 as libc::c_int,
                        129 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_cpols.c\0"
                            as *const u8 as *const libc::c_char,
                        233 as libc::c_int as libc::c_uint,
                    );
                    ERR_add_error_data(
                        6 as libc::c_int as libc::c_uint,
                        b"section:\0" as *const u8 as *const libc::c_char,
                        (*cnf).section,
                        b",name:\0" as *const u8 as *const libc::c_char,
                        (*cnf).name,
                        b",value:\0" as *const u8 as *const libc::c_char,
                        (*cnf).value,
                    );
                    current_block = 928128453121088265;
                    break;
                } else {
                    (*pol).policyid = pobj;
                }
            } else if x509v3_conf_name_matches(
                (*cnf).name,
                b"CPS\0" as *const u8 as *const libc::c_char,
            ) != 0
            {
                if ((*pol).qualifiers).is_null() {
                    (*pol).qualifiers = sk_POLICYQUALINFO_new_null();
                }
                qual = POLICYQUALINFO_new();
                if qual.is_null() {
                    current_block = 928128453121088265;
                    break;
                }
                if sk_POLICYQUALINFO_push((*pol).qualifiers, qual) == 0 {
                    current_block = 928128453121088265;
                    break;
                }
                (*qual).pqualid = OBJ_nid2obj(164 as libc::c_int);
                if ((*qual).pqualid).is_null() {
                    ERR_put_error(
                        20 as libc::c_int,
                        0 as libc::c_int,
                        4 as libc::c_int | 64 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_cpols.c\0"
                            as *const u8 as *const libc::c_char,
                        251 as libc::c_int as libc::c_uint,
                    );
                    current_block = 928128453121088265;
                    break;
                } else {
                    (*qual).d.cpsuri = ASN1_IA5STRING_new();
                    if ((*qual).d.cpsuri).is_null() {
                        current_block = 928128453121088265;
                        break;
                    }
                    if ASN1_STRING_set(
                        (*qual).d.cpsuri,
                        (*cnf).value as *const libc::c_void,
                        strlen((*cnf).value) as ossl_ssize_t,
                    ) == 0
                    {
                        current_block = 928128453121088265;
                        break;
                    }
                }
            } else if x509v3_conf_name_matches(
                (*cnf).name,
                b"userNotice\0" as *const u8 as *const libc::c_char,
            ) != 0
            {
                if *(*cnf).value as libc::c_int != '@' as i32 {
                    ERR_put_error(
                        20 as libc::c_int,
                        0 as libc::c_int,
                        111 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_cpols.c\0"
                            as *const u8 as *const libc::c_char,
                        263 as libc::c_int as libc::c_uint,
                    );
                    ERR_add_error_data(
                        6 as libc::c_int as libc::c_uint,
                        b"section:\0" as *const u8 as *const libc::c_char,
                        (*cnf).section,
                        b",name:\0" as *const u8 as *const libc::c_char,
                        (*cnf).name,
                        b",value:\0" as *const u8 as *const libc::c_char,
                        (*cnf).value,
                    );
                    current_block = 928128453121088265;
                    break;
                } else {
                    let mut unot: *const stack_st_CONF_VALUE = X509V3_get_section(
                        ctx,
                        ((*cnf).value).offset(1 as libc::c_int as isize),
                    );
                    if unot.is_null() {
                        ERR_put_error(
                            20 as libc::c_int,
                            0 as libc::c_int,
                            134 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_cpols.c\0"
                                as *const u8 as *const libc::c_char,
                            270 as libc::c_int as libc::c_uint,
                        );
                        ERR_add_error_data(
                            6 as libc::c_int as libc::c_uint,
                            b"section:\0" as *const u8 as *const libc::c_char,
                            (*cnf).section,
                            b",name:\0" as *const u8 as *const libc::c_char,
                            (*cnf).name,
                            b",value:\0" as *const u8 as *const libc::c_char,
                            (*cnf).value,
                        );
                        current_block = 928128453121088265;
                        break;
                    } else {
                        qual = notice_section(ctx, unot, ia5org);
                        if qual.is_null() {
                            current_block = 928128453121088265;
                            break;
                        }
                        if ((*pol).qualifiers).is_null() {
                            (*pol).qualifiers = sk_POLICYQUALINFO_new_null();
                        }
                        if sk_POLICYQUALINFO_push((*pol).qualifiers, qual) == 0 {
                            current_block = 928128453121088265;
                            break;
                        }
                    }
                }
            } else {
                ERR_put_error(
                    20 as libc::c_int,
                    0 as libc::c_int,
                    130 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_cpols.c\0"
                        as *const u8 as *const libc::c_char,
                    285 as libc::c_int as libc::c_uint,
                );
                ERR_add_error_data(
                    6 as libc::c_int as libc::c_uint,
                    b"section:\0" as *const u8 as *const libc::c_char,
                    (*cnf).section,
                    b",name:\0" as *const u8 as *const libc::c_char,
                    (*cnf).name,
                    b",value:\0" as *const u8 as *const libc::c_char,
                    (*cnf).value,
                );
                current_block = 928128453121088265;
                break;
            }
            i = i.wrapping_add(1);
            i;
        }
        match current_block {
            928128453121088265 => {}
            _ => {
                if ((*pol).policyid).is_null() {
                    ERR_put_error(
                        20 as libc::c_int,
                        0 as libc::c_int,
                        142 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_cpols.c\0"
                            as *const u8 as *const libc::c_char,
                        292 as libc::c_int as libc::c_uint,
                    );
                } else {
                    return pol
                }
            }
        }
    }
    POLICYINFO_free(pol);
    return 0 as *mut POLICYINFO;
}
unsafe extern "C" fn notice_section(
    mut ctx: *const X509V3_CTX,
    mut unot: *const stack_st_CONF_VALUE,
    mut ia5org: libc::c_int,
) -> *mut POLICYQUALINFO {
    let mut current_block: u64;
    let mut notice: *mut USERNOTICE = 0 as *mut USERNOTICE;
    let mut qual: *mut POLICYQUALINFO = 0 as *mut POLICYQUALINFO;
    qual = POLICYQUALINFO_new();
    if !qual.is_null() {
        (*qual).pqualid = OBJ_nid2obj(165 as libc::c_int);
        if ((*qual).pqualid).is_null() {
            ERR_put_error(
                20 as libc::c_int,
                0 as libc::c_int,
                4 as libc::c_int | 64 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_cpols.c\0"
                    as *const u8 as *const libc::c_char,
                313 as libc::c_int as libc::c_uint,
            );
        } else {
            notice = USERNOTICE_new();
            if !notice.is_null() {
                (*qual).d.usernotice = notice;
                let mut i: size_t = 0 as libc::c_int as size_t;
                loop {
                    if !(i < sk_CONF_VALUE_num(unot)) {
                        current_block = 10758786907990354186;
                        break;
                    }
                    let mut cnf: *const CONF_VALUE = sk_CONF_VALUE_value(unot, i);
                    if strcmp(
                        (*cnf).name,
                        b"explicitText\0" as *const u8 as *const libc::c_char,
                    ) == 0
                    {
                        (*notice).exptext = ASN1_VISIBLESTRING_new();
                        if ((*notice).exptext).is_null() {
                            current_block = 16405847503798288364;
                            break;
                        }
                        if ASN1_STRING_set(
                            (*notice).exptext,
                            (*cnf).value as *const libc::c_void,
                            strlen((*cnf).value) as ossl_ssize_t,
                        ) == 0
                        {
                            current_block = 16405847503798288364;
                            break;
                        }
                    } else if strcmp(
                        (*cnf).name,
                        b"organization\0" as *const u8 as *const libc::c_char,
                    ) == 0
                    {
                        let mut nref: *mut NOTICEREF = 0 as *mut NOTICEREF;
                        if ((*notice).noticeref).is_null() {
                            nref = NOTICEREF_new();
                            if nref.is_null() {
                                current_block = 16405847503798288364;
                                break;
                            }
                            (*notice).noticeref = nref;
                        } else {
                            nref = (*notice).noticeref;
                        }
                        if ia5org != 0 {
                            (*(*nref).organization).type_0 = 22 as libc::c_int;
                        } else {
                            (*(*nref).organization).type_0 = 26 as libc::c_int;
                        }
                        if ASN1_STRING_set(
                            (*nref).organization,
                            (*cnf).value as *const libc::c_void,
                            strlen((*cnf).value) as ossl_ssize_t,
                        ) == 0
                        {
                            current_block = 16405847503798288364;
                            break;
                        }
                    } else if strcmp(
                        (*cnf).name,
                        b"noticeNumbers\0" as *const u8 as *const libc::c_char,
                    ) == 0
                    {
                        let mut nref_0: *mut NOTICEREF = 0 as *mut NOTICEREF;
                        let mut nos: *mut stack_st_CONF_VALUE = 0
                            as *mut stack_st_CONF_VALUE;
                        if ((*notice).noticeref).is_null() {
                            nref_0 = NOTICEREF_new();
                            if nref_0.is_null() {
                                current_block = 16405847503798288364;
                                break;
                            }
                            (*notice).noticeref = nref_0;
                        } else {
                            nref_0 = (*notice).noticeref;
                        }
                        nos = X509V3_parse_list((*cnf).value);
                        if nos.is_null() || sk_CONF_VALUE_num(nos) == 0 {
                            ERR_put_error(
                                20 as libc::c_int,
                                0 as libc::c_int,
                                128 as libc::c_int,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_cpols.c\0"
                                    as *const u8 as *const libc::c_char,
                                362 as libc::c_int as libc::c_uint,
                            );
                            ERR_add_error_data(
                                6 as libc::c_int as libc::c_uint,
                                b"section:\0" as *const u8 as *const libc::c_char,
                                (*cnf).section,
                                b",name:\0" as *const u8 as *const libc::c_char,
                                (*cnf).name,
                                b",value:\0" as *const u8 as *const libc::c_char,
                                (*cnf).value,
                            );
                            current_block = 16405847503798288364;
                            break;
                        } else {
                            let mut ret: libc::c_int = nref_nos(
                                (*nref_0).noticenos,
                                nos,
                            );
                            sk_CONF_VALUE_pop_free(
                                nos,
                                Some(
                                    X509V3_conf_free
                                        as unsafe extern "C" fn(*mut CONF_VALUE) -> (),
                                ),
                            );
                            if ret == 0 {
                                current_block = 16405847503798288364;
                                break;
                            }
                        }
                    } else {
                        ERR_put_error(
                            20 as libc::c_int,
                            0 as libc::c_int,
                            130 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_cpols.c\0"
                                as *const u8 as *const libc::c_char,
                            372 as libc::c_int as libc::c_uint,
                        );
                        ERR_add_error_data(
                            6 as libc::c_int as libc::c_uint,
                            b"section:\0" as *const u8 as *const libc::c_char,
                            (*cnf).section,
                            b",name:\0" as *const u8 as *const libc::c_char,
                            (*cnf).name,
                            b",value:\0" as *const u8 as *const libc::c_char,
                            (*cnf).value,
                        );
                        current_block = 16405847503798288364;
                        break;
                    }
                    i = i.wrapping_add(1);
                    i;
                }
                match current_block {
                    16405847503798288364 => {}
                    _ => {
                        if !((*notice).noticeref).is_null()
                            && (((*(*notice).noticeref).noticenos).is_null()
                                || ((*(*notice).noticeref).organization).is_null())
                        {
                            ERR_put_error(
                                20 as libc::c_int,
                                0 as libc::c_int,
                                138 as libc::c_int,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_cpols.c\0"
                                    as *const u8 as *const libc::c_char,
                                380 as libc::c_int as libc::c_uint,
                            );
                        } else {
                            return qual
                        }
                    }
                }
            }
        }
    }
    POLICYQUALINFO_free(qual);
    return 0 as *mut POLICYQUALINFO;
}
unsafe extern "C" fn nref_nos(
    mut nnums: *mut stack_st_ASN1_INTEGER,
    mut nos: *const stack_st_CONF_VALUE,
) -> libc::c_int {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_CONF_VALUE_num(nos) {
        let mut cnf: *const CONF_VALUE = sk_CONF_VALUE_value(nos, i);
        let mut aint: *mut ASN1_INTEGER = s2i_ASN1_INTEGER(
            0 as *const X509V3_EXT_METHOD,
            (*cnf).name,
        );
        if aint.is_null() {
            ERR_put_error(
                20 as libc::c_int,
                0 as libc::c_int,
                127 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_cpols.c\0"
                    as *const u8 as *const libc::c_char,
                397 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        if sk_ASN1_INTEGER_push(nnums, aint) == 0 {
            ASN1_INTEGER_free(aint);
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn i2r_certpol(
    mut method: *const X509V3_EXT_METHOD,
    mut ext: *mut libc::c_void,
    mut out: *mut BIO,
    mut indent: libc::c_int,
) -> libc::c_int {
    let mut pol: *const stack_st_POLICYINFO = ext as *const stack_st_POLICYINFO;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_POLICYINFO_num(pol) {
        let mut pinfo: *const POLICYINFO = sk_POLICYINFO_value(pol, i);
        BIO_printf(
            out,
            b"%*sPolicy: \0" as *const u8 as *const libc::c_char,
            indent,
            b"\0" as *const u8 as *const libc::c_char,
        );
        i2a_ASN1_OBJECT(out, (*pinfo).policyid);
        BIO_puts(out, b"\n\0" as *const u8 as *const libc::c_char);
        if !((*pinfo).qualifiers).is_null() {
            print_qualifiers(out, (*pinfo).qualifiers, indent + 2 as libc::c_int);
        }
        i = i.wrapping_add(1);
        i;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn print_qualifiers(
    mut out: *mut BIO,
    mut quals: *const stack_st_POLICYQUALINFO,
    mut indent: libc::c_int,
) {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_POLICYQUALINFO_num(quals) {
        let mut qualinfo: *const POLICYQUALINFO = sk_POLICYQUALINFO_value(quals, i);
        match OBJ_obj2nid((*qualinfo).pqualid) {
            164 => {
                BIO_printf(
                    out,
                    b"%*sCPS: %.*s\n\0" as *const u8 as *const libc::c_char,
                    indent,
                    b"\0" as *const u8 as *const libc::c_char,
                    (*(*qualinfo).d.cpsuri).length,
                    (*(*qualinfo).d.cpsuri).data,
                );
            }
            165 => {
                BIO_printf(
                    out,
                    b"%*sUser Notice:\n\0" as *const u8 as *const libc::c_char,
                    indent,
                    b"\0" as *const u8 as *const libc::c_char,
                );
                print_notice(out, (*qualinfo).d.usernotice, indent + 2 as libc::c_int);
            }
            _ => {
                BIO_printf(
                    out,
                    b"%*sUnknown Qualifier: \0" as *const u8 as *const libc::c_char,
                    indent + 2 as libc::c_int,
                    b"\0" as *const u8 as *const libc::c_char,
                );
                i2a_ASN1_OBJECT(out, (*qualinfo).pqualid);
                BIO_puts(out, b"\n\0" as *const u8 as *const libc::c_char);
            }
        }
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn print_notice(
    mut out: *mut BIO,
    mut notice: *const USERNOTICE,
    mut indent: libc::c_int,
) {
    if !((*notice).noticeref).is_null() {
        let mut ref_0: *mut NOTICEREF = 0 as *mut NOTICEREF;
        ref_0 = (*notice).noticeref;
        BIO_printf(
            out,
            b"%*sOrganization: %.*s\n\0" as *const u8 as *const libc::c_char,
            indent,
            b"\0" as *const u8 as *const libc::c_char,
            (*(*ref_0).organization).length,
            (*(*ref_0).organization).data,
        );
        BIO_printf(
            out,
            b"%*sNumber%s: \0" as *const u8 as *const libc::c_char,
            indent,
            b"\0" as *const u8 as *const libc::c_char,
            if sk_ASN1_INTEGER_num((*ref_0).noticenos) > 1 as libc::c_int as size_t {
                b"s\0" as *const u8 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
        );
        let mut i: size_t = 0 as libc::c_int as size_t;
        while i < sk_ASN1_INTEGER_num((*ref_0).noticenos) {
            let mut num: *mut ASN1_INTEGER = 0 as *mut ASN1_INTEGER;
            let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
            num = sk_ASN1_INTEGER_value((*ref_0).noticenos, i);
            if i != 0 {
                BIO_puts(out, b", \0" as *const u8 as *const libc::c_char);
            }
            if num.is_null() {
                BIO_puts(out, b"(null)\0" as *const u8 as *const libc::c_char);
            } else {
                tmp = i2s_ASN1_INTEGER(0 as *const X509V3_EXT_METHOD, num);
                if tmp.is_null() {
                    return;
                }
                BIO_puts(out, tmp);
                OPENSSL_free(tmp as *mut libc::c_void);
            }
            i = i.wrapping_add(1);
            i;
        }
        BIO_puts(out, b"\n\0" as *const u8 as *const libc::c_char);
    }
    if !((*notice).exptext).is_null() {
        BIO_printf(
            out,
            b"%*sExplicit Text: %.*s\n\0" as *const u8 as *const libc::c_char,
            indent,
            b"\0" as *const u8 as *const libc::c_char,
            (*(*notice).exptext).length,
            (*(*notice).exptext).data,
        );
    }
}
unsafe extern "C" fn run_static_initializers() {
    POLICYINFO_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: POLICYINFO_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 2]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<POLICYINFO>() as libc::c_ulong as libc::c_long,
            sname: b"POLICYINFO\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    POLICYQUALINFO_adb = {
        let mut init = ASN1_ADB_st {
            flags: 0 as libc::c_int as uint32_t,
            offset: 0 as libc::c_ulong,
            unused: 0 as *mut ASN1_MUST_BE_NULL,
            tbl: POLICYQUALINFO_adbtbl.as_ptr(),
            tblcount: (::core::mem::size_of::<[ASN1_ADB_TABLE; 2]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_ADB_TABLE>() as libc::c_ulong)
                as libc::c_long,
            default_tt: &policydefault_tt,
            null_tt: 0 as *const ASN1_TEMPLATE,
        };
        init
    };
    POLICYQUALINFO_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: POLICYQUALINFO_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 2]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<POLICYQUALINFO>() as libc::c_ulong
                as libc::c_long,
            sname: b"POLICYQUALINFO\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    USERNOTICE_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: USERNOTICE_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 2]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<USERNOTICE>() as libc::c_ulong as libc::c_long,
            sname: b"USERNOTICE\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    NOTICEREF_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: NOTICEREF_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 2]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<NOTICEREF>() as libc::c_ulong as libc::c_long,
            sname: b"NOTICEREF\0" as *const u8 as *const libc::c_char,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
