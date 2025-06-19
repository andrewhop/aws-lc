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
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strncmp(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn ASN1_item_free(val: *mut ASN1_VALUE, it: *const ASN1_ITEM);
    fn ASN1_item_i2d(
        val: *mut ASN1_VALUE,
        outp: *mut *mut libc::c_uchar,
        it: *const ASN1_ITEM,
    ) -> libc::c_int;
    fn ASN1_STRING_set0(
        str: *mut ASN1_STRING,
        data: *mut libc::c_void,
        len: libc::c_int,
    );
    fn ASN1_OCTET_STRING_new() -> *mut ASN1_OCTET_STRING;
    fn ASN1_OCTET_STRING_free(str: *mut ASN1_OCTET_STRING);
    fn ASN1_OBJECT_free(a: *mut ASN1_OBJECT);
    fn ASN1_TYPE_free(a: *mut ASN1_TYPE);
    fn i2d_ASN1_TYPE(in_0: *const ASN1_TYPE, outp: *mut *mut uint8_t) -> libc::c_int;
    fn X509_REQ_add_extensions(
        req: *mut X509_REQ,
        exts: *const stack_st_X509_EXTENSION,
    ) -> libc::c_int;
    fn X509_EXTENSION_free(ex: *mut X509_EXTENSION);
    fn X509_EXTENSION_create_by_NID(
        ex: *mut *mut X509_EXTENSION,
        nid: libc::c_int,
        crit: libc::c_int,
        data: *const ASN1_OCTET_STRING,
    ) -> *mut X509_EXTENSION;
    fn X509_EXTENSION_create_by_OBJ(
        ex: *mut *mut X509_EXTENSION,
        obj: *const ASN1_OBJECT,
        crit: libc::c_int,
        data: *const ASN1_OCTET_STRING,
    ) -> *mut X509_EXTENSION;
    fn X509v3_add_ext(
        x: *mut *mut stack_st_X509_EXTENSION,
        ex: *const X509_EXTENSION,
        loc: libc::c_int,
    ) -> *mut stack_st_X509_EXTENSION;
    fn X509V3_EXT_get_nid(nid: libc::c_int) -> *const X509V3_EXT_METHOD;
    fn X509V3_conf_free(val: *mut CONF_VALUE);
    fn X509V3_parse_list(line: *const libc::c_char) -> *mut stack_st_CONF_VALUE;
    fn ASN1_generate_v3(
        str: *const libc::c_char,
        cnf: *const X509V3_CTX,
    ) -> *mut ASN1_TYPE;
    fn x509v3_hex_to_bytes(
        str: *const libc::c_char,
        len: *mut size_t,
    ) -> *mut libc::c_uchar;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_pop_free_ex(
        sk: *mut OPENSSL_STACK,
        call_free_func: OPENSSL_sk_call_free_func,
        free_func: OPENSSL_sk_free_func,
    );
    fn NCONF_get_section(
        conf: *const CONF,
        section: *const libc::c_char,
    ) -> *const stack_st_CONF_VALUE;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_isspace(c: libc::c_int) -> libc::c_int;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn ERR_add_error_data(count: libc::c_uint, _: ...);
    fn OBJ_sn2nid(short_name: *const libc::c_char) -> libc::c_int;
    fn OBJ_nid2sn(nid: libc::c_int) -> *const libc::c_char;
    fn OBJ_txt2obj(
        s: *const libc::c_char,
        dont_search_names: libc::c_int,
    ) -> *mut ASN1_OBJECT;
}
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type size_t = libc::c_ulong;
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
pub type sk_X509_EXTENSION_free_func = Option::<
    unsafe extern "C" fn(*mut X509_EXTENSION) -> (),
>;
#[inline]
unsafe extern "C" fn sk_X509_EXTENSION_pop_free(
    mut sk: *mut stack_st_X509_EXTENSION,
    mut free_func: sk_X509_EXTENSION_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_X509_EXTENSION_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_X509_EXTENSION_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_X509_EXTENSION_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<
        OPENSSL_sk_free_func,
        sk_X509_EXTENSION_free_func,
    >(free_func))
        .expect("non-null function pointer")(ptr as *mut X509_EXTENSION);
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
#[inline]
unsafe extern "C" fn OPENSSL_memset(
    mut dst: *mut libc::c_void,
    mut c: libc::c_int,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return dst;
    }
    return memset(dst, c, n);
}
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_nconf(
    mut conf: *const CONF,
    mut ctx: *const X509V3_CTX,
    mut name: *const libc::c_char,
    mut value: *const libc::c_char,
) -> *mut X509_EXTENSION {
    let mut ctx_tmp: X509V3_CTX = v3_ext_ctx {
        flags: 0,
        issuer_cert: 0 as *const X509,
        subject_cert: 0 as *const X509,
        subject_req: 0 as *const X509_REQ,
        crl: 0 as *const X509_CRL,
        db: 0 as *const CONF,
    };
    if ctx.is_null() {
        X509V3_set_ctx(
            &mut ctx_tmp,
            0 as *const X509,
            0 as *const X509,
            0 as *const X509_REQ,
            0 as *const X509_CRL,
            0 as libc::c_int,
        );
        X509V3_set_nconf(&mut ctx_tmp, conf);
        ctx = &mut ctx_tmp;
    }
    let mut crit: libc::c_int = v3_check_critical(&mut value);
    let mut ext_type: libc::c_int = v3_check_generic(&mut value);
    if ext_type != 0 as libc::c_int {
        return v3_generic_extension(name, value, crit, ext_type, ctx);
    }
    let mut ret: *mut X509_EXTENSION = do_ext_nconf(
        conf,
        ctx,
        OBJ_sn2nid(name),
        crit,
        value,
    );
    if ret.is_null() {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            110 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_conf.c\0" as *const u8
                as *const libc::c_char,
            102 as libc::c_int as libc::c_uint,
        );
        ERR_add_error_data(
            4 as libc::c_int as libc::c_uint,
            b"name=\0" as *const u8 as *const libc::c_char,
            name,
            b", value=\0" as *const u8 as *const libc::c_char,
            value,
        );
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_nconf_nid(
    mut conf: *const CONF,
    mut ctx: *const X509V3_CTX,
    mut ext_nid: libc::c_int,
    mut value: *const libc::c_char,
) -> *mut X509_EXTENSION {
    let mut ctx_tmp: X509V3_CTX = v3_ext_ctx {
        flags: 0,
        issuer_cert: 0 as *const X509,
        subject_cert: 0 as *const X509,
        subject_req: 0 as *const X509_REQ,
        crl: 0 as *const X509_CRL,
        db: 0 as *const CONF,
    };
    if ctx.is_null() {
        X509V3_set_ctx(
            &mut ctx_tmp,
            0 as *const X509,
            0 as *const X509,
            0 as *const X509_REQ,
            0 as *const X509_CRL,
            0 as libc::c_int,
        );
        X509V3_set_nconf(&mut ctx_tmp, conf);
        ctx = &mut ctx_tmp;
    }
    let mut crit: libc::c_int = v3_check_critical(&mut value);
    let mut ext_type: libc::c_int = v3_check_generic(&mut value);
    if ext_type != 0 as libc::c_int {
        return v3_generic_extension(OBJ_nid2sn(ext_nid), value, crit, ext_type, ctx);
    }
    return do_ext_nconf(conf, ctx, ext_nid, crit, value);
}
unsafe extern "C" fn do_ext_nconf(
    mut conf: *const CONF,
    mut ctx: *const X509V3_CTX,
    mut ext_nid: libc::c_int,
    mut crit: libc::c_int,
    mut value: *const libc::c_char,
) -> *mut X509_EXTENSION {
    let mut method: *const X509V3_EXT_METHOD = 0 as *const X509V3_EXT_METHOD;
    let mut ext: *mut X509_EXTENSION = 0 as *mut X509_EXTENSION;
    let mut nval: *const stack_st_CONF_VALUE = 0 as *const stack_st_CONF_VALUE;
    let mut nval_owned: *mut stack_st_CONF_VALUE = 0 as *mut stack_st_CONF_VALUE;
    let mut ext_struc: *mut libc::c_void = 0 as *mut libc::c_void;
    if ext_nid == 0 as libc::c_int {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            158 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_conf.c\0" as *const u8
                as *const libc::c_char,
            137 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut X509_EXTENSION;
    }
    method = X509V3_EXT_get_nid(ext_nid);
    if method.is_null() {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            157 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_conf.c\0" as *const u8
                as *const libc::c_char,
            141 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut X509_EXTENSION;
    }
    if ((*method).v2i).is_some() {
        if *value as libc::c_int == '@' as i32 {
            if conf.is_null() {
                ERR_put_error(
                    20 as libc::c_int,
                    0 as libc::c_int,
                    139 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_conf.c\0"
                        as *const u8 as *const libc::c_char,
                    151 as libc::c_int as libc::c_uint,
                );
                return 0 as *mut X509_EXTENSION;
            }
            nval = NCONF_get_section(conf, value.offset(1 as libc::c_int as isize));
        } else {
            nval_owned = X509V3_parse_list(value);
            nval = nval_owned;
        }
        if nval.is_null() || sk_CONF_VALUE_num(nval) <= 0 as libc::c_int as size_t {
            ERR_put_error(
                20 as libc::c_int,
                0 as libc::c_int,
                121 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_conf.c\0" as *const u8
                    as *const libc::c_char,
                160 as libc::c_int as libc::c_uint,
            );
            ERR_add_error_data(
                4 as libc::c_int as libc::c_uint,
                b"name=\0" as *const u8 as *const libc::c_char,
                OBJ_nid2sn(ext_nid),
                b",section=\0" as *const u8 as *const libc::c_char,
                value,
            );
            sk_CONF_VALUE_pop_free(
                nval_owned,
                Some(X509V3_conf_free as unsafe extern "C" fn(*mut CONF_VALUE) -> ()),
            );
            return 0 as *mut X509_EXTENSION;
        }
        ext_struc = ((*method).v2i)
            .expect("non-null function pointer")(method, ctx, nval);
        sk_CONF_VALUE_pop_free(
            nval_owned,
            Some(X509V3_conf_free as unsafe extern "C" fn(*mut CONF_VALUE) -> ()),
        );
        if ext_struc.is_null() {
            return 0 as *mut X509_EXTENSION;
        }
    } else if ((*method).s2i).is_some() {
        ext_struc = ((*method).s2i)
            .expect("non-null function pointer")(method, ctx, value);
        if ext_struc.is_null() {
            return 0 as *mut X509_EXTENSION;
        }
    } else if ((*method).r2i).is_some() {
        if ((*ctx).db).is_null() {
            ERR_put_error(
                20 as libc::c_int,
                0 as libc::c_int,
                139 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_conf.c\0" as *const u8
                    as *const libc::c_char,
                180 as libc::c_int as libc::c_uint,
            );
            return 0 as *mut X509_EXTENSION;
        }
        ext_struc = ((*method).r2i)
            .expect("non-null function pointer")(method, ctx, value);
        if ext_struc.is_null() {
            return 0 as *mut X509_EXTENSION;
        }
    } else {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            115 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_conf.c\0" as *const u8
                as *const libc::c_char,
            187 as libc::c_int as libc::c_uint,
        );
        ERR_add_error_data(
            2 as libc::c_int as libc::c_uint,
            b"name=\0" as *const u8 as *const libc::c_char,
            OBJ_nid2sn(ext_nid),
        );
        return 0 as *mut X509_EXTENSION;
    }
    ext = do_ext_i2d(method, ext_nid, crit, ext_struc);
    ASN1_item_free(ext_struc as *mut ASN1_VALUE, (*method).it);
    return ext;
}
unsafe extern "C" fn do_ext_i2d(
    mut method: *const X509V3_EXT_METHOD,
    mut ext_nid: libc::c_int,
    mut crit: libc::c_int,
    mut ext_struc: *mut libc::c_void,
) -> *mut X509_EXTENSION {
    let mut ext_der: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut ext_len: libc::c_int = 0;
    if !((*method).it).is_null() {
        ext_der = 0 as *mut libc::c_uchar;
        ext_len = ASN1_item_i2d(
            ext_struc as *mut ASN1_VALUE,
            &mut ext_der,
            (*method).it,
        );
        if ext_len < 0 as libc::c_int {
            return 0 as *mut X509_EXTENSION;
        }
    } else if (*method).ext_nid == 366 as libc::c_int && ((*method).i2d).is_some() {
        ext_len = ((*method).i2d)
            .expect("non-null function pointer")(ext_struc, 0 as *mut *mut uint8_t);
        ext_der = OPENSSL_malloc(ext_len as size_t) as *mut libc::c_uchar;
        if ext_der.is_null() {
            return 0 as *mut X509_EXTENSION;
        }
        let mut p: *mut libc::c_uchar = ext_der;
        ((*method).i2d).expect("non-null function pointer")(ext_struc, &mut p);
    } else {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            147 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_conf.c\0" as *const u8
                as *const libc::c_char,
            219 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut X509_EXTENSION;
    }
    let mut ext_oct: *mut ASN1_OCTET_STRING = ASN1_OCTET_STRING_new();
    if ext_oct.is_null() {
        OPENSSL_free(ext_der as *mut libc::c_void);
        return 0 as *mut X509_EXTENSION;
    }
    ASN1_STRING_set0(ext_oct, ext_der as *mut libc::c_void, ext_len);
    let mut ext: *mut X509_EXTENSION = X509_EXTENSION_create_by_NID(
        0 as *mut *mut X509_EXTENSION,
        ext_nid,
        crit,
        ext_oct,
    );
    ASN1_OCTET_STRING_free(ext_oct);
    return ext;
}
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_i2d(
    mut ext_nid: libc::c_int,
    mut crit: libc::c_int,
    mut ext_struc: *mut libc::c_void,
) -> *mut X509_EXTENSION {
    let mut method: *const X509V3_EXT_METHOD = 0 as *const X509V3_EXT_METHOD;
    method = X509V3_EXT_get_nid(ext_nid);
    if method.is_null() {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            157 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_conf.c\0" as *const u8
                as *const libc::c_char,
            241 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut X509_EXTENSION;
    }
    return do_ext_i2d(method, ext_nid, crit, ext_struc);
}
unsafe extern "C" fn v3_check_critical(
    mut value: *mut *const libc::c_char,
) -> libc::c_int {
    let mut p: *const libc::c_char = *value;
    if strlen(p) < 9 as libc::c_int as libc::c_ulong
        || strncmp(
            p,
            b"critical,\0" as *const u8 as *const libc::c_char,
            9 as libc::c_int as libc::c_ulong,
        ) != 0
    {
        return 0 as libc::c_int;
    }
    p = p.offset(9 as libc::c_int as isize);
    while OPENSSL_isspace(*p as libc::c_uchar as libc::c_int) != 0 {
        p = p.offset(1);
        p;
    }
    *value = p;
    return 1 as libc::c_int;
}
unsafe extern "C" fn v3_check_generic(
    mut value: *mut *const libc::c_char,
) -> libc::c_int {
    let mut gen_type: libc::c_int = 0 as libc::c_int;
    let mut p: *const libc::c_char = *value;
    if strlen(p) >= 4 as libc::c_int as libc::c_ulong
        && strncmp(
            p,
            b"DER:\0" as *const u8 as *const libc::c_char,
            4 as libc::c_int as libc::c_ulong,
        ) == 0
    {
        p = p.offset(4 as libc::c_int as isize);
        gen_type = 1 as libc::c_int;
    } else if strlen(p) >= 5 as libc::c_int as libc::c_ulong
        && strncmp(
            p,
            b"ASN1:\0" as *const u8 as *const libc::c_char,
            5 as libc::c_int as libc::c_ulong,
        ) == 0
    {
        p = p.offset(5 as libc::c_int as isize);
        gen_type = 2 as libc::c_int;
    } else {
        return 0 as libc::c_int
    }
    while OPENSSL_isspace(*p as libc::c_uchar as libc::c_int) != 0 {
        p = p.offset(1);
        p;
    }
    *value = p;
    return gen_type;
}
unsafe extern "C" fn v3_generic_extension(
    mut ext: *const libc::c_char,
    mut value: *const libc::c_char,
    mut crit: libc::c_int,
    mut gen_type: libc::c_int,
    mut ctx: *const X509V3_CTX,
) -> *mut X509_EXTENSION {
    let mut ext_der: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut ext_len: size_t = 0 as libc::c_int as size_t;
    let mut obj: *mut ASN1_OBJECT = 0 as *mut ASN1_OBJECT;
    let mut oct: *mut ASN1_OCTET_STRING = 0 as *mut ASN1_OCTET_STRING;
    let mut extension: *mut X509_EXTENSION = 0 as *mut X509_EXTENSION;
    obj = OBJ_txt2obj(ext, 0 as libc::c_int);
    if obj.is_null() {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            113 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_conf.c\0" as *const u8
                as *const libc::c_char,
            292 as libc::c_int as libc::c_uint,
        );
        ERR_add_error_data(
            2 as libc::c_int as libc::c_uint,
            b"name=\0" as *const u8 as *const libc::c_char,
            ext,
        );
    } else {
        if gen_type == 1 as libc::c_int {
            ext_der = x509v3_hex_to_bytes(value, &mut ext_len);
        } else if gen_type == 2 as libc::c_int {
            ext_der = generic_asn1(value, ctx, &mut ext_len);
        }
        if ext_der.is_null() {
            ERR_put_error(
                20 as libc::c_int,
                0 as libc::c_int,
                116 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_conf.c\0" as *const u8
                    as *const libc::c_char,
                304 as libc::c_int as libc::c_uint,
            );
            ERR_add_error_data(
                2 as libc::c_int as libc::c_uint,
                b"value=\0" as *const u8 as *const libc::c_char,
                value,
            );
        } else if ext_len > 2147483647 as libc::c_int as size_t {
            ERR_put_error(
                20 as libc::c_int,
                0 as libc::c_int,
                5 as libc::c_int | 64 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_conf.c\0" as *const u8
                    as *const libc::c_char,
                310 as libc::c_int as libc::c_uint,
            );
        } else {
            oct = ASN1_OCTET_STRING_new();
            if !oct.is_null() {
                ASN1_STRING_set0(
                    oct,
                    ext_der as *mut libc::c_void,
                    ext_len as libc::c_int,
                );
                ext_der = 0 as *mut libc::c_uchar;
                extension = X509_EXTENSION_create_by_OBJ(
                    0 as *mut *mut X509_EXTENSION,
                    obj,
                    crit,
                    oct,
                );
            }
        }
    }
    ASN1_OBJECT_free(obj);
    ASN1_OCTET_STRING_free(oct);
    OPENSSL_free(ext_der as *mut libc::c_void);
    return extension;
}
unsafe extern "C" fn generic_asn1(
    mut value: *const libc::c_char,
    mut ctx: *const X509V3_CTX,
    mut ext_len: *mut size_t,
) -> *mut libc::c_uchar {
    let mut typ: *mut ASN1_TYPE = ASN1_generate_v3(value, ctx);
    if typ.is_null() {
        return 0 as *mut libc::c_uchar;
    }
    let mut ext_der: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut len: libc::c_int = i2d_ASN1_TYPE(typ, &mut ext_der);
    ASN1_TYPE_free(typ);
    if len < 0 as libc::c_int {
        return 0 as *mut libc::c_uchar;
    }
    *ext_len = len as size_t;
    return ext_der;
}
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_add_nconf_sk(
    mut conf: *const CONF,
    mut ctx: *const X509V3_CTX,
    mut section: *const libc::c_char,
    mut sk: *mut *mut stack_st_X509_EXTENSION,
) -> libc::c_int {
    let mut nval: *const stack_st_CONF_VALUE = NCONF_get_section(conf, section);
    if nval.is_null() {
        return 0 as libc::c_int;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_CONF_VALUE_num(nval) {
        let mut val: *const CONF_VALUE = sk_CONF_VALUE_value(nval, i);
        let mut ext: *mut X509_EXTENSION = X509V3_EXT_nconf(
            conf,
            ctx,
            (*val).name,
            (*val).value,
        );
        let mut ok: libc::c_int = (!ext.is_null()
            && (sk.is_null()
                || !(X509v3_add_ext(sk, ext, -(1 as libc::c_int))).is_null()))
            as libc::c_int;
        X509_EXTENSION_free(ext);
        if ok == 0 {
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_add_nconf(
    mut conf: *const CONF,
    mut ctx: *const X509V3_CTX,
    mut section: *const libc::c_char,
    mut cert: *mut X509,
) -> libc::c_int {
    let mut sk: *mut *mut stack_st_X509_EXTENSION = 0
        as *mut *mut stack_st_X509_EXTENSION;
    if !cert.is_null() {
        sk = &mut (*(*cert).cert_info).extensions;
    }
    return X509V3_EXT_add_nconf_sk(conf, ctx, section, sk);
}
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_CRL_add_nconf(
    mut conf: *const CONF,
    mut ctx: *const X509V3_CTX,
    mut section: *const libc::c_char,
    mut crl: *mut X509_CRL,
) -> libc::c_int {
    let mut sk: *mut *mut stack_st_X509_EXTENSION = 0
        as *mut *mut stack_st_X509_EXTENSION;
    if !crl.is_null() {
        sk = &mut (*(*crl).crl).extensions;
    }
    return X509V3_EXT_add_nconf_sk(conf, ctx, section, sk);
}
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_REQ_add_nconf(
    mut conf: *const CONF,
    mut ctx: *const X509V3_CTX,
    mut section: *const libc::c_char,
    mut req: *mut X509_REQ,
) -> libc::c_int {
    let mut extlist: *mut stack_st_X509_EXTENSION = 0 as *mut stack_st_X509_EXTENSION;
    let mut sk: *mut *mut stack_st_X509_EXTENSION = 0
        as *mut *mut stack_st_X509_EXTENSION;
    let mut i: libc::c_int = 0;
    if !req.is_null() {
        sk = &mut extlist;
    }
    i = X509V3_EXT_add_nconf_sk(conf, ctx, section, sk);
    if i == 0 || sk.is_null() {
        return i;
    }
    i = X509_REQ_add_extensions(req, extlist);
    sk_X509_EXTENSION_pop_free(
        extlist,
        Some(X509_EXTENSION_free as unsafe extern "C" fn(*mut X509_EXTENSION) -> ()),
    );
    return i;
}
#[no_mangle]
pub unsafe extern "C" fn X509V3_get_section(
    mut ctx: *const X509V3_CTX,
    mut section: *const libc::c_char,
) -> *const stack_st_CONF_VALUE {
    if ((*ctx).db).is_null() {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            147 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_conf.c\0" as *const u8
                as *const libc::c_char,
            415 as libc::c_int as libc::c_uint,
        );
        return 0 as *const stack_st_CONF_VALUE;
    }
    return NCONF_get_section((*ctx).db, section);
}
#[no_mangle]
pub unsafe extern "C" fn X509V3_set_nconf(
    mut ctx: *mut X509V3_CTX,
    mut conf: *const CONF,
) {
    (*ctx).db = conf;
}
#[no_mangle]
pub unsafe extern "C" fn X509V3_set_ctx(
    mut ctx: *mut X509V3_CTX,
    mut issuer: *const X509,
    mut subj: *const X509,
    mut req: *const X509_REQ,
    mut crl: *const X509_CRL,
    mut flags: libc::c_int,
) {
    OPENSSL_memset(
        ctx as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<X509V3_CTX>() as libc::c_ulong,
    );
    (*ctx).issuer_cert = issuer;
    (*ctx).subject_cert = subj;
    (*ctx).crl = crl;
    (*ctx).subject_req = req;
    (*ctx).flags = flags;
}
