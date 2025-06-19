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
    pub type stack_st_ACCESS_DESCRIPTION;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
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
    static ASN1_OBJECT_it: ASN1_ITEM;
    fn i2t_ASN1_OBJECT(
        buf: *mut libc::c_char,
        buf_len: libc::c_int,
        a: *const ASN1_OBJECT,
    ) -> libc::c_int;
    fn X509V3_conf_free(val: *mut CONF_VALUE);
    fn i2v_GENERAL_NAME(
        method: *const X509V3_EXT_METHOD,
        gen: *const GENERAL_NAME,
        ret: *mut stack_st_CONF_VALUE,
    ) -> *mut stack_st_CONF_VALUE;
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
    fn OPENSSL_sk_pop_free_ex(
        sk: *mut OPENSSL_STACK,
        call_free_func: OPENSSL_sk_call_free_func,
        free_func: OPENSSL_sk_free_func,
    );
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_strndup(str: *const libc::c_char, size: size_t) -> *mut libc::c_char;
    fn OPENSSL_strlcpy(
        dst: *mut libc::c_char,
        src: *const libc::c_char,
        dst_size: size_t,
    ) -> size_t;
    fn OPENSSL_strlcat(
        dst: *mut libc::c_char,
        src: *const libc::c_char,
        dst_size: size_t,
    ) -> size_t;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn ERR_add_error_data(count: libc::c_uint, _: ...);
    fn OBJ_txt2obj(
        s: *const libc::c_char,
        dont_search_names: libc::c_int,
    ) -> *mut ASN1_OBJECT;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ACCESS_DESCRIPTION_st {
    pub method: *mut ASN1_OBJECT,
    pub location: *mut GENERAL_NAME,
}
pub type ACCESS_DESCRIPTION = ACCESS_DESCRIPTION_st;
pub type sk_ACCESS_DESCRIPTION_free_func = Option::<
    unsafe extern "C" fn(*mut ACCESS_DESCRIPTION) -> (),
>;
pub type AUTHORITY_INFO_ACCESS = stack_st_ACCESS_DESCRIPTION;
#[inline]
unsafe extern "C" fn sk_ACCESS_DESCRIPTION_pop_free(
    mut sk: *mut stack_st_ACCESS_DESCRIPTION,
    mut free_func: sk_ACCESS_DESCRIPTION_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_ACCESS_DESCRIPTION_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_ACCESS_DESCRIPTION_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_ACCESS_DESCRIPTION_push(
    mut sk: *mut stack_st_ACCESS_DESCRIPTION,
    mut p: *mut ACCESS_DESCRIPTION,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_ACCESS_DESCRIPTION_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<
        OPENSSL_sk_free_func,
        sk_ACCESS_DESCRIPTION_free_func,
    >(free_func))
        .expect("non-null function pointer")(ptr as *mut ACCESS_DESCRIPTION);
}
#[inline]
unsafe extern "C" fn sk_ACCESS_DESCRIPTION_new_null() -> *mut stack_st_ACCESS_DESCRIPTION {
    return OPENSSL_sk_new_null() as *mut stack_st_ACCESS_DESCRIPTION;
}
#[inline]
unsafe extern "C" fn sk_ACCESS_DESCRIPTION_num(
    mut sk: *const stack_st_ACCESS_DESCRIPTION,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_ACCESS_DESCRIPTION_value(
    mut sk: *const stack_st_ACCESS_DESCRIPTION,
    mut i: size_t,
) -> *mut ACCESS_DESCRIPTION {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut ACCESS_DESCRIPTION;
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
unsafe extern "C" fn sk_CONF_VALUE_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<OPENSSL_sk_free_func, sk_CONF_VALUE_free_func>(free_func))
        .expect("non-null function pointer")(ptr as *mut CONF_VALUE);
}
#[inline]
unsafe extern "C" fn sk_CONF_VALUE_new_null() -> *mut stack_st_CONF_VALUE {
    return OPENSSL_sk_new_null() as *mut stack_st_CONF_VALUE;
}
#[inline]
unsafe extern "C" fn sk_CONF_VALUE_num(mut sk: *const stack_st_CONF_VALUE) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[no_mangle]
pub static mut v3_info: X509V3_EXT_METHOD = unsafe {
    {
        let mut init = v3_ext_method {
            ext_nid: 177 as libc::c_int,
            ext_flags: 0x4 as libc::c_int,
            it: &AUTHORITY_INFO_ACCESS_it as *const ASN1_ITEM,
            ext_new: None,
            ext_free: None,
            d2i: None,
            i2d: None,
            i2s: None,
            s2i: None,
            i2v: Some(
                i2v_AUTHORITY_INFO_ACCESS
                    as unsafe extern "C" fn(
                        *const X509V3_EXT_METHOD,
                        *mut libc::c_void,
                        *mut stack_st_CONF_VALUE,
                    ) -> *mut stack_st_CONF_VALUE,
            ),
            v2i: Some(
                v2i_AUTHORITY_INFO_ACCESS
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
#[no_mangle]
pub static mut v3_sinfo: X509V3_EXT_METHOD = unsafe {
    {
        let mut init = v3_ext_method {
            ext_nid: 398 as libc::c_int,
            ext_flags: 0x4 as libc::c_int,
            it: &AUTHORITY_INFO_ACCESS_it as *const ASN1_ITEM,
            ext_new: None,
            ext_free: None,
            d2i: None,
            i2d: None,
            i2s: None,
            s2i: None,
            i2v: Some(
                i2v_AUTHORITY_INFO_ACCESS
                    as unsafe extern "C" fn(
                        *const X509V3_EXT_METHOD,
                        *mut libc::c_void,
                        *mut stack_st_CONF_VALUE,
                    ) -> *mut stack_st_CONF_VALUE,
            ),
            v2i: Some(
                v2i_AUTHORITY_INFO_ACCESS
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
static mut ACCESS_DESCRIPTION_seq_tt: [ASN1_TEMPLATE; 2] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"method\0" as *const u8 as *const libc::c_char,
                item: &ASN1_OBJECT_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"location\0" as *const u8 as *const libc::c_char,
                item: &GENERAL_NAME_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut ACCESS_DESCRIPTION_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[no_mangle]
pub unsafe extern "C" fn ACCESS_DESCRIPTION_free(mut a: *mut ACCESS_DESCRIPTION) {
    ASN1_item_free(a as *mut ASN1_VALUE, &ACCESS_DESCRIPTION_it);
}
#[no_mangle]
pub unsafe extern "C" fn ACCESS_DESCRIPTION_new() -> *mut ACCESS_DESCRIPTION {
    return ASN1_item_new(&ACCESS_DESCRIPTION_it) as *mut ACCESS_DESCRIPTION;
}
static mut AUTHORITY_INFO_ACCESS_item_tt: ASN1_TEMPLATE = unsafe {
    {
        let mut init = ASN1_TEMPLATE_st {
            flags: ((0x2 as libc::c_int) << 1 as libc::c_int) as uint32_t,
            tag: 0 as libc::c_int,
            offset: 0 as libc::c_int as libc::c_ulong,
            field_name: b"GeneralNames\0" as *const u8 as *const libc::c_char,
            item: &ACCESS_DESCRIPTION_it as *const ASN1_ITEM,
        };
        init
    }
};
#[no_mangle]
pub static mut AUTHORITY_INFO_ACCESS_it: ASN1_ITEM = unsafe {
    {
        let mut init = ASN1_ITEM_st {
            itype: 0 as libc::c_int as libc::c_char,
            utype: -(1 as libc::c_int),
            templates: &AUTHORITY_INFO_ACCESS_item_tt as *const ASN1_TEMPLATE,
            tcount: 0 as libc::c_int as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: 0 as libc::c_int as libc::c_long,
            sname: b"AUTHORITY_INFO_ACCESS\0" as *const u8 as *const libc::c_char,
        };
        init
    }
};
#[no_mangle]
pub unsafe extern "C" fn i2d_AUTHORITY_INFO_ACCESS(
    mut a: *mut AUTHORITY_INFO_ACCESS,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &AUTHORITY_INFO_ACCESS_it);
}
#[no_mangle]
pub unsafe extern "C" fn AUTHORITY_INFO_ACCESS_free(mut a: *mut AUTHORITY_INFO_ACCESS) {
    ASN1_item_free(a as *mut ASN1_VALUE, &AUTHORITY_INFO_ACCESS_it);
}
#[no_mangle]
pub unsafe extern "C" fn AUTHORITY_INFO_ACCESS_new() -> *mut AUTHORITY_INFO_ACCESS {
    return ASN1_item_new(&AUTHORITY_INFO_ACCESS_it) as *mut AUTHORITY_INFO_ACCESS;
}
#[no_mangle]
pub unsafe extern "C" fn d2i_AUTHORITY_INFO_ACCESS(
    mut a: *mut *mut AUTHORITY_INFO_ACCESS,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut AUTHORITY_INFO_ACCESS {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &AUTHORITY_INFO_ACCESS_it)
        as *mut AUTHORITY_INFO_ACCESS;
}
unsafe extern "C" fn i2v_AUTHORITY_INFO_ACCESS(
    mut method: *const X509V3_EXT_METHOD,
    mut ext: *mut libc::c_void,
    mut ret: *mut stack_st_CONF_VALUE,
) -> *mut stack_st_CONF_VALUE {
    let mut current_block: u64;
    let mut ainfo: *const AUTHORITY_INFO_ACCESS = ext as *const AUTHORITY_INFO_ACCESS;
    let mut desc: *mut ACCESS_DESCRIPTION = 0 as *mut ACCESS_DESCRIPTION;
    let mut nlen: libc::c_int = 0;
    let mut objtmp: [libc::c_char; 80] = [0; 80];
    let mut ntmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut vtmp: *mut CONF_VALUE = 0 as *mut CONF_VALUE;
    let mut tret: *mut stack_st_CONF_VALUE = ret;
    let mut i: size_t = 0 as libc::c_int as size_t;
    loop {
        if !(i < sk_ACCESS_DESCRIPTION_num(ainfo)) {
            current_block = 17860125682698302841;
            break;
        }
        let mut tmp: *mut stack_st_CONF_VALUE = 0 as *mut stack_st_CONF_VALUE;
        desc = sk_ACCESS_DESCRIPTION_value(ainfo, i);
        tmp = i2v_GENERAL_NAME(method, (*desc).location, tret);
        if tmp.is_null() {
            current_block = 3428876297151359101;
            break;
        }
        tret = tmp;
        vtmp = sk_CONF_VALUE_value(tret, i);
        i2t_ASN1_OBJECT(
            objtmp.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 80]>() as libc::c_ulong as libc::c_int,
            (*desc).method,
        );
        nlen = (strlen(objtmp.as_mut_ptr()))
            .wrapping_add(strlen((*vtmp).name))
            .wrapping_add(5 as libc::c_int as libc::c_ulong) as libc::c_int;
        ntmp = OPENSSL_malloc(nlen as size_t) as *mut libc::c_char;
        if ntmp.is_null() {
            current_block = 3428876297151359101;
            break;
        }
        OPENSSL_strlcpy(ntmp, objtmp.as_mut_ptr(), nlen as size_t);
        OPENSSL_strlcat(
            ntmp,
            b" - \0" as *const u8 as *const libc::c_char,
            nlen as size_t,
        );
        OPENSSL_strlcat(ntmp, (*vtmp).name, nlen as size_t);
        OPENSSL_free((*vtmp).name as *mut libc::c_void);
        (*vtmp).name = ntmp;
        i = i.wrapping_add(1);
        i;
    }
    match current_block {
        3428876297151359101 => {
            if ret.is_null() && !tret.is_null() {
                sk_CONF_VALUE_pop_free(
                    tret,
                    Some(X509V3_conf_free as unsafe extern "C" fn(*mut CONF_VALUE) -> ()),
                );
            }
            return 0 as *mut stack_st_CONF_VALUE;
        }
        _ => {
            if ret.is_null() && tret.is_null() {
                return sk_CONF_VALUE_new_null();
            }
            return tret;
        }
    };
}
unsafe extern "C" fn v2i_AUTHORITY_INFO_ACCESS(
    mut method: *const X509V3_EXT_METHOD,
    mut ctx: *const X509V3_CTX,
    mut nval: *const stack_st_CONF_VALUE,
) -> *mut libc::c_void {
    let mut current_block: u64;
    let mut ainfo: *mut AUTHORITY_INFO_ACCESS = 0 as *mut AUTHORITY_INFO_ACCESS;
    let mut acc: *mut ACCESS_DESCRIPTION = 0 as *mut ACCESS_DESCRIPTION;
    ainfo = sk_ACCESS_DESCRIPTION_new_null();
    if ainfo.is_null() {
        return 0 as *mut libc::c_void;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    loop {
        if !(i < sk_CONF_VALUE_num(nval)) {
            current_block = 5948590327928692120;
            break;
        }
        let mut cnf: *const CONF_VALUE = sk_CONF_VALUE_value(nval, i);
        acc = ACCESS_DESCRIPTION_new();
        if acc.is_null() || sk_ACCESS_DESCRIPTION_push(ainfo, acc) == 0 {
            current_block = 13898672388320790607;
            break;
        }
        let mut ptmp: *mut libc::c_char = strchr((*cnf).name, ';' as i32);
        if ptmp.is_null() {
            ERR_put_error(
                20 as libc::c_int,
                0 as libc::c_int,
                135 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_info.c\0" as *const u8
                    as *const libc::c_char,
                185 as libc::c_int as libc::c_uint,
            );
            current_block = 13898672388320790607;
            break;
        } else {
            let mut ctmp: CONF_VALUE = conf_value_st {
                section: 0 as *mut libc::c_char,
                name: 0 as *mut libc::c_char,
                value: 0 as *mut libc::c_char,
            };
            ctmp.name = ptmp.offset(1 as libc::c_int as isize);
            ctmp.value = (*cnf).value;
            if (v2i_GENERAL_NAME_ex(
                (*acc).location,
                method,
                ctx,
                &mut ctmp,
                0 as libc::c_int,
            ))
                .is_null()
            {
                current_block = 13898672388320790607;
                break;
            }
            let mut objtmp: *mut libc::c_char = OPENSSL_strndup(
                (*cnf).name,
                ptmp.offset_from((*cnf).name) as libc::c_long as size_t,
            );
            if objtmp.is_null() {
                current_block = 13898672388320790607;
                break;
            }
            (*acc).method = OBJ_txt2obj(objtmp, 0 as libc::c_int);
            if ((*acc).method).is_null() {
                ERR_put_error(
                    20 as libc::c_int,
                    0 as libc::c_int,
                    101 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_info.c\0"
                        as *const u8 as *const libc::c_char,
                    200 as libc::c_int as libc::c_uint,
                );
                ERR_add_error_data(
                    2 as libc::c_int as libc::c_uint,
                    b"value=\0" as *const u8 as *const libc::c_char,
                    objtmp,
                );
                OPENSSL_free(objtmp as *mut libc::c_void);
                current_block = 13898672388320790607;
                break;
            } else {
                OPENSSL_free(objtmp as *mut libc::c_void);
                i = i.wrapping_add(1);
                i;
            }
        }
    }
    match current_block {
        5948590327928692120 => return ainfo as *mut libc::c_void,
        _ => {
            sk_ACCESS_DESCRIPTION_pop_free(
                ainfo,
                Some(
                    ACCESS_DESCRIPTION_free
                        as unsafe extern "C" fn(*mut ACCESS_DESCRIPTION) -> (),
                ),
            );
            return 0 as *mut libc::c_void;
        }
    };
}
unsafe extern "C" fn run_static_initializers() {
    ACCESS_DESCRIPTION_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: ACCESS_DESCRIPTION_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 2]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<ACCESS_DESCRIPTION>() as libc::c_ulong
                as libc::c_long,
            sname: b"ACCESS_DESCRIPTION\0" as *const u8 as *const libc::c_char,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
