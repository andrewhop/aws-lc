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
    pub type stack_st_X509V3_EXT_METHOD;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn bsearch(
        __key: *const libc::c_void,
        __base: *const libc::c_void,
        __nmemb: size_t,
        __size: size_t,
        __compar: __compar_fn_t,
    ) -> *mut libc::c_void;
    fn ASN1_item_free(val: *mut ASN1_VALUE, it: *const ASN1_ITEM);
    fn ASN1_item_d2i(
        out: *mut *mut ASN1_VALUE,
        inp: *mut *const libc::c_uchar,
        len: libc::c_long,
        it: *const ASN1_ITEM,
    ) -> *mut ASN1_VALUE;
    fn X509_EXTENSION_free(ex: *mut X509_EXTENSION);
    fn X509_EXTENSION_get_critical(ex: *const X509_EXTENSION) -> libc::c_int;
    fn X509v3_get_ext_by_NID(
        x: *const stack_st_X509_EXTENSION,
        nid: libc::c_int,
        lastpos: libc::c_int,
    ) -> libc::c_int;
    fn X509V3_EXT_i2d(
        ext_nid: libc::c_int,
        crit: libc::c_int,
        ext_struc: *mut libc::c_void,
    ) -> *mut X509_EXTENSION;
    fn OPENSSL_sk_new(comp: OPENSSL_sk_cmp_func) -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_set(
        sk: *mut OPENSSL_STACK,
        i: size_t,
        p: *mut libc::c_void,
    ) -> *mut libc::c_void;
    fn OPENSSL_sk_free(sk: *mut OPENSSL_STACK);
    fn OPENSSL_sk_delete(sk: *mut OPENSSL_STACK, where_0: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_find(
        sk: *const OPENSSL_STACK,
        out_index: *mut size_t,
        p: *const libc::c_void,
        call_cmp_func: OPENSSL_sk_call_cmp_func,
    ) -> libc::c_int;
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn OPENSSL_sk_sort(sk: *mut OPENSSL_STACK, call_cmp_func: OPENSSL_sk_call_cmp_func);
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OBJ_obj2nid(obj: *const ASN1_OBJECT) -> libc::c_int;
    static v3_bcons: X509V3_EXT_METHOD;
    static v3_nscert: X509V3_EXT_METHOD;
    static v3_key_usage: X509V3_EXT_METHOD;
    static v3_ext_ku: X509V3_EXT_METHOD;
    static v3_info: X509V3_EXT_METHOD;
    static v3_sinfo: X509V3_EXT_METHOD;
    static v3_ns_ia5_list: [X509V3_EXT_METHOD; 0];
    static v3_alt: [X509V3_EXT_METHOD; 0];
    static v3_skey_id: X509V3_EXT_METHOD;
    static v3_akey_id: X509V3_EXT_METHOD;
    static v3_crl_num: X509V3_EXT_METHOD;
    static v3_crl_reason: X509V3_EXT_METHOD;
    static v3_crl_invdate: X509V3_EXT_METHOD;
    static v3_delta_crl: X509V3_EXT_METHOD;
    static v3_cpols: X509V3_EXT_METHOD;
    static v3_crld: X509V3_EXT_METHOD;
    static v3_freshest_crl: X509V3_EXT_METHOD;
    static v3_ocsp_nonce: X509V3_EXT_METHOD;
    static v3_ocsp_nocheck: X509V3_EXT_METHOD;
    static v3_policy_mappings: X509V3_EXT_METHOD;
    static v3_policy_constraints: X509V3_EXT_METHOD;
    static v3_name_constraints: X509V3_EXT_METHOD;
    static v3_inhibit_anyp: X509V3_EXT_METHOD;
    static v3_idp: X509V3_EXT_METHOD;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type __compar_fn_t = Option::<
    unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> libc::c_int,
>;
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
pub type OPENSSL_sk_cmp_func = Option::<
    unsafe extern "C" fn(
        *const *const libc::c_void,
        *const *const libc::c_void,
    ) -> libc::c_int,
>;
pub type OPENSSL_sk_call_cmp_func = Option::<
    unsafe extern "C" fn(
        OPENSSL_sk_cmp_func,
        *const libc::c_void,
        *const libc::c_void,
    ) -> libc::c_int,
>;
pub type OPENSSL_STACK = stack_st;
pub type sk_X509V3_EXT_METHOD_cmp_func = Option::<
    unsafe extern "C" fn(
        *const *const X509V3_EXT_METHOD,
        *const *const X509V3_EXT_METHOD,
    ) -> libc::c_int,
>;
#[inline]
unsafe extern "C" fn sk_X509_EXTENSION_new_null() -> *mut stack_st_X509_EXTENSION {
    return OPENSSL_sk_new_null() as *mut stack_st_X509_EXTENSION;
}
#[inline]
unsafe extern "C" fn sk_X509_EXTENSION_num(
    mut sk: *const stack_st_X509_EXTENSION,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_EXTENSION_value(
    mut sk: *const stack_st_X509_EXTENSION,
    mut i: size_t,
) -> *mut X509_EXTENSION {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509_EXTENSION;
}
#[inline]
unsafe extern "C" fn sk_X509_EXTENSION_set(
    mut sk: *mut stack_st_X509_EXTENSION,
    mut i: size_t,
    mut p: *mut X509_EXTENSION,
) -> *mut X509_EXTENSION {
    return OPENSSL_sk_set(sk as *mut OPENSSL_STACK, i, p as *mut libc::c_void)
        as *mut X509_EXTENSION;
}
#[inline]
unsafe extern "C" fn sk_X509_EXTENSION_free(mut sk: *mut stack_st_X509_EXTENSION) {
    OPENSSL_sk_free(sk as *mut OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_EXTENSION_delete(
    mut sk: *mut stack_st_X509_EXTENSION,
    mut where_0: size_t,
) -> *mut X509_EXTENSION {
    return OPENSSL_sk_delete(sk as *mut OPENSSL_STACK, where_0) as *mut X509_EXTENSION;
}
#[inline]
unsafe extern "C" fn sk_X509_EXTENSION_push(
    mut sk: *mut stack_st_X509_EXTENSION,
    mut p: *mut X509_EXTENSION,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
static mut standard_exts: [*const X509V3_EXT_METHOD; 32] = [0
    as *const X509V3_EXT_METHOD; 32];
#[inline]
unsafe extern "C" fn sk_X509V3_EXT_METHOD_sort(mut sk: *mut stack_st_X509V3_EXT_METHOD) {
    OPENSSL_sk_sort(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_X509V3_EXT_METHOD_call_cmp_func
                as unsafe extern "C" fn(
                    OPENSSL_sk_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
}
#[inline]
unsafe extern "C" fn sk_X509V3_EXT_METHOD_push(
    mut sk: *mut stack_st_X509V3_EXT_METHOD,
    mut p: *mut X509V3_EXT_METHOD,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_X509V3_EXT_METHOD_new(
    mut comp: sk_X509V3_EXT_METHOD_cmp_func,
) -> *mut stack_st_X509V3_EXT_METHOD {
    return OPENSSL_sk_new(
        ::core::mem::transmute::<
            sk_X509V3_EXT_METHOD_cmp_func,
            OPENSSL_sk_cmp_func,
        >(comp),
    ) as *mut stack_st_X509V3_EXT_METHOD;
}
#[inline]
unsafe extern "C" fn sk_X509V3_EXT_METHOD_value(
    mut sk: *const stack_st_X509V3_EXT_METHOD,
    mut i: size_t,
) -> *mut X509V3_EXT_METHOD {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509V3_EXT_METHOD;
}
#[inline]
unsafe extern "C" fn sk_X509V3_EXT_METHOD_find_awslc(
    mut sk: *const stack_st_X509V3_EXT_METHOD,
    mut out_index: *mut size_t,
    mut p: *const X509V3_EXT_METHOD,
) -> libc::c_int {
    return OPENSSL_sk_find(
        sk as *const OPENSSL_STACK,
        out_index,
        p as *const libc::c_void,
        Some(
            sk_X509V3_EXT_METHOD_call_cmp_func
                as unsafe extern "C" fn(
                    OPENSSL_sk_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
}
#[inline]
unsafe extern "C" fn sk_X509V3_EXT_METHOD_call_cmp_func(
    mut cmp_func: OPENSSL_sk_cmp_func,
    mut a: *const libc::c_void,
    mut b: *const libc::c_void,
) -> libc::c_int {
    let mut a_ptr: *const X509V3_EXT_METHOD = a as *const X509V3_EXT_METHOD;
    let mut b_ptr: *const X509V3_EXT_METHOD = b as *const X509V3_EXT_METHOD;
    return (::core::mem::transmute::<
        OPENSSL_sk_cmp_func,
        sk_X509V3_EXT_METHOD_cmp_func,
    >(cmp_func))
        .expect("non-null function pointer")(&mut a_ptr, &mut b_ptr);
}
static mut ext_list: *mut stack_st_X509V3_EXT_METHOD = 0
    as *const stack_st_X509V3_EXT_METHOD as *mut stack_st_X509V3_EXT_METHOD;
unsafe extern "C" fn ext_stack_cmp(
    mut a: *const *const X509V3_EXT_METHOD,
    mut b: *const *const X509V3_EXT_METHOD,
) -> libc::c_int {
    return (**a).ext_nid - (**b).ext_nid;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509V3_EXT_add(mut ext: *mut X509V3_EXT_METHOD) -> libc::c_int {
    if !((*ext).it).is_null() {} else {
        __assert_fail(
            b"ext->it != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_lib.c\0" as *const u8
                as *const libc::c_char,
            84 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 40],
                &[libc::c_char; 40],
            >(b"int X509V3_EXT_add(X509V3_EXT_METHOD *)\0"))
                .as_ptr(),
        );
    }
    'c_23272: {
        if !((*ext).it).is_null() {} else {
            __assert_fail(
                b"ext->it != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_lib.c\0" as *const u8
                    as *const libc::c_char,
                84 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 40],
                    &[libc::c_char; 40],
                >(b"int X509V3_EXT_add(X509V3_EXT_METHOD *)\0"))
                    .as_ptr(),
            );
        }
    };
    if ext_list.is_null()
        && {
            ext_list = sk_X509V3_EXT_METHOD_new(
                Some(
                    ext_stack_cmp
                        as unsafe extern "C" fn(
                            *const *const X509V3_EXT_METHOD,
                            *const *const X509V3_EXT_METHOD,
                        ) -> libc::c_int,
                ),
            );
            ext_list.is_null()
        }
    {
        return 0 as libc::c_int;
    }
    if sk_X509V3_EXT_METHOD_push(ext_list, ext) == 0 {
        return 0 as libc::c_int;
    }
    sk_X509V3_EXT_METHOD_sort(ext_list);
    return 1 as libc::c_int;
}
unsafe extern "C" fn ext_cmp(
    mut void_a: *const libc::c_void,
    mut void_b: *const libc::c_void,
) -> libc::c_int {
    let mut a: *mut *const X509V3_EXT_METHOD = void_a as *mut *const X509V3_EXT_METHOD;
    let mut b: *mut *const X509V3_EXT_METHOD = void_b as *mut *const X509V3_EXT_METHOD;
    return ext_stack_cmp(a, b);
}
unsafe extern "C" fn x509v3_ext_method_validate(
    mut ext_method: *const X509V3_EXT_METHOD,
) -> libc::c_int {
    if ext_method.is_null() {
        return 0 as libc::c_int;
    }
    if (*ext_method).ext_nid == 366 as libc::c_int && ((*ext_method).d2i).is_some()
        && ((*ext_method).i2d).is_some() && ((*ext_method).ext_new).is_some()
        && ((*ext_method).ext_free).is_some()
    {
        return 1 as libc::c_int;
    }
    if ((*ext_method).it).is_null() {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            147 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_lib.c\0" as *const u8
                as *const libc::c_char,
            118 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509V3_EXT_get_nid(
    mut nid: libc::c_int,
) -> *const X509V3_EXT_METHOD {
    let mut tmp: X509V3_EXT_METHOD = v3_ext_method {
        ext_nid: 0,
        ext_flags: 0,
        it: 0 as *const ASN1_ITEM_EXP,
        ext_new: None,
        ext_free: None,
        d2i: None,
        i2d: None,
        i2s: None,
        s2i: None,
        i2v: None,
        v2i: None,
        i2r: None,
        r2i: None,
        usr_data: 0 as *const libc::c_void as *mut libc::c_void,
    };
    let mut t: *const X509V3_EXT_METHOD = &mut tmp;
    let mut ret: *const *const X509V3_EXT_METHOD = 0 as *const *const X509V3_EXT_METHOD;
    let mut idx: size_t = 0;
    if nid < 0 as libc::c_int {
        return 0 as *const X509V3_EXT_METHOD;
    }
    tmp.ext_nid = nid;
    ret = bsearch(
        &mut t as *mut *const X509V3_EXT_METHOD as *const libc::c_void,
        standard_exts.as_ptr() as *const libc::c_void,
        (::core::mem::size_of::<[*const X509V3_EXT_METHOD; 32]>() as libc::c_ulong)
            .wrapping_div(
                ::core::mem::size_of::<*mut X509V3_EXT_METHOD>() as libc::c_ulong,
            ),
        ::core::mem::size_of::<*mut X509V3_EXT_METHOD>() as libc::c_ulong,
        Some(
            ext_cmp
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    ) as *const *const X509V3_EXT_METHOD;
    if !ret.is_null() && x509v3_ext_method_validate(*ret) != 0 {
        return *ret;
    }
    if ext_list.is_null() {
        return 0 as *const X509V3_EXT_METHOD;
    }
    if sk_X509V3_EXT_METHOD_find_awslc(ext_list, &mut idx, &mut tmp) == 0 {
        return 0 as *const X509V3_EXT_METHOD;
    }
    let mut method: *const X509V3_EXT_METHOD = sk_X509V3_EXT_METHOD_value(ext_list, idx);
    if !method.is_null() && x509v3_ext_method_validate(method) != 0 {
        return method;
    }
    return 0 as *const X509V3_EXT_METHOD;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509V3_EXT_get(
    mut ext: *const X509_EXTENSION,
) -> *const X509V3_EXT_METHOD {
    let mut nid: libc::c_int = 0;
    if ext.is_null()
        || {
            nid = OBJ_obj2nid((*ext).object);
            nid == 0 as libc::c_int
        }
    {
        return 0 as *const X509V3_EXT_METHOD;
    }
    return X509V3_EXT_get_nid(nid);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn x509v3_ext_free_with_method(
    mut ext_method: *const X509V3_EXT_METHOD,
    mut ext_data: *mut libc::c_void,
) -> libc::c_int {
    if ext_method.is_null() {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_lib.c\0" as *const u8
                as *const libc::c_char,
            164 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if !((*ext_method).it).is_null() {
        ASN1_item_free(ext_data as *mut ASN1_VALUE, (*ext_method).it);
    } else if (*ext_method).ext_nid == 366 as libc::c_int
        && ((*ext_method).ext_free).is_some()
    {
        ((*ext_method).ext_free).expect("non-null function pointer")(ext_data);
    } else {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_lib.c\0" as *const u8
                as *const libc::c_char,
            177 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509V3_EXT_free(
    mut nid: libc::c_int,
    mut ext_data: *mut libc::c_void,
) -> libc::c_int {
    return x509v3_ext_free_with_method(X509V3_EXT_get_nid(nid), ext_data);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509V3_EXT_add_alias(
    mut nid_to: libc::c_int,
    mut nid_from: libc::c_int,
) -> libc::c_int {
    let mut ext: *const X509V3_EXT_METHOD = 0 as *const X509V3_EXT_METHOD;
    let mut tmpext: *mut X509V3_EXT_METHOD = 0 as *mut X509V3_EXT_METHOD;
    ext = X509V3_EXT_get_nid(nid_from);
    if ext.is_null() {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            114 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_lib.c\0" as *const u8
                as *const libc::c_char,
            193 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    tmpext = OPENSSL_malloc(::core::mem::size_of::<X509V3_EXT_METHOD>() as libc::c_ulong)
        as *mut X509V3_EXT_METHOD;
    if tmpext.is_null() {
        return 0 as libc::c_int;
    }
    *tmpext = *ext;
    (*tmpext).ext_nid = nid_to;
    if X509V3_EXT_add(tmpext) == 0 {
        OPENSSL_free(tmpext as *mut libc::c_void);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509V3_add_standard_extensions() -> libc::c_int {
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509V3_EXT_d2i(
    mut ext: *const X509_EXTENSION,
) -> *mut libc::c_void {
    let mut method: *const X509V3_EXT_METHOD = 0 as *const X509V3_EXT_METHOD;
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    method = X509V3_EXT_get(ext);
    if method.is_null() {
        return 0 as *mut libc::c_void;
    }
    p = (*(*ext).value).data;
    let mut ret: *mut libc::c_void = 0 as *mut libc::c_void;
    if !((*method).it).is_null() {
        ret = ASN1_item_d2i(
            0 as *mut *mut ASN1_VALUE,
            &mut p,
            (*(*ext).value).length as libc::c_long,
            (*method).it,
        ) as *mut libc::c_void;
    } else if (*method).ext_nid == 366 as libc::c_int && ((*method).d2i).is_some() {
        ret = ((*method).d2i)
            .expect(
                "non-null function pointer",
            )(0 as *mut libc::c_void, &mut p, (*(*ext).value).length as libc::c_long);
    } else {
        __assert_fail(
            b"0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_lib.c\0" as *const u8
                as *const libc::c_char,
            235 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 45],
                &[libc::c_char; 45],
            >(b"void *X509V3_EXT_d2i(const X509_EXTENSION *)\0"))
                .as_ptr(),
        );
        'c_19007: {
            __assert_fail(
                b"0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_lib.c\0" as *const u8
                    as *const libc::c_char,
                235 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 45],
                    &[libc::c_char; 45],
                >(b"void *X509V3_EXT_d2i(const X509_EXTENSION *)\0"))
                    .as_ptr(),
            );
        };
    }
    if ret.is_null() {
        return 0 as *mut libc::c_void;
    }
    if p
        != ((*(*ext).value).data).offset((*(*ext).value).length as isize)
            as *const libc::c_uchar
    {
        x509v3_ext_free_with_method(method, ret);
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            164 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_lib.c\0" as *const u8
                as *const libc::c_char,
            244 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut libc::c_void;
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509V3_get_d2i(
    mut extensions: *const stack_st_X509_EXTENSION,
    mut nid: libc::c_int,
    mut out_critical: *mut libc::c_int,
    mut out_idx: *mut libc::c_int,
) -> *mut libc::c_void {
    let mut lastpos: libc::c_int = 0;
    let mut ex: *mut X509_EXTENSION = 0 as *mut X509_EXTENSION;
    let mut found_ex: *mut X509_EXTENSION = 0 as *mut X509_EXTENSION;
    if extensions.is_null() {
        if !out_idx.is_null() {
            *out_idx = -(1 as libc::c_int);
        }
        if !out_critical.is_null() {
            *out_critical = -(1 as libc::c_int);
        }
        return 0 as *mut libc::c_void;
    }
    if !out_idx.is_null() {
        lastpos = *out_idx + 1 as libc::c_int;
    } else {
        lastpos = 0 as libc::c_int;
    }
    if lastpos < 0 as libc::c_int {
        lastpos = 0 as libc::c_int;
    }
    let mut i: size_t = lastpos as size_t;
    while i < sk_X509_EXTENSION_num(extensions) {
        ex = sk_X509_EXTENSION_value(extensions, i);
        if OBJ_obj2nid((*ex).object) == nid {
            if !out_idx.is_null() {
                *out_idx = i as libc::c_int;
                found_ex = ex;
                break;
            } else {
                if !found_ex.is_null() {
                    if !out_critical.is_null() {
                        *out_critical = -(2 as libc::c_int);
                    }
                    return 0 as *mut libc::c_void;
                }
                found_ex = ex;
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    if !found_ex.is_null() {
        if !out_critical.is_null() {
            *out_critical = X509_EXTENSION_get_critical(found_ex);
        }
        return X509V3_EXT_d2i(found_ex);
    }
    if !out_idx.is_null() {
        *out_idx = -(1 as libc::c_int);
    }
    if !out_critical.is_null() {
        *out_critical = -(1 as libc::c_int);
    }
    return 0 as *mut libc::c_void;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509V3_add1_i2d(
    mut x: *mut *mut stack_st_X509_EXTENSION,
    mut nid: libc::c_int,
    mut value: *mut libc::c_void,
    mut crit: libc::c_int,
    mut flags: libc::c_ulong,
) -> libc::c_int {
    let mut current_block: u64;
    let mut errcode: libc::c_int = 0;
    let mut extidx: libc::c_int = -(1 as libc::c_int);
    let mut ext: *mut X509_EXTENSION = 0 as *mut X509_EXTENSION;
    let mut extmp: *mut X509_EXTENSION = 0 as *mut X509_EXTENSION;
    let mut ret: *mut stack_st_X509_EXTENSION = 0 as *mut stack_st_X509_EXTENSION;
    let mut ext_op: libc::c_ulong = flags & 0xf as libc::c_long as libc::c_ulong;
    if ext_op != 1 as libc::c_long as libc::c_ulong {
        extidx = X509v3_get_ext_by_NID(*x, nid, -(1 as libc::c_int));
    }
    if extidx >= 0 as libc::c_int {
        if ext_op == 4 as libc::c_long as libc::c_ulong {
            return 1 as libc::c_int;
        }
        if ext_op == 0 as libc::c_long as libc::c_ulong {
            errcode = 112 as libc::c_int;
            current_block = 13314012977420976562;
        } else {
            if ext_op == 5 as libc::c_long as libc::c_ulong {
                let mut prev_ext: *mut X509_EXTENSION = sk_X509_EXTENSION_delete(
                    *x,
                    extidx as size_t,
                );
                if prev_ext.is_null() {
                    return -(1 as libc::c_int);
                }
                X509_EXTENSION_free(prev_ext);
                return 1 as libc::c_int;
            }
            current_block = 15976848397966268834;
        }
    } else if ext_op == 3 as libc::c_long as libc::c_ulong
        || ext_op == 5 as libc::c_long as libc::c_ulong
    {
        errcode = 114 as libc::c_int;
        current_block = 13314012977420976562;
    } else {
        current_block = 15976848397966268834;
    }
    match current_block {
        13314012977420976562 => {
            if flags & 0x10 as libc::c_int as libc::c_ulong == 0 {
                ERR_put_error(
                    20 as libc::c_int,
                    0 as libc::c_int,
                    errcode,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_lib.c\0"
                        as *const u8 as *const libc::c_char,
                    393 as libc::c_int as libc::c_uint,
                );
            }
            return 0 as libc::c_int;
        }
        _ => {
            ext = X509V3_EXT_i2d(nid, crit, value);
            if ext.is_null() {
                ERR_put_error(
                    20 as libc::c_int,
                    0 as libc::c_int,
                    109 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_lib.c\0"
                        as *const u8 as *const libc::c_char,
                    360 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            if extidx >= 0 as libc::c_int {
                extmp = sk_X509_EXTENSION_value(*x, extidx as size_t);
                X509_EXTENSION_free(extmp);
                if (sk_X509_EXTENSION_set(*x, extidx as size_t, ext)).is_null() {
                    return -(1 as libc::c_int);
                }
                return 1 as libc::c_int;
            }
            ret = *x;
            if !(ret.is_null()
                && {
                    ret = sk_X509_EXTENSION_new_null();
                    ret.is_null()
                })
            {
                if !(sk_X509_EXTENSION_push(ret, ext) == 0) {
                    *x = ret;
                    return 1 as libc::c_int;
                }
            }
            if ret != *x {
                sk_X509_EXTENSION_free(ret);
            }
            X509_EXTENSION_free(ext);
            return -(1 as libc::c_int);
        }
    };
}
unsafe extern "C" fn run_static_initializers() {
    standard_exts = [
        &v3_nscert,
        &*v3_ns_ia5_list.as_ptr().offset(0 as libc::c_int as isize)
            as *const X509V3_EXT_METHOD,
        &*v3_ns_ia5_list.as_ptr().offset(1 as libc::c_int as isize)
            as *const X509V3_EXT_METHOD,
        &*v3_ns_ia5_list.as_ptr().offset(2 as libc::c_int as isize)
            as *const X509V3_EXT_METHOD,
        &*v3_ns_ia5_list.as_ptr().offset(3 as libc::c_int as isize)
            as *const X509V3_EXT_METHOD,
        &*v3_ns_ia5_list.as_ptr().offset(4 as libc::c_int as isize)
            as *const X509V3_EXT_METHOD,
        &*v3_ns_ia5_list.as_ptr().offset(5 as libc::c_int as isize)
            as *const X509V3_EXT_METHOD,
        &*v3_ns_ia5_list.as_ptr().offset(6 as libc::c_int as isize)
            as *const X509V3_EXT_METHOD,
        &v3_skey_id,
        &v3_key_usage,
        &*v3_alt.as_ptr().offset(0 as libc::c_int as isize) as *const X509V3_EXT_METHOD,
        &*v3_alt.as_ptr().offset(1 as libc::c_int as isize) as *const X509V3_EXT_METHOD,
        &v3_bcons,
        &v3_crl_num,
        &v3_cpols,
        &v3_akey_id,
        &v3_crld,
        &v3_ext_ku,
        &v3_delta_crl,
        &v3_crl_reason,
        &v3_crl_invdate,
        &v3_info,
        &v3_ocsp_nonce,
        &v3_ocsp_nocheck,
        &v3_sinfo,
        &v3_policy_constraints,
        &v3_name_constraints,
        &v3_policy_mappings,
        &v3_inhibit_anyp,
        &v3_idp,
        &*v3_alt.as_ptr().offset(2 as libc::c_int as isize) as *const X509V3_EXT_METHOD,
        &v3_freshest_crl,
    ];
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
