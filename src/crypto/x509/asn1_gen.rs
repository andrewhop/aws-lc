#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(extern_types, label_break_value)]
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
    fn ASN1_tag2bit(tag: libc::c_int) -> libc::c_ulong;
    fn ASN1_STRING_free(str: *mut ASN1_STRING);
    fn ASN1_mbstring_ncopy(
        out: *mut *mut ASN1_STRING,
        in_0: *const uint8_t,
        len: ossl_ssize_t,
        inform: libc::c_int,
        mask: libc::c_ulong,
        minsize: ossl_ssize_t,
        maxsize: ossl_ssize_t,
    ) -> libc::c_int;
    fn ASN1_BIT_STRING_new() -> *mut ASN1_BIT_STRING;
    fn ASN1_BIT_STRING_free(str: *mut ASN1_BIT_STRING);
    fn i2c_ASN1_BIT_STRING(
        in_0: *const ASN1_BIT_STRING,
        outp: *mut *mut uint8_t,
    ) -> libc::c_int;
    fn ASN1_BIT_STRING_set_bit(
        str: *mut ASN1_BIT_STRING,
        n: libc::c_int,
        value: libc::c_int,
    ) -> libc::c_int;
    fn ASN1_INTEGER_free(str: *mut ASN1_INTEGER);
    fn i2c_ASN1_INTEGER(
        in_0: *const ASN1_INTEGER,
        outp: *mut *mut uint8_t,
    ) -> libc::c_int;
    fn ASN1_OBJECT_free(a: *mut ASN1_OBJECT);
    fn d2i_ASN1_TYPE(
        out: *mut *mut ASN1_TYPE,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut ASN1_TYPE;
    fn s2i_ASN1_INTEGER(
        method: *const X509V3_EXT_METHOD,
        value: *const libc::c_char,
    ) -> *mut ASN1_INTEGER;
    fn x509v3_hex_to_bytes(
        str: *const libc::c_char,
        len: *mut size_t,
    ) -> *mut libc::c_uchar;
    fn X509V3_bool_from_string(
        str: *const libc::c_char,
        out_bool: *mut ASN1_BOOLEAN,
    ) -> libc::c_int;
    fn X509V3_get_section(
        ctx: *const X509V3_CTX,
        section: *const libc::c_char,
    ) -> *const stack_st_CONF_VALUE;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_skip(cbs: *mut CBS, len: size_t) -> libc::c_int;
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_get_u8(cbs: *mut CBS, out: *mut uint8_t) -> libc::c_int;
    fn CBS_get_last_u8(cbs: *mut CBS, out: *mut uint8_t) -> libc::c_int;
    fn CBS_get_until_first(cbs: *mut CBS, out: *mut CBS, c: uint8_t) -> libc::c_int;
    fn CBS_get_u64_decimal(cbs: *mut CBS, out: *mut uint64_t) -> libc::c_int;
    fn CBS_parse_generalized_time(
        cbs: *const CBS,
        out_tm: *mut tm,
        allow_timezone_offset: libc::c_int,
    ) -> libc::c_int;
    fn CBS_parse_utc_time(
        cbs: *const CBS,
        out_tm: *mut tm,
        allow_timezone_offset: libc::c_int,
    ) -> libc::c_int;
    fn CBB_init(cbb: *mut CBB, initial_capacity: size_t) -> libc::c_int;
    fn CBB_cleanup(cbb: *mut CBB);
    fn CBB_flush(cbb: *mut CBB) -> libc::c_int;
    fn CBB_data(cbb: *const CBB) -> *const uint8_t;
    fn CBB_len(cbb: *const CBB) -> size_t;
    fn CBB_add_asn1(
        cbb: *mut CBB,
        out_contents: *mut CBB,
        tag: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBB_add_bytes(cbb: *mut CBB, data: *const uint8_t, len: size_t) -> libc::c_int;
    fn CBB_add_space(
        cbb: *mut CBB,
        out_data: *mut *mut uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn CBB_add_u8(cbb: *mut CBB, value: uint8_t) -> libc::c_int;
    fn CBB_flush_asn1_set_of(cbb: *mut CBB) -> libc::c_int;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_isspace(c: libc::c_int) -> libc::c_int;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OBJ_txt2obj(
        s: *const libc::c_char,
        dont_search_names: libc::c_int,
    ) -> *mut ASN1_OBJECT;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn CONF_parse_list(
        list: *const libc::c_char,
        sep: libc::c_char,
        remove_whitespace: libc::c_int,
        list_cb: Option::<
            unsafe extern "C" fn(
                *const libc::c_char,
                size_t,
                *mut libc::c_void,
            ) -> libc::c_int,
        >,
        arg: *mut libc::c_void,
    ) -> libc::c_int;
}
pub type ptrdiff_t = libc::c_long;
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type ossl_ssize_t = ptrdiff_t;
pub type CBS_ASN1_TAG = uint32_t;
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
pub struct cbb_st {
    pub child: *mut CBB,
    pub is_child: libc::c_char,
    pub u: C2RustUnnamed_1,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_1 {
    pub base: cbb_buffer_st,
    pub child: cbb_child_st,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct cbb_child_st {
    pub base: *mut cbb_buffer_st,
    pub offset: size_t,
    pub pending_len_len: uint8_t,
    #[bitfield(name = "pending_is_asn1", ty = "libc::c_uint", bits = "0..=0")]
    pub pending_is_asn1: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 6],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct cbb_buffer_st {
    pub buf: *mut uint8_t,
    pub len: size_t,
    pub cap: size_t,
    #[bitfield(name = "can_resize", ty = "libc::c_uint", bits = "0..=0")]
    #[bitfield(name = "error", ty = "libc::c_uint", bits = "1..=1")]
    pub can_resize_error: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
pub type CBB = cbb_st;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct tm {
    pub tm_sec: libc::c_int,
    pub tm_min: libc::c_int,
    pub tm_hour: libc::c_int,
    pub tm_mday: libc::c_int,
    pub tm_mon: libc::c_int,
    pub tm_year: libc::c_int,
    pub tm_wday: libc::c_int,
    pub tm_yday: libc::c_int,
    pub tm_isdst: libc::c_int,
    pub __tm_gmtoff: libc::c_long,
    pub __tm_zone: *const libc::c_char,
}
pub type OPENSSL_STACK = stack_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_2 {
    pub name: *const libc::c_char,
    pub type_0: CBS_ASN1_TAG,
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
#[no_mangle]
pub unsafe extern "C" fn ASN1_generate_v3(
    mut str: *const libc::c_char,
    mut cnf: *const X509V3_CTX,
) -> *mut ASN1_TYPE {
    let mut cbb: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_1 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    if CBB_init(&mut cbb, 0 as libc::c_int as size_t) == 0
        || generate_v3(
            &mut cbb,
            str,
            cnf,
            0 as libc::c_int as CBS_ASN1_TAG,
            1 as libc::c_int,
            0 as libc::c_int,
        ) == 0
    {
        CBB_cleanup(&mut cbb);
        return 0 as *mut ASN1_TYPE;
    }
    if CBB_len(&mut cbb) > (64 as libc::c_int * 1024 as libc::c_int) as size_t {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            177 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0" as *const u8
                as *const libc::c_char,
            115 as libc::c_int as libc::c_uint,
        );
        CBB_cleanup(&mut cbb);
        return 0 as *mut ASN1_TYPE;
    }
    let mut der: *const uint8_t = CBB_data(&mut cbb);
    let mut ret: *mut ASN1_TYPE = d2i_ASN1_TYPE(
        0 as *mut *mut ASN1_TYPE,
        &mut der,
        CBB_len(&mut cbb) as libc::c_long,
    );
    CBB_cleanup(&mut cbb);
    return ret;
}
unsafe extern "C" fn cbs_str_equal(
    mut cbs: *const CBS,
    mut str: *const libc::c_char,
) -> libc::c_int {
    return (CBS_len(cbs) == strlen(str)
        && OPENSSL_memcmp(
            CBS_data(cbs) as *const libc::c_void,
            str as *const libc::c_void,
            strlen(str),
        ) == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn parse_tag(mut cbs: *const CBS) -> CBS_ASN1_TAG {
    let mut copy: CBS = *cbs;
    let mut num: uint64_t = 0;
    if CBS_get_u64_decimal(&mut copy, &mut num) == 0
        || num
            > ((1 as libc::c_uint) << 5 as libc::c_int + 24 as libc::c_int)
                .wrapping_sub(1 as libc::c_int as libc::c_uint) as uint64_t
    {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            145 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0" as *const u8
                as *const libc::c_char,
            138 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int as CBS_ASN1_TAG;
    }
    let mut tag_class: CBS_ASN1_TAG = (0x80 as libc::c_uint) << 24 as libc::c_int;
    let mut c: uint8_t = 0;
    if CBS_get_u8(&mut copy, &mut c) != 0 {
        match c as libc::c_int {
            85 => {
                tag_class = (0 as libc::c_uint) << 24 as libc::c_int;
            }
            65 => {
                tag_class = (0x40 as libc::c_uint) << 24 as libc::c_int;
            }
            80 => {
                tag_class = (0xc0 as libc::c_uint) << 24 as libc::c_int;
            }
            67 => {
                tag_class = (0x80 as libc::c_uint) << 24 as libc::c_int;
            }
            _ => {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    144 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0"
                        as *const u8 as *const libc::c_char,
                    160 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int as CBS_ASN1_TAG;
            }
        }
        if CBS_len(&mut copy) != 0 as libc::c_int as size_t {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                144 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0"
                    as *const u8 as *const libc::c_char,
                165 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int as CBS_ASN1_TAG;
        }
    }
    if tag_class == (0 as libc::c_uint) << 24 as libc::c_int
        && num == 0 as libc::c_int as uint64_t
    {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            145 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0" as *const u8
                as *const libc::c_char,
            173 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int as CBS_ASN1_TAG;
    }
    return tag_class | num as CBS_ASN1_TAG;
}
unsafe extern "C" fn generate_wrapped(
    mut cbb: *mut CBB,
    mut str: *const libc::c_char,
    mut cnf: *const X509V3_CTX,
    mut tag: CBS_ASN1_TAG,
    mut padding: libc::c_int,
    mut format: libc::c_int,
    mut depth: libc::c_int,
) -> libc::c_int {
    let mut child: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_1 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    return (CBB_add_asn1(cbb, &mut child, tag) != 0
        && (padding == 0 || CBB_add_u8(&mut child, 0 as libc::c_int as uint8_t) != 0)
        && generate_v3(
            &mut child,
            str,
            cnf,
            0 as libc::c_int as CBS_ASN1_TAG,
            format,
            depth + 1 as libc::c_int,
        ) != 0 && CBB_flush(cbb) != 0) as libc::c_int;
}
unsafe extern "C" fn generate_v3(
    mut cbb: *mut CBB,
    mut str: *const libc::c_char,
    mut cnf: *const X509V3_CTX,
    mut tag: CBS_ASN1_TAG,
    mut format: libc::c_int,
    mut depth: libc::c_int,
) -> libc::c_int {
    if tag & (0x20 as libc::c_uint) << 24 as libc::c_int
        == 0 as libc::c_int as libc::c_uint
    {} else {
        __assert_fail(
            b"(tag & CBS_ASN1_CONSTRUCTED) == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0" as *const u8
                as *const libc::c_char,
            192 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 81],
                &[libc::c_char; 81],
            >(
                b"int generate_v3(CBB *, const char *, const X509V3_CTX *, CBS_ASN1_TAG, int, int)\0",
            ))
                .as_ptr(),
        );
    }
    'c_32962: {
        if tag & (0x20 as libc::c_uint) << 24 as libc::c_int
            == 0 as libc::c_int as libc::c_uint
        {} else {
            __assert_fail(
                b"(tag & CBS_ASN1_CONSTRUCTED) == 0\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0"
                    as *const u8 as *const libc::c_char,
                192 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 81],
                    &[libc::c_char; 81],
                >(
                    b"int generate_v3(CBB *, const char *, const X509V3_CTX *, CBS_ASN1_TAG, int, int)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if depth > 50 as libc::c_int {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            131 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0" as *const u8
                as *const libc::c_char,
            194 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    loop {
        while *str as libc::c_int != '\0' as i32
            && OPENSSL_isspace(*str as libc::c_uchar as libc::c_int) != 0
        {
            str = str.offset(1);
            str;
        }
        let mut comma: *const libc::c_char = strchr(str, ',' as i32);
        if comma.is_null() {
            break;
        }
        let mut modifier: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        CBS_init(
            &mut modifier,
            str as *const uint8_t,
            comma.offset_from(str) as libc::c_long as size_t,
        );
        loop {
            let mut v: uint8_t = 0;
            let mut copy: CBS = modifier;
            if CBS_get_last_u8(&mut copy, &mut v) == 0
                || OPENSSL_isspace(v as libc::c_int) == 0
            {
                break;
            }
            modifier = copy;
        }
        let mut str_old: *const libc::c_char = str;
        str = comma.offset(1 as libc::c_int as isize);
        let mut name: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        let mut has_value: libc::c_int = CBS_get_until_first(
            &mut modifier,
            &mut name,
            ':' as i32 as uint8_t,
        );
        if has_value != 0 {
            CBS_skip(&mut modifier, 1 as libc::c_int as size_t);
        } else {
            name = modifier;
            CBS_init(&mut modifier, 0 as *const uint8_t, 0 as libc::c_int as size_t);
        }
        if cbs_str_equal(&mut name, b"FORMAT\0" as *const u8 as *const libc::c_char) != 0
            || cbs_str_equal(&mut name, b"FORM\0" as *const u8 as *const libc::c_char)
                != 0
        {
            if cbs_str_equal(
                &mut modifier,
                b"ASCII\0" as *const u8 as *const libc::c_char,
            ) != 0
            {
                format = 1 as libc::c_int;
            } else if cbs_str_equal(
                &mut modifier,
                b"UTF8\0" as *const u8 as *const libc::c_char,
            ) != 0
            {
                format = 2 as libc::c_int;
            } else if cbs_str_equal(
                &mut modifier,
                b"HEX\0" as *const u8 as *const libc::c_char,
            ) != 0
            {
                format = 3 as libc::c_int;
            } else if cbs_str_equal(
                &mut modifier,
                b"BITLIST\0" as *const u8 as *const libc::c_char,
            ) != 0
            {
                format = 4 as libc::c_int;
            } else {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    182 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0"
                        as *const u8 as *const libc::c_char,
                    250 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
        } else if cbs_str_equal(&mut name, b"IMP\0" as *const u8 as *const libc::c_char)
            != 0
            || cbs_str_equal(
                &mut name,
                b"IMPLICIT\0" as *const u8 as *const libc::c_char,
            ) != 0
        {
            if tag != 0 as libc::c_int as CBS_ASN1_TAG {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    131 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0"
                        as *const u8 as *const libc::c_char,
                    256 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            tag = parse_tag(&mut modifier);
            if tag == 0 as libc::c_int as CBS_ASN1_TAG {
                return 0 as libc::c_int;
            }
        } else if cbs_str_equal(&mut name, b"EXP\0" as *const u8 as *const libc::c_char)
            != 0
            || cbs_str_equal(
                &mut name,
                b"EXPLICIT\0" as *const u8 as *const libc::c_char,
            ) != 0
        {
            if tag != 0 as libc::c_int as CBS_ASN1_TAG {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    131 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0"
                        as *const u8 as *const libc::c_char,
                    268 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            tag = parse_tag(&mut modifier);
            return (tag != 0 as libc::c_int as CBS_ASN1_TAG
                && generate_wrapped(
                    cbb,
                    str,
                    cnf,
                    tag | (0x20 as libc::c_uint) << 24 as libc::c_int,
                    0 as libc::c_int,
                    format,
                    depth,
                ) != 0) as libc::c_int;
        } else if cbs_str_equal(
            &mut name,
            b"OCTWRAP\0" as *const u8 as *const libc::c_char,
        ) != 0
        {
            tag = if tag == 0 as libc::c_int as CBS_ASN1_TAG {
                0x4 as libc::c_uint
            } else {
                tag
            };
            return generate_wrapped(cbb, str, cnf, tag, 0 as libc::c_int, format, depth);
        } else if cbs_str_equal(
            &mut name,
            b"BITWRAP\0" as *const u8 as *const libc::c_char,
        ) != 0
        {
            tag = if tag == 0 as libc::c_int as CBS_ASN1_TAG {
                0x3 as libc::c_uint
            } else {
                tag
            };
            return generate_wrapped(cbb, str, cnf, tag, 1 as libc::c_int, format, depth);
        } else if cbs_str_equal(
            &mut name,
            b"SEQWRAP\0" as *const u8 as *const libc::c_char,
        ) != 0
        {
            tag = if tag == 0 as libc::c_int as CBS_ASN1_TAG {
                0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int
            } else {
                tag | (0x20 as libc::c_uint) << 24 as libc::c_int
            };
            tag |= (0x20 as libc::c_uint) << 24 as libc::c_int;
            return generate_wrapped(cbb, str, cnf, tag, 0 as libc::c_int, format, depth);
        } else if cbs_str_equal(
            &mut name,
            b"SETWRAP\0" as *const u8 as *const libc::c_char,
        ) != 0
        {
            tag = if tag == 0 as libc::c_int as CBS_ASN1_TAG {
                0x11 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int
            } else {
                tag | (0x20 as libc::c_uint) << 24 as libc::c_int
            };
            return generate_wrapped(cbb, str, cnf, tag, 0 as libc::c_int, format, depth);
        } else {
            str = str_old;
            break;
        }
    }
    let mut colon: *const libc::c_char = strchr(str, ':' as i32);
    let mut name_0: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut value: *const libc::c_char = 0 as *const libc::c_char;
    let mut has_value_0: libc::c_int = (colon
        != 0 as *mut libc::c_void as *const libc::c_char) as libc::c_int;
    if has_value_0 != 0 {
        CBS_init(
            &mut name_0,
            str as *const uint8_t,
            colon.offset_from(str) as libc::c_long as size_t,
        );
        value = colon.offset(1 as libc::c_int as isize);
    } else {
        CBS_init(&mut name_0, str as *const uint8_t, strlen(str));
        value = b"\0" as *const u8 as *const libc::c_char;
    }
    static mut kTypes: [C2RustUnnamed_2; 33] = [
        {
            let mut init = C2RustUnnamed_2 {
                name: b"BOOL\0" as *const u8 as *const libc::c_char,
                type_0: 0x1 as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"BOOLEAN\0" as *const u8 as *const libc::c_char,
                type_0: 0x1 as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"NULL\0" as *const u8 as *const libc::c_char,
                type_0: 0x5 as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"INT\0" as *const u8 as *const libc::c_char,
                type_0: 0x2 as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"INTEGER\0" as *const u8 as *const libc::c_char,
                type_0: 0x2 as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"ENUM\0" as *const u8 as *const libc::c_char,
                type_0: 0xa as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"ENUMERATED\0" as *const u8 as *const libc::c_char,
                type_0: 0xa as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"OID\0" as *const u8 as *const libc::c_char,
                type_0: 0x6 as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"OBJECT\0" as *const u8 as *const libc::c_char,
                type_0: 0x6 as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"UTCTIME\0" as *const u8 as *const libc::c_char,
                type_0: 0x17 as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"UTC\0" as *const u8 as *const libc::c_char,
                type_0: 0x17 as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"GENERALIZEDTIME\0" as *const u8 as *const libc::c_char,
                type_0: 0x18 as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"GENTIME\0" as *const u8 as *const libc::c_char,
                type_0: 0x18 as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"OCT\0" as *const u8 as *const libc::c_char,
                type_0: 0x4 as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"OCTETSTRING\0" as *const u8 as *const libc::c_char,
                type_0: 0x4 as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"BITSTR\0" as *const u8 as *const libc::c_char,
                type_0: 0x3 as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"BITSTRING\0" as *const u8 as *const libc::c_char,
                type_0: 0x3 as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"UNIVERSALSTRING\0" as *const u8 as *const libc::c_char,
                type_0: 0x1c as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"UNIV\0" as *const u8 as *const libc::c_char,
                type_0: 0x1c as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"IA5\0" as *const u8 as *const libc::c_char,
                type_0: 0x16 as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"IA5STRING\0" as *const u8 as *const libc::c_char,
                type_0: 0x16 as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"UTF8\0" as *const u8 as *const libc::c_char,
                type_0: 0xc as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"UTF8String\0" as *const u8 as *const libc::c_char,
                type_0: 0xc as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"BMP\0" as *const u8 as *const libc::c_char,
                type_0: 0x1e as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"BMPSTRING\0" as *const u8 as *const libc::c_char,
                type_0: 0x1e as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"PRINTABLESTRING\0" as *const u8 as *const libc::c_char,
                type_0: 0x13 as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"PRINTABLE\0" as *const u8 as *const libc::c_char,
                type_0: 0x13 as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"T61\0" as *const u8 as *const libc::c_char,
                type_0: 0x14 as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"T61STRING\0" as *const u8 as *const libc::c_char,
                type_0: 0x14 as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"TELETEXSTRING\0" as *const u8 as *const libc::c_char,
                type_0: 0x14 as libc::c_uint,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"SEQUENCE\0" as *const u8 as *const libc::c_char,
                type_0: 0x10 as libc::c_uint
                    | (0x20 as libc::c_uint) << 24 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"SEQ\0" as *const u8 as *const libc::c_char,
                type_0: 0x10 as libc::c_uint
                    | (0x20 as libc::c_uint) << 24 as libc::c_int,
            };
            init
        },
        {
            let mut init = C2RustUnnamed_2 {
                name: b"SET\0" as *const u8 as *const libc::c_char,
                type_0: 0x11 as libc::c_uint
                    | (0x20 as libc::c_uint) << 24 as libc::c_int,
            };
            init
        },
    ];
    let mut type_0: CBS_ASN1_TAG = 0 as libc::c_int as CBS_ASN1_TAG;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (::core::mem::size_of::<[C2RustUnnamed_2; 33]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<C2RustUnnamed_2>() as libc::c_ulong)
    {
        if cbs_str_equal(&mut name_0, kTypes[i as usize].name) != 0 {
            type_0 = kTypes[i as usize].type_0;
            break;
        } else {
            i = i.wrapping_add(1);
            i;
        }
    }
    if type_0 == 0 as libc::c_int as CBS_ASN1_TAG {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            185 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0" as *const u8
                as *const libc::c_char,
            356 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    tag = if tag == 0 as libc::c_int as CBS_ASN1_TAG {
        type_0
    } else {
        tag | type_0 & (0x20 as libc::c_uint) << 24 as libc::c_int
    };
    let mut child: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_1 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    if CBB_add_asn1(cbb, &mut child, tag) == 0 {
        return 0 as libc::c_int;
    }
    match type_0 {
        5 => {
            if *value as libc::c_int != '\0' as i32 {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    133 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0"
                        as *const u8 as *const libc::c_char,
                    370 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            return CBB_flush(cbb);
        }
        1 => {
            if format != 1 as libc::c_int {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    161 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0"
                        as *const u8 as *const libc::c_char,
                    377 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            let mut boolean: ASN1_BOOLEAN = 0;
            if X509V3_bool_from_string(value, &mut boolean) == 0 {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    125 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0"
                        as *const u8 as *const libc::c_char,
                    382 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            return (CBB_add_u8(
                &mut child,
                (if boolean != 0 { 0xff as libc::c_int } else { 0 as libc::c_int })
                    as uint8_t,
            ) != 0 && CBB_flush(cbb) != 0) as libc::c_int;
        }
        2 | 10 => {
            if format != 1 as libc::c_int {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    139 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0"
                        as *const u8 as *const libc::c_char,
                    391 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            let mut obj: *mut ASN1_INTEGER = s2i_ASN1_INTEGER(
                0 as *const X509V3_EXT_METHOD,
                value,
            );
            if obj.is_null() {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    130 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0"
                        as *const u8 as *const libc::c_char,
                    396 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            let mut len: libc::c_int = i2c_ASN1_INTEGER(obj, 0 as *mut *mut uint8_t);
            let mut out: *mut uint8_t = 0 as *mut uint8_t;
            let mut ok: libc::c_int = (len > 0 as libc::c_int
                && CBB_add_space(&mut child, &mut out, len as size_t) != 0
                && i2c_ASN1_INTEGER(obj, &mut out) == len && CBB_flush(cbb) != 0)
                as libc::c_int;
            ASN1_INTEGER_free(obj);
            return ok;
        }
        6 => {
            if format != 1 as libc::c_int {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    165 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0"
                        as *const u8 as *const libc::c_char,
                    411 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            let mut obj_0: *mut ASN1_OBJECT = OBJ_txt2obj(value, 0 as libc::c_int);
            if obj_0.is_null() || (*obj_0).length == 0 as libc::c_int {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    134 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0"
                        as *const u8 as *const libc::c_char,
                    416 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            let mut ok_0: libc::c_int = (CBB_add_bytes(
                &mut child,
                (*obj_0).data,
                (*obj_0).length as size_t,
            ) != 0 && CBB_flush(cbb) != 0) as libc::c_int;
            ASN1_OBJECT_free(obj_0);
            return ok_0;
        }
        23 | 24 => {
            if format != 1 as libc::c_int {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    176 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0"
                        as *const u8 as *const libc::c_char,
                    427 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            let mut value_cbs: CBS = cbs_st {
                data: 0 as *const uint8_t,
                len: 0,
            };
            CBS_init(&mut value_cbs, value as *const uint8_t, strlen(value));
            let mut ok_1: libc::c_int = if type_0 == 0x17 as libc::c_uint {
                CBS_parse_utc_time(&mut value_cbs, 0 as *mut tm, 0 as libc::c_int)
            } else {
                CBS_parse_generalized_time(
                    &mut value_cbs,
                    0 as *mut tm,
                    0 as libc::c_int,
                )
            };
            if ok_1 == 0 {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    138 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0"
                        as *const u8 as *const libc::c_char,
                    438 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            return (CBB_add_bytes(&mut child, value as *const uint8_t, strlen(value))
                != 0 && CBB_flush(cbb) != 0) as libc::c_int;
        }
        28 | 22 | 12 | 30 | 19 | 20 => {
            let mut encoding: libc::c_int = 0;
            if format == 1 as libc::c_int {
                encoding = 0x1000 as libc::c_int | 1 as libc::c_int;
            } else if format == 2 as libc::c_int {
                encoding = 0x1000 as libc::c_int;
            } else {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    127 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0"
                        as *const u8 as *const libc::c_char,
                    457 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            let mut obj_1: *mut ASN1_STRING = 0 as *mut ASN1_STRING;
            if ASN1_mbstring_ncopy(
                &mut obj_1,
                value as *const uint8_t,
                -(1 as libc::c_int) as ossl_ssize_t,
                encoding,
                ASN1_tag2bit(type_0 as libc::c_int),
                0 as libc::c_int as ossl_ssize_t,
                (64 as libc::c_int * 1024 as libc::c_int) as ossl_ssize_t,
            ) <= 0 as libc::c_int
            {
                return 0 as libc::c_int;
            }
            let mut ok_2: libc::c_int = (CBB_add_bytes(
                &mut child,
                (*obj_1).data,
                (*obj_1).length as size_t,
            ) != 0 && CBB_flush(cbb) != 0) as libc::c_int;
            ASN1_STRING_free(obj_1);
            return ok_2;
        }
        3 => {
            if format == 4 as libc::c_int {
                let mut obj_2: *mut ASN1_BIT_STRING = ASN1_BIT_STRING_new();
                if obj_2.is_null() {
                    return 0 as libc::c_int;
                }
                if CONF_parse_list(
                    value,
                    ',' as i32 as libc::c_char,
                    1 as libc::c_int,
                    Some(
                        bitstr_cb
                            as unsafe extern "C" fn(
                                *const libc::c_char,
                                size_t,
                                *mut libc::c_void,
                            ) -> libc::c_int,
                    ),
                    obj_2 as *mut libc::c_void,
                ) == 0
                {
                    ERR_put_error(
                        12 as libc::c_int,
                        0 as libc::c_int,
                        151 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0"
                            as *const u8 as *const libc::c_char,
                        483 as libc::c_int as libc::c_uint,
                    );
                    ASN1_BIT_STRING_free(obj_2);
                    return 0 as libc::c_int;
                }
                let mut len_0: libc::c_int = i2c_ASN1_BIT_STRING(
                    obj_2,
                    0 as *mut *mut uint8_t,
                );
                let mut out_0: *mut uint8_t = 0 as *mut uint8_t;
                let mut ok_3: libc::c_int = (len_0 > 0 as libc::c_int
                    && CBB_add_space(&mut child, &mut out_0, len_0 as size_t) != 0
                    && i2c_ASN1_BIT_STRING(obj_2, &mut out_0) == len_0
                    && CBB_flush(cbb) != 0) as libc::c_int;
                ASN1_BIT_STRING_free(obj_2);
                return ok_3;
            }
            if CBB_add_u8(&mut child, 0 as libc::c_int as uint8_t) == 0 {
                return 0 as libc::c_int;
            }
        }
        4 => {}
        536870928 | 536870929 => {
            if has_value_0 != 0 {
                if cnf.is_null() {
                    ERR_put_error(
                        12 as libc::c_int,
                        0 as libc::c_int,
                        170 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0"
                            as *const u8 as *const libc::c_char,
                        528 as libc::c_int as libc::c_uint,
                    );
                    return 0 as libc::c_int;
                }
                let mut section: *const stack_st_CONF_VALUE = X509V3_get_section(
                    cnf,
                    value,
                );
                if section.is_null() {
                    ERR_put_error(
                        12 as libc::c_int,
                        0 as libc::c_int,
                        170 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0"
                            as *const u8 as *const libc::c_char,
                        533 as libc::c_int as libc::c_uint,
                    );
                    return 0 as libc::c_int;
                }
                let mut i_0: size_t = 0 as libc::c_int as size_t;
                while i_0 < sk_CONF_VALUE_num(section) {
                    let mut conf: *const CONF_VALUE = sk_CONF_VALUE_value(section, i_0);
                    if generate_v3(
                        &mut child,
                        (*conf).value,
                        cnf,
                        0 as libc::c_int as CBS_ASN1_TAG,
                        1 as libc::c_int,
                        depth + 1 as libc::c_int,
                    ) == 0
                    {
                        return 0 as libc::c_int;
                    }
                    if CBB_len(&mut child)
                        > (64 as libc::c_int * 1024 as libc::c_int) as size_t
                    {
                        ERR_put_error(
                            12 as libc::c_int,
                            0 as libc::c_int,
                            177 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0"
                                as *const u8 as *const libc::c_char,
                            546 as libc::c_int as libc::c_uint,
                        );
                        return 0 as libc::c_int;
                    }
                    i_0 = i_0.wrapping_add(1);
                    i_0;
                }
            }
            if type_0
                == 0x11 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int
            {
                return (CBB_flush_asn1_set_of(&mut child) != 0 && CBB_flush(cbb) != 0)
                    as libc::c_int;
            }
            return CBB_flush(cbb);
        }
        _ => {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                4 as libc::c_int | 64 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0"
                    as *const u8 as *const libc::c_char,
                558 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    }
    if format == 1 as libc::c_int {
        return (CBB_add_bytes(&mut child, value as *const uint8_t, strlen(value)) != 0
            && CBB_flush(cbb) != 0) as libc::c_int;
    }
    if format == 3 as libc::c_int {
        let mut len_1: size_t = 0;
        let mut data: *mut uint8_t = x509v3_hex_to_bytes(value, &mut len_1);
        if data.is_null() {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                128 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0"
                    as *const u8 as *const libc::c_char,
                513 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        let mut ok_4: libc::c_int = (CBB_add_bytes(&mut child, data, len_1) != 0
            && CBB_flush(cbb) != 0) as libc::c_int;
        OPENSSL_free(data as *mut libc::c_void);
        return ok_4;
    }
    ERR_put_error(
        12 as libc::c_int,
        0 as libc::c_int,
        124 as libc::c_int,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0" as *const u8
            as *const libc::c_char,
        521 as libc::c_int as libc::c_uint,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn bitstr_cb(
    mut elem: *const libc::c_char,
    mut len: size_t,
    mut bitstr: *mut libc::c_void,
) -> libc::c_int {
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, elem as *const uint8_t, len);
    let mut bitnum: uint64_t = 0;
    if CBS_get_u64_decimal(&mut cbs, &mut bitnum) == 0
        || CBS_len(&mut cbs) != 0 as libc::c_int as size_t
        || bitnum > 256 as libc::c_int as uint64_t
    {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            145 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/asn1_gen.c\0" as *const u8
                as *const libc::c_char,
            578 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ASN1_BIT_STRING_set_bit(
        bitstr as *mut ASN1_BIT_STRING,
        bitnum as libc::c_int,
        1 as libc::c_int,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
