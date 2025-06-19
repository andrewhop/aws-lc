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
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
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
    fn ASN1_item_d2i(
        out: *mut *mut ASN1_VALUE,
        inp: *mut *const libc::c_uchar,
        len: libc::c_long,
        it: *const ASN1_ITEM,
    ) -> *mut ASN1_VALUE;
    fn ASN1_STRING_get0_data(str: *const ASN1_STRING) -> *const libc::c_uchar;
    fn ASN1_STRING_length(str: *const ASN1_STRING) -> libc::c_int;
    fn ASN1_STRING_print(out: *mut BIO, str: *const ASN1_STRING) -> libc::c_int;
    fn i2a_ASN1_OBJECT(bp: *mut BIO, a: *const ASN1_OBJECT) -> libc::c_int;
    fn X509_EXTENSION_get_object(ex: *const X509_EXTENSION) -> *mut ASN1_OBJECT;
    fn X509_EXTENSION_get_data(ne: *const X509_EXTENSION) -> *mut ASN1_OCTET_STRING;
    fn X509_EXTENSION_get_critical(ex: *const X509_EXTENSION) -> libc::c_int;
    fn X509V3_EXT_get(ext: *const X509_EXTENSION) -> *const X509V3_EXT_METHOD;
    fn X509V3_conf_free(val: *mut CONF_VALUE);
    fn x509v3_ext_free_with_method(
        ext_method: *const X509V3_EXT_METHOD,
        ext_data: *mut libc::c_void,
    ) -> libc::c_int;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_pop_free_ex(
        sk: *mut OPENSSL_STACK,
        call_free_func: OPENSSL_sk_call_free_func,
        free_func: OPENSSL_sk_free_func,
    );
    fn BIO_free(bio: *mut BIO) -> libc::c_int;
    fn BIO_write(
        bio: *mut BIO,
        data: *const libc::c_void,
        len: libc::c_int,
    ) -> libc::c_int;
    fn BIO_puts(bio: *mut BIO, buf: *const libc::c_char) -> libc::c_int;
    fn BIO_printf(bio: *mut BIO, format: *const libc::c_char, _: ...) -> libc::c_int;
    fn BIO_hexdump(
        bio: *mut BIO,
        data: *const uint8_t,
        len: size_t,
        indent: libc::c_uint,
    ) -> libc::c_int;
    fn BIO_new_fp(stream: *mut FILE, close_flag: libc::c_int) -> *mut BIO;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
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
#[inline]
unsafe extern "C" fn sk_X509_EXTENSION_value(
    mut sk: *const stack_st_X509_EXTENSION,
    mut i: size_t,
) -> *mut X509_EXTENSION {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509_EXTENSION;
}
#[inline]
unsafe extern "C" fn sk_X509_EXTENSION_num(
    mut sk: *const stack_st_X509_EXTENSION,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
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
unsafe extern "C" fn sk_CONF_VALUE_num(mut sk: *const stack_st_CONF_VALUE) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
unsafe extern "C" fn X509V3_EXT_val_prn(
    mut out: *mut BIO,
    mut val: *const stack_st_CONF_VALUE,
    mut indent: libc::c_int,
    mut ml: libc::c_int,
) {
    if val.is_null() {
        return;
    }
    if ml == 0 || sk_CONF_VALUE_num(val) == 0 {
        BIO_printf(
            out,
            b"%*s\0" as *const u8 as *const libc::c_char,
            indent,
            b"\0" as *const u8 as *const libc::c_char,
        );
        if sk_CONF_VALUE_num(val) == 0 {
            BIO_puts(out, b"<EMPTY>\n\0" as *const u8 as *const libc::c_char);
        }
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_CONF_VALUE_num(val) {
        if ml != 0 {
            BIO_printf(
                out,
                b"%*s\0" as *const u8 as *const libc::c_char,
                indent,
                b"\0" as *const u8 as *const libc::c_char,
            );
        } else if i > 0 as libc::c_int as size_t {
            BIO_printf(out, b", \0" as *const u8 as *const libc::c_char);
        }
        let mut nval: *const CONF_VALUE = sk_CONF_VALUE_value(val, i);
        if ((*nval).name).is_null() {
            BIO_puts(out, (*nval).value);
        } else if ((*nval).value).is_null() {
            BIO_puts(out, (*nval).name);
        } else {
            BIO_printf(
                out,
                b"%s:%s\0" as *const u8 as *const libc::c_char,
                (*nval).name,
                (*nval).value,
            );
        }
        if ml != 0 {
            BIO_puts(out, b"\n\0" as *const u8 as *const libc::c_char);
        }
        i = i.wrapping_add(1);
        i;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509V3_EXT_print(
    mut out: *mut BIO,
    mut ext: *const X509_EXTENSION,
    mut flag: libc::c_ulong,
    mut indent: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ext_str: *mut libc::c_void = 0 as *mut libc::c_void;
    let mut method: *const X509V3_EXT_METHOD = X509V3_EXT_get(ext);
    if method.is_null() {
        return unknown_ext_print(out, ext, flag, indent, 0 as libc::c_int);
    }
    let mut ext_data: *const ASN1_STRING = X509_EXTENSION_get_data(ext);
    let mut p: *const libc::c_uchar = ASN1_STRING_get0_data(ext_data);
    if !((*method).it).is_null() {
        ext_str = ASN1_item_d2i(
            0 as *mut *mut ASN1_VALUE,
            &mut p,
            ASN1_STRING_length(ext_data) as libc::c_long,
            (*method).it,
        ) as *mut libc::c_void;
    } else if (*method).ext_nid == 366 as libc::c_int && ((*method).d2i).is_some() {
        ext_str = ((*method).d2i)
            .expect(
                "non-null function pointer",
            )(
            0 as *mut libc::c_void,
            &mut p,
            ASN1_STRING_length(ext_data) as libc::c_long,
        );
    } else {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            147 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_prn.c\0" as *const u8
                as *const libc::c_char,
            125 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ext_str.is_null() {
        return unknown_ext_print(out, ext, flag, indent, 1 as libc::c_int);
    }
    let mut value: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut nval: *mut stack_st_CONF_VALUE = 0 as *mut stack_st_CONF_VALUE;
    let mut ok: libc::c_int = 0 as libc::c_int;
    if ((*method).i2s).is_some() {
        value = ((*method).i2s).expect("non-null function pointer")(method, ext_str);
        if value.is_null() {
            current_block = 9100345430942156073;
        } else {
            BIO_printf(
                out,
                b"%*s%s\0" as *const u8 as *const libc::c_char,
                indent,
                b"\0" as *const u8 as *const libc::c_char,
                value,
            );
            current_block = 2719512138335094285;
        }
    } else if ((*method).i2v).is_some() {
        nval = ((*method).i2v)
            .expect(
                "non-null function pointer",
            )(method, ext_str, 0 as *mut stack_st_CONF_VALUE);
        if nval.is_null() {
            current_block = 9100345430942156073;
        } else {
            X509V3_EXT_val_prn(
                out,
                nval,
                indent,
                (*method).ext_flags & 0x4 as libc::c_int,
            );
            current_block = 2719512138335094285;
        }
    } else if ((*method).i2r).is_some() {
        if ((*method).i2r)
            .expect("non-null function pointer")(method, ext_str, out, indent) == 0
        {
            current_block = 9100345430942156073;
        } else {
            current_block = 2719512138335094285;
        }
    } else {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            147 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_prn.c\0" as *const u8
                as *const libc::c_char,
            152 as libc::c_int as libc::c_uint,
        );
        current_block = 9100345430942156073;
    }
    match current_block {
        2719512138335094285 => {
            ok = 1 as libc::c_int;
        }
        _ => {}
    }
    sk_CONF_VALUE_pop_free(
        nval,
        Some(X509V3_conf_free as unsafe extern "C" fn(*mut CONF_VALUE) -> ()),
    );
    OPENSSL_free(value as *mut libc::c_void);
    x509v3_ext_free_with_method(method, ext_str);
    return ok;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509V3_extensions_print(
    mut bp: *mut BIO,
    mut title: *const libc::c_char,
    mut exts: *const stack_st_X509_EXTENSION,
    mut flag: libc::c_ulong,
    mut indent: libc::c_int,
) -> libc::c_int {
    let mut i: size_t = 0;
    let mut j: libc::c_int = 0;
    if sk_X509_EXTENSION_num(exts) <= 0 as libc::c_int as size_t {
        return 1 as libc::c_int;
    }
    if !title.is_null() {
        BIO_printf(
            bp,
            b"%*s%s:\n\0" as *const u8 as *const libc::c_char,
            indent,
            b"\0" as *const u8 as *const libc::c_char,
            title,
        );
        indent += 4 as libc::c_int;
    }
    i = 0 as libc::c_int as size_t;
    while i < sk_X509_EXTENSION_num(exts) {
        let mut ex: *const X509_EXTENSION = sk_X509_EXTENSION_value(exts, i);
        if indent != 0
            && BIO_printf(
                bp,
                b"%*s\0" as *const u8 as *const libc::c_char,
                indent,
                b"\0" as *const u8 as *const libc::c_char,
            ) <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        let mut obj: *const ASN1_OBJECT = X509_EXTENSION_get_object(ex);
        i2a_ASN1_OBJECT(bp, obj);
        j = X509_EXTENSION_get_critical(ex);
        if BIO_printf(
            bp,
            b": %s\n\0" as *const u8 as *const libc::c_char,
            (if j != 0 {
                b"critical\0" as *const u8 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            }),
        ) <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        if X509V3_EXT_print(bp, ex, flag, indent + 4 as libc::c_int) == 0 {
            BIO_printf(
                bp,
                b"%*s\0" as *const u8 as *const libc::c_char,
                indent + 4 as libc::c_int,
                b"\0" as *const u8 as *const libc::c_char,
            );
            ASN1_STRING_print(bp, X509_EXTENSION_get_data(ex));
        }
        if BIO_write(
            bp,
            b"\n\0" as *const u8 as *const libc::c_char as *const libc::c_void,
            1 as libc::c_int,
        ) <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn unknown_ext_print(
    mut out: *mut BIO,
    mut ext: *const X509_EXTENSION,
    mut flag: libc::c_ulong,
    mut indent: libc::c_int,
    mut supported: libc::c_int,
) -> libc::c_int {
    match flag & ((0xf as libc::c_long) << 16 as libc::c_int) as libc::c_ulong {
        0 => return 0 as libc::c_int,
        65536 => {
            if supported != 0 {
                BIO_printf(
                    out,
                    b"%*s<Parse Error>\0" as *const u8 as *const libc::c_char,
                    indent,
                    b"\0" as *const u8 as *const libc::c_char,
                );
            } else {
                BIO_printf(
                    out,
                    b"%*s<Not Supported>\0" as *const u8 as *const libc::c_char,
                    indent,
                    b"\0" as *const u8 as *const libc::c_char,
                );
            }
            return 1 as libc::c_int;
        }
        131072 | 196608 => {
            let mut data: *const ASN1_STRING = X509_EXTENSION_get_data(ext);
            return BIO_hexdump(
                out,
                ASN1_STRING_get0_data(data),
                ASN1_STRING_length(data) as size_t,
                indent as libc::c_uint,
            );
        }
        _ => return 1 as libc::c_int,
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509V3_EXT_print_fp(
    mut fp: *mut FILE,
    mut ext: *const X509_EXTENSION,
    mut flag: libc::c_int,
    mut indent: libc::c_int,
) -> libc::c_int {
    let mut bio_tmp: *mut BIO = 0 as *mut BIO;
    let mut ret: libc::c_int = 0;
    bio_tmp = BIO_new_fp(fp, 0 as libc::c_int);
    if bio_tmp.is_null() {
        return 0 as libc::c_int;
    }
    ret = X509V3_EXT_print(bio_tmp, ext, flag as libc::c_ulong, indent);
    BIO_free(bio_tmp);
    return ret;
}
