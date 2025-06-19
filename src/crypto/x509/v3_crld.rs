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
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strncmp(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> libc::c_int;
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
    static ASN1_FBOOLEAN_it: ASN1_ITEM;
    fn ASN1_BIT_STRING_new() -> *mut ASN1_BIT_STRING;
    static ASN1_BIT_STRING_it: ASN1_ITEM;
    fn ASN1_BIT_STRING_set_bit(
        str: *mut ASN1_BIT_STRING,
        n: libc::c_int,
        value: libc::c_int,
    ) -> libc::c_int;
    fn ASN1_BIT_STRING_get_bit(
        str: *const ASN1_BIT_STRING,
        n: libc::c_int,
    ) -> libc::c_int;
    fn X509_NAME_new() -> *mut X509_NAME;
    fn X509_NAME_free(name: *mut X509_NAME);
    fn i2d_X509_NAME(in_0: *mut X509_NAME, outp: *mut *mut uint8_t) -> libc::c_int;
    fn X509_NAME_dup(name: *mut X509_NAME) -> *mut X509_NAME;
    fn X509_NAME_add_entry(
        name: *mut X509_NAME,
        entry: *const X509_NAME_ENTRY,
        loc: libc::c_int,
        set: libc::c_int,
    ) -> libc::c_int;
    static X509_NAME_ENTRY_it: ASN1_ITEM;
    fn X509_NAME_ENTRY_free(entry: *mut X509_NAME_ENTRY);
    fn GENERAL_NAME_free(gen: *mut GENERAL_NAME);
    fn GENERAL_NAMES_new() -> *mut GENERAL_NAMES;
    fn GENERAL_NAMES_free(gens: *mut GENERAL_NAMES);
    fn X509_NAME_print_ex(
        out: *mut BIO,
        nm: *const X509_NAME,
        indent: libc::c_int,
        flags: libc::c_ulong,
    ) -> libc::c_int;
    fn GENERAL_NAME_print(out: *mut BIO, gen: *const GENERAL_NAME) -> libc::c_int;
    fn X509V3_conf_free(val: *mut CONF_VALUE);
    fn X509V3_parse_list(line: *const libc::c_char) -> *mut stack_st_CONF_VALUE;
    static GENERAL_NAME_it: ASN1_ITEM;
    fn X509V3_NAME_from_section(
        nm: *mut X509_NAME,
        dn_sk: *const stack_st_CONF_VALUE,
        chtype: libc::c_int,
    ) -> libc::c_int;
    fn X509V3_get_value_bool(
        value: *const CONF_VALUE,
        out_bool: *mut ASN1_BOOLEAN,
    ) -> libc::c_int;
    fn X509V3_get_section(
        ctx: *const X509V3_CTX,
        section: *const libc::c_char,
    ) -> *const stack_st_CONF_VALUE;
    fn v2i_GENERAL_NAME(
        method: *const X509V3_EXT_METHOD,
        ctx: *const X509V3_CTX,
        cnf: *const CONF_VALUE,
    ) -> *mut GENERAL_NAME;
    fn v2i_GENERAL_NAMES(
        method: *const X509V3_EXT_METHOD,
        ctx: *const X509V3_CTX,
        nval: *const stack_st_CONF_VALUE,
    ) -> *mut GENERAL_NAMES;
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
pub type ASN1_aux_cb = unsafe extern "C" fn(
    libc::c_int,
    *mut *mut ASN1_VALUE,
    *const ASN1_ITEM,
    *mut libc::c_void,
) -> libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ASN1_AUX_st {
    pub app_data: *mut libc::c_void,
    pub flags: uint32_t,
    pub ref_offset: libc::c_int,
    pub asn1_cb: Option::<ASN1_aux_cb>,
    pub enc_offset: libc::c_int,
}
pub type ASN1_AUX = ASN1_AUX_st;
pub type sk_CONF_VALUE_free_func = Option::<unsafe extern "C" fn(*mut CONF_VALUE) -> ()>;
pub type sk_GENERAL_NAME_free_func = Option::<
    unsafe extern "C" fn(*mut GENERAL_NAME) -> (),
>;
pub type sk_X509_NAME_ENTRY_free_func = Option::<
    unsafe extern "C" fn(*mut X509_NAME_ENTRY) -> (),
>;
pub type CRL_DIST_POINTS = stack_st_DIST_POINT;
pub type sk_DIST_POINT_free_func = Option::<unsafe extern "C" fn(*mut DIST_POINT) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct BIT_STRING_BITNAME {
    pub bitnum: libc::c_int,
    pub lname: *const libc::c_char,
    pub sname: *const libc::c_char,
}
#[inline]
unsafe extern "C" fn sk_GENERAL_NAME_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<
        OPENSSL_sk_free_func,
        sk_GENERAL_NAME_free_func,
    >(free_func))
        .expect("non-null function pointer")(ptr as *mut GENERAL_NAME);
}
#[inline]
unsafe extern "C" fn sk_GENERAL_NAME_num(
    mut sk: *const stack_st_GENERAL_NAME,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_GENERAL_NAME_value(
    mut sk: *const stack_st_GENERAL_NAME,
    mut i: size_t,
) -> *mut GENERAL_NAME {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut GENERAL_NAME;
}
#[inline]
unsafe extern "C" fn sk_GENERAL_NAME_pop_free(
    mut sk: *mut stack_st_GENERAL_NAME,
    mut free_func: sk_GENERAL_NAME_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_GENERAL_NAME_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_GENERAL_NAME_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_GENERAL_NAME_push(
    mut sk: *mut stack_st_GENERAL_NAME,
    mut p: *mut GENERAL_NAME,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_X509_NAME_ENTRY_value(
    mut sk: *const stack_st_X509_NAME_ENTRY,
    mut i: size_t,
) -> *mut X509_NAME_ENTRY {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509_NAME_ENTRY;
}
#[inline]
unsafe extern "C" fn sk_X509_NAME_ENTRY_pop_free(
    mut sk: *mut stack_st_X509_NAME_ENTRY,
    mut free_func: sk_X509_NAME_ENTRY_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_X509_NAME_ENTRY_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_X509_NAME_ENTRY_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_X509_NAME_ENTRY_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<
        OPENSSL_sk_free_func,
        sk_X509_NAME_ENTRY_free_func,
    >(free_func))
        .expect("non-null function pointer")(ptr as *mut X509_NAME_ENTRY);
}
#[inline]
unsafe extern "C" fn sk_X509_NAME_ENTRY_num(
    mut sk: *const stack_st_X509_NAME_ENTRY,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_DIST_POINT_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<OPENSSL_sk_free_func, sk_DIST_POINT_free_func>(free_func))
        .expect("non-null function pointer")(ptr as *mut DIST_POINT);
}
#[inline]
unsafe extern "C" fn sk_DIST_POINT_new_null() -> *mut stack_st_DIST_POINT {
    return OPENSSL_sk_new_null() as *mut stack_st_DIST_POINT;
}
#[inline]
unsafe extern "C" fn sk_DIST_POINT_num(mut sk: *const stack_st_DIST_POINT) -> size_t {
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
unsafe extern "C" fn sk_DIST_POINT_pop_free(
    mut sk: *mut stack_st_DIST_POINT,
    mut free_func: sk_DIST_POINT_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_DIST_POINT_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_DIST_POINT_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_DIST_POINT_push(
    mut sk: *mut stack_st_DIST_POINT,
    mut p: *mut DIST_POINT,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
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
#[unsafe(no_mangle)]
pub static mut v3_crld: X509V3_EXT_METHOD = unsafe {
    {
        let mut init = v3_ext_method {
            ext_nid: 103 as libc::c_int,
            ext_flags: 0 as libc::c_int,
            it: &CRL_DIST_POINTS_it as *const ASN1_ITEM,
            ext_new: None,
            ext_free: None,
            d2i: None,
            i2d: None,
            i2s: None,
            s2i: None,
            i2v: None,
            v2i: Some(
                v2i_crld
                    as unsafe extern "C" fn(
                        *const X509V3_EXT_METHOD,
                        *const X509V3_CTX,
                        *const stack_st_CONF_VALUE,
                    ) -> *mut libc::c_void,
            ),
            i2r: Some(
                i2r_crldp
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
#[unsafe(no_mangle)]
pub static mut v3_freshest_crl: X509V3_EXT_METHOD = unsafe {
    {
        let mut init = v3_ext_method {
            ext_nid: 857 as libc::c_int,
            ext_flags: 0 as libc::c_int,
            it: &CRL_DIST_POINTS_it as *const ASN1_ITEM,
            ext_new: None,
            ext_free: None,
            d2i: None,
            i2d: None,
            i2s: None,
            s2i: None,
            i2v: None,
            v2i: Some(
                v2i_crld
                    as unsafe extern "C" fn(
                        *const X509V3_EXT_METHOD,
                        *const X509V3_CTX,
                        *const stack_st_CONF_VALUE,
                    ) -> *mut libc::c_void,
            ),
            i2r: Some(
                i2r_crldp
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
unsafe extern "C" fn gnames_from_sectname(
    mut ctx: *const X509V3_CTX,
    mut sect: *mut libc::c_char,
) -> *mut stack_st_GENERAL_NAME {
    let mut gnsect: *const stack_st_CONF_VALUE = 0 as *const stack_st_CONF_VALUE;
    let mut gnsect_owned: *mut stack_st_CONF_VALUE = 0 as *mut stack_st_CONF_VALUE;
    if *sect as libc::c_int == '@' as i32 {
        gnsect = X509V3_get_section(ctx, sect.offset(1 as libc::c_int as isize));
    } else {
        gnsect_owned = X509V3_parse_list(sect);
        gnsect = gnsect_owned;
    }
    if gnsect.is_null() {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            153 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_crld.c\0" as *const u8
                as *const libc::c_char,
            121 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut stack_st_GENERAL_NAME;
    }
    let mut gens: *mut stack_st_GENERAL_NAME = v2i_GENERAL_NAMES(
        0 as *const X509V3_EXT_METHOD,
        ctx,
        gnsect,
    );
    sk_CONF_VALUE_pop_free(
        gnsect_owned,
        Some(X509V3_conf_free as unsafe extern "C" fn(*mut CONF_VALUE) -> ()),
    );
    return gens;
}
unsafe extern "C" fn set_dist_point_name(
    mut pdp: *mut *mut DIST_POINT_NAME,
    mut ctx: *const X509V3_CTX,
    mut cnf: *const CONF_VALUE,
) -> libc::c_int {
    let mut current_block: u64;
    let mut fnm: *mut stack_st_GENERAL_NAME = 0 as *mut stack_st_GENERAL_NAME;
    let mut rnm: *mut stack_st_X509_NAME_ENTRY = 0 as *mut stack_st_X509_NAME_ENTRY;
    if strncmp(
        (*cnf).name,
        b"fullname\0" as *const u8 as *const libc::c_char,
        9 as libc::c_int as libc::c_ulong,
    ) == 0
    {
        if ((*cnf).value).is_null() {
            ERR_put_error(
                20 as libc::c_int,
                0 as libc::c_int,
                137 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_crld.c\0" as *const u8
                    as *const libc::c_char,
                141 as libc::c_int as libc::c_uint,
            );
            return -(1 as libc::c_int);
        }
        fnm = gnames_from_sectname(ctx, (*cnf).value);
        if fnm.is_null() {
            current_block = 1501127316712460593;
        } else {
            current_block = 14401909646449704462;
        }
    } else if strcmp((*cnf).name, b"relativename\0" as *const u8 as *const libc::c_char)
        == 0
    {
        if ((*cnf).value).is_null() {
            ERR_put_error(
                20 as libc::c_int,
                0 as libc::c_int,
                137 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_crld.c\0" as *const u8
                    as *const libc::c_char,
                152 as libc::c_int as libc::c_uint,
            );
            return -(1 as libc::c_int);
        }
        let mut dnsect: *const stack_st_CONF_VALUE = X509V3_get_section(
            ctx,
            (*cnf).value,
        );
        if dnsect.is_null() {
            ERR_put_error(
                20 as libc::c_int,
                0 as libc::c_int,
                153 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_crld.c\0" as *const u8
                    as *const libc::c_char,
                157 as libc::c_int as libc::c_uint,
            );
            return -(1 as libc::c_int);
        }
        let mut nm: *mut X509_NAME = X509_NAME_new();
        if nm.is_null() {
            return -(1 as libc::c_int);
        }
        let mut ret: libc::c_int = X509V3_NAME_from_section(
            nm,
            dnsect,
            0x1000 as libc::c_int | 1 as libc::c_int,
        );
        rnm = (*nm).entries;
        (*nm).entries = 0 as *mut stack_st_X509_NAME_ENTRY;
        X509_NAME_free(nm);
        if ret == 0 || sk_X509_NAME_ENTRY_num(rnm) <= 0 as libc::c_int as size_t {
            current_block = 1501127316712460593;
        } else if (*sk_X509_NAME_ENTRY_value(
            rnm,
            (sk_X509_NAME_ENTRY_num(rnm)).wrapping_sub(1 as libc::c_int as size_t),
        ))
            .set != 0
        {
            ERR_put_error(
                20 as libc::c_int,
                0 as libc::c_int,
                122 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_crld.c\0" as *const u8
                    as *const libc::c_char,
                173 as libc::c_int as libc::c_uint,
            );
            current_block = 1501127316712460593;
        } else {
            current_block = 14401909646449704462;
        }
    } else {
        return 0 as libc::c_int
    }
    match current_block {
        14401909646449704462 => {
            if !(*pdp).is_null() {
                ERR_put_error(
                    20 as libc::c_int,
                    0 as libc::c_int,
                    106 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_crld.c\0"
                        as *const u8 as *const libc::c_char,
                    181 as libc::c_int as libc::c_uint,
                );
            } else {
                *pdp = DIST_POINT_NAME_new();
                if !(*pdp).is_null() {
                    if !fnm.is_null() {
                        (**pdp).type_0 = 0 as libc::c_int;
                        (**pdp).name.fullname = fnm;
                    } else {
                        (**pdp).type_0 = 1 as libc::c_int;
                        (**pdp).name.relativename = rnm;
                    }
                    return 1 as libc::c_int;
                }
            }
        }
        _ => {}
    }
    sk_GENERAL_NAME_pop_free(
        fnm,
        Some(GENERAL_NAME_free as unsafe extern "C" fn(*mut GENERAL_NAME) -> ()),
    );
    sk_X509_NAME_ENTRY_pop_free(
        rnm,
        Some(X509_NAME_ENTRY_free as unsafe extern "C" fn(*mut X509_NAME_ENTRY) -> ()),
    );
    return -(1 as libc::c_int);
}
static mut reason_flags: [BIT_STRING_BITNAME; 10] = [
    {
        let mut init = BIT_STRING_BITNAME {
            bitnum: 0 as libc::c_int,
            lname: b"Unused\0" as *const u8 as *const libc::c_char,
            sname: b"unused\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = BIT_STRING_BITNAME {
            bitnum: 1 as libc::c_int,
            lname: b"Key Compromise\0" as *const u8 as *const libc::c_char,
            sname: b"keyCompromise\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = BIT_STRING_BITNAME {
            bitnum: 2 as libc::c_int,
            lname: b"CA Compromise\0" as *const u8 as *const libc::c_char,
            sname: b"CACompromise\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = BIT_STRING_BITNAME {
            bitnum: 3 as libc::c_int,
            lname: b"Affiliation Changed\0" as *const u8 as *const libc::c_char,
            sname: b"affiliationChanged\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = BIT_STRING_BITNAME {
            bitnum: 4 as libc::c_int,
            lname: b"Superseded\0" as *const u8 as *const libc::c_char,
            sname: b"superseded\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = BIT_STRING_BITNAME {
            bitnum: 5 as libc::c_int,
            lname: b"Cessation Of Operation\0" as *const u8 as *const libc::c_char,
            sname: b"cessationOfOperation\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = BIT_STRING_BITNAME {
            bitnum: 6 as libc::c_int,
            lname: b"Certificate Hold\0" as *const u8 as *const libc::c_char,
            sname: b"certificateHold\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = BIT_STRING_BITNAME {
            bitnum: 7 as libc::c_int,
            lname: b"Privilege Withdrawn\0" as *const u8 as *const libc::c_char,
            sname: b"privilegeWithdrawn\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = BIT_STRING_BITNAME {
            bitnum: 8 as libc::c_int,
            lname: b"AA Compromise\0" as *const u8 as *const libc::c_char,
            sname: b"AACompromise\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = BIT_STRING_BITNAME {
            bitnum: -(1 as libc::c_int),
            lname: 0 as *const libc::c_char,
            sname: 0 as *const libc::c_char,
        };
        init
    },
];
unsafe extern "C" fn set_reasons(
    mut preas: *mut *mut ASN1_BIT_STRING,
    mut value: *const libc::c_char,
) -> libc::c_int {
    let mut current_block: u64;
    if !(*preas).is_null() {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            163 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_crld.c\0" as *const u8
                as *const libc::c_char,
            220 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut rsk: *mut stack_st_CONF_VALUE = X509V3_parse_list(value);
    if rsk.is_null() {
        return 0 as libc::c_int;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    's_29: loop {
        if !(i < sk_CONF_VALUE_num(rsk)) {
            current_block = 15904375183555213903;
            break;
        }
        let mut bnam: *const libc::c_char = (*sk_CONF_VALUE_value(rsk, i)).name;
        if (*preas).is_null() {
            *preas = ASN1_BIT_STRING_new();
            if (*preas).is_null() {
                current_block = 6321100699738297719;
                break;
            }
        }
        let mut pbn: *const BIT_STRING_BITNAME = 0 as *const BIT_STRING_BITNAME;
        pbn = reason_flags.as_ptr();
        while !((*pbn).lname).is_null() {
            if strcmp((*pbn).sname, bnam) == 0 {
                if ASN1_BIT_STRING_set_bit(*preas, (*pbn).bitnum, 1 as libc::c_int) == 0
                {
                    current_block = 6321100699738297719;
                    break 's_29;
                } else {
                    break;
                }
            } else {
                pbn = pbn.offset(1);
                pbn;
            }
        }
        if ((*pbn).lname).is_null() {
            current_block = 6321100699738297719;
            break;
        }
        i = i.wrapping_add(1);
        i;
    }
    match current_block {
        15904375183555213903 => {
            ret = 1 as libc::c_int;
        }
        _ => {}
    }
    sk_CONF_VALUE_pop_free(
        rsk,
        Some(X509V3_conf_free as unsafe extern "C" fn(*mut CONF_VALUE) -> ()),
    );
    return ret;
}
unsafe extern "C" fn print_reasons(
    mut out: *mut BIO,
    mut rname: *const libc::c_char,
    mut rflags: *mut ASN1_BIT_STRING,
    mut indent: libc::c_int,
) -> libc::c_int {
    let mut first: libc::c_int = 1 as libc::c_int;
    let mut pbn: *const BIT_STRING_BITNAME = 0 as *const BIT_STRING_BITNAME;
    BIO_printf(
        out,
        b"%*s%s:\n%*s\0" as *const u8 as *const libc::c_char,
        indent,
        b"\0" as *const u8 as *const libc::c_char,
        rname,
        indent + 2 as libc::c_int,
        b"\0" as *const u8 as *const libc::c_char,
    );
    pbn = reason_flags.as_ptr();
    while !((*pbn).lname).is_null() {
        if ASN1_BIT_STRING_get_bit(rflags, (*pbn).bitnum) != 0 {
            if first != 0 {
                first = 0 as libc::c_int;
            } else {
                BIO_puts(out, b", \0" as *const u8 as *const libc::c_char);
            }
            BIO_puts(out, (*pbn).lname);
        }
        pbn = pbn.offset(1);
        pbn;
    }
    if first != 0 {
        BIO_puts(out, b"<EMPTY>\n\0" as *const u8 as *const libc::c_char);
    } else {
        BIO_puts(out, b"\n\0" as *const u8 as *const libc::c_char);
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn crldp_from_section(
    mut ctx: *const X509V3_CTX,
    mut nval: *const stack_st_CONF_VALUE,
) -> *mut DIST_POINT {
    let mut current_block: u64;
    let mut point: *mut DIST_POINT = 0 as *mut DIST_POINT;
    point = DIST_POINT_new();
    if !point.is_null() {
        let mut i: size_t = 0 as libc::c_int as size_t;
        loop {
            if !(i < sk_CONF_VALUE_num(nval)) {
                current_block = 7976072742316086414;
                break;
            }
            let mut cnf: *const CONF_VALUE = sk_CONF_VALUE_value(nval, i);
            let mut ret: libc::c_int = set_dist_point_name(
                &mut (*point).distpoint,
                ctx,
                cnf,
            );
            if !(ret > 0 as libc::c_int) {
                if ret < 0 as libc::c_int {
                    current_block = 12196772669239209823;
                    break;
                }
                if strcmp((*cnf).name, b"reasons\0" as *const u8 as *const libc::c_char)
                    == 0
                {
                    if set_reasons(&mut (*point).reasons, (*cnf).value) == 0 {
                        current_block = 12196772669239209823;
                        break;
                    }
                } else if strcmp(
                    (*cnf).name,
                    b"CRLissuer\0" as *const u8 as *const libc::c_char,
                ) == 0
                {
                    GENERAL_NAMES_free((*point).CRLissuer);
                    (*point).CRLissuer = gnames_from_sectname(ctx, (*cnf).value);
                    if ((*point).CRLissuer).is_null() {
                        current_block = 12196772669239209823;
                        break;
                    }
                }
            }
            i = i.wrapping_add(1);
            i;
        }
        match current_block {
            12196772669239209823 => {}
            _ => return point,
        }
    }
    DIST_POINT_free(point);
    return 0 as *mut DIST_POINT;
}
unsafe extern "C" fn v2i_crld(
    mut method: *const X509V3_EXT_METHOD,
    mut ctx: *const X509V3_CTX,
    mut nval: *const stack_st_CONF_VALUE,
) -> *mut libc::c_void {
    let mut current_block: u64;
    let mut crld: *mut stack_st_DIST_POINT = 0 as *mut stack_st_DIST_POINT;
    let mut gens: *mut GENERAL_NAMES = 0 as *mut GENERAL_NAMES;
    let mut gen: *mut GENERAL_NAME = 0 as *mut GENERAL_NAME;
    crld = sk_DIST_POINT_new_null();
    if !crld.is_null() {
        let mut i: size_t = 0 as libc::c_int as size_t;
        loop {
            if !(i < sk_CONF_VALUE_num(nval)) {
                current_block = 15768484401365413375;
                break;
            }
            let mut point: *mut DIST_POINT = 0 as *mut DIST_POINT;
            let mut cnf: *const CONF_VALUE = sk_CONF_VALUE_value(nval, i);
            if ((*cnf).value).is_null() {
                let mut dpsect: *const stack_st_CONF_VALUE = X509V3_get_section(
                    ctx,
                    (*cnf).name,
                );
                if dpsect.is_null() {
                    current_block = 1963799921680137506;
                    break;
                }
                point = crldp_from_section(ctx, dpsect);
                if point.is_null() {
                    current_block = 1963799921680137506;
                    break;
                }
                if sk_DIST_POINT_push(crld, point) == 0 {
                    DIST_POINT_free(point);
                    current_block = 1963799921680137506;
                    break;
                }
            } else {
                gen = v2i_GENERAL_NAME(method, ctx, cnf);
                if gen.is_null() {
                    current_block = 1963799921680137506;
                    break;
                }
                gens = GENERAL_NAMES_new();
                if gens.is_null() {
                    current_block = 1963799921680137506;
                    break;
                }
                if sk_GENERAL_NAME_push(gens, gen) == 0 {
                    current_block = 1963799921680137506;
                    break;
                }
                gen = 0 as *mut GENERAL_NAME;
                point = DIST_POINT_new();
                if point.is_null() {
                    current_block = 1963799921680137506;
                    break;
                }
                if sk_DIST_POINT_push(crld, point) == 0 {
                    DIST_POINT_free(point);
                    current_block = 1963799921680137506;
                    break;
                } else {
                    (*point).distpoint = DIST_POINT_NAME_new();
                    if ((*point).distpoint).is_null() {
                        current_block = 1963799921680137506;
                        break;
                    }
                    (*(*point).distpoint).name.fullname = gens;
                    (*(*point).distpoint).type_0 = 0 as libc::c_int;
                    gens = 0 as *mut GENERAL_NAMES;
                }
            }
            i = i.wrapping_add(1);
            i;
        }
        match current_block {
            1963799921680137506 => {}
            _ => return crld as *mut libc::c_void,
        }
    }
    GENERAL_NAME_free(gen);
    GENERAL_NAMES_free(gens);
    sk_DIST_POINT_pop_free(
        crld,
        Some(DIST_POINT_free as unsafe extern "C" fn(*mut DIST_POINT) -> ()),
    );
    return 0 as *mut libc::c_void;
}
unsafe extern "C" fn dpn_cb(
    mut operation: libc::c_int,
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
    mut exarg: *mut libc::c_void,
) -> libc::c_int {
    let mut dpn: *mut DIST_POINT_NAME = *pval as *mut DIST_POINT_NAME;
    match operation {
        1 => {
            (*dpn).dpname = 0 as *mut X509_NAME;
        }
        3 => {
            X509_NAME_free((*dpn).dpname);
        }
        _ => {}
    }
    return 1 as libc::c_int;
}
static mut DIST_POINT_NAME_aux: ASN1_AUX = unsafe {
    {
        let mut init = ASN1_AUX_st {
            app_data: 0 as *const libc::c_void as *mut libc::c_void,
            flags: 0 as libc::c_int as uint32_t,
            ref_offset: 0 as libc::c_int,
            asn1_cb: Some(
                dpn_cb
                    as unsafe extern "C" fn(
                        libc::c_int,
                        *mut *mut ASN1_VALUE,
                        *const ASN1_ITEM,
                        *mut libc::c_void,
                    ) -> libc::c_int,
            ),
            enc_offset: 0 as libc::c_int,
        };
        init
    }
};
static mut DIST_POINT_NAME_ch_tt: [ASN1_TEMPLATE; 2] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int
                    | (0x2 as libc::c_int) << 1 as libc::c_int) as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"name.fullname\0" as *const u8 as *const libc::c_char,
                item: &GENERAL_NAME_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int
                    | (0x1 as libc::c_int) << 1 as libc::c_int) as uint32_t,
                tag: 1 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"name.relativename\0" as *const u8 as *const libc::c_char,
                item: &X509_NAME_ENTRY_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[unsafe(no_mangle)]
pub static mut DIST_POINT_NAME_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DIST_POINT_NAME_free(mut a: *mut DIST_POINT_NAME) {
    ASN1_item_free(a as *mut ASN1_VALUE, &DIST_POINT_NAME_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DIST_POINT_NAME_new() -> *mut DIST_POINT_NAME {
    return ASN1_item_new(&DIST_POINT_NAME_it) as *mut DIST_POINT_NAME;
}
static mut DIST_POINT_seq_tt: [ASN1_TEMPLATE; 3] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"distpoint\0" as *const u8 as *const libc::c_char,
                item: &DIST_POINT_NAME_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 1 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"reasons\0" as *const u8 as *const libc::c_char,
                item: &ASN1_BIT_STRING_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int
                    | (0x2 as libc::c_int) << 1 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 2 as libc::c_int,
                offset: 16 as libc::c_ulong,
                field_name: b"CRLissuer\0" as *const u8 as *const libc::c_char,
                item: &GENERAL_NAME_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[unsafe(no_mangle)]
pub static mut DIST_POINT_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DIST_POINT_free(mut a: *mut DIST_POINT) {
    ASN1_item_free(a as *mut ASN1_VALUE, &DIST_POINT_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DIST_POINT_new() -> *mut DIST_POINT {
    return ASN1_item_new(&DIST_POINT_it) as *mut DIST_POINT;
}
static mut CRL_DIST_POINTS_item_tt: ASN1_TEMPLATE = unsafe {
    {
        let mut init = ASN1_TEMPLATE_st {
            flags: ((0x2 as libc::c_int) << 1 as libc::c_int) as uint32_t,
            tag: 0 as libc::c_int,
            offset: 0 as libc::c_int as libc::c_ulong,
            field_name: b"CRLDistributionPoints\0" as *const u8 as *const libc::c_char,
            item: &DIST_POINT_it as *const ASN1_ITEM,
        };
        init
    }
};
#[unsafe(no_mangle)]
pub static mut CRL_DIST_POINTS_it: ASN1_ITEM = unsafe {
    {
        let mut init = ASN1_ITEM_st {
            itype: 0 as libc::c_int as libc::c_char,
            utype: -(1 as libc::c_int),
            templates: &CRL_DIST_POINTS_item_tt as *const ASN1_TEMPLATE,
            tcount: 0 as libc::c_int as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: 0 as libc::c_int as libc::c_long,
            sname: b"CRL_DIST_POINTS\0" as *const u8 as *const libc::c_char,
        };
        init
    }
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_CRL_DIST_POINTS(
    mut a: *mut CRL_DIST_POINTS,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &CRL_DIST_POINTS_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRL_DIST_POINTS_free(mut a: *mut CRL_DIST_POINTS) {
    ASN1_item_free(a as *mut ASN1_VALUE, &CRL_DIST_POINTS_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_CRL_DIST_POINTS(
    mut a: *mut *mut CRL_DIST_POINTS,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut CRL_DIST_POINTS {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &CRL_DIST_POINTS_it)
        as *mut CRL_DIST_POINTS;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRL_DIST_POINTS_new() -> *mut CRL_DIST_POINTS {
    return ASN1_item_new(&CRL_DIST_POINTS_it) as *mut CRL_DIST_POINTS;
}
static mut ISSUING_DIST_POINT_seq_tt: [ASN1_TEMPLATE; 6] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"distpoint\0" as *const u8 as *const libc::c_char,
                item: &DIST_POINT_NAME_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 1 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"onlyuser\0" as *const u8 as *const libc::c_char,
                item: &ASN1_FBOOLEAN_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 2 as libc::c_int,
                offset: 12 as libc::c_ulong,
                field_name: b"onlyCA\0" as *const u8 as *const libc::c_char,
                item: &ASN1_FBOOLEAN_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 3 as libc::c_int,
                offset: 16 as libc::c_ulong,
                field_name: b"onlysomereasons\0" as *const u8 as *const libc::c_char,
                item: &ASN1_BIT_STRING_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 4 as libc::c_int,
                offset: 24 as libc::c_ulong,
                field_name: b"indirectCRL\0" as *const u8 as *const libc::c_char,
                item: &ASN1_FBOOLEAN_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 5 as libc::c_int,
                offset: 28 as libc::c_ulong,
                field_name: b"onlyattr\0" as *const u8 as *const libc::c_char,
                item: &ASN1_FBOOLEAN_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[unsafe(no_mangle)]
pub static mut ISSUING_DIST_POINT_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ISSUING_DIST_POINT_free(mut a: *mut ISSUING_DIST_POINT) {
    ASN1_item_free(a as *mut ASN1_VALUE, &ISSUING_DIST_POINT_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ISSUING_DIST_POINT(
    mut a: *mut ISSUING_DIST_POINT,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &ISSUING_DIST_POINT_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ISSUING_DIST_POINT(
    mut a: *mut *mut ISSUING_DIST_POINT,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ISSUING_DIST_POINT {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &ISSUING_DIST_POINT_it)
        as *mut ISSUING_DIST_POINT;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ISSUING_DIST_POINT_new() -> *mut ISSUING_DIST_POINT {
    return ASN1_item_new(&ISSUING_DIST_POINT_it) as *mut ISSUING_DIST_POINT;
}
#[unsafe(no_mangle)]
pub static mut v3_idp: X509V3_EXT_METHOD = unsafe {
    {
        let mut init = v3_ext_method {
            ext_nid: 770 as libc::c_int,
            ext_flags: 0x4 as libc::c_int,
            it: &ISSUING_DIST_POINT_it as *const ASN1_ITEM,
            ext_new: None,
            ext_free: None,
            d2i: None,
            i2d: None,
            i2s: None,
            s2i: None,
            i2v: None,
            v2i: Some(
                v2i_idp
                    as unsafe extern "C" fn(
                        *const X509V3_EXT_METHOD,
                        *const X509V3_CTX,
                        *const stack_st_CONF_VALUE,
                    ) -> *mut libc::c_void,
            ),
            i2r: Some(
                i2r_idp
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
unsafe extern "C" fn v2i_idp(
    mut method: *const X509V3_EXT_METHOD,
    mut ctx: *const X509V3_CTX,
    mut nval: *const stack_st_CONF_VALUE,
) -> *mut libc::c_void {
    let mut current_block: u64;
    let mut idp: *mut ISSUING_DIST_POINT = ISSUING_DIST_POINT_new();
    if !idp.is_null() {
        let mut i: size_t = 0 as libc::c_int as size_t;
        loop {
            if !(i < sk_CONF_VALUE_num(nval)) {
                current_block = 18386322304582297246;
                break;
            }
            let mut cnf: *const CONF_VALUE = sk_CONF_VALUE_value(nval, i);
            let mut name: *const libc::c_char = (*cnf).name;
            let mut val: *const libc::c_char = (*cnf).value;
            let mut ret: libc::c_int = set_dist_point_name(
                &mut (*idp).distpoint,
                ctx,
                cnf,
            );
            if !(ret > 0 as libc::c_int) {
                if ret < 0 as libc::c_int {
                    current_block = 6248945398838106501;
                    break;
                }
                if strcmp(name, b"onlyuser\0" as *const u8 as *const libc::c_char) == 0 {
                    if X509V3_get_value_bool(cnf, &mut (*idp).onlyuser) == 0 {
                        current_block = 6248945398838106501;
                        break;
                    }
                } else if strcmp(name, b"onlyCA\0" as *const u8 as *const libc::c_char)
                    == 0
                {
                    if X509V3_get_value_bool(cnf, &mut (*idp).onlyCA) == 0 {
                        current_block = 6248945398838106501;
                        break;
                    }
                } else if strcmp(name, b"onlyAA\0" as *const u8 as *const libc::c_char)
                    == 0
                {
                    if X509V3_get_value_bool(cnf, &mut (*idp).onlyattr) == 0 {
                        current_block = 6248945398838106501;
                        break;
                    }
                } else if strcmp(
                    name,
                    b"indirectCRL\0" as *const u8 as *const libc::c_char,
                ) == 0
                {
                    if X509V3_get_value_bool(cnf, &mut (*idp).indirectCRL) == 0 {
                        current_block = 6248945398838106501;
                        break;
                    }
                } else if strcmp(
                    name,
                    b"onlysomereasons\0" as *const u8 as *const libc::c_char,
                ) == 0
                {
                    if set_reasons(&mut (*idp).onlysomereasons, val) == 0 {
                        current_block = 6248945398838106501;
                        break;
                    }
                } else {
                    ERR_put_error(
                        20 as libc::c_int,
                        0 as libc::c_int,
                        123 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_crld.c\0"
                            as *const u8 as *const libc::c_char,
                        483 as libc::c_int as libc::c_uint,
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
                    current_block = 6248945398838106501;
                    break;
                }
            }
            i = i.wrapping_add(1);
            i;
        }
        match current_block {
            6248945398838106501 => {}
            _ => return idp as *mut libc::c_void,
        }
    }
    ISSUING_DIST_POINT_free(idp);
    return 0 as *mut libc::c_void;
}
unsafe extern "C" fn print_gens(
    mut out: *mut BIO,
    mut gens: *mut stack_st_GENERAL_NAME,
    mut indent: libc::c_int,
) -> libc::c_int {
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < sk_GENERAL_NAME_num(gens) {
        BIO_printf(
            out,
            b"%*s\0" as *const u8 as *const libc::c_char,
            indent + 2 as libc::c_int,
            b"\0" as *const u8 as *const libc::c_char,
        );
        GENERAL_NAME_print(out, sk_GENERAL_NAME_value(gens, i));
        BIO_puts(out, b"\n\0" as *const u8 as *const libc::c_char);
        i = i.wrapping_add(1);
        i;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn print_distpoint(
    mut out: *mut BIO,
    mut dpn: *mut DIST_POINT_NAME,
    mut indent: libc::c_int,
) -> libc::c_int {
    if (*dpn).type_0 == 0 as libc::c_int {
        BIO_printf(
            out,
            b"%*sFull Name:\n\0" as *const u8 as *const libc::c_char,
            indent,
            b"\0" as *const u8 as *const libc::c_char,
        );
        print_gens(out, (*dpn).name.fullname, indent);
    } else {
        let mut ntmp: X509_NAME = X509_name_st {
            entries: 0 as *mut stack_st_X509_NAME_ENTRY,
            modified: 0,
            bytes: 0 as *mut BUF_MEM,
            canon_enc: 0 as *mut libc::c_uchar,
            canon_enclen: 0,
        };
        ntmp.entries = (*dpn).name.relativename;
        BIO_printf(
            out,
            b"%*sRelative Name:\n%*s\0" as *const u8 as *const libc::c_char,
            indent,
            b"\0" as *const u8 as *const libc::c_char,
            indent + 2 as libc::c_int,
            b"\0" as *const u8 as *const libc::c_char,
        );
        X509_NAME_print_ex(
            out,
            &mut ntmp,
            0 as libc::c_int,
            1 as libc::c_ulong | 2 as libc::c_ulong | 4 as libc::c_ulong
                | 0x10 as libc::c_ulong | 0x100 as libc::c_ulong | 0x200 as libc::c_ulong
                | 8 as libc::c_ulong | (2 as libc::c_ulong) << 16 as libc::c_int
                | (1 as libc::c_ulong) << 23 as libc::c_int | 0 as libc::c_ulong,
        );
        BIO_puts(out, b"\n\0" as *const u8 as *const libc::c_char);
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn i2r_idp(
    mut method: *const X509V3_EXT_METHOD,
    mut pidp: *mut libc::c_void,
    mut out: *mut BIO,
    mut indent: libc::c_int,
) -> libc::c_int {
    let mut idp: *mut ISSUING_DIST_POINT = pidp as *mut ISSUING_DIST_POINT;
    if !((*idp).distpoint).is_null() {
        print_distpoint(out, (*idp).distpoint, indent);
    }
    if (*idp).onlyuser > 0 as libc::c_int {
        BIO_printf(
            out,
            b"%*sOnly User Certificates\n\0" as *const u8 as *const libc::c_char,
            indent,
            b"\0" as *const u8 as *const libc::c_char,
        );
    }
    if (*idp).onlyCA > 0 as libc::c_int {
        BIO_printf(
            out,
            b"%*sOnly CA Certificates\n\0" as *const u8 as *const libc::c_char,
            indent,
            b"\0" as *const u8 as *const libc::c_char,
        );
    }
    if (*idp).indirectCRL > 0 as libc::c_int {
        BIO_printf(
            out,
            b"%*sIndirect CRL\n\0" as *const u8 as *const libc::c_char,
            indent,
            b"\0" as *const u8 as *const libc::c_char,
        );
    }
    if !((*idp).onlysomereasons).is_null() {
        print_reasons(
            out,
            b"Only Some Reasons\0" as *const u8 as *const libc::c_char,
            (*idp).onlysomereasons,
            indent,
        );
    }
    if (*idp).onlyattr > 0 as libc::c_int {
        BIO_printf(
            out,
            b"%*sOnly Attribute Certificates\n\0" as *const u8 as *const libc::c_char,
            indent,
            b"\0" as *const u8 as *const libc::c_char,
        );
    }
    if ((*idp).distpoint).is_null() && (*idp).onlyuser <= 0 as libc::c_int
        && (*idp).onlyCA <= 0 as libc::c_int && (*idp).indirectCRL <= 0 as libc::c_int
        && ((*idp).onlysomereasons).is_null() && (*idp).onlyattr <= 0 as libc::c_int
    {
        BIO_printf(
            out,
            b"%*s<EMPTY>\n\0" as *const u8 as *const libc::c_char,
            indent,
            b"\0" as *const u8 as *const libc::c_char,
        );
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn i2r_crldp(
    mut method: *const X509V3_EXT_METHOD,
    mut pcrldp: *mut libc::c_void,
    mut out: *mut BIO,
    mut indent: libc::c_int,
) -> libc::c_int {
    let mut crld: *mut stack_st_DIST_POINT = pcrldp as *mut stack_st_DIST_POINT;
    let mut point: *mut DIST_POINT = 0 as *mut DIST_POINT;
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < sk_DIST_POINT_num(crld) {
        BIO_puts(out, b"\n\0" as *const u8 as *const libc::c_char);
        point = sk_DIST_POINT_value(crld, i);
        if !((*point).distpoint).is_null() {
            print_distpoint(out, (*point).distpoint, indent);
        }
        if !((*point).reasons).is_null() {
            print_reasons(
                out,
                b"Reasons\0" as *const u8 as *const libc::c_char,
                (*point).reasons,
                indent,
            );
        }
        if !((*point).CRLissuer).is_null() {
            BIO_printf(
                out,
                b"%*sCRL Issuer:\n\0" as *const u8 as *const libc::c_char,
                indent,
                b"\0" as *const u8 as *const libc::c_char,
            );
            print_gens(out, (*point).CRLissuer, indent);
        }
        i = i.wrapping_add(1);
        i;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DIST_POINT_set_dpname(
    mut dpn: *mut DIST_POINT_NAME,
    mut iname: *mut X509_NAME,
) -> libc::c_int {
    let mut i: size_t = 0;
    let mut frag: *mut stack_st_X509_NAME_ENTRY = 0 as *mut stack_st_X509_NAME_ENTRY;
    let mut ne: *mut X509_NAME_ENTRY = 0 as *mut X509_NAME_ENTRY;
    if dpn.is_null() || (*dpn).type_0 != 1 as libc::c_int {
        return 1 as libc::c_int;
    }
    frag = (*dpn).name.relativename;
    (*dpn).dpname = X509_NAME_dup(iname);
    if ((*dpn).dpname).is_null() {
        return 0 as libc::c_int;
    }
    i = 0 as libc::c_int as size_t;
    while i < sk_X509_NAME_ENTRY_num(frag) {
        ne = sk_X509_NAME_ENTRY_value(frag, i);
        if X509_NAME_add_entry(
            (*dpn).dpname,
            ne,
            -(1 as libc::c_int),
            if i != 0 { 0 as libc::c_int } else { 1 as libc::c_int },
        ) == 0
        {
            X509_NAME_free((*dpn).dpname);
            (*dpn).dpname = 0 as *mut X509_NAME;
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    if i2d_X509_NAME((*dpn).dpname, 0 as *mut *mut uint8_t) < 0 as libc::c_int {
        X509_NAME_free((*dpn).dpname);
        (*dpn).dpname = 0 as *mut X509_NAME;
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn run_static_initializers() {
    DIST_POINT_NAME_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x2 as libc::c_int as libc::c_char,
            utype: 0 as libc::c_ulong as libc::c_int,
            templates: DIST_POINT_NAME_ch_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 2]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: &DIST_POINT_NAME_aux as *const ASN1_AUX as *const libc::c_void,
            size: ::core::mem::size_of::<DIST_POINT_NAME>() as libc::c_ulong
                as libc::c_long,
            sname: b"DIST_POINT_NAME\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    DIST_POINT_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: DIST_POINT_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 3]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<DIST_POINT>() as libc::c_ulong as libc::c_long,
            sname: b"DIST_POINT\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    ISSUING_DIST_POINT_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: ISSUING_DIST_POINT_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 6]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<ISSUING_DIST_POINT>() as libc::c_ulong
                as libc::c_long,
            sname: b"ISSUING_DIST_POINT\0" as *const u8 as *const libc::c_char,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
