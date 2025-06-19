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
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn ASN1_STRING_free(str: *mut ASN1_STRING);
    fn ASN1_STRING_dup(str: *const ASN1_STRING) -> *mut ASN1_STRING;
    fn ASN1_STRING_set(
        str: *mut ASN1_STRING,
        data: *const libc::c_void,
        len: ossl_ssize_t,
    ) -> libc::c_int;
    fn ASN1_IA5STRING_new() -> *mut ASN1_IA5STRING;
    fn ASN1_IA5STRING_free(str: *mut ASN1_IA5STRING);
    fn ASN1_OBJECT_free(a: *mut ASN1_OBJECT);
    fn ASN1_TYPE_free(a: *mut ASN1_TYPE);
    fn ASN1_STRING_print(out: *mut BIO, str: *const ASN1_STRING) -> libc::c_int;
    fn i2a_ASN1_OBJECT(bp: *mut BIO, a: *const ASN1_OBJECT) -> libc::c_int;
    fn i2t_ASN1_OBJECT(
        buf: *mut libc::c_char,
        buf_len: libc::c_int,
        a: *const ASN1_OBJECT,
    ) -> libc::c_int;
    fn X509_get_subject_name(x509: *const X509) -> *mut X509_NAME;
    fn X509_get_ext_by_NID(
        x: *const X509,
        nid: libc::c_int,
        lastpos: libc::c_int,
    ) -> libc::c_int;
    fn X509_get_ext(x: *const X509, loc: libc::c_int) -> *mut X509_EXTENSION;
    fn X509_REQ_get_subject_name(req: *const X509_REQ) -> *mut X509_NAME;
    fn X509_NAME_new() -> *mut X509_NAME;
    fn X509_NAME_free(name: *mut X509_NAME);
    fn X509_NAME_get_index_by_NID(
        name: *const X509_NAME,
        nid: libc::c_int,
        lastpos: libc::c_int,
    ) -> libc::c_int;
    fn X509_NAME_get_entry(
        name: *const X509_NAME,
        loc: libc::c_int,
    ) -> *mut X509_NAME_ENTRY;
    fn X509_NAME_delete_entry(
        name: *mut X509_NAME,
        loc: libc::c_int,
    ) -> *mut X509_NAME_ENTRY;
    fn X509_NAME_ENTRY_free(entry: *mut X509_NAME_ENTRY);
    fn X509_NAME_ENTRY_get_data(entry: *const X509_NAME_ENTRY) -> *mut ASN1_STRING;
    fn X509V3_EXT_d2i(ext: *const X509_EXTENSION) -> *mut libc::c_void;
    fn GENERAL_NAME_new() -> *mut GENERAL_NAME;
    fn GENERAL_NAME_free(gen: *mut GENERAL_NAME);
    fn GENERAL_NAMES_free(gens: *mut GENERAL_NAMES);
    fn OTHERNAME_new() -> *mut OTHERNAME;
    fn OTHERNAME_free(name: *mut OTHERNAME);
    fn X509_NAME_print_ex(
        out: *mut BIO,
        nm: *const X509_NAME,
        indent: libc::c_int,
        flags: libc::c_ulong,
    ) -> libc::c_int;
    fn X509_NAME_oneline(
        name: *const X509_NAME,
        buf: *mut libc::c_char,
        size: libc::c_int,
    ) -> *mut libc::c_char;
    fn X509V3_conf_free(val: *mut CONF_VALUE);
    fn a2i_IPADDRESS(ipasc: *const libc::c_char) -> *mut ASN1_OCTET_STRING;
    fn a2i_IPADDRESS_NC(ipasc: *const libc::c_char) -> *mut ASN1_OCTET_STRING;
    static GENERAL_NAMES_it: ASN1_ITEM;
    fn ASN1_generate_v3(
        str: *const libc::c_char,
        cnf: *const X509V3_CTX,
    ) -> *mut ASN1_TYPE;
    fn x509v3_conf_name_matches(
        name: *const libc::c_char,
        cmp: *const libc::c_char,
    ) -> libc::c_int;
    fn x509V3_add_value_asn1_string(
        name: *const libc::c_char,
        value: *const ASN1_STRING,
        extlist: *mut *mut stack_st_CONF_VALUE,
    ) -> libc::c_int;
    fn X509V3_NAME_from_section(
        nm: *mut X509_NAME,
        dn_sk: *const stack_st_CONF_VALUE,
        chtype: libc::c_int,
    ) -> libc::c_int;
    fn X509V3_get_section(
        ctx: *const X509V3_CTX,
        section: *const libc::c_char,
    ) -> *const stack_st_CONF_VALUE;
    fn X509V3_add_value(
        name: *const libc::c_char,
        value: *const libc::c_char,
        extlist: *mut *mut stack_st_CONF_VALUE,
    ) -> libc::c_int;
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_set(
        sk: *mut OPENSSL_STACK,
        i: size_t,
        p: *mut libc::c_void,
    ) -> *mut libc::c_void;
    fn OPENSSL_sk_pop_free_ex(
        sk: *mut OPENSSL_STACK,
        call_free_func: OPENSSL_sk_call_free_func,
        free_func: OPENSSL_sk_free_func,
    );
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn BIO_puts(bio: *mut BIO, buf: *const libc::c_char) -> libc::c_int;
    fn BIO_printf(bio: *mut BIO, format: *const libc::c_char, _: ...) -> libc::c_int;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_strndup(str: *const libc::c_char, size: size_t) -> *mut libc::c_char;
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
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type ptrdiff_t = libc::c_long;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
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
pub type sk_CONF_VALUE_free_func = Option::<unsafe extern "C" fn(*mut CONF_VALUE) -> ()>;
pub type sk_GENERAL_NAME_free_func = Option::<
    unsafe extern "C" fn(*mut GENERAL_NAME) -> (),
>;
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
unsafe extern "C" fn sk_GENERAL_NAME_set(
    mut sk: *mut stack_st_GENERAL_NAME,
    mut i: size_t,
    mut p: *mut GENERAL_NAME,
) -> *mut GENERAL_NAME {
    return OPENSSL_sk_set(sk as *mut OPENSSL_STACK, i, p as *mut libc::c_void)
        as *mut GENERAL_NAME;
}
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
unsafe extern "C" fn sk_CONF_VALUE_new_null() -> *mut stack_st_CONF_VALUE {
    return OPENSSL_sk_new_null() as *mut stack_st_CONF_VALUE;
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
unsafe extern "C" fn i2v_GENERAL_NAMES_cb(
    mut method: *const X509V3_EXT_METHOD,
    mut ext: *mut libc::c_void,
    mut ret: *mut stack_st_CONF_VALUE,
) -> *mut stack_st_CONF_VALUE {
    return i2v_GENERAL_NAMES(method, ext as *const GENERAL_NAMES, ret);
}
#[unsafe(no_mangle)]
pub static mut v3_alt: [X509V3_EXT_METHOD; 3] = unsafe {
    [
        {
            let mut init = v3_ext_method {
                ext_nid: 85 as libc::c_int,
                ext_flags: 0 as libc::c_int,
                it: &GENERAL_NAMES_it as *const ASN1_ITEM,
                ext_new: None,
                ext_free: None,
                d2i: None,
                i2d: None,
                i2s: None,
                s2i: None,
                i2v: Some(
                    i2v_GENERAL_NAMES_cb
                        as unsafe extern "C" fn(
                            *const X509V3_EXT_METHOD,
                            *mut libc::c_void,
                            *mut stack_st_CONF_VALUE,
                        ) -> *mut stack_st_CONF_VALUE,
                ),
                v2i: Some(
                    v2i_subject_alt
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
        },
        {
            let mut init = v3_ext_method {
                ext_nid: 86 as libc::c_int,
                ext_flags: 0 as libc::c_int,
                it: &GENERAL_NAMES_it as *const ASN1_ITEM,
                ext_new: None,
                ext_free: None,
                d2i: None,
                i2d: None,
                i2s: None,
                s2i: None,
                i2v: Some(
                    i2v_GENERAL_NAMES_cb
                        as unsafe extern "C" fn(
                            *const X509V3_EXT_METHOD,
                            *mut libc::c_void,
                            *mut stack_st_CONF_VALUE,
                        ) -> *mut stack_st_CONF_VALUE,
                ),
                v2i: Some(
                    v2i_issuer_alt
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
        },
        {
            let mut init = v3_ext_method {
                ext_nid: 771 as libc::c_int,
                ext_flags: 0 as libc::c_int,
                it: &GENERAL_NAMES_it as *const ASN1_ITEM,
                ext_new: None,
                ext_free: None,
                d2i: None,
                i2d: None,
                i2s: None,
                s2i: None,
                i2v: Some(
                    i2v_GENERAL_NAMES_cb
                        as unsafe extern "C" fn(
                            *const X509V3_EXT_METHOD,
                            *mut libc::c_void,
                            *mut stack_st_CONF_VALUE,
                        ) -> *mut stack_st_CONF_VALUE,
                ),
                v2i: None,
                i2r: None,
                r2i: None,
                usr_data: 0 as *const libc::c_void as *mut libc::c_void,
            };
            init
        },
    ]
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2v_GENERAL_NAMES(
    mut method: *const X509V3_EXT_METHOD,
    mut gens: *const GENERAL_NAMES,
    mut ret: *mut stack_st_CONF_VALUE,
) -> *mut stack_st_CONF_VALUE {
    let mut ret_was_null: libc::c_int = (ret
        == 0 as *mut libc::c_void as *mut stack_st_CONF_VALUE) as libc::c_int;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_GENERAL_NAME_num(gens) {
        let mut gen: *const GENERAL_NAME = sk_GENERAL_NAME_value(gens, i);
        let mut tmp: *mut stack_st_CONF_VALUE = i2v_GENERAL_NAME(method, gen, ret);
        if tmp.is_null() {
            if ret_was_null != 0 {
                sk_CONF_VALUE_pop_free(
                    ret,
                    Some(X509V3_conf_free as unsafe extern "C" fn(*mut CONF_VALUE) -> ()),
                );
            }
            return 0 as *mut stack_st_CONF_VALUE;
        }
        ret = tmp;
        i = i.wrapping_add(1);
        i;
    }
    if ret.is_null() {
        return sk_CONF_VALUE_new_null();
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2v_GENERAL_NAME(
    mut method: *const X509V3_EXT_METHOD,
    mut gen: *const GENERAL_NAME,
    mut ret: *mut stack_st_CONF_VALUE,
) -> *mut stack_st_CONF_VALUE {
    let mut p: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut oline: [libc::c_char; 256] = [0; 256];
    let mut htmp: [libc::c_char; 5] = [0; 5];
    let mut i: libc::c_int = 0;
    let mut current_block_44: u64;
    match (*gen).type_0 {
        0 => {
            if X509V3_add_value(
                b"othername\0" as *const u8 as *const libc::c_char,
                b"<unsupported>\0" as *const u8 as *const libc::c_char,
                &mut ret,
            ) == 0
            {
                return 0 as *mut stack_st_CONF_VALUE;
            }
        }
        3 => {
            if X509V3_add_value(
                b"X400Name\0" as *const u8 as *const libc::c_char,
                b"<unsupported>\0" as *const u8 as *const libc::c_char,
                &mut ret,
            ) == 0
            {
                return 0 as *mut stack_st_CONF_VALUE;
            }
        }
        5 => {
            if X509V3_add_value(
                b"EdiPartyName\0" as *const u8 as *const libc::c_char,
                b"<unsupported>\0" as *const u8 as *const libc::c_char,
                &mut ret,
            ) == 0
            {
                return 0 as *mut stack_st_CONF_VALUE;
            }
        }
        1 => {
            if x509V3_add_value_asn1_string(
                b"email\0" as *const u8 as *const libc::c_char,
                (*gen).d.ia5,
                &mut ret,
            ) == 0
            {
                return 0 as *mut stack_st_CONF_VALUE;
            }
        }
        2 => {
            if x509V3_add_value_asn1_string(
                b"DNS\0" as *const u8 as *const libc::c_char,
                (*gen).d.ia5,
                &mut ret,
            ) == 0
            {
                return 0 as *mut stack_st_CONF_VALUE;
            }
        }
        6 => {
            if x509V3_add_value_asn1_string(
                b"URI\0" as *const u8 as *const libc::c_char,
                (*gen).d.ia5,
                &mut ret,
            ) == 0
            {
                return 0 as *mut stack_st_CONF_VALUE;
            }
        }
        4 => {
            if (X509_NAME_oneline((*gen).d.dirn, oline.as_mut_ptr(), 256 as libc::c_int))
                .is_null()
                || X509V3_add_value(
                    b"DirName\0" as *const u8 as *const libc::c_char,
                    oline.as_mut_ptr(),
                    &mut ret,
                ) == 0
            {
                return 0 as *mut stack_st_CONF_VALUE;
            }
        }
        7 => {
            p = (*(*gen).d.ip).data;
            if (*(*gen).d.ip).length == 4 as libc::c_int {
                snprintf(
                    oline.as_mut_ptr(),
                    ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                    b"%d.%d.%d.%d\0" as *const u8 as *const libc::c_char,
                    *p.offset(0 as libc::c_int as isize) as libc::c_int,
                    *p.offset(1 as libc::c_int as isize) as libc::c_int,
                    *p.offset(2 as libc::c_int as isize) as libc::c_int,
                    *p.offset(3 as libc::c_int as isize) as libc::c_int,
                );
                current_block_44 = 6417057564578538666;
            } else if (*(*gen).d.ip).length == 16 as libc::c_int {
                oline[0 as libc::c_int as usize] = 0 as libc::c_int as libc::c_char;
                i = 0 as libc::c_int;
                while i < 8 as libc::c_int {
                    let mut v: uint16_t = ((*p.offset(0 as libc::c_int as isize)
                        as uint16_t as libc::c_int) << 8 as libc::c_int
                        | *p.offset(1 as libc::c_int as isize) as libc::c_int)
                        as uint16_t;
                    snprintf(
                        htmp.as_mut_ptr(),
                        ::core::mem::size_of::<[libc::c_char; 5]>() as libc::c_ulong,
                        b"%X\0" as *const u8 as *const libc::c_char,
                        v as libc::c_int,
                    );
                    p = p.offset(2 as libc::c_int as isize);
                    OPENSSL_strlcat(
                        oline.as_mut_ptr(),
                        htmp.as_mut_ptr(),
                        ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
                    );
                    if i != 7 as libc::c_int {
                        OPENSSL_strlcat(
                            oline.as_mut_ptr(),
                            b":\0" as *const u8 as *const libc::c_char,
                            ::core::mem::size_of::<[libc::c_char; 256]>()
                                as libc::c_ulong,
                        );
                    }
                    i += 1;
                    i;
                }
                current_block_44 = 6417057564578538666;
            } else {
                if X509V3_add_value(
                    b"IP Address\0" as *const u8 as *const libc::c_char,
                    b"<invalid>\0" as *const u8 as *const libc::c_char,
                    &mut ret,
                ) == 0
                {
                    return 0 as *mut stack_st_CONF_VALUE;
                }
                current_block_44 = 2543120759711851213;
            }
            match current_block_44 {
                2543120759711851213 => {}
                _ => {
                    if X509V3_add_value(
                        b"IP Address\0" as *const u8 as *const libc::c_char,
                        oline.as_mut_ptr(),
                        &mut ret,
                    ) == 0
                    {
                        return 0 as *mut stack_st_CONF_VALUE;
                    }
                }
            }
        }
        8 => {
            i2t_ASN1_OBJECT(oline.as_mut_ptr(), 256 as libc::c_int, (*gen).d.rid);
            if X509V3_add_value(
                b"Registered ID\0" as *const u8 as *const libc::c_char,
                oline.as_mut_ptr(),
                &mut ret,
            ) == 0
            {
                return 0 as *mut stack_st_CONF_VALUE;
            }
        }
        _ => {}
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn GENERAL_NAME_print(
    mut out: *mut BIO,
    mut gen: *const GENERAL_NAME,
) -> libc::c_int {
    match (*gen).type_0 {
        0 => {
            BIO_printf(
                out,
                b"othername:<unsupported>\0" as *const u8 as *const libc::c_char,
            );
        }
        3 => {
            BIO_printf(
                out,
                b"X400Name:<unsupported>\0" as *const u8 as *const libc::c_char,
            );
        }
        5 => {
            BIO_printf(
                out,
                b"EdiPartyName:<unsupported>\0" as *const u8 as *const libc::c_char,
            );
        }
        1 => {
            BIO_printf(out, b"email:\0" as *const u8 as *const libc::c_char);
            ASN1_STRING_print(out, (*gen).d.ia5);
        }
        2 => {
            BIO_printf(out, b"DNS:\0" as *const u8 as *const libc::c_char);
            ASN1_STRING_print(out, (*gen).d.ia5);
        }
        6 => {
            BIO_printf(out, b"URI:\0" as *const u8 as *const libc::c_char);
            ASN1_STRING_print(out, (*gen).d.ia5);
        }
        4 => {
            BIO_printf(out, b"DirName: \0" as *const u8 as *const libc::c_char);
            X509_NAME_print_ex(
                out,
                (*gen).d.dirn,
                0 as libc::c_int,
                1 as libc::c_ulong | 2 as libc::c_ulong | 4 as libc::c_ulong
                    | 0x10 as libc::c_ulong | 0x100 as libc::c_ulong
                    | 0x200 as libc::c_ulong | 8 as libc::c_ulong
                    | (2 as libc::c_ulong) << 16 as libc::c_int
                    | (1 as libc::c_ulong) << 23 as libc::c_int | 0 as libc::c_ulong,
            );
        }
        7 => {
            let mut p: *const libc::c_uchar = (*(*gen).d.ip).data;
            if (*(*gen).d.ip).length == 4 as libc::c_int {
                BIO_printf(
                    out,
                    b"IP Address:%d.%d.%d.%d\0" as *const u8 as *const libc::c_char,
                    *p.offset(0 as libc::c_int as isize) as libc::c_int,
                    *p.offset(1 as libc::c_int as isize) as libc::c_int,
                    *p.offset(2 as libc::c_int as isize) as libc::c_int,
                    *p.offset(3 as libc::c_int as isize) as libc::c_int,
                );
            } else if (*(*gen).d.ip).length == 16 as libc::c_int {
                BIO_printf(out, b"IP Address\0" as *const u8 as *const libc::c_char);
                let mut i: libc::c_int = 0 as libc::c_int;
                while i < 8 as libc::c_int {
                    let mut v: uint16_t = ((*p.offset(0 as libc::c_int as isize)
                        as uint16_t as libc::c_int) << 8 as libc::c_int
                        | *p.offset(1 as libc::c_int as isize) as libc::c_int)
                        as uint16_t;
                    BIO_printf(
                        out,
                        b":%X\0" as *const u8 as *const libc::c_char,
                        v as libc::c_int,
                    );
                    p = p.offset(2 as libc::c_int as isize);
                    i += 1;
                    i;
                }
                BIO_puts(out, b"\n\0" as *const u8 as *const libc::c_char);
            } else {
                BIO_printf(
                    out,
                    b"IP Address:<invalid>\0" as *const u8 as *const libc::c_char,
                );
            }
        }
        8 => {
            BIO_printf(out, b"Registered ID\0" as *const u8 as *const libc::c_char);
            i2a_ASN1_OBJECT(out, (*gen).d.rid);
        }
        _ => {}
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn v2i_issuer_alt(
    mut method: *const X509V3_EXT_METHOD,
    mut ctx: *const X509V3_CTX,
    mut nval: *const stack_st_CONF_VALUE,
) -> *mut libc::c_void {
    let mut current_block: u64;
    let mut gens: *mut GENERAL_NAMES = sk_GENERAL_NAME_new_null();
    if gens.is_null() {
        return 0 as *mut libc::c_void;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    loop {
        if !(i < sk_CONF_VALUE_num(nval)) {
            current_block = 13536709405535804910;
            break;
        }
        let mut cnf: *const CONF_VALUE = sk_CONF_VALUE_value(nval, i);
        if x509v3_conf_name_matches(
            (*cnf).name,
            b"issuer\0" as *const u8 as *const libc::c_char,
        ) != 0 && !((*cnf).value).is_null()
            && strcmp((*cnf).value, b"copy\0" as *const u8 as *const libc::c_char) == 0
        {
            if copy_issuer(ctx, gens) == 0 {
                current_block = 2650570297374498087;
                break;
            }
        } else {
            let mut gen: *mut GENERAL_NAME = v2i_GENERAL_NAME(method, ctx, cnf);
            if gen.is_null() || sk_GENERAL_NAME_push(gens, gen) == 0 {
                GENERAL_NAME_free(gen);
                current_block = 2650570297374498087;
                break;
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    match current_block {
        13536709405535804910 => return gens as *mut libc::c_void,
        _ => {
            sk_GENERAL_NAME_pop_free(
                gens,
                Some(GENERAL_NAME_free as unsafe extern "C" fn(*mut GENERAL_NAME) -> ()),
            );
            return 0 as *mut libc::c_void;
        }
    };
}
unsafe extern "C" fn copy_issuer(
    mut ctx: *const X509V3_CTX,
    mut gens: *mut GENERAL_NAMES,
) -> libc::c_int {
    let mut current_block: u64;
    if !ctx.is_null() && (*ctx).flags == 0x1 as libc::c_int {
        return 1 as libc::c_int;
    }
    if ctx.is_null() || ((*ctx).issuer_cert).is_null() {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            141 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_alt.c\0" as *const u8
                as *const libc::c_char,
            305 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut i: libc::c_int = X509_get_ext_by_NID(
        (*ctx).issuer_cert,
        85 as libc::c_int,
        -(1 as libc::c_int),
    );
    if i < 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut ialt: *mut GENERAL_NAMES = 0 as *mut GENERAL_NAMES;
    let mut ext: *mut X509_EXTENSION = 0 as *mut X509_EXTENSION;
    ext = X509_get_ext((*ctx).issuer_cert, i);
    if ext.is_null()
        || {
            ialt = X509V3_EXT_d2i(ext) as *mut GENERAL_NAMES;
            ialt.is_null()
        }
    {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            136 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_alt.c\0" as *const u8
                as *const libc::c_char,
            318 as libc::c_int as libc::c_uint,
        );
    } else {
        let mut j: size_t = 0 as libc::c_int as size_t;
        loop {
            if !(j < sk_GENERAL_NAME_num(ialt)) {
                current_block = 8236137900636309791;
                break;
            }
            let mut gen: *mut GENERAL_NAME = sk_GENERAL_NAME_value(ialt, j);
            if sk_GENERAL_NAME_push(gens, gen) == 0 {
                current_block = 6713123492723606712;
                break;
            }
            sk_GENERAL_NAME_set(ialt, j, 0 as *mut GENERAL_NAME);
            j = j.wrapping_add(1);
            j;
        }
        match current_block {
            6713123492723606712 => {}
            _ => {
                ret = 1 as libc::c_int;
            }
        }
    }
    GENERAL_NAMES_free(ialt);
    return ret;
}
unsafe extern "C" fn v2i_subject_alt(
    mut method: *const X509V3_EXT_METHOD,
    mut ctx: *const X509V3_CTX,
    mut nval: *const stack_st_CONF_VALUE,
) -> *mut libc::c_void {
    let mut current_block: u64;
    let mut gens: *mut GENERAL_NAMES = sk_GENERAL_NAME_new_null();
    if gens.is_null() {
        return 0 as *mut libc::c_void;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    loop {
        if !(i < sk_CONF_VALUE_num(nval)) {
            current_block = 3512920355445576850;
            break;
        }
        let mut cnf: *const CONF_VALUE = sk_CONF_VALUE_value(nval, i);
        if x509v3_conf_name_matches(
            (*cnf).name,
            b"email\0" as *const u8 as *const libc::c_char,
        ) != 0 && !((*cnf).value).is_null()
            && strcmp((*cnf).value, b"copy\0" as *const u8 as *const libc::c_char) == 0
        {
            if copy_email(ctx, gens, 0 as libc::c_int) == 0 {
                current_block = 14871721009904760284;
                break;
            }
        } else if x509v3_conf_name_matches(
            (*cnf).name,
            b"email\0" as *const u8 as *const libc::c_char,
        ) != 0 && !((*cnf).value).is_null()
            && strcmp((*cnf).value, b"move\0" as *const u8 as *const libc::c_char) == 0
        {
            if copy_email(ctx, gens, 1 as libc::c_int) == 0 {
                current_block = 14871721009904760284;
                break;
            }
        } else {
            let mut gen: *mut GENERAL_NAME = v2i_GENERAL_NAME(method, ctx, cnf);
            if gen.is_null() || sk_GENERAL_NAME_push(gens, gen) == 0 {
                GENERAL_NAME_free(gen);
                current_block = 14871721009904760284;
                break;
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    match current_block {
        3512920355445576850 => return gens as *mut libc::c_void,
        _ => {
            sk_GENERAL_NAME_pop_free(
                gens,
                Some(GENERAL_NAME_free as unsafe extern "C" fn(*mut GENERAL_NAME) -> ()),
            );
            return 0 as *mut libc::c_void;
        }
    };
}
unsafe extern "C" fn copy_email(
    mut ctx: *const X509V3_CTX,
    mut gens: *mut GENERAL_NAMES,
    mut move_p: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut nm: *mut X509_NAME = 0 as *mut X509_NAME;
    let mut email: *mut ASN1_IA5STRING = 0 as *mut ASN1_IA5STRING;
    let mut ne: *mut X509_NAME_ENTRY = 0 as *mut X509_NAME_ENTRY;
    let mut gen: *mut GENERAL_NAME = 0 as *mut GENERAL_NAME;
    let mut i: libc::c_int = 0;
    if !ctx.is_null() && (*ctx).flags == 0x1 as libc::c_int {
        return 1 as libc::c_int;
    }
    if ctx.is_null() || ((*ctx).subject_cert).is_null() && ((*ctx).subject_req).is_null()
    {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            145 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_alt.c\0" as *const u8
                as *const libc::c_char,
            383 as libc::c_int as libc::c_uint,
        );
    } else {
        if !((*ctx).subject_cert).is_null() {
            nm = X509_get_subject_name((*ctx).subject_cert);
        } else {
            nm = X509_REQ_get_subject_name((*ctx).subject_req);
        }
        i = -(1 as libc::c_int);
        loop {
            i = X509_NAME_get_index_by_NID(nm, 48 as libc::c_int, i);
            if !(i >= 0 as libc::c_int) {
                current_block = 2668756484064249700;
                break;
            }
            ne = X509_NAME_get_entry(nm, i);
            email = ASN1_STRING_dup(X509_NAME_ENTRY_get_data(ne));
            if move_p != 0 {
                X509_NAME_delete_entry(nm, i);
                X509_NAME_ENTRY_free(ne);
                i -= 1;
                i;
            }
            if email.is_null()
                || {
                    gen = GENERAL_NAME_new();
                    gen.is_null()
                }
            {
                current_block = 7736996231541083617;
                break;
            }
            (*gen).d.ia5 = email;
            email = 0 as *mut ASN1_IA5STRING;
            (*gen).type_0 = 1 as libc::c_int;
            if sk_GENERAL_NAME_push(gens, gen) == 0 {
                current_block = 7736996231541083617;
                break;
            }
            gen = 0 as *mut GENERAL_NAME;
        }
        match current_block {
            7736996231541083617 => {}
            _ => return 1 as libc::c_int,
        }
    }
    GENERAL_NAME_free(gen);
    ASN1_IA5STRING_free(email);
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn v2i_GENERAL_NAMES(
    mut method: *const X509V3_EXT_METHOD,
    mut ctx: *const X509V3_CTX,
    mut nval: *const stack_st_CONF_VALUE,
) -> *mut GENERAL_NAMES {
    let mut current_block: u64;
    let mut gens: *mut GENERAL_NAMES = sk_GENERAL_NAME_new_null();
    if gens.is_null() {
        return 0 as *mut GENERAL_NAMES;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    loop {
        if !(i < sk_CONF_VALUE_num(nval)) {
            current_block = 7351195479953500246;
            break;
        }
        let mut cnf: *const CONF_VALUE = sk_CONF_VALUE_value(nval, i);
        let mut gen: *mut GENERAL_NAME = v2i_GENERAL_NAME(method, ctx, cnf);
        if gen.is_null() || sk_GENERAL_NAME_push(gens, gen) == 0 {
            GENERAL_NAME_free(gen);
            current_block = 9328158167074439510;
            break;
        } else {
            i = i.wrapping_add(1);
            i;
        }
    }
    match current_block {
        7351195479953500246 => return gens,
        _ => {
            sk_GENERAL_NAME_pop_free(
                gens,
                Some(GENERAL_NAME_free as unsafe extern "C" fn(*mut GENERAL_NAME) -> ()),
            );
            return 0 as *mut GENERAL_NAMES;
        }
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn v2i_GENERAL_NAME(
    mut method: *const X509V3_EXT_METHOD,
    mut ctx: *const X509V3_CTX,
    mut cnf: *const CONF_VALUE,
) -> *mut GENERAL_NAME {
    return v2i_GENERAL_NAME_ex(
        0 as *mut GENERAL_NAME,
        method,
        ctx,
        cnf,
        0 as libc::c_int,
    );
}
unsafe extern "C" fn a2i_GENERAL_NAME(
    mut out: *mut GENERAL_NAME,
    mut method: *const X509V3_EXT_METHOD,
    mut ctx: *const X509V3_CTX,
    mut gen_type: libc::c_int,
    mut value: *const libc::c_char,
    mut is_nc: libc::c_int,
) -> *mut GENERAL_NAME {
    let mut current_block: u64;
    if value.is_null() {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            137 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_alt.c\0" as *const u8
                as *const libc::c_char,
            454 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut GENERAL_NAME;
    }
    let mut gen: *mut GENERAL_NAME = 0 as *mut GENERAL_NAME;
    if !out.is_null() {
        gen = out;
    } else {
        gen = GENERAL_NAME_new();
        if gen.is_null() {
            return 0 as *mut GENERAL_NAME;
        }
    }
    match gen_type {
        6 | 1 | 2 => {
            let mut str: *mut ASN1_IA5STRING = ASN1_IA5STRING_new();
            if str.is_null()
                || ASN1_STRING_set(
                    str,
                    value as *const libc::c_void,
                    strlen(value) as ossl_ssize_t,
                ) == 0
            {
                ASN1_STRING_free(str);
                current_block = 6636287004453629652;
            } else {
                (*gen).type_0 = gen_type;
                (*gen).d.ia5 = str;
                current_block = 7333393191927787629;
            }
        }
        8 => {
            let mut obj: *mut ASN1_OBJECT = 0 as *mut ASN1_OBJECT;
            obj = OBJ_txt2obj(value, 0 as libc::c_int);
            if obj.is_null() {
                ERR_put_error(
                    20 as libc::c_int,
                    0 as libc::c_int,
                    101 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_alt.c\0"
                        as *const u8 as *const libc::c_char,
                    485 as libc::c_int as libc::c_uint,
                );
                ERR_add_error_data(
                    2 as libc::c_int as libc::c_uint,
                    b"value=\0" as *const u8 as *const libc::c_char,
                    value,
                );
                current_block = 6636287004453629652;
            } else {
                (*gen).type_0 = 8 as libc::c_int;
                (*gen).d.rid = obj;
                current_block = 7333393191927787629;
            }
        }
        7 => {
            (*gen).type_0 = 7 as libc::c_int;
            if is_nc != 0 {
                (*gen).d.ip = a2i_IPADDRESS_NC(value);
            } else {
                (*gen).d.ip = a2i_IPADDRESS(value);
            }
            if ((*gen).d.ip).is_null() {
                ERR_put_error(
                    20 as libc::c_int,
                    0 as libc::c_int,
                    100 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_alt.c\0"
                        as *const u8 as *const libc::c_char,
                    502 as libc::c_int as libc::c_uint,
                );
                ERR_add_error_data(
                    2 as libc::c_int as libc::c_uint,
                    b"value=\0" as *const u8 as *const libc::c_char,
                    value,
                );
                current_block = 6636287004453629652;
            } else {
                current_block = 7333393191927787629;
            }
        }
        4 => {
            if do_dirname(gen, value, ctx) == 0 {
                ERR_put_error(
                    20 as libc::c_int,
                    0 as libc::c_int,
                    105 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_alt.c\0"
                        as *const u8 as *const libc::c_char,
                    510 as libc::c_int as libc::c_uint,
                );
                current_block = 6636287004453629652;
            } else {
                current_block = 7333393191927787629;
            }
        }
        0 => {
            if do_othername(gen, value, ctx) == 0 {
                ERR_put_error(
                    20 as libc::c_int,
                    0 as libc::c_int,
                    148 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_alt.c\0"
                        as *const u8 as *const libc::c_char,
                    517 as libc::c_int as libc::c_uint,
                );
                current_block = 6636287004453629652;
            } else {
                current_block = 7333393191927787629;
            }
        }
        _ => {
            ERR_put_error(
                20 as libc::c_int,
                0 as libc::c_int,
                161 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_alt.c\0" as *const u8
                    as *const libc::c_char,
                522 as libc::c_int as libc::c_uint,
            );
            current_block = 6636287004453629652;
        }
    }
    match current_block {
        7333393191927787629 => return gen,
        _ => {
            if out.is_null() {
                GENERAL_NAME_free(gen);
            }
            return 0 as *mut GENERAL_NAME;
        }
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn v2i_GENERAL_NAME_ex(
    mut out: *mut GENERAL_NAME,
    mut method: *const X509V3_EXT_METHOD,
    mut ctx: *const X509V3_CTX,
    mut cnf: *const CONF_VALUE,
    mut is_nc: libc::c_int,
) -> *mut GENERAL_NAME {
    let mut name: *const libc::c_char = (*cnf).name;
    let mut value: *const libc::c_char = (*cnf).value;
    if value.is_null() {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            137 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_alt.c\0" as *const u8
                as *const libc::c_char,
            542 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut GENERAL_NAME;
    }
    let mut type_0: libc::c_int = 0;
    if x509v3_conf_name_matches(name, b"email\0" as *const u8 as *const libc::c_char)
        != 0
    {
        type_0 = 1 as libc::c_int;
    } else if x509v3_conf_name_matches(
        name,
        b"URI\0" as *const u8 as *const libc::c_char,
    ) != 0
    {
        type_0 = 6 as libc::c_int;
    } else if x509v3_conf_name_matches(
        name,
        b"DNS\0" as *const u8 as *const libc::c_char,
    ) != 0
    {
        type_0 = 2 as libc::c_int;
    } else if x509v3_conf_name_matches(
        name,
        b"RID\0" as *const u8 as *const libc::c_char,
    ) != 0
    {
        type_0 = 8 as libc::c_int;
    } else if x509v3_conf_name_matches(name, b"IP\0" as *const u8 as *const libc::c_char)
        != 0
    {
        type_0 = 7 as libc::c_int;
    } else if x509v3_conf_name_matches(
        name,
        b"dirName\0" as *const u8 as *const libc::c_char,
    ) != 0
    {
        type_0 = 4 as libc::c_int;
    } else if x509v3_conf_name_matches(
        name,
        b"otherName\0" as *const u8 as *const libc::c_char,
    ) != 0
    {
        type_0 = 0 as libc::c_int;
    } else {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            160 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_alt.c\0" as *const u8
                as *const libc::c_char,
            562 as libc::c_int as libc::c_uint,
        );
        ERR_add_error_data(
            2 as libc::c_int as libc::c_uint,
            b"name=\0" as *const u8 as *const libc::c_char,
            name,
        );
        return 0 as *mut GENERAL_NAME;
    }
    return a2i_GENERAL_NAME(out, method, ctx, type_0, value, is_nc);
}
unsafe extern "C" fn do_othername(
    mut gen: *mut GENERAL_NAME,
    mut value: *const libc::c_char,
    mut ctx: *const X509V3_CTX,
) -> libc::c_int {
    let mut semicolon: *const libc::c_char = strchr(value, ';' as i32);
    if semicolon.is_null() {
        return 0 as libc::c_int;
    }
    let mut name: *mut OTHERNAME = OTHERNAME_new();
    if name.is_null() {
        return 0 as libc::c_int;
    }
    let mut objtmp: *mut libc::c_char = OPENSSL_strndup(
        value,
        semicolon.offset_from(value) as libc::c_long as size_t,
    );
    if !objtmp.is_null() {
        ASN1_OBJECT_free((*name).type_id);
        (*name).type_id = OBJ_txt2obj(objtmp, 0 as libc::c_int);
        OPENSSL_free(objtmp as *mut libc::c_void);
        if !((*name).type_id).is_null() {
            ASN1_TYPE_free((*name).value);
            (*name)
                .value = ASN1_generate_v3(
                semicolon.offset(1 as libc::c_int as isize),
                ctx,
            );
            if !((*name).value).is_null() {
                (*gen).type_0 = 0 as libc::c_int;
                (*gen).d.otherName = name;
                return 1 as libc::c_int;
            }
        }
    }
    OTHERNAME_free(name);
    return 0 as libc::c_int;
}
unsafe extern "C" fn do_dirname(
    mut gen: *mut GENERAL_NAME,
    mut value: *const libc::c_char,
    mut ctx: *const X509V3_CTX,
) -> libc::c_int {
    let mut sk: *const stack_st_CONF_VALUE = 0 as *const stack_st_CONF_VALUE;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut nm: *mut X509_NAME = X509_NAME_new();
    if !nm.is_null() {
        sk = X509V3_get_section(ctx, value);
        if sk.is_null() {
            ERR_put_error(
                20 as libc::c_int,
                0 as libc::c_int,
                153 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_alt.c\0" as *const u8
                    as *const libc::c_char,
                617 as libc::c_int as libc::c_uint,
            );
            ERR_add_error_data(
                2 as libc::c_int as libc::c_uint,
                b"section=\0" as *const u8 as *const libc::c_char,
                value,
            );
        } else if !(X509V3_NAME_from_section(
            nm,
            sk,
            0x1000 as libc::c_int | 1 as libc::c_int,
        ) == 0)
        {
            (*gen).type_0 = 4 as libc::c_int;
            (*gen).d.dirn = nm;
            ret = 1 as libc::c_int;
        }
    }
    if ret == 0 {
        X509_NAME_free(nm);
    }
    return ret;
}
