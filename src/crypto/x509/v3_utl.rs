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
    pub type stack_st_OPENSSL_STRING;
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
    fn sscanf(_: *const libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn memchr(
        _: *const libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strncmp(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn ASN1_OCTET_STRING_new() -> *mut ASN1_OCTET_STRING;
    fn ASN1_OCTET_STRING_free(str: *mut ASN1_OCTET_STRING);
    fn ASN1_OCTET_STRING_set(
        str: *mut ASN1_OCTET_STRING,
        data: *const libc::c_uchar,
        len: libc::c_int,
    ) -> libc::c_int;
    fn ASN1_STRING_to_UTF8(
        out: *mut *mut libc::c_uchar,
        in_0: *const ASN1_STRING,
    ) -> libc::c_int;
    fn ASN1_INTEGER_free(str: *mut ASN1_INTEGER);
    fn BN_to_ASN1_INTEGER(bn: *const BIGNUM, ai: *mut ASN1_INTEGER) -> *mut ASN1_INTEGER;
    fn ASN1_INTEGER_to_BN(ai: *const ASN1_INTEGER, bn: *mut BIGNUM) -> *mut BIGNUM;
    fn ASN1_ENUMERATED_to_BN(ai: *const ASN1_ENUMERATED, bn: *mut BIGNUM) -> *mut BIGNUM;
    fn X509_get_subject_name(x509: *const X509) -> *mut X509_NAME;
    fn X509_get_ext_d2i(
        x509: *const X509,
        nid: libc::c_int,
        out_critical: *mut libc::c_int,
        out_idx: *mut libc::c_int,
    ) -> *mut libc::c_void;
    fn X509_REQ_get_subject_name(req: *const X509_REQ) -> *mut X509_NAME;
    fn X509_REQ_get_extensions(req: *const X509_REQ) -> *mut stack_st_X509_EXTENSION;
    fn X509_NAME_get_index_by_NID(
        name: *const X509_NAME,
        nid: libc::c_int,
        lastpos: libc::c_int,
    ) -> libc::c_int;
    fn X509_NAME_get_entry(
        name: *const X509_NAME,
        loc: libc::c_int,
    ) -> *mut X509_NAME_ENTRY;
    fn X509_NAME_add_entry_by_txt(
        name: *mut X509_NAME,
        field: *const libc::c_char,
        type_0: libc::c_int,
        bytes: *const uint8_t,
        len: ossl_ssize_t,
        loc: libc::c_int,
        set: libc::c_int,
    ) -> libc::c_int;
    fn X509_NAME_ENTRY_get_data(entry: *const X509_NAME_ENTRY) -> *mut ASN1_STRING;
    fn X509_EXTENSION_free(ex: *mut X509_EXTENSION);
    fn X509V3_get_d2i(
        extensions: *const stack_st_X509_EXTENSION,
        nid: libc::c_int,
        out_critical: *mut libc::c_int,
        out_idx: *mut libc::c_int,
    ) -> *mut libc::c_void;
    fn GENERAL_NAME_free(gen: *mut GENERAL_NAME);
    fn GENERAL_NAMES_free(gens: *mut GENERAL_NAMES);
    fn AUTHORITY_INFO_ACCESS_free(aia: *mut AUTHORITY_INFO_ACCESS);
    fn BN_new() -> *mut BIGNUM;
    fn BN_free(bn: *mut BIGNUM);
    fn BN_num_bits(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_bn2hex(bn: *const BIGNUM) -> *mut libc::c_char;
    fn BN_hex2bn(outp: *mut *mut BIGNUM, in_0: *const libc::c_char) -> libc::c_int;
    fn BN_bn2dec(a: *const BIGNUM) -> *mut libc::c_char;
    fn BN_dec2bn(outp: *mut *mut BIGNUM, in_0: *const libc::c_char) -> libc::c_int;
    fn BN_is_zero(bn: *const BIGNUM) -> libc::c_int;
    fn OPENSSL_sk_new(comp: OPENSSL_sk_cmp_func) -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_free(sk: *mut OPENSSL_STACK);
    fn OPENSSL_sk_pop_free_ex(
        sk: *mut OPENSSL_STACK,
        call_free_func: OPENSSL_sk_call_free_func,
        free_func: OPENSSL_sk_free_func,
    );
    fn OPENSSL_sk_find(
        sk: *const OPENSSL_STACK,
        out_index: *mut size_t,
        p: *const libc::c_void,
        call_cmp_func: OPENSSL_sk_call_cmp_func,
    ) -> libc::c_int;
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn OPENSSL_sk_sort(sk: *mut OPENSSL_STACK, call_cmp_func: OPENSSL_sk_call_cmp_func);
    fn CBB_init(cbb: *mut CBB, initial_capacity: size_t) -> libc::c_int;
    fn CBB_cleanup(cbb: *mut CBB);
    fn CBB_finish(
        cbb: *mut CBB,
        out_data: *mut *mut uint8_t,
        out_len: *mut size_t,
    ) -> libc::c_int;
    fn CBB_add_u8(cbb: *mut CBB, value: uint8_t) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_strdup(s: *const libc::c_char) -> *mut libc::c_char;
    fn OPENSSL_fromxdigit(out: *mut uint8_t, c: libc::c_int) -> libc::c_int;
    fn OPENSSL_isalnum(c: libc::c_int) -> libc::c_int;
    fn OPENSSL_tolower(c: libc::c_int) -> libc::c_int;
    fn OPENSSL_isspace(c: libc::c_int) -> libc::c_int;
    fn OPENSSL_strncasecmp(
        a: *const libc::c_char,
        b: *const libc::c_char,
        n: size_t,
    ) -> libc::c_int;
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
    fn OBJ_obj2nid(obj: *const ASN1_OBJECT) -> libc::c_int;
    fn CONF_VALUE_new() -> *mut CONF_VALUE;
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
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type size_t = libc::c_ulong;
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
pub type BIGNUM = bignum_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bignum_st {
    pub d: *mut BN_ULONG,
    pub width: libc::c_int,
    pub dmax: libc::c_int,
    pub neg: libc::c_int,
    pub flags: libc::c_int,
}
pub type BN_ULONG = uint64_t;
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
pub struct cbb_st {
    pub child: *mut CBB,
    pub is_child: libc::c_char,
    pub u: C2RustUnnamed_2,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_2 {
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
pub type OPENSSL_sk_cmp_func = Option::<
    unsafe extern "C" fn(
        *const *const libc::c_void,
        *const *const libc::c_void,
    ) -> libc::c_int,
>;
pub type OPENSSL_sk_call_free_func = Option::<
    unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
>;
pub type OPENSSL_sk_call_cmp_func = Option::<
    unsafe extern "C" fn(
        OPENSSL_sk_cmp_func,
        *const libc::c_void,
        *const libc::c_void,
    ) -> libc::c_int,
>;
pub type OPENSSL_STACK = stack_st;
pub type OPENSSL_STRING = *mut libc::c_char;
pub type sk_OPENSSL_STRING_free_func = Option::<
    unsafe extern "C" fn(*mut libc::c_char) -> (),
>;
pub type sk_OPENSSL_STRING_cmp_func = Option::<
    unsafe extern "C" fn(
        *const *const libc::c_char,
        *const *const libc::c_char,
    ) -> libc::c_int,
>;
pub type sk_CONF_VALUE_free_func = Option::<unsafe extern "C" fn(*mut CONF_VALUE) -> ()>;
pub type sk_GENERAL_NAME_free_func = Option::<
    unsafe extern "C" fn(*mut GENERAL_NAME) -> (),
>;
pub type AUTHORITY_INFO_ACCESS = stack_st_ACCESS_DESCRIPTION;
pub type ACCESS_DESCRIPTION = ACCESS_DESCRIPTION_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ACCESS_DESCRIPTION_st {
    pub method: *mut ASN1_OBJECT,
    pub location: *mut GENERAL_NAME,
}
pub type sk_X509_EXTENSION_free_func = Option::<
    unsafe extern "C" fn(*mut X509_EXTENSION) -> (),
>;
pub type equal_fn = Option::<
    unsafe extern "C" fn(
        *const libc::c_uchar,
        size_t,
        *const libc::c_uchar,
        size_t,
        libc::c_uint,
    ) -> libc::c_int,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct IPV6_STAT {
    pub tmp: [libc::c_uchar; 16],
    pub total: libc::c_int,
    pub zero_pos: libc::c_int,
    pub zero_cnt: libc::c_int,
}
#[inline]
unsafe extern "C" fn sk_GENERAL_NAME_num(
    mut sk: *const stack_st_GENERAL_NAME,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
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
unsafe extern "C" fn sk_GENERAL_NAME_value(
    mut sk: *const stack_st_GENERAL_NAME,
    mut i: size_t,
) -> *mut GENERAL_NAME {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut GENERAL_NAME;
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
unsafe extern "C" fn sk_ACCESS_DESCRIPTION_value(
    mut sk: *const stack_st_ACCESS_DESCRIPTION,
    mut i: size_t,
) -> *mut ACCESS_DESCRIPTION {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut ACCESS_DESCRIPTION;
}
#[inline]
unsafe extern "C" fn sk_ACCESS_DESCRIPTION_num(
    mut sk: *const stack_st_ACCESS_DESCRIPTION,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_OPENSSL_STRING_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<
        OPENSSL_sk_free_func,
        sk_OPENSSL_STRING_free_func,
    >(free_func))
        .expect("non-null function pointer")(ptr as *mut libc::c_char);
}
#[inline]
unsafe extern "C" fn sk_OPENSSL_STRING_call_cmp_func(
    mut cmp_func: OPENSSL_sk_cmp_func,
    mut a: *const libc::c_void,
    mut b: *const libc::c_void,
) -> libc::c_int {
    let mut a_ptr: *const libc::c_char = a as *const libc::c_char;
    let mut b_ptr: *const libc::c_char = b as *const libc::c_char;
    return (::core::mem::transmute::<
        OPENSSL_sk_cmp_func,
        sk_OPENSSL_STRING_cmp_func,
    >(cmp_func))
        .expect("non-null function pointer")(&mut a_ptr, &mut b_ptr);
}
#[inline]
unsafe extern "C" fn sk_OPENSSL_STRING_new(
    mut comp: sk_OPENSSL_STRING_cmp_func,
) -> *mut stack_st_OPENSSL_STRING {
    return OPENSSL_sk_new(
        ::core::mem::transmute::<sk_OPENSSL_STRING_cmp_func, OPENSSL_sk_cmp_func>(comp),
    ) as *mut stack_st_OPENSSL_STRING;
}
#[inline]
unsafe extern "C" fn sk_OPENSSL_STRING_pop_free(
    mut sk: *mut stack_st_OPENSSL_STRING,
    mut free_func: sk_OPENSSL_STRING_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_OPENSSL_STRING_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_OPENSSL_STRING_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_OPENSSL_STRING_find_awslc(
    mut sk: *const stack_st_OPENSSL_STRING,
    mut out_index: *mut size_t,
    mut p: *const libc::c_char,
) -> libc::c_int {
    return OPENSSL_sk_find(
        sk as *const OPENSSL_STACK,
        out_index,
        p as *const libc::c_void,
        Some(
            sk_OPENSSL_STRING_call_cmp_func
                as unsafe extern "C" fn(
                    OPENSSL_sk_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
}
#[inline]
unsafe extern "C" fn sk_OPENSSL_STRING_push(
    mut sk: *mut stack_st_OPENSSL_STRING,
    mut p: *mut libc::c_char,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_OPENSSL_STRING_sort(mut sk: *mut stack_st_OPENSSL_STRING) {
    OPENSSL_sk_sort(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_OPENSSL_STRING_call_cmp_func
                as unsafe extern "C" fn(
                    OPENSSL_sk_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
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
unsafe extern "C" fn sk_CONF_VALUE_push(
    mut sk: *mut stack_st_CONF_VALUE,
    mut p: *mut CONF_VALUE,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_CONF_VALUE_new_null() -> *mut stack_st_CONF_VALUE {
    return OPENSSL_sk_new_null() as *mut stack_st_CONF_VALUE;
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
unsafe extern "C" fn sk_CONF_VALUE_free(mut sk: *mut stack_st_CONF_VALUE) {
    OPENSSL_sk_free(sk as *mut OPENSSL_STACK);
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
unsafe extern "C" fn OPENSSL_memchr(
    mut s: *const libc::c_void,
    mut c: libc::c_int,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return 0 as *mut libc::c_void;
    }
    return memchr(s, c, n);
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
#[inline]
unsafe extern "C" fn OPENSSL_memcpy(
    mut dst: *mut libc::c_void,
    mut src: *const libc::c_void,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return dst;
    }
    return memcpy(dst, src, n);
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
unsafe extern "C" fn x509V3_add_len_value(
    mut name: *const libc::c_char,
    mut value: *const libc::c_char,
    mut value_len: size_t,
    mut omit_value: libc::c_int,
    mut extlist: *mut *mut stack_st_CONF_VALUE,
) -> libc::c_int {
    let mut current_block: u64;
    let mut vtmp: *mut CONF_VALUE = 0 as *mut CONF_VALUE;
    let mut tname: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tvalue: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut extlist_was_null: libc::c_int = (*extlist
        == 0 as *mut libc::c_void as *mut stack_st_CONF_VALUE) as libc::c_int;
    if !(!name.is_null()
        && {
            tname = OPENSSL_strdup(name);
            tname.is_null()
        })
    {
        if omit_value == 0 {
            if !(OPENSSL_memchr(
                value as *const libc::c_void,
                0 as libc::c_int,
                value_len,
            ))
                .is_null()
            {
                ERR_put_error(
                    20 as libc::c_int,
                    0 as libc::c_int,
                    163 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_utl.c\0"
                        as *const u8 as *const libc::c_char,
                    104 as libc::c_int as libc::c_uint,
                );
                current_block = 4986702840849568528;
            } else {
                tvalue = OPENSSL_strndup(value, value_len);
                if tvalue.is_null() {
                    current_block = 4986702840849568528;
                } else {
                    current_block = 6937071982253665452;
                }
            }
        } else {
            current_block = 6937071982253665452;
        }
        match current_block {
            4986702840849568528 => {}
            _ => {
                vtmp = CONF_VALUE_new();
                if !vtmp.is_null() {
                    if !((*extlist).is_null()
                        && {
                            *extlist = sk_CONF_VALUE_new_null();
                            (*extlist).is_null()
                        })
                    {
                        (*vtmp).section = 0 as *mut libc::c_char;
                        (*vtmp).name = tname;
                        (*vtmp).value = tvalue;
                        if !(sk_CONF_VALUE_push(*extlist, vtmp) == 0) {
                            return 1 as libc::c_int;
                        }
                    }
                }
            }
        }
    }
    if extlist_was_null != 0 {
        sk_CONF_VALUE_free(*extlist);
        *extlist = 0 as *mut stack_st_CONF_VALUE;
    }
    OPENSSL_free(vtmp as *mut libc::c_void);
    OPENSSL_free(tname as *mut libc::c_void);
    OPENSSL_free(tvalue as *mut libc::c_void);
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509V3_add_value(
    mut name: *const libc::c_char,
    mut value: *const libc::c_char,
    mut extlist: *mut *mut stack_st_CONF_VALUE,
) -> libc::c_int {
    return x509V3_add_len_value(
        name,
        value,
        if !value.is_null() { strlen(value) } else { 0 as libc::c_int as libc::c_ulong },
        (value == 0 as *mut libc::c_void as *const libc::c_char) as libc::c_int,
        extlist,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn x509V3_add_value_asn1_string(
    mut name: *const libc::c_char,
    mut value: *const ASN1_STRING,
    mut extlist: *mut *mut stack_st_CONF_VALUE,
) -> libc::c_int {
    return x509V3_add_len_value(
        name,
        (*value).data as *const libc::c_char,
        (*value).length as size_t,
        0 as libc::c_int,
        extlist,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509V3_conf_free(mut conf: *mut CONF_VALUE) {
    if conf.is_null() {
        return;
    }
    OPENSSL_free((*conf).name as *mut libc::c_void);
    OPENSSL_free((*conf).value as *mut libc::c_void);
    OPENSSL_free((*conf).section as *mut libc::c_void);
    OPENSSL_free(conf as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509V3_add_value_bool(
    mut name: *const libc::c_char,
    mut asn1_bool: libc::c_int,
    mut extlist: *mut *mut stack_st_CONF_VALUE,
) -> libc::c_int {
    if asn1_bool != 0 {
        return X509V3_add_value(
            name,
            b"TRUE\0" as *const u8 as *const libc::c_char,
            extlist,
        );
    }
    return X509V3_add_value(
        name,
        b"FALSE\0" as *const u8 as *const libc::c_char,
        extlist,
    );
}
unsafe extern "C" fn bignum_to_string(mut bn: *const BIGNUM) -> *mut libc::c_char {
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: size_t = 0;
    if BN_num_bits(bn) < 128 as libc::c_int as libc::c_uint {
        return BN_bn2dec(bn);
    }
    tmp = BN_bn2hex(bn);
    if tmp.is_null() {
        return 0 as *mut libc::c_char;
    }
    len = (strlen(tmp)).wrapping_add(3 as libc::c_int as libc::c_ulong);
    ret = OPENSSL_malloc(len) as *mut libc::c_char;
    if ret.is_null() {
        OPENSSL_free(tmp as *mut libc::c_void);
        return 0 as *mut libc::c_char;
    }
    if *tmp.offset(0 as libc::c_int as isize) as libc::c_int == '-' as i32 {
        OPENSSL_strlcpy(ret, b"-0x\0" as *const u8 as *const libc::c_char, len);
        OPENSSL_strlcat(ret, tmp.offset(1 as libc::c_int as isize), len);
    } else {
        OPENSSL_strlcpy(ret, b"0x\0" as *const u8 as *const libc::c_char, len);
        OPENSSL_strlcat(ret, tmp, len);
    }
    OPENSSL_free(tmp as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2s_ASN1_ENUMERATED(
    mut method: *const X509V3_EXT_METHOD,
    mut a: *const ASN1_ENUMERATED,
) -> *mut libc::c_char {
    let mut bntmp: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut strtmp: *mut libc::c_char = 0 as *mut libc::c_char;
    if a.is_null() {
        return 0 as *mut libc::c_char;
    }
    bntmp = ASN1_ENUMERATED_to_BN(a, 0 as *mut BIGNUM);
    bntmp.is_null()
        || {
            strtmp = bignum_to_string(bntmp);
            strtmp.is_null()
        };
    BN_free(bntmp);
    return strtmp;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2s_ASN1_INTEGER(
    mut method: *const X509V3_EXT_METHOD,
    mut a: *const ASN1_INTEGER,
) -> *mut libc::c_char {
    let mut bntmp: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut strtmp: *mut libc::c_char = 0 as *mut libc::c_char;
    if a.is_null() {
        return 0 as *mut libc::c_char;
    }
    bntmp = ASN1_INTEGER_to_BN(a, 0 as *mut BIGNUM);
    bntmp.is_null()
        || {
            strtmp = bignum_to_string(bntmp);
            strtmp.is_null()
        };
    BN_free(bntmp);
    return strtmp;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn s2i_ASN1_INTEGER(
    mut method: *const X509V3_EXT_METHOD,
    mut value: *const libc::c_char,
) -> *mut ASN1_INTEGER {
    let mut bn: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut aint: *mut ASN1_INTEGER = 0 as *mut ASN1_INTEGER;
    let mut isneg: libc::c_int = 0;
    let mut ishex: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    if value.is_null() {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            126 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_utl.c\0" as *const u8
                as *const libc::c_char,
            238 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut ASN1_INTEGER;
    }
    bn = BN_new();
    if *value.offset(0 as libc::c_int as isize) as libc::c_int == '-' as i32 {
        value = value.offset(1);
        value;
        isneg = 1 as libc::c_int;
    } else {
        isneg = 0 as libc::c_int;
    }
    if *value.offset(0 as libc::c_int as isize) as libc::c_int == '0' as i32
        && (*value.offset(1 as libc::c_int as isize) as libc::c_int == 'x' as i32
            || *value.offset(1 as libc::c_int as isize) as libc::c_int == 'X' as i32)
    {
        value = value.offset(2 as libc::c_int as isize);
        ishex = 1 as libc::c_int;
    } else {
        ishex = 0 as libc::c_int;
    }
    if ishex != 0 {
        ret = BN_hex2bn(&mut bn, value);
    } else {
        if strlen(value) > 8192 as libc::c_int as libc::c_ulong {
            BN_free(bn);
            ERR_put_error(
                20 as libc::c_int,
                0 as libc::c_int,
                127 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_utl.c\0" as *const u8
                    as *const libc::c_char,
                266 as libc::c_int as libc::c_uint,
            );
            return 0 as *mut ASN1_INTEGER;
        }
        ret = BN_dec2bn(&mut bn, value);
    }
    if ret == 0 || *value.offset(ret as isize) as libc::c_int != 0 {
        BN_free(bn);
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_utl.c\0" as *const u8
                as *const libc::c_char,
            274 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut ASN1_INTEGER;
    }
    if isneg != 0 && BN_is_zero(bn) != 0 {
        isneg = 0 as libc::c_int;
    }
    aint = BN_to_ASN1_INTEGER(bn, 0 as *mut ASN1_INTEGER);
    BN_free(bn);
    if aint.is_null() {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            103 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_utl.c\0" as *const u8
                as *const libc::c_char,
            285 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut ASN1_INTEGER;
    }
    if isneg != 0 {
        (*aint).type_0 |= 0x100 as libc::c_int;
    }
    return aint;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509V3_add_value_int(
    mut name: *const libc::c_char,
    mut aint: *const ASN1_INTEGER,
    mut extlist: *mut *mut stack_st_CONF_VALUE,
) -> libc::c_int {
    let mut strtmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ret: libc::c_int = 0;
    if aint.is_null() {
        return 1 as libc::c_int;
    }
    strtmp = i2s_ASN1_INTEGER(0 as *const X509V3_EXT_METHOD, aint);
    if strtmp.is_null() {
        return 0 as libc::c_int;
    }
    ret = X509V3_add_value(name, strtmp, extlist);
    OPENSSL_free(strtmp as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509V3_bool_from_string(
    mut str: *const libc::c_char,
    mut out_bool: *mut ASN1_BOOLEAN,
) -> libc::c_int {
    if strcmp(str, b"TRUE\0" as *const u8 as *const libc::c_char) == 0
        || strcmp(str, b"true\0" as *const u8 as *const libc::c_char) == 0
        || strcmp(str, b"Y\0" as *const u8 as *const libc::c_char) == 0
        || strcmp(str, b"y\0" as *const u8 as *const libc::c_char) == 0
        || strcmp(str, b"YES\0" as *const u8 as *const libc::c_char) == 0
        || strcmp(str, b"yes\0" as *const u8 as *const libc::c_char) == 0
    {
        *out_bool = 0xff as libc::c_int;
        return 1 as libc::c_int;
    }
    if strcmp(str, b"FALSE\0" as *const u8 as *const libc::c_char) == 0
        || strcmp(str, b"false\0" as *const u8 as *const libc::c_char) == 0
        || strcmp(str, b"N\0" as *const u8 as *const libc::c_char) == 0
        || strcmp(str, b"n\0" as *const u8 as *const libc::c_char) == 0
        || strcmp(str, b"NO\0" as *const u8 as *const libc::c_char) == 0
        || strcmp(str, b"no\0" as *const u8 as *const libc::c_char) == 0
    {
        *out_bool = 0 as libc::c_int;
        return 1 as libc::c_int;
    }
    ERR_put_error(
        20 as libc::c_int,
        0 as libc::c_int,
        120 as libc::c_int,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_utl.c\0" as *const u8
            as *const libc::c_char,
        320 as libc::c_int as libc::c_uint,
    );
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509V3_get_value_bool(
    mut value: *const CONF_VALUE,
    mut out_bool: *mut ASN1_BOOLEAN,
) -> libc::c_int {
    let mut btmp: *const libc::c_char = (*value).value;
    if btmp.is_null() {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            120 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_utl.c\0" as *const u8
                as *const libc::c_char,
            327 as libc::c_int as libc::c_uint,
        );
    } else if !(X509V3_bool_from_string(btmp, out_bool) == 0) {
        return 1 as libc::c_int
    }
    ERR_add_error_data(
        6 as libc::c_int as libc::c_uint,
        b"section:\0" as *const u8 as *const libc::c_char,
        (*value).section,
        b",name:\0" as *const u8 as *const libc::c_char,
        (*value).name,
        b",value:\0" as *const u8 as *const libc::c_char,
        (*value).value,
    );
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509V3_get_value_int(
    mut value: *const CONF_VALUE,
    mut aint: *mut *mut ASN1_INTEGER,
) -> libc::c_int {
    let mut itmp: *mut ASN1_INTEGER = 0 as *mut ASN1_INTEGER;
    itmp = s2i_ASN1_INTEGER(0 as *const X509V3_EXT_METHOD, (*value).value);
    if itmp.is_null() {
        ERR_add_error_data(
            6 as libc::c_int as libc::c_uint,
            b"section:\0" as *const u8 as *const libc::c_char,
            (*value).section,
            b",name:\0" as *const u8 as *const libc::c_char,
            (*value).name,
            b",value:\0" as *const u8 as *const libc::c_char,
            (*value).value,
        );
        return 0 as libc::c_int;
    }
    ASN1_INTEGER_free(*aint);
    *aint = itmp;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509V3_parse_list(
    mut line: *const libc::c_char,
) -> *mut stack_st_CONF_VALUE {
    let mut current_block: u64;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut q: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut c: libc::c_char = 0;
    let mut ntmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut vtmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut values: *mut stack_st_CONF_VALUE = 0 as *mut stack_st_CONF_VALUE;
    let mut linebuf: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut state: libc::c_int = 0;
    linebuf = OPENSSL_strdup(line);
    if !linebuf.is_null() {
        state = 1 as libc::c_int;
        ntmp = 0 as *mut libc::c_char;
        p = linebuf;
        q = linebuf;
        loop {
            c = *p;
            if !(c as libc::c_int != 0 && c as libc::c_int != '\r' as i32
                && c as libc::c_int != '\n' as i32)
            {
                current_block = 16924917904204750491;
                break;
            }
            match state {
                1 => {
                    if c as libc::c_int == ':' as i32 {
                        state = 2 as libc::c_int;
                        *p = 0 as libc::c_int as libc::c_char;
                        ntmp = strip_spaces(q);
                        if ntmp.is_null() {
                            ERR_put_error(
                                20 as libc::c_int,
                                0 as libc::c_int,
                                125 as libc::c_int,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_utl.c\0"
                                    as *const u8 as *const libc::c_char,
                                378 as libc::c_int as libc::c_uint,
                            );
                            current_block = 5259496027229040717;
                            break;
                        } else {
                            q = p.offset(1 as libc::c_int as isize);
                        }
                    } else if c as libc::c_int == ',' as i32 {
                        *p = 0 as libc::c_int as libc::c_char;
                        ntmp = strip_spaces(q);
                        q = p.offset(1 as libc::c_int as isize);
                        if ntmp.is_null() {
                            ERR_put_error(
                                20 as libc::c_int,
                                0 as libc::c_int,
                                125 as libc::c_int,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_utl.c\0"
                                    as *const u8 as *const libc::c_char,
                                390 as libc::c_int as libc::c_uint,
                            );
                            current_block = 5259496027229040717;
                            break;
                        } else {
                            X509V3_add_value(
                                ntmp,
                                0 as *const libc::c_char,
                                &mut values,
                            );
                        }
                    }
                }
                2 => {
                    if c as libc::c_int == ',' as i32 {
                        state = 1 as libc::c_int;
                        *p = 0 as libc::c_int as libc::c_char;
                        vtmp = strip_spaces(q);
                        if vtmp.is_null() {
                            ERR_put_error(
                                20 as libc::c_int,
                                0 as libc::c_int,
                                126 as libc::c_int,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_utl.c\0"
                                    as *const u8 as *const libc::c_char,
                                406 as libc::c_int as libc::c_uint,
                            );
                            current_block = 5259496027229040717;
                            break;
                        } else {
                            X509V3_add_value(ntmp, vtmp, &mut values);
                            ntmp = 0 as *mut libc::c_char;
                            q = p.offset(1 as libc::c_int as isize);
                        }
                    }
                }
                _ => {}
            }
            p = p.offset(1);
            p;
        }
        match current_block {
            5259496027229040717 => {}
            _ => {
                if state == 2 as libc::c_int {
                    vtmp = strip_spaces(q);
                    if vtmp.is_null() {
                        ERR_put_error(
                            20 as libc::c_int,
                            0 as libc::c_int,
                            126 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_utl.c\0"
                                as *const u8 as *const libc::c_char,
                            422 as libc::c_int as libc::c_uint,
                        );
                        current_block = 5259496027229040717;
                    } else {
                        X509V3_add_value(ntmp, vtmp, &mut values);
                        current_block = 15597372965620363352;
                    }
                } else {
                    ntmp = strip_spaces(q);
                    if ntmp.is_null() {
                        ERR_put_error(
                            20 as libc::c_int,
                            0 as libc::c_int,
                            125 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_utl.c\0"
                                as *const u8 as *const libc::c_char,
                            432 as libc::c_int as libc::c_uint,
                        );
                        current_block = 5259496027229040717;
                    } else {
                        X509V3_add_value(ntmp, 0 as *const libc::c_char, &mut values);
                        current_block = 15597372965620363352;
                    }
                }
                match current_block {
                    5259496027229040717 => {}
                    _ => {
                        OPENSSL_free(linebuf as *mut libc::c_void);
                        return values;
                    }
                }
            }
        }
    }
    OPENSSL_free(linebuf as *mut libc::c_void);
    sk_CONF_VALUE_pop_free(
        values,
        Some(X509V3_conf_free as unsafe extern "C" fn(*mut CONF_VALUE) -> ()),
    );
    return 0 as *mut stack_st_CONF_VALUE;
}
unsafe extern "C" fn strip_spaces(mut name: *mut libc::c_char) -> *mut libc::c_char {
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut q: *mut libc::c_char = 0 as *mut libc::c_char;
    p = name;
    while *p as libc::c_int != 0
        && OPENSSL_isspace(*p as libc::c_uchar as libc::c_int) != 0
    {
        p = p.offset(1);
        p;
    }
    if *p == 0 {
        return 0 as *mut libc::c_char;
    }
    q = p.offset(strlen(p) as isize).offset(-(1 as libc::c_int as isize));
    while q != p && OPENSSL_isspace(*q as libc::c_uchar as libc::c_int) != 0 {
        q = q.offset(-1);
        q;
    }
    if p != q {
        *q.offset(1 as libc::c_int as isize) = 0 as libc::c_int as libc::c_char;
    }
    if *p == 0 {
        return 0 as *mut libc::c_char;
    }
    return p;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn x509v3_bytes_to_hex(
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> *mut libc::c_char {
    let mut ret: *mut uint8_t = 0 as *mut uint8_t;
    let mut unused_len: size_t = 0;
    let mut current_block: u64;
    let mut cbb: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_2 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    if !(CBB_init(
        &mut cbb,
        (len * 3 as libc::c_int as size_t).wrapping_add(1 as libc::c_int as size_t),
    ) == 0)
    {
        let mut i: size_t = 0 as libc::c_int as size_t;
        loop {
            if !(i < len) {
                current_block = 6873731126896040597;
                break;
            }
            static mut hex: [libc::c_char; 17] = unsafe {
                *::core::mem::transmute::<
                    &[u8; 17],
                    &[libc::c_char; 17],
                >(b"0123456789ABCDEF\0")
            };
            if i > 0 as libc::c_int as size_t
                && CBB_add_u8(&mut cbb, ':' as i32 as uint8_t) == 0
                || CBB_add_u8(
                    &mut cbb,
                    hex[(*in_0.offset(i as isize) as libc::c_int >> 4 as libc::c_int)
                        as usize] as uint8_t,
                ) == 0
                || CBB_add_u8(
                    &mut cbb,
                    hex[(*in_0.offset(i as isize) as libc::c_int & 0xf as libc::c_int)
                        as usize] as uint8_t,
                ) == 0
            {
                current_block = 9554121836984671177;
                break;
            }
            i = i.wrapping_add(1);
            i;
        }
        match current_block {
            9554121836984671177 => {}
            _ => {
                ret = 0 as *mut uint8_t;
                unused_len = 0;
                if !(CBB_add_u8(&mut cbb, 0 as libc::c_int as uint8_t) == 0
                    || CBB_finish(&mut cbb, &mut ret, &mut unused_len) == 0)
                {
                    return ret as *mut libc::c_char;
                }
            }
        }
    }
    CBB_cleanup(&mut cbb);
    return 0 as *mut libc::c_char;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn x509v3_hex_to_bytes(
    mut str: *const libc::c_char,
    mut len: *mut size_t,
) -> *mut libc::c_uchar {
    let mut current_block: u64;
    let mut hexbuf: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut q: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut ch: libc::c_uchar = 0;
    let mut cl: libc::c_uchar = 0;
    let mut p: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut high: uint8_t = 0;
    let mut low: uint8_t = 0;
    if str.is_null() {
        ERR_put_error(
            20 as libc::c_int,
            0 as libc::c_int,
            124 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_utl.c\0" as *const u8
                as *const libc::c_char,
            503 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut libc::c_uchar;
    }
    hexbuf = OPENSSL_malloc(strlen(str) >> 1 as libc::c_int) as *mut libc::c_uchar;
    if hexbuf.is_null() {
        OPENSSL_free(hexbuf as *mut libc::c_void);
        return 0 as *mut libc::c_uchar;
    } else {
        p = str as *mut libc::c_uchar;
        q = hexbuf;
        loop {
            if !(*p != 0) {
                current_block = 5143058163439228106;
                break;
            }
            let fresh0 = p;
            p = p.offset(1);
            ch = *fresh0;
            if ch as libc::c_int == ':' as i32 {
                continue;
            }
            let fresh1 = p;
            p = p.offset(1);
            cl = *fresh1;
            if cl == 0 {
                ERR_put_error(
                    20 as libc::c_int,
                    0 as libc::c_int,
                    146 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_utl.c\0"
                        as *const u8 as *const libc::c_char,
                    516 as libc::c_int as libc::c_uint,
                );
                OPENSSL_free(hexbuf as *mut libc::c_void);
                return 0 as *mut libc::c_uchar;
            }
            if OPENSSL_fromxdigit(&mut high, ch as libc::c_int) == 0 {
                current_block = 13593118018608365534;
                break;
            }
            if OPENSSL_fromxdigit(&mut low, cl as libc::c_int) == 0 {
                current_block = 13593118018608365534;
                break;
            }
            let fresh2 = q;
            q = q.offset(1);
            *fresh2 = ((high as libc::c_int) << 4 as libc::c_int | low as libc::c_int)
                as libc::c_uchar;
        }
        match current_block {
            13593118018608365534 => {
                OPENSSL_free(hexbuf as *mut libc::c_void);
                ERR_put_error(
                    20 as libc::c_int,
                    0 as libc::c_int,
                    118 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_utl.c\0"
                        as *const u8 as *const libc::c_char,
                    541 as libc::c_int as libc::c_uint,
                );
                return 0 as *mut libc::c_uchar;
            }
            _ => {
                if !len.is_null() {
                    *len = q.offset_from(hexbuf) as libc::c_long as size_t;
                }
                return hexbuf;
            }
        }
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn x509v3_conf_name_matches(
    mut name: *const libc::c_char,
    mut cmp: *const libc::c_char,
) -> libc::c_int {
    let mut len: size_t = strlen(cmp);
    if strncmp(name, cmp, len) != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    return (*name.offset(len as isize) as libc::c_int == '\0' as i32
        || *name.offset(len as isize) as libc::c_int == '.' as i32) as libc::c_int;
}
unsafe extern "C" fn sk_strcmp(
    mut a: *const *const libc::c_char,
    mut b: *const *const libc::c_char,
) -> libc::c_int {
    return strcmp(*a, *b);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_get1_email(
    mut x: *const X509,
) -> *mut stack_st_OPENSSL_STRING {
    let mut gens: *mut GENERAL_NAMES = 0 as *mut GENERAL_NAMES;
    let mut ret: *mut stack_st_OPENSSL_STRING = 0 as *mut stack_st_OPENSSL_STRING;
    gens = X509_get_ext_d2i(
        x,
        85 as libc::c_int,
        0 as *mut libc::c_int,
        0 as *mut libc::c_int,
    ) as *mut GENERAL_NAMES;
    ret = get_email(X509_get_subject_name(x), gens);
    sk_GENERAL_NAME_pop_free(
        gens,
        Some(GENERAL_NAME_free as unsafe extern "C" fn(*mut GENERAL_NAME) -> ()),
    );
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_get1_ocsp(
    mut x: *const X509,
) -> *mut stack_st_OPENSSL_STRING {
    let mut info: *mut AUTHORITY_INFO_ACCESS = 0 as *mut AUTHORITY_INFO_ACCESS;
    let mut ret: *mut stack_st_OPENSSL_STRING = 0 as *mut stack_st_OPENSSL_STRING;
    let mut i: size_t = 0;
    info = X509_get_ext_d2i(
        x,
        177 as libc::c_int,
        0 as *mut libc::c_int,
        0 as *mut libc::c_int,
    ) as *mut AUTHORITY_INFO_ACCESS;
    if info.is_null() {
        return 0 as *mut stack_st_OPENSSL_STRING;
    }
    i = 0 as libc::c_int as size_t;
    while i < sk_ACCESS_DESCRIPTION_num(info) {
        let mut ad: *mut ACCESS_DESCRIPTION = sk_ACCESS_DESCRIPTION_value(info, i);
        if OBJ_obj2nid((*ad).method) == 178 as libc::c_int {
            if (*(*ad).location).type_0 == 6 as libc::c_int {
                if append_ia5(&mut ret, (*(*ad).location).d.uniformResourceIdentifier)
                    == 0
                {
                    break;
                }
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    AUTHORITY_INFO_ACCESS_free(info);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_REQ_get1_email(
    mut x: *const X509_REQ,
) -> *mut stack_st_OPENSSL_STRING {
    let mut gens: *mut GENERAL_NAMES = 0 as *mut GENERAL_NAMES;
    let mut exts: *mut stack_st_X509_EXTENSION = 0 as *mut stack_st_X509_EXTENSION;
    let mut ret: *mut stack_st_OPENSSL_STRING = 0 as *mut stack_st_OPENSSL_STRING;
    exts = X509_REQ_get_extensions(x);
    gens = X509V3_get_d2i(
        exts,
        85 as libc::c_int,
        0 as *mut libc::c_int,
        0 as *mut libc::c_int,
    ) as *mut GENERAL_NAMES;
    ret = get_email(X509_REQ_get_subject_name(x), gens);
    sk_GENERAL_NAME_pop_free(
        gens,
        Some(GENERAL_NAME_free as unsafe extern "C" fn(*mut GENERAL_NAME) -> ()),
    );
    sk_X509_EXTENSION_pop_free(
        exts,
        Some(X509_EXTENSION_free as unsafe extern "C" fn(*mut X509_EXTENSION) -> ()),
    );
    return ret;
}
unsafe extern "C" fn get_email(
    mut name: *const X509_NAME,
    mut gens: *const GENERAL_NAMES,
) -> *mut stack_st_OPENSSL_STRING {
    let mut ret: *mut stack_st_OPENSSL_STRING = 0 as *mut stack_st_OPENSSL_STRING;
    let mut i: libc::c_int = -(1 as libc::c_int);
    loop {
        i = X509_NAME_get_index_by_NID(name, 48 as libc::c_int, i);
        if !(i >= 0 as libc::c_int) {
            break;
        }
        let mut ne: *const X509_NAME_ENTRY = X509_NAME_get_entry(name, i);
        let mut email: *const ASN1_IA5STRING = X509_NAME_ENTRY_get_data(ne);
        if append_ia5(&mut ret, email) == 0 {
            return 0 as *mut stack_st_OPENSSL_STRING;
        }
    }
    let mut j: size_t = 0 as libc::c_int as size_t;
    while j < sk_GENERAL_NAME_num(gens) {
        let mut gen: *const GENERAL_NAME = sk_GENERAL_NAME_value(gens, j);
        if !((*gen).type_0 != 1 as libc::c_int) {
            if append_ia5(&mut ret, (*gen).d.ia5) == 0 {
                return 0 as *mut stack_st_OPENSSL_STRING;
            }
        }
        j = j.wrapping_add(1);
        j;
    }
    return ret;
}
unsafe extern "C" fn str_free(mut str: OPENSSL_STRING) {
    OPENSSL_free(str as *mut libc::c_void);
}
unsafe extern "C" fn append_ia5(
    mut sk: *mut *mut stack_st_OPENSSL_STRING,
    mut email: *const ASN1_IA5STRING,
) -> libc::c_int {
    if (*email).type_0 != 22 as libc::c_int {
        return 1 as libc::c_int;
    }
    if ((*email).data).is_null() || (*email).length == 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    if !(OPENSSL_memchr(
        (*email).data as *const libc::c_void,
        0 as libc::c_int,
        (*email).length as size_t,
    ))
        .is_null()
    {
        return 1 as libc::c_int;
    }
    let mut emtmp: *mut libc::c_char = 0 as *mut libc::c_char;
    if (*sk).is_null() {
        *sk = sk_OPENSSL_STRING_new(
            Some(
                sk_strcmp
                    as unsafe extern "C" fn(
                        *const *const libc::c_char,
                        *const *const libc::c_char,
                    ) -> libc::c_int,
            ),
        );
    }
    if !(*sk).is_null() {
        emtmp = OPENSSL_strndup(
            (*email).data as *mut libc::c_char,
            (*email).length as size_t,
        );
        if !emtmp.is_null() {
            sk_OPENSSL_STRING_sort(*sk);
            if sk_OPENSSL_STRING_find_awslc(*sk, 0 as *mut size_t, emtmp) != 0 {
                OPENSSL_free(emtmp as *mut libc::c_void);
                return 1 as libc::c_int;
            }
            if !(sk_OPENSSL_STRING_push(*sk, emtmp) == 0) {
                return 1 as libc::c_int;
            }
        }
    }
    OPENSSL_free(emtmp as *mut libc::c_void);
    X509_email_free(*sk);
    *sk = 0 as *mut stack_st_OPENSSL_STRING;
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_email_free(mut sk: *mut stack_st_OPENSSL_STRING) {
    sk_OPENSSL_STRING_pop_free(
        sk,
        Some(str_free as unsafe extern "C" fn(OPENSSL_STRING) -> ()),
    );
}
unsafe extern "C" fn equal_nocase(
    mut pattern: *const libc::c_uchar,
    mut pattern_len: size_t,
    mut subject: *const libc::c_uchar,
    mut subject_len: size_t,
    mut flags: libc::c_uint,
) -> libc::c_int {
    if pattern_len != subject_len {
        return 0 as libc::c_int;
    }
    if pattern_len > 0 as libc::c_int as size_t
        && (pattern.is_null() || subject.is_null())
    {
        return 0 as libc::c_int;
    }
    while pattern_len != 0 {
        let mut l: libc::c_uchar = *pattern;
        let mut r: libc::c_uchar = *subject;
        if l as libc::c_int == 0 as libc::c_int {
            return 0 as libc::c_int;
        }
        if l as libc::c_int != r as libc::c_int {
            if OPENSSL_tolower(l as libc::c_int) != OPENSSL_tolower(r as libc::c_int) {
                return 0 as libc::c_int;
            }
        }
        pattern = pattern.offset(1);
        pattern;
        subject = subject.offset(1);
        subject;
        pattern_len = pattern_len.wrapping_sub(1);
        pattern_len;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn equal_case(
    mut pattern: *const libc::c_uchar,
    mut pattern_len: size_t,
    mut subject: *const libc::c_uchar,
    mut subject_len: size_t,
    mut flags: libc::c_uint,
) -> libc::c_int {
    if pattern_len != subject_len {
        return 0 as libc::c_int;
    }
    return (OPENSSL_memcmp(
        pattern as *const libc::c_void,
        subject as *const libc::c_void,
        pattern_len,
    ) == 0) as libc::c_int;
}
unsafe extern "C" fn equal_email(
    mut a: *const libc::c_uchar,
    mut a_len: size_t,
    mut b: *const libc::c_uchar,
    mut b_len: size_t,
    mut unused_flags: libc::c_uint,
) -> libc::c_int {
    let mut i: size_t = a_len;
    if a_len != b_len {
        return 0 as libc::c_int;
    }
    while i > 0 as libc::c_int as size_t {
        i = i.wrapping_sub(1);
        i;
        if !(*a.offset(i as isize) as libc::c_int == '@' as i32
            || *b.offset(i as isize) as libc::c_int == '@' as i32)
        {
            continue;
        }
        if equal_nocase(
            a.offset(i as isize),
            a_len.wrapping_sub(i),
            b.offset(i as isize),
            a_len.wrapping_sub(i),
            0 as libc::c_int as libc::c_uint,
        ) == 0
        {
            return 0 as libc::c_int;
        }
        break;
    }
    if i == 0 as libc::c_int as size_t {
        i = a_len;
    }
    return equal_case(a, i, b, i, 0 as libc::c_int as libc::c_uint);
}
unsafe extern "C" fn wildcard_match(
    mut prefix: *const libc::c_uchar,
    mut prefix_len: size_t,
    mut suffix: *const libc::c_uchar,
    mut suffix_len: size_t,
    mut subject: *const libc::c_uchar,
    mut subject_len: size_t,
    mut flags: libc::c_uint,
) -> libc::c_int {
    let mut wildcard_start: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut wildcard_end: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut allow_idna: libc::c_int = 0 as libc::c_int;
    if subject_len < prefix_len.wrapping_add(suffix_len) {
        return 0 as libc::c_int;
    }
    if equal_nocase(prefix, prefix_len, subject, prefix_len, flags) == 0 {
        return 0 as libc::c_int;
    }
    wildcard_start = subject.offset(prefix_len as isize);
    wildcard_end = subject.offset(subject_len.wrapping_sub(suffix_len) as isize);
    if equal_nocase(wildcard_end, suffix_len, suffix, suffix_len, flags) == 0 {
        return 0 as libc::c_int;
    }
    if prefix_len == 0 as libc::c_int as size_t && *suffix as libc::c_int == '.' as i32 {
        if wildcard_start == wildcard_end {
            return 0 as libc::c_int;
        }
        allow_idna = 1 as libc::c_int;
    }
    if allow_idna == 0 && subject_len >= 4 as libc::c_int as size_t
        && OPENSSL_strncasecmp(
            subject as *mut libc::c_char,
            b"xn--\0" as *const u8 as *const libc::c_char,
            4 as libc::c_int as size_t,
        ) == 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    if wildcard_end == wildcard_start.offset(1 as libc::c_int as isize)
        && *wildcard_start as libc::c_int == '*' as i32
    {
        return 1 as libc::c_int;
    }
    p = wildcard_start;
    while p != wildcard_end {
        if OPENSSL_isalnum(*p as libc::c_int) == 0 && *p as libc::c_int != '-' as i32 {
            return 0 as libc::c_int;
        }
        p = p.offset(1);
        p;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn valid_star(
    mut p: *const libc::c_uchar,
    mut len: size_t,
    mut flags: libc::c_uint,
) -> *const libc::c_uchar {
    let mut star: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut i: size_t = 0;
    let mut state: libc::c_int = (1 as libc::c_int) << 0 as libc::c_int;
    let mut dots: libc::c_int = 0 as libc::c_int;
    i = 0 as libc::c_int as size_t;
    while i < len {
        if *p.offset(i as isize) as libc::c_int == '*' as i32 {
            let mut atstart: libc::c_int = state
                & (1 as libc::c_int) << 0 as libc::c_int;
            let mut atend: libc::c_int = (i
                == len.wrapping_sub(1 as libc::c_int as size_t)
                || *p.offset(i.wrapping_add(1 as libc::c_int as size_t) as isize)
                    as libc::c_int == '.' as i32) as libc::c_int;
            if !star.is_null()
                || state & (1 as libc::c_int) << 3 as libc::c_int != 0 as libc::c_int
                || dots != 0
            {
                return 0 as *const libc::c_uchar;
            }
            if atstart == 0 || atend == 0 {
                return 0 as *const libc::c_uchar;
            }
            star = &*p.offset(i as isize) as *const libc::c_uchar;
            state &= !((1 as libc::c_int) << 0 as libc::c_int);
        } else if OPENSSL_isalnum(*p.offset(i as isize) as libc::c_int) != 0 {
            if state & (1 as libc::c_int) << 0 as libc::c_int != 0 as libc::c_int
                && len.wrapping_sub(i) >= 4 as libc::c_int as size_t
                && OPENSSL_strncasecmp(
                    &*p.offset(i as isize) as *const libc::c_uchar as *mut libc::c_char,
                    b"xn--\0" as *const u8 as *const libc::c_char,
                    4 as libc::c_int as size_t,
                ) == 0 as libc::c_int
            {
                state |= (1 as libc::c_int) << 3 as libc::c_int;
            }
            state
                &= !((1 as libc::c_int) << 2 as libc::c_int
                    | (1 as libc::c_int) << 0 as libc::c_int);
        } else if *p.offset(i as isize) as libc::c_int == '.' as i32 {
            if state
                & ((1 as libc::c_int) << 2 as libc::c_int
                    | (1 as libc::c_int) << 0 as libc::c_int) != 0 as libc::c_int
            {
                return 0 as *const libc::c_uchar;
            }
            state = (1 as libc::c_int) << 0 as libc::c_int;
            dots += 1;
            dots;
        } else if *p.offset(i as isize) as libc::c_int == '-' as i32 {
            if state & (1 as libc::c_int) << 0 as libc::c_int != 0 as libc::c_int {
                return 0 as *const libc::c_uchar;
            }
            state |= (1 as libc::c_int) << 2 as libc::c_int;
        } else {
            return 0 as *const libc::c_uchar
        }
        i = i.wrapping_add(1);
        i;
    }
    if state
        & ((1 as libc::c_int) << 0 as libc::c_int
            | (1 as libc::c_int) << 2 as libc::c_int) != 0 as libc::c_int
        || dots < 2 as libc::c_int
    {
        return 0 as *const libc::c_uchar;
    }
    return star;
}
unsafe extern "C" fn equal_wildcard(
    mut pattern: *const libc::c_uchar,
    mut pattern_len: size_t,
    mut subject: *const libc::c_uchar,
    mut subject_len: size_t,
    mut flags: libc::c_uint,
) -> libc::c_int {
    let mut star: *const libc::c_uchar = 0 as *const libc::c_uchar;
    if !(subject_len > 1 as libc::c_int as size_t
        && *subject.offset(0 as libc::c_int as isize) as libc::c_int == '.' as i32)
    {
        star = valid_star(pattern, pattern_len, flags);
    }
    if star.is_null() {
        return equal_nocase(pattern, pattern_len, subject, subject_len, flags);
    }
    return wildcard_match(
        pattern,
        star.offset_from(pattern) as libc::c_long as size_t,
        star.offset(1 as libc::c_int as isize),
        (pattern.offset(pattern_len as isize).offset_from(star) as libc::c_long
            - 1 as libc::c_int as libc::c_long) as size_t,
        subject,
        subject_len,
        flags,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn x509v3_looks_like_dns_name(
    mut in_0: *const libc::c_uchar,
    mut len: size_t,
) -> libc::c_int {
    if len > 0 as libc::c_int as size_t
        && *in_0.offset(len.wrapping_sub(1 as libc::c_int as size_t) as isize)
            as libc::c_int == '.' as i32
    {
        len = len.wrapping_sub(1);
        len;
    }
    if len >= 2 as libc::c_int as size_t
        && *in_0.offset(0 as libc::c_int as isize) as libc::c_int == '*' as i32
        && *in_0.offset(1 as libc::c_int as isize) as libc::c_int == '.' as i32
    {
        in_0 = in_0.offset(2 as libc::c_int as isize);
        len = len.wrapping_sub(2 as libc::c_int as size_t);
    }
    if len == 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    let mut label_start: size_t = 0 as libc::c_int as size_t;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < len {
        let mut c: libc::c_uchar = *in_0.offset(i as isize);
        if !(OPENSSL_isalnum(c as libc::c_int) != 0
            || c as libc::c_int == '-' as i32 && i > label_start
            || c as libc::c_int == '_' as i32 || c as libc::c_int == ':' as i32)
        {
            if c as libc::c_int == '.' as i32 && i > label_start
                && i < len.wrapping_sub(1 as libc::c_int as size_t)
            {
                label_start = i.wrapping_add(1 as libc::c_int as size_t);
            } else {
                return 0 as libc::c_int
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn do_check_string(
    mut a: *const ASN1_STRING,
    mut cmp_type: libc::c_int,
    mut equal: equal_fn,
    mut flags: libc::c_uint,
    mut check_type: libc::c_int,
    mut b: *const libc::c_char,
    mut blen: size_t,
    mut peername: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut rv: libc::c_int = 0 as libc::c_int;
    if ((*a).data).is_null() || (*a).length == 0 {
        return 0 as libc::c_int;
    }
    if cmp_type > 0 as libc::c_int {
        if cmp_type != (*a).type_0 {
            return 0 as libc::c_int;
        }
        if cmp_type == 22 as libc::c_int {
            rv = equal
                .expect(
                    "non-null function pointer",
                )(
                (*a).data,
                (*a).length as size_t,
                b as *mut libc::c_uchar,
                blen,
                flags,
            );
        } else if (*a).length == blen as libc::c_int
            && OPENSSL_memcmp(
                (*a).data as *const libc::c_void,
                b as *const libc::c_void,
                blen,
            ) == 0
        {
            rv = 1 as libc::c_int;
        }
        if rv > 0 as libc::c_int && !peername.is_null() {
            *peername = OPENSSL_strndup(
                (*a).data as *mut libc::c_char,
                (*a).length as size_t,
            );
            if (*peername).is_null() {
                return -(1 as libc::c_int);
            }
        }
    } else {
        let mut astrlen: libc::c_int = 0;
        let mut astr: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
        astrlen = ASN1_STRING_to_UTF8(&mut astr, a);
        if astrlen < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        if check_type == 2 as libc::c_int
            && x509v3_looks_like_dns_name(astr, astrlen as size_t) == 0
        {
            rv = 0 as libc::c_int;
        } else {
            rv = equal
                .expect(
                    "non-null function pointer",
                )(astr, astrlen as size_t, b as *mut libc::c_uchar, blen, flags);
        }
        if rv > 0 as libc::c_int && !peername.is_null() {
            *peername = OPENSSL_strndup(astr as *mut libc::c_char, astrlen as size_t);
            if (*peername).is_null() {
                return -(1 as libc::c_int);
            }
        }
        OPENSSL_free(astr as *mut libc::c_void);
    }
    return rv;
}
unsafe extern "C" fn do_x509_check(
    mut x: *const X509,
    mut chk: *const libc::c_char,
    mut chklen: size_t,
    mut flags: libc::c_uint,
    mut check_type: libc::c_int,
    mut peername: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut cnid: libc::c_int = 0 as libc::c_int;
    let mut alt_type: libc::c_int = 0;
    let mut rv: libc::c_int = 0 as libc::c_int;
    let mut equal: equal_fn = None;
    if check_type == 1 as libc::c_int {
        cnid = 48 as libc::c_int;
        alt_type = 22 as libc::c_int;
        equal = Some(
            equal_email
                as unsafe extern "C" fn(
                    *const libc::c_uchar,
                    size_t,
                    *const libc::c_uchar,
                    size_t,
                    libc::c_uint,
                ) -> libc::c_int,
        );
    } else if check_type == 2 as libc::c_int {
        cnid = 13 as libc::c_int;
        alt_type = 22 as libc::c_int;
        if flags & 0x2 as libc::c_int as libc::c_uint != 0 {
            equal = Some(
                equal_nocase
                    as unsafe extern "C" fn(
                        *const libc::c_uchar,
                        size_t,
                        *const libc::c_uchar,
                        size_t,
                        libc::c_uint,
                    ) -> libc::c_int,
            );
        } else {
            equal = Some(
                equal_wildcard
                    as unsafe extern "C" fn(
                        *const libc::c_uchar,
                        size_t,
                        *const libc::c_uchar,
                        size_t,
                        libc::c_uint,
                    ) -> libc::c_int,
            );
        }
    } else {
        alt_type = 4 as libc::c_int;
        equal = Some(
            equal_case
                as unsafe extern "C" fn(
                    *const libc::c_uchar,
                    size_t,
                    *const libc::c_uchar,
                    size_t,
                    libc::c_uint,
                ) -> libc::c_int,
        );
    }
    let mut gens: *mut GENERAL_NAMES = X509_get_ext_d2i(
        x,
        85 as libc::c_int,
        0 as *mut libc::c_int,
        0 as *mut libc::c_int,
    ) as *mut GENERAL_NAMES;
    if !gens.is_null() {
        let mut i: size_t = 0 as libc::c_int as size_t;
        while i < sk_GENERAL_NAME_num(gens) {
            let mut gen: *const GENERAL_NAME = sk_GENERAL_NAME_value(gens, i);
            if !((*gen).type_0 != check_type) {
                let mut cstr: *const ASN1_STRING = 0 as *const ASN1_STRING;
                if check_type == 1 as libc::c_int {
                    cstr = (*gen).d.rfc822Name;
                } else if check_type == 2 as libc::c_int {
                    cstr = (*gen).d.dNSName;
                } else {
                    cstr = (*gen).d.iPAddress;
                }
                rv = do_check_string(
                    cstr,
                    alt_type,
                    equal,
                    flags,
                    check_type,
                    chk,
                    chklen,
                    peername,
                );
                if rv != 0 as libc::c_int {
                    break;
                }
            }
            i = i.wrapping_add(1);
            i;
        }
        GENERAL_NAMES_free(gens);
        return rv;
    }
    if cnid == 0 as libc::c_int || flags & 0x20 as libc::c_int as libc::c_uint != 0 {
        return 0 as libc::c_int;
    }
    let mut j: libc::c_int = -(1 as libc::c_int);
    let mut name: *const X509_NAME = X509_get_subject_name(x);
    loop {
        j = X509_NAME_get_index_by_NID(name, cnid, j);
        if !(j >= 0 as libc::c_int) {
            break;
        }
        let mut ne: *const X509_NAME_ENTRY = X509_NAME_get_entry(name, j);
        let mut str: *const ASN1_STRING = X509_NAME_ENTRY_get_data(ne);
        rv = do_check_string(
            str,
            -(1 as libc::c_int),
            equal,
            flags,
            check_type,
            chk,
            chklen,
            peername,
        );
        if rv != 0 as libc::c_int {
            return rv;
        }
    }
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_check_host(
    mut x: *const X509,
    mut chk: *const libc::c_char,
    mut chklen: size_t,
    mut flags: libc::c_uint,
    mut peername: *mut *mut libc::c_char,
) -> libc::c_int {
    if chk.is_null() {
        return -(2 as libc::c_int);
    }
    if chklen == 0 as libc::c_int as size_t {
        chklen = strlen(chk);
    } else if !(OPENSSL_memchr(chk as *const libc::c_void, '\0' as i32, chklen))
        .is_null()
    {
        return -(2 as libc::c_int)
    }
    return do_x509_check(x, chk, chklen, flags, 2 as libc::c_int, peername);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_check_email(
    mut x: *const X509,
    mut chk: *const libc::c_char,
    mut chklen: size_t,
    mut flags: libc::c_uint,
) -> libc::c_int {
    if chk.is_null() {
        return -(2 as libc::c_int);
    }
    if chklen == 0 as libc::c_int as size_t {
        chklen = strlen(chk);
    } else if !(OPENSSL_memchr(chk as *const libc::c_void, '\0' as i32, chklen))
        .is_null()
    {
        return -(2 as libc::c_int)
    }
    return do_x509_check(
        x,
        chk,
        chklen,
        flags,
        1 as libc::c_int,
        0 as *mut *mut libc::c_char,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_check_ip(
    mut x: *const X509,
    mut chk: *const libc::c_uchar,
    mut chklen: size_t,
    mut flags: libc::c_uint,
) -> libc::c_int {
    if chk.is_null() {
        return -(2 as libc::c_int);
    }
    return do_x509_check(
        x,
        chk as *const libc::c_char,
        chklen,
        flags,
        7 as libc::c_int,
        0 as *mut *mut libc::c_char,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_check_ip_asc(
    mut x: *const X509,
    mut ipasc: *const libc::c_char,
    mut flags: libc::c_uint,
) -> libc::c_int {
    let mut ipout: [libc::c_uchar; 16] = [0; 16];
    let mut iplen: size_t = 0;
    if ipasc.is_null() {
        return -(2 as libc::c_int);
    }
    iplen = x509v3_a2i_ipadd(ipout.as_mut_ptr(), ipasc) as size_t;
    if iplen == 0 as libc::c_int as size_t {
        return -(2 as libc::c_int);
    }
    return do_x509_check(
        x,
        ipout.as_mut_ptr() as *const libc::c_char,
        iplen,
        flags,
        7 as libc::c_int,
        0 as *mut *mut libc::c_char,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn a2i_IPADDRESS(
    mut ipasc: *const libc::c_char,
) -> *mut ASN1_OCTET_STRING {
    let mut ipout: [libc::c_uchar; 16] = [0; 16];
    let mut ret: *mut ASN1_OCTET_STRING = 0 as *mut ASN1_OCTET_STRING;
    let mut iplen: libc::c_int = 0;
    iplen = x509v3_a2i_ipadd(ipout.as_mut_ptr(), ipasc);
    if iplen == 0 {
        return 0 as *mut ASN1_OCTET_STRING;
    }
    ret = ASN1_OCTET_STRING_new();
    if ret.is_null() {
        return 0 as *mut ASN1_OCTET_STRING;
    }
    if ASN1_OCTET_STRING_set(ret, ipout.as_mut_ptr(), iplen) == 0 {
        ASN1_OCTET_STRING_free(ret);
        return 0 as *mut ASN1_OCTET_STRING;
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn a2i_IPADDRESS_NC(
    mut ipasc: *const libc::c_char,
) -> *mut ASN1_OCTET_STRING {
    let mut ret: *mut ASN1_OCTET_STRING = 0 as *mut ASN1_OCTET_STRING;
    let mut ipout: [libc::c_uchar; 32] = [0; 32];
    let mut iptmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut iplen1: libc::c_int = 0;
    let mut iplen2: libc::c_int = 0;
    p = strchr(ipasc, '/' as i32);
    if p.is_null() {
        return 0 as *mut ASN1_OCTET_STRING;
    }
    iptmp = OPENSSL_strdup(ipasc);
    if iptmp.is_null() {
        return 0 as *mut ASN1_OCTET_STRING;
    }
    p = iptmp.offset(p.offset_from(ipasc) as libc::c_long as isize);
    let fresh3 = p;
    p = p.offset(1);
    *fresh3 = 0 as libc::c_int as libc::c_char;
    iplen1 = x509v3_a2i_ipadd(ipout.as_mut_ptr(), iptmp);
    if !(iplen1 == 0) {
        iplen2 = x509v3_a2i_ipadd(ipout.as_mut_ptr().offset(iplen1 as isize), p);
        OPENSSL_free(iptmp as *mut libc::c_void);
        iptmp = 0 as *mut libc::c_char;
        if !(iplen2 == 0 || iplen1 != iplen2) {
            ret = ASN1_OCTET_STRING_new();
            if !ret.is_null() {
                if !(ASN1_OCTET_STRING_set(ret, ipout.as_mut_ptr(), iplen1 + iplen2)
                    == 0)
                {
                    return ret;
                }
            }
        }
    }
    OPENSSL_free(iptmp as *mut libc::c_void);
    ASN1_OCTET_STRING_free(ret);
    return 0 as *mut ASN1_OCTET_STRING;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn x509v3_a2i_ipadd(
    mut ipout: *mut libc::c_uchar,
    mut ipasc: *const libc::c_char,
) -> libc::c_int {
    if !(strchr(ipasc, ':' as i32)).is_null() {
        if ipv6_from_asc(ipout, ipasc) == 0 {
            return 0 as libc::c_int;
        }
        return 16 as libc::c_int;
    } else {
        if ipv4_from_asc(ipout, ipasc) == 0 {
            return 0 as libc::c_int;
        }
        return 4 as libc::c_int;
    };
}
unsafe extern "C" fn ipv4_from_asc(
    mut v4: *mut libc::c_uchar,
    mut in_0: *const libc::c_char,
) -> libc::c_int {
    let mut a0: libc::c_int = 0;
    let mut a1: libc::c_int = 0;
    let mut a2: libc::c_int = 0;
    let mut a3: libc::c_int = 0;
    if sscanf(
        in_0,
        b"%d.%d.%d.%d\0" as *const u8 as *const libc::c_char,
        &mut a0 as *mut libc::c_int,
        &mut a1 as *mut libc::c_int,
        &mut a2 as *mut libc::c_int,
        &mut a3 as *mut libc::c_int,
    ) != 4 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    if a0 < 0 as libc::c_int || a0 > 255 as libc::c_int || a1 < 0 as libc::c_int
        || a1 > 255 as libc::c_int || a2 < 0 as libc::c_int || a2 > 255 as libc::c_int
        || a3 < 0 as libc::c_int || a3 > 255 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    *v4.offset(0 as libc::c_int as isize) = a0 as libc::c_uchar;
    *v4.offset(1 as libc::c_int as isize) = a1 as libc::c_uchar;
    *v4.offset(2 as libc::c_int as isize) = a2 as libc::c_uchar;
    *v4.offset(3 as libc::c_int as isize) = a3 as libc::c_uchar;
    return 1 as libc::c_int;
}
unsafe extern "C" fn ipv6_from_asc(
    mut v6: *mut libc::c_uchar,
    mut in_0: *const libc::c_char,
) -> libc::c_int {
    let mut v6stat: IPV6_STAT = IPV6_STAT {
        tmp: [0; 16],
        total: 0,
        zero_pos: 0,
        zero_cnt: 0,
    };
    v6stat.total = 0 as libc::c_int;
    v6stat.zero_pos = -(1 as libc::c_int);
    v6stat.zero_cnt = 0 as libc::c_int;
    if CONF_parse_list(
        in_0,
        ':' as i32 as libc::c_char,
        0 as libc::c_int,
        Some(
            ipv6_cb
                as unsafe extern "C" fn(
                    *const libc::c_char,
                    size_t,
                    *mut libc::c_void,
                ) -> libc::c_int,
        ),
        &mut v6stat as *mut IPV6_STAT as *mut libc::c_void,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    if v6stat.zero_pos == -(1 as libc::c_int) {
        if v6stat.total != 16 as libc::c_int {
            return 0 as libc::c_int;
        }
    } else {
        if v6stat.total >= 16 as libc::c_int {
            return 0 as libc::c_int;
        }
        if v6stat.zero_cnt > 3 as libc::c_int {
            return 0 as libc::c_int
        } else if v6stat.zero_cnt == 3 as libc::c_int {
            if v6stat.total > 0 as libc::c_int {
                return 0 as libc::c_int;
            }
        } else if v6stat.zero_cnt == 2 as libc::c_int {
            if v6stat.zero_pos != 0 as libc::c_int && v6stat.zero_pos != v6stat.total {
                return 0 as libc::c_int;
            }
        } else if v6stat.zero_pos == 0 as libc::c_int || v6stat.zero_pos == v6stat.total
        {
            return 0 as libc::c_int
        }
    }
    if v6stat.zero_pos >= 0 as libc::c_int {
        OPENSSL_memcpy(
            v6 as *mut libc::c_void,
            (v6stat.tmp).as_mut_ptr() as *const libc::c_void,
            v6stat.zero_pos as size_t,
        );
        if v6stat.zero_pos >= v6stat.total {
            return 0 as libc::c_int;
        }
        OPENSSL_memset(
            v6.offset(v6stat.zero_pos as isize) as *mut libc::c_void,
            0 as libc::c_int,
            (16 as libc::c_int - v6stat.total) as size_t,
        );
        if v6stat.total != v6stat.zero_pos {
            OPENSSL_memcpy(
                v6
                    .offset(v6stat.zero_pos as isize)
                    .offset(16 as libc::c_int as isize)
                    .offset(-(v6stat.total as isize)) as *mut libc::c_void,
                (v6stat.tmp).as_mut_ptr().offset(v6stat.zero_pos as isize)
                    as *const libc::c_void,
                (v6stat.total - v6stat.zero_pos) as size_t,
            );
        }
    } else {
        OPENSSL_memcpy(
            v6 as *mut libc::c_void,
            (v6stat.tmp).as_mut_ptr() as *const libc::c_void,
            16 as libc::c_int as size_t,
        );
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn ipv6_cb(
    mut elem: *const libc::c_char,
    mut len: size_t,
    mut usr: *mut libc::c_void,
) -> libc::c_int {
    let mut s: *mut IPV6_STAT = usr as *mut IPV6_STAT;
    if (*s).total == 16 as libc::c_int {
        return 0 as libc::c_int;
    }
    if len == 0 as libc::c_int as size_t {
        if (*s).zero_pos == -(1 as libc::c_int) {
            (*s).zero_pos = (*s).total;
        } else if (*s).zero_pos != (*s).total {
            return 0 as libc::c_int
        }
        if (*s).zero_cnt >= 3 as libc::c_int {
            return 0 as libc::c_int;
        }
        (*s).zero_cnt += 1;
        (*s).zero_cnt;
    } else if len > 4 as libc::c_int as size_t {
        if (*s).total > 12 as libc::c_int {
            return 0 as libc::c_int;
        }
        if *elem.offset(len as isize) != 0 {
            return 0 as libc::c_int;
        }
        if ipv4_from_asc(((*s).tmp).as_mut_ptr().offset((*s).total as isize), elem) == 0
        {
            return 0 as libc::c_int;
        }
        (*s).total += 4 as libc::c_int;
    } else {
        if ipv6_hex(((*s).tmp).as_mut_ptr().offset((*s).total as isize), elem, len) == 0
        {
            return 0 as libc::c_int;
        }
        (*s).total += 2 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn ipv6_hex(
    mut out: *mut libc::c_uchar,
    mut in_0: *const libc::c_char,
    mut inlen: size_t,
) -> libc::c_int {
    if inlen > 4 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    let mut num: uint16_t = 0 as libc::c_int as uint16_t;
    loop {
        let fresh4 = inlen;
        inlen = inlen.wrapping_sub(1);
        if !(fresh4 != 0) {
            break;
        }
        let mut val: uint8_t = 0;
        let fresh5 = in_0;
        in_0 = in_0.offset(1);
        if OPENSSL_fromxdigit(&mut val, *fresh5 as libc::c_int) == 0 {
            return 0 as libc::c_int;
        }
        num = ((num as libc::c_int) << 4 as libc::c_int | val as libc::c_int)
            as uint16_t;
    }
    *out
        .offset(
            0 as libc::c_int as isize,
        ) = (num as libc::c_int >> 8 as libc::c_int) as libc::c_uchar;
    *out
        .offset(
            1 as libc::c_int as isize,
        ) = (num as libc::c_int & 0xff as libc::c_int) as libc::c_uchar;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509V3_NAME_from_section(
    mut nm: *mut X509_NAME,
    mut dn_sk: *const stack_st_CONF_VALUE,
    mut chtype: libc::c_int,
) -> libc::c_int {
    if nm.is_null() {
        return 0 as libc::c_int;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_CONF_VALUE_num(dn_sk) {
        let mut v: *const CONF_VALUE = sk_CONF_VALUE_value(dn_sk, i);
        let mut type_0: *const libc::c_char = (*v).name;
        let mut p: *const libc::c_char = type_0;
        while *p != 0 {
            if *p as libc::c_int == ':' as i32 || *p as libc::c_int == ',' as i32
                || *p as libc::c_int == '.' as i32
            {
                p = p.offset(1);
                p;
                if *p != 0 {
                    type_0 = p;
                }
                break;
            } else {
                p = p.offset(1);
                p;
            }
        }
        let mut mval: libc::c_int = 0;
        if *type_0 as libc::c_int == '+' as i32 {
            mval = -(1 as libc::c_int);
            type_0 = type_0.offset(1);
            type_0;
        } else {
            mval = 0 as libc::c_int;
        }
        if X509_NAME_add_entry_by_txt(
            nm,
            type_0,
            chtype,
            (*v).value as *mut libc::c_uchar,
            -(1 as libc::c_int) as ossl_ssize_t,
            -(1 as libc::c_int),
            mval,
        ) == 0
        {
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 1 as libc::c_int;
}
