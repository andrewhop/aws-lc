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
    pub type stack_st_OPENSSL_STRING;
    pub type stack_st_ASN1_OBJECT;
    pub type stack_st_X509_EXTENSION;
    pub type stack_st_X509_REVOKED;
    pub type crypto_buffer_st;
    pub type stack_st_DIST_POINT;
    pub type stack_st_void;
    pub type stack_st_X509_CRL;
    pub type stack_st_X509;
    pub type stack_st_X509_LOOKUP;
    pub type stack_st_X509_OBJECT;
    pub type stack_st;
    pub type stack_st_CRYPTO_EX_DATA_FUNCS;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn time(__timer: *mut time_t) -> time_t;
    fn abort() -> !;
    fn ASN1_STRING_to_UTF8(
        out: *mut *mut libc::c_uchar,
        in_0: *const ASN1_STRING,
    ) -> libc::c_int;
    fn ASN1_TIME_diff(
        out_days: *mut libc::c_int,
        out_seconds: *mut libc::c_int,
        from: *const ASN1_TIME,
        to: *const ASN1_TIME,
    ) -> libc::c_int;
    fn ASN1_TIME_adj(
        s: *mut ASN1_TIME,
        posix_time: int64_t,
        offset_day: libc::c_int,
        offset_sec: libc::c_long,
    ) -> *mut ASN1_TIME;
    fn ASN1_TIME_to_posix(t: *const ASN1_TIME, out: *mut int64_t) -> libc::c_int;
    fn ASN1_OBJECT_free(a: *mut ASN1_OBJECT);
    fn X509_up_ref(x509: *mut X509) -> libc::c_int;
    fn X509_chain_up_ref(chain: *mut stack_st_X509) -> *mut stack_st_X509;
    fn X509_free(x509: *mut X509);
    fn X509_get_issuer_name(x509: *const X509) -> *mut X509_NAME;
    fn X509_get_subject_name(x509: *const X509) -> *mut X509_NAME;
    fn X509_get0_pubkey(x509: *const X509) -> *mut EVP_PKEY;
    fn X509_get_ext_by_critical(
        x: *const X509,
        crit: libc::c_int,
        lastpos: libc::c_int,
    ) -> libc::c_int;
    fn X509_get_ext(x: *const X509, loc: libc::c_int) -> *mut X509_EXTENSION;
    fn X509_verify(x509: *mut X509, pkey: *mut EVP_PKEY) -> libc::c_int;
    fn X509_cmp(a: *const X509, b: *const X509) -> libc::c_int;
    fn X509_CRL_up_ref(crl: *mut X509_CRL) -> libc::c_int;
    fn X509_CRL_free(crl: *mut X509_CRL);
    fn X509_CRL_get0_lastUpdate(crl: *const X509_CRL) -> *const ASN1_TIME;
    fn X509_CRL_get0_nextUpdate(crl: *const X509_CRL) -> *const ASN1_TIME;
    fn X509_CRL_get_issuer(crl: *const X509_CRL) -> *mut X509_NAME;
    fn X509_CRL_get0_by_cert(
        crl: *mut X509_CRL,
        out: *mut *mut X509_REVOKED,
        x509: *mut X509,
    ) -> libc::c_int;
    fn X509_CRL_verify(crl: *mut X509_CRL, pkey: *mut EVP_PKEY) -> libc::c_int;
    fn X509_NAME_cmp(a: *const X509_NAME, b: *const X509_NAME) -> libc::c_int;
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
    fn X509_VERIFY_PARAM_new() -> *mut X509_VERIFY_PARAM;
    fn X509_VERIFY_PARAM_free(param: *mut X509_VERIFY_PARAM);
    fn X509_VERIFY_PARAM_inherit(
        to: *mut X509_VERIFY_PARAM,
        from: *const X509_VERIFY_PARAM,
    ) -> libc::c_int;
    fn X509_VERIFY_PARAM_set_flags(
        param: *mut X509_VERIFY_PARAM,
        flags: libc::c_ulong,
    ) -> libc::c_int;
    fn X509_VERIFY_PARAM_set_depth(param: *mut X509_VERIFY_PARAM, depth: libc::c_int);
    fn X509_VERIFY_PARAM_set_time_posix(param: *mut X509_VERIFY_PARAM, t: int64_t);
    fn X509_supported_extension(ex: *const X509_EXTENSION) -> libc::c_int;
    fn X509_check_ca(x509: *mut X509) -> libc::c_int;
    fn X509_check_issued(issuer: *mut X509, subject: *mut X509) -> libc::c_int;
    fn NAME_CONSTRAINTS_check(x509: *mut X509, nc: *mut NAME_CONSTRAINTS) -> libc::c_int;
    fn X509_check_host(
        x509: *const X509,
        chk: *const libc::c_char,
        chklen: size_t,
        flags: libc::c_uint,
        out_peername: *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn X509_check_email(
        x509: *const X509,
        chk: *const libc::c_char,
        chklen: size_t,
        flags: libc::c_uint,
    ) -> libc::c_int;
    fn X509_check_ip(
        x509: *const X509,
        chk: *const uint8_t,
        chklen: size_t,
        flags: libc::c_uint,
    ) -> libc::c_int;
    fn X509_STORE_CTX_get1_issuer(
        out_issuer: *mut *mut X509,
        ctx: *mut X509_STORE_CTX,
        x509: *mut X509,
    ) -> libc::c_int;
    fn X509_check_purpose(
        x509: *mut X509,
        purpose: libc::c_int,
        ca: libc::c_int,
    ) -> libc::c_int;
    fn X509_check_trust(
        x509: *mut X509,
        id: libc::c_int,
        flags: libc::c_int,
    ) -> libc::c_int;
    fn X509_get_notBefore(x509: *const X509) -> *mut ASN1_TIME;
    fn X509_get_notAfter(x509: *const X509) -> *mut ASN1_TIME;
    fn X509_PURPOSE_get0(id: libc::c_int) -> *const X509_PURPOSE;
    fn X509_TRUST_get_by_id(id: libc::c_int) -> libc::c_int;
    fn X509_STORE_CTX_get1_certs(
        st: *mut X509_STORE_CTX,
        nm: *mut X509_NAME,
    ) -> *mut stack_st_X509;
    fn X509_STORE_CTX_get1_crls(
        st: *mut X509_STORE_CTX,
        nm: *mut X509_NAME,
    ) -> *mut stack_st_X509_CRL;
    fn X509_PURPOSE_get_by_id(id: libc::c_int) -> libc::c_int;
    fn X509_PURPOSE_get_trust(xp: *const X509_PURPOSE) -> libc::c_int;
    fn X509_policy_check(
        certs: *const stack_st_X509,
        user_policies: *const stack_st_ASN1_OBJECT,
        flags: libc::c_ulong,
        out_current_cert: *mut *mut X509,
    ) -> libc::c_int;
    fn x509v3_looks_like_dns_name(
        in_0: *const libc::c_uchar,
        len: size_t,
    ) -> libc::c_int;
    fn x509v3_cache_extensions(x: *mut X509) -> libc::c_int;
    fn GENERAL_NAME_cmp(a: *const GENERAL_NAME, b: *const GENERAL_NAME) -> libc::c_int;
    fn X509_VERIFY_PARAM_lookup(name: *const libc::c_char) -> *const X509_VERIFY_PARAM;
    fn X509_check_akid(issuer: *mut X509, akid: *const AUTHORITY_KEYID) -> libc::c_int;
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_set(
        sk: *mut OPENSSL_STACK,
        i: size_t,
        p: *mut libc::c_void,
    ) -> *mut libc::c_void;
    fn OPENSSL_sk_free(sk: *mut OPENSSL_STACK);
    fn OPENSSL_sk_pop_free_ex(
        sk: *mut OPENSSL_STACK,
        call_free_func: OPENSSL_sk_call_free_func,
        free_func: OPENSSL_sk_free_func,
    );
    fn OPENSSL_sk_delete_ptr(
        sk: *mut OPENSSL_STACK,
        p: *const libc::c_void,
    ) -> *mut libc::c_void;
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn OPENSSL_sk_pop(sk: *mut OPENSSL_STACK) -> *mut libc::c_void;
    fn OPENSSL_sk_dup(sk: *const OPENSSL_STACK) -> *mut OPENSSL_STACK;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OBJ_dup(obj: *const ASN1_OBJECT) -> *mut ASN1_OBJECT;
    fn OBJ_cmp(a: *const ASN1_OBJECT, b: *const ASN1_OBJECT) -> libc::c_int;
    fn CRYPTO_get_ex_new_index(
        ex_data_class: *mut CRYPTO_EX_DATA_CLASS,
        out_index: *mut libc::c_int,
        argl: libc::c_long,
        argp: *mut libc::c_void,
        free_func: Option::<CRYPTO_EX_free>,
    ) -> libc::c_int;
    fn CRYPTO_set_ex_data(
        ad: *mut CRYPTO_EX_DATA,
        index: libc::c_int,
        val: *mut libc::c_void,
    ) -> libc::c_int;
    fn CRYPTO_get_ex_data(
        ad: *const CRYPTO_EX_DATA,
        index: libc::c_int,
    ) -> *mut libc::c_void;
    fn CRYPTO_new_ex_data(ad: *mut CRYPTO_EX_DATA);
    fn CRYPTO_free_ex_data(
        ex_data_class: *mut CRYPTO_EX_DATA_CLASS,
        obj: *mut libc::c_void,
        ad: *mut CRYPTO_EX_DATA,
    );
}
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type size_t = libc::c_ulong;
pub type time_t = __time_t;
pub type int64_t = __int64_t;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_rwlock_arch_t {
    pub __readers: libc::c_uint,
    pub __writers: libc::c_uint,
    pub __wrphase_futex: libc::c_uint,
    pub __writers_futex: libc::c_uint,
    pub __pad3: libc::c_uint,
    pub __pad4: libc::c_uint,
    pub __cur_writer: libc::c_int,
    pub __shared: libc::c_int,
    pub __rwelision: libc::c_schar,
    pub __pad1: [libc::c_uchar; 7],
    pub __pad2: libc::c_ulong,
    pub __flags: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_rwlock_t {
    pub __data: __pthread_rwlock_arch_t,
    pub __size: [libc::c_char; 56],
    pub __align: libc::c_long,
}
pub type ASN1_BOOLEAN = libc::c_int;
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
pub struct X509_VERIFY_PARAM_st {
    pub check_time: int64_t,
    pub flags: libc::c_ulong,
    pub purpose: libc::c_int,
    pub trust: libc::c_int,
    pub depth: libc::c_int,
    pub policies: *mut stack_st_ASN1_OBJECT,
    pub hosts: *mut stack_st_OPENSSL_STRING,
    pub hostflags: libc::c_uint,
    pub email: *mut libc::c_char,
    pub emaillen: size_t,
    pub ip: *mut libc::c_uchar,
    pub iplen: size_t,
    pub poison: libc::c_uchar,
}
pub type X509_VERIFY_PARAM = X509_VERIFY_PARAM_st;
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
pub type X509_STORE = x509_store_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_store_st {
    pub objs: *mut stack_st_X509_OBJECT,
    pub objs_lock: CRYPTO_MUTEX,
    pub get_cert_methods: *mut stack_st_X509_LOOKUP,
    pub param: *mut X509_VERIFY_PARAM,
    pub verify_cb: X509_STORE_CTX_verify_cb,
    pub get_crl: X509_STORE_CTX_get_crl_fn,
    pub check_crl: X509_STORE_CTX_check_crl_fn,
    pub references: CRYPTO_refcount_t,
    pub ex_data: CRYPTO_EX_DATA,
}
pub type X509_STORE_CTX_check_crl_fn = Option::<
    unsafe extern "C" fn(*mut X509_STORE_CTX, *mut X509_CRL) -> libc::c_int,
>;
pub type X509_STORE_CTX = x509_store_ctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_store_ctx_st {
    pub ctx: *mut X509_STORE,
    pub cert: *mut X509,
    pub untrusted: *mut stack_st_X509,
    pub crls: *mut stack_st_X509_CRL,
    pub param: *mut X509_VERIFY_PARAM,
    pub trusted_stack: *mut stack_st_X509,
    pub verify_cb: X509_STORE_CTX_verify_cb,
    pub get_crl: X509_STORE_CTX_get_crl_fn,
    pub check_crl: X509_STORE_CTX_check_crl_fn,
    pub verify_custom_crit_oids: X509_STORE_CTX_verify_crit_oids_cb,
    pub last_untrusted: libc::c_int,
    pub chain: *mut stack_st_X509,
    pub error_depth: libc::c_int,
    pub error: libc::c_int,
    pub current_cert: *mut X509,
    pub current_issuer: *mut X509,
    pub current_crl: *mut X509_CRL,
    pub current_crl_score: libc::c_int,
    pub custom_crit_oids: *mut stack_st_ASN1_OBJECT,
    pub ex_data: CRYPTO_EX_DATA,
}
pub type X509_STORE_CTX_verify_crit_oids_cb = Option::<
    unsafe extern "C" fn(
        *mut X509_STORE_CTX,
        *mut X509,
        *mut stack_st_ASN1_OBJECT,
    ) -> libc::c_int,
>;
pub type X509_STORE_CTX_get_crl_fn = Option::<
    unsafe extern "C" fn(
        *mut X509_STORE_CTX,
        *mut *mut X509_CRL,
        *mut X509,
    ) -> libc::c_int,
>;
pub type X509_STORE_CTX_verify_cb = Option::<
    unsafe extern "C" fn(libc::c_int, *mut X509_STORE_CTX) -> libc::c_int,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_revoked_st {
    pub serialNumber: *mut ASN1_INTEGER,
    pub revocationDate: *mut ASN1_TIME,
    pub extensions: *mut stack_st_X509_EXTENSION,
    pub reason: libc::c_int,
}
pub type X509_REVOKED = x509_revoked_st;
pub type OPENSSL_sk_free_func = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type OPENSSL_sk_call_free_func = Option::<
    unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
>;
pub type OPENSSL_STACK = stack_st;
pub type CRYPTO_EX_free = unsafe extern "C" fn(
    *mut libc::c_void,
    *mut libc::c_void,
    *mut CRYPTO_EX_DATA,
    libc::c_int,
    libc::c_long,
    *mut libc::c_void,
) -> ();
pub type CRYPTO_EX_dup = unsafe extern "C" fn(
    *mut CRYPTO_EX_DATA,
    *const CRYPTO_EX_DATA,
    *mut *mut libc::c_void,
    libc::c_int,
    libc::c_long,
    *mut libc::c_void,
) -> libc::c_int;
pub type CRYPTO_EX_unused = libc::c_int;
pub type sk_ASN1_OBJECT_free_func = Option::<
    unsafe extern "C" fn(*mut ASN1_OBJECT) -> (),
>;
pub type sk_X509_free_func = Option::<unsafe extern "C" fn(*mut X509) -> ()>;
pub type sk_X509_CRL_free_func = Option::<unsafe extern "C" fn(*mut X509_CRL) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CRYPTO_EX_DATA_CLASS {
    pub lock: CRYPTO_STATIC_MUTEX,
    pub meth: *mut stack_st_CRYPTO_EX_DATA_FUNCS,
    pub num_reserved: uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CRYPTO_STATIC_MUTEX {
    pub lock: pthread_rwlock_t,
}
pub const PTHREAD_RWLOCK_DEFAULT_NP: C2RustUnnamed_2 = 0;
pub type X509_PURPOSE = x509_purpose_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_purpose_st {
    pub purpose: libc::c_int,
    pub trust: libc::c_int,
    pub flags: libc::c_int,
    pub check_purpose: Option::<
        unsafe extern "C" fn(
            *const x509_purpose_st,
            *const X509,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub name: *mut libc::c_char,
    pub sname: *mut libc::c_char,
    pub usr_data: *mut libc::c_void,
}
pub type C2RustUnnamed_2 = libc::c_uint;
pub const PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP: C2RustUnnamed_2 = 2;
pub const PTHREAD_RWLOCK_PREFER_WRITER_NP: C2RustUnnamed_2 = 1;
pub const PTHREAD_RWLOCK_PREFER_READER_NP: C2RustUnnamed_2 = 0;
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_num(mut sk: *const stack_st_ASN1_OBJECT) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_pop_free(
    mut sk: *mut stack_st_ASN1_OBJECT,
    mut free_func: sk_ASN1_OBJECT_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_ASN1_OBJECT_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_ASN1_OBJECT_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_value(
    mut sk: *const stack_st_ASN1_OBJECT,
    mut i: size_t,
) -> *mut ASN1_OBJECT {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut ASN1_OBJECT;
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_push(
    mut sk: *mut stack_st_ASN1_OBJECT,
    mut p: *mut ASN1_OBJECT,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<OPENSSL_sk_free_func, sk_ASN1_OBJECT_free_func>(free_func))
        .expect("non-null function pointer")(ptr as *mut ASN1_OBJECT);
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_new_null() -> *mut stack_st_ASN1_OBJECT {
    return OPENSSL_sk_new_null() as *mut stack_st_ASN1_OBJECT;
}
#[inline]
unsafe extern "C" fn sk_X509_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<OPENSSL_sk_free_func, sk_X509_free_func>(free_func))
        .expect("non-null function pointer")(ptr as *mut X509);
}
#[inline]
unsafe extern "C" fn sk_X509_new_null() -> *mut stack_st_X509 {
    return OPENSSL_sk_new_null() as *mut stack_st_X509;
}
#[inline]
unsafe extern "C" fn sk_X509_num(mut sk: *const stack_st_X509) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_value(
    mut sk: *const stack_st_X509,
    mut i: size_t,
) -> *mut X509 {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509;
}
#[inline]
unsafe extern "C" fn sk_X509_set(
    mut sk: *mut stack_st_X509,
    mut i: size_t,
    mut p: *mut X509,
) -> *mut X509 {
    return OPENSSL_sk_set(sk as *mut OPENSSL_STACK, i, p as *mut libc::c_void)
        as *mut X509;
}
#[inline]
unsafe extern "C" fn sk_X509_free(mut sk: *mut stack_st_X509) {
    OPENSSL_sk_free(sk as *mut OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_pop_free(
    mut sk: *mut stack_st_X509,
    mut free_func: sk_X509_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_X509_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<sk_X509_free_func, OPENSSL_sk_free_func>(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_X509_delete_ptr(
    mut sk: *mut stack_st_X509,
    mut p: *const X509,
) -> *mut X509 {
    return OPENSSL_sk_delete_ptr(sk as *mut OPENSSL_STACK, p as *const libc::c_void)
        as *mut X509;
}
#[inline]
unsafe extern "C" fn sk_X509_push(
    mut sk: *mut stack_st_X509,
    mut p: *mut X509,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_X509_pop(mut sk: *mut stack_st_X509) -> *mut X509 {
    return OPENSSL_sk_pop(sk as *mut OPENSSL_STACK) as *mut X509;
}
#[inline]
unsafe extern "C" fn sk_X509_dup(mut sk: *const stack_st_X509) -> *mut stack_st_X509 {
    return OPENSSL_sk_dup(sk as *const OPENSSL_STACK) as *mut stack_st_X509;
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
unsafe extern "C" fn sk_X509_CRL_num(mut sk: *const stack_st_X509_CRL) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_CRL_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<OPENSSL_sk_free_func, sk_X509_CRL_free_func>(free_func))
        .expect("non-null function pointer")(ptr as *mut X509_CRL);
}
#[inline]
unsafe extern "C" fn sk_X509_CRL_value(
    mut sk: *const stack_st_X509_CRL,
    mut i: size_t,
) -> *mut X509_CRL {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509_CRL;
}
#[inline]
unsafe extern "C" fn sk_X509_CRL_pop_free(
    mut sk: *mut stack_st_X509_CRL,
    mut free_func: sk_X509_CRL_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_X509_CRL_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<sk_X509_CRL_free_func, OPENSSL_sk_free_func>(free_func),
    );
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
unsafe extern "C" fn sk_OPENSSL_STRING_num(
    mut sk: *const stack_st_OPENSSL_STRING,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_OPENSSL_STRING_value(
    mut sk: *const stack_st_OPENSSL_STRING,
    mut i: size_t,
) -> *mut libc::c_char {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut libc::c_char;
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
static mut g_ex_data_class: CRYPTO_EX_DATA_CLASS = {
    let mut init = CRYPTO_EX_DATA_CLASS {
        lock: {
            let mut init = CRYPTO_STATIC_MUTEX {
                lock: pthread_rwlock_t {
                    __data: {
                        let mut init = __pthread_rwlock_arch_t {
                            __readers: 0 as libc::c_int as libc::c_uint,
                            __writers: 0 as libc::c_int as libc::c_uint,
                            __wrphase_futex: 0 as libc::c_int as libc::c_uint,
                            __writers_futex: 0 as libc::c_int as libc::c_uint,
                            __pad3: 0 as libc::c_int as libc::c_uint,
                            __pad4: 0 as libc::c_int as libc::c_uint,
                            __cur_writer: 0 as libc::c_int,
                            __shared: 0 as libc::c_int,
                            __rwelision: 0 as libc::c_int as libc::c_schar,
                            __pad1: [
                                0 as libc::c_int as libc::c_uchar,
                                0 as libc::c_int as libc::c_uchar,
                                0 as libc::c_int as libc::c_uchar,
                                0 as libc::c_int as libc::c_uchar,
                                0 as libc::c_int as libc::c_uchar,
                                0 as libc::c_int as libc::c_uchar,
                                0 as libc::c_int as libc::c_uchar,
                            ],
                            __pad2: 0 as libc::c_int as libc::c_ulong,
                            __flags: PTHREAD_RWLOCK_DEFAULT_NP as libc::c_int
                                as libc::c_uint,
                        };
                        init
                    },
                },
            };
            init
        },
        meth: 0 as *const stack_st_CRYPTO_EX_DATA_FUNCS
            as *mut stack_st_CRYPTO_EX_DATA_FUNCS,
        num_reserved: 1 as libc::c_int as uint8_t,
    };
    init
};
unsafe extern "C" fn null_callback(
    mut ok: libc::c_int,
    mut e: *mut X509_STORE_CTX,
) -> libc::c_int {
    return ok;
}
unsafe extern "C" fn null_verify_custom_crit_oids_callback(
    mut ctx: *mut X509_STORE_CTX,
    mut x509: *mut X509,
    mut oids: *mut stack_st_ASN1_OBJECT,
) -> libc::c_int {
    return 0 as libc::c_int;
}
unsafe extern "C" fn cert_self_signed(
    mut x: *mut X509,
    mut out_is_self_signed: *mut libc::c_int,
) -> libc::c_int {
    if x509v3_cache_extensions(x) == 0 {
        return 0 as libc::c_int;
    }
    *out_is_self_signed = ((*x).ex_flags & 0x2000 as libc::c_int as uint32_t
        != 0 as libc::c_int as uint32_t) as libc::c_int;
    return 1 as libc::c_int;
}
unsafe extern "C" fn call_verify_cb(
    mut ok: libc::c_int,
    mut ctx: *mut X509_STORE_CTX,
) -> libc::c_int {
    ok = ((*ctx).verify_cb).expect("non-null function pointer")(ok, ctx);
    if !(ok == 0 as libc::c_int || ok == 1 as libc::c_int) {
        abort();
    }
    return ok;
}
unsafe extern "C" fn lookup_cert_match(
    mut ctx: *mut X509_STORE_CTX,
    mut x: *mut X509,
) -> *mut X509 {
    let mut certs: *mut stack_st_X509 = 0 as *mut stack_st_X509;
    let mut xtmp: *mut X509 = 0 as *mut X509;
    let mut i: size_t = 0;
    certs = X509_STORE_CTX_get1_certs(ctx, X509_get_subject_name(x));
    if certs.is_null() {
        return 0 as *mut X509;
    }
    i = 0 as libc::c_int as size_t;
    while i < sk_X509_num(certs) {
        xtmp = sk_X509_value(certs, i);
        if X509_cmp(xtmp, x) == 0 {
            break;
        }
        i = i.wrapping_add(1);
        i;
    }
    if i < sk_X509_num(certs) {
        X509_up_ref(xtmp);
    } else {
        xtmp = 0 as *mut X509;
    }
    sk_X509_pop_free(certs, Some(X509_free as unsafe extern "C" fn(*mut X509) -> ()));
    return xtmp;
}
#[no_mangle]
pub unsafe extern "C" fn X509_verify_cert(mut ctx: *mut X509_STORE_CTX) -> libc::c_int {
    let mut num: libc::c_int = 0;
    let mut x: *mut X509 = 0 as *mut X509;
    let mut max_chain: libc::c_int = 0;
    let mut current_block: u64;
    let mut xtmp: *mut X509 = 0 as *mut X509;
    let mut xtmp2: *mut X509 = 0 as *mut X509;
    let mut chain_ss: *mut X509 = 0 as *mut X509;
    let mut bad_chain: libc::c_int = 0 as libc::c_int;
    let mut param: *mut X509_VERIFY_PARAM = (*ctx).param;
    let mut i: libc::c_int = 0;
    let mut ok: libc::c_int = 0 as libc::c_int;
    let mut j: libc::c_int = 0;
    let mut retry: libc::c_int = 0;
    let mut trust: libc::c_int = 0;
    let mut sktmp: *mut stack_st_X509 = 0 as *mut stack_st_X509;
    if ((*ctx).cert).is_null() {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            122 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_vfy.c\0" as *const u8
                as *const libc::c_char,
            190 as libc::c_int as libc::c_uint,
        );
        (*ctx).error = 65 as libc::c_int;
        return -(1 as libc::c_int);
    }
    if !((*ctx).chain).is_null() {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_vfy.c\0" as *const u8
                as *const libc::c_char,
            198 as libc::c_int as libc::c_uint,
        );
        (*ctx).error = 65 as libc::c_int;
        return -(1 as libc::c_int);
    }
    if (*(*ctx).param).flags
        & (0x1000 as libc::c_int | 0x2000 as libc::c_int) as libc::c_ulong != 0
    {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_vfy.c\0" as *const u8
                as *const libc::c_char,
            208 as libc::c_int as libc::c_uint,
        );
        (*ctx).error = 65 as libc::c_int;
        return -(1 as libc::c_int);
    }
    (*ctx).chain = sk_X509_new_null();
    if ((*ctx).chain).is_null() || sk_X509_push((*ctx).chain, (*ctx).cert) == 0 {
        (*ctx).error = 17 as libc::c_int;
    } else {
        X509_up_ref((*ctx).cert);
        (*ctx).last_untrusted = 1 as libc::c_int;
        if !((*ctx).untrusted).is_null()
            && {
                sktmp = sk_X509_dup((*ctx).untrusted);
                sktmp.is_null()
            }
        {
            (*ctx).error = 17 as libc::c_int;
        } else {
            num = sk_X509_num((*ctx).chain) as libc::c_int;
            x = sk_X509_value((*ctx).chain, (num - 1 as libc::c_int) as size_t);
            max_chain = if (*param).depth >= 2147483647 as libc::c_int - 2 as libc::c_int
            {
                2147483647 as libc::c_int
            } else {
                (*param).depth + 2 as libc::c_int
            };
            loop {
                if num >= max_chain {
                    current_block = 10891380440665537214;
                    break;
                }
                let mut is_self_signed: libc::c_int = 0;
                if cert_self_signed(x, &mut is_self_signed) == 0 {
                    (*ctx).error = 41 as libc::c_int;
                    current_block = 16998124838723934101;
                    break;
                } else {
                    if is_self_signed != 0 {
                        current_block = 10891380440665537214;
                        break;
                    }
                    if (*(*ctx).param).flags & 0x8000 as libc::c_int as libc::c_ulong
                        != 0
                    {
                        ok = get_issuer(&mut xtmp, ctx, x);
                        if ok < 0 as libc::c_int {
                            (*ctx).error = 66 as libc::c_int;
                            current_block = 16998124838723934101;
                            break;
                        } else if ok > 0 as libc::c_int {
                            X509_free(xtmp);
                            current_block = 10891380440665537214;
                            break;
                        }
                    }
                    if sktmp.is_null() {
                        current_block = 10891380440665537214;
                        break;
                    }
                    xtmp = find_issuer(ctx, sktmp, x);
                    if xtmp.is_null() {
                        current_block = 10891380440665537214;
                        break;
                    }
                    if sk_X509_push((*ctx).chain, xtmp) == 0 {
                        (*ctx).error = 17 as libc::c_int;
                        ok = 0 as libc::c_int;
                        current_block = 16998124838723934101;
                        break;
                    } else {
                        X509_up_ref(xtmp);
                        sk_X509_delete_ptr(sktmp, xtmp);
                        (*ctx).last_untrusted += 1;
                        (*ctx).last_untrusted;
                        x = xtmp;
                        num += 1;
                        num;
                    }
                }
            }
            match current_block {
                16998124838723934101 => {}
                _ => {
                    j = num;
                    's_213: loop {
                        i = sk_X509_num((*ctx).chain) as libc::c_int;
                        x = sk_X509_value(
                            (*ctx).chain,
                            (i - 1 as libc::c_int) as size_t,
                        );
                        let mut is_self_signed_0: libc::c_int = 0;
                        if cert_self_signed(x, &mut is_self_signed_0) == 0 {
                            (*ctx).error = 41 as libc::c_int;
                            current_block = 16998124838723934101;
                            break;
                        } else {
                            if is_self_signed_0 != 0 {
                                if sk_X509_num((*ctx).chain) == 1 as libc::c_int as size_t {
                                    ok = get_issuer(&mut xtmp, ctx, x);
                                    if ok <= 0 as libc::c_int || X509_cmp(x, xtmp) != 0 {
                                        (*ctx).error = 18 as libc::c_int;
                                        (*ctx).current_cert = x;
                                        (*ctx).error_depth = i - 1 as libc::c_int;
                                        if ok == 1 as libc::c_int {
                                            X509_free(xtmp);
                                        }
                                        bad_chain = 1 as libc::c_int;
                                        ok = call_verify_cb(0 as libc::c_int, ctx);
                                        if ok == 0 {
                                            current_block = 16998124838723934101;
                                            break;
                                        }
                                    } else {
                                        X509_free(x);
                                        x = xtmp;
                                        sk_X509_set(
                                            (*ctx).chain,
                                            (i - 1 as libc::c_int) as size_t,
                                            x,
                                        );
                                        (*ctx).last_untrusted = 0 as libc::c_int;
                                    }
                                } else {
                                    chain_ss = sk_X509_pop((*ctx).chain);
                                    (*ctx).last_untrusted -= 1;
                                    (*ctx).last_untrusted;
                                    num -= 1;
                                    num;
                                    j -= 1;
                                    j;
                                    x = sk_X509_value(
                                        (*ctx).chain,
                                        (num - 1 as libc::c_int) as size_t,
                                    );
                                }
                            }
                            while !(num >= max_chain) {
                                if cert_self_signed(x, &mut is_self_signed_0) == 0 {
                                    (*ctx).error = 41 as libc::c_int;
                                    current_block = 16998124838723934101;
                                    break 's_213;
                                } else {
                                    if is_self_signed_0 != 0 {
                                        break;
                                    }
                                    ok = get_issuer(&mut xtmp, ctx, x);
                                    if ok < 0 as libc::c_int {
                                        (*ctx).error = 66 as libc::c_int;
                                        current_block = 16998124838723934101;
                                        break 's_213;
                                    } else {
                                        if ok == 0 as libc::c_int {
                                            break;
                                        }
                                        x = xtmp;
                                        if sk_X509_push((*ctx).chain, x) == 0 {
                                            X509_free(xtmp);
                                            (*ctx).error = 17 as libc::c_int;
                                            ok = 0 as libc::c_int;
                                            current_block = 16998124838723934101;
                                            break 's_213;
                                        } else {
                                            trust = check_trust(ctx);
                                            if trust == 1 as libc::c_int || trust == 2 as libc::c_int {
                                                break;
                                            }
                                            num += 1;
                                            num;
                                        }
                                    }
                                }
                            }
                            trust = check_trust(ctx);
                            if trust == 2 as libc::c_int {
                                ok = 0 as libc::c_int;
                                current_block = 16998124838723934101;
                                break;
                            } else {
                                retry = 0 as libc::c_int;
                                if trust != 1 as libc::c_int
                                    && (*(*ctx).param).flags
                                        & 0x8000 as libc::c_int as libc::c_ulong == 0
                                    && (*(*ctx).param).flags
                                        & 0x100000 as libc::c_int as libc::c_ulong == 0
                                {
                                    loop {
                                        let fresh0 = j;
                                        j = j - 1;
                                        if !(fresh0 > 1 as libc::c_int) {
                                            break;
                                        }
                                        xtmp2 = sk_X509_value(
                                            (*ctx).chain,
                                            (j - 1 as libc::c_int) as size_t,
                                        );
                                        ok = get_issuer(&mut xtmp, ctx, xtmp2);
                                        if ok < 0 as libc::c_int {
                                            current_block = 16998124838723934101;
                                            break 's_213;
                                        }
                                        if !(ok > 0 as libc::c_int) {
                                            continue;
                                        }
                                        X509_free(xtmp);
                                        while num > j {
                                            xtmp = sk_X509_pop((*ctx).chain);
                                            X509_free(xtmp);
                                            num -= 1;
                                            num;
                                        }
                                        (*ctx)
                                            .last_untrusted = sk_X509_num((*ctx).chain) as libc::c_int;
                                        retry = 1 as libc::c_int;
                                        break;
                                    }
                                }
                                if !(retry != 0) {
                                    current_block = 4488496028633655612;
                                    break;
                                }
                            }
                        }
                    }
                    match current_block {
                        16998124838723934101 => {}
                        _ => {
                            if trust != 1 as libc::c_int && bad_chain == 0 {
                                if chain_ss.is_null()
                                    || x509_check_issued_with_callback(ctx, x, chain_ss) == 0
                                {
                                    if (*ctx).last_untrusted >= num {
                                        (*ctx).error = 20 as libc::c_int;
                                    } else {
                                        (*ctx).error = 2 as libc::c_int;
                                    }
                                    (*ctx).current_cert = x;
                                    current_block = 10109057886293123569;
                                } else if sk_X509_push((*ctx).chain, chain_ss) == 0 {
                                    (*ctx).error = 17 as libc::c_int;
                                    ok = 0 as libc::c_int;
                                    current_block = 16998124838723934101;
                                } else {
                                    num += 1;
                                    num;
                                    (*ctx).last_untrusted = num;
                                    (*ctx).current_cert = chain_ss;
                                    (*ctx).error = 19 as libc::c_int;
                                    chain_ss = 0 as *mut X509;
                                    current_block = 10109057886293123569;
                                }
                                match current_block {
                                    16998124838723934101 => {}
                                    _ => {
                                        (*ctx).error_depth = num - 1 as libc::c_int;
                                        bad_chain = 1 as libc::c_int;
                                        ok = call_verify_cb(0 as libc::c_int, ctx);
                                        if ok == 0 {
                                            current_block = 16998124838723934101;
                                        } else {
                                            current_block = 18002345992382212654;
                                        }
                                    }
                                }
                            } else {
                                current_block = 18002345992382212654;
                            }
                            match current_block {
                                16998124838723934101 => {}
                                _ => {
                                    ok = check_chain_extensions(ctx);
                                    if !(ok == 0) {
                                        ok = check_id(ctx);
                                        if !(ok == 0) {
                                            ok = check_revocation(ctx);
                                            if !(ok == 0) {
                                                ok = internal_verify(ctx);
                                                if !(ok == 0) {
                                                    ok = check_name_constraints(ctx);
                                                    if !(ok == 0) {
                                                        if bad_chain == 0
                                                            && (*(*ctx).param).flags
                                                                & 0x80 as libc::c_int as libc::c_ulong != 0
                                                        {
                                                            ok = check_policy(ctx);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if !sktmp.is_null() {
        sk_X509_free(sktmp);
    }
    if !chain_ss.is_null() {
        X509_free(chain_ss);
    }
    if ok <= 0 as libc::c_int && (*ctx).error == 0 as libc::c_int {
        (*ctx).error = 1 as libc::c_int;
    }
    return ok;
}
unsafe extern "C" fn find_issuer(
    mut ctx: *mut X509_STORE_CTX,
    mut sk: *mut stack_st_X509,
    mut x: *mut X509,
) -> *mut X509 {
    let mut i: size_t = 0;
    let mut issuer: *mut X509 = 0 as *mut X509;
    let mut candidate: *mut X509 = 0 as *mut X509;
    i = 0 as libc::c_int as size_t;
    while i < sk_X509_num(sk) {
        issuer = sk_X509_value(sk, i);
        if x509_check_issued_with_callback(ctx, x, issuer) != 0 {
            candidate = issuer;
            if x509_check_cert_time(ctx, candidate, 1 as libc::c_int) != 0 {
                break;
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    return candidate;
}
#[no_mangle]
pub unsafe extern "C" fn x509_check_issued_with_callback(
    mut ctx: *mut X509_STORE_CTX,
    mut x: *mut X509,
    mut issuer: *mut X509,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    ret = X509_check_issued(issuer, x);
    if ret == 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    if (*(*ctx).param).flags & 0x1 as libc::c_int as libc::c_ulong == 0 {
        return 0 as libc::c_int;
    }
    (*ctx).error = ret;
    (*ctx).current_cert = x;
    (*ctx).current_issuer = issuer;
    return call_verify_cb(0 as libc::c_int, ctx);
}
unsafe extern "C" fn get_issuer(
    mut issuer: *mut *mut X509,
    mut ctx: *mut X509_STORE_CTX,
    mut x: *mut X509,
) -> libc::c_int {
    if !((*ctx).trusted_stack).is_null() {
        *issuer = find_issuer(ctx, (*ctx).trusted_stack, x);
        if !(*issuer).is_null() {
            X509_up_ref(*issuer);
            return 1 as libc::c_int;
        }
        return 0 as libc::c_int;
    }
    return X509_STORE_CTX_get1_issuer(issuer, ctx, x);
}
unsafe extern "C" fn check_custom_critical_extensions(
    mut ctx: *mut X509_STORE_CTX,
    mut x: *mut X509,
) -> libc::c_int {
    if ((*ctx).custom_crit_oids).is_null() {
        return 0 as libc::c_int;
    }
    let mut known_oid_count: size_t = sk_ASN1_OBJECT_num((*ctx).custom_crit_oids);
    if known_oid_count == 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    let mut found_exts: *mut stack_st_ASN1_OBJECT = sk_ASN1_OBJECT_new_null();
    if found_exts.is_null() {
        return 0 as libc::c_int;
    }
    let mut last_pos: libc::c_int = X509_get_ext_by_critical(
        x,
        1 as libc::c_int,
        -(1 as libc::c_int),
    );
    while last_pos >= 0 as libc::c_int {
        let mut ext: *const X509_EXTENSION = X509_get_ext(x, last_pos);
        if X509_supported_extension(ext) == 0 {
            let mut found: libc::c_int = 0 as libc::c_int;
            let mut i: size_t = 0 as libc::c_int as size_t;
            while i < known_oid_count {
                let mut known_ext: *const ASN1_OBJECT = sk_ASN1_OBJECT_value(
                    (*ctx).custom_crit_oids,
                    i,
                );
                if OBJ_cmp((*ext).object, known_ext) == 0 as libc::c_int {
                    let mut dup_obj: *mut ASN1_OBJECT = OBJ_dup(known_ext);
                    if dup_obj.is_null() || sk_ASN1_OBJECT_push(found_exts, dup_obj) == 0
                    {
                        ASN1_OBJECT_free(dup_obj);
                        sk_ASN1_OBJECT_pop_free(
                            found_exts,
                            Some(
                                ASN1_OBJECT_free
                                    as unsafe extern "C" fn(*mut ASN1_OBJECT) -> (),
                            ),
                        );
                        return 0 as libc::c_int;
                    }
                    found = 1 as libc::c_int;
                    break;
                } else {
                    i = i.wrapping_add(1);
                    i;
                }
            }
            if found == 0 {
                sk_ASN1_OBJECT_pop_free(
                    found_exts,
                    Some(
                        ASN1_OBJECT_free as unsafe extern "C" fn(*mut ASN1_OBJECT) -> (),
                    ),
                );
                return 0 as libc::c_int;
            }
        }
        last_pos = X509_get_ext_by_critical(x, 1 as libc::c_int, last_pos);
    }
    if ((*ctx).verify_custom_crit_oids)
        .expect("non-null function pointer")(ctx, x, found_exts) == 0
    {
        sk_ASN1_OBJECT_pop_free(
            found_exts,
            Some(ASN1_OBJECT_free as unsafe extern "C" fn(*mut ASN1_OBJECT) -> ()),
        );
        return 0 as libc::c_int;
    }
    (*x).ex_flags &= !(0x200 as libc::c_int) as uint32_t;
    sk_ASN1_OBJECT_pop_free(
        found_exts,
        Some(ASN1_OBJECT_free as unsafe extern "C" fn(*mut ASN1_OBJECT) -> ()),
    );
    return 1 as libc::c_int;
}
unsafe extern "C" fn check_chain_extensions(
    mut ctx: *mut X509_STORE_CTX,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ok: libc::c_int = 0 as libc::c_int;
    let mut plen: libc::c_int = 0 as libc::c_int;
    let mut purpose: libc::c_int = (*(*ctx).param).purpose;
    let mut i: libc::c_int = 0 as libc::c_int;
    loop {
        if !(i < (*ctx).last_untrusted) {
            current_block = 15125582407903384992;
            break;
        }
        let mut x: *mut X509 = sk_X509_value((*ctx).chain, i as size_t);
        if (*(*ctx).param).flags & 0x10 as libc::c_int as libc::c_ulong == 0
            && (*x).ex_flags & 0x200 as libc::c_int as uint32_t != 0
            && check_custom_critical_extensions(ctx, x) == 0
        {
            (*ctx).error = 34 as libc::c_int;
            (*ctx).error_depth = i;
            (*ctx).current_cert = x;
            ok = call_verify_cb(0 as libc::c_int, ctx);
            if ok == 0 {
                current_block = 7263863983984538461;
                break;
            }
        }
        let mut must_be_ca: libc::c_int = (i > 0 as libc::c_int) as libc::c_int;
        if must_be_ca != 0 && X509_check_ca(x) == 0 {
            (*ctx).error = 24 as libc::c_int;
            (*ctx).error_depth = i;
            (*ctx).current_cert = x;
            ok = call_verify_cb(0 as libc::c_int, ctx);
            if ok == 0 {
                current_block = 7263863983984538461;
                break;
            }
        }
        if (*(*ctx).param).purpose > 0 as libc::c_int
            && X509_check_purpose(x, purpose, must_be_ca) != 1 as libc::c_int
        {
            (*ctx).error = 26 as libc::c_int;
            (*ctx).error_depth = i;
            (*ctx).current_cert = x;
            ok = call_verify_cb(0 as libc::c_int, ctx);
            if ok == 0 {
                current_block = 7263863983984538461;
                break;
            }
        }
        if i > 1 as libc::c_int && (*x).ex_flags & 0x20 as libc::c_int as uint32_t == 0
            && (*x).ex_pathlen != -(1 as libc::c_int) as libc::c_long
            && plen as libc::c_long > (*x).ex_pathlen + 1 as libc::c_int as libc::c_long
        {
            (*ctx).error = 25 as libc::c_int;
            (*ctx).error_depth = i;
            (*ctx).current_cert = x;
            ok = call_verify_cb(0 as libc::c_int, ctx);
            if ok == 0 {
                current_block = 7263863983984538461;
                break;
            }
        }
        if (*x).ex_flags & 0x20 as libc::c_int as uint32_t == 0 {
            plen += 1;
            plen;
        }
        i += 1;
        i;
    }
    match current_block {
        15125582407903384992 => {
            ok = 1 as libc::c_int;
        }
        _ => {}
    }
    return ok;
}
unsafe extern "C" fn reject_dns_name_in_common_name(mut x509: *mut X509) -> libc::c_int {
    let mut name: *const X509_NAME = X509_get_subject_name(x509);
    let mut i: libc::c_int = -(1 as libc::c_int);
    loop {
        i = X509_NAME_get_index_by_NID(name, 13 as libc::c_int, i);
        if i == -(1 as libc::c_int) {
            return 0 as libc::c_int;
        }
        let mut entry: *const X509_NAME_ENTRY = X509_NAME_get_entry(name, i);
        let mut common_name: *const ASN1_STRING = X509_NAME_ENTRY_get_data(entry);
        let mut idval: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
        let mut idlen: libc::c_int = ASN1_STRING_to_UTF8(&mut idval, common_name);
        if idlen < 0 as libc::c_int {
            return 17 as libc::c_int;
        }
        let mut looks_like_dns: libc::c_int = x509v3_looks_like_dns_name(
            idval,
            idlen as size_t,
        );
        OPENSSL_free(idval as *mut libc::c_void);
        if looks_like_dns != 0 {
            return 67 as libc::c_int;
        }
    };
}
unsafe extern "C" fn check_name_constraints(
    mut ctx: *mut X509_STORE_CTX,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    let mut rv: libc::c_int = 0;
    let mut has_name_constraints: libc::c_int = 0 as libc::c_int;
    i = sk_X509_num((*ctx).chain) as libc::c_int - 1 as libc::c_int;
    while i >= 0 as libc::c_int {
        let mut x: *mut X509 = sk_X509_value((*ctx).chain, i as size_t);
        if !(i != 0 && (*x).ex_flags & 0x20 as libc::c_int as uint32_t != 0) {
            let mut current_block_11: u64;
            j = sk_X509_num((*ctx).chain) as libc::c_int - 1 as libc::c_int;
            while j > i {
                let mut nc: *mut NAME_CONSTRAINTS = (*sk_X509_value(
                    (*ctx).chain,
                    j as size_t,
                ))
                    .nc;
                if !nc.is_null() {
                    has_name_constraints = 1 as libc::c_int;
                    rv = NAME_CONSTRAINTS_check(x, nc);
                    match rv {
                        0 => {}
                        17 => {
                            current_block_11 = 9960393165163978828;
                            match current_block_11 {
                                9960393165163978828 => {
                                    (*ctx).error = rv;
                                    return 0 as libc::c_int;
                                }
                                _ => {
                                    (*ctx).error = rv;
                                    (*ctx).error_depth = i;
                                    (*ctx).current_cert = x;
                                    if call_verify_cb(0 as libc::c_int, ctx) == 0 {
                                        return 0 as libc::c_int;
                                    }
                                }
                            }
                        }
                        _ => {
                            current_block_11 = 9400921230118713208;
                            match current_block_11 {
                                9960393165163978828 => {
                                    (*ctx).error = rv;
                                    return 0 as libc::c_int;
                                }
                                _ => {
                                    (*ctx).error = rv;
                                    (*ctx).error_depth = i;
                                    (*ctx).current_cert = x;
                                    if call_verify_cb(0 as libc::c_int, ctx) == 0 {
                                        return 0 as libc::c_int;
                                    }
                                }
                            }
                        }
                    }
                }
                j -= 1;
                j;
            }
        }
        i -= 1;
        i;
    }
    let mut leaf: *mut X509 = sk_X509_value((*ctx).chain, 0 as libc::c_int as size_t);
    if has_name_constraints != 0 && ((*leaf).altname).is_null() {
        rv = reject_dns_name_in_common_name(leaf);
        match rv {
            0 => {}
            17 => {
                (*ctx).error = rv;
                return 0 as libc::c_int;
            }
            _ => {
                (*ctx).error = rv;
                (*ctx).error_depth = i;
                (*ctx).current_cert = leaf;
                if call_verify_cb(0 as libc::c_int, ctx) == 0 {
                    return 0 as libc::c_int;
                }
            }
        }
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn check_id_error(
    mut ctx: *mut X509_STORE_CTX,
    mut errcode: libc::c_int,
) -> libc::c_int {
    (*ctx).error = errcode;
    (*ctx).current_cert = (*ctx).cert;
    (*ctx).error_depth = 0 as libc::c_int;
    return call_verify_cb(0 as libc::c_int, ctx);
}
unsafe extern "C" fn check_hosts(
    mut x: *mut X509,
    mut param: *mut X509_VERIFY_PARAM,
) -> libc::c_int {
    let mut i: size_t = 0;
    let mut n: size_t = sk_OPENSSL_STRING_num((*param).hosts);
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    i = 0 as libc::c_int as size_t;
    while i < n {
        name = sk_OPENSSL_STRING_value((*param).hosts, i);
        if X509_check_host(
            x,
            name,
            strlen(name),
            (*param).hostflags,
            0 as *mut *mut libc::c_char,
        ) > 0 as libc::c_int
        {
            return 1 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return (n == 0 as libc::c_int as size_t) as libc::c_int;
}
unsafe extern "C" fn check_id(mut ctx: *mut X509_STORE_CTX) -> libc::c_int {
    let mut vpm: *mut X509_VERIFY_PARAM = (*ctx).param;
    let mut x: *mut X509 = (*ctx).cert;
    if (*vpm).poison != 0 {
        if check_id_error(ctx, 65 as libc::c_int) == 0 {
            return 0 as libc::c_int;
        }
    }
    if !((*vpm).hosts).is_null() && check_hosts(x, vpm) <= 0 as libc::c_int {
        if check_id_error(ctx, 62 as libc::c_int) == 0 {
            return 0 as libc::c_int;
        }
    }
    if !((*vpm).email).is_null()
        && X509_check_email(
            x,
            (*vpm).email,
            (*vpm).emaillen,
            0 as libc::c_int as libc::c_uint,
        ) <= 0 as libc::c_int
    {
        if check_id_error(ctx, 63 as libc::c_int) == 0 {
            return 0 as libc::c_int;
        }
    }
    if !((*vpm).ip).is_null()
        && X509_check_ip(x, (*vpm).ip, (*vpm).iplen, 0 as libc::c_int as libc::c_uint)
            <= 0 as libc::c_int
    {
        if check_id_error(ctx, 64 as libc::c_int) == 0 {
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn check_trust(mut ctx: *mut X509_STORE_CTX) -> libc::c_int {
    let mut ok: libc::c_int = 0;
    let mut x: *mut X509 = 0 as *mut X509;
    let mut i: size_t = (*ctx).last_untrusted as size_t;
    while i < sk_X509_num((*ctx).chain) {
        x = sk_X509_value((*ctx).chain, i);
        ok = X509_check_trust(x, (*(*ctx).param).trust, 0 as libc::c_int);
        if ok == 1 as libc::c_int {
            return 1 as libc::c_int;
        }
        if ok == 2 as libc::c_int {
            (*ctx).error_depth = i as libc::c_int;
            (*ctx).current_cert = x;
            (*ctx).error = 28 as libc::c_int;
            ok = call_verify_cb(0 as libc::c_int, ctx);
            if ok == 0 {
                return 2 as libc::c_int;
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    if (*(*ctx).param).flags & 0x80000 as libc::c_int as libc::c_ulong != 0 {
        let mut mx: *mut X509 = 0 as *mut X509;
        if (*ctx).last_untrusted < sk_X509_num((*ctx).chain) as libc::c_int {
            return 1 as libc::c_int;
        }
        x = sk_X509_value((*ctx).chain, 0 as libc::c_int as size_t);
        mx = lookup_cert_match(ctx, x);
        if !mx.is_null() {
            sk_X509_set((*ctx).chain, 0 as libc::c_int as size_t, mx);
            X509_free(x);
            (*ctx).last_untrusted = 0 as libc::c_int;
            return 1 as libc::c_int;
        }
    }
    return 3 as libc::c_int;
}
unsafe extern "C" fn check_revocation(mut ctx: *mut X509_STORE_CTX) -> libc::c_int {
    if (*(*ctx).param).flags & 0x4 as libc::c_int as libc::c_ulong == 0 {
        return 1 as libc::c_int;
    }
    let mut last: libc::c_int = 0;
    if (*(*ctx).param).flags & 0x8 as libc::c_int as libc::c_ulong != 0 {
        last = sk_X509_num((*ctx).chain) as libc::c_int - 1 as libc::c_int;
    } else {
        last = 0 as libc::c_int;
    }
    let mut i: libc::c_int = 0 as libc::c_int;
    while i <= last {
        (*ctx).error_depth = i;
        let mut ok: libc::c_int = check_cert(ctx);
        if ok == 0 {
            return ok;
        }
        i += 1;
        i;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn check_cert(mut ctx: *mut X509_STORE_CTX) -> libc::c_int {
    let mut crl: *mut X509_CRL = 0 as *mut X509_CRL;
    let mut ok: libc::c_int = 0 as libc::c_int;
    let mut cnum: libc::c_int = (*ctx).error_depth;
    let mut x: *mut X509 = sk_X509_value((*ctx).chain, cnum as size_t);
    (*ctx).current_cert = x;
    (*ctx).current_issuer = 0 as *mut X509;
    (*ctx).current_crl_score = 0 as libc::c_int;
    ok = ((*ctx).get_crl).expect("non-null function pointer")(ctx, &mut crl, x);
    if ok == 0 {
        (*ctx).error = 3 as libc::c_int;
        ok = call_verify_cb(0 as libc::c_int, ctx);
    } else {
        (*ctx).current_crl = crl;
        ok = ((*ctx).check_crl).expect("non-null function pointer")(ctx, crl);
        if !(ok == 0) {
            ok = cert_crl(ctx, crl, x);
            ok == 0;
        }
    }
    X509_CRL_free(crl);
    (*ctx).current_crl = 0 as *mut X509_CRL;
    return ok;
}
unsafe extern "C" fn check_crl_time(
    mut ctx: *mut X509_STORE_CTX,
    mut crl: *mut X509_CRL,
    mut notify: libc::c_int,
) -> libc::c_int {
    if (*(*ctx).param).flags & 0x200000 as libc::c_int as libc::c_ulong != 0 {
        return 1 as libc::c_int;
    }
    if notify != 0 {
        (*ctx).current_crl = crl;
    }
    let mut ptime: int64_t = 0;
    if (*(*ctx).param).flags & 0x2 as libc::c_int as libc::c_ulong != 0 {
        ptime = (*(*ctx).param).check_time;
    } else {
        ptime = time(0 as *mut time_t);
    }
    let mut i: libc::c_int = X509_cmp_time_posix(X509_CRL_get0_lastUpdate(crl), ptime);
    if i == 0 as libc::c_int {
        if notify == 0 {
            return 0 as libc::c_int;
        }
        (*ctx).error = 15 as libc::c_int;
        if call_verify_cb(0 as libc::c_int, ctx) == 0 {
            return 0 as libc::c_int;
        }
    }
    if i > 0 as libc::c_int {
        if notify == 0 {
            return 0 as libc::c_int;
        }
        (*ctx).error = 11 as libc::c_int;
        if call_verify_cb(0 as libc::c_int, ctx) == 0 {
            return 0 as libc::c_int;
        }
    }
    if !(X509_CRL_get0_nextUpdate(crl)).is_null() {
        i = X509_cmp_time_posix(X509_CRL_get0_nextUpdate(crl), ptime);
        if i == 0 as libc::c_int {
            if notify == 0 {
                return 0 as libc::c_int;
            }
            (*ctx).error = 16 as libc::c_int;
            if call_verify_cb(0 as libc::c_int, ctx) == 0 {
                return 0 as libc::c_int;
            }
        }
        if i < 0 as libc::c_int {
            if notify == 0 {
                return 0 as libc::c_int;
            }
            (*ctx).error = 12 as libc::c_int;
            if call_verify_cb(0 as libc::c_int, ctx) == 0 {
                return 0 as libc::c_int;
            }
        }
    }
    if notify != 0 {
        (*ctx).current_crl = 0 as *mut X509_CRL;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn get_crl_sk(
    mut ctx: *mut X509_STORE_CTX,
    mut pcrl: *mut *mut X509_CRL,
    mut pissuer: *mut *mut X509,
    mut pscore: *mut libc::c_int,
    mut crls: *mut stack_st_X509_CRL,
) -> libc::c_int {
    let mut crl_score: libc::c_int = 0;
    let mut best_score: libc::c_int = *pscore;
    let mut x: *mut X509 = (*ctx).current_cert;
    let mut best_crl: *mut X509_CRL = 0 as *mut X509_CRL;
    let mut crl_issuer: *mut X509 = 0 as *mut X509;
    let mut best_crl_issuer: *mut X509 = 0 as *mut X509;
    let mut current_block_3: u64;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_X509_CRL_num(crls) {
        let mut crl: *mut X509_CRL = sk_X509_CRL_value(crls, i);
        crl_score = get_crl_score(ctx, &mut crl_issuer, crl, x);
        if !(crl_score < best_score || crl_score == 0 as libc::c_int) {
            if crl_score == best_score && !best_crl.is_null() {
                let mut day: libc::c_int = 0;
                let mut sec: libc::c_int = 0;
                if ASN1_TIME_diff(
                    &mut day,
                    &mut sec,
                    X509_CRL_get0_lastUpdate(best_crl),
                    X509_CRL_get0_lastUpdate(crl),
                ) == 0 as libc::c_int
                {
                    current_block_3 = 8258075665625361029;
                } else if day <= 0 as libc::c_int && sec <= 0 as libc::c_int {
                    current_block_3 = 8258075665625361029;
                } else {
                    current_block_3 = 11812396948646013369;
                }
            } else {
                current_block_3 = 11812396948646013369;
            }
            match current_block_3 {
                8258075665625361029 => {}
                _ => {
                    best_crl = crl;
                    best_crl_issuer = crl_issuer;
                    best_score = crl_score;
                }
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    if !best_crl.is_null() {
        if !(*pcrl).is_null() {
            X509_CRL_free(*pcrl);
        }
        *pcrl = best_crl;
        *pissuer = best_crl_issuer;
        *pscore = best_score;
        X509_CRL_up_ref(best_crl);
    }
    if best_score >= 0x100 as libc::c_int | 0x40 as libc::c_int | 0x80 as libc::c_int {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn get_crl_score(
    mut ctx: *mut X509_STORE_CTX,
    mut pissuer: *mut *mut X509,
    mut crl: *mut X509_CRL,
    mut x: *mut X509,
) -> libc::c_int {
    let mut crl_score: libc::c_int = 0 as libc::c_int;
    if (*crl).idp_flags & 0x2 as libc::c_int != 0 {
        return 0 as libc::c_int;
    }
    if (*crl).idp_flags & (0x20 as libc::c_int | 0x40 as libc::c_int) != 0 {
        return 0 as libc::c_int;
    }
    if X509_NAME_cmp(X509_get_issuer_name(x), X509_CRL_get_issuer(crl)) != 0 {
        return 0 as libc::c_int;
    }
    crl_score |= 0x20 as libc::c_int;
    if (*crl).flags & 0x200 as libc::c_int == 0 {
        crl_score |= 0x100 as libc::c_int;
    }
    if check_crl_time(ctx, crl, 0 as libc::c_int) != 0 {
        crl_score |= 0x40 as libc::c_int;
    }
    if crl_akid_check(ctx, crl, pissuer, &mut crl_score) == 0 {
        return 0 as libc::c_int;
    }
    if crl_crldp_check(x, crl, crl_score) != 0 {
        crl_score |= 0x80 as libc::c_int;
    }
    return crl_score;
}
unsafe extern "C" fn crl_akid_check(
    mut ctx: *mut X509_STORE_CTX,
    mut crl: *mut X509_CRL,
    mut pissuer: *mut *mut X509,
    mut pcrl_score: *mut libc::c_int,
) -> libc::c_int {
    let mut crl_issuer: *mut X509 = 0 as *mut X509;
    let mut cnm: *mut X509_NAME = X509_CRL_get_issuer(crl);
    let mut cidx: libc::c_int = (*ctx).error_depth;
    if cidx as size_t
        != (sk_X509_num((*ctx).chain)).wrapping_sub(1 as libc::c_int as size_t)
    {
        cidx += 1;
        cidx;
    }
    crl_issuer = sk_X509_value((*ctx).chain, cidx as size_t);
    if X509_check_akid(crl_issuer, (*crl).akid) == 0 as libc::c_int {
        *pcrl_score |= 0x4 as libc::c_int | 0x18 as libc::c_int;
        *pissuer = crl_issuer;
        return 1 as libc::c_int;
    }
    cidx += 1;
    cidx;
    while cidx < sk_X509_num((*ctx).chain) as libc::c_int {
        crl_issuer = sk_X509_value((*ctx).chain, cidx as size_t);
        if !(X509_NAME_cmp(X509_get_subject_name(crl_issuer), cnm) != 0) {
            if X509_check_akid(crl_issuer, (*crl).akid) == 0 as libc::c_int {
                *pcrl_score |= 0x4 as libc::c_int | 0x8 as libc::c_int;
                *pissuer = crl_issuer;
                return 1 as libc::c_int;
            }
        }
        cidx += 1;
        cidx;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn idp_check_dp(
    mut a: *mut DIST_POINT_NAME,
    mut b: *mut DIST_POINT_NAME,
) -> libc::c_int {
    let mut nm: *mut X509_NAME = 0 as *mut X509_NAME;
    let mut gens: *mut GENERAL_NAMES = 0 as *mut GENERAL_NAMES;
    let mut gena: *mut GENERAL_NAME = 0 as *mut GENERAL_NAME;
    let mut genb: *mut GENERAL_NAME = 0 as *mut GENERAL_NAME;
    let mut i: size_t = 0;
    let mut j: size_t = 0;
    if a.is_null() || b.is_null() {
        return 1 as libc::c_int;
    }
    if (*a).type_0 == 1 as libc::c_int {
        if ((*a).dpname).is_null() {
            return 0 as libc::c_int;
        }
        if (*b).type_0 == 1 as libc::c_int {
            if ((*b).dpname).is_null() {
                return 0 as libc::c_int;
            }
            if X509_NAME_cmp((*a).dpname, (*b).dpname) == 0 {
                return 1 as libc::c_int
            } else {
                return 0 as libc::c_int
            }
        }
        nm = (*a).dpname;
        gens = (*b).name.fullname;
    } else if (*b).type_0 == 1 as libc::c_int {
        if ((*b).dpname).is_null() {
            return 0 as libc::c_int;
        }
        gens = (*a).name.fullname;
        nm = (*b).dpname;
    }
    if !nm.is_null() {
        i = 0 as libc::c_int as size_t;
        while i < sk_GENERAL_NAME_num(gens) {
            gena = sk_GENERAL_NAME_value(gens, i);
            if !((*gena).type_0 != 4 as libc::c_int) {
                if X509_NAME_cmp(nm, (*gena).d.directoryName) == 0 {
                    return 1 as libc::c_int;
                }
            }
            i = i.wrapping_add(1);
            i;
        }
        return 0 as libc::c_int;
    }
    i = 0 as libc::c_int as size_t;
    while i < sk_GENERAL_NAME_num((*a).name.fullname) {
        gena = sk_GENERAL_NAME_value((*a).name.fullname, i);
        j = 0 as libc::c_int as size_t;
        while j < sk_GENERAL_NAME_num((*b).name.fullname) {
            genb = sk_GENERAL_NAME_value((*b).name.fullname, j);
            if GENERAL_NAME_cmp(gena, genb) == 0 {
                return 1 as libc::c_int;
            }
            j = j.wrapping_add(1);
            j;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn crl_crldp_check(
    mut x: *mut X509,
    mut crl: *mut X509_CRL,
    mut crl_score: libc::c_int,
) -> libc::c_int {
    if (*crl).idp_flags & 0x10 as libc::c_int != 0 {
        return 0 as libc::c_int;
    }
    if (*x).ex_flags & 0x10 as libc::c_int as uint32_t != 0 {
        if (*crl).idp_flags & 0x4 as libc::c_int != 0 {
            return 0 as libc::c_int;
        }
    } else if (*crl).idp_flags & 0x8 as libc::c_int != 0 {
        return 0 as libc::c_int
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_DIST_POINT_num((*x).crldp) {
        let mut dp: *mut DIST_POINT = sk_DIST_POINT_value((*x).crldp, i);
        if !((*dp).reasons).is_null() && !((*dp).CRLissuer).is_null()
            && (((*crl).idp).is_null()
                || idp_check_dp((*dp).distpoint, (*(*crl).idp).distpoint) != 0)
        {
            return 1 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return (((*crl).idp).is_null() || ((*(*crl).idp).distpoint).is_null())
        as libc::c_int;
}
unsafe extern "C" fn get_crl(
    mut ctx: *mut X509_STORE_CTX,
    mut pcrl: *mut *mut X509_CRL,
    mut x: *mut X509,
) -> libc::c_int {
    let mut ok: libc::c_int = 0;
    let mut issuer: *mut X509 = 0 as *mut X509;
    let mut crl_score: libc::c_int = 0 as libc::c_int;
    let mut crl: *mut X509_CRL = 0 as *mut X509_CRL;
    let mut skcrl: *mut stack_st_X509_CRL = 0 as *mut stack_st_X509_CRL;
    let mut nm: *mut X509_NAME = X509_get_issuer_name(x);
    ok = get_crl_sk(ctx, &mut crl, &mut issuer, &mut crl_score, (*ctx).crls);
    if !(ok != 0) {
        skcrl = X509_STORE_CTX_get1_crls(ctx, nm);
        if !(skcrl.is_null() && !crl.is_null()) {
            get_crl_sk(ctx, &mut crl, &mut issuer, &mut crl_score, skcrl);
            sk_X509_CRL_pop_free(
                skcrl,
                Some(X509_CRL_free as unsafe extern "C" fn(*mut X509_CRL) -> ()),
            );
        }
    }
    if !crl.is_null() {
        (*ctx).current_issuer = issuer;
        (*ctx).current_crl_score = crl_score;
        *pcrl = crl;
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn check_crl(
    mut ctx: *mut X509_STORE_CTX,
    mut crl: *mut X509_CRL,
) -> libc::c_int {
    let mut issuer: *mut X509 = 0 as *mut X509;
    let mut cnum: libc::c_int = (*ctx).error_depth;
    let mut chnum: libc::c_int = sk_X509_num((*ctx).chain) as libc::c_int
        - 1 as libc::c_int;
    if !((*ctx).current_issuer).is_null() {
        issuer = (*ctx).current_issuer;
    } else if cnum < chnum {
        issuer = sk_X509_value((*ctx).chain, (cnum + 1 as libc::c_int) as size_t);
    } else {
        issuer = sk_X509_value((*ctx).chain, chnum as size_t);
        if x509_check_issued_with_callback(ctx, issuer, issuer) == 0 {
            (*ctx).error = 33 as libc::c_int;
            if call_verify_cb(0 as libc::c_int, ctx) == 0 {
                return 0 as libc::c_int;
            }
        }
    }
    if !issuer.is_null() {
        if (*issuer).ex_flags & 0x2 as libc::c_int as uint32_t != 0
            && (*issuer).ex_kusage & 0x2 as libc::c_int as uint32_t == 0
        {
            (*ctx).error = 35 as libc::c_int;
            if call_verify_cb(0 as libc::c_int, ctx) == 0 {
                return 0 as libc::c_int;
            }
        }
        if (*ctx).current_crl_score & 0x80 as libc::c_int == 0 {
            (*ctx).error = 44 as libc::c_int;
            if call_verify_cb(0 as libc::c_int, ctx) == 0 {
                return 0 as libc::c_int;
            }
        }
        if (*crl).idp_flags & 0x2 as libc::c_int != 0 {
            (*ctx).error = 41 as libc::c_int;
            if call_verify_cb(0 as libc::c_int, ctx) == 0 {
                return 0 as libc::c_int;
            }
        }
        if (*ctx).current_crl_score & 0x40 as libc::c_int == 0 {
            if check_crl_time(ctx, crl, 1 as libc::c_int) == 0 {
                return 0 as libc::c_int;
            }
        }
        let mut ikey: *mut EVP_PKEY = X509_get0_pubkey(issuer);
        if ikey.is_null() {
            (*ctx).error = 6 as libc::c_int;
            if call_verify_cb(0 as libc::c_int, ctx) == 0 {
                return 0 as libc::c_int;
            }
        } else if X509_CRL_verify(crl, ikey) <= 0 as libc::c_int {
            (*ctx).error = 8 as libc::c_int;
            if call_verify_cb(0 as libc::c_int, ctx) == 0 {
                return 0 as libc::c_int;
            }
        }
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn cert_crl(
    mut ctx: *mut X509_STORE_CTX,
    mut crl: *mut X509_CRL,
    mut x: *mut X509,
) -> libc::c_int {
    let mut ok: libc::c_int = 0;
    let mut rev: *mut X509_REVOKED = 0 as *mut X509_REVOKED;
    if (*(*ctx).param).flags & 0x10 as libc::c_int as libc::c_ulong == 0
        && (*crl).flags & 0x200 as libc::c_int != 0
    {
        (*ctx).error = 36 as libc::c_int;
        ok = call_verify_cb(0 as libc::c_int, ctx);
        if ok == 0 {
            return 0 as libc::c_int;
        }
    }
    if X509_CRL_get0_by_cert(crl, &mut rev, x) != 0 {
        (*ctx).error = 23 as libc::c_int;
        ok = call_verify_cb(0 as libc::c_int, ctx);
        if ok == 0 {
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn check_policy(mut ctx: *mut X509_STORE_CTX) -> libc::c_int {
    let mut current_cert: *mut X509 = 0 as *mut X509;
    let mut ret: libc::c_int = X509_policy_check(
        (*ctx).chain,
        (*(*ctx).param).policies,
        (*(*ctx).param).flags,
        &mut current_cert,
    );
    if ret != 0 as libc::c_int {
        (*ctx).current_cert = current_cert;
        (*ctx).error = ret;
        if ret == 17 as libc::c_int {
            return 0 as libc::c_int;
        }
        return call_verify_cb(0 as libc::c_int, ctx);
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn x509_check_cert_time(
    mut ctx: *mut X509_STORE_CTX,
    mut x509: *mut X509,
    mut suppress_error: libc::c_int,
) -> libc::c_int {
    if (*(*ctx).param).flags & 0x200000 as libc::c_int as libc::c_ulong != 0 {
        return 1 as libc::c_int;
    }
    let mut ptime: int64_t = 0;
    if (*(*ctx).param).flags & 0x2 as libc::c_int as libc::c_ulong != 0 {
        ptime = (*(*ctx).param).check_time;
    } else {
        ptime = time(0 as *mut time_t);
    }
    let mut i: libc::c_int = X509_cmp_time_posix(X509_get_notBefore(x509), ptime);
    if i == 0 as libc::c_int {
        if suppress_error != 0 as libc::c_int {
            return 0 as libc::c_int;
        }
        (*ctx).error = 13 as libc::c_int;
        (*ctx).current_cert = x509;
        if call_verify_cb(0 as libc::c_int, ctx) == 0 {
            return 0 as libc::c_int;
        }
    }
    if i > 0 as libc::c_int {
        if suppress_error != 0 as libc::c_int {
            return 0 as libc::c_int;
        }
        (*ctx).error = 9 as libc::c_int;
        (*ctx).current_cert = x509;
        if call_verify_cb(0 as libc::c_int, ctx) == 0 {
            return 0 as libc::c_int;
        }
    }
    i = X509_cmp_time_posix(X509_get_notAfter(x509), ptime);
    if i == 0 as libc::c_int {
        if suppress_error != 0 as libc::c_int {
            return 0 as libc::c_int;
        }
        (*ctx).error = 14 as libc::c_int;
        (*ctx).current_cert = x509;
        if call_verify_cb(0 as libc::c_int, ctx) == 0 {
            return 0 as libc::c_int;
        }
    }
    if i < 0 as libc::c_int {
        if suppress_error != 0 as libc::c_int {
            return 0 as libc::c_int;
        }
        (*ctx).error = 10 as libc::c_int;
        (*ctx).current_cert = x509;
        if call_verify_cb(0 as libc::c_int, ctx) == 0 {
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn internal_verify(mut ctx: *mut X509_STORE_CTX) -> libc::c_int {
    let mut current_block: u64;
    let mut ok: libc::c_int = 0 as libc::c_int;
    let mut xs: *mut X509 = 0 as *mut X509;
    let mut xi: *mut X509 = 0 as *mut X509;
    let mut n: libc::c_int = sk_X509_num((*ctx).chain) as libc::c_int;
    (*ctx).error_depth = n - 1 as libc::c_int;
    n -= 1;
    n;
    xi = sk_X509_value((*ctx).chain, n as size_t);
    if x509_check_issued_with_callback(ctx, xi, xi) != 0 {
        xs = xi;
        current_block = 3512920355445576850;
    } else if (*(*ctx).param).flags & 0x80000 as libc::c_int as libc::c_ulong != 0 {
        xs = xi;
        current_block = 15159374346321111969;
    } else if n <= 0 as libc::c_int {
        (*ctx).error = 21 as libc::c_int;
        (*ctx).current_cert = xi;
        ok = call_verify_cb(0 as libc::c_int, ctx);
        current_block = 889319865048872625;
    } else {
        n -= 1;
        n;
        (*ctx).error_depth = n;
        xs = sk_X509_value((*ctx).chain, n as size_t);
        current_block = 3512920355445576850;
    }
    loop {
        match current_block {
            889319865048872625 => return ok,
            3512920355445576850 => {
                if n >= 0 as libc::c_int {
                    (*ctx).error_depth = n;
                    if !(xs != xi
                        || (*(*ctx).param).flags & 0x4000 as libc::c_int as libc::c_ulong
                            != 0)
                    {
                        current_block = 15159374346321111969;
                        continue;
                    }
                    let mut pkey: *mut EVP_PKEY = X509_get0_pubkey(xi);
                    if pkey.is_null() {
                        (*ctx).error = 6 as libc::c_int;
                        (*ctx).current_cert = xi;
                        ok = call_verify_cb(0 as libc::c_int, ctx);
                        if ok == 0 {
                            current_block = 889319865048872625;
                        } else {
                            current_block = 15159374346321111969;
                        }
                    } else {
                        if !(X509_verify(xs, pkey) <= 0 as libc::c_int) {
                            current_block = 15159374346321111969;
                            continue;
                        }
                        (*ctx).error = 7 as libc::c_int;
                        (*ctx).current_cert = xs;
                        ok = call_verify_cb(0 as libc::c_int, ctx);
                        if ok == 0 {
                            current_block = 889319865048872625;
                        } else {
                            current_block = 15159374346321111969;
                        }
                    }
                } else {
                    ok = 1 as libc::c_int;
                    current_block = 889319865048872625;
                }
            }
            _ => {
                ok = x509_check_cert_time(ctx, xs, 0 as libc::c_int);
                if ok == 0 {
                    current_block = 889319865048872625;
                    continue;
                }
                (*ctx).current_issuer = xi;
                (*ctx).current_cert = xs;
                ok = call_verify_cb(1 as libc::c_int, ctx);
                if ok == 0 {
                    current_block = 889319865048872625;
                    continue;
                }
                n -= 1;
                n;
                if n >= 0 as libc::c_int {
                    xi = xs;
                    xs = sk_X509_value((*ctx).chain, n as size_t);
                }
                current_block = 3512920355445576850;
            }
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn X509_cmp_current_time(
    mut ctm: *const ASN1_TIME,
) -> libc::c_int {
    return X509_cmp_time_posix(ctm, time(0 as *mut time_t));
}
#[no_mangle]
pub unsafe extern "C" fn X509_cmp_time(
    mut ctm: *const ASN1_TIME,
    mut cmp_time: *const time_t,
) -> libc::c_int {
    let mut compare_time: int64_t = if cmp_time.is_null() {
        time(0 as *mut time_t)
    } else {
        *cmp_time
    };
    return X509_cmp_time_posix(ctm, compare_time);
}
#[no_mangle]
pub unsafe extern "C" fn X509_cmp_time_posix(
    mut ctm: *const ASN1_TIME,
    mut cmp_time: int64_t,
) -> libc::c_int {
    let mut ctm_time: int64_t = 0;
    if ASN1_TIME_to_posix(ctm, &mut ctm_time) == 0 {
        return 0 as libc::c_int;
    }
    return if ctm_time - cmp_time <= 0 as libc::c_int as int64_t {
        -(1 as libc::c_int)
    } else {
        1 as libc::c_int
    };
}
#[no_mangle]
pub unsafe extern "C" fn X509_gmtime_adj(
    mut s: *mut ASN1_TIME,
    mut offset_sec: libc::c_long,
) -> *mut ASN1_TIME {
    return X509_time_adj(s, offset_sec, 0 as *const time_t);
}
#[no_mangle]
pub unsafe extern "C" fn X509_time_adj(
    mut s: *mut ASN1_TIME,
    mut offset_sec: libc::c_long,
    mut in_tm: *const time_t,
) -> *mut ASN1_TIME {
    return X509_time_adj_ex(s, 0 as libc::c_int, offset_sec, in_tm);
}
#[no_mangle]
pub unsafe extern "C" fn X509_time_adj_ex(
    mut s: *mut ASN1_TIME,
    mut offset_day: libc::c_int,
    mut offset_sec: libc::c_long,
    mut in_tm: *const time_t,
) -> *mut ASN1_TIME {
    let mut t: int64_t = 0 as libc::c_int as int64_t;
    if !in_tm.is_null() {
        t = *in_tm;
    } else {
        t = time(0 as *mut time_t);
    }
    return ASN1_TIME_adj(s, t, offset_day, offset_sec);
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_ex_new_index(
    mut argl: libc::c_long,
    mut argp: *mut libc::c_void,
    mut unused: *mut CRYPTO_EX_unused,
    mut dup_unused: Option::<CRYPTO_EX_dup>,
    mut free_func: Option::<CRYPTO_EX_free>,
) -> libc::c_int {
    let mut index: libc::c_int = 0;
    if CRYPTO_get_ex_new_index(&mut g_ex_data_class, &mut index, argl, argp, free_func)
        == 0
    {
        return -(1 as libc::c_int);
    }
    return index;
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_ex_data(
    mut ctx: *mut X509_STORE_CTX,
    mut idx: libc::c_int,
    mut data: *mut libc::c_void,
) -> libc::c_int {
    return CRYPTO_set_ex_data(&mut (*ctx).ex_data, idx, data);
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_ex_data(
    mut ctx: *mut X509_STORE_CTX,
    mut idx: libc::c_int,
) -> *mut libc::c_void {
    return CRYPTO_get_ex_data(&mut (*ctx).ex_data, idx);
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_error(
    mut ctx: *mut X509_STORE_CTX,
) -> libc::c_int {
    return (*ctx).error;
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_error(
    mut ctx: *mut X509_STORE_CTX,
    mut err: libc::c_int,
) {
    (*ctx).error = err;
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_error_depth(
    mut ctx: *mut X509_STORE_CTX,
) -> libc::c_int {
    return (*ctx).error_depth;
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_current_cert(
    mut ctx: *mut X509_STORE_CTX,
) -> *mut X509 {
    return (*ctx).current_cert;
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_chain(
    mut ctx: *mut X509_STORE_CTX,
) -> *mut stack_st_X509 {
    return (*ctx).chain;
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get0_chain(
    mut ctx: *mut X509_STORE_CTX,
) -> *mut stack_st_X509 {
    return (*ctx).chain;
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get1_chain(
    mut ctx: *mut X509_STORE_CTX,
) -> *mut stack_st_X509 {
    if ((*ctx).chain).is_null() {
        return 0 as *mut stack_st_X509;
    }
    return X509_chain_up_ref((*ctx).chain);
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get0_current_issuer(
    mut ctx: *mut X509_STORE_CTX,
) -> *mut X509 {
    return (*ctx).current_issuer;
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get0_current_crl(
    mut ctx: *mut X509_STORE_CTX,
) -> *mut X509_CRL {
    return (*ctx).current_crl;
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get0_parent_ctx(
    mut ctx: *mut X509_STORE_CTX,
) -> *mut X509_STORE_CTX {
    return 0 as *mut X509_STORE_CTX;
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_cert(
    mut ctx: *mut X509_STORE_CTX,
    mut x: *mut X509,
) {
    (*ctx).cert = x;
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_chain(
    mut ctx: *mut X509_STORE_CTX,
    mut sk: *mut stack_st_X509,
) {
    (*ctx).untrusted = sk;
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set0_untrusted(
    mut ctx: *mut X509_STORE_CTX,
    mut sk: *mut stack_st_X509,
) {
    X509_STORE_CTX_set_chain(ctx, sk);
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get0_untrusted(
    mut ctx: *mut X509_STORE_CTX,
) -> *mut stack_st_X509 {
    return (*ctx).untrusted;
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set0_crls(
    mut ctx: *mut X509_STORE_CTX,
    mut sk: *mut stack_st_X509_CRL,
) {
    (*ctx).crls = sk;
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_purpose(
    mut ctx: *mut X509_STORE_CTX,
    mut purpose: libc::c_int,
) -> libc::c_int {
    if purpose == 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    let mut idx: libc::c_int = X509_PURPOSE_get_by_id(purpose);
    if idx == -(1 as libc::c_int) {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            130 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_vfy.c\0" as *const u8
                as *const libc::c_char,
            1675 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut trust: libc::c_int = X509_PURPOSE_get_trust(X509_PURPOSE_get0(idx));
    if X509_STORE_CTX_set_trust(ctx, trust) == 0 {
        return 0 as libc::c_int;
    }
    if (*(*ctx).param).purpose == 0 as libc::c_int {
        (*(*ctx).param).purpose = purpose;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_trust(
    mut ctx: *mut X509_STORE_CTX,
    mut trust: libc::c_int,
) -> libc::c_int {
    if trust == 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    if X509_TRUST_get_by_id(trust) == -(1 as libc::c_int) {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            131 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_vfy.c\0" as *const u8
                as *const libc::c_char,
            1697 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*(*ctx).param).trust == 0 as libc::c_int {
        (*(*ctx).param).trust = trust;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_new() -> *mut X509_STORE_CTX {
    return OPENSSL_zalloc(::core::mem::size_of::<X509_STORE_CTX>() as libc::c_ulong)
        as *mut X509_STORE_CTX;
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_free(mut ctx: *mut X509_STORE_CTX) {
    if ctx.is_null() {
        return;
    }
    X509_STORE_CTX_cleanup(ctx);
    OPENSSL_free(ctx as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_init(
    mut ctx: *mut X509_STORE_CTX,
    mut store: *mut X509_STORE,
    mut x509: *mut X509,
    mut chain: *mut stack_st_X509,
) -> libc::c_int {
    X509_STORE_CTX_cleanup(ctx);
    (*ctx).ctx = store;
    (*ctx).cert = x509;
    (*ctx).untrusted = chain;
    CRYPTO_new_ex_data(&mut (*ctx).ex_data);
    if store.is_null() {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_vfy.c\0" as *const u8
                as *const libc::c_char,
            1730 as libc::c_int as libc::c_uint,
        );
    } else {
        (*ctx).param = X509_VERIFY_PARAM_new();
        if !((*ctx).param).is_null() {
            (*ctx).verify_cb = (*store).verify_cb;
            if !(X509_VERIFY_PARAM_inherit((*ctx).param, (*store).param) == 0
                || X509_VERIFY_PARAM_inherit(
                    (*ctx).param,
                    X509_VERIFY_PARAM_lookup(
                        b"default\0" as *const u8 as *const libc::c_char,
                    ),
                ) == 0)
            {
                if ((*store).verify_cb).is_some() {
                    (*ctx).verify_cb = (*store).verify_cb;
                } else {
                    (*ctx)
                        .verify_cb = Some(
                        null_callback
                            as unsafe extern "C" fn(
                                libc::c_int,
                                *mut X509_STORE_CTX,
                            ) -> libc::c_int,
                    );
                }
                if ((*store).get_crl).is_some() {
                    (*ctx).get_crl = (*store).get_crl;
                } else {
                    (*ctx)
                        .get_crl = Some(
                        get_crl
                            as unsafe extern "C" fn(
                                *mut X509_STORE_CTX,
                                *mut *mut X509_CRL,
                                *mut X509,
                            ) -> libc::c_int,
                    );
                }
                if ((*store).check_crl).is_some() {
                    (*ctx).check_crl = (*store).check_crl;
                } else {
                    (*ctx)
                        .check_crl = Some(
                        check_crl
                            as unsafe extern "C" fn(
                                *mut X509_STORE_CTX,
                                *mut X509_CRL,
                            ) -> libc::c_int,
                    );
                }
                (*ctx)
                    .verify_custom_crit_oids = Some(
                    null_verify_custom_crit_oids_callback
                        as unsafe extern "C" fn(
                            *mut X509_STORE_CTX,
                            *mut X509,
                            *mut stack_st_ASN1_OBJECT,
                        ) -> libc::c_int,
                );
                return 1 as libc::c_int;
            }
        }
    }
    CRYPTO_free_ex_data(
        &mut g_ex_data_class,
        ctx as *mut libc::c_void,
        &mut (*ctx).ex_data,
    );
    if !((*ctx).param).is_null() {
        X509_VERIFY_PARAM_free((*ctx).param);
    }
    OPENSSL_memset(
        ctx as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<X509_STORE_CTX>() as libc::c_ulong,
    );
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set0_trusted_stack(
    mut ctx: *mut X509_STORE_CTX,
    mut sk: *mut stack_st_X509,
) {
    (*ctx).trusted_stack = sk;
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_trusted_stack(
    mut ctx: *mut X509_STORE_CTX,
    mut sk: *mut stack_st_X509,
) {
    X509_STORE_CTX_set0_trusted_stack(ctx, sk);
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_cleanup(mut ctx: *mut X509_STORE_CTX) {
    CRYPTO_free_ex_data(
        &mut g_ex_data_class,
        ctx as *mut libc::c_void,
        &mut (*ctx).ex_data,
    );
    X509_VERIFY_PARAM_free((*ctx).param);
    sk_X509_pop_free(
        (*ctx).chain,
        Some(X509_free as unsafe extern "C" fn(*mut X509) -> ()),
    );
    sk_ASN1_OBJECT_pop_free(
        (*ctx).custom_crit_oids,
        Some(ASN1_OBJECT_free as unsafe extern "C" fn(*mut ASN1_OBJECT) -> ()),
    );
    OPENSSL_memset(
        ctx as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<X509_STORE_CTX>() as libc::c_ulong,
    );
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_depth(
    mut ctx: *mut X509_STORE_CTX,
    mut depth: libc::c_int,
) {
    X509_VERIFY_PARAM_set_depth((*ctx).param, depth);
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_flags(
    mut ctx: *mut X509_STORE_CTX,
    mut flags: libc::c_ulong,
) {
    X509_VERIFY_PARAM_set_flags((*ctx).param, flags);
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_time_posix(
    mut ctx: *mut X509_STORE_CTX,
    mut flags: libc::c_ulong,
    mut t: int64_t,
) {
    X509_VERIFY_PARAM_set_time_posix((*ctx).param, t);
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_time(
    mut ctx: *mut X509_STORE_CTX,
    mut flags: libc::c_ulong,
    mut t: time_t,
) {
    X509_STORE_CTX_set_time_posix(ctx, flags, t);
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get0_cert(
    mut ctx: *mut X509_STORE_CTX,
) -> *mut X509 {
    return (*ctx).cert;
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_verify_cb(
    mut ctx: *mut X509_STORE_CTX,
    mut verify_cb: Option::<
        unsafe extern "C" fn(libc::c_int, *mut X509_STORE_CTX) -> libc::c_int,
    >,
) {
    (*ctx).verify_cb = verify_cb;
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_default(
    mut ctx: *mut X509_STORE_CTX,
    mut name: *const libc::c_char,
) -> libc::c_int {
    let mut param: *const X509_VERIFY_PARAM = X509_VERIFY_PARAM_lookup(name);
    if param.is_null() {
        return 0 as libc::c_int;
    }
    return X509_VERIFY_PARAM_inherit((*ctx).param, param);
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get0_param(
    mut ctx: *mut X509_STORE_CTX,
) -> *mut X509_VERIFY_PARAM {
    return (*ctx).param;
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set0_param(
    mut ctx: *mut X509_STORE_CTX,
    mut param: *mut X509_VERIFY_PARAM,
) {
    if !((*ctx).param).is_null() {
        X509_VERIFY_PARAM_free((*ctx).param);
    }
    (*ctx).param = param;
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_add_custom_crit_oid(
    mut ctx: *mut X509_STORE_CTX,
    mut oid: *mut ASN1_OBJECT,
) -> libc::c_int {
    if ctx.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_vfy.c\0" as *const u8
                as *const libc::c_char,
            1848 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if oid.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_vfy.c\0" as *const u8
                as *const libc::c_char,
            1849 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut oid_dup: *mut ASN1_OBJECT = OBJ_dup(oid);
    if oid_dup.is_null() {
        return 0 as libc::c_int;
    }
    if ((*ctx).custom_crit_oids).is_null() {
        (*ctx).custom_crit_oids = sk_ASN1_OBJECT_new_null();
        if ((*ctx).custom_crit_oids).is_null() {
            return 0 as libc::c_int;
        }
    }
    if sk_ASN1_OBJECT_push((*ctx).custom_crit_oids, oid_dup) == 0 {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_verify_crit_oids(
    mut ctx: *mut X509_STORE_CTX,
    mut verify_custom_crit_oids: X509_STORE_CTX_verify_crit_oids_cb,
) {
    (*ctx).verify_custom_crit_oids = verify_custom_crit_oids;
}
