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
    pub type stack_st_BY_DIR_HASH;
    pub type stack_st_BY_DIR_ENTRY;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strncmp(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;
    fn X509_LOOKUP_ctrl(
        lookup: *mut X509_LOOKUP,
        cmd: libc::c_int,
        argc: *const libc::c_char,
        argl: libc::c_long,
        ret: *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn X509_load_cert_file(
        lookup: *mut X509_LOOKUP,
        file: *const libc::c_char,
        type_0: libc::c_int,
    ) -> libc::c_int;
    fn X509_load_crl_file(
        lookup: *mut X509_LOOKUP,
        file: *const libc::c_char,
        type_0: libc::c_int,
    ) -> libc::c_int;
    fn X509_NAME_hash(name: *mut X509_NAME) -> uint32_t;
    fn X509_NAME_hash_old(name: *mut X509_NAME) -> uint32_t;
    fn X509_get_default_cert_dir() -> *const libc::c_char;
    fn X509_get_default_cert_dir_env() -> *const libc::c_char;
    fn BUF_MEM_new() -> *mut BUF_MEM;
    fn BUF_MEM_free(buf: *mut BUF_MEM);
    fn BUF_MEM_grow(buf: *mut BUF_MEM, len: size_t) -> size_t;
    fn OPENSSL_sk_new(comp: OPENSSL_sk_cmp_func) -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
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
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_strndup(str: *const libc::c_char, size: size_t) -> *mut libc::c_char;
    fn ERR_clear_error();
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn CRYPTO_MUTEX_init(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_lock_read(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_lock_write(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_unlock_read(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_unlock_write(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_cleanup(lock: *mut CRYPTO_MUTEX);
}
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type int64_t = __int64_t;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type size_t = libc::c_ulong;
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
pub struct x509_lookup_st {
    pub method: *const X509_LOOKUP_METHOD,
    pub method_data: *mut libc::c_void,
    pub store_ctx: *mut X509_STORE,
}
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
pub type X509_LOOKUP_METHOD = x509_lookup_method_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_lookup_method_st {
    pub new_item: Option::<unsafe extern "C" fn(*mut X509_LOOKUP) -> libc::c_int>,
    pub free: Option::<unsafe extern "C" fn(*mut X509_LOOKUP) -> ()>,
    pub ctrl: Option::<
        unsafe extern "C" fn(
            *mut X509_LOOKUP,
            libc::c_int,
            *const libc::c_char,
            libc::c_long,
            *mut *mut libc::c_char,
        ) -> libc::c_int,
    >,
    pub get_by_subject: Option::<
        unsafe extern "C" fn(
            *mut X509_LOOKUP,
            libc::c_int,
            *mut X509_NAME,
            *mut X509_OBJECT,
        ) -> libc::c_int,
    >,
}
pub type X509_OBJECT = x509_object_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_object_st {
    pub type_0: libc::c_int,
    pub data: C2RustUnnamed_1,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_1 {
    pub ptr: *mut libc::c_char,
    pub x509: *mut X509,
    pub crl: *mut X509_CRL,
    pub pkey: *mut EVP_PKEY,
}
pub type X509_LOOKUP = x509_lookup_st;
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
pub type sk_X509_OBJECT_cmp_func = Option::<
    unsafe extern "C" fn(
        *const *const X509_OBJECT,
        *const *const X509_OBJECT,
    ) -> libc::c_int,
>;
pub type BY_DIR_ENTRY = lookup_dir_entry_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct lookup_dir_entry_st {
    pub lock: CRYPTO_MUTEX,
    pub dir: *mut libc::c_char,
    pub dir_type: libc::c_int,
    pub hashes: *mut stack_st_BY_DIR_HASH,
}
pub type BY_DIR_HASH = lookup_dir_hashes_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct lookup_dir_hashes_st {
    pub hash: uint32_t,
    pub suffix: libc::c_int,
}
pub type sk_BY_DIR_HASH_cmp_func = Option::<
    unsafe extern "C" fn(
        *const *const BY_DIR_HASH,
        *const *const BY_DIR_HASH,
    ) -> libc::c_int,
>;
pub type BY_DIR = lookup_dir_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct lookup_dir_st {
    pub dirs: *mut stack_st_BY_DIR_ENTRY,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_2 {
    pub st_crl: X509_CRL,
    pub st_crl_info: X509_CRL_INFO,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_3 {
    pub x509: C2RustUnnamed_4,
    pub crl: C2RustUnnamed_2,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_4 {
    pub st_x509: X509,
    pub st_x509_cinf: X509_CINF,
}
pub type sk_BY_DIR_HASH_free_func = Option::<
    unsafe extern "C" fn(*mut BY_DIR_HASH) -> (),
>;
pub type sk_BY_DIR_ENTRY_free_func = Option::<
    unsafe extern "C" fn(*mut BY_DIR_ENTRY) -> (),
>;
#[inline]
unsafe extern "C" fn sk_X509_OBJECT_sort(mut sk: *mut stack_st_X509_OBJECT) {
    OPENSSL_sk_sort(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_X509_OBJECT_call_cmp_func
                as unsafe extern "C" fn(
                    OPENSSL_sk_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
}
#[inline]
unsafe extern "C" fn sk_X509_OBJECT_call_cmp_func(
    mut cmp_func: OPENSSL_sk_cmp_func,
    mut a: *const libc::c_void,
    mut b: *const libc::c_void,
) -> libc::c_int {
    let mut a_ptr: *const X509_OBJECT = a as *const X509_OBJECT;
    let mut b_ptr: *const X509_OBJECT = b as *const X509_OBJECT;
    return (::core::mem::transmute::<
        OPENSSL_sk_cmp_func,
        sk_X509_OBJECT_cmp_func,
    >(cmp_func))
        .expect("non-null function pointer")(&mut a_ptr, &mut b_ptr);
}
#[inline]
unsafe extern "C" fn sk_X509_OBJECT_value(
    mut sk: *const stack_st_X509_OBJECT,
    mut i: size_t,
) -> *mut X509_OBJECT {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509_OBJECT;
}
#[inline]
unsafe extern "C" fn sk_X509_OBJECT_find_awslc(
    mut sk: *const stack_st_X509_OBJECT,
    mut out_index: *mut size_t,
    mut p: *const X509_OBJECT,
) -> libc::c_int {
    return OPENSSL_sk_find(
        sk as *const OPENSSL_STACK,
        out_index,
        p as *const libc::c_void,
        Some(
            sk_X509_OBJECT_call_cmp_func
                as unsafe extern "C" fn(
                    OPENSSL_sk_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
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
unsafe extern "C" fn sk_BY_DIR_HASH_sort(mut sk: *mut stack_st_BY_DIR_HASH) {
    OPENSSL_sk_sort(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_BY_DIR_HASH_call_cmp_func
                as unsafe extern "C" fn(
                    OPENSSL_sk_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
}
#[inline]
unsafe extern "C" fn sk_BY_DIR_HASH_call_cmp_func(
    mut cmp_func: OPENSSL_sk_cmp_func,
    mut a: *const libc::c_void,
    mut b: *const libc::c_void,
) -> libc::c_int {
    let mut a_ptr: *const BY_DIR_HASH = a as *const BY_DIR_HASH;
    let mut b_ptr: *const BY_DIR_HASH = b as *const BY_DIR_HASH;
    return (::core::mem::transmute::<
        OPENSSL_sk_cmp_func,
        sk_BY_DIR_HASH_cmp_func,
    >(cmp_func))
        .expect("non-null function pointer")(&mut a_ptr, &mut b_ptr);
}
#[inline]
unsafe extern "C" fn sk_BY_DIR_HASH_pop_free(
    mut sk: *mut stack_st_BY_DIR_HASH,
    mut free_func: sk_BY_DIR_HASH_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_BY_DIR_HASH_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_BY_DIR_HASH_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_BY_DIR_HASH_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<OPENSSL_sk_free_func, sk_BY_DIR_HASH_free_func>(free_func))
        .expect("non-null function pointer")(ptr as *mut BY_DIR_HASH);
}
#[inline]
unsafe extern "C" fn sk_BY_DIR_HASH_new(
    mut comp: sk_BY_DIR_HASH_cmp_func,
) -> *mut stack_st_BY_DIR_HASH {
    return OPENSSL_sk_new(
        ::core::mem::transmute::<sk_BY_DIR_HASH_cmp_func, OPENSSL_sk_cmp_func>(comp),
    ) as *mut stack_st_BY_DIR_HASH;
}
#[inline]
unsafe extern "C" fn sk_BY_DIR_HASH_push(
    mut sk: *mut stack_st_BY_DIR_HASH,
    mut p: *mut BY_DIR_HASH,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_BY_DIR_HASH_value(
    mut sk: *const stack_st_BY_DIR_HASH,
    mut i: size_t,
) -> *mut BY_DIR_HASH {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut BY_DIR_HASH;
}
#[inline]
unsafe extern "C" fn sk_BY_DIR_HASH_find_awslc(
    mut sk: *const stack_st_BY_DIR_HASH,
    mut out_index: *mut size_t,
    mut p: *const BY_DIR_HASH,
) -> libc::c_int {
    return OPENSSL_sk_find(
        sk as *const OPENSSL_STACK,
        out_index,
        p as *const libc::c_void,
        Some(
            sk_BY_DIR_HASH_call_cmp_func
                as unsafe extern "C" fn(
                    OPENSSL_sk_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
}
#[inline]
unsafe extern "C" fn sk_BY_DIR_ENTRY_value(
    mut sk: *const stack_st_BY_DIR_ENTRY,
    mut i: size_t,
) -> *mut BY_DIR_ENTRY {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut BY_DIR_ENTRY;
}
#[inline]
unsafe extern "C" fn sk_BY_DIR_ENTRY_pop_free(
    mut sk: *mut stack_st_BY_DIR_ENTRY,
    mut free_func: sk_BY_DIR_ENTRY_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_BY_DIR_ENTRY_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_BY_DIR_ENTRY_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_BY_DIR_ENTRY_push(
    mut sk: *mut stack_st_BY_DIR_ENTRY,
    mut p: *mut BY_DIR_ENTRY,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_BY_DIR_ENTRY_new_null() -> *mut stack_st_BY_DIR_ENTRY {
    return OPENSSL_sk_new_null() as *mut stack_st_BY_DIR_ENTRY;
}
#[inline]
unsafe extern "C" fn sk_BY_DIR_ENTRY_num(
    mut sk: *const stack_st_BY_DIR_ENTRY,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_BY_DIR_ENTRY_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<
        OPENSSL_sk_free_func,
        sk_BY_DIR_ENTRY_free_func,
    >(free_func))
        .expect("non-null function pointer")(ptr as *mut BY_DIR_ENTRY);
}
static mut x509_dir_lookup: X509_LOOKUP_METHOD = unsafe {
    {
        let mut init = x509_lookup_method_st {
            new_item: Some(
                new_dir as unsafe extern "C" fn(*mut X509_LOOKUP) -> libc::c_int,
            ),
            free: Some(free_dir as unsafe extern "C" fn(*mut X509_LOOKUP) -> ()),
            ctrl: Some(
                dir_ctrl
                    as unsafe extern "C" fn(
                        *mut X509_LOOKUP,
                        libc::c_int,
                        *const libc::c_char,
                        libc::c_long,
                        *mut *mut libc::c_char,
                    ) -> libc::c_int,
            ),
            get_by_subject: Some(
                get_cert_by_subject
                    as unsafe extern "C" fn(
                        *mut X509_LOOKUP,
                        libc::c_int,
                        *mut X509_NAME,
                        *mut X509_OBJECT,
                    ) -> libc::c_int,
            ),
        };
        init
    }
};
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_hash_dir() -> *const X509_LOOKUP_METHOD {
    return &x509_dir_lookup;
}
unsafe extern "C" fn dir_ctrl(
    mut ctx: *mut X509_LOOKUP,
    mut cmd: libc::c_int,
    mut argp: *const libc::c_char,
    mut argl: libc::c_long,
    mut retp: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut dir: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ld: *mut BY_DIR = (*ctx).method_data as *mut BY_DIR;
    match cmd {
        2 => {
            if argl == 3 as libc::c_int as libc::c_long {
                dir = getenv(X509_get_default_cert_dir_env());
                if !dir.is_null() {
                    ret = add_cert_dir(ld, dir, 1 as libc::c_int);
                } else {
                    ret = add_cert_dir(
                        ld,
                        X509_get_default_cert_dir(),
                        1 as libc::c_int,
                    );
                }
                if ret == 0 {
                    ERR_put_error(
                        11 as libc::c_int,
                        0 as libc::c_int,
                        117 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/by_dir.c\0"
                            as *const u8 as *const libc::c_char,
                        126 as libc::c_int as libc::c_uint,
                    );
                }
            } else {
                ret = add_cert_dir(ld, argp, argl as libc::c_int);
            }
        }
        _ => {}
    }
    return ret;
}
unsafe extern "C" fn new_dir(mut lu: *mut X509_LOOKUP) -> libc::c_int {
    let mut a: *mut BY_DIR = 0 as *mut BY_DIR;
    a = OPENSSL_malloc(::core::mem::size_of::<BY_DIR>() as libc::c_ulong) as *mut BY_DIR;
    if a.is_null() {
        return 0 as libc::c_int;
    }
    (*a).dirs = 0 as *mut stack_st_BY_DIR_ENTRY;
    (*lu).method_data = a as *mut libc::c_void;
    return 1 as libc::c_int;
}
unsafe extern "C" fn by_dir_hash_free(mut hash: *mut BY_DIR_HASH) {
    OPENSSL_free(hash as *mut libc::c_void);
}
unsafe extern "C" fn by_dir_hash_cmp(
    mut a: *const *const BY_DIR_HASH,
    mut b: *const *const BY_DIR_HASH,
) -> libc::c_int {
    if (**a).hash > (**b).hash {
        return 1 as libc::c_int;
    }
    if (**a).hash < (**b).hash {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn by_dir_entry_free(mut ent: *mut BY_DIR_ENTRY) {
    if !ent.is_null() {
        CRYPTO_MUTEX_cleanup(&mut (*ent).lock);
        OPENSSL_free((*ent).dir as *mut libc::c_void);
        sk_BY_DIR_HASH_pop_free(
            (*ent).hashes,
            Some(by_dir_hash_free as unsafe extern "C" fn(*mut BY_DIR_HASH) -> ()),
        );
        OPENSSL_free(ent as *mut libc::c_void);
    }
}
unsafe extern "C" fn free_dir(mut lu: *mut X509_LOOKUP) {
    let mut a: *mut BY_DIR = (*lu).method_data as *mut BY_DIR;
    if !a.is_null() {
        sk_BY_DIR_ENTRY_pop_free(
            (*a).dirs,
            Some(by_dir_entry_free as unsafe extern "C" fn(*mut BY_DIR_ENTRY) -> ()),
        );
        OPENSSL_free(a as *mut libc::c_void);
    }
}
unsafe extern "C" fn add_cert_dir(
    mut ctx: *mut BY_DIR,
    mut dir: *const libc::c_char,
    mut type_0: libc::c_int,
) -> libc::c_int {
    let mut j: size_t = 0;
    let mut len: size_t = 0;
    let mut s: *const libc::c_char = 0 as *const libc::c_char;
    let mut ss: *const libc::c_char = 0 as *const libc::c_char;
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    if dir.is_null() || *dir == 0 {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            110 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/by_dir.c\0" as *const u8
                as *const libc::c_char,
            182 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    s = dir;
    p = s;
    loop {
        if *p as libc::c_int == ':' as i32 || *p as libc::c_int == '\0' as i32 {
            let mut ent: *mut BY_DIR_ENTRY = 0 as *mut BY_DIR_ENTRY;
            ss = s;
            s = p.offset(1 as libc::c_int as isize);
            len = p.offset_from(ss) as libc::c_long as size_t;
            if !(len == 0 as libc::c_int as size_t) {
                j = 0 as libc::c_int as size_t;
                while j < sk_BY_DIR_ENTRY_num((*ctx).dirs) {
                    ent = sk_BY_DIR_ENTRY_value((*ctx).dirs, j);
                    if strlen((*ent).dir) == len
                        && strncmp((*ent).dir, ss, len) == 0 as libc::c_int
                    {
                        break;
                    }
                    j = j.wrapping_add(1);
                    j;
                }
                if !(j < sk_BY_DIR_ENTRY_num((*ctx).dirs)) {
                    if ((*ctx).dirs).is_null() {
                        (*ctx).dirs = sk_BY_DIR_ENTRY_new_null();
                        if ((*ctx).dirs).is_null() {
                            return 0 as libc::c_int;
                        }
                    }
                    ent = OPENSSL_malloc(
                        ::core::mem::size_of::<BY_DIR_ENTRY>() as libc::c_ulong,
                    ) as *mut BY_DIR_ENTRY;
                    if ent.is_null() {
                        return 0 as libc::c_int;
                    }
                    CRYPTO_MUTEX_init(&mut (*ent).lock);
                    (*ent).dir_type = type_0;
                    (*ent)
                        .hashes = sk_BY_DIR_HASH_new(
                        Some(
                            by_dir_hash_cmp
                                as unsafe extern "C" fn(
                                    *const *const BY_DIR_HASH,
                                    *const *const BY_DIR_HASH,
                                ) -> libc::c_int,
                        ),
                    );
                    (*ent).dir = OPENSSL_strndup(ss, len);
                    if ((*ent).dir).is_null() || ((*ent).hashes).is_null()
                        || sk_BY_DIR_ENTRY_push((*ctx).dirs, ent) == 0
                    {
                        by_dir_entry_free(ent);
                        return 0 as libc::c_int;
                    }
                }
            }
        }
        let fresh0 = p;
        p = p.offset(1);
        if !(*fresh0 as libc::c_int != '\0' as i32) {
            break;
        }
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn get_cert_by_subject(
    mut xl: *mut X509_LOOKUP,
    mut type_0: libc::c_int,
    mut name: *mut X509_NAME,
    mut ret: *mut X509_OBJECT,
) -> libc::c_int {
    let mut ctx: *mut BY_DIR = 0 as *mut BY_DIR;
    let mut current_block: u64;
    let mut data: C2RustUnnamed_3 = C2RustUnnamed_3 {
        x509: C2RustUnnamed_4 {
            st_x509: x509_st {
                cert_info: 0 as *mut X509_CINF,
                sig_alg: 0 as *mut X509_ALGOR,
                signature: 0 as *mut ASN1_BIT_STRING,
                sig_info: x509_sig_info_st {
                    digest_nid: 0,
                    pubkey_nid: 0,
                    sec_bits: 0,
                    flags: 0,
                },
                references: 0,
                ex_data: crypto_ex_data_st {
                    sk: 0 as *mut stack_st_void,
                },
                ex_pathlen: 0,
                ex_flags: 0,
                ex_kusage: 0,
                ex_xkusage: 0,
                ex_nscert: 0,
                skid: 0 as *mut ASN1_OCTET_STRING,
                akid: 0 as *mut AUTHORITY_KEYID,
                crldp: 0 as *mut stack_st_DIST_POINT,
                altname: 0 as *mut stack_st_GENERAL_NAME,
                nc: 0 as *mut NAME_CONSTRAINTS,
                cert_hash: [0; 32],
                aux: 0 as *mut X509_CERT_AUX,
                buf: 0 as *mut CRYPTO_BUFFER,
                lock: crypto_mutex_st { alignment: 0. },
            },
            st_x509_cinf: X509_CINF {
                version: 0 as *mut ASN1_INTEGER,
                serialNumber: 0 as *mut ASN1_INTEGER,
                signature: 0 as *mut X509_ALGOR,
                issuer: 0 as *mut X509_NAME,
                validity: 0 as *mut X509_VAL,
                subject: 0 as *mut X509_NAME,
                key: 0 as *mut X509_PUBKEY,
                issuerUID: 0 as *mut ASN1_BIT_STRING,
                subjectUID: 0 as *mut ASN1_BIT_STRING,
                extensions: 0 as *mut stack_st_X509_EXTENSION,
                enc: ASN1_ENCODING_st {
                    enc: 0 as *mut libc::c_uchar,
                    len: 0,
                    alias_only_alias_only_on_next_parse: [0; 1],
                    c2rust_padding: [0; 7],
                },
            },
        },
    };
    let mut ok: libc::c_int = 0 as libc::c_int;
    let mut i: size_t = 0;
    let mut j: libc::c_int = 0;
    let mut k: libc::c_int = 0;
    let mut h: uint32_t = 0;
    let mut hash_array: [uint32_t; 2] = [0; 2];
    let mut hash_index: libc::c_int = 0;
    let mut b: *mut BUF_MEM = 0 as *mut BUF_MEM;
    let mut stmp: X509_OBJECT = x509_object_st {
        type_0: 0,
        data: C2RustUnnamed_1 {
            ptr: 0 as *mut libc::c_char,
        },
    };
    let mut tmp: *mut X509_OBJECT = 0 as *mut X509_OBJECT;
    let mut postfix: *const libc::c_char = 0 as *const libc::c_char;
    if name.is_null() {
        return 0 as libc::c_int;
    }
    stmp.type_0 = type_0;
    if type_0 == 1 as libc::c_int {
        data.x509.st_x509.cert_info = &mut data.x509.st_x509_cinf;
        data.x509.st_x509_cinf.subject = name;
        stmp.data.x509 = &mut data.x509.st_x509;
        postfix = b"\0" as *const u8 as *const libc::c_char;
        current_block = 1054647088692577877;
    } else if type_0 == 2 as libc::c_int {
        data.crl.st_crl.crl = &mut data.crl.st_crl_info;
        data.crl.st_crl_info.issuer = name;
        stmp.data.crl = &mut data.crl.st_crl;
        postfix = b"r\0" as *const u8 as *const libc::c_char;
        current_block = 1054647088692577877;
    } else {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            133 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/by_dir.c\0" as *const u8
                as *const libc::c_char,
            268 as libc::c_int as libc::c_uint,
        );
        current_block = 11910281040804028364;
    }
    match current_block {
        1054647088692577877 => {
            b = BUF_MEM_new();
            if b.is_null() {
                ERR_put_error(
                    11 as libc::c_int,
                    0 as libc::c_int,
                    7 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/by_dir.c\0"
                        as *const u8 as *const libc::c_char,
                    273 as libc::c_int as libc::c_uint,
                );
            } else {
                ctx = (*xl).method_data as *mut BY_DIR;
                hash_array[0 as libc::c_int as usize] = X509_NAME_hash(name);
                hash_array[1 as libc::c_int as usize] = X509_NAME_hash_old(name);
                hash_index = 0 as libc::c_int;
                's_101: while hash_index < 2 as libc::c_int {
                    h = hash_array[hash_index as usize];
                    i = 0 as libc::c_int as size_t;
                    while i < sk_BY_DIR_ENTRY_num((*ctx).dirs) {
                        let mut ent: *mut BY_DIR_ENTRY = 0 as *mut BY_DIR_ENTRY;
                        let mut idx: size_t = 0;
                        let mut htmp: BY_DIR_HASH = lookup_dir_hashes_st {
                            hash: 0,
                            suffix: 0,
                        };
                        let mut hent: *mut BY_DIR_HASH = 0 as *mut BY_DIR_HASH;
                        ent = sk_BY_DIR_ENTRY_value((*ctx).dirs, i);
                        j = (strlen((*ent).dir))
                            .wrapping_add(1 as libc::c_int as libc::c_ulong)
                            .wrapping_add(8 as libc::c_int as libc::c_ulong)
                            .wrapping_add(6 as libc::c_int as libc::c_ulong)
                            .wrapping_add(1 as libc::c_int as libc::c_ulong)
                            .wrapping_add(1 as libc::c_int as libc::c_ulong)
                            as libc::c_int;
                        if BUF_MEM_grow(b, j as size_t) == 0 {
                            break 's_101;
                        }
                        if type_0 == 2 as libc::c_int && !((*ent).hashes).is_null() {
                            htmp.hash = h;
                            CRYPTO_MUTEX_lock_read(&mut (*ent).lock);
                            if sk_BY_DIR_HASH_find_awslc(
                                (*ent).hashes,
                                &mut idx,
                                &mut htmp,
                            ) != 0
                            {
                                hent = sk_BY_DIR_HASH_value((*ent).hashes, idx);
                                k = (*hent).suffix;
                            } else {
                                hent = 0 as *mut BY_DIR_HASH;
                                k = 0 as libc::c_int;
                            }
                            CRYPTO_MUTEX_unlock_read(&mut (*ent).lock);
                        } else {
                            k = 0 as libc::c_int;
                            hent = 0 as *mut BY_DIR_HASH;
                        }
                        loop {
                            snprintf(
                                (*b).data,
                                (*b).max,
                                b"%s/%08x.%s%d\0" as *const u8 as *const libc::c_char,
                                (*ent).dir,
                                h,
                                postfix,
                                k,
                            );
                            if type_0 == 1 as libc::c_int {
                                if X509_load_cert_file(xl, (*b).data, (*ent).dir_type)
                                    == 0 as libc::c_int
                                {
                                    ERR_clear_error();
                                    break;
                                }
                            } else if type_0 == 2 as libc::c_int {
                                if X509_load_crl_file(xl, (*b).data, (*ent).dir_type)
                                    == 0 as libc::c_int
                                {
                                    ERR_clear_error();
                                    break;
                                }
                            }
                            k += 1;
                            k;
                        }
                        CRYPTO_MUTEX_lock_write(&mut (*(*xl).store_ctx).objs_lock);
                        tmp = 0 as *mut X509_OBJECT;
                        sk_X509_OBJECT_sort((*(*xl).store_ctx).objs);
                        if sk_X509_OBJECT_find_awslc(
                            (*(*xl).store_ctx).objs,
                            &mut idx,
                            &mut stmp,
                        ) != 0
                        {
                            tmp = sk_X509_OBJECT_value((*(*xl).store_ctx).objs, idx);
                        }
                        CRYPTO_MUTEX_unlock_write(&mut (*(*xl).store_ctx).objs_lock);
                        if type_0 == 2 as libc::c_int {
                            CRYPTO_MUTEX_lock_write(&mut (*ent).lock);
                            if hent.is_null() {
                                htmp.hash = h;
                                sk_BY_DIR_HASH_sort((*ent).hashes);
                                if sk_BY_DIR_HASH_find_awslc(
                                    (*ent).hashes,
                                    &mut idx,
                                    &mut htmp,
                                ) != 0
                                {
                                    hent = sk_BY_DIR_HASH_value((*ent).hashes, idx);
                                }
                            }
                            if hent.is_null() {
                                hent = OPENSSL_malloc(
                                    ::core::mem::size_of::<BY_DIR_HASH>() as libc::c_ulong,
                                ) as *mut BY_DIR_HASH;
                                if hent.is_null() {
                                    CRYPTO_MUTEX_unlock_write(&mut (*ent).lock);
                                    ok = 0 as libc::c_int;
                                    break 's_101;
                                } else {
                                    (*hent).hash = h;
                                    (*hent).suffix = k;
                                    if sk_BY_DIR_HASH_push((*ent).hashes, hent) == 0 {
                                        CRYPTO_MUTEX_unlock_write(&mut (*ent).lock);
                                        OPENSSL_free(hent as *mut libc::c_void);
                                        ok = 0 as libc::c_int;
                                        break 's_101;
                                    } else {
                                        sk_BY_DIR_HASH_sort((*ent).hashes);
                                    }
                                }
                            } else if (*hent).suffix < k {
                                (*hent).suffix = k;
                            }
                            CRYPTO_MUTEX_unlock_write(&mut (*ent).lock);
                        }
                        if !tmp.is_null() {
                            ok = 1 as libc::c_int;
                            (*ret).type_0 = (*tmp).type_0;
                            OPENSSL_memcpy(
                                &mut (*ret).data as *mut C2RustUnnamed_1
                                    as *mut libc::c_void,
                                &mut (*tmp).data as *mut C2RustUnnamed_1
                                    as *const libc::c_void,
                                ::core::mem::size_of::<C2RustUnnamed_1>() as libc::c_ulong,
                            );
                            ERR_clear_error();
                            break 's_101;
                        } else {
                            i = i.wrapping_add(1);
                            i;
                        }
                    }
                    hash_index += 1;
                    hash_index;
                }
            }
        }
        _ => {}
    }
    BUF_MEM_free(b);
    return ok;
}
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_add_dir(
    mut lookup: *mut X509_LOOKUP,
    mut name: *const libc::c_char,
    mut type_0: libc::c_int,
) -> libc::c_int {
    return X509_LOOKUP_ctrl(
        lookup,
        2 as libc::c_int,
        name,
        type_0 as libc::c_long,
        0 as *mut *mut libc::c_char,
    );
}
