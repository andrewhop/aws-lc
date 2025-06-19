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
    fn X509_up_ref(x509: *mut X509) -> libc::c_int;
    fn X509_free(x509: *mut X509);
    fn X509_get_issuer_name(x509: *const X509) -> *mut X509_NAME;
    fn X509_get_subject_name(x509: *const X509) -> *mut X509_NAME;
    fn X509_cmp(a: *const X509, b: *const X509) -> libc::c_int;
    fn X509_CRL_up_ref(crl: *mut X509_CRL) -> libc::c_int;
    fn X509_CRL_free(crl: *mut X509_CRL);
    fn X509_CRL_match(a: *const X509_CRL, b: *const X509_CRL) -> libc::c_int;
    fn X509_NAME_cmp(a: *const X509_NAME, b: *const X509_NAME) -> libc::c_int;
    fn X509_VERIFY_PARAM_new() -> *mut X509_VERIFY_PARAM;
    fn X509_VERIFY_PARAM_free(param: *mut X509_VERIFY_PARAM);
    fn X509_VERIFY_PARAM_set1(
        to: *mut X509_VERIFY_PARAM,
        from: *const X509_VERIFY_PARAM,
    ) -> libc::c_int;
    fn X509_VERIFY_PARAM_set_flags(
        param: *mut X509_VERIFY_PARAM,
        flags: libc::c_ulong,
    ) -> libc::c_int;
    fn X509_VERIFY_PARAM_set_depth(param: *mut X509_VERIFY_PARAM, depth: libc::c_int);
    fn X509_VERIFY_PARAM_set_purpose(
        param: *mut X509_VERIFY_PARAM,
        purpose: libc::c_int,
    ) -> libc::c_int;
    fn X509_VERIFY_PARAM_set_trust(
        param: *mut X509_VERIFY_PARAM,
        trust: libc::c_int,
    ) -> libc::c_int;
    fn X509_subject_name_cmp(a: *const X509, b: *const X509) -> libc::c_int;
    fn X509_CRL_cmp(a: *const X509_CRL, b: *const X509_CRL) -> libc::c_int;
    fn x509_check_cert_time(
        ctx: *mut X509_STORE_CTX,
        x: *mut X509,
        suppress_error: libc::c_int,
    ) -> libc::c_int;
    fn x509_check_issued_with_callback(
        ctx: *mut X509_STORE_CTX,
        x: *mut X509,
        issuer: *mut X509,
    ) -> libc::c_int;
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
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn CRYPTO_refcount_inc(count: *mut CRYPTO_refcount_t);
    fn CRYPTO_refcount_dec_and_test_zero(count: *mut CRYPTO_refcount_t) -> libc::c_int;
    fn CRYPTO_MUTEX_init(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_lock_write(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_unlock_write(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_cleanup(lock: *mut CRYPTO_MUTEX);
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
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
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
pub type sk_X509_free_func = Option::<unsafe extern "C" fn(*mut X509) -> ()>;
pub type sk_X509_CRL_free_func = Option::<unsafe extern "C" fn(*mut X509_CRL) -> ()>;
pub type sk_X509_OBJECT_free_func = Option::<
    unsafe extern "C" fn(*mut X509_OBJECT) -> (),
>;
pub type sk_X509_LOOKUP_free_func = Option::<
    unsafe extern "C" fn(*mut X509_LOOKUP) -> (),
>;
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
pub type sk_X509_OBJECT_cmp_func = Option::<
    unsafe extern "C" fn(
        *const *const X509_OBJECT,
        *const *const X509_OBJECT,
    ) -> libc::c_int,
>;
pub type C2RustUnnamed_2 = libc::c_uint;
pub const PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP: C2RustUnnamed_2 = 2;
pub const PTHREAD_RWLOCK_PREFER_WRITER_NP: C2RustUnnamed_2 = 1;
pub const PTHREAD_RWLOCK_PREFER_READER_NP: C2RustUnnamed_2 = 0;
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
unsafe extern "C" fn sk_X509_push(
    mut sk: *mut stack_st_X509,
    mut p: *mut X509,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
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
unsafe extern "C" fn sk_X509_CRL_push(
    mut sk: *mut stack_st_X509_CRL,
    mut p: *mut X509_CRL,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
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
unsafe extern "C" fn sk_X509_CRL_new_null() -> *mut stack_st_X509_CRL {
    return OPENSSL_sk_new_null() as *mut stack_st_X509_CRL;
}
#[inline]
unsafe extern "C" fn sk_X509_CRL_free(mut sk: *mut stack_st_X509_CRL) {
    OPENSSL_sk_free(sk as *mut OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_OBJECT_pop_free(
    mut sk: *mut stack_st_X509_OBJECT,
    mut free_func: sk_X509_OBJECT_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_X509_OBJECT_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_X509_OBJECT_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_X509_OBJECT_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<OPENSSL_sk_free_func, sk_X509_OBJECT_free_func>(free_func))
        .expect("non-null function pointer")(ptr as *mut X509_OBJECT);
}
#[inline]
unsafe extern "C" fn sk_X509_OBJECT_new(
    mut comp: sk_X509_OBJECT_cmp_func,
) -> *mut stack_st_X509_OBJECT {
    return OPENSSL_sk_new(
        ::core::mem::transmute::<sk_X509_OBJECT_cmp_func, OPENSSL_sk_cmp_func>(comp),
    ) as *mut stack_st_X509_OBJECT;
}
#[inline]
unsafe extern "C" fn sk_X509_OBJECT_push(
    mut sk: *mut stack_st_X509_OBJECT,
    mut p: *mut X509_OBJECT,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_X509_OBJECT_value(
    mut sk: *const stack_st_X509_OBJECT,
    mut i: size_t,
) -> *mut X509_OBJECT {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509_OBJECT;
}
#[inline]
unsafe extern "C" fn sk_X509_OBJECT_num(mut sk: *const stack_st_X509_OBJECT) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
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
unsafe extern "C" fn sk_X509_LOOKUP_pop_free(
    mut sk: *mut stack_st_X509_LOOKUP,
    mut free_func: sk_X509_LOOKUP_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_X509_LOOKUP_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_X509_LOOKUP_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_X509_LOOKUP_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<OPENSSL_sk_free_func, sk_X509_LOOKUP_free_func>(free_func))
        .expect("non-null function pointer")(ptr as *mut X509_LOOKUP);
}
#[inline]
unsafe extern "C" fn sk_X509_LOOKUP_new_null() -> *mut stack_st_X509_LOOKUP {
    return OPENSSL_sk_new_null() as *mut stack_st_X509_LOOKUP;
}
#[inline]
unsafe extern "C" fn sk_X509_LOOKUP_push(
    mut sk: *mut stack_st_X509_LOOKUP,
    mut p: *mut X509_LOOKUP,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_X509_LOOKUP_value(
    mut sk: *const stack_st_X509_LOOKUP,
    mut i: size_t,
) -> *mut X509_LOOKUP {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509_LOOKUP;
}
#[inline]
unsafe extern "C" fn sk_X509_LOOKUP_num(mut sk: *const stack_st_X509_LOOKUP) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
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
unsafe extern "C" fn X509_LOOKUP_new(
    mut method: *const X509_LOOKUP_METHOD,
    mut store: *mut X509_STORE,
) -> *mut X509_LOOKUP {
    let mut ret: *mut X509_LOOKUP = OPENSSL_zalloc(
        ::core::mem::size_of::<X509_LOOKUP>() as libc::c_ulong,
    ) as *mut X509_LOOKUP;
    if ret.is_null() {
        return 0 as *mut X509_LOOKUP;
    }
    (*ret).method = method;
    (*ret).store_ctx = store;
    if ((*method).new_item).is_some()
        && ((*method).new_item).expect("non-null function pointer")(ret) == 0
    {
        OPENSSL_free(ret as *mut libc::c_void);
        return 0 as *mut X509_LOOKUP;
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_LOOKUP_free(mut ctx: *mut X509_LOOKUP) {
    if ctx.is_null() {
        return;
    }
    if !((*ctx).method).is_null() && ((*(*ctx).method).free).is_some() {
        (Some(((*(*ctx).method).free).expect("non-null function pointer")))
            .expect("non-null function pointer")(ctx);
    }
    OPENSSL_free(ctx as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_LOOKUP_ctrl(
    mut ctx: *mut X509_LOOKUP,
    mut cmd: libc::c_int,
    mut argc: *const libc::c_char,
    mut argl: libc::c_long,
    mut ret: *mut *mut libc::c_char,
) -> libc::c_int {
    if ((*ctx).method).is_null() {
        return -(1 as libc::c_int);
    }
    if ((*(*ctx).method).ctrl).is_some() {
        return ((*(*ctx).method).ctrl)
            .expect("non-null function pointer")(ctx, cmd, argc, argl, ret)
    } else {
        return 1 as libc::c_int
    };
}
unsafe extern "C" fn X509_LOOKUP_by_subject(
    mut ctx: *mut X509_LOOKUP,
    mut type_0: libc::c_int,
    mut name: *mut X509_NAME,
    mut ret: *mut X509_OBJECT,
) -> libc::c_int {
    if ((*ctx).method).is_null() || ((*(*ctx).method).get_by_subject).is_none() {
        return 0 as libc::c_int;
    }
    return (((*(*ctx).method).get_by_subject)
        .expect("non-null function pointer")(ctx, type_0, name, ret) > 0 as libc::c_int)
        as libc::c_int;
}
unsafe extern "C" fn x509_object_cmp(
    mut a: *const X509_OBJECT,
    mut b: *const X509_OBJECT,
) -> libc::c_int {
    let mut ret: libc::c_int = (*a).type_0 - (*b).type_0;
    if ret != 0 {
        return ret;
    }
    match (*a).type_0 {
        1 => return X509_subject_name_cmp((*a).data.x509, (*b).data.x509),
        2 => return X509_CRL_cmp((*a).data.crl, (*b).data.crl),
        _ => return 0 as libc::c_int,
    };
}
unsafe extern "C" fn x509_object_cmp_sk(
    mut a: *const *const X509_OBJECT,
    mut b: *const *const X509_OBJECT,
) -> libc::c_int {
    return x509_object_cmp(*a, *b);
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_new() -> *mut X509_STORE {
    let mut ret: *mut X509_STORE = OPENSSL_zalloc(
        ::core::mem::size_of::<X509_STORE>() as libc::c_ulong,
    ) as *mut X509_STORE;
    if ret.is_null() {
        return 0 as *mut X509_STORE;
    }
    (*ret).references = 1 as libc::c_int as CRYPTO_refcount_t;
    CRYPTO_MUTEX_init(&mut (*ret).objs_lock);
    CRYPTO_new_ex_data(&mut (*ret).ex_data);
    (*ret)
        .objs = sk_X509_OBJECT_new(
        Some(
            x509_object_cmp_sk
                as unsafe extern "C" fn(
                    *const *const X509_OBJECT,
                    *const *const X509_OBJECT,
                ) -> libc::c_int,
        ),
    );
    (*ret).get_cert_methods = sk_X509_LOOKUP_new_null();
    (*ret).param = X509_VERIFY_PARAM_new();
    if ((*ret).objs).is_null() || ((*ret).get_cert_methods).is_null()
        || ((*ret).param).is_null()
    {
        X509_STORE_free(ret);
        return 0 as *mut X509_STORE;
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_lock(mut v: *mut X509_STORE) -> libc::c_int {
    if v.is_null() {
        return 0 as libc::c_int;
    }
    CRYPTO_MUTEX_lock_write(&mut (*v).objs_lock);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_unlock(mut v: *mut X509_STORE) -> libc::c_int {
    if v.is_null() {
        return 0 as libc::c_int;
    }
    CRYPTO_MUTEX_unlock_write(&mut (*v).objs_lock);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_up_ref(mut store: *mut X509_STORE) -> libc::c_int {
    CRYPTO_refcount_inc(&mut (*store).references);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_free(mut vfy: *mut X509_STORE) {
    if vfy.is_null() {
        return;
    }
    if CRYPTO_refcount_dec_and_test_zero(&mut (*vfy).references) == 0 {
        return;
    }
    CRYPTO_MUTEX_cleanup(&mut (*vfy).objs_lock);
    CRYPTO_free_ex_data(
        &mut g_ex_data_class,
        vfy as *mut libc::c_void,
        &mut (*vfy).ex_data,
    );
    sk_X509_LOOKUP_pop_free(
        (*vfy).get_cert_methods,
        Some(X509_LOOKUP_free as unsafe extern "C" fn(*mut X509_LOOKUP) -> ()),
    );
    sk_X509_OBJECT_pop_free(
        (*vfy).objs,
        Some(X509_OBJECT_free as unsafe extern "C" fn(*mut X509_OBJECT) -> ()),
    );
    X509_VERIFY_PARAM_free((*vfy).param);
    OPENSSL_free(vfy as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_add_lookup(
    mut v: *mut X509_STORE,
    mut m: *const X509_LOOKUP_METHOD,
) -> *mut X509_LOOKUP {
    let mut sk: *mut stack_st_X509_LOOKUP = (*v).get_cert_methods;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_X509_LOOKUP_num(sk) {
        let mut lu: *mut X509_LOOKUP = sk_X509_LOOKUP_value(sk, i);
        if m == (*lu).method {
            return lu;
        }
        i = i.wrapping_add(1);
        i;
    }
    let mut lu_0: *mut X509_LOOKUP = X509_LOOKUP_new(m, v);
    if lu_0.is_null() || sk_X509_LOOKUP_push((*v).get_cert_methods, lu_0) == 0 {
        X509_LOOKUP_free(lu_0);
        return 0 as *mut X509_LOOKUP;
    }
    return lu_0;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_CTX_get_by_subject(
    mut vs: *mut X509_STORE_CTX,
    mut type_0: libc::c_int,
    mut name: *mut X509_NAME,
    mut ret: *mut X509_OBJECT,
) -> libc::c_int {
    let mut ctx: *mut X509_STORE = (*vs).ctx;
    let mut stmp: X509_OBJECT = x509_object_st {
        type_0: 0,
        data: C2RustUnnamed_1 {
            ptr: 0 as *mut libc::c_char,
        },
    };
    CRYPTO_MUTEX_lock_write(&mut (*ctx).objs_lock);
    let mut tmp: *mut X509_OBJECT = X509_OBJECT_retrieve_by_subject(
        (*ctx).objs,
        type_0,
        name,
    );
    CRYPTO_MUTEX_unlock_write(&mut (*ctx).objs_lock);
    if tmp.is_null() || type_0 == 2 as libc::c_int {
        let mut i: size_t = 0 as libc::c_int as size_t;
        while i < sk_X509_LOOKUP_num((*ctx).get_cert_methods) {
            let mut lu: *mut X509_LOOKUP = sk_X509_LOOKUP_value(
                (*ctx).get_cert_methods,
                i,
            );
            if X509_LOOKUP_by_subject(lu, type_0, name, &mut stmp) != 0 {
                tmp = &mut stmp;
                break;
            } else {
                i = i.wrapping_add(1);
                i;
            }
        }
        if tmp.is_null() {
            return 0 as libc::c_int;
        }
    }
    (*ret).type_0 = (*tmp).type_0;
    (*ret).data.ptr = (*tmp).data.ptr;
    X509_OBJECT_up_ref_count(ret);
    return 1 as libc::c_int;
}
unsafe extern "C" fn x509_store_add(
    mut ctx: *mut X509_STORE,
    mut x: *mut libc::c_void,
    mut is_crl: libc::c_int,
) -> libc::c_int {
    if x.is_null() {
        return 0 as libc::c_int;
    }
    let obj: *mut X509_OBJECT = X509_OBJECT_new();
    if obj.is_null() {
        return 0 as libc::c_int;
    }
    if is_crl != 0 {
        (*obj).type_0 = 2 as libc::c_int;
        (*obj).data.crl = x as *mut X509_CRL;
    } else {
        (*obj).type_0 = 1 as libc::c_int;
        (*obj).data.x509 = x as *mut X509;
    }
    X509_OBJECT_up_ref_count(obj);
    CRYPTO_MUTEX_lock_write(&mut (*ctx).objs_lock);
    let mut ret: libc::c_int = 1 as libc::c_int;
    let mut added: libc::c_int = 0 as libc::c_int;
    if (X509_OBJECT_retrieve_match((*ctx).objs, obj)).is_null() {
        added = (sk_X509_OBJECT_push((*ctx).objs, obj) != 0 as libc::c_int as size_t)
            as libc::c_int;
        ret = added;
    }
    CRYPTO_MUTEX_unlock_write(&mut (*ctx).objs_lock);
    if added == 0 {
        X509_OBJECT_free(obj);
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_add_cert(
    mut ctx: *mut X509_STORE,
    mut x: *mut X509,
) -> libc::c_int {
    return x509_store_add(ctx, x as *mut libc::c_void, 0 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_add_crl(
    mut ctx: *mut X509_STORE,
    mut x: *mut X509_CRL,
) -> libc::c_int {
    return x509_store_add(ctx, x as *mut libc::c_void, 1 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_OBJECT_new() -> *mut X509_OBJECT {
    return OPENSSL_zalloc(::core::mem::size_of::<X509_OBJECT>() as libc::c_ulong)
        as *mut X509_OBJECT;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_OBJECT_free(mut obj: *mut X509_OBJECT) {
    if obj.is_null() {
        return;
    }
    X509_OBJECT_free_contents(obj);
    OPENSSL_free(obj as *mut libc::c_void);
}
unsafe extern "C" fn X509_OBJECT_up_ref_count(mut a: *mut X509_OBJECT) -> libc::c_int {
    match (*a).type_0 {
        1 => {
            X509_up_ref((*a).data.x509);
        }
        2 => {
            X509_CRL_up_ref((*a).data.crl);
        }
        _ => {}
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_OBJECT_free_contents(mut a: *mut X509_OBJECT) {
    match (*a).type_0 {
        1 => {
            X509_free((*a).data.x509);
        }
        2 => {
            X509_CRL_free((*a).data.crl);
        }
        _ => {}
    }
    OPENSSL_memset(
        a as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<X509_OBJECT>() as libc::c_ulong,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_OBJECT_get_type(mut a: *const X509_OBJECT) -> libc::c_int {
    return (*a).type_0;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_OBJECT_get0_X509(mut a: *const X509_OBJECT) -> *mut X509 {
    if a.is_null() || (*a).type_0 != 1 as libc::c_int {
        return 0 as *mut X509;
    }
    return (*a).data.x509;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_OBJECT_get0_X509_CRL(
    mut a: *const X509_OBJECT,
) -> *mut X509_CRL {
    if a.is_null() || (*a).type_0 != 2 as libc::c_int {
        return 0 as *mut X509_CRL;
    }
    return (*a).data.crl;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_OBJECT_set1_X509(
    mut a: *mut X509_OBJECT,
    mut obj: *mut X509,
) -> libc::c_int {
    if a.is_null() || X509_up_ref(obj) == 0 {
        return 0 as libc::c_int;
    }
    X509_OBJECT_free_contents(a);
    (*a).type_0 = 1 as libc::c_int;
    (*a).data.x509 = obj;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_OBJECT_set1_X509_CRL(
    mut a: *mut X509_OBJECT,
    mut obj: *mut X509_CRL,
) -> libc::c_int {
    if a.is_null() || X509_CRL_up_ref(obj) == 0 {
        return 0 as libc::c_int;
    }
    X509_OBJECT_free_contents(a);
    (*a).type_0 = 2 as libc::c_int;
    (*a).data.crl = obj;
    return 1 as libc::c_int;
}
unsafe extern "C" fn x509_object_idx_cnt(
    mut h: *mut stack_st_X509_OBJECT,
    mut type_0: libc::c_int,
    mut name: *mut X509_NAME,
    mut pnmatch: *mut libc::c_int,
) -> libc::c_int {
    let mut stmp: X509_OBJECT = x509_object_st {
        type_0: 0,
        data: C2RustUnnamed_1 {
            ptr: 0 as *mut libc::c_char,
        },
    };
    let mut x509_s: X509 = x509_st {
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
    };
    let mut cinf_s: X509_CINF = X509_CINF {
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
    };
    let mut crl_s: X509_CRL = X509_crl_st {
        crl: 0 as *mut X509_CRL_INFO,
        sig_alg: 0 as *mut X509_ALGOR,
        signature: 0 as *mut ASN1_BIT_STRING,
        references: 0,
        flags: 0,
        akid: 0 as *mut AUTHORITY_KEYID,
        idp: 0 as *mut ISSUING_DIST_POINT,
        idp_flags: 0,
        crl_hash: [0; 32],
    };
    let mut crl_info_s: X509_CRL_INFO = X509_CRL_INFO {
        version: 0 as *mut ASN1_INTEGER,
        sig_alg: 0 as *mut X509_ALGOR,
        issuer: 0 as *mut X509_NAME,
        lastUpdate: 0 as *mut ASN1_TIME,
        nextUpdate: 0 as *mut ASN1_TIME,
        revoked: 0 as *mut stack_st_X509_REVOKED,
        extensions: 0 as *mut stack_st_X509_EXTENSION,
        enc: ASN1_ENCODING_st {
            enc: 0 as *mut libc::c_uchar,
            len: 0,
            alias_only_alias_only_on_next_parse: [0; 1],
            c2rust_padding: [0; 7],
        },
    };
    stmp.type_0 = type_0;
    match type_0 {
        1 => {
            stmp.data.x509 = &mut x509_s;
            x509_s.cert_info = &mut cinf_s;
            cinf_s.subject = name;
        }
        2 => {
            stmp.data.crl = &mut crl_s;
            crl_s.crl = &mut crl_info_s;
            crl_info_s.issuer = name;
        }
        _ => return -(1 as libc::c_int),
    }
    let mut idx: size_t = 0;
    sk_X509_OBJECT_sort(h);
    if sk_X509_OBJECT_find_awslc(h, &mut idx, &mut stmp) == 0 {
        return -(1 as libc::c_int);
    }
    if !pnmatch.is_null() {
        *pnmatch = 1 as libc::c_int;
        let mut tidx: size_t = idx.wrapping_add(1 as libc::c_int as size_t);
        while tidx < sk_X509_OBJECT_num(h) {
            let mut tobj: *const X509_OBJECT = sk_X509_OBJECT_value(h, tidx);
            if x509_object_cmp(tobj, &mut stmp) != 0 {
                break;
            }
            *pnmatch += 1;
            *pnmatch;
            tidx = tidx.wrapping_add(1);
            tidx;
        }
    }
    return idx as libc::c_int;
}
unsafe extern "C" fn X509_OBJECT_idx_by_subject(
    mut h: *mut stack_st_X509_OBJECT,
    mut type_0: libc::c_int,
    mut name: *mut X509_NAME,
) -> libc::c_int {
    return x509_object_idx_cnt(h, type_0, name, 0 as *mut libc::c_int);
}
unsafe extern "C" fn X509_OBJECT_retrieve_by_subject(
    mut h: *mut stack_st_X509_OBJECT,
    mut type_0: libc::c_int,
    mut name: *mut X509_NAME,
) -> *mut X509_OBJECT {
    let mut idx: libc::c_int = 0;
    idx = X509_OBJECT_idx_by_subject(h, type_0, name);
    if idx == -(1 as libc::c_int) {
        return 0 as *mut X509_OBJECT;
    }
    return sk_X509_OBJECT_value(h, idx as size_t);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_get0_objects(
    mut st: *mut X509_STORE,
) -> *mut stack_st_X509_OBJECT {
    return (*st).objs;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_CTX_get1_certs(
    mut ctx: *mut X509_STORE_CTX,
    mut nm: *mut X509_NAME,
) -> *mut stack_st_X509 {
    let mut cnt: libc::c_int = 0;
    let mut sk: *mut stack_st_X509 = sk_X509_new_null();
    if sk.is_null() {
        return 0 as *mut stack_st_X509;
    }
    CRYPTO_MUTEX_lock_write(&mut (*(*ctx).ctx).objs_lock);
    let mut idx: libc::c_int = x509_object_idx_cnt(
        (*(*ctx).ctx).objs,
        1 as libc::c_int,
        nm,
        &mut cnt,
    );
    if idx < 0 as libc::c_int {
        let mut xobj: X509_OBJECT = x509_object_st {
            type_0: 0,
            data: C2RustUnnamed_1 {
                ptr: 0 as *mut libc::c_char,
            },
        };
        CRYPTO_MUTEX_unlock_write(&mut (*(*ctx).ctx).objs_lock);
        if X509_STORE_CTX_get_by_subject(ctx, 1 as libc::c_int, nm, &mut xobj) == 0 {
            sk_X509_free(sk);
            return 0 as *mut stack_st_X509;
        }
        X509_OBJECT_free_contents(&mut xobj);
        CRYPTO_MUTEX_lock_write(&mut (*(*ctx).ctx).objs_lock);
        idx = x509_object_idx_cnt((*(*ctx).ctx).objs, 1 as libc::c_int, nm, &mut cnt);
        if idx < 0 as libc::c_int {
            CRYPTO_MUTEX_unlock_write(&mut (*(*ctx).ctx).objs_lock);
            sk_X509_free(sk);
            return 0 as *mut stack_st_X509;
        }
    }
    let mut i: libc::c_int = 0 as libc::c_int;
    while i < cnt {
        let mut obj: *mut X509_OBJECT = sk_X509_OBJECT_value(
            (*(*ctx).ctx).objs,
            idx as size_t,
        );
        let mut x: *mut X509 = (*obj).data.x509;
        if sk_X509_push(sk, x) == 0 {
            CRYPTO_MUTEX_unlock_write(&mut (*(*ctx).ctx).objs_lock);
            sk_X509_pop_free(
                sk,
                Some(X509_free as unsafe extern "C" fn(*mut X509) -> ()),
            );
            return 0 as *mut stack_st_X509;
        }
        X509_up_ref(x);
        i += 1;
        i;
        idx += 1;
        idx;
    }
    CRYPTO_MUTEX_unlock_write(&mut (*(*ctx).ctx).objs_lock);
    return sk;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_CTX_get1_crls(
    mut ctx: *mut X509_STORE_CTX,
    mut nm: *mut X509_NAME,
) -> *mut stack_st_X509_CRL {
    let mut cnt: libc::c_int = 0;
    let mut xobj: X509_OBJECT = x509_object_st {
        type_0: 0,
        data: C2RustUnnamed_1 {
            ptr: 0 as *mut libc::c_char,
        },
    };
    let mut sk: *mut stack_st_X509_CRL = sk_X509_CRL_new_null();
    if sk.is_null() {
        return 0 as *mut stack_st_X509_CRL;
    }
    if X509_STORE_CTX_get_by_subject(ctx, 2 as libc::c_int, nm, &mut xobj) == 0 {
        sk_X509_CRL_free(sk);
        return 0 as *mut stack_st_X509_CRL;
    }
    X509_OBJECT_free_contents(&mut xobj);
    CRYPTO_MUTEX_lock_write(&mut (*(*ctx).ctx).objs_lock);
    let mut idx: libc::c_int = x509_object_idx_cnt(
        (*(*ctx).ctx).objs,
        2 as libc::c_int,
        nm,
        &mut cnt,
    );
    if idx < 0 as libc::c_int {
        CRYPTO_MUTEX_unlock_write(&mut (*(*ctx).ctx).objs_lock);
        sk_X509_CRL_free(sk);
        return 0 as *mut stack_st_X509_CRL;
    }
    let mut i: libc::c_int = 0 as libc::c_int;
    while i < cnt {
        let mut obj: *mut X509_OBJECT = sk_X509_OBJECT_value(
            (*(*ctx).ctx).objs,
            idx as size_t,
        );
        let mut x: *mut X509_CRL = (*obj).data.crl;
        X509_CRL_up_ref(x);
        if sk_X509_CRL_push(sk, x) == 0 {
            CRYPTO_MUTEX_unlock_write(&mut (*(*ctx).ctx).objs_lock);
            X509_CRL_free(x);
            sk_X509_CRL_pop_free(
                sk,
                Some(X509_CRL_free as unsafe extern "C" fn(*mut X509_CRL) -> ()),
            );
            return 0 as *mut stack_st_X509_CRL;
        }
        i += 1;
        i;
        idx += 1;
        idx;
    }
    CRYPTO_MUTEX_unlock_write(&mut (*(*ctx).ctx).objs_lock);
    return sk;
}
unsafe extern "C" fn X509_OBJECT_retrieve_match(
    mut h: *mut stack_st_X509_OBJECT,
    mut x: *mut X509_OBJECT,
) -> *mut X509_OBJECT {
    sk_X509_OBJECT_sort(h);
    let mut idx: size_t = 0;
    if sk_X509_OBJECT_find_awslc(h, &mut idx, x) == 0 {
        return 0 as *mut X509_OBJECT;
    }
    if (*x).type_0 != 1 as libc::c_int && (*x).type_0 != 2 as libc::c_int {
        return sk_X509_OBJECT_value(h, idx);
    }
    let mut i: size_t = idx;
    while i < sk_X509_OBJECT_num(h) {
        let mut obj: *mut X509_OBJECT = sk_X509_OBJECT_value(h, i);
        if x509_object_cmp(obj, x) != 0 {
            return 0 as *mut X509_OBJECT;
        }
        if (*x).type_0 == 1 as libc::c_int {
            if X509_cmp((*obj).data.x509, (*x).data.x509) == 0 {
                return obj;
            }
        } else if (*x).type_0 == 2 as libc::c_int {
            if X509_CRL_match((*obj).data.crl, (*x).data.crl) == 0 {
                return obj;
            }
        } else {
            return obj
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as *mut X509_OBJECT;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_CTX_get1_issuer(
    mut issuer: *mut *mut X509,
    mut ctx: *mut X509_STORE_CTX,
    mut x: *mut X509,
) -> libc::c_int {
    let mut xn: *mut X509_NAME = 0 as *mut X509_NAME;
    let mut obj: X509_OBJECT = x509_object_st {
        type_0: 0,
        data: C2RustUnnamed_1 {
            ptr: 0 as *mut libc::c_char,
        },
    };
    let mut pobj: *mut X509_OBJECT = 0 as *mut X509_OBJECT;
    let mut idx: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    let mut i: size_t = 0;
    *issuer = 0 as *mut X509;
    xn = X509_get_issuer_name(x);
    if X509_STORE_CTX_get_by_subject(ctx, 1 as libc::c_int, xn, &mut obj) == 0 {
        return 0 as libc::c_int;
    }
    if x509_check_issued_with_callback(ctx, x, obj.data.x509) != 0 {
        if x509_check_cert_time(ctx, obj.data.x509, 1 as libc::c_int) != 0 {
            *issuer = obj.data.x509;
            return 1 as libc::c_int;
        }
    }
    X509_OBJECT_free_contents(&mut obj);
    ret = 0 as libc::c_int;
    CRYPTO_MUTEX_lock_write(&mut (*(*ctx).ctx).objs_lock);
    idx = X509_OBJECT_idx_by_subject((*(*ctx).ctx).objs, 1 as libc::c_int, xn);
    if idx != -(1 as libc::c_int) {
        i = idx as size_t;
        while i < sk_X509_OBJECT_num((*(*ctx).ctx).objs) {
            pobj = sk_X509_OBJECT_value((*(*ctx).ctx).objs, i);
            if (*pobj).type_0 != 1 as libc::c_int {
                break;
            }
            if X509_NAME_cmp(xn, X509_get_subject_name((*pobj).data.x509)) != 0 {
                break;
            }
            if x509_check_issued_with_callback(ctx, x, (*pobj).data.x509) != 0 {
                *issuer = (*pobj).data.x509;
                ret = 1 as libc::c_int;
                if x509_check_cert_time(ctx, *issuer, 1 as libc::c_int) != 0 {
                    break;
                }
            }
            i = i.wrapping_add(1);
            i;
        }
    }
    CRYPTO_MUTEX_unlock_write(&mut (*(*ctx).ctx).objs_lock);
    if !(*issuer).is_null() {
        X509_up_ref(*issuer);
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_set_flags(
    mut ctx: *mut X509_STORE,
    mut flags: libc::c_ulong,
) -> libc::c_int {
    return X509_VERIFY_PARAM_set_flags((*ctx).param, flags);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_set_depth(
    mut ctx: *mut X509_STORE,
    mut depth: libc::c_int,
) -> libc::c_int {
    X509_VERIFY_PARAM_set_depth((*ctx).param, depth);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_set_purpose(
    mut ctx: *mut X509_STORE,
    mut purpose: libc::c_int,
) -> libc::c_int {
    return X509_VERIFY_PARAM_set_purpose((*ctx).param, purpose);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_set_trust(
    mut ctx: *mut X509_STORE,
    mut trust: libc::c_int,
) -> libc::c_int {
    return X509_VERIFY_PARAM_set_trust((*ctx).param, trust);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_set1_param(
    mut ctx: *mut X509_STORE,
    mut param: *const X509_VERIFY_PARAM,
) -> libc::c_int {
    return X509_VERIFY_PARAM_set1((*ctx).param, param);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_get0_param(
    mut ctx: *mut X509_STORE,
) -> *mut X509_VERIFY_PARAM {
    return (*ctx).param;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_set_verify_cb(
    mut ctx: *mut X509_STORE,
    mut verify_cb: X509_STORE_CTX_verify_cb,
) {
    (*ctx).verify_cb = verify_cb;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_set_get_crl(
    mut ctx: *mut X509_STORE,
    mut get_crl: X509_STORE_CTX_get_crl_fn,
) {
    (*ctx).get_crl = get_crl;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_set_check_crl(
    mut ctx: *mut X509_STORE,
    mut check_crl: X509_STORE_CTX_check_crl_fn,
) {
    (*ctx).check_crl = check_crl;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_CTX_get0_store(
    mut ctx: *mut X509_STORE_CTX,
) -> *mut X509_STORE {
    return (*ctx).ctx;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_get_ex_new_index(
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_set_ex_data(
    mut ctx: *mut X509_STORE,
    mut idx: libc::c_int,
    mut data: *mut libc::c_void,
) -> libc::c_int {
    return CRYPTO_set_ex_data(&mut (*ctx).ex_data, idx, data);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_STORE_get_ex_data(
    mut ctx: *mut X509_STORE,
    mut idx: libc::c_int,
) -> *mut libc::c_void {
    return CRYPTO_get_ex_data(&mut (*ctx).ex_data, idx);
}
