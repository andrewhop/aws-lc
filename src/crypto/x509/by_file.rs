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
    pub type evp_cipher_st;
    pub type crypto_buffer_st;
    pub type stack_st_DIST_POINT;
    pub type stack_st_void;
    pub type stack_st_X509_CRL;
    pub type stack_st_X509;
    pub type stack_st_X509_LOOKUP;
    pub type stack_st_X509_OBJECT;
    pub type stack_st;
    pub type stack_st_X509_INFO;
    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;
    fn X509_free(x509: *mut X509);
    fn X509_CRL_free(crl: *mut X509_CRL);
    fn X509_STORE_add_cert(store: *mut X509_STORE, x509: *mut X509) -> libc::c_int;
    fn X509_STORE_add_crl(store: *mut X509_STORE, crl: *mut X509_CRL) -> libc::c_int;
    fn X509_LOOKUP_ctrl(
        lookup: *mut X509_LOOKUP,
        cmd: libc::c_int,
        argc: *const libc::c_char,
        argl: libc::c_long,
        ret: *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn X509_get_default_cert_file() -> *const libc::c_char;
    fn X509_get_default_cert_file_env() -> *const libc::c_char;
    fn d2i_X509_bio(bp: *mut BIO, x509: *mut *mut X509) -> *mut X509;
    fn d2i_X509_CRL_bio(bp: *mut BIO, crl: *mut *mut X509_CRL) -> *mut X509_CRL;
    fn X509_INFO_free(info: *mut X509_INFO);
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_pop_free_ex(
        sk: *mut OPENSSL_STACK,
        call_free_func: OPENSSL_sk_call_free_func,
        free_func: OPENSSL_sk_free_func,
    );
    fn BIO_new(method: *const BIO_METHOD) -> *mut BIO;
    fn BIO_free(bio: *mut BIO) -> libc::c_int;
    fn BIO_s_file() -> *const BIO_METHOD;
    fn BIO_new_file(
        filename: *const libc::c_char,
        mode: *const libc::c_char,
    ) -> *mut BIO;
    fn BIO_read_filename(bio: *mut BIO, filename: *const libc::c_char) -> libc::c_int;
    fn ERR_peek_last_error() -> uint32_t;
    fn ERR_clear_error();
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn PEM_X509_INFO_read_bio(
        bp: *mut BIO,
        sk: *mut stack_st_X509_INFO,
        cb: Option::<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> *mut stack_st_X509_INFO;
    fn PEM_read_bio_X509_AUX(
        bp: *mut BIO,
        x: *mut *mut X509,
        cb: Option::<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> *mut X509;
    fn PEM_read_bio_X509_CRL(
        bp: *mut BIO,
        x: *mut *mut X509_CRL,
        cb: Option::<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> *mut X509_CRL;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type int64_t = __int64_t;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_info_st {
    pub x509: *mut X509,
    pub crl: *mut X509_CRL,
    pub x_pkey: *mut X509_PKEY,
    pub enc_cipher: EVP_CIPHER_INFO,
    pub enc_len: libc::c_int,
    pub enc_data: *mut libc::c_char,
}
pub type EVP_CIPHER_INFO = evp_cipher_info_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_cipher_info_st {
    pub cipher: *const EVP_CIPHER,
    pub iv: [libc::c_uchar; 16],
}
pub type EVP_CIPHER = evp_cipher_st;
pub type X509_PKEY = private_key_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct private_key_st {
    pub dec_pkey: *mut EVP_PKEY,
}
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
pub type X509_INFO = X509_info_st;
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
pub type OPENSSL_sk_call_free_func = Option::<
    unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
>;
pub type OPENSSL_STACK = stack_st;
pub type sk_X509_INFO_free_func = Option::<unsafe extern "C" fn(*mut X509_INFO) -> ()>;
pub type pem_password_cb = unsafe extern "C" fn(
    *mut libc::c_char,
    libc::c_int,
    libc::c_int,
    *mut libc::c_void,
) -> libc::c_int;
#[inline]
unsafe extern "C" fn sk_X509_INFO_pop_free(
    mut sk: *mut stack_st_X509_INFO,
    mut free_func: sk_X509_INFO_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_X509_INFO_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<sk_X509_INFO_free_func, OPENSSL_sk_free_func>(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_X509_INFO_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<OPENSSL_sk_free_func, sk_X509_INFO_free_func>(free_func))
        .expect("non-null function pointer")(ptr as *mut X509_INFO);
}
#[inline]
unsafe extern "C" fn sk_X509_INFO_value(
    mut sk: *const stack_st_X509_INFO,
    mut i: size_t,
) -> *mut X509_INFO {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509_INFO;
}
#[inline]
unsafe extern "C" fn sk_X509_INFO_num(mut sk: *const stack_st_X509_INFO) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn ERR_GET_LIB(mut packed_error: uint32_t) -> libc::c_int {
    return (packed_error >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as libc::c_int;
}
#[inline]
unsafe extern "C" fn ERR_GET_REASON(mut packed_error: uint32_t) -> libc::c_int {
    return (packed_error & 0xfff as libc::c_int as uint32_t) as libc::c_int;
}
static mut x509_file_lookup: X509_LOOKUP_METHOD = unsafe {
    {
        let mut init = x509_lookup_method_st {
            new_item: None,
            free: None,
            ctrl: Some(
                by_file_ctrl
                    as unsafe extern "C" fn(
                        *mut X509_LOOKUP,
                        libc::c_int,
                        *const libc::c_char,
                        libc::c_long,
                        *mut *mut libc::c_char,
                    ) -> libc::c_int,
            ),
            get_by_subject: None,
        };
        init
    }
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_LOOKUP_file() -> *const X509_LOOKUP_METHOD {
    return &x509_file_lookup;
}
unsafe extern "C" fn by_file_ctrl(
    mut ctx: *mut X509_LOOKUP,
    mut cmd: libc::c_int,
    mut argp: *const libc::c_char,
    mut argl: libc::c_long,
    mut ret: *mut *mut libc::c_char,
) -> libc::c_int {
    if cmd != 1 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut file: *const libc::c_char = argp;
    let mut type_0: libc::c_int = argl as libc::c_int;
    if argl == 3 as libc::c_int as libc::c_long {
        file = getenv(X509_get_default_cert_file_env());
        if file.is_null() {
            file = X509_get_default_cert_file();
        }
        type_0 = 1 as libc::c_int;
    }
    if X509_load_cert_crl_file(ctx, file, type_0) != 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    if argl == 3 as libc::c_int as libc::c_long {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            118 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/by_file.c\0" as *const u8
                as *const libc::c_char,
            94 as libc::c_int as libc::c_uint,
        );
    }
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_load_cert_file(
    mut ctx: *mut X509_LOOKUP,
    mut file: *const libc::c_char,
    mut type_0: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut in_0: *mut BIO = 0 as *mut BIO;
    let mut i: libc::c_int = 0;
    let mut count: libc::c_int = 0 as libc::c_int;
    let mut x: *mut X509 = 0 as *mut X509;
    in_0 = BIO_new(BIO_s_file());
    if in_0.is_null() || BIO_read_filename(in_0, file) <= 0 as libc::c_int {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/by_file.c\0" as *const u8
                as *const libc::c_char,
            108 as libc::c_int as libc::c_uint,
        );
    } else {
        if type_0 == 1 as libc::c_int {
            loop {
                x = PEM_read_bio_X509_AUX(
                    in_0,
                    0 as *mut *mut X509,
                    None,
                    0 as *mut libc::c_void,
                );
                if x.is_null() {
                    let mut error: uint32_t = ERR_peek_last_error();
                    if ERR_GET_LIB(error) == 9 as libc::c_int
                        && ERR_GET_REASON(error) == 110 as libc::c_int
                        && count > 0 as libc::c_int
                    {
                        ERR_clear_error();
                        current_block = 17407779659766490442;
                        break;
                    } else {
                        ERR_put_error(
                            11 as libc::c_int,
                            0 as libc::c_int,
                            9 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/by_file.c\0"
                                as *const u8 as *const libc::c_char,
                            122 as libc::c_int as libc::c_uint,
                        );
                        current_block = 14553428118505794742;
                        break;
                    }
                } else {
                    i = X509_STORE_add_cert((*ctx).store_ctx, x);
                    if i == 0 {
                        current_block = 14553428118505794742;
                        break;
                    }
                    count += 1;
                    count;
                    X509_free(x);
                    x = 0 as *mut X509;
                }
            }
            match current_block {
                14553428118505794742 => {}
                _ => {
                    ret = count;
                    current_block = 15768484401365413375;
                }
            }
        } else if type_0 == 2 as libc::c_int {
            x = d2i_X509_bio(in_0, 0 as *mut *mut X509);
            if x.is_null() {
                ERR_put_error(
                    11 as libc::c_int,
                    0 as libc::c_int,
                    12 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/by_file.c\0"
                        as *const u8 as *const libc::c_char,
                    137 as libc::c_int as libc::c_uint,
                );
                current_block = 14553428118505794742;
            } else {
                i = X509_STORE_add_cert((*ctx).store_ctx, x);
                if i == 0 {
                    current_block = 14553428118505794742;
                } else {
                    ret = i;
                    current_block = 15768484401365413375;
                }
            }
        } else {
            ERR_put_error(
                11 as libc::c_int,
                0 as libc::c_int,
                102 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/by_file.c\0" as *const u8
                    as *const libc::c_char,
                146 as libc::c_int as libc::c_uint,
            );
            current_block = 14553428118505794742;
        }
        match current_block {
            14553428118505794742 => {}
            _ => {
                if ret == 0 as libc::c_int {
                    ERR_put_error(
                        11 as libc::c_int,
                        0 as libc::c_int,
                        141 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/by_file.c\0"
                            as *const u8 as *const libc::c_char,
                        151 as libc::c_int as libc::c_uint,
                    );
                }
            }
        }
    }
    X509_free(x);
    BIO_free(in_0);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_load_crl_file(
    mut ctx: *mut X509_LOOKUP,
    mut file: *const libc::c_char,
    mut type_0: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut in_0: *mut BIO = 0 as *mut BIO;
    let mut i: libc::c_int = 0;
    let mut count: libc::c_int = 0 as libc::c_int;
    let mut x: *mut X509_CRL = 0 as *mut X509_CRL;
    in_0 = BIO_new(BIO_s_file());
    if in_0.is_null() || BIO_read_filename(in_0, file) <= 0 as libc::c_int {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/by_file.c\0" as *const u8
                as *const libc::c_char,
            169 as libc::c_int as libc::c_uint,
        );
    } else {
        if type_0 == 1 as libc::c_int {
            loop {
                x = PEM_read_bio_X509_CRL(
                    in_0,
                    0 as *mut *mut X509_CRL,
                    None,
                    0 as *mut libc::c_void,
                );
                if x.is_null() {
                    let mut error: uint32_t = ERR_peek_last_error();
                    if ERR_GET_LIB(error) == 9 as libc::c_int
                        && ERR_GET_REASON(error) == 110 as libc::c_int
                        && count > 0 as libc::c_int
                    {
                        ERR_clear_error();
                        current_block = 17407779659766490442;
                        break;
                    } else {
                        ERR_put_error(
                            11 as libc::c_int,
                            0 as libc::c_int,
                            9 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/by_file.c\0"
                                as *const u8 as *const libc::c_char,
                            183 as libc::c_int as libc::c_uint,
                        );
                        current_block = 11632942497881377693;
                        break;
                    }
                } else {
                    i = X509_STORE_add_crl((*ctx).store_ctx, x);
                    if i == 0 {
                        current_block = 11632942497881377693;
                        break;
                    }
                    count += 1;
                    count;
                    X509_CRL_free(x);
                    x = 0 as *mut X509_CRL;
                }
            }
            match current_block {
                11632942497881377693 => {}
                _ => {
                    ret = count;
                    current_block = 15768484401365413375;
                }
            }
        } else if type_0 == 2 as libc::c_int {
            x = d2i_X509_CRL_bio(in_0, 0 as *mut *mut X509_CRL);
            if x.is_null() {
                ERR_put_error(
                    11 as libc::c_int,
                    0 as libc::c_int,
                    12 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/by_file.c\0"
                        as *const u8 as *const libc::c_char,
                    198 as libc::c_int as libc::c_uint,
                );
                current_block = 11632942497881377693;
            } else {
                i = X509_STORE_add_crl((*ctx).store_ctx, x);
                if i == 0 {
                    current_block = 11632942497881377693;
                } else {
                    ret = i;
                    current_block = 15768484401365413375;
                }
            }
        } else {
            ERR_put_error(
                11 as libc::c_int,
                0 as libc::c_int,
                102 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/by_file.c\0" as *const u8
                    as *const libc::c_char,
                207 as libc::c_int as libc::c_uint,
            );
            current_block = 11632942497881377693;
        }
        match current_block {
            11632942497881377693 => {}
            _ => {
                if ret == 0 as libc::c_int {
                    ERR_put_error(
                        11 as libc::c_int,
                        0 as libc::c_int,
                        143 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/by_file.c\0"
                            as *const u8 as *const libc::c_char,
                        212 as libc::c_int as libc::c_uint,
                    );
                }
            }
        }
    }
    X509_CRL_free(x);
    BIO_free(in_0);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_load_cert_crl_file(
    mut ctx: *mut X509_LOOKUP,
    mut file: *const libc::c_char,
    mut type_0: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut inf: *mut stack_st_X509_INFO = 0 as *mut stack_st_X509_INFO;
    let mut itmp: *mut X509_INFO = 0 as *mut X509_INFO;
    let mut in_0: *mut BIO = 0 as *mut BIO;
    let mut i: size_t = 0;
    let mut count: libc::c_int = 0 as libc::c_int;
    if type_0 != 1 as libc::c_int {
        return X509_load_cert_file(ctx, file, type_0);
    }
    in_0 = BIO_new_file(file, b"rb\0" as *const u8 as *const libc::c_char);
    if in_0.is_null() {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/by_file.c\0" as *const u8
                as *const libc::c_char,
            233 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    inf = PEM_X509_INFO_read_bio(
        in_0,
        0 as *mut stack_st_X509_INFO,
        None,
        0 as *mut libc::c_void,
    );
    BIO_free(in_0);
    if inf.is_null() {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            9 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/by_file.c\0" as *const u8
                as *const libc::c_char,
            239 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    i = 0 as libc::c_int as size_t;
    loop {
        if !(i < sk_X509_INFO_num(inf)) {
            current_block = 12147880666119273379;
            break;
        }
        itmp = sk_X509_INFO_value(inf, i);
        if !((*itmp).x509).is_null() {
            if X509_STORE_add_cert((*ctx).store_ctx, (*itmp).x509) == 0 {
                current_block = 928953504504528572;
                break;
            }
            count += 1;
            count;
        }
        if !((*itmp).crl).is_null() {
            if X509_STORE_add_crl((*ctx).store_ctx, (*itmp).crl) == 0 {
                current_block = 928953504504528572;
                break;
            }
            count += 1;
            count;
        }
        i = i.wrapping_add(1);
        i;
    }
    match current_block {
        12147880666119273379 => {
            if count == 0 as libc::c_int {
                ERR_put_error(
                    11 as libc::c_int,
                    0 as libc::c_int,
                    142 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/by_file.c\0"
                        as *const u8 as *const libc::c_char,
                    259 as libc::c_int as libc::c_uint,
                );
            }
        }
        _ => {}
    }
    sk_X509_INFO_pop_free(
        inf,
        Some(X509_INFO_free as unsafe extern "C" fn(*mut X509_INFO) -> ()),
    );
    return count;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_LOOKUP_load_file(
    mut lookup: *mut X509_LOOKUP,
    mut name: *const libc::c_char,
    mut type_0: libc::c_int,
) -> libc::c_int {
    return X509_LOOKUP_ctrl(
        lookup,
        1 as libc::c_int,
        name,
        type_0 as libc::c_long,
        0 as *mut *mut libc::c_char,
    );
}
