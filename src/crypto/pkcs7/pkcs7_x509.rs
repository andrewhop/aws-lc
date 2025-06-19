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
    pub type ASN1_ITEM_st;
    pub type asn1_object_st;
    pub type ASN1_VALUE_st;
    pub type X509_name_st;
    pub type X509_crl_st;
    pub type evp_cipher_st;
    pub type evp_pkey_st;
    pub type x509_st;
    pub type stack_st_void;
    pub type crypto_buffer_pool_st;
    pub type crypto_buffer_st;
    pub type engine_st;
    pub type evp_md_pctx_ops;
    pub type evp_pkey_ctx_st;
    pub type env_md_st;
    pub type stack_st_PKCS7_SIGNER_INFO;
    pub type stack_st_X509_CRL;
    pub type stack_st_X509;
    pub type stack_st_X509_ALGOR;
    pub type stack_st_PKCS7_RECIP_INFO;
    pub type stack_st_X509_ATTRIBUTE;
    pub type stack_st;
    pub type stack_st_CRYPTO_BUFFER;
    fn ASN1_item_i2d_bio(
        it: *const ASN1_ITEM,
        out: *mut BIO,
        in_0: *mut libc::c_void,
    ) -> libc::c_int;
    fn ASN1_OCTET_STRING_free(str: *mut ASN1_OCTET_STRING);
    fn i2d_ASN1_INTEGER(
        in_0: *const ASN1_INTEGER,
        outp: *mut *mut uint8_t,
    ) -> libc::c_int;
    fn X509_up_ref(x509: *mut X509) -> libc::c_int;
    fn X509_free(x509: *mut X509);
    fn X509_parse_from_buffer(buf: *mut CRYPTO_BUFFER) -> *mut X509;
    fn i2d_X509(x509: *mut X509, outp: *mut *mut uint8_t) -> libc::c_int;
    fn X509_get0_serialNumber(x509: *const X509) -> *const ASN1_INTEGER;
    fn X509_get_subject_name(x509: *const X509) -> *mut X509_NAME;
    fn X509_check_private_key(x509: *const X509, pkey: *const EVP_PKEY) -> libc::c_int;
    fn X509_CRL_up_ref(crl: *mut X509_CRL) -> libc::c_int;
    fn X509_CRL_free(crl: *mut X509_CRL);
    fn d2i_X509_CRL(
        out: *mut *mut X509_CRL,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut X509_CRL;
    fn i2d_X509_CRL(crl: *mut X509_CRL, outp: *mut *mut uint8_t) -> libc::c_int;
    fn i2d_X509_NAME(in_0: *mut X509_NAME, outp: *mut *mut uint8_t) -> libc::c_int;
    fn BIO_read(bio: *mut BIO, data: *mut libc::c_void, len: libc::c_int) -> libc::c_int;
    fn BIO_read_asn1(
        bio: *mut BIO,
        out: *mut *mut uint8_t,
        out_len: *mut size_t,
        max_len: size_t,
    ) -> libc::c_int;
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_pop_free_ex(
        sk: *mut OPENSSL_STACK,
        call_free_func: OPENSSL_sk_call_free_func,
        free_func: OPENSSL_sk_free_func,
    );
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn OPENSSL_sk_pop(sk: *mut OPENSSL_STACK) -> *mut libc::c_void;
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_get_asn1_element(
        cbs: *mut CBS,
        out: *mut CBS,
        tag_value: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBS_get_optional_asn1(
        cbs: *mut CBS,
        out: *mut CBS,
        out_present: *mut libc::c_int,
        tag: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBB_init(cbb: *mut CBB, initial_capacity: size_t) -> libc::c_int;
    fn CBB_cleanup(cbb: *mut CBB);
    fn CBB_finish(
        cbb: *mut CBB,
        out_data: *mut *mut uint8_t,
        out_len: *mut size_t,
    ) -> libc::c_int;
    fn CBB_flush(cbb: *mut CBB) -> libc::c_int;
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
    fn CBB_add_asn1_uint64(cbb: *mut CBB, value: uint64_t) -> libc::c_int;
    fn CBB_flush_asn1_set_of(cbb: *mut CBB) -> libc::c_int;
    fn EVP_sha256() -> *const EVP_MD;
    fn EVP_MD_CTX_init(ctx: *mut EVP_MD_CTX);
    fn EVP_MD_CTX_cleanup(ctx: *mut EVP_MD_CTX) -> libc::c_int;
    fn pkcs7_parse_header(
        der_bytes: *mut *mut uint8_t,
        out: *mut CBS,
        cbs: *mut CBS,
    ) -> libc::c_int;
    fn pkcs7_add_signed_data(
        out: *mut CBB,
        digest_algos_cb: Option::<
            unsafe extern "C" fn(*mut CBB, *const libc::c_void) -> libc::c_int,
        >,
        cert_crl_cb: Option::<
            unsafe extern "C" fn(*mut CBB, *const libc::c_void) -> libc::c_int,
        >,
        signer_infos_cb: Option::<
            unsafe extern "C" fn(*mut CBB, *const libc::c_void) -> libc::c_int,
        >,
        arg: *const libc::c_void,
    ) -> libc::c_int;
    fn pkcs7_final(p7: *mut PKCS7, data: *mut BIO) -> libc::c_int;
    fn PKCS7_get_raw_certificates(
        out_certs: *mut stack_st_CRYPTO_BUFFER,
        cbs: *mut CBS,
        pool: *mut CRYPTO_BUFFER_POOL,
    ) -> libc::c_int;
    fn d2i_PKCS7(
        a: *mut *mut PKCS7,
        in_0: *mut *const libc::c_uchar,
        len: libc::c_long,
    ) -> *mut PKCS7;
    static PKCS7_it: ASN1_ITEM;
    fn PKCS7_new() -> *mut PKCS7;
    fn PKCS7_free(a: *mut PKCS7);
    fn PKCS7_SIGNER_INFO_new() -> *mut PKCS7_SIGNER_INFO;
    fn PKCS7_SIGNER_INFO_free(a: *mut PKCS7_SIGNER_INFO);
    fn PKCS7_SIGNER_INFO_set(
        p7i: *mut PKCS7_SIGNER_INFO,
        x509: *mut X509,
        pkey: *mut EVP_PKEY,
        dgst: *const EVP_MD,
    ) -> libc::c_int;
    fn PKCS7_add_signer(p7: *mut PKCS7, p7i: *mut PKCS7_SIGNER_INFO) -> libc::c_int;
    fn PKCS7_content_new(p7: *mut PKCS7, nid: libc::c_int) -> libc::c_int;
    fn PKCS7_set_type(p7: *mut PKCS7, type_0: libc::c_int) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn OBJ_obj2nid(obj: *const ASN1_OBJECT) -> libc::c_int;
    fn OBJ_nid2cbb(out: *mut CBB, nid: libc::c_int) -> libc::c_int;
    fn EVP_PKEY_size(pkey: *const EVP_PKEY) -> libc::c_int;
    fn EVP_PKEY_id(pkey: *const EVP_PKEY) -> libc::c_int;
    fn EVP_DigestSignInit(
        ctx: *mut EVP_MD_CTX,
        pctx: *mut *mut EVP_PKEY_CTX,
        type_0: *const EVP_MD,
        e: *mut ENGINE,
        pkey: *mut EVP_PKEY,
    ) -> libc::c_int;
    fn EVP_DigestSignUpdate(
        ctx: *mut EVP_MD_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn EVP_DigestSignFinal(
        ctx: *mut EVP_MD_CTX,
        out_sig: *mut uint8_t,
        out_sig_len: *mut size_t,
    ) -> libc::c_int;
    fn CRYPTO_BUFFER_free(buf: *mut CRYPTO_BUFFER);
    fn PEM_bytes_read_bio(
        pdata: *mut *mut libc::c_uchar,
        plen: *mut libc::c_long,
        pnm: *mut *mut libc::c_char,
        name: *const libc::c_char,
        bp: *mut BIO,
        cb: Option::<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type CBS_ASN1_TAG = uint32_t;
pub type ASN1_BOOLEAN = libc::c_int;
pub type ASN1_ITEM = ASN1_ITEM_st;
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
pub type X509_NAME = X509_name_st;
pub type X509_ALGOR = X509_algor_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_algor_st {
    pub algorithm: *mut ASN1_OBJECT,
    pub parameter: *mut ASN1_TYPE,
}
pub type X509_CRL = X509_crl_st;
pub type EVP_CIPHER = evp_cipher_st;
pub type EVP_PKEY = evp_pkey_st;
pub type X509 = x509_st;
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
pub type CRYPTO_refcount_t = uint32_t;
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
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
pub type BIO_METHOD = bio_method_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cbb_st {
    pub child: *mut CBB,
    pub is_child: libc::c_char,
    pub u: C2RustUnnamed_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
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
pub type CRYPTO_BUFFER_POOL = crypto_buffer_pool_st;
pub type CRYPTO_BUFFER = crypto_buffer_st;
pub type ENGINE = engine_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct env_md_ctx_st {
    pub digest: *const EVP_MD,
    pub md_data: *mut libc::c_void,
    pub update: Option::<
        unsafe extern "C" fn(*mut EVP_MD_CTX, *const libc::c_void, size_t) -> libc::c_int,
    >,
    pub pctx: *mut EVP_PKEY_CTX,
    pub pctx_ops: *const evp_md_pctx_ops,
    pub flags: libc::c_ulong,
}
pub type EVP_PKEY_CTX = evp_pkey_ctx_st;
pub type EVP_MD_CTX = env_md_ctx_st;
pub type EVP_MD = env_md_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pkcs7_digest_st {
    pub version: *mut ASN1_INTEGER,
    pub digest_alg: *mut X509_ALGOR,
    pub contents: *mut PKCS7,
    pub digest: *mut ASN1_OCTET_STRING,
    pub md: *const EVP_MD,
}
pub type PKCS7 = pkcs7_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pkcs7_st {
    pub type_0: *mut ASN1_OBJECT,
    pub d: C2RustUnnamed_1,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_1 {
    pub ptr: *mut libc::c_char,
    pub data: *mut ASN1_OCTET_STRING,
    pub sign: *mut PKCS7_SIGNED,
    pub enveloped: *mut PKCS7_ENVELOPE,
    pub signed_and_enveloped: *mut PKCS7_SIGN_ENVELOPE,
    pub digest: *mut PKCS7_DIGEST,
    pub encrypted: *mut PKCS7_ENCRYPT,
}
pub type PKCS7_ENCRYPT = pkcs7_encrypt_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pkcs7_encrypt_st {
    pub version: *mut ASN1_INTEGER,
    pub enc_data: *mut PKCS7_ENC_CONTENT,
}
pub type PKCS7_ENC_CONTENT = pkcs7_enc_content_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pkcs7_enc_content_st {
    pub content_type: *mut ASN1_OBJECT,
    pub algorithm: *mut X509_ALGOR,
    pub enc_data: *mut ASN1_OCTET_STRING,
    pub cipher: *const EVP_CIPHER,
}
pub type PKCS7_DIGEST = pkcs7_digest_st;
pub type PKCS7_SIGN_ENVELOPE = pkcs7_sign_envelope_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pkcs7_sign_envelope_st {
    pub version: *mut ASN1_INTEGER,
    pub recipientinfo: *mut stack_st_PKCS7_RECIP_INFO,
    pub md_algs: *mut stack_st_X509_ALGOR,
    pub enc_data: *mut PKCS7_ENC_CONTENT,
    pub cert: *mut stack_st_X509,
    pub crl: *mut stack_st_X509_CRL,
    pub signer_info: *mut stack_st_PKCS7_SIGNER_INFO,
}
pub type PKCS7_ENVELOPE = pkcs7_envelope_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pkcs7_envelope_st {
    pub version: *mut ASN1_INTEGER,
    pub enc_data: *mut PKCS7_ENC_CONTENT,
    pub recipientinfo: *mut stack_st_PKCS7_RECIP_INFO,
}
pub type PKCS7_SIGNED = pkcs7_signed_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pkcs7_signed_st {
    pub version: *mut ASN1_INTEGER,
    pub md_algs: *mut stack_st_X509_ALGOR,
    pub contents: *mut PKCS7,
    pub cert: *mut stack_st_X509,
    pub crl: *mut stack_st_X509_CRL,
    pub signer_info: *mut stack_st_PKCS7_SIGNER_INFO,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pkcs7_issuer_and_serial_st {
    pub issuer: *mut X509_NAME,
    pub serial: *mut ASN1_INTEGER,
}
pub type PKCS7_ISSUER_AND_SERIAL = pkcs7_issuer_and_serial_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pkcs7_signer_info_st {
    pub version: *mut ASN1_INTEGER,
    pub issuer_and_serial: *mut PKCS7_ISSUER_AND_SERIAL,
    pub digest_alg: *mut X509_ALGOR,
    pub auth_attr: *mut stack_st_X509_ATTRIBUTE,
    pub digest_enc_alg: *mut X509_ALGOR,
    pub enc_digest: *mut ASN1_OCTET_STRING,
    pub unauth_attr: *mut stack_st_X509_ATTRIBUTE,
    pub pkey: *mut EVP_PKEY,
}
pub type PKCS7_SIGNER_INFO = pkcs7_signer_info_st;
pub type OPENSSL_sk_free_func = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type OPENSSL_sk_call_free_func = Option::<
    unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
>;
pub type OPENSSL_STACK = stack_st;
pub type sk_CRYPTO_BUFFER_free_func = Option::<
    unsafe extern "C" fn(*mut CRYPTO_BUFFER) -> (),
>;
pub type pem_password_cb = unsafe extern "C" fn(
    *mut libc::c_char,
    libc::c_int,
    libc::c_int,
    *mut libc::c_void,
) -> libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct signer_info_data {
    pub sign_cert: *const X509,
    pub signature: *mut uint8_t,
    pub signature_len: size_t,
}
#[inline]
unsafe extern "C" fn sk_X509_new_null() -> *mut stack_st_X509 {
    return OPENSSL_sk_new_null() as *mut stack_st_X509;
}
#[inline]
unsafe extern "C" fn sk_X509_value(
    mut sk: *const stack_st_X509,
    mut i: size_t,
) -> *mut X509 {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509;
}
#[inline]
unsafe extern "C" fn sk_X509_pop(mut sk: *mut stack_st_X509) -> *mut X509 {
    return OPENSSL_sk_pop(sk as *mut OPENSSL_STACK) as *mut X509;
}
#[inline]
unsafe extern "C" fn sk_X509_num(mut sk: *const stack_st_X509) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_push(
    mut sk: *mut stack_st_X509,
    mut p: *mut X509,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_X509_CRL_value(
    mut sk: *const stack_st_X509_CRL,
    mut i: size_t,
) -> *mut X509_CRL {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509_CRL;
}
#[inline]
unsafe extern "C" fn sk_X509_CRL_new_null() -> *mut stack_st_X509_CRL {
    return OPENSSL_sk_new_null() as *mut stack_st_X509_CRL;
}
#[inline]
unsafe extern "C" fn sk_X509_CRL_pop(mut sk: *mut stack_st_X509_CRL) -> *mut X509_CRL {
    return OPENSSL_sk_pop(sk as *mut OPENSSL_STACK) as *mut X509_CRL;
}
#[inline]
unsafe extern "C" fn sk_X509_CRL_num(mut sk: *const stack_st_X509_CRL) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_CRL_push(
    mut sk: *mut stack_st_X509_CRL,
    mut p: *mut X509_CRL,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_CRYPTO_BUFFER_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<
        OPENSSL_sk_free_func,
        sk_CRYPTO_BUFFER_free_func,
    >(free_func))
        .expect("non-null function pointer")(ptr as *mut CRYPTO_BUFFER);
}
#[inline]
unsafe extern "C" fn sk_CRYPTO_BUFFER_num(
    mut sk: *const stack_st_CRYPTO_BUFFER,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_CRYPTO_BUFFER_value(
    mut sk: *const stack_st_CRYPTO_BUFFER,
    mut i: size_t,
) -> *mut CRYPTO_BUFFER {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut CRYPTO_BUFFER;
}
#[inline]
unsafe extern "C" fn sk_CRYPTO_BUFFER_pop_free(
    mut sk: *mut stack_st_CRYPTO_BUFFER,
    mut free_func: sk_CRYPTO_BUFFER_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_CRYPTO_BUFFER_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_CRYPTO_BUFFER_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_CRYPTO_BUFFER_new_null() -> *mut stack_st_CRYPTO_BUFFER {
    return OPENSSL_sk_new_null() as *mut stack_st_CRYPTO_BUFFER;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS7_get_certificates(
    mut out_certs: *mut stack_st_X509,
    mut cbs: *mut CBS,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let initial_certs_len: size_t = sk_X509_num(out_certs);
    let mut raw: *mut stack_st_CRYPTO_BUFFER = sk_CRYPTO_BUFFER_new_null();
    if !(raw.is_null()
        || PKCS7_get_raw_certificates(raw, cbs, 0 as *mut CRYPTO_BUFFER_POOL) == 0)
    {
        let mut i: size_t = 0 as libc::c_int as size_t;
        loop {
            if !(i < sk_CRYPTO_BUFFER_num(raw)) {
                current_block = 7815301370352969686;
                break;
            }
            let mut buf: *mut CRYPTO_BUFFER = sk_CRYPTO_BUFFER_value(raw, i);
            let mut x509: *mut X509 = X509_parse_from_buffer(buf);
            if x509.is_null() || sk_X509_push(out_certs, x509) == 0 {
                X509_free(x509);
                current_block = 16612411757188433022;
                break;
            } else {
                i = i.wrapping_add(1);
                i;
            }
        }
        match current_block {
            16612411757188433022 => {}
            _ => {
                ret = 1 as libc::c_int;
            }
        }
    }
    sk_CRYPTO_BUFFER_pop_free(
        raw,
        Some(CRYPTO_BUFFER_free as unsafe extern "C" fn(*mut CRYPTO_BUFFER) -> ()),
    );
    if ret == 0 {
        while sk_X509_num(out_certs) != initial_certs_len {
            let mut x509_0: *mut X509 = sk_X509_pop(out_certs);
            X509_free(x509_0);
        }
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS7_get_CRLs(
    mut out_crls: *mut stack_st_X509_CRL,
    mut cbs: *mut CBS,
) -> libc::c_int {
    let mut current_block: u64;
    let mut signed_data: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut crls: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut der_bytes: *mut uint8_t = 0 as *mut uint8_t;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut has_crls: libc::c_int = 0;
    let initial_crls_len: size_t = sk_X509_CRL_num(out_crls);
    if !(pkcs7_parse_header(&mut der_bytes, &mut signed_data, cbs) == 0
        || CBS_get_optional_asn1(
            &mut signed_data,
            0 as *mut CBS,
            0 as *mut libc::c_int,
            (0x80 as libc::c_uint) << 24 as libc::c_int
                | (0x20 as libc::c_uint) << 24 as libc::c_int
                | 0 as libc::c_int as libc::c_uint,
        ) == 0
        || CBS_get_optional_asn1(
            &mut signed_data,
            &mut crls,
            &mut has_crls,
            (0x80 as libc::c_uint) << 24 as libc::c_int
                | (0x20 as libc::c_uint) << 24 as libc::c_int
                | 1 as libc::c_int as libc::c_uint,
        ) == 0)
    {
        if has_crls == 0 {
            CBS_init(&mut crls, 0 as *const uint8_t, 0 as libc::c_int as size_t);
        }
        loop {
            if !(CBS_len(&mut crls) > 0 as libc::c_int as size_t) {
                current_block = 1054647088692577877;
                break;
            }
            let mut crl_data: CBS = cbs_st {
                data: 0 as *const uint8_t,
                len: 0,
            };
            let mut crl: *mut X509_CRL = 0 as *mut X509_CRL;
            let mut inp: *const uint8_t = 0 as *const uint8_t;
            if CBS_get_asn1_element(
                &mut crls,
                &mut crl_data,
                0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
            ) == 0
            {
                current_block = 366007166016629927;
                break;
            }
            if CBS_len(&mut crl_data) > 9223372036854775807 as libc::c_long as size_t {
                current_block = 366007166016629927;
                break;
            }
            inp = CBS_data(&mut crl_data);
            crl = d2i_X509_CRL(
                0 as *mut *mut X509_CRL,
                &mut inp,
                CBS_len(&mut crl_data) as libc::c_long,
            );
            if crl.is_null() {
                current_block = 366007166016629927;
                break;
            }
            if inp == (CBS_data(&mut crl_data)).offset(CBS_len(&mut crl_data) as isize)
            {} else {
                __assert_fail(
                    b"inp == CBS_data(&crl_data) + CBS_len(&crl_data)\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7_x509.c\0"
                        as *const u8 as *const libc::c_char,
                    106 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 54],
                        &[libc::c_char; 54],
                    >(b"int PKCS7_get_CRLs(struct stack_st_X509_CRL *, CBS *)\0"))
                        .as_ptr(),
                );
            }
            'c_9704: {
                if inp
                    == (CBS_data(&mut crl_data)).offset(CBS_len(&mut crl_data) as isize)
                {} else {
                    __assert_fail(
                        b"inp == CBS_data(&crl_data) + CBS_len(&crl_data)\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7_x509.c\0"
                            as *const u8 as *const libc::c_char,
                        106 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 54],
                            &[libc::c_char; 54],
                        >(b"int PKCS7_get_CRLs(struct stack_st_X509_CRL *, CBS *)\0"))
                            .as_ptr(),
                    );
                }
            };
            if !(sk_X509_CRL_push(out_crls, crl) == 0 as libc::c_int as size_t) {
                continue;
            }
            X509_CRL_free(crl);
            current_block = 366007166016629927;
            break;
        }
        match current_block {
            366007166016629927 => {}
            _ => {
                ret = 1 as libc::c_int;
            }
        }
    }
    OPENSSL_free(der_bytes as *mut libc::c_void);
    if ret == 0 {
        while sk_X509_CRL_num(out_crls) != initial_crls_len {
            X509_CRL_free(sk_X509_CRL_pop(out_crls));
        }
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS7_get_PEM_certificates(
    mut out_certs: *mut stack_st_X509,
    mut pem_bio: *mut BIO,
) -> libc::c_int {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: libc::c_long = 0;
    let mut ret: libc::c_int = 0;
    if PEM_bytes_read_bio(
        &mut data,
        &mut len,
        0 as *mut *mut libc::c_char,
        b"PKCS7\0" as *const u8 as *const libc::c_char,
        pem_bio,
        None,
        0 as *mut libc::c_void,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, data, len as size_t);
    ret = PKCS7_get_certificates(out_certs, &mut cbs);
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS7_get_PEM_CRLs(
    mut out_crls: *mut stack_st_X509_CRL,
    mut pem_bio: *mut BIO,
) -> libc::c_int {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: libc::c_long = 0;
    let mut ret: libc::c_int = 0;
    if PEM_bytes_read_bio(
        &mut data,
        &mut len,
        0 as *mut *mut libc::c_char,
        b"PKCS7\0" as *const u8 as *const libc::c_char,
        pem_bio,
        None,
        0 as *mut libc::c_void,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, data, len as size_t);
    ret = PKCS7_get_CRLs(out_crls, &mut cbs);
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn pkcs7_bundle_certificates_cb(
    mut out: *mut CBB,
    mut arg: *const libc::c_void,
) -> libc::c_int {
    let mut certs: *const stack_st_X509 = arg as *const stack_st_X509;
    let mut i: size_t = 0;
    let mut certificates: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    if CBB_add_asn1(
        out,
        &mut certificates,
        (0x80 as libc::c_uint) << 24 as libc::c_int
            | (0x20 as libc::c_uint) << 24 as libc::c_int
            | 0 as libc::c_int as libc::c_uint,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    i = 0 as libc::c_int as size_t;
    while i < sk_X509_num(certs) {
        let mut x509: *mut X509 = sk_X509_value(certs, i);
        let mut buf: *mut uint8_t = 0 as *mut uint8_t;
        let mut len: libc::c_int = i2d_X509(x509, 0 as *mut *mut uint8_t);
        if len < 0 as libc::c_int
            || CBB_add_space(&mut certificates, &mut buf, len as size_t) == 0
            || i2d_X509(x509, &mut buf) < 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return (CBB_flush_asn1_set_of(&mut certificates) != 0 && CBB_flush(out) != 0)
        as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS7_bundle_certificates(
    mut out: *mut CBB,
    mut certs: *const stack_st_X509,
) -> libc::c_int {
    return pkcs7_add_signed_data(
        out,
        None,
        Some(
            pkcs7_bundle_certificates_cb
                as unsafe extern "C" fn(*mut CBB, *const libc::c_void) -> libc::c_int,
        ),
        None,
        certs as *const libc::c_void,
    );
}
unsafe extern "C" fn pkcs7_bundle_crls_cb(
    mut out: *mut CBB,
    mut arg: *const libc::c_void,
) -> libc::c_int {
    let mut crls: *const stack_st_X509_CRL = arg as *const stack_st_X509_CRL;
    let mut i: size_t = 0;
    let mut crl_data: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    if CBB_add_asn1(
        out,
        &mut crl_data,
        (0x80 as libc::c_uint) << 24 as libc::c_int
            | (0x20 as libc::c_uint) << 24 as libc::c_int
            | 1 as libc::c_int as libc::c_uint,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    i = 0 as libc::c_int as size_t;
    while i < sk_X509_CRL_num(crls) {
        let mut crl: *mut X509_CRL = sk_X509_CRL_value(crls, i);
        let mut buf: *mut uint8_t = 0 as *mut uint8_t;
        let mut len: libc::c_int = i2d_X509_CRL(crl, 0 as *mut *mut uint8_t);
        if len < 0 as libc::c_int
            || CBB_add_space(&mut crl_data, &mut buf, len as size_t) == 0
            || i2d_X509_CRL(crl, &mut buf) < 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return (CBB_flush_asn1_set_of(&mut crl_data) != 0 && CBB_flush(out) != 0)
        as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS7_bundle_CRLs(
    mut out: *mut CBB,
    mut crls: *const stack_st_X509_CRL,
) -> libc::c_int {
    return pkcs7_add_signed_data(
        out,
        None,
        Some(
            pkcs7_bundle_crls_cb
                as unsafe extern "C" fn(*mut CBB, *const libc::c_void) -> libc::c_int,
        ),
        None,
        crls as *const libc::c_void,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_PKCS7_bio(
    mut bio: *mut BIO,
    mut out: *mut *mut PKCS7,
) -> *mut PKCS7 {
    if bio.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7_x509.c\0" as *const u8
                as *const libc::c_char,
            237 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut PKCS7;
    }
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = 0;
    if BIO_read_asn1(bio, &mut data, &mut len, 2147483647 as libc::c_int as size_t) == 0
    {
        return 0 as *mut PKCS7;
    }
    let mut ptr: *const uint8_t = data;
    let mut ret: *mut PKCS7 = d2i_PKCS7(out, &mut ptr, len as libc::c_long);
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_PKCS7_bio(
    mut bio: *mut BIO,
    mut p7: *const PKCS7,
) -> libc::c_int {
    return ASN1_item_i2d_bio(&PKCS7_it, bio, p7 as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS7_type_is_data(mut p7: *const PKCS7) -> libc::c_int {
    return (OBJ_obj2nid((*p7).type_0) == 21 as libc::c_int) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS7_type_is_digest(mut p7: *const PKCS7) -> libc::c_int {
    return (OBJ_obj2nid((*p7).type_0) == 25 as libc::c_int) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS7_type_is_encrypted(mut p7: *const PKCS7) -> libc::c_int {
    return (OBJ_obj2nid((*p7).type_0) == 26 as libc::c_int) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS7_type_is_enveloped(mut p7: *const PKCS7) -> libc::c_int {
    return (OBJ_obj2nid((*p7).type_0) == 23 as libc::c_int) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS7_type_is_signed(mut p7: *const PKCS7) -> libc::c_int {
    return (OBJ_obj2nid((*p7).type_0) == 22 as libc::c_int) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS7_type_is_signedAndEnveloped(
    mut p7: *const PKCS7,
) -> libc::c_int {
    return (OBJ_obj2nid((*p7).type_0) == 24 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn write_sha256_ai(
    mut digest_algos_set: *mut CBB,
    mut arg: *const libc::c_void,
) -> libc::c_int {
    let mut seq: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    return (CBB_add_asn1(
        digest_algos_set,
        &mut seq,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) != 0 && OBJ_nid2cbb(&mut seq, 672 as libc::c_int) != 0
        && CBB_flush(digest_algos_set) != 0) as libc::c_int;
}
unsafe extern "C" fn sign_sha256(
    mut out_sig: *mut uint8_t,
    mut out_sig_len: *mut size_t,
    mut max_out_sig: size_t,
    mut pkey: *mut EVP_PKEY,
    mut data: *mut BIO,
) -> libc::c_int {
    let mut current_block: u64;
    static mut kBufSize: size_t = 4096 as libc::c_int as size_t;
    let mut buffer: *mut uint8_t = OPENSSL_malloc(kBufSize) as *mut uint8_t;
    if buffer.is_null() {
        return 0 as libc::c_int;
    }
    let mut ctx: EVP_MD_CTX = env_md_ctx_st {
        digest: 0 as *const EVP_MD,
        md_data: 0 as *mut libc::c_void,
        update: None,
        pctx: 0 as *mut EVP_PKEY_CTX,
        pctx_ops: 0 as *const evp_md_pctx_ops,
        flags: 0,
    };
    EVP_MD_CTX_init(&mut ctx);
    let mut ret: libc::c_int = 0 as libc::c_int;
    if EVP_DigestSignInit(
        &mut ctx,
        0 as *mut *mut EVP_PKEY_CTX,
        EVP_sha256(),
        0 as *mut ENGINE,
        pkey,
    ) == 0
    {
        current_block = 16884785536832181919;
    } else {
        current_block = 2473556513754201174;
    }
    loop {
        match current_block {
            16884785536832181919 => {
                EVP_MD_CTX_cleanup(&mut ctx);
                break;
            }
            _ => {
                let n: libc::c_int = BIO_read(
                    data,
                    buffer as *mut libc::c_void,
                    kBufSize as libc::c_int,
                );
                if n == 0 as libc::c_int {
                    *out_sig_len = max_out_sig;
                    if EVP_DigestSignFinal(&mut ctx, out_sig, out_sig_len) == 0 {
                        current_block = 16884785536832181919;
                        continue;
                    }
                    ret = 1 as libc::c_int;
                    current_block = 16884785536832181919;
                } else if n < 0 as libc::c_int
                    || EVP_DigestSignUpdate(
                        &mut ctx,
                        buffer as *const libc::c_void,
                        n as size_t,
                    ) == 0
                {
                    current_block = 16884785536832181919;
                } else {
                    current_block = 2473556513754201174;
                }
            }
        }
    }
    OPENSSL_free(buffer as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn write_signer_info(
    mut out: *mut CBB,
    mut arg: *const libc::c_void,
) -> libc::c_int {
    let si_data: *const signer_info_data = arg as *const signer_info_data;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut subject_bytes: *mut uint8_t = 0 as *mut uint8_t;
    let mut serial_bytes: *mut uint8_t = 0 as *mut uint8_t;
    let subject_len: libc::c_int = i2d_X509_NAME(
        X509_get_subject_name((*si_data).sign_cert),
        &mut subject_bytes,
    );
    let serial_len: libc::c_int = i2d_ASN1_INTEGER(
        X509_get0_serialNumber((*si_data).sign_cert) as *mut ASN1_INTEGER,
        &mut serial_bytes,
    );
    let mut seq: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut issuer_and_serial: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut signing_algo: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut null: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut signature: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    if !(subject_len < 0 as libc::c_int || serial_len < 0 as libc::c_int
        || CBB_add_asn1(
            out,
            &mut seq,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0 || CBB_add_asn1_uint64(&mut seq, 1 as libc::c_int as uint64_t) == 0
        || CBB_add_asn1(
            &mut seq,
            &mut issuer_and_serial,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0
        || CBB_add_bytes(&mut issuer_and_serial, subject_bytes, subject_len as size_t)
            == 0
        || CBB_add_bytes(&mut issuer_and_serial, serial_bytes, serial_len as size_t) == 0
        || write_sha256_ai(&mut seq, 0 as *const libc::c_void) == 0
        || CBB_add_asn1(
            &mut seq,
            &mut signing_algo,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0 || OBJ_nid2cbb(&mut signing_algo, 6 as libc::c_int) == 0
        || CBB_add_asn1(&mut signing_algo, &mut null, 0x5 as libc::c_uint) == 0
        || CBB_add_asn1(&mut seq, &mut signature, 0x4 as libc::c_uint) == 0
        || CBB_add_bytes(&mut signature, (*si_data).signature, (*si_data).signature_len)
            == 0 || CBB_flush(out) == 0)
    {
        ret = 1 as libc::c_int;
    }
    OPENSSL_free(subject_bytes as *mut libc::c_void);
    OPENSSL_free(serial_bytes as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn pkcs7_add_signature(
    mut p7: *mut PKCS7,
    mut x509: *mut X509,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    let mut digest: *const EVP_MD = EVP_sha256();
    let mut si: *mut PKCS7_SIGNER_INFO = 0 as *mut PKCS7_SIGNER_INFO;
    match EVP_PKEY_id(pkey) {
        6 | 116 | 408 => {
            si = PKCS7_SIGNER_INFO_new();
            if si.is_null() || PKCS7_SIGNER_INFO_set(si, x509, pkey, digest) == 0
                || PKCS7_add_signer(p7, si) == 0
            {
                ERR_put_error(
                    18 as libc::c_int,
                    0 as libc::c_int,
                    122 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7_x509.c\0"
                        as *const u8 as *const libc::c_char,
                    404 as libc::c_int as libc::c_uint,
                );
            } else {
                return 1 as libc::c_int
            }
        }
        _ => {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                133 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7_x509.c\0"
                    as *const u8 as *const libc::c_char,
                395 as libc::c_int as libc::c_uint,
            );
        }
    }
    PKCS7_SIGNER_INFO_free(si);
    return 0 as libc::c_int;
}
unsafe extern "C" fn pkcs7_sign_add_signer(
    mut p7: *mut PKCS7,
    mut signcert: *mut X509,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    if X509_check_private_key(signcert, pkey) == 0 {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            120 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7_x509.c\0" as *const u8
                as *const libc::c_char,
            415 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if pkcs7_add_signature(p7, signcert, pkey) == 0 {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            132 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7_x509.c\0" as *const u8
                as *const libc::c_char,
            420 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if PKCS7_add_certificate(p7, signcert) == 0 {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkcs7_do_general_sign(
    mut sign_cert: *mut X509,
    mut pkey: *mut EVP_PKEY,
    mut certs: *mut stack_st_X509,
    mut data: *mut BIO,
    mut flags: libc::c_int,
) -> *mut PKCS7 {
    let mut current_block: u64;
    let mut ret: *mut PKCS7 = 0 as *mut PKCS7;
    ret = PKCS7_new();
    if ret.is_null() || PKCS7_set_type(ret, 22 as libc::c_int) == 0
        || PKCS7_content_new(ret, 21 as libc::c_int) == 0
    {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            18 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7_x509.c\0" as *const u8
                as *const libc::c_char,
            437 as libc::c_int as libc::c_uint,
        );
    } else if pkcs7_sign_add_signer(ret, sign_cert, pkey) == 0 {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            131 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7_x509.c\0" as *const u8
                as *const libc::c_char,
            442 as libc::c_int as libc::c_uint,
        );
    } else {
        let mut i: size_t = 0 as libc::c_int as size_t;
        loop {
            if !(i < sk_X509_num(certs)) {
                current_block = 8515828400728868193;
                break;
            }
            if PKCS7_add_certificate(ret, sk_X509_value(certs, i)) == 0 {
                ERR_put_error(
                    18 as libc::c_int,
                    0 as libc::c_int,
                    131 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7_x509.c\0"
                        as *const u8 as *const libc::c_char,
                    448 as libc::c_int as libc::c_uint,
                );
                current_block = 1152188271278734773;
                break;
            } else {
                i = i.wrapping_add(1);
                i;
            }
        }
        match current_block {
            1152188271278734773 => {}
            _ => {
                if flags & 0x40 as libc::c_int != 0
                    && PKCS7_type_is_data((*(*ret).d.sign).contents) != 0
                {
                    ASN1_OCTET_STRING_free((*(*(*ret).d.sign).contents).d.data);
                    (*(*(*ret).d.sign).contents).d.data = 0 as *mut ASN1_OCTET_STRING;
                }
                if !(pkcs7_final(ret, data) == 0) {
                    return ret;
                }
            }
        }
    }
    PKCS7_free(ret);
    return 0 as *mut PKCS7;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS7_sign(
    mut sign_cert: *mut X509,
    mut pkey: *mut EVP_PKEY,
    mut certs: *mut stack_st_X509,
    mut data: *mut BIO,
    mut flags: libc::c_int,
) -> *mut PKCS7 {
    let mut const_der: *const uint8_t = 0 as *const uint8_t;
    let mut current_block: u64;
    let mut cbb: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    if CBB_init(&mut cbb, 2048 as libc::c_int as size_t) == 0 {
        return 0 as *mut PKCS7;
    }
    let mut der: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = 0;
    let mut ret: *mut PKCS7 = 0 as *mut PKCS7;
    if sign_cert.is_null() && pkey.is_null() && flags == 0x40 as libc::c_int {
        if PKCS7_bundle_certificates(&mut cbb, certs) == 0 {
            current_block = 13860710552827432782;
        } else {
            current_block = 8236137900636309791;
        }
    } else if !sign_cert.is_null() && !pkey.is_null() && certs.is_null()
        && !data.is_null()
        && flags
            == 0x100 as libc::c_int | 0x80 as libc::c_int | 0x2 as libc::c_int
                | 0x40 as libc::c_int && EVP_PKEY_id(pkey) == 6 as libc::c_int
    {
        let signature_max_len: size_t = EVP_PKEY_size(pkey) as size_t;
        let mut si_data: signer_info_data = {
            let mut init = signer_info_data {
                sign_cert: sign_cert,
                signature: OPENSSL_malloc(signature_max_len) as *mut uint8_t,
                signature_len: 0,
            };
            init
        };
        if (si_data.signature).is_null()
            || sign_sha256(
                si_data.signature,
                &mut si_data.signature_len,
                signature_max_len,
                pkey,
                data,
            ) == 0
            || pkcs7_add_signed_data(
                &mut cbb,
                Some(
                    write_sha256_ai
                        as unsafe extern "C" fn(
                            *mut CBB,
                            *const libc::c_void,
                        ) -> libc::c_int,
                ),
                None,
                Some(
                    write_signer_info
                        as unsafe extern "C" fn(
                            *mut CBB,
                            *const libc::c_void,
                        ) -> libc::c_int,
                ),
                &mut si_data as *mut signer_info_data as *const libc::c_void,
            ) == 0
        {
            OPENSSL_free(si_data.signature as *mut libc::c_void);
            current_block = 13860710552827432782;
        } else {
            OPENSSL_free(si_data.signature as *mut libc::c_void);
            current_block = 8236137900636309791;
        }
    } else {
        if !sign_cert.is_null() && !pkey.is_null() && !data.is_null()
            && flags & 0x2 as libc::c_int == 0
        {
            ret = pkcs7_do_general_sign(sign_cert, pkey, certs, data, flags);
        } else {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                2 as libc::c_int | 64 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7_x509.c\0"
                    as *const u8 as *const libc::c_char,
                510 as libc::c_int as libc::c_uint,
            );
        }
        current_block = 13860710552827432782;
    }
    match current_block {
        8236137900636309791 => {
            if !(CBB_finish(&mut cbb, &mut der, &mut len) == 0) {
                const_der = der;
                ret = d2i_PKCS7(
                    0 as *mut *mut PKCS7,
                    &mut const_der,
                    len as libc::c_long,
                );
            }
        }
        _ => {}
    }
    CBB_cleanup(&mut cbb);
    OPENSSL_free(der as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS7_add_certificate(
    mut p7: *mut PKCS7,
    mut x509: *mut X509,
) -> libc::c_int {
    let mut sk: *mut *mut stack_st_X509 = 0 as *mut *mut stack_st_X509;
    if p7.is_null() || x509.is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7_x509.c\0" as *const u8
                as *const libc::c_char,
            531 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    match OBJ_obj2nid((*p7).type_0) {
        22 => {
            sk = &mut (*(*p7).d.sign).cert;
        }
        24 => {
            sk = &mut (*(*p7).d.signed_and_enveloped).cert;
        }
        _ => {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                110 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7_x509.c\0"
                    as *const u8 as *const libc::c_char,
                543 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    }
    if (*sk).is_null() {
        *sk = sk_X509_new_null();
    }
    if (*sk).is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            14 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7_x509.c\0" as *const u8
                as *const libc::c_char,
            551 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if sk_X509_push(*sk, x509) == 0 {
        return 0 as libc::c_int;
    }
    X509_up_ref(x509);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS7_add_crl(
    mut p7: *mut PKCS7,
    mut crl: *mut X509_CRL,
) -> libc::c_int {
    let mut sk: *mut *mut stack_st_X509_CRL = 0 as *mut *mut stack_st_X509_CRL;
    if p7.is_null() || crl.is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7_x509.c\0" as *const u8
                as *const libc::c_char,
            566 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    match OBJ_obj2nid((*p7).type_0) {
        22 => {
            sk = &mut (*(*p7).d.sign).crl;
        }
        24 => {
            sk = &mut (*(*p7).d.signed_and_enveloped).crl;
        }
        _ => {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                110 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7_x509.c\0"
                    as *const u8 as *const libc::c_char,
                578 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    }
    if (*sk).is_null() {
        *sk = sk_X509_CRL_new_null();
    }
    if (*sk).is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            14 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7_x509.c\0" as *const u8
                as *const libc::c_char,
            586 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if sk_X509_CRL_push(*sk, crl) == 0 {
        return 0 as libc::c_int;
    }
    X509_CRL_up_ref(crl);
    return 1 as libc::c_int;
}
