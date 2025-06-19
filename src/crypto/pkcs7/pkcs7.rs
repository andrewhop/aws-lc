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
    pub type ASN1_ITEM_st;
    pub type asn1_object_st;
    pub type ASN1_VALUE_st;
    pub type X509_name_st;
    pub type evp_cipher_st;
    pub type evp_pkey_st;
    pub type x509_st;
    pub type stack_st_void;
    pub type crypto_buffer_pool_st;
    pub type crypto_buffer_st;
    pub type engine_st;
    pub type evp_pkey_ctx_st;
    pub type stack_st_PKCS7_SIGNER_INFO;
    pub type stack_st_X509_CRL;
    pub type stack_st_X509;
    pub type stack_st_X509_ALGOR;
    pub type stack_st_PKCS7_RECIP_INFO;
    pub type stack_st_X509_ATTRIBUTE;
    pub type x509_attributes_st;
    pub type x509_store_ctx_st;
    pub type x509_store_st;
    pub type stack_st;
    pub type stack_st_CRYPTO_BUFFER;
    fn ASN1_item_i2d(
        val: *mut ASN1_VALUE,
        outp: *mut *mut libc::c_uchar,
        it: *const ASN1_ITEM,
    ) -> libc::c_int;
    fn ASN1_STRING_set0(
        str: *mut ASN1_STRING,
        data: *mut libc::c_void,
        len: libc::c_int,
    );
    fn ASN1_OCTET_STRING_new() -> *mut ASN1_OCTET_STRING;
    fn ASN1_OCTET_STRING_free(str: *mut ASN1_OCTET_STRING);
    fn ASN1_OCTET_STRING_set(
        str: *mut ASN1_OCTET_STRING,
        data: *const libc::c_uchar,
        len: libc::c_int,
    ) -> libc::c_int;
    fn ASN1_INTEGER_free(str: *mut ASN1_INTEGER);
    fn ASN1_INTEGER_dup(x: *const ASN1_INTEGER) -> *mut ASN1_INTEGER;
    fn ASN1_INTEGER_cmp(x: *const ASN1_INTEGER, y: *const ASN1_INTEGER) -> libc::c_int;
    fn ASN1_OBJECT_free(a: *mut ASN1_OBJECT);
    fn ASN1_TYPE_new() -> *mut ASN1_TYPE;
    fn ASN1_TYPE_free(a: *mut ASN1_TYPE);
    fn ASN1_INTEGER_set(a: *mut ASN1_INTEGER, v: libc::c_long) -> libc::c_int;
    fn X509_up_ref(x509: *mut X509) -> libc::c_int;
    fn X509_free(x509: *mut X509);
    fn X509_get0_serialNumber(x509: *const X509) -> *const ASN1_INTEGER;
    fn X509_get_issuer_name(x509: *const X509) -> *mut X509_NAME;
    fn X509_get0_pubkey(x509: *const X509) -> *mut EVP_PKEY;
    fn X509_check_private_key(x509: *const X509, pkey: *const EVP_PKEY) -> libc::c_int;
    fn X509_NAME_cmp(a: *const X509_NAME, b: *const X509_NAME) -> libc::c_int;
    fn X509_NAME_set(xn: *mut *mut X509_NAME, name: *mut X509_NAME) -> libc::c_int;
    fn X509_ALGOR_new() -> *mut X509_ALGOR;
    fn X509_ALGOR_free(alg: *mut X509_ALGOR);
    fn X509_ALGOR_set0(
        alg: *mut X509_ALGOR,
        obj: *mut ASN1_OBJECT,
        param_type: libc::c_int,
        param_value: *mut libc::c_void,
    ) -> libc::c_int;
    fn X509_ATTRIBUTE_get0_object(attr: *mut X509_ATTRIBUTE) -> *mut ASN1_OBJECT;
    fn X509_ATTRIBUTE_get0_type(
        attr: *mut X509_ATTRIBUTE,
        idx: libc::c_int,
    ) -> *mut ASN1_TYPE;
    fn X509_STORE_CTX_new() -> *mut X509_STORE_CTX;
    fn X509_STORE_CTX_free(ctx: *mut X509_STORE_CTX);
    fn X509_STORE_CTX_init(
        ctx: *mut X509_STORE_CTX,
        store: *mut X509_STORE,
        x509: *mut X509,
        chain: *mut stack_st_X509,
    ) -> libc::c_int;
    fn X509_verify_cert(ctx: *mut X509_STORE_CTX) -> libc::c_int;
    fn X509_STORE_CTX_set0_crls(ctx: *mut X509_STORE_CTX, sk: *mut stack_st_X509_CRL);
    fn X509_STORE_CTX_set_default(
        ctx: *mut X509_STORE_CTX,
        name: *const libc::c_char,
    ) -> libc::c_int;
    fn X509_find_by_issuer_and_serial(
        sk: *const stack_st_X509,
        name: *mut X509_NAME,
        serial: *const ASN1_INTEGER,
    ) -> *mut X509;
    fn EVP_get_cipherbynid(nid: libc::c_int) -> *const EVP_CIPHER;
    fn EVP_CipherInit_ex(
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        engine: *mut ENGINE,
        key: *const uint8_t,
        iv: *const uint8_t,
        enc: libc::c_int,
    ) -> libc::c_int;
    fn EVP_CIPHER_CTX_key_length(ctx: *const EVP_CIPHER_CTX) -> libc::c_uint;
    fn EVP_CIPHER_CTX_iv_length(ctx: *const EVP_CIPHER_CTX) -> libc::c_uint;
    fn EVP_CIPHER_nid(cipher: *const EVP_CIPHER) -> libc::c_int;
    fn EVP_CIPHER_key_length(cipher: *const EVP_CIPHER) -> libc::c_uint;
    fn EVP_CIPHER_iv_length(cipher: *const EVP_CIPHER) -> libc::c_uint;
    fn BIO_new(method: *const BIO_METHOD) -> *mut BIO;
    fn BIO_free(bio: *mut BIO) -> libc::c_int;
    fn BIO_read(bio: *mut BIO, data: *mut libc::c_void, len: libc::c_int) -> libc::c_int;
    fn BIO_write(
        bio: *mut BIO,
        data: *const libc::c_void,
        len: libc::c_int,
    ) -> libc::c_int;
    fn BIO_write_all(
        bio: *mut BIO,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn BIO_flush(bio: *mut BIO) -> libc::c_int;
    fn BIO_set_flags(bio: *mut BIO, flags: libc::c_int);
    fn BIO_push(bio: *mut BIO, appended_bio: *mut BIO) -> *mut BIO;
    fn BIO_pop(bio: *mut BIO) -> *mut BIO;
    fn BIO_next(bio: *mut BIO) -> *mut BIO;
    fn BIO_free_all(bio: *mut BIO);
    fn BIO_find_type(bio: *mut BIO, type_0: libc::c_int) -> *mut BIO;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_new_mem_buf(buf: *const libc::c_void, len: ossl_ssize_t) -> *mut BIO;
    fn BIO_mem_contents(
        bio: *const BIO,
        out_contents: *mut *const uint8_t,
        out_len: *mut size_t,
    ) -> libc::c_int;
    fn BIO_set_mem_eof_return(bio: *mut BIO, eof_value: libc::c_int) -> libc::c_int;
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_free(sk: *mut OPENSSL_STACK);
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn OPENSSL_sk_pop(sk: *mut OPENSSL_STACK) -> *mut libc::c_void;
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_mem_equal(cbs: *const CBS, data: *const uint8_t, len: size_t) -> libc::c_int;
    fn CBS_get_asn1(
        cbs: *mut CBS,
        out: *mut CBS,
        tag_value: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBS_get_asn1_element(
        cbs: *mut CBS,
        out: *mut CBS,
        tag_value: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBS_get_asn1_uint64(cbs: *mut CBS, out: *mut uint64_t) -> libc::c_int;
    fn CBS_get_optional_asn1(
        cbs: *mut CBS,
        out: *mut CBS,
        out_present: *mut libc::c_int,
        tag: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBB_flush(cbb: *mut CBB) -> libc::c_int;
    fn CBB_add_asn1(
        cbb: *mut CBB,
        out_contents: *mut CBB,
        tag: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBB_add_bytes(cbb: *mut CBB, data: *const uint8_t, len: size_t) -> libc::c_int;
    fn CBB_add_u8(cbb: *mut CBB, value: uint8_t) -> libc::c_int;
    fn CBB_flush_asn1_set_of(cbb: *mut CBB) -> libc::c_int;
    fn EVP_get_digestbynid(nid: libc::c_int) -> *const EVP_MD;
    fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX;
    fn EVP_MD_CTX_free(ctx: *mut EVP_MD_CTX);
    fn EVP_MD_CTX_copy_ex(out: *mut EVP_MD_CTX, in_0: *const EVP_MD_CTX) -> libc::c_int;
    fn EVP_DigestFinal_ex(
        ctx: *mut EVP_MD_CTX,
        md_out: *mut uint8_t,
        out_size: *mut libc::c_uint,
    ) -> libc::c_int;
    fn EVP_MD_type(md: *const EVP_MD) -> libc::c_int;
    fn EVP_MD_CTX_type(ctx: *const EVP_MD_CTX) -> libc::c_int;
    fn EVP_MD_nid(md: *const EVP_MD) -> libc::c_int;
    fn PKCS7_SIGNED_free(a: *mut PKCS7_SIGNED);
    fn PKCS7_SIGNED_new() -> *mut PKCS7_SIGNED;
    fn PKCS7_ENCRYPT_free(a: *mut PKCS7_ENCRYPT);
    fn PKCS7_ENCRYPT_new() -> *mut PKCS7_ENCRYPT;
    fn PKCS7_ENVELOPE_new() -> *mut PKCS7_ENVELOPE;
    fn PKCS7_ENVELOPE_free(a: *mut PKCS7_ENVELOPE);
    fn PKCS7_DIGEST_new() -> *mut PKCS7_DIGEST;
    fn PKCS7_DIGEST_free(a: *mut PKCS7_DIGEST);
    fn PKCS7_SIGN_ENVELOPE_free(a: *mut PKCS7_SIGN_ENVELOPE);
    fn PKCS7_SIGN_ENVELOPE_new() -> *mut PKCS7_SIGN_ENVELOPE;
    static PKCS7_ATTR_VERIFY_it: ASN1_ITEM;
    fn BIO_f_md() -> *const BIO_METHOD;
    fn BIO_get_md_ctx(b: *mut BIO, ctx: *mut *mut EVP_MD_CTX) -> libc::c_int;
    fn BIO_set_md(b: *mut BIO, md: *const EVP_MD) -> libc::c_int;
    fn BIO_f_cipher() -> *const BIO_METHOD;
    fn BIO_get_cipher_ctx(b: *mut BIO, ctx: *mut *mut EVP_CIPHER_CTX) -> libc::c_int;
    fn BIO_get_cipher_status(b: *mut BIO) -> libc::c_int;
    fn PKCS7_type_is_data(p7: *const PKCS7) -> libc::c_int;
    fn PKCS7_type_is_signed(p7: *const PKCS7) -> libc::c_int;
    fn PKCS7_new() -> *mut PKCS7;
    fn PKCS7_free(a: *mut PKCS7);
    fn PKCS7_RECIP_INFO_free(a: *mut PKCS7_RECIP_INFO);
    fn PKCS7_RECIP_INFO_new() -> *mut PKCS7_RECIP_INFO;
    fn RAND_bytes(buf: *mut uint8_t, len: size_t) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn ERR_clear_error();
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OBJ_dup(obj: *const ASN1_OBJECT) -> *mut ASN1_OBJECT;
    fn OBJ_cmp(a: *const ASN1_OBJECT, b: *const ASN1_OBJECT) -> libc::c_int;
    fn OBJ_obj2nid(obj: *const ASN1_OBJECT) -> libc::c_int;
    fn OBJ_nid2obj(nid: libc::c_int) -> *mut ASN1_OBJECT;
    fn OBJ_find_sigid_by_algs(
        out_sign_nid: *mut libc::c_int,
        digest_nid: libc::c_int,
        pkey_nid: libc::c_int,
    ) -> libc::c_int;
    fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
    fn EVP_PKEY_up_ref(pkey: *mut EVP_PKEY) -> libc::c_int;
    fn EVP_PKEY_size(pkey: *const EVP_PKEY) -> libc::c_int;
    fn EVP_PKEY_id(pkey: *const EVP_PKEY) -> libc::c_int;
    fn EVP_SignFinal(
        ctx: *const EVP_MD_CTX,
        sig: *mut uint8_t,
        out_sig_len: *mut libc::c_uint,
        pkey: *mut EVP_PKEY,
    ) -> libc::c_int;
    fn EVP_VerifyInit_ex(
        ctx: *mut EVP_MD_CTX,
        type_0: *const EVP_MD,
        impl_0: *mut ENGINE,
    ) -> libc::c_int;
    fn EVP_VerifyUpdate(
        ctx: *mut EVP_MD_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn EVP_VerifyFinal(
        ctx: *mut EVP_MD_CTX,
        sig: *const uint8_t,
        sig_len: size_t,
        pkey: *mut EVP_PKEY,
    ) -> libc::c_int;
    fn EVP_PKEY_CTX_new(pkey: *mut EVP_PKEY, e: *mut ENGINE) -> *mut EVP_PKEY_CTX;
    fn EVP_PKEY_CTX_free(ctx: *mut EVP_PKEY_CTX);
    fn EVP_PKEY_encrypt_init(ctx: *mut EVP_PKEY_CTX) -> libc::c_int;
    fn EVP_PKEY_encrypt(
        ctx: *mut EVP_PKEY_CTX,
        out: *mut uint8_t,
        out_len: *mut size_t,
        in_0: *const uint8_t,
        in_len: size_t,
    ) -> libc::c_int;
    fn EVP_PKEY_decrypt_init(ctx: *mut EVP_PKEY_CTX) -> libc::c_int;
    fn EVP_PKEY_decrypt(
        ctx: *mut EVP_PKEY_CTX,
        out: *mut uint8_t,
        out_len: *mut size_t,
        in_0: *const uint8_t,
        in_len: size_t,
    ) -> libc::c_int;
    fn CRYPTO_BUFFER_new_from_CBS(
        cbs: *const CBS,
        pool: *mut CRYPTO_BUFFER_POOL,
    ) -> *mut CRYPTO_BUFFER;
    fn CRYPTO_BUFFER_free(buf: *mut CRYPTO_BUFFER);
    fn CRYPTO_BUFFER_data(buf: *const CRYPTO_BUFFER) -> *const uint8_t;
    fn CRYPTO_BUFFER_len(buf: *const CRYPTO_BUFFER) -> size_t;
    fn CBS_asn1_ber_to_der(
        in_0: *mut CBS,
        out: *mut CBS,
        out_storage: *mut *mut uint8_t,
    ) -> libc::c_int;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_md_pctx_ops {
    pub free: Option::<unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> ()>,
    pub dup: Option::<unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> *mut EVP_PKEY_CTX>,
}
pub type EVP_PKEY_CTX = evp_pkey_ctx_st;
pub type EVP_MD_CTX = env_md_ctx_st;
pub type EVP_MD = env_md_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct env_md_st {
    pub type_0: libc::c_int,
    pub md_size: libc::c_uint,
    pub flags: uint32_t,
    pub init: Option::<unsafe extern "C" fn(*mut EVP_MD_CTX) -> ()>,
    pub update: Option::<
        unsafe extern "C" fn(*mut EVP_MD_CTX, *const libc::c_void, size_t) -> libc::c_int,
    >,
    pub final_0: Option::<unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t) -> ()>,
    pub block_size: libc::c_uint,
    pub ctx_size: libc::c_uint,
    pub finalXOF: Option::<
        unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t, size_t) -> libc::c_int,
    >,
    pub squeezeXOF: Option::<
        unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t, size_t) -> (),
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_cipher_ctx_st {
    pub cipher: *const EVP_CIPHER,
    pub app_data: *mut libc::c_void,
    pub cipher_data: *mut libc::c_void,
    pub key_len: libc::c_uint,
    pub encrypt: libc::c_int,
    pub flags: uint32_t,
    pub oiv: [uint8_t; 16],
    pub iv: [uint8_t; 16],
    pub buf: [uint8_t; 32],
    pub buf_len: libc::c_int,
    pub num: libc::c_uint,
    pub final_used: libc::c_int,
    pub final_0: [uint8_t; 32],
    pub poisoned: libc::c_int,
}
pub type EVP_CIPHER_CTX = evp_cipher_ctx_st;
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
pub struct pkcs7_recip_info_st {
    pub version: *mut ASN1_INTEGER,
    pub issuer_and_serial: *mut PKCS7_ISSUER_AND_SERIAL,
    pub key_enc_algor: *mut X509_ALGOR,
    pub enc_key: *mut ASN1_OCTET_STRING,
    pub cert: *mut X509,
}
pub type PKCS7_RECIP_INFO = pkcs7_recip_info_st;
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
pub type X509_ATTRIBUTE = x509_attributes_st;
pub type X509_STORE_CTX = x509_store_ctx_st;
pub type X509_STORE = x509_store_st;
pub type OPENSSL_STACK = stack_st;
#[inline]
unsafe extern "C" fn sk_X509_new_null() -> *mut stack_st_X509 {
    return OPENSSL_sk_new_null() as *mut stack_st_X509;
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
unsafe extern "C" fn sk_X509_value(
    mut sk: *const stack_st_X509,
    mut i: size_t,
) -> *mut X509 {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509;
}
#[inline]
unsafe extern "C" fn sk_X509_free(mut sk: *mut stack_st_X509) {
    OPENSSL_sk_free(sk as *mut OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_ALGOR_push(
    mut sk: *mut stack_st_X509_ALGOR,
    mut p: *mut X509_ALGOR,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_X509_ALGOR_value(
    mut sk: *const stack_st_X509_ALGOR,
    mut i: size_t,
) -> *mut X509_ALGOR {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509_ALGOR;
}
#[inline]
unsafe extern "C" fn sk_X509_ALGOR_num(mut sk: *const stack_st_X509_ALGOR) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_ATTRIBUTE_num(
    mut sk: *const stack_st_X509_ATTRIBUTE,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_ATTRIBUTE_value(
    mut sk: *const stack_st_X509_ATTRIBUTE,
    mut i: size_t,
) -> *mut X509_ATTRIBUTE {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509_ATTRIBUTE;
}
#[inline]
unsafe extern "C" fn sk_PKCS7_RECIP_INFO_num(
    mut sk: *const stack_st_PKCS7_RECIP_INFO,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_PKCS7_RECIP_INFO_value(
    mut sk: *const stack_st_PKCS7_RECIP_INFO,
    mut i: size_t,
) -> *mut PKCS7_RECIP_INFO {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut PKCS7_RECIP_INFO;
}
#[inline]
unsafe extern "C" fn sk_PKCS7_RECIP_INFO_push(
    mut sk: *mut stack_st_PKCS7_RECIP_INFO,
    mut p: *mut PKCS7_RECIP_INFO,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_PKCS7_SIGNER_INFO_value(
    mut sk: *const stack_st_PKCS7_SIGNER_INFO,
    mut i: size_t,
) -> *mut PKCS7_SIGNER_INFO {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut PKCS7_SIGNER_INFO;
}
#[inline]
unsafe extern "C" fn sk_PKCS7_SIGNER_INFO_push(
    mut sk: *mut stack_st_PKCS7_SIGNER_INFO,
    mut p: *mut PKCS7_SIGNER_INFO,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_PKCS7_SIGNER_INFO_num(
    mut sk: *const stack_st_PKCS7_SIGNER_INFO,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_CRYPTO_BUFFER_num(
    mut sk: *const stack_st_CRYPTO_BUFFER,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_CRYPTO_BUFFER_push(
    mut sk: *mut stack_st_CRYPTO_BUFFER,
    mut p: *mut CRYPTO_BUFFER,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_CRYPTO_BUFFER_pop(
    mut sk: *mut stack_st_CRYPTO_BUFFER,
) -> *mut CRYPTO_BUFFER {
    return OPENSSL_sk_pop(sk as *mut OPENSSL_STACK) as *mut CRYPTO_BUFFER;
}
#[inline]
unsafe extern "C" fn sk_CRYPTO_BUFFER_value(
    mut sk: *const stack_st_CRYPTO_BUFFER,
    mut i: size_t,
) -> *mut CRYPTO_BUFFER {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut CRYPTO_BUFFER;
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
static mut kPKCS7Data: [uint8_t; 9] = [
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
];
static mut kPKCS7SignedData: [uint8_t; 9] = [
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
];
#[no_mangle]
pub unsafe extern "C" fn pkcs7_parse_header(
    mut der_bytes: *mut *mut uint8_t,
    mut out: *mut CBS,
    mut cbs: *mut CBS,
) -> libc::c_int {
    let mut in_0: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut content_info: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut content_type: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut wrapped_signed_data: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut signed_data: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut version: uint64_t = 0;
    *der_bytes = 0 as *mut uint8_t;
    if !(CBS_asn1_ber_to_der(cbs, &mut in_0, der_bytes) == 0
        || CBS_get_asn1(
            &mut in_0,
            &mut content_info,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0
        || CBS_get_asn1(&mut content_info, &mut content_type, 0x6 as libc::c_uint) == 0)
    {
        if CBS_mem_equal(
            &mut content_type,
            kPKCS7SignedData.as_ptr(),
            ::core::mem::size_of::<[uint8_t; 9]>() as libc::c_ulong,
        ) == 0
        {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                101 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                    as *const libc::c_char,
                65 as libc::c_int as libc::c_uint,
            );
        } else if !(CBS_get_asn1(
            &mut content_info,
            &mut wrapped_signed_data,
            (0x80 as libc::c_uint) << 24 as libc::c_int
                | (0x20 as libc::c_uint) << 24 as libc::c_int
                | 0 as libc::c_int as libc::c_uint,
        ) == 0
            || CBS_get_asn1(
                &mut wrapped_signed_data,
                &mut signed_data,
                0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
            ) == 0 || CBS_get_asn1_uint64(&mut signed_data, &mut version) == 0
            || CBS_get_asn1(
                &mut signed_data,
                0 as *mut CBS,
                0x11 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
            ) == 0
            || CBS_get_asn1(
                &mut signed_data,
                0 as *mut CBS,
                0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
            ) == 0)
        {
            if version < 1 as libc::c_int as uint64_t {
                ERR_put_error(
                    18 as libc::c_int,
                    0 as libc::c_int,
                    100 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                        as *const u8 as *const libc::c_char,
                    80 as libc::c_int as libc::c_uint,
                );
            } else {
                CBS_init(out, CBS_data(&mut signed_data), CBS_len(&mut signed_data));
                return 1 as libc::c_int;
            }
        }
    }
    OPENSSL_free(*der_bytes as *mut libc::c_void);
    *der_bytes = 0 as *mut uint8_t;
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_get_raw_certificates(
    mut out_certs: *mut stack_st_CRYPTO_BUFFER,
    mut cbs: *mut CBS,
    mut pool: *mut CRYPTO_BUFFER_POOL,
) -> libc::c_int {
    let mut current_block: u64;
    let mut signed_data: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut certificates: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut der_bytes: *mut uint8_t = 0 as *mut uint8_t;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut has_certificates: libc::c_int = 0;
    let initial_certs_len: size_t = sk_CRYPTO_BUFFER_num(out_certs);
    if !(pkcs7_parse_header(&mut der_bytes, &mut signed_data, cbs) == 0
        || CBS_get_optional_asn1(
            &mut signed_data,
            &mut certificates,
            &mut has_certificates,
            (0x80 as libc::c_uint) << 24 as libc::c_int
                | (0x20 as libc::c_uint) << 24 as libc::c_int
                | 0 as libc::c_int as libc::c_uint,
        ) == 0)
    {
        if has_certificates == 0 {
            CBS_init(&mut certificates, 0 as *const uint8_t, 0 as libc::c_int as size_t);
        }
        loop {
            if !(CBS_len(&mut certificates) > 0 as libc::c_int as size_t) {
                current_block = 13536709405535804910;
                break;
            }
            let mut cert: CBS = cbs_st {
                data: 0 as *const uint8_t,
                len: 0,
            };
            if CBS_get_asn1_element(
                &mut certificates,
                &mut cert,
                0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
            ) == 0
            {
                current_block = 8805220693585407842;
                break;
            }
            let mut buf: *mut CRYPTO_BUFFER = CRYPTO_BUFFER_new_from_CBS(
                &mut cert,
                pool,
            );
            if !(buf.is_null() || sk_CRYPTO_BUFFER_push(out_certs, buf) == 0) {
                continue;
            }
            CRYPTO_BUFFER_free(buf);
            current_block = 8805220693585407842;
            break;
        }
        match current_block {
            8805220693585407842 => {}
            _ => {
                ret = 1 as libc::c_int;
            }
        }
    }
    OPENSSL_free(der_bytes as *mut libc::c_void);
    if ret == 0 {
        while sk_CRYPTO_BUFFER_num(out_certs) != initial_certs_len {
            let mut buf_0: *mut CRYPTO_BUFFER = sk_CRYPTO_BUFFER_pop(out_certs);
            CRYPTO_BUFFER_free(buf_0);
        }
    }
    return ret;
}
unsafe extern "C" fn pkcs7_bundle_raw_certificates_cb(
    mut out: *mut CBB,
    mut arg: *const libc::c_void,
) -> libc::c_int {
    let mut certs: *const stack_st_CRYPTO_BUFFER = arg as *const stack_st_CRYPTO_BUFFER;
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
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_CRYPTO_BUFFER_num(certs) {
        let mut cert: *mut CRYPTO_BUFFER = sk_CRYPTO_BUFFER_value(certs, i);
        if CBB_add_bytes(
            &mut certificates,
            CRYPTO_BUFFER_data(cert),
            CRYPTO_BUFFER_len(cert),
        ) == 0
        {
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return (CBB_flush_asn1_set_of(&mut certificates) != 0 && CBB_flush(out) != 0)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_bundle_raw_certificates(
    mut out: *mut CBB,
    mut certs: *const stack_st_CRYPTO_BUFFER,
) -> libc::c_int {
    return pkcs7_add_signed_data(
        out,
        None,
        Some(
            pkcs7_bundle_raw_certificates_cb
                as unsafe extern "C" fn(*mut CBB, *const libc::c_void) -> libc::c_int,
        ),
        None,
        certs as *const libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn pkcs7_add_signed_data(
    mut out: *mut CBB,
    mut digest_algos_cb: Option::<
        unsafe extern "C" fn(*mut CBB, *const libc::c_void) -> libc::c_int,
    >,
    mut cert_crl_cb: Option::<
        unsafe extern "C" fn(*mut CBB, *const libc::c_void) -> libc::c_int,
    >,
    mut signer_infos_cb: Option::<
        unsafe extern "C" fn(*mut CBB, *const libc::c_void) -> libc::c_int,
    >,
    mut arg: *const libc::c_void,
) -> libc::c_int {
    let mut outer_seq: CBB = cbb_st {
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
    let mut oid: CBB = cbb_st {
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
    let mut wrapped_seq: CBB = cbb_st {
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
    let mut version_bytes: CBB = cbb_st {
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
    let mut digest_algos_set: CBB = cbb_st {
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
    let mut content_info: CBB = cbb_st {
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
    let mut signer_infos: CBB = cbb_st {
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
        &mut outer_seq,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || CBB_add_asn1(&mut outer_seq, &mut oid, 0x6 as libc::c_uint) == 0
        || CBB_add_bytes(
            &mut oid,
            kPKCS7SignedData.as_ptr(),
            ::core::mem::size_of::<[uint8_t; 9]>() as libc::c_ulong,
        ) == 0
        || CBB_add_asn1(
            &mut outer_seq,
            &mut wrapped_seq,
            (0x80 as libc::c_uint) << 24 as libc::c_int
                | (0x20 as libc::c_uint) << 24 as libc::c_int
                | 0 as libc::c_int as libc::c_uint,
        ) == 0
        || CBB_add_asn1(
            &mut wrapped_seq,
            &mut seq,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0 || CBB_add_asn1(&mut seq, &mut version_bytes, 0x2 as libc::c_uint) == 0
        || CBB_add_u8(&mut version_bytes, 1 as libc::c_int as uint8_t) == 0
        || CBB_add_asn1(
            &mut seq,
            &mut digest_algos_set,
            0x11 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0
        || digest_algos_cb.is_some()
            && digest_algos_cb
                .expect("non-null function pointer")(&mut digest_algos_set, arg) == 0
        || CBB_add_asn1(
            &mut seq,
            &mut content_info,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0 || CBB_add_asn1(&mut content_info, &mut oid, 0x6 as libc::c_uint) == 0
        || CBB_add_bytes(
            &mut oid,
            kPKCS7Data.as_ptr(),
            ::core::mem::size_of::<[uint8_t; 9]>() as libc::c_ulong,
        ) == 0
        || cert_crl_cb.is_some()
            && cert_crl_cb.expect("non-null function pointer")(&mut seq, arg) == 0
        || CBB_add_asn1(
            &mut seq,
            &mut signer_infos,
            0x11 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0
        || signer_infos_cb.is_some()
            && signer_infos_cb
                .expect("non-null function pointer")(&mut signer_infos, arg) == 0
    {
        return 0 as libc::c_int;
    }
    return CBB_flush(out);
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_set_type(
    mut p7: *mut PKCS7,
    mut type_0: libc::c_int,
) -> libc::c_int {
    if p7.is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            203 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut obj: *mut ASN1_OBJECT = OBJ_nid2obj(type_0);
    if obj.is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            107 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            208 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    match type_0 {
        22 => {
            (*p7).type_0 = obj;
            PKCS7_SIGNED_free((*p7).d.sign);
            (*p7).d.sign = PKCS7_SIGNED_new();
            if ((*p7).d.sign).is_null() {
                return 0 as libc::c_int;
            }
            if ASN1_INTEGER_set(
                (*(*p7).d.sign).version,
                1 as libc::c_int as libc::c_long,
            ) == 0
            {
                PKCS7_SIGNED_free((*p7).d.sign);
                (*p7).d.sign = 0 as *mut PKCS7_SIGNED;
                return 0 as libc::c_int;
            }
        }
        25 => {
            (*p7).type_0 = obj;
            PKCS7_DIGEST_free((*p7).d.digest);
            (*p7).d.digest = PKCS7_DIGEST_new();
            if ((*p7).d.digest).is_null() {
                return 0 as libc::c_int;
            }
            if ASN1_INTEGER_set(
                (*(*p7).d.digest).version,
                0 as libc::c_int as libc::c_long,
            ) == 0
            {
                PKCS7_DIGEST_free((*p7).d.digest);
                (*p7).d.digest = 0 as *mut PKCS7_DIGEST;
                return 0 as libc::c_int;
            }
        }
        21 => {
            (*p7).type_0 = obj;
            ASN1_OCTET_STRING_free((*p7).d.data);
            (*p7).d.data = ASN1_OCTET_STRING_new();
            if ((*p7).d.data).is_null() {
                return 0 as libc::c_int;
            }
        }
        24 => {
            (*p7).type_0 = obj;
            PKCS7_SIGN_ENVELOPE_free((*p7).d.signed_and_enveloped);
            (*p7).d.signed_and_enveloped = PKCS7_SIGN_ENVELOPE_new();
            if ((*p7).d.signed_and_enveloped).is_null() {
                return 0 as libc::c_int;
            }
            if ASN1_INTEGER_set(
                (*(*p7).d.signed_and_enveloped).version,
                1 as libc::c_int as libc::c_long,
            ) == 0
            {
                PKCS7_SIGN_ENVELOPE_free((*p7).d.signed_and_enveloped);
                (*p7).d.signed_and_enveloped = 0 as *mut PKCS7_SIGN_ENVELOPE;
                return 0 as libc::c_int;
            }
            (*(*(*p7).d.signed_and_enveloped).enc_data)
                .content_type = OBJ_nid2obj(21 as libc::c_int);
        }
        23 => {
            (*p7).type_0 = obj;
            PKCS7_ENVELOPE_free((*p7).d.enveloped);
            (*p7).d.enveloped = PKCS7_ENVELOPE_new();
            if ((*p7).d.enveloped).is_null() {
                return 0 as libc::c_int;
            }
            if ASN1_INTEGER_set(
                (*(*p7).d.enveloped).version,
                0 as libc::c_int as libc::c_long,
            ) == 0
            {
                PKCS7_ENVELOPE_free((*p7).d.enveloped);
                (*p7).d.enveloped = 0 as *mut PKCS7_ENVELOPE;
                return 0 as libc::c_int;
            }
            (*(*(*p7).d.enveloped).enc_data)
                .content_type = OBJ_nid2obj(21 as libc::c_int);
        }
        26 => {
            (*p7).type_0 = obj;
            PKCS7_ENCRYPT_free((*p7).d.encrypted);
            (*p7).d.encrypted = PKCS7_ENCRYPT_new();
            if ((*p7).d.encrypted).is_null() {
                return 0 as libc::c_int;
            }
            if ASN1_INTEGER_set(
                (*(*p7).d.encrypted).version,
                0 as libc::c_int as libc::c_long,
            ) == 0
            {
                PKCS7_ENCRYPT_free((*p7).d.encrypted);
                (*p7).d.encrypted = 0 as *mut PKCS7_ENCRYPT;
                return 0 as libc::c_int;
            }
            (*(*(*p7).d.encrypted).enc_data)
                .content_type = OBJ_nid2obj(21 as libc::c_int);
        }
        _ => {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                107 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                    as *const libc::c_char,
                291 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_set_cipher(
    mut p7: *mut PKCS7,
    mut cipher: *const EVP_CIPHER,
) -> libc::c_int {
    if p7.is_null() || cipher.is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            299 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (EVP_get_cipherbynid(EVP_CIPHER_nid(cipher))).is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            123 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            303 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ec: *mut PKCS7_ENC_CONTENT = 0 as *mut PKCS7_ENC_CONTENT;
    match OBJ_obj2nid((*p7).type_0) {
        24 => {
            ec = (*(*p7).d.signed_and_enveloped).enc_data;
        }
        23 => {
            ec = (*(*p7).d.enveloped).enc_data;
        }
        _ => {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                110 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                    as *const libc::c_char,
                316 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    }
    (*ec).cipher = cipher;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_set_content(
    mut p7: *mut PKCS7,
    mut p7_data: *mut PKCS7,
) -> libc::c_int {
    if p7.is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            326 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    match OBJ_obj2nid((*p7).type_0) {
        22 => {
            PKCS7_free((*(*p7).d.sign).contents);
            (*(*p7).d.sign).contents = p7_data;
        }
        25 => {
            PKCS7_free((*(*p7).d.digest).contents);
            (*(*p7).d.digest).contents = p7_data;
        }
        _ => {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                107 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                    as *const libc::c_char,
                340 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_content_new(
    mut p7: *mut PKCS7,
    mut type_0: libc::c_int,
) -> libc::c_int {
    let mut ret: *mut PKCS7 = PKCS7_new();
    if !ret.is_null() {
        if !(PKCS7_set_type(ret, type_0) == 0) {
            if !(PKCS7_set_content(p7, ret) == 0) {
                return 1 as libc::c_int;
            }
        }
    }
    PKCS7_free(ret);
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_add_recipient_info(
    mut p7: *mut PKCS7,
    mut ri: *mut PKCS7_RECIP_INFO,
) -> libc::c_int {
    let mut sk: *mut stack_st_PKCS7_RECIP_INFO = 0 as *mut stack_st_PKCS7_RECIP_INFO;
    if p7.is_null() || ri.is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            367 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    match OBJ_obj2nid((*p7).type_0) {
        24 => {
            sk = (*(*p7).d.signed_and_enveloped).recipientinfo;
        }
        23 => {
            sk = (*(*p7).d.enveloped).recipientinfo;
        }
        _ => {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                110 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                    as *const libc::c_char,
                379 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    }
    if sk_PKCS7_RECIP_INFO_push(sk, ri) == 0 {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_add_signer(
    mut p7: *mut PKCS7,
    mut p7i: *mut PKCS7_SIGNER_INFO,
) -> libc::c_int {
    if p7.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            390 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if p7i.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            391 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut obj: *mut ASN1_OBJECT = 0 as *mut ASN1_OBJECT;
    let mut alg: *mut X509_ALGOR = 0 as *mut X509_ALGOR;
    let mut signer_sk: *mut stack_st_PKCS7_SIGNER_INFO = 0
        as *mut stack_st_PKCS7_SIGNER_INFO;
    let mut md_sk: *mut stack_st_X509_ALGOR = 0 as *mut stack_st_X509_ALGOR;
    match OBJ_obj2nid((*p7).type_0) {
        22 => {
            signer_sk = (*(*p7).d.sign).signer_info;
            md_sk = (*(*p7).d.sign).md_algs;
        }
        24 => {
            signer_sk = (*(*p7).d.signed_and_enveloped).signer_info;
            md_sk = (*(*p7).d.signed_and_enveloped).md_algs;
        }
        _ => {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                110 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                    as *const libc::c_char,
                407 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    }
    obj = (*(*p7i).digest_alg).algorithm;
    let mut alg_found: libc::c_int = 0 as libc::c_int;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_X509_ALGOR_num(md_sk) {
        alg = sk_X509_ALGOR_value(md_sk, i);
        if OBJ_cmp(obj, (*alg).algorithm) == 0 as libc::c_int {
            alg_found = 1 as libc::c_int;
            break;
        } else {
            i = i.wrapping_add(1);
            i;
        }
    }
    if alg_found == 0 {
        alg = X509_ALGOR_new();
        if alg.is_null()
            || {
                (*alg).parameter = ASN1_TYPE_new();
                ((*alg).parameter).is_null()
            }
        {
            X509_ALGOR_free(alg);
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                12 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                    as *const libc::c_char,
                425 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        let mut nid: libc::c_int = OBJ_obj2nid(obj);
        if nid != 0 as libc::c_int {
            (*alg).algorithm = OBJ_nid2obj(nid);
        } else {
            (*alg).algorithm = OBJ_dup(obj);
        }
        (*(*alg).parameter).type_0 = 5 as libc::c_int;
        if ((*alg).algorithm).is_null() || sk_X509_ALGOR_push(md_sk, alg) == 0 {
            X509_ALGOR_free(alg);
            return 0 as libc::c_int;
        }
    }
    if sk_PKCS7_SIGNER_INFO_push(signer_sk, p7i) == 0 {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn get_attribute(
    mut sk: *mut stack_st_X509_ATTRIBUTE,
    mut nid: libc::c_int,
) -> *mut ASN1_TYPE {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_X509_ATTRIBUTE_num(sk) {
        let mut attr: *mut X509_ATTRIBUTE = sk_X509_ATTRIBUTE_value(sk, i);
        let mut obj: *mut ASN1_OBJECT = X509_ATTRIBUTE_get0_object(attr);
        if OBJ_obj2nid(obj) == nid {
            return X509_ATTRIBUTE_get0_type(attr, 0 as libc::c_int);
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as *mut ASN1_TYPE;
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_get_signed_attribute(
    mut si: *const PKCS7_SIGNER_INFO,
    mut nid: libc::c_int,
) -> *mut ASN1_TYPE {
    if si.is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            462 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut ASN1_TYPE;
    }
    return get_attribute((*si).auth_attr, nid);
}
unsafe extern "C" fn PKCS7_digest_from_attributes(
    mut sk: *mut stack_st_X509_ATTRIBUTE,
) -> *mut ASN1_OCTET_STRING {
    if sk.is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            471 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut ASN1_OCTET_STRING;
    }
    let mut astype: *mut ASN1_TYPE = get_attribute(sk, 51 as libc::c_int);
    if astype.is_null() {
        return 0 as *mut ASN1_OCTET_STRING;
    }
    return (*astype).value.octet_string;
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_get_signer_info(
    mut p7: *mut PKCS7,
) -> *mut stack_st_PKCS7_SIGNER_INFO {
    if p7.is_null() || ((*p7).d.ptr).is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            483 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut stack_st_PKCS7_SIGNER_INFO;
    }
    match OBJ_obj2nid((*p7).type_0) {
        22 => return (*(*p7).d.sign).signer_info,
        24 => return (*(*p7).d.signed_and_enveloped).signer_info,
        _ => return 0 as *mut stack_st_PKCS7_SIGNER_INFO,
    };
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_SIGNER_INFO_set(
    mut p7i: *mut PKCS7_SIGNER_INFO,
    mut x509: *mut X509,
    mut pkey: *mut EVP_PKEY,
    mut dgst: *const EVP_MD,
) -> libc::c_int {
    if p7i.is_null() || x509.is_null() || pkey.is_null() || dgst.is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            500 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    } else if ASN1_INTEGER_set((*p7i).version, 1 as libc::c_int as libc::c_long) == 0 {
        return 0 as libc::c_int
    } else if X509_NAME_set(
        &mut (*(*p7i).issuer_and_serial).issuer,
        X509_get_issuer_name(x509),
    ) == 0
    {
        return 0 as libc::c_int
    }
    ASN1_INTEGER_free((*(*p7i).issuer_and_serial).serial);
    (*(*p7i).issuer_and_serial).serial = ASN1_INTEGER_dup(X509_get0_serialNumber(x509));
    if ((*(*p7i).issuer_and_serial).serial).is_null() {
        return 0 as libc::c_int;
    }
    EVP_PKEY_free((*p7i).pkey);
    EVP_PKEY_up_ref(pkey);
    (*p7i).pkey = pkey;
    if X509_ALGOR_set0(
        (*p7i).digest_alg,
        OBJ_nid2obj(EVP_MD_type(dgst)),
        5 as libc::c_int,
        0 as *mut libc::c_void,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    match EVP_PKEY_id(pkey) {
        408 | 28 => {
            let mut snid: libc::c_int = 0;
            let mut hnid: libc::c_int = 0;
            let mut alg1: *mut X509_ALGOR = 0 as *mut X509_ALGOR;
            let mut alg2: *mut X509_ALGOR = 0 as *mut X509_ALGOR;
            PKCS7_SIGNER_INFO_get0_algs(
                p7i,
                0 as *mut *mut EVP_PKEY,
                &mut alg1,
                &mut alg2,
            );
            if alg1.is_null() || ((*alg1).algorithm).is_null() {
                return 0 as libc::c_int;
            }
            hnid = OBJ_obj2nid((*alg1).algorithm);
            if hnid == 0 as libc::c_int
                || OBJ_find_sigid_by_algs(&mut snid, hnid, EVP_PKEY_id(pkey)) == 0
                || X509_ALGOR_set0(
                    alg2,
                    OBJ_nid2obj(snid),
                    -(1 as libc::c_int),
                    0 as *mut libc::c_void,
                ) == 0
            {
                return 0 as libc::c_int;
            }
        }
        6 | 912 => {
            let mut alg: *mut X509_ALGOR = 0 as *mut X509_ALGOR;
            PKCS7_SIGNER_INFO_get0_algs(
                p7i,
                0 as *mut *mut EVP_PKEY,
                0 as *mut *mut X509_ALGOR,
                &mut alg,
            );
            if !alg.is_null() {
                return X509_ALGOR_set0(
                    alg,
                    OBJ_nid2obj(6 as libc::c_int),
                    5 as libc::c_int,
                    0 as *mut libc::c_void,
                );
            }
        }
        _ => {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                124 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                    as *const libc::c_char,
                554 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_RECIP_INFO_set(
    mut p7i: *mut PKCS7_RECIP_INFO,
    mut x509: *mut X509,
) -> libc::c_int {
    if p7i.is_null() || x509.is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            563 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ASN1_INTEGER_set((*p7i).version, 0 as libc::c_int as libc::c_long) == 0 {
        return 0 as libc::c_int
    } else if X509_NAME_set(
        &mut (*(*p7i).issuer_and_serial).issuer,
        X509_get_issuer_name(x509),
    ) == 0
    {
        return 0 as libc::c_int
    }
    ASN1_INTEGER_free((*(*p7i).issuer_and_serial).serial);
    (*(*p7i).issuer_and_serial).serial = ASN1_INTEGER_dup(X509_get0_serialNumber(x509));
    if ((*(*p7i).issuer_and_serial).serial).is_null() {
        return 0 as libc::c_int;
    }
    let mut pkey: *mut EVP_PKEY = X509_get0_pubkey(x509);
    if pkey.is_null() {
        return 0 as libc::c_int;
    }
    if EVP_PKEY_id(pkey) == 912 as libc::c_int {
        return 0 as libc::c_int
    } else if EVP_PKEY_id(pkey) == 6 as libc::c_int {
        let mut alg: *mut X509_ALGOR = 0 as *mut X509_ALGOR;
        PKCS7_RECIP_INFO_get0_alg(p7i, &mut alg);
        if X509_ALGOR_set0(
            alg,
            OBJ_nid2obj(6 as libc::c_int),
            5 as libc::c_int,
            0 as *mut libc::c_void,
        ) == 0
        {
            return 0 as libc::c_int;
        }
    }
    X509_free((*p7i).cert);
    X509_up_ref(x509);
    (*p7i).cert = x509;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_SIGNER_INFO_get0_algs(
    mut si: *mut PKCS7_SIGNER_INFO,
    mut pk: *mut *mut EVP_PKEY,
    mut pdig: *mut *mut X509_ALGOR,
    mut psig: *mut *mut X509_ALGOR,
) {
    if si.is_null() {
        return;
    }
    if !pk.is_null() {
        *pk = (*si).pkey;
    }
    if !pdig.is_null() {
        *pdig = (*si).digest_alg;
    }
    if !psig.is_null() {
        *psig = (*si).digest_enc_alg;
    }
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_RECIP_INFO_get0_alg(
    mut ri: *mut PKCS7_RECIP_INFO,
    mut penc: *mut *mut X509_ALGOR,
) {
    if ri.is_null() {
        return;
    }
    if !penc.is_null() {
        *penc = (*ri).key_enc_algor;
    }
}
unsafe extern "C" fn PKCS7_get_octet_string(
    mut p7: *mut PKCS7,
) -> *mut ASN1_OCTET_STRING {
    if p7.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            630 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut ASN1_OCTET_STRING;
    }
    if PKCS7_type_is_data(p7) != 0 {
        return (*p7).d.data;
    }
    return 0 as *mut ASN1_OCTET_STRING;
}
unsafe extern "C" fn pkcs7_bio_add_digest(
    mut pbio: *mut *mut BIO,
    mut alg: *mut X509_ALGOR,
) -> libc::c_int {
    let mut current_block: u64;
    if pbio.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            638 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if alg.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            639 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut btmp: *mut BIO = 0 as *mut BIO;
    let mut md: *const EVP_MD = EVP_get_digestbynid(OBJ_obj2nid((*alg).algorithm));
    if md.is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            644 as libc::c_int as libc::c_uint,
        );
    } else {
        btmp = BIO_new(BIO_f_md());
        if btmp.is_null() {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                17 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                    as *const libc::c_char,
                649 as libc::c_int as libc::c_uint,
            );
        } else if BIO_set_md(btmp, md as *mut EVP_MD) <= 0 as libc::c_int {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                17 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                    as *const libc::c_char,
                654 as libc::c_int as libc::c_uint,
            );
        } else {
            if (*pbio).is_null() {
                *pbio = btmp;
                current_block = 4808432441040389987;
            } else if (BIO_push(*pbio, btmp)).is_null() {
                ERR_put_error(
                    18 as libc::c_int,
                    0 as libc::c_int,
                    17 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                        as *const u8 as *const libc::c_char,
                    660 as libc::c_int as libc::c_uint,
                );
                current_block = 15495884845292841460;
            } else {
                current_block = 4808432441040389987;
            }
            match current_block {
                15495884845292841460 => {}
                _ => return 1 as libc::c_int,
            }
        }
    }
    BIO_free(btmp);
    return 0 as libc::c_int;
}
unsafe extern "C" fn pkcs7_encode_rinfo(
    mut ri: *mut PKCS7_RECIP_INFO,
    mut key: *mut libc::c_uchar,
    mut keylen: libc::c_int,
) -> libc::c_int {
    if ri.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            673 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if key.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            674 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut pctx: *mut EVP_PKEY_CTX = 0 as *mut EVP_PKEY_CTX;
    let mut pkey: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
    let mut ek: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut eklen: size_t = 0;
    pkey = X509_get0_pubkey((*ri).cert);
    if !pkey.is_null() {
        pctx = EVP_PKEY_CTX_new(pkey, 0 as *mut ENGINE);
        if !(pctx.is_null() || EVP_PKEY_encrypt_init(pctx) <= 0 as libc::c_int
            || EVP_PKEY_encrypt(
                pctx,
                0 as *mut uint8_t,
                &mut eklen,
                key,
                keylen as size_t,
            ) <= 0 as libc::c_int
            || {
                ek = OPENSSL_malloc(eklen) as *mut libc::c_uchar;
                ek.is_null()
            }
            || EVP_PKEY_encrypt(pctx, ek, &mut eklen, key, keylen as size_t)
                <= 0 as libc::c_int)
        {
            ASN1_STRING_set0(
                (*ri).enc_key,
                ek as *mut libc::c_void,
                eklen as libc::c_int,
            );
            ek = 0 as *mut libc::c_uchar;
            ret = 1 as libc::c_int;
        }
    }
    EVP_PKEY_CTX_free(pctx);
    OPENSSL_free(ek as *mut libc::c_void);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_dataInit(
    mut p7: *mut PKCS7,
    mut bio: *mut BIO,
) -> *mut BIO {
    let mut current_block: u64;
    if p7.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            705 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut BIO;
    }
    let mut out: *mut BIO = 0 as *mut BIO;
    let mut btmp: *mut BIO = 0 as *mut BIO;
    let mut evp_cipher: *const EVP_CIPHER = 0 as *const EVP_CIPHER;
    let mut rsk: *mut stack_st_PKCS7_RECIP_INFO = 0 as *mut stack_st_PKCS7_RECIP_INFO;
    let mut md_sk: *mut stack_st_X509_ALGOR = 0 as *mut stack_st_X509_ALGOR;
    let mut xalg: *mut X509_ALGOR = 0 as *mut X509_ALGOR;
    let mut ri: *mut PKCS7_RECIP_INFO = 0 as *mut PKCS7_RECIP_INFO;
    let mut content: *mut ASN1_OCTET_STRING = 0 as *mut ASN1_OCTET_STRING;
    if ((*p7).d.ptr).is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            720 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut BIO;
    }
    match OBJ_obj2nid((*p7).type_0) {
        22 => {
            md_sk = (*(*p7).d.sign).md_algs;
            content = PKCS7_get_octet_string((*(*p7).d.sign).contents);
            current_block = 15925075030174552612;
        }
        24 => {
            md_sk = (*(*p7).d.signed_and_enveloped).md_algs;
            rsk = (*(*p7).d.signed_and_enveloped).recipientinfo;
            xalg = (*(*(*p7).d.signed_and_enveloped).enc_data).algorithm;
            evp_cipher = (*(*(*p7).d.signed_and_enveloped).enc_data).cipher;
            if evp_cipher.is_null() {
                ERR_put_error(
                    18 as libc::c_int,
                    0 as libc::c_int,
                    106 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                        as *const u8 as *const libc::c_char,
                    735 as libc::c_int as libc::c_uint,
                );
                current_block = 11858205456395594388;
            } else {
                current_block = 15925075030174552612;
            }
        }
        23 => {
            rsk = (*(*p7).d.enveloped).recipientinfo;
            xalg = (*(*(*p7).d.enveloped).enc_data).algorithm;
            evp_cipher = (*(*(*p7).d.enveloped).enc_data).cipher;
            if evp_cipher.is_null() {
                ERR_put_error(
                    18 as libc::c_int,
                    0 as libc::c_int,
                    106 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                        as *const u8 as *const libc::c_char,
                    744 as libc::c_int as libc::c_uint,
                );
                current_block = 11858205456395594388;
            } else {
                current_block = 15925075030174552612;
            }
        }
        25 => {
            content = PKCS7_get_octet_string((*(*p7).d.digest).contents);
            if pkcs7_bio_add_digest(&mut out, (*(*p7).d.digest).digest_alg) == 0 {
                current_block = 11858205456395594388;
            } else {
                current_block = 15925075030174552612;
            }
        }
        21 => {
            current_block = 15925075030174552612;
        }
        _ => {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                107 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                    as *const libc::c_char,
                757 as libc::c_int as libc::c_uint,
            );
            current_block = 11858205456395594388;
        }
    }
    match current_block {
        15925075030174552612 => {
            let mut i: size_t = 0 as libc::c_int as size_t;
            loop {
                if !(i < sk_X509_ALGOR_num(md_sk)) {
                    current_block = 2569451025026770673;
                    break;
                }
                if pkcs7_bio_add_digest(&mut out, sk_X509_ALGOR_value(md_sk, i)) == 0 {
                    current_block = 11858205456395594388;
                    break;
                }
                i = i.wrapping_add(1);
                i;
            }
            match current_block {
                11858205456395594388 => {}
                _ => {
                    if !evp_cipher.is_null() {
                        let mut key: [libc::c_uchar; 64] = [0; 64];
                        let mut iv: [libc::c_uchar; 16] = [0; 16];
                        let mut keylen: libc::c_int = 0;
                        let mut ivlen: libc::c_int = 0;
                        let mut ctx: *mut EVP_CIPHER_CTX = 0 as *mut EVP_CIPHER_CTX;
                        btmp = BIO_new(BIO_f_cipher());
                        if btmp.is_null() {
                            ERR_put_error(
                                18 as libc::c_int,
                                0 as libc::c_int,
                                17 as libc::c_int,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                                    as *const u8 as *const libc::c_char,
                                775 as libc::c_int as libc::c_uint,
                            );
                            current_block = 11858205456395594388;
                        } else if BIO_get_cipher_ctx(btmp, &mut ctx) == 0 {
                            ERR_put_error(
                                18 as libc::c_int,
                                0 as libc::c_int,
                                17 as libc::c_int,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                                    as *const u8 as *const libc::c_char,
                                779 as libc::c_int as libc::c_uint,
                            );
                            current_block = 11858205456395594388;
                        } else {
                            keylen = EVP_CIPHER_key_length(evp_cipher) as libc::c_int;
                            ivlen = EVP_CIPHER_iv_length(evp_cipher) as libc::c_int;
                            ASN1_OBJECT_free((*xalg).algorithm);
                            (*xalg).algorithm = OBJ_nid2obj(EVP_CIPHER_nid(evp_cipher));
                            if ivlen > 0 as libc::c_int {
                                RAND_bytes(iv.as_mut_ptr(), ivlen as size_t);
                            }
                            if keylen > 0 as libc::c_int {
                                RAND_bytes(key.as_mut_ptr(), keylen as size_t);
                            }
                            if EVP_CipherInit_ex(
                                ctx,
                                evp_cipher,
                                0 as *mut ENGINE,
                                key.as_mut_ptr(),
                                iv.as_mut_ptr(),
                                1 as libc::c_int,
                            ) <= 0 as libc::c_int
                            {
                                current_block = 11858205456395594388;
                            } else {
                                if ivlen > 0 as libc::c_int {
                                    ASN1_TYPE_free((*xalg).parameter);
                                    (*xalg).parameter = ASN1_TYPE_new();
                                    if ((*xalg).parameter).is_null() {
                                        current_block = 11858205456395594388;
                                    } else {
                                        (*(*xalg).parameter).type_0 = 4 as libc::c_int;
                                        (*(*xalg).parameter)
                                            .value
                                            .octet_string = ASN1_OCTET_STRING_new();
                                        if ASN1_OCTET_STRING_set(
                                            (*(*xalg).parameter).value.octet_string,
                                            iv.as_mut_ptr(),
                                            ivlen,
                                        ) == 0
                                        {
                                            current_block = 11858205456395594388;
                                        } else {
                                            current_block = 13321564401369230990;
                                        }
                                    }
                                } else {
                                    current_block = 13321564401369230990;
                                }
                                match current_block {
                                    11858205456395594388 => {}
                                    _ => {
                                        let mut i_0: size_t = 0 as libc::c_int as size_t;
                                        loop {
                                            if !(i_0 < sk_PKCS7_RECIP_INFO_num(rsk)) {
                                                current_block = 13325891313334703151;
                                                break;
                                            }
                                            ri = sk_PKCS7_RECIP_INFO_value(rsk, i_0);
                                            if pkcs7_encode_rinfo(ri, key.as_mut_ptr(), keylen)
                                                <= 0 as libc::c_int
                                            {
                                                current_block = 11858205456395594388;
                                                break;
                                            }
                                            i_0 = i_0.wrapping_add(1);
                                            i_0;
                                        }
                                        match current_block {
                                            11858205456395594388 => {}
                                            _ => {
                                                OPENSSL_cleanse(
                                                    key.as_mut_ptr() as *mut libc::c_void,
                                                    keylen as size_t,
                                                );
                                                if out.is_null() {
                                                    out = btmp;
                                                } else {
                                                    BIO_push(out, btmp);
                                                }
                                                btmp = 0 as *mut BIO;
                                                current_block = 15594603006322722090;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        current_block = 15594603006322722090;
                    }
                    match current_block {
                        11858205456395594388 => {}
                        _ => {
                            if bio.is_null() {
                                bio = BIO_new(BIO_s_mem());
                                if bio.is_null() {
                                    current_block = 11858205456395594388;
                                } else {
                                    BIO_set_mem_eof_return(bio, 0 as libc::c_int);
                                    if PKCS7_is_detached(p7) == 0 && !content.is_null()
                                        && (*content).length > 0 as libc::c_int
                                    {
                                        if BIO_write(
                                            bio,
                                            (*content).data as *const libc::c_void,
                                            (*content).length,
                                        ) != (*content).length
                                        {
                                            current_block = 11858205456395594388;
                                        } else {
                                            current_block = 18038362259723567392;
                                        }
                                    } else {
                                        current_block = 18038362259723567392;
                                    }
                                }
                            } else {
                                current_block = 18038362259723567392;
                            }
                            match current_block {
                                11858205456395594388 => {}
                                _ => {
                                    if !out.is_null() {
                                        BIO_push(out, bio);
                                    } else {
                                        out = bio;
                                    }
                                    return out;
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    BIO_free_all(out);
    BIO_free_all(btmp);
    return 0 as *mut BIO;
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_is_detached(mut p7: *mut PKCS7) -> libc::c_int {
    if p7.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            856 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if PKCS7_type_is_signed(p7) != 0 {
        return (((*p7).d.sign).is_null()
            || ((*(*(*p7).d.sign).contents).d.ptr).is_null()) as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_set_detached(
    mut p7: *mut PKCS7,
    mut detach: libc::c_int,
) -> libc::c_int {
    if p7.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            864 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if detach != 0 as libc::c_int && detach != 1 as libc::c_int {
        return 0 as libc::c_int;
    }
    if PKCS7_type_is_signed(p7) != 0 {
        if ((*p7).d.sign).is_null() {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                105 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                    as *const libc::c_char,
                872 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        if detach != 0 && PKCS7_type_is_data((*(*p7).d.sign).contents) != 0 {
            ASN1_OCTET_STRING_free((*(*(*p7).d.sign).contents).d.data);
            (*(*(*p7).d.sign).contents).d.data = 0 as *mut ASN1_OCTET_STRING;
        }
        return detach;
    } else {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            135 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            881 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    };
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_get_detached(mut p7: *mut PKCS7) -> libc::c_int {
    return PKCS7_is_detached(p7);
}
unsafe extern "C" fn pkcs7_find_digest(
    mut pmd: *mut *mut EVP_MD_CTX,
    mut bio: *mut BIO,
    mut nid: libc::c_int,
) -> *mut BIO {
    if pmd.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            890 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut BIO;
    }
    while !bio.is_null() {
        bio = BIO_find_type(bio, 8 as libc::c_int | 0x200 as libc::c_int);
        if bio.is_null() {
            return 0 as *mut BIO;
        }
        if BIO_get_md_ctx(bio, pmd) == 0 || (*pmd).is_null() {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                4 as libc::c_int | 64 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                    as *const libc::c_char,
                897 as libc::c_int as libc::c_uint,
            );
            return 0 as *mut BIO;
        }
        if EVP_MD_CTX_type(*pmd) == nid {
            return bio;
        }
        bio = BIO_next(bio);
    }
    ERR_put_error(
        18 as libc::c_int,
        0 as libc::c_int,
        108 as libc::c_int,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
            as *const libc::c_char,
        905 as libc::c_int as libc::c_uint,
    );
    return 0 as *mut BIO;
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_set_digest(
    mut p7: *mut PKCS7,
    mut md: *const EVP_MD,
) -> libc::c_int {
    if p7.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            910 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if md.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            911 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    match OBJ_obj2nid((*p7).type_0) {
        25 => {
            if EVP_MD_nid(md) == 0 as libc::c_int {
                ERR_put_error(
                    18 as libc::c_int,
                    0 as libc::c_int,
                    125 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                        as *const u8 as *const libc::c_char,
                    915 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            if ((*(*p7).d.digest).digest_alg).is_null() {
                ERR_put_error(
                    18 as libc::c_int,
                    0 as libc::c_int,
                    12 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                        as *const u8 as *const libc::c_char,
                    919 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            OPENSSL_free((*(*(*p7).d.digest).digest_alg).parameter as *mut libc::c_void);
            (*(*(*p7).d.digest).digest_alg).parameter = ASN1_TYPE_new();
            if ((*(*(*p7).d.digest).digest_alg).parameter).is_null() {
                ERR_put_error(
                    18 as libc::c_int,
                    0 as libc::c_int,
                    12 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                        as *const u8 as *const libc::c_char,
                    924 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            (*(*p7).d.digest).md = md;
            (*(*(*(*p7).d.digest).digest_alg).parameter).type_0 = 5 as libc::c_int;
            (*(*(*p7).d.digest).digest_alg).algorithm = OBJ_nid2obj(EVP_MD_nid(md));
            return 1 as libc::c_int;
        }
        _ => {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                110 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                    as *const libc::c_char,
                932 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_get_recipient_info(
    mut p7: *mut PKCS7,
) -> *mut stack_st_PKCS7_RECIP_INFO {
    if p7.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            939 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut stack_st_PKCS7_RECIP_INFO;
    }
    if ((*p7).d.ptr).is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            940 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut stack_st_PKCS7_RECIP_INFO;
    }
    match OBJ_obj2nid((*p7).type_0) {
        23 => return (*(*p7).d.enveloped).recipientinfo,
        _ => return 0 as *mut stack_st_PKCS7_RECIP_INFO,
    };
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_dataFinal(
    mut p7: *mut PKCS7,
    mut bio: *mut BIO,
) -> libc::c_int {
    let mut current_block: u64;
    if p7.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            950 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if bio.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            951 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut bio_tmp: *mut BIO = 0 as *mut BIO;
    let mut si: *mut PKCS7_SIGNER_INFO = 0 as *mut PKCS7_SIGNER_INFO;
    let mut md_ctx: *mut EVP_MD_CTX = 0 as *mut EVP_MD_CTX;
    let mut md_ctx_tmp: *mut EVP_MD_CTX = 0 as *mut EVP_MD_CTX;
    let mut si_sk: *mut stack_st_PKCS7_SIGNER_INFO = 0
        as *mut stack_st_PKCS7_SIGNER_INFO;
    let mut content: *mut ASN1_OCTET_STRING = 0 as *mut ASN1_OCTET_STRING;
    if ((*p7).d.ptr).is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            960 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    md_ctx_tmp = EVP_MD_CTX_new();
    if md_ctx_tmp.is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            6 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            966 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    match OBJ_obj2nid((*p7).type_0) {
        21 => {
            content = (*p7).d.data;
            current_block = 3938820862080741272;
        }
        24 => {
            si_sk = (*(*p7).d.signed_and_enveloped).signer_info;
            content = (*(*(*p7).d.signed_and_enveloped).enc_data).enc_data;
            if content.is_null() {
                content = ASN1_OCTET_STRING_new();
                if content.is_null() {
                    ERR_put_error(
                        18 as libc::c_int,
                        0 as libc::c_int,
                        12 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                            as *const u8 as *const libc::c_char,
                        980 as libc::c_int as libc::c_uint,
                    );
                    current_block = 16515462738276716790;
                } else {
                    (*(*(*p7).d.signed_and_enveloped).enc_data).enc_data = content;
                    current_block = 3938820862080741272;
                }
            } else {
                current_block = 3938820862080741272;
            }
        }
        23 => {
            content = (*(*(*p7).d.enveloped).enc_data).enc_data;
            if content.is_null() {
                content = ASN1_OCTET_STRING_new();
                if content.is_null() {
                    ERR_put_error(
                        18 as libc::c_int,
                        0 as libc::c_int,
                        12 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                            as *const u8 as *const libc::c_char,
                        991 as libc::c_int as libc::c_uint,
                    );
                    current_block = 16515462738276716790;
                } else {
                    (*(*(*p7).d.enveloped).enc_data).enc_data = content;
                    current_block = 3938820862080741272;
                }
            } else {
                current_block = 3938820862080741272;
            }
        }
        22 => {
            si_sk = (*(*p7).d.sign).signer_info;
            content = PKCS7_get_octet_string((*(*p7).d.sign).contents);
            if PKCS7_type_is_data((*(*p7).d.sign).contents) != 0
                && PKCS7_is_detached(p7) != 0
            {
                ASN1_OCTET_STRING_free(content);
                content = 0 as *mut ASN1_OCTET_STRING;
                (*(*(*p7).d.sign).contents).d.data = 0 as *mut ASN1_OCTET_STRING;
            }
            current_block = 3938820862080741272;
        }
        25 => {
            content = PKCS7_get_octet_string((*(*p7).d.digest).contents);
            if PKCS7_type_is_data((*(*p7).d.digest).contents) != 0
                && PKCS7_is_detached(p7) != 0
            {
                ASN1_OCTET_STRING_free(content);
                content = 0 as *mut ASN1_OCTET_STRING;
                (*(*(*p7).d.digest).contents).d.data = 0 as *mut ASN1_OCTET_STRING;
            }
            current_block = 3938820862080741272;
        }
        _ => {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                107 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                    as *const libc::c_char,
                1021 as libc::c_int as libc::c_uint,
            );
            current_block = 16515462738276716790;
        }
    }
    match current_block {
        3938820862080741272 => {
            if !si_sk.is_null() {
                let mut ii: size_t = 0 as libc::c_int as size_t;
                loop {
                    if !(ii < sk_PKCS7_SIGNER_INFO_num(si_sk)) {
                        current_block = 13707613154239713890;
                        break;
                    }
                    si = sk_PKCS7_SIGNER_INFO_value(si_sk, ii);
                    if !(si.is_null() || ((*si).pkey).is_null()) {
                        let mut sign_nid: libc::c_int = OBJ_obj2nid(
                            (*(*si).digest_alg).algorithm,
                        );
                        bio_tmp = pkcs7_find_digest(&mut md_ctx, bio, sign_nid);
                        if bio_tmp.is_null() {
                            current_block = 16515462738276716790;
                            break;
                        }
                        if EVP_MD_CTX_copy_ex(md_ctx_tmp, md_ctx) == 0 {
                            current_block = 16515462738276716790;
                            break;
                        }
                        if sk_X509_ATTRIBUTE_num((*si).auth_attr)
                            > 0 as libc::c_int as size_t
                        {
                            ERR_put_error(
                                18 as libc::c_int,
                                0 as libc::c_int,
                                122 as libc::c_int,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                                    as *const u8 as *const libc::c_char,
                                1042 as libc::c_int as libc::c_uint,
                            );
                            current_block = 16515462738276716790;
                            break;
                        } else {
                            let mut abuf: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
                            let mut abuflen: libc::c_uint = EVP_PKEY_size((*si).pkey)
                                as libc::c_uint;
                            if abuflen == 0 as libc::c_int as libc::c_uint
                                || {
                                    abuf = OPENSSL_malloc(abuflen as size_t)
                                        as *mut libc::c_uchar;
                                    abuf.is_null()
                                }
                            {
                                current_block = 16515462738276716790;
                                break;
                            }
                            if EVP_SignFinal(md_ctx_tmp, abuf, &mut abuflen, (*si).pkey)
                                == 0
                            {
                                OPENSSL_free(abuf as *mut libc::c_void);
                                ERR_put_error(
                                    18 as libc::c_int,
                                    0 as libc::c_int,
                                    6 as libc::c_int,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                                        as *const u8 as *const libc::c_char,
                                    1055 as libc::c_int as libc::c_uint,
                                );
                                current_block = 16515462738276716790;
                                break;
                            } else {
                                ASN1_STRING_set0(
                                    (*si).enc_digest,
                                    abuf as *mut libc::c_void,
                                    abuflen as libc::c_int,
                                );
                            }
                        }
                    }
                    ii = ii.wrapping_add(1);
                    ii;
                }
            } else if OBJ_obj2nid((*p7).type_0) == 25 as libc::c_int {
                let mut md_data: [libc::c_uchar; 64] = [0; 64];
                let mut md_len: libc::c_uint = 0;
                if (pkcs7_find_digest(
                    &mut md_ctx,
                    bio,
                    EVP_MD_nid((*(*p7).d.digest).md),
                ))
                    .is_null()
                    || EVP_DigestFinal_ex(md_ctx, md_data.as_mut_ptr(), &mut md_len) == 0
                    || ASN1_OCTET_STRING_set(
                        (*(*p7).d.digest).digest,
                        md_data.as_mut_ptr(),
                        md_len as libc::c_int,
                    ) == 0
                {
                    current_block = 16515462738276716790;
                } else {
                    current_block = 13707613154239713890;
                }
            } else {
                current_block = 13707613154239713890;
            }
            match current_block {
                16515462738276716790 => {}
                _ => {
                    if PKCS7_is_detached(p7) == 0 {
                        if content.is_null() {
                            current_block = 16515462738276716790;
                        } else {
                            let mut cont: *const uint8_t = 0 as *const uint8_t;
                            let mut contlen: size_t = 0;
                            bio_tmp = BIO_find_type(
                                bio,
                                1 as libc::c_int | 0x400 as libc::c_int,
                            );
                            if bio_tmp.is_null() {
                                ERR_put_error(
                                    18 as libc::c_int,
                                    0 as libc::c_int,
                                    109 as libc::c_int,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                                        as *const u8 as *const libc::c_char,
                                    1078 as libc::c_int as libc::c_uint,
                                );
                                current_block = 16515462738276716790;
                            } else if BIO_mem_contents(bio_tmp, &mut cont, &mut contlen)
                                == 0
                            {
                                current_block = 16515462738276716790;
                            } else {
                                BIO_set_flags(bio_tmp, 0x200 as libc::c_int);
                                BIO_set_mem_eof_return(bio_tmp, 0 as libc::c_int);
                                ASN1_STRING_set0(
                                    content,
                                    cont as *mut libc::c_uchar as *mut libc::c_void,
                                    contlen as libc::c_int,
                                );
                                current_block = 17239133558811367971;
                            }
                        }
                    } else {
                        current_block = 17239133558811367971;
                    }
                    match current_block {
                        16515462738276716790 => {}
                        _ => {
                            ret = 1 as libc::c_int;
                        }
                    }
                }
            }
        }
        _ => {}
    }
    EVP_MD_CTX_free(md_ctx_tmp);
    return ret;
}
unsafe extern "C" fn pkcs7_bio_copy_content(
    mut src: *mut BIO,
    mut dst: *mut BIO,
) -> libc::c_int {
    let mut current_block: u64;
    let mut buf: [uint8_t; 1024] = [0; 1024];
    let mut bytes_processed: libc::c_int = 0 as libc::c_int;
    let mut ret: libc::c_int = 0 as libc::c_int;
    loop {
        bytes_processed = BIO_read(
            src,
            buf.as_mut_ptr() as *mut libc::c_void,
            ::core::mem::size_of::<[uint8_t; 1024]>() as libc::c_ulong as libc::c_int,
        );
        if !(bytes_processed > 0 as libc::c_int) {
            current_block = 10680521327981672866;
            break;
        }
        if !dst.is_null()
            && BIO_write_all(
                dst,
                buf.as_mut_ptr() as *const libc::c_void,
                bytes_processed as size_t,
            ) == 0
        {
            current_block = 12565901710616911928;
            break;
        }
    }
    match current_block {
        10680521327981672866 => {
            if !(bytes_processed < 0 as libc::c_int
                || !dst.is_null() && BIO_flush(dst) == 0)
            {
                ret = 1 as libc::c_int;
            }
        }
        _ => {}
    }
    OPENSSL_cleanse(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 1024]>() as libc::c_ulong,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn pkcs7_final(
    mut p7: *mut PKCS7,
    mut data: *mut BIO,
) -> libc::c_int {
    let mut p7bio: *mut BIO = 0 as *mut BIO;
    let mut ret: libc::c_int = 0 as libc::c_int;
    p7bio = PKCS7_dataInit(p7, 0 as *mut BIO);
    if p7bio.is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            18 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1124 as libc::c_int as libc::c_uint,
        );
    } else if !(pkcs7_bio_copy_content(data, p7bio) == 0) {
        if PKCS7_dataFinal(p7, p7bio) == 0 {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                18 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                    as *const libc::c_char,
                1133 as libc::c_int as libc::c_uint,
            );
        } else {
            ret = 1 as libc::c_int;
        }
    }
    BIO_free_all(p7bio);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_encrypt(
    mut certs: *mut stack_st_X509,
    mut in_0: *mut BIO,
    mut cipher: *const EVP_CIPHER,
    mut flags: libc::c_int,
) -> *mut PKCS7 {
    let mut current_block: u64;
    if certs.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1145 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut PKCS7;
    }
    if in_0.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1146 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut PKCS7;
    }
    if cipher.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1147 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut PKCS7;
    }
    let mut p7: *mut PKCS7 = 0 as *mut PKCS7;
    let mut x509: *mut X509 = 0 as *mut X509;
    p7 = PKCS7_new();
    if p7.is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            18 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1152 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut PKCS7;
    }
    if PKCS7_set_type(p7, 23 as libc::c_int) == 0 {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            110 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1156 as libc::c_int as libc::c_uint,
        );
    } else if PKCS7_set_cipher(p7, cipher) == 0 {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            118 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1160 as libc::c_int as libc::c_uint,
        );
    } else {
        let mut i: size_t = 0 as libc::c_int as size_t;
        loop {
            if !(i < sk_X509_num(certs)) {
                current_block = 6669252993407410313;
                break;
            }
            x509 = sk_X509_value(certs, i);
            if (PKCS7_add_recipient(p7, x509)).is_null() {
                ERR_put_error(
                    18 as libc::c_int,
                    0 as libc::c_int,
                    119 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                        as *const u8 as *const libc::c_char,
                    1167 as libc::c_int as libc::c_uint,
                );
                current_block = 9515048208466453364;
                break;
            } else {
                i = i.wrapping_add(1);
                i;
            }
        }
        match current_block {
            9515048208466453364 => {}
            _ => {
                if pkcs7_final(p7, in_0) != 0 {
                    return p7;
                }
            }
        }
    }
    PKCS7_free(p7);
    return 0 as *mut PKCS7;
}
unsafe extern "C" fn pkcs7_decrypt_rinfo(
    mut ek_out: *mut *mut libc::c_uchar,
    mut ri: *mut PKCS7_RECIP_INFO,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    let mut len: size_t = 0;
    let mut ok: libc::c_int = 0;
    if ri.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1183 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ek_out.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1184 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ek: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut ctx: *mut EVP_PKEY_CTX = EVP_PKEY_CTX_new(pkey, 0 as *mut ENGINE);
    if !(ctx.is_null() || EVP_PKEY_decrypt_init(ctx) == 0) {
        len = 0;
        if EVP_PKEY_decrypt(
            ctx,
            0 as *mut uint8_t,
            &mut len,
            (*(*ri).enc_key).data,
            (*(*ri).enc_key).length as size_t,
        ) == 0
            || {
                ek = OPENSSL_malloc(len) as *mut libc::c_uchar;
                ek.is_null()
            }
        {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                6 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                    as *const libc::c_char,
                1196 as libc::c_int as libc::c_uint,
            );
        } else {
            ok = EVP_PKEY_decrypt(
                ctx,
                ek,
                &mut len,
                (*(*ri).enc_key).data,
                (*(*ri).enc_key).length as size_t,
            );
            if ok == 0 {
                OPENSSL_free(ek as *mut libc::c_void);
                ek = 0 as *mut libc::c_uchar;
            }
            ret = 1 as libc::c_int;
            *ek_out = ek;
        }
    }
    EVP_PKEY_CTX_free(ctx);
    return ret;
}
unsafe extern "C" fn pkcs7_cmp_ri(
    mut ri: *mut PKCS7_RECIP_INFO,
    mut pcert: *mut X509,
) -> libc::c_int {
    if ri.is_null() || ((*ri).issuer_and_serial).is_null() || pcert.is_null() {
        return 1 as libc::c_int;
    }
    let mut ret: libc::c_int = X509_NAME_cmp(
        (*(*ri).issuer_and_serial).issuer,
        X509_get_issuer_name(pcert),
    );
    if ret != 0 {
        return ret;
    }
    return ASN1_INTEGER_cmp(
        X509_get0_serialNumber(pcert),
        (*(*ri).issuer_and_serial).serial,
    );
}
unsafe extern "C" fn pkcs7_data_decode(
    mut p7: *mut PKCS7,
    mut pkey: *mut EVP_PKEY,
    mut pcert: *mut X509,
) -> *mut BIO {
    let mut evp_ctx: *mut EVP_CIPHER_CTX = 0 as *mut EVP_CIPHER_CTX;
    let mut expected_iv_len: libc::c_int = 0;
    let mut iv: [uint8_t; 16] = [0; 16];
    let mut len: libc::c_int = 0;
    let mut current_block: u64;
    if p7.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1234 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut BIO;
    }
    if pkey.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1235 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut BIO;
    }
    let mut out: *mut BIO = 0 as *mut BIO;
    let mut cipher_bio: *mut BIO = 0 as *mut BIO;
    let mut data_bio: *mut BIO = 0 as *mut BIO;
    let mut data_body: *mut ASN1_OCTET_STRING = 0 as *mut ASN1_OCTET_STRING;
    let mut cipher: *const EVP_CIPHER = 0 as *const EVP_CIPHER;
    let mut enc_alg: *mut X509_ALGOR = 0 as *mut X509_ALGOR;
    let mut rsk: *mut stack_st_PKCS7_RECIP_INFO = 0 as *mut stack_st_PKCS7_RECIP_INFO;
    let mut ri: *mut PKCS7_RECIP_INFO = 0 as *mut PKCS7_RECIP_INFO;
    let mut cek: *mut uint8_t = 0 as *mut uint8_t;
    let mut dummy_key: *mut uint8_t = 0 as *mut uint8_t;
    if ((*p7).d.ptr).is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1245 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut BIO;
    }
    match OBJ_obj2nid((*p7).type_0) {
        23 => {
            rsk = (*(*p7).d.enveloped).recipientinfo;
            enc_alg = (*(*(*p7).d.enveloped).enc_data).algorithm;
            if enc_alg.is_null() || ((*enc_alg).parameter).is_null()
                || ((*(*enc_alg).parameter).value.octet_string).is_null()
                || ((*enc_alg).algorithm).is_null()
            {
                ERR_put_error(
                    18 as libc::c_int,
                    0 as libc::c_int,
                    18 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                        as *const u8 as *const libc::c_char,
                    1256 as libc::c_int as libc::c_uint,
                );
            } else {
                data_body = (*(*(*p7).d.enveloped).enc_data).enc_data;
                cipher = EVP_get_cipherbynid(OBJ_obj2nid((*enc_alg).algorithm));
                if cipher.is_null() {
                    ERR_put_error(
                        18 as libc::c_int,
                        0 as libc::c_int,
                        127 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                            as *const u8 as *const libc::c_char,
                        1263 as libc::c_int as libc::c_uint,
                    );
                } else if data_body.is_null() {
                    ERR_put_error(
                        18 as libc::c_int,
                        0 as libc::c_int,
                        105 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                            as *const u8 as *const libc::c_char,
                        1274 as libc::c_int as libc::c_uint,
                    );
                } else {
                    cipher_bio = BIO_new(BIO_f_cipher());
                    if cipher_bio.is_null() {
                        ERR_put_error(
                            18 as libc::c_int,
                            0 as libc::c_int,
                            17 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                                as *const u8 as *const libc::c_char,
                            1279 as libc::c_int as libc::c_uint,
                        );
                    } else {
                        if !pcert.is_null() {
                            let mut ii: size_t = 0 as libc::c_int as size_t;
                            while ii < sk_PKCS7_RECIP_INFO_num(rsk) {
                                ri = sk_PKCS7_RECIP_INFO_value(rsk, ii);
                                if pkcs7_cmp_ri(ri, pcert) == 0 {
                                    break;
                                }
                                ri = 0 as *mut PKCS7_RECIP_INFO;
                                ii = ii.wrapping_add(1);
                                ii;
                            }
                            if ri.is_null() {
                                ERR_put_error(
                                    18 as libc::c_int,
                                    0 as libc::c_int,
                                    128 as libc::c_int,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                                        as *const u8 as *const libc::c_char,
                                    1309 as libc::c_int as libc::c_uint,
                                );
                                current_block = 2566414484888233258;
                            } else if pkcs7_decrypt_rinfo(&mut cek, ri, pkey) == 0 {
                                current_block = 2566414484888233258;
                            } else {
                                current_block = 1345366029464561491;
                            }
                        } else {
                            let mut ii_0: size_t = 0 as libc::c_int as size_t;
                            loop {
                                if !(ii_0 < sk_PKCS7_RECIP_INFO_num(rsk)) {
                                    current_block = 1345366029464561491;
                                    break;
                                }
                                ri = sk_PKCS7_RECIP_INFO_value(rsk, ii_0);
                                let mut tmp_cek: *mut uint8_t = 0 as *mut uint8_t;
                                if pkcs7_decrypt_rinfo(&mut tmp_cek, ri, pkey) == 0 {
                                    current_block = 2566414484888233258;
                                    break;
                                }
                                if !tmp_cek.is_null() {
                                    OPENSSL_free(cek as *mut libc::c_void);
                                    cek = tmp_cek;
                                }
                                ii_0 = ii_0.wrapping_add(1);
                                ii_0;
                            }
                        }
                        match current_block {
                            2566414484888233258 => {}
                            _ => {
                                ERR_clear_error();
                                evp_ctx = 0 as *mut EVP_CIPHER_CTX;
                                if !(BIO_get_cipher_ctx(cipher_bio, &mut evp_ctx) == 0
                                    || EVP_CipherInit_ex(
                                        evp_ctx,
                                        cipher,
                                        0 as *mut ENGINE,
                                        0 as *const uint8_t,
                                        0 as *const uint8_t,
                                        0 as libc::c_int,
                                    ) == 0)
                                {
                                    expected_iv_len = EVP_CIPHER_CTX_iv_length(evp_ctx)
                                        as libc::c_int;
                                    if (*(*(*enc_alg).parameter).value.octet_string).length
                                        != expected_iv_len
                                    {
                                        ERR_put_error(
                                            18 as libc::c_int,
                                            0 as libc::c_int,
                                            18 as libc::c_int,
                                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                                                as *const u8 as *const libc::c_char,
                                            1348 as libc::c_int as libc::c_uint,
                                        );
                                    } else {
                                        iv = [0; 16];
                                        OPENSSL_memcpy(
                                            iv.as_mut_ptr() as *mut libc::c_void,
                                            (*(*(*enc_alg).parameter).value.octet_string).data
                                                as *const libc::c_void,
                                            expected_iv_len as size_t,
                                        );
                                        if !(EVP_CipherInit_ex(
                                            evp_ctx,
                                            0 as *const EVP_CIPHER,
                                            0 as *mut ENGINE,
                                            0 as *const uint8_t,
                                            iv.as_mut_ptr(),
                                            0 as libc::c_int,
                                        ) == 0)
                                        {
                                            len = EVP_CIPHER_CTX_key_length(evp_ctx) as libc::c_int;
                                            if !(len == 0) {
                                                dummy_key = OPENSSL_malloc(len as size_t) as *mut uint8_t;
                                                RAND_bytes(dummy_key, len as size_t);
                                                if cek.is_null() {
                                                    cek = dummy_key;
                                                    dummy_key = 0 as *mut uint8_t;
                                                }
                                                if !(EVP_CipherInit_ex(
                                                    evp_ctx,
                                                    0 as *const EVP_CIPHER,
                                                    0 as *mut ENGINE,
                                                    cek,
                                                    0 as *const uint8_t,
                                                    0 as libc::c_int,
                                                ) == 0)
                                                {
                                                    OPENSSL_free(cek as *mut libc::c_void);
                                                    OPENSSL_free(dummy_key as *mut libc::c_void);
                                                    cek = 0 as *mut uint8_t;
                                                    dummy_key = 0 as *mut uint8_t;
                                                    out = cipher_bio;
                                                    if (*data_body).length > 0 as libc::c_int {
                                                        data_bio = BIO_new_mem_buf(
                                                            (*data_body).data as *const libc::c_void,
                                                            (*data_body).length as ossl_ssize_t,
                                                        );
                                                        current_block = 1868291631715963762;
                                                    } else {
                                                        data_bio = BIO_new(BIO_s_mem());
                                                        if data_bio.is_null()
                                                            || BIO_set_mem_eof_return(data_bio, 0 as libc::c_int) == 0
                                                        {
                                                            current_block = 2566414484888233258;
                                                        } else {
                                                            current_block = 1868291631715963762;
                                                        }
                                                    }
                                                    match current_block {
                                                        2566414484888233258 => {}
                                                        _ => {
                                                            if !data_bio.is_null() {
                                                                BIO_push(out, data_bio);
                                                                return out;
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
        _ => {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                107 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                    as *const libc::c_char,
                1268 as libc::c_int as libc::c_uint,
            );
        }
    }
    OPENSSL_free(cek as *mut libc::c_void);
    OPENSSL_free(dummy_key as *mut libc::c_void);
    BIO_free_all(out);
    BIO_free_all(cipher_bio);
    BIO_free_all(data_bio);
    return 0 as *mut BIO;
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_add_recipient(
    mut p7: *mut PKCS7,
    mut x509: *mut X509,
) -> *mut PKCS7_RECIP_INFO {
    if p7.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1408 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut PKCS7_RECIP_INFO;
    }
    if x509.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1409 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut PKCS7_RECIP_INFO;
    }
    let mut ri: *mut PKCS7_RECIP_INFO = 0 as *mut PKCS7_RECIP_INFO;
    ri = PKCS7_RECIP_INFO_new();
    if ri.is_null() || PKCS7_RECIP_INFO_set(ri, x509) == 0
        || PKCS7_add_recipient_info(p7, ri) == 0
    {
        PKCS7_RECIP_INFO_free(ri);
        return 0 as *mut PKCS7_RECIP_INFO;
    }
    return ri;
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_decrypt(
    mut p7: *mut PKCS7,
    mut pkey: *mut EVP_PKEY,
    mut cert: *mut X509,
    mut data: *mut BIO,
    mut _flags: libc::c_int,
) -> libc::c_int {
    if p7.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1421 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if pkey.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1422 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if data.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1423 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut bio: *mut BIO = 0 as *mut BIO;
    let mut ret: libc::c_int = 0 as libc::c_int;
    match OBJ_obj2nid((*p7).type_0) {
        23 => {
            if !cert.is_null() && X509_check_private_key(cert, pkey) == 0 {
                ERR_put_error(
                    18 as libc::c_int,
                    0 as libc::c_int,
                    120 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                        as *const u8 as *const libc::c_char,
                    1436 as libc::c_int as libc::c_uint,
                );
            } else {
                bio = pkcs7_data_decode(p7, pkey, cert);
                if bio.is_null() || pkcs7_bio_copy_content(bio, data) == 0 {
                    ERR_put_error(
                        18 as libc::c_int,
                        0 as libc::c_int,
                        121 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                            as *const u8 as *const libc::c_char,
                        1442 as libc::c_int as libc::c_uint,
                    );
                } else if 1 as libc::c_int != BIO_get_cipher_status(bio) {
                    ERR_put_error(
                        18 as libc::c_int,
                        0 as libc::c_int,
                        121 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                            as *const u8 as *const libc::c_char,
                        1448 as libc::c_int as libc::c_uint,
                    );
                } else {
                    ret = 1 as libc::c_int;
                }
            }
        }
        _ => {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                110 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                    as *const libc::c_char,
                1431 as libc::c_int as libc::c_uint,
            );
        }
    }
    BIO_free_all(bio);
    return ret;
}
unsafe extern "C" fn pkcs7_get0_certificates(
    mut p7: *const PKCS7,
) -> *mut stack_st_X509 {
    if p7.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1460 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut stack_st_X509;
    }
    if ((*p7).d.ptr).is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1461 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut stack_st_X509;
    }
    match OBJ_obj2nid((*p7).type_0) {
        22 => return (*(*p7).d.sign).cert,
        _ => return 0 as *mut stack_st_X509,
    };
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_get0_signers(
    mut p7: *mut PKCS7,
    mut certs: *mut stack_st_X509,
    mut flags: libc::c_int,
) -> *mut stack_st_X509 {
    if p7.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1472 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut stack_st_X509;
    }
    let mut signers: *mut stack_st_X509 = 0 as *mut stack_st_X509;
    let mut signer: *mut X509 = 0 as *mut X509;
    let mut included_certs: *mut stack_st_X509 = pkcs7_get0_certificates(p7);
    let mut sinfos: *mut stack_st_PKCS7_SIGNER_INFO = PKCS7_get_signer_info(p7);
    if sk_PKCS7_SIGNER_INFO_num(sinfos) <= 0 as libc::c_int as size_t {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            116 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1480 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut stack_st_X509;
    }
    signers = sk_X509_new_null();
    if signers.is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            14 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1485 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut stack_st_X509;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_PKCS7_SIGNER_INFO_num(sinfos) {
        let mut si: *mut PKCS7_SIGNER_INFO = sk_PKCS7_SIGNER_INFO_value(sinfos, i);
        let mut ias: *mut PKCS7_ISSUER_AND_SERIAL = (*si).issuer_and_serial;
        signer = X509_find_by_issuer_and_serial(certs, (*ias).issuer, (*ias).serial);
        if flags & 0x10 as libc::c_int == 0 && signer.is_null() {
            signer = X509_find_by_issuer_and_serial(
                included_certs,
                (*ias).issuer,
                (*ias).serial,
            );
        }
        if signer.is_null() {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                117 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                    as *const libc::c_char,
                1499 as libc::c_int as libc::c_uint,
            );
            sk_X509_free(signers);
            return 0 as *mut stack_st_X509;
        }
        if sk_X509_push(signers, signer) == 0 {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                18 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                    as *const libc::c_char,
                1504 as libc::c_int as libc::c_uint,
            );
            sk_X509_free(signers);
            return 0 as *mut stack_st_X509;
        }
        i = i.wrapping_add(1);
        i;
    }
    return signers;
}
unsafe extern "C" fn pkcs7_x509_add_cert_new(
    mut p_sk: *mut *mut stack_st_X509,
    mut cert: *mut X509,
) -> libc::c_int {
    if p_sk.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1514 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if !((*p_sk).is_null()
        && {
            *p_sk = sk_X509_new_null();
            (*p_sk).is_null()
        })
    {
        if !(sk_X509_push(*p_sk, cert) == 0) {
            return 1 as libc::c_int;
        }
    }
    ERR_put_error(
        11 as libc::c_int,
        0 as libc::c_int,
        14 as libc::c_int,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
            as *const libc::c_char,
        1523 as libc::c_int as libc::c_uint,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn pkcs7_x509_add_certs_new(
    mut p_sk: *mut *mut stack_st_X509,
    mut certs: *mut stack_st_X509,
) -> libc::c_int {
    if p_sk.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1529 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if certs.is_null() {
        return 1 as libc::c_int;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_X509_num(certs) {
        if pkcs7_x509_add_cert_new(p_sk, sk_X509_value(certs, i)) == 0 {
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkcs7_signature_verify(
    mut in_bio: *mut BIO,
    mut p7: *mut PKCS7,
    mut si: *mut PKCS7_SIGNER_INFO,
    mut signer: *mut X509,
) -> libc::c_int {
    let mut md_type: libc::c_int = 0;
    let mut mdc: *mut EVP_MD_CTX = 0 as *mut EVP_MD_CTX;
    let mut bio: *mut BIO = 0 as *mut BIO;
    let mut pkey: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
    let mut data_body: *mut ASN1_OCTET_STRING = 0 as *mut ASN1_OCTET_STRING;
    let mut current_block: u64;
    if in_bio.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1542 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if p7.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1543 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if si.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1544 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*si).digest_alg).is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1545 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if signer.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1546 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut mdc_tmp: *mut EVP_MD_CTX = EVP_MD_CTX_new();
    if mdc_tmp.is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            1 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1553 as libc::c_int as libc::c_uint,
        );
    } else {
        md_type = OBJ_obj2nid((*(*si).digest_alg).algorithm);
        if !(md_type == 0 as libc::c_int) {
            mdc = 0 as *mut EVP_MD_CTX;
            bio = in_bio;
            loop {
                if bio.is_null() {
                    current_block = 17184638872671510253;
                    break;
                }
                bio = BIO_find_type(bio, 8 as libc::c_int | 0x200 as libc::c_int);
                if bio.is_null() {
                    ERR_put_error(
                        18 as libc::c_int,
                        0 as libc::c_int,
                        108 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                            as *const u8 as *const libc::c_char,
                        1567 as libc::c_int as libc::c_uint,
                    );
                    current_block = 18151955548183327492;
                    break;
                } else if BIO_get_md_ctx(bio, &mut mdc) == 0 || mdc.is_null() {
                    ERR_put_error(
                        18 as libc::c_int,
                        0 as libc::c_int,
                        18 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                            as *const u8 as *const libc::c_char,
                        1571 as libc::c_int as libc::c_uint,
                    );
                    current_block = 18151955548183327492;
                    break;
                } else if EVP_MD_CTX_type(mdc) == md_type {
                    current_block = 17184638872671510253;
                    break;
                } else {
                    bio = BIO_next(bio);
                }
            }
            match current_block {
                18151955548183327492 => {}
                _ => {
                    if !(EVP_MD_CTX_copy_ex(mdc_tmp, mdc) == 0) {
                        if !((*si).auth_attr).is_null()
                            && sk_X509_ATTRIBUTE_num((*si).auth_attr)
                                != 0 as libc::c_int as size_t
                        {
                            let mut md_data: [libc::c_uchar; 64] = [0; 64];
                            let mut abuf: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
                            let mut md_len: libc::c_uint = 0;
                            if EVP_DigestFinal_ex(
                                mdc_tmp,
                                md_data.as_mut_ptr(),
                                &mut md_len,
                            ) == 0
                            {
                                current_block = 18151955548183327492;
                            } else {
                                let mut message_digest: *mut ASN1_OCTET_STRING = PKCS7_digest_from_attributes(
                                    (*si).auth_attr,
                                );
                                if message_digest.is_null() {
                                    ERR_put_error(
                                        18 as libc::c_int,
                                        0 as libc::c_int,
                                        108 as libc::c_int,
                                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                                            as *const u8 as *const libc::c_char,
                                        1596 as libc::c_int as libc::c_uint,
                                    );
                                    current_block = 18151955548183327492;
                                } else if (*message_digest).length != md_len as libc::c_int
                                    || OPENSSL_memcmp(
                                        (*message_digest).data as *const libc::c_void,
                                        md_data.as_mut_ptr() as *const libc::c_void,
                                        md_len as size_t,
                                    ) != 0 as libc::c_int
                                {
                                    ERR_put_error(
                                        18 as libc::c_int,
                                        0 as libc::c_int,
                                        129 as libc::c_int,
                                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                                            as *const u8 as *const libc::c_char,
                                        1601 as libc::c_int as libc::c_uint,
                                    );
                                    current_block = 18151955548183327492;
                                } else {
                                    let mut md: *const EVP_MD = EVP_get_digestbynid(md_type);
                                    if md.is_null()
                                        || EVP_VerifyInit_ex(mdc_tmp, md, 0 as *mut ENGINE) == 0
                                    {
                                        current_block = 18151955548183327492;
                                    } else {
                                        let mut alen: libc::c_int = ASN1_item_i2d(
                                            (*si).auth_attr as *mut ASN1_VALUE,
                                            &mut abuf,
                                            &PKCS7_ATTR_VERIFY_it,
                                        );
                                        if alen <= 0 as libc::c_int || abuf.is_null() {
                                            ERR_put_error(
                                                18 as libc::c_int,
                                                0 as libc::c_int,
                                                12 as libc::c_int,
                                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                                                    as *const u8 as *const libc::c_char,
                                                1613 as libc::c_int as libc::c_uint,
                                            );
                                            ret = -(1 as libc::c_int);
                                            current_block = 18151955548183327492;
                                        } else if EVP_VerifyUpdate(
                                            mdc_tmp,
                                            abuf as *const libc::c_void,
                                            alen as size_t,
                                        ) == 0
                                        {
                                            OPENSSL_free(abuf as *mut libc::c_void);
                                            current_block = 18151955548183327492;
                                        } else {
                                            OPENSSL_free(abuf as *mut libc::c_void);
                                            current_block = 5892776923941496671;
                                        }
                                    }
                                }
                            }
                        } else {
                            current_block = 5892776923941496671;
                        }
                        match current_block {
                            18151955548183327492 => {}
                            _ => {
                                pkey = X509_get0_pubkey(signer);
                                if !pkey.is_null() {
                                    data_body = (*si).enc_digest;
                                    if EVP_VerifyFinal(
                                        mdc_tmp,
                                        (*data_body).data,
                                        (*data_body).length as size_t,
                                        pkey,
                                    ) == 0
                                    {
                                        ERR_put_error(
                                            18 as libc::c_int,
                                            0 as libc::c_int,
                                            115 as libc::c_int,
                                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                                                as *const u8 as *const libc::c_char,
                                            1631 as libc::c_int as libc::c_uint,
                                        );
                                    } else {
                                        ret = 1 as libc::c_int;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    EVP_MD_CTX_free(mdc_tmp);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_verify(
    mut p7: *mut PKCS7,
    mut certs: *mut stack_st_X509,
    mut store: *mut X509_STORE,
    mut indata: *mut BIO,
    mut outdata: *mut BIO,
    mut flags: libc::c_int,
) -> libc::c_int {
    let mut sinfos: *mut stack_st_PKCS7_SIGNER_INFO = 0
        as *mut stack_st_PKCS7_SIGNER_INFO;
    let mut current_block: u64;
    if p7.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1644 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if store.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1645 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut signers: *mut stack_st_X509 = 0 as *mut stack_st_X509;
    let mut untrusted: *mut stack_st_X509 = 0 as *mut stack_st_X509;
    let mut cert_ctx: *mut X509_STORE_CTX = 0 as *mut X509_STORE_CTX;
    let mut p7bio: *mut BIO = 0 as *mut BIO;
    let mut ret: libc::c_int = 0 as libc::c_int;
    if PKCS7_type_is_signed(p7) == 0 {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            110 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1652 as libc::c_int as libc::c_uint,
        );
    } else if PKCS7_is_detached(p7) != 0 && indata.is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1658 as libc::c_int as libc::c_uint,
        );
    } else if PKCS7_is_detached(p7) == 0 && !indata.is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            111 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                as *const libc::c_char,
            1664 as libc::c_int as libc::c_uint,
        );
    } else {
        sinfos = PKCS7_get_signer_info(p7);
        if sinfos.is_null() || sk_PKCS7_SIGNER_INFO_num(sinfos) == 0 as libc::c_ulong {
            ERR_put_error(
                18 as libc::c_int,
                0 as libc::c_int,
                112 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0" as *const u8
                    as *const libc::c_char,
                1670 as libc::c_int as libc::c_uint,
            );
        } else {
            signers = PKCS7_get0_signers(p7, certs, flags);
            if !signers.is_null() {
                if flags & 0x20 as libc::c_int == 0 {
                    let mut included_certs: *mut stack_st_X509 = pkcs7_get0_certificates(
                        p7,
                    );
                    cert_ctx = X509_STORE_CTX_new();
                    if cert_ctx.is_null()
                        || pkcs7_x509_add_certs_new(&mut untrusted, certs) == 0
                        || pkcs7_x509_add_certs_new(&mut untrusted, included_certs) == 0
                    {
                        ERR_put_error(
                            18 as libc::c_int,
                            0 as libc::c_int,
                            18 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                                as *const u8 as *const libc::c_char,
                            1683 as libc::c_int as libc::c_uint,
                        );
                        current_block = 1316287911593477742;
                    } else {
                        let mut k: size_t = 0 as libc::c_int as size_t;
                        loop {
                            if !(k < sk_X509_num(signers)) {
                                current_block = 11932355480408055363;
                                break;
                            }
                            let mut signer: *mut X509 = sk_X509_value(signers, k);
                            if X509_STORE_CTX_init(cert_ctx, store, signer, untrusted)
                                == 0
                            {
                                ERR_put_error(
                                    18 as libc::c_int,
                                    0 as libc::c_int,
                                    11 as libc::c_int,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                                        as *const u8 as *const libc::c_char,
                                    1690 as libc::c_int as libc::c_uint,
                                );
                                current_block = 1316287911593477742;
                                break;
                            } else {
                                if X509_STORE_CTX_set_default(
                                    cert_ctx,
                                    b"smime_sign\0" as *const u8 as *const libc::c_char,
                                ) == 0
                                {
                                    current_block = 1316287911593477742;
                                    break;
                                }
                                X509_STORE_CTX_set0_crls(cert_ctx, (*(*p7).d.sign).crl);
                                k = k.wrapping_add(1);
                                k;
                            }
                        }
                        match current_block {
                            1316287911593477742 => {}
                            _ => {
                                if X509_verify_cert(cert_ctx) <= 0 as libc::c_int {
                                    ERR_put_error(
                                        18 as libc::c_int,
                                        0 as libc::c_int,
                                        113 as libc::c_int,
                                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                                            as *const u8 as *const libc::c_char,
                                        1702 as libc::c_int as libc::c_uint,
                                    );
                                    current_block = 1316287911593477742;
                                } else {
                                    current_block = 11913429853522160501;
                                }
                            }
                        }
                    }
                } else {
                    current_block = 11913429853522160501;
                }
                match current_block {
                    1316287911593477742 => {}
                    _ => {
                        p7bio = PKCS7_dataInit(p7, indata);
                        if !(p7bio.is_null()
                            || pkcs7_bio_copy_content(p7bio, outdata) == 0)
                        {
                            let mut ii: size_t = 0 as libc::c_int as size_t;
                            loop {
                                if !(ii < sk_PKCS7_SIGNER_INFO_num(sinfos)) {
                                    current_block = 9007357115414505193;
                                    break;
                                }
                                let mut si: *mut PKCS7_SIGNER_INFO = sk_PKCS7_SIGNER_INFO_value(
                                    sinfos,
                                    ii,
                                );
                                let mut signer_0: *mut X509 = sk_X509_value(signers, ii);
                                if pkcs7_signature_verify(p7bio, p7, si, signer_0) == 0 {
                                    ERR_put_error(
                                        18 as libc::c_int,
                                        0 as libc::c_int,
                                        115 as libc::c_int,
                                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7.c\0"
                                            as *const u8 as *const libc::c_char,
                                        1722 as libc::c_int as libc::c_uint,
                                    );
                                    current_block = 1316287911593477742;
                                    break;
                                } else {
                                    ii = ii.wrapping_add(1);
                                    ii;
                                }
                            }
                            match current_block {
                                1316287911593477742 => {}
                                _ => {
                                    ret = 1 as libc::c_int;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    X509_STORE_CTX_free(cert_ctx);
    if !indata.is_null() {
        BIO_pop(p7bio);
    }
    BIO_free_all(p7bio);
    sk_X509_free(signers);
    sk_X509_free(untrusted);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn SMIME_read_PKCS7(
    mut in_0: *mut BIO,
    mut bcont: *mut *mut BIO,
) -> *mut PKCS7 {
    return 0 as *mut PKCS7;
}
#[no_mangle]
pub unsafe extern "C" fn SMIME_write_PKCS7(
    mut out: *mut BIO,
    mut p7: *mut PKCS7,
    mut data: *mut BIO,
    mut flags: libc::c_int,
) -> libc::c_int {
    return 0 as libc::c_int;
}
