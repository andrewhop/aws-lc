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
    pub type X509_sig_st;
    pub type dh_st;
    pub type dsa_st;
    pub type ec_key_st;
    pub type engine_st;
    pub type evp_md_pctx_ops;
    pub type evp_pkey_ctx_st;
    pub type env_md_st;
    pub type pkcs8_priv_key_info_st;
    pub type rsa_st;
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn ASN1_item_d2i_fp(
        it: *const ASN1_ITEM,
        in_0: *mut FILE,
        out: *mut libc::c_void,
    ) -> *mut libc::c_void;
    fn ASN1_item_d2i_bio(
        it: *const ASN1_ITEM,
        in_0: *mut BIO,
        out: *mut libc::c_void,
    ) -> *mut libc::c_void;
    fn ASN1_item_i2d_fp(
        it: *const ASN1_ITEM,
        out: *mut FILE,
        in_0: *mut libc::c_void,
    ) -> libc::c_int;
    fn ASN1_item_i2d_bio(
        it: *const ASN1_ITEM,
        out: *mut BIO,
        in_0: *mut libc::c_void,
    ) -> libc::c_int;
    fn asn1_encoding_clear(enc: *mut ASN1_ENCODING);
    static X509_it: ASN1_ITEM;
    fn X509_get0_pubkey_bitstr(x509: *const X509) -> *mut ASN1_BIT_STRING;
    static X509_CRL_it: ASN1_ITEM;
    static X509_REQ_it: ASN1_ITEM;
    static X509_NAME_it: ASN1_ITEM;
    fn X509_ALGOR_cmp(a: *const X509_ALGOR, b: *const X509_ALGOR) -> libc::c_int;
    static NETSCAPE_SPKAC_it: ASN1_ITEM;
    fn PKCS8_PRIV_KEY_INFO_free(key: *mut PKCS8_PRIV_KEY_INFO);
    fn d2i_PKCS8_PRIV_KEY_INFO(
        out: *mut *mut PKCS8_PRIV_KEY_INFO,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut PKCS8_PRIV_KEY_INFO;
    fn i2d_PKCS8_PRIV_KEY_INFO(
        key: *const PKCS8_PRIV_KEY_INFO,
        outp: *mut *mut uint8_t,
    ) -> libc::c_int;
    fn EVP_PKEY2PKCS8(pkey: *const EVP_PKEY) -> *mut PKCS8_PRIV_KEY_INFO;
    fn d2i_X509_SIG(
        out: *mut *mut X509_SIG,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut X509_SIG;
    fn i2d_X509_SIG(sig: *const X509_SIG, outp: *mut *mut uint8_t) -> libc::c_int;
    fn ASN1_item_digest(
        it: *const ASN1_ITEM,
        type_0: *const EVP_MD,
        data: *mut libc::c_void,
        md: *mut libc::c_uchar,
        len: *mut libc::c_uint,
    ) -> libc::c_int;
    fn ASN1_item_verify(
        it: *const ASN1_ITEM,
        algor1: *const X509_ALGOR,
        signature: *const ASN1_BIT_STRING,
        data: *mut libc::c_void,
        pkey: *mut EVP_PKEY,
    ) -> libc::c_int;
    fn ASN1_item_sign(
        it: *const ASN1_ITEM,
        algor1: *mut X509_ALGOR,
        algor2: *mut X509_ALGOR,
        signature: *mut ASN1_BIT_STRING,
        data: *mut libc::c_void,
        pkey: *mut EVP_PKEY,
        type_0: *const EVP_MD,
    ) -> libc::c_int;
    fn ASN1_item_sign_ctx(
        it: *const ASN1_ITEM,
        algor1: *mut X509_ALGOR,
        algor2: *mut X509_ALGOR,
        signature: *mut ASN1_BIT_STRING,
        asn: *mut libc::c_void,
        ctx: *mut EVP_MD_CTX,
    ) -> libc::c_int;
    static X509_CINF_it: ASN1_ITEM;
    static X509_REQ_INFO_it: ASN1_ITEM;
    static X509_CRL_INFO_it: ASN1_ITEM;
    fn d2i_DSAPrivateKey(
        out: *mut *mut DSA,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut DSA;
    fn i2d_DSAPrivateKey(in_0: *const DSA, outp: *mut *mut uint8_t) -> libc::c_int;
    fn BIO_free(bio: *mut BIO) -> libc::c_int;
    fn BIO_write_all(
        bio: *mut BIO,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn BIO_read_asn1(
        bio: *mut BIO,
        out: *mut *mut uint8_t,
        out_len: *mut size_t,
        max_len: size_t,
    ) -> libc::c_int;
    fn BIO_new_fp(stream: *mut FILE, close_flag: libc::c_int) -> *mut BIO;
    fn EVP_Digest(
        data: *const libc::c_void,
        len: size_t,
        md_out: *mut uint8_t,
        out_size: *mut libc::c_uint,
        type_0: *const EVP_MD,
        impl_0: *mut ENGINE,
    ) -> libc::c_int;
    fn OCSP_REQ_CTX_nbio_d2i(
        rctx: *mut OCSP_REQ_CTX,
        pval: *mut *mut ASN1_VALUE,
        it: *const ASN1_ITEM,
    ) -> libc::c_int;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn d2i_DHparams(
        ret: *mut *mut DH,
        inp: *mut *const libc::c_uchar,
        len: libc::c_long,
    ) -> *mut DH;
    fn i2d_DHparams(in_0: *const DH, outp: *mut *mut libc::c_uchar) -> libc::c_int;
    fn d2i_ECPrivateKey(
        out_key: *mut *mut EC_KEY,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut EC_KEY;
    fn i2d_ECPrivateKey(key: *const EC_KEY, outp: *mut *mut uint8_t) -> libc::c_int;
    fn i2d_PrivateKey(key: *const EVP_PKEY, outp: *mut *mut uint8_t) -> libc::c_int;
    fn d2i_AutoPrivateKey(
        out: *mut *mut EVP_PKEY,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut EVP_PKEY;
    fn i2d_PUBKEY(pkey: *const EVP_PKEY, outp: *mut *mut uint8_t) -> libc::c_int;
    fn d2i_PUBKEY(
        out: *mut *mut EVP_PKEY,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut EVP_PKEY;
    fn i2d_RSA_PUBKEY(rsa: *const RSA, outp: *mut *mut uint8_t) -> libc::c_int;
    fn d2i_RSA_PUBKEY(
        out: *mut *mut RSA,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut RSA;
    fn i2d_DSA_PUBKEY(dsa: *const DSA, outp: *mut *mut uint8_t) -> libc::c_int;
    fn d2i_DSA_PUBKEY(
        out: *mut *mut DSA,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut DSA;
    fn i2d_EC_PUBKEY(ec_key: *const EC_KEY, outp: *mut *mut uint8_t) -> libc::c_int;
    fn d2i_EC_PUBKEY(
        out: *mut *mut EC_KEY,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut EC_KEY;
    fn d2i_RSAPublicKey(
        out: *mut *mut RSA,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut RSA;
    fn i2d_RSAPublicKey(in_0: *const RSA, outp: *mut *mut uint8_t) -> libc::c_int;
    fn d2i_RSAPrivateKey(
        out: *mut *mut RSA,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut RSA;
    fn i2d_RSAPrivateKey(in_0: *const RSA, outp: *mut *mut uint8_t) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Netscape_spkac_st {
    pub pubkey: *mut X509_PUBKEY,
    pub challenge: *mut ASN1_IA5STRING,
}
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
pub type NETSCAPE_SPKAC = Netscape_spkac_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Netscape_spki_st {
    pub spkac: *mut NETSCAPE_SPKAC,
    pub sig_algor: *mut X509_ALGOR,
    pub signature: *mut ASN1_BIT_STRING,
}
pub type NETSCAPE_SPKI = Netscape_spki_st;
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
pub type X509_SIG = X509_sig_st;
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
pub type DH = dh_st;
pub type DSA = dsa_st;
pub type EC_KEY = ec_key_st;
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
pub struct ocsp_req_ctx_st {
    pub state: libc::c_int,
    pub iobuf: *mut libc::c_uchar,
    pub iobuflen: libc::c_int,
    pub io: *mut BIO,
    pub mem: *mut BIO,
    pub asn1_len: libc::c_ulong,
    pub max_resp_len: libc::c_ulong,
}
pub type OCSP_REQ_CTX = ocsp_req_ctx_st;
pub type PKCS8_PRIV_KEY_INFO = pkcs8_priv_key_info_st;
pub type RSA = rsa_st;
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_verify(
    mut x509: *mut X509,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    if X509_ALGOR_cmp((*x509).sig_alg, (*(*x509).cert_info).signature) != 0 {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            137 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x_all.c\0" as *const u8
                as *const libc::c_char,
            76 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ASN1_item_verify(
        &X509_CINF_it,
        (*x509).sig_alg,
        (*x509).signature,
        (*x509).cert_info as *mut libc::c_void,
        pkey,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_REQ_verify(
    mut req: *mut X509_REQ,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    return ASN1_item_verify(
        &X509_REQ_INFO_it,
        (*req).sig_alg,
        (*req).signature,
        (*req).req_info as *mut libc::c_void,
        pkey,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_sign(
    mut x: *mut X509,
    mut pkey: *mut EVP_PKEY,
    mut md: *const EVP_MD,
) -> libc::c_int {
    asn1_encoding_clear(&mut (*(*x).cert_info).enc);
    return ASN1_item_sign(
        &X509_CINF_it,
        (*(*x).cert_info).signature,
        (*x).sig_alg,
        (*x).signature,
        (*x).cert_info as *mut libc::c_void,
        pkey,
        md,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_sign_ctx(
    mut x: *mut X509,
    mut ctx: *mut EVP_MD_CTX,
) -> libc::c_int {
    asn1_encoding_clear(&mut (*(*x).cert_info).enc);
    return ASN1_item_sign_ctx(
        &X509_CINF_it,
        (*(*x).cert_info).signature,
        (*x).sig_alg,
        (*x).signature,
        (*x).cert_info as *mut libc::c_void,
        ctx,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_REQ_sign(
    mut x: *mut X509_REQ,
    mut pkey: *mut EVP_PKEY,
    mut md: *const EVP_MD,
) -> libc::c_int {
    asn1_encoding_clear(&mut (*(*x).req_info).enc);
    return ASN1_item_sign(
        &X509_REQ_INFO_it,
        (*x).sig_alg,
        0 as *mut X509_ALGOR,
        (*x).signature,
        (*x).req_info as *mut libc::c_void,
        pkey,
        md,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_REQ_sign_ctx(
    mut x: *mut X509_REQ,
    mut ctx: *mut EVP_MD_CTX,
) -> libc::c_int {
    asn1_encoding_clear(&mut (*(*x).req_info).enc);
    return ASN1_item_sign_ctx(
        &X509_REQ_INFO_it,
        (*x).sig_alg,
        0 as *mut X509_ALGOR,
        (*x).signature,
        (*x).req_info as *mut libc::c_void,
        ctx,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_CRL_sign(
    mut x: *mut X509_CRL,
    mut pkey: *mut EVP_PKEY,
    mut md: *const EVP_MD,
) -> libc::c_int {
    asn1_encoding_clear(&mut (*(*x).crl).enc);
    return ASN1_item_sign(
        &X509_CRL_INFO_it,
        (*(*x).crl).sig_alg,
        (*x).sig_alg,
        (*x).signature,
        (*x).crl as *mut libc::c_void,
        pkey,
        md,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_CRL_sign_ctx(
    mut x: *mut X509_CRL,
    mut ctx: *mut EVP_MD_CTX,
) -> libc::c_int {
    asn1_encoding_clear(&mut (*(*x).crl).enc);
    return ASN1_item_sign_ctx(
        &X509_CRL_INFO_it,
        (*(*x).crl).sig_alg,
        (*x).sig_alg,
        (*x).signature,
        (*x).crl as *mut libc::c_void,
        ctx,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_CRL_http_nbio(
    mut rctx: *mut OCSP_REQ_CTX,
    mut pcrl: *mut *mut X509_CRL,
) -> libc::c_int {
    return OCSP_REQ_CTX_nbio_d2i(rctx, pcrl as *mut *mut ASN1_VALUE, &X509_CRL_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NETSCAPE_SPKI_sign(
    mut x: *mut NETSCAPE_SPKI,
    mut pkey: *mut EVP_PKEY,
    mut md: *const EVP_MD,
) -> libc::c_int {
    return ASN1_item_sign(
        &NETSCAPE_SPKAC_it,
        (*x).sig_algor,
        0 as *mut X509_ALGOR,
        (*x).signature,
        (*x).spkac as *mut libc::c_void,
        pkey,
        md,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NETSCAPE_SPKI_verify(
    mut spki: *mut NETSCAPE_SPKI,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    return ASN1_item_verify(
        &NETSCAPE_SPKAC_it,
        (*spki).sig_algor,
        (*spki).signature,
        (*spki).spkac as *mut libc::c_void,
        pkey,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_X509_fp(
    mut fp: *mut FILE,
    mut x509: *mut *mut X509,
) -> *mut X509 {
    return ASN1_item_d2i_fp(&X509_it, fp, x509 as *mut libc::c_void) as *mut X509;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_X509_fp(
    mut fp: *mut FILE,
    mut x509: *mut X509,
) -> libc::c_int {
    return ASN1_item_i2d_fp(&X509_it, fp, x509 as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_X509_bio(
    mut bp: *mut BIO,
    mut x509: *mut *mut X509,
) -> *mut X509 {
    return ASN1_item_d2i_bio(&X509_it, bp, x509 as *mut libc::c_void) as *mut X509;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_X509_bio(
    mut bp: *mut BIO,
    mut x509: *mut X509,
) -> libc::c_int {
    return ASN1_item_i2d_bio(&X509_it, bp, x509 as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_X509_CRL_fp(
    mut fp: *mut FILE,
    mut crl: *mut *mut X509_CRL,
) -> *mut X509_CRL {
    return ASN1_item_d2i_fp(&X509_CRL_it, fp, crl as *mut libc::c_void) as *mut X509_CRL;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_X509_CRL_fp(
    mut fp: *mut FILE,
    mut crl: *mut X509_CRL,
) -> libc::c_int {
    return ASN1_item_i2d_fp(&X509_CRL_it, fp, crl as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_X509_CRL_bio(
    mut bp: *mut BIO,
    mut crl: *mut *mut X509_CRL,
) -> *mut X509_CRL {
    return ASN1_item_d2i_bio(&X509_CRL_it, bp, crl as *mut libc::c_void)
        as *mut X509_CRL;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_X509_CRL_bio(
    mut bp: *mut BIO,
    mut crl: *mut X509_CRL,
) -> libc::c_int {
    return ASN1_item_i2d_bio(&X509_CRL_it, bp, crl as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_X509_REQ_fp(
    mut fp: *mut FILE,
    mut req: *mut *mut X509_REQ,
) -> *mut X509_REQ {
    return ASN1_item_d2i_fp(&X509_REQ_it, fp, req as *mut libc::c_void) as *mut X509_REQ;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_X509_REQ_fp(
    mut fp: *mut FILE,
    mut req: *mut X509_REQ,
) -> libc::c_int {
    return ASN1_item_i2d_fp(&X509_REQ_it, fp, req as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_X509_REQ_bio(
    mut bp: *mut BIO,
    mut req: *mut *mut X509_REQ,
) -> *mut X509_REQ {
    return ASN1_item_d2i_bio(&X509_REQ_it, bp, req as *mut libc::c_void)
        as *mut X509_REQ;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_X509_REQ_bio(
    mut bp: *mut BIO,
    mut req: *mut X509_REQ,
) -> libc::c_int {
    return ASN1_item_i2d_bio(&X509_REQ_it, bp, req as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_RSAPrivateKey_fp(
    mut fp: *mut FILE,
    mut obj: *mut *mut RSA,
) -> *mut RSA {
    let mut bio: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if bio.is_null() {
        return 0 as *mut RSA;
    }
    let mut ret: *mut RSA = d2i_RSAPrivateKey_bio(bio, obj);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_RSAPrivateKey_fp(
    mut fp: *mut FILE,
    mut obj: *mut RSA,
) -> libc::c_int {
    let mut bio: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if bio.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = i2d_RSAPrivateKey_bio(bio, obj);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_RSAPublicKey_fp(
    mut fp: *mut FILE,
    mut obj: *mut *mut RSA,
) -> *mut RSA {
    let mut bio: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if bio.is_null() {
        return 0 as *mut RSA;
    }
    let mut ret: *mut RSA = d2i_RSAPublicKey_bio(bio, obj);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_RSAPublicKey_fp(
    mut fp: *mut FILE,
    mut obj: *mut RSA,
) -> libc::c_int {
    let mut bio: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if bio.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = i2d_RSAPublicKey_bio(bio, obj);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_RSA_PUBKEY_fp(
    mut fp: *mut FILE,
    mut obj: *mut *mut RSA,
) -> *mut RSA {
    let mut bio: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if bio.is_null() {
        return 0 as *mut RSA;
    }
    let mut ret: *mut RSA = d2i_RSA_PUBKEY_bio(bio, obj);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_RSA_PUBKEY_fp(
    mut fp: *mut FILE,
    mut obj: *mut RSA,
) -> libc::c_int {
    let mut bio: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if bio.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = i2d_RSA_PUBKEY_bio(bio, obj);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_RSAPrivateKey_bio(
    mut bio: *mut BIO,
    mut obj: *mut *mut RSA,
) -> *mut RSA {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = 0;
    if BIO_read_asn1(
        bio,
        &mut data,
        &mut len,
        (100 as libc::c_int * 1024 as libc::c_int) as size_t,
    ) == 0
    {
        return 0 as *mut RSA;
    }
    let mut ptr: *const uint8_t = data;
    let mut ret: *mut RSA = d2i_RSAPrivateKey(obj, &mut ptr, len as libc::c_long);
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_RSAPrivateKey_bio(
    mut bio: *mut BIO,
    mut obj: *mut RSA,
) -> libc::c_int {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: libc::c_int = i2d_RSAPrivateKey(obj, &mut data);
    if len < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = BIO_write_all(
        bio,
        data as *const libc::c_void,
        len as size_t,
    );
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_RSAPublicKey_bio(
    mut bio: *mut BIO,
    mut obj: *mut *mut RSA,
) -> *mut RSA {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = 0;
    if BIO_read_asn1(
        bio,
        &mut data,
        &mut len,
        (100 as libc::c_int * 1024 as libc::c_int) as size_t,
    ) == 0
    {
        return 0 as *mut RSA;
    }
    let mut ptr: *const uint8_t = data;
    let mut ret: *mut RSA = d2i_RSAPublicKey(obj, &mut ptr, len as libc::c_long);
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_RSAPublicKey_bio(
    mut bio: *mut BIO,
    mut obj: *mut RSA,
) -> libc::c_int {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: libc::c_int = i2d_RSAPublicKey(obj, &mut data);
    if len < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = BIO_write_all(
        bio,
        data as *const libc::c_void,
        len as size_t,
    );
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_RSA_PUBKEY_bio(
    mut bio: *mut BIO,
    mut obj: *mut *mut RSA,
) -> *mut RSA {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = 0;
    if BIO_read_asn1(
        bio,
        &mut data,
        &mut len,
        (100 as libc::c_int * 1024 as libc::c_int) as size_t,
    ) == 0
    {
        return 0 as *mut RSA;
    }
    let mut ptr: *const uint8_t = data;
    let mut ret: *mut RSA = d2i_RSA_PUBKEY(obj, &mut ptr, len as libc::c_long);
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_RSA_PUBKEY_bio(
    mut bio: *mut BIO,
    mut obj: *mut RSA,
) -> libc::c_int {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: libc::c_int = i2d_RSA_PUBKEY(obj, &mut data);
    if len < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = BIO_write_all(
        bio,
        data as *const libc::c_void,
        len as size_t,
    );
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_DSAPrivateKey_fp(
    mut fp: *mut FILE,
    mut obj: *mut *mut DSA,
) -> *mut DSA {
    let mut bio: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if bio.is_null() {
        return 0 as *mut DSA;
    }
    let mut ret: *mut DSA = d2i_DSAPrivateKey_bio(bio, obj);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_DSAPrivateKey_fp(
    mut fp: *mut FILE,
    mut obj: *mut DSA,
) -> libc::c_int {
    let mut bio: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if bio.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = i2d_DSAPrivateKey_bio(bio, obj);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_DSA_PUBKEY_fp(
    mut fp: *mut FILE,
    mut obj: *mut *mut DSA,
) -> *mut DSA {
    let mut bio: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if bio.is_null() {
        return 0 as *mut DSA;
    }
    let mut ret: *mut DSA = d2i_DSA_PUBKEY_bio(bio, obj);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_DSA_PUBKEY_fp(
    mut fp: *mut FILE,
    mut obj: *mut DSA,
) -> libc::c_int {
    let mut bio: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if bio.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = i2d_DSA_PUBKEY_bio(bio, obj);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_DSAPrivateKey_bio(
    mut bio: *mut BIO,
    mut obj: *mut *mut DSA,
) -> *mut DSA {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = 0;
    if BIO_read_asn1(
        bio,
        &mut data,
        &mut len,
        (100 as libc::c_int * 1024 as libc::c_int) as size_t,
    ) == 0
    {
        return 0 as *mut DSA;
    }
    let mut ptr: *const uint8_t = data;
    let mut ret: *mut DSA = d2i_DSAPrivateKey(obj, &mut ptr, len as libc::c_long);
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_DSAPrivateKey_bio(
    mut bio: *mut BIO,
    mut obj: *mut DSA,
) -> libc::c_int {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: libc::c_int = i2d_DSAPrivateKey(obj, &mut data);
    if len < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = BIO_write_all(
        bio,
        data as *const libc::c_void,
        len as size_t,
    );
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_DSA_PUBKEY_bio(
    mut bio: *mut BIO,
    mut obj: *mut *mut DSA,
) -> *mut DSA {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = 0;
    if BIO_read_asn1(
        bio,
        &mut data,
        &mut len,
        (100 as libc::c_int * 1024 as libc::c_int) as size_t,
    ) == 0
    {
        return 0 as *mut DSA;
    }
    let mut ptr: *const uint8_t = data;
    let mut ret: *mut DSA = d2i_DSA_PUBKEY(obj, &mut ptr, len as libc::c_long);
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_DSA_PUBKEY_bio(
    mut bio: *mut BIO,
    mut obj: *mut DSA,
) -> libc::c_int {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: libc::c_int = i2d_DSA_PUBKEY(obj, &mut data);
    if len < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = BIO_write_all(
        bio,
        data as *const libc::c_void,
        len as size_t,
    );
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ECPrivateKey_fp(
    mut fp: *mut FILE,
    mut obj: *mut *mut EC_KEY,
) -> *mut EC_KEY {
    let mut bio: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if bio.is_null() {
        return 0 as *mut EC_KEY;
    }
    let mut ret: *mut EC_KEY = d2i_ECPrivateKey_bio(bio, obj);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ECPrivateKey_fp(
    mut fp: *mut FILE,
    mut obj: *mut EC_KEY,
) -> libc::c_int {
    let mut bio: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if bio.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = i2d_ECPrivateKey_bio(bio, obj);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_EC_PUBKEY_fp(
    mut fp: *mut FILE,
    mut obj: *mut *mut EC_KEY,
) -> *mut EC_KEY {
    let mut bio: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if bio.is_null() {
        return 0 as *mut EC_KEY;
    }
    let mut ret: *mut EC_KEY = d2i_EC_PUBKEY_bio(bio, obj);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_EC_PUBKEY_fp(
    mut fp: *mut FILE,
    mut obj: *mut EC_KEY,
) -> libc::c_int {
    let mut bio: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if bio.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = i2d_EC_PUBKEY_bio(bio, obj);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ECPrivateKey_bio(
    mut bio: *mut BIO,
    mut obj: *mut *mut EC_KEY,
) -> *mut EC_KEY {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = 0;
    if BIO_read_asn1(
        bio,
        &mut data,
        &mut len,
        (100 as libc::c_int * 1024 as libc::c_int) as size_t,
    ) == 0
    {
        return 0 as *mut EC_KEY;
    }
    let mut ptr: *const uint8_t = data;
    let mut ret: *mut EC_KEY = d2i_ECPrivateKey(obj, &mut ptr, len as libc::c_long);
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ECPrivateKey_bio(
    mut bio: *mut BIO,
    mut obj: *mut EC_KEY,
) -> libc::c_int {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: libc::c_int = i2d_ECPrivateKey(obj, &mut data);
    if len < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = BIO_write_all(
        bio,
        data as *const libc::c_void,
        len as size_t,
    );
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_EC_PUBKEY_bio(
    mut bio: *mut BIO,
    mut obj: *mut *mut EC_KEY,
) -> *mut EC_KEY {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = 0;
    if BIO_read_asn1(
        bio,
        &mut data,
        &mut len,
        (100 as libc::c_int * 1024 as libc::c_int) as size_t,
    ) == 0
    {
        return 0 as *mut EC_KEY;
    }
    let mut ptr: *const uint8_t = data;
    let mut ret: *mut EC_KEY = d2i_EC_PUBKEY(obj, &mut ptr, len as libc::c_long);
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_EC_PUBKEY_bio(
    mut bio: *mut BIO,
    mut obj: *mut EC_KEY,
) -> libc::c_int {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: libc::c_int = i2d_EC_PUBKEY(obj, &mut data);
    if len < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = BIO_write_all(
        bio,
        data as *const libc::c_void,
        len as size_t,
    );
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_pubkey_digest(
    mut data: *const X509,
    mut type_0: *const EVP_MD,
    mut md: *mut libc::c_uchar,
    mut len: *mut libc::c_uint,
) -> libc::c_int {
    let mut key: *mut ASN1_BIT_STRING = 0 as *mut ASN1_BIT_STRING;
    key = X509_get0_pubkey_bitstr(data);
    if key.is_null() {
        return 0 as libc::c_int;
    }
    return EVP_Digest(
        (*key).data as *const libc::c_void,
        (*key).length as size_t,
        md,
        len,
        type_0,
        0 as *mut ENGINE,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_digest(
    mut data: *const X509,
    mut type_0: *const EVP_MD,
    mut md: *mut libc::c_uchar,
    mut len: *mut libc::c_uint,
) -> libc::c_int {
    return ASN1_item_digest(
        &X509_it,
        type_0,
        data as *mut libc::c_char as *mut libc::c_void,
        md,
        len,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_CRL_digest(
    mut data: *const X509_CRL,
    mut type_0: *const EVP_MD,
    mut md: *mut libc::c_uchar,
    mut len: *mut libc::c_uint,
) -> libc::c_int {
    return ASN1_item_digest(
        &X509_CRL_it,
        type_0,
        data as *mut libc::c_char as *mut libc::c_void,
        md,
        len,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_REQ_digest(
    mut data: *const X509_REQ,
    mut type_0: *const EVP_MD,
    mut md: *mut libc::c_uchar,
    mut len: *mut libc::c_uint,
) -> libc::c_int {
    return ASN1_item_digest(
        &X509_REQ_it,
        type_0,
        data as *mut libc::c_char as *mut libc::c_void,
        md,
        len,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_NAME_digest(
    mut data: *const X509_NAME,
    mut type_0: *const EVP_MD,
    mut md: *mut libc::c_uchar,
    mut len: *mut libc::c_uint,
) -> libc::c_int {
    return ASN1_item_digest(
        &X509_NAME_it,
        type_0,
        data as *mut libc::c_char as *mut libc::c_void,
        md,
        len,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_PKCS8_fp(
    mut fp: *mut FILE,
    mut obj: *mut *mut X509_SIG,
) -> *mut X509_SIG {
    let mut bio: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if bio.is_null() {
        return 0 as *mut X509_SIG;
    }
    let mut ret: *mut X509_SIG = d2i_PKCS8_bio(bio, obj);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_PKCS8_fp(
    mut fp: *mut FILE,
    mut obj: *mut X509_SIG,
) -> libc::c_int {
    let mut bio: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if bio.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = i2d_PKCS8_bio(bio, obj);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_PKCS8_bio(
    mut bio: *mut BIO,
    mut obj: *mut *mut X509_SIG,
) -> *mut X509_SIG {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = 0;
    if BIO_read_asn1(
        bio,
        &mut data,
        &mut len,
        (100 as libc::c_int * 1024 as libc::c_int) as size_t,
    ) == 0
    {
        return 0 as *mut X509_SIG;
    }
    let mut ptr: *const uint8_t = data;
    let mut ret: *mut X509_SIG = d2i_X509_SIG(obj, &mut ptr, len as libc::c_long);
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_PKCS8_bio(
    mut bio: *mut BIO,
    mut obj: *mut X509_SIG,
) -> libc::c_int {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: libc::c_int = i2d_X509_SIG(obj, &mut data);
    if len < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = BIO_write_all(
        bio,
        data as *const libc::c_void,
        len as size_t,
    );
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_PKCS8_PRIV_KEY_INFO_fp(
    mut fp: *mut FILE,
    mut obj: *mut *mut PKCS8_PRIV_KEY_INFO,
) -> *mut PKCS8_PRIV_KEY_INFO {
    let mut bio: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if bio.is_null() {
        return 0 as *mut PKCS8_PRIV_KEY_INFO;
    }
    let mut ret: *mut PKCS8_PRIV_KEY_INFO = d2i_PKCS8_PRIV_KEY_INFO_bio(bio, obj);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_PKCS8_PRIV_KEY_INFO_fp(
    mut fp: *mut FILE,
    mut obj: *mut PKCS8_PRIV_KEY_INFO,
) -> libc::c_int {
    let mut bio: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if bio.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = i2d_PKCS8_PRIV_KEY_INFO_bio(bio, obj);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_PKCS8PrivateKeyInfo_fp(
    mut fp: *mut FILE,
    mut key: *mut EVP_PKEY,
) -> libc::c_int {
    let mut p8inf: *mut PKCS8_PRIV_KEY_INFO = 0 as *mut PKCS8_PRIV_KEY_INFO;
    let mut ret: libc::c_int = 0;
    p8inf = EVP_PKEY2PKCS8(key);
    if p8inf.is_null() {
        return 0 as libc::c_int;
    }
    ret = i2d_PKCS8_PRIV_KEY_INFO_fp(fp, p8inf);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_PrivateKey_fp(
    mut fp: *mut FILE,
    mut obj: *mut *mut EVP_PKEY,
) -> *mut EVP_PKEY {
    let mut bio: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if bio.is_null() {
        return 0 as *mut EVP_PKEY;
    }
    let mut ret: *mut EVP_PKEY = d2i_PrivateKey_bio(bio, obj);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_PrivateKey_fp(
    mut fp: *mut FILE,
    mut obj: *mut EVP_PKEY,
) -> libc::c_int {
    let mut bio: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if bio.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = i2d_PrivateKey_bio(bio, obj);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_PUBKEY_fp(
    mut fp: *mut FILE,
    mut obj: *mut *mut EVP_PKEY,
) -> *mut EVP_PKEY {
    let mut bio: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if bio.is_null() {
        return 0 as *mut EVP_PKEY;
    }
    let mut ret: *mut EVP_PKEY = d2i_PUBKEY_bio(bio, obj);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_PUBKEY_fp(
    mut fp: *mut FILE,
    mut obj: *mut EVP_PKEY,
) -> libc::c_int {
    let mut bio: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if bio.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = i2d_PUBKEY_bio(bio, obj);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_PKCS8_PRIV_KEY_INFO_bio(
    mut bio: *mut BIO,
    mut obj: *mut *mut PKCS8_PRIV_KEY_INFO,
) -> *mut PKCS8_PRIV_KEY_INFO {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = 0;
    if BIO_read_asn1(
        bio,
        &mut data,
        &mut len,
        (100 as libc::c_int * 1024 as libc::c_int) as size_t,
    ) == 0
    {
        return 0 as *mut PKCS8_PRIV_KEY_INFO;
    }
    let mut ptr: *const uint8_t = data;
    let mut ret: *mut PKCS8_PRIV_KEY_INFO = d2i_PKCS8_PRIV_KEY_INFO(
        obj,
        &mut ptr,
        len as libc::c_long,
    );
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_PKCS8_PRIV_KEY_INFO_bio(
    mut bio: *mut BIO,
    mut obj: *mut PKCS8_PRIV_KEY_INFO,
) -> libc::c_int {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: libc::c_int = i2d_PKCS8_PRIV_KEY_INFO(obj, &mut data);
    if len < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = BIO_write_all(
        bio,
        data as *const libc::c_void,
        len as size_t,
    );
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_PKCS8PrivateKeyInfo_bio(
    mut bp: *mut BIO,
    mut key: *mut EVP_PKEY,
) -> libc::c_int {
    let mut p8inf: *mut PKCS8_PRIV_KEY_INFO = 0 as *mut PKCS8_PRIV_KEY_INFO;
    let mut ret: libc::c_int = 0;
    p8inf = EVP_PKEY2PKCS8(key);
    if p8inf.is_null() {
        return 0 as libc::c_int;
    }
    ret = i2d_PKCS8_PRIV_KEY_INFO_bio(bp, p8inf);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_PrivateKey_bio(
    mut bio: *mut BIO,
    mut obj: *mut *mut EVP_PKEY,
) -> *mut EVP_PKEY {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = 0;
    if BIO_read_asn1(
        bio,
        &mut data,
        &mut len,
        (100 as libc::c_int * 1024 as libc::c_int) as size_t,
    ) == 0
    {
        return 0 as *mut EVP_PKEY;
    }
    let mut ptr: *const uint8_t = data;
    let mut ret: *mut EVP_PKEY = d2i_AutoPrivateKey(obj, &mut ptr, len as libc::c_long);
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_PrivateKey_bio(
    mut bio: *mut BIO,
    mut obj: *mut EVP_PKEY,
) -> libc::c_int {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: libc::c_int = i2d_PrivateKey(obj, &mut data);
    if len < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = BIO_write_all(
        bio,
        data as *const libc::c_void,
        len as size_t,
    );
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_PUBKEY_bio(
    mut bio: *mut BIO,
    mut obj: *mut *mut EVP_PKEY,
) -> *mut EVP_PKEY {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = 0;
    if BIO_read_asn1(
        bio,
        &mut data,
        &mut len,
        (100 as libc::c_int * 1024 as libc::c_int) as size_t,
    ) == 0
    {
        return 0 as *mut EVP_PKEY;
    }
    let mut ptr: *const uint8_t = data;
    let mut ret: *mut EVP_PKEY = d2i_PUBKEY(obj, &mut ptr, len as libc::c_long);
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_PUBKEY_bio(
    mut bio: *mut BIO,
    mut obj: *mut EVP_PKEY,
) -> libc::c_int {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: libc::c_int = i2d_PUBKEY(obj, &mut data);
    if len < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = BIO_write_all(
        bio,
        data as *const libc::c_void,
        len as size_t,
    );
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_DHparams_bio(
    mut bio: *mut BIO,
    mut obj: *mut *mut DH,
) -> *mut DH {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = 0;
    if BIO_read_asn1(
        bio,
        &mut data,
        &mut len,
        (100 as libc::c_int * 1024 as libc::c_int) as size_t,
    ) == 0
    {
        return 0 as *mut DH;
    }
    let mut ptr: *const uint8_t = data;
    let mut ret: *mut DH = d2i_DHparams(obj, &mut ptr, len as libc::c_long);
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_DHparams_bio(
    mut bio: *mut BIO,
    mut obj: *const DH,
) -> libc::c_int {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: libc::c_int = i2d_DHparams(obj, &mut data);
    if len < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = BIO_write_all(
        bio,
        data as *const libc::c_void,
        len as size_t,
    );
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
