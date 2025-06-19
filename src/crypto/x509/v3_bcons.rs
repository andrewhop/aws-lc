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
    static ASN1_INTEGER_it: ASN1_ITEM;
    fn X509V3_get_value_bool(
        value: *const CONF_VALUE,
        out_bool: *mut ASN1_BOOLEAN,
    ) -> libc::c_int;
    fn X509V3_get_value_int(
        value: *const CONF_VALUE,
        aint: *mut *mut ASN1_INTEGER,
    ) -> libc::c_int;
    fn X509V3_add_value_bool(
        name: *const libc::c_char,
        asn1_bool: libc::c_int,
        extlist: *mut *mut stack_st_CONF_VALUE,
    ) -> libc::c_int;
    fn X509V3_add_value_int(
        name: *const libc::c_char,
        aint: *const ASN1_INTEGER,
        extlist: *mut *mut stack_st_CONF_VALUE,
    ) -> libc::c_int;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
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
pub struct BASIC_CONSTRAINTS_st {
    pub ca: ASN1_BOOLEAN,
    pub pathlen: *mut ASN1_INTEGER,
}
pub type BASIC_CONSTRAINTS = BASIC_CONSTRAINTS_st;
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
pub type OPENSSL_STACK = stack_st;
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
#[no_mangle]
pub static mut v3_bcons: X509V3_EXT_METHOD = unsafe {
    {
        let mut init = v3_ext_method {
            ext_nid: 87 as libc::c_int,
            ext_flags: 0 as libc::c_int,
            it: &BASIC_CONSTRAINTS_it as *const ASN1_ITEM,
            ext_new: None,
            ext_free: None,
            d2i: None,
            i2d: None,
            i2s: None,
            s2i: None,
            i2v: Some(
                i2v_BASIC_CONSTRAINTS
                    as unsafe extern "C" fn(
                        *const X509V3_EXT_METHOD,
                        *mut libc::c_void,
                        *mut stack_st_CONF_VALUE,
                    ) -> *mut stack_st_CONF_VALUE,
            ),
            v2i: Some(
                v2i_BASIC_CONSTRAINTS
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
    }
};
static mut BASIC_CONSTRAINTS_seq_tt: [ASN1_TEMPLATE; 2] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0x1 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"ca\0" as *const u8 as *const libc::c_char,
                item: &ASN1_FBOOLEAN_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0x1 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"pathlen\0" as *const u8 as *const libc::c_char,
                item: &ASN1_INTEGER_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut BASIC_CONSTRAINTS_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[no_mangle]
pub unsafe extern "C" fn i2d_BASIC_CONSTRAINTS(
    mut a: *const BASIC_CONSTRAINTS,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &BASIC_CONSTRAINTS_it);
}
#[no_mangle]
pub unsafe extern "C" fn BASIC_CONSTRAINTS_free(mut a: *mut BASIC_CONSTRAINTS) {
    ASN1_item_free(a as *mut ASN1_VALUE, &BASIC_CONSTRAINTS_it);
}
#[no_mangle]
pub unsafe extern "C" fn d2i_BASIC_CONSTRAINTS(
    mut a: *mut *mut BASIC_CONSTRAINTS,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut BASIC_CONSTRAINTS {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &BASIC_CONSTRAINTS_it)
        as *mut BASIC_CONSTRAINTS;
}
#[no_mangle]
pub unsafe extern "C" fn BASIC_CONSTRAINTS_new() -> *mut BASIC_CONSTRAINTS {
    return ASN1_item_new(&BASIC_CONSTRAINTS_it) as *mut BASIC_CONSTRAINTS;
}
unsafe extern "C" fn i2v_BASIC_CONSTRAINTS(
    mut method: *const X509V3_EXT_METHOD,
    mut ext: *mut libc::c_void,
    mut extlist: *mut stack_st_CONF_VALUE,
) -> *mut stack_st_CONF_VALUE {
    let mut bcons: *const BASIC_CONSTRAINTS = ext as *const BASIC_CONSTRAINTS;
    X509V3_add_value_bool(
        b"CA\0" as *const u8 as *const libc::c_char,
        (*bcons).ca,
        &mut extlist,
    );
    X509V3_add_value_int(
        b"pathlen\0" as *const u8 as *const libc::c_char,
        (*bcons).pathlen,
        &mut extlist,
    );
    return extlist;
}
unsafe extern "C" fn v2i_BASIC_CONSTRAINTS(
    mut method: *const X509V3_EXT_METHOD,
    mut ctx: *const X509V3_CTX,
    mut values: *const stack_st_CONF_VALUE,
) -> *mut libc::c_void {
    let mut current_block: u64;
    let mut bcons: *mut BASIC_CONSTRAINTS = 0 as *mut BASIC_CONSTRAINTS;
    bcons = BASIC_CONSTRAINTS_new();
    if bcons.is_null() {
        return 0 as *mut libc::c_void;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    loop {
        if !(i < sk_CONF_VALUE_num(values)) {
            current_block = 12800627514080957624;
            break;
        }
        let mut val: *const CONF_VALUE = sk_CONF_VALUE_value(values, i);
        if strcmp((*val).name, b"CA\0" as *const u8 as *const libc::c_char) == 0 {
            if X509V3_get_value_bool(val, &mut (*bcons).ca) == 0 {
                current_block = 6147965311307017742;
                break;
            }
        } else if strcmp((*val).name, b"pathlen\0" as *const u8 as *const libc::c_char)
            == 0
        {
            if X509V3_get_value_int(val, &mut (*bcons).pathlen) == 0 {
                current_block = 6147965311307017742;
                break;
            }
        } else {
            ERR_put_error(
                20 as libc::c_int,
                0 as libc::c_int,
                123 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/v3_bcons.c\0"
                    as *const u8 as *const libc::c_char,
                126 as libc::c_int as libc::c_uint,
            );
            ERR_add_error_data(
                6 as libc::c_int as libc::c_uint,
                b"section:\0" as *const u8 as *const libc::c_char,
                (*val).section,
                b",name:\0" as *const u8 as *const libc::c_char,
                (*val).name,
                b",value:\0" as *const u8 as *const libc::c_char,
                (*val).value,
            );
            current_block = 6147965311307017742;
            break;
        }
        i = i.wrapping_add(1);
        i;
    }
    match current_block {
        12800627514080957624 => return bcons as *mut libc::c_void,
        _ => {
            BASIC_CONSTRAINTS_free(bcons);
            return 0 as *mut libc::c_void;
        }
    };
}
unsafe extern "C" fn run_static_initializers() {
    BASIC_CONSTRAINTS_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: BASIC_CONSTRAINTS_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 2]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<BASIC_CONSTRAINTS>() as libc::c_ulong
                as libc::c_long,
            sname: b"BASIC_CONSTRAINTS\0" as *const u8 as *const libc::c_char,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
