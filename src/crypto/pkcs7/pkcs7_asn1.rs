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
    pub type asn1_object_st;
    pub type asn1_pctx_st;
    pub type ASN1_VALUE_st;
    pub type X509_name_st;
    pub type evp_cipher_st;
    pub type evp_pkey_st;
    pub type x509_st;
    pub type stack_st_void;
    pub type env_md_st;
    pub type stack_st_PKCS7_SIGNER_INFO;
    pub type stack_st_X509_CRL;
    pub type stack_st_X509;
    pub type stack_st_X509_ALGOR;
    pub type stack_st_PKCS7_RECIP_INFO;
    pub type stack_st_X509_ATTRIBUTE;
    pub type asn1_must_be_null_st;
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
    fn ASN1_item_dup(it: *const ASN1_ITEM, x: *mut libc::c_void) -> *mut libc::c_void;
    static ASN1_OCTET_STRING_it: ASN1_ITEM;
    static ASN1_INTEGER_it: ASN1_ITEM;
    static ASN1_OBJECT_it: ASN1_ITEM;
    static ASN1_ANY_it: ASN1_ITEM;
    static X509_it: ASN1_ITEM;
    fn X509_free(x509: *mut X509);
    static X509_CRL_it: ASN1_ITEM;
    static X509_NAME_it: ASN1_ITEM;
    static X509_ALGOR_it: ASN1_ITEM;
    static X509_ATTRIBUTE_it: ASN1_ITEM;
    fn BIO_printf(bio: *mut BIO, format: *const libc::c_char, _: ...) -> libc::c_int;
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
    fn CBS_asn1_ber_to_der(
        in_0: *mut CBS,
        out: *mut CBS,
        out_storage: *mut *mut uint8_t,
    ) -> libc::c_int;
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
pub type ASN1_OBJECT = asn1_object_st;
pub type ASN1_PCTX = asn1_pctx_st;
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
pub struct cbs_st {
    pub data: *const uint8_t,
    pub len: size_t,
}
pub type CBS = cbs_st;
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
    pub d: C2RustUnnamed_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
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
pub type ASN1_ADB = ASN1_ADB_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ASN1_ADB_st {
    pub flags: uint32_t,
    pub offset: libc::c_ulong,
    pub unused: *mut ASN1_MUST_BE_NULL,
    pub tbl: *const ASN1_ADB_TABLE,
    pub tblcount: libc::c_long,
    pub default_tt: *const ASN1_TEMPLATE,
    pub null_tt: *const ASN1_TEMPLATE,
}
pub type ASN1_ADB_TABLE = ASN1_ADB_TABLE_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ASN1_ADB_TABLE_st {
    pub value: libc::c_int,
    pub tt: ASN1_TEMPLATE,
}
pub type ASN1_MUST_BE_NULL = asn1_must_be_null_st;
pub type ASN1_AUX = ASN1_AUX_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ASN1_AUX_st {
    pub app_data: *mut libc::c_void,
    pub flags: uint32_t,
    pub ref_offset: libc::c_int,
    pub asn1_cb: Option::<ASN1_aux_cb>,
    pub enc_offset: libc::c_int,
}
pub type ASN1_aux_cb = unsafe extern "C" fn(
    libc::c_int,
    *mut *mut ASN1_VALUE,
    *const ASN1_ITEM,
    *mut libc::c_void,
) -> libc::c_int;
static mut p7default_tt: ASN1_TEMPLATE = unsafe {
    {
        let mut init = ASN1_TEMPLATE_st {
            flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                as uint32_t,
            tag: 0 as libc::c_int,
            offset: 8 as libc::c_ulong,
            field_name: b"d.data\0" as *const u8 as *const libc::c_char,
            item: &ASN1_ANY_it as *const ASN1_ITEM,
        };
        init
    }
};
static mut PKCS7_adbtbl: [ASN1_ADB_TABLE; 6] = unsafe {
    [
        {
            let mut init = ASN1_ADB_TABLE_st {
                value: 21 as libc::c_int,
                tt: {
                    let mut init = ASN1_TEMPLATE_st {
                        flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                            | (0x2 as libc::c_int) << 6 as libc::c_int
                            | 0x1 as libc::c_int) as uint32_t,
                        tag: 0 as libc::c_int,
                        offset: 8 as libc::c_ulong,
                        field_name: b"d.data\0" as *const u8 as *const libc::c_char,
                        item: &ASN1_OCTET_STRING_it as *const ASN1_ITEM,
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ASN1_ADB_TABLE_st {
                value: 22 as libc::c_int,
                tt: {
                    let mut init = ASN1_TEMPLATE_st {
                        flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                            | (0x2 as libc::c_int) << 6 as libc::c_int
                            | 0x1 as libc::c_int) as uint32_t,
                        tag: 0 as libc::c_int,
                        offset: 8 as libc::c_ulong,
                        field_name: b"d.sign\0" as *const u8 as *const libc::c_char,
                        item: &PKCS7_SIGNED_it as *const ASN1_ITEM,
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ASN1_ADB_TABLE_st {
                value: 23 as libc::c_int,
                tt: {
                    let mut init = ASN1_TEMPLATE_st {
                        flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                            | (0x2 as libc::c_int) << 6 as libc::c_int
                            | 0x1 as libc::c_int) as uint32_t,
                        tag: 0 as libc::c_int,
                        offset: 8 as libc::c_ulong,
                        field_name: b"d.enveloped\0" as *const u8 as *const libc::c_char,
                        item: &PKCS7_ENVELOPE_it as *const ASN1_ITEM,
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ASN1_ADB_TABLE_st {
                value: 24 as libc::c_int,
                tt: {
                    let mut init = ASN1_TEMPLATE_st {
                        flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                            | (0x2 as libc::c_int) << 6 as libc::c_int
                            | 0x1 as libc::c_int) as uint32_t,
                        tag: 0 as libc::c_int,
                        offset: 8 as libc::c_ulong,
                        field_name: b"d.signed_and_enveloped\0" as *const u8
                            as *const libc::c_char,
                        item: &PKCS7_SIGN_ENVELOPE_it as *const ASN1_ITEM,
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ASN1_ADB_TABLE_st {
                value: 25 as libc::c_int,
                tt: {
                    let mut init = ASN1_TEMPLATE_st {
                        flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                            | (0x2 as libc::c_int) << 6 as libc::c_int
                            | 0x1 as libc::c_int) as uint32_t,
                        tag: 0 as libc::c_int,
                        offset: 8 as libc::c_ulong,
                        field_name: b"d.digest\0" as *const u8 as *const libc::c_char,
                        item: &PKCS7_DIGEST_it as *const ASN1_ITEM,
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ASN1_ADB_TABLE_st {
                value: 26 as libc::c_int,
                tt: {
                    let mut init = ASN1_TEMPLATE_st {
                        flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                            | (0x2 as libc::c_int) << 6 as libc::c_int
                            | 0x1 as libc::c_int) as uint32_t,
                        tag: 0 as libc::c_int,
                        offset: 8 as libc::c_ulong,
                        field_name: b"d.encrypted\0" as *const u8 as *const libc::c_char,
                        item: &PKCS7_ENCRYPT_it as *const ASN1_ITEM,
                    };
                    init
                },
            };
            init
        },
    ]
};
static mut PKCS7_adb: ASN1_ADB = ASN1_ADB_st {
    flags: 0,
    offset: 0,
    unused: 0 as *const ASN1_MUST_BE_NULL as *mut ASN1_MUST_BE_NULL,
    tbl: 0 as *const ASN1_ADB_TABLE,
    tblcount: 0,
    default_tt: 0 as *const ASN1_TEMPLATE,
    null_tt: 0 as *const ASN1_TEMPLATE,
};
static mut PKCS7_seq_tt: [ASN1_TEMPLATE; 2] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"type\0" as *const u8 as *const libc::c_char,
                item: &ASN1_OBJECT_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 8 as libc::c_int) as uint32_t,
                tag: -(1 as libc::c_int),
                offset: 0 as libc::c_int as libc::c_ulong,
                field_name: b"PKCS7\0" as *const u8 as *const libc::c_char,
                item: &PKCS7_adb as *const ASN1_ADB as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut PKCS7_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[no_mangle]
pub unsafe extern "C" fn PKCS7_free(mut a: *mut PKCS7) {
    ASN1_item_free(a as *mut ASN1_VALUE, &PKCS7_it);
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_new() -> *mut PKCS7 {
    return ASN1_item_new(&PKCS7_it) as *mut PKCS7;
}
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS7(
    mut a: *mut *mut PKCS7,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut PKCS7 {
    let mut der_bytes: *mut uint8_t = 0 as *mut uint8_t;
    let mut ret: *mut PKCS7 = 0 as *mut PKCS7;
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut cbs_der: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if in_0.is_null() {
        return 0 as *mut PKCS7;
    }
    CBS_init(&mut cbs, *in_0, len as size_t);
    if !(CBS_asn1_ber_to_der(&mut cbs, &mut cbs_der, &mut der_bytes) == 0) {
        if der_bytes.is_null() {
            ret = ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &PKCS7_it)
                as *mut PKCS7;
        } else {
            let mut der_bytes_ptr: *mut uint8_t = der_bytes;
            let mut der_len: size_t = CBS_len(&mut cbs_der);
            ret = ASN1_item_d2i(
                a as *mut *mut ASN1_VALUE,
                &mut der_bytes_ptr as *mut *mut uint8_t as *mut *const uint8_t,
                der_len as libc::c_long,
                &PKCS7_it,
            ) as *mut PKCS7;
            *in_0 = (*in_0)
                .offset(der_bytes_ptr.offset_from(der_bytes) as libc::c_long as isize);
        }
    }
    OPENSSL_free(der_bytes as *mut libc::c_void);
    der_bytes = 0 as *mut uint8_t;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS7(
    mut a: *mut PKCS7,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &PKCS7_it);
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_dup(mut x: *mut PKCS7) -> *mut PKCS7 {
    return ASN1_item_dup(&PKCS7_it, x as *mut libc::c_void) as *mut PKCS7;
}
static mut PKCS7_SIGNED_seq_tt: [ASN1_TEMPLATE; 6] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"version\0" as *const u8 as *const libc::c_char,
                item: &ASN1_INTEGER_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 1 as libc::c_int) as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"md_algs\0" as *const u8 as *const libc::c_char,
                item: &X509_ALGOR_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 16 as libc::c_ulong,
                field_name: b"contents\0" as *const u8 as *const libc::c_char,
                item: &PKCS7_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int
                    | (0x2 as libc::c_int) << 1 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 24 as libc::c_ulong,
                field_name: b"cert\0" as *const u8 as *const libc::c_char,
                item: &X509_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int
                    | (0x1 as libc::c_int) << 1 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 1 as libc::c_int,
                offset: 32 as libc::c_ulong,
                field_name: b"crl\0" as *const u8 as *const libc::c_char,
                item: &X509_CRL_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 1 as libc::c_int) as uint32_t,
                tag: 0 as libc::c_int,
                offset: 40 as libc::c_ulong,
                field_name: b"signer_info\0" as *const u8 as *const libc::c_char,
                item: &PKCS7_SIGNER_INFO_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut PKCS7_SIGNED_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[no_mangle]
pub unsafe extern "C" fn PKCS7_SIGNED_free(mut a: *mut PKCS7_SIGNED) {
    ASN1_item_free(a as *mut ASN1_VALUE, &PKCS7_SIGNED_it);
}
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS7_SIGNED(
    mut a: *mut PKCS7_SIGNED,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &PKCS7_SIGNED_it);
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_SIGNED_new() -> *mut PKCS7_SIGNED {
    return ASN1_item_new(&PKCS7_SIGNED_it) as *mut PKCS7_SIGNED;
}
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS7_SIGNED(
    mut a: *mut *mut PKCS7_SIGNED,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut PKCS7_SIGNED {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &PKCS7_SIGNED_it)
        as *mut PKCS7_SIGNED;
}
static mut PKCS7_ISSUER_AND_SERIAL_seq_tt: [ASN1_TEMPLATE; 2] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"issuer\0" as *const u8 as *const libc::c_char,
                item: &X509_NAME_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"serial\0" as *const u8 as *const libc::c_char,
                item: &ASN1_INTEGER_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut PKCS7_ISSUER_AND_SERIAL_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[no_mangle]
pub unsafe extern "C" fn PKCS7_ISSUER_AND_SERIAL_free(
    mut a: *mut PKCS7_ISSUER_AND_SERIAL,
) {
    ASN1_item_free(a as *mut ASN1_VALUE, &PKCS7_ISSUER_AND_SERIAL_it);
}
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS7_ISSUER_AND_SERIAL(
    mut a: *mut PKCS7_ISSUER_AND_SERIAL,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &PKCS7_ISSUER_AND_SERIAL_it);
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_ISSUER_AND_SERIAL_new() -> *mut PKCS7_ISSUER_AND_SERIAL {
    return ASN1_item_new(&PKCS7_ISSUER_AND_SERIAL_it) as *mut PKCS7_ISSUER_AND_SERIAL;
}
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS7_ISSUER_AND_SERIAL(
    mut a: *mut *mut PKCS7_ISSUER_AND_SERIAL,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut PKCS7_ISSUER_AND_SERIAL {
    return ASN1_item_d2i(
        a as *mut *mut ASN1_VALUE,
        in_0,
        len,
        &PKCS7_ISSUER_AND_SERIAL_it,
    ) as *mut PKCS7_ISSUER_AND_SERIAL;
}
unsafe extern "C" fn recip_info_cb(
    mut operation: libc::c_int,
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
    mut exarg: *mut libc::c_void,
) -> libc::c_int {
    if operation == 3 as libc::c_int {
        let mut ri: *mut PKCS7_RECIP_INFO = *pval as *mut PKCS7_RECIP_INFO;
        X509_free((*ri).cert);
    }
    return 1 as libc::c_int;
}
static mut PKCS7_RECIP_INFO_seq_tt: [ASN1_TEMPLATE; 4] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"version\0" as *const u8 as *const libc::c_char,
                item: &ASN1_INTEGER_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"issuer_and_serial\0" as *const u8 as *const libc::c_char,
                item: &PKCS7_ISSUER_AND_SERIAL_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 16 as libc::c_ulong,
                field_name: b"key_enc_algor\0" as *const u8 as *const libc::c_char,
                item: &X509_ALGOR_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 24 as libc::c_ulong,
                field_name: b"enc_key\0" as *const u8 as *const libc::c_char,
                item: &ASN1_OCTET_STRING_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
static mut PKCS7_RECIP_INFO_aux: ASN1_AUX = unsafe {
    {
        let mut init = ASN1_AUX_st {
            app_data: 0 as *const libc::c_void as *mut libc::c_void,
            flags: 0 as libc::c_int as uint32_t,
            ref_offset: 0 as libc::c_int,
            asn1_cb: Some(
                recip_info_cb
                    as unsafe extern "C" fn(
                        libc::c_int,
                        *mut *mut ASN1_VALUE,
                        *const ASN1_ITEM,
                        *mut libc::c_void,
                    ) -> libc::c_int,
            ),
            enc_offset: 0 as libc::c_int,
        };
        init
    }
};
#[no_mangle]
pub static mut PKCS7_RECIP_INFO_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[no_mangle]
pub unsafe extern "C" fn PKCS7_RECIP_INFO_free(mut a: *mut PKCS7_RECIP_INFO) {
    ASN1_item_free(a as *mut ASN1_VALUE, &PKCS7_RECIP_INFO_it);
}
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS7_RECIP_INFO(
    mut a: *mut PKCS7_RECIP_INFO,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &PKCS7_RECIP_INFO_it);
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_RECIP_INFO_new() -> *mut PKCS7_RECIP_INFO {
    return ASN1_item_new(&PKCS7_RECIP_INFO_it) as *mut PKCS7_RECIP_INFO;
}
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS7_RECIP_INFO(
    mut a: *mut *mut PKCS7_RECIP_INFO,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut PKCS7_RECIP_INFO {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &PKCS7_RECIP_INFO_it)
        as *mut PKCS7_RECIP_INFO;
}
unsafe extern "C" fn signer_info_cb(
    mut operation: libc::c_int,
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
    mut exarg: *mut libc::c_void,
) -> libc::c_int {
    let mut si: *mut PKCS7_SIGNER_INFO = *pval as *mut PKCS7_SIGNER_INFO;
    if operation == 3 as libc::c_int {
        EVP_PKEY_free((*si).pkey);
    }
    return 1 as libc::c_int;
}
static mut PKCS7_SIGNER_INFO_aux: ASN1_AUX = unsafe {
    {
        let mut init = ASN1_AUX_st {
            app_data: 0 as *const libc::c_void as *mut libc::c_void,
            flags: 0 as libc::c_int as uint32_t,
            ref_offset: 0 as libc::c_int,
            asn1_cb: Some(
                signer_info_cb
                    as unsafe extern "C" fn(
                        libc::c_int,
                        *mut *mut ASN1_VALUE,
                        *const ASN1_ITEM,
                        *mut libc::c_void,
                    ) -> libc::c_int,
            ),
            enc_offset: 0 as libc::c_int,
        };
        init
    }
};
static mut PKCS7_SIGNER_INFO_seq_tt: [ASN1_TEMPLATE; 7] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"version\0" as *const u8 as *const libc::c_char,
                item: &ASN1_INTEGER_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"issuer_and_serial\0" as *const u8 as *const libc::c_char,
                item: &PKCS7_ISSUER_AND_SERIAL_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 16 as libc::c_ulong,
                field_name: b"digest_alg\0" as *const u8 as *const libc::c_char,
                item: &X509_ALGOR_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int
                    | (0x2 as libc::c_int) << 1 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 24 as libc::c_ulong,
                field_name: b"auth_attr\0" as *const u8 as *const libc::c_char,
                item: &X509_ATTRIBUTE_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 32 as libc::c_ulong,
                field_name: b"digest_enc_alg\0" as *const u8 as *const libc::c_char,
                item: &X509_ALGOR_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 40 as libc::c_ulong,
                field_name: b"enc_digest\0" as *const u8 as *const libc::c_char,
                item: &ASN1_OCTET_STRING_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int
                    | (0x1 as libc::c_int) << 1 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 1 as libc::c_int,
                offset: 48 as libc::c_ulong,
                field_name: b"unauth_attr\0" as *const u8 as *const libc::c_char,
                item: &X509_ATTRIBUTE_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut PKCS7_SIGNER_INFO_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[no_mangle]
pub unsafe extern "C" fn PKCS7_SIGNER_INFO_free(mut a: *mut PKCS7_SIGNER_INFO) {
    ASN1_item_free(a as *mut ASN1_VALUE, &PKCS7_SIGNER_INFO_it);
}
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS7_SIGNER_INFO(
    mut a: *mut PKCS7_SIGNER_INFO,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &PKCS7_SIGNER_INFO_it);
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_SIGNER_INFO_new() -> *mut PKCS7_SIGNER_INFO {
    return ASN1_item_new(&PKCS7_SIGNER_INFO_it) as *mut PKCS7_SIGNER_INFO;
}
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS7_SIGNER_INFO(
    mut a: *mut *mut PKCS7_SIGNER_INFO,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut PKCS7_SIGNER_INFO {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &PKCS7_SIGNER_INFO_it)
        as *mut PKCS7_SIGNER_INFO;
}
static mut PKCS7_ENC_CONTENT_seq_tt: [ASN1_TEMPLATE; 3] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"content_type\0" as *const u8 as *const libc::c_char,
                item: &ASN1_OBJECT_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"algorithm\0" as *const u8 as *const libc::c_char,
                item: &X509_ALGOR_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 16 as libc::c_ulong,
                field_name: b"enc_data\0" as *const u8 as *const libc::c_char,
                item: &ASN1_OCTET_STRING_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut PKCS7_ENC_CONTENT_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS7_ENC_CONTENT(
    mut a: *mut PKCS7_ENC_CONTENT,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &PKCS7_ENC_CONTENT_it);
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_ENC_CONTENT_free(mut a: *mut PKCS7_ENC_CONTENT) {
    ASN1_item_free(a as *mut ASN1_VALUE, &PKCS7_ENC_CONTENT_it);
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_ENC_CONTENT_new() -> *mut PKCS7_ENC_CONTENT {
    return ASN1_item_new(&PKCS7_ENC_CONTENT_it) as *mut PKCS7_ENC_CONTENT;
}
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS7_ENC_CONTENT(
    mut a: *mut *mut PKCS7_ENC_CONTENT,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut PKCS7_ENC_CONTENT {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &PKCS7_ENC_CONTENT_it)
        as *mut PKCS7_ENC_CONTENT;
}
static mut PKCS7_SIGN_ENVELOPE_seq_tt: [ASN1_TEMPLATE; 7] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"version\0" as *const u8 as *const libc::c_char,
                item: &ASN1_INTEGER_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 1 as libc::c_int) as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"recipientinfo\0" as *const u8 as *const libc::c_char,
                item: &PKCS7_RECIP_INFO_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 1 as libc::c_int) as uint32_t,
                tag: 0 as libc::c_int,
                offset: 16 as libc::c_ulong,
                field_name: b"md_algs\0" as *const u8 as *const libc::c_char,
                item: &X509_ALGOR_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 24 as libc::c_ulong,
                field_name: b"enc_data\0" as *const u8 as *const libc::c_char,
                item: &PKCS7_ENC_CONTENT_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int
                    | (0x1 as libc::c_int) << 1 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 32 as libc::c_ulong,
                field_name: b"cert\0" as *const u8 as *const libc::c_char,
                item: &X509_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int
                    | (0x1 as libc::c_int) << 1 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 1 as libc::c_int,
                offset: 40 as libc::c_ulong,
                field_name: b"crl\0" as *const u8 as *const libc::c_char,
                item: &X509_CRL_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 1 as libc::c_int) as uint32_t,
                tag: 0 as libc::c_int,
                offset: 48 as libc::c_ulong,
                field_name: b"signer_info\0" as *const u8 as *const libc::c_char,
                item: &PKCS7_SIGNER_INFO_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut PKCS7_SIGN_ENVELOPE_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS7_SIGN_ENVELOPE(
    mut a: *mut PKCS7_SIGN_ENVELOPE,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &PKCS7_SIGN_ENVELOPE_it);
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_SIGN_ENVELOPE_free(mut a: *mut PKCS7_SIGN_ENVELOPE) {
    ASN1_item_free(a as *mut ASN1_VALUE, &PKCS7_SIGN_ENVELOPE_it);
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_SIGN_ENVELOPE_new() -> *mut PKCS7_SIGN_ENVELOPE {
    return ASN1_item_new(&PKCS7_SIGN_ENVELOPE_it) as *mut PKCS7_SIGN_ENVELOPE;
}
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS7_SIGN_ENVELOPE(
    mut a: *mut *mut PKCS7_SIGN_ENVELOPE,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut PKCS7_SIGN_ENVELOPE {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &PKCS7_SIGN_ENVELOPE_it)
        as *mut PKCS7_SIGN_ENVELOPE;
}
static mut PKCS7_ENCRYPT_seq_tt: [ASN1_TEMPLATE; 2] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"version\0" as *const u8 as *const libc::c_char,
                item: &ASN1_INTEGER_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"enc_data\0" as *const u8 as *const libc::c_char,
                item: &PKCS7_ENC_CONTENT_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut PKCS7_ENCRYPT_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[no_mangle]
pub unsafe extern "C" fn PKCS7_ENCRYPT_free(mut a: *mut PKCS7_ENCRYPT) {
    ASN1_item_free(a as *mut ASN1_VALUE, &PKCS7_ENCRYPT_it);
}
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS7_ENCRYPT(
    mut a: *mut PKCS7_ENCRYPT,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &PKCS7_ENCRYPT_it);
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_ENCRYPT_new() -> *mut PKCS7_ENCRYPT {
    return ASN1_item_new(&PKCS7_ENCRYPT_it) as *mut PKCS7_ENCRYPT;
}
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS7_ENCRYPT(
    mut a: *mut *mut PKCS7_ENCRYPT,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut PKCS7_ENCRYPT {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &PKCS7_ENCRYPT_it)
        as *mut PKCS7_ENCRYPT;
}
static mut PKCS7_DIGEST_seq_tt: [ASN1_TEMPLATE; 4] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"version\0" as *const u8 as *const libc::c_char,
                item: &ASN1_INTEGER_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"digest_alg\0" as *const u8 as *const libc::c_char,
                item: &X509_ALGOR_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 16 as libc::c_ulong,
                field_name: b"contents\0" as *const u8 as *const libc::c_char,
                item: &PKCS7_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 24 as libc::c_ulong,
                field_name: b"digest\0" as *const u8 as *const libc::c_char,
                item: &ASN1_OCTET_STRING_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut PKCS7_DIGEST_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS7_DIGEST(
    mut a: *mut PKCS7_DIGEST,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &PKCS7_DIGEST_it);
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_DIGEST_free(mut a: *mut PKCS7_DIGEST) {
    ASN1_item_free(a as *mut ASN1_VALUE, &PKCS7_DIGEST_it);
}
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS7_DIGEST(
    mut a: *mut *mut PKCS7_DIGEST,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut PKCS7_DIGEST {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &PKCS7_DIGEST_it)
        as *mut PKCS7_DIGEST;
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_DIGEST_new() -> *mut PKCS7_DIGEST {
    return ASN1_item_new(&PKCS7_DIGEST_it) as *mut PKCS7_DIGEST;
}
static mut PKCS7_ENVELOPE_seq_tt: [ASN1_TEMPLATE; 3] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"version\0" as *const u8 as *const libc::c_char,
                item: &ASN1_INTEGER_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 1 as libc::c_int) as uint32_t,
                tag: 0 as libc::c_int,
                offset: 16 as libc::c_ulong,
                field_name: b"recipientinfo\0" as *const u8 as *const libc::c_char,
                item: &PKCS7_RECIP_INFO_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"enc_data\0" as *const u8 as *const libc::c_char,
                item: &PKCS7_ENC_CONTENT_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut PKCS7_ENVELOPE_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS7_ENVELOPE(
    mut a: *mut PKCS7_ENVELOPE,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &PKCS7_ENVELOPE_it);
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_ENVELOPE_free(mut a: *mut PKCS7_ENVELOPE) {
    ASN1_item_free(a as *mut ASN1_VALUE, &PKCS7_ENVELOPE_it);
}
#[no_mangle]
pub unsafe extern "C" fn PKCS7_ENVELOPE_new() -> *mut PKCS7_ENVELOPE {
    return ASN1_item_new(&PKCS7_ENVELOPE_it) as *mut PKCS7_ENVELOPE;
}
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS7_ENVELOPE(
    mut a: *mut *mut PKCS7_ENVELOPE,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut PKCS7_ENVELOPE {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &PKCS7_ENVELOPE_it)
        as *mut PKCS7_ENVELOPE;
}
static mut PKCS7_ATTR_VERIFY_item_tt: ASN1_TEMPLATE = unsafe {
    {
        let mut init = ASN1_TEMPLATE_st {
            flags: ((0x2 as libc::c_int) << 1 as libc::c_int
                | (0x1 as libc::c_int) << 3 as libc::c_int
                | (0 as libc::c_int) << 6 as libc::c_int) as uint32_t,
            tag: 17 as libc::c_int,
            offset: 0 as libc::c_int as libc::c_ulong,
            field_name: b"PKCS7_ATTRIBUTES\0" as *const u8 as *const libc::c_char,
            item: &X509_ATTRIBUTE_it as *const ASN1_ITEM,
        };
        init
    }
};
#[no_mangle]
pub static mut PKCS7_ATTR_VERIFY_it: ASN1_ITEM = unsafe {
    {
        let mut init = ASN1_ITEM_st {
            itype: 0 as libc::c_int as libc::c_char,
            utype: -(1 as libc::c_int),
            templates: &PKCS7_ATTR_VERIFY_item_tt as *const ASN1_TEMPLATE,
            tcount: 0 as libc::c_int as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: 0 as libc::c_int as libc::c_long,
            sname: b"PKCS7_ATTR_VERIFY\0" as *const u8 as *const libc::c_char,
        };
        init
    }
};
#[no_mangle]
pub unsafe extern "C" fn PKCS7_print_ctx(
    mut bio: *mut BIO,
    mut pkcs7: *mut PKCS7,
    mut indent: libc::c_int,
    mut pctx: *const ASN1_PCTX,
) -> libc::c_int {
    if bio.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7_asn1.c\0" as *const u8
                as *const libc::c_char,
            196 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if pkcs7.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs7/pkcs7_asn1.c\0" as *const u8
                as *const libc::c_char,
            197 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if BIO_printf(
        bio,
        b"PKCS7 printing is not supported\0" as *const u8 as *const libc::c_char,
    ) <= 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn run_static_initializers() {
    PKCS7_adb = {
        let mut init = ASN1_ADB_st {
            flags: 0 as libc::c_int as uint32_t,
            offset: 0 as libc::c_ulong,
            unused: 0 as *mut ASN1_MUST_BE_NULL,
            tbl: PKCS7_adbtbl.as_ptr(),
            tblcount: (::core::mem::size_of::<[ASN1_ADB_TABLE; 6]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_ADB_TABLE>() as libc::c_ulong)
                as libc::c_long,
            default_tt: &p7default_tt,
            null_tt: 0 as *const ASN1_TEMPLATE,
        };
        init
    };
    PKCS7_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: PKCS7_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 2]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<PKCS7>() as libc::c_ulong as libc::c_long,
            sname: b"PKCS7\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    PKCS7_SIGNED_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: PKCS7_SIGNED_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 6]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<PKCS7_SIGNED>() as libc::c_ulong
                as libc::c_long,
            sname: b"PKCS7_SIGNED\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    PKCS7_ISSUER_AND_SERIAL_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: PKCS7_ISSUER_AND_SERIAL_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 2]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<PKCS7_ISSUER_AND_SERIAL>() as libc::c_ulong
                as libc::c_long,
            sname: b"PKCS7_ISSUER_AND_SERIAL\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    PKCS7_RECIP_INFO_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: PKCS7_RECIP_INFO_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 4]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: &PKCS7_RECIP_INFO_aux as *const ASN1_AUX as *const libc::c_void,
            size: ::core::mem::size_of::<PKCS7_RECIP_INFO>() as libc::c_ulong
                as libc::c_long,
            sname: b"PKCS7_RECIP_INFO\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    PKCS7_SIGNER_INFO_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: PKCS7_SIGNER_INFO_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 7]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: &PKCS7_SIGNER_INFO_aux as *const ASN1_AUX as *const libc::c_void,
            size: ::core::mem::size_of::<PKCS7_SIGNER_INFO>() as libc::c_ulong
                as libc::c_long,
            sname: b"PKCS7_SIGNER_INFO\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    PKCS7_ENC_CONTENT_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: PKCS7_ENC_CONTENT_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 3]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<PKCS7_ENC_CONTENT>() as libc::c_ulong
                as libc::c_long,
            sname: b"PKCS7_ENC_CONTENT\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    PKCS7_SIGN_ENVELOPE_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: PKCS7_SIGN_ENVELOPE_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 7]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<PKCS7_SIGN_ENVELOPE>() as libc::c_ulong
                as libc::c_long,
            sname: b"PKCS7_SIGN_ENVELOPE\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    PKCS7_ENCRYPT_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: PKCS7_ENCRYPT_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 2]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<PKCS7_ENCRYPT>() as libc::c_ulong
                as libc::c_long,
            sname: b"PKCS7_ENCRYPT\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    PKCS7_DIGEST_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: PKCS7_DIGEST_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 4]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<PKCS7_DIGEST>() as libc::c_ulong
                as libc::c_long,
            sname: b"PKCS7_DIGEST\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    PKCS7_ENVELOPE_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: PKCS7_ENVELOPE_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 3]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<PKCS7_ENVELOPE>() as libc::c_ulong
                as libc::c_long,
            sname: b"PKCS7_ENVELOPE\0" as *const u8 as *const libc::c_char,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
