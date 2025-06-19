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
    pub type evp_pkey_st;
    pub type engine_st;
    pub type evp_md_pctx_ops;
    pub type evp_pkey_ctx_st;
    pub type env_md_st;
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
    fn x509_digest_sign_algorithm(
        ctx: *mut EVP_MD_CTX,
        algor: *mut X509_ALGOR,
    ) -> libc::c_int;
    fn EVP_MD_CTX_init(ctx: *mut EVP_MD_CTX);
    fn EVP_MD_CTX_cleanup(ctx: *mut EVP_MD_CTX) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn EVP_PKEY_size(pkey: *const EVP_PKEY) -> libc::c_int;
    fn EVP_DigestSignInit(
        ctx: *mut EVP_MD_CTX,
        pctx: *mut *mut EVP_PKEY_CTX,
        type_0: *const EVP_MD,
        e: *mut ENGINE,
        pkey: *mut EVP_PKEY,
    ) -> libc::c_int;
    fn EVP_DigestSign(
        ctx: *mut EVP_MD_CTX,
        out_sig: *mut uint8_t,
        out_sig_len: *mut size_t,
        data: *const uint8_t,
        data_len: size_t,
    ) -> libc::c_int;
    fn EVP_PKEY_CTX_get0_pkey(ctx: *mut EVP_PKEY_CTX) -> *mut EVP_PKEY;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
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
pub type EVP_PKEY = evp_pkey_st;
pub type X509_ALGOR = X509_algor_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_algor_st {
    pub algorithm: *mut ASN1_OBJECT,
    pub parameter: *mut ASN1_TYPE,
}
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
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_sign(
    mut it: *const ASN1_ITEM,
    mut algor1: *mut X509_ALGOR,
    mut algor2: *mut X509_ALGOR,
    mut signature: *mut ASN1_BIT_STRING,
    mut asn: *mut libc::c_void,
    mut pkey: *mut EVP_PKEY,
    mut type_0: *const EVP_MD,
) -> libc::c_int {
    if (*signature).type_0 != 3 as libc::c_int {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            191 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/a_sign.c\0" as *const u8
                as *const libc::c_char,
            73 as libc::c_int as libc::c_uint,
        );
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
    if EVP_DigestSignInit(
        &mut ctx,
        0 as *mut *mut EVP_PKEY_CTX,
        type_0,
        0 as *mut ENGINE,
        pkey,
    ) == 0
    {
        EVP_MD_CTX_cleanup(&mut ctx);
        return 0 as libc::c_int;
    }
    return ASN1_item_sign_ctx(it, algor1, algor2, signature, asn, &mut ctx);
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_sign_ctx(
    mut it: *const ASN1_ITEM,
    mut algor1: *mut X509_ALGOR,
    mut algor2: *mut X509_ALGOR,
    mut signature: *mut ASN1_BIT_STRING,
    mut asn: *mut libc::c_void,
    mut ctx: *mut EVP_MD_CTX,
) -> libc::c_int {
    let mut in_len: libc::c_int = 0;
    let mut pkey: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
    let mut out_len: size_t = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut in_0: *mut uint8_t = 0 as *mut uint8_t;
    let mut out: *mut uint8_t = 0 as *mut uint8_t;
    if (*signature).type_0 != 3 as libc::c_int {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            191 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/a_sign.c\0" as *const u8
                as *const libc::c_char,
            91 as libc::c_int as libc::c_uint,
        );
    } else if !(!algor1.is_null() && x509_digest_sign_algorithm(ctx, algor1) == 0) {
        if !(!algor2.is_null() && x509_digest_sign_algorithm(ctx, algor2) == 0) {
            in_len = ASN1_item_i2d(asn as *mut ASN1_VALUE, &mut in_0, it);
            if !(in_len < 0 as libc::c_int) {
                pkey = EVP_PKEY_CTX_get0_pkey((*ctx).pctx);
                out_len = EVP_PKEY_size(pkey) as size_t;
                if out_len > 2147483647 as libc::c_int as size_t {
                    ERR_put_error(
                        11 as libc::c_int,
                        0 as libc::c_int,
                        5 as libc::c_int | 64 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/a_sign.c\0"
                            as *const u8 as *const libc::c_char,
                        111 as libc::c_int as libc::c_uint,
                    );
                } else {
                    out = OPENSSL_malloc(out_len) as *mut uint8_t;
                    if !out.is_null() {
                        if EVP_DigestSign(ctx, out, &mut out_len, in_0, in_len as size_t)
                            == 0
                        {
                            ERR_put_error(
                                11 as libc::c_int,
                                0 as libc::c_int,
                                6 as libc::c_int,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/a_sign.c\0"
                                    as *const u8 as *const libc::c_char,
                                121 as libc::c_int as libc::c_uint,
                            );
                        } else {
                            ASN1_STRING_set0(
                                signature,
                                out as *mut libc::c_void,
                                out_len as libc::c_int,
                            );
                            out = 0 as *mut uint8_t;
                            (*signature).flags
                                &= !(0x8 as libc::c_int | 0x7 as libc::c_int)
                                    as libc::c_long;
                            (*signature).flags |= 0x8 as libc::c_int as libc::c_long;
                            ret = out_len as libc::c_int;
                        }
                    }
                }
            }
        }
    }
    EVP_MD_CTX_cleanup(ctx);
    OPENSSL_free(in_0 as *mut libc::c_void);
    OPENSSL_free(out as *mut libc::c_void);
    return ret;
}
