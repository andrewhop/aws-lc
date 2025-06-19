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
    pub type evp_pkey_st;
    pub type evp_md_pctx_ops;
    pub type evp_pkey_ctx_st;
    pub type env_md_st;
    fn ASN1_item_i2d(
        val: *mut ASN1_VALUE,
        outp: *mut *mut libc::c_uchar,
        it: *const ASN1_ITEM,
    ) -> libc::c_int;
    fn ASN1_STRING_get0_data(str: *const ASN1_STRING) -> *const libc::c_uchar;
    fn ASN1_STRING_length(str: *const ASN1_STRING) -> libc::c_int;
    fn ASN1_BIT_STRING_num_bytes(
        str: *const ASN1_BIT_STRING,
        out: *mut size_t,
    ) -> libc::c_int;
    fn x509_digest_verify_init(
        ctx: *mut EVP_MD_CTX,
        sigalg: *const X509_ALGOR,
        pkey: *mut EVP_PKEY,
    ) -> libc::c_int;
    fn EVP_MD_CTX_init(ctx: *mut EVP_MD_CTX);
    fn EVP_MD_CTX_cleanup(ctx: *mut EVP_MD_CTX) -> libc::c_int;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn EVP_DigestVerify(
        ctx: *mut EVP_MD_CTX,
        sig: *const uint8_t,
        sig_len: size_t,
        data: *const uint8_t,
        len: size_t,
    ) -> libc::c_int;
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_item_verify(
    mut it: *const ASN1_ITEM,
    mut a: *const X509_ALGOR,
    mut signature: *const ASN1_BIT_STRING,
    mut asn: *mut libc::c_void,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    if pkey.is_null() {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/a_verify.c\0" as *const u8
                as *const libc::c_char,
            75 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut sig_len: size_t = 0;
    if (*signature).type_0 == 3 as libc::c_int {
        if ASN1_BIT_STRING_num_bytes(signature, &mut sig_len) == 0 {
            ERR_put_error(
                11 as libc::c_int,
                0 as libc::c_int,
                109 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/a_verify.c\0"
                    as *const u8 as *const libc::c_char,
                82 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    } else {
        sig_len = ASN1_STRING_length(signature) as size_t;
    }
    let mut ctx: EVP_MD_CTX = env_md_ctx_st {
        digest: 0 as *const EVP_MD,
        md_data: 0 as *mut libc::c_void,
        update: None,
        pctx: 0 as *mut EVP_PKEY_CTX,
        pctx_ops: 0 as *const evp_md_pctx_ops,
        flags: 0,
    };
    let mut buf_in: *mut uint8_t = 0 as *mut uint8_t;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut inl: libc::c_int = 0 as libc::c_int;
    EVP_MD_CTX_init(&mut ctx);
    if !(x509_digest_verify_init(&mut ctx, a, pkey) == 0) {
        inl = ASN1_item_i2d(asn as *mut ASN1_VALUE, &mut buf_in, it);
        if !buf_in.is_null() {
            if EVP_DigestVerify(
                &mut ctx,
                ASN1_STRING_get0_data(signature),
                sig_len,
                buf_in,
                inl as size_t,
            ) == 0
            {
                ERR_put_error(
                    11 as libc::c_int,
                    0 as libc::c_int,
                    6 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/a_verify.c\0"
                        as *const u8 as *const libc::c_char,
                    106 as libc::c_int as libc::c_uint,
                );
            } else {
                ret = 1 as libc::c_int;
            }
        }
    }
    OPENSSL_free(buf_in as *mut libc::c_void);
    EVP_MD_CTX_cleanup(&mut ctx);
    return ret;
}
