#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(extern_types, label_break_value)]
extern "C" {
    pub type asn1_pctx_st;
    pub type ASN1_VALUE_st;
    pub type evp_pkey_st;
    pub type stack_st_void;
    pub type engine_st;
    pub type evp_md_pctx_ops;
    pub type evp_pkey_ctx_st;
    pub type env_md_st;
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
    fn ASN1_item_pack(
        obj: *mut libc::c_void,
        it: *const ASN1_ITEM,
        out: *mut *mut ASN1_STRING,
    ) -> *mut ASN1_STRING;
    fn ASN1_STRING_free(str: *mut ASN1_STRING);
    fn ASN1_INTEGER_new() -> *mut ASN1_INTEGER;
    static ASN1_INTEGER_it: ASN1_ITEM;
    fn ASN1_INTEGER_set_int64(out: *mut ASN1_INTEGER, v: int64_t) -> libc::c_int;
    fn i2a_ASN1_INTEGER(bp: *mut BIO, a: *const ASN1_INTEGER) -> libc::c_int;
    fn i2a_ASN1_OBJECT(bp: *mut BIO, a: *const ASN1_OBJECT) -> libc::c_int;
    fn ASN1_INTEGER_get(a: *const ASN1_INTEGER) -> libc::c_long;
    static X509_ALGOR_it: ASN1_ITEM;
    fn X509_ALGOR_new() -> *mut X509_ALGOR;
    fn X509_ALGOR_free(alg: *mut X509_ALGOR);
    fn d2i_X509_ALGOR(
        out: *mut *mut X509_ALGOR,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut X509_ALGOR;
    fn X509_ALGOR_set0(
        alg: *mut X509_ALGOR,
        obj: *mut ASN1_OBJECT,
        param_type: libc::c_int,
        param_value: *mut libc::c_void,
    ) -> libc::c_int;
    fn X509_ALGOR_set_md(alg: *mut X509_ALGOR, md: *const EVP_MD) -> libc::c_int;
    fn BIO_puts(bio: *mut BIO, buf: *const libc::c_char) -> libc::c_int;
    fn BIO_indent(
        bio: *mut BIO,
        indent: libc::c_uint,
        max_indent: libc::c_uint,
    ) -> libc::c_int;
    fn EVP_sha1() -> *const EVP_MD;
    fn EVP_get_digestbyobj(obj: *const ASN1_OBJECT) -> *const EVP_MD;
    fn EVP_MD_type(md: *const EVP_MD) -> libc::c_int;
    fn EVP_MD_size(md: *const EVP_MD) -> size_t;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OBJ_obj2nid(obj: *const ASN1_OBJECT) -> libc::c_int;
    fn OBJ_nid2obj(nid: libc::c_int) -> *mut ASN1_OBJECT;
    fn EVP_PKEY_size(pkey: *const EVP_PKEY) -> libc::c_int;
    fn EVP_PKEY_bits(pkey: *const EVP_PKEY) -> libc::c_int;
    fn EVP_DigestVerifyInit(
        ctx: *mut EVP_MD_CTX,
        pctx: *mut *mut EVP_PKEY_CTX,
        type_0: *const EVP_MD,
        e: *mut ENGINE,
        pkey: *mut EVP_PKEY,
    ) -> libc::c_int;
    fn EVP_PKEY_CTX_get0_pkey(ctx: *mut EVP_PKEY_CTX) -> *mut EVP_PKEY;
    fn EVP_PKEY_CTX_get_signature_md(
        ctx: *mut EVP_PKEY_CTX,
        out_md: *mut *const EVP_MD,
    ) -> libc::c_int;
    fn EVP_PKEY_CTX_set_rsa_padding(
        ctx: *mut EVP_PKEY_CTX,
        padding: libc::c_int,
    ) -> libc::c_int;
    fn EVP_PKEY_CTX_set_rsa_pss_saltlen(
        ctx: *mut EVP_PKEY_CTX,
        salt_len: libc::c_int,
    ) -> libc::c_int;
    fn EVP_PKEY_CTX_get_rsa_pss_saltlen(
        ctx: *mut EVP_PKEY_CTX,
        out_salt_len: *mut libc::c_int,
    ) -> libc::c_int;
    fn EVP_PKEY_CTX_set_rsa_mgf1_md(
        ctx: *mut EVP_PKEY_CTX,
        md: *const EVP_MD,
    ) -> libc::c_int;
    fn EVP_PKEY_CTX_get_rsa_mgf1_md(
        ctx: *mut EVP_PKEY_CTX,
        out_md: *mut *const EVP_MD,
    ) -> libc::c_int;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
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
pub type EVP_PKEY = evp_pkey_st;
pub type X509_ALGOR = X509_algor_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_algor_st {
    pub algorithm: *mut ASN1_OBJECT,
    pub parameter: *mut ASN1_TYPE,
}
pub type CRYPTO_refcount_t = uint32_t;
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
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
pub struct rsa_pss_params_st {
    pub hashAlgorithm: *mut X509_ALGOR,
    pub maskGenAlgorithm: *mut X509_ALGOR,
    pub saltLength: *mut ASN1_INTEGER,
    pub trailerField: *mut ASN1_INTEGER,
    pub maskHash: *mut X509_ALGOR,
}
pub type RSA_PSS_PARAMS = rsa_pss_params_st;
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
unsafe extern "C" fn rsa_pss_cb(
    mut operation: libc::c_int,
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
    mut exarg: *mut libc::c_void,
) -> libc::c_int {
    if operation == 2 as libc::c_int {
        let mut pss: *mut RSA_PSS_PARAMS = *pval as *mut RSA_PSS_PARAMS;
        X509_ALGOR_free((*pss).maskHash);
    }
    return 1 as libc::c_int;
}
static mut RSA_PSS_PARAMS_aux: ASN1_AUX = unsafe {
    {
        let mut init = ASN1_AUX_st {
            app_data: 0 as *const libc::c_void as *mut libc::c_void,
            flags: 0 as libc::c_int as uint32_t,
            ref_offset: 0 as libc::c_int,
            asn1_cb: Some(
                rsa_pss_cb
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
static mut RSA_PSS_PARAMS_seq_tt: [ASN1_TEMPLATE; 4] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"hashAlgorithm\0" as *const u8 as *const libc::c_char,
                item: &X509_ALGOR_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 1 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"maskGenAlgorithm\0" as *const u8 as *const libc::c_char,
                item: &X509_ALGOR_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 2 as libc::c_int,
                offset: 16 as libc::c_ulong,
                field_name: b"saltLength\0" as *const u8 as *const libc::c_char,
                item: &ASN1_INTEGER_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 3 as libc::c_int,
                offset: 24 as libc::c_ulong,
                field_name: b"trailerField\0" as *const u8 as *const libc::c_char,
                item: &ASN1_INTEGER_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut RSA_PSS_PARAMS_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[no_mangle]
pub unsafe extern "C" fn RSA_PSS_PARAMS_free(mut a: *mut RSA_PSS_PARAMS) {
    ASN1_item_free(a as *mut ASN1_VALUE, &RSA_PSS_PARAMS_it);
}
#[no_mangle]
pub unsafe extern "C" fn i2d_RSA_PSS_PARAMS(
    mut a: *const RSA_PSS_PARAMS,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &RSA_PSS_PARAMS_it);
}
#[no_mangle]
pub unsafe extern "C" fn d2i_RSA_PSS_PARAMS(
    mut a: *mut *mut RSA_PSS_PARAMS,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut RSA_PSS_PARAMS {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &RSA_PSS_PARAMS_it)
        as *mut RSA_PSS_PARAMS;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_PSS_PARAMS_new() -> *mut RSA_PSS_PARAMS {
    return ASN1_item_new(&RSA_PSS_PARAMS_it) as *mut RSA_PSS_PARAMS;
}
unsafe extern "C" fn rsa_mgf1_decode(mut alg: *mut X509_ALGOR) -> *mut X509_ALGOR {
    if alg.is_null() || ((*alg).parameter).is_null()
        || OBJ_obj2nid((*alg).algorithm) != 911 as libc::c_int
        || (*(*alg).parameter).type_0 != 16 as libc::c_int
    {
        return 0 as *mut X509_ALGOR;
    }
    let mut p: *const uint8_t = (*(*(*alg).parameter).value.sequence).data;
    let mut plen: libc::c_int = (*(*(*alg).parameter).value.sequence).length;
    return d2i_X509_ALGOR(0 as *mut *mut X509_ALGOR, &mut p, plen as libc::c_long);
}
unsafe extern "C" fn rsa_pss_decode(
    mut alg: *const X509_ALGOR,
    mut pmaskHash: *mut *mut X509_ALGOR,
) -> *mut RSA_PSS_PARAMS {
    *pmaskHash = 0 as *mut X509_ALGOR;
    if ((*alg).parameter).is_null() || (*(*alg).parameter).type_0 != 16 as libc::c_int {
        return 0 as *mut RSA_PSS_PARAMS;
    }
    let mut p: *const uint8_t = (*(*(*alg).parameter).value.sequence).data;
    let mut plen: libc::c_int = (*(*(*alg).parameter).value.sequence).length;
    let mut pss: *mut RSA_PSS_PARAMS = d2i_RSA_PSS_PARAMS(
        0 as *mut *mut RSA_PSS_PARAMS,
        &mut p,
        plen as libc::c_long,
    );
    if pss.is_null() {
        return 0 as *mut RSA_PSS_PARAMS;
    }
    *pmaskHash = rsa_mgf1_decode((*pss).maskGenAlgorithm);
    return pss;
}
unsafe extern "C" fn rsa_md_to_algor(
    mut palg: *mut *mut X509_ALGOR,
    mut md: *const EVP_MD,
) -> libc::c_int {
    if EVP_MD_type(md) == 64 as libc::c_int {
        return 1 as libc::c_int;
    }
    *palg = X509_ALGOR_new();
    if (*palg).is_null() {
        return 0 as libc::c_int;
    }
    if X509_ALGOR_set_md(*palg, md) == 0 {
        X509_ALGOR_free(*palg);
        *palg = 0 as *mut X509_ALGOR;
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn rsa_md_to_mgf1(
    mut palg: *mut *mut X509_ALGOR,
    mut mgf1md: *const EVP_MD,
) -> libc::c_int {
    let mut algtmp: *mut X509_ALGOR = 0 as *mut X509_ALGOR;
    let mut stmp: *mut ASN1_STRING = 0 as *mut ASN1_STRING;
    *palg = 0 as *mut X509_ALGOR;
    if EVP_MD_type(mgf1md) == 64 as libc::c_int {
        return 1 as libc::c_int;
    }
    if !(rsa_md_to_algor(&mut algtmp, mgf1md) == 0
        || (ASN1_item_pack(algtmp as *mut libc::c_void, &X509_ALGOR_it, &mut stmp))
            .is_null())
    {
        *palg = X509_ALGOR_new();
        if !(*palg).is_null() {
            if !(X509_ALGOR_set0(
                *palg,
                OBJ_nid2obj(911 as libc::c_int),
                16 as libc::c_int,
                stmp as *mut libc::c_void,
            ) == 0)
            {
                stmp = 0 as *mut ASN1_STRING;
            }
        }
    }
    ASN1_STRING_free(stmp);
    X509_ALGOR_free(algtmp);
    if !(*palg).is_null() {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn rsa_algor_to_md(mut alg: *mut X509_ALGOR) -> *const EVP_MD {
    let mut md: *const EVP_MD = 0 as *const EVP_MD;
    if alg.is_null() {
        return EVP_sha1();
    }
    md = EVP_get_digestbyobj((*alg).algorithm);
    if md.is_null() {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            112 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/rsa_pss.c\0" as *const u8
                as *const libc::c_char,
            179 as libc::c_int as libc::c_uint,
        );
    }
    return md;
}
unsafe extern "C" fn rsa_mgf1_to_md(
    mut alg: *const X509_ALGOR,
    mut maskHash: *mut X509_ALGOR,
) -> *const EVP_MD {
    let mut md: *const EVP_MD = 0 as *const EVP_MD;
    if alg.is_null() {
        return EVP_sha1();
    }
    if OBJ_obj2nid((*alg).algorithm) != 911 as libc::c_int || maskHash.is_null() {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            112 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/rsa_pss.c\0" as *const u8
                as *const libc::c_char,
            193 as libc::c_int as libc::c_uint,
        );
        return 0 as *const EVP_MD;
    }
    md = EVP_get_digestbyobj((*maskHash).algorithm);
    if md.is_null() {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            112 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/rsa_pss.c\0" as *const u8
                as *const libc::c_char,
            198 as libc::c_int as libc::c_uint,
        );
        return 0 as *const EVP_MD;
    }
    return md;
}
#[no_mangle]
pub unsafe extern "C" fn x509_rsa_ctx_to_pss(
    mut ctx: *mut EVP_MD_CTX,
    mut algor: *mut X509_ALGOR,
) -> libc::c_int {
    let mut current_block: u64;
    let mut sigmd: *const EVP_MD = 0 as *const EVP_MD;
    let mut mgf1md: *const EVP_MD = 0 as *const EVP_MD;
    let mut saltlen: libc::c_int = 0;
    if EVP_PKEY_CTX_get_signature_md((*ctx).pctx, &mut sigmd) == 0
        || EVP_PKEY_CTX_get_rsa_mgf1_md((*ctx).pctx, &mut mgf1md) == 0
        || EVP_PKEY_CTX_get_rsa_pss_saltlen((*ctx).pctx, &mut saltlen) == 0
    {
        return 0 as libc::c_int;
    }
    let mut pk: *mut EVP_PKEY = EVP_PKEY_CTX_get0_pkey((*ctx).pctx);
    if saltlen == -(1 as libc::c_int) {
        saltlen = EVP_MD_size(sigmd) as libc::c_int;
    } else if saltlen == -(2 as libc::c_int) {
        saltlen = (EVP_PKEY_size(pk) as size_t)
            .wrapping_sub(EVP_MD_size(sigmd))
            .wrapping_sub(2 as libc::c_int as size_t) as libc::c_int;
        if EVP_PKEY_bits(pk) - 1 as libc::c_int & 0x7 as libc::c_int == 0 as libc::c_int
        {
            saltlen -= 1;
            saltlen;
        }
    } else if saltlen != EVP_MD_size(sigmd) as libc::c_int {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            112 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/rsa_pss.c\0" as *const u8
                as *const libc::c_char,
            225 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut os: *mut ASN1_STRING = 0 as *mut ASN1_STRING;
    let mut pss: *mut RSA_PSS_PARAMS = RSA_PSS_PARAMS_new();
    if !pss.is_null() {
        if saltlen != 20 as libc::c_int {
            (*pss).saltLength = ASN1_INTEGER_new();
            if ((*pss).saltLength).is_null()
                || ASN1_INTEGER_set_int64((*pss).saltLength, saltlen as int64_t) == 0
            {
                current_block = 7370235848212660886;
            } else {
                current_block = 13242334135786603907;
            }
        } else {
            current_block = 13242334135786603907;
        }
        match current_block {
            7370235848212660886 => {}
            _ => {
                if !(rsa_md_to_algor(&mut (*pss).hashAlgorithm, sigmd) == 0
                    || rsa_md_to_mgf1(&mut (*pss).maskGenAlgorithm, mgf1md) == 0)
                {
                    if !(ASN1_item_pack(
                        pss as *mut libc::c_void,
                        &RSA_PSS_PARAMS_it,
                        &mut os,
                    ))
                        .is_null()
                    {
                        if !(X509_ALGOR_set0(
                            algor,
                            OBJ_nid2obj(912 as libc::c_int),
                            16 as libc::c_int,
                            os as *mut libc::c_void,
                        ) == 0)
                        {
                            os = 0 as *mut ASN1_STRING;
                            ret = 1 as libc::c_int;
                        }
                    }
                }
            }
        }
    }
    RSA_PSS_PARAMS_free(pss);
    ASN1_STRING_free(os);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn x509_rsa_pss_to_ctx(
    mut ctx: *mut EVP_MD_CTX,
    mut sigalg: *const X509_ALGOR,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    let mut mgf1md: *const EVP_MD = 0 as *const EVP_MD;
    let mut md: *const EVP_MD = 0 as *const EVP_MD;
    let mut saltlen: libc::c_int = 0;
    let mut pctx: *mut EVP_PKEY_CTX = 0 as *mut EVP_PKEY_CTX;
    let mut current_block: u64;
    if OBJ_obj2nid((*sigalg).algorithm) == 912 as libc::c_int {} else {
        __assert_fail(
            b"OBJ_obj2nid(sigalg->algorithm) == NID_rsassaPss\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/rsa_pss.c\0" as *const u8
                as *const libc::c_char,
            267 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 70],
                &[libc::c_char; 70],
            >(
                b"int x509_rsa_pss_to_ctx(EVP_MD_CTX *, const X509_ALGOR *, EVP_PKEY *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_30770: {
        if OBJ_obj2nid((*sigalg).algorithm) == 912 as libc::c_int {} else {
            __assert_fail(
                b"OBJ_obj2nid(sigalg->algorithm) == NID_rsassaPss\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/rsa_pss.c\0" as *const u8
                    as *const libc::c_char,
                267 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 70],
                    &[libc::c_char; 70],
                >(
                    b"int x509_rsa_pss_to_ctx(EVP_MD_CTX *, const X509_ALGOR *, EVP_PKEY *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut maskHash: *mut X509_ALGOR = 0 as *mut X509_ALGOR;
    let mut pss: *mut RSA_PSS_PARAMS = rsa_pss_decode(sigalg, &mut maskHash);
    if pss.is_null() {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            112 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/rsa_pss.c\0" as *const u8
                as *const libc::c_char,
            274 as libc::c_int as libc::c_uint,
        );
    } else {
        mgf1md = rsa_mgf1_to_md((*pss).maskGenAlgorithm, maskHash);
        md = rsa_algor_to_md((*pss).hashAlgorithm);
        if !(mgf1md.is_null() || md.is_null()) {
            saltlen = 20 as libc::c_int;
            if !((*pss).saltLength).is_null() {
                saltlen = ASN1_INTEGER_get((*pss).saltLength) as libc::c_int;
                if saltlen < 0 as libc::c_int {
                    ERR_put_error(
                        11 as libc::c_int,
                        0 as libc::c_int,
                        112 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/rsa_pss.c\0"
                            as *const u8 as *const libc::c_char,
                        291 as libc::c_int as libc::c_uint,
                    );
                    current_block = 1213819706323749325;
                } else {
                    current_block = 1917311967535052937;
                }
            } else {
                current_block = 1917311967535052937;
            }
            match current_block {
                1213819706323749325 => {}
                _ => {
                    if !((*pss).trailerField).is_null()
                        && ASN1_INTEGER_get((*pss).trailerField)
                            != 1 as libc::c_int as libc::c_long
                    {
                        ERR_put_error(
                            11 as libc::c_int,
                            0 as libc::c_int,
                            112 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/rsa_pss.c\0"
                                as *const u8 as *const libc::c_char,
                            299 as libc::c_int as libc::c_uint,
                        );
                    } else {
                        pctx = 0 as *mut EVP_PKEY_CTX;
                        if !(EVP_DigestVerifyInit(
                            ctx,
                            &mut pctx,
                            md,
                            0 as *mut ENGINE,
                            pkey,
                        ) == 0
                            || EVP_PKEY_CTX_set_rsa_padding(pctx, 6 as libc::c_int) == 0
                            || EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, saltlen) == 0
                            || EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, mgf1md) == 0)
                        {
                            ret = 1 as libc::c_int;
                        }
                    }
                }
            }
        }
    }
    RSA_PSS_PARAMS_free(pss);
    X509_ALGOR_free(maskHash);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn x509_print_rsa_pss_params(
    mut bp: *mut BIO,
    mut sigalg: *const X509_ALGOR,
    mut indent: libc::c_int,
    mut pctx: *mut ASN1_PCTX,
) -> libc::c_int {
    let mut current_block: u64;
    if OBJ_obj2nid((*sigalg).algorithm) == 912 as libc::c_int {} else {
        __assert_fail(
            b"OBJ_obj2nid(sigalg->algorithm) == NID_rsassaPss\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/rsa_pss.c\0" as *const u8
                as *const libc::c_char,
            321 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 75],
                &[libc::c_char; 75],
            >(
                b"int x509_print_rsa_pss_params(BIO *, const X509_ALGOR *, int, ASN1_PCTX *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_31704: {
        if OBJ_obj2nid((*sigalg).algorithm) == 912 as libc::c_int {} else {
            __assert_fail(
                b"OBJ_obj2nid(sigalg->algorithm) == NID_rsassaPss\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/rsa_pss.c\0" as *const u8
                    as *const libc::c_char,
                321 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 75],
                    &[libc::c_char; 75],
                >(
                    b"int x509_print_rsa_pss_params(BIO *, const X509_ALGOR *, int, ASN1_PCTX *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut rv: libc::c_int = 0 as libc::c_int;
    let mut maskHash: *mut X509_ALGOR = 0 as *mut X509_ALGOR;
    let mut pss: *mut RSA_PSS_PARAMS = rsa_pss_decode(sigalg, &mut maskHash);
    if pss.is_null() {
        if !(BIO_puts(
            bp,
            b" (INVALID PSS PARAMETERS)\n\0" as *const u8 as *const libc::c_char,
        ) <= 0 as libc::c_int)
        {
            rv = 1 as libc::c_int;
        }
    } else if !(BIO_puts(bp, b"\n\0" as *const u8 as *const libc::c_char)
        <= 0 as libc::c_int
        || BIO_indent(bp, indent as libc::c_uint, 128 as libc::c_int as libc::c_uint)
            == 0
        || BIO_puts(bp, b"Hash Algorithm: \0" as *const u8 as *const libc::c_char)
            <= 0 as libc::c_int)
    {
        if !((*pss).hashAlgorithm).is_null() {
            if i2a_ASN1_OBJECT(bp, (*(*pss).hashAlgorithm).algorithm) <= 0 as libc::c_int
            {
                current_block = 10147784506383650182;
            } else {
                current_block = 11650488183268122163;
            }
        } else if BIO_puts(bp, b"sha1 (default)\0" as *const u8 as *const libc::c_char)
            <= 0 as libc::c_int
        {
            current_block = 10147784506383650182;
        } else {
            current_block = 11650488183268122163;
        }
        match current_block {
            10147784506383650182 => {}
            _ => {
                if !(BIO_puts(bp, b"\n\0" as *const u8 as *const libc::c_char)
                    <= 0 as libc::c_int
                    || BIO_indent(
                        bp,
                        indent as libc::c_uint,
                        128 as libc::c_int as libc::c_uint,
                    ) == 0
                    || BIO_puts(
                        bp,
                        b"Mask Algorithm: \0" as *const u8 as *const libc::c_char,
                    ) <= 0 as libc::c_int)
                {
                    if !((*pss).maskGenAlgorithm).is_null() {
                        if i2a_ASN1_OBJECT(bp, (*(*pss).maskGenAlgorithm).algorithm)
                            <= 0 as libc::c_int
                            || BIO_puts(
                                bp,
                                b" with \0" as *const u8 as *const libc::c_char,
                            ) <= 0 as libc::c_int
                        {
                            current_block = 10147784506383650182;
                        } else if !maskHash.is_null() {
                            if i2a_ASN1_OBJECT(bp, (*maskHash).algorithm)
                                <= 0 as libc::c_int
                            {
                                current_block = 10147784506383650182;
                            } else {
                                current_block = 224731115979188411;
                            }
                        } else if BIO_puts(
                            bp,
                            b"INVALID\0" as *const u8 as *const libc::c_char,
                        ) <= 0 as libc::c_int
                        {
                            current_block = 10147784506383650182;
                        } else {
                            current_block = 224731115979188411;
                        }
                    } else if BIO_puts(
                        bp,
                        b"mgf1 with sha1 (default)\0" as *const u8 as *const libc::c_char,
                    ) <= 0 as libc::c_int
                    {
                        current_block = 10147784506383650182;
                    } else {
                        current_block = 224731115979188411;
                    }
                    match current_block {
                        10147784506383650182 => {}
                        _ => {
                            BIO_puts(bp, b"\n\0" as *const u8 as *const libc::c_char);
                            if !(BIO_indent(
                                bp,
                                indent as libc::c_uint,
                                128 as libc::c_int as libc::c_uint,
                            ) == 0
                                || BIO_puts(
                                    bp,
                                    b"Salt Length: 0x\0" as *const u8 as *const libc::c_char,
                                ) <= 0 as libc::c_int)
                            {
                                if !((*pss).saltLength).is_null() {
                                    if i2a_ASN1_INTEGER(bp, (*pss).saltLength)
                                        <= 0 as libc::c_int
                                    {
                                        current_block = 10147784506383650182;
                                    } else {
                                        current_block = 14763689060501151050;
                                    }
                                } else if BIO_puts(
                                    bp,
                                    b"14 (default)\0" as *const u8 as *const libc::c_char,
                                ) <= 0 as libc::c_int
                                {
                                    current_block = 10147784506383650182;
                                } else {
                                    current_block = 14763689060501151050;
                                }
                                match current_block {
                                    10147784506383650182 => {}
                                    _ => {
                                        BIO_puts(bp, b"\n\0" as *const u8 as *const libc::c_char);
                                        if !(BIO_indent(
                                            bp,
                                            indent as libc::c_uint,
                                            128 as libc::c_int as libc::c_uint,
                                        ) == 0
                                            || BIO_puts(
                                                bp,
                                                b"Trailer Field: 0x\0" as *const u8 as *const libc::c_char,
                                            ) <= 0 as libc::c_int)
                                        {
                                            if !((*pss).trailerField).is_null() {
                                                if i2a_ASN1_INTEGER(bp, (*pss).trailerField)
                                                    <= 0 as libc::c_int
                                                {
                                                    current_block = 10147784506383650182;
                                                } else {
                                                    current_block = 1118134448028020070;
                                                }
                                            } else if BIO_puts(
                                                bp,
                                                b"BC (default)\0" as *const u8 as *const libc::c_char,
                                            ) <= 0 as libc::c_int
                                            {
                                                current_block = 10147784506383650182;
                                            } else {
                                                current_block = 1118134448028020070;
                                            }
                                            match current_block {
                                                10147784506383650182 => {}
                                                _ => {
                                                    BIO_puts(bp, b"\n\0" as *const u8 as *const libc::c_char);
                                                    rv = 1 as libc::c_int;
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
    RSA_PSS_PARAMS_free(pss);
    X509_ALGOR_free(maskHash);
    return rv;
}
unsafe extern "C" fn run_static_initializers() {
    RSA_PSS_PARAMS_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: RSA_PSS_PARAMS_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 4]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: &RSA_PSS_PARAMS_aux as *const ASN1_AUX as *const libc::c_void,
            size: ::core::mem::size_of::<RSA_PSS_PARAMS>() as libc::c_ulong
                as libc::c_long,
            sname: b"RSA_PSS_PARAMS\0" as *const u8 as *const libc::c_char,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
