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
    pub type kem_key_st;
    pub type ec_key_st;
    pub type dh_st;
    pub type dsa_st;
    pub type rsa_st;
    pub type engine_st;
    pub type evp_md_pctx_ops;
    pub type env_md_st;
    fn X509_ALGOR_set0(
        alg: *mut X509_ALGOR,
        obj: *mut ASN1_OBJECT,
        param_type: libc::c_int,
        param_value: *mut libc::c_void,
    ) -> libc::c_int;
    fn x509_rsa_pss_to_ctx(
        ctx: *mut EVP_MD_CTX,
        sigalg: *const X509_ALGOR,
        pkey: *mut EVP_PKEY,
    ) -> libc::c_int;
    fn x509_rsa_ctx_to_pss(ctx: *mut EVP_MD_CTX, algor: *mut X509_ALGOR) -> libc::c_int;
    fn EVP_get_digestbynid(nid: libc::c_int) -> *const EVP_MD;
    fn EVP_MD_type(md: *const EVP_MD) -> libc::c_int;
    fn EVP_MD_CTX_md(ctx: *const EVP_MD_CTX) -> *const EVP_MD;
    fn EVP_PKEY_id(pkey: *const EVP_PKEY) -> libc::c_int;
    fn EVP_DigestVerifyInit(
        ctx: *mut EVP_MD_CTX,
        pctx: *mut *mut EVP_PKEY_CTX,
        type_0: *const EVP_MD,
        e: *mut ENGINE,
        pkey: *mut EVP_PKEY,
    ) -> libc::c_int;
    fn EVP_PKEY_CTX_get0_pkey(ctx: *mut EVP_PKEY_CTX) -> *mut EVP_PKEY;
    fn EVP_PKEY_CTX_get_rsa_padding(
        ctx: *mut EVP_PKEY_CTX,
        out_padding: *mut libc::c_int,
    ) -> libc::c_int;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OBJ_obj2nid(obj: *const ASN1_OBJECT) -> libc::c_int;
    fn OBJ_nid2obj(nid: libc::c_int) -> *mut ASN1_OBJECT;
    fn OBJ_find_sigid_algs(
        sign_nid: libc::c_int,
        out_digest_nid: *mut libc::c_int,
        out_pkey_nid: *mut libc::c_int,
    ) -> libc::c_int;
    fn OBJ_find_sigid_by_algs(
        out_sign_nid: *mut libc::c_int,
        digest_nid: libc::c_int,
        pkey_nid: libc::c_int,
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_pkey_st {
    pub references: CRYPTO_refcount_t,
    pub type_0: libc::c_int,
    pub pkey: C2RustUnnamed_1,
    pub ameth: *const EVP_PKEY_ASN1_METHOD,
}
pub type EVP_PKEY_ASN1_METHOD = evp_pkey_asn1_method_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_pkey_asn1_method_st {
    pub pkey_id: libc::c_int,
    pub oid: [uint8_t; 11],
    pub oid_len: uint8_t,
    pub pem_str: *const libc::c_char,
    pub info: *const libc::c_char,
    pub pub_decode: Option::<
        unsafe extern "C" fn(*mut EVP_PKEY, *mut CBS, *mut CBS, *mut CBS) -> libc::c_int,
    >,
    pub pub_encode: Option::<
        unsafe extern "C" fn(*mut CBB, *const EVP_PKEY) -> libc::c_int,
    >,
    pub pub_cmp: Option::<
        unsafe extern "C" fn(*const EVP_PKEY, *const EVP_PKEY) -> libc::c_int,
    >,
    pub priv_decode: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY,
            *mut CBS,
            *mut CBS,
            *mut CBS,
            *mut CBS,
        ) -> libc::c_int,
    >,
    pub priv_encode: Option::<
        unsafe extern "C" fn(*mut CBB, *const EVP_PKEY) -> libc::c_int,
    >,
    pub priv_encode_v2: Option::<
        unsafe extern "C" fn(*mut CBB, *const EVP_PKEY) -> libc::c_int,
    >,
    pub set_priv_raw: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub set_pub_raw: Option::<
        unsafe extern "C" fn(*mut EVP_PKEY, *const uint8_t, size_t) -> libc::c_int,
    >,
    pub get_priv_raw: Option::<
        unsafe extern "C" fn(*const EVP_PKEY, *mut uint8_t, *mut size_t) -> libc::c_int,
    >,
    pub get_pub_raw: Option::<
        unsafe extern "C" fn(*const EVP_PKEY, *mut uint8_t, *mut size_t) -> libc::c_int,
    >,
    pub pkey_opaque: Option::<unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int>,
    pub pkey_size: Option::<unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int>,
    pub pkey_bits: Option::<unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int>,
    pub param_missing: Option::<unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int>,
    pub param_copy: Option::<
        unsafe extern "C" fn(*mut EVP_PKEY, *const EVP_PKEY) -> libc::c_int,
    >,
    pub param_cmp: Option::<
        unsafe extern "C" fn(*const EVP_PKEY, *const EVP_PKEY) -> libc::c_int,
    >,
    pub pkey_free: Option::<unsafe extern "C" fn(*mut EVP_PKEY) -> ()>,
}
pub type CBB = cbb_st;
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
pub type CBS = cbs_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cbs_st {
    pub data: *const uint8_t,
    pub len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_1 {
    pub ptr: *mut libc::c_void,
    pub rsa: *mut RSA,
    pub dsa: *mut DSA,
    pub dh: *mut DH,
    pub ec: *mut EC_KEY,
    pub kem_key: *mut KEM_KEY,
    pub pqdsa_key: *mut PQDSA_KEY,
}
pub type PQDSA_KEY = pqdsa_key_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pqdsa_key_st {
    pub pqdsa: *const PQDSA,
    pub public_key: *mut uint8_t,
    pub private_key: *mut uint8_t,
    pub seed: *mut uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PQDSA {
    pub nid: libc::c_int,
    pub oid: *const uint8_t,
    pub oid_len: uint8_t,
    pub comment: *const libc::c_char,
    pub public_key_len: size_t,
    pub private_key_len: size_t,
    pub signature_len: size_t,
    pub keygen_seed_len: size_t,
    pub sign_seed_len: size_t,
    pub method: *const PQDSA_METHOD,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PQDSA_METHOD {
    pub pqdsa_keygen: Option::<
        unsafe extern "C" fn(*mut uint8_t, *mut uint8_t, *mut uint8_t) -> libc::c_int,
    >,
    pub pqdsa_keygen_internal: Option::<
        unsafe extern "C" fn(*mut uint8_t, *mut uint8_t, *const uint8_t) -> libc::c_int,
    >,
    pub pqdsa_sign_message: Option::<
        unsafe extern "C" fn(
            *const uint8_t,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub pqdsa_sign: Option::<
        unsafe extern "C" fn(
            *const uint8_t,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub pqdsa_verify_message: Option::<
        unsafe extern "C" fn(
            *const uint8_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub pqdsa_verify: Option::<
        unsafe extern "C" fn(
            *const uint8_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub pqdsa_pack_pk_from_sk: Option::<
        unsafe extern "C" fn(*mut uint8_t, *const uint8_t) -> libc::c_int,
    >,
}
pub type KEM_KEY = kem_key_st;
pub type EC_KEY = ec_key_st;
pub type DH = dh_st;
pub type DSA = dsa_st;
pub type RSA = rsa_st;
pub type CRYPTO_refcount_t = uint32_t;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_pkey_ctx_st {
    pub pmeth: *const EVP_PKEY_METHOD,
    pub engine: *mut ENGINE,
    pub pkey: *mut EVP_PKEY,
    pub peerkey: *mut EVP_PKEY,
    pub operation: libc::c_int,
    pub data: *mut libc::c_void,
    pub app_data: *mut libc::c_void,
    pub pkey_gencb: Option::<EVP_PKEY_gen_cb>,
    pub keygen_info: [libc::c_int; 2],
}
pub type EVP_PKEY_gen_cb = unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> libc::c_int;
pub type EVP_PKEY_METHOD = evp_pkey_method_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_pkey_method_st {
    pub pkey_id: libc::c_int,
    pub init: Option::<unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> libc::c_int>,
    pub copy: Option::<
        unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY_CTX) -> libc::c_int,
    >,
    pub cleanup: Option::<unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> ()>,
    pub keygen: Option::<
        unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY) -> libc::c_int,
    >,
    pub sign_init: Option::<unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> libc::c_int>,
    pub sign: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub sign_message: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub verify_init: Option::<unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> libc::c_int>,
    pub verify: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub verify_message: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub verify_recover: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub encrypt: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub decrypt: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub derive: Option::<
        unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut uint8_t, *mut size_t) -> libc::c_int,
    >,
    pub paramgen: Option::<
        unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY) -> libc::c_int,
    >,
    pub ctrl: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            libc::c_int,
            libc::c_int,
            *mut libc::c_void,
        ) -> libc::c_int,
    >,
    pub ctrl_str: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *const libc::c_char,
            *const libc::c_char,
        ) -> libc::c_int,
    >,
    pub keygen_deterministic: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut EVP_PKEY,
            *const uint8_t,
            *mut size_t,
        ) -> libc::c_int,
    >,
    pub encapsulate_deterministic: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut uint8_t,
            *mut size_t,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            *mut size_t,
        ) -> libc::c_int,
    >,
    pub encapsulate: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut uint8_t,
            *mut size_t,
            *mut uint8_t,
            *mut size_t,
        ) -> libc::c_int,
    >,
    pub decapsulate: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
}
pub type EVP_MD_CTX = env_md_ctx_st;
pub type EVP_MD = env_md_st;
unsafe extern "C" fn x509_digest_nid_ok(digest_nid: libc::c_int) -> libc::c_int {
    match digest_nid {
        257 | 4 => return 0 as libc::c_int,
        _ => {}
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn x509_digest_sign_algorithm(
    mut ctx: *mut EVP_MD_CTX,
    mut algor: *mut X509_ALGOR,
) -> libc::c_int {
    let mut pkey: *mut EVP_PKEY = EVP_PKEY_CTX_get0_pkey((*ctx).pctx);
    if pkey.is_null() {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            108 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/algorithm.c\0" as *const u8
                as *const libc::c_char,
            82 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if EVP_PKEY_id(pkey) == 6 as libc::c_int {
        let mut pad_mode: libc::c_int = 0;
        if EVP_PKEY_CTX_get_rsa_padding((*ctx).pctx, &mut pad_mode) == 0 {
            return 0 as libc::c_int;
        }
        if pad_mode == 6 as libc::c_int {
            return x509_rsa_ctx_to_pss(ctx, algor);
        }
    }
    if EVP_PKEY_id(pkey) == 949 as libc::c_int {
        return X509_ALGOR_set0(
            algor,
            OBJ_nid2obj(949 as libc::c_int),
            -(1 as libc::c_int),
            0 as *mut libc::c_void,
        );
    }
    if EVP_PKEY_id(pkey) == 993 as libc::c_int {
        return X509_ALGOR_set0(
            algor,
            OBJ_nid2obj((*(*(*pkey).pkey.pqdsa_key).pqdsa).nid),
            -(1 as libc::c_int),
            0 as *mut libc::c_void,
        );
    }
    let mut digest: *const EVP_MD = EVP_MD_CTX_md(ctx);
    if digest.is_null() {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            108 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/algorithm.c\0" as *const u8
                as *const libc::c_char,
            109 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let digest_nid: libc::c_int = EVP_MD_type(digest);
    let mut sign_nid: libc::c_int = 0;
    if x509_digest_nid_ok(digest_nid) == 0
        || OBJ_find_sigid_by_algs(&mut sign_nid, digest_nid, EVP_PKEY_id(pkey)) == 0
    {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            111 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/algorithm.c\0" as *const u8
                as *const libc::c_char,
            117 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut paramtype: libc::c_int = if EVP_PKEY_id(pkey) == 6 as libc::c_int {
        5 as libc::c_int
    } else {
        -(1 as libc::c_int)
    };
    return X509_ALGOR_set0(
        algor,
        OBJ_nid2obj(sign_nid),
        paramtype,
        0 as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn x509_digest_verify_init(
    mut ctx: *mut EVP_MD_CTX,
    mut sigalg: *const X509_ALGOR,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    let mut sigalg_nid: libc::c_int = OBJ_obj2nid((*sigalg).algorithm);
    let mut digest_nid: libc::c_int = 0;
    let mut pkey_nid: libc::c_int = 0;
    if OBJ_find_sigid_algs(sigalg_nid, &mut digest_nid, &mut pkey_nid) == 0 {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            184 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/algorithm.c\0" as *const u8
                as *const libc::c_char,
            134 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if pkey_nid != EVP_PKEY_id(pkey)
        && !(sigalg_nid == 912 as libc::c_int && pkey_nid == 6 as libc::c_int
            && EVP_PKEY_id(pkey) == 912 as libc::c_int)
        && !(sigalg_nid == 995 as libc::c_int && pkey_nid == 995 as libc::c_int
            && EVP_PKEY_id(pkey) == 993 as libc::c_int)
    {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            189 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/algorithm.c\0" as *const u8
                as *const libc::c_char,
            147 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if x509_digest_nid_ok(digest_nid) == 0 {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            111 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/algorithm.c\0" as *const u8
                as *const libc::c_char,
            153 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if digest_nid == 0 as libc::c_int {
        if sigalg_nid == 912 as libc::c_int {
            return x509_rsa_pss_to_ctx(ctx, sigalg, pkey);
        }
        if sigalg_nid == 949 as libc::c_int || sigalg_nid == 995 as libc::c_int {
            if !((*sigalg).parameter).is_null() {
                ERR_put_error(
                    11 as libc::c_int,
                    0 as libc::c_int,
                    136 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/algorithm.c\0"
                        as *const u8 as *const libc::c_char,
                    165 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            return EVP_DigestVerifyInit(
                ctx,
                0 as *mut *mut EVP_PKEY_CTX,
                0 as *const EVP_MD,
                0 as *mut ENGINE,
                pkey,
            );
        }
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            184 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/algorithm.c\0" as *const u8
                as *const libc::c_char,
            170 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if !((*sigalg).parameter).is_null()
        && (*(*sigalg).parameter).type_0 != 5 as libc::c_int
    {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            136 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/algorithm.c\0" as *const u8
                as *const libc::c_char,
            180 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut digest: *const EVP_MD = EVP_get_digestbynid(digest_nid);
    if digest.is_null() {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            183 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/algorithm.c\0" as *const u8
                as *const libc::c_char,
            187 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return EVP_DigestVerifyInit(
        ctx,
        0 as *mut *mut EVP_PKEY_CTX,
        digest,
        0 as *mut ENGINE,
        pkey,
    );
}
