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
    pub type bignum_ctx;
    pub type dh_st;
    pub type dsa_st;
    pub type ec_group_st;
    pub type ec_key_st;
    pub type ec_point_st;
    pub type engine_st;
    pub type pqdsa_key_st;
    pub type kem_key_st;
    pub type rsa_st;
    fn DSA_up_ref(dsa: *mut DSA) -> libc::c_int;
    fn EVP_MD_nid(md: *const EVP_MD) -> libc::c_int;
    fn EVP_PKEY_CTX_ctrl(
        ctx: *mut EVP_PKEY_CTX,
        keytype: libc::c_int,
        optype: libc::c_int,
        cmd: libc::c_int,
        p1: libc::c_int,
        p2: *mut libc::c_void,
    ) -> libc::c_int;
    fn HMAC_KEY_new() -> *mut HMAC_KEY;
    fn EVP_PKEY_assign_DH(pkey: *mut EVP_PKEY, key: *mut DH) -> libc::c_int;
    fn EVP_PKEY_asn1_find_str(
        _pe: *mut *mut ENGINE,
        name: *const libc::c_char,
        len: libc::c_int,
    ) -> *const EVP_PKEY_ASN1_METHOD;
    fn OBJ_nid2sn(nid: libc::c_int) -> *const libc::c_char;
    fn OBJ_find_sigid_by_algs(
        out_sign_nid: *mut libc::c_int,
        digest_nid: libc::c_int,
        pkey_nid: libc::c_int,
    ) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_memdup(data: *const libc::c_void, size: size_t) -> *mut libc::c_void;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn ERR_add_error_dataf(format: *const libc::c_char, _: ...);
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn EC_GROUP_get_curve_name(group: *const EC_GROUP) -> libc::c_int;
    fn EC_POINT_new(group: *const EC_GROUP) -> *mut EC_POINT;
    fn EC_POINT_free(point: *mut EC_POINT);
    fn EC_POINT_oct2point(
        group: *const EC_GROUP,
        point: *mut EC_POINT,
        buf: *const uint8_t,
        len: size_t,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn EC_KEY_up_ref(key: *mut EC_KEY) -> libc::c_int;
    fn EC_KEY_get0_group(key: *const EC_KEY) -> *const EC_GROUP;
    fn EC_KEY_set_public_key(key: *mut EC_KEY, pub_0: *const EC_POINT) -> libc::c_int;
    fn EC_KEY_get_conv_form(key: *const EC_KEY) -> point_conversion_form_t;
    fn EC_KEY_key2buf(
        key: *const EC_KEY,
        form: point_conversion_form_t,
        out_buf: *mut *mut libc::c_uchar,
        ctx: *mut BN_CTX,
    ) -> size_t;
    fn RSA_up_ref(rsa: *mut RSA) -> libc::c_int;
    static ed25519_asn1_meth: EVP_PKEY_ASN1_METHOD;
    static x25519_asn1_meth: EVP_PKEY_ASN1_METHOD;
    static hmac_asn1_meth: EVP_PKEY_ASN1_METHOD;
    static ed25519ph_asn1_meth: EVP_PKEY_ASN1_METHOD;
    fn AWSLC_non_fips_pkey_evp_asn1_methods() -> *const *const EVP_PKEY_ASN1_METHOD;
    fn CRYPTO_refcount_inc(count: *mut CRYPTO_refcount_t);
    fn CRYPTO_refcount_dec_and_test_zero(count: *mut CRYPTO_refcount_t) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type BN_CTX = bignum_ctx;
pub type CRYPTO_refcount_t = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cbb_st {
    pub child: *mut CBB,
    pub is_child: libc::c_char,
    pub u: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
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
pub type DH = dh_st;
pub type DSA = dsa_st;
pub type EC_GROUP = ec_group_st;
pub type EC_KEY = ec_key_st;
pub type EC_POINT = ec_point_st;
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
pub type EVP_PKEY = evp_pkey_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_pkey_st {
    pub references: CRYPTO_refcount_t,
    pub type_0: libc::c_int,
    pub pkey: C2RustUnnamed_0,
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
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub ptr: *mut libc::c_void,
    pub rsa: *mut RSA,
    pub dsa: *mut DSA,
    pub dh: *mut DH,
    pub ec: *mut EC_KEY,
    pub kem_key: *mut KEM_KEY,
    pub pqdsa_key: *mut PQDSA_KEY,
}
pub type PQDSA_KEY = pqdsa_key_st;
pub type KEM_KEY = kem_key_st;
pub type RSA = rsa_st;
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
pub struct evp_pkey_ctx_signature_context_params_st {
    pub context: *const uint8_t,
    pub context_len: size_t,
}
pub type EVP_PKEY_CTX_SIGNATURE_CONTEXT_PARAMS = evp_pkey_ctx_signature_context_params_st;
pub const POINT_CONVERSION_UNCOMPRESSED: point_conversion_form_t = 4;
pub type point_conversion_form_t = libc::c_uint;
pub const POINT_CONVERSION_HYBRID: point_conversion_form_t = 6;
pub const POINT_CONVERSION_COMPRESSED: point_conversion_form_t = 2;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct HMAC_KEY {
    pub key: *mut uint8_t,
    pub key_len: size_t,
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_new() -> *mut EVP_PKEY {
    let mut ret: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
    ret = OPENSSL_zalloc(::core::mem::size_of::<EVP_PKEY>() as libc::c_ulong)
        as *mut EVP_PKEY;
    if ret.is_null() {
        return 0 as *mut EVP_PKEY;
    }
    (*ret).type_0 = 0 as libc::c_int;
    (*ret).references = 1 as libc::c_int as CRYPTO_refcount_t;
    return ret;
}
unsafe extern "C" fn free_it(mut pkey: *mut EVP_PKEY) {
    if !((*pkey).ameth).is_null() && ((*(*pkey).ameth).pkey_free).is_some() {
        ((*(*pkey).ameth).pkey_free).expect("non-null function pointer")(pkey);
        (*pkey).pkey.ptr = 0 as *mut libc::c_void;
        (*pkey).type_0 = 0 as libc::c_int;
    }
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_free(mut pkey: *mut EVP_PKEY) {
    if pkey.is_null() {
        return;
    }
    if CRYPTO_refcount_dec_and_test_zero(&mut (*pkey).references) == 0 {
        return;
    }
    free_it(pkey);
    OPENSSL_free(pkey as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_up_ref(mut pkey: *mut EVP_PKEY) -> libc::c_int {
    CRYPTO_refcount_inc(&mut (*pkey).references);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_is_opaque(mut pkey: *const EVP_PKEY) -> libc::c_int {
    if !((*pkey).ameth).is_null() && ((*(*pkey).ameth).pkey_opaque).is_some() {
        return ((*(*pkey).ameth).pkey_opaque).expect("non-null function pointer")(pkey);
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_cmp(
    mut a: *const EVP_PKEY,
    mut b: *const EVP_PKEY,
) -> libc::c_int {
    if (*a).type_0 != (*b).type_0 {
        return -(1 as libc::c_int);
    }
    if !((*a).ameth).is_null() {
        let mut ret: libc::c_int = 0;
        if ((*(*a).ameth).param_cmp).is_some() {
            ret = ((*(*a).ameth).param_cmp).expect("non-null function pointer")(a, b);
            if ret <= 0 as libc::c_int {
                return ret;
            }
        }
        if ((*(*a).ameth).pub_cmp).is_some() {
            return ((*(*a).ameth).pub_cmp).expect("non-null function pointer")(a, b);
        }
    }
    return -(2 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_copy_parameters(
    mut to: *mut EVP_PKEY,
    mut from: *const EVP_PKEY,
) -> libc::c_int {
    if (*to).type_0 == 0 as libc::c_int {
        evp_pkey_set_method(to, (*from).ameth);
    } else if (*to).type_0 != (*from).type_0 {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            103 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            166 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if EVP_PKEY_missing_parameters(from) != 0 {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            118 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            171 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if EVP_PKEY_missing_parameters(to) == 0 {
        if EVP_PKEY_cmp_parameters(to, from) == 1 as libc::c_int {
            return 1 as libc::c_int;
        }
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            180 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if !((*from).ameth).is_null() && ((*(*from).ameth).param_copy).is_some() {
        return ((*(*from).ameth).param_copy)
            .expect("non-null function pointer")(to, from);
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_missing_parameters(
    mut pkey: *const EVP_PKEY,
) -> libc::c_int {
    if !((*pkey).ameth).is_null() && ((*(*pkey).ameth).param_missing).is_some() {
        return ((*(*pkey).ameth).param_missing)
            .expect("non-null function pointer")(pkey);
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_size(mut pkey: *const EVP_PKEY) -> libc::c_int {
    if !pkey.is_null() && !((*pkey).ameth).is_null()
        && ((*(*pkey).ameth).pkey_size).is_some()
    {
        return ((*(*pkey).ameth).pkey_size).expect("non-null function pointer")(pkey);
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_bits(mut pkey: *const EVP_PKEY) -> libc::c_int {
    if !pkey.is_null() && !((*pkey).ameth).is_null()
        && ((*(*pkey).ameth).pkey_bits).is_some()
    {
        return ((*(*pkey).ameth).pkey_bits).expect("non-null function pointer")(pkey);
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_id(mut pkey: *const EVP_PKEY) -> libc::c_int {
    return (*pkey).type_0;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_get_pkey_type(mut md: *const EVP_MD) -> libc::c_int {
    if !md.is_null() {
        let mut sig_nid: libc::c_int = 0 as libc::c_int;
        if OBJ_find_sigid_by_algs(&mut sig_nid, (*md).type_0, 6 as libc::c_int) != 0 {
            return sig_nid;
        }
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_pkey_type(mut md: *const EVP_MD) -> libc::c_int {
    return EVP_MD_get_pkey_type(md);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_get0_name(mut md: *const EVP_MD) -> *const libc::c_char {
    if !md.is_null() {
        return OBJ_nid2sn(EVP_MD_nid(md));
    }
    return 0 as *const libc::c_char;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_name(mut md: *const EVP_MD) -> *const libc::c_char {
    return EVP_MD_get0_name(md);
}
unsafe extern "C" fn evp_pkey_asn1_find(
    mut nid: libc::c_int,
) -> *const EVP_PKEY_ASN1_METHOD {
    let mut methods: *const *const EVP_PKEY_ASN1_METHOD = AWSLC_non_fips_pkey_evp_asn1_methods();
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < 11 as libc::c_int as size_t {
        if (**methods.offset(i as isize)).pkey_id == nid {
            return *methods.offset(i as isize);
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as *const EVP_PKEY_ASN1_METHOD;
}
#[no_mangle]
pub unsafe extern "C" fn evp_pkey_set_method(
    mut pkey: *mut EVP_PKEY,
    mut method: *const EVP_PKEY_ASN1_METHOD,
) {
    free_it(pkey);
    (*pkey).ameth = method;
    (*pkey).type_0 = (*(*pkey).ameth).pkey_id;
}
unsafe extern "C" fn pkey_set_type(
    mut pkey: *mut EVP_PKEY,
    mut type_0: libc::c_int,
    mut str: *const libc::c_char,
    mut len: libc::c_int,
) -> libc::c_int {
    if !pkey.is_null() && !((*pkey).pkey.ptr).is_null() {
        free_it(pkey);
    }
    let mut ameth: *const EVP_PKEY_ASN1_METHOD = 0 as *const EVP_PKEY_ASN1_METHOD;
    if !str.is_null() {
        ameth = EVP_PKEY_asn1_find_str(0 as *mut *mut ENGINE, str, len);
    } else {
        ameth = evp_pkey_asn1_find(type_0);
    }
    if ameth.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            128 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            285 as libc::c_int as libc::c_uint,
        );
        ERR_add_error_dataf(
            b"algorithm %d\0" as *const u8 as *const libc::c_char,
            type_0,
        );
        return 0 as libc::c_int;
    }
    if !pkey.is_null() {
        evp_pkey_set_method(pkey, ameth);
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_type(mut nid: libc::c_int) -> libc::c_int {
    return nid;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_new_mac_key(
    mut type_0: libc::c_int,
    mut engine: *mut ENGINE,
    mut mac_key: *const uint8_t,
    mut mac_key_len: size_t,
) -> *mut EVP_PKEY {
    if type_0 != 855 as libc::c_int {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            308 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EVP_PKEY;
    }
    if mac_key.is_null() && mac_key_len > 0 as libc::c_int as size_t {
        return 0 as *mut EVP_PKEY;
    }
    let mut ret: *mut EVP_PKEY = EVP_PKEY_new();
    if ret.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            6 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            319 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EVP_PKEY;
    }
    let mut key: *mut HMAC_KEY = HMAC_KEY_new();
    if !key.is_null() {
        (*key)
            .key = OPENSSL_memdup(mac_key as *const libc::c_void, mac_key_len)
            as *mut uint8_t;
        if ((*key).key).is_null() && mac_key_len > 0 as libc::c_int as size_t {
            OPENSSL_free(key as *mut libc::c_void);
        } else {
            (*key).key_len = mac_key_len;
            if EVP_PKEY_assign(ret, 855 as libc::c_int, key as *mut libc::c_void) == 0 {
                OPENSSL_free(key as *mut libc::c_void);
            } else {
                return ret
            }
        }
    }
    ERR_put_error(
        6 as libc::c_int,
        0 as libc::c_int,
        6 as libc::c_int,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0" as *const u8
            as *const libc::c_char,
        341 as libc::c_int as libc::c_uint,
    );
    EVP_PKEY_free(ret);
    return 0 as *mut EVP_PKEY;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_set1_RSA(
    mut pkey: *mut EVP_PKEY,
    mut key: *mut RSA,
) -> libc::c_int {
    if EVP_PKEY_assign_RSA(pkey, key) != 0 {
        RSA_up_ref(key);
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_assign_RSA(
    mut pkey: *mut EVP_PKEY,
    mut key: *mut RSA,
) -> libc::c_int {
    let mut meth: *const EVP_PKEY_ASN1_METHOD = evp_pkey_asn1_find(6 as libc::c_int);
    if !meth.is_null() {} else {
        __assert_fail(
            b"meth != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            358 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 43],
                &[libc::c_char; 43],
            >(b"int EVP_PKEY_assign_RSA(EVP_PKEY *, RSA *)\0"))
                .as_ptr(),
        );
    }
    'c_10710: {
        if !meth.is_null() {} else {
            __assert_fail(
                b"meth != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                    as *const u8 as *const libc::c_char,
                358 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 43],
                    &[libc::c_char; 43],
                >(b"int EVP_PKEY_assign_RSA(EVP_PKEY *, RSA *)\0"))
                    .as_ptr(),
            );
        }
    };
    evp_pkey_set_method(pkey, meth);
    (*pkey).pkey.ptr = key as *mut libc::c_void;
    return (key != 0 as *mut libc::c_void as *mut RSA) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get0_RSA(mut pkey: *const EVP_PKEY) -> *mut RSA {
    if (*pkey).type_0 != 6 as libc::c_int && (*pkey).type_0 != 912 as libc::c_int {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            107 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            367 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut RSA;
    }
    return (*pkey).pkey.rsa;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get1_RSA(mut pkey: *const EVP_PKEY) -> *mut RSA {
    let mut rsa: *mut RSA = EVP_PKEY_get0_RSA(pkey);
    if !rsa.is_null() {
        RSA_up_ref(rsa);
    }
    return rsa;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_set1_DSA(
    mut pkey: *mut EVP_PKEY,
    mut key: *mut DSA,
) -> libc::c_int {
    if EVP_PKEY_assign_DSA(pkey, key) != 0 {
        DSA_up_ref(key);
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_assign_DSA(
    mut pkey: *mut EVP_PKEY,
    mut key: *mut DSA,
) -> libc::c_int {
    let mut meth: *const EVP_PKEY_ASN1_METHOD = evp_pkey_asn1_find(116 as libc::c_int);
    if !meth.is_null() {} else {
        __assert_fail(
            b"meth != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            394 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 43],
                &[libc::c_char; 43],
            >(b"int EVP_PKEY_assign_DSA(EVP_PKEY *, DSA *)\0"))
                .as_ptr(),
        );
    }
    'c_10905: {
        if !meth.is_null() {} else {
            __assert_fail(
                b"meth != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                    as *const u8 as *const libc::c_char,
                394 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 43],
                    &[libc::c_char; 43],
                >(b"int EVP_PKEY_assign_DSA(EVP_PKEY *, DSA *)\0"))
                    .as_ptr(),
            );
        }
    };
    evp_pkey_set_method(pkey, meth);
    (*pkey).pkey.ptr = key as *mut libc::c_void;
    return (key != 0 as *mut libc::c_void as *mut DSA) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get0_DSA(mut pkey: *const EVP_PKEY) -> *mut DSA {
    if (*pkey).type_0 != 116 as libc::c_int {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            108 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            403 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut DSA;
    }
    return (*pkey).pkey.dsa;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get1_DSA(mut pkey: *const EVP_PKEY) -> *mut DSA {
    let mut dsa: *mut DSA = EVP_PKEY_get0_DSA(pkey);
    if !dsa.is_null() {
        DSA_up_ref(dsa);
    }
    return dsa;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_set1_EC_KEY(
    mut pkey: *mut EVP_PKEY,
    mut key: *mut EC_KEY,
) -> libc::c_int {
    if EVP_PKEY_assign_EC_KEY(pkey, key) != 0 {
        EC_KEY_up_ref(key);
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_assign_EC_KEY(
    mut pkey: *mut EVP_PKEY,
    mut key: *mut EC_KEY,
) -> libc::c_int {
    let mut meth: *const EVP_PKEY_ASN1_METHOD = evp_pkey_asn1_find(408 as libc::c_int);
    if !meth.is_null() {} else {
        __assert_fail(
            b"meth != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            430 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 49],
                &[libc::c_char; 49],
            >(b"int EVP_PKEY_assign_EC_KEY(EVP_PKEY *, EC_KEY *)\0"))
                .as_ptr(),
        );
    }
    'c_11081: {
        if !meth.is_null() {} else {
            __assert_fail(
                b"meth != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                    as *const u8 as *const libc::c_char,
                430 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 49],
                    &[libc::c_char; 49],
                >(b"int EVP_PKEY_assign_EC_KEY(EVP_PKEY *, EC_KEY *)\0"))
                    .as_ptr(),
            );
        }
    };
    evp_pkey_set_method(pkey, meth);
    (*pkey).pkey.ptr = key as *mut libc::c_void;
    return (key != 0 as *mut libc::c_void as *mut EC_KEY) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get0_EC_KEY(mut pkey: *const EVP_PKEY) -> *mut EC_KEY {
    if (*pkey).type_0 != 408 as libc::c_int {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            439 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EC_KEY;
    }
    return (*pkey).pkey.ec;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get1_EC_KEY(mut pkey: *const EVP_PKEY) -> *mut EC_KEY {
    let mut ec_key: *mut EC_KEY = EVP_PKEY_get0_EC_KEY(pkey);
    if !ec_key.is_null() {
        EC_KEY_up_ref(ec_key);
    }
    return ec_key;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_assign(
    mut pkey: *mut EVP_PKEY,
    mut type_0: libc::c_int,
    mut key: *mut libc::c_void,
) -> libc::c_int {
    match type_0 {
        6 => return EVP_PKEY_assign_RSA(pkey, key as *mut RSA),
        116 => return EVP_PKEY_assign_DSA(pkey, key as *mut DSA),
        408 => return EVP_PKEY_assign_EC_KEY(pkey, key as *mut EC_KEY),
        28 => return EVP_PKEY_assign_DH(pkey, key as *mut DH),
        _ => {
            if EVP_PKEY_set_type(pkey, type_0) == 0 {
                return 0 as libc::c_int;
            }
            (*pkey).pkey.ptr = key;
            return (key != 0 as *mut libc::c_void) as libc::c_int;
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_set_type(
    mut pkey: *mut EVP_PKEY,
    mut type_0: libc::c_int,
) -> libc::c_int {
    return pkey_set_type(pkey, type_0, 0 as *const libc::c_char, -(1 as libc::c_int));
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_set_type_str(
    mut pkey: *mut EVP_PKEY,
    mut str: *const libc::c_char,
    mut len: libc::c_int,
) -> libc::c_int {
    return pkey_set_type(pkey, 0 as libc::c_int, str, len);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_new_raw_private_key(
    mut type_0: libc::c_int,
    mut unused: *mut ENGINE,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> *mut EVP_PKEY {
    let mut method: *const EVP_PKEY_ASN1_METHOD = 0 as *const EVP_PKEY_ASN1_METHOD;
    match type_0 {
        948 => {
            method = &x25519_asn1_meth;
        }
        949 => {
            method = &ed25519_asn1_meth;
        }
        997 => {
            method = &ed25519ph_asn1_meth;
        }
        855 => {
            method = &hmac_asn1_meth;
        }
        _ => {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                128 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                    as *const u8 as *const libc::c_char,
                507 as libc::c_int as libc::c_uint,
            );
            return 0 as *mut EVP_PKEY;
        }
    }
    let mut ret: *mut EVP_PKEY = EVP_PKEY_new();
    if !ret.is_null() {
        evp_pkey_set_method(ret, method);
        if !(((*(*ret).ameth).set_priv_raw)
            .expect(
                "non-null function pointer",
            )(ret, in_0, len, 0 as *const uint8_t, 0 as libc::c_int as size_t) == 0)
        {
            return ret;
        }
    }
    EVP_PKEY_free(ret);
    return 0 as *mut EVP_PKEY;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_new_raw_public_key(
    mut type_0: libc::c_int,
    mut unused: *mut ENGINE,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> *mut EVP_PKEY {
    let mut method: *const EVP_PKEY_ASN1_METHOD = 0 as *const EVP_PKEY_ASN1_METHOD;
    match type_0 {
        948 => {
            method = &x25519_asn1_meth;
        }
        949 => {
            method = &ed25519_asn1_meth;
        }
        997 => {
            method = &ed25519ph_asn1_meth;
        }
        _ => {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                128 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                    as *const u8 as *const libc::c_char,
                544 as libc::c_int as libc::c_uint,
            );
            return 0 as *mut EVP_PKEY;
        }
    }
    let mut ret: *mut EVP_PKEY = EVP_PKEY_new();
    if !ret.is_null() {
        evp_pkey_set_method(ret, method);
        if !(((*(*ret).ameth).set_pub_raw)
            .expect("non-null function pointer")(ret, in_0, len) == 0)
        {
            return ret;
        }
    }
    EVP_PKEY_free(ret);
    return 0 as *mut EVP_PKEY;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_raw_private_key(
    mut pkey: *const EVP_PKEY,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
) -> libc::c_int {
    if pkey.is_null() || ((*pkey).ameth).is_null()
        || ((*(*pkey).ameth).get_priv_raw).is_none()
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            571 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ((*(*pkey).ameth).get_priv_raw)
        .expect("non-null function pointer")(pkey, out, out_len);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get_raw_public_key(
    mut pkey: *const EVP_PKEY,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
) -> libc::c_int {
    if pkey.is_null() || ((*pkey).ameth).is_null()
        || ((*(*pkey).ameth).get_pub_raw).is_none()
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            584 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ((*(*pkey).ameth).get_pub_raw)
        .expect("non-null function pointer")(pkey, out, out_len);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_cmp_parameters(
    mut a: *const EVP_PKEY,
    mut b: *const EVP_PKEY,
) -> libc::c_int {
    if (*a).type_0 != (*b).type_0 {
        return -(1 as libc::c_int);
    }
    if !((*a).ameth).is_null() && ((*(*a).ameth).param_cmp).is_some() {
        return ((*(*a).ameth).param_cmp).expect("non-null function pointer")(a, b);
    }
    return -(2 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_signature_md(
    mut ctx: *mut EVP_PKEY_CTX,
    mut md: *const EVP_MD,
) -> libc::c_int {
    return EVP_PKEY_CTX_ctrl(
        ctx,
        -(1 as libc::c_int),
        (1 as libc::c_int) << 3 as libc::c_int | (1 as libc::c_int) << 4 as libc::c_int
            | (1 as libc::c_int) << 5 as libc::c_int,
        1 as libc::c_int,
        0 as libc::c_int,
        md as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_signature_md(
    mut ctx: *mut EVP_PKEY_CTX,
    mut out_md: *mut *const EVP_MD,
) -> libc::c_int {
    return EVP_PKEY_CTX_ctrl(
        ctx,
        -(1 as libc::c_int),
        (1 as libc::c_int) << 3 as libc::c_int | (1 as libc::c_int) << 4 as libc::c_int
            | (1 as libc::c_int) << 5 as libc::c_int,
        2 as libc::c_int,
        0 as libc::c_int,
        out_md as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_signature_context(
    mut ctx: *mut EVP_PKEY_CTX,
    mut context: *const uint8_t,
    mut context_len: size_t,
) -> libc::c_int {
    let mut params: EVP_PKEY_CTX_SIGNATURE_CONTEXT_PARAMS = {
        let mut init = evp_pkey_ctx_signature_context_params_st {
            context: context,
            context_len: context_len,
        };
        init
    };
    return EVP_PKEY_CTX_ctrl(
        ctx,
        -(1 as libc::c_int),
        (1 as libc::c_int) << 3 as libc::c_int | (1 as libc::c_int) << 4 as libc::c_int
            | (1 as libc::c_int) << 5 as libc::c_int,
        3 as libc::c_int,
        0 as libc::c_int,
        &mut params as *mut EVP_PKEY_CTX_SIGNATURE_CONTEXT_PARAMS as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get0_signature_context(
    mut ctx: *mut EVP_PKEY_CTX,
    mut context: *mut *const uint8_t,
    mut context_len: *mut size_t,
) -> libc::c_int {
    if context.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            627 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if context_len.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            628 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut params: EVP_PKEY_CTX_SIGNATURE_CONTEXT_PARAMS = {
        let mut init = evp_pkey_ctx_signature_context_params_st {
            context: 0 as *const uint8_t,
            context_len: 0 as libc::c_int as size_t,
        };
        init
    };
    if EVP_PKEY_CTX_ctrl(
        ctx,
        -(1 as libc::c_int),
        (1 as libc::c_int) << 3 as libc::c_int | (1 as libc::c_int) << 4 as libc::c_int
            | (1 as libc::c_int) << 5 as libc::c_int,
        4 as libc::c_int,
        0 as libc::c_int,
        &mut params as *mut EVP_PKEY_CTX_SIGNATURE_CONTEXT_PARAMS as *mut libc::c_void,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    *context = params.context;
    *context_len = params.context_len;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get0(mut pkey: *const EVP_PKEY) -> *mut libc::c_void {
    if pkey.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            642 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut libc::c_void;
    }
    match (*pkey).type_0 {
        6 | 912 | 116 | 408 | 28 => return (*pkey).pkey.ptr,
        _ => return 0 as *mut libc::c_void,
    };
}
#[no_mangle]
pub unsafe extern "C" fn OpenSSL_add_all_algorithms() {}
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_add_all_algorithms_conf() {}
#[no_mangle]
pub unsafe extern "C" fn OpenSSL_add_all_ciphers() {}
#[no_mangle]
pub unsafe extern "C" fn OpenSSL_add_all_digests() {}
#[no_mangle]
pub unsafe extern "C" fn EVP_cleanup() {}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_base_id(mut pkey: *const EVP_PKEY) -> libc::c_int {
    return EVP_PKEY_id(pkey);
}
unsafe extern "C" fn evp_pkey_tls_encodedpoint_ec_curve_supported(
    mut ec_key: *const EC_KEY,
) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut curve_nid: libc::c_int = 0 as libc::c_int;
    let mut ec_key_group: *const EC_GROUP = 0 as *const EC_GROUP;
    if ec_key.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            680 as libc::c_int as libc::c_uint,
        );
    } else {
        ec_key_group = EC_KEY_get0_group(ec_key);
        if ec_key_group.is_null() {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                118 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                    as *const u8 as *const libc::c_char,
                686 as libc::c_int as libc::c_uint,
            );
        } else {
            curve_nid = EC_GROUP_get_curve_name(ec_key_group);
            if 713 as libc::c_int != curve_nid && 415 as libc::c_int != curve_nid
                && 715 as libc::c_int != curve_nid && 716 as libc::c_int != curve_nid
            {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    129 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                        as *const u8 as *const libc::c_char,
                    695 as libc::c_int as libc::c_uint,
                );
            } else {
                ret = 1 as libc::c_int;
            }
        }
    }
    return ret;
}
unsafe extern "C" fn evp_pkey_set1_tls_encodedpoint_ec_key(
    mut pkey: *mut EVP_PKEY,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut ec_key: *mut EC_KEY = 0 as *mut EC_KEY;
    let mut ec_key_group: *const EC_GROUP = 0 as *const EC_GROUP;
    let mut ec_point: *mut EC_POINT = 0 as *mut EC_POINT;
    if pkey.is_null() || in_0.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            714 as libc::c_int as libc::c_uint,
        );
    } else if 1 as libc::c_int as size_t > len {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            133 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            719 as libc::c_int as libc::c_uint,
        );
    } else if 408 as libc::c_int != (*pkey).type_0 {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            129 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            724 as libc::c_int as libc::c_uint,
        );
    } else if POINT_CONVERSION_UNCOMPRESSED as libc::c_int
        != *in_0.offset(0 as libc::c_int as isize) as libc::c_int
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            6 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            737 as libc::c_int as libc::c_uint,
        );
    } else {
        ec_key = EVP_PKEY_get0_EC_KEY(pkey);
        if ec_key.is_null() {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                120 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                    as *const u8 as *const libc::c_char,
                743 as libc::c_int as libc::c_uint,
            );
        } else if 0 as libc::c_int
            == evp_pkey_tls_encodedpoint_ec_curve_supported(ec_key)
        {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                6 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                    as *const u8 as *const libc::c_char,
                748 as libc::c_int as libc::c_uint,
            );
        } else {
            ec_key_group = EC_KEY_get0_group(ec_key);
            if ec_key_group.is_null() {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    118 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                        as *const u8 as *const libc::c_char,
                    754 as libc::c_int as libc::c_uint,
                );
            } else {
                ec_point = EC_POINT_new(ec_key_group);
                if ec_point.is_null() {
                    ERR_put_error(
                        6 as libc::c_int,
                        0 as libc::c_int,
                        6 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                            as *const u8 as *const libc::c_char,
                        760 as libc::c_int as libc::c_uint,
                    );
                } else if 0 as libc::c_int
                    == EC_POINT_oct2point(
                        ec_key_group,
                        ec_point,
                        in_0,
                        len,
                        0 as *mut BN_CTX,
                    )
                {
                    ERR_put_error(
                        6 as libc::c_int,
                        0 as libc::c_int,
                        6 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                            as *const u8 as *const libc::c_char,
                        765 as libc::c_int as libc::c_uint,
                    );
                } else if 0 as libc::c_int
                    == EC_KEY_set_public_key(ec_key, ec_point as *const EC_POINT)
                {
                    ERR_put_error(
                        6 as libc::c_int,
                        0 as libc::c_int,
                        6 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                            as *const u8 as *const libc::c_char,
                        770 as libc::c_int as libc::c_uint,
                    );
                } else {
                    ret = 1 as libc::c_int;
                }
            }
        }
    }
    EC_POINT_free(ec_point);
    return ret;
}
unsafe extern "C" fn evp_pkey_set1_tls_encodedpoint_x25519(
    mut pkey: *mut EVP_PKEY,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    if pkey.is_null() || in_0.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            787 as libc::c_int as libc::c_uint,
        );
    } else if 948 as libc::c_int != (*pkey).type_0 {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            129 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            792 as libc::c_int as libc::c_uint,
        );
    } else if 1 as libc::c_int as size_t > len {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            133 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            797 as libc::c_int as libc::c_uint,
        );
    } else if ((*pkey).ameth).is_null() || ((*(*pkey).ameth).set_pub_raw).is_none() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            802 as libc::c_int as libc::c_uint,
        );
    } else if 0 as libc::c_int
        == ((*(*pkey).ameth).set_pub_raw)
            .expect("non-null function pointer")(pkey, in_0, len)
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            6 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            807 as libc::c_int as libc::c_uint,
        );
    } else {
        ret = 1 as libc::c_int;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_set1_tls_encodedpoint(
    mut pkey: *mut EVP_PKEY,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    if pkey.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            821 as libc::c_int as libc::c_uint,
        );
    } else {
        match (*pkey).type_0 {
            948 => return evp_pkey_set1_tls_encodedpoint_x25519(pkey, in_0, len),
            408 => return evp_pkey_set1_tls_encodedpoint_ec_key(pkey, in_0, len),
            _ => {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    129 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                        as *const u8 as *const libc::c_char,
                    831 as libc::c_int as libc::c_uint,
                );
            }
        }
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn evp_pkey_get1_tls_encodedpoint_ec_key(
    mut pkey: *const EVP_PKEY,
    mut out_ptr: *mut *mut uint8_t,
) -> size_t {
    let mut ret: size_t = 0 as libc::c_int as size_t;
    let mut ec_key: *const EC_KEY = 0 as *const EC_KEY;
    if pkey.is_null() || out_ptr.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            846 as libc::c_int as libc::c_uint,
        );
    } else if 408 as libc::c_int != (*pkey).type_0 {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            129 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            851 as libc::c_int as libc::c_uint,
        );
    } else {
        ec_key = EVP_PKEY_get0_EC_KEY(pkey);
        if ec_key.is_null() {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                120 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                    as *const u8 as *const libc::c_char,
                857 as libc::c_int as libc::c_uint,
            );
        } else if 0 as libc::c_int
            == evp_pkey_tls_encodedpoint_ec_curve_supported(ec_key)
        {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                6 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                    as *const u8 as *const libc::c_char,
                862 as libc::c_int as libc::c_uint,
            );
        } else if POINT_CONVERSION_UNCOMPRESSED as libc::c_int as libc::c_uint
            != EC_KEY_get_conv_form(ec_key) as libc::c_uint
        {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                6 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                    as *const u8 as *const libc::c_char,
                870 as libc::c_int as libc::c_uint,
            );
        } else {
            ret = EC_KEY_key2buf(
                ec_key,
                POINT_CONVERSION_UNCOMPRESSED,
                out_ptr,
                0 as *mut BN_CTX,
            );
            if 0 as libc::c_int as size_t == ret {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    6 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                        as *const u8 as *const libc::c_char,
                    877 as libc::c_int as libc::c_uint,
                );
            }
        }
    }
    return ret;
}
unsafe extern "C" fn evp_pkey_get1_tls_encodedpoint_x25519(
    mut pkey: *const EVP_PKEY,
    mut out_ptr: *mut *mut uint8_t,
) -> size_t {
    let mut ret: size_t = 0 as libc::c_int as size_t;
    let mut out_len: size_t = 0 as libc::c_int as size_t;
    if pkey.is_null() || out_ptr.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            892 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int as size_t;
    }
    if 948 as libc::c_int != (*pkey).type_0 {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            129 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            897 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int as size_t;
    }
    if ((*pkey).ameth).is_null() || ((*(*pkey).ameth).get_pub_raw).is_none() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            902 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int as size_t;
    }
    out_len = 32 as libc::c_int as size_t;
    *out_ptr = OPENSSL_malloc(32 as libc::c_int as size_t) as *mut uint8_t;
    if (*out_ptr).is_null() {
        return 0 as libc::c_int as size_t;
    }
    if 0 as libc::c_int
        == ((*(*pkey).ameth).get_pub_raw)
            .expect("non-null function pointer")(pkey, *out_ptr, &mut out_len)
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            6 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            913 as libc::c_int as libc::c_uint,
        );
    } else if 32 as libc::c_int as size_t != out_len {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            6 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            918 as libc::c_int as libc::c_uint,
        );
    } else {
        ret = 32 as libc::c_int as size_t;
    }
    if 0 as libc::c_int as size_t == ret {
        OPENSSL_free(*out_ptr as *mut libc::c_void);
        *out_ptr = 0 as *mut uint8_t;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get1_tls_encodedpoint(
    mut pkey: *const EVP_PKEY,
    mut out_ptr: *mut *mut uint8_t,
) -> size_t {
    if pkey.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                as *const u8 as *const libc::c_char,
            935 as libc::c_int as libc::c_uint,
        );
    } else {
        match (*pkey).type_0 {
            948 => return evp_pkey_get1_tls_encodedpoint_x25519(pkey, out_ptr),
            408 => return evp_pkey_get1_tls_encodedpoint_ec_key(pkey, out_ptr),
            _ => {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    129 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp.c\0"
                        as *const u8 as *const libc::c_char,
                    945 as libc::c_int as libc::c_uint,
                );
            }
        }
    }
    return 0 as libc::c_int as size_t;
}
