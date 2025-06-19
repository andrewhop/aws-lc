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
    pub type dh_st;
    pub type dsa_st;
    pub type ec_key_st;
    pub type engine_st;
    pub type evp_md_pctx_ops;
    pub type pqdsa_key_st;
    pub type kem_key_st;
    pub type rsa_st;
    pub type env_md_st;
    fn EVP_MD_CTX_init(ctx: *mut EVP_MD_CTX);
    fn EVP_MD_CTX_cleanup(ctx: *mut EVP_MD_CTX) -> libc::c_int;
    fn EVP_MD_CTX_copy_ex(out: *mut EVP_MD_CTX, in_0: *const EVP_MD_CTX) -> libc::c_int;
    fn EVP_DigestInit_ex(
        ctx: *mut EVP_MD_CTX,
        type_0: *const EVP_MD,
        engine: *mut ENGINE,
    ) -> libc::c_int;
    fn EVP_DigestInit(ctx: *mut EVP_MD_CTX, type_0: *const EVP_MD) -> libc::c_int;
    fn EVP_DigestUpdate(
        ctx: *mut EVP_MD_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn EVP_DigestFinal_ex(
        ctx: *mut EVP_MD_CTX,
        md_out: *mut uint8_t,
        out_size: *mut libc::c_uint,
    ) -> libc::c_int;
    fn EVP_PKEY_size(pkey: *const EVP_PKEY) -> libc::c_int;
    fn EVP_PKEY_CTX_new(pkey: *mut EVP_PKEY, e: *mut ENGINE) -> *mut EVP_PKEY_CTX;
    fn EVP_PKEY_CTX_free(ctx: *mut EVP_PKEY_CTX);
    fn EVP_PKEY_sign_init(ctx: *mut EVP_PKEY_CTX) -> libc::c_int;
    fn EVP_PKEY_sign(
        ctx: *mut EVP_PKEY_CTX,
        sig: *mut uint8_t,
        sig_len: *mut size_t,
        digest: *const uint8_t,
        digest_len: size_t,
    ) -> libc::c_int;
    fn EVP_PKEY_verify_init(ctx: *mut EVP_PKEY_CTX) -> libc::c_int;
    fn EVP_PKEY_verify(
        ctx: *mut EVP_PKEY_CTX,
        sig: *const uint8_t,
        sig_len: size_t,
        digest: *const uint8_t,
        digest_len: size_t,
    ) -> libc::c_int;
    fn EVP_PKEY_CTX_set_signature_md(
        ctx: *mut EVP_PKEY_CTX,
        md: *const EVP_MD,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
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
#[no_mangle]
pub unsafe extern "C" fn EVP_SignInit_ex(
    mut ctx: *mut EVP_MD_CTX,
    mut type_0: *const EVP_MD,
    mut impl_0: *mut ENGINE,
) -> libc::c_int {
    return EVP_DigestInit_ex(ctx, type_0, impl_0);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_SignInit(
    mut ctx: *mut EVP_MD_CTX,
    mut type_0: *const EVP_MD,
) -> libc::c_int {
    return EVP_DigestInit(ctx, type_0);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_SignUpdate(
    mut ctx: *mut EVP_MD_CTX,
    mut data: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    return EVP_DigestUpdate(ctx, data, len);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_SignFinal(
    mut ctx: *const EVP_MD_CTX,
    mut sig: *mut uint8_t,
    mut out_sig_len: *mut libc::c_uint,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    let mut m: [uint8_t; 64] = [0; 64];
    let mut m_len: libc::c_uint = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut tmp_ctx: EVP_MD_CTX = env_md_ctx_st {
        digest: 0 as *const EVP_MD,
        md_data: 0 as *mut libc::c_void,
        update: None,
        pctx: 0 as *mut EVP_PKEY_CTX,
        pctx_ops: 0 as *const evp_md_pctx_ops,
        flags: 0,
    };
    let mut pkctx: *mut EVP_PKEY_CTX = 0 as *mut EVP_PKEY_CTX;
    let mut sig_len: size_t = EVP_PKEY_size(pkey) as size_t;
    if sig_len
        > (2147483647 as libc::c_int as libc::c_uint)
            .wrapping_mul(2 as libc::c_uint)
            .wrapping_add(1 as libc::c_uint) as size_t
    {
        sig_len = (2147483647 as libc::c_int as libc::c_uint)
            .wrapping_mul(2 as libc::c_uint)
            .wrapping_add(1 as libc::c_uint) as size_t;
    }
    *out_sig_len = 0 as libc::c_int as libc::c_uint;
    EVP_MD_CTX_init(&mut tmp_ctx);
    if !(EVP_MD_CTX_copy_ex(&mut tmp_ctx, ctx) == 0
        || EVP_DigestFinal_ex(&mut tmp_ctx, m.as_mut_ptr(), &mut m_len) == 0)
    {
        EVP_MD_CTX_cleanup(&mut tmp_ctx);
        pkctx = EVP_PKEY_CTX_new(pkey, 0 as *mut ENGINE);
        if !(pkctx.is_null() || EVP_PKEY_sign_init(pkctx) == 0
            || EVP_PKEY_CTX_set_signature_md(pkctx, (*ctx).digest) == 0
            || EVP_PKEY_sign(pkctx, sig, &mut sig_len, m.as_mut_ptr(), m_len as size_t)
                == 0)
        {
            *out_sig_len = sig_len as libc::c_uint;
            ret = 1 as libc::c_int;
        }
    }
    EVP_PKEY_CTX_free(pkctx);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_VerifyInit_ex(
    mut ctx: *mut EVP_MD_CTX,
    mut type_0: *const EVP_MD,
    mut impl_0: *mut ENGINE,
) -> libc::c_int {
    return EVP_DigestInit_ex(ctx, type_0, impl_0);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_VerifyInit(
    mut ctx: *mut EVP_MD_CTX,
    mut type_0: *const EVP_MD,
) -> libc::c_int {
    return EVP_DigestInit(ctx, type_0);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_VerifyUpdate(
    mut ctx: *mut EVP_MD_CTX,
    mut data: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    return EVP_DigestUpdate(ctx, data, len);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_VerifyFinal(
    mut ctx: *mut EVP_MD_CTX,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    let mut m: [uint8_t; 64] = [0; 64];
    let mut m_len: libc::c_uint = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut tmp_ctx: EVP_MD_CTX = env_md_ctx_st {
        digest: 0 as *const EVP_MD,
        md_data: 0 as *mut libc::c_void,
        update: None,
        pctx: 0 as *mut EVP_PKEY_CTX,
        pctx_ops: 0 as *const evp_md_pctx_ops,
        flags: 0,
    };
    let mut pkctx: *mut EVP_PKEY_CTX = 0 as *mut EVP_PKEY_CTX;
    EVP_MD_CTX_init(&mut tmp_ctx);
    if EVP_MD_CTX_copy_ex(&mut tmp_ctx, ctx) == 0
        || EVP_DigestFinal_ex(&mut tmp_ctx, m.as_mut_ptr(), &mut m_len) == 0
    {
        EVP_MD_CTX_cleanup(&mut tmp_ctx);
    } else {
        EVP_MD_CTX_cleanup(&mut tmp_ctx);
        pkctx = EVP_PKEY_CTX_new(pkey, 0 as *mut ENGINE);
        if !(pkctx.is_null() || EVP_PKEY_verify_init(pkctx) == 0
            || EVP_PKEY_CTX_set_signature_md(pkctx, (*ctx).digest) == 0)
        {
            ret = EVP_PKEY_verify(pkctx, sig, sig_len, m.as_mut_ptr(), m_len as size_t);
        }
    }
    EVP_PKEY_CTX_free(pkctx);
    return ret;
}
