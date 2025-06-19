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
    pub type kem_key_st;
    pub type rsa_st;
    pub type hmac_methods_st;
    fn EVP_MD_CTX_init(ctx: *mut EVP_MD_CTX);
    fn EVP_MD_CTX_cleanup(ctx: *mut EVP_MD_CTX) -> libc::c_int;
    fn EVP_MD_CTX_copy_ex(out: *mut EVP_MD_CTX, in_0: *const EVP_MD_CTX) -> libc::c_int;
    fn EVP_DigestInit_ex(
        ctx: *mut EVP_MD_CTX,
        type_0: *const EVP_MD,
        engine: *mut ENGINE,
    ) -> libc::c_int;
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
    fn EVP_MD_size(md: *const EVP_MD) -> size_t;
    fn EVP_MD_CTX_size(ctx: *const EVP_MD_CTX) -> size_t;
    fn used_for_hmac(ctx: *mut EVP_MD_CTX) -> libc::c_int;
    fn EVP_PKEY_CTX_new(pkey: *mut EVP_PKEY, e: *mut ENGINE) -> *mut EVP_PKEY_CTX;
    fn EVP_PKEY_CTX_free(ctx: *mut EVP_PKEY_CTX);
    fn EVP_PKEY_CTX_dup(ctx: *mut EVP_PKEY_CTX) -> *mut EVP_PKEY_CTX;
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
    fn HMAC_Update(
        ctx: *mut HMAC_CTX,
        data: *const uint8_t,
        data_len: size_t,
    ) -> libc::c_int;
    fn HMAC_Final(
        ctx: *mut HMAC_CTX,
        out: *mut uint8_t,
        out_len: *mut libc::c_uint,
    ) -> libc::c_int;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn CRYPTO_once(
        once: *mut CRYPTO_once_t,
        init: Option::<unsafe extern "C" fn() -> ()>,
    );
}
pub type size_t = libc::c_ulong;
pub type __int8_t = libc::c_schar;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type int8_t = __int8_t;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type pthread_once_t = libc::c_int;
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
pub struct hmac_ctx_st {
    pub md: *const EVP_MD,
    pub methods: *const HmacMethods,
    pub md_ctx: md_ctx_union,
    pub i_ctx: md_ctx_union,
    pub o_ctx: md_ctx_union,
    pub state: int8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union md_ctx_union {
    pub md5: MD5_CTX,
    pub sha1: SHA_CTX,
    pub sha256: SHA256_CTX,
    pub sha512: SHA512_CTX,
}
pub type SHA512_CTX = sha512_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sha512_state_st {
    pub h: [uint64_t; 8],
    pub Nl: uint64_t,
    pub Nh: uint64_t,
    pub p: [uint8_t; 128],
    pub num: libc::c_uint,
    pub md_len: libc::c_uint,
}
pub type SHA256_CTX = sha256_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sha256_state_st {
    pub h: [uint32_t; 8],
    pub Nl: uint32_t,
    pub Nh: uint32_t,
    pub data: [uint8_t; 64],
    pub num: libc::c_uint,
    pub md_len: libc::c_uint,
}
pub type SHA_CTX = sha_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sha_state_st {
    pub h: [uint32_t; 5],
    pub Nl: uint32_t,
    pub Nh: uint32_t,
    pub data: [uint8_t; 64],
    pub num: libc::c_uint,
}
pub type MD5_CTX = md5_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct md5_state_st {
    pub h: [uint32_t; 4],
    pub Nl: uint32_t,
    pub Nh: uint32_t,
    pub data: [uint8_t; 64],
    pub num: libc::c_uint,
}
pub type HmacMethods = hmac_methods_st;
pub type HMAC_CTX = hmac_ctx_st;
pub type CRYPTO_once_t = pthread_once_t;
pub type evp_sign_verify_t = libc::c_uint;
pub const evp_verify: evp_sign_verify_t = 1;
pub const evp_sign: evp_sign_verify_t = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct HMAC_PKEY_CTX {
    pub md: *const EVP_MD,
    pub ctx: HMAC_CTX,
    pub ktmp: HMAC_KEY,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct HMAC_KEY {
    pub key: *mut uint8_t,
    pub key_len: size_t,
}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_lock_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_unlock_state() {}
#[inline]
unsafe extern "C" fn EVP_DigestSign_verify_service_indicator(
    mut ctx: *const EVP_MD_CTX,
) {}
#[inline]
unsafe extern "C" fn EVP_DigestVerify_verify_service_indicator(
    mut ctx: *const EVP_MD_CTX,
) {}
unsafe extern "C" fn EVP_MD_pctx_ops() -> *const evp_md_pctx_ops {
    CRYPTO_once(
        EVP_MD_pctx_ops_once_bss_get(),
        Some(EVP_MD_pctx_ops_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_MD_pctx_ops_storage_bss_get() as *const evp_md_pctx_ops;
}
unsafe extern "C" fn EVP_MD_pctx_ops_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_MD_pctx_ops_once;
}
static mut EVP_MD_pctx_ops_storage: evp_md_pctx_ops = evp_md_pctx_ops {
    free: None,
    dup: None,
};
unsafe extern "C" fn EVP_MD_pctx_ops_storage_bss_get() -> *mut evp_md_pctx_ops {
    return &mut EVP_MD_pctx_ops_storage;
}
unsafe extern "C" fn EVP_MD_pctx_ops_init() {
    EVP_MD_pctx_ops_do_init(EVP_MD_pctx_ops_storage_bss_get());
}
unsafe extern "C" fn EVP_MD_pctx_ops_do_init(mut out: *mut evp_md_pctx_ops) {
    (*out)
        .free = Some(EVP_PKEY_CTX_free as unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> ());
    (*out)
        .dup = Some(
        EVP_PKEY_CTX_dup as unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> *mut EVP_PKEY_CTX,
    );
}
static mut EVP_MD_pctx_ops_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn uses_prehash(
    mut ctx: *mut EVP_MD_CTX,
    mut op: evp_sign_verify_t,
) -> libc::c_int {
    if (*(*(*ctx).pctx).pkey).type_0 == 993 as libc::c_int
        && !((*(*(*ctx).pctx).pkey).pkey.pqdsa_key).is_null()
    {
        let mut nid: libc::c_int = (*(*(*(*(*ctx).pctx).pkey).pkey.pqdsa_key).pqdsa).nid;
        if nid == 994 as libc::c_int || nid == 995 as libc::c_int
            || nid == 996 as libc::c_int
        {
            return 0 as libc::c_int;
        }
    }
    return if op as libc::c_uint == evp_sign as libc::c_int as libc::c_uint {
        ((*(*(*ctx).pctx).pmeth).sign).is_some() as libc::c_int
    } else {
        ((*(*(*ctx).pctx).pmeth).verify).is_some() as libc::c_int
    };
}
unsafe extern "C" fn hmac_update(
    mut ctx: *mut EVP_MD_CTX,
    mut data: *const libc::c_void,
    mut count: size_t,
) -> libc::c_int {
    let mut hctx: *mut HMAC_PKEY_CTX = (*(*ctx).pctx).data as *mut HMAC_PKEY_CTX;
    return HMAC_Update(&mut (*hctx).ctx, data as *const uint8_t, count);
}
unsafe extern "C" fn HMAC_DigestFinal_ex(
    mut ctx: *mut EVP_MD_CTX,
    mut out_sig: *mut uint8_t,
    mut out_sig_len: *mut size_t,
) -> libc::c_int {
    let mut mdlen: libc::c_uint = 0;
    if *out_sig_len < EVP_MD_CTX_size(ctx) {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/digestsign.c\0"
                as *const u8 as *const libc::c_char,
            109 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut hctx: *mut HMAC_PKEY_CTX = (*(*ctx).pctx).data as *mut HMAC_PKEY_CTX;
    if HMAC_Final(&mut (*hctx).ctx, out_sig, &mut mdlen) == 0 {
        return 0 as libc::c_int;
    }
    *out_sig_len = mdlen as size_t;
    return 1 as libc::c_int;
}
unsafe extern "C" fn do_sigver_init(
    mut ctx: *mut EVP_MD_CTX,
    mut pctx: *mut *mut EVP_PKEY_CTX,
    mut type_0: *const EVP_MD,
    mut e: *mut ENGINE,
    mut pkey: *mut EVP_PKEY,
    mut op: evp_sign_verify_t,
) -> libc::c_int {
    if ((*ctx).pctx).is_null() {
        (*ctx).pctx = EVP_PKEY_CTX_new(pkey, e);
    }
    if ((*ctx).pctx).is_null() {
        return 0 as libc::c_int;
    }
    (*ctx).pctx_ops = EVP_MD_pctx_ops();
    if op as libc::c_uint == evp_verify as libc::c_int as libc::c_uint {
        if EVP_PKEY_verify_init((*ctx).pctx) == 0 {
            return 0 as libc::c_int;
        }
    } else if (*pkey).type_0 == 855 as libc::c_int {
        (*(*ctx).pctx).operation = (1 as libc::c_int) << 3 as libc::c_int;
        (*ctx).flags |= 0x800 as libc::c_int as libc::c_ulong;
        (*ctx)
            .update = Some(
            hmac_update
                as unsafe extern "C" fn(
                    *mut EVP_MD_CTX,
                    *const libc::c_void,
                    size_t,
                ) -> libc::c_int,
        );
    } else if EVP_PKEY_sign_init((*ctx).pctx) == 0 {
        return 0 as libc::c_int
    }
    if !type_0.is_null() && EVP_PKEY_CTX_set_signature_md((*ctx).pctx, type_0) == 0 {
        return 0 as libc::c_int;
    }
    if uses_prehash(ctx, op) != 0 || used_for_hmac(ctx) != 0 {
        if type_0.is_null() {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                119 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/digestsign.c\0"
                    as *const u8 as *const libc::c_char,
                159 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        if EVP_DigestInit_ex(ctx, type_0, e) == 0 {
            return 0 as libc::c_int;
        }
    }
    if !pctx.is_null() {
        *pctx = (*ctx).pctx;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_DigestSignInit(
    mut ctx: *mut EVP_MD_CTX,
    mut pctx: *mut *mut EVP_PKEY_CTX,
    mut type_0: *const EVP_MD,
    mut e: *mut ENGINE,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    return do_sigver_init(ctx, pctx, type_0, e, pkey, evp_sign);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_DigestVerifyInit(
    mut ctx: *mut EVP_MD_CTX,
    mut pctx: *mut *mut EVP_PKEY_CTX,
    mut type_0: *const EVP_MD,
    mut e: *mut ENGINE,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    return do_sigver_init(ctx, pctx, type_0, e, pkey, evp_verify);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_DigestSignUpdate(
    mut ctx: *mut EVP_MD_CTX,
    mut data: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    if uses_prehash(ctx, evp_sign) == 0 && used_for_hmac(ctx) == 0 {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/digestsign.c\0"
                as *const u8 as *const libc::c_char,
            188 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return EVP_DigestUpdate(ctx, data, len);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_DigestVerifyUpdate(
    mut ctx: *mut EVP_MD_CTX,
    mut data: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    if uses_prehash(ctx, evp_verify) == 0 || used_for_hmac(ctx) != 0 {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/digestsign.c\0"
                as *const u8 as *const libc::c_char,
            198 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return EVP_DigestUpdate(ctx, data, len);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_DigestSignFinal(
    mut ctx: *mut EVP_MD_CTX,
    mut out_sig: *mut uint8_t,
    mut out_sig_len: *mut size_t,
) -> libc::c_int {
    if uses_prehash(ctx, evp_sign) == 0 && used_for_hmac(ctx) == 0 {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/digestsign.c\0"
                as *const u8 as *const libc::c_char,
            209 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if !out_sig.is_null() {
        let mut tmp_ctx: EVP_MD_CTX = env_md_ctx_st {
            digest: 0 as *const EVP_MD,
            md_data: 0 as *mut libc::c_void,
            update: None,
            pctx: 0 as *mut EVP_PKEY_CTX,
            pctx_ops: 0 as *const evp_md_pctx_ops,
            flags: 0,
        };
        let mut ret: libc::c_int = 0 as libc::c_int;
        let mut md: [uint8_t; 64] = [0; 64];
        let mut mdlen: libc::c_uint = 0;
        FIPS_service_indicator_lock_state();
        EVP_MD_CTX_init(&mut tmp_ctx);
        if EVP_MD_CTX_copy_ex(&mut tmp_ctx, ctx) != 0 {
            if used_for_hmac(ctx) != 0 {
                ret = HMAC_DigestFinal_ex(&mut tmp_ctx, out_sig, out_sig_len);
            } else {
                ret = (EVP_DigestFinal_ex(&mut tmp_ctx, md.as_mut_ptr(), &mut mdlen) != 0
                    && EVP_PKEY_sign(
                        (*ctx).pctx,
                        out_sig,
                        out_sig_len,
                        md.as_mut_ptr(),
                        mdlen as size_t,
                    ) != 0) as libc::c_int;
            }
        }
        EVP_MD_CTX_cleanup(&mut tmp_ctx);
        FIPS_service_indicator_unlock_state();
        if ret > 0 as libc::c_int {
            EVP_DigestSign_verify_service_indicator(ctx);
        }
        return ret;
    } else if used_for_hmac(ctx) != 0 {
        *out_sig_len = EVP_MD_CTX_size(ctx);
        return 1 as libc::c_int;
    } else {
        let mut s: size_t = EVP_MD_size((*ctx).digest);
        return EVP_PKEY_sign((*ctx).pctx, out_sig, out_sig_len, 0 as *const uint8_t, s);
    };
}
#[no_mangle]
pub unsafe extern "C" fn EVP_DigestVerifyFinal(
    mut ctx: *mut EVP_MD_CTX,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
) -> libc::c_int {
    if uses_prehash(ctx, evp_verify) == 0 || used_for_hmac(ctx) != 0 {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/digestsign.c\0"
                as *const u8 as *const libc::c_char,
            255 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    FIPS_service_indicator_lock_state();
    let mut tmp_ctx: EVP_MD_CTX = env_md_ctx_st {
        digest: 0 as *const EVP_MD,
        md_data: 0 as *mut libc::c_void,
        update: None,
        pctx: 0 as *mut EVP_PKEY_CTX,
        pctx_ops: 0 as *const evp_md_pctx_ops,
        flags: 0,
    };
    let mut ret: libc::c_int = 0;
    let mut md: [uint8_t; 64] = [0; 64];
    let mut mdlen: libc::c_uint = 0;
    EVP_MD_CTX_init(&mut tmp_ctx);
    ret = (EVP_MD_CTX_copy_ex(&mut tmp_ctx, ctx) != 0
        && EVP_DigestFinal_ex(&mut tmp_ctx, md.as_mut_ptr(), &mut mdlen) != 0
        && EVP_PKEY_verify((*ctx).pctx, sig, sig_len, md.as_mut_ptr(), mdlen as size_t)
            != 0) as libc::c_int;
    EVP_MD_CTX_cleanup(&mut tmp_ctx);
    FIPS_service_indicator_unlock_state();
    if ret > 0 as libc::c_int {
        EVP_DigestVerify_verify_service_indicator(ctx);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_DigestSign(
    mut ctx: *mut EVP_MD_CTX,
    mut out_sig: *mut uint8_t,
    mut out_sig_len: *mut size_t,
    mut data: *const uint8_t,
    mut data_len: size_t,
) -> libc::c_int {
    if ((*ctx).pctx).is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/digestsign.c\0"
                as *const u8 as *const libc::c_char,
            282 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    FIPS_service_indicator_lock_state();
    let mut ret: libc::c_int = 0 as libc::c_int;
    if uses_prehash(ctx, evp_sign) != 0 || used_for_hmac(ctx) != 0 {
        if !(!out_sig.is_null()
            && EVP_DigestSignUpdate(ctx, data as *const libc::c_void, data_len) == 0)
        {
            ret = EVP_DigestSignFinal(ctx, out_sig, out_sig_len);
        }
    } else if ((*(*(*ctx).pctx).pmeth).sign_message).is_none() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/digestsign.c\0"
                as *const u8 as *const libc::c_char,
            301 as libc::c_int as libc::c_uint,
        );
    } else {
        ret = ((*(*(*ctx).pctx).pmeth).sign_message)
            .expect(
                "non-null function pointer",
            )((*ctx).pctx, out_sig, out_sig_len, data, data_len);
    }
    FIPS_service_indicator_unlock_state();
    if ret > 0 as libc::c_int && !out_sig.is_null() {
        EVP_DigestSign_verify_service_indicator(ctx);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_DigestVerify(
    mut ctx: *mut EVP_MD_CTX,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
    mut data: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    if ((*ctx).pctx).is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/digestsign.c\0"
                as *const u8 as *const libc::c_char,
            321 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    FIPS_service_indicator_lock_state();
    let mut ret: libc::c_int = 0 as libc::c_int;
    if uses_prehash(ctx, evp_verify) != 0 && used_for_hmac(ctx) == 0 {
        ret = (EVP_DigestVerifyUpdate(ctx, data as *const libc::c_void, len) != 0
            && EVP_DigestVerifyFinal(ctx, sig, sig_len) != 0) as libc::c_int;
    } else if ((*(*(*ctx).pctx).pmeth).verify_message).is_none() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/digestsign.c\0"
                as *const u8 as *const libc::c_char,
            335 as libc::c_int as libc::c_uint,
        );
    } else {
        ret = ((*(*(*ctx).pctx).pmeth).verify_message)
            .expect("non-null function pointer")((*ctx).pctx, sig, sig_len, data, len);
    }
    FIPS_service_indicator_unlock_state();
    if ret > 0 as libc::c_int {
        EVP_DigestVerify_verify_service_indicator(ctx);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_CTX_set_pkey_ctx(
    mut ctx: *mut EVP_MD_CTX,
    mut pctx: *mut EVP_PKEY_CTX,
) {
    if (*ctx).flags & 0x400 as libc::c_int as libc::c_ulong == 0 {
        EVP_PKEY_CTX_free((*ctx).pctx);
    }
    (*ctx).pctx = pctx;
    (*ctx).pctx_ops = EVP_MD_pctx_ops();
    if !pctx.is_null() {
        (*ctx).flags |= 0x400 as libc::c_int as libc::c_ulong;
    } else {
        (*ctx).flags &= !(0x400 as libc::c_int) as libc::c_ulong;
    };
}
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_CTX_get_pkey_ctx(
    mut ctx: *const EVP_MD_CTX,
) -> *mut EVP_PKEY_CTX {
    if ctx.is_null() {
        return 0 as *mut EVP_PKEY_CTX;
    }
    return (*ctx).pctx;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_CTX_pkey_ctx(
    mut ctx: *const EVP_MD_CTX,
) -> *mut EVP_PKEY_CTX {
    return EVP_MD_CTX_get_pkey_ctx(ctx);
}
