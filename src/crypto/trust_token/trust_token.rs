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
    pub type engine_st;
    pub type evp_md_pctx_ops;
    pub type evp_pkey_ctx_st;
    pub type env_md_st;
    pub type evp_pkey_st;
    pub type stack_st_TRUST_TOKEN_PRETOKEN;
    pub type stack_st_TRUST_TOKEN;
    pub type stack_st;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_pop_free_ex(
        sk: *mut OPENSSL_STACK,
        call_free_func: OPENSSL_sk_call_free_func,
        free_func: OPENSSL_sk_free_func,
    );
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_skip(cbs: *mut CBS, len: size_t) -> libc::c_int;
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_stow(
        cbs: *const CBS,
        out_ptr: *mut *mut uint8_t,
        out_len: *mut size_t,
    ) -> libc::c_int;
    fn CBS_get_u16(cbs: *mut CBS, out: *mut uint16_t) -> libc::c_int;
    fn CBS_get_u32(cbs: *mut CBS, out: *mut uint32_t) -> libc::c_int;
    fn CBS_get_u16_length_prefixed(cbs: *mut CBS, out: *mut CBS) -> libc::c_int;
    fn CBB_init(cbb: *mut CBB, initial_capacity: size_t) -> libc::c_int;
    fn CBB_init_fixed(cbb: *mut CBB, buf: *mut uint8_t, len: size_t) -> libc::c_int;
    fn CBB_cleanup(cbb: *mut CBB);
    fn CBB_finish(
        cbb: *mut CBB,
        out_data: *mut *mut uint8_t,
        out_len: *mut size_t,
    ) -> libc::c_int;
    fn CBB_add_u16_length_prefixed(cbb: *mut CBB, out_contents: *mut CBB) -> libc::c_int;
    fn CBB_add_bytes(cbb: *mut CBB, data: *const uint8_t, len: size_t) -> libc::c_int;
    fn CBB_add_u16(cbb: *mut CBB, value: uint16_t) -> libc::c_int;
    fn CBB_add_u32(cbb: *mut CBB, value: uint32_t) -> libc::c_int;
    fn CBB_add_u64(cbb: *mut CBB, value: uint64_t) -> libc::c_int;
    fn EVP_MD_CTX_init(ctx: *mut EVP_MD_CTX);
    fn EVP_MD_CTX_cleanup(ctx: *mut EVP_MD_CTX) -> libc::c_int;
    fn SHA256_Init(sha: *mut SHA256_CTX) -> libc::c_int;
    fn SHA256_Update(
        sha: *mut SHA256_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn SHA256_Final(out: *mut uint8_t, sha: *mut SHA256_CTX) -> libc::c_int;
    fn pmbtoken_exp1_generate_key(
        out_private: *mut CBB,
        out_public: *mut CBB,
    ) -> libc::c_int;
    fn pmbtoken_exp1_derive_key_from_secret(
        out_private: *mut CBB,
        out_public: *mut CBB,
        secret: *const uint8_t,
        secret_len: size_t,
    ) -> libc::c_int;
    fn pmbtoken_exp1_client_key_from_bytes(
        key: *mut TRUST_TOKEN_CLIENT_KEY,
        in_0: *const uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn pmbtoken_exp1_issuer_key_from_bytes(
        key: *mut TRUST_TOKEN_ISSUER_KEY,
        in_0: *const uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn pmbtoken_exp1_blind(
        cbb: *mut CBB,
        count: size_t,
        include_message: libc::c_int,
        msg: *const uint8_t,
        msg_len: size_t,
    ) -> *mut stack_st_TRUST_TOKEN_PRETOKEN;
    fn pmbtoken_exp1_sign(
        key: *const TRUST_TOKEN_ISSUER_KEY,
        cbb: *mut CBB,
        cbs: *mut CBS,
        num_requested: size_t,
        num_to_issue: size_t,
        private_metadata: uint8_t,
    ) -> libc::c_int;
    fn pmbtoken_exp1_unblind(
        key: *const TRUST_TOKEN_CLIENT_KEY,
        pretokens: *const stack_st_TRUST_TOKEN_PRETOKEN,
        cbs: *mut CBS,
        count: size_t,
        key_id: uint32_t,
    ) -> *mut stack_st_TRUST_TOKEN;
    fn pmbtoken_exp1_read(
        key: *const TRUST_TOKEN_ISSUER_KEY,
        out_nonce: *mut uint8_t,
        out_private_metadata: *mut uint8_t,
        token: *const uint8_t,
        token_len: size_t,
        include_message: libc::c_int,
        msg: *const uint8_t,
        msg_len: size_t,
    ) -> libc::c_int;
    fn pmbtoken_exp2_generate_key(
        out_private: *mut CBB,
        out_public: *mut CBB,
    ) -> libc::c_int;
    fn pmbtoken_exp2_derive_key_from_secret(
        out_private: *mut CBB,
        out_public: *mut CBB,
        secret: *const uint8_t,
        secret_len: size_t,
    ) -> libc::c_int;
    fn pmbtoken_exp2_client_key_from_bytes(
        key: *mut TRUST_TOKEN_CLIENT_KEY,
        in_0: *const uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn pmbtoken_exp2_issuer_key_from_bytes(
        key: *mut TRUST_TOKEN_ISSUER_KEY,
        in_0: *const uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn pmbtoken_exp2_blind(
        cbb: *mut CBB,
        count: size_t,
        include_message: libc::c_int,
        msg: *const uint8_t,
        msg_len: size_t,
    ) -> *mut stack_st_TRUST_TOKEN_PRETOKEN;
    fn pmbtoken_exp2_sign(
        key: *const TRUST_TOKEN_ISSUER_KEY,
        cbb: *mut CBB,
        cbs: *mut CBS,
        num_requested: size_t,
        num_to_issue: size_t,
        private_metadata: uint8_t,
    ) -> libc::c_int;
    fn pmbtoken_exp2_unblind(
        key: *const TRUST_TOKEN_CLIENT_KEY,
        pretokens: *const stack_st_TRUST_TOKEN_PRETOKEN,
        cbs: *mut CBS,
        count: size_t,
        key_id: uint32_t,
    ) -> *mut stack_st_TRUST_TOKEN;
    fn pmbtoken_exp2_read(
        key: *const TRUST_TOKEN_ISSUER_KEY,
        out_nonce: *mut uint8_t,
        out_private_metadata: *mut uint8_t,
        token: *const uint8_t,
        token_len: size_t,
        include_message: libc::c_int,
        msg: *const uint8_t,
        msg_len: size_t,
    ) -> libc::c_int;
    fn pmbtoken_pst1_generate_key(
        out_private: *mut CBB,
        out_public: *mut CBB,
    ) -> libc::c_int;
    fn pmbtoken_pst1_derive_key_from_secret(
        out_private: *mut CBB,
        out_public: *mut CBB,
        secret: *const uint8_t,
        secret_len: size_t,
    ) -> libc::c_int;
    fn pmbtoken_pst1_client_key_from_bytes(
        key: *mut TRUST_TOKEN_CLIENT_KEY,
        in_0: *const uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn pmbtoken_pst1_issuer_key_from_bytes(
        key: *mut TRUST_TOKEN_ISSUER_KEY,
        in_0: *const uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn pmbtoken_pst1_blind(
        cbb: *mut CBB,
        count: size_t,
        include_message: libc::c_int,
        msg: *const uint8_t,
        msg_len: size_t,
    ) -> *mut stack_st_TRUST_TOKEN_PRETOKEN;
    fn pmbtoken_pst1_sign(
        key: *const TRUST_TOKEN_ISSUER_KEY,
        cbb: *mut CBB,
        cbs: *mut CBS,
        num_requested: size_t,
        num_to_issue: size_t,
        private_metadata: uint8_t,
    ) -> libc::c_int;
    fn pmbtoken_pst1_unblind(
        key: *const TRUST_TOKEN_CLIENT_KEY,
        pretokens: *const stack_st_TRUST_TOKEN_PRETOKEN,
        cbs: *mut CBS,
        count: size_t,
        key_id: uint32_t,
    ) -> *mut stack_st_TRUST_TOKEN;
    fn pmbtoken_pst1_read(
        key: *const TRUST_TOKEN_ISSUER_KEY,
        out_nonce: *mut uint8_t,
        out_private_metadata: *mut uint8_t,
        token: *const uint8_t,
        token_len: size_t,
        include_message: libc::c_int,
        msg: *const uint8_t,
        msg_len: size_t,
    ) -> libc::c_int;
    fn voprf_exp2_generate_key(
        out_private: *mut CBB,
        out_public: *mut CBB,
    ) -> libc::c_int;
    fn voprf_exp2_derive_key_from_secret(
        out_private: *mut CBB,
        out_public: *mut CBB,
        secret: *const uint8_t,
        secret_len: size_t,
    ) -> libc::c_int;
    fn voprf_exp2_client_key_from_bytes(
        key: *mut TRUST_TOKEN_CLIENT_KEY,
        in_0: *const uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn voprf_exp2_issuer_key_from_bytes(
        key: *mut TRUST_TOKEN_ISSUER_KEY,
        in_0: *const uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn voprf_exp2_blind(
        cbb: *mut CBB,
        count: size_t,
        include_message: libc::c_int,
        msg: *const uint8_t,
        msg_len: size_t,
    ) -> *mut stack_st_TRUST_TOKEN_PRETOKEN;
    fn voprf_exp2_sign(
        key: *const TRUST_TOKEN_ISSUER_KEY,
        cbb: *mut CBB,
        cbs: *mut CBS,
        num_requested: size_t,
        num_to_issue: size_t,
        private_metadata: uint8_t,
    ) -> libc::c_int;
    fn voprf_exp2_unblind(
        key: *const TRUST_TOKEN_CLIENT_KEY,
        pretokens: *const stack_st_TRUST_TOKEN_PRETOKEN,
        cbs: *mut CBS,
        count: size_t,
        key_id: uint32_t,
    ) -> *mut stack_st_TRUST_TOKEN;
    fn voprf_exp2_read(
        key: *const TRUST_TOKEN_ISSUER_KEY,
        out_nonce: *mut uint8_t,
        out_private_metadata: *mut uint8_t,
        token: *const uint8_t,
        token_len: size_t,
        include_message: libc::c_int,
        msg: *const uint8_t,
        msg_len: size_t,
    ) -> libc::c_int;
    fn voprf_pst1_generate_key(
        out_private: *mut CBB,
        out_public: *mut CBB,
    ) -> libc::c_int;
    fn voprf_pst1_derive_key_from_secret(
        out_private: *mut CBB,
        out_public: *mut CBB,
        secret: *const uint8_t,
        secret_len: size_t,
    ) -> libc::c_int;
    fn voprf_pst1_client_key_from_bytes(
        key: *mut TRUST_TOKEN_CLIENT_KEY,
        in_0: *const uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn voprf_pst1_issuer_key_from_bytes(
        key: *mut TRUST_TOKEN_ISSUER_KEY,
        in_0: *const uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn voprf_pst1_blind(
        cbb: *mut CBB,
        count: size_t,
        include_message: libc::c_int,
        msg: *const uint8_t,
        msg_len: size_t,
    ) -> *mut stack_st_TRUST_TOKEN_PRETOKEN;
    fn voprf_pst1_sign(
        key: *const TRUST_TOKEN_ISSUER_KEY,
        cbb: *mut CBB,
        cbs: *mut CBS,
        num_requested: size_t,
        num_to_issue: size_t,
        private_metadata: uint8_t,
    ) -> libc::c_int;
    fn voprf_pst1_unblind(
        key: *const TRUST_TOKEN_CLIENT_KEY,
        pretokens: *const stack_st_TRUST_TOKEN_PRETOKEN,
        cbs: *mut CBS,
        count: size_t,
        key_id: uint32_t,
    ) -> *mut stack_st_TRUST_TOKEN;
    fn voprf_pst1_read(
        key: *const TRUST_TOKEN_ISSUER_KEY,
        out_nonce: *mut uint8_t,
        out_private_metadata: *mut uint8_t,
        token: *const uint8_t,
        token_len: size_t,
        include_message: libc::c_int,
        msg: *const uint8_t,
        msg_len: size_t,
    ) -> libc::c_int;
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
    fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
    fn EVP_PKEY_up_ref(pkey: *mut EVP_PKEY) -> libc::c_int;
    fn EVP_DigestVerifyInit(
        ctx: *mut EVP_MD_CTX,
        pctx: *mut *mut EVP_PKEY_CTX,
        type_0: *const EVP_MD,
        e: *mut ENGINE,
        pkey: *mut EVP_PKEY,
    ) -> libc::c_int;
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
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type BN_ULONG = uint64_t;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EC_FELEM {
    pub words: [BN_ULONG; 9],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EC_SCALAR {
    pub words: [BN_ULONG; 9],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union EC_PRECOMP {
    pub comb: [EC_AFFINE; 31],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EC_AFFINE {
    pub X: EC_FELEM,
    pub Y: EC_FELEM,
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
pub type EVP_PKEY = evp_pkey_st;
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
pub type SHA256_CTX = sha256_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct trust_token_st {
    pub data: *mut uint8_t,
    pub len: size_t,
}
pub type TRUST_TOKEN = trust_token_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct trust_token_client_st {
    pub method: *const TRUST_TOKEN_METHOD,
    pub max_batchsize: uint16_t,
    pub keys: [trust_token_client_key_st; 6],
    pub num_keys: size_t,
    pub pretokens: *mut stack_st_TRUST_TOKEN_PRETOKEN,
    pub srr_key: *mut EVP_PKEY,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct trust_token_client_key_st {
    pub id: uint32_t,
    pub key: TRUST_TOKEN_CLIENT_KEY,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct TRUST_TOKEN_CLIENT_KEY {
    pub pub0: EC_AFFINE,
    pub pub1: EC_AFFINE,
    pub pubs: EC_AFFINE,
}
pub type TRUST_TOKEN_METHOD = trust_token_method_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct trust_token_method_st {
    pub generate_key: Option::<unsafe extern "C" fn(*mut CBB, *mut CBB) -> libc::c_int>,
    pub derive_key_from_secret: Option::<
        unsafe extern "C" fn(*mut CBB, *mut CBB, *const uint8_t, size_t) -> libc::c_int,
    >,
    pub client_key_from_bytes: Option::<
        unsafe extern "C" fn(
            *mut TRUST_TOKEN_CLIENT_KEY,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub issuer_key_from_bytes: Option::<
        unsafe extern "C" fn(
            *mut TRUST_TOKEN_ISSUER_KEY,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub blind: Option::<
        unsafe extern "C" fn(
            *mut CBB,
            size_t,
            libc::c_int,
            *const uint8_t,
            size_t,
        ) -> *mut stack_st_TRUST_TOKEN_PRETOKEN,
    >,
    pub sign: Option::<
        unsafe extern "C" fn(
            *const TRUST_TOKEN_ISSUER_KEY,
            *mut CBB,
            *mut CBS,
            size_t,
            size_t,
            uint8_t,
        ) -> libc::c_int,
    >,
    pub unblind: Option::<
        unsafe extern "C" fn(
            *const TRUST_TOKEN_CLIENT_KEY,
            *const stack_st_TRUST_TOKEN_PRETOKEN,
            *mut CBS,
            size_t,
            uint32_t,
        ) -> *mut stack_st_TRUST_TOKEN,
    >,
    pub read: Option::<
        unsafe extern "C" fn(
            *const TRUST_TOKEN_ISSUER_KEY,
            *mut uint8_t,
            *mut uint8_t,
            *const uint8_t,
            size_t,
            libc::c_int,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub has_private_metadata: libc::c_int,
    pub max_keys: size_t,
    pub has_srr: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct TRUST_TOKEN_ISSUER_KEY {
    pub x0: EC_SCALAR,
    pub y0: EC_SCALAR,
    pub x1: EC_SCALAR,
    pub y1: EC_SCALAR,
    pub xs: EC_SCALAR,
    pub ys: EC_SCALAR,
    pub pub0: EC_AFFINE,
    pub pub0_precomp: EC_PRECOMP,
    pub pub1: EC_AFFINE,
    pub pub1_precomp: EC_PRECOMP,
    pub pubs: EC_AFFINE,
    pub pubs_precomp: EC_PRECOMP,
}
pub type TRUST_TOKEN_CLIENT = trust_token_client_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct trust_token_issuer_st {
    pub method: *const TRUST_TOKEN_METHOD,
    pub max_batchsize: uint16_t,
    pub keys: [trust_token_issuer_key_st; 6],
    pub num_keys: size_t,
    pub srr_key: *mut EVP_PKEY,
    pub metadata_key: *mut uint8_t,
    pub metadata_key_len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct trust_token_issuer_key_st {
    pub id: uint32_t,
    pub key: TRUST_TOKEN_ISSUER_KEY,
}
pub type TRUST_TOKEN_ISSUER = trust_token_issuer_st;
pub type OPENSSL_sk_free_func = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type OPENSSL_sk_call_free_func = Option::<
    unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
>;
pub type OPENSSL_STACK = stack_st;
pub type sk_TRUST_TOKEN_free_func = Option::<
    unsafe extern "C" fn(*mut TRUST_TOKEN) -> (),
>;
pub type TRUST_TOKEN_PRETOKEN = pmb_pretoken_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pmb_pretoken_st {
    pub salt: [uint8_t; 64],
    pub t: [uint8_t; 64],
    pub r: EC_SCALAR,
    pub Tp: EC_AFFINE,
}
pub type sk_TRUST_TOKEN_PRETOKEN_free_func = Option::<
    unsafe extern "C" fn(*mut TRUST_TOKEN_PRETOKEN) -> (),
>;
#[inline]
unsafe extern "C" fn sk_TRUST_TOKEN_pop_free(
    mut sk: *mut stack_st_TRUST_TOKEN,
    mut free_func: sk_TRUST_TOKEN_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_TRUST_TOKEN_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_TRUST_TOKEN_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_TRUST_TOKEN_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<OPENSSL_sk_free_func, sk_TRUST_TOKEN_free_func>(free_func))
        .expect("non-null function pointer")(ptr as *mut TRUST_TOKEN);
}
#[inline]
unsafe extern "C" fn sk_TRUST_TOKEN_PRETOKEN_pop_free(
    mut sk: *mut stack_st_TRUST_TOKEN_PRETOKEN,
    mut free_func: sk_TRUST_TOKEN_PRETOKEN_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_TRUST_TOKEN_PRETOKEN_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_TRUST_TOKEN_PRETOKEN_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_TRUST_TOKEN_PRETOKEN_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<
        OPENSSL_sk_free_func,
        sk_TRUST_TOKEN_PRETOKEN_free_func,
    >(free_func))
        .expect("non-null function pointer")(ptr as *mut TRUST_TOKEN_PRETOKEN);
}
#[inline]
unsafe extern "C" fn sk_TRUST_TOKEN_PRETOKEN_num(
    mut sk: *const stack_st_TRUST_TOKEN_PRETOKEN,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_experiment_v1() -> *const TRUST_TOKEN_METHOD {
    static mut kMethod: TRUST_TOKEN_METHOD = unsafe {
        {
            let mut init = trust_token_method_st {
                generate_key: Some(
                    pmbtoken_exp1_generate_key
                        as unsafe extern "C" fn(*mut CBB, *mut CBB) -> libc::c_int,
                ),
                derive_key_from_secret: Some(
                    pmbtoken_exp1_derive_key_from_secret
                        as unsafe extern "C" fn(
                            *mut CBB,
                            *mut CBB,
                            *const uint8_t,
                            size_t,
                        ) -> libc::c_int,
                ),
                client_key_from_bytes: Some(
                    pmbtoken_exp1_client_key_from_bytes
                        as unsafe extern "C" fn(
                            *mut TRUST_TOKEN_CLIENT_KEY,
                            *const uint8_t,
                            size_t,
                        ) -> libc::c_int,
                ),
                issuer_key_from_bytes: Some(
                    pmbtoken_exp1_issuer_key_from_bytes
                        as unsafe extern "C" fn(
                            *mut TRUST_TOKEN_ISSUER_KEY,
                            *const uint8_t,
                            size_t,
                        ) -> libc::c_int,
                ),
                blind: Some(
                    pmbtoken_exp1_blind
                        as unsafe extern "C" fn(
                            *mut CBB,
                            size_t,
                            libc::c_int,
                            *const uint8_t,
                            size_t,
                        ) -> *mut stack_st_TRUST_TOKEN_PRETOKEN,
                ),
                sign: Some(
                    pmbtoken_exp1_sign
                        as unsafe extern "C" fn(
                            *const TRUST_TOKEN_ISSUER_KEY,
                            *mut CBB,
                            *mut CBS,
                            size_t,
                            size_t,
                            uint8_t,
                        ) -> libc::c_int,
                ),
                unblind: Some(
                    pmbtoken_exp1_unblind
                        as unsafe extern "C" fn(
                            *const TRUST_TOKEN_CLIENT_KEY,
                            *const stack_st_TRUST_TOKEN_PRETOKEN,
                            *mut CBS,
                            size_t,
                            uint32_t,
                        ) -> *mut stack_st_TRUST_TOKEN,
                ),
                read: Some(
                    pmbtoken_exp1_read
                        as unsafe extern "C" fn(
                            *const TRUST_TOKEN_ISSUER_KEY,
                            *mut uint8_t,
                            *mut uint8_t,
                            *const uint8_t,
                            size_t,
                            libc::c_int,
                            *const uint8_t,
                            size_t,
                        ) -> libc::c_int,
                ),
                has_private_metadata: 1 as libc::c_int,
                max_keys: 3 as libc::c_int as size_t,
                has_srr: 1 as libc::c_int,
            };
            init
        }
    };
    return &kMethod;
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_experiment_v2_voprf() -> *const TRUST_TOKEN_METHOD {
    static mut kMethod: TRUST_TOKEN_METHOD = unsafe {
        {
            let mut init = trust_token_method_st {
                generate_key: Some(
                    voprf_exp2_generate_key
                        as unsafe extern "C" fn(*mut CBB, *mut CBB) -> libc::c_int,
                ),
                derive_key_from_secret: Some(
                    voprf_exp2_derive_key_from_secret
                        as unsafe extern "C" fn(
                            *mut CBB,
                            *mut CBB,
                            *const uint8_t,
                            size_t,
                        ) -> libc::c_int,
                ),
                client_key_from_bytes: Some(
                    voprf_exp2_client_key_from_bytes
                        as unsafe extern "C" fn(
                            *mut TRUST_TOKEN_CLIENT_KEY,
                            *const uint8_t,
                            size_t,
                        ) -> libc::c_int,
                ),
                issuer_key_from_bytes: Some(
                    voprf_exp2_issuer_key_from_bytes
                        as unsafe extern "C" fn(
                            *mut TRUST_TOKEN_ISSUER_KEY,
                            *const uint8_t,
                            size_t,
                        ) -> libc::c_int,
                ),
                blind: Some(
                    voprf_exp2_blind
                        as unsafe extern "C" fn(
                            *mut CBB,
                            size_t,
                            libc::c_int,
                            *const uint8_t,
                            size_t,
                        ) -> *mut stack_st_TRUST_TOKEN_PRETOKEN,
                ),
                sign: Some(
                    voprf_exp2_sign
                        as unsafe extern "C" fn(
                            *const TRUST_TOKEN_ISSUER_KEY,
                            *mut CBB,
                            *mut CBS,
                            size_t,
                            size_t,
                            uint8_t,
                        ) -> libc::c_int,
                ),
                unblind: Some(
                    voprf_exp2_unblind
                        as unsafe extern "C" fn(
                            *const TRUST_TOKEN_CLIENT_KEY,
                            *const stack_st_TRUST_TOKEN_PRETOKEN,
                            *mut CBS,
                            size_t,
                            uint32_t,
                        ) -> *mut stack_st_TRUST_TOKEN,
                ),
                read: Some(
                    voprf_exp2_read
                        as unsafe extern "C" fn(
                            *const TRUST_TOKEN_ISSUER_KEY,
                            *mut uint8_t,
                            *mut uint8_t,
                            *const uint8_t,
                            size_t,
                            libc::c_int,
                            *const uint8_t,
                            size_t,
                        ) -> libc::c_int,
                ),
                has_private_metadata: 0 as libc::c_int,
                max_keys: 6 as libc::c_int as size_t,
                has_srr: 0 as libc::c_int,
            };
            init
        }
    };
    return &kMethod;
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_experiment_v2_pmb() -> *const TRUST_TOKEN_METHOD {
    static mut kMethod: TRUST_TOKEN_METHOD = unsafe {
        {
            let mut init = trust_token_method_st {
                generate_key: Some(
                    pmbtoken_exp2_generate_key
                        as unsafe extern "C" fn(*mut CBB, *mut CBB) -> libc::c_int,
                ),
                derive_key_from_secret: Some(
                    pmbtoken_exp2_derive_key_from_secret
                        as unsafe extern "C" fn(
                            *mut CBB,
                            *mut CBB,
                            *const uint8_t,
                            size_t,
                        ) -> libc::c_int,
                ),
                client_key_from_bytes: Some(
                    pmbtoken_exp2_client_key_from_bytes
                        as unsafe extern "C" fn(
                            *mut TRUST_TOKEN_CLIENT_KEY,
                            *const uint8_t,
                            size_t,
                        ) -> libc::c_int,
                ),
                issuer_key_from_bytes: Some(
                    pmbtoken_exp2_issuer_key_from_bytes
                        as unsafe extern "C" fn(
                            *mut TRUST_TOKEN_ISSUER_KEY,
                            *const uint8_t,
                            size_t,
                        ) -> libc::c_int,
                ),
                blind: Some(
                    pmbtoken_exp2_blind
                        as unsafe extern "C" fn(
                            *mut CBB,
                            size_t,
                            libc::c_int,
                            *const uint8_t,
                            size_t,
                        ) -> *mut stack_st_TRUST_TOKEN_PRETOKEN,
                ),
                sign: Some(
                    pmbtoken_exp2_sign
                        as unsafe extern "C" fn(
                            *const TRUST_TOKEN_ISSUER_KEY,
                            *mut CBB,
                            *mut CBS,
                            size_t,
                            size_t,
                            uint8_t,
                        ) -> libc::c_int,
                ),
                unblind: Some(
                    pmbtoken_exp2_unblind
                        as unsafe extern "C" fn(
                            *const TRUST_TOKEN_CLIENT_KEY,
                            *const stack_st_TRUST_TOKEN_PRETOKEN,
                            *mut CBS,
                            size_t,
                            uint32_t,
                        ) -> *mut stack_st_TRUST_TOKEN,
                ),
                read: Some(
                    pmbtoken_exp2_read
                        as unsafe extern "C" fn(
                            *const TRUST_TOKEN_ISSUER_KEY,
                            *mut uint8_t,
                            *mut uint8_t,
                            *const uint8_t,
                            size_t,
                            libc::c_int,
                            *const uint8_t,
                            size_t,
                        ) -> libc::c_int,
                ),
                has_private_metadata: 1 as libc::c_int,
                max_keys: 3 as libc::c_int as size_t,
                has_srr: 0 as libc::c_int,
            };
            init
        }
    };
    return &kMethod;
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_pst_v1_voprf() -> *const TRUST_TOKEN_METHOD {
    static mut kMethod: TRUST_TOKEN_METHOD = unsafe {
        {
            let mut init = trust_token_method_st {
                generate_key: Some(
                    voprf_pst1_generate_key
                        as unsafe extern "C" fn(*mut CBB, *mut CBB) -> libc::c_int,
                ),
                derive_key_from_secret: Some(
                    voprf_pst1_derive_key_from_secret
                        as unsafe extern "C" fn(
                            *mut CBB,
                            *mut CBB,
                            *const uint8_t,
                            size_t,
                        ) -> libc::c_int,
                ),
                client_key_from_bytes: Some(
                    voprf_pst1_client_key_from_bytes
                        as unsafe extern "C" fn(
                            *mut TRUST_TOKEN_CLIENT_KEY,
                            *const uint8_t,
                            size_t,
                        ) -> libc::c_int,
                ),
                issuer_key_from_bytes: Some(
                    voprf_pst1_issuer_key_from_bytes
                        as unsafe extern "C" fn(
                            *mut TRUST_TOKEN_ISSUER_KEY,
                            *const uint8_t,
                            size_t,
                        ) -> libc::c_int,
                ),
                blind: Some(
                    voprf_pst1_blind
                        as unsafe extern "C" fn(
                            *mut CBB,
                            size_t,
                            libc::c_int,
                            *const uint8_t,
                            size_t,
                        ) -> *mut stack_st_TRUST_TOKEN_PRETOKEN,
                ),
                sign: Some(
                    voprf_pst1_sign
                        as unsafe extern "C" fn(
                            *const TRUST_TOKEN_ISSUER_KEY,
                            *mut CBB,
                            *mut CBS,
                            size_t,
                            size_t,
                            uint8_t,
                        ) -> libc::c_int,
                ),
                unblind: Some(
                    voprf_pst1_unblind
                        as unsafe extern "C" fn(
                            *const TRUST_TOKEN_CLIENT_KEY,
                            *const stack_st_TRUST_TOKEN_PRETOKEN,
                            *mut CBS,
                            size_t,
                            uint32_t,
                        ) -> *mut stack_st_TRUST_TOKEN,
                ),
                read: Some(
                    voprf_pst1_read
                        as unsafe extern "C" fn(
                            *const TRUST_TOKEN_ISSUER_KEY,
                            *mut uint8_t,
                            *mut uint8_t,
                            *const uint8_t,
                            size_t,
                            libc::c_int,
                            *const uint8_t,
                            size_t,
                        ) -> libc::c_int,
                ),
                has_private_metadata: 0 as libc::c_int,
                max_keys: 6 as libc::c_int as size_t,
                has_srr: 0 as libc::c_int,
            };
            init
        }
    };
    return &kMethod;
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_pst_v1_pmb() -> *const TRUST_TOKEN_METHOD {
    static mut kMethod: TRUST_TOKEN_METHOD = unsafe {
        {
            let mut init = trust_token_method_st {
                generate_key: Some(
                    pmbtoken_pst1_generate_key
                        as unsafe extern "C" fn(*mut CBB, *mut CBB) -> libc::c_int,
                ),
                derive_key_from_secret: Some(
                    pmbtoken_pst1_derive_key_from_secret
                        as unsafe extern "C" fn(
                            *mut CBB,
                            *mut CBB,
                            *const uint8_t,
                            size_t,
                        ) -> libc::c_int,
                ),
                client_key_from_bytes: Some(
                    pmbtoken_pst1_client_key_from_bytes
                        as unsafe extern "C" fn(
                            *mut TRUST_TOKEN_CLIENT_KEY,
                            *const uint8_t,
                            size_t,
                        ) -> libc::c_int,
                ),
                issuer_key_from_bytes: Some(
                    pmbtoken_pst1_issuer_key_from_bytes
                        as unsafe extern "C" fn(
                            *mut TRUST_TOKEN_ISSUER_KEY,
                            *const uint8_t,
                            size_t,
                        ) -> libc::c_int,
                ),
                blind: Some(
                    pmbtoken_pst1_blind
                        as unsafe extern "C" fn(
                            *mut CBB,
                            size_t,
                            libc::c_int,
                            *const uint8_t,
                            size_t,
                        ) -> *mut stack_st_TRUST_TOKEN_PRETOKEN,
                ),
                sign: Some(
                    pmbtoken_pst1_sign
                        as unsafe extern "C" fn(
                            *const TRUST_TOKEN_ISSUER_KEY,
                            *mut CBB,
                            *mut CBS,
                            size_t,
                            size_t,
                            uint8_t,
                        ) -> libc::c_int,
                ),
                unblind: Some(
                    pmbtoken_pst1_unblind
                        as unsafe extern "C" fn(
                            *const TRUST_TOKEN_CLIENT_KEY,
                            *const stack_st_TRUST_TOKEN_PRETOKEN,
                            *mut CBS,
                            size_t,
                            uint32_t,
                        ) -> *mut stack_st_TRUST_TOKEN,
                ),
                read: Some(
                    pmbtoken_pst1_read
                        as unsafe extern "C" fn(
                            *const TRUST_TOKEN_ISSUER_KEY,
                            *mut uint8_t,
                            *mut uint8_t,
                            *const uint8_t,
                            size_t,
                            libc::c_int,
                            *const uint8_t,
                            size_t,
                        ) -> libc::c_int,
                ),
                has_private_metadata: 1 as libc::c_int,
                max_keys: 3 as libc::c_int as size_t,
                has_srr: 0 as libc::c_int,
            };
            init
        }
    };
    return &kMethod;
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_PRETOKEN_free(
    mut pretoken: *mut TRUST_TOKEN_PRETOKEN,
) {
    OPENSSL_free(pretoken as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_new(
    mut data: *const uint8_t,
    mut len: size_t,
) -> *mut TRUST_TOKEN {
    let mut ret: *mut TRUST_TOKEN = OPENSSL_zalloc(
        ::core::mem::size_of::<TRUST_TOKEN>() as libc::c_ulong,
    ) as *mut TRUST_TOKEN;
    if ret.is_null() {
        return 0 as *mut TRUST_TOKEN;
    }
    (*ret).data = OPENSSL_memdup(data as *const libc::c_void, len) as *mut uint8_t;
    if len != 0 as libc::c_int as size_t && ((*ret).data).is_null() {
        OPENSSL_free(ret as *mut libc::c_void);
        return 0 as *mut TRUST_TOKEN;
    }
    (*ret).len = len;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_free(mut token: *mut TRUST_TOKEN) {
    if token.is_null() {
        return;
    }
    OPENSSL_free((*token).data as *mut libc::c_void);
    OPENSSL_free(token as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_generate_key(
    mut method: *const TRUST_TOKEN_METHOD,
    mut out_priv_key: *mut uint8_t,
    mut out_priv_key_len: *mut size_t,
    mut max_priv_key_len: size_t,
    mut out_pub_key: *mut uint8_t,
    mut out_pub_key_len: *mut size_t,
    mut max_pub_key_len: size_t,
    mut id: uint32_t,
) -> libc::c_int {
    let mut priv_cbb: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut pub_cbb: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    CBB_init_fixed(&mut priv_cbb, out_priv_key, max_priv_key_len);
    CBB_init_fixed(&mut pub_cbb, out_pub_key, max_pub_key_len);
    if CBB_add_u32(&mut priv_cbb, id) == 0 || CBB_add_u32(&mut pub_cbb, id) == 0 {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/trust_token.c\0"
                as *const u8 as *const libc::c_char,
            153 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*method).generate_key)
        .expect("non-null function pointer")(&mut priv_cbb, &mut pub_cbb) == 0
    {
        return 0 as libc::c_int;
    }
    if CBB_finish(&mut priv_cbb, 0 as *mut *mut uint8_t, out_priv_key_len) == 0
        || CBB_finish(&mut pub_cbb, 0 as *mut *mut uint8_t, out_pub_key_len) == 0
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/trust_token.c\0"
                as *const u8 as *const libc::c_char,
            163 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_derive_key_from_secret(
    mut method: *const TRUST_TOKEN_METHOD,
    mut out_priv_key: *mut uint8_t,
    mut out_priv_key_len: *mut size_t,
    mut max_priv_key_len: size_t,
    mut out_pub_key: *mut uint8_t,
    mut out_pub_key_len: *mut size_t,
    mut max_pub_key_len: size_t,
    mut id: uint32_t,
    mut secret: *const uint8_t,
    mut secret_len: size_t,
) -> libc::c_int {
    let mut priv_cbb: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut pub_cbb: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    CBB_init_fixed(&mut priv_cbb, out_priv_key, max_priv_key_len);
    CBB_init_fixed(&mut pub_cbb, out_pub_key, max_pub_key_len);
    if CBB_add_u32(&mut priv_cbb, id) == 0 || CBB_add_u32(&mut pub_cbb, id) == 0 {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/trust_token.c\0"
                as *const u8 as *const libc::c_char,
            181 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*method).derive_key_from_secret)
        .expect(
            "non-null function pointer",
        )(&mut priv_cbb, &mut pub_cbb, secret, secret_len) == 0
    {
        return 0 as libc::c_int;
    }
    if CBB_finish(&mut priv_cbb, 0 as *mut *mut uint8_t, out_priv_key_len) == 0
        || CBB_finish(&mut pub_cbb, 0 as *mut *mut uint8_t, out_pub_key_len) == 0
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/trust_token.c\0"
                as *const u8 as *const libc::c_char,
            192 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_CLIENT_new(
    mut method: *const TRUST_TOKEN_METHOD,
    mut max_batchsize: size_t,
) -> *mut TRUST_TOKEN_CLIENT {
    if max_batchsize > 0xffff as libc::c_int as size_t {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/trust_token.c\0"
                as *const u8 as *const libc::c_char,
            203 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut TRUST_TOKEN_CLIENT;
    }
    let mut ret: *mut TRUST_TOKEN_CLIENT = OPENSSL_zalloc(
        ::core::mem::size_of::<TRUST_TOKEN_CLIENT>() as libc::c_ulong,
    ) as *mut TRUST_TOKEN_CLIENT;
    if ret.is_null() {
        return 0 as *mut TRUST_TOKEN_CLIENT;
    }
    (*ret).method = method;
    (*ret).max_batchsize = max_batchsize as uint16_t;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_CLIENT_free(mut ctx: *mut TRUST_TOKEN_CLIENT) {
    if ctx.is_null() {
        return;
    }
    EVP_PKEY_free((*ctx).srr_key);
    sk_TRUST_TOKEN_PRETOKEN_pop_free(
        (*ctx).pretokens,
        Some(
            TRUST_TOKEN_PRETOKEN_free
                as unsafe extern "C" fn(*mut TRUST_TOKEN_PRETOKEN) -> (),
        ),
    );
    OPENSSL_free(ctx as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_CLIENT_add_key(
    mut ctx: *mut TRUST_TOKEN_CLIENT,
    mut out_key_index: *mut size_t,
    mut key: *const uint8_t,
    mut key_len: size_t,
) -> libc::c_int {
    if (*ctx).num_keys
        == (::core::mem::size_of::<[trust_token_client_key_st; 6]>() as libc::c_ulong)
            .wrapping_div(
                ::core::mem::size_of::<trust_token_client_key_st>() as libc::c_ulong,
            ) || (*ctx).num_keys >= (*(*ctx).method).max_keys
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            107 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/trust_token.c\0"
                as *const u8 as *const libc::c_char,
            229 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut key_s: *mut trust_token_client_key_st = &mut *((*ctx).keys)
        .as_mut_ptr()
        .offset((*ctx).num_keys as isize) as *mut trust_token_client_key_st;
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, key, key_len);
    let mut key_id: uint32_t = 0;
    if CBS_get_u32(&mut cbs, &mut key_id) == 0
        || ((*(*ctx).method).client_key_from_bytes)
            .expect(
                "non-null function pointer",
            )(&mut (*key_s).key, CBS_data(&mut cbs), CBS_len(&mut cbs)) == 0
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/trust_token.c\0"
                as *const u8 as *const libc::c_char,
            240 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*key_s).id = key_id;
    *out_key_index = (*ctx).num_keys;
    (*ctx).num_keys = ((*ctx).num_keys).wrapping_add(1 as libc::c_int as size_t);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_CLIENT_set_srr_key(
    mut ctx: *mut TRUST_TOKEN_CLIENT,
    mut key: *mut EVP_PKEY,
) -> libc::c_int {
    if (*(*ctx).method).has_srr == 0 {
        return 1 as libc::c_int;
    }
    EVP_PKEY_free((*ctx).srr_key);
    EVP_PKEY_up_ref(key);
    (*ctx).srr_key = key;
    return 1 as libc::c_int;
}
unsafe extern "C" fn trust_token_client_begin_issuance_impl(
    mut ctx: *mut TRUST_TOKEN_CLIENT,
    mut out: *mut *mut uint8_t,
    mut out_len: *mut size_t,
    mut count: size_t,
    mut include_message: libc::c_int,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> libc::c_int {
    if count > (*ctx).max_batchsize as size_t {
        count = (*ctx).max_batchsize as size_t;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut request: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut pretokens: *mut stack_st_TRUST_TOKEN_PRETOKEN = 0
        as *mut stack_st_TRUST_TOKEN_PRETOKEN;
    if !(CBB_init(&mut request, 0 as libc::c_int as size_t) == 0
        || CBB_add_u16(&mut request, count as uint16_t) == 0)
    {
        pretokens = ((*(*ctx).method).blind)
            .expect(
                "non-null function pointer",
            )(&mut request, count, include_message, msg, msg_len);
        if !pretokens.is_null() {
            if !(CBB_finish(&mut request, out, out_len) == 0) {
                sk_TRUST_TOKEN_PRETOKEN_pop_free(
                    (*ctx).pretokens,
                    Some(
                        TRUST_TOKEN_PRETOKEN_free
                            as unsafe extern "C" fn(*mut TRUST_TOKEN_PRETOKEN) -> (),
                    ),
                );
                (*ctx).pretokens = pretokens;
                pretokens = 0 as *mut stack_st_TRUST_TOKEN_PRETOKEN;
                ret = 1 as libc::c_int;
            }
        }
    }
    CBB_cleanup(&mut request);
    sk_TRUST_TOKEN_PRETOKEN_pop_free(
        pretokens,
        Some(
            TRUST_TOKEN_PRETOKEN_free
                as unsafe extern "C" fn(*mut TRUST_TOKEN_PRETOKEN) -> (),
        ),
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_CLIENT_begin_issuance(
    mut ctx: *mut TRUST_TOKEN_CLIENT,
    mut out: *mut *mut uint8_t,
    mut out_len: *mut size_t,
    mut count: size_t,
) -> libc::c_int {
    return trust_token_client_begin_issuance_impl(
        ctx,
        out,
        out_len,
        count,
        0 as libc::c_int,
        0 as *const uint8_t,
        0 as libc::c_int as size_t,
    );
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_CLIENT_begin_issuance_over_message(
    mut ctx: *mut TRUST_TOKEN_CLIENT,
    mut out: *mut *mut uint8_t,
    mut out_len: *mut size_t,
    mut count: size_t,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> libc::c_int {
    return trust_token_client_begin_issuance_impl(
        ctx,
        out,
        out_len,
        count,
        1 as libc::c_int,
        msg,
        msg_len,
    );
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_CLIENT_finish_issuance(
    mut ctx: *mut TRUST_TOKEN_CLIENT,
    mut out_key_index: *mut size_t,
    mut response: *const uint8_t,
    mut response_len: size_t,
) -> *mut stack_st_TRUST_TOKEN {
    let mut in_0: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut in_0, response, response_len);
    let mut count: uint16_t = 0;
    let mut key_id: uint32_t = 0;
    if CBS_get_u16(&mut in_0, &mut count) == 0
        || CBS_get_u32(&mut in_0, &mut key_id) == 0
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/trust_token.c\0"
                as *const u8 as *const libc::c_char,
            320 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut stack_st_TRUST_TOKEN;
    }
    let mut key_index: size_t = 0 as libc::c_int as size_t;
    let mut key: *const trust_token_client_key_st = 0
        as *const trust_token_client_key_st;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < (*ctx).num_keys {
        if (*ctx).keys[i as usize].id == key_id {
            key_index = i;
            key = &mut *((*ctx).keys).as_mut_ptr().offset(i as isize)
                as *mut trust_token_client_key_st;
            break;
        } else {
            i = i.wrapping_add(1);
            i;
        }
    }
    if key.is_null() {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/trust_token.c\0"
                as *const u8 as *const libc::c_char,
            335 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut stack_st_TRUST_TOKEN;
    }
    if count as size_t > sk_TRUST_TOKEN_PRETOKEN_num((*ctx).pretokens) {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/trust_token.c\0"
                as *const u8 as *const libc::c_char,
            340 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut stack_st_TRUST_TOKEN;
    }
    let mut tokens: *mut stack_st_TRUST_TOKEN = ((*(*ctx).method).unblind)
        .expect(
            "non-null function pointer",
        )(&(*key).key, (*ctx).pretokens, &mut in_0, count as size_t, key_id);
    if tokens.is_null() {
        return 0 as *mut stack_st_TRUST_TOKEN;
    }
    if CBS_len(&mut in_0) != 0 as libc::c_int as size_t {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/trust_token.c\0"
                as *const u8 as *const libc::c_char,
            351 as libc::c_int as libc::c_uint,
        );
        sk_TRUST_TOKEN_pop_free(
            tokens,
            Some(TRUST_TOKEN_free as unsafe extern "C" fn(*mut TRUST_TOKEN) -> ()),
        );
        return 0 as *mut stack_st_TRUST_TOKEN;
    }
    sk_TRUST_TOKEN_PRETOKEN_pop_free(
        (*ctx).pretokens,
        Some(
            TRUST_TOKEN_PRETOKEN_free
                as unsafe extern "C" fn(*mut TRUST_TOKEN_PRETOKEN) -> (),
        ),
    );
    (*ctx).pretokens = 0 as *mut stack_st_TRUST_TOKEN_PRETOKEN;
    *out_key_index = key_index;
    return tokens;
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_CLIENT_begin_redemption(
    mut ctx: *mut TRUST_TOKEN_CLIENT,
    mut out: *mut *mut uint8_t,
    mut out_len: *mut size_t,
    mut token: *const TRUST_TOKEN,
    mut data: *const uint8_t,
    mut data_len: size_t,
    mut time: uint64_t,
) -> libc::c_int {
    let mut request: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut token_inner: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut inner: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    if CBB_init(&mut request, 0 as libc::c_int as size_t) == 0
        || CBB_add_u16_length_prefixed(&mut request, &mut token_inner) == 0
        || CBB_add_bytes(&mut token_inner, (*token).data, (*token).len) == 0
        || CBB_add_u16_length_prefixed(&mut request, &mut inner) == 0
        || CBB_add_bytes(&mut inner, data, data_len) == 0
        || (*(*ctx).method).has_srr != 0 && CBB_add_u64(&mut request, time) == 0
        || CBB_finish(&mut request, out, out_len) == 0
    {
        CBB_cleanup(&mut request);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_CLIENT_finish_redemption(
    mut ctx: *mut TRUST_TOKEN_CLIENT,
    mut out_rr: *mut *mut uint8_t,
    mut out_rr_len: *mut size_t,
    mut out_sig: *mut *mut uint8_t,
    mut out_sig_len: *mut size_t,
    mut response: *const uint8_t,
    mut response_len: size_t,
) -> libc::c_int {
    let mut in_0: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut srr: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut sig: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut in_0, response, response_len);
    if (*(*ctx).method).has_srr == 0 {
        if CBS_stow(&mut in_0, out_rr, out_rr_len) == 0 {
            return 0 as libc::c_int;
        }
        *out_sig = 0 as *mut uint8_t;
        *out_sig_len = 0 as libc::c_int as size_t;
        return 1 as libc::c_int;
    }
    if CBS_get_u16_length_prefixed(&mut in_0, &mut srr) == 0
        || CBS_get_u16_length_prefixed(&mut in_0, &mut sig) == 0
        || CBS_len(&mut in_0) != 0 as libc::c_int as size_t
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            103 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/trust_token.c\0"
                as *const u8 as *const libc::c_char,
            402 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*ctx).srr_key).is_null() {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            112 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/trust_token.c\0"
                as *const u8 as *const libc::c_char,
            407 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut md_ctx: EVP_MD_CTX = env_md_ctx_st {
        digest: 0 as *const EVP_MD,
        md_data: 0 as *mut libc::c_void,
        update: None,
        pctx: 0 as *mut EVP_PKEY_CTX,
        pctx_ops: 0 as *const evp_md_pctx_ops,
        flags: 0,
    };
    EVP_MD_CTX_init(&mut md_ctx);
    let mut sig_ok: libc::c_int = (EVP_DigestVerifyInit(
        &mut md_ctx,
        0 as *mut *mut EVP_PKEY_CTX,
        0 as *const EVP_MD,
        0 as *mut ENGINE,
        (*ctx).srr_key,
    ) != 0
        && EVP_DigestVerify(
            &mut md_ctx,
            CBS_data(&mut sig),
            CBS_len(&mut sig),
            CBS_data(&mut srr),
            CBS_len(&mut srr),
        ) != 0) as libc::c_int;
    EVP_MD_CTX_cleanup(&mut md_ctx);
    if sig_ok == 0 {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/trust_token.c\0"
                as *const u8 as *const libc::c_char,
            419 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut srr_buf: *mut uint8_t = 0 as *mut uint8_t;
    let mut sig_buf: *mut uint8_t = 0 as *mut uint8_t;
    let mut srr_len: size_t = 0;
    let mut sig_len: size_t = 0;
    if CBS_stow(&mut srr, &mut srr_buf, &mut srr_len) == 0
        || CBS_stow(&mut sig, &mut sig_buf, &mut sig_len) == 0
    {
        OPENSSL_free(srr_buf as *mut libc::c_void);
        OPENSSL_free(sig_buf as *mut libc::c_void);
        return 0 as libc::c_int;
    }
    *out_rr = srr_buf;
    *out_rr_len = srr_len;
    *out_sig = sig_buf;
    *out_sig_len = sig_len;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_ISSUER_new(
    mut method: *const TRUST_TOKEN_METHOD,
    mut max_batchsize: size_t,
) -> *mut TRUST_TOKEN_ISSUER {
    if max_batchsize > 0xffff as libc::c_int as size_t {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/trust_token.c\0"
                as *const u8 as *const libc::c_char,
            443 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut TRUST_TOKEN_ISSUER;
    }
    let mut ret: *mut TRUST_TOKEN_ISSUER = OPENSSL_zalloc(
        ::core::mem::size_of::<TRUST_TOKEN_ISSUER>() as libc::c_ulong,
    ) as *mut TRUST_TOKEN_ISSUER;
    if ret.is_null() {
        return 0 as *mut TRUST_TOKEN_ISSUER;
    }
    (*ret).method = method;
    (*ret).max_batchsize = max_batchsize as uint16_t;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_ISSUER_free(mut ctx: *mut TRUST_TOKEN_ISSUER) {
    if ctx.is_null() {
        return;
    }
    EVP_PKEY_free((*ctx).srr_key);
    OPENSSL_free((*ctx).metadata_key as *mut libc::c_void);
    OPENSSL_free(ctx as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_ISSUER_add_key(
    mut ctx: *mut TRUST_TOKEN_ISSUER,
    mut key: *const uint8_t,
    mut key_len: size_t,
) -> libc::c_int {
    if (*ctx).num_keys
        == (::core::mem::size_of::<[trust_token_issuer_key_st; 6]>() as libc::c_ulong)
            .wrapping_div(
                ::core::mem::size_of::<trust_token_issuer_key_st>() as libc::c_ulong,
            ) || (*ctx).num_keys >= (*(*ctx).method).max_keys
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            107 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/trust_token.c\0"
                as *const u8 as *const libc::c_char,
            469 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut key_s: *mut trust_token_issuer_key_st = &mut *((*ctx).keys)
        .as_mut_ptr()
        .offset((*ctx).num_keys as isize) as *mut trust_token_issuer_key_st;
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, key, key_len);
    let mut key_id: uint32_t = 0;
    if CBS_get_u32(&mut cbs, &mut key_id) == 0
        || ((*(*ctx).method).issuer_key_from_bytes)
            .expect(
                "non-null function pointer",
            )(&mut (*key_s).key, CBS_data(&mut cbs), CBS_len(&mut cbs)) == 0
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/trust_token.c\0"
                as *const u8 as *const libc::c_char,
            480 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*key_s).id = key_id;
    (*ctx).num_keys = ((*ctx).num_keys).wrapping_add(1 as libc::c_int as size_t);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_ISSUER_set_srr_key(
    mut ctx: *mut TRUST_TOKEN_ISSUER,
    mut key: *mut EVP_PKEY,
) -> libc::c_int {
    EVP_PKEY_free((*ctx).srr_key);
    EVP_PKEY_up_ref(key);
    (*ctx).srr_key = key;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_ISSUER_set_metadata_key(
    mut ctx: *mut TRUST_TOKEN_ISSUER,
    mut key: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    if len < 32 as libc::c_int as size_t {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            113 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/trust_token.c\0"
                as *const u8 as *const libc::c_char,
            499 as libc::c_int as libc::c_uint,
        );
    }
    OPENSSL_free((*ctx).metadata_key as *mut libc::c_void);
    (*ctx).metadata_key_len = 0 as libc::c_int as size_t;
    (*ctx)
        .metadata_key = OPENSSL_memdup(key as *const libc::c_void, len) as *mut uint8_t;
    if ((*ctx).metadata_key).is_null() {
        return 0 as libc::c_int;
    }
    (*ctx).metadata_key_len = len;
    return 1 as libc::c_int;
}
unsafe extern "C" fn trust_token_issuer_get_key(
    mut ctx: *const TRUST_TOKEN_ISSUER,
    mut key_id: uint32_t,
) -> *const trust_token_issuer_key_st {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < (*ctx).num_keys {
        if (*ctx).keys[i as usize].id == key_id {
            return &*((*ctx).keys).as_ptr().offset(i as isize)
                as *const trust_token_issuer_key_st;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as *const trust_token_issuer_key_st;
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_ISSUER_issue(
    mut ctx: *const TRUST_TOKEN_ISSUER,
    mut out: *mut *mut uint8_t,
    mut out_len: *mut size_t,
    mut out_tokens_issued: *mut size_t,
    mut request: *const uint8_t,
    mut request_len: size_t,
    mut public_metadata: uint32_t,
    mut private_metadata: uint8_t,
    mut max_issuance: size_t,
) -> libc::c_int {
    if max_issuance > (*ctx).max_batchsize as size_t {
        max_issuance = (*ctx).max_batchsize as size_t;
    }
    let mut key: *const trust_token_issuer_key_st = trust_token_issuer_get_key(
        ctx,
        public_metadata,
    );
    if key.is_null() || private_metadata as libc::c_int > 1 as libc::c_int
        || (*(*ctx).method).has_private_metadata == 0
            && private_metadata as libc::c_int != 0 as libc::c_int
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/trust_token.c\0"
                as *const u8 as *const libc::c_char,
            534 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut in_0: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut num_requested: uint16_t = 0;
    CBS_init(&mut in_0, request, request_len);
    if CBS_get_u16(&mut in_0, &mut num_requested) == 0 {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/trust_token.c\0"
                as *const u8 as *const libc::c_char,
            542 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut num_to_issue: size_t = num_requested as size_t;
    if num_to_issue > max_issuance {
        num_to_issue = max_issuance;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut response: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    if !(CBB_init(&mut response, 0 as libc::c_int as size_t) == 0
        || CBB_add_u16(&mut response, num_to_issue as uint16_t) == 0
        || CBB_add_u32(&mut response, public_metadata) == 0)
    {
        if !(((*(*ctx).method).sign)
            .expect(
                "non-null function pointer",
            )(
            &(*key).key,
            &mut response,
            &mut in_0,
            num_requested as size_t,
            num_to_issue,
            private_metadata,
        ) == 0)
        {
            if CBS_len(&mut in_0) != 0 as libc::c_int as size_t {
                ERR_put_error(
                    32 as libc::c_int,
                    0 as libc::c_int,
                    105 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/trust_token.c\0"
                        as *const u8 as *const libc::c_char,
                    565 as libc::c_int as libc::c_uint,
                );
            } else if !(CBB_finish(&mut response, out, out_len) == 0) {
                *out_tokens_issued = num_to_issue;
                ret = 1 as libc::c_int;
            }
        }
    }
    CBB_cleanup(&mut response);
    return ret;
}
unsafe extern "C" fn trust_token_issuer_redeem_impl(
    mut ctx: *const TRUST_TOKEN_ISSUER,
    mut out_public: *mut uint32_t,
    mut out_private: *mut uint8_t,
    mut out_token: *mut *mut TRUST_TOKEN,
    mut out_client_data: *mut *mut uint8_t,
    mut out_client_data_len: *mut size_t,
    mut request: *const uint8_t,
    mut request_len: size_t,
    mut include_message: libc::c_int,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> libc::c_int {
    let mut token: *mut TRUST_TOKEN = 0 as *mut TRUST_TOKEN;
    let mut request_cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut token_cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut request_cbs, request, request_len);
    if CBS_get_u16_length_prefixed(&mut request_cbs, &mut token_cbs) == 0 {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            103 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/trust_token.c\0"
                as *const u8 as *const libc::c_char,
            589 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut public_metadata: uint32_t = 0 as libc::c_int as uint32_t;
    let mut private_metadata: uint8_t = 0 as libc::c_int as uint8_t;
    if CBS_get_u32(&mut token_cbs, &mut public_metadata) == 0 {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            110 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/trust_token.c\0"
                as *const u8 as *const libc::c_char,
            598 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut key: *const trust_token_issuer_key_st = trust_token_issuer_get_key(
        ctx,
        public_metadata,
    );
    let mut nonce: [uint8_t; 64] = [0; 64];
    if key.is_null()
        || ((*(*ctx).method).read)
            .expect(
                "non-null function pointer",
            )(
            &(*key).key,
            nonce.as_mut_ptr(),
            &mut private_metadata,
            CBS_data(&mut token_cbs),
            CBS_len(&mut token_cbs),
            include_message,
            msg,
            msg_len,
        ) == 0
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            110 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/trust_token.c\0"
                as *const u8 as *const libc::c_char,
            609 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut client_data: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_get_u16_length_prefixed(&mut request_cbs, &mut client_data) == 0
        || (*(*ctx).method).has_srr != 0
            && CBS_skip(&mut request_cbs, 8 as libc::c_int as size_t) == 0
        || CBS_len(&mut request_cbs) != 0 as libc::c_int as size_t
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            103 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/trust_token.c\0"
                as *const u8 as *const libc::c_char,
            617 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut client_data_buf: *mut uint8_t = 0 as *mut uint8_t;
    let mut client_data_len: size_t = 0 as libc::c_int as size_t;
    if !(CBS_stow(&mut client_data, &mut client_data_buf, &mut client_data_len) == 0) {
        token = TRUST_TOKEN_new(nonce.as_mut_ptr(), 64 as libc::c_int as size_t);
        if !token.is_null() {
            *out_public = public_metadata;
            *out_private = private_metadata;
            *out_token = token;
            *out_client_data = client_data_buf;
            *out_client_data_len = client_data_len;
            return 1 as libc::c_int;
        }
    }
    OPENSSL_free(client_data_buf as *mut libc::c_void);
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_ISSUER_redeem(
    mut ctx: *const TRUST_TOKEN_ISSUER,
    mut out_public: *mut uint32_t,
    mut out_private: *mut uint8_t,
    mut out_token: *mut *mut TRUST_TOKEN,
    mut out_client_data: *mut *mut uint8_t,
    mut out_client_data_len: *mut size_t,
    mut request: *const uint8_t,
    mut request_len: size_t,
) -> libc::c_int {
    return trust_token_issuer_redeem_impl(
        ctx,
        out_public,
        out_private,
        out_token,
        out_client_data,
        out_client_data_len,
        request,
        request_len,
        0 as libc::c_int,
        0 as *const uint8_t,
        0 as libc::c_int as size_t,
    );
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_ISSUER_redeem_over_message(
    mut ctx: *const TRUST_TOKEN_ISSUER,
    mut out_public: *mut uint32_t,
    mut out_private: *mut uint8_t,
    mut out_token: *mut *mut TRUST_TOKEN,
    mut out_client_data: *mut *mut uint8_t,
    mut out_client_data_len: *mut size_t,
    mut request: *const uint8_t,
    mut request_len: size_t,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> libc::c_int {
    return trust_token_issuer_redeem_impl(
        ctx,
        out_public,
        out_private,
        out_token,
        out_client_data,
        out_client_data_len,
        request,
        request_len,
        1 as libc::c_int,
        msg,
        msg_len,
    );
}
unsafe extern "C" fn get_metadata_obfuscator(
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut client_data: *const uint8_t,
    mut client_data_len: size_t,
) -> uint8_t {
    let mut metadata_obfuscator: [uint8_t; 32] = [0; 32];
    let mut sha_ctx: SHA256_CTX = sha256_state_st {
        h: [0; 8],
        Nl: 0,
        Nh: 0,
        data: [0; 64],
        num: 0,
        md_len: 0,
    };
    SHA256_Init(&mut sha_ctx);
    SHA256_Update(&mut sha_ctx, key as *const libc::c_void, key_len);
    SHA256_Update(&mut sha_ctx, client_data as *const libc::c_void, client_data_len);
    SHA256_Final(metadata_obfuscator.as_mut_ptr(), &mut sha_ctx);
    return (metadata_obfuscator[0 as libc::c_int as usize] as libc::c_int
        >> 7 as libc::c_int) as uint8_t;
}
#[no_mangle]
pub unsafe extern "C" fn TRUST_TOKEN_decode_private_metadata(
    mut method: *const TRUST_TOKEN_METHOD,
    mut out_value: *mut uint8_t,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut nonce: *const uint8_t,
    mut nonce_len: size_t,
    mut encrypted_bit: uint8_t,
) -> libc::c_int {
    let mut metadata_obfuscator: uint8_t = get_metadata_obfuscator(
        key,
        key_len,
        nonce,
        nonce_len,
    );
    *out_value = (encrypted_bit as libc::c_int ^ metadata_obfuscator as libc::c_int)
        as uint8_t;
    return 1 as libc::c_int;
}
