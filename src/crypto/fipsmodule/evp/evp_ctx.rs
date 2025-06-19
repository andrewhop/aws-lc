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
    pub type pqdsa_key_st;
    pub type kem_key_st;
    pub type rsa_st;
    pub type env_md_st;
    fn BN_GENCB_set(
        callback: *mut BN_GENCB,
        f: Option::<
            unsafe extern "C" fn(libc::c_int, libc::c_int, *mut BN_GENCB) -> libc::c_int,
        >,
        arg: *mut libc::c_void,
    );
    fn BN_GENCB_get_arg(callback: *const BN_GENCB) -> *mut libc::c_void;
    fn EVP_get_digestbyname(_: *const libc::c_char) -> *const EVP_MD;
    fn EVP_PKEY_rsa_pkey_meth() -> *const EVP_PKEY_METHOD;
    fn EVP_PKEY_rsa_pss_pkey_meth() -> *const EVP_PKEY_METHOD;
    fn EVP_PKEY_ec_pkey_meth() -> *const EVP_PKEY_METHOD;
    fn EVP_PKEY_hkdf_pkey_meth() -> *const EVP_PKEY_METHOD;
    fn EVP_PKEY_hmac_pkey_meth() -> *const EVP_PKEY_METHOD;
    fn EVP_PKEY_ed25519_pkey_meth() -> *const EVP_PKEY_METHOD;
    fn EVP_PKEY_kem_pkey_meth() -> *const EVP_PKEY_METHOD;
    fn EVP_PKEY_pqdsa_pkey_meth() -> *const EVP_PKEY_METHOD;
    fn EVP_PKEY_ed25519ph_pkey_meth() -> *const EVP_PKEY_METHOD;
    fn EVP_PKEY_new() -> *mut EVP_PKEY;
    fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
    fn EVP_PKEY_up_ref(pkey: *mut EVP_PKEY) -> libc::c_int;
    fn EVP_PKEY_missing_parameters(pkey: *const EVP_PKEY) -> libc::c_int;
    fn EVP_PKEY_cmp_parameters(a: *const EVP_PKEY, b: *const EVP_PKEY) -> libc::c_int;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn ERR_add_error_dataf(format: *const libc::c_char, _: ...);
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn CRYPTO_once(
        once: *mut CRYPTO_once_t,
        init: Option::<unsafe extern "C" fn() -> ()>,
    );
    fn AWSLC_non_fips_pkey_evp_methods() -> *const *const EVP_PKEY_METHOD;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type pthread_once_t = libc::c_int;
pub type CRYPTO_refcount_t = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bn_gencb_st {
    pub type_0: uint8_t,
    pub arg: *mut libc::c_void,
    pub callback: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub new_style: Option::<
        unsafe extern "C" fn(libc::c_int, libc::c_int, *mut bn_gencb_st) -> libc::c_int,
    >,
    pub old_style: Option::<
        unsafe extern "C" fn(libc::c_int, libc::c_int, *mut libc::c_void) -> (),
    >,
}
pub type BN_GENCB = bn_gencb_st;
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
pub type EVP_MD = env_md_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct fips_evp_pkey_methods {
    pub methods: [*const EVP_PKEY_METHOD; 9],
}
pub type CRYPTO_once_t = pthread_once_t;
#[inline]
unsafe extern "C" fn FIPS_service_indicator_lock_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_unlock_state() {}
#[inline]
unsafe extern "C" fn EVP_PKEY_keygen_verify_service_indicator(
    mut pkey: *const EVP_PKEY,
) {}
#[inline]
unsafe extern "C" fn EVP_PKEY_encapsulate_verify_service_indicator(
    mut ctx: *const EVP_PKEY_CTX,
) {}
#[inline]
unsafe extern "C" fn EVP_PKEY_decapsulate_verify_service_indicator(
    mut ctx: *const EVP_PKEY_CTX,
) {}
unsafe extern "C" fn AWSLC_fips_evp_pkey_methods_init() {
    AWSLC_fips_evp_pkey_methods_do_init(AWSLC_fips_evp_pkey_methods_storage_bss_get());
}
static mut AWSLC_fips_evp_pkey_methods_storage: fips_evp_pkey_methods = fips_evp_pkey_methods {
    methods: [0 as *const EVP_PKEY_METHOD; 9],
};
static mut AWSLC_fips_evp_pkey_methods_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn AWSLC_fips_evp_pkey_methods() -> *const fips_evp_pkey_methods {
    CRYPTO_once(
        AWSLC_fips_evp_pkey_methods_once_bss_get(),
        Some(AWSLC_fips_evp_pkey_methods_init as unsafe extern "C" fn() -> ()),
    );
    return AWSLC_fips_evp_pkey_methods_storage_bss_get() as *const fips_evp_pkey_methods;
}
unsafe extern "C" fn AWSLC_fips_evp_pkey_methods_storage_bss_get() -> *mut fips_evp_pkey_methods {
    return &mut AWSLC_fips_evp_pkey_methods_storage;
}
unsafe extern "C" fn AWSLC_fips_evp_pkey_methods_do_init(
    mut out: *mut fips_evp_pkey_methods,
) {
    (*out).methods[0 as libc::c_int as usize] = EVP_PKEY_rsa_pkey_meth();
    (*out).methods[1 as libc::c_int as usize] = EVP_PKEY_rsa_pss_pkey_meth();
    (*out).methods[2 as libc::c_int as usize] = EVP_PKEY_ec_pkey_meth();
    (*out).methods[3 as libc::c_int as usize] = EVP_PKEY_hkdf_pkey_meth();
    (*out).methods[4 as libc::c_int as usize] = EVP_PKEY_hmac_pkey_meth();
    (*out).methods[5 as libc::c_int as usize] = EVP_PKEY_ed25519_pkey_meth();
    (*out).methods[6 as libc::c_int as usize] = EVP_PKEY_kem_pkey_meth();
    (*out).methods[7 as libc::c_int as usize] = EVP_PKEY_pqdsa_pkey_meth();
    (*out).methods[8 as libc::c_int as usize] = EVP_PKEY_ed25519ph_pkey_meth();
}
unsafe extern "C" fn AWSLC_fips_evp_pkey_methods_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut AWSLC_fips_evp_pkey_methods_once;
}
unsafe extern "C" fn evp_pkey_meth_find(
    mut type_0: libc::c_int,
) -> *const EVP_PKEY_METHOD {
    let fips_methods: *const fips_evp_pkey_methods = AWSLC_fips_evp_pkey_methods();
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < 9 as libc::c_int as size_t {
        if (*(*fips_methods).methods[i as usize]).pkey_id == type_0 {
            return (*fips_methods).methods[i as usize];
        }
        i = i.wrapping_add(1);
        i;
    }
    let mut non_fips_methods: *const *const EVP_PKEY_METHOD = AWSLC_non_fips_pkey_evp_methods();
    let mut i_0: size_t = 0 as libc::c_int as size_t;
    while i_0 < 3 as libc::c_int as size_t {
        if (**non_fips_methods.offset(i_0 as isize)).pkey_id == type_0 {
            return *non_fips_methods.offset(i_0 as isize);
        }
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
    return 0 as *const EVP_PKEY_METHOD;
}
unsafe extern "C" fn evp_pkey_ctx_new(
    mut pkey: *mut EVP_PKEY,
    mut e: *mut ENGINE,
    mut id: libc::c_int,
) -> *mut EVP_PKEY_CTX {
    let mut ret: *mut EVP_PKEY_CTX = 0 as *mut EVP_PKEY_CTX;
    let mut pmeth: *const EVP_PKEY_METHOD = 0 as *const EVP_PKEY_METHOD;
    if id == -(1 as libc::c_int) {
        if pkey.is_null() || ((*pkey).ameth).is_null() {
            return 0 as *mut EVP_PKEY_CTX;
        }
        id = (*(*pkey).ameth).pkey_id;
    }
    pmeth = evp_pkey_meth_find(id);
    if pmeth.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            128 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            121 as libc::c_int as libc::c_uint,
        );
        ERR_add_error_dataf(b"algorithm %d\0" as *const u8 as *const libc::c_char, id);
        return 0 as *mut EVP_PKEY_CTX;
    }
    ret = OPENSSL_zalloc(::core::mem::size_of::<EVP_PKEY_CTX>() as libc::c_ulong)
        as *mut EVP_PKEY_CTX;
    if ret.is_null() {
        return 0 as *mut EVP_PKEY_CTX;
    }
    (*ret).engine = e;
    (*ret).pmeth = pmeth;
    (*ret).operation = 0 as libc::c_int;
    if !pkey.is_null() {
        EVP_PKEY_up_ref(pkey);
        (*ret).pkey = pkey;
    }
    if ((*pmeth).init).is_some() {
        if ((*pmeth).init).expect("non-null function pointer")(ret) <= 0 as libc::c_int {
            EVP_PKEY_free((*ret).pkey);
            OPENSSL_free(ret as *mut libc::c_void);
            return 0 as *mut EVP_PKEY_CTX;
        }
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_new(
    mut pkey: *mut EVP_PKEY,
    mut e: *mut ENGINE,
) -> *mut EVP_PKEY_CTX {
    return evp_pkey_ctx_new(pkey, e, -(1 as libc::c_int));
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_new_id(
    mut id: libc::c_int,
    mut e: *mut ENGINE,
) -> *mut EVP_PKEY_CTX {
    return evp_pkey_ctx_new(0 as *mut EVP_PKEY, e, id);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_free(mut ctx: *mut EVP_PKEY_CTX) {
    if ctx.is_null() {
        return;
    }
    if !((*ctx).pmeth).is_null() && ((*(*ctx).pmeth).cleanup).is_some() {
        ((*(*ctx).pmeth).cleanup).expect("non-null function pointer")(ctx);
    }
    EVP_PKEY_free((*ctx).pkey);
    EVP_PKEY_free((*ctx).peerkey);
    OPENSSL_free(ctx as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_dup(
    mut ctx: *mut EVP_PKEY_CTX,
) -> *mut EVP_PKEY_CTX {
    if ((*ctx).pmeth).is_null() || ((*(*ctx).pmeth).copy).is_none() {
        return 0 as *mut EVP_PKEY_CTX;
    }
    let mut ret: *mut EVP_PKEY_CTX = OPENSSL_zalloc(
        ::core::mem::size_of::<EVP_PKEY_CTX>() as libc::c_ulong,
    ) as *mut EVP_PKEY_CTX;
    if ret.is_null() {
        return 0 as *mut EVP_PKEY_CTX;
    }
    (*ret).pmeth = (*ctx).pmeth;
    (*ret).engine = (*ctx).engine;
    (*ret).operation = (*ctx).operation;
    if !((*ctx).pkey).is_null() {
        EVP_PKEY_up_ref((*ctx).pkey);
        (*ret).pkey = (*ctx).pkey;
    }
    if !((*ctx).peerkey).is_null() {
        EVP_PKEY_up_ref((*ctx).peerkey);
        (*ret).peerkey = (*ctx).peerkey;
    }
    if ((*(*ctx).pmeth).copy).expect("non-null function pointer")(ret, ctx)
        <= 0 as libc::c_int
    {
        (*ret).pmeth = 0 as *const EVP_PKEY_METHOD;
        EVP_PKEY_CTX_free(ret);
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            6 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            201 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EVP_PKEY_CTX;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get0_pkey(
    mut ctx: *mut EVP_PKEY_CTX,
) -> *mut EVP_PKEY {
    return (*ctx).pkey;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_ctrl(
    mut ctx: *mut EVP_PKEY_CTX,
    mut keytype: libc::c_int,
    mut optype: libc::c_int,
    mut cmd: libc::c_int,
    mut p1: libc::c_int,
    mut p2: *mut libc::c_void,
) -> libc::c_int {
    if ctx.is_null() || ((*ctx).pmeth).is_null() || ((*(*ctx).pmeth).ctrl).is_none() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            217 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if keytype != -(1 as libc::c_int) && (*(*ctx).pmeth).pkey_id != keytype {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            221 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*ctx).operation == 0 as libc::c_int {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            123 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            226 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if optype != -(1 as libc::c_int) && (*ctx).operation & optype == 0 {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            114 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            231 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ((*(*ctx).pmeth).ctrl).expect("non-null function pointer")(ctx, cmd, p1, p2);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_sign_init(mut ctx: *mut EVP_PKEY_CTX) -> libc::c_int {
    if ctx.is_null() || ((*ctx).pmeth).is_null()
        || ((*(*ctx).pmeth).sign).is_none() && ((*(*ctx).pmeth).sign_message).is_none()
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            242 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*ctx).operation = (1 as libc::c_int) << 3 as libc::c_int;
    if ((*(*ctx).pmeth).sign_init).is_none()
        || ((*(*ctx).pmeth).sign_init).expect("non-null function pointer")(ctx) != 0
    {
        return 1 as libc::c_int;
    }
    (*ctx).operation = 0 as libc::c_int;
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_sign(
    mut ctx: *mut EVP_PKEY_CTX,
    mut sig: *mut uint8_t,
    mut sig_len: *mut size_t,
    mut digest: *const uint8_t,
    mut digest_len: size_t,
) -> libc::c_int {
    if ctx.is_null() || ((*ctx).pmeth).is_null() || ((*(*ctx).pmeth).sign).is_none() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            258 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*ctx).operation != (1 as libc::c_int) << 3 as libc::c_int {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            126 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            262 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ((*(*ctx).pmeth).sign)
        .expect("non-null function pointer")(ctx, sig, sig_len, digest, digest_len);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_verify_init(
    mut ctx: *mut EVP_PKEY_CTX,
) -> libc::c_int {
    if ctx.is_null() || ((*ctx).pmeth).is_null()
        || ((*(*ctx).pmeth).verify).is_none()
            && ((*(*ctx).pmeth).verify_message).is_none()
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            272 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*ctx).operation = (1 as libc::c_int) << 4 as libc::c_int;
    if ((*(*ctx).pmeth).verify_init).is_none()
        || ((*(*ctx).pmeth).verify_init).expect("non-null function pointer")(ctx) != 0
    {
        return 1 as libc::c_int;
    }
    (*ctx).operation = 0 as libc::c_int;
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_verify(
    mut ctx: *mut EVP_PKEY_CTX,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
    mut digest: *const uint8_t,
    mut digest_len: size_t,
) -> libc::c_int {
    if ctx.is_null() || ((*ctx).pmeth).is_null() || ((*(*ctx).pmeth).verify).is_none() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            287 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*ctx).operation != (1 as libc::c_int) << 4 as libc::c_int {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            126 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            291 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ((*(*ctx).pmeth).verify)
        .expect("non-null function pointer")(ctx, sig, sig_len, digest, digest_len);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_encrypt_init(
    mut ctx: *mut EVP_PKEY_CTX,
) -> libc::c_int {
    if ctx.is_null() || ((*ctx).pmeth).is_null() || ((*(*ctx).pmeth).encrypt).is_none() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            299 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*ctx).operation = (1 as libc::c_int) << 6 as libc::c_int;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_encrypt(
    mut ctx: *mut EVP_PKEY_CTX,
    mut out: *mut uint8_t,
    mut outlen: *mut size_t,
    mut in_0: *const uint8_t,
    mut inlen: size_t,
) -> libc::c_int {
    if ctx.is_null() || ((*ctx).pmeth).is_null() || ((*(*ctx).pmeth).encrypt).is_none() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            310 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*ctx).operation != (1 as libc::c_int) << 6 as libc::c_int {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            126 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            314 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ((*(*ctx).pmeth).encrypt)
        .expect("non-null function pointer")(ctx, out, outlen, in_0, inlen);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_decrypt_init(
    mut ctx: *mut EVP_PKEY_CTX,
) -> libc::c_int {
    if ctx.is_null() || ((*ctx).pmeth).is_null() || ((*(*ctx).pmeth).decrypt).is_none() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            323 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*ctx).operation = (1 as libc::c_int) << 7 as libc::c_int;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_decrypt(
    mut ctx: *mut EVP_PKEY_CTX,
    mut out: *mut uint8_t,
    mut outlen: *mut size_t,
    mut in_0: *const uint8_t,
    mut inlen: size_t,
) -> libc::c_int {
    if ctx.is_null() || ((*ctx).pmeth).is_null() || ((*(*ctx).pmeth).decrypt).is_none() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            334 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*ctx).operation != (1 as libc::c_int) << 7 as libc::c_int {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            126 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            338 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ((*(*ctx).pmeth).decrypt)
        .expect("non-null function pointer")(ctx, out, outlen, in_0, inlen);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_verify_recover_init(
    mut ctx: *mut EVP_PKEY_CTX,
) -> libc::c_int {
    if ctx.is_null() || ((*ctx).pmeth).is_null()
        || ((*(*ctx).pmeth).verify_recover).is_none()
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            347 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*ctx).operation = (1 as libc::c_int) << 5 as libc::c_int;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_verify_recover(
    mut ctx: *mut EVP_PKEY_CTX,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
) -> libc::c_int {
    if ctx.is_null() || ((*ctx).pmeth).is_null()
        || ((*(*ctx).pmeth).verify_recover).is_none()
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            358 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*ctx).operation != (1 as libc::c_int) << 5 as libc::c_int {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            126 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            362 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ((*(*ctx).pmeth).verify_recover)
        .expect("non-null function pointer")(ctx, out, out_len, sig, sig_len);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_derive_init(
    mut ctx: *mut EVP_PKEY_CTX,
) -> libc::c_int {
    if ctx.is_null() || ((*ctx).pmeth).is_null() || ((*(*ctx).pmeth).derive).is_none() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            371 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*ctx).operation = (1 as libc::c_int) << 8 as libc::c_int;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_derive_set_peer(
    mut ctx: *mut EVP_PKEY_CTX,
    mut peer: *mut EVP_PKEY,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    if ctx.is_null() || ((*ctx).pmeth).is_null()
        || !(((*(*ctx).pmeth).derive).is_some() || ((*(*ctx).pmeth).encrypt).is_some()
            || ((*(*ctx).pmeth).decrypt).is_some()) || ((*(*ctx).pmeth).ctrl).is_none()
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            384 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*ctx).operation != (1 as libc::c_int) << 8 as libc::c_int
        && (*ctx).operation != (1 as libc::c_int) << 6 as libc::c_int
        && (*ctx).operation != (1 as libc::c_int) << 7 as libc::c_int
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            126 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            390 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    ret = ((*(*ctx).pmeth).ctrl)
        .expect(
            "non-null function pointer",
        )(ctx, 3 as libc::c_int, 0 as libc::c_int, peer as *mut libc::c_void);
    if ret <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if ret == 2 as libc::c_int {
        return 1 as libc::c_int;
    }
    if ((*ctx).pkey).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            120 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            405 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*(*ctx).pkey).type_0 != (*peer).type_0 {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            103 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            410 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if EVP_PKEY_missing_parameters(peer) == 0
        && EVP_PKEY_cmp_parameters((*ctx).pkey, peer) == 0
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            421 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    EVP_PKEY_free((*ctx).peerkey);
    (*ctx).peerkey = peer;
    ret = ((*(*ctx).pmeth).ctrl)
        .expect(
            "non-null function pointer",
        )(ctx, 3 as libc::c_int, 1 as libc::c_int, peer as *mut libc::c_void);
    if ret <= 0 as libc::c_int {
        (*ctx).peerkey = 0 as *mut EVP_PKEY;
        return 0 as libc::c_int;
    }
    EVP_PKEY_up_ref(peer);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_derive(
    mut ctx: *mut EVP_PKEY_CTX,
    mut key: *mut uint8_t,
    mut out_key_len: *mut size_t,
) -> libc::c_int {
    if ctx.is_null() || ((*ctx).pmeth).is_null() || ((*(*ctx).pmeth).derive).is_none() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            442 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*ctx).operation != (1 as libc::c_int) << 8 as libc::c_int {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            126 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            446 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ((*(*ctx).pmeth).derive)
        .expect("non-null function pointer")(ctx, key, out_key_len);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_keygen_init(
    mut ctx: *mut EVP_PKEY_CTX,
) -> libc::c_int {
    if ctx.is_null() || ((*ctx).pmeth).is_null() || ((*(*ctx).pmeth).keygen).is_none() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            455 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*ctx).operation = (1 as libc::c_int) << 2 as libc::c_int;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_keygen_deterministic(
    mut ctx: *mut EVP_PKEY_CTX,
    mut out_pkey: *mut *mut EVP_PKEY,
    mut seed: *const uint8_t,
    mut seed_len: *mut size_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ret: libc::c_int = 0 as libc::c_int;
    if ctx.is_null() || ((*ctx).pmeth).is_null()
        || ((*(*ctx).pmeth).keygen_deterministic).is_none()
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            468 as libc::c_int as libc::c_uint,
        );
    } else if (*ctx).operation != (1 as libc::c_int) << 2 as libc::c_int {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            126 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            472 as libc::c_int as libc::c_uint,
        );
    } else if (out_pkey == 0 as *mut libc::c_void as *mut *mut EVP_PKEY) as libc::c_int
        != (seed == 0 as *mut libc::c_void as *const uint8_t) as libc::c_int
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            133 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            477 as libc::c_int as libc::c_uint,
        );
    } else if out_pkey.is_null() && seed.is_null() {
        if !(((*(*ctx).pmeth).keygen_deterministic)
            .expect(
                "non-null function pointer",
            )(ctx, 0 as *mut EVP_PKEY, 0 as *const uint8_t, seed_len) == 0)
        {
            ret = 1 as libc::c_int;
        }
    } else {
        if (*out_pkey).is_null() {
            *out_pkey = EVP_PKEY_new();
            if (*out_pkey).is_null() {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    6 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                        as *const u8 as *const libc::c_char,
                    493 as libc::c_int as libc::c_uint,
                );
                current_block = 1667238433122401810;
            } else {
                current_block = 10599921512955367680;
            }
        } else {
            current_block = 10599921512955367680;
        }
        match current_block {
            1667238433122401810 => {}
            _ => {
                if ((*(*ctx).pmeth).keygen_deterministic)
                    .expect("non-null function pointer")(ctx, *out_pkey, seed, seed_len)
                    == 0
                {
                    EVP_PKEY_free(*out_pkey);
                    *out_pkey = 0 as *mut EVP_PKEY;
                } else {
                    ret = 1 as libc::c_int;
                }
            }
        }
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_keygen(
    mut ctx: *mut EVP_PKEY_CTX,
    mut out_pkey: *mut *mut EVP_PKEY,
) -> libc::c_int {
    let mut current_block: u64;
    FIPS_service_indicator_lock_state();
    let mut ret: libc::c_int = 0 as libc::c_int;
    if ctx.is_null() || ((*ctx).pmeth).is_null() || ((*(*ctx).pmeth).keygen).is_none() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            516 as libc::c_int as libc::c_uint,
        );
    } else if (*ctx).operation != (1 as libc::c_int) << 2 as libc::c_int {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            126 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            520 as libc::c_int as libc::c_uint,
        );
    } else if !out_pkey.is_null() {
        if (*out_pkey).is_null() {
            *out_pkey = EVP_PKEY_new();
            if (*out_pkey).is_null() {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    6 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                        as *const u8 as *const libc::c_char,
                    531 as libc::c_int as libc::c_uint,
                );
                current_block = 13377030187248248530;
            } else {
                current_block = 11650488183268122163;
            }
        } else {
            current_block = 11650488183268122163;
        }
        match current_block {
            13377030187248248530 => {}
            _ => {
                if ((*(*ctx).pmeth).keygen)
                    .expect("non-null function pointer")(ctx, *out_pkey) == 0
                {
                    EVP_PKEY_free(*out_pkey);
                    *out_pkey = 0 as *mut EVP_PKEY;
                } else {
                    ret = 1 as libc::c_int;
                }
            }
        }
    }
    FIPS_service_indicator_unlock_state();
    if ret != 0 {
        EVP_PKEY_keygen_verify_service_indicator(*out_pkey);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_paramgen_init(
    mut ctx: *mut EVP_PKEY_CTX,
) -> libc::c_int {
    if ctx.is_null() || ((*ctx).pmeth).is_null() || ((*(*ctx).pmeth).paramgen).is_none()
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            554 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*ctx).operation = (1 as libc::c_int) << 9 as libc::c_int;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_paramgen(
    mut ctx: *mut EVP_PKEY_CTX,
    mut out_pkey: *mut *mut EVP_PKEY,
) -> libc::c_int {
    if ctx.is_null() || ((*ctx).pmeth).is_null() || ((*(*ctx).pmeth).paramgen).is_none()
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            564 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*ctx).operation != (1 as libc::c_int) << 9 as libc::c_int {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            126 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            568 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if out_pkey.is_null() {
        return 0 as libc::c_int;
    }
    if (*out_pkey).is_null() {
        *out_pkey = EVP_PKEY_new();
        if (*out_pkey).is_null() {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                6 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                    as *const u8 as *const libc::c_char,
                579 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    }
    if ((*(*ctx).pmeth).paramgen).expect("non-null function pointer")(ctx, *out_pkey)
        == 0
    {
        EVP_PKEY_free(*out_pkey);
        *out_pkey = 0 as *mut EVP_PKEY;
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_encapsulate_deterministic(
    mut ctx: *mut EVP_PKEY_CTX,
    mut ciphertext: *mut uint8_t,
    mut ciphertext_len: *mut size_t,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut seed: *const uint8_t,
    mut seed_len: *mut size_t,
) -> libc::c_int {
    if ctx.is_null() || ((*ctx).pmeth).is_null()
        || ((*(*ctx).pmeth).encapsulate_deterministic).is_none()
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            600 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ((*(*ctx).pmeth).encapsulate_deterministic)
        .expect(
            "non-null function pointer",
        )(
        ctx,
        ciphertext,
        ciphertext_len,
        shared_secret,
        shared_secret_len,
        seed,
        seed_len,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_encapsulate(
    mut ctx: *mut EVP_PKEY_CTX,
    mut ciphertext: *mut uint8_t,
    mut ciphertext_len: *mut size_t,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
) -> libc::c_int {
    FIPS_service_indicator_lock_state();
    let mut ret: libc::c_int = 0 as libc::c_int;
    if ctx.is_null() || ((*ctx).pmeth).is_null()
        || ((*(*ctx).pmeth).encapsulate).is_none()
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            619 as libc::c_int as libc::c_uint,
        );
    } else if !(((*(*ctx).pmeth).encapsulate)
        .expect(
            "non-null function pointer",
        )(ctx, ciphertext, ciphertext_len, shared_secret, shared_secret_len) == 0)
    {
        ret = 1 as libc::c_int;
    }
    FIPS_service_indicator_unlock_state();
    if ret != 0 && !ciphertext.is_null() && !shared_secret.is_null() {
        EVP_PKEY_encapsulate_verify_service_indicator(ctx);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_decapsulate(
    mut ctx: *mut EVP_PKEY_CTX,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut ciphertext: *const uint8_t,
    mut ciphertext_len: size_t,
) -> libc::c_int {
    FIPS_service_indicator_lock_state();
    let mut ret: libc::c_int = 0 as libc::c_int;
    if ctx.is_null() || ((*ctx).pmeth).is_null()
        || ((*(*ctx).pmeth).decapsulate).is_none()
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            646 as libc::c_int as libc::c_uint,
        );
    } else if !(((*(*ctx).pmeth).decapsulate)
        .expect(
            "non-null function pointer",
        )(ctx, shared_secret, shared_secret_len, ciphertext, ciphertext_len) == 0)
    {
        ret = 1 as libc::c_int;
    }
    FIPS_service_indicator_unlock_state();
    if ret != 0 && !shared_secret.is_null() {
        EVP_PKEY_decapsulate_verify_service_indicator(ctx);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_md(
    mut ctx: *mut EVP_PKEY_CTX,
    mut optype: libc::c_int,
    mut cmd: libc::c_int,
    mut md: *const libc::c_char,
) -> libc::c_int {
    let mut m: *const EVP_MD = 0 as *const EVP_MD;
    if md.is_null()
        || {
            m = EVP_get_digestbyname(md);
            m.is_null()
        }
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            111 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            667 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return EVP_PKEY_CTX_ctrl(
        ctx,
        -(1 as libc::c_int),
        optype,
        cmd,
        0 as libc::c_int,
        m as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_ctrl_str(
    mut ctx: *mut EVP_PKEY_CTX,
    mut name: *const libc::c_char,
    mut value: *const libc::c_char,
) -> libc::c_int {
    if ctx.is_null() || ((*ctx).pmeth).is_null() || ((*(*ctx).pmeth).ctrl_str).is_none()
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            676 as libc::c_int as libc::c_uint,
        );
        return -(2 as libc::c_int);
    }
    if strcmp(name, b"digest\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
    {
        return EVP_PKEY_CTX_md(
            ctx,
            (1 as libc::c_int) << 3 as libc::c_int
                | (1 as libc::c_int) << 4 as libc::c_int
                | (1 as libc::c_int) << 5 as libc::c_int,
            1 as libc::c_int,
            value,
        );
    }
    return ((*(*ctx).pmeth).ctrl_str)
        .expect("non-null function pointer")(ctx, name, value);
}
unsafe extern "C" fn trans_cb(
    mut a: libc::c_int,
    mut b: libc::c_int,
    mut gcb: *mut BN_GENCB,
) -> libc::c_int {
    let mut ctx: *mut EVP_PKEY_CTX = BN_GENCB_get_arg(gcb) as *mut EVP_PKEY_CTX;
    (*ctx).keygen_info[0 as libc::c_int as usize] = a;
    (*ctx).keygen_info[1 as libc::c_int as usize] = b;
    return ((*ctx).pkey_gencb).expect("non-null function pointer")(ctx);
}
#[no_mangle]
pub unsafe extern "C" fn evp_pkey_set_cb_translate(
    mut cb: *mut BN_GENCB,
    mut ctx: *mut EVP_PKEY_CTX,
) {
    BN_GENCB_set(
        cb,
        Some(
            trans_cb
                as unsafe extern "C" fn(
                    libc::c_int,
                    libc::c_int,
                    *mut BN_GENCB,
                ) -> libc::c_int,
        ),
        ctx as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_cb(
    mut ctx: *mut EVP_PKEY_CTX,
    mut cb: Option::<EVP_PKEY_gen_cb>,
) {
    if ctx.is_null() {
        return;
    }
    (*ctx).pkey_gencb = cb;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_app_data(
    mut ctx: *mut EVP_PKEY_CTX,
    mut data: *mut libc::c_void,
) {
    if ctx.is_null() {
        return;
    }
    (*ctx).app_data = data;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_app_data(
    mut ctx: *mut EVP_PKEY_CTX,
) -> *mut libc::c_void {
    if ctx.is_null() {
        return 0 as *mut libc::c_void;
    }
    return (*ctx).app_data;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_keygen_info(
    mut ctx: *mut EVP_PKEY_CTX,
    mut idx: libc::c_int,
) -> libc::c_int {
    if ctx.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/evp_ctx.c\0"
                as *const u8 as *const libc::c_char,
            722 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if idx == -(1 as libc::c_int) {
        return 2 as libc::c_int;
    }
    if idx < 0 as libc::c_int || idx >= 2 as libc::c_int
        || (*ctx).operation != (1 as libc::c_int) << 2 as libc::c_int
            && (*ctx).operation != (1 as libc::c_int) << 9 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    return (*ctx).keygen_info[idx as usize];
}
