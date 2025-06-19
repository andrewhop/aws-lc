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
    fn EVP_MD_type(md: *const EVP_MD) -> libc::c_int;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn ED25519ph_sign_digest(
        out_sig: *mut uint8_t,
        digest: *const uint8_t,
        private_key: *const uint8_t,
        context: *const uint8_t,
        context_len: size_t,
    ) -> libc::c_int;
    fn ED25519ph_verify_digest(
        digest: *const uint8_t,
        signature: *const uint8_t,
        public_key: *const uint8_t,
        context: *const uint8_t,
        context_len: size_t,
    ) -> libc::c_int;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn CRYPTO_once(
        once: *mut CRYPTO_once_t,
        init: Option::<unsafe extern "C" fn() -> ()>,
    );
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
pub type EVP_MD = env_md_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_pkey_ctx_signature_context_params_st {
    pub context: *const uint8_t,
    pub context_len: size_t,
}
pub type EVP_PKEY_CTX_SIGNATURE_CONTEXT_PARAMS = evp_pkey_ctx_signature_context_params_st;
pub type CRYPTO_once_t = pthread_once_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ED25519_KEY {
    pub key: [uint8_t; 64],
    pub has_private: libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ED25519PH_PKEY_CTX {
    pub context: [uint8_t; 255],
    pub context_len: size_t,
}
#[inline]
unsafe extern "C" fn OPENSSL_memcpy(
    mut dst: *mut libc::c_void,
    mut src: *const libc::c_void,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return dst;
    }
    return memcpy(dst, src, n);
}
unsafe extern "C" fn pkey_ed25519ph_init(mut ctx: *mut EVP_PKEY_CTX) -> libc::c_int {
    let mut dctx: *mut ED25519PH_PKEY_CTX = OPENSSL_zalloc(
        ::core::mem::size_of::<ED25519PH_PKEY_CTX>() as libc::c_ulong,
    ) as *mut ED25519PH_PKEY_CTX;
    if dctx.is_null() {
        return 0 as libc::c_int;
    }
    (*ctx).data = dctx as *mut libc::c_void;
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_ed25519ph_cleanup(mut ctx: *mut EVP_PKEY_CTX) {
    let mut dctx: *mut ED25519PH_PKEY_CTX = (*ctx).data as *mut ED25519PH_PKEY_CTX;
    if dctx.is_null() {
        return;
    }
    OPENSSL_free(dctx as *mut libc::c_void);
}
unsafe extern "C" fn pkey_ed25519ph_copy(
    mut dst: *mut EVP_PKEY_CTX,
    mut src: *mut EVP_PKEY_CTX,
) -> libc::c_int {
    if pkey_ed25519ph_init(dst) == 0 {
        return 0 as libc::c_int;
    }
    let mut dctx: *mut ED25519PH_PKEY_CTX = (*dst).data as *mut ED25519PH_PKEY_CTX;
    let mut sctx: *mut ED25519PH_PKEY_CTX = (*src).data as *mut ED25519PH_PKEY_CTX;
    if dctx.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_ed25519ph.c\0"
                as *const u8 as *const libc::c_char,
            55 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if sctx.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_ed25519ph.c\0"
                as *const u8 as *const libc::c_char,
            56 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    OPENSSL_memcpy(
        ((*dctx).context).as_mut_ptr() as *mut libc::c_void,
        ((*sctx).context).as_mut_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint8_t; 255]>() as libc::c_ulong,
    );
    (*dctx).context_len = (*sctx).context_len;
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_ed25519ph_sign(
    mut ctx: *mut EVP_PKEY_CTX,
    mut sig: *mut uint8_t,
    mut siglen: *mut size_t,
    mut tbs: *const uint8_t,
    mut tbslen: size_t,
) -> libc::c_int {
    let mut key: *mut ED25519_KEY = (*(*ctx).pkey).pkey.ptr as *mut ED25519_KEY;
    if (*key).has_private == 0 {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            130 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_ed25519ph.c\0"
                as *const u8 as *const libc::c_char,
            68 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if sig.is_null() {
        *siglen = 64 as libc::c_int as size_t;
        return 1 as libc::c_int;
    }
    if *siglen < 64 as libc::c_int as size_t {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_ed25519ph.c\0"
                as *const u8 as *const libc::c_char,
            78 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if tbslen < 64 as libc::c_int as size_t {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_ed25519ph.c\0"
                as *const u8 as *const libc::c_char,
            83 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut dctx: *mut ED25519PH_PKEY_CTX = (*ctx).data as *mut ED25519PH_PKEY_CTX;
    if dctx.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_ed25519ph.c\0"
                as *const u8 as *const libc::c_char,
            88 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ED25519ph_sign_digest(
        sig,
        tbs,
        ((*key).key).as_mut_ptr() as *const uint8_t,
        ((*dctx).context).as_mut_ptr(),
        (*dctx).context_len,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    *siglen = 64 as libc::c_int as size_t;
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_ed25519ph_verify(
    mut ctx: *mut EVP_PKEY_CTX,
    mut sig: *const uint8_t,
    mut siglen: size_t,
    mut tbs: *const uint8_t,
    mut tbslen: size_t,
) -> libc::c_int {
    let mut key: *mut ED25519_KEY = (*(*ctx).pkey).pkey.ptr as *mut ED25519_KEY;
    let mut dctx: *mut ED25519PH_PKEY_CTX = (*ctx).data as *mut ED25519PH_PKEY_CTX;
    if dctx.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_ed25519ph.c\0"
                as *const u8 as *const libc::c_char,
            104 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if siglen != 64 as libc::c_int as size_t || tbslen < 64 as libc::c_int as size_t
        || ED25519ph_verify_digest(
            tbs,
            sig,
            ((*key).key).as_mut_ptr().offset(32 as libc::c_int as isize)
                as *const uint8_t,
            ((*dctx).context).as_mut_ptr(),
            (*dctx).context_len,
        ) == 0
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            131 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_ed25519ph.c\0"
                as *const u8 as *const libc::c_char,
            109 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_ed25519ph_ctrl(
    mut ctx: *mut EVP_PKEY_CTX,
    mut type_0: libc::c_int,
    mut p1: libc::c_int,
    mut p2: *mut libc::c_void,
) -> libc::c_int {
    if ctx.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_ed25519ph.c\0"
                as *const u8 as *const libc::c_char,
            117 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut dctx: *mut ED25519PH_PKEY_CTX = (*ctx).data as *mut ED25519PH_PKEY_CTX;
    match type_0 {
        1 => {
            let mut md: *const EVP_MD = p2 as *const EVP_MD;
            let mut md_type: libc::c_int = EVP_MD_type(md);
            if md_type != 674 as libc::c_int {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    101 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_ed25519ph.c\0"
                        as *const u8 as *const libc::c_char,
                    125 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
        }
        3 => {
            let mut params: *mut EVP_PKEY_CTX_SIGNATURE_CONTEXT_PARAMS = p2
                as *mut EVP_PKEY_CTX_SIGNATURE_CONTEXT_PARAMS;
            if params.is_null() || dctx.is_null()
                || (*params).context_len
                    > ::core::mem::size_of::<[uint8_t; 255]>() as libc::c_ulong
            {
                return 0 as libc::c_int;
            }
            OPENSSL_memcpy(
                ((*dctx).context).as_mut_ptr() as *mut libc::c_void,
                (*params).context as *const libc::c_void,
                (*params).context_len,
            );
            (*dctx).context_len = (*params).context_len;
        }
        4 => {
            let mut params_0: *mut EVP_PKEY_CTX_SIGNATURE_CONTEXT_PARAMS = p2
                as *mut EVP_PKEY_CTX_SIGNATURE_CONTEXT_PARAMS;
            if params_0.is_null() || dctx.is_null() {
                return 0 as libc::c_int;
            }
            if (*dctx).context_len == 0 as libc::c_int as size_t {
                (*params_0).context = 0 as *const uint8_t;
                (*params_0).context_len = 0 as libc::c_int as size_t;
            } else {
                (*params_0).context = ((*dctx).context).as_mut_ptr();
                (*params_0).context_len = (*dctx).context_len;
            }
            return 1 as libc::c_int;
        }
        _ => {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                101 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_ed25519ph.c\0"
                    as *const u8 as *const libc::c_char,
                154 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_ed25519ph_pkey_meth() -> *const EVP_PKEY_METHOD {
    CRYPTO_once(
        EVP_PKEY_ed25519ph_pkey_meth_once_bss_get(),
        Some(EVP_PKEY_ed25519ph_pkey_meth_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_PKEY_ed25519ph_pkey_meth_storage_bss_get() as *const EVP_PKEY_METHOD;
}
unsafe extern "C" fn EVP_PKEY_ed25519ph_pkey_meth_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_PKEY_ed25519ph_pkey_meth_once;
}
static mut EVP_PKEY_ed25519ph_pkey_meth_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EVP_PKEY_ed25519ph_pkey_meth_storage_bss_get() -> *mut EVP_PKEY_METHOD {
    return &mut EVP_PKEY_ed25519ph_pkey_meth_storage;
}
static mut EVP_PKEY_ed25519ph_pkey_meth_storage: EVP_PKEY_METHOD = evp_pkey_method_st {
    pkey_id: 0,
    init: None,
    copy: None,
    cleanup: None,
    keygen: None,
    sign_init: None,
    sign: None,
    sign_message: None,
    verify_init: None,
    verify: None,
    verify_message: None,
    verify_recover: None,
    encrypt: None,
    decrypt: None,
    derive: None,
    paramgen: None,
    ctrl: None,
    ctrl_str: None,
    keygen_deterministic: None,
    encapsulate_deterministic: None,
    encapsulate: None,
    decapsulate: None,
};
unsafe extern "C" fn EVP_PKEY_ed25519ph_pkey_meth_do_init(
    mut out: *mut EVP_PKEY_METHOD,
) {
    (*out).pkey_id = 997 as libc::c_int;
    (*out)
        .init = Some(
        pkey_ed25519ph_init as unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> libc::c_int,
    );
    (*out)
        .copy = Some(
        pkey_ed25519ph_copy
            as unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY_CTX) -> libc::c_int,
    );
    (*out)
        .cleanup = Some(
        pkey_ed25519ph_cleanup as unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> (),
    );
    (*out).keygen = None;
    (*out).sign_init = None;
    (*out)
        .sign = Some(
        pkey_ed25519ph_sign
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out).verify_init = None;
    (*out)
        .verify = Some(
        pkey_ed25519ph_verify
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *const uint8_t,
                size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out).verify_message = None;
    (*out).verify_recover = None;
    (*out).encrypt = None;
    (*out).decrypt = None;
    (*out).derive = None;
    (*out).paramgen = None;
    (*out)
        .ctrl = Some(
        pkey_ed25519ph_ctrl
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                libc::c_int,
                libc::c_int,
                *mut libc::c_void,
            ) -> libc::c_int,
    );
    (*out).ctrl_str = None;
    (*out).keygen_deterministic = None;
    (*out).encapsulate_deterministic = None;
    (*out).encapsulate = None;
    (*out).decapsulate = None;
}
unsafe extern "C" fn EVP_PKEY_ed25519ph_pkey_meth_init() {
    EVP_PKEY_ed25519ph_pkey_meth_do_init(EVP_PKEY_ed25519ph_pkey_meth_storage_bss_get());
}
