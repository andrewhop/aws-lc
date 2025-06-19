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
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_stow(
        cbs: *const CBS,
        out_ptr: *mut *mut uint8_t,
        out_len: *mut size_t,
    ) -> libc::c_int;
    fn CBB_init(cbb: *mut CBB, initial_capacity: size_t) -> libc::c_int;
    fn CBB_cleanup(cbb: *mut CBB);
    fn CBB_data(cbb: *const CBB) -> *const uint8_t;
    fn CBB_len(cbb: *const CBB) -> size_t;
    fn CBB_add_bytes(cbb: *mut CBB, data: *const uint8_t, len: size_t) -> libc::c_int;
    fn EVP_MD_size(md: *const EVP_MD) -> size_t;
    fn EVP_PKEY_CTX_ctrl(
        ctx: *mut EVP_PKEY_CTX,
        keytype: libc::c_int,
        optype: libc::c_int,
        cmd: libc::c_int,
        p1: libc::c_int,
        p2: *mut libc::c_void,
    ) -> libc::c_int;
    fn EVP_PKEY_CTX_md(
        ctx: *mut EVP_PKEY_CTX,
        optype: libc::c_int,
        cmd: libc::c_int,
        md: *const libc::c_char,
    ) -> libc::c_int;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_strnlen(s: *const libc::c_char, len: size_t) -> size_t;
    fn OPENSSL_hexstr2buf(str: *const libc::c_char, len: *mut size_t) -> *mut uint8_t;
    fn OPENSSL_memdup(data: *const libc::c_void, size: size_t) -> *mut libc::c_void;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn HKDF(
        out_key: *mut uint8_t,
        out_len: size_t,
        digest: *const EVP_MD,
        secret: *const uint8_t,
        secret_len: size_t,
        salt: *const uint8_t,
        salt_len: size_t,
        info: *const uint8_t,
        info_len: size_t,
    ) -> libc::c_int;
    fn HKDF_extract(
        out_key: *mut uint8_t,
        out_len: *mut size_t,
        digest: *const EVP_MD,
        secret: *const uint8_t,
        secret_len: size_t,
        salt: *const uint8_t,
        salt_len: size_t,
    ) -> libc::c_int;
    fn HKDF_expand(
        out_key: *mut uint8_t,
        out_len: size_t,
        digest: *const EVP_MD,
        prk: *const uint8_t,
        prk_len: size_t,
        info: *const uint8_t,
        info_len: size_t,
    ) -> libc::c_int;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
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
pub type CRYPTO_once_t = pthread_once_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct HKDF_PKEY_CTX {
    pub mode: libc::c_int,
    pub md: *const EVP_MD,
    pub key: *mut uint8_t,
    pub key_len: size_t,
    pub salt: *mut uint8_t,
    pub salt_len: size_t,
    pub info: CBB,
}
unsafe extern "C" fn pkey_hkdf_init(mut ctx: *mut EVP_PKEY_CTX) -> libc::c_int {
    let mut hctx: *mut HKDF_PKEY_CTX = OPENSSL_zalloc(
        ::core::mem::size_of::<HKDF_PKEY_CTX>() as libc::c_ulong,
    ) as *mut HKDF_PKEY_CTX;
    if hctx.is_null() {
        return 0 as libc::c_int;
    }
    if CBB_init(&mut (*hctx).info, 0 as libc::c_int as size_t) == 0 {
        OPENSSL_free(hctx as *mut libc::c_void);
        return 0 as libc::c_int;
    }
    (*ctx).data = hctx as *mut libc::c_void;
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_hkdf_copy(
    mut dst: *mut EVP_PKEY_CTX,
    mut src: *mut EVP_PKEY_CTX,
) -> libc::c_int {
    if pkey_hkdf_init(dst) == 0 {
        return 0 as libc::c_int;
    }
    let mut hctx_dst: *mut HKDF_PKEY_CTX = (*dst).data as *mut HKDF_PKEY_CTX;
    let mut hctx_src: *const HKDF_PKEY_CTX = (*src).data as *const HKDF_PKEY_CTX;
    (*hctx_dst).mode = (*hctx_src).mode;
    (*hctx_dst).md = (*hctx_src).md;
    if (*hctx_src).key_len != 0 as libc::c_int as size_t {
        (*hctx_dst)
            .key = OPENSSL_memdup(
            (*hctx_src).key as *const libc::c_void,
            (*hctx_src).key_len,
        ) as *mut uint8_t;
        if ((*hctx_dst).key).is_null() {
            return 0 as libc::c_int;
        }
        (*hctx_dst).key_len = (*hctx_src).key_len;
    }
    if (*hctx_src).salt_len != 0 as libc::c_int as size_t {
        (*hctx_dst)
            .salt = OPENSSL_memdup(
            (*hctx_src).salt as *const libc::c_void,
            (*hctx_src).salt_len,
        ) as *mut uint8_t;
        if ((*hctx_dst).salt).is_null() {
            return 0 as libc::c_int;
        }
        (*hctx_dst).salt_len = (*hctx_src).salt_len;
    }
    if CBB_add_bytes(
        &mut (*hctx_dst).info,
        CBB_data(&(*hctx_src).info),
        CBB_len(&(*hctx_src).info),
    ) == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_hkdf_cleanup(mut ctx: *mut EVP_PKEY_CTX) {
    let mut hctx: *mut HKDF_PKEY_CTX = (*ctx).data as *mut HKDF_PKEY_CTX;
    if !hctx.is_null() {
        OPENSSL_free((*hctx).key as *mut libc::c_void);
        OPENSSL_free((*hctx).salt as *mut libc::c_void);
        CBB_cleanup(&mut (*hctx).info);
        OPENSSL_free(hctx as *mut libc::c_void);
        (*ctx).data = 0 as *mut libc::c_void;
    }
}
#[no_mangle]
pub unsafe extern "C" fn pkey_hkdf_derive(
    mut ctx: *mut EVP_PKEY_CTX,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
) -> libc::c_int {
    let mut hctx: *mut HKDF_PKEY_CTX = (*ctx).data as *mut HKDF_PKEY_CTX;
    if ((*hctx).md).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            118 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_hkdf.c\0"
                as *const u8 as *const libc::c_char,
            103 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*hctx).key_len == 0 as libc::c_int as size_t {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            120 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_hkdf.c\0"
                as *const u8 as *const libc::c_char,
            107 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if out.is_null() {
        if (*hctx).mode == 1 as libc::c_int {
            *out_len = EVP_MD_size((*hctx).md);
        }
        return 1 as libc::c_int;
    }
    match (*hctx).mode {
        0 => {
            return HKDF(
                out,
                *out_len,
                (*hctx).md,
                (*hctx).key,
                (*hctx).key_len,
                (*hctx).salt,
                (*hctx).salt_len,
                CBB_data(&mut (*hctx).info),
                CBB_len(&mut (*hctx).info),
            );
        }
        1 => {
            if *out_len < EVP_MD_size((*hctx).md) {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    100 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_hkdf.c\0"
                        as *const u8 as *const libc::c_char,
                    127 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            return HKDF_extract(
                out,
                out_len,
                (*hctx).md,
                (*hctx).key,
                (*hctx).key_len,
                (*hctx).salt,
                (*hctx).salt_len,
            );
        }
        2 => {
            return HKDF_expand(
                out,
                *out_len,
                (*hctx).md,
                (*hctx).key,
                (*hctx).key_len,
                CBB_data(&mut (*hctx).info),
                CBB_len(&mut (*hctx).info),
            );
        }
        _ => {}
    }
    ERR_put_error(
        6 as libc::c_int,
        0 as libc::c_int,
        4 as libc::c_int | 64 as libc::c_int,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_hkdf.c\0"
            as *const u8 as *const libc::c_char,
        137 as libc::c_int as libc::c_uint,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn pkey_hkdf_ctrl(
    mut ctx: *mut EVP_PKEY_CTX,
    mut type_0: libc::c_int,
    mut p1: libc::c_int,
    mut p2: *mut libc::c_void,
) -> libc::c_int {
    let mut hctx: *mut HKDF_PKEY_CTX = (*ctx).data as *mut HKDF_PKEY_CTX;
    match type_0 {
        4110 => {
            if p1 != 0 as libc::c_int && p1 != 1 as libc::c_int && p1 != 2 as libc::c_int
            {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    114 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_hkdf.c\0"
                        as *const u8 as *const libc::c_char,
                    148 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            (*hctx).mode = p1;
            return 1 as libc::c_int;
        }
        4111 => {
            (*hctx).md = p2 as *const EVP_MD;
            return 1 as libc::c_int;
        }
        4112 => {
            let mut key: *const CBS = p2 as *const CBS;
            if CBS_stow(key, &mut (*hctx).key, &mut (*hctx).key_len) == 0 {
                return 0 as libc::c_int;
            }
            return 1 as libc::c_int;
        }
        4113 => {
            let mut salt: *const CBS = p2 as *const CBS;
            if CBS_stow(salt, &mut (*hctx).salt, &mut (*hctx).salt_len) == 0 {
                return 0 as libc::c_int;
            }
            return 1 as libc::c_int;
        }
        4114 => {
            let mut info: *const CBS = p2 as *const CBS;
            if CBB_add_bytes(&mut (*hctx).info, CBS_data(info), CBS_len(info)) == 0 {
                return 0 as libc::c_int;
            }
            return 1 as libc::c_int;
        }
        _ => {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                101 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_hkdf.c\0"
                    as *const u8 as *const libc::c_char,
                180 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    };
}
unsafe extern "C" fn pkey_hkdf_ctrl_str(
    mut ctx: *mut EVP_PKEY_CTX,
    mut type_0: *const libc::c_char,
    mut value: *const libc::c_char,
) -> libc::c_int {
    if strcmp(type_0, b"mode\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
    {
        let mut mode: libc::c_int = 0;
        if strcmp(value, b"EXTRACT_AND_EXPAND\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            mode = 0 as libc::c_int;
        } else if strcmp(value, b"EXTRACT_ONLY\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            mode = 1 as libc::c_int;
        } else if strcmp(value, b"EXPAND_ONLY\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            mode = 2 as libc::c_int;
        } else {
            return 0 as libc::c_int
        }
        return EVP_PKEY_CTX_hkdf_mode(ctx, mode);
    }
    if strcmp(type_0, b"md\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        return EVP_PKEY_CTX_md(
            ctx,
            (1 as libc::c_int) << 8 as libc::c_int,
            0x1000 as libc::c_int + 15 as libc::c_int,
            value,
        );
    }
    if strcmp(type_0, b"salt\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
    {
        let saltlen: size_t = OPENSSL_strnlen(value, 32767 as libc::c_int as size_t);
        return EVP_PKEY_CTX_set1_hkdf_salt(ctx, value as *const uint8_t, saltlen);
    }
    if strcmp(type_0, b"hexsalt\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        let mut hex_saltlen: size_t = 0 as libc::c_int as size_t;
        let mut salt: *mut uint8_t = OPENSSL_hexstr2buf(value, &mut hex_saltlen);
        if salt.is_null() {
            return 0 as libc::c_int;
        }
        let mut result: libc::c_int = EVP_PKEY_CTX_set1_hkdf_salt(
            ctx,
            salt,
            hex_saltlen,
        );
        OPENSSL_free(salt as *mut libc::c_void);
        return result;
    }
    if strcmp(type_0, b"key\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        let keylen: size_t = OPENSSL_strnlen(value, 32767 as libc::c_int as size_t);
        return EVP_PKEY_CTX_set1_hkdf_key(ctx, value as *const uint8_t, keylen);
    }
    if strcmp(type_0, b"hexkey\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        let mut hex_keylen: size_t = 0 as libc::c_int as size_t;
        let mut key: *mut uint8_t = OPENSSL_hexstr2buf(value, &mut hex_keylen);
        if key.is_null() {
            return 0 as libc::c_int;
        }
        let mut result_0: libc::c_int = EVP_PKEY_CTX_set1_hkdf_key(ctx, key, hex_keylen);
        OPENSSL_free(key as *mut libc::c_void);
        return result_0;
    }
    if strcmp(type_0, b"info\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
    {
        let infolen: size_t = OPENSSL_strnlen(value, 32767 as libc::c_int as size_t);
        return EVP_PKEY_CTX_add1_hkdf_info(ctx, value as *const uint8_t, infolen);
    }
    if strcmp(type_0, b"hexinfo\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        let mut hex_infolen: size_t = 0 as libc::c_int as size_t;
        let mut info: *mut uint8_t = OPENSSL_hexstr2buf(value, &mut hex_infolen);
        if info.is_null() {
            return 0 as libc::c_int;
        }
        let mut result_1: libc::c_int = EVP_PKEY_CTX_add1_hkdf_info(
            ctx,
            info,
            hex_infolen,
        );
        OPENSSL_free(info as *mut libc::c_void);
        return result_1;
    }
    return -(2 as libc::c_int);
}
unsafe extern "C" fn EVP_PKEY_hkdf_pkey_meth_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_PKEY_hkdf_pkey_meth_once;
}
static mut EVP_PKEY_hkdf_pkey_meth_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EVP_PKEY_hkdf_pkey_meth_storage_bss_get() -> *mut EVP_PKEY_METHOD {
    return &mut EVP_PKEY_hkdf_pkey_meth_storage;
}
static mut EVP_PKEY_hkdf_pkey_meth_storage: EVP_PKEY_METHOD = evp_pkey_method_st {
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
unsafe extern "C" fn EVP_PKEY_hkdf_pkey_meth_init() {
    EVP_PKEY_hkdf_pkey_meth_do_init(EVP_PKEY_hkdf_pkey_meth_storage_bss_get());
}
unsafe extern "C" fn EVP_PKEY_hkdf_pkey_meth_do_init(mut out: *mut EVP_PKEY_METHOD) {
    (*out).pkey_id = 969 as libc::c_int;
    (*out)
        .init = Some(
        pkey_hkdf_init as unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> libc::c_int,
    );
    (*out)
        .copy = Some(
        pkey_hkdf_copy
            as unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY_CTX) -> libc::c_int,
    );
    (*out)
        .cleanup = Some(
        pkey_hkdf_cleanup as unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> (),
    );
    (*out).keygen = None;
    (*out).sign_init = None;
    (*out).sign = None;
    (*out).sign_message = None;
    (*out).verify_init = None;
    (*out).verify = None;
    (*out).verify_message = None;
    (*out).verify_recover = None;
    (*out).encrypt = None;
    (*out).decrypt = None;
    (*out)
        .derive = Some(
        pkey_hkdf_derive
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *mut uint8_t,
                *mut size_t,
            ) -> libc::c_int,
    );
    (*out).paramgen = None;
    (*out)
        .ctrl = Some(
        pkey_hkdf_ctrl
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                libc::c_int,
                libc::c_int,
                *mut libc::c_void,
            ) -> libc::c_int,
    );
    (*out)
        .ctrl_str = Some(
        pkey_hkdf_ctrl_str
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *const libc::c_char,
                *const libc::c_char,
            ) -> libc::c_int,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_hkdf_pkey_meth() -> *const EVP_PKEY_METHOD {
    CRYPTO_once(
        EVP_PKEY_hkdf_pkey_meth_once_bss_get(),
        Some(EVP_PKEY_hkdf_pkey_meth_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_PKEY_hkdf_pkey_meth_storage_bss_get() as *const EVP_PKEY_METHOD;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_hkdf_mode(
    mut ctx: *mut EVP_PKEY_CTX,
    mut mode: libc::c_int,
) -> libc::c_int {
    return EVP_PKEY_CTX_ctrl(
        ctx,
        969 as libc::c_int,
        (1 as libc::c_int) << 8 as libc::c_int,
        0x1000 as libc::c_int + 14 as libc::c_int,
        mode,
        0 as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_hkdf_md(
    mut ctx: *mut EVP_PKEY_CTX,
    mut md: *const EVP_MD,
) -> libc::c_int {
    return EVP_PKEY_CTX_ctrl(
        ctx,
        969 as libc::c_int,
        (1 as libc::c_int) << 8 as libc::c_int,
        0x1000 as libc::c_int + 15 as libc::c_int,
        0 as libc::c_int,
        md as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set1_hkdf_key(
    mut ctx: *mut EVP_PKEY_CTX,
    mut key: *const uint8_t,
    mut key_len: size_t,
) -> libc::c_int {
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, key, key_len);
    return EVP_PKEY_CTX_ctrl(
        ctx,
        969 as libc::c_int,
        (1 as libc::c_int) << 8 as libc::c_int,
        0x1000 as libc::c_int + 16 as libc::c_int,
        0 as libc::c_int,
        &mut cbs as *mut CBS as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set1_hkdf_salt(
    mut ctx: *mut EVP_PKEY_CTX,
    mut salt: *const uint8_t,
    mut salt_len: size_t,
) -> libc::c_int {
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, salt, salt_len);
    return EVP_PKEY_CTX_ctrl(
        ctx,
        969 as libc::c_int,
        (1 as libc::c_int) << 8 as libc::c_int,
        0x1000 as libc::c_int + 17 as libc::c_int,
        0 as libc::c_int,
        &mut cbs as *mut CBS as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_add1_hkdf_info(
    mut ctx: *mut EVP_PKEY_CTX,
    mut info: *const uint8_t,
    mut info_len: size_t,
) -> libc::c_int {
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, info, info_len);
    return EVP_PKEY_CTX_ctrl(
        ctx,
        969 as libc::c_int,
        (1 as libc::c_int) << 8 as libc::c_int,
        0x1000 as libc::c_int + 18 as libc::c_int,
        0 as libc::c_int,
        &mut cbs as *mut CBS as *mut libc::c_void,
    );
}
