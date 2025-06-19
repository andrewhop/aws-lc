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
    pub type dh_st;
    pub type dsa_st;
    pub type ec_key_st;
    pub type engine_st;
    pub type pqdsa_key_st;
    pub type kem_key_st;
    pub type rsa_st;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strtol(
        _: *const libc::c_char,
        _: *mut *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_long;
    fn BN_GENCB_new() -> *mut BN_GENCB;
    fn BN_GENCB_free(callback: *mut BN_GENCB);
    fn EVP_PKEY_CTX_ctrl(
        ctx: *mut EVP_PKEY_CTX,
        keytype: libc::c_int,
        optype: libc::c_int,
        cmd: libc::c_int,
        p1: libc::c_int,
        p2: *mut libc::c_void,
    ) -> libc::c_int;
    fn evp_pkey_set_cb_translate(cb: *mut BN_GENCB, ctx: *mut EVP_PKEY_CTX);
    fn EVP_PKEY_copy_parameters(to: *mut EVP_PKEY, from: *const EVP_PKEY) -> libc::c_int;
    fn EVP_PKEY_assign_DH(pkey: *mut EVP_PKEY, key: *mut DH) -> libc::c_int;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn DH_new() -> *mut DH;
    fn DH_free(dh: *mut DH);
    fn DH_get0_pub_key(dh: *const DH) -> *const BIGNUM;
    fn DH_generate_parameters_ex(
        dh: *mut DH,
        prime_bits: libc::c_int,
        generator: libc::c_int,
        cb: *mut BN_GENCB,
    ) -> libc::c_int;
    fn DH_generate_key(dh: *mut DH) -> libc::c_int;
    fn DH_compute_key_padded(
        out: *mut uint8_t,
        peers_key: *const BIGNUM,
        dh: *mut DH,
    ) -> libc::c_int;
    fn DH_size(dh: *const DH) -> libc::c_int;
    fn DH_compute_key(
        out: *mut uint8_t,
        peers_key: *const BIGNUM,
        dh: *mut DH,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bignum_st {
    pub d: *mut BN_ULONG,
    pub width: libc::c_int,
    pub dmax: libc::c_int,
    pub neg: libc::c_int,
    pub flags: libc::c_int,
}
pub type BN_ULONG = uint64_t;
pub type BIGNUM = bignum_st;
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
pub type DH_PKEY_CTX = dh_pkey_ctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dh_pkey_ctx_st {
    pub pad: libc::c_int,
    pub prime_len: libc::c_int,
    pub generator: libc::c_int,
}
unsafe extern "C" fn pkey_dh_init(mut ctx: *mut EVP_PKEY_CTX) -> libc::c_int {
    let mut dctx: *mut DH_PKEY_CTX = OPENSSL_zalloc(
        ::core::mem::size_of::<DH_PKEY_CTX>() as libc::c_ulong,
    ) as *mut DH_PKEY_CTX;
    if dctx.is_null() {
        return 0 as libc::c_int;
    }
    (*dctx).prime_len = 2048 as libc::c_int;
    (*dctx).generator = 2 as libc::c_int;
    (*ctx).data = dctx as *mut libc::c_void;
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_dh_copy(
    mut dst: *mut EVP_PKEY_CTX,
    mut src: *mut EVP_PKEY_CTX,
) -> libc::c_int {
    if pkey_dh_init(dst) == 0 {
        return 0 as libc::c_int;
    }
    let mut sctx: *const DH_PKEY_CTX = (*src).data as *const DH_PKEY_CTX;
    let mut dctx: *mut DH_PKEY_CTX = (*dst).data as *mut DH_PKEY_CTX;
    (*dctx).pad = (*sctx).pad;
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_dh_cleanup(mut ctx: *mut EVP_PKEY_CTX) {
    OPENSSL_free((*ctx).data);
    (*ctx).data = 0 as *mut libc::c_void;
}
unsafe extern "C" fn pkey_dh_keygen(
    mut ctx: *mut EVP_PKEY_CTX,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    let mut dh: *mut DH = DH_new();
    if dh.is_null() || EVP_PKEY_assign_DH(pkey, dh) == 0 {
        DH_free(dh);
        return 0 as libc::c_int;
    }
    if !((*ctx).pkey).is_null() && EVP_PKEY_copy_parameters(pkey, (*ctx).pkey) == 0 {
        return 0 as libc::c_int;
    }
    return DH_generate_key(dh);
}
unsafe extern "C" fn pkey_dh_derive(
    mut ctx: *mut EVP_PKEY_CTX,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
) -> libc::c_int {
    let mut dctx: *mut DH_PKEY_CTX = (*ctx).data as *mut DH_PKEY_CTX;
    if ((*ctx).pkey).is_null() || ((*ctx).peerkey).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            117 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dh.c\0" as *const u8
                as *const libc::c_char,
            75 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut our_key: *mut DH = (*(*ctx).pkey).pkey.dh;
    let mut peer_key: *mut DH = (*(*ctx).peerkey).pkey.dh;
    if our_key.is_null() || peer_key.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            117 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dh.c\0" as *const u8
                as *const libc::c_char,
            82 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut pub_key: *const BIGNUM = DH_get0_pub_key(peer_key);
    if pub_key.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            117 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dh.c\0" as *const u8
                as *const libc::c_char,
            88 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if out.is_null() {
        *out_len = DH_size(our_key) as size_t;
        return 1 as libc::c_int;
    }
    if *out_len < DH_size(our_key) as size_t {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dh.c\0" as *const u8
                as *const libc::c_char,
            98 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = if (*dctx).pad != 0 {
        DH_compute_key_padded(out, pub_key, our_key)
    } else {
        DH_compute_key(out, pub_key, our_key)
    };
    if ret < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if ret <= DH_size(our_key) {} else {
        __assert_fail(
            b"ret <= DH_size(our_key)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dh.c\0" as *const u8
                as *const libc::c_char,
            108 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 56],
                &[libc::c_char; 56],
            >(b"int pkey_dh_derive(EVP_PKEY_CTX *, uint8_t *, size_t *)\0"))
                .as_ptr(),
        );
    }
    'c_12472: {
        if ret <= DH_size(our_key) {} else {
            __assert_fail(
                b"ret <= DH_size(our_key)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dh.c\0"
                    as *const u8 as *const libc::c_char,
                108 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 56],
                    &[libc::c_char; 56],
                >(b"int pkey_dh_derive(EVP_PKEY_CTX *, uint8_t *, size_t *)\0"))
                    .as_ptr(),
            );
        }
    };
    *out_len = ret as size_t;
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_dh_ctrl(
    mut ctx: *mut EVP_PKEY_CTX,
    mut type_0: libc::c_int,
    mut p1: libc::c_int,
    mut _p2: *mut libc::c_void,
) -> libc::c_int {
    let mut dctx: *mut DH_PKEY_CTX = (*ctx).data as *mut DH_PKEY_CTX;
    match type_0 {
        3 => return 1 as libc::c_int,
        4115 => {
            (*dctx).pad = p1;
            return 1 as libc::c_int;
        }
        4116 => {
            if p1 < 256 as libc::c_int {
                return -(2 as libc::c_int);
            }
            (*dctx).prime_len = p1;
            return 1 as libc::c_int;
        }
        4117 => {
            if p1 < 2 as libc::c_int {
                return -(2 as libc::c_int);
            }
            (*dctx).generator = p1;
            return 1 as libc::c_int;
        }
        _ => {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                101 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dh.c\0"
                    as *const u8 as *const libc::c_char,
                140 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    };
}
unsafe extern "C" fn pkey_dh_paramgen(
    mut ctx: *mut EVP_PKEY_CTX,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut dctx: *mut DH_PKEY_CTX = (*ctx).data as *mut DH_PKEY_CTX;
    let mut dh: *mut DH = DH_new();
    if dh.is_null() {
        return 0 as libc::c_int;
    }
    let mut pkey_ctx_cb: *mut BN_GENCB = 0 as *mut BN_GENCB;
    if ((*ctx).pkey_gencb).is_some() {
        pkey_ctx_cb = BN_GENCB_new();
        if pkey_ctx_cb.is_null() {
            current_block = 5902962431511916255;
        } else {
            evp_pkey_set_cb_translate(pkey_ctx_cb, ctx);
            current_block = 7351195479953500246;
        }
    } else {
        current_block = 7351195479953500246;
    }
    match current_block {
        7351195479953500246 => {
            ret = DH_generate_parameters_ex(
                dh,
                (*dctx).prime_len,
                (*dctx).generator,
                pkey_ctx_cb,
            );
        }
        _ => {}
    }
    if ret == 1 as libc::c_int {
        EVP_PKEY_assign_DH(pkey, dh);
    } else {
        ret = 0 as libc::c_int;
        DH_free(dh);
    }
    BN_GENCB_free(pkey_ctx_cb);
    return ret;
}
unsafe extern "C" fn pkey_dh_ctrl_str(
    mut ctx: *mut EVP_PKEY_CTX,
    mut type_0: *const libc::c_char,
    mut value: *const libc::c_char,
) -> libc::c_int {
    if strcmp(type_0, b"dh_paramgen_prime_len\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        let mut str_end: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut prime_len: libc::c_long = strtol(value, &mut str_end, 10 as libc::c_int);
        if str_end == value as *mut libc::c_char
            || prime_len < 0 as libc::c_int as libc::c_long
            || prime_len > 2147483647 as libc::c_int as libc::c_long
        {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                114 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dh.c\0"
                    as *const u8 as *const libc::c_char,
                186 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        return EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, prime_len as libc::c_int);
    }
    if strcmp(type_0, b"dh_paramgen_generator\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        let mut str_end_0: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut generator: libc::c_long = strtol(
            value,
            &mut str_end_0,
            10 as libc::c_int,
        );
        if str_end_0 == value as *mut libc::c_char
            || generator < 0 as libc::c_int as libc::c_long
            || generator > 2147483647 as libc::c_int as libc::c_long
        {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                114 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dh.c\0"
                    as *const u8 as *const libc::c_char,
                196 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        return EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, generator as libc::c_int);
    }
    if strcmp(type_0, b"dh_pad\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        let mut str_end_1: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut pad: libc::c_long = strtol(value, &mut str_end_1, 10 as libc::c_int);
        if str_end_1 == value as *mut libc::c_char
            || pad < 0 as libc::c_int as libc::c_long
            || pad > 2147483647 as libc::c_int as libc::c_long
        {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                114 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dh.c\0"
                    as *const u8 as *const libc::c_char,
                207 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        return EVP_PKEY_CTX_set_dh_pad(ctx, pad as libc::c_int);
    }
    return -(2 as libc::c_int);
}
#[unsafe(no_mangle)]
pub static mut dh_pkey_meth: EVP_PKEY_METHOD = unsafe {
    {
        let mut init = evp_pkey_method_st {
            pkey_id: 28 as libc::c_int,
            init: Some(
                pkey_dh_init as unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> libc::c_int,
            ),
            copy: Some(
                pkey_dh_copy
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY_CTX,
                        *mut EVP_PKEY_CTX,
                    ) -> libc::c_int,
            ),
            cleanup: Some(
                pkey_dh_cleanup as unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> (),
            ),
            keygen: Some(
                pkey_dh_keygen
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY_CTX,
                        *mut EVP_PKEY,
                    ) -> libc::c_int,
            ),
            sign_init: None,
            sign: None,
            sign_message: None,
            verify_init: None,
            verify: None,
            verify_message: None,
            verify_recover: None,
            encrypt: None,
            decrypt: None,
            derive: Some(
                pkey_dh_derive
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY_CTX,
                        *mut uint8_t,
                        *mut size_t,
                    ) -> libc::c_int,
            ),
            paramgen: Some(
                pkey_dh_paramgen
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY_CTX,
                        *mut EVP_PKEY,
                    ) -> libc::c_int,
            ),
            ctrl: Some(
                pkey_dh_ctrl
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY_CTX,
                        libc::c_int,
                        libc::c_int,
                        *mut libc::c_void,
                    ) -> libc::c_int,
            ),
            ctrl_str: Some(
                pkey_dh_ctrl_str
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY_CTX,
                        *const libc::c_char,
                        *const libc::c_char,
                    ) -> libc::c_int,
            ),
            keygen_deterministic: None,
            encapsulate_deterministic: None,
            encapsulate: None,
            decapsulate: None,
        };
        init
    }
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_pad(
    mut ctx: *mut EVP_PKEY_CTX,
    mut pad: libc::c_int,
) -> libc::c_int {
    return EVP_PKEY_CTX_ctrl(
        ctx,
        28 as libc::c_int,
        (1 as libc::c_int) << 8 as libc::c_int,
        0x1000 as libc::c_int + 19 as libc::c_int,
        pad,
        0 as *mut libc::c_void,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_paramgen_prime_len(
    mut ctx: *mut EVP_PKEY_CTX,
    mut pbits: libc::c_int,
) -> libc::c_int {
    return EVP_PKEY_CTX_ctrl(
        ctx,
        28 as libc::c_int,
        (1 as libc::c_int) << 9 as libc::c_int,
        0x1000 as libc::c_int + 20 as libc::c_int,
        pbits,
        0 as *mut libc::c_void,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_paramgen_generator(
    mut ctx: *mut EVP_PKEY_CTX,
    mut gen: libc::c_int,
) -> libc::c_int {
    return EVP_PKEY_CTX_ctrl(
        ctx,
        28 as libc::c_int,
        (1 as libc::c_int) << 9 as libc::c_int,
        0x1000 as libc::c_int + 21 as libc::c_int,
        gen,
        0 as *mut libc::c_void,
    );
}
