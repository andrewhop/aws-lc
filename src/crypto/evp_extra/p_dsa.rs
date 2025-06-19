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
    pub type stack_st_void;
    pub type dh_st;
    pub type ec_key_st;
    pub type engine_st;
    pub type pqdsa_key_st;
    pub type kem_key_st;
    pub type rsa_st;
    pub type env_md_st;
    fn strtol(
        _: *const libc::c_char,
        _: *mut *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_long;
    fn DSA_new() -> *mut DSA;
    fn DSA_generate_key(dsa: *mut DSA) -> libc::c_int;
    fn DSA_SIG_free(sig: *mut DSA_SIG);
    fn DSA_do_sign(
        digest: *const uint8_t,
        digest_len: size_t,
        dsa: *const DSA,
    ) -> *mut DSA_SIG;
    fn DSA_do_verify(
        digest: *const uint8_t,
        digest_len: size_t,
        sig: *const DSA_SIG,
        dsa: *const DSA,
    ) -> libc::c_int;
    fn DSA_size(dsa: *const DSA) -> libc::c_int;
    fn DSA_SIG_parse(cbs: *mut CBS) -> *mut DSA_SIG;
    fn DSA_SIG_marshal(cbb: *mut CBB, sig: *const DSA_SIG) -> libc::c_int;
    fn BN_GENCB_new() -> *mut BN_GENCB;
    fn BN_GENCB_free(callback: *mut BN_GENCB);
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBB_init(cbb: *mut CBB, initial_capacity: size_t) -> libc::c_int;
    fn CBB_finish(
        cbb: *mut CBB,
        out_data: *mut *mut uint8_t,
        out_len: *mut size_t,
    ) -> libc::c_int;
    fn dsa_internal_paramgen(
        dsa: *mut DSA,
        bits: size_t,
        evpmd: *const EVP_MD,
        seed_in: *const libc::c_uchar,
        seed_len: size_t,
        out_counter: *mut libc::c_int,
        out_h: *mut libc::c_ulong,
        cb: *mut BN_GENCB,
    ) -> libc::c_int;
    fn EVP_sha1() -> *const EVP_MD;
    fn EVP_sha224() -> *const EVP_MD;
    fn EVP_sha256() -> *const EVP_MD;
    fn EVP_MD_type(md: *const EVP_MD) -> libc::c_int;
    fn EVP_MD_size(md: *const EVP_MD) -> size_t;
    fn EVP_get_digestbyname(_: *const libc::c_char) -> *const EVP_MD;
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
    fn EVP_PKEY_assign_DSA(pkey: *mut EVP_PKEY, key: *mut DSA) -> libc::c_int;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
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
pub struct DSA_SIG_st {
    pub r: *mut BIGNUM,
    pub s: *mut BIGNUM,
}
pub type BIGNUM = bignum_st;
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
pub type DSA_SIG = DSA_SIG_st;
pub type CRYPTO_refcount_t = uint32_t;
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
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
pub struct bn_mont_ctx_st {
    pub RR: BIGNUM,
    pub N: BIGNUM,
    pub n0: [BN_ULONG; 2],
}
pub type BN_MONT_CTX = bn_mont_ctx_st;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dsa_st {
    pub p: *mut BIGNUM,
    pub q: *mut BIGNUM,
    pub g: *mut BIGNUM,
    pub pub_key: *mut BIGNUM,
    pub priv_key: *mut BIGNUM,
    pub method_mont_lock: CRYPTO_MUTEX,
    pub method_mont_p: *mut BN_MONT_CTX,
    pub method_mont_q: *mut BN_MONT_CTX,
    pub references: CRYPTO_refcount_t,
    pub ex_data: CRYPTO_EX_DATA,
}
pub type CRYPTO_MUTEX = crypto_mutex_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub union crypto_mutex_st {
    pub alignment: libc::c_double,
    pub padding: [uint8_t; 56],
}
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
pub struct DSA_PKEY_CTX {
    pub nbits: libc::c_int,
    pub qbits: libc::c_int,
    pub pmd: *const EVP_MD,
    pub md: *const EVP_MD,
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
unsafe extern "C" fn pkey_dsa_init(mut ctx: *mut EVP_PKEY_CTX) -> libc::c_int {
    let mut dctx: *mut DSA_PKEY_CTX = 0 as *mut DSA_PKEY_CTX;
    dctx = OPENSSL_zalloc(::core::mem::size_of::<DSA_PKEY_CTX>() as libc::c_ulong)
        as *mut DSA_PKEY_CTX;
    if dctx.is_null() {
        return 0 as libc::c_int;
    }
    (*dctx).nbits = 2048 as libc::c_int;
    (*dctx).qbits = 256 as libc::c_int;
    (*dctx).pmd = 0 as *const EVP_MD;
    (*dctx).md = 0 as *const EVP_MD;
    (*ctx).data = dctx as *mut libc::c_void;
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_dsa_copy(
    mut dst: *mut EVP_PKEY_CTX,
    mut src: *mut EVP_PKEY_CTX,
) -> libc::c_int {
    let mut dctx: *mut DSA_PKEY_CTX = 0 as *mut DSA_PKEY_CTX;
    let mut sctx: *mut DSA_PKEY_CTX = 0 as *mut DSA_PKEY_CTX;
    if pkey_dsa_init(dst) == 0 {
        return 0 as libc::c_int;
    }
    sctx = (*src).data as *mut DSA_PKEY_CTX;
    dctx = (*dst).data as *mut DSA_PKEY_CTX;
    if sctx.is_null() || dctx.is_null() {
        return 0 as libc::c_int;
    }
    (*dctx).nbits = (*sctx).nbits;
    (*dctx).qbits = (*sctx).qbits;
    (*dctx).pmd = (*sctx).pmd;
    (*dctx).md = (*sctx).md;
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_dsa_cleanup(mut ctx: *mut EVP_PKEY_CTX) {
    OPENSSL_free((*ctx).data);
    (*ctx).data = 0 as *mut libc::c_void;
}
unsafe extern "C" fn pkey_dsa_keygen(
    mut ctx: *mut EVP_PKEY_CTX,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    if ((*ctx).pkey).is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa.c\0" as *const u8
                as *const libc::c_char,
            59 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut dsa: *mut DSA = 0 as *mut DSA;
    dsa = DSA_new();
    if !(dsa.is_null() || EVP_PKEY_assign_DSA(pkey, dsa) == 0
        || EVP_PKEY_copy_parameters(pkey, (*ctx).pkey) == 0)
    {
        ret = DSA_generate_key((*pkey).pkey.dsa);
    }
    if ret != 1 as libc::c_int {
        OPENSSL_free(dsa as *mut libc::c_void);
    }
    return ret;
}
unsafe extern "C" fn pkey_dsa_paramgen(
    mut ctx: *mut EVP_PKEY_CTX,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    let mut pmd: *const EVP_MD = 0 as *const EVP_MD;
    let mut current_block: u64;
    let mut pkey_ctx_cb: *mut BN_GENCB = 0 as *mut BN_GENCB;
    let mut dsa: *mut DSA = 0 as *mut DSA;
    let mut dctx: *mut DSA_PKEY_CTX = (*ctx).data as *mut DSA_PKEY_CTX;
    if dctx.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa.c\0" as *const u8
                as *const libc::c_char,
            80 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    if ((*ctx).pkey_gencb).is_some() {
        pkey_ctx_cb = BN_GENCB_new();
        if pkey_ctx_cb.is_null() {
            current_block = 8111870951567043281;
        } else {
            evp_pkey_set_cb_translate(pkey_ctx_cb, ctx);
            current_block = 11812396948646013369;
        }
    } else {
        current_block = 11812396948646013369;
    }
    match current_block {
        11812396948646013369 => {
            pmd = (*dctx).pmd;
            if pmd.is_null() {
                match (*dctx).qbits {
                    160 => {
                        pmd = EVP_sha1();
                        current_block = 5948590327928692120;
                    }
                    224 => {
                        pmd = EVP_sha224();
                        current_block = 5948590327928692120;
                    }
                    256 => {
                        pmd = EVP_sha256();
                        current_block = 5948590327928692120;
                    }
                    _ => {
                        ERR_put_error(
                            6 as libc::c_int,
                            0 as libc::c_int,
                            114 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa.c\0"
                                as *const u8 as *const libc::c_char,
                            106 as libc::c_int as libc::c_uint,
                        );
                        current_block = 8111870951567043281;
                    }
                }
            } else {
                current_block = 5948590327928692120;
            }
            match current_block {
                8111870951567043281 => {}
                _ => {
                    dsa = DSA_new();
                    if !dsa.is_null() {
                        if !(dsa_internal_paramgen(
                            dsa,
                            (*dctx).nbits as size_t,
                            pmd,
                            0 as *const libc::c_uchar,
                            0 as libc::c_int as size_t,
                            0 as *mut libc::c_int,
                            0 as *mut libc::c_ulong,
                            pkey_ctx_cb,
                        ) == 0)
                        {
                            ret = EVP_PKEY_assign_DSA(pkey, dsa);
                        }
                    }
                }
            }
        }
        _ => {}
    }
    BN_GENCB_free(pkey_ctx_cb);
    if ret != 1 as libc::c_int {
        OPENSSL_free(dsa as *mut libc::c_void);
    }
    return ret;
}
unsafe extern "C" fn pkey_dsa_sign(
    mut ctx: *mut EVP_PKEY_CTX,
    mut sig: *mut libc::c_uchar,
    mut siglen: *mut size_t,
    mut tbs: *const libc::c_uchar,
    mut tbslen: size_t,
) -> libc::c_int {
    let mut sig_bytes: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    if ((*ctx).pkey).is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa.c\0" as *const u8
                as *const libc::c_char,
            132 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*(*ctx).pkey).pkey.ptr).is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa.c\0" as *const u8
                as *const libc::c_char,
            133 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*ctx).data).is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa.c\0" as *const u8
                as *const libc::c_char,
            134 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if siglen.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa.c\0" as *const u8
                as *const libc::c_char,
            135 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut dctx: *mut DSA_PKEY_CTX = (*ctx).data as *mut DSA_PKEY_CTX;
    let mut dsa: *mut DSA = (*(*ctx).pkey).pkey.dsa;
    if sig.is_null() {
        *siglen = DSA_size(dsa) as size_t;
        return 1 as libc::c_int;
    }
    let mut result: *mut DSA_SIG = 0 as *mut DSA_SIG;
    let mut sig_buffer: *mut uint8_t = 0 as *mut uint8_t;
    let mut retval: libc::c_int = 0 as libc::c_int;
    if !((*dctx).md).is_null() && tbslen != EVP_MD_size((*dctx).md) {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            133 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa.c\0" as *const u8
                as *const libc::c_char,
            151 as libc::c_int as libc::c_uint,
        );
    } else {
        result = DSA_do_sign(tbs, tbslen, dsa);
        if !result.is_null() {
            sig_bytes = cbb_st {
                child: 0 as *mut CBB,
                is_child: 0,
                u: C2RustUnnamed_0 {
                    base: cbb_buffer_st {
                        buf: 0 as *mut uint8_t,
                        len: 0,
                        cap: 0,
                        can_resize_error: [0; 1],
                        c2rust_padding: [0; 7],
                    },
                },
            };
            if !(1 as libc::c_int != CBB_init(&mut sig_bytes, tbslen)) {
                DSA_SIG_marshal(&mut sig_bytes, result);
                if !(1 as libc::c_int
                    != CBB_finish(&mut sig_bytes, &mut sig_buffer, siglen))
                {
                    OPENSSL_memcpy(
                        sig as *mut libc::c_void,
                        sig_buffer as *const libc::c_void,
                        *siglen,
                    );
                    retval = 1 as libc::c_int;
                }
            }
        }
    }
    OPENSSL_free(sig_buffer as *mut libc::c_void);
    DSA_SIG_free(result);
    return retval;
}
unsafe extern "C" fn pkey_dsa_verify(
    mut ctx: *mut EVP_PKEY_CTX,
    mut sig: *const libc::c_uchar,
    mut siglen: size_t,
    mut tbs: *const libc::c_uchar,
    mut tbslen: size_t,
) -> libc::c_int {
    if ((*ctx).pkey).is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa.c\0" as *const u8
                as *const libc::c_char,
            178 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*(*ctx).pkey).pkey.ptr).is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa.c\0" as *const u8
                as *const libc::c_char,
            179 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*ctx).data).is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa.c\0" as *const u8
                as *const libc::c_char,
            180 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if tbs.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa.c\0" as *const u8
                as *const libc::c_char,
            181 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut dctx: *mut DSA_PKEY_CTX = (*ctx).data as *mut DSA_PKEY_CTX;
    let mut dsa: *const DSA = (*(*ctx).pkey).pkey.dsa;
    if !((*dctx).md).is_null() && tbslen != EVP_MD_size((*dctx).md) {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            133 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa.c\0" as *const u8
                as *const libc::c_char,
            187 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut dsa_sig: *mut DSA_SIG = 0 as *mut DSA_SIG;
    let mut retval: libc::c_int = 0 as libc::c_int;
    let mut sig_cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut sig_cbs, sig, siglen);
    dsa_sig = DSA_SIG_parse(&mut sig_cbs);
    if !(dsa_sig.is_null() || CBS_len(&mut sig_cbs) != 0 as libc::c_int as size_t) {
        if !(1 as libc::c_int != DSA_do_verify(tbs, tbslen, dsa_sig, dsa)) {
            retval = 1 as libc::c_int;
        }
    }
    DSA_SIG_free(dsa_sig);
    return retval;
}
unsafe extern "C" fn pkey_dsa_ctrl(
    mut ctx: *mut EVP_PKEY_CTX,
    mut type_0: libc::c_int,
    mut p1: libc::c_int,
    mut p2: *mut libc::c_void,
) -> libc::c_int {
    let mut dctx: *mut DSA_PKEY_CTX = (*ctx).data as *mut DSA_PKEY_CTX;
    match type_0 {
        4119 => {
            if p1 < 512 as libc::c_int {
                return -(2 as libc::c_int);
            }
            (*dctx).nbits = p1;
            return 1 as libc::c_int;
        }
        4120 => {
            match p1 {
                160 | 224 | 256 => {
                    (*dctx).qbits = p1;
                    return 1 as libc::c_int;
                }
                _ => return -(2 as libc::c_int),
            }
        }
        4121 => {
            let mut pmd: *const EVP_MD = p2 as *const EVP_MD;
            if pmd.is_null() {
                return 0 as libc::c_int;
            }
            match EVP_MD_type(pmd) {
                64 | 675 | 672 => {
                    (*dctx).pmd = pmd;
                    return 1 as libc::c_int;
                }
                _ => {
                    ERR_put_error(
                        6 as libc::c_int,
                        0 as libc::c_int,
                        111 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa.c\0"
                            as *const u8 as *const libc::c_char,
                        245 as libc::c_int as libc::c_uint,
                    );
                    return 0 as libc::c_int;
                }
            }
        }
        1 => {
            let mut md: *const EVP_MD = p2 as *const EVP_MD;
            if md.is_null() {
                return 0 as libc::c_int;
            }
            match EVP_MD_type(md) {
                64 | 675 | 672 | 673 | 674 | 965 | 966 | 967 | 968 => {
                    (*dctx).md = md;
                    return 1 as libc::c_int;
                }
                _ => {
                    ERR_put_error(
                        6 as libc::c_int,
                        0 as libc::c_int,
                        111 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa.c\0"
                            as *const u8 as *const libc::c_char,
                        267 as libc::c_int as libc::c_uint,
                    );
                    return 0 as libc::c_int;
                }
            }
        }
        2 => {
            if p2.is_null() {
                return 0 as libc::c_int;
            }
            let ref mut fresh0 = *(p2 as *mut *const EVP_MD);
            *fresh0 = (*dctx).md;
            return 1 as libc::c_int;
        }
        3 => {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                125 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa.c\0"
                    as *const u8 as *const libc::c_char,
                279 as libc::c_int as libc::c_uint,
            );
            return -(2 as libc::c_int);
        }
        _ => {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                101 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa.c\0"
                    as *const u8 as *const libc::c_char,
                282 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    };
}
unsafe extern "C" fn pkey_dsa_ctrl_str(
    mut ctx: *mut EVP_PKEY_CTX,
    mut type_0: *const libc::c_char,
    mut value: *const libc::c_char,
) -> libc::c_int {
    if strcmp(type_0, b"dsa_paramgen_bits\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        let mut str_end: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut nbits: libc::c_long = strtol(value, &mut str_end, 10 as libc::c_int);
        if str_end == value as *mut libc::c_char
            || nbits < 0 as libc::c_int as libc::c_long
            || nbits > 2147483647 as libc::c_int as libc::c_long
        {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                114 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa.c\0"
                    as *const u8 as *const libc::c_char,
                293 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        return EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, nbits as libc::c_int);
    }
    if strcmp(type_0, b"dsa_paramgen_q_bits\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        let mut str_end_0: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut qbits: libc::c_long = strtol(value, &mut str_end_0, 10 as libc::c_int);
        if str_end_0 == value as *mut libc::c_char
            || qbits < 0 as libc::c_int as libc::c_long
            || qbits > 2147483647 as libc::c_int as libc::c_long
        {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                114 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa.c\0"
                    as *const u8 as *const libc::c_char,
                304 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        return EVP_PKEY_CTX_set_dsa_paramgen_q_bits(ctx, qbits as libc::c_int);
    }
    if strcmp(type_0, b"dsa_paramgen_md\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        let mut md: *const EVP_MD = EVP_get_digestbyname(value);
        if md.is_null() {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                111 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/p_dsa.c\0"
                    as *const u8 as *const libc::c_char,
                315 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        return EVP_PKEY_CTX_set_dsa_paramgen_md(ctx, md);
    }
    return -(2 as libc::c_int);
}
#[no_mangle]
pub static mut dsa_pkey_meth: EVP_PKEY_METHOD = unsafe {
    {
        let mut init = evp_pkey_method_st {
            pkey_id: 116 as libc::c_int,
            init: Some(
                pkey_dsa_init as unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> libc::c_int,
            ),
            copy: Some(
                pkey_dsa_copy
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY_CTX,
                        *mut EVP_PKEY_CTX,
                    ) -> libc::c_int,
            ),
            cleanup: Some(
                pkey_dsa_cleanup as unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> (),
            ),
            keygen: Some(
                pkey_dsa_keygen
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY_CTX,
                        *mut EVP_PKEY,
                    ) -> libc::c_int,
            ),
            sign_init: None,
            sign: Some(
                pkey_dsa_sign
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY_CTX,
                        *mut libc::c_uchar,
                        *mut size_t,
                        *const libc::c_uchar,
                        size_t,
                    ) -> libc::c_int,
            ),
            sign_message: None,
            verify_init: None,
            verify: Some(
                pkey_dsa_verify
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY_CTX,
                        *const libc::c_uchar,
                        size_t,
                        *const libc::c_uchar,
                        size_t,
                    ) -> libc::c_int,
            ),
            verify_message: None,
            verify_recover: None,
            encrypt: None,
            decrypt: None,
            derive: None,
            paramgen: Some(
                pkey_dsa_paramgen
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY_CTX,
                        *mut EVP_PKEY,
                    ) -> libc::c_int,
            ),
            ctrl: Some(
                pkey_dsa_ctrl
                    as unsafe extern "C" fn(
                        *mut EVP_PKEY_CTX,
                        libc::c_int,
                        libc::c_int,
                        *mut libc::c_void,
                    ) -> libc::c_int,
            ),
            ctrl_str: Some(
                pkey_dsa_ctrl_str
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
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dsa_paramgen_bits(
    mut ctx: *mut EVP_PKEY_CTX,
    mut nbits: libc::c_int,
) -> libc::c_int {
    if 1 as libc::c_int
        == EVP_PKEY_CTX_ctrl(
            ctx,
            116 as libc::c_int,
            (1 as libc::c_int) << 9 as libc::c_int,
            0x1000 as libc::c_int + 23 as libc::c_int,
            nbits,
            0 as *mut libc::c_void,
        )
    {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dsa_paramgen_q_bits(
    mut ctx: *mut EVP_PKEY_CTX,
    mut qbits: libc::c_int,
) -> libc::c_int {
    if 1 as libc::c_int
        == EVP_PKEY_CTX_ctrl(
            ctx,
            116 as libc::c_int,
            (1 as libc::c_int) << 9 as libc::c_int,
            0x1000 as libc::c_int + 24 as libc::c_int,
            qbits,
            0 as *mut libc::c_void,
        )
    {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_dsa_paramgen_md(
    mut ctx: *mut EVP_PKEY_CTX,
    mut md: *const EVP_MD,
) -> libc::c_int {
    if 1 as libc::c_int
        == EVP_PKEY_CTX_ctrl(
            ctx,
            116 as libc::c_int,
            (1 as libc::c_int) << 9 as libc::c_int,
            0x1000 as libc::c_int + 25 as libc::c_int,
            0 as libc::c_int,
            md as *mut libc::c_void,
        )
    {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
