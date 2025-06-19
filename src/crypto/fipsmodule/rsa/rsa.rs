#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(asm, extern_types, label_break_value)]
use core::arch::asm;
extern "C" {
    pub type bignum_ctx;
    pub type stack_st_void;
    pub type dh_st;
    pub type dsa_st;
    pub type ec_key_st;
    pub type engine_st;
    pub type evp_md_pctx_ops;
    pub type pqdsa_key_st;
    pub type kem_key_st;
    pub type bn_blinding_st;
    pub type env_md_st;
    pub type rsa_pss_params_st;
    pub type stack_st_CRYPTO_EX_DATA_FUNCS;
    fn BN_init(bn: *mut BIGNUM);
    fn BN_free(bn: *mut BIGNUM);
    fn BN_dup(src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_value_one() -> *const BIGNUM;
    fn BN_num_bits(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_is_negative(bn: *const BIGNUM) -> libc::c_int;
    fn BN_CTX_new() -> *mut BN_CTX;
    fn BN_CTX_free(ctx: *mut BN_CTX);
    fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_ucmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_is_one(bn: *const BIGNUM) -> libc::c_int;
    fn BN_is_odd(bn: *const BIGNUM) -> libc::c_int;
    fn BN_enhanced_miller_rabin_primality_test(
        out_result: *mut bn_primality_result_t,
        w: *const BIGNUM,
        checks: libc::c_int,
        ctx: *mut BN_CTX,
        cb: *mut BN_GENCB,
    ) -> libc::c_int;
    fn BN_gcd(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        b: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn EVP_sha256() -> *const EVP_MD;
    fn EVP_MD_CTX_init(ctx: *mut EVP_MD_CTX);
    fn EVP_MD_CTX_cleanse(ctx: *mut EVP_MD_CTX);
    fn EVP_Digest(
        data: *const libc::c_void,
        len: size_t,
        md_out: *mut uint8_t,
        out_size: *mut libc::c_uint,
        type_0: *const EVP_MD,
        impl_0: *mut ENGINE,
    ) -> libc::c_int;
    fn EVP_MD_type(md: *const EVP_MD) -> libc::c_int;
    fn EVP_MD_size(md: *const EVP_MD) -> size_t;
    fn EVP_PKEY_CTX_ctrl(
        ctx: *mut EVP_PKEY_CTX,
        keytype: libc::c_int,
        optype: libc::c_int,
        cmd: libc::c_int,
        p1: libc::c_int,
        p2: *mut libc::c_void,
    ) -> libc::c_int;
    fn rsa_default_size(rsa: *const RSA) -> size_t;
    fn rsa_default_sign_raw(
        rsa: *mut RSA,
        out_len: *mut size_t,
        out: *mut uint8_t,
        max_out: size_t,
        in_0: *const uint8_t,
        in_len: size_t,
        padding: libc::c_int,
    ) -> libc::c_int;
    fn rsa_default_private_transform(
        rsa: *mut RSA,
        out: *mut uint8_t,
        in_0: *const uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn rsa_invalidate_key(rsa: *mut RSA);
    fn rsa_verify_raw_no_self_test(
        rsa: *mut RSA,
        out_len: *mut size_t,
        out: *mut uint8_t,
        max_out: size_t,
        in_0: *const uint8_t,
        in_len: size_t,
        padding: libc::c_int,
    ) -> libc::c_int;
    fn RSASSA_PSS_PARAMS_free(params: *mut RSASSA_PSS_PARAMS);
    fn EVP_PKEY_new() -> *mut EVP_PKEY;
    fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
    fn EVP_PKEY_set1_RSA(pkey: *mut EVP_PKEY, key: *mut RSA) -> libc::c_int;
    fn EVP_DigestSignInit(
        ctx: *mut EVP_MD_CTX,
        pctx: *mut *mut EVP_PKEY_CTX,
        type_0: *const EVP_MD,
        e: *mut ENGINE,
        pkey: *mut EVP_PKEY,
    ) -> libc::c_int;
    fn EVP_DigestSign(
        ctx: *mut EVP_MD_CTX,
        out_sig: *mut uint8_t,
        out_sig_len: *mut size_t,
        data: *const uint8_t,
        data_len: size_t,
    ) -> libc::c_int;
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
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ENGINE_get_RSA(engine: *const ENGINE) -> *const RSA_METHOD;
    fn RSA_get_default_method() -> *const RSA_METHOD;
    fn RSA_verify_raw(
        rsa: *mut RSA,
        out_len: *mut size_t,
        out: *mut uint8_t,
        max_out: size_t,
        in_0: *const uint8_t,
        in_len: size_t,
        padding: libc::c_int,
    ) -> libc::c_int;
    fn RSA_verify_PKCS1_PSS_mgf1(
        rsa: *const RSA,
        mHash: *const uint8_t,
        Hash: *const EVP_MD,
        mgf1Hash: *const EVP_MD,
        EM: *const uint8_t,
        sLen: libc::c_int,
    ) -> libc::c_int;
    fn RSA_padding_add_PKCS1_PSS_mgf1(
        rsa: *const RSA,
        EM: *mut uint8_t,
        mHash: *const uint8_t,
        Hash: *const EVP_MD,
        mgf1Hash: *const EVP_MD,
        sLen: libc::c_int,
    ) -> libc::c_int;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn CRYPTO_once(
        once: *mut CRYPTO_once_t,
        init: Option::<unsafe extern "C" fn() -> ()>,
    );
    fn CRYPTO_refcount_inc(count: *mut CRYPTO_refcount_t);
    fn CRYPTO_refcount_dec_and_test_zero(count: *mut CRYPTO_refcount_t) -> libc::c_int;
    fn CRYPTO_MUTEX_init(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_cleanup(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_get_ex_new_index(
        ex_data_class: *mut CRYPTO_EX_DATA_CLASS,
        out_index: *mut libc::c_int,
        argl: libc::c_long,
        argp: *mut libc::c_void,
        free_func: Option::<CRYPTO_EX_free>,
    ) -> libc::c_int;
    fn CRYPTO_set_ex_data(
        ad: *mut CRYPTO_EX_DATA,
        index: libc::c_int,
        val: *mut libc::c_void,
    ) -> libc::c_int;
    fn CRYPTO_get_ex_data(
        ad: *const CRYPTO_EX_DATA,
        index: libc::c_int,
    ) -> *mut libc::c_void;
    fn CRYPTO_new_ex_data(ad: *mut CRYPTO_EX_DATA);
    fn CRYPTO_free_ex_data(
        ex_data_class: *mut CRYPTO_EX_DATA_CLASS,
        obj: *mut libc::c_void,
        ad: *mut CRYPTO_EX_DATA,
    );
    fn bn_usub_consttime(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        b: *const BIGNUM,
    ) -> libc::c_int;
    fn bn_mul_consttime(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        b: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn bn_div_consttime(
        quotient: *mut BIGNUM,
        remainder: *mut BIGNUM,
        numerator: *const BIGNUM,
        divisor: *const BIGNUM,
        divisor_min_bits: libc::c_uint,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type int64_t = __int64_t;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_rwlock_arch_t {
    pub __readers: libc::c_uint,
    pub __writers: libc::c_uint,
    pub __wrphase_futex: libc::c_uint,
    pub __writers_futex: libc::c_uint,
    pub __pad3: libc::c_uint,
    pub __pad4: libc::c_uint,
    pub __cur_writer: libc::c_int,
    pub __shared: libc::c_int,
    pub __rwelision: libc::c_schar,
    pub __pad1: [libc::c_uchar; 7],
    pub __pad2: libc::c_ulong,
    pub __flags: libc::c_uint,
}
pub type pthread_once_t = libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_rwlock_t {
    pub __data: __pthread_rwlock_arch_t,
    pub __size: [libc::c_char; 56],
    pub __align: libc::c_long,
}
pub type BN_CTX = bignum_ctx;
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
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct rsa_st {
    pub meth: *const RSA_METHOD,
    pub n: *mut BIGNUM,
    pub e: *mut BIGNUM,
    pub d: *mut BIGNUM,
    pub p: *mut BIGNUM,
    pub q: *mut BIGNUM,
    pub dmp1: *mut BIGNUM,
    pub dmq1: *mut BIGNUM,
    pub iqmp: *mut BIGNUM,
    pub pss: *mut RSASSA_PSS_PARAMS,
    pub ex_data: CRYPTO_EX_DATA,
    pub references: CRYPTO_refcount_t,
    pub flags: libc::c_int,
    pub lock: CRYPTO_MUTEX,
    pub mont_n: *mut BN_MONT_CTX,
    pub mont_p: *mut BN_MONT_CTX,
    pub mont_q: *mut BN_MONT_CTX,
    pub d_fixed: *mut BIGNUM,
    pub dmp1_fixed: *mut BIGNUM,
    pub dmq1_fixed: *mut BIGNUM,
    pub iqmp_mont: *mut BIGNUM,
    pub num_blindings: size_t,
    pub blindings: *mut *mut BN_BLINDING,
    pub blindings_inuse: *mut libc::c_uchar,
    pub blinding_fork_generation: uint64_t,
    #[bitfield(name = "private_key_frozen", ty = "libc::c_uint", bits = "0..=0")]
    pub private_key_frozen: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
pub type BN_BLINDING = bn_blinding_st;
pub type CRYPTO_MUTEX = crypto_mutex_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub union crypto_mutex_st {
    pub alignment: libc::c_double,
    pub padding: [uint8_t; 56],
}
pub type RSASSA_PSS_PARAMS = rsassa_pss_params_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rsassa_pss_params_st {
    pub hash_algor: *mut RSA_ALGOR_IDENTIFIER,
    pub mask_gen_algor: *mut RSA_MGA_IDENTIFIER,
    pub salt_len: *mut RSA_INTEGER,
    pub trailer_field: *mut RSA_INTEGER,
}
pub type RSA_INTEGER = rsa_integer_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rsa_integer_st {
    pub value: int64_t,
}
pub type RSA_MGA_IDENTIFIER = rsa_mga_identifier_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rsa_mga_identifier_st {
    pub mask_gen: *mut RSA_ALGOR_IDENTIFIER,
    pub one_way_hash: *mut RSA_ALGOR_IDENTIFIER,
}
pub type RSA_ALGOR_IDENTIFIER = rsa_algor_identifier_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rsa_algor_identifier_st {
    pub nid: libc::c_int,
}
pub type RSA_METHOD = rsa_meth_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rsa_meth_st {
    pub app_data: *mut libc::c_void,
    pub init: Option::<unsafe extern "C" fn(*mut RSA) -> libc::c_int>,
    pub finish: Option::<unsafe extern "C" fn(*mut RSA) -> libc::c_int>,
    pub size: Option::<unsafe extern "C" fn(*const RSA) -> size_t>,
    pub sign: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            libc::c_uint,
            *mut uint8_t,
            *mut libc::c_uint,
            *const RSA,
        ) -> libc::c_int,
    >,
    pub sign_raw: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            *mut uint8_t,
            *mut RSA,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub verify_raw: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            *mut uint8_t,
            *mut RSA,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub decrypt: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            *mut uint8_t,
            *mut RSA,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub encrypt: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            *mut uint8_t,
            *mut RSA,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub private_transform: Option::<
        unsafe extern "C" fn(
            *mut RSA,
            *mut uint8_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub flags: libc::c_int,
}
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
pub type RSA_PSS_PARAMS = rsa_pss_params_st;
pub type bn_primality_result_t = libc::c_uint;
pub const bn_non_prime_power_composite: bn_primality_result_t = 2;
pub const bn_composite: bn_primality_result_t = 1;
pub const bn_probably_prime: bn_primality_result_t = 0;
pub type CRYPTO_EX_free = unsafe extern "C" fn(
    *mut libc::c_void,
    *mut libc::c_void,
    *mut CRYPTO_EX_DATA,
    libc::c_int,
    libc::c_long,
    *mut libc::c_void,
) -> ();
pub type CRYPTO_EX_dup = unsafe extern "C" fn(
    *mut CRYPTO_EX_DATA,
    *const CRYPTO_EX_DATA,
    *mut *mut libc::c_void,
    libc::c_int,
    libc::c_long,
    *mut libc::c_void,
) -> libc::c_int;
pub type CRYPTO_EX_unused = libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CRYPTO_EX_DATA_CLASS {
    pub lock: CRYPTO_STATIC_MUTEX,
    pub meth: *mut stack_st_CRYPTO_EX_DATA_FUNCS,
    pub num_reserved: uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CRYPTO_STATIC_MUTEX {
    pub lock: pthread_rwlock_t,
}
pub const PTHREAD_RWLOCK_DEFAULT_NP: C2RustUnnamed_2 = 0;
pub const RSA_KEY_TYPE_FOR_CHECKING_PRIVATE: rsa_key_type_for_checking = 2;
pub type rsa_key_type_for_checking = libc::c_uint;
pub const RSA_KEY_TYPE_FOR_CHECKING_INVALID: rsa_key_type_for_checking = 5;
pub const RSA_KEY_TYPE_FOR_CHECKING_PRIVATE_STRIP: rsa_key_type_for_checking = 4;
pub const RSA_KEY_TYPE_FOR_CHECKING_PRIVATE_CRT: rsa_key_type_for_checking = 3;
pub const RSA_KEY_TYPE_FOR_CHECKING_PRIVATE_MIN: rsa_key_type_for_checking = 1;
pub const RSA_KEY_TYPE_FOR_CHECKING_PUBLIC: rsa_key_type_for_checking = 0;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_552_error_is_int_is_not_the_same_size_as_uint32_t {
    #[bitfield(
        name = "static_assertion_at_line_552_error_is_int_is_not_the_same_size_as_uint32_t",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_552_error_is_int_is_not_the_same_size_as_uint32_t: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pkcs1_sig_prefix {
    pub nid: libc::c_int,
    pub hash_len: uint8_t,
    pub len: uint8_t,
    pub bytes: [uint8_t; 19],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_851_error_is_digest_too_long {
    #[bitfield(
        name = "static_assertion_at_line_851_error_is_digest_too_long",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_851_error_is_digest_too_long: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
pub type CRYPTO_once_t = pthread_once_t;
pub type C2RustUnnamed_2 = libc::c_uint;
pub const PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP: C2RustUnnamed_2 = 2;
pub const PTHREAD_RWLOCK_PREFER_WRITER_NP: C2RustUnnamed_2 = 1;
pub const PTHREAD_RWLOCK_PREFER_READER_NP: C2RustUnnamed_2 = 0;
#[inline]
unsafe extern "C" fn value_barrier_u32(mut a: uint32_t) -> uint32_t {
    asm!("", inlateout(reg) a, options(preserves_flags, pure, readonly, att_syntax));
    return a;
}
#[inline]
unsafe extern "C" fn constant_time_declassify_int(mut v: libc::c_int) -> libc::c_int {
    return value_barrier_u32(v as uint32_t) as libc::c_int;
}
#[inline]
unsafe extern "C" fn OPENSSL_memcmp(
    mut s1: *const libc::c_void,
    mut s2: *const libc::c_void,
    mut n: size_t,
) -> libc::c_int {
    if n == 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    return memcmp(s1, s2, n);
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
#[inline]
unsafe extern "C" fn boringssl_ensure_rsa_self_test() {}
#[inline]
unsafe extern "C" fn boringssl_fips_break_test(
    mut test: *const libc::c_char,
) -> libc::c_int {
    return 0 as libc::c_int;
}
unsafe extern "C" fn g_rsa_ex_data_class_bss_get() -> *mut CRYPTO_EX_DATA_CLASS {
    return &mut g_rsa_ex_data_class;
}
static mut g_rsa_ex_data_class: CRYPTO_EX_DATA_CLASS = {
    let mut init = CRYPTO_EX_DATA_CLASS {
        lock: {
            let mut init = CRYPTO_STATIC_MUTEX {
                lock: pthread_rwlock_t {
                    __data: {
                        let mut init = __pthread_rwlock_arch_t {
                            __readers: 0 as libc::c_int as libc::c_uint,
                            __writers: 0 as libc::c_int as libc::c_uint,
                            __wrphase_futex: 0 as libc::c_int as libc::c_uint,
                            __writers_futex: 0 as libc::c_int as libc::c_uint,
                            __pad3: 0 as libc::c_int as libc::c_uint,
                            __pad4: 0 as libc::c_int as libc::c_uint,
                            __cur_writer: 0 as libc::c_int,
                            __shared: 0 as libc::c_int,
                            __rwelision: 0 as libc::c_int as libc::c_schar,
                            __pad1: [
                                0 as libc::c_int as libc::c_uchar,
                                0 as libc::c_int as libc::c_uchar,
                                0 as libc::c_int as libc::c_uchar,
                                0 as libc::c_int as libc::c_uchar,
                                0 as libc::c_int as libc::c_uchar,
                                0 as libc::c_int as libc::c_uchar,
                                0 as libc::c_int as libc::c_uchar,
                            ],
                            __pad2: 0 as libc::c_int as libc::c_ulong,
                            __flags: PTHREAD_RWLOCK_DEFAULT_NP as libc::c_int
                                as libc::c_uint,
                        };
                        init
                    },
                },
            };
            init
        },
        meth: 0 as *const stack_st_CRYPTO_EX_DATA_FUNCS
            as *mut stack_st_CRYPTO_EX_DATA_FUNCS,
        num_reserved: 0 as libc::c_int as uint8_t,
    };
    init
};
unsafe extern "C" fn bn_dup_into(
    mut dst: *mut *mut BIGNUM,
    mut src: *const BIGNUM,
) -> libc::c_int {
    if src.is_null() {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            91 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    BN_free(*dst);
    *dst = BN_dup(src);
    return (*dst != 0 as *mut libc::c_void as *mut BIGNUM) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_new_public_key(
    mut n: *const BIGNUM,
    mut e: *const BIGNUM,
) -> *mut RSA {
    let mut rsa: *mut RSA = RSA_new();
    if rsa.is_null() || bn_dup_into(&mut (*rsa).n, n) == 0
        || bn_dup_into(&mut (*rsa).e, e) == 0 || RSA_check_key(rsa) == 0
    {
        RSA_free(rsa);
        return 0 as *mut RSA;
    }
    return rsa;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_new_private_key(
    mut n: *const BIGNUM,
    mut e: *const BIGNUM,
    mut d: *const BIGNUM,
    mut p: *const BIGNUM,
    mut q: *const BIGNUM,
    mut dmp1: *const BIGNUM,
    mut dmq1: *const BIGNUM,
    mut iqmp: *const BIGNUM,
) -> *mut RSA {
    let mut rsa: *mut RSA = RSA_new();
    if rsa.is_null() || bn_dup_into(&mut (*rsa).n, n) == 0
        || bn_dup_into(&mut (*rsa).e, e) == 0 || bn_dup_into(&mut (*rsa).d, d) == 0
        || bn_dup_into(&mut (*rsa).p, p) == 0 || bn_dup_into(&mut (*rsa).q, q) == 0
        || bn_dup_into(&mut (*rsa).dmp1, dmp1) == 0
        || bn_dup_into(&mut (*rsa).dmq1, dmq1) == 0
        || bn_dup_into(&mut (*rsa).iqmp, iqmp) == 0 || RSA_check_key(rsa) == 0
    {
        RSA_free(rsa);
        return 0 as *mut RSA;
    }
    return rsa;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_new_private_key_no_crt(
    mut n: *const BIGNUM,
    mut e: *const BIGNUM,
    mut d: *const BIGNUM,
) -> *mut RSA {
    let mut rsa: *mut RSA = RSA_new();
    if rsa.is_null() || bn_dup_into(&mut (*rsa).n, n) == 0
        || bn_dup_into(&mut (*rsa).e, e) == 0 || bn_dup_into(&mut (*rsa).d, d) == 0
        || RSA_check_key(rsa) == 0
    {
        RSA_free(rsa);
        return 0 as *mut RSA;
    }
    return rsa;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_new_private_key_no_e(
    mut n: *const BIGNUM,
    mut d: *const BIGNUM,
) -> *mut RSA {
    let mut rsa: *mut RSA = RSA_new();
    if rsa.is_null() {
        return 0 as *mut RSA;
    }
    (*rsa).flags |= 0x40 as libc::c_int;
    if bn_dup_into(&mut (*rsa).n, n) == 0 || bn_dup_into(&mut (*rsa).d, d) == 0
        || RSA_check_key(rsa) == 0
    {
        RSA_free(rsa);
        return 0 as *mut RSA;
    }
    return rsa;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_new_public_key_large_e(
    mut n: *const BIGNUM,
    mut e: *const BIGNUM,
) -> *mut RSA {
    let mut rsa: *mut RSA = RSA_new();
    if rsa.is_null() {
        return 0 as *mut RSA;
    }
    (*rsa).flags |= 0x80 as libc::c_int;
    if bn_dup_into(&mut (*rsa).n, n) == 0 || bn_dup_into(&mut (*rsa).e, e) == 0
        || RSA_check_key(rsa) == 0
    {
        RSA_free(rsa);
        return 0 as *mut RSA;
    }
    return rsa;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_new_private_key_large_e(
    mut n: *const BIGNUM,
    mut e: *const BIGNUM,
    mut d: *const BIGNUM,
    mut p: *const BIGNUM,
    mut q: *const BIGNUM,
    mut dmp1: *const BIGNUM,
    mut dmq1: *const BIGNUM,
    mut iqmp: *const BIGNUM,
) -> *mut RSA {
    let mut rsa: *mut RSA = RSA_new();
    if rsa.is_null() {
        return 0 as *mut RSA;
    }
    (*rsa).flags |= 0x80 as libc::c_int;
    if bn_dup_into(&mut (*rsa).n, n) == 0 || bn_dup_into(&mut (*rsa).e, e) == 0
        || bn_dup_into(&mut (*rsa).d, d) == 0 || bn_dup_into(&mut (*rsa).p, p) == 0
        || bn_dup_into(&mut (*rsa).q, q) == 0 || bn_dup_into(&mut (*rsa).dmp1, dmp1) == 0
        || bn_dup_into(&mut (*rsa).dmq1, dmq1) == 0
        || bn_dup_into(&mut (*rsa).iqmp, iqmp) == 0 || RSA_check_key(rsa) == 0
    {
        RSA_free(rsa);
        return 0 as *mut RSA;
    }
    return rsa;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_new() -> *mut RSA {
    return RSA_new_method(0 as *const ENGINE);
}
#[no_mangle]
pub unsafe extern "C" fn RSA_new_method(mut engine: *const ENGINE) -> *mut RSA {
    let mut rsa: *mut RSA = OPENSSL_zalloc(
        ::core::mem::size_of::<RSA>() as libc::c_ulong,
    ) as *mut RSA;
    if rsa.is_null() {
        return 0 as *mut RSA;
    }
    if !engine.is_null() {
        (*rsa).meth = ENGINE_get_RSA(engine);
    }
    if ((*rsa).meth).is_null() {
        (*rsa).meth = RSA_get_default_method() as *mut RSA_METHOD;
    }
    (*rsa).references = 1 as libc::c_int as CRYPTO_refcount_t;
    (*rsa).flags = (*(*rsa).meth).flags;
    CRYPTO_MUTEX_init(&mut (*rsa).lock);
    CRYPTO_new_ex_data(&mut (*rsa).ex_data);
    if ((*(*rsa).meth).init).is_some()
        && ((*(*rsa).meth).init).expect("non-null function pointer")(rsa) == 0
    {
        CRYPTO_free_ex_data(
            g_rsa_ex_data_class_bss_get(),
            rsa as *mut libc::c_void,
            &mut (*rsa).ex_data,
        );
        CRYPTO_MUTEX_cleanup(&mut (*rsa).lock);
        OPENSSL_free(rsa as *mut libc::c_void);
        return 0 as *mut RSA;
    }
    return rsa;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_new_method_no_e(
    mut engine: *const ENGINE,
    mut n: *const BIGNUM,
) -> *mut RSA {
    let mut rsa: *mut RSA = RSA_new_method(engine);
    if rsa.is_null() || bn_dup_into(&mut (*rsa).n, n) == 0 {
        RSA_free(rsa);
        return 0 as *mut RSA;
    }
    (*rsa).flags |= 0x40 as libc::c_int;
    return rsa;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_free(mut rsa: *mut RSA) {
    if rsa.is_null() {
        return;
    }
    if CRYPTO_refcount_dec_and_test_zero(&mut (*rsa).references) == 0 {
        return;
    }
    if !((*rsa).meth).is_null() && ((*(*rsa).meth).finish).is_some() {
        ((*(*rsa).meth).finish).expect("non-null function pointer")(rsa);
    }
    CRYPTO_free_ex_data(
        g_rsa_ex_data_class_bss_get(),
        rsa as *mut libc::c_void,
        &mut (*rsa).ex_data,
    );
    BN_free((*rsa).n);
    BN_free((*rsa).e);
    BN_free((*rsa).d);
    BN_free((*rsa).p);
    BN_free((*rsa).q);
    BN_free((*rsa).dmp1);
    BN_free((*rsa).dmq1);
    BN_free((*rsa).iqmp);
    RSASSA_PSS_PARAMS_free((*rsa).pss);
    rsa_invalidate_key(rsa);
    CRYPTO_MUTEX_cleanup(&mut (*rsa).lock);
    OPENSSL_free(rsa as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn RSA_up_ref(mut rsa: *mut RSA) -> libc::c_int {
    CRYPTO_refcount_inc(&mut (*rsa).references);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_bits(mut rsa: *const RSA) -> libc::c_uint {
    return BN_num_bits((*rsa).n);
}
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_n(mut rsa: *const RSA) -> *const BIGNUM {
    return (*rsa).n;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_e(mut rsa: *const RSA) -> *const BIGNUM {
    return (*rsa).e;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_d(mut rsa: *const RSA) -> *const BIGNUM {
    return (*rsa).d;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_p(mut rsa: *const RSA) -> *const BIGNUM {
    return (*rsa).p;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_q(mut rsa: *const RSA) -> *const BIGNUM {
    return (*rsa).q;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_dmp1(mut rsa: *const RSA) -> *const BIGNUM {
    return (*rsa).dmp1;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_dmq1(mut rsa: *const RSA) -> *const BIGNUM {
    return (*rsa).dmq1;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_iqmp(mut rsa: *const RSA) -> *const BIGNUM {
    return (*rsa).iqmp;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_key(
    mut rsa: *const RSA,
    mut out_n: *mut *const BIGNUM,
    mut out_e: *mut *const BIGNUM,
    mut out_d: *mut *const BIGNUM,
) {
    if !out_n.is_null() {
        *out_n = (*rsa).n;
    }
    if !out_e.is_null() {
        *out_e = (*rsa).e;
    }
    if !out_d.is_null() {
        *out_d = (*rsa).d;
    }
}
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_factors(
    mut rsa: *const RSA,
    mut out_p: *mut *const BIGNUM,
    mut out_q: *mut *const BIGNUM,
) {
    if !out_p.is_null() {
        *out_p = (*rsa).p;
    }
    if !out_q.is_null() {
        *out_q = (*rsa).q;
    }
}
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_pss_params(
    mut rsa: *const RSA,
) -> *const RSA_PSS_PARAMS {
    return 0 as *const RSA_PSS_PARAMS;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_get0_crt_params(
    mut rsa: *const RSA,
    mut out_dmp1: *mut *const BIGNUM,
    mut out_dmq1: *mut *const BIGNUM,
    mut out_iqmp: *mut *const BIGNUM,
) {
    if !out_dmp1.is_null() {
        *out_dmp1 = (*rsa).dmp1;
    }
    if !out_dmq1.is_null() {
        *out_dmq1 = (*rsa).dmq1;
    }
    if !out_iqmp.is_null() {
        *out_iqmp = (*rsa).iqmp;
    }
}
#[no_mangle]
pub unsafe extern "C" fn RSA_set0_key(
    mut rsa: *mut RSA,
    mut n: *mut BIGNUM,
    mut e: *mut BIGNUM,
    mut d: *mut BIGNUM,
) -> libc::c_int {
    if ((*rsa).n).is_null() && n.is_null()
        || ((*rsa).e).is_null() && e.is_null() && ((*rsa).d).is_null() && d.is_null()
    {
        return 0 as libc::c_int;
    }
    if !n.is_null() {
        BN_free((*rsa).n);
        (*rsa).n = n;
    }
    if !e.is_null() {
        BN_free((*rsa).e);
        (*rsa).e = e;
    }
    if !d.is_null() {
        BN_free((*rsa).d);
        (*rsa).d = d;
    }
    rsa_invalidate_key(rsa);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_set0_factors(
    mut rsa: *mut RSA,
    mut p: *mut BIGNUM,
    mut q: *mut BIGNUM,
) -> libc::c_int {
    if ((*rsa).p).is_null() && p.is_null() || ((*rsa).q).is_null() && q.is_null() {
        return 0 as libc::c_int;
    }
    if !p.is_null() {
        BN_free((*rsa).p);
        (*rsa).p = p;
    }
    if !q.is_null() {
        BN_free((*rsa).q);
        (*rsa).q = q;
    }
    rsa_invalidate_key(rsa);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_set0_crt_params(
    mut rsa: *mut RSA,
    mut dmp1: *mut BIGNUM,
    mut dmq1: *mut BIGNUM,
    mut iqmp: *mut BIGNUM,
) -> libc::c_int {
    if ((*rsa).dmp1).is_null() && dmp1.is_null()
        || ((*rsa).dmq1).is_null() && dmq1.is_null()
        || ((*rsa).iqmp).is_null() && iqmp.is_null()
    {
        return 0 as libc::c_int;
    }
    if !dmp1.is_null() {
        BN_free((*rsa).dmp1);
        (*rsa).dmp1 = dmp1;
    }
    if !dmq1.is_null() {
        BN_free((*rsa).dmq1);
        (*rsa).dmq1 = dmq1;
    }
    if !iqmp.is_null() {
        BN_free((*rsa).iqmp);
        (*rsa).iqmp = iqmp;
    }
    rsa_invalidate_key(rsa);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_new(
    mut name: *const libc::c_char,
    mut flags: libc::c_int,
) -> *mut RSA_METHOD {
    let mut meth: *mut RSA_METHOD = OPENSSL_zalloc(
        ::core::mem::size_of::<RSA_METHOD>() as libc::c_ulong,
    ) as *mut RSA_METHOD;
    if meth.is_null() {
        return 0 as *mut RSA_METHOD;
    }
    if flags == 1 as libc::c_int {
        (*meth).flags = flags;
    }
    return meth;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_set_method(
    mut rsa: *mut RSA,
    mut meth: *const RSA_METHOD,
) -> libc::c_int {
    if rsa.is_null() || meth.is_null() {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            468 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*rsa).meth = meth;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_get_method(mut rsa: *const RSA) -> *const RSA_METHOD {
    if rsa.is_null() {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            478 as libc::c_int as libc::c_uint,
        );
        return 0 as *const RSA_METHOD;
    }
    return (*rsa).meth;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_free(mut meth: *mut RSA_METHOD) {
    if !meth.is_null() {
        OPENSSL_free(meth as *mut libc::c_void);
    }
}
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_set_init(
    mut meth: *mut RSA_METHOD,
    mut init: Option::<unsafe extern "C" fn(*mut RSA) -> libc::c_int>,
) -> libc::c_int {
    if meth.is_null() {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            494 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*meth).init = init;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_set_finish(
    mut meth: *mut RSA_METHOD,
    mut finish: Option::<unsafe extern "C" fn(*mut RSA) -> libc::c_int>,
) -> libc::c_int {
    if meth.is_null() {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            504 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*meth).finish = finish;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_set_priv_dec(
    mut meth: *mut RSA_METHOD,
    mut priv_dec: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            *mut uint8_t,
            *mut RSA,
            libc::c_int,
        ) -> libc::c_int,
    >,
) -> libc::c_int {
    if meth.is_null() {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            517 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*meth).decrypt = priv_dec;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_set_priv_enc(
    mut meth: *mut RSA_METHOD,
    mut priv_enc: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            *mut uint8_t,
            *mut RSA,
            libc::c_int,
        ) -> libc::c_int,
    >,
) -> libc::c_int {
    if meth.is_null() {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            530 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*meth).sign_raw = priv_enc;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_set_pub_dec(
    mut meth: *mut RSA_METHOD,
    mut pub_dec: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            *mut uint8_t,
            *mut RSA,
            libc::c_int,
        ) -> libc::c_int,
    >,
) -> libc::c_int {
    if meth.is_null() {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            543 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*meth).verify_raw = pub_dec;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_set_pub_enc(
    mut meth: *mut RSA_METHOD,
    mut pub_enc: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            *mut uint8_t,
            *mut RSA,
            libc::c_int,
        ) -> libc::c_int,
    >,
) -> libc::c_int {
    if meth.is_null() {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            556 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*meth).encrypt = pub_enc;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_set0_app_data(
    mut meth: *mut RSA_METHOD,
    mut app_data: *mut libc::c_void,
) -> libc::c_int {
    if meth.is_null() {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            566 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*meth).app_data = app_data;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_meth_set_sign(
    mut meth: *mut RSA_METHOD,
    mut sign: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const libc::c_uchar,
            libc::c_uint,
            *mut libc::c_uchar,
            *mut libc::c_uint,
            *const RSA,
        ) -> libc::c_int,
    >,
) -> libc::c_int {
    if meth.is_null() {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            578 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*meth).sign = sign;
    return 1 as libc::c_int;
}
unsafe extern "C" fn rsa_sign_raw_no_self_test(
    mut rsa: *mut RSA,
    mut out_len: *mut size_t,
    mut out: *mut uint8_t,
    mut max_out: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut padding: libc::c_int,
) -> libc::c_int {
    if !((*rsa).meth).is_null() && ((*(*rsa).meth).sign_raw).is_some() {
        let mut ret: libc::c_int = ((*(*rsa).meth).sign_raw)
            .expect(
                "non-null function pointer",
            )(max_out as libc::c_int, in_0, out, rsa, padding);
        if ret < 0 as libc::c_int {
            *out_len = 0 as libc::c_int as size_t;
            return 0 as libc::c_int;
        }
        *out_len = ret as size_t;
        return 1 as libc::c_int;
    }
    return rsa_default_sign_raw(rsa, out_len, out, max_out, in_0, in_len, padding);
}
#[no_mangle]
pub unsafe extern "C" fn RSA_sign_raw(
    mut rsa: *mut RSA,
    mut out_len: *mut size_t,
    mut out: *mut uint8_t,
    mut max_out: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut padding: libc::c_int,
) -> libc::c_int {
    boringssl_ensure_rsa_self_test();
    return rsa_sign_raw_no_self_test(rsa, out_len, out, max_out, in_0, in_len, padding);
}
#[no_mangle]
pub unsafe extern "C" fn RSA_size(mut rsa: *const RSA) -> libc::c_uint {
    let mut ret: size_t = if !((*rsa).meth).is_null() && ((*(*rsa).meth).size).is_some()
    {
        ((*(*rsa).meth).size).expect("non-null function pointer")(rsa)
    } else {
        rsa_default_size(rsa)
    };
    if ret
        < (2147483647 as libc::c_int as libc::c_uint)
            .wrapping_mul(2 as libc::c_uint)
            .wrapping_add(1 as libc::c_uint) as size_t
    {} else {
        __assert_fail(
            b"ret < UINT_MAX\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            626 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 35],
                &[libc::c_char; 35],
            >(b"unsigned int RSA_size(const RSA *)\0"))
                .as_ptr(),
        );
    }
    'c_8066: {
        if ret
            < (2147483647 as libc::c_int as libc::c_uint)
                .wrapping_mul(2 as libc::c_uint)
                .wrapping_add(1 as libc::c_uint) as size_t
        {} else {
            __assert_fail(
                b"ret < UINT_MAX\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                    as *const u8 as *const libc::c_char,
                626 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 35],
                    &[libc::c_char; 35],
                >(b"unsigned int RSA_size(const RSA *)\0"))
                    .as_ptr(),
            );
        }
    };
    return ret as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_is_opaque(mut rsa: *const RSA) -> libc::c_int {
    return (!((*rsa).meth).is_null() && (*(*rsa).meth).flags & 1 as libc::c_int != 0)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_get_ex_new_index(
    mut argl: libc::c_long,
    mut argp: *mut libc::c_void,
    mut unused: *mut CRYPTO_EX_unused,
    mut dup_unused: Option::<CRYPTO_EX_dup>,
    mut free_func: Option::<CRYPTO_EX_free>,
) -> libc::c_int {
    let mut index: libc::c_int = 0;
    if CRYPTO_get_ex_new_index(
        g_rsa_ex_data_class_bss_get(),
        &mut index,
        argl,
        argp,
        free_func,
    ) == 0
    {
        return -(1 as libc::c_int);
    }
    return index;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_set_ex_data(
    mut rsa: *mut RSA,
    mut idx: libc::c_int,
    mut arg: *mut libc::c_void,
) -> libc::c_int {
    return CRYPTO_set_ex_data(&mut (*rsa).ex_data, idx, arg);
}
#[no_mangle]
pub unsafe extern "C" fn RSA_get_ex_data(
    mut rsa: *const RSA,
    mut idx: libc::c_int,
) -> *mut libc::c_void {
    return CRYPTO_get_ex_data(&(*rsa).ex_data, idx);
}
static mut SSL_SIG_LENGTH: libc::c_uint = 36 as libc::c_int as libc::c_uint;
static mut kPKCS1SigPrefixes: [pkcs1_sig_prefix; 13] = [
    {
        let mut init = pkcs1_sig_prefix {
            nid: 4 as libc::c_int,
            hash_len: 16 as libc::c_int as uint8_t,
            len: 18 as libc::c_int as uint8_t,
            bytes: [
                0x30 as libc::c_int as uint8_t,
                0x20 as libc::c_int as uint8_t,
                0x30 as libc::c_int as uint8_t,
                0xc as libc::c_int as uint8_t,
                0x6 as libc::c_int as uint8_t,
                0x8 as libc::c_int as uint8_t,
                0x2a as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0xf7 as libc::c_int as uint8_t,
                0xd as libc::c_int as uint8_t,
                0x2 as libc::c_int as uint8_t,
                0x5 as libc::c_int as uint8_t,
                0x5 as libc::c_int as uint8_t,
                0 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x10 as libc::c_int as uint8_t,
                0,
            ],
        };
        init
    },
    {
        let mut init = pkcs1_sig_prefix {
            nid: 64 as libc::c_int,
            hash_len: 20 as libc::c_int as uint8_t,
            len: 15 as libc::c_int as uint8_t,
            bytes: [
                0x30 as libc::c_int as uint8_t,
                0x21 as libc::c_int as uint8_t,
                0x30 as libc::c_int as uint8_t,
                0x9 as libc::c_int as uint8_t,
                0x6 as libc::c_int as uint8_t,
                0x5 as libc::c_int as uint8_t,
                0x2b as libc::c_int as uint8_t,
                0xe as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0x2 as libc::c_int as uint8_t,
                0x1a as libc::c_int as uint8_t,
                0x5 as libc::c_int as uint8_t,
                0 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x14 as libc::c_int as uint8_t,
                0,
                0,
                0,
                0,
            ],
        };
        init
    },
    {
        let mut init = pkcs1_sig_prefix {
            nid: 675 as libc::c_int,
            hash_len: 28 as libc::c_int as uint8_t,
            len: 19 as libc::c_int as uint8_t,
            bytes: [
                0x30 as libc::c_int as uint8_t,
                0x2d as libc::c_int as uint8_t,
                0x30 as libc::c_int as uint8_t,
                0xd as libc::c_int as uint8_t,
                0x6 as libc::c_int as uint8_t,
                0x9 as libc::c_int as uint8_t,
                0x60 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x65 as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x2 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x5 as libc::c_int as uint8_t,
                0 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x1c as libc::c_int as uint8_t,
            ],
        };
        init
    },
    {
        let mut init = pkcs1_sig_prefix {
            nid: 672 as libc::c_int,
            hash_len: 32 as libc::c_int as uint8_t,
            len: 19 as libc::c_int as uint8_t,
            bytes: [
                0x30 as libc::c_int as uint8_t,
                0x31 as libc::c_int as uint8_t,
                0x30 as libc::c_int as uint8_t,
                0xd as libc::c_int as uint8_t,
                0x6 as libc::c_int as uint8_t,
                0x9 as libc::c_int as uint8_t,
                0x60 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x65 as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x2 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x5 as libc::c_int as uint8_t,
                0 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x20 as libc::c_int as uint8_t,
            ],
        };
        init
    },
    {
        let mut init = pkcs1_sig_prefix {
            nid: 673 as libc::c_int,
            hash_len: 48 as libc::c_int as uint8_t,
            len: 19 as libc::c_int as uint8_t,
            bytes: [
                0x30 as libc::c_int as uint8_t,
                0x41 as libc::c_int as uint8_t,
                0x30 as libc::c_int as uint8_t,
                0xd as libc::c_int as uint8_t,
                0x6 as libc::c_int as uint8_t,
                0x9 as libc::c_int as uint8_t,
                0x60 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x65 as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x2 as libc::c_int as uint8_t,
                0x2 as libc::c_int as uint8_t,
                0x5 as libc::c_int as uint8_t,
                0 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x30 as libc::c_int as uint8_t,
            ],
        };
        init
    },
    {
        let mut init = pkcs1_sig_prefix {
            nid: 674 as libc::c_int,
            hash_len: 64 as libc::c_int as uint8_t,
            len: 19 as libc::c_int as uint8_t,
            bytes: [
                0x30 as libc::c_int as uint8_t,
                0x51 as libc::c_int as uint8_t,
                0x30 as libc::c_int as uint8_t,
                0xd as libc::c_int as uint8_t,
                0x6 as libc::c_int as uint8_t,
                0x9 as libc::c_int as uint8_t,
                0x60 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x65 as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x2 as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0x5 as libc::c_int as uint8_t,
                0 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x40 as libc::c_int as uint8_t,
            ],
        };
        init
    },
    {
        let mut init = pkcs1_sig_prefix {
            nid: 978 as libc::c_int,
            hash_len: 28 as libc::c_int as uint8_t,
            len: 19 as libc::c_int as uint8_t,
            bytes: [
                0x30 as libc::c_int as uint8_t,
                0x2d as libc::c_int as uint8_t,
                0x30 as libc::c_int as uint8_t,
                0xd as libc::c_int as uint8_t,
                0x6 as libc::c_int as uint8_t,
                0x9 as libc::c_int as uint8_t,
                0x60 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x65 as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x2 as libc::c_int as uint8_t,
                0x5 as libc::c_int as uint8_t,
                0x5 as libc::c_int as uint8_t,
                0 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x1c as libc::c_int as uint8_t,
            ],
        };
        init
    },
    {
        let mut init = pkcs1_sig_prefix {
            nid: 962 as libc::c_int,
            hash_len: 32 as libc::c_int as uint8_t,
            len: 19 as libc::c_int as uint8_t,
            bytes: [
                0x30 as libc::c_int as uint8_t,
                0x31 as libc::c_int as uint8_t,
                0x30 as libc::c_int as uint8_t,
                0xd as libc::c_int as uint8_t,
                0x6 as libc::c_int as uint8_t,
                0x9 as libc::c_int as uint8_t,
                0x60 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x65 as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x2 as libc::c_int as uint8_t,
                0x6 as libc::c_int as uint8_t,
                0x5 as libc::c_int as uint8_t,
                0 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x20 as libc::c_int as uint8_t,
            ],
        };
        init
    },
    {
        let mut init = pkcs1_sig_prefix {
            nid: 965 as libc::c_int,
            hash_len: 28 as libc::c_int as uint8_t,
            len: 19 as libc::c_int as uint8_t,
            bytes: [
                0x30 as libc::c_int as uint8_t,
                0x2d as libc::c_int as uint8_t,
                0x30 as libc::c_int as uint8_t,
                0xd as libc::c_int as uint8_t,
                0x6 as libc::c_int as uint8_t,
                0x9 as libc::c_int as uint8_t,
                0x60 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x65 as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x2 as libc::c_int as uint8_t,
                0x7 as libc::c_int as uint8_t,
                0x5 as libc::c_int as uint8_t,
                0 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x1c as libc::c_int as uint8_t,
            ],
        };
        init
    },
    {
        let mut init = pkcs1_sig_prefix {
            nid: 966 as libc::c_int,
            hash_len: 32 as libc::c_int as uint8_t,
            len: 19 as libc::c_int as uint8_t,
            bytes: [
                0x30 as libc::c_int as uint8_t,
                0x31 as libc::c_int as uint8_t,
                0x30 as libc::c_int as uint8_t,
                0xd as libc::c_int as uint8_t,
                0x6 as libc::c_int as uint8_t,
                0x9 as libc::c_int as uint8_t,
                0x60 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x65 as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x2 as libc::c_int as uint8_t,
                0x8 as libc::c_int as uint8_t,
                0x5 as libc::c_int as uint8_t,
                0 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x20 as libc::c_int as uint8_t,
            ],
        };
        init
    },
    {
        let mut init = pkcs1_sig_prefix {
            nid: 967 as libc::c_int,
            hash_len: 48 as libc::c_int as uint8_t,
            len: 19 as libc::c_int as uint8_t,
            bytes: [
                0x30 as libc::c_int as uint8_t,
                0x41 as libc::c_int as uint8_t,
                0x30 as libc::c_int as uint8_t,
                0xd as libc::c_int as uint8_t,
                0x6 as libc::c_int as uint8_t,
                0x9 as libc::c_int as uint8_t,
                0x60 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x65 as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x2 as libc::c_int as uint8_t,
                0x9 as libc::c_int as uint8_t,
                0x5 as libc::c_int as uint8_t,
                0 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x30 as libc::c_int as uint8_t,
            ],
        };
        init
    },
    {
        let mut init = pkcs1_sig_prefix {
            nid: 968 as libc::c_int,
            hash_len: 64 as libc::c_int as uint8_t,
            len: 19 as libc::c_int as uint8_t,
            bytes: [
                0x30 as libc::c_int as uint8_t,
                0x51 as libc::c_int as uint8_t,
                0x30 as libc::c_int as uint8_t,
                0xd as libc::c_int as uint8_t,
                0x6 as libc::c_int as uint8_t,
                0x9 as libc::c_int as uint8_t,
                0x60 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x65 as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x2 as libc::c_int as uint8_t,
                0xa as libc::c_int as uint8_t,
                0x5 as libc::c_int as uint8_t,
                0 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x40 as libc::c_int as uint8_t,
            ],
        };
        init
    },
    {
        let mut init = pkcs1_sig_prefix {
            nid: 0 as libc::c_int,
            hash_len: 0 as libc::c_int as uint8_t,
            len: 0 as libc::c_int as uint8_t,
            bytes: [
                0 as libc::c_int as uint8_t,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
        };
        init
    },
];
unsafe extern "C" fn rsa_check_digest_size(
    mut hash_nid: libc::c_int,
    mut digest_len: size_t,
) -> libc::c_int {
    if hash_nid == 114 as libc::c_int {
        if digest_len != SSL_SIG_LENGTH as size_t {
            ERR_put_error(
                4 as libc::c_int,
                0 as libc::c_int,
                125 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                    as *const u8 as *const libc::c_char,
                769 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        return 1 as libc::c_int;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while kPKCS1SigPrefixes[i as usize].nid != 0 as libc::c_int {
        let mut sig_prefix: *const pkcs1_sig_prefix = &*kPKCS1SigPrefixes
            .as_ptr()
            .offset(i as isize) as *const pkcs1_sig_prefix;
        if (*sig_prefix).nid == hash_nid {
            if digest_len != (*sig_prefix).hash_len as size_t {
                ERR_put_error(
                    4 as libc::c_int,
                    0 as libc::c_int,
                    125 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                        as *const u8 as *const libc::c_char,
                    779 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            return 1 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    ERR_put_error(
        4 as libc::c_int,
        0 as libc::c_int,
        142 as libc::c_int,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0" as *const u8
            as *const libc::c_char,
        786 as libc::c_int as libc::c_uint,
    );
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_add_pkcs1_prefix(
    mut out_msg: *mut *mut uint8_t,
    mut out_msg_len: *mut size_t,
    mut is_alloced: *mut libc::c_int,
    mut hash_nid: libc::c_int,
    mut digest: *const uint8_t,
    mut digest_len: size_t,
) -> libc::c_int {
    if rsa_check_digest_size(hash_nid, digest_len) == 0 {
        return 0 as libc::c_int;
    }
    if hash_nid == 114 as libc::c_int {
        if digest_len == SSL_SIG_LENGTH as size_t {} else {
            __assert_fail(
                b"digest_len == SSL_SIG_LENGTH\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                    as *const u8 as *const libc::c_char,
                800 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 84],
                    &[libc::c_char; 84],
                >(
                    b"int RSA_add_pkcs1_prefix(uint8_t **, size_t *, int *, int, const uint8_t *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_9109: {
            if digest_len == SSL_SIG_LENGTH as size_t {} else {
                __assert_fail(
                    b"digest_len == SSL_SIG_LENGTH\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                        as *const u8 as *const libc::c_char,
                    800 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 84],
                        &[libc::c_char; 84],
                    >(
                        b"int RSA_add_pkcs1_prefix(uint8_t **, size_t *, int *, int, const uint8_t *, size_t)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        *out_msg = digest as *mut uint8_t;
        *out_msg_len = digest_len;
        *is_alloced = 0 as libc::c_int;
        return 1 as libc::c_int;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while kPKCS1SigPrefixes[i as usize].nid != 0 as libc::c_int {
        let mut sig_prefix: *const pkcs1_sig_prefix = &*kPKCS1SigPrefixes
            .as_ptr()
            .offset(i as isize) as *const pkcs1_sig_prefix;
        if (*sig_prefix).nid != hash_nid {
            i = i.wrapping_add(1);
            i;
        } else {
            if digest_len == (*sig_prefix).hash_len as size_t {} else {
                __assert_fail(
                    b"digest_len == sig_prefix->hash_len\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                        as *const u8 as *const libc::c_char,
                    814 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 84],
                        &[libc::c_char; 84],
                    >(
                        b"int RSA_add_pkcs1_prefix(uint8_t **, size_t *, int *, int, const uint8_t *, size_t)\0",
                    ))
                        .as_ptr(),
                );
            }
            'c_9020: {
                if digest_len == (*sig_prefix).hash_len as size_t {} else {
                    __assert_fail(
                        b"digest_len == sig_prefix->hash_len\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                            as *const u8 as *const libc::c_char,
                        814 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 84],
                            &[libc::c_char; 84],
                        >(
                            b"int RSA_add_pkcs1_prefix(uint8_t **, size_t *, int *, int, const uint8_t *, size_t)\0",
                        ))
                            .as_ptr(),
                    );
                }
            };
            let mut prefix: *const uint8_t = ((*sig_prefix).bytes).as_ptr();
            let mut prefix_len: size_t = (*sig_prefix).len as size_t;
            let mut signed_msg_len: size_t = prefix_len.wrapping_add(digest_len);
            if signed_msg_len < prefix_len {
                ERR_put_error(
                    4 as libc::c_int,
                    0 as libc::c_int,
                    140 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                        as *const u8 as *const libc::c_char,
                    819 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            let mut signed_msg: *mut uint8_t = OPENSSL_malloc(signed_msg_len)
                as *mut uint8_t;
            if signed_msg.is_null() {
                return 0 as libc::c_int;
            }
            OPENSSL_memcpy(
                signed_msg as *mut libc::c_void,
                prefix as *const libc::c_void,
                prefix_len,
            );
            OPENSSL_memcpy(
                signed_msg.offset(prefix_len as isize) as *mut libc::c_void,
                digest as *const libc::c_void,
                digest_len,
            );
            *out_msg = signed_msg;
            *out_msg_len = signed_msg_len;
            *is_alloced = 1 as libc::c_int;
            return 1 as libc::c_int;
        }
    }
    ERR_put_error(
        4 as libc::c_int,
        0 as libc::c_int,
        142 as libc::c_int,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0" as *const u8
            as *const libc::c_char,
        838 as libc::c_int as libc::c_uint,
    );
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn rsa_sign_no_self_test(
    mut hash_nid: libc::c_int,
    mut digest: *const uint8_t,
    mut digest_len: size_t,
    mut out: *mut uint8_t,
    mut out_len: *mut libc::c_uint,
    mut rsa: *mut RSA,
) -> libc::c_int {
    if !((*rsa).meth).is_null() && ((*(*rsa).meth).sign).is_some() {
        if rsa_check_digest_size(hash_nid, digest_len) == 0 {
            return 0 as libc::c_int;
        }
        if digest_len <= 64 as libc::c_int as size_t {} else {
            __assert_fail(
                b"digest_len <= EVP_MAX_MD_SIZE\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                    as *const u8 as *const libc::c_char,
                850 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 90],
                    &[libc::c_char; 90],
                >(
                    b"int rsa_sign_no_self_test(int, const uint8_t *, size_t, uint8_t *, unsigned int *, RSA *)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_9308: {
            if digest_len <= 64 as libc::c_int as size_t {} else {
                __assert_fail(
                    b"digest_len <= EVP_MAX_MD_SIZE\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                        as *const u8 as *const libc::c_char,
                    850 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 90],
                        &[libc::c_char; 90],
                    >(
                        b"int rsa_sign_no_self_test(int, const uint8_t *, size_t, uint8_t *, unsigned int *, RSA *)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        return ((*(*rsa).meth).sign)
            .expect(
                "non-null function pointer",
            )(hash_nid, digest, digest_len as libc::c_uint, out, out_len, rsa);
    }
    let rsa_size: libc::c_uint = RSA_size(rsa);
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut signed_msg: *mut uint8_t = 0 as *mut uint8_t;
    let mut signed_msg_len: size_t = 0 as libc::c_int as size_t;
    let mut signed_msg_is_alloced: libc::c_int = 0 as libc::c_int;
    let mut size_t_out_len: size_t = 0;
    if !(RSA_add_pkcs1_prefix(
        &mut signed_msg,
        &mut signed_msg_len,
        &mut signed_msg_is_alloced,
        hash_nid,
        digest,
        digest_len,
    ) == 0
        || rsa_sign_raw_no_self_test(
            rsa,
            &mut size_t_out_len,
            out,
            rsa_size as size_t,
            signed_msg,
            signed_msg_len,
            1 as libc::c_int,
        ) == 0)
    {
        if size_t_out_len
            > (2147483647 as libc::c_int as libc::c_uint)
                .wrapping_mul(2 as libc::c_uint)
                .wrapping_add(1 as libc::c_uint) as size_t
        {
            ERR_put_error(
                4 as libc::c_int,
                0 as libc::c_int,
                5 as libc::c_int | 64 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                    as *const u8 as *const libc::c_char,
                872 as libc::c_int as libc::c_uint,
            );
        } else {
            *out_len = size_t_out_len as libc::c_uint;
            ret = 1 as libc::c_int;
        }
    }
    if signed_msg_is_alloced != 0 {
        OPENSSL_free(signed_msg as *mut libc::c_void);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_sign(
    mut hash_nid: libc::c_int,
    mut digest: *const uint8_t,
    mut digest_len: size_t,
    mut out: *mut uint8_t,
    mut out_len: *mut libc::c_uint,
    mut rsa: *mut RSA,
) -> libc::c_int {
    boringssl_ensure_rsa_self_test();
    return rsa_sign_no_self_test(hash_nid, digest, digest_len, out, out_len, rsa);
}
#[no_mangle]
pub unsafe extern "C" fn RSA_sign_pss_mgf1(
    mut rsa: *mut RSA,
    mut out_len: *mut size_t,
    mut out: *mut uint8_t,
    mut max_out: size_t,
    mut digest: *const uint8_t,
    mut digest_len: size_t,
    mut md: *const EVP_MD,
    mut mgf1_md: *const EVP_MD,
    mut salt_len: libc::c_int,
) -> libc::c_int {
    if digest_len != EVP_MD_size(md) {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            899 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut padded_len: size_t = RSA_size(rsa) as size_t;
    let mut padded: *mut uint8_t = OPENSSL_malloc(padded_len) as *mut uint8_t;
    if padded.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = (RSA_padding_add_PKCS1_PSS_mgf1(
        rsa,
        padded,
        digest,
        md,
        mgf1_md,
        salt_len,
    ) != 0
        && RSA_sign_raw(rsa, out_len, out, max_out, padded, padded_len, 3 as libc::c_int)
            != 0) as libc::c_int;
    OPENSSL_free(padded as *mut libc::c_void);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn rsa_digestsign_no_self_test(
    mut md: *const EVP_MD,
    mut input: *const uint8_t,
    mut in_len: size_t,
    mut out: *mut uint8_t,
    mut out_len: *mut libc::c_uint,
    mut rsa: *mut RSA,
) -> libc::c_int {
    let mut digest: [uint8_t; 64] = [0; 64];
    let mut digest_len: libc::c_uint = 64 as libc::c_int as libc::c_uint;
    if EVP_Digest(
        input as *const libc::c_void,
        in_len,
        digest.as_mut_ptr(),
        &mut digest_len,
        md,
        0 as *mut ENGINE,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    return rsa_sign_no_self_test(
        EVP_MD_type(md),
        digest.as_mut_ptr(),
        digest_len as size_t,
        out,
        out_len,
        rsa,
    );
}
#[no_mangle]
pub unsafe extern "C" fn rsa_verify_no_self_test(
    mut hash_nid: libc::c_int,
    mut digest: *const uint8_t,
    mut digest_len: size_t,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
    mut rsa: *mut RSA,
) -> libc::c_int {
    if ((*rsa).n).is_null() || ((*rsa).e).is_null() {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            144 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            936 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let rsa_size: size_t = RSA_size(rsa) as size_t;
    let mut buf: *mut uint8_t = 0 as *mut uint8_t;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut signed_msg: *mut uint8_t = 0 as *mut uint8_t;
    let mut signed_msg_len: size_t = 0 as libc::c_int as size_t;
    let mut len: size_t = 0;
    let mut signed_msg_is_alloced: libc::c_int = 0 as libc::c_int;
    if hash_nid == 114 as libc::c_int && digest_len != SSL_SIG_LENGTH as size_t {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            948 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    buf = OPENSSL_malloc(rsa_size) as *mut uint8_t;
    if buf.is_null() {
        return 0 as libc::c_int;
    }
    if !(rsa_verify_raw_no_self_test(
        rsa,
        &mut len,
        buf,
        rsa_size,
        sig,
        sig_len,
        1 as libc::c_int,
    ) == 0
        || RSA_add_pkcs1_prefix(
            &mut signed_msg,
            &mut signed_msg_len,
            &mut signed_msg_is_alloced,
            hash_nid,
            digest,
            digest_len,
        ) == 0)
    {
        if len != signed_msg_len {
            ERR_put_error(
                4 as libc::c_int,
                0 as libc::c_int,
                105 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                    as *const u8 as *const libc::c_char,
                967 as libc::c_int as libc::c_uint,
            );
        } else if OPENSSL_memcmp(
            buf as *const libc::c_void,
            signed_msg as *const libc::c_void,
            len,
        ) != 0 as libc::c_int
        {
            ERR_put_error(
                4 as libc::c_int,
                0 as libc::c_int,
                248 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                    as *const u8 as *const libc::c_char,
                973 as libc::c_int as libc::c_uint,
            );
        } else {
            ret = 1 as libc::c_int;
        }
    }
    OPENSSL_free(buf as *mut libc::c_void);
    if signed_msg_is_alloced != 0 {
        OPENSSL_free(signed_msg as *mut libc::c_void);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn rsa_digestverify_no_self_test(
    mut md: *const EVP_MD,
    mut input: *const uint8_t,
    mut in_len: size_t,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
    mut rsa: *mut RSA,
) -> libc::c_int {
    let mut digest: [uint8_t; 64] = [0; 64];
    let mut digest_len: libc::c_uint = 64 as libc::c_int as libc::c_uint;
    if EVP_Digest(
        input as *const libc::c_void,
        in_len,
        digest.as_mut_ptr(),
        &mut digest_len,
        md,
        0 as *mut ENGINE,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    return rsa_verify_no_self_test(
        EVP_MD_type(md),
        digest.as_mut_ptr(),
        digest_len as size_t,
        sig,
        sig_len,
        rsa,
    );
}
#[no_mangle]
pub unsafe extern "C" fn RSA_verify(
    mut hash_nid: libc::c_int,
    mut digest: *const uint8_t,
    mut digest_len: size_t,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
    mut rsa: *mut RSA,
) -> libc::c_int {
    boringssl_ensure_rsa_self_test();
    return rsa_verify_no_self_test(hash_nid, digest, digest_len, sig, sig_len, rsa);
}
#[no_mangle]
pub unsafe extern "C" fn RSA_verify_pss_mgf1(
    mut rsa: *mut RSA,
    mut digest: *const uint8_t,
    mut digest_len: size_t,
    mut md: *const EVP_MD,
    mut mgf1_md: *const EVP_MD,
    mut salt_len: libc::c_int,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
) -> libc::c_int {
    if digest_len != EVP_MD_size(md) {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            1013 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut em_len: size_t = RSA_size(rsa) as size_t;
    let mut em: *mut uint8_t = OPENSSL_malloc(em_len) as *mut uint8_t;
    if em.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    if !(RSA_verify_raw(rsa, &mut em_len, em, em_len, sig, sig_len, 3 as libc::c_int)
        == 0)
    {
        if em_len != RSA_size(rsa) as size_t {
            ERR_put_error(
                4 as libc::c_int,
                0 as libc::c_int,
                4 as libc::c_int | 64 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                    as *const u8 as *const libc::c_char,
                1029 as libc::c_int as libc::c_uint,
            );
        } else {
            ret = RSA_verify_PKCS1_PSS_mgf1(rsa, digest, md, mgf1_md, em, salt_len);
        }
    }
    OPENSSL_free(em as *mut libc::c_void);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn rsa_private_transform_no_self_test(
    mut rsa: *mut RSA,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    if !((*rsa).meth).is_null() && ((*(*rsa).meth).private_transform).is_some() {
        return ((*(*rsa).meth).private_transform)
            .expect("non-null function pointer")(rsa, out, in_0, len);
    }
    return rsa_default_private_transform(rsa, out, in_0, len);
}
#[no_mangle]
pub unsafe extern "C" fn rsa_private_transform(
    mut rsa: *mut RSA,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    boringssl_ensure_rsa_self_test();
    return rsa_private_transform_no_self_test(rsa, out, in_0, len);
}
#[no_mangle]
pub unsafe extern "C" fn RSA_flags(mut rsa: *const RSA) -> libc::c_int {
    if rsa.is_null() {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            1059 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return (*rsa).flags;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_set_flags(mut rsa: *mut RSA, mut flags: libc::c_int) {
    if rsa.is_null() {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            1069 as libc::c_int as libc::c_uint,
        );
        return;
    }
    (*rsa).flags |= flags;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_test_flags(
    mut rsa: *const RSA,
    mut flags: libc::c_int,
) -> libc::c_int {
    if !rsa.is_null() {
        return (*rsa).flags & flags;
    }
    ERR_put_error(
        4 as libc::c_int,
        0 as libc::c_int,
        3 as libc::c_int | 64 as libc::c_int,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0" as *const u8
            as *const libc::c_char,
        1082 as libc::c_int as libc::c_uint,
    );
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_blinding_on(
    mut rsa: *mut RSA,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    return if !rsa.is_null() && (*rsa).flags & 8 as libc::c_int == 0 as libc::c_int {
        1 as libc::c_int
    } else {
        0 as libc::c_int
    };
}
#[no_mangle]
pub unsafe extern "C" fn RSA_blinding_off_temp_for_accp_compatibility(
    mut rsa: *mut RSA,
) {
    if !rsa.is_null() {
        (*rsa).flags |= 8 as libc::c_int;
    }
}
#[no_mangle]
pub unsafe extern "C" fn RSA_pkey_ctx_ctrl(
    mut ctx: *mut EVP_PKEY_CTX,
    mut optype: libc::c_int,
    mut cmd: libc::c_int,
    mut p1: libc::c_int,
    mut p2: *mut libc::c_void,
) -> libc::c_int {
    if !ctx.is_null() && !((*ctx).pmeth).is_null() {
        if (*(*ctx).pmeth).pkey_id == 6 as libc::c_int
            || (*(*ctx).pmeth).pkey_id == 912 as libc::c_int
        {
            return EVP_PKEY_CTX_ctrl(ctx, -(1 as libc::c_int), optype, cmd, p1, p2);
        }
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn is_public_component_of_rsa_key_good(
    mut key: *const RSA,
) -> libc::c_int {
    if ((*key).n).is_null() {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            144 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            1126 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut n_bits: libc::c_uint = BN_num_bits((*key).n);
    if n_bits > (16 as libc::c_int * 1024 as libc::c_int) as libc::c_uint {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            128 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            1132 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if BN_is_odd((*key).n) == 0 || BN_is_negative((*key).n) != 0 {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            1139 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*key).e).is_null() {
        if (*key).flags & 0x40 as libc::c_int == 0 {
            ERR_put_error(
                4 as libc::c_int,
                0 as libc::c_int,
                144 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                    as *const u8 as *const libc::c_char,
                1148 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        return 1 as libc::c_int;
    }
    let mut e_bits: libc::c_uint = BN_num_bits((*key).e);
    if BN_is_odd((*key).e) == 0 || BN_is_negative((*key).e) != 0
        || e_bits < 2 as libc::c_int as libc::c_uint
    {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            1163 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*key).flags & 0x80 as libc::c_int != 0 {
        if BN_ucmp((*key).n, (*key).e) <= 0 as libc::c_int {
            ERR_put_error(
                4 as libc::c_int,
                0 as libc::c_int,
                101 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                    as *const u8 as *const libc::c_char,
                1171 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    } else if e_bits > 33 as libc::c_int as libc::c_uint {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            1181 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn determine_key_type_for_checking(
    mut key: *const RSA,
) -> rsa_key_type_for_checking {
    if ((*key).n).is_null() {
        return RSA_KEY_TYPE_FOR_CHECKING_INVALID;
    }
    if !((*key).e).is_null() && ((*key).d).is_null() && ((*key).p).is_null()
        && ((*key).q).is_null() && ((*key).dmp1).is_null() && ((*key).dmq1).is_null()
        && ((*key).iqmp).is_null()
    {
        return RSA_KEY_TYPE_FOR_CHECKING_PUBLIC;
    }
    if !((*key).e).is_null() && !((*key).d).is_null() && ((*key).p).is_null()
        && ((*key).q).is_null() && ((*key).dmp1).is_null() && ((*key).dmq1).is_null()
        && ((*key).iqmp).is_null()
    {
        return RSA_KEY_TYPE_FOR_CHECKING_PRIVATE_MIN;
    }
    if !((*key).e).is_null() && !((*key).d).is_null() && !((*key).p).is_null()
        && !((*key).q).is_null() && ((*key).dmp1).is_null() && ((*key).dmq1).is_null()
        && ((*key).iqmp).is_null()
    {
        return RSA_KEY_TYPE_FOR_CHECKING_PRIVATE;
    }
    if !((*key).e).is_null() && !((*key).d).is_null() && !((*key).p).is_null()
        && !((*key).q).is_null() && !((*key).dmp1).is_null() && !((*key).dmq1).is_null()
        && !((*key).iqmp).is_null()
    {
        return RSA_KEY_TYPE_FOR_CHECKING_PRIVATE_CRT;
    }
    if ((*key).e).is_null() && !((*key).d).is_null() && ((*key).p).is_null()
        && ((*key).q).is_null() && ((*key).dmp1).is_null() && ((*key).dmq1).is_null()
        && ((*key).iqmp).is_null()
    {
        return RSA_KEY_TYPE_FOR_CHECKING_PRIVATE_STRIP;
    }
    return RSA_KEY_TYPE_FOR_CHECKING_INVALID;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_check_key(mut key: *const RSA) -> libc::c_int {
    let mut pm1_bits: libc::c_uint = 0;
    let mut qm1_bits: libc::c_uint = 0;
    let mut key_type: rsa_key_type_for_checking = determine_key_type_for_checking(key);
    if key_type as libc::c_uint
        == RSA_KEY_TYPE_FOR_CHECKING_INVALID as libc::c_int as libc::c_uint
    {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            1277 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if is_public_component_of_rsa_key_good(key) == 0 {
        return 0 as libc::c_int;
    }
    if key_type as libc::c_uint
        == RSA_KEY_TYPE_FOR_CHECKING_PUBLIC as libc::c_int as libc::c_uint
        || key_type as libc::c_uint
            == RSA_KEY_TYPE_FOR_CHECKING_PRIVATE_MIN as libc::c_int as libc::c_uint
        || key_type as libc::c_uint
            == RSA_KEY_TYPE_FOR_CHECKING_PRIVATE_STRIP as libc::c_int as libc::c_uint
    {
        return 1 as libc::c_int;
    }
    if key_type as libc::c_uint
        != RSA_KEY_TYPE_FOR_CHECKING_PRIVATE as libc::c_int as libc::c_uint
        && key_type as libc::c_uint
            != RSA_KEY_TYPE_FOR_CHECKING_PRIVATE_CRT as libc::c_int as libc::c_uint
    {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            1298 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut ctx: *mut BN_CTX = BN_CTX_new();
    if ctx.is_null() {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            1306 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut tmp: BIGNUM = bignum_st {
        d: 0 as *mut BN_ULONG,
        width: 0,
        dmax: 0,
        neg: 0,
        flags: 0,
    };
    let mut de: BIGNUM = bignum_st {
        d: 0 as *mut BN_ULONG,
        width: 0,
        dmax: 0,
        neg: 0,
        flags: 0,
    };
    let mut pm1: BIGNUM = bignum_st {
        d: 0 as *mut BN_ULONG,
        width: 0,
        dmax: 0,
        neg: 0,
        flags: 0,
    };
    let mut qm1: BIGNUM = bignum_st {
        d: 0 as *mut BN_ULONG,
        width: 0,
        dmax: 0,
        neg: 0,
        flags: 0,
    };
    let mut dmp1: BIGNUM = bignum_st {
        d: 0 as *mut BN_ULONG,
        width: 0,
        dmax: 0,
        neg: 0,
        flags: 0,
    };
    let mut dmq1: BIGNUM = bignum_st {
        d: 0 as *mut BN_ULONG,
        width: 0,
        dmax: 0,
        neg: 0,
        flags: 0,
    };
    BN_init(&mut tmp);
    BN_init(&mut de);
    BN_init(&mut pm1);
    BN_init(&mut qm1);
    BN_init(&mut dmp1);
    BN_init(&mut dmq1);
    if BN_is_negative((*key).p) != 0
        || constant_time_declassify_int(
            (BN_cmp((*key).p, (*key).n) >= 0 as libc::c_int) as libc::c_int,
        ) != 0 || BN_is_negative((*key).q) != 0
        || constant_time_declassify_int(
            (BN_cmp((*key).q, (*key).n) >= 0 as libc::c_int) as libc::c_int,
        ) != 0
    {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            1327 as libc::c_int as libc::c_uint,
        );
    } else if bn_mul_consttime(&mut tmp, (*key).p, (*key).q, ctx) == 0 {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            1331 as libc::c_int as libc::c_uint,
        );
    } else if BN_cmp(&mut tmp, (*key).n) != 0 as libc::c_int {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            132 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            1335 as libc::c_int as libc::c_uint,
        );
    } else if bn_usub_consttime(&mut pm1, (*key).p, BN_value_one()) == 0
        || bn_usub_consttime(&mut qm1, (*key).q, BN_value_one()) == 0
    {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            1345 as libc::c_int as libc::c_uint,
        );
    } else {
        pm1_bits = BN_num_bits(&mut pm1);
        qm1_bits = BN_num_bits(&mut qm1);
        if bn_mul_consttime(&mut de, (*key).d, (*key).e, ctx) == 0
            || bn_div_consttime(
                0 as *mut BIGNUM,
                &mut tmp,
                &mut de,
                &mut pm1,
                pm1_bits,
                ctx,
            ) == 0
            || bn_div_consttime(
                0 as *mut BIGNUM,
                &mut de,
                &mut de,
                &mut qm1,
                qm1_bits,
                ctx,
            ) == 0
        {
            ERR_put_error(
                4 as libc::c_int,
                0 as libc::c_int,
                3 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                    as *const u8 as *const libc::c_char,
                1353 as libc::c_int as libc::c_uint,
            );
        } else if constant_time_declassify_int((BN_is_one(&mut tmp) == 0) as libc::c_int)
            != 0
            || constant_time_declassify_int((BN_is_one(&mut de) == 0) as libc::c_int)
                != 0
        {
            ERR_put_error(
                4 as libc::c_int,
                0 as libc::c_int,
                119 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                    as *const u8 as *const libc::c_char,
                1359 as libc::c_int as libc::c_uint,
            );
        } else if key_type as libc::c_uint
            == RSA_KEY_TYPE_FOR_CHECKING_PRIVATE as libc::c_int as libc::c_uint
        {
            ret = 1 as libc::c_int;
        } else if bn_div_consttime(
            0 as *mut BIGNUM,
            &mut tmp,
            (*key).d,
            &mut pm1,
            pm1_bits,
            ctx,
        ) == 0
            || bn_div_consttime(
                0 as *mut BIGNUM,
                &mut de,
                (*key).d,
                &mut qm1,
                qm1_bits,
                ctx,
            ) == 0
        {
            ERR_put_error(
                4 as libc::c_int,
                0 as libc::c_int,
                3 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                    as *const u8 as *const libc::c_char,
                1377 as libc::c_int as libc::c_uint,
            );
        } else if BN_cmp(&mut tmp, (*key).dmp1) != 0 as libc::c_int
            || BN_cmp(&mut de, (*key).dmq1) != 0 as libc::c_int
        {
            ERR_put_error(
                4 as libc::c_int,
                0 as libc::c_int,
                111 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                    as *const u8 as *const libc::c_char,
                1383 as libc::c_int as libc::c_uint,
            );
        } else if BN_cmp((*key).iqmp, (*key).p) >= 0 as libc::c_int {
            ERR_put_error(
                4 as libc::c_int,
                0 as libc::c_int,
                111 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                    as *const u8 as *const libc::c_char,
                1389 as libc::c_int as libc::c_uint,
            );
        } else if bn_mul_consttime(&mut tmp, (*key).q, (*key).iqmp, ctx) == 0
            || bn_div_consttime(
                0 as *mut BIGNUM,
                &mut tmp,
                &mut tmp,
                (*key).p,
                pm1_bits,
                ctx,
            ) == 0
        {
            ERR_put_error(
                4 as libc::c_int,
                0 as libc::c_int,
                3 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                    as *const u8 as *const libc::c_char,
                1396 as libc::c_int as libc::c_uint,
            );
        } else if BN_cmp(&mut tmp, BN_value_one()) != 0 as libc::c_int {
            ERR_put_error(
                4 as libc::c_int,
                0 as libc::c_int,
                111 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                    as *const u8 as *const libc::c_char,
                1402 as libc::c_int as libc::c_uint,
            );
        } else {
            ret = 1 as libc::c_int;
        }
    }
    BN_free(&mut tmp);
    BN_free(&mut de);
    BN_free(&mut pm1);
    BN_free(&mut qm1);
    BN_free(&mut dmp1);
    BN_free(&mut dmq1);
    BN_CTX_free(ctx);
    return ret;
}
unsafe extern "C" fn rsa_key_fips_pairwise_consistency_test_signing(
    mut key: *mut RSA,
) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut msg: [uint8_t; 1] = [0 as libc::c_int as uint8_t];
    let mut msg_len: size_t = 1 as libc::c_int as size_t;
    let mut sig_der: *mut uint8_t = 0 as *mut uint8_t;
    let mut sig_len: size_t = 0 as libc::c_int as size_t;
    let mut evp_pkey: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
    let mut md_ctx: EVP_MD_CTX = env_md_ctx_st {
        digest: 0 as *const EVP_MD,
        md_data: 0 as *mut libc::c_void,
        update: None,
        pctx: 0 as *mut EVP_PKEY_CTX,
        pctx_ops: 0 as *const evp_md_pctx_ops,
        flags: 0,
    };
    let mut md: *const EVP_MD = EVP_sha256();
    evp_pkey = EVP_PKEY_new();
    if evp_pkey.is_null() || EVP_PKEY_set1_RSA(evp_pkey, key) == 0 {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            4 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            1439 as libc::c_int as libc::c_uint,
        );
    } else {
        EVP_MD_CTX_init(&mut md_ctx);
        if EVP_DigestSignInit(
            &mut md_ctx,
            0 as *mut *mut EVP_PKEY_CTX,
            md,
            0 as *mut ENGINE,
            evp_pkey,
        ) == 0
            || EVP_DigestSign(
                &mut md_ctx,
                0 as *mut uint8_t,
                &mut sig_len,
                msg.as_mut_ptr(),
                msg_len,
            ) == 0
        {
            ERR_put_error(
                4 as libc::c_int,
                0 as libc::c_int,
                4 as libc::c_int | 64 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                    as *const u8 as *const libc::c_char,
                1447 as libc::c_int as libc::c_uint,
            );
        } else {
            sig_der = OPENSSL_malloc(sig_len) as *mut uint8_t;
            if sig_der.is_null()
                || EVP_DigestSign(
                    &mut md_ctx,
                    sig_der,
                    &mut sig_len,
                    msg.as_mut_ptr(),
                    msg_len,
                ) == 0
            {
                ERR_put_error(
                    4 as libc::c_int,
                    0 as libc::c_int,
                    4 as libc::c_int | 64 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                        as *const u8 as *const libc::c_char,
                    1454 as libc::c_int as libc::c_uint,
                );
            } else {
                if boringssl_fips_break_test(
                    b"RSA_PWCT\0" as *const u8 as *const libc::c_char,
                ) != 0
                {
                    msg[0 as libc::c_int
                        as usize] = !(msg[0 as libc::c_int as usize] as libc::c_int)
                        as uint8_t;
                }
                if !(EVP_DigestVerifyInit(
                    &mut md_ctx,
                    0 as *mut *mut EVP_PKEY_CTX,
                    md,
                    0 as *mut ENGINE,
                    evp_pkey,
                ) == 0
                    || EVP_DigestVerify(
                        &mut md_ctx,
                        sig_der,
                        sig_len,
                        msg.as_mut_ptr(),
                        msg_len,
                    ) == 0)
                {
                    ret = 1 as libc::c_int;
                }
            }
        }
    }
    EVP_PKEY_free(evp_pkey);
    EVP_MD_CTX_cleanse(&mut md_ctx);
    OPENSSL_free(sig_der as *mut libc::c_void);
    return ret;
}
static mut kSmallFactorsLimbs: [BN_ULONG; 17] = [
    (0xc4309333 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0x3ef4e3e1 as libc::c_int as BN_ULONG,
    (0x71161eb6 as libc::c_int as BN_ULONG) << 32 as libc::c_int
        | 0xcd2d655f as libc::c_uint as BN_ULONG,
    (0x95e2238c as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0xbf94862 as libc::c_int as BN_ULONG,
    (0x3eb233d3 as libc::c_int as BN_ULONG) << 32 as libc::c_int
        | 0x24f7912b as libc::c_int as BN_ULONG,
    (0x6b55514b as libc::c_int as BN_ULONG) << 32 as libc::c_int
        | 0xbf26c483 as libc::c_uint as BN_ULONG,
    (0xa84d817 as libc::c_int as BN_ULONG) << 32 as libc::c_int
        | 0x5a144871 as libc::c_int as BN_ULONG,
    (0x77d12fee as libc::c_int as BN_ULONG) << 32 as libc::c_int
        | 0x9b82210a as libc::c_uint as BN_ULONG,
    (0xdb5b93c2 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0x97f050b3 as libc::c_uint as BN_ULONG,
    (0x4acad6b9 as libc::c_int as BN_ULONG) << 32 as libc::c_int
        | 0x4d6c026b as libc::c_int as BN_ULONG,
    (0xeb7751f3 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0x54aec893 as libc::c_int as BN_ULONG,
    (0xdba53368 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0x36bc85c4 as libc::c_int as BN_ULONG,
    (0xd85a1b28 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0x7f5ec78e as libc::c_int as BN_ULONG,
    (0x2eb072d8 as libc::c_int as BN_ULONG) << 32 as libc::c_int
        | 0x6b322244 as libc::c_int as BN_ULONG,
    (0xbba51112 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
        | 0x5e2b3aea as libc::c_int as BN_ULONG,
    (0x36ed1a6c as libc::c_int as BN_ULONG) << 32 as libc::c_int
        | 0xe2486bf as libc::c_int as BN_ULONG,
    (0x5f270460 as libc::c_int as BN_ULONG) << 32 as libc::c_int
        | 0xec0c5727 as libc::c_uint as BN_ULONG,
    0x17b1 as libc::c_int as BN_ULONG,
];
static mut g_small_factors_storage: BIGNUM = bignum_st {
    d: 0 as *mut BN_ULONG,
    width: 0,
    dmax: 0,
    neg: 0,
    flags: 0,
};
unsafe extern "C" fn g_small_factors_storage_bss_get() -> *mut BIGNUM {
    return &mut g_small_factors_storage;
}
unsafe extern "C" fn g_small_factors_do_init(mut out: *mut BIGNUM) {
    (*out).d = kSmallFactorsLimbs.as_ptr() as *mut BN_ULONG;
    (*out)
        .width = (::core::mem::size_of::<[BN_ULONG; 17]>() as libc::c_ulong)
        .wrapping_div(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong)
        as libc::c_int;
    (*out).dmax = (*out).width;
    (*out).neg = 0 as libc::c_int;
    (*out).flags = 0x2 as libc::c_int;
}
unsafe extern "C" fn g_small_factors_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut g_small_factors_once;
}
static mut g_small_factors_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn g_small_factors_init() {
    g_small_factors_do_init(g_small_factors_storage_bss_get());
}
unsafe extern "C" fn g_small_factors() -> *const BIGNUM {
    CRYPTO_once(
        g_small_factors_once_bss_get(),
        Some(g_small_factors_init as unsafe extern "C" fn() -> ()),
    );
    return g_small_factors_storage_bss_get() as *const BIGNUM;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_check_fips(mut key: *mut RSA) -> libc::c_int {
    let mut key_type: rsa_key_type_for_checking = determine_key_type_for_checking(key);
    if key_type as libc::c_uint
        == RSA_KEY_TYPE_FOR_CHECKING_INVALID as libc::c_int as libc::c_uint
        || key_type as libc::c_uint
            == RSA_KEY_TYPE_FOR_CHECKING_PRIVATE_STRIP as libc::c_int as libc::c_uint
    {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            1513 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if RSA_check_key(key) == 0 {
        return 0 as libc::c_int;
    }
    let mut ctx: *mut BN_CTX = BN_CTX_new();
    if ctx.is_null() {
        return 0 as libc::c_int;
    }
    let mut small_gcd: BIGNUM = bignum_st {
        d: 0 as *mut BN_ULONG,
        width: 0,
        dmax: 0,
        neg: 0,
        flags: 0,
    };
    BN_init(&mut small_gcd);
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut sig: *mut uint8_t = 0 as *mut uint8_t;
    let mut primality_result: bn_primality_result_t = bn_probably_prime;
    if BN_num_bits((*key).e) <= 16 as libc::c_int as libc::c_uint
        || BN_num_bits((*key).e) > 256 as libc::c_int as libc::c_uint
        || BN_is_odd((*key).n) == 0 || BN_is_odd((*key).e) == 0
        || BN_gcd(&mut small_gcd, (*key).n, g_small_factors(), ctx) == 0
        || BN_is_one(&mut small_gcd) == 0
        || BN_enhanced_miller_rabin_primality_test(
            &mut primality_result,
            (*key).n,
            0 as libc::c_int,
            ctx,
            0 as *mut BN_GENCB,
        ) == 0
        || primality_result as libc::c_uint
            != bn_non_prime_power_composite as libc::c_int as libc::c_uint
    {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            146 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                as *const u8 as *const libc::c_char,
            1550 as libc::c_int as libc::c_uint,
        );
    } else if key_type as libc::c_uint
        == RSA_KEY_TYPE_FOR_CHECKING_PUBLIC as libc::c_int as libc::c_uint
    {
        ret = 1 as libc::c_int;
    } else if !(key_type as libc::c_uint
        != RSA_KEY_TYPE_FOR_CHECKING_PRIVATE_MIN as libc::c_int as libc::c_uint
        && key_type as libc::c_uint
            != RSA_KEY_TYPE_FOR_CHECKING_PRIVATE as libc::c_int as libc::c_uint
        && key_type as libc::c_uint
            != RSA_KEY_TYPE_FOR_CHECKING_PRIVATE_CRT as libc::c_int as libc::c_uint)
    {
        if rsa_key_fips_pairwise_consistency_test_signing(key) == 0 {
            ERR_put_error(
                4 as libc::c_int,
                0 as libc::c_int,
                146 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/rsa.c\0"
                    as *const u8 as *const libc::c_char,
                1576 as libc::c_int as libc::c_uint,
            );
        } else {
            ret = 1 as libc::c_int;
        }
    }
    BN_free(&mut small_gcd);
    BN_CTX_free(ctx);
    OPENSSL_free(sig as *mut libc::c_void);
    return ret;
}
