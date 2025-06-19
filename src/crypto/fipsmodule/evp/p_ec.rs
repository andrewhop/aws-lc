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
    pub type dsa_st;
    pub type engine_st;
    pub type pqdsa_key_st;
    pub type kem_key_st;
    pub type rsa_st;
    pub type env_md_st;
    fn ECDH_compute_shared_secret(
        buf: *mut uint8_t,
        buflen: *mut size_t,
        pub_key: *const EC_POINT,
        priv_key: *const EC_KEY,
    ) -> libc::c_int;
    fn EC_GROUP_new_by_curve_name(nid: libc::c_int) -> *mut EC_GROUP;
    fn EC_GROUP_get_degree(group: *const EC_GROUP) -> libc::c_uint;
    fn EC_curve_nist2nid(name: *const libc::c_char) -> libc::c_int;
    fn ECDSA_sign(
        type_0: libc::c_int,
        digest: *const uint8_t,
        digest_len: size_t,
        sig: *mut uint8_t,
        sig_len: *mut libc::c_uint,
        key: *const EC_KEY,
    ) -> libc::c_int;
    fn ECDSA_verify(
        type_0: libc::c_int,
        digest: *const uint8_t,
        digest_len: size_t,
        sig: *const uint8_t,
        sig_len: size_t,
        key: *const EC_KEY,
    ) -> libc::c_int;
    fn ECDSA_size(key: *const EC_KEY) -> size_t;
    fn EVP_MD_type(md: *const EVP_MD) -> libc::c_int;
    fn EVP_PKEY_CTX_ctrl(
        ctx: *mut EVP_PKEY_CTX,
        keytype: libc::c_int,
        optype: libc::c_int,
        cmd: libc::c_int,
        p1: libc::c_int,
        p2: *mut libc::c_void,
    ) -> libc::c_int;
    fn EVP_PKEY_assign_EC_KEY(pkey: *mut EVP_PKEY, key: *mut EC_KEY) -> libc::c_int;
    fn OBJ_sn2nid(short_name: *const libc::c_char) -> libc::c_int;
    fn OBJ_ln2nid(long_name: *const libc::c_char) -> libc::c_int;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn EC_KEY_new() -> *mut EC_KEY;
    fn EC_KEY_free(key: *mut EC_KEY);
    fn EC_KEY_get0_group(key: *const EC_KEY) -> *const EC_GROUP;
    fn EC_KEY_set_group(key: *mut EC_KEY, group: *const EC_GROUP) -> libc::c_int;
    fn EC_KEY_get0_public_key(key: *const EC_KEY) -> *const EC_POINT;
    fn EC_KEY_generate_key(key: *mut EC_KEY) -> libc::c_int;
    fn EC_KEY_generate_key_fips(key: *mut EC_KEY) -> libc::c_int;
    fn CRYPTO_once(
        once: *mut CRYPTO_once_t,
        init: Option::<unsafe extern "C" fn() -> ()>,
    );
    fn is_fips_build() -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type pthread_once_t = libc::c_int;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ec_group_st {
    pub meth: *const EC_METHOD,
    pub generator: EC_POINT,
    pub order: BN_MONT_CTX,
    pub field: BN_MONT_CTX,
    pub a: EC_FELEM,
    pub b: EC_FELEM,
    pub comment: *const libc::c_char,
    pub curve_name: libc::c_int,
    pub oid: [uint8_t; 9],
    pub oid_len: uint8_t,
    pub a_is_minus3: libc::c_int,
    pub has_order: libc::c_int,
    pub field_greater_than_order: libc::c_int,
    pub conv_form: point_conversion_form_t,
    pub mutable_ec_group: libc::c_int,
}
pub type point_conversion_form_t = libc::c_uint;
pub const POINT_CONVERSION_HYBRID: point_conversion_form_t = 6;
pub const POINT_CONVERSION_UNCOMPRESSED: point_conversion_form_t = 4;
pub const POINT_CONVERSION_COMPRESSED: point_conversion_form_t = 2;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EC_FELEM {
    pub words: [BN_ULONG; 9],
}
pub type EC_POINT = ec_point_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ec_point_st {
    pub group: *mut EC_GROUP,
    pub raw: EC_JACOBIAN,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EC_JACOBIAN {
    pub X: EC_FELEM,
    pub Y: EC_FELEM,
    pub Z: EC_FELEM,
}
pub type EC_GROUP = ec_group_st;
pub type EC_METHOD = ec_method_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ec_method_st {
    pub point_get_affine_coordinates: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *const EC_JACOBIAN,
            *mut EC_FELEM,
            *mut EC_FELEM,
        ) -> libc::c_int,
    >,
    pub jacobian_to_affine_batch: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_AFFINE,
            *const EC_JACOBIAN,
            size_t,
        ) -> libc::c_int,
    >,
    pub add: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_JACOBIAN,
            *const EC_JACOBIAN,
            *const EC_JACOBIAN,
        ) -> (),
    >,
    pub dbl: Option::<
        unsafe extern "C" fn(*const EC_GROUP, *mut EC_JACOBIAN, *const EC_JACOBIAN) -> (),
    >,
    pub mul: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_JACOBIAN,
            *const EC_JACOBIAN,
            *const EC_SCALAR,
        ) -> (),
    >,
    pub mul_base: Option::<
        unsafe extern "C" fn(*const EC_GROUP, *mut EC_JACOBIAN, *const EC_SCALAR) -> (),
    >,
    pub mul_batch: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_JACOBIAN,
            *const EC_JACOBIAN,
            *const EC_SCALAR,
            *const EC_JACOBIAN,
            *const EC_SCALAR,
            *const EC_JACOBIAN,
            *const EC_SCALAR,
        ) -> (),
    >,
    pub mul_public: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_JACOBIAN,
            *const EC_SCALAR,
            *const EC_JACOBIAN,
            *const EC_SCALAR,
        ) -> (),
    >,
    pub mul_public_batch: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_JACOBIAN,
            *const EC_SCALAR,
            *const EC_JACOBIAN,
            *const EC_SCALAR,
            size_t,
        ) -> libc::c_int,
    >,
    pub init_precomp: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_PRECOMP,
            *const EC_JACOBIAN,
        ) -> libc::c_int,
    >,
    pub mul_precomp: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_JACOBIAN,
            *const EC_PRECOMP,
            *const EC_SCALAR,
            *const EC_PRECOMP,
            *const EC_SCALAR,
            *const EC_PRECOMP,
            *const EC_SCALAR,
        ) -> (),
    >,
    pub felem_mul: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_FELEM,
            *const EC_FELEM,
            *const EC_FELEM,
        ) -> (),
    >,
    pub felem_sqr: Option::<
        unsafe extern "C" fn(*const EC_GROUP, *mut EC_FELEM, *const EC_FELEM) -> (),
    >,
    pub felem_to_bytes: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut uint8_t,
            *mut size_t,
            *const EC_FELEM,
        ) -> (),
    >,
    pub felem_from_bytes: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_FELEM,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub felem_reduce: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_FELEM,
            *const BN_ULONG,
            size_t,
        ) -> (),
    >,
    pub felem_exp: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_FELEM,
            *const EC_FELEM,
            *const BN_ULONG,
            size_t,
        ) -> (),
    >,
    pub scalar_inv0_montgomery: Option::<
        unsafe extern "C" fn(*const EC_GROUP, *mut EC_SCALAR, *const EC_SCALAR) -> (),
    >,
    pub scalar_to_montgomery_inv_vartime: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_SCALAR,
            *const EC_SCALAR,
        ) -> libc::c_int,
    >,
    pub cmp_x_coordinate: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *const EC_JACOBIAN,
            *const EC_SCALAR,
        ) -> libc::c_int,
    >,
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ec_key_st {
    pub group: *mut EC_GROUP,
    pub pub_key: *mut EC_POINT,
    pub priv_key: *mut EC_WRAPPED_SCALAR,
    pub enc_flag: libc::c_uint,
    pub conv_form: point_conversion_form_t,
    pub references: CRYPTO_refcount_t,
    pub eckey_method: *const EC_KEY_METHOD,
    pub ex_data: CRYPTO_EX_DATA,
}
pub type EC_KEY_METHOD = ec_key_method_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ec_key_method_st {
    pub init: Option::<unsafe extern "C" fn(*mut EC_KEY) -> libc::c_int>,
    pub finish: Option::<unsafe extern "C" fn(*mut EC_KEY) -> ()>,
    pub sign: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            libc::c_int,
            *mut uint8_t,
            *mut libc::c_uint,
            *const BIGNUM,
            *const BIGNUM,
            *mut EC_KEY,
        ) -> libc::c_int,
    >,
    pub sign_sig: Option::<
        unsafe extern "C" fn(
            *const uint8_t,
            libc::c_int,
            *const BIGNUM,
            *const BIGNUM,
            *mut EC_KEY,
        ) -> *mut ECDSA_SIG,
    >,
    pub flags: libc::c_int,
}
pub type EC_KEY = ec_key_st;
pub type ECDSA_SIG = ecdsa_sig_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ecdsa_sig_st {
    pub r: *mut BIGNUM,
    pub s: *mut BIGNUM,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EC_WRAPPED_SCALAR {
    pub bignum: BIGNUM,
    pub scalar: EC_SCALAR,
}
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
pub struct EC_PKEY_CTX {
    pub md: *const EVP_MD,
    pub gen_group: *const EC_GROUP,
}
pub type CRYPTO_once_t = pthread_once_t;
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
unsafe extern "C" fn FIPS_service_indicator_lock_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_unlock_state() {}
#[inline]
unsafe extern "C" fn ECDH_verify_service_indicator(mut ec_key: *const EC_KEY) {}
unsafe extern "C" fn pkey_ec_init(mut ctx: *mut EVP_PKEY_CTX) -> libc::c_int {
    let mut dctx: *mut EC_PKEY_CTX = 0 as *mut EC_PKEY_CTX;
    dctx = OPENSSL_zalloc(::core::mem::size_of::<EC_PKEY_CTX>() as libc::c_ulong)
        as *mut EC_PKEY_CTX;
    if dctx.is_null() {
        return 0 as libc::c_int;
    }
    (*ctx).data = dctx as *mut libc::c_void;
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_ec_copy(
    mut dst: *mut EVP_PKEY_CTX,
    mut src: *mut EVP_PKEY_CTX,
) -> libc::c_int {
    if pkey_ec_init(dst) == 0 {
        return 0 as libc::c_int;
    }
    let mut sctx: *const EC_PKEY_CTX = (*src).data as *const EC_PKEY_CTX;
    let mut dctx: *mut EC_PKEY_CTX = (*dst).data as *mut EC_PKEY_CTX;
    (*dctx).md = (*sctx).md;
    (*dctx).gen_group = (*sctx).gen_group;
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_ec_cleanup(mut ctx: *mut EVP_PKEY_CTX) {
    let mut dctx: *mut EC_PKEY_CTX = (*ctx).data as *mut EC_PKEY_CTX;
    if dctx.is_null() {
        return;
    }
    OPENSSL_free(dctx as *mut libc::c_void);
}
unsafe extern "C" fn pkey_ec_sign(
    mut ctx: *mut EVP_PKEY_CTX,
    mut sig: *mut uint8_t,
    mut siglen: *mut size_t,
    mut tbs: *const uint8_t,
    mut tbslen: size_t,
) -> libc::c_int {
    let mut sltmp: libc::c_uint = 0;
    let mut ec: *mut EC_KEY = (*(*ctx).pkey).pkey.ec;
    if sig.is_null() {
        *siglen = ECDSA_size(ec);
        return 1 as libc::c_int;
    } else if *siglen < ECDSA_size(ec) {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_ec.c\0"
                as *const u8 as *const libc::c_char,
            127 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ECDSA_sign(0 as libc::c_int, tbs, tbslen, sig, &mut sltmp, ec) == 0 {
        return 0 as libc::c_int;
    }
    *siglen = sltmp as size_t;
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_ec_verify(
    mut ctx: *mut EVP_PKEY_CTX,
    mut sig: *const uint8_t,
    mut siglen: size_t,
    mut tbs: *const uint8_t,
    mut tbslen: size_t,
) -> libc::c_int {
    return ECDSA_verify(
        0 as libc::c_int,
        tbs,
        tbslen,
        sig,
        siglen,
        (*(*ctx).pkey).pkey.ec,
    );
}
unsafe extern "C" fn pkey_ec_derive(
    mut ctx: *mut EVP_PKEY_CTX,
    mut key: *mut uint8_t,
    mut keylen: *mut size_t,
) -> libc::c_int {
    let mut pubkey: *const EC_POINT = 0 as *const EC_POINT;
    let mut eckey: *mut EC_KEY = 0 as *mut EC_KEY;
    let mut buf: [uint8_t; 66] = [0; 66];
    let mut buflen: size_t = ::core::mem::size_of::<[uint8_t; 66]>() as libc::c_ulong;
    if ((*ctx).pkey).is_null() || ((*ctx).peerkey).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            117 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_ec.c\0"
                as *const u8 as *const libc::c_char,
            151 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    eckey = (*(*ctx).pkey).pkey.ec;
    if key.is_null() {
        let mut group: *const EC_GROUP = 0 as *const EC_GROUP;
        group = EC_KEY_get0_group(eckey);
        *keylen = (EC_GROUP_get_degree(group))
            .wrapping_add(7 as libc::c_int as libc::c_uint)
            .wrapping_div(8 as libc::c_int as libc::c_uint) as size_t;
        return 1 as libc::c_int;
    }
    pubkey = EC_KEY_get0_public_key((*(*ctx).peerkey).pkey.ec);
    if ECDH_compute_shared_secret(buf.as_mut_ptr(), &mut buflen, pubkey, eckey) == 0 {
        return 0 as libc::c_int;
    }
    if buflen < *keylen {
        *keylen = buflen;
    }
    OPENSSL_memcpy(
        key as *mut libc::c_void,
        buf.as_mut_ptr() as *const libc::c_void,
        *keylen,
    );
    ECDH_verify_service_indicator(eckey);
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_ec_ctrl(
    mut ctx: *mut EVP_PKEY_CTX,
    mut type_0: libc::c_int,
    mut p1: libc::c_int,
    mut p2: *mut libc::c_void,
) -> libc::c_int {
    let mut dctx: *mut EC_PKEY_CTX = (*ctx).data as *mut EC_PKEY_CTX;
    match type_0 {
        1 => {
            let mut md: *const EVP_MD = p2 as *const EVP_MD;
            let mut md_type: libc::c_int = EVP_MD_type(md);
            if md_type != 64 as libc::c_int && md_type != 675 as libc::c_int
                && md_type != 672 as libc::c_int && md_type != 673 as libc::c_int
                && md_type != 674 as libc::c_int && md_type != 978 as libc::c_int
                && md_type != 962 as libc::c_int && md_type != 965 as libc::c_int
                && md_type != 966 as libc::c_int && md_type != 967 as libc::c_int
                && md_type != 968 as libc::c_int
            {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    111 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_ec.c\0"
                        as *const u8 as *const libc::c_char,
                    201 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            (*dctx).md = md;
            return 1 as libc::c_int;
        }
        2 => {
            let ref mut fresh0 = *(p2 as *mut *const EVP_MD);
            *fresh0 = (*dctx).md;
            return 1 as libc::c_int;
        }
        3 => return 1 as libc::c_int,
        4109 => {
            let mut group: *const EC_GROUP = EC_GROUP_new_by_curve_name(p1);
            if group.is_null() {
                return 0 as libc::c_int;
            }
            (*dctx).gen_group = group;
            return 1 as libc::c_int;
        }
        _ => {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                101 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_ec.c\0"
                    as *const u8 as *const libc::c_char,
                226 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    };
}
unsafe extern "C" fn pkey_ec_ctrl_str(
    mut ctx: *mut EVP_PKEY_CTX,
    mut type_0: *const libc::c_char,
    mut value: *const libc::c_char,
) -> libc::c_int {
    if strcmp(type_0, b"ec_paramgen_curve\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        let mut nid: libc::c_int = 0;
        nid = EC_curve_nist2nid(value);
        if nid == 0 as libc::c_int {
            nid = OBJ_sn2nid(value);
        }
        if nid == 0 as libc::c_int {
            nid = OBJ_ln2nid(value);
        }
        if nid == 0 as libc::c_int {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                109 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_ec.c\0"
                    as *const u8 as *const libc::c_char,
                243 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
    }
    if strcmp(type_0, b"ec_param_enc\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        let mut param_enc: libc::c_int = 0;
        if strcmp(value, b"named_curve\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            param_enc = 1 as libc::c_int;
        } else {
            return -(2 as libc::c_int)
        }
        return EVP_PKEY_CTX_set_ec_param_enc(ctx, param_enc);
    }
    return -(2 as libc::c_int);
}
unsafe extern "C" fn pkey_ec_keygen(
    mut ctx: *mut EVP_PKEY_CTX,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut dctx: *mut EC_PKEY_CTX = (*ctx).data as *mut EC_PKEY_CTX;
    let mut group: *const EC_GROUP = (*dctx).gen_group;
    if group.is_null() {
        if ((*ctx).pkey).is_null() {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                124 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_ec.c\0"
                    as *const u8 as *const libc::c_char,
                270 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        group = EC_KEY_get0_group((*(*ctx).pkey).pkey.ec);
    }
    let mut ec: *mut EC_KEY = EC_KEY_new();
    FIPS_service_indicator_lock_state();
    if ec.is_null() || EC_KEY_set_group(ec, group) == 0
        || is_fips_build() == 0 && EC_KEY_generate_key(ec) == 0
        || is_fips_build() != 0 && EC_KEY_generate_key_fips(ec) == 0
    {
        EC_KEY_free(ec);
    } else {
        EVP_PKEY_assign_EC_KEY(pkey, ec);
        ret = 1 as libc::c_int;
    }
    FIPS_service_indicator_unlock_state();
    return ret;
}
unsafe extern "C" fn pkey_ec_paramgen(
    mut ctx: *mut EVP_PKEY_CTX,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    let mut dctx: *mut EC_PKEY_CTX = (*ctx).data as *mut EC_PKEY_CTX;
    if ((*dctx).gen_group).is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            124 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_ec.c\0"
                as *const u8 as *const libc::c_char,
            296 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ec: *mut EC_KEY = EC_KEY_new();
    if ec.is_null() || EC_KEY_set_group(ec, (*dctx).gen_group) == 0 {
        EC_KEY_free(ec);
        return 0 as libc::c_int;
    }
    EVP_PKEY_assign_EC_KEY(pkey, ec);
    return 1 as libc::c_int;
}
unsafe extern "C" fn EVP_PKEY_ec_pkey_meth_storage_bss_get() -> *mut EVP_PKEY_METHOD {
    return &mut EVP_PKEY_ec_pkey_meth_storage;
}
unsafe extern "C" fn EVP_PKEY_ec_pkey_meth_do_init(mut out: *mut EVP_PKEY_METHOD) {
    (*out).pkey_id = 408 as libc::c_int;
    (*out)
        .init = Some(
        pkey_ec_init as unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> libc::c_int,
    );
    (*out)
        .copy = Some(
        pkey_ec_copy
            as unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY_CTX) -> libc::c_int,
    );
    (*out)
        .cleanup = Some(
        pkey_ec_cleanup as unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> (),
    );
    (*out)
        .keygen = Some(
        pkey_ec_keygen
            as unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY) -> libc::c_int,
    );
    (*out).sign_init = None;
    (*out)
        .sign = Some(
        pkey_ec_sign
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out).sign_message = None;
    (*out).verify_init = None;
    (*out)
        .verify = Some(
        pkey_ec_verify
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
    (*out)
        .derive = Some(
        pkey_ec_derive
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *mut uint8_t,
                *mut size_t,
            ) -> libc::c_int,
    );
    (*out)
        .paramgen = Some(
        pkey_ec_paramgen
            as unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY) -> libc::c_int,
    );
    (*out)
        .ctrl = Some(
        pkey_ec_ctrl
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                libc::c_int,
                libc::c_int,
                *mut libc::c_void,
            ) -> libc::c_int,
    );
    (*out)
        .ctrl_str = Some(
        pkey_ec_ctrl_str
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *const libc::c_char,
                *const libc::c_char,
            ) -> libc::c_int,
    );
}
unsafe extern "C" fn EVP_PKEY_ec_pkey_meth_init() {
    EVP_PKEY_ec_pkey_meth_do_init(EVP_PKEY_ec_pkey_meth_storage_bss_get());
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_ec_pkey_meth() -> *const EVP_PKEY_METHOD {
    CRYPTO_once(
        EVP_PKEY_ec_pkey_meth_once_bss_get(),
        Some(EVP_PKEY_ec_pkey_meth_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_PKEY_ec_pkey_meth_storage_bss_get() as *const EVP_PKEY_METHOD;
}
static mut EVP_PKEY_ec_pkey_meth_storage: EVP_PKEY_METHOD = evp_pkey_method_st {
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
unsafe extern "C" fn EVP_PKEY_ec_pkey_meth_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_PKEY_ec_pkey_meth_once;
}
static mut EVP_PKEY_ec_pkey_meth_once: CRYPTO_once_t = 0 as libc::c_int;
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
    mut ctx: *mut EVP_PKEY_CTX,
    mut nid: libc::c_int,
) -> libc::c_int {
    return EVP_PKEY_CTX_ctrl(
        ctx,
        408 as libc::c_int,
        (1 as libc::c_int) << 2 as libc::c_int | (1 as libc::c_int) << 9 as libc::c_int,
        0x1000 as libc::c_int + 13 as libc::c_int,
        nid,
        0 as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_ec_param_enc(
    mut ctx: *mut EVP_PKEY_CTX,
    mut encoding: libc::c_int,
) -> libc::c_int {
    if encoding != 1 as libc::c_int {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            133 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_ec.c\0"
                as *const u8 as *const libc::c_char,
            338 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
