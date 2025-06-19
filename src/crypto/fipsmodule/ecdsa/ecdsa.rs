#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(asm, extern_types)]
use core::arch::asm;
extern "C" {
    pub type stack_st_void;
    pub type engine_st;
    pub type env_md_st;
    fn BN_new() -> *mut BIGNUM;
    fn BN_free(bn: *mut BIGNUM);
    fn BN_num_bits(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_is_zero(bn: *const BIGNUM) -> libc::c_int;
    fn CBB_init_fixed(cbb: *mut CBB, buf: *mut uint8_t, len: size_t) -> libc::c_int;
    fn CBB_finish(
        cbb: *mut CBB,
        out_data: *mut *mut uint8_t,
        out_len: *mut size_t,
    ) -> libc::c_int;
    fn ec_bignum_to_scalar(
        group: *const EC_GROUP,
        out: *mut EC_SCALAR,
        in_0: *const BIGNUM,
    ) -> libc::c_int;
    fn ec_scalar_from_bytes(
        group: *const EC_GROUP,
        out: *mut EC_SCALAR,
        in_0: *const uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn ec_random_nonzero_scalar(
        group: *const EC_GROUP,
        out: *mut EC_SCALAR,
        additional_data: *const uint8_t,
    ) -> libc::c_int;
    fn ec_scalar_is_zero(group: *const EC_GROUP, a: *const EC_SCALAR) -> libc::c_int;
    fn ec_scalar_add(
        group: *const EC_GROUP,
        r: *mut EC_SCALAR,
        a: *const EC_SCALAR,
        b: *const EC_SCALAR,
    );
    fn ec_scalar_to_montgomery(
        group: *const EC_GROUP,
        r: *mut EC_SCALAR,
        a: *const EC_SCALAR,
    );
    fn ec_scalar_from_montgomery(
        group: *const EC_GROUP,
        r: *mut EC_SCALAR,
        a: *const EC_SCALAR,
    );
    fn ec_scalar_mul_montgomery(
        group: *const EC_GROUP,
        r: *mut EC_SCALAR,
        a: *const EC_SCALAR,
        b: *const EC_SCALAR,
    );
    fn ec_scalar_inv0_montgomery(
        group: *const EC_GROUP,
        r: *mut EC_SCALAR,
        a: *const EC_SCALAR,
    );
    fn ec_scalar_to_montgomery_inv_vartime(
        group: *const EC_GROUP,
        r: *mut EC_SCALAR,
        a: *const EC_SCALAR,
    ) -> libc::c_int;
    fn ec_point_mul_scalar_base(
        group: *const EC_GROUP,
        r: *mut EC_JACOBIAN,
        scalar: *const EC_SCALAR,
    ) -> libc::c_int;
    fn ec_point_mul_scalar_public(
        group: *const EC_GROUP,
        r: *mut EC_JACOBIAN,
        g_scalar: *const EC_SCALAR,
        p: *const EC_JACOBIAN,
        p_scalar: *const EC_SCALAR,
    ) -> libc::c_int;
    fn ec_cmp_x_coordinate(
        group: *const EC_GROUP,
        p: *const EC_JACOBIAN,
        r: *const EC_SCALAR,
    ) -> libc::c_int;
    fn ec_get_x_coordinate_as_scalar(
        group: *const EC_GROUP,
        out: *mut EC_SCALAR,
        p: *const EC_JACOBIAN,
    ) -> libc::c_int;
    fn EC_GROUP_get0_order(group: *const EC_GROUP) -> *const BIGNUM;
    fn ECDSA_size(key: *const EC_KEY) -> size_t;
    fn ECDSA_SIG_from_bytes(in_0: *const uint8_t, in_len: size_t) -> *mut ECDSA_SIG;
    fn ECDSA_SIG_marshal(cbb: *mut CBB, sig: *const ECDSA_SIG) -> libc::c_int;
    fn ECDSA_SIG_to_bytes(
        out_bytes: *mut *mut uint8_t,
        out_len: *mut size_t,
        sig: *const ECDSA_SIG,
    ) -> libc::c_int;
    fn EVP_Digest(
        data: *const libc::c_void,
        len: size_t,
        md_out: *mut uint8_t,
        out_size: *mut libc::c_uint,
        type_0: *const EVP_MD,
        impl_0: *mut ENGINE,
    ) -> libc::c_int;
    fn SHA512_Init(sha: *mut SHA512_CTX) -> libc::c_int;
    fn SHA512_Update(
        sha: *mut SHA512_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn SHA512_Final(out: *mut uint8_t, sha: *mut SHA512_CTX) -> libc::c_int;
    fn EC_KEY_get0_group(key: *const EC_KEY) -> *const EC_GROUP;
    fn EC_KEY_get0_public_key(key: *const EC_KEY) -> *const EC_POINT;
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn bn_set_words(bn: *mut BIGNUM, words: *const BN_ULONG, num: size_t) -> libc::c_int;
    fn bn_rshift_words(
        r: *mut BN_ULONG,
        a: *const BN_ULONG,
        shift: libc::c_uint,
        num: size_t,
    );
    fn bn_reduce_once_in_place(
        r: *mut BN_ULONG,
        carry: BN_ULONG,
        m: *const BN_ULONG,
        tmp: *mut BN_ULONG,
        num: size_t,
    ) -> BN_ULONG;
    fn bn_big_endian_to_words(
        out: *mut BN_ULONG,
        out_len: size_t,
        in_0: *const uint8_t,
        in_len: size_t,
    );
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
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
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
pub type CRYPTO_refcount_t = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EC_WRAPPED_SCALAR {
    pub bignum: BIGNUM,
    pub scalar: EC_SCALAR,
}
pub type ENGINE = engine_st;
pub type EVP_MD = env_md_st;
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
pub type SHA512_CTX = sha512_state_st;
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
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_333_error_is_additional_data_is_too_large_for_SHA_512 {
    #[bitfield(
        name = "static_assertion_at_line_333_error_is_additional_data_is_too_large_for_SHA_512",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_333_error_is_additional_data_is_too_large_for_SHA_512: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
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
unsafe extern "C" fn boringssl_ensure_ecc_self_test() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_lock_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_unlock_state() {}
unsafe extern "C" fn digest_to_scalar(
    mut group: *const EC_GROUP,
    mut out: *mut EC_SCALAR,
    mut digest: *const uint8_t,
    mut digest_len: size_t,
) {
    let mut order: *const BIGNUM = EC_GROUP_get0_order(group);
    let mut num_bits: size_t = BN_num_bits(order) as size_t;
    let mut num_bytes: size_t = num_bits.wrapping_add(7 as libc::c_int as size_t)
        / 8 as libc::c_int as size_t;
    if digest_len > num_bytes {
        digest_len = num_bytes;
    }
    bn_big_endian_to_words(
        ((*out).words).as_mut_ptr(),
        (*order).width as size_t,
        digest,
        digest_len,
    );
    if 8 as libc::c_int as size_t * digest_len > num_bits {
        bn_rshift_words(
            ((*out).words).as_mut_ptr(),
            ((*out).words).as_mut_ptr(),
            (8 as libc::c_int as size_t)
                .wrapping_sub(num_bits & 0x7 as libc::c_int as size_t) as libc::c_uint,
            (*order).width as size_t,
        );
    }
    let mut tmp: [BN_ULONG; 9] = [0; 9];
    bn_reduce_once_in_place(
        ((*out).words).as_mut_ptr(),
        0 as libc::c_int as BN_ULONG,
        (*order).d,
        tmp.as_mut_ptr(),
        (*order).width as size_t,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ECDSA_SIG_new() -> *mut ECDSA_SIG {
    let mut sig: *mut ECDSA_SIG = OPENSSL_malloc(
        ::core::mem::size_of::<ECDSA_SIG>() as libc::c_ulong,
    ) as *mut ECDSA_SIG;
    if sig.is_null() {
        return 0 as *mut ECDSA_SIG;
    }
    (*sig).r = BN_new();
    (*sig).s = BN_new();
    if ((*sig).r).is_null() || ((*sig).s).is_null() {
        ECDSA_SIG_free(sig);
        return 0 as *mut ECDSA_SIG;
    }
    return sig;
}
#[no_mangle]
pub unsafe extern "C" fn ECDSA_SIG_free(mut sig: *mut ECDSA_SIG) {
    if sig.is_null() {
        return;
    }
    BN_free((*sig).r);
    BN_free((*sig).s);
    OPENSSL_free(sig as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn ECDSA_SIG_get0_r(mut sig: *const ECDSA_SIG) -> *const BIGNUM {
    return (*sig).r;
}
#[no_mangle]
pub unsafe extern "C" fn ECDSA_SIG_get0_s(mut sig: *const ECDSA_SIG) -> *const BIGNUM {
    return (*sig).s;
}
#[no_mangle]
pub unsafe extern "C" fn ECDSA_SIG_get0(
    mut sig: *const ECDSA_SIG,
    mut out_r: *mut *const BIGNUM,
    mut out_s: *mut *const BIGNUM,
) {
    if !out_r.is_null() {
        *out_r = (*sig).r;
    }
    if !out_s.is_null() {
        *out_s = (*sig).s;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ECDSA_SIG_set0(
    mut sig: *mut ECDSA_SIG,
    mut r: *mut BIGNUM,
    mut s: *mut BIGNUM,
) -> libc::c_int {
    if r.is_null() || s.is_null() {
        return 0 as libc::c_int;
    }
    BN_free((*sig).r);
    BN_free((*sig).s);
    (*sig).r = r;
    (*sig).s = s;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ecdsa_do_verify_no_self_test(
    mut digest: *const uint8_t,
    mut digest_len: size_t,
    mut sig: *const ECDSA_SIG,
    mut eckey: *const EC_KEY,
) -> libc::c_int {
    let mut group: *const EC_GROUP = EC_KEY_get0_group(eckey);
    let mut pub_key: *const EC_POINT = EC_KEY_get0_public_key(eckey);
    if group.is_null() || pub_key.is_null() || sig.is_null() {
        ERR_put_error(
            26 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ecdsa/ecdsa.c\0"
                as *const u8 as *const libc::c_char,
            159 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut r: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut s: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut u1: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut u2: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut s_inv_mont: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut m: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    if BN_is_zero((*sig).r) != 0 || ec_bignum_to_scalar(group, &mut r, (*sig).r) == 0
        || BN_is_zero((*sig).s) != 0 || ec_bignum_to_scalar(group, &mut s, (*sig).s) == 0
    {
        ERR_put_error(
            26 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ecdsa/ecdsa.c\0"
                as *const u8 as *const libc::c_char,
            168 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ec_scalar_to_montgomery_inv_vartime(group, &mut s_inv_mont, &mut s) == 0 {
        ERR_put_error(
            26 as libc::c_int,
            0 as libc::c_int,
            4 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ecdsa/ecdsa.c\0"
                as *const u8 as *const libc::c_char,
            174 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    digest_to_scalar(group, &mut m, digest, digest_len);
    ec_scalar_mul_montgomery(group, &mut u1, &mut m, &mut s_inv_mont);
    ec_scalar_mul_montgomery(group, &mut u2, &mut r, &mut s_inv_mont);
    let mut point: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    if ec_point_mul_scalar_public(group, &mut point, &mut u1, &(*pub_key).raw, &mut u2)
        == 0
    {
        ERR_put_error(
            26 as libc::c_int,
            0 as libc::c_int,
            15 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ecdsa/ecdsa.c\0"
                as *const u8 as *const libc::c_char,
            189 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ec_cmp_x_coordinate(group, &mut point, &mut r) == 0 {
        ERR_put_error(
            26 as libc::c_int,
            0 as libc::c_int,
            205 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ecdsa/ecdsa.c\0"
                as *const u8 as *const libc::c_char,
            194 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ECDSA_do_verify(
    mut digest: *const uint8_t,
    mut digest_len: size_t,
    mut sig: *const ECDSA_SIG,
    mut eckey: *const EC_KEY,
) -> libc::c_int {
    boringssl_ensure_ecc_self_test();
    return ecdsa_do_verify_no_self_test(digest, digest_len, sig, eckey);
}
unsafe extern "C" fn ecdsa_sign_impl(
    mut group: *const EC_GROUP,
    mut out_retry: *mut libc::c_int,
    mut priv_key: *const EC_SCALAR,
    mut k: *const EC_SCALAR,
    mut digest: *const uint8_t,
    mut digest_len: size_t,
) -> *mut ECDSA_SIG {
    *out_retry = 0 as libc::c_int;
    let mut order: *const BIGNUM = EC_GROUP_get0_order(group);
    if BN_num_bits(order) < 160 as libc::c_int as libc::c_uint {
        ERR_put_error(
            26 as libc::c_int,
            0 as libc::c_int,
            112 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ecdsa/ecdsa.c\0"
                as *const u8 as *const libc::c_char,
            217 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut ECDSA_SIG;
    }
    let mut tmp_point: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    let mut r: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    if ec_point_mul_scalar_base(group, &mut tmp_point, k) == 0
        || ec_get_x_coordinate_as_scalar(group, &mut r, &mut tmp_point) == 0
    {
        return 0 as *mut ECDSA_SIG;
    }
    if constant_time_declassify_int(ec_scalar_is_zero(group, &mut r)) != 0 {
        *out_retry = 1 as libc::c_int;
        return 0 as *mut ECDSA_SIG;
    }
    let mut s: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    ec_scalar_to_montgomery(group, &mut s, &mut r);
    ec_scalar_mul_montgomery(group, &mut s, priv_key, &mut s);
    let mut tmp: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    digest_to_scalar(group, &mut tmp, digest, digest_len);
    ec_scalar_add(group, &mut s, &mut s, &mut tmp);
    ec_scalar_inv0_montgomery(group, &mut tmp, k);
    ec_scalar_from_montgomery(group, &mut tmp, &mut tmp);
    ec_scalar_mul_montgomery(group, &mut s, &mut s, &mut tmp);
    if constant_time_declassify_int(ec_scalar_is_zero(group, &mut s)) != 0 {
        *out_retry = 1 as libc::c_int;
        return 0 as *mut ECDSA_SIG;
    }
    let mut ret: *mut ECDSA_SIG = ECDSA_SIG_new();
    if ret.is_null()
        || bn_set_words((*ret).r, (r.words).as_mut_ptr(), (*order).width as size_t) == 0
        || bn_set_words((*ret).s, (s.words).as_mut_ptr(), (*order).width as size_t) == 0
    {
        ECDSA_SIG_free(ret);
        return 0 as *mut ECDSA_SIG;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn ecdsa_sign_with_nonce_for_known_answer_test(
    mut digest: *const uint8_t,
    mut digest_len: size_t,
    mut eckey: *const EC_KEY,
    mut nonce: *const uint8_t,
    mut nonce_len: size_t,
) -> *mut ECDSA_SIG {
    if !((*eckey).eckey_method).is_null() && ((*(*eckey).eckey_method).sign).is_some() {
        ERR_put_error(
            26 as libc::c_int,
            0 as libc::c_int,
            103 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ecdsa/ecdsa.c\0"
                as *const u8 as *const libc::c_char,
            279 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut ECDSA_SIG;
    }
    let mut group: *const EC_GROUP = EC_KEY_get0_group(eckey);
    if group.is_null() || ((*eckey).priv_key).is_null() {
        ERR_put_error(
            26 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ecdsa/ecdsa.c\0"
                as *const u8 as *const libc::c_char,
            285 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut ECDSA_SIG;
    }
    let mut priv_key: *const EC_SCALAR = &mut (*(*eckey).priv_key).scalar;
    let mut k: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    if ec_scalar_from_bytes(group, &mut k, nonce, nonce_len) == 0 {
        return 0 as *mut ECDSA_SIG;
    }
    let mut retry_ignored: libc::c_int = 0;
    return ecdsa_sign_impl(
        group,
        &mut retry_ignored,
        priv_key,
        &mut k,
        digest,
        digest_len,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ECDSA_sign_with_nonce_and_leak_private_key_for_testing(
    mut digest: *const uint8_t,
    mut digest_len: size_t,
    mut eckey: *const EC_KEY,
    mut nonce: *const uint8_t,
    mut nonce_len: size_t,
) -> *mut ECDSA_SIG {
    boringssl_ensure_ecc_self_test();
    return ecdsa_sign_with_nonce_for_known_answer_test(
        digest,
        digest_len,
        eckey,
        nonce,
        nonce_len,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ECDSA_do_sign(
    mut digest: *const uint8_t,
    mut digest_len: size_t,
    mut eckey: *const EC_KEY,
) -> *mut ECDSA_SIG {
    boringssl_ensure_ecc_self_test();
    if !((*eckey).eckey_method).is_null()
        && ((*(*eckey).eckey_method).sign_sig).is_some()
    {
        return ((*(*eckey).eckey_method).sign_sig)
            .expect(
                "non-null function pointer",
            )(
            digest,
            digest_len as libc::c_int,
            0 as *const BIGNUM,
            0 as *const BIGNUM,
            eckey as *mut EC_KEY,
        );
    }
    let mut group: *const EC_GROUP = EC_KEY_get0_group(eckey);
    if group.is_null() || ((*eckey).priv_key).is_null() {
        ERR_put_error(
            26 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ecdsa/ecdsa.c\0"
                as *const u8 as *const libc::c_char,
            321 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut ECDSA_SIG;
    }
    FIPS_service_indicator_lock_state();
    let mut order: *const BIGNUM = EC_GROUP_get0_order(group);
    let mut priv_key: *const EC_SCALAR = &mut (*(*eckey).priv_key).scalar;
    let mut sha: SHA512_CTX = sha512_state_st {
        h: [0; 8],
        Nl: 0,
        Nh: 0,
        p: [0; 128],
        num: 0,
        md_len: 0,
    };
    let mut additional_data: [uint8_t; 64] = [0; 64];
    SHA512_Init(&mut sha);
    SHA512_Update(
        &mut sha,
        ((*priv_key).words).as_ptr() as *const libc::c_void,
        ((*order).width as libc::c_ulong)
            .wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    );
    SHA512_Update(&mut sha, digest as *const libc::c_void, digest_len);
    SHA512_Final(additional_data.as_mut_ptr(), &mut sha);
    FIPS_service_indicator_unlock_state();
    static mut kMaxIterations: libc::c_int = 32 as libc::c_int;
    let mut iters: libc::c_int = 0 as libc::c_int;
    loop {
        let mut k: EC_SCALAR = EC_SCALAR { words: [0; 9] };
        if ec_random_nonzero_scalar(
            group,
            &mut k,
            additional_data.as_mut_ptr() as *const uint8_t,
        ) == 0
        {
            OPENSSL_cleanse(
                &mut k as *mut EC_SCALAR as *mut libc::c_void,
                ::core::mem::size_of::<EC_SCALAR>() as libc::c_ulong,
            );
            return 0 as *mut ECDSA_SIG;
        }
        let mut retry: libc::c_int = 0;
        let mut sig: *mut ECDSA_SIG = ecdsa_sign_impl(
            group,
            &mut retry,
            priv_key,
            &mut k,
            digest,
            digest_len,
        );
        if !sig.is_null() || retry == 0 {
            OPENSSL_cleanse(
                &mut k as *mut EC_SCALAR as *mut libc::c_void,
                ::core::mem::size_of::<EC_SCALAR>() as libc::c_ulong,
            );
            return sig;
        }
        iters += 1;
        iters;
        if iters > kMaxIterations {
            OPENSSL_cleanse(
                &mut k as *mut EC_SCALAR as *mut libc::c_void,
                ::core::mem::size_of::<EC_SCALAR>() as libc::c_ulong,
            );
            ERR_put_error(
                26 as libc::c_int,
                0 as libc::c_int,
                106 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ecdsa/ecdsa.c\0"
                    as *const u8 as *const libc::c_char,
                370 as libc::c_int as libc::c_uint,
            );
            return 0 as *mut ECDSA_SIG;
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn ECDSA_sign(
    mut type_0: libc::c_int,
    mut digest: *const uint8_t,
    mut digest_len: size_t,
    mut sig: *mut uint8_t,
    mut sig_len: *mut libc::c_uint,
    mut eckey: *const EC_KEY,
) -> libc::c_int {
    let mut cbb: CBB = cbb_st {
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
    let mut len: size_t = 0;
    if !((*eckey).eckey_method).is_null() && ((*(*eckey).eckey_method).sign).is_some() {
        return ((*(*eckey).eckey_method).sign)
            .expect(
                "non-null function pointer",
            )(
            type_0,
            digest,
            digest_len as libc::c_int,
            sig,
            sig_len,
            0 as *const BIGNUM,
            0 as *const BIGNUM,
            eckey as *mut EC_KEY,
        );
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut s: *mut ECDSA_SIG = ECDSA_do_sign(digest, digest_len, eckey);
    if s.is_null() {
        *sig_len = 0 as libc::c_int as libc::c_uint;
    } else {
        cbb = cbb_st {
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
        CBB_init_fixed(&mut cbb, sig, ECDSA_size(eckey));
        len = 0;
        if ECDSA_SIG_marshal(&mut cbb, s) == 0
            || CBB_finish(&mut cbb, 0 as *mut *mut uint8_t, &mut len) == 0
        {
            ERR_put_error(
                26 as libc::c_int,
                0 as libc::c_int,
                105 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ecdsa/ecdsa.c\0"
                    as *const u8 as *const libc::c_char,
                399 as libc::c_int as libc::c_uint,
            );
            *sig_len = 0 as libc::c_int as libc::c_uint;
        } else {
            *sig_len = len as libc::c_uint;
            ret = 1 as libc::c_int;
        }
    }
    ECDSA_SIG_free(s);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn ECDSA_verify(
    mut type_0: libc::c_int,
    mut digest: *const uint8_t,
    mut digest_len: size_t,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
    mut eckey: *const EC_KEY,
) -> libc::c_int {
    let mut der_len: size_t = 0;
    let mut s: *mut ECDSA_SIG = 0 as *mut ECDSA_SIG;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut der: *mut uint8_t = 0 as *mut uint8_t;
    s = ECDSA_SIG_from_bytes(sig, sig_len);
    if !s.is_null() {
        der_len = 0;
        if ECDSA_SIG_to_bytes(&mut der, &mut der_len, s) == 0 || der_len != sig_len
            || OPENSSL_memcmp(
                sig as *const libc::c_void,
                der as *const libc::c_void,
                sig_len,
            ) != 0 as libc::c_int
        {
            ERR_put_error(
                26 as libc::c_int,
                0 as libc::c_int,
                4 as libc::c_int | 64 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ecdsa/ecdsa.c\0"
                    as *const u8 as *const libc::c_char,
                431 as libc::c_int as libc::c_uint,
            );
        } else {
            ret = ECDSA_do_verify(digest, digest_len, s, eckey);
        }
    }
    OPENSSL_free(der as *mut libc::c_void);
    ECDSA_SIG_free(s);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn ecdsa_digestsign_no_self_test(
    mut md: *const EVP_MD,
    mut input: *const uint8_t,
    mut in_len: size_t,
    mut eckey: *const EC_KEY,
    mut nonce: *const uint8_t,
    mut nonce_len: size_t,
) -> *mut ECDSA_SIG {
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
        return 0 as *mut ECDSA_SIG;
    }
    return ecdsa_sign_with_nonce_for_known_answer_test(
        digest.as_mut_ptr(),
        digest_len as size_t,
        eckey,
        nonce,
        nonce_len,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ecdsa_digestverify_no_self_test(
    mut md: *const EVP_MD,
    mut input: *const uint8_t,
    mut in_len: size_t,
    mut sig: *const ECDSA_SIG,
    mut eckey: *const EC_KEY,
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
    return ecdsa_do_verify_no_self_test(
        digest.as_mut_ptr(),
        digest_len as size_t,
        sig,
        eckey,
    );
}
