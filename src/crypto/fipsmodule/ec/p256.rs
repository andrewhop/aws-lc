#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(asm, label_break_value)]
use core::arch::asm;
extern "C" {
    fn ec_GFp_mont_felem_reduce(
        group: *const EC_GROUP,
        out: *mut EC_FELEM,
        words: *const BN_ULONG,
        num: size_t,
    );
    fn ec_GFp_mont_felem_exp(
        group: *const EC_GROUP,
        out: *mut EC_FELEM,
        a: *const EC_FELEM,
        exp: *const BN_ULONG,
        num_exp: size_t,
    );
    fn ec_GFp_simple_is_at_infinity(
        _: *const EC_GROUP,
        _: *const EC_JACOBIAN,
    ) -> libc::c_int;
    fn ec_simple_scalar_inv0_montgomery(
        group: *const EC_GROUP,
        r: *mut EC_SCALAR,
        a: *const EC_SCALAR,
    );
    fn ec_simple_scalar_to_montgomery_inv_vartime(
        group: *const EC_GROUP,
        r: *mut EC_SCALAR,
        a: *const EC_SCALAR,
    ) -> libc::c_int;
    fn ec_GFp_mont_felem_mul(
        _: *const EC_GROUP,
        r: *mut EC_FELEM,
        a: *const EC_FELEM,
        b: *const EC_FELEM,
    );
    fn ec_GFp_mont_felem_sqr(_: *const EC_GROUP, r: *mut EC_FELEM, a: *const EC_FELEM);
    fn ec_GFp_mont_felem_to_bytes(
        group: *const EC_GROUP,
        out: *mut uint8_t,
        out_len: *mut size_t,
        in_0: *const EC_FELEM,
    );
    fn ec_GFp_mont_felem_from_bytes(
        group: *const EC_GROUP,
        out: *mut EC_FELEM,
        in_0: *const uint8_t,
        len: size_t,
    ) -> libc::c_int;
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
    fn bn_add_words(
        rp: *mut BN_ULONG,
        ap: *const BN_ULONG,
        bp: *const BN_ULONG,
        num: size_t,
    ) -> BN_ULONG;
    fn bn_less_than_words(
        a: *const BN_ULONG,
        b: *const BN_ULONG,
        len: size_t,
    ) -> libc::c_int;
    fn ec_nistp_point_double(
        ctx: *const ec_nistp_meth,
        x_out: *mut ec_nistp_felem_limb,
        y_out: *mut ec_nistp_felem_limb,
        z_out: *mut ec_nistp_felem_limb,
        x_in: *const ec_nistp_felem_limb,
        y_in: *const ec_nistp_felem_limb,
        z_in: *const ec_nistp_felem_limb,
    );
    fn ec_nistp_point_add(
        ctx: *const ec_nistp_meth,
        x3: *mut ec_nistp_felem_limb,
        y3: *mut ec_nistp_felem_limb,
        z3: *mut ec_nistp_felem_limb,
        x1: *const ec_nistp_felem_limb,
        y1: *const ec_nistp_felem_limb,
        z1: *const ec_nistp_felem_limb,
        mixed: libc::c_int,
        x2: *const ec_nistp_felem_limb,
        y2: *const ec_nistp_felem_limb,
        z2: *const ec_nistp_felem_limb,
    );
    fn ec_nistp_scalar_mul(
        ctx: *const ec_nistp_meth,
        x_out: *mut ec_nistp_felem_limb,
        y_out: *mut ec_nistp_felem_limb,
        z_out: *mut ec_nistp_felem_limb,
        x_in: *const ec_nistp_felem_limb,
        y_in: *const ec_nistp_felem_limb,
        z_in: *const ec_nistp_felem_limb,
        scalar: *const EC_SCALAR,
    );
    fn ec_nistp_scalar_mul_base(
        ctx: *const ec_nistp_meth,
        x_out: *mut ec_nistp_felem_limb,
        y_out: *mut ec_nistp_felem_limb,
        z_out: *mut ec_nistp_felem_limb,
        scalar: *const EC_SCALAR,
    );
    fn ec_nistp_scalar_mul_public(
        ctx: *const ec_nistp_meth,
        x_out: *mut ec_nistp_felem_limb,
        y_out: *mut ec_nistp_felem_limb,
        z_out: *mut ec_nistp_felem_limb,
        g_scalar: *const EC_SCALAR,
        x_p: *const ec_nistp_felem_limb,
        y_p: *const ec_nistp_felem_limb,
        z_p: *const ec_nistp_felem_limb,
        p_scalar: *const EC_SCALAR,
    );
}
pub type __int128_t = i128;
pub type __uint128_t = u128;
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
pub type CRYPTO_once_t = pthread_once_t;
pub type fiat_p256_felem = [uint64_t; 4];
pub type fiat_p256_uint1 = libc::c_uchar;
pub type fiat_p256_int1 = libc::c_schar;
pub type fiat_p256_int128 = __int128_t;
pub type fiat_p256_uint128 = __uint128_t;
pub type ec_nistp_felem_limb = uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ec_nistp_meth {
    pub felem_num_limbs: size_t,
    pub felem_num_bits: size_t,
    pub felem_add: Option::<
        unsafe extern "C" fn(
            *mut ec_nistp_felem_limb,
            *const ec_nistp_felem_limb,
            *const ec_nistp_felem_limb,
        ) -> (),
    >,
    pub felem_sub: Option::<
        unsafe extern "C" fn(
            *mut ec_nistp_felem_limb,
            *const ec_nistp_felem_limb,
            *const ec_nistp_felem_limb,
        ) -> (),
    >,
    pub felem_mul: Option::<
        unsafe extern "C" fn(
            *mut ec_nistp_felem_limb,
            *const ec_nistp_felem_limb,
            *const ec_nistp_felem_limb,
        ) -> (),
    >,
    pub felem_sqr: Option::<
        unsafe extern "C" fn(*mut ec_nistp_felem_limb, *const ec_nistp_felem_limb) -> (),
    >,
    pub felem_neg: Option::<
        unsafe extern "C" fn(*mut ec_nistp_felem_limb, *const ec_nistp_felem_limb) -> (),
    >,
    pub felem_nz: Option::<
        unsafe extern "C" fn(*const ec_nistp_felem_limb) -> ec_nistp_felem_limb,
    >,
    pub felem_one: *const ec_nistp_felem_limb,
    pub point_dbl: Option::<
        unsafe extern "C" fn(
            *mut ec_nistp_felem_limb,
            *mut ec_nistp_felem_limb,
            *mut ec_nistp_felem_limb,
            *const ec_nistp_felem_limb,
            *const ec_nistp_felem_limb,
            *const ec_nistp_felem_limb,
        ) -> (),
    >,
    pub point_add: Option::<
        unsafe extern "C" fn(
            *mut ec_nistp_felem_limb,
            *mut ec_nistp_felem_limb,
            *mut ec_nistp_felem_limb,
            *const ec_nistp_felem_limb,
            *const ec_nistp_felem_limb,
            *const ec_nistp_felem_limb,
            libc::c_int,
            *const ec_nistp_felem_limb,
            *const ec_nistp_felem_limb,
            *const ec_nistp_felem_limb,
        ) -> (),
    >,
    pub scalar_mul_base_table: *const ec_nistp_felem_limb,
}
pub type fiat_p256_limb_t = uint64_t;
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
unsafe extern "C" fn fiat_p256_value_barrier_u64(mut a: uint64_t) -> uint64_t {
    asm!("", inlateout(reg) a, options(preserves_flags, pure, readonly, att_syntax));
    return a;
}
#[inline]
unsafe extern "C" fn fiat_p256_addcarryx_u64(
    mut out1: *mut uint64_t,
    mut out2: *mut fiat_p256_uint1,
    mut arg1: fiat_p256_uint1,
    mut arg2: uint64_t,
    mut arg3: uint64_t,
) {
    let mut x1: fiat_p256_uint128 = 0;
    let mut x2: uint64_t = 0;
    let mut x3: fiat_p256_uint1 = 0;
    x1 = (arg1 as fiat_p256_uint128)
        .wrapping_add(arg2 as fiat_p256_uint128)
        .wrapping_add(arg3 as fiat_p256_uint128);
    x2 = (x1 & 0xffffffffffffffff as libc::c_ulong as fiat_p256_uint128) as uint64_t;
    x3 = (x1 >> 64 as libc::c_int) as fiat_p256_uint1;
    *out1 = x2;
    *out2 = x3;
}
#[inline]
unsafe extern "C" fn fiat_p256_subborrowx_u64(
    mut out1: *mut uint64_t,
    mut out2: *mut fiat_p256_uint1,
    mut arg1: fiat_p256_uint1,
    mut arg2: uint64_t,
    mut arg3: uint64_t,
) {
    let mut x1: fiat_p256_int128 = 0;
    let mut x2: fiat_p256_int1 = 0;
    let mut x3: uint64_t = 0;
    x1 = arg2 as fiat_p256_int128 - arg1 as fiat_p256_int128 - arg3 as fiat_p256_int128;
    x2 = (x1 >> 64 as libc::c_int) as fiat_p256_int1;
    x3 = (x1 & 0xffffffffffffffff as libc::c_ulong as fiat_p256_int128) as uint64_t;
    *out1 = x3;
    *out2 = (0 as libc::c_int - x2 as libc::c_int) as fiat_p256_uint1;
}
#[inline]
unsafe extern "C" fn fiat_p256_mulx_u64(
    mut out1: *mut uint64_t,
    mut out2: *mut uint64_t,
    mut arg1: uint64_t,
    mut arg2: uint64_t,
) {
    let mut x1: fiat_p256_uint128 = 0;
    let mut x2: uint64_t = 0;
    let mut x3: uint64_t = 0;
    x1 = arg1 as fiat_p256_uint128 * arg2 as fiat_p256_uint128;
    x2 = (x1 & 0xffffffffffffffff as libc::c_ulong as fiat_p256_uint128) as uint64_t;
    x3 = (x1 >> 64 as libc::c_int) as uint64_t;
    *out1 = x2;
    *out2 = x3;
}
#[inline]
unsafe extern "C" fn fiat_p256_cmovznz_u64(
    mut out1: *mut uint64_t,
    mut arg1: fiat_p256_uint1,
    mut arg2: uint64_t,
    mut arg3: uint64_t,
) {
    let mut x1: fiat_p256_uint1 = 0;
    let mut x2: uint64_t = 0;
    let mut x3: uint64_t = 0;
    x1 = (arg1 != 0) as libc::c_int as fiat_p256_uint1;
    x2 = (0 as libc::c_int - x1 as libc::c_int) as fiat_p256_int1 as libc::c_ulong
        & 0xffffffffffffffff as libc::c_ulong;
    x3 = fiat_p256_value_barrier_u64(x2) & arg3
        | fiat_p256_value_barrier_u64(!x2) & arg2;
    *out1 = x3;
}
#[inline]
unsafe extern "C" fn fiat_p256_mul(
    mut out1: *mut uint64_t,
    mut arg1: *const uint64_t,
    mut arg2: *const uint64_t,
) {
    let mut x1: uint64_t = 0;
    let mut x2: uint64_t = 0;
    let mut x3: uint64_t = 0;
    let mut x4: uint64_t = 0;
    let mut x5: uint64_t = 0;
    let mut x6: uint64_t = 0;
    let mut x7: uint64_t = 0;
    let mut x8: uint64_t = 0;
    let mut x9: uint64_t = 0;
    let mut x10: uint64_t = 0;
    let mut x11: uint64_t = 0;
    let mut x12: uint64_t = 0;
    let mut x13: uint64_t = 0;
    let mut x14: fiat_p256_uint1 = 0;
    let mut x15: uint64_t = 0;
    let mut x16: fiat_p256_uint1 = 0;
    let mut x17: uint64_t = 0;
    let mut x18: fiat_p256_uint1 = 0;
    let mut x19: uint64_t = 0;
    let mut x20: uint64_t = 0;
    let mut x21: uint64_t = 0;
    let mut x22: uint64_t = 0;
    let mut x23: uint64_t = 0;
    let mut x24: uint64_t = 0;
    let mut x25: uint64_t = 0;
    let mut x26: uint64_t = 0;
    let mut x27: fiat_p256_uint1 = 0;
    let mut x28: uint64_t = 0;
    let mut x29: uint64_t = 0;
    let mut x30: fiat_p256_uint1 = 0;
    let mut x31: uint64_t = 0;
    let mut x32: fiat_p256_uint1 = 0;
    let mut x33: uint64_t = 0;
    let mut x34: fiat_p256_uint1 = 0;
    let mut x35: uint64_t = 0;
    let mut x36: fiat_p256_uint1 = 0;
    let mut x37: uint64_t = 0;
    let mut x38: fiat_p256_uint1 = 0;
    let mut x39: uint64_t = 0;
    let mut x40: uint64_t = 0;
    let mut x41: uint64_t = 0;
    let mut x42: uint64_t = 0;
    let mut x43: uint64_t = 0;
    let mut x44: uint64_t = 0;
    let mut x45: uint64_t = 0;
    let mut x46: uint64_t = 0;
    let mut x47: uint64_t = 0;
    let mut x48: fiat_p256_uint1 = 0;
    let mut x49: uint64_t = 0;
    let mut x50: fiat_p256_uint1 = 0;
    let mut x51: uint64_t = 0;
    let mut x52: fiat_p256_uint1 = 0;
    let mut x53: uint64_t = 0;
    let mut x54: uint64_t = 0;
    let mut x55: fiat_p256_uint1 = 0;
    let mut x56: uint64_t = 0;
    let mut x57: fiat_p256_uint1 = 0;
    let mut x58: uint64_t = 0;
    let mut x59: fiat_p256_uint1 = 0;
    let mut x60: uint64_t = 0;
    let mut x61: fiat_p256_uint1 = 0;
    let mut x62: uint64_t = 0;
    let mut x63: fiat_p256_uint1 = 0;
    let mut x64: uint64_t = 0;
    let mut x65: uint64_t = 0;
    let mut x66: uint64_t = 0;
    let mut x67: uint64_t = 0;
    let mut x68: uint64_t = 0;
    let mut x69: uint64_t = 0;
    let mut x70: uint64_t = 0;
    let mut x71: fiat_p256_uint1 = 0;
    let mut x72: uint64_t = 0;
    let mut x73: uint64_t = 0;
    let mut x74: fiat_p256_uint1 = 0;
    let mut x75: uint64_t = 0;
    let mut x76: fiat_p256_uint1 = 0;
    let mut x77: uint64_t = 0;
    let mut x78: fiat_p256_uint1 = 0;
    let mut x79: uint64_t = 0;
    let mut x80: fiat_p256_uint1 = 0;
    let mut x81: uint64_t = 0;
    let mut x82: fiat_p256_uint1 = 0;
    let mut x83: uint64_t = 0;
    let mut x84: uint64_t = 0;
    let mut x85: uint64_t = 0;
    let mut x86: uint64_t = 0;
    let mut x87: uint64_t = 0;
    let mut x88: uint64_t = 0;
    let mut x89: uint64_t = 0;
    let mut x90: uint64_t = 0;
    let mut x91: uint64_t = 0;
    let mut x92: uint64_t = 0;
    let mut x93: fiat_p256_uint1 = 0;
    let mut x94: uint64_t = 0;
    let mut x95: fiat_p256_uint1 = 0;
    let mut x96: uint64_t = 0;
    let mut x97: fiat_p256_uint1 = 0;
    let mut x98: uint64_t = 0;
    let mut x99: uint64_t = 0;
    let mut x100: fiat_p256_uint1 = 0;
    let mut x101: uint64_t = 0;
    let mut x102: fiat_p256_uint1 = 0;
    let mut x103: uint64_t = 0;
    let mut x104: fiat_p256_uint1 = 0;
    let mut x105: uint64_t = 0;
    let mut x106: fiat_p256_uint1 = 0;
    let mut x107: uint64_t = 0;
    let mut x108: fiat_p256_uint1 = 0;
    let mut x109: uint64_t = 0;
    let mut x110: uint64_t = 0;
    let mut x111: uint64_t = 0;
    let mut x112: uint64_t = 0;
    let mut x113: uint64_t = 0;
    let mut x114: uint64_t = 0;
    let mut x115: uint64_t = 0;
    let mut x116: fiat_p256_uint1 = 0;
    let mut x117: uint64_t = 0;
    let mut x118: uint64_t = 0;
    let mut x119: fiat_p256_uint1 = 0;
    let mut x120: uint64_t = 0;
    let mut x121: fiat_p256_uint1 = 0;
    let mut x122: uint64_t = 0;
    let mut x123: fiat_p256_uint1 = 0;
    let mut x124: uint64_t = 0;
    let mut x125: fiat_p256_uint1 = 0;
    let mut x126: uint64_t = 0;
    let mut x127: fiat_p256_uint1 = 0;
    let mut x128: uint64_t = 0;
    let mut x129: uint64_t = 0;
    let mut x130: uint64_t = 0;
    let mut x131: uint64_t = 0;
    let mut x132: uint64_t = 0;
    let mut x133: uint64_t = 0;
    let mut x134: uint64_t = 0;
    let mut x135: uint64_t = 0;
    let mut x136: uint64_t = 0;
    let mut x137: uint64_t = 0;
    let mut x138: fiat_p256_uint1 = 0;
    let mut x139: uint64_t = 0;
    let mut x140: fiat_p256_uint1 = 0;
    let mut x141: uint64_t = 0;
    let mut x142: fiat_p256_uint1 = 0;
    let mut x143: uint64_t = 0;
    let mut x144: uint64_t = 0;
    let mut x145: fiat_p256_uint1 = 0;
    let mut x146: uint64_t = 0;
    let mut x147: fiat_p256_uint1 = 0;
    let mut x148: uint64_t = 0;
    let mut x149: fiat_p256_uint1 = 0;
    let mut x150: uint64_t = 0;
    let mut x151: fiat_p256_uint1 = 0;
    let mut x152: uint64_t = 0;
    let mut x153: fiat_p256_uint1 = 0;
    let mut x154: uint64_t = 0;
    let mut x155: uint64_t = 0;
    let mut x156: uint64_t = 0;
    let mut x157: uint64_t = 0;
    let mut x158: uint64_t = 0;
    let mut x159: uint64_t = 0;
    let mut x160: uint64_t = 0;
    let mut x161: fiat_p256_uint1 = 0;
    let mut x162: uint64_t = 0;
    let mut x163: uint64_t = 0;
    let mut x164: fiat_p256_uint1 = 0;
    let mut x165: uint64_t = 0;
    let mut x166: fiat_p256_uint1 = 0;
    let mut x167: uint64_t = 0;
    let mut x168: fiat_p256_uint1 = 0;
    let mut x169: uint64_t = 0;
    let mut x170: fiat_p256_uint1 = 0;
    let mut x171: uint64_t = 0;
    let mut x172: fiat_p256_uint1 = 0;
    let mut x173: uint64_t = 0;
    let mut x174: uint64_t = 0;
    let mut x175: fiat_p256_uint1 = 0;
    let mut x176: uint64_t = 0;
    let mut x177: fiat_p256_uint1 = 0;
    let mut x178: uint64_t = 0;
    let mut x179: fiat_p256_uint1 = 0;
    let mut x180: uint64_t = 0;
    let mut x181: fiat_p256_uint1 = 0;
    let mut x182: uint64_t = 0;
    let mut x183: fiat_p256_uint1 = 0;
    let mut x184: uint64_t = 0;
    let mut x185: uint64_t = 0;
    let mut x186: uint64_t = 0;
    let mut x187: uint64_t = 0;
    x1 = *arg1.offset(1 as libc::c_int as isize);
    x2 = *arg1.offset(2 as libc::c_int as isize);
    x3 = *arg1.offset(3 as libc::c_int as isize);
    x4 = *arg1.offset(0 as libc::c_int as isize);
    fiat_p256_mulx_u64(&mut x5, &mut x6, x4, *arg2.offset(3 as libc::c_int as isize));
    fiat_p256_mulx_u64(&mut x7, &mut x8, x4, *arg2.offset(2 as libc::c_int as isize));
    fiat_p256_mulx_u64(&mut x9, &mut x10, x4, *arg2.offset(1 as libc::c_int as isize));
    fiat_p256_mulx_u64(&mut x11, &mut x12, x4, *arg2.offset(0 as libc::c_int as isize));
    fiat_p256_addcarryx_u64(
        &mut x13,
        &mut x14,
        0 as libc::c_int as fiat_p256_uint1,
        x12,
        x9,
    );
    fiat_p256_addcarryx_u64(&mut x15, &mut x16, x14, x10, x7);
    fiat_p256_addcarryx_u64(&mut x17, &mut x18, x16, x8, x5);
    x19 = (x18 as uint64_t).wrapping_add(x6);
    fiat_p256_mulx_u64(&mut x20, &mut x21, x11, 0xffffffff00000001 as libc::c_ulong);
    fiat_p256_mulx_u64(&mut x22, &mut x23, x11, 0xffffffff as libc::c_uint as uint64_t);
    fiat_p256_mulx_u64(&mut x24, &mut x25, x11, 0xffffffffffffffff as libc::c_ulong);
    fiat_p256_addcarryx_u64(
        &mut x26,
        &mut x27,
        0 as libc::c_int as fiat_p256_uint1,
        x25,
        x22,
    );
    x28 = (x27 as uint64_t).wrapping_add(x23);
    fiat_p256_addcarryx_u64(
        &mut x29,
        &mut x30,
        0 as libc::c_int as fiat_p256_uint1,
        x11,
        x24,
    );
    fiat_p256_addcarryx_u64(&mut x31, &mut x32, x30, x13, x26);
    fiat_p256_addcarryx_u64(&mut x33, &mut x34, x32, x15, x28);
    fiat_p256_addcarryx_u64(&mut x35, &mut x36, x34, x17, x20);
    fiat_p256_addcarryx_u64(&mut x37, &mut x38, x36, x19, x21);
    fiat_p256_mulx_u64(&mut x39, &mut x40, x1, *arg2.offset(3 as libc::c_int as isize));
    fiat_p256_mulx_u64(&mut x41, &mut x42, x1, *arg2.offset(2 as libc::c_int as isize));
    fiat_p256_mulx_u64(&mut x43, &mut x44, x1, *arg2.offset(1 as libc::c_int as isize));
    fiat_p256_mulx_u64(&mut x45, &mut x46, x1, *arg2.offset(0 as libc::c_int as isize));
    fiat_p256_addcarryx_u64(
        &mut x47,
        &mut x48,
        0 as libc::c_int as fiat_p256_uint1,
        x46,
        x43,
    );
    fiat_p256_addcarryx_u64(&mut x49, &mut x50, x48, x44, x41);
    fiat_p256_addcarryx_u64(&mut x51, &mut x52, x50, x42, x39);
    x53 = (x52 as uint64_t).wrapping_add(x40);
    fiat_p256_addcarryx_u64(
        &mut x54,
        &mut x55,
        0 as libc::c_int as fiat_p256_uint1,
        x31,
        x45,
    );
    fiat_p256_addcarryx_u64(&mut x56, &mut x57, x55, x33, x47);
    fiat_p256_addcarryx_u64(&mut x58, &mut x59, x57, x35, x49);
    fiat_p256_addcarryx_u64(&mut x60, &mut x61, x59, x37, x51);
    fiat_p256_addcarryx_u64(&mut x62, &mut x63, x61, x38 as uint64_t, x53);
    fiat_p256_mulx_u64(&mut x64, &mut x65, x54, 0xffffffff00000001 as libc::c_ulong);
    fiat_p256_mulx_u64(&mut x66, &mut x67, x54, 0xffffffff as libc::c_uint as uint64_t);
    fiat_p256_mulx_u64(&mut x68, &mut x69, x54, 0xffffffffffffffff as libc::c_ulong);
    fiat_p256_addcarryx_u64(
        &mut x70,
        &mut x71,
        0 as libc::c_int as fiat_p256_uint1,
        x69,
        x66,
    );
    x72 = (x71 as uint64_t).wrapping_add(x67);
    fiat_p256_addcarryx_u64(
        &mut x73,
        &mut x74,
        0 as libc::c_int as fiat_p256_uint1,
        x54,
        x68,
    );
    fiat_p256_addcarryx_u64(&mut x75, &mut x76, x74, x56, x70);
    fiat_p256_addcarryx_u64(&mut x77, &mut x78, x76, x58, x72);
    fiat_p256_addcarryx_u64(&mut x79, &mut x80, x78, x60, x64);
    fiat_p256_addcarryx_u64(&mut x81, &mut x82, x80, x62, x65);
    x83 = (x82 as uint64_t).wrapping_add(x63 as uint64_t);
    fiat_p256_mulx_u64(&mut x84, &mut x85, x2, *arg2.offset(3 as libc::c_int as isize));
    fiat_p256_mulx_u64(&mut x86, &mut x87, x2, *arg2.offset(2 as libc::c_int as isize));
    fiat_p256_mulx_u64(&mut x88, &mut x89, x2, *arg2.offset(1 as libc::c_int as isize));
    fiat_p256_mulx_u64(&mut x90, &mut x91, x2, *arg2.offset(0 as libc::c_int as isize));
    fiat_p256_addcarryx_u64(
        &mut x92,
        &mut x93,
        0 as libc::c_int as fiat_p256_uint1,
        x91,
        x88,
    );
    fiat_p256_addcarryx_u64(&mut x94, &mut x95, x93, x89, x86);
    fiat_p256_addcarryx_u64(&mut x96, &mut x97, x95, x87, x84);
    x98 = (x97 as uint64_t).wrapping_add(x85);
    fiat_p256_addcarryx_u64(
        &mut x99,
        &mut x100,
        0 as libc::c_int as fiat_p256_uint1,
        x75,
        x90,
    );
    fiat_p256_addcarryx_u64(&mut x101, &mut x102, x100, x77, x92);
    fiat_p256_addcarryx_u64(&mut x103, &mut x104, x102, x79, x94);
    fiat_p256_addcarryx_u64(&mut x105, &mut x106, x104, x81, x96);
    fiat_p256_addcarryx_u64(&mut x107, &mut x108, x106, x83, x98);
    fiat_p256_mulx_u64(&mut x109, &mut x110, x99, 0xffffffff00000001 as libc::c_ulong);
    fiat_p256_mulx_u64(
        &mut x111,
        &mut x112,
        x99,
        0xffffffff as libc::c_uint as uint64_t,
    );
    fiat_p256_mulx_u64(&mut x113, &mut x114, x99, 0xffffffffffffffff as libc::c_ulong);
    fiat_p256_addcarryx_u64(
        &mut x115,
        &mut x116,
        0 as libc::c_int as fiat_p256_uint1,
        x114,
        x111,
    );
    x117 = (x116 as uint64_t).wrapping_add(x112);
    fiat_p256_addcarryx_u64(
        &mut x118,
        &mut x119,
        0 as libc::c_int as fiat_p256_uint1,
        x99,
        x113,
    );
    fiat_p256_addcarryx_u64(&mut x120, &mut x121, x119, x101, x115);
    fiat_p256_addcarryx_u64(&mut x122, &mut x123, x121, x103, x117);
    fiat_p256_addcarryx_u64(&mut x124, &mut x125, x123, x105, x109);
    fiat_p256_addcarryx_u64(&mut x126, &mut x127, x125, x107, x110);
    x128 = (x127 as uint64_t).wrapping_add(x108 as uint64_t);
    fiat_p256_mulx_u64(
        &mut x129,
        &mut x130,
        x3,
        *arg2.offset(3 as libc::c_int as isize),
    );
    fiat_p256_mulx_u64(
        &mut x131,
        &mut x132,
        x3,
        *arg2.offset(2 as libc::c_int as isize),
    );
    fiat_p256_mulx_u64(
        &mut x133,
        &mut x134,
        x3,
        *arg2.offset(1 as libc::c_int as isize),
    );
    fiat_p256_mulx_u64(
        &mut x135,
        &mut x136,
        x3,
        *arg2.offset(0 as libc::c_int as isize),
    );
    fiat_p256_addcarryx_u64(
        &mut x137,
        &mut x138,
        0 as libc::c_int as fiat_p256_uint1,
        x136,
        x133,
    );
    fiat_p256_addcarryx_u64(&mut x139, &mut x140, x138, x134, x131);
    fiat_p256_addcarryx_u64(&mut x141, &mut x142, x140, x132, x129);
    x143 = (x142 as uint64_t).wrapping_add(x130);
    fiat_p256_addcarryx_u64(
        &mut x144,
        &mut x145,
        0 as libc::c_int as fiat_p256_uint1,
        x120,
        x135,
    );
    fiat_p256_addcarryx_u64(&mut x146, &mut x147, x145, x122, x137);
    fiat_p256_addcarryx_u64(&mut x148, &mut x149, x147, x124, x139);
    fiat_p256_addcarryx_u64(&mut x150, &mut x151, x149, x126, x141);
    fiat_p256_addcarryx_u64(&mut x152, &mut x153, x151, x128, x143);
    fiat_p256_mulx_u64(&mut x154, &mut x155, x144, 0xffffffff00000001 as libc::c_ulong);
    fiat_p256_mulx_u64(
        &mut x156,
        &mut x157,
        x144,
        0xffffffff as libc::c_uint as uint64_t,
    );
    fiat_p256_mulx_u64(&mut x158, &mut x159, x144, 0xffffffffffffffff as libc::c_ulong);
    fiat_p256_addcarryx_u64(
        &mut x160,
        &mut x161,
        0 as libc::c_int as fiat_p256_uint1,
        x159,
        x156,
    );
    x162 = (x161 as uint64_t).wrapping_add(x157);
    fiat_p256_addcarryx_u64(
        &mut x163,
        &mut x164,
        0 as libc::c_int as fiat_p256_uint1,
        x144,
        x158,
    );
    fiat_p256_addcarryx_u64(&mut x165, &mut x166, x164, x146, x160);
    fiat_p256_addcarryx_u64(&mut x167, &mut x168, x166, x148, x162);
    fiat_p256_addcarryx_u64(&mut x169, &mut x170, x168, x150, x154);
    fiat_p256_addcarryx_u64(&mut x171, &mut x172, x170, x152, x155);
    x173 = (x172 as uint64_t).wrapping_add(x153 as uint64_t);
    fiat_p256_subborrowx_u64(
        &mut x174,
        &mut x175,
        0 as libc::c_int as fiat_p256_uint1,
        x165,
        0xffffffffffffffff as libc::c_ulong,
    );
    fiat_p256_subborrowx_u64(
        &mut x176,
        &mut x177,
        x175,
        x167,
        0xffffffff as libc::c_uint as uint64_t,
    );
    fiat_p256_subborrowx_u64(
        &mut x178,
        &mut x179,
        x177,
        x169,
        0 as libc::c_int as uint64_t,
    );
    fiat_p256_subborrowx_u64(
        &mut x180,
        &mut x181,
        x179,
        x171,
        0xffffffff00000001 as libc::c_ulong,
    );
    fiat_p256_subborrowx_u64(
        &mut x182,
        &mut x183,
        x181,
        x173,
        0 as libc::c_int as uint64_t,
    );
    fiat_p256_cmovznz_u64(&mut x184, x183, x174, x165);
    fiat_p256_cmovznz_u64(&mut x185, x183, x176, x167);
    fiat_p256_cmovznz_u64(&mut x186, x183, x178, x169);
    fiat_p256_cmovznz_u64(&mut x187, x183, x180, x171);
    *out1.offset(0 as libc::c_int as isize) = x184;
    *out1.offset(1 as libc::c_int as isize) = x185;
    *out1.offset(2 as libc::c_int as isize) = x186;
    *out1.offset(3 as libc::c_int as isize) = x187;
}
#[inline]
unsafe extern "C" fn fiat_p256_square(
    mut out1: *mut uint64_t,
    mut arg1: *const uint64_t,
) {
    let mut x1: uint64_t = 0;
    let mut x2: uint64_t = 0;
    let mut x3: uint64_t = 0;
    let mut x4: uint64_t = 0;
    let mut x5: uint64_t = 0;
    let mut x6: uint64_t = 0;
    let mut x7: uint64_t = 0;
    let mut x8: uint64_t = 0;
    let mut x9: uint64_t = 0;
    let mut x10: uint64_t = 0;
    let mut x11: uint64_t = 0;
    let mut x12: uint64_t = 0;
    let mut x13: uint64_t = 0;
    let mut x14: fiat_p256_uint1 = 0;
    let mut x15: uint64_t = 0;
    let mut x16: fiat_p256_uint1 = 0;
    let mut x17: uint64_t = 0;
    let mut x18: fiat_p256_uint1 = 0;
    let mut x19: uint64_t = 0;
    let mut x20: uint64_t = 0;
    let mut x21: uint64_t = 0;
    let mut x22: uint64_t = 0;
    let mut x23: uint64_t = 0;
    let mut x24: uint64_t = 0;
    let mut x25: uint64_t = 0;
    let mut x26: uint64_t = 0;
    let mut x27: fiat_p256_uint1 = 0;
    let mut x28: uint64_t = 0;
    let mut x29: uint64_t = 0;
    let mut x30: fiat_p256_uint1 = 0;
    let mut x31: uint64_t = 0;
    let mut x32: fiat_p256_uint1 = 0;
    let mut x33: uint64_t = 0;
    let mut x34: fiat_p256_uint1 = 0;
    let mut x35: uint64_t = 0;
    let mut x36: fiat_p256_uint1 = 0;
    let mut x37: uint64_t = 0;
    let mut x38: fiat_p256_uint1 = 0;
    let mut x39: uint64_t = 0;
    let mut x40: uint64_t = 0;
    let mut x41: uint64_t = 0;
    let mut x42: uint64_t = 0;
    let mut x43: uint64_t = 0;
    let mut x44: uint64_t = 0;
    let mut x45: uint64_t = 0;
    let mut x46: uint64_t = 0;
    let mut x47: uint64_t = 0;
    let mut x48: fiat_p256_uint1 = 0;
    let mut x49: uint64_t = 0;
    let mut x50: fiat_p256_uint1 = 0;
    let mut x51: uint64_t = 0;
    let mut x52: fiat_p256_uint1 = 0;
    let mut x53: uint64_t = 0;
    let mut x54: uint64_t = 0;
    let mut x55: fiat_p256_uint1 = 0;
    let mut x56: uint64_t = 0;
    let mut x57: fiat_p256_uint1 = 0;
    let mut x58: uint64_t = 0;
    let mut x59: fiat_p256_uint1 = 0;
    let mut x60: uint64_t = 0;
    let mut x61: fiat_p256_uint1 = 0;
    let mut x62: uint64_t = 0;
    let mut x63: fiat_p256_uint1 = 0;
    let mut x64: uint64_t = 0;
    let mut x65: uint64_t = 0;
    let mut x66: uint64_t = 0;
    let mut x67: uint64_t = 0;
    let mut x68: uint64_t = 0;
    let mut x69: uint64_t = 0;
    let mut x70: uint64_t = 0;
    let mut x71: fiat_p256_uint1 = 0;
    let mut x72: uint64_t = 0;
    let mut x73: uint64_t = 0;
    let mut x74: fiat_p256_uint1 = 0;
    let mut x75: uint64_t = 0;
    let mut x76: fiat_p256_uint1 = 0;
    let mut x77: uint64_t = 0;
    let mut x78: fiat_p256_uint1 = 0;
    let mut x79: uint64_t = 0;
    let mut x80: fiat_p256_uint1 = 0;
    let mut x81: uint64_t = 0;
    let mut x82: fiat_p256_uint1 = 0;
    let mut x83: uint64_t = 0;
    let mut x84: uint64_t = 0;
    let mut x85: uint64_t = 0;
    let mut x86: uint64_t = 0;
    let mut x87: uint64_t = 0;
    let mut x88: uint64_t = 0;
    let mut x89: uint64_t = 0;
    let mut x90: uint64_t = 0;
    let mut x91: uint64_t = 0;
    let mut x92: uint64_t = 0;
    let mut x93: fiat_p256_uint1 = 0;
    let mut x94: uint64_t = 0;
    let mut x95: fiat_p256_uint1 = 0;
    let mut x96: uint64_t = 0;
    let mut x97: fiat_p256_uint1 = 0;
    let mut x98: uint64_t = 0;
    let mut x99: uint64_t = 0;
    let mut x100: fiat_p256_uint1 = 0;
    let mut x101: uint64_t = 0;
    let mut x102: fiat_p256_uint1 = 0;
    let mut x103: uint64_t = 0;
    let mut x104: fiat_p256_uint1 = 0;
    let mut x105: uint64_t = 0;
    let mut x106: fiat_p256_uint1 = 0;
    let mut x107: uint64_t = 0;
    let mut x108: fiat_p256_uint1 = 0;
    let mut x109: uint64_t = 0;
    let mut x110: uint64_t = 0;
    let mut x111: uint64_t = 0;
    let mut x112: uint64_t = 0;
    let mut x113: uint64_t = 0;
    let mut x114: uint64_t = 0;
    let mut x115: uint64_t = 0;
    let mut x116: fiat_p256_uint1 = 0;
    let mut x117: uint64_t = 0;
    let mut x118: uint64_t = 0;
    let mut x119: fiat_p256_uint1 = 0;
    let mut x120: uint64_t = 0;
    let mut x121: fiat_p256_uint1 = 0;
    let mut x122: uint64_t = 0;
    let mut x123: fiat_p256_uint1 = 0;
    let mut x124: uint64_t = 0;
    let mut x125: fiat_p256_uint1 = 0;
    let mut x126: uint64_t = 0;
    let mut x127: fiat_p256_uint1 = 0;
    let mut x128: uint64_t = 0;
    let mut x129: uint64_t = 0;
    let mut x130: uint64_t = 0;
    let mut x131: uint64_t = 0;
    let mut x132: uint64_t = 0;
    let mut x133: uint64_t = 0;
    let mut x134: uint64_t = 0;
    let mut x135: uint64_t = 0;
    let mut x136: uint64_t = 0;
    let mut x137: uint64_t = 0;
    let mut x138: fiat_p256_uint1 = 0;
    let mut x139: uint64_t = 0;
    let mut x140: fiat_p256_uint1 = 0;
    let mut x141: uint64_t = 0;
    let mut x142: fiat_p256_uint1 = 0;
    let mut x143: uint64_t = 0;
    let mut x144: uint64_t = 0;
    let mut x145: fiat_p256_uint1 = 0;
    let mut x146: uint64_t = 0;
    let mut x147: fiat_p256_uint1 = 0;
    let mut x148: uint64_t = 0;
    let mut x149: fiat_p256_uint1 = 0;
    let mut x150: uint64_t = 0;
    let mut x151: fiat_p256_uint1 = 0;
    let mut x152: uint64_t = 0;
    let mut x153: fiat_p256_uint1 = 0;
    let mut x154: uint64_t = 0;
    let mut x155: uint64_t = 0;
    let mut x156: uint64_t = 0;
    let mut x157: uint64_t = 0;
    let mut x158: uint64_t = 0;
    let mut x159: uint64_t = 0;
    let mut x160: uint64_t = 0;
    let mut x161: fiat_p256_uint1 = 0;
    let mut x162: uint64_t = 0;
    let mut x163: uint64_t = 0;
    let mut x164: fiat_p256_uint1 = 0;
    let mut x165: uint64_t = 0;
    let mut x166: fiat_p256_uint1 = 0;
    let mut x167: uint64_t = 0;
    let mut x168: fiat_p256_uint1 = 0;
    let mut x169: uint64_t = 0;
    let mut x170: fiat_p256_uint1 = 0;
    let mut x171: uint64_t = 0;
    let mut x172: fiat_p256_uint1 = 0;
    let mut x173: uint64_t = 0;
    let mut x174: uint64_t = 0;
    let mut x175: fiat_p256_uint1 = 0;
    let mut x176: uint64_t = 0;
    let mut x177: fiat_p256_uint1 = 0;
    let mut x178: uint64_t = 0;
    let mut x179: fiat_p256_uint1 = 0;
    let mut x180: uint64_t = 0;
    let mut x181: fiat_p256_uint1 = 0;
    let mut x182: uint64_t = 0;
    let mut x183: fiat_p256_uint1 = 0;
    let mut x184: uint64_t = 0;
    let mut x185: uint64_t = 0;
    let mut x186: uint64_t = 0;
    let mut x187: uint64_t = 0;
    x1 = *arg1.offset(1 as libc::c_int as isize);
    x2 = *arg1.offset(2 as libc::c_int as isize);
    x3 = *arg1.offset(3 as libc::c_int as isize);
    x4 = *arg1.offset(0 as libc::c_int as isize);
    fiat_p256_mulx_u64(&mut x5, &mut x6, x4, *arg1.offset(3 as libc::c_int as isize));
    fiat_p256_mulx_u64(&mut x7, &mut x8, x4, *arg1.offset(2 as libc::c_int as isize));
    fiat_p256_mulx_u64(&mut x9, &mut x10, x4, *arg1.offset(1 as libc::c_int as isize));
    fiat_p256_mulx_u64(&mut x11, &mut x12, x4, *arg1.offset(0 as libc::c_int as isize));
    fiat_p256_addcarryx_u64(
        &mut x13,
        &mut x14,
        0 as libc::c_int as fiat_p256_uint1,
        x12,
        x9,
    );
    fiat_p256_addcarryx_u64(&mut x15, &mut x16, x14, x10, x7);
    fiat_p256_addcarryx_u64(&mut x17, &mut x18, x16, x8, x5);
    x19 = (x18 as uint64_t).wrapping_add(x6);
    fiat_p256_mulx_u64(&mut x20, &mut x21, x11, 0xffffffff00000001 as libc::c_ulong);
    fiat_p256_mulx_u64(&mut x22, &mut x23, x11, 0xffffffff as libc::c_uint as uint64_t);
    fiat_p256_mulx_u64(&mut x24, &mut x25, x11, 0xffffffffffffffff as libc::c_ulong);
    fiat_p256_addcarryx_u64(
        &mut x26,
        &mut x27,
        0 as libc::c_int as fiat_p256_uint1,
        x25,
        x22,
    );
    x28 = (x27 as uint64_t).wrapping_add(x23);
    fiat_p256_addcarryx_u64(
        &mut x29,
        &mut x30,
        0 as libc::c_int as fiat_p256_uint1,
        x11,
        x24,
    );
    fiat_p256_addcarryx_u64(&mut x31, &mut x32, x30, x13, x26);
    fiat_p256_addcarryx_u64(&mut x33, &mut x34, x32, x15, x28);
    fiat_p256_addcarryx_u64(&mut x35, &mut x36, x34, x17, x20);
    fiat_p256_addcarryx_u64(&mut x37, &mut x38, x36, x19, x21);
    fiat_p256_mulx_u64(&mut x39, &mut x40, x1, *arg1.offset(3 as libc::c_int as isize));
    fiat_p256_mulx_u64(&mut x41, &mut x42, x1, *arg1.offset(2 as libc::c_int as isize));
    fiat_p256_mulx_u64(&mut x43, &mut x44, x1, *arg1.offset(1 as libc::c_int as isize));
    fiat_p256_mulx_u64(&mut x45, &mut x46, x1, *arg1.offset(0 as libc::c_int as isize));
    fiat_p256_addcarryx_u64(
        &mut x47,
        &mut x48,
        0 as libc::c_int as fiat_p256_uint1,
        x46,
        x43,
    );
    fiat_p256_addcarryx_u64(&mut x49, &mut x50, x48, x44, x41);
    fiat_p256_addcarryx_u64(&mut x51, &mut x52, x50, x42, x39);
    x53 = (x52 as uint64_t).wrapping_add(x40);
    fiat_p256_addcarryx_u64(
        &mut x54,
        &mut x55,
        0 as libc::c_int as fiat_p256_uint1,
        x31,
        x45,
    );
    fiat_p256_addcarryx_u64(&mut x56, &mut x57, x55, x33, x47);
    fiat_p256_addcarryx_u64(&mut x58, &mut x59, x57, x35, x49);
    fiat_p256_addcarryx_u64(&mut x60, &mut x61, x59, x37, x51);
    fiat_p256_addcarryx_u64(&mut x62, &mut x63, x61, x38 as uint64_t, x53);
    fiat_p256_mulx_u64(&mut x64, &mut x65, x54, 0xffffffff00000001 as libc::c_ulong);
    fiat_p256_mulx_u64(&mut x66, &mut x67, x54, 0xffffffff as libc::c_uint as uint64_t);
    fiat_p256_mulx_u64(&mut x68, &mut x69, x54, 0xffffffffffffffff as libc::c_ulong);
    fiat_p256_addcarryx_u64(
        &mut x70,
        &mut x71,
        0 as libc::c_int as fiat_p256_uint1,
        x69,
        x66,
    );
    x72 = (x71 as uint64_t).wrapping_add(x67);
    fiat_p256_addcarryx_u64(
        &mut x73,
        &mut x74,
        0 as libc::c_int as fiat_p256_uint1,
        x54,
        x68,
    );
    fiat_p256_addcarryx_u64(&mut x75, &mut x76, x74, x56, x70);
    fiat_p256_addcarryx_u64(&mut x77, &mut x78, x76, x58, x72);
    fiat_p256_addcarryx_u64(&mut x79, &mut x80, x78, x60, x64);
    fiat_p256_addcarryx_u64(&mut x81, &mut x82, x80, x62, x65);
    x83 = (x82 as uint64_t).wrapping_add(x63 as uint64_t);
    fiat_p256_mulx_u64(&mut x84, &mut x85, x2, *arg1.offset(3 as libc::c_int as isize));
    fiat_p256_mulx_u64(&mut x86, &mut x87, x2, *arg1.offset(2 as libc::c_int as isize));
    fiat_p256_mulx_u64(&mut x88, &mut x89, x2, *arg1.offset(1 as libc::c_int as isize));
    fiat_p256_mulx_u64(&mut x90, &mut x91, x2, *arg1.offset(0 as libc::c_int as isize));
    fiat_p256_addcarryx_u64(
        &mut x92,
        &mut x93,
        0 as libc::c_int as fiat_p256_uint1,
        x91,
        x88,
    );
    fiat_p256_addcarryx_u64(&mut x94, &mut x95, x93, x89, x86);
    fiat_p256_addcarryx_u64(&mut x96, &mut x97, x95, x87, x84);
    x98 = (x97 as uint64_t).wrapping_add(x85);
    fiat_p256_addcarryx_u64(
        &mut x99,
        &mut x100,
        0 as libc::c_int as fiat_p256_uint1,
        x75,
        x90,
    );
    fiat_p256_addcarryx_u64(&mut x101, &mut x102, x100, x77, x92);
    fiat_p256_addcarryx_u64(&mut x103, &mut x104, x102, x79, x94);
    fiat_p256_addcarryx_u64(&mut x105, &mut x106, x104, x81, x96);
    fiat_p256_addcarryx_u64(&mut x107, &mut x108, x106, x83, x98);
    fiat_p256_mulx_u64(&mut x109, &mut x110, x99, 0xffffffff00000001 as libc::c_ulong);
    fiat_p256_mulx_u64(
        &mut x111,
        &mut x112,
        x99,
        0xffffffff as libc::c_uint as uint64_t,
    );
    fiat_p256_mulx_u64(&mut x113, &mut x114, x99, 0xffffffffffffffff as libc::c_ulong);
    fiat_p256_addcarryx_u64(
        &mut x115,
        &mut x116,
        0 as libc::c_int as fiat_p256_uint1,
        x114,
        x111,
    );
    x117 = (x116 as uint64_t).wrapping_add(x112);
    fiat_p256_addcarryx_u64(
        &mut x118,
        &mut x119,
        0 as libc::c_int as fiat_p256_uint1,
        x99,
        x113,
    );
    fiat_p256_addcarryx_u64(&mut x120, &mut x121, x119, x101, x115);
    fiat_p256_addcarryx_u64(&mut x122, &mut x123, x121, x103, x117);
    fiat_p256_addcarryx_u64(&mut x124, &mut x125, x123, x105, x109);
    fiat_p256_addcarryx_u64(&mut x126, &mut x127, x125, x107, x110);
    x128 = (x127 as uint64_t).wrapping_add(x108 as uint64_t);
    fiat_p256_mulx_u64(
        &mut x129,
        &mut x130,
        x3,
        *arg1.offset(3 as libc::c_int as isize),
    );
    fiat_p256_mulx_u64(
        &mut x131,
        &mut x132,
        x3,
        *arg1.offset(2 as libc::c_int as isize),
    );
    fiat_p256_mulx_u64(
        &mut x133,
        &mut x134,
        x3,
        *arg1.offset(1 as libc::c_int as isize),
    );
    fiat_p256_mulx_u64(
        &mut x135,
        &mut x136,
        x3,
        *arg1.offset(0 as libc::c_int as isize),
    );
    fiat_p256_addcarryx_u64(
        &mut x137,
        &mut x138,
        0 as libc::c_int as fiat_p256_uint1,
        x136,
        x133,
    );
    fiat_p256_addcarryx_u64(&mut x139, &mut x140, x138, x134, x131);
    fiat_p256_addcarryx_u64(&mut x141, &mut x142, x140, x132, x129);
    x143 = (x142 as uint64_t).wrapping_add(x130);
    fiat_p256_addcarryx_u64(
        &mut x144,
        &mut x145,
        0 as libc::c_int as fiat_p256_uint1,
        x120,
        x135,
    );
    fiat_p256_addcarryx_u64(&mut x146, &mut x147, x145, x122, x137);
    fiat_p256_addcarryx_u64(&mut x148, &mut x149, x147, x124, x139);
    fiat_p256_addcarryx_u64(&mut x150, &mut x151, x149, x126, x141);
    fiat_p256_addcarryx_u64(&mut x152, &mut x153, x151, x128, x143);
    fiat_p256_mulx_u64(&mut x154, &mut x155, x144, 0xffffffff00000001 as libc::c_ulong);
    fiat_p256_mulx_u64(
        &mut x156,
        &mut x157,
        x144,
        0xffffffff as libc::c_uint as uint64_t,
    );
    fiat_p256_mulx_u64(&mut x158, &mut x159, x144, 0xffffffffffffffff as libc::c_ulong);
    fiat_p256_addcarryx_u64(
        &mut x160,
        &mut x161,
        0 as libc::c_int as fiat_p256_uint1,
        x159,
        x156,
    );
    x162 = (x161 as uint64_t).wrapping_add(x157);
    fiat_p256_addcarryx_u64(
        &mut x163,
        &mut x164,
        0 as libc::c_int as fiat_p256_uint1,
        x144,
        x158,
    );
    fiat_p256_addcarryx_u64(&mut x165, &mut x166, x164, x146, x160);
    fiat_p256_addcarryx_u64(&mut x167, &mut x168, x166, x148, x162);
    fiat_p256_addcarryx_u64(&mut x169, &mut x170, x168, x150, x154);
    fiat_p256_addcarryx_u64(&mut x171, &mut x172, x170, x152, x155);
    x173 = (x172 as uint64_t).wrapping_add(x153 as uint64_t);
    fiat_p256_subborrowx_u64(
        &mut x174,
        &mut x175,
        0 as libc::c_int as fiat_p256_uint1,
        x165,
        0xffffffffffffffff as libc::c_ulong,
    );
    fiat_p256_subborrowx_u64(
        &mut x176,
        &mut x177,
        x175,
        x167,
        0xffffffff as libc::c_uint as uint64_t,
    );
    fiat_p256_subborrowx_u64(
        &mut x178,
        &mut x179,
        x177,
        x169,
        0 as libc::c_int as uint64_t,
    );
    fiat_p256_subborrowx_u64(
        &mut x180,
        &mut x181,
        x179,
        x171,
        0xffffffff00000001 as libc::c_ulong,
    );
    fiat_p256_subborrowx_u64(
        &mut x182,
        &mut x183,
        x181,
        x173,
        0 as libc::c_int as uint64_t,
    );
    fiat_p256_cmovznz_u64(&mut x184, x183, x174, x165);
    fiat_p256_cmovznz_u64(&mut x185, x183, x176, x167);
    fiat_p256_cmovznz_u64(&mut x186, x183, x178, x169);
    fiat_p256_cmovznz_u64(&mut x187, x183, x180, x171);
    *out1.offset(0 as libc::c_int as isize) = x184;
    *out1.offset(1 as libc::c_int as isize) = x185;
    *out1.offset(2 as libc::c_int as isize) = x186;
    *out1.offset(3 as libc::c_int as isize) = x187;
}
#[inline]
unsafe extern "C" fn fiat_p256_add(
    mut out1: *mut uint64_t,
    mut arg1: *const uint64_t,
    mut arg2: *const uint64_t,
) {
    let mut x1: uint64_t = 0;
    let mut x2: fiat_p256_uint1 = 0;
    let mut x3: uint64_t = 0;
    let mut x4: fiat_p256_uint1 = 0;
    let mut x5: uint64_t = 0;
    let mut x6: fiat_p256_uint1 = 0;
    let mut x7: uint64_t = 0;
    let mut x8: fiat_p256_uint1 = 0;
    let mut x9: uint64_t = 0;
    let mut x10: fiat_p256_uint1 = 0;
    let mut x11: uint64_t = 0;
    let mut x12: fiat_p256_uint1 = 0;
    let mut x13: uint64_t = 0;
    let mut x14: fiat_p256_uint1 = 0;
    let mut x15: uint64_t = 0;
    let mut x16: fiat_p256_uint1 = 0;
    let mut x17: uint64_t = 0;
    let mut x18: fiat_p256_uint1 = 0;
    let mut x19: uint64_t = 0;
    let mut x20: uint64_t = 0;
    let mut x21: uint64_t = 0;
    let mut x22: uint64_t = 0;
    fiat_p256_addcarryx_u64(
        &mut x1,
        &mut x2,
        0 as libc::c_int as fiat_p256_uint1,
        *arg1.offset(0 as libc::c_int as isize),
        *arg2.offset(0 as libc::c_int as isize),
    );
    fiat_p256_addcarryx_u64(
        &mut x3,
        &mut x4,
        x2,
        *arg1.offset(1 as libc::c_int as isize),
        *arg2.offset(1 as libc::c_int as isize),
    );
    fiat_p256_addcarryx_u64(
        &mut x5,
        &mut x6,
        x4,
        *arg1.offset(2 as libc::c_int as isize),
        *arg2.offset(2 as libc::c_int as isize),
    );
    fiat_p256_addcarryx_u64(
        &mut x7,
        &mut x8,
        x6,
        *arg1.offset(3 as libc::c_int as isize),
        *arg2.offset(3 as libc::c_int as isize),
    );
    fiat_p256_subborrowx_u64(
        &mut x9,
        &mut x10,
        0 as libc::c_int as fiat_p256_uint1,
        x1,
        0xffffffffffffffff as libc::c_ulong,
    );
    fiat_p256_subborrowx_u64(
        &mut x11,
        &mut x12,
        x10,
        x3,
        0xffffffff as libc::c_uint as uint64_t,
    );
    fiat_p256_subborrowx_u64(&mut x13, &mut x14, x12, x5, 0 as libc::c_int as uint64_t);
    fiat_p256_subborrowx_u64(
        &mut x15,
        &mut x16,
        x14,
        x7,
        0xffffffff00000001 as libc::c_ulong,
    );
    fiat_p256_subborrowx_u64(
        &mut x17,
        &mut x18,
        x16,
        x8 as uint64_t,
        0 as libc::c_int as uint64_t,
    );
    fiat_p256_cmovznz_u64(&mut x19, x18, x9, x1);
    fiat_p256_cmovznz_u64(&mut x20, x18, x11, x3);
    fiat_p256_cmovznz_u64(&mut x21, x18, x13, x5);
    fiat_p256_cmovznz_u64(&mut x22, x18, x15, x7);
    *out1.offset(0 as libc::c_int as isize) = x19;
    *out1.offset(1 as libc::c_int as isize) = x20;
    *out1.offset(2 as libc::c_int as isize) = x21;
    *out1.offset(3 as libc::c_int as isize) = x22;
}
#[inline]
unsafe extern "C" fn fiat_p256_sub(
    mut out1: *mut uint64_t,
    mut arg1: *const uint64_t,
    mut arg2: *const uint64_t,
) {
    let mut x1: uint64_t = 0;
    let mut x2: fiat_p256_uint1 = 0;
    let mut x3: uint64_t = 0;
    let mut x4: fiat_p256_uint1 = 0;
    let mut x5: uint64_t = 0;
    let mut x6: fiat_p256_uint1 = 0;
    let mut x7: uint64_t = 0;
    let mut x8: fiat_p256_uint1 = 0;
    let mut x9: uint64_t = 0;
    let mut x10: uint64_t = 0;
    let mut x11: fiat_p256_uint1 = 0;
    let mut x12: uint64_t = 0;
    let mut x13: fiat_p256_uint1 = 0;
    let mut x14: uint64_t = 0;
    let mut x15: fiat_p256_uint1 = 0;
    let mut x16: uint64_t = 0;
    let mut x17: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u64(
        &mut x1,
        &mut x2,
        0 as libc::c_int as fiat_p256_uint1,
        *arg1.offset(0 as libc::c_int as isize),
        *arg2.offset(0 as libc::c_int as isize),
    );
    fiat_p256_subborrowx_u64(
        &mut x3,
        &mut x4,
        x2,
        *arg1.offset(1 as libc::c_int as isize),
        *arg2.offset(1 as libc::c_int as isize),
    );
    fiat_p256_subborrowx_u64(
        &mut x5,
        &mut x6,
        x4,
        *arg1.offset(2 as libc::c_int as isize),
        *arg2.offset(2 as libc::c_int as isize),
    );
    fiat_p256_subborrowx_u64(
        &mut x7,
        &mut x8,
        x6,
        *arg1.offset(3 as libc::c_int as isize),
        *arg2.offset(3 as libc::c_int as isize),
    );
    fiat_p256_cmovznz_u64(
        &mut x9,
        x8,
        0 as libc::c_int as uint64_t,
        0xffffffffffffffff as libc::c_ulong,
    );
    fiat_p256_addcarryx_u64(
        &mut x10,
        &mut x11,
        0 as libc::c_int as fiat_p256_uint1,
        x1,
        x9,
    );
    fiat_p256_addcarryx_u64(
        &mut x12,
        &mut x13,
        x11,
        x3,
        x9 & 0xffffffff as libc::c_uint as uint64_t,
    );
    fiat_p256_addcarryx_u64(&mut x14, &mut x15, x13, x5, 0 as libc::c_int as uint64_t);
    fiat_p256_addcarryx_u64(
        &mut x16,
        &mut x17,
        x15,
        x7,
        x9 & 0xffffffff00000001 as libc::c_ulong,
    );
    *out1.offset(0 as libc::c_int as isize) = x10;
    *out1.offset(1 as libc::c_int as isize) = x12;
    *out1.offset(2 as libc::c_int as isize) = x14;
    *out1.offset(3 as libc::c_int as isize) = x16;
}
#[inline]
unsafe extern "C" fn fiat_p256_opp(mut out1: *mut uint64_t, mut arg1: *const uint64_t) {
    let mut x1: uint64_t = 0;
    let mut x2: fiat_p256_uint1 = 0;
    let mut x3: uint64_t = 0;
    let mut x4: fiat_p256_uint1 = 0;
    let mut x5: uint64_t = 0;
    let mut x6: fiat_p256_uint1 = 0;
    let mut x7: uint64_t = 0;
    let mut x8: fiat_p256_uint1 = 0;
    let mut x9: uint64_t = 0;
    let mut x10: uint64_t = 0;
    let mut x11: fiat_p256_uint1 = 0;
    let mut x12: uint64_t = 0;
    let mut x13: fiat_p256_uint1 = 0;
    let mut x14: uint64_t = 0;
    let mut x15: fiat_p256_uint1 = 0;
    let mut x16: uint64_t = 0;
    let mut x17: fiat_p256_uint1 = 0;
    fiat_p256_subborrowx_u64(
        &mut x1,
        &mut x2,
        0 as libc::c_int as fiat_p256_uint1,
        0 as libc::c_int as uint64_t,
        *arg1.offset(0 as libc::c_int as isize),
    );
    fiat_p256_subborrowx_u64(
        &mut x3,
        &mut x4,
        x2,
        0 as libc::c_int as uint64_t,
        *arg1.offset(1 as libc::c_int as isize),
    );
    fiat_p256_subborrowx_u64(
        &mut x5,
        &mut x6,
        x4,
        0 as libc::c_int as uint64_t,
        *arg1.offset(2 as libc::c_int as isize),
    );
    fiat_p256_subborrowx_u64(
        &mut x7,
        &mut x8,
        x6,
        0 as libc::c_int as uint64_t,
        *arg1.offset(3 as libc::c_int as isize),
    );
    fiat_p256_cmovznz_u64(
        &mut x9,
        x8,
        0 as libc::c_int as uint64_t,
        0xffffffffffffffff as libc::c_ulong,
    );
    fiat_p256_addcarryx_u64(
        &mut x10,
        &mut x11,
        0 as libc::c_int as fiat_p256_uint1,
        x1,
        x9,
    );
    fiat_p256_addcarryx_u64(
        &mut x12,
        &mut x13,
        x11,
        x3,
        x9 & 0xffffffff as libc::c_uint as uint64_t,
    );
    fiat_p256_addcarryx_u64(&mut x14, &mut x15, x13, x5, 0 as libc::c_int as uint64_t);
    fiat_p256_addcarryx_u64(
        &mut x16,
        &mut x17,
        x15,
        x7,
        x9 & 0xffffffff00000001 as libc::c_ulong,
    );
    *out1.offset(0 as libc::c_int as isize) = x10;
    *out1.offset(1 as libc::c_int as isize) = x12;
    *out1.offset(2 as libc::c_int as isize) = x14;
    *out1.offset(3 as libc::c_int as isize) = x16;
}
#[inline]
unsafe extern "C" fn fiat_p256_from_montgomery(
    mut out1: *mut uint64_t,
    mut arg1: *const uint64_t,
) {
    let mut x1: uint64_t = 0;
    let mut x2: uint64_t = 0;
    let mut x3: uint64_t = 0;
    let mut x4: uint64_t = 0;
    let mut x5: uint64_t = 0;
    let mut x6: uint64_t = 0;
    let mut x7: uint64_t = 0;
    let mut x8: uint64_t = 0;
    let mut x9: fiat_p256_uint1 = 0;
    let mut x10: uint64_t = 0;
    let mut x11: fiat_p256_uint1 = 0;
    let mut x12: uint64_t = 0;
    let mut x13: fiat_p256_uint1 = 0;
    let mut x14: uint64_t = 0;
    let mut x15: fiat_p256_uint1 = 0;
    let mut x16: uint64_t = 0;
    let mut x17: uint64_t = 0;
    let mut x18: uint64_t = 0;
    let mut x19: uint64_t = 0;
    let mut x20: uint64_t = 0;
    let mut x21: uint64_t = 0;
    let mut x22: uint64_t = 0;
    let mut x23: fiat_p256_uint1 = 0;
    let mut x24: uint64_t = 0;
    let mut x25: fiat_p256_uint1 = 0;
    let mut x26: uint64_t = 0;
    let mut x27: fiat_p256_uint1 = 0;
    let mut x28: uint64_t = 0;
    let mut x29: fiat_p256_uint1 = 0;
    let mut x30: uint64_t = 0;
    let mut x31: fiat_p256_uint1 = 0;
    let mut x32: uint64_t = 0;
    let mut x33: fiat_p256_uint1 = 0;
    let mut x34: uint64_t = 0;
    let mut x35: fiat_p256_uint1 = 0;
    let mut x36: uint64_t = 0;
    let mut x37: fiat_p256_uint1 = 0;
    let mut x38: uint64_t = 0;
    let mut x39: uint64_t = 0;
    let mut x40: uint64_t = 0;
    let mut x41: uint64_t = 0;
    let mut x42: uint64_t = 0;
    let mut x43: uint64_t = 0;
    let mut x44: uint64_t = 0;
    let mut x45: fiat_p256_uint1 = 0;
    let mut x46: uint64_t = 0;
    let mut x47: fiat_p256_uint1 = 0;
    let mut x48: uint64_t = 0;
    let mut x49: fiat_p256_uint1 = 0;
    let mut x50: uint64_t = 0;
    let mut x51: fiat_p256_uint1 = 0;
    let mut x52: uint64_t = 0;
    let mut x53: fiat_p256_uint1 = 0;
    let mut x54: uint64_t = 0;
    let mut x55: fiat_p256_uint1 = 0;
    let mut x56: uint64_t = 0;
    let mut x57: fiat_p256_uint1 = 0;
    let mut x58: uint64_t = 0;
    let mut x59: fiat_p256_uint1 = 0;
    let mut x60: uint64_t = 0;
    let mut x61: uint64_t = 0;
    let mut x62: uint64_t = 0;
    let mut x63: uint64_t = 0;
    let mut x64: uint64_t = 0;
    let mut x65: uint64_t = 0;
    let mut x66: uint64_t = 0;
    let mut x67: fiat_p256_uint1 = 0;
    let mut x68: uint64_t = 0;
    let mut x69: fiat_p256_uint1 = 0;
    let mut x70: uint64_t = 0;
    let mut x71: fiat_p256_uint1 = 0;
    let mut x72: uint64_t = 0;
    let mut x73: fiat_p256_uint1 = 0;
    let mut x74: uint64_t = 0;
    let mut x75: fiat_p256_uint1 = 0;
    let mut x76: uint64_t = 0;
    let mut x77: uint64_t = 0;
    let mut x78: fiat_p256_uint1 = 0;
    let mut x79: uint64_t = 0;
    let mut x80: fiat_p256_uint1 = 0;
    let mut x81: uint64_t = 0;
    let mut x82: fiat_p256_uint1 = 0;
    let mut x83: uint64_t = 0;
    let mut x84: fiat_p256_uint1 = 0;
    let mut x85: uint64_t = 0;
    let mut x86: fiat_p256_uint1 = 0;
    let mut x87: uint64_t = 0;
    let mut x88: uint64_t = 0;
    let mut x89: uint64_t = 0;
    let mut x90: uint64_t = 0;
    x1 = *arg1.offset(0 as libc::c_int as isize);
    fiat_p256_mulx_u64(&mut x2, &mut x3, x1, 0xffffffff00000001 as libc::c_ulong);
    fiat_p256_mulx_u64(&mut x4, &mut x5, x1, 0xffffffff as libc::c_uint as uint64_t);
    fiat_p256_mulx_u64(&mut x6, &mut x7, x1, 0xffffffffffffffff as libc::c_ulong);
    fiat_p256_addcarryx_u64(
        &mut x8,
        &mut x9,
        0 as libc::c_int as fiat_p256_uint1,
        x7,
        x4,
    );
    fiat_p256_addcarryx_u64(
        &mut x10,
        &mut x11,
        0 as libc::c_int as fiat_p256_uint1,
        x1,
        x6,
    );
    fiat_p256_addcarryx_u64(&mut x12, &mut x13, x11, 0 as libc::c_int as uint64_t, x8);
    fiat_p256_addcarryx_u64(
        &mut x14,
        &mut x15,
        0 as libc::c_int as fiat_p256_uint1,
        x12,
        *arg1.offset(1 as libc::c_int as isize),
    );
    fiat_p256_mulx_u64(&mut x16, &mut x17, x14, 0xffffffff00000001 as libc::c_ulong);
    fiat_p256_mulx_u64(&mut x18, &mut x19, x14, 0xffffffff as libc::c_uint as uint64_t);
    fiat_p256_mulx_u64(&mut x20, &mut x21, x14, 0xffffffffffffffff as libc::c_ulong);
    fiat_p256_addcarryx_u64(
        &mut x22,
        &mut x23,
        0 as libc::c_int as fiat_p256_uint1,
        x21,
        x18,
    );
    fiat_p256_addcarryx_u64(
        &mut x24,
        &mut x25,
        0 as libc::c_int as fiat_p256_uint1,
        x14,
        x20,
    );
    fiat_p256_addcarryx_u64(
        &mut x26,
        &mut x27,
        x25,
        (x15 as uint64_t)
            .wrapping_add(
                (x13 as uint64_t).wrapping_add((x9 as uint64_t).wrapping_add(x5)),
            ),
        x22,
    );
    fiat_p256_addcarryx_u64(
        &mut x28,
        &mut x29,
        x27,
        x2,
        (x23 as uint64_t).wrapping_add(x19),
    );
    fiat_p256_addcarryx_u64(&mut x30, &mut x31, x29, x3, x16);
    fiat_p256_addcarryx_u64(
        &mut x32,
        &mut x33,
        0 as libc::c_int as fiat_p256_uint1,
        x26,
        *arg1.offset(2 as libc::c_int as isize),
    );
    fiat_p256_addcarryx_u64(&mut x34, &mut x35, x33, x28, 0 as libc::c_int as uint64_t);
    fiat_p256_addcarryx_u64(&mut x36, &mut x37, x35, x30, 0 as libc::c_int as uint64_t);
    fiat_p256_mulx_u64(&mut x38, &mut x39, x32, 0xffffffff00000001 as libc::c_ulong);
    fiat_p256_mulx_u64(&mut x40, &mut x41, x32, 0xffffffff as libc::c_uint as uint64_t);
    fiat_p256_mulx_u64(&mut x42, &mut x43, x32, 0xffffffffffffffff as libc::c_ulong);
    fiat_p256_addcarryx_u64(
        &mut x44,
        &mut x45,
        0 as libc::c_int as fiat_p256_uint1,
        x43,
        x40,
    );
    fiat_p256_addcarryx_u64(
        &mut x46,
        &mut x47,
        0 as libc::c_int as fiat_p256_uint1,
        x32,
        x42,
    );
    fiat_p256_addcarryx_u64(&mut x48, &mut x49, x47, x34, x44);
    fiat_p256_addcarryx_u64(
        &mut x50,
        &mut x51,
        x49,
        x36,
        (x45 as uint64_t).wrapping_add(x41),
    );
    fiat_p256_addcarryx_u64(
        &mut x52,
        &mut x53,
        x51,
        (x37 as uint64_t).wrapping_add((x31 as uint64_t).wrapping_add(x17)),
        x38,
    );
    fiat_p256_addcarryx_u64(
        &mut x54,
        &mut x55,
        0 as libc::c_int as fiat_p256_uint1,
        x48,
        *arg1.offset(3 as libc::c_int as isize),
    );
    fiat_p256_addcarryx_u64(&mut x56, &mut x57, x55, x50, 0 as libc::c_int as uint64_t);
    fiat_p256_addcarryx_u64(&mut x58, &mut x59, x57, x52, 0 as libc::c_int as uint64_t);
    fiat_p256_mulx_u64(&mut x60, &mut x61, x54, 0xffffffff00000001 as libc::c_ulong);
    fiat_p256_mulx_u64(&mut x62, &mut x63, x54, 0xffffffff as libc::c_uint as uint64_t);
    fiat_p256_mulx_u64(&mut x64, &mut x65, x54, 0xffffffffffffffff as libc::c_ulong);
    fiat_p256_addcarryx_u64(
        &mut x66,
        &mut x67,
        0 as libc::c_int as fiat_p256_uint1,
        x65,
        x62,
    );
    fiat_p256_addcarryx_u64(
        &mut x68,
        &mut x69,
        0 as libc::c_int as fiat_p256_uint1,
        x54,
        x64,
    );
    fiat_p256_addcarryx_u64(&mut x70, &mut x71, x69, x56, x66);
    fiat_p256_addcarryx_u64(
        &mut x72,
        &mut x73,
        x71,
        x58,
        (x67 as uint64_t).wrapping_add(x63),
    );
    fiat_p256_addcarryx_u64(
        &mut x74,
        &mut x75,
        x73,
        (x59 as uint64_t).wrapping_add((x53 as uint64_t).wrapping_add(x39)),
        x60,
    );
    x76 = (x75 as uint64_t).wrapping_add(x61);
    fiat_p256_subborrowx_u64(
        &mut x77,
        &mut x78,
        0 as libc::c_int as fiat_p256_uint1,
        x70,
        0xffffffffffffffff as libc::c_ulong,
    );
    fiat_p256_subborrowx_u64(
        &mut x79,
        &mut x80,
        x78,
        x72,
        0xffffffff as libc::c_uint as uint64_t,
    );
    fiat_p256_subborrowx_u64(&mut x81, &mut x82, x80, x74, 0 as libc::c_int as uint64_t);
    fiat_p256_subborrowx_u64(
        &mut x83,
        &mut x84,
        x82,
        x76,
        0xffffffff00000001 as libc::c_ulong,
    );
    fiat_p256_subborrowx_u64(
        &mut x85,
        &mut x86,
        x84,
        0 as libc::c_int as uint64_t,
        0 as libc::c_int as uint64_t,
    );
    fiat_p256_cmovznz_u64(&mut x87, x86, x77, x70);
    fiat_p256_cmovznz_u64(&mut x88, x86, x79, x72);
    fiat_p256_cmovznz_u64(&mut x89, x86, x81, x74);
    fiat_p256_cmovznz_u64(&mut x90, x86, x83, x76);
    *out1.offset(0 as libc::c_int as isize) = x87;
    *out1.offset(1 as libc::c_int as isize) = x88;
    *out1.offset(2 as libc::c_int as isize) = x89;
    *out1.offset(3 as libc::c_int as isize) = x90;
}
#[inline]
unsafe extern "C" fn fiat_p256_nonzero(
    mut out1: *mut uint64_t,
    mut arg1: *const uint64_t,
) {
    let mut x1: uint64_t = 0;
    x1 = *arg1.offset(0 as libc::c_int as isize)
        | (*arg1.offset(1 as libc::c_int as isize)
            | (*arg1.offset(2 as libc::c_int as isize)
                | *arg1.offset(3 as libc::c_int as isize)));
    *out1 = x1;
}
static mut fiat_p256_g_pre_comp: [[[fiat_p256_felem; 2]; 16]; 13] = [
    [
        [
            [
                0x79e730d418a9143c as libc::c_long as uint64_t,
                0x75ba95fc5fedb601 as libc::c_long as uint64_t,
                0x79fb732b77622510 as libc::c_long as uint64_t,
                0x18905f76a53755c6 as libc::c_long as uint64_t,
            ],
            [
                0xddf25357ce95560a as libc::c_ulong,
                0x8b4ab8e4ba19e45c as libc::c_ulong,
                0xd2e88688dd21f325 as libc::c_ulong,
                0x8571ff1825885d85 as libc::c_ulong,
            ],
        ],
        [
            [
                0xffac3f904eebc127 as libc::c_ulong,
                0xb027f84a087d81fb as libc::c_ulong,
                0x66ad77dd87cbbc98 as libc::c_long as uint64_t,
                0x26936a3fb6ff747e as libc::c_long as uint64_t,
            ],
            [
                0xb04c5c1fc983a7eb as libc::c_ulong,
                0x583e47ad0861fe1a as libc::c_long as uint64_t,
                0x788208311a2ee98e as libc::c_long as uint64_t,
                0xd5f06a29e587cc07 as libc::c_ulong,
            ],
        ],
        [
            [
                0xbe1b8aaec45c61f5 as libc::c_ulong,
                0x90ec649a94b9537d as libc::c_ulong,
                0x941cb5aad076c20c as libc::c_ulong,
                0xc9079605890523c8 as libc::c_ulong,
            ],
            [
                0xeb309b4ae7ba4f10 as libc::c_ulong,
                0x73c568efe5eb882b as libc::c_long as uint64_t,
                0x3540a9877e7a1f68 as libc::c_long as uint64_t,
                0x73a076bb2dd1e916 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x746354ea0173b4f as libc::c_long as uint64_t,
                0x2bd20213d23c00f7 as libc::c_long as uint64_t,
                0xf43eaab50c23bb08 as libc::c_ulong,
                0x13ba5119c3123e03 as libc::c_long as uint64_t,
            ],
            [
                0x2847d0303f5b9d4d as libc::c_long as uint64_t,
                0x6742f2f25da67bdd as libc::c_long as uint64_t,
                0xef933bdc77c94195 as libc::c_ulong,
                0xeaedd9156e240867 as libc::c_ulong,
            ],
        ],
        [
            [
                0x75c96e8f264e20e8 as libc::c_long as uint64_t,
                0xabe6bfed59a7a841 as libc::c_ulong,
                0x2cc09c0444c8eb00 as libc::c_long as uint64_t,
                0xe05b3080f0c4e16b as libc::c_ulong,
            ],
            [
                0x1eb7777aa45f3314 as libc::c_long as uint64_t,
                0x56af7bedce5d45e3 as libc::c_long as uint64_t,
                0x2b6e019a88b12f1a as libc::c_long as uint64_t,
                0x86659cdfd835f9b as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xea7d260a6245e404 as libc::c_ulong,
                0x9de407956e7fdfe0 as libc::c_ulong,
                0x1ff3a4158dac1ab5 as libc::c_long as uint64_t,
                0x3e7090f1649c9073 as libc::c_long as uint64_t,
            ],
            [
                0x1a7685612b944e88 as libc::c_long as uint64_t,
                0x250f939ee57f61c8 as libc::c_long as uint64_t,
                0xc0daa891ead643d as libc::c_long as uint64_t,
                0x68930023e125b88e as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xccc425634b2ed709 as libc::c_ulong,
                0xe356769856fd30d as libc::c_long as uint64_t,
                0xbcbcd43f559e9811 as libc::c_ulong,
                0x738477ac5395b759 as libc::c_long as uint64_t,
            ],
            [
                0x35752b90c00ee17f as libc::c_long as uint64_t,
                0x68748390742ed2e3 as libc::c_long as uint64_t,
                0x7cd06422bd1f5bc1 as libc::c_long as uint64_t,
                0xfbc08769c9e7b797 as libc::c_ulong,
            ],
        ],
        [
            [
                0x72bcd8b7bc60055b as libc::c_long as uint64_t,
                0x3cc23ee56e27e4b as libc::c_long as uint64_t,
                0xee337424e4819370 as libc::c_ulong,
                0xe2aa0e430ad3da09 as libc::c_ulong,
            ],
            [
                0x40b8524f6383c45d as libc::c_long as uint64_t,
                0xd766355442a41b25 as libc::c_ulong,
                0x64efa6de778a4797 as libc::c_long as uint64_t,
                0x2042170a7079adf4 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x97091dcbd53c5c9d as libc::c_ulong,
                0xf17624b6ac0a177b as libc::c_ulong,
                0xb0f139752cfe2dff as libc::c_ulong,
                0xc1a35c0a6c7a574e as libc::c_ulong,
            ],
            [
                0x227d314693e79987 as libc::c_long as uint64_t,
                0x575bf30e89cb80e as libc::c_long as uint64_t,
                0x2f4e247f0d1883bb as libc::c_long as uint64_t,
                0xebd512263274c3d0 as libc::c_ulong,
            ],
        ],
        [
            [
                0xfea912baa5659ae8 as libc::c_ulong,
                0x68363aba25e1a16e as libc::c_long as uint64_t,
                0xb8842277752c41ac as libc::c_ulong,
                0xfe545c282897c3fc as libc::c_ulong,
            ],
            [
                0x2d36e9e7dc4c696b as libc::c_long as uint64_t,
                0x5806244afba977c5 as libc::c_long as uint64_t,
                0x85665e9be39508c1 as libc::c_ulong,
                0xf720ee256d12597b as libc::c_ulong,
            ],
        ],
        [
            [
                0x562e4cecc135b208 as libc::c_long as uint64_t,
                0x74e1b2654783f47d as libc::c_long as uint64_t,
                0x6d2a506c5a3f3b30 as libc::c_long as uint64_t,
                0xecead9f4c16762fc as libc::c_ulong,
            ],
            [
                0xf29dd4b2e286e5b9 as libc::c_ulong,
                0x1b0fadc083bb3c61 as libc::c_long as uint64_t,
                0x7a75023e7fac29a4 as libc::c_long as uint64_t,
                0xc086d5f1c9477fa3 as libc::c_ulong,
            ],
        ],
        [
            [
                0xf4f876532de45068 as libc::c_ulong,
                0x37c7a7e89e2e1f6e as libc::c_long as uint64_t,
                0xd0825fa2a3584069 as libc::c_ulong,
                0xaf2cea7c1727bf42 as libc::c_ulong,
            ],
            [
                0x360a4fb9e4785a9 as libc::c_long as uint64_t,
                0xe5fda49c27299f4a as libc::c_ulong,
                0x48068e1371ac2f71 as libc::c_long as uint64_t,
                0x83d0687b9077666f as libc::c_ulong,
            ],
        ],
        [
            [
                0xa4a319acd837879f as libc::c_ulong,
                0x6fc1b49eed6b67b0 as libc::c_long as uint64_t,
                0xe395993332f1f3af as libc::c_ulong,
                0x966742eb65432a2e as libc::c_ulong,
            ],
            [
                0x4b8dc9feb4966228 as libc::c_long as uint64_t,
                0x96cc631243f43950 as libc::c_ulong,
                0x12068859c9b731ee as libc::c_long as uint64_t,
                0x7b948dc356f79968 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x42c2af497e2feb4 as libc::c_long as uint64_t,
                0xd36a42d7aebf7313 as libc::c_ulong,
                0x49d2c9eb084ffdd7 as libc::c_long as uint64_t,
                0x9f8aa54b2ef7c76a as libc::c_ulong,
            ],
            [
                0x9200b7ba09895e70 as libc::c_ulong,
                0x3bd0c66fddb7fb58 as libc::c_long as uint64_t,
                0x2d97d10878eb4cbb as libc::c_long as uint64_t,
                0x2d431068d84bde31 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x5e5db46acb66e132 as libc::c_long as uint64_t,
                0xf1be963a0d925880 as libc::c_ulong,
                0x944a70270317b9e2 as libc::c_ulong,
                0xe266f95948603d48 as libc::c_ulong,
            ],
            [
                0x98db66735c208899 as libc::c_ulong,
                0x90472447a2fb18a3 as libc::c_ulong,
                0x8a966939777c619f as libc::c_ulong,
                0x3798142a2a3be21b as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xe2f73c696755ff89 as libc::c_ulong,
                0xdd3cf7e7473017e6 as libc::c_ulong,
                0x8ef5689d3cf7600d as libc::c_ulong,
                0x948dc4f8b1fc87b4 as libc::c_ulong,
            ],
            [
                0xd9e9fe814ea53299 as libc::c_ulong,
                0x2d921ca298eb6028 as libc::c_long as uint64_t,
                0xfaecedfd0c9803fc as libc::c_ulong,
                0xf38ae8914d7b4745 as libc::c_ulong,
            ],
        ],
    ],
    [
        [
            [
                0xa7a8746a584c5e20 as libc::c_ulong,
                0x267e4ea1b9dc7035 as libc::c_long as uint64_t,
                0x593a15cfb9548c9b as libc::c_long as uint64_t,
                0x5e6e21354bd012f3 as libc::c_long as uint64_t,
            ],
            [
                0xdf31cc6a8c8f936e as libc::c_ulong,
                0x8af84d04b5c241dc as libc::c_ulong,
                0x63990a6f345efb86 as libc::c_long as uint64_t,
                0x6fef4e61b9b962cb as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xf2efe23d442a8ad1 as libc::c_ulong,
                0xc3816a7d06b9c164 as libc::c_ulong,
                0xa9df2d8bdc0aa5e5 as libc::c_ulong,
                0x191ae46f120a8e65 as libc::c_long as uint64_t,
            ],
            [
                0x83667f8700611c5b as libc::c_ulong,
                0x83171ed7ff109948 as libc::c_ulong,
                0x33a2ecf8ca695952 as libc::c_long as uint64_t,
                0xfa4a73eef48d1a13 as libc::c_ulong,
            ],
        ],
        [
            [
                0x48fc4ed082dd1b6a as libc::c_long as uint64_t,
                0x5783a13867b703af as libc::c_long as uint64_t,
                0x2463cb9a005d6aaa as libc::c_long as uint64_t,
                0xd31ec55c706ecd43 as libc::c_ulong,
            ],
            [
                0x9f8ed33f8e9a7641 as libc::c_ulong,
                0x625453ed098d9e7a as libc::c_long as uint64_t,
                0xa3beade4ec887493 as libc::c_ulong,
                0x442b80505a795566 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x46df582d3bfab839 as libc::c_long as uint64_t,
                0x92474e042f8adade as libc::c_ulong,
                0x36a7766a147a1bc3 as libc::c_long as uint64_t,
                0xb6940f540dc0f979 as libc::c_ulong,
            ],
            [
                0x44738ef2f2759f25 as libc::c_long as uint64_t,
                0x9dd95789a719f4c6 as libc::c_ulong,
                0x2859b7f40750c345 as libc::c_long as uint64_t,
                0x5e788bf2b22180d5 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xa839c9fdfd67ca25 as libc::c_ulong,
                0x23e626860f2015c as libc::c_long as uint64_t,
                0x2414a7930e7b2a65 as libc::c_long as uint64_t,
                0x92dbe372b13edcbb as libc::c_ulong,
            ],
            [
                0xf64981ee64c2200f as libc::c_ulong,
                0x94fb9cdf8446f2f3 as libc::c_ulong,
                0x1411a6a3f1367bb as libc::c_long as uint64_t,
                0x7985c1915a1e8331 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xc8123c6037e2efea as libc::c_ulong,
                0x8d49b502034a96f6 as libc::c_ulong,
                0x466a346b973e4a95 as libc::c_long as uint64_t,
                0xf176b5bab7de00ff as libc::c_ulong,
            ],
            [
                0x1c58fa3b82dfa945 as libc::c_long as uint64_t,
                0x2eb27a9609e429ae as libc::c_long as uint64_t,
                0x57c67a67a12b187c as libc::c_long as uint64_t,
                0xb155ba82e2298bba as libc::c_ulong,
            ],
        ],
        [
            [
                0xf1a542073d99bcfa as libc::c_ulong,
                0x59db703ce8becf6d as libc::c_long as uint64_t,
                0x2e455142d2459569 as libc::c_long as uint64_t,
                0xb0ee5143a901b910 as libc::c_ulong,
            ],
            [
                0xfc05d451e26d994f as libc::c_ulong,
                0x7a6062b41360caaf as libc::c_long as uint64_t,
                0xdf1ded5f4fa639b1 as libc::c_ulong,
                0xaf930348d335b8b0 as libc::c_ulong,
            ],
        ],
        [
            [
                0x3d8f248a21fd0861 as libc::c_long as uint64_t,
                0xade3bd649bd5a4b6 as libc::c_ulong,
                0xcb56c953c2e2a6bf as libc::c_ulong,
                0x699cd2b5287d6c5f as libc::c_long as uint64_t,
            ],
            [
                0xdebce1be47d05e8f as libc::c_ulong,
                0x1a4fbb13a8f53732 as libc::c_long as uint64_t,
                0x97163beaa5852b08 as libc::c_ulong,
                0x92c49e6ceec6987a as libc::c_ulong,
            ],
        ],
        [
            [
                0x48cc82c592c60e66 as libc::c_long as uint64_t,
                0x64c7f176daedc594 as libc::c_long as uint64_t,
                0xccaa64a6085c6a4a as libc::c_ulong,
                0x2b00fb9816f5e01a as libc::c_long as uint64_t,
            ],
            [
                0x3233d099d487af8a as libc::c_long as uint64_t,
                0xac0d63e9d44603d0 as libc::c_ulong,
                0x23de19484183bd5d as libc::c_long as uint64_t,
                0xb51192cefa892d9c as libc::c_ulong,
            ],
        ],
        [
            [
                0x9a1bbfa646384f83 as libc::c_ulong,
                0x18d9c6fbd307c4ee as libc::c_long as uint64_t,
                0x11a35453c02e76ee as libc::c_long as uint64_t,
                0x17bd50b502ac53c as libc::c_long as uint64_t,
            ],
            [
                0x10e2865029fd361f as libc::c_long as uint64_t,
                0x2bc91f835ef98bcf as libc::c_long as uint64_t,
                0x36d459bcd336f52b as libc::c_long as uint64_t,
                0x1b05c746c4b10292 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x75441cb9b3c2f0c2 as libc::c_long as uint64_t,
                0x2305e276db87aa0c as libc::c_long as uint64_t,
                0x9b303d441b15ef99 as libc::c_ulong,
                0x7cf7239b418ebc5f as libc::c_long as uint64_t,
            ],
            [
                0xca59017e6bb609f1 as libc::c_ulong,
                0x72565c537ac26028 as libc::c_long as uint64_t,
                0x28589a5d4ab8a177 as libc::c_long as uint64_t,
                0x4bf0cdb9435973a4 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xa82663cdeca65db1 as libc::c_ulong,
                0xd19b0e414d7b5c21 as libc::c_ulong,
                0x77cf1adc6f73c8da as libc::c_long as uint64_t,
                0xb9351db7583cf69 as libc::c_long as uint64_t,
            ],
            [
                0x76ce05c8ce282b4f as libc::c_long as uint64_t,
                0x214ad9c302f6fb6d as libc::c_long as uint64_t,
                0x8fc76d150bb38a03 as libc::c_ulong,
                0x9637a9226cfaa7db as libc::c_ulong,
            ],
        ],
        [
            [
                0xa0cc89cfe6caa4ac as libc::c_ulong,
                0xee18ec657546ae5e as libc::c_ulong,
                0xa476a9ba2bc59122 as libc::c_ulong,
                0x76690ad371d4f50f as libc::c_long as uint64_t,
            ],
            [
                0xefa64071f06f61ae as libc::c_ulong,
                0xaabf07c957e16bbf as libc::c_ulong,
                0x802321b5d7d6823c as libc::c_ulong,
                0x7327aa9bafc50c12 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x2691c0a8af26e7e5 as libc::c_long as uint64_t,
                0xd3b6575e527e0154 as libc::c_ulong,
                0x10fe7d35a1b1b2d9 as libc::c_long as uint64_t,
                0x8ed062a8f47a76 as libc::c_long as uint64_t,
            ],
            [
                0xfa84c67c2c0844b8 as libc::c_ulong,
                0xad0ff3812a79a670 as libc::c_ulong,
                0xbdfb21b748bbdaad as libc::c_ulong,
                0x61ed81b7e142b6c2 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x45be41c751de0e7f as libc::c_long as uint64_t,
                0xbaf20542e13ba8 as libc::c_long as uint64_t,
                0x3c8b0b1456d7b5ea as libc::c_long as uint64_t,
                0x936182aba3776bd0 as libc::c_ulong,
            ],
            [
                0xdd5d490786a670db as libc::c_ulong,
                0xeb5e00cfaf2291c8 as libc::c_ulong,
                0x739eec624553a4de as libc::c_long as uint64_t,
                0x278503e1624a63cc as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x851a16612a497576 as libc::c_ulong,
                0x2536f457849ad3b as libc::c_long as uint64_t,
                0x88e401763ec068dc as libc::c_ulong,
                0x5123c8a6f0076b34 as libc::c_long as uint64_t,
            ],
            [
                0x784c32ae3fd5593c as libc::c_long as uint64_t,
                0xb51411a1bedcd922 as libc::c_ulong,
                0x2570118deff1f6d0 as libc::c_long as uint64_t,
                0x5cd238d6cb8070ee as libc::c_long as uint64_t,
            ],
        ],
    ],
    [
        [
            [
                0x889f6d65533ef217 as libc::c_ulong,
                0x7158c7e4c3ca2e87 as libc::c_long as uint64_t,
                0xfb670dfbdc2b4167 as libc::c_ulong,
                0x75910a01844c257f as libc::c_long as uint64_t,
            ],
            [
                0xf336bf07cf88577d as libc::c_ulong,
                0x22245250e45e2ace as libc::c_long as uint64_t,
                0x2ed92e8d7ca23d85 as libc::c_long as uint64_t,
                0x29f8be4c2b812f58 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xc51e414351facc61 as libc::c_ulong,
                0xbaf2647de68a25bc as libc::c_ulong,
                0x8f5271a00ff872ed as libc::c_ulong,
                0x8f32ef993d2d9659 as libc::c_ulong,
            ],
            [
                0xca12488c7593cbd4 as libc::c_ulong,
                0xed266c5d02b82fab as libc::c_ulong,
                0xa2f78ad14eb3f16 as libc::c_long as uint64_t,
                0xc34049484d47afe3 as libc::c_ulong,
            ],
        ],
        [
            [
                0x9c1670209470496 as libc::c_long as uint64_t,
                0xa489a5edebd23815 as libc::c_ulong,
                0xc4dde4648edd4398 as libc::c_ulong,
                0x3ca7b94a80111696 as libc::c_long as uint64_t,
            ],
            [
                0x3c385d682ad636a4 as libc::c_long as uint64_t,
                0x6702702508dc5f1e as libc::c_long as uint64_t,
                0xc1965deafa21943 as libc::c_long as uint64_t,
                0x18666e16610be69e as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x45beb4ca2a604b3b as libc::c_long as uint64_t,
                0x56f651843a616762 as libc::c_long as uint64_t,
                0xf52f5a70978b806e as libc::c_ulong,
                0x7aa3978711dc4480 as libc::c_long as uint64_t,
            ],
            [
                0xe13fac2a0e01fabc as libc::c_ulong,
                0x7c6ee8a5237d99f9 as libc::c_long as uint64_t,
                0x251384ee05211ffe as libc::c_long as uint64_t,
                0x4ff6976d1bc9d3eb as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xdde0492316e043a2 as libc::c_ulong,
                0x98a452611dd3d209 as libc::c_ulong,
                0xeaf9f61bd431ebe8 as libc::c_ulong,
                0x919f4dbaf56abd as libc::c_long as uint64_t,
            ],
            [
                0xe42417db6d8774b1 as libc::c_ulong,
                0x5fc5279c58e0e309 as libc::c_long as uint64_t,
                0x64aa40613adf81ea as libc::c_long as uint64_t,
                0xef419edabc627c7f as libc::c_ulong,
            ],
        ],
        [
            [
                0xfa24d0537a4af00f as libc::c_ulong,
                0x3f938926ca294614 as libc::c_long as uint64_t,
                0xd700c183982182e as libc::c_long as uint64_t,
                0x801334434cc59947 as libc::c_ulong,
            ],
            [
                0xf0397106ec87c925 as libc::c_ulong,
                0x62bd59fc0ed6665c as libc::c_long as uint64_t,
                0xe8414348c7cca8b5 as libc::c_ulong,
                0x574c76209f9f0a30 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x95be42e2bb8b6a07 as libc::c_ulong,
                0x64be74eeca23f86a as libc::c_long as uint64_t,
                0xa73d74fd154ce470 as libc::c_ulong,
                0x1c2d2857d8dc076a as libc::c_long as uint64_t,
            ],
            [
                0xb1fa1c575a887868 as libc::c_ulong,
                0x38df8e0b3de64818 as libc::c_long as uint64_t,
                0xd88e52f9c34e8967 as libc::c_ulong,
                0x274b4f018b4cc76c as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x3f5c05b4f8b7559d as libc::c_long as uint64_t,
                0xbe4c7acfae29200 as libc::c_long as uint64_t,
                0xdd6d3ef756532acc as libc::c_ulong,
                0xf6c3ed87eea7a285 as libc::c_ulong,
            ],
            [
                0xe463b0a8f46ec59b as libc::c_ulong,
                0x531d9b14ecea6c83 as libc::c_long as uint64_t,
                0x3d6bdbafc2dc836b as libc::c_long as uint64_t,
                0x3ee501e92ab27f0b as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x7b1a921ea6b3340b as libc::c_long as uint64_t,
                0x6d7c4d7d7438a53e as libc::c_long as uint64_t,
                0x2b9ef73c5bf71d8f as libc::c_long as uint64_t,
                0xb5f6e0182b167a7c as libc::c_ulong,
            ],
            [
                0x5ada98ab0ce536a3 as libc::c_long as uint64_t,
                0xee0f16f9e1fea850 as libc::c_ulong,
                0xf6424e9d74f1c0c5 as libc::c_ulong,
                0x4d00de0cd3d10b41 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xd542f522a6533610 as libc::c_ulong,
                0xfdde15a734ec439a as libc::c_ulong,
                0x696560fedc87dd0d as libc::c_long as uint64_t,
                0x69eab421e01fd05f as libc::c_long as uint64_t,
            ],
            [
                0xca4febdc95cc5988 as libc::c_ulong,
                0x839be396c44d92fb as libc::c_ulong,
                0x7bedff6daffe543b as libc::c_long as uint64_t,
                0xd2bb97296f6da43a as libc::c_ulong,
            ],
        ],
        [
            [
                0x5bc6dea80b8d0077 as libc::c_long as uint64_t,
                0xb2adf5d1ea9c49ef as libc::c_ulong,
                0x7104c20eaafe8659 as libc::c_long as uint64_t,
                0x1e3604f37866ee7e as libc::c_long as uint64_t,
            ],
            [
                0xcfc7e7b3075c8c5 as libc::c_long as uint64_t,
                0x5281d9bb639c5a2b as libc::c_long as uint64_t,
                0xcbdf42494bc44ee3 as libc::c_ulong,
                0x835ab066655e9209 as libc::c_ulong,
            ],
        ],
        [
            [
                0x78fbda4b90b94ffa as libc::c_long as uint64_t,
                0x447e52eb7beb993c as libc::c_long as uint64_t,
                0x920011bc92620d15 as libc::c_ulong,
                0x7bad6ecf481fd396 as libc::c_long as uint64_t,
            ],
            [
                0xad3bd28ba989a09e as libc::c_ulong,
                0x20491784a3e62b78 as libc::c_long as uint64_t,
                0xcdcd7096b07bd9ef as libc::c_ulong,
                0x9bf5bb7337d780ad as libc::c_ulong,
            ],
        ],
        [
            [
                0xbe911a71a976c8d4 as libc::c_ulong,
                0xba0346743fdd778e as libc::c_ulong,
                0x2359e7434cf87ea1 as libc::c_long as uint64_t,
                0x8dccf65f07ebb691 as libc::c_ulong,
            ],
            [
                0x6c2c18eb09746d87 as libc::c_long as uint64_t,
                0x6a19945fd2ecc8fa as libc::c_long as uint64_t,
                0xc67121ff2ffa0339 as libc::c_ulong,
                0x408c95ba9bd9fc31 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xa317204bcaa5da39 as libc::c_ulong,
                0xd390df7468bf53d7 as libc::c_ulong,
                0x56de18b2dbd71c0d as libc::c_long as uint64_t,
                0xcb4d3bee75184779 as libc::c_ulong,
            ],
            [
                0x815a219499d920a5 as libc::c_ulong,
                0x9e10fb4ecf3d3a64 as libc::c_ulong,
                0x7fd4901dfe92e1ee as libc::c_long as uint64_t,
                0x5d86d10d3ab87b2e as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x98e9136c878303e4 as libc::c_ulong,
                0x2769e74fd1e65efd as libc::c_long as uint64_t,
                0x6154c545809da56e as libc::c_long as uint64_t,
                0x8c5d50a04301638c as libc::c_ulong,
            ],
            [
                0x10f3d2068214b763 as libc::c_long as uint64_t,
                0x2da9a2fc44df0644 as libc::c_long as uint64_t,
                0xca912bab588a6fcd as libc::c_ulong,
                0xe9e82d9b227e1932 as libc::c_ulong,
            ],
        ],
        [
            [
                0xcbdc4d66d080e55b as libc::c_ulong,
                0xad3f11e5b8f98d6b as libc::c_ulong,
                0x31bea68e18a32480 as libc::c_long as uint64_t,
                0xdf1c6fd52c1bcf6e as libc::c_ulong,
            ],
            [
                0xadcda7ee118a3f39 as libc::c_ulong,
                0xbd02f857ac060d5f as libc::c_ulong,
                0xd2d0265d86631997 as libc::c_ulong,
                0xb866a7d33818f2d4 as libc::c_ulong,
            ],
        ],
    ],
    [
        [
            [
                0x646f96796424c49b as libc::c_long as uint64_t,
                0xf888dfe867c241c9 as libc::c_ulong,
                0xe12d4b9324f68b49 as libc::c_ulong,
                0x9a6b62d8a571df20 as libc::c_ulong,
            ],
            [
                0x81b4b26d179483cb as libc::c_ulong,
                0x666f96329511fae2 as libc::c_long as uint64_t,
                0xd281b3e4d53aa51f as libc::c_ulong,
                0x7f96a7657f3dbd16 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xf167b4e0bdefdd4f as libc::c_ulong,
                0x69958465f366e401 as libc::c_long as uint64_t,
                0x5aa368aba73bbec0 as libc::c_long as uint64_t,
                0x121487097b240c21 as libc::c_long as uint64_t,
            ],
            [
                0x378c323318969006 as libc::c_long as uint64_t,
                0xcb4d73cee1fe53d1 as libc::c_ulong,
                0x5f50a80e130c4361 as libc::c_long as uint64_t,
                0xd67f59517ef5212b as libc::c_ulong,
            ],
        ],
        [
            [
                0xeb4437434573eab0 as libc::c_ulong,
                0x11570dfbd1ac6031 as libc::c_long as uint64_t,
                0xf7d9b45b44dd9afd as libc::c_ulong,
                0xb8066add22067231 as libc::c_ulong,
            ],
            [
                0x15f92ad8f8a3f0b4 as libc::c_long as uint64_t,
                0x9e0e4899e0ace2a2 as libc::c_ulong,
                0xbdcd0aadfab38b80 as libc::c_ulong,
                0x46506ae917020052 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x5a059565352c4b5c as libc::c_long as uint64_t,
                0x49261531590bc3e2 as libc::c_long as uint64_t,
                0x809f7521f66f9f5f as libc::c_ulong,
                0x2baef6bfc70a4a9b as libc::c_long as uint64_t,
            ],
            [
                0xe7e6fa6509ed3561 as libc::c_ulong,
                0x11370233984b230c as libc::c_long as uint64_t,
                0x2151659bd04cdc69 as libc::c_long as uint64_t,
                0xbdb83c63f007d416 as libc::c_ulong,
            ],
        ],
        [
            [
                0xcb35a1a85ca37ff0 as libc::c_ulong,
                0xe1a04f1ccd2f1c8f as libc::c_ulong,
                0x238816ce15a26112 as libc::c_long as uint64_t,
                0xe206a111095b177e as libc::c_ulong,
            ],
            [
                0x3c10b6048a424149 as libc::c_long as uint64_t,
                0xc6a3f56774752cfb as libc::c_ulong,
                0xbf16a37a47f1dbb8 as libc::c_ulong,
                0x7c372f9ad31a3dfb as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xf84b48f7864ac537 as libc::c_ulong,
                0x4713409a6940d3d as libc::c_long as uint64_t,
                0x14db22d6174c7ae as libc::c_long as uint64_t,
                0xc73a1c438c213034 as libc::c_ulong,
            ],
            [
                0x18ac4ea5ffdd93ec as libc::c_long as uint64_t,
                0x724fc7576102783e as libc::c_long as uint64_t,
                0x9fe13fcc91c3e83f as libc::c_ulong,
                0x92a8c2c8f08f0bf5 as libc::c_ulong,
            ],
        ],
        [
            [
                0xa72cf82ae255d7ec as libc::c_ulong,
                0x52025c23a460e204 as libc::c_long as uint64_t,
                0x10ae542d7d5b0a44 as libc::c_long as uint64_t,
                0xa85143109305aeda as libc::c_ulong,
            ],
            [
                0x958315f5a14bbfe8 as libc::c_ulong,
                0x3f361826385365fe as libc::c_long as uint64_t,
                0xc2b3a36b66d95040 as libc::c_ulong,
                0x12c7b3347cf4eda2 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xbdb9e57ca3d24f6a as libc::c_ulong,
                0x8a8246d7f345a763 as libc::c_ulong,
                0x73bd2a6d98cfbb5f as libc::c_long as uint64_t,
                0x1dd8e85e86ed04db as libc::c_long as uint64_t,
            ],
            [
                0x76f2da42c01f420b as libc::c_long as uint64_t,
                0x7ef0547364407bc7 as libc::c_long as uint64_t,
                0x7e98ba7faff548f5 as libc::c_long as uint64_t,
                0x6b7afbeefd30b64a as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x67639eaeb2572f8 as libc::c_long as uint64_t,
                0xb0cef632d70853ce as libc::c_ulong,
                0xd87f1f31e9989004 as libc::c_ulong,
                0x94aa7236a26582c0 as libc::c_ulong,
            ],
            [
                0x4211b8e5b0c2c656 as libc::c_long as uint64_t,
                0x5aaa79ba257414e as libc::c_long as uint64_t,
                0x672f841e0f09ab0 as libc::c_long as uint64_t,
                0xa3c5f9bf3ec81c65 as libc::c_ulong,
            ],
        ],
        [
            [
                0xa4a11bb60877b3a7 as libc::c_ulong,
                0x244d11a62cd521a9 as libc::c_long as uint64_t,
                0x464b19b7bff5c62c as libc::c_long as uint64_t,
                0x27f3eba79076657c as libc::c_long as uint64_t,
            ],
            [
                0x483abf970c7581a9 as libc::c_long as uint64_t,
                0x2ef108e0ae0b22f3 as libc::c_long as uint64_t,
                0xd603f3665064bcd5 as libc::c_ulong,
                0xcf4875a75bf5025e as libc::c_ulong,
            ],
        ],
        [
            [
                0xe05e91b162edc562 as libc::c_ulong,
                0xb5e1fe7262bcd185 as libc::c_ulong,
                0x1d526908b8105b19 as libc::c_long as uint64_t,
                0xd11447e896bbb22 as libc::c_long as uint64_t,
            ],
            [
                0x647aaa492c2213f0 as libc::c_long as uint64_t,
                0xf6c9f8c62e2fc14b as libc::c_ulong,
                0x90ca259abc4168c6 as libc::c_ulong,
                0x3bb92762dd8e3461 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x5c10b148f3deae70 as libc::c_long as uint64_t,
                0x2044b536eabc433 as libc::c_long as uint64_t,
                0x1e82790cfe63f18e as libc::c_long as uint64_t,
                0x2886b65aaa695ff1 as libc::c_long as uint64_t,
            ],
            [
                0x994fdf934627a4ed as libc::c_ulong,
                0xe9b4dec0872eb0b9 as libc::c_ulong,
                0x4c0bec8d58f7a28f as libc::c_long as uint64_t,
                0xc30c4dedeaf9c5fe as libc::c_ulong,
            ],
        ],
        [
            [
                0x69f63538b65579cd as libc::c_long as uint64_t,
                0xd070605cadf933a1 as libc::c_ulong,
                0x17e870583be9f6c as libc::c_long as uint64_t,
                0xe9442faab247b8a1 as libc::c_ulong,
            ],
            [
                0x54eeff9e540d3d68 as libc::c_long as uint64_t,
                0x1f3edeabcae3be19 as libc::c_long as uint64_t,
                0x95c528b07035311b as libc::c_ulong,
                0xb35d3ab796bcc0a7 as libc::c_ulong,
            ],
        ],
        [
            [
                0xb4897d052106e16d as libc::c_ulong,
                0x85bbdf9b50a07f8c as libc::c_ulong,
                0x42632a3d6c49ffd7 as libc::c_long as uint64_t,
                0xb7885e7c600720b8 as libc::c_ulong,
            ],
            [
                0x6fa47fdcdeb694ac as libc::c_long as uint64_t,
                0x384614f58ae0d179 as libc::c_long as uint64_t,
                0x78fcba29bd124ab3 as libc::c_long as uint64_t,
                0xbb113d9e748f12ea as libc::c_ulong,
            ],
        ],
        [
            [
                0xc3b013d0f38493fe as libc::c_ulong,
                0xa32cae9607baf718 as libc::c_ulong,
                0x371da6c22095b3ba as libc::c_long as uint64_t,
                0x31c0abdb041909e as libc::c_long as uint64_t,
            ],
            [
                0x11cc6dbe431a9e60 as libc::c_long as uint64_t,
                0x7e9194765bf38f6e as libc::c_long as uint64_t,
                0xbe47f076462a4a33 as libc::c_ulong,
                0x33b3c9df3041b830 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x2653302e5053d70 as libc::c_long as uint64_t,
                0x3c33e35bb8c6bfc9 as libc::c_long as uint64_t,
                0xa72c4b409a021ee9 as libc::c_ulong,
                0xe11b800d3f6527e4 as libc::c_ulong,
            ],
            [
                0x8fc1d44ab6dc37b5 as libc::c_ulong,
                0x5d8606b5f580e474 as libc::c_long as uint64_t,
                0xdf25754a87b5b0fa as libc::c_ulong,
                0xbaf50ce8bb692a5e as libc::c_ulong,
            ],
        ],
    ],
    [
        [
            [
                0xe4050f1cf1c367ca as libc::c_ulong,
                0x9bc85a9bc90fbc7d as libc::c_ulong,
                0xa373c4a2e1a11032 as libc::c_ulong,
                0xb64232b7ad0393a9 as libc::c_ulong,
            ],
            [
                0xf5577eb0167dad29 as libc::c_ulong,
                0x1604f30194b78ab2 as libc::c_long as uint64_t,
                0xbaa94afe829348b as libc::c_long as uint64_t,
                0x77fbd8dd41654342 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xa2f7932c68af43ee as libc::c_ulong,
                0x5502468e703d00bd as libc::c_long as uint64_t,
                0xe5dc978f2fb061f5 as libc::c_ulong,
                0xc9a1904a28c815ad as libc::c_ulong,
            ],
            [
                0xd3af538d470c56a4 as libc::c_ulong,
                0x159abc5f193d8ced as libc::c_long as uint64_t,
                0x2a37245f20108ef3 as libc::c_long as uint64_t,
                0xfa17081e223f7178 as libc::c_ulong,
            ],
        ],
        [
            [
                0x5c18acf88e2f7d90 as libc::c_long as uint64_t,
                0xfdbf33d777be32cd as libc::c_ulong,
                0xa085cd7d2eb5ee9 as libc::c_long as uint64_t,
                0x2d702cfbb3201115 as libc::c_long as uint64_t,
            ],
            [
                0xb6e0ebdb85c88ce8 as libc::c_ulong,
                0x23a3ce3c1e01d617 as libc::c_long as uint64_t,
                0x3041618e567333ac as libc::c_long as uint64_t,
                0x9dd0fd8f157edb6b as libc::c_ulong,
            ],
        ],
        [
            [
                0x516ff3a36fa6110c as libc::c_long as uint64_t,
                0x74fb1eb1fb93561f as libc::c_long as uint64_t,
                0x6c0c90478457522b as libc::c_long as uint64_t,
                0xcfd321046bb8bdc6 as libc::c_ulong,
            ],
            [
                0x2d6884a2cc80ad57 as libc::c_long as uint64_t,
                0x7c27fc3586a9b637 as libc::c_long as uint64_t,
                0x3461baedadf4e8cd as libc::c_long as uint64_t,
                0x1d56251a617242f0 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x892c81a321175ec1 as libc::c_ulong,
                0x9159a505ee018109 as libc::c_ulong,
                0xc70130532d8be316 as libc::c_ulong,
                0x76060c21426fa2e5 as libc::c_long as uint64_t,
            ],
            [
                0x74d2dfc6b6f0f22 as libc::c_long as uint64_t,
                0x9725fc64ca01a671 as libc::c_ulong,
                0x3f6679b92770bd8e as libc::c_long as uint64_t,
                0x8fe6604fd7c9b3fe as libc::c_ulong,
            ],
        ],
        [
            [
                0x71d530cc73204349 as libc::c_long as uint64_t,
                0xc9df473d94a0679c as libc::c_ulong,
                0xc572f0014261e031 as libc::c_ulong,
                0x9786b71f22f135fe as libc::c_ulong,
            ],
            [
                0xed6505fa6b64e56f as libc::c_ulong,
                0xe2fb48e905219c46 as libc::c_ulong,
                0xdbec45bedf53d71 as libc::c_long as uint64_t,
                0xd7d782f2c589f406 as libc::c_ulong,
            ],
        ],
        [
            [
                0x6513c8a446cd7f4 as libc::c_long as uint64_t,
                0x158c423b906d52a6 as libc::c_long as uint64_t,
                0x71503261c423866c as libc::c_long as uint64_t,
                0x4b96f57093c148ee as libc::c_long as uint64_t,
            ],
            [
                0x5daf9cc7239a8523 as libc::c_long as uint64_t,
                0x611b597695ac4b8b as libc::c_long as uint64_t,
                0xde3981db724bf7f6 as libc::c_ulong,
                0x7e7d0f7867afc443 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x3d1ab80c8ce59954 as libc::c_long as uint64_t,
                0x742c5a9478222ac0 as libc::c_long as uint64_t,
                0x3ddacbf894f878dd as libc::c_long as uint64_t,
                0xfc085117e7d54a99 as libc::c_ulong,
            ],
            [
                0xfb0f1dfa21e38ec2 as libc::c_ulong,
                0x1c7b59cb16f4ff7f as libc::c_long as uint64_t,
                0x988752397ea888fe as libc::c_ulong,
                0x705d270cb10dc889 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xd7c89ba1e7d1cefd as libc::c_ulong,
                0xcb33553a9a91e03d as libc::c_ulong,
                0xa01caaff59f01e54 as libc::c_ulong,
                0x4a71c141de07def7 as libc::c_long as uint64_t,
            ],
            [
                0xe1616a4034d467d1 as libc::c_ulong,
                0x6f395ab2e8ba8817 as libc::c_long as uint64_t,
                0xf781ea64e45869ab as libc::c_ulong,
                0x8b9513bb7134f484 as libc::c_ulong,
            ],
        ],
        [
            [
                0xb0ec9035948c135 as libc::c_long as uint64_t,
                0xaee219539a990127 as libc::c_ulong,
                0x9d15ba0eb185dda1 as libc::c_ulong,
                0xd87bc2fb2c7d6802 as libc::c_ulong,
            ],
            [
                0x5a480307a82d7f8 as libc::c_long as uint64_t,
                0x7b591ce4e7e11ec3 as libc::c_long as uint64_t,
                0x14d4cc22a0e15fdb as libc::c_long as uint64_t,
                0xf2d4213576def955 as libc::c_ulong,
            ],
        ],
        [
            [
                0xd56d69e4117a5f59 as libc::c_ulong,
                0xcae6008a01286e97 as libc::c_ulong,
                0x716a0a282dab13b0 as libc::c_long as uint64_t,
                0xc821da99b3a8d2d0 as libc::c_ulong,
            ],
            [
                0x6898b66239c305e6 as libc::c_long as uint64_t,
                0xe42d3394c8b61142 as libc::c_ulong,
                0x54c1d2b253b16712 as libc::c_long as uint64_t,
                0x3cec3953a01f4be6 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x5bd1e3036951b85e as libc::c_long as uint64_t,
                0x1a73f1fb164d79a4 as libc::c_long as uint64_t,
                0x6e77abd39fb22bc3 as libc::c_long as uint64_t,
                0x8ae4c181b3d18dfd as libc::c_ulong,
            ],
            [
                0xdd4226f5a6a14ed1 as libc::c_ulong,
                0x620e111feb4e1d92 as libc::c_long as uint64_t,
                0xffce6e59edca4fe8 as libc::c_ulong,
                0x39f5fc053d0a717d as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xef8fa78cd91aff44 as libc::c_ulong,
                0x6f3f9749bdc03be7 as libc::c_long as uint64_t,
                0x171545f8b8596075 as libc::c_long as uint64_t,
                0xbe31a73e2af132ce as libc::c_ulong,
            ],
            [
                0x5b4e174123884e1d as libc::c_long as uint64_t,
                0x4373357ea9fa75f0 as libc::c_long as uint64_t,
                0x8dba2731bc06f49e as libc::c_ulong,
                0xa09aebc877fa6de8 as libc::c_ulong,
            ],
        ],
        [
            [
                0xd4974e518293e18c as libc::c_ulong,
                0x1e4cfc5331ec0e8f as libc::c_long as uint64_t,
                0x80b4258325d40b1e as libc::c_ulong,
                0x5cfb73a2a85f7588 as libc::c_long as uint64_t,
            ],
            [
                0xe553efd204c0e00b as libc::c_ulong,
                0xdaa6750e9a48ac39 as libc::c_ulong,
                0xf20936b00abda06a as libc::c_ulong,
                0xbfd3c7e4bf85771c as libc::c_ulong,
            ],
        ],
        [
            [
                0x3086643551138f2b as libc::c_long as uint64_t,
                0x1176d8e6108a36ba as libc::c_long as uint64_t,
                0xd78b3b400d4d4b66 as libc::c_ulong,
                0x99ddd9bd956dbff1 as libc::c_ulong,
            ],
            [
                0x91dfe72822f08e5f as libc::c_ulong,
                0x7fd8cfe6a081ac4e as libc::c_long as uint64_t,
                0x8ebb278ed75285c2 as libc::c_ulong,
                0x2335fe00ef457ac0 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xe9d79c50f058191a as libc::c_ulong,
                0x6749c3b05d3183f8 as libc::c_long as uint64_t,
                0x5edc2708dbfeb1ec as libc::c_long as uint64_t,
                0x2c18f93621275986 as libc::c_long as uint64_t,
            ],
            [
                0x3a093e1f0703389f as libc::c_long as uint64_t,
                0xdf065e4a3ef60f44 as libc::c_ulong,
                0x6860e4df87e7c458 as libc::c_long as uint64_t,
                0xdb22d96e8bfe4c7d as libc::c_ulong,
            ],
        ],
    ],
    [
        [
            [
                0xf893a5dc8de610b as libc::c_long as uint64_t,
                0xe8c515fb67e223ce as libc::c_ulong,
                0x7774bfa64ead6dc5 as libc::c_long as uint64_t,
                0x89d20f95925c728f as libc::c_ulong,
            ],
            [
                0x7a1e0966098583ce as libc::c_long as uint64_t,
                0xa2eedb9493f2a7d7 as libc::c_ulong,
                0x1b2820974c304d4a as libc::c_long as uint64_t,
                0x842e3dac077282d as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x5a3097befc15aa1e as libc::c_long as uint64_t,
                0x40d12548b54b0745 as libc::c_long as uint64_t,
                0x5bad4706519a5f12 as libc::c_long as uint64_t,
                0xed03f717a439dee6 as libc::c_ulong,
            ],
            [
                0x794bb6c4a02c499 as libc::c_long as uint64_t,
                0xf725083dcffe71d2 as libc::c_ulong,
                0x2cad75190f3adcaf as libc::c_long as uint64_t,
                0x7f68ea1c43729310 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x9c806d8af7f91d0f as libc::c_ulong,
                0x3b61b0f1a82a5728 as libc::c_long as uint64_t,
                0x4640032d94d76754 as libc::c_long as uint64_t,
                0x273eb5de47d834c6 as libc::c_long as uint64_t,
            ],
            [
                0x2988abf77b4e4d53 as libc::c_long as uint64_t,
                0xb7ce66bfde401777 as libc::c_ulong,
                0x9fba6b32715071b3 as libc::c_ulong,
                0x82413c24ad3a1a98 as libc::c_ulong,
            ],
        ],
        [
            [
                0x69c435269be47be0 as libc::c_long as uint64_t,
                0x323b7dd8cb28fea1 as libc::c_long as uint64_t,
                0xfa5538ba3a6c67e5 as libc::c_ulong,
                0xef921d701d378e46 as libc::c_ulong,
            ],
            [
                0xf92961fc3c4b880e as libc::c_ulong,
                0x3f6f914e98940a67 as libc::c_long as uint64_t,
                0xa990eb0afef0ff39 as libc::c_ulong,
                0xa6c2920ff0eeff9c as libc::c_ulong,
            ],
        ],
        [
            [
                0x70b63d32343bf1a9 as libc::c_long as uint64_t,
                0x8fd3bd2837d1a6b1 as libc::c_ulong,
                0x454879c316865b4 as libc::c_long as uint64_t,
                0xee959ff6c458efa2 as libc::c_ulong,
            ],
            [
                0x461dcf89706dc3f as libc::c_long as uint64_t,
                0x737db0e2164e4b2e as libc::c_long as uint64_t,
                0x92626802f8843c8 as libc::c_long as uint64_t,
                0x54498bbc7745e6f6 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x4c1f428cd5f30851 as libc::c_long as uint64_t,
                0x94dfed272a4f6630 as libc::c_ulong,
                0x4df53772fc5d48a4 as libc::c_long as uint64_t,
                0xdd2d5a2f933260ce as libc::c_ulong,
            ],
            [
                0x574115bdd44cc7a5 as libc::c_long as uint64_t,
                0x4ba6b20dbd12533a as libc::c_long as uint64_t,
                0x30e93cb8243057c9 as libc::c_long as uint64_t,
                0x794c486a14de320e as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xc232d97302f1cd1e as libc::c_ulong,
                0xce87eacb1dd212a4 as libc::c_ulong,
                0x6e4c8c73e69802f7 as libc::c_long as uint64_t,
                0x12ef02901fffddbd as libc::c_long as uint64_t,
            ],
            [
                0x941ec74e1bcea6e2 as libc::c_ulong,
                0xd0b540243cb92cbb as libc::c_ulong,
                0x809fb9d47e8f9d05 as libc::c_ulong,
                0x3bf16159f2992aae as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xbdb8e675b055cb40 as libc::c_ulong,
                0x898f8e7b977b5167 as libc::c_ulong,
                0xecc65651b82fb863 as libc::c_ulong,
                0x565448146d88f01f as libc::c_long as uint64_t,
            ],
            [
                0xb0928e95263a75a9 as libc::c_ulong,
                0xcfb6836f1a22fcda as libc::c_ulong,
                0x651d14db3f3bd37c as libc::c_long as uint64_t,
                0x1d3837fbb6ad4664 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xa1fe9cf1a378c0df as libc::c_ulong,
                0xf6af74007d8e9907 as libc::c_ulong,
                0xbcdcb19ce98eed7b as libc::c_ulong,
                0x3096dbccdf97366 as libc::c_long as uint64_t,
            ],
            [
                0xdfddd8427337d182 as libc::c_ulong,
                0x388f7c736f3586f5 as libc::c_long as uint64_t,
                0x3ea5a436f2669df5 as libc::c_long as uint64_t,
                0x31fc2026bb37176c as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x11481a821554475b as libc::c_long as uint64_t,
                0x44a39c59194eb2c8 as libc::c_long as uint64_t,
                0x41cde9e0118774a5 as libc::c_long as uint64_t,
                0x85b5ed5739ffd48 as libc::c_long as uint64_t,
            ],
            [
                0x8b315da94ac9de12 as libc::c_ulong,
                0x5b6614cced9bff87 as libc::c_long as uint64_t,
                0x7709353601e471a3 as libc::c_long as uint64_t,
                0xd61d6dfb5a1bb435 as libc::c_ulong,
            ],
        ],
        [
            [
                0x1d5a02e062f7ab23 as libc::c_long as uint64_t,
                0x5efe19ef8543ff8a as libc::c_long as uint64_t,
                0xbb1b9ed9cb0bc6ed as libc::c_ulong,
                0xdd39ce40b6f0396c as libc::c_ulong,
            ],
            [
                0x568acb3e2c7cf13b as libc::c_long as uint64_t,
                0xecbd6775d0a64471 as libc::c_ulong,
                0x3af6e5c7cf4ad49a as libc::c_long as uint64_t,
                0x8c0eb770a987d6b9 as libc::c_ulong,
            ],
        ],
        [
            [
                0x3183b1fdef9ddf95 as libc::c_long as uint64_t,
                0xa558488aa9cc3648 as libc::c_ulong,
                0x4a8ada95c81fe849 as libc::c_long as uint64_t,
                0x61eda26c7662e842 as libc::c_long as uint64_t,
            ],
            [
                0xaf20f8c27feef4c9 as libc::c_ulong,
                0x4aea64196ca19293 as libc::c_long as uint64_t,
                0x6be10fc05b0d8f89 as libc::c_long as uint64_t,
                0x84972f138d25ff66 as libc::c_ulong,
            ],
        ],
        [
            [
                0xd4a7fc6af28c493e as libc::c_ulong,
                0xd4a27458d6c40d79 as libc::c_ulong,
                0xff708eef051eeafe as libc::c_ulong,
                0xe820786d21ad0480 as libc::c_ulong,
            ],
            [
                0x3555a0e9aef67a72 as libc::c_long as uint64_t,
                0x544d549823bd19b4 as libc::c_long as uint64_t,
                0xbaa70bc59bec07f7 as libc::c_ulong,
                0xe2e490af7302dbd0 as libc::c_ulong,
            ],
        ],
        [
            [
                0xa5704c2bae8bd113 as libc::c_ulong,
                0xc20d4b20b742a07d as libc::c_ulong,
                0x3a96cad327054b82 as libc::c_long as uint64_t,
                0x287da7030450aa1a as libc::c_long as uint64_t,
            ],
            [
                0xdca42b5f29ea0c9c as libc::c_ulong,
                0x50142f080d0047e2 as libc::c_long as uint64_t,
                0xe173d7f1cb8df1a9 as libc::c_ulong,
                0xc6302f9607a1333e as libc::c_ulong,
            ],
        ],
        [
            [
                0x768a4b5dec0766f5 as libc::c_long as uint64_t,
                0x59e71a8318b63ca6 as libc::c_long as uint64_t,
                0x67683b2fe7fbff7e as libc::c_long as uint64_t,
                0x12ac72991f51bf14 as libc::c_long as uint64_t,
            ],
            [
                0x75c8b865dfb20e6 as libc::c_long as uint64_t,
                0x4fb42d8609ab32fd as libc::c_long as uint64_t,
                0xba34d637d50d6fd as libc::c_long as uint64_t,
                0x5c1d8c5584f2921f as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xbff994fb0dc0eaf2 as libc::c_ulong,
                0x956359266fedbccc as libc::c_ulong,
                0xeaa2d7e028b3a574 as libc::c_ulong,
                0x9b0985259fd621e8 as libc::c_ulong,
            ],
            [
                0xae4f1a48c2c4cc91 as libc::c_ulong,
                0x442789c5e65741c8 as libc::c_long as uint64_t,
                0x77500e29f263bdaa as libc::c_long as uint64_t,
                0x205f0b66ea0e1525 as libc::c_long as uint64_t,
            ],
        ],
    ],
    [
        [
            [
                0x3e0e5c9dd111f8ec as libc::c_long as uint64_t,
                0xbcc33f8db7c4e760 as libc::c_ulong,
                0x702f9a91bd392a51 as libc::c_long as uint64_t,
                0x7da4a795c132e92d as libc::c_long as uint64_t,
            ],
            [
                0x1a0b0ae30bb1151b as libc::c_long as uint64_t,
                0x54febac802e32251 as libc::c_long as uint64_t,
                0xea3a5082694e9e78 as libc::c_ulong,
                0xe58ffec1e4fe40b8 as libc::c_ulong,
            ],
        ],
        [
            [
                0x7b23c513516e19e4 as libc::c_long as uint64_t,
                0x56e2e847c5c4d593 as libc::c_long as uint64_t,
                0x9f727d735ce71ef6 as libc::c_ulong,
                0x5b6304a6f79a44c5 as libc::c_long as uint64_t,
            ],
            [
                0x6638a7363ab7e433 as libc::c_long as uint64_t,
                0x1adea470fe742f83 as libc::c_long as uint64_t,
                0xe054b8545b7fc19f as libc::c_ulong,
                0xf935381aba1d0698 as libc::c_ulong,
            ],
        ],
        [
            [
                0x55366b7d5846426f as libc::c_long as uint64_t,
                0xe7d09e89247d441d as libc::c_ulong,
                0x510b404d736fbf48 as libc::c_long as uint64_t,
                0x7fa003d0e784bd7d as libc::c_long as uint64_t,
            ],
            [
                0x25f7614f17fd9596 as libc::c_long as uint64_t,
                0x49e0e0a135cb98db as libc::c_long as uint64_t,
                0x2c65957b2e83a76a as libc::c_long as uint64_t,
                0x5d40da8dcddbe0f8 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x9fb3bba354530bb2 as libc::c_ulong,
                0xbde3ef77cb0869ea as libc::c_ulong,
                0x89bc90460b431163 as libc::c_ulong,
                0x4d03d7d2e4819a35 as libc::c_long as uint64_t,
            ],
            [
                0x33ae4f9e43b6a782 as libc::c_long as uint64_t,
                0x216db3079c88a686 as libc::c_long as uint64_t,
                0x91dd88e000ffedd9 as libc::c_ulong,
                0xb280da9f12bd4840 as libc::c_ulong,
            ],
        ],
        [
            [
                0xa37f3573f37f5937 as libc::c_ulong,
                0xeb0f6c7dd1e4fca5 as libc::c_ulong,
                0x2965a554ac8ab0fc as libc::c_long as uint64_t,
                0x17fbf56c274676ac as libc::c_long as uint64_t,
            ],
            [
                0x2e2f6bd9acf7d720 as libc::c_long as uint64_t,
                0x41fc8f8810224766 as libc::c_long as uint64_t,
                0x517a14b385d53bef as libc::c_long as uint64_t,
                0xdae327a57d76a7d1 as libc::c_ulong,
            ],
        ],
        [
            [
                0x43c41ac194d7d9b1 as libc::c_long as uint64_t,
                0x5bafdd82c82e7f17 as libc::c_long as uint64_t,
                0xdf0614c15fda0fca as libc::c_ulong,
                0x74b043a7a8ae37ad as libc::c_long as uint64_t,
            ],
            [
                0x3ba6afa19e71734c as libc::c_long as uint64_t,
                0x15d5437e9c450f2e as libc::c_long as uint64_t,
                0x4a5883fe67e242b1 as libc::c_long as uint64_t,
                0x5143bdc22c1953c2 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xc676d7f2b1f3390b as libc::c_ulong,
                0x9f7a1b8ca5b61272 as libc::c_ulong,
                0x4ebebfc9c2e127a9 as libc::c_long as uint64_t,
                0x4602500c5dd997bf as libc::c_long as uint64_t,
            ],
            [
                0x7f09771c4711230f as libc::c_long as uint64_t,
                0x58eb37c020f09c1 as libc::c_long as uint64_t,
                0xab693d4bfee5e38b as libc::c_ulong,
                0x9289eb1f4653cbc0 as libc::c_ulong,
            ],
        ],
        [
            [
                0x54da9dc7ab952578 as libc::c_long as uint64_t,
                0xb5423df226e84d0b as libc::c_ulong,
                0xa8b64eeb9b872042 as libc::c_ulong,
                0xac2057825990f6df as libc::c_ulong,
            ],
            [
                0x4ff696eb21f4c77a as libc::c_long as uint64_t,
                0x1a79c3e4aab273af as libc::c_long as uint64_t,
                0x29bc922e9436b3f1 as libc::c_long as uint64_t,
                0xff807ef8d6d9a27a as libc::c_ulong,
            ],
        ],
        [
            [
                0xe4ca688fd06f56c0 as libc::c_ulong,
                0xa48af70ddf027972 as libc::c_ulong,
                0x691f0f045e9a609d as libc::c_long as uint64_t,
                0xa9dd82cdee61270e as libc::c_ulong,
            ],
            [
                0x8903ca63a0ef18d3 as libc::c_ulong,
                0x9fb7ee353d6ca3bd as libc::c_ulong,
                0xa7b4a09cabf47d03 as libc::c_ulong,
                0x4cdada011c67de8e as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xac127dc1e038a675 as libc::c_ulong,
                0x729deff38c5c6320 as libc::c_long as uint64_t,
                0xb7df8fd4a90d2c53 as libc::c_ulong,
                0x9b74b0ec681e7cd3 as libc::c_ulong,
            ],
            [
                0x5cb5a623dab407e5 as libc::c_long as uint64_t,
                0xcdbd361576b340c6 as libc::c_ulong,
                0xa184415a7d28392c as libc::c_ulong,
                0xc184c1d8e96f7830 as libc::c_ulong,
            ],
        ],
        [
            [
                0x86a9303b2f7e85c3 as libc::c_ulong,
                0x5fce462171988f9b as libc::c_long as uint64_t,
                0x5b935bf6c138acb5 as libc::c_long as uint64_t,
                0x30ea7d6725661212 as libc::c_long as uint64_t,
            ],
            [
                0xef1eb5f4e51ab9a2 as libc::c_ulong,
                0x587c98aae067c78 as libc::c_long as uint64_t,
                0xb3ce1b3c77ca9ca6 as libc::c_ulong,
                0x2a553d4d54b5f057 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x2c7156e10b1894a0 as libc::c_long as uint64_t,
                0x92034001d81c68c0 as libc::c_ulong,
                0xed225d00c8b115b5 as libc::c_ulong,
                0x237f9c2283b907f2 as libc::c_long as uint64_t,
            ],
            [
                0xea2f32f4470e2c0 as libc::c_long as uint64_t,
                0xb725f7c158be4e95 as libc::c_ulong,
                0xf1dcafab1ae5463 as libc::c_long as uint64_t,
                0x59ed51871ba2fc04 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xd1b0ccdec9520711 as libc::c_ulong,
                0x55a9e4ed3c8b84bf as libc::c_long as uint64_t,
                0x9426bd39a1fef314 as libc::c_ulong,
                0x4f5f638e6eb93f2b as libc::c_long as uint64_t,
            ],
            [
                0xba2a1ed32bf9341b as libc::c_ulong,
                0xd63c13214d42d5a9 as libc::c_ulong,
                0xd2964a89316dc7c5 as libc::c_ulong,
                0xd1759606ca511851 as libc::c_ulong,
            ],
        ],
        [
            [
                0xedf69feaf8c51187 as libc::c_ulong,
                0x5bb67ec741e4da7 as libc::c_long as uint64_t,
                0x47df0f3208114345 as libc::c_long as uint64_t,
                0x56facb07bb9792b1 as libc::c_long as uint64_t,
            ],
            [
                0xf3e007e98f6229e4 as libc::c_ulong,
                0x62d103f4526fba0f as libc::c_long as uint64_t,
                0x4f33bef7b0339d79 as libc::c_long as uint64_t,
                0x9841357bb59bfec1 as libc::c_ulong,
            ],
        ],
        [
            [
                0x830e6eea60dbac1f as libc::c_ulong,
                0x23d8c484da06a2f7 as libc::c_long as uint64_t,
                0x896714b050ca535b as libc::c_ulong,
                0xdc8d3644ebd97a9b as libc::c_ulong,
            ],
            [
                0x106ef9fab12177b4 as libc::c_long as uint64_t,
                0xf79bf464534d5d9c as libc::c_ulong,
                0x2537a349a6ab360b as libc::c_long as uint64_t,
                0xc7c54253a00c744f as libc::c_ulong,
            ],
        ],
        [
            [
                0x24d661d168754ab0 as libc::c_long as uint64_t,
                0x801fce1d6f429a76 as libc::c_ulong,
                0xc068a85fa58ce769 as libc::c_ulong,
                0xedc35c545d5eca2b as libc::c_ulong,
            ],
            [
                0xea31276fa3f660d1 as libc::c_ulong,
                0xa0184ebeb8fc7167 as libc::c_ulong,
                0xf20f21a1d8db0ae as libc::c_long as uint64_t,
                0xd96d095f56c35e12 as libc::c_ulong,
            ],
        ],
    ],
    [
        [
            [
                0xef0a3fecfa181e69 as libc::c_ulong,
                0x9ea02f8130d69a98 as libc::c_ulong,
                0xb2e9cf8e66eab95d as libc::c_ulong,
                0x520f2beb24720021 as libc::c_long as uint64_t,
            ],
            [
                0x621c540a1df84361 as libc::c_long as uint64_t,
                0x1203772171fa6d5d as libc::c_long as uint64_t,
                0x6e3c7b510ff5f6ff as libc::c_long as uint64_t,
                0x817a069babb2bef3 as libc::c_ulong,
            ],
        ],
        [
            [
                0x8a10b53189e800ca as libc::c_ulong,
                0x50fe0c17145208fd as libc::c_long as uint64_t,
                0x9e43c0d3b714ba37 as libc::c_ulong,
                0x427d200e34189acc as libc::c_long as uint64_t,
            ],
            [
                0x5dee24fe616e2c0 as libc::c_long as uint64_t,
                0x9c25f4c8ee1854c1 as libc::c_ulong,
                0x4d3222a58f342a73 as libc::c_long as uint64_t,
                0x807804fa027c952 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x22c49ec9b809b7ce as libc::c_long as uint64_t,
                0x8a41486be2c72c2c as libc::c_ulong,
                0x813b9420fea0bf36 as libc::c_ulong,
                0xb3d36ee9a66dac69 as libc::c_ulong,
            ],
            [
                0x6fddc08a328cc987 as libc::c_long as uint64_t,
                0xa3bcd2c3a326461 as libc::c_long as uint64_t,
                0x7103c49dd810dbba as libc::c_long as uint64_t,
                0xf9d81a284b78a4c4 as libc::c_ulong,
            ],
        ],
        [
            [
                0x501d070cb98fe684 as libc::c_long as uint64_t,
                0xd60fbe9a124a1458 as libc::c_ulong,
                0xa45761c892bc6b3f as libc::c_ulong,
                0xf5384858fe6f27cb as libc::c_ulong,
            ],
            [
                0x4b0271f7b59e763b as libc::c_long as uint64_t,
                0x3d4606a95b5a8e5e as libc::c_long as uint64_t,
                0x1eda5d9b05a48292 as libc::c_long as uint64_t,
                0xda7731d0e6fec446 as libc::c_ulong,
            ],
        ],
        [
            [
                0x70469b8295caabee as libc::c_long as uint64_t,
                0xde024ca5889501e3 as libc::c_ulong,
                0x6bdadc06076ed265 as libc::c_long as uint64_t,
                0xcb1236b5a0ef8b2 as libc::c_long as uint64_t,
            ],
            [
                0x4065ddbf0972ebf9 as libc::c_long as uint64_t,
                0xf1dd387522aca432 as libc::c_ulong,
                0xa88b97cf744aff76 as libc::c_ulong,
                0xd1359afdfe8e3d24 as libc::c_ulong,
            ],
        ],
        [
            [
                0xe8815ff62f93a675 as libc::c_ulong,
                0xa6ec968405f48679 as libc::c_ulong,
                0x6dcbb556358ae884 as libc::c_long as uint64_t,
                0xaf61472e19e3873 as libc::c_long as uint64_t,
            ],
            [
                0x72334372a5f696be as libc::c_long as uint64_t,
                0xc65e57ea6f22fb70 as libc::c_ulong,
                0x268da30c946cea90 as libc::c_long as uint64_t,
                0x136a8a8765681b2a as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x1192d9d493a3147a as libc::c_long as uint64_t,
                0x9f30a5dc9a565545 as libc::c_ulong,
                0x90b1f9cb6ef07212 as libc::c_ulong,
                0x299585460d87fc13 as libc::c_long as uint64_t,
            ],
            [
                0xd3323effc17db9ba as libc::c_ulong,
                0xcb18548ccb1644a8 as libc::c_ulong,
                0x18a306d44f49ffbc as libc::c_long as uint64_t,
                0x28d658f14c2e8684 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x83ccbe808c3bff36 as libc::c_ulong,
                0x5a0bd25263e575 as libc::c_long as uint64_t,
                0x460d7dda259bdcd1 as libc::c_long as uint64_t,
                0x4a1c5642fa5cab6b as libc::c_long as uint64_t,
            ],
            [
                0x2b7bdbb99fe4fc88 as libc::c_long as uint64_t,
                0x9418e28cc97bbb5 as libc::c_long as uint64_t,
                0xd8274fb4a12321ae as libc::c_ulong,
                0xb137007d5c87b64e as libc::c_ulong,
            ],
        ],
        [
            [
                0xfe48f575f8547be3 as libc::c_ulong,
                0xa7033cda9e45f98 as libc::c_long as uint64_t,
                0x4b45d3a918c50100 as libc::c_long as uint64_t,
                0xb2a6cd6aa61d41da as libc::c_ulong,
            ],
            [
                0x60bbb4f557933c6b as libc::c_long as uint64_t,
                0xa7538ebd2b0d7ffc as libc::c_ulong,
                0x9ea3ab8d8cd626b6 as libc::c_ulong,
                0x8273a4843601625a as libc::c_ulong,
            ],
        ],
        [
            [
                0x7e3320eb34a9f7ae as libc::c_long as uint64_t,
                0xe5e8cf72d751efe4 as libc::c_ulong,
                0x7ea003bcd9be2f37 as libc::c_long as uint64_t,
                0xc0f551a0b6c08ef7 as libc::c_ulong,
            ],
            [
                0x56606268038f6725 as libc::c_long as uint64_t,
                0x1dd38e356d92d3b6 as libc::c_long as uint64_t,
                0x7dfce7cc3cbd686 as libc::c_long as uint64_t,
                0x4e549e04651c5da8 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x2a29ebfe6ddd505 as libc::c_long as uint64_t,
                0x37064e74b50bed1a as libc::c_long as uint64_t,
                0x3f6bae65a7327d57 as libc::c_long as uint64_t,
                0x3846f5f1f83920bc as libc::c_long as uint64_t,
            ],
            [
                0x87c3749160df1b9b as libc::c_ulong,
                0x4cfb28952d1da29f as libc::c_long as uint64_t,
                0x10a478ca4ed1743c as libc::c_long as uint64_t,
                0x390c60303edd47c6 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x4aeaf742580b1a01 as libc::c_long as uint64_t,
                0xf080415d60423b79 as libc::c_ulong,
                0xe12622cda7dea144 as libc::c_ulong,
                0x49ea499659d62472 as libc::c_long as uint64_t,
            ],
            [
                0xb42991ef571f3913 as libc::c_ulong,
                0x610f214f5b25a8a as libc::c_long as uint64_t,
                0x47adc58530b79e8f as libc::c_long as uint64_t,
                0xf90e3df607a065a2 as libc::c_ulong,
            ],
        ],
        [
            [
                0xd3fb577157151692 as libc::c_ulong,
                0xeb2721f8d98e1c44 as libc::c_ulong,
                0xc050608732399be1 as libc::c_ulong,
                0xda5a5511d979d8b8 as libc::c_ulong,
            ],
            [
                0x737ed55dc6f56780 as libc::c_long as uint64_t,
                0xe20d30040dc7a7f4 as libc::c_ulong,
                0x2ce7301f5941a03 as libc::c_long as uint64_t,
                0x91ef5215ed30f83a as libc::c_ulong,
            ],
        ],
        [
            [
                0x665c228bf99c2471 as libc::c_long as uint64_t,
                0xf2d8a11b191eb110 as libc::c_ulong,
                0x4594f494d36d7024 as libc::c_long as uint64_t,
                0x482ded8bcdcb25a1 as libc::c_long as uint64_t,
            ],
            [
                0xc958a9d8dadd4885 as libc::c_ulong,
                0x7004477ef1d2b547 as libc::c_long as uint64_t,
                0xa45f6ef2a0af550 as libc::c_long as uint64_t,
                0x4fc739d62f8d6351 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x5ad98ed583fa1e08 as libc::c_long as uint64_t,
                0x7780d33ebeabd1fb as libc::c_long as uint64_t,
                0xe330513c903b1196 as libc::c_ulong,
                0xba11de9ea47bc8c4 as libc::c_ulong,
            ],
            [
                0x684334da02c2d064 as libc::c_long as uint64_t,
                0x7ecf360da48de23b as libc::c_long as uint64_t,
                0x57a1b4740a9089d8 as libc::c_long as uint64_t,
                0xf28fa439ff36734c as libc::c_ulong,
            ],
        ],
        [
            [
                0x383f9ed9926fce43 as libc::c_long as uint64_t,
                0x809dd1c704da2930 as libc::c_ulong,
                0x30f6f5968a4cb227 as libc::c_long as uint64_t,
                0xd700c7f73a56b38 as libc::c_long as uint64_t,
            ],
            [
                0x1825ea33ab64a065 as libc::c_long as uint64_t,
                0xaab9b7351338df80 as libc::c_ulong,
                0x1516100d9b63f57f as libc::c_long as uint64_t,
                0x2574395a27a6a634 as libc::c_long as uint64_t,
            ],
        ],
    ],
    [
        [
            [
                0xd433e50f6d3549cf as libc::c_ulong,
                0x6f33696ffacd665e as libc::c_long as uint64_t,
                0x695bfdacce11fcb4 as libc::c_long as uint64_t,
                0x810ee252af7c9860 as libc::c_ulong,
            ],
            [
                0x65450fe17159bb2c as libc::c_long as uint64_t,
                0xf7dfbebe758b357b as libc::c_ulong,
                0x2b057e74d69fea72 as libc::c_long as uint64_t,
                0xd485717a92731745 as libc::c_ulong,
            ],
        ],
        [
            [
                0x6c8d0aa9b898fd52 as libc::c_long as uint64_t,
                0x2fb38a57be9af1a7 as libc::c_long as uint64_t,
                0xe1f2b9a93b4f03f8 as libc::c_ulong,
                0x2b1aad44c3f0cc6f as libc::c_long as uint64_t,
            ],
            [
                0x58b5332e7cf2c084 as libc::c_long as uint64_t,
                0x1c57d96f0367d26d as libc::c_long as uint64_t,
                0x2297eabdfa6e4a8d as libc::c_long as uint64_t,
                0x65a947ee4a0e2b6a as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xf535b616fdd5b854 as libc::c_ulong,
                0x592549c85728719f as libc::c_long as uint64_t,
                0xe231468606921cad as libc::c_ulong,
                0x98c8ce34311b1ef8 as libc::c_ulong,
            ],
            [
                0x28b937e7e9090b36 as libc::c_long as uint64_t,
                0x67fc3ab90bf7bbb7 as libc::c_long as uint64_t,
                0x12337097a9d87974 as libc::c_long as uint64_t,
                0x3e5adca1f970e3fe as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xcdcc68a7b3f85ff0 as libc::c_ulong,
                0xacd21cdd1a888044 as libc::c_ulong,
                0xb6719b2e05dbe894 as libc::c_ulong,
                0xfae1d3d88b8260d4 as libc::c_ulong,
            ],
            [
                0xedfedece8a1c5d92 as libc::c_ulong,
                0xbca01a94dc52077e as libc::c_ulong,
                0xc085549c16dd13ed as libc::c_ulong,
                0xdc5c3bae495ebaad as libc::c_ulong,
            ],
        ],
        [
            [
                0xcc17063fbe7b643a as libc::c_ulong,
                0x7872e1c846085760 as libc::c_long as uint64_t,
                0x86b0fffbb4214c9e as libc::c_ulong,
                0xb18bbc0e72bf3638 as libc::c_ulong,
            ],
            [
                0x8b17de0c722591c9 as libc::c_ulong,
                0x1edeab1948c29e0c as libc::c_long as uint64_t,
                0x9fbfd98ef4304f20 as libc::c_ulong,
                0x2d1dbb6b9c77ffb6 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x255616d3c7141771 as libc::c_long as uint64_t,
                0xa86691ab2f226b66 as libc::c_ulong,
                0xda19fea4b3ca63a9 as libc::c_ulong,
                0xfc05dc42ae672f2b as libc::c_ulong,
            ],
            [
                0xa9c6e786718ba28f as libc::c_ulong,
                0x7b7995b9c66b984 as libc::c_long as uint64_t,
                0xf434f551b3702f2 as libc::c_long as uint64_t,
                0xd6f6212fda84eeff as libc::c_ulong,
            ],
        ],
        [
            [
                0x4b0e7987b5b41d78 as libc::c_long as uint64_t,
                0xea7df9074bf0c4f8 as libc::c_ulong,
                0xb4d03560fab80ecd as libc::c_ulong,
                0x6cf306f6fb1db7e5 as libc::c_long as uint64_t,
            ],
            [
                0xd59fb5689fd4773 as libc::c_long as uint64_t,
                0xab254f4000f9be33 as libc::c_ulong,
                0x18a09a9277352da4 as libc::c_long as uint64_t,
                0xf81862f5641ea3ef as libc::c_ulong,
            ],
        ],
        [
            [
                0xb59b01579f759d01 as libc::c_ulong,
                0xa2923d2f7eae4fde as libc::c_ulong,
                0x18327757690ba8c0 as libc::c_long as uint64_t,
                0x4bf7e38b44f51443 as libc::c_long as uint64_t,
            ],
            [
                0xb6812563b413fc26 as libc::c_ulong,
                0xedb7d36379e53b36 as libc::c_ulong,
                0x4fa585c4c389f66d as libc::c_long as uint64_t,
                0x8e1adc3154bd3416 as libc::c_ulong,
            ],
        ],
        [
            [
                0x971e9eedd5098497 as libc::c_ulong,
                0x97692be63077d8a7 as libc::c_ulong,
                0xb57e02ad79625a8a as libc::c_ulong,
                0x5e3d20f6a688ecd5 as libc::c_long as uint64_t,
            ],
            [
                0xa4431a28188f964d as libc::c_ulong,
                0xd4eb23bd5a11c1db as libc::c_ulong,
                0xfcda853eadc7446f as libc::c_ulong,
                0x9e2e98b593c94046 as libc::c_ulong,
            ],
        ],
        [
            [
                0x4a649b66eddaa4f1 as libc::c_long as uint64_t,
                0x35a04f185e690c50 as libc::c_long as uint64_t,
                0x1639bdcff908bc53 as libc::c_long as uint64_t,
                0xce6d525c121726e8 as libc::c_ulong,
            ],
            [
                0x70f34948902b402c as libc::c_long as uint64_t,
                0x3a40c6950e290579 as libc::c_long as uint64_t,
                0x7b0ed90f469a0085 as libc::c_long as uint64_t,
                0xecb979c60189c501 as libc::c_ulong,
            ],
        ],
        [
            [
                0x847e2bde5cee8d07 as libc::c_ulong,
                0x1bed198cd3340037 as libc::c_long as uint64_t,
                0x439ffb3ce41586e3 as libc::c_long as uint64_t,
                0x594980f1856f15b0 as libc::c_long as uint64_t,
            ],
            [
                0x22c3b86c6e9307c6 as libc::c_long as uint64_t,
                0xf8b3ee08876382db as libc::c_ulong,
                0x850c628e628f3f30 as libc::c_ulong,
                0x22ec0acb51ee3659 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xa4052591efcef5a0 as libc::c_ulong,
                0x82692a47106d55af as libc::c_ulong,
                0xdac3ea88e6ead453 as libc::c_ulong,
                0xaa1368fcf3dfd875 as libc::c_ulong,
            ],
            [
                0x87bc688aa0c539ea as libc::c_ulong,
                0x905e206040b1de3e as libc::c_ulong,
                0x72240b8f1d52452 as libc::c_long as uint64_t,
                0x3ebf0644d57b6580 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x12109bcc07a0b2f8 as libc::c_long as uint64_t,
                0x336f87d2ca23f14c as libc::c_long as uint64_t,
                0xb39ae282452a2ea2 as libc::c_ulong,
                0x8e085f5bab59a500 as libc::c_ulong,
            ],
            [
                0xf7daeb69b63f015c as libc::c_ulong,
                0x44c555bcacb47b38 as libc::c_long as uint64_t,
                0x96190454b623910a as libc::c_ulong,
                0x4b666e2255b41b70 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xf146914eb53419fd as libc::c_ulong,
                0xd2109b07493e88bf as libc::c_ulong,
                0x30bf9cbccc54bcd5 as libc::c_long as uint64_t,
                0xcf9ea59750e34a1f as libc::c_ulong,
            ],
            [
                0x70ade8a59588591d as libc::c_long as uint64_t,
                0xf668be676b41c269 as libc::c_ulong,
                0x3497c58f78df2e6b as libc::c_long as uint64_t,
                0xfad05cc71042b56 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x709da836093aa5f6 as libc::c_long as uint64_t,
                0x567a9becb4644ede as libc::c_long as uint64_t,
                0xae02a46044466b0c as libc::c_ulong,
                0xc80b237a407f1b3b as libc::c_ulong,
            ],
            [
                0x451df45ab4168a98 as libc::c_long as uint64_t,
                0xdc9b40ef24a3f7c9 as libc::c_ulong,
                0x23593ef32671341d as libc::c_long as uint64_t,
                0x40f4533190b90faa as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x7f97768e922f36e3 as libc::c_long as uint64_t,
                0x936943f8491034a2 as libc::c_ulong,
                0x72f6c17f21483753 as libc::c_long as uint64_t,
                0x5489fa0cb2918619 as libc::c_long as uint64_t,
            ],
            [
                0x55b31aa59cc21a46 as libc::c_long as uint64_t,
                0xde4cc71a8e54ab14 as libc::c_ulong,
                0x942cb8be9eaff8b0 as libc::c_ulong,
                0xe38f6116d1755231 as libc::c_ulong,
            ],
        ],
    ],
    [
        [
            [
                0x949c9976e1337c26 as libc::c_ulong,
                0x6faadebdd73d68e5 as libc::c_long as uint64_t,
                0x9e158614f1b768d9 as libc::c_ulong,
                0x22dfa5579cc4f069 as libc::c_long as uint64_t,
            ],
            [
                0xccd6da17be93c6d6 as libc::c_ulong,
                0x24866c61a504f5b9 as libc::c_long as uint64_t,
                0x2121353c8d694da1 as libc::c_long as uint64_t,
                0x1c6ca5800140b8c6 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xbd5660ed9aed9f40 as libc::c_ulong,
                0x70ca6ad1532a8c99 as libc::c_long as uint64_t,
                0xc4978bfb95c371ea as libc::c_ulong,
                0xe5464d0d7003109d as libc::c_ulong,
            ],
            [
                0x1af32fdfd9e535ef as libc::c_long as uint64_t,
                0xabf57ea798c9185b as libc::c_ulong,
                0xed7a741712b42488 as libc::c_ulong,
                0x8e0296a7e97286fa as libc::c_ulong,
            ],
        ],
        [
            [
                0x8b57416e1f017d5e as libc::c_ulong,
                0x375333967674e99b as libc::c_long as uint64_t,
                0x6e6d94c0e8f488a0 as libc::c_long as uint64_t,
                0xb93a787adc16f95e as libc::c_ulong,
            ],
            [
                0xc3ac51a2dcc99ccc as libc::c_ulong,
                0xc134b4139aa47c1d as libc::c_ulong,
                0xf28fcdafafdfd8d5 as libc::c_ulong,
                0xd57bd8e10b831ed as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xd2fcd2006c19d4c7 as libc::c_ulong,
                0xa0f3c437e1b1e976 as libc::c_ulong,
                0xf0545ff694f237e8 as libc::c_ulong,
                0xdd10ec3fc0bf8bb1 as libc::c_ulong,
            ],
            [
                0x4f89696cac7cd3e1 as libc::c_long as uint64_t,
                0xed3714ec5f24bfe6 as libc::c_ulong,
                0x363eb1d85faf7706 as libc::c_long as uint64_t,
                0xfcbd604dc027cc32 as libc::c_ulong,
            ],
        ],
        [
            [
                0x16ce8eddc355363b as libc::c_long as uint64_t,
                0x4af2f70ff8820d6e as libc::c_long as uint64_t,
                0xcb7ed4d27661a508 as libc::c_ulong,
                0x41d3444edd195472 as libc::c_long as uint64_t,
            ],
            [
                0x17fea2b438da9649 as libc::c_long as uint64_t,
                0x9bf69356aeb4a200 as libc::c_ulong,
                0xa13b5f916ab19c3d as libc::c_ulong,
                0xc0519c14dc9360a6 as libc::c_ulong,
            ],
        ],
        [
            [
                0xde74e49ca70684d1 as libc::c_ulong,
                0x3ae8766133e80c3d as libc::c_long as uint64_t,
                0x5984a2a916a5c34d as libc::c_long as uint64_t,
                0x9a83eccb8298c35 as libc::c_long as uint64_t,
            ],
            [
                0x9a19867caa4ca4c0 as libc::c_ulong,
                0x2085610b375b8ff as libc::c_long as uint64_t,
                0xf296328bf70396dc as libc::c_ulong,
                0x9c9ddc4cde6fae63 as libc::c_ulong,
            ],
        ],
        [
            [
                0x94683d260b083b6e as libc::c_ulong,
                0xa3752eb06f6a54d as libc::c_long as uint64_t,
                0x48bedc23752074dd as libc::c_long as uint64_t,
                0x637622fc3e822593 as libc::c_long as uint64_t,
            ],
            [
                0xea0005136be55d3b as libc::c_ulong,
                0x9f5e12f4324d006d as libc::c_ulong,
                0x529486a964fc0270 as libc::c_long as uint64_t,
                0x9ba0d0c923399e6 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xd3e926ab121550b3 as libc::c_ulong,
                0xe4975e4ac147ce84 as libc::c_ulong,
                0x7a8be0f95eff722a as libc::c_long as uint64_t,
                0x71e4702c6fd4f2a0 as libc::c_long as uint64_t,
            ],
            [
                0x13b92acf3cb7b280 as libc::c_long as uint64_t,
                0xc588716d28272d73 as libc::c_ulong,
                0x862c7bf3daa9fe5c as libc::c_ulong,
                0x78c008f2e2a79e42 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xed5832c5f536fa1f as libc::c_ulong,
                0xe16f3f55928244a4 as libc::c_ulong,
                0xf43a2621bf5be190 as libc::c_ulong,
                0xf7d672c3ca2b6b2b as libc::c_ulong,
            ],
            [
                0x64f86245827a5b83 as libc::c_long as uint64_t,
                0xc1a109f500e97f72 as libc::c_ulong,
                0xc259785ca47327bb as libc::c_ulong,
                0xdaf109e97f6a62b6 as libc::c_ulong,
            ],
        ],
        [
            [
                0xcea3f5e91cc1d43a as libc::c_ulong,
                0x624acadb6a233af4 as libc::c_long as uint64_t,
                0xc9df18a9d0efe7c2 as libc::c_ulong,
                0xfe0d0be879ba79f3 as libc::c_ulong,
            ],
            [
                0xc74c5a56522ff5ea as libc::c_ulong,
                0x4ac379f06c7d514e as libc::c_long as uint64_t,
                0x64921404d70ea29f as libc::c_long as uint64_t,
                0x443ee5910269f270 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x3874f443a61ea539 as libc::c_long as uint64_t,
                0x90a3a311c206fedf as libc::c_ulong,
                0x962a7b5b0fbd8785 as libc::c_ulong,
                0xfc37e97058c31c8b as libc::c_ulong,
            ],
            [
                0xcdeb55385f1a1048 as libc::c_ulong,
                0x5a2051228ccd6255 as libc::c_long as uint64_t,
                0x9762d4969c4f1b8b as libc::c_ulong,
                0x213d8803d52f05de as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xc89cd3a713c5f7f4 as libc::c_ulong,
                0xd9cb54eac352eed as libc::c_long as uint64_t,
                0x462e7aee33b34788 as libc::c_long as uint64_t,
                0x831af1437c998d9a as libc::c_ulong,
            ],
            [
                0xed8802c911e04f87 as libc::c_ulong,
                0x1ca1a00b1938d969 as libc::c_long as uint64_t,
                0x52805bb47bbb9310 as libc::c_long as uint64_t,
                0xcaa3cde431c16410 as libc::c_ulong,
            ],
        ],
        [
            [
                0x2eb856d5390bc059 as libc::c_long as uint64_t,
                0xc0eabd5f041312df as libc::c_ulong,
                0x7eef45df8636d67b as libc::c_long as uint64_t,
                0x6909e81fdfea7fb5 as libc::c_long as uint64_t,
            ],
            [
                0x628e8c5331da7737 as libc::c_long as uint64_t,
                0x1b2f8be3755b55bc as libc::c_long as uint64_t,
                0x35ba0512137841d7 as libc::c_long as uint64_t,
                0x59550359317ce57d as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x34ef003b45575c1c as libc::c_long as uint64_t,
                0xdeb3e7a049c2fe0c as libc::c_ulong,
                0x48ec01df7149c63 as libc::c_long as uint64_t,
                0x203869b9c79a986c as libc::c_long as uint64_t,
            ],
            [
                0xcf7c40836c1e80ef as libc::c_ulong,
                0x210e17d58e294447 as libc::c_long as uint64_t,
                0x2b507d2e1212601c as libc::c_long as uint64_t,
                0x98edd3fa5a17e279 as libc::c_ulong,
            ],
        ],
        [
            [
                0x9bf42636e91d691d as libc::c_ulong,
                0xbcc32428fc07be4 as libc::c_long as uint64_t,
                0x5b205cae69e9aa90 as libc::c_long as uint64_t,
                0x6f69722b399cf75e as libc::c_long as uint64_t,
            ],
            [
                0x3db059f679424235 as libc::c_long as uint64_t,
                0x6b98b404a2205463 as libc::c_long as uint64_t,
                0x68caf5e46f60f451 as libc::c_long as uint64_t,
                0xe8f1fc66ad08939e as libc::c_ulong,
            ],
        ],
        [
            [
                0x1939fd67c776edf8 as libc::c_long as uint64_t,
                0xd0847c70cb5c848a as libc::c_ulong,
                0x4ff553915ade03d1 as libc::c_long as uint64_t,
                0x8fb54d83cfa9823e as libc::c_ulong,
            ],
            [
                0xb308146ef10d4e04 as libc::c_ulong,
                0x14a691b3b6cb2a36 as libc::c_long as uint64_t,
                0x2f419b93c620657f as libc::c_long as uint64_t,
                0x4db7aaa2d3e1da7f as libc::c_long as uint64_t,
            ],
        ],
    ],
    [
        [
            [
                0x25914f7881fdad90 as libc::c_long as uint64_t,
                0xcf638f560d2cf6ab as libc::c_ulong,
                0xb90bc03fcc054de5 as libc::c_ulong,
                0x932811a718b06350 as libc::c_ulong,
            ],
            [
                0x2f00b3309bbd11ff as libc::c_long as uint64_t,
                0x76108a6fb4044974 as libc::c_long as uint64_t,
                0x801bb9e0a851d266 as libc::c_ulong,
                0xdd099bebf8990c1 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xebd6a6777b0ac93d as libc::c_ulong,
                0xa6e37b0d78f5e0d7 as libc::c_ulong,
                0x2516c09676f5492b as libc::c_long as uint64_t,
                0x1e4bf8889ac05f3a as libc::c_long as uint64_t,
            ],
            [
                0xcdb42ce04df0ba2b as libc::c_ulong,
                0x935d5cfd5062341b as libc::c_ulong,
                0x8a30333382acac20 as libc::c_ulong,
                0x429438c45198b00e as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x6c626f56c1770616 as libc::c_long as uint64_t,
                0x5351909e09da9a2d as libc::c_long as uint64_t,
                0xe58e6825a3730e45 as libc::c_ulong,
                0x9d8c8bc003ef0a79 as libc::c_ulong,
            ],
            [
                0x543f78b6056becfd as libc::c_long as uint64_t,
                0x33f13253a090b36d as libc::c_long as uint64_t,
                0x82ad4997794432f9 as libc::c_ulong,
                0x1386493c4721f502 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xe566f400b008733a as libc::c_ulong,
                0xcba0697d512e1f57 as libc::c_ulong,
                0x9537c2b240509cd0 as libc::c_ulong,
                0x5f989c6957353d8c as libc::c_long as uint64_t,
            ],
            [
                0x7dbec9724c3c2b2f as libc::c_long as uint64_t,
                0x90e02fa8ff031fa8 as libc::c_ulong,
                0xf4d15c53cfd5d11f as libc::c_ulong,
                0xb3404fae48314dfc as libc::c_ulong,
            ],
        ],
        [
            [
                0xf02cc3a9f327a07f as libc::c_ulong,
                0xefb27a9b4490937d as libc::c_ulong,
                0x81451e96b1b3afa5 as libc::c_ulong,
                0x67e24de891883be4 as libc::c_long as uint64_t,
            ],
            [
                0x1ad65d4770869e54 as libc::c_long as uint64_t,
                0xd36291a464a3856a as libc::c_ulong,
                0x70a1abf7132e880 as libc::c_long as uint64_t,
                0x9511d0a30e28dfdf as libc::c_ulong,
            ],
        ],
        [
            [
                0x9b185facc72a4be5 as libc::c_ulong,
                0xf66de2364d848089 as libc::c_ulong,
                0xba14d07c717afea9 as libc::c_ulong,
                0x25bfbfc02d551c1c as libc::c_long as uint64_t,
            ],
            [
                0x2cef0ecd4cdf3d88 as libc::c_long as uint64_t,
                0x8cee2aa3647f73c4 as libc::c_ulong,
                0xc10a7d3d722d67f7 as libc::c_ulong,
                0x90037a294564a21 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x6ac07bb84f3815c4 as libc::c_long as uint64_t,
                0xddb9f6241aa9017e as libc::c_ulong,
                0x31e30228ca85720a as libc::c_long as uint64_t,
                0xe59d63f57cb75838 as libc::c_ulong,
            ],
            [
                0x69e18e777baad2d0 as libc::c_long as uint64_t,
                0x2cfdb784d42f5d73 as libc::c_long as uint64_t,
                0x25dd53df5774983 as libc::c_long as uint64_t,
                0x2f80e7cee042cd52 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x43f18d7f4d6ee4ab as libc::c_long as uint64_t,
                0xd3ac8cde9570c3dc as libc::c_ulong,
                0x527e49070b8c9b2a as libc::c_long as uint64_t,
                0x716709a7c5a4c0f1 as libc::c_long as uint64_t,
            ],
            [
                0x930852b0916a26b1 as libc::c_ulong,
                0x3cc17fcf4e071177 as libc::c_long as uint64_t,
                0x34f5e3d459694868 as libc::c_long as uint64_t,
                0xee0341aba28f655d as libc::c_ulong,
            ],
        ],
        [
            [
                0x4b764317aa365220 as libc::c_long as uint64_t,
                0x7a24affe68cc0355 as libc::c_long as uint64_t,
                0x76732ed0ceb3df5e as libc::c_long as uint64_t,
                0x2ce1332aae096ed0 as libc::c_long as uint64_t,
            ],
            [
                0x89ce70a7b8adac9d as libc::c_ulong,
                0xfdddcf05b3fc85c8 as libc::c_ulong,
                0xbd7b29c6f2ee8bfe as libc::c_ulong,
                0xa1effcb9457d50f3 as libc::c_ulong,
            ],
        ],
        [
            [
                0x6053972dac953207 as libc::c_long as uint64_t,
                0xc2ca9a8408ad12f6 as libc::c_ulong,
                0x9ed6cd386ba36190 as libc::c_ulong,
                0xa5b50a48539d18a4 as libc::c_ulong,
            ],
            [
                0xd9491347dbf18c2a as libc::c_ulong,
                0x2cdce4662e9697cf as libc::c_long as uint64_t,
                0x4e97db5ca9e31819 as libc::c_long as uint64_t,
                0xfb02e2d4c044b74 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x66a4dd414aa5e9dd as libc::c_long as uint64_t,
                0x6ec7576e64f6aeb9 as libc::c_long as uint64_t,
                0x3f08ce06c7e980b5 as libc::c_long as uint64_t,
                0x52fe9fd6c1a2aa7e as libc::c_long as uint64_t,
            ],
            [
                0xfe46e6d95074326a as libc::c_ulong,
                0xd570ed734c126c1d as libc::c_ulong,
                0x86c7ec257217d55a as libc::c_ulong,
                0x3cb434057c3de2b2 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x48e0295dcc9e79bf as libc::c_long as uint64_t,
                0x2419485693eb403d as libc::c_long as uint64_t,
                0x9386fb7709dd8194 as libc::c_ulong,
                0xb6e89bb101a242f6 as libc::c_ulong,
            ],
            [
                0xc7994f3924d308d7 as libc::c_ulong,
                0xf0fbc392de673d88 as libc::c_ulong,
                0x43eed52ea11abb62 as libc::c_long as uint64_t,
                0xc900f9d0c83e7fbe as libc::c_ulong,
            ],
        ],
        [
            [
                0x214a10dca8152891 as libc::c_long as uint64_t,
                0xe6787b4c64f1abb2 as libc::c_ulong,
                0x276333d9fa1a10ed as libc::c_long as uint64_t,
                0xc0e1c88e47dbccbc as libc::c_ulong,
            ],
            [
                0x8a3c37c4849dd12e as libc::c_ulong,
                0x2144a8c8d86e109f as libc::c_long as uint64_t,
                0xbb6891f7286c140c as libc::c_ulong,
                0xb0b8c5e29cce5e6f as libc::c_ulong,
            ],
        ],
        [
            [
                0x3f9e0e3499753288 as libc::c_long as uint64_t,
                0x6b26f1ebe559d93a as libc::c_long as uint64_t,
                0x647fe21d9841faf1 as libc::c_long as uint64_t,
                0x48a4b6efa786ea02 as libc::c_long as uint64_t,
            ],
            [
                0x6e09cd22665a882d as libc::c_long as uint64_t,
                0x95390d81b63ccda6 as libc::c_ulong,
                0x5b014db4b026a44a as libc::c_long as uint64_t,
                0x5b96efb22ad30ff1 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x571c246bf009a690 as libc::c_long as uint64_t,
                0x8fe54231ccd90d3a as libc::c_ulong,
                0x8adde6adfe173b79 as libc::c_ulong,
                0x75d9a392b05a5e3b as libc::c_long as uint64_t,
            ],
            [
                0x607f47b0d1bb3a84 as libc::c_long as uint64_t,
                0xe4e3b472058e691a as libc::c_ulong,
                0xfc0f793bf3d956e3 as libc::c_ulong,
                0x6a6730b605de54da as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x4daf7f540d80aaa1 as libc::c_long as uint64_t,
                0xc571d04c229c4574 as libc::c_ulong,
                0x469e2da5fffca53d as libc::c_long as uint64_t,
                0x9fffe29513ff7f59 as libc::c_ulong,
            ],
            [
                0x2075da5a33a254f7 as libc::c_long as uint64_t,
                0x769f33acd35e575d as libc::c_long as uint64_t,
                0x7b940d2c3d35001a as libc::c_long as uint64_t,
                0x2d606b57e34c95b7 as libc::c_long as uint64_t,
            ],
        ],
    ],
    [
        [
            [
                0xdb567d6ac42bd6d2 as libc::c_ulong,
                0x6df86468bb1f96ae as libc::c_long as uint64_t,
                0xefe5b1a4843b28e as libc::c_long as uint64_t,
                0x961bbb056379b240 as libc::c_ulong,
            ],
            [
                0xb6caf5f070a6a26b as libc::c_ulong,
                0x70686c0d328e6e39 as libc::c_long as uint64_t,
                0x80da06cf895fc8d3 as libc::c_ulong,
                0x804d8810b363fdc9 as libc::c_ulong,
            ],
        ],
        [
            [
                0x14e49da11f17a34c as libc::c_long as uint64_t,
                0x5420ab39235a1456 as libc::c_long as uint64_t,
                0xb76372412f50363b as libc::c_ulong,
                0x7b15d623c3fabb6e as libc::c_long as uint64_t,
            ],
            [
                0xa0ef40b1e274e49c as libc::c_ulong,
                0x5cf5074496b1860a as libc::c_long as uint64_t,
                0xd6583fbf66afe5a4 as libc::c_ulong,
                0x44240510f47e3e9a as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xb5358b1e48ac2840 as libc::c_ulong,
                0x18311294ecba9477 as libc::c_long as uint64_t,
                0xda58f990a6946b43 as libc::c_ulong,
                0x3098baf99ab41819 as libc::c_long as uint64_t,
            ],
            [
                0x66c4c1584198da52 as libc::c_long as uint64_t,
                0xab4fc17c146bfd1b as libc::c_ulong,
                0x2f0a4c3cbf36a908 as libc::c_long as uint64_t,
                0x2ae9e34b58cf7838 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x417499e84a34f239 as libc::c_long as uint64_t,
                0x15fdb83cb90402d5 as libc::c_long as uint64_t,
                0xb75f46bf433aa832 as libc::c_ulong,
                0xb61e15af63215db1 as libc::c_ulong,
            ],
            [
                0xaabe59d4a127f89a as libc::c_ulong,
                0x5d541e0c07e816da as libc::c_long as uint64_t,
                0xaaba0659a618b692 as libc::c_ulong,
                0x5532773317266026 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x23c155d3f6effc7 as libc::c_long as uint64_t,
                0x1fbd69ff9c90f0c7 as libc::c_long as uint64_t,
                0xe5d7da8abeec2c5d as libc::c_ulong,
                0x8813872bd7e86273 as libc::c_ulong,
            ],
            [
                0x9f3bc2c655f5e228 as libc::c_ulong,
                0x11482869b0923b41 as libc::c_long as uint64_t,
                0x65d75c741aa307ca as libc::c_long as uint64_t,
                0xda92c2577f24eee5 as libc::c_ulong,
            ],
        ],
        [
            [
                0x8dd1028754c92e1 as libc::c_long as uint64_t,
                0xca90b57acf0fef34 as libc::c_ulong,
                0x1a9b84ac8af55919 as libc::c_long as uint64_t,
                0xaa95e0e1ed93686b as libc::c_ulong,
            ],
            [
                0x46737315167021a4 as libc::c_long as uint64_t,
                0x6cb6a0da20d5ff98 as libc::c_long as uint64_t,
                0xecc4801a1092e706 as libc::c_ulong,
                0xedcab23a3c5e61a6 as libc::c_ulong,
            ],
        ],
        [
            [
                0x7f1290fca06d107e as libc::c_long as uint64_t,
                0x697261fdb7661137 as libc::c_long as uint64_t,
                0x1bb5be4e947b4b38 as libc::c_long as uint64_t,
                0xb49826b63bb79130 as libc::c_ulong,
            ],
            [
                0x19ddfe85ba8bffb as libc::c_long as uint64_t,
                0xb1af79007e3fa8e4 as libc::c_ulong,
                0x72e1bdf201bcfe7f as libc::c_long as uint64_t,
                0x2ed3ca8fd1169aea as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xe17a9947d9de99a8 as libc::c_ulong,
                0xc2e61b2dc93477bd as libc::c_ulong,
                0x57f684d41d19e287 as libc::c_long as uint64_t,
                0x843c2122fe358135 as libc::c_ulong,
            ],
            [
                0xe2d3e2e904f7e8ab as libc::c_ulong,
                0xbf93ffe9b5f27aee as libc::c_ulong,
                0x29830d1d7b1858c4 as libc::c_long as uint64_t,
                0xa8f449648106adbf as libc::c_ulong,
            ],
        ],
        [
            [
                0xe4f68e09ea39ff58 as libc::c_ulong,
                0x529a6c01093f5747 as libc::c_long as uint64_t,
                0x69504f5b89d3815e as libc::c_long as uint64_t,
                0x9e354edc178d50ef as libc::c_ulong,
            ],
            [
                0xbaf10e717ffd934f as libc::c_ulong,
                0x3ccded216718fc09 as libc::c_long as uint64_t,
                0xa2141853fab6ebc0 as libc::c_ulong,
                0x4c6f6cece062d3db as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xe450071612f040ac as libc::c_ulong,
                0x97e2dc6e81f403ce as libc::c_ulong,
                0xb7a60132a135d84 as libc::c_long as uint64_t,
                0xea6bb391e0aeb332 as libc::c_ulong,
            ],
            [
                0xddd39eb5ddecd27c as libc::c_ulong,
                0x1160d45674186a8c as libc::c_long as uint64_t,
                0x9b5bfef1dae8e79c as libc::c_ulong,
                0x9c2af530cbbeb888 as libc::c_ulong,
            ],
        ],
        [
            [
                0x3c2cf12ce6f1a8b4 as libc::c_long as uint64_t,
                0x492b6425a8e11250 as libc::c_long as uint64_t,
                0x10367ec10046b83f as libc::c_long as uint64_t,
                0xa434ff33b8f3ed80 as libc::c_ulong,
            ],
            [
                0xf5c5edf4a0ff3578 as libc::c_ulong,
                0x4b2a5daa53491b25 as libc::c_long as uint64_t,
                0xd260c25406d96030 as libc::c_ulong,
                0xe683a5b411ee77f7 as libc::c_ulong,
            ],
        ],
        [
            [
                0xbd2ed4e5d46da145 as libc::c_ulong,
                0x69df49b64c054bc5 as libc::c_long as uint64_t,
                0xde40cfeef3d7b2fd as libc::c_ulong,
                0x80aa0674f66c8b72 as libc::c_ulong,
            ],
            [
                0x34895b55bd856cf as libc::c_long as uint64_t,
                0x2362171c0c9f52a7 as libc::c_long as uint64_t,
                0x31d0922d63848be4 as libc::c_long as uint64_t,
                0x70f58d9694e18e3 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xdf40adf8fb91f82 as libc::c_long as uint64_t,
                0xe7fde72efecaed56 as libc::c_ulong,
                0x458aeebc0c172b82 as libc::c_long as uint64_t,
                0xc29825e877b1dba2 as libc::c_ulong,
            ],
            [
                0xf4c7612d55acca5 as libc::c_long as uint64_t,
                0x244d5acda96018b as libc::c_long as uint64_t,
                0x47156df5333ea811 as libc::c_long as uint64_t,
                0xae1b96346219e32c as libc::c_ulong,
            ],
        ],
        [
            [
                0x4caf2b4ed2e557cd as libc::c_long as uint64_t,
                0x70f317d0dc6b17bb as libc::c_long as uint64_t,
                0x965bae79492434bb as libc::c_ulong,
                0x15a7acecec046ab as libc::c_long as uint64_t,
            ],
            [
                0xeb0756f2ac542cbf as libc::c_ulong,
                0xbb951a76086ecce0 as libc::c_ulong,
                0x8ae57a4f059a0b92 as libc::c_ulong,
                0x2d333620203a7409 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x10baeb71a3316b4 as libc::c_long as uint64_t,
                0x433792f5123cc15b as libc::c_long as uint64_t,
                0x828fbb9458112bc4 as libc::c_ulong,
                0x2a935f89dc691ead as libc::c_long as uint64_t,
            ],
            [
                0x631bc14331c39202 as libc::c_long as uint64_t,
                0xb4ced9159a1525ff as libc::c_ulong,
                0x9bd706e96ed94fca as libc::c_ulong,
                0x6df7fbf749b1044b as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x43582c6a7979676 as libc::c_long as uint64_t,
                0xe9778e1923d181c8 as libc::c_ulong,
                0x6595e1b6cc92c2c0 as libc::c_long as uint64_t,
                0xea60c4dcafdea46e as libc::c_ulong,
            ],
            [
                0xb6a34f3b4adc2531 as libc::c_ulong,
                0xac3750d3293b93fb as libc::c_ulong,
                0xa88f5d600c49b911 as libc::c_ulong,
                0xe43125876460f19d as libc::c_ulong,
            ],
        ],
    ],
    [
        [
            [
                0x1083e2ea1f095615 as libc::c_long as uint64_t,
                0xa28ad7714e68c33 as libc::c_long as uint64_t,
                0x6bfc02523d8818be as libc::c_long as uint64_t,
                0xb585113af35850cd as libc::c_ulong,
            ],
            [
                0x7d935f0b30df8aa1 as libc::c_long as uint64_t,
                0xaddda07c4ab7e3ac as libc::c_ulong,
                0x92c34299552f00cb as libc::c_ulong,
                0xc33ed1de2909df6c as libc::c_ulong,
            ],
        ],
        [
            [
                0xabe7905a83cdd60e as libc::c_ulong,
                0x50602fb5a1170184 as libc::c_long as uint64_t,
                0x689886cdb023642a as libc::c_long as uint64_t,
                0xd568d090a6e1fb00 as libc::c_ulong,
            ],
            [
                0x5b1922c70259217f as libc::c_long as uint64_t,
                0x93831cd9c43141e4 as libc::c_ulong,
                0xdfca35870c95f86e as libc::c_ulong,
                0xdec2057a568ae828 as libc::c_ulong,
            ],
        ],
        [
            [
                0x860d523d42e06189 as libc::c_ulong,
                0xbf0779414e3aff13 as libc::c_ulong,
                0xb616dcac1b20650 as libc::c_long as uint64_t,
                0xe66dd6d12131300d as libc::c_ulong,
            ],
            [
                0xd4a0fd67ff99abde as libc::c_ulong,
                0xc9903550c7aac50d as libc::c_ulong,
                0x22ecf8b7c46b2d7 as libc::c_long as uint64_t,
                0x3333b1e83abf92af as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xefecdef7be42a582 as libc::c_ulong,
                0xd3fc608065046be6 as libc::c_ulong,
                0xc9af13c809e8dba9 as libc::c_ulong,
                0x1e6c9847641491ff as libc::c_long as uint64_t,
            ],
            [
                0x3b574925d30c31f7 as libc::c_long as uint64_t,
                0xb7eb72baac2a2122 as libc::c_ulong,
                0x776a0dacef0859e7 as libc::c_long as uint64_t,
                0x6fec31421900942 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x7ec62fbbf4737f21 as libc::c_long as uint64_t,
                0xd8dba5ab6209f5ac as libc::c_ulong,
                0x24b5d7a9a5f9adbe as libc::c_long as uint64_t,
                0x707d28f7a61dc768 as libc::c_long as uint64_t,
            ],
            [
                0x7711460bcaa999ea as libc::c_long as uint64_t,
                0xba7b174d1c92e4cc as libc::c_ulong,
                0x3c4bab6618d4bf2d as libc::c_long as uint64_t,
                0xb8f0c980eb8bd279 as libc::c_ulong,
            ],
        ],
        [
            [
                0x28d675b2c0519a23 as libc::c_long as uint64_t,
                0x9ebf94fe4f6952e3 as libc::c_ulong,
                0xf28bb767a2294a8a as libc::c_ulong,
                0x85512b4dfe0af3f5 as libc::c_ulong,
            ],
            [
                0x18958ba899b16a0d as libc::c_long as uint64_t,
                0x95c2430cba7548a7 as libc::c_ulong,
                0xb30d1b10a16be615 as libc::c_ulong,
                0xe3ebbb9785bfb74c as libc::c_ulong,
            ],
        ],
        [
            [
                0x81eeb865d2fdca23 as libc::c_ulong,
                0x5a15ee08cc8ef895 as libc::c_long as uint64_t,
                0x768fa10a01905614 as libc::c_long as uint64_t,
                0xeff5b8ef880ee19b as libc::c_ulong,
            ],
            [
                0xf0c0cabbcb1c8a0e as libc::c_ulong,
                0x2e1ee9cdb8c838f9 as libc::c_long as uint64_t,
                0x587d8b88a4a14c0 as libc::c_long as uint64_t,
                0xf6f278962ff698e5 as libc::c_ulong,
            ],
        ],
        [
            [
                0x9c4b646e9e2fce99 as libc::c_ulong,
                0x68a210811e80857f as libc::c_long as uint64_t,
                0x6d54e443643b52a as libc::c_long as uint64_t,
                0xde8d6d630d8eb843 as libc::c_ulong,
            ],
            [
                0x7032156342146a0a as libc::c_long as uint64_t,
                0x8ba826f25eaa3622 as libc::c_ulong,
                0x227a58bd86138787 as libc::c_long as uint64_t,
                0x43b6c03c10281d37 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x7aca2632f02fc0f0 as libc::c_long as uint64_t,
                0xb92b337dc7f01c86 as libc::c_ulong,
                0x624bc4bf5afbdc7d as libc::c_long as uint64_t,
                0x812b07bc4de21a5e as libc::c_ulong,
            ],
            [
                0x29d137240b2090cc as libc::c_long as uint64_t,
                0x403c5095a1b2132 as libc::c_long as uint64_t,
                0x1dca34d50e35e015 as libc::c_long as uint64_t,
                0xf085ed7d3bbbb66f as libc::c_ulong,
            ],
        ],
        [
            [
                0xc27b98f9f781e865 as libc::c_ulong,
                0x51e1f692994e1345 as libc::c_long as uint64_t,
                0x807d516e19361ee as libc::c_long as uint64_t,
                0x13885ceffb998aef as libc::c_long as uint64_t,
            ],
            [
                0xd223d5e92f0f8a17 as libc::c_ulong,
                0x48672010e8d20280 as libc::c_long as uint64_t,
                0x6f02fd60237eac98 as libc::c_long as uint64_t,
                0xcc51bfad9ada7ee7 as libc::c_ulong,
            ],
        ],
        [
            [
                0x2756bcdd1e09701d as libc::c_long as uint64_t,
                0x94e31db990d45c80 as libc::c_ulong,
                0xb9e856a98566e584 as libc::c_ulong,
                0x4f87d9deab10e3f3 as libc::c_long as uint64_t,
            ],
            [
                0x166ecb373ded9cb2 as libc::c_long as uint64_t,
                0xfd14c7073f653d3e as libc::c_ulong,
                0x105d049b92aec425 as libc::c_long as uint64_t,
                0x7f657e4909a42e11 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0xea6490076a159594 as libc::c_ulong,
                0x3e424d6b1f97ce52 as libc::c_long as uint64_t,
                0xac6df30a185e8ccb as libc::c_ulong,
                0xad56ec80517747bf as libc::c_ulong,
            ],
            [
                0xf0935ccf4391fe93 as libc::c_ulong,
                0x866b260f03811d40 as libc::c_ulong,
                0x792047b99f7b9abe as libc::c_long as uint64_t,
                0xb1600bc88ee42d84 as libc::c_ulong,
            ],
        ],
        [
            [
                0x2d97b3db7768a85f as libc::c_long as uint64_t,
                0x2b78f6334287e038 as libc::c_long as uint64_t,
                0x86c947676f892bb1 as libc::c_ulong,
                0x920bfb1ac0a9c200 as libc::c_ulong,
            ],
            [
                0x4292f6ec332041b2 as libc::c_long as uint64_t,
                0xa30bb937c9989d54 as libc::c_ulong,
                0x39f941ebc6d5879e as libc::c_long as uint64_t,
                0x76a450fcdfdbb187 as libc::c_long as uint64_t,
            ],
        ],
        [
            [
                0x31256089ee430db6 as libc::c_long as uint64_t,
                0xaece9bd8f6836f56 as libc::c_ulong,
                0x484cfc4bfb85a046 as libc::c_long as uint64_t,
                0xee1e3e2c1599b2b9 as libc::c_ulong,
            ],
            [
                0x7e3c38903d122eaf as libc::c_long as uint64_t,
                0xaa940ce0c770556c as libc::c_ulong,
                0x4802d6631b08fae8 as libc::c_long as uint64_t,
                0xb08a85807f69f8ba as libc::c_ulong,
            ],
        ],
        [
            [
                0x4902f495b959b920 as libc::c_long as uint64_t,
                0x13b0fdbdfca2d885 as libc::c_long as uint64_t,
                0x41cbd9e7b6a2f0fa as libc::c_long as uint64_t,
                0xf9bdf11056430b87 as libc::c_ulong,
            ],
            [
                0xd705a223954d19b9 as libc::c_ulong,
                0x74d0fc5c972a4fde as libc::c_long as uint64_t,
                0xcbcbfed6912977ea as libc::c_ulong,
                0x870611fdcc59a5af as libc::c_ulong,
            ],
        ],
        [
            [
                0xf4f19bd04089236a as libc::c_ulong,
                0x3b206c12313d0e0b as libc::c_long as uint64_t,
                0x73e70df303feaeb2 as libc::c_long as uint64_t,
                0x9dba0eb9bd1efe0 as libc::c_long as uint64_t,
            ],
            [
                0x4c7fd532fc4e5305 as libc::c_long as uint64_t,
                0xd792ffede93d787a as libc::c_ulong,
                0xc72dc4e2e4245010 as libc::c_ulong,
                0xe7e0d47d0466bbbd as libc::c_ulong,
            ],
        ],
    ],
];
static mut fiat_p256_one: fiat_p256_felem = [
    0x1 as libc::c_int as uint64_t,
    0xffffffff00000000 as libc::c_ulong,
    0xffffffffffffffff as libc::c_ulong,
    0xfffffffe as libc::c_uint as uint64_t,
];
unsafe extern "C" fn fiat_p256_nz(mut in1: *const fiat_p256_limb_t) -> fiat_p256_limb_t {
    let mut ret: fiat_p256_limb_t = 0;
    fiat_p256_nonzero(&mut ret, in1);
    return ret;
}
unsafe extern "C" fn fiat_p256_from_words(
    mut out: *mut uint64_t,
    mut in_0: *const BN_ULONG,
) {
    OPENSSL_memcpy(
        out as *mut libc::c_void,
        in_0 as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
}
unsafe extern "C" fn fiat_p256_from_generic(
    mut out: *mut uint64_t,
    mut in_0: *const EC_FELEM,
) {
    fiat_p256_from_words(out, ((*in_0).words).as_ptr());
}
unsafe extern "C" fn fiat_p256_to_generic(
    mut out: *mut EC_FELEM,
    mut in_0: *const uint64_t,
) {
    OPENSSL_memcpy(
        ((*out).words).as_mut_ptr() as *mut libc::c_void,
        in_0 as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
}
unsafe extern "C" fn fiat_p256_inv_square(
    mut out: *mut uint64_t,
    mut in_0: *const uint64_t,
) {
    let mut x2: fiat_p256_felem = [0; 4];
    let mut x3: fiat_p256_felem = [0; 4];
    let mut x6: fiat_p256_felem = [0; 4];
    let mut x12: fiat_p256_felem = [0; 4];
    let mut x15: fiat_p256_felem = [0; 4];
    let mut x30: fiat_p256_felem = [0; 4];
    let mut x32: fiat_p256_felem = [0; 4];
    fiat_p256_square(x2.as_mut_ptr(), in_0);
    fiat_p256_mul(x2.as_mut_ptr(), x2.as_mut_ptr() as *const uint64_t, in_0);
    fiat_p256_square(x3.as_mut_ptr(), x2.as_mut_ptr() as *const uint64_t);
    fiat_p256_mul(x3.as_mut_ptr(), x3.as_mut_ptr() as *const uint64_t, in_0);
    fiat_p256_square(x6.as_mut_ptr(), x3.as_mut_ptr() as *const uint64_t);
    let mut i: libc::c_int = 1 as libc::c_int;
    while i < 3 as libc::c_int {
        fiat_p256_square(x6.as_mut_ptr(), x6.as_mut_ptr() as *const uint64_t);
        i += 1;
        i;
    }
    fiat_p256_mul(
        x6.as_mut_ptr(),
        x6.as_mut_ptr() as *const uint64_t,
        x3.as_mut_ptr() as *const uint64_t,
    );
    fiat_p256_square(x12.as_mut_ptr(), x6.as_mut_ptr() as *const uint64_t);
    let mut i_0: libc::c_int = 1 as libc::c_int;
    while i_0 < 6 as libc::c_int {
        fiat_p256_square(x12.as_mut_ptr(), x12.as_mut_ptr() as *const uint64_t);
        i_0 += 1;
        i_0;
    }
    fiat_p256_mul(
        x12.as_mut_ptr(),
        x12.as_mut_ptr() as *const uint64_t,
        x6.as_mut_ptr() as *const uint64_t,
    );
    fiat_p256_square(x15.as_mut_ptr(), x12.as_mut_ptr() as *const uint64_t);
    let mut i_1: libc::c_int = 1 as libc::c_int;
    while i_1 < 3 as libc::c_int {
        fiat_p256_square(x15.as_mut_ptr(), x15.as_mut_ptr() as *const uint64_t);
        i_1 += 1;
        i_1;
    }
    fiat_p256_mul(
        x15.as_mut_ptr(),
        x15.as_mut_ptr() as *const uint64_t,
        x3.as_mut_ptr() as *const uint64_t,
    );
    fiat_p256_square(x30.as_mut_ptr(), x15.as_mut_ptr() as *const uint64_t);
    let mut i_2: libc::c_int = 1 as libc::c_int;
    while i_2 < 15 as libc::c_int {
        fiat_p256_square(x30.as_mut_ptr(), x30.as_mut_ptr() as *const uint64_t);
        i_2 += 1;
        i_2;
    }
    fiat_p256_mul(
        x30.as_mut_ptr(),
        x30.as_mut_ptr() as *const uint64_t,
        x15.as_mut_ptr() as *const uint64_t,
    );
    fiat_p256_square(x32.as_mut_ptr(), x30.as_mut_ptr() as *const uint64_t);
    fiat_p256_square(x32.as_mut_ptr(), x32.as_mut_ptr() as *const uint64_t);
    fiat_p256_mul(
        x32.as_mut_ptr(),
        x32.as_mut_ptr() as *const uint64_t,
        x2.as_mut_ptr() as *const uint64_t,
    );
    let mut ret: fiat_p256_felem = [0; 4];
    fiat_p256_square(ret.as_mut_ptr(), x32.as_mut_ptr() as *const uint64_t);
    let mut i_3: libc::c_int = 1 as libc::c_int;
    while i_3 < 31 as libc::c_int + 1 as libc::c_int {
        fiat_p256_square(ret.as_mut_ptr(), ret.as_mut_ptr() as *const uint64_t);
        i_3 += 1;
        i_3;
    }
    fiat_p256_mul(ret.as_mut_ptr(), ret.as_mut_ptr() as *const uint64_t, in_0);
    let mut i_4: libc::c_int = 0 as libc::c_int;
    while i_4 < 96 as libc::c_int + 32 as libc::c_int {
        fiat_p256_square(ret.as_mut_ptr(), ret.as_mut_ptr() as *const uint64_t);
        i_4 += 1;
        i_4;
    }
    fiat_p256_mul(
        ret.as_mut_ptr(),
        ret.as_mut_ptr() as *const uint64_t,
        x32.as_mut_ptr() as *const uint64_t,
    );
    let mut i_5: libc::c_int = 0 as libc::c_int;
    while i_5 < 32 as libc::c_int {
        fiat_p256_square(ret.as_mut_ptr(), ret.as_mut_ptr() as *const uint64_t);
        i_5 += 1;
        i_5;
    }
    fiat_p256_mul(
        ret.as_mut_ptr(),
        ret.as_mut_ptr() as *const uint64_t,
        x32.as_mut_ptr() as *const uint64_t,
    );
    let mut i_6: libc::c_int = 0 as libc::c_int;
    while i_6 < 30 as libc::c_int {
        fiat_p256_square(ret.as_mut_ptr(), ret.as_mut_ptr() as *const uint64_t);
        i_6 += 1;
        i_6;
    }
    fiat_p256_mul(
        ret.as_mut_ptr(),
        ret.as_mut_ptr() as *const uint64_t,
        x30.as_mut_ptr() as *const uint64_t,
    );
    fiat_p256_square(ret.as_mut_ptr(), ret.as_mut_ptr() as *const uint64_t);
    fiat_p256_square(out, ret.as_mut_ptr() as *const uint64_t);
}
unsafe extern "C" fn fiat_p256_point_double(
    mut x_out: *mut uint64_t,
    mut y_out: *mut uint64_t,
    mut z_out: *mut uint64_t,
    mut x_in: *const uint64_t,
    mut y_in: *const uint64_t,
    mut z_in: *const uint64_t,
) {
    ec_nistp_point_double(p256_methods(), x_out, y_out, z_out, x_in, y_in, z_in);
}
unsafe extern "C" fn fiat_p256_point_add(
    mut x3: *mut uint64_t,
    mut y3: *mut uint64_t,
    mut z3: *mut uint64_t,
    mut x1: *const uint64_t,
    mut y1: *const uint64_t,
    mut z1: *const uint64_t,
    mixed: libc::c_int,
    mut x2: *const uint64_t,
    mut y2: *const uint64_t,
    mut z2: *const uint64_t,
) {
    ec_nistp_point_add(p256_methods(), x3, y3, z3, x1, y1, z1, mixed, x2, y2, z2);
}
#[no_mangle]
pub unsafe extern "C" fn p256_methods() -> *const ec_nistp_meth {
    CRYPTO_once(
        p256_methods_once_bss_get(),
        Some(p256_methods_init as unsafe extern "C" fn() -> ()),
    );
    return p256_methods_storage_bss_get() as *const ec_nistp_meth;
}
unsafe extern "C" fn p256_methods_init() {
    p256_methods_do_init(p256_methods_storage_bss_get());
}
unsafe extern "C" fn p256_methods_do_init(mut out: *mut ec_nistp_meth) {
    (*out).felem_num_limbs = 4 as libc::c_int as size_t;
    (*out).felem_num_bits = 256 as libc::c_int as size_t;
    (*out)
        .felem_add = Some(
        fiat_p256_add
            as unsafe extern "C" fn(
                *mut uint64_t,
                *const uint64_t,
                *const uint64_t,
            ) -> (),
    );
    (*out)
        .felem_sub = Some(
        fiat_p256_sub
            as unsafe extern "C" fn(
                *mut uint64_t,
                *const uint64_t,
                *const uint64_t,
            ) -> (),
    );
    (*out)
        .felem_mul = Some(
        fiat_p256_mul
            as unsafe extern "C" fn(
                *mut uint64_t,
                *const uint64_t,
                *const uint64_t,
            ) -> (),
    );
    (*out)
        .felem_sqr = Some(
        fiat_p256_square as unsafe extern "C" fn(*mut uint64_t, *const uint64_t) -> (),
    );
    (*out)
        .felem_neg = Some(
        fiat_p256_opp as unsafe extern "C" fn(*mut uint64_t, *const uint64_t) -> (),
    );
    (*out)
        .felem_nz = Some(
        fiat_p256_nz as unsafe extern "C" fn(*const fiat_p256_limb_t) -> fiat_p256_limb_t,
    );
    (*out).felem_one = fiat_p256_one.as_ptr();
    (*out)
        .point_dbl = Some(
        fiat_p256_point_double
            as unsafe extern "C" fn(
                *mut uint64_t,
                *mut uint64_t,
                *mut uint64_t,
                *const uint64_t,
                *const uint64_t,
                *const uint64_t,
            ) -> (),
    );
    (*out)
        .point_add = Some(
        fiat_p256_point_add
            as unsafe extern "C" fn(
                *mut uint64_t,
                *mut uint64_t,
                *mut uint64_t,
                *const uint64_t,
                *const uint64_t,
                *const uint64_t,
                libc::c_int,
                *const uint64_t,
                *const uint64_t,
                *const uint64_t,
            ) -> (),
    );
    (*out)
        .scalar_mul_base_table = fiat_p256_g_pre_comp.as_ptr()
        as *const ec_nistp_felem_limb;
}
static mut p256_methods_storage: ec_nistp_meth = ec_nistp_meth {
    felem_num_limbs: 0,
    felem_num_bits: 0,
    felem_add: None,
    felem_sub: None,
    felem_mul: None,
    felem_sqr: None,
    felem_neg: None,
    felem_nz: None,
    felem_one: 0 as *const ec_nistp_felem_limb,
    point_dbl: None,
    point_add: None,
    scalar_mul_base_table: 0 as *const ec_nistp_felem_limb,
};
unsafe extern "C" fn p256_methods_storage_bss_get() -> *mut ec_nistp_meth {
    return &mut p256_methods_storage;
}
static mut p256_methods_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn p256_methods_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut p256_methods_once;
}
unsafe extern "C" fn ec_GFp_nistp256_point_get_affine_coordinates(
    mut group: *const EC_GROUP,
    mut point: *const EC_JACOBIAN,
    mut x_out: *mut EC_FELEM,
    mut y_out: *mut EC_FELEM,
) -> libc::c_int {
    if constant_time_declassify_int(ec_GFp_simple_is_at_infinity(group, point)) != 0 {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            119 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/p256.c\0"
                as *const u8 as *const libc::c_char,
            201 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut z1: fiat_p256_felem = [0; 4];
    let mut z2: fiat_p256_felem = [0; 4];
    fiat_p256_from_generic(z1.as_mut_ptr(), &(*point).Z);
    fiat_p256_inv_square(z2.as_mut_ptr(), z1.as_mut_ptr() as *const uint64_t);
    if !x_out.is_null() {
        let mut x: fiat_p256_felem = [0; 4];
        fiat_p256_from_generic(x.as_mut_ptr(), &(*point).X);
        fiat_p256_mul(
            x.as_mut_ptr(),
            x.as_mut_ptr() as *const uint64_t,
            z2.as_mut_ptr() as *const uint64_t,
        );
        fiat_p256_to_generic(x_out, x.as_mut_ptr() as *const uint64_t);
    }
    if !y_out.is_null() {
        let mut y: fiat_p256_felem = [0; 4];
        fiat_p256_from_generic(y.as_mut_ptr(), &(*point).Y);
        fiat_p256_square(z2.as_mut_ptr(), z2.as_mut_ptr() as *const uint64_t);
        fiat_p256_mul(
            y.as_mut_ptr(),
            y.as_mut_ptr() as *const uint64_t,
            z1.as_mut_ptr() as *const uint64_t,
        );
        fiat_p256_mul(
            y.as_mut_ptr(),
            y.as_mut_ptr() as *const uint64_t,
            z2.as_mut_ptr() as *const uint64_t,
        );
        fiat_p256_to_generic(y_out, y.as_mut_ptr() as *const uint64_t);
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn ec_GFp_nistp256_add(
    mut group: *const EC_GROUP,
    mut r: *mut EC_JACOBIAN,
    mut a: *const EC_JACOBIAN,
    mut b: *const EC_JACOBIAN,
) {
    let mut x1: fiat_p256_felem = [0; 4];
    let mut y1: fiat_p256_felem = [0; 4];
    let mut z1: fiat_p256_felem = [0; 4];
    let mut x2: fiat_p256_felem = [0; 4];
    let mut y2: fiat_p256_felem = [0; 4];
    let mut z2: fiat_p256_felem = [0; 4];
    fiat_p256_from_generic(x1.as_mut_ptr(), &(*a).X);
    fiat_p256_from_generic(y1.as_mut_ptr(), &(*a).Y);
    fiat_p256_from_generic(z1.as_mut_ptr(), &(*a).Z);
    fiat_p256_from_generic(x2.as_mut_ptr(), &(*b).X);
    fiat_p256_from_generic(y2.as_mut_ptr(), &(*b).Y);
    fiat_p256_from_generic(z2.as_mut_ptr(), &(*b).Z);
    fiat_p256_point_add(
        x1.as_mut_ptr(),
        y1.as_mut_ptr(),
        z1.as_mut_ptr(),
        x1.as_mut_ptr() as *const uint64_t,
        y1.as_mut_ptr() as *const uint64_t,
        z1.as_mut_ptr() as *const uint64_t,
        0 as libc::c_int,
        x2.as_mut_ptr() as *const uint64_t,
        y2.as_mut_ptr() as *const uint64_t,
        z2.as_mut_ptr() as *const uint64_t,
    );
    fiat_p256_to_generic(&mut (*r).X, x1.as_mut_ptr() as *const uint64_t);
    fiat_p256_to_generic(&mut (*r).Y, y1.as_mut_ptr() as *const uint64_t);
    fiat_p256_to_generic(&mut (*r).Z, z1.as_mut_ptr() as *const uint64_t);
}
unsafe extern "C" fn ec_GFp_nistp256_dbl(
    mut group: *const EC_GROUP,
    mut r: *mut EC_JACOBIAN,
    mut a: *const EC_JACOBIAN,
) {
    let mut x: fiat_p256_felem = [0; 4];
    let mut y: fiat_p256_felem = [0; 4];
    let mut z: fiat_p256_felem = [0; 4];
    fiat_p256_from_generic(x.as_mut_ptr(), &(*a).X);
    fiat_p256_from_generic(y.as_mut_ptr(), &(*a).Y);
    fiat_p256_from_generic(z.as_mut_ptr(), &(*a).Z);
    fiat_p256_point_double(
        x.as_mut_ptr(),
        y.as_mut_ptr(),
        z.as_mut_ptr(),
        x.as_mut_ptr() as *const uint64_t,
        y.as_mut_ptr() as *const uint64_t,
        z.as_mut_ptr() as *const uint64_t,
    );
    fiat_p256_to_generic(&mut (*r).X, x.as_mut_ptr() as *const uint64_t);
    fiat_p256_to_generic(&mut (*r).Y, y.as_mut_ptr() as *const uint64_t);
    fiat_p256_to_generic(&mut (*r).Z, z.as_mut_ptr() as *const uint64_t);
}
unsafe extern "C" fn ec_GFp_nistp256_point_mul(
    mut group: *const EC_GROUP,
    mut r: *mut EC_JACOBIAN,
    mut p: *const EC_JACOBIAN,
    mut scalar: *const EC_SCALAR,
) {
    let mut res: [fiat_p256_felem; 3] = [[0; 4]; 3];
    let mut tmp: [fiat_p256_felem; 3] = [[0; 4]; 3];
    fiat_p256_from_generic((tmp[0 as libc::c_int as usize]).as_mut_ptr(), &(*p).X);
    fiat_p256_from_generic((tmp[1 as libc::c_int as usize]).as_mut_ptr(), &(*p).Y);
    fiat_p256_from_generic((tmp[2 as libc::c_int as usize]).as_mut_ptr(), &(*p).Z);
    ec_nistp_scalar_mul(
        p256_methods(),
        (res[0 as libc::c_int as usize]).as_mut_ptr(),
        (res[1 as libc::c_int as usize]).as_mut_ptr(),
        (res[2 as libc::c_int as usize]).as_mut_ptr(),
        (tmp[0 as libc::c_int as usize]).as_mut_ptr(),
        (tmp[1 as libc::c_int as usize]).as_mut_ptr(),
        (tmp[2 as libc::c_int as usize]).as_mut_ptr(),
        scalar,
    );
    fiat_p256_to_generic(
        &mut (*r).X,
        (res[0 as libc::c_int as usize]).as_mut_ptr() as *const uint64_t,
    );
    fiat_p256_to_generic(
        &mut (*r).Y,
        (res[1 as libc::c_int as usize]).as_mut_ptr() as *const uint64_t,
    );
    fiat_p256_to_generic(
        &mut (*r).Z,
        (res[2 as libc::c_int as usize]).as_mut_ptr() as *const uint64_t,
    );
}
unsafe extern "C" fn ec_GFp_nistp256_point_mul_base(
    mut group: *const EC_GROUP,
    mut r: *mut EC_JACOBIAN,
    mut scalar: *const EC_SCALAR,
) {
    let mut res: [fiat_p256_felem; 3] = [[0; 4]; 3];
    ec_nistp_scalar_mul_base(
        p256_methods(),
        (res[0 as libc::c_int as usize]).as_mut_ptr(),
        (res[1 as libc::c_int as usize]).as_mut_ptr(),
        (res[2 as libc::c_int as usize]).as_mut_ptr(),
        scalar,
    );
    fiat_p256_to_generic(
        &mut (*r).X,
        (res[0 as libc::c_int as usize]).as_mut_ptr() as *const uint64_t,
    );
    fiat_p256_to_generic(
        &mut (*r).Y,
        (res[1 as libc::c_int as usize]).as_mut_ptr() as *const uint64_t,
    );
    fiat_p256_to_generic(
        &mut (*r).Z,
        (res[2 as libc::c_int as usize]).as_mut_ptr() as *const uint64_t,
    );
}
unsafe extern "C" fn ec_GFp_nistp256_point_mul_public(
    mut group: *const EC_GROUP,
    mut r: *mut EC_JACOBIAN,
    mut g_scalar: *const EC_SCALAR,
    mut p: *const EC_JACOBIAN,
    mut p_scalar: *const EC_SCALAR,
) {
    let mut res: [fiat_p256_felem; 3] = [[0; 4]; 3];
    let mut tmp: [fiat_p256_felem; 3] = [[0; 4]; 3];
    fiat_p256_from_generic((tmp[0 as libc::c_int as usize]).as_mut_ptr(), &(*p).X);
    fiat_p256_from_generic((tmp[1 as libc::c_int as usize]).as_mut_ptr(), &(*p).Y);
    fiat_p256_from_generic((tmp[2 as libc::c_int as usize]).as_mut_ptr(), &(*p).Z);
    ec_nistp_scalar_mul_public(
        p256_methods(),
        (res[0 as libc::c_int as usize]).as_mut_ptr(),
        (res[1 as libc::c_int as usize]).as_mut_ptr(),
        (res[2 as libc::c_int as usize]).as_mut_ptr(),
        g_scalar,
        (tmp[0 as libc::c_int as usize]).as_mut_ptr(),
        (tmp[1 as libc::c_int as usize]).as_mut_ptr(),
        (tmp[2 as libc::c_int as usize]).as_mut_ptr(),
        p_scalar,
    );
    fiat_p256_to_generic(
        &mut (*r).X,
        (res[0 as libc::c_int as usize]).as_mut_ptr() as *const uint64_t,
    );
    fiat_p256_to_generic(
        &mut (*r).Y,
        (res[1 as libc::c_int as usize]).as_mut_ptr() as *const uint64_t,
    );
    fiat_p256_to_generic(
        &mut (*r).Z,
        (res[2 as libc::c_int as usize]).as_mut_ptr() as *const uint64_t,
    );
}
unsafe extern "C" fn ec_GFp_nistp256_cmp_x_coordinate(
    mut group: *const EC_GROUP,
    mut p: *const EC_JACOBIAN,
    mut r: *const EC_SCALAR,
) -> libc::c_int {
    if ec_GFp_simple_is_at_infinity(group, p) != 0 {
        return 0 as libc::c_int;
    }
    let mut Z2_mont: fiat_p256_felem = [0; 4];
    fiat_p256_from_generic(Z2_mont.as_mut_ptr(), &(*p).Z);
    fiat_p256_mul(
        Z2_mont.as_mut_ptr(),
        Z2_mont.as_mut_ptr() as *const uint64_t,
        Z2_mont.as_mut_ptr() as *const uint64_t,
    );
    let mut r_Z2: fiat_p256_felem = [0; 4];
    fiat_p256_from_words(r_Z2.as_mut_ptr(), ((*r).words).as_ptr());
    fiat_p256_mul(
        r_Z2.as_mut_ptr(),
        r_Z2.as_mut_ptr() as *const uint64_t,
        Z2_mont.as_mut_ptr() as *const uint64_t,
    );
    let mut X: fiat_p256_felem = [0; 4];
    fiat_p256_from_generic(X.as_mut_ptr(), &(*p).X);
    fiat_p256_from_montgomery(X.as_mut_ptr(), X.as_mut_ptr() as *const uint64_t);
    if OPENSSL_memcmp(
        &mut r_Z2 as *mut fiat_p256_felem as *const libc::c_void,
        &mut X as *mut fiat_p256_felem as *const libc::c_void,
        ::core::mem::size_of::<fiat_p256_felem>() as libc::c_ulong,
    ) == 0 as libc::c_int
    {
        return 1 as libc::c_int;
    }
    if (*group).field.N.width == (*group).order.N.width {} else {
        __assert_fail(
            b"group->field.N.width == group->order.N.width\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/p256.c\0"
                as *const u8 as *const libc::c_char,
            330 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 95],
                &[libc::c_char; 95],
            >(
                b"int ec_GFp_nistp256_cmp_x_coordinate(const EC_GROUP *, const EC_JACOBIAN *, const EC_SCALAR *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_11020: {
        if (*group).field.N.width == (*group).order.N.width {} else {
            __assert_fail(
                b"group->field.N.width == group->order.N.width\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/p256.c\0"
                    as *const u8 as *const libc::c_char,
                330 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 95],
                    &[libc::c_char; 95],
                >(
                    b"int ec_GFp_nistp256_cmp_x_coordinate(const EC_GROUP *, const EC_JACOBIAN *, const EC_SCALAR *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut tmp: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut carry: BN_ULONG = bn_add_words(
        (tmp.words).as_mut_ptr(),
        ((*r).words).as_ptr(),
        (*group).order.N.d,
        (*group).field.N.width as size_t,
    );
    if carry == 0 as libc::c_int as BN_ULONG
        && bn_less_than_words(
            (tmp.words).as_mut_ptr(),
            (*group).field.N.d,
            (*group).field.N.width as size_t,
        ) != 0
    {
        fiat_p256_from_generic(r_Z2.as_mut_ptr(), &mut tmp);
        fiat_p256_mul(
            r_Z2.as_mut_ptr(),
            r_Z2.as_mut_ptr() as *const uint64_t,
            Z2_mont.as_mut_ptr() as *const uint64_t,
        );
        if OPENSSL_memcmp(
            &mut r_Z2 as *mut fiat_p256_felem as *const libc::c_void,
            &mut X as *mut fiat_p256_felem as *const libc::c_void,
            ::core::mem::size_of::<fiat_p256_felem>() as libc::c_ulong,
        ) == 0 as libc::c_int
        {
            return 1 as libc::c_int;
        }
    }
    return 0 as libc::c_int;
}
static mut EC_GFp_nistp256_method_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EC_GFp_nistp256_method_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EC_GFp_nistp256_method_once;
}
unsafe extern "C" fn EC_GFp_nistp256_method_init() {
    EC_GFp_nistp256_method_do_init(EC_GFp_nistp256_method_storage_bss_get());
}
unsafe extern "C" fn EC_GFp_nistp256_method_do_init(mut out: *mut EC_METHOD) {
    (*out)
        .point_get_affine_coordinates = Some(
        ec_GFp_nistp256_point_get_affine_coordinates
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *const EC_JACOBIAN,
                *mut EC_FELEM,
                *mut EC_FELEM,
            ) -> libc::c_int,
    );
    (*out)
        .add = Some(
        ec_GFp_nistp256_add
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_JACOBIAN,
                *const EC_JACOBIAN,
                *const EC_JACOBIAN,
            ) -> (),
    );
    (*out)
        .dbl = Some(
        ec_GFp_nistp256_dbl
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_JACOBIAN,
                *const EC_JACOBIAN,
            ) -> (),
    );
    (*out)
        .mul = Some(
        ec_GFp_nistp256_point_mul
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_JACOBIAN,
                *const EC_JACOBIAN,
                *const EC_SCALAR,
            ) -> (),
    );
    (*out)
        .mul_base = Some(
        ec_GFp_nistp256_point_mul_base
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_JACOBIAN,
                *const EC_SCALAR,
            ) -> (),
    );
    (*out)
        .mul_public = Some(
        ec_GFp_nistp256_point_mul_public
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_JACOBIAN,
                *const EC_SCALAR,
                *const EC_JACOBIAN,
                *const EC_SCALAR,
            ) -> (),
    );
    (*out)
        .felem_mul = Some(
        ec_GFp_mont_felem_mul
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_FELEM,
                *const EC_FELEM,
                *const EC_FELEM,
            ) -> (),
    );
    (*out)
        .felem_sqr = Some(
        ec_GFp_mont_felem_sqr
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_FELEM,
                *const EC_FELEM,
            ) -> (),
    );
    (*out)
        .felem_to_bytes = Some(
        ec_GFp_mont_felem_to_bytes
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut uint8_t,
                *mut size_t,
                *const EC_FELEM,
            ) -> (),
    );
    (*out)
        .felem_from_bytes = Some(
        ec_GFp_mont_felem_from_bytes
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_FELEM,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .felem_reduce = Some(
        ec_GFp_mont_felem_reduce
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_FELEM,
                *const BN_ULONG,
                size_t,
            ) -> (),
    );
    (*out)
        .felem_exp = Some(
        ec_GFp_mont_felem_exp
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_FELEM,
                *const EC_FELEM,
                *const BN_ULONG,
                size_t,
            ) -> (),
    );
    (*out)
        .scalar_inv0_montgomery = Some(
        ec_simple_scalar_inv0_montgomery
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_SCALAR,
                *const EC_SCALAR,
            ) -> (),
    );
    (*out)
        .scalar_to_montgomery_inv_vartime = Some(
        ec_simple_scalar_to_montgomery_inv_vartime
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_SCALAR,
                *const EC_SCALAR,
            ) -> libc::c_int,
    );
    (*out)
        .cmp_x_coordinate = Some(
        ec_GFp_nistp256_cmp_x_coordinate
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *const EC_JACOBIAN,
                *const EC_SCALAR,
            ) -> libc::c_int,
    );
}
unsafe extern "C" fn EC_GFp_nistp256_method_storage_bss_get() -> *mut EC_METHOD {
    return &mut EC_GFp_nistp256_method_storage;
}
static mut EC_GFp_nistp256_method_storage: EC_METHOD = ec_method_st {
    point_get_affine_coordinates: None,
    jacobian_to_affine_batch: None,
    add: None,
    dbl: None,
    mul: None,
    mul_base: None,
    mul_batch: None,
    mul_public: None,
    mul_public_batch: None,
    init_precomp: None,
    mul_precomp: None,
    felem_mul: None,
    felem_sqr: None,
    felem_to_bytes: None,
    felem_from_bytes: None,
    felem_reduce: None,
    felem_exp: None,
    scalar_inv0_montgomery: None,
    scalar_to_montgomery_inv_vartime: None,
    cmp_x_coordinate: None,
};
#[no_mangle]
pub unsafe extern "C" fn EC_GFp_nistp256_method() -> *const EC_METHOD {
    CRYPTO_once(
        EC_GFp_nistp256_method_once_bss_get(),
        Some(EC_GFp_nistp256_method_init as unsafe extern "C" fn() -> ()),
    );
    return EC_GFp_nistp256_method_storage_bss_get() as *const EC_METHOD;
}
