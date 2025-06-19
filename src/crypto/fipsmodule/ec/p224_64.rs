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
    fn ec_GFp_simple_cmp_x_coordinate(
        group: *const EC_GROUP,
        p: *const EC_JACOBIAN,
        r: *const EC_SCALAR,
    ) -> libc::c_int;
    fn ec_GFp_simple_felem_to_bytes(
        group: *const EC_GROUP,
        out: *mut uint8_t,
        out_len: *mut size_t,
        in_0: *const EC_FELEM,
    );
    fn ec_GFp_simple_felem_from_bytes(
        group: *const EC_GROUP,
        out: *mut EC_FELEM,
        in_0: *const uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn ec_GFp_nistp_recode_scalar_bits(
        sign: *mut crypto_word_t,
        digit: *mut crypto_word_t,
        in_0: crypto_word_t,
    );
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
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn CRYPTO_once(
        once: *mut CRYPTO_once_t,
        init: Option::<unsafe extern "C" fn() -> ()>,
    );
}
pub type __uint128_t = u128;
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type int64_t = __int64_t;
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
pub type uint128_t = __uint128_t;
pub type crypto_word_t = uint64_t;
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
pub type p224_limb = uint64_t;
pub type p224_felem = [p224_limb; 4];
pub type p224_widelimb = uint128_t;
pub type p224_widefelem = [p224_widelimb; 7];
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_844_error_is_crypto_word_t_is_too_small {
    #[bitfield(
        name = "static_assertion_at_line_844_error_is_crypto_word_t_is_too_small",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_844_error_is_crypto_word_t_is_too_small: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_842_error_is_crypto_word_t_is_too_small {
    #[bitfield(
        name = "static_assertion_at_line_842_error_is_crypto_word_t_is_too_small",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_842_error_is_crypto_word_t_is_too_small: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[inline]
unsafe extern "C" fn value_barrier_w(mut a: crypto_word_t) -> crypto_word_t {
    asm!("", inlateout(reg) a, options(preserves_flags, pure, readonly, att_syntax));
    return a;
}
#[inline]
unsafe extern "C" fn value_barrier_u32(mut a: uint32_t) -> uint32_t {
    asm!("", inlateout(reg) a, options(preserves_flags, pure, readonly, att_syntax));
    return a;
}
#[inline]
unsafe extern "C" fn constant_time_msb_w(mut a: crypto_word_t) -> crypto_word_t {
    return (0 as libc::c_uint as crypto_word_t)
        .wrapping_sub(
            a
                >> (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        );
}
#[inline]
unsafe extern "C" fn constant_time_is_zero_w(mut a: crypto_word_t) -> crypto_word_t {
    return constant_time_msb_w(!a & a.wrapping_sub(1 as libc::c_int as crypto_word_t));
}
#[inline]
unsafe extern "C" fn constant_time_eq_w(
    mut a: crypto_word_t,
    mut b: crypto_word_t,
) -> crypto_word_t {
    return constant_time_is_zero_w(a ^ b);
}
#[inline]
unsafe extern "C" fn constant_time_declassify_w(mut v: crypto_word_t) -> crypto_word_t {
    return value_barrier_w(v);
}
#[inline]
unsafe extern "C" fn constant_time_declassify_int(mut v: libc::c_int) -> libc::c_int {
    return value_barrier_u32(v as uint32_t) as libc::c_int;
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
unsafe extern "C" fn OPENSSL_memset(
    mut dst: *mut libc::c_void,
    mut c: libc::c_int,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return dst;
    }
    return memset(dst, c, n);
}
static mut g_p224_pre_comp: [[[p224_felem; 3]; 16]; 2] = [
    [
        [
            [
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
            [
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
            [
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0x3280d6115c1d21 as libc::c_long as p224_limb,
                0xc1d356c2112234 as libc::c_long as p224_limb,
                0x7f321390b94a03 as libc::c_long as p224_limb,
                0xb70e0cbd6bb4bf as libc::c_long as p224_limb,
            ],
            [
                0xd5819985007e34 as libc::c_long as p224_limb,
                0x75a05a07476444 as libc::c_long as p224_limb,
                0xfb4c22dfe6cd43 as libc::c_long as p224_limb,
                0xbd376388b5f723 as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0xfd9675666ebbe9 as libc::c_long as p224_limb,
                0xbca7664d40ce5e as libc::c_long as p224_limb,
                0x2242df8d8a2a43 as libc::c_long as p224_limb,
                0x1f49bbb0f99bc5 as libc::c_long as p224_limb,
            ],
            [
                0x29e0b892dc9c43 as libc::c_long as p224_limb,
                0xece8608436e662 as libc::c_long as p224_limb,
                0xdc858f185310d0 as libc::c_long as p224_limb,
                0x9812dd4eb8d321 as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0x6d3e678d5d8eb8 as libc::c_long as p224_limb,
                0x559eed1cb362f1 as libc::c_long as p224_limb,
                0x16e9a3bbce8a3f as libc::c_long as p224_limb,
                0xeedcccd8c2a748 as libc::c_long as p224_limb,
            ],
            [
                0xf19f90ed50266d as libc::c_long as p224_limb,
                0xabf2b4bf65f9df as libc::c_long as p224_limb,
                0x313865468fafec as libc::c_long as p224_limb,
                0x5cb379ba910a17 as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0x641966cab26e3 as libc::c_long as p224_limb,
                0x91fb2991fab0a0 as libc::c_long as p224_limb,
                0xefec27a4e13a0b as libc::c_long as p224_limb,
                0x499aa8a5f8ebe as libc::c_long as p224_limb,
            ],
            [
                0x7510407766af5d as libc::c_long as p224_limb,
                0x84d929610d5450 as libc::c_long as p224_limb,
                0x81d77aae82f706 as libc::c_long as p224_limb,
                0x6916f6d4338c5b as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0xea95ac3b1f15c6 as libc::c_long as p224_limb,
                0x86000905e82d4 as libc::c_long as p224_limb,
                0xdd323ae4d1c8b1 as libc::c_long as p224_limb,
                0x932b56be7685a3 as libc::c_long as p224_limb,
            ],
            [
                0x9ef93dea25dbbf as libc::c_long as p224_limb,
                0x41665960f390f0 as libc::c_long as p224_limb,
                0xfdec76dbe2a8a7 as libc::c_long as p224_limb,
                0x523e80f019062a as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0x822fdd26732c73 as libc::c_long as p224_limb,
                0xa01c83531b5d0f as libc::c_long as p224_limb,
                0x363f37347c1ba4 as libc::c_long as p224_limb,
                0xc391b45c84725c as libc::c_long as p224_limb,
            ],
            [
                0xbbd5e1b2d6ad24 as libc::c_long as p224_limb,
                0xddfbcde19dfaec as libc::c_long as p224_limb,
                0xc393da7e222a7f as libc::c_long as p224_limb,
                0x1efb7890ede244 as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0x4c9e90ca217da1 as libc::c_long as p224_limb,
                0xd11beca79159bb as libc::c_long as p224_limb,
                0xff8d33c2c98b7c as libc::c_long as p224_limb,
                0x2610b39409f849 as libc::c_long as p224_limb,
            ],
            [
                0x44d1352ac64da0 as libc::c_long as p224_limb,
                0xcdbb7b2c46b4fb as libc::c_long as p224_limb,
                0x966c079b753c89 as libc::c_long as p224_limb,
                0xfe67e4e820b112 as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0xe28cae2df5312d as libc::c_long as p224_limb,
                0xc71b61d16f5c6e as libc::c_long as p224_limb,
                0x79b7619a3e7c4c as libc::c_long as p224_limb,
                0x5c73240899b47 as libc::c_long as p224_limb,
            ],
            [
                0x9f7f6382c73e3a as libc::c_long as p224_limb,
                0x18615165c56bda as libc::c_long as p224_limb,
                0x641fab2116fd56 as libc::c_long as p224_limb,
                0x72855882b08394 as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0x469182f161c09 as libc::c_long as p224_limb,
                0x74a98ca8d00fb5 as libc::c_long as p224_limb,
                0xb89da93489a3e0 as libc::c_long as p224_limb,
                0x41c98768fb0c1d as libc::c_long as p224_limb,
            ],
            [
                0xe5ea05fb32da81 as libc::c_long as p224_limb,
                0x3dce9ffbca6855 as libc::c_long as p224_limb,
                0x1cfe2d3fbf59e6 as libc::c_long as p224_limb,
                0xe5e03408738a7 as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0xdab22b2333e87f as libc::c_long as p224_limb,
                0x4430137a5dd2f6 as libc::c_long as p224_limb,
                0xe03ab9f738beb8 as libc::c_long as p224_limb,
                0xcb0c5d0dc34f24 as libc::c_long as p224_limb,
            ],
            [
                0x764a7df0c8fda5 as libc::c_long as p224_limb,
                0x185ba5c3fa2044 as libc::c_long as p224_limb,
                0x9281d688bcbe50 as libc::c_long as p224_limb,
                0xc40331df893881 as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0xb89530796f0f60 as libc::c_long as p224_limb,
                0xade92bd26909a3 as libc::c_long as p224_limb,
                0x1a0c83fb4884da as libc::c_long as p224_limb,
                0x1765bf22a5a984 as libc::c_long as p224_limb,
            ],
            [
                0x772a9ee75db09e as libc::c_long as p224_limb,
                0x23bc6c67cec16f as libc::c_long as p224_limb,
                0x4c1edba8b14e2f as libc::c_long as p224_limb,
                0xe2a215d9611369 as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0x571e509fb5efb3 as libc::c_long as p224_limb,
                0xade88696410552 as libc::c_long as p224_limb,
                0xc8ae85fada74fe as libc::c_long as p224_limb,
                0x6c7e4be83bbde3 as libc::c_long as p224_limb,
            ],
            [
                0xff9f51160f4652 as libc::c_long as p224_limb,
                0xb47ce2495a6539 as libc::c_long as p224_limb,
                0xa2946c53b582f4 as libc::c_long as p224_limb,
                0x286d2db3ee9a60 as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0x40bbd5081a44af as libc::c_long as p224_limb,
                0x995183b13926c as libc::c_long as p224_limb,
                0xbcefba6f47f6d0 as libc::c_long as p224_limb,
                0x215619e9cc0057 as libc::c_long as p224_limb,
            ],
            [
                0x8bc94d3b0df45e as libc::c_long as p224_limb,
                0xf11c54a3694f6f as libc::c_long as p224_limb,
                0x8631b93cdfe8b5 as libc::c_long as p224_limb,
                0xe7e3f4b0982db9 as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0xb17048ab3e1c7b as libc::c_long as p224_limb,
                0xac38f36ff8a1d8 as libc::c_long as p224_limb,
                0x1c29819435d2c6 as libc::c_long as p224_limb,
                0xc813132f4c07e9 as libc::c_long as p224_limb,
            ],
            [
                0x2891425503b11f as libc::c_long as p224_limb,
                0x8781030579fea as libc::c_long as p224_limb,
                0xf5426ba5cc9674 as libc::c_long as p224_limb,
                0x1e28ebf18562bc as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0x9f31997cc864eb as libc::c_long as p224_limb,
                0x6cd91d28b5e4c as libc::c_long as p224_limb,
                0xff17036691a973 as libc::c_long as p224_limb,
                0xf1aef351497c58 as libc::c_long as p224_limb,
            ],
            [
                0xdd1f2d600564ff as libc::c_long as p224_limb,
                0xdead073b1402db as libc::c_long as p224_limb,
                0x74a684435bd693 as libc::c_long as p224_limb,
                0xeea7471f962558 as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
    ],
    [
        [
            [
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
            [
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
            [
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0x9665266dddf554 as libc::c_long as p224_limb,
                0x9613d78b60ef2d as libc::c_long as p224_limb,
                0xce27a34cdba417 as libc::c_long as p224_limb,
                0xd35ab74d6afc31 as libc::c_long as p224_limb,
            ],
            [
                0x85ccdd22deb15e as libc::c_long as p224_limb,
                0x2137e5783a6aab as libc::c_long as p224_limb,
                0xa141cffd8c93c6 as libc::c_long as p224_limb,
                0x355a1830e90f2d as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0x1a494eadaade65 as libc::c_long as p224_limb,
                0xd6da4da77fe53c as libc::c_long as p224_limb,
                0xe7992996abec86 as libc::c_long as p224_limb,
                0x65c3553c6090e3 as libc::c_long as p224_limb,
            ],
            [
                0xfa610b1fb09346 as libc::c_long as p224_limb,
                0xf1c6540b8a4aaf as libc::c_long as p224_limb,
                0xc51a13ccd3cbab as libc::c_long as p224_limb,
                0x2995b1b18c28a as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0x7874568e7295ef as libc::c_long as p224_limb,
                0x86b419fbe38d04 as libc::c_long as p224_limb,
                0xdc0690a7550d9a as libc::c_long as p224_limb,
                0xd3966a44beac33 as libc::c_long as p224_limb,
            ],
            [
                0x2b7280ec29132f as libc::c_long as p224_limb,
                0xbeaa3b6a032df3 as libc::c_long as p224_limb,
                0xdc7dd88ae41200 as libc::c_long as p224_limb,
                0xd25e2513e3a100 as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0x924857eb2efafd as libc::c_long as p224_limb,
                0xac2bce41223190 as libc::c_long as p224_limb,
                0x8edaa1445553fc as libc::c_long as p224_limb,
                0x825800fd3562d5 as libc::c_long as p224_limb,
            ],
            [
                0x8d79148ea96621 as libc::c_long as p224_limb,
                0x23a01c3dd9ed8d as libc::c_long as p224_limb,
                0xaf8b219f9416b5 as libc::c_long as p224_limb,
                0xd8db0cc277daea as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0x76a9c3b1a700f0 as libc::c_long as p224_limb,
                0xe9acd29bc7e691 as libc::c_long as p224_limb,
                0x69212d1a6b0327 as libc::c_long as p224_limb,
                0x6322e97fe154be as libc::c_long as p224_limb,
            ],
            [
                0x469fc5465d62aa as libc::c_long as p224_limb,
                0x8d41ed18883b05 as libc::c_long as p224_limb,
                0x1f8eae66c52b88 as libc::c_long as p224_limb,
                0xe4fcbe9325be51 as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0x825fdf583cac16 as libc::c_long as p224_limb,
                0x20b857c7b023a as libc::c_long as p224_limb,
                0x683c17744b0165 as libc::c_long as p224_limb,
                0x14ffd0a2daf2f1 as libc::c_long as p224_limb,
            ],
            [
                0x323b36184218f9 as libc::c_long as p224_limb,
                0x4944ec4e3b47d4 as libc::c_long as p224_limb,
                0xc15b3080841acf as libc::c_long as p224_limb,
                0xbced4b01a28bb as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0x92ac22230df5c4 as libc::c_long as p224_limb,
                0x52f33b4063eda8 as libc::c_long as p224_limb,
                0xcb3f19870c0c93 as libc::c_long as p224_limb,
                0x40064f2ba65233 as libc::c_long as p224_limb,
            ],
            [
                0xfe16f0924f8992 as libc::c_long as p224_limb,
                0x12da25af5b517 as libc::c_long as p224_limb,
                0x1a57bb24f723a6 as libc::c_long as p224_limb,
                0x6f8bc76760def as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0x4a7084f7817cb9 as libc::c_long as p224_limb,
                0xbcab0738ee9a78 as libc::c_long as p224_limb,
                0x3ec11e11d9c326 as libc::c_long as p224_limb,
                0xdc0fe90e0f1aae as libc::c_long as p224_limb,
            ],
            [
                0xcf639ea5f98390 as libc::c_long as p224_limb,
                0x5c350aa22ffb74 as libc::c_long as p224_limb,
                0x9afae98a4047b7 as libc::c_long as p224_limb,
                0x956ec2d617fc45 as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0x4306d648c1be6a as libc::c_long as p224_limb,
                0x9247cd8bc9a462 as libc::c_long as p224_limb,
                0xf5595e377d2f2e as libc::c_long as p224_limb,
                0xbd1c3caff1a52e as libc::c_long as p224_limb,
            ],
            [
                0x45e14472409d0 as libc::c_long as p224_limb,
                0x29f3e17078f773 as libc::c_long as p224_limb,
                0x745a602b2d4f7d as libc::c_long as p224_limb,
                0x191837685cdfbb as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0x5b6ee254a8cb79 as libc::c_long as p224_limb,
                0x4953433f5e7026 as libc::c_long as p224_limb,
                0xe21faeb1d1def4 as libc::c_long as p224_limb,
                0xc4c225785c09de as libc::c_long as p224_limb,
            ],
            [
                0x307ce7bba1e518 as libc::c_long as p224_limb,
                0x31b125b1036db8 as libc::c_long as p224_limb,
                0x47e91868839e8f as libc::c_long as p224_limb,
                0xc765866e33b9f3 as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0x3bfece24f96906 as libc::c_long as p224_limb,
                0x4794da641e5093 as libc::c_long as p224_limb,
                0xde5df64f95db26 as libc::c_long as p224_limb,
                0x297ecd89714b05 as libc::c_long as p224_limb,
            ],
            [
                0x701bd3ebb2c3aa as libc::c_long as p224_limb,
                0x7073b4f53cb1d5 as libc::c_long as p224_limb,
                0x13c5665658af16 as libc::c_long as p224_limb,
                0x9895089d66fe58 as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0xfef05f78c4790 as libc::c_long as p224_limb,
                0x2d773633b05d2e as libc::c_long as p224_limb,
                0x94229c3a951c94 as libc::c_long as p224_limb,
                0xbbbd70df4911bb as libc::c_long as p224_limb,
            ],
            [
                0xb2c6963d2c1168 as libc::c_long as p224_limb,
                0x105f47a72b0d73 as libc::c_long as p224_limb,
                0x9fdf6111614080 as libc::c_long as p224_limb,
                0x7b7e94b39e67b0 as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0xad1a7d6efbe2b3 as libc::c_long as p224_limb,
                0xf012482c0da69d as libc::c_long as p224_limb,
                0x6b3bdf12438345 as libc::c_long as p224_limb,
                0x40d7558d7aa4d9 as libc::c_long as p224_limb,
            ],
            [
                0x8a09fffb5c6d3d as libc::c_long as p224_limb,
                0x9a356e5d9ffd38 as libc::c_long as p224_limb,
                0x5973f15f4f9b1c as libc::c_long as p224_limb,
                0xdcd5f59f63c3ea as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0xacf39f4c5ca7ab as libc::c_long as p224_limb,
                0x4c8071cc5fd737 as libc::c_long as p224_limb,
                0xc64e3602cd1184 as libc::c_long as p224_limb,
                0xacd4644c9abba as libc::c_long as p224_limb,
            ],
            [
                0x6c011a36d8bf6e as libc::c_long as p224_limb,
                0xfecd87ba24e32a as libc::c_long as p224_limb,
                0x19f6f56574fad8 as libc::c_long as p224_limb,
                0x50b204ced9405 as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
        [
            [
                0xed4f1cae7d9a96 as libc::c_long as p224_limb,
                0x5ceef7ad94c40a as libc::c_long as p224_limb,
                0x778e4a3bf3ef9b as libc::c_long as p224_limb,
                0x7405783dc3b55e as libc::c_long as p224_limb,
            ],
            [
                0x32477c61b6e8c6 as libc::c_long as p224_limb,
                0xb46a97570f018b as libc::c_long as p224_limb,
                0x91176d0a7e95d1 as libc::c_long as p224_limb,
                0x3df90fbc4c7d0e as libc::c_long as p224_limb,
            ],
            [
                1 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
                0 as libc::c_int as p224_limb,
            ],
        ],
    ],
];
unsafe extern "C" fn p224_generic_to_felem(
    mut out: *mut p224_limb,
    mut in_0: *const EC_FELEM,
) {
    *out
        .offset(
            0 as libc::c_int as isize,
        ) = (*in_0).words[0 as libc::c_int as usize]
        & 0xffffffffffffff as libc::c_long as BN_ULONG;
    *out
        .offset(
            1 as libc::c_int as isize,
        ) = ((*in_0).words[0 as libc::c_int as usize] >> 56 as libc::c_int
        | (*in_0).words[1 as libc::c_int as usize] << 8 as libc::c_int)
        & 0xffffffffffffff as libc::c_long as BN_ULONG;
    *out
        .offset(
            2 as libc::c_int as isize,
        ) = ((*in_0).words[1 as libc::c_int as usize] >> 48 as libc::c_int
        | (*in_0).words[2 as libc::c_int as usize] << 16 as libc::c_int)
        & 0xffffffffffffff as libc::c_long as BN_ULONG;
    *out
        .offset(
            3 as libc::c_int as isize,
        ) = ((*in_0).words[2 as libc::c_int as usize] >> 40 as libc::c_int
        | (*in_0).words[3 as libc::c_int as usize] << 24 as libc::c_int)
        & 0xffffffffffffff as libc::c_long as BN_ULONG;
}
unsafe extern "C" fn p224_felem_to_generic(
    mut out: *mut EC_FELEM,
    mut in_0: *const p224_limb,
) {
    static mut two56: int64_t = ((1 as libc::c_int as p224_limb) << 56 as libc::c_int)
        as int64_t;
    let mut tmp: [int64_t; 4] = [0; 4];
    let mut a: int64_t = 0;
    tmp[0 as libc::c_int as usize] = *in_0.offset(0 as libc::c_int as isize) as int64_t;
    tmp[1 as libc::c_int as usize] = *in_0.offset(1 as libc::c_int as isize) as int64_t;
    tmp[2 as libc::c_int as usize] = *in_0.offset(2 as libc::c_int as isize) as int64_t;
    tmp[3 as libc::c_int as usize] = *in_0.offset(3 as libc::c_int as isize) as int64_t;
    a = (*in_0.offset(3 as libc::c_int as isize) >> 56 as libc::c_int) as int64_t;
    tmp[0 as libc::c_int as usize] -= a;
    tmp[1 as libc::c_int as usize] += a << 40 as libc::c_int;
    tmp[3 as libc::c_int as usize] &= 0xffffffffffffff as libc::c_long;
    a = ((*in_0.offset(3 as libc::c_int as isize)
        & *in_0.offset(2 as libc::c_int as isize)
        & (*in_0.offset(1 as libc::c_int as isize)
            | 0xffffffffff as libc::c_long as p224_limb))
        .wrapping_add(1 as libc::c_int as p224_limb)
        | ((*in_0.offset(0 as libc::c_int as isize))
            .wrapping_add(
                *in_0.offset(1 as libc::c_int as isize)
                    & 0xffffffffff as libc::c_long as p224_limb,
            ) as int64_t - 1 as libc::c_int as int64_t >> 63 as libc::c_int)
            as p224_limb) as int64_t;
    a &= 0xffffffffffffff as libc::c_long;
    a = a - 1 as libc::c_int as int64_t >> 63 as libc::c_int;
    tmp[3 as libc::c_int
        as usize] = (tmp[3 as libc::c_int as usize] as libc::c_ulong
        & (a as libc::c_ulong ^ 0xffffffffffffffff as libc::c_ulong)) as int64_t;
    tmp[2 as libc::c_int
        as usize] = (tmp[2 as libc::c_int as usize] as libc::c_ulong
        & (a as libc::c_ulong ^ 0xffffffffffffffff as libc::c_ulong)) as int64_t;
    tmp[1 as libc::c_int
        as usize] = (tmp[1 as libc::c_int as usize] as libc::c_ulong
        & (a as libc::c_ulong ^ 0xffffffffffffffff as libc::c_ulong
            | 0xffffffffff as libc::c_long as libc::c_ulong)) as int64_t;
    tmp[0 as libc::c_int as usize] -= 1 as libc::c_int as int64_t & a;
    a = tmp[0 as libc::c_int as usize] >> 63 as libc::c_int;
    tmp[0 as libc::c_int as usize] += two56 & a;
    tmp[1 as libc::c_int as usize] -= 1 as libc::c_int as int64_t & a;
    tmp[2 as libc::c_int as usize]
        += tmp[1 as libc::c_int as usize] >> 56 as libc::c_int;
    tmp[1 as libc::c_int as usize] &= 0xffffffffffffff as libc::c_long;
    tmp[3 as libc::c_int as usize]
        += tmp[2 as libc::c_int as usize] >> 56 as libc::c_int;
    tmp[2 as libc::c_int as usize] &= 0xffffffffffffff as libc::c_long;
    let mut tmp2: p224_felem = [0; 4];
    tmp2[0 as libc::c_int as usize] = tmp[0 as libc::c_int as usize] as p224_limb;
    tmp2[1 as libc::c_int as usize] = tmp[1 as libc::c_int as usize] as p224_limb;
    tmp2[2 as libc::c_int as usize] = tmp[2 as libc::c_int as usize] as p224_limb;
    tmp2[3 as libc::c_int as usize] = tmp[3 as libc::c_int as usize] as p224_limb;
    (*out)
        .words[0 as libc::c_int
        as usize] = tmp2[0 as libc::c_int as usize]
        | tmp2[1 as libc::c_int as usize] << 56 as libc::c_int;
    (*out)
        .words[1 as libc::c_int
        as usize] = tmp2[1 as libc::c_int as usize] >> 8 as libc::c_int
        | tmp2[2 as libc::c_int as usize] << 48 as libc::c_int;
    (*out)
        .words[2 as libc::c_int
        as usize] = tmp2[2 as libc::c_int as usize] >> 16 as libc::c_int
        | tmp2[3 as libc::c_int as usize] << 40 as libc::c_int;
    (*out)
        .words[3 as libc::c_int
        as usize] = tmp2[3 as libc::c_int as usize] >> 24 as libc::c_int;
}
unsafe extern "C" fn p224_felem_assign(
    mut out: *mut p224_limb,
    mut in_0: *const p224_limb,
) {
    *out.offset(0 as libc::c_int as isize) = *in_0.offset(0 as libc::c_int as isize);
    *out.offset(1 as libc::c_int as isize) = *in_0.offset(1 as libc::c_int as isize);
    *out.offset(2 as libc::c_int as isize) = *in_0.offset(2 as libc::c_int as isize);
    *out.offset(3 as libc::c_int as isize) = *in_0.offset(3 as libc::c_int as isize);
}
unsafe extern "C" fn p224_felem_sum(
    mut out: *mut p224_limb,
    mut in_0: *const p224_limb,
) {
    let ref mut fresh0 = *out.offset(0 as libc::c_int as isize);
    *fresh0 = (*fresh0).wrapping_add(*in_0.offset(0 as libc::c_int as isize));
    let ref mut fresh1 = *out.offset(1 as libc::c_int as isize);
    *fresh1 = (*fresh1).wrapping_add(*in_0.offset(1 as libc::c_int as isize));
    let ref mut fresh2 = *out.offset(2 as libc::c_int as isize);
    *fresh2 = (*fresh2).wrapping_add(*in_0.offset(2 as libc::c_int as isize));
    let ref mut fresh3 = *out.offset(3 as libc::c_int as isize);
    *fresh3 = (*fresh3).wrapping_add(*in_0.offset(3 as libc::c_int as isize));
}
static mut two58p2: p224_limb = 0;
static mut two58m2: p224_limb = 0;
static mut two58m42m2: p224_limb = 0;
unsafe extern "C" fn p224_felem_diff(
    mut out: *mut p224_limb,
    mut in_0: *const p224_limb,
) {
    let ref mut fresh4 = *out.offset(0 as libc::c_int as isize);
    *fresh4 = (*fresh4).wrapping_add(two58p2);
    let ref mut fresh5 = *out.offset(1 as libc::c_int as isize);
    *fresh5 = (*fresh5).wrapping_add(two58m42m2);
    let ref mut fresh6 = *out.offset(2 as libc::c_int as isize);
    *fresh6 = (*fresh6).wrapping_add(two58m2);
    let ref mut fresh7 = *out.offset(3 as libc::c_int as isize);
    *fresh7 = (*fresh7).wrapping_add(two58m2);
    let ref mut fresh8 = *out.offset(0 as libc::c_int as isize);
    *fresh8 = (*fresh8).wrapping_sub(*in_0.offset(0 as libc::c_int as isize));
    let ref mut fresh9 = *out.offset(1 as libc::c_int as isize);
    *fresh9 = (*fresh9).wrapping_sub(*in_0.offset(1 as libc::c_int as isize));
    let ref mut fresh10 = *out.offset(2 as libc::c_int as isize);
    *fresh10 = (*fresh10).wrapping_sub(*in_0.offset(2 as libc::c_int as isize));
    let ref mut fresh11 = *out.offset(3 as libc::c_int as isize);
    *fresh11 = (*fresh11).wrapping_sub(*in_0.offset(3 as libc::c_int as isize));
}
static mut two120m64: p224_widelimb = 0;
static mut two120m104m64: p224_widelimb = 0;
unsafe extern "C" fn p224_widefelem_diff(
    mut out: *mut p224_widelimb,
    mut in_0: *const p224_widelimb,
) {
    static mut two120: p224_widelimb = (1 as libc::c_int as p224_widelimb)
        << 120 as libc::c_int;
    let ref mut fresh12 = *out.offset(0 as libc::c_int as isize);
    *fresh12 = (*fresh12).wrapping_add(two120);
    let ref mut fresh13 = *out.offset(1 as libc::c_int as isize);
    *fresh13 = (*fresh13).wrapping_add(two120m64);
    let ref mut fresh14 = *out.offset(2 as libc::c_int as isize);
    *fresh14 = (*fresh14).wrapping_add(two120m64);
    let ref mut fresh15 = *out.offset(3 as libc::c_int as isize);
    *fresh15 = (*fresh15).wrapping_add(two120);
    let ref mut fresh16 = *out.offset(4 as libc::c_int as isize);
    *fresh16 = (*fresh16).wrapping_add(two120m104m64);
    let ref mut fresh17 = *out.offset(5 as libc::c_int as isize);
    *fresh17 = (*fresh17).wrapping_add(two120m64);
    let ref mut fresh18 = *out.offset(6 as libc::c_int as isize);
    *fresh18 = (*fresh18).wrapping_add(two120m64);
    let ref mut fresh19 = *out.offset(0 as libc::c_int as isize);
    *fresh19 = (*fresh19).wrapping_sub(*in_0.offset(0 as libc::c_int as isize));
    let ref mut fresh20 = *out.offset(1 as libc::c_int as isize);
    *fresh20 = (*fresh20).wrapping_sub(*in_0.offset(1 as libc::c_int as isize));
    let ref mut fresh21 = *out.offset(2 as libc::c_int as isize);
    *fresh21 = (*fresh21).wrapping_sub(*in_0.offset(2 as libc::c_int as isize));
    let ref mut fresh22 = *out.offset(3 as libc::c_int as isize);
    *fresh22 = (*fresh22).wrapping_sub(*in_0.offset(3 as libc::c_int as isize));
    let ref mut fresh23 = *out.offset(4 as libc::c_int as isize);
    *fresh23 = (*fresh23).wrapping_sub(*in_0.offset(4 as libc::c_int as isize));
    let ref mut fresh24 = *out.offset(5 as libc::c_int as isize);
    *fresh24 = (*fresh24).wrapping_sub(*in_0.offset(5 as libc::c_int as isize));
    let ref mut fresh25 = *out.offset(6 as libc::c_int as isize);
    *fresh25 = (*fresh25).wrapping_sub(*in_0.offset(6 as libc::c_int as isize));
}
static mut two64p8: p224_widelimb = 0;
static mut two64m8: p224_widelimb = 0;
static mut two64m48m8: p224_widelimb = 0;
unsafe extern "C" fn p224_felem_diff_128_64(
    mut out: *mut p224_widelimb,
    mut in_0: *const p224_limb,
) {
    let ref mut fresh26 = *out.offset(0 as libc::c_int as isize);
    *fresh26 = (*fresh26).wrapping_add(two64p8);
    let ref mut fresh27 = *out.offset(1 as libc::c_int as isize);
    *fresh27 = (*fresh27).wrapping_add(two64m48m8);
    let ref mut fresh28 = *out.offset(2 as libc::c_int as isize);
    *fresh28 = (*fresh28).wrapping_add(two64m8);
    let ref mut fresh29 = *out.offset(3 as libc::c_int as isize);
    *fresh29 = (*fresh29).wrapping_add(two64m8);
    let ref mut fresh30 = *out.offset(0 as libc::c_int as isize);
    *fresh30 = (*fresh30)
        .wrapping_sub(*in_0.offset(0 as libc::c_int as isize) as p224_widelimb);
    let ref mut fresh31 = *out.offset(1 as libc::c_int as isize);
    *fresh31 = (*fresh31)
        .wrapping_sub(*in_0.offset(1 as libc::c_int as isize) as p224_widelimb);
    let ref mut fresh32 = *out.offset(2 as libc::c_int as isize);
    *fresh32 = (*fresh32)
        .wrapping_sub(*in_0.offset(2 as libc::c_int as isize) as p224_widelimb);
    let ref mut fresh33 = *out.offset(3 as libc::c_int as isize);
    *fresh33 = (*fresh33)
        .wrapping_sub(*in_0.offset(3 as libc::c_int as isize) as p224_widelimb);
}
unsafe extern "C" fn p224_felem_scalar(mut out: *mut p224_limb, scalar: p224_limb) {
    let ref mut fresh34 = *out.offset(0 as libc::c_int as isize);
    *fresh34 = *fresh34 * scalar;
    let ref mut fresh35 = *out.offset(1 as libc::c_int as isize);
    *fresh35 = *fresh35 * scalar;
    let ref mut fresh36 = *out.offset(2 as libc::c_int as isize);
    *fresh36 = *fresh36 * scalar;
    let ref mut fresh37 = *out.offset(3 as libc::c_int as isize);
    *fresh37 = *fresh37 * scalar;
}
unsafe extern "C" fn p224_widefelem_scalar(
    mut out: *mut p224_widelimb,
    scalar: p224_widelimb,
) {
    let ref mut fresh38 = *out.offset(0 as libc::c_int as isize);
    *fresh38 = *fresh38 * scalar;
    let ref mut fresh39 = *out.offset(1 as libc::c_int as isize);
    *fresh39 = *fresh39 * scalar;
    let ref mut fresh40 = *out.offset(2 as libc::c_int as isize);
    *fresh40 = *fresh40 * scalar;
    let ref mut fresh41 = *out.offset(3 as libc::c_int as isize);
    *fresh41 = *fresh41 * scalar;
    let ref mut fresh42 = *out.offset(4 as libc::c_int as isize);
    *fresh42 = *fresh42 * scalar;
    let ref mut fresh43 = *out.offset(5 as libc::c_int as isize);
    *fresh43 = *fresh43 * scalar;
    let ref mut fresh44 = *out.offset(6 as libc::c_int as isize);
    *fresh44 = *fresh44 * scalar;
}
unsafe extern "C" fn p224_felem_square(
    mut out: *mut p224_widelimb,
    mut in_0: *const p224_limb,
) {
    let mut tmp0: p224_limb = 0;
    let mut tmp1: p224_limb = 0;
    let mut tmp2: p224_limb = 0;
    tmp0 = 2 as libc::c_int as p224_limb * *in_0.offset(0 as libc::c_int as isize);
    tmp1 = 2 as libc::c_int as p224_limb * *in_0.offset(1 as libc::c_int as isize);
    tmp2 = 2 as libc::c_int as p224_limb * *in_0.offset(2 as libc::c_int as isize);
    *out
        .offset(
            0 as libc::c_int as isize,
        ) = *in_0.offset(0 as libc::c_int as isize) as p224_widelimb
        * *in_0.offset(0 as libc::c_int as isize) as p224_widelimb;
    *out
        .offset(
            1 as libc::c_int as isize,
        ) = *in_0.offset(0 as libc::c_int as isize) as p224_widelimb
        * tmp1 as p224_widelimb;
    *out
        .offset(
            2 as libc::c_int as isize,
        ) = (*in_0.offset(0 as libc::c_int as isize) as p224_widelimb
        * tmp2 as p224_widelimb)
        .wrapping_add(
            *in_0.offset(1 as libc::c_int as isize) as p224_widelimb
                * *in_0.offset(1 as libc::c_int as isize) as p224_widelimb,
        );
    *out
        .offset(
            3 as libc::c_int as isize,
        ) = (*in_0.offset(3 as libc::c_int as isize) as p224_widelimb
        * tmp0 as p224_widelimb)
        .wrapping_add(
            *in_0.offset(1 as libc::c_int as isize) as p224_widelimb
                * tmp2 as p224_widelimb,
        );
    *out
        .offset(
            4 as libc::c_int as isize,
        ) = (*in_0.offset(3 as libc::c_int as isize) as p224_widelimb
        * tmp1 as p224_widelimb)
        .wrapping_add(
            *in_0.offset(2 as libc::c_int as isize) as p224_widelimb
                * *in_0.offset(2 as libc::c_int as isize) as p224_widelimb,
        );
    *out
        .offset(
            5 as libc::c_int as isize,
        ) = *in_0.offset(3 as libc::c_int as isize) as p224_widelimb
        * tmp2 as p224_widelimb;
    *out
        .offset(
            6 as libc::c_int as isize,
        ) = *in_0.offset(3 as libc::c_int as isize) as p224_widelimb
        * *in_0.offset(3 as libc::c_int as isize) as p224_widelimb;
}
unsafe extern "C" fn p224_felem_mul(
    mut out: *mut p224_widelimb,
    mut in1: *const p224_limb,
    mut in2: *const p224_limb,
) {
    *out
        .offset(
            0 as libc::c_int as isize,
        ) = *in1.offset(0 as libc::c_int as isize) as p224_widelimb
        * *in2.offset(0 as libc::c_int as isize) as p224_widelimb;
    *out
        .offset(
            1 as libc::c_int as isize,
        ) = (*in1.offset(0 as libc::c_int as isize) as p224_widelimb
        * *in2.offset(1 as libc::c_int as isize) as p224_widelimb)
        .wrapping_add(
            *in1.offset(1 as libc::c_int as isize) as p224_widelimb
                * *in2.offset(0 as libc::c_int as isize) as p224_widelimb,
        );
    *out
        .offset(
            2 as libc::c_int as isize,
        ) = (*in1.offset(0 as libc::c_int as isize) as p224_widelimb
        * *in2.offset(2 as libc::c_int as isize) as p224_widelimb)
        .wrapping_add(
            *in1.offset(1 as libc::c_int as isize) as p224_widelimb
                * *in2.offset(1 as libc::c_int as isize) as p224_widelimb,
        )
        .wrapping_add(
            *in1.offset(2 as libc::c_int as isize) as p224_widelimb
                * *in2.offset(0 as libc::c_int as isize) as p224_widelimb,
        );
    *out
        .offset(
            3 as libc::c_int as isize,
        ) = (*in1.offset(0 as libc::c_int as isize) as p224_widelimb
        * *in2.offset(3 as libc::c_int as isize) as p224_widelimb)
        .wrapping_add(
            *in1.offset(1 as libc::c_int as isize) as p224_widelimb
                * *in2.offset(2 as libc::c_int as isize) as p224_widelimb,
        )
        .wrapping_add(
            *in1.offset(2 as libc::c_int as isize) as p224_widelimb
                * *in2.offset(1 as libc::c_int as isize) as p224_widelimb,
        )
        .wrapping_add(
            *in1.offset(3 as libc::c_int as isize) as p224_widelimb
                * *in2.offset(0 as libc::c_int as isize) as p224_widelimb,
        );
    *out
        .offset(
            4 as libc::c_int as isize,
        ) = (*in1.offset(1 as libc::c_int as isize) as p224_widelimb
        * *in2.offset(3 as libc::c_int as isize) as p224_widelimb)
        .wrapping_add(
            *in1.offset(2 as libc::c_int as isize) as p224_widelimb
                * *in2.offset(2 as libc::c_int as isize) as p224_widelimb,
        )
        .wrapping_add(
            *in1.offset(3 as libc::c_int as isize) as p224_widelimb
                * *in2.offset(1 as libc::c_int as isize) as p224_widelimb,
        );
    *out
        .offset(
            5 as libc::c_int as isize,
        ) = (*in1.offset(2 as libc::c_int as isize) as p224_widelimb
        * *in2.offset(3 as libc::c_int as isize) as p224_widelimb)
        .wrapping_add(
            *in1.offset(3 as libc::c_int as isize) as p224_widelimb
                * *in2.offset(2 as libc::c_int as isize) as p224_widelimb,
        );
    *out
        .offset(
            6 as libc::c_int as isize,
        ) = *in1.offset(3 as libc::c_int as isize) as p224_widelimb
        * *in2.offset(3 as libc::c_int as isize) as p224_widelimb;
}
static mut two127p15: p224_widelimb = 0;
static mut two127m71: p224_widelimb = 0;
static mut two127m71m55: p224_widelimb = 0;
unsafe extern "C" fn p224_felem_reduce(
    mut out: *mut p224_limb,
    mut in_0: *const p224_widelimb,
) {
    let mut output: [p224_widelimb; 5] = [0; 5];
    output[0 as libc::c_int
        as usize] = (*in_0.offset(0 as libc::c_int as isize)).wrapping_add(two127p15);
    output[1 as libc::c_int
        as usize] = (*in_0.offset(1 as libc::c_int as isize)).wrapping_add(two127m71m55);
    output[2 as libc::c_int
        as usize] = (*in_0.offset(2 as libc::c_int as isize)).wrapping_add(two127m71);
    output[3 as libc::c_int as usize] = *in_0.offset(3 as libc::c_int as isize);
    output[4 as libc::c_int as usize] = *in_0.offset(4 as libc::c_int as isize);
    output[4 as libc::c_int
        as usize] = (output[4 as libc::c_int as usize])
        .wrapping_add(*in_0.offset(6 as libc::c_int as isize) >> 16 as libc::c_int);
    output[3 as libc::c_int
        as usize] = (output[3 as libc::c_int as usize])
        .wrapping_add(
            (*in_0.offset(6 as libc::c_int as isize)
                & 0xffff as libc::c_int as p224_widelimb) << 40 as libc::c_int,
        );
    output[2 as libc::c_int
        as usize] = (output[2 as libc::c_int as usize])
        .wrapping_sub(*in_0.offset(6 as libc::c_int as isize));
    output[3 as libc::c_int
        as usize] = (output[3 as libc::c_int as usize])
        .wrapping_add(*in_0.offset(5 as libc::c_int as isize) >> 16 as libc::c_int);
    output[2 as libc::c_int
        as usize] = (output[2 as libc::c_int as usize])
        .wrapping_add(
            (*in_0.offset(5 as libc::c_int as isize)
                & 0xffff as libc::c_int as p224_widelimb) << 40 as libc::c_int,
        );
    output[1 as libc::c_int
        as usize] = (output[1 as libc::c_int as usize])
        .wrapping_sub(*in_0.offset(5 as libc::c_int as isize));
    output[2 as libc::c_int
        as usize] = (output[2 as libc::c_int as usize])
        .wrapping_add(output[4 as libc::c_int as usize] >> 16 as libc::c_int);
    output[1 as libc::c_int
        as usize] = (output[1 as libc::c_int as usize])
        .wrapping_add(
            (output[4 as libc::c_int as usize] & 0xffff as libc::c_int as p224_widelimb)
                << 40 as libc::c_int,
        );
    output[0 as libc::c_int
        as usize] = (output[0 as libc::c_int as usize])
        .wrapping_sub(output[4 as libc::c_int as usize]);
    output[3 as libc::c_int
        as usize] = (output[3 as libc::c_int as usize])
        .wrapping_add(output[2 as libc::c_int as usize] >> 56 as libc::c_int);
    output[2 as libc::c_int as usize]
        &= 0xffffffffffffff as libc::c_long as p224_widelimb;
    output[4 as libc::c_int
        as usize] = output[3 as libc::c_int as usize] >> 56 as libc::c_int;
    output[3 as libc::c_int as usize]
        &= 0xffffffffffffff as libc::c_long as p224_widelimb;
    output[2 as libc::c_int
        as usize] = (output[2 as libc::c_int as usize])
        .wrapping_add(output[4 as libc::c_int as usize] >> 16 as libc::c_int);
    output[1 as libc::c_int
        as usize] = (output[1 as libc::c_int as usize])
        .wrapping_add(
            (output[4 as libc::c_int as usize] & 0xffff as libc::c_int as p224_widelimb)
                << 40 as libc::c_int,
        );
    output[0 as libc::c_int
        as usize] = (output[0 as libc::c_int as usize])
        .wrapping_sub(output[4 as libc::c_int as usize]);
    output[1 as libc::c_int
        as usize] = (output[1 as libc::c_int as usize])
        .wrapping_add(output[0 as libc::c_int as usize] >> 56 as libc::c_int);
    *out
        .offset(
            0 as libc::c_int as isize,
        ) = (output[0 as libc::c_int as usize]
        & 0xffffffffffffff as libc::c_long as p224_widelimb) as p224_limb;
    output[2 as libc::c_int
        as usize] = (output[2 as libc::c_int as usize])
        .wrapping_add(output[1 as libc::c_int as usize] >> 56 as libc::c_int);
    *out
        .offset(
            1 as libc::c_int as isize,
        ) = (output[1 as libc::c_int as usize]
        & 0xffffffffffffff as libc::c_long as p224_widelimb) as p224_limb;
    output[3 as libc::c_int
        as usize] = (output[3 as libc::c_int as usize])
        .wrapping_add(output[2 as libc::c_int as usize] >> 56 as libc::c_int);
    *out
        .offset(
            2 as libc::c_int as isize,
        ) = (output[2 as libc::c_int as usize]
        & 0xffffffffffffff as libc::c_long as p224_widelimb) as p224_limb;
    *out
        .offset(
            3 as libc::c_int as isize,
        ) = output[3 as libc::c_int as usize] as p224_limb;
}
unsafe extern "C" fn p224_felem_neg(
    mut out: *mut p224_limb,
    mut in_0: *const p224_limb,
) {
    let mut tmp: p224_widefelem = [0 as libc::c_int as p224_widelimb, 0, 0, 0, 0, 0, 0];
    p224_felem_diff_128_64(tmp.as_mut_ptr(), in_0);
    p224_felem_reduce(out, tmp.as_mut_ptr() as *const p224_widelimb);
}
unsafe extern "C" fn p224_felem_is_zero(mut in_0: *const p224_limb) -> p224_limb {
    let mut zero: p224_limb = *in_0.offset(0 as libc::c_int as isize)
        | *in_0.offset(1 as libc::c_int as isize)
        | *in_0.offset(2 as libc::c_int as isize)
        | *in_0.offset(3 as libc::c_int as isize);
    zero = (zero as int64_t - 1 as libc::c_int as int64_t >> 63 as libc::c_int
        & 1 as libc::c_int as int64_t) as p224_limb;
    let mut two224m96p1: p224_limb = *in_0.offset(0 as libc::c_int as isize)
        ^ 1 as libc::c_int as p224_limb
        | *in_0.offset(1 as libc::c_int as isize)
            ^ 0xffff0000000000 as libc::c_long as p224_limb
        | *in_0.offset(2 as libc::c_int as isize)
            ^ 0xffffffffffffff as libc::c_long as p224_limb
        | *in_0.offset(3 as libc::c_int as isize)
            ^ 0xffffffffffffff as libc::c_long as p224_limb;
    two224m96p1 = (two224m96p1 as int64_t - 1 as libc::c_int as int64_t
        >> 63 as libc::c_int & 1 as libc::c_int as int64_t) as p224_limb;
    let mut two225m97p2: p224_limb = *in_0.offset(0 as libc::c_int as isize)
        ^ 2 as libc::c_int as p224_limb
        | *in_0.offset(1 as libc::c_int as isize)
            ^ 0xfffe0000000000 as libc::c_long as p224_limb
        | *in_0.offset(2 as libc::c_int as isize)
            ^ 0xffffffffffffff as libc::c_long as p224_limb
        | *in_0.offset(3 as libc::c_int as isize)
            ^ 0x1ffffffffffffff as libc::c_long as p224_limb;
    two225m97p2 = (two225m97p2 as int64_t - 1 as libc::c_int as int64_t
        >> 63 as libc::c_int & 1 as libc::c_int as int64_t) as p224_limb;
    return zero | two224m96p1 | two225m97p2;
}
unsafe extern "C" fn p224_felem_inv(
    mut out: *mut p224_limb,
    mut in_0: *const p224_limb,
) {
    let mut ftmp: p224_felem = [0; 4];
    let mut ftmp2: p224_felem = [0; 4];
    let mut ftmp3: p224_felem = [0; 4];
    let mut ftmp4: p224_felem = [0; 4];
    let mut tmp: p224_widefelem = [0; 7];
    p224_felem_square(tmp.as_mut_ptr(), in_0);
    p224_felem_reduce(ftmp.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_mul(tmp.as_mut_ptr(), in_0, ftmp.as_mut_ptr() as *const p224_limb);
    p224_felem_reduce(ftmp.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_square(tmp.as_mut_ptr(), ftmp.as_mut_ptr() as *const p224_limb);
    p224_felem_reduce(ftmp.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_mul(tmp.as_mut_ptr(), in_0, ftmp.as_mut_ptr() as *const p224_limb);
    p224_felem_reduce(ftmp.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_square(tmp.as_mut_ptr(), ftmp.as_mut_ptr() as *const p224_limb);
    p224_felem_reduce(ftmp2.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_square(tmp.as_mut_ptr(), ftmp2.as_mut_ptr() as *const p224_limb);
    p224_felem_reduce(ftmp2.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_square(tmp.as_mut_ptr(), ftmp2.as_mut_ptr() as *const p224_limb);
    p224_felem_reduce(ftmp2.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_mul(
        tmp.as_mut_ptr(),
        ftmp2.as_mut_ptr() as *const p224_limb,
        ftmp.as_mut_ptr() as *const p224_limb,
    );
    p224_felem_reduce(ftmp.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_square(tmp.as_mut_ptr(), ftmp.as_mut_ptr() as *const p224_limb);
    p224_felem_reduce(ftmp2.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < 5 as libc::c_int as size_t {
        p224_felem_square(tmp.as_mut_ptr(), ftmp2.as_mut_ptr() as *const p224_limb);
        p224_felem_reduce(ftmp2.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
        i = i.wrapping_add(1);
        i;
    }
    p224_felem_mul(
        tmp.as_mut_ptr(),
        ftmp2.as_mut_ptr() as *const p224_limb,
        ftmp.as_mut_ptr() as *const p224_limb,
    );
    p224_felem_reduce(ftmp2.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_square(tmp.as_mut_ptr(), ftmp2.as_mut_ptr() as *const p224_limb);
    p224_felem_reduce(ftmp3.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    let mut i_0: size_t = 0 as libc::c_int as size_t;
    while i_0 < 11 as libc::c_int as size_t {
        p224_felem_square(tmp.as_mut_ptr(), ftmp3.as_mut_ptr() as *const p224_limb);
        p224_felem_reduce(ftmp3.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
    p224_felem_mul(
        tmp.as_mut_ptr(),
        ftmp3.as_mut_ptr() as *const p224_limb,
        ftmp2.as_mut_ptr() as *const p224_limb,
    );
    p224_felem_reduce(ftmp2.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_square(tmp.as_mut_ptr(), ftmp2.as_mut_ptr() as *const p224_limb);
    p224_felem_reduce(ftmp3.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    let mut i_1: size_t = 0 as libc::c_int as size_t;
    while i_1 < 23 as libc::c_int as size_t {
        p224_felem_square(tmp.as_mut_ptr(), ftmp3.as_mut_ptr() as *const p224_limb);
        p224_felem_reduce(ftmp3.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
        i_1 = i_1.wrapping_add(1);
        i_1;
    }
    p224_felem_mul(
        tmp.as_mut_ptr(),
        ftmp3.as_mut_ptr() as *const p224_limb,
        ftmp2.as_mut_ptr() as *const p224_limb,
    );
    p224_felem_reduce(ftmp3.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_square(tmp.as_mut_ptr(), ftmp3.as_mut_ptr() as *const p224_limb);
    p224_felem_reduce(ftmp4.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    let mut i_2: size_t = 0 as libc::c_int as size_t;
    while i_2 < 47 as libc::c_int as size_t {
        p224_felem_square(tmp.as_mut_ptr(), ftmp4.as_mut_ptr() as *const p224_limb);
        p224_felem_reduce(ftmp4.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
        i_2 = i_2.wrapping_add(1);
        i_2;
    }
    p224_felem_mul(
        tmp.as_mut_ptr(),
        ftmp3.as_mut_ptr() as *const p224_limb,
        ftmp4.as_mut_ptr() as *const p224_limb,
    );
    p224_felem_reduce(ftmp3.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_square(tmp.as_mut_ptr(), ftmp3.as_mut_ptr() as *const p224_limb);
    p224_felem_reduce(ftmp4.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    let mut i_3: size_t = 0 as libc::c_int as size_t;
    while i_3 < 23 as libc::c_int as size_t {
        p224_felem_square(tmp.as_mut_ptr(), ftmp4.as_mut_ptr() as *const p224_limb);
        p224_felem_reduce(ftmp4.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
        i_3 = i_3.wrapping_add(1);
        i_3;
    }
    p224_felem_mul(
        tmp.as_mut_ptr(),
        ftmp2.as_mut_ptr() as *const p224_limb,
        ftmp4.as_mut_ptr() as *const p224_limb,
    );
    p224_felem_reduce(ftmp2.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    let mut i_4: size_t = 0 as libc::c_int as size_t;
    while i_4 < 6 as libc::c_int as size_t {
        p224_felem_square(tmp.as_mut_ptr(), ftmp2.as_mut_ptr() as *const p224_limb);
        p224_felem_reduce(ftmp2.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
        i_4 = i_4.wrapping_add(1);
        i_4;
    }
    p224_felem_mul(
        tmp.as_mut_ptr(),
        ftmp2.as_mut_ptr() as *const p224_limb,
        ftmp.as_mut_ptr() as *const p224_limb,
    );
    p224_felem_reduce(ftmp.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_square(tmp.as_mut_ptr(), ftmp.as_mut_ptr() as *const p224_limb);
    p224_felem_reduce(ftmp.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_mul(tmp.as_mut_ptr(), ftmp.as_mut_ptr() as *const p224_limb, in_0);
    p224_felem_reduce(ftmp.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    let mut i_5: size_t = 0 as libc::c_int as size_t;
    while i_5 < 97 as libc::c_int as size_t {
        p224_felem_square(tmp.as_mut_ptr(), ftmp.as_mut_ptr() as *const p224_limb);
        p224_felem_reduce(ftmp.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
        i_5 = i_5.wrapping_add(1);
        i_5;
    }
    p224_felem_mul(
        tmp.as_mut_ptr(),
        ftmp.as_mut_ptr() as *const p224_limb,
        ftmp3.as_mut_ptr() as *const p224_limb,
    );
    p224_felem_reduce(out, tmp.as_mut_ptr() as *const p224_widelimb);
}
unsafe extern "C" fn p224_copy_conditional(
    mut out: *mut p224_limb,
    mut in_0: *const p224_limb,
    mut icopy: p224_limb,
) {
    let copy: p224_limb = icopy.wrapping_neg();
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < 4 as libc::c_int as size_t {
        let tmp: p224_limb = copy & (*in_0.offset(i as isize) ^ *out.offset(i as isize));
        *out.offset(i as isize) ^= tmp;
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn p224_point_double(
    mut x_out: *mut p224_limb,
    mut y_out: *mut p224_limb,
    mut z_out: *mut p224_limb,
    mut x_in: *const p224_limb,
    mut y_in: *const p224_limb,
    mut z_in: *const p224_limb,
) {
    let mut tmp: p224_widefelem = [0; 7];
    let mut tmp2: p224_widefelem = [0; 7];
    let mut delta: p224_felem = [0; 4];
    let mut gamma: p224_felem = [0; 4];
    let mut beta: p224_felem = [0; 4];
    let mut alpha: p224_felem = [0; 4];
    let mut ftmp: p224_felem = [0; 4];
    let mut ftmp2: p224_felem = [0; 4];
    p224_felem_assign(ftmp.as_mut_ptr(), x_in);
    p224_felem_assign(ftmp2.as_mut_ptr(), x_in);
    p224_felem_square(tmp.as_mut_ptr(), z_in);
    p224_felem_reduce(delta.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_square(tmp.as_mut_ptr(), y_in);
    p224_felem_reduce(gamma.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_mul(tmp.as_mut_ptr(), x_in, gamma.as_mut_ptr() as *const p224_limb);
    p224_felem_reduce(beta.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_diff(ftmp.as_mut_ptr(), delta.as_mut_ptr() as *const p224_limb);
    p224_felem_sum(ftmp2.as_mut_ptr(), delta.as_mut_ptr() as *const p224_limb);
    p224_felem_scalar(ftmp2.as_mut_ptr(), 3 as libc::c_int as p224_limb);
    p224_felem_mul(
        tmp.as_mut_ptr(),
        ftmp.as_mut_ptr() as *const p224_limb,
        ftmp2.as_mut_ptr() as *const p224_limb,
    );
    p224_felem_reduce(alpha.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_square(tmp.as_mut_ptr(), alpha.as_mut_ptr() as *const p224_limb);
    p224_felem_assign(ftmp.as_mut_ptr(), beta.as_mut_ptr() as *const p224_limb);
    p224_felem_scalar(ftmp.as_mut_ptr(), 8 as libc::c_int as p224_limb);
    p224_felem_diff_128_64(tmp.as_mut_ptr(), ftmp.as_mut_ptr() as *const p224_limb);
    p224_felem_reduce(x_out, tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_sum(delta.as_mut_ptr(), gamma.as_mut_ptr() as *const p224_limb);
    p224_felem_assign(ftmp.as_mut_ptr(), y_in);
    p224_felem_sum(ftmp.as_mut_ptr(), z_in);
    p224_felem_square(tmp.as_mut_ptr(), ftmp.as_mut_ptr() as *const p224_limb);
    p224_felem_diff_128_64(tmp.as_mut_ptr(), delta.as_mut_ptr() as *const p224_limb);
    p224_felem_reduce(z_out, tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_scalar(beta.as_mut_ptr(), 4 as libc::c_int as p224_limb);
    p224_felem_diff(beta.as_mut_ptr(), x_out as *const p224_limb);
    p224_felem_mul(
        tmp.as_mut_ptr(),
        alpha.as_mut_ptr() as *const p224_limb,
        beta.as_mut_ptr() as *const p224_limb,
    );
    p224_felem_square(tmp2.as_mut_ptr(), gamma.as_mut_ptr() as *const p224_limb);
    p224_widefelem_scalar(tmp2.as_mut_ptr(), 8 as libc::c_int as p224_widelimb);
    p224_widefelem_diff(tmp.as_mut_ptr(), tmp2.as_mut_ptr() as *const p224_widelimb);
    p224_felem_reduce(y_out, tmp.as_mut_ptr() as *const p224_widelimb);
}
unsafe extern "C" fn p224_point_add(
    mut x3: *mut p224_limb,
    mut y3: *mut p224_limb,
    mut z3: *mut p224_limb,
    mut x1: *const p224_limb,
    mut y1: *const p224_limb,
    mut z1: *const p224_limb,
    mixed: libc::c_int,
    mut x2: *const p224_limb,
    mut y2: *const p224_limb,
    mut z2: *const p224_limb,
) {
    let mut ftmp: p224_felem = [0; 4];
    let mut ftmp2: p224_felem = [0; 4];
    let mut ftmp3: p224_felem = [0; 4];
    let mut ftmp4: p224_felem = [0; 4];
    let mut ftmp5: p224_felem = [0; 4];
    let mut x_out: p224_felem = [0; 4];
    let mut y_out: p224_felem = [0; 4];
    let mut z_out: p224_felem = [0; 4];
    let mut tmp: p224_widefelem = [0; 7];
    let mut tmp2: p224_widefelem = [0; 7];
    let mut z1_is_zero: p224_limb = 0;
    let mut z2_is_zero: p224_limb = 0;
    let mut x_equal: p224_limb = 0;
    let mut y_equal: p224_limb = 0;
    if mixed == 0 {
        p224_felem_square(tmp.as_mut_ptr(), z2);
        p224_felem_reduce(ftmp2.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
        p224_felem_mul(tmp.as_mut_ptr(), ftmp2.as_mut_ptr() as *const p224_limb, z2);
        p224_felem_reduce(ftmp4.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
        p224_felem_mul(tmp2.as_mut_ptr(), ftmp4.as_mut_ptr() as *const p224_limb, y1);
        p224_felem_reduce(ftmp4.as_mut_ptr(), tmp2.as_mut_ptr() as *const p224_widelimb);
        p224_felem_mul(tmp2.as_mut_ptr(), ftmp2.as_mut_ptr() as *const p224_limb, x1);
        p224_felem_reduce(ftmp2.as_mut_ptr(), tmp2.as_mut_ptr() as *const p224_widelimb);
    } else {
        p224_felem_assign(ftmp4.as_mut_ptr(), y1);
        p224_felem_assign(ftmp2.as_mut_ptr(), x1);
    }
    p224_felem_square(tmp.as_mut_ptr(), z1);
    p224_felem_reduce(ftmp.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_mul(tmp.as_mut_ptr(), ftmp.as_mut_ptr() as *const p224_limb, z1);
    p224_felem_reduce(ftmp3.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_mul(tmp.as_mut_ptr(), ftmp3.as_mut_ptr() as *const p224_limb, y2);
    p224_felem_diff_128_64(tmp.as_mut_ptr(), ftmp4.as_mut_ptr() as *const p224_limb);
    p224_felem_reduce(ftmp3.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_mul(tmp.as_mut_ptr(), ftmp.as_mut_ptr() as *const p224_limb, x2);
    p224_felem_diff_128_64(tmp.as_mut_ptr(), ftmp2.as_mut_ptr() as *const p224_limb);
    p224_felem_reduce(ftmp.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    x_equal = p224_felem_is_zero(ftmp.as_mut_ptr() as *const p224_limb);
    y_equal = p224_felem_is_zero(ftmp3.as_mut_ptr() as *const p224_limb);
    z1_is_zero = p224_felem_is_zero(z1);
    z2_is_zero = p224_felem_is_zero(z2);
    let mut is_nontrivial_double: p224_limb = x_equal & y_equal
        & (1 as libc::c_int as p224_limb).wrapping_sub(z1_is_zero)
        & (1 as libc::c_int as p224_limb).wrapping_sub(z2_is_zero);
    if constant_time_declassify_w(is_nontrivial_double) != 0 {
        p224_point_double(x3, y3, z3, x1, y1, z1);
        return;
    }
    if mixed == 0 {
        p224_felem_mul(tmp.as_mut_ptr(), z1, z2);
        p224_felem_reduce(ftmp5.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    } else {
        p224_felem_assign(ftmp5.as_mut_ptr(), z1);
    }
    p224_felem_mul(
        tmp.as_mut_ptr(),
        ftmp.as_mut_ptr() as *const p224_limb,
        ftmp5.as_mut_ptr() as *const p224_limb,
    );
    p224_felem_reduce(z_out.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_assign(ftmp5.as_mut_ptr(), ftmp.as_mut_ptr() as *const p224_limb);
    p224_felem_square(tmp.as_mut_ptr(), ftmp.as_mut_ptr() as *const p224_limb);
    p224_felem_reduce(ftmp.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_mul(
        tmp.as_mut_ptr(),
        ftmp.as_mut_ptr() as *const p224_limb,
        ftmp5.as_mut_ptr() as *const p224_limb,
    );
    p224_felem_reduce(ftmp5.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_mul(
        tmp.as_mut_ptr(),
        ftmp2.as_mut_ptr() as *const p224_limb,
        ftmp.as_mut_ptr() as *const p224_limb,
    );
    p224_felem_reduce(ftmp2.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_mul(
        tmp.as_mut_ptr(),
        ftmp4.as_mut_ptr() as *const p224_limb,
        ftmp5.as_mut_ptr() as *const p224_limb,
    );
    p224_felem_square(tmp2.as_mut_ptr(), ftmp3.as_mut_ptr() as *const p224_limb);
    p224_felem_diff_128_64(tmp2.as_mut_ptr(), ftmp5.as_mut_ptr() as *const p224_limb);
    p224_felem_assign(ftmp5.as_mut_ptr(), ftmp2.as_mut_ptr() as *const p224_limb);
    p224_felem_scalar(ftmp5.as_mut_ptr(), 2 as libc::c_int as p224_limb);
    p224_felem_diff_128_64(tmp2.as_mut_ptr(), ftmp5.as_mut_ptr() as *const p224_limb);
    p224_felem_reduce(x_out.as_mut_ptr(), tmp2.as_mut_ptr() as *const p224_widelimb);
    p224_felem_diff(ftmp2.as_mut_ptr(), x_out.as_mut_ptr() as *const p224_limb);
    p224_felem_mul(
        tmp2.as_mut_ptr(),
        ftmp3.as_mut_ptr() as *const p224_limb,
        ftmp2.as_mut_ptr() as *const p224_limb,
    );
    p224_widefelem_diff(tmp2.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    p224_felem_reduce(y_out.as_mut_ptr(), tmp2.as_mut_ptr() as *const p224_widelimb);
    p224_copy_conditional(x_out.as_mut_ptr(), x2, z1_is_zero);
    p224_copy_conditional(x_out.as_mut_ptr(), x1, z2_is_zero);
    p224_copy_conditional(y_out.as_mut_ptr(), y2, z1_is_zero);
    p224_copy_conditional(y_out.as_mut_ptr(), y1, z2_is_zero);
    p224_copy_conditional(z_out.as_mut_ptr(), z2, z1_is_zero);
    p224_copy_conditional(z_out.as_mut_ptr(), z1, z2_is_zero);
    p224_felem_assign(x3, x_out.as_mut_ptr() as *const p224_limb);
    p224_felem_assign(y3, y_out.as_mut_ptr() as *const p224_limb);
    p224_felem_assign(z3, z_out.as_mut_ptr() as *const p224_limb);
}
unsafe extern "C" fn p224_select_point(
    idx: uint64_t,
    mut size: size_t,
    mut pre_comp: *const [p224_felem; 3],
    mut out: *mut p224_felem,
) {
    let mut outlimbs: *mut p224_limb = &mut *(*out.offset(0 as libc::c_int as isize))
        .as_mut_ptr()
        .offset(0 as libc::c_int as isize) as *mut p224_limb;
    OPENSSL_memset(
        outlimbs as *mut libc::c_void,
        0 as libc::c_int,
        (3 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::core::mem::size_of::<p224_felem>() as libc::c_ulong),
    );
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < size {
        let mut inlimbs: *const p224_limb = &*(*(*pre_comp.offset(i as isize))
            .as_ptr()
            .offset(0 as libc::c_int as isize))
            .as_ptr()
            .offset(0 as libc::c_int as isize) as *const p224_limb;
        let mut mask: uint64_t = value_barrier_w(constant_time_eq_w(i, idx));
        let mut j: size_t = 0 as libc::c_int as size_t;
        while j < (4 as libc::c_int * 3 as libc::c_int) as size_t {
            let ref mut fresh45 = *outlimbs.offset(j as isize);
            *fresh45 |= *inlimbs.offset(j as isize) & mask;
            j = j.wrapping_add(1);
            j;
        }
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn p224_get_bit(
    mut in_0: *const EC_SCALAR,
    mut i: size_t,
) -> crypto_word_t {
    if i >= 224 as libc::c_int as size_t {
        return 0 as libc::c_int as crypto_word_t;
    }
    if ::core::mem::size_of::<BN_ULONG>() as libc::c_ulong
        == 8 as libc::c_int as libc::c_ulong
    {} else {
        __assert_fail(
            b"sizeof(in->words[0]) == 8\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/p224-64.c\0"
                as *const u8 as *const libc::c_char,
            858 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 54],
                &[libc::c_char; 54],
            >(b"crypto_word_t p224_get_bit(const EC_SCALAR *, size_t)\0"))
                .as_ptr(),
        );
    }
    'c_12500: {
        if ::core::mem::size_of::<BN_ULONG>() as libc::c_ulong
            == 8 as libc::c_int as libc::c_ulong
        {} else {
            __assert_fail(
                b"sizeof(in->words[0]) == 8\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/p224-64.c\0"
                    as *const u8 as *const libc::c_char,
                858 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 54],
                    &[libc::c_char; 54],
                >(b"crypto_word_t p224_get_bit(const EC_SCALAR *, size_t)\0"))
                    .as_ptr(),
            );
        }
    };
    return (*in_0).words[(i >> 6 as libc::c_int) as usize]
        >> (i & 63 as libc::c_int as size_t) & 1 as libc::c_int as BN_ULONG;
}
unsafe extern "C" fn ec_GFp_nistp224_point_get_affine_coordinates(
    mut group: *const EC_GROUP,
    mut point: *const EC_JACOBIAN,
    mut x: *mut EC_FELEM,
    mut y: *mut EC_FELEM,
) -> libc::c_int {
    if constant_time_declassify_int(ec_GFp_simple_is_at_infinity(group, point)) != 0 {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            119 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/p224-64.c\0"
                as *const u8 as *const libc::c_char,
            869 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut z1: p224_felem = [0; 4];
    let mut z2: p224_felem = [0; 4];
    let mut tmp: p224_widefelem = [0; 7];
    p224_generic_to_felem(z1.as_mut_ptr(), &(*point).Z);
    p224_felem_inv(z2.as_mut_ptr(), z1.as_mut_ptr() as *const p224_limb);
    p224_felem_square(tmp.as_mut_ptr(), z2.as_mut_ptr() as *const p224_limb);
    p224_felem_reduce(z1.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
    if !x.is_null() {
        let mut x_in: p224_felem = [0; 4];
        let mut x_out: p224_felem = [0; 4];
        p224_generic_to_felem(x_in.as_mut_ptr(), &(*point).X);
        p224_felem_mul(
            tmp.as_mut_ptr(),
            x_in.as_mut_ptr() as *const p224_limb,
            z1.as_mut_ptr() as *const p224_limb,
        );
        p224_felem_reduce(x_out.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
        p224_felem_to_generic(x, x_out.as_mut_ptr() as *const p224_limb);
    }
    if !y.is_null() {
        let mut y_in: p224_felem = [0; 4];
        let mut y_out: p224_felem = [0; 4];
        p224_generic_to_felem(y_in.as_mut_ptr(), &(*point).Y);
        p224_felem_mul(
            tmp.as_mut_ptr(),
            z1.as_mut_ptr() as *const p224_limb,
            z2.as_mut_ptr() as *const p224_limb,
        );
        p224_felem_reduce(z1.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
        p224_felem_mul(
            tmp.as_mut_ptr(),
            y_in.as_mut_ptr() as *const p224_limb,
            z1.as_mut_ptr() as *const p224_limb,
        );
        p224_felem_reduce(y_out.as_mut_ptr(), tmp.as_mut_ptr() as *const p224_widelimb);
        p224_felem_to_generic(y, y_out.as_mut_ptr() as *const p224_limb);
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn ec_GFp_nistp224_add(
    mut group: *const EC_GROUP,
    mut r: *mut EC_JACOBIAN,
    mut a: *const EC_JACOBIAN,
    mut b: *const EC_JACOBIAN,
) {
    let mut x1: p224_felem = [0; 4];
    let mut y1: p224_felem = [0; 4];
    let mut z1: p224_felem = [0; 4];
    let mut x2: p224_felem = [0; 4];
    let mut y2: p224_felem = [0; 4];
    let mut z2: p224_felem = [0; 4];
    p224_generic_to_felem(x1.as_mut_ptr(), &(*a).X);
    p224_generic_to_felem(y1.as_mut_ptr(), &(*a).Y);
    p224_generic_to_felem(z1.as_mut_ptr(), &(*a).Z);
    p224_generic_to_felem(x2.as_mut_ptr(), &(*b).X);
    p224_generic_to_felem(y2.as_mut_ptr(), &(*b).Y);
    p224_generic_to_felem(z2.as_mut_ptr(), &(*b).Z);
    p224_point_add(
        x1.as_mut_ptr(),
        y1.as_mut_ptr(),
        z1.as_mut_ptr(),
        x1.as_mut_ptr() as *const p224_limb,
        y1.as_mut_ptr() as *const p224_limb,
        z1.as_mut_ptr() as *const p224_limb,
        0 as libc::c_int,
        x2.as_mut_ptr() as *const p224_limb,
        y2.as_mut_ptr() as *const p224_limb,
        z2.as_mut_ptr() as *const p224_limb,
    );
    p224_felem_to_generic(&mut (*r).X, x1.as_mut_ptr() as *const p224_limb);
    p224_felem_to_generic(&mut (*r).Y, y1.as_mut_ptr() as *const p224_limb);
    p224_felem_to_generic(&mut (*r).Z, z1.as_mut_ptr() as *const p224_limb);
}
unsafe extern "C" fn ec_GFp_nistp224_dbl(
    mut group: *const EC_GROUP,
    mut r: *mut EC_JACOBIAN,
    mut a: *const EC_JACOBIAN,
) {
    let mut x: p224_felem = [0; 4];
    let mut y: p224_felem = [0; 4];
    let mut z: p224_felem = [0; 4];
    p224_generic_to_felem(x.as_mut_ptr(), &(*a).X);
    p224_generic_to_felem(y.as_mut_ptr(), &(*a).Y);
    p224_generic_to_felem(z.as_mut_ptr(), &(*a).Z);
    p224_point_double(
        x.as_mut_ptr(),
        y.as_mut_ptr(),
        z.as_mut_ptr(),
        x.as_mut_ptr() as *const p224_limb,
        y.as_mut_ptr() as *const p224_limb,
        z.as_mut_ptr() as *const p224_limb,
    );
    p224_felem_to_generic(&mut (*r).X, x.as_mut_ptr() as *const p224_limb);
    p224_felem_to_generic(&mut (*r).Y, y.as_mut_ptr() as *const p224_limb);
    p224_felem_to_generic(&mut (*r).Z, z.as_mut_ptr() as *const p224_limb);
}
unsafe extern "C" fn ec_GFp_nistp224_make_precomp(
    mut out: *mut [p224_felem; 3],
    mut p: *const EC_JACOBIAN,
) {
    OPENSSL_memset(
        (*out.offset(0 as libc::c_int as isize)).as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        (::core::mem::size_of::<p224_felem>() as libc::c_ulong)
            .wrapping_mul(3 as libc::c_int as libc::c_ulong),
    );
    p224_generic_to_felem(
        ((*out.offset(1 as libc::c_int as isize))[0 as libc::c_int as usize])
            .as_mut_ptr(),
        &(*p).X,
    );
    p224_generic_to_felem(
        ((*out.offset(1 as libc::c_int as isize))[1 as libc::c_int as usize])
            .as_mut_ptr(),
        &(*p).Y,
    );
    p224_generic_to_felem(
        ((*out.offset(1 as libc::c_int as isize))[2 as libc::c_int as usize])
            .as_mut_ptr(),
        &(*p).Z,
    );
    let mut j: size_t = 2 as libc::c_int as size_t;
    while j <= 16 as libc::c_int as size_t {
        if j & 1 as libc::c_int as size_t != 0 {
            p224_point_add(
                ((*out.offset(j as isize))[0 as libc::c_int as usize]).as_mut_ptr(),
                ((*out.offset(j as isize))[1 as libc::c_int as usize]).as_mut_ptr(),
                ((*out.offset(j as isize))[2 as libc::c_int as usize]).as_mut_ptr(),
                ((*out.offset(1 as libc::c_int as isize))[0 as libc::c_int as usize])
                    .as_mut_ptr() as *const p224_limb,
                ((*out.offset(1 as libc::c_int as isize))[1 as libc::c_int as usize])
                    .as_mut_ptr() as *const p224_limb,
                ((*out.offset(1 as libc::c_int as isize))[2 as libc::c_int as usize])
                    .as_mut_ptr() as *const p224_limb,
                0 as libc::c_int,
                ((*out
                    .offset(
                        j.wrapping_sub(1 as libc::c_int as size_t) as isize,
                    ))[0 as libc::c_int as usize])
                    .as_mut_ptr() as *const p224_limb,
                ((*out
                    .offset(
                        j.wrapping_sub(1 as libc::c_int as size_t) as isize,
                    ))[1 as libc::c_int as usize])
                    .as_mut_ptr() as *const p224_limb,
                ((*out
                    .offset(
                        j.wrapping_sub(1 as libc::c_int as size_t) as isize,
                    ))[2 as libc::c_int as usize])
                    .as_mut_ptr() as *const p224_limb,
            );
        } else {
            p224_point_double(
                ((*out.offset(j as isize))[0 as libc::c_int as usize]).as_mut_ptr(),
                ((*out.offset(j as isize))[1 as libc::c_int as usize]).as_mut_ptr(),
                ((*out.offset(j as isize))[2 as libc::c_int as usize]).as_mut_ptr(),
                ((*out
                    .offset(
                        (j / 2 as libc::c_int as size_t) as isize,
                    ))[0 as libc::c_int as usize])
                    .as_mut_ptr() as *const p224_limb,
                ((*out
                    .offset(
                        (j / 2 as libc::c_int as size_t) as isize,
                    ))[1 as libc::c_int as usize])
                    .as_mut_ptr() as *const p224_limb,
                ((*out
                    .offset(
                        (j / 2 as libc::c_int as size_t) as isize,
                    ))[2 as libc::c_int as usize])
                    .as_mut_ptr() as *const p224_limb,
            );
        }
        j = j.wrapping_add(1);
        j;
    }
}
unsafe extern "C" fn ec_GFp_nistp224_point_mul(
    mut group: *const EC_GROUP,
    mut r: *mut EC_JACOBIAN,
    mut p: *const EC_JACOBIAN,
    mut scalar: *const EC_SCALAR,
) {
    let mut p_pre_comp: [[p224_felem; 3]; 17] = [[[0; 4]; 3]; 17];
    ec_GFp_nistp224_make_precomp(p_pre_comp.as_mut_ptr(), p);
    let mut nq: [p224_felem; 3] = [[0; 4]; 3];
    let mut tmp: [p224_felem; 4] = [[0; 4]; 4];
    OPENSSL_memset(
        nq.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        (3 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::core::mem::size_of::<p224_felem>() as libc::c_ulong),
    );
    let mut skip: libc::c_int = 1 as libc::c_int;
    let mut i: size_t = 220 as libc::c_int as size_t;
    while i < 221 as libc::c_int as size_t {
        if skip == 0 {
            p224_point_double(
                (nq[0 as libc::c_int as usize]).as_mut_ptr(),
                (nq[1 as libc::c_int as usize]).as_mut_ptr(),
                (nq[2 as libc::c_int as usize]).as_mut_ptr(),
                (nq[0 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                (nq[1 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                (nq[2 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
            );
        }
        if i % 5 as libc::c_int as size_t == 0 as libc::c_int as size_t {
            let mut bits: crypto_word_t = p224_get_bit(
                scalar,
                i.wrapping_add(4 as libc::c_int as size_t),
            ) << 5 as libc::c_int;
            bits
                |= p224_get_bit(scalar, i.wrapping_add(3 as libc::c_int as size_t))
                    << 4 as libc::c_int;
            bits
                |= p224_get_bit(scalar, i.wrapping_add(2 as libc::c_int as size_t))
                    << 3 as libc::c_int;
            bits
                |= p224_get_bit(scalar, i.wrapping_add(1 as libc::c_int as size_t))
                    << 2 as libc::c_int;
            bits |= p224_get_bit(scalar, i) << 1 as libc::c_int;
            bits |= p224_get_bit(scalar, i.wrapping_sub(1 as libc::c_int as size_t));
            let mut sign: crypto_word_t = 0;
            let mut digit: crypto_word_t = 0;
            ec_GFp_nistp_recode_scalar_bits(&mut sign, &mut digit, bits);
            p224_select_point(
                digit,
                17 as libc::c_int as size_t,
                p_pre_comp.as_mut_ptr() as *const [p224_felem; 3],
                tmp.as_mut_ptr(),
            );
            p224_felem_neg(
                (tmp[3 as libc::c_int as usize]).as_mut_ptr(),
                (tmp[1 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
            );
            p224_copy_conditional(
                (tmp[1 as libc::c_int as usize]).as_mut_ptr(),
                (tmp[3 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                sign,
            );
            if skip == 0 {
                p224_point_add(
                    (nq[0 as libc::c_int as usize]).as_mut_ptr(),
                    (nq[1 as libc::c_int as usize]).as_mut_ptr(),
                    (nq[2 as libc::c_int as usize]).as_mut_ptr(),
                    (nq[0 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                    (nq[1 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                    (nq[2 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                    0 as libc::c_int,
                    (tmp[0 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                    (tmp[1 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                    (tmp[2 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                );
            } else {
                OPENSSL_memcpy(
                    nq.as_mut_ptr() as *mut libc::c_void,
                    tmp.as_mut_ptr() as *const libc::c_void,
                    (3 as libc::c_int as libc::c_ulong)
                        .wrapping_mul(
                            ::core::mem::size_of::<p224_felem>() as libc::c_ulong,
                        ),
                );
                skip = 0 as libc::c_int;
            }
        }
        i = i.wrapping_sub(1);
        i;
    }
    p224_felem_to_generic(
        &mut (*r).X,
        (nq[0 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
    );
    p224_felem_to_generic(
        &mut (*r).Y,
        (nq[1 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
    );
    p224_felem_to_generic(
        &mut (*r).Z,
        (nq[2 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
    );
}
unsafe extern "C" fn ec_GFp_nistp224_point_mul_base(
    mut group: *const EC_GROUP,
    mut r: *mut EC_JACOBIAN,
    mut scalar: *const EC_SCALAR,
) {
    let mut nq: [p224_felem; 3] = [[0; 4]; 3];
    let mut tmp: [p224_felem; 3] = [[0; 4]; 3];
    OPENSSL_memset(
        nq.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        (3 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::core::mem::size_of::<p224_felem>() as libc::c_ulong),
    );
    let mut skip: libc::c_int = 1 as libc::c_int;
    let mut i: size_t = 27 as libc::c_int as size_t;
    while i < 28 as libc::c_int as size_t {
        if skip == 0 {
            p224_point_double(
                (nq[0 as libc::c_int as usize]).as_mut_ptr(),
                (nq[1 as libc::c_int as usize]).as_mut_ptr(),
                (nq[2 as libc::c_int as usize]).as_mut_ptr(),
                (nq[0 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                (nq[1 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                (nq[2 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
            );
        }
        let mut bits: crypto_word_t = p224_get_bit(
            scalar,
            i.wrapping_add(196 as libc::c_int as size_t),
        ) << 3 as libc::c_int;
        bits
            |= p224_get_bit(scalar, i.wrapping_add(140 as libc::c_int as size_t))
                << 2 as libc::c_int;
        bits
            |= p224_get_bit(scalar, i.wrapping_add(84 as libc::c_int as size_t))
                << 1 as libc::c_int;
        bits |= p224_get_bit(scalar, i.wrapping_add(28 as libc::c_int as size_t));
        p224_select_point(
            bits,
            16 as libc::c_int as size_t,
            (g_p224_pre_comp[1 as libc::c_int as usize]).as_ptr(),
            tmp.as_mut_ptr(),
        );
        if skip == 0 {
            p224_point_add(
                (nq[0 as libc::c_int as usize]).as_mut_ptr(),
                (nq[1 as libc::c_int as usize]).as_mut_ptr(),
                (nq[2 as libc::c_int as usize]).as_mut_ptr(),
                (nq[0 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                (nq[1 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                (nq[2 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                1 as libc::c_int,
                (tmp[0 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                (tmp[1 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                (tmp[2 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
            );
        } else {
            OPENSSL_memcpy(
                nq.as_mut_ptr() as *mut libc::c_void,
                tmp.as_mut_ptr() as *const libc::c_void,
                (3 as libc::c_int as libc::c_ulong)
                    .wrapping_mul(::core::mem::size_of::<p224_felem>() as libc::c_ulong),
            );
            skip = 0 as libc::c_int;
        }
        bits = p224_get_bit(scalar, i.wrapping_add(168 as libc::c_int as size_t))
            << 3 as libc::c_int;
        bits
            |= p224_get_bit(scalar, i.wrapping_add(112 as libc::c_int as size_t))
                << 2 as libc::c_int;
        bits
            |= p224_get_bit(scalar, i.wrapping_add(56 as libc::c_int as size_t))
                << 1 as libc::c_int;
        bits |= p224_get_bit(scalar, i);
        p224_select_point(
            bits,
            16 as libc::c_int as size_t,
            (g_p224_pre_comp[0 as libc::c_int as usize]).as_ptr(),
            tmp.as_mut_ptr(),
        );
        p224_point_add(
            (nq[0 as libc::c_int as usize]).as_mut_ptr(),
            (nq[1 as libc::c_int as usize]).as_mut_ptr(),
            (nq[2 as libc::c_int as usize]).as_mut_ptr(),
            (nq[0 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
            (nq[1 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
            (nq[2 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
            1 as libc::c_int,
            (tmp[0 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
            (tmp[1 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
            (tmp[2 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
        );
        i = i.wrapping_sub(1);
        i;
    }
    p224_felem_to_generic(
        &mut (*r).X,
        (nq[0 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
    );
    p224_felem_to_generic(
        &mut (*r).Y,
        (nq[1 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
    );
    p224_felem_to_generic(
        &mut (*r).Z,
        (nq[2 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
    );
}
unsafe extern "C" fn ec_GFp_nistp224_point_mul_public(
    mut group: *const EC_GROUP,
    mut r: *mut EC_JACOBIAN,
    mut g_scalar: *const EC_SCALAR,
    mut p: *const EC_JACOBIAN,
    mut p_scalar: *const EC_SCALAR,
) {
    let mut p_pre_comp: [[p224_felem; 3]; 17] = [[[0; 4]; 3]; 17];
    ec_GFp_nistp224_make_precomp(p_pre_comp.as_mut_ptr(), p);
    let mut nq: [p224_felem; 3] = [[0; 4]; 3];
    let mut tmp: [p224_felem; 3] = [[0; 4]; 3];
    OPENSSL_memset(
        nq.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        (3 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::core::mem::size_of::<p224_felem>() as libc::c_ulong),
    );
    let mut skip: libc::c_int = 1 as libc::c_int;
    let mut i: size_t = 220 as libc::c_int as size_t;
    while i < 221 as libc::c_int as size_t {
        if skip == 0 {
            p224_point_double(
                (nq[0 as libc::c_int as usize]).as_mut_ptr(),
                (nq[1 as libc::c_int as usize]).as_mut_ptr(),
                (nq[2 as libc::c_int as usize]).as_mut_ptr(),
                (nq[0 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                (nq[1 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                (nq[2 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
            );
        }
        if i <= 27 as libc::c_int as size_t {
            let mut bits: crypto_word_t = p224_get_bit(
                g_scalar,
                i.wrapping_add(196 as libc::c_int as size_t),
            ) << 3 as libc::c_int;
            bits
                |= p224_get_bit(g_scalar, i.wrapping_add(140 as libc::c_int as size_t))
                    << 2 as libc::c_int;
            bits
                |= p224_get_bit(g_scalar, i.wrapping_add(84 as libc::c_int as size_t))
                    << 1 as libc::c_int;
            bits |= p224_get_bit(g_scalar, i.wrapping_add(28 as libc::c_int as size_t));
            let mut index: size_t = bits;
            p224_point_add(
                (nq[0 as libc::c_int as usize]).as_mut_ptr(),
                (nq[1 as libc::c_int as usize]).as_mut_ptr(),
                (nq[2 as libc::c_int as usize]).as_mut_ptr(),
                (nq[0 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                (nq[1 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                (nq[2 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                1 as libc::c_int,
                (g_p224_pre_comp[1 as libc::c_int
                    as usize][index as usize][0 as libc::c_int as usize])
                    .as_ptr(),
                (g_p224_pre_comp[1 as libc::c_int
                    as usize][index as usize][1 as libc::c_int as usize])
                    .as_ptr(),
                (g_p224_pre_comp[1 as libc::c_int
                    as usize][index as usize][2 as libc::c_int as usize])
                    .as_ptr(),
            );
            if skip == 0 {} else {
                __assert_fail(
                    b"!skip\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/p224-64.c\0"
                        as *const u8 as *const libc::c_char,
                    1079 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 130],
                        &[libc::c_char; 130],
                    >(
                        b"void ec_GFp_nistp224_point_mul_public(const EC_GROUP *, EC_JACOBIAN *, const EC_SCALAR *, const EC_JACOBIAN *, const EC_SCALAR *)\0",
                    ))
                        .as_ptr(),
                );
            }
            'c_13836: {
                if skip == 0 {} else {
                    __assert_fail(
                        b"!skip\0" as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/p224-64.c\0"
                            as *const u8 as *const libc::c_char,
                        1079 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 130],
                            &[libc::c_char; 130],
                        >(
                            b"void ec_GFp_nistp224_point_mul_public(const EC_GROUP *, EC_JACOBIAN *, const EC_SCALAR *, const EC_JACOBIAN *, const EC_SCALAR *)\0",
                        ))
                            .as_ptr(),
                    );
                }
            };
            bits = p224_get_bit(g_scalar, i.wrapping_add(168 as libc::c_int as size_t))
                << 3 as libc::c_int;
            bits
                |= p224_get_bit(g_scalar, i.wrapping_add(112 as libc::c_int as size_t))
                    << 2 as libc::c_int;
            bits
                |= p224_get_bit(g_scalar, i.wrapping_add(56 as libc::c_int as size_t))
                    << 1 as libc::c_int;
            bits |= p224_get_bit(g_scalar, i);
            index = bits;
            p224_point_add(
                (nq[0 as libc::c_int as usize]).as_mut_ptr(),
                (nq[1 as libc::c_int as usize]).as_mut_ptr(),
                (nq[2 as libc::c_int as usize]).as_mut_ptr(),
                (nq[0 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                (nq[1 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                (nq[2 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                1 as libc::c_int,
                (g_p224_pre_comp[0 as libc::c_int
                    as usize][index as usize][0 as libc::c_int as usize])
                    .as_ptr(),
                (g_p224_pre_comp[0 as libc::c_int
                    as usize][index as usize][1 as libc::c_int as usize])
                    .as_ptr(),
                (g_p224_pre_comp[0 as libc::c_int
                    as usize][index as usize][2 as libc::c_int as usize])
                    .as_ptr(),
            );
        }
        if i % 5 as libc::c_int as size_t == 0 as libc::c_int as size_t {
            let mut bits_0: crypto_word_t = p224_get_bit(
                p_scalar,
                i.wrapping_add(4 as libc::c_int as size_t),
            ) << 5 as libc::c_int;
            bits_0
                |= p224_get_bit(p_scalar, i.wrapping_add(3 as libc::c_int as size_t))
                    << 4 as libc::c_int;
            bits_0
                |= p224_get_bit(p_scalar, i.wrapping_add(2 as libc::c_int as size_t))
                    << 3 as libc::c_int;
            bits_0
                |= p224_get_bit(p_scalar, i.wrapping_add(1 as libc::c_int as size_t))
                    << 2 as libc::c_int;
            bits_0 |= p224_get_bit(p_scalar, i) << 1 as libc::c_int;
            bits_0 |= p224_get_bit(p_scalar, i.wrapping_sub(1 as libc::c_int as size_t));
            let mut sign: crypto_word_t = 0;
            let mut digit: crypto_word_t = 0;
            ec_GFp_nistp_recode_scalar_bits(&mut sign, &mut digit, bits_0);
            OPENSSL_memcpy(
                tmp.as_mut_ptr() as *mut libc::c_void,
                (p_pre_comp[digit as usize]).as_mut_ptr() as *const libc::c_void,
                (3 as libc::c_int as libc::c_ulong)
                    .wrapping_mul(::core::mem::size_of::<p224_felem>() as libc::c_ulong),
            );
            if sign != 0 {
                p224_felem_neg(
                    (tmp[1 as libc::c_int as usize]).as_mut_ptr(),
                    (tmp[1 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                );
            }
            if skip == 0 {
                p224_point_add(
                    (nq[0 as libc::c_int as usize]).as_mut_ptr(),
                    (nq[1 as libc::c_int as usize]).as_mut_ptr(),
                    (nq[2 as libc::c_int as usize]).as_mut_ptr(),
                    (nq[0 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                    (nq[1 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                    (nq[2 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                    0 as libc::c_int,
                    (tmp[0 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                    (tmp[1 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                    (tmp[2 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
                );
            } else {
                OPENSSL_memcpy(
                    nq.as_mut_ptr() as *mut libc::c_void,
                    tmp.as_mut_ptr() as *const libc::c_void,
                    (3 as libc::c_int as libc::c_ulong)
                        .wrapping_mul(
                            ::core::mem::size_of::<p224_felem>() as libc::c_ulong,
                        ),
                );
                skip = 0 as libc::c_int;
            }
        }
        i = i.wrapping_sub(1);
        i;
    }
    p224_felem_to_generic(
        &mut (*r).X,
        (nq[0 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
    );
    p224_felem_to_generic(
        &mut (*r).Y,
        (nq[1 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
    );
    p224_felem_to_generic(
        &mut (*r).Z,
        (nq[2 as libc::c_int as usize]).as_mut_ptr() as *const p224_limb,
    );
}
unsafe extern "C" fn ec_GFp_nistp224_felem_mul(
    mut group: *const EC_GROUP,
    mut r: *mut EC_FELEM,
    mut a: *const EC_FELEM,
    mut b: *const EC_FELEM,
) {
    let mut felem1: p224_felem = [0; 4];
    let mut felem2: p224_felem = [0; 4];
    let mut wide: p224_widefelem = [0; 7];
    p224_generic_to_felem(felem1.as_mut_ptr(), a);
    p224_generic_to_felem(felem2.as_mut_ptr(), b);
    p224_felem_mul(
        wide.as_mut_ptr(),
        felem1.as_mut_ptr() as *const p224_limb,
        felem2.as_mut_ptr() as *const p224_limb,
    );
    p224_felem_reduce(felem1.as_mut_ptr(), wide.as_mut_ptr() as *const p224_widelimb);
    p224_felem_to_generic(r, felem1.as_mut_ptr() as *const p224_limb);
}
unsafe extern "C" fn ec_GFp_nistp224_felem_sqr(
    mut group: *const EC_GROUP,
    mut r: *mut EC_FELEM,
    mut a: *const EC_FELEM,
) {
    let mut felem: p224_felem = [0; 4];
    p224_generic_to_felem(felem.as_mut_ptr(), a);
    let mut wide: p224_widefelem = [0; 7];
    p224_felem_square(wide.as_mut_ptr(), felem.as_mut_ptr() as *const p224_limb);
    p224_felem_reduce(felem.as_mut_ptr(), wide.as_mut_ptr() as *const p224_widelimb);
    p224_felem_to_generic(r, felem.as_mut_ptr() as *const p224_limb);
}
static mut EC_GFp_nistp224_method_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EC_GFp_nistp224_method_init() {
    EC_GFp_nistp224_method_do_init(EC_GFp_nistp224_method_storage_bss_get());
}
static mut EC_GFp_nistp224_method_storage: EC_METHOD = ec_method_st {
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
pub unsafe extern "C" fn EC_GFp_nistp224_method() -> *const EC_METHOD {
    CRYPTO_once(
        EC_GFp_nistp224_method_once_bss_get(),
        Some(EC_GFp_nistp224_method_init as unsafe extern "C" fn() -> ()),
    );
    return EC_GFp_nistp224_method_storage_bss_get() as *const EC_METHOD;
}
unsafe extern "C" fn EC_GFp_nistp224_method_storage_bss_get() -> *mut EC_METHOD {
    return &mut EC_GFp_nistp224_method_storage;
}
unsafe extern "C" fn EC_GFp_nistp224_method_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EC_GFp_nistp224_method_once;
}
unsafe extern "C" fn EC_GFp_nistp224_method_do_init(mut out: *mut EC_METHOD) {
    (*out)
        .point_get_affine_coordinates = Some(
        ec_GFp_nistp224_point_get_affine_coordinates
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *const EC_JACOBIAN,
                *mut EC_FELEM,
                *mut EC_FELEM,
            ) -> libc::c_int,
    );
    (*out)
        .add = Some(
        ec_GFp_nistp224_add
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_JACOBIAN,
                *const EC_JACOBIAN,
                *const EC_JACOBIAN,
            ) -> (),
    );
    (*out)
        .dbl = Some(
        ec_GFp_nistp224_dbl
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_JACOBIAN,
                *const EC_JACOBIAN,
            ) -> (),
    );
    (*out)
        .mul = Some(
        ec_GFp_nistp224_point_mul
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_JACOBIAN,
                *const EC_JACOBIAN,
                *const EC_SCALAR,
            ) -> (),
    );
    (*out)
        .mul_base = Some(
        ec_GFp_nistp224_point_mul_base
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_JACOBIAN,
                *const EC_SCALAR,
            ) -> (),
    );
    (*out)
        .mul_public = Some(
        ec_GFp_nistp224_point_mul_public
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
        ec_GFp_nistp224_felem_mul
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_FELEM,
                *const EC_FELEM,
                *const EC_FELEM,
            ) -> (),
    );
    (*out)
        .felem_sqr = Some(
        ec_GFp_nistp224_felem_sqr
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_FELEM,
                *const EC_FELEM,
            ) -> (),
    );
    (*out)
        .felem_to_bytes = Some(
        ec_GFp_simple_felem_to_bytes
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut uint8_t,
                *mut size_t,
                *const EC_FELEM,
            ) -> (),
    );
    (*out)
        .felem_from_bytes = Some(
        ec_GFp_simple_felem_from_bytes
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_FELEM,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
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
        ec_GFp_simple_cmp_x_coordinate
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *const EC_JACOBIAN,
                *const EC_SCALAR,
            ) -> libc::c_int,
    );
}
unsafe extern "C" fn run_static_initializers() {
    two58p2 = ((1 as libc::c_int as p224_limb) << 58 as libc::c_int)
        .wrapping_add((1 as libc::c_int as p224_limb) << 2 as libc::c_int);
    two58m2 = ((1 as libc::c_int as p224_limb) << 58 as libc::c_int)
        .wrapping_sub((1 as libc::c_int as p224_limb) << 2 as libc::c_int);
    two58m42m2 = ((1 as libc::c_int as p224_limb) << 58 as libc::c_int)
        .wrapping_sub((1 as libc::c_int as p224_limb) << 42 as libc::c_int)
        .wrapping_sub((1 as libc::c_int as p224_limb) << 2 as libc::c_int);
    two120m64 = ((1 as libc::c_int as p224_widelimb) << 120 as libc::c_int)
        .wrapping_sub((1 as libc::c_int as p224_widelimb) << 64 as libc::c_int);
    two120m104m64 = ((1 as libc::c_int as p224_widelimb) << 120 as libc::c_int)
        .wrapping_sub((1 as libc::c_int as p224_widelimb) << 104 as libc::c_int)
        .wrapping_sub((1 as libc::c_int as p224_widelimb) << 64 as libc::c_int);
    two64p8 = ((1 as libc::c_int as p224_widelimb) << 64 as libc::c_int)
        .wrapping_add((1 as libc::c_int as p224_widelimb) << 8 as libc::c_int);
    two64m8 = ((1 as libc::c_int as p224_widelimb) << 64 as libc::c_int)
        .wrapping_sub((1 as libc::c_int as p224_widelimb) << 8 as libc::c_int);
    two64m48m8 = ((1 as libc::c_int as p224_widelimb) << 64 as libc::c_int)
        .wrapping_sub((1 as libc::c_int as p224_widelimb) << 48 as libc::c_int)
        .wrapping_sub((1 as libc::c_int as p224_widelimb) << 8 as libc::c_int);
    two127p15 = ((1 as libc::c_int as p224_widelimb) << 127 as libc::c_int)
        .wrapping_add((1 as libc::c_int as p224_widelimb) << 15 as libc::c_int);
    two127m71 = ((1 as libc::c_int as p224_widelimb) << 127 as libc::c_int)
        .wrapping_sub((1 as libc::c_int as p224_widelimb) << 71 as libc::c_int);
    two127m71m55 = ((1 as libc::c_int as p224_widelimb) << 127 as libc::c_int)
        .wrapping_sub((1 as libc::c_int as p224_widelimb) << 71 as libc::c_int)
        .wrapping_sub((1 as libc::c_int as p224_widelimb) << 55 as libc::c_int);
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
