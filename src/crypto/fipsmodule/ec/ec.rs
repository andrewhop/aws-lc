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
unsafe extern "C" {
    pub type bignum_ctx;
    fn BN_new() -> *mut BIGNUM;
    fn BN_free(bn: *mut BIGNUM);
    fn BN_copy(dest: *mut BIGNUM, src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_num_bits(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_num_bytes(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_set_word(bn: *mut BIGNUM, value: BN_ULONG) -> libc::c_int;
    fn BN_CTX_new() -> *mut BN_CTX;
    fn BN_CTX_free(ctx: *mut BN_CTX);
    fn BN_CTX_start(ctx: *mut BN_CTX);
    fn BN_CTX_get(ctx: *mut BN_CTX) -> *mut BIGNUM;
    fn BN_CTX_end(ctx: *mut BN_CTX);
    fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_is_one(bn: *const BIGNUM) -> libc::c_int;
    fn BN_lshift1(r: *mut BIGNUM, a: *const BIGNUM) -> libc::c_int;
    fn BN_nnmod(
        rem: *mut BIGNUM,
        numerator: *const BIGNUM,
        divisor: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_MONT_CTX_copy(
        to: *mut BN_MONT_CTX,
        from: *const BN_MONT_CTX,
    ) -> *mut BN_MONT_CTX;
    fn BN_MONT_CTX_set(
        mont: *mut BN_MONT_CTX,
        mod_0: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn ec_bignum_to_scalar(
        group: *const EC_GROUP,
        out: *mut EC_SCALAR,
        in_0: *const BIGNUM,
    ) -> libc::c_int;
    fn ec_felem_one(group: *const EC_GROUP) -> *const EC_FELEM;
    fn ec_bignum_to_felem(
        group: *const EC_GROUP,
        out: *mut EC_FELEM,
        in_0: *const BIGNUM,
    ) -> libc::c_int;
    fn ec_felem_to_bignum(
        group: *const EC_GROUP,
        out: *mut BIGNUM,
        in_0: *const EC_FELEM,
    ) -> libc::c_int;
    fn ec_felem_to_bytes(
        group: *const EC_GROUP,
        out: *mut uint8_t,
        out_len: *mut size_t,
        in_0: *const EC_FELEM,
    );
    fn ec_felem_neg(group: *const EC_GROUP, out: *mut EC_FELEM, a: *const EC_FELEM);
    fn ec_felem_add(
        group: *const EC_GROUP,
        out: *mut EC_FELEM,
        a: *const EC_FELEM,
        b: *const EC_FELEM,
    );
    fn ec_felem_sub(
        group: *const EC_GROUP,
        out: *mut EC_FELEM,
        a: *const EC_FELEM,
        b: *const EC_FELEM,
    );
    fn ec_felem_select(
        group: *const EC_GROUP,
        out: *mut EC_FELEM,
        mask: BN_ULONG,
        a: *const EC_FELEM,
        b: *const EC_FELEM,
    );
    fn ec_felem_equal(
        group: *const EC_GROUP,
        a: *const EC_FELEM,
        b: *const EC_FELEM,
    ) -> libc::c_int;
    fn EC_GFp_mont_method() -> *const EC_METHOD;
    fn ec_GFp_simple_group_set_curve(
        _: *mut EC_GROUP,
        p: *const BIGNUM,
        a: *const BIGNUM,
        b: *const BIGNUM,
        _: *mut BN_CTX,
    ) -> libc::c_int;
    fn ec_GFp_simple_group_get_curve(
        _: *const EC_GROUP,
        p: *mut BIGNUM,
        a: *mut BIGNUM,
        b: *mut BIGNUM,
    ) -> libc::c_int;
    fn ec_GFp_simple_point_init(_: *mut EC_JACOBIAN);
    fn ec_GFp_simple_point_copy(_: *mut EC_JACOBIAN, _: *const EC_JACOBIAN);
    fn ec_GFp_simple_point_set_to_infinity(_: *const EC_GROUP, _: *mut EC_JACOBIAN);
    fn ec_GFp_simple_invert(_: *const EC_GROUP, _: *mut EC_JACOBIAN);
    fn ec_GFp_simple_is_at_infinity(
        _: *const EC_GROUP,
        _: *const EC_JACOBIAN,
    ) -> libc::c_int;
    fn ec_GFp_simple_is_on_curve(
        _: *const EC_GROUP,
        _: *const EC_JACOBIAN,
    ) -> libc::c_int;
    fn ec_GFp_simple_points_equal(
        _: *const EC_GROUP,
        a: *const EC_JACOBIAN,
        b: *const EC_JACOBIAN,
    ) -> libc::c_int;
    fn EC_GFp_nistp224_method() -> *const EC_METHOD;
    fn EC_GFp_nistp256_method() -> *const EC_METHOD;
    fn EC_GFp_nistp384_method() -> *const EC_METHOD;
    fn EC_GFp_nistp521_method() -> *const EC_METHOD;
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
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_memdup(data: *const libc::c_void, size: size_t) -> *mut libc::c_void;
    fn ERR_clear_error();
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn CRYPTO_once(
        once: *mut CRYPTO_once_t,
        init: Option::<unsafe extern "C" fn() -> ()>,
    );
    fn bn_set_static_words(bn: *mut BIGNUM, words: *const BN_ULONG, num: size_t);
    fn bn_reduce_once(
        r: *mut BN_ULONG,
        a: *const BN_ULONG,
        carry: BN_ULONG,
        m: *const BN_ULONG,
        num: size_t,
    ) -> BN_ULONG;
    fn bn_mont_ctx_init(mont: *mut BN_MONT_CTX);
    fn bn_mont_ctx_cleanup(mont: *mut BN_MONT_CTX);
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
pub type pthread_once_t = libc::c_int;
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
pub type CRYPTO_once_t = pthread_once_t;
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
pub struct static_assertion_at_line_1059_error_is_out_comb_does_not_span_the_entire_structure {
    #[bitfield(
        name = "static_assertion_at_line_1059_error_is_out_comb_does_not_span_the_entire_structure",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_1059_error_is_out_comb_does_not_span_the_entire_structure: [u8; 1],
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
#[inline]
unsafe extern "C" fn boringssl_ensure_ecc_self_test() {}
static mut kP224FieldN0: uint64_t = 0xffffffffffffffff as libc::c_ulong;
static mut kP224OrderN0: uint64_t = 0xd6e242706a1fc2eb as libc::c_ulong;
static mut kP224Field: [uint64_t; 4] = [
    0x1 as libc::c_int as uint64_t,
    0xffffffff00000000 as libc::c_ulong,
    0xffffffffffffffff as libc::c_ulong,
    0xffffffff as libc::c_uint as uint64_t,
];
static mut kP224Order: [uint64_t; 4] = [
    0x13dd29455c5c2a3d as libc::c_long as uint64_t,
    0xffff16a2e0b8f03e as libc::c_ulong,
    0xffffffffffffffff as libc::c_ulong,
    0xffffffff as libc::c_uint as uint64_t,
];
static mut kP224B: [uint64_t; 4] = [
    0x270b39432355ffb4 as libc::c_long as uint64_t,
    0x5044b0b7d7bfd8ba as libc::c_long as uint64_t,
    0xc04b3abf5413256 as libc::c_long as uint64_t,
    0xb4050a85 as libc::c_uint as uint64_t,
];
static mut kP224GX: [uint64_t; 4] = [
    0x343280d6115c1d21 as libc::c_long as uint64_t,
    0x4a03c1d356c21122 as libc::c_long as uint64_t,
    0x6bb4bf7f321390b9 as libc::c_long as uint64_t,
    0xb70e0cbd as libc::c_uint as uint64_t,
];
static mut kP224GY: [uint64_t; 4] = [
    0x44d5819985007e34 as libc::c_long as uint64_t,
    0xcd4375a05a074764 as libc::c_ulong,
    0xb5f723fb4c22dfe6 as libc::c_ulong,
    0xbd376388 as libc::c_uint as uint64_t,
];
static mut kP224FieldRR: [uint64_t; 4] = [
    0xffffffff00000001 as libc::c_ulong,
    0xffffffff00000000 as libc::c_ulong,
    0xfffffffe00000000 as libc::c_ulong,
    0xffffffff as libc::c_uint as uint64_t,
];
static mut kP224OrderRR: [uint64_t; 4] = [
    0x29947a695f517d15 as libc::c_long as uint64_t,
    0xabc8ff5931d63f4b as libc::c_ulong,
    0x6ad15f7cd9714856 as libc::c_long as uint64_t,
    0xb1e97961 as libc::c_uint as uint64_t,
];
static mut kP256FieldN0: uint64_t = 0x1 as libc::c_int as uint64_t;
static mut kP256OrderN0: uint64_t = 0xccd1c8aaee00bc4f as libc::c_ulong;
static mut kP256Field: [uint64_t; 4] = [
    0xffffffffffffffff as libc::c_ulong,
    0xffffffff as libc::c_uint as uint64_t,
    0 as libc::c_int as uint64_t,
    0xffffffff00000001 as libc::c_ulong,
];
static mut kP256Order: [uint64_t; 4] = [
    0xf3b9cac2fc632551 as libc::c_ulong,
    0xbce6faada7179e84 as libc::c_ulong,
    0xffffffffffffffff as libc::c_ulong,
    0xffffffff00000000 as libc::c_ulong,
];
static mut kP256FieldR: [uint64_t; 4] = [
    0x1 as libc::c_int as uint64_t,
    0xffffffff00000000 as libc::c_ulong,
    0xffffffffffffffff as libc::c_ulong,
    0xfffffffe as libc::c_uint as uint64_t,
];
static mut kP256FieldRR: [uint64_t; 4] = [
    0x3 as libc::c_int as uint64_t,
    0xfffffffbffffffff as libc::c_ulong,
    0xfffffffffffffffe as libc::c_ulong,
    0x4fffffffd as libc::c_long as uint64_t,
];
static mut kP256OrderRR: [uint64_t; 4] = [
    0x83244c95be79eea2 as libc::c_ulong,
    0x4699799c49bd6fa6 as libc::c_long as uint64_t,
    0x2845b2392b6bec59 as libc::c_long as uint64_t,
    0x66e12d94f3d95620 as libc::c_long as uint64_t,
];
static mut kP256MontB: [uint64_t; 4] = [
    0xd89cdf6229c4bddf as libc::c_ulong,
    0xacf005cd78843090 as libc::c_ulong,
    0xe5a220abf7212ed6 as libc::c_ulong,
    0xdc30061d04874834 as libc::c_ulong,
];
static mut kP256MontGX: [uint64_t; 4] = [
    0x79e730d418a9143c as libc::c_long as uint64_t,
    0x75ba95fc5fedb601 as libc::c_long as uint64_t,
    0x79fb732b77622510 as libc::c_long as uint64_t,
    0x18905f76a53755c6 as libc::c_long as uint64_t,
];
static mut kP256MontGY: [uint64_t; 4] = [
    0xddf25357ce95560a as libc::c_ulong,
    0x8b4ab8e4ba19e45c as libc::c_ulong,
    0xd2e88688dd21f325 as libc::c_ulong,
    0x8571ff1825885d85 as libc::c_ulong,
];
static mut kP384FieldN0: uint64_t = 0x100000001 as libc::c_long as uint64_t;
static mut kP384OrderN0: uint64_t = 0x6ed46089e88fdc45 as libc::c_long as uint64_t;
static mut kP384Field: [uint64_t; 6] = [
    0xffffffff as libc::c_uint as uint64_t,
    0xffffffff00000000 as libc::c_ulong,
    0xfffffffffffffffe as libc::c_ulong,
    0xffffffffffffffff as libc::c_ulong,
    0xffffffffffffffff as libc::c_ulong,
    0xffffffffffffffff as libc::c_ulong,
];
static mut kP384Order: [uint64_t; 6] = [
    0xecec196accc52973 as libc::c_ulong,
    0x581a0db248b0a77a as libc::c_long as uint64_t,
    0xc7634d81f4372ddf as libc::c_ulong,
    0xffffffffffffffff as libc::c_ulong,
    0xffffffffffffffff as libc::c_ulong,
    0xffffffffffffffff as libc::c_ulong,
];
static mut kP384FieldR: [uint64_t; 6] = [
    0xffffffff00000001 as libc::c_ulong,
    0xffffffff as libc::c_uint as uint64_t,
    0x1 as libc::c_int as uint64_t,
    0 as libc::c_int as uint64_t,
    0 as libc::c_int as uint64_t,
    0 as libc::c_int as uint64_t,
];
static mut kP384FieldRR: [uint64_t; 6] = [
    0xfffffffe00000001 as libc::c_ulong,
    0x200000000 as libc::c_long as uint64_t,
    0xfffffffe00000000 as libc::c_ulong,
    0x200000000 as libc::c_long as uint64_t,
    0x1 as libc::c_int as uint64_t,
    0 as libc::c_int as uint64_t,
];
static mut kP384OrderRR: [uint64_t; 6] = [
    0x2d319b2419b409a9 as libc::c_long as uint64_t,
    0xff3d81e5df1aa419 as libc::c_ulong,
    0xbc3e483afcb82947 as libc::c_ulong,
    0xd40d49174aab1cc5 as libc::c_ulong,
    0x3fb05b7a28266895 as libc::c_long as uint64_t,
    0xc84ee012b39bf21 as libc::c_long as uint64_t,
];
static mut kP384MontB: [uint64_t; 6] = [
    0x81188719d412dcc as libc::c_long as uint64_t,
    0xf729add87a4c32ec as libc::c_ulong,
    0x77f2209b1920022e as libc::c_long as uint64_t,
    0xe3374bee94938ae2 as libc::c_ulong,
    0xb62b21f41f022094 as libc::c_ulong,
    0xcd08114b604fbff9 as libc::c_ulong,
];
static mut kP384MontGX: [uint64_t; 6] = [
    0x3dd0756649c0b528 as libc::c_long as uint64_t,
    0x20e378e2a0d6ce38 as libc::c_long as uint64_t,
    0x879c3afc541b4d6e as libc::c_ulong,
    0x6454868459a30eff as libc::c_long as uint64_t,
    0x812ff723614ede2b as libc::c_ulong,
    0x4d3aadc2299e1513 as libc::c_long as uint64_t,
];
static mut kP384MontGY: [uint64_t; 6] = [
    0x23043dad4b03a4fe as libc::c_long as uint64_t,
    0xa1bfa8bf7bb4a9ac as libc::c_ulong,
    0x8bade7562e83b050 as libc::c_ulong,
    0xc6c3521968f4ffd9 as libc::c_ulong,
    0xdd8002263969a840 as libc::c_ulong,
    0x2b78abc25a15c5e9 as libc::c_long as uint64_t,
];
static mut kP521FieldN0: uint64_t = 0x1 as libc::c_int as uint64_t;
static mut kP521OrderN0: uint64_t = 0x1d2f5ccd79a995c7 as libc::c_long as uint64_t;
static mut kP521Field: [uint64_t; 9] = [
    0xffffffffffffffff as libc::c_ulong,
    0xffffffffffffffff as libc::c_ulong,
    0xffffffffffffffff as libc::c_ulong,
    0xffffffffffffffff as libc::c_ulong,
    0xffffffffffffffff as libc::c_ulong,
    0xffffffffffffffff as libc::c_ulong,
    0xffffffffffffffff as libc::c_ulong,
    0xffffffffffffffff as libc::c_ulong,
    0x1ff as libc::c_int as uint64_t,
];
static mut kP521Order: [uint64_t; 9] = [
    0xbb6fb71e91386409 as libc::c_ulong,
    0x3bb5c9b8899c47ae as libc::c_long as uint64_t,
    0x7fcc0148f709a5d0 as libc::c_long as uint64_t,
    0x51868783bf2f966b as libc::c_long as uint64_t,
    0xfffffffffffffffa as libc::c_ulong,
    0xffffffffffffffff as libc::c_ulong,
    0xffffffffffffffff as libc::c_ulong,
    0xffffffffffffffff as libc::c_ulong,
    0x1ff as libc::c_int as uint64_t,
];
static mut kP521B: [uint64_t; 9] = [
    0xef451fd46b503f00 as libc::c_ulong,
    0x3573df883d2c34f1 as libc::c_long as uint64_t,
    0x1652c0bd3bb1bf07 as libc::c_long as uint64_t,
    0x56193951ec7e937b as libc::c_long as uint64_t,
    0xb8b489918ef109e1 as libc::c_ulong,
    0xa2da725b99b315f3 as libc::c_ulong,
    0x929a21a0b68540ee as libc::c_ulong,
    0x953eb9618e1c9a1f as libc::c_ulong,
    0x51 as libc::c_int as uint64_t,
];
static mut kP521GX: [uint64_t; 9] = [
    0xf97e7e31c2e5bd66 as libc::c_ulong,
    0x3348b3c1856a429b as libc::c_long as uint64_t,
    0xfe1dc127a2ffa8de as libc::c_ulong,
    0xa14b5e77efe75928 as libc::c_ulong,
    0xf828af606b4d3dba as libc::c_ulong,
    0x9c648139053fb521 as libc::c_ulong,
    0x9e3ecb662395b442 as libc::c_ulong,
    0x858e06b70404e9cd as libc::c_ulong,
    0xc6 as libc::c_int as uint64_t,
];
static mut kP521GY: [uint64_t; 9] = [
    0x88be94769fd16650 as libc::c_ulong,
    0x353c7086a272c240 as libc::c_long as uint64_t,
    0xc550b9013fad0761 as libc::c_ulong,
    0x97ee72995ef42640 as libc::c_ulong,
    0x17afbd17273e662c as libc::c_long as uint64_t,
    0x98f54449579b4468 as libc::c_ulong,
    0x5c8a5fb42c7d1bd9 as libc::c_long as uint64_t,
    0x39296a789a3bc004 as libc::c_long as uint64_t,
    0x118 as libc::c_int as uint64_t,
];
static mut kP521FieldRR: [uint64_t; 9] = [
    0 as libc::c_int as uint64_t,
    0x400000000000 as libc::c_long as uint64_t,
    0 as libc::c_int as uint64_t,
    0 as libc::c_int as uint64_t,
    0 as libc::c_int as uint64_t,
    0 as libc::c_int as uint64_t,
    0 as libc::c_int as uint64_t,
    0 as libc::c_int as uint64_t,
    0 as libc::c_int as uint64_t,
];
static mut kP521OrderRR: [uint64_t; 9] = [
    0x137cd04dcf15dd04 as libc::c_long as uint64_t,
    0xf707badce5547ea3 as libc::c_ulong,
    0x12a78d38794573ff as libc::c_long as uint64_t,
    0xd3721ef557f75e06 as libc::c_ulong,
    0xdd6e23d82e49c7db as libc::c_ulong,
    0xcff3d142b7756e3e as libc::c_ulong,
    0x5bcc6d61a8e567bc as libc::c_long as uint64_t,
    0x2d8e03d1492d0d45 as libc::c_long as uint64_t,
    0x3d as libc::c_int as uint64_t,
];
static mut ksecp256k1FieldN0: uint64_t = 0xd838091dd2253531 as libc::c_ulong;
static mut ksecp256k1OrderN0: uint64_t = 0x4b0dff665588b13f as libc::c_long as uint64_t;
static mut ksecp256k1Field: [uint64_t; 4] = [
    0xfffffffefffffc2f as libc::c_ulong,
    0xffffffffffffffff as libc::c_ulong,
    0xffffffffffffffff as libc::c_ulong,
    0xffffffffffffffff as libc::c_ulong,
];
static mut ksecp256k1Order: [uint64_t; 4] = [
    0xbfd25e8cd0364141 as libc::c_ulong,
    0xbaaedce6af48a03b as libc::c_ulong,
    0xfffffffffffffffe as libc::c_ulong,
    0xffffffffffffffff as libc::c_ulong,
];
static mut ksecp256k1FieldR: [uint64_t; 4] = [
    0x1000003d1 as libc::c_long as uint64_t,
    0 as libc::c_int as uint64_t,
    0 as libc::c_int as uint64_t,
    0 as libc::c_int as uint64_t,
];
static mut ksecp256k1FieldRR: [uint64_t; 4] = [
    0x7a2000e90a1 as libc::c_long as uint64_t,
    0x1 as libc::c_int as uint64_t,
    0 as libc::c_int as uint64_t,
    0 as libc::c_int as uint64_t,
];
static mut ksecp256k1OrderRR: [uint64_t; 4] = [
    0x896cf21467d7d140 as libc::c_ulong,
    0x741496c20e7cf878 as libc::c_long as uint64_t,
    0xe697f5e45bcd07c6 as libc::c_ulong,
    0x9d671cd581c69bc5 as libc::c_ulong,
];
static mut ksecp256k1MontB: [uint64_t; 4] = [
    0x700001ab7 as libc::c_long as uint64_t,
    0 as libc::c_int as uint64_t,
    0 as libc::c_int as uint64_t,
    0 as libc::c_int as uint64_t,
];
static mut ksecp256k1MontGX: [uint64_t; 4] = [
    0xd7362e5a487e2097 as libc::c_ulong,
    0x231e295329bc66db as libc::c_long as uint64_t,
    0x979f48c033fd129c as libc::c_ulong,
    0x9981e643e9089f48 as libc::c_ulong,
];
static mut ksecp256k1MontGY: [uint64_t; 4] = [
    0xb15ea6d2d3dbabe2 as libc::c_ulong,
    0x8dfc5d5d1f1dc64d as libc::c_ulong,
    0x70b6b59aac19c136 as libc::c_long as uint64_t,
    0xcf3f851fd4a582d6 as libc::c_ulong,
];
unsafe extern "C" fn ec_group_init_static_mont(
    mut mont: *mut BN_MONT_CTX,
    mut num_words: size_t,
    mut modulus: *const BN_ULONG,
    mut rr: *const BN_ULONG,
    mut n0: uint64_t,
) {
    bn_set_static_words(&mut (*mont).N, modulus, num_words);
    bn_set_static_words(&mut (*mont).RR, rr, num_words);
    (*mont).n0[0 as libc::c_int as usize] = n0;
}
unsafe extern "C" fn ec_group_set_a_minus3(mut group: *mut EC_GROUP) {
    let mut one: *const EC_FELEM = ec_felem_one(group);
    (*group).a_is_minus3 = 1 as libc::c_int;
    ec_felem_neg(group, &mut (*group).a, one);
    ec_felem_sub(group, &mut (*group).a, &mut (*group).a, one);
    ec_felem_sub(group, &mut (*group).a, &mut (*group).a, one);
}
unsafe extern "C" fn ec_group_set_a_zero(mut group: *mut EC_GROUP) {
    (*group).a_is_minus3 = 0 as libc::c_int;
    OPENSSL_memset(
        ((*group).a.words).as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EC_FELEM>() as libc::c_ulong,
    );
}
static mut EC_group_p224_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EC_group_p224_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EC_group_p224_once;
}
unsafe extern "C" fn EC_group_p224_do_init(mut out: *mut EC_GROUP) {
    (*out).curve_name = 713 as libc::c_int;
    (*out).comment = b"NIST P-224\0" as *const u8 as *const libc::c_char;
    static mut kOIDP224: [uint8_t; 5] = [
        0x2b as libc::c_int as uint8_t,
        0x81 as libc::c_int as uint8_t,
        0x4 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0x21 as libc::c_int as uint8_t,
    ];
    OPENSSL_memcpy(
        ((*out).oid).as_mut_ptr() as *mut libc::c_void,
        kOIDP224.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint8_t; 5]>() as libc::c_ulong,
    );
    (*out).oid_len = ::core::mem::size_of::<[uint8_t; 5]>() as libc::c_ulong as uint8_t;
    ec_group_init_static_mont(
        &mut (*out).field,
        (::core::mem::size_of::<[uint64_t; 4]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<uint64_t>() as libc::c_ulong),
        kP224Field.as_ptr(),
        kP224FieldRR.as_ptr(),
        kP224FieldN0,
    );
    ec_group_init_static_mont(
        &mut (*out).order,
        (::core::mem::size_of::<[uint64_t; 4]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<uint64_t>() as libc::c_ulong),
        kP224Order.as_ptr(),
        kP224OrderRR.as_ptr(),
        kP224OrderN0,
    );
    (*out).meth = EC_GFp_nistp224_method();
    OPENSSL_memcpy(
        ((*out).generator.raw.X.words).as_mut_ptr() as *mut libc::c_void,
        kP224GX.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint64_t; 4]>() as libc::c_ulong,
    );
    OPENSSL_memcpy(
        ((*out).generator.raw.Y.words).as_mut_ptr() as *mut libc::c_void,
        kP224GY.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint64_t; 4]>() as libc::c_ulong,
    );
    (*out)
        .generator
        .raw
        .Z
        .words[0 as libc::c_int as usize] = 1 as libc::c_int as BN_ULONG;
    OPENSSL_memcpy(
        ((*out).b.words).as_mut_ptr() as *mut libc::c_void,
        kP224B.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint64_t; 4]>() as libc::c_ulong,
    );
    (*out).generator.group = out;
    ec_group_set_a_minus3(out);
    (*out).has_order = 1 as libc::c_int;
    (*out).field_greater_than_order = 1 as libc::c_int;
    (*out).conv_form = POINT_CONVERSION_UNCOMPRESSED;
    (*out).mutable_ec_group = 0 as libc::c_int;
}
unsafe extern "C" fn EC_group_p224_storage_bss_get() -> *mut EC_GROUP {
    return &mut EC_group_p224_storage;
}
static mut EC_group_p224_storage: EC_GROUP = ec_group_st {
    meth: 0 as *const EC_METHOD,
    generator: ec_point_st {
        group: 0 as *const EC_GROUP as *mut EC_GROUP,
        raw: EC_JACOBIAN {
            X: EC_FELEM { words: [0; 9] },
            Y: EC_FELEM { words: [0; 9] },
            Z: EC_FELEM { words: [0; 9] },
        },
    },
    order: bn_mont_ctx_st {
        RR: bignum_st {
            d: 0 as *const BN_ULONG as *mut BN_ULONG,
            width: 0,
            dmax: 0,
            neg: 0,
            flags: 0,
        },
        N: bignum_st {
            d: 0 as *const BN_ULONG as *mut BN_ULONG,
            width: 0,
            dmax: 0,
            neg: 0,
            flags: 0,
        },
        n0: [0; 2],
    },
    field: bn_mont_ctx_st {
        RR: bignum_st {
            d: 0 as *const BN_ULONG as *mut BN_ULONG,
            width: 0,
            dmax: 0,
            neg: 0,
            flags: 0,
        },
        N: bignum_st {
            d: 0 as *const BN_ULONG as *mut BN_ULONG,
            width: 0,
            dmax: 0,
            neg: 0,
            flags: 0,
        },
        n0: [0; 2],
    },
    a: EC_FELEM { words: [0; 9] },
    b: EC_FELEM { words: [0; 9] },
    comment: 0 as *const libc::c_char,
    curve_name: 0,
    oid: [0; 9],
    oid_len: 0,
    a_is_minus3: 0,
    has_order: 0,
    field_greater_than_order: 0,
    conv_form: 0 as point_conversion_form_t,
    mutable_ec_group: 0,
};
unsafe extern "C" fn EC_group_p224_init() {
    EC_group_p224_do_init(EC_group_p224_storage_bss_get());
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_group_p224() -> *const EC_GROUP {
    CRYPTO_once(
        EC_group_p224_once_bss_get(),
        Some(EC_group_p224_init as unsafe extern "C" fn() -> ()),
    );
    return EC_group_p224_storage_bss_get() as *const EC_GROUP;
}
static mut EC_group_p256_once: CRYPTO_once_t = 0 as libc::c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_group_p256() -> *const EC_GROUP {
    CRYPTO_once(
        EC_group_p256_once_bss_get(),
        Some(EC_group_p256_init as unsafe extern "C" fn() -> ()),
    );
    return EC_group_p256_storage_bss_get() as *const EC_GROUP;
}
unsafe extern "C" fn EC_group_p256_storage_bss_get() -> *mut EC_GROUP {
    return &mut EC_group_p256_storage;
}
static mut EC_group_p256_storage: EC_GROUP = ec_group_st {
    meth: 0 as *const EC_METHOD,
    generator: ec_point_st {
        group: 0 as *const EC_GROUP as *mut EC_GROUP,
        raw: EC_JACOBIAN {
            X: EC_FELEM { words: [0; 9] },
            Y: EC_FELEM { words: [0; 9] },
            Z: EC_FELEM { words: [0; 9] },
        },
    },
    order: bn_mont_ctx_st {
        RR: bignum_st {
            d: 0 as *const BN_ULONG as *mut BN_ULONG,
            width: 0,
            dmax: 0,
            neg: 0,
            flags: 0,
        },
        N: bignum_st {
            d: 0 as *const BN_ULONG as *mut BN_ULONG,
            width: 0,
            dmax: 0,
            neg: 0,
            flags: 0,
        },
        n0: [0; 2],
    },
    field: bn_mont_ctx_st {
        RR: bignum_st {
            d: 0 as *const BN_ULONG as *mut BN_ULONG,
            width: 0,
            dmax: 0,
            neg: 0,
            flags: 0,
        },
        N: bignum_st {
            d: 0 as *const BN_ULONG as *mut BN_ULONG,
            width: 0,
            dmax: 0,
            neg: 0,
            flags: 0,
        },
        n0: [0; 2],
    },
    a: EC_FELEM { words: [0; 9] },
    b: EC_FELEM { words: [0; 9] },
    comment: 0 as *const libc::c_char,
    curve_name: 0,
    oid: [0; 9],
    oid_len: 0,
    a_is_minus3: 0,
    has_order: 0,
    field_greater_than_order: 0,
    conv_form: 0 as point_conversion_form_t,
    mutable_ec_group: 0,
};
unsafe extern "C" fn EC_group_p256_init() {
    EC_group_p256_do_init(EC_group_p256_storage_bss_get());
}
unsafe extern "C" fn EC_group_p256_do_init(mut out: *mut EC_GROUP) {
    (*out).curve_name = 415 as libc::c_int;
    (*out).comment = b"NIST P-256\0" as *const u8 as *const libc::c_char;
    static mut kOIDP256: [uint8_t; 8] = [
        0x2a as libc::c_int as uint8_t,
        0x86 as libc::c_int as uint8_t,
        0x48 as libc::c_int as uint8_t,
        0xce as libc::c_int as uint8_t,
        0x3d as libc::c_int as uint8_t,
        0x3 as libc::c_int as uint8_t,
        0x1 as libc::c_int as uint8_t,
        0x7 as libc::c_int as uint8_t,
    ];
    OPENSSL_memcpy(
        ((*out).oid).as_mut_ptr() as *mut libc::c_void,
        kOIDP256.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint8_t; 8]>() as libc::c_ulong,
    );
    (*out).oid_len = ::core::mem::size_of::<[uint8_t; 8]>() as libc::c_ulong as uint8_t;
    ec_group_init_static_mont(
        &mut (*out).field,
        (::core::mem::size_of::<[uint64_t; 4]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<uint64_t>() as libc::c_ulong),
        kP256Field.as_ptr(),
        kP256FieldRR.as_ptr(),
        kP256FieldN0,
    );
    ec_group_init_static_mont(
        &mut (*out).order,
        (::core::mem::size_of::<[uint64_t; 4]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<uint64_t>() as libc::c_ulong),
        kP256Order.as_ptr(),
        kP256OrderRR.as_ptr(),
        kP256OrderN0,
    );
    (*out).meth = EC_GFp_nistp256_method();
    (*out).generator.group = out;
    OPENSSL_memcpy(
        ((*out).generator.raw.X.words).as_mut_ptr() as *mut libc::c_void,
        kP256MontGX.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint64_t; 4]>() as libc::c_ulong,
    );
    OPENSSL_memcpy(
        ((*out).generator.raw.Y.words).as_mut_ptr() as *mut libc::c_void,
        kP256MontGY.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint64_t; 4]>() as libc::c_ulong,
    );
    OPENSSL_memcpy(
        ((*out).generator.raw.Z.words).as_mut_ptr() as *mut libc::c_void,
        kP256FieldR.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint64_t; 4]>() as libc::c_ulong,
    );
    OPENSSL_memcpy(
        ((*out).b.words).as_mut_ptr() as *mut libc::c_void,
        kP256MontB.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint64_t; 4]>() as libc::c_ulong,
    );
    ec_group_set_a_minus3(out);
    (*out).has_order = 1 as libc::c_int;
    (*out).field_greater_than_order = 1 as libc::c_int;
    (*out).conv_form = POINT_CONVERSION_UNCOMPRESSED;
    (*out).mutable_ec_group = 0 as libc::c_int;
}
unsafe extern "C" fn EC_group_p256_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EC_group_p256_once;
}
unsafe extern "C" fn EC_group_p384_init() {
    EC_group_p384_do_init(EC_group_p384_storage_bss_get());
}
static mut EC_group_p384_storage: EC_GROUP = ec_group_st {
    meth: 0 as *const EC_METHOD,
    generator: ec_point_st {
        group: 0 as *const EC_GROUP as *mut EC_GROUP,
        raw: EC_JACOBIAN {
            X: EC_FELEM { words: [0; 9] },
            Y: EC_FELEM { words: [0; 9] },
            Z: EC_FELEM { words: [0; 9] },
        },
    },
    order: bn_mont_ctx_st {
        RR: bignum_st {
            d: 0 as *const BN_ULONG as *mut BN_ULONG,
            width: 0,
            dmax: 0,
            neg: 0,
            flags: 0,
        },
        N: bignum_st {
            d: 0 as *const BN_ULONG as *mut BN_ULONG,
            width: 0,
            dmax: 0,
            neg: 0,
            flags: 0,
        },
        n0: [0; 2],
    },
    field: bn_mont_ctx_st {
        RR: bignum_st {
            d: 0 as *const BN_ULONG as *mut BN_ULONG,
            width: 0,
            dmax: 0,
            neg: 0,
            flags: 0,
        },
        N: bignum_st {
            d: 0 as *const BN_ULONG as *mut BN_ULONG,
            width: 0,
            dmax: 0,
            neg: 0,
            flags: 0,
        },
        n0: [0; 2],
    },
    a: EC_FELEM { words: [0; 9] },
    b: EC_FELEM { words: [0; 9] },
    comment: 0 as *const libc::c_char,
    curve_name: 0,
    oid: [0; 9],
    oid_len: 0,
    a_is_minus3: 0,
    has_order: 0,
    field_greater_than_order: 0,
    conv_form: 0 as point_conversion_form_t,
    mutable_ec_group: 0,
};
unsafe extern "C" fn EC_group_p384_do_init(mut out: *mut EC_GROUP) {
    (*out).curve_name = 715 as libc::c_int;
    (*out).comment = b"NIST P-384\0" as *const u8 as *const libc::c_char;
    static mut kOIDP384: [uint8_t; 5] = [
        0x2b as libc::c_int as uint8_t,
        0x81 as libc::c_int as uint8_t,
        0x4 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0x22 as libc::c_int as uint8_t,
    ];
    OPENSSL_memcpy(
        ((*out).oid).as_mut_ptr() as *mut libc::c_void,
        kOIDP384.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint8_t; 5]>() as libc::c_ulong,
    );
    (*out).oid_len = ::core::mem::size_of::<[uint8_t; 5]>() as libc::c_ulong as uint8_t;
    ec_group_init_static_mont(
        &mut (*out).field,
        (::core::mem::size_of::<[uint64_t; 6]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<uint64_t>() as libc::c_ulong),
        kP384Field.as_ptr(),
        kP384FieldRR.as_ptr(),
        kP384FieldN0,
    );
    ec_group_init_static_mont(
        &mut (*out).order,
        (::core::mem::size_of::<[uint64_t; 6]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<uint64_t>() as libc::c_ulong),
        kP384Order.as_ptr(),
        kP384OrderRR.as_ptr(),
        kP384OrderN0,
    );
    (*out).meth = EC_GFp_nistp384_method();
    (*out).generator.group = out;
    OPENSSL_memcpy(
        ((*out).generator.raw.X.words).as_mut_ptr() as *mut libc::c_void,
        kP384MontGX.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint64_t; 6]>() as libc::c_ulong,
    );
    OPENSSL_memcpy(
        ((*out).generator.raw.Y.words).as_mut_ptr() as *mut libc::c_void,
        kP384MontGY.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint64_t; 6]>() as libc::c_ulong,
    );
    OPENSSL_memcpy(
        ((*out).generator.raw.Z.words).as_mut_ptr() as *mut libc::c_void,
        kP384FieldR.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint64_t; 6]>() as libc::c_ulong,
    );
    OPENSSL_memcpy(
        ((*out).b.words).as_mut_ptr() as *mut libc::c_void,
        kP384MontB.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint64_t; 6]>() as libc::c_ulong,
    );
    ec_group_set_a_minus3(out);
    (*out).has_order = 1 as libc::c_int;
    (*out).field_greater_than_order = 1 as libc::c_int;
    (*out).conv_form = POINT_CONVERSION_UNCOMPRESSED;
    (*out).mutable_ec_group = 0 as libc::c_int;
}
unsafe extern "C" fn EC_group_p384_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EC_group_p384_once;
}
static mut EC_group_p384_once: CRYPTO_once_t = 0 as libc::c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_group_p384() -> *const EC_GROUP {
    CRYPTO_once(
        EC_group_p384_once_bss_get(),
        Some(EC_group_p384_init as unsafe extern "C" fn() -> ()),
    );
    return EC_group_p384_storage_bss_get() as *const EC_GROUP;
}
unsafe extern "C" fn EC_group_p384_storage_bss_get() -> *mut EC_GROUP {
    return &mut EC_group_p384_storage;
}
unsafe extern "C" fn EC_group_p521_storage_bss_get() -> *mut EC_GROUP {
    return &mut EC_group_p521_storage;
}
unsafe extern "C" fn EC_group_p521_do_init(mut out: *mut EC_GROUP) {
    (*out).curve_name = 716 as libc::c_int;
    (*out).comment = b"NIST P-521\0" as *const u8 as *const libc::c_char;
    static mut kOIDP521: [uint8_t; 5] = [
        0x2b as libc::c_int as uint8_t,
        0x81 as libc::c_int as uint8_t,
        0x4 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0x23 as libc::c_int as uint8_t,
    ];
    OPENSSL_memcpy(
        ((*out).oid).as_mut_ptr() as *mut libc::c_void,
        kOIDP521.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint8_t; 5]>() as libc::c_ulong,
    );
    (*out).oid_len = ::core::mem::size_of::<[uint8_t; 5]>() as libc::c_ulong as uint8_t;
    ec_group_init_static_mont(
        &mut (*out).field,
        (::core::mem::size_of::<[uint64_t; 9]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<uint64_t>() as libc::c_ulong),
        kP521Field.as_ptr(),
        kP521FieldRR.as_ptr(),
        kP521FieldN0,
    );
    ec_group_init_static_mont(
        &mut (*out).order,
        (::core::mem::size_of::<[uint64_t; 9]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<uint64_t>() as libc::c_ulong),
        kP521Order.as_ptr(),
        kP521OrderRR.as_ptr(),
        kP521OrderN0,
    );
    (*out).meth = EC_GFp_nistp521_method();
    OPENSSL_memcpy(
        ((*out).generator.raw.X.words).as_mut_ptr() as *mut libc::c_void,
        kP521GX.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint64_t; 9]>() as libc::c_ulong,
    );
    OPENSSL_memcpy(
        ((*out).generator.raw.Y.words).as_mut_ptr() as *mut libc::c_void,
        kP521GY.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint64_t; 9]>() as libc::c_ulong,
    );
    (*out)
        .generator
        .raw
        .Z
        .words[0 as libc::c_int as usize] = 1 as libc::c_int as BN_ULONG;
    OPENSSL_memcpy(
        ((*out).b.words).as_mut_ptr() as *mut libc::c_void,
        kP521B.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint64_t; 9]>() as libc::c_ulong,
    );
    (*out).generator.group = out;
    ec_group_set_a_minus3(out);
    (*out).has_order = 1 as libc::c_int;
    (*out).field_greater_than_order = 1 as libc::c_int;
    (*out).conv_form = POINT_CONVERSION_UNCOMPRESSED;
    (*out).mutable_ec_group = 0 as libc::c_int;
}
unsafe extern "C" fn EC_group_p521_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EC_group_p521_once;
}
unsafe extern "C" fn EC_group_p521_init() {
    EC_group_p521_do_init(EC_group_p521_storage_bss_get());
}
static mut EC_group_p521_once: CRYPTO_once_t = 0 as libc::c_int;
static mut EC_group_p521_storage: EC_GROUP = ec_group_st {
    meth: 0 as *const EC_METHOD,
    generator: ec_point_st {
        group: 0 as *const EC_GROUP as *mut EC_GROUP,
        raw: EC_JACOBIAN {
            X: EC_FELEM { words: [0; 9] },
            Y: EC_FELEM { words: [0; 9] },
            Z: EC_FELEM { words: [0; 9] },
        },
    },
    order: bn_mont_ctx_st {
        RR: bignum_st {
            d: 0 as *const BN_ULONG as *mut BN_ULONG,
            width: 0,
            dmax: 0,
            neg: 0,
            flags: 0,
        },
        N: bignum_st {
            d: 0 as *const BN_ULONG as *mut BN_ULONG,
            width: 0,
            dmax: 0,
            neg: 0,
            flags: 0,
        },
        n0: [0; 2],
    },
    field: bn_mont_ctx_st {
        RR: bignum_st {
            d: 0 as *const BN_ULONG as *mut BN_ULONG,
            width: 0,
            dmax: 0,
            neg: 0,
            flags: 0,
        },
        N: bignum_st {
            d: 0 as *const BN_ULONG as *mut BN_ULONG,
            width: 0,
            dmax: 0,
            neg: 0,
            flags: 0,
        },
        n0: [0; 2],
    },
    a: EC_FELEM { words: [0; 9] },
    b: EC_FELEM { words: [0; 9] },
    comment: 0 as *const libc::c_char,
    curve_name: 0,
    oid: [0; 9],
    oid_len: 0,
    a_is_minus3: 0,
    has_order: 0,
    field_greater_than_order: 0,
    conv_form: 0 as point_conversion_form_t,
    mutable_ec_group: 0,
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_group_p521() -> *const EC_GROUP {
    CRYPTO_once(
        EC_group_p521_once_bss_get(),
        Some(EC_group_p521_init as unsafe extern "C" fn() -> ()),
    );
    return EC_group_p521_storage_bss_get() as *const EC_GROUP;
}
static mut EC_group_secp256k1_storage: EC_GROUP = ec_group_st {
    meth: 0 as *const EC_METHOD,
    generator: ec_point_st {
        group: 0 as *const EC_GROUP as *mut EC_GROUP,
        raw: EC_JACOBIAN {
            X: EC_FELEM { words: [0; 9] },
            Y: EC_FELEM { words: [0; 9] },
            Z: EC_FELEM { words: [0; 9] },
        },
    },
    order: bn_mont_ctx_st {
        RR: bignum_st {
            d: 0 as *const BN_ULONG as *mut BN_ULONG,
            width: 0,
            dmax: 0,
            neg: 0,
            flags: 0,
        },
        N: bignum_st {
            d: 0 as *const BN_ULONG as *mut BN_ULONG,
            width: 0,
            dmax: 0,
            neg: 0,
            flags: 0,
        },
        n0: [0; 2],
    },
    field: bn_mont_ctx_st {
        RR: bignum_st {
            d: 0 as *const BN_ULONG as *mut BN_ULONG,
            width: 0,
            dmax: 0,
            neg: 0,
            flags: 0,
        },
        N: bignum_st {
            d: 0 as *const BN_ULONG as *mut BN_ULONG,
            width: 0,
            dmax: 0,
            neg: 0,
            flags: 0,
        },
        n0: [0; 2],
    },
    a: EC_FELEM { words: [0; 9] },
    b: EC_FELEM { words: [0; 9] },
    comment: 0 as *const libc::c_char,
    curve_name: 0,
    oid: [0; 9],
    oid_len: 0,
    a_is_minus3: 0,
    has_order: 0,
    field_greater_than_order: 0,
    conv_form: 0 as point_conversion_form_t,
    mutable_ec_group: 0,
};
unsafe extern "C" fn EC_group_secp256k1_storage_bss_get() -> *mut EC_GROUP {
    return &mut EC_group_secp256k1_storage;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_group_secp256k1() -> *const EC_GROUP {
    CRYPTO_once(
        EC_group_secp256k1_once_bss_get(),
        Some(EC_group_secp256k1_init as unsafe extern "C" fn() -> ()),
    );
    return EC_group_secp256k1_storage_bss_get() as *const EC_GROUP;
}
unsafe extern "C" fn EC_group_secp256k1_init() {
    EC_group_secp256k1_do_init(EC_group_secp256k1_storage_bss_get());
}
unsafe extern "C" fn EC_group_secp256k1_do_init(mut out: *mut EC_GROUP) {
    (*out).curve_name = 714 as libc::c_int;
    (*out).comment = b"secp256k1\0" as *const u8 as *const libc::c_char;
    static mut kOIDP256K1: [uint8_t; 5] = [
        0x2b as libc::c_int as uint8_t,
        0x81 as libc::c_int as uint8_t,
        0x4 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0xa as libc::c_int as uint8_t,
    ];
    OPENSSL_memcpy(
        ((*out).oid).as_mut_ptr() as *mut libc::c_void,
        kOIDP256K1.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint8_t; 5]>() as libc::c_ulong,
    );
    (*out).oid_len = ::core::mem::size_of::<[uint8_t; 5]>() as libc::c_ulong as uint8_t;
    ec_group_init_static_mont(
        &mut (*out).field,
        (::core::mem::size_of::<[uint64_t; 4]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<uint64_t>() as libc::c_ulong),
        ksecp256k1Field.as_ptr(),
        ksecp256k1FieldRR.as_ptr(),
        ksecp256k1FieldN0,
    );
    ec_group_init_static_mont(
        &mut (*out).order,
        (::core::mem::size_of::<[uint64_t; 4]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<uint64_t>() as libc::c_ulong),
        ksecp256k1Order.as_ptr(),
        ksecp256k1OrderRR.as_ptr(),
        ksecp256k1OrderN0,
    );
    (*out).meth = EC_GFp_mont_method();
    (*out).generator.group = out;
    OPENSSL_memcpy(
        ((*out).generator.raw.X.words).as_mut_ptr() as *mut libc::c_void,
        ksecp256k1MontGX.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint64_t; 4]>() as libc::c_ulong,
    );
    OPENSSL_memcpy(
        ((*out).generator.raw.Y.words).as_mut_ptr() as *mut libc::c_void,
        ksecp256k1MontGY.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint64_t; 4]>() as libc::c_ulong,
    );
    OPENSSL_memcpy(
        ((*out).generator.raw.Z.words).as_mut_ptr() as *mut libc::c_void,
        ksecp256k1FieldR.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint64_t; 4]>() as libc::c_ulong,
    );
    OPENSSL_memcpy(
        ((*out).b.words).as_mut_ptr() as *mut libc::c_void,
        ksecp256k1MontB.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint64_t; 4]>() as libc::c_ulong,
    );
    ec_group_set_a_zero(out);
    (*out).has_order = 1 as libc::c_int;
    (*out).field_greater_than_order = 1 as libc::c_int;
    (*out).conv_form = POINT_CONVERSION_UNCOMPRESSED;
    (*out).mutable_ec_group = 0 as libc::c_int;
}
unsafe extern "C" fn EC_group_secp256k1_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EC_group_secp256k1_once;
}
static mut EC_group_secp256k1_once: CRYPTO_once_t = 0 as libc::c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_GROUP_new_curve_GFp(
    mut p: *const BIGNUM,
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> *mut EC_GROUP {
    if BN_num_bytes(p) > 66 as libc::c_int as libc::c_uint {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            110 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            284 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EC_GROUP;
    }
    let mut new_ctx: *mut BN_CTX = 0 as *mut BN_CTX;
    if ctx.is_null() {
        new_ctx = BN_CTX_new();
        ctx = new_ctx;
        if ctx.is_null() {
            return 0 as *mut EC_GROUP;
        }
    }
    let mut ret: *mut EC_GROUP = 0 as *mut EC_GROUP;
    BN_CTX_start(ctx);
    let mut a_reduced: *mut BIGNUM = BN_CTX_get(ctx);
    let mut b_reduced: *mut BIGNUM = BN_CTX_get(ctx);
    if !(a_reduced.is_null() || b_reduced.is_null()
        || BN_nnmod(a_reduced, a, p, ctx) == 0 || BN_nnmod(b_reduced, b, p, ctx) == 0)
    {
        ret = OPENSSL_zalloc(::core::mem::size_of::<EC_GROUP>() as libc::c_ulong)
            as *mut EC_GROUP;
        if ret.is_null() {
            return 0 as *mut EC_GROUP;
        }
        (*ret).mutable_ec_group = 1 as libc::c_int;
        (*ret).conv_form = POINT_CONVERSION_UNCOMPRESSED;
        (*ret).meth = EC_GFp_mont_method();
        bn_mont_ctx_init(&mut (*ret).field);
        bn_mont_ctx_init(&mut (*ret).order);
        (*ret).generator.group = ret;
        if ec_GFp_simple_group_set_curve(ret, p, a_reduced, b_reduced, ctx) == 0 {
            EC_GROUP_free(ret);
            ret = 0 as *mut EC_GROUP;
        }
    }
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_GROUP_set_generator(
    mut group: *mut EC_GROUP,
    mut generator: *const EC_POINT,
    mut order: *const BIGNUM,
    mut cofactor: *const BIGNUM,
) -> libc::c_int {
    let mut affine: EC_AFFINE = EC_AFFINE {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
    };
    if (*group).curve_name != 0 as libc::c_int || (*group).has_order != 0
        || EC_GROUP_cmp((*generator).group, group, 0 as *mut BN_CTX) != 0
    {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            337 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if BN_num_bytes(order) > 66 as libc::c_int as libc::c_uint {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            112 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            342 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if BN_is_one(cofactor) == 0 {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            131 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            348 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut tmp: *mut BIGNUM = BN_new();
    if !(tmp.is_null() || BN_lshift1(tmp, order) == 0) {
        if BN_cmp(tmp, &mut (*group).field.N) <= 0 as libc::c_int {
            ERR_put_error(
                15 as libc::c_int,
                0 as libc::c_int,
                112 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0"
                    as *const u8 as *const libc::c_char,
                364 as libc::c_int as libc::c_uint,
            );
        } else {
            affine = EC_AFFINE {
                X: EC_FELEM { words: [0; 9] },
                Y: EC_FELEM { words: [0; 9] },
            };
            if !(ec_jacobian_to_affine(group, &mut affine, &(*generator).raw) == 0
                || BN_MONT_CTX_set(&mut (*group).order, order, 0 as *mut BN_CTX) == 0)
            {
                (*group)
                    .field_greater_than_order = (BN_cmp(&mut (*group).field.N, order)
                    > 0 as libc::c_int) as libc::c_int;
                (*group).generator.raw.X = affine.X;
                (*group).generator.raw.Y = affine.Y;
                (*group).has_order = 1 as libc::c_int;
                ret = 1 as libc::c_int;
            }
        }
    }
    BN_free(tmp);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_GROUP_new_by_curve_name(
    mut nid: libc::c_int,
) -> *mut EC_GROUP {
    match nid {
        713 => return EC_group_p224() as *mut EC_GROUP,
        415 => return EC_group_p256() as *mut EC_GROUP,
        715 => return EC_group_p384() as *mut EC_GROUP,
        716 => return EC_group_p521() as *mut EC_GROUP,
        714 => return EC_group_secp256k1() as *mut EC_GROUP,
        _ => {
            ERR_put_error(
                15 as libc::c_int,
                0 as libc::c_int,
                123 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0"
                    as *const u8 as *const libc::c_char,
                399 as libc::c_int as libc::c_uint,
            );
            return 0 as *mut EC_GROUP;
        }
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_GROUP_new_by_curve_name_mutable(
    mut nid: libc::c_int,
) -> *mut EC_GROUP {
    let mut ret: *mut EC_GROUP = 0 as *mut EC_GROUP;
    match nid {
        713 => {
            ret = OPENSSL_memdup(
                EC_group_p224() as *const libc::c_void,
                ::core::mem::size_of::<EC_GROUP>() as libc::c_ulong,
            ) as *mut EC_GROUP;
        }
        415 => {
            ret = OPENSSL_memdup(
                EC_group_p256() as *const libc::c_void,
                ::core::mem::size_of::<EC_GROUP>() as libc::c_ulong,
            ) as *mut EC_GROUP;
        }
        715 => {
            ret = OPENSSL_memdup(
                EC_group_p384() as *const libc::c_void,
                ::core::mem::size_of::<EC_GROUP>() as libc::c_ulong,
            ) as *mut EC_GROUP;
        }
        716 => {
            ret = OPENSSL_memdup(
                EC_group_p521() as *const libc::c_void,
                ::core::mem::size_of::<EC_GROUP>() as libc::c_ulong,
            ) as *mut EC_GROUP;
        }
        714 => {
            ret = OPENSSL_memdup(
                EC_group_secp256k1() as *const libc::c_void,
                ::core::mem::size_of::<EC_GROUP>() as libc::c_ulong,
            ) as *mut EC_GROUP;
        }
        _ => {
            ERR_put_error(
                15 as libc::c_int,
                0 as libc::c_int,
                123 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0"
                    as *const u8 as *const libc::c_char,
                423 as libc::c_int as libc::c_uint,
            );
            return 0 as *mut EC_GROUP;
        }
    }
    if ret.is_null() {
        return 0 as *mut EC_GROUP;
    }
    (*ret).mutable_ec_group = 1 as libc::c_int;
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_GROUP_free(mut group: *mut EC_GROUP) {
    if group.is_null() {
        return;
    }
    if (*group).mutable_ec_group == 0 {
        if (*group).curve_name != 0 as libc::c_int {
            return;
        }
    }
    bn_mont_ctx_cleanup(&mut (*group).order);
    bn_mont_ctx_cleanup(&mut (*group).field);
    OPENSSL_free(group as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_GROUP_dup(mut a: *const EC_GROUP) -> *mut EC_GROUP {
    if a.is_null() {
        return 0 as *mut EC_GROUP;
    }
    if (*a).mutable_ec_group == 0 {
        if (*a).curve_name != 0 as libc::c_int {
            return a as *mut EC_GROUP;
        }
    }
    let mut ret: *mut EC_GROUP = OPENSSL_memdup(
        a as *const libc::c_void,
        ::core::mem::size_of::<EC_GROUP>() as libc::c_ulong,
    ) as *mut EC_GROUP;
    if ret.is_null() {
        return 0 as *mut EC_GROUP;
    }
    (*ret).generator.group = ret;
    bn_mont_ctx_init(&mut (*ret).field);
    bn_mont_ctx_init(&mut (*ret).order);
    if (BN_MONT_CTX_copy(&mut (*ret).field, &(*a).field)).is_null()
        || (BN_MONT_CTX_copy(&mut (*ret).order, &(*a).order)).is_null()
    {
        EC_GROUP_free(ret);
        ret = 0 as *mut EC_GROUP;
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_GROUP_cmp(
    mut a: *const EC_GROUP,
    mut b: *const EC_GROUP,
    mut ignored: *mut BN_CTX,
) -> libc::c_int {
    if a == b {
        return 0 as libc::c_int;
    }
    if (*a).curve_name != (*b).curve_name {
        return 1 as libc::c_int;
    }
    if (*a).curve_name != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    return ((*a).meth != (*b).meth || (*a).has_order != (*b).has_order
        || BN_cmp(&(*a).field.N, &(*b).field.N) != 0 as libc::c_int
        || ec_felem_equal(a, &(*a).a, &(*b).a) == 0
        || ec_felem_equal(a, &(*a).b, &(*b).b) == 0
        || (*a).has_order != 0 && (*b).has_order != 0
            && (BN_cmp(&(*a).order.N, &(*b).order.N) != 0 as libc::c_int
                || ec_GFp_simple_points_equal(
                    a,
                    &(*a).generator.raw,
                    &(*b).generator.raw,
                ) == 0)) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_GROUP_get0_generator(
    mut group: *const EC_GROUP,
) -> *const EC_POINT {
    return if (*group).has_order != 0 {
        &(*group).generator
    } else {
        0 as *const EC_POINT
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_GROUP_get0_order(
    mut group: *const EC_GROUP,
) -> *const BIGNUM {
    if (*group).has_order != 0 {} else {
        __assert_fail(
            b"group->has_order\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            516 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 52],
                &[libc::c_char; 52],
            >(b"const BIGNUM *EC_GROUP_get0_order(const EC_GROUP *)\0"))
                .as_ptr(),
        );
    }
    'c_3913: {
        if (*group).has_order != 0 {} else {
            __assert_fail(
                b"group->has_order\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0"
                    as *const u8 as *const libc::c_char,
                516 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 52],
                    &[libc::c_char; 52],
                >(b"const BIGNUM *EC_GROUP_get0_order(const EC_GROUP *)\0"))
                    .as_ptr(),
            );
        }
    };
    return &(*group).order.N;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_GROUP_get_order(
    mut group: *const EC_GROUP,
    mut order: *mut BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if (BN_copy(order, EC_GROUP_get0_order(group))).is_null() {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_GROUP_order_bits(mut group: *const EC_GROUP) -> libc::c_int {
    return BN_num_bits(&(*group).order.N) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_GROUP_get_cofactor(
    mut group: *const EC_GROUP,
    mut cofactor: *mut BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    return BN_set_word(cofactor, 1 as libc::c_int as BN_ULONG);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_GROUP_get_curve_GFp(
    mut group: *const EC_GROUP,
    mut out_p: *mut BIGNUM,
    mut out_a: *mut BIGNUM,
    mut out_b: *mut BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    return ec_GFp_simple_group_get_curve(group, out_p, out_a, out_b);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_GROUP_get_curve_name(
    mut group: *const EC_GROUP,
) -> libc::c_int {
    return (*group).curve_name;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_GROUP_get_degree(
    mut group: *const EC_GROUP,
) -> libc::c_uint {
    return BN_num_bits(&(*group).field.N);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_curve_nid2nist(mut nid: libc::c_int) -> *const libc::c_char {
    match nid {
        713 => return b"P-224\0" as *const u8 as *const libc::c_char,
        415 => return b"P-256\0" as *const u8 as *const libc::c_char,
        715 => return b"P-384\0" as *const u8 as *const libc::c_char,
        716 => return b"P-521\0" as *const u8 as *const libc::c_char,
        _ => {}
    }
    return 0 as *const libc::c_char;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_curve_nist2nid(
    mut name: *const libc::c_char,
) -> libc::c_int {
    if strcmp(name, b"P-224\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        return 713 as libc::c_int;
    }
    if strcmp(name, b"P-256\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        return 415 as libc::c_int;
    }
    if strcmp(name, b"P-384\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        return 715 as libc::c_int;
    }
    if strcmp(name, b"P-521\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        return 716 as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_POINT_new(mut group: *const EC_GROUP) -> *mut EC_POINT {
    if group.is_null() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            580 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EC_POINT;
    }
    let mut ret: *mut EC_POINT = OPENSSL_malloc(
        ::core::mem::size_of::<EC_POINT>() as libc::c_ulong,
    ) as *mut EC_POINT;
    if ret.is_null() {
        return 0 as *mut EC_POINT;
    }
    (*ret).group = EC_GROUP_dup(group);
    ec_GFp_simple_point_init(&mut (*ret).raw);
    return ret;
}
unsafe extern "C" fn ec_point_free(
    mut point: *mut EC_POINT,
    mut free_group: libc::c_int,
) {
    if point.is_null() {
        return;
    }
    if free_group != 0 {
        EC_GROUP_free((*point).group);
    }
    OPENSSL_free(point as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_POINT_free(mut point: *mut EC_POINT) {
    ec_point_free(point, 1 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_POINT_clear_free(mut point: *mut EC_POINT) {
    EC_POINT_free(point);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_POINT_copy(
    mut dest: *mut EC_POINT,
    mut src: *const EC_POINT,
) -> libc::c_int {
    if EC_GROUP_cmp((*dest).group, (*src).group, 0 as *mut BN_CTX) != 0 as libc::c_int {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            612 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if dest == src as *mut EC_POINT {
        return 1 as libc::c_int;
    }
    ec_GFp_simple_point_copy(&mut (*dest).raw, &(*src).raw);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_POINT_dup(
    mut a: *const EC_POINT,
    mut group: *const EC_GROUP,
) -> *mut EC_POINT {
    if a.is_null() {
        return 0 as *mut EC_POINT;
    }
    let mut ret: *mut EC_POINT = EC_POINT_new(group);
    if ret.is_null() || EC_POINT_copy(ret, a) == 0 {
        EC_POINT_free(ret);
        return 0 as *mut EC_POINT;
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_POINT_set_to_infinity(
    mut group: *const EC_GROUP,
    mut point: *mut EC_POINT,
) -> libc::c_int {
    if EC_GROUP_cmp(group, (*point).group, 0 as *mut BN_CTX) != 0 as libc::c_int {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            638 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    ec_GFp_simple_point_set_to_infinity(group, &mut (*point).raw);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_POINT_is_at_infinity(
    mut group: *const EC_GROUP,
    mut point: *const EC_POINT,
) -> libc::c_int {
    if EC_GROUP_cmp(group, (*point).group, 0 as *mut BN_CTX) != 0 as libc::c_int {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            647 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ec_GFp_simple_is_at_infinity(group, &(*point).raw);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_POINT_is_on_curve(
    mut group: *const EC_GROUP,
    mut point: *const EC_POINT,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if EC_GROUP_cmp(group, (*point).group, 0 as *mut BN_CTX) != 0 as libc::c_int {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            656 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ec_GFp_simple_is_on_curve(group, &(*point).raw);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_POINT_cmp(
    mut group: *const EC_GROUP,
    mut a: *const EC_POINT,
    mut b: *const EC_POINT,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if EC_GROUP_cmp(group, (*a).group, 0 as *mut BN_CTX) != 0 as libc::c_int
        || EC_GROUP_cmp(group, (*b).group, 0 as *mut BN_CTX) != 0 as libc::c_int
    {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            666 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    return if ec_GFp_simple_points_equal(group, &(*a).raw, &(*b).raw) != 0 {
        0 as libc::c_int
    } else {
        1 as libc::c_int
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_POINT_get_affine_coordinates_GFp(
    mut group: *const EC_GROUP,
    mut point: *const EC_POINT,
    mut x: *mut BIGNUM,
    mut y: *mut BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if ((*(*group).meth).point_get_affine_coordinates).is_none() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            678 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if EC_GROUP_cmp(group, (*point).group, 0 as *mut BN_CTX) != 0 as libc::c_int {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            682 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut x_felem: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut y_felem: EC_FELEM = EC_FELEM { words: [0; 9] };
    if ((*(*group).meth).point_get_affine_coordinates)
        .expect(
            "non-null function pointer",
        )(
        group,
        &(*point).raw,
        (if x.is_null() { 0 as *mut EC_FELEM } else { &mut x_felem }),
        (if y.is_null() { 0 as *mut EC_FELEM } else { &mut y_felem }),
    ) == 0 || !x.is_null() && ec_felem_to_bignum(group, x, &mut x_felem) == 0
        || !y.is_null() && ec_felem_to_bignum(group, y, &mut y_felem) == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_POINT_get_affine_coordinates(
    mut group: *const EC_GROUP,
    mut point: *const EC_POINT,
    mut x: *mut BIGNUM,
    mut y: *mut BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    return EC_POINT_get_affine_coordinates_GFp(group, point, x, y, ctx);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_affine_to_jacobian(
    mut group: *const EC_GROUP,
    mut out: *mut EC_JACOBIAN,
    mut p: *const EC_AFFINE,
) {
    (*out).X = (*p).X;
    (*out).Y = (*p).Y;
    (*out).Z = *ec_felem_one(group);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_jacobian_to_affine(
    mut group: *const EC_GROUP,
    mut out: *mut EC_AFFINE,
    mut p: *const EC_JACOBIAN,
) -> libc::c_int {
    return ((*(*group).meth).point_get_affine_coordinates)
        .expect("non-null function pointer")(group, p, &mut (*out).X, &mut (*out).Y);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_jacobian_to_affine_batch(
    mut group: *const EC_GROUP,
    mut out: *mut EC_AFFINE,
    mut in_0: *const EC_JACOBIAN,
    mut num: size_t,
) -> libc::c_int {
    if ((*(*group).meth).jacobian_to_affine_batch).is_none() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            717 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ((*(*group).meth).jacobian_to_affine_batch)
        .expect("non-null function pointer")(group, out, in_0, num);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_point_set_affine_coordinates(
    mut group: *const EC_GROUP,
    mut out: *mut EC_AFFINE,
    mut x: *const EC_FELEM,
    mut y: *const EC_FELEM,
) -> libc::c_int {
    let felem_mul: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_FELEM,
            *const EC_FELEM,
            *const EC_FELEM,
        ) -> (),
    > = (*(*group).meth).felem_mul;
    let felem_sqr: Option::<
        unsafe extern "C" fn(*const EC_GROUP, *mut EC_FELEM, *const EC_FELEM) -> (),
    > = (*(*group).meth).felem_sqr;
    let mut lhs: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut rhs: EC_FELEM = EC_FELEM { words: [0; 9] };
    felem_sqr.expect("non-null function pointer")(group, &mut lhs, y);
    felem_sqr.expect("non-null function pointer")(group, &mut rhs, x);
    ec_felem_add(group, &mut rhs, &mut rhs, &(*group).a);
    felem_mul.expect("non-null function pointer")(group, &mut rhs, &mut rhs, x);
    ec_felem_add(group, &mut rhs, &mut rhs, &(*group).b);
    if ec_felem_equal(group, &mut lhs, &mut rhs) == 0 {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            120 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            739 as libc::c_int as libc::c_uint,
        );
        if (*group).has_order != 0 {
            (*out).X = (*group).generator.raw.X;
            (*out).Y = (*group).generator.raw.Y;
        }
        return 0 as libc::c_int;
    }
    (*out).X = *x;
    (*out).Y = *y;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_POINT_set_affine_coordinates_GFp(
    mut group: *const EC_GROUP,
    mut point: *mut EC_POINT,
    mut x: *const BIGNUM,
    mut y: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if EC_GROUP_cmp(group, (*point).group, 0 as *mut BN_CTX) != 0 as libc::c_int {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            760 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if x.is_null() || y.is_null() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            765 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut x_felem: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut y_felem: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut affine: EC_AFFINE = EC_AFFINE {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
    };
    if ec_bignum_to_felem(group, &mut x_felem, x) == 0
        || ec_bignum_to_felem(group, &mut y_felem, y) == 0
        || ec_point_set_affine_coordinates(
            group,
            &mut affine,
            &mut x_felem,
            &mut y_felem,
        ) == 0
    {
        ec_set_to_safe_point(group, &mut (*point).raw);
        return 0 as libc::c_int;
    }
    ec_affine_to_jacobian(group, &mut (*point).raw, &mut affine);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_POINT_set_affine_coordinates(
    mut group: *const EC_GROUP,
    mut point: *mut EC_POINT,
    mut x: *const BIGNUM,
    mut y: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    return EC_POINT_set_affine_coordinates_GFp(group, point, x, y, ctx);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_POINT_add(
    mut group: *const EC_GROUP,
    mut r: *mut EC_POINT,
    mut a: *const EC_POINT,
    mut b: *const EC_POINT,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if EC_GROUP_cmp(group, (*r).group, 0 as *mut BN_CTX) != 0 as libc::c_int
        || EC_GROUP_cmp(group, (*a).group, 0 as *mut BN_CTX) != 0 as libc::c_int
        || EC_GROUP_cmp(group, (*b).group, 0 as *mut BN_CTX) != 0 as libc::c_int
    {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            795 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    ((*(*group).meth).add)
        .expect("non-null function pointer")(group, &mut (*r).raw, &(*a).raw, &(*b).raw);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_POINT_dbl(
    mut group: *const EC_GROUP,
    mut r: *mut EC_POINT,
    mut a: *const EC_POINT,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if EC_GROUP_cmp(group, (*r).group, 0 as *mut BN_CTX) != 0 as libc::c_int
        || EC_GROUP_cmp(group, (*a).group, 0 as *mut BN_CTX) != 0 as libc::c_int
    {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            806 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    ((*(*group).meth).dbl)
        .expect("non-null function pointer")(group, &mut (*r).raw, &(*a).raw);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_POINT_invert(
    mut group: *const EC_GROUP,
    mut a: *mut EC_POINT,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if EC_GROUP_cmp(group, (*a).group, 0 as *mut BN_CTX) != 0 as libc::c_int {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            816 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    ec_GFp_simple_invert(group, &mut (*a).raw);
    return 1 as libc::c_int;
}
unsafe extern "C" fn arbitrary_bignum_to_scalar(
    mut group: *const EC_GROUP,
    mut out: *mut EC_SCALAR,
    mut in_0: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if ec_bignum_to_scalar(group, out, in_0) != 0 {
        return 1 as libc::c_int;
    }
    ERR_clear_error();
    BN_CTX_start(ctx);
    let mut tmp: *mut BIGNUM = BN_CTX_get(ctx);
    let mut ok: libc::c_int = (!tmp.is_null()
        && BN_nnmod(tmp, in_0, EC_GROUP_get0_order(group), ctx) != 0
        && ec_bignum_to_scalar(group, out, tmp) != 0) as libc::c_int;
    BN_CTX_end(ctx);
    return ok;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_point_mul_no_self_test(
    mut group: *const EC_GROUP,
    mut r: *mut EC_POINT,
    mut g_scalar: *const BIGNUM,
    mut p: *const EC_POINT,
    mut p_scalar: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut current_block: u64;
    if g_scalar.is_null() && p_scalar.is_null()
        || (p == 0 as *mut libc::c_void as *const EC_POINT) as libc::c_int
            != (p_scalar == 0 as *mut libc::c_void as *const BIGNUM) as libc::c_int
    {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            849 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if EC_GROUP_cmp(group, (*r).group, 0 as *mut BN_CTX) != 0 as libc::c_int
        || !p.is_null()
            && EC_GROUP_cmp(group, (*p).group, 0 as *mut BN_CTX) != 0 as libc::c_int
    {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            855 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut new_ctx: *mut BN_CTX = 0 as *mut BN_CTX;
    if ctx.is_null() {
        new_ctx = BN_CTX_new();
        if new_ctx.is_null() {
            current_block = 9382962911417247340;
        } else {
            ctx = new_ctx;
            current_block = 3640593987805443782;
        }
    } else {
        current_block = 3640593987805443782;
    }
    match current_block {
        3640593987805443782 => {
            if !g_scalar.is_null() {
                let mut scalar: EC_SCALAR = EC_SCALAR { words: [0; 9] };
                if arbitrary_bignum_to_scalar(group, &mut scalar, g_scalar, ctx) == 0
                    || ec_point_mul_scalar_base(group, &mut (*r).raw, &mut scalar) == 0
                {
                    current_block = 9382962911417247340;
                } else {
                    current_block = 11050875288958768710;
                }
            } else {
                current_block = 11050875288958768710;
            }
            match current_block {
                9382962911417247340 => {}
                _ => {
                    if !p_scalar.is_null() {
                        let mut scalar_0: EC_SCALAR = EC_SCALAR { words: [0; 9] };
                        let mut tmp: EC_JACOBIAN = EC_JACOBIAN {
                            X: EC_FELEM { words: [0; 9] },
                            Y: EC_FELEM { words: [0; 9] },
                            Z: EC_FELEM { words: [0; 9] },
                        };
                        if arbitrary_bignum_to_scalar(
                            group,
                            &mut scalar_0,
                            p_scalar,
                            ctx,
                        ) == 0
                            || ec_point_mul_scalar(
                                group,
                                &mut tmp,
                                &(*p).raw,
                                &mut scalar_0,
                            ) == 0
                        {
                            current_block = 9382962911417247340;
                        } else {
                            if g_scalar.is_null() {
                                OPENSSL_memcpy(
                                    &mut (*r).raw as *mut EC_JACOBIAN as *mut libc::c_void,
                                    &mut tmp as *mut EC_JACOBIAN as *const libc::c_void,
                                    ::core::mem::size_of::<EC_JACOBIAN>() as libc::c_ulong,
                                );
                            } else {
                                ((*(*group).meth).add)
                                    .expect(
                                        "non-null function pointer",
                                    )(group, &mut (*r).raw, &mut (*r).raw, &mut tmp);
                            }
                            current_block = 11584701595673473500;
                        }
                    } else {
                        current_block = 11584701595673473500;
                    }
                    match current_block {
                        9382962911417247340 => {}
                        _ => {
                            ret = 1 as libc::c_int;
                        }
                    }
                }
            }
        }
        _ => {}
    }
    BN_CTX_free(new_ctx);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_POINT_mul(
    mut group: *const EC_GROUP,
    mut r: *mut EC_POINT,
    mut g_scalar: *const BIGNUM,
    mut p: *const EC_POINT,
    mut p_scalar: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    boringssl_ensure_ecc_self_test();
    return ec_point_mul_no_self_test(group, r, g_scalar, p, p_scalar, ctx);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_point_mul_scalar_public(
    mut group: *const EC_GROUP,
    mut r: *mut EC_JACOBIAN,
    mut g_scalar: *const EC_SCALAR,
    mut p: *const EC_JACOBIAN,
    mut p_scalar: *const EC_SCALAR,
) -> libc::c_int {
    if g_scalar.is_null() || p_scalar.is_null() || p.is_null() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            921 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*(*group).meth).mul_public).is_none() {
        return ((*(*group).meth).mul_public_batch)
            .expect(
                "non-null function pointer",
            )(group, r, g_scalar, p, p_scalar, 1 as libc::c_int as size_t);
    }
    ((*(*group).meth).mul_public)
        .expect("non-null function pointer")(group, r, g_scalar, p, p_scalar);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_point_mul_scalar_public_batch(
    mut group: *const EC_GROUP,
    mut r: *mut EC_JACOBIAN,
    mut g_scalar: *const EC_SCALAR,
    mut points: *const EC_JACOBIAN,
    mut scalars: *const EC_SCALAR,
    mut num: size_t,
) -> libc::c_int {
    if ((*(*group).meth).mul_public_batch).is_none() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            938 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ((*(*group).meth).mul_public_batch)
        .expect("non-null function pointer")(group, r, g_scalar, points, scalars, num);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_point_mul_scalar(
    mut group: *const EC_GROUP,
    mut r: *mut EC_JACOBIAN,
    mut p: *const EC_JACOBIAN,
    mut scalar: *const EC_SCALAR,
) -> libc::c_int {
    if p.is_null() || scalar.is_null() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            950 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    ((*(*group).meth).mul).expect("non-null function pointer")(group, r, p, scalar);
    if ec_GFp_simple_is_on_curve(group, r) == 0 {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            4 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            959 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_point_mul_scalar_base(
    mut group: *const EC_GROUP,
    mut r: *mut EC_JACOBIAN,
    mut scalar: *const EC_SCALAR,
) -> libc::c_int {
    if scalar.is_null() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            970 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    ((*(*group).meth).mul_base).expect("non-null function pointer")(group, r, scalar);
    if constant_time_declassify_int(ec_GFp_simple_is_on_curve(group, r)) == 0 {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            4 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            982 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_point_mul_scalar_batch(
    mut group: *const EC_GROUP,
    mut r: *mut EC_JACOBIAN,
    mut p0: *const EC_JACOBIAN,
    mut scalar0: *const EC_SCALAR,
    mut p1: *const EC_JACOBIAN,
    mut scalar1: *const EC_SCALAR,
    mut p2: *const EC_JACOBIAN,
    mut scalar2: *const EC_SCALAR,
) -> libc::c_int {
    if ((*(*group).meth).mul_batch).is_none() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            995 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    ((*(*group).meth).mul_batch)
        .expect(
            "non-null function pointer",
        )(group, r, p0, scalar0, p1, scalar1, p2, scalar2);
    if ec_GFp_simple_is_on_curve(group, r) == 0 {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            4 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            1004 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_init_precomp(
    mut group: *const EC_GROUP,
    mut out: *mut EC_PRECOMP,
    mut p: *const EC_JACOBIAN,
) -> libc::c_int {
    if ((*(*group).meth).init_precomp).is_none() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            1014 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ((*(*group).meth).init_precomp)
        .expect("non-null function pointer")(group, out, p);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_point_mul_scalar_precomp(
    mut group: *const EC_GROUP,
    mut r: *mut EC_JACOBIAN,
    mut p0: *const EC_PRECOMP,
    mut scalar0: *const EC_SCALAR,
    mut p1: *const EC_PRECOMP,
    mut scalar1: *const EC_SCALAR,
    mut p2: *const EC_PRECOMP,
    mut scalar2: *const EC_SCALAR,
) -> libc::c_int {
    if ((*(*group).meth).mul_precomp).is_none() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            1027 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    ((*(*group).meth).mul_precomp)
        .expect(
            "non-null function pointer",
        )(group, r, p0, scalar0, p1, scalar1, p2, scalar2);
    if ec_GFp_simple_is_on_curve(group, r) == 0 {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            4 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            1036 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_point_select(
    mut group: *const EC_GROUP,
    mut out: *mut EC_JACOBIAN,
    mut mask: BN_ULONG,
    mut a: *const EC_JACOBIAN,
    mut b: *const EC_JACOBIAN,
) {
    ec_felem_select(group, &mut (*out).X, mask, &(*a).X, &(*b).X);
    ec_felem_select(group, &mut (*out).Y, mask, &(*a).Y, &(*b).Y);
    ec_felem_select(group, &mut (*out).Z, mask, &(*a).Z, &(*b).Z);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_affine_select(
    mut group: *const EC_GROUP,
    mut out: *mut EC_AFFINE,
    mut mask: BN_ULONG,
    mut a: *const EC_AFFINE,
    mut b: *const EC_AFFINE,
) {
    ec_felem_select(group, &mut (*out).X, mask, &(*a).X, &(*b).X);
    ec_felem_select(group, &mut (*out).Y, mask, &(*a).Y, &(*b).Y);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_precomp_select(
    mut group: *const EC_GROUP,
    mut out: *mut EC_PRECOMP,
    mut mask: BN_ULONG,
    mut a: *const EC_PRECOMP,
    mut b: *const EC_PRECOMP,
) {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (::core::mem::size_of::<[EC_AFFINE; 31]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<EC_AFFINE>() as libc::c_ulong)
    {
        ec_affine_select(
            group,
            &mut *((*out).comb).as_mut_ptr().offset(i as isize),
            mask,
            &*((*a).comb).as_ptr().offset(i as isize),
            &*((*b).comb).as_ptr().offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_cmp_x_coordinate(
    mut group: *const EC_GROUP,
    mut p: *const EC_JACOBIAN,
    mut r: *const EC_SCALAR,
) -> libc::c_int {
    return ((*(*group).meth).cmp_x_coordinate)
        .expect("non-null function pointer")(group, p, r);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_get_x_coordinate_as_scalar(
    mut group: *const EC_GROUP,
    mut out: *mut EC_SCALAR,
    mut p: *const EC_JACOBIAN,
) -> libc::c_int {
    let mut bytes: [uint8_t; 66] = [0; 66];
    let mut len: size_t = 0;
    if ec_get_x_coordinate_as_bytes(
        group,
        bytes.as_mut_ptr(),
        &mut len,
        ::core::mem::size_of::<[uint8_t; 66]>() as libc::c_ulong,
        p,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut order: *const BIGNUM = EC_GROUP_get0_order(group);
    let mut words: [BN_ULONG; 10] = [
        0 as libc::c_int as BN_ULONG,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    bn_big_endian_to_words(
        words.as_mut_ptr(),
        ((*order).width + 1 as libc::c_int) as size_t,
        bytes.as_mut_ptr(),
        len,
    );
    bn_reduce_once(
        ((*out).words).as_mut_ptr(),
        words.as_mut_ptr(),
        words[(*order).width as usize],
        (*order).d,
        (*order).width as size_t,
    );
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_get_x_coordinate_as_bytes(
    mut group: *const EC_GROUP,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
    mut max_out: size_t,
    mut p: *const EC_JACOBIAN,
) -> libc::c_int {
    let mut len: size_t = BN_num_bytes(&(*group).field.N) as size_t;
    if len <= 66 as libc::c_int as size_t {} else {
        __assert_fail(
            b"len <= EC_MAX_BYTES\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            1109 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 101],
                &[libc::c_char; 101],
            >(
                b"int ec_get_x_coordinate_as_bytes(const EC_GROUP *, uint8_t *, size_t *, size_t, const EC_JACOBIAN *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_14295: {
        if len <= 66 as libc::c_int as size_t {} else {
            __assert_fail(
                b"len <= EC_MAX_BYTES\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0"
                    as *const u8 as *const libc::c_char,
                1109 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 101],
                    &[libc::c_char; 101],
                >(
                    b"int ec_get_x_coordinate_as_bytes(const EC_GROUP *, uint8_t *, size_t *, size_t, const EC_JACOBIAN *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if max_out < len {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec.c\0" as *const u8
                as *const libc::c_char,
            1111 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut x: EC_FELEM = EC_FELEM { words: [0; 9] };
    if ((*(*group).meth).point_get_affine_coordinates)
        .expect("non-null function pointer")(group, p, &mut x, 0 as *mut EC_FELEM) == 0
    {
        return 0 as libc::c_int;
    }
    ec_felem_to_bytes(group, out, out_len, &mut x);
    *out_len = len;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_set_to_safe_point(
    mut group: *const EC_GROUP,
    mut out: *mut EC_JACOBIAN,
) {
    if (*group).has_order != 0 {
        ec_GFp_simple_point_copy(out, &(*group).generator.raw);
    } else {
        ec_GFp_simple_point_set_to_infinity(group, out);
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_GROUP_set_asn1_flag(
    mut group: *mut EC_GROUP,
    mut flag: libc::c_int,
) {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_GROUP_get_asn1_flag(
    mut group: *const EC_GROUP,
) -> libc::c_int {
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_GROUP_method_of(
    mut group: *const EC_GROUP,
) -> *const EC_METHOD {
    return 0x12340000 as libc::c_int as *const EC_METHOD;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_METHOD_get_field_type(
    mut meth: *const EC_METHOD,
) -> libc::c_int {
    return 406 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_GROUP_set_point_conversion_form(
    mut group: *mut EC_GROUP,
    mut form: point_conversion_form_t,
) {
    if (*group).mutable_ec_group != 0 {
        (*group).conv_form = form;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_GROUP_get_point_conversion_form(
    mut group: *const EC_GROUP,
) -> point_conversion_form_t {
    return (*group).conv_form;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_GROUP_set_seed(
    mut group: *mut EC_GROUP,
    mut seed: *const libc::c_uchar,
    mut len: size_t,
) -> size_t {
    return 0 as libc::c_int as size_t;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_GROUP_get0_seed(
    mut group: *const EC_GROUP,
) -> *mut libc::c_uchar {
    return 0 as *mut libc::c_uchar;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_GROUP_get_seed_len(mut group: *const EC_GROUP) -> size_t {
    return 0 as libc::c_int as size_t;
}
