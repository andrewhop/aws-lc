#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(asm)]
use core::arch::asm;
extern "C" {
    fn BN_num_bytes(bn: *const BIGNUM) -> libc::c_uint;
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn bn_select_words(
        r: *mut BN_ULONG,
        mask: BN_ULONG,
        a: *const BN_ULONG,
        b: *const BN_ULONG,
        num: size_t,
    );
    fn bn_copy_words(out: *mut BN_ULONG, num: size_t, bn: *const BIGNUM) -> libc::c_int;
    fn bn_less_than_words(
        a: *const BN_ULONG,
        b: *const BN_ULONG,
        len: size_t,
    ) -> libc::c_int;
    fn bn_rand_range_words(
        out: *mut BN_ULONG,
        min_inclusive: BN_ULONG,
        max_exclusive: *const BN_ULONG,
        len: size_t,
        additional_data: *const uint8_t,
    ) -> libc::c_int;
    fn bn_mod_add_words(
        r: *mut BN_ULONG,
        a: *const BN_ULONG,
        b: *const BN_ULONG,
        m: *const BN_ULONG,
        tmp: *mut BN_ULONG,
        num: size_t,
    );
    fn bn_mod_sub_words(
        r: *mut BN_ULONG,
        a: *const BN_ULONG,
        b: *const BN_ULONG,
        m: *const BN_ULONG,
        tmp: *mut BN_ULONG,
        num: size_t,
    );
    fn bn_to_montgomery_small(
        r: *mut BN_ULONG,
        a: *const BN_ULONG,
        num: size_t,
        mont: *const BN_MONT_CTX,
    );
    fn bn_from_montgomery_small(
        r: *mut BN_ULONG,
        num_r: size_t,
        a: *const BN_ULONG,
        num_a: size_t,
        mont: *const BN_MONT_CTX,
    );
    fn bn_mod_mul_montgomery_small(
        r: *mut BN_ULONG,
        a: *const BN_ULONG,
        b: *const BN_ULONG,
        num: size_t,
        mont: *const BN_MONT_CTX,
    );
    fn bn_mod_inverse0_prime_mont_small(
        r: *mut BN_ULONG,
        a: *const BN_ULONG,
        num: size_t,
        mont: *const BN_MONT_CTX,
    );
    fn bn_big_endian_to_words(
        out: *mut BN_ULONG,
        out_len: size_t,
        in_0: *const uint8_t,
        in_len: size_t,
    );
    fn bn_words_to_big_endian(
        out: *mut uint8_t,
        out_len: size_t,
        in_0: *const BN_ULONG,
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
#[no_mangle]
pub unsafe extern "C" fn ec_bignum_to_scalar(
    mut group: *const EC_GROUP,
    mut out: *mut EC_SCALAR,
    mut in_0: *const BIGNUM,
) -> libc::c_int {
    if bn_copy_words(((*out).words).as_mut_ptr(), (*group).order.N.width as size_t, in_0)
        == 0
        || constant_time_declassify_int(
            bn_less_than_words(
                ((*out).words).as_mut_ptr(),
                (*group).order.N.d,
                (*group).order.N.width as size_t,
            ),
        ) == 0
    {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            133 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/scalar.c\0"
                as *const u8 as *const libc::c_char,
            32 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ec_scalar_equal_vartime(
    mut group: *const EC_GROUP,
    mut a: *const EC_SCALAR,
    mut b: *const EC_SCALAR,
) -> libc::c_int {
    return (OPENSSL_memcmp(
        ((*a).words).as_ptr() as *const libc::c_void,
        ((*b).words).as_ptr() as *const libc::c_void,
        ((*group).order.N.width as libc::c_ulong)
            .wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    ) == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ec_scalar_is_zero(
    mut group: *const EC_GROUP,
    mut a: *const EC_SCALAR,
) -> libc::c_int {
    let mut mask: BN_ULONG = 0 as libc::c_int as BN_ULONG;
    let mut i: libc::c_int = 0 as libc::c_int;
    while i < (*group).order.N.width {
        mask |= (*a).words[i as usize];
        i += 1;
        i;
    }
    return (mask == 0 as libc::c_int as BN_ULONG) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ec_random_nonzero_scalar(
    mut group: *const EC_GROUP,
    mut out: *mut EC_SCALAR,
    mut additional_data: *const uint8_t,
) -> libc::c_int {
    return bn_rand_range_words(
        ((*out).words).as_mut_ptr(),
        1 as libc::c_int as BN_ULONG,
        (*group).order.N.d,
        (*group).order.N.width as size_t,
        additional_data,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ec_scalar_to_bytes(
    mut group: *const EC_GROUP,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
    mut in_0: *const EC_SCALAR,
) {
    let mut len: size_t = BN_num_bytes(&(*group).order.N) as size_t;
    bn_words_to_big_endian(
        out,
        len,
        ((*in_0).words).as_ptr(),
        (*group).order.N.width as size_t,
    );
    *out_len = len;
}
#[no_mangle]
pub unsafe extern "C" fn ec_scalar_from_bytes(
    mut group: *const EC_GROUP,
    mut out: *mut EC_SCALAR,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    if len != BN_num_bytes(&(*group).order.N) as size_t {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            133 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/scalar.c\0"
                as *const u8 as *const libc::c_char,
            68 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    bn_big_endian_to_words(
        ((*out).words).as_mut_ptr(),
        (*group).order.N.width as size_t,
        in_0,
        len,
    );
    if bn_less_than_words(
        ((*out).words).as_mut_ptr(),
        (*group).order.N.d,
        (*group).order.N.width as size_t,
    ) == 0
    {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            133 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/scalar.c\0"
                as *const u8 as *const libc::c_char,
            75 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ec_scalar_reduce(
    mut group: *const EC_GROUP,
    mut out: *mut EC_SCALAR,
    mut words: *const BN_ULONG,
    mut num: size_t,
) {
    bn_from_montgomery_small(
        ((*out).words).as_mut_ptr(),
        (*group).order.N.width as size_t,
        words,
        num,
        &(*group).order,
    );
    ec_scalar_to_montgomery(group, out, out);
}
#[no_mangle]
pub unsafe extern "C" fn ec_scalar_add(
    mut group: *const EC_GROUP,
    mut r: *mut EC_SCALAR,
    mut a: *const EC_SCALAR,
    mut b: *const EC_SCALAR,
) {
    let mut order: *const BIGNUM = &(*group).order.N;
    let mut tmp: [BN_ULONG; 9] = [0; 9];
    bn_mod_add_words(
        ((*r).words).as_mut_ptr(),
        ((*a).words).as_ptr(),
        ((*b).words).as_ptr(),
        (*order).d,
        tmp.as_mut_ptr(),
        (*order).width as size_t,
    );
    OPENSSL_cleanse(
        tmp.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[BN_ULONG; 9]>() as libc::c_ulong,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ec_scalar_sub(
    mut group: *const EC_GROUP,
    mut r: *mut EC_SCALAR,
    mut a: *const EC_SCALAR,
    mut b: *const EC_SCALAR,
) {
    let mut order: *const BIGNUM = &(*group).order.N;
    let mut tmp: [BN_ULONG; 9] = [0; 9];
    bn_mod_sub_words(
        ((*r).words).as_mut_ptr(),
        ((*a).words).as_ptr(),
        ((*b).words).as_ptr(),
        (*order).d,
        tmp.as_mut_ptr(),
        (*order).width as size_t,
    );
    OPENSSL_cleanse(
        tmp.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[BN_ULONG; 9]>() as libc::c_ulong,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ec_scalar_neg(
    mut group: *const EC_GROUP,
    mut r: *mut EC_SCALAR,
    mut a: *const EC_SCALAR,
) {
    let mut zero: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    OPENSSL_memset(
        &mut zero as *mut EC_SCALAR as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EC_SCALAR>() as libc::c_ulong,
    );
    ec_scalar_sub(group, r, &mut zero, a);
}
#[no_mangle]
pub unsafe extern "C" fn ec_scalar_select(
    mut group: *const EC_GROUP,
    mut out: *mut EC_SCALAR,
    mut mask: BN_ULONG,
    mut a: *const EC_SCALAR,
    mut b: *const EC_SCALAR,
) {
    let mut order: *const BIGNUM = &(*group).order.N;
    bn_select_words(
        ((*out).words).as_mut_ptr(),
        mask,
        ((*a).words).as_ptr(),
        ((*b).words).as_ptr(),
        (*order).width as size_t,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ec_scalar_to_montgomery(
    mut group: *const EC_GROUP,
    mut r: *mut EC_SCALAR,
    mut a: *const EC_SCALAR,
) {
    let mut order: *const BIGNUM = &(*group).order.N;
    bn_to_montgomery_small(
        ((*r).words).as_mut_ptr(),
        ((*a).words).as_ptr(),
        (*order).width as size_t,
        &(*group).order,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ec_scalar_from_montgomery(
    mut group: *const EC_GROUP,
    mut r: *mut EC_SCALAR,
    mut a: *const EC_SCALAR,
) {
    let mut order: *const BIGNUM = &(*group).order.N;
    bn_from_montgomery_small(
        ((*r).words).as_mut_ptr(),
        (*order).width as size_t,
        ((*a).words).as_ptr(),
        (*order).width as size_t,
        &(*group).order,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ec_scalar_mul_montgomery(
    mut group: *const EC_GROUP,
    mut r: *mut EC_SCALAR,
    mut a: *const EC_SCALAR,
    mut b: *const EC_SCALAR,
) {
    let mut order: *const BIGNUM = &(*group).order.N;
    bn_mod_mul_montgomery_small(
        ((*r).words).as_mut_ptr(),
        ((*a).words).as_ptr(),
        ((*b).words).as_ptr(),
        (*order).width as size_t,
        &(*group).order,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ec_simple_scalar_inv0_montgomery(
    mut group: *const EC_GROUP,
    mut r: *mut EC_SCALAR,
    mut a: *const EC_SCALAR,
) {
    let mut order: *const BIGNUM = &(*group).order.N;
    bn_mod_inverse0_prime_mont_small(
        ((*r).words).as_mut_ptr(),
        ((*a).words).as_ptr(),
        (*order).width as size_t,
        &(*group).order,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ec_simple_scalar_to_montgomery_inv_vartime(
    mut group: *const EC_GROUP,
    mut r: *mut EC_SCALAR,
    mut a: *const EC_SCALAR,
) -> libc::c_int {
    if ec_scalar_is_zero(group, a) != 0 {
        return 0 as libc::c_int;
    }
    ec_scalar_inv0_montgomery(group, r, a);
    ec_scalar_from_montgomery(group, r, r);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ec_scalar_inv0_montgomery(
    mut group: *const EC_GROUP,
    mut r: *mut EC_SCALAR,
    mut a: *const EC_SCALAR,
) {
    ((*(*group).meth).scalar_inv0_montgomery)
        .expect("non-null function pointer")(group, r, a);
}
#[no_mangle]
pub unsafe extern "C" fn ec_scalar_to_montgomery_inv_vartime(
    mut group: *const EC_GROUP,
    mut r: *mut EC_SCALAR,
    mut a: *const EC_SCALAR,
) -> libc::c_int {
    return ((*(*group).meth).scalar_to_montgomery_inv_vartime)
        .expect("non-null function pointer")(group, r, a);
}
