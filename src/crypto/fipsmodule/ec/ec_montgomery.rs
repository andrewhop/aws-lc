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
unsafe extern "C" {
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
    fn ec_felem_non_zero_mask(group: *const EC_GROUP, a: *const EC_FELEM) -> BN_ULONG;
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
    fn ec_GFp_mont_mul(
        group: *const EC_GROUP,
        r: *mut EC_JACOBIAN,
        p: *const EC_JACOBIAN,
        scalar: *const EC_SCALAR,
    );
    fn ec_GFp_mont_mul_base(
        group: *const EC_GROUP,
        r: *mut EC_JACOBIAN,
        scalar: *const EC_SCALAR,
    );
    fn ec_GFp_mont_mul_batch(
        group: *const EC_GROUP,
        r: *mut EC_JACOBIAN,
        p0: *const EC_JACOBIAN,
        scalar0: *const EC_SCALAR,
        p1: *const EC_JACOBIAN,
        scalar1: *const EC_SCALAR,
        p2: *const EC_JACOBIAN,
        scalar2: *const EC_SCALAR,
    );
    fn ec_GFp_mont_init_precomp(
        group: *const EC_GROUP,
        out: *mut EC_PRECOMP,
        p: *const EC_JACOBIAN,
    ) -> libc::c_int;
    fn ec_GFp_mont_mul_precomp(
        group: *const EC_GROUP,
        r: *mut EC_JACOBIAN,
        p0: *const EC_PRECOMP,
        scalar0: *const EC_SCALAR,
        p1: *const EC_PRECOMP,
        scalar1: *const EC_SCALAR,
        p2: *const EC_PRECOMP,
        scalar2: *const EC_SCALAR,
    );
    fn ec_GFp_mont_mul_public_batch(
        group: *const EC_GROUP,
        r: *mut EC_JACOBIAN,
        g_scalar: *const EC_SCALAR,
        points: *const EC_JACOBIAN,
        scalars: *const EC_SCALAR,
        num: size_t,
    ) -> libc::c_int;
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
    fn bn_mod_exp_mont_small(
        r: *mut BN_ULONG,
        a: *const BN_ULONG,
        num: size_t,
        p: *const BN_ULONG,
        num_p: size_t,
        mont: *const BN_MONT_CTX,
    );
    fn bn_mod_inverse0_prime_mont_small(
        r: *mut BN_ULONG,
        a: *const BN_ULONG,
        num: size_t,
        mont: *const BN_MONT_CTX,
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
unsafe extern "C" fn ec_GFp_mont_felem_to_montgomery(
    mut group: *const EC_GROUP,
    mut out: *mut EC_FELEM,
    mut in_0: *const EC_FELEM,
) {
    bn_to_montgomery_small(
        ((*out).words).as_mut_ptr(),
        ((*in_0).words).as_ptr(),
        (*group).field.N.width as size_t,
        &(*group).field,
    );
}
unsafe extern "C" fn ec_GFp_mont_felem_from_montgomery(
    mut group: *const EC_GROUP,
    mut out: *mut EC_FELEM,
    mut in_0: *const EC_FELEM,
) {
    bn_from_montgomery_small(
        ((*out).words).as_mut_ptr(),
        (*group).field.N.width as size_t,
        ((*in_0).words).as_ptr(),
        (*group).field.N.width as size_t,
        &(*group).field,
    );
}
unsafe extern "C" fn ec_GFp_mont_felem_inv0(
    mut group: *const EC_GROUP,
    mut out: *mut EC_FELEM,
    mut a: *const EC_FELEM,
) {
    bn_mod_inverse0_prime_mont_small(
        ((*out).words).as_mut_ptr(),
        ((*a).words).as_ptr(),
        (*group).field.N.width as size_t,
        &(*group).field,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_GFp_mont_felem_mul(
    mut group: *const EC_GROUP,
    mut r: *mut EC_FELEM,
    mut a: *const EC_FELEM,
    mut b: *const EC_FELEM,
) {
    bn_mod_mul_montgomery_small(
        ((*r).words).as_mut_ptr(),
        ((*a).words).as_ptr(),
        ((*b).words).as_ptr(),
        (*group).field.N.width as size_t,
        &(*group).field,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_GFp_mont_felem_sqr(
    mut group: *const EC_GROUP,
    mut r: *mut EC_FELEM,
    mut a: *const EC_FELEM,
) {
    bn_mod_mul_montgomery_small(
        ((*r).words).as_mut_ptr(),
        ((*a).words).as_ptr(),
        ((*a).words).as_ptr(),
        (*group).field.N.width as size_t,
        &(*group).field,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_GFp_mont_felem_to_bytes(
    mut group: *const EC_GROUP,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
    mut in_0: *const EC_FELEM,
) {
    let mut tmp: EC_FELEM = EC_FELEM { words: [0; 9] };
    ec_GFp_mont_felem_from_montgomery(group, &mut tmp, in_0);
    ec_GFp_simple_felem_to_bytes(group, out, out_len, &mut tmp);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_GFp_mont_felem_from_bytes(
    mut group: *const EC_GROUP,
    mut out: *mut EC_FELEM,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    if ec_GFp_simple_felem_from_bytes(group, out, in_0, len) == 0 {
        return 0 as libc::c_int;
    }
    ec_GFp_mont_felem_to_montgomery(group, out, out);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_GFp_mont_felem_reduce(
    mut group: *const EC_GROUP,
    mut out: *mut EC_FELEM,
    mut words: *const BN_ULONG,
    mut num: size_t,
) {
    bn_from_montgomery_small(
        ((*out).words).as_mut_ptr(),
        (*group).field.N.width as size_t,
        words,
        num,
        &(*group).field,
    );
    ec_GFp_mont_felem_to_montgomery(group, out, out);
    ec_GFp_mont_felem_to_montgomery(group, out, out);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_GFp_mont_felem_exp(
    mut group: *const EC_GROUP,
    mut out: *mut EC_FELEM,
    mut a: *const EC_FELEM,
    mut exp: *const BN_ULONG,
    mut num_exp: size_t,
) {
    bn_mod_exp_mont_small(
        ((*out).words).as_mut_ptr(),
        ((*a).words).as_ptr(),
        (*group).field.N.width as size_t,
        exp,
        num_exp,
        &(*group).field,
    );
}
unsafe extern "C" fn ec_GFp_mont_point_get_affine_coordinates(
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
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_montgomery.c\0"
                as *const u8 as *const libc::c_char,
            150 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut z1: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut z2: EC_FELEM = EC_FELEM { words: [0; 9] };
    ec_GFp_mont_felem_inv0(group, &mut z2, &(*point).Z);
    ec_GFp_mont_felem_sqr(group, &mut z1, &mut z2);
    if !x.is_null() {
        ec_GFp_mont_felem_mul(group, x, &(*point).X, &mut z1);
    }
    if !y.is_null() {
        ec_GFp_mont_felem_mul(group, &mut z1, &mut z1, &mut z2);
        ec_GFp_mont_felem_mul(group, y, &(*point).Y, &mut z1);
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_GFp_mont_jacobian_to_affine_batch(
    mut group: *const EC_GROUP,
    mut out: *mut EC_AFFINE,
    mut in_0: *const EC_JACOBIAN,
    mut num: size_t,
) -> libc::c_int {
    if num == 0 as libc::c_int as size_t {
        return 1 as libc::c_int;
    }
    (*out.offset(0 as libc::c_int as isize))
        .X = (*in_0.offset(0 as libc::c_int as isize)).Z;
    let mut i: size_t = 1 as libc::c_int as size_t;
    while i < num {
        ec_GFp_mont_felem_mul(
            group,
            &mut (*out.offset(i as isize)).X,
            &mut (*out.offset(i.wrapping_sub(1 as libc::c_int as size_t) as isize)).X,
            &(*in_0.offset(i as isize)).Z,
        );
        i = i.wrapping_add(1);
        i;
    }
    if ec_felem_non_zero_mask(
        group,
        &mut (*out.offset(num.wrapping_sub(1 as libc::c_int as size_t) as isize)).X,
    ) == 0 as libc::c_int as BN_ULONG
    {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            119 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_montgomery.c\0"
                as *const u8 as *const libc::c_char,
            189 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut zinvprod: EC_FELEM = EC_FELEM { words: [0; 9] };
    ec_GFp_mont_felem_inv0(
        group,
        &mut zinvprod,
        &mut (*out.offset(num.wrapping_sub(1 as libc::c_int as size_t) as isize)).X,
    );
    let mut i_0: size_t = num.wrapping_sub(1 as libc::c_int as size_t);
    while i_0 < num {
        let mut zinv: EC_FELEM = EC_FELEM { words: [0; 9] };
        let mut zinv2: EC_FELEM = EC_FELEM { words: [0; 9] };
        if i_0 == 0 as libc::c_int as size_t {
            zinv = zinvprod;
        } else {
            ec_GFp_mont_felem_mul(
                group,
                &mut zinv,
                &mut zinvprod,
                &mut (*out.offset(i_0.wrapping_sub(1 as libc::c_int as size_t) as isize))
                    .X,
            );
            ec_GFp_mont_felem_mul(
                group,
                &mut zinvprod,
                &mut zinvprod,
                &(*in_0.offset(i_0 as isize)).Z,
            );
        }
        ec_GFp_mont_felem_sqr(group, &mut zinv2, &mut zinv);
        ec_GFp_mont_felem_mul(
            group,
            &mut (*out.offset(i_0 as isize)).X,
            &(*in_0.offset(i_0 as isize)).X,
            &mut zinv2,
        );
        ec_GFp_mont_felem_mul(
            group,
            &mut (*out.offset(i_0 as isize)).Y,
            &(*in_0.offset(i_0 as isize)).Y,
            &mut zinv2,
        );
        ec_GFp_mont_felem_mul(
            group,
            &mut (*out.offset(i_0 as isize)).Y,
            &mut (*out.offset(i_0 as isize)).Y,
            &mut zinv,
        );
        i_0 = i_0.wrapping_sub(1);
        i_0;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_GFp_mont_add(
    mut group: *const EC_GROUP,
    mut out: *mut EC_JACOBIAN,
    mut a: *const EC_JACOBIAN,
    mut b: *const EC_JACOBIAN,
) {
    if a == b {
        ec_GFp_mont_dbl(group, out, a);
        return;
    }
    let mut x_out: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut y_out: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut z_out: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut z1nz: BN_ULONG = ec_felem_non_zero_mask(group, &(*a).Z);
    let mut z2nz: BN_ULONG = ec_felem_non_zero_mask(group, &(*b).Z);
    let mut z1z1: EC_FELEM = EC_FELEM { words: [0; 9] };
    ec_GFp_mont_felem_sqr(group, &mut z1z1, &(*a).Z);
    let mut z2z2: EC_FELEM = EC_FELEM { words: [0; 9] };
    ec_GFp_mont_felem_sqr(group, &mut z2z2, &(*b).Z);
    let mut u1: EC_FELEM = EC_FELEM { words: [0; 9] };
    ec_GFp_mont_felem_mul(group, &mut u1, &(*a).X, &mut z2z2);
    let mut two_z1z2: EC_FELEM = EC_FELEM { words: [0; 9] };
    ec_felem_add(group, &mut two_z1z2, &(*a).Z, &(*b).Z);
    ec_GFp_mont_felem_sqr(group, &mut two_z1z2, &mut two_z1z2);
    ec_felem_sub(group, &mut two_z1z2, &mut two_z1z2, &mut z1z1);
    ec_felem_sub(group, &mut two_z1z2, &mut two_z1z2, &mut z2z2);
    let mut s1: EC_FELEM = EC_FELEM { words: [0; 9] };
    ec_GFp_mont_felem_mul(group, &mut s1, &(*b).Z, &mut z2z2);
    ec_GFp_mont_felem_mul(group, &mut s1, &mut s1, &(*a).Y);
    let mut u2: EC_FELEM = EC_FELEM { words: [0; 9] };
    ec_GFp_mont_felem_mul(group, &mut u2, &(*b).X, &mut z1z1);
    let mut h: EC_FELEM = EC_FELEM { words: [0; 9] };
    ec_felem_sub(group, &mut h, &mut u2, &mut u1);
    let mut xneq: BN_ULONG = ec_felem_non_zero_mask(group, &mut h);
    ec_GFp_mont_felem_mul(group, &mut z_out, &mut h, &mut two_z1z2);
    let mut z1z1z1: EC_FELEM = EC_FELEM { words: [0; 9] };
    ec_GFp_mont_felem_mul(group, &mut z1z1z1, &(*a).Z, &mut z1z1);
    let mut s2: EC_FELEM = EC_FELEM { words: [0; 9] };
    ec_GFp_mont_felem_mul(group, &mut s2, &(*b).Y, &mut z1z1z1);
    let mut r: EC_FELEM = EC_FELEM { words: [0; 9] };
    ec_felem_sub(group, &mut r, &mut s2, &mut s1);
    ec_felem_add(group, &mut r, &mut r, &mut r);
    let mut yneq: BN_ULONG = ec_felem_non_zero_mask(group, &mut r);
    let mut is_nontrivial_double: BN_ULONG = !xneq & !yneq & z1nz & z2nz;
    if constant_time_declassify_w(is_nontrivial_double) != 0 {
        ec_GFp_mont_dbl(group, out, a);
        return;
    }
    let mut i: EC_FELEM = EC_FELEM { words: [0; 9] };
    ec_felem_add(group, &mut i, &mut h, &mut h);
    ec_GFp_mont_felem_sqr(group, &mut i, &mut i);
    let mut j: EC_FELEM = EC_FELEM { words: [0; 9] };
    ec_GFp_mont_felem_mul(group, &mut j, &mut h, &mut i);
    let mut v: EC_FELEM = EC_FELEM { words: [0; 9] };
    ec_GFp_mont_felem_mul(group, &mut v, &mut u1, &mut i);
    ec_GFp_mont_felem_sqr(group, &mut x_out, &mut r);
    ec_felem_sub(group, &mut x_out, &mut x_out, &mut j);
    ec_felem_sub(group, &mut x_out, &mut x_out, &mut v);
    ec_felem_sub(group, &mut x_out, &mut x_out, &mut v);
    ec_felem_sub(group, &mut y_out, &mut v, &mut x_out);
    ec_GFp_mont_felem_mul(group, &mut y_out, &mut y_out, &mut r);
    let mut s1j: EC_FELEM = EC_FELEM { words: [0; 9] };
    ec_GFp_mont_felem_mul(group, &mut s1j, &mut s1, &mut j);
    ec_felem_sub(group, &mut y_out, &mut y_out, &mut s1j);
    ec_felem_sub(group, &mut y_out, &mut y_out, &mut s1j);
    ec_felem_select(group, &mut x_out, z1nz, &mut x_out, &(*b).X);
    ec_felem_select(group, &mut (*out).X, z2nz, &mut x_out, &(*a).X);
    ec_felem_select(group, &mut y_out, z1nz, &mut y_out, &(*b).Y);
    ec_felem_select(group, &mut (*out).Y, z2nz, &mut y_out, &(*a).Y);
    ec_felem_select(group, &mut z_out, z1nz, &mut z_out, &(*b).Z);
    ec_felem_select(group, &mut (*out).Z, z2nz, &mut z_out, &(*a).Z);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_GFp_mont_dbl(
    mut group: *const EC_GROUP,
    mut r: *mut EC_JACOBIAN,
    mut a: *const EC_JACOBIAN,
) {
    if (*group).a_is_minus3 != 0 {
        let mut delta: EC_FELEM = {
            let mut init = EC_FELEM {
                words: [0 as libc::c_int as BN_ULONG, 0, 0, 0, 0, 0, 0, 0, 0],
            };
            init
        };
        let mut gamma: EC_FELEM = {
            let mut init = EC_FELEM {
                words: [0 as libc::c_int as BN_ULONG, 0, 0, 0, 0, 0, 0, 0, 0],
            };
            init
        };
        let mut beta: EC_FELEM = {
            let mut init = EC_FELEM {
                words: [0 as libc::c_int as BN_ULONG, 0, 0, 0, 0, 0, 0, 0, 0],
            };
            init
        };
        let mut ftmp: EC_FELEM = {
            let mut init = EC_FELEM {
                words: [0 as libc::c_int as BN_ULONG, 0, 0, 0, 0, 0, 0, 0, 0],
            };
            init
        };
        let mut ftmp2: EC_FELEM = {
            let mut init = EC_FELEM {
                words: [0 as libc::c_int as BN_ULONG, 0, 0, 0, 0, 0, 0, 0, 0],
            };
            init
        };
        let mut tmptmp: EC_FELEM = {
            let mut init = EC_FELEM {
                words: [0 as libc::c_int as BN_ULONG, 0, 0, 0, 0, 0, 0, 0, 0],
            };
            init
        };
        let mut alpha: EC_FELEM = {
            let mut init = EC_FELEM {
                words: [0 as libc::c_int as BN_ULONG, 0, 0, 0, 0, 0, 0, 0, 0],
            };
            init
        };
        let mut fourbeta: EC_FELEM = {
            let mut init = EC_FELEM {
                words: [0 as libc::c_int as BN_ULONG, 0, 0, 0, 0, 0, 0, 0, 0],
            };
            init
        };
        ec_GFp_mont_felem_sqr(group, &mut delta, &(*a).Z);
        ec_GFp_mont_felem_sqr(group, &mut gamma, &(*a).Y);
        ec_GFp_mont_felem_mul(group, &mut beta, &(*a).X, &mut gamma);
        ec_felem_sub(group, &mut ftmp, &(*a).X, &mut delta);
        ec_felem_add(group, &mut ftmp2, &(*a).X, &mut delta);
        ec_felem_add(group, &mut tmptmp, &mut ftmp2, &mut ftmp2);
        ec_felem_add(group, &mut ftmp2, &mut ftmp2, &mut tmptmp);
        ec_GFp_mont_felem_mul(group, &mut alpha, &mut ftmp, &mut ftmp2);
        ec_GFp_mont_felem_sqr(group, &mut (*r).X, &mut alpha);
        ec_felem_add(group, &mut fourbeta, &mut beta, &mut beta);
        ec_felem_add(group, &mut fourbeta, &mut fourbeta, &mut fourbeta);
        ec_felem_add(group, &mut tmptmp, &mut fourbeta, &mut fourbeta);
        ec_felem_sub(group, &mut (*r).X, &mut (*r).X, &mut tmptmp);
        ec_felem_add(group, &mut delta, &mut gamma, &mut delta);
        ec_felem_add(group, &mut ftmp, &(*a).Y, &(*a).Z);
        ec_GFp_mont_felem_sqr(group, &mut (*r).Z, &mut ftmp);
        ec_felem_sub(group, &mut (*r).Z, &mut (*r).Z, &mut delta);
        ec_felem_sub(group, &mut (*r).Y, &mut fourbeta, &mut (*r).X);
        ec_felem_add(group, &mut gamma, &mut gamma, &mut gamma);
        ec_GFp_mont_felem_sqr(group, &mut gamma, &mut gamma);
        ec_GFp_mont_felem_mul(group, &mut (*r).Y, &mut alpha, &mut (*r).Y);
        ec_felem_add(group, &mut gamma, &mut gamma, &mut gamma);
        ec_felem_sub(group, &mut (*r).Y, &mut (*r).Y, &mut gamma);
    } else {
        let mut xx: EC_FELEM = EC_FELEM { words: [0; 9] };
        let mut yy: EC_FELEM = EC_FELEM { words: [0; 9] };
        let mut yyyy: EC_FELEM = EC_FELEM { words: [0; 9] };
        let mut zz: EC_FELEM = EC_FELEM { words: [0; 9] };
        ec_GFp_mont_felem_sqr(group, &mut xx, &(*a).X);
        ec_GFp_mont_felem_sqr(group, &mut yy, &(*a).Y);
        ec_GFp_mont_felem_sqr(group, &mut yyyy, &mut yy);
        ec_GFp_mont_felem_sqr(group, &mut zz, &(*a).Z);
        let mut s: EC_FELEM = EC_FELEM { words: [0; 9] };
        ec_felem_add(group, &mut s, &(*a).X, &mut yy);
        ec_GFp_mont_felem_sqr(group, &mut s, &mut s);
        ec_felem_sub(group, &mut s, &mut s, &mut xx);
        ec_felem_sub(group, &mut s, &mut s, &mut yyyy);
        ec_felem_add(group, &mut s, &mut s, &mut s);
        let mut m: EC_FELEM = EC_FELEM { words: [0; 9] };
        ec_GFp_mont_felem_sqr(group, &mut m, &mut zz);
        ec_GFp_mont_felem_mul(group, &mut m, &(*group).a, &mut m);
        ec_felem_add(group, &mut m, &mut m, &mut xx);
        ec_felem_add(group, &mut m, &mut m, &mut xx);
        ec_felem_add(group, &mut m, &mut m, &mut xx);
        ec_GFp_mont_felem_sqr(group, &mut (*r).X, &mut m);
        ec_felem_sub(group, &mut (*r).X, &mut (*r).X, &mut s);
        ec_felem_sub(group, &mut (*r).X, &mut (*r).X, &mut s);
        ec_felem_add(group, &mut (*r).Z, &(*a).Y, &(*a).Z);
        ec_GFp_mont_felem_sqr(group, &mut (*r).Z, &mut (*r).Z);
        ec_felem_sub(group, &mut (*r).Z, &mut (*r).Z, &mut yy);
        ec_felem_sub(group, &mut (*r).Z, &mut (*r).Z, &mut zz);
        ec_felem_add(group, &mut yyyy, &mut yyyy, &mut yyyy);
        ec_felem_add(group, &mut yyyy, &mut yyyy, &mut yyyy);
        ec_felem_add(group, &mut yyyy, &mut yyyy, &mut yyyy);
        ec_felem_sub(group, &mut (*r).Y, &mut s, &mut (*r).X);
        ec_GFp_mont_felem_mul(group, &mut (*r).Y, &mut (*r).Y, &mut m);
        ec_felem_sub(group, &mut (*r).Y, &mut (*r).Y, &mut yyyy);
    };
}
unsafe extern "C" fn ec_GFp_mont_cmp_x_coordinate(
    mut group: *const EC_GROUP,
    mut p: *const EC_JACOBIAN,
    mut r: *const EC_SCALAR,
) -> libc::c_int {
    if (*group).field_greater_than_order == 0
        || (*group).field.N.width != (*group).order.N.width
    {
        return ec_GFp_simple_cmp_x_coordinate(group, p, r);
    }
    if ec_GFp_simple_is_at_infinity(group, p) != 0 {
        return 0 as libc::c_int;
    }
    let mut r_Z2: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut Z2_mont: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut X: EC_FELEM = EC_FELEM { words: [0; 9] };
    ec_GFp_mont_felem_mul(group, &mut Z2_mont, &(*p).Z, &(*p).Z);
    OPENSSL_memcpy(
        (r_Z2.words).as_mut_ptr() as *mut libc::c_void,
        ((*r).words).as_ptr() as *const libc::c_void,
        ((*group).field.N.width as libc::c_ulong)
            .wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    );
    ec_GFp_mont_felem_mul(group, &mut r_Z2, &mut r_Z2, &mut Z2_mont);
    ec_GFp_mont_felem_from_montgomery(group, &mut X, &(*p).X);
    if ec_felem_equal(group, &mut r_Z2, &mut X) != 0 {
        return 1 as libc::c_int;
    }
    let mut carry: BN_ULONG = bn_add_words(
        (r_Z2.words).as_mut_ptr(),
        ((*r).words).as_ptr(),
        (*group).order.N.d,
        (*group).field.N.width as size_t,
    );
    if carry == 0 as libc::c_int as BN_ULONG
        && bn_less_than_words(
            (r_Z2.words).as_mut_ptr(),
            (*group).field.N.d,
            (*group).field.N.width as size_t,
        ) != 0
    {
        ec_GFp_mont_felem_mul(group, &mut r_Z2, &mut r_Z2, &mut Z2_mont);
        if ec_felem_equal(group, &mut r_Z2, &mut X) != 0 {
            return 1 as libc::c_int;
        }
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn EC_GFp_mont_method_storage_bss_get() -> *mut EC_METHOD {
    return &mut EC_GFp_mont_method_storage;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_GFp_mont_method() -> *const EC_METHOD {
    CRYPTO_once(
        EC_GFp_mont_method_once_bss_get(),
        Some(EC_GFp_mont_method_init as unsafe extern "C" fn() -> ()),
    );
    return EC_GFp_mont_method_storage_bss_get() as *const EC_METHOD;
}
unsafe extern "C" fn EC_GFp_mont_method_init() {
    EC_GFp_mont_method_do_init(EC_GFp_mont_method_storage_bss_get());
}
unsafe extern "C" fn EC_GFp_mont_method_do_init(mut out: *mut EC_METHOD) {
    (*out)
        .point_get_affine_coordinates = Some(
        ec_GFp_mont_point_get_affine_coordinates
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *const EC_JACOBIAN,
                *mut EC_FELEM,
                *mut EC_FELEM,
            ) -> libc::c_int,
    );
    (*out)
        .jacobian_to_affine_batch = Some(
        ec_GFp_mont_jacobian_to_affine_batch
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_AFFINE,
                *const EC_JACOBIAN,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .add = Some(
        ec_GFp_mont_add
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_JACOBIAN,
                *const EC_JACOBIAN,
                *const EC_JACOBIAN,
            ) -> (),
    );
    (*out)
        .dbl = Some(
        ec_GFp_mont_dbl
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_JACOBIAN,
                *const EC_JACOBIAN,
            ) -> (),
    );
    (*out)
        .mul = Some(
        ec_GFp_mont_mul
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_JACOBIAN,
                *const EC_JACOBIAN,
                *const EC_SCALAR,
            ) -> (),
    );
    (*out)
        .mul_base = Some(
        ec_GFp_mont_mul_base
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_JACOBIAN,
                *const EC_SCALAR,
            ) -> (),
    );
    (*out)
        .mul_batch = Some(
        ec_GFp_mont_mul_batch
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_JACOBIAN,
                *const EC_JACOBIAN,
                *const EC_SCALAR,
                *const EC_JACOBIAN,
                *const EC_SCALAR,
                *const EC_JACOBIAN,
                *const EC_SCALAR,
            ) -> (),
    );
    (*out)
        .mul_public_batch = Some(
        ec_GFp_mont_mul_public_batch
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_JACOBIAN,
                *const EC_SCALAR,
                *const EC_JACOBIAN,
                *const EC_SCALAR,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .init_precomp = Some(
        ec_GFp_mont_init_precomp
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_PRECOMP,
                *const EC_JACOBIAN,
            ) -> libc::c_int,
    );
    (*out)
        .mul_precomp = Some(
        ec_GFp_mont_mul_precomp
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *mut EC_JACOBIAN,
                *const EC_PRECOMP,
                *const EC_SCALAR,
                *const EC_PRECOMP,
                *const EC_SCALAR,
                *const EC_PRECOMP,
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
        ec_GFp_mont_cmp_x_coordinate
            as unsafe extern "C" fn(
                *const EC_GROUP,
                *const EC_JACOBIAN,
                *const EC_SCALAR,
            ) -> libc::c_int,
    );
}
static mut EC_GFp_mont_method_storage: EC_METHOD = ec_method_st {
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
unsafe extern "C" fn EC_GFp_mont_method_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EC_GFp_mont_method_once;
}
static mut EC_GFp_mont_method_once: CRYPTO_once_t = 0 as libc::c_int;
