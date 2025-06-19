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
    pub type bignum_ctx;
    fn BN_copy(dest: *mut BIGNUM, src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_value_one() -> *const BIGNUM;
    fn BN_num_bits(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_num_bytes(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_CTX_start(ctx: *mut BN_CTX);
    fn BN_CTX_get(ctx: *mut BN_CTX) -> *mut BIGNUM;
    fn BN_CTX_end(ctx: *mut BN_CTX);
    fn BN_add_word(a: *mut BIGNUM, w: BN_ULONG) -> libc::c_int;
    fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_is_odd(bn: *const BIGNUM) -> libc::c_int;
    fn BN_MONT_CTX_set(
        mont: *mut BN_MONT_CTX,
        mod_0: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn ec_scalar_equal_vartime(
        group: *const EC_GROUP,
        a: *const EC_SCALAR,
        b: *const EC_SCALAR,
    ) -> libc::c_int;
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
    fn ec_felem_non_zero_mask(group: *const EC_GROUP, a: *const EC_FELEM) -> BN_ULONG;
    fn ec_get_x_coordinate_as_scalar(
        group: *const EC_GROUP,
        out: *mut EC_SCALAR,
        p: *const EC_JACOBIAN,
    ) -> libc::c_int;
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
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn bn_less_than_words(
        a: *const BN_ULONG,
        b: *const BN_ULONG,
        len: size_t,
    ) -> libc::c_int;
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
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint64_t = __uint64_t;
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
#[no_mangle]
pub unsafe extern "C" fn ec_GFp_simple_group_set_curve(
    mut group: *mut EC_GROUP,
    mut p: *const BIGNUM,
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if BN_num_bits(p) <= 2 as libc::c_int as libc::c_uint || BN_is_odd(p) == 0 {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            110 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/simple.c\0"
                as *const u8 as *const libc::c_char,
            96 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    BN_CTX_start(ctx);
    let mut tmp: *mut BIGNUM = BN_CTX_get(ctx);
    if !tmp.is_null() {
        if !(BN_MONT_CTX_set(&mut (*group).field, p, ctx) == 0
            || ec_bignum_to_felem(group, &mut (*group).a, a) == 0
            || ec_bignum_to_felem(group, &mut (*group).b, b) == 0
            || ec_bignum_to_felem(group, &mut (*group).generator.raw.Z, BN_value_one())
                == 0)
        {
            if !((BN_copy(tmp, a)).is_null()
                || BN_add_word(tmp, 3 as libc::c_int as BN_ULONG) == 0)
            {
                (*group)
                    .a_is_minus3 = (0 as libc::c_int
                    == BN_cmp(tmp, &mut (*group).field.N)) as libc::c_int;
                ret = 1 as libc::c_int;
            }
        }
    }
    BN_CTX_end(ctx);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn ec_GFp_simple_group_get_curve(
    mut group: *const EC_GROUP,
    mut p: *mut BIGNUM,
    mut a: *mut BIGNUM,
    mut b: *mut BIGNUM,
) -> libc::c_int {
    if !p.is_null() && (BN_copy(p, &(*group).field.N)).is_null()
        || !a.is_null() && ec_felem_to_bignum(group, a, &(*group).a) == 0
        || !b.is_null() && ec_felem_to_bignum(group, b, &(*group).b) == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ec_GFp_simple_point_init(mut point: *mut EC_JACOBIAN) {
    OPENSSL_memset(
        &mut (*point).X as *mut EC_FELEM as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EC_FELEM>() as libc::c_ulong,
    );
    OPENSSL_memset(
        &mut (*point).Y as *mut EC_FELEM as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EC_FELEM>() as libc::c_ulong,
    );
    OPENSSL_memset(
        &mut (*point).Z as *mut EC_FELEM as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EC_FELEM>() as libc::c_ulong,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ec_GFp_simple_point_copy(
    mut dest: *mut EC_JACOBIAN,
    mut src: *const EC_JACOBIAN,
) {
    OPENSSL_memcpy(
        &mut (*dest).X as *mut EC_FELEM as *mut libc::c_void,
        &(*src).X as *const EC_FELEM as *const libc::c_void,
        ::core::mem::size_of::<EC_FELEM>() as libc::c_ulong,
    );
    OPENSSL_memcpy(
        &mut (*dest).Y as *mut EC_FELEM as *mut libc::c_void,
        &(*src).Y as *const EC_FELEM as *const libc::c_void,
        ::core::mem::size_of::<EC_FELEM>() as libc::c_ulong,
    );
    OPENSSL_memcpy(
        &mut (*dest).Z as *mut EC_FELEM as *mut libc::c_void,
        &(*src).Z as *const EC_FELEM as *const libc::c_void,
        ::core::mem::size_of::<EC_FELEM>() as libc::c_ulong,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ec_GFp_simple_point_set_to_infinity(
    mut group: *const EC_GROUP,
    mut point: *mut EC_JACOBIAN,
) {
    ec_GFp_simple_point_init(point);
}
#[no_mangle]
pub unsafe extern "C" fn ec_GFp_simple_invert(
    mut group: *const EC_GROUP,
    mut point: *mut EC_JACOBIAN,
) {
    ec_felem_neg(group, &mut (*point).Y, &mut (*point).Y);
}
#[no_mangle]
pub unsafe extern "C" fn ec_GFp_simple_is_at_infinity(
    mut group: *const EC_GROUP,
    mut point: *const EC_JACOBIAN,
) -> libc::c_int {
    return (ec_felem_non_zero_mask(group, &(*point).Z) == 0 as libc::c_int as BN_ULONG)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ec_GFp_simple_is_on_curve(
    mut group: *const EC_GROUP,
    mut point: *const EC_JACOBIAN,
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
    let mut rh: EC_FELEM = EC_FELEM { words: [0; 9] };
    felem_sqr.expect("non-null function pointer")(group, &mut rh, &(*point).X);
    let mut tmp: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut Z4: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut Z6: EC_FELEM = EC_FELEM { words: [0; 9] };
    felem_sqr.expect("non-null function pointer")(group, &mut tmp, &(*point).Z);
    felem_sqr.expect("non-null function pointer")(group, &mut Z4, &mut tmp);
    felem_mul.expect("non-null function pointer")(group, &mut Z6, &mut Z4, &mut tmp);
    if (*group).a_is_minus3 != 0 {
        ec_felem_add(group, &mut tmp, &mut Z4, &mut Z4);
        ec_felem_add(group, &mut tmp, &mut tmp, &mut Z4);
        ec_felem_sub(group, &mut rh, &mut rh, &mut tmp);
    } else {
        felem_mul
            .expect("non-null function pointer")(group, &mut tmp, &mut Z4, &(*group).a);
        ec_felem_add(group, &mut rh, &mut rh, &mut tmp);
    }
    felem_mul.expect("non-null function pointer")(group, &mut rh, &mut rh, &(*point).X);
    felem_mul.expect("non-null function pointer")(group, &mut tmp, &(*group).b, &mut Z6);
    ec_felem_add(group, &mut rh, &mut rh, &mut tmp);
    felem_sqr.expect("non-null function pointer")(group, &mut tmp, &(*point).Y);
    ec_felem_sub(group, &mut tmp, &mut tmp, &mut rh);
    let mut not_equal: BN_ULONG = ec_felem_non_zero_mask(group, &mut tmp);
    let mut not_infinity: BN_ULONG = ec_felem_non_zero_mask(group, &(*point).Z);
    return (1 as libc::c_int as BN_ULONG & !(not_infinity & not_equal)) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ec_GFp_simple_points_equal(
    mut group: *const EC_GROUP,
    mut a: *const EC_JACOBIAN,
    mut b: *const EC_JACOBIAN,
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
    let mut tmp1: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut tmp2: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut Za23: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut Zb23: EC_FELEM = EC_FELEM { words: [0; 9] };
    felem_sqr.expect("non-null function pointer")(group, &mut Zb23, &(*b).Z);
    felem_mul.expect("non-null function pointer")(group, &mut tmp1, &(*a).X, &mut Zb23);
    felem_sqr.expect("non-null function pointer")(group, &mut Za23, &(*a).Z);
    felem_mul.expect("non-null function pointer")(group, &mut tmp2, &(*b).X, &mut Za23);
    ec_felem_sub(group, &mut tmp1, &mut tmp1, &mut tmp2);
    let x_not_equal: BN_ULONG = ec_felem_non_zero_mask(group, &mut tmp1);
    felem_mul.expect("non-null function pointer")(group, &mut Zb23, &mut Zb23, &(*b).Z);
    felem_mul.expect("non-null function pointer")(group, &mut tmp1, &(*a).Y, &mut Zb23);
    felem_mul.expect("non-null function pointer")(group, &mut Za23, &mut Za23, &(*a).Z);
    felem_mul.expect("non-null function pointer")(group, &mut tmp2, &(*b).Y, &mut Za23);
    ec_felem_sub(group, &mut tmp1, &mut tmp1, &mut tmp2);
    let y_not_equal: BN_ULONG = ec_felem_non_zero_mask(group, &mut tmp1);
    let x_and_y_equal: BN_ULONG = !(x_not_equal | y_not_equal);
    let a_not_infinity: BN_ULONG = ec_felem_non_zero_mask(group, &(*a).Z);
    let b_not_infinity: BN_ULONG = ec_felem_non_zero_mask(group, &(*b).Z);
    let a_and_b_infinity: BN_ULONG = !(a_not_infinity | b_not_infinity);
    let equal: BN_ULONG = a_and_b_infinity
        | a_not_infinity & b_not_infinity & x_and_y_equal;
    return (equal & 1 as libc::c_int as BN_ULONG) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ec_affine_jacobian_equal(
    mut group: *const EC_GROUP,
    mut a: *const EC_AFFINE,
    mut b: *const EC_JACOBIAN,
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
    let mut tmp: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut Zb2: EC_FELEM = EC_FELEM { words: [0; 9] };
    felem_sqr.expect("non-null function pointer")(group, &mut Zb2, &(*b).Z);
    felem_mul.expect("non-null function pointer")(group, &mut tmp, &(*a).X, &mut Zb2);
    ec_felem_sub(group, &mut tmp, &mut tmp, &(*b).X);
    let x_not_equal: BN_ULONG = ec_felem_non_zero_mask(group, &mut tmp);
    felem_mul.expect("non-null function pointer")(group, &mut tmp, &(*a).Y, &mut Zb2);
    felem_mul.expect("non-null function pointer")(group, &mut tmp, &mut tmp, &(*b).Z);
    ec_felem_sub(group, &mut tmp, &mut tmp, &(*b).Y);
    let y_not_equal: BN_ULONG = ec_felem_non_zero_mask(group, &mut tmp);
    let x_and_y_equal: BN_ULONG = !(x_not_equal | y_not_equal);
    let b_not_infinity: BN_ULONG = ec_felem_non_zero_mask(group, &(*b).Z);
    let equal: BN_ULONG = b_not_infinity & x_and_y_equal;
    return (equal & 1 as libc::c_int as BN_ULONG) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ec_GFp_simple_cmp_x_coordinate(
    mut group: *const EC_GROUP,
    mut p: *const EC_JACOBIAN,
    mut r: *const EC_SCALAR,
) -> libc::c_int {
    if ec_GFp_simple_is_at_infinity(group, p) != 0 {
        return 0 as libc::c_int;
    }
    let mut x: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    return (ec_get_x_coordinate_as_scalar(group, &mut x, p) != 0
        && ec_scalar_equal_vartime(group, &mut x, r) != 0) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ec_GFp_simple_felem_to_bytes(
    mut group: *const EC_GROUP,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
    mut in_0: *const EC_FELEM,
) {
    let mut len: size_t = BN_num_bytes(&(*group).field.N) as size_t;
    bn_words_to_big_endian(
        out,
        len,
        ((*in_0).words).as_ptr(),
        (*group).field.N.width as size_t,
    );
    *out_len = len;
}
#[no_mangle]
pub unsafe extern "C" fn ec_GFp_simple_felem_from_bytes(
    mut group: *const EC_GROUP,
    mut out: *mut EC_FELEM,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    if len != BN_num_bytes(&(*group).field.N) as size_t {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            128 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/simple.c\0"
                as *const u8 as *const libc::c_char,
            324 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    bn_big_endian_to_words(
        ((*out).words).as_mut_ptr(),
        (*group).field.N.width as size_t,
        in_0,
        len,
    );
    if bn_less_than_words(
        ((*out).words).as_mut_ptr(),
        (*group).field.N.d,
        (*group).field.N.width as size_t,
    ) == 0
    {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            128 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/simple.c\0"
                as *const u8 as *const libc::c_char,
            331 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
