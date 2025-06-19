#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(extern_types, label_break_value)]
extern "C" {
    pub type bignum_ctx;
    fn BN_num_bytes(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_is_negative(bn: *const BIGNUM) -> libc::c_int;
    fn BN_bin2bn(in_0: *const uint8_t, len: size_t, ret: *mut BIGNUM) -> *mut BIGNUM;
    fn BN_CTX_new() -> *mut BN_CTX;
    fn BN_CTX_free(ctx: *mut BN_CTX);
    fn BN_CTX_start(ctx: *mut BN_CTX);
    fn BN_CTX_get(ctx: *mut BN_CTX) -> *mut BIGNUM;
    fn BN_CTX_end(ctx: *mut BN_CTX);
    fn BN_usub(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_ucmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_is_zero(bn: *const BIGNUM) -> libc::c_int;
    fn BN_is_odd(bn: *const BIGNUM) -> libc::c_int;
    fn BN_mod_mul(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        b: *const BIGNUM,
        m: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_mod_sqr(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        m: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_mod_sqrt(
        in_0: *mut BIGNUM,
        a: *const BIGNUM,
        p: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> *mut BIGNUM;
    fn ec_felem_to_bytes(
        group: *const EC_GROUP,
        out: *mut uint8_t,
        out_len: *mut size_t,
        in_0: *const EC_FELEM,
    );
    fn ec_felem_from_bytes(
        group: *const EC_GROUP,
        out: *mut EC_FELEM,
        in_0: *const uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn ec_affine_to_jacobian(
        group: *const EC_GROUP,
        out: *mut EC_JACOBIAN,
        p: *const EC_AFFINE,
    );
    fn ec_jacobian_to_affine(
        group: *const EC_GROUP,
        out: *mut EC_AFFINE,
        p: *const EC_JACOBIAN,
    ) -> libc::c_int;
    fn ec_point_set_affine_coordinates(
        group: *const EC_GROUP,
        out: *mut EC_AFFINE,
        x: *const EC_FELEM,
        y: *const EC_FELEM,
    ) -> libc::c_int;
    fn ec_set_to_safe_point(group: *const EC_GROUP, out: *mut EC_JACOBIAN);
    fn ec_GFp_simple_point_set_to_infinity(_: *const EC_GROUP, _: *mut EC_JACOBIAN);
    fn ec_GFp_simple_is_at_infinity(
        _: *const EC_GROUP,
        _: *const EC_JACOBIAN,
    ) -> libc::c_int;
    fn EC_GROUP_cmp(
        a: *const EC_GROUP,
        b: *const EC_GROUP,
        ignored: *mut BN_CTX,
    ) -> libc::c_int;
    fn EC_GROUP_get_curve_GFp(
        group: *const EC_GROUP,
        out_p: *mut BIGNUM,
        out_a: *mut BIGNUM,
        out_b: *mut BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn EC_POINT_set_affine_coordinates_GFp(
        group: *const EC_GROUP,
        point: *mut EC_POINT,
        x: *const BIGNUM,
        y: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn ERR_peek_last_error() -> uint32_t;
    fn ERR_clear_error();
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
    fn bn_mod_add_consttime(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        b: *const BIGNUM,
        m: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn bn_mod_sub_consttime(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        b: *const BIGNUM,
        m: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn bn_mod_lshift1_consttime(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        m: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
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
unsafe extern "C" fn ERR_GET_LIB(mut packed_error: uint32_t) -> libc::c_int {
    return (packed_error >> 24 as libc::c_int & 0xff as libc::c_int as uint32_t)
        as libc::c_int;
}
#[inline]
unsafe extern "C" fn ERR_GET_REASON(mut packed_error: uint32_t) -> libc::c_int {
    return (packed_error & 0xfff as libc::c_int as uint32_t) as libc::c_int;
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
unsafe extern "C" fn is_point_conversion_form_hybrid(
    mut form_bit: libc::c_int,
) -> libc::c_int {
    return (POINT_CONVERSION_HYBRID as libc::c_int as libc::c_uint
        == form_bit as libc::c_uint & !(1 as libc::c_uint)) as libc::c_int;
}
unsafe extern "C" fn is_hybrid_bytes_consistent(
    mut in_0: *const uint8_t,
    mut field_len: size_t,
) -> libc::c_int {
    return (*in_0.offset(0 as libc::c_int as isize) as libc::c_int & 1 as libc::c_int
        == *in_0
            .offset(
                (1 as libc::c_int as size_t)
                    .wrapping_add(field_len * 2 as libc::c_int as size_t)
                    .wrapping_sub(1 as libc::c_int as size_t) as isize,
            ) as libc::c_int & 1 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ec_point_byte_len(
    mut group: *const EC_GROUP,
    mut form: point_conversion_form_t,
) -> size_t {
    if form as libc::c_uint != POINT_CONVERSION_COMPRESSED as libc::c_int as libc::c_uint
        && form as libc::c_uint
            != POINT_CONVERSION_UNCOMPRESSED as libc::c_int as libc::c_uint
        && form as libc::c_uint != POINT_CONVERSION_HYBRID as libc::c_int as libc::c_uint
    {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            111 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/oct.c\0"
                as *const u8 as *const libc::c_char,
            89 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int as size_t;
    }
    let field_len: size_t = BN_num_bytes(&(*group).field.N) as size_t;
    let mut output_len: size_t = (1 as libc::c_int as size_t).wrapping_add(field_len);
    if form as libc::c_uint
        == POINT_CONVERSION_UNCOMPRESSED as libc::c_int as libc::c_uint
        || form as libc::c_uint == POINT_CONVERSION_HYBRID as libc::c_int as libc::c_uint
    {
        output_len = output_len.wrapping_add(field_len);
    }
    return output_len;
}
#[no_mangle]
pub unsafe extern "C" fn ec_point_to_bytes(
    mut group: *const EC_GROUP,
    mut point: *const EC_AFFINE,
    mut form: point_conversion_form_t,
    mut buf: *mut uint8_t,
    mut len: size_t,
) -> size_t {
    let mut output_len: size_t = ec_point_byte_len(group, form);
    if len < output_len {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/oct.c\0"
                as *const u8 as *const libc::c_char,
            108 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int as size_t;
    }
    let mut field_len: size_t = 0;
    ec_felem_to_bytes(
        group,
        buf.offset(1 as libc::c_int as isize),
        &mut field_len,
        &(*point).X,
    );
    if field_len == BN_num_bytes(&(*group).field.N) as size_t {} else {
        __assert_fail(
            b"field_len == BN_num_bytes(&group->field.N)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/oct.c\0"
                as *const u8 as *const libc::c_char,
            114 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 106],
                &[libc::c_char; 106],
            >(
                b"size_t ec_point_to_bytes(const EC_GROUP *, const EC_AFFINE *, point_conversion_form_t, uint8_t *, size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_1966: {
        if field_len == BN_num_bytes(&(*group).field.N) as size_t {} else {
            __assert_fail(
                b"field_len == BN_num_bytes(&group->field.N)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/oct.c\0"
                    as *const u8 as *const libc::c_char,
                114 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 106],
                    &[libc::c_char; 106],
                >(
                    b"size_t ec_point_to_bytes(const EC_GROUP *, const EC_AFFINE *, point_conversion_form_t, uint8_t *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if form as libc::c_uint
        == POINT_CONVERSION_UNCOMPRESSED as libc::c_int as libc::c_uint
    {
        ec_felem_to_bytes(
            group,
            buf.offset(1 as libc::c_int as isize).offset(field_len as isize),
            &mut field_len,
            &(*point).Y,
        );
        if field_len == BN_num_bytes(&(*group).field.N) as size_t {} else {
            __assert_fail(
                b"field_len == BN_num_bytes(&group->field.N)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/oct.c\0"
                    as *const u8 as *const libc::c_char,
                118 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 106],
                    &[libc::c_char; 106],
                >(
                    b"size_t ec_point_to_bytes(const EC_GROUP *, const EC_AFFINE *, point_conversion_form_t, uint8_t *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_1881: {
            if field_len == BN_num_bytes(&(*group).field.N) as size_t {} else {
                __assert_fail(
                    b"field_len == BN_num_bytes(&group->field.N)\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/oct.c\0"
                        as *const u8 as *const libc::c_char,
                    118 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 106],
                        &[libc::c_char; 106],
                    >(
                        b"size_t ec_point_to_bytes(const EC_GROUP *, const EC_AFFINE *, point_conversion_form_t, uint8_t *, size_t)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        *buf.offset(0 as libc::c_int as isize) = form as uint8_t;
    } else {
        let mut y_buf: [uint8_t; 66] = [0; 66];
        ec_felem_to_bytes(group, y_buf.as_mut_ptr(), &mut field_len, &(*point).Y);
        *buf
            .offset(
                0 as libc::c_int as isize,
            ) = (form as libc::c_uint)
            .wrapping_add(
                (y_buf[field_len.wrapping_sub(1 as libc::c_int as size_t) as usize]
                    as libc::c_int & 1 as libc::c_int) as libc::c_uint,
            ) as uint8_t;
        if form as libc::c_uint == POINT_CONVERSION_HYBRID as libc::c_int as libc::c_uint
        {
            OPENSSL_memcpy(
                buf.offset(1 as libc::c_int as isize).offset(field_len as isize)
                    as *mut libc::c_void,
                y_buf.as_mut_ptr() as *const libc::c_void,
                field_len,
            );
        }
    }
    return output_len;
}
#[no_mangle]
pub unsafe extern "C" fn ec_point_from_uncompressed(
    mut group: *const EC_GROUP,
    mut out: *mut EC_AFFINE,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let field_len: size_t = BN_num_bytes(&(*group).field.N) as size_t;
    if len
        != (1 as libc::c_int as size_t)
            .wrapping_add(2 as libc::c_int as size_t * field_len)
        || *in_0.offset(0 as libc::c_int as isize) as libc::c_int
            != POINT_CONVERSION_UNCOMPRESSED as libc::c_int
    {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/oct.c\0"
                as *const u8 as *const libc::c_char,
            138 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut x: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut y: EC_FELEM = EC_FELEM { words: [0; 9] };
    if ec_felem_from_bytes(
        group,
        &mut x,
        in_0.offset(1 as libc::c_int as isize),
        field_len,
    ) == 0
        || ec_felem_from_bytes(
            group,
            &mut y,
            in_0.offset(1 as libc::c_int as isize).offset(field_len as isize),
            field_len,
        ) == 0 || ec_point_set_affine_coordinates(group, out, &mut x, &mut y) == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn ec_point_from_hybrid(
    mut group: *const EC_GROUP,
    mut out: *mut EC_AFFINE,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let field_len: size_t = BN_num_bytes(&(*group).field.N) as size_t;
    if len
        != (1 as libc::c_int as size_t)
            .wrapping_add(2 as libc::c_int as size_t * field_len)
        || is_point_conversion_form_hybrid(
            *in_0.offset(0 as libc::c_int as isize) as libc::c_int,
        ) == 0 || is_hybrid_bytes_consistent(in_0, field_len) == 0
    {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/oct.c\0"
                as *const u8 as *const libc::c_char,
            159 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut x: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut y: EC_FELEM = EC_FELEM { words: [0; 9] };
    if ec_felem_from_bytes(
        group,
        &mut x,
        in_0.offset(1 as libc::c_int as isize),
        field_len,
    ) == 0
        || ec_felem_from_bytes(
            group,
            &mut y,
            in_0.offset(1 as libc::c_int as isize).offset(field_len as isize),
            field_len,
        ) == 0 || ec_point_set_affine_coordinates(group, out, &mut x, &mut y) == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn ec_GFp_simple_oct2point(
    mut group: *const EC_GROUP,
    mut point: *mut EC_POINT,
    mut buf: *const uint8_t,
    mut len: size_t,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if len == 0 as libc::c_int as size_t {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/oct.c\0"
                as *const u8 as *const libc::c_char,
            177 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut form: point_conversion_form_t = *buf.offset(0 as libc::c_int as isize)
        as point_conversion_form_t;
    if form as libc::c_uint == 0 as libc::c_int as libc::c_uint {
        if len != 1 as libc::c_int as size_t {
            ERR_put_error(
                15 as libc::c_int,
                0 as libc::c_int,
                109 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/oct.c\0"
                    as *const u8 as *const libc::c_char,
                186 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        ec_GFp_simple_point_set_to_infinity(group, &mut (*point).raw);
        return 1 as libc::c_int;
    }
    let y_bit: libc::c_int = (form as libc::c_uint & 1 as libc::c_int as libc::c_uint)
        as libc::c_int;
    form = (form as libc::c_uint & !(1 as libc::c_uint)) as point_conversion_form_t;
    if form as libc::c_uint
        == POINT_CONVERSION_UNCOMPRESSED as libc::c_int as libc::c_uint
    {
        let mut affine: EC_AFFINE = EC_AFFINE {
            X: EC_FELEM { words: [0; 9] },
            Y: EC_FELEM { words: [0; 9] },
        };
        if ec_point_from_uncompressed(group, &mut affine, buf, len) == 0 {
            ec_set_to_safe_point(group, &mut (*point).raw);
            return 0 as libc::c_int;
        }
        ec_affine_to_jacobian(group, &mut (*point).raw, &mut affine);
        return 1 as libc::c_int;
    }
    if form as libc::c_uint == POINT_CONVERSION_HYBRID as libc::c_int as libc::c_uint {
        let mut affine_0: EC_AFFINE = EC_AFFINE {
            X: EC_FELEM { words: [0; 9] },
            Y: EC_FELEM { words: [0; 9] },
        };
        if ec_point_from_hybrid(group, &mut affine_0, buf, len) == 0 {
            ec_set_to_safe_point(group, &mut (*point).raw);
            return 0 as libc::c_int;
        }
        ec_affine_to_jacobian(group, &mut (*point).raw, &mut affine_0);
        return 1 as libc::c_int;
    }
    let field_len: size_t = BN_num_bytes(&(*group).field.N) as size_t;
    if form as libc::c_uint != POINT_CONVERSION_COMPRESSED as libc::c_int as libc::c_uint
        || len != (1 as libc::c_int as size_t).wrapping_add(field_len)
    {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/oct.c\0"
                as *const u8 as *const libc::c_char,
            221 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut new_ctx: *mut BN_CTX = 0 as *mut BN_CTX;
    if ctx.is_null() {
        new_ctx = BN_CTX_new();
        ctx = new_ctx;
        if ctx.is_null() {
            return 0 as libc::c_int;
        }
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    BN_CTX_start(ctx);
    let mut x: *mut BIGNUM = BN_CTX_get(ctx);
    if !(x.is_null()
        || (BN_bin2bn(buf.offset(1 as libc::c_int as isize), field_len, x)).is_null())
    {
        if BN_ucmp(x, &(*group).field.N) >= 0 as libc::c_int {
            ERR_put_error(
                15 as libc::c_int,
                0 as libc::c_int,
                109 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/oct.c\0"
                    as *const u8 as *const libc::c_char,
                245 as libc::c_int as libc::c_uint,
            );
        } else if !(EC_POINT_set_compressed_coordinates_GFp(group, point, x, y_bit, ctx)
            == 0)
        {
            ret = 1 as libc::c_int;
        }
    }
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_oct2point(
    mut group: *const EC_GROUP,
    mut point: *mut EC_POINT,
    mut buf: *const uint8_t,
    mut len: size_t,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    if EC_GROUP_cmp(group, (*point).group, 0 as *mut BN_CTX) != 0 as libc::c_int {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/oct.c\0"
                as *const u8 as *const libc::c_char,
            264 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ec_GFp_simple_oct2point(group, point, buf, len, ctx);
}
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_point2oct(
    mut group: *const EC_GROUP,
    mut point: *const EC_POINT,
    mut form: point_conversion_form_t,
    mut buf: *mut uint8_t,
    mut len: size_t,
    mut ctx: *mut BN_CTX,
) -> size_t {
    if EC_GROUP_cmp(group, (*point).group, 0 as *mut BN_CTX) != 0 as libc::c_int {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/oct.c\0"
                as *const u8 as *const libc::c_char,
            274 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int as size_t;
    }
    if ec_GFp_simple_is_at_infinity(group, &(*point).raw) != 0 {
        if !buf.is_null() {
            if len < 1 as libc::c_int as size_t {
                ERR_put_error(
                    15 as libc::c_int,
                    0 as libc::c_int,
                    100 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/oct.c\0"
                        as *const u8 as *const libc::c_char,
                    282 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int as size_t;
            }
            *buf.offset(0 as libc::c_int as isize) = 0 as libc::c_int as uint8_t;
        }
        return 1 as libc::c_int as size_t;
    }
    if buf.is_null() {
        return ec_point_byte_len(group, form);
    }
    let mut affine: EC_AFFINE = EC_AFFINE {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
    };
    if ec_jacobian_to_affine(group, &mut affine, &(*point).raw) == 0 {
        return 0 as libc::c_int as size_t;
    }
    return ec_point_to_bytes(group, &mut affine, form, buf, len);
}
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_set_compressed_coordinates_GFp(
    mut group: *const EC_GROUP,
    mut point: *mut EC_POINT,
    mut x: *const BIGNUM,
    mut y_bit: libc::c_int,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut current_block: u64;
    if EC_GROUP_cmp(group, (*point).group, 0 as *mut BN_CTX) != 0 as libc::c_int {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/oct.c\0"
                as *const u8 as *const libc::c_char,
            306 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut field: *const BIGNUM = &(*group).field.N;
    if BN_is_negative(x) != 0 || BN_cmp(x, field) >= 0 as libc::c_int {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            107 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/oct.c\0"
                as *const u8 as *const libc::c_char,
            312 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut new_ctx: *mut BN_CTX = 0 as *mut BN_CTX;
    let mut ret: libc::c_int = 0 as libc::c_int;
    ERR_clear_error();
    if ctx.is_null() {
        new_ctx = BN_CTX_new();
        ctx = new_ctx;
        if ctx.is_null() {
            return 0 as libc::c_int;
        }
    }
    y_bit = (y_bit != 0 as libc::c_int) as libc::c_int;
    BN_CTX_start(ctx);
    let mut tmp1: *mut BIGNUM = BN_CTX_get(ctx);
    let mut tmp2: *mut BIGNUM = BN_CTX_get(ctx);
    let mut a: *mut BIGNUM = BN_CTX_get(ctx);
    let mut b: *mut BIGNUM = BN_CTX_get(ctx);
    let mut y: *mut BIGNUM = BN_CTX_get(ctx);
    if !(y.is_null() || EC_GROUP_get_curve_GFp(group, 0 as *mut BIGNUM, a, b, ctx) == 0)
    {
        if !(BN_mod_sqr(tmp2, x, field, ctx) == 0
            || BN_mod_mul(tmp1, tmp2, x, field, ctx) == 0)
        {
            if (*group).a_is_minus3 != 0 {
                if bn_mod_lshift1_consttime(tmp2, x, field, ctx) == 0
                    || bn_mod_add_consttime(tmp2, tmp2, x, field, ctx) == 0
                    || bn_mod_sub_consttime(tmp1, tmp1, tmp2, field, ctx) == 0
                {
                    current_block = 17677712226570019540;
                } else {
                    current_block = 11042950489265723346;
                }
            } else if BN_mod_mul(tmp2, a, x, field, ctx) == 0
                || bn_mod_add_consttime(tmp1, tmp1, tmp2, field, ctx) == 0
            {
                current_block = 17677712226570019540;
            } else {
                current_block = 11042950489265723346;
            }
            match current_block {
                17677712226570019540 => {}
                _ => {
                    if !(bn_mod_add_consttime(tmp1, tmp1, b, field, ctx) == 0) {
                        if (BN_mod_sqrt(y, tmp1, field, ctx)).is_null() {
                            let mut err: uint32_t = ERR_peek_last_error();
                            if ERR_GET_LIB(err) == 3 as libc::c_int
                                && ERR_GET_REASON(err) == 110 as libc::c_int
                            {
                                ERR_clear_error();
                                ERR_put_error(
                                    15 as libc::c_int,
                                    0 as libc::c_int,
                                    107 as libc::c_int,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/oct.c\0"
                                        as *const u8 as *const libc::c_char,
                                    375 as libc::c_int as libc::c_uint,
                                );
                            } else {
                                ERR_put_error(
                                    15 as libc::c_int,
                                    0 as libc::c_int,
                                    3 as libc::c_int,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/oct.c\0"
                                        as *const u8 as *const libc::c_char,
                                    377 as libc::c_int as libc::c_uint,
                                );
                            }
                        } else {
                            if y_bit != BN_is_odd(y) {
                                if BN_is_zero(y) != 0 {
                                    ERR_put_error(
                                        15 as libc::c_int,
                                        0 as libc::c_int,
                                        108 as libc::c_int,
                                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/oct.c\0"
                                            as *const u8 as *const libc::c_char,
                                        384 as libc::c_int as libc::c_uint,
                                    );
                                    current_block = 17677712226570019540;
                                } else if BN_usub(y, field, y) == 0 {
                                    current_block = 17677712226570019540;
                                } else {
                                    current_block = 9520865839495247062;
                                }
                            } else {
                                current_block = 9520865839495247062;
                            }
                            match current_block {
                                17677712226570019540 => {}
                                _ => {
                                    if y_bit != BN_is_odd(y) {
                                        ERR_put_error(
                                            15 as libc::c_int,
                                            0 as libc::c_int,
                                            4 as libc::c_int | 64 as libc::c_int,
                                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/oct.c\0"
                                                as *const u8 as *const libc::c_char,
                                            392 as libc::c_int as libc::c_uint,
                                        );
                                    } else if !(EC_POINT_set_affine_coordinates_GFp(
                                        group,
                                        point,
                                        x,
                                        y,
                                        ctx,
                                    ) == 0)
                                    {
                                        ret = 1 as libc::c_int;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}
