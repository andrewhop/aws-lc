#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(label_break_value)]
extern "C" {
    fn ec_felem_one(group: *const EC_GROUP) -> *const EC_FELEM;
    fn ec_felem_neg(group: *const EC_GROUP, out: *mut EC_FELEM, a: *const EC_FELEM);
    fn ec_felem_select(
        group: *const EC_GROUP,
        out: *mut EC_FELEM,
        mask: BN_ULONG,
        a: *const EC_FELEM,
        b: *const EC_FELEM,
    );
    fn ec_jacobian_to_affine_batch(
        group: *const EC_GROUP,
        out: *mut EC_AFFINE,
        in_0: *const EC_JACOBIAN,
        num: size_t,
    ) -> libc::c_int;
    fn ec_point_select(
        group: *const EC_GROUP,
        out: *mut EC_JACOBIAN,
        mask: BN_ULONG,
        a: *const EC_JACOBIAN,
        b: *const EC_JACOBIAN,
    );
    fn ec_GFp_simple_point_copy(_: *mut EC_JACOBIAN, _: *const EC_JACOBIAN);
    fn ec_GFp_simple_point_set_to_infinity(_: *const EC_GROUP, _: *mut EC_JACOBIAN);
    fn ec_GFp_mont_add(
        _: *const EC_GROUP,
        r: *mut EC_JACOBIAN,
        a: *const EC_JACOBIAN,
        b: *const EC_JACOBIAN,
    );
    fn ec_GFp_mont_dbl(_: *const EC_GROUP, r: *mut EC_JACOBIAN, a: *const EC_JACOBIAN);
    fn ec_GFp_nistp_recode_scalar_bits(
        sign: *mut crypto_word_t,
        digit: *mut crypto_word_t,
        in_0: crypto_word_t,
    );
    fn EC_GROUP_order_bits(group: *const EC_GROUP) -> libc::c_int;
    fn EC_GROUP_get_degree(group: *const EC_GROUP) -> libc::c_uint;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn bn_is_bit_set_words(a: *const BN_ULONG, num: size_t, bit: size_t) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
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
pub type crypto_word_t = uint64_t;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_210_error_is_comb_sizes_did_not_match {
    #[bitfield(
        name = "static_assertion_at_line_210_error_is_comb_sizes_did_not_match",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_210_error_is_comb_sizes_did_not_match: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
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
pub unsafe extern "C" fn ec_GFp_mont_mul(
    mut group: *const EC_GROUP,
    mut r: *mut EC_JACOBIAN,
    mut p: *const EC_JACOBIAN,
    mut scalar: *const EC_SCALAR,
) {
    let mut precomp: [EC_JACOBIAN; 32] = [EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    }; 32];
    ec_GFp_simple_point_set_to_infinity(
        group,
        &mut *precomp.as_mut_ptr().offset(0 as libc::c_int as isize),
    );
    ec_GFp_simple_point_copy(
        &mut *precomp.as_mut_ptr().offset(1 as libc::c_int as isize),
        p,
    );
    let mut j: size_t = 2 as libc::c_int as size_t;
    while j
        < (::core::mem::size_of::<[EC_JACOBIAN; 32]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<EC_JACOBIAN>() as libc::c_ulong)
    {
        if j & 1 as libc::c_int as size_t != 0 {
            ec_GFp_mont_add(
                group,
                &mut *precomp.as_mut_ptr().offset(j as isize),
                &mut *precomp.as_mut_ptr().offset(1 as libc::c_int as isize),
                &mut *precomp
                    .as_mut_ptr()
                    .offset(j.wrapping_sub(1 as libc::c_int as size_t) as isize),
            );
        } else {
            ec_GFp_mont_dbl(
                group,
                &mut *precomp.as_mut_ptr().offset(j as isize),
                &mut *precomp
                    .as_mut_ptr()
                    .offset((j / 2 as libc::c_int as size_t) as isize),
            );
        }
        j = j.wrapping_add(1);
        j;
    }
    let mut bits: libc::c_uint = EC_GROUP_order_bits(group) as libc::c_uint;
    let mut r_is_at_infinity: libc::c_int = 1 as libc::c_int;
    let mut i: libc::c_uint = bits.wrapping_sub(1 as libc::c_int as libc::c_uint);
    while i < bits {
        if r_is_at_infinity == 0 {
            ec_GFp_mont_dbl(group, r, r);
        }
        if i.wrapping_rem(5 as libc::c_int as libc::c_uint)
            == 0 as libc::c_int as libc::c_uint
        {
            let width: size_t = (*group).order.N.width as size_t;
            let mut window: uint8_t = (bn_is_bit_set_words(
                ((*scalar).words).as_ptr(),
                width,
                i.wrapping_add(4 as libc::c_int as libc::c_uint) as size_t,
            ) << 4 as libc::c_int) as uint8_t;
            window = (window as libc::c_int
                | bn_is_bit_set_words(
                    ((*scalar).words).as_ptr(),
                    width,
                    i.wrapping_add(3 as libc::c_int as libc::c_uint) as size_t,
                ) << 3 as libc::c_int) as uint8_t;
            window = (window as libc::c_int
                | bn_is_bit_set_words(
                    ((*scalar).words).as_ptr(),
                    width,
                    i.wrapping_add(2 as libc::c_int as libc::c_uint) as size_t,
                ) << 2 as libc::c_int) as uint8_t;
            window = (window as libc::c_int
                | bn_is_bit_set_words(
                    ((*scalar).words).as_ptr(),
                    width,
                    i.wrapping_add(1 as libc::c_int as libc::c_uint) as size_t,
                ) << 1 as libc::c_int) as uint8_t;
            window = (window as libc::c_int
                | bn_is_bit_set_words(((*scalar).words).as_ptr(), width, i as size_t))
                as uint8_t;
            let mut tmp: EC_JACOBIAN = EC_JACOBIAN {
                X: EC_FELEM { words: [0; 9] },
                Y: EC_FELEM { words: [0; 9] },
                Z: EC_FELEM { words: [0; 9] },
            };
            OPENSSL_memset(
                &mut tmp as *mut EC_JACOBIAN as *mut libc::c_void,
                0 as libc::c_int,
                ::core::mem::size_of::<EC_JACOBIAN>() as libc::c_ulong,
            );
            let mut j_0: size_t = 0 as libc::c_int as size_t;
            while j_0
                < (::core::mem::size_of::<[EC_JACOBIAN; 32]>() as libc::c_ulong)
                    .wrapping_div(::core::mem::size_of::<EC_JACOBIAN>() as libc::c_ulong)
            {
                let mut mask: BN_ULONG = constant_time_eq_w(
                    j_0,
                    window as crypto_word_t,
                );
                ec_point_select(
                    group,
                    &mut tmp,
                    mask,
                    &mut *precomp.as_mut_ptr().offset(j_0 as isize),
                    &mut tmp,
                );
                j_0 = j_0.wrapping_add(1);
                j_0;
            }
            if r_is_at_infinity != 0 {
                ec_GFp_simple_point_copy(r, &mut tmp);
                r_is_at_infinity = 0 as libc::c_int;
            } else {
                ec_GFp_mont_add(group, r, r, &mut tmp);
            }
        }
        i = i.wrapping_sub(1);
        i;
    }
    if r_is_at_infinity != 0 {
        ec_GFp_simple_point_set_to_infinity(group, r);
    }
}
#[no_mangle]
pub unsafe extern "C" fn ec_GFp_mont_mul_base(
    mut group: *const EC_GROUP,
    mut r: *mut EC_JACOBIAN,
    mut scalar: *const EC_SCALAR,
) {
    ec_GFp_mont_mul(group, r, &(*group).generator.raw, scalar);
}
unsafe extern "C" fn ec_GFp_mont_batch_precomp(
    mut group: *const EC_GROUP,
    mut out: *mut EC_JACOBIAN,
    mut num: size_t,
    mut p: *const EC_JACOBIAN,
) {
    if num > 1 as libc::c_int as size_t {} else {
        __assert_fail(
            b"num > 1\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/simple_mul.c\0"
                as *const u8 as *const libc::c_char,
            86 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 93],
                &[libc::c_char; 93],
            >(
                b"void ec_GFp_mont_batch_precomp(const EC_GROUP *, EC_JACOBIAN *, size_t, const EC_JACOBIAN *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_9598: {
        if num > 1 as libc::c_int as size_t {} else {
            __assert_fail(
                b"num > 1\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/simple_mul.c\0"
                    as *const u8 as *const libc::c_char,
                86 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 93],
                    &[libc::c_char; 93],
                >(
                    b"void ec_GFp_mont_batch_precomp(const EC_GROUP *, EC_JACOBIAN *, size_t, const EC_JACOBIAN *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    ec_GFp_simple_point_set_to_infinity(
        group,
        &mut *out.offset(0 as libc::c_int as isize),
    );
    ec_GFp_simple_point_copy(&mut *out.offset(1 as libc::c_int as isize), p);
    let mut j: size_t = 2 as libc::c_int as size_t;
    while j < num {
        if j & 1 as libc::c_int as size_t != 0 {
            ec_GFp_mont_add(
                group,
                &mut *out.offset(j as isize),
                &mut *out.offset(1 as libc::c_int as isize),
                &mut *out.offset(j.wrapping_sub(1 as libc::c_int as size_t) as isize),
            );
        } else {
            ec_GFp_mont_dbl(
                group,
                &mut *out.offset(j as isize),
                &mut *out.offset((j / 2 as libc::c_int as size_t) as isize),
            );
        }
        j = j.wrapping_add(1);
        j;
    }
}
unsafe extern "C" fn ec_GFp_mont_batch_get_window(
    mut group: *const EC_GROUP,
    mut out: *mut EC_JACOBIAN,
    mut precomp: *const EC_JACOBIAN,
    mut scalar: *const EC_SCALAR,
    mut i: libc::c_uint,
) {
    let width: size_t = (*group).order.N.width as size_t;
    let mut window: uint8_t = (bn_is_bit_set_words(
        ((*scalar).words).as_ptr(),
        width,
        i.wrapping_add(4 as libc::c_int as libc::c_uint) as size_t,
    ) << 5 as libc::c_int) as uint8_t;
    window = (window as libc::c_int
        | bn_is_bit_set_words(
            ((*scalar).words).as_ptr(),
            width,
            i.wrapping_add(3 as libc::c_int as libc::c_uint) as size_t,
        ) << 4 as libc::c_int) as uint8_t;
    window = (window as libc::c_int
        | bn_is_bit_set_words(
            ((*scalar).words).as_ptr(),
            width,
            i.wrapping_add(2 as libc::c_int as libc::c_uint) as size_t,
        ) << 3 as libc::c_int) as uint8_t;
    window = (window as libc::c_int
        | bn_is_bit_set_words(
            ((*scalar).words).as_ptr(),
            width,
            i.wrapping_add(1 as libc::c_int as libc::c_uint) as size_t,
        ) << 2 as libc::c_int) as uint8_t;
    window = (window as libc::c_int
        | bn_is_bit_set_words(((*scalar).words).as_ptr(), width, i as size_t)
            << 1 as libc::c_int) as uint8_t;
    if i > 0 as libc::c_int as libc::c_uint {
        window = (window as libc::c_int
            | bn_is_bit_set_words(
                ((*scalar).words).as_ptr(),
                width,
                i.wrapping_sub(1 as libc::c_int as libc::c_uint) as size_t,
            )) as uint8_t;
    }
    let mut sign: crypto_word_t = 0;
    let mut digit: crypto_word_t = 0;
    ec_GFp_nistp_recode_scalar_bits(&mut sign, &mut digit, window as crypto_word_t);
    OPENSSL_memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EC_JACOBIAN>() as libc::c_ulong,
    );
    let mut j: size_t = 0 as libc::c_int as size_t;
    while j < 17 as libc::c_int as size_t {
        let mut mask: BN_ULONG = constant_time_eq_w(j, digit);
        ec_point_select(group, out, mask, &*precomp.offset(j as isize), out);
        j = j.wrapping_add(1);
        j;
    }
    let mut neg_Y: EC_FELEM = EC_FELEM { words: [0; 9] };
    OPENSSL_memset(
        &mut neg_Y as *mut EC_FELEM as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EC_FELEM>() as libc::c_ulong,
    );
    ec_felem_neg(group, &mut neg_Y, &mut (*out).Y);
    let mut sign_mask: crypto_word_t = sign;
    sign_mask = (0 as libc::c_uint as crypto_word_t).wrapping_sub(sign_mask);
    ec_felem_select(group, &mut (*out).Y, sign_mask, &mut neg_Y, &mut (*out).Y);
}
#[no_mangle]
pub unsafe extern "C" fn ec_GFp_mont_mul_batch(
    mut group: *const EC_GROUP,
    mut r: *mut EC_JACOBIAN,
    mut p0: *const EC_JACOBIAN,
    mut scalar0: *const EC_SCALAR,
    mut p1: *const EC_JACOBIAN,
    mut scalar1: *const EC_SCALAR,
    mut p2: *const EC_JACOBIAN,
    mut scalar2: *const EC_SCALAR,
) {
    let mut precomp: [[EC_JACOBIAN; 17]; 3] = [[EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    }; 17]; 3];
    ec_GFp_mont_batch_precomp(
        group,
        (precomp[0 as libc::c_int as usize]).as_mut_ptr(),
        17 as libc::c_int as size_t,
        p0,
    );
    ec_GFp_mont_batch_precomp(
        group,
        (precomp[1 as libc::c_int as usize]).as_mut_ptr(),
        17 as libc::c_int as size_t,
        p1,
    );
    if !p2.is_null() {
        ec_GFp_mont_batch_precomp(
            group,
            (precomp[2 as libc::c_int as usize]).as_mut_ptr(),
            17 as libc::c_int as size_t,
            p2,
        );
    }
    let mut bits: libc::c_uint = EC_GROUP_order_bits(group) as libc::c_uint;
    let mut r_is_at_infinity: libc::c_int = 1 as libc::c_int;
    let mut i: libc::c_uint = bits;
    while i <= bits {
        if r_is_at_infinity == 0 {
            ec_GFp_mont_dbl(group, r, r);
        }
        if i.wrapping_rem(5 as libc::c_int as libc::c_uint)
            == 0 as libc::c_int as libc::c_uint
        {
            let mut tmp: EC_JACOBIAN = EC_JACOBIAN {
                X: EC_FELEM { words: [0; 9] },
                Y: EC_FELEM { words: [0; 9] },
                Z: EC_FELEM { words: [0; 9] },
            };
            ec_GFp_mont_batch_get_window(
                group,
                &mut tmp,
                (precomp[0 as libc::c_int as usize]).as_mut_ptr() as *const EC_JACOBIAN,
                scalar0,
                i,
            );
            if r_is_at_infinity != 0 {
                ec_GFp_simple_point_copy(r, &mut tmp);
                r_is_at_infinity = 0 as libc::c_int;
            } else {
                ec_GFp_mont_add(group, r, r, &mut tmp);
            }
            ec_GFp_mont_batch_get_window(
                group,
                &mut tmp,
                (precomp[1 as libc::c_int as usize]).as_mut_ptr() as *const EC_JACOBIAN,
                scalar1,
                i,
            );
            ec_GFp_mont_add(group, r, r, &mut tmp);
            if !p2.is_null() {
                ec_GFp_mont_batch_get_window(
                    group,
                    &mut tmp,
                    (precomp[2 as libc::c_int as usize]).as_mut_ptr()
                        as *const EC_JACOBIAN,
                    scalar2,
                    i,
                );
                ec_GFp_mont_add(group, r, r, &mut tmp);
            }
        }
        i = i.wrapping_sub(1);
        i;
    }
    if r_is_at_infinity != 0 {
        ec_GFp_simple_point_set_to_infinity(group, r);
    }
}
unsafe extern "C" fn ec_GFp_mont_comb_stride(
    mut group: *const EC_GROUP,
) -> libc::c_uint {
    return (EC_GROUP_get_degree(group))
        .wrapping_add(5 as libc::c_int as libc::c_uint)
        .wrapping_sub(1 as libc::c_int as libc::c_uint)
        .wrapping_div(5 as libc::c_int as libc::c_uint);
}
#[no_mangle]
pub unsafe extern "C" fn ec_GFp_mont_init_precomp(
    mut group: *const EC_GROUP,
    mut out: *mut EC_PRECOMP,
    mut p: *const EC_JACOBIAN,
) -> libc::c_int {
    let mut comb: [EC_JACOBIAN; 31] = [EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    }; 31];
    let mut stride: libc::c_uint = ec_GFp_mont_comb_stride(group);
    comb[(((1 as libc::c_int) << 0 as libc::c_int) - 1 as libc::c_int) as usize] = *p;
    let mut i: libc::c_uint = 1 as libc::c_int as libc::c_uint;
    while i < 5 as libc::c_int as libc::c_uint {
        let mut bit: libc::c_uint = ((1 as libc::c_int) << i) as libc::c_uint;
        ec_GFp_mont_dbl(
            group,
            &mut *comb
                .as_mut_ptr()
                .offset(bit.wrapping_sub(1 as libc::c_int as libc::c_uint) as isize),
            &mut *comb
                .as_mut_ptr()
                .offset(
                    bit
                        .wrapping_div(2 as libc::c_int as libc::c_uint)
                        .wrapping_sub(1 as libc::c_int as libc::c_uint) as isize,
                ),
        );
        let mut j: libc::c_uint = 1 as libc::c_int as libc::c_uint;
        while j < stride {
            ec_GFp_mont_dbl(
                group,
                &mut *comb
                    .as_mut_ptr()
                    .offset(bit.wrapping_sub(1 as libc::c_int as libc::c_uint) as isize),
                &mut *comb
                    .as_mut_ptr()
                    .offset(bit.wrapping_sub(1 as libc::c_int as libc::c_uint) as isize),
            );
            j = j.wrapping_add(1);
            j;
        }
        let mut j_0: libc::c_uint = 1 as libc::c_int as libc::c_uint;
        while j_0 < bit {
            ec_GFp_mont_add(
                group,
                &mut *comb
                    .as_mut_ptr()
                    .offset(
                        bit
                            .wrapping_add(j_0)
                            .wrapping_sub(1 as libc::c_int as libc::c_uint) as isize,
                    ),
                &mut *comb
                    .as_mut_ptr()
                    .offset(bit.wrapping_sub(1 as libc::c_int as libc::c_uint) as isize),
                &mut *comb
                    .as_mut_ptr()
                    .offset(j_0.wrapping_sub(1 as libc::c_int as libc::c_uint) as isize),
            );
            j_0 = j_0.wrapping_add(1);
            j_0;
        }
        i = i.wrapping_add(1);
        i;
    }
    return ec_jacobian_to_affine_batch(
        group,
        ((*out).comb).as_mut_ptr(),
        comb.as_mut_ptr(),
        (::core::mem::size_of::<[EC_JACOBIAN; 31]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<EC_JACOBIAN>() as libc::c_ulong),
    );
}
unsafe extern "C" fn ec_GFp_mont_get_comb_window(
    mut group: *const EC_GROUP,
    mut out: *mut EC_JACOBIAN,
    mut precomp: *const EC_PRECOMP,
    mut scalar: *const EC_SCALAR,
    mut i: libc::c_uint,
) {
    let width: size_t = (*group).order.N.width as size_t;
    let mut stride: libc::c_uint = ec_GFp_mont_comb_stride(group);
    let mut window: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut j: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while j < 5 as libc::c_int as libc::c_uint {
        window
            |= (bn_is_bit_set_words(
                ((*scalar).words).as_ptr(),
                width,
                j.wrapping_mul(stride).wrapping_add(i) as size_t,
            ) << j) as libc::c_uint;
        j = j.wrapping_add(1);
        j;
    }
    OPENSSL_memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EC_JACOBIAN>() as libc::c_ulong,
    );
    let mut j_0: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while (j_0 as libc::c_ulong)
        < (::core::mem::size_of::<[EC_AFFINE; 31]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<EC_AFFINE>() as libc::c_ulong)
    {
        let mut match_0: BN_ULONG = constant_time_eq_w(
            window as crypto_word_t,
            j_0.wrapping_add(1 as libc::c_int as libc::c_uint) as crypto_word_t,
        );
        ec_felem_select(
            group,
            &mut (*out).X,
            match_0,
            &(*((*precomp).comb).as_ptr().offset(j_0 as isize)).X,
            &mut (*out).X,
        );
        ec_felem_select(
            group,
            &mut (*out).Y,
            match_0,
            &(*((*precomp).comb).as_ptr().offset(j_0 as isize)).Y,
            &mut (*out).Y,
        );
        j_0 = j_0.wrapping_add(1);
        j_0;
    }
    let mut is_infinity: BN_ULONG = constant_time_is_zero_w(window as crypto_word_t);
    ec_felem_select(
        group,
        &mut (*out).Z,
        is_infinity,
        &mut (*out).Z,
        ec_felem_one(group),
    );
}
#[no_mangle]
pub unsafe extern "C" fn ec_GFp_mont_mul_precomp(
    mut group: *const EC_GROUP,
    mut r: *mut EC_JACOBIAN,
    mut p0: *const EC_PRECOMP,
    mut scalar0: *const EC_SCALAR,
    mut p1: *const EC_PRECOMP,
    mut scalar1: *const EC_SCALAR,
    mut p2: *const EC_PRECOMP,
    mut scalar2: *const EC_SCALAR,
) {
    let mut stride: libc::c_uint = ec_GFp_mont_comb_stride(group);
    let mut r_is_at_infinity: libc::c_int = 1 as libc::c_int;
    let mut i: libc::c_uint = stride.wrapping_sub(1 as libc::c_int as libc::c_uint);
    while i < stride {
        if r_is_at_infinity == 0 {
            ec_GFp_mont_dbl(group, r, r);
        }
        let mut tmp: EC_JACOBIAN = EC_JACOBIAN {
            X: EC_FELEM { words: [0; 9] },
            Y: EC_FELEM { words: [0; 9] },
            Z: EC_FELEM { words: [0; 9] },
        };
        ec_GFp_mont_get_comb_window(group, &mut tmp, p0, scalar0, i);
        if r_is_at_infinity != 0 {
            ec_GFp_simple_point_copy(r, &mut tmp);
            r_is_at_infinity = 0 as libc::c_int;
        } else {
            ec_GFp_mont_add(group, r, r, &mut tmp);
        }
        if !p1.is_null() {
            ec_GFp_mont_get_comb_window(group, &mut tmp, p1, scalar1, i);
            ec_GFp_mont_add(group, r, r, &mut tmp);
        }
        if !p2.is_null() {
            ec_GFp_mont_get_comb_window(group, &mut tmp, p2, scalar2, i);
            ec_GFp_mont_add(group, r, r, &mut tmp);
        }
        i = i.wrapping_sub(1);
        i;
    }
    if r_is_at_infinity != 0 {
        ec_GFp_simple_point_set_to_infinity(group, r);
    }
}
