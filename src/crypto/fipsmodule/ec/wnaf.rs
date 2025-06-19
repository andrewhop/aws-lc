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
    fn ec_GFp_simple_point_copy(_: *mut EC_JACOBIAN, _: *const EC_JACOBIAN);
    fn ec_GFp_simple_point_set_to_infinity(_: *const EC_GROUP, _: *mut EC_JACOBIAN);
    fn ec_GFp_mont_add(
        _: *const EC_GROUP,
        r: *mut EC_JACOBIAN,
        a: *const EC_JACOBIAN,
        b: *const EC_JACOBIAN,
    );
    fn ec_GFp_mont_dbl(_: *const EC_GROUP, r: *mut EC_JACOBIAN, a: *const EC_JACOBIAN);
    fn ec_GFp_simple_invert(_: *const EC_GROUP, _: *mut EC_JACOBIAN);
    fn EC_GROUP_order_bits(group: *const EC_GROUP) -> libc::c_int;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn OPENSSL_calloc(num: size_t, size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn bn_is_bit_set_words(a: *const BN_ULONG, num: size_t, bit: size_t) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __int8_t = libc::c_schar;
pub type __uint8_t = libc::c_uchar;
pub type __uint64_t = libc::c_ulong;
pub type int8_t = __int8_t;
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
#[no_mangle]
pub unsafe extern "C" fn ec_compute_wNAF(
    mut out: *mut int8_t,
    mut scalar: *const EC_SCALAR,
    mut bits: size_t,
    mut w: libc::c_int,
) {
    if (0 as libc::c_int) < w && w <= 7 as libc::c_int {} else {
        __assert_fail(
            b"0 < w && w <= 7\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/wnaf.c\0"
                as *const u8 as *const libc::c_char,
            90 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 63],
                &[libc::c_char; 63],
            >(b"void ec_compute_wNAF(int8_t *, const EC_SCALAR *, size_t, int)\0"))
                .as_ptr(),
        );
    }
    'c_9179: {
        if (0 as libc::c_int) < w && w <= 7 as libc::c_int {} else {
            __assert_fail(
                b"0 < w && w <= 7\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/wnaf.c\0"
                    as *const u8 as *const libc::c_char,
                90 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 63],
                    &[libc::c_char; 63],
                >(b"void ec_compute_wNAF(int8_t *, const EC_SCALAR *, size_t, int)\0"))
                    .as_ptr(),
            );
        }
    };
    if bits != 0 as libc::c_int as size_t {} else {
        __assert_fail(
            b"bits != 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/wnaf.c\0"
                as *const u8 as *const libc::c_char,
            91 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 63],
                &[libc::c_char; 63],
            >(b"void ec_compute_wNAF(int8_t *, const EC_SCALAR *, size_t, int)\0"))
                .as_ptr(),
        );
    }
    'c_9141: {
        if bits != 0 as libc::c_int as size_t {} else {
            __assert_fail(
                b"bits != 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/wnaf.c\0"
                    as *const u8 as *const libc::c_char,
                91 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 63],
                    &[libc::c_char; 63],
                >(b"void ec_compute_wNAF(int8_t *, const EC_SCALAR *, size_t, int)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut bit: libc::c_int = (1 as libc::c_int) << w;
    let mut next_bit: libc::c_int = bit << 1 as libc::c_int;
    let mut mask: libc::c_int = next_bit - 1 as libc::c_int;
    let mut window_val: libc::c_int = ((*scalar).words[0 as libc::c_int as usize]
        & mask as BN_ULONG) as libc::c_int;
    let mut j: size_t = 0 as libc::c_int as size_t;
    while j < bits.wrapping_add(1 as libc::c_int as size_t) {
        if 0 as libc::c_int <= window_val && window_val <= next_bit {} else {
            __assert_fail(
                b"0 <= window_val && window_val <= next_bit\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/wnaf.c\0"
                    as *const u8 as *const libc::c_char,
                98 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 63],
                    &[libc::c_char; 63],
                >(b"void ec_compute_wNAF(int8_t *, const EC_SCALAR *, size_t, int)\0"))
                    .as_ptr(),
            );
        }
        'c_9085: {
            if 0 as libc::c_int <= window_val && window_val <= next_bit {} else {
                __assert_fail(
                    b"0 <= window_val && window_val <= next_bit\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/wnaf.c\0"
                        as *const u8 as *const libc::c_char,
                    98 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 63],
                        &[libc::c_char; 63],
                    >(
                        b"void ec_compute_wNAF(int8_t *, const EC_SCALAR *, size_t, int)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        let mut digit: libc::c_int = 0 as libc::c_int;
        if window_val & 1 as libc::c_int != 0 {
            if (0 as libc::c_int) < window_val && window_val < next_bit {} else {
                __assert_fail(
                    b"0 < window_val && window_val < next_bit\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/wnaf.c\0"
                        as *const u8 as *const libc::c_char,
                    101 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 63],
                        &[libc::c_char; 63],
                    >(
                        b"void ec_compute_wNAF(int8_t *, const EC_SCALAR *, size_t, int)\0",
                    ))
                        .as_ptr(),
                );
            }
            'c_9034: {
                if (0 as libc::c_int) < window_val && window_val < next_bit {} else {
                    __assert_fail(
                        b"0 < window_val && window_val < next_bit\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/wnaf.c\0"
                            as *const u8 as *const libc::c_char,
                        101 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 63],
                            &[libc::c_char; 63],
                        >(
                            b"void ec_compute_wNAF(int8_t *, const EC_SCALAR *, size_t, int)\0",
                        ))
                            .as_ptr(),
                    );
                }
            };
            if window_val & bit != 0 {
                digit = window_val - next_bit;
                if j.wrapping_add(w as size_t).wrapping_add(1 as libc::c_int as size_t)
                    >= bits
                {
                    digit = window_val & mask >> 1 as libc::c_int;
                }
            } else {
                digit = window_val;
            }
            window_val -= digit;
            if window_val == 0 as libc::c_int || window_val == next_bit
                || window_val == bit
            {} else {
                __assert_fail(
                    b"window_val == 0 || window_val == next_bit || window_val == bit\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/wnaf.c\0"
                        as *const u8 as *const libc::c_char,
                    127 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 63],
                        &[libc::c_char; 63],
                    >(
                        b"void ec_compute_wNAF(int8_t *, const EC_SCALAR *, size_t, int)\0",
                    ))
                        .as_ptr(),
                );
            }
            'c_8925: {
                if window_val == 0 as libc::c_int || window_val == next_bit
                    || window_val == bit
                {} else {
                    __assert_fail(
                        b"window_val == 0 || window_val == next_bit || window_val == bit\0"
                            as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/wnaf.c\0"
                            as *const u8 as *const libc::c_char,
                        127 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 63],
                            &[libc::c_char; 63],
                        >(
                            b"void ec_compute_wNAF(int8_t *, const EC_SCALAR *, size_t, int)\0",
                        ))
                            .as_ptr(),
                    );
                }
            };
            if -bit < digit && digit < bit {} else {
                __assert_fail(
                    b"-bit < digit && digit < bit\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/wnaf.c\0"
                        as *const u8 as *const libc::c_char,
                    128 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 63],
                        &[libc::c_char; 63],
                    >(
                        b"void ec_compute_wNAF(int8_t *, const EC_SCALAR *, size_t, int)\0",
                    ))
                        .as_ptr(),
                );
            }
            'c_8872: {
                if -bit < digit && digit < bit {} else {
                    __assert_fail(
                        b"-bit < digit && digit < bit\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/wnaf.c\0"
                            as *const u8 as *const libc::c_char,
                        128 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 63],
                            &[libc::c_char; 63],
                        >(
                            b"void ec_compute_wNAF(int8_t *, const EC_SCALAR *, size_t, int)\0",
                        ))
                            .as_ptr(),
                    );
                }
            };
            if digit & 1 as libc::c_int != 0 {} else {
                __assert_fail(
                    b"digit & 1\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/wnaf.c\0"
                        as *const u8 as *const libc::c_char,
                    131 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 63],
                        &[libc::c_char; 63],
                    >(
                        b"void ec_compute_wNAF(int8_t *, const EC_SCALAR *, size_t, int)\0",
                    ))
                        .as_ptr(),
                );
            }
            'c_8835: {
                if digit & 1 as libc::c_int != 0 {} else {
                    __assert_fail(
                        b"digit & 1\0" as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/wnaf.c\0"
                            as *const u8 as *const libc::c_char,
                        131 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 63],
                            &[libc::c_char; 63],
                        >(
                            b"void ec_compute_wNAF(int8_t *, const EC_SCALAR *, size_t, int)\0",
                        ))
                            .as_ptr(),
                    );
                }
            };
        }
        *out.offset(j as isize) = digit as int8_t;
        window_val >>= 1 as libc::c_int;
        let bits_per_word: size_t = (::core::mem::size_of::<BN_ULONG>() as libc::c_ulong)
            .wrapping_mul(8 as libc::c_int as libc::c_ulong);
        let num_words: size_t = bits
            .wrapping_add(bits_per_word)
            .wrapping_sub(1 as libc::c_int as size_t) / bits_per_word;
        window_val
            += bit
                * bn_is_bit_set_words(
                    ((*scalar).words).as_ptr(),
                    num_words,
                    j.wrapping_add(w as size_t).wrapping_add(1 as libc::c_int as size_t),
                );
        if window_val <= next_bit {} else {
            __assert_fail(
                b"window_val <= next_bit\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/wnaf.c\0"
                    as *const u8 as *const libc::c_char,
                143 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 63],
                    &[libc::c_char; 63],
                >(b"void ec_compute_wNAF(int8_t *, const EC_SCALAR *, size_t, int)\0"))
                    .as_ptr(),
            );
        }
        'c_8722: {
            if window_val <= next_bit {} else {
                __assert_fail(
                    b"window_val <= next_bit\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/wnaf.c\0"
                        as *const u8 as *const libc::c_char,
                    143 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 63],
                        &[libc::c_char; 63],
                    >(
                        b"void ec_compute_wNAF(int8_t *, const EC_SCALAR *, size_t, int)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        j = j.wrapping_add(1);
        j;
    }
    if window_val == 0 as libc::c_int {} else {
        __assert_fail(
            b"window_val == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/wnaf.c\0"
                as *const u8 as *const libc::c_char,
            147 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 63],
                &[libc::c_char; 63],
            >(b"void ec_compute_wNAF(int8_t *, const EC_SCALAR *, size_t, int)\0"))
                .as_ptr(),
        );
    }
    'c_8642: {
        if window_val == 0 as libc::c_int {} else {
            __assert_fail(
                b"window_val == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/wnaf.c\0"
                    as *const u8 as *const libc::c_char,
                147 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 63],
                    &[libc::c_char; 63],
                >(b"void ec_compute_wNAF(int8_t *, const EC_SCALAR *, size_t, int)\0"))
                    .as_ptr(),
            );
        }
    };
}
unsafe extern "C" fn compute_precomp(
    mut group: *const EC_GROUP,
    mut out: *mut EC_JACOBIAN,
    mut p: *const EC_JACOBIAN,
    mut len: size_t,
) {
    ec_GFp_simple_point_copy(&mut *out.offset(0 as libc::c_int as isize), p);
    let mut two_p: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    ec_GFp_mont_dbl(group, &mut two_p, p);
    let mut i: size_t = 1 as libc::c_int as size_t;
    while i < len {
        ec_GFp_mont_add(
            group,
            &mut *out.offset(i as isize),
            &mut *out.offset(i.wrapping_sub(1 as libc::c_int as size_t) as isize),
            &mut two_p,
        );
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn lookup_precomp(
    mut group: *const EC_GROUP,
    mut out: *mut EC_JACOBIAN,
    mut precomp: *const EC_JACOBIAN,
    mut digit: libc::c_int,
) {
    if digit < 0 as libc::c_int {
        digit = -digit;
        ec_GFp_simple_point_copy(
            out,
            &*precomp.offset((digit >> 1 as libc::c_int) as isize),
        );
        ec_GFp_simple_invert(group, out);
    } else {
        ec_GFp_simple_point_copy(
            out,
            &*precomp.offset((digit >> 1 as libc::c_int) as isize),
        );
    };
}
#[no_mangle]
pub unsafe extern "C" fn ec_GFp_mont_mul_public_batch(
    mut group: *const EC_GROUP,
    mut r: *mut EC_JACOBIAN,
    mut g_scalar: *const EC_SCALAR,
    mut points: *const EC_JACOBIAN,
    mut scalars: *const EC_SCALAR,
    mut num: size_t,
) -> libc::c_int {
    let mut g_wNAF: [int8_t; 529] = [0; 529];
    let mut g_precomp: [EC_JACOBIAN; 8] = [EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    }; 8];
    let mut g: *const EC_JACOBIAN = 0 as *const EC_JACOBIAN;
    let mut tmp: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    let mut r_is_at_infinity: libc::c_int = 0;
    let mut current_block: u64;
    let mut bits: size_t = EC_GROUP_order_bits(group) as size_t;
    let mut wNAF_len: size_t = bits.wrapping_add(1 as libc::c_int as size_t);
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut wNAF_stack: [[int8_t; 529]; 3] = [[0; 529]; 3];
    let mut wNAF_alloc: *mut [int8_t; 529] = 0 as *mut [int8_t; 529];
    let mut wNAF: *mut [int8_t; 529] = 0 as *mut [int8_t; 529];
    let mut precomp_stack: [[EC_JACOBIAN; 8]; 3] = [[EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    }; 8]; 3];
    let mut precomp_alloc: *mut [EC_JACOBIAN; 8] = 0 as *mut [EC_JACOBIAN; 8];
    let mut precomp: *mut [EC_JACOBIAN; 8] = 0 as *mut [EC_JACOBIAN; 8];
    if num <= 3 as libc::c_int as size_t {
        wNAF = wNAF_stack.as_mut_ptr();
        precomp = precomp_stack.as_mut_ptr();
        current_block = 11650488183268122163;
    } else {
        wNAF_alloc = OPENSSL_calloc(
            num,
            ::core::mem::size_of::<[int8_t; 529]>() as libc::c_ulong,
        ) as *mut [int8_t; 529];
        precomp_alloc = OPENSSL_calloc(
            num,
            ::core::mem::size_of::<[EC_JACOBIAN; 8]>() as libc::c_ulong,
        ) as *mut [EC_JACOBIAN; 8];
        if wNAF_alloc.is_null() || precomp_alloc.is_null() {
            current_block = 10145989829926723752;
        } else {
            wNAF = wNAF_alloc;
            precomp = precomp_alloc;
            current_block = 11650488183268122163;
        }
    }
    match current_block {
        11650488183268122163 => {
            g_wNAF = [0; 529];
            g_precomp = [EC_JACOBIAN {
                X: EC_FELEM { words: [0; 9] },
                Y: EC_FELEM { words: [0; 9] },
                Z: EC_FELEM { words: [0; 9] },
            }; 8];
            if wNAF_len
                <= (::core::mem::size_of::<[int8_t; 529]>() as libc::c_ulong)
                    .wrapping_div(::core::mem::size_of::<int8_t>() as libc::c_ulong)
            {} else {
                __assert_fail(
                    b"wNAF_len <= OPENSSL_ARRAY_SIZE(g_wNAF)\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/wnaf.c\0"
                        as *const u8 as *const libc::c_char,
                    211 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 133],
                        &[libc::c_char; 133],
                    >(
                        b"int ec_GFp_mont_mul_public_batch(const EC_GROUP *, EC_JACOBIAN *, const EC_SCALAR *, const EC_JACOBIAN *, const EC_SCALAR *, size_t)\0",
                    ))
                        .as_ptr(),
                );
            }
            'c_9840: {
                if wNAF_len
                    <= (::core::mem::size_of::<[int8_t; 529]>() as libc::c_ulong)
                        .wrapping_div(::core::mem::size_of::<int8_t>() as libc::c_ulong)
                {} else {
                    __assert_fail(
                        b"wNAF_len <= OPENSSL_ARRAY_SIZE(g_wNAF)\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/wnaf.c\0"
                            as *const u8 as *const libc::c_char,
                        211 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 133],
                            &[libc::c_char; 133],
                        >(
                            b"int ec_GFp_mont_mul_public_batch(const EC_GROUP *, EC_JACOBIAN *, const EC_SCALAR *, const EC_JACOBIAN *, const EC_SCALAR *, size_t)\0",
                        ))
                            .as_ptr(),
                    );
                }
            };
            g = &(*group).generator.raw;
            if !g_scalar.is_null() {
                ec_compute_wNAF(g_wNAF.as_mut_ptr(), g_scalar, bits, 4 as libc::c_int);
                compute_precomp(
                    group,
                    g_precomp.as_mut_ptr(),
                    g,
                    ((1 as libc::c_int) << 4 as libc::c_int - 1 as libc::c_int) as size_t,
                );
            }
            let mut i: size_t = 0 as libc::c_int as size_t;
            while i < num {
                if wNAF_len
                    <= (::core::mem::size_of::<[int8_t; 529]>() as libc::c_ulong)
                        .wrapping_div(::core::mem::size_of::<int8_t>() as libc::c_ulong)
                {} else {
                    __assert_fail(
                        b"wNAF_len <= OPENSSL_ARRAY_SIZE(wNAF[i])\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/wnaf.c\0"
                            as *const u8 as *const libc::c_char,
                        219 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 133],
                            &[libc::c_char; 133],
                        >(
                            b"int ec_GFp_mont_mul_public_batch(const EC_GROUP *, EC_JACOBIAN *, const EC_SCALAR *, const EC_JACOBIAN *, const EC_SCALAR *, size_t)\0",
                        ))
                            .as_ptr(),
                    );
                }
                'c_9717: {
                    if wNAF_len
                        <= (::core::mem::size_of::<[int8_t; 529]>() as libc::c_ulong)
                            .wrapping_div(
                                ::core::mem::size_of::<int8_t>() as libc::c_ulong,
                            )
                    {} else {
                        __assert_fail(
                            b"wNAF_len <= OPENSSL_ARRAY_SIZE(wNAF[i])\0" as *const u8
                                as *const libc::c_char,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/wnaf.c\0"
                                as *const u8 as *const libc::c_char,
                            219 as libc::c_int as libc::c_uint,
                            (*::core::mem::transmute::<
                                &[u8; 133],
                                &[libc::c_char; 133],
                            >(
                                b"int ec_GFp_mont_mul_public_batch(const EC_GROUP *, EC_JACOBIAN *, const EC_SCALAR *, const EC_JACOBIAN *, const EC_SCALAR *, size_t)\0",
                            ))
                                .as_ptr(),
                        );
                    }
                };
                ec_compute_wNAF(
                    (*wNAF.offset(i as isize)).as_mut_ptr(),
                    &*scalars.offset(i as isize),
                    bits,
                    4 as libc::c_int,
                );
                compute_precomp(
                    group,
                    (*precomp.offset(i as isize)).as_mut_ptr(),
                    &*points.offset(i as isize),
                    ((1 as libc::c_int) << 4 as libc::c_int - 1 as libc::c_int) as size_t,
                );
                i = i.wrapping_add(1);
                i;
            }
            tmp = EC_JACOBIAN {
                X: EC_FELEM { words: [0; 9] },
                Y: EC_FELEM { words: [0; 9] },
                Z: EC_FELEM { words: [0; 9] },
            };
            r_is_at_infinity = 1 as libc::c_int;
            let mut k: size_t = wNAF_len.wrapping_sub(1 as libc::c_int as size_t);
            while k < wNAF_len {
                if r_is_at_infinity == 0 {
                    ec_GFp_mont_dbl(group, r, r);
                }
                if !g_scalar.is_null()
                    && g_wNAF[k as usize] as libc::c_int != 0 as libc::c_int
                {
                    lookup_precomp(
                        group,
                        &mut tmp,
                        g_precomp.as_mut_ptr(),
                        g_wNAF[k as usize] as libc::c_int,
                    );
                    if r_is_at_infinity != 0 {
                        ec_GFp_simple_point_copy(r, &mut tmp);
                        r_is_at_infinity = 0 as libc::c_int;
                    } else {
                        ec_GFp_mont_add(group, r, r, &mut tmp);
                    }
                }
                let mut i_0: size_t = 0 as libc::c_int as size_t;
                while i_0 < num {
                    if (*wNAF.offset(i_0 as isize))[k as usize] as libc::c_int
                        != 0 as libc::c_int
                    {
                        lookup_precomp(
                            group,
                            &mut tmp,
                            (*precomp.offset(i_0 as isize)).as_mut_ptr(),
                            (*wNAF.offset(i_0 as isize))[k as usize] as libc::c_int,
                        );
                        if r_is_at_infinity != 0 {
                            ec_GFp_simple_point_copy(r, &mut tmp);
                            r_is_at_infinity = 0 as libc::c_int;
                        } else {
                            ec_GFp_mont_add(group, r, r, &mut tmp);
                        }
                    }
                    i_0 = i_0.wrapping_add(1);
                    i_0;
                }
                k = k.wrapping_sub(1);
                k;
            }
            if r_is_at_infinity != 0 {
                ec_GFp_simple_point_set_to_infinity(group, r);
            }
            ret = 1 as libc::c_int;
        }
        _ => {}
    }
    OPENSSL_free(wNAF_alloc as *mut libc::c_void);
    OPENSSL_free(precomp_alloc as *mut libc::c_void);
    return ret;
}
