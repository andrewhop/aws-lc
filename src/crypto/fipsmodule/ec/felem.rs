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
unsafe extern "C" {
    fn BN_num_bytes(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_is_negative(bn: *const BIGNUM) -> libc::c_int;
    fn BN_bin2bn(in_0: *const uint8_t, len: size_t, ret: *mut BIGNUM) -> *mut BIGNUM;
    fn BN_bn2bin_padded(
        out: *mut uint8_t,
        len: size_t,
        in_0: *const BIGNUM,
    ) -> libc::c_int;
    fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn CRYPTO_memcmp(
        a: *const libc::c_void,
        b: *const libc::c_void,
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
    fn bn_select_words(
        r: *mut BN_ULONG,
        mask: BN_ULONG,
        a: *const BN_ULONG,
        b: *const BN_ULONG,
        num: size_t,
    );
    fn bn_sub_words(
        rp: *mut BN_ULONG,
        ap: *const BN_ULONG,
        bp: *const BN_ULONG,
        num: size_t,
    ) -> BN_ULONG;
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_felem_one(mut group: *const EC_GROUP) -> *const EC_FELEM {
    return &(*group).generator.raw.Z;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_bignum_to_felem(
    mut group: *const EC_GROUP,
    mut out: *mut EC_FELEM,
    mut in_0: *const BIGNUM,
) -> libc::c_int {
    let mut bytes: [uint8_t; 66] = [0; 66];
    let mut len: size_t = BN_num_bytes(&(*group).field.N) as size_t;
    if ::core::mem::size_of::<[uint8_t; 66]>() as libc::c_ulong >= len {} else {
        __assert_fail(
            b"sizeof(bytes) >= len\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/felem.c\0"
                as *const u8 as *const libc::c_char,
            34 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 69],
                &[libc::c_char; 69],
            >(b"int ec_bignum_to_felem(const EC_GROUP *, EC_FELEM *, const BIGNUM *)\0"))
                .as_ptr(),
        );
    }
    'c_8495: {
        if ::core::mem::size_of::<[uint8_t; 66]>() as libc::c_ulong >= len {} else {
            __assert_fail(
                b"sizeof(bytes) >= len\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/felem.c\0"
                    as *const u8 as *const libc::c_char,
                34 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 69],
                    &[libc::c_char; 69],
                >(
                    b"int ec_bignum_to_felem(const EC_GROUP *, EC_FELEM *, const BIGNUM *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if BN_is_negative(in_0) != 0 || BN_cmp(in_0, &(*group).field.N) >= 0 as libc::c_int
        || BN_bn2bin_padded(bytes.as_mut_ptr(), len, in_0) == 0
    {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/felem.c\0"
                as *const u8 as *const libc::c_char,
            37 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ec_felem_from_bytes(group, out, bytes.as_mut_ptr(), len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_felem_to_bignum(
    mut group: *const EC_GROUP,
    mut out: *mut BIGNUM,
    mut in_0: *const EC_FELEM,
) -> libc::c_int {
    let mut bytes: [uint8_t; 66] = [0; 66];
    let mut len: size_t = 0;
    ec_felem_to_bytes(group, bytes.as_mut_ptr(), &mut len, in_0);
    return (BN_bin2bn(bytes.as_mut_ptr(), len, out)
        != 0 as *mut libc::c_void as *mut BIGNUM) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_felem_to_bytes(
    mut group: *const EC_GROUP,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
    mut in_0: *const EC_FELEM,
) {
    ((*(*group).meth).felem_to_bytes)
        .expect("non-null function pointer")(group, out, out_len, in_0);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_felem_from_bytes(
    mut group: *const EC_GROUP,
    mut out: *mut EC_FELEM,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    return ((*(*group).meth).felem_from_bytes)
        .expect("non-null function pointer")(group, out, in_0, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_felem_neg(
    mut group: *const EC_GROUP,
    mut out: *mut EC_FELEM,
    mut a: *const EC_FELEM,
) {
    let mut mask: BN_ULONG = ec_felem_non_zero_mask(group, a);
    let mut borrow: BN_ULONG = bn_sub_words(
        ((*out).words).as_mut_ptr(),
        (*group).field.N.d,
        ((*a).words).as_ptr(),
        (*group).field.N.width as size_t,
    );
    if borrow == 0 as libc::c_int as BN_ULONG {} else {
        __assert_fail(
            b"borrow == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/felem.c\0"
                as *const u8 as *const libc::c_char,
            66 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 66],
                &[libc::c_char; 66],
            >(b"void ec_felem_neg(const EC_GROUP *, EC_FELEM *, const EC_FELEM *)\0"))
                .as_ptr(),
        );
    }
    'c_8717: {
        if borrow == 0 as libc::c_int as BN_ULONG {} else {
            __assert_fail(
                b"borrow == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/felem.c\0"
                    as *const u8 as *const libc::c_char,
                66 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 66],
                    &[libc::c_char; 66],
                >(
                    b"void ec_felem_neg(const EC_GROUP *, EC_FELEM *, const EC_FELEM *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut i: libc::c_int = 0 as libc::c_int;
    while i < (*group).field.N.width {
        (*out).words[i as usize] &= mask;
        i += 1;
        i;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_felem_add(
    mut group: *const EC_GROUP,
    mut out: *mut EC_FELEM,
    mut a: *const EC_FELEM,
    mut b: *const EC_FELEM,
) {
    let mut tmp: EC_FELEM = EC_FELEM { words: [0; 9] };
    bn_mod_add_words(
        ((*out).words).as_mut_ptr(),
        ((*a).words).as_ptr(),
        ((*b).words).as_ptr(),
        (*group).field.N.d,
        (tmp.words).as_mut_ptr(),
        (*group).field.N.width as size_t,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_felem_sub(
    mut group: *const EC_GROUP,
    mut out: *mut EC_FELEM,
    mut a: *const EC_FELEM,
    mut b: *const EC_FELEM,
) {
    let mut tmp: EC_FELEM = EC_FELEM { words: [0; 9] };
    bn_mod_sub_words(
        ((*out).words).as_mut_ptr(),
        ((*a).words).as_ptr(),
        ((*b).words).as_ptr(),
        (*group).field.N.d,
        (tmp.words).as_mut_ptr(),
        (*group).field.N.width as size_t,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_felem_non_zero_mask(
    mut group: *const EC_GROUP,
    mut a: *const EC_FELEM,
) -> BN_ULONG {
    let mut mask: BN_ULONG = 0 as libc::c_int as BN_ULONG;
    let mut i: libc::c_int = 0 as libc::c_int;
    while i < (*group).field.N.width {
        mask |= (*a).words[i as usize];
        i += 1;
        i;
    }
    return !constant_time_is_zero_w(mask);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_felem_select(
    mut group: *const EC_GROUP,
    mut out: *mut EC_FELEM,
    mut mask: BN_ULONG,
    mut a: *const EC_FELEM,
    mut b: *const EC_FELEM,
) {
    bn_select_words(
        ((*out).words).as_mut_ptr(),
        mask,
        ((*a).words).as_ptr(),
        ((*b).words).as_ptr(),
        (*group).field.N.width as size_t,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_felem_equal(
    mut group: *const EC_GROUP,
    mut a: *const EC_FELEM,
    mut b: *const EC_FELEM,
) -> libc::c_int {
    return (CRYPTO_memcmp(
        ((*a).words).as_ptr() as *const libc::c_void,
        ((*b).words).as_ptr() as *const libc::c_void,
        ((*group).field.N.width as libc::c_ulong)
            .wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    ) == 0 as libc::c_int) as libc::c_int;
}
