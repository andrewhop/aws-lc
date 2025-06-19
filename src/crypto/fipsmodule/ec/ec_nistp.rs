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
unsafe extern "C" {
    fn ec_compute_wNAF(
        out: *mut int8_t,
        scalar: *const EC_SCALAR,
        bits: size_t,
        w: libc::c_int,
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
}
pub type __int8_t = libc::c_schar;
pub type __int16_t = libc::c_short;
pub type __uint64_t = libc::c_ulong;
pub type int8_t = __int8_t;
pub type int16_t = __int16_t;
pub type uint64_t = __uint64_t;
pub type size_t = libc::c_ulong;
pub type BN_ULONG = uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EC_SCALAR {
    pub words: [BN_ULONG; 9],
}
pub type crypto_word_t = uint64_t;
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
pub type ec_nistp_felem = [ec_nistp_felem_limb; 9];
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_267_error_is_bn_ulong_not_eight_bytes {
    #[bitfield(
        name = "static_assertion_at_line_267_error_is_bn_ulong_not_eight_bytes",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_267_error_is_bn_ulong_not_eight_bytes: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[inline]
unsafe extern "C" fn value_barrier_w(mut a: crypto_word_t) -> crypto_word_t {
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
unsafe extern "C" fn constant_time_select_w(
    mut mask: crypto_word_t,
    mut a: crypto_word_t,
    mut b: crypto_word_t,
) -> crypto_word_t {
    return value_barrier_w(mask) & a | value_barrier_w(!mask) & b;
}
#[inline]
unsafe extern "C" fn constant_time_select_array_w(
    mut c: *mut crypto_word_t,
    mut a: *mut crypto_word_t,
    mut b: *mut crypto_word_t,
    mut mask: crypto_word_t,
    mut len: size_t,
) {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < len {
        *c
            .offset(
                i as isize,
            ) = constant_time_select_w(
            mask,
            *a.offset(i as isize),
            *b.offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[inline]
unsafe extern "C" fn constant_time_select_entry_from_table_w(
    mut out: *mut crypto_word_t,
    mut table: *mut crypto_word_t,
    mut idx: size_t,
    mut num_entries: size_t,
    mut entry_size: size_t,
) {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < num_entries {
        let mut mask: crypto_word_t = constant_time_eq_w(i, idx);
        constant_time_select_array_w(
            out,
            &mut *table.offset((i * entry_size) as isize),
            out,
            mask,
            entry_size,
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[inline]
unsafe extern "C" fn constant_time_declassify_w(mut v: crypto_word_t) -> crypto_word_t {
    return value_barrier_w(v);
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
unsafe extern "C" fn cmovznz(
    mut out: *mut ec_nistp_felem_limb,
    mut num_limbs: size_t,
    mut t: ec_nistp_felem_limb,
    mut z: *const ec_nistp_felem_limb,
    mut nz: *const ec_nistp_felem_limb,
) {
    let mut mask: ec_nistp_felem_limb = constant_time_is_zero_w(t);
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < num_limbs {
        *out
            .offset(
                i as isize,
            ) = constant_time_select_w(
            mask,
            *z.offset(i as isize),
            *nz.offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_nistp_point_double(
    mut ctx: *const ec_nistp_meth,
    mut x_out: *mut ec_nistp_felem_limb,
    mut y_out: *mut ec_nistp_felem_limb,
    mut z_out: *mut ec_nistp_felem_limb,
    mut x_in: *const ec_nistp_felem_limb,
    mut y_in: *const ec_nistp_felem_limb,
    mut z_in: *const ec_nistp_felem_limb,
) {
    let mut delta: ec_nistp_felem = [0; 9];
    let mut gamma: ec_nistp_felem = [0; 9];
    let mut beta: ec_nistp_felem = [0; 9];
    let mut ftmp: ec_nistp_felem = [0; 9];
    let mut ftmp2: ec_nistp_felem = [0; 9];
    let mut tmptmp: ec_nistp_felem = [0; 9];
    let mut alpha: ec_nistp_felem = [0; 9];
    let mut fourbeta: ec_nistp_felem = [0; 9];
    ((*ctx).felem_sqr).expect("non-null function pointer")(delta.as_mut_ptr(), z_in);
    ((*ctx).felem_sqr).expect("non-null function pointer")(gamma.as_mut_ptr(), y_in);
    ((*ctx).felem_mul)
        .expect(
            "non-null function pointer",
        )(beta.as_mut_ptr(), x_in, gamma.as_mut_ptr());
    ((*ctx).felem_sub)
        .expect(
            "non-null function pointer",
        )(ftmp.as_mut_ptr(), x_in, delta.as_mut_ptr());
    ((*ctx).felem_add)
        .expect(
            "non-null function pointer",
        )(ftmp2.as_mut_ptr(), x_in, delta.as_mut_ptr());
    ((*ctx).felem_add)
        .expect(
            "non-null function pointer",
        )(tmptmp.as_mut_ptr(), ftmp2.as_mut_ptr(), ftmp2.as_mut_ptr());
    ((*ctx).felem_add)
        .expect(
            "non-null function pointer",
        )(ftmp2.as_mut_ptr(), ftmp2.as_mut_ptr(), tmptmp.as_mut_ptr());
    ((*ctx).felem_mul)
        .expect(
            "non-null function pointer",
        )(alpha.as_mut_ptr(), ftmp.as_mut_ptr(), ftmp2.as_mut_ptr());
    ((*ctx).felem_sqr).expect("non-null function pointer")(x_out, alpha.as_mut_ptr());
    ((*ctx).felem_add)
        .expect(
            "non-null function pointer",
        )(fourbeta.as_mut_ptr(), beta.as_mut_ptr(), beta.as_mut_ptr());
    ((*ctx).felem_add)
        .expect(
            "non-null function pointer",
        )(fourbeta.as_mut_ptr(), fourbeta.as_mut_ptr(), fourbeta.as_mut_ptr());
    ((*ctx).felem_add)
        .expect(
            "non-null function pointer",
        )(tmptmp.as_mut_ptr(), fourbeta.as_mut_ptr(), fourbeta.as_mut_ptr());
    ((*ctx).felem_sub)
        .expect("non-null function pointer")(x_out, x_out, tmptmp.as_mut_ptr());
    ((*ctx).felem_add)
        .expect("non-null function pointer")(ftmp.as_mut_ptr(), y_in, z_in);
    ((*ctx).felem_sqr).expect("non-null function pointer")(z_out, ftmp.as_mut_ptr());
    ((*ctx).felem_sub)
        .expect("non-null function pointer")(z_out, z_out, gamma.as_mut_ptr());
    ((*ctx).felem_sub)
        .expect("non-null function pointer")(z_out, z_out, delta.as_mut_ptr());
    ((*ctx).felem_sub)
        .expect("non-null function pointer")(y_out, fourbeta.as_mut_ptr(), x_out);
    ((*ctx).felem_add)
        .expect(
            "non-null function pointer",
        )(gamma.as_mut_ptr(), gamma.as_mut_ptr(), gamma.as_mut_ptr());
    ((*ctx).felem_sqr)
        .expect("non-null function pointer")(gamma.as_mut_ptr(), gamma.as_mut_ptr());
    ((*ctx).felem_mul)
        .expect("non-null function pointer")(y_out, alpha.as_mut_ptr(), y_out);
    ((*ctx).felem_add)
        .expect(
            "non-null function pointer",
        )(gamma.as_mut_ptr(), gamma.as_mut_ptr(), gamma.as_mut_ptr());
    ((*ctx).felem_sub)
        .expect("non-null function pointer")(y_out, y_out, gamma.as_mut_ptr());
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_nistp_point_add(
    mut ctx: *const ec_nistp_meth,
    mut x3: *mut ec_nistp_felem_limb,
    mut y3: *mut ec_nistp_felem_limb,
    mut z3: *mut ec_nistp_felem_limb,
    mut x1: *const ec_nistp_felem_limb,
    mut y1: *const ec_nistp_felem_limb,
    mut z1: *const ec_nistp_felem_limb,
    mixed: libc::c_int,
    mut x2: *const ec_nistp_felem_limb,
    mut y2: *const ec_nistp_felem_limb,
    mut z2: *const ec_nistp_felem_limb,
) {
    let mut x_out: ec_nistp_felem = [0; 9];
    let mut y_out: ec_nistp_felem = [0; 9];
    let mut z_out: ec_nistp_felem = [0; 9];
    let mut z1nz: ec_nistp_felem_limb = ((*ctx).felem_nz)
        .expect("non-null function pointer")(z1);
    let mut z2nz: ec_nistp_felem_limb = ((*ctx).felem_nz)
        .expect("non-null function pointer")(z2);
    let mut z1z1: ec_nistp_felem = [0; 9];
    ((*ctx).felem_sqr).expect("non-null function pointer")(z1z1.as_mut_ptr(), z1);
    let mut u1: ec_nistp_felem = [0; 9];
    let mut s1: ec_nistp_felem = [0; 9];
    let mut two_z1z2: ec_nistp_felem = [0; 9];
    if mixed == 0 {
        let mut z2z2: ec_nistp_felem = [0; 9];
        ((*ctx).felem_sqr).expect("non-null function pointer")(z2z2.as_mut_ptr(), z2);
        ((*ctx).felem_mul)
            .expect("non-null function pointer")(u1.as_mut_ptr(), x1, z2z2.as_mut_ptr());
        ((*ctx).felem_add)
            .expect("non-null function pointer")(two_z1z2.as_mut_ptr(), z1, z2);
        ((*ctx).felem_sqr)
            .expect(
                "non-null function pointer",
            )(two_z1z2.as_mut_ptr(), two_z1z2.as_mut_ptr());
        ((*ctx).felem_sub)
            .expect(
                "non-null function pointer",
            )(two_z1z2.as_mut_ptr(), two_z1z2.as_mut_ptr(), z1z1.as_mut_ptr());
        ((*ctx).felem_sub)
            .expect(
                "non-null function pointer",
            )(two_z1z2.as_mut_ptr(), two_z1z2.as_mut_ptr(), z2z2.as_mut_ptr());
        ((*ctx).felem_mul)
            .expect("non-null function pointer")(s1.as_mut_ptr(), z2, z2z2.as_mut_ptr());
        ((*ctx).felem_mul)
            .expect("non-null function pointer")(s1.as_mut_ptr(), s1.as_mut_ptr(), y1);
    } else {
        OPENSSL_memcpy(
            u1.as_mut_ptr() as *mut libc::c_void,
            x1 as *const libc::c_void,
            ((*ctx).felem_num_limbs)
                .wrapping_mul(
                    ::core::mem::size_of::<ec_nistp_felem_limb>() as libc::c_ulong,
                ),
        );
        ((*ctx).felem_add)
            .expect("non-null function pointer")(two_z1z2.as_mut_ptr(), z1, z1);
        OPENSSL_memcpy(
            s1.as_mut_ptr() as *mut libc::c_void,
            y1 as *const libc::c_void,
            ((*ctx).felem_num_limbs)
                .wrapping_mul(
                    ::core::mem::size_of::<ec_nistp_felem_limb>() as libc::c_ulong,
                ),
        );
    }
    let mut u2: ec_nistp_felem = [0; 9];
    ((*ctx).felem_mul)
        .expect("non-null function pointer")(u2.as_mut_ptr(), x2, z1z1.as_mut_ptr());
    let mut h: ec_nistp_felem = [0; 9];
    ((*ctx).felem_sub)
        .expect(
            "non-null function pointer",
        )(h.as_mut_ptr(), u2.as_mut_ptr(), u1.as_mut_ptr());
    let mut xneq: ec_nistp_felem_limb = ((*ctx).felem_nz)
        .expect("non-null function pointer")(h.as_mut_ptr());
    ((*ctx).felem_mul)
        .expect(
            "non-null function pointer",
        )(z_out.as_mut_ptr(), h.as_mut_ptr(), two_z1z2.as_mut_ptr());
    let mut z1z1z1: ec_nistp_felem = [0; 9];
    ((*ctx).felem_mul)
        .expect("non-null function pointer")(z1z1z1.as_mut_ptr(), z1, z1z1.as_mut_ptr());
    let mut s2: ec_nistp_felem = [0; 9];
    ((*ctx).felem_mul)
        .expect("non-null function pointer")(s2.as_mut_ptr(), y2, z1z1z1.as_mut_ptr());
    let mut r: ec_nistp_felem = [0; 9];
    ((*ctx).felem_sub)
        .expect(
            "non-null function pointer",
        )(r.as_mut_ptr(), s2.as_mut_ptr(), s1.as_mut_ptr());
    ((*ctx).felem_add)
        .expect(
            "non-null function pointer",
        )(r.as_mut_ptr(), r.as_mut_ptr(), r.as_mut_ptr());
    let mut yneq: ec_nistp_felem_limb = ((*ctx).felem_nz)
        .expect("non-null function pointer")(r.as_mut_ptr());
    let mut is_nontrivial_double: ec_nistp_felem_limb = constant_time_is_zero_w(
        xneq | yneq,
    ) & !constant_time_is_zero_w(z1nz) & !constant_time_is_zero_w(z2nz);
    if constant_time_declassify_w(is_nontrivial_double) != 0 {
        ec_nistp_point_double(ctx, x3, y3, z3, x1, y1, z1);
        return;
    }
    let mut i: ec_nistp_felem = [0; 9];
    ((*ctx).felem_add)
        .expect(
            "non-null function pointer",
        )(i.as_mut_ptr(), h.as_mut_ptr(), h.as_mut_ptr());
    ((*ctx).felem_sqr)
        .expect("non-null function pointer")(i.as_mut_ptr(), i.as_mut_ptr());
    let mut j: ec_nistp_felem = [0; 9];
    ((*ctx).felem_mul)
        .expect(
            "non-null function pointer",
        )(j.as_mut_ptr(), h.as_mut_ptr(), i.as_mut_ptr());
    let mut v: ec_nistp_felem = [0; 9];
    ((*ctx).felem_mul)
        .expect(
            "non-null function pointer",
        )(v.as_mut_ptr(), u1.as_mut_ptr(), i.as_mut_ptr());
    ((*ctx).felem_sqr)
        .expect("non-null function pointer")(x_out.as_mut_ptr(), r.as_mut_ptr());
    ((*ctx).felem_sub)
        .expect(
            "non-null function pointer",
        )(x_out.as_mut_ptr(), x_out.as_mut_ptr(), j.as_mut_ptr());
    ((*ctx).felem_sub)
        .expect(
            "non-null function pointer",
        )(x_out.as_mut_ptr(), x_out.as_mut_ptr(), v.as_mut_ptr());
    ((*ctx).felem_sub)
        .expect(
            "non-null function pointer",
        )(x_out.as_mut_ptr(), x_out.as_mut_ptr(), v.as_mut_ptr());
    ((*ctx).felem_sub)
        .expect(
            "non-null function pointer",
        )(y_out.as_mut_ptr(), v.as_mut_ptr(), x_out.as_mut_ptr());
    ((*ctx).felem_mul)
        .expect(
            "non-null function pointer",
        )(y_out.as_mut_ptr(), y_out.as_mut_ptr(), r.as_mut_ptr());
    let mut s1j: ec_nistp_felem = [0; 9];
    ((*ctx).felem_mul)
        .expect(
            "non-null function pointer",
        )(s1j.as_mut_ptr(), s1.as_mut_ptr(), j.as_mut_ptr());
    ((*ctx).felem_sub)
        .expect(
            "non-null function pointer",
        )(y_out.as_mut_ptr(), y_out.as_mut_ptr(), s1j.as_mut_ptr());
    ((*ctx).felem_sub)
        .expect(
            "non-null function pointer",
        )(y_out.as_mut_ptr(), y_out.as_mut_ptr(), s1j.as_mut_ptr());
    cmovznz(x_out.as_mut_ptr(), (*ctx).felem_num_limbs, z1nz, x2, x_out.as_mut_ptr());
    cmovznz(y_out.as_mut_ptr(), (*ctx).felem_num_limbs, z1nz, y2, y_out.as_mut_ptr());
    cmovznz(z_out.as_mut_ptr(), (*ctx).felem_num_limbs, z1nz, z2, z_out.as_mut_ptr());
    cmovznz(x3, (*ctx).felem_num_limbs, z2nz, x1, x_out.as_mut_ptr());
    cmovznz(y3, (*ctx).felem_num_limbs, z2nz, y1, y_out.as_mut_ptr());
    cmovznz(z3, (*ctx).felem_num_limbs, z2nz, z1, z_out.as_mut_ptr());
}
unsafe extern "C" fn get_bit(mut in_0: *const EC_SCALAR, mut i: size_t) -> int16_t {
    return ((*in_0).words[(i >> 6 as libc::c_int) as usize]
        >> (i & 63 as libc::c_int as size_t) & 1 as libc::c_int as BN_ULONG) as int16_t;
}
unsafe extern "C" fn scalar_rwnaf(
    mut out: *mut int16_t,
    mut window_size: size_t,
    mut scalar: *const EC_SCALAR,
    mut scalar_bit_size: size_t,
) {
    if window_size < 14 as libc::c_int as size_t {} else {
        __assert_fail(
            b"window_size < 14\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_nistp.c\0"
                as *const u8 as *const libc::c_char,
            285 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 64],
                &[libc::c_char; 64],
            >(b"void scalar_rwnaf(int16_t *, size_t, const EC_SCALAR *, size_t)\0"))
                .as_ptr(),
        );
    }
    'c_10574: {
        if window_size < 14 as libc::c_int as size_t {} else {
            __assert_fail(
                b"window_size < 14\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_nistp.c\0"
                    as *const u8 as *const libc::c_char,
                285 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 64],
                    &[libc::c_char; 64],
                >(b"void scalar_rwnaf(int16_t *, size_t, const EC_SCALAR *, size_t)\0"))
                    .as_ptr(),
            );
        }
    };
    let window_mask: int16_t = (((1 as libc::c_int)
        << window_size.wrapping_add(1 as libc::c_int as size_t)) - 1 as libc::c_int)
        as int16_t;
    let mut window: int16_t = ((*scalar).words[0 as libc::c_int as usize]
        & window_mask as BN_ULONG) as int16_t;
    window = (window as libc::c_int | 1 as libc::c_int) as int16_t;
    let num_windows: size_t = scalar_bit_size
        .wrapping_add(window_size)
        .wrapping_sub(1 as libc::c_int as size_t) / window_size;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < num_windows.wrapping_sub(1 as libc::c_int as size_t) {
        let mut d: int16_t = ((window as libc::c_int & window_mask as libc::c_int)
            - ((1 as libc::c_int) << window_size) as int16_t as libc::c_int) as int16_t;
        *out.offset(i as isize) = d;
        window = (window as libc::c_int - d as libc::c_int >> window_size) as int16_t;
        let mut j: size_t = 1 as libc::c_int as size_t;
        while j <= window_size {
            let mut idx: size_t = (i.wrapping_add(1 as libc::c_int as size_t)
                * window_size)
                .wrapping_add(j);
            if idx < scalar_bit_size {
                window = (window as libc::c_int
                    | (get_bit(scalar, idx) as libc::c_int) << j) as int16_t;
            }
            j = j.wrapping_add(1);
            j;
        }
        i = i.wrapping_add(1);
        i;
    }
    *out.offset(num_windows.wrapping_sub(1 as libc::c_int as size_t) as isize) = window;
}
unsafe extern "C" fn generate_table(
    mut ctx: *const ec_nistp_meth,
    mut table: *mut ec_nistp_felem_limb,
    mut x_in: *const ec_nistp_felem_limb,
    mut y_in: *const ec_nistp_felem_limb,
    mut z_in: *const ec_nistp_felem_limb,
) {
    let felem_num_limbs: size_t = (*ctx).felem_num_limbs;
    let felem_num_bytes: size_t = felem_num_limbs
        .wrapping_mul(::core::mem::size_of::<ec_nistp_felem_limb>() as libc::c_ulong);
    let x_idx: size_t = 0 as libc::c_int as size_t;
    let y_idx: size_t = felem_num_limbs;
    let z_idx: size_t = felem_num_limbs * 2 as libc::c_int as size_t;
    OPENSSL_memcpy(
        &mut *table.offset(x_idx as isize) as *mut ec_nistp_felem_limb
            as *mut libc::c_void,
        x_in as *const libc::c_void,
        felem_num_bytes,
    );
    OPENSSL_memcpy(
        &mut *table.offset(y_idx as isize) as *mut ec_nistp_felem_limb
            as *mut libc::c_void,
        y_in as *const libc::c_void,
        felem_num_bytes,
    );
    OPENSSL_memcpy(
        &mut *table.offset(z_idx as isize) as *mut ec_nistp_felem_limb
            as *mut libc::c_void,
        z_in as *const libc::c_void,
        felem_num_bytes,
    );
    let mut x_in_dbl: ec_nistp_felem = [0; 9];
    let mut y_in_dbl: ec_nistp_felem = [0; 9];
    let mut z_in_dbl: ec_nistp_felem = [0; 9];
    ((*ctx).point_dbl)
        .expect(
            "non-null function pointer",
        )(
        x_in_dbl.as_mut_ptr(),
        y_in_dbl.as_mut_ptr(),
        z_in_dbl.as_mut_ptr(),
        &mut *table.offset(x_idx as isize),
        &mut *table.offset(y_idx as isize),
        &mut *table.offset(z_idx as isize),
    );
    let mut i: size_t = 1 as libc::c_int as size_t;
    while i < ((1 as libc::c_int) << 5 as libc::c_int - 1 as libc::c_int) as size_t {
        let mut point_i: *mut ec_nistp_felem_limb = &mut *table
            .offset((i * 3 as libc::c_int as size_t * felem_num_limbs) as isize)
            as *mut ec_nistp_felem_limb;
        let mut point_im1: *mut ec_nistp_felem_limb = &mut *table
            .offset(
                (i.wrapping_sub(1 as libc::c_int as size_t) * 3 as libc::c_int as size_t
                    * felem_num_limbs) as isize,
            ) as *mut ec_nistp_felem_limb;
        ((*ctx).point_add)
            .expect(
                "non-null function pointer",
            )(
            &mut *point_i.offset(x_idx as isize),
            &mut *point_i.offset(y_idx as isize),
            &mut *point_i.offset(z_idx as isize),
            &mut *point_im1.offset(x_idx as isize),
            &mut *point_im1.offset(y_idx as isize),
            &mut *point_im1.offset(z_idx as isize),
            0 as libc::c_int,
            x_in_dbl.as_mut_ptr(),
            y_in_dbl.as_mut_ptr(),
            z_in_dbl.as_mut_ptr(),
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[inline]
unsafe extern "C" fn select_point_from_table(
    mut ctx: *const ec_nistp_meth,
    mut out: *mut ec_nistp_felem_limb,
    mut table: *const ec_nistp_felem_limb,
    idx: size_t,
    projective: size_t,
) {
    let mut point_num_coord: size_t = (2 as libc::c_int
        + (if projective != 0 as libc::c_int as size_t {
            1 as libc::c_int
        } else {
            0 as libc::c_int
        })) as size_t;
    let mut point_num_limbs: size_t = (*ctx).felem_num_limbs * point_num_coord;
    constant_time_select_entry_from_table_w(
        out,
        table as *mut crypto_word_t,
        idx,
        ((1 as libc::c_int) << 5 as libc::c_int - 1 as libc::c_int) as size_t,
        point_num_limbs,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_nistp_scalar_mul(
    mut ctx: *const ec_nistp_meth,
    mut x_out: *mut ec_nistp_felem_limb,
    mut y_out: *mut ec_nistp_felem_limb,
    mut z_out: *mut ec_nistp_felem_limb,
    mut x_in: *const ec_nistp_felem_limb,
    mut y_in: *const ec_nistp_felem_limb,
    mut z_in: *const ec_nistp_felem_limb,
    mut scalar: *const EC_SCALAR,
) {
    if (((1 as libc::c_int) << 5 as libc::c_int - 1 as libc::c_int) * 3 as libc::c_int
        * 9 as libc::c_int) as size_t
        >= ((1 as libc::c_int) << 5 as libc::c_int - 1 as libc::c_int) as size_t
            * (*ctx).felem_num_limbs * 3 as libc::c_int as size_t
    {} else {
        __assert_fail(
            b"SCALAR_MUL_TABLE_MAX_NUM_FELEM_LIMBS >= SCALAR_MUL_TABLE_NUM_POINTS * ctx->felem_num_limbs * 3\0"
                as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_nistp.c\0"
                as *const u8 as *const libc::c_char,
            429 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 223],
                &[libc::c_char; 223],
            >(
                b"void ec_nistp_scalar_mul(const ec_nistp_meth *, ec_nistp_felem_limb *, ec_nistp_felem_limb *, ec_nistp_felem_limb *, const ec_nistp_felem_limb *, const ec_nistp_felem_limb *, const ec_nistp_felem_limb *, const EC_SCALAR *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_10856: {
        if (((1 as libc::c_int) << 5 as libc::c_int - 1 as libc::c_int)
            * 3 as libc::c_int * 9 as libc::c_int) as size_t
            >= ((1 as libc::c_int) << 5 as libc::c_int - 1 as libc::c_int) as size_t
                * (*ctx).felem_num_limbs * 3 as libc::c_int as size_t
        {} else {
            __assert_fail(
                b"SCALAR_MUL_TABLE_MAX_NUM_FELEM_LIMBS >= SCALAR_MUL_TABLE_NUM_POINTS * ctx->felem_num_limbs * 3\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_nistp.c\0"
                    as *const u8 as *const libc::c_char,
                429 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 223],
                    &[libc::c_char; 223],
                >(
                    b"void ec_nistp_scalar_mul(const ec_nistp_meth *, ec_nistp_felem_limb *, ec_nistp_felem_limb *, ec_nistp_felem_limb *, const ec_nistp_felem_limb *, const ec_nistp_felem_limb *, const ec_nistp_felem_limb *, const EC_SCALAR *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut table: [ec_nistp_felem_limb; 432] = [0; 432];
    generate_table(ctx, table.as_mut_ptr(), x_in, y_in, z_in);
    let mut rwnaf: [int16_t; 105] = [0; 105];
    scalar_rwnaf(
        rwnaf.as_mut_ptr(),
        5 as libc::c_int as size_t,
        scalar,
        (*ctx).felem_num_bits,
    );
    let mut res: [ec_nistp_felem_limb; 27] = [0; 27];
    let mut tmp: [ec_nistp_felem_limb; 27] = [0; 27];
    let mut x_res: *mut ec_nistp_felem_limb = &mut *res
        .as_mut_ptr()
        .offset(0 as libc::c_int as isize) as *mut ec_nistp_felem_limb;
    let mut y_res: *mut ec_nistp_felem_limb = &mut *res
        .as_mut_ptr()
        .offset((*ctx).felem_num_limbs as isize) as *mut ec_nistp_felem_limb;
    let mut z_res: *mut ec_nistp_felem_limb = &mut *res
        .as_mut_ptr()
        .offset(((*ctx).felem_num_limbs * 2 as libc::c_int as size_t) as isize)
        as *mut ec_nistp_felem_limb;
    let mut x_tmp: *mut ec_nistp_felem_limb = &mut *tmp
        .as_mut_ptr()
        .offset(0 as libc::c_int as isize) as *mut ec_nistp_felem_limb;
    let mut y_tmp: *mut ec_nistp_felem_limb = &mut *tmp
        .as_mut_ptr()
        .offset((*ctx).felem_num_limbs as isize) as *mut ec_nistp_felem_limb;
    let mut z_tmp: *mut ec_nistp_felem_limb = &mut *tmp
        .as_mut_ptr()
        .offset(((*ctx).felem_num_limbs * 2 as libc::c_int as size_t) as isize)
        as *mut ec_nistp_felem_limb;
    let num_windows: size_t = ((*ctx).felem_num_bits)
        .wrapping_add(5 as libc::c_int as size_t)
        .wrapping_sub(1 as libc::c_int as size_t) / 5 as libc::c_int as size_t;
    let mut idx: int16_t = rwnaf[num_windows.wrapping_sub(1 as libc::c_int as size_t)
        as usize];
    idx = (idx as libc::c_int >> 1 as libc::c_int) as int16_t;
    select_point_from_table(
        ctx,
        res.as_mut_ptr(),
        table.as_mut_ptr(),
        idx as size_t,
        1 as libc::c_int as size_t,
    );
    let mut i: libc::c_int = num_windows.wrapping_sub(2 as libc::c_int as size_t)
        as libc::c_int;
    while i >= 0 as libc::c_int {
        let mut j: size_t = 0 as libc::c_int as size_t;
        while j < 5 as libc::c_int as size_t {
            ((*ctx).point_dbl)
                .expect(
                    "non-null function pointer",
                )(x_res, y_res, z_res, x_res, y_res, z_res);
            j = j.wrapping_add(1);
            j;
        }
        let mut d: int16_t = rwnaf[i as usize];
        let mut is_neg: int16_t = (d as libc::c_int >> 15 as libc::c_int
            & 1 as libc::c_int) as int16_t;
        d = ((d as libc::c_int ^ -(is_neg as libc::c_int)) + is_neg as libc::c_int)
            as int16_t;
        idx = (d as libc::c_int >> 1 as libc::c_int) as int16_t;
        select_point_from_table(
            ctx,
            tmp.as_mut_ptr(),
            table.as_mut_ptr(),
            idx as size_t,
            1 as libc::c_int as size_t,
        );
        let mut ftmp: ec_nistp_felem = [0; 9];
        ((*ctx).felem_neg).expect("non-null function pointer")(ftmp.as_mut_ptr(), y_tmp);
        cmovznz(
            y_tmp,
            (*ctx).felem_num_limbs,
            is_neg as ec_nistp_felem_limb,
            y_tmp,
            ftmp.as_mut_ptr(),
        );
        ((*ctx).point_add)
            .expect(
                "non-null function pointer",
            )(
            x_res,
            y_res,
            z_res,
            x_res,
            y_res,
            z_res,
            0 as libc::c_int,
            x_tmp,
            y_tmp,
            z_tmp,
        );
        i -= 1;
        i;
    }
    let mut x_mp: *mut ec_nistp_felem_limb = &mut *table
        .as_mut_ptr()
        .offset(0 as libc::c_int as isize) as *mut ec_nistp_felem_limb;
    let mut y_mp: *mut ec_nistp_felem_limb = &mut *table
        .as_mut_ptr()
        .offset((*ctx).felem_num_limbs as isize) as *mut ec_nistp_felem_limb;
    let mut z_mp: *mut ec_nistp_felem_limb = &mut *table
        .as_mut_ptr()
        .offset(((*ctx).felem_num_limbs * 2 as libc::c_int as size_t) as isize)
        as *mut ec_nistp_felem_limb;
    ((*ctx).felem_neg).expect("non-null function pointer")(y_mp, y_mp);
    ((*ctx).point_add)
        .expect(
            "non-null function pointer",
        )(x_tmp, y_tmp, z_tmp, x_res, y_res, z_res, 0 as libc::c_int, x_mp, y_mp, z_mp);
    let mut t: ec_nistp_felem_limb = (*scalar).words[0 as libc::c_int as usize]
        & 1 as libc::c_int as BN_ULONG;
    cmovznz(x_out, (*ctx).felem_num_limbs, t, x_tmp, x_res);
    cmovznz(y_out, (*ctx).felem_num_limbs, t, y_tmp, y_res);
    cmovznz(z_out, (*ctx).felem_num_limbs, t, z_tmp, z_res);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_nistp_scalar_mul_base(
    mut ctx: *const ec_nistp_meth,
    mut x_out: *mut ec_nistp_felem_limb,
    mut y_out: *mut ec_nistp_felem_limb,
    mut z_out: *mut ec_nistp_felem_limb,
    mut scalar: *const EC_SCALAR,
) {
    let mut rwnaf: [int16_t; 105] = [0; 105];
    scalar_rwnaf(
        rwnaf.as_mut_ptr(),
        5 as libc::c_int as size_t,
        scalar,
        (*ctx).felem_num_bits,
    );
    let mut num_windows: size_t = ((*ctx).felem_num_bits)
        .wrapping_add(5 as libc::c_int as size_t)
        .wrapping_sub(1 as libc::c_int as size_t) / 5 as libc::c_int as size_t;
    let mut res: [ec_nistp_felem_limb; 27] = [
        0 as libc::c_int as ec_nistp_felem_limb,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
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
    let mut tmp: [ec_nistp_felem_limb; 27] = [
        0 as libc::c_int as ec_nistp_felem_limb,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
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
    let mut x_res: *mut ec_nistp_felem_limb = &mut *res
        .as_mut_ptr()
        .offset(0 as libc::c_int as isize) as *mut ec_nistp_felem_limb;
    let mut y_res: *mut ec_nistp_felem_limb = &mut *res
        .as_mut_ptr()
        .offset((*ctx).felem_num_limbs as isize) as *mut ec_nistp_felem_limb;
    let mut z_res: *mut ec_nistp_felem_limb = &mut *res
        .as_mut_ptr()
        .offset(((*ctx).felem_num_limbs * 2 as libc::c_int as size_t) as isize)
        as *mut ec_nistp_felem_limb;
    let mut x_tmp: *mut ec_nistp_felem_limb = &mut *tmp
        .as_mut_ptr()
        .offset(0 as libc::c_int as isize) as *mut ec_nistp_felem_limb;
    let mut y_tmp: *mut ec_nistp_felem_limb = &mut *tmp
        .as_mut_ptr()
        .offset((*ctx).felem_num_limbs as isize) as *mut ec_nistp_felem_limb;
    let mut z_tmp: *mut ec_nistp_felem_limb = &mut *tmp
        .as_mut_ptr()
        .offset(((*ctx).felem_num_limbs * 2 as libc::c_int as size_t) as isize)
        as *mut ec_nistp_felem_limb;
    let mut i: libc::c_int = 3 as libc::c_int;
    while i >= 0 as libc::c_int {
        let mut j: size_t = 0 as libc::c_int as size_t;
        while i != 3 as libc::c_int && j < 5 as libc::c_int as size_t {
            ((*ctx).point_dbl)
                .expect(
                    "non-null function pointer",
                )(x_res, y_res, z_res, x_res, y_res, z_res);
            j = j.wrapping_add(1);
            j;
        }
        let mut start_idx: size_t = (num_windows
            .wrapping_sub(i as size_t)
            .wrapping_sub(1 as libc::c_int as size_t) / 4 as libc::c_int as size_t
            * 4 as libc::c_int as size_t)
            .wrapping_add(i as size_t);
        let mut j_0: libc::c_int = start_idx as libc::c_int;
        while j_0 >= 0 as libc::c_int {
            let mut d: int16_t = rwnaf[j_0 as usize];
            let mut is_neg: int16_t = (d as libc::c_int >> 15 as libc::c_int
                & 1 as libc::c_int) as int16_t;
            d = ((d as libc::c_int ^ -(is_neg as libc::c_int)) + is_neg as libc::c_int)
                as int16_t;
            let mut idx: int16_t = (d as libc::c_int >> 1 as libc::c_int) as int16_t;
            let mut point_num_limbs: size_t = 2 as libc::c_int as size_t
                * (*ctx).felem_num_limbs;
            let mut subtable_num_limbs: size_t = ((1 as libc::c_int)
                << 5 as libc::c_int - 1 as libc::c_int) as size_t * point_num_limbs;
            let mut table_idx: size_t = (j_0 / 4 as libc::c_int) as size_t
                * subtable_num_limbs;
            let mut table: *const ec_nistp_felem_limb = &*((*ctx).scalar_mul_base_table)
                .offset(table_idx as isize) as *const ec_nistp_felem_limb;
            select_point_from_table(
                ctx,
                tmp.as_mut_ptr(),
                table,
                idx as size_t,
                0 as libc::c_int as size_t,
            );
            let mut ftmp: ec_nistp_felem = [0; 9];
            ((*ctx).felem_neg)
                .expect("non-null function pointer")(ftmp.as_mut_ptr(), y_tmp);
            cmovznz(
                y_tmp,
                (*ctx).felem_num_limbs,
                is_neg as ec_nistp_felem_limb,
                y_tmp,
                ftmp.as_mut_ptr(),
            );
            ((*ctx).point_add)
                .expect(
                    "non-null function pointer",
                )(
                x_res,
                y_res,
                z_res,
                x_res,
                y_res,
                z_res,
                1 as libc::c_int,
                x_tmp,
                y_tmp,
                (*ctx).felem_one,
            );
            j_0 -= 4 as libc::c_int;
        }
        i -= 1;
        i;
    }
    let mut x_mp: *const ec_nistp_felem_limb = &*((*ctx).scalar_mul_base_table)
        .offset(0 as libc::c_int as isize) as *const ec_nistp_felem_limb;
    let mut y_mp: *const ec_nistp_felem_limb = &*((*ctx).scalar_mul_base_table)
        .offset((*ctx).felem_num_limbs as isize) as *const ec_nistp_felem_limb;
    let mut ftmp_0: ec_nistp_felem = [0; 9];
    ((*ctx).felem_neg).expect("non-null function pointer")(ftmp_0.as_mut_ptr(), y_mp);
    ((*ctx).point_add)
        .expect(
            "non-null function pointer",
        )(
        x_tmp,
        y_tmp,
        z_tmp,
        x_res,
        y_res,
        z_res,
        1 as libc::c_int,
        x_mp,
        ftmp_0.as_mut_ptr(),
        (*ctx).felem_one,
    );
    let mut t: ec_nistp_felem_limb = (*scalar).words[0 as libc::c_int as usize]
        & 1 as libc::c_int as BN_ULONG;
    cmovznz(x_out, (*ctx).felem_num_limbs, t, x_tmp, x_res);
    cmovznz(y_out, (*ctx).felem_num_limbs, t, y_tmp, y_res);
    cmovznz(z_out, (*ctx).felem_num_limbs, t, z_tmp, z_res);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_nistp_scalar_mul_public(
    mut ctx: *const ec_nistp_meth,
    mut x_out: *mut ec_nistp_felem_limb,
    mut y_out: *mut ec_nistp_felem_limb,
    mut z_out: *mut ec_nistp_felem_limb,
    mut g_scalar: *const EC_SCALAR,
    mut x_p: *const ec_nistp_felem_limb,
    mut y_p: *const ec_nistp_felem_limb,
    mut z_p: *const ec_nistp_felem_limb,
    mut p_scalar: *const EC_SCALAR,
) {
    let felem_num_bytes: size_t = ((*ctx).felem_num_limbs)
        .wrapping_mul(::core::mem::size_of::<ec_nistp_felem_limb>() as libc::c_ulong);
    let mut p_table: [ec_nistp_felem_limb; 432] = [0; 432];
    generate_table(ctx, p_table.as_mut_ptr(), x_p, y_p, z_p);
    let p_point_num_limbs: size_t = 3 as libc::c_int as size_t * (*ctx).felem_num_limbs;
    let mut g_table: *const ec_nistp_felem_limb = (*ctx).scalar_mul_base_table;
    let g_point_num_limbs: size_t = 2 as libc::c_int as size_t * (*ctx).felem_num_limbs;
    let mut p_wnaf: [int8_t; 522] = [
        0 as libc::c_int as int8_t,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
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
    let mut g_wnaf: [int8_t; 522] = [
        0 as libc::c_int as int8_t,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
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
    ec_compute_wNAF(
        p_wnaf.as_mut_ptr(),
        p_scalar,
        (*ctx).felem_num_bits,
        5 as libc::c_int,
    );
    ec_compute_wNAF(
        g_wnaf.as_mut_ptr(),
        g_scalar,
        (*ctx).felem_num_bits,
        5 as libc::c_int,
    );
    let mut res_is_inf: int16_t = 1 as libc::c_int as int16_t;
    let mut d: int16_t = 0;
    let mut is_neg: int16_t = 0;
    let mut idx: int16_t = 0;
    let mut ftmp: ec_nistp_felem = [0; 9];
    let mut i: libc::c_int = (*ctx).felem_num_bits as libc::c_int;
    while i >= 0 as libc::c_int {
        if res_is_inf == 0 {
            ((*ctx).point_dbl)
                .expect(
                    "non-null function pointer",
                )(x_out, y_out, z_out, x_out, y_out, z_out);
        }
        d = p_wnaf[i as usize] as int16_t;
        if d as libc::c_int != 0 as libc::c_int {
            is_neg = (if (d as libc::c_int) < 0 as libc::c_int {
                1 as libc::c_int
            } else {
                0 as libc::c_int
            }) as int16_t;
            idx = (if is_neg as libc::c_int != 0 {
                -(d as libc::c_int) - 1 as libc::c_int >> 1 as libc::c_int
            } else {
                d as libc::c_int - 1 as libc::c_int >> 1 as libc::c_int
            }) as int16_t;
            if res_is_inf != 0 {
                let table_idx: size_t = idx as size_t * p_point_num_limbs;
                OPENSSL_memcpy(
                    x_out as *mut libc::c_void,
                    &mut *p_table.as_mut_ptr().offset(table_idx as isize)
                        as *mut ec_nistp_felem_limb as *const libc::c_void,
                    felem_num_bytes,
                );
                OPENSSL_memcpy(
                    y_out as *mut libc::c_void,
                    &mut *p_table
                        .as_mut_ptr()
                        .offset(table_idx.wrapping_add((*ctx).felem_num_limbs) as isize)
                        as *mut ec_nistp_felem_limb as *const libc::c_void,
                    felem_num_bytes,
                );
                OPENSSL_memcpy(
                    z_out as *mut libc::c_void,
                    &mut *p_table
                        .as_mut_ptr()
                        .offset(
                            table_idx
                                .wrapping_add(
                                    (*ctx).felem_num_limbs * 2 as libc::c_int as size_t,
                                ) as isize,
                        ) as *mut ec_nistp_felem_limb as *const libc::c_void,
                    felem_num_bytes,
                );
                res_is_inf = 0 as libc::c_int as int16_t;
            } else {
                let mut y_tmp: *const ec_nistp_felem_limb = 0
                    as *const ec_nistp_felem_limb;
                y_tmp = &mut *p_table
                    .as_mut_ptr()
                    .offset(
                        (idx as size_t * p_point_num_limbs)
                            .wrapping_add((*ctx).felem_num_limbs) as isize,
                    ) as *mut ec_nistp_felem_limb;
                if is_neg != 0 {
                    ((*ctx).felem_neg)
                        .expect("non-null function pointer")(ftmp.as_mut_ptr(), y_tmp);
                    y_tmp = ftmp.as_mut_ptr();
                }
                ((*ctx).point_add)
                    .expect(
                        "non-null function pointer",
                    )(
                    x_out,
                    y_out,
                    z_out,
                    x_out,
                    y_out,
                    z_out,
                    0 as libc::c_int,
                    &mut *p_table
                        .as_mut_ptr()
                        .offset((idx as size_t * p_point_num_limbs) as isize),
                    y_tmp,
                    &mut *p_table
                        .as_mut_ptr()
                        .offset(
                            (idx as size_t * p_point_num_limbs)
                                .wrapping_add(
                                    (*ctx).felem_num_limbs * 2 as libc::c_int as size_t,
                                ) as isize,
                        ),
                );
            }
        }
        d = g_wnaf[i as usize] as int16_t;
        if d as libc::c_int != 0 as libc::c_int {
            is_neg = (if (d as libc::c_int) < 0 as libc::c_int {
                1 as libc::c_int
            } else {
                0 as libc::c_int
            }) as int16_t;
            idx = (if is_neg as libc::c_int != 0 {
                -(d as libc::c_int) - 1 as libc::c_int >> 1 as libc::c_int
            } else {
                d as libc::c_int - 1 as libc::c_int >> 1 as libc::c_int
            }) as int16_t;
            if res_is_inf != 0 {
                let table_idx_0: size_t = idx as size_t * g_point_num_limbs;
                OPENSSL_memcpy(
                    x_out as *mut libc::c_void,
                    &*g_table.offset(table_idx_0 as isize) as *const ec_nistp_felem_limb
                        as *const libc::c_void,
                    felem_num_bytes,
                );
                OPENSSL_memcpy(
                    y_out as *mut libc::c_void,
                    &*g_table
                        .offset(
                            table_idx_0.wrapping_add((*ctx).felem_num_limbs) as isize,
                        ) as *const ec_nistp_felem_limb as *const libc::c_void,
                    felem_num_bytes,
                );
                OPENSSL_memcpy(
                    z_out as *mut libc::c_void,
                    (*ctx).felem_one as *const libc::c_void,
                    felem_num_bytes,
                );
                res_is_inf = 0 as libc::c_int as int16_t;
            } else {
                let mut y_tmp_0: *const ec_nistp_felem_limb = 0
                    as *const ec_nistp_felem_limb;
                y_tmp_0 = &*g_table
                    .offset(
                        (idx as size_t * g_point_num_limbs)
                            .wrapping_add((*ctx).felem_num_limbs) as isize,
                    ) as *const ec_nistp_felem_limb;
                if is_neg != 0 {
                    ((*ctx).felem_neg)
                        .expect(
                            "non-null function pointer",
                        )(
                        ftmp.as_mut_ptr(),
                        &*g_table
                            .offset(
                                (idx as size_t * g_point_num_limbs)
                                    .wrapping_add((*ctx).felem_num_limbs) as isize,
                            ),
                    );
                    y_tmp_0 = ftmp.as_mut_ptr();
                }
                ((*ctx).point_add)
                    .expect(
                        "non-null function pointer",
                    )(
                    x_out,
                    y_out,
                    z_out,
                    x_out,
                    y_out,
                    z_out,
                    1 as libc::c_int,
                    &*g_table.offset((idx as size_t * g_point_num_limbs) as isize),
                    y_tmp_0,
                    (*ctx).felem_one,
                );
            }
        }
        i -= 1;
        i;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_nistp_point_to_coordinates(
    mut x_out: *mut ec_nistp_felem_limb,
    mut y_out: *mut ec_nistp_felem_limb,
    mut z_out: *mut ec_nistp_felem_limb,
    mut xyz_in: *const ec_nistp_felem_limb,
    mut num_limbs_per_coord: size_t,
) {
    let mut num_bytes_per_coord: size_t = num_limbs_per_coord
        .wrapping_mul(::core::mem::size_of::<ec_nistp_felem_limb>() as libc::c_ulong);
    OPENSSL_memcpy(
        x_out as *mut libc::c_void,
        xyz_in as *const libc::c_void,
        num_bytes_per_coord,
    );
    OPENSSL_memcpy(
        y_out as *mut libc::c_void,
        &*xyz_in.offset(num_limbs_per_coord as isize) as *const ec_nistp_felem_limb
            as *const libc::c_void,
        num_bytes_per_coord,
    );
    OPENSSL_memcpy(
        z_out as *mut libc::c_void,
        &*xyz_in.offset((num_limbs_per_coord * 2 as libc::c_int as size_t) as isize)
            as *const ec_nistp_felem_limb as *const libc::c_void,
        num_bytes_per_coord,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ec_nistp_coordinates_to_point(
    mut xyz_out: *mut ec_nistp_felem_limb,
    mut x_in: *const ec_nistp_felem_limb,
    mut y_in: *const ec_nistp_felem_limb,
    mut z_in: *const ec_nistp_felem_limb,
    mut num_limbs_per_coord: size_t,
) {
    let mut num_bytes_per_coord: size_t = num_limbs_per_coord
        .wrapping_mul(::core::mem::size_of::<ec_nistp_felem_limb>() as libc::c_ulong);
    OPENSSL_memcpy(
        xyz_out as *mut libc::c_void,
        x_in as *const libc::c_void,
        num_bytes_per_coord,
    );
    OPENSSL_memcpy(
        &mut *xyz_out.offset(num_limbs_per_coord as isize) as *mut ec_nistp_felem_limb
            as *mut libc::c_void,
        y_in as *const libc::c_void,
        num_bytes_per_coord,
    );
    OPENSSL_memcpy(
        &mut *xyz_out.offset((num_limbs_per_coord * 2 as libc::c_int as size_t) as isize)
            as *mut ec_nistp_felem_limb as *mut libc::c_void,
        z_in as *const libc::c_void,
        num_bytes_per_coord,
    );
}
