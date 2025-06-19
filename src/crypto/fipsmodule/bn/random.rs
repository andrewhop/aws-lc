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
    fn BN_zero(bn: *mut BIGNUM);
    fn RAND_bytes_with_additional_data(
        out: *mut uint8_t,
        out_len: size_t,
        user_additional_data: *const uint8_t,
    );
    fn RAND_bytes(buf: *mut uint8_t, len: size_t) -> libc::c_int;
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
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn bn_wexpand(bn: *mut BIGNUM, words: size_t) -> libc::c_int;
    fn bn_less_than_words(
        a: *const BN_ULONG,
        b: *const BN_ULONG,
        len: size_t,
    ) -> libc::c_int;
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
pub type crypto_word_t = uint64_t;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_205_error_is_crypto_word_t_is_too_small {
    #[bitfield(
        name = "static_assertion_at_line_205_error_is_crypto_word_t_is_too_small",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_205_error_is_crypto_word_t_is_too_small: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
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
unsafe extern "C" fn constant_time_lt_w(
    mut a: crypto_word_t,
    mut b: crypto_word_t,
) -> crypto_word_t {
    return constant_time_msb_w(a ^ (a ^ b | a.wrapping_sub(b) ^ a));
}
#[inline]
unsafe extern "C" fn constant_time_is_zero_w(mut a: crypto_word_t) -> crypto_word_t {
    return constant_time_msb_w(!a & a.wrapping_sub(1 as libc::c_int as crypto_word_t));
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
unsafe extern "C" fn constant_time_declassify_int(mut v: libc::c_int) -> libc::c_int {
    return value_barrier_u32(v as uint32_t) as libc::c_int;
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
unsafe extern "C" fn FIPS_service_indicator_lock_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_unlock_state() {}
#[no_mangle]
pub unsafe extern "C" fn BN_rand(
    mut rnd: *mut BIGNUM,
    mut bits: libc::c_int,
    mut top: libc::c_int,
    mut bottom: libc::c_int,
) -> libc::c_int {
    if rnd.is_null() {
        return 0 as libc::c_int;
    }
    if top != -(1 as libc::c_int) && top != 0 as libc::c_int && top != 1 as libc::c_int {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/random.c\0"
                as *const u8 as *const libc::c_char,
            131 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if bottom != 0 as libc::c_int && bottom != 1 as libc::c_int {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/random.c\0"
                as *const u8 as *const libc::c_char,
            136 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if bits == 0 as libc::c_int {
        BN_zero(rnd);
        return 1 as libc::c_int;
    }
    if bits > 2147483647 as libc::c_int - (64 as libc::c_int - 1 as libc::c_int) {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/random.c\0"
                as *const u8 as *const libc::c_char,
            146 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut words: libc::c_int = (bits + 64 as libc::c_int - 1 as libc::c_int)
        / 64 as libc::c_int;
    let mut bit: libc::c_int = (bits - 1 as libc::c_int) % 64 as libc::c_int;
    let kOne: BN_ULONG = 1 as libc::c_int as BN_ULONG;
    let kThree: BN_ULONG = 3 as libc::c_int as BN_ULONG;
    let mut mask: BN_ULONG = if bit < 64 as libc::c_int - 1 as libc::c_int {
        (kOne << bit + 1 as libc::c_int).wrapping_sub(1 as libc::c_int as BN_ULONG)
    } else {
        0xffffffffffffffff as libc::c_ulong
    };
    if bn_wexpand(rnd, words as size_t) == 0 {
        return 0 as libc::c_int;
    }
    FIPS_service_indicator_lock_state();
    RAND_bytes(
        (*rnd).d as *mut uint8_t,
        (words as libc::c_ulong)
            .wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    );
    FIPS_service_indicator_unlock_state();
    *((*rnd).d).offset((words - 1 as libc::c_int) as isize) &= mask;
    if top != -(1 as libc::c_int) {
        if top == 1 as libc::c_int && bits > 1 as libc::c_int {
            if bit == 0 as libc::c_int {
                *((*rnd).d).offset((words - 1 as libc::c_int) as isize)
                    |= 1 as libc::c_int as BN_ULONG;
                *((*rnd).d).offset((words - 2 as libc::c_int) as isize)
                    |= kOne << 64 as libc::c_int - 1 as libc::c_int;
            } else {
                *((*rnd).d).offset((words - 1 as libc::c_int) as isize)
                    |= kThree << bit - 1 as libc::c_int;
            }
        } else {
            *((*rnd).d).offset((words - 1 as libc::c_int) as isize) |= kOne << bit;
        }
    }
    if bottom == 1 as libc::c_int {
        *((*rnd).d).offset(0 as libc::c_int as isize) |= 1 as libc::c_int as BN_ULONG;
    }
    (*rnd).neg = 0 as libc::c_int;
    (*rnd).width = words;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn BN_pseudo_rand(
    mut rnd: *mut BIGNUM,
    mut bits: libc::c_int,
    mut top: libc::c_int,
    mut bottom: libc::c_int,
) -> libc::c_int {
    return BN_rand(rnd, bits, top, bottom);
}
unsafe extern "C" fn bn_less_than_word_mask(
    mut a: *const BN_ULONG,
    mut len: size_t,
    mut b: BN_ULONG,
) -> crypto_word_t {
    if b == 0 as libc::c_int as BN_ULONG {
        return 0 as libc::c_int as crypto_word_t;
    }
    if len == 0 as libc::c_int as size_t {
        return !(0 as libc::c_int as crypto_word_t);
    }
    let mut mask: crypto_word_t = 0 as libc::c_int as crypto_word_t;
    let mut i: size_t = 1 as libc::c_int as size_t;
    while i < len {
        mask |= *a.offset(i as isize);
        i = i.wrapping_add(1);
        i;
    }
    mask = constant_time_is_zero_w(mask);
    mask &= constant_time_lt_w(*a.offset(0 as libc::c_int as isize), b);
    return mask;
}
#[no_mangle]
pub unsafe extern "C" fn bn_in_range_words(
    mut a: *const BN_ULONG,
    mut min_inclusive: BN_ULONG,
    mut max_exclusive: *const BN_ULONG,
    mut len: size_t,
) -> libc::c_int {
    let mut mask: crypto_word_t = !bn_less_than_word_mask(a, len, min_inclusive);
    return (mask & bn_less_than_words(a, max_exclusive, len) as crypto_word_t)
        as libc::c_int;
}
unsafe extern "C" fn bn_range_to_mask(
    mut out_words: *mut size_t,
    mut out_mask: *mut BN_ULONG,
    mut min_inclusive: size_t,
    mut max_exclusive: *const BN_ULONG,
    mut len: size_t,
) -> libc::c_int {
    let mut words: size_t = len;
    while words > 0 as libc::c_int as size_t
        && *max_exclusive.offset(words.wrapping_sub(1 as libc::c_int as size_t) as isize)
            == 0 as libc::c_int as BN_ULONG
    {
        words = words.wrapping_sub(1);
        words;
    }
    if words == 0 as libc::c_int as size_t
        || words == 1 as libc::c_int as size_t
            && *max_exclusive.offset(0 as libc::c_int as isize) <= min_inclusive
    {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            108 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/random.c\0"
                as *const u8 as *const libc::c_char,
            232 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut mask: BN_ULONG = *max_exclusive
        .offset(words.wrapping_sub(1 as libc::c_int as size_t) as isize);
    mask |= mask >> 1 as libc::c_int;
    mask |= mask >> 2 as libc::c_int;
    mask |= mask >> 4 as libc::c_int;
    mask |= mask >> 8 as libc::c_int;
    mask |= mask >> 16 as libc::c_int;
    mask |= mask >> 32 as libc::c_int;
    *out_words = words;
    *out_mask = mask;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn bn_rand_range_words(
    mut out: *mut BN_ULONG,
    mut min_inclusive: BN_ULONG,
    mut max_exclusive: *const BN_ULONG,
    mut len: size_t,
    mut additional_data: *const uint8_t,
) -> libc::c_int {
    let mut count: libc::c_uint = 0;
    let mut current_block: u64;
    FIPS_service_indicator_lock_state();
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut words: size_t = 0;
    let mut mask: BN_ULONG = 0;
    if !(bn_range_to_mask(&mut words, &mut mask, min_inclusive, max_exclusive, len) == 0)
    {
        OPENSSL_memset(
            out.offset(words as isize) as *mut libc::c_void,
            0 as libc::c_int,
            len
                .wrapping_sub(words)
                .wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
        );
        count = 100 as libc::c_int as libc::c_uint;
        loop {
            count = count.wrapping_sub(1);
            if count == 0 {
                ERR_put_error(
                    3 as libc::c_int,
                    0 as libc::c_int,
                    115 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/random.c\0"
                        as *const u8 as *const libc::c_char,
                    278 as libc::c_int as libc::c_uint,
                );
                current_block = 16699561238812206362;
                break;
            } else {
                RAND_bytes_with_additional_data(
                    out as *mut uint8_t,
                    words
                        .wrapping_mul(
                            ::core::mem::size_of::<BN_ULONG>() as libc::c_ulong,
                        ),
                    additional_data,
                );
                *out.offset(words.wrapping_sub(1 as libc::c_int as size_t) as isize)
                    &= mask;
                if !(constant_time_declassify_int(
                    bn_in_range_words(out, min_inclusive, max_exclusive, words),
                ) == 0)
                {
                    current_block = 13513818773234778473;
                    break;
                }
            }
        }
        match current_block {
            16699561238812206362 => {}
            _ => {
                ret = 1 as libc::c_int;
            }
        }
    }
    FIPS_service_indicator_unlock_state();
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn BN_rand_range_ex(
    mut r: *mut BIGNUM,
    mut min_inclusive: BN_ULONG,
    mut max_exclusive: *const BIGNUM,
) -> libc::c_int {
    static mut kDefaultAdditionalData: [uint8_t; 32] = [
        0 as libc::c_int as uint8_t,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
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
    if bn_wexpand(r, (*max_exclusive).width as size_t) == 0
        || bn_rand_range_words(
            (*r).d,
            min_inclusive,
            (*max_exclusive).d,
            (*max_exclusive).width as size_t,
            kDefaultAdditionalData.as_ptr(),
        ) == 0
    {
        return 0 as libc::c_int;
    }
    (*r).neg = 0 as libc::c_int;
    (*r).width = (*max_exclusive).width;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn bn_rand_secret_range(
    mut r: *mut BIGNUM,
    mut out_is_uniform: *mut libc::c_int,
    mut min_inclusive: BN_ULONG,
    mut max_exclusive: *const BIGNUM,
) -> libc::c_int {
    let mut in_range: crypto_word_t = 0;
    FIPS_service_indicator_lock_state();
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut words: size_t = 0;
    let mut mask: BN_ULONG = 0;
    if !(bn_range_to_mask(
        &mut words,
        &mut mask,
        min_inclusive,
        (*max_exclusive).d,
        (*max_exclusive).width as size_t,
    ) == 0 || bn_wexpand(r, words) == 0)
    {
        if words > 0 as libc::c_int as size_t {} else {
            __assert_fail(
                b"words > 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/random.c\0"
                    as *const u8 as *const libc::c_char,
                334 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 68],
                    &[libc::c_char; 68],
                >(
                    b"int bn_rand_secret_range(BIGNUM *, int *, BN_ULONG, const BIGNUM *)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_8565: {
            if words > 0 as libc::c_int as size_t {} else {
                __assert_fail(
                    b"words > 0\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/random.c\0"
                        as *const u8 as *const libc::c_char,
                    334 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 68],
                        &[libc::c_char; 68],
                    >(
                        b"int bn_rand_secret_range(BIGNUM *, int *, BN_ULONG, const BIGNUM *)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        if mask != 0 as libc::c_int as BN_ULONG {} else {
            __assert_fail(
                b"mask != 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/random.c\0"
                    as *const u8 as *const libc::c_char,
                335 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 68],
                    &[libc::c_char; 68],
                >(
                    b"int bn_rand_secret_range(BIGNUM *, int *, BN_ULONG, const BIGNUM *)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_8526: {
            if mask != 0 as libc::c_int as BN_ULONG {} else {
                __assert_fail(
                    b"mask != 0\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/random.c\0"
                        as *const u8 as *const libc::c_char,
                    335 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 68],
                        &[libc::c_char; 68],
                    >(
                        b"int bn_rand_secret_range(BIGNUM *, int *, BN_ULONG, const BIGNUM *)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        if words == 1 as libc::c_int as size_t
            && min_inclusive > mask >> 1 as libc::c_int
        {
            ERR_put_error(
                3 as libc::c_int,
                0 as libc::c_int,
                108 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/random.c\0"
                    as *const u8 as *const libc::c_char,
                338 as libc::c_int as libc::c_uint,
            );
        } else {
            RAND_bytes(
                (*r).d as *mut uint8_t,
                words.wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
            );
            *((*r).d).offset(words.wrapping_sub(1 as libc::c_int as size_t) as isize)
                &= mask;
            *out_is_uniform = bn_in_range_words(
                (*r).d,
                min_inclusive,
                (*max_exclusive).d,
                words,
            );
            in_range = *out_is_uniform as crypto_word_t;
            in_range = (0 as libc::c_int as crypto_word_t).wrapping_sub(in_range);
            let ref mut fresh0 = *((*r).d).offset(0 as libc::c_int as isize);
            *fresh0
                |= constant_time_select_w(
                    in_range,
                    0 as libc::c_int as crypto_word_t,
                    min_inclusive,
                );
            let ref mut fresh1 = *((*r).d)
                .offset(words.wrapping_sub(1 as libc::c_int as size_t) as isize);
            *fresh1
                &= constant_time_select_w(
                    in_range,
                    0xffffffffffffffff as libc::c_ulong,
                    mask >> 1 as libc::c_int,
                );
            if constant_time_declassify_int(
                bn_in_range_words((*r).d, min_inclusive, (*max_exclusive).d, words),
            ) != 0
            {} else {
                __assert_fail(
                    b"constant_time_declassify_int(bn_in_range_words(r->d, min_inclusive, max_exclusive->d, words))\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/random.c\0"
                        as *const u8 as *const libc::c_char,
                    356 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 68],
                        &[libc::c_char; 68],
                    >(
                        b"int bn_rand_secret_range(BIGNUM *, int *, BN_ULONG, const BIGNUM *)\0",
                    ))
                        .as_ptr(),
                );
            }
            'c_8331: {
                if constant_time_declassify_int(
                    bn_in_range_words((*r).d, min_inclusive, (*max_exclusive).d, words),
                ) != 0
                {} else {
                    __assert_fail(
                        b"constant_time_declassify_int(bn_in_range_words(r->d, min_inclusive, max_exclusive->d, words))\0"
                            as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/random.c\0"
                            as *const u8 as *const libc::c_char,
                        356 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 68],
                            &[libc::c_char; 68],
                        >(
                            b"int bn_rand_secret_range(BIGNUM *, int *, BN_ULONG, const BIGNUM *)\0",
                        ))
                            .as_ptr(),
                    );
                }
            };
            (*r).neg = 0 as libc::c_int;
            (*r).width = words as libc::c_int;
            ret = 1 as libc::c_int;
        }
    }
    FIPS_service_indicator_unlock_state();
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn BN_rand_range(
    mut r: *mut BIGNUM,
    mut range: *const BIGNUM,
) -> libc::c_int {
    return BN_rand_range_ex(r, 0 as libc::c_int as BN_ULONG, range);
}
#[no_mangle]
pub unsafe extern "C" fn BN_pseudo_rand_range(
    mut r: *mut BIGNUM,
    mut range: *const BIGNUM,
) -> libc::c_int {
    return BN_rand_range(r, range);
}
