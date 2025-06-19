#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(asm, extern_types)]
use core::arch::asm;
unsafe extern "C" {
    pub type bignum_ctx;
    fn BN_copy(dest: *mut BIGNUM, src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_CTX_start(ctx: *mut BN_CTX);
    fn BN_CTX_get(ctx: *mut BN_CTX) -> *mut BIGNUM;
    fn BN_CTX_end(ctx: *mut BN_CTX);
    fn memmove(
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
    fn bn_set_minimal_width(bn: *mut BIGNUM);
    fn bn_wexpand(bn: *mut BIGNUM, words: size_t) -> libc::c_int;
    fn bn_select_words(
        r: *mut BN_ULONG,
        mask: BN_ULONG,
        a: *const BN_ULONG,
        b: *const BN_ULONG,
        num: size_t,
    );
}
pub type size_t = libc::c_ulong;
pub type __uint64_t = libc::c_ulong;
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
pub type crypto_word_t = uint64_t;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_307_error_is_BN_ULONG_gets_promoted_to_int {
    #[bitfield(
        name = "static_assertion_at_line_307_error_is_BN_ULONG_gets_promoted_to_int",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_307_error_is_BN_ULONG_gets_promoted_to_int: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_304_error_is_BN_ULONG_has_padding_bits {
    #[bitfield(
        name = "static_assertion_at_line_304_error_is_BN_ULONG_has_padding_bits",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_304_error_is_BN_ULONG_has_padding_bits: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_302_error_is_crypto_word_t_is_too_small {
    #[bitfield(
        name = "static_assertion_at_line_302_error_is_crypto_word_t_is_too_small",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_302_error_is_crypto_word_t_is_too_small: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_300_error_is_crypto_word_t_is_too_small {
    #[bitfield(
        name = "static_assertion_at_line_300_error_is_crypto_word_t_is_too_small",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_300_error_is_crypto_word_t_is_too_small: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_348_error_is_crypto_word_t_is_too_small {
    #[bitfield(
        name = "static_assertion_at_line_348_error_is_crypto_word_t_is_too_small",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_348_error_is_crypto_word_t_is_too_small: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_346_error_is_crypto_word_t_is_too_small {
    #[bitfield(
        name = "static_assertion_at_line_346_error_is_crypto_word_t_is_too_small",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_346_error_is_crypto_word_t_is_too_small: [u8; 1],
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
unsafe extern "C" fn constant_time_select_w(
    mut mask: crypto_word_t,
    mut a: crypto_word_t,
    mut b: crypto_word_t,
) -> crypto_word_t {
    return value_barrier_w(mask) & a | value_barrier_w(!mask) & b;
}
#[inline]
unsafe extern "C" fn OPENSSL_memmove(
    mut dst: *mut libc::c_void,
    mut src: *const libc::c_void,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return dst;
    }
    return memmove(dst, src, n);
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_lshift(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut n: libc::c_int,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut nw: libc::c_int = 0;
    let mut lb: libc::c_int = 0;
    let mut rb: libc::c_int = 0;
    let mut t: *mut BN_ULONG = 0 as *mut BN_ULONG;
    let mut f: *mut BN_ULONG = 0 as *mut BN_ULONG;
    let mut l: BN_ULONG = 0;
    if n < 0 as libc::c_int {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/shift.c\0"
                as *const u8 as *const libc::c_char,
            73 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*r).neg = (*a).neg;
    nw = n / 64 as libc::c_int;
    if bn_wexpand(r, ((*a).width + nw + 1 as libc::c_int) as size_t) == 0 {
        return 0 as libc::c_int;
    }
    lb = n % 64 as libc::c_int;
    rb = 64 as libc::c_int - lb;
    f = (*a).d;
    t = (*r).d;
    *t.offset(((*a).width + nw) as isize) = 0 as libc::c_int as BN_ULONG;
    if lb == 0 as libc::c_int {
        i = (*a).width - 1 as libc::c_int;
        while i >= 0 as libc::c_int {
            *t.offset((nw + i) as isize) = *f.offset(i as isize);
            i -= 1;
            i;
        }
    } else {
        i = (*a).width - 1 as libc::c_int;
        while i >= 0 as libc::c_int {
            l = *f.offset(i as isize);
            *t.offset((nw + i + 1 as libc::c_int) as isize) |= l >> rb;
            *t.offset((nw + i) as isize) = l << lb;
            i -= 1;
            i;
        }
    }
    OPENSSL_memset(
        t as *mut libc::c_void,
        0 as libc::c_int,
        (nw as libc::c_ulong)
            .wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    );
    (*r).width = (*a).width + nw + 1 as libc::c_int;
    bn_set_minimal_width(r);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_lshift1(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
) -> libc::c_int {
    let mut ap: *mut BN_ULONG = 0 as *mut BN_ULONG;
    let mut rp: *mut BN_ULONG = 0 as *mut BN_ULONG;
    let mut t: BN_ULONG = 0;
    let mut c: BN_ULONG = 0;
    let mut i: libc::c_int = 0;
    if r != a as *mut BIGNUM {
        (*r).neg = (*a).neg;
        if bn_wexpand(r, ((*a).width + 1 as libc::c_int) as size_t) == 0 {
            return 0 as libc::c_int;
        }
        (*r).width = (*a).width;
    } else if bn_wexpand(r, ((*a).width + 1 as libc::c_int) as size_t) == 0 {
        return 0 as libc::c_int
    }
    ap = (*a).d;
    rp = (*r).d;
    c = 0 as libc::c_int as BN_ULONG;
    i = 0 as libc::c_int;
    while i < (*a).width {
        let fresh0 = ap;
        ap = ap.offset(1);
        t = *fresh0;
        let fresh1 = rp;
        rp = rp.offset(1);
        *fresh1 = t << 1 as libc::c_int | c;
        c = t >> 64 as libc::c_int - 1 as libc::c_int;
        i += 1;
        i;
    }
    if c != 0 {
        *rp = 1 as libc::c_int as BN_ULONG;
        (*r).width += 1;
        (*r).width;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_rshift_words(
    mut r: *mut BN_ULONG,
    mut a: *const BN_ULONG,
    mut shift: libc::c_uint,
    mut num: size_t,
) {
    let mut shift_bits: libc::c_uint = shift
        .wrapping_rem(64 as libc::c_int as libc::c_uint);
    let mut shift_words: size_t = shift.wrapping_div(64 as libc::c_int as libc::c_uint)
        as size_t;
    if shift_words >= num {
        OPENSSL_memset(
            r as *mut libc::c_void,
            0 as libc::c_int,
            num.wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
        );
        return;
    }
    if shift_bits == 0 as libc::c_int as libc::c_uint {
        OPENSSL_memmove(
            r as *mut libc::c_void,
            a.offset(shift_words as isize) as *const libc::c_void,
            num
                .wrapping_sub(shift_words)
                .wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
        );
    } else {
        let mut i: size_t = shift_words;
        while i < num.wrapping_sub(1 as libc::c_int as size_t) {
            *r
                .offset(
                    i.wrapping_sub(shift_words) as isize,
                ) = *a.offset(i as isize) >> shift_bits
                | *a.offset(i.wrapping_add(1 as libc::c_int as size_t) as isize)
                    << (64 as libc::c_int as libc::c_uint).wrapping_sub(shift_bits);
            i = i.wrapping_add(1);
            i;
        }
        *r
            .offset(
                num.wrapping_sub(1 as libc::c_int as size_t).wrapping_sub(shift_words)
                    as isize,
            ) = *a.offset(num.wrapping_sub(1 as libc::c_int as size_t) as isize)
            >> shift_bits;
    }
    OPENSSL_memset(
        r.offset(num as isize).offset(-(shift_words as isize)) as *mut libc::c_void,
        0 as libc::c_int,
        shift_words.wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_rshift(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut n: libc::c_int,
) -> libc::c_int {
    if n < 0 as libc::c_int {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/shift.c\0"
                as *const u8 as *const libc::c_char,
            158 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if bn_wexpand(r, (*a).width as size_t) == 0 {
        return 0 as libc::c_int;
    }
    bn_rshift_words((*r).d, (*a).d, n as libc::c_uint, (*a).width as size_t);
    (*r).neg = (*a).neg;
    (*r).width = (*a).width;
    bn_set_minimal_width(r);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_rshift_secret_shift(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut n: libc::c_uint,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut max_bits: libc::c_uint = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    BN_CTX_start(ctx);
    let mut tmp: *mut BIGNUM = BN_CTX_get(ctx);
    if !(tmp.is_null() || (BN_copy(r, a)).is_null()
        || bn_wexpand(tmp, (*r).width as size_t) == 0)
    {
        max_bits = (64 as libc::c_int * (*r).width) as libc::c_uint;
        let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
        while max_bits >> i != 0 as libc::c_int as libc::c_uint {
            let mut mask: BN_ULONG = (n >> i & 1 as libc::c_int as libc::c_uint)
                as BN_ULONG;
            mask = (0 as libc::c_int as BN_ULONG).wrapping_sub(mask);
            bn_rshift_words(
                (*tmp).d,
                (*r).d,
                (1 as libc::c_uint) << i,
                (*r).width as size_t,
            );
            bn_select_words((*r).d, mask, (*tmp).d, (*r).d, (*r).width as size_t);
            i = i.wrapping_add(1);
            i;
        }
        ret = 1 as libc::c_int;
    }
    BN_CTX_end(ctx);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_rshift1_words(
    mut r: *mut BN_ULONG,
    mut a: *const BN_ULONG,
    mut num: size_t,
) {
    if num == 0 as libc::c_int as size_t {
        return;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < num.wrapping_sub(1 as libc::c_int as size_t) {
        *r
            .offset(
                i as isize,
            ) = *a.offset(i as isize) >> 1 as libc::c_int
            | *a.offset(i.wrapping_add(1 as libc::c_int as size_t) as isize)
                << 64 as libc::c_int - 1 as libc::c_int;
        i = i.wrapping_add(1);
        i;
    }
    *r
        .offset(
            num.wrapping_sub(1 as libc::c_int as size_t) as isize,
        ) = *a.offset(num.wrapping_sub(1 as libc::c_int as size_t) as isize)
        >> 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_rshift1(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
) -> libc::c_int {
    if bn_wexpand(r, (*a).width as size_t) == 0 {
        return 0 as libc::c_int;
    }
    bn_rshift1_words((*r).d, (*a).d, (*a).width as size_t);
    (*r).width = (*a).width;
    (*r).neg = (*a).neg;
    bn_set_minimal_width(r);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_set_bit(
    mut a: *mut BIGNUM,
    mut n: libc::c_int,
) -> libc::c_int {
    if n < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut i: libc::c_int = n / 64 as libc::c_int;
    let mut j: libc::c_int = n % 64 as libc::c_int;
    if (*a).width <= i {
        if bn_wexpand(a, (i + 1 as libc::c_int) as size_t) == 0 {
            return 0 as libc::c_int;
        }
        let mut k: libc::c_int = (*a).width;
        while k < i + 1 as libc::c_int {
            *((*a).d).offset(k as isize) = 0 as libc::c_int as BN_ULONG;
            k += 1;
            k;
        }
        (*a).width = i + 1 as libc::c_int;
    }
    *((*a).d).offset(i as isize) |= (1 as libc::c_int as BN_ULONG) << j;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_clear_bit(
    mut a: *mut BIGNUM,
    mut n: libc::c_int,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    if n < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    i = n / 64 as libc::c_int;
    j = n % 64 as libc::c_int;
    if (*a).width <= i {
        return 0 as libc::c_int;
    }
    *((*a).d).offset(i as isize) &= !((1 as libc::c_int as BN_ULONG) << j);
    bn_set_minimal_width(a);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_is_bit_set_words(
    mut a: *const BN_ULONG,
    mut num: size_t,
    mut bit: size_t,
) -> libc::c_int {
    let mut i: size_t = bit / 64 as libc::c_int as size_t;
    let mut j: size_t = bit % 64 as libc::c_int as size_t;
    if i >= num {
        return 0 as libc::c_int;
    }
    return (*a.offset(i as isize) >> j & 1 as libc::c_int as BN_ULONG) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_is_bit_set(
    mut a: *const BIGNUM,
    mut n: libc::c_int,
) -> libc::c_int {
    if n < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    return bn_is_bit_set_words((*a).d, (*a).width as size_t, n as size_t);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_mask_bits(
    mut a: *mut BIGNUM,
    mut n: libc::c_int,
) -> libc::c_int {
    if n < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut w: libc::c_int = n / 64 as libc::c_int;
    let mut b: libc::c_int = n % 64 as libc::c_int;
    if w >= (*a).width {
        return 1 as libc::c_int;
    }
    if b == 0 as libc::c_int {
        (*a).width = w;
    } else {
        (*a).width = w + 1 as libc::c_int;
        let ref mut fresh2 = *((*a).d).offset(w as isize);
        *fresh2 &= !((0xffffffffffffffff as libc::c_ulong) << b);
    }
    bn_set_minimal_width(a);
    return 1 as libc::c_int;
}
unsafe extern "C" fn bn_count_low_zero_bits_word(mut l: BN_ULONG) -> libc::c_int {
    let mut mask: crypto_word_t = 0;
    let mut bits: libc::c_int = 0 as libc::c_int;
    mask = constant_time_is_zero_w(l << 64 as libc::c_int - 32 as libc::c_int);
    bits = (bits as crypto_word_t)
        .wrapping_add(32 as libc::c_int as crypto_word_t & mask) as libc::c_int
        as libc::c_int;
    l = constant_time_select_w(mask, l >> 32 as libc::c_int, l);
    mask = constant_time_is_zero_w(l << 64 as libc::c_int - 16 as libc::c_int);
    bits = (bits as crypto_word_t)
        .wrapping_add(16 as libc::c_int as crypto_word_t & mask) as libc::c_int
        as libc::c_int;
    l = constant_time_select_w(mask, l >> 16 as libc::c_int, l);
    mask = constant_time_is_zero_w(l << 64 as libc::c_int - 8 as libc::c_int);
    bits = (bits as crypto_word_t).wrapping_add(8 as libc::c_int as crypto_word_t & mask)
        as libc::c_int as libc::c_int;
    l = constant_time_select_w(mask, l >> 8 as libc::c_int, l);
    mask = constant_time_is_zero_w(l << 64 as libc::c_int - 4 as libc::c_int);
    bits = (bits as crypto_word_t).wrapping_add(4 as libc::c_int as crypto_word_t & mask)
        as libc::c_int as libc::c_int;
    l = constant_time_select_w(mask, l >> 4 as libc::c_int, l);
    mask = constant_time_is_zero_w(l << 64 as libc::c_int - 2 as libc::c_int);
    bits = (bits as crypto_word_t).wrapping_add(2 as libc::c_int as crypto_word_t & mask)
        as libc::c_int as libc::c_int;
    l = constant_time_select_w(mask, l >> 2 as libc::c_int, l);
    mask = constant_time_is_zero_w(l << 64 as libc::c_int - 1 as libc::c_int);
    bits = (bits as crypto_word_t).wrapping_add(1 as libc::c_int as crypto_word_t & mask)
        as libc::c_int as libc::c_int;
    return bits;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_count_low_zero_bits(mut bn: *const BIGNUM) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut saw_nonzero: crypto_word_t = 0 as libc::c_int as crypto_word_t;
    let mut i: libc::c_int = 0 as libc::c_int;
    while i < (*bn).width {
        let mut nonzero: crypto_word_t = !constant_time_is_zero_w(
            *((*bn).d).offset(i as isize),
        );
        let mut first_nonzero: crypto_word_t = !saw_nonzero & nonzero;
        saw_nonzero |= nonzero;
        let mut bits: libc::c_int = bn_count_low_zero_bits_word(
            *((*bn).d).offset(i as isize),
        );
        ret = (ret as crypto_word_t
            | first_nonzero & (i * 64 as libc::c_int + bits) as crypto_word_t)
            as libc::c_int;
        i += 1;
        i;
    }
    return ret;
}
