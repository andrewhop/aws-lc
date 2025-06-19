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
    fn BN_is_zero(bn: *const BIGNUM) -> libc::c_int;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
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
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_calloc(num: size_t, size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
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
    fn CRYPTO_once(
        once: *mut CRYPTO_once_t,
        init: Option::<unsafe extern "C" fn() -> ()>,
    );
}
pub type size_t = libc::c_ulong;
pub type __uint64_t = libc::c_ulong;
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
pub type CRYPTO_once_t = pthread_once_t;
pub type crypto_word_t = uint64_t;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_436_error_is_crypto_word_t_is_too_small {
    #[bitfield(
        name = "static_assertion_at_line_436_error_is_crypto_word_t_is_too_small",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_436_error_is_crypto_word_t_is_too_small: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[inline]
unsafe extern "C" fn value_barrier_w(mut a: crypto_word_t) -> crypto_word_t {
    asm!("", inlateout(reg) a, options(preserves_flags, pure, readonly, att_syntax));
    return a;
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
pub unsafe extern "C" fn BN_new() -> *mut BIGNUM {
    let mut bn: *mut BIGNUM = OPENSSL_zalloc(
        ::core::mem::size_of::<BIGNUM>() as libc::c_ulong,
    ) as *mut BIGNUM;
    if bn.is_null() {
        return 0 as *mut BIGNUM;
    }
    (*bn).flags = 0x1 as libc::c_int;
    return bn;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_secure_new() -> *mut BIGNUM {
    return BN_new();
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_init(mut bn: *mut BIGNUM) {
    OPENSSL_memset(
        bn as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<BIGNUM>() as libc::c_ulong,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_free(mut bn: *mut BIGNUM) {
    if bn.is_null() {
        return;
    }
    if (*bn).flags & 0x2 as libc::c_int == 0 as libc::c_int {
        OPENSSL_free((*bn).d as *mut libc::c_void);
    }
    if (*bn).flags & 0x1 as libc::c_int != 0 {
        OPENSSL_free(bn as *mut libc::c_void);
    } else {
        (*bn).d = 0 as *mut BN_ULONG;
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_clear_free(mut bn: *mut BIGNUM) {
    BN_free(bn);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_dup(mut src: *const BIGNUM) -> *mut BIGNUM {
    let mut copy: *mut BIGNUM = 0 as *mut BIGNUM;
    if src.is_null() {
        return 0 as *mut BIGNUM;
    }
    copy = BN_new();
    if copy.is_null() {
        return 0 as *mut BIGNUM;
    }
    if (BN_copy(copy, src)).is_null() {
        BN_free(copy);
        return 0 as *mut BIGNUM;
    }
    return copy;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_copy(
    mut dest: *mut BIGNUM,
    mut src: *const BIGNUM,
) -> *mut BIGNUM {
    if src == dest as *const BIGNUM {
        return dest;
    }
    if bn_wexpand(dest, (*src).width as size_t) == 0 {
        return 0 as *mut BIGNUM;
    }
    OPENSSL_memcpy(
        (*dest).d as *mut libc::c_void,
        (*src).d as *const libc::c_void,
        (::core::mem::size_of::<BN_ULONG>() as libc::c_ulong)
            .wrapping_mul((*src).width as libc::c_ulong),
    );
    (*dest).width = (*src).width;
    (*dest).neg = (*src).neg;
    return dest;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_clear(mut bn: *mut BIGNUM) {
    if !((*bn).d).is_null() {
        OPENSSL_memset(
            (*bn).d as *mut libc::c_void,
            0 as libc::c_int,
            ((*bn).dmax as libc::c_ulong)
                .wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
        );
    }
    (*bn).width = 0 as libc::c_int;
    (*bn).neg = 0 as libc::c_int;
}
unsafe extern "C" fn BN_value_one_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut BN_value_one_once;
}
static mut BN_value_one_once: CRYPTO_once_t = 0 as libc::c_int;
static mut BN_value_one_storage: BIGNUM = bignum_st {
    d: 0 as *const BN_ULONG as *mut BN_ULONG,
    width: 0,
    dmax: 0,
    neg: 0,
    flags: 0,
};
unsafe extern "C" fn BN_value_one_init() {
    BN_value_one_do_init(BN_value_one_storage_bss_get());
}
unsafe extern "C" fn BN_value_one_do_init(mut out: *mut BIGNUM) {
    static mut kOneLimbs: [BN_ULONG; 1] = [1 as libc::c_int as BN_ULONG];
    (*out).d = kOneLimbs.as_ptr() as *mut BN_ULONG;
    (*out).width = 1 as libc::c_int;
    (*out).dmax = 1 as libc::c_int;
    (*out).neg = 0 as libc::c_int;
    (*out).flags = 0x2 as libc::c_int;
}
unsafe extern "C" fn BN_value_one_storage_bss_get() -> *mut BIGNUM {
    return &mut BN_value_one_storage;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_value_one() -> *const BIGNUM {
    CRYPTO_once(
        BN_value_one_once_bss_get(),
        Some(BN_value_one_init as unsafe extern "C" fn() -> ()),
    );
    return BN_value_one_storage_bss_get() as *const BIGNUM;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_num_bits_word(mut l: BN_ULONG) -> libc::c_uint {
    let mut x: BN_ULONG = 0;
    let mut mask: BN_ULONG = 0;
    let mut bits: libc::c_int = (l != 0 as libc::c_int as BN_ULONG) as libc::c_int;
    x = l >> 32 as libc::c_int;
    mask = (0 as libc::c_uint as BN_ULONG).wrapping_sub(x);
    mask = (0 as libc::c_uint as BN_ULONG)
        .wrapping_sub(mask >> 64 as libc::c_int - 1 as libc::c_int);
    bits = (bits as BN_ULONG).wrapping_add(32 as libc::c_int as BN_ULONG & mask)
        as libc::c_int as libc::c_int;
    l ^= (x ^ l) & mask;
    x = l >> 16 as libc::c_int;
    mask = (0 as libc::c_uint as BN_ULONG).wrapping_sub(x);
    mask = (0 as libc::c_uint as BN_ULONG)
        .wrapping_sub(mask >> 64 as libc::c_int - 1 as libc::c_int);
    bits = (bits as BN_ULONG).wrapping_add(16 as libc::c_int as BN_ULONG & mask)
        as libc::c_int as libc::c_int;
    l ^= (x ^ l) & mask;
    x = l >> 8 as libc::c_int;
    mask = (0 as libc::c_uint as BN_ULONG).wrapping_sub(x);
    mask = (0 as libc::c_uint as BN_ULONG)
        .wrapping_sub(mask >> 64 as libc::c_int - 1 as libc::c_int);
    bits = (bits as BN_ULONG).wrapping_add(8 as libc::c_int as BN_ULONG & mask)
        as libc::c_int as libc::c_int;
    l ^= (x ^ l) & mask;
    x = l >> 4 as libc::c_int;
    mask = (0 as libc::c_uint as BN_ULONG).wrapping_sub(x);
    mask = (0 as libc::c_uint as BN_ULONG)
        .wrapping_sub(mask >> 64 as libc::c_int - 1 as libc::c_int);
    bits = (bits as BN_ULONG).wrapping_add(4 as libc::c_int as BN_ULONG & mask)
        as libc::c_int as libc::c_int;
    l ^= (x ^ l) & mask;
    x = l >> 2 as libc::c_int;
    mask = (0 as libc::c_uint as BN_ULONG).wrapping_sub(x);
    mask = (0 as libc::c_uint as BN_ULONG)
        .wrapping_sub(mask >> 64 as libc::c_int - 1 as libc::c_int);
    bits = (bits as BN_ULONG).wrapping_add(2 as libc::c_int as BN_ULONG & mask)
        as libc::c_int as libc::c_int;
    l ^= (x ^ l) & mask;
    x = l >> 1 as libc::c_int;
    mask = (0 as libc::c_uint as BN_ULONG).wrapping_sub(x);
    mask = (0 as libc::c_uint as BN_ULONG)
        .wrapping_sub(mask >> 64 as libc::c_int - 1 as libc::c_int);
    bits = (bits as BN_ULONG).wrapping_add(1 as libc::c_int as BN_ULONG & mask)
        as libc::c_int as libc::c_int;
    return bits as libc::c_uint;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_num_bits(mut bn: *const BIGNUM) -> libc::c_uint {
    let width: libc::c_int = bn_minimal_width(bn);
    if width == 0 as libc::c_int {
        return 0 as libc::c_int as libc::c_uint;
    }
    return (((width - 1 as libc::c_int) * 64 as libc::c_int) as libc::c_uint)
        .wrapping_add(
            BN_num_bits_word(*((*bn).d).offset((width - 1 as libc::c_int) as isize)),
        );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_num_bytes(mut bn: *const BIGNUM) -> libc::c_uint {
    return (BN_num_bits(bn))
        .wrapping_add(7 as libc::c_int as libc::c_uint)
        .wrapping_div(8 as libc::c_int as libc::c_uint);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_get_minimal_width(mut bn: *const BIGNUM) -> libc::c_int {
    return bn_minimal_width(bn);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_zero(mut bn: *mut BIGNUM) {
    (*bn).neg = 0 as libc::c_int;
    (*bn).width = (*bn).neg;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_one(mut bn: *mut BIGNUM) -> libc::c_int {
    return BN_set_word(bn, 1 as libc::c_int as BN_ULONG);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_set_word(
    mut bn: *mut BIGNUM,
    mut value: BN_ULONG,
) -> libc::c_int {
    if value == 0 as libc::c_int as BN_ULONG {
        BN_zero(bn);
        return 1 as libc::c_int;
    }
    if bn_wexpand(bn, 1 as libc::c_int as size_t) == 0 {
        return 0 as libc::c_int;
    }
    (*bn).neg = 0 as libc::c_int;
    *((*bn).d).offset(0 as libc::c_int as isize) = value;
    (*bn).width = 1 as libc::c_int;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_set_u64(
    mut bn: *mut BIGNUM,
    mut value: uint64_t,
) -> libc::c_int {
    return BN_set_word(bn, value);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_set_words(
    mut bn: *mut BIGNUM,
    mut words: *const BN_ULONG,
    mut num: size_t,
) -> libc::c_int {
    if bn_wexpand(bn, num) == 0 {
        return 0 as libc::c_int;
    }
    OPENSSL_memmove(
        (*bn).d as *mut libc::c_void,
        words as *const libc::c_void,
        num.wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    );
    (*bn).width = num as libc::c_int;
    (*bn).neg = 0 as libc::c_int;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_set_static_words(
    mut bn: *mut BIGNUM,
    mut words: *const BN_ULONG,
    mut num: size_t,
) {
    if (*bn).flags & 0x2 as libc::c_int == 0 as libc::c_int {
        OPENSSL_free((*bn).d as *mut libc::c_void);
    }
    (*bn).d = words as *mut BN_ULONG;
    if num
        <= (2147483647 as libc::c_int / (4 as libc::c_int * 64 as libc::c_int)) as size_t
    {} else {
        __assert_fail(
            b"num <= BN_MAX_WORDS\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/bn.c\0" as *const u8
                as *const libc::c_char,
            308 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 61],
                &[libc::c_char; 61],
            >(b"void bn_set_static_words(BIGNUM *, const BN_ULONG *, size_t)\0"))
                .as_ptr(),
        );
    }
    'c_8610: {
        if num
            <= (2147483647 as libc::c_int / (4 as libc::c_int * 64 as libc::c_int))
                as size_t
        {} else {
            __assert_fail(
                b"num <= BN_MAX_WORDS\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/bn.c\0"
                    as *const u8 as *const libc::c_char,
                308 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 61],
                    &[libc::c_char; 61],
                >(b"void bn_set_static_words(BIGNUM *, const BN_ULONG *, size_t)\0"))
                    .as_ptr(),
            );
        }
    };
    (*bn).width = num as libc::c_int;
    (*bn).dmax = num as libc::c_int;
    (*bn).neg = 0 as libc::c_int;
    (*bn).flags |= 0x2 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_fits_in_words(
    mut bn: *const BIGNUM,
    mut num: size_t,
) -> libc::c_int {
    let mut mask: BN_ULONG = 0 as libc::c_int as BN_ULONG;
    let mut i: size_t = num;
    while i < (*bn).width as size_t {
        mask |= *((*bn).d).offset(i as isize);
        i = i.wrapping_add(1);
        i;
    }
    return (mask == 0 as libc::c_int as BN_ULONG) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_copy_words(
    mut out: *mut BN_ULONG,
    mut num: size_t,
    mut bn: *const BIGNUM,
) -> libc::c_int {
    if (*bn).neg != 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/bn.c\0" as *const u8
                as *const libc::c_char,
            326 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut width: size_t = (*bn).width as size_t;
    if width > num {
        if bn_fits_in_words(bn, num) == 0 {
            ERR_put_error(
                3 as libc::c_int,
                0 as libc::c_int,
                102 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/bn.c\0"
                    as *const u8 as *const libc::c_char,
                333 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        width = num;
    }
    OPENSSL_memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        (::core::mem::size_of::<BN_ULONG>() as libc::c_ulong).wrapping_mul(num),
    );
    OPENSSL_memcpy(
        out as *mut libc::c_void,
        (*bn).d as *const libc::c_void,
        (::core::mem::size_of::<BN_ULONG>() as libc::c_ulong).wrapping_mul(width),
    );
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_is_negative(mut bn: *const BIGNUM) -> libc::c_int {
    return ((*bn).neg != 0 as libc::c_int) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_set_negative(mut bn: *mut BIGNUM, mut sign: libc::c_int) {
    if sign != 0 && BN_is_zero(bn) == 0 {
        (*bn).neg = 1 as libc::c_int;
    } else {
        (*bn).neg = 0 as libc::c_int;
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_wexpand(
    mut bn: *mut BIGNUM,
    mut words: size_t,
) -> libc::c_int {
    let mut a: *mut BN_ULONG = 0 as *mut BN_ULONG;
    if words <= (*bn).dmax as size_t {
        return 1 as libc::c_int;
    }
    if words
        > (2147483647 as libc::c_int / (4 as libc::c_int * 64 as libc::c_int)) as size_t
    {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/bn.c\0" as *const u8
                as *const libc::c_char,
            364 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*bn).flags & 0x2 as libc::c_int != 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/bn.c\0" as *const u8
                as *const libc::c_char,
            369 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    a = OPENSSL_calloc(words, ::core::mem::size_of::<BN_ULONG>() as libc::c_ulong)
        as *mut BN_ULONG;
    if a.is_null() {
        return 0 as libc::c_int;
    }
    OPENSSL_memcpy(
        a as *mut libc::c_void,
        (*bn).d as *const libc::c_void,
        (::core::mem::size_of::<BN_ULONG>() as libc::c_ulong)
            .wrapping_mul((*bn).width as libc::c_ulong),
    );
    OPENSSL_free((*bn).d as *mut libc::c_void);
    (*bn).d = a;
    (*bn).dmax = words as libc::c_int;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_expand(
    mut bn: *mut BIGNUM,
    mut bits: size_t,
) -> libc::c_int {
    if bits
        .wrapping_add(64 as libc::c_int as size_t)
        .wrapping_sub(1 as libc::c_int as size_t) < bits
    {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/bn.c\0" as *const u8
                as *const libc::c_char,
            389 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return bn_wexpand(
        bn,
        bits
            .wrapping_add(64 as libc::c_int as size_t)
            .wrapping_sub(1 as libc::c_int as size_t) / 64 as libc::c_int as size_t,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_resize_words(
    mut bn: *mut BIGNUM,
    mut words: size_t,
) -> libc::c_int {
    if (*bn).width as size_t <= words {
        if bn_wexpand(bn, words) == 0 {
            return 0 as libc::c_int;
        }
        OPENSSL_memset(
            ((*bn).d).offset((*bn).width as isize) as *mut libc::c_void,
            0 as libc::c_int,
            words
                .wrapping_sub((*bn).width as size_t)
                .wrapping_mul(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
        );
        (*bn).width = words as libc::c_int;
        return 1 as libc::c_int;
    }
    if bn_fits_in_words(bn, words) == 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/bn.c\0" as *const u8
                as *const libc::c_char,
            425 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*bn).width = words as libc::c_int;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_select_words(
    mut r: *mut BN_ULONG,
    mut mask: BN_ULONG,
    mut a: *const BN_ULONG,
    mut b: *const BN_ULONG,
    mut num: size_t,
) {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < num {
        *r
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_minimal_width(mut bn: *const BIGNUM) -> libc::c_int {
    let mut ret: libc::c_int = (*bn).width;
    while ret > 0 as libc::c_int
        && *((*bn).d).offset((ret - 1 as libc::c_int) as isize)
            == 0 as libc::c_int as BN_ULONG
    {
        ret -= 1;
        ret;
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_set_minimal_width(mut bn: *mut BIGNUM) {
    (*bn).width = bn_minimal_width(bn);
    if (*bn).width == 0 as libc::c_int {
        (*bn).neg = 0 as libc::c_int;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_get_flags(
    mut bn: *const BIGNUM,
    mut flags: libc::c_int,
) -> libc::c_int {
    return (*bn).flags & flags;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_set_flags(mut b: *mut BIGNUM, mut n: libc::c_int) {}
