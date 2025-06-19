#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
unsafe extern "C" {
    fn CRYPTO_memcmp(
        a: *const libc::c_void,
        b: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
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
pub struct DES_cblock_st {
    pub bytes: [uint8_t; 8],
}
pub type DES_cblock = DES_cblock_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct DES_ks {
    pub subkeys: [[uint32_t; 2]; 16],
}
pub type DES_key_schedule = DES_ks;
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
#[inline]
unsafe extern "C" fn constant_time_eq_w(
    mut a: crypto_word_t,
    mut b: crypto_word_t,
) -> crypto_word_t {
    return constant_time_is_zero_w(a ^ b);
}
#[inline]
unsafe extern "C" fn constant_time_eq_8(
    mut a: crypto_word_t,
    mut b: crypto_word_t,
) -> uint8_t {
    return constant_time_eq_w(a, b) as uint8_t;
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
unsafe extern "C" fn CRYPTO_load_u32_le(mut in_0: *const libc::c_void) -> uint32_t {
    let mut v: uint32_t = 0;
    OPENSSL_memcpy(
        &mut v as *mut uint32_t as *mut libc::c_void,
        in_0,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
    return v;
}
#[inline]
unsafe extern "C" fn CRYPTO_store_u32_le(mut out: *mut libc::c_void, mut v: uint32_t) {
    OPENSSL_memcpy(
        out,
        &mut v as *mut uint32_t as *const libc::c_void,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
}
#[inline]
unsafe extern "C" fn CRYPTO_rotr_u32(
    mut value: uint32_t,
    mut shift: libc::c_int,
) -> uint32_t {
    return value >> shift | value << (-shift & 31 as libc::c_int);
}
static mut des_skb: [[uint32_t; 64]; 8] = [
    [
        0 as libc::c_int as uint32_t,
        0x10 as libc::c_int as uint32_t,
        0x20000000 as libc::c_int as uint32_t,
        0x20000010 as libc::c_int as uint32_t,
        0x10000 as libc::c_int as uint32_t,
        0x10010 as libc::c_int as uint32_t,
        0x20010000 as libc::c_int as uint32_t,
        0x20010010 as libc::c_int as uint32_t,
        0x800 as libc::c_int as uint32_t,
        0x810 as libc::c_int as uint32_t,
        0x20000800 as libc::c_int as uint32_t,
        0x20000810 as libc::c_int as uint32_t,
        0x10800 as libc::c_int as uint32_t,
        0x10810 as libc::c_int as uint32_t,
        0x20010800 as libc::c_int as uint32_t,
        0x20010810 as libc::c_int as uint32_t,
        0x20 as libc::c_int as uint32_t,
        0x30 as libc::c_int as uint32_t,
        0x20000020 as libc::c_int as uint32_t,
        0x20000030 as libc::c_int as uint32_t,
        0x10020 as libc::c_int as uint32_t,
        0x10030 as libc::c_int as uint32_t,
        0x20010020 as libc::c_int as uint32_t,
        0x20010030 as libc::c_int as uint32_t,
        0x820 as libc::c_int as uint32_t,
        0x830 as libc::c_int as uint32_t,
        0x20000820 as libc::c_int as uint32_t,
        0x20000830 as libc::c_int as uint32_t,
        0x10820 as libc::c_int as uint32_t,
        0x10830 as libc::c_int as uint32_t,
        0x20010820 as libc::c_int as uint32_t,
        0x20010830 as libc::c_int as uint32_t,
        0x80000 as libc::c_int as uint32_t,
        0x80010 as libc::c_int as uint32_t,
        0x20080000 as libc::c_int as uint32_t,
        0x20080010 as libc::c_int as uint32_t,
        0x90000 as libc::c_int as uint32_t,
        0x90010 as libc::c_int as uint32_t,
        0x20090000 as libc::c_int as uint32_t,
        0x20090010 as libc::c_int as uint32_t,
        0x80800 as libc::c_int as uint32_t,
        0x80810 as libc::c_int as uint32_t,
        0x20080800 as libc::c_int as uint32_t,
        0x20080810 as libc::c_int as uint32_t,
        0x90800 as libc::c_int as uint32_t,
        0x90810 as libc::c_int as uint32_t,
        0x20090800 as libc::c_int as uint32_t,
        0x20090810 as libc::c_int as uint32_t,
        0x80020 as libc::c_int as uint32_t,
        0x80030 as libc::c_int as uint32_t,
        0x20080020 as libc::c_int as uint32_t,
        0x20080030 as libc::c_int as uint32_t,
        0x90020 as libc::c_int as uint32_t,
        0x90030 as libc::c_int as uint32_t,
        0x20090020 as libc::c_int as uint32_t,
        0x20090030 as libc::c_int as uint32_t,
        0x80820 as libc::c_int as uint32_t,
        0x80830 as libc::c_int as uint32_t,
        0x20080820 as libc::c_int as uint32_t,
        0x20080830 as libc::c_int as uint32_t,
        0x90820 as libc::c_int as uint32_t,
        0x90830 as libc::c_int as uint32_t,
        0x20090820 as libc::c_int as uint32_t,
        0x20090830 as libc::c_int as uint32_t,
    ],
    [
        0 as libc::c_int as uint32_t,
        0x2000000 as libc::c_int as uint32_t,
        0x2000 as libc::c_int as uint32_t,
        0x2002000 as libc::c_int as uint32_t,
        0x200000 as libc::c_int as uint32_t,
        0x2200000 as libc::c_int as uint32_t,
        0x202000 as libc::c_int as uint32_t,
        0x2202000 as libc::c_int as uint32_t,
        0x4 as libc::c_int as uint32_t,
        0x2000004 as libc::c_int as uint32_t,
        0x2004 as libc::c_int as uint32_t,
        0x2002004 as libc::c_int as uint32_t,
        0x200004 as libc::c_int as uint32_t,
        0x2200004 as libc::c_int as uint32_t,
        0x202004 as libc::c_int as uint32_t,
        0x2202004 as libc::c_int as uint32_t,
        0x400 as libc::c_int as uint32_t,
        0x2000400 as libc::c_int as uint32_t,
        0x2400 as libc::c_int as uint32_t,
        0x2002400 as libc::c_int as uint32_t,
        0x200400 as libc::c_int as uint32_t,
        0x2200400 as libc::c_int as uint32_t,
        0x202400 as libc::c_int as uint32_t,
        0x2202400 as libc::c_int as uint32_t,
        0x404 as libc::c_int as uint32_t,
        0x2000404 as libc::c_int as uint32_t,
        0x2404 as libc::c_int as uint32_t,
        0x2002404 as libc::c_int as uint32_t,
        0x200404 as libc::c_int as uint32_t,
        0x2200404 as libc::c_int as uint32_t,
        0x202404 as libc::c_int as uint32_t,
        0x2202404 as libc::c_int as uint32_t,
        0x10000000 as libc::c_int as uint32_t,
        0x12000000 as libc::c_int as uint32_t,
        0x10002000 as libc::c_int as uint32_t,
        0x12002000 as libc::c_int as uint32_t,
        0x10200000 as libc::c_int as uint32_t,
        0x12200000 as libc::c_int as uint32_t,
        0x10202000 as libc::c_int as uint32_t,
        0x12202000 as libc::c_int as uint32_t,
        0x10000004 as libc::c_int as uint32_t,
        0x12000004 as libc::c_int as uint32_t,
        0x10002004 as libc::c_int as uint32_t,
        0x12002004 as libc::c_int as uint32_t,
        0x10200004 as libc::c_int as uint32_t,
        0x12200004 as libc::c_int as uint32_t,
        0x10202004 as libc::c_int as uint32_t,
        0x12202004 as libc::c_int as uint32_t,
        0x10000400 as libc::c_int as uint32_t,
        0x12000400 as libc::c_int as uint32_t,
        0x10002400 as libc::c_int as uint32_t,
        0x12002400 as libc::c_int as uint32_t,
        0x10200400 as libc::c_int as uint32_t,
        0x12200400 as libc::c_int as uint32_t,
        0x10202400 as libc::c_int as uint32_t,
        0x12202400 as libc::c_int as uint32_t,
        0x10000404 as libc::c_int as uint32_t,
        0x12000404 as libc::c_int as uint32_t,
        0x10002404 as libc::c_int as uint32_t,
        0x12002404 as libc::c_int as uint32_t,
        0x10200404 as libc::c_int as uint32_t,
        0x12200404 as libc::c_int as uint32_t,
        0x10202404 as libc::c_int as uint32_t,
        0x12202404 as libc::c_int as uint32_t,
    ],
    [
        0 as libc::c_int as uint32_t,
        0x1 as libc::c_int as uint32_t,
        0x40000 as libc::c_int as uint32_t,
        0x40001 as libc::c_int as uint32_t,
        0x1000000 as libc::c_int as uint32_t,
        0x1000001 as libc::c_int as uint32_t,
        0x1040000 as libc::c_int as uint32_t,
        0x1040001 as libc::c_int as uint32_t,
        0x2 as libc::c_int as uint32_t,
        0x3 as libc::c_int as uint32_t,
        0x40002 as libc::c_int as uint32_t,
        0x40003 as libc::c_int as uint32_t,
        0x1000002 as libc::c_int as uint32_t,
        0x1000003 as libc::c_int as uint32_t,
        0x1040002 as libc::c_int as uint32_t,
        0x1040003 as libc::c_int as uint32_t,
        0x200 as libc::c_int as uint32_t,
        0x201 as libc::c_int as uint32_t,
        0x40200 as libc::c_int as uint32_t,
        0x40201 as libc::c_int as uint32_t,
        0x1000200 as libc::c_int as uint32_t,
        0x1000201 as libc::c_int as uint32_t,
        0x1040200 as libc::c_int as uint32_t,
        0x1040201 as libc::c_int as uint32_t,
        0x202 as libc::c_int as uint32_t,
        0x203 as libc::c_int as uint32_t,
        0x40202 as libc::c_int as uint32_t,
        0x40203 as libc::c_int as uint32_t,
        0x1000202 as libc::c_int as uint32_t,
        0x1000203 as libc::c_int as uint32_t,
        0x1040202 as libc::c_int as uint32_t,
        0x1040203 as libc::c_int as uint32_t,
        0x8000000 as libc::c_int as uint32_t,
        0x8000001 as libc::c_int as uint32_t,
        0x8040000 as libc::c_int as uint32_t,
        0x8040001 as libc::c_int as uint32_t,
        0x9000000 as libc::c_int as uint32_t,
        0x9000001 as libc::c_int as uint32_t,
        0x9040000 as libc::c_int as uint32_t,
        0x9040001 as libc::c_int as uint32_t,
        0x8000002 as libc::c_int as uint32_t,
        0x8000003 as libc::c_int as uint32_t,
        0x8040002 as libc::c_int as uint32_t,
        0x8040003 as libc::c_int as uint32_t,
        0x9000002 as libc::c_int as uint32_t,
        0x9000003 as libc::c_int as uint32_t,
        0x9040002 as libc::c_int as uint32_t,
        0x9040003 as libc::c_int as uint32_t,
        0x8000200 as libc::c_int as uint32_t,
        0x8000201 as libc::c_int as uint32_t,
        0x8040200 as libc::c_int as uint32_t,
        0x8040201 as libc::c_int as uint32_t,
        0x9000200 as libc::c_int as uint32_t,
        0x9000201 as libc::c_int as uint32_t,
        0x9040200 as libc::c_int as uint32_t,
        0x9040201 as libc::c_int as uint32_t,
        0x8000202 as libc::c_int as uint32_t,
        0x8000203 as libc::c_int as uint32_t,
        0x8040202 as libc::c_int as uint32_t,
        0x8040203 as libc::c_int as uint32_t,
        0x9000202 as libc::c_int as uint32_t,
        0x9000203 as libc::c_int as uint32_t,
        0x9040202 as libc::c_int as uint32_t,
        0x9040203 as libc::c_int as uint32_t,
    ],
    [
        0 as libc::c_int as uint32_t,
        0x100000 as libc::c_int as uint32_t,
        0x100 as libc::c_int as uint32_t,
        0x100100 as libc::c_int as uint32_t,
        0x8 as libc::c_int as uint32_t,
        0x100008 as libc::c_int as uint32_t,
        0x108 as libc::c_int as uint32_t,
        0x100108 as libc::c_int as uint32_t,
        0x1000 as libc::c_int as uint32_t,
        0x101000 as libc::c_int as uint32_t,
        0x1100 as libc::c_int as uint32_t,
        0x101100 as libc::c_int as uint32_t,
        0x1008 as libc::c_int as uint32_t,
        0x101008 as libc::c_int as uint32_t,
        0x1108 as libc::c_int as uint32_t,
        0x101108 as libc::c_int as uint32_t,
        0x4000000 as libc::c_int as uint32_t,
        0x4100000 as libc::c_int as uint32_t,
        0x4000100 as libc::c_int as uint32_t,
        0x4100100 as libc::c_int as uint32_t,
        0x4000008 as libc::c_int as uint32_t,
        0x4100008 as libc::c_int as uint32_t,
        0x4000108 as libc::c_int as uint32_t,
        0x4100108 as libc::c_int as uint32_t,
        0x4001000 as libc::c_int as uint32_t,
        0x4101000 as libc::c_int as uint32_t,
        0x4001100 as libc::c_int as uint32_t,
        0x4101100 as libc::c_int as uint32_t,
        0x4001008 as libc::c_int as uint32_t,
        0x4101008 as libc::c_int as uint32_t,
        0x4001108 as libc::c_int as uint32_t,
        0x4101108 as libc::c_int as uint32_t,
        0x20000 as libc::c_int as uint32_t,
        0x120000 as libc::c_int as uint32_t,
        0x20100 as libc::c_int as uint32_t,
        0x120100 as libc::c_int as uint32_t,
        0x20008 as libc::c_int as uint32_t,
        0x120008 as libc::c_int as uint32_t,
        0x20108 as libc::c_int as uint32_t,
        0x120108 as libc::c_int as uint32_t,
        0x21000 as libc::c_int as uint32_t,
        0x121000 as libc::c_int as uint32_t,
        0x21100 as libc::c_int as uint32_t,
        0x121100 as libc::c_int as uint32_t,
        0x21008 as libc::c_int as uint32_t,
        0x121008 as libc::c_int as uint32_t,
        0x21108 as libc::c_int as uint32_t,
        0x121108 as libc::c_int as uint32_t,
        0x4020000 as libc::c_int as uint32_t,
        0x4120000 as libc::c_int as uint32_t,
        0x4020100 as libc::c_int as uint32_t,
        0x4120100 as libc::c_int as uint32_t,
        0x4020008 as libc::c_int as uint32_t,
        0x4120008 as libc::c_int as uint32_t,
        0x4020108 as libc::c_int as uint32_t,
        0x4120108 as libc::c_int as uint32_t,
        0x4021000 as libc::c_int as uint32_t,
        0x4121000 as libc::c_int as uint32_t,
        0x4021100 as libc::c_int as uint32_t,
        0x4121100 as libc::c_int as uint32_t,
        0x4021008 as libc::c_int as uint32_t,
        0x4121008 as libc::c_int as uint32_t,
        0x4021108 as libc::c_int as uint32_t,
        0x4121108 as libc::c_int as uint32_t,
    ],
    [
        0 as libc::c_int as uint32_t,
        0x10000000 as libc::c_int as uint32_t,
        0x10000 as libc::c_int as uint32_t,
        0x10010000 as libc::c_int as uint32_t,
        0x4 as libc::c_int as uint32_t,
        0x10000004 as libc::c_int as uint32_t,
        0x10004 as libc::c_int as uint32_t,
        0x10010004 as libc::c_int as uint32_t,
        0x20000000 as libc::c_int as uint32_t,
        0x30000000 as libc::c_int as uint32_t,
        0x20010000 as libc::c_int as uint32_t,
        0x30010000 as libc::c_int as uint32_t,
        0x20000004 as libc::c_int as uint32_t,
        0x30000004 as libc::c_int as uint32_t,
        0x20010004 as libc::c_int as uint32_t,
        0x30010004 as libc::c_int as uint32_t,
        0x100000 as libc::c_int as uint32_t,
        0x10100000 as libc::c_int as uint32_t,
        0x110000 as libc::c_int as uint32_t,
        0x10110000 as libc::c_int as uint32_t,
        0x100004 as libc::c_int as uint32_t,
        0x10100004 as libc::c_int as uint32_t,
        0x110004 as libc::c_int as uint32_t,
        0x10110004 as libc::c_int as uint32_t,
        0x20100000 as libc::c_int as uint32_t,
        0x30100000 as libc::c_int as uint32_t,
        0x20110000 as libc::c_int as uint32_t,
        0x30110000 as libc::c_int as uint32_t,
        0x20100004 as libc::c_int as uint32_t,
        0x30100004 as libc::c_int as uint32_t,
        0x20110004 as libc::c_int as uint32_t,
        0x30110004 as libc::c_int as uint32_t,
        0x1000 as libc::c_int as uint32_t,
        0x10001000 as libc::c_int as uint32_t,
        0x11000 as libc::c_int as uint32_t,
        0x10011000 as libc::c_int as uint32_t,
        0x1004 as libc::c_int as uint32_t,
        0x10001004 as libc::c_int as uint32_t,
        0x11004 as libc::c_int as uint32_t,
        0x10011004 as libc::c_int as uint32_t,
        0x20001000 as libc::c_int as uint32_t,
        0x30001000 as libc::c_int as uint32_t,
        0x20011000 as libc::c_int as uint32_t,
        0x30011000 as libc::c_int as uint32_t,
        0x20001004 as libc::c_int as uint32_t,
        0x30001004 as libc::c_int as uint32_t,
        0x20011004 as libc::c_int as uint32_t,
        0x30011004 as libc::c_int as uint32_t,
        0x101000 as libc::c_int as uint32_t,
        0x10101000 as libc::c_int as uint32_t,
        0x111000 as libc::c_int as uint32_t,
        0x10111000 as libc::c_int as uint32_t,
        0x101004 as libc::c_int as uint32_t,
        0x10101004 as libc::c_int as uint32_t,
        0x111004 as libc::c_int as uint32_t,
        0x10111004 as libc::c_int as uint32_t,
        0x20101000 as libc::c_int as uint32_t,
        0x30101000 as libc::c_int as uint32_t,
        0x20111000 as libc::c_int as uint32_t,
        0x30111000 as libc::c_int as uint32_t,
        0x20101004 as libc::c_int as uint32_t,
        0x30101004 as libc::c_int as uint32_t,
        0x20111004 as libc::c_int as uint32_t,
        0x30111004 as libc::c_int as uint32_t,
    ],
    [
        0 as libc::c_int as uint32_t,
        0x8000000 as libc::c_int as uint32_t,
        0x8 as libc::c_int as uint32_t,
        0x8000008 as libc::c_int as uint32_t,
        0x400 as libc::c_int as uint32_t,
        0x8000400 as libc::c_int as uint32_t,
        0x408 as libc::c_int as uint32_t,
        0x8000408 as libc::c_int as uint32_t,
        0x20000 as libc::c_int as uint32_t,
        0x8020000 as libc::c_int as uint32_t,
        0x20008 as libc::c_int as uint32_t,
        0x8020008 as libc::c_int as uint32_t,
        0x20400 as libc::c_int as uint32_t,
        0x8020400 as libc::c_int as uint32_t,
        0x20408 as libc::c_int as uint32_t,
        0x8020408 as libc::c_int as uint32_t,
        0x1 as libc::c_int as uint32_t,
        0x8000001 as libc::c_int as uint32_t,
        0x9 as libc::c_int as uint32_t,
        0x8000009 as libc::c_int as uint32_t,
        0x401 as libc::c_int as uint32_t,
        0x8000401 as libc::c_int as uint32_t,
        0x409 as libc::c_int as uint32_t,
        0x8000409 as libc::c_int as uint32_t,
        0x20001 as libc::c_int as uint32_t,
        0x8020001 as libc::c_int as uint32_t,
        0x20009 as libc::c_int as uint32_t,
        0x8020009 as libc::c_int as uint32_t,
        0x20401 as libc::c_int as uint32_t,
        0x8020401 as libc::c_int as uint32_t,
        0x20409 as libc::c_int as uint32_t,
        0x8020409 as libc::c_int as uint32_t,
        0x2000000 as libc::c_int as uint32_t,
        0xa000000 as libc::c_int as uint32_t,
        0x2000008 as libc::c_int as uint32_t,
        0xa000008 as libc::c_int as uint32_t,
        0x2000400 as libc::c_int as uint32_t,
        0xa000400 as libc::c_int as uint32_t,
        0x2000408 as libc::c_int as uint32_t,
        0xa000408 as libc::c_int as uint32_t,
        0x2020000 as libc::c_int as uint32_t,
        0xa020000 as libc::c_int as uint32_t,
        0x2020008 as libc::c_int as uint32_t,
        0xa020008 as libc::c_int as uint32_t,
        0x2020400 as libc::c_int as uint32_t,
        0xa020400 as libc::c_int as uint32_t,
        0x2020408 as libc::c_int as uint32_t,
        0xa020408 as libc::c_int as uint32_t,
        0x2000001 as libc::c_int as uint32_t,
        0xa000001 as libc::c_int as uint32_t,
        0x2000009 as libc::c_int as uint32_t,
        0xa000009 as libc::c_int as uint32_t,
        0x2000401 as libc::c_int as uint32_t,
        0xa000401 as libc::c_int as uint32_t,
        0x2000409 as libc::c_int as uint32_t,
        0xa000409 as libc::c_int as uint32_t,
        0x2020001 as libc::c_int as uint32_t,
        0xa020001 as libc::c_int as uint32_t,
        0x2020009 as libc::c_int as uint32_t,
        0xa020009 as libc::c_int as uint32_t,
        0x2020401 as libc::c_int as uint32_t,
        0xa020401 as libc::c_int as uint32_t,
        0x2020409 as libc::c_int as uint32_t,
        0xa020409 as libc::c_int as uint32_t,
    ],
    [
        0 as libc::c_int as uint32_t,
        0x100 as libc::c_int as uint32_t,
        0x80000 as libc::c_int as uint32_t,
        0x80100 as libc::c_int as uint32_t,
        0x1000000 as libc::c_int as uint32_t,
        0x1000100 as libc::c_int as uint32_t,
        0x1080000 as libc::c_int as uint32_t,
        0x1080100 as libc::c_int as uint32_t,
        0x10 as libc::c_int as uint32_t,
        0x110 as libc::c_int as uint32_t,
        0x80010 as libc::c_int as uint32_t,
        0x80110 as libc::c_int as uint32_t,
        0x1000010 as libc::c_int as uint32_t,
        0x1000110 as libc::c_int as uint32_t,
        0x1080010 as libc::c_int as uint32_t,
        0x1080110 as libc::c_int as uint32_t,
        0x200000 as libc::c_int as uint32_t,
        0x200100 as libc::c_int as uint32_t,
        0x280000 as libc::c_int as uint32_t,
        0x280100 as libc::c_int as uint32_t,
        0x1200000 as libc::c_int as uint32_t,
        0x1200100 as libc::c_int as uint32_t,
        0x1280000 as libc::c_int as uint32_t,
        0x1280100 as libc::c_int as uint32_t,
        0x200010 as libc::c_int as uint32_t,
        0x200110 as libc::c_int as uint32_t,
        0x280010 as libc::c_int as uint32_t,
        0x280110 as libc::c_int as uint32_t,
        0x1200010 as libc::c_int as uint32_t,
        0x1200110 as libc::c_int as uint32_t,
        0x1280010 as libc::c_int as uint32_t,
        0x1280110 as libc::c_int as uint32_t,
        0x200 as libc::c_int as uint32_t,
        0x300 as libc::c_int as uint32_t,
        0x80200 as libc::c_int as uint32_t,
        0x80300 as libc::c_int as uint32_t,
        0x1000200 as libc::c_int as uint32_t,
        0x1000300 as libc::c_int as uint32_t,
        0x1080200 as libc::c_int as uint32_t,
        0x1080300 as libc::c_int as uint32_t,
        0x210 as libc::c_int as uint32_t,
        0x310 as libc::c_int as uint32_t,
        0x80210 as libc::c_int as uint32_t,
        0x80310 as libc::c_int as uint32_t,
        0x1000210 as libc::c_int as uint32_t,
        0x1000310 as libc::c_int as uint32_t,
        0x1080210 as libc::c_int as uint32_t,
        0x1080310 as libc::c_int as uint32_t,
        0x200200 as libc::c_int as uint32_t,
        0x200300 as libc::c_int as uint32_t,
        0x280200 as libc::c_int as uint32_t,
        0x280300 as libc::c_int as uint32_t,
        0x1200200 as libc::c_int as uint32_t,
        0x1200300 as libc::c_int as uint32_t,
        0x1280200 as libc::c_int as uint32_t,
        0x1280300 as libc::c_int as uint32_t,
        0x200210 as libc::c_int as uint32_t,
        0x200310 as libc::c_int as uint32_t,
        0x280210 as libc::c_int as uint32_t,
        0x280310 as libc::c_int as uint32_t,
        0x1200210 as libc::c_int as uint32_t,
        0x1200310 as libc::c_int as uint32_t,
        0x1280210 as libc::c_int as uint32_t,
        0x1280310 as libc::c_int as uint32_t,
    ],
    [
        0 as libc::c_int as uint32_t,
        0x4000000 as libc::c_int as uint32_t,
        0x40000 as libc::c_int as uint32_t,
        0x4040000 as libc::c_int as uint32_t,
        0x2 as libc::c_int as uint32_t,
        0x4000002 as libc::c_int as uint32_t,
        0x40002 as libc::c_int as uint32_t,
        0x4040002 as libc::c_int as uint32_t,
        0x2000 as libc::c_int as uint32_t,
        0x4002000 as libc::c_int as uint32_t,
        0x42000 as libc::c_int as uint32_t,
        0x4042000 as libc::c_int as uint32_t,
        0x2002 as libc::c_int as uint32_t,
        0x4002002 as libc::c_int as uint32_t,
        0x42002 as libc::c_int as uint32_t,
        0x4042002 as libc::c_int as uint32_t,
        0x20 as libc::c_int as uint32_t,
        0x4000020 as libc::c_int as uint32_t,
        0x40020 as libc::c_int as uint32_t,
        0x4040020 as libc::c_int as uint32_t,
        0x22 as libc::c_int as uint32_t,
        0x4000022 as libc::c_int as uint32_t,
        0x40022 as libc::c_int as uint32_t,
        0x4040022 as libc::c_int as uint32_t,
        0x2020 as libc::c_int as uint32_t,
        0x4002020 as libc::c_int as uint32_t,
        0x42020 as libc::c_int as uint32_t,
        0x4042020 as libc::c_int as uint32_t,
        0x2022 as libc::c_int as uint32_t,
        0x4002022 as libc::c_int as uint32_t,
        0x42022 as libc::c_int as uint32_t,
        0x4042022 as libc::c_int as uint32_t,
        0x800 as libc::c_int as uint32_t,
        0x4000800 as libc::c_int as uint32_t,
        0x40800 as libc::c_int as uint32_t,
        0x4040800 as libc::c_int as uint32_t,
        0x802 as libc::c_int as uint32_t,
        0x4000802 as libc::c_int as uint32_t,
        0x40802 as libc::c_int as uint32_t,
        0x4040802 as libc::c_int as uint32_t,
        0x2800 as libc::c_int as uint32_t,
        0x4002800 as libc::c_int as uint32_t,
        0x42800 as libc::c_int as uint32_t,
        0x4042800 as libc::c_int as uint32_t,
        0x2802 as libc::c_int as uint32_t,
        0x4002802 as libc::c_int as uint32_t,
        0x42802 as libc::c_int as uint32_t,
        0x4042802 as libc::c_int as uint32_t,
        0x820 as libc::c_int as uint32_t,
        0x4000820 as libc::c_int as uint32_t,
        0x40820 as libc::c_int as uint32_t,
        0x4040820 as libc::c_int as uint32_t,
        0x822 as libc::c_int as uint32_t,
        0x4000822 as libc::c_int as uint32_t,
        0x40822 as libc::c_int as uint32_t,
        0x4040822 as libc::c_int as uint32_t,
        0x2820 as libc::c_int as uint32_t,
        0x4002820 as libc::c_int as uint32_t,
        0x42820 as libc::c_int as uint32_t,
        0x4042820 as libc::c_int as uint32_t,
        0x2822 as libc::c_int as uint32_t,
        0x4002822 as libc::c_int as uint32_t,
        0x42822 as libc::c_int as uint32_t,
        0x4042822 as libc::c_int as uint32_t,
    ],
];
static mut DES_SPtrans: [[uint32_t; 64]; 8] = [
    [
        0x2080800 as libc::c_int as uint32_t,
        0x80000 as libc::c_int as uint32_t,
        0x2000002 as libc::c_int as uint32_t,
        0x2080802 as libc::c_int as uint32_t,
        0x2000000 as libc::c_int as uint32_t,
        0x80802 as libc::c_int as uint32_t,
        0x80002 as libc::c_int as uint32_t,
        0x2000002 as libc::c_int as uint32_t,
        0x80802 as libc::c_int as uint32_t,
        0x2080800 as libc::c_int as uint32_t,
        0x2080000 as libc::c_int as uint32_t,
        0x802 as libc::c_int as uint32_t,
        0x2000802 as libc::c_int as uint32_t,
        0x2000000 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x80002 as libc::c_int as uint32_t,
        0x80000 as libc::c_int as uint32_t,
        0x2 as libc::c_int as uint32_t,
        0x2000800 as libc::c_int as uint32_t,
        0x80800 as libc::c_int as uint32_t,
        0x2080802 as libc::c_int as uint32_t,
        0x2080000 as libc::c_int as uint32_t,
        0x802 as libc::c_int as uint32_t,
        0x2000800 as libc::c_int as uint32_t,
        0x2 as libc::c_int as uint32_t,
        0x800 as libc::c_int as uint32_t,
        0x80800 as libc::c_int as uint32_t,
        0x2080002 as libc::c_int as uint32_t,
        0x800 as libc::c_int as uint32_t,
        0x2000802 as libc::c_int as uint32_t,
        0x2080002 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x2080802 as libc::c_int as uint32_t,
        0x2000800 as libc::c_int as uint32_t,
        0x80002 as libc::c_int as uint32_t,
        0x2080800 as libc::c_int as uint32_t,
        0x80000 as libc::c_int as uint32_t,
        0x802 as libc::c_int as uint32_t,
        0x2000800 as libc::c_int as uint32_t,
        0x2080002 as libc::c_int as uint32_t,
        0x800 as libc::c_int as uint32_t,
        0x80800 as libc::c_int as uint32_t,
        0x2000002 as libc::c_int as uint32_t,
        0x80802 as libc::c_int as uint32_t,
        0x2 as libc::c_int as uint32_t,
        0x2000002 as libc::c_int as uint32_t,
        0x2080000 as libc::c_int as uint32_t,
        0x2080802 as libc::c_int as uint32_t,
        0x80800 as libc::c_int as uint32_t,
        0x2080000 as libc::c_int as uint32_t,
        0x2000802 as libc::c_int as uint32_t,
        0x2000000 as libc::c_int as uint32_t,
        0x802 as libc::c_int as uint32_t,
        0x80002 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x80000 as libc::c_int as uint32_t,
        0x2000000 as libc::c_int as uint32_t,
        0x2000802 as libc::c_int as uint32_t,
        0x2080800 as libc::c_int as uint32_t,
        0x2 as libc::c_int as uint32_t,
        0x2080002 as libc::c_int as uint32_t,
        0x800 as libc::c_int as uint32_t,
        0x80802 as libc::c_int as uint32_t,
    ],
    [
        0x40108010 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x108000 as libc::c_int as uint32_t,
        0x40100000 as libc::c_int as uint32_t,
        0x40000010 as libc::c_int as uint32_t,
        0x8010 as libc::c_int as uint32_t,
        0x40008000 as libc::c_int as uint32_t,
        0x108000 as libc::c_int as uint32_t,
        0x8000 as libc::c_int as uint32_t,
        0x40100010 as libc::c_int as uint32_t,
        0x10 as libc::c_int as uint32_t,
        0x40008000 as libc::c_int as uint32_t,
        0x100010 as libc::c_int as uint32_t,
        0x40108000 as libc::c_int as uint32_t,
        0x40100000 as libc::c_int as uint32_t,
        0x10 as libc::c_int as uint32_t,
        0x100000 as libc::c_int as uint32_t,
        0x40008010 as libc::c_int as uint32_t,
        0x40100010 as libc::c_int as uint32_t,
        0x8000 as libc::c_int as uint32_t,
        0x108010 as libc::c_int as uint32_t,
        0x40000000 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x100010 as libc::c_int as uint32_t,
        0x40008010 as libc::c_int as uint32_t,
        0x108010 as libc::c_int as uint32_t,
        0x40108000 as libc::c_int as uint32_t,
        0x40000010 as libc::c_int as uint32_t,
        0x40000000 as libc::c_int as uint32_t,
        0x100000 as libc::c_int as uint32_t,
        0x8010 as libc::c_int as uint32_t,
        0x40108010 as libc::c_int as uint32_t,
        0x100010 as libc::c_int as uint32_t,
        0x40108000 as libc::c_int as uint32_t,
        0x40008000 as libc::c_int as uint32_t,
        0x108010 as libc::c_int as uint32_t,
        0x40108010 as libc::c_int as uint32_t,
        0x100010 as libc::c_int as uint32_t,
        0x40000010 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x40000000 as libc::c_int as uint32_t,
        0x8010 as libc::c_int as uint32_t,
        0x100000 as libc::c_int as uint32_t,
        0x40100010 as libc::c_int as uint32_t,
        0x8000 as libc::c_int as uint32_t,
        0x40000000 as libc::c_int as uint32_t,
        0x108010 as libc::c_int as uint32_t,
        0x40008010 as libc::c_int as uint32_t,
        0x40108000 as libc::c_int as uint32_t,
        0x8000 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x40000010 as libc::c_int as uint32_t,
        0x10 as libc::c_int as uint32_t,
        0x40108010 as libc::c_int as uint32_t,
        0x108000 as libc::c_int as uint32_t,
        0x40100000 as libc::c_int as uint32_t,
        0x40100010 as libc::c_int as uint32_t,
        0x100000 as libc::c_int as uint32_t,
        0x8010 as libc::c_int as uint32_t,
        0x40008000 as libc::c_int as uint32_t,
        0x40008010 as libc::c_int as uint32_t,
        0x10 as libc::c_int as uint32_t,
        0x40100000 as libc::c_int as uint32_t,
        0x108000 as libc::c_int as uint32_t,
    ],
    [
        0x4000001 as libc::c_int as uint32_t,
        0x4040100 as libc::c_int as uint32_t,
        0x100 as libc::c_int as uint32_t,
        0x4000101 as libc::c_int as uint32_t,
        0x40001 as libc::c_int as uint32_t,
        0x4000000 as libc::c_int as uint32_t,
        0x4000101 as libc::c_int as uint32_t,
        0x40100 as libc::c_int as uint32_t,
        0x4000100 as libc::c_int as uint32_t,
        0x40000 as libc::c_int as uint32_t,
        0x4040000 as libc::c_int as uint32_t,
        0x1 as libc::c_int as uint32_t,
        0x4040101 as libc::c_int as uint32_t,
        0x101 as libc::c_int as uint32_t,
        0x1 as libc::c_int as uint32_t,
        0x4040001 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x40001 as libc::c_int as uint32_t,
        0x4040100 as libc::c_int as uint32_t,
        0x100 as libc::c_int as uint32_t,
        0x101 as libc::c_int as uint32_t,
        0x4040101 as libc::c_int as uint32_t,
        0x40000 as libc::c_int as uint32_t,
        0x4000001 as libc::c_int as uint32_t,
        0x4040001 as libc::c_int as uint32_t,
        0x4000100 as libc::c_int as uint32_t,
        0x40101 as libc::c_int as uint32_t,
        0x4040000 as libc::c_int as uint32_t,
        0x40100 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x4000000 as libc::c_int as uint32_t,
        0x40101 as libc::c_int as uint32_t,
        0x4040100 as libc::c_int as uint32_t,
        0x100 as libc::c_int as uint32_t,
        0x1 as libc::c_int as uint32_t,
        0x40000 as libc::c_int as uint32_t,
        0x101 as libc::c_int as uint32_t,
        0x40001 as libc::c_int as uint32_t,
        0x4040000 as libc::c_int as uint32_t,
        0x4000101 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x4040100 as libc::c_int as uint32_t,
        0x40100 as libc::c_int as uint32_t,
        0x4040001 as libc::c_int as uint32_t,
        0x40001 as libc::c_int as uint32_t,
        0x4000000 as libc::c_int as uint32_t,
        0x4040101 as libc::c_int as uint32_t,
        0x1 as libc::c_int as uint32_t,
        0x40101 as libc::c_int as uint32_t,
        0x4000001 as libc::c_int as uint32_t,
        0x4000000 as libc::c_int as uint32_t,
        0x4040101 as libc::c_int as uint32_t,
        0x40000 as libc::c_int as uint32_t,
        0x4000100 as libc::c_int as uint32_t,
        0x4000101 as libc::c_int as uint32_t,
        0x40100 as libc::c_int as uint32_t,
        0x4000100 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x4040001 as libc::c_int as uint32_t,
        0x101 as libc::c_int as uint32_t,
        0x4000001 as libc::c_int as uint32_t,
        0x40101 as libc::c_int as uint32_t,
        0x100 as libc::c_int as uint32_t,
        0x4040000 as libc::c_int as uint32_t,
    ],
    [
        0x401008 as libc::c_int as uint32_t,
        0x10001000 as libc::c_int as uint32_t,
        0x8 as libc::c_int as uint32_t,
        0x10401008 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x10400000 as libc::c_int as uint32_t,
        0x10001008 as libc::c_int as uint32_t,
        0x400008 as libc::c_int as uint32_t,
        0x10401000 as libc::c_int as uint32_t,
        0x10000008 as libc::c_int as uint32_t,
        0x10000000 as libc::c_int as uint32_t,
        0x1008 as libc::c_int as uint32_t,
        0x10000008 as libc::c_int as uint32_t,
        0x401008 as libc::c_int as uint32_t,
        0x400000 as libc::c_int as uint32_t,
        0x10000000 as libc::c_int as uint32_t,
        0x10400008 as libc::c_int as uint32_t,
        0x401000 as libc::c_int as uint32_t,
        0x1000 as libc::c_int as uint32_t,
        0x8 as libc::c_int as uint32_t,
        0x401000 as libc::c_int as uint32_t,
        0x10001008 as libc::c_int as uint32_t,
        0x10400000 as libc::c_int as uint32_t,
        0x1000 as libc::c_int as uint32_t,
        0x1008 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x400008 as libc::c_int as uint32_t,
        0x10401000 as libc::c_int as uint32_t,
        0x10001000 as libc::c_int as uint32_t,
        0x10400008 as libc::c_int as uint32_t,
        0x10401008 as libc::c_int as uint32_t,
        0x400000 as libc::c_int as uint32_t,
        0x10400008 as libc::c_int as uint32_t,
        0x1008 as libc::c_int as uint32_t,
        0x400000 as libc::c_int as uint32_t,
        0x10000008 as libc::c_int as uint32_t,
        0x401000 as libc::c_int as uint32_t,
        0x10001000 as libc::c_int as uint32_t,
        0x8 as libc::c_int as uint32_t,
        0x10400000 as libc::c_int as uint32_t,
        0x10001008 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x1000 as libc::c_int as uint32_t,
        0x400008 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x10400008 as libc::c_int as uint32_t,
        0x10401000 as libc::c_int as uint32_t,
        0x1000 as libc::c_int as uint32_t,
        0x10000000 as libc::c_int as uint32_t,
        0x10401008 as libc::c_int as uint32_t,
        0x401008 as libc::c_int as uint32_t,
        0x400000 as libc::c_int as uint32_t,
        0x10401008 as libc::c_int as uint32_t,
        0x8 as libc::c_int as uint32_t,
        0x10001000 as libc::c_int as uint32_t,
        0x401008 as libc::c_int as uint32_t,
        0x400008 as libc::c_int as uint32_t,
        0x401000 as libc::c_int as uint32_t,
        0x10400000 as libc::c_int as uint32_t,
        0x10001008 as libc::c_int as uint32_t,
        0x1008 as libc::c_int as uint32_t,
        0x10000000 as libc::c_int as uint32_t,
        0x10000008 as libc::c_int as uint32_t,
        0x10401000 as libc::c_int as uint32_t,
    ],
    [
        0x8000000 as libc::c_int as uint32_t,
        0x10000 as libc::c_int as uint32_t,
        0x400 as libc::c_int as uint32_t,
        0x8010420 as libc::c_int as uint32_t,
        0x8010020 as libc::c_int as uint32_t,
        0x8000400 as libc::c_int as uint32_t,
        0x10420 as libc::c_int as uint32_t,
        0x8010000 as libc::c_int as uint32_t,
        0x10000 as libc::c_int as uint32_t,
        0x20 as libc::c_int as uint32_t,
        0x8000020 as libc::c_int as uint32_t,
        0x10400 as libc::c_int as uint32_t,
        0x8000420 as libc::c_int as uint32_t,
        0x8010020 as libc::c_int as uint32_t,
        0x8010400 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x10400 as libc::c_int as uint32_t,
        0x8000000 as libc::c_int as uint32_t,
        0x10020 as libc::c_int as uint32_t,
        0x420 as libc::c_int as uint32_t,
        0x8000400 as libc::c_int as uint32_t,
        0x10420 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x8000020 as libc::c_int as uint32_t,
        0x20 as libc::c_int as uint32_t,
        0x8000420 as libc::c_int as uint32_t,
        0x8010420 as libc::c_int as uint32_t,
        0x10020 as libc::c_int as uint32_t,
        0x8010000 as libc::c_int as uint32_t,
        0x400 as libc::c_int as uint32_t,
        0x420 as libc::c_int as uint32_t,
        0x8010400 as libc::c_int as uint32_t,
        0x8010400 as libc::c_int as uint32_t,
        0x8000420 as libc::c_int as uint32_t,
        0x10020 as libc::c_int as uint32_t,
        0x8010000 as libc::c_int as uint32_t,
        0x10000 as libc::c_int as uint32_t,
        0x20 as libc::c_int as uint32_t,
        0x8000020 as libc::c_int as uint32_t,
        0x8000400 as libc::c_int as uint32_t,
        0x8000000 as libc::c_int as uint32_t,
        0x10400 as libc::c_int as uint32_t,
        0x8010420 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x10420 as libc::c_int as uint32_t,
        0x8000000 as libc::c_int as uint32_t,
        0x400 as libc::c_int as uint32_t,
        0x10020 as libc::c_int as uint32_t,
        0x8000420 as libc::c_int as uint32_t,
        0x400 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x8010420 as libc::c_int as uint32_t,
        0x8010020 as libc::c_int as uint32_t,
        0x8010400 as libc::c_int as uint32_t,
        0x420 as libc::c_int as uint32_t,
        0x10000 as libc::c_int as uint32_t,
        0x10400 as libc::c_int as uint32_t,
        0x8010020 as libc::c_int as uint32_t,
        0x8000400 as libc::c_int as uint32_t,
        0x420 as libc::c_int as uint32_t,
        0x20 as libc::c_int as uint32_t,
        0x10420 as libc::c_int as uint32_t,
        0x8010000 as libc::c_int as uint32_t,
        0x8000020 as libc::c_int as uint32_t,
    ],
    [
        0x80000040 as libc::c_uint,
        0x200040 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x80202000 as libc::c_uint,
        0x200040 as libc::c_int as uint32_t,
        0x2000 as libc::c_int as uint32_t,
        0x80002040 as libc::c_uint,
        0x200000 as libc::c_int as uint32_t,
        0x2040 as libc::c_int as uint32_t,
        0x80202040 as libc::c_uint,
        0x202000 as libc::c_int as uint32_t,
        0x80000000 as libc::c_uint,
        0x80002000 as libc::c_uint,
        0x80000040 as libc::c_uint,
        0x80200000 as libc::c_uint,
        0x202040 as libc::c_int as uint32_t,
        0x200000 as libc::c_int as uint32_t,
        0x80002040 as libc::c_uint,
        0x80200040 as libc::c_uint,
        0 as libc::c_int as uint32_t,
        0x2000 as libc::c_int as uint32_t,
        0x40 as libc::c_int as uint32_t,
        0x80202000 as libc::c_uint,
        0x80200040 as libc::c_uint,
        0x80202040 as libc::c_uint,
        0x80200000 as libc::c_uint,
        0x80000000 as libc::c_uint,
        0x2040 as libc::c_int as uint32_t,
        0x40 as libc::c_int as uint32_t,
        0x202000 as libc::c_int as uint32_t,
        0x202040 as libc::c_int as uint32_t,
        0x80002000 as libc::c_uint,
        0x2040 as libc::c_int as uint32_t,
        0x80000000 as libc::c_uint,
        0x80002000 as libc::c_uint,
        0x202040 as libc::c_int as uint32_t,
        0x80202000 as libc::c_uint,
        0x200040 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x80002000 as libc::c_uint,
        0x80000000 as libc::c_uint,
        0x2000 as libc::c_int as uint32_t,
        0x80200040 as libc::c_uint,
        0x200000 as libc::c_int as uint32_t,
        0x200040 as libc::c_int as uint32_t,
        0x80202040 as libc::c_uint,
        0x202000 as libc::c_int as uint32_t,
        0x40 as libc::c_int as uint32_t,
        0x80202040 as libc::c_uint,
        0x202000 as libc::c_int as uint32_t,
        0x200000 as libc::c_int as uint32_t,
        0x80002040 as libc::c_uint,
        0x80000040 as libc::c_uint,
        0x80200000 as libc::c_uint,
        0x202040 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x2000 as libc::c_int as uint32_t,
        0x80000040 as libc::c_uint,
        0x80002040 as libc::c_uint,
        0x80202000 as libc::c_uint,
        0x80200000 as libc::c_uint,
        0x2040 as libc::c_int as uint32_t,
        0x40 as libc::c_int as uint32_t,
        0x80200040 as libc::c_uint,
    ],
    [
        0x4000 as libc::c_int as uint32_t,
        0x200 as libc::c_int as uint32_t,
        0x1000200 as libc::c_int as uint32_t,
        0x1000004 as libc::c_int as uint32_t,
        0x1004204 as libc::c_int as uint32_t,
        0x4004 as libc::c_int as uint32_t,
        0x4200 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x1000000 as libc::c_int as uint32_t,
        0x1000204 as libc::c_int as uint32_t,
        0x204 as libc::c_int as uint32_t,
        0x1004000 as libc::c_int as uint32_t,
        0x4 as libc::c_int as uint32_t,
        0x1004200 as libc::c_int as uint32_t,
        0x1004000 as libc::c_int as uint32_t,
        0x204 as libc::c_int as uint32_t,
        0x1000204 as libc::c_int as uint32_t,
        0x4000 as libc::c_int as uint32_t,
        0x4004 as libc::c_int as uint32_t,
        0x1004204 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x1000200 as libc::c_int as uint32_t,
        0x1000004 as libc::c_int as uint32_t,
        0x4200 as libc::c_int as uint32_t,
        0x1004004 as libc::c_int as uint32_t,
        0x4204 as libc::c_int as uint32_t,
        0x1004200 as libc::c_int as uint32_t,
        0x4 as libc::c_int as uint32_t,
        0x4204 as libc::c_int as uint32_t,
        0x1004004 as libc::c_int as uint32_t,
        0x200 as libc::c_int as uint32_t,
        0x1000000 as libc::c_int as uint32_t,
        0x4204 as libc::c_int as uint32_t,
        0x1004000 as libc::c_int as uint32_t,
        0x1004004 as libc::c_int as uint32_t,
        0x204 as libc::c_int as uint32_t,
        0x4000 as libc::c_int as uint32_t,
        0x200 as libc::c_int as uint32_t,
        0x1000000 as libc::c_int as uint32_t,
        0x1004004 as libc::c_int as uint32_t,
        0x1000204 as libc::c_int as uint32_t,
        0x4204 as libc::c_int as uint32_t,
        0x4200 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x200 as libc::c_int as uint32_t,
        0x1000004 as libc::c_int as uint32_t,
        0x4 as libc::c_int as uint32_t,
        0x1000200 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x1000204 as libc::c_int as uint32_t,
        0x1000200 as libc::c_int as uint32_t,
        0x4200 as libc::c_int as uint32_t,
        0x204 as libc::c_int as uint32_t,
        0x4000 as libc::c_int as uint32_t,
        0x1004204 as libc::c_int as uint32_t,
        0x1000000 as libc::c_int as uint32_t,
        0x1004200 as libc::c_int as uint32_t,
        0x4 as libc::c_int as uint32_t,
        0x4004 as libc::c_int as uint32_t,
        0x1004204 as libc::c_int as uint32_t,
        0x1000004 as libc::c_int as uint32_t,
        0x1004200 as libc::c_int as uint32_t,
        0x1004000 as libc::c_int as uint32_t,
        0x4004 as libc::c_int as uint32_t,
    ],
    [
        0x20800080 as libc::c_int as uint32_t,
        0x20820000 as libc::c_int as uint32_t,
        0x20080 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x20020000 as libc::c_int as uint32_t,
        0x800080 as libc::c_int as uint32_t,
        0x20800000 as libc::c_int as uint32_t,
        0x20820080 as libc::c_int as uint32_t,
        0x80 as libc::c_int as uint32_t,
        0x20000000 as libc::c_int as uint32_t,
        0x820000 as libc::c_int as uint32_t,
        0x20080 as libc::c_int as uint32_t,
        0x820080 as libc::c_int as uint32_t,
        0x20020080 as libc::c_int as uint32_t,
        0x20000080 as libc::c_int as uint32_t,
        0x20800000 as libc::c_int as uint32_t,
        0x20000 as libc::c_int as uint32_t,
        0x820080 as libc::c_int as uint32_t,
        0x800080 as libc::c_int as uint32_t,
        0x20020000 as libc::c_int as uint32_t,
        0x20820080 as libc::c_int as uint32_t,
        0x20000080 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x820000 as libc::c_int as uint32_t,
        0x20000000 as libc::c_int as uint32_t,
        0x800000 as libc::c_int as uint32_t,
        0x20020080 as libc::c_int as uint32_t,
        0x20800080 as libc::c_int as uint32_t,
        0x800000 as libc::c_int as uint32_t,
        0x20000 as libc::c_int as uint32_t,
        0x20820000 as libc::c_int as uint32_t,
        0x80 as libc::c_int as uint32_t,
        0x800000 as libc::c_int as uint32_t,
        0x20000 as libc::c_int as uint32_t,
        0x20000080 as libc::c_int as uint32_t,
        0x20820080 as libc::c_int as uint32_t,
        0x20080 as libc::c_int as uint32_t,
        0x20000000 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x820000 as libc::c_int as uint32_t,
        0x20800080 as libc::c_int as uint32_t,
        0x20020080 as libc::c_int as uint32_t,
        0x20020000 as libc::c_int as uint32_t,
        0x800080 as libc::c_int as uint32_t,
        0x20820000 as libc::c_int as uint32_t,
        0x80 as libc::c_int as uint32_t,
        0x800080 as libc::c_int as uint32_t,
        0x20020000 as libc::c_int as uint32_t,
        0x20820080 as libc::c_int as uint32_t,
        0x800000 as libc::c_int as uint32_t,
        0x20800000 as libc::c_int as uint32_t,
        0x20000080 as libc::c_int as uint32_t,
        0x820000 as libc::c_int as uint32_t,
        0x20080 as libc::c_int as uint32_t,
        0x20020080 as libc::c_int as uint32_t,
        0x20800000 as libc::c_int as uint32_t,
        0x80 as libc::c_int as uint32_t,
        0x20820000 as libc::c_int as uint32_t,
        0x820080 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        0x20000000 as libc::c_int as uint32_t,
        0x20800080 as libc::c_int as uint32_t,
        0x20000 as libc::c_int as uint32_t,
        0x820080 as libc::c_int as uint32_t,
    ],
];
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DES_set_key_unchecked(
    mut key: *const DES_cblock,
    mut schedule: *mut DES_key_schedule,
) {
    DES_set_key_ex(((*key).bytes).as_ptr(), schedule);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DES_set_key_ex(
    mut key: *const uint8_t,
    mut schedule: *mut DES_key_schedule,
) {
    static mut shifts2: [libc::c_int; 16] = [
        0 as libc::c_int,
        0 as libc::c_int,
        1 as libc::c_int,
        1 as libc::c_int,
        1 as libc::c_int,
        1 as libc::c_int,
        1 as libc::c_int,
        1 as libc::c_int,
        0 as libc::c_int,
        1 as libc::c_int,
        1 as libc::c_int,
        1 as libc::c_int,
        1 as libc::c_int,
        1 as libc::c_int,
        1 as libc::c_int,
        0 as libc::c_int,
    ];
    let mut c: uint32_t = 0;
    let mut d: uint32_t = 0;
    let mut t: uint32_t = 0;
    let mut s: uint32_t = 0;
    let mut t2: uint32_t = 0;
    let mut in_0: *const uint8_t = 0 as *const uint8_t;
    let mut i: libc::c_int = 0;
    in_0 = key;
    let fresh0 = in_0;
    in_0 = in_0.offset(1);
    c = *fresh0 as uint32_t;
    let fresh1 = in_0;
    in_0 = in_0.offset(1);
    c |= (*fresh1 as uint32_t) << 8 as libc::c_long;
    let fresh2 = in_0;
    in_0 = in_0.offset(1);
    c |= (*fresh2 as uint32_t) << 16 as libc::c_long;
    let fresh3 = in_0;
    in_0 = in_0.offset(1);
    c |= (*fresh3 as uint32_t) << 24 as libc::c_long;
    let fresh4 = in_0;
    in_0 = in_0.offset(1);
    d = *fresh4 as uint32_t;
    let fresh5 = in_0;
    in_0 = in_0.offset(1);
    d |= (*fresh5 as uint32_t) << 8 as libc::c_long;
    let fresh6 = in_0;
    in_0 = in_0.offset(1);
    d |= (*fresh6 as uint32_t) << 16 as libc::c_long;
    let fresh7 = in_0;
    in_0 = in_0.offset(1);
    d |= (*fresh7 as uint32_t) << 24 as libc::c_long;
    t = (d >> 4 as libc::c_int ^ c) & 0xf0f0f0f as libc::c_int as uint32_t;
    c ^= t;
    d ^= t << 4 as libc::c_int;
    t = (c << 16 as libc::c_int - -(2 as libc::c_int) ^ c) & 0xcccc0000 as libc::c_uint;
    c = c ^ t ^ t >> 16 as libc::c_int - -(2 as libc::c_int);
    t = (d << 16 as libc::c_int - -(2 as libc::c_int) ^ d) & 0xcccc0000 as libc::c_uint;
    d = d ^ t ^ t >> 16 as libc::c_int - -(2 as libc::c_int);
    t = (d >> 1 as libc::c_int ^ c) & 0x55555555 as libc::c_int as uint32_t;
    c ^= t;
    d ^= t << 1 as libc::c_int;
    t = (c >> 8 as libc::c_int ^ d) & 0xff00ff as libc::c_int as uint32_t;
    d ^= t;
    c ^= t << 8 as libc::c_int;
    t = (d >> 1 as libc::c_int ^ c) & 0x55555555 as libc::c_int as uint32_t;
    c ^= t;
    d ^= t << 1 as libc::c_int;
    d = (d & 0xff as libc::c_int as uint32_t) << 16 as libc::c_int
        | d & 0xff00 as libc::c_int as uint32_t
        | (d & 0xff0000 as libc::c_int as uint32_t) >> 16 as libc::c_int
        | (c & 0xf0000000 as libc::c_uint) >> 4 as libc::c_int;
    c &= 0xfffffff as libc::c_int as uint32_t;
    i = 0 as libc::c_int;
    while i < 16 as libc::c_int {
        if shifts2[i as usize] != 0 {
            c = c >> 2 as libc::c_int | c << 26 as libc::c_int;
            d = d >> 2 as libc::c_int | d << 26 as libc::c_int;
        } else {
            c = c >> 1 as libc::c_int | c << 27 as libc::c_int;
            d = d >> 1 as libc::c_int | d << 27 as libc::c_int;
        }
        c &= 0xfffffff as libc::c_int as uint32_t;
        d &= 0xfffffff as libc::c_int as uint32_t;
        s = des_skb[0 as libc::c_int
            as usize][(c & 0x3f as libc::c_int as uint32_t) as usize]
            | des_skb[1 as libc::c_int
                as usize][(c >> 6 as libc::c_int & 0x3 as libc::c_int as uint32_t
                | c >> 7 as libc::c_int & 0x3c as libc::c_int as uint32_t) as usize]
            | des_skb[2 as libc::c_int
                as usize][(c >> 13 as libc::c_int & 0xf as libc::c_int as uint32_t
                | c >> 14 as libc::c_int & 0x30 as libc::c_int as uint32_t) as usize]
            | des_skb[3 as libc::c_int
                as usize][(c >> 20 as libc::c_int & 0x1 as libc::c_int as uint32_t
                | c >> 21 as libc::c_int & 0x6 as libc::c_int as uint32_t
                | c >> 22 as libc::c_int & 0x38 as libc::c_int as uint32_t) as usize];
        t = des_skb[4 as libc::c_int
            as usize][(d & 0x3f as libc::c_int as uint32_t) as usize]
            | des_skb[5 as libc::c_int
                as usize][(d >> 7 as libc::c_int & 0x3 as libc::c_int as uint32_t
                | d >> 8 as libc::c_int & 0x3c as libc::c_int as uint32_t) as usize]
            | des_skb[6 as libc::c_int
                as usize][(d >> 15 as libc::c_int & 0x3f as libc::c_int as uint32_t)
                as usize]
            | des_skb[7 as libc::c_int
                as usize][(d >> 21 as libc::c_int & 0xf as libc::c_int as uint32_t
                | d >> 22 as libc::c_int & 0x30 as libc::c_int as uint32_t) as usize];
        t2 = (t << 16 as libc::c_int | s & 0xffff as libc::c_int as uint32_t)
            & 0xffffffff as libc::c_uint;
        (*schedule)
            .subkeys[i
            as usize][0 as libc::c_int
            as usize] = CRYPTO_rotr_u32(t2, 30 as libc::c_int);
        t2 = s >> 16 as libc::c_int | t & 0xffff0000 as libc::c_uint;
        (*schedule)
            .subkeys[i
            as usize][1 as libc::c_int
            as usize] = CRYPTO_rotr_u32(t2, 26 as libc::c_int);
        i += 1;
        i;
    }
}
unsafe extern "C" fn DES_check_key_parity(mut key: *const DES_cblock) -> libc::c_int {
    let mut result: uint8_t = 255 as libc::c_int as uint8_t;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < ::core::mem::size_of::<DES_cblock>() as libc::c_ulong {
        let mut b: uint8_t = (*key).bytes[i as usize];
        b = (b as libc::c_int ^ b as libc::c_int >> 4 as libc::c_int) as uint8_t;
        b = (b as libc::c_int ^ b as libc::c_int >> 2 as libc::c_int) as uint8_t;
        b = (b as libc::c_int ^ b as libc::c_int >> 1 as libc::c_int) as uint8_t;
        result = (result as libc::c_int
            & constant_time_eq_8(
                (b as libc::c_int & 1 as libc::c_int) as crypto_word_t,
                1 as libc::c_int as crypto_word_t,
            ) as libc::c_int) as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
    return result as libc::c_int & 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DES_set_key(
    mut key: *const DES_cblock,
    mut schedule: *mut DES_key_schedule,
) -> libc::c_int {
    let mut result: libc::c_int = 0 as libc::c_int;
    if DES_check_key_parity(key) == 0 {
        result = -(1 as libc::c_int);
    }
    if DES_is_weak_key(key) != 0 {
        result = -(2 as libc::c_int);
    }
    DES_set_key_unchecked(key, schedule);
    return result;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DES_key_sched(
    mut key: *const DES_cblock,
    mut schedule: *mut DES_key_schedule,
) -> libc::c_int {
    return DES_set_key(key, schedule);
}
static mut kOddParity: [uint8_t; 256] = [
    1 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
    7 as libc::c_int as uint8_t,
    7 as libc::c_int as uint8_t,
    8 as libc::c_int as uint8_t,
    8 as libc::c_int as uint8_t,
    11 as libc::c_int as uint8_t,
    11 as libc::c_int as uint8_t,
    13 as libc::c_int as uint8_t,
    13 as libc::c_int as uint8_t,
    14 as libc::c_int as uint8_t,
    14 as libc::c_int as uint8_t,
    16 as libc::c_int as uint8_t,
    16 as libc::c_int as uint8_t,
    19 as libc::c_int as uint8_t,
    19 as libc::c_int as uint8_t,
    21 as libc::c_int as uint8_t,
    21 as libc::c_int as uint8_t,
    22 as libc::c_int as uint8_t,
    22 as libc::c_int as uint8_t,
    25 as libc::c_int as uint8_t,
    25 as libc::c_int as uint8_t,
    26 as libc::c_int as uint8_t,
    26 as libc::c_int as uint8_t,
    28 as libc::c_int as uint8_t,
    28 as libc::c_int as uint8_t,
    31 as libc::c_int as uint8_t,
    31 as libc::c_int as uint8_t,
    32 as libc::c_int as uint8_t,
    32 as libc::c_int as uint8_t,
    35 as libc::c_int as uint8_t,
    35 as libc::c_int as uint8_t,
    37 as libc::c_int as uint8_t,
    37 as libc::c_int as uint8_t,
    38 as libc::c_int as uint8_t,
    38 as libc::c_int as uint8_t,
    41 as libc::c_int as uint8_t,
    41 as libc::c_int as uint8_t,
    42 as libc::c_int as uint8_t,
    42 as libc::c_int as uint8_t,
    44 as libc::c_int as uint8_t,
    44 as libc::c_int as uint8_t,
    47 as libc::c_int as uint8_t,
    47 as libc::c_int as uint8_t,
    49 as libc::c_int as uint8_t,
    49 as libc::c_int as uint8_t,
    50 as libc::c_int as uint8_t,
    50 as libc::c_int as uint8_t,
    52 as libc::c_int as uint8_t,
    52 as libc::c_int as uint8_t,
    55 as libc::c_int as uint8_t,
    55 as libc::c_int as uint8_t,
    56 as libc::c_int as uint8_t,
    56 as libc::c_int as uint8_t,
    59 as libc::c_int as uint8_t,
    59 as libc::c_int as uint8_t,
    61 as libc::c_int as uint8_t,
    61 as libc::c_int as uint8_t,
    62 as libc::c_int as uint8_t,
    62 as libc::c_int as uint8_t,
    64 as libc::c_int as uint8_t,
    64 as libc::c_int as uint8_t,
    67 as libc::c_int as uint8_t,
    67 as libc::c_int as uint8_t,
    69 as libc::c_int as uint8_t,
    69 as libc::c_int as uint8_t,
    70 as libc::c_int as uint8_t,
    70 as libc::c_int as uint8_t,
    73 as libc::c_int as uint8_t,
    73 as libc::c_int as uint8_t,
    74 as libc::c_int as uint8_t,
    74 as libc::c_int as uint8_t,
    76 as libc::c_int as uint8_t,
    76 as libc::c_int as uint8_t,
    79 as libc::c_int as uint8_t,
    79 as libc::c_int as uint8_t,
    81 as libc::c_int as uint8_t,
    81 as libc::c_int as uint8_t,
    82 as libc::c_int as uint8_t,
    82 as libc::c_int as uint8_t,
    84 as libc::c_int as uint8_t,
    84 as libc::c_int as uint8_t,
    87 as libc::c_int as uint8_t,
    87 as libc::c_int as uint8_t,
    88 as libc::c_int as uint8_t,
    88 as libc::c_int as uint8_t,
    91 as libc::c_int as uint8_t,
    91 as libc::c_int as uint8_t,
    93 as libc::c_int as uint8_t,
    93 as libc::c_int as uint8_t,
    94 as libc::c_int as uint8_t,
    94 as libc::c_int as uint8_t,
    97 as libc::c_int as uint8_t,
    97 as libc::c_int as uint8_t,
    98 as libc::c_int as uint8_t,
    98 as libc::c_int as uint8_t,
    100 as libc::c_int as uint8_t,
    100 as libc::c_int as uint8_t,
    103 as libc::c_int as uint8_t,
    103 as libc::c_int as uint8_t,
    104 as libc::c_int as uint8_t,
    104 as libc::c_int as uint8_t,
    107 as libc::c_int as uint8_t,
    107 as libc::c_int as uint8_t,
    109 as libc::c_int as uint8_t,
    109 as libc::c_int as uint8_t,
    110 as libc::c_int as uint8_t,
    110 as libc::c_int as uint8_t,
    112 as libc::c_int as uint8_t,
    112 as libc::c_int as uint8_t,
    115 as libc::c_int as uint8_t,
    115 as libc::c_int as uint8_t,
    117 as libc::c_int as uint8_t,
    117 as libc::c_int as uint8_t,
    118 as libc::c_int as uint8_t,
    118 as libc::c_int as uint8_t,
    121 as libc::c_int as uint8_t,
    121 as libc::c_int as uint8_t,
    122 as libc::c_int as uint8_t,
    122 as libc::c_int as uint8_t,
    124 as libc::c_int as uint8_t,
    124 as libc::c_int as uint8_t,
    127 as libc::c_int as uint8_t,
    127 as libc::c_int as uint8_t,
    128 as libc::c_int as uint8_t,
    128 as libc::c_int as uint8_t,
    131 as libc::c_int as uint8_t,
    131 as libc::c_int as uint8_t,
    133 as libc::c_int as uint8_t,
    133 as libc::c_int as uint8_t,
    134 as libc::c_int as uint8_t,
    134 as libc::c_int as uint8_t,
    137 as libc::c_int as uint8_t,
    137 as libc::c_int as uint8_t,
    138 as libc::c_int as uint8_t,
    138 as libc::c_int as uint8_t,
    140 as libc::c_int as uint8_t,
    140 as libc::c_int as uint8_t,
    143 as libc::c_int as uint8_t,
    143 as libc::c_int as uint8_t,
    145 as libc::c_int as uint8_t,
    145 as libc::c_int as uint8_t,
    146 as libc::c_int as uint8_t,
    146 as libc::c_int as uint8_t,
    148 as libc::c_int as uint8_t,
    148 as libc::c_int as uint8_t,
    151 as libc::c_int as uint8_t,
    151 as libc::c_int as uint8_t,
    152 as libc::c_int as uint8_t,
    152 as libc::c_int as uint8_t,
    155 as libc::c_int as uint8_t,
    155 as libc::c_int as uint8_t,
    157 as libc::c_int as uint8_t,
    157 as libc::c_int as uint8_t,
    158 as libc::c_int as uint8_t,
    158 as libc::c_int as uint8_t,
    161 as libc::c_int as uint8_t,
    161 as libc::c_int as uint8_t,
    162 as libc::c_int as uint8_t,
    162 as libc::c_int as uint8_t,
    164 as libc::c_int as uint8_t,
    164 as libc::c_int as uint8_t,
    167 as libc::c_int as uint8_t,
    167 as libc::c_int as uint8_t,
    168 as libc::c_int as uint8_t,
    168 as libc::c_int as uint8_t,
    171 as libc::c_int as uint8_t,
    171 as libc::c_int as uint8_t,
    173 as libc::c_int as uint8_t,
    173 as libc::c_int as uint8_t,
    174 as libc::c_int as uint8_t,
    174 as libc::c_int as uint8_t,
    176 as libc::c_int as uint8_t,
    176 as libc::c_int as uint8_t,
    179 as libc::c_int as uint8_t,
    179 as libc::c_int as uint8_t,
    181 as libc::c_int as uint8_t,
    181 as libc::c_int as uint8_t,
    182 as libc::c_int as uint8_t,
    182 as libc::c_int as uint8_t,
    185 as libc::c_int as uint8_t,
    185 as libc::c_int as uint8_t,
    186 as libc::c_int as uint8_t,
    186 as libc::c_int as uint8_t,
    188 as libc::c_int as uint8_t,
    188 as libc::c_int as uint8_t,
    191 as libc::c_int as uint8_t,
    191 as libc::c_int as uint8_t,
    193 as libc::c_int as uint8_t,
    193 as libc::c_int as uint8_t,
    194 as libc::c_int as uint8_t,
    194 as libc::c_int as uint8_t,
    196 as libc::c_int as uint8_t,
    196 as libc::c_int as uint8_t,
    199 as libc::c_int as uint8_t,
    199 as libc::c_int as uint8_t,
    200 as libc::c_int as uint8_t,
    200 as libc::c_int as uint8_t,
    203 as libc::c_int as uint8_t,
    203 as libc::c_int as uint8_t,
    205 as libc::c_int as uint8_t,
    205 as libc::c_int as uint8_t,
    206 as libc::c_int as uint8_t,
    206 as libc::c_int as uint8_t,
    208 as libc::c_int as uint8_t,
    208 as libc::c_int as uint8_t,
    211 as libc::c_int as uint8_t,
    211 as libc::c_int as uint8_t,
    213 as libc::c_int as uint8_t,
    213 as libc::c_int as uint8_t,
    214 as libc::c_int as uint8_t,
    214 as libc::c_int as uint8_t,
    217 as libc::c_int as uint8_t,
    217 as libc::c_int as uint8_t,
    218 as libc::c_int as uint8_t,
    218 as libc::c_int as uint8_t,
    220 as libc::c_int as uint8_t,
    220 as libc::c_int as uint8_t,
    223 as libc::c_int as uint8_t,
    223 as libc::c_int as uint8_t,
    224 as libc::c_int as uint8_t,
    224 as libc::c_int as uint8_t,
    227 as libc::c_int as uint8_t,
    227 as libc::c_int as uint8_t,
    229 as libc::c_int as uint8_t,
    229 as libc::c_int as uint8_t,
    230 as libc::c_int as uint8_t,
    230 as libc::c_int as uint8_t,
    233 as libc::c_int as uint8_t,
    233 as libc::c_int as uint8_t,
    234 as libc::c_int as uint8_t,
    234 as libc::c_int as uint8_t,
    236 as libc::c_int as uint8_t,
    236 as libc::c_int as uint8_t,
    239 as libc::c_int as uint8_t,
    239 as libc::c_int as uint8_t,
    241 as libc::c_int as uint8_t,
    241 as libc::c_int as uint8_t,
    242 as libc::c_int as uint8_t,
    242 as libc::c_int as uint8_t,
    244 as libc::c_int as uint8_t,
    244 as libc::c_int as uint8_t,
    247 as libc::c_int as uint8_t,
    247 as libc::c_int as uint8_t,
    248 as libc::c_int as uint8_t,
    248 as libc::c_int as uint8_t,
    251 as libc::c_int as uint8_t,
    251 as libc::c_int as uint8_t,
    253 as libc::c_int as uint8_t,
    253 as libc::c_int as uint8_t,
    254 as libc::c_int as uint8_t,
    254 as libc::c_int as uint8_t,
];
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DES_set_odd_parity(mut key: *mut DES_cblock) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong) < ::core::mem::size_of::<DES_cblock>() as libc::c_ulong {
        (*key).bytes[i as usize] = kOddParity[(*key).bytes[i as usize] as usize];
        i = i.wrapping_add(1);
        i;
    }
}
static mut weak_keys: [DES_cblock; 16] = [
    {
        let mut init = DES_cblock_st {
            bytes: [
                0x1 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
            ],
        };
        init
    },
    {
        let mut init = DES_cblock_st {
            bytes: [
                0xfe as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
            ],
        };
        init
    },
    {
        let mut init = DES_cblock_st {
            bytes: [
                0x1f as libc::c_int as uint8_t,
                0x1f as libc::c_int as uint8_t,
                0x1f as libc::c_int as uint8_t,
                0x1f as libc::c_int as uint8_t,
                0xe as libc::c_int as uint8_t,
                0xe as libc::c_int as uint8_t,
                0xe as libc::c_int as uint8_t,
                0xe as libc::c_int as uint8_t,
            ],
        };
        init
    },
    {
        let mut init = DES_cblock_st {
            bytes: [
                0xe0 as libc::c_int as uint8_t,
                0xe0 as libc::c_int as uint8_t,
                0xe0 as libc::c_int as uint8_t,
                0xe0 as libc::c_int as uint8_t,
                0xf1 as libc::c_int as uint8_t,
                0xf1 as libc::c_int as uint8_t,
                0xf1 as libc::c_int as uint8_t,
                0xf1 as libc::c_int as uint8_t,
            ],
        };
        init
    },
    {
        let mut init = DES_cblock_st {
            bytes: [
                0x1 as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
            ],
        };
        init
    },
    {
        let mut init = DES_cblock_st {
            bytes: [
                0xfe as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
            ],
        };
        init
    },
    {
        let mut init = DES_cblock_st {
            bytes: [
                0x1f as libc::c_int as uint8_t,
                0xe0 as libc::c_int as uint8_t,
                0x1f as libc::c_int as uint8_t,
                0xe0 as libc::c_int as uint8_t,
                0xe as libc::c_int as uint8_t,
                0xf1 as libc::c_int as uint8_t,
                0xe as libc::c_int as uint8_t,
                0xf1 as libc::c_int as uint8_t,
            ],
        };
        init
    },
    {
        let mut init = DES_cblock_st {
            bytes: [
                0xe0 as libc::c_int as uint8_t,
                0x1f as libc::c_int as uint8_t,
                0xe0 as libc::c_int as uint8_t,
                0x1f as libc::c_int as uint8_t,
                0xf1 as libc::c_int as uint8_t,
                0xe as libc::c_int as uint8_t,
                0xf1 as libc::c_int as uint8_t,
                0xe as libc::c_int as uint8_t,
            ],
        };
        init
    },
    {
        let mut init = DES_cblock_st {
            bytes: [
                0x1 as libc::c_int as uint8_t,
                0xe0 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0xe0 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0xf1 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0xf1 as libc::c_int as uint8_t,
            ],
        };
        init
    },
    {
        let mut init = DES_cblock_st {
            bytes: [
                0xe0 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0xe0 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0xf1 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0xf1 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
            ],
        };
        init
    },
    {
        let mut init = DES_cblock_st {
            bytes: [
                0x1f as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
                0x1f as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
                0xe as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
                0xe as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
            ],
        };
        init
    },
    {
        let mut init = DES_cblock_st {
            bytes: [
                0xfe as libc::c_int as uint8_t,
                0x1f as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
                0x1f as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
                0xe as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
                0xe as libc::c_int as uint8_t,
            ],
        };
        init
    },
    {
        let mut init = DES_cblock_st {
            bytes: [
                0x1 as libc::c_int as uint8_t,
                0x1f as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x1f as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0xe as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0xe as libc::c_int as uint8_t,
            ],
        };
        init
    },
    {
        let mut init = DES_cblock_st {
            bytes: [
                0x1f as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x1f as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0xe as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0xe as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
            ],
        };
        init
    },
    {
        let mut init = DES_cblock_st {
            bytes: [
                0xe0 as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
                0xe0 as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
                0xf1 as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
                0xf1 as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
            ],
        };
        init
    },
    {
        let mut init = DES_cblock_st {
            bytes: [
                0xfe as libc::c_int as uint8_t,
                0xe0 as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
                0xe0 as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
                0xf1 as libc::c_int as uint8_t,
                0xfe as libc::c_int as uint8_t,
                0xf1 as libc::c_int as uint8_t,
            ],
        };
        init
    },
];
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DES_is_weak_key(mut key: *const DES_cblock) -> libc::c_int {
    let mut result: crypto_word_t = 0 as libc::c_int as crypto_word_t;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (::core::mem::size_of::<[DES_cblock; 16]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<DES_cblock>() as libc::c_ulong)
    {
        let mut match_0: libc::c_int = CRYPTO_memcmp(
            &*weak_keys.as_ptr().offset(i as isize) as *const DES_cblock
                as *const libc::c_void,
            key as *const libc::c_void,
            ::core::mem::size_of::<DES_cblock>() as libc::c_ulong,
        );
        result |= constant_time_is_zero_w(match_0 as crypto_word_t);
        i = i.wrapping_add(1);
        i;
    }
    return (result & 1 as libc::c_int as crypto_word_t) as libc::c_int;
}
unsafe extern "C" fn DES_encrypt1(
    mut data: *mut uint32_t,
    mut ks: *const DES_key_schedule,
    mut enc: libc::c_int,
) {
    let mut l: uint32_t = 0;
    let mut r: uint32_t = 0;
    let mut t: uint32_t = 0;
    let mut u: uint32_t = 0;
    r = *data.offset(0 as libc::c_int as isize);
    l = *data.offset(1 as libc::c_int as isize);
    let mut tt: uint32_t = 0;
    tt = ((l >> 4 as libc::c_int ^ r) as libc::c_long & 0xf0f0f0f as libc::c_long)
        as uint32_t;
    r ^= tt;
    l ^= tt << 4 as libc::c_int;
    tt = ((r >> 16 as libc::c_int ^ l) as libc::c_long & 0xffff as libc::c_long)
        as uint32_t;
    l ^= tt;
    r ^= tt << 16 as libc::c_int;
    tt = ((l >> 2 as libc::c_int ^ r) as libc::c_long & 0x33333333 as libc::c_long)
        as uint32_t;
    r ^= tt;
    l ^= tt << 2 as libc::c_int;
    tt = ((r >> 8 as libc::c_int ^ l) as libc::c_long & 0xff00ff as libc::c_long)
        as uint32_t;
    l ^= tt;
    r ^= tt << 8 as libc::c_int;
    tt = ((l >> 1 as libc::c_int ^ r) as libc::c_long & 0x55555555 as libc::c_long)
        as uint32_t;
    r ^= tt;
    l ^= tt << 1 as libc::c_int;
    r = CRYPTO_rotr_u32(r, 29 as libc::c_int);
    l = CRYPTO_rotr_u32(l, 29 as libc::c_int);
    if enc != 0 {
        u = r ^ (*ks).subkeys[0 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[0 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[1 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[1 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[2 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[2 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[3 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[3 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[4 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[4 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[5 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[5 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[6 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[6 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[7 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[7 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[8 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[8 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[9 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[9 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[10 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[10 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[11 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[11 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[12 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[12 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[13 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[13 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[14 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[14 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[15 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[15 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
    } else {
        u = r ^ (*ks).subkeys[15 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[15 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[14 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[14 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[13 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[13 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[12 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[12 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[11 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[11 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[10 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[10 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[9 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[9 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[8 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[8 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[7 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[7 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[6 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[6 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[5 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[5 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[4 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[4 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[3 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[3 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[2 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[2 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[1 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[1 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[0 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[0 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
    }
    l = CRYPTO_rotr_u32(l, 3 as libc::c_int);
    r = CRYPTO_rotr_u32(r, 3 as libc::c_int);
    let mut tt_0: uint32_t = 0;
    tt_0 = ((r >> 1 as libc::c_int ^ l) as libc::c_long & 0x55555555 as libc::c_long)
        as uint32_t;
    l ^= tt_0;
    r ^= tt_0 << 1 as libc::c_int;
    tt_0 = ((l >> 8 as libc::c_int ^ r) as libc::c_long & 0xff00ff as libc::c_long)
        as uint32_t;
    r ^= tt_0;
    l ^= tt_0 << 8 as libc::c_int;
    tt_0 = ((r >> 2 as libc::c_int ^ l) as libc::c_long & 0x33333333 as libc::c_long)
        as uint32_t;
    l ^= tt_0;
    r ^= tt_0 << 2 as libc::c_int;
    tt_0 = ((l >> 16 as libc::c_int ^ r) as libc::c_long & 0xffff as libc::c_long)
        as uint32_t;
    r ^= tt_0;
    l ^= tt_0 << 16 as libc::c_int;
    tt_0 = ((r >> 4 as libc::c_int ^ l) as libc::c_long & 0xf0f0f0f as libc::c_long)
        as uint32_t;
    l ^= tt_0;
    r ^= tt_0 << 4 as libc::c_int;
    *data.offset(0 as libc::c_int as isize) = l;
    *data.offset(1 as libc::c_int as isize) = r;
}
unsafe extern "C" fn DES_encrypt2(
    mut data: *mut uint32_t,
    mut ks: *const DES_key_schedule,
    mut enc: libc::c_int,
) {
    let mut l: uint32_t = 0;
    let mut r: uint32_t = 0;
    let mut t: uint32_t = 0;
    let mut u: uint32_t = 0;
    r = *data.offset(0 as libc::c_int as isize);
    l = *data.offset(1 as libc::c_int as isize);
    r = CRYPTO_rotr_u32(r, 29 as libc::c_int);
    l = CRYPTO_rotr_u32(l, 29 as libc::c_int);
    if enc != 0 {
        u = r ^ (*ks).subkeys[0 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[0 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[1 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[1 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[2 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[2 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[3 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[3 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[4 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[4 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[5 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[5 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[6 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[6 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[7 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[7 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[8 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[8 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[9 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[9 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[10 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[10 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[11 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[11 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[12 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[12 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[13 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[13 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[14 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[14 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[15 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[15 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
    } else {
        u = r ^ (*ks).subkeys[15 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[15 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[14 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[14 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[13 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[13 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[12 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[12 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[11 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[11 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[10 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[10 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[9 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[9 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[8 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[8 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[7 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[7 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[6 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[6 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[5 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[5 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[4 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[4 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[3 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[3 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[2 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[2 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = r ^ (*ks).subkeys[1 as libc::c_int as usize][0 as libc::c_int as usize];
        t = r ^ (*ks).subkeys[1 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        l
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
        u = l ^ (*ks).subkeys[0 as libc::c_int as usize][0 as libc::c_int as usize];
        t = l ^ (*ks).subkeys[0 as libc::c_int as usize][1 as libc::c_int as usize];
        t = CRYPTO_rotr_u32(t, 4 as libc::c_int);
        r
            ^= DES_SPtrans[0 as libc::c_int
                as usize][(u >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                as usize]
                ^ DES_SPtrans[2 as libc::c_int
                    as usize][(u >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[4 as libc::c_int
                    as usize][(u >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[6 as libc::c_int
                    as usize][(u >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[1 as libc::c_int
                    as usize][(t >> 2 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[3 as libc::c_int
                    as usize][(t >> 10 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[5 as libc::c_int
                    as usize][(t >> 18 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize]
                ^ DES_SPtrans[7 as libc::c_int
                    as usize][(t >> 26 as libc::c_long & 0x3f as libc::c_int as uint32_t)
                    as usize];
    }
    *data.offset(0 as libc::c_int as isize) = CRYPTO_rotr_u32(l, 3 as libc::c_int);
    *data.offset(1 as libc::c_int as isize) = CRYPTO_rotr_u32(r, 3 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DES_encrypt3(
    mut data: *mut uint32_t,
    mut ks1: *const DES_key_schedule,
    mut ks2: *const DES_key_schedule,
    mut ks3: *const DES_key_schedule,
) {
    let mut l: uint32_t = 0;
    let mut r: uint32_t = 0;
    l = *data.offset(0 as libc::c_int as isize);
    r = *data.offset(1 as libc::c_int as isize);
    let mut tt: uint32_t = 0;
    tt = ((r >> 4 as libc::c_int ^ l) as libc::c_long & 0xf0f0f0f as libc::c_long)
        as uint32_t;
    l ^= tt;
    r ^= tt << 4 as libc::c_int;
    tt = ((l >> 16 as libc::c_int ^ r) as libc::c_long & 0xffff as libc::c_long)
        as uint32_t;
    r ^= tt;
    l ^= tt << 16 as libc::c_int;
    tt = ((r >> 2 as libc::c_int ^ l) as libc::c_long & 0x33333333 as libc::c_long)
        as uint32_t;
    l ^= tt;
    r ^= tt << 2 as libc::c_int;
    tt = ((l >> 8 as libc::c_int ^ r) as libc::c_long & 0xff00ff as libc::c_long)
        as uint32_t;
    r ^= tt;
    l ^= tt << 8 as libc::c_int;
    tt = ((r >> 1 as libc::c_int ^ l) as libc::c_long & 0x55555555 as libc::c_long)
        as uint32_t;
    l ^= tt;
    r ^= tt << 1 as libc::c_int;
    *data.offset(0 as libc::c_int as isize) = l;
    *data.offset(1 as libc::c_int as isize) = r;
    DES_encrypt2(data, ks1, 1 as libc::c_int);
    DES_encrypt2(data, ks2, 0 as libc::c_int);
    DES_encrypt2(data, ks3, 1 as libc::c_int);
    l = *data.offset(0 as libc::c_int as isize);
    r = *data.offset(1 as libc::c_int as isize);
    let mut tt_0: uint32_t = 0;
    tt_0 = ((r >> 1 as libc::c_int ^ l) as libc::c_long & 0x55555555 as libc::c_long)
        as uint32_t;
    l ^= tt_0;
    r ^= tt_0 << 1 as libc::c_int;
    tt_0 = ((l >> 8 as libc::c_int ^ r) as libc::c_long & 0xff00ff as libc::c_long)
        as uint32_t;
    r ^= tt_0;
    l ^= tt_0 << 8 as libc::c_int;
    tt_0 = ((r >> 2 as libc::c_int ^ l) as libc::c_long & 0x33333333 as libc::c_long)
        as uint32_t;
    l ^= tt_0;
    r ^= tt_0 << 2 as libc::c_int;
    tt_0 = ((l >> 16 as libc::c_int ^ r) as libc::c_long & 0xffff as libc::c_long)
        as uint32_t;
    r ^= tt_0;
    l ^= tt_0 << 16 as libc::c_int;
    tt_0 = ((r >> 4 as libc::c_int ^ l) as libc::c_long & 0xf0f0f0f as libc::c_long)
        as uint32_t;
    l ^= tt_0;
    r ^= tt_0 << 4 as libc::c_int;
    *data.offset(0 as libc::c_int as isize) = l;
    *data.offset(1 as libc::c_int as isize) = r;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DES_decrypt3(
    mut data: *mut uint32_t,
    mut ks1: *const DES_key_schedule,
    mut ks2: *const DES_key_schedule,
    mut ks3: *const DES_key_schedule,
) {
    let mut l: uint32_t = 0;
    let mut r: uint32_t = 0;
    l = *data.offset(0 as libc::c_int as isize);
    r = *data.offset(1 as libc::c_int as isize);
    let mut tt: uint32_t = 0;
    tt = ((r >> 4 as libc::c_int ^ l) as libc::c_long & 0xf0f0f0f as libc::c_long)
        as uint32_t;
    l ^= tt;
    r ^= tt << 4 as libc::c_int;
    tt = ((l >> 16 as libc::c_int ^ r) as libc::c_long & 0xffff as libc::c_long)
        as uint32_t;
    r ^= tt;
    l ^= tt << 16 as libc::c_int;
    tt = ((r >> 2 as libc::c_int ^ l) as libc::c_long & 0x33333333 as libc::c_long)
        as uint32_t;
    l ^= tt;
    r ^= tt << 2 as libc::c_int;
    tt = ((l >> 8 as libc::c_int ^ r) as libc::c_long & 0xff00ff as libc::c_long)
        as uint32_t;
    r ^= tt;
    l ^= tt << 8 as libc::c_int;
    tt = ((r >> 1 as libc::c_int ^ l) as libc::c_long & 0x55555555 as libc::c_long)
        as uint32_t;
    l ^= tt;
    r ^= tt << 1 as libc::c_int;
    *data.offset(0 as libc::c_int as isize) = l;
    *data.offset(1 as libc::c_int as isize) = r;
    DES_encrypt2(data, ks3, 0 as libc::c_int);
    DES_encrypt2(data, ks2, 1 as libc::c_int);
    DES_encrypt2(data, ks1, 0 as libc::c_int);
    l = *data.offset(0 as libc::c_int as isize);
    r = *data.offset(1 as libc::c_int as isize);
    let mut tt_0: uint32_t = 0;
    tt_0 = ((r >> 1 as libc::c_int ^ l) as libc::c_long & 0x55555555 as libc::c_long)
        as uint32_t;
    l ^= tt_0;
    r ^= tt_0 << 1 as libc::c_int;
    tt_0 = ((l >> 8 as libc::c_int ^ r) as libc::c_long & 0xff00ff as libc::c_long)
        as uint32_t;
    r ^= tt_0;
    l ^= tt_0 << 8 as libc::c_int;
    tt_0 = ((r >> 2 as libc::c_int ^ l) as libc::c_long & 0x33333333 as libc::c_long)
        as uint32_t;
    l ^= tt_0;
    r ^= tt_0 << 2 as libc::c_int;
    tt_0 = ((l >> 16 as libc::c_int ^ r) as libc::c_long & 0xffff as libc::c_long)
        as uint32_t;
    r ^= tt_0;
    l ^= tt_0 << 16 as libc::c_int;
    tt_0 = ((r >> 4 as libc::c_int ^ l) as libc::c_long & 0xf0f0f0f as libc::c_long)
        as uint32_t;
    l ^= tt_0;
    r ^= tt_0 << 4 as libc::c_int;
    *data.offset(0 as libc::c_int as isize) = l;
    *data.offset(1 as libc::c_int as isize) = r;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DES_ecb_encrypt(
    mut in_block: *const DES_cblock,
    mut out_block: *mut DES_cblock,
    mut schedule: *const DES_key_schedule,
    mut is_encrypt: libc::c_int,
) {
    DES_ecb_encrypt_ex(
        ((*in_block).bytes).as_ptr(),
        ((*out_block).bytes).as_mut_ptr(),
        schedule,
        is_encrypt,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DES_ecb_encrypt_ex(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut schedule: *const DES_key_schedule,
    mut is_encrypt: libc::c_int,
) {
    let mut ll: [uint32_t; 2] = [0; 2];
    ll[0 as libc::c_int as usize] = CRYPTO_load_u32_le(in_0 as *const libc::c_void);
    ll[1 as libc::c_int
        as usize] = CRYPTO_load_u32_le(
        in_0.offset(4 as libc::c_int as isize) as *const libc::c_void,
    );
    DES_encrypt1(ll.as_mut_ptr(), schedule, is_encrypt);
    CRYPTO_store_u32_le(out as *mut libc::c_void, ll[0 as libc::c_int as usize]);
    CRYPTO_store_u32_le(
        out.offset(4 as libc::c_int as isize) as *mut libc::c_void,
        ll[1 as libc::c_int as usize],
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DES_ncbc_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut len: size_t,
    mut schedule: *const DES_key_schedule,
    mut ivec: *mut DES_cblock,
    mut enc: libc::c_int,
) {
    DES_ncbc_encrypt_ex(in_0, out, len, schedule, ((*ivec).bytes).as_mut_ptr(), enc);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DES_ncbc_encrypt_ex(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut len: size_t,
    mut schedule: *const DES_key_schedule,
    mut ivec: *mut uint8_t,
    mut enc: libc::c_int,
) {
    let mut tin0: uint32_t = 0;
    let mut tin1: uint32_t = 0;
    let mut tout0: uint32_t = 0;
    let mut tout1: uint32_t = 0;
    let mut xor0: uint32_t = 0;
    let mut xor1: uint32_t = 0;
    let mut tin: [uint32_t; 2] = [0; 2];
    let mut iv: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    iv = ivec;
    if enc != 0 {
        let fresh8 = iv;
        iv = iv.offset(1);
        tout0 = *fresh8 as uint32_t;
        let fresh9 = iv;
        iv = iv.offset(1);
        tout0 |= (*fresh9 as uint32_t) << 8 as libc::c_long;
        let fresh10 = iv;
        iv = iv.offset(1);
        tout0 |= (*fresh10 as uint32_t) << 16 as libc::c_long;
        let fresh11 = iv;
        iv = iv.offset(1);
        tout0 |= (*fresh11 as uint32_t) << 24 as libc::c_long;
        let fresh12 = iv;
        iv = iv.offset(1);
        tout1 = *fresh12 as uint32_t;
        let fresh13 = iv;
        iv = iv.offset(1);
        tout1 |= (*fresh13 as uint32_t) << 8 as libc::c_long;
        let fresh14 = iv;
        iv = iv.offset(1);
        tout1 |= (*fresh14 as uint32_t) << 16 as libc::c_long;
        let fresh15 = iv;
        iv = iv.offset(1);
        tout1 |= (*fresh15 as uint32_t) << 24 as libc::c_long;
        while len >= 8 as libc::c_int as size_t {
            let fresh16 = in_0;
            in_0 = in_0.offset(1);
            tin0 = *fresh16 as uint32_t;
            let fresh17 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh17 as uint32_t) << 8 as libc::c_long;
            let fresh18 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh18 as uint32_t) << 16 as libc::c_long;
            let fresh19 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh19 as uint32_t) << 24 as libc::c_long;
            let fresh20 = in_0;
            in_0 = in_0.offset(1);
            tin1 = *fresh20 as uint32_t;
            let fresh21 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh21 as uint32_t) << 8 as libc::c_long;
            let fresh22 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh22 as uint32_t) << 16 as libc::c_long;
            let fresh23 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh23 as uint32_t) << 24 as libc::c_long;
            tin0 ^= tout0;
            tin[0 as libc::c_int as usize] = tin0;
            tin1 ^= tout1;
            tin[1 as libc::c_int as usize] = tin1;
            DES_encrypt1(tin.as_mut_ptr(), schedule, 1 as libc::c_int);
            tout0 = tin[0 as libc::c_int as usize];
            let fresh24 = out;
            out = out.offset(1);
            *fresh24 = (tout0 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
            let fresh25 = out;
            out = out.offset(1);
            *fresh25 = (tout0 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh26 = out;
            out = out.offset(1);
            *fresh26 = (tout0 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh27 = out;
            out = out.offset(1);
            *fresh27 = (tout0 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            tout1 = tin[1 as libc::c_int as usize];
            let fresh28 = out;
            out = out.offset(1);
            *fresh28 = (tout1 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
            let fresh29 = out;
            out = out.offset(1);
            *fresh29 = (tout1 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh30 = out;
            out = out.offset(1);
            *fresh30 = (tout1 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh31 = out;
            out = out.offset(1);
            *fresh31 = (tout1 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            len = len.wrapping_sub(8 as libc::c_int as size_t);
        }
        if len != 0 as libc::c_int as size_t {
            in_0 = in_0.offset(len as isize);
            tin1 = 0 as libc::c_int as uint32_t;
            tin0 = tin1;
            let mut current_block_62: u64;
            match len {
                8 => {
                    in_0 = in_0.offset(-1);
                    tin1 = (*in_0 as uint32_t) << 24 as libc::c_long;
                    current_block_62 = 8218929041491088611;
                }
                7 => {
                    current_block_62 = 8218929041491088611;
                }
                6 => {
                    current_block_62 = 7973540781028298654;
                }
                5 => {
                    current_block_62 = 5942396365242503499;
                }
                4 => {
                    current_block_62 = 5055818706731838159;
                }
                3 => {
                    current_block_62 = 13064844953531049122;
                }
                2 => {
                    current_block_62 = 9561202965565166129;
                }
                1 => {
                    current_block_62 = 2850954090395841656;
                }
                _ => {
                    current_block_62 = 11777552016271000781;
                }
            }
            match current_block_62 {
                8218929041491088611 => {
                    in_0 = in_0.offset(-1);
                    tin1 |= (*in_0 as uint32_t) << 16 as libc::c_long;
                    current_block_62 = 7973540781028298654;
                }
                _ => {}
            }
            match current_block_62 {
                7973540781028298654 => {
                    in_0 = in_0.offset(-1);
                    tin1 |= (*in_0 as uint32_t) << 8 as libc::c_long;
                    current_block_62 = 5942396365242503499;
                }
                _ => {}
            }
            match current_block_62 {
                5942396365242503499 => {
                    in_0 = in_0.offset(-1);
                    tin1 |= *in_0 as uint32_t;
                    current_block_62 = 5055818706731838159;
                }
                _ => {}
            }
            match current_block_62 {
                5055818706731838159 => {
                    in_0 = in_0.offset(-1);
                    tin0 = (*in_0 as uint32_t) << 24 as libc::c_long;
                    current_block_62 = 13064844953531049122;
                }
                _ => {}
            }
            match current_block_62 {
                13064844953531049122 => {
                    in_0 = in_0.offset(-1);
                    tin0 |= (*in_0 as uint32_t) << 16 as libc::c_long;
                    current_block_62 = 9561202965565166129;
                }
                _ => {}
            }
            match current_block_62 {
                9561202965565166129 => {
                    in_0 = in_0.offset(-1);
                    tin0 |= (*in_0 as uint32_t) << 8 as libc::c_long;
                    current_block_62 = 2850954090395841656;
                }
                _ => {}
            }
            match current_block_62 {
                2850954090395841656 => {
                    in_0 = in_0.offset(-1);
                    tin0 |= *in_0 as uint32_t;
                }
                _ => {}
            }
            tin0 ^= tout0;
            tin[0 as libc::c_int as usize] = tin0;
            tin1 ^= tout1;
            tin[1 as libc::c_int as usize] = tin1;
            DES_encrypt1(tin.as_mut_ptr(), schedule, 1 as libc::c_int);
            tout0 = tin[0 as libc::c_int as usize];
            let fresh32 = out;
            out = out.offset(1);
            *fresh32 = (tout0 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
            let fresh33 = out;
            out = out.offset(1);
            *fresh33 = (tout0 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh34 = out;
            out = out.offset(1);
            *fresh34 = (tout0 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh35 = out;
            out = out.offset(1);
            *fresh35 = (tout0 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            tout1 = tin[1 as libc::c_int as usize];
            let fresh36 = out;
            out = out.offset(1);
            *fresh36 = (tout1 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
            let fresh37 = out;
            out = out.offset(1);
            *fresh37 = (tout1 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh38 = out;
            out = out.offset(1);
            *fresh38 = (tout1 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh39 = out;
            out = out.offset(1);
            *fresh39 = (tout1 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
        }
        iv = ivec;
        let fresh40 = iv;
        iv = iv.offset(1);
        *fresh40 = (tout0 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
        let fresh41 = iv;
        iv = iv.offset(1);
        *fresh41 = (tout0 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh42 = iv;
        iv = iv.offset(1);
        *fresh42 = (tout0 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh43 = iv;
        iv = iv.offset(1);
        *fresh43 = (tout0 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh44 = iv;
        iv = iv.offset(1);
        *fresh44 = (tout1 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
        let fresh45 = iv;
        iv = iv.offset(1);
        *fresh45 = (tout1 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh46 = iv;
        iv = iv.offset(1);
        *fresh46 = (tout1 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh47 = iv;
        iv = iv.offset(1);
        *fresh47 = (tout1 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
    } else {
        let fresh48 = iv;
        iv = iv.offset(1);
        xor0 = *fresh48 as uint32_t;
        let fresh49 = iv;
        iv = iv.offset(1);
        xor0 |= (*fresh49 as uint32_t) << 8 as libc::c_long;
        let fresh50 = iv;
        iv = iv.offset(1);
        xor0 |= (*fresh50 as uint32_t) << 16 as libc::c_long;
        let fresh51 = iv;
        iv = iv.offset(1);
        xor0 |= (*fresh51 as uint32_t) << 24 as libc::c_long;
        let fresh52 = iv;
        iv = iv.offset(1);
        xor1 = *fresh52 as uint32_t;
        let fresh53 = iv;
        iv = iv.offset(1);
        xor1 |= (*fresh53 as uint32_t) << 8 as libc::c_long;
        let fresh54 = iv;
        iv = iv.offset(1);
        xor1 |= (*fresh54 as uint32_t) << 16 as libc::c_long;
        let fresh55 = iv;
        iv = iv.offset(1);
        xor1 |= (*fresh55 as uint32_t) << 24 as libc::c_long;
        while len >= 8 as libc::c_int as size_t {
            let fresh56 = in_0;
            in_0 = in_0.offset(1);
            tin0 = *fresh56 as uint32_t;
            let fresh57 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh57 as uint32_t) << 8 as libc::c_long;
            let fresh58 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh58 as uint32_t) << 16 as libc::c_long;
            let fresh59 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh59 as uint32_t) << 24 as libc::c_long;
            tin[0 as libc::c_int as usize] = tin0;
            let fresh60 = in_0;
            in_0 = in_0.offset(1);
            tin1 = *fresh60 as uint32_t;
            let fresh61 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh61 as uint32_t) << 8 as libc::c_long;
            let fresh62 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh62 as uint32_t) << 16 as libc::c_long;
            let fresh63 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh63 as uint32_t) << 24 as libc::c_long;
            tin[1 as libc::c_int as usize] = tin1;
            DES_encrypt1(tin.as_mut_ptr(), schedule, 0 as libc::c_int);
            tout0 = tin[0 as libc::c_int as usize] ^ xor0;
            tout1 = tin[1 as libc::c_int as usize] ^ xor1;
            let fresh64 = out;
            out = out.offset(1);
            *fresh64 = (tout0 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
            let fresh65 = out;
            out = out.offset(1);
            *fresh65 = (tout0 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh66 = out;
            out = out.offset(1);
            *fresh66 = (tout0 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh67 = out;
            out = out.offset(1);
            *fresh67 = (tout0 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh68 = out;
            out = out.offset(1);
            *fresh68 = (tout1 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
            let fresh69 = out;
            out = out.offset(1);
            *fresh69 = (tout1 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh70 = out;
            out = out.offset(1);
            *fresh70 = (tout1 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh71 = out;
            out = out.offset(1);
            *fresh71 = (tout1 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            xor0 = tin0;
            xor1 = tin1;
            len = len.wrapping_sub(8 as libc::c_int as size_t);
        }
        if len != 0 as libc::c_int as size_t {
            let fresh72 = in_0;
            in_0 = in_0.offset(1);
            tin0 = *fresh72 as uint32_t;
            let fresh73 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh73 as uint32_t) << 8 as libc::c_long;
            let fresh74 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh74 as uint32_t) << 16 as libc::c_long;
            let fresh75 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh75 as uint32_t) << 24 as libc::c_long;
            tin[0 as libc::c_int as usize] = tin0;
            let fresh76 = in_0;
            in_0 = in_0.offset(1);
            tin1 = *fresh76 as uint32_t;
            let fresh77 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh77 as uint32_t) << 8 as libc::c_long;
            let fresh78 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh78 as uint32_t) << 16 as libc::c_long;
            let fresh79 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh79 as uint32_t) << 24 as libc::c_long;
            tin[1 as libc::c_int as usize] = tin1;
            DES_encrypt1(tin.as_mut_ptr(), schedule, 0 as libc::c_int);
            tout0 = tin[0 as libc::c_int as usize] ^ xor0;
            tout1 = tin[1 as libc::c_int as usize] ^ xor1;
            out = out.offset(len as isize);
            let mut current_block_178: u64;
            match len {
                8 => {
                    out = out.offset(-1);
                    *out = (tout1 >> 24 as libc::c_long
                        & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
                    current_block_178 = 9519645648565637137;
                }
                7 => {
                    current_block_178 = 9519645648565637137;
                }
                6 => {
                    current_block_178 = 7897470734003119868;
                }
                5 => {
                    current_block_178 = 18082770182913259415;
                }
                4 => {
                    current_block_178 = 3117274791635106389;
                }
                3 => {
                    current_block_178 = 10932728404159094139;
                }
                2 => {
                    current_block_178 = 2912699219018881187;
                }
                1 => {
                    current_block_178 = 2275314692770682857;
                }
                _ => {
                    current_block_178 = 5431927413890720344;
                }
            }
            match current_block_178 {
                9519645648565637137 => {
                    out = out.offset(-1);
                    *out = (tout1 >> 16 as libc::c_long
                        & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
                    current_block_178 = 7897470734003119868;
                }
                _ => {}
            }
            match current_block_178 {
                7897470734003119868 => {
                    out = out.offset(-1);
                    *out = (tout1 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                        as libc::c_uchar;
                    current_block_178 = 18082770182913259415;
                }
                _ => {}
            }
            match current_block_178 {
                18082770182913259415 => {
                    out = out.offset(-1);
                    *out = (tout1 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
                    current_block_178 = 3117274791635106389;
                }
                _ => {}
            }
            match current_block_178 {
                3117274791635106389 => {
                    out = out.offset(-1);
                    *out = (tout0 >> 24 as libc::c_long
                        & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
                    current_block_178 = 10932728404159094139;
                }
                _ => {}
            }
            match current_block_178 {
                10932728404159094139 => {
                    out = out.offset(-1);
                    *out = (tout0 >> 16 as libc::c_long
                        & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
                    current_block_178 = 2912699219018881187;
                }
                _ => {}
            }
            match current_block_178 {
                2912699219018881187 => {
                    out = out.offset(-1);
                    *out = (tout0 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                        as libc::c_uchar;
                    current_block_178 = 2275314692770682857;
                }
                _ => {}
            }
            match current_block_178 {
                2275314692770682857 => {
                    out = out.offset(-1);
                    *out = (tout0 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
                }
                _ => {}
            }
            xor0 = tin0;
            xor1 = tin1;
        }
        iv = ivec;
        let fresh80 = iv;
        iv = iv.offset(1);
        *fresh80 = (xor0 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
        let fresh81 = iv;
        iv = iv.offset(1);
        *fresh81 = (xor0 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh82 = iv;
        iv = iv.offset(1);
        *fresh82 = (xor0 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh83 = iv;
        iv = iv.offset(1);
        *fresh83 = (xor0 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh84 = iv;
        iv = iv.offset(1);
        *fresh84 = (xor1 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
        let fresh85 = iv;
        iv = iv.offset(1);
        *fresh85 = (xor1 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh86 = iv;
        iv = iv.offset(1);
        *fresh86 = (xor1 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh87 = iv;
        iv = iv.offset(1);
        *fresh87 = (xor1 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
    }
    tin[1 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    tin[0 as libc::c_int as usize] = tin[1 as libc::c_int as usize];
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DES_ecb3_encrypt(
    mut input: *const DES_cblock,
    mut output: *mut DES_cblock,
    mut ks1: *const DES_key_schedule,
    mut ks2: *const DES_key_schedule,
    mut ks3: *const DES_key_schedule,
    mut enc: libc::c_int,
) {
    DES_ecb3_encrypt_ex(
        ((*input).bytes).as_ptr(),
        ((*output).bytes).as_mut_ptr(),
        ks1,
        ks2,
        ks3,
        enc,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DES_ecb3_encrypt_ex(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut ks1: *const DES_key_schedule,
    mut ks2: *const DES_key_schedule,
    mut ks3: *const DES_key_schedule,
    mut enc: libc::c_int,
) {
    let mut ll: [uint32_t; 2] = [0; 2];
    ll[0 as libc::c_int as usize] = CRYPTO_load_u32_le(in_0 as *const libc::c_void);
    ll[1 as libc::c_int
        as usize] = CRYPTO_load_u32_le(
        in_0.offset(4 as libc::c_int as isize) as *const libc::c_void,
    );
    if enc != 0 {
        DES_encrypt3(ll.as_mut_ptr(), ks1, ks2, ks3);
    } else {
        DES_decrypt3(ll.as_mut_ptr(), ks1, ks2, ks3);
    }
    CRYPTO_store_u32_le(out as *mut libc::c_void, ll[0 as libc::c_int as usize]);
    CRYPTO_store_u32_le(
        out.offset(4 as libc::c_int as isize) as *mut libc::c_void,
        ll[1 as libc::c_int as usize],
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DES_ede3_cbc_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut len: size_t,
    mut ks1: *const DES_key_schedule,
    mut ks2: *const DES_key_schedule,
    mut ks3: *const DES_key_schedule,
    mut ivec: *mut DES_cblock,
    mut enc: libc::c_int,
) {
    DES_ede3_cbc_encrypt_ex(
        in_0,
        out,
        len,
        ks1,
        ks2,
        ks3,
        ((*ivec).bytes).as_mut_ptr(),
        enc,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DES_ede3_cbc_encrypt_ex(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut len: size_t,
    mut ks1: *const DES_key_schedule,
    mut ks2: *const DES_key_schedule,
    mut ks3: *const DES_key_schedule,
    mut ivec: *mut uint8_t,
    mut enc: libc::c_int,
) {
    let mut tin0: uint32_t = 0;
    let mut tin1: uint32_t = 0;
    let mut tout0: uint32_t = 0;
    let mut tout1: uint32_t = 0;
    let mut xor0: uint32_t = 0;
    let mut xor1: uint32_t = 0;
    let mut tin: [uint32_t; 2] = [0; 2];
    let mut iv: *mut uint8_t = 0 as *mut uint8_t;
    iv = ivec;
    if enc != 0 {
        let fresh88 = iv;
        iv = iv.offset(1);
        tout0 = *fresh88 as uint32_t;
        let fresh89 = iv;
        iv = iv.offset(1);
        tout0 |= (*fresh89 as uint32_t) << 8 as libc::c_long;
        let fresh90 = iv;
        iv = iv.offset(1);
        tout0 |= (*fresh90 as uint32_t) << 16 as libc::c_long;
        let fresh91 = iv;
        iv = iv.offset(1);
        tout0 |= (*fresh91 as uint32_t) << 24 as libc::c_long;
        let fresh92 = iv;
        iv = iv.offset(1);
        tout1 = *fresh92 as uint32_t;
        let fresh93 = iv;
        iv = iv.offset(1);
        tout1 |= (*fresh93 as uint32_t) << 8 as libc::c_long;
        let fresh94 = iv;
        iv = iv.offset(1);
        tout1 |= (*fresh94 as uint32_t) << 16 as libc::c_long;
        let fresh95 = iv;
        iv = iv.offset(1);
        tout1 |= (*fresh95 as uint32_t) << 24 as libc::c_long;
        while len >= 8 as libc::c_int as size_t {
            let fresh96 = in_0;
            in_0 = in_0.offset(1);
            tin0 = *fresh96 as uint32_t;
            let fresh97 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh97 as uint32_t) << 8 as libc::c_long;
            let fresh98 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh98 as uint32_t) << 16 as libc::c_long;
            let fresh99 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh99 as uint32_t) << 24 as libc::c_long;
            let fresh100 = in_0;
            in_0 = in_0.offset(1);
            tin1 = *fresh100 as uint32_t;
            let fresh101 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh101 as uint32_t) << 8 as libc::c_long;
            let fresh102 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh102 as uint32_t) << 16 as libc::c_long;
            let fresh103 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh103 as uint32_t) << 24 as libc::c_long;
            tin0 ^= tout0;
            tin1 ^= tout1;
            tin[0 as libc::c_int as usize] = tin0;
            tin[1 as libc::c_int as usize] = tin1;
            DES_encrypt3(tin.as_mut_ptr(), ks1, ks2, ks3);
            tout0 = tin[0 as libc::c_int as usize];
            tout1 = tin[1 as libc::c_int as usize];
            let fresh104 = out;
            out = out.offset(1);
            *fresh104 = (tout0 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
            let fresh105 = out;
            out = out.offset(1);
            *fresh105 = (tout0 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh106 = out;
            out = out.offset(1);
            *fresh106 = (tout0 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh107 = out;
            out = out.offset(1);
            *fresh107 = (tout0 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh108 = out;
            out = out.offset(1);
            *fresh108 = (tout1 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
            let fresh109 = out;
            out = out.offset(1);
            *fresh109 = (tout1 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh110 = out;
            out = out.offset(1);
            *fresh110 = (tout1 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh111 = out;
            out = out.offset(1);
            *fresh111 = (tout1 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            len = len.wrapping_sub(8 as libc::c_int as size_t);
        }
        if len != 0 as libc::c_int as size_t {
            in_0 = in_0.offset(len as isize);
            tin1 = 0 as libc::c_int as uint32_t;
            tin0 = tin1;
            let mut current_block_62: u64;
            match len {
                8 => {
                    in_0 = in_0.offset(-1);
                    tin1 = (*in_0 as uint32_t) << 24 as libc::c_long;
                    current_block_62 = 15127167126390415221;
                }
                7 => {
                    current_block_62 = 15127167126390415221;
                }
                6 => {
                    current_block_62 = 2337206861410066326;
                }
                5 => {
                    current_block_62 = 18367542186514147735;
                }
                4 => {
                    current_block_62 = 2741599847739000878;
                }
                3 => {
                    current_block_62 = 11800758854290119221;
                }
                2 => {
                    current_block_62 = 10954195357765137716;
                }
                1 => {
                    current_block_62 = 10748006672221819954;
                }
                _ => {
                    current_block_62 = 11777552016271000781;
                }
            }
            match current_block_62 {
                15127167126390415221 => {
                    in_0 = in_0.offset(-1);
                    tin1 |= (*in_0 as uint32_t) << 16 as libc::c_long;
                    current_block_62 = 2337206861410066326;
                }
                _ => {}
            }
            match current_block_62 {
                2337206861410066326 => {
                    in_0 = in_0.offset(-1);
                    tin1 |= (*in_0 as uint32_t) << 8 as libc::c_long;
                    current_block_62 = 18367542186514147735;
                }
                _ => {}
            }
            match current_block_62 {
                18367542186514147735 => {
                    in_0 = in_0.offset(-1);
                    tin1 |= *in_0 as uint32_t;
                    current_block_62 = 2741599847739000878;
                }
                _ => {}
            }
            match current_block_62 {
                2741599847739000878 => {
                    in_0 = in_0.offset(-1);
                    tin0 = (*in_0 as uint32_t) << 24 as libc::c_long;
                    current_block_62 = 11800758854290119221;
                }
                _ => {}
            }
            match current_block_62 {
                11800758854290119221 => {
                    in_0 = in_0.offset(-1);
                    tin0 |= (*in_0 as uint32_t) << 16 as libc::c_long;
                    current_block_62 = 10954195357765137716;
                }
                _ => {}
            }
            match current_block_62 {
                10954195357765137716 => {
                    in_0 = in_0.offset(-1);
                    tin0 |= (*in_0 as uint32_t) << 8 as libc::c_long;
                    current_block_62 = 10748006672221819954;
                }
                _ => {}
            }
            match current_block_62 {
                10748006672221819954 => {
                    in_0 = in_0.offset(-1);
                    tin0 |= *in_0 as uint32_t;
                }
                _ => {}
            }
            tin0 ^= tout0;
            tin1 ^= tout1;
            tin[0 as libc::c_int as usize] = tin0;
            tin[1 as libc::c_int as usize] = tin1;
            DES_encrypt3(tin.as_mut_ptr(), ks1, ks2, ks3);
            tout0 = tin[0 as libc::c_int as usize];
            tout1 = tin[1 as libc::c_int as usize];
            let fresh112 = out;
            out = out.offset(1);
            *fresh112 = (tout0 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
            let fresh113 = out;
            out = out.offset(1);
            *fresh113 = (tout0 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh114 = out;
            out = out.offset(1);
            *fresh114 = (tout0 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh115 = out;
            out = out.offset(1);
            *fresh115 = (tout0 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh116 = out;
            out = out.offset(1);
            *fresh116 = (tout1 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
            let fresh117 = out;
            out = out.offset(1);
            *fresh117 = (tout1 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh118 = out;
            out = out.offset(1);
            *fresh118 = (tout1 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh119 = out;
            out = out.offset(1);
            *fresh119 = (tout1 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
        }
        iv = ivec;
        let fresh120 = iv;
        iv = iv.offset(1);
        *fresh120 = (tout0 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
        let fresh121 = iv;
        iv = iv.offset(1);
        *fresh121 = (tout0 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh122 = iv;
        iv = iv.offset(1);
        *fresh122 = (tout0 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh123 = iv;
        iv = iv.offset(1);
        *fresh123 = (tout0 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh124 = iv;
        iv = iv.offset(1);
        *fresh124 = (tout1 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
        let fresh125 = iv;
        iv = iv.offset(1);
        *fresh125 = (tout1 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh126 = iv;
        iv = iv.offset(1);
        *fresh126 = (tout1 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh127 = iv;
        iv = iv.offset(1);
        *fresh127 = (tout1 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
    } else {
        let mut t0: uint32_t = 0;
        let mut t1: uint32_t = 0;
        let fresh128 = iv;
        iv = iv.offset(1);
        xor0 = *fresh128 as uint32_t;
        let fresh129 = iv;
        iv = iv.offset(1);
        xor0 |= (*fresh129 as uint32_t) << 8 as libc::c_long;
        let fresh130 = iv;
        iv = iv.offset(1);
        xor0 |= (*fresh130 as uint32_t) << 16 as libc::c_long;
        let fresh131 = iv;
        iv = iv.offset(1);
        xor0 |= (*fresh131 as uint32_t) << 24 as libc::c_long;
        let fresh132 = iv;
        iv = iv.offset(1);
        xor1 = *fresh132 as uint32_t;
        let fresh133 = iv;
        iv = iv.offset(1);
        xor1 |= (*fresh133 as uint32_t) << 8 as libc::c_long;
        let fresh134 = iv;
        iv = iv.offset(1);
        xor1 |= (*fresh134 as uint32_t) << 16 as libc::c_long;
        let fresh135 = iv;
        iv = iv.offset(1);
        xor1 |= (*fresh135 as uint32_t) << 24 as libc::c_long;
        while len >= 8 as libc::c_int as size_t {
            let fresh136 = in_0;
            in_0 = in_0.offset(1);
            tin0 = *fresh136 as uint32_t;
            let fresh137 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh137 as uint32_t) << 8 as libc::c_long;
            let fresh138 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh138 as uint32_t) << 16 as libc::c_long;
            let fresh139 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh139 as uint32_t) << 24 as libc::c_long;
            let fresh140 = in_0;
            in_0 = in_0.offset(1);
            tin1 = *fresh140 as uint32_t;
            let fresh141 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh141 as uint32_t) << 8 as libc::c_long;
            let fresh142 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh142 as uint32_t) << 16 as libc::c_long;
            let fresh143 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh143 as uint32_t) << 24 as libc::c_long;
            t0 = tin0;
            t1 = tin1;
            tin[0 as libc::c_int as usize] = tin0;
            tin[1 as libc::c_int as usize] = tin1;
            DES_decrypt3(tin.as_mut_ptr(), ks1, ks2, ks3);
            tout0 = tin[0 as libc::c_int as usize];
            tout1 = tin[1 as libc::c_int as usize];
            tout0 ^= xor0;
            tout1 ^= xor1;
            let fresh144 = out;
            out = out.offset(1);
            *fresh144 = (tout0 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
            let fresh145 = out;
            out = out.offset(1);
            *fresh145 = (tout0 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh146 = out;
            out = out.offset(1);
            *fresh146 = (tout0 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh147 = out;
            out = out.offset(1);
            *fresh147 = (tout0 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh148 = out;
            out = out.offset(1);
            *fresh148 = (tout1 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
            let fresh149 = out;
            out = out.offset(1);
            *fresh149 = (tout1 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh150 = out;
            out = out.offset(1);
            *fresh150 = (tout1 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            let fresh151 = out;
            out = out.offset(1);
            *fresh151 = (tout1 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
                as libc::c_uchar;
            xor0 = t0;
            xor1 = t1;
            len = len.wrapping_sub(8 as libc::c_int as size_t);
        }
        if len != 0 as libc::c_int as size_t {
            let fresh152 = in_0;
            in_0 = in_0.offset(1);
            tin0 = *fresh152 as uint32_t;
            let fresh153 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh153 as uint32_t) << 8 as libc::c_long;
            let fresh154 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh154 as uint32_t) << 16 as libc::c_long;
            let fresh155 = in_0;
            in_0 = in_0.offset(1);
            tin0 |= (*fresh155 as uint32_t) << 24 as libc::c_long;
            let fresh156 = in_0;
            in_0 = in_0.offset(1);
            tin1 = *fresh156 as uint32_t;
            let fresh157 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh157 as uint32_t) << 8 as libc::c_long;
            let fresh158 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh158 as uint32_t) << 16 as libc::c_long;
            let fresh159 = in_0;
            in_0 = in_0.offset(1);
            tin1 |= (*fresh159 as uint32_t) << 24 as libc::c_long;
            t0 = tin0;
            t1 = tin1;
            tin[0 as libc::c_int as usize] = tin0;
            tin[1 as libc::c_int as usize] = tin1;
            DES_decrypt3(tin.as_mut_ptr(), ks1, ks2, ks3);
            tout0 = tin[0 as libc::c_int as usize];
            tout1 = tin[1 as libc::c_int as usize];
            tout0 ^= xor0;
            tout1 ^= xor1;
            out = out.offset(len as isize);
            let mut current_block_186: u64;
            match len {
                8 => {
                    out = out.offset(-1);
                    *out = (tout1 >> 24 as libc::c_long
                        & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
                    current_block_186 = 9363759360034762163;
                }
                7 => {
                    current_block_186 = 9363759360034762163;
                }
                6 => {
                    current_block_186 = 7204900954078054643;
                }
                5 => {
                    current_block_186 = 15583329789015001518;
                }
                4 => {
                    current_block_186 = 14852958370163223038;
                }
                3 => {
                    current_block_186 = 6372261630850399728;
                }
                2 => {
                    current_block_186 = 10607098743120199864;
                }
                1 => {
                    current_block_186 = 1276191155120476369;
                }
                _ => {
                    current_block_186 = 10570719081292997246;
                }
            }
            match current_block_186 {
                9363759360034762163 => {
                    out = out.offset(-1);
                    *out = (tout1 >> 16 as libc::c_long
                        & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
                    current_block_186 = 7204900954078054643;
                }
                _ => {}
            }
            match current_block_186 {
                7204900954078054643 => {
                    out = out.offset(-1);
                    *out = (tout1 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                        as libc::c_uchar;
                    current_block_186 = 15583329789015001518;
                }
                _ => {}
            }
            match current_block_186 {
                15583329789015001518 => {
                    out = out.offset(-1);
                    *out = (tout1 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
                    current_block_186 = 14852958370163223038;
                }
                _ => {}
            }
            match current_block_186 {
                14852958370163223038 => {
                    out = out.offset(-1);
                    *out = (tout0 >> 24 as libc::c_long
                        & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
                    current_block_186 = 6372261630850399728;
                }
                _ => {}
            }
            match current_block_186 {
                6372261630850399728 => {
                    out = out.offset(-1);
                    *out = (tout0 >> 16 as libc::c_long
                        & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
                    current_block_186 = 10607098743120199864;
                }
                _ => {}
            }
            match current_block_186 {
                10607098743120199864 => {
                    out = out.offset(-1);
                    *out = (tout0 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
                        as libc::c_uchar;
                    current_block_186 = 1276191155120476369;
                }
                _ => {}
            }
            match current_block_186 {
                1276191155120476369 => {
                    out = out.offset(-1);
                    *out = (tout0 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
                }
                _ => {}
            }
            xor0 = t0;
            xor1 = t1;
        }
        iv = ivec;
        let fresh160 = iv;
        iv = iv.offset(1);
        *fresh160 = (xor0 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
        let fresh161 = iv;
        iv = iv.offset(1);
        *fresh161 = (xor0 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh162 = iv;
        iv = iv.offset(1);
        *fresh162 = (xor0 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh163 = iv;
        iv = iv.offset(1);
        *fresh163 = (xor0 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh164 = iv;
        iv = iv.offset(1);
        *fresh164 = (xor1 & 0xff as libc::c_int as uint32_t) as libc::c_uchar;
        let fresh165 = iv;
        iv = iv.offset(1);
        *fresh165 = (xor1 >> 8 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh166 = iv;
        iv = iv.offset(1);
        *fresh166 = (xor1 >> 16 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
        let fresh167 = iv;
        iv = iv.offset(1);
        *fresh167 = (xor1 >> 24 as libc::c_long & 0xff as libc::c_int as uint32_t)
            as libc::c_uchar;
    }
    tin[1 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    tin[0 as libc::c_int as usize] = tin[1 as libc::c_int as usize];
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DES_ede2_cbc_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut len: size_t,
    mut ks1: *const DES_key_schedule,
    mut ks2: *const DES_key_schedule,
    mut ivec: *mut DES_cblock,
    mut enc: libc::c_int,
) {
    DES_ede3_cbc_encrypt(in_0, out, len, ks1, ks2, ks1, ivec, enc);
}
