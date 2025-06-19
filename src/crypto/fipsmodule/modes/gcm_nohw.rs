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
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
}
pub type __uint128_t = u128;
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint64_t = __uint64_t;
pub type uint128_t = __uint128_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct u128_0 {
    pub hi: uint64_t,
    pub lo: uint64_t,
}
#[inline]
unsafe extern "C" fn CRYPTO_bswap8(mut x: uint64_t) -> uint64_t {
    return x.swap_bytes();
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
unsafe extern "C" fn CRYPTO_load_u64_be(mut ptr: *const libc::c_void) -> uint64_t {
    let mut ret: uint64_t = 0;
    OPENSSL_memcpy(
        &mut ret as *mut uint64_t as *mut libc::c_void,
        ptr,
        ::core::mem::size_of::<uint64_t>() as libc::c_ulong,
    );
    return CRYPTO_bswap8(ret);
}
#[inline]
unsafe extern "C" fn CRYPTO_store_u64_be(mut out: *mut libc::c_void, mut v: uint64_t) {
    v = CRYPTO_bswap8(v);
    OPENSSL_memcpy(
        out,
        &mut v as *mut uint64_t as *const libc::c_void,
        ::core::mem::size_of::<uint64_t>() as libc::c_ulong,
    );
}
unsafe extern "C" fn gcm_mul64_nohw(
    mut out_lo: *mut uint64_t,
    mut out_hi: *mut uint64_t,
    mut a: uint64_t,
    mut b: uint64_t,
) {
    let mut a0: uint64_t = a & 0x1111111111111110 as libc::c_ulong;
    let mut a1: uint64_t = a & 0x2222222222222220 as libc::c_ulong;
    let mut a2: uint64_t = a & 0x4444444444444440 as libc::c_ulong;
    let mut a3: uint64_t = a & 0x8888888888888880 as libc::c_ulong;
    let mut b0: uint64_t = b & 0x1111111111111111 as libc::c_ulong;
    let mut b1: uint64_t = b & 0x2222222222222222 as libc::c_ulong;
    let mut b2: uint64_t = b & 0x4444444444444444 as libc::c_ulong;
    let mut b3: uint64_t = b & 0x8888888888888888 as libc::c_ulong;
    let mut c0: uint128_t = a0 as uint128_t * b0 as uint128_t
        ^ a1 as uint128_t * b3 as uint128_t ^ a2 as uint128_t * b2 as uint128_t
        ^ a3 as uint128_t * b1 as uint128_t;
    let mut c1: uint128_t = a0 as uint128_t * b1 as uint128_t
        ^ a1 as uint128_t * b0 as uint128_t ^ a2 as uint128_t * b3 as uint128_t
        ^ a3 as uint128_t * b2 as uint128_t;
    let mut c2: uint128_t = a0 as uint128_t * b2 as uint128_t
        ^ a1 as uint128_t * b1 as uint128_t ^ a2 as uint128_t * b0 as uint128_t
        ^ a3 as uint128_t * b3 as uint128_t;
    let mut c3: uint128_t = a0 as uint128_t * b3 as uint128_t
        ^ a1 as uint128_t * b2 as uint128_t ^ a2 as uint128_t * b1 as uint128_t
        ^ a3 as uint128_t * b0 as uint128_t;
    let mut a0_mask: uint64_t = (0 as libc::c_ulong)
        .wrapping_sub(a & 1 as libc::c_int as uint64_t);
    let mut a1_mask: uint64_t = (0 as libc::c_ulong)
        .wrapping_sub(a >> 1 as libc::c_int & 1 as libc::c_int as uint64_t);
    let mut a2_mask: uint64_t = (0 as libc::c_ulong)
        .wrapping_sub(a >> 2 as libc::c_int & 1 as libc::c_int as uint64_t);
    let mut a3_mask: uint64_t = (0 as libc::c_ulong)
        .wrapping_sub(a >> 3 as libc::c_int & 1 as libc::c_int as uint64_t);
    let mut extra: uint128_t = (a0_mask & b) as uint128_t
        ^ ((a1_mask & b) as uint128_t) << 1 as libc::c_int
        ^ ((a2_mask & b) as uint128_t) << 2 as libc::c_int
        ^ ((a3_mask & b) as uint128_t) << 3 as libc::c_int;
    *out_lo = c0 as uint64_t & 0x1111111111111111 as libc::c_ulong
        ^ c1 as uint64_t & 0x2222222222222222 as libc::c_ulong
        ^ c2 as uint64_t & 0x4444444444444444 as libc::c_ulong
        ^ c3 as uint64_t & 0x8888888888888888 as libc::c_ulong ^ extra as uint64_t;
    *out_hi = (c0 >> 64 as libc::c_int) as uint64_t & 0x1111111111111111 as libc::c_ulong
        ^ (c1 >> 64 as libc::c_int) as uint64_t & 0x2222222222222222 as libc::c_ulong
        ^ (c2 >> 64 as libc::c_int) as uint64_t & 0x4444444444444444 as libc::c_ulong
        ^ (c3 >> 64 as libc::c_int) as uint64_t & 0x8888888888888888 as libc::c_ulong
        ^ (extra >> 64 as libc::c_int) as uint64_t;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gcm_init_nohw(
    mut Htable: *mut u128_0,
    mut Xi: *const uint64_t,
) {
    (*Htable.offset(0 as libc::c_int as isize))
        .lo = *Xi.offset(1 as libc::c_int as isize);
    (*Htable.offset(0 as libc::c_int as isize))
        .hi = *Xi.offset(0 as libc::c_int as isize);
    let mut carry: uint64_t = (*Htable.offset(0 as libc::c_int as isize)).hi
        >> 63 as libc::c_int;
    carry = (0 as libc::c_uint as uint64_t).wrapping_sub(carry);
    (*Htable.offset(0 as libc::c_int as isize)).hi <<= 1 as libc::c_int;
    (*Htable.offset(0 as libc::c_int as isize)).hi
        |= (*Htable.offset(0 as libc::c_int as isize)).lo >> 63 as libc::c_int;
    (*Htable.offset(0 as libc::c_int as isize)).lo <<= 1 as libc::c_int;
    (*Htable.offset(0 as libc::c_int as isize)).lo
        ^= carry & 1 as libc::c_int as uint64_t;
    let ref mut fresh0 = (*Htable.offset(0 as libc::c_int as isize)).hi;
    *fresh0 ^= carry & 0xc200000000000000 as libc::c_ulong;
}
unsafe extern "C" fn gcm_polyval_nohw(mut Xi: *mut uint64_t, mut H: *const u128_0) {
    let mut r0: uint64_t = 0;
    let mut r1: uint64_t = 0;
    gcm_mul64_nohw(&mut r0, &mut r1, *Xi.offset(0 as libc::c_int as isize), (*H).lo);
    let mut r2: uint64_t = 0;
    let mut r3: uint64_t = 0;
    gcm_mul64_nohw(&mut r2, &mut r3, *Xi.offset(1 as libc::c_int as isize), (*H).hi);
    let mut mid0: uint64_t = 0;
    let mut mid1: uint64_t = 0;
    gcm_mul64_nohw(
        &mut mid0,
        &mut mid1,
        *Xi.offset(0 as libc::c_int as isize) ^ *Xi.offset(1 as libc::c_int as isize),
        (*H).hi ^ (*H).lo,
    );
    mid0 ^= r0 ^ r2;
    mid1 ^= r1 ^ r3;
    r2 ^= mid1;
    r1 ^= mid0;
    r1 ^= r0 << 63 as libc::c_int ^ r0 << 62 as libc::c_int ^ r0 << 57 as libc::c_int;
    r2 ^= r0;
    r3 ^= r1;
    r2 ^= r0 >> 1 as libc::c_int;
    r2 ^= r1 << 63 as libc::c_int;
    r3 ^= r1 >> 1 as libc::c_int;
    r2 ^= r0 >> 2 as libc::c_int;
    r2 ^= r1 << 62 as libc::c_int;
    r3 ^= r1 >> 2 as libc::c_int;
    r2 ^= r0 >> 7 as libc::c_int;
    r2 ^= r1 << 57 as libc::c_int;
    r3 ^= r1 >> 7 as libc::c_int;
    *Xi.offset(0 as libc::c_int as isize) = r2;
    *Xi.offset(1 as libc::c_int as isize) = r3;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gcm_gmult_nohw(
    mut Xi: *mut uint8_t,
    mut Htable: *const u128_0,
) {
    let mut swapped: [uint64_t; 2] = [0; 2];
    swapped[0 as libc::c_int
        as usize] = CRYPTO_load_u64_be(
        Xi.offset(8 as libc::c_int as isize) as *const libc::c_void,
    );
    swapped[1 as libc::c_int as usize] = CRYPTO_load_u64_be(Xi as *const libc::c_void);
    gcm_polyval_nohw(swapped.as_mut_ptr(), &*Htable.offset(0 as libc::c_int as isize));
    CRYPTO_store_u64_be(Xi as *mut libc::c_void, swapped[1 as libc::c_int as usize]);
    CRYPTO_store_u64_be(
        Xi.offset(8 as libc::c_int as isize) as *mut libc::c_void,
        swapped[0 as libc::c_int as usize],
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gcm_ghash_nohw(
    mut Xi: *mut uint8_t,
    mut Htable: *const u128_0,
    mut inp: *const uint8_t,
    mut len: size_t,
) {
    let mut swapped: [uint64_t; 2] = [0; 2];
    swapped[0 as libc::c_int
        as usize] = CRYPTO_load_u64_be(
        Xi.offset(8 as libc::c_int as isize) as *const libc::c_void,
    );
    swapped[1 as libc::c_int as usize] = CRYPTO_load_u64_be(Xi as *const libc::c_void);
    while len >= 16 as libc::c_int as size_t {
        swapped[0 as libc::c_int as usize]
            ^= CRYPTO_load_u64_be(
                inp.offset(8 as libc::c_int as isize) as *const libc::c_void,
            );
        swapped[1 as libc::c_int as usize]
            ^= CRYPTO_load_u64_be(inp as *const libc::c_void);
        gcm_polyval_nohw(
            swapped.as_mut_ptr(),
            &*Htable.offset(0 as libc::c_int as isize),
        );
        inp = inp.offset(16 as libc::c_int as isize);
        len = len.wrapping_sub(16 as libc::c_int as size_t);
    }
    CRYPTO_store_u64_be(Xi as *mut libc::c_void, swapped[1 as libc::c_int as usize]);
    CRYPTO_store_u64_be(
        Xi.offset(8 as libc::c_int as isize) as *mut libc::c_void,
        swapped[0 as libc::c_int as usize],
    );
}
