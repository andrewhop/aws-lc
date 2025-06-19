#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
extern "C" {
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
}
pub type __uint8_t = libc::c_uchar;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint64_t = __uint64_t;
pub type size_t = libc::c_ulong;
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
unsafe extern "C" fn CRYPTO_load_u64_le(mut in_0: *const libc::c_void) -> uint64_t {
    let mut v: uint64_t = 0;
    OPENSSL_memcpy(
        &mut v as *mut uint64_t as *mut libc::c_void,
        in_0,
        ::core::mem::size_of::<uint64_t>() as libc::c_ulong,
    );
    return v;
}
#[inline]
unsafe extern "C" fn CRYPTO_rotl_u64(
    mut value: uint64_t,
    mut shift: libc::c_int,
) -> uint64_t {
    return value << shift | value >> (-shift & 63 as libc::c_int);
}
unsafe extern "C" fn siphash_round(mut v: *mut uint64_t) {
    let ref mut fresh0 = *v.offset(0 as libc::c_int as isize);
    *fresh0 = (*fresh0).wrapping_add(*v.offset(1 as libc::c_int as isize));
    let ref mut fresh1 = *v.offset(2 as libc::c_int as isize);
    *fresh1 = (*fresh1).wrapping_add(*v.offset(3 as libc::c_int as isize));
    *v
        .offset(
            1 as libc::c_int as isize,
        ) = CRYPTO_rotl_u64(*v.offset(1 as libc::c_int as isize), 13 as libc::c_int);
    *v
        .offset(
            3 as libc::c_int as isize,
        ) = CRYPTO_rotl_u64(*v.offset(3 as libc::c_int as isize), 16 as libc::c_int);
    *v.offset(1 as libc::c_int as isize) ^= *v.offset(0 as libc::c_int as isize);
    *v.offset(3 as libc::c_int as isize) ^= *v.offset(2 as libc::c_int as isize);
    *v
        .offset(
            0 as libc::c_int as isize,
        ) = CRYPTO_rotl_u64(*v.offset(0 as libc::c_int as isize), 32 as libc::c_int);
    let ref mut fresh2 = *v.offset(2 as libc::c_int as isize);
    *fresh2 = (*fresh2).wrapping_add(*v.offset(1 as libc::c_int as isize));
    let ref mut fresh3 = *v.offset(0 as libc::c_int as isize);
    *fresh3 = (*fresh3).wrapping_add(*v.offset(3 as libc::c_int as isize));
    *v
        .offset(
            1 as libc::c_int as isize,
        ) = CRYPTO_rotl_u64(*v.offset(1 as libc::c_int as isize), 17 as libc::c_int);
    *v
        .offset(
            3 as libc::c_int as isize,
        ) = CRYPTO_rotl_u64(*v.offset(3 as libc::c_int as isize), 21 as libc::c_int);
    *v.offset(1 as libc::c_int as isize) ^= *v.offset(2 as libc::c_int as isize);
    *v.offset(3 as libc::c_int as isize) ^= *v.offset(0 as libc::c_int as isize);
    *v
        .offset(
            2 as libc::c_int as isize,
        ) = CRYPTO_rotl_u64(*v.offset(2 as libc::c_int as isize), 32 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn SIPHASH_24(
    mut key: *const uint64_t,
    mut input: *const uint8_t,
    mut input_len: size_t,
) -> uint64_t {
    let orig_input_len: size_t = input_len;
    let mut v: [uint64_t; 4] = [0; 4];
    let mut k0: uint64_t = 0;
    let mut k1: uint64_t = 0;
    k0 = *key.offset(0 as libc::c_int as isize);
    k1 = *key.offset(1 as libc::c_int as isize);
    v[0 as libc::c_int as usize] = k0 ^ 0x736f6d6570736575 as libc::c_ulong;
    v[1 as libc::c_int as usize] = k1 ^ 0x646f72616e646f6d as libc::c_ulong;
    v[2 as libc::c_int as usize] = k0 ^ 0x6c7967656e657261 as libc::c_ulong;
    v[3 as libc::c_int as usize] = k1 ^ 0x7465646279746573 as libc::c_ulong;
    while input_len >= ::core::mem::size_of::<uint64_t>() as libc::c_ulong {
        let mut m: uint64_t = CRYPTO_load_u64_le(input as *const libc::c_void);
        v[3 as libc::c_int as usize] ^= m;
        siphash_round(v.as_mut_ptr());
        siphash_round(v.as_mut_ptr());
        v[0 as libc::c_int as usize] ^= m;
        input = input
            .offset(::core::mem::size_of::<uint64_t>() as libc::c_ulong as isize);
        input_len = (input_len as libc::c_ulong)
            .wrapping_sub(::core::mem::size_of::<uint64_t>() as libc::c_ulong) as size_t
            as size_t;
    }
    let mut last_block: [uint8_t; 8] = [0; 8];
    OPENSSL_memset(
        last_block.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[uint8_t; 8]>() as libc::c_ulong,
    );
    OPENSSL_memcpy(
        last_block.as_mut_ptr() as *mut libc::c_void,
        input as *const libc::c_void,
        input_len,
    );
    last_block[7 as libc::c_int
        as usize] = (orig_input_len & 0xff as libc::c_int as size_t) as uint8_t;
    let mut last_block_word: uint64_t = CRYPTO_load_u64_le(
        last_block.as_mut_ptr() as *const libc::c_void,
    );
    v[3 as libc::c_int as usize] ^= last_block_word;
    siphash_round(v.as_mut_ptr());
    siphash_round(v.as_mut_ptr());
    v[0 as libc::c_int as usize] ^= last_block_word;
    v[2 as libc::c_int as usize] ^= 0xff as libc::c_int as uint64_t;
    siphash_round(v.as_mut_ptr());
    siphash_round(v.as_mut_ptr());
    siphash_round(v.as_mut_ptr());
    siphash_round(v.as_mut_ptr());
    return v[0 as libc::c_int as usize] ^ v[1 as libc::c_int as usize]
        ^ v[2 as libc::c_int as usize] ^ v[3 as libc::c_int as usize];
}
