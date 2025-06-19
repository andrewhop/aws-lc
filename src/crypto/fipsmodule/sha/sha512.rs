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
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sha512_state_st {
    pub h: [uint64_t; 8],
    pub Nl: uint64_t,
    pub Nh: uint64_t,
    pub p: [uint8_t; 128],
    pub num: libc::c_uint,
    pub md_len: libc::c_uint,
}
pub type SHA512_CTX = sha512_state_st;
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
#[inline]
unsafe extern "C" fn CRYPTO_rotr_u64(
    mut value: uint64_t,
    mut shift: libc::c_int,
) -> uint64_t {
    return value >> shift | value << (-shift & 63 as libc::c_int);
}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_update_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_lock_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_unlock_state() {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA384_Init(mut sha: *mut SHA512_CTX) -> libc::c_int {
    (*sha).h[0 as libc::c_int as usize] = 0xcbbb9d5dc1059ed8 as libc::c_ulong;
    (*sha).h[1 as libc::c_int as usize] = 0x629a292a367cd507 as libc::c_ulong;
    (*sha).h[2 as libc::c_int as usize] = 0x9159015a3070dd17 as libc::c_ulong;
    (*sha).h[3 as libc::c_int as usize] = 0x152fecd8f70e5939 as libc::c_ulong;
    (*sha).h[4 as libc::c_int as usize] = 0x67332667ffc00b31 as libc::c_ulong;
    (*sha).h[5 as libc::c_int as usize] = 0x8eb44a8768581511 as libc::c_ulong;
    (*sha).h[6 as libc::c_int as usize] = 0xdb0c2e0d64f98fa7 as libc::c_ulong;
    (*sha).h[7 as libc::c_int as usize] = 0x47b5481dbefa4fa4 as libc::c_ulong;
    (*sha).Nl = 0 as libc::c_int as uint64_t;
    (*sha).Nh = 0 as libc::c_int as uint64_t;
    (*sha).num = 0 as libc::c_int as libc::c_uint;
    (*sha).md_len = 48 as libc::c_int as libc::c_uint;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA512_Init(mut sha: *mut SHA512_CTX) -> libc::c_int {
    (*sha).h[0 as libc::c_int as usize] = 0x6a09e667f3bcc908 as libc::c_ulong;
    (*sha).h[1 as libc::c_int as usize] = 0xbb67ae8584caa73b as libc::c_ulong;
    (*sha).h[2 as libc::c_int as usize] = 0x3c6ef372fe94f82b as libc::c_ulong;
    (*sha).h[3 as libc::c_int as usize] = 0xa54ff53a5f1d36f1 as libc::c_ulong;
    (*sha).h[4 as libc::c_int as usize] = 0x510e527fade682d1 as libc::c_ulong;
    (*sha).h[5 as libc::c_int as usize] = 0x9b05688c2b3e6c1f as libc::c_ulong;
    (*sha).h[6 as libc::c_int as usize] = 0x1f83d9abfb41bd6b as libc::c_ulong;
    (*sha).h[7 as libc::c_int as usize] = 0x5be0cd19137e2179 as libc::c_ulong;
    (*sha).Nl = 0 as libc::c_int as uint64_t;
    (*sha).Nh = 0 as libc::c_int as uint64_t;
    (*sha).num = 0 as libc::c_int as libc::c_uint;
    (*sha).md_len = 64 as libc::c_int as libc::c_uint;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA512_224_Init(mut sha: *mut SHA512_CTX) -> libc::c_int {
    (*sha).h[0 as libc::c_int as usize] = 0x8c3d37c819544da2 as libc::c_ulong;
    (*sha).h[1 as libc::c_int as usize] = 0x73e1996689dcd4d6 as libc::c_ulong;
    (*sha).h[2 as libc::c_int as usize] = 0x1dfab7ae32ff9c82 as libc::c_ulong;
    (*sha).h[3 as libc::c_int as usize] = 0x679dd514582f9fcf as libc::c_ulong;
    (*sha).h[4 as libc::c_int as usize] = 0xf6d2b697bd44da8 as libc::c_ulong;
    (*sha).h[5 as libc::c_int as usize] = 0x77e36f7304c48942 as libc::c_ulong;
    (*sha).h[6 as libc::c_int as usize] = 0x3f9d85a86a1d36c8 as libc::c_ulong;
    (*sha).h[7 as libc::c_int as usize] = 0x1112e6ad91d692a1 as libc::c_ulong;
    (*sha).Nl = 0 as libc::c_int as uint64_t;
    (*sha).Nh = 0 as libc::c_int as uint64_t;
    (*sha).num = 0 as libc::c_int as libc::c_uint;
    (*sha).md_len = 28 as libc::c_int as libc::c_uint;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA512_256_Init(mut sha: *mut SHA512_CTX) -> libc::c_int {
    (*sha).h[0 as libc::c_int as usize] = 0x22312194fc2bf72c as libc::c_ulong;
    (*sha).h[1 as libc::c_int as usize] = 0x9f555fa3c84c64c2 as libc::c_ulong;
    (*sha).h[2 as libc::c_int as usize] = 0x2393b86b6f53b151 as libc::c_ulong;
    (*sha).h[3 as libc::c_int as usize] = 0x963877195940eabd as libc::c_ulong;
    (*sha).h[4 as libc::c_int as usize] = 0x96283ee2a88effe3 as libc::c_ulong;
    (*sha).h[5 as libc::c_int as usize] = 0xbe5e1e2553863992 as libc::c_ulong;
    (*sha).h[6 as libc::c_int as usize] = 0x2b0199fc2c85b8aa as libc::c_ulong;
    (*sha).h[7 as libc::c_int as usize] = 0xeb72ddc81c52ca2 as libc::c_ulong;
    (*sha).Nl = 0 as libc::c_int as uint64_t;
    (*sha).Nh = 0 as libc::c_int as uint64_t;
    (*sha).num = 0 as libc::c_int as libc::c_uint;
    (*sha).md_len = 32 as libc::c_int as libc::c_uint;
    return 1 as libc::c_int;
}
unsafe extern "C" fn sha512_init_from_state_impl(
    mut sha: *mut SHA512_CTX,
    mut md_len: libc::c_int,
    mut h: *const uint8_t,
    mut n: uint64_t,
) -> libc::c_int {
    if n % (128 as libc::c_int as uint64_t * 8 as libc::c_int as uint64_t)
        != 0 as libc::c_int as uint64_t
    {
        return 0 as libc::c_int;
    }
    OPENSSL_memset(
        sha as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<SHA512_CTX>() as libc::c_ulong,
    );
    (*sha).md_len = md_len as libc::c_uint;
    let out_words: size_t = (64 as libc::c_int / 8 as libc::c_int) as size_t;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < out_words {
        (*sha).h[i as usize] = CRYPTO_load_u64_be(h as *const libc::c_void);
        h = h.offset(8 as libc::c_int as isize);
        i = i.wrapping_add(1);
        i;
    }
    (*sha).Nh = 0 as libc::c_int as uint64_t;
    (*sha).Nl = n;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA384_Init_from_state(
    mut sha: *mut SHA512_CTX,
    mut h: *const uint8_t,
    mut n: uint64_t,
) -> libc::c_int {
    return sha512_init_from_state_impl(sha, 48 as libc::c_int, h, n);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA512_Init_from_state(
    mut sha: *mut SHA512_CTX,
    mut h: *const uint8_t,
    mut n: uint64_t,
) -> libc::c_int {
    return sha512_init_from_state_impl(sha, 64 as libc::c_int, h, n);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA512_224_Init_from_state(
    mut sha: *mut SHA512_CTX,
    mut h: *const uint8_t,
    mut n: uint64_t,
) -> libc::c_int {
    return sha512_init_from_state_impl(sha, 28 as libc::c_int, h, n);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA512_256_Init_from_state(
    mut sha: *mut SHA512_CTX,
    mut h: *const uint8_t,
    mut n: uint64_t,
) -> libc::c_int {
    return sha512_init_from_state_impl(sha, 32 as libc::c_int, h, n);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA384(
    mut data: *const uint8_t,
    mut len: size_t,
    mut out: *mut uint8_t,
) -> *mut uint8_t {
    FIPS_service_indicator_lock_state();
    let mut ctx: SHA512_CTX = sha512_state_st {
        h: [0; 8],
        Nl: 0,
        Nh: 0,
        p: [0; 128],
        num: 0,
        md_len: 0,
    };
    let ok: libc::c_int = (SHA384_Init(&mut ctx) != 0
        && SHA384_Update(&mut ctx, data as *const libc::c_void, len) != 0
        && SHA384_Final(out, &mut ctx) != 0) as libc::c_int;
    FIPS_service_indicator_unlock_state();
    if ok != 0 {
        FIPS_service_indicator_update_state();
    }
    OPENSSL_cleanse(
        &mut ctx as *mut SHA512_CTX as *mut libc::c_void,
        ::core::mem::size_of::<SHA512_CTX>() as libc::c_ulong,
    );
    return out;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA512(
    mut data: *const uint8_t,
    mut len: size_t,
    mut out: *mut uint8_t,
) -> *mut uint8_t {
    FIPS_service_indicator_lock_state();
    let mut ctx: SHA512_CTX = sha512_state_st {
        h: [0; 8],
        Nl: 0,
        Nh: 0,
        p: [0; 128],
        num: 0,
        md_len: 0,
    };
    let ok: libc::c_int = (SHA512_Init(&mut ctx) != 0
        && SHA512_Update(&mut ctx, data as *const libc::c_void, len) != 0
        && SHA512_Final(out, &mut ctx) != 0) as libc::c_int;
    FIPS_service_indicator_unlock_state();
    if ok != 0 {
        FIPS_service_indicator_update_state();
    }
    OPENSSL_cleanse(
        &mut ctx as *mut SHA512_CTX as *mut libc::c_void,
        ::core::mem::size_of::<SHA512_CTX>() as libc::c_ulong,
    );
    return out;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA512_224(
    mut data: *const uint8_t,
    mut len: size_t,
    mut out: *mut uint8_t,
) -> *mut uint8_t {
    FIPS_service_indicator_lock_state();
    let mut ctx: SHA512_CTX = sha512_state_st {
        h: [0; 8],
        Nl: 0,
        Nh: 0,
        p: [0; 128],
        num: 0,
        md_len: 0,
    };
    let ok: libc::c_int = (SHA512_224_Init(&mut ctx) != 0
        && SHA512_224_Update(&mut ctx, data as *const libc::c_void, len) != 0
        && SHA512_224_Final(out, &mut ctx) != 0) as libc::c_int;
    FIPS_service_indicator_unlock_state();
    if ok != 0 {
        FIPS_service_indicator_update_state();
    }
    OPENSSL_cleanse(
        &mut ctx as *mut SHA512_CTX as *mut libc::c_void,
        ::core::mem::size_of::<SHA512_CTX>() as libc::c_ulong,
    );
    return out;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA512_256(
    mut data: *const uint8_t,
    mut len: size_t,
    mut out: *mut uint8_t,
) -> *mut uint8_t {
    FIPS_service_indicator_lock_state();
    let mut ctx: SHA512_CTX = sha512_state_st {
        h: [0; 8],
        Nl: 0,
        Nh: 0,
        p: [0; 128],
        num: 0,
        md_len: 0,
    };
    let ok: libc::c_int = (SHA512_256_Init(&mut ctx) != 0
        && SHA512_256_Update(&mut ctx, data as *const libc::c_void, len) != 0
        && SHA512_256_Final(out, &mut ctx) != 0) as libc::c_int;
    FIPS_service_indicator_unlock_state();
    if ok != 0 {
        FIPS_service_indicator_update_state();
    }
    OPENSSL_cleanse(
        &mut ctx as *mut SHA512_CTX as *mut libc::c_void,
        ::core::mem::size_of::<SHA512_CTX>() as libc::c_ulong,
    );
    return out;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA384_Final(
    mut out: *mut uint8_t,
    mut sha: *mut SHA512_CTX,
) -> libc::c_int {
    if (*sha).md_len == 48 as libc::c_int as libc::c_uint {} else {
        __assert_fail(
            b"sha->md_len == SHA384_DIGEST_LENGTH\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/sha/sha512.c\0"
                as *const u8 as *const libc::c_char,
            279 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 42],
                &[libc::c_char; 42],
            >(b"int SHA384_Final(uint8_t *, SHA512_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_8554: {
        if (*sha).md_len == 48 as libc::c_int as libc::c_uint {} else {
            __assert_fail(
                b"sha->md_len == SHA384_DIGEST_LENGTH\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/sha/sha512.c\0"
                    as *const u8 as *const libc::c_char,
                279 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 42],
                    &[libc::c_char; 42],
                >(b"int SHA384_Final(uint8_t *, SHA512_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    return sha512_final_impl(out, 48 as libc::c_int as size_t, sha);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA384_Update(
    mut sha: *mut SHA512_CTX,
    mut data: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    return SHA512_Update(sha, data, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA512_224_Update(
    mut sha: *mut SHA512_CTX,
    mut data: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    return SHA512_Update(sha, data, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA512_224_Final(
    mut out: *mut uint8_t,
    mut sha: *mut SHA512_CTX,
) -> libc::c_int {
    if (*sha).md_len == 28 as libc::c_int as libc::c_uint {} else {
        __assert_fail(
            b"sha->md_len == SHA512_224_DIGEST_LENGTH\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/sha/sha512.c\0"
                as *const u8 as *const libc::c_char,
            294 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 46],
                &[libc::c_char; 46],
            >(b"int SHA512_224_Final(uint8_t *, SHA512_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_9016: {
        if (*sha).md_len == 28 as libc::c_int as libc::c_uint {} else {
            __assert_fail(
                b"sha->md_len == SHA512_224_DIGEST_LENGTH\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/sha/sha512.c\0"
                    as *const u8 as *const libc::c_char,
                294 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 46],
                    &[libc::c_char; 46],
                >(b"int SHA512_224_Final(uint8_t *, SHA512_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    return sha512_final_impl(out, 28 as libc::c_int as size_t, sha);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA512_256_Update(
    mut sha: *mut SHA512_CTX,
    mut data: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    return SHA512_Update(sha, data, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA512_256_Final(
    mut out: *mut uint8_t,
    mut sha: *mut SHA512_CTX,
) -> libc::c_int {
    if (*sha).md_len == 32 as libc::c_int as libc::c_uint {} else {
        __assert_fail(
            b"sha->md_len == SHA512_256_DIGEST_LENGTH\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/sha/sha512.c\0"
                as *const u8 as *const libc::c_char,
            305 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 46],
                &[libc::c_char; 46],
            >(b"int SHA512_256_Final(uint8_t *, SHA512_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_9260: {
        if (*sha).md_len == 32 as libc::c_int as libc::c_uint {} else {
            __assert_fail(
                b"sha->md_len == SHA512_256_DIGEST_LENGTH\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/sha/sha512.c\0"
                    as *const u8 as *const libc::c_char,
                305 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 46],
                    &[libc::c_char; 46],
                >(b"int SHA512_256_Final(uint8_t *, SHA512_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    return sha512_final_impl(out, 32 as libc::c_int as size_t, sha);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA512_Transform(
    mut c: *mut SHA512_CTX,
    mut block: *const uint8_t,
) {
    sha512_block_data_order(((*c).h).as_mut_ptr(), block, 1 as libc::c_int as size_t);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA512_Update(
    mut c: *mut SHA512_CTX,
    mut in_data: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    let mut l: uint64_t = 0;
    let mut p: *mut uint8_t = ((*c).p).as_mut_ptr();
    let mut data: *const uint8_t = in_data as *const uint8_t;
    if len == 0 as libc::c_int as size_t {
        return 1 as libc::c_int;
    }
    l = ((*c).Nl).wrapping_add(len << 3 as libc::c_int)
        & 0xffffffffffffffff as libc::c_ulong;
    if l < (*c).Nl {
        (*c).Nh = ((*c).Nh).wrapping_add(1);
        (*c).Nh;
    }
    if ::core::mem::size_of::<size_t>() as libc::c_ulong
        >= 8 as libc::c_int as libc::c_ulong
    {
        (*c).Nh = ((*c).Nh).wrapping_add(len >> 61 as libc::c_int);
    }
    (*c).Nl = l;
    if (*c).num != 0 as libc::c_int as libc::c_uint {
        let mut n: size_t = (::core::mem::size_of::<[uint8_t; 128]>() as libc::c_ulong)
            .wrapping_sub((*c).num as libc::c_ulong);
        if len < n {
            OPENSSL_memcpy(
                p.offset((*c).num as isize) as *mut libc::c_void,
                data as *const libc::c_void,
                len,
            );
            (*c).num = ((*c).num).wrapping_add(len as libc::c_uint);
            return 1 as libc::c_int;
        } else {
            OPENSSL_memcpy(
                p.offset((*c).num as isize) as *mut libc::c_void,
                data as *const libc::c_void,
                n,
            );
            (*c).num = 0 as libc::c_int as libc::c_uint;
            len = len.wrapping_sub(n);
            data = data.offset(n as isize);
            sha512_block_data_order(
                ((*c).h).as_mut_ptr(),
                p,
                1 as libc::c_int as size_t,
            );
        }
    }
    if len >= ::core::mem::size_of::<[uint8_t; 128]>() as libc::c_ulong {
        sha512_block_data_order(
            ((*c).h).as_mut_ptr(),
            data,
            len.wrapping_div(::core::mem::size_of::<[uint8_t; 128]>() as libc::c_ulong),
        );
        data = data.offset(len as isize);
        len = (len as libc::c_ulong)
            .wrapping_rem(::core::mem::size_of::<[uint8_t; 128]>() as libc::c_ulong)
            as size_t as size_t;
        data = data.offset(-(len as isize));
    }
    if len != 0 as libc::c_int as size_t {
        OPENSSL_memcpy(p as *mut libc::c_void, data as *const libc::c_void, len);
        (*c).num = len as libc::c_int as libc::c_uint;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA512_Final(
    mut out: *mut uint8_t,
    mut sha: *mut SHA512_CTX,
) -> libc::c_int {
    return sha512_final_impl(out, (*sha).md_len as size_t, sha);
}
unsafe extern "C" fn sha512_final_impl(
    mut out: *mut uint8_t,
    mut md_len: size_t,
    mut sha: *mut SHA512_CTX,
) -> libc::c_int {
    let mut p: *mut uint8_t = ((*sha).p).as_mut_ptr();
    let mut n: size_t = (*sha).num as size_t;
    *p.offset(n as isize) = 0x80 as libc::c_int as uint8_t;
    n = n.wrapping_add(1);
    n;
    if n
        > (::core::mem::size_of::<[uint8_t; 128]>() as libc::c_ulong)
            .wrapping_sub(16 as libc::c_int as libc::c_ulong)
    {
        OPENSSL_memset(
            p.offset(n as isize) as *mut libc::c_void,
            0 as libc::c_int,
            (::core::mem::size_of::<[uint8_t; 128]>() as libc::c_ulong).wrapping_sub(n),
        );
        n = 0 as libc::c_int as size_t;
        sha512_block_data_order(((*sha).h).as_mut_ptr(), p, 1 as libc::c_int as size_t);
    }
    OPENSSL_memset(
        p.offset(n as isize) as *mut libc::c_void,
        0 as libc::c_int,
        (::core::mem::size_of::<[uint8_t; 128]>() as libc::c_ulong)
            .wrapping_sub(16 as libc::c_int as libc::c_ulong)
            .wrapping_sub(n),
    );
    CRYPTO_store_u64_be(
        p
            .offset(::core::mem::size_of::<[uint8_t; 128]>() as libc::c_ulong as isize)
            .offset(-(16 as libc::c_int as isize)) as *mut libc::c_void,
        (*sha).Nh,
    );
    CRYPTO_store_u64_be(
        p
            .offset(::core::mem::size_of::<[uint8_t; 128]>() as libc::c_ulong as isize)
            .offset(-(8 as libc::c_int as isize)) as *mut libc::c_void,
        (*sha).Nl,
    );
    sha512_block_data_order(((*sha).h).as_mut_ptr(), p, 1 as libc::c_int as size_t);
    if out.is_null() {
        return 0 as libc::c_int;
    }
    let out_words: size_t = md_len / 8 as libc::c_int as size_t;
    if md_len % 8 as libc::c_int as size_t == 0 as libc::c_int as size_t
        || md_len == 28 as libc::c_int as size_t
    {} else {
        __assert_fail(
            b"md_len % 8 == 0 || md_len == SHA512_224_DIGEST_LENGTH\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/sha/sha512.c\0"
                as *const u8 as *const libc::c_char,
            395 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 55],
                &[libc::c_char; 55],
            >(b"int sha512_final_impl(uint8_t *, size_t, SHA512_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_8303: {
        if md_len % 8 as libc::c_int as size_t == 0 as libc::c_int as size_t
            || md_len == 28 as libc::c_int as size_t
        {} else {
            __assert_fail(
                b"md_len % 8 == 0 || md_len == SHA512_224_DIGEST_LENGTH\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/sha/sha512.c\0"
                    as *const u8 as *const libc::c_char,
                395 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 55],
                    &[libc::c_char; 55],
                >(b"int sha512_final_impl(uint8_t *, size_t, SHA512_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < out_words {
        CRYPTO_store_u64_be(out as *mut libc::c_void, (*sha).h[i as usize]);
        out = out.offset(8 as libc::c_int as isize);
        i = i.wrapping_add(1);
        i;
    }
    if md_len == 28 as libc::c_int as size_t {
        let mut trailer: uint64_t = 0;
        CRYPTO_store_u64_be(
            &mut trailer as *mut uint64_t as *mut libc::c_void,
            (*sha).h[out_words as usize],
        );
        OPENSSL_memcpy(
            out as *mut libc::c_void,
            &mut trailer as *mut uint64_t as *const libc::c_void,
            (28 as libc::c_int % 8 as libc::c_int) as size_t,
        );
    }
    FIPS_service_indicator_update_state();
    return 1 as libc::c_int;
}
unsafe extern "C" fn sha512_get_state_impl(
    mut ctx: *mut SHA512_CTX,
    mut out_h: *mut uint8_t,
    mut out_n: *mut uint64_t,
) -> libc::c_int {
    if (*ctx).Nl % (128 as libc::c_int as uint64_t * 8 as libc::c_int as uint64_t)
        != 0 as libc::c_int as uint64_t
    {
        return 0 as libc::c_int;
    }
    if (*ctx).Nh != 0 as libc::c_int as uint64_t {
        return 0 as libc::c_int;
    }
    let out_words: size_t = (64 as libc::c_int / 8 as libc::c_int) as size_t;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < out_words {
        CRYPTO_store_u64_be(out_h as *mut libc::c_void, (*ctx).h[i as usize]);
        out_h = out_h.offset(8 as libc::c_int as isize);
        i = i.wrapping_add(1);
        i;
    }
    *out_n = (*ctx).Nl;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA384_get_state(
    mut ctx: *mut SHA512_CTX,
    mut out_h: *mut uint8_t,
    mut out_n: *mut uint64_t,
) -> libc::c_int {
    return sha512_get_state_impl(ctx, out_h, out_n);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA512_get_state(
    mut ctx: *mut SHA512_CTX,
    mut out_h: *mut uint8_t,
    mut out_n: *mut uint64_t,
) -> libc::c_int {
    return sha512_get_state_impl(ctx, out_h, out_n);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA512_224_get_state(
    mut ctx: *mut SHA512_CTX,
    mut out_h: *mut uint8_t,
    mut out_n: *mut uint64_t,
) -> libc::c_int {
    return sha512_get_state_impl(ctx, out_h, out_n);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SHA512_256_get_state(
    mut ctx: *mut SHA512_CTX,
    mut out_h: *mut uint8_t,
    mut out_n: *mut uint64_t,
) -> libc::c_int {
    return sha512_get_state_impl(ctx, out_h, out_n);
}
static mut K512: [uint64_t; 80] = [
    0x428a2f98d728ae22 as libc::c_ulong,
    0x7137449123ef65cd as libc::c_ulong,
    0xb5c0fbcfec4d3b2f as libc::c_ulong,
    0xe9b5dba58189dbbc as libc::c_ulong,
    0x3956c25bf348b538 as libc::c_ulong,
    0x59f111f1b605d019 as libc::c_ulong,
    0x923f82a4af194f9b as libc::c_ulong,
    0xab1c5ed5da6d8118 as libc::c_ulong,
    0xd807aa98a3030242 as libc::c_ulong,
    0x12835b0145706fbe as libc::c_ulong,
    0x243185be4ee4b28c as libc::c_ulong,
    0x550c7dc3d5ffb4e2 as libc::c_ulong,
    0x72be5d74f27b896f as libc::c_ulong,
    0x80deb1fe3b1696b1 as libc::c_ulong,
    0x9bdc06a725c71235 as libc::c_ulong,
    0xc19bf174cf692694 as libc::c_ulong,
    0xe49b69c19ef14ad2 as libc::c_ulong,
    0xefbe4786384f25e3 as libc::c_ulong,
    0xfc19dc68b8cd5b5 as libc::c_ulong,
    0x240ca1cc77ac9c65 as libc::c_ulong,
    0x2de92c6f592b0275 as libc::c_ulong,
    0x4a7484aa6ea6e483 as libc::c_ulong,
    0x5cb0a9dcbd41fbd4 as libc::c_ulong,
    0x76f988da831153b5 as libc::c_ulong,
    0x983e5152ee66dfab as libc::c_ulong,
    0xa831c66d2db43210 as libc::c_ulong,
    0xb00327c898fb213f as libc::c_ulong,
    0xbf597fc7beef0ee4 as libc::c_ulong,
    0xc6e00bf33da88fc2 as libc::c_ulong,
    0xd5a79147930aa725 as libc::c_ulong,
    0x6ca6351e003826f as libc::c_ulong,
    0x142929670a0e6e70 as libc::c_ulong,
    0x27b70a8546d22ffc as libc::c_ulong,
    0x2e1b21385c26c926 as libc::c_ulong,
    0x4d2c6dfc5ac42aed as libc::c_ulong,
    0x53380d139d95b3df as libc::c_ulong,
    0x650a73548baf63de as libc::c_ulong,
    0x766a0abb3c77b2a8 as libc::c_ulong,
    0x81c2c92e47edaee6 as libc::c_ulong,
    0x92722c851482353b as libc::c_ulong,
    0xa2bfe8a14cf10364 as libc::c_ulong,
    0xa81a664bbc423001 as libc::c_ulong,
    0xc24b8b70d0f89791 as libc::c_ulong,
    0xc76c51a30654be30 as libc::c_ulong,
    0xd192e819d6ef5218 as libc::c_ulong,
    0xd69906245565a910 as libc::c_ulong,
    0xf40e35855771202a as libc::c_ulong,
    0x106aa07032bbd1b8 as libc::c_ulong,
    0x19a4c116b8d2d0c8 as libc::c_ulong,
    0x1e376c085141ab53 as libc::c_ulong,
    0x2748774cdf8eeb99 as libc::c_ulong,
    0x34b0bcb5e19b48a8 as libc::c_ulong,
    0x391c0cb3c5c95a63 as libc::c_ulong,
    0x4ed8aa4ae3418acb as libc::c_ulong,
    0x5b9cca4f7763e373 as libc::c_ulong,
    0x682e6ff3d6b2b8a3 as libc::c_ulong,
    0x748f82ee5defb2fc as libc::c_ulong,
    0x78a5636f43172f60 as libc::c_ulong,
    0x84c87814a1f0ab72 as libc::c_ulong,
    0x8cc702081a6439ec as libc::c_ulong,
    0x90befffa23631e28 as libc::c_ulong,
    0xa4506cebde82bde9 as libc::c_ulong,
    0xbef9a3f7b2c67915 as libc::c_ulong,
    0xc67178f2e372532b as libc::c_ulong,
    0xca273eceea26619c as libc::c_ulong,
    0xd186b8c721c0c207 as libc::c_ulong,
    0xeada7dd6cde0eb1e as libc::c_ulong,
    0xf57d4f7fee6ed178 as libc::c_ulong,
    0x6f067aa72176fba as libc::c_ulong,
    0xa637dc5a2c898a6 as libc::c_ulong,
    0x113f9804bef90dae as libc::c_ulong,
    0x1b710b35131c471b as libc::c_ulong,
    0x28db77f523047d84 as libc::c_ulong,
    0x32caab7b40c72493 as libc::c_ulong,
    0x3c9ebe0a15c9bebc as libc::c_ulong,
    0x431d67c49c100d4c as libc::c_ulong,
    0x4cc5d4becb3e42b6 as libc::c_ulong,
    0x597f299cfc657e2a as libc::c_ulong,
    0x5fcb6fab3ad6faec as libc::c_ulong,
    0x6c44198c4a475817 as libc::c_ulong,
];
unsafe extern "C" fn sha512_block_data_order_nohw(
    mut state: *mut uint64_t,
    mut in_0: *const uint8_t,
    mut num: size_t,
) {
    let mut a: uint64_t = 0;
    let mut b: uint64_t = 0;
    let mut c: uint64_t = 0;
    let mut d: uint64_t = 0;
    let mut e: uint64_t = 0;
    let mut f: uint64_t = 0;
    let mut g: uint64_t = 0;
    let mut h: uint64_t = 0;
    let mut s0: uint64_t = 0;
    let mut s1: uint64_t = 0;
    let mut T1: uint64_t = 0;
    let mut X: [uint64_t; 16] = [0; 16];
    let mut i: libc::c_int = 0;
    loop {
        let fresh0 = num;
        num = num.wrapping_sub(1);
        if !(fresh0 != 0) {
            break;
        }
        a = *state.offset(0 as libc::c_int as isize);
        b = *state.offset(1 as libc::c_int as isize);
        c = *state.offset(2 as libc::c_int as isize);
        d = *state.offset(3 as libc::c_int as isize);
        e = *state.offset(4 as libc::c_int as isize);
        f = *state.offset(5 as libc::c_int as isize);
        g = *state.offset(6 as libc::c_int as isize);
        h = *state.offset(7 as libc::c_int as isize);
        X[0 as libc::c_int as usize] = CRYPTO_load_u64_be(in_0 as *const libc::c_void);
        T1 = X[0 as libc::c_int as usize];
        T1 = T1
            .wrapping_add(
                h
                    .wrapping_add(
                        CRYPTO_rotr_u64(e, 14 as libc::c_int)
                            ^ CRYPTO_rotr_u64(e, 18 as libc::c_int)
                            ^ CRYPTO_rotr_u64(e, 41 as libc::c_int),
                    )
                    .wrapping_add(e & f ^ !e & g)
                    .wrapping_add(K512[0 as libc::c_int as usize]),
            );
        h = (CRYPTO_rotr_u64(a, 28 as libc::c_int)
            ^ CRYPTO_rotr_u64(a, 34 as libc::c_int)
            ^ CRYPTO_rotr_u64(a, 39 as libc::c_int))
            .wrapping_add(a & b ^ a & c ^ b & c);
        d = d.wrapping_add(T1);
        h = h.wrapping_add(T1);
        X[1 as libc::c_int
            as usize] = CRYPTO_load_u64_be(
            in_0.offset(8 as libc::c_int as isize) as *const libc::c_void,
        );
        T1 = X[1 as libc::c_int as usize];
        T1 = T1
            .wrapping_add(
                g
                    .wrapping_add(
                        CRYPTO_rotr_u64(d, 14 as libc::c_int)
                            ^ CRYPTO_rotr_u64(d, 18 as libc::c_int)
                            ^ CRYPTO_rotr_u64(d, 41 as libc::c_int),
                    )
                    .wrapping_add(d & e ^ !d & f)
                    .wrapping_add(K512[1 as libc::c_int as usize]),
            );
        g = (CRYPTO_rotr_u64(h, 28 as libc::c_int)
            ^ CRYPTO_rotr_u64(h, 34 as libc::c_int)
            ^ CRYPTO_rotr_u64(h, 39 as libc::c_int))
            .wrapping_add(h & a ^ h & b ^ a & b);
        c = c.wrapping_add(T1);
        g = g.wrapping_add(T1);
        X[2 as libc::c_int
            as usize] = CRYPTO_load_u64_be(
            in_0.offset((2 as libc::c_int * 8 as libc::c_int) as isize)
                as *const libc::c_void,
        );
        T1 = X[2 as libc::c_int as usize];
        T1 = T1
            .wrapping_add(
                f
                    .wrapping_add(
                        CRYPTO_rotr_u64(c, 14 as libc::c_int)
                            ^ CRYPTO_rotr_u64(c, 18 as libc::c_int)
                            ^ CRYPTO_rotr_u64(c, 41 as libc::c_int),
                    )
                    .wrapping_add(c & d ^ !c & e)
                    .wrapping_add(K512[2 as libc::c_int as usize]),
            );
        f = (CRYPTO_rotr_u64(g, 28 as libc::c_int)
            ^ CRYPTO_rotr_u64(g, 34 as libc::c_int)
            ^ CRYPTO_rotr_u64(g, 39 as libc::c_int))
            .wrapping_add(g & h ^ g & a ^ h & a);
        b = b.wrapping_add(T1);
        f = f.wrapping_add(T1);
        X[3 as libc::c_int
            as usize] = CRYPTO_load_u64_be(
            in_0.offset((3 as libc::c_int * 8 as libc::c_int) as isize)
                as *const libc::c_void,
        );
        T1 = X[3 as libc::c_int as usize];
        T1 = T1
            .wrapping_add(
                e
                    .wrapping_add(
                        CRYPTO_rotr_u64(b, 14 as libc::c_int)
                            ^ CRYPTO_rotr_u64(b, 18 as libc::c_int)
                            ^ CRYPTO_rotr_u64(b, 41 as libc::c_int),
                    )
                    .wrapping_add(b & c ^ !b & d)
                    .wrapping_add(K512[3 as libc::c_int as usize]),
            );
        e = (CRYPTO_rotr_u64(f, 28 as libc::c_int)
            ^ CRYPTO_rotr_u64(f, 34 as libc::c_int)
            ^ CRYPTO_rotr_u64(f, 39 as libc::c_int))
            .wrapping_add(f & g ^ f & h ^ g & h);
        a = a.wrapping_add(T1);
        e = e.wrapping_add(T1);
        X[4 as libc::c_int
            as usize] = CRYPTO_load_u64_be(
            in_0.offset((4 as libc::c_int * 8 as libc::c_int) as isize)
                as *const libc::c_void,
        );
        T1 = X[4 as libc::c_int as usize];
        T1 = T1
            .wrapping_add(
                d
                    .wrapping_add(
                        CRYPTO_rotr_u64(a, 14 as libc::c_int)
                            ^ CRYPTO_rotr_u64(a, 18 as libc::c_int)
                            ^ CRYPTO_rotr_u64(a, 41 as libc::c_int),
                    )
                    .wrapping_add(a & b ^ !a & c)
                    .wrapping_add(K512[4 as libc::c_int as usize]),
            );
        d = (CRYPTO_rotr_u64(e, 28 as libc::c_int)
            ^ CRYPTO_rotr_u64(e, 34 as libc::c_int)
            ^ CRYPTO_rotr_u64(e, 39 as libc::c_int))
            .wrapping_add(e & f ^ e & g ^ f & g);
        h = h.wrapping_add(T1);
        d = d.wrapping_add(T1);
        X[5 as libc::c_int
            as usize] = CRYPTO_load_u64_be(
            in_0.offset((5 as libc::c_int * 8 as libc::c_int) as isize)
                as *const libc::c_void,
        );
        T1 = X[5 as libc::c_int as usize];
        T1 = T1
            .wrapping_add(
                c
                    .wrapping_add(
                        CRYPTO_rotr_u64(h, 14 as libc::c_int)
                            ^ CRYPTO_rotr_u64(h, 18 as libc::c_int)
                            ^ CRYPTO_rotr_u64(h, 41 as libc::c_int),
                    )
                    .wrapping_add(h & a ^ !h & b)
                    .wrapping_add(K512[5 as libc::c_int as usize]),
            );
        c = (CRYPTO_rotr_u64(d, 28 as libc::c_int)
            ^ CRYPTO_rotr_u64(d, 34 as libc::c_int)
            ^ CRYPTO_rotr_u64(d, 39 as libc::c_int))
            .wrapping_add(d & e ^ d & f ^ e & f);
        g = g.wrapping_add(T1);
        c = c.wrapping_add(T1);
        X[6 as libc::c_int
            as usize] = CRYPTO_load_u64_be(
            in_0.offset((6 as libc::c_int * 8 as libc::c_int) as isize)
                as *const libc::c_void,
        );
        T1 = X[6 as libc::c_int as usize];
        T1 = T1
            .wrapping_add(
                b
                    .wrapping_add(
                        CRYPTO_rotr_u64(g, 14 as libc::c_int)
                            ^ CRYPTO_rotr_u64(g, 18 as libc::c_int)
                            ^ CRYPTO_rotr_u64(g, 41 as libc::c_int),
                    )
                    .wrapping_add(g & h ^ !g & a)
                    .wrapping_add(K512[6 as libc::c_int as usize]),
            );
        b = (CRYPTO_rotr_u64(c, 28 as libc::c_int)
            ^ CRYPTO_rotr_u64(c, 34 as libc::c_int)
            ^ CRYPTO_rotr_u64(c, 39 as libc::c_int))
            .wrapping_add(c & d ^ c & e ^ d & e);
        f = f.wrapping_add(T1);
        b = b.wrapping_add(T1);
        X[7 as libc::c_int
            as usize] = CRYPTO_load_u64_be(
            in_0.offset((7 as libc::c_int * 8 as libc::c_int) as isize)
                as *const libc::c_void,
        );
        T1 = X[7 as libc::c_int as usize];
        T1 = T1
            .wrapping_add(
                a
                    .wrapping_add(
                        CRYPTO_rotr_u64(f, 14 as libc::c_int)
                            ^ CRYPTO_rotr_u64(f, 18 as libc::c_int)
                            ^ CRYPTO_rotr_u64(f, 41 as libc::c_int),
                    )
                    .wrapping_add(f & g ^ !f & h)
                    .wrapping_add(K512[7 as libc::c_int as usize]),
            );
        a = (CRYPTO_rotr_u64(b, 28 as libc::c_int)
            ^ CRYPTO_rotr_u64(b, 34 as libc::c_int)
            ^ CRYPTO_rotr_u64(b, 39 as libc::c_int))
            .wrapping_add(b & c ^ b & d ^ c & d);
        e = e.wrapping_add(T1);
        a = a.wrapping_add(T1);
        X[8 as libc::c_int
            as usize] = CRYPTO_load_u64_be(
            in_0.offset((8 as libc::c_int * 8 as libc::c_int) as isize)
                as *const libc::c_void,
        );
        T1 = X[8 as libc::c_int as usize];
        T1 = T1
            .wrapping_add(
                h
                    .wrapping_add(
                        CRYPTO_rotr_u64(e, 14 as libc::c_int)
                            ^ CRYPTO_rotr_u64(e, 18 as libc::c_int)
                            ^ CRYPTO_rotr_u64(e, 41 as libc::c_int),
                    )
                    .wrapping_add(e & f ^ !e & g)
                    .wrapping_add(K512[8 as libc::c_int as usize]),
            );
        h = (CRYPTO_rotr_u64(a, 28 as libc::c_int)
            ^ CRYPTO_rotr_u64(a, 34 as libc::c_int)
            ^ CRYPTO_rotr_u64(a, 39 as libc::c_int))
            .wrapping_add(a & b ^ a & c ^ b & c);
        d = d.wrapping_add(T1);
        h = h.wrapping_add(T1);
        X[9 as libc::c_int
            as usize] = CRYPTO_load_u64_be(
            in_0.offset((9 as libc::c_int * 8 as libc::c_int) as isize)
                as *const libc::c_void,
        );
        T1 = X[9 as libc::c_int as usize];
        T1 = T1
            .wrapping_add(
                g
                    .wrapping_add(
                        CRYPTO_rotr_u64(d, 14 as libc::c_int)
                            ^ CRYPTO_rotr_u64(d, 18 as libc::c_int)
                            ^ CRYPTO_rotr_u64(d, 41 as libc::c_int),
                    )
                    .wrapping_add(d & e ^ !d & f)
                    .wrapping_add(K512[9 as libc::c_int as usize]),
            );
        g = (CRYPTO_rotr_u64(h, 28 as libc::c_int)
            ^ CRYPTO_rotr_u64(h, 34 as libc::c_int)
            ^ CRYPTO_rotr_u64(h, 39 as libc::c_int))
            .wrapping_add(h & a ^ h & b ^ a & b);
        c = c.wrapping_add(T1);
        g = g.wrapping_add(T1);
        X[10 as libc::c_int
            as usize] = CRYPTO_load_u64_be(
            in_0.offset((10 as libc::c_int * 8 as libc::c_int) as isize)
                as *const libc::c_void,
        );
        T1 = X[10 as libc::c_int as usize];
        T1 = T1
            .wrapping_add(
                f
                    .wrapping_add(
                        CRYPTO_rotr_u64(c, 14 as libc::c_int)
                            ^ CRYPTO_rotr_u64(c, 18 as libc::c_int)
                            ^ CRYPTO_rotr_u64(c, 41 as libc::c_int),
                    )
                    .wrapping_add(c & d ^ !c & e)
                    .wrapping_add(K512[10 as libc::c_int as usize]),
            );
        f = (CRYPTO_rotr_u64(g, 28 as libc::c_int)
            ^ CRYPTO_rotr_u64(g, 34 as libc::c_int)
            ^ CRYPTO_rotr_u64(g, 39 as libc::c_int))
            .wrapping_add(g & h ^ g & a ^ h & a);
        b = b.wrapping_add(T1);
        f = f.wrapping_add(T1);
        X[11 as libc::c_int
            as usize] = CRYPTO_load_u64_be(
            in_0.offset((11 as libc::c_int * 8 as libc::c_int) as isize)
                as *const libc::c_void,
        );
        T1 = X[11 as libc::c_int as usize];
        T1 = T1
            .wrapping_add(
                e
                    .wrapping_add(
                        CRYPTO_rotr_u64(b, 14 as libc::c_int)
                            ^ CRYPTO_rotr_u64(b, 18 as libc::c_int)
                            ^ CRYPTO_rotr_u64(b, 41 as libc::c_int),
                    )
                    .wrapping_add(b & c ^ !b & d)
                    .wrapping_add(K512[11 as libc::c_int as usize]),
            );
        e = (CRYPTO_rotr_u64(f, 28 as libc::c_int)
            ^ CRYPTO_rotr_u64(f, 34 as libc::c_int)
            ^ CRYPTO_rotr_u64(f, 39 as libc::c_int))
            .wrapping_add(f & g ^ f & h ^ g & h);
        a = a.wrapping_add(T1);
        e = e.wrapping_add(T1);
        X[12 as libc::c_int
            as usize] = CRYPTO_load_u64_be(
            in_0.offset((12 as libc::c_int * 8 as libc::c_int) as isize)
                as *const libc::c_void,
        );
        T1 = X[12 as libc::c_int as usize];
        T1 = T1
            .wrapping_add(
                d
                    .wrapping_add(
                        CRYPTO_rotr_u64(a, 14 as libc::c_int)
                            ^ CRYPTO_rotr_u64(a, 18 as libc::c_int)
                            ^ CRYPTO_rotr_u64(a, 41 as libc::c_int),
                    )
                    .wrapping_add(a & b ^ !a & c)
                    .wrapping_add(K512[12 as libc::c_int as usize]),
            );
        d = (CRYPTO_rotr_u64(e, 28 as libc::c_int)
            ^ CRYPTO_rotr_u64(e, 34 as libc::c_int)
            ^ CRYPTO_rotr_u64(e, 39 as libc::c_int))
            .wrapping_add(e & f ^ e & g ^ f & g);
        h = h.wrapping_add(T1);
        d = d.wrapping_add(T1);
        X[13 as libc::c_int
            as usize] = CRYPTO_load_u64_be(
            in_0.offset((13 as libc::c_int * 8 as libc::c_int) as isize)
                as *const libc::c_void,
        );
        T1 = X[13 as libc::c_int as usize];
        T1 = T1
            .wrapping_add(
                c
                    .wrapping_add(
                        CRYPTO_rotr_u64(h, 14 as libc::c_int)
                            ^ CRYPTO_rotr_u64(h, 18 as libc::c_int)
                            ^ CRYPTO_rotr_u64(h, 41 as libc::c_int),
                    )
                    .wrapping_add(h & a ^ !h & b)
                    .wrapping_add(K512[13 as libc::c_int as usize]),
            );
        c = (CRYPTO_rotr_u64(d, 28 as libc::c_int)
            ^ CRYPTO_rotr_u64(d, 34 as libc::c_int)
            ^ CRYPTO_rotr_u64(d, 39 as libc::c_int))
            .wrapping_add(d & e ^ d & f ^ e & f);
        g = g.wrapping_add(T1);
        c = c.wrapping_add(T1);
        X[14 as libc::c_int
            as usize] = CRYPTO_load_u64_be(
            in_0.offset((14 as libc::c_int * 8 as libc::c_int) as isize)
                as *const libc::c_void,
        );
        T1 = X[14 as libc::c_int as usize];
        T1 = T1
            .wrapping_add(
                b
                    .wrapping_add(
                        CRYPTO_rotr_u64(g, 14 as libc::c_int)
                            ^ CRYPTO_rotr_u64(g, 18 as libc::c_int)
                            ^ CRYPTO_rotr_u64(g, 41 as libc::c_int),
                    )
                    .wrapping_add(g & h ^ !g & a)
                    .wrapping_add(K512[14 as libc::c_int as usize]),
            );
        b = (CRYPTO_rotr_u64(c, 28 as libc::c_int)
            ^ CRYPTO_rotr_u64(c, 34 as libc::c_int)
            ^ CRYPTO_rotr_u64(c, 39 as libc::c_int))
            .wrapping_add(c & d ^ c & e ^ d & e);
        f = f.wrapping_add(T1);
        b = b.wrapping_add(T1);
        X[15 as libc::c_int
            as usize] = CRYPTO_load_u64_be(
            in_0.offset((15 as libc::c_int * 8 as libc::c_int) as isize)
                as *const libc::c_void,
        );
        T1 = X[15 as libc::c_int as usize];
        T1 = T1
            .wrapping_add(
                a
                    .wrapping_add(
                        CRYPTO_rotr_u64(f, 14 as libc::c_int)
                            ^ CRYPTO_rotr_u64(f, 18 as libc::c_int)
                            ^ CRYPTO_rotr_u64(f, 41 as libc::c_int),
                    )
                    .wrapping_add(f & g ^ !f & h)
                    .wrapping_add(K512[15 as libc::c_int as usize]),
            );
        a = (CRYPTO_rotr_u64(b, 28 as libc::c_int)
            ^ CRYPTO_rotr_u64(b, 34 as libc::c_int)
            ^ CRYPTO_rotr_u64(b, 39 as libc::c_int))
            .wrapping_add(b & c ^ b & d ^ c & d);
        e = e.wrapping_add(T1);
        a = a.wrapping_add(T1);
        i = 16 as libc::c_int;
        while i < 80 as libc::c_int {
            s0 = X[(0 as libc::c_int + 1 as libc::c_int & 0xf as libc::c_int) as usize];
            s0 = CRYPTO_rotr_u64(s0, 1 as libc::c_int)
                ^ CRYPTO_rotr_u64(s0, 8 as libc::c_int) ^ s0 >> 7 as libc::c_int;
            s1 = X[(0 as libc::c_int + 14 as libc::c_int & 0xf as libc::c_int) as usize];
            s1 = CRYPTO_rotr_u64(s1, 19 as libc::c_int)
                ^ CRYPTO_rotr_u64(s1, 61 as libc::c_int) ^ s1 >> 6 as libc::c_int;
            X[(0 as libc::c_int & 0xf as libc::c_int)
                as usize] = (X[(0 as libc::c_int & 0xf as libc::c_int) as usize])
                .wrapping_add(
                    s0
                        .wrapping_add(s1)
                        .wrapping_add(
                            X[(0 as libc::c_int + 9 as libc::c_int & 0xf as libc::c_int)
                                as usize],
                        ),
                );
            T1 = X[(0 as libc::c_int & 0xf as libc::c_int) as usize];
            T1 = T1
                .wrapping_add(
                    h
                        .wrapping_add(
                            CRYPTO_rotr_u64(e, 14 as libc::c_int)
                                ^ CRYPTO_rotr_u64(e, 18 as libc::c_int)
                                ^ CRYPTO_rotr_u64(e, 41 as libc::c_int),
                        )
                        .wrapping_add(e & f ^ !e & g)
                        .wrapping_add(K512[(i + 0 as libc::c_int) as usize]),
                );
            h = (CRYPTO_rotr_u64(a, 28 as libc::c_int)
                ^ CRYPTO_rotr_u64(a, 34 as libc::c_int)
                ^ CRYPTO_rotr_u64(a, 39 as libc::c_int))
                .wrapping_add(a & b ^ a & c ^ b & c);
            d = d.wrapping_add(T1);
            h = h.wrapping_add(T1);
            s0 = X[(1 as libc::c_int + 1 as libc::c_int & 0xf as libc::c_int) as usize];
            s0 = CRYPTO_rotr_u64(s0, 1 as libc::c_int)
                ^ CRYPTO_rotr_u64(s0, 8 as libc::c_int) ^ s0 >> 7 as libc::c_int;
            s1 = X[(1 as libc::c_int + 14 as libc::c_int & 0xf as libc::c_int) as usize];
            s1 = CRYPTO_rotr_u64(s1, 19 as libc::c_int)
                ^ CRYPTO_rotr_u64(s1, 61 as libc::c_int) ^ s1 >> 6 as libc::c_int;
            X[(1 as libc::c_int & 0xf as libc::c_int)
                as usize] = (X[(1 as libc::c_int & 0xf as libc::c_int) as usize])
                .wrapping_add(
                    s0
                        .wrapping_add(s1)
                        .wrapping_add(
                            X[(1 as libc::c_int + 9 as libc::c_int & 0xf as libc::c_int)
                                as usize],
                        ),
                );
            T1 = X[(1 as libc::c_int & 0xf as libc::c_int) as usize];
            T1 = T1
                .wrapping_add(
                    g
                        .wrapping_add(
                            CRYPTO_rotr_u64(d, 14 as libc::c_int)
                                ^ CRYPTO_rotr_u64(d, 18 as libc::c_int)
                                ^ CRYPTO_rotr_u64(d, 41 as libc::c_int),
                        )
                        .wrapping_add(d & e ^ !d & f)
                        .wrapping_add(K512[(i + 1 as libc::c_int) as usize]),
                );
            g = (CRYPTO_rotr_u64(h, 28 as libc::c_int)
                ^ CRYPTO_rotr_u64(h, 34 as libc::c_int)
                ^ CRYPTO_rotr_u64(h, 39 as libc::c_int))
                .wrapping_add(h & a ^ h & b ^ a & b);
            c = c.wrapping_add(T1);
            g = g.wrapping_add(T1);
            s0 = X[(2 as libc::c_int + 1 as libc::c_int & 0xf as libc::c_int) as usize];
            s0 = CRYPTO_rotr_u64(s0, 1 as libc::c_int)
                ^ CRYPTO_rotr_u64(s0, 8 as libc::c_int) ^ s0 >> 7 as libc::c_int;
            s1 = X[(2 as libc::c_int + 14 as libc::c_int & 0xf as libc::c_int) as usize];
            s1 = CRYPTO_rotr_u64(s1, 19 as libc::c_int)
                ^ CRYPTO_rotr_u64(s1, 61 as libc::c_int) ^ s1 >> 6 as libc::c_int;
            X[(2 as libc::c_int & 0xf as libc::c_int)
                as usize] = (X[(2 as libc::c_int & 0xf as libc::c_int) as usize])
                .wrapping_add(
                    s0
                        .wrapping_add(s1)
                        .wrapping_add(
                            X[(2 as libc::c_int + 9 as libc::c_int & 0xf as libc::c_int)
                                as usize],
                        ),
                );
            T1 = X[(2 as libc::c_int & 0xf as libc::c_int) as usize];
            T1 = T1
                .wrapping_add(
                    f
                        .wrapping_add(
                            CRYPTO_rotr_u64(c, 14 as libc::c_int)
                                ^ CRYPTO_rotr_u64(c, 18 as libc::c_int)
                                ^ CRYPTO_rotr_u64(c, 41 as libc::c_int),
                        )
                        .wrapping_add(c & d ^ !c & e)
                        .wrapping_add(K512[(i + 2 as libc::c_int) as usize]),
                );
            f = (CRYPTO_rotr_u64(g, 28 as libc::c_int)
                ^ CRYPTO_rotr_u64(g, 34 as libc::c_int)
                ^ CRYPTO_rotr_u64(g, 39 as libc::c_int))
                .wrapping_add(g & h ^ g & a ^ h & a);
            b = b.wrapping_add(T1);
            f = f.wrapping_add(T1);
            s0 = X[(3 as libc::c_int + 1 as libc::c_int & 0xf as libc::c_int) as usize];
            s0 = CRYPTO_rotr_u64(s0, 1 as libc::c_int)
                ^ CRYPTO_rotr_u64(s0, 8 as libc::c_int) ^ s0 >> 7 as libc::c_int;
            s1 = X[(3 as libc::c_int + 14 as libc::c_int & 0xf as libc::c_int) as usize];
            s1 = CRYPTO_rotr_u64(s1, 19 as libc::c_int)
                ^ CRYPTO_rotr_u64(s1, 61 as libc::c_int) ^ s1 >> 6 as libc::c_int;
            X[(3 as libc::c_int & 0xf as libc::c_int)
                as usize] = (X[(3 as libc::c_int & 0xf as libc::c_int) as usize])
                .wrapping_add(
                    s0
                        .wrapping_add(s1)
                        .wrapping_add(
                            X[(3 as libc::c_int + 9 as libc::c_int & 0xf as libc::c_int)
                                as usize],
                        ),
                );
            T1 = X[(3 as libc::c_int & 0xf as libc::c_int) as usize];
            T1 = T1
                .wrapping_add(
                    e
                        .wrapping_add(
                            CRYPTO_rotr_u64(b, 14 as libc::c_int)
                                ^ CRYPTO_rotr_u64(b, 18 as libc::c_int)
                                ^ CRYPTO_rotr_u64(b, 41 as libc::c_int),
                        )
                        .wrapping_add(b & c ^ !b & d)
                        .wrapping_add(K512[(i + 3 as libc::c_int) as usize]),
                );
            e = (CRYPTO_rotr_u64(f, 28 as libc::c_int)
                ^ CRYPTO_rotr_u64(f, 34 as libc::c_int)
                ^ CRYPTO_rotr_u64(f, 39 as libc::c_int))
                .wrapping_add(f & g ^ f & h ^ g & h);
            a = a.wrapping_add(T1);
            e = e.wrapping_add(T1);
            s0 = X[(4 as libc::c_int + 1 as libc::c_int & 0xf as libc::c_int) as usize];
            s0 = CRYPTO_rotr_u64(s0, 1 as libc::c_int)
                ^ CRYPTO_rotr_u64(s0, 8 as libc::c_int) ^ s0 >> 7 as libc::c_int;
            s1 = X[(4 as libc::c_int + 14 as libc::c_int & 0xf as libc::c_int) as usize];
            s1 = CRYPTO_rotr_u64(s1, 19 as libc::c_int)
                ^ CRYPTO_rotr_u64(s1, 61 as libc::c_int) ^ s1 >> 6 as libc::c_int;
            X[(4 as libc::c_int & 0xf as libc::c_int)
                as usize] = (X[(4 as libc::c_int & 0xf as libc::c_int) as usize])
                .wrapping_add(
                    s0
                        .wrapping_add(s1)
                        .wrapping_add(
                            X[(4 as libc::c_int + 9 as libc::c_int & 0xf as libc::c_int)
                                as usize],
                        ),
                );
            T1 = X[(4 as libc::c_int & 0xf as libc::c_int) as usize];
            T1 = T1
                .wrapping_add(
                    d
                        .wrapping_add(
                            CRYPTO_rotr_u64(a, 14 as libc::c_int)
                                ^ CRYPTO_rotr_u64(a, 18 as libc::c_int)
                                ^ CRYPTO_rotr_u64(a, 41 as libc::c_int),
                        )
                        .wrapping_add(a & b ^ !a & c)
                        .wrapping_add(K512[(i + 4 as libc::c_int) as usize]),
                );
            d = (CRYPTO_rotr_u64(e, 28 as libc::c_int)
                ^ CRYPTO_rotr_u64(e, 34 as libc::c_int)
                ^ CRYPTO_rotr_u64(e, 39 as libc::c_int))
                .wrapping_add(e & f ^ e & g ^ f & g);
            h = h.wrapping_add(T1);
            d = d.wrapping_add(T1);
            s0 = X[(5 as libc::c_int + 1 as libc::c_int & 0xf as libc::c_int) as usize];
            s0 = CRYPTO_rotr_u64(s0, 1 as libc::c_int)
                ^ CRYPTO_rotr_u64(s0, 8 as libc::c_int) ^ s0 >> 7 as libc::c_int;
            s1 = X[(5 as libc::c_int + 14 as libc::c_int & 0xf as libc::c_int) as usize];
            s1 = CRYPTO_rotr_u64(s1, 19 as libc::c_int)
                ^ CRYPTO_rotr_u64(s1, 61 as libc::c_int) ^ s1 >> 6 as libc::c_int;
            X[(5 as libc::c_int & 0xf as libc::c_int)
                as usize] = (X[(5 as libc::c_int & 0xf as libc::c_int) as usize])
                .wrapping_add(
                    s0
                        .wrapping_add(s1)
                        .wrapping_add(
                            X[(5 as libc::c_int + 9 as libc::c_int & 0xf as libc::c_int)
                                as usize],
                        ),
                );
            T1 = X[(5 as libc::c_int & 0xf as libc::c_int) as usize];
            T1 = T1
                .wrapping_add(
                    c
                        .wrapping_add(
                            CRYPTO_rotr_u64(h, 14 as libc::c_int)
                                ^ CRYPTO_rotr_u64(h, 18 as libc::c_int)
                                ^ CRYPTO_rotr_u64(h, 41 as libc::c_int),
                        )
                        .wrapping_add(h & a ^ !h & b)
                        .wrapping_add(K512[(i + 5 as libc::c_int) as usize]),
                );
            c = (CRYPTO_rotr_u64(d, 28 as libc::c_int)
                ^ CRYPTO_rotr_u64(d, 34 as libc::c_int)
                ^ CRYPTO_rotr_u64(d, 39 as libc::c_int))
                .wrapping_add(d & e ^ d & f ^ e & f);
            g = g.wrapping_add(T1);
            c = c.wrapping_add(T1);
            s0 = X[(6 as libc::c_int + 1 as libc::c_int & 0xf as libc::c_int) as usize];
            s0 = CRYPTO_rotr_u64(s0, 1 as libc::c_int)
                ^ CRYPTO_rotr_u64(s0, 8 as libc::c_int) ^ s0 >> 7 as libc::c_int;
            s1 = X[(6 as libc::c_int + 14 as libc::c_int & 0xf as libc::c_int) as usize];
            s1 = CRYPTO_rotr_u64(s1, 19 as libc::c_int)
                ^ CRYPTO_rotr_u64(s1, 61 as libc::c_int) ^ s1 >> 6 as libc::c_int;
            X[(6 as libc::c_int & 0xf as libc::c_int)
                as usize] = (X[(6 as libc::c_int & 0xf as libc::c_int) as usize])
                .wrapping_add(
                    s0
                        .wrapping_add(s1)
                        .wrapping_add(
                            X[(6 as libc::c_int + 9 as libc::c_int & 0xf as libc::c_int)
                                as usize],
                        ),
                );
            T1 = X[(6 as libc::c_int & 0xf as libc::c_int) as usize];
            T1 = T1
                .wrapping_add(
                    b
                        .wrapping_add(
                            CRYPTO_rotr_u64(g, 14 as libc::c_int)
                                ^ CRYPTO_rotr_u64(g, 18 as libc::c_int)
                                ^ CRYPTO_rotr_u64(g, 41 as libc::c_int),
                        )
                        .wrapping_add(g & h ^ !g & a)
                        .wrapping_add(K512[(i + 6 as libc::c_int) as usize]),
                );
            b = (CRYPTO_rotr_u64(c, 28 as libc::c_int)
                ^ CRYPTO_rotr_u64(c, 34 as libc::c_int)
                ^ CRYPTO_rotr_u64(c, 39 as libc::c_int))
                .wrapping_add(c & d ^ c & e ^ d & e);
            f = f.wrapping_add(T1);
            b = b.wrapping_add(T1);
            s0 = X[(7 as libc::c_int + 1 as libc::c_int & 0xf as libc::c_int) as usize];
            s0 = CRYPTO_rotr_u64(s0, 1 as libc::c_int)
                ^ CRYPTO_rotr_u64(s0, 8 as libc::c_int) ^ s0 >> 7 as libc::c_int;
            s1 = X[(7 as libc::c_int + 14 as libc::c_int & 0xf as libc::c_int) as usize];
            s1 = CRYPTO_rotr_u64(s1, 19 as libc::c_int)
                ^ CRYPTO_rotr_u64(s1, 61 as libc::c_int) ^ s1 >> 6 as libc::c_int;
            X[(7 as libc::c_int & 0xf as libc::c_int)
                as usize] = (X[(7 as libc::c_int & 0xf as libc::c_int) as usize])
                .wrapping_add(
                    s0
                        .wrapping_add(s1)
                        .wrapping_add(
                            X[(7 as libc::c_int + 9 as libc::c_int & 0xf as libc::c_int)
                                as usize],
                        ),
                );
            T1 = X[(7 as libc::c_int & 0xf as libc::c_int) as usize];
            T1 = T1
                .wrapping_add(
                    a
                        .wrapping_add(
                            CRYPTO_rotr_u64(f, 14 as libc::c_int)
                                ^ CRYPTO_rotr_u64(f, 18 as libc::c_int)
                                ^ CRYPTO_rotr_u64(f, 41 as libc::c_int),
                        )
                        .wrapping_add(f & g ^ !f & h)
                        .wrapping_add(K512[(i + 7 as libc::c_int) as usize]),
                );
            a = (CRYPTO_rotr_u64(b, 28 as libc::c_int)
                ^ CRYPTO_rotr_u64(b, 34 as libc::c_int)
                ^ CRYPTO_rotr_u64(b, 39 as libc::c_int))
                .wrapping_add(b & c ^ b & d ^ c & d);
            e = e.wrapping_add(T1);
            a = a.wrapping_add(T1);
            s0 = X[(8 as libc::c_int + 1 as libc::c_int & 0xf as libc::c_int) as usize];
            s0 = CRYPTO_rotr_u64(s0, 1 as libc::c_int)
                ^ CRYPTO_rotr_u64(s0, 8 as libc::c_int) ^ s0 >> 7 as libc::c_int;
            s1 = X[(8 as libc::c_int + 14 as libc::c_int & 0xf as libc::c_int) as usize];
            s1 = CRYPTO_rotr_u64(s1, 19 as libc::c_int)
                ^ CRYPTO_rotr_u64(s1, 61 as libc::c_int) ^ s1 >> 6 as libc::c_int;
            X[(8 as libc::c_int & 0xf as libc::c_int)
                as usize] = (X[(8 as libc::c_int & 0xf as libc::c_int) as usize])
                .wrapping_add(
                    s0
                        .wrapping_add(s1)
                        .wrapping_add(
                            X[(8 as libc::c_int + 9 as libc::c_int & 0xf as libc::c_int)
                                as usize],
                        ),
                );
            T1 = X[(8 as libc::c_int & 0xf as libc::c_int) as usize];
            T1 = T1
                .wrapping_add(
                    h
                        .wrapping_add(
                            CRYPTO_rotr_u64(e, 14 as libc::c_int)
                                ^ CRYPTO_rotr_u64(e, 18 as libc::c_int)
                                ^ CRYPTO_rotr_u64(e, 41 as libc::c_int),
                        )
                        .wrapping_add(e & f ^ !e & g)
                        .wrapping_add(K512[(i + 8 as libc::c_int) as usize]),
                );
            h = (CRYPTO_rotr_u64(a, 28 as libc::c_int)
                ^ CRYPTO_rotr_u64(a, 34 as libc::c_int)
                ^ CRYPTO_rotr_u64(a, 39 as libc::c_int))
                .wrapping_add(a & b ^ a & c ^ b & c);
            d = d.wrapping_add(T1);
            h = h.wrapping_add(T1);
            s0 = X[(9 as libc::c_int + 1 as libc::c_int & 0xf as libc::c_int) as usize];
            s0 = CRYPTO_rotr_u64(s0, 1 as libc::c_int)
                ^ CRYPTO_rotr_u64(s0, 8 as libc::c_int) ^ s0 >> 7 as libc::c_int;
            s1 = X[(9 as libc::c_int + 14 as libc::c_int & 0xf as libc::c_int) as usize];
            s1 = CRYPTO_rotr_u64(s1, 19 as libc::c_int)
                ^ CRYPTO_rotr_u64(s1, 61 as libc::c_int) ^ s1 >> 6 as libc::c_int;
            X[(9 as libc::c_int & 0xf as libc::c_int)
                as usize] = (X[(9 as libc::c_int & 0xf as libc::c_int) as usize])
                .wrapping_add(
                    s0
                        .wrapping_add(s1)
                        .wrapping_add(
                            X[(9 as libc::c_int + 9 as libc::c_int & 0xf as libc::c_int)
                                as usize],
                        ),
                );
            T1 = X[(9 as libc::c_int & 0xf as libc::c_int) as usize];
            T1 = T1
                .wrapping_add(
                    g
                        .wrapping_add(
                            CRYPTO_rotr_u64(d, 14 as libc::c_int)
                                ^ CRYPTO_rotr_u64(d, 18 as libc::c_int)
                                ^ CRYPTO_rotr_u64(d, 41 as libc::c_int),
                        )
                        .wrapping_add(d & e ^ !d & f)
                        .wrapping_add(K512[(i + 9 as libc::c_int) as usize]),
                );
            g = (CRYPTO_rotr_u64(h, 28 as libc::c_int)
                ^ CRYPTO_rotr_u64(h, 34 as libc::c_int)
                ^ CRYPTO_rotr_u64(h, 39 as libc::c_int))
                .wrapping_add(h & a ^ h & b ^ a & b);
            c = c.wrapping_add(T1);
            g = g.wrapping_add(T1);
            s0 = X[(10 as libc::c_int + 1 as libc::c_int & 0xf as libc::c_int) as usize];
            s0 = CRYPTO_rotr_u64(s0, 1 as libc::c_int)
                ^ CRYPTO_rotr_u64(s0, 8 as libc::c_int) ^ s0 >> 7 as libc::c_int;
            s1 = X[(10 as libc::c_int + 14 as libc::c_int & 0xf as libc::c_int)
                as usize];
            s1 = CRYPTO_rotr_u64(s1, 19 as libc::c_int)
                ^ CRYPTO_rotr_u64(s1, 61 as libc::c_int) ^ s1 >> 6 as libc::c_int;
            X[(10 as libc::c_int & 0xf as libc::c_int)
                as usize] = (X[(10 as libc::c_int & 0xf as libc::c_int) as usize])
                .wrapping_add(
                    s0
                        .wrapping_add(s1)
                        .wrapping_add(
                            X[(10 as libc::c_int + 9 as libc::c_int & 0xf as libc::c_int)
                                as usize],
                        ),
                );
            T1 = X[(10 as libc::c_int & 0xf as libc::c_int) as usize];
            T1 = T1
                .wrapping_add(
                    f
                        .wrapping_add(
                            CRYPTO_rotr_u64(c, 14 as libc::c_int)
                                ^ CRYPTO_rotr_u64(c, 18 as libc::c_int)
                                ^ CRYPTO_rotr_u64(c, 41 as libc::c_int),
                        )
                        .wrapping_add(c & d ^ !c & e)
                        .wrapping_add(K512[(i + 10 as libc::c_int) as usize]),
                );
            f = (CRYPTO_rotr_u64(g, 28 as libc::c_int)
                ^ CRYPTO_rotr_u64(g, 34 as libc::c_int)
                ^ CRYPTO_rotr_u64(g, 39 as libc::c_int))
                .wrapping_add(g & h ^ g & a ^ h & a);
            b = b.wrapping_add(T1);
            f = f.wrapping_add(T1);
            s0 = X[(11 as libc::c_int + 1 as libc::c_int & 0xf as libc::c_int) as usize];
            s0 = CRYPTO_rotr_u64(s0, 1 as libc::c_int)
                ^ CRYPTO_rotr_u64(s0, 8 as libc::c_int) ^ s0 >> 7 as libc::c_int;
            s1 = X[(11 as libc::c_int + 14 as libc::c_int & 0xf as libc::c_int)
                as usize];
            s1 = CRYPTO_rotr_u64(s1, 19 as libc::c_int)
                ^ CRYPTO_rotr_u64(s1, 61 as libc::c_int) ^ s1 >> 6 as libc::c_int;
            X[(11 as libc::c_int & 0xf as libc::c_int)
                as usize] = (X[(11 as libc::c_int & 0xf as libc::c_int) as usize])
                .wrapping_add(
                    s0
                        .wrapping_add(s1)
                        .wrapping_add(
                            X[(11 as libc::c_int + 9 as libc::c_int & 0xf as libc::c_int)
                                as usize],
                        ),
                );
            T1 = X[(11 as libc::c_int & 0xf as libc::c_int) as usize];
            T1 = T1
                .wrapping_add(
                    e
                        .wrapping_add(
                            CRYPTO_rotr_u64(b, 14 as libc::c_int)
                                ^ CRYPTO_rotr_u64(b, 18 as libc::c_int)
                                ^ CRYPTO_rotr_u64(b, 41 as libc::c_int),
                        )
                        .wrapping_add(b & c ^ !b & d)
                        .wrapping_add(K512[(i + 11 as libc::c_int) as usize]),
                );
            e = (CRYPTO_rotr_u64(f, 28 as libc::c_int)
                ^ CRYPTO_rotr_u64(f, 34 as libc::c_int)
                ^ CRYPTO_rotr_u64(f, 39 as libc::c_int))
                .wrapping_add(f & g ^ f & h ^ g & h);
            a = a.wrapping_add(T1);
            e = e.wrapping_add(T1);
            s0 = X[(12 as libc::c_int + 1 as libc::c_int & 0xf as libc::c_int) as usize];
            s0 = CRYPTO_rotr_u64(s0, 1 as libc::c_int)
                ^ CRYPTO_rotr_u64(s0, 8 as libc::c_int) ^ s0 >> 7 as libc::c_int;
            s1 = X[(12 as libc::c_int + 14 as libc::c_int & 0xf as libc::c_int)
                as usize];
            s1 = CRYPTO_rotr_u64(s1, 19 as libc::c_int)
                ^ CRYPTO_rotr_u64(s1, 61 as libc::c_int) ^ s1 >> 6 as libc::c_int;
            X[(12 as libc::c_int & 0xf as libc::c_int)
                as usize] = (X[(12 as libc::c_int & 0xf as libc::c_int) as usize])
                .wrapping_add(
                    s0
                        .wrapping_add(s1)
                        .wrapping_add(
                            X[(12 as libc::c_int + 9 as libc::c_int & 0xf as libc::c_int)
                                as usize],
                        ),
                );
            T1 = X[(12 as libc::c_int & 0xf as libc::c_int) as usize];
            T1 = T1
                .wrapping_add(
                    d
                        .wrapping_add(
                            CRYPTO_rotr_u64(a, 14 as libc::c_int)
                                ^ CRYPTO_rotr_u64(a, 18 as libc::c_int)
                                ^ CRYPTO_rotr_u64(a, 41 as libc::c_int),
                        )
                        .wrapping_add(a & b ^ !a & c)
                        .wrapping_add(K512[(i + 12 as libc::c_int) as usize]),
                );
            d = (CRYPTO_rotr_u64(e, 28 as libc::c_int)
                ^ CRYPTO_rotr_u64(e, 34 as libc::c_int)
                ^ CRYPTO_rotr_u64(e, 39 as libc::c_int))
                .wrapping_add(e & f ^ e & g ^ f & g);
            h = h.wrapping_add(T1);
            d = d.wrapping_add(T1);
            s0 = X[(13 as libc::c_int + 1 as libc::c_int & 0xf as libc::c_int) as usize];
            s0 = CRYPTO_rotr_u64(s0, 1 as libc::c_int)
                ^ CRYPTO_rotr_u64(s0, 8 as libc::c_int) ^ s0 >> 7 as libc::c_int;
            s1 = X[(13 as libc::c_int + 14 as libc::c_int & 0xf as libc::c_int)
                as usize];
            s1 = CRYPTO_rotr_u64(s1, 19 as libc::c_int)
                ^ CRYPTO_rotr_u64(s1, 61 as libc::c_int) ^ s1 >> 6 as libc::c_int;
            X[(13 as libc::c_int & 0xf as libc::c_int)
                as usize] = (X[(13 as libc::c_int & 0xf as libc::c_int) as usize])
                .wrapping_add(
                    s0
                        .wrapping_add(s1)
                        .wrapping_add(
                            X[(13 as libc::c_int + 9 as libc::c_int & 0xf as libc::c_int)
                                as usize],
                        ),
                );
            T1 = X[(13 as libc::c_int & 0xf as libc::c_int) as usize];
            T1 = T1
                .wrapping_add(
                    c
                        .wrapping_add(
                            CRYPTO_rotr_u64(h, 14 as libc::c_int)
                                ^ CRYPTO_rotr_u64(h, 18 as libc::c_int)
                                ^ CRYPTO_rotr_u64(h, 41 as libc::c_int),
                        )
                        .wrapping_add(h & a ^ !h & b)
                        .wrapping_add(K512[(i + 13 as libc::c_int) as usize]),
                );
            c = (CRYPTO_rotr_u64(d, 28 as libc::c_int)
                ^ CRYPTO_rotr_u64(d, 34 as libc::c_int)
                ^ CRYPTO_rotr_u64(d, 39 as libc::c_int))
                .wrapping_add(d & e ^ d & f ^ e & f);
            g = g.wrapping_add(T1);
            c = c.wrapping_add(T1);
            s0 = X[(14 as libc::c_int + 1 as libc::c_int & 0xf as libc::c_int) as usize];
            s0 = CRYPTO_rotr_u64(s0, 1 as libc::c_int)
                ^ CRYPTO_rotr_u64(s0, 8 as libc::c_int) ^ s0 >> 7 as libc::c_int;
            s1 = X[(14 as libc::c_int + 14 as libc::c_int & 0xf as libc::c_int)
                as usize];
            s1 = CRYPTO_rotr_u64(s1, 19 as libc::c_int)
                ^ CRYPTO_rotr_u64(s1, 61 as libc::c_int) ^ s1 >> 6 as libc::c_int;
            X[(14 as libc::c_int & 0xf as libc::c_int)
                as usize] = (X[(14 as libc::c_int & 0xf as libc::c_int) as usize])
                .wrapping_add(
                    s0
                        .wrapping_add(s1)
                        .wrapping_add(
                            X[(14 as libc::c_int + 9 as libc::c_int & 0xf as libc::c_int)
                                as usize],
                        ),
                );
            T1 = X[(14 as libc::c_int & 0xf as libc::c_int) as usize];
            T1 = T1
                .wrapping_add(
                    b
                        .wrapping_add(
                            CRYPTO_rotr_u64(g, 14 as libc::c_int)
                                ^ CRYPTO_rotr_u64(g, 18 as libc::c_int)
                                ^ CRYPTO_rotr_u64(g, 41 as libc::c_int),
                        )
                        .wrapping_add(g & h ^ !g & a)
                        .wrapping_add(K512[(i + 14 as libc::c_int) as usize]),
                );
            b = (CRYPTO_rotr_u64(c, 28 as libc::c_int)
                ^ CRYPTO_rotr_u64(c, 34 as libc::c_int)
                ^ CRYPTO_rotr_u64(c, 39 as libc::c_int))
                .wrapping_add(c & d ^ c & e ^ d & e);
            f = f.wrapping_add(T1);
            b = b.wrapping_add(T1);
            s0 = X[(15 as libc::c_int + 1 as libc::c_int & 0xf as libc::c_int) as usize];
            s0 = CRYPTO_rotr_u64(s0, 1 as libc::c_int)
                ^ CRYPTO_rotr_u64(s0, 8 as libc::c_int) ^ s0 >> 7 as libc::c_int;
            s1 = X[(15 as libc::c_int + 14 as libc::c_int & 0xf as libc::c_int)
                as usize];
            s1 = CRYPTO_rotr_u64(s1, 19 as libc::c_int)
                ^ CRYPTO_rotr_u64(s1, 61 as libc::c_int) ^ s1 >> 6 as libc::c_int;
            X[(15 as libc::c_int & 0xf as libc::c_int)
                as usize] = (X[(15 as libc::c_int & 0xf as libc::c_int) as usize])
                .wrapping_add(
                    s0
                        .wrapping_add(s1)
                        .wrapping_add(
                            X[(15 as libc::c_int + 9 as libc::c_int & 0xf as libc::c_int)
                                as usize],
                        ),
                );
            T1 = X[(15 as libc::c_int & 0xf as libc::c_int) as usize];
            T1 = T1
                .wrapping_add(
                    a
                        .wrapping_add(
                            CRYPTO_rotr_u64(f, 14 as libc::c_int)
                                ^ CRYPTO_rotr_u64(f, 18 as libc::c_int)
                                ^ CRYPTO_rotr_u64(f, 41 as libc::c_int),
                        )
                        .wrapping_add(f & g ^ !f & h)
                        .wrapping_add(K512[(i + 15 as libc::c_int) as usize]),
                );
            a = (CRYPTO_rotr_u64(b, 28 as libc::c_int)
                ^ CRYPTO_rotr_u64(b, 34 as libc::c_int)
                ^ CRYPTO_rotr_u64(b, 39 as libc::c_int))
                .wrapping_add(b & c ^ b & d ^ c & d);
            e = e.wrapping_add(T1);
            a = a.wrapping_add(T1);
            i += 16 as libc::c_int;
        }
        let ref mut fresh1 = *state.offset(0 as libc::c_int as isize);
        *fresh1 = (*fresh1).wrapping_add(a);
        let ref mut fresh2 = *state.offset(1 as libc::c_int as isize);
        *fresh2 = (*fresh2).wrapping_add(b);
        let ref mut fresh3 = *state.offset(2 as libc::c_int as isize);
        *fresh3 = (*fresh3).wrapping_add(c);
        let ref mut fresh4 = *state.offset(3 as libc::c_int as isize);
        *fresh4 = (*fresh4).wrapping_add(d);
        let ref mut fresh5 = *state.offset(4 as libc::c_int as isize);
        *fresh5 = (*fresh5).wrapping_add(e);
        let ref mut fresh6 = *state.offset(5 as libc::c_int as isize);
        *fresh6 = (*fresh6).wrapping_add(f);
        let ref mut fresh7 = *state.offset(6 as libc::c_int as isize);
        *fresh7 = (*fresh7).wrapping_add(g);
        let ref mut fresh8 = *state.offset(7 as libc::c_int as isize);
        *fresh8 = (*fresh8).wrapping_add(h);
        in_0 = in_0.offset((16 as libc::c_int * 8 as libc::c_int) as isize);
    };
}
unsafe extern "C" fn sha512_block_data_order(
    mut state: *mut uint64_t,
    mut data: *const uint8_t,
    mut num: size_t,
) {
    sha512_block_data_order_nohw(state, data, num);
}
