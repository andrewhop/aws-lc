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
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sha256_state_st {
    pub h: [uint32_t; 8],
    pub Nl: uint32_t,
    pub Nh: uint32_t,
    pub data: [uint8_t; 64],
    pub num: libc::c_uint,
    pub md_len: libc::c_uint,
}
pub type SHA256_CTX = sha256_state_st;
pub type crypto_md32_block_func = Option::<
    unsafe extern "C" fn(*mut uint32_t, *const uint8_t, size_t) -> (),
>;
#[inline]
unsafe extern "C" fn CRYPTO_bswap4(mut x: uint32_t) -> uint32_t {
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
unsafe extern "C" fn CRYPTO_store_u32_le(mut out: *mut libc::c_void, mut v: uint32_t) {
    OPENSSL_memcpy(
        out,
        &mut v as *mut uint32_t as *const libc::c_void,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
}
#[inline]
unsafe extern "C" fn CRYPTO_load_u32_be(mut in_0: *const libc::c_void) -> uint32_t {
    let mut v: uint32_t = 0;
    OPENSSL_memcpy(
        &mut v as *mut uint32_t as *mut libc::c_void,
        in_0,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
    return CRYPTO_bswap4(v);
}
#[inline]
unsafe extern "C" fn CRYPTO_store_u32_be(mut out: *mut libc::c_void, mut v: uint32_t) {
    v = CRYPTO_bswap4(v);
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
#[inline]
unsafe extern "C" fn FIPS_service_indicator_update_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_lock_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_unlock_state() {}
#[inline]
unsafe extern "C" fn crypto_md32_update(
    mut block_func: crypto_md32_block_func,
    mut h: *mut uint32_t,
    mut data: *mut uint8_t,
    mut block_size: size_t,
    mut num: *mut libc::c_uint,
    mut Nh: *mut uint32_t,
    mut Nl: *mut uint32_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
) {
    if len == 0 as libc::c_int as size_t {
        return;
    }
    let mut l: uint32_t = (*Nl).wrapping_add((len as uint32_t) << 3 as libc::c_int);
    if l < *Nl {
        *Nh = (*Nh).wrapping_add(1);
        *Nh;
    }
    *Nh = (*Nh).wrapping_add((len >> 29 as libc::c_int) as uint32_t);
    *Nl = l;
    let mut n: size_t = *num as size_t;
    if n != 0 as libc::c_int as size_t {
        if len >= block_size || len.wrapping_add(n) >= block_size {
            OPENSSL_memcpy(
                data.offset(n as isize) as *mut libc::c_void,
                in_0 as *const libc::c_void,
                block_size.wrapping_sub(n),
            );
            block_func
                .expect(
                    "non-null function pointer",
                )(h, data, 1 as libc::c_int as size_t);
            n = block_size.wrapping_sub(n);
            in_0 = in_0.offset(n as isize);
            len = len.wrapping_sub(n);
            *num = 0 as libc::c_int as libc::c_uint;
            OPENSSL_memset(data as *mut libc::c_void, 0 as libc::c_int, block_size);
        } else {
            OPENSSL_memcpy(
                data.offset(n as isize) as *mut libc::c_void,
                in_0 as *const libc::c_void,
                len,
            );
            *num = (*num).wrapping_add(len as libc::c_uint);
            return;
        }
    }
    n = len / block_size;
    if n > 0 as libc::c_int as size_t {
        block_func.expect("non-null function pointer")(h, in_0, n);
        n = n * block_size;
        in_0 = in_0.offset(n as isize);
        len = len.wrapping_sub(n);
    }
    if len != 0 as libc::c_int as size_t {
        *num = len as libc::c_uint;
        OPENSSL_memcpy(data as *mut libc::c_void, in_0 as *const libc::c_void, len);
    }
}
#[inline]
unsafe extern "C" fn crypto_md32_final(
    mut block_func: crypto_md32_block_func,
    mut h: *mut uint32_t,
    mut data: *mut uint8_t,
    mut block_size: size_t,
    mut num: *mut libc::c_uint,
    mut Nh: uint32_t,
    mut Nl: uint32_t,
    mut is_big_endian: libc::c_int,
) {
    let mut n: size_t = *num as size_t;
    if n < block_size {} else {
        __assert_fail(
            b"n < block_size\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/sha/../digest/md32_common.h\0"
                as *const u8 as *const libc::c_char,
            165 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 119],
                &[libc::c_char; 119],
            >(
                b"void crypto_md32_final(crypto_md32_block_func, uint32_t *, uint8_t *, size_t, unsigned int *, uint32_t, uint32_t, int)\0",
            ))
                .as_ptr(),
        );
    }
    'c_6818: {
        if n < block_size {} else {
            __assert_fail(
                b"n < block_size\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/sha/../digest/md32_common.h\0"
                    as *const u8 as *const libc::c_char,
                165 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 119],
                    &[libc::c_char; 119],
                >(
                    b"void crypto_md32_final(crypto_md32_block_func, uint32_t *, uint8_t *, size_t, unsigned int *, uint32_t, uint32_t, int)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    *data.offset(n as isize) = 0x80 as libc::c_int as uint8_t;
    n = n.wrapping_add(1);
    n;
    if n > block_size.wrapping_sub(8 as libc::c_int as size_t) {
        OPENSSL_memset(
            data.offset(n as isize) as *mut libc::c_void,
            0 as libc::c_int,
            block_size.wrapping_sub(n),
        );
        n = 0 as libc::c_int as size_t;
        block_func
            .expect("non-null function pointer")(h, data, 1 as libc::c_int as size_t);
    }
    OPENSSL_memset(
        data.offset(n as isize) as *mut libc::c_void,
        0 as libc::c_int,
        block_size.wrapping_sub(8 as libc::c_int as size_t).wrapping_sub(n),
    );
    if is_big_endian != 0 {
        CRYPTO_store_u32_be(
            data.offset(block_size as isize).offset(-(8 as libc::c_int as isize))
                as *mut libc::c_void,
            Nh,
        );
        CRYPTO_store_u32_be(
            data.offset(block_size as isize).offset(-(4 as libc::c_int as isize))
                as *mut libc::c_void,
            Nl,
        );
    } else {
        CRYPTO_store_u32_le(
            data.offset(block_size as isize).offset(-(8 as libc::c_int as isize))
                as *mut libc::c_void,
            Nl,
        );
        CRYPTO_store_u32_le(
            data.offset(block_size as isize).offset(-(4 as libc::c_int as isize))
                as *mut libc::c_void,
            Nh,
        );
    }
    block_func.expect("non-null function pointer")(h, data, 1 as libc::c_int as size_t);
    *num = 0 as libc::c_int as libc::c_uint;
    OPENSSL_memset(data as *mut libc::c_void, 0 as libc::c_int, block_size);
}
#[no_mangle]
pub unsafe extern "C" fn SHA224_Init(mut sha: *mut SHA256_CTX) -> libc::c_int {
    OPENSSL_memset(
        sha as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<SHA256_CTX>() as libc::c_ulong,
    );
    (*sha).h[0 as libc::c_int as usize] = 0xc1059ed8 as libc::c_ulong as uint32_t;
    (*sha).h[1 as libc::c_int as usize] = 0x367cd507 as libc::c_ulong as uint32_t;
    (*sha).h[2 as libc::c_int as usize] = 0x3070dd17 as libc::c_ulong as uint32_t;
    (*sha).h[3 as libc::c_int as usize] = 0xf70e5939 as libc::c_ulong as uint32_t;
    (*sha).h[4 as libc::c_int as usize] = 0xffc00b31 as libc::c_ulong as uint32_t;
    (*sha).h[5 as libc::c_int as usize] = 0x68581511 as libc::c_ulong as uint32_t;
    (*sha).h[6 as libc::c_int as usize] = 0x64f98fa7 as libc::c_ulong as uint32_t;
    (*sha).h[7 as libc::c_int as usize] = 0xbefa4fa4 as libc::c_ulong as uint32_t;
    (*sha).md_len = 28 as libc::c_int as libc::c_uint;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn SHA256_Init(mut sha: *mut SHA256_CTX) -> libc::c_int {
    OPENSSL_memset(
        sha as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<SHA256_CTX>() as libc::c_ulong,
    );
    (*sha).h[0 as libc::c_int as usize] = 0x6a09e667 as libc::c_ulong as uint32_t;
    (*sha).h[1 as libc::c_int as usize] = 0xbb67ae85 as libc::c_ulong as uint32_t;
    (*sha).h[2 as libc::c_int as usize] = 0x3c6ef372 as libc::c_ulong as uint32_t;
    (*sha).h[3 as libc::c_int as usize] = 0xa54ff53a as libc::c_ulong as uint32_t;
    (*sha).h[4 as libc::c_int as usize] = 0x510e527f as libc::c_ulong as uint32_t;
    (*sha).h[5 as libc::c_int as usize] = 0x9b05688c as libc::c_ulong as uint32_t;
    (*sha).h[6 as libc::c_int as usize] = 0x1f83d9ab as libc::c_ulong as uint32_t;
    (*sha).h[7 as libc::c_int as usize] = 0x5be0cd19 as libc::c_ulong as uint32_t;
    (*sha).md_len = 32 as libc::c_int as libc::c_uint;
    return 1 as libc::c_int;
}
unsafe extern "C" fn sha256_init_from_state_impl(
    mut sha: *mut SHA256_CTX,
    mut md_len: libc::c_int,
    mut h: *const uint8_t,
    mut n: uint64_t,
) -> libc::c_int {
    if n % (64 as libc::c_int as uint64_t * 8 as libc::c_int as uint64_t)
        != 0 as libc::c_int as uint64_t
    {
        return 0 as libc::c_int;
    }
    OPENSSL_memset(
        sha as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<SHA256_CTX>() as libc::c_ulong,
    );
    (*sha).md_len = md_len as libc::c_uint;
    let out_words: size_t = (32 as libc::c_int / 4 as libc::c_int) as size_t;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < out_words {
        (*sha).h[i as usize] = CRYPTO_load_u32_be(h as *const libc::c_void);
        h = h.offset(4 as libc::c_int as isize);
        i = i.wrapping_add(1);
        i;
    }
    (*sha).Nh = (n >> 32 as libc::c_int) as uint32_t;
    (*sha).Nl = (n & 0xffffffff as libc::c_uint as uint64_t) as uint32_t;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn SHA224_Init_from_state(
    mut sha: *mut SHA256_CTX,
    mut h: *const uint8_t,
    mut n: uint64_t,
) -> libc::c_int {
    return sha256_init_from_state_impl(sha, 28 as libc::c_int, h, n);
}
#[no_mangle]
pub unsafe extern "C" fn SHA256_Init_from_state(
    mut sha: *mut SHA256_CTX,
    mut h: *const uint8_t,
    mut n: uint64_t,
) -> libc::c_int {
    return sha256_init_from_state_impl(sha, 32 as libc::c_int, h, n);
}
#[no_mangle]
pub unsafe extern "C" fn SHA224(
    mut data: *const uint8_t,
    mut len: size_t,
    mut out: *mut uint8_t,
) -> *mut uint8_t {
    FIPS_service_indicator_lock_state();
    let mut ctx: SHA256_CTX = sha256_state_st {
        h: [0; 8],
        Nl: 0,
        Nh: 0,
        data: [0; 64],
        num: 0,
        md_len: 0,
    };
    let ok: libc::c_int = (SHA224_Init(&mut ctx) != 0
        && SHA224_Update(&mut ctx, data as *const libc::c_void, len) != 0
        && SHA224_Final(out, &mut ctx) != 0) as libc::c_int;
    FIPS_service_indicator_unlock_state();
    if ok != 0 {
        FIPS_service_indicator_update_state();
    }
    OPENSSL_cleanse(
        &mut ctx as *mut SHA256_CTX as *mut libc::c_void,
        ::core::mem::size_of::<SHA256_CTX>() as libc::c_ulong,
    );
    return out;
}
#[no_mangle]
pub unsafe extern "C" fn SHA256(
    mut data: *const uint8_t,
    mut len: size_t,
    mut out: *mut uint8_t,
) -> *mut uint8_t {
    FIPS_service_indicator_lock_state();
    let mut ctx: SHA256_CTX = sha256_state_st {
        h: [0; 8],
        Nl: 0,
        Nh: 0,
        data: [0; 64],
        num: 0,
        md_len: 0,
    };
    let ok: libc::c_int = (SHA256_Init(&mut ctx) != 0
        && SHA256_Update(&mut ctx, data as *const libc::c_void, len) != 0
        && SHA256_Final(out, &mut ctx) != 0) as libc::c_int;
    FIPS_service_indicator_unlock_state();
    if ok != 0 {
        FIPS_service_indicator_update_state();
    }
    OPENSSL_cleanse(
        &mut ctx as *mut SHA256_CTX as *mut libc::c_void,
        ::core::mem::size_of::<SHA256_CTX>() as libc::c_ulong,
    );
    return out;
}
#[no_mangle]
pub unsafe extern "C" fn SHA256_Transform(
    mut c: *mut SHA256_CTX,
    mut data: *const uint8_t,
) {
    sha256_block_data_order(((*c).h).as_mut_ptr(), data, 1 as libc::c_int as size_t);
}
#[no_mangle]
pub unsafe extern "C" fn SHA256_Update(
    mut c: *mut SHA256_CTX,
    mut data: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    crypto_md32_update(
        Some(
            sha256_block_data_order
                as unsafe extern "C" fn(*mut uint32_t, *const uint8_t, size_t) -> (),
        ),
        ((*c).h).as_mut_ptr(),
        ((*c).data).as_mut_ptr(),
        64 as libc::c_int as size_t,
        &mut (*c).num,
        &mut (*c).Nh,
        &mut (*c).Nl,
        data as *const uint8_t,
        len,
    );
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn SHA224_Update(
    mut ctx: *mut SHA256_CTX,
    mut data: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    return SHA256_Update(ctx, data, len);
}
unsafe extern "C" fn sha256_final_impl(
    mut out: *mut uint8_t,
    mut md_len: size_t,
    mut c: *mut SHA256_CTX,
) -> libc::c_int {
    crypto_md32_final(
        Some(
            sha256_block_data_order
                as unsafe extern "C" fn(*mut uint32_t, *const uint8_t, size_t) -> (),
        ),
        ((*c).h).as_mut_ptr(),
        ((*c).data).as_mut_ptr(),
        64 as libc::c_int as size_t,
        &mut (*c).num,
        (*c).Nh,
        (*c).Nl,
        1 as libc::c_int,
    );
    if (*c).md_len as size_t != md_len {
        return 0 as libc::c_int;
    }
    if md_len % 4 as libc::c_int as size_t == 0 as libc::c_int as size_t {} else {
        __assert_fail(
            b"md_len % 4 == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/sha/sha256.c\0"
                as *const u8 as *const libc::c_char,
            198 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 55],
                &[libc::c_char; 55],
            >(b"int sha256_final_impl(uint8_t *, size_t, SHA256_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_6526: {
        if md_len % 4 as libc::c_int as size_t == 0 as libc::c_int as size_t {} else {
            __assert_fail(
                b"md_len % 4 == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/sha/sha256.c\0"
                    as *const u8 as *const libc::c_char,
                198 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 55],
                    &[libc::c_char; 55],
                >(b"int sha256_final_impl(uint8_t *, size_t, SHA256_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    let out_words: size_t = md_len / 4 as libc::c_int as size_t;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < out_words {
        CRYPTO_store_u32_be(out as *mut libc::c_void, (*c).h[i as usize]);
        out = out.offset(4 as libc::c_int as isize);
        i = i.wrapping_add(1);
        i;
    }
    FIPS_service_indicator_update_state();
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn SHA256_Final(
    mut out: *mut uint8_t,
    mut c: *mut SHA256_CTX,
) -> libc::c_int {
    return sha256_final_impl(out, 32 as libc::c_int as size_t, c);
}
#[no_mangle]
pub unsafe extern "C" fn SHA224_Final(
    mut out: *mut uint8_t,
    mut ctx: *mut SHA256_CTX,
) -> libc::c_int {
    return sha256_final_impl(out, 28 as libc::c_int as size_t, ctx);
}
unsafe extern "C" fn sha256_get_state_impl(
    mut ctx: *mut SHA256_CTX,
    mut out_h: *mut uint8_t,
    mut out_n: *mut uint64_t,
) -> libc::c_int {
    if (*ctx).Nl as uint64_t
        % (64 as libc::c_int as uint64_t * 8 as libc::c_int as uint64_t)
        != 0 as libc::c_int as uint64_t
    {
        return 0 as libc::c_int;
    }
    let out_words: size_t = (32 as libc::c_int / 4 as libc::c_int) as size_t;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < out_words {
        CRYPTO_store_u32_be(out_h as *mut libc::c_void, (*ctx).h[i as usize]);
        out_h = out_h.offset(4 as libc::c_int as isize);
        i = i.wrapping_add(1);
        i;
    }
    *out_n = (((*ctx).Nh as uint64_t) << 32 as libc::c_int)
        .wrapping_add((*ctx).Nl as uint64_t);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn SHA224_get_state(
    mut ctx: *mut SHA256_CTX,
    mut out_h: *mut uint8_t,
    mut out_n: *mut uint64_t,
) -> libc::c_int {
    return sha256_get_state_impl(ctx, out_h, out_n);
}
#[no_mangle]
pub unsafe extern "C" fn SHA256_get_state(
    mut ctx: *mut SHA256_CTX,
    mut out_h: *mut uint8_t,
    mut out_n: *mut uint64_t,
) -> libc::c_int {
    return sha256_get_state_impl(ctx, out_h, out_n);
}
static mut K256: [uint32_t; 64] = [
    0x428a2f98 as libc::c_ulong as uint32_t,
    0x71374491 as libc::c_ulong as uint32_t,
    0xb5c0fbcf as libc::c_ulong as uint32_t,
    0xe9b5dba5 as libc::c_ulong as uint32_t,
    0x3956c25b as libc::c_ulong as uint32_t,
    0x59f111f1 as libc::c_ulong as uint32_t,
    0x923f82a4 as libc::c_ulong as uint32_t,
    0xab1c5ed5 as libc::c_ulong as uint32_t,
    0xd807aa98 as libc::c_ulong as uint32_t,
    0x12835b01 as libc::c_ulong as uint32_t,
    0x243185be as libc::c_ulong as uint32_t,
    0x550c7dc3 as libc::c_ulong as uint32_t,
    0x72be5d74 as libc::c_ulong as uint32_t,
    0x80deb1fe as libc::c_ulong as uint32_t,
    0x9bdc06a7 as libc::c_ulong as uint32_t,
    0xc19bf174 as libc::c_ulong as uint32_t,
    0xe49b69c1 as libc::c_ulong as uint32_t,
    0xefbe4786 as libc::c_ulong as uint32_t,
    0xfc19dc6 as libc::c_ulong as uint32_t,
    0x240ca1cc as libc::c_ulong as uint32_t,
    0x2de92c6f as libc::c_ulong as uint32_t,
    0x4a7484aa as libc::c_ulong as uint32_t,
    0x5cb0a9dc as libc::c_ulong as uint32_t,
    0x76f988da as libc::c_ulong as uint32_t,
    0x983e5152 as libc::c_ulong as uint32_t,
    0xa831c66d as libc::c_ulong as uint32_t,
    0xb00327c8 as libc::c_ulong as uint32_t,
    0xbf597fc7 as libc::c_ulong as uint32_t,
    0xc6e00bf3 as libc::c_ulong as uint32_t,
    0xd5a79147 as libc::c_ulong as uint32_t,
    0x6ca6351 as libc::c_ulong as uint32_t,
    0x14292967 as libc::c_ulong as uint32_t,
    0x27b70a85 as libc::c_ulong as uint32_t,
    0x2e1b2138 as libc::c_ulong as uint32_t,
    0x4d2c6dfc as libc::c_ulong as uint32_t,
    0x53380d13 as libc::c_ulong as uint32_t,
    0x650a7354 as libc::c_ulong as uint32_t,
    0x766a0abb as libc::c_ulong as uint32_t,
    0x81c2c92e as libc::c_ulong as uint32_t,
    0x92722c85 as libc::c_ulong as uint32_t,
    0xa2bfe8a1 as libc::c_ulong as uint32_t,
    0xa81a664b as libc::c_ulong as uint32_t,
    0xc24b8b70 as libc::c_ulong as uint32_t,
    0xc76c51a3 as libc::c_ulong as uint32_t,
    0xd192e819 as libc::c_ulong as uint32_t,
    0xd6990624 as libc::c_ulong as uint32_t,
    0xf40e3585 as libc::c_ulong as uint32_t,
    0x106aa070 as libc::c_ulong as uint32_t,
    0x19a4c116 as libc::c_ulong as uint32_t,
    0x1e376c08 as libc::c_ulong as uint32_t,
    0x2748774c as libc::c_ulong as uint32_t,
    0x34b0bcb5 as libc::c_ulong as uint32_t,
    0x391c0cb3 as libc::c_ulong as uint32_t,
    0x4ed8aa4a as libc::c_ulong as uint32_t,
    0x5b9cca4f as libc::c_ulong as uint32_t,
    0x682e6ff3 as libc::c_ulong as uint32_t,
    0x748f82ee as libc::c_ulong as uint32_t,
    0x78a5636f as libc::c_ulong as uint32_t,
    0x84c87814 as libc::c_ulong as uint32_t,
    0x8cc70208 as libc::c_ulong as uint32_t,
    0x90befffa as libc::c_ulong as uint32_t,
    0xa4506ceb as libc::c_ulong as uint32_t,
    0xbef9a3f7 as libc::c_ulong as uint32_t,
    0xc67178f2 as libc::c_ulong as uint32_t,
];
unsafe extern "C" fn sha256_block_data_order_nohw(
    mut state: *mut uint32_t,
    mut data: *const uint8_t,
    mut num: size_t,
) {
    let mut a: uint32_t = 0;
    let mut b: uint32_t = 0;
    let mut c: uint32_t = 0;
    let mut d: uint32_t = 0;
    let mut e: uint32_t = 0;
    let mut f: uint32_t = 0;
    let mut g: uint32_t = 0;
    let mut h: uint32_t = 0;
    let mut s0: uint32_t = 0;
    let mut s1: uint32_t = 0;
    let mut T1: uint32_t = 0;
    let mut X: [uint32_t; 16] = [0; 16];
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
        X[0 as libc::c_int as usize] = CRYPTO_load_u32_be(data as *const libc::c_void);
        T1 = X[0 as libc::c_int as usize];
        data = data.offset(4 as libc::c_int as isize);
        T1 = T1
            .wrapping_add(
                h
                    .wrapping_add(
                        CRYPTO_rotr_u32(e, 6 as libc::c_int)
                            ^ CRYPTO_rotr_u32(e, 11 as libc::c_int)
                            ^ CRYPTO_rotr_u32(e, 25 as libc::c_int),
                    )
                    .wrapping_add(e & f ^ !e & g)
                    .wrapping_add(K256[0 as libc::c_int as usize]),
            );
        h = (CRYPTO_rotr_u32(a, 2 as libc::c_int) ^ CRYPTO_rotr_u32(a, 13 as libc::c_int)
            ^ CRYPTO_rotr_u32(a, 22 as libc::c_int))
            .wrapping_add(a & b ^ a & c ^ b & c);
        d = d.wrapping_add(T1);
        h = h.wrapping_add(T1);
        X[1 as libc::c_int as usize] = CRYPTO_load_u32_be(data as *const libc::c_void);
        T1 = X[1 as libc::c_int as usize];
        data = data.offset(4 as libc::c_int as isize);
        T1 = T1
            .wrapping_add(
                g
                    .wrapping_add(
                        CRYPTO_rotr_u32(d, 6 as libc::c_int)
                            ^ CRYPTO_rotr_u32(d, 11 as libc::c_int)
                            ^ CRYPTO_rotr_u32(d, 25 as libc::c_int),
                    )
                    .wrapping_add(d & e ^ !d & f)
                    .wrapping_add(K256[1 as libc::c_int as usize]),
            );
        g = (CRYPTO_rotr_u32(h, 2 as libc::c_int) ^ CRYPTO_rotr_u32(h, 13 as libc::c_int)
            ^ CRYPTO_rotr_u32(h, 22 as libc::c_int))
            .wrapping_add(h & a ^ h & b ^ a & b);
        c = c.wrapping_add(T1);
        g = g.wrapping_add(T1);
        X[2 as libc::c_int as usize] = CRYPTO_load_u32_be(data as *const libc::c_void);
        T1 = X[2 as libc::c_int as usize];
        data = data.offset(4 as libc::c_int as isize);
        T1 = T1
            .wrapping_add(
                f
                    .wrapping_add(
                        CRYPTO_rotr_u32(c, 6 as libc::c_int)
                            ^ CRYPTO_rotr_u32(c, 11 as libc::c_int)
                            ^ CRYPTO_rotr_u32(c, 25 as libc::c_int),
                    )
                    .wrapping_add(c & d ^ !c & e)
                    .wrapping_add(K256[2 as libc::c_int as usize]),
            );
        f = (CRYPTO_rotr_u32(g, 2 as libc::c_int) ^ CRYPTO_rotr_u32(g, 13 as libc::c_int)
            ^ CRYPTO_rotr_u32(g, 22 as libc::c_int))
            .wrapping_add(g & h ^ g & a ^ h & a);
        b = b.wrapping_add(T1);
        f = f.wrapping_add(T1);
        X[3 as libc::c_int as usize] = CRYPTO_load_u32_be(data as *const libc::c_void);
        T1 = X[3 as libc::c_int as usize];
        data = data.offset(4 as libc::c_int as isize);
        T1 = T1
            .wrapping_add(
                e
                    .wrapping_add(
                        CRYPTO_rotr_u32(b, 6 as libc::c_int)
                            ^ CRYPTO_rotr_u32(b, 11 as libc::c_int)
                            ^ CRYPTO_rotr_u32(b, 25 as libc::c_int),
                    )
                    .wrapping_add(b & c ^ !b & d)
                    .wrapping_add(K256[3 as libc::c_int as usize]),
            );
        e = (CRYPTO_rotr_u32(f, 2 as libc::c_int) ^ CRYPTO_rotr_u32(f, 13 as libc::c_int)
            ^ CRYPTO_rotr_u32(f, 22 as libc::c_int))
            .wrapping_add(f & g ^ f & h ^ g & h);
        a = a.wrapping_add(T1);
        e = e.wrapping_add(T1);
        X[4 as libc::c_int as usize] = CRYPTO_load_u32_be(data as *const libc::c_void);
        T1 = X[4 as libc::c_int as usize];
        data = data.offset(4 as libc::c_int as isize);
        T1 = T1
            .wrapping_add(
                d
                    .wrapping_add(
                        CRYPTO_rotr_u32(a, 6 as libc::c_int)
                            ^ CRYPTO_rotr_u32(a, 11 as libc::c_int)
                            ^ CRYPTO_rotr_u32(a, 25 as libc::c_int),
                    )
                    .wrapping_add(a & b ^ !a & c)
                    .wrapping_add(K256[4 as libc::c_int as usize]),
            );
        d = (CRYPTO_rotr_u32(e, 2 as libc::c_int) ^ CRYPTO_rotr_u32(e, 13 as libc::c_int)
            ^ CRYPTO_rotr_u32(e, 22 as libc::c_int))
            .wrapping_add(e & f ^ e & g ^ f & g);
        h = h.wrapping_add(T1);
        d = d.wrapping_add(T1);
        X[5 as libc::c_int as usize] = CRYPTO_load_u32_be(data as *const libc::c_void);
        T1 = X[5 as libc::c_int as usize];
        data = data.offset(4 as libc::c_int as isize);
        T1 = T1
            .wrapping_add(
                c
                    .wrapping_add(
                        CRYPTO_rotr_u32(h, 6 as libc::c_int)
                            ^ CRYPTO_rotr_u32(h, 11 as libc::c_int)
                            ^ CRYPTO_rotr_u32(h, 25 as libc::c_int),
                    )
                    .wrapping_add(h & a ^ !h & b)
                    .wrapping_add(K256[5 as libc::c_int as usize]),
            );
        c = (CRYPTO_rotr_u32(d, 2 as libc::c_int) ^ CRYPTO_rotr_u32(d, 13 as libc::c_int)
            ^ CRYPTO_rotr_u32(d, 22 as libc::c_int))
            .wrapping_add(d & e ^ d & f ^ e & f);
        g = g.wrapping_add(T1);
        c = c.wrapping_add(T1);
        X[6 as libc::c_int as usize] = CRYPTO_load_u32_be(data as *const libc::c_void);
        T1 = X[6 as libc::c_int as usize];
        data = data.offset(4 as libc::c_int as isize);
        T1 = T1
            .wrapping_add(
                b
                    .wrapping_add(
                        CRYPTO_rotr_u32(g, 6 as libc::c_int)
                            ^ CRYPTO_rotr_u32(g, 11 as libc::c_int)
                            ^ CRYPTO_rotr_u32(g, 25 as libc::c_int),
                    )
                    .wrapping_add(g & h ^ !g & a)
                    .wrapping_add(K256[6 as libc::c_int as usize]),
            );
        b = (CRYPTO_rotr_u32(c, 2 as libc::c_int) ^ CRYPTO_rotr_u32(c, 13 as libc::c_int)
            ^ CRYPTO_rotr_u32(c, 22 as libc::c_int))
            .wrapping_add(c & d ^ c & e ^ d & e);
        f = f.wrapping_add(T1);
        b = b.wrapping_add(T1);
        X[7 as libc::c_int as usize] = CRYPTO_load_u32_be(data as *const libc::c_void);
        T1 = X[7 as libc::c_int as usize];
        data = data.offset(4 as libc::c_int as isize);
        T1 = T1
            .wrapping_add(
                a
                    .wrapping_add(
                        CRYPTO_rotr_u32(f, 6 as libc::c_int)
                            ^ CRYPTO_rotr_u32(f, 11 as libc::c_int)
                            ^ CRYPTO_rotr_u32(f, 25 as libc::c_int),
                    )
                    .wrapping_add(f & g ^ !f & h)
                    .wrapping_add(K256[7 as libc::c_int as usize]),
            );
        a = (CRYPTO_rotr_u32(b, 2 as libc::c_int) ^ CRYPTO_rotr_u32(b, 13 as libc::c_int)
            ^ CRYPTO_rotr_u32(b, 22 as libc::c_int))
            .wrapping_add(b & c ^ b & d ^ c & d);
        e = e.wrapping_add(T1);
        a = a.wrapping_add(T1);
        X[8 as libc::c_int as usize] = CRYPTO_load_u32_be(data as *const libc::c_void);
        T1 = X[8 as libc::c_int as usize];
        data = data.offset(4 as libc::c_int as isize);
        T1 = T1
            .wrapping_add(
                h
                    .wrapping_add(
                        CRYPTO_rotr_u32(e, 6 as libc::c_int)
                            ^ CRYPTO_rotr_u32(e, 11 as libc::c_int)
                            ^ CRYPTO_rotr_u32(e, 25 as libc::c_int),
                    )
                    .wrapping_add(e & f ^ !e & g)
                    .wrapping_add(K256[8 as libc::c_int as usize]),
            );
        h = (CRYPTO_rotr_u32(a, 2 as libc::c_int) ^ CRYPTO_rotr_u32(a, 13 as libc::c_int)
            ^ CRYPTO_rotr_u32(a, 22 as libc::c_int))
            .wrapping_add(a & b ^ a & c ^ b & c);
        d = d.wrapping_add(T1);
        h = h.wrapping_add(T1);
        X[9 as libc::c_int as usize] = CRYPTO_load_u32_be(data as *const libc::c_void);
        T1 = X[9 as libc::c_int as usize];
        data = data.offset(4 as libc::c_int as isize);
        T1 = T1
            .wrapping_add(
                g
                    .wrapping_add(
                        CRYPTO_rotr_u32(d, 6 as libc::c_int)
                            ^ CRYPTO_rotr_u32(d, 11 as libc::c_int)
                            ^ CRYPTO_rotr_u32(d, 25 as libc::c_int),
                    )
                    .wrapping_add(d & e ^ !d & f)
                    .wrapping_add(K256[9 as libc::c_int as usize]),
            );
        g = (CRYPTO_rotr_u32(h, 2 as libc::c_int) ^ CRYPTO_rotr_u32(h, 13 as libc::c_int)
            ^ CRYPTO_rotr_u32(h, 22 as libc::c_int))
            .wrapping_add(h & a ^ h & b ^ a & b);
        c = c.wrapping_add(T1);
        g = g.wrapping_add(T1);
        X[10 as libc::c_int as usize] = CRYPTO_load_u32_be(data as *const libc::c_void);
        T1 = X[10 as libc::c_int as usize];
        data = data.offset(4 as libc::c_int as isize);
        T1 = T1
            .wrapping_add(
                f
                    .wrapping_add(
                        CRYPTO_rotr_u32(c, 6 as libc::c_int)
                            ^ CRYPTO_rotr_u32(c, 11 as libc::c_int)
                            ^ CRYPTO_rotr_u32(c, 25 as libc::c_int),
                    )
                    .wrapping_add(c & d ^ !c & e)
                    .wrapping_add(K256[10 as libc::c_int as usize]),
            );
        f = (CRYPTO_rotr_u32(g, 2 as libc::c_int) ^ CRYPTO_rotr_u32(g, 13 as libc::c_int)
            ^ CRYPTO_rotr_u32(g, 22 as libc::c_int))
            .wrapping_add(g & h ^ g & a ^ h & a);
        b = b.wrapping_add(T1);
        f = f.wrapping_add(T1);
        X[11 as libc::c_int as usize] = CRYPTO_load_u32_be(data as *const libc::c_void);
        T1 = X[11 as libc::c_int as usize];
        data = data.offset(4 as libc::c_int as isize);
        T1 = T1
            .wrapping_add(
                e
                    .wrapping_add(
                        CRYPTO_rotr_u32(b, 6 as libc::c_int)
                            ^ CRYPTO_rotr_u32(b, 11 as libc::c_int)
                            ^ CRYPTO_rotr_u32(b, 25 as libc::c_int),
                    )
                    .wrapping_add(b & c ^ !b & d)
                    .wrapping_add(K256[11 as libc::c_int as usize]),
            );
        e = (CRYPTO_rotr_u32(f, 2 as libc::c_int) ^ CRYPTO_rotr_u32(f, 13 as libc::c_int)
            ^ CRYPTO_rotr_u32(f, 22 as libc::c_int))
            .wrapping_add(f & g ^ f & h ^ g & h);
        a = a.wrapping_add(T1);
        e = e.wrapping_add(T1);
        X[12 as libc::c_int as usize] = CRYPTO_load_u32_be(data as *const libc::c_void);
        T1 = X[12 as libc::c_int as usize];
        data = data.offset(4 as libc::c_int as isize);
        T1 = T1
            .wrapping_add(
                d
                    .wrapping_add(
                        CRYPTO_rotr_u32(a, 6 as libc::c_int)
                            ^ CRYPTO_rotr_u32(a, 11 as libc::c_int)
                            ^ CRYPTO_rotr_u32(a, 25 as libc::c_int),
                    )
                    .wrapping_add(a & b ^ !a & c)
                    .wrapping_add(K256[12 as libc::c_int as usize]),
            );
        d = (CRYPTO_rotr_u32(e, 2 as libc::c_int) ^ CRYPTO_rotr_u32(e, 13 as libc::c_int)
            ^ CRYPTO_rotr_u32(e, 22 as libc::c_int))
            .wrapping_add(e & f ^ e & g ^ f & g);
        h = h.wrapping_add(T1);
        d = d.wrapping_add(T1);
        X[13 as libc::c_int as usize] = CRYPTO_load_u32_be(data as *const libc::c_void);
        T1 = X[13 as libc::c_int as usize];
        data = data.offset(4 as libc::c_int as isize);
        T1 = T1
            .wrapping_add(
                c
                    .wrapping_add(
                        CRYPTO_rotr_u32(h, 6 as libc::c_int)
                            ^ CRYPTO_rotr_u32(h, 11 as libc::c_int)
                            ^ CRYPTO_rotr_u32(h, 25 as libc::c_int),
                    )
                    .wrapping_add(h & a ^ !h & b)
                    .wrapping_add(K256[13 as libc::c_int as usize]),
            );
        c = (CRYPTO_rotr_u32(d, 2 as libc::c_int) ^ CRYPTO_rotr_u32(d, 13 as libc::c_int)
            ^ CRYPTO_rotr_u32(d, 22 as libc::c_int))
            .wrapping_add(d & e ^ d & f ^ e & f);
        g = g.wrapping_add(T1);
        c = c.wrapping_add(T1);
        X[14 as libc::c_int as usize] = CRYPTO_load_u32_be(data as *const libc::c_void);
        T1 = X[14 as libc::c_int as usize];
        data = data.offset(4 as libc::c_int as isize);
        T1 = T1
            .wrapping_add(
                b
                    .wrapping_add(
                        CRYPTO_rotr_u32(g, 6 as libc::c_int)
                            ^ CRYPTO_rotr_u32(g, 11 as libc::c_int)
                            ^ CRYPTO_rotr_u32(g, 25 as libc::c_int),
                    )
                    .wrapping_add(g & h ^ !g & a)
                    .wrapping_add(K256[14 as libc::c_int as usize]),
            );
        b = (CRYPTO_rotr_u32(c, 2 as libc::c_int) ^ CRYPTO_rotr_u32(c, 13 as libc::c_int)
            ^ CRYPTO_rotr_u32(c, 22 as libc::c_int))
            .wrapping_add(c & d ^ c & e ^ d & e);
        f = f.wrapping_add(T1);
        b = b.wrapping_add(T1);
        X[15 as libc::c_int as usize] = CRYPTO_load_u32_be(data as *const libc::c_void);
        T1 = X[15 as libc::c_int as usize];
        data = data.offset(4 as libc::c_int as isize);
        T1 = T1
            .wrapping_add(
                a
                    .wrapping_add(
                        CRYPTO_rotr_u32(f, 6 as libc::c_int)
                            ^ CRYPTO_rotr_u32(f, 11 as libc::c_int)
                            ^ CRYPTO_rotr_u32(f, 25 as libc::c_int),
                    )
                    .wrapping_add(f & g ^ !f & h)
                    .wrapping_add(K256[15 as libc::c_int as usize]),
            );
        a = (CRYPTO_rotr_u32(b, 2 as libc::c_int) ^ CRYPTO_rotr_u32(b, 13 as libc::c_int)
            ^ CRYPTO_rotr_u32(b, 22 as libc::c_int))
            .wrapping_add(b & c ^ b & d ^ c & d);
        e = e.wrapping_add(T1);
        a = a.wrapping_add(T1);
        i = 16 as libc::c_int;
        while i < 64 as libc::c_int {
            s0 = X[(i + 0 as libc::c_int + 1 as libc::c_int & 0xf as libc::c_int)
                as usize];
            s0 = CRYPTO_rotr_u32(s0, 7 as libc::c_int)
                ^ CRYPTO_rotr_u32(s0, 18 as libc::c_int) ^ s0 >> 3 as libc::c_int;
            s1 = X[(i + 0 as libc::c_int + 14 as libc::c_int & 0xf as libc::c_int)
                as usize];
            s1 = CRYPTO_rotr_u32(s1, 17 as libc::c_int)
                ^ CRYPTO_rotr_u32(s1, 19 as libc::c_int) ^ s1 >> 10 as libc::c_int;
            X[(i + 0 as libc::c_int & 0xf as libc::c_int)
                as usize] = (X[(i + 0 as libc::c_int & 0xf as libc::c_int) as usize])
                .wrapping_add(
                    s0
                        .wrapping_add(s1)
                        .wrapping_add(
                            X[(i + 0 as libc::c_int + 9 as libc::c_int
                                & 0xf as libc::c_int) as usize],
                        ),
                );
            T1 = X[(i + 0 as libc::c_int & 0xf as libc::c_int) as usize];
            T1 = T1
                .wrapping_add(
                    h
                        .wrapping_add(
                            CRYPTO_rotr_u32(e, 6 as libc::c_int)
                                ^ CRYPTO_rotr_u32(e, 11 as libc::c_int)
                                ^ CRYPTO_rotr_u32(e, 25 as libc::c_int),
                        )
                        .wrapping_add(e & f ^ !e & g)
                        .wrapping_add(K256[(i + 0 as libc::c_int) as usize]),
                );
            h = (CRYPTO_rotr_u32(a, 2 as libc::c_int)
                ^ CRYPTO_rotr_u32(a, 13 as libc::c_int)
                ^ CRYPTO_rotr_u32(a, 22 as libc::c_int))
                .wrapping_add(a & b ^ a & c ^ b & c);
            d = d.wrapping_add(T1);
            h = h.wrapping_add(T1);
            s0 = X[(i + 1 as libc::c_int + 1 as libc::c_int & 0xf as libc::c_int)
                as usize];
            s0 = CRYPTO_rotr_u32(s0, 7 as libc::c_int)
                ^ CRYPTO_rotr_u32(s0, 18 as libc::c_int) ^ s0 >> 3 as libc::c_int;
            s1 = X[(i + 1 as libc::c_int + 14 as libc::c_int & 0xf as libc::c_int)
                as usize];
            s1 = CRYPTO_rotr_u32(s1, 17 as libc::c_int)
                ^ CRYPTO_rotr_u32(s1, 19 as libc::c_int) ^ s1 >> 10 as libc::c_int;
            X[(i + 1 as libc::c_int & 0xf as libc::c_int)
                as usize] = (X[(i + 1 as libc::c_int & 0xf as libc::c_int) as usize])
                .wrapping_add(
                    s0
                        .wrapping_add(s1)
                        .wrapping_add(
                            X[(i + 1 as libc::c_int + 9 as libc::c_int
                                & 0xf as libc::c_int) as usize],
                        ),
                );
            T1 = X[(i + 1 as libc::c_int & 0xf as libc::c_int) as usize];
            T1 = T1
                .wrapping_add(
                    g
                        .wrapping_add(
                            CRYPTO_rotr_u32(d, 6 as libc::c_int)
                                ^ CRYPTO_rotr_u32(d, 11 as libc::c_int)
                                ^ CRYPTO_rotr_u32(d, 25 as libc::c_int),
                        )
                        .wrapping_add(d & e ^ !d & f)
                        .wrapping_add(K256[(i + 1 as libc::c_int) as usize]),
                );
            g = (CRYPTO_rotr_u32(h, 2 as libc::c_int)
                ^ CRYPTO_rotr_u32(h, 13 as libc::c_int)
                ^ CRYPTO_rotr_u32(h, 22 as libc::c_int))
                .wrapping_add(h & a ^ h & b ^ a & b);
            c = c.wrapping_add(T1);
            g = g.wrapping_add(T1);
            s0 = X[(i + 2 as libc::c_int + 1 as libc::c_int & 0xf as libc::c_int)
                as usize];
            s0 = CRYPTO_rotr_u32(s0, 7 as libc::c_int)
                ^ CRYPTO_rotr_u32(s0, 18 as libc::c_int) ^ s0 >> 3 as libc::c_int;
            s1 = X[(i + 2 as libc::c_int + 14 as libc::c_int & 0xf as libc::c_int)
                as usize];
            s1 = CRYPTO_rotr_u32(s1, 17 as libc::c_int)
                ^ CRYPTO_rotr_u32(s1, 19 as libc::c_int) ^ s1 >> 10 as libc::c_int;
            X[(i + 2 as libc::c_int & 0xf as libc::c_int)
                as usize] = (X[(i + 2 as libc::c_int & 0xf as libc::c_int) as usize])
                .wrapping_add(
                    s0
                        .wrapping_add(s1)
                        .wrapping_add(
                            X[(i + 2 as libc::c_int + 9 as libc::c_int
                                & 0xf as libc::c_int) as usize],
                        ),
                );
            T1 = X[(i + 2 as libc::c_int & 0xf as libc::c_int) as usize];
            T1 = T1
                .wrapping_add(
                    f
                        .wrapping_add(
                            CRYPTO_rotr_u32(c, 6 as libc::c_int)
                                ^ CRYPTO_rotr_u32(c, 11 as libc::c_int)
                                ^ CRYPTO_rotr_u32(c, 25 as libc::c_int),
                        )
                        .wrapping_add(c & d ^ !c & e)
                        .wrapping_add(K256[(i + 2 as libc::c_int) as usize]),
                );
            f = (CRYPTO_rotr_u32(g, 2 as libc::c_int)
                ^ CRYPTO_rotr_u32(g, 13 as libc::c_int)
                ^ CRYPTO_rotr_u32(g, 22 as libc::c_int))
                .wrapping_add(g & h ^ g & a ^ h & a);
            b = b.wrapping_add(T1);
            f = f.wrapping_add(T1);
            s0 = X[(i + 3 as libc::c_int + 1 as libc::c_int & 0xf as libc::c_int)
                as usize];
            s0 = CRYPTO_rotr_u32(s0, 7 as libc::c_int)
                ^ CRYPTO_rotr_u32(s0, 18 as libc::c_int) ^ s0 >> 3 as libc::c_int;
            s1 = X[(i + 3 as libc::c_int + 14 as libc::c_int & 0xf as libc::c_int)
                as usize];
            s1 = CRYPTO_rotr_u32(s1, 17 as libc::c_int)
                ^ CRYPTO_rotr_u32(s1, 19 as libc::c_int) ^ s1 >> 10 as libc::c_int;
            X[(i + 3 as libc::c_int & 0xf as libc::c_int)
                as usize] = (X[(i + 3 as libc::c_int & 0xf as libc::c_int) as usize])
                .wrapping_add(
                    s0
                        .wrapping_add(s1)
                        .wrapping_add(
                            X[(i + 3 as libc::c_int + 9 as libc::c_int
                                & 0xf as libc::c_int) as usize],
                        ),
                );
            T1 = X[(i + 3 as libc::c_int & 0xf as libc::c_int) as usize];
            T1 = T1
                .wrapping_add(
                    e
                        .wrapping_add(
                            CRYPTO_rotr_u32(b, 6 as libc::c_int)
                                ^ CRYPTO_rotr_u32(b, 11 as libc::c_int)
                                ^ CRYPTO_rotr_u32(b, 25 as libc::c_int),
                        )
                        .wrapping_add(b & c ^ !b & d)
                        .wrapping_add(K256[(i + 3 as libc::c_int) as usize]),
                );
            e = (CRYPTO_rotr_u32(f, 2 as libc::c_int)
                ^ CRYPTO_rotr_u32(f, 13 as libc::c_int)
                ^ CRYPTO_rotr_u32(f, 22 as libc::c_int))
                .wrapping_add(f & g ^ f & h ^ g & h);
            a = a.wrapping_add(T1);
            e = e.wrapping_add(T1);
            s0 = X[(i + 4 as libc::c_int + 1 as libc::c_int & 0xf as libc::c_int)
                as usize];
            s0 = CRYPTO_rotr_u32(s0, 7 as libc::c_int)
                ^ CRYPTO_rotr_u32(s0, 18 as libc::c_int) ^ s0 >> 3 as libc::c_int;
            s1 = X[(i + 4 as libc::c_int + 14 as libc::c_int & 0xf as libc::c_int)
                as usize];
            s1 = CRYPTO_rotr_u32(s1, 17 as libc::c_int)
                ^ CRYPTO_rotr_u32(s1, 19 as libc::c_int) ^ s1 >> 10 as libc::c_int;
            X[(i + 4 as libc::c_int & 0xf as libc::c_int)
                as usize] = (X[(i + 4 as libc::c_int & 0xf as libc::c_int) as usize])
                .wrapping_add(
                    s0
                        .wrapping_add(s1)
                        .wrapping_add(
                            X[(i + 4 as libc::c_int + 9 as libc::c_int
                                & 0xf as libc::c_int) as usize],
                        ),
                );
            T1 = X[(i + 4 as libc::c_int & 0xf as libc::c_int) as usize];
            T1 = T1
                .wrapping_add(
                    d
                        .wrapping_add(
                            CRYPTO_rotr_u32(a, 6 as libc::c_int)
                                ^ CRYPTO_rotr_u32(a, 11 as libc::c_int)
                                ^ CRYPTO_rotr_u32(a, 25 as libc::c_int),
                        )
                        .wrapping_add(a & b ^ !a & c)
                        .wrapping_add(K256[(i + 4 as libc::c_int) as usize]),
                );
            d = (CRYPTO_rotr_u32(e, 2 as libc::c_int)
                ^ CRYPTO_rotr_u32(e, 13 as libc::c_int)
                ^ CRYPTO_rotr_u32(e, 22 as libc::c_int))
                .wrapping_add(e & f ^ e & g ^ f & g);
            h = h.wrapping_add(T1);
            d = d.wrapping_add(T1);
            s0 = X[(i + 5 as libc::c_int + 1 as libc::c_int & 0xf as libc::c_int)
                as usize];
            s0 = CRYPTO_rotr_u32(s0, 7 as libc::c_int)
                ^ CRYPTO_rotr_u32(s0, 18 as libc::c_int) ^ s0 >> 3 as libc::c_int;
            s1 = X[(i + 5 as libc::c_int + 14 as libc::c_int & 0xf as libc::c_int)
                as usize];
            s1 = CRYPTO_rotr_u32(s1, 17 as libc::c_int)
                ^ CRYPTO_rotr_u32(s1, 19 as libc::c_int) ^ s1 >> 10 as libc::c_int;
            X[(i + 5 as libc::c_int & 0xf as libc::c_int)
                as usize] = (X[(i + 5 as libc::c_int & 0xf as libc::c_int) as usize])
                .wrapping_add(
                    s0
                        .wrapping_add(s1)
                        .wrapping_add(
                            X[(i + 5 as libc::c_int + 9 as libc::c_int
                                & 0xf as libc::c_int) as usize],
                        ),
                );
            T1 = X[(i + 5 as libc::c_int & 0xf as libc::c_int) as usize];
            T1 = T1
                .wrapping_add(
                    c
                        .wrapping_add(
                            CRYPTO_rotr_u32(h, 6 as libc::c_int)
                                ^ CRYPTO_rotr_u32(h, 11 as libc::c_int)
                                ^ CRYPTO_rotr_u32(h, 25 as libc::c_int),
                        )
                        .wrapping_add(h & a ^ !h & b)
                        .wrapping_add(K256[(i + 5 as libc::c_int) as usize]),
                );
            c = (CRYPTO_rotr_u32(d, 2 as libc::c_int)
                ^ CRYPTO_rotr_u32(d, 13 as libc::c_int)
                ^ CRYPTO_rotr_u32(d, 22 as libc::c_int))
                .wrapping_add(d & e ^ d & f ^ e & f);
            g = g.wrapping_add(T1);
            c = c.wrapping_add(T1);
            s0 = X[(i + 6 as libc::c_int + 1 as libc::c_int & 0xf as libc::c_int)
                as usize];
            s0 = CRYPTO_rotr_u32(s0, 7 as libc::c_int)
                ^ CRYPTO_rotr_u32(s0, 18 as libc::c_int) ^ s0 >> 3 as libc::c_int;
            s1 = X[(i + 6 as libc::c_int + 14 as libc::c_int & 0xf as libc::c_int)
                as usize];
            s1 = CRYPTO_rotr_u32(s1, 17 as libc::c_int)
                ^ CRYPTO_rotr_u32(s1, 19 as libc::c_int) ^ s1 >> 10 as libc::c_int;
            X[(i + 6 as libc::c_int & 0xf as libc::c_int)
                as usize] = (X[(i + 6 as libc::c_int & 0xf as libc::c_int) as usize])
                .wrapping_add(
                    s0
                        .wrapping_add(s1)
                        .wrapping_add(
                            X[(i + 6 as libc::c_int + 9 as libc::c_int
                                & 0xf as libc::c_int) as usize],
                        ),
                );
            T1 = X[(i + 6 as libc::c_int & 0xf as libc::c_int) as usize];
            T1 = T1
                .wrapping_add(
                    b
                        .wrapping_add(
                            CRYPTO_rotr_u32(g, 6 as libc::c_int)
                                ^ CRYPTO_rotr_u32(g, 11 as libc::c_int)
                                ^ CRYPTO_rotr_u32(g, 25 as libc::c_int),
                        )
                        .wrapping_add(g & h ^ !g & a)
                        .wrapping_add(K256[(i + 6 as libc::c_int) as usize]),
                );
            b = (CRYPTO_rotr_u32(c, 2 as libc::c_int)
                ^ CRYPTO_rotr_u32(c, 13 as libc::c_int)
                ^ CRYPTO_rotr_u32(c, 22 as libc::c_int))
                .wrapping_add(c & d ^ c & e ^ d & e);
            f = f.wrapping_add(T1);
            b = b.wrapping_add(T1);
            s0 = X[(i + 7 as libc::c_int + 1 as libc::c_int & 0xf as libc::c_int)
                as usize];
            s0 = CRYPTO_rotr_u32(s0, 7 as libc::c_int)
                ^ CRYPTO_rotr_u32(s0, 18 as libc::c_int) ^ s0 >> 3 as libc::c_int;
            s1 = X[(i + 7 as libc::c_int + 14 as libc::c_int & 0xf as libc::c_int)
                as usize];
            s1 = CRYPTO_rotr_u32(s1, 17 as libc::c_int)
                ^ CRYPTO_rotr_u32(s1, 19 as libc::c_int) ^ s1 >> 10 as libc::c_int;
            X[(i + 7 as libc::c_int & 0xf as libc::c_int)
                as usize] = (X[(i + 7 as libc::c_int & 0xf as libc::c_int) as usize])
                .wrapping_add(
                    s0
                        .wrapping_add(s1)
                        .wrapping_add(
                            X[(i + 7 as libc::c_int + 9 as libc::c_int
                                & 0xf as libc::c_int) as usize],
                        ),
                );
            T1 = X[(i + 7 as libc::c_int & 0xf as libc::c_int) as usize];
            T1 = T1
                .wrapping_add(
                    a
                        .wrapping_add(
                            CRYPTO_rotr_u32(f, 6 as libc::c_int)
                                ^ CRYPTO_rotr_u32(f, 11 as libc::c_int)
                                ^ CRYPTO_rotr_u32(f, 25 as libc::c_int),
                        )
                        .wrapping_add(f & g ^ !f & h)
                        .wrapping_add(K256[(i + 7 as libc::c_int) as usize]),
                );
            a = (CRYPTO_rotr_u32(b, 2 as libc::c_int)
                ^ CRYPTO_rotr_u32(b, 13 as libc::c_int)
                ^ CRYPTO_rotr_u32(b, 22 as libc::c_int))
                .wrapping_add(b & c ^ b & d ^ c & d);
            e = e.wrapping_add(T1);
            a = a.wrapping_add(T1);
            i += 8 as libc::c_int;
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
    };
}
unsafe extern "C" fn sha256_block_data_order(
    mut state: *mut uint32_t,
    mut data: *const uint8_t,
    mut num: size_t,
) {
    sha256_block_data_order_nohw(state, data, num);
}
#[no_mangle]
pub unsafe extern "C" fn SHA256_TransformBlocks(
    mut state: *mut uint32_t,
    mut data: *const uint8_t,
    mut num_blocks: size_t,
) {
    sha256_block_data_order(state, data, num_blocks);
}
