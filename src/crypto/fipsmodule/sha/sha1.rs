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
pub struct sha_state_st {
    pub h: [uint32_t; 5],
    pub Nl: uint32_t,
    pub Nh: uint32_t,
    pub data: [uint8_t; 64],
    pub num: libc::c_uint,
}
pub type SHA_CTX = sha_state_st;
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
unsafe extern "C" fn CRYPTO_rotl_u32(
    mut value: uint32_t,
    mut shift: libc::c_int,
) -> uint32_t {
    return value << shift | value >> (-shift & 31 as libc::c_int);
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
    'c_9491: {
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
pub unsafe extern "C" fn SHA1_Init(mut sha: *mut SHA_CTX) -> libc::c_int {
    OPENSSL_memset(
        sha as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<SHA_CTX>() as libc::c_ulong,
    );
    (*sha).h[0 as libc::c_int as usize] = 0x67452301 as libc::c_ulong as uint32_t;
    (*sha).h[1 as libc::c_int as usize] = 0xefcdab89 as libc::c_ulong as uint32_t;
    (*sha).h[2 as libc::c_int as usize] = 0x98badcfe as libc::c_ulong as uint32_t;
    (*sha).h[3 as libc::c_int as usize] = 0x10325476 as libc::c_ulong as uint32_t;
    (*sha).h[4 as libc::c_int as usize] = 0xc3d2e1f0 as libc::c_ulong as uint32_t;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn SHA1_Init_from_state(
    mut sha: *mut SHA_CTX,
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
        ::core::mem::size_of::<SHA_CTX>() as libc::c_ulong,
    );
    let out_words: size_t = (20 as libc::c_int / 4 as libc::c_int) as size_t;
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
pub unsafe extern "C" fn SHA1(
    mut data: *const uint8_t,
    mut len: size_t,
    mut out: *mut uint8_t,
) -> *mut uint8_t {
    FIPS_service_indicator_lock_state();
    let mut ctx: SHA_CTX = sha_state_st {
        h: [0; 5],
        Nl: 0,
        Nh: 0,
        data: [0; 64],
        num: 0,
    };
    let ok: libc::c_int = (SHA1_Init(&mut ctx) != 0
        && SHA1_Update(&mut ctx, data as *const libc::c_void, len) != 0
        && SHA1_Final(out, &mut ctx) != 0) as libc::c_int;
    FIPS_service_indicator_unlock_state();
    if ok != 0 {
        FIPS_service_indicator_update_state();
    }
    OPENSSL_cleanse(
        &mut ctx as *mut SHA_CTX as *mut libc::c_void,
        ::core::mem::size_of::<SHA_CTX>() as libc::c_ulong,
    );
    return out;
}
#[no_mangle]
pub unsafe extern "C" fn SHA1_Transform(mut c: *mut SHA_CTX, mut data: *const uint8_t) {
    sha1_block_data_order(((*c).h).as_mut_ptr(), data, 1 as libc::c_int as size_t);
}
#[no_mangle]
pub unsafe extern "C" fn SHA1_Update(
    mut c: *mut SHA_CTX,
    mut data: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    crypto_md32_update(
        Some(
            sha1_block_data_order
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
pub unsafe extern "C" fn SHA1_Final(
    mut out: *mut uint8_t,
    mut c: *mut SHA_CTX,
) -> libc::c_int {
    crypto_md32_final(
        Some(
            sha1_block_data_order
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
    CRYPTO_store_u32_be(out as *mut libc::c_void, (*c).h[0 as libc::c_int as usize]);
    CRYPTO_store_u32_be(
        out.offset(4 as libc::c_int as isize) as *mut libc::c_void,
        (*c).h[1 as libc::c_int as usize],
    );
    CRYPTO_store_u32_be(
        out.offset(8 as libc::c_int as isize) as *mut libc::c_void,
        (*c).h[2 as libc::c_int as usize],
    );
    CRYPTO_store_u32_be(
        out.offset(12 as libc::c_int as isize) as *mut libc::c_void,
        (*c).h[3 as libc::c_int as usize],
    );
    CRYPTO_store_u32_be(
        out.offset(16 as libc::c_int as isize) as *mut libc::c_void,
        (*c).h[4 as libc::c_int as usize],
    );
    FIPS_service_indicator_update_state();
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn SHA1_get_state(
    mut ctx: *mut SHA_CTX,
    mut out_h: *mut uint8_t,
    mut out_n: *mut uint64_t,
) -> libc::c_int {
    if (*ctx).Nl as uint64_t
        % (64 as libc::c_int as uint64_t * 8 as libc::c_int as uint64_t)
        != 0 as libc::c_int as uint64_t
    {
        return 0 as libc::c_int;
    }
    let out_words: size_t = (20 as libc::c_int / 4 as libc::c_int) as size_t;
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
unsafe extern "C" fn sha1_block_data_order_nohw(
    mut state: *mut uint32_t,
    mut data: *const uint8_t,
    mut num: size_t,
) {
    let mut A: uint32_t = 0;
    let mut B: uint32_t = 0;
    let mut C: uint32_t = 0;
    let mut D: uint32_t = 0;
    let mut E: uint32_t = 0;
    let mut T: uint32_t = 0;
    let mut XX0: uint32_t = 0;
    let mut XX1: uint32_t = 0;
    let mut XX2: uint32_t = 0;
    let mut XX3: uint32_t = 0;
    let mut XX4: uint32_t = 0;
    let mut XX5: uint32_t = 0;
    let mut XX6: uint32_t = 0;
    let mut XX7: uint32_t = 0;
    let mut XX8: uint32_t = 0;
    let mut XX9: uint32_t = 0;
    let mut XX10: uint32_t = 0;
    let mut XX11: uint32_t = 0;
    let mut XX12: uint32_t = 0;
    let mut XX13: uint32_t = 0;
    let mut XX14: uint32_t = 0;
    let mut XX15: uint32_t = 0;
    A = *state.offset(0 as libc::c_int as isize);
    B = *state.offset(1 as libc::c_int as isize);
    C = *state.offset(2 as libc::c_int as isize);
    D = *state.offset(3 as libc::c_int as isize);
    E = *state.offset(4 as libc::c_int as isize);
    loop {
        XX0 = CRYPTO_load_u32_be(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        XX1 = CRYPTO_load_u32_be(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        T = (XX0.wrapping_add(E) as libc::c_ulong)
            .wrapping_add(0x5a827999 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(A, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add(((C ^ D) & B ^ D) as libc::c_ulong) as uint32_t;
        B = CRYPTO_rotl_u32(B, 30 as libc::c_int);
        XX2 = CRYPTO_load_u32_be(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        E = (XX1.wrapping_add(D) as libc::c_ulong)
            .wrapping_add(0x5a827999 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(T, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add(((B ^ C) & A ^ C) as libc::c_ulong) as uint32_t;
        A = CRYPTO_rotl_u32(A, 30 as libc::c_int);
        XX3 = CRYPTO_load_u32_be(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        D = (XX2.wrapping_add(C) as libc::c_ulong)
            .wrapping_add(0x5a827999 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(E, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add(((A ^ B) & T ^ B) as libc::c_ulong) as uint32_t;
        T = CRYPTO_rotl_u32(T, 30 as libc::c_int);
        XX4 = CRYPTO_load_u32_be(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        C = (XX3.wrapping_add(B) as libc::c_ulong)
            .wrapping_add(0x5a827999 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(D, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add(((T ^ A) & E ^ A) as libc::c_ulong) as uint32_t;
        E = CRYPTO_rotl_u32(E, 30 as libc::c_int);
        XX5 = CRYPTO_load_u32_be(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        B = (XX4.wrapping_add(A) as libc::c_ulong)
            .wrapping_add(0x5a827999 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(C, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add(((E ^ T) & D ^ T) as libc::c_ulong) as uint32_t;
        D = CRYPTO_rotl_u32(D, 30 as libc::c_int);
        XX6 = CRYPTO_load_u32_be(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        A = (XX5.wrapping_add(T) as libc::c_ulong)
            .wrapping_add(0x5a827999 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(B, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add(((D ^ E) & C ^ E) as libc::c_ulong) as uint32_t;
        C = CRYPTO_rotl_u32(C, 30 as libc::c_int);
        XX7 = CRYPTO_load_u32_be(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        T = (XX6.wrapping_add(E) as libc::c_ulong)
            .wrapping_add(0x5a827999 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(A, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add(((C ^ D) & B ^ D) as libc::c_ulong) as uint32_t;
        B = CRYPTO_rotl_u32(B, 30 as libc::c_int);
        XX8 = CRYPTO_load_u32_be(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        E = (XX7.wrapping_add(D) as libc::c_ulong)
            .wrapping_add(0x5a827999 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(T, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add(((B ^ C) & A ^ C) as libc::c_ulong) as uint32_t;
        A = CRYPTO_rotl_u32(A, 30 as libc::c_int);
        XX9 = CRYPTO_load_u32_be(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        D = (XX8.wrapping_add(C) as libc::c_ulong)
            .wrapping_add(0x5a827999 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(E, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add(((A ^ B) & T ^ B) as libc::c_ulong) as uint32_t;
        T = CRYPTO_rotl_u32(T, 30 as libc::c_int);
        XX10 = CRYPTO_load_u32_be(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        C = (XX9.wrapping_add(B) as libc::c_ulong)
            .wrapping_add(0x5a827999 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(D, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add(((T ^ A) & E ^ A) as libc::c_ulong) as uint32_t;
        E = CRYPTO_rotl_u32(E, 30 as libc::c_int);
        XX11 = CRYPTO_load_u32_be(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        B = (XX10.wrapping_add(A) as libc::c_ulong)
            .wrapping_add(0x5a827999 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(C, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add(((E ^ T) & D ^ T) as libc::c_ulong) as uint32_t;
        D = CRYPTO_rotl_u32(D, 30 as libc::c_int);
        XX12 = CRYPTO_load_u32_be(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        A = (XX11.wrapping_add(T) as libc::c_ulong)
            .wrapping_add(0x5a827999 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(B, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add(((D ^ E) & C ^ E) as libc::c_ulong) as uint32_t;
        C = CRYPTO_rotl_u32(C, 30 as libc::c_int);
        XX13 = CRYPTO_load_u32_be(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        T = (XX12.wrapping_add(E) as libc::c_ulong)
            .wrapping_add(0x5a827999 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(A, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add(((C ^ D) & B ^ D) as libc::c_ulong) as uint32_t;
        B = CRYPTO_rotl_u32(B, 30 as libc::c_int);
        XX14 = CRYPTO_load_u32_be(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        E = (XX13.wrapping_add(D) as libc::c_ulong)
            .wrapping_add(0x5a827999 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(T, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add(((B ^ C) & A ^ C) as libc::c_ulong) as uint32_t;
        A = CRYPTO_rotl_u32(A, 30 as libc::c_int);
        XX15 = CRYPTO_load_u32_be(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        D = (XX14.wrapping_add(C) as libc::c_ulong)
            .wrapping_add(0x5a827999 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(E, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add(((A ^ B) & T ^ B) as libc::c_ulong) as uint32_t;
        T = CRYPTO_rotl_u32(T, 30 as libc::c_int);
        C = (XX15.wrapping_add(B) as libc::c_ulong)
            .wrapping_add(0x5a827999 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(D, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add(((T ^ A) & E ^ A) as libc::c_ulong) as uint32_t;
        E = CRYPTO_rotl_u32(E, 30 as libc::c_int);
        B = XX0 ^ XX2 ^ XX8 ^ XX13;
        B = CRYPTO_rotl_u32(B, 1 as libc::c_int);
        XX0 = B;
        B = (B as libc::c_ulong)
            .wrapping_add(
                (A as libc::c_ulong)
                    .wrapping_add(0x5a827999 as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(C, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add(((E ^ T) & D ^ T) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        D = CRYPTO_rotl_u32(D, 30 as libc::c_int);
        A = XX1 ^ XX3 ^ XX9 ^ XX14;
        A = CRYPTO_rotl_u32(A, 1 as libc::c_int);
        XX1 = A;
        A = (A as libc::c_ulong)
            .wrapping_add(
                (T as libc::c_ulong)
                    .wrapping_add(0x5a827999 as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(B, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add(((D ^ E) & C ^ E) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        C = CRYPTO_rotl_u32(C, 30 as libc::c_int);
        T = XX2 ^ XX4 ^ XX10 ^ XX15;
        T = CRYPTO_rotl_u32(T, 1 as libc::c_int);
        XX2 = T;
        T = (T as libc::c_ulong)
            .wrapping_add(
                (E as libc::c_ulong)
                    .wrapping_add(0x5a827999 as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(A, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add(((C ^ D) & B ^ D) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        B = CRYPTO_rotl_u32(B, 30 as libc::c_int);
        E = XX3 ^ XX5 ^ XX11 ^ XX0;
        E = CRYPTO_rotl_u32(E, 1 as libc::c_int);
        XX3 = E;
        E = (E as libc::c_ulong)
            .wrapping_add(
                (D as libc::c_ulong)
                    .wrapping_add(0x5a827999 as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(T, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add(((B ^ C) & A ^ C) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        A = CRYPTO_rotl_u32(A, 30 as libc::c_int);
        D = XX4 ^ XX6 ^ XX12 ^ XX1;
        D = CRYPTO_rotl_u32(D, 1 as libc::c_int);
        XX4 = D;
        D = (D as libc::c_ulong)
            .wrapping_add(
                (C as libc::c_ulong)
                    .wrapping_add(0x6ed9eba1 as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(E, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((T ^ A ^ B) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        T = CRYPTO_rotl_u32(T, 30 as libc::c_int);
        C = XX5 ^ XX7 ^ XX13 ^ XX2;
        C = CRYPTO_rotl_u32(C, 1 as libc::c_int);
        XX5 = C;
        C = (C as libc::c_ulong)
            .wrapping_add(
                (B as libc::c_ulong)
                    .wrapping_add(0x6ed9eba1 as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(D, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((E ^ T ^ A) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        E = CRYPTO_rotl_u32(E, 30 as libc::c_int);
        B = XX6 ^ XX8 ^ XX14 ^ XX3;
        B = CRYPTO_rotl_u32(B, 1 as libc::c_int);
        XX6 = B;
        B = (B as libc::c_ulong)
            .wrapping_add(
                (A as libc::c_ulong)
                    .wrapping_add(0x6ed9eba1 as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(C, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((D ^ E ^ T) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        D = CRYPTO_rotl_u32(D, 30 as libc::c_int);
        A = XX7 ^ XX9 ^ XX15 ^ XX4;
        A = CRYPTO_rotl_u32(A, 1 as libc::c_int);
        XX7 = A;
        A = (A as libc::c_ulong)
            .wrapping_add(
                (T as libc::c_ulong)
                    .wrapping_add(0x6ed9eba1 as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(B, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((C ^ D ^ E) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        C = CRYPTO_rotl_u32(C, 30 as libc::c_int);
        T = XX8 ^ XX10 ^ XX0 ^ XX5;
        T = CRYPTO_rotl_u32(T, 1 as libc::c_int);
        XX8 = T;
        T = (T as libc::c_ulong)
            .wrapping_add(
                (E as libc::c_ulong)
                    .wrapping_add(0x6ed9eba1 as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(A, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((B ^ C ^ D) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        B = CRYPTO_rotl_u32(B, 30 as libc::c_int);
        E = XX9 ^ XX11 ^ XX1 ^ XX6;
        E = CRYPTO_rotl_u32(E, 1 as libc::c_int);
        XX9 = E;
        E = (E as libc::c_ulong)
            .wrapping_add(
                (D as libc::c_ulong)
                    .wrapping_add(0x6ed9eba1 as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(T, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((A ^ B ^ C) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        A = CRYPTO_rotl_u32(A, 30 as libc::c_int);
        D = XX10 ^ XX12 ^ XX2 ^ XX7;
        D = CRYPTO_rotl_u32(D, 1 as libc::c_int);
        XX10 = D;
        D = (D as libc::c_ulong)
            .wrapping_add(
                (C as libc::c_ulong)
                    .wrapping_add(0x6ed9eba1 as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(E, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((T ^ A ^ B) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        T = CRYPTO_rotl_u32(T, 30 as libc::c_int);
        C = XX11 ^ XX13 ^ XX3 ^ XX8;
        C = CRYPTO_rotl_u32(C, 1 as libc::c_int);
        XX11 = C;
        C = (C as libc::c_ulong)
            .wrapping_add(
                (B as libc::c_ulong)
                    .wrapping_add(0x6ed9eba1 as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(D, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((E ^ T ^ A) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        E = CRYPTO_rotl_u32(E, 30 as libc::c_int);
        B = XX12 ^ XX14 ^ XX4 ^ XX9;
        B = CRYPTO_rotl_u32(B, 1 as libc::c_int);
        XX12 = B;
        B = (B as libc::c_ulong)
            .wrapping_add(
                (A as libc::c_ulong)
                    .wrapping_add(0x6ed9eba1 as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(C, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((D ^ E ^ T) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        D = CRYPTO_rotl_u32(D, 30 as libc::c_int);
        A = XX13 ^ XX15 ^ XX5 ^ XX10;
        A = CRYPTO_rotl_u32(A, 1 as libc::c_int);
        XX13 = A;
        A = (A as libc::c_ulong)
            .wrapping_add(
                (T as libc::c_ulong)
                    .wrapping_add(0x6ed9eba1 as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(B, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((C ^ D ^ E) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        C = CRYPTO_rotl_u32(C, 30 as libc::c_int);
        T = XX14 ^ XX0 ^ XX6 ^ XX11;
        T = CRYPTO_rotl_u32(T, 1 as libc::c_int);
        XX14 = T;
        T = (T as libc::c_ulong)
            .wrapping_add(
                (E as libc::c_ulong)
                    .wrapping_add(0x6ed9eba1 as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(A, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((B ^ C ^ D) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        B = CRYPTO_rotl_u32(B, 30 as libc::c_int);
        E = XX15 ^ XX1 ^ XX7 ^ XX12;
        E = CRYPTO_rotl_u32(E, 1 as libc::c_int);
        XX15 = E;
        E = (E as libc::c_ulong)
            .wrapping_add(
                (D as libc::c_ulong)
                    .wrapping_add(0x6ed9eba1 as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(T, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((A ^ B ^ C) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        A = CRYPTO_rotl_u32(A, 30 as libc::c_int);
        D = XX0 ^ XX2 ^ XX8 ^ XX13;
        D = CRYPTO_rotl_u32(D, 1 as libc::c_int);
        XX0 = D;
        D = (D as libc::c_ulong)
            .wrapping_add(
                (C as libc::c_ulong)
                    .wrapping_add(0x6ed9eba1 as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(E, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((T ^ A ^ B) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        T = CRYPTO_rotl_u32(T, 30 as libc::c_int);
        C = XX1 ^ XX3 ^ XX9 ^ XX14;
        C = CRYPTO_rotl_u32(C, 1 as libc::c_int);
        XX1 = C;
        C = (C as libc::c_ulong)
            .wrapping_add(
                (B as libc::c_ulong)
                    .wrapping_add(0x6ed9eba1 as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(D, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((E ^ T ^ A) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        E = CRYPTO_rotl_u32(E, 30 as libc::c_int);
        B = XX2 ^ XX4 ^ XX10 ^ XX15;
        B = CRYPTO_rotl_u32(B, 1 as libc::c_int);
        XX2 = B;
        B = (B as libc::c_ulong)
            .wrapping_add(
                (A as libc::c_ulong)
                    .wrapping_add(0x6ed9eba1 as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(C, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((D ^ E ^ T) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        D = CRYPTO_rotl_u32(D, 30 as libc::c_int);
        A = XX3 ^ XX5 ^ XX11 ^ XX0;
        A = CRYPTO_rotl_u32(A, 1 as libc::c_int);
        XX3 = A;
        A = (A as libc::c_ulong)
            .wrapping_add(
                (T as libc::c_ulong)
                    .wrapping_add(0x6ed9eba1 as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(B, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((C ^ D ^ E) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        C = CRYPTO_rotl_u32(C, 30 as libc::c_int);
        T = XX4 ^ XX6 ^ XX12 ^ XX1;
        T = CRYPTO_rotl_u32(T, 1 as libc::c_int);
        XX4 = T;
        T = (T as libc::c_ulong)
            .wrapping_add(
                (E as libc::c_ulong)
                    .wrapping_add(0x6ed9eba1 as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(A, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((B ^ C ^ D) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        B = CRYPTO_rotl_u32(B, 30 as libc::c_int);
        E = XX5 ^ XX7 ^ XX13 ^ XX2;
        E = CRYPTO_rotl_u32(E, 1 as libc::c_int);
        XX5 = E;
        E = (E as libc::c_ulong)
            .wrapping_add(
                (D as libc::c_ulong)
                    .wrapping_add(0x6ed9eba1 as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(T, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((A ^ B ^ C) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        A = CRYPTO_rotl_u32(A, 30 as libc::c_int);
        D = XX6 ^ XX8 ^ XX14 ^ XX3;
        D = CRYPTO_rotl_u32(D, 1 as libc::c_int);
        XX6 = D;
        D = (D as libc::c_ulong)
            .wrapping_add(
                (C as libc::c_ulong)
                    .wrapping_add(0x6ed9eba1 as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(E, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((T ^ A ^ B) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        T = CRYPTO_rotl_u32(T, 30 as libc::c_int);
        C = XX7 ^ XX9 ^ XX15 ^ XX4;
        C = CRYPTO_rotl_u32(C, 1 as libc::c_int);
        XX7 = C;
        C = (C as libc::c_ulong)
            .wrapping_add(
                (B as libc::c_ulong)
                    .wrapping_add(0x6ed9eba1 as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(D, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((E ^ T ^ A) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        E = CRYPTO_rotl_u32(E, 30 as libc::c_int);
        B = XX8 ^ XX10 ^ XX0 ^ XX5;
        B = CRYPTO_rotl_u32(B, 1 as libc::c_int);
        XX8 = B;
        B = (B as libc::c_ulong)
            .wrapping_add(
                (A as libc::c_ulong)
                    .wrapping_add(0x8f1bbcdc as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(C, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((D & E | (D | E) & T) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        D = CRYPTO_rotl_u32(D, 30 as libc::c_int);
        A = XX9 ^ XX11 ^ XX1 ^ XX6;
        A = CRYPTO_rotl_u32(A, 1 as libc::c_int);
        XX9 = A;
        A = (A as libc::c_ulong)
            .wrapping_add(
                (T as libc::c_ulong)
                    .wrapping_add(0x8f1bbcdc as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(B, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((C & D | (C | D) & E) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        C = CRYPTO_rotl_u32(C, 30 as libc::c_int);
        T = XX10 ^ XX12 ^ XX2 ^ XX7;
        T = CRYPTO_rotl_u32(T, 1 as libc::c_int);
        XX10 = T;
        T = (T as libc::c_ulong)
            .wrapping_add(
                (E as libc::c_ulong)
                    .wrapping_add(0x8f1bbcdc as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(A, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((B & C | (B | C) & D) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        B = CRYPTO_rotl_u32(B, 30 as libc::c_int);
        E = XX11 ^ XX13 ^ XX3 ^ XX8;
        E = CRYPTO_rotl_u32(E, 1 as libc::c_int);
        XX11 = E;
        E = (E as libc::c_ulong)
            .wrapping_add(
                (D as libc::c_ulong)
                    .wrapping_add(0x8f1bbcdc as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(T, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((A & B | (A | B) & C) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        A = CRYPTO_rotl_u32(A, 30 as libc::c_int);
        D = XX12 ^ XX14 ^ XX4 ^ XX9;
        D = CRYPTO_rotl_u32(D, 1 as libc::c_int);
        XX12 = D;
        D = (D as libc::c_ulong)
            .wrapping_add(
                (C as libc::c_ulong)
                    .wrapping_add(0x8f1bbcdc as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(E, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((T & A | (T | A) & B) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        T = CRYPTO_rotl_u32(T, 30 as libc::c_int);
        C = XX13 ^ XX15 ^ XX5 ^ XX10;
        C = CRYPTO_rotl_u32(C, 1 as libc::c_int);
        XX13 = C;
        C = (C as libc::c_ulong)
            .wrapping_add(
                (B as libc::c_ulong)
                    .wrapping_add(0x8f1bbcdc as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(D, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((E & T | (E | T) & A) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        E = CRYPTO_rotl_u32(E, 30 as libc::c_int);
        B = XX14 ^ XX0 ^ XX6 ^ XX11;
        B = CRYPTO_rotl_u32(B, 1 as libc::c_int);
        XX14 = B;
        B = (B as libc::c_ulong)
            .wrapping_add(
                (A as libc::c_ulong)
                    .wrapping_add(0x8f1bbcdc as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(C, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((D & E | (D | E) & T) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        D = CRYPTO_rotl_u32(D, 30 as libc::c_int);
        A = XX15 ^ XX1 ^ XX7 ^ XX12;
        A = CRYPTO_rotl_u32(A, 1 as libc::c_int);
        XX15 = A;
        A = (A as libc::c_ulong)
            .wrapping_add(
                (T as libc::c_ulong)
                    .wrapping_add(0x8f1bbcdc as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(B, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((C & D | (C | D) & E) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        C = CRYPTO_rotl_u32(C, 30 as libc::c_int);
        T = XX0 ^ XX2 ^ XX8 ^ XX13;
        T = CRYPTO_rotl_u32(T, 1 as libc::c_int);
        XX0 = T;
        T = (T as libc::c_ulong)
            .wrapping_add(
                (E as libc::c_ulong)
                    .wrapping_add(0x8f1bbcdc as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(A, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((B & C | (B | C) & D) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        B = CRYPTO_rotl_u32(B, 30 as libc::c_int);
        E = XX1 ^ XX3 ^ XX9 ^ XX14;
        E = CRYPTO_rotl_u32(E, 1 as libc::c_int);
        XX1 = E;
        E = (E as libc::c_ulong)
            .wrapping_add(
                (D as libc::c_ulong)
                    .wrapping_add(0x8f1bbcdc as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(T, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((A & B | (A | B) & C) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        A = CRYPTO_rotl_u32(A, 30 as libc::c_int);
        D = XX2 ^ XX4 ^ XX10 ^ XX15;
        D = CRYPTO_rotl_u32(D, 1 as libc::c_int);
        XX2 = D;
        D = (D as libc::c_ulong)
            .wrapping_add(
                (C as libc::c_ulong)
                    .wrapping_add(0x8f1bbcdc as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(E, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((T & A | (T | A) & B) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        T = CRYPTO_rotl_u32(T, 30 as libc::c_int);
        C = XX3 ^ XX5 ^ XX11 ^ XX0;
        C = CRYPTO_rotl_u32(C, 1 as libc::c_int);
        XX3 = C;
        C = (C as libc::c_ulong)
            .wrapping_add(
                (B as libc::c_ulong)
                    .wrapping_add(0x8f1bbcdc as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(D, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((E & T | (E | T) & A) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        E = CRYPTO_rotl_u32(E, 30 as libc::c_int);
        B = XX4 ^ XX6 ^ XX12 ^ XX1;
        B = CRYPTO_rotl_u32(B, 1 as libc::c_int);
        XX4 = B;
        B = (B as libc::c_ulong)
            .wrapping_add(
                (A as libc::c_ulong)
                    .wrapping_add(0x8f1bbcdc as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(C, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((D & E | (D | E) & T) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        D = CRYPTO_rotl_u32(D, 30 as libc::c_int);
        A = XX5 ^ XX7 ^ XX13 ^ XX2;
        A = CRYPTO_rotl_u32(A, 1 as libc::c_int);
        XX5 = A;
        A = (A as libc::c_ulong)
            .wrapping_add(
                (T as libc::c_ulong)
                    .wrapping_add(0x8f1bbcdc as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(B, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((C & D | (C | D) & E) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        C = CRYPTO_rotl_u32(C, 30 as libc::c_int);
        T = XX6 ^ XX8 ^ XX14 ^ XX3;
        T = CRYPTO_rotl_u32(T, 1 as libc::c_int);
        XX6 = T;
        T = (T as libc::c_ulong)
            .wrapping_add(
                (E as libc::c_ulong)
                    .wrapping_add(0x8f1bbcdc as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(A, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((B & C | (B | C) & D) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        B = CRYPTO_rotl_u32(B, 30 as libc::c_int);
        E = XX7 ^ XX9 ^ XX15 ^ XX4;
        E = CRYPTO_rotl_u32(E, 1 as libc::c_int);
        XX7 = E;
        E = (E as libc::c_ulong)
            .wrapping_add(
                (D as libc::c_ulong)
                    .wrapping_add(0x8f1bbcdc as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(T, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((A & B | (A | B) & C) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        A = CRYPTO_rotl_u32(A, 30 as libc::c_int);
        D = XX8 ^ XX10 ^ XX0 ^ XX5;
        D = CRYPTO_rotl_u32(D, 1 as libc::c_int);
        XX8 = D;
        D = (D as libc::c_ulong)
            .wrapping_add(
                (C as libc::c_ulong)
                    .wrapping_add(0x8f1bbcdc as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(E, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((T & A | (T | A) & B) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        T = CRYPTO_rotl_u32(T, 30 as libc::c_int);
        C = XX9 ^ XX11 ^ XX1 ^ XX6;
        C = CRYPTO_rotl_u32(C, 1 as libc::c_int);
        XX9 = C;
        C = (C as libc::c_ulong)
            .wrapping_add(
                (B as libc::c_ulong)
                    .wrapping_add(0x8f1bbcdc as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(D, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((E & T | (E | T) & A) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        E = CRYPTO_rotl_u32(E, 30 as libc::c_int);
        B = XX10 ^ XX12 ^ XX2 ^ XX7;
        B = CRYPTO_rotl_u32(B, 1 as libc::c_int);
        XX10 = B;
        B = (B as libc::c_ulong)
            .wrapping_add(
                (A as libc::c_ulong)
                    .wrapping_add(0x8f1bbcdc as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(C, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((D & E | (D | E) & T) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        D = CRYPTO_rotl_u32(D, 30 as libc::c_int);
        A = XX11 ^ XX13 ^ XX3 ^ XX8;
        A = CRYPTO_rotl_u32(A, 1 as libc::c_int);
        XX11 = A;
        A = (A as libc::c_ulong)
            .wrapping_add(
                (T as libc::c_ulong)
                    .wrapping_add(0x8f1bbcdc as libc::c_ulong)
                    .wrapping_add(CRYPTO_rotl_u32(B, 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_add((C & D | (C | D) & E) as libc::c_ulong),
            ) as uint32_t as uint32_t;
        C = CRYPTO_rotl_u32(C, 30 as libc::c_int);
        T = XX12 ^ XX14 ^ XX4 ^ XX9;
        T = CRYPTO_rotl_u32(T, 1 as libc::c_int);
        XX12 = T;
        T = (XX12.wrapping_add(E) as libc::c_ulong)
            .wrapping_add(0xca62c1d6 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(A, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add((B ^ C ^ D) as libc::c_ulong) as uint32_t;
        B = CRYPTO_rotl_u32(B, 30 as libc::c_int);
        E = XX13 ^ XX15 ^ XX5 ^ XX10;
        E = CRYPTO_rotl_u32(E, 1 as libc::c_int);
        XX13 = E;
        E = (XX13.wrapping_add(D) as libc::c_ulong)
            .wrapping_add(0xca62c1d6 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(T, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add((A ^ B ^ C) as libc::c_ulong) as uint32_t;
        A = CRYPTO_rotl_u32(A, 30 as libc::c_int);
        D = XX14 ^ XX0 ^ XX6 ^ XX11;
        D = CRYPTO_rotl_u32(D, 1 as libc::c_int);
        XX14 = D;
        D = (XX14.wrapping_add(C) as libc::c_ulong)
            .wrapping_add(0xca62c1d6 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(E, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add((T ^ A ^ B) as libc::c_ulong) as uint32_t;
        T = CRYPTO_rotl_u32(T, 30 as libc::c_int);
        C = XX15 ^ XX1 ^ XX7 ^ XX12;
        C = CRYPTO_rotl_u32(C, 1 as libc::c_int);
        XX15 = C;
        C = (XX15.wrapping_add(B) as libc::c_ulong)
            .wrapping_add(0xca62c1d6 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(D, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add((E ^ T ^ A) as libc::c_ulong) as uint32_t;
        E = CRYPTO_rotl_u32(E, 30 as libc::c_int);
        B = XX0 ^ XX2 ^ XX8 ^ XX13;
        B = CRYPTO_rotl_u32(B, 1 as libc::c_int);
        XX0 = B;
        B = (XX0.wrapping_add(A) as libc::c_ulong)
            .wrapping_add(0xca62c1d6 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(C, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add((D ^ E ^ T) as libc::c_ulong) as uint32_t;
        D = CRYPTO_rotl_u32(D, 30 as libc::c_int);
        A = XX1 ^ XX3 ^ XX9 ^ XX14;
        A = CRYPTO_rotl_u32(A, 1 as libc::c_int);
        XX1 = A;
        A = (XX1.wrapping_add(T) as libc::c_ulong)
            .wrapping_add(0xca62c1d6 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(B, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add((C ^ D ^ E) as libc::c_ulong) as uint32_t;
        C = CRYPTO_rotl_u32(C, 30 as libc::c_int);
        T = XX2 ^ XX4 ^ XX10 ^ XX15;
        T = CRYPTO_rotl_u32(T, 1 as libc::c_int);
        XX2 = T;
        T = (XX2.wrapping_add(E) as libc::c_ulong)
            .wrapping_add(0xca62c1d6 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(A, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add((B ^ C ^ D) as libc::c_ulong) as uint32_t;
        B = CRYPTO_rotl_u32(B, 30 as libc::c_int);
        E = XX3 ^ XX5 ^ XX11 ^ XX0;
        E = CRYPTO_rotl_u32(E, 1 as libc::c_int);
        XX3 = E;
        E = (XX3.wrapping_add(D) as libc::c_ulong)
            .wrapping_add(0xca62c1d6 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(T, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add((A ^ B ^ C) as libc::c_ulong) as uint32_t;
        A = CRYPTO_rotl_u32(A, 30 as libc::c_int);
        D = XX4 ^ XX6 ^ XX12 ^ XX1;
        D = CRYPTO_rotl_u32(D, 1 as libc::c_int);
        XX4 = D;
        D = (XX4.wrapping_add(C) as libc::c_ulong)
            .wrapping_add(0xca62c1d6 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(E, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add((T ^ A ^ B) as libc::c_ulong) as uint32_t;
        T = CRYPTO_rotl_u32(T, 30 as libc::c_int);
        C = XX5 ^ XX7 ^ XX13 ^ XX2;
        C = CRYPTO_rotl_u32(C, 1 as libc::c_int);
        XX5 = C;
        C = (XX5.wrapping_add(B) as libc::c_ulong)
            .wrapping_add(0xca62c1d6 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(D, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add((E ^ T ^ A) as libc::c_ulong) as uint32_t;
        E = CRYPTO_rotl_u32(E, 30 as libc::c_int);
        B = XX6 ^ XX8 ^ XX14 ^ XX3;
        B = CRYPTO_rotl_u32(B, 1 as libc::c_int);
        XX6 = B;
        B = (XX6.wrapping_add(A) as libc::c_ulong)
            .wrapping_add(0xca62c1d6 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(C, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add((D ^ E ^ T) as libc::c_ulong) as uint32_t;
        D = CRYPTO_rotl_u32(D, 30 as libc::c_int);
        A = XX7 ^ XX9 ^ XX15 ^ XX4;
        A = CRYPTO_rotl_u32(A, 1 as libc::c_int);
        XX7 = A;
        A = (XX7.wrapping_add(T) as libc::c_ulong)
            .wrapping_add(0xca62c1d6 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(B, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add((C ^ D ^ E) as libc::c_ulong) as uint32_t;
        C = CRYPTO_rotl_u32(C, 30 as libc::c_int);
        T = XX8 ^ XX10 ^ XX0 ^ XX5;
        T = CRYPTO_rotl_u32(T, 1 as libc::c_int);
        XX8 = T;
        T = (XX8.wrapping_add(E) as libc::c_ulong)
            .wrapping_add(0xca62c1d6 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(A, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add((B ^ C ^ D) as libc::c_ulong) as uint32_t;
        B = CRYPTO_rotl_u32(B, 30 as libc::c_int);
        E = XX9 ^ XX11 ^ XX1 ^ XX6;
        E = CRYPTO_rotl_u32(E, 1 as libc::c_int);
        XX9 = E;
        E = (XX9.wrapping_add(D) as libc::c_ulong)
            .wrapping_add(0xca62c1d6 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(T, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add((A ^ B ^ C) as libc::c_ulong) as uint32_t;
        A = CRYPTO_rotl_u32(A, 30 as libc::c_int);
        D = XX10 ^ XX12 ^ XX2 ^ XX7;
        D = CRYPTO_rotl_u32(D, 1 as libc::c_int);
        XX10 = D;
        D = (XX10.wrapping_add(C) as libc::c_ulong)
            .wrapping_add(0xca62c1d6 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(E, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add((T ^ A ^ B) as libc::c_ulong) as uint32_t;
        T = CRYPTO_rotl_u32(T, 30 as libc::c_int);
        C = XX11 ^ XX13 ^ XX3 ^ XX8;
        C = CRYPTO_rotl_u32(C, 1 as libc::c_int);
        XX11 = C;
        C = (XX11.wrapping_add(B) as libc::c_ulong)
            .wrapping_add(0xca62c1d6 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(D, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add((E ^ T ^ A) as libc::c_ulong) as uint32_t;
        E = CRYPTO_rotl_u32(E, 30 as libc::c_int);
        B = XX12 ^ XX14 ^ XX4 ^ XX9;
        B = CRYPTO_rotl_u32(B, 1 as libc::c_int);
        XX12 = B;
        B = (XX12.wrapping_add(A) as libc::c_ulong)
            .wrapping_add(0xca62c1d6 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(C, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add((D ^ E ^ T) as libc::c_ulong) as uint32_t;
        D = CRYPTO_rotl_u32(D, 30 as libc::c_int);
        A = XX13 ^ XX15 ^ XX5 ^ XX10;
        A = CRYPTO_rotl_u32(A, 1 as libc::c_int);
        XX13 = A;
        A = (XX13.wrapping_add(T) as libc::c_ulong)
            .wrapping_add(0xca62c1d6 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(B, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add((C ^ D ^ E) as libc::c_ulong) as uint32_t;
        C = CRYPTO_rotl_u32(C, 30 as libc::c_int);
        T = XX14 ^ XX0 ^ XX6 ^ XX11;
        T = CRYPTO_rotl_u32(T, 1 as libc::c_int);
        XX14 = T;
        T = (XX14.wrapping_add(E) as libc::c_ulong)
            .wrapping_add(0xca62c1d6 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(A, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add((B ^ C ^ D) as libc::c_ulong) as uint32_t;
        B = CRYPTO_rotl_u32(B, 30 as libc::c_int);
        E = XX15 ^ XX1 ^ XX7 ^ XX12;
        E = CRYPTO_rotl_u32(E, 1 as libc::c_int);
        XX15 = E;
        E = (XX15.wrapping_add(D) as libc::c_ulong)
            .wrapping_add(0xca62c1d6 as libc::c_ulong)
            .wrapping_add(CRYPTO_rotl_u32(T, 5 as libc::c_int) as libc::c_ulong)
            .wrapping_add((A ^ B ^ C) as libc::c_ulong) as uint32_t;
        A = CRYPTO_rotl_u32(A, 30 as libc::c_int);
        *state
            .offset(
                0 as libc::c_int as isize,
            ) = ((*state.offset(0 as libc::c_int as isize)).wrapping_add(E)
            as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
        *state
            .offset(
                1 as libc::c_int as isize,
            ) = ((*state.offset(1 as libc::c_int as isize)).wrapping_add(T)
            as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
        *state
            .offset(
                2 as libc::c_int as isize,
            ) = ((*state.offset(2 as libc::c_int as isize)).wrapping_add(A)
            as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
        *state
            .offset(
                3 as libc::c_int as isize,
            ) = ((*state.offset(3 as libc::c_int as isize)).wrapping_add(B)
            as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
        *state
            .offset(
                4 as libc::c_int as isize,
            ) = ((*state.offset(4 as libc::c_int as isize)).wrapping_add(C)
            as libc::c_long & 0xffffffff as libc::c_long) as uint32_t;
        num = num.wrapping_sub(1);
        if num == 0 as libc::c_int as size_t {
            break;
        }
        A = *state.offset(0 as libc::c_int as isize);
        B = *state.offset(1 as libc::c_int as isize);
        C = *state.offset(2 as libc::c_int as isize);
        D = *state.offset(3 as libc::c_int as isize);
        E = *state.offset(4 as libc::c_int as isize);
    };
}
unsafe extern "C" fn sha1_block_data_order(
    mut state: *mut uint32_t,
    mut data: *const uint8_t,
    mut num: size_t,
) {
    sha1_block_data_order_nohw(state, data, num);
}
