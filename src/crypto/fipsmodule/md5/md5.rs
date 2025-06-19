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
pub struct md5_state_st {
    pub h: [uint32_t; 4],
    pub Nl: uint32_t,
    pub Nh: uint32_t,
    pub data: [uint8_t; 64],
    pub num: libc::c_uint,
}
pub type MD5_CTX = md5_state_st;
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
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/md5/../digest/md32_common.h\0"
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
    'c_5775: {
        if n < block_size {} else {
            __assert_fail(
                b"n < block_size\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/md5/../digest/md32_common.h\0"
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
pub unsafe extern "C" fn MD5(
    mut data: *const uint8_t,
    mut len: size_t,
    mut out: *mut uint8_t,
) -> *mut uint8_t {
    let mut ctx: MD5_CTX = md5_state_st {
        h: [0; 4],
        Nl: 0,
        Nh: 0,
        data: [0; 64],
        num: 0,
    };
    MD5_Init(&mut ctx);
    MD5_Update(&mut ctx, data as *const libc::c_void, len);
    MD5_Final(out, &mut ctx);
    return out;
}
#[no_mangle]
pub unsafe extern "C" fn MD5_Init(mut md5: *mut MD5_CTX) -> libc::c_int {
    OPENSSL_memset(
        md5 as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<MD5_CTX>() as libc::c_ulong,
    );
    (*md5).h[0 as libc::c_int as usize] = 0x67452301 as libc::c_ulong as uint32_t;
    (*md5).h[1 as libc::c_int as usize] = 0xefcdab89 as libc::c_ulong as uint32_t;
    (*md5).h[2 as libc::c_int as usize] = 0x98badcfe as libc::c_ulong as uint32_t;
    (*md5).h[3 as libc::c_int as usize] = 0x10325476 as libc::c_ulong as uint32_t;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn MD5_Init_from_state(
    mut md5: *mut MD5_CTX,
    mut h: *const uint8_t,
    mut n: uint64_t,
) -> libc::c_int {
    if n % (64 as libc::c_int as uint64_t * 8 as libc::c_int as uint64_t)
        != 0 as libc::c_int as uint64_t
    {
        return 0 as libc::c_int;
    }
    OPENSSL_memset(
        md5 as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<MD5_CTX>() as libc::c_ulong,
    );
    let out_words: size_t = (16 as libc::c_int / 4 as libc::c_int) as size_t;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < out_words {
        (*md5).h[i as usize] = CRYPTO_load_u32_be(h as *const libc::c_void);
        h = h.offset(4 as libc::c_int as isize);
        i = i.wrapping_add(1);
        i;
    }
    (*md5).Nh = (n >> 32 as libc::c_int) as uint32_t;
    (*md5).Nl = (n & 0xffffffff as libc::c_uint as uint64_t) as uint32_t;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn MD5_Transform(mut c: *mut MD5_CTX, mut data: *const uint8_t) {
    md5_block_data_order(((*c).h).as_mut_ptr(), data, 1 as libc::c_int as size_t);
}
#[no_mangle]
pub unsafe extern "C" fn MD5_Update(
    mut c: *mut MD5_CTX,
    mut data: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    crypto_md32_update(
        Some(
            md5_block_data_order
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
pub unsafe extern "C" fn MD5_Final(
    mut out: *mut uint8_t,
    mut c: *mut MD5_CTX,
) -> libc::c_int {
    crypto_md32_final(
        Some(
            md5_block_data_order
                as unsafe extern "C" fn(*mut uint32_t, *const uint8_t, size_t) -> (),
        ),
        ((*c).h).as_mut_ptr(),
        ((*c).data).as_mut_ptr(),
        64 as libc::c_int as size_t,
        &mut (*c).num,
        (*c).Nh,
        (*c).Nl,
        0 as libc::c_int,
    );
    CRYPTO_store_u32_le(out as *mut libc::c_void, (*c).h[0 as libc::c_int as usize]);
    CRYPTO_store_u32_le(
        out.offset(4 as libc::c_int as isize) as *mut libc::c_void,
        (*c).h[1 as libc::c_int as usize],
    );
    CRYPTO_store_u32_le(
        out.offset(8 as libc::c_int as isize) as *mut libc::c_void,
        (*c).h[2 as libc::c_int as usize],
    );
    CRYPTO_store_u32_le(
        out.offset(12 as libc::c_int as isize) as *mut libc::c_void,
        (*c).h[3 as libc::c_int as usize],
    );
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn MD5_get_state(
    mut ctx: *mut MD5_CTX,
    mut out_h: *mut uint8_t,
    mut out_n: *mut uint64_t,
) -> libc::c_int {
    if (*ctx).Nl as uint64_t
        % (64 as libc::c_int as uint64_t * 8 as libc::c_int as uint64_t)
        != 0 as libc::c_int as uint64_t
    {
        return 0 as libc::c_int;
    }
    let out_words: size_t = (16 as libc::c_int / 4 as libc::c_int) as size_t;
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
unsafe extern "C" fn md5_block_data_order(
    mut state: *mut uint32_t,
    mut data: *const uint8_t,
    mut num: size_t,
) {
    let mut A: uint32_t = 0;
    let mut B: uint32_t = 0;
    let mut C: uint32_t = 0;
    let mut D: uint32_t = 0;
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
    loop {
        let fresh0 = num;
        num = num.wrapping_sub(1);
        if !(fresh0 != 0) {
            break;
        }
        XX0 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        XX1 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        A = (A as libc::c_long
            + (XX0 as libc::c_long + 0xd76aa478 as libc::c_long
                + ((C ^ D) & B ^ D) as libc::c_long)) as uint32_t;
        A = CRYPTO_rotl_u32(A, 7 as libc::c_int);
        A = A.wrapping_add(B);
        XX2 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        D = (D as libc::c_long
            + (XX1 as libc::c_long + 0xe8c7b756 as libc::c_long
                + ((B ^ C) & A ^ C) as libc::c_long)) as uint32_t;
        D = CRYPTO_rotl_u32(D, 12 as libc::c_int);
        D = D.wrapping_add(A);
        XX3 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        C = (C as libc::c_long
            + (XX2 as libc::c_long + 0x242070db as libc::c_long
                + ((A ^ B) & D ^ B) as libc::c_long)) as uint32_t;
        C = CRYPTO_rotl_u32(C, 17 as libc::c_int);
        C = C.wrapping_add(D);
        XX4 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        B = (B as libc::c_long
            + (XX3 as libc::c_long + 0xc1bdceee as libc::c_long
                + ((D ^ A) & C ^ A) as libc::c_long)) as uint32_t;
        B = CRYPTO_rotl_u32(B, 22 as libc::c_int);
        B = B.wrapping_add(C);
        XX5 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        A = (A as libc::c_long
            + (XX4 as libc::c_long + 0xf57c0faf as libc::c_long
                + ((C ^ D) & B ^ D) as libc::c_long)) as uint32_t;
        A = CRYPTO_rotl_u32(A, 7 as libc::c_int);
        A = A.wrapping_add(B);
        XX6 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        D = (D as libc::c_long
            + (XX5 as libc::c_long + 0x4787c62a as libc::c_long
                + ((B ^ C) & A ^ C) as libc::c_long)) as uint32_t;
        D = CRYPTO_rotl_u32(D, 12 as libc::c_int);
        D = D.wrapping_add(A);
        XX7 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        C = (C as libc::c_long
            + (XX6 as libc::c_long + 0xa8304613 as libc::c_long
                + ((A ^ B) & D ^ B) as libc::c_long)) as uint32_t;
        C = CRYPTO_rotl_u32(C, 17 as libc::c_int);
        C = C.wrapping_add(D);
        XX8 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        B = (B as libc::c_long
            + (XX7 as libc::c_long + 0xfd469501 as libc::c_long
                + ((D ^ A) & C ^ A) as libc::c_long)) as uint32_t;
        B = CRYPTO_rotl_u32(B, 22 as libc::c_int);
        B = B.wrapping_add(C);
        XX9 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        A = (A as libc::c_long
            + (XX8 as libc::c_long + 0x698098d8 as libc::c_long
                + ((C ^ D) & B ^ D) as libc::c_long)) as uint32_t;
        A = CRYPTO_rotl_u32(A, 7 as libc::c_int);
        A = A.wrapping_add(B);
        XX10 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        D = (D as libc::c_long
            + (XX9 as libc::c_long + 0x8b44f7af as libc::c_long
                + ((B ^ C) & A ^ C) as libc::c_long)) as uint32_t;
        D = CRYPTO_rotl_u32(D, 12 as libc::c_int);
        D = D.wrapping_add(A);
        XX11 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        C = (C as libc::c_long
            + (XX10 as libc::c_long + 0xffff5bb1 as libc::c_long
                + ((A ^ B) & D ^ B) as libc::c_long)) as uint32_t;
        C = CRYPTO_rotl_u32(C, 17 as libc::c_int);
        C = C.wrapping_add(D);
        XX12 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        B = (B as libc::c_long
            + (XX11 as libc::c_long + 0x895cd7be as libc::c_long
                + ((D ^ A) & C ^ A) as libc::c_long)) as uint32_t;
        B = CRYPTO_rotl_u32(B, 22 as libc::c_int);
        B = B.wrapping_add(C);
        XX13 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        A = (A as libc::c_long
            + (XX12 as libc::c_long + 0x6b901122 as libc::c_long
                + ((C ^ D) & B ^ D) as libc::c_long)) as uint32_t;
        A = CRYPTO_rotl_u32(A, 7 as libc::c_int);
        A = A.wrapping_add(B);
        XX14 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        D = (D as libc::c_long
            + (XX13 as libc::c_long + 0xfd987193 as libc::c_long
                + ((B ^ C) & A ^ C) as libc::c_long)) as uint32_t;
        D = CRYPTO_rotl_u32(D, 12 as libc::c_int);
        D = D.wrapping_add(A);
        XX15 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        C = (C as libc::c_long
            + (XX14 as libc::c_long + 0xa679438e as libc::c_long
                + ((A ^ B) & D ^ B) as libc::c_long)) as uint32_t;
        C = CRYPTO_rotl_u32(C, 17 as libc::c_int);
        C = C.wrapping_add(D);
        B = (B as libc::c_long
            + (XX15 as libc::c_long + 0x49b40821 as libc::c_long
                + ((D ^ A) & C ^ A) as libc::c_long)) as uint32_t;
        B = CRYPTO_rotl_u32(B, 22 as libc::c_int);
        B = B.wrapping_add(C);
        A = (A as libc::c_long
            + (XX1 as libc::c_long + 0xf61e2562 as libc::c_long
                + ((B ^ C) & D ^ C) as libc::c_long)) as uint32_t;
        A = CRYPTO_rotl_u32(A, 5 as libc::c_int);
        A = A.wrapping_add(B);
        D = (D as libc::c_long
            + (XX6 as libc::c_long + 0xc040b340 as libc::c_long
                + ((A ^ B) & C ^ B) as libc::c_long)) as uint32_t;
        D = CRYPTO_rotl_u32(D, 9 as libc::c_int);
        D = D.wrapping_add(A);
        C = (C as libc::c_long
            + (XX11 as libc::c_long + 0x265e5a51 as libc::c_long
                + ((D ^ A) & B ^ A) as libc::c_long)) as uint32_t;
        C = CRYPTO_rotl_u32(C, 14 as libc::c_int);
        C = C.wrapping_add(D);
        B = (B as libc::c_long
            + (XX0 as libc::c_long + 0xe9b6c7aa as libc::c_long
                + ((C ^ D) & A ^ D) as libc::c_long)) as uint32_t;
        B = CRYPTO_rotl_u32(B, 20 as libc::c_int);
        B = B.wrapping_add(C);
        A = (A as libc::c_long
            + (XX5 as libc::c_long + 0xd62f105d as libc::c_long
                + ((B ^ C) & D ^ C) as libc::c_long)) as uint32_t;
        A = CRYPTO_rotl_u32(A, 5 as libc::c_int);
        A = A.wrapping_add(B);
        D = (D as libc::c_long
            + (XX10 as libc::c_long + 0x2441453 as libc::c_long
                + ((A ^ B) & C ^ B) as libc::c_long)) as uint32_t;
        D = CRYPTO_rotl_u32(D, 9 as libc::c_int);
        D = D.wrapping_add(A);
        C = (C as libc::c_long
            + (XX15 as libc::c_long + 0xd8a1e681 as libc::c_long
                + ((D ^ A) & B ^ A) as libc::c_long)) as uint32_t;
        C = CRYPTO_rotl_u32(C, 14 as libc::c_int);
        C = C.wrapping_add(D);
        B = (B as libc::c_long
            + (XX4 as libc::c_long + 0xe7d3fbc8 as libc::c_long
                + ((C ^ D) & A ^ D) as libc::c_long)) as uint32_t;
        B = CRYPTO_rotl_u32(B, 20 as libc::c_int);
        B = B.wrapping_add(C);
        A = (A as libc::c_long
            + (XX9 as libc::c_long + 0x21e1cde6 as libc::c_long
                + ((B ^ C) & D ^ C) as libc::c_long)) as uint32_t;
        A = CRYPTO_rotl_u32(A, 5 as libc::c_int);
        A = A.wrapping_add(B);
        D = (D as libc::c_long
            + (XX14 as libc::c_long + 0xc33707d6 as libc::c_long
                + ((A ^ B) & C ^ B) as libc::c_long)) as uint32_t;
        D = CRYPTO_rotl_u32(D, 9 as libc::c_int);
        D = D.wrapping_add(A);
        C = (C as libc::c_long
            + (XX3 as libc::c_long + 0xf4d50d87 as libc::c_long
                + ((D ^ A) & B ^ A) as libc::c_long)) as uint32_t;
        C = CRYPTO_rotl_u32(C, 14 as libc::c_int);
        C = C.wrapping_add(D);
        B = (B as libc::c_long
            + (XX8 as libc::c_long + 0x455a14ed as libc::c_long
                + ((C ^ D) & A ^ D) as libc::c_long)) as uint32_t;
        B = CRYPTO_rotl_u32(B, 20 as libc::c_int);
        B = B.wrapping_add(C);
        A = (A as libc::c_long
            + (XX13 as libc::c_long + 0xa9e3e905 as libc::c_long
                + ((B ^ C) & D ^ C) as libc::c_long)) as uint32_t;
        A = CRYPTO_rotl_u32(A, 5 as libc::c_int);
        A = A.wrapping_add(B);
        D = (D as libc::c_long
            + (XX2 as libc::c_long + 0xfcefa3f8 as libc::c_long
                + ((A ^ B) & C ^ B) as libc::c_long)) as uint32_t;
        D = CRYPTO_rotl_u32(D, 9 as libc::c_int);
        D = D.wrapping_add(A);
        C = (C as libc::c_long
            + (XX7 as libc::c_long + 0x676f02d9 as libc::c_long
                + ((D ^ A) & B ^ A) as libc::c_long)) as uint32_t;
        C = CRYPTO_rotl_u32(C, 14 as libc::c_int);
        C = C.wrapping_add(D);
        B = (B as libc::c_long
            + (XX12 as libc::c_long + 0x8d2a4c8a as libc::c_long
                + ((C ^ D) & A ^ D) as libc::c_long)) as uint32_t;
        B = CRYPTO_rotl_u32(B, 20 as libc::c_int);
        B = B.wrapping_add(C);
        A = (A as libc::c_long
            + (XX5 as libc::c_long + 0xfffa3942 as libc::c_long
                + (B ^ C ^ D) as libc::c_long)) as uint32_t;
        A = CRYPTO_rotl_u32(A, 4 as libc::c_int);
        A = A.wrapping_add(B);
        D = (D as libc::c_long
            + (XX8 as libc::c_long + 0x8771f681 as libc::c_long
                + (A ^ B ^ C) as libc::c_long)) as uint32_t;
        D = CRYPTO_rotl_u32(D, 11 as libc::c_int);
        D = D.wrapping_add(A);
        C = (C as libc::c_long
            + (XX11 as libc::c_long + 0x6d9d6122 as libc::c_long
                + (D ^ A ^ B) as libc::c_long)) as uint32_t;
        C = CRYPTO_rotl_u32(C, 16 as libc::c_int);
        C = C.wrapping_add(D);
        B = (B as libc::c_long
            + (XX14 as libc::c_long + 0xfde5380c as libc::c_long
                + (C ^ D ^ A) as libc::c_long)) as uint32_t;
        B = CRYPTO_rotl_u32(B, 23 as libc::c_int);
        B = B.wrapping_add(C);
        A = (A as libc::c_long
            + (XX1 as libc::c_long + 0xa4beea44 as libc::c_long
                + (B ^ C ^ D) as libc::c_long)) as uint32_t;
        A = CRYPTO_rotl_u32(A, 4 as libc::c_int);
        A = A.wrapping_add(B);
        D = (D as libc::c_long
            + (XX4 as libc::c_long + 0x4bdecfa9 as libc::c_long
                + (A ^ B ^ C) as libc::c_long)) as uint32_t;
        D = CRYPTO_rotl_u32(D, 11 as libc::c_int);
        D = D.wrapping_add(A);
        C = (C as libc::c_long
            + (XX7 as libc::c_long + 0xf6bb4b60 as libc::c_long
                + (D ^ A ^ B) as libc::c_long)) as uint32_t;
        C = CRYPTO_rotl_u32(C, 16 as libc::c_int);
        C = C.wrapping_add(D);
        B = (B as libc::c_long
            + (XX10 as libc::c_long + 0xbebfbc70 as libc::c_long
                + (C ^ D ^ A) as libc::c_long)) as uint32_t;
        B = CRYPTO_rotl_u32(B, 23 as libc::c_int);
        B = B.wrapping_add(C);
        A = (A as libc::c_long
            + (XX13 as libc::c_long + 0x289b7ec6 as libc::c_long
                + (B ^ C ^ D) as libc::c_long)) as uint32_t;
        A = CRYPTO_rotl_u32(A, 4 as libc::c_int);
        A = A.wrapping_add(B);
        D = (D as libc::c_long
            + (XX0 as libc::c_long + 0xeaa127fa as libc::c_long
                + (A ^ B ^ C) as libc::c_long)) as uint32_t;
        D = CRYPTO_rotl_u32(D, 11 as libc::c_int);
        D = D.wrapping_add(A);
        C = (C as libc::c_long
            + (XX3 as libc::c_long + 0xd4ef3085 as libc::c_long
                + (D ^ A ^ B) as libc::c_long)) as uint32_t;
        C = CRYPTO_rotl_u32(C, 16 as libc::c_int);
        C = C.wrapping_add(D);
        B = (B as libc::c_long
            + (XX6 as libc::c_long + 0x4881d05 as libc::c_long
                + (C ^ D ^ A) as libc::c_long)) as uint32_t;
        B = CRYPTO_rotl_u32(B, 23 as libc::c_int);
        B = B.wrapping_add(C);
        A = (A as libc::c_long
            + (XX9 as libc::c_long + 0xd9d4d039 as libc::c_long
                + (B ^ C ^ D) as libc::c_long)) as uint32_t;
        A = CRYPTO_rotl_u32(A, 4 as libc::c_int);
        A = A.wrapping_add(B);
        D = (D as libc::c_long
            + (XX12 as libc::c_long + 0xe6db99e5 as libc::c_long
                + (A ^ B ^ C) as libc::c_long)) as uint32_t;
        D = CRYPTO_rotl_u32(D, 11 as libc::c_int);
        D = D.wrapping_add(A);
        C = (C as libc::c_long
            + (XX15 as libc::c_long + 0x1fa27cf8 as libc::c_long
                + (D ^ A ^ B) as libc::c_long)) as uint32_t;
        C = CRYPTO_rotl_u32(C, 16 as libc::c_int);
        C = C.wrapping_add(D);
        B = (B as libc::c_long
            + (XX2 as libc::c_long + 0xc4ac5665 as libc::c_long
                + (C ^ D ^ A) as libc::c_long)) as uint32_t;
        B = CRYPTO_rotl_u32(B, 23 as libc::c_int);
        B = B.wrapping_add(C);
        A = (A as libc::c_long
            + (XX0 as libc::c_long + 0xf4292244 as libc::c_long
                + ((!D | B) ^ C) as libc::c_long)) as uint32_t;
        A = CRYPTO_rotl_u32(A, 6 as libc::c_int);
        A = A.wrapping_add(B);
        D = (D as libc::c_long
            + (XX7 as libc::c_long + 0x432aff97 as libc::c_long
                + ((!C | A) ^ B) as libc::c_long)) as uint32_t;
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        D = D.wrapping_add(A);
        C = (C as libc::c_long
            + (XX14 as libc::c_long + 0xab9423a7 as libc::c_long
                + ((!B | D) ^ A) as libc::c_long)) as uint32_t;
        C = CRYPTO_rotl_u32(C, 15 as libc::c_int);
        C = C.wrapping_add(D);
        B = (B as libc::c_long
            + (XX5 as libc::c_long + 0xfc93a039 as libc::c_long
                + ((!A | C) ^ D) as libc::c_long)) as uint32_t;
        B = CRYPTO_rotl_u32(B, 21 as libc::c_int);
        B = B.wrapping_add(C);
        A = (A as libc::c_long
            + (XX12 as libc::c_long + 0x655b59c3 as libc::c_long
                + ((!D | B) ^ C) as libc::c_long)) as uint32_t;
        A = CRYPTO_rotl_u32(A, 6 as libc::c_int);
        A = A.wrapping_add(B);
        D = (D as libc::c_long
            + (XX3 as libc::c_long + 0x8f0ccc92 as libc::c_long
                + ((!C | A) ^ B) as libc::c_long)) as uint32_t;
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        D = D.wrapping_add(A);
        C = (C as libc::c_long
            + (XX10 as libc::c_long + 0xffeff47d as libc::c_long
                + ((!B | D) ^ A) as libc::c_long)) as uint32_t;
        C = CRYPTO_rotl_u32(C, 15 as libc::c_int);
        C = C.wrapping_add(D);
        B = (B as libc::c_long
            + (XX1 as libc::c_long + 0x85845dd1 as libc::c_long
                + ((!A | C) ^ D) as libc::c_long)) as uint32_t;
        B = CRYPTO_rotl_u32(B, 21 as libc::c_int);
        B = B.wrapping_add(C);
        A = (A as libc::c_long
            + (XX8 as libc::c_long + 0x6fa87e4f as libc::c_long
                + ((!D | B) ^ C) as libc::c_long)) as uint32_t;
        A = CRYPTO_rotl_u32(A, 6 as libc::c_int);
        A = A.wrapping_add(B);
        D = (D as libc::c_long
            + (XX15 as libc::c_long + 0xfe2ce6e0 as libc::c_long
                + ((!C | A) ^ B) as libc::c_long)) as uint32_t;
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        D = D.wrapping_add(A);
        C = (C as libc::c_long
            + (XX6 as libc::c_long + 0xa3014314 as libc::c_long
                + ((!B | D) ^ A) as libc::c_long)) as uint32_t;
        C = CRYPTO_rotl_u32(C, 15 as libc::c_int);
        C = C.wrapping_add(D);
        B = (B as libc::c_long
            + (XX13 as libc::c_long + 0x4e0811a1 as libc::c_long
                + ((!A | C) ^ D) as libc::c_long)) as uint32_t;
        B = CRYPTO_rotl_u32(B, 21 as libc::c_int);
        B = B.wrapping_add(C);
        A = (A as libc::c_long
            + (XX4 as libc::c_long + 0xf7537e82 as libc::c_long
                + ((!D | B) ^ C) as libc::c_long)) as uint32_t;
        A = CRYPTO_rotl_u32(A, 6 as libc::c_int);
        A = A.wrapping_add(B);
        D = (D as libc::c_long
            + (XX11 as libc::c_long + 0xbd3af235 as libc::c_long
                + ((!C | A) ^ B) as libc::c_long)) as uint32_t;
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        D = D.wrapping_add(A);
        C = (C as libc::c_long
            + (XX2 as libc::c_long + 0x2ad7d2bb as libc::c_long
                + ((!B | D) ^ A) as libc::c_long)) as uint32_t;
        C = CRYPTO_rotl_u32(C, 15 as libc::c_int);
        C = C.wrapping_add(D);
        B = (B as libc::c_long
            + (XX9 as libc::c_long + 0xeb86d391 as libc::c_long
                + ((!A | C) ^ D) as libc::c_long)) as uint32_t;
        B = CRYPTO_rotl_u32(B, 21 as libc::c_int);
        B = B.wrapping_add(C);
        let ref mut fresh1 = *state.offset(0 as libc::c_int as isize);
        *fresh1 = (*fresh1).wrapping_add(A);
        A = *fresh1;
        let ref mut fresh2 = *state.offset(1 as libc::c_int as isize);
        *fresh2 = (*fresh2).wrapping_add(B);
        B = *fresh2;
        let ref mut fresh3 = *state.offset(2 as libc::c_int as isize);
        *fresh3 = (*fresh3).wrapping_add(C);
        C = *fresh3;
        let ref mut fresh4 = *state.offset(3 as libc::c_int as isize);
        *fresh4 = (*fresh4).wrapping_add(D);
        D = *fresh4;
    };
}
