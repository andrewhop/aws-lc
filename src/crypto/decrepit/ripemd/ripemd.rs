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
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct RIPEMD160state_st {
    pub h: [uint32_t; 5],
    pub Nl: uint32_t,
    pub Nh: uint32_t,
    pub data: [uint8_t; 64],
    pub num: libc::c_uint,
}
pub type RIPEMD160_CTX = RIPEMD160state_st;
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
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/ripemd/../../fipsmodule/digest/md32_common.h\0"
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
    'c_10055: {
        if n < block_size {} else {
            __assert_fail(
                b"n < block_size\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/ripemd/../../fipsmodule/digest/md32_common.h\0"
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
pub unsafe extern "C" fn RIPEMD160_Init(mut ctx: *mut RIPEMD160_CTX) -> libc::c_int {
    OPENSSL_memset(
        ctx as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<RIPEMD160_CTX>() as libc::c_ulong,
    );
    (*ctx).h[0 as libc::c_int as usize] = 0x67452301 as libc::c_long as uint32_t;
    (*ctx).h[1 as libc::c_int as usize] = 0xefcdab89 as libc::c_long as uint32_t;
    (*ctx).h[2 as libc::c_int as usize] = 0x98badcfe as libc::c_long as uint32_t;
    (*ctx).h[3 as libc::c_int as usize] = 0x10325476 as libc::c_long as uint32_t;
    (*ctx).h[4 as libc::c_int as usize] = 0xc3d2e1f0 as libc::c_long as uint32_t;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RIPEMD160_Update(
    mut c: *mut RIPEMD160_CTX,
    mut data: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    crypto_md32_update(
        Some(
            ripemd160_block_data_order
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
pub unsafe extern "C" fn RIPEMD160_Final(
    mut out: *mut uint8_t,
    mut c: *mut RIPEMD160_CTX,
) -> libc::c_int {
    crypto_md32_final(
        Some(
            ripemd160_block_data_order
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
    CRYPTO_store_u32_le(
        out.offset(16 as libc::c_int as isize) as *mut libc::c_void,
        (*c).h[4 as libc::c_int as usize],
    );
    return 1 as libc::c_int;
}
unsafe extern "C" fn ripemd160_block_data_order(
    mut h: *mut uint32_t,
    mut data: *const uint8_t,
    mut num: size_t,
) {
    let mut A: uint32_t = 0;
    let mut B: uint32_t = 0;
    let mut C: uint32_t = 0;
    let mut D: uint32_t = 0;
    let mut E: uint32_t = 0;
    let mut a: uint32_t = 0;
    let mut b: uint32_t = 0;
    let mut c: uint32_t = 0;
    let mut d: uint32_t = 0;
    let mut e: uint32_t = 0;
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
    loop {
        let fresh0 = num;
        num = num.wrapping_sub(1);
        if !(fresh0 != 0) {
            break;
        }
        A = *h.offset(0 as libc::c_int as isize);
        B = *h.offset(1 as libc::c_int as isize);
        C = *h.offset(2 as libc::c_int as isize);
        D = *h.offset(3 as libc::c_int as isize);
        E = *h.offset(4 as libc::c_int as isize);
        XX0 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        XX1 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        A = A.wrapping_add((B ^ C ^ D).wrapping_add(XX0));
        A = (CRYPTO_rotl_u32(A, 11 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        XX2 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        E = E.wrapping_add((A ^ B ^ C).wrapping_add(XX1));
        E = (CRYPTO_rotl_u32(E, 14 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        XX3 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        D = D.wrapping_add((E ^ A ^ B).wrapping_add(XX2));
        D = (CRYPTO_rotl_u32(D, 15 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        XX4 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        C = C.wrapping_add((D ^ E ^ A).wrapping_add(XX3));
        C = (CRYPTO_rotl_u32(C, 12 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        XX5 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        B = B.wrapping_add((C ^ D ^ E).wrapping_add(XX4));
        B = (CRYPTO_rotl_u32(B, 5 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        XX6 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        A = A.wrapping_add((B ^ C ^ D).wrapping_add(XX5));
        A = (CRYPTO_rotl_u32(A, 8 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        XX7 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        E = E.wrapping_add((A ^ B ^ C).wrapping_add(XX6));
        E = (CRYPTO_rotl_u32(E, 7 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        XX8 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        D = D.wrapping_add((E ^ A ^ B).wrapping_add(XX7));
        D = (CRYPTO_rotl_u32(D, 9 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        XX9 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        C = C.wrapping_add((D ^ E ^ A).wrapping_add(XX8));
        C = (CRYPTO_rotl_u32(C, 11 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        XX10 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        B = B.wrapping_add((C ^ D ^ E).wrapping_add(XX9));
        B = (CRYPTO_rotl_u32(B, 13 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        XX11 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        A = A.wrapping_add((B ^ C ^ D).wrapping_add(XX10));
        A = (CRYPTO_rotl_u32(A, 14 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        XX12 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        E = E.wrapping_add((A ^ B ^ C).wrapping_add(XX11));
        E = (CRYPTO_rotl_u32(E, 15 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        XX13 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        D = D.wrapping_add((E ^ A ^ B).wrapping_add(XX12));
        D = (CRYPTO_rotl_u32(D, 6 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        XX14 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        C = C.wrapping_add((D ^ E ^ A).wrapping_add(XX13));
        C = (CRYPTO_rotl_u32(C, 7 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        XX15 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        B = B.wrapping_add((C ^ D ^ E).wrapping_add(XX14));
        B = (CRYPTO_rotl_u32(B, 9 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = A.wrapping_add((B ^ C ^ D).wrapping_add(XX15));
        A = (CRYPTO_rotl_u32(A, 8 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((B ^ C) & A ^ C).wrapping_add(XX7) as libc::c_long
                + 0x5a827999 as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 7 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((A ^ B) & E ^ B).wrapping_add(XX4) as libc::c_long
                + 0x5a827999 as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 6 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((E ^ A) & D ^ A).wrapping_add(XX13) as libc::c_long
                + 0x5a827999 as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 8 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = (B as libc::c_long
            + (((D ^ E) & C ^ E).wrapping_add(XX1) as libc::c_long
                + 0x5a827999 as libc::c_long)) as uint32_t;
        B = (CRYPTO_rotl_u32(B, 13 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = (A as libc::c_long
            + (((C ^ D) & B ^ D).wrapping_add(XX10) as libc::c_long
                + 0x5a827999 as libc::c_long)) as uint32_t;
        A = (CRYPTO_rotl_u32(A, 11 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((B ^ C) & A ^ C).wrapping_add(XX6) as libc::c_long
                + 0x5a827999 as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 9 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((A ^ B) & E ^ B).wrapping_add(XX15) as libc::c_long
                + 0x5a827999 as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 7 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((E ^ A) & D ^ A).wrapping_add(XX3) as libc::c_long
                + 0x5a827999 as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 15 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = (B as libc::c_long
            + (((D ^ E) & C ^ E).wrapping_add(XX12) as libc::c_long
                + 0x5a827999 as libc::c_long)) as uint32_t;
        B = (CRYPTO_rotl_u32(B, 7 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = (A as libc::c_long
            + (((C ^ D) & B ^ D).wrapping_add(XX0) as libc::c_long
                + 0x5a827999 as libc::c_long)) as uint32_t;
        A = (CRYPTO_rotl_u32(A, 12 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((B ^ C) & A ^ C).wrapping_add(XX9) as libc::c_long
                + 0x5a827999 as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 15 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((A ^ B) & E ^ B).wrapping_add(XX5) as libc::c_long
                + 0x5a827999 as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 9 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((E ^ A) & D ^ A).wrapping_add(XX2) as libc::c_long
                + 0x5a827999 as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 11 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = (B as libc::c_long
            + (((D ^ E) & C ^ E).wrapping_add(XX14) as libc::c_long
                + 0x5a827999 as libc::c_long)) as uint32_t;
        B = (CRYPTO_rotl_u32(B, 7 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = (A as libc::c_long
            + (((C ^ D) & B ^ D).wrapping_add(XX11) as libc::c_long
                + 0x5a827999 as libc::c_long)) as uint32_t;
        A = (CRYPTO_rotl_u32(A, 13 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((B ^ C) & A ^ C).wrapping_add(XX8) as libc::c_long
                + 0x5a827999 as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 12 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((!A | E) ^ B).wrapping_add(XX3) as libc::c_long
                + 0x6ed9eba1 as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 11 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((!E | D) ^ A).wrapping_add(XX10) as libc::c_long
                + 0x6ed9eba1 as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 13 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = (B as libc::c_long
            + (((!D | C) ^ E).wrapping_add(XX14) as libc::c_long
                + 0x6ed9eba1 as libc::c_long)) as uint32_t;
        B = (CRYPTO_rotl_u32(B, 6 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = (A as libc::c_long
            + (((!C | B) ^ D).wrapping_add(XX4) as libc::c_long
                + 0x6ed9eba1 as libc::c_long)) as uint32_t;
        A = (CRYPTO_rotl_u32(A, 7 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((!B | A) ^ C).wrapping_add(XX9) as libc::c_long
                + 0x6ed9eba1 as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 14 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((!A | E) ^ B).wrapping_add(XX15) as libc::c_long
                + 0x6ed9eba1 as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 9 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((!E | D) ^ A).wrapping_add(XX8) as libc::c_long
                + 0x6ed9eba1 as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 13 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = (B as libc::c_long
            + (((!D | C) ^ E).wrapping_add(XX1) as libc::c_long
                + 0x6ed9eba1 as libc::c_long)) as uint32_t;
        B = (CRYPTO_rotl_u32(B, 15 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = (A as libc::c_long
            + (((!C | B) ^ D).wrapping_add(XX2) as libc::c_long
                + 0x6ed9eba1 as libc::c_long)) as uint32_t;
        A = (CRYPTO_rotl_u32(A, 14 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((!B | A) ^ C).wrapping_add(XX7) as libc::c_long
                + 0x6ed9eba1 as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 8 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((!A | E) ^ B).wrapping_add(XX0) as libc::c_long
                + 0x6ed9eba1 as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 13 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((!E | D) ^ A).wrapping_add(XX6) as libc::c_long
                + 0x6ed9eba1 as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 6 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = (B as libc::c_long
            + (((!D | C) ^ E).wrapping_add(XX13) as libc::c_long
                + 0x6ed9eba1 as libc::c_long)) as uint32_t;
        B = (CRYPTO_rotl_u32(B, 5 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = (A as libc::c_long
            + (((!C | B) ^ D).wrapping_add(XX11) as libc::c_long
                + 0x6ed9eba1 as libc::c_long)) as uint32_t;
        A = (CRYPTO_rotl_u32(A, 12 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((!B | A) ^ C).wrapping_add(XX5) as libc::c_long
                + 0x6ed9eba1 as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 7 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((!A | E) ^ B).wrapping_add(XX12) as libc::c_long
                + 0x6ed9eba1 as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 5 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((D ^ E) & A ^ E).wrapping_add(XX1) as libc::c_long
                + 0x8f1bbcdc as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 11 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = (B as libc::c_long
            + (((C ^ D) & E ^ D).wrapping_add(XX9) as libc::c_long
                + 0x8f1bbcdc as libc::c_long)) as uint32_t;
        B = (CRYPTO_rotl_u32(B, 12 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = (A as libc::c_long
            + (((B ^ C) & D ^ C).wrapping_add(XX11) as libc::c_long
                + 0x8f1bbcdc as libc::c_long)) as uint32_t;
        A = (CRYPTO_rotl_u32(A, 14 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((A ^ B) & C ^ B).wrapping_add(XX10) as libc::c_long
                + 0x8f1bbcdc as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 15 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((E ^ A) & B ^ A).wrapping_add(XX0) as libc::c_long
                + 0x8f1bbcdc as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 14 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((D ^ E) & A ^ E).wrapping_add(XX8) as libc::c_long
                + 0x8f1bbcdc as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 15 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = (B as libc::c_long
            + (((C ^ D) & E ^ D).wrapping_add(XX12) as libc::c_long
                + 0x8f1bbcdc as libc::c_long)) as uint32_t;
        B = (CRYPTO_rotl_u32(B, 9 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = (A as libc::c_long
            + (((B ^ C) & D ^ C).wrapping_add(XX4) as libc::c_long
                + 0x8f1bbcdc as libc::c_long)) as uint32_t;
        A = (CRYPTO_rotl_u32(A, 8 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((A ^ B) & C ^ B).wrapping_add(XX13) as libc::c_long
                + 0x8f1bbcdc as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 9 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((E ^ A) & B ^ A).wrapping_add(XX3) as libc::c_long
                + 0x8f1bbcdc as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 14 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((D ^ E) & A ^ E).wrapping_add(XX7) as libc::c_long
                + 0x8f1bbcdc as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 5 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = (B as libc::c_long
            + (((C ^ D) & E ^ D).wrapping_add(XX15) as libc::c_long
                + 0x8f1bbcdc as libc::c_long)) as uint32_t;
        B = (CRYPTO_rotl_u32(B, 6 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = (A as libc::c_long
            + (((B ^ C) & D ^ C).wrapping_add(XX14) as libc::c_long
                + 0x8f1bbcdc as libc::c_long)) as uint32_t;
        A = (CRYPTO_rotl_u32(A, 8 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((A ^ B) & C ^ B).wrapping_add(XX5) as libc::c_long
                + 0x8f1bbcdc as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 6 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((E ^ A) & B ^ A).wrapping_add(XX6) as libc::c_long
                + 0x8f1bbcdc as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 5 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((D ^ E) & A ^ E).wrapping_add(XX2) as libc::c_long
                + 0x8f1bbcdc as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 12 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = (B as libc::c_long
            + (((!E | D) ^ C).wrapping_add(XX4) as libc::c_long
                + 0xa953fd4e as libc::c_long)) as uint32_t;
        B = (CRYPTO_rotl_u32(B, 9 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = (A as libc::c_long
            + (((!D | C) ^ B).wrapping_add(XX0) as libc::c_long
                + 0xa953fd4e as libc::c_long)) as uint32_t;
        A = (CRYPTO_rotl_u32(A, 15 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((!C | B) ^ A).wrapping_add(XX5) as libc::c_long
                + 0xa953fd4e as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 5 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((!B | A) ^ E).wrapping_add(XX9) as libc::c_long
                + 0xa953fd4e as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 11 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((!A | E) ^ D).wrapping_add(XX7) as libc::c_long
                + 0xa953fd4e as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 6 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = (B as libc::c_long
            + (((!E | D) ^ C).wrapping_add(XX12) as libc::c_long
                + 0xa953fd4e as libc::c_long)) as uint32_t;
        B = (CRYPTO_rotl_u32(B, 8 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = (A as libc::c_long
            + (((!D | C) ^ B).wrapping_add(XX2) as libc::c_long
                + 0xa953fd4e as libc::c_long)) as uint32_t;
        A = (CRYPTO_rotl_u32(A, 13 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((!C | B) ^ A).wrapping_add(XX10) as libc::c_long
                + 0xa953fd4e as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 12 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((!B | A) ^ E).wrapping_add(XX14) as libc::c_long
                + 0xa953fd4e as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 5 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((!A | E) ^ D).wrapping_add(XX1) as libc::c_long
                + 0xa953fd4e as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 12 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = (B as libc::c_long
            + (((!E | D) ^ C).wrapping_add(XX3) as libc::c_long
                + 0xa953fd4e as libc::c_long)) as uint32_t;
        B = (CRYPTO_rotl_u32(B, 13 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = (A as libc::c_long
            + (((!D | C) ^ B).wrapping_add(XX8) as libc::c_long
                + 0xa953fd4e as libc::c_long)) as uint32_t;
        A = (CRYPTO_rotl_u32(A, 14 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((!C | B) ^ A).wrapping_add(XX11) as libc::c_long
                + 0xa953fd4e as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 11 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((!B | A) ^ E).wrapping_add(XX6) as libc::c_long
                + 0xa953fd4e as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 8 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((!A | E) ^ D).wrapping_add(XX15) as libc::c_long
                + 0xa953fd4e as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 5 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = (B as libc::c_long
            + (((!E | D) ^ C).wrapping_add(XX13) as libc::c_long
                + 0xa953fd4e as libc::c_long)) as uint32_t;
        B = (CRYPTO_rotl_u32(B, 6 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        a = A;
        b = B;
        c = C;
        d = D;
        e = E;
        A = *h.offset(0 as libc::c_int as isize);
        B = *h.offset(1 as libc::c_int as isize);
        C = *h.offset(2 as libc::c_int as isize);
        D = *h.offset(3 as libc::c_int as isize);
        E = *h.offset(4 as libc::c_int as isize);
        A = (A as libc::c_long
            + (((!D | C) ^ B).wrapping_add(XX5) as libc::c_long
                + 0x50a28be6 as libc::c_long)) as uint32_t;
        A = (CRYPTO_rotl_u32(A, 8 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((!C | B) ^ A).wrapping_add(XX14) as libc::c_long
                + 0x50a28be6 as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 9 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((!B | A) ^ E).wrapping_add(XX7) as libc::c_long
                + 0x50a28be6 as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 9 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((!A | E) ^ D).wrapping_add(XX0) as libc::c_long
                + 0x50a28be6 as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 11 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = (B as libc::c_long
            + (((!E | D) ^ C).wrapping_add(XX9) as libc::c_long
                + 0x50a28be6 as libc::c_long)) as uint32_t;
        B = (CRYPTO_rotl_u32(B, 13 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = (A as libc::c_long
            + (((!D | C) ^ B).wrapping_add(XX2) as libc::c_long
                + 0x50a28be6 as libc::c_long)) as uint32_t;
        A = (CRYPTO_rotl_u32(A, 15 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((!C | B) ^ A).wrapping_add(XX11) as libc::c_long
                + 0x50a28be6 as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 15 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((!B | A) ^ E).wrapping_add(XX4) as libc::c_long
                + 0x50a28be6 as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 5 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((!A | E) ^ D).wrapping_add(XX13) as libc::c_long
                + 0x50a28be6 as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 7 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = (B as libc::c_long
            + (((!E | D) ^ C).wrapping_add(XX6) as libc::c_long
                + 0x50a28be6 as libc::c_long)) as uint32_t;
        B = (CRYPTO_rotl_u32(B, 7 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = (A as libc::c_long
            + (((!D | C) ^ B).wrapping_add(XX15) as libc::c_long
                + 0x50a28be6 as libc::c_long)) as uint32_t;
        A = (CRYPTO_rotl_u32(A, 8 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((!C | B) ^ A).wrapping_add(XX8) as libc::c_long
                + 0x50a28be6 as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 11 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((!B | A) ^ E).wrapping_add(XX1) as libc::c_long
                + 0x50a28be6 as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 14 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((!A | E) ^ D).wrapping_add(XX10) as libc::c_long
                + 0x50a28be6 as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 14 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = (B as libc::c_long
            + (((!E | D) ^ C).wrapping_add(XX3) as libc::c_long
                + 0x50a28be6 as libc::c_long)) as uint32_t;
        B = (CRYPTO_rotl_u32(B, 12 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = (A as libc::c_long
            + (((!D | C) ^ B).wrapping_add(XX12) as libc::c_long
                + 0x50a28be6 as libc::c_long)) as uint32_t;
        A = (CRYPTO_rotl_u32(A, 6 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((A ^ B) & C ^ B).wrapping_add(XX6) as libc::c_long
                + 0x5c4dd124 as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 9 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((E ^ A) & B ^ A).wrapping_add(XX11) as libc::c_long
                + 0x5c4dd124 as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 13 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((D ^ E) & A ^ E).wrapping_add(XX3) as libc::c_long
                + 0x5c4dd124 as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 15 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = (B as libc::c_long
            + (((C ^ D) & E ^ D).wrapping_add(XX7) as libc::c_long
                + 0x5c4dd124 as libc::c_long)) as uint32_t;
        B = (CRYPTO_rotl_u32(B, 7 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = (A as libc::c_long
            + (((B ^ C) & D ^ C).wrapping_add(XX0) as libc::c_long
                + 0x5c4dd124 as libc::c_long)) as uint32_t;
        A = (CRYPTO_rotl_u32(A, 12 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((A ^ B) & C ^ B).wrapping_add(XX13) as libc::c_long
                + 0x5c4dd124 as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 8 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((E ^ A) & B ^ A).wrapping_add(XX5) as libc::c_long
                + 0x5c4dd124 as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 9 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((D ^ E) & A ^ E).wrapping_add(XX10) as libc::c_long
                + 0x5c4dd124 as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 11 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = (B as libc::c_long
            + (((C ^ D) & E ^ D).wrapping_add(XX14) as libc::c_long
                + 0x5c4dd124 as libc::c_long)) as uint32_t;
        B = (CRYPTO_rotl_u32(B, 7 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = (A as libc::c_long
            + (((B ^ C) & D ^ C).wrapping_add(XX15) as libc::c_long
                + 0x5c4dd124 as libc::c_long)) as uint32_t;
        A = (CRYPTO_rotl_u32(A, 7 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((A ^ B) & C ^ B).wrapping_add(XX8) as libc::c_long
                + 0x5c4dd124 as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 12 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((E ^ A) & B ^ A).wrapping_add(XX12) as libc::c_long
                + 0x5c4dd124 as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 7 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((D ^ E) & A ^ E).wrapping_add(XX4) as libc::c_long
                + 0x5c4dd124 as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 6 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = (B as libc::c_long
            + (((C ^ D) & E ^ D).wrapping_add(XX9) as libc::c_long
                + 0x5c4dd124 as libc::c_long)) as uint32_t;
        B = (CRYPTO_rotl_u32(B, 15 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = (A as libc::c_long
            + (((B ^ C) & D ^ C).wrapping_add(XX1) as libc::c_long
                + 0x5c4dd124 as libc::c_long)) as uint32_t;
        A = (CRYPTO_rotl_u32(A, 13 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((A ^ B) & C ^ B).wrapping_add(XX2) as libc::c_long
                + 0x5c4dd124 as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 11 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((!A | E) ^ B).wrapping_add(XX15) as libc::c_long
                + 0x6d703ef3 as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 9 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((!E | D) ^ A).wrapping_add(XX5) as libc::c_long
                + 0x6d703ef3 as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 7 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = (B as libc::c_long
            + (((!D | C) ^ E).wrapping_add(XX1) as libc::c_long
                + 0x6d703ef3 as libc::c_long)) as uint32_t;
        B = (CRYPTO_rotl_u32(B, 15 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = (A as libc::c_long
            + (((!C | B) ^ D).wrapping_add(XX3) as libc::c_long
                + 0x6d703ef3 as libc::c_long)) as uint32_t;
        A = (CRYPTO_rotl_u32(A, 11 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((!B | A) ^ C).wrapping_add(XX7) as libc::c_long
                + 0x6d703ef3 as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 8 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((!A | E) ^ B).wrapping_add(XX14) as libc::c_long
                + 0x6d703ef3 as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 6 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((!E | D) ^ A).wrapping_add(XX6) as libc::c_long
                + 0x6d703ef3 as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 6 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = (B as libc::c_long
            + (((!D | C) ^ E).wrapping_add(XX9) as libc::c_long
                + 0x6d703ef3 as libc::c_long)) as uint32_t;
        B = (CRYPTO_rotl_u32(B, 14 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = (A as libc::c_long
            + (((!C | B) ^ D).wrapping_add(XX11) as libc::c_long
                + 0x6d703ef3 as libc::c_long)) as uint32_t;
        A = (CRYPTO_rotl_u32(A, 12 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((!B | A) ^ C).wrapping_add(XX8) as libc::c_long
                + 0x6d703ef3 as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 13 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((!A | E) ^ B).wrapping_add(XX12) as libc::c_long
                + 0x6d703ef3 as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 5 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((!E | D) ^ A).wrapping_add(XX2) as libc::c_long
                + 0x6d703ef3 as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 14 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = (B as libc::c_long
            + (((!D | C) ^ E).wrapping_add(XX10) as libc::c_long
                + 0x6d703ef3 as libc::c_long)) as uint32_t;
        B = (CRYPTO_rotl_u32(B, 13 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = (A as libc::c_long
            + (((!C | B) ^ D).wrapping_add(XX0) as libc::c_long
                + 0x6d703ef3 as libc::c_long)) as uint32_t;
        A = (CRYPTO_rotl_u32(A, 13 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((!B | A) ^ C).wrapping_add(XX4) as libc::c_long
                + 0x6d703ef3 as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 7 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((!A | E) ^ B).wrapping_add(XX13) as libc::c_long
                + 0x6d703ef3 as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 5 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((E ^ A) & D ^ A).wrapping_add(XX8) as libc::c_long
                + 0x7a6d76e9 as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 15 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = (B as libc::c_long
            + (((D ^ E) & C ^ E).wrapping_add(XX6) as libc::c_long
                + 0x7a6d76e9 as libc::c_long)) as uint32_t;
        B = (CRYPTO_rotl_u32(B, 5 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = (A as libc::c_long
            + (((C ^ D) & B ^ D).wrapping_add(XX4) as libc::c_long
                + 0x7a6d76e9 as libc::c_long)) as uint32_t;
        A = (CRYPTO_rotl_u32(A, 8 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((B ^ C) & A ^ C).wrapping_add(XX1) as libc::c_long
                + 0x7a6d76e9 as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 11 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((A ^ B) & E ^ B).wrapping_add(XX3) as libc::c_long
                + 0x7a6d76e9 as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 14 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((E ^ A) & D ^ A).wrapping_add(XX11) as libc::c_long
                + 0x7a6d76e9 as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 14 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = (B as libc::c_long
            + (((D ^ E) & C ^ E).wrapping_add(XX15) as libc::c_long
                + 0x7a6d76e9 as libc::c_long)) as uint32_t;
        B = (CRYPTO_rotl_u32(B, 6 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = (A as libc::c_long
            + (((C ^ D) & B ^ D).wrapping_add(XX0) as libc::c_long
                + 0x7a6d76e9 as libc::c_long)) as uint32_t;
        A = (CRYPTO_rotl_u32(A, 14 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((B ^ C) & A ^ C).wrapping_add(XX5) as libc::c_long
                + 0x7a6d76e9 as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 6 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((A ^ B) & E ^ B).wrapping_add(XX12) as libc::c_long
                + 0x7a6d76e9 as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 9 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((E ^ A) & D ^ A).wrapping_add(XX2) as libc::c_long
                + 0x7a6d76e9 as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 12 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = (B as libc::c_long
            + (((D ^ E) & C ^ E).wrapping_add(XX13) as libc::c_long
                + 0x7a6d76e9 as libc::c_long)) as uint32_t;
        B = (CRYPTO_rotl_u32(B, 9 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = (A as libc::c_long
            + (((C ^ D) & B ^ D).wrapping_add(XX9) as libc::c_long
                + 0x7a6d76e9 as libc::c_long)) as uint32_t;
        A = (CRYPTO_rotl_u32(A, 12 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = (E as libc::c_long
            + (((B ^ C) & A ^ C).wrapping_add(XX7) as libc::c_long
                + 0x7a6d76e9 as libc::c_long)) as uint32_t;
        E = (CRYPTO_rotl_u32(E, 5 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = (D as libc::c_long
            + (((A ^ B) & E ^ B).wrapping_add(XX10) as libc::c_long
                + 0x7a6d76e9 as libc::c_long)) as uint32_t;
        D = (CRYPTO_rotl_u32(D, 15 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = (C as libc::c_long
            + (((E ^ A) & D ^ A).wrapping_add(XX14) as libc::c_long
                + 0x7a6d76e9 as libc::c_long)) as uint32_t;
        C = (CRYPTO_rotl_u32(C, 8 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = B.wrapping_add((C ^ D ^ E).wrapping_add(XX12));
        B = (CRYPTO_rotl_u32(B, 8 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = A.wrapping_add((B ^ C ^ D).wrapping_add(XX15));
        A = (CRYPTO_rotl_u32(A, 5 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = E.wrapping_add((A ^ B ^ C).wrapping_add(XX10));
        E = (CRYPTO_rotl_u32(E, 12 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = D.wrapping_add((E ^ A ^ B).wrapping_add(XX4));
        D = (CRYPTO_rotl_u32(D, 9 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = C.wrapping_add((D ^ E ^ A).wrapping_add(XX1));
        C = (CRYPTO_rotl_u32(C, 12 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = B.wrapping_add((C ^ D ^ E).wrapping_add(XX5));
        B = (CRYPTO_rotl_u32(B, 5 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = A.wrapping_add((B ^ C ^ D).wrapping_add(XX8));
        A = (CRYPTO_rotl_u32(A, 14 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = E.wrapping_add((A ^ B ^ C).wrapping_add(XX7));
        E = (CRYPTO_rotl_u32(E, 6 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = D.wrapping_add((E ^ A ^ B).wrapping_add(XX6));
        D = (CRYPTO_rotl_u32(D, 8 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = C.wrapping_add((D ^ E ^ A).wrapping_add(XX2));
        C = (CRYPTO_rotl_u32(C, 13 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = B.wrapping_add((C ^ D ^ E).wrapping_add(XX13));
        B = (CRYPTO_rotl_u32(B, 6 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        A = A.wrapping_add((B ^ C ^ D).wrapping_add(XX14));
        A = (CRYPTO_rotl_u32(A, 5 as libc::c_int)).wrapping_add(E);
        C = CRYPTO_rotl_u32(C, 10 as libc::c_int);
        E = E.wrapping_add((A ^ B ^ C).wrapping_add(XX0));
        E = (CRYPTO_rotl_u32(E, 15 as libc::c_int)).wrapping_add(D);
        B = CRYPTO_rotl_u32(B, 10 as libc::c_int);
        D = D.wrapping_add((E ^ A ^ B).wrapping_add(XX3));
        D = (CRYPTO_rotl_u32(D, 13 as libc::c_int)).wrapping_add(C);
        A = CRYPTO_rotl_u32(A, 10 as libc::c_int);
        C = C.wrapping_add((D ^ E ^ A).wrapping_add(XX9));
        C = (CRYPTO_rotl_u32(C, 11 as libc::c_int)).wrapping_add(B);
        E = CRYPTO_rotl_u32(E, 10 as libc::c_int);
        B = B.wrapping_add((C ^ D ^ E).wrapping_add(XX11));
        B = (CRYPTO_rotl_u32(B, 11 as libc::c_int)).wrapping_add(A);
        D = CRYPTO_rotl_u32(D, 10 as libc::c_int);
        D = (*h.offset(1 as libc::c_int as isize)).wrapping_add(c).wrapping_add(D);
        *h
            .offset(
                1 as libc::c_int as isize,
            ) = (*h.offset(2 as libc::c_int as isize)).wrapping_add(d).wrapping_add(E);
        *h
            .offset(
                2 as libc::c_int as isize,
            ) = (*h.offset(3 as libc::c_int as isize)).wrapping_add(e).wrapping_add(A);
        *h
            .offset(
                3 as libc::c_int as isize,
            ) = (*h.offset(4 as libc::c_int as isize)).wrapping_add(a).wrapping_add(B);
        *h
            .offset(
                4 as libc::c_int as isize,
            ) = (*h.offset(0 as libc::c_int as isize)).wrapping_add(b).wrapping_add(C);
        *h.offset(0 as libc::c_int as isize) = D;
    };
}
#[no_mangle]
pub unsafe extern "C" fn RIPEMD160(
    mut data: *const uint8_t,
    mut len: size_t,
    mut out: *mut uint8_t,
) -> *mut uint8_t {
    let mut ctx: RIPEMD160_CTX = RIPEMD160state_st {
        h: [0; 5],
        Nl: 0,
        Nh: 0,
        data: [0; 64],
        num: 0,
    };
    if RIPEMD160_Init(&mut ctx) == 0 {
        return 0 as *mut uint8_t;
    }
    RIPEMD160_Update(&mut ctx, data as *const libc::c_void, len);
    RIPEMD160_Final(out, &mut ctx);
    return out;
}
