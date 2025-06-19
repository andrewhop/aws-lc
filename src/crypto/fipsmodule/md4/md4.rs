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
pub struct md4_state_st {
    pub h: [uint32_t; 4],
    pub Nl: uint32_t,
    pub Nh: uint32_t,
    pub data: [uint8_t; 64],
    pub num: libc::c_uint,
}
pub type MD4_CTX = md4_state_st;
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
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/md4/../digest/md32_common.h\0"
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
    'c_4766: {
        if n < block_size {} else {
            __assert_fail(
                b"n < block_size\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/md4/../digest/md32_common.h\0"
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
pub unsafe extern "C" fn MD4(
    mut data: *const uint8_t,
    mut len: size_t,
    mut out: *mut uint8_t,
) -> *mut uint8_t {
    let mut ctx: MD4_CTX = md4_state_st {
        h: [0; 4],
        Nl: 0,
        Nh: 0,
        data: [0; 64],
        num: 0,
    };
    MD4_Init(&mut ctx);
    MD4_Update(&mut ctx, data as *const libc::c_void, len);
    MD4_Final(out, &mut ctx);
    return out;
}
#[no_mangle]
pub unsafe extern "C" fn MD4_Init(mut md4: *mut MD4_CTX) -> libc::c_int {
    OPENSSL_memset(
        md4 as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<MD4_CTX>() as libc::c_ulong,
    );
    (*md4).h[0 as libc::c_int as usize] = 0x67452301 as libc::c_ulong as uint32_t;
    (*md4).h[1 as libc::c_int as usize] = 0xefcdab89 as libc::c_ulong as uint32_t;
    (*md4).h[2 as libc::c_int as usize] = 0x98badcfe as libc::c_ulong as uint32_t;
    (*md4).h[3 as libc::c_int as usize] = 0x10325476 as libc::c_ulong as uint32_t;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn MD4_Transform(mut c: *mut MD4_CTX, mut data: *const uint8_t) {
    md4_block_data_order(((*c).h).as_mut_ptr(), data, 1 as libc::c_int as size_t);
}
#[no_mangle]
pub unsafe extern "C" fn MD4_Update(
    mut c: *mut MD4_CTX,
    mut data: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    crypto_md32_update(
        Some(
            md4_block_data_order
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
pub unsafe extern "C" fn MD4_Final(
    mut out: *mut uint8_t,
    mut c: *mut MD4_CTX,
) -> libc::c_int {
    crypto_md32_final(
        Some(
            md4_block_data_order
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
pub unsafe extern "C" fn md4_block_data_order(
    mut state: *mut uint32_t,
    mut data: *const uint8_t,
    mut num: size_t,
) {
    let mut A: uint32_t = 0;
    let mut B: uint32_t = 0;
    let mut C: uint32_t = 0;
    let mut D: uint32_t = 0;
    let mut X0: uint32_t = 0;
    let mut X1: uint32_t = 0;
    let mut X2: uint32_t = 0;
    let mut X3: uint32_t = 0;
    let mut X4: uint32_t = 0;
    let mut X5: uint32_t = 0;
    let mut X6: uint32_t = 0;
    let mut X7: uint32_t = 0;
    let mut X8: uint32_t = 0;
    let mut X9: uint32_t = 0;
    let mut X10: uint32_t = 0;
    let mut X11: uint32_t = 0;
    let mut X12: uint32_t = 0;
    let mut X13: uint32_t = 0;
    let mut X14: uint32_t = 0;
    let mut X15: uint32_t = 0;
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
        X0 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        X1 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        A = A
            .wrapping_add(
                X0
                    .wrapping_add(0 as libc::c_int as uint32_t)
                    .wrapping_add((C ^ D) & B ^ D),
            );
        A = CRYPTO_rotl_u32(A, 3 as libc::c_int);
        X2 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        D = D
            .wrapping_add(
                X1
                    .wrapping_add(0 as libc::c_int as uint32_t)
                    .wrapping_add((B ^ C) & A ^ C),
            );
        D = CRYPTO_rotl_u32(D, 7 as libc::c_int);
        X3 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        C = C
            .wrapping_add(
                X2
                    .wrapping_add(0 as libc::c_int as uint32_t)
                    .wrapping_add((A ^ B) & D ^ B),
            );
        C = CRYPTO_rotl_u32(C, 11 as libc::c_int);
        X4 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        B = B
            .wrapping_add(
                X3
                    .wrapping_add(0 as libc::c_int as uint32_t)
                    .wrapping_add((D ^ A) & C ^ A),
            );
        B = CRYPTO_rotl_u32(B, 19 as libc::c_int);
        X5 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        A = A
            .wrapping_add(
                X4
                    .wrapping_add(0 as libc::c_int as uint32_t)
                    .wrapping_add((C ^ D) & B ^ D),
            );
        A = CRYPTO_rotl_u32(A, 3 as libc::c_int);
        X6 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        D = D
            .wrapping_add(
                X5
                    .wrapping_add(0 as libc::c_int as uint32_t)
                    .wrapping_add((B ^ C) & A ^ C),
            );
        D = CRYPTO_rotl_u32(D, 7 as libc::c_int);
        X7 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        C = C
            .wrapping_add(
                X6
                    .wrapping_add(0 as libc::c_int as uint32_t)
                    .wrapping_add((A ^ B) & D ^ B),
            );
        C = CRYPTO_rotl_u32(C, 11 as libc::c_int);
        X8 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        B = B
            .wrapping_add(
                X7
                    .wrapping_add(0 as libc::c_int as uint32_t)
                    .wrapping_add((D ^ A) & C ^ A),
            );
        B = CRYPTO_rotl_u32(B, 19 as libc::c_int);
        X9 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        A = A
            .wrapping_add(
                X8
                    .wrapping_add(0 as libc::c_int as uint32_t)
                    .wrapping_add((C ^ D) & B ^ D),
            );
        A = CRYPTO_rotl_u32(A, 3 as libc::c_int);
        X10 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        D = D
            .wrapping_add(
                X9
                    .wrapping_add(0 as libc::c_int as uint32_t)
                    .wrapping_add((B ^ C) & A ^ C),
            );
        D = CRYPTO_rotl_u32(D, 7 as libc::c_int);
        X11 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        C = C
            .wrapping_add(
                X10
                    .wrapping_add(0 as libc::c_int as uint32_t)
                    .wrapping_add((A ^ B) & D ^ B),
            );
        C = CRYPTO_rotl_u32(C, 11 as libc::c_int);
        X12 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        B = B
            .wrapping_add(
                X11
                    .wrapping_add(0 as libc::c_int as uint32_t)
                    .wrapping_add((D ^ A) & C ^ A),
            );
        B = CRYPTO_rotl_u32(B, 19 as libc::c_int);
        X13 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        A = A
            .wrapping_add(
                X12
                    .wrapping_add(0 as libc::c_int as uint32_t)
                    .wrapping_add((C ^ D) & B ^ D),
            );
        A = CRYPTO_rotl_u32(A, 3 as libc::c_int);
        X14 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        D = D
            .wrapping_add(
                X13
                    .wrapping_add(0 as libc::c_int as uint32_t)
                    .wrapping_add((B ^ C) & A ^ C),
            );
        D = CRYPTO_rotl_u32(D, 7 as libc::c_int);
        X15 = CRYPTO_load_u32_le(data as *const libc::c_void);
        data = data.offset(4 as libc::c_int as isize);
        C = C
            .wrapping_add(
                X14
                    .wrapping_add(0 as libc::c_int as uint32_t)
                    .wrapping_add((A ^ B) & D ^ B),
            );
        C = CRYPTO_rotl_u32(C, 11 as libc::c_int);
        B = B
            .wrapping_add(
                X15
                    .wrapping_add(0 as libc::c_int as uint32_t)
                    .wrapping_add((D ^ A) & C ^ A),
            );
        B = CRYPTO_rotl_u32(B, 19 as libc::c_int);
        A = (A as libc::c_long
            + (X0 as libc::c_long + 0x5a827999 as libc::c_long
                + (B & C | B & D | C & D) as libc::c_long)) as uint32_t;
        A = CRYPTO_rotl_u32(A, 3 as libc::c_int);
        D = (D as libc::c_long
            + (X4 as libc::c_long + 0x5a827999 as libc::c_long
                + (A & B | A & C | B & C) as libc::c_long)) as uint32_t;
        D = CRYPTO_rotl_u32(D, 5 as libc::c_int);
        C = (C as libc::c_long
            + (X8 as libc::c_long + 0x5a827999 as libc::c_long
                + (D & A | D & B | A & B) as libc::c_long)) as uint32_t;
        C = CRYPTO_rotl_u32(C, 9 as libc::c_int);
        B = (B as libc::c_long
            + (X12 as libc::c_long + 0x5a827999 as libc::c_long
                + (C & D | C & A | D & A) as libc::c_long)) as uint32_t;
        B = CRYPTO_rotl_u32(B, 13 as libc::c_int);
        A = (A as libc::c_long
            + (X1 as libc::c_long + 0x5a827999 as libc::c_long
                + (B & C | B & D | C & D) as libc::c_long)) as uint32_t;
        A = CRYPTO_rotl_u32(A, 3 as libc::c_int);
        D = (D as libc::c_long
            + (X5 as libc::c_long + 0x5a827999 as libc::c_long
                + (A & B | A & C | B & C) as libc::c_long)) as uint32_t;
        D = CRYPTO_rotl_u32(D, 5 as libc::c_int);
        C = (C as libc::c_long
            + (X9 as libc::c_long + 0x5a827999 as libc::c_long
                + (D & A | D & B | A & B) as libc::c_long)) as uint32_t;
        C = CRYPTO_rotl_u32(C, 9 as libc::c_int);
        B = (B as libc::c_long
            + (X13 as libc::c_long + 0x5a827999 as libc::c_long
                + (C & D | C & A | D & A) as libc::c_long)) as uint32_t;
        B = CRYPTO_rotl_u32(B, 13 as libc::c_int);
        A = (A as libc::c_long
            + (X2 as libc::c_long + 0x5a827999 as libc::c_long
                + (B & C | B & D | C & D) as libc::c_long)) as uint32_t;
        A = CRYPTO_rotl_u32(A, 3 as libc::c_int);
        D = (D as libc::c_long
            + (X6 as libc::c_long + 0x5a827999 as libc::c_long
                + (A & B | A & C | B & C) as libc::c_long)) as uint32_t;
        D = CRYPTO_rotl_u32(D, 5 as libc::c_int);
        C = (C as libc::c_long
            + (X10 as libc::c_long + 0x5a827999 as libc::c_long
                + (D & A | D & B | A & B) as libc::c_long)) as uint32_t;
        C = CRYPTO_rotl_u32(C, 9 as libc::c_int);
        B = (B as libc::c_long
            + (X14 as libc::c_long + 0x5a827999 as libc::c_long
                + (C & D | C & A | D & A) as libc::c_long)) as uint32_t;
        B = CRYPTO_rotl_u32(B, 13 as libc::c_int);
        A = (A as libc::c_long
            + (X3 as libc::c_long + 0x5a827999 as libc::c_long
                + (B & C | B & D | C & D) as libc::c_long)) as uint32_t;
        A = CRYPTO_rotl_u32(A, 3 as libc::c_int);
        D = (D as libc::c_long
            + (X7 as libc::c_long + 0x5a827999 as libc::c_long
                + (A & B | A & C | B & C) as libc::c_long)) as uint32_t;
        D = CRYPTO_rotl_u32(D, 5 as libc::c_int);
        C = (C as libc::c_long
            + (X11 as libc::c_long + 0x5a827999 as libc::c_long
                + (D & A | D & B | A & B) as libc::c_long)) as uint32_t;
        C = CRYPTO_rotl_u32(C, 9 as libc::c_int);
        B = (B as libc::c_long
            + (X15 as libc::c_long + 0x5a827999 as libc::c_long
                + (C & D | C & A | D & A) as libc::c_long)) as uint32_t;
        B = CRYPTO_rotl_u32(B, 13 as libc::c_int);
        A = (A as libc::c_long
            + (X0 as libc::c_long + 0x6ed9eba1 as libc::c_long
                + (B ^ C ^ D) as libc::c_long)) as uint32_t;
        A = CRYPTO_rotl_u32(A, 3 as libc::c_int);
        D = (D as libc::c_long
            + (X8 as libc::c_long + 0x6ed9eba1 as libc::c_long
                + (A ^ B ^ C) as libc::c_long)) as uint32_t;
        D = CRYPTO_rotl_u32(D, 9 as libc::c_int);
        C = (C as libc::c_long
            + (X4 as libc::c_long + 0x6ed9eba1 as libc::c_long
                + (D ^ A ^ B) as libc::c_long)) as uint32_t;
        C = CRYPTO_rotl_u32(C, 11 as libc::c_int);
        B = (B as libc::c_long
            + (X12 as libc::c_long + 0x6ed9eba1 as libc::c_long
                + (C ^ D ^ A) as libc::c_long)) as uint32_t;
        B = CRYPTO_rotl_u32(B, 15 as libc::c_int);
        A = (A as libc::c_long
            + (X2 as libc::c_long + 0x6ed9eba1 as libc::c_long
                + (B ^ C ^ D) as libc::c_long)) as uint32_t;
        A = CRYPTO_rotl_u32(A, 3 as libc::c_int);
        D = (D as libc::c_long
            + (X10 as libc::c_long + 0x6ed9eba1 as libc::c_long
                + (A ^ B ^ C) as libc::c_long)) as uint32_t;
        D = CRYPTO_rotl_u32(D, 9 as libc::c_int);
        C = (C as libc::c_long
            + (X6 as libc::c_long + 0x6ed9eba1 as libc::c_long
                + (D ^ A ^ B) as libc::c_long)) as uint32_t;
        C = CRYPTO_rotl_u32(C, 11 as libc::c_int);
        B = (B as libc::c_long
            + (X14 as libc::c_long + 0x6ed9eba1 as libc::c_long
                + (C ^ D ^ A) as libc::c_long)) as uint32_t;
        B = CRYPTO_rotl_u32(B, 15 as libc::c_int);
        A = (A as libc::c_long
            + (X1 as libc::c_long + 0x6ed9eba1 as libc::c_long
                + (B ^ C ^ D) as libc::c_long)) as uint32_t;
        A = CRYPTO_rotl_u32(A, 3 as libc::c_int);
        D = (D as libc::c_long
            + (X9 as libc::c_long + 0x6ed9eba1 as libc::c_long
                + (A ^ B ^ C) as libc::c_long)) as uint32_t;
        D = CRYPTO_rotl_u32(D, 9 as libc::c_int);
        C = (C as libc::c_long
            + (X5 as libc::c_long + 0x6ed9eba1 as libc::c_long
                + (D ^ A ^ B) as libc::c_long)) as uint32_t;
        C = CRYPTO_rotl_u32(C, 11 as libc::c_int);
        B = (B as libc::c_long
            + (X13 as libc::c_long + 0x6ed9eba1 as libc::c_long
                + (C ^ D ^ A) as libc::c_long)) as uint32_t;
        B = CRYPTO_rotl_u32(B, 15 as libc::c_int);
        A = (A as libc::c_long
            + (X3 as libc::c_long + 0x6ed9eba1 as libc::c_long
                + (B ^ C ^ D) as libc::c_long)) as uint32_t;
        A = CRYPTO_rotl_u32(A, 3 as libc::c_int);
        D = (D as libc::c_long
            + (X11 as libc::c_long + 0x6ed9eba1 as libc::c_long
                + (A ^ B ^ C) as libc::c_long)) as uint32_t;
        D = CRYPTO_rotl_u32(D, 9 as libc::c_int);
        C = (C as libc::c_long
            + (X7 as libc::c_long + 0x6ed9eba1 as libc::c_long
                + (D ^ A ^ B) as libc::c_long)) as uint32_t;
        C = CRYPTO_rotl_u32(C, 11 as libc::c_int);
        B = (B as libc::c_long
            + (X15 as libc::c_long + 0x6ed9eba1 as libc::c_long
                + (C ^ D ^ A) as libc::c_long)) as uint32_t;
        B = CRYPTO_rotl_u32(B, 15 as libc::c_int);
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
