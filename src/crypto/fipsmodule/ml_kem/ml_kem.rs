#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(asm)]
use core::arch::asm;
unsafe extern "C" {
    fn RAND_bytes(buf: *mut uint8_t, len: size_t) -> libc::c_int;
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn SHA3_256(data: *const uint8_t, len: size_t, out: *mut uint8_t) -> *mut uint8_t;
    fn SHA3_512(data: *const uint8_t, len: size_t, out: *mut uint8_t) -> *mut uint8_t;
    fn SHAKE256(
        data: *const uint8_t,
        in_len: size_t,
        out: *mut uint8_t,
        out_len: size_t,
    ) -> *mut uint8_t;
    fn SHAKE_Init(ctx: *mut KECCAK1600_CTX, block_size: size_t) -> libc::c_int;
    fn SHAKE_Absorb(
        ctx: *mut KECCAK1600_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn SHAKE_Squeeze(
        md: *mut uint8_t,
        ctx: *mut KECCAK1600_CTX,
        len: size_t,
    ) -> libc::c_int;
    fn SHAKE128_Init_x4(ctx: *mut KECCAK1600_CTX_x4) -> libc::c_int;
    fn SHAKE128_Absorb_once_x4(
        ctx: *mut KECCAK1600_CTX_x4,
        data0: *const libc::c_void,
        data1: *const libc::c_void,
        data2: *const libc::c_void,
        data3: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn SHAKE128_Squeezeblocks_x4(
        md0: *mut uint8_t,
        md1: *mut uint8_t,
        md2: *mut uint8_t,
        md3: *mut uint8_t,
        ctx: *mut KECCAK1600_CTX_x4,
        blks: size_t,
    ) -> libc::c_int;
    fn SHAKE256_x4(
        data0: *const uint8_t,
        data1: *const uint8_t,
        data2: *const uint8_t,
        data3: *const uint8_t,
        in_len: size_t,
        out0: *mut uint8_t,
        out1: *mut uint8_t,
        out2: *mut uint8_t,
        out3: *mut uint8_t,
        out_len: size_t,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __int16_t = libc::c_short;
pub type __uint16_t = libc::c_ushort;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type int16_t = __int16_t;
pub type int32_t = __int32_t;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C, align(32))]
pub struct mlk_poly(pub mlk_poly_Inner);
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mlk_poly_Inner {
    pub coeffs: [int16_t; 256],
}
#[allow(dead_code, non_upper_case_globals)]
const mlk_poly_PADDING: usize = ::core::mem::size_of::<mlk_poly>()
    - ::core::mem::size_of::<mlk_poly_Inner>();
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mlk_poly_mulcache {
    pub coeffs: [int16_t; 128],
}
pub type mlk_polyvec512 = [mlk_poly; 2];
pub type mlk_polymat512 = [mlk_poly; 4];
pub type mlk_polyvec_mulcache512 = [mlk_poly_mulcache; 2];
pub type KECCAK1600_CTX = keccak_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct keccak_st {
    pub A: [[uint64_t; 5]; 5],
    pub block_size: size_t,
    pub md_size: size_t,
    pub buf_load: size_t,
    pub buf: [uint8_t; 168],
    pub pad: uint8_t,
    pub state: uint8_t,
}
pub type KECCAK1600_CTX_x4 = [KECCAK1600_CTX; 4];
pub type mlk_polyvec768 = [mlk_poly; 3];
pub type mlk_polymat768 = [mlk_poly; 9];
pub type mlk_polyvec_mulcache768 = [mlk_poly_mulcache; 3];
pub type mlk_polyvec1024 = [mlk_poly; 4];
pub type mlk_polymat1024 = [mlk_poly; 16];
pub type mlk_polyvec_mulcache1024 = [mlk_poly_mulcache; 4];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct output_buffer {
    pub buffer: *mut uint8_t,
    pub length: *mut size_t,
    pub expected_length: size_t,
}
#[inline]
unsafe extern "C" fn boringssl_ensure_ml_kem_self_test() {}
#[inline]
unsafe extern "C" fn mlk_zeroize(mut ptr: *mut libc::c_void, mut len: size_t) {
    OPENSSL_cleanse(ptr, len);
}
#[inline]
unsafe extern "C" fn mlk_randombytes(mut ptr: *mut libc::c_void, mut len: size_t) {
    RAND_bytes(ptr as *mut uint8_t, len);
}
#[inline]
unsafe extern "C" fn mlk_value_barrier_u32(mut b: uint32_t) -> uint32_t {
    asm!("", inlateout(reg) b, options(preserves_flags, pure, readonly, att_syntax));
    return b;
}
#[inline]
unsafe extern "C" fn mlk_value_barrier_i32(mut b: int32_t) -> int32_t {
    asm!("", inlateout(reg) b, options(preserves_flags, pure, readonly, att_syntax));
    return b;
}
#[inline]
unsafe extern "C" fn mlk_value_barrier_u8(mut b: uint8_t) -> uint8_t {
    asm!("", inlateout(reg) b, options(preserves_flags, pure, readonly, att_syntax));
    return b;
}
#[inline]
unsafe extern "C" fn mlk_ct_cmask_nonzero_u16(mut x: uint16_t) -> uint16_t {
    let mut tmp: uint32_t = mlk_value_barrier_u32((x as uint32_t).wrapping_neg());
    tmp >>= 16 as libc::c_int;
    return tmp as uint16_t;
}
#[inline]
unsafe extern "C" fn mlk_ct_cmask_nonzero_u8(mut x: uint8_t) -> uint8_t {
    let mut tmp: uint32_t = mlk_value_barrier_u32((x as uint32_t).wrapping_neg());
    tmp >>= 24 as libc::c_int;
    return tmp as uint8_t;
}
#[inline]
unsafe extern "C" fn mlk_ct_cmask_neg_i16(mut x: int16_t) -> uint16_t {
    let mut tmp: int32_t = mlk_value_barrier_i32(x as int32_t);
    tmp >>= 16 as libc::c_int;
    return tmp as int16_t as uint16_t;
}
#[inline]
unsafe extern "C" fn mlk_ct_sel_int16(
    mut a: int16_t,
    mut b: int16_t,
    mut cond: uint16_t,
) -> int16_t {
    let mut au: uint16_t = a as uint16_t;
    let mut bu: uint16_t = b as uint16_t;
    let mut res: uint16_t = (bu as libc::c_int
        ^ mlk_ct_cmask_nonzero_u16(cond) as libc::c_int
            & (au as libc::c_int ^ bu as libc::c_int)) as uint16_t;
    return res as int16_t;
}
#[inline]
unsafe extern "C" fn mlk_ct_sel_uint8(
    mut a: uint8_t,
    mut b: uint8_t,
    mut cond: uint8_t,
) -> uint8_t {
    return (b as libc::c_int
        ^ mlk_ct_cmask_nonzero_u8(cond) as libc::c_int
            & (a as libc::c_int ^ b as libc::c_int)) as uint8_t;
}
#[inline]
unsafe extern "C" fn mlk_ct_memcmp(
    mut a: *const uint8_t,
    mut b: *const uint8_t,
    len: size_t,
) -> uint8_t {
    let mut r: uint8_t = 0 as libc::c_int as uint8_t;
    let mut s: uint8_t = 0 as libc::c_int as uint8_t;
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while (i as size_t) < len {
        r = (r as libc::c_int
            | *a.offset(i as isize) as libc::c_int
                ^ *b.offset(i as isize) as libc::c_int) as uint8_t;
        s = (s as libc::c_int
            ^ (*a.offset(i as isize) as libc::c_int
                ^ *b.offset(i as isize) as libc::c_int)) as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
    return (mlk_value_barrier_u8(
        (mlk_ct_cmask_nonzero_u8(r) as libc::c_int ^ s as libc::c_int) as uint8_t,
    ) as libc::c_int ^ s as libc::c_int) as uint8_t;
}
#[inline]
unsafe extern "C" fn mlk_ct_cmov_zero(
    mut r: *mut uint8_t,
    mut x: *const uint8_t,
    mut len: size_t,
    mut b: uint8_t,
) {
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < len {
        *r
            .offset(
                i as isize,
            ) = mlk_ct_sel_uint8(*r.offset(i as isize), *x.offset(i as isize), b);
        i = i.wrapping_add(1);
        i;
    }
}
#[inline(always)]
unsafe extern "C" fn mlk_cast_uint16_to_int16(mut x: uint16_t) -> int16_t {
    return x as int16_t;
}
#[inline(always)]
unsafe extern "C" fn mlk_montgomery_reduce(mut a: int32_t) -> int16_t {
    let QINV: uint32_t = 62209 as libc::c_int as uint32_t;
    let a_reduced: uint16_t = (a & 65535 as libc::c_int) as uint16_t;
    let a_inverted: uint16_t = (a_reduced as uint32_t * QINV
        & 65535 as libc::c_int as uint32_t) as uint16_t;
    let t: int16_t = mlk_cast_uint16_to_int16(a_inverted);
    let mut r: int32_t = 0;
    r = a - t as int32_t * 3329 as libc::c_int;
    r = r >> 16 as libc::c_int;
    return r as int16_t;
}
#[inline]
unsafe extern "C" fn mlk_fqmul(mut a: int16_t, mut b: int16_t) -> int16_t {
    let mut res: int16_t = 0;
    res = mlk_montgomery_reduce(a as int32_t * b as int32_t);
    return res;
}
#[inline]
unsafe extern "C" fn mlk_barrett_reduce(mut a: int16_t) -> int16_t {
    let magic: int32_t = 20159 as libc::c_int;
    let t: int32_t = magic * a as libc::c_int + ((1 as libc::c_int) << 25 as libc::c_int)
        >> 26 as libc::c_int;
    let mut res: int16_t = (a as libc::c_int - t * 3329 as libc::c_int) as int16_t;
    return res;
}
unsafe extern "C" fn mlkem_poly_tomont(mut r: *mut mlk_poly) {
    let mut i: libc::c_uint = 0;
    let f: int16_t = 1353 as libc::c_int as int16_t;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 256 as libc::c_int as libc::c_uint {
        (*r).0.coeffs[i as usize] = mlk_fqmul((*r).0.coeffs[i as usize], f);
        i = i.wrapping_add(1);
        i;
    }
}
#[inline]
unsafe extern "C" fn mlk_scalar_signed_to_unsigned_q(mut c: int16_t) -> uint16_t {
    c = mlk_ct_sel_int16(
        (c as libc::c_int + 3329 as libc::c_int) as int16_t,
        c,
        mlk_ct_cmask_neg_i16(c),
    );
    return c as uint16_t;
}
unsafe extern "C" fn mlkem_poly_reduce(mut r: *mut mlk_poly) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 256 as libc::c_int as libc::c_uint {
        let mut t: int16_t = mlk_barrett_reduce((*r).0.coeffs[i as usize]);
        (*r).0.coeffs[i as usize] = mlk_scalar_signed_to_unsigned_q(t) as int16_t;
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem_poly_add(mut r: *mut mlk_poly, mut b: *const mlk_poly) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 256 as libc::c_int as libc::c_uint {
        (*r)
            .0
            .coeffs[i
            as usize] = ((*r).0.coeffs[i as usize] as libc::c_int
            + (*b).0.coeffs[i as usize] as libc::c_int) as int16_t;
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem_poly_sub(mut r: *mut mlk_poly, mut b: *const mlk_poly) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 256 as libc::c_int as libc::c_uint {
        (*r)
            .0
            .coeffs[i
            as usize] = ((*r).0.coeffs[i as usize] as libc::c_int
            - (*b).0.coeffs[i as usize] as libc::c_int) as int16_t;
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem_poly_mulcache_compute(
    mut x: *mut mlk_poly_mulcache,
    mut a: *const mlk_poly,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 4 as libc::c_int) as libc::c_uint {
        (*x)
            .coeffs[(2 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(0 as libc::c_int as libc::c_uint)
            as usize] = mlk_fqmul(
            (*a)
                .0
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(1 as libc::c_int as libc::c_uint) as usize],
            zetas[(64 as libc::c_int as libc::c_uint).wrapping_add(i) as usize],
        );
        (*x)
            .coeffs[(2 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(1 as libc::c_int as libc::c_uint)
            as usize] = mlk_fqmul(
            (*a)
                .0
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(3 as libc::c_int as libc::c_uint) as usize],
            -(zetas[(64 as libc::c_int as libc::c_uint).wrapping_add(i) as usize]
                as libc::c_int) as int16_t,
        );
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlk_ntt_butterfly_block(
    mut r: *mut int16_t,
    mut zeta: int16_t,
    mut start: libc::c_uint,
    mut len: libc::c_uint,
    mut bound: libc::c_int,
) {
    let mut j: libc::c_uint = 0;
    j = start;
    while j < start.wrapping_add(len) {
        let mut t: int16_t = 0;
        t = mlk_fqmul(*r.offset(j.wrapping_add(len) as isize), zeta);
        *r
            .offset(
                j.wrapping_add(len) as isize,
            ) = (*r.offset(j as isize) as libc::c_int - t as libc::c_int) as int16_t;
        *r
            .offset(
                j as isize,
            ) = (*r.offset(j as isize) as libc::c_int + t as libc::c_int) as int16_t;
        j = j.wrapping_add(1);
        j;
    }
}
unsafe extern "C" fn mlk_ntt_layer(mut r: *mut int16_t, mut layer: libc::c_uint) {
    let mut start: libc::c_uint = 0;
    let mut k: libc::c_uint = 0;
    let mut len: libc::c_uint = 0;
    k = (1 as libc::c_uint) << layer.wrapping_sub(1 as libc::c_int as libc::c_uint);
    len = (256 as libc::c_int >> layer) as libc::c_uint;
    start = 0 as libc::c_int as libc::c_uint;
    while start < 256 as libc::c_int as libc::c_uint {
        let fresh0 = k;
        k = k.wrapping_add(1);
        let mut zeta: int16_t = zetas[fresh0 as usize];
        mlk_ntt_butterfly_block(
            r,
            zeta,
            start,
            len,
            layer.wrapping_mul(3329 as libc::c_int as libc::c_uint) as libc::c_int,
        );
        start = start.wrapping_add((2 as libc::c_int as libc::c_uint).wrapping_mul(len));
    }
}
unsafe extern "C" fn mlkem_poly_ntt(mut p: *mut mlk_poly) {
    let mut layer: libc::c_uint = 0;
    let mut r: *mut int16_t = 0 as *mut int16_t;
    r = ((*p).0.coeffs).as_mut_ptr();
    layer = 1 as libc::c_int as libc::c_uint;
    while layer <= 7 as libc::c_int as libc::c_uint {
        mlk_ntt_layer(r, layer);
        layer = layer.wrapping_add(1);
        layer;
    }
}
unsafe extern "C" fn mlk_invntt_layer(mut r: *mut int16_t, mut layer: libc::c_uint) {
    let mut start: libc::c_uint = 0;
    let mut k: libc::c_uint = 0;
    let mut len: libc::c_uint = 0;
    len = (256 as libc::c_int >> layer) as libc::c_uint;
    k = ((1 as libc::c_uint) << layer).wrapping_sub(1 as libc::c_int as libc::c_uint);
    start = 0 as libc::c_int as libc::c_uint;
    while start < 256 as libc::c_int as libc::c_uint {
        let mut j: libc::c_uint = 0;
        let fresh1 = k;
        k = k.wrapping_sub(1);
        let mut zeta: int16_t = zetas[fresh1 as usize];
        j = start;
        while j < start.wrapping_add(len) {
            let mut t: int16_t = *r.offset(j as isize);
            *r
                .offset(
                    j as isize,
                ) = mlk_barrett_reduce(
                (t as libc::c_int
                    + *r.offset(j.wrapping_add(len) as isize) as libc::c_int) as int16_t,
            );
            *r
                .offset(
                    j.wrapping_add(len) as isize,
                ) = (*r.offset(j.wrapping_add(len) as isize) as libc::c_int
                - t as libc::c_int) as int16_t;
            *r
                .offset(
                    j.wrapping_add(len) as isize,
                ) = mlk_fqmul(*r.offset(j.wrapping_add(len) as isize), zeta);
            j = j.wrapping_add(1);
            j;
        }
        start = start.wrapping_add((2 as libc::c_int as libc::c_uint).wrapping_mul(len));
    }
}
unsafe extern "C" fn mlkem_poly_invntt_tomont(mut p: *mut mlk_poly) {
    let mut j: libc::c_uint = 0;
    let mut layer: libc::c_uint = 0;
    let f: int16_t = 1441 as libc::c_int as int16_t;
    let mut r: *mut int16_t = ((*p).0.coeffs).as_mut_ptr();
    j = 0 as libc::c_int as libc::c_uint;
    while j < 256 as libc::c_int as libc::c_uint {
        *r.offset(j as isize) = mlk_fqmul(*r.offset(j as isize), f);
        j = j.wrapping_add(1);
        j;
    }
    layer = 7 as libc::c_int as libc::c_uint;
    while layer > 0 as libc::c_int as libc::c_uint {
        mlk_invntt_layer(r, layer);
        layer = layer.wrapping_sub(1);
        layer;
    }
}
#[inline]
unsafe extern "C" fn mlk_scalar_compress_d1(mut u: uint16_t) -> uint32_t {
    let mut d0: uint32_t = u as uint32_t * 1290168 as libc::c_int as uint32_t;
    return d0.wrapping_add((1 as libc::c_uint) << 30 as libc::c_int)
        >> 31 as libc::c_int;
}
#[inline]
unsafe extern "C" fn mlk_scalar_compress_d4(mut u: uint16_t) -> uint32_t {
    let mut d0: uint32_t = u as uint32_t * 1290160 as libc::c_int as uint32_t;
    return d0.wrapping_add((1 as libc::c_uint) << 27 as libc::c_int)
        >> 28 as libc::c_int;
}
#[inline]
unsafe extern "C" fn mlk_scalar_decompress_d4(mut u: uint32_t) -> uint16_t {
    return ((u * 3329 as libc::c_int as uint32_t)
        .wrapping_add(8 as libc::c_int as uint32_t) >> 4 as libc::c_int) as uint16_t;
}
#[inline]
unsafe extern "C" fn mlk_scalar_compress_d5(mut u: uint16_t) -> uint32_t {
    let mut d0: uint32_t = u as uint32_t * 1290176 as libc::c_int as uint32_t;
    return d0.wrapping_add((1 as libc::c_uint) << 26 as libc::c_int)
        >> 27 as libc::c_int;
}
#[inline]
unsafe extern "C" fn mlk_scalar_decompress_d5(mut u: uint32_t) -> uint16_t {
    return ((u * 3329 as libc::c_int as uint32_t)
        .wrapping_add(16 as libc::c_int as uint32_t) >> 5 as libc::c_int) as uint16_t;
}
#[inline]
unsafe extern "C" fn mlk_scalar_compress_d10(mut u: uint16_t) -> uint32_t {
    let mut d0: uint64_t = u as uint64_t * 2642263040 as libc::c_long as uint64_t;
    d0 = d0.wrapping_add((1 as libc::c_uint as uint64_t) << 32 as libc::c_int)
        >> 33 as libc::c_int;
    return (d0 & 0x3ff as libc::c_int as uint64_t) as uint32_t;
}
#[inline]
unsafe extern "C" fn mlk_scalar_decompress_d10(mut u: uint32_t) -> uint16_t {
    return ((u * 3329 as libc::c_int as uint32_t)
        .wrapping_add(512 as libc::c_int as uint32_t) >> 10 as libc::c_int) as uint16_t;
}
#[inline]
unsafe extern "C" fn mlk_scalar_compress_d11(mut u: uint16_t) -> uint32_t {
    let mut d0: uint64_t = u as uint64_t * 5284526080 as libc::c_long as uint64_t;
    d0 = d0.wrapping_add((1 as libc::c_uint as uint64_t) << 32 as libc::c_int)
        >> 33 as libc::c_int;
    return (d0 & 0x7ff as libc::c_int as uint64_t) as uint32_t;
}
#[inline]
unsafe extern "C" fn mlk_scalar_decompress_d11(mut u: uint32_t) -> uint16_t {
    return ((u * 3329 as libc::c_int as uint32_t)
        .wrapping_add(1024 as libc::c_int as uint32_t) >> 11 as libc::c_int) as uint16_t;
}
unsafe extern "C" fn mlkem_poly_compress_d4(
    mut r: *mut uint8_t,
    mut a: *const mlk_poly,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 8 as libc::c_int) as libc::c_uint {
        let mut j: libc::c_uint = 0;
        let mut t: [uint8_t; 8] = [0 as libc::c_int as uint8_t, 0, 0, 0, 0, 0, 0, 0];
        j = 0 as libc::c_int as libc::c_uint;
        while j < 8 as libc::c_int as libc::c_uint {
            t[j
                as usize] = mlk_scalar_compress_d4(
                (*a)
                    .0
                    .coeffs[(8 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(j) as usize] as uint16_t,
            ) as uint8_t;
            j = j.wrapping_add(1);
            j;
        }
        *r
            .offset(
                i.wrapping_mul(4 as libc::c_int as libc::c_uint) as isize,
            ) = (t[0 as libc::c_int as usize] as libc::c_int
            | (t[1 as libc::c_int as usize] as libc::c_int) << 4 as libc::c_int)
            as uint8_t;
        *r
            .offset(
                i
                    .wrapping_mul(4 as libc::c_int as libc::c_uint)
                    .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
            ) = (t[2 as libc::c_int as usize] as libc::c_int
            | (t[3 as libc::c_int as usize] as libc::c_int) << 4 as libc::c_int)
            as uint8_t;
        *r
            .offset(
                i
                    .wrapping_mul(4 as libc::c_int as libc::c_uint)
                    .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
            ) = (t[4 as libc::c_int as usize] as libc::c_int
            | (t[5 as libc::c_int as usize] as libc::c_int) << 4 as libc::c_int)
            as uint8_t;
        *r
            .offset(
                i
                    .wrapping_mul(4 as libc::c_int as libc::c_uint)
                    .wrapping_add(3 as libc::c_int as libc::c_uint) as isize,
            ) = (t[6 as libc::c_int as usize] as libc::c_int
            | (t[7 as libc::c_int as usize] as libc::c_int) << 4 as libc::c_int)
            as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem_poly_compress_d10(
    mut r: *mut uint8_t,
    mut a: *const mlk_poly,
) {
    let mut j: libc::c_uint = 0;
    j = 0 as libc::c_int as libc::c_uint;
    while j < (256 as libc::c_int / 4 as libc::c_int) as libc::c_uint {
        let mut k: libc::c_uint = 0;
        let mut t: [uint16_t; 4] = [0; 4];
        k = 0 as libc::c_int as libc::c_uint;
        while k < 4 as libc::c_int as libc::c_uint {
            t[k
                as usize] = mlk_scalar_compress_d10(
                (*a)
                    .0
                    .coeffs[(4 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(k) as usize] as uint16_t,
            ) as uint16_t;
            k = k.wrapping_add(1);
            k;
        }
        *r
            .offset(
                (5 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(0 as libc::c_int as libc::c_uint) as isize,
            ) = (t[0 as libc::c_int as usize] as libc::c_int >> 0 as libc::c_int
            & 0xff as libc::c_int) as uint8_t;
        *r
            .offset(
                (5 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
            ) = (t[0 as libc::c_int as usize] as libc::c_int >> 8 as libc::c_int
            | (t[1 as libc::c_int as usize] as libc::c_int) << 2 as libc::c_int
                & 0xff as libc::c_int) as uint8_t;
        *r
            .offset(
                (5 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
            ) = (t[1 as libc::c_int as usize] as libc::c_int >> 6 as libc::c_int
            | (t[2 as libc::c_int as usize] as libc::c_int) << 4 as libc::c_int
                & 0xff as libc::c_int) as uint8_t;
        *r
            .offset(
                (5 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(3 as libc::c_int as libc::c_uint) as isize,
            ) = (t[2 as libc::c_int as usize] as libc::c_int >> 4 as libc::c_int
            | (t[3 as libc::c_int as usize] as libc::c_int) << 6 as libc::c_int
                & 0xff as libc::c_int) as uint8_t;
        *r
            .offset(
                (5 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(4 as libc::c_int as libc::c_uint) as isize,
            ) = (t[3 as libc::c_int as usize] as libc::c_int >> 2 as libc::c_int)
            as uint8_t;
        j = j.wrapping_add(1);
        j;
    }
}
unsafe extern "C" fn mlkem_poly_decompress_d4(
    mut r: *mut mlk_poly,
    mut a: *const uint8_t,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 2 as libc::c_int) as libc::c_uint {
        (*r)
            .0
            .coeffs[(2 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(0 as libc::c_int as libc::c_uint)
            as usize] = mlk_scalar_decompress_d4(
            (*a.offset(i as isize) as libc::c_int >> 0 as libc::c_int
                & 0xf as libc::c_int) as uint32_t,
        ) as int16_t;
        (*r)
            .0
            .coeffs[(2 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(1 as libc::c_int as libc::c_uint)
            as usize] = mlk_scalar_decompress_d4(
            (*a.offset(i as isize) as libc::c_int >> 4 as libc::c_int
                & 0xf as libc::c_int) as uint32_t,
        ) as int16_t;
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem_poly_decompress_d10(
    mut r: *mut mlk_poly,
    mut a: *const uint8_t,
) {
    let mut j: libc::c_uint = 0;
    j = 0 as libc::c_int as libc::c_uint;
    while j < (256 as libc::c_int / 4 as libc::c_int) as libc::c_uint {
        let mut k: libc::c_uint = 0;
        let mut t: [uint16_t; 4] = [0; 4];
        let mut base: *const uint8_t = &*a
            .offset((5 as libc::c_int as libc::c_uint).wrapping_mul(j) as isize)
            as *const uint8_t;
        t[0 as libc::c_int
            as usize] = (0x3ff as libc::c_int
            & (*base.offset(0 as libc::c_int as isize) as libc::c_int >> 0 as libc::c_int
                | (*base.offset(1 as libc::c_int as isize) as uint16_t as libc::c_int)
                    << 8 as libc::c_int)) as uint16_t;
        t[1 as libc::c_int
            as usize] = (0x3ff as libc::c_int
            & (*base.offset(1 as libc::c_int as isize) as libc::c_int >> 2 as libc::c_int
                | (*base.offset(2 as libc::c_int as isize) as uint16_t as libc::c_int)
                    << 6 as libc::c_int)) as uint16_t;
        t[2 as libc::c_int
            as usize] = (0x3ff as libc::c_int
            & (*base.offset(2 as libc::c_int as isize) as libc::c_int >> 4 as libc::c_int
                | (*base.offset(3 as libc::c_int as isize) as uint16_t as libc::c_int)
                    << 4 as libc::c_int)) as uint16_t;
        t[3 as libc::c_int
            as usize] = (0x3ff as libc::c_int
            & (*base.offset(3 as libc::c_int as isize) as libc::c_int >> 6 as libc::c_int
                | (*base.offset(4 as libc::c_int as isize) as uint16_t as libc::c_int)
                    << 2 as libc::c_int)) as uint16_t;
        k = 0 as libc::c_int as libc::c_uint;
        while k < 4 as libc::c_int as libc::c_uint {
            (*r)
                .0
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(j)
                .wrapping_add(k)
                as usize] = mlk_scalar_decompress_d10(t[k as usize] as uint32_t)
                as int16_t;
            k = k.wrapping_add(1);
            k;
        }
        j = j.wrapping_add(1);
        j;
    }
}
unsafe extern "C" fn mlkem_poly_compress_d5(
    mut r: *mut uint8_t,
    mut a: *const mlk_poly,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 8 as libc::c_int) as libc::c_uint {
        let mut j: libc::c_uint = 0;
        let mut t: [uint8_t; 8] = [0 as libc::c_int as uint8_t, 0, 0, 0, 0, 0, 0, 0];
        j = 0 as libc::c_int as libc::c_uint;
        while j < 8 as libc::c_int as libc::c_uint {
            t[j
                as usize] = mlk_scalar_compress_d5(
                (*a)
                    .0
                    .coeffs[(8 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(j) as usize] as uint16_t,
            ) as uint8_t;
            j = j.wrapping_add(1);
            j;
        }
        *r
            .offset(
                i.wrapping_mul(5 as libc::c_int as libc::c_uint) as isize,
            ) = (0xff as libc::c_int
            & (t[0 as libc::c_int as usize] as libc::c_int >> 0 as libc::c_int
                | (t[1 as libc::c_int as usize] as libc::c_int) << 5 as libc::c_int))
            as uint8_t;
        *r
            .offset(
                i
                    .wrapping_mul(5 as libc::c_int as libc::c_uint)
                    .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
            ) = (0xff as libc::c_int
            & (t[1 as libc::c_int as usize] as libc::c_int >> 3 as libc::c_int
                | (t[2 as libc::c_int as usize] as libc::c_int) << 2 as libc::c_int
                | (t[3 as libc::c_int as usize] as libc::c_int) << 7 as libc::c_int))
            as uint8_t;
        *r
            .offset(
                i
                    .wrapping_mul(5 as libc::c_int as libc::c_uint)
                    .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
            ) = (0xff as libc::c_int
            & (t[3 as libc::c_int as usize] as libc::c_int >> 1 as libc::c_int
                | (t[4 as libc::c_int as usize] as libc::c_int) << 4 as libc::c_int))
            as uint8_t;
        *r
            .offset(
                i
                    .wrapping_mul(5 as libc::c_int as libc::c_uint)
                    .wrapping_add(3 as libc::c_int as libc::c_uint) as isize,
            ) = (0xff as libc::c_int
            & (t[4 as libc::c_int as usize] as libc::c_int >> 4 as libc::c_int
                | (t[5 as libc::c_int as usize] as libc::c_int) << 1 as libc::c_int
                | (t[6 as libc::c_int as usize] as libc::c_int) << 6 as libc::c_int))
            as uint8_t;
        *r
            .offset(
                i
                    .wrapping_mul(5 as libc::c_int as libc::c_uint)
                    .wrapping_add(4 as libc::c_int as libc::c_uint) as isize,
            ) = (0xff as libc::c_int
            & (t[6 as libc::c_int as usize] as libc::c_int >> 2 as libc::c_int
                | (t[7 as libc::c_int as usize] as libc::c_int) << 3 as libc::c_int))
            as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem_poly_compress_d11(
    mut r: *mut uint8_t,
    mut a: *const mlk_poly,
) {
    let mut j: libc::c_uint = 0;
    j = 0 as libc::c_int as libc::c_uint;
    while j < (256 as libc::c_int / 8 as libc::c_int) as libc::c_uint {
        let mut k: libc::c_uint = 0;
        let mut t: [uint16_t; 8] = [0; 8];
        k = 0 as libc::c_int as libc::c_uint;
        while k < 8 as libc::c_int as libc::c_uint {
            t[k
                as usize] = mlk_scalar_compress_d11(
                (*a)
                    .0
                    .coeffs[(8 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(k) as usize] as uint16_t,
            ) as uint16_t;
            k = k.wrapping_add(1);
            k;
        }
        *r
            .offset(
                (11 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(0 as libc::c_int as libc::c_uint) as isize,
            ) = (t[0 as libc::c_int as usize] as libc::c_int >> 0 as libc::c_int
            & 0xff as libc::c_int) as uint8_t;
        *r
            .offset(
                (11 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
            ) = (t[0 as libc::c_int as usize] as libc::c_int >> 8 as libc::c_int
            | (t[1 as libc::c_int as usize] as libc::c_int) << 3 as libc::c_int
                & 0xff as libc::c_int) as uint8_t;
        *r
            .offset(
                (11 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
            ) = (t[1 as libc::c_int as usize] as libc::c_int >> 5 as libc::c_int
            | (t[2 as libc::c_int as usize] as libc::c_int) << 6 as libc::c_int
                & 0xff as libc::c_int) as uint8_t;
        *r
            .offset(
                (11 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(3 as libc::c_int as libc::c_uint) as isize,
            ) = (t[2 as libc::c_int as usize] as libc::c_int >> 2 as libc::c_int
            & 0xff as libc::c_int) as uint8_t;
        *r
            .offset(
                (11 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(4 as libc::c_int as libc::c_uint) as isize,
            ) = (t[2 as libc::c_int as usize] as libc::c_int >> 10 as libc::c_int
            | (t[3 as libc::c_int as usize] as libc::c_int) << 1 as libc::c_int
                & 0xff as libc::c_int) as uint8_t;
        *r
            .offset(
                (11 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(5 as libc::c_int as libc::c_uint) as isize,
            ) = (t[3 as libc::c_int as usize] as libc::c_int >> 7 as libc::c_int
            | (t[4 as libc::c_int as usize] as libc::c_int) << 4 as libc::c_int
                & 0xff as libc::c_int) as uint8_t;
        *r
            .offset(
                (11 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(6 as libc::c_int as libc::c_uint) as isize,
            ) = (t[4 as libc::c_int as usize] as libc::c_int >> 4 as libc::c_int
            | (t[5 as libc::c_int as usize] as libc::c_int) << 7 as libc::c_int
                & 0xff as libc::c_int) as uint8_t;
        *r
            .offset(
                (11 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(7 as libc::c_int as libc::c_uint) as isize,
            ) = (t[5 as libc::c_int as usize] as libc::c_int >> 1 as libc::c_int
            & 0xff as libc::c_int) as uint8_t;
        *r
            .offset(
                (11 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(8 as libc::c_int as libc::c_uint) as isize,
            ) = (t[5 as libc::c_int as usize] as libc::c_int >> 9 as libc::c_int
            | (t[6 as libc::c_int as usize] as libc::c_int) << 2 as libc::c_int
                & 0xff as libc::c_int) as uint8_t;
        *r
            .offset(
                (11 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(9 as libc::c_int as libc::c_uint) as isize,
            ) = (t[6 as libc::c_int as usize] as libc::c_int >> 6 as libc::c_int
            | (t[7 as libc::c_int as usize] as libc::c_int) << 5 as libc::c_int
                & 0xff as libc::c_int) as uint8_t;
        *r
            .offset(
                (11 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(10 as libc::c_int as libc::c_uint) as isize,
            ) = (t[7 as libc::c_int as usize] as libc::c_int >> 3 as libc::c_int)
            as uint8_t;
        j = j.wrapping_add(1);
        j;
    }
}
unsafe extern "C" fn mlkem_poly_decompress_d5(
    mut r: *mut mlk_poly,
    mut a: *const uint8_t,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 8 as libc::c_int) as libc::c_uint {
        let mut j: libc::c_uint = 0;
        let mut t: [uint8_t; 8] = [0; 8];
        let offset: libc::c_uint = i.wrapping_mul(5 as libc::c_int as libc::c_uint);
        t[0 as libc::c_int
            as usize] = (0x1f as libc::c_int
            & *a.offset(offset.wrapping_add(0 as libc::c_int as libc::c_uint) as isize)
                as libc::c_int >> 0 as libc::c_int) as uint8_t;
        t[1 as libc::c_int
            as usize] = (0x1f as libc::c_int
            & (*a.offset(offset.wrapping_add(0 as libc::c_int as libc::c_uint) as isize)
                as libc::c_int >> 5 as libc::c_int
                | (*a
                    .offset(
                        offset.wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
                    ) as libc::c_int) << 3 as libc::c_int)) as uint8_t;
        t[2 as libc::c_int
            as usize] = (0x1f as libc::c_int
            & *a.offset(offset.wrapping_add(1 as libc::c_int as libc::c_uint) as isize)
                as libc::c_int >> 2 as libc::c_int) as uint8_t;
        t[3 as libc::c_int
            as usize] = (0x1f as libc::c_int
            & (*a.offset(offset.wrapping_add(1 as libc::c_int as libc::c_uint) as isize)
                as libc::c_int >> 7 as libc::c_int
                | (*a
                    .offset(
                        offset.wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
                    ) as libc::c_int) << 1 as libc::c_int)) as uint8_t;
        t[4 as libc::c_int
            as usize] = (0x1f as libc::c_int
            & (*a.offset(offset.wrapping_add(2 as libc::c_int as libc::c_uint) as isize)
                as libc::c_int >> 4 as libc::c_int
                | (*a
                    .offset(
                        offset.wrapping_add(3 as libc::c_int as libc::c_uint) as isize,
                    ) as libc::c_int) << 4 as libc::c_int)) as uint8_t;
        t[5 as libc::c_int
            as usize] = (0x1f as libc::c_int
            & *a.offset(offset.wrapping_add(3 as libc::c_int as libc::c_uint) as isize)
                as libc::c_int >> 1 as libc::c_int) as uint8_t;
        t[6 as libc::c_int
            as usize] = (0x1f as libc::c_int
            & (*a.offset(offset.wrapping_add(3 as libc::c_int as libc::c_uint) as isize)
                as libc::c_int >> 6 as libc::c_int
                | (*a
                    .offset(
                        offset.wrapping_add(4 as libc::c_int as libc::c_uint) as isize,
                    ) as libc::c_int) << 2 as libc::c_int)) as uint8_t;
        t[7 as libc::c_int
            as usize] = (0x1f as libc::c_int
            & *a.offset(offset.wrapping_add(4 as libc::c_int as libc::c_uint) as isize)
                as libc::c_int >> 3 as libc::c_int) as uint8_t;
        j = 0 as libc::c_int as libc::c_uint;
        while j < 8 as libc::c_int as libc::c_uint {
            (*r)
                .0
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(j)
                as usize] = mlk_scalar_decompress_d5(t[j as usize] as uint32_t)
                as int16_t;
            j = j.wrapping_add(1);
            j;
        }
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem_poly_decompress_d11(
    mut r: *mut mlk_poly,
    mut a: *const uint8_t,
) {
    let mut j: libc::c_uint = 0;
    j = 0 as libc::c_int as libc::c_uint;
    while j < (256 as libc::c_int / 8 as libc::c_int) as libc::c_uint {
        let mut k: libc::c_uint = 0;
        let mut t: [uint16_t; 8] = [0; 8];
        let mut base: *const uint8_t = &*a
            .offset((11 as libc::c_int as libc::c_uint).wrapping_mul(j) as isize)
            as *const uint8_t;
        t[0 as libc::c_int
            as usize] = (0x7ff as libc::c_int
            & (*base.offset(0 as libc::c_int as isize) as libc::c_int >> 0 as libc::c_int
                | (*base.offset(1 as libc::c_int as isize) as uint16_t as libc::c_int)
                    << 8 as libc::c_int)) as uint16_t;
        t[1 as libc::c_int
            as usize] = (0x7ff as libc::c_int
            & (*base.offset(1 as libc::c_int as isize) as libc::c_int >> 3 as libc::c_int
                | (*base.offset(2 as libc::c_int as isize) as uint16_t as libc::c_int)
                    << 5 as libc::c_int)) as uint16_t;
        t[2 as libc::c_int
            as usize] = (0x7ff as libc::c_int
            & (*base.offset(2 as libc::c_int as isize) as libc::c_int >> 6 as libc::c_int
                | (*base.offset(3 as libc::c_int as isize) as uint16_t as libc::c_int)
                    << 2 as libc::c_int
                | (*base.offset(4 as libc::c_int as isize) as uint16_t as libc::c_int)
                    << 10 as libc::c_int)) as uint16_t;
        t[3 as libc::c_int
            as usize] = (0x7ff as libc::c_int
            & (*base.offset(4 as libc::c_int as isize) as libc::c_int >> 1 as libc::c_int
                | (*base.offset(5 as libc::c_int as isize) as uint16_t as libc::c_int)
                    << 7 as libc::c_int)) as uint16_t;
        t[4 as libc::c_int
            as usize] = (0x7ff as libc::c_int
            & (*base.offset(5 as libc::c_int as isize) as libc::c_int >> 4 as libc::c_int
                | (*base.offset(6 as libc::c_int as isize) as uint16_t as libc::c_int)
                    << 4 as libc::c_int)) as uint16_t;
        t[5 as libc::c_int
            as usize] = (0x7ff as libc::c_int
            & (*base.offset(6 as libc::c_int as isize) as libc::c_int >> 7 as libc::c_int
                | (*base.offset(7 as libc::c_int as isize) as uint16_t as libc::c_int)
                    << 1 as libc::c_int
                | (*base.offset(8 as libc::c_int as isize) as uint16_t as libc::c_int)
                    << 9 as libc::c_int)) as uint16_t;
        t[6 as libc::c_int
            as usize] = (0x7ff as libc::c_int
            & (*base.offset(8 as libc::c_int as isize) as libc::c_int >> 2 as libc::c_int
                | (*base.offset(9 as libc::c_int as isize) as uint16_t as libc::c_int)
                    << 6 as libc::c_int)) as uint16_t;
        t[7 as libc::c_int
            as usize] = (0x7ff as libc::c_int
            & (*base.offset(9 as libc::c_int as isize) as libc::c_int >> 5 as libc::c_int
                | (*base.offset(10 as libc::c_int as isize) as uint16_t as libc::c_int)
                    << 3 as libc::c_int)) as uint16_t;
        k = 0 as libc::c_int as libc::c_uint;
        while k < 8 as libc::c_int as libc::c_uint {
            (*r)
                .0
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(j)
                .wrapping_add(k)
                as usize] = mlk_scalar_decompress_d11(t[k as usize] as uint32_t)
                as int16_t;
            k = k.wrapping_add(1);
            k;
        }
        j = j.wrapping_add(1);
        j;
    }
}
unsafe extern "C" fn mlkem_poly_tobytes(mut r: *mut uint8_t, mut a: *const mlk_poly) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 2 as libc::c_int) as libc::c_uint {
        let t0: uint16_t = (*a)
            .0
            .coeffs[(2 as libc::c_int as libc::c_uint).wrapping_mul(i) as usize]
            as uint16_t;
        let t1: uint16_t = (*a)
            .0
            .coeffs[(2 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(1 as libc::c_int as libc::c_uint) as usize] as uint16_t;
        *r
            .offset(
                (3 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(0 as libc::c_int as libc::c_uint) as isize,
            ) = (t0 as libc::c_int & 0xff as libc::c_int) as uint8_t;
        *r
            .offset(
                (3 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
            ) = (t0 as libc::c_int >> 8 as libc::c_int
            | (t1 as libc::c_int) << 4 as libc::c_int & 0xf0 as libc::c_int) as uint8_t;
        *r
            .offset(
                (3 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
            ) = (t1 as libc::c_int >> 4 as libc::c_int) as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem_poly_frombytes(mut r: *mut mlk_poly, mut a: *const uint8_t) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 2 as libc::c_int) as libc::c_uint {
        let t0: uint8_t = *a
            .offset(
                (3 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(0 as libc::c_int as libc::c_uint) as isize,
            );
        let t1: uint8_t = *a
            .offset(
                (3 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
            );
        let t2: uint8_t = *a
            .offset(
                (3 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
            );
        (*r)
            .0
            .coeffs[(2 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(0 as libc::c_int as libc::c_uint)
            as usize] = (t0 as libc::c_int
            | (t1 as libc::c_int) << 8 as libc::c_int & 0xfff as libc::c_int) as int16_t;
        (*r)
            .0
            .coeffs[(2 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(1 as libc::c_int as libc::c_uint)
            as usize] = (t1 as libc::c_int >> 4 as libc::c_int
            | (t2 as libc::c_int) << 4 as libc::c_int) as int16_t;
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem_poly_frommsg(mut r: *mut mlk_poly, mut msg: *const uint8_t) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 8 as libc::c_int) as libc::c_uint {
        let mut j: libc::c_uint = 0;
        j = 0 as libc::c_int as libc::c_uint;
        while j < 8 as libc::c_int as libc::c_uint {
            let mut mask: uint8_t = mlk_value_barrier_u8(
                ((1 as libc::c_uint) << j) as uint8_t,
            );
            (*r)
                .0
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(j)
                as usize] = mlk_ct_sel_int16(
                ((3329 as libc::c_int + 1 as libc::c_int) / 2 as libc::c_int) as int16_t,
                0 as libc::c_int as int16_t,
                (*msg.offset(i as isize) as libc::c_int & mask as libc::c_int)
                    as uint16_t,
            );
            j = j.wrapping_add(1);
            j;
        }
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem_poly_tomsg(mut msg: *mut uint8_t, mut a: *const mlk_poly) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 8 as libc::c_int) as libc::c_uint {
        let mut j: libc::c_uint = 0;
        *msg.offset(i as isize) = 0 as libc::c_int as uint8_t;
        j = 0 as libc::c_int as libc::c_uint;
        while j < 8 as libc::c_int as libc::c_uint {
            let mut t: uint32_t = mlk_scalar_compress_d1(
                (*a)
                    .0
                    .coeffs[(8 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(j) as usize] as uint16_t,
            );
            let ref mut fresh2 = *msg.offset(i as isize);
            *fresh2 = (*fresh2 as uint32_t | t << j) as uint8_t;
            j = j.wrapping_add(1);
            j;
        }
        i = i.wrapping_add(1);
        i;
    }
}
#[inline]
unsafe extern "C" fn mlkem512_poly_compress_du(
    mut r: *mut uint8_t,
    mut a: *const mlk_poly,
) {
    mlkem_poly_compress_d10(r, a);
}
#[inline]
unsafe extern "C" fn mlkem512_poly_decompress_du(
    mut r: *mut mlk_poly,
    mut a: *const uint8_t,
) {
    mlkem_poly_decompress_d10(r, a);
}
#[inline]
unsafe extern "C" fn mlkem512_poly_compress_dv(
    mut r: *mut uint8_t,
    mut a: *const mlk_poly,
) {
    mlkem_poly_compress_d4(r, a);
}
#[inline]
unsafe extern "C" fn mlkem512_poly_decompress_dv(
    mut r: *mut mlk_poly,
    mut a: *const uint8_t,
) {
    mlkem_poly_decompress_d4(r, a);
}
#[inline]
unsafe extern "C" fn mlkem768_poly_compress_du(
    mut r: *mut uint8_t,
    mut a: *const mlk_poly,
) {
    mlkem_poly_compress_d10(r, a);
}
#[inline]
unsafe extern "C" fn mlkem768_poly_decompress_du(
    mut r: *mut mlk_poly,
    mut a: *const uint8_t,
) {
    mlkem_poly_decompress_d10(r, a);
}
#[inline]
unsafe extern "C" fn mlkem768_poly_compress_dv(
    mut r: *mut uint8_t,
    mut a: *const mlk_poly,
) {
    mlkem_poly_compress_d4(r, a);
}
#[inline]
unsafe extern "C" fn mlkem768_poly_decompress_dv(
    mut r: *mut mlk_poly,
    mut a: *const uint8_t,
) {
    mlkem_poly_decompress_d4(r, a);
}
#[inline]
unsafe extern "C" fn mlkem1024_poly_compress_du(
    mut r: *mut uint8_t,
    mut a: *const mlk_poly,
) {
    mlkem_poly_compress_d11(r, a);
}
#[inline]
unsafe extern "C" fn mlkem1024_poly_decompress_du(
    mut r: *mut mlk_poly,
    mut a: *const uint8_t,
) {
    mlkem_poly_decompress_d11(r, a);
}
#[inline]
unsafe extern "C" fn mlkem1024_poly_compress_dv(
    mut r: *mut uint8_t,
    mut a: *const mlk_poly,
) {
    mlkem_poly_compress_d5(r, a);
}
#[inline]
unsafe extern "C" fn mlkem1024_poly_decompress_dv(
    mut r: *mut mlk_poly,
    mut a: *const uint8_t,
) {
    mlkem_poly_decompress_d5(r, a);
}
unsafe extern "C" fn mlkem512_polyvec_compress_du(
    mut r: *mut uint8_t,
    mut a: *const mlk_poly,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        mlkem512_poly_compress_du(
            r.offset(i.wrapping_mul(320 as libc::c_int as libc::c_uint) as isize),
            &*a.offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem512_polyvec_decompress_du(
    mut r: *mut mlk_poly,
    mut a: *const uint8_t,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        mlkem512_poly_decompress_du(
            &mut *r.offset(i as isize),
            a.offset(i.wrapping_mul(320 as libc::c_int as libc::c_uint) as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem512_polyvec_tobytes(
    mut r: *mut uint8_t,
    mut a: *const mlk_poly,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        mlkem_poly_tobytes(
            r.offset(i.wrapping_mul(384 as libc::c_int as libc::c_uint) as isize),
            &*a.offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem512_polyvec_frombytes(
    mut r: *mut mlk_poly,
    mut a: *const uint8_t,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        mlkem_poly_frombytes(
            &mut *r.offset(i as isize),
            a.offset(i.wrapping_mul(384 as libc::c_int as libc::c_uint) as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem512_polyvec_ntt(mut r: *mut mlk_poly) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        mlkem_poly_ntt(&mut *r.offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem512_polyvec_invntt_tomont(mut r: *mut mlk_poly) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        mlkem_poly_invntt_tomont(&mut *r.offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem512_polyvec_basemul_acc_montgomery_cached(
    mut r: *mut mlk_poly,
    mut a: *const mlk_poly,
    mut b: *const mlk_poly,
    mut b_cache: *const mlk_poly_mulcache,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 2 as libc::c_int) as libc::c_uint {
        let mut k: libc::c_uint = 0;
        let mut t: [int32_t; 2] = [0 as libc::c_int, 0];
        k = 0 as libc::c_int as libc::c_uint;
        while k < 2 as libc::c_int as libc::c_uint {
            t[0 as libc::c_int as usize]
                += (*a.offset(k as isize))
                    .0
                    .coeffs[(2 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(1 as libc::c_int as libc::c_uint) as usize] as int32_t
                    * (*b_cache.offset(k as isize)).coeffs[i as usize] as libc::c_int;
            t[0 as libc::c_int as usize]
                += (*a.offset(k as isize))
                    .0
                    .coeffs[(2 as libc::c_int as libc::c_uint).wrapping_mul(i) as usize]
                    as int32_t
                    * (*b.offset(k as isize))
                        .0
                        .coeffs[(2 as libc::c_int as libc::c_uint).wrapping_mul(i)
                        as usize] as libc::c_int;
            t[1 as libc::c_int as usize]
                += (*a.offset(k as isize))
                    .0
                    .coeffs[(2 as libc::c_int as libc::c_uint).wrapping_mul(i) as usize]
                    as int32_t
                    * (*b.offset(k as isize))
                        .0
                        .coeffs[(2 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(1 as libc::c_int as libc::c_uint) as usize]
                        as libc::c_int;
            t[1 as libc::c_int as usize]
                += (*a.offset(k as isize))
                    .0
                    .coeffs[(2 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(1 as libc::c_int as libc::c_uint) as usize] as int32_t
                    * (*b.offset(k as isize))
                        .0
                        .coeffs[(2 as libc::c_int as libc::c_uint).wrapping_mul(i)
                        as usize] as libc::c_int;
            k = k.wrapping_add(1);
            k;
        }
        (*r)
            .0
            .coeffs[(2 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(0 as libc::c_int as libc::c_uint)
            as usize] = mlk_montgomery_reduce(t[0 as libc::c_int as usize]);
        (*r)
            .0
            .coeffs[(2 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(1 as libc::c_int as libc::c_uint)
            as usize] = mlk_montgomery_reduce(t[1 as libc::c_int as usize]);
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem512_polyvec_mulcache_compute(
    mut x: *mut mlk_poly_mulcache,
    mut a: *const mlk_poly,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        mlkem_poly_mulcache_compute(&mut *x.offset(i as isize), &*a.offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem512_polyvec_reduce(mut r: *mut mlk_poly) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        mlkem_poly_reduce(&mut *r.offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem512_polyvec_add(mut r: *mut mlk_poly, mut b: *const mlk_poly) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        mlkem_poly_add(&mut *r.offset(i as isize), &*b.offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem512_polyvec_tomont(mut r: *mut mlk_poly) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        mlkem_poly_tomont(&mut *r.offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
#[inline]
unsafe extern "C" fn mlk_poly_cbd_eta1512(
    mut r: *mut mlk_poly,
    mut buf: *const uint8_t,
) {
    mlkem_poly_cbd3(r, buf);
}
unsafe extern "C" fn mlkem512_poly_getnoise_eta1_4x(
    mut r0: *mut mlk_poly,
    mut r1: *mut mlk_poly,
    mut r2: *mut mlk_poly,
    mut r3: *mut mlk_poly,
    mut seed: *const uint8_t,
    mut nonce0: uint8_t,
    mut nonce1: uint8_t,
    mut nonce2: uint8_t,
    mut nonce3: uint8_t,
) {
    let mut buf: [[uint8_t; 192]; 4] = [[0; 192]; 4];
    let mut extkey: [[uint8_t; 64]; 4] = [[0; 64]; 4];
    memcpy(
        (extkey[0 as libc::c_int as usize]).as_mut_ptr() as *mut libc::c_void,
        seed as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    memcpy(
        (extkey[1 as libc::c_int as usize]).as_mut_ptr() as *mut libc::c_void,
        seed as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    memcpy(
        (extkey[2 as libc::c_int as usize]).as_mut_ptr() as *mut libc::c_void,
        seed as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    memcpy(
        (extkey[3 as libc::c_int as usize]).as_mut_ptr() as *mut libc::c_void,
        seed as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    extkey[0 as libc::c_int as usize][32 as libc::c_int as usize] = nonce0;
    extkey[1 as libc::c_int as usize][32 as libc::c_int as usize] = nonce1;
    extkey[2 as libc::c_int as usize][32 as libc::c_int as usize] = nonce2;
    extkey[3 as libc::c_int as usize][32 as libc::c_int as usize] = nonce3;
    mlk_shake256x4(
        (buf[0 as libc::c_int as usize]).as_mut_ptr(),
        (buf[1 as libc::c_int as usize]).as_mut_ptr(),
        (buf[2 as libc::c_int as usize]).as_mut_ptr(),
        (buf[3 as libc::c_int as usize]).as_mut_ptr(),
        (3 as libc::c_int * 256 as libc::c_int / 4 as libc::c_int) as size_t,
        (extkey[0 as libc::c_int as usize]).as_mut_ptr(),
        (extkey[1 as libc::c_int as usize]).as_mut_ptr(),
        (extkey[2 as libc::c_int as usize]).as_mut_ptr(),
        (extkey[3 as libc::c_int as usize]).as_mut_ptr(),
        (32 as libc::c_int + 1 as libc::c_int) as size_t,
    );
    mlk_poly_cbd_eta1512(
        r0,
        (buf[0 as libc::c_int as usize]).as_mut_ptr() as *const uint8_t,
    );
    mlk_poly_cbd_eta1512(
        r1,
        (buf[1 as libc::c_int as usize]).as_mut_ptr() as *const uint8_t,
    );
    mlk_poly_cbd_eta1512(
        r2,
        (buf[2 as libc::c_int as usize]).as_mut_ptr() as *const uint8_t,
    );
    mlk_poly_cbd_eta1512(
        r3,
        (buf[3 as libc::c_int as usize]).as_mut_ptr() as *const uint8_t,
    );
    mlk_zeroize(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[[uint8_t; 192]; 4]>() as libc::c_ulong,
    );
    mlk_zeroize(
        extkey.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[[uint8_t; 64]; 4]>() as libc::c_ulong,
    );
}
#[inline]
unsafe extern "C" fn mlk_poly_cbd_eta2512(
    mut r: *mut mlk_poly,
    mut buf: *const uint8_t,
) {
    mlkem_poly_cbd2(r, buf);
}
unsafe extern "C" fn mlkem512_poly_getnoise_eta2(
    mut r: *mut mlk_poly,
    mut seed: *const uint8_t,
    mut nonce: uint8_t,
) {
    let mut buf: [uint8_t; 128] = [0; 128];
    let mut extkey: [uint8_t; 33] = [0; 33];
    memcpy(
        extkey.as_mut_ptr() as *mut libc::c_void,
        seed as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    extkey[32 as libc::c_int as usize] = nonce;
    mlk_shake256(
        buf.as_mut_ptr(),
        (2 as libc::c_int * 256 as libc::c_int / 4 as libc::c_int) as size_t,
        extkey.as_mut_ptr(),
        (32 as libc::c_int + 1 as libc::c_int) as size_t,
    );
    mlk_poly_cbd_eta2512(r, buf.as_mut_ptr() as *const uint8_t);
    mlk_zeroize(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 128]>() as libc::c_ulong,
    );
    mlk_zeroize(
        extkey.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 33]>() as libc::c_ulong,
    );
}
unsafe extern "C" fn mlkem512_poly_getnoise_eta1122_4x(
    mut r0: *mut mlk_poly,
    mut r1: *mut mlk_poly,
    mut r2: *mut mlk_poly,
    mut r3: *mut mlk_poly,
    mut seed: *const uint8_t,
    mut nonce0: uint8_t,
    mut nonce1: uint8_t,
    mut nonce2: uint8_t,
    mut nonce3: uint8_t,
) {
    let mut buf: [[uint8_t; 192]; 4] = [[0; 192]; 4];
    let mut extkey: [[uint8_t; 64]; 4] = [[0; 64]; 4];
    memcpy(
        (extkey[0 as libc::c_int as usize]).as_mut_ptr() as *mut libc::c_void,
        seed as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    memcpy(
        (extkey[1 as libc::c_int as usize]).as_mut_ptr() as *mut libc::c_void,
        seed as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    memcpy(
        (extkey[2 as libc::c_int as usize]).as_mut_ptr() as *mut libc::c_void,
        seed as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    memcpy(
        (extkey[3 as libc::c_int as usize]).as_mut_ptr() as *mut libc::c_void,
        seed as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    extkey[0 as libc::c_int as usize][32 as libc::c_int as usize] = nonce0;
    extkey[1 as libc::c_int as usize][32 as libc::c_int as usize] = nonce1;
    extkey[2 as libc::c_int as usize][32 as libc::c_int as usize] = nonce2;
    extkey[3 as libc::c_int as usize][32 as libc::c_int as usize] = nonce3;
    mlk_shake256x4(
        (buf[0 as libc::c_int as usize]).as_mut_ptr(),
        (buf[1 as libc::c_int as usize]).as_mut_ptr(),
        (buf[2 as libc::c_int as usize]).as_mut_ptr(),
        (buf[3 as libc::c_int as usize]).as_mut_ptr(),
        (3 as libc::c_int * 256 as libc::c_int / 4 as libc::c_int) as size_t,
        (extkey[0 as libc::c_int as usize]).as_mut_ptr(),
        (extkey[1 as libc::c_int as usize]).as_mut_ptr(),
        (extkey[2 as libc::c_int as usize]).as_mut_ptr(),
        (extkey[3 as libc::c_int as usize]).as_mut_ptr(),
        (32 as libc::c_int + 1 as libc::c_int) as size_t,
    );
    mlk_poly_cbd_eta1512(
        r0,
        (buf[0 as libc::c_int as usize]).as_mut_ptr() as *const uint8_t,
    );
    mlk_poly_cbd_eta1512(
        r1,
        (buf[1 as libc::c_int as usize]).as_mut_ptr() as *const uint8_t,
    );
    mlk_poly_cbd_eta2512(
        r2,
        (buf[2 as libc::c_int as usize]).as_mut_ptr() as *const uint8_t,
    );
    mlk_poly_cbd_eta2512(
        r3,
        (buf[3 as libc::c_int as usize]).as_mut_ptr() as *const uint8_t,
    );
    mlk_zeroize(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[[uint8_t; 192]; 4]>() as libc::c_ulong,
    );
    mlk_zeroize(
        extkey.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[[uint8_t; 64]; 4]>() as libc::c_ulong,
    );
}
unsafe extern "C" fn mlkem768_polyvec_compress_du(
    mut r: *mut uint8_t,
    mut a: *const mlk_poly,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 3 as libc::c_int as libc::c_uint {
        mlkem768_poly_compress_du(
            r.offset(i.wrapping_mul(320 as libc::c_int as libc::c_uint) as isize),
            &*a.offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem768_polyvec_decompress_du(
    mut r: *mut mlk_poly,
    mut a: *const uint8_t,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 3 as libc::c_int as libc::c_uint {
        mlkem768_poly_decompress_du(
            &mut *r.offset(i as isize),
            a.offset(i.wrapping_mul(320 as libc::c_int as libc::c_uint) as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem768_polyvec_tobytes(
    mut r: *mut uint8_t,
    mut a: *const mlk_poly,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 3 as libc::c_int as libc::c_uint {
        mlkem_poly_tobytes(
            r.offset(i.wrapping_mul(384 as libc::c_int as libc::c_uint) as isize),
            &*a.offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem768_polyvec_frombytes(
    mut r: *mut mlk_poly,
    mut a: *const uint8_t,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 3 as libc::c_int as libc::c_uint {
        mlkem_poly_frombytes(
            &mut *r.offset(i as isize),
            a.offset(i.wrapping_mul(384 as libc::c_int as libc::c_uint) as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem768_polyvec_ntt(mut r: *mut mlk_poly) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 3 as libc::c_int as libc::c_uint {
        mlkem_poly_ntt(&mut *r.offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem768_polyvec_invntt_tomont(mut r: *mut mlk_poly) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 3 as libc::c_int as libc::c_uint {
        mlkem_poly_invntt_tomont(&mut *r.offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem768_polyvec_basemul_acc_montgomery_cached(
    mut r: *mut mlk_poly,
    mut a: *const mlk_poly,
    mut b: *const mlk_poly,
    mut b_cache: *const mlk_poly_mulcache,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 2 as libc::c_int) as libc::c_uint {
        let mut k: libc::c_uint = 0;
        let mut t: [int32_t; 2] = [0 as libc::c_int, 0];
        k = 0 as libc::c_int as libc::c_uint;
        while k < 3 as libc::c_int as libc::c_uint {
            t[0 as libc::c_int as usize]
                += (*a.offset(k as isize))
                    .0
                    .coeffs[(2 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(1 as libc::c_int as libc::c_uint) as usize] as int32_t
                    * (*b_cache.offset(k as isize)).coeffs[i as usize] as libc::c_int;
            t[0 as libc::c_int as usize]
                += (*a.offset(k as isize))
                    .0
                    .coeffs[(2 as libc::c_int as libc::c_uint).wrapping_mul(i) as usize]
                    as int32_t
                    * (*b.offset(k as isize))
                        .0
                        .coeffs[(2 as libc::c_int as libc::c_uint).wrapping_mul(i)
                        as usize] as libc::c_int;
            t[1 as libc::c_int as usize]
                += (*a.offset(k as isize))
                    .0
                    .coeffs[(2 as libc::c_int as libc::c_uint).wrapping_mul(i) as usize]
                    as int32_t
                    * (*b.offset(k as isize))
                        .0
                        .coeffs[(2 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(1 as libc::c_int as libc::c_uint) as usize]
                        as libc::c_int;
            t[1 as libc::c_int as usize]
                += (*a.offset(k as isize))
                    .0
                    .coeffs[(2 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(1 as libc::c_int as libc::c_uint) as usize] as int32_t
                    * (*b.offset(k as isize))
                        .0
                        .coeffs[(2 as libc::c_int as libc::c_uint).wrapping_mul(i)
                        as usize] as libc::c_int;
            k = k.wrapping_add(1);
            k;
        }
        (*r)
            .0
            .coeffs[(2 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(0 as libc::c_int as libc::c_uint)
            as usize] = mlk_montgomery_reduce(t[0 as libc::c_int as usize]);
        (*r)
            .0
            .coeffs[(2 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(1 as libc::c_int as libc::c_uint)
            as usize] = mlk_montgomery_reduce(t[1 as libc::c_int as usize]);
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem768_polyvec_mulcache_compute(
    mut x: *mut mlk_poly_mulcache,
    mut a: *const mlk_poly,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 3 as libc::c_int as libc::c_uint {
        mlkem_poly_mulcache_compute(&mut *x.offset(i as isize), &*a.offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem768_polyvec_reduce(mut r: *mut mlk_poly) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 3 as libc::c_int as libc::c_uint {
        mlkem_poly_reduce(&mut *r.offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem768_polyvec_add(mut r: *mut mlk_poly, mut b: *const mlk_poly) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 3 as libc::c_int as libc::c_uint {
        mlkem_poly_add(&mut *r.offset(i as isize), &*b.offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem768_polyvec_tomont(mut r: *mut mlk_poly) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 3 as libc::c_int as libc::c_uint {
        mlkem_poly_tomont(&mut *r.offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
#[inline]
unsafe extern "C" fn mlk_poly_cbd_eta1768(
    mut r: *mut mlk_poly,
    mut buf: *const uint8_t,
) {
    mlkem_poly_cbd2(r, buf);
}
unsafe extern "C" fn mlkem768_poly_getnoise_eta1_4x(
    mut r0: *mut mlk_poly,
    mut r1: *mut mlk_poly,
    mut r2: *mut mlk_poly,
    mut r3: *mut mlk_poly,
    mut seed: *const uint8_t,
    mut nonce0: uint8_t,
    mut nonce1: uint8_t,
    mut nonce2: uint8_t,
    mut nonce3: uint8_t,
) {
    let mut buf: [[uint8_t; 128]; 4] = [[0; 128]; 4];
    let mut extkey: [[uint8_t; 64]; 4] = [[0; 64]; 4];
    memcpy(
        (extkey[0 as libc::c_int as usize]).as_mut_ptr() as *mut libc::c_void,
        seed as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    memcpy(
        (extkey[1 as libc::c_int as usize]).as_mut_ptr() as *mut libc::c_void,
        seed as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    memcpy(
        (extkey[2 as libc::c_int as usize]).as_mut_ptr() as *mut libc::c_void,
        seed as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    memcpy(
        (extkey[3 as libc::c_int as usize]).as_mut_ptr() as *mut libc::c_void,
        seed as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    extkey[0 as libc::c_int as usize][32 as libc::c_int as usize] = nonce0;
    extkey[1 as libc::c_int as usize][32 as libc::c_int as usize] = nonce1;
    extkey[2 as libc::c_int as usize][32 as libc::c_int as usize] = nonce2;
    extkey[3 as libc::c_int as usize][32 as libc::c_int as usize] = nonce3;
    mlk_shake256x4(
        (buf[0 as libc::c_int as usize]).as_mut_ptr(),
        (buf[1 as libc::c_int as usize]).as_mut_ptr(),
        (buf[2 as libc::c_int as usize]).as_mut_ptr(),
        (buf[3 as libc::c_int as usize]).as_mut_ptr(),
        (2 as libc::c_int * 256 as libc::c_int / 4 as libc::c_int) as size_t,
        (extkey[0 as libc::c_int as usize]).as_mut_ptr(),
        (extkey[1 as libc::c_int as usize]).as_mut_ptr(),
        (extkey[2 as libc::c_int as usize]).as_mut_ptr(),
        (extkey[3 as libc::c_int as usize]).as_mut_ptr(),
        (32 as libc::c_int + 1 as libc::c_int) as size_t,
    );
    mlk_poly_cbd_eta1768(
        r0,
        (buf[0 as libc::c_int as usize]).as_mut_ptr() as *const uint8_t,
    );
    mlk_poly_cbd_eta1768(
        r1,
        (buf[1 as libc::c_int as usize]).as_mut_ptr() as *const uint8_t,
    );
    mlk_poly_cbd_eta1768(
        r2,
        (buf[2 as libc::c_int as usize]).as_mut_ptr() as *const uint8_t,
    );
    mlk_poly_cbd_eta1768(
        r3,
        (buf[3 as libc::c_int as usize]).as_mut_ptr() as *const uint8_t,
    );
    mlk_zeroize(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[[uint8_t; 128]; 4]>() as libc::c_ulong,
    );
    mlk_zeroize(
        extkey.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[[uint8_t; 64]; 4]>() as libc::c_ulong,
    );
}
unsafe extern "C" fn mlkem1024_polyvec_compress_du(
    mut r: *mut uint8_t,
    mut a: *const mlk_poly,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 4 as libc::c_int as libc::c_uint {
        mlkem1024_poly_compress_du(
            r.offset(i.wrapping_mul(352 as libc::c_int as libc::c_uint) as isize),
            &*a.offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem1024_polyvec_decompress_du(
    mut r: *mut mlk_poly,
    mut a: *const uint8_t,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 4 as libc::c_int as libc::c_uint {
        mlkem1024_poly_decompress_du(
            &mut *r.offset(i as isize),
            a.offset(i.wrapping_mul(352 as libc::c_int as libc::c_uint) as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem1024_polyvec_tobytes(
    mut r: *mut uint8_t,
    mut a: *const mlk_poly,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 4 as libc::c_int as libc::c_uint {
        mlkem_poly_tobytes(
            r.offset(i.wrapping_mul(384 as libc::c_int as libc::c_uint) as isize),
            &*a.offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem1024_polyvec_frombytes(
    mut r: *mut mlk_poly,
    mut a: *const uint8_t,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 4 as libc::c_int as libc::c_uint {
        mlkem_poly_frombytes(
            &mut *r.offset(i as isize),
            a.offset(i.wrapping_mul(384 as libc::c_int as libc::c_uint) as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem1024_polyvec_ntt(mut r: *mut mlk_poly) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 4 as libc::c_int as libc::c_uint {
        mlkem_poly_ntt(&mut *r.offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem1024_polyvec_invntt_tomont(mut r: *mut mlk_poly) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 4 as libc::c_int as libc::c_uint {
        mlkem_poly_invntt_tomont(&mut *r.offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem1024_polyvec_basemul_acc_montgomery_cached(
    mut r: *mut mlk_poly,
    mut a: *const mlk_poly,
    mut b: *const mlk_poly,
    mut b_cache: *const mlk_poly_mulcache,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 2 as libc::c_int) as libc::c_uint {
        let mut k: libc::c_uint = 0;
        let mut t: [int32_t; 2] = [0 as libc::c_int, 0];
        k = 0 as libc::c_int as libc::c_uint;
        while k < 4 as libc::c_int as libc::c_uint {
            t[0 as libc::c_int as usize]
                += (*a.offset(k as isize))
                    .0
                    .coeffs[(2 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(1 as libc::c_int as libc::c_uint) as usize] as int32_t
                    * (*b_cache.offset(k as isize)).coeffs[i as usize] as libc::c_int;
            t[0 as libc::c_int as usize]
                += (*a.offset(k as isize))
                    .0
                    .coeffs[(2 as libc::c_int as libc::c_uint).wrapping_mul(i) as usize]
                    as int32_t
                    * (*b.offset(k as isize))
                        .0
                        .coeffs[(2 as libc::c_int as libc::c_uint).wrapping_mul(i)
                        as usize] as libc::c_int;
            t[1 as libc::c_int as usize]
                += (*a.offset(k as isize))
                    .0
                    .coeffs[(2 as libc::c_int as libc::c_uint).wrapping_mul(i) as usize]
                    as int32_t
                    * (*b.offset(k as isize))
                        .0
                        .coeffs[(2 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(1 as libc::c_int as libc::c_uint) as usize]
                        as libc::c_int;
            t[1 as libc::c_int as usize]
                += (*a.offset(k as isize))
                    .0
                    .coeffs[(2 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(1 as libc::c_int as libc::c_uint) as usize] as int32_t
                    * (*b.offset(k as isize))
                        .0
                        .coeffs[(2 as libc::c_int as libc::c_uint).wrapping_mul(i)
                        as usize] as libc::c_int;
            k = k.wrapping_add(1);
            k;
        }
        (*r)
            .0
            .coeffs[(2 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(0 as libc::c_int as libc::c_uint)
            as usize] = mlk_montgomery_reduce(t[0 as libc::c_int as usize]);
        (*r)
            .0
            .coeffs[(2 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(1 as libc::c_int as libc::c_uint)
            as usize] = mlk_montgomery_reduce(t[1 as libc::c_int as usize]);
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem1024_polyvec_mulcache_compute(
    mut x: *mut mlk_poly_mulcache,
    mut a: *const mlk_poly,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 4 as libc::c_int as libc::c_uint {
        mlkem_poly_mulcache_compute(&mut *x.offset(i as isize), &*a.offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem1024_polyvec_reduce(mut r: *mut mlk_poly) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 4 as libc::c_int as libc::c_uint {
        mlkem_poly_reduce(&mut *r.offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem1024_polyvec_add(
    mut r: *mut mlk_poly,
    mut b: *const mlk_poly,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 4 as libc::c_int as libc::c_uint {
        mlkem_poly_add(&mut *r.offset(i as isize), &*b.offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem1024_polyvec_tomont(mut r: *mut mlk_poly) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 4 as libc::c_int as libc::c_uint {
        mlkem_poly_tomont(&mut *r.offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
#[inline]
unsafe extern "C" fn mlk_poly_cbd_eta11024(
    mut r: *mut mlk_poly,
    mut buf: *const uint8_t,
) {
    mlkem_poly_cbd2(r, buf);
}
unsafe extern "C" fn mlkem1024_poly_getnoise_eta1_4x(
    mut r0: *mut mlk_poly,
    mut r1: *mut mlk_poly,
    mut r2: *mut mlk_poly,
    mut r3: *mut mlk_poly,
    mut seed: *const uint8_t,
    mut nonce0: uint8_t,
    mut nonce1: uint8_t,
    mut nonce2: uint8_t,
    mut nonce3: uint8_t,
) {
    let mut buf: [[uint8_t; 128]; 4] = [[0; 128]; 4];
    let mut extkey: [[uint8_t; 64]; 4] = [[0; 64]; 4];
    memcpy(
        (extkey[0 as libc::c_int as usize]).as_mut_ptr() as *mut libc::c_void,
        seed as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    memcpy(
        (extkey[1 as libc::c_int as usize]).as_mut_ptr() as *mut libc::c_void,
        seed as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    memcpy(
        (extkey[2 as libc::c_int as usize]).as_mut_ptr() as *mut libc::c_void,
        seed as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    memcpy(
        (extkey[3 as libc::c_int as usize]).as_mut_ptr() as *mut libc::c_void,
        seed as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    extkey[0 as libc::c_int as usize][32 as libc::c_int as usize] = nonce0;
    extkey[1 as libc::c_int as usize][32 as libc::c_int as usize] = nonce1;
    extkey[2 as libc::c_int as usize][32 as libc::c_int as usize] = nonce2;
    extkey[3 as libc::c_int as usize][32 as libc::c_int as usize] = nonce3;
    mlk_shake256x4(
        (buf[0 as libc::c_int as usize]).as_mut_ptr(),
        (buf[1 as libc::c_int as usize]).as_mut_ptr(),
        (buf[2 as libc::c_int as usize]).as_mut_ptr(),
        (buf[3 as libc::c_int as usize]).as_mut_ptr(),
        (2 as libc::c_int * 256 as libc::c_int / 4 as libc::c_int) as size_t,
        (extkey[0 as libc::c_int as usize]).as_mut_ptr(),
        (extkey[1 as libc::c_int as usize]).as_mut_ptr(),
        (extkey[2 as libc::c_int as usize]).as_mut_ptr(),
        (extkey[3 as libc::c_int as usize]).as_mut_ptr(),
        (32 as libc::c_int + 1 as libc::c_int) as size_t,
    );
    mlk_poly_cbd_eta11024(
        r0,
        (buf[0 as libc::c_int as usize]).as_mut_ptr() as *const uint8_t,
    );
    mlk_poly_cbd_eta11024(
        r1,
        (buf[1 as libc::c_int as usize]).as_mut_ptr() as *const uint8_t,
    );
    mlk_poly_cbd_eta11024(
        r2,
        (buf[2 as libc::c_int as usize]).as_mut_ptr() as *const uint8_t,
    );
    mlk_poly_cbd_eta11024(
        r3,
        (buf[3 as libc::c_int as usize]).as_mut_ptr() as *const uint8_t,
    );
    mlk_zeroize(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[[uint8_t; 128]; 4]>() as libc::c_ulong,
    );
    mlk_zeroize(
        extkey.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[[uint8_t; 64]; 4]>() as libc::c_ulong,
    );
}
#[inline]
unsafe extern "C" fn mlk_poly_cbd_eta21024(
    mut r: *mut mlk_poly,
    mut buf: *const uint8_t,
) {
    mlkem_poly_cbd2(r, buf);
}
unsafe extern "C" fn mlkem1024_poly_getnoise_eta2(
    mut r: *mut mlk_poly,
    mut seed: *const uint8_t,
    mut nonce: uint8_t,
) {
    let mut buf: [uint8_t; 128] = [0; 128];
    let mut extkey: [uint8_t; 33] = [0; 33];
    memcpy(
        extkey.as_mut_ptr() as *mut libc::c_void,
        seed as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    extkey[32 as libc::c_int as usize] = nonce;
    mlk_shake256(
        buf.as_mut_ptr(),
        (2 as libc::c_int * 256 as libc::c_int / 4 as libc::c_int) as size_t,
        extkey.as_mut_ptr(),
        (32 as libc::c_int + 1 as libc::c_int) as size_t,
    );
    mlk_poly_cbd_eta21024(r, buf.as_mut_ptr() as *const uint8_t);
    mlk_zeroize(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 128]>() as libc::c_ulong,
    );
    mlk_zeroize(
        extkey.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 33]>() as libc::c_ulong,
    );
}
unsafe extern "C" fn mlk_pack_pk512(
    mut r: *mut uint8_t,
    mut pk: *mut mlk_poly,
    mut seed: *const uint8_t,
) {
    mlkem512_polyvec_tobytes(r, pk as *const mlk_poly);
    memcpy(
        r.offset((2 as libc::c_int * 384 as libc::c_int) as isize) as *mut libc::c_void,
        seed as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
}
unsafe extern "C" fn mlk_unpack_pk512(
    mut pk: *mut mlk_poly,
    mut seed: *mut uint8_t,
    mut packedpk: *const uint8_t,
) {
    mlkem512_polyvec_frombytes(pk, packedpk);
    memcpy(
        seed as *mut libc::c_void,
        packedpk.offset((2 as libc::c_int * 384 as libc::c_int) as isize)
            as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
}
unsafe extern "C" fn mlk_pack_sk512(mut r: *mut uint8_t, mut sk: *mut mlk_poly) {
    mlkem512_polyvec_tobytes(r, sk as *const mlk_poly);
}
unsafe extern "C" fn mlk_unpack_sk512(
    mut sk: *mut mlk_poly,
    mut packedsk: *const uint8_t,
) {
    mlkem512_polyvec_frombytes(sk, packedsk);
}
unsafe extern "C" fn mlk_pack_ciphertext512(
    mut r: *mut uint8_t,
    mut b: *mut mlk_poly,
    mut v: *mut mlk_poly,
) {
    mlkem512_polyvec_compress_du(r, b as *const mlk_poly);
    mlkem512_poly_compress_dv(
        r.offset((2 as libc::c_int * 320 as libc::c_int) as isize),
        v,
    );
}
unsafe extern "C" fn mlk_unpack_ciphertext512(
    mut b: *mut mlk_poly,
    mut v: *mut mlk_poly,
    mut c: *const uint8_t,
) {
    mlkem512_polyvec_decompress_du(b, c);
    mlkem512_poly_decompress_dv(
        v,
        c.offset((2 as libc::c_int * 320 as libc::c_int) as isize),
    );
}
#[inline]
unsafe extern "C" fn mlk_poly_permute_bitrev_to_custom512(mut data: *mut int16_t) {}
unsafe extern "C" fn mlkem512_gen_matrix(
    mut a: *mut mlk_poly,
    mut seed: *const uint8_t,
    mut transposed: libc::c_int,
) {
    let mut i: libc::c_uint = 0;
    let mut j: libc::c_uint = 0;
    let mut seed_ext: [[uint8_t; 64]; 4] = [[0; 64]; 4];
    j = 0 as libc::c_int as libc::c_uint;
    while j < 4 as libc::c_int as libc::c_uint {
        memcpy(
            (seed_ext[j as usize]).as_mut_ptr() as *mut libc::c_void,
            seed as *const libc::c_void,
            32 as libc::c_int as libc::c_ulong,
        );
        j = j.wrapping_add(1);
        j;
    }
    i = 0 as libc::c_int as libc::c_uint;
    while i
        < (2 as libc::c_int * 2 as libc::c_int / 4 as libc::c_int * 4 as libc::c_int)
            as libc::c_uint
    {
        let mut x: uint8_t = 0;
        let mut y: uint8_t = 0;
        j = 0 as libc::c_int as libc::c_uint;
        while j < 4 as libc::c_int as libc::c_uint {
            x = i.wrapping_add(j).wrapping_div(2 as libc::c_int as libc::c_uint)
                as uint8_t;
            y = i.wrapping_add(j).wrapping_rem(2 as libc::c_int as libc::c_uint)
                as uint8_t;
            if transposed != 0 {
                seed_ext[j
                    as usize][(32 as libc::c_int + 0 as libc::c_int) as usize] = x;
                seed_ext[j
                    as usize][(32 as libc::c_int + 1 as libc::c_int) as usize] = y;
            } else {
                seed_ext[j
                    as usize][(32 as libc::c_int + 0 as libc::c_int) as usize] = y;
                seed_ext[j
                    as usize][(32 as libc::c_int + 1 as libc::c_int) as usize] = x;
            }
            j = j.wrapping_add(1);
            j;
        }
        mlkem_poly_rej_uniform_x4(&mut *a.offset(i as isize), seed_ext.as_mut_ptr());
        i = i.wrapping_add(4 as libc::c_int as libc::c_uint);
    }
    if i < (2 as libc::c_int * 2 as libc::c_int) as libc::c_uint {
        let mut x_0: uint8_t = 0;
        let mut y_0: uint8_t = 0;
        x_0 = i.wrapping_div(2 as libc::c_int as libc::c_uint) as uint8_t;
        y_0 = i.wrapping_rem(2 as libc::c_int as libc::c_uint) as uint8_t;
        if transposed != 0 {
            seed_ext[0 as libc::c_int
                as usize][(32 as libc::c_int + 0 as libc::c_int) as usize] = x_0;
            seed_ext[0 as libc::c_int
                as usize][(32 as libc::c_int + 1 as libc::c_int) as usize] = y_0;
        } else {
            seed_ext[0 as libc::c_int
                as usize][(32 as libc::c_int + 0 as libc::c_int) as usize] = y_0;
            seed_ext[0 as libc::c_int
                as usize][(32 as libc::c_int + 1 as libc::c_int) as usize] = x_0;
        }
        mlkem_poly_rej_uniform(
            &mut *a.offset(i as isize),
            (seed_ext[0 as libc::c_int as usize]).as_mut_ptr(),
        );
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as libc::c_uint;
    while i < (2 as libc::c_int * 2 as libc::c_int) as libc::c_uint {
        mlk_poly_permute_bitrev_to_custom512(
            ((*a.offset(i as isize)).0.coeffs).as_mut_ptr(),
        );
        i = i.wrapping_add(1);
        i;
    }
    mlk_zeroize(
        seed_ext.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[[uint8_t; 64]; 4]>() as libc::c_ulong,
    );
}
unsafe extern "C" fn mlk_matvec_mul512(
    mut out: *mut mlk_poly,
    mut a: *const mlk_poly,
    mut v: *const mlk_poly,
    mut vc: *const mlk_poly_mulcache,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        mlkem512_polyvec_basemul_acc_montgomery_cached(
            &mut *out.offset(i as isize),
            &*a.offset((2 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize),
            v,
            vc,
        );
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem512_indcpa_keypair_derand(
    mut pk: *mut uint8_t,
    mut sk: *mut uint8_t,
    mut coins: *const uint8_t,
) {
    let mut buf: [uint8_t; 64] = [0; 64];
    let mut publicseed: *const uint8_t = buf.as_mut_ptr();
    let mut noiseseed: *const uint8_t = buf
        .as_mut_ptr()
        .offset(32 as libc::c_int as isize);
    let mut a: mlk_polymat512 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 4];
    let mut e: mlk_polyvec512 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 2];
    let mut pkpv: mlk_polyvec512 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 2];
    let mut skpv: mlk_polyvec512 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 2];
    let mut skpv_cache: mlk_polyvec_mulcache512 = [mlk_poly_mulcache {
        coeffs: [0; 128],
    }; 2];
    let mut coins_with_domain_separator: [uint8_t; 33] = [0; 33];
    memcpy(
        coins_with_domain_separator.as_mut_ptr() as *mut libc::c_void,
        coins as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    coins_with_domain_separator[32 as libc::c_int
        as usize] = 2 as libc::c_int as uint8_t;
    mlk_sha3_512(
        buf.as_mut_ptr(),
        coins_with_domain_separator.as_mut_ptr(),
        (32 as libc::c_int + 1 as libc::c_int) as size_t,
    );
    mlkem512_gen_matrix(a.as_mut_ptr(), publicseed, 0 as libc::c_int);
    mlkem512_poly_getnoise_eta1_4x(
        &mut *skpv.as_mut_ptr().offset(0 as libc::c_int as isize),
        &mut *skpv.as_mut_ptr().offset(1 as libc::c_int as isize),
        &mut *e.as_mut_ptr().offset(0 as libc::c_int as isize),
        &mut *e.as_mut_ptr().offset(1 as libc::c_int as isize),
        noiseseed,
        0 as libc::c_int as uint8_t,
        1 as libc::c_int as uint8_t,
        2 as libc::c_int as uint8_t,
        3 as libc::c_int as uint8_t,
    );
    mlkem512_polyvec_ntt(skpv.as_mut_ptr());
    mlkem512_polyvec_ntt(e.as_mut_ptr());
    mlkem512_polyvec_mulcache_compute(
        skpv_cache.as_mut_ptr(),
        skpv.as_mut_ptr() as *const mlk_poly,
    );
    mlk_matvec_mul512(
        pkpv.as_mut_ptr(),
        a.as_mut_ptr() as *const mlk_poly,
        skpv.as_mut_ptr() as *const mlk_poly,
        skpv_cache.as_mut_ptr() as *const mlk_poly_mulcache,
    );
    mlkem512_polyvec_tomont(pkpv.as_mut_ptr());
    mlkem512_polyvec_add(pkpv.as_mut_ptr(), e.as_mut_ptr() as *const mlk_poly);
    mlkem512_polyvec_reduce(pkpv.as_mut_ptr());
    mlkem512_polyvec_reduce(skpv.as_mut_ptr());
    mlk_pack_sk512(sk, skpv.as_mut_ptr());
    mlk_pack_pk512(pk, pkpv.as_mut_ptr(), publicseed);
    mlk_zeroize(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    mlk_zeroize(
        coins_with_domain_separator.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 33]>() as libc::c_ulong,
    );
    mlk_zeroize(
        a.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polymat512>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut e as *mut mlk_polyvec512 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec512>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut skpv as *mut mlk_polyvec512 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec512>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut skpv_cache as *mut mlk_polyvec_mulcache512 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec_mulcache512>() as libc::c_ulong,
    );
}
unsafe extern "C" fn mlkem512_indcpa_enc(
    mut c: *mut uint8_t,
    mut m: *const uint8_t,
    mut pk: *const uint8_t,
    mut coins: *const uint8_t,
) {
    let mut seed: [uint8_t; 32] = [0; 32];
    let mut at: mlk_polymat512 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 4];
    let mut sp: mlk_polyvec512 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 2];
    let mut pkpv: mlk_polyvec512 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 2];
    let mut ep: mlk_polyvec512 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 2];
    let mut b: mlk_polyvec512 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 2];
    let mut v: mlk_poly = mlk_poly(mlk_poly_Inner { coeffs: [0; 256] });
    let mut k: mlk_poly = mlk_poly(mlk_poly_Inner { coeffs: [0; 256] });
    let mut epp: mlk_poly = mlk_poly(mlk_poly_Inner { coeffs: [0; 256] });
    let mut sp_cache: mlk_polyvec_mulcache512 = [mlk_poly_mulcache {
        coeffs: [0; 128],
    }; 2];
    mlk_unpack_pk512(pkpv.as_mut_ptr(), seed.as_mut_ptr(), pk);
    mlkem_poly_frommsg(&mut k, m);
    mlkem512_gen_matrix(
        at.as_mut_ptr(),
        seed.as_mut_ptr() as *const uint8_t,
        1 as libc::c_int,
    );
    mlkem512_poly_getnoise_eta1122_4x(
        &mut *sp.as_mut_ptr().offset(0 as libc::c_int as isize),
        &mut *sp.as_mut_ptr().offset(1 as libc::c_int as isize),
        &mut *ep.as_mut_ptr().offset(0 as libc::c_int as isize),
        &mut *ep.as_mut_ptr().offset(1 as libc::c_int as isize),
        coins,
        0 as libc::c_int as uint8_t,
        1 as libc::c_int as uint8_t,
        2 as libc::c_int as uint8_t,
        3 as libc::c_int as uint8_t,
    );
    mlkem512_poly_getnoise_eta2(&mut epp, coins, 4 as libc::c_int as uint8_t);
    mlkem512_polyvec_ntt(sp.as_mut_ptr());
    mlkem512_polyvec_mulcache_compute(
        sp_cache.as_mut_ptr(),
        sp.as_mut_ptr() as *const mlk_poly,
    );
    mlk_matvec_mul512(
        b.as_mut_ptr(),
        at.as_mut_ptr() as *const mlk_poly,
        sp.as_mut_ptr() as *const mlk_poly,
        sp_cache.as_mut_ptr() as *const mlk_poly_mulcache,
    );
    mlkem512_polyvec_basemul_acc_montgomery_cached(
        &mut v,
        pkpv.as_mut_ptr() as *const mlk_poly,
        sp.as_mut_ptr() as *const mlk_poly,
        sp_cache.as_mut_ptr() as *const mlk_poly_mulcache,
    );
    mlkem512_polyvec_invntt_tomont(b.as_mut_ptr());
    mlkem_poly_invntt_tomont(&mut v);
    mlkem512_polyvec_add(b.as_mut_ptr(), ep.as_mut_ptr() as *const mlk_poly);
    mlkem_poly_add(&mut v, &mut epp);
    mlkem_poly_add(&mut v, &mut k);
    mlkem512_polyvec_reduce(b.as_mut_ptr());
    mlkem_poly_reduce(&mut v);
    mlk_pack_ciphertext512(c, b.as_mut_ptr(), &mut v);
    mlk_zeroize(
        seed.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut sp as *mut mlk_polyvec512 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec512>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut sp_cache as *mut mlk_polyvec_mulcache512 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec_mulcache512>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut b as *mut mlk_polyvec512 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec512>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut v as *mut mlk_poly as *mut libc::c_void,
        ::core::mem::size_of::<mlk_poly>() as libc::c_ulong,
    );
    mlk_zeroize(
        at.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polymat512>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut k as *mut mlk_poly as *mut libc::c_void,
        ::core::mem::size_of::<mlk_poly>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut ep as *mut mlk_polyvec512 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec512>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut epp as *mut mlk_poly as *mut libc::c_void,
        ::core::mem::size_of::<mlk_poly>() as libc::c_ulong,
    );
}
unsafe extern "C" fn mlkem512_indcpa_dec(
    mut m: *mut uint8_t,
    mut c: *const uint8_t,
    mut sk: *const uint8_t,
) {
    let mut b: mlk_polyvec512 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 2];
    let mut skpv: mlk_polyvec512 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 2];
    let mut v: mlk_poly = mlk_poly(mlk_poly_Inner { coeffs: [0; 256] });
    let mut sb: mlk_poly = mlk_poly(mlk_poly_Inner { coeffs: [0; 256] });
    let mut b_cache: mlk_polyvec_mulcache512 = [mlk_poly_mulcache {
        coeffs: [0; 128],
    }; 2];
    mlk_unpack_ciphertext512(b.as_mut_ptr(), &mut v, c);
    mlk_unpack_sk512(skpv.as_mut_ptr(), sk);
    mlkem512_polyvec_ntt(b.as_mut_ptr());
    mlkem512_polyvec_mulcache_compute(
        b_cache.as_mut_ptr(),
        b.as_mut_ptr() as *const mlk_poly,
    );
    mlkem512_polyvec_basemul_acc_montgomery_cached(
        &mut sb,
        skpv.as_mut_ptr() as *const mlk_poly,
        b.as_mut_ptr() as *const mlk_poly,
        b_cache.as_mut_ptr() as *const mlk_poly_mulcache,
    );
    mlkem_poly_invntt_tomont(&mut sb);
    mlkem_poly_sub(&mut v, &mut sb);
    mlkem_poly_reduce(&mut v);
    mlkem_poly_tomsg(m, &mut v);
    mlk_zeroize(
        &mut skpv as *mut mlk_polyvec512 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec512>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut b as *mut mlk_polyvec512 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec512>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut b_cache as *mut mlk_polyvec_mulcache512 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec_mulcache512>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut v as *mut mlk_poly as *mut libc::c_void,
        ::core::mem::size_of::<mlk_poly>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut sb as *mut mlk_poly as *mut libc::c_void,
        ::core::mem::size_of::<mlk_poly>() as libc::c_ulong,
    );
}
unsafe extern "C" fn mlk_pack_pk768(
    mut r: *mut uint8_t,
    mut pk: *mut mlk_poly,
    mut seed: *const uint8_t,
) {
    mlkem768_polyvec_tobytes(r, pk as *const mlk_poly);
    memcpy(
        r.offset((3 as libc::c_int * 384 as libc::c_int) as isize) as *mut libc::c_void,
        seed as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
}
unsafe extern "C" fn mlk_unpack_pk768(
    mut pk: *mut mlk_poly,
    mut seed: *mut uint8_t,
    mut packedpk: *const uint8_t,
) {
    mlkem768_polyvec_frombytes(pk, packedpk);
    memcpy(
        seed as *mut libc::c_void,
        packedpk.offset((3 as libc::c_int * 384 as libc::c_int) as isize)
            as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
}
unsafe extern "C" fn mlk_pack_sk768(mut r: *mut uint8_t, mut sk: *mut mlk_poly) {
    mlkem768_polyvec_tobytes(r, sk as *const mlk_poly);
}
unsafe extern "C" fn mlk_unpack_sk768(
    mut sk: *mut mlk_poly,
    mut packedsk: *const uint8_t,
) {
    mlkem768_polyvec_frombytes(sk, packedsk);
}
unsafe extern "C" fn mlk_pack_ciphertext768(
    mut r: *mut uint8_t,
    mut b: *mut mlk_poly,
    mut v: *mut mlk_poly,
) {
    mlkem768_polyvec_compress_du(r, b as *const mlk_poly);
    mlkem768_poly_compress_dv(
        r.offset((3 as libc::c_int * 320 as libc::c_int) as isize),
        v,
    );
}
unsafe extern "C" fn mlk_unpack_ciphertext768(
    mut b: *mut mlk_poly,
    mut v: *mut mlk_poly,
    mut c: *const uint8_t,
) {
    mlkem768_polyvec_decompress_du(b, c);
    mlkem768_poly_decompress_dv(
        v,
        c.offset((3 as libc::c_int * 320 as libc::c_int) as isize),
    );
}
#[inline]
unsafe extern "C" fn mlk_poly_permute_bitrev_to_custom768(mut data: *mut int16_t) {}
unsafe extern "C" fn mlkem768_gen_matrix(
    mut a: *mut mlk_poly,
    mut seed: *const uint8_t,
    mut transposed: libc::c_int,
) {
    let mut i: libc::c_uint = 0;
    let mut j: libc::c_uint = 0;
    let mut seed_ext: [[uint8_t; 64]; 4] = [[0; 64]; 4];
    j = 0 as libc::c_int as libc::c_uint;
    while j < 4 as libc::c_int as libc::c_uint {
        memcpy(
            (seed_ext[j as usize]).as_mut_ptr() as *mut libc::c_void,
            seed as *const libc::c_void,
            32 as libc::c_int as libc::c_ulong,
        );
        j = j.wrapping_add(1);
        j;
    }
    i = 0 as libc::c_int as libc::c_uint;
    while i
        < (3 as libc::c_int * 3 as libc::c_int / 4 as libc::c_int * 4 as libc::c_int)
            as libc::c_uint
    {
        let mut x: uint8_t = 0;
        let mut y: uint8_t = 0;
        j = 0 as libc::c_int as libc::c_uint;
        while j < 4 as libc::c_int as libc::c_uint {
            x = i.wrapping_add(j).wrapping_div(3 as libc::c_int as libc::c_uint)
                as uint8_t;
            y = i.wrapping_add(j).wrapping_rem(3 as libc::c_int as libc::c_uint)
                as uint8_t;
            if transposed != 0 {
                seed_ext[j
                    as usize][(32 as libc::c_int + 0 as libc::c_int) as usize] = x;
                seed_ext[j
                    as usize][(32 as libc::c_int + 1 as libc::c_int) as usize] = y;
            } else {
                seed_ext[j
                    as usize][(32 as libc::c_int + 0 as libc::c_int) as usize] = y;
                seed_ext[j
                    as usize][(32 as libc::c_int + 1 as libc::c_int) as usize] = x;
            }
            j = j.wrapping_add(1);
            j;
        }
        mlkem_poly_rej_uniform_x4(&mut *a.offset(i as isize), seed_ext.as_mut_ptr());
        i = i.wrapping_add(4 as libc::c_int as libc::c_uint);
    }
    if i < (3 as libc::c_int * 3 as libc::c_int) as libc::c_uint {
        let mut x_0: uint8_t = 0;
        let mut y_0: uint8_t = 0;
        x_0 = i.wrapping_div(3 as libc::c_int as libc::c_uint) as uint8_t;
        y_0 = i.wrapping_rem(3 as libc::c_int as libc::c_uint) as uint8_t;
        if transposed != 0 {
            seed_ext[0 as libc::c_int
                as usize][(32 as libc::c_int + 0 as libc::c_int) as usize] = x_0;
            seed_ext[0 as libc::c_int
                as usize][(32 as libc::c_int + 1 as libc::c_int) as usize] = y_0;
        } else {
            seed_ext[0 as libc::c_int
                as usize][(32 as libc::c_int + 0 as libc::c_int) as usize] = y_0;
            seed_ext[0 as libc::c_int
                as usize][(32 as libc::c_int + 1 as libc::c_int) as usize] = x_0;
        }
        mlkem_poly_rej_uniform(
            &mut *a.offset(i as isize),
            (seed_ext[0 as libc::c_int as usize]).as_mut_ptr(),
        );
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as libc::c_uint;
    while i < (3 as libc::c_int * 3 as libc::c_int) as libc::c_uint {
        mlk_poly_permute_bitrev_to_custom768(
            ((*a.offset(i as isize)).0.coeffs).as_mut_ptr(),
        );
        i = i.wrapping_add(1);
        i;
    }
    mlk_zeroize(
        seed_ext.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[[uint8_t; 64]; 4]>() as libc::c_ulong,
    );
}
unsafe extern "C" fn mlk_matvec_mul768(
    mut out: *mut mlk_poly,
    mut a: *const mlk_poly,
    mut v: *const mlk_poly,
    mut vc: *const mlk_poly_mulcache,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 3 as libc::c_int as libc::c_uint {
        mlkem768_polyvec_basemul_acc_montgomery_cached(
            &mut *out.offset(i as isize),
            &*a.offset((3 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize),
            v,
            vc,
        );
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem768_indcpa_keypair_derand(
    mut pk: *mut uint8_t,
    mut sk: *mut uint8_t,
    mut coins: *const uint8_t,
) {
    let mut buf: [uint8_t; 64] = [0; 64];
    let mut publicseed: *const uint8_t = buf.as_mut_ptr();
    let mut noiseseed: *const uint8_t = buf
        .as_mut_ptr()
        .offset(32 as libc::c_int as isize);
    let mut a: mlk_polymat768 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 9];
    let mut e: mlk_polyvec768 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 3];
    let mut pkpv: mlk_polyvec768 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 3];
    let mut skpv: mlk_polyvec768 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 3];
    let mut skpv_cache: mlk_polyvec_mulcache768 = [mlk_poly_mulcache {
        coeffs: [0; 128],
    }; 3];
    let mut coins_with_domain_separator: [uint8_t; 33] = [0; 33];
    memcpy(
        coins_with_domain_separator.as_mut_ptr() as *mut libc::c_void,
        coins as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    coins_with_domain_separator[32 as libc::c_int
        as usize] = 3 as libc::c_int as uint8_t;
    mlk_sha3_512(
        buf.as_mut_ptr(),
        coins_with_domain_separator.as_mut_ptr(),
        (32 as libc::c_int + 1 as libc::c_int) as size_t,
    );
    mlkem768_gen_matrix(a.as_mut_ptr(), publicseed, 0 as libc::c_int);
    mlkem768_poly_getnoise_eta1_4x(
        &mut *skpv.as_mut_ptr().offset(0 as libc::c_int as isize),
        &mut *skpv.as_mut_ptr().offset(1 as libc::c_int as isize),
        &mut *skpv.as_mut_ptr().offset(2 as libc::c_int as isize),
        &mut *pkpv.as_mut_ptr().offset(0 as libc::c_int as isize),
        noiseseed,
        0 as libc::c_int as uint8_t,
        1 as libc::c_int as uint8_t,
        2 as libc::c_int as uint8_t,
        0xff as libc::c_int as uint8_t,
    );
    mlkem768_poly_getnoise_eta1_4x(
        &mut *e.as_mut_ptr().offset(0 as libc::c_int as isize),
        &mut *e.as_mut_ptr().offset(1 as libc::c_int as isize),
        &mut *e.as_mut_ptr().offset(2 as libc::c_int as isize),
        &mut *pkpv.as_mut_ptr().offset(0 as libc::c_int as isize),
        noiseseed,
        3 as libc::c_int as uint8_t,
        4 as libc::c_int as uint8_t,
        5 as libc::c_int as uint8_t,
        0xff as libc::c_int as uint8_t,
    );
    mlkem768_polyvec_ntt(skpv.as_mut_ptr());
    mlkem768_polyvec_ntt(e.as_mut_ptr());
    mlkem768_polyvec_mulcache_compute(
        skpv_cache.as_mut_ptr(),
        skpv.as_mut_ptr() as *const mlk_poly,
    );
    mlk_matvec_mul768(
        pkpv.as_mut_ptr(),
        a.as_mut_ptr() as *const mlk_poly,
        skpv.as_mut_ptr() as *const mlk_poly,
        skpv_cache.as_mut_ptr() as *const mlk_poly_mulcache,
    );
    mlkem768_polyvec_tomont(pkpv.as_mut_ptr());
    mlkem768_polyvec_add(pkpv.as_mut_ptr(), e.as_mut_ptr() as *const mlk_poly);
    mlkem768_polyvec_reduce(pkpv.as_mut_ptr());
    mlkem768_polyvec_reduce(skpv.as_mut_ptr());
    mlk_pack_sk768(sk, skpv.as_mut_ptr());
    mlk_pack_pk768(pk, pkpv.as_mut_ptr(), publicseed);
    mlk_zeroize(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    mlk_zeroize(
        coins_with_domain_separator.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 33]>() as libc::c_ulong,
    );
    mlk_zeroize(
        a.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polymat768>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut e as *mut mlk_polyvec768 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec768>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut skpv as *mut mlk_polyvec768 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec768>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut skpv_cache as *mut mlk_polyvec_mulcache768 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec_mulcache768>() as libc::c_ulong,
    );
}
unsafe extern "C" fn mlkem768_indcpa_enc(
    mut c: *mut uint8_t,
    mut m: *const uint8_t,
    mut pk: *const uint8_t,
    mut coins: *const uint8_t,
) {
    let mut seed: [uint8_t; 32] = [0; 32];
    let mut at: mlk_polymat768 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 9];
    let mut sp: mlk_polyvec768 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 3];
    let mut pkpv: mlk_polyvec768 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 3];
    let mut ep: mlk_polyvec768 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 3];
    let mut b: mlk_polyvec768 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 3];
    let mut v: mlk_poly = mlk_poly(mlk_poly_Inner { coeffs: [0; 256] });
    let mut k: mlk_poly = mlk_poly(mlk_poly_Inner { coeffs: [0; 256] });
    let mut epp: mlk_poly = mlk_poly(mlk_poly_Inner { coeffs: [0; 256] });
    let mut sp_cache: mlk_polyvec_mulcache768 = [mlk_poly_mulcache {
        coeffs: [0; 128],
    }; 3];
    mlk_unpack_pk768(pkpv.as_mut_ptr(), seed.as_mut_ptr(), pk);
    mlkem_poly_frommsg(&mut k, m);
    mlkem768_gen_matrix(
        at.as_mut_ptr(),
        seed.as_mut_ptr() as *const uint8_t,
        1 as libc::c_int,
    );
    mlkem768_poly_getnoise_eta1_4x(
        &mut *sp.as_mut_ptr().offset(0 as libc::c_int as isize),
        &mut *sp.as_mut_ptr().offset(1 as libc::c_int as isize),
        &mut *sp.as_mut_ptr().offset(2 as libc::c_int as isize),
        &mut *b.as_mut_ptr().offset(0 as libc::c_int as isize),
        coins,
        0 as libc::c_int as uint8_t,
        1 as libc::c_int as uint8_t,
        2 as libc::c_int as uint8_t,
        0xff as libc::c_int as uint8_t,
    );
    mlkem768_poly_getnoise_eta1_4x(
        &mut *ep.as_mut_ptr().offset(0 as libc::c_int as isize),
        &mut *ep.as_mut_ptr().offset(1 as libc::c_int as isize),
        &mut *ep.as_mut_ptr().offset(2 as libc::c_int as isize),
        &mut epp,
        coins,
        3 as libc::c_int as uint8_t,
        4 as libc::c_int as uint8_t,
        5 as libc::c_int as uint8_t,
        6 as libc::c_int as uint8_t,
    );
    mlkem768_polyvec_ntt(sp.as_mut_ptr());
    mlkem768_polyvec_mulcache_compute(
        sp_cache.as_mut_ptr(),
        sp.as_mut_ptr() as *const mlk_poly,
    );
    mlk_matvec_mul768(
        b.as_mut_ptr(),
        at.as_mut_ptr() as *const mlk_poly,
        sp.as_mut_ptr() as *const mlk_poly,
        sp_cache.as_mut_ptr() as *const mlk_poly_mulcache,
    );
    mlkem768_polyvec_basemul_acc_montgomery_cached(
        &mut v,
        pkpv.as_mut_ptr() as *const mlk_poly,
        sp.as_mut_ptr() as *const mlk_poly,
        sp_cache.as_mut_ptr() as *const mlk_poly_mulcache,
    );
    mlkem768_polyvec_invntt_tomont(b.as_mut_ptr());
    mlkem_poly_invntt_tomont(&mut v);
    mlkem768_polyvec_add(b.as_mut_ptr(), ep.as_mut_ptr() as *const mlk_poly);
    mlkem_poly_add(&mut v, &mut epp);
    mlkem_poly_add(&mut v, &mut k);
    mlkem768_polyvec_reduce(b.as_mut_ptr());
    mlkem_poly_reduce(&mut v);
    mlk_pack_ciphertext768(c, b.as_mut_ptr(), &mut v);
    mlk_zeroize(
        seed.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut sp as *mut mlk_polyvec768 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec768>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut sp_cache as *mut mlk_polyvec_mulcache768 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec_mulcache768>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut b as *mut mlk_polyvec768 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec768>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut v as *mut mlk_poly as *mut libc::c_void,
        ::core::mem::size_of::<mlk_poly>() as libc::c_ulong,
    );
    mlk_zeroize(
        at.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polymat768>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut k as *mut mlk_poly as *mut libc::c_void,
        ::core::mem::size_of::<mlk_poly>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut ep as *mut mlk_polyvec768 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec768>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut epp as *mut mlk_poly as *mut libc::c_void,
        ::core::mem::size_of::<mlk_poly>() as libc::c_ulong,
    );
}
unsafe extern "C" fn mlkem768_indcpa_dec(
    mut m: *mut uint8_t,
    mut c: *const uint8_t,
    mut sk: *const uint8_t,
) {
    let mut b: mlk_polyvec768 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 3];
    let mut skpv: mlk_polyvec768 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 3];
    let mut v: mlk_poly = mlk_poly(mlk_poly_Inner { coeffs: [0; 256] });
    let mut sb: mlk_poly = mlk_poly(mlk_poly_Inner { coeffs: [0; 256] });
    let mut b_cache: mlk_polyvec_mulcache768 = [mlk_poly_mulcache {
        coeffs: [0; 128],
    }; 3];
    mlk_unpack_ciphertext768(b.as_mut_ptr(), &mut v, c);
    mlk_unpack_sk768(skpv.as_mut_ptr(), sk);
    mlkem768_polyvec_ntt(b.as_mut_ptr());
    mlkem768_polyvec_mulcache_compute(
        b_cache.as_mut_ptr(),
        b.as_mut_ptr() as *const mlk_poly,
    );
    mlkem768_polyvec_basemul_acc_montgomery_cached(
        &mut sb,
        skpv.as_mut_ptr() as *const mlk_poly,
        b.as_mut_ptr() as *const mlk_poly,
        b_cache.as_mut_ptr() as *const mlk_poly_mulcache,
    );
    mlkem_poly_invntt_tomont(&mut sb);
    mlkem_poly_sub(&mut v, &mut sb);
    mlkem_poly_reduce(&mut v);
    mlkem_poly_tomsg(m, &mut v);
    mlk_zeroize(
        &mut skpv as *mut mlk_polyvec768 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec768>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut b as *mut mlk_polyvec768 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec768>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut b_cache as *mut mlk_polyvec_mulcache768 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec_mulcache768>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut v as *mut mlk_poly as *mut libc::c_void,
        ::core::mem::size_of::<mlk_poly>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut sb as *mut mlk_poly as *mut libc::c_void,
        ::core::mem::size_of::<mlk_poly>() as libc::c_ulong,
    );
}
unsafe extern "C" fn mlk_pack_pk1024(
    mut r: *mut uint8_t,
    mut pk: *mut mlk_poly,
    mut seed: *const uint8_t,
) {
    mlkem1024_polyvec_tobytes(r, pk as *const mlk_poly);
    memcpy(
        r.offset((4 as libc::c_int * 384 as libc::c_int) as isize) as *mut libc::c_void,
        seed as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
}
unsafe extern "C" fn mlk_unpack_pk1024(
    mut pk: *mut mlk_poly,
    mut seed: *mut uint8_t,
    mut packedpk: *const uint8_t,
) {
    mlkem1024_polyvec_frombytes(pk, packedpk);
    memcpy(
        seed as *mut libc::c_void,
        packedpk.offset((4 as libc::c_int * 384 as libc::c_int) as isize)
            as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
}
unsafe extern "C" fn mlk_pack_sk1024(mut r: *mut uint8_t, mut sk: *mut mlk_poly) {
    mlkem1024_polyvec_tobytes(r, sk as *const mlk_poly);
}
unsafe extern "C" fn mlk_unpack_sk1024(
    mut sk: *mut mlk_poly,
    mut packedsk: *const uint8_t,
) {
    mlkem1024_polyvec_frombytes(sk, packedsk);
}
unsafe extern "C" fn mlk_pack_ciphertext1024(
    mut r: *mut uint8_t,
    mut b: *mut mlk_poly,
    mut v: *mut mlk_poly,
) {
    mlkem1024_polyvec_compress_du(r, b as *const mlk_poly);
    mlkem1024_poly_compress_dv(
        r.offset((4 as libc::c_int * 352 as libc::c_int) as isize),
        v,
    );
}
unsafe extern "C" fn mlk_unpack_ciphertext1024(
    mut b: *mut mlk_poly,
    mut v: *mut mlk_poly,
    mut c: *const uint8_t,
) {
    mlkem1024_polyvec_decompress_du(b, c);
    mlkem1024_poly_decompress_dv(
        v,
        c.offset((4 as libc::c_int * 352 as libc::c_int) as isize),
    );
}
#[inline]
unsafe extern "C" fn mlk_poly_permute_bitrev_to_custom1024(mut data: *mut int16_t) {}
unsafe extern "C" fn mlkem1024_gen_matrix(
    mut a: *mut mlk_poly,
    mut seed: *const uint8_t,
    mut transposed: libc::c_int,
) {
    let mut i: libc::c_uint = 0;
    let mut j: libc::c_uint = 0;
    let mut seed_ext: [[uint8_t; 64]; 4] = [[0; 64]; 4];
    j = 0 as libc::c_int as libc::c_uint;
    while j < 4 as libc::c_int as libc::c_uint {
        memcpy(
            (seed_ext[j as usize]).as_mut_ptr() as *mut libc::c_void,
            seed as *const libc::c_void,
            32 as libc::c_int as libc::c_ulong,
        );
        j = j.wrapping_add(1);
        j;
    }
    i = 0 as libc::c_int as libc::c_uint;
    while i
        < (4 as libc::c_int * 4 as libc::c_int / 4 as libc::c_int * 4 as libc::c_int)
            as libc::c_uint
    {
        let mut x: uint8_t = 0;
        let mut y: uint8_t = 0;
        j = 0 as libc::c_int as libc::c_uint;
        while j < 4 as libc::c_int as libc::c_uint {
            x = i.wrapping_add(j).wrapping_div(4 as libc::c_int as libc::c_uint)
                as uint8_t;
            y = i.wrapping_add(j).wrapping_rem(4 as libc::c_int as libc::c_uint)
                as uint8_t;
            if transposed != 0 {
                seed_ext[j
                    as usize][(32 as libc::c_int + 0 as libc::c_int) as usize] = x;
                seed_ext[j
                    as usize][(32 as libc::c_int + 1 as libc::c_int) as usize] = y;
            } else {
                seed_ext[j
                    as usize][(32 as libc::c_int + 0 as libc::c_int) as usize] = y;
                seed_ext[j
                    as usize][(32 as libc::c_int + 1 as libc::c_int) as usize] = x;
            }
            j = j.wrapping_add(1);
            j;
        }
        mlkem_poly_rej_uniform_x4(&mut *a.offset(i as isize), seed_ext.as_mut_ptr());
        i = i.wrapping_add(4 as libc::c_int as libc::c_uint);
    }
    if i < (4 as libc::c_int * 4 as libc::c_int) as libc::c_uint {
        let mut x_0: uint8_t = 0;
        let mut y_0: uint8_t = 0;
        x_0 = i.wrapping_div(4 as libc::c_int as libc::c_uint) as uint8_t;
        y_0 = i.wrapping_rem(4 as libc::c_int as libc::c_uint) as uint8_t;
        if transposed != 0 {
            seed_ext[0 as libc::c_int
                as usize][(32 as libc::c_int + 0 as libc::c_int) as usize] = x_0;
            seed_ext[0 as libc::c_int
                as usize][(32 as libc::c_int + 1 as libc::c_int) as usize] = y_0;
        } else {
            seed_ext[0 as libc::c_int
                as usize][(32 as libc::c_int + 0 as libc::c_int) as usize] = y_0;
            seed_ext[0 as libc::c_int
                as usize][(32 as libc::c_int + 1 as libc::c_int) as usize] = x_0;
        }
        mlkem_poly_rej_uniform(
            &mut *a.offset(i as isize),
            (seed_ext[0 as libc::c_int as usize]).as_mut_ptr(),
        );
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as libc::c_uint;
    while i < (4 as libc::c_int * 4 as libc::c_int) as libc::c_uint {
        mlk_poly_permute_bitrev_to_custom1024(
            ((*a.offset(i as isize)).0.coeffs).as_mut_ptr(),
        );
        i = i.wrapping_add(1);
        i;
    }
    mlk_zeroize(
        seed_ext.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[[uint8_t; 64]; 4]>() as libc::c_ulong,
    );
}
unsafe extern "C" fn mlk_matvec_mul1024(
    mut out: *mut mlk_poly,
    mut a: *const mlk_poly,
    mut v: *const mlk_poly,
    mut vc: *const mlk_poly_mulcache,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 4 as libc::c_int as libc::c_uint {
        mlkem1024_polyvec_basemul_acc_montgomery_cached(
            &mut *out.offset(i as isize),
            &*a.offset((4 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize),
            v,
            vc,
        );
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlkem1024_indcpa_keypair_derand(
    mut pk: *mut uint8_t,
    mut sk: *mut uint8_t,
    mut coins: *const uint8_t,
) {
    let mut buf: [uint8_t; 64] = [0; 64];
    let mut publicseed: *const uint8_t = buf.as_mut_ptr();
    let mut noiseseed: *const uint8_t = buf
        .as_mut_ptr()
        .offset(32 as libc::c_int as isize);
    let mut a: mlk_polymat1024 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 16];
    let mut e: mlk_polyvec1024 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 4];
    let mut pkpv: mlk_polyvec1024 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 4];
    let mut skpv: mlk_polyvec1024 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 4];
    let mut skpv_cache: mlk_polyvec_mulcache1024 = [mlk_poly_mulcache {
        coeffs: [0; 128],
    }; 4];
    let mut coins_with_domain_separator: [uint8_t; 33] = [0; 33];
    memcpy(
        coins_with_domain_separator.as_mut_ptr() as *mut libc::c_void,
        coins as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    coins_with_domain_separator[32 as libc::c_int
        as usize] = 4 as libc::c_int as uint8_t;
    mlk_sha3_512(
        buf.as_mut_ptr(),
        coins_with_domain_separator.as_mut_ptr(),
        (32 as libc::c_int + 1 as libc::c_int) as size_t,
    );
    mlkem1024_gen_matrix(a.as_mut_ptr(), publicseed, 0 as libc::c_int);
    mlkem1024_poly_getnoise_eta1_4x(
        &mut *skpv.as_mut_ptr().offset(0 as libc::c_int as isize),
        &mut *skpv.as_mut_ptr().offset(1 as libc::c_int as isize),
        &mut *skpv.as_mut_ptr().offset(2 as libc::c_int as isize),
        &mut *skpv.as_mut_ptr().offset(3 as libc::c_int as isize),
        noiseseed,
        0 as libc::c_int as uint8_t,
        1 as libc::c_int as uint8_t,
        2 as libc::c_int as uint8_t,
        3 as libc::c_int as uint8_t,
    );
    mlkem1024_poly_getnoise_eta1_4x(
        &mut *e.as_mut_ptr().offset(0 as libc::c_int as isize),
        &mut *e.as_mut_ptr().offset(1 as libc::c_int as isize),
        &mut *e.as_mut_ptr().offset(2 as libc::c_int as isize),
        &mut *e.as_mut_ptr().offset(3 as libc::c_int as isize),
        noiseseed,
        4 as libc::c_int as uint8_t,
        5 as libc::c_int as uint8_t,
        6 as libc::c_int as uint8_t,
        7 as libc::c_int as uint8_t,
    );
    mlkem1024_polyvec_ntt(skpv.as_mut_ptr());
    mlkem1024_polyvec_ntt(e.as_mut_ptr());
    mlkem1024_polyvec_mulcache_compute(
        skpv_cache.as_mut_ptr(),
        skpv.as_mut_ptr() as *const mlk_poly,
    );
    mlk_matvec_mul1024(
        pkpv.as_mut_ptr(),
        a.as_mut_ptr() as *const mlk_poly,
        skpv.as_mut_ptr() as *const mlk_poly,
        skpv_cache.as_mut_ptr() as *const mlk_poly_mulcache,
    );
    mlkem1024_polyvec_tomont(pkpv.as_mut_ptr());
    mlkem1024_polyvec_add(pkpv.as_mut_ptr(), e.as_mut_ptr() as *const mlk_poly);
    mlkem1024_polyvec_reduce(pkpv.as_mut_ptr());
    mlkem1024_polyvec_reduce(skpv.as_mut_ptr());
    mlk_pack_sk1024(sk, skpv.as_mut_ptr());
    mlk_pack_pk1024(pk, pkpv.as_mut_ptr(), publicseed);
    mlk_zeroize(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    mlk_zeroize(
        coins_with_domain_separator.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 33]>() as libc::c_ulong,
    );
    mlk_zeroize(
        a.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polymat1024>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut e as *mut mlk_polyvec1024 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec1024>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut skpv as *mut mlk_polyvec1024 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec1024>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut skpv_cache as *mut mlk_polyvec_mulcache1024 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec_mulcache1024>() as libc::c_ulong,
    );
}
unsafe extern "C" fn mlkem1024_indcpa_enc(
    mut c: *mut uint8_t,
    mut m: *const uint8_t,
    mut pk: *const uint8_t,
    mut coins: *const uint8_t,
) {
    let mut seed: [uint8_t; 32] = [0; 32];
    let mut at: mlk_polymat1024 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 16];
    let mut sp: mlk_polyvec1024 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 4];
    let mut pkpv: mlk_polyvec1024 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 4];
    let mut ep: mlk_polyvec1024 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 4];
    let mut b: mlk_polyvec1024 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 4];
    let mut v: mlk_poly = mlk_poly(mlk_poly_Inner { coeffs: [0; 256] });
    let mut k: mlk_poly = mlk_poly(mlk_poly_Inner { coeffs: [0; 256] });
    let mut epp: mlk_poly = mlk_poly(mlk_poly_Inner { coeffs: [0; 256] });
    let mut sp_cache: mlk_polyvec_mulcache1024 = [mlk_poly_mulcache {
        coeffs: [0; 128],
    }; 4];
    mlk_unpack_pk1024(pkpv.as_mut_ptr(), seed.as_mut_ptr(), pk);
    mlkem_poly_frommsg(&mut k, m);
    mlkem1024_gen_matrix(
        at.as_mut_ptr(),
        seed.as_mut_ptr() as *const uint8_t,
        1 as libc::c_int,
    );
    mlkem1024_poly_getnoise_eta1_4x(
        &mut *sp.as_mut_ptr().offset(0 as libc::c_int as isize),
        &mut *sp.as_mut_ptr().offset(1 as libc::c_int as isize),
        &mut *sp.as_mut_ptr().offset(2 as libc::c_int as isize),
        &mut *sp.as_mut_ptr().offset(3 as libc::c_int as isize),
        coins,
        0 as libc::c_int as uint8_t,
        1 as libc::c_int as uint8_t,
        2 as libc::c_int as uint8_t,
        3 as libc::c_int as uint8_t,
    );
    mlkem1024_poly_getnoise_eta1_4x(
        &mut *ep.as_mut_ptr().offset(0 as libc::c_int as isize),
        &mut *ep.as_mut_ptr().offset(1 as libc::c_int as isize),
        &mut *ep.as_mut_ptr().offset(2 as libc::c_int as isize),
        &mut *ep.as_mut_ptr().offset(3 as libc::c_int as isize),
        coins,
        4 as libc::c_int as uint8_t,
        5 as libc::c_int as uint8_t,
        6 as libc::c_int as uint8_t,
        7 as libc::c_int as uint8_t,
    );
    mlkem1024_poly_getnoise_eta2(&mut epp, coins, 8 as libc::c_int as uint8_t);
    mlkem1024_polyvec_ntt(sp.as_mut_ptr());
    mlkem1024_polyvec_mulcache_compute(
        sp_cache.as_mut_ptr(),
        sp.as_mut_ptr() as *const mlk_poly,
    );
    mlk_matvec_mul1024(
        b.as_mut_ptr(),
        at.as_mut_ptr() as *const mlk_poly,
        sp.as_mut_ptr() as *const mlk_poly,
        sp_cache.as_mut_ptr() as *const mlk_poly_mulcache,
    );
    mlkem1024_polyvec_basemul_acc_montgomery_cached(
        &mut v,
        pkpv.as_mut_ptr() as *const mlk_poly,
        sp.as_mut_ptr() as *const mlk_poly,
        sp_cache.as_mut_ptr() as *const mlk_poly_mulcache,
    );
    mlkem1024_polyvec_invntt_tomont(b.as_mut_ptr());
    mlkem_poly_invntt_tomont(&mut v);
    mlkem1024_polyvec_add(b.as_mut_ptr(), ep.as_mut_ptr() as *const mlk_poly);
    mlkem_poly_add(&mut v, &mut epp);
    mlkem_poly_add(&mut v, &mut k);
    mlkem1024_polyvec_reduce(b.as_mut_ptr());
    mlkem_poly_reduce(&mut v);
    mlk_pack_ciphertext1024(c, b.as_mut_ptr(), &mut v);
    mlk_zeroize(
        seed.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut sp as *mut mlk_polyvec1024 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec1024>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut sp_cache as *mut mlk_polyvec_mulcache1024 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec_mulcache1024>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut b as *mut mlk_polyvec1024 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec1024>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut v as *mut mlk_poly as *mut libc::c_void,
        ::core::mem::size_of::<mlk_poly>() as libc::c_ulong,
    );
    mlk_zeroize(
        at.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polymat1024>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut k as *mut mlk_poly as *mut libc::c_void,
        ::core::mem::size_of::<mlk_poly>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut ep as *mut mlk_polyvec1024 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec1024>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut epp as *mut mlk_poly as *mut libc::c_void,
        ::core::mem::size_of::<mlk_poly>() as libc::c_ulong,
    );
}
unsafe extern "C" fn mlkem1024_indcpa_dec(
    mut m: *mut uint8_t,
    mut c: *const uint8_t,
    mut sk: *const uint8_t,
) {
    let mut b: mlk_polyvec1024 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 4];
    let mut skpv: mlk_polyvec1024 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 4];
    let mut v: mlk_poly = mlk_poly(mlk_poly_Inner { coeffs: [0; 256] });
    let mut sb: mlk_poly = mlk_poly(mlk_poly_Inner { coeffs: [0; 256] });
    let mut b_cache: mlk_polyvec_mulcache1024 = [mlk_poly_mulcache {
        coeffs: [0; 128],
    }; 4];
    mlk_unpack_ciphertext1024(b.as_mut_ptr(), &mut v, c);
    mlk_unpack_sk1024(skpv.as_mut_ptr(), sk);
    mlkem1024_polyvec_ntt(b.as_mut_ptr());
    mlkem1024_polyvec_mulcache_compute(
        b_cache.as_mut_ptr(),
        b.as_mut_ptr() as *const mlk_poly,
    );
    mlkem1024_polyvec_basemul_acc_montgomery_cached(
        &mut sb,
        skpv.as_mut_ptr() as *const mlk_poly,
        b.as_mut_ptr() as *const mlk_poly,
        b_cache.as_mut_ptr() as *const mlk_poly_mulcache,
    );
    mlkem_poly_invntt_tomont(&mut sb);
    mlkem_poly_sub(&mut v, &mut sb);
    mlkem_poly_reduce(&mut v);
    mlkem_poly_tomsg(m, &mut v);
    mlk_zeroize(
        &mut skpv as *mut mlk_polyvec1024 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec1024>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut b as *mut mlk_polyvec1024 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec1024>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut b_cache as *mut mlk_polyvec_mulcache1024 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec_mulcache1024>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut v as *mut mlk_poly as *mut libc::c_void,
        ::core::mem::size_of::<mlk_poly>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut sb as *mut mlk_poly as *mut libc::c_void,
        ::core::mem::size_of::<mlk_poly>() as libc::c_ulong,
    );
}
unsafe extern "C" fn mlk_rej_uniform_scalar(
    mut r: *mut int16_t,
    mut target: libc::c_uint,
    mut offset: libc::c_uint,
    mut buf: *const uint8_t,
    mut buflen: libc::c_uint,
) -> libc::c_uint {
    let mut ctr: libc::c_uint = 0;
    let mut pos: libc::c_uint = 0;
    let mut val0: uint16_t = 0;
    let mut val1: uint16_t = 0;
    ctr = offset;
    pos = 0 as libc::c_int as libc::c_uint;
    while ctr < target && pos.wrapping_add(3 as libc::c_int as libc::c_uint) <= buflen {
        val0 = ((*buf.offset(pos.wrapping_add(0 as libc::c_int as libc::c_uint) as isize)
            as libc::c_int >> 0 as libc::c_int
            | (*buf.offset(pos.wrapping_add(1 as libc::c_int as libc::c_uint) as isize)
                as uint16_t as libc::c_int) << 8 as libc::c_int) & 0xfff as libc::c_int)
            as uint16_t;
        val1 = ((*buf.offset(pos.wrapping_add(1 as libc::c_int as libc::c_uint) as isize)
            as libc::c_int >> 4 as libc::c_int
            | (*buf.offset(pos.wrapping_add(2 as libc::c_int as libc::c_uint) as isize)
                as uint16_t as libc::c_int) << 4 as libc::c_int) & 0xfff as libc::c_int)
            as uint16_t;
        pos = pos.wrapping_add(3 as libc::c_int as libc::c_uint);
        if (val0 as libc::c_int) < 3329 as libc::c_int {
            let fresh3 = ctr;
            ctr = ctr.wrapping_add(1);
            *r.offset(fresh3 as isize) = val0 as int16_t;
        }
        if ctr < target && (val1 as libc::c_int) < 3329 as libc::c_int {
            let fresh4 = ctr;
            ctr = ctr.wrapping_add(1);
            *r.offset(fresh4 as isize) = val1 as int16_t;
        }
    }
    return ctr;
}
unsafe extern "C" fn mlk_rej_uniform(
    mut r: *mut int16_t,
    mut target: libc::c_uint,
    mut offset: libc::c_uint,
    mut buf: *const uint8_t,
    mut buflen: libc::c_uint,
) -> libc::c_uint {
    return mlk_rej_uniform_scalar(r, target, offset, buf, buflen);
}
unsafe extern "C" fn mlkem_poly_rej_uniform_x4(
    mut vec: *mut mlk_poly,
    mut seed: *mut [uint8_t; 64],
) {
    let mut buf: [[uint8_t; 512]; 4] = [[0; 512]; 4];
    let mut ctr: [libc::c_uint; 4] = [0; 4];
    let mut statex: KECCAK1600_CTX_x4 = [keccak_st {
        A: [[0; 5]; 5],
        block_size: 0,
        md_size: 0,
        buf_load: 0,
        buf: [0; 168],
        pad: 0,
        state: 0,
    }; 4];
    let mut buflen: libc::c_uint = 0;
    mlk_shake128x4_init(&mut statex);
    mlk_shake128x4_absorb_once(
        &mut statex,
        (*seed.offset(0 as libc::c_int as isize)).as_mut_ptr(),
        (*seed.offset(1 as libc::c_int as isize)).as_mut_ptr(),
        (*seed.offset(2 as libc::c_int as isize)).as_mut_ptr(),
        (*seed.offset(3 as libc::c_int as isize)).as_mut_ptr(),
        (32 as libc::c_int + 2 as libc::c_int) as size_t,
    );
    mlk_shake128x4_squeezeblocks(
        (buf[0 as libc::c_int as usize]).as_mut_ptr(),
        (buf[1 as libc::c_int as usize]).as_mut_ptr(),
        (buf[2 as libc::c_int as usize]).as_mut_ptr(),
        (buf[3 as libc::c_int as usize]).as_mut_ptr(),
        ((12 as libc::c_int * 256 as libc::c_int / 8 as libc::c_int
            * ((1 as libc::c_int) << 12 as libc::c_int) / 3329 as libc::c_int
            + 168 as libc::c_int) / 168 as libc::c_int) as size_t,
        &mut statex,
    );
    buflen = ((12 as libc::c_int * 256 as libc::c_int / 8 as libc::c_int
        * ((1 as libc::c_int) << 12 as libc::c_int) / 3329 as libc::c_int
        + 168 as libc::c_int) / 168 as libc::c_int * 168 as libc::c_int) as libc::c_uint;
    ctr[0 as libc::c_int
        as usize] = mlk_rej_uniform(
        ((*vec.offset(0 as libc::c_int as isize)).0.coeffs).as_mut_ptr(),
        256 as libc::c_int as libc::c_uint,
        0 as libc::c_int as libc::c_uint,
        (buf[0 as libc::c_int as usize]).as_mut_ptr(),
        buflen,
    );
    ctr[1 as libc::c_int
        as usize] = mlk_rej_uniform(
        ((*vec.offset(1 as libc::c_int as isize)).0.coeffs).as_mut_ptr(),
        256 as libc::c_int as libc::c_uint,
        0 as libc::c_int as libc::c_uint,
        (buf[1 as libc::c_int as usize]).as_mut_ptr(),
        buflen,
    );
    ctr[2 as libc::c_int
        as usize] = mlk_rej_uniform(
        ((*vec.offset(2 as libc::c_int as isize)).0.coeffs).as_mut_ptr(),
        256 as libc::c_int as libc::c_uint,
        0 as libc::c_int as libc::c_uint,
        (buf[2 as libc::c_int as usize]).as_mut_ptr(),
        buflen,
    );
    ctr[3 as libc::c_int
        as usize] = mlk_rej_uniform(
        ((*vec.offset(3 as libc::c_int as isize)).0.coeffs).as_mut_ptr(),
        256 as libc::c_int as libc::c_uint,
        0 as libc::c_int as libc::c_uint,
        (buf[3 as libc::c_int as usize]).as_mut_ptr(),
        buflen,
    );
    buflen = 168 as libc::c_int as libc::c_uint;
    while ctr[0 as libc::c_int as usize] < 256 as libc::c_int as libc::c_uint
        || ctr[1 as libc::c_int as usize] < 256 as libc::c_int as libc::c_uint
        || ctr[2 as libc::c_int as usize] < 256 as libc::c_int as libc::c_uint
        || ctr[3 as libc::c_int as usize] < 256 as libc::c_int as libc::c_uint
    {
        mlk_shake128x4_squeezeblocks(
            (buf[0 as libc::c_int as usize]).as_mut_ptr(),
            (buf[1 as libc::c_int as usize]).as_mut_ptr(),
            (buf[2 as libc::c_int as usize]).as_mut_ptr(),
            (buf[3 as libc::c_int as usize]).as_mut_ptr(),
            1 as libc::c_int as size_t,
            &mut statex,
        );
        ctr[0 as libc::c_int
            as usize] = mlk_rej_uniform(
            ((*vec.offset(0 as libc::c_int as isize)).0.coeffs).as_mut_ptr(),
            256 as libc::c_int as libc::c_uint,
            ctr[0 as libc::c_int as usize],
            (buf[0 as libc::c_int as usize]).as_mut_ptr(),
            buflen,
        );
        ctr[1 as libc::c_int
            as usize] = mlk_rej_uniform(
            ((*vec.offset(1 as libc::c_int as isize)).0.coeffs).as_mut_ptr(),
            256 as libc::c_int as libc::c_uint,
            ctr[1 as libc::c_int as usize],
            (buf[1 as libc::c_int as usize]).as_mut_ptr(),
            buflen,
        );
        ctr[2 as libc::c_int
            as usize] = mlk_rej_uniform(
            ((*vec.offset(2 as libc::c_int as isize)).0.coeffs).as_mut_ptr(),
            256 as libc::c_int as libc::c_uint,
            ctr[2 as libc::c_int as usize],
            (buf[2 as libc::c_int as usize]).as_mut_ptr(),
            buflen,
        );
        ctr[3 as libc::c_int
            as usize] = mlk_rej_uniform(
            ((*vec.offset(3 as libc::c_int as isize)).0.coeffs).as_mut_ptr(),
            256 as libc::c_int as libc::c_uint,
            ctr[3 as libc::c_int as usize],
            (buf[3 as libc::c_int as usize]).as_mut_ptr(),
            buflen,
        );
    }
    mlk_shake128x4_release(&mut statex);
    mlk_zeroize(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[[uint8_t; 512]; 4]>() as libc::c_ulong,
    );
}
unsafe extern "C" fn mlkem_poly_rej_uniform(
    mut entry: *mut mlk_poly,
    mut seed: *mut uint8_t,
) {
    let mut state: KECCAK1600_CTX = keccak_st {
        A: [[0; 5]; 5],
        block_size: 0,
        md_size: 0,
        buf_load: 0,
        buf: [0; 168],
        pad: 0,
        state: 0,
    };
    let mut buf: [uint8_t; 504] = [0; 504];
    let mut ctr: libc::c_uint = 0;
    let mut buflen: libc::c_uint = 0;
    mlk_shake128_init(&mut state);
    mlk_shake128_absorb_once(
        &mut state,
        seed as *const uint8_t,
        (32 as libc::c_int + 2 as libc::c_int) as size_t,
    );
    mlk_shake128_squeezeblocks(
        buf.as_mut_ptr(),
        ((12 as libc::c_int * 256 as libc::c_int / 8 as libc::c_int
            * ((1 as libc::c_int) << 12 as libc::c_int) / 3329 as libc::c_int
            + 168 as libc::c_int) / 168 as libc::c_int) as size_t,
        &mut state,
    );
    buflen = ((12 as libc::c_int * 256 as libc::c_int / 8 as libc::c_int
        * ((1 as libc::c_int) << 12 as libc::c_int) / 3329 as libc::c_int
        + 168 as libc::c_int) / 168 as libc::c_int * 168 as libc::c_int) as libc::c_uint;
    ctr = mlk_rej_uniform(
        ((*entry).0.coeffs).as_mut_ptr(),
        256 as libc::c_int as libc::c_uint,
        0 as libc::c_int as libc::c_uint,
        buf.as_mut_ptr(),
        buflen,
    );
    buflen = 168 as libc::c_int as libc::c_uint;
    while ctr < 256 as libc::c_int as libc::c_uint {
        mlk_shake128_squeezeblocks(
            buf.as_mut_ptr(),
            1 as libc::c_int as size_t,
            &mut state,
        );
        ctr = mlk_rej_uniform(
            ((*entry).0.coeffs).as_mut_ptr(),
            256 as libc::c_int as libc::c_uint,
            ctr,
            buf.as_mut_ptr(),
            buflen,
        );
    }
    mlk_shake128_release(&mut state);
    mlk_zeroize(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 504]>() as libc::c_ulong,
    );
}
unsafe extern "C" fn mlk_load32_littleendian(mut x: *const uint8_t) -> uint32_t {
    let mut r: uint32_t = 0;
    r = *x.offset(0 as libc::c_int as isize) as uint32_t;
    r |= (*x.offset(1 as libc::c_int as isize) as uint32_t) << 8 as libc::c_int;
    r |= (*x.offset(2 as libc::c_int as isize) as uint32_t) << 16 as libc::c_int;
    r |= (*x.offset(3 as libc::c_int as isize) as uint32_t) << 24 as libc::c_int;
    return r;
}
unsafe extern "C" fn mlkem_poly_cbd2(mut r: *mut mlk_poly, mut buf: *const uint8_t) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 8 as libc::c_int) as libc::c_uint {
        let mut j: libc::c_uint = 0;
        let mut t: uint32_t = mlk_load32_littleendian(
            buf.offset((4 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize),
        );
        let mut d: uint32_t = t & 0x55555555 as libc::c_int as uint32_t;
        d = d
            .wrapping_add(t >> 1 as libc::c_int & 0x55555555 as libc::c_int as uint32_t);
        j = 0 as libc::c_int as libc::c_uint;
        while j < 8 as libc::c_int as libc::c_uint {
            let a: int16_t = (d
                >> (4 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(0 as libc::c_int as libc::c_uint)
                & 0x3 as libc::c_int as uint32_t) as int16_t;
            let b: int16_t = (d
                >> (4 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(2 as libc::c_int as libc::c_uint)
                & 0x3 as libc::c_int as uint32_t) as int16_t;
            (*r)
                .0
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(j)
                as usize] = (a as libc::c_int - b as libc::c_int) as int16_t;
            j = j.wrapping_add(1);
            j;
        }
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn mlk_load24_littleendian(mut x: *const uint8_t) -> uint32_t {
    let mut r: uint32_t = 0;
    r = *x.offset(0 as libc::c_int as isize) as uint32_t;
    r |= (*x.offset(1 as libc::c_int as isize) as uint32_t) << 8 as libc::c_int;
    r |= (*x.offset(2 as libc::c_int as isize) as uint32_t) << 16 as libc::c_int;
    return r;
}
unsafe extern "C" fn mlkem_poly_cbd3(mut r: *mut mlk_poly, mut buf: *const uint8_t) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 4 as libc::c_int) as libc::c_uint {
        let mut j: libc::c_uint = 0;
        let t: uint32_t = mlk_load24_littleendian(
            buf.offset((3 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize),
        );
        let mut d: uint32_t = t & 0x249249 as libc::c_int as uint32_t;
        d = d.wrapping_add(t >> 1 as libc::c_int & 0x249249 as libc::c_int as uint32_t);
        d = d.wrapping_add(t >> 2 as libc::c_int & 0x249249 as libc::c_int as uint32_t);
        j = 0 as libc::c_int as libc::c_uint;
        while j < 4 as libc::c_int as libc::c_uint {
            let a: int16_t = (d
                >> (6 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(0 as libc::c_int as libc::c_uint)
                & 0x7 as libc::c_int as uint32_t) as int16_t;
            let b: int16_t = (d
                >> (6 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(3 as libc::c_int as libc::c_uint)
                & 0x7 as libc::c_int as uint32_t) as int16_t;
            (*r)
                .0
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(j)
                as usize] = (a as libc::c_int - b as libc::c_int) as int16_t;
            j = j.wrapping_add(1);
            j;
        }
        i = i.wrapping_add(1);
        i;
    }
}
#[inline]
unsafe extern "C" fn mlk_shake128_init(mut state: *mut KECCAK1600_CTX) {
    SHAKE_Init(
        state,
        ((1600 as libc::c_int - 128 as libc::c_int * 2 as libc::c_int)
            / 8 as libc::c_int) as size_t,
    );
}
#[inline]
unsafe extern "C" fn mlk_shake128_release(mut state: *mut KECCAK1600_CTX) {}
#[inline]
unsafe extern "C" fn mlk_shake128_absorb_once(
    mut state: *mut KECCAK1600_CTX,
    mut input: *const uint8_t,
    mut inlen: size_t,
) {
    SHAKE_Absorb(state, input as *const libc::c_void, inlen);
}
#[inline]
unsafe extern "C" fn mlk_shake128_squeezeblocks(
    mut output: *mut uint8_t,
    mut nblocks: size_t,
    mut state: *mut KECCAK1600_CTX,
) {
    SHAKE_Squeeze(output, state, nblocks * 168 as libc::c_int as size_t);
}
#[inline]
unsafe extern "C" fn mlk_shake256(
    mut output: *mut uint8_t,
    mut outlen: size_t,
    mut input: *const uint8_t,
    mut inlen: size_t,
) {
    SHAKE256(input, inlen, output, outlen);
}
#[inline]
unsafe extern "C" fn mlk_sha3_256(
    mut output: *mut uint8_t,
    mut input: *const uint8_t,
    mut inlen: size_t,
) {
    SHA3_256(input, inlen, output);
}
#[inline]
unsafe extern "C" fn mlk_sha3_512(
    mut output: *mut uint8_t,
    mut input: *const uint8_t,
    mut inlen: size_t,
) {
    SHA3_512(input, inlen, output);
}
#[inline]
unsafe extern "C" fn mlk_shake128x4_absorb_once(
    mut state: *mut KECCAK1600_CTX_x4,
    mut in0: *const uint8_t,
    mut in1: *const uint8_t,
    mut in2: *const uint8_t,
    mut in3: *const uint8_t,
    mut inlen: size_t,
) {
    SHAKE128_Absorb_once_x4(
        state,
        in0 as *const libc::c_void,
        in1 as *const libc::c_void,
        in2 as *const libc::c_void,
        in3 as *const libc::c_void,
        inlen,
    );
}
#[inline]
unsafe extern "C" fn mlk_shake128x4_squeezeblocks(
    mut out0: *mut uint8_t,
    mut out1: *mut uint8_t,
    mut out2: *mut uint8_t,
    mut out3: *mut uint8_t,
    mut nblocks: size_t,
    mut state: *mut KECCAK1600_CTX_x4,
) {
    SHAKE128_Squeezeblocks_x4(out0, out1, out2, out3, state, nblocks);
}
#[inline]
unsafe extern "C" fn mlk_shake128x4_init(mut state: *mut KECCAK1600_CTX_x4) {
    SHAKE128_Init_x4(state);
}
#[inline]
unsafe extern "C" fn mlk_shake128x4_release(mut state: *mut KECCAK1600_CTX_x4) {}
#[inline]
unsafe extern "C" fn mlk_shake256x4(
    mut out0: *mut uint8_t,
    mut out1: *mut uint8_t,
    mut out2: *mut uint8_t,
    mut out3: *mut uint8_t,
    mut outlen: size_t,
    mut in0: *mut uint8_t,
    mut in1: *mut uint8_t,
    mut in2: *mut uint8_t,
    mut in3: *mut uint8_t,
    mut inlen: size_t,
) {
    SHAKE256_x4(in0, in1, in2, in3, inlen, out0, out1, out2, out3, outlen);
}
unsafe extern "C" fn mlk_check_pk512(mut pk: *const uint8_t) -> libc::c_int {
    let mut res: libc::c_int = 0;
    let mut p: mlk_polyvec512 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 2];
    let mut p_reencoded: [uint8_t; 768] = [0; 768];
    mlkem512_polyvec_frombytes(p.as_mut_ptr(), pk);
    mlkem512_polyvec_reduce(p.as_mut_ptr());
    mlkem512_polyvec_tobytes(
        p_reencoded.as_mut_ptr(),
        p.as_mut_ptr() as *const mlk_poly,
    );
    res = if mlk_ct_memcmp(
        pk,
        p_reencoded.as_mut_ptr(),
        (2 as libc::c_int * 384 as libc::c_int) as size_t,
    ) as libc::c_int != 0
    {
        -(1 as libc::c_int)
    } else {
        0 as libc::c_int
    };
    mlk_zeroize(
        p_reencoded.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 768]>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut p as *mut mlk_polyvec512 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec512>() as libc::c_ulong,
    );
    return res;
}
unsafe extern "C" fn mlk_check_sk512(mut sk: *const uint8_t) -> libc::c_int {
    let mut res: libc::c_int = 0;
    let mut test: [uint8_t; 32] = [0; 32];
    mlk_sha3_256(
        test.as_mut_ptr(),
        sk.offset((2 as libc::c_int * 384 as libc::c_int) as isize),
        (2 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int) as size_t,
    );
    res = if memcmp(
        sk
            .offset(
                (2 as libc::c_int * 384 as libc::c_int
                    + (2 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int)
                    + 2 as libc::c_int * 32 as libc::c_int) as isize,
            )
            .offset(-((2 as libc::c_int * 32 as libc::c_int) as isize))
            as *const libc::c_void,
        test.as_mut_ptr() as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    ) != 0
    {
        -(1 as libc::c_int)
    } else {
        0 as libc::c_int
    };
    mlk_zeroize(
        test.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
    );
    return res;
}
unsafe extern "C" fn mlk_check_pct512(
    mut pk: *const uint8_t,
    mut sk: *const uint8_t,
) -> libc::c_int {
    return 0 as libc::c_int;
}
unsafe extern "C" fn mlkem512_keypair_derand(
    mut pk: *mut uint8_t,
    mut sk: *mut uint8_t,
    mut coins: *const uint8_t,
) -> libc::c_int {
    mlkem512_indcpa_keypair_derand(pk, sk, coins);
    memcpy(
        sk.offset((2 as libc::c_int * 384 as libc::c_int) as isize) as *mut libc::c_void,
        pk as *const libc::c_void,
        (2 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int) as libc::c_ulong,
    );
    mlk_sha3_256(
        sk
            .offset(
                (2 as libc::c_int * 384 as libc::c_int
                    + (2 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int)
                    + 2 as libc::c_int * 32 as libc::c_int) as isize,
            )
            .offset(-((2 as libc::c_int * 32 as libc::c_int) as isize)),
        pk as *const uint8_t,
        (2 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int) as size_t,
    );
    memcpy(
        sk
            .offset(
                (2 as libc::c_int * 384 as libc::c_int
                    + (2 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int)
                    + 2 as libc::c_int * 32 as libc::c_int) as isize,
            )
            .offset(-(32 as libc::c_int as isize)) as *mut libc::c_void,
        coins.offset(32 as libc::c_int as isize) as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    if mlk_check_pct512(pk as *const uint8_t, sk as *const uint8_t) != 0 {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn mlkem512_keypair(
    mut pk: *mut uint8_t,
    mut sk: *mut uint8_t,
) -> libc::c_int {
    let mut res: libc::c_int = 0;
    let mut coins: [uint8_t; 64] = [0; 64];
    mlk_randombytes(
        coins.as_mut_ptr() as *mut libc::c_void,
        (2 as libc::c_int * 32 as libc::c_int) as size_t,
    );
    res = mlkem512_keypair_derand(pk, sk, coins.as_mut_ptr() as *const uint8_t);
    mlk_zeroize(
        coins.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    return res;
}
unsafe extern "C" fn mlkem512_enc_derand(
    mut ct: *mut uint8_t,
    mut ss: *mut uint8_t,
    mut pk: *const uint8_t,
    mut coins: *const uint8_t,
) -> libc::c_int {
    let mut buf: [uint8_t; 64] = [0; 64];
    let mut kr: [uint8_t; 64] = [0; 64];
    if mlk_check_pk512(pk) != 0 {
        return -(1 as libc::c_int);
    }
    memcpy(
        buf.as_mut_ptr() as *mut libc::c_void,
        coins as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    mlk_sha3_256(
        buf.as_mut_ptr().offset(32 as libc::c_int as isize),
        pk,
        (2 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int) as size_t,
    );
    mlk_sha3_512(
        kr.as_mut_ptr(),
        buf.as_mut_ptr(),
        (2 as libc::c_int * 32 as libc::c_int) as size_t,
    );
    mlkem512_indcpa_enc(
        ct,
        buf.as_mut_ptr() as *const uint8_t,
        pk,
        kr.as_mut_ptr().offset(32 as libc::c_int as isize) as *const uint8_t,
    );
    memcpy(
        ss as *mut libc::c_void,
        kr.as_mut_ptr() as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    mlk_zeroize(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    mlk_zeroize(
        kr.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn mlkem512_enc(
    mut ct: *mut uint8_t,
    mut ss: *mut uint8_t,
    mut pk: *const uint8_t,
) -> libc::c_int {
    let mut res: libc::c_int = 0;
    let mut coins: [uint8_t; 32] = [0; 32];
    mlk_randombytes(
        coins.as_mut_ptr() as *mut libc::c_void,
        32 as libc::c_int as size_t,
    );
    res = mlkem512_enc_derand(ct, ss, pk, coins.as_mut_ptr() as *const uint8_t);
    mlk_zeroize(
        coins.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
    );
    return res;
}
unsafe extern "C" fn mlkem512_dec(
    mut ss: *mut uint8_t,
    mut ct: *const uint8_t,
    mut sk: *const uint8_t,
) -> libc::c_int {
    let mut fail: uint8_t = 0;
    let mut buf: [uint8_t; 64] = [0; 64];
    let mut kr: [uint8_t; 64] = [0; 64];
    let mut tmp: [uint8_t; 800] = [0; 800];
    let mut pk: *const uint8_t = sk
        .offset((2 as libc::c_int * 384 as libc::c_int) as isize);
    if mlk_check_sk512(sk) != 0 {
        return -(1 as libc::c_int);
    }
    mlkem512_indcpa_dec(buf.as_mut_ptr(), ct, sk);
    memcpy(
        buf.as_mut_ptr().offset(32 as libc::c_int as isize) as *mut libc::c_void,
        sk
            .offset(
                (2 as libc::c_int * 384 as libc::c_int
                    + (2 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int)
                    + 2 as libc::c_int * 32 as libc::c_int) as isize,
            )
            .offset(-((2 as libc::c_int * 32 as libc::c_int) as isize))
            as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    mlk_sha3_512(
        kr.as_mut_ptr(),
        buf.as_mut_ptr(),
        (2 as libc::c_int * 32 as libc::c_int) as size_t,
    );
    mlkem512_indcpa_enc(
        tmp.as_mut_ptr(),
        buf.as_mut_ptr() as *const uint8_t,
        pk,
        kr.as_mut_ptr().offset(32 as libc::c_int as isize) as *const uint8_t,
    );
    fail = mlk_ct_memcmp(
        ct,
        tmp.as_mut_ptr(),
        (2 as libc::c_int * 320 as libc::c_int + 128 as libc::c_int) as size_t,
    );
    memcpy(
        tmp.as_mut_ptr() as *mut libc::c_void,
        sk
            .offset(
                (2 as libc::c_int * 384 as libc::c_int
                    + (2 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int)
                    + 2 as libc::c_int * 32 as libc::c_int) as isize,
            )
            .offset(-(32 as libc::c_int as isize)) as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    memcpy(
        tmp.as_mut_ptr().offset(32 as libc::c_int as isize) as *mut libc::c_void,
        ct as *const libc::c_void,
        (2 as libc::c_int * 320 as libc::c_int + 128 as libc::c_int) as libc::c_ulong,
    );
    mlk_shake256(
        ss,
        32 as libc::c_int as size_t,
        tmp.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 800]>() as libc::c_ulong,
    );
    mlk_ct_cmov_zero(ss, kr.as_mut_ptr(), 32 as libc::c_int as size_t, fail);
    mlk_zeroize(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    mlk_zeroize(
        kr.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    mlk_zeroize(
        tmp.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 800]>() as libc::c_ulong,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn mlk_check_pk768(mut pk: *const uint8_t) -> libc::c_int {
    let mut res: libc::c_int = 0;
    let mut p: mlk_polyvec768 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 3];
    let mut p_reencoded: [uint8_t; 1152] = [0; 1152];
    mlkem768_polyvec_frombytes(p.as_mut_ptr(), pk);
    mlkem768_polyvec_reduce(p.as_mut_ptr());
    mlkem768_polyvec_tobytes(
        p_reencoded.as_mut_ptr(),
        p.as_mut_ptr() as *const mlk_poly,
    );
    res = if mlk_ct_memcmp(
        pk,
        p_reencoded.as_mut_ptr(),
        (3 as libc::c_int * 384 as libc::c_int) as size_t,
    ) as libc::c_int != 0
    {
        -(1 as libc::c_int)
    } else {
        0 as libc::c_int
    };
    mlk_zeroize(
        p_reencoded.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 1152]>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut p as *mut mlk_polyvec768 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec768>() as libc::c_ulong,
    );
    return res;
}
unsafe extern "C" fn mlk_check_sk768(mut sk: *const uint8_t) -> libc::c_int {
    let mut res: libc::c_int = 0;
    let mut test: [uint8_t; 32] = [0; 32];
    mlk_sha3_256(
        test.as_mut_ptr(),
        sk.offset((3 as libc::c_int * 384 as libc::c_int) as isize),
        (3 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int) as size_t,
    );
    res = if memcmp(
        sk
            .offset(
                (3 as libc::c_int * 384 as libc::c_int
                    + (3 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int)
                    + 2 as libc::c_int * 32 as libc::c_int) as isize,
            )
            .offset(-((2 as libc::c_int * 32 as libc::c_int) as isize))
            as *const libc::c_void,
        test.as_mut_ptr() as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    ) != 0
    {
        -(1 as libc::c_int)
    } else {
        0 as libc::c_int
    };
    mlk_zeroize(
        test.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
    );
    return res;
}
unsafe extern "C" fn mlk_check_pct768(
    mut pk: *const uint8_t,
    mut sk: *const uint8_t,
) -> libc::c_int {
    return 0 as libc::c_int;
}
unsafe extern "C" fn mlkem768_keypair_derand(
    mut pk: *mut uint8_t,
    mut sk: *mut uint8_t,
    mut coins: *const uint8_t,
) -> libc::c_int {
    mlkem768_indcpa_keypair_derand(pk, sk, coins);
    memcpy(
        sk.offset((3 as libc::c_int * 384 as libc::c_int) as isize) as *mut libc::c_void,
        pk as *const libc::c_void,
        (3 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int) as libc::c_ulong,
    );
    mlk_sha3_256(
        sk
            .offset(
                (3 as libc::c_int * 384 as libc::c_int
                    + (3 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int)
                    + 2 as libc::c_int * 32 as libc::c_int) as isize,
            )
            .offset(-((2 as libc::c_int * 32 as libc::c_int) as isize)),
        pk as *const uint8_t,
        (3 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int) as size_t,
    );
    memcpy(
        sk
            .offset(
                (3 as libc::c_int * 384 as libc::c_int
                    + (3 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int)
                    + 2 as libc::c_int * 32 as libc::c_int) as isize,
            )
            .offset(-(32 as libc::c_int as isize)) as *mut libc::c_void,
        coins.offset(32 as libc::c_int as isize) as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    if mlk_check_pct768(pk as *const uint8_t, sk as *const uint8_t) != 0 {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn mlkem768_keypair(
    mut pk: *mut uint8_t,
    mut sk: *mut uint8_t,
) -> libc::c_int {
    let mut res: libc::c_int = 0;
    let mut coins: [uint8_t; 64] = [0; 64];
    mlk_randombytes(
        coins.as_mut_ptr() as *mut libc::c_void,
        (2 as libc::c_int * 32 as libc::c_int) as size_t,
    );
    res = mlkem768_keypair_derand(pk, sk, coins.as_mut_ptr() as *const uint8_t);
    mlk_zeroize(
        coins.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    return res;
}
unsafe extern "C" fn mlkem768_enc_derand(
    mut ct: *mut uint8_t,
    mut ss: *mut uint8_t,
    mut pk: *const uint8_t,
    mut coins: *const uint8_t,
) -> libc::c_int {
    let mut buf: [uint8_t; 64] = [0; 64];
    let mut kr: [uint8_t; 64] = [0; 64];
    if mlk_check_pk768(pk) != 0 {
        return -(1 as libc::c_int);
    }
    memcpy(
        buf.as_mut_ptr() as *mut libc::c_void,
        coins as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    mlk_sha3_256(
        buf.as_mut_ptr().offset(32 as libc::c_int as isize),
        pk,
        (3 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int) as size_t,
    );
    mlk_sha3_512(
        kr.as_mut_ptr(),
        buf.as_mut_ptr(),
        (2 as libc::c_int * 32 as libc::c_int) as size_t,
    );
    mlkem768_indcpa_enc(
        ct,
        buf.as_mut_ptr() as *const uint8_t,
        pk,
        kr.as_mut_ptr().offset(32 as libc::c_int as isize) as *const uint8_t,
    );
    memcpy(
        ss as *mut libc::c_void,
        kr.as_mut_ptr() as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    mlk_zeroize(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    mlk_zeroize(
        kr.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn mlkem768_enc(
    mut ct: *mut uint8_t,
    mut ss: *mut uint8_t,
    mut pk: *const uint8_t,
) -> libc::c_int {
    let mut res: libc::c_int = 0;
    let mut coins: [uint8_t; 32] = [0; 32];
    mlk_randombytes(
        coins.as_mut_ptr() as *mut libc::c_void,
        32 as libc::c_int as size_t,
    );
    res = mlkem768_enc_derand(ct, ss, pk, coins.as_mut_ptr() as *const uint8_t);
    mlk_zeroize(
        coins.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
    );
    return res;
}
unsafe extern "C" fn mlkem768_dec(
    mut ss: *mut uint8_t,
    mut ct: *const uint8_t,
    mut sk: *const uint8_t,
) -> libc::c_int {
    let mut fail: uint8_t = 0;
    let mut buf: [uint8_t; 64] = [0; 64];
    let mut kr: [uint8_t; 64] = [0; 64];
    let mut tmp: [uint8_t; 1120] = [0; 1120];
    let mut pk: *const uint8_t = sk
        .offset((3 as libc::c_int * 384 as libc::c_int) as isize);
    if mlk_check_sk768(sk) != 0 {
        return -(1 as libc::c_int);
    }
    mlkem768_indcpa_dec(buf.as_mut_ptr(), ct, sk);
    memcpy(
        buf.as_mut_ptr().offset(32 as libc::c_int as isize) as *mut libc::c_void,
        sk
            .offset(
                (3 as libc::c_int * 384 as libc::c_int
                    + (3 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int)
                    + 2 as libc::c_int * 32 as libc::c_int) as isize,
            )
            .offset(-((2 as libc::c_int * 32 as libc::c_int) as isize))
            as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    mlk_sha3_512(
        kr.as_mut_ptr(),
        buf.as_mut_ptr(),
        (2 as libc::c_int * 32 as libc::c_int) as size_t,
    );
    mlkem768_indcpa_enc(
        tmp.as_mut_ptr(),
        buf.as_mut_ptr() as *const uint8_t,
        pk,
        kr.as_mut_ptr().offset(32 as libc::c_int as isize) as *const uint8_t,
    );
    fail = mlk_ct_memcmp(
        ct,
        tmp.as_mut_ptr(),
        (3 as libc::c_int * 320 as libc::c_int + 128 as libc::c_int) as size_t,
    );
    memcpy(
        tmp.as_mut_ptr() as *mut libc::c_void,
        sk
            .offset(
                (3 as libc::c_int * 384 as libc::c_int
                    + (3 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int)
                    + 2 as libc::c_int * 32 as libc::c_int) as isize,
            )
            .offset(-(32 as libc::c_int as isize)) as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    memcpy(
        tmp.as_mut_ptr().offset(32 as libc::c_int as isize) as *mut libc::c_void,
        ct as *const libc::c_void,
        (3 as libc::c_int * 320 as libc::c_int + 128 as libc::c_int) as libc::c_ulong,
    );
    mlk_shake256(
        ss,
        32 as libc::c_int as size_t,
        tmp.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 1120]>() as libc::c_ulong,
    );
    mlk_ct_cmov_zero(ss, kr.as_mut_ptr(), 32 as libc::c_int as size_t, fail);
    mlk_zeroize(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    mlk_zeroize(
        kr.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    mlk_zeroize(
        tmp.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 1120]>() as libc::c_ulong,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn mlk_check_pk1024(mut pk: *const uint8_t) -> libc::c_int {
    let mut res: libc::c_int = 0;
    let mut p: mlk_polyvec1024 = [mlk_poly(mlk_poly_Inner { coeffs: [0; 256] }); 4];
    let mut p_reencoded: [uint8_t; 1536] = [0; 1536];
    mlkem1024_polyvec_frombytes(p.as_mut_ptr(), pk);
    mlkem1024_polyvec_reduce(p.as_mut_ptr());
    mlkem1024_polyvec_tobytes(
        p_reencoded.as_mut_ptr(),
        p.as_mut_ptr() as *const mlk_poly,
    );
    res = if mlk_ct_memcmp(
        pk,
        p_reencoded.as_mut_ptr(),
        (4 as libc::c_int * 384 as libc::c_int) as size_t,
    ) as libc::c_int != 0
    {
        -(1 as libc::c_int)
    } else {
        0 as libc::c_int
    };
    mlk_zeroize(
        p_reencoded.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 1536]>() as libc::c_ulong,
    );
    mlk_zeroize(
        &mut p as *mut mlk_polyvec1024 as *mut libc::c_void,
        ::core::mem::size_of::<mlk_polyvec1024>() as libc::c_ulong,
    );
    return res;
}
unsafe extern "C" fn mlk_check_sk1024(mut sk: *const uint8_t) -> libc::c_int {
    let mut res: libc::c_int = 0;
    let mut test: [uint8_t; 32] = [0; 32];
    mlk_sha3_256(
        test.as_mut_ptr(),
        sk.offset((4 as libc::c_int * 384 as libc::c_int) as isize),
        (4 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int) as size_t,
    );
    res = if memcmp(
        sk
            .offset(
                (4 as libc::c_int * 384 as libc::c_int
                    + (4 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int)
                    + 2 as libc::c_int * 32 as libc::c_int) as isize,
            )
            .offset(-((2 as libc::c_int * 32 as libc::c_int) as isize))
            as *const libc::c_void,
        test.as_mut_ptr() as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    ) != 0
    {
        -(1 as libc::c_int)
    } else {
        0 as libc::c_int
    };
    mlk_zeroize(
        test.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
    );
    return res;
}
unsafe extern "C" fn mlk_check_pct1024(
    mut pk: *const uint8_t,
    mut sk: *const uint8_t,
) -> libc::c_int {
    return 0 as libc::c_int;
}
unsafe extern "C" fn mlkem1024_keypair_derand(
    mut pk: *mut uint8_t,
    mut sk: *mut uint8_t,
    mut coins: *const uint8_t,
) -> libc::c_int {
    mlkem1024_indcpa_keypair_derand(pk, sk, coins);
    memcpy(
        sk.offset((4 as libc::c_int * 384 as libc::c_int) as isize) as *mut libc::c_void,
        pk as *const libc::c_void,
        (4 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int) as libc::c_ulong,
    );
    mlk_sha3_256(
        sk
            .offset(
                (4 as libc::c_int * 384 as libc::c_int
                    + (4 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int)
                    + 2 as libc::c_int * 32 as libc::c_int) as isize,
            )
            .offset(-((2 as libc::c_int * 32 as libc::c_int) as isize)),
        pk as *const uint8_t,
        (4 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int) as size_t,
    );
    memcpy(
        sk
            .offset(
                (4 as libc::c_int * 384 as libc::c_int
                    + (4 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int)
                    + 2 as libc::c_int * 32 as libc::c_int) as isize,
            )
            .offset(-(32 as libc::c_int as isize)) as *mut libc::c_void,
        coins.offset(32 as libc::c_int as isize) as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    if mlk_check_pct1024(pk as *const uint8_t, sk as *const uint8_t) != 0 {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn mlkem1024_keypair(
    mut pk: *mut uint8_t,
    mut sk: *mut uint8_t,
) -> libc::c_int {
    let mut res: libc::c_int = 0;
    let mut coins: [uint8_t; 64] = [0; 64];
    mlk_randombytes(
        coins.as_mut_ptr() as *mut libc::c_void,
        (2 as libc::c_int * 32 as libc::c_int) as size_t,
    );
    res = mlkem1024_keypair_derand(pk, sk, coins.as_mut_ptr() as *const uint8_t);
    mlk_zeroize(
        coins.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    return res;
}
unsafe extern "C" fn mlkem1024_enc_derand(
    mut ct: *mut uint8_t,
    mut ss: *mut uint8_t,
    mut pk: *const uint8_t,
    mut coins: *const uint8_t,
) -> libc::c_int {
    let mut buf: [uint8_t; 64] = [0; 64];
    let mut kr: [uint8_t; 64] = [0; 64];
    if mlk_check_pk1024(pk) != 0 {
        return -(1 as libc::c_int);
    }
    memcpy(
        buf.as_mut_ptr() as *mut libc::c_void,
        coins as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    mlk_sha3_256(
        buf.as_mut_ptr().offset(32 as libc::c_int as isize),
        pk,
        (4 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int) as size_t,
    );
    mlk_sha3_512(
        kr.as_mut_ptr(),
        buf.as_mut_ptr(),
        (2 as libc::c_int * 32 as libc::c_int) as size_t,
    );
    mlkem1024_indcpa_enc(
        ct,
        buf.as_mut_ptr() as *const uint8_t,
        pk,
        kr.as_mut_ptr().offset(32 as libc::c_int as isize) as *const uint8_t,
    );
    memcpy(
        ss as *mut libc::c_void,
        kr.as_mut_ptr() as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    mlk_zeroize(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    mlk_zeroize(
        kr.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn mlkem1024_enc(
    mut ct: *mut uint8_t,
    mut ss: *mut uint8_t,
    mut pk: *const uint8_t,
) -> libc::c_int {
    let mut res: libc::c_int = 0;
    let mut coins: [uint8_t; 32] = [0; 32];
    mlk_randombytes(
        coins.as_mut_ptr() as *mut libc::c_void,
        32 as libc::c_int as size_t,
    );
    res = mlkem1024_enc_derand(ct, ss, pk, coins.as_mut_ptr() as *const uint8_t);
    mlk_zeroize(
        coins.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
    );
    return res;
}
unsafe extern "C" fn mlkem1024_dec(
    mut ss: *mut uint8_t,
    mut ct: *const uint8_t,
    mut sk: *const uint8_t,
) -> libc::c_int {
    let mut fail: uint8_t = 0;
    let mut buf: [uint8_t; 64] = [0; 64];
    let mut kr: [uint8_t; 64] = [0; 64];
    let mut tmp: [uint8_t; 1600] = [0; 1600];
    let mut pk: *const uint8_t = sk
        .offset((4 as libc::c_int * 384 as libc::c_int) as isize);
    if mlk_check_sk1024(sk) != 0 {
        return -(1 as libc::c_int);
    }
    mlkem1024_indcpa_dec(buf.as_mut_ptr(), ct, sk);
    memcpy(
        buf.as_mut_ptr().offset(32 as libc::c_int as isize) as *mut libc::c_void,
        sk
            .offset(
                (4 as libc::c_int * 384 as libc::c_int
                    + (4 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int)
                    + 2 as libc::c_int * 32 as libc::c_int) as isize,
            )
            .offset(-((2 as libc::c_int * 32 as libc::c_int) as isize))
            as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    mlk_sha3_512(
        kr.as_mut_ptr(),
        buf.as_mut_ptr(),
        (2 as libc::c_int * 32 as libc::c_int) as size_t,
    );
    mlkem1024_indcpa_enc(
        tmp.as_mut_ptr(),
        buf.as_mut_ptr() as *const uint8_t,
        pk,
        kr.as_mut_ptr().offset(32 as libc::c_int as isize) as *const uint8_t,
    );
    fail = mlk_ct_memcmp(
        ct,
        tmp.as_mut_ptr(),
        (4 as libc::c_int * 352 as libc::c_int + 160 as libc::c_int) as size_t,
    );
    memcpy(
        tmp.as_mut_ptr() as *mut libc::c_void,
        sk
            .offset(
                (4 as libc::c_int * 384 as libc::c_int
                    + (4 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int)
                    + 2 as libc::c_int * 32 as libc::c_int) as isize,
            )
            .offset(-(32 as libc::c_int as isize)) as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    memcpy(
        tmp.as_mut_ptr().offset(32 as libc::c_int as isize) as *mut libc::c_void,
        ct as *const libc::c_void,
        (4 as libc::c_int * 352 as libc::c_int + 160 as libc::c_int) as libc::c_ulong,
    );
    mlk_shake256(
        ss,
        32 as libc::c_int as size_t,
        tmp.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 1600]>() as libc::c_ulong,
    );
    mlk_ct_cmov_zero(ss, kr.as_mut_ptr(), 32 as libc::c_int as size_t, fail);
    mlk_zeroize(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    mlk_zeroize(
        kr.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    mlk_zeroize(
        tmp.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 1600]>() as libc::c_ulong,
    );
    return 0 as libc::c_int;
}
static mut zetas: [int16_t; 128] = [
    -(1044 as libc::c_int) as int16_t,
    -(758 as libc::c_int) as int16_t,
    -(359 as libc::c_int) as int16_t,
    -(1517 as libc::c_int) as int16_t,
    1493 as libc::c_int as int16_t,
    1422 as libc::c_int as int16_t,
    287 as libc::c_int as int16_t,
    202 as libc::c_int as int16_t,
    -(171 as libc::c_int) as int16_t,
    622 as libc::c_int as int16_t,
    1577 as libc::c_int as int16_t,
    182 as libc::c_int as int16_t,
    962 as libc::c_int as int16_t,
    -(1202 as libc::c_int) as int16_t,
    -(1474 as libc::c_int) as int16_t,
    1468 as libc::c_int as int16_t,
    573 as libc::c_int as int16_t,
    -(1325 as libc::c_int) as int16_t,
    264 as libc::c_int as int16_t,
    383 as libc::c_int as int16_t,
    -(829 as libc::c_int) as int16_t,
    1458 as libc::c_int as int16_t,
    -(1602 as libc::c_int) as int16_t,
    -(130 as libc::c_int) as int16_t,
    -(681 as libc::c_int) as int16_t,
    1017 as libc::c_int as int16_t,
    732 as libc::c_int as int16_t,
    608 as libc::c_int as int16_t,
    -(1542 as libc::c_int) as int16_t,
    411 as libc::c_int as int16_t,
    -(205 as libc::c_int) as int16_t,
    -(1571 as libc::c_int) as int16_t,
    1223 as libc::c_int as int16_t,
    652 as libc::c_int as int16_t,
    -(552 as libc::c_int) as int16_t,
    1015 as libc::c_int as int16_t,
    -(1293 as libc::c_int) as int16_t,
    1491 as libc::c_int as int16_t,
    -(282 as libc::c_int) as int16_t,
    -(1544 as libc::c_int) as int16_t,
    516 as libc::c_int as int16_t,
    -(8 as libc::c_int) as int16_t,
    -(320 as libc::c_int) as int16_t,
    -(666 as libc::c_int) as int16_t,
    -(1618 as libc::c_int) as int16_t,
    -(1162 as libc::c_int) as int16_t,
    126 as libc::c_int as int16_t,
    1469 as libc::c_int as int16_t,
    -(853 as libc::c_int) as int16_t,
    -(90 as libc::c_int) as int16_t,
    -(271 as libc::c_int) as int16_t,
    830 as libc::c_int as int16_t,
    107 as libc::c_int as int16_t,
    -(1421 as libc::c_int) as int16_t,
    -(247 as libc::c_int) as int16_t,
    -(951 as libc::c_int) as int16_t,
    -(398 as libc::c_int) as int16_t,
    961 as libc::c_int as int16_t,
    -(1508 as libc::c_int) as int16_t,
    -(725 as libc::c_int) as int16_t,
    448 as libc::c_int as int16_t,
    -(1065 as libc::c_int) as int16_t,
    677 as libc::c_int as int16_t,
    -(1275 as libc::c_int) as int16_t,
    -(1103 as libc::c_int) as int16_t,
    430 as libc::c_int as int16_t,
    555 as libc::c_int as int16_t,
    843 as libc::c_int as int16_t,
    -(1251 as libc::c_int) as int16_t,
    871 as libc::c_int as int16_t,
    1550 as libc::c_int as int16_t,
    105 as libc::c_int as int16_t,
    422 as libc::c_int as int16_t,
    587 as libc::c_int as int16_t,
    177 as libc::c_int as int16_t,
    -(235 as libc::c_int) as int16_t,
    -(291 as libc::c_int) as int16_t,
    -(460 as libc::c_int) as int16_t,
    1574 as libc::c_int as int16_t,
    1653 as libc::c_int as int16_t,
    -(246 as libc::c_int) as int16_t,
    778 as libc::c_int as int16_t,
    1159 as libc::c_int as int16_t,
    -(147 as libc::c_int) as int16_t,
    -(777 as libc::c_int) as int16_t,
    1483 as libc::c_int as int16_t,
    -(602 as libc::c_int) as int16_t,
    1119 as libc::c_int as int16_t,
    -(1590 as libc::c_int) as int16_t,
    644 as libc::c_int as int16_t,
    -(872 as libc::c_int) as int16_t,
    349 as libc::c_int as int16_t,
    418 as libc::c_int as int16_t,
    329 as libc::c_int as int16_t,
    -(156 as libc::c_int) as int16_t,
    -(75 as libc::c_int) as int16_t,
    817 as libc::c_int as int16_t,
    1097 as libc::c_int as int16_t,
    603 as libc::c_int as int16_t,
    610 as libc::c_int as int16_t,
    1322 as libc::c_int as int16_t,
    -(1285 as libc::c_int) as int16_t,
    -(1465 as libc::c_int) as int16_t,
    384 as libc::c_int as int16_t,
    -(1215 as libc::c_int) as int16_t,
    -(136 as libc::c_int) as int16_t,
    1218 as libc::c_int as int16_t,
    -(1335 as libc::c_int) as int16_t,
    -(874 as libc::c_int) as int16_t,
    220 as libc::c_int as int16_t,
    -(1187 as libc::c_int) as int16_t,
    -(1659 as libc::c_int) as int16_t,
    -(1185 as libc::c_int) as int16_t,
    -(1530 as libc::c_int) as int16_t,
    -(1278 as libc::c_int) as int16_t,
    794 as libc::c_int as int16_t,
    -(1510 as libc::c_int) as int16_t,
    -(854 as libc::c_int) as int16_t,
    -(870 as libc::c_int) as int16_t,
    478 as libc::c_int as int16_t,
    -(108 as libc::c_int) as int16_t,
    -(308 as libc::c_int) as int16_t,
    996 as libc::c_int as int16_t,
    991 as libc::c_int as int16_t,
    958 as libc::c_int as int16_t,
    -(1460 as libc::c_int) as int16_t,
    1522 as libc::c_int as int16_t,
    1628 as libc::c_int as int16_t,
];
unsafe extern "C" fn check_buffer(data: output_buffer) -> libc::c_int {
    if (data.buffer).is_null() || *data.length < data.expected_length {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn set_written_len_on_success(
    result: libc::c_int,
    mut data: output_buffer,
) {
    if result == 0 as libc::c_int {
        *data.length = data.expected_length;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_512_keypair_deterministic(
    mut public_key: *mut uint8_t,
    mut public_len: *mut size_t,
    mut secret_key: *mut uint8_t,
    mut secret_len: *mut size_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    boringssl_ensure_ml_kem_self_test();
    return ml_kem_512_keypair_deterministic_no_self_test(
        public_key,
        public_len,
        secret_key,
        secret_len,
        seed,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_512_keypair_deterministic_no_self_test(
    mut public_key: *mut uint8_t,
    mut public_len: *mut size_t,
    mut secret_key: *mut uint8_t,
    mut secret_len: *mut size_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    let mut pkey: output_buffer = {
        let mut init = output_buffer {
            buffer: public_key,
            length: public_len,
            expected_length: 800 as libc::c_int as size_t,
        };
        init
    };
    let mut skey: output_buffer = {
        let mut init = output_buffer {
            buffer: secret_key,
            length: secret_len,
            expected_length: 1632 as libc::c_int as size_t,
        };
        init
    };
    if check_buffer(pkey) == 0 || check_buffer(skey) == 0 {
        return 1 as libc::c_int;
    }
    let res: libc::c_int = mlkem512_keypair_derand(pkey.buffer, skey.buffer, seed);
    set_written_len_on_success(res, pkey);
    set_written_len_on_success(res, skey);
    return res;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_512_keypair(
    mut public_key: *mut uint8_t,
    mut public_len: *mut size_t,
    mut secret_key: *mut uint8_t,
    mut secret_len: *mut size_t,
) -> libc::c_int {
    let mut pkey: output_buffer = {
        let mut init = output_buffer {
            buffer: public_key,
            length: public_len,
            expected_length: 800 as libc::c_int as size_t,
        };
        init
    };
    let mut skey: output_buffer = {
        let mut init = output_buffer {
            buffer: secret_key,
            length: secret_len,
            expected_length: 1632 as libc::c_int as size_t,
        };
        init
    };
    return ml_kem_common_keypair(
        Some(
            mlkem512_keypair
                as unsafe extern "C" fn(*mut uint8_t, *mut uint8_t) -> libc::c_int,
        ),
        pkey,
        skey,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_512_encapsulate_deterministic(
    mut ciphertext: *mut uint8_t,
    mut ciphertext_len: *mut size_t,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut public_key: *const uint8_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    boringssl_ensure_ml_kem_self_test();
    return ml_kem_512_encapsulate_deterministic_no_self_test(
        ciphertext,
        ciphertext_len,
        shared_secret,
        shared_secret_len,
        public_key,
        seed,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_512_encapsulate_deterministic_no_self_test(
    mut ciphertext: *mut uint8_t,
    mut ciphertext_len: *mut size_t,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut public_key: *const uint8_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    let mut ctext: output_buffer = {
        let mut init = output_buffer {
            buffer: ciphertext,
            length: ciphertext_len,
            expected_length: 768 as libc::c_int as size_t,
        };
        init
    };
    let mut ss: output_buffer = {
        let mut init = output_buffer {
            buffer: shared_secret,
            length: shared_secret_len,
            expected_length: 32 as libc::c_int as size_t,
        };
        init
    };
    return ml_kem_common_encapsulate_deterministic(
        Some(
            mlkem512_enc_derand
                as unsafe extern "C" fn(
                    *mut uint8_t,
                    *mut uint8_t,
                    *const uint8_t,
                    *const uint8_t,
                ) -> libc::c_int,
        ),
        ctext,
        ss,
        public_key,
        seed,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_512_encapsulate(
    mut ciphertext: *mut uint8_t,
    mut ciphertext_len: *mut size_t,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut public_key: *const uint8_t,
) -> libc::c_int {
    let mut ctext: output_buffer = {
        let mut init = output_buffer {
            buffer: ciphertext,
            length: ciphertext_len,
            expected_length: 768 as libc::c_int as size_t,
        };
        init
    };
    let mut ss: output_buffer = {
        let mut init = output_buffer {
            buffer: shared_secret,
            length: shared_secret_len,
            expected_length: 32 as libc::c_int as size_t,
        };
        init
    };
    return ml_kem_common_encapsulate(
        Some(
            mlkem512_enc
                as unsafe extern "C" fn(
                    *mut uint8_t,
                    *mut uint8_t,
                    *const uint8_t,
                ) -> libc::c_int,
        ),
        ctext,
        ss,
        public_key,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_512_decapsulate(
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut ciphertext: *const uint8_t,
    mut secret_key: *const uint8_t,
) -> libc::c_int {
    boringssl_ensure_ml_kem_self_test();
    return ml_kem_512_decapsulate_no_self_test(
        shared_secret,
        shared_secret_len,
        ciphertext,
        secret_key,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_512_decapsulate_no_self_test(
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut ciphertext: *const uint8_t,
    mut secret_key: *const uint8_t,
) -> libc::c_int {
    let mut ss: output_buffer = {
        let mut init = output_buffer {
            buffer: shared_secret,
            length: shared_secret_len,
            expected_length: 32 as libc::c_int as size_t,
        };
        init
    };
    return ml_kem_common_decapsulate(
        Some(
            mlkem512_dec
                as unsafe extern "C" fn(
                    *mut uint8_t,
                    *const uint8_t,
                    *const uint8_t,
                ) -> libc::c_int,
        ),
        ss,
        ciphertext,
        secret_key,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_768_keypair_deterministic(
    mut public_key: *mut uint8_t,
    mut public_len: *mut size_t,
    mut secret_key: *mut uint8_t,
    mut secret_len: *mut size_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    boringssl_ensure_ml_kem_self_test();
    return ml_kem_768_keypair_deterministic_no_self_test(
        public_key,
        public_len,
        secret_key,
        secret_len,
        seed,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_768_keypair_deterministic_no_self_test(
    mut public_key: *mut uint8_t,
    mut public_len: *mut size_t,
    mut secret_key: *mut uint8_t,
    mut secret_len: *mut size_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    let mut pkey: output_buffer = {
        let mut init = output_buffer {
            buffer: public_key,
            length: public_len,
            expected_length: 1184 as libc::c_int as size_t,
        };
        init
    };
    let mut skey: output_buffer = {
        let mut init = output_buffer {
            buffer: secret_key,
            length: secret_len,
            expected_length: 2400 as libc::c_int as size_t,
        };
        init
    };
    if check_buffer(pkey) == 0 || check_buffer(skey) == 0 {
        return 1 as libc::c_int;
    }
    let res: libc::c_int = mlkem768_keypair_derand(pkey.buffer, skey.buffer, seed);
    set_written_len_on_success(res, pkey);
    set_written_len_on_success(res, skey);
    return res;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_768_keypair(
    mut public_key: *mut uint8_t,
    mut public_len: *mut size_t,
    mut secret_key: *mut uint8_t,
    mut secret_len: *mut size_t,
) -> libc::c_int {
    let mut pkey: output_buffer = {
        let mut init = output_buffer {
            buffer: public_key,
            length: public_len,
            expected_length: 1184 as libc::c_int as size_t,
        };
        init
    };
    let mut skey: output_buffer = {
        let mut init = output_buffer {
            buffer: secret_key,
            length: secret_len,
            expected_length: 2400 as libc::c_int as size_t,
        };
        init
    };
    return ml_kem_common_keypair(
        Some(
            mlkem768_keypair
                as unsafe extern "C" fn(*mut uint8_t, *mut uint8_t) -> libc::c_int,
        ),
        pkey,
        skey,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_768_encapsulate_deterministic(
    mut ciphertext: *mut uint8_t,
    mut ciphertext_len: *mut size_t,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut public_key: *const uint8_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    boringssl_ensure_ml_kem_self_test();
    return ml_kem_768_encapsulate_deterministic_no_self_test(
        ciphertext,
        ciphertext_len,
        shared_secret,
        shared_secret_len,
        public_key,
        seed,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_768_encapsulate_deterministic_no_self_test(
    mut ciphertext: *mut uint8_t,
    mut ciphertext_len: *mut size_t,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut public_key: *const uint8_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    let mut ctext: output_buffer = {
        let mut init = output_buffer {
            buffer: ciphertext,
            length: ciphertext_len,
            expected_length: 1088 as libc::c_int as size_t,
        };
        init
    };
    let mut ss: output_buffer = {
        let mut init = output_buffer {
            buffer: shared_secret,
            length: shared_secret_len,
            expected_length: 32 as libc::c_int as size_t,
        };
        init
    };
    return ml_kem_common_encapsulate_deterministic(
        Some(
            mlkem768_enc_derand
                as unsafe extern "C" fn(
                    *mut uint8_t,
                    *mut uint8_t,
                    *const uint8_t,
                    *const uint8_t,
                ) -> libc::c_int,
        ),
        ctext,
        ss,
        public_key,
        seed,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_768_encapsulate(
    mut ciphertext: *mut uint8_t,
    mut ciphertext_len: *mut size_t,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut public_key: *const uint8_t,
) -> libc::c_int {
    let mut ctext: output_buffer = {
        let mut init = output_buffer {
            buffer: ciphertext,
            length: ciphertext_len,
            expected_length: 1088 as libc::c_int as size_t,
        };
        init
    };
    let mut ss: output_buffer = {
        let mut init = output_buffer {
            buffer: shared_secret,
            length: shared_secret_len,
            expected_length: 32 as libc::c_int as size_t,
        };
        init
    };
    return ml_kem_common_encapsulate(
        Some(
            mlkem768_enc
                as unsafe extern "C" fn(
                    *mut uint8_t,
                    *mut uint8_t,
                    *const uint8_t,
                ) -> libc::c_int,
        ),
        ctext,
        ss,
        public_key,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_768_decapsulate(
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut ciphertext: *const uint8_t,
    mut secret_key: *const uint8_t,
) -> libc::c_int {
    boringssl_ensure_ml_kem_self_test();
    return ml_kem_768_decapsulate_no_self_test(
        shared_secret,
        shared_secret_len,
        ciphertext,
        secret_key,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_768_decapsulate_no_self_test(
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut ciphertext: *const uint8_t,
    mut secret_key: *const uint8_t,
) -> libc::c_int {
    let mut ss: output_buffer = {
        let mut init = output_buffer {
            buffer: shared_secret,
            length: shared_secret_len,
            expected_length: 32 as libc::c_int as size_t,
        };
        init
    };
    return ml_kem_common_decapsulate(
        Some(
            mlkem768_dec
                as unsafe extern "C" fn(
                    *mut uint8_t,
                    *const uint8_t,
                    *const uint8_t,
                ) -> libc::c_int,
        ),
        ss,
        ciphertext,
        secret_key,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_1024_keypair_deterministic(
    mut public_key: *mut uint8_t,
    mut public_len: *mut size_t,
    mut secret_key: *mut uint8_t,
    mut secret_len: *mut size_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    boringssl_ensure_ml_kem_self_test();
    return ml_kem_1024_keypair_deterministic_no_self_test(
        public_key,
        public_len,
        secret_key,
        secret_len,
        seed,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_1024_keypair_deterministic_no_self_test(
    mut public_key: *mut uint8_t,
    mut public_len: *mut size_t,
    mut secret_key: *mut uint8_t,
    mut secret_len: *mut size_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    let mut pkey: output_buffer = {
        let mut init = output_buffer {
            buffer: public_key,
            length: public_len,
            expected_length: 1568 as libc::c_int as size_t,
        };
        init
    };
    let mut skey: output_buffer = {
        let mut init = output_buffer {
            buffer: secret_key,
            length: secret_len,
            expected_length: 3168 as libc::c_int as size_t,
        };
        init
    };
    if check_buffer(pkey) == 0 || check_buffer(skey) == 0 {
        return 1 as libc::c_int;
    }
    let res: libc::c_int = mlkem1024_keypair_derand(pkey.buffer, skey.buffer, seed);
    set_written_len_on_success(res, pkey);
    set_written_len_on_success(res, skey);
    return res;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_1024_keypair(
    mut public_key: *mut uint8_t,
    mut public_len: *mut size_t,
    mut secret_key: *mut uint8_t,
    mut secret_len: *mut size_t,
) -> libc::c_int {
    let mut pkey: output_buffer = {
        let mut init = output_buffer {
            buffer: public_key,
            length: public_len,
            expected_length: 1568 as libc::c_int as size_t,
        };
        init
    };
    let mut skey: output_buffer = {
        let mut init = output_buffer {
            buffer: secret_key,
            length: secret_len,
            expected_length: 3168 as libc::c_int as size_t,
        };
        init
    };
    return ml_kem_common_keypair(
        Some(
            mlkem1024_keypair
                as unsafe extern "C" fn(*mut uint8_t, *mut uint8_t) -> libc::c_int,
        ),
        pkey,
        skey,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_1024_encapsulate_deterministic(
    mut ciphertext: *mut uint8_t,
    mut ciphertext_len: *mut size_t,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut public_key: *const uint8_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    boringssl_ensure_ml_kem_self_test();
    return ml_kem_1024_encapsulate_deterministic_no_self_test(
        ciphertext,
        ciphertext_len,
        shared_secret,
        shared_secret_len,
        public_key,
        seed,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_1024_encapsulate_deterministic_no_self_test(
    mut ciphertext: *mut uint8_t,
    mut ciphertext_len: *mut size_t,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut public_key: *const uint8_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    let mut ctext: output_buffer = {
        let mut init = output_buffer {
            buffer: ciphertext,
            length: ciphertext_len,
            expected_length: 1568 as libc::c_int as size_t,
        };
        init
    };
    let mut ss: output_buffer = {
        let mut init = output_buffer {
            buffer: shared_secret,
            length: shared_secret_len,
            expected_length: 32 as libc::c_int as size_t,
        };
        init
    };
    return ml_kem_common_encapsulate_deterministic(
        Some(
            mlkem1024_enc_derand
                as unsafe extern "C" fn(
                    *mut uint8_t,
                    *mut uint8_t,
                    *const uint8_t,
                    *const uint8_t,
                ) -> libc::c_int,
        ),
        ctext,
        ss,
        public_key,
        seed,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_1024_encapsulate(
    mut ciphertext: *mut uint8_t,
    mut ciphertext_len: *mut size_t,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut public_key: *const uint8_t,
) -> libc::c_int {
    let mut ctext: output_buffer = {
        let mut init = output_buffer {
            buffer: ciphertext,
            length: ciphertext_len,
            expected_length: 1568 as libc::c_int as size_t,
        };
        init
    };
    let mut ss: output_buffer = {
        let mut init = output_buffer {
            buffer: shared_secret,
            length: shared_secret_len,
            expected_length: 32 as libc::c_int as size_t,
        };
        init
    };
    return ml_kem_common_encapsulate(
        Some(
            mlkem1024_enc
                as unsafe extern "C" fn(
                    *mut uint8_t,
                    *mut uint8_t,
                    *const uint8_t,
                ) -> libc::c_int,
        ),
        ctext,
        ss,
        public_key,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_1024_decapsulate(
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut ciphertext: *const uint8_t,
    mut secret_key: *const uint8_t,
) -> libc::c_int {
    boringssl_ensure_ml_kem_self_test();
    return ml_kem_1024_decapsulate_no_self_test(
        shared_secret,
        shared_secret_len,
        ciphertext,
        secret_key,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_1024_decapsulate_no_self_test(
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut ciphertext: *const uint8_t,
    mut secret_key: *const uint8_t,
) -> libc::c_int {
    let mut ss: output_buffer = {
        let mut init = output_buffer {
            buffer: shared_secret,
            length: shared_secret_len,
            expected_length: 32 as libc::c_int as size_t,
        };
        init
    };
    return ml_kem_common_decapsulate(
        Some(
            mlkem1024_dec
                as unsafe extern "C" fn(
                    *mut uint8_t,
                    *const uint8_t,
                    *const uint8_t,
                ) -> libc::c_int,
        ),
        ss,
        ciphertext,
        secret_key,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_common_keypair(
    mut keypair: Option::<
        unsafe extern "C" fn(*mut uint8_t, *mut uint8_t) -> libc::c_int,
    >,
    mut public_key: output_buffer,
    mut secret_key: output_buffer,
) -> libc::c_int {
    boringssl_ensure_ml_kem_self_test();
    if check_buffer(public_key) == 0 || check_buffer(secret_key) == 0 {
        return 1 as libc::c_int;
    }
    let res: libc::c_int = keypair
        .expect("non-null function pointer")(public_key.buffer, secret_key.buffer);
    set_written_len_on_success(res, public_key);
    set_written_len_on_success(res, secret_key);
    return res;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_common_encapsulate_deterministic(
    mut encapsulate: Option::<
        unsafe extern "C" fn(
            *mut uint8_t,
            *mut uint8_t,
            *const uint8_t,
            *const uint8_t,
        ) -> libc::c_int,
    >,
    mut ciphertext: output_buffer,
    mut shared_secret: output_buffer,
    mut public_key: *const uint8_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    if check_buffer(ciphertext) == 0 || check_buffer(shared_secret) == 0 {
        return 1 as libc::c_int;
    }
    let res: libc::c_int = encapsulate
        .expect(
            "non-null function pointer",
        )(ciphertext.buffer, shared_secret.buffer, public_key, seed);
    set_written_len_on_success(res, ciphertext);
    set_written_len_on_success(res, shared_secret);
    return res;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_common_encapsulate(
    mut encapsulate: Option::<
        unsafe extern "C" fn(*mut uint8_t, *mut uint8_t, *const uint8_t) -> libc::c_int,
    >,
    mut ciphertext: output_buffer,
    mut shared_secret: output_buffer,
    mut public_key: *const uint8_t,
) -> libc::c_int {
    boringssl_ensure_ml_kem_self_test();
    if check_buffer(ciphertext) == 0 || check_buffer(shared_secret) == 0 {
        return 1 as libc::c_int;
    }
    let res: libc::c_int = encapsulate
        .expect(
            "non-null function pointer",
        )(ciphertext.buffer, shared_secret.buffer, public_key);
    set_written_len_on_success(res, ciphertext);
    set_written_len_on_success(res, shared_secret);
    return res;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ml_kem_common_decapsulate(
    mut decapsulate: Option::<
        unsafe extern "C" fn(*mut uint8_t, *const uint8_t, *const uint8_t) -> libc::c_int,
    >,
    mut shared_secret: output_buffer,
    mut ciphertext: *const uint8_t,
    mut secret_key: *const uint8_t,
) -> libc::c_int {
    if check_buffer(shared_secret) == 0 {
        return 1 as libc::c_int;
    }
    let res: libc::c_int = decapsulate
        .expect(
            "non-null function pointer",
        )(shared_secret.buffer, ciphertext, secret_key);
    set_written_len_on_success(res, shared_secret);
    return res;
}
