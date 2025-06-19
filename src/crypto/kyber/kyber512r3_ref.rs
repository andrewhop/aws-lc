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
extern "C" {
    fn RAND_bytes(buf: *mut uint8_t, len: size_t) -> libc::c_int;
    fn pqcrystals_kyber_fips202_ref_shake128_absorb_once(
        state: *mut keccak_state,
        in_0: *const uint8_t,
        inlen: size_t,
    );
    fn pqcrystals_kyber_fips202_ref_shake128_squeezeblocks(
        out: *mut uint8_t,
        nblocks: size_t,
        state: *mut keccak_state,
    );
    fn pqcrystals_kyber_fips202_ref_shake256(
        out: *mut uint8_t,
        outlen: size_t,
        in_0: *const uint8_t,
        inlen: size_t,
    );
    fn pqcrystals_kyber_fips202_ref_sha3_256(
        h: *mut uint8_t,
        in_0: *const uint8_t,
        inlen: size_t,
    );
    fn pqcrystals_kyber_fips202_ref_sha3_512(
        h: *mut uint8_t,
        in_0: *const uint8_t,
        inlen: size_t,
    );
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
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
#[repr(C)]
pub struct poly {
    pub coeffs: [int16_t; 256],
}
pub type crypto_word_t = uint64_t;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_184_error_is_value_exceeds_int16_max {
    #[bitfield(
        name = "static_assertion_at_line_184_error_is_value_exceeds_int16_max",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_184_error_is_value_exceeds_int16_max: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct polyvec {
    pub vec: [poly; 2],
}
pub type keccak_state = xof_state;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xof_state {
    pub s: [uint64_t; 25],
    pub pos: libc::c_uint,
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_poly_compress(
    mut r: *mut uint8_t,
    mut a: *const poly,
) {
    let mut i: libc::c_uint = 0;
    let mut j: libc::c_uint = 0;
    let mut u: int16_t = 0;
    let mut d0: uint32_t = 0;
    let mut t: [uint8_t; 8] = [0; 8];
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 8 as libc::c_int) as libc::c_uint {
        j = 0 as libc::c_int as libc::c_uint;
        while j < 8 as libc::c_int as libc::c_uint {
            u = (*a)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(j) as usize];
            u = (u as libc::c_int
                + (u as libc::c_int >> 15 as libc::c_int & 3329 as libc::c_int))
                as int16_t;
            d0 = ((u as libc::c_int) << 4 as libc::c_int) as uint32_t;
            d0 = d0.wrapping_add(1665 as libc::c_int as uint32_t);
            d0 = d0 * 80635 as libc::c_int as uint32_t;
            d0 >>= 28 as libc::c_int;
            t[j as usize] = (d0 & 0xf as libc::c_int as uint32_t) as uint8_t;
            j = j.wrapping_add(1);
            j;
        }
        *r
            .offset(
                0 as libc::c_int as isize,
            ) = (t[0 as libc::c_int as usize] as libc::c_int
            | (t[1 as libc::c_int as usize] as libc::c_int) << 4 as libc::c_int)
            as uint8_t;
        *r
            .offset(
                1 as libc::c_int as isize,
            ) = (t[2 as libc::c_int as usize] as libc::c_int
            | (t[3 as libc::c_int as usize] as libc::c_int) << 4 as libc::c_int)
            as uint8_t;
        *r
            .offset(
                2 as libc::c_int as isize,
            ) = (t[4 as libc::c_int as usize] as libc::c_int
            | (t[5 as libc::c_int as usize] as libc::c_int) << 4 as libc::c_int)
            as uint8_t;
        *r
            .offset(
                3 as libc::c_int as isize,
            ) = (t[6 as libc::c_int as usize] as libc::c_int
            | (t[7 as libc::c_int as usize] as libc::c_int) << 4 as libc::c_int)
            as uint8_t;
        r = r.offset(4 as libc::c_int as isize);
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_poly_decompress(
    mut r: *mut poly,
    mut a: *const uint8_t,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 2 as libc::c_int) as libc::c_uint {
        (*r)
            .coeffs[(2 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(0 as libc::c_int as libc::c_uint)
            as usize] = ((*a.offset(0 as libc::c_int as isize) as libc::c_int
            & 15 as libc::c_int) as uint16_t as libc::c_int * 3329 as libc::c_int
            + 8 as libc::c_int >> 4 as libc::c_int) as int16_t;
        (*r)
            .coeffs[(2 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(1 as libc::c_int as libc::c_uint)
            as usize] = ((*a.offset(0 as libc::c_int as isize) as libc::c_int
            >> 4 as libc::c_int) as uint16_t as libc::c_int * 3329 as libc::c_int
            + 8 as libc::c_int >> 4 as libc::c_int) as int16_t;
        a = a.offset(1 as libc::c_int as isize);
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_poly_tobytes(
    mut r: *mut uint8_t,
    mut a: *const poly,
) {
    let mut i: libc::c_uint = 0;
    let mut t0: uint16_t = 0;
    let mut t1: uint16_t = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 2 as libc::c_int) as libc::c_uint {
        t0 = (*a).coeffs[(2 as libc::c_int as libc::c_uint).wrapping_mul(i) as usize]
            as uint16_t;
        t0 = (t0 as libc::c_int
            + (t0 as int16_t as libc::c_int >> 15 as libc::c_int & 3329 as libc::c_int))
            as uint16_t;
        t1 = (*a)
            .coeffs[(2 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(1 as libc::c_int as libc::c_uint) as usize] as uint16_t;
        t1 = (t1 as libc::c_int
            + (t1 as int16_t as libc::c_int >> 15 as libc::c_int & 3329 as libc::c_int))
            as uint16_t;
        *r
            .offset(
                (3 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(0 as libc::c_int as libc::c_uint) as isize,
            ) = (t0 as libc::c_int >> 0 as libc::c_int) as uint8_t;
        *r
            .offset(
                (3 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
            ) = (t0 as libc::c_int >> 8 as libc::c_int
            | (t1 as libc::c_int) << 4 as libc::c_int) as uint8_t;
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
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_poly_frombytes(
    mut r: *mut poly,
    mut a: *const uint8_t,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 2 as libc::c_int) as libc::c_uint {
        (*r)
            .coeffs[(2 as libc::c_int as libc::c_uint).wrapping_mul(i)
            as usize] = ((*a
            .offset(
                (3 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(0 as libc::c_int as libc::c_uint) as isize,
            ) as libc::c_int >> 0 as libc::c_int
            | (*a
                .offset(
                    (3 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
                ) as uint16_t as libc::c_int) << 8 as libc::c_int)
            & 0xfff as libc::c_int) as int16_t;
        (*r)
            .coeffs[(2 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(1 as libc::c_int as libc::c_uint)
            as usize] = ((*a
            .offset(
                (3 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
            ) as libc::c_int >> 4 as libc::c_int
            | (*a
                .offset(
                    (3 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
                ) as uint16_t as libc::c_int) << 4 as libc::c_int)
            & 0xfff as libc::c_int) as int16_t;
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_poly_frommsg(
    mut r: *mut poly,
    mut msg: *const uint8_t,
) {
    let mut i: libc::c_uint = 0;
    let mut j: libc::c_uint = 0;
    let mut mask: crypto_word_t = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 8 as libc::c_int) as libc::c_uint {
        j = 0 as libc::c_int as libc::c_uint;
        while j < 8 as libc::c_int as libc::c_uint {
            mask = constant_time_is_zero_w(
                (*msg.offset(i as isize) as libc::c_int >> j & 1 as libc::c_int)
                    as crypto_word_t,
            );
            (*r)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(j)
                as usize] = constant_time_select_w(
                mask,
                0 as libc::c_int as crypto_word_t,
                ((3329 as libc::c_int + 1 as libc::c_int) / 2 as libc::c_int)
                    as crypto_word_t,
            ) as int16_t;
            j = j.wrapping_add(1);
            j;
        }
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_poly_tomsg(
    mut msg: *mut uint8_t,
    mut a: *const poly,
) {
    let mut i: libc::c_uint = 0;
    let mut j: libc::c_uint = 0;
    let mut t: uint32_t = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 8 as libc::c_int) as libc::c_uint {
        *msg.offset(i as isize) = 0 as libc::c_int as uint8_t;
        j = 0 as libc::c_int as libc::c_uint;
        while j < 8 as libc::c_int as libc::c_uint {
            t = (*a)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(j) as usize] as uint32_t;
            t <<= 1 as libc::c_int;
            t = t.wrapping_add(1665 as libc::c_int as uint32_t);
            t = t * 80635 as libc::c_int as uint32_t;
            t >>= 28 as libc::c_int;
            t &= 1 as libc::c_int as uint32_t;
            let ref mut fresh0 = *msg.offset(i as isize);
            *fresh0 = (*fresh0 as uint32_t | t << j) as uint8_t;
            j = j.wrapping_add(1);
            j;
        }
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_poly_getnoise_eta1(
    mut r: *mut poly,
    mut seed: *const uint8_t,
    mut nonce: uint8_t,
) {
    let mut buf: [uint8_t; 192] = [0; 192];
    pqcrystals_kyber512_ref_kyber_shake256_prf(
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 192]>() as libc::c_ulong,
        seed,
        nonce,
    );
    pqcrystals_kyber512_ref_poly_cbd_eta1(r, buf.as_mut_ptr() as *const uint8_t);
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_poly_getnoise_eta2(
    mut r: *mut poly,
    mut seed: *const uint8_t,
    mut nonce: uint8_t,
) {
    let mut buf: [uint8_t; 128] = [0; 128];
    pqcrystals_kyber512_ref_kyber_shake256_prf(
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 128]>() as libc::c_ulong,
        seed,
        nonce,
    );
    pqcrystals_kyber512_ref_poly_cbd_eta2(r, buf.as_mut_ptr() as *const uint8_t);
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_poly_ntt(mut r: *mut poly) {
    pqcrystals_kyber512_ref_ntt(((*r).coeffs).as_mut_ptr());
    pqcrystals_kyber512_ref_poly_reduce(r);
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_poly_invntt_tomont(mut r: *mut poly) {
    pqcrystals_kyber512_ref_invntt(((*r).coeffs).as_mut_ptr());
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_poly_basemul_montgomery(
    mut r: *mut poly,
    mut a: *const poly,
    mut b: *const poly,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 4 as libc::c_int) as libc::c_uint {
        pqcrystals_kyber512_ref_basemul(
            &mut *((*r).coeffs)
                .as_mut_ptr()
                .offset((4 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize),
            &*((*a).coeffs)
                .as_ptr()
                .offset((4 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize),
            &*((*b).coeffs)
                .as_ptr()
                .offset((4 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize),
            pqcrystals_kyber512_ref_zetas[(64 as libc::c_int as libc::c_uint)
                .wrapping_add(i) as usize],
        );
        pqcrystals_kyber512_ref_basemul(
            &mut *((*r).coeffs)
                .as_mut_ptr()
                .offset(
                    (4 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
                ),
            &*((*a).coeffs)
                .as_ptr()
                .offset(
                    (4 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
                ),
            &*((*b).coeffs)
                .as_ptr()
                .offset(
                    (4 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
                ),
            -(pqcrystals_kyber512_ref_zetas[(64 as libc::c_int as libc::c_uint)
                .wrapping_add(i) as usize] as libc::c_int) as int16_t,
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_poly_tomont(mut r: *mut poly) {
    let mut i: libc::c_uint = 0;
    let f: int16_t = ((1 as libc::c_ulonglong) << 32 as libc::c_int)
        .wrapping_rem(3329 as libc::c_int as libc::c_ulonglong) as int16_t;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 256 as libc::c_int as libc::c_uint {
        (*r)
            .coeffs[i
            as usize] = pqcrystals_kyber512_ref_montgomery_reduce(
            (*r).coeffs[i as usize] as int32_t * f as libc::c_int,
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_poly_reduce(mut r: *mut poly) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 256 as libc::c_int as libc::c_uint {
        (*r)
            .coeffs[i
            as usize] = pqcrystals_kyber512_ref_barrett_reduce((*r).coeffs[i as usize]);
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_poly_add(
    mut r: *mut poly,
    mut a: *const poly,
    mut b: *const poly,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 256 as libc::c_int as libc::c_uint {
        (*r)
            .coeffs[i
            as usize] = ((*a).coeffs[i as usize] as libc::c_int
            + (*b).coeffs[i as usize] as libc::c_int) as int16_t;
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_poly_sub(
    mut r: *mut poly,
    mut a: *const poly,
    mut b: *const poly,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 256 as libc::c_int as libc::c_uint {
        (*r)
            .coeffs[i
            as usize] = ((*a).coeffs[i as usize] as libc::c_int
            - (*b).coeffs[i as usize] as libc::c_int) as int16_t;
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn load32_littleendian(mut x: *const uint8_t) -> uint32_t {
    let mut r: uint32_t = 0;
    r = *x.offset(0 as libc::c_int as isize) as uint32_t;
    r |= (*x.offset(1 as libc::c_int as isize) as uint32_t) << 8 as libc::c_int;
    r |= (*x.offset(2 as libc::c_int as isize) as uint32_t) << 16 as libc::c_int;
    r |= (*x.offset(3 as libc::c_int as isize) as uint32_t) << 24 as libc::c_int;
    return r;
}
unsafe extern "C" fn load24_littleendian(mut x: *const uint8_t) -> uint32_t {
    let mut r: uint32_t = 0;
    r = *x.offset(0 as libc::c_int as isize) as uint32_t;
    r |= (*x.offset(1 as libc::c_int as isize) as uint32_t) << 8 as libc::c_int;
    r |= (*x.offset(2 as libc::c_int as isize) as uint32_t) << 16 as libc::c_int;
    return r;
}
unsafe extern "C" fn cbd2(mut r: *mut poly, mut buf: *const uint8_t) {
    let mut i: libc::c_uint = 0;
    let mut j: libc::c_uint = 0;
    let mut t: uint32_t = 0;
    let mut d: uint32_t = 0;
    let mut a: int16_t = 0;
    let mut b: int16_t = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 8 as libc::c_int) as libc::c_uint {
        t = load32_littleendian(
            buf.offset((4 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize),
        );
        d = t & 0x55555555 as libc::c_int as uint32_t;
        d = d
            .wrapping_add(t >> 1 as libc::c_int & 0x55555555 as libc::c_int as uint32_t);
        j = 0 as libc::c_int as libc::c_uint;
        while j < 8 as libc::c_int as libc::c_uint {
            a = (d
                >> (4 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(0 as libc::c_int as libc::c_uint)
                & 0x3 as libc::c_int as uint32_t) as int16_t;
            b = (d
                >> (4 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(2 as libc::c_int as libc::c_uint)
                & 0x3 as libc::c_int as uint32_t) as int16_t;
            (*r)
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
unsafe extern "C" fn cbd3(mut r: *mut poly, mut buf: *const uint8_t) {
    let mut i: libc::c_uint = 0;
    let mut j: libc::c_uint = 0;
    let mut t: uint32_t = 0;
    let mut d: uint32_t = 0;
    let mut a: int16_t = 0;
    let mut b: int16_t = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 4 as libc::c_int) as libc::c_uint {
        t = load24_littleendian(
            buf.offset((3 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize),
        );
        d = t & 0x249249 as libc::c_int as uint32_t;
        d = d.wrapping_add(t >> 1 as libc::c_int & 0x249249 as libc::c_int as uint32_t);
        d = d.wrapping_add(t >> 2 as libc::c_int & 0x249249 as libc::c_int as uint32_t);
        j = 0 as libc::c_int as libc::c_uint;
        while j < 4 as libc::c_int as libc::c_uint {
            a = (d
                >> (6 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(0 as libc::c_int as libc::c_uint)
                & 0x7 as libc::c_int as uint32_t) as int16_t;
            b = (d
                >> (6 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(3 as libc::c_int as libc::c_uint)
                & 0x7 as libc::c_int as uint32_t) as int16_t;
            (*r)
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
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_poly_cbd_eta1(
    mut r: *mut poly,
    mut buf: *const uint8_t,
) {
    cbd3(r, buf);
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_poly_cbd_eta2(
    mut r: *mut poly,
    mut buf: *const uint8_t,
) {
    cbd2(r, buf);
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_polyvec_compress(
    mut r: *mut uint8_t,
    mut a: *const polyvec,
) {
    let mut i: libc::c_uint = 0;
    let mut j: libc::c_uint = 0;
    let mut k: libc::c_uint = 0;
    let mut d0: uint64_t = 0;
    let mut t: [uint16_t; 4] = [0; 4];
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        j = 0 as libc::c_int as libc::c_uint;
        while j < (256 as libc::c_int / 4 as libc::c_int) as libc::c_uint {
            k = 0 as libc::c_int as libc::c_uint;
            while k < 4 as libc::c_int as libc::c_uint {
                t[k
                    as usize] = (*a)
                    .vec[i as usize]
                    .coeffs[(4 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(k) as usize] as uint16_t;
                t[k
                    as usize] = (t[k as usize] as libc::c_int
                    + (t[k as usize] as int16_t as libc::c_int >> 15 as libc::c_int
                        & 3329 as libc::c_int)) as uint16_t;
                d0 = t[k as usize] as uint64_t;
                d0 <<= 10 as libc::c_int;
                d0 = d0.wrapping_add(1665 as libc::c_int as uint64_t);
                d0 = d0 * 1290167 as libc::c_int as uint64_t;
                d0 >>= 32 as libc::c_int;
                t[k as usize] = (d0 & 0x3ff as libc::c_int as uint64_t) as uint16_t;
                k = k.wrapping_add(1);
                k;
            }
            *r
                .offset(
                    0 as libc::c_int as isize,
                ) = (t[0 as libc::c_int as usize] as libc::c_int >> 0 as libc::c_int)
                as uint8_t;
            *r
                .offset(
                    1 as libc::c_int as isize,
                ) = (t[0 as libc::c_int as usize] as libc::c_int >> 8 as libc::c_int
                | (t[1 as libc::c_int as usize] as libc::c_int) << 2 as libc::c_int)
                as uint8_t;
            *r
                .offset(
                    2 as libc::c_int as isize,
                ) = (t[1 as libc::c_int as usize] as libc::c_int >> 6 as libc::c_int
                | (t[2 as libc::c_int as usize] as libc::c_int) << 4 as libc::c_int)
                as uint8_t;
            *r
                .offset(
                    3 as libc::c_int as isize,
                ) = (t[2 as libc::c_int as usize] as libc::c_int >> 4 as libc::c_int
                | (t[3 as libc::c_int as usize] as libc::c_int) << 6 as libc::c_int)
                as uint8_t;
            *r
                .offset(
                    4 as libc::c_int as isize,
                ) = (t[3 as libc::c_int as usize] as libc::c_int >> 2 as libc::c_int)
                as uint8_t;
            r = r.offset(5 as libc::c_int as isize);
            j = j.wrapping_add(1);
            j;
        }
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_polyvec_decompress(
    mut r: *mut polyvec,
    mut a: *const uint8_t,
) {
    let mut i: libc::c_uint = 0;
    let mut j: libc::c_uint = 0;
    let mut k: libc::c_uint = 0;
    let mut t: [uint16_t; 4] = [0; 4];
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        j = 0 as libc::c_int as libc::c_uint;
        while j < (256 as libc::c_int / 4 as libc::c_int) as libc::c_uint {
            t[0 as libc::c_int
                as usize] = (*a.offset(0 as libc::c_int as isize) as libc::c_int
                >> 0 as libc::c_int
                | (*a.offset(1 as libc::c_int as isize) as uint16_t as libc::c_int)
                    << 8 as libc::c_int) as uint16_t;
            t[1 as libc::c_int
                as usize] = (*a.offset(1 as libc::c_int as isize) as libc::c_int
                >> 2 as libc::c_int
                | (*a.offset(2 as libc::c_int as isize) as uint16_t as libc::c_int)
                    << 6 as libc::c_int) as uint16_t;
            t[2 as libc::c_int
                as usize] = (*a.offset(2 as libc::c_int as isize) as libc::c_int
                >> 4 as libc::c_int
                | (*a.offset(3 as libc::c_int as isize) as uint16_t as libc::c_int)
                    << 4 as libc::c_int) as uint16_t;
            t[3 as libc::c_int
                as usize] = (*a.offset(3 as libc::c_int as isize) as libc::c_int
                >> 6 as libc::c_int
                | (*a.offset(4 as libc::c_int as isize) as uint16_t as libc::c_int)
                    << 2 as libc::c_int) as uint16_t;
            a = a.offset(5 as libc::c_int as isize);
            k = 0 as libc::c_int as libc::c_uint;
            while k < 4 as libc::c_int as libc::c_uint {
                (*r)
                    .vec[i as usize]
                    .coeffs[(4 as libc::c_int as libc::c_uint)
                    .wrapping_mul(j)
                    .wrapping_add(k)
                    as usize] = (((t[k as usize] as libc::c_int & 0x3ff as libc::c_int)
                    as uint32_t * 3329 as libc::c_int as uint32_t)
                    .wrapping_add(512 as libc::c_int as uint32_t) >> 10 as libc::c_int)
                    as int16_t;
                k = k.wrapping_add(1);
                k;
            }
            j = j.wrapping_add(1);
            j;
        }
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_polyvec_tobytes(
    mut r: *mut uint8_t,
    mut a: *const polyvec,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        pqcrystals_kyber512_ref_poly_tobytes(
            r.offset(i.wrapping_mul(384 as libc::c_int as libc::c_uint) as isize),
            &*((*a).vec).as_ptr().offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_polyvec_frombytes(
    mut r: *mut polyvec,
    mut a: *const uint8_t,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        pqcrystals_kyber512_ref_poly_frombytes(
            &mut *((*r).vec).as_mut_ptr().offset(i as isize),
            a.offset(i.wrapping_mul(384 as libc::c_int as libc::c_uint) as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_polyvec_ntt(mut r: *mut polyvec) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        pqcrystals_kyber512_ref_poly_ntt(
            &mut *((*r).vec).as_mut_ptr().offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_polyvec_invntt_tomont(
    mut r: *mut polyvec,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        pqcrystals_kyber512_ref_poly_invntt_tomont(
            &mut *((*r).vec).as_mut_ptr().offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_polyvec_basemul_acc_montgomery(
    mut r: *mut poly,
    mut a: *const polyvec,
    mut b: *const polyvec,
) {
    let mut i: libc::c_uint = 0;
    let mut t: poly = poly { coeffs: [0; 256] };
    pqcrystals_kyber512_ref_poly_basemul_montgomery(
        r,
        &*((*a).vec).as_ptr().offset(0 as libc::c_int as isize),
        &*((*b).vec).as_ptr().offset(0 as libc::c_int as isize),
    );
    i = 1 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        pqcrystals_kyber512_ref_poly_basemul_montgomery(
            &mut t,
            &*((*a).vec).as_ptr().offset(i as isize),
            &*((*b).vec).as_ptr().offset(i as isize),
        );
        pqcrystals_kyber512_ref_poly_add(r, r, &mut t);
        i = i.wrapping_add(1);
        i;
    }
    pqcrystals_kyber512_ref_poly_reduce(r);
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_polyvec_reduce(mut r: *mut polyvec) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        pqcrystals_kyber512_ref_poly_reduce(
            &mut *((*r).vec).as_mut_ptr().offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_polyvec_add(
    mut r: *mut polyvec,
    mut a: *const polyvec,
    mut b: *const polyvec,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        pqcrystals_kyber512_ref_poly_add(
            &mut *((*r).vec).as_mut_ptr().offset(i as isize),
            &*((*a).vec).as_ptr().offset(i as isize),
            &*((*b).vec).as_ptr().offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn pack_pk(
    mut r: *mut uint8_t,
    mut pk: *mut polyvec,
    mut seed: *const uint8_t,
) {
    let mut i: size_t = 0;
    pqcrystals_kyber512_ref_polyvec_tobytes(r, pk);
    i = 0 as libc::c_int as size_t;
    while i < 32 as libc::c_int as size_t {
        *r
            .offset(
                i.wrapping_add((2 as libc::c_int * 384 as libc::c_int) as size_t)
                    as isize,
            ) = *seed.offset(i as isize);
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn unpack_pk(
    mut pk: *mut polyvec,
    mut seed: *mut uint8_t,
    mut packedpk: *const uint8_t,
) {
    let mut i: size_t = 0;
    pqcrystals_kyber512_ref_polyvec_frombytes(pk, packedpk);
    i = 0 as libc::c_int as size_t;
    while i < 32 as libc::c_int as size_t {
        *seed
            .offset(
                i as isize,
            ) = *packedpk
            .offset(
                i.wrapping_add((2 as libc::c_int * 384 as libc::c_int) as size_t)
                    as isize,
            );
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn pack_sk(mut r: *mut uint8_t, mut sk: *mut polyvec) {
    pqcrystals_kyber512_ref_polyvec_tobytes(r, sk);
}
unsafe extern "C" fn unpack_sk(mut sk: *mut polyvec, mut packedsk: *const uint8_t) {
    pqcrystals_kyber512_ref_polyvec_frombytes(sk, packedsk);
}
unsafe extern "C" fn pack_ciphertext(
    mut r: *mut uint8_t,
    mut b: *mut polyvec,
    mut v: *mut poly,
) {
    pqcrystals_kyber512_ref_polyvec_compress(r, b);
    pqcrystals_kyber512_ref_poly_compress(
        r.offset((2 as libc::c_int * 320 as libc::c_int) as isize),
        v,
    );
}
unsafe extern "C" fn unpack_ciphertext(
    mut b: *mut polyvec,
    mut v: *mut poly,
    mut c: *const uint8_t,
) {
    pqcrystals_kyber512_ref_polyvec_decompress(b, c);
    pqcrystals_kyber512_ref_poly_decompress(
        v,
        c.offset((2 as libc::c_int * 320 as libc::c_int) as isize),
    );
}
unsafe extern "C" fn rej_uniform(
    mut r: *mut int16_t,
    mut len: libc::c_uint,
    mut buf: *const uint8_t,
    mut buflen: libc::c_uint,
) -> libc::c_uint {
    let mut ctr: libc::c_uint = 0;
    let mut pos: libc::c_uint = 0;
    let mut val0: uint16_t = 0;
    let mut val1: uint16_t = 0;
    pos = 0 as libc::c_int as libc::c_uint;
    ctr = pos;
    while ctr < len && pos.wrapping_add(3 as libc::c_int as libc::c_uint) <= buflen {
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
            let fresh1 = ctr;
            ctr = ctr.wrapping_add(1);
            *r.offset(fresh1 as isize) = val0 as int16_t;
        }
        if ctr < len && (val1 as libc::c_int) < 3329 as libc::c_int {
            let fresh2 = ctr;
            ctr = ctr.wrapping_add(1);
            *r.offset(fresh2 as isize) = val1 as int16_t;
        }
    }
    return ctr;
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_gen_matrix(
    mut a: *mut polyvec,
    mut seed: *const uint8_t,
    mut transposed: libc::c_int,
) {
    let mut ctr: libc::c_uint = 0;
    let mut i: libc::c_uint = 0;
    let mut j: libc::c_uint = 0;
    let mut k: libc::c_uint = 0;
    let mut buflen: libc::c_uint = 0;
    let mut off: libc::c_uint = 0;
    let mut buf: [uint8_t; 506] = [0; 506];
    let mut state: xof_state = xof_state { s: [0; 25], pos: 0 };
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        j = 0 as libc::c_int as libc::c_uint;
        while j < 2 as libc::c_int as libc::c_uint {
            if transposed != 0 {
                pqcrystals_kyber512_ref_kyber_shake128_absorb(
                    &mut state,
                    seed,
                    i as uint8_t,
                    j as uint8_t,
                );
            } else {
                pqcrystals_kyber512_ref_kyber_shake128_absorb(
                    &mut state,
                    seed,
                    j as uint8_t,
                    i as uint8_t,
                );
            }
            pqcrystals_kyber_fips202_ref_shake128_squeezeblocks(
                buf.as_mut_ptr(),
                ((12 as libc::c_int * 256 as libc::c_int / 8 as libc::c_int
                    * ((1 as libc::c_int) << 12 as libc::c_int) / 3329 as libc::c_int
                    + 168 as libc::c_int) / 168 as libc::c_int) as size_t,
                &mut state,
            );
            buflen = ((12 as libc::c_int * 256 as libc::c_int / 8 as libc::c_int
                * ((1 as libc::c_int) << 12 as libc::c_int) / 3329 as libc::c_int
                + 168 as libc::c_int) / 168 as libc::c_int * 168 as libc::c_int)
                as libc::c_uint;
            ctr = rej_uniform(
                ((*a.offset(i as isize)).vec[j as usize].coeffs).as_mut_ptr(),
                256 as libc::c_int as libc::c_uint,
                buf.as_mut_ptr(),
                buflen,
            );
            while ctr < 256 as libc::c_int as libc::c_uint {
                off = buflen.wrapping_rem(3 as libc::c_int as libc::c_uint);
                k = 0 as libc::c_int as libc::c_uint;
                while k < off {
                    buf[k
                        as usize] = buf[buflen.wrapping_sub(off).wrapping_add(k)
                        as usize];
                    k = k.wrapping_add(1);
                    k;
                }
                pqcrystals_kyber_fips202_ref_shake128_squeezeblocks(
                    buf.as_mut_ptr().offset(off as isize),
                    1 as libc::c_int as size_t,
                    &mut state,
                );
                buflen = off.wrapping_add(168 as libc::c_int as libc::c_uint);
                ctr = ctr
                    .wrapping_add(
                        rej_uniform(
                            ((*a.offset(i as isize)).vec[j as usize].coeffs)
                                .as_mut_ptr()
                                .offset(ctr as isize),
                            (256 as libc::c_int as libc::c_uint).wrapping_sub(ctr),
                            buf.as_mut_ptr(),
                            buflen,
                        ),
                    );
            }
            j = j.wrapping_add(1);
            j;
        }
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_indcpa_keypair_derand(
    mut pk: *mut uint8_t,
    mut sk: *mut uint8_t,
    mut coins: *const uint8_t,
) {
    let mut i: libc::c_uint = 0;
    let mut buf: [uint8_t; 64] = [0; 64];
    let mut publicseed: *const uint8_t = buf.as_mut_ptr();
    let mut noiseseed: *const uint8_t = buf
        .as_mut_ptr()
        .offset(32 as libc::c_int as isize);
    let mut nonce: uint8_t = 0 as libc::c_int as uint8_t;
    let mut a: [polyvec; 2] = [polyvec {
        vec: [poly { coeffs: [0; 256] }; 2],
    }; 2];
    let mut e: polyvec = polyvec {
        vec: [poly { coeffs: [0; 256] }; 2],
    };
    let mut pkpv: polyvec = polyvec {
        vec: [poly { coeffs: [0; 256] }; 2],
    };
    let mut skpv: polyvec = polyvec {
        vec: [poly { coeffs: [0; 256] }; 2],
    };
    pqcrystals_kyber_fips202_ref_sha3_512(
        buf.as_mut_ptr(),
        coins,
        32 as libc::c_int as size_t,
    );
    pqcrystals_kyber512_ref_gen_matrix(a.as_mut_ptr(), publicseed, 0 as libc::c_int);
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        let fresh3 = nonce;
        nonce = nonce.wrapping_add(1);
        pqcrystals_kyber512_ref_poly_getnoise_eta1(
            &mut *(skpv.vec).as_mut_ptr().offset(i as isize),
            noiseseed,
            fresh3,
        );
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        let fresh4 = nonce;
        nonce = nonce.wrapping_add(1);
        pqcrystals_kyber512_ref_poly_getnoise_eta1(
            &mut *(e.vec).as_mut_ptr().offset(i as isize),
            noiseseed,
            fresh4,
        );
        i = i.wrapping_add(1);
        i;
    }
    pqcrystals_kyber512_ref_polyvec_ntt(&mut skpv);
    pqcrystals_kyber512_ref_polyvec_ntt(&mut e);
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        pqcrystals_kyber512_ref_polyvec_basemul_acc_montgomery(
            &mut *(pkpv.vec).as_mut_ptr().offset(i as isize),
            &mut *a.as_mut_ptr().offset(i as isize),
            &mut skpv,
        );
        pqcrystals_kyber512_ref_poly_tomont(
            &mut *(pkpv.vec).as_mut_ptr().offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
    pqcrystals_kyber512_ref_polyvec_add(&mut pkpv, &mut pkpv, &mut e);
    pqcrystals_kyber512_ref_polyvec_reduce(&mut pkpv);
    pack_sk(sk, &mut skpv);
    pack_pk(pk, &mut pkpv, publicseed);
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_indcpa_enc(
    mut c: *mut uint8_t,
    mut m: *const uint8_t,
    mut pk: *const uint8_t,
    mut coins: *const uint8_t,
) {
    let mut i: libc::c_uint = 0;
    let mut seed: [uint8_t; 32] = [0; 32];
    let mut nonce: uint8_t = 0 as libc::c_int as uint8_t;
    let mut sp: polyvec = polyvec {
        vec: [poly { coeffs: [0; 256] }; 2],
    };
    let mut pkpv: polyvec = polyvec {
        vec: [poly { coeffs: [0; 256] }; 2],
    };
    let mut ep: polyvec = polyvec {
        vec: [poly { coeffs: [0; 256] }; 2],
    };
    let mut at: [polyvec; 2] = [polyvec {
        vec: [poly { coeffs: [0; 256] }; 2],
    }; 2];
    let mut b: polyvec = polyvec {
        vec: [poly { coeffs: [0; 256] }; 2],
    };
    let mut v: poly = poly { coeffs: [0; 256] };
    let mut k: poly = poly { coeffs: [0; 256] };
    let mut epp: poly = poly { coeffs: [0; 256] };
    unpack_pk(&mut pkpv, seed.as_mut_ptr(), pk);
    pqcrystals_kyber512_ref_poly_frommsg(&mut k, m);
    pqcrystals_kyber512_ref_gen_matrix(
        at.as_mut_ptr(),
        seed.as_mut_ptr() as *const uint8_t,
        1 as libc::c_int,
    );
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        let fresh5 = nonce;
        nonce = nonce.wrapping_add(1);
        pqcrystals_kyber512_ref_poly_getnoise_eta1(
            (sp.vec).as_mut_ptr().offset(i as isize),
            coins,
            fresh5,
        );
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        let fresh6 = nonce;
        nonce = nonce.wrapping_add(1);
        pqcrystals_kyber512_ref_poly_getnoise_eta2(
            (ep.vec).as_mut_ptr().offset(i as isize),
            coins,
            fresh6,
        );
        i = i.wrapping_add(1);
        i;
    }
    let fresh7 = nonce;
    nonce = nonce.wrapping_add(1);
    pqcrystals_kyber512_ref_poly_getnoise_eta2(&mut epp, coins, fresh7);
    pqcrystals_kyber512_ref_polyvec_ntt(&mut sp);
    i = 0 as libc::c_int as libc::c_uint;
    while i < 2 as libc::c_int as libc::c_uint {
        pqcrystals_kyber512_ref_polyvec_basemul_acc_montgomery(
            &mut *(b.vec).as_mut_ptr().offset(i as isize),
            &mut *at.as_mut_ptr().offset(i as isize),
            &mut sp,
        );
        i = i.wrapping_add(1);
        i;
    }
    pqcrystals_kyber512_ref_polyvec_basemul_acc_montgomery(&mut v, &mut pkpv, &mut sp);
    pqcrystals_kyber512_ref_polyvec_invntt_tomont(&mut b);
    pqcrystals_kyber512_ref_poly_invntt_tomont(&mut v);
    pqcrystals_kyber512_ref_polyvec_add(&mut b, &mut b, &mut ep);
    pqcrystals_kyber512_ref_poly_add(&mut v, &mut v, &mut epp);
    pqcrystals_kyber512_ref_poly_add(&mut v, &mut v, &mut k);
    pqcrystals_kyber512_ref_polyvec_reduce(&mut b);
    pqcrystals_kyber512_ref_poly_reduce(&mut v);
    pack_ciphertext(c, &mut b, &mut v);
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_indcpa_dec(
    mut m: *mut uint8_t,
    mut c: *const uint8_t,
    mut sk: *const uint8_t,
) {
    let mut b: polyvec = polyvec {
        vec: [poly { coeffs: [0; 256] }; 2],
    };
    let mut skpv: polyvec = polyvec {
        vec: [poly { coeffs: [0; 256] }; 2],
    };
    let mut v: poly = poly { coeffs: [0; 256] };
    let mut mp: poly = poly { coeffs: [0; 256] };
    unpack_ciphertext(&mut b, &mut v, c);
    unpack_sk(&mut skpv, sk);
    pqcrystals_kyber512_ref_polyvec_ntt(&mut b);
    pqcrystals_kyber512_ref_polyvec_basemul_acc_montgomery(&mut mp, &mut skpv, &mut b);
    pqcrystals_kyber512_ref_poly_invntt_tomont(&mut mp);
    pqcrystals_kyber512_ref_poly_sub(&mut mp, &mut v, &mut mp);
    pqcrystals_kyber512_ref_poly_reduce(&mut mp);
    pqcrystals_kyber512_ref_poly_tomsg(m, &mut mp);
}
#[no_mangle]
pub static mut pqcrystals_kyber512_ref_zetas: [int16_t; 128] = [
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
unsafe extern "C" fn fqmul(mut a: int16_t, mut b: int16_t) -> int16_t {
    return pqcrystals_kyber512_ref_montgomery_reduce(a as int32_t * b as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_ntt(mut r: *mut int16_t) {
    let mut len: libc::c_uint = 0;
    let mut start: libc::c_uint = 0;
    let mut j: libc::c_uint = 0;
    let mut k: libc::c_uint = 0;
    let mut t: int16_t = 0;
    let mut zeta: int16_t = 0;
    k = 1 as libc::c_int as libc::c_uint;
    len = 128 as libc::c_int as libc::c_uint;
    while len >= 2 as libc::c_int as libc::c_uint {
        start = 0 as libc::c_int as libc::c_uint;
        while start < 256 as libc::c_int as libc::c_uint {
            let fresh8 = k;
            k = k.wrapping_add(1);
            zeta = pqcrystals_kyber512_ref_zetas[fresh8 as usize];
            j = start;
            while j < start.wrapping_add(len) {
                t = fqmul(zeta, *r.offset(j.wrapping_add(len) as isize));
                *r
                    .offset(
                        j.wrapping_add(len) as isize,
                    ) = (*r.offset(j as isize) as libc::c_int - t as libc::c_int)
                    as int16_t;
                *r
                    .offset(
                        j as isize,
                    ) = (*r.offset(j as isize) as libc::c_int + t as libc::c_int)
                    as int16_t;
                j = j.wrapping_add(1);
                j;
            }
            start = j.wrapping_add(len);
        }
        len >>= 1 as libc::c_int;
    }
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_invntt(mut r: *mut int16_t) {
    let mut start: libc::c_uint = 0;
    let mut len: libc::c_uint = 0;
    let mut j: libc::c_uint = 0;
    let mut k: libc::c_uint = 0;
    let mut t: int16_t = 0;
    let mut zeta: int16_t = 0;
    let f: int16_t = 1441 as libc::c_int as int16_t;
    k = 127 as libc::c_int as libc::c_uint;
    len = 2 as libc::c_int as libc::c_uint;
    while len <= 128 as libc::c_int as libc::c_uint {
        start = 0 as libc::c_int as libc::c_uint;
        while start < 256 as libc::c_int as libc::c_uint {
            let fresh9 = k;
            k = k.wrapping_sub(1);
            zeta = pqcrystals_kyber512_ref_zetas[fresh9 as usize];
            j = start;
            while j < start.wrapping_add(len) {
                t = *r.offset(j as isize);
                *r
                    .offset(
                        j as isize,
                    ) = pqcrystals_kyber512_ref_barrett_reduce(
                    (t as libc::c_int
                        + *r.offset(j.wrapping_add(len) as isize) as libc::c_int)
                        as int16_t,
                );
                *r
                    .offset(
                        j.wrapping_add(len) as isize,
                    ) = (*r.offset(j.wrapping_add(len) as isize) as libc::c_int
                    - t as libc::c_int) as int16_t;
                *r
                    .offset(
                        j.wrapping_add(len) as isize,
                    ) = fqmul(zeta, *r.offset(j.wrapping_add(len) as isize));
                j = j.wrapping_add(1);
                j;
            }
            start = j.wrapping_add(len);
        }
        len <<= 1 as libc::c_int;
    }
    j = 0 as libc::c_int as libc::c_uint;
    while j < 256 as libc::c_int as libc::c_uint {
        *r.offset(j as isize) = fqmul(*r.offset(j as isize), f);
        j = j.wrapping_add(1);
        j;
    }
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_basemul(
    mut r: *mut int16_t,
    mut a: *const int16_t,
    mut b: *const int16_t,
    mut zeta: int16_t,
) {
    *r
        .offset(
            0 as libc::c_int as isize,
        ) = fqmul(
        *a.offset(1 as libc::c_int as isize),
        *b.offset(1 as libc::c_int as isize),
    );
    *r
        .offset(
            0 as libc::c_int as isize,
        ) = fqmul(*r.offset(0 as libc::c_int as isize), zeta);
    let ref mut fresh10 = *r.offset(0 as libc::c_int as isize);
    *fresh10 = (*fresh10 as libc::c_int
        + fqmul(
            *a.offset(0 as libc::c_int as isize),
            *b.offset(0 as libc::c_int as isize),
        ) as libc::c_int) as int16_t;
    *r
        .offset(
            1 as libc::c_int as isize,
        ) = fqmul(
        *a.offset(0 as libc::c_int as isize),
        *b.offset(1 as libc::c_int as isize),
    );
    let ref mut fresh11 = *r.offset(1 as libc::c_int as isize);
    *fresh11 = (*fresh11 as libc::c_int
        + fqmul(
            *a.offset(1 as libc::c_int as isize),
            *b.offset(0 as libc::c_int as isize),
        ) as libc::c_int) as int16_t;
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_kyber_shake128_absorb(
    mut state: *mut keccak_state,
    mut seed: *const uint8_t,
    mut x: uint8_t,
    mut y: uint8_t,
) {
    let mut extseed: [uint8_t; 34] = [0; 34];
    memcpy(
        extseed.as_mut_ptr() as *mut libc::c_void,
        seed as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    extseed[(32 as libc::c_int + 0 as libc::c_int) as usize] = x;
    extseed[(32 as libc::c_int + 1 as libc::c_int) as usize] = y;
    pqcrystals_kyber_fips202_ref_shake128_absorb_once(
        state,
        extseed.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 34]>() as libc::c_ulong,
    );
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_kyber_shake256_prf(
    mut out: *mut uint8_t,
    mut outlen: size_t,
    mut key: *const uint8_t,
    mut nonce: uint8_t,
) {
    let mut extkey: [uint8_t; 33] = [0; 33];
    memcpy(
        extkey.as_mut_ptr() as *mut libc::c_void,
        key as *const libc::c_void,
        32 as libc::c_int as libc::c_ulong,
    );
    extkey[32 as libc::c_int as usize] = nonce;
    pqcrystals_kyber_fips202_ref_shake256(
        out,
        outlen,
        extkey.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 33]>() as libc::c_ulong,
    );
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_keypair_derand(
    mut pk: *mut uint8_t,
    mut sk: *mut uint8_t,
    mut coins: *const uint8_t,
) -> libc::c_int {
    pqcrystals_kyber512_ref_indcpa_keypair_derand(pk, sk, coins);
    memcpy(
        sk.offset((2 as libc::c_int * 384 as libc::c_int) as isize) as *mut libc::c_void,
        pk as *const libc::c_void,
        (2 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int) as libc::c_ulong,
    );
    pqcrystals_kyber_fips202_ref_sha3_256(
        sk
            .offset(
                (2 as libc::c_int * 384 as libc::c_int
                    + (2 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int)
                    + 2 as libc::c_int * 32 as libc::c_int) as isize,
            )
            .offset(-((2 as libc::c_int * 32 as libc::c_int) as isize)),
        pk,
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
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_keypair(
    mut pk: *mut uint8_t,
    mut sk: *mut uint8_t,
) -> libc::c_int {
    let mut coins: [uint8_t; 64] = [0; 64];
    RAND_bytes(coins.as_mut_ptr(), 32 as libc::c_int as size_t);
    RAND_bytes(
        coins.as_mut_ptr().offset(32 as libc::c_int as isize),
        32 as libc::c_int as size_t,
    );
    pqcrystals_kyber512_ref_keypair_derand(pk, sk, coins.as_mut_ptr() as *const uint8_t);
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_enc_derand(
    mut ct: *mut uint8_t,
    mut ss: *mut uint8_t,
    mut pk: *const uint8_t,
    mut coins: *const uint8_t,
) -> libc::c_int {
    let mut buf: [uint8_t; 64] = [0; 64];
    let mut kr: [uint8_t; 64] = [0; 64];
    pqcrystals_kyber_fips202_ref_sha3_256(
        buf.as_mut_ptr(),
        coins,
        32 as libc::c_int as size_t,
    );
    pqcrystals_kyber_fips202_ref_sha3_256(
        buf.as_mut_ptr().offset(32 as libc::c_int as isize),
        pk,
        (2 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int) as size_t,
    );
    pqcrystals_kyber_fips202_ref_sha3_512(
        kr.as_mut_ptr(),
        buf.as_mut_ptr(),
        (2 as libc::c_int * 32 as libc::c_int) as size_t,
    );
    pqcrystals_kyber512_ref_indcpa_enc(
        ct,
        buf.as_mut_ptr() as *const uint8_t,
        pk,
        kr.as_mut_ptr().offset(32 as libc::c_int as isize) as *const uint8_t,
    );
    pqcrystals_kyber_fips202_ref_sha3_256(
        kr.as_mut_ptr().offset(32 as libc::c_int as isize),
        ct,
        (2 as libc::c_int * 320 as libc::c_int + 128 as libc::c_int) as size_t,
    );
    pqcrystals_kyber_fips202_ref_shake256(
        ss,
        32 as libc::c_int as size_t,
        kr.as_mut_ptr(),
        (2 as libc::c_int * 32 as libc::c_int) as size_t,
    );
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_enc(
    mut ct: *mut uint8_t,
    mut ss: *mut uint8_t,
    mut pk: *const uint8_t,
) -> libc::c_int {
    let mut coins: [uint8_t; 32] = [0; 32];
    RAND_bytes(coins.as_mut_ptr(), 32 as libc::c_int as size_t);
    pqcrystals_kyber512_ref_enc_derand(ct, ss, pk, coins.as_mut_ptr() as *const uint8_t);
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_dec(
    mut ss: *mut uint8_t,
    mut ct: *const uint8_t,
    mut sk: *const uint8_t,
) -> libc::c_int {
    let mut i: size_t = 0;
    let mut fail: libc::c_int = 0;
    let mut buf: [uint8_t; 64] = [0; 64];
    let mut kr: [uint8_t; 64] = [0; 64];
    let mut cmp: [uint8_t; 768] = [0; 768];
    let mut pk: *const uint8_t = sk
        .offset((2 as libc::c_int * 384 as libc::c_int) as isize);
    pqcrystals_kyber512_ref_indcpa_dec(buf.as_mut_ptr(), ct, sk);
    i = 0 as libc::c_int as size_t;
    while i < 32 as libc::c_int as size_t {
        buf[(32 as libc::c_int as size_t).wrapping_add(i)
            as usize] = *sk
            .offset(
                ((2 as libc::c_int * 384 as libc::c_int
                    + (2 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int)
                    + 2 as libc::c_int * 32 as libc::c_int
                    - 2 as libc::c_int * 32 as libc::c_int) as size_t)
                    .wrapping_add(i) as isize,
            );
        i = i.wrapping_add(1);
        i;
    }
    pqcrystals_kyber_fips202_ref_sha3_512(
        kr.as_mut_ptr(),
        buf.as_mut_ptr(),
        (2 as libc::c_int * 32 as libc::c_int) as size_t,
    );
    pqcrystals_kyber512_ref_indcpa_enc(
        cmp.as_mut_ptr(),
        buf.as_mut_ptr() as *const uint8_t,
        pk,
        kr.as_mut_ptr().offset(32 as libc::c_int as isize) as *const uint8_t,
    );
    fail = pqcrystals_kyber512_ref_verify(
        ct,
        cmp.as_mut_ptr(),
        (2 as libc::c_int * 320 as libc::c_int + 128 as libc::c_int) as size_t,
    );
    pqcrystals_kyber_fips202_ref_sha3_256(
        kr.as_mut_ptr().offset(32 as libc::c_int as isize),
        ct,
        (2 as libc::c_int * 320 as libc::c_int + 128 as libc::c_int) as size_t,
    );
    pqcrystals_kyber512_ref_cmov(
        kr.as_mut_ptr(),
        sk
            .offset(
                (2 as libc::c_int * 384 as libc::c_int
                    + (2 as libc::c_int * 384 as libc::c_int + 32 as libc::c_int)
                    + 2 as libc::c_int * 32 as libc::c_int) as isize,
            )
            .offset(-(32 as libc::c_int as isize)),
        32 as libc::c_int as size_t,
        fail as uint8_t,
    );
    pqcrystals_kyber_fips202_ref_shake256(
        ss,
        32 as libc::c_int as size_t,
        kr.as_mut_ptr(),
        (2 as libc::c_int * 32 as libc::c_int) as size_t,
    );
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_verify(
    mut a: *const uint8_t,
    mut b: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut i: size_t = 0;
    let mut r: uint8_t = 0 as libc::c_int as uint8_t;
    i = 0 as libc::c_int as size_t;
    while i < len {
        r = (r as libc::c_int
            | *a.offset(i as isize) as libc::c_int
                ^ *b.offset(i as isize) as libc::c_int) as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
    return ((r as uint64_t).wrapping_neg() >> 63 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_cmov(
    mut r: *mut uint8_t,
    mut x: *const uint8_t,
    mut len: size_t,
    mut b: uint8_t,
) {
    let mut mask: uint8_t = constant_time_is_zero_8(b as crypto_word_t);
    constant_time_select_array_8(r, r, x as *mut uint8_t, mask, len);
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_montgomery_reduce(
    mut a: int32_t,
) -> int16_t {
    let mut t: int16_t = 0;
    t = (a as int16_t as libc::c_int * -(3327 as libc::c_int)) as int16_t;
    t = (a - t as int32_t * 3329 as libc::c_int >> 16 as libc::c_int) as int16_t;
    return t;
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber512_ref_barrett_reduce(
    mut a: int16_t,
) -> int16_t {
    let mut t: int16_t = 0;
    let v: int16_t = ((((1 as libc::c_int) << 26 as libc::c_int)
        + 3329 as libc::c_int / 2 as libc::c_int) / 3329 as libc::c_int) as int16_t;
    t = (v as int32_t * a as libc::c_int + ((1 as libc::c_int) << 25 as libc::c_int)
        >> 26 as libc::c_int) as int16_t;
    t = (t as libc::c_int * 3329 as libc::c_int) as int16_t;
    return (a as libc::c_int - t as libc::c_int) as int16_t;
}
#[inline]
unsafe extern "C" fn value_barrier_w(mut a: crypto_word_t) -> crypto_word_t {
    asm!("", inlateout(reg) a, options(preserves_flags, pure, readonly, att_syntax));
    return a;
}
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
unsafe extern "C" fn constant_time_is_zero_8(mut a: crypto_word_t) -> uint8_t {
    return constant_time_is_zero_w(a) as uint8_t;
}
#[inline]
unsafe extern "C" fn constant_time_select_w(
    mut mask: crypto_word_t,
    mut a: crypto_word_t,
    mut b: crypto_word_t,
) -> crypto_word_t {
    return value_barrier_w(mask) & a | value_barrier_w(!mask) & b;
}
#[inline]
unsafe extern "C" fn constant_time_select_8(
    mut mask: uint8_t,
    mut a: uint8_t,
    mut b: uint8_t,
) -> uint8_t {
    return constant_time_select_w(
        mask as crypto_word_t,
        a as crypto_word_t,
        b as crypto_word_t,
    ) as uint8_t;
}
#[inline]
unsafe extern "C" fn constant_time_select_array_8(
    mut c: *mut uint8_t,
    mut a: *mut uint8_t,
    mut b: *mut uint8_t,
    mut mask: uint8_t,
    mut len: size_t,
) {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < len {
        *c
            .offset(
                i as isize,
            ) = constant_time_select_8(
            mask,
            *a.offset(i as isize),
            *b.offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
