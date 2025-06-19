#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(stdsimd)]
#[cfg(target_arch = "x86")]
pub use core::arch::x86::{
    __m128i, _mm_add_epi64, _mm_mul_epu32, _mm_and_si128, _mm_or_si128, _mm_slli_epi64,
    _mm_srli_epi64, _mm_cvtsi32_si128, _mm_cvtsi128_si32, _mm_load_si128,
    _mm_loadl_epi64, _mm_setzero_si128, _mm_unpacklo_epi64, _mm_shuffle_epi32,
};
#[cfg(target_arch = "x86_64")]
pub use core::arch::x86_64::{
    __m128i, _mm_add_epi64, _mm_mul_epu32, _mm_and_si128, _mm_or_si128, _mm_slli_epi64,
    _mm_srli_epi64, _mm_cvtsi32_si128, _mm_cvtsi128_si32, _mm_load_si128,
    _mm_loadl_epi64, _mm_setzero_si128, _mm_unpacklo_epi64, _mm_shuffle_epi32,
};
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
pub type __uint128_t = u128;
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type poly1305_state = [uint8_t; 512];
pub type poly1305_state_internal = poly1305_state_internal_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct poly1305_state_internal_t {
    pub P: [poly1305_power; 2],
    pub u: C2RustUnnamed,
    pub started: uint64_t,
    pub leftover: uint64_t,
    pub buffer: [uint8_t; 64],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub H: [xmmi; 5],
    pub HH: [uint64_t; 10],
}
pub type xmmi = __m128i;
pub type poly1305_power = poly1305_power_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct poly1305_power_t {
    pub R20: C2RustUnnamed_0,
    pub R21: C2RustUnnamed_0,
    pub R22: C2RustUnnamed_0,
    pub R23: C2RustUnnamed_0,
    pub R24: C2RustUnnamed_0,
    pub S21: C2RustUnnamed_0,
    pub S22: C2RustUnnamed_0,
    pub S23: C2RustUnnamed_0,
    pub S24: C2RustUnnamed_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub v: xmmi,
    pub u: [uint64_t; 2],
    pub d: [uint32_t; 4],
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct __mm_loadl_epi64_struct {
    pub __u: libc::c_longlong,
}
pub type uint128_t = __uint128_t;
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
unsafe extern "C" fn CRYPTO_store_u64_le(mut out: *mut libc::c_void, mut v: uint64_t) {
    OPENSSL_memcpy(
        out,
        &mut v as *mut uint64_t as *const libc::c_void,
        ::core::mem::size_of::<uint64_t>() as libc::c_ulong,
    );
}
static mut poly1305_x64_sse2_message_mask: [uint32_t; 4] = [
    (((1 as libc::c_int) << 26 as libc::c_int) - 1 as libc::c_int) as uint32_t,
    0 as libc::c_int as uint32_t,
    (((1 as libc::c_int) << 26 as libc::c_int) - 1 as libc::c_int) as uint32_t,
    0 as libc::c_int as uint32_t,
];
static mut poly1305_x64_sse2_5: [uint32_t; 4] = [
    5 as libc::c_int as uint32_t,
    0 as libc::c_int as uint32_t,
    5 as libc::c_int as uint32_t,
    0 as libc::c_int as uint32_t,
];
static mut poly1305_x64_sse2_1shl128: [uint32_t; 4] = [
    ((1 as libc::c_int) << 24 as libc::c_int) as uint32_t,
    0 as libc::c_int as uint32_t,
    ((1 as libc::c_int) << 24 as libc::c_int) as uint32_t,
    0 as libc::c_int as uint32_t,
];
#[inline]
unsafe extern "C" fn add128(mut a: uint128_t, mut b: uint128_t) -> uint128_t {
    return a.wrapping_add(b);
}
#[inline]
unsafe extern "C" fn add128_64(mut a: uint128_t, mut b: uint64_t) -> uint128_t {
    return a.wrapping_add(b as uint128_t);
}
#[inline]
unsafe extern "C" fn mul64x64_128(mut a: uint64_t, mut b: uint64_t) -> uint128_t {
    return a as uint128_t * b as uint128_t;
}
#[inline]
unsafe extern "C" fn lo128(mut a: uint128_t) -> uint64_t {
    return a as uint64_t;
}
#[inline]
unsafe extern "C" fn shr128(mut v: uint128_t, shift: libc::c_int) -> uint64_t {
    return (v >> shift) as uint64_t;
}
#[inline]
unsafe extern "C" fn shr128_pair(
    mut hi: uint64_t,
    mut lo: uint64_t,
    shift: libc::c_int,
) -> uint64_t {
    return (((hi as uint128_t) << 64 as libc::c_int | lo as uint128_t) >> shift)
        as uint64_t;
}
#[inline]
unsafe extern "C" fn poly1305_aligned_state(
    mut state: *mut poly1305_state,
) -> *mut poly1305_state_internal {
    return ((state as uint64_t).wrapping_add(63 as libc::c_int as uint64_t)
        & !(63 as libc::c_int) as uint64_t) as *mut poly1305_state_internal;
}
#[inline]
unsafe extern "C" fn poly1305_min(mut a: size_t, mut b: size_t) -> size_t {
    return if a < b { a } else { b };
}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_poly1305_init(
    mut state: *mut poly1305_state,
    mut key: *const uint8_t,
) {
    let mut st: *mut poly1305_state_internal = poly1305_aligned_state(state);
    let mut p: *mut poly1305_power = 0 as *mut poly1305_power;
    let mut r0: uint64_t = 0;
    let mut r1: uint64_t = 0;
    let mut r2: uint64_t = 0;
    let mut t0: uint64_t = 0;
    let mut t1: uint64_t = 0;
    t0 = CRYPTO_load_u64_le(
        key.offset(0 as libc::c_int as isize) as *const libc::c_void,
    );
    t1 = CRYPTO_load_u64_le(
        key.offset(8 as libc::c_int as isize) as *const libc::c_void,
    );
    r0 = t0 & 0xffc0fffffff as libc::c_long as uint64_t;
    t0 >>= 44 as libc::c_int;
    t0 |= t1 << 20 as libc::c_int;
    r1 = t0 & 0xfffffc0ffff as libc::c_long as uint64_t;
    t1 >>= 24 as libc::c_int;
    r2 = t1 & 0xffffffc0f as libc::c_long as uint64_t;
    p = &mut *((*st).P).as_mut_ptr().offset(1 as libc::c_int as isize)
        as *mut poly1305_power;
    (*p).R20.d[1 as libc::c_int as usize] = r0 as uint32_t;
    (*p).R20.d[3 as libc::c_int as usize] = (r0 >> 32 as libc::c_int) as uint32_t;
    (*p).R21.d[1 as libc::c_int as usize] = r1 as uint32_t;
    (*p).R21.d[3 as libc::c_int as usize] = (r1 >> 32 as libc::c_int) as uint32_t;
    (*p).R22.d[1 as libc::c_int as usize] = r2 as uint32_t;
    (*p).R22.d[3 as libc::c_int as usize] = (r2 >> 32 as libc::c_int) as uint32_t;
    (*p)
        .R23
        .d[1 as libc::c_int
        as usize] = CRYPTO_load_u32_le(
        key.offset(16 as libc::c_int as isize) as *const libc::c_void,
    );
    (*p)
        .R23
        .d[3 as libc::c_int
        as usize] = CRYPTO_load_u32_le(
        key.offset(20 as libc::c_int as isize) as *const libc::c_void,
    );
    (*p)
        .R24
        .d[1 as libc::c_int
        as usize] = CRYPTO_load_u32_le(
        key.offset(24 as libc::c_int as isize) as *const libc::c_void,
    );
    (*p)
        .R24
        .d[3 as libc::c_int
        as usize] = CRYPTO_load_u32_le(
        key.offset(28 as libc::c_int as isize) as *const libc::c_void,
    );
    (*st).u.H[0 as libc::c_int as usize] = _mm_setzero_si128();
    (*st).u.H[1 as libc::c_int as usize] = _mm_setzero_si128();
    (*st).u.H[2 as libc::c_int as usize] = _mm_setzero_si128();
    (*st).u.H[3 as libc::c_int as usize] = _mm_setzero_si128();
    (*st).u.H[4 as libc::c_int as usize] = _mm_setzero_si128();
    (*st).started = 0 as libc::c_int as uint64_t;
    (*st).leftover = 0 as libc::c_int as uint64_t;
}
unsafe extern "C" fn poly1305_first_block(
    mut st: *mut poly1305_state_internal,
    mut m: *const uint8_t,
) {
    let MMASK: xmmi = _mm_load_si128(
        poly1305_x64_sse2_message_mask.as_ptr() as *const xmmi,
    );
    let FIVE: xmmi = _mm_load_si128(poly1305_x64_sse2_5.as_ptr() as *const xmmi);
    let HIBIT: xmmi = _mm_load_si128(poly1305_x64_sse2_1shl128.as_ptr() as *const xmmi);
    let mut T5: xmmi = _mm_setzero_si128();
    let mut T6: xmmi = _mm_setzero_si128();
    let mut p: *mut poly1305_power = 0 as *mut poly1305_power;
    let mut d: [uint128_t; 3] = [0; 3];
    let mut r0: uint64_t = 0;
    let mut r1: uint64_t = 0;
    let mut r2: uint64_t = 0;
    let mut r20: uint64_t = 0;
    let mut r21: uint64_t = 0;
    let mut r22: uint64_t = 0;
    let mut s22: uint64_t = 0;
    let mut pad0: uint64_t = 0;
    let mut pad1: uint64_t = 0;
    let mut c: uint64_t = 0;
    let mut i: uint64_t = 0;
    p = &mut *((*st).P).as_mut_ptr().offset(1 as libc::c_int as isize)
        as *mut poly1305_power;
    r0 = ((*p).R20.d[3 as libc::c_int as usize] as uint64_t) << 32 as libc::c_int
        | (*p).R20.d[1 as libc::c_int as usize] as uint64_t;
    r1 = ((*p).R21.d[3 as libc::c_int as usize] as uint64_t) << 32 as libc::c_int
        | (*p).R21.d[1 as libc::c_int as usize] as uint64_t;
    r2 = ((*p).R22.d[3 as libc::c_int as usize] as uint64_t) << 32 as libc::c_int
        | (*p).R22.d[1 as libc::c_int as usize] as uint64_t;
    pad0 = ((*p).R23.d[3 as libc::c_int as usize] as uint64_t) << 32 as libc::c_int
        | (*p).R23.d[1 as libc::c_int as usize] as uint64_t;
    pad1 = ((*p).R24.d[3 as libc::c_int as usize] as uint64_t) << 32 as libc::c_int
        | (*p).R24.d[1 as libc::c_int as usize] as uint64_t;
    r20 = r0;
    r21 = r1;
    r22 = r2;
    i = 0 as libc::c_int as uint64_t;
    while i < 2 as libc::c_int as uint64_t {
        s22 = r22 * ((5 as libc::c_int) << 2 as libc::c_int) as uint64_t;
        d[0 as libc::c_int
            as usize] = add128(
            mul64x64_128(r20, r20),
            mul64x64_128(r21 * 2 as libc::c_int as uint64_t, s22),
        );
        d[1 as libc::c_int
            as usize] = add128(
            mul64x64_128(r22, s22),
            mul64x64_128(r20 * 2 as libc::c_int as uint64_t, r21),
        );
        d[2 as libc::c_int
            as usize] = add128(
            mul64x64_128(r21, r21),
            mul64x64_128(r22 * 2 as libc::c_int as uint64_t, r20),
        );
        r20 = lo128(d[0 as libc::c_int as usize])
            & 0xfffffffffff as libc::c_long as uint64_t;
        c = shr128(d[0 as libc::c_int as usize], 44 as libc::c_int);
        d[1 as libc::c_int as usize] = add128_64(d[1 as libc::c_int as usize], c);
        r21 = lo128(d[1 as libc::c_int as usize])
            & 0xfffffffffff as libc::c_long as uint64_t;
        c = shr128(d[1 as libc::c_int as usize], 44 as libc::c_int);
        d[2 as libc::c_int as usize] = add128_64(d[2 as libc::c_int as usize], c);
        r22 = lo128(d[2 as libc::c_int as usize])
            & 0x3ffffffffff as libc::c_long as uint64_t;
        c = shr128(d[2 as libc::c_int as usize], 42 as libc::c_int);
        r20 = r20.wrapping_add(c * 5 as libc::c_int as uint64_t);
        c = r20 >> 44 as libc::c_int;
        r20 = r20 & 0xfffffffffff as libc::c_long as uint64_t;
        r21 = r21.wrapping_add(c);
        (*p)
            .R20
            .v = _mm_shuffle_epi32(
            _mm_cvtsi32_si128(
                (r20 as uint32_t & 0x3ffffff as libc::c_int as uint32_t) as libc::c_int,
            ),
            (1 as libc::c_int) << 6 as libc::c_int
                | (0 as libc::c_int) << 4 as libc::c_int
                | (1 as libc::c_int) << 2 as libc::c_int | 0 as libc::c_int,
        );
        (*p)
            .R21
            .v = _mm_shuffle_epi32(
            _mm_cvtsi32_si128(
                ((r20 >> 26 as libc::c_int | r21 << 18 as libc::c_int) as uint32_t
                    & 0x3ffffff as libc::c_int as uint32_t) as libc::c_int,
            ),
            (1 as libc::c_int) << 6 as libc::c_int
                | (0 as libc::c_int) << 4 as libc::c_int
                | (1 as libc::c_int) << 2 as libc::c_int | 0 as libc::c_int,
        );
        (*p)
            .R22
            .v = _mm_shuffle_epi32(
            _mm_cvtsi32_si128(
                ((r21 >> 8 as libc::c_int) as uint32_t
                    & 0x3ffffff as libc::c_int as uint32_t) as libc::c_int,
            ),
            (1 as libc::c_int) << 6 as libc::c_int
                | (0 as libc::c_int) << 4 as libc::c_int
                | (1 as libc::c_int) << 2 as libc::c_int | 0 as libc::c_int,
        );
        (*p)
            .R23
            .v = _mm_shuffle_epi32(
            _mm_cvtsi32_si128(
                ((r21 >> 34 as libc::c_int | r22 << 10 as libc::c_int) as uint32_t
                    & 0x3ffffff as libc::c_int as uint32_t) as libc::c_int,
            ),
            (1 as libc::c_int) << 6 as libc::c_int
                | (0 as libc::c_int) << 4 as libc::c_int
                | (1 as libc::c_int) << 2 as libc::c_int | 0 as libc::c_int,
        );
        (*p)
            .R24
            .v = _mm_shuffle_epi32(
            _mm_cvtsi32_si128((r22 >> 16 as libc::c_int) as uint32_t as libc::c_int),
            (1 as libc::c_int) << 6 as libc::c_int
                | (0 as libc::c_int) << 4 as libc::c_int
                | (1 as libc::c_int) << 2 as libc::c_int | 0 as libc::c_int,
        );
        (*p).S21.v = _mm_mul_epu32((*p).R21.v, FIVE);
        (*p).S22.v = _mm_mul_epu32((*p).R22.v, FIVE);
        (*p).S23.v = _mm_mul_epu32((*p).R23.v, FIVE);
        (*p).S24.v = _mm_mul_epu32((*p).R24.v, FIVE);
        p = p.offset(-1);
        p;
        i = i.wrapping_add(1);
        i;
    }
    p = &mut *((*st).P).as_mut_ptr().offset(1 as libc::c_int as isize)
        as *mut poly1305_power;
    (*p).R20.d[1 as libc::c_int as usize] = r0 as uint32_t;
    (*p).R20.d[3 as libc::c_int as usize] = (r0 >> 32 as libc::c_int) as uint32_t;
    (*p).R21.d[1 as libc::c_int as usize] = r1 as uint32_t;
    (*p).R21.d[3 as libc::c_int as usize] = (r1 >> 32 as libc::c_int) as uint32_t;
    (*p).R22.d[1 as libc::c_int as usize] = r2 as uint32_t;
    (*p).R22.d[3 as libc::c_int as usize] = (r2 >> 32 as libc::c_int) as uint32_t;
    (*p).R23.d[1 as libc::c_int as usize] = pad0 as uint32_t;
    (*p).R23.d[3 as libc::c_int as usize] = (pad0 >> 32 as libc::c_int) as uint32_t;
    (*p).R24.d[1 as libc::c_int as usize] = pad1 as uint32_t;
    (*p).R24.d[3 as libc::c_int as usize] = (pad1 >> 32 as libc::c_int) as uint32_t;
    T5 = _mm_unpacklo_epi64(
        _mm_loadl_epi64(m.offset(0 as libc::c_int as isize) as *const xmmi),
        _mm_loadl_epi64(m.offset(16 as libc::c_int as isize) as *const xmmi),
    );
    T6 = _mm_unpacklo_epi64(
        _mm_loadl_epi64(m.offset(8 as libc::c_int as isize) as *const xmmi),
        _mm_loadl_epi64(m.offset(24 as libc::c_int as isize) as *const xmmi),
    );
    (*st).u.H[0 as libc::c_int as usize] = _mm_and_si128(MMASK, T5);
    (*st)
        .u
        .H[1 as libc::c_int
        as usize] = _mm_and_si128(MMASK, _mm_srli_epi64(T5, 26 as libc::c_int));
    T5 = _mm_or_si128(
        _mm_srli_epi64(T5, 52 as libc::c_int),
        _mm_slli_epi64(T6, 12 as libc::c_int),
    );
    (*st).u.H[2 as libc::c_int as usize] = _mm_and_si128(MMASK, T5);
    (*st)
        .u
        .H[3 as libc::c_int
        as usize] = _mm_and_si128(MMASK, _mm_srli_epi64(T5, 26 as libc::c_int));
    (*st)
        .u
        .H[4 as libc::c_int
        as usize] = _mm_or_si128(_mm_srli_epi64(T6, 40 as libc::c_int), HIBIT);
}
unsafe extern "C" fn poly1305_blocks(
    mut st: *mut poly1305_state_internal,
    mut m: *const uint8_t,
    mut bytes: size_t,
) {
    let MMASK: xmmi = _mm_load_si128(
        poly1305_x64_sse2_message_mask.as_ptr() as *const xmmi,
    );
    let FIVE: xmmi = _mm_load_si128(poly1305_x64_sse2_5.as_ptr() as *const xmmi);
    let HIBIT: xmmi = _mm_load_si128(poly1305_x64_sse2_1shl128.as_ptr() as *const xmmi);
    let mut p: *mut poly1305_power = 0 as *mut poly1305_power;
    let mut H0: xmmi = _mm_setzero_si128();
    let mut H1: xmmi = _mm_setzero_si128();
    let mut H2: xmmi = _mm_setzero_si128();
    let mut H3: xmmi = _mm_setzero_si128();
    let mut H4: xmmi = _mm_setzero_si128();
    let mut T0: xmmi = _mm_setzero_si128();
    let mut T1: xmmi = _mm_setzero_si128();
    let mut T2: xmmi = _mm_setzero_si128();
    let mut T3: xmmi = _mm_setzero_si128();
    let mut T4: xmmi = _mm_setzero_si128();
    let mut T5: xmmi = _mm_setzero_si128();
    let mut T6: xmmi = _mm_setzero_si128();
    let mut M0: xmmi = _mm_setzero_si128();
    let mut M1: xmmi = _mm_setzero_si128();
    let mut M2: xmmi = _mm_setzero_si128();
    let mut M3: xmmi = _mm_setzero_si128();
    let mut M4: xmmi = _mm_setzero_si128();
    let mut C1: xmmi = _mm_setzero_si128();
    let mut C2: xmmi = _mm_setzero_si128();
    H0 = (*st).u.H[0 as libc::c_int as usize];
    H1 = (*st).u.H[1 as libc::c_int as usize];
    H2 = (*st).u.H[2 as libc::c_int as usize];
    H3 = (*st).u.H[3 as libc::c_int as usize];
    H4 = (*st).u.H[4 as libc::c_int as usize];
    while bytes >= 64 as libc::c_int as size_t {
        p = &mut *((*st).P).as_mut_ptr().offset(0 as libc::c_int as isize)
            as *mut poly1305_power;
        T0 = _mm_mul_epu32(H0, (*p).R20.v);
        T1 = _mm_mul_epu32(H0, (*p).R21.v);
        T2 = _mm_mul_epu32(H0, (*p).R22.v);
        T3 = _mm_mul_epu32(H0, (*p).R23.v);
        T4 = _mm_mul_epu32(H0, (*p).R24.v);
        T5 = _mm_mul_epu32(H1, (*p).S24.v);
        T6 = _mm_mul_epu32(H1, (*p).R20.v);
        T0 = _mm_add_epi64(T0, T5);
        T1 = _mm_add_epi64(T1, T6);
        T5 = _mm_mul_epu32(H2, (*p).S23.v);
        T6 = _mm_mul_epu32(H2, (*p).S24.v);
        T0 = _mm_add_epi64(T0, T5);
        T1 = _mm_add_epi64(T1, T6);
        T5 = _mm_mul_epu32(H3, (*p).S22.v);
        T6 = _mm_mul_epu32(H3, (*p).S23.v);
        T0 = _mm_add_epi64(T0, T5);
        T1 = _mm_add_epi64(T1, T6);
        T5 = _mm_mul_epu32(H4, (*p).S21.v);
        T6 = _mm_mul_epu32(H4, (*p).S22.v);
        T0 = _mm_add_epi64(T0, T5);
        T1 = _mm_add_epi64(T1, T6);
        T5 = _mm_mul_epu32(H1, (*p).R21.v);
        T6 = _mm_mul_epu32(H1, (*p).R22.v);
        T2 = _mm_add_epi64(T2, T5);
        T3 = _mm_add_epi64(T3, T6);
        T5 = _mm_mul_epu32(H2, (*p).R20.v);
        T6 = _mm_mul_epu32(H2, (*p).R21.v);
        T2 = _mm_add_epi64(T2, T5);
        T3 = _mm_add_epi64(T3, T6);
        T5 = _mm_mul_epu32(H3, (*p).S24.v);
        T6 = _mm_mul_epu32(H3, (*p).R20.v);
        T2 = _mm_add_epi64(T2, T5);
        T3 = _mm_add_epi64(T3, T6);
        T5 = _mm_mul_epu32(H4, (*p).S23.v);
        T6 = _mm_mul_epu32(H4, (*p).S24.v);
        T2 = _mm_add_epi64(T2, T5);
        T3 = _mm_add_epi64(T3, T6);
        T5 = _mm_mul_epu32(H1, (*p).R23.v);
        T4 = _mm_add_epi64(T4, T5);
        T5 = _mm_mul_epu32(H2, (*p).R22.v);
        T4 = _mm_add_epi64(T4, T5);
        T5 = _mm_mul_epu32(H3, (*p).R21.v);
        T4 = _mm_add_epi64(T4, T5);
        T5 = _mm_mul_epu32(H4, (*p).R20.v);
        T4 = _mm_add_epi64(T4, T5);
        T5 = _mm_unpacklo_epi64(
            _mm_loadl_epi64(m.offset(0 as libc::c_int as isize) as *const xmmi),
            _mm_loadl_epi64(m.offset(16 as libc::c_int as isize) as *const xmmi),
        );
        T6 = _mm_unpacklo_epi64(
            _mm_loadl_epi64(m.offset(8 as libc::c_int as isize) as *const xmmi),
            _mm_loadl_epi64(m.offset(24 as libc::c_int as isize) as *const xmmi),
        );
        M0 = _mm_and_si128(MMASK, T5);
        M1 = _mm_and_si128(MMASK, _mm_srli_epi64(T5, 26 as libc::c_int));
        T5 = _mm_or_si128(
            _mm_srli_epi64(T5, 52 as libc::c_int),
            _mm_slli_epi64(T6, 12 as libc::c_int),
        );
        M2 = _mm_and_si128(MMASK, T5);
        M3 = _mm_and_si128(MMASK, _mm_srli_epi64(T5, 26 as libc::c_int));
        M4 = _mm_or_si128(_mm_srli_epi64(T6, 40 as libc::c_int), HIBIT);
        p = &mut *((*st).P).as_mut_ptr().offset(1 as libc::c_int as isize)
            as *mut poly1305_power;
        T5 = _mm_mul_epu32(M0, (*p).R20.v);
        T6 = _mm_mul_epu32(M0, (*p).R21.v);
        T0 = _mm_add_epi64(T0, T5);
        T1 = _mm_add_epi64(T1, T6);
        T5 = _mm_mul_epu32(M1, (*p).S24.v);
        T6 = _mm_mul_epu32(M1, (*p).R20.v);
        T0 = _mm_add_epi64(T0, T5);
        T1 = _mm_add_epi64(T1, T6);
        T5 = _mm_mul_epu32(M2, (*p).S23.v);
        T6 = _mm_mul_epu32(M2, (*p).S24.v);
        T0 = _mm_add_epi64(T0, T5);
        T1 = _mm_add_epi64(T1, T6);
        T5 = _mm_mul_epu32(M3, (*p).S22.v);
        T6 = _mm_mul_epu32(M3, (*p).S23.v);
        T0 = _mm_add_epi64(T0, T5);
        T1 = _mm_add_epi64(T1, T6);
        T5 = _mm_mul_epu32(M4, (*p).S21.v);
        T6 = _mm_mul_epu32(M4, (*p).S22.v);
        T0 = _mm_add_epi64(T0, T5);
        T1 = _mm_add_epi64(T1, T6);
        T5 = _mm_mul_epu32(M0, (*p).R22.v);
        T6 = _mm_mul_epu32(M0, (*p).R23.v);
        T2 = _mm_add_epi64(T2, T5);
        T3 = _mm_add_epi64(T3, T6);
        T5 = _mm_mul_epu32(M1, (*p).R21.v);
        T6 = _mm_mul_epu32(M1, (*p).R22.v);
        T2 = _mm_add_epi64(T2, T5);
        T3 = _mm_add_epi64(T3, T6);
        T5 = _mm_mul_epu32(M2, (*p).R20.v);
        T6 = _mm_mul_epu32(M2, (*p).R21.v);
        T2 = _mm_add_epi64(T2, T5);
        T3 = _mm_add_epi64(T3, T6);
        T5 = _mm_mul_epu32(M3, (*p).S24.v);
        T6 = _mm_mul_epu32(M3, (*p).R20.v);
        T2 = _mm_add_epi64(T2, T5);
        T3 = _mm_add_epi64(T3, T6);
        T5 = _mm_mul_epu32(M4, (*p).S23.v);
        T6 = _mm_mul_epu32(M4, (*p).S24.v);
        T2 = _mm_add_epi64(T2, T5);
        T3 = _mm_add_epi64(T3, T6);
        T5 = _mm_mul_epu32(M0, (*p).R24.v);
        T4 = _mm_add_epi64(T4, T5);
        T5 = _mm_mul_epu32(M1, (*p).R23.v);
        T4 = _mm_add_epi64(T4, T5);
        T5 = _mm_mul_epu32(M2, (*p).R22.v);
        T4 = _mm_add_epi64(T4, T5);
        T5 = _mm_mul_epu32(M3, (*p).R21.v);
        T4 = _mm_add_epi64(T4, T5);
        T5 = _mm_mul_epu32(M4, (*p).R20.v);
        T4 = _mm_add_epi64(T4, T5);
        T5 = _mm_unpacklo_epi64(
            _mm_loadl_epi64(m.offset(32 as libc::c_int as isize) as *const xmmi),
            _mm_loadl_epi64(m.offset(48 as libc::c_int as isize) as *const xmmi),
        );
        T6 = _mm_unpacklo_epi64(
            _mm_loadl_epi64(m.offset(40 as libc::c_int as isize) as *const xmmi),
            _mm_loadl_epi64(m.offset(56 as libc::c_int as isize) as *const xmmi),
        );
        M0 = _mm_and_si128(MMASK, T5);
        M1 = _mm_and_si128(MMASK, _mm_srli_epi64(T5, 26 as libc::c_int));
        T5 = _mm_or_si128(
            _mm_srli_epi64(T5, 52 as libc::c_int),
            _mm_slli_epi64(T6, 12 as libc::c_int),
        );
        M2 = _mm_and_si128(MMASK, T5);
        M3 = _mm_and_si128(MMASK, _mm_srli_epi64(T5, 26 as libc::c_int));
        M4 = _mm_or_si128(_mm_srli_epi64(T6, 40 as libc::c_int), HIBIT);
        T0 = _mm_add_epi64(T0, M0);
        T1 = _mm_add_epi64(T1, M1);
        T2 = _mm_add_epi64(T2, M2);
        T3 = _mm_add_epi64(T3, M3);
        T4 = _mm_add_epi64(T4, M4);
        C1 = _mm_srli_epi64(T0, 26 as libc::c_int);
        C2 = _mm_srli_epi64(T3, 26 as libc::c_int);
        T0 = _mm_and_si128(T0, MMASK);
        T3 = _mm_and_si128(T3, MMASK);
        T1 = _mm_add_epi64(T1, C1);
        T4 = _mm_add_epi64(T4, C2);
        C1 = _mm_srli_epi64(T1, 26 as libc::c_int);
        C2 = _mm_srli_epi64(T4, 26 as libc::c_int);
        T1 = _mm_and_si128(T1, MMASK);
        T4 = _mm_and_si128(T4, MMASK);
        T2 = _mm_add_epi64(T2, C1);
        T0 = _mm_add_epi64(T0, _mm_mul_epu32(C2, FIVE));
        C1 = _mm_srli_epi64(T2, 26 as libc::c_int);
        C2 = _mm_srli_epi64(T0, 26 as libc::c_int);
        T2 = _mm_and_si128(T2, MMASK);
        T0 = _mm_and_si128(T0, MMASK);
        T3 = _mm_add_epi64(T3, C1);
        T1 = _mm_add_epi64(T1, C2);
        C1 = _mm_srli_epi64(T3, 26 as libc::c_int);
        T3 = _mm_and_si128(T3, MMASK);
        T4 = _mm_add_epi64(T4, C1);
        H0 = T0;
        H1 = T1;
        H2 = T2;
        H3 = T3;
        H4 = T4;
        m = m.offset(64 as libc::c_int as isize);
        bytes = bytes.wrapping_sub(64 as libc::c_int as size_t);
    }
    (*st).u.H[0 as libc::c_int as usize] = H0;
    (*st).u.H[1 as libc::c_int as usize] = H1;
    (*st).u.H[2 as libc::c_int as usize] = H2;
    (*st).u.H[3 as libc::c_int as usize] = H3;
    (*st).u.H[4 as libc::c_int as usize] = H4;
}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_poly1305_update(
    mut state: *mut poly1305_state,
    mut m: *const uint8_t,
    mut bytes: size_t,
) {
    let mut st: *mut poly1305_state_internal = poly1305_aligned_state(state);
    let mut want: size_t = 0;
    if bytes == 0 as libc::c_int as size_t {
        return;
    }
    if (*st).started == 0 {
        if (*st).leftover == 0 as libc::c_int as uint64_t
            && bytes > 32 as libc::c_int as size_t
        {
            poly1305_first_block(st, m);
            m = m.offset(32 as libc::c_int as isize);
            bytes = bytes.wrapping_sub(32 as libc::c_int as size_t);
        } else {
            want = poly1305_min(
                (32 as libc::c_int as uint64_t).wrapping_sub((*st).leftover),
                bytes,
            );
            OPENSSL_memcpy(
                ((*st).buffer).as_mut_ptr().offset((*st).leftover as isize)
                    as *mut libc::c_void,
                m as *const libc::c_void,
                want,
            );
            bytes = bytes.wrapping_sub(want);
            m = m.offset(want as isize);
            (*st)
                .leftover = ((*st).leftover as libc::c_ulong).wrapping_add(want)
                as uint64_t as uint64_t;
            if (*st).leftover < 32 as libc::c_int as uint64_t
                || bytes == 0 as libc::c_int as size_t
            {
                return;
            }
            poly1305_first_block(st, ((*st).buffer).as_mut_ptr());
            (*st).leftover = 0 as libc::c_int as uint64_t;
        }
        (*st).started = 1 as libc::c_int as uint64_t;
    }
    if (*st).leftover != 0 {
        want = poly1305_min(
            (64 as libc::c_int as uint64_t).wrapping_sub((*st).leftover),
            bytes,
        );
        OPENSSL_memcpy(
            ((*st).buffer).as_mut_ptr().offset((*st).leftover as isize)
                as *mut libc::c_void,
            m as *const libc::c_void,
            want,
        );
        bytes = bytes.wrapping_sub(want);
        m = m.offset(want as isize);
        (*st)
            .leftover = ((*st).leftover as libc::c_ulong).wrapping_add(want) as uint64_t
            as uint64_t;
        if (*st).leftover < 64 as libc::c_int as uint64_t {
            return;
        }
        poly1305_blocks(st, ((*st).buffer).as_mut_ptr(), 64 as libc::c_int as size_t);
        (*st).leftover = 0 as libc::c_int as uint64_t;
    }
    if bytes >= 64 as libc::c_int as size_t {
        want = bytes & !(63 as libc::c_int) as size_t;
        poly1305_blocks(st, m, want);
        m = m.offset(want as isize);
        bytes = bytes.wrapping_sub(want);
    }
    if bytes != 0 {
        OPENSSL_memcpy(
            ((*st).buffer).as_mut_ptr().offset((*st).leftover as isize)
                as *mut libc::c_void,
            m as *const libc::c_void,
            bytes,
        );
        (*st)
            .leftover = ((*st).leftover as libc::c_ulong).wrapping_add(bytes) as uint64_t
            as uint64_t;
    }
}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_poly1305_finish(
    mut state: *mut poly1305_state,
    mut mac: *mut uint8_t,
) {
    let mut current_block: u64;
    let mut st: *mut poly1305_state_internal = poly1305_aligned_state(state);
    let mut leftover: size_t = (*st).leftover;
    let mut m: *mut uint8_t = ((*st).buffer).as_mut_ptr();
    let mut d: [uint128_t; 3] = [0; 3];
    let mut h0: uint64_t = 0;
    let mut h1: uint64_t = 0;
    let mut h2: uint64_t = 0;
    let mut t0: uint64_t = 0;
    let mut t1: uint64_t = 0;
    let mut g0: uint64_t = 0;
    let mut g1: uint64_t = 0;
    let mut g2: uint64_t = 0;
    let mut c: uint64_t = 0;
    let mut nc: uint64_t = 0;
    let mut r0: uint64_t = 0;
    let mut r1: uint64_t = 0;
    let mut r2: uint64_t = 0;
    let mut s1: uint64_t = 0;
    let mut s2: uint64_t = 0;
    let mut p: *mut poly1305_power = 0 as *mut poly1305_power;
    if (*st).started != 0 {
        let mut consumed: size_t = poly1305_combine(st, m, leftover);
        leftover = leftover.wrapping_sub(consumed);
        m = m.offset(consumed as isize);
    }
    h0 = (*st).u.HH[0 as libc::c_int as usize];
    h1 = (*st).u.HH[1 as libc::c_int as usize];
    h2 = (*st).u.HH[2 as libc::c_int as usize];
    p = &mut *((*st).P).as_mut_ptr().offset(1 as libc::c_int as isize)
        as *mut poly1305_power;
    r0 = ((*p).R20.d[3 as libc::c_int as usize] as uint64_t) << 32 as libc::c_int
        | (*p).R20.d[1 as libc::c_int as usize] as uint64_t;
    r1 = ((*p).R21.d[3 as libc::c_int as usize] as uint64_t) << 32 as libc::c_int
        | (*p).R21.d[1 as libc::c_int as usize] as uint64_t;
    r2 = ((*p).R22.d[3 as libc::c_int as usize] as uint64_t) << 32 as libc::c_int
        | (*p).R22.d[1 as libc::c_int as usize] as uint64_t;
    s1 = r1 * ((5 as libc::c_int) << 2 as libc::c_int) as uint64_t;
    s2 = r2 * ((5 as libc::c_int) << 2 as libc::c_int) as uint64_t;
    if leftover < 16 as libc::c_int as size_t {
        current_block = 8836998360920615650;
    } else {
        current_block = 3971592935999415235;
    }
    loop {
        match current_block {
            3971592935999415235 => {
                t0 = CRYPTO_load_u64_le(
                    m.offset(0 as libc::c_int as isize) as *const libc::c_void,
                );
                t1 = CRYPTO_load_u64_le(
                    m.offset(8 as libc::c_int as isize) as *const libc::c_void,
                );
                h0 = h0.wrapping_add(t0 & 0xfffffffffff as libc::c_long as uint64_t);
                t0 = shr128_pair(t1, t0, 44 as libc::c_int);
                h1 = h1.wrapping_add(t0 & 0xfffffffffff as libc::c_long as uint64_t);
                h2 = h2
                    .wrapping_add(
                        t1 >> 24 as libc::c_int
                            | (1 as libc::c_int as uint64_t) << 40 as libc::c_int,
                    );
            }
            _ => {
                if leftover == 0 {
                    break;
                }
                let fresh0 = leftover;
                leftover = leftover.wrapping_add(1);
                *m.offset(fresh0 as isize) = 1 as libc::c_int as uint8_t;
                OPENSSL_memset(
                    m.offset(leftover as isize) as *mut libc::c_void,
                    0 as libc::c_int,
                    (16 as libc::c_int as size_t).wrapping_sub(leftover),
                );
                leftover = 16 as libc::c_int as size_t;
                t0 = CRYPTO_load_u64_le(
                    m.offset(0 as libc::c_int as isize) as *const libc::c_void,
                );
                t1 = CRYPTO_load_u64_le(
                    m.offset(8 as libc::c_int as isize) as *const libc::c_void,
                );
                h0 = h0.wrapping_add(t0 & 0xfffffffffff as libc::c_long as uint64_t);
                t0 = shr128_pair(t1, t0, 44 as libc::c_int);
                h1 = h1.wrapping_add(t0 & 0xfffffffffff as libc::c_long as uint64_t);
                h2 = h2.wrapping_add(t1 >> 24 as libc::c_int);
            }
        }
        d[0 as libc::c_int
            as usize] = add128(
            add128(mul64x64_128(h0, r0), mul64x64_128(h1, s2)),
            mul64x64_128(h2, s1),
        );
        d[1 as libc::c_int
            as usize] = add128(
            add128(mul64x64_128(h0, r1), mul64x64_128(h1, r0)),
            mul64x64_128(h2, s2),
        );
        d[2 as libc::c_int
            as usize] = add128(
            add128(mul64x64_128(h0, r2), mul64x64_128(h1, r1)),
            mul64x64_128(h2, r0),
        );
        h0 = lo128(d[0 as libc::c_int as usize])
            & 0xfffffffffff as libc::c_long as uint64_t;
        c = shr128(d[0 as libc::c_int as usize], 44 as libc::c_int);
        d[1 as libc::c_int as usize] = add128_64(d[1 as libc::c_int as usize], c);
        h1 = lo128(d[1 as libc::c_int as usize])
            & 0xfffffffffff as libc::c_long as uint64_t;
        c = shr128(d[1 as libc::c_int as usize], 44 as libc::c_int);
        d[2 as libc::c_int as usize] = add128_64(d[2 as libc::c_int as usize], c);
        h2 = lo128(d[2 as libc::c_int as usize])
            & 0x3ffffffffff as libc::c_long as uint64_t;
        c = shr128(d[2 as libc::c_int as usize], 42 as libc::c_int);
        h0 = h0.wrapping_add(c * 5 as libc::c_int as uint64_t);
        m = m.offset(16 as libc::c_int as isize);
        leftover = leftover.wrapping_sub(16 as libc::c_int as size_t);
        if leftover >= 16 as libc::c_int as size_t {
            current_block = 3971592935999415235;
        } else {
            current_block = 8836998360920615650;
        }
    }
    c = h0 >> 44 as libc::c_int;
    h0 &= 0xfffffffffff as libc::c_long as uint64_t;
    h1 = h1.wrapping_add(c);
    c = h1 >> 44 as libc::c_int;
    h1 &= 0xfffffffffff as libc::c_long as uint64_t;
    h2 = h2.wrapping_add(c);
    c = h2 >> 42 as libc::c_int;
    h2 &= 0x3ffffffffff as libc::c_long as uint64_t;
    h0 = h0.wrapping_add(c * 5 as libc::c_int as uint64_t);
    g0 = h0.wrapping_add(5 as libc::c_int as uint64_t);
    c = g0 >> 44 as libc::c_int;
    g0 &= 0xfffffffffff as libc::c_long as uint64_t;
    g1 = h1.wrapping_add(c);
    c = g1 >> 44 as libc::c_int;
    g1 &= 0xfffffffffff as libc::c_long as uint64_t;
    g2 = h2
        .wrapping_add(c)
        .wrapping_sub((1 as libc::c_int as uint64_t) << 42 as libc::c_int);
    c = (g2 >> 63 as libc::c_int).wrapping_sub(1 as libc::c_int as uint64_t);
    nc = !c;
    h0 = h0 & nc | g0 & c;
    h1 = h1 & nc | g1 & c;
    h2 = h2 & nc | g2 & c;
    t0 = ((*p).R23.d[3 as libc::c_int as usize] as uint64_t) << 32 as libc::c_int
        | (*p).R23.d[1 as libc::c_int as usize] as uint64_t;
    t1 = ((*p).R24.d[3 as libc::c_int as usize] as uint64_t) << 32 as libc::c_int
        | (*p).R24.d[1 as libc::c_int as usize] as uint64_t;
    h0 = h0.wrapping_add(t0 & 0xfffffffffff as libc::c_long as uint64_t);
    c = h0 >> 44 as libc::c_int;
    h0 &= 0xfffffffffff as libc::c_long as uint64_t;
    t0 = shr128_pair(t1, t0, 44 as libc::c_int);
    h1 = h1
        .wrapping_add((t0 & 0xfffffffffff as libc::c_long as uint64_t).wrapping_add(c));
    c = h1 >> 44 as libc::c_int;
    h1 &= 0xfffffffffff as libc::c_long as uint64_t;
    t1 = t1 >> 24 as libc::c_int;
    h2 = h2.wrapping_add(t1.wrapping_add(c));
    CRYPTO_store_u64_le(
        mac.offset(0 as libc::c_int as isize) as *mut libc::c_void,
        h0 | h1 << 44 as libc::c_int,
    );
    CRYPTO_store_u64_le(
        mac.offset(8 as libc::c_int as isize) as *mut libc::c_void,
        h1 >> 20 as libc::c_int | h2 << 24 as libc::c_int,
    );
}
