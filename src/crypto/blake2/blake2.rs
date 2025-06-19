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
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
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
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct blake2b_state_st {
    pub h: [uint64_t; 8],
    pub t_low: uint64_t,
    pub t_high: uint64_t,
    pub block: [uint8_t; 128],
    pub block_used: size_t,
}
pub type BLAKE2B_CTX = blake2b_state_st;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_121_error_is__ {
    #[bitfield(
        name = "static_assertion_at_line_121_error_is__",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_121_error_is__: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_77_error_is__ {
    #[bitfield(
        name = "static_assertion_at_line_77_error_is__",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_77_error_is__: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_170_error_is__ {
    #[bitfield(
        name = "static_assertion_at_line_170_error_is__",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_170_error_is__: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
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
unsafe extern "C" fn CRYPTO_rotr_u64(
    mut value: uint64_t,
    mut shift: libc::c_int,
) -> uint64_t {
    return value >> shift | value << (-shift & 63 as libc::c_int);
}
static mut kIV: [uint64_t; 8] = [
    0x6a09e667f3bcc908 as libc::c_ulong,
    0xbb67ae8584caa73b as libc::c_ulong,
    0x3c6ef372fe94f82b as libc::c_ulong,
    0xa54ff53a5f1d36f1 as libc::c_ulong,
    0x510e527fade682d1 as libc::c_ulong,
    0x9b05688c2b3e6c1f as libc::c_ulong,
    0x1f83d9abfb41bd6b as libc::c_ulong,
    0x5be0cd19137e2179 as libc::c_ulong,
];
static mut kSigma: [uint8_t; 160] = [
    0 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    3 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
    5 as libc::c_int as uint8_t,
    6 as libc::c_int as uint8_t,
    7 as libc::c_int as uint8_t,
    8 as libc::c_int as uint8_t,
    9 as libc::c_int as uint8_t,
    10 as libc::c_int as uint8_t,
    11 as libc::c_int as uint8_t,
    12 as libc::c_int as uint8_t,
    13 as libc::c_int as uint8_t,
    14 as libc::c_int as uint8_t,
    15 as libc::c_int as uint8_t,
    14 as libc::c_int as uint8_t,
    10 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
    8 as libc::c_int as uint8_t,
    9 as libc::c_int as uint8_t,
    15 as libc::c_int as uint8_t,
    13 as libc::c_int as uint8_t,
    6 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    12 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    11 as libc::c_int as uint8_t,
    7 as libc::c_int as uint8_t,
    5 as libc::c_int as uint8_t,
    3 as libc::c_int as uint8_t,
    11 as libc::c_int as uint8_t,
    8 as libc::c_int as uint8_t,
    12 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    5 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    15 as libc::c_int as uint8_t,
    13 as libc::c_int as uint8_t,
    10 as libc::c_int as uint8_t,
    14 as libc::c_int as uint8_t,
    3 as libc::c_int as uint8_t,
    6 as libc::c_int as uint8_t,
    7 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    9 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
    7 as libc::c_int as uint8_t,
    9 as libc::c_int as uint8_t,
    3 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    13 as libc::c_int as uint8_t,
    12 as libc::c_int as uint8_t,
    11 as libc::c_int as uint8_t,
    14 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    6 as libc::c_int as uint8_t,
    5 as libc::c_int as uint8_t,
    10 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    15 as libc::c_int as uint8_t,
    8 as libc::c_int as uint8_t,
    9 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    5 as libc::c_int as uint8_t,
    7 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
    10 as libc::c_int as uint8_t,
    15 as libc::c_int as uint8_t,
    14 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    11 as libc::c_int as uint8_t,
    12 as libc::c_int as uint8_t,
    6 as libc::c_int as uint8_t,
    8 as libc::c_int as uint8_t,
    3 as libc::c_int as uint8_t,
    13 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    12 as libc::c_int as uint8_t,
    6 as libc::c_int as uint8_t,
    10 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    11 as libc::c_int as uint8_t,
    8 as libc::c_int as uint8_t,
    3 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
    13 as libc::c_int as uint8_t,
    7 as libc::c_int as uint8_t,
    5 as libc::c_int as uint8_t,
    15 as libc::c_int as uint8_t,
    14 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    9 as libc::c_int as uint8_t,
    12 as libc::c_int as uint8_t,
    5 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    15 as libc::c_int as uint8_t,
    14 as libc::c_int as uint8_t,
    13 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
    10 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    7 as libc::c_int as uint8_t,
    6 as libc::c_int as uint8_t,
    3 as libc::c_int as uint8_t,
    9 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    8 as libc::c_int as uint8_t,
    11 as libc::c_int as uint8_t,
    13 as libc::c_int as uint8_t,
    11 as libc::c_int as uint8_t,
    7 as libc::c_int as uint8_t,
    14 as libc::c_int as uint8_t,
    12 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    3 as libc::c_int as uint8_t,
    9 as libc::c_int as uint8_t,
    5 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    15 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
    8 as libc::c_int as uint8_t,
    6 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    10 as libc::c_int as uint8_t,
    6 as libc::c_int as uint8_t,
    15 as libc::c_int as uint8_t,
    14 as libc::c_int as uint8_t,
    9 as libc::c_int as uint8_t,
    11 as libc::c_int as uint8_t,
    3 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    8 as libc::c_int as uint8_t,
    12 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    13 as libc::c_int as uint8_t,
    7 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
    10 as libc::c_int as uint8_t,
    5 as libc::c_int as uint8_t,
    10 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    8 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
    7 as libc::c_int as uint8_t,
    6 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    5 as libc::c_int as uint8_t,
    15 as libc::c_int as uint8_t,
    11 as libc::c_int as uint8_t,
    9 as libc::c_int as uint8_t,
    14 as libc::c_int as uint8_t,
    3 as libc::c_int as uint8_t,
    12 as libc::c_int as uint8_t,
    13 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
];
unsafe extern "C" fn blake2b_mix(
    mut v: *mut uint64_t,
    mut a: libc::c_int,
    mut b: libc::c_int,
    mut c: libc::c_int,
    mut d: libc::c_int,
    mut x: uint64_t,
    mut y: uint64_t,
) {
    *v
        .offset(
            a as isize,
        ) = (*v.offset(a as isize)).wrapping_add(*v.offset(b as isize)).wrapping_add(x);
    *v
        .offset(
            d as isize,
        ) = CRYPTO_rotr_u64(
        *v.offset(d as isize) ^ *v.offset(a as isize),
        32 as libc::c_int,
    );
    *v.offset(c as isize) = (*v.offset(c as isize)).wrapping_add(*v.offset(d as isize));
    *v
        .offset(
            b as isize,
        ) = CRYPTO_rotr_u64(
        *v.offset(b as isize) ^ *v.offset(c as isize),
        24 as libc::c_int,
    );
    *v
        .offset(
            a as isize,
        ) = (*v.offset(a as isize)).wrapping_add(*v.offset(b as isize)).wrapping_add(y);
    *v
        .offset(
            d as isize,
        ) = CRYPTO_rotr_u64(
        *v.offset(d as isize) ^ *v.offset(a as isize),
        16 as libc::c_int,
    );
    *v.offset(c as isize) = (*v.offset(c as isize)).wrapping_add(*v.offset(d as isize));
    *v
        .offset(
            b as isize,
        ) = CRYPTO_rotr_u64(
        *v.offset(b as isize) ^ *v.offset(c as isize),
        63 as libc::c_int,
    );
}
unsafe extern "C" fn blake2b_load(mut block: *const uint8_t, mut i: size_t) -> uint64_t {
    return CRYPTO_load_u64_le(
        block.offset((8 as libc::c_int as size_t * i) as isize) as *const libc::c_void,
    );
}
unsafe extern "C" fn copy_digest_words_to_dest(
    mut dest: *mut uint8_t,
    mut src: *mut uint64_t,
    mut word_count: size_t,
) {
    OPENSSL_memcpy(
        dest as *mut libc::c_void,
        src as *const libc::c_void,
        word_count.wrapping_mul(::core::mem::size_of::<uint64_t>() as libc::c_ulong),
    );
}
unsafe extern "C" fn blake2b_transform(
    mut b2b: *mut BLAKE2B_CTX,
    mut block: *const uint8_t,
    mut num_bytes: size_t,
    mut is_final_block: libc::c_int,
) {
    let mut v: [uint64_t; 16] = [0; 16];
    OPENSSL_memcpy(
        v.as_mut_ptr() as *mut libc::c_void,
        ((*b2b).h).as_mut_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint64_t; 8]>() as libc::c_ulong,
    );
    OPENSSL_memcpy(
        &mut *v.as_mut_ptr().offset(8 as libc::c_int as isize) as *mut uint64_t
            as *mut libc::c_void,
        kIV.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint64_t; 8]>() as libc::c_ulong,
    );
    (*b2b)
        .t_low = ((*b2b).t_low as libc::c_ulong).wrapping_add(num_bytes) as uint64_t
        as uint64_t;
    if (*b2b).t_low < num_bytes {
        (*b2b).t_high = ((*b2b).t_high).wrapping_add(1);
        (*b2b).t_high;
    }
    v[12 as libc::c_int as usize] ^= (*b2b).t_low;
    v[13 as libc::c_int as usize] ^= (*b2b).t_high;
    if is_final_block != 0 {
        v[14 as libc::c_int as usize] = !v[14 as libc::c_int as usize];
    }
    let mut round: libc::c_int = 0 as libc::c_int;
    while round < 12 as libc::c_int {
        let s: *const uint8_t = &*kSigma
            .as_ptr()
            .offset((16 as libc::c_int * (round % 10 as libc::c_int)) as isize)
            as *const uint8_t;
        blake2b_mix(
            v.as_mut_ptr(),
            0 as libc::c_int,
            4 as libc::c_int,
            8 as libc::c_int,
            12 as libc::c_int,
            blake2b_load(block, *s.offset(0 as libc::c_int as isize) as size_t),
            blake2b_load(block, *s.offset(1 as libc::c_int as isize) as size_t),
        );
        blake2b_mix(
            v.as_mut_ptr(),
            1 as libc::c_int,
            5 as libc::c_int,
            9 as libc::c_int,
            13 as libc::c_int,
            blake2b_load(block, *s.offset(2 as libc::c_int as isize) as size_t),
            blake2b_load(block, *s.offset(3 as libc::c_int as isize) as size_t),
        );
        blake2b_mix(
            v.as_mut_ptr(),
            2 as libc::c_int,
            6 as libc::c_int,
            10 as libc::c_int,
            14 as libc::c_int,
            blake2b_load(block, *s.offset(4 as libc::c_int as isize) as size_t),
            blake2b_load(block, *s.offset(5 as libc::c_int as isize) as size_t),
        );
        blake2b_mix(
            v.as_mut_ptr(),
            3 as libc::c_int,
            7 as libc::c_int,
            11 as libc::c_int,
            15 as libc::c_int,
            blake2b_load(block, *s.offset(6 as libc::c_int as isize) as size_t),
            blake2b_load(block, *s.offset(7 as libc::c_int as isize) as size_t),
        );
        blake2b_mix(
            v.as_mut_ptr(),
            0 as libc::c_int,
            5 as libc::c_int,
            10 as libc::c_int,
            15 as libc::c_int,
            blake2b_load(block, *s.offset(8 as libc::c_int as isize) as size_t),
            blake2b_load(block, *s.offset(9 as libc::c_int as isize) as size_t),
        );
        blake2b_mix(
            v.as_mut_ptr(),
            1 as libc::c_int,
            6 as libc::c_int,
            11 as libc::c_int,
            12 as libc::c_int,
            blake2b_load(block, *s.offset(10 as libc::c_int as isize) as size_t),
            blake2b_load(block, *s.offset(11 as libc::c_int as isize) as size_t),
        );
        blake2b_mix(
            v.as_mut_ptr(),
            2 as libc::c_int,
            7 as libc::c_int,
            8 as libc::c_int,
            13 as libc::c_int,
            blake2b_load(block, *s.offset(12 as libc::c_int as isize) as size_t),
            blake2b_load(block, *s.offset(13 as libc::c_int as isize) as size_t),
        );
        blake2b_mix(
            v.as_mut_ptr(),
            3 as libc::c_int,
            4 as libc::c_int,
            9 as libc::c_int,
            14 as libc::c_int,
            blake2b_load(block, *s.offset(14 as libc::c_int as isize) as size_t),
            blake2b_load(block, *s.offset(15 as libc::c_int as isize) as size_t),
        );
        round += 1;
        round;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (::core::mem::size_of::<[uint64_t; 8]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<uint64_t>() as libc::c_ulong)
    {
        (*b2b).h[i as usize] ^= v[i as usize];
        (*b2b).h[i as usize] ^= v[i.wrapping_add(8 as libc::c_int as size_t) as usize];
        i = i.wrapping_add(1);
        i;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BLAKE2B256_Init(mut b2b: *mut BLAKE2B_CTX) {
    OPENSSL_memset(
        b2b as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<BLAKE2B_CTX>() as libc::c_ulong,
    );
    OPENSSL_memcpy(
        &mut (*b2b).h as *mut [uint64_t; 8] as *mut libc::c_void,
        kIV.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint64_t; 8]>() as libc::c_ulong,
    );
    (*b2b).h[0 as libc::c_int as usize]
        ^= (0x1010000 as libc::c_int | 256 as libc::c_int / 8 as libc::c_int)
            as uint64_t;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BLAKE2B256_Update(
    mut b2b: *mut BLAKE2B_CTX,
    mut in_data: *const libc::c_void,
    mut len: size_t,
) {
    if len == 0 as libc::c_int as size_t {
        return;
    }
    let mut data: *const uint8_t = in_data as *const uint8_t;
    let mut todo: size_t = (::core::mem::size_of::<[uint8_t; 128]>() as libc::c_ulong)
        .wrapping_sub((*b2b).block_used);
    if todo > len {
        todo = len;
    }
    OPENSSL_memcpy(
        &mut *((*b2b).block).as_mut_ptr().offset((*b2b).block_used as isize)
            as *mut uint8_t as *mut libc::c_void,
        data as *const libc::c_void,
        todo,
    );
    (*b2b).block_used = ((*b2b).block_used).wrapping_add(todo);
    data = data.offset(todo as isize);
    len = len.wrapping_sub(todo);
    if len == 0 as libc::c_int as size_t {
        return;
    }
    if (*b2b).block_used == 128 as libc::c_int as size_t {} else {
        __assert_fail(
            b"b2b->block_used == BLAKE2B_CBLOCK\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/blake2/blake2.c\0" as *const u8
                as *const libc::c_char,
            150 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 60],
                &[libc::c_char; 60],
            >(b"void BLAKE2B256_Update(BLAKE2B_CTX *, const void *, size_t)\0"))
                .as_ptr(),
        );
    }
    'c_2495: {
        if (*b2b).block_used == 128 as libc::c_int as size_t {} else {
            __assert_fail(
                b"b2b->block_used == BLAKE2B_CBLOCK\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/blake2/blake2.c\0"
                    as *const u8 as *const libc::c_char,
                150 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 60],
                    &[libc::c_char; 60],
                >(b"void BLAKE2B256_Update(BLAKE2B_CTX *, const void *, size_t)\0"))
                    .as_ptr(),
            );
        }
    };
    blake2b_transform(
        b2b,
        ((*b2b).block).as_mut_ptr() as *const uint8_t,
        128 as libc::c_int as size_t,
        0 as libc::c_int,
    );
    (*b2b).block_used = 0 as libc::c_int as size_t;
    while len > 128 as libc::c_int as size_t {
        blake2b_transform(b2b, data, 128 as libc::c_int as size_t, 0 as libc::c_int);
        data = data.offset(128 as libc::c_int as isize);
        len = len.wrapping_sub(128 as libc::c_int as size_t);
    }
    OPENSSL_memcpy(
        ((*b2b).block).as_mut_ptr() as *mut libc::c_void,
        data as *const libc::c_void,
        len,
    );
    (*b2b).block_used = len;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BLAKE2B256_Final(
    mut out: *mut uint8_t,
    mut b2b: *mut BLAKE2B_CTX,
) {
    OPENSSL_memset(
        &mut *((*b2b).block).as_mut_ptr().offset((*b2b).block_used as isize)
            as *mut uint8_t as *mut libc::c_void,
        0 as libc::c_int,
        (::core::mem::size_of::<[uint8_t; 128]>() as libc::c_ulong)
            .wrapping_sub((*b2b).block_used),
    );
    blake2b_transform(
        b2b,
        ((*b2b).block).as_mut_ptr() as *const uint8_t,
        (*b2b).block_used,
        1 as libc::c_int,
    );
    copy_digest_words_to_dest(
        out,
        ((*b2b).h).as_mut_ptr(),
        (256 as libc::c_int / 8 as libc::c_int / 8 as libc::c_int) as size_t,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BLAKE2B256(
    mut data: *const uint8_t,
    mut len: size_t,
    mut out: *mut uint8_t,
) {
    let mut ctx: BLAKE2B_CTX = blake2b_state_st {
        h: [0; 8],
        t_low: 0,
        t_high: 0,
        block: [0; 128],
        block_used: 0,
    };
    BLAKE2B256_Init(&mut ctx);
    BLAKE2B256_Update(&mut ctx, data as *const libc::c_void, len);
    BLAKE2B256_Final(out, &mut ctx);
}
