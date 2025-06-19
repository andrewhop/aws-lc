#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
unsafe extern "C" {
    pub type env_md_st;
    fn EVP_sha256() -> *const EVP_MD;
    fn OPENSSL_calloc(num: size_t, size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn PKCS5_PBKDF2_HMAC(
        password: *const libc::c_char,
        password_len: size_t,
        salt: *const uint8_t,
        salt_len: size_t,
        iterations: uint32_t,
        digest: *const EVP_MD,
        key_len: size_t,
        out_key: *mut uint8_t,
    ) -> libc::c_int;
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
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type EVP_MD = env_md_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct block_t {
    pub words: [uint32_t; 16],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_186_error_is_size_t_exceeds_uint64_t {
    #[bitfield(
        name = "static_assertion_at_line_186_error_is_size_t_exceeds_uint64_t",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_186_error_is_size_t_exceeds_uint64_t: [u8; 1],
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
unsafe extern "C" fn CRYPTO_rotl_u32(
    mut value: uint32_t,
    mut shift: libc::c_int,
) -> uint32_t {
    return value << shift | value >> (-shift & 31 as libc::c_int);
}
unsafe extern "C" fn salsa208_word_specification(mut inout: *mut block_t) {
    let mut x: block_t = block_t { words: [0; 16] };
    OPENSSL_memcpy(
        &mut x as *mut block_t as *mut libc::c_void,
        inout as *const libc::c_void,
        ::core::mem::size_of::<block_t>() as libc::c_ulong,
    );
    let mut i: libc::c_int = 8 as libc::c_int;
    while i > 0 as libc::c_int {
        x.words[4 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[0 as libc::c_int as usize])
                    .wrapping_add(x.words[12 as libc::c_int as usize]),
                7 as libc::c_int,
            );
        x.words[8 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[4 as libc::c_int as usize])
                    .wrapping_add(x.words[0 as libc::c_int as usize]),
                9 as libc::c_int,
            );
        x.words[12 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[8 as libc::c_int as usize])
                    .wrapping_add(x.words[4 as libc::c_int as usize]),
                13 as libc::c_int,
            );
        x.words[0 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[12 as libc::c_int as usize])
                    .wrapping_add(x.words[8 as libc::c_int as usize]),
                18 as libc::c_int,
            );
        x.words[9 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[5 as libc::c_int as usize])
                    .wrapping_add(x.words[1 as libc::c_int as usize]),
                7 as libc::c_int,
            );
        x.words[13 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[9 as libc::c_int as usize])
                    .wrapping_add(x.words[5 as libc::c_int as usize]),
                9 as libc::c_int,
            );
        x.words[1 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[13 as libc::c_int as usize])
                    .wrapping_add(x.words[9 as libc::c_int as usize]),
                13 as libc::c_int,
            );
        x.words[5 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[1 as libc::c_int as usize])
                    .wrapping_add(x.words[13 as libc::c_int as usize]),
                18 as libc::c_int,
            );
        x.words[14 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[10 as libc::c_int as usize])
                    .wrapping_add(x.words[6 as libc::c_int as usize]),
                7 as libc::c_int,
            );
        x.words[2 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[14 as libc::c_int as usize])
                    .wrapping_add(x.words[10 as libc::c_int as usize]),
                9 as libc::c_int,
            );
        x.words[6 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[2 as libc::c_int as usize])
                    .wrapping_add(x.words[14 as libc::c_int as usize]),
                13 as libc::c_int,
            );
        x.words[10 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[6 as libc::c_int as usize])
                    .wrapping_add(x.words[2 as libc::c_int as usize]),
                18 as libc::c_int,
            );
        x.words[3 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[15 as libc::c_int as usize])
                    .wrapping_add(x.words[11 as libc::c_int as usize]),
                7 as libc::c_int,
            );
        x.words[7 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[3 as libc::c_int as usize])
                    .wrapping_add(x.words[15 as libc::c_int as usize]),
                9 as libc::c_int,
            );
        x.words[11 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[7 as libc::c_int as usize])
                    .wrapping_add(x.words[3 as libc::c_int as usize]),
                13 as libc::c_int,
            );
        x.words[15 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[11 as libc::c_int as usize])
                    .wrapping_add(x.words[7 as libc::c_int as usize]),
                18 as libc::c_int,
            );
        x.words[1 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[0 as libc::c_int as usize])
                    .wrapping_add(x.words[3 as libc::c_int as usize]),
                7 as libc::c_int,
            );
        x.words[2 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[1 as libc::c_int as usize])
                    .wrapping_add(x.words[0 as libc::c_int as usize]),
                9 as libc::c_int,
            );
        x.words[3 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[2 as libc::c_int as usize])
                    .wrapping_add(x.words[1 as libc::c_int as usize]),
                13 as libc::c_int,
            );
        x.words[0 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[3 as libc::c_int as usize])
                    .wrapping_add(x.words[2 as libc::c_int as usize]),
                18 as libc::c_int,
            );
        x.words[6 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[5 as libc::c_int as usize])
                    .wrapping_add(x.words[4 as libc::c_int as usize]),
                7 as libc::c_int,
            );
        x.words[7 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[6 as libc::c_int as usize])
                    .wrapping_add(x.words[5 as libc::c_int as usize]),
                9 as libc::c_int,
            );
        x.words[4 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[7 as libc::c_int as usize])
                    .wrapping_add(x.words[6 as libc::c_int as usize]),
                13 as libc::c_int,
            );
        x.words[5 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[4 as libc::c_int as usize])
                    .wrapping_add(x.words[7 as libc::c_int as usize]),
                18 as libc::c_int,
            );
        x.words[11 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[10 as libc::c_int as usize])
                    .wrapping_add(x.words[9 as libc::c_int as usize]),
                7 as libc::c_int,
            );
        x.words[8 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[11 as libc::c_int as usize])
                    .wrapping_add(x.words[10 as libc::c_int as usize]),
                9 as libc::c_int,
            );
        x.words[9 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[8 as libc::c_int as usize])
                    .wrapping_add(x.words[11 as libc::c_int as usize]),
                13 as libc::c_int,
            );
        x.words[10 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[9 as libc::c_int as usize])
                    .wrapping_add(x.words[8 as libc::c_int as usize]),
                18 as libc::c_int,
            );
        x.words[12 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[15 as libc::c_int as usize])
                    .wrapping_add(x.words[14 as libc::c_int as usize]),
                7 as libc::c_int,
            );
        x.words[13 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[12 as libc::c_int as usize])
                    .wrapping_add(x.words[15 as libc::c_int as usize]),
                9 as libc::c_int,
            );
        x.words[14 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[13 as libc::c_int as usize])
                    .wrapping_add(x.words[12 as libc::c_int as usize]),
                13 as libc::c_int,
            );
        x.words[15 as libc::c_int as usize]
            ^= CRYPTO_rotl_u32(
                (x.words[14 as libc::c_int as usize])
                    .wrapping_add(x.words[13 as libc::c_int as usize]),
                18 as libc::c_int,
            );
        i -= 2 as libc::c_int;
    }
    let mut i_0: libc::c_int = 0 as libc::c_int;
    while i_0 < 16 as libc::c_int {
        (*inout)
            .words[i_0
            as usize] = ((*inout).words[i_0 as usize])
            .wrapping_add(x.words[i_0 as usize]);
        i_0 += 1;
        i_0;
    }
}
unsafe extern "C" fn xor_block(
    mut out: *mut block_t,
    mut a: *const block_t,
    mut b: *const block_t,
) {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < 16 as libc::c_int as size_t {
        (*out).words[i as usize] = (*a).words[i as usize] ^ (*b).words[i as usize];
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn scryptBlockMix(
    mut out: *mut block_t,
    mut B: *const block_t,
    mut r: uint64_t,
) {
    if out != B as *mut block_t {} else {
        __assert_fail(
            b"out != B\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/scrypt.c\0" as *const u8
                as *const libc::c_char,
            94 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 58],
                &[libc::c_char; 58],
            >(b"void scryptBlockMix(block_t *, const block_t *, uint64_t)\0"))
                .as_ptr(),
        );
    }
    'c_11246: {
        if out != B as *mut block_t {} else {
            __assert_fail(
                b"out != B\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/scrypt.c\0"
                    as *const u8 as *const libc::c_char,
                94 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 58],
                    &[libc::c_char; 58],
                >(b"void scryptBlockMix(block_t *, const block_t *, uint64_t)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut X: block_t = block_t { words: [0; 16] };
    OPENSSL_memcpy(
        &mut X as *mut block_t as *mut libc::c_void,
        &*B
            .offset(
                (r * 2 as libc::c_int as uint64_t)
                    .wrapping_sub(1 as libc::c_int as uint64_t) as isize,
            ) as *const block_t as *const libc::c_void,
        ::core::mem::size_of::<block_t>() as libc::c_ulong,
    );
    let mut i: uint64_t = 0 as libc::c_int as uint64_t;
    while i < r * 2 as libc::c_int as uint64_t {
        xor_block(&mut X, &mut X, &*B.offset(i as isize));
        salsa208_word_specification(&mut X);
        OPENSSL_memcpy(
            &mut *out
                .offset(
                    (i / 2 as libc::c_int as uint64_t)
                        .wrapping_add((i & 1 as libc::c_int as uint64_t) * r) as isize,
                ) as *mut block_t as *mut libc::c_void,
            &mut X as *mut block_t as *const libc::c_void,
            ::core::mem::size_of::<block_t>() as libc::c_ulong,
        );
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn scryptROMix(
    mut B: *mut block_t,
    mut r: uint64_t,
    mut N: uint64_t,
    mut T: *mut block_t,
    mut V: *mut block_t,
) {
    OPENSSL_memcpy(
        V as *mut libc::c_void,
        B as *const libc::c_void,
        (2 as libc::c_int as uint64_t * r)
            .wrapping_mul(::core::mem::size_of::<block_t>() as libc::c_ulong),
    );
    let mut i: uint64_t = 1 as libc::c_int as uint64_t;
    while i < N {
        scryptBlockMix(
            &mut *V.offset((2 as libc::c_int as uint64_t * r * i) as isize),
            &mut *V
                .offset(
                    (2 as libc::c_int as uint64_t * r
                        * i.wrapping_sub(1 as libc::c_int as uint64_t)) as isize,
                ),
            r,
        );
        i = i.wrapping_add(1);
        i;
    }
    scryptBlockMix(
        B,
        &mut *V
            .offset(
                (2 as libc::c_int as uint64_t * r
                    * N.wrapping_sub(1 as libc::c_int as uint64_t)) as isize,
            ),
        r,
    );
    let mut i_0: uint64_t = 0 as libc::c_int as uint64_t;
    while i_0 < N {
        let mut j: uint32_t = ((*B
            .offset(
                (2 as libc::c_int as uint64_t * r)
                    .wrapping_sub(1 as libc::c_int as uint64_t) as isize,
            ))
            .words[0 as libc::c_int as usize] as uint64_t
            & N.wrapping_sub(1 as libc::c_int as uint64_t)) as uint32_t;
        let mut k: size_t = 0 as libc::c_int as size_t;
        while k < 2 as libc::c_int as uint64_t * r {
            xor_block(
                &mut *T.offset(k as isize),
                &mut *B.offset(k as isize),
                &mut *V
                    .offset(
                        (2 as libc::c_int as uint64_t * r * j as uint64_t)
                            .wrapping_add(k) as isize,
                    ),
            );
            k = k.wrapping_add(1);
            k;
        }
        scryptBlockMix(B, T, r);
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_PBE_scrypt(
    mut password: *const libc::c_char,
    mut password_len: size_t,
    mut salt: *const uint8_t,
    mut salt_len: size_t,
    mut N: uint64_t,
    mut r: uint64_t,
    mut p: uint64_t,
    mut max_mem: size_t,
    mut out_key: *mut uint8_t,
    mut key_len: size_t,
) -> libc::c_int {
    if r == 0 as libc::c_int as uint64_t || p == 0 as libc::c_int as uint64_t
        || p
            > (((1 as libc::c_int) << 30 as libc::c_int) - 1 as libc::c_int) as uint64_t
                / r || N < 2 as libc::c_int as uint64_t
        || N & N.wrapping_sub(1 as libc::c_int as uint64_t) != 0
        || N > (1 as libc::c_ulong) << 32 as libc::c_int
        || 16 as libc::c_int as uint64_t * r <= 63 as libc::c_int as uint64_t
            && N >= (1 as libc::c_ulong) << 16 as libc::c_int as uint64_t * r
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            133 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/scrypt.c\0" as *const u8
                as *const libc::c_char,
            167 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if max_mem == 0 as libc::c_int as size_t {
        max_mem = (1024 as libc::c_int * 1024 as libc::c_int * 32 as libc::c_int)
            as size_t;
    }
    let mut max_scrypt_blocks: size_t = max_mem
        .wrapping_div(
            (2 as libc::c_int as uint64_t * r)
                .wrapping_mul(::core::mem::size_of::<block_t>() as libc::c_ulong),
        );
    if max_scrypt_blocks < p.wrapping_add(1 as libc::c_int as uint64_t)
        || max_scrypt_blocks
            .wrapping_sub(p)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong) < N
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            132 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/scrypt.c\0" as *const u8
                as *const libc::c_char,
            180 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut B_blocks: size_t = p * 2 as libc::c_int as uint64_t * r;
    let mut B_bytes: size_t = B_blocks
        .wrapping_mul(::core::mem::size_of::<block_t>() as libc::c_ulong);
    let mut T_blocks: size_t = 2 as libc::c_int as uint64_t * r;
    let mut V_blocks: size_t = N * 2 as libc::c_int as uint64_t * r;
    let mut B: *mut block_t = OPENSSL_calloc(
        B_blocks.wrapping_add(T_blocks).wrapping_add(V_blocks),
        ::core::mem::size_of::<block_t>() as libc::c_ulong,
    ) as *mut block_t;
    if B.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut T: *mut block_t = B.offset(B_blocks as isize);
    let mut V: *mut block_t = T.offset(T_blocks as isize);
    if !(PKCS5_PBKDF2_HMAC(
        password,
        password_len,
        salt,
        salt_len,
        1 as libc::c_int as uint32_t,
        EVP_sha256(),
        B_bytes,
        B as *mut uint8_t,
    ) == 0)
    {
        let mut i: uint64_t = 0 as libc::c_int as uint64_t;
        while i < p {
            scryptROMix(
                B.offset((2 as libc::c_int as uint64_t * r * i) as isize),
                r,
                N,
                T,
                V,
            );
            i = i.wrapping_add(1);
            i;
        }
        if !(PKCS5_PBKDF2_HMAC(
            password,
            password_len,
            B as *const uint8_t,
            B_bytes,
            1 as libc::c_int as uint32_t,
            EVP_sha256(),
            key_len,
            out_key,
        ) == 0)
        {
            ret = 1 as libc::c_int;
        }
    }
    OPENSSL_free(B as *mut libc::c_void);
    return ret;
}
