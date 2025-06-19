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
    fn abort() -> !;
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
    fn CRYPTO_memcmp(
        a: *const libc::c_void,
        b: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn gcm_init_nohw(Htable: *mut u128_0, H: *const uint64_t);
    fn gcm_gmult_nohw(Xi: *mut uint8_t, Htable: *const u128_0);
    fn gcm_ghash_nohw(
        Xi: *mut uint8_t,
        Htable: *const u128_0,
        inp: *const uint8_t,
        len: size_t,
    );
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
pub struct aes_key_st {
    pub rd_key: [uint32_t; 60],
    pub rounds: libc::c_uint,
}
pub type AES_KEY = aes_key_st;
pub type crypto_word_t = uint64_t;
pub type block128_f = Option::<
    unsafe extern "C" fn(*const uint8_t, *mut uint8_t, *const AES_KEY) -> (),
>;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_90_error_is_block_cannot_be_evenly_divided_into_crypto_word_t {
    #[bitfield(
        name = "static_assertion_at_line_90_error_is_block_cannot_be_evenly_divided_into_crypto_word_t",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_90_error_is_block_cannot_be_evenly_divided_into_crypto_word_t: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
pub type ctr128_f = Option::<
    unsafe extern "C" fn(
        *const uint8_t,
        *mut uint8_t,
        size_t,
        *const AES_KEY,
        *const uint8_t,
    ) -> (),
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct u128_0 {
    pub hi: uint64_t,
    pub lo: uint64_t,
}
pub type gmult_func = Option::<unsafe extern "C" fn(*mut uint8_t, *const u128_0) -> ()>;
pub type ghash_func = Option::<
    unsafe extern "C" fn(*mut uint8_t, *const u128_0, *const uint8_t, size_t) -> (),
>;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct gcm128_key_st {
    pub Htable: [u128_0; 16],
    pub gmult: gmult_func,
    pub ghash: ghash_func,
    pub block: block128_f,
    #[bitfield(name = "use_hw_gcm_crypt", ty = "libc::c_uint", bits = "0..=0")]
    pub use_hw_gcm_crypt: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
pub type GCM128_KEY = gcm128_key_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct GCM128_CONTEXT {
    pub Yi: [uint8_t; 16],
    pub EKi: [uint8_t; 16],
    pub EK0: [uint8_t; 16],
    pub len: C2RustUnnamed,
    pub Xi: [uint8_t; 16],
    pub gcm_key: GCM128_KEY,
    pub mres: libc::c_uint,
    pub ares: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed {
    pub aad: uint64_t,
    pub msg: uint64_t,
}
#[inline]
unsafe extern "C" fn CRYPTO_bswap4(mut x: uint32_t) -> uint32_t {
    return x.swap_bytes();
}
#[inline]
unsafe extern "C" fn CRYPTO_bswap8(mut x: uint64_t) -> uint64_t {
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
unsafe extern "C" fn CRYPTO_load_u64_be(mut ptr: *const libc::c_void) -> uint64_t {
    let mut ret: uint64_t = 0;
    OPENSSL_memcpy(
        &mut ret as *mut uint64_t as *mut libc::c_void,
        ptr,
        ::core::mem::size_of::<uint64_t>() as libc::c_ulong,
    );
    return CRYPTO_bswap8(ret);
}
#[inline]
unsafe extern "C" fn CRYPTO_store_u64_be(mut out: *mut libc::c_void, mut v: uint64_t) {
    v = CRYPTO_bswap8(v);
    OPENSSL_memcpy(
        out,
        &mut v as *mut uint64_t as *const libc::c_void,
        ::core::mem::size_of::<uint64_t>() as libc::c_ulong,
    );
}
#[inline]
unsafe extern "C" fn CRYPTO_load_word_le(
    mut in_0: *const libc::c_void,
) -> crypto_word_t {
    let mut v: crypto_word_t = 0;
    OPENSSL_memcpy(
        &mut v as *mut crypto_word_t as *mut libc::c_void,
        in_0,
        ::core::mem::size_of::<crypto_word_t>() as libc::c_ulong,
    );
    return v;
}
#[inline]
unsafe extern "C" fn CRYPTO_store_word_le(
    mut out: *mut libc::c_void,
    mut v: crypto_word_t,
) {
    OPENSSL_memcpy(
        out,
        &mut v as *mut crypto_word_t as *const libc::c_void,
        ::core::mem::size_of::<crypto_word_t>() as libc::c_ulong,
    );
}
#[inline]
unsafe extern "C" fn CRYPTO_xor16(
    mut out: *mut uint8_t,
    mut a: *const uint8_t,
    mut b: *const uint8_t,
) {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < 16 as libc::c_int as size_t {
        CRYPTO_store_word_le(
            out.offset(i as isize) as *mut libc::c_void,
            CRYPTO_load_word_le(a.offset(i as isize) as *const libc::c_void)
                ^ CRYPTO_load_word_le(b.offset(i as isize) as *const libc::c_void),
        );
        i = (i as libc::c_ulong)
            .wrapping_add(::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
            as size_t as size_t;
    }
}
static mut kSizeTWithoutLower4Bits: size_t = -(16 as libc::c_int) as size_t;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_ghash_init(
    mut out_mult: *mut gmult_func,
    mut out_hash: *mut ghash_func,
    mut out_table: *mut u128_0,
    mut out_is_avx: *mut libc::c_int,
    mut gcm_key: *const uint8_t,
) {
    *out_is_avx = 0 as libc::c_int;
    let mut H: [uint64_t; 2] = [
        CRYPTO_load_u64_be(gcm_key as *const libc::c_void),
        CRYPTO_load_u64_be(
            gcm_key.offset(8 as libc::c_int as isize) as *const libc::c_void,
        ),
    ];
    gcm_init_nohw(out_table, H.as_mut_ptr() as *const uint64_t);
    *out_mult = Some(
        gcm_gmult_nohw as unsafe extern "C" fn(*mut uint8_t, *const u128_0) -> (),
    );
    *out_hash = Some(
        gcm_ghash_nohw
            as unsafe extern "C" fn(
                *mut uint8_t,
                *const u128_0,
                *const uint8_t,
                size_t,
            ) -> (),
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_gcm128_init_key(
    mut gcm_key: *mut GCM128_KEY,
    mut aes_key: *const AES_KEY,
    mut block: block128_f,
    mut block_is_hwaes: libc::c_int,
) {
    OPENSSL_memset(
        gcm_key as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<GCM128_KEY>() as libc::c_ulong,
    );
    (*gcm_key).block = block;
    let mut ghash_key: [uint8_t; 16] = [0; 16];
    OPENSSL_memset(
        ghash_key.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong,
    );
    (Some(block.expect("non-null function pointer")))
        .expect(
            "non-null function pointer",
        )(ghash_key.as_mut_ptr() as *const uint8_t, ghash_key.as_mut_ptr(), aes_key);
    let mut is_avx: libc::c_int = 0;
    CRYPTO_ghash_init(
        &mut (*gcm_key).gmult,
        &mut (*gcm_key).ghash,
        ((*gcm_key).Htable).as_mut_ptr(),
        &mut is_avx,
        ghash_key.as_mut_ptr() as *const uint8_t,
    );
    (*gcm_key)
        .set_use_hw_gcm_crypt(
            (if is_avx != 0 && block_is_hwaes != 0 {
                1 as libc::c_int
            } else {
                0 as libc::c_int
            }) as libc::c_uint,
        );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_gcm128_setiv(
    mut ctx: *mut GCM128_CONTEXT,
    mut key: *const AES_KEY,
    mut iv: *const uint8_t,
    mut len: size_t,
) {
    OPENSSL_memset(
        &mut (*ctx).Yi as *mut [uint8_t; 16] as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong,
    );
    OPENSSL_memset(
        &mut (*ctx).Xi as *mut [uint8_t; 16] as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong,
    );
    (*ctx).len.aad = 0 as libc::c_int as uint64_t;
    (*ctx).len.msg = 0 as libc::c_int as uint64_t;
    (*ctx).ares = 0 as libc::c_int as libc::c_uint;
    (*ctx).mres = 0 as libc::c_int as libc::c_uint;
    let mut ctr: uint32_t = 0;
    if len == 12 as libc::c_int as size_t {
        OPENSSL_memcpy(
            ((*ctx).Yi).as_mut_ptr() as *mut libc::c_void,
            iv as *const libc::c_void,
            12 as libc::c_int as size_t,
        );
        (*ctx).Yi[15 as libc::c_int as usize] = 1 as libc::c_int as uint8_t;
        ctr = 1 as libc::c_int as uint32_t;
    } else {
        let mut len0: uint64_t = len;
        while len >= 16 as libc::c_int as size_t {
            CRYPTO_xor16(
                ((*ctx).Yi).as_mut_ptr(),
                ((*ctx).Yi).as_mut_ptr() as *const uint8_t,
                iv,
            );
            gcm_gmult_nohw(
                ((*ctx).Yi).as_mut_ptr(),
                ((*ctx).gcm_key.Htable).as_mut_ptr() as *const u128_0,
            );
            iv = iv.offset(16 as libc::c_int as isize);
            len = len.wrapping_sub(16 as libc::c_int as size_t);
        }
        if len != 0 {
            let mut i: size_t = 0 as libc::c_int as size_t;
            while i < len {
                (*ctx)
                    .Yi[i
                    as usize] = ((*ctx).Yi[i as usize] as libc::c_int
                    ^ *iv.offset(i as isize) as libc::c_int) as uint8_t;
                i = i.wrapping_add(1);
                i;
            }
            gcm_gmult_nohw(
                ((*ctx).Yi).as_mut_ptr(),
                ((*ctx).gcm_key.Htable).as_mut_ptr() as *const u128_0,
            );
        }
        let mut len_block: [uint8_t; 16] = [0; 16];
        OPENSSL_memset(
            len_block.as_mut_ptr() as *mut libc::c_void,
            0 as libc::c_int,
            8 as libc::c_int as size_t,
        );
        CRYPTO_store_u64_be(
            len_block.as_mut_ptr().offset(8 as libc::c_int as isize)
                as *mut libc::c_void,
            len0 << 3 as libc::c_int,
        );
        CRYPTO_xor16(
            ((*ctx).Yi).as_mut_ptr(),
            ((*ctx).Yi).as_mut_ptr() as *const uint8_t,
            len_block.as_mut_ptr() as *const uint8_t,
        );
        gcm_gmult_nohw(
            ((*ctx).Yi).as_mut_ptr(),
            ((*ctx).gcm_key.Htable).as_mut_ptr() as *const u128_0,
        );
        ctr = CRYPTO_load_u32_be(
            ((*ctx).Yi).as_mut_ptr().offset(12 as libc::c_int as isize)
                as *const libc::c_void,
        );
    }
    (Some(((*ctx).gcm_key.block).expect("non-null function pointer")))
        .expect(
            "non-null function pointer",
        )(((*ctx).Yi).as_mut_ptr() as *const uint8_t, ((*ctx).EK0).as_mut_ptr(), key);
    ctr = ctr.wrapping_add(1);
    ctr;
    CRYPTO_store_u32_be(
        ((*ctx).Yi).as_mut_ptr().offset(12 as libc::c_int as isize) as *mut libc::c_void,
        ctr,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_gcm128_aad(
    mut ctx: *mut GCM128_CONTEXT,
    mut aad: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    if (*ctx).len.msg != 0 as libc::c_int as uint64_t {
        return 0 as libc::c_int;
    }
    let mut alen: uint64_t = ((*ctx).len.aad).wrapping_add(len);
    if alen > (1 as libc::c_ulong) << 61 as libc::c_int
        || ::core::mem::size_of::<size_t>() as libc::c_ulong
            == 8 as libc::c_int as libc::c_ulong && alen < len
    {
        return 0 as libc::c_int;
    }
    (*ctx).len.aad = alen;
    let mut n: libc::c_uint = (*ctx).ares;
    if n != 0 {
        while n != 0 && len != 0 {
            let fresh0 = aad;
            aad = aad.offset(1);
            (*ctx)
                .Xi[n
                as usize] = ((*ctx).Xi[n as usize] as libc::c_int
                ^ *fresh0 as libc::c_int) as uint8_t;
            len = len.wrapping_sub(1);
            len;
            n = n
                .wrapping_add(1 as libc::c_int as libc::c_uint)
                .wrapping_rem(16 as libc::c_int as libc::c_uint);
        }
        if n == 0 as libc::c_int as libc::c_uint {
            gcm_gmult_nohw(
                ((*ctx).Xi).as_mut_ptr(),
                ((*ctx).gcm_key.Htable).as_mut_ptr() as *const u128_0,
            );
        } else {
            (*ctx).ares = n;
            return 1 as libc::c_int;
        }
    }
    let mut len_blocks: size_t = len & kSizeTWithoutLower4Bits;
    if len_blocks != 0 as libc::c_int as size_t {
        gcm_ghash_nohw(
            ((*ctx).Xi).as_mut_ptr(),
            ((*ctx).gcm_key.Htable).as_mut_ptr() as *const u128_0,
            aad,
            len_blocks,
        );
        aad = aad.offset(len_blocks as isize);
        len = len.wrapping_sub(len_blocks);
    }
    if len != 0 as libc::c_int as size_t {
        if len > 16 as libc::c_int as size_t {
            abort();
        }
        n = len as libc::c_uint;
        let mut i: size_t = 0 as libc::c_int as size_t;
        while i < len {
            (*ctx)
                .Xi[i
                as usize] = ((*ctx).Xi[i as usize] as libc::c_int
                ^ *aad.offset(i as isize) as libc::c_int) as uint8_t;
            i = i.wrapping_add(1);
            i;
        }
    }
    (*ctx).ares = n;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_gcm128_encrypt(
    mut ctx: *mut GCM128_CONTEXT,
    mut key: *const AES_KEY,
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut block: block128_f = (*ctx).gcm_key.block;
    let mut mlen: uint64_t = ((*ctx).len.msg).wrapping_add(len);
    if mlen
        > ((1 as libc::c_ulong) << 36 as libc::c_int)
            .wrapping_sub(32 as libc::c_int as libc::c_ulong)
        || ::core::mem::size_of::<size_t>() as libc::c_ulong
            == 8 as libc::c_int as libc::c_ulong && mlen < len
    {
        return 0 as libc::c_int;
    }
    (*ctx).len.msg = mlen;
    if (*ctx).ares != 0 {
        gcm_gmult_nohw(
            ((*ctx).Xi).as_mut_ptr(),
            ((*ctx).gcm_key.Htable).as_mut_ptr() as *const u128_0,
        );
        (*ctx).ares = 0 as libc::c_int as libc::c_uint;
    }
    let mut n: libc::c_uint = (*ctx).mres;
    if n != 0 {
        while n != 0 && len != 0 {
            let fresh1 = in_0;
            in_0 = in_0.offset(1);
            let fresh2 = out;
            out = out.offset(1);
            *fresh2 = (*fresh1 as libc::c_int ^ (*ctx).EKi[n as usize] as libc::c_int)
                as uint8_t;
            (*ctx)
                .Xi[n
                as usize] = ((*ctx).Xi[n as usize] as libc::c_int
                ^ *fresh2 as libc::c_int) as uint8_t;
            len = len.wrapping_sub(1);
            len;
            n = n
                .wrapping_add(1 as libc::c_int as libc::c_uint)
                .wrapping_rem(16 as libc::c_int as libc::c_uint);
        }
        if n == 0 as libc::c_int as libc::c_uint {
            gcm_gmult_nohw(
                ((*ctx).Xi).as_mut_ptr(),
                ((*ctx).gcm_key.Htable).as_mut_ptr() as *const u128_0,
            );
        } else {
            (*ctx).mres = n;
            return 1 as libc::c_int;
        }
    }
    let mut ctr: uint32_t = CRYPTO_load_u32_be(
        ((*ctx).Yi).as_mut_ptr().offset(12 as libc::c_int as isize)
            as *const libc::c_void,
    );
    while len >= (3 as libc::c_int * 1024 as libc::c_int) as size_t {
        let mut j: size_t = (3 as libc::c_int * 1024 as libc::c_int) as size_t;
        while j != 0 {
            (Some(block.expect("non-null function pointer")))
                .expect(
                    "non-null function pointer",
                )(
                ((*ctx).Yi).as_mut_ptr() as *const uint8_t,
                ((*ctx).EKi).as_mut_ptr(),
                key,
            );
            ctr = ctr.wrapping_add(1);
            ctr;
            CRYPTO_store_u32_be(
                ((*ctx).Yi).as_mut_ptr().offset(12 as libc::c_int as isize)
                    as *mut libc::c_void,
                ctr,
            );
            CRYPTO_xor16(out, in_0, ((*ctx).EKi).as_mut_ptr() as *const uint8_t);
            out = out.offset(16 as libc::c_int as isize);
            in_0 = in_0.offset(16 as libc::c_int as isize);
            j = j.wrapping_sub(16 as libc::c_int as size_t);
        }
        gcm_ghash_nohw(
            ((*ctx).Xi).as_mut_ptr(),
            ((*ctx).gcm_key.Htable).as_mut_ptr() as *const u128_0,
            out.offset(-((3 as libc::c_int * 1024 as libc::c_int) as isize)),
            (3 as libc::c_int * 1024 as libc::c_int) as size_t,
        );
        len = len.wrapping_sub((3 as libc::c_int * 1024 as libc::c_int) as size_t);
    }
    let mut len_blocks: size_t = len & kSizeTWithoutLower4Bits;
    if len_blocks != 0 as libc::c_int as size_t {
        while len >= 16 as libc::c_int as size_t {
            (Some(block.expect("non-null function pointer")))
                .expect(
                    "non-null function pointer",
                )(
                ((*ctx).Yi).as_mut_ptr() as *const uint8_t,
                ((*ctx).EKi).as_mut_ptr(),
                key,
            );
            ctr = ctr.wrapping_add(1);
            ctr;
            CRYPTO_store_u32_be(
                ((*ctx).Yi).as_mut_ptr().offset(12 as libc::c_int as isize)
                    as *mut libc::c_void,
                ctr,
            );
            CRYPTO_xor16(out, in_0, ((*ctx).EKi).as_mut_ptr() as *const uint8_t);
            out = out.offset(16 as libc::c_int as isize);
            in_0 = in_0.offset(16 as libc::c_int as isize);
            len = len.wrapping_sub(16 as libc::c_int as size_t);
        }
        gcm_ghash_nohw(
            ((*ctx).Xi).as_mut_ptr(),
            ((*ctx).gcm_key.Htable).as_mut_ptr() as *const u128_0,
            out.offset(-(len_blocks as isize)),
            len_blocks,
        );
    }
    if len != 0 {
        (Some(block.expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )(
            ((*ctx).Yi).as_mut_ptr() as *const uint8_t,
            ((*ctx).EKi).as_mut_ptr(),
            key,
        );
        ctr = ctr.wrapping_add(1);
        ctr;
        CRYPTO_store_u32_be(
            ((*ctx).Yi).as_mut_ptr().offset(12 as libc::c_int as isize)
                as *mut libc::c_void,
            ctr,
        );
        loop {
            let fresh3 = len;
            len = len.wrapping_sub(1);
            if !(fresh3 != 0) {
                break;
            }
            let ref mut fresh4 = *out.offset(n as isize);
            *fresh4 = (*in_0.offset(n as isize) as libc::c_int
                ^ (*ctx).EKi[n as usize] as libc::c_int) as uint8_t;
            (*ctx)
                .Xi[n
                as usize] = ((*ctx).Xi[n as usize] as libc::c_int
                ^ *fresh4 as libc::c_int) as uint8_t;
            n = n.wrapping_add(1);
            n;
        }
    }
    (*ctx).mres = n;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_gcm128_decrypt(
    mut ctx: *mut GCM128_CONTEXT,
    mut key: *const AES_KEY,
    mut in_0: *const libc::c_uchar,
    mut out: *mut libc::c_uchar,
    mut len: size_t,
) -> libc::c_int {
    let mut block: block128_f = (*ctx).gcm_key.block;
    let mut mlen: uint64_t = ((*ctx).len.msg).wrapping_add(len);
    if mlen
        > ((1 as libc::c_ulong) << 36 as libc::c_int)
            .wrapping_sub(32 as libc::c_int as libc::c_ulong)
        || ::core::mem::size_of::<size_t>() as libc::c_ulong
            == 8 as libc::c_int as libc::c_ulong && mlen < len
    {
        return 0 as libc::c_int;
    }
    (*ctx).len.msg = mlen;
    if (*ctx).ares != 0 {
        gcm_gmult_nohw(
            ((*ctx).Xi).as_mut_ptr(),
            ((*ctx).gcm_key.Htable).as_mut_ptr() as *const u128_0,
        );
        (*ctx).ares = 0 as libc::c_int as libc::c_uint;
    }
    let mut n: libc::c_uint = (*ctx).mres;
    if n != 0 {
        while n != 0 && len != 0 {
            let fresh5 = in_0;
            in_0 = in_0.offset(1);
            let mut c: uint8_t = *fresh5;
            let fresh6 = out;
            out = out.offset(1);
            *fresh6 = (c as libc::c_int ^ (*ctx).EKi[n as usize] as libc::c_int)
                as libc::c_uchar;
            (*ctx)
                .Xi[n
                as usize] = ((*ctx).Xi[n as usize] as libc::c_int ^ c as libc::c_int)
                as uint8_t;
            len = len.wrapping_sub(1);
            len;
            n = n
                .wrapping_add(1 as libc::c_int as libc::c_uint)
                .wrapping_rem(16 as libc::c_int as libc::c_uint);
        }
        if n == 0 as libc::c_int as libc::c_uint {
            gcm_gmult_nohw(
                ((*ctx).Xi).as_mut_ptr(),
                ((*ctx).gcm_key.Htable).as_mut_ptr() as *const u128_0,
            );
        } else {
            (*ctx).mres = n;
            return 1 as libc::c_int;
        }
    }
    let mut ctr: uint32_t = CRYPTO_load_u32_be(
        ((*ctx).Yi).as_mut_ptr().offset(12 as libc::c_int as isize)
            as *const libc::c_void,
    );
    while len >= (3 as libc::c_int * 1024 as libc::c_int) as size_t {
        let mut j: size_t = (3 as libc::c_int * 1024 as libc::c_int) as size_t;
        gcm_ghash_nohw(
            ((*ctx).Xi).as_mut_ptr(),
            ((*ctx).gcm_key.Htable).as_mut_ptr() as *const u128_0,
            in_0,
            (3 as libc::c_int * 1024 as libc::c_int) as size_t,
        );
        while j != 0 {
            (Some(block.expect("non-null function pointer")))
                .expect(
                    "non-null function pointer",
                )(
                ((*ctx).Yi).as_mut_ptr() as *const uint8_t,
                ((*ctx).EKi).as_mut_ptr(),
                key,
            );
            ctr = ctr.wrapping_add(1);
            ctr;
            CRYPTO_store_u32_be(
                ((*ctx).Yi).as_mut_ptr().offset(12 as libc::c_int as isize)
                    as *mut libc::c_void,
                ctr,
            );
            CRYPTO_xor16(out, in_0, ((*ctx).EKi).as_mut_ptr() as *const uint8_t);
            out = out.offset(16 as libc::c_int as isize);
            in_0 = in_0.offset(16 as libc::c_int as isize);
            j = j.wrapping_sub(16 as libc::c_int as size_t);
        }
        len = len.wrapping_sub((3 as libc::c_int * 1024 as libc::c_int) as size_t);
    }
    let mut len_blocks: size_t = len & kSizeTWithoutLower4Bits;
    if len_blocks != 0 as libc::c_int as size_t {
        gcm_ghash_nohw(
            ((*ctx).Xi).as_mut_ptr(),
            ((*ctx).gcm_key.Htable).as_mut_ptr() as *const u128_0,
            in_0,
            len_blocks,
        );
        while len >= 16 as libc::c_int as size_t {
            (Some(block.expect("non-null function pointer")))
                .expect(
                    "non-null function pointer",
                )(
                ((*ctx).Yi).as_mut_ptr() as *const uint8_t,
                ((*ctx).EKi).as_mut_ptr(),
                key,
            );
            ctr = ctr.wrapping_add(1);
            ctr;
            CRYPTO_store_u32_be(
                ((*ctx).Yi).as_mut_ptr().offset(12 as libc::c_int as isize)
                    as *mut libc::c_void,
                ctr,
            );
            CRYPTO_xor16(out, in_0, ((*ctx).EKi).as_mut_ptr() as *const uint8_t);
            out = out.offset(16 as libc::c_int as isize);
            in_0 = in_0.offset(16 as libc::c_int as isize);
            len = len.wrapping_sub(16 as libc::c_int as size_t);
        }
    }
    if len != 0 {
        (Some(block.expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )(
            ((*ctx).Yi).as_mut_ptr() as *const uint8_t,
            ((*ctx).EKi).as_mut_ptr(),
            key,
        );
        ctr = ctr.wrapping_add(1);
        ctr;
        CRYPTO_store_u32_be(
            ((*ctx).Yi).as_mut_ptr().offset(12 as libc::c_int as isize)
                as *mut libc::c_void,
            ctr,
        );
        loop {
            let fresh7 = len;
            len = len.wrapping_sub(1);
            if !(fresh7 != 0) {
                break;
            }
            let mut c_0: uint8_t = *in_0.offset(n as isize);
            (*ctx)
                .Xi[n
                as usize] = ((*ctx).Xi[n as usize] as libc::c_int ^ c_0 as libc::c_int)
                as uint8_t;
            *out
                .offset(
                    n as isize,
                ) = (c_0 as libc::c_int ^ (*ctx).EKi[n as usize] as libc::c_int)
                as libc::c_uchar;
            n = n.wrapping_add(1);
            n;
        }
    }
    (*ctx).mres = n;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_gcm128_encrypt_ctr32(
    mut ctx: *mut GCM128_CONTEXT,
    mut key: *const AES_KEY,
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut len: size_t,
    mut stream: ctr128_f,
) -> libc::c_int {
    let mut mlen: uint64_t = ((*ctx).len.msg).wrapping_add(len);
    if mlen
        > ((1 as libc::c_ulong) << 36 as libc::c_int)
            .wrapping_sub(32 as libc::c_int as libc::c_ulong)
        || ::core::mem::size_of::<size_t>() as libc::c_ulong
            == 8 as libc::c_int as libc::c_ulong && mlen < len
    {
        return 0 as libc::c_int;
    }
    (*ctx).len.msg = mlen;
    if (*ctx).ares != 0 {
        gcm_gmult_nohw(
            ((*ctx).Xi).as_mut_ptr(),
            ((*ctx).gcm_key.Htable).as_mut_ptr() as *const u128_0,
        );
        (*ctx).ares = 0 as libc::c_int as libc::c_uint;
    }
    let mut n: libc::c_uint = (*ctx).mres;
    if n != 0 {
        while n != 0 && len != 0 {
            let fresh8 = in_0;
            in_0 = in_0.offset(1);
            let fresh9 = out;
            out = out.offset(1);
            *fresh9 = (*fresh8 as libc::c_int ^ (*ctx).EKi[n as usize] as libc::c_int)
                as uint8_t;
            (*ctx)
                .Xi[n
                as usize] = ((*ctx).Xi[n as usize] as libc::c_int
                ^ *fresh9 as libc::c_int) as uint8_t;
            len = len.wrapping_sub(1);
            len;
            n = n
                .wrapping_add(1 as libc::c_int as libc::c_uint)
                .wrapping_rem(16 as libc::c_int as libc::c_uint);
        }
        if n == 0 as libc::c_int as libc::c_uint {
            gcm_gmult_nohw(
                ((*ctx).Xi).as_mut_ptr(),
                ((*ctx).gcm_key.Htable).as_mut_ptr() as *const u128_0,
            );
        } else {
            (*ctx).mres = n;
            return 1 as libc::c_int;
        }
    }
    let mut ctr: uint32_t = CRYPTO_load_u32_be(
        ((*ctx).Yi).as_mut_ptr().offset(12 as libc::c_int as isize)
            as *const libc::c_void,
    );
    while len >= (3 as libc::c_int * 1024 as libc::c_int) as size_t {
        (Some(stream.expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )(
            in_0,
            out,
            (3 as libc::c_int * 1024 as libc::c_int / 16 as libc::c_int) as size_t,
            key,
            ((*ctx).Yi).as_mut_ptr() as *const uint8_t,
        );
        ctr = ctr
            .wrapping_add(
                (3 as libc::c_int * 1024 as libc::c_int / 16 as libc::c_int) as uint32_t,
            );
        CRYPTO_store_u32_be(
            ((*ctx).Yi).as_mut_ptr().offset(12 as libc::c_int as isize)
                as *mut libc::c_void,
            ctr,
        );
        gcm_ghash_nohw(
            ((*ctx).Xi).as_mut_ptr(),
            ((*ctx).gcm_key.Htable).as_mut_ptr() as *const u128_0,
            out,
            (3 as libc::c_int * 1024 as libc::c_int) as size_t,
        );
        out = out.offset((3 as libc::c_int * 1024 as libc::c_int) as isize);
        in_0 = in_0.offset((3 as libc::c_int * 1024 as libc::c_int) as isize);
        len = len.wrapping_sub((3 as libc::c_int * 1024 as libc::c_int) as size_t);
    }
    let mut len_blocks: size_t = len & kSizeTWithoutLower4Bits;
    if len_blocks != 0 as libc::c_int as size_t {
        let mut j: size_t = len_blocks / 16 as libc::c_int as size_t;
        (Some(stream.expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )(in_0, out, j, key, ((*ctx).Yi).as_mut_ptr() as *const uint8_t);
        ctr = (ctr as libc::c_uint).wrapping_add(j as libc::c_uint) as uint32_t
            as uint32_t;
        CRYPTO_store_u32_be(
            ((*ctx).Yi).as_mut_ptr().offset(12 as libc::c_int as isize)
                as *mut libc::c_void,
            ctr,
        );
        in_0 = in_0.offset(len_blocks as isize);
        len = len.wrapping_sub(len_blocks);
        gcm_ghash_nohw(
            ((*ctx).Xi).as_mut_ptr(),
            ((*ctx).gcm_key.Htable).as_mut_ptr() as *const u128_0,
            out,
            len_blocks,
        );
        out = out.offset(len_blocks as isize);
    }
    if len != 0 {
        (Some(((*ctx).gcm_key.block).expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )(
            ((*ctx).Yi).as_mut_ptr() as *const uint8_t,
            ((*ctx).EKi).as_mut_ptr(),
            key,
        );
        ctr = ctr.wrapping_add(1);
        ctr;
        CRYPTO_store_u32_be(
            ((*ctx).Yi).as_mut_ptr().offset(12 as libc::c_int as isize)
                as *mut libc::c_void,
            ctr,
        );
        if (n as size_t).wrapping_add(len) > 16 as libc::c_int as size_t {
            abort();
        }
        loop {
            let fresh10 = len;
            len = len.wrapping_sub(1);
            if !(fresh10 != 0) {
                break;
            }
            let ref mut fresh11 = *out.offset(n as isize);
            *fresh11 = (*in_0.offset(n as isize) as libc::c_int
                ^ (*ctx).EKi[n as usize] as libc::c_int) as uint8_t;
            (*ctx)
                .Xi[n
                as usize] = ((*ctx).Xi[n as usize] as libc::c_int
                ^ *fresh11 as libc::c_int) as uint8_t;
            n = n.wrapping_add(1);
            n;
        }
    }
    (*ctx).mres = n;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_gcm128_decrypt_ctr32(
    mut ctx: *mut GCM128_CONTEXT,
    mut key: *const AES_KEY,
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut len: size_t,
    mut stream: ctr128_f,
) -> libc::c_int {
    let mut mlen: uint64_t = ((*ctx).len.msg).wrapping_add(len);
    if mlen
        > ((1 as libc::c_ulong) << 36 as libc::c_int)
            .wrapping_sub(32 as libc::c_int as libc::c_ulong)
        || ::core::mem::size_of::<size_t>() as libc::c_ulong
            == 8 as libc::c_int as libc::c_ulong && mlen < len
    {
        return 0 as libc::c_int;
    }
    (*ctx).len.msg = mlen;
    if (*ctx).ares != 0 {
        gcm_gmult_nohw(
            ((*ctx).Xi).as_mut_ptr(),
            ((*ctx).gcm_key.Htable).as_mut_ptr() as *const u128_0,
        );
        (*ctx).ares = 0 as libc::c_int as libc::c_uint;
    }
    let mut n: libc::c_uint = (*ctx).mres;
    if n != 0 {
        while n != 0 && len != 0 {
            let fresh12 = in_0;
            in_0 = in_0.offset(1);
            let mut c: uint8_t = *fresh12;
            let fresh13 = out;
            out = out.offset(1);
            *fresh13 = (c as libc::c_int ^ (*ctx).EKi[n as usize] as libc::c_int)
                as uint8_t;
            (*ctx)
                .Xi[n
                as usize] = ((*ctx).Xi[n as usize] as libc::c_int ^ c as libc::c_int)
                as uint8_t;
            len = len.wrapping_sub(1);
            len;
            n = n
                .wrapping_add(1 as libc::c_int as libc::c_uint)
                .wrapping_rem(16 as libc::c_int as libc::c_uint);
        }
        if n == 0 as libc::c_int as libc::c_uint {
            gcm_gmult_nohw(
                ((*ctx).Xi).as_mut_ptr(),
                ((*ctx).gcm_key.Htable).as_mut_ptr() as *const u128_0,
            );
        } else {
            (*ctx).mres = n;
            return 1 as libc::c_int;
        }
    }
    let mut ctr: uint32_t = CRYPTO_load_u32_be(
        ((*ctx).Yi).as_mut_ptr().offset(12 as libc::c_int as isize)
            as *const libc::c_void,
    );
    while len >= (3 as libc::c_int * 1024 as libc::c_int) as size_t {
        gcm_ghash_nohw(
            ((*ctx).Xi).as_mut_ptr(),
            ((*ctx).gcm_key.Htable).as_mut_ptr() as *const u128_0,
            in_0,
            (3 as libc::c_int * 1024 as libc::c_int) as size_t,
        );
        (Some(stream.expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )(
            in_0,
            out,
            (3 as libc::c_int * 1024 as libc::c_int / 16 as libc::c_int) as size_t,
            key,
            ((*ctx).Yi).as_mut_ptr() as *const uint8_t,
        );
        ctr = ctr
            .wrapping_add(
                (3 as libc::c_int * 1024 as libc::c_int / 16 as libc::c_int) as uint32_t,
            );
        CRYPTO_store_u32_be(
            ((*ctx).Yi).as_mut_ptr().offset(12 as libc::c_int as isize)
                as *mut libc::c_void,
            ctr,
        );
        out = out.offset((3 as libc::c_int * 1024 as libc::c_int) as isize);
        in_0 = in_0.offset((3 as libc::c_int * 1024 as libc::c_int) as isize);
        len = len.wrapping_sub((3 as libc::c_int * 1024 as libc::c_int) as size_t);
    }
    let mut len_blocks: size_t = len & kSizeTWithoutLower4Bits;
    if len_blocks != 0 as libc::c_int as size_t {
        let mut j: size_t = len_blocks / 16 as libc::c_int as size_t;
        gcm_ghash_nohw(
            ((*ctx).Xi).as_mut_ptr(),
            ((*ctx).gcm_key.Htable).as_mut_ptr() as *const u128_0,
            in_0,
            len_blocks,
        );
        (Some(stream.expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )(in_0, out, j, key, ((*ctx).Yi).as_mut_ptr() as *const uint8_t);
        ctr = (ctr as libc::c_uint).wrapping_add(j as libc::c_uint) as uint32_t
            as uint32_t;
        CRYPTO_store_u32_be(
            ((*ctx).Yi).as_mut_ptr().offset(12 as libc::c_int as isize)
                as *mut libc::c_void,
            ctr,
        );
        out = out.offset(len_blocks as isize);
        in_0 = in_0.offset(len_blocks as isize);
        len = len.wrapping_sub(len_blocks);
    }
    if len != 0 {
        (Some(((*ctx).gcm_key.block).expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )(
            ((*ctx).Yi).as_mut_ptr() as *const uint8_t,
            ((*ctx).EKi).as_mut_ptr(),
            key,
        );
        ctr = ctr.wrapping_add(1);
        ctr;
        CRYPTO_store_u32_be(
            ((*ctx).Yi).as_mut_ptr().offset(12 as libc::c_int as isize)
                as *mut libc::c_void,
            ctr,
        );
        if (n as size_t).wrapping_add(len) > 16 as libc::c_int as size_t {
            abort();
        }
        loop {
            let fresh14 = len;
            len = len.wrapping_sub(1);
            if !(fresh14 != 0) {
                break;
            }
            let mut c_0: uint8_t = *in_0.offset(n as isize);
            (*ctx)
                .Xi[n
                as usize] = ((*ctx).Xi[n as usize] as libc::c_int ^ c_0 as libc::c_int)
                as uint8_t;
            *out
                .offset(
                    n as isize,
                ) = (c_0 as libc::c_int ^ (*ctx).EKi[n as usize] as libc::c_int)
                as uint8_t;
            n = n.wrapping_add(1);
            n;
        }
    }
    (*ctx).mres = n;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_gcm128_finish(
    mut ctx: *mut GCM128_CONTEXT,
    mut tag: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    if (*ctx).mres != 0 || (*ctx).ares != 0 {
        gcm_gmult_nohw(
            ((*ctx).Xi).as_mut_ptr(),
            ((*ctx).gcm_key.Htable).as_mut_ptr() as *const u128_0,
        );
    }
    let mut len_block: [uint8_t; 16] = [0; 16];
    CRYPTO_store_u64_be(
        len_block.as_mut_ptr() as *mut libc::c_void,
        (*ctx).len.aad << 3 as libc::c_int,
    );
    CRYPTO_store_u64_be(
        len_block.as_mut_ptr().offset(8 as libc::c_int as isize) as *mut libc::c_void,
        (*ctx).len.msg << 3 as libc::c_int,
    );
    CRYPTO_xor16(
        ((*ctx).Xi).as_mut_ptr(),
        ((*ctx).Xi).as_mut_ptr() as *const uint8_t,
        len_block.as_mut_ptr() as *const uint8_t,
    );
    gcm_gmult_nohw(
        ((*ctx).Xi).as_mut_ptr(),
        ((*ctx).gcm_key.Htable).as_mut_ptr() as *const u128_0,
    );
    CRYPTO_xor16(
        ((*ctx).Xi).as_mut_ptr(),
        ((*ctx).Xi).as_mut_ptr() as *const uint8_t,
        ((*ctx).EK0).as_mut_ptr() as *const uint8_t,
    );
    if !tag.is_null() && len <= ::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong
    {
        return (CRYPTO_memcmp(
            ((*ctx).Xi).as_mut_ptr() as *const libc::c_void,
            tag as *const libc::c_void,
            len,
        ) == 0 as libc::c_int) as libc::c_int
    } else {
        return 0 as libc::c_int
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_gcm128_tag(
    mut ctx: *mut GCM128_CONTEXT,
    mut tag: *mut libc::c_uchar,
    mut len: size_t,
) {
    CRYPTO_gcm128_finish(ctx, 0 as *const uint8_t, 0 as libc::c_int as size_t);
    OPENSSL_memcpy(
        tag as *mut libc::c_void,
        ((*ctx).Xi).as_mut_ptr() as *const libc::c_void,
        if len <= ::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong {
            len
        } else {
            ::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong
        },
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_gcm_clmul_enabled() -> libc::c_int {
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_gcm_avx512_enabled() -> libc::c_int {
    return 0 as libc::c_int;
}
