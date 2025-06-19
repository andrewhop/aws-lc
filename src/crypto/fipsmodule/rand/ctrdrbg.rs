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
    fn aes_ctr_set_key(
        aes_key: *mut AES_KEY,
        gcm_key: *mut GCM128_KEY,
        out_block: *mut block128_f,
        key: *const uint8_t,
        key_bytes: size_t,
    ) -> ctr128_f;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
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
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type uintptr_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ctr_drbg_state_st {
    pub ks: AES_KEY,
    pub block: block128_f,
    pub ctr: ctr128_f,
    pub counter: [uint8_t; 16],
    pub reseed_counter: uint64_t,
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
pub type AES_KEY = aes_key_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct aes_key_st {
    pub rd_key: [uint32_t; 60],
    pub rounds: libc::c_uint,
}
pub type block128_f = Option::<
    unsafe extern "C" fn(*const uint8_t, *mut uint8_t, *const AES_KEY) -> (),
>;
pub type CTR_DRBG_STATE = ctr_drbg_state_st;
pub type GCM128_KEY = gcm128_key_st;
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
pub type ghash_func = Option::<
    unsafe extern "C" fn(*mut uint8_t, *const u128_0, *const uint8_t, size_t) -> (),
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct u128_0 {
    pub hi: uint64_t,
    pub lo: uint64_t,
}
pub type gmult_func = Option::<unsafe extern "C" fn(*mut uint8_t, *const u128_0) -> ()>;
#[inline]
unsafe extern "C" fn buffers_alias(
    mut a: *const uint8_t,
    mut a_len: size_t,
    mut b: *const uint8_t,
    mut b_len: size_t,
) -> libc::c_int {
    let mut a_u: uintptr_t = a as uintptr_t;
    let mut b_u: uintptr_t = b as uintptr_t;
    return (a_u.wrapping_add(a_len) > b_u && b_u.wrapping_add(b_len) > a_u)
        as libc::c_int;
}
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
unsafe extern "C" fn FIPS_service_indicator_update_state() {}
static mut kMaxReseedCount: uint64_t = (1 as libc::c_ulong) << 48 as libc::c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CTR_DRBG_new(
    mut entropy: *const uint8_t,
    mut personalization: *const uint8_t,
    mut personalization_len: size_t,
) -> *mut CTR_DRBG_STATE {
    let mut drbg: *mut CTR_DRBG_STATE = OPENSSL_malloc(
        ::core::mem::size_of::<CTR_DRBG_STATE>() as libc::c_ulong,
    ) as *mut CTR_DRBG_STATE;
    if drbg.is_null()
        || CTR_DRBG_init(drbg, entropy, personalization, personalization_len) == 0
    {
        CTR_DRBG_free(drbg);
        return 0 as *mut CTR_DRBG_STATE;
    }
    return drbg;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CTR_DRBG_free(mut state: *mut CTR_DRBG_STATE) {
    OPENSSL_free(state as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CTR_DRBG_init(
    mut drbg: *mut CTR_DRBG_STATE,
    mut entropy: *const uint8_t,
    mut personalization: *const uint8_t,
    mut personalization_len: size_t,
) -> libc::c_int {
    if buffers_alias(
        entropy,
        48 as libc::c_int as size_t,
        personalization,
        personalization_len,
    ) != 0
    {
        return 0 as libc::c_int;
    }
    if personalization_len > 48 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    let mut seed_material: [uint8_t; 48] = [0; 48];
    OPENSSL_memcpy(
        seed_material.as_mut_ptr() as *mut libc::c_void,
        entropy as *const libc::c_void,
        48 as libc::c_int as size_t,
    );
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < personalization_len {
        seed_material[i
            as usize] = (seed_material[i as usize] as libc::c_int
            ^ *personalization.offset(i as isize) as libc::c_int) as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
    static mut kInitMask: [uint8_t; 48] = [
        0x53 as libc::c_int as uint8_t,
        0xf as libc::c_int as uint8_t,
        0x8a as libc::c_int as uint8_t,
        0xfb as libc::c_int as uint8_t,
        0xc7 as libc::c_int as uint8_t,
        0x45 as libc::c_int as uint8_t,
        0x36 as libc::c_int as uint8_t,
        0xb9 as libc::c_int as uint8_t,
        0xa9 as libc::c_int as uint8_t,
        0x63 as libc::c_int as uint8_t,
        0xb4 as libc::c_int as uint8_t,
        0xf1 as libc::c_int as uint8_t,
        0xc4 as libc::c_int as uint8_t,
        0xcb as libc::c_int as uint8_t,
        0x73 as libc::c_int as uint8_t,
        0x8b as libc::c_int as uint8_t,
        0xce as libc::c_int as uint8_t,
        0xa7 as libc::c_int as uint8_t,
        0x40 as libc::c_int as uint8_t,
        0x3d as libc::c_int as uint8_t,
        0x4d as libc::c_int as uint8_t,
        0x60 as libc::c_int as uint8_t,
        0x6b as libc::c_int as uint8_t,
        0x6e as libc::c_int as uint8_t,
        0x7 as libc::c_int as uint8_t,
        0x4e as libc::c_int as uint8_t,
        0xc5 as libc::c_int as uint8_t,
        0xd3 as libc::c_int as uint8_t,
        0xba as libc::c_int as uint8_t,
        0xf3 as libc::c_int as uint8_t,
        0x9d as libc::c_int as uint8_t,
        0x18 as libc::c_int as uint8_t,
        0x72 as libc::c_int as uint8_t,
        0x60 as libc::c_int as uint8_t,
        0x3 as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0x37 as libc::c_int as uint8_t,
        0xa6 as libc::c_int as uint8_t,
        0x2a as libc::c_int as uint8_t,
        0x74 as libc::c_int as uint8_t,
        0xd1 as libc::c_int as uint8_t,
        0xa2 as libc::c_int as uint8_t,
        0xf5 as libc::c_int as uint8_t,
        0x8e as libc::c_int as uint8_t,
        0x75 as libc::c_int as uint8_t,
        0x6 as libc::c_int as uint8_t,
        0x35 as libc::c_int as uint8_t,
        0x8e as libc::c_int as uint8_t,
    ];
    let mut i_0: size_t = 0 as libc::c_int as size_t;
    while i_0 < ::core::mem::size_of::<[uint8_t; 48]>() as libc::c_ulong {
        seed_material[i_0
            as usize] = (seed_material[i_0 as usize] as libc::c_int
            ^ kInitMask[i_0 as usize] as libc::c_int) as uint8_t;
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
    (*drbg)
        .ctr = aes_ctr_set_key(
        &mut (*drbg).ks,
        0 as *mut GCM128_KEY,
        &mut (*drbg).block,
        seed_material.as_mut_ptr(),
        32 as libc::c_int as size_t,
    );
    OPENSSL_memcpy(
        ((*drbg).counter).as_mut_ptr() as *mut libc::c_void,
        seed_material.as_mut_ptr().offset(32 as libc::c_int as isize)
            as *const libc::c_void,
        16 as libc::c_int as size_t,
    );
    (*drbg).reseed_counter = 1 as libc::c_int as uint64_t;
    return 1 as libc::c_int;
}
unsafe extern "C" fn ctr32_add(mut drbg: *mut CTR_DRBG_STATE, mut n: uint32_t) {
    let mut ctr: uint32_t = CRYPTO_load_u32_be(
        ((*drbg).counter).as_mut_ptr().offset(12 as libc::c_int as isize)
            as *const libc::c_void,
    );
    CRYPTO_store_u32_be(
        ((*drbg).counter).as_mut_ptr().offset(12 as libc::c_int as isize)
            as *mut libc::c_void,
        ctr.wrapping_add(n),
    );
}
unsafe extern "C" fn ctr_drbg_update(
    mut drbg: *mut CTR_DRBG_STATE,
    mut data: *const uint8_t,
    mut data_len: size_t,
) -> libc::c_int {
    if data_len > 48 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    let mut temp: [uint8_t; 48] = [0; 48];
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < 48 as libc::c_int as size_t {
        ctr32_add(drbg, 1 as libc::c_int as uint32_t);
        ((*drbg).block)
            .expect(
                "non-null function pointer",
            )(
            ((*drbg).counter).as_mut_ptr() as *const uint8_t,
            temp.as_mut_ptr().offset(i as isize),
            &mut (*drbg).ks,
        );
        i = i.wrapping_add(16 as libc::c_int as size_t);
    }
    let mut i_0: size_t = 0 as libc::c_int as size_t;
    while i_0 < data_len {
        temp[i_0
            as usize] = (temp[i_0 as usize] as libc::c_int
            ^ *data.offset(i_0 as isize) as libc::c_int) as uint8_t;
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
    (*drbg)
        .ctr = aes_ctr_set_key(
        &mut (*drbg).ks,
        0 as *mut GCM128_KEY,
        &mut (*drbg).block,
        temp.as_mut_ptr(),
        32 as libc::c_int as size_t,
    );
    OPENSSL_memcpy(
        ((*drbg).counter).as_mut_ptr() as *mut libc::c_void,
        temp.as_mut_ptr().offset(32 as libc::c_int as isize) as *const libc::c_void,
        16 as libc::c_int as size_t,
    );
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CTR_DRBG_reseed(
    mut drbg: *mut CTR_DRBG_STATE,
    mut entropy: *const uint8_t,
    mut additional_data: *const uint8_t,
    mut additional_data_len: size_t,
) -> libc::c_int {
    if buffers_alias(
        entropy,
        48 as libc::c_int as size_t,
        additional_data,
        additional_data_len,
    ) != 0
    {
        return 0 as libc::c_int;
    }
    let mut entropy_copy: [uint8_t; 48] = [0; 48];
    if additional_data_len > 0 as libc::c_int as size_t {
        if additional_data_len > 48 as libc::c_int as size_t {
            return 0 as libc::c_int;
        }
        OPENSSL_memcpy(
            entropy_copy.as_mut_ptr() as *mut libc::c_void,
            entropy as *const libc::c_void,
            48 as libc::c_int as size_t,
        );
        let mut i: size_t = 0 as libc::c_int as size_t;
        while i < additional_data_len {
            entropy_copy[i
                as usize] = (entropy_copy[i as usize] as libc::c_int
                ^ *additional_data.offset(i as isize) as libc::c_int) as uint8_t;
            i = i.wrapping_add(1);
            i;
        }
        entropy = entropy_copy.as_mut_ptr() as *const uint8_t;
    }
    if ctr_drbg_update(drbg, entropy, 48 as libc::c_int as size_t) == 0 {
        return 0 as libc::c_int;
    }
    (*drbg).reseed_counter = 1 as libc::c_int as uint64_t;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CTR_DRBG_generate(
    mut drbg: *mut CTR_DRBG_STATE,
    mut out: *mut uint8_t,
    mut out_len: size_t,
    mut additional_data: *const uint8_t,
    mut additional_data_len: size_t,
) -> libc::c_int {
    if out_len > 65536 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    if (*drbg).reseed_counter > kMaxReseedCount {
        return 0 as libc::c_int;
    }
    if additional_data_len != 0 as libc::c_int as size_t
        && ctr_drbg_update(drbg, additional_data, additional_data_len) == 0
    {
        return 0 as libc::c_int;
    }
    static mut kChunkSize: size_t = (8 as libc::c_int * 1024 as libc::c_int) as size_t;
    while out_len >= 16 as libc::c_int as size_t {
        let mut todo: size_t = kChunkSize;
        if todo > out_len {
            todo = out_len;
        }
        todo &= !(16 as libc::c_int - 1 as libc::c_int) as size_t;
        let num_blocks: size_t = todo / 16 as libc::c_int as size_t;
        if ((*drbg).ctr).is_some() {
            OPENSSL_memset(out as *mut libc::c_void, 0 as libc::c_int, todo);
            ctr32_add(drbg, 1 as libc::c_int as uint32_t);
            ((*drbg).ctr)
                .expect(
                    "non-null function pointer",
                )(
                out,
                out,
                num_blocks,
                &mut (*drbg).ks,
                ((*drbg).counter).as_mut_ptr() as *const uint8_t,
            );
            ctr32_add(
                drbg,
                num_blocks.wrapping_sub(1 as libc::c_int as size_t) as uint32_t,
            );
        } else {
            let mut i: size_t = 0 as libc::c_int as size_t;
            while i < todo {
                ctr32_add(drbg, 1 as libc::c_int as uint32_t);
                ((*drbg).block)
                    .expect(
                        "non-null function pointer",
                    )(
                    ((*drbg).counter).as_mut_ptr() as *const uint8_t,
                    out.offset(i as isize),
                    &mut (*drbg).ks,
                );
                i = i.wrapping_add(16 as libc::c_int as size_t);
            }
        }
        out = out.offset(todo as isize);
        out_len = out_len.wrapping_sub(todo);
    }
    if out_len > 0 as libc::c_int as size_t {
        let mut block: [uint8_t; 16] = [0; 16];
        ctr32_add(drbg, 1 as libc::c_int as uint32_t);
        ((*drbg).block)
            .expect(
                "non-null function pointer",
            )(
            ((*drbg).counter).as_mut_ptr() as *const uint8_t,
            block.as_mut_ptr(),
            &mut (*drbg).ks,
        );
        OPENSSL_memcpy(
            out as *mut libc::c_void,
            block.as_mut_ptr() as *const libc::c_void,
            out_len,
        );
    }
    if ctr_drbg_update(drbg, additional_data, additional_data_len) == 0 {
        return 0 as libc::c_int;
    }
    (*drbg).reseed_counter = ((*drbg).reseed_counter).wrapping_add(1);
    (*drbg).reseed_counter;
    FIPS_service_indicator_update_state();
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CTR_DRBG_clear(mut drbg: *mut CTR_DRBG_STATE) {
    OPENSSL_cleanse(
        drbg as *mut libc::c_void,
        ::core::mem::size_of::<CTR_DRBG_STATE>() as libc::c_ulong,
    );
}
