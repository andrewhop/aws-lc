#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
extern "C" {
    fn aes_ctr_set_key(
        aes_key: *mut AES_KEY,
        gcm_key: *mut GCM128_KEY,
        out_block: *mut block128_f,
        key: *const uint8_t,
        key_bytes: size_t,
    ) -> ctr128_f;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn CRYPTO_memcmp(
        a: *const libc::c_void,
        b: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
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
    fn CRYPTO_POLYVAL_init(ctx: *mut polyval_ctx, key: *const uint8_t);
    fn CRYPTO_POLYVAL_update_blocks(
        ctx: *mut polyval_ctx,
        in_0: *const uint8_t,
        in_len: size_t,
    );
    fn CRYPTO_POLYVAL_finish(ctx: *const polyval_ctx, out: *mut uint8_t);
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cbb_st {
    pub child: *mut CBB,
    pub is_child: libc::c_char,
    pub u: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub base: cbb_buffer_st,
    pub child: cbb_child_st,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct cbb_child_st {
    pub base: *mut cbb_buffer_st,
    pub offset: size_t,
    pub pending_len_len: uint8_t,
    #[bitfield(name = "pending_is_asn1", ty = "libc::c_uint", bits = "0..=0")]
    pub pending_is_asn1: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 6],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct cbb_buffer_st {
    pub buf: *mut uint8_t,
    pub len: size_t,
    pub cap: size_t,
    #[bitfield(name = "can_resize", ty = "libc::c_uint", bits = "0..=0")]
    #[bitfield(name = "error", ty = "libc::c_uint", bits = "1..=1")]
    pub can_resize_error: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
pub type CBB = cbb_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cbs_st {
    pub data: *const uint8_t,
    pub len: size_t,
}
pub type CBS = cbs_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_aead_st {
    pub key_len: uint8_t,
    pub nonce_len: uint8_t,
    pub overhead: uint8_t,
    pub max_tag_len: uint8_t,
    pub aead_id: uint16_t,
    pub seal_scatter_supports_extra_in: libc::c_int,
    pub init: Option::<
        unsafe extern "C" fn(
            *mut EVP_AEAD_CTX,
            *const uint8_t,
            size_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub init_with_direction: Option::<
        unsafe extern "C" fn(
            *mut EVP_AEAD_CTX,
            *const uint8_t,
            size_t,
            size_t,
            evp_aead_direction_t,
        ) -> libc::c_int,
    >,
    pub cleanup: Option::<unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> ()>,
    pub open: Option::<
        unsafe extern "C" fn(
            *const EVP_AEAD_CTX,
            *mut uint8_t,
            *mut size_t,
            size_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub seal_scatter: Option::<
        unsafe extern "C" fn(
            *const EVP_AEAD_CTX,
            *mut uint8_t,
            *mut uint8_t,
            *mut size_t,
            size_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub open_gather: Option::<
        unsafe extern "C" fn(
            *const EVP_AEAD_CTX,
            *mut uint8_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub get_iv: Option::<
        unsafe extern "C" fn(
            *const EVP_AEAD_CTX,
            *mut *const uint8_t,
            *mut size_t,
        ) -> libc::c_int,
    >,
    pub tag_len: Option::<
        unsafe extern "C" fn(*const EVP_AEAD_CTX, size_t, size_t) -> size_t,
    >,
    pub serialize_state: Option::<
        unsafe extern "C" fn(*const EVP_AEAD_CTX, *mut CBB) -> libc::c_int,
    >,
    pub deserialize_state: Option::<
        unsafe extern "C" fn(*const EVP_AEAD_CTX, *mut CBS) -> libc::c_int,
    >,
}
pub type EVP_AEAD_CTX = evp_aead_ctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_aead_ctx_st {
    pub aead: *const EVP_AEAD,
    pub state: evp_aead_ctx_st_state,
    pub state_offset: uint8_t,
    pub tag_len: uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union evp_aead_ctx_st_state {
    pub opaque: [uint8_t; 564],
    pub alignment: uint64_t,
    pub ptr: *mut libc::c_void,
}
pub type EVP_AEAD = evp_aead_st;
pub type evp_aead_direction_t = libc::c_uint;
pub const evp_aead_seal: evp_aead_direction_t = 1;
pub const evp_aead_open: evp_aead_direction_t = 0;
pub type AES_KEY = aes_key_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct aes_key_st {
    pub rd_key: [uint32_t; 60],
    pub rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub align: libc::c_double,
    pub ks: AES_KEY,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct gcm_siv_record_keys {
    pub auth_key: [uint8_t; 16],
    pub enc_key: C2RustUnnamed_0,
    pub enc_block: block128_f,
}
pub type block128_f = Option::<
    unsafe extern "C" fn(*const uint8_t, *mut uint8_t, *const AES_KEY) -> (),
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct polyval_ctx {
    pub S: [uint8_t; 16],
    pub Htable: [u128_0; 16],
    pub gmult: gmult_func,
    pub ghash: ghash_func,
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
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct aead_aes_gcm_siv_ctx {
    pub ks: C2RustUnnamed_1,
    pub kgk_block: block128_f,
    #[bitfield(name = "is_256", ty = "libc::c_uint", bits = "0..=0")]
    pub is_256: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_1 {
    pub align: libc::c_double,
    pub ks: AES_KEY,
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
unsafe extern "C" fn CRYPTO_store_u64_le(mut out: *mut libc::c_void, mut v: uint64_t) {
    OPENSSL_memcpy(
        out,
        &mut v as *mut uint64_t as *const libc::c_void,
        ::core::mem::size_of::<uint64_t>() as libc::c_ulong,
    );
}
unsafe extern "C" fn aead_aes_gcm_siv_init(
    mut ctx: *mut EVP_AEAD_CTX,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut tag_len: size_t,
) -> libc::c_int {
    let key_bits: size_t = key_len * 8 as libc::c_int as size_t;
    if key_bits != 128 as libc::c_int as size_t
        && key_bits != 256 as libc::c_int as size_t
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_aesgcmsiv.c\0"
                as *const u8 as *const libc::c_char,
            575 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if tag_len == 0 as libc::c_int as size_t {
        tag_len = 16 as libc::c_int as size_t;
    }
    if tag_len != 16 as libc::c_int as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            116 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_aesgcmsiv.c\0"
                as *const u8 as *const libc::c_char,
            583 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut gcm_siv_ctx: *mut aead_aes_gcm_siv_ctx = &mut (*ctx).state
        as *mut evp_aead_ctx_st_state as *mut aead_aes_gcm_siv_ctx;
    OPENSSL_memset(
        gcm_siv_ctx as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<aead_aes_gcm_siv_ctx>() as libc::c_ulong,
    );
    aes_ctr_set_key(
        &mut (*gcm_siv_ctx).ks.ks,
        0 as *mut GCM128_KEY,
        &mut (*gcm_siv_ctx).kgk_block,
        key,
        key_len,
    );
    (*gcm_siv_ctx)
        .set_is_256(
            (key_len == 32 as libc::c_int as size_t) as libc::c_int as libc::c_uint,
        );
    (*ctx).tag_len = tag_len as uint8_t;
    return 1 as libc::c_int;
}
unsafe extern "C" fn aead_aes_gcm_siv_cleanup(mut ctx: *mut EVP_AEAD_CTX) {}
unsafe extern "C" fn gcm_siv_crypt(
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut initial_counter: *const uint8_t,
    mut enc_block: block128_f,
    mut key: *const AES_KEY,
) {
    let mut counter: [uint8_t; 16] = [0; 16];
    OPENSSL_memcpy(
        counter.as_mut_ptr() as *mut libc::c_void,
        initial_counter as *const libc::c_void,
        16 as libc::c_int as size_t,
    );
    counter[15 as libc::c_int
        as usize] = (counter[15 as libc::c_int as usize] as libc::c_int
        | 0x80 as libc::c_int) as uint8_t;
    let mut done: size_t = 0 as libc::c_int as size_t;
    while done < in_len {
        let mut keystream: [uint8_t; 16] = [0; 16];
        enc_block
            .expect(
                "non-null function pointer",
            )(counter.as_mut_ptr() as *const uint8_t, keystream.as_mut_ptr(), key);
        CRYPTO_store_u32_le(
            counter.as_mut_ptr() as *mut libc::c_void,
            (CRYPTO_load_u32_le(counter.as_mut_ptr() as *const libc::c_void))
                .wrapping_add(1 as libc::c_int as uint32_t),
        );
        let mut todo: size_t = 16 as libc::c_int as size_t;
        if in_len.wrapping_sub(done) < todo {
            todo = in_len.wrapping_sub(done);
        }
        let mut i: size_t = 0 as libc::c_int as size_t;
        while i < todo {
            *out
                .offset(
                    done.wrapping_add(i) as isize,
                ) = (keystream[i as usize] as libc::c_int
                ^ *in_0.offset(done.wrapping_add(i) as isize) as libc::c_int) as uint8_t;
            i = i.wrapping_add(1);
            i;
        }
        done = done.wrapping_add(todo);
    }
}
unsafe extern "C" fn gcm_siv_polyval(
    mut out_tag: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut ad: *const uint8_t,
    mut ad_len: size_t,
    mut auth_key: *const uint8_t,
    mut nonce: *const uint8_t,
) {
    let mut polyval_ctx: polyval_ctx = polyval_ctx {
        S: [0; 16],
        Htable: [u128_0 { hi: 0, lo: 0 }; 16],
        gmult: None,
        ghash: None,
    };
    CRYPTO_POLYVAL_init(&mut polyval_ctx, auth_key);
    CRYPTO_POLYVAL_update_blocks(
        &mut polyval_ctx,
        ad,
        ad_len & !(15 as libc::c_int) as size_t,
    );
    let mut scratch: [uint8_t; 16] = [0; 16];
    if ad_len & 15 as libc::c_int as size_t != 0 {
        OPENSSL_memset(
            scratch.as_mut_ptr() as *mut libc::c_void,
            0 as libc::c_int,
            ::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong,
        );
        OPENSSL_memcpy(
            scratch.as_mut_ptr() as *mut libc::c_void,
            &*ad.offset((ad_len & !(15 as libc::c_int) as size_t) as isize)
                as *const uint8_t as *const libc::c_void,
            ad_len & 15 as libc::c_int as size_t,
        );
        CRYPTO_POLYVAL_update_blocks(
            &mut polyval_ctx,
            scratch.as_mut_ptr(),
            ::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong,
        );
    }
    CRYPTO_POLYVAL_update_blocks(
        &mut polyval_ctx,
        in_0,
        in_len & !(15 as libc::c_int) as size_t,
    );
    if in_len & 15 as libc::c_int as size_t != 0 {
        OPENSSL_memset(
            scratch.as_mut_ptr() as *mut libc::c_void,
            0 as libc::c_int,
            ::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong,
        );
        OPENSSL_memcpy(
            scratch.as_mut_ptr() as *mut libc::c_void,
            &*in_0.offset((in_len & !(15 as libc::c_int) as size_t) as isize)
                as *const uint8_t as *const libc::c_void,
            in_len & 15 as libc::c_int as size_t,
        );
        CRYPTO_POLYVAL_update_blocks(
            &mut polyval_ctx,
            scratch.as_mut_ptr(),
            ::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong,
        );
    }
    let mut length_block: [uint8_t; 16] = [0; 16];
    CRYPTO_store_u64_le(
        length_block.as_mut_ptr() as *mut libc::c_void,
        ad_len * 8 as libc::c_int as uint64_t,
    );
    CRYPTO_store_u64_le(
        length_block.as_mut_ptr().offset(8 as libc::c_int as isize) as *mut libc::c_void,
        in_len * 8 as libc::c_int as uint64_t,
    );
    CRYPTO_POLYVAL_update_blocks(
        &mut polyval_ctx,
        length_block.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong,
    );
    CRYPTO_POLYVAL_finish(&mut polyval_ctx, out_tag);
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < 12 as libc::c_int as size_t {
        let ref mut fresh0 = *out_tag.offset(i as isize);
        *fresh0 = (*fresh0 as libc::c_int ^ *nonce.offset(i as isize) as libc::c_int)
            as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
    let ref mut fresh1 = *out_tag.offset(15 as libc::c_int as isize);
    *fresh1 = (*fresh1 as libc::c_int & 0x7f as libc::c_int) as uint8_t;
}
unsafe extern "C" fn gcm_siv_keys(
    mut gcm_siv_ctx: *const aead_aes_gcm_siv_ctx,
    mut out_keys: *mut gcm_siv_record_keys,
    mut nonce: *const uint8_t,
) {
    let key: *const AES_KEY = &(*gcm_siv_ctx).ks.ks;
    let mut key_material: [uint8_t; 48] = [0; 48];
    let blocks_needed: size_t = (if (*gcm_siv_ctx).is_256() as libc::c_int != 0 {
        6 as libc::c_int
    } else {
        4 as libc::c_int
    }) as size_t;
    let mut counter: [uint8_t; 16] = [0; 16];
    OPENSSL_memset(
        counter.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        (16 as libc::c_int - 12 as libc::c_int) as size_t,
    );
    OPENSSL_memcpy(
        counter
            .as_mut_ptr()
            .offset(16 as libc::c_int as isize)
            .offset(-(12 as libc::c_int as isize)) as *mut libc::c_void,
        nonce as *const libc::c_void,
        12 as libc::c_int as size_t,
    );
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < blocks_needed {
        counter[0 as libc::c_int as usize] = i as uint8_t;
        let mut ciphertext: [uint8_t; 16] = [0; 16];
        ((*gcm_siv_ctx).kgk_block)
            .expect(
                "non-null function pointer",
            )(counter.as_mut_ptr() as *const uint8_t, ciphertext.as_mut_ptr(), key);
        OPENSSL_memcpy(
            &mut *key_material
                .as_mut_ptr()
                .offset((i * 8 as libc::c_int as size_t) as isize) as *mut uint8_t
                as *mut libc::c_void,
            ciphertext.as_mut_ptr() as *const libc::c_void,
            8 as libc::c_int as size_t,
        );
        i = i.wrapping_add(1);
        i;
    }
    OPENSSL_memcpy(
        ((*out_keys).auth_key).as_mut_ptr() as *mut libc::c_void,
        key_material.as_mut_ptr() as *const libc::c_void,
        16 as libc::c_int as size_t,
    );
    aes_ctr_set_key(
        &mut (*out_keys).enc_key.ks,
        0 as *mut GCM128_KEY,
        &mut (*out_keys).enc_block,
        key_material.as_mut_ptr().offset(16 as libc::c_int as isize),
        (if (*gcm_siv_ctx).is_256() as libc::c_int != 0 {
            32 as libc::c_int
        } else {
            16 as libc::c_int
        }) as size_t,
    );
}
unsafe extern "C" fn aead_aes_gcm_siv_seal_scatter(
    mut ctx: *const EVP_AEAD_CTX,
    mut out: *mut uint8_t,
    mut out_tag: *mut uint8_t,
    mut out_tag_len: *mut size_t,
    mut max_out_tag_len: size_t,
    mut nonce: *const uint8_t,
    mut nonce_len: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut extra_in: *const uint8_t,
    mut extra_in_len: size_t,
    mut ad: *const uint8_t,
    mut ad_len: size_t,
) -> libc::c_int {
    let mut gcm_siv_ctx: *const aead_aes_gcm_siv_ctx = &(*ctx).state
        as *const evp_aead_ctx_st_state as *mut aead_aes_gcm_siv_ctx;
    let in_len_64: uint64_t = in_len;
    let ad_len_64: uint64_t = ad_len;
    if in_len.wrapping_add(16 as libc::c_int as size_t) < in_len
        || in_len_64 > (1 as libc::c_ulong) << 36 as libc::c_int
        || ad_len_64 >= (1 as libc::c_ulong) << 61 as libc::c_int
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            117 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_aesgcmsiv.c\0"
                as *const u8 as *const libc::c_char,
            728 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if max_out_tag_len < 16 as libc::c_int as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            103 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_aesgcmsiv.c\0"
                as *const u8 as *const libc::c_char,
            733 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if nonce_len != 12 as libc::c_int as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            121 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_aesgcmsiv.c\0"
                as *const u8 as *const libc::c_char,
            738 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut keys: gcm_siv_record_keys = gcm_siv_record_keys {
        auth_key: [0; 16],
        enc_key: C2RustUnnamed_0 { align: 0. },
        enc_block: None,
    };
    gcm_siv_keys(gcm_siv_ctx, &mut keys, nonce);
    let mut tag: [uint8_t; 16] = [0; 16];
    gcm_siv_polyval(
        tag.as_mut_ptr(),
        in_0,
        in_len,
        ad,
        ad_len,
        (keys.auth_key).as_mut_ptr() as *const uint8_t,
        nonce,
    );
    (keys.enc_block)
        .expect(
            "non-null function pointer",
        )(tag.as_mut_ptr() as *const uint8_t, tag.as_mut_ptr(), &mut keys.enc_key.ks);
    gcm_siv_crypt(
        out,
        in_0,
        in_len,
        tag.as_mut_ptr() as *const uint8_t,
        keys.enc_block,
        &mut keys.enc_key.ks,
    );
    OPENSSL_memcpy(
        out_tag as *mut libc::c_void,
        tag.as_mut_ptr() as *const libc::c_void,
        16 as libc::c_int as size_t,
    );
    *out_tag_len = 16 as libc::c_int as size_t;
    return 1 as libc::c_int;
}
unsafe extern "C" fn aead_aes_gcm_siv_open_gather(
    mut ctx: *const EVP_AEAD_CTX,
    mut out: *mut uint8_t,
    mut nonce: *const uint8_t,
    mut nonce_len: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut in_tag: *const uint8_t,
    mut in_tag_len: size_t,
    mut ad: *const uint8_t,
    mut ad_len: size_t,
) -> libc::c_int {
    let ad_len_64: uint64_t = ad_len;
    if ad_len_64 >= (1 as libc::c_ulong) << 61 as libc::c_int {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            117 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_aesgcmsiv.c\0"
                as *const u8 as *const libc::c_char,
            765 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let in_len_64: uint64_t = in_len;
    if in_tag_len != 16 as libc::c_int as size_t
        || in_len_64
            > ((1 as libc::c_ulong) << 36 as libc::c_int)
                .wrapping_add(16 as libc::c_int as libc::c_ulong)
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_aesgcmsiv.c\0"
                as *const u8 as *const libc::c_char,
            772 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if nonce_len != 12 as libc::c_int as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            121 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_aesgcmsiv.c\0"
                as *const u8 as *const libc::c_char,
            777 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut gcm_siv_ctx: *const aead_aes_gcm_siv_ctx = &(*ctx).state
        as *const evp_aead_ctx_st_state as *mut aead_aes_gcm_siv_ctx;
    let mut keys: gcm_siv_record_keys = gcm_siv_record_keys {
        auth_key: [0; 16],
        enc_key: C2RustUnnamed_0 { align: 0. },
        enc_block: None,
    };
    gcm_siv_keys(gcm_siv_ctx, &mut keys, nonce);
    gcm_siv_crypt(out, in_0, in_len, in_tag, keys.enc_block, &mut keys.enc_key.ks);
    let mut expected_tag: [uint8_t; 16] = [0; 16];
    gcm_siv_polyval(
        expected_tag.as_mut_ptr(),
        out,
        in_len,
        ad,
        ad_len,
        (keys.auth_key).as_mut_ptr() as *const uint8_t,
        nonce,
    );
    (keys.enc_block)
        .expect(
            "non-null function pointer",
        )(
        expected_tag.as_mut_ptr() as *const uint8_t,
        expected_tag.as_mut_ptr(),
        &mut keys.enc_key.ks,
    );
    if CRYPTO_memcmp(
        expected_tag.as_mut_ptr() as *const libc::c_void,
        in_tag as *const libc::c_void,
        ::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong,
    ) != 0 as libc::c_int
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_aesgcmsiv.c\0"
                as *const u8 as *const libc::c_char,
            794 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
static mut aead_aes_128_gcm_siv: EVP_AEAD = unsafe {
    {
        let mut init = evp_aead_st {
            key_len: 16 as libc::c_int as uint8_t,
            nonce_len: 12 as libc::c_int as uint8_t,
            overhead: 16 as libc::c_int as uint8_t,
            max_tag_len: 16 as libc::c_int as uint8_t,
            aead_id: 3 as libc::c_int as uint16_t,
            seal_scatter_supports_extra_in: 0 as libc::c_int,
            init: Some(
                aead_aes_gcm_siv_init
                    as unsafe extern "C" fn(
                        *mut EVP_AEAD_CTX,
                        *const uint8_t,
                        size_t,
                        size_t,
                    ) -> libc::c_int,
            ),
            init_with_direction: None,
            cleanup: Some(
                aead_aes_gcm_siv_cleanup as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
            ),
            open: None,
            seal_scatter: Some(
                aead_aes_gcm_siv_seal_scatter
                    as unsafe extern "C" fn(
                        *const EVP_AEAD_CTX,
                        *mut uint8_t,
                        *mut uint8_t,
                        *mut size_t,
                        size_t,
                        *const uint8_t,
                        size_t,
                        *const uint8_t,
                        size_t,
                        *const uint8_t,
                        size_t,
                        *const uint8_t,
                        size_t,
                    ) -> libc::c_int,
            ),
            open_gather: Some(
                aead_aes_gcm_siv_open_gather
                    as unsafe extern "C" fn(
                        *const EVP_AEAD_CTX,
                        *mut uint8_t,
                        *const uint8_t,
                        size_t,
                        *const uint8_t,
                        size_t,
                        *const uint8_t,
                        size_t,
                        *const uint8_t,
                        size_t,
                    ) -> libc::c_int,
            ),
            get_iv: None,
            tag_len: None,
            serialize_state: None,
            deserialize_state: None,
        };
        init
    }
};
static mut aead_aes_256_gcm_siv: EVP_AEAD = unsafe {
    {
        let mut init = evp_aead_st {
            key_len: 32 as libc::c_int as uint8_t,
            nonce_len: 12 as libc::c_int as uint8_t,
            overhead: 16 as libc::c_int as uint8_t,
            max_tag_len: 16 as libc::c_int as uint8_t,
            aead_id: 4 as libc::c_int as uint16_t,
            seal_scatter_supports_extra_in: 0 as libc::c_int,
            init: Some(
                aead_aes_gcm_siv_init
                    as unsafe extern "C" fn(
                        *mut EVP_AEAD_CTX,
                        *const uint8_t,
                        size_t,
                        size_t,
                    ) -> libc::c_int,
            ),
            init_with_direction: None,
            cleanup: Some(
                aead_aes_gcm_siv_cleanup as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
            ),
            open: None,
            seal_scatter: Some(
                aead_aes_gcm_siv_seal_scatter
                    as unsafe extern "C" fn(
                        *const EVP_AEAD_CTX,
                        *mut uint8_t,
                        *mut uint8_t,
                        *mut size_t,
                        size_t,
                        *const uint8_t,
                        size_t,
                        *const uint8_t,
                        size_t,
                        *const uint8_t,
                        size_t,
                        *const uint8_t,
                        size_t,
                    ) -> libc::c_int,
            ),
            open_gather: Some(
                aead_aes_gcm_siv_open_gather
                    as unsafe extern "C" fn(
                        *const EVP_AEAD_CTX,
                        *mut uint8_t,
                        *const uint8_t,
                        size_t,
                        *const uint8_t,
                        size_t,
                        *const uint8_t,
                        size_t,
                        *const uint8_t,
                        size_t,
                    ) -> libc::c_int,
            ),
            get_iv: None,
            tag_len: None,
            serialize_state: None,
            deserialize_state: None,
        };
        init
    }
};
#[no_mangle]
pub unsafe extern "C" fn EVP_aead_aes_128_gcm_siv() -> *const EVP_AEAD {
    return &aead_aes_128_gcm_siv;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_aead_aes_256_gcm_siv() -> *const EVP_AEAD {
    return &aead_aes_256_gcm_siv;
}
#[no_mangle]
pub unsafe extern "C" fn x86_64_assembly_implementation_FOR_TESTING() -> libc::c_int {
    return 0 as libc::c_int;
}
