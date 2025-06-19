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
    fn SHA256_Init(sha: *mut SHA256_CTX) -> libc::c_int;
    fn SHA256_Update(
        sha: *mut SHA256_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn SHA256_Final(out: *mut uint8_t, sha: *mut SHA256_CTX) -> libc::c_int;
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
    fn CRYPTO_ctr128_encrypt(
        in_0: *const uint8_t,
        out: *mut uint8_t,
        len: size_t,
        key: *const AES_KEY,
        ivec: *mut uint8_t,
        ecount_buf: *mut uint8_t,
        num: *mut libc::c_uint,
        block: block128_f,
    );
    fn CRYPTO_ctr128_encrypt_ctr32(
        in_0: *const uint8_t,
        out: *mut uint8_t,
        len: size_t,
        key: *const AES_KEY,
        ivec: *mut uint8_t,
        ecount_buf: *mut uint8_t,
        num: *mut libc::c_uint,
        ctr: ctr128_f,
    );
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sha256_state_st {
    pub h: [uint32_t; 8],
    pub Nl: uint32_t,
    pub Nh: uint32_t,
    pub data: [uint8_t; 64],
    pub num: libc::c_uint,
    pub md_len: libc::c_uint,
}
pub type SHA256_CTX = sha256_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct aead_aes_ctr_hmac_sha256_ctx {
    pub ks: C2RustUnnamed_0,
    pub ctr: ctr128_f,
    pub block: block128_f,
    pub inner_init_state: SHA256_CTX,
    pub outer_init_state: SHA256_CTX,
}
pub type block128_f = Option::<
    unsafe extern "C" fn(*const uint8_t, *mut uint8_t, *const AES_KEY) -> (),
>;
pub type AES_KEY = aes_key_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct aes_key_st {
    pub rd_key: [uint32_t; 60],
    pub rounds: libc::c_uint,
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
pub union C2RustUnnamed_0 {
    pub align: libc::c_double,
    pub ks: AES_KEY,
}
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
unsafe extern "C" fn hmac_init(
    mut out_inner: *mut SHA256_CTX,
    mut out_outer: *mut SHA256_CTX,
    mut hmac_key: *const uint8_t,
) {
    static mut hmac_key_len: size_t = 32 as libc::c_int as size_t;
    let mut block: [uint8_t; 64] = [0; 64];
    OPENSSL_memcpy(
        block.as_mut_ptr() as *mut libc::c_void,
        hmac_key as *const libc::c_void,
        hmac_key_len,
    );
    OPENSSL_memset(
        block.as_mut_ptr().offset(hmac_key_len as isize) as *mut libc::c_void,
        0x36 as libc::c_int,
        (::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong)
            .wrapping_sub(hmac_key_len),
    );
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while (i as size_t) < hmac_key_len {
        block[i
            as usize] = (block[i as usize] as libc::c_int ^ 0x36 as libc::c_int)
            as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
    SHA256_Init(out_inner);
    SHA256_Update(
        out_inner,
        block.as_mut_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    OPENSSL_memset(
        block.as_mut_ptr().offset(hmac_key_len as isize) as *mut libc::c_void,
        0x5c as libc::c_int,
        (::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong)
            .wrapping_sub(hmac_key_len),
    );
    i = 0 as libc::c_int as libc::c_uint;
    while (i as size_t) < hmac_key_len {
        block[i
            as usize] = (block[i as usize] as libc::c_int
            ^ (0x36 as libc::c_int ^ 0x5c as libc::c_int)) as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
    SHA256_Init(out_outer);
    SHA256_Update(
        out_outer,
        block.as_mut_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
}
unsafe extern "C" fn aead_aes_ctr_hmac_sha256_init(
    mut ctx: *mut EVP_AEAD_CTX,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut tag_len: size_t,
) -> libc::c_int {
    let mut aes_ctx: *mut aead_aes_ctr_hmac_sha256_ctx = &mut (*ctx).state
        as *mut evp_aead_ctx_st_state as *mut aead_aes_ctr_hmac_sha256_ctx;
    static mut hmac_key_len: size_t = 32 as libc::c_int as size_t;
    if key_len < hmac_key_len {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_aesctrhmac.c\0"
                as *const u8 as *const libc::c_char,
            76 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let aes_key_len: size_t = key_len.wrapping_sub(hmac_key_len);
    if aes_key_len != 16 as libc::c_int as size_t
        && aes_key_len != 32 as libc::c_int as size_t
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_aesctrhmac.c\0"
                as *const u8 as *const libc::c_char,
            82 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if tag_len == 0 as libc::c_int as size_t {
        tag_len = 32 as libc::c_int as size_t;
    }
    if tag_len > 32 as libc::c_int as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            116 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_aesctrhmac.c\0"
                as *const u8 as *const libc::c_char,
            91 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*aes_ctx)
        .ctr = aes_ctr_set_key(
        &mut (*aes_ctx).ks.ks,
        0 as *mut GCM128_KEY,
        &mut (*aes_ctx).block,
        key,
        aes_key_len,
    );
    (*ctx).tag_len = tag_len as uint8_t;
    hmac_init(
        &mut (*aes_ctx).inner_init_state,
        &mut (*aes_ctx).outer_init_state,
        key.offset(aes_key_len as isize),
    );
    return 1 as libc::c_int;
}
unsafe extern "C" fn aead_aes_ctr_hmac_sha256_cleanup(mut ctx: *mut EVP_AEAD_CTX) {}
unsafe extern "C" fn hmac_update_uint64(
    mut sha256: *mut SHA256_CTX,
    mut value: uint64_t,
) {
    let mut i: libc::c_uint = 0;
    let mut bytes: [uint8_t; 8] = [0; 8];
    i = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong) < ::core::mem::size_of::<[uint8_t; 8]>() as libc::c_ulong
    {
        bytes[i as usize] = (value & 0xff as libc::c_int as uint64_t) as uint8_t;
        value >>= 8 as libc::c_int;
        i = i.wrapping_add(1);
        i;
    }
    SHA256_Update(
        sha256,
        bytes.as_mut_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint8_t; 8]>() as libc::c_ulong,
    );
}
unsafe extern "C" fn hmac_calculate(
    mut out: *mut uint8_t,
    mut inner_init_state: *const SHA256_CTX,
    mut outer_init_state: *const SHA256_CTX,
    mut ad: *const uint8_t,
    mut ad_len: size_t,
    mut nonce: *const uint8_t,
    mut ciphertext: *const uint8_t,
    mut ciphertext_len: size_t,
) {
    let mut sha256: SHA256_CTX = sha256_state_st {
        h: [0; 8],
        Nl: 0,
        Nh: 0,
        data: [0; 64],
        num: 0,
        md_len: 0,
    };
    OPENSSL_memcpy(
        &mut sha256 as *mut SHA256_CTX as *mut libc::c_void,
        inner_init_state as *const libc::c_void,
        ::core::mem::size_of::<SHA256_CTX>() as libc::c_ulong,
    );
    hmac_update_uint64(&mut sha256, ad_len);
    hmac_update_uint64(&mut sha256, ciphertext_len);
    SHA256_Update(
        &mut sha256,
        nonce as *const libc::c_void,
        12 as libc::c_int as size_t,
    );
    SHA256_Update(&mut sha256, ad as *const libc::c_void, ad_len);
    let num_padding: libc::c_uint = (64 as libc::c_int as libc::c_ulong)
        .wrapping_sub(
            (::core::mem::size_of::<uint64_t>() as libc::c_ulong)
                .wrapping_mul(2 as libc::c_int as libc::c_ulong)
                .wrapping_add(12 as libc::c_int as libc::c_ulong)
                .wrapping_add(ad_len)
                .wrapping_rem(64 as libc::c_int as libc::c_ulong),
        )
        .wrapping_rem(64 as libc::c_int as libc::c_ulong) as libc::c_uint;
    let mut padding: [uint8_t; 64] = [0; 64];
    OPENSSL_memset(
        padding.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        num_padding as size_t,
    );
    SHA256_Update(
        &mut sha256,
        padding.as_mut_ptr() as *const libc::c_void,
        num_padding as size_t,
    );
    SHA256_Update(&mut sha256, ciphertext as *const libc::c_void, ciphertext_len);
    let mut inner_digest: [uint8_t; 32] = [0; 32];
    SHA256_Final(inner_digest.as_mut_ptr(), &mut sha256);
    OPENSSL_memcpy(
        &mut sha256 as *mut SHA256_CTX as *mut libc::c_void,
        outer_init_state as *const libc::c_void,
        ::core::mem::size_of::<SHA256_CTX>() as libc::c_ulong,
    );
    SHA256_Update(
        &mut sha256,
        inner_digest.as_mut_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
    );
    SHA256_Final(out, &mut sha256);
}
unsafe extern "C" fn aead_aes_ctr_hmac_sha256_crypt(
    mut aes_ctx: *const aead_aes_ctr_hmac_sha256_ctx,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
    mut nonce: *const uint8_t,
) {
    let mut partial_block_buffer: [uint8_t; 16] = [0; 16];
    let mut partial_block_offset: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    OPENSSL_memset(
        partial_block_buffer.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong,
    );
    let mut counter: [uint8_t; 16] = [0; 16];
    OPENSSL_memcpy(
        counter.as_mut_ptr() as *mut libc::c_void,
        nonce as *const libc::c_void,
        12 as libc::c_int as size_t,
    );
    OPENSSL_memset(
        counter.as_mut_ptr().offset(12 as libc::c_int as isize) as *mut libc::c_void,
        0 as libc::c_int,
        4 as libc::c_int as size_t,
    );
    if ((*aes_ctx).ctr).is_some() {
        CRYPTO_ctr128_encrypt_ctr32(
            in_0,
            out,
            len,
            &(*aes_ctx).ks.ks,
            counter.as_mut_ptr(),
            partial_block_buffer.as_mut_ptr(),
            &mut partial_block_offset,
            (*aes_ctx).ctr,
        );
    } else {
        CRYPTO_ctr128_encrypt(
            in_0,
            out,
            len,
            &(*aes_ctx).ks.ks,
            counter.as_mut_ptr(),
            partial_block_buffer.as_mut_ptr(),
            &mut partial_block_offset,
            (*aes_ctx).block,
        );
    };
}
unsafe extern "C" fn aead_aes_ctr_hmac_sha256_seal_scatter(
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
    let mut aes_ctx: *const aead_aes_ctr_hmac_sha256_ctx = &(*ctx).state
        as *const evp_aead_ctx_st_state as *mut aead_aes_ctr_hmac_sha256_ctx;
    let in_len_64: uint64_t = in_len;
    if in_len_64
        >= ((1 as libc::c_ulong) << 32 as libc::c_int)
            .wrapping_mul(16 as libc::c_int as libc::c_ulong)
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            117 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_aesctrhmac.c\0"
                as *const u8 as *const libc::c_char,
            185 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if max_out_tag_len < (*ctx).tag_len as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            103 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_aesctrhmac.c\0"
                as *const u8 as *const libc::c_char,
            190 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if nonce_len != 12 as libc::c_int as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            121 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_aesctrhmac.c\0"
                as *const u8 as *const libc::c_char,
            195 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    aead_aes_ctr_hmac_sha256_crypt(aes_ctx, out, in_0, in_len, nonce);
    let mut hmac_result: [uint8_t; 32] = [0; 32];
    hmac_calculate(
        hmac_result.as_mut_ptr(),
        &(*aes_ctx).inner_init_state,
        &(*aes_ctx).outer_init_state,
        ad,
        ad_len,
        nonce,
        out,
        in_len,
    );
    OPENSSL_memcpy(
        out_tag as *mut libc::c_void,
        hmac_result.as_mut_ptr() as *const libc::c_void,
        (*ctx).tag_len as size_t,
    );
    *out_tag_len = (*ctx).tag_len as size_t;
    return 1 as libc::c_int;
}
unsafe extern "C" fn aead_aes_ctr_hmac_sha256_open_gather(
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
    let mut aes_ctx: *const aead_aes_ctr_hmac_sha256_ctx = &(*ctx).state
        as *const evp_aead_ctx_st_state as *mut aead_aes_ctr_hmac_sha256_ctx;
    if in_tag_len != (*ctx).tag_len as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_aesctrhmac.c\0"
                as *const u8 as *const libc::c_char,
            218 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if nonce_len != 12 as libc::c_int as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            121 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_aesctrhmac.c\0"
                as *const u8 as *const libc::c_char,
            223 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut hmac_result: [uint8_t; 32] = [0; 32];
    hmac_calculate(
        hmac_result.as_mut_ptr(),
        &(*aes_ctx).inner_init_state,
        &(*aes_ctx).outer_init_state,
        ad,
        ad_len,
        nonce,
        in_0,
        in_len,
    );
    if CRYPTO_memcmp(
        hmac_result.as_mut_ptr() as *const libc::c_void,
        in_tag as *const libc::c_void,
        (*ctx).tag_len as size_t,
    ) != 0 as libc::c_int
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_aesctrhmac.c\0"
                as *const u8 as *const libc::c_char,
            231 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    aead_aes_ctr_hmac_sha256_crypt(aes_ctx, out, in_0, in_len, nonce);
    return 1 as libc::c_int;
}
static mut aead_aes_128_ctr_hmac_sha256: EVP_AEAD = unsafe {
    {
        let mut init = evp_aead_st {
            key_len: (16 as libc::c_int + 32 as libc::c_int) as uint8_t,
            nonce_len: 12 as libc::c_int as uint8_t,
            overhead: 32 as libc::c_int as uint8_t,
            max_tag_len: 32 as libc::c_int as uint8_t,
            aead_id: 1 as libc::c_int as uint16_t,
            seal_scatter_supports_extra_in: 0 as libc::c_int,
            init: Some(
                aead_aes_ctr_hmac_sha256_init
                    as unsafe extern "C" fn(
                        *mut EVP_AEAD_CTX,
                        *const uint8_t,
                        size_t,
                        size_t,
                    ) -> libc::c_int,
            ),
            init_with_direction: None,
            cleanup: Some(
                aead_aes_ctr_hmac_sha256_cleanup
                    as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
            ),
            open: None,
            seal_scatter: Some(
                aead_aes_ctr_hmac_sha256_seal_scatter
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
                aead_aes_ctr_hmac_sha256_open_gather
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
static mut aead_aes_256_ctr_hmac_sha256: EVP_AEAD = unsafe {
    {
        let mut init = evp_aead_st {
            key_len: (32 as libc::c_int + 32 as libc::c_int) as uint8_t,
            nonce_len: 12 as libc::c_int as uint8_t,
            overhead: 32 as libc::c_int as uint8_t,
            max_tag_len: 32 as libc::c_int as uint8_t,
            aead_id: 2 as libc::c_int as uint16_t,
            seal_scatter_supports_extra_in: 0 as libc::c_int,
            init: Some(
                aead_aes_ctr_hmac_sha256_init
                    as unsafe extern "C" fn(
                        *mut EVP_AEAD_CTX,
                        *const uint8_t,
                        size_t,
                        size_t,
                    ) -> libc::c_int,
            ),
            init_with_direction: None,
            cleanup: Some(
                aead_aes_ctr_hmac_sha256_cleanup
                    as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
            ),
            open: None,
            seal_scatter: Some(
                aead_aes_ctr_hmac_sha256_seal_scatter
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
                aead_aes_ctr_hmac_sha256_open_gather
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
pub unsafe extern "C" fn EVP_aead_aes_128_ctr_hmac_sha256() -> *const EVP_AEAD {
    return &aead_aes_128_ctr_hmac_sha256;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_aead_aes_256_ctr_hmac_sha256() -> *const EVP_AEAD {
    return &aead_aes_256_ctr_hmac_sha256;
}
