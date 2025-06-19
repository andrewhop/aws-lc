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
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn abort() -> !;
    fn CBS_get_asn1(
        cbs: *mut CBS,
        out: *mut CBS,
        tag_value: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBS_get_asn1_uint64(cbs: *mut CBS, out: *mut uint64_t) -> libc::c_int;
    fn CBS_get_asn1_bool(cbs: *mut CBS, out: *mut libc::c_int) -> libc::c_int;
    fn CBB_flush(cbb: *mut CBB) -> libc::c_int;
    fn CBB_add_asn1(
        cbb: *mut CBB,
        out_contents: *mut CBB,
        tag: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBB_add_asn1_uint64(cbb: *mut CBB, value: uint64_t) -> libc::c_int;
    fn CBB_add_asn1_bool(cbb: *mut CBB, value: libc::c_int) -> libc::c_int;
    fn EVP_CIPHER_CTX_key_length(ctx: *const EVP_CIPHER_CTX) -> libc::c_uint;
    fn RAND_bytes(buf: *mut uint8_t, len: size_t) -> libc::c_int;
    fn AES_set_encrypt_key(
        key: *const uint8_t,
        bits: libc::c_uint,
        aeskey: *mut AES_KEY,
    ) -> libc::c_int;
    fn AES_set_decrypt_key(
        key: *const uint8_t,
        bits: libc::c_uint,
        aeskey: *mut AES_KEY,
    ) -> libc::c_int;
    fn AES_encrypt(in_0: *const uint8_t, out: *mut uint8_t, key: *const AES_KEY);
    fn AES_decrypt(in_0: *const uint8_t, out: *mut uint8_t, key: *const AES_KEY);
    fn AES_wrap_key(
        key: *const AES_KEY,
        iv: *const uint8_t,
        out: *mut uint8_t,
        in_0: *const uint8_t,
        in_len: size_t,
    ) -> libc::c_int;
    fn AES_unwrap_key(
        key: *const AES_KEY,
        iv: *const uint8_t,
        out: *mut uint8_t,
        in_0: *const uint8_t,
        in_len: size_t,
    ) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn CRYPTO_memcmp(
        a: *const libc::c_void,
        b: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn OPENSSL_memdup(data: *const libc::c_void, size: size_t) -> *mut libc::c_void;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn CRYPTO_once(
        once: *mut CRYPTO_once_t,
        init: Option::<unsafe extern "C" fn() -> ()>,
    );
    fn aes_nohw_set_encrypt_key(
        key: *const uint8_t,
        bits: libc::c_uint,
        aeskey: *mut AES_KEY,
    ) -> libc::c_int;
    fn aes_nohw_set_decrypt_key(
        key: *const uint8_t,
        bits: libc::c_uint,
        aeskey: *mut AES_KEY,
    ) -> libc::c_int;
    fn aes_nohw_encrypt(in_0: *const uint8_t, out: *mut uint8_t, key: *const AES_KEY);
    fn aes_nohw_decrypt(in_0: *const uint8_t, out: *mut uint8_t, key: *const AES_KEY);
    fn aes_nohw_ctr32_encrypt_blocks(
        in_0: *const uint8_t,
        out: *mut uint8_t,
        blocks: size_t,
        key: *const AES_KEY,
        ivec: *const uint8_t,
    );
    fn aes_nohw_cbc_encrypt(
        in_0: *const uint8_t,
        out: *mut uint8_t,
        len: size_t,
        key: *const AES_KEY,
        ivec: *mut uint8_t,
        enc: libc::c_int,
    );
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
    fn crypto_gcm_clmul_enabled() -> libc::c_int;
    fn CRYPTO_gcm128_init_key(
        gcm_key: *mut GCM128_KEY,
        key: *const AES_KEY,
        block: block128_f,
        block_is_hwaes: libc::c_int,
    );
    fn CRYPTO_gcm128_setiv(
        ctx: *mut GCM128_CONTEXT,
        key: *const AES_KEY,
        iv: *const uint8_t,
        iv_len: size_t,
    );
    fn CRYPTO_gcm128_aad(
        ctx: *mut GCM128_CONTEXT,
        aad: *const uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn CRYPTO_gcm128_encrypt(
        ctx: *mut GCM128_CONTEXT,
        key: *const AES_KEY,
        in_0: *const uint8_t,
        out: *mut uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn CRYPTO_gcm128_decrypt(
        ctx: *mut GCM128_CONTEXT,
        key: *const AES_KEY,
        in_0: *const uint8_t,
        out: *mut uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn CRYPTO_gcm128_encrypt_ctr32(
        ctx: *mut GCM128_CONTEXT,
        key: *const AES_KEY,
        in_0: *const uint8_t,
        out: *mut uint8_t,
        len: size_t,
        stream: ctr128_f,
    ) -> libc::c_int;
    fn CRYPTO_gcm128_decrypt_ctr32(
        ctx: *mut GCM128_CONTEXT,
        key: *const AES_KEY,
        in_0: *const uint8_t,
        out: *mut uint8_t,
        len: size_t,
        stream: ctr128_f,
    ) -> libc::c_int;
    fn CRYPTO_gcm128_finish(
        ctx: *mut GCM128_CONTEXT,
        tag: *const uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn CRYPTO_gcm128_tag(ctx: *mut GCM128_CONTEXT, tag: *mut uint8_t, len: size_t);
    fn CRYPTO_cbc128_encrypt(
        in_0: *const uint8_t,
        out: *mut uint8_t,
        len: size_t,
        key: *const AES_KEY,
        ivec: *mut uint8_t,
        block: block128_f,
    );
    fn CRYPTO_cbc128_decrypt(
        in_0: *const uint8_t,
        out: *mut uint8_t,
        len: size_t,
        key: *const AES_KEY,
        ivec: *mut uint8_t,
        block: block128_f,
    );
    fn CRYPTO_ofb128_encrypt(
        in_0: *const uint8_t,
        out: *mut uint8_t,
        len: size_t,
        key: *const AES_KEY,
        ivec: *mut uint8_t,
        num: *mut libc::c_uint,
        block: block128_f,
    );
    fn CRYPTO_xts128_encrypt(
        ctx: *const XTS128_CONTEXT,
        iv: *const uint8_t,
        inp: *const uint8_t,
        out: *mut uint8_t,
        len: size_t,
        enc: libc::c_int,
    ) -> size_t;
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
pub type uintptr_t = libc::c_ulong;
pub type pthread_once_t = libc::c_int;
pub type CBS_ASN1_TAG = uint32_t;
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
pub struct evp_cipher_ctx_st {
    pub cipher: *const EVP_CIPHER,
    pub app_data: *mut libc::c_void,
    pub cipher_data: *mut libc::c_void,
    pub key_len: libc::c_uint,
    pub encrypt: libc::c_int,
    pub flags: uint32_t,
    pub oiv: [uint8_t; 16],
    pub iv: [uint8_t; 16],
    pub buf: [uint8_t; 32],
    pub buf_len: libc::c_int,
    pub num: libc::c_uint,
    pub final_used: libc::c_int,
    pub final_0: [uint8_t; 32],
    pub poisoned: libc::c_int,
}
pub type EVP_CIPHER = evp_cipher_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_cipher_st {
    pub nid: libc::c_int,
    pub block_size: libc::c_uint,
    pub key_len: libc::c_uint,
    pub iv_len: libc::c_uint,
    pub ctx_size: libc::c_uint,
    pub flags: uint32_t,
    pub init: Option::<
        unsafe extern "C" fn(
            *mut EVP_CIPHER_CTX,
            *const uint8_t,
            *const uint8_t,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub cipher: Option::<
        unsafe extern "C" fn(
            *mut EVP_CIPHER_CTX,
            *mut uint8_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub cleanup: Option::<unsafe extern "C" fn(*mut EVP_CIPHER_CTX) -> ()>,
    pub ctrl: Option::<
        unsafe extern "C" fn(
            *mut EVP_CIPHER_CTX,
            libc::c_int,
            libc::c_int,
            *mut libc::c_void,
        ) -> libc::c_int,
    >,
}
pub type EVP_CIPHER_CTX = evp_cipher_ctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct aead_aes_gcm_ctx {
    pub ks: C2RustUnnamed_0,
    pub gcm_key: GCM128_KEY,
    pub ctr: ctr128_f,
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
pub type block128_f = Option::<
    unsafe extern "C" fn(*const uint8_t, *mut uint8_t, *const AES_KEY) -> (),
>;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub align: libc::c_double,
    pub ks: AES_KEY,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct GCM128_CONTEXT {
    pub Yi: [uint8_t; 16],
    pub EKi: [uint8_t; 16],
    pub EK0: [uint8_t; 16],
    pub len: C2RustUnnamed_1,
    pub Xi: [uint8_t; 16],
    pub gcm_key: GCM128_KEY,
    pub mres: libc::c_uint,
    pub ares: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_1 {
    pub aad: uint64_t,
    pub msg: uint64_t,
}
pub type fips_counter_t = libc::c_uint;
pub const fips_counter_max: fips_counter_t = 3;
pub const fips_counter_evp_aes_256_ctr: fips_counter_t = 3;
pub const fips_counter_evp_aes_128_ctr: fips_counter_t = 2;
pub const fips_counter_evp_aes_256_gcm: fips_counter_t = 1;
pub const fips_counter_evp_aes_128_gcm: fips_counter_t = 0;
pub type CRYPTO_once_t = pthread_once_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct aead_aes_gcm_tls12_ctx {
    pub gcm_ctx: aead_aes_gcm_ctx,
    pub min_next_nonce: uint64_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct aead_aes_gcm_tls13_ctx {
    pub gcm_ctx: aead_aes_gcm_ctx,
    pub min_next_nonce: uint64_t,
    pub mask: uint64_t,
    pub first: uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_2 {
    pub align: libc::c_double,
    pub ks: AES_KEY,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EVP_AES_KEY {
    pub ks: C2RustUnnamed_2,
    pub block: block128_f,
    pub stream: C2RustUnnamed_3,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_3 {
    pub cbc: cbc128_f,
    pub ctr: ctr128_f,
}
pub type cbc128_f = Option::<
    unsafe extern "C" fn(
        *const uint8_t,
        *mut uint8_t,
        size_t,
        *const AES_KEY,
        *mut uint8_t,
        libc::c_int,
    ) -> (),
>;
pub type XTS128_CONTEXT = xts128_context;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xts128_context {
    pub key1: *mut AES_KEY,
    pub key2: *mut AES_KEY,
    pub block1: block128_f,
    pub block2: block128_f,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EVP_AES_XTS_CTX {
    pub ks1: C2RustUnnamed_4,
    pub ks2: C2RustUnnamed_4,
    pub xts: XTS128_CONTEXT,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_4 {
    pub align: libc::c_double,
    pub ks: AES_KEY,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EVP_AES_WRAP_CTX {
    pub ks: C2RustUnnamed_5,
    pub iv: *const uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_5 {
    pub align: libc::c_double,
    pub ks: AES_KEY,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EVP_AES_GCM_CTX {
    pub gcm: GCM128_CONTEXT,
    pub ks: C2RustUnnamed_6,
    pub key_set: libc::c_int,
    pub iv_set: libc::c_int,
    pub iv: *mut uint8_t,
    pub ivlen: libc::c_int,
    pub taglen: libc::c_int,
    pub iv_gen: libc::c_int,
    pub ctr: ctr128_f,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_6 {
    pub align: libc::c_double,
    pub ks: AES_KEY,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_352_error_is_EVP_AES_GCM_CTX_needs_more_alignment_than_this_function_provides {
    #[bitfield(
        name = "static_assertion_at_line_352_error_is_EVP_AES_GCM_CTX_needs_more_alignment_than_this_function_provides",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_352_error_is_EVP_AES_GCM_CTX_needs_more_alignment_than_this_function_provides: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[inline]
unsafe extern "C" fn CRYPTO_bswap8(mut x: uint64_t) -> uint64_t {
    return x.swap_bytes();
}
#[inline]
unsafe extern "C" fn OPENSSL_memcmp(
    mut s1: *const libc::c_void,
    mut s2: *const libc::c_void,
    mut n: size_t,
) -> libc::c_int {
    if n == 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    return memcmp(s1, s2, n);
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
unsafe extern "C" fn boringssl_fips_inc_counter(mut counter: fips_counter_t) {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_lock_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_unlock_state() {}
#[inline]
unsafe extern "C" fn AEAD_GCM_verify_service_indicator(mut ctx: *const EVP_AEAD_CTX) {}
#[inline]
unsafe extern "C" fn hwaes_capable() -> libc::c_int {
    return 0 as libc::c_int;
}
#[inline]
unsafe extern "C" fn aes_hw_set_encrypt_key(
    mut user_key: *const uint8_t,
    mut bits: libc::c_int,
    mut key: *mut AES_KEY,
) -> libc::c_int {
    abort();
}
#[inline]
unsafe extern "C" fn aes_hw_set_decrypt_key(
    mut user_key: *const uint8_t,
    mut bits: libc::c_int,
    mut key: *mut AES_KEY,
) -> libc::c_int {
    abort();
}
#[inline]
unsafe extern "C" fn aes_hw_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut key: *const AES_KEY,
) {
    abort();
}
#[inline]
unsafe extern "C" fn aes_hw_decrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut key: *const AES_KEY,
) {
    abort();
}
#[inline]
unsafe extern "C" fn aes_hw_cbc_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut length: size_t,
    mut key: *const AES_KEY,
    mut ivec: *mut uint8_t,
    mut enc: libc::c_int,
) {
    abort();
}
#[inline]
unsafe extern "C" fn aes_hw_ctr32_encrypt_blocks(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut len: size_t,
    mut key: *const AES_KEY,
    mut ivec: *const uint8_t,
) {
    abort();
}
#[inline]
unsafe extern "C" fn hwaes_xts_available() -> libc::c_int {
    return 0 as libc::c_int;
}
#[inline]
unsafe extern "C" fn aes_hw_xts_cipher(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut length: size_t,
    mut key1: *const AES_KEY,
    mut key2: *const AES_KEY,
    mut iv: *const uint8_t,
    mut enc: libc::c_int,
) -> libc::c_int {
    abort();
}
#[inline]
unsafe extern "C" fn bsaes_capable() -> libc::c_char {
    return 0 as libc::c_int as libc::c_char;
}
#[inline]
unsafe extern "C" fn bsaes_cbc_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut length: size_t,
    mut key: *const AES_KEY,
    mut ivec: *mut uint8_t,
    mut enc: libc::c_int,
) {
    abort();
}
#[inline]
unsafe extern "C" fn vpaes_decrypt_key_to_bsaes(
    mut out_bsaes: *mut AES_KEY,
    mut vpaes: *const AES_KEY,
) {
    abort();
}
#[inline]
unsafe extern "C" fn vpaes_capable() -> libc::c_char {
    return 0 as libc::c_int as libc::c_char;
}
#[inline]
unsafe extern "C" fn vpaes_set_encrypt_key(
    mut userKey: *const uint8_t,
    mut bits: libc::c_int,
    mut key: *mut AES_KEY,
) -> libc::c_int {
    abort();
}
#[inline]
unsafe extern "C" fn vpaes_set_decrypt_key(
    mut userKey: *const uint8_t,
    mut bits: libc::c_int,
    mut key: *mut AES_KEY,
) -> libc::c_int {
    abort();
}
#[inline]
unsafe extern "C" fn vpaes_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut key: *const AES_KEY,
) {
    abort();
}
#[inline]
unsafe extern "C" fn vpaes_decrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut key: *const AES_KEY,
) {
    abort();
}
unsafe extern "C" fn aes_init_key(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut key: *const uint8_t,
    mut iv: *const uint8_t,
    mut enc: libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    let mut dat: *mut EVP_AES_KEY = (*ctx).cipher_data as *mut EVP_AES_KEY;
    let mode: libc::c_int = ((*(*ctx).cipher).flags & 0x3f as libc::c_int as uint32_t)
        as libc::c_int;
    if mode == 0x5 as libc::c_int {
        match (*ctx).key_len {
            16 => {
                boringssl_fips_inc_counter(fips_counter_evp_aes_128_ctr);
            }
            32 => {
                boringssl_fips_inc_counter(fips_counter_evp_aes_256_ctr);
            }
            _ => {}
        }
    }
    if (mode == 0x1 as libc::c_int || mode == 0x2 as libc::c_int) && enc == 0 {
        if hwaes_capable() != 0 {
            ret = aes_hw_set_decrypt_key(
                key,
                ((*ctx).key_len).wrapping_mul(8 as libc::c_int as libc::c_uint)
                    as libc::c_int,
                &mut (*dat).ks.ks,
            );
            (*dat)
                .block = Some(
                aes_hw_decrypt
                    as unsafe extern "C" fn(
                        *const uint8_t,
                        *mut uint8_t,
                        *const AES_KEY,
                    ) -> (),
            );
            (*dat).stream.cbc = None;
            if mode == 0x2 as libc::c_int {
                (*dat)
                    .stream
                    .cbc = Some(
                    aes_hw_cbc_encrypt
                        as unsafe extern "C" fn(
                            *const uint8_t,
                            *mut uint8_t,
                            size_t,
                            *const AES_KEY,
                            *mut uint8_t,
                            libc::c_int,
                        ) -> (),
                );
            }
        } else if bsaes_capable() as libc::c_int != 0 && mode == 0x2 as libc::c_int {
            if vpaes_capable() != 0 {} else {
                __assert_fail(
                    b"vpaes_capable()\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                        as *const u8 as *const libc::c_char,
                    176 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 74],
                        &[libc::c_char; 74],
                    >(
                        b"int aes_init_key(EVP_CIPHER_CTX *, const uint8_t *, const uint8_t *, int)\0",
                    ))
                        .as_ptr(),
                );
            }
            'c_6226: {
                if vpaes_capable() != 0 {} else {
                    __assert_fail(
                        b"vpaes_capable()\0" as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                            as *const u8 as *const libc::c_char,
                        176 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 74],
                            &[libc::c_char; 74],
                        >(
                            b"int aes_init_key(EVP_CIPHER_CTX *, const uint8_t *, const uint8_t *, int)\0",
                        ))
                            .as_ptr(),
                    );
                }
            };
            ret = vpaes_set_decrypt_key(
                key,
                ((*ctx).key_len).wrapping_mul(8 as libc::c_int as libc::c_uint)
                    as libc::c_int,
                &mut (*dat).ks.ks,
            );
            if ret == 0 as libc::c_int {
                vpaes_decrypt_key_to_bsaes(&mut (*dat).ks.ks, &mut (*dat).ks.ks);
            }
            (*dat).block = None;
            (*dat)
                .stream
                .cbc = Some(
                bsaes_cbc_encrypt
                    as unsafe extern "C" fn(
                        *const uint8_t,
                        *mut uint8_t,
                        size_t,
                        *const AES_KEY,
                        *mut uint8_t,
                        libc::c_int,
                    ) -> (),
            );
        } else if vpaes_capable() != 0 {
            ret = vpaes_set_decrypt_key(
                key,
                ((*ctx).key_len).wrapping_mul(8 as libc::c_int as libc::c_uint)
                    as libc::c_int,
                &mut (*dat).ks.ks,
            );
            (*dat)
                .block = Some(
                vpaes_decrypt
                    as unsafe extern "C" fn(
                        *const uint8_t,
                        *mut uint8_t,
                        *const AES_KEY,
                    ) -> (),
            );
            (*dat).stream.cbc = None;
        } else {
            ret = aes_nohw_set_decrypt_key(
                key,
                ((*ctx).key_len).wrapping_mul(8 as libc::c_int as libc::c_uint),
                &mut (*dat).ks.ks,
            );
            (*dat)
                .block = Some(
                aes_nohw_decrypt
                    as unsafe extern "C" fn(
                        *const uint8_t,
                        *mut uint8_t,
                        *const AES_KEY,
                    ) -> (),
            );
            (*dat).stream.cbc = None;
            if mode == 0x2 as libc::c_int {
                (*dat)
                    .stream
                    .cbc = Some(
                    aes_nohw_cbc_encrypt
                        as unsafe extern "C" fn(
                            *const uint8_t,
                            *mut uint8_t,
                            size_t,
                            *const AES_KEY,
                            *mut uint8_t,
                            libc::c_int,
                        ) -> (),
                );
            }
        }
    } else if hwaes_capable() != 0 {
        ret = aes_hw_set_encrypt_key(
            key,
            ((*ctx).key_len).wrapping_mul(8 as libc::c_int as libc::c_uint)
                as libc::c_int,
            &mut (*dat).ks.ks,
        );
        (*dat)
            .block = Some(
            aes_hw_encrypt
                as unsafe extern "C" fn(
                    *const uint8_t,
                    *mut uint8_t,
                    *const AES_KEY,
                ) -> (),
        );
        (*dat).stream.cbc = None;
        if mode == 0x2 as libc::c_int {
            (*dat)
                .stream
                .cbc = Some(
                aes_hw_cbc_encrypt
                    as unsafe extern "C" fn(
                        *const uint8_t,
                        *mut uint8_t,
                        size_t,
                        *const AES_KEY,
                        *mut uint8_t,
                        libc::c_int,
                    ) -> (),
            );
        } else if mode == 0x5 as libc::c_int {
            (*dat)
                .stream
                .ctr = Some(
                aes_hw_ctr32_encrypt_blocks
                    as unsafe extern "C" fn(
                        *const uint8_t,
                        *mut uint8_t,
                        size_t,
                        *const AES_KEY,
                        *const uint8_t,
                    ) -> (),
            );
        }
    } else if vpaes_capable() != 0 {
        ret = vpaes_set_encrypt_key(
            key,
            ((*ctx).key_len).wrapping_mul(8 as libc::c_int as libc::c_uint)
                as libc::c_int,
            &mut (*dat).ks.ks,
        );
        (*dat)
            .block = Some(
            vpaes_encrypt
                as unsafe extern "C" fn(
                    *const uint8_t,
                    *mut uint8_t,
                    *const AES_KEY,
                ) -> (),
        );
        (*dat).stream.cbc = None;
        mode == 0x5 as libc::c_int;
    } else {
        ret = aes_nohw_set_encrypt_key(
            key,
            ((*ctx).key_len).wrapping_mul(8 as libc::c_int as libc::c_uint),
            &mut (*dat).ks.ks,
        );
        (*dat)
            .block = Some(
            aes_nohw_encrypt
                as unsafe extern "C" fn(
                    *const uint8_t,
                    *mut uint8_t,
                    *const AES_KEY,
                ) -> (),
        );
        (*dat).stream.cbc = None;
        if mode == 0x2 as libc::c_int {
            (*dat)
                .stream
                .cbc = Some(
                aes_nohw_cbc_encrypt
                    as unsafe extern "C" fn(
                        *const uint8_t,
                        *mut uint8_t,
                        size_t,
                        *const AES_KEY,
                        *mut uint8_t,
                        libc::c_int,
                    ) -> (),
            );
        }
    }
    if ret < 0 as libc::c_int {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            237 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn aes_cbc_cipher(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut dat: *mut EVP_AES_KEY = (*ctx).cipher_data as *mut EVP_AES_KEY;
    if ((*dat).stream.cbc).is_some() {
        (Some(((*dat).stream.cbc).expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )(
            in_0,
            out,
            len,
            &mut (*dat).ks.ks,
            ((*ctx).iv).as_mut_ptr(),
            (*ctx).encrypt,
        );
    } else if (*ctx).encrypt != 0 {
        CRYPTO_cbc128_encrypt(
            in_0,
            out,
            len,
            &mut (*dat).ks.ks,
            ((*ctx).iv).as_mut_ptr(),
            (*dat).block,
        );
    } else {
        CRYPTO_cbc128_decrypt(
            in_0,
            out,
            len,
            &mut (*dat).ks.ks,
            ((*ctx).iv).as_mut_ptr(),
            (*dat).block,
        );
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn aes_ecb_cipher(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut bl: size_t = (*(*ctx).cipher).block_size as size_t;
    let mut dat: *mut EVP_AES_KEY = (*ctx).cipher_data as *mut EVP_AES_KEY;
    if len < bl {
        return 1 as libc::c_int;
    }
    len = len.wrapping_sub(bl);
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i <= len {
        (Some(((*dat).block).expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )(in_0.offset(i as isize), out.offset(i as isize), &mut (*dat).ks.ks);
        i = i.wrapping_add(bl);
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn aes_ctr_cipher(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut dat: *mut EVP_AES_KEY = (*ctx).cipher_data as *mut EVP_AES_KEY;
    if ((*dat).stream.ctr).is_some() {
        CRYPTO_ctr128_encrypt_ctr32(
            in_0,
            out,
            len,
            &mut (*dat).ks.ks,
            ((*ctx).iv).as_mut_ptr(),
            ((*ctx).buf).as_mut_ptr(),
            &mut (*ctx).num,
            (*dat).stream.ctr,
        );
    } else {
        CRYPTO_ctr128_encrypt(
            in_0,
            out,
            len,
            &mut (*dat).ks.ks,
            ((*ctx).iv).as_mut_ptr(),
            ((*ctx).buf).as_mut_ptr(),
            &mut (*ctx).num,
            (*dat).block,
        );
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn aes_ofb_cipher(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut dat: *mut EVP_AES_KEY = (*ctx).cipher_data as *mut EVP_AES_KEY;
    CRYPTO_ofb128_encrypt(
        in_0,
        out,
        len,
        &mut (*dat).ks.ks,
        ((*ctx).iv).as_mut_ptr(),
        &mut (*ctx).num,
        (*dat).block,
    );
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aes_ctr_set_key(
    mut aes_key: *mut AES_KEY,
    mut gcm_key: *mut GCM128_KEY,
    mut out_block: *mut block128_f,
    mut key: *const uint8_t,
    mut key_bytes: size_t,
) -> ctr128_f {
    if key_bytes == (128 as libc::c_int / 8 as libc::c_int) as size_t
        || key_bytes == (192 as libc::c_int / 8 as libc::c_int) as size_t
        || key_bytes == (256 as libc::c_int / 8 as libc::c_int) as size_t
    {} else {
        __assert_fail(
            b"key_bytes == 128 / 8 || key_bytes == 192 / 8 || key_bytes == 256 / 8\0"
                as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            303 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 89],
                &[libc::c_char; 89],
            >(
                b"ctr128_f aes_ctr_set_key(AES_KEY *, GCM128_KEY *, block128_f *, const uint8_t *, size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2863: {
        if key_bytes == (128 as libc::c_int / 8 as libc::c_int) as size_t
            || key_bytes == (192 as libc::c_int / 8 as libc::c_int) as size_t
            || key_bytes == (256 as libc::c_int / 8 as libc::c_int) as size_t
        {} else {
            __assert_fail(
                b"key_bytes == 128 / 8 || key_bytes == 192 / 8 || key_bytes == 256 / 8\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                    as *const u8 as *const libc::c_char,
                303 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 89],
                    &[libc::c_char; 89],
                >(
                    b"ctr128_f aes_ctr_set_key(AES_KEY *, GCM128_KEY *, block128_f *, const uint8_t *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if hwaes_capable() != 0 {
        aes_hw_set_encrypt_key(
            key,
            key_bytes as libc::c_int * 8 as libc::c_int,
            aes_key,
        );
        if !gcm_key.is_null() {
            CRYPTO_gcm128_init_key(
                gcm_key,
                aes_key,
                Some(
                    aes_hw_encrypt
                        as unsafe extern "C" fn(
                            *const uint8_t,
                            *mut uint8_t,
                            *const AES_KEY,
                        ) -> (),
                ),
                1 as libc::c_int,
            );
        }
        if !out_block.is_null() {
            *out_block = Some(
                aes_hw_encrypt
                    as unsafe extern "C" fn(
                        *const uint8_t,
                        *mut uint8_t,
                        *const AES_KEY,
                    ) -> (),
            );
        }
        return Some(
            aes_hw_ctr32_encrypt_blocks
                as unsafe extern "C" fn(
                    *const uint8_t,
                    *mut uint8_t,
                    size_t,
                    *const AES_KEY,
                    *const uint8_t,
                ) -> (),
        );
    }
    if vpaes_capable() != 0 {
        vpaes_set_encrypt_key(key, key_bytes as libc::c_int * 8 as libc::c_int, aes_key);
        if !out_block.is_null() {
            *out_block = Some(
                vpaes_encrypt
                    as unsafe extern "C" fn(
                        *const uint8_t,
                        *mut uint8_t,
                        *const AES_KEY,
                    ) -> (),
            );
        }
        if !gcm_key.is_null() {
            CRYPTO_gcm128_init_key(
                gcm_key,
                aes_key,
                Some(
                    vpaes_encrypt
                        as unsafe extern "C" fn(
                            *const uint8_t,
                            *mut uint8_t,
                            *const AES_KEY,
                        ) -> (),
                ),
                0 as libc::c_int,
            );
        }
        return None;
    }
    aes_nohw_set_encrypt_key(
        key,
        (key_bytes as libc::c_int * 8 as libc::c_int) as libc::c_uint,
        aes_key,
    );
    if !gcm_key.is_null() {
        CRYPTO_gcm128_init_key(
            gcm_key,
            aes_key,
            Some(
                aes_nohw_encrypt
                    as unsafe extern "C" fn(
                        *const uint8_t,
                        *mut uint8_t,
                        *const AES_KEY,
                    ) -> (),
            ),
            0 as libc::c_int,
        );
    }
    if !out_block.is_null() {
        *out_block = Some(
            aes_nohw_encrypt
                as unsafe extern "C" fn(
                    *const uint8_t,
                    *mut uint8_t,
                    *const AES_KEY,
                ) -> (),
        );
    }
    return Some(
        aes_nohw_ctr32_encrypt_blocks
            as unsafe extern "C" fn(
                *const uint8_t,
                *mut uint8_t,
                size_t,
                *const AES_KEY,
                *const uint8_t,
            ) -> (),
    );
}
unsafe extern "C" fn aes_gcm_from_cipher_ctx(
    mut ctx: *mut EVP_CIPHER_CTX,
) -> *mut EVP_AES_GCM_CTX {
    if (*(*ctx).cipher).ctx_size as libc::c_ulong
        == (::core::mem::size_of::<EVP_AES_GCM_CTX>() as libc::c_ulong)
            .wrapping_add(8 as libc::c_int as libc::c_ulong)
    {} else {
        __assert_fail(
            b"ctx->cipher->ctx_size == sizeof(EVP_AES_GCM_CTX) + EVP_AES_GCM_CTX_PADDING\0"
                as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            357 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 59],
                &[libc::c_char; 59],
            >(b"EVP_AES_GCM_CTX *aes_gcm_from_cipher_ctx(EVP_CIPHER_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_8926: {
        if (*(*ctx).cipher).ctx_size as libc::c_ulong
            == (::core::mem::size_of::<EVP_AES_GCM_CTX>() as libc::c_ulong)
                .wrapping_add(8 as libc::c_int as libc::c_ulong)
        {} else {
            __assert_fail(
                b"ctx->cipher->ctx_size == sizeof(EVP_AES_GCM_CTX) + EVP_AES_GCM_CTX_PADDING\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                    as *const u8 as *const libc::c_char,
                357 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 59],
                    &[libc::c_char; 59],
                >(b"EVP_AES_GCM_CTX *aes_gcm_from_cipher_ctx(EVP_CIPHER_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut ptr: *mut libc::c_char = (*ctx).cipher_data as *mut libc::c_char;
    if ptr as uintptr_t % 8 as libc::c_int as uintptr_t == 0 as libc::c_int as uintptr_t
    {} else {
        __assert_fail(
            b"(uintptr_t)ptr % 8 == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            364 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 59],
                &[libc::c_char; 59],
            >(b"EVP_AES_GCM_CTX *aes_gcm_from_cipher_ctx(EVP_CIPHER_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_8878: {
        if ptr as uintptr_t % 8 as libc::c_int as uintptr_t
            == 0 as libc::c_int as uintptr_t
        {} else {
            __assert_fail(
                b"(uintptr_t)ptr % 8 == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                    as *const u8 as *const libc::c_char,
                364 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 59],
                    &[libc::c_char; 59],
                >(b"EVP_AES_GCM_CTX *aes_gcm_from_cipher_ctx(EVP_CIPHER_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    ptr = ptr.offset((ptr as uintptr_t & 8 as libc::c_int as uintptr_t) as isize);
    return ptr as *mut EVP_AES_GCM_CTX;
}
unsafe extern "C" fn aes_gcm_init_key(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut key: *const uint8_t,
    mut iv: *const uint8_t,
    mut enc: libc::c_int,
) -> libc::c_int {
    let mut gctx: *mut EVP_AES_GCM_CTX = aes_gcm_from_cipher_ctx(ctx);
    if iv.is_null() && key.is_null() {
        return 1 as libc::c_int;
    }
    match (*ctx).key_len {
        16 => {
            boringssl_fips_inc_counter(fips_counter_evp_aes_128_gcm);
        }
        32 => {
            boringssl_fips_inc_counter(fips_counter_evp_aes_256_gcm);
        }
        _ => {}
    }
    if !key.is_null() {
        OPENSSL_memset(
            &mut (*gctx).gcm as *mut GCM128_CONTEXT as *mut libc::c_void,
            0 as libc::c_int,
            ::core::mem::size_of::<GCM128_CONTEXT>() as libc::c_ulong,
        );
        (*gctx)
            .ctr = aes_ctr_set_key(
            &mut (*gctx).ks.ks,
            &mut (*gctx).gcm.gcm_key,
            0 as *mut block128_f,
            key,
            (*ctx).key_len as size_t,
        );
        if iv.is_null() && (*gctx).iv_set != 0 {
            iv = (*gctx).iv;
        }
        if !iv.is_null() {
            CRYPTO_gcm128_setiv(
                &mut (*gctx).gcm,
                &mut (*gctx).ks.ks,
                iv,
                (*gctx).ivlen as size_t,
            );
            (*gctx).iv_set = 1 as libc::c_int;
        }
        (*gctx).key_set = 1 as libc::c_int;
    } else {
        if (*gctx).key_set != 0 {
            CRYPTO_gcm128_setiv(
                &mut (*gctx).gcm,
                &mut (*gctx).ks.ks,
                iv,
                (*gctx).ivlen as size_t,
            );
        } else {
            OPENSSL_memcpy(
                (*gctx).iv as *mut libc::c_void,
                iv as *const libc::c_void,
                (*gctx).ivlen as size_t,
            );
        }
        (*gctx).iv_set = 1 as libc::c_int;
        (*gctx).iv_gen = 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn aes_gcm_cleanup(mut c: *mut EVP_CIPHER_CTX) {
    let mut gctx: *mut EVP_AES_GCM_CTX = aes_gcm_from_cipher_ctx(c);
    OPENSSL_cleanse(
        &mut (*gctx).gcm as *mut GCM128_CONTEXT as *mut libc::c_void,
        ::core::mem::size_of::<GCM128_CONTEXT>() as libc::c_ulong,
    );
    if (*gctx).iv != ((*c).iv).as_mut_ptr() {
        OPENSSL_free((*gctx).iv as *mut libc::c_void);
    }
}
unsafe extern "C" fn aes_gcm_ctrl(
    mut c: *mut EVP_CIPHER_CTX,
    mut type_0: libc::c_int,
    mut arg: libc::c_int,
    mut ptr: *mut libc::c_void,
) -> libc::c_int {
    let mut gctx: *mut EVP_AES_GCM_CTX = aes_gcm_from_cipher_ctx(c);
    match type_0 {
        0 => {
            (*gctx).key_set = 0 as libc::c_int;
            (*gctx).iv_set = 0 as libc::c_int;
            (*gctx).ivlen = (*(*c).cipher).iv_len as libc::c_int;
            (*gctx).iv = ((*c).iv).as_mut_ptr();
            (*gctx).taglen = -(1 as libc::c_int);
            (*gctx).iv_gen = 0 as libc::c_int;
            return 1 as libc::c_int;
        }
        9 => {
            if arg <= 0 as libc::c_int {
                return 0 as libc::c_int;
            }
            if arg > 16 as libc::c_int && arg > (*gctx).ivlen {
                if (*gctx).iv != ((*c).iv).as_mut_ptr() {
                    OPENSSL_free((*gctx).iv as *mut libc::c_void);
                }
                (*gctx).iv = OPENSSL_malloc(arg as size_t) as *mut uint8_t;
                if ((*gctx).iv).is_null() {
                    return 0 as libc::c_int;
                }
            }
            (*gctx).ivlen = arg;
            return 1 as libc::c_int;
        }
        25 => {
            *(ptr as *mut libc::c_int) = (*gctx).ivlen;
            return 1 as libc::c_int;
        }
        17 => {
            if arg <= 0 as libc::c_int || arg > 16 as libc::c_int || (*c).encrypt != 0 {
                return 0 as libc::c_int;
            }
            OPENSSL_memcpy(
                ((*c).buf).as_mut_ptr() as *mut libc::c_void,
                ptr,
                arg as size_t,
            );
            (*gctx).taglen = arg;
            return 1 as libc::c_int;
        }
        16 => {
            if arg <= 0 as libc::c_int || arg > 16 as libc::c_int || (*c).encrypt == 0
                || (*gctx).taglen < 0 as libc::c_int
            {
                return 0 as libc::c_int;
            }
            OPENSSL_memcpy(
                ptr,
                ((*c).buf).as_mut_ptr() as *const libc::c_void,
                arg as size_t,
            );
            return 1 as libc::c_int;
        }
        18 => {
            if arg == -(1 as libc::c_int) {
                OPENSSL_memcpy(
                    (*gctx).iv as *mut libc::c_void,
                    ptr,
                    (*gctx).ivlen as size_t,
                );
                (*gctx).iv_gen = 1 as libc::c_int;
                return 1 as libc::c_int;
            }
            if arg < 4 as libc::c_int || (*gctx).ivlen - arg < 8 as libc::c_int {
                return 0 as libc::c_int;
            }
            OPENSSL_memcpy((*gctx).iv as *mut libc::c_void, ptr, arg as size_t);
            FIPS_service_indicator_lock_state();
            if (*c).encrypt != 0
                && RAND_bytes(
                    ((*gctx).iv).offset(arg as isize),
                    ((*gctx).ivlen - arg) as size_t,
                ) == 0
            {
                FIPS_service_indicator_unlock_state();
                return 0 as libc::c_int;
            }
            FIPS_service_indicator_unlock_state();
            (*gctx).iv_gen = 1 as libc::c_int;
            return 1 as libc::c_int;
        }
        19 => {
            if (*gctx).iv_gen == 0 as libc::c_int || (*gctx).key_set == 0 as libc::c_int
            {
                return 0 as libc::c_int;
            }
            CRYPTO_gcm128_setiv(
                &mut (*gctx).gcm,
                &mut (*gctx).ks.ks,
                (*gctx).iv,
                (*gctx).ivlen as size_t,
            );
            if arg <= 0 as libc::c_int || arg > (*gctx).ivlen {
                arg = (*gctx).ivlen;
            }
            OPENSSL_memcpy(
                ptr,
                ((*gctx).iv).offset((*gctx).ivlen as isize).offset(-(arg as isize))
                    as *const libc::c_void,
                arg as size_t,
            );
            let mut ctr: *mut uint8_t = ((*gctx).iv)
                .offset((*gctx).ivlen as isize)
                .offset(-(8 as libc::c_int as isize));
            CRYPTO_store_u64_be(
                ctr as *mut libc::c_void,
                (CRYPTO_load_u64_be(ctr as *const libc::c_void))
                    .wrapping_add(1 as libc::c_int as uint64_t),
            );
            (*gctx).iv_set = 1 as libc::c_int;
            return 1 as libc::c_int;
        }
        24 => {
            if (*gctx).iv_gen == 0 as libc::c_int || (*gctx).key_set == 0 as libc::c_int
                || (*c).encrypt != 0
            {
                return 0 as libc::c_int;
            }
            OPENSSL_memcpy(
                ((*gctx).iv).offset((*gctx).ivlen as isize).offset(-(arg as isize))
                    as *mut libc::c_void,
                ptr,
                arg as size_t,
            );
            CRYPTO_gcm128_setiv(
                &mut (*gctx).gcm,
                &mut (*gctx).ks.ks,
                (*gctx).iv,
                (*gctx).ivlen as size_t,
            );
            (*gctx).iv_set = 1 as libc::c_int;
            return 1 as libc::c_int;
        }
        8 => {
            let mut out: *mut EVP_CIPHER_CTX = ptr as *mut EVP_CIPHER_CTX;
            let mut gctx_out: *mut EVP_AES_GCM_CTX = aes_gcm_from_cipher_ctx(out);
            OPENSSL_memcpy(
                gctx_out as *mut libc::c_void,
                gctx as *const libc::c_void,
                ::core::mem::size_of::<EVP_AES_GCM_CTX>() as libc::c_ulong,
            );
            if (*gctx).iv == ((*c).iv).as_mut_ptr() {
                (*gctx_out).iv = ((*out).iv).as_mut_ptr();
            } else {
                (*gctx_out)
                    .iv = OPENSSL_memdup(
                    (*gctx).iv as *const libc::c_void,
                    (*gctx).ivlen as size_t,
                ) as *mut uint8_t;
                if ((*gctx_out).iv).is_null() {
                    return 0 as libc::c_int;
                }
            }
            return 1 as libc::c_int;
        }
        _ => return -(1 as libc::c_int),
    };
}
unsafe extern "C" fn aes_gcm_cipher(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut gctx: *mut EVP_AES_GCM_CTX = aes_gcm_from_cipher_ctx(ctx);
    if (*gctx).key_set == 0 {
        return -(1 as libc::c_int);
    }
    if (*gctx).iv_set == 0 {
        return -(1 as libc::c_int);
    }
    if len > 2147483647 as libc::c_int as size_t {
        return -(1 as libc::c_int);
    }
    if !in_0.is_null() {
        if out.is_null() {
            if CRYPTO_gcm128_aad(&mut (*gctx).gcm, in_0, len) == 0 {
                return -(1 as libc::c_int);
            }
        } else if (*ctx).encrypt != 0 {
            if ((*gctx).ctr).is_some() {
                if CRYPTO_gcm128_encrypt_ctr32(
                    &mut (*gctx).gcm,
                    &mut (*gctx).ks.ks,
                    in_0,
                    out,
                    len,
                    (*gctx).ctr,
                ) == 0
                {
                    return -(1 as libc::c_int);
                }
            } else if CRYPTO_gcm128_encrypt(
                &mut (*gctx).gcm,
                &mut (*gctx).ks.ks,
                in_0,
                out,
                len,
            ) == 0
            {
                return -(1 as libc::c_int)
            }
        } else if ((*gctx).ctr).is_some() {
            if CRYPTO_gcm128_decrypt_ctr32(
                &mut (*gctx).gcm,
                &mut (*gctx).ks.ks,
                in_0,
                out,
                len,
                (*gctx).ctr,
            ) == 0
            {
                return -(1 as libc::c_int);
            }
        } else if CRYPTO_gcm128_decrypt(
            &mut (*gctx).gcm,
            &mut (*gctx).ks.ks,
            in_0,
            out,
            len,
        ) == 0
        {
            return -(1 as libc::c_int)
        }
        return len as libc::c_int;
    } else {
        if (*ctx).encrypt == 0 {
            if (*gctx).taglen < 0 as libc::c_int
                || CRYPTO_gcm128_finish(
                    &mut (*gctx).gcm,
                    ((*ctx).buf).as_mut_ptr(),
                    (*gctx).taglen as size_t,
                ) == 0
            {
                return -(1 as libc::c_int);
            }
            (*gctx).iv_set = 0 as libc::c_int;
            return 0 as libc::c_int;
        }
        CRYPTO_gcm128_tag(
            &mut (*gctx).gcm,
            ((*ctx).buf).as_mut_ptr(),
            16 as libc::c_int as size_t,
        );
        (*gctx).taglen = 16 as libc::c_int;
        (*gctx).iv_set = 0 as libc::c_int;
        return 0 as libc::c_int;
    };
}
unsafe extern "C" fn aes_xts_init_key(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut key: *const uint8_t,
    mut iv: *const uint8_t,
    mut enc: libc::c_int,
) -> libc::c_int {
    let mut xctx: *mut EVP_AES_XTS_CTX = (*ctx).cipher_data as *mut EVP_AES_XTS_CTX;
    if iv.is_null() && key.is_null() {
        return 1 as libc::c_int;
    }
    if !key.is_null() {
        if OPENSSL_memcmp(
            key as *const libc::c_void,
            key
                .offset(
                    ((*ctx).key_len).wrapping_div(2 as libc::c_int as libc::c_uint)
                        as isize,
                ) as *const libc::c_void,
            ((*ctx).key_len).wrapping_div(2 as libc::c_int as libc::c_uint) as size_t,
        ) == 0 as libc::c_int
        {
            ERR_put_error(
                30 as libc::c_int,
                0 as libc::c_int,
                138 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                    as *const u8 as *const libc::c_char,
                634 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        if enc != 0 {
            AES_set_encrypt_key(
                key,
                ((*ctx).key_len).wrapping_mul(4 as libc::c_int as libc::c_uint),
                &mut (*xctx).ks1.ks,
            );
            (*xctx)
                .xts
                .block1 = Some(
                AES_encrypt
                    as unsafe extern "C" fn(
                        *const uint8_t,
                        *mut uint8_t,
                        *const AES_KEY,
                    ) -> (),
            );
        } else {
            AES_set_decrypt_key(
                key,
                ((*ctx).key_len).wrapping_mul(4 as libc::c_int as libc::c_uint),
                &mut (*xctx).ks1.ks,
            );
            (*xctx)
                .xts
                .block1 = Some(
                AES_decrypt
                    as unsafe extern "C" fn(
                        *const uint8_t,
                        *mut uint8_t,
                        *const AES_KEY,
                    ) -> (),
            );
        }
        AES_set_encrypt_key(
            key
                .offset(
                    ((*ctx).key_len).wrapping_div(2 as libc::c_int as libc::c_uint)
                        as isize,
                ),
            ((*ctx).key_len).wrapping_mul(4 as libc::c_int as libc::c_uint),
            &mut (*xctx).ks2.ks,
        );
        (*xctx)
            .xts
            .block2 = Some(
            AES_encrypt
                as unsafe extern "C" fn(
                    *const uint8_t,
                    *mut uint8_t,
                    *const AES_KEY,
                ) -> (),
        );
        (*xctx).xts.key1 = &mut (*xctx).ks1.ks;
    }
    if !iv.is_null() {
        (*xctx).xts.key2 = &mut (*xctx).ks2.ks;
        OPENSSL_memcpy(
            ((*ctx).iv).as_mut_ptr() as *mut libc::c_void,
            iv as *const libc::c_void,
            16 as libc::c_int as size_t,
        );
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn aes_xts_cipher(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut xctx: *mut EVP_AES_XTS_CTX = (*ctx).cipher_data as *mut EVP_AES_XTS_CTX;
    if ((*xctx).xts.key1).is_null() || ((*xctx).xts.key2).is_null() || out.is_null()
        || in_0.is_null() || len < 16 as libc::c_int as size_t
    {
        return 0 as libc::c_int;
    }
    if len > (((1 as libc::c_int) << 20 as libc::c_int) * 16 as libc::c_int) as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            139 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            673 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if hwaes_xts_available() != 0 {
        return aes_hw_xts_cipher(
            in_0,
            out,
            len,
            (*xctx).xts.key1,
            (*xctx).xts.key2,
            ((*ctx).iv).as_mut_ptr() as *const uint8_t,
            (*ctx).encrypt,
        )
    } else {
        return CRYPTO_xts128_encrypt(
            &mut (*xctx).xts,
            ((*ctx).iv).as_mut_ptr() as *const uint8_t,
            in_0,
            out,
            len,
            (*ctx).encrypt,
        ) as libc::c_int
    };
}
unsafe extern "C" fn aes_xts_ctrl(
    mut c: *mut EVP_CIPHER_CTX,
    mut type_0: libc::c_int,
    mut arg: libc::c_int,
    mut ptr: *mut libc::c_void,
) -> libc::c_int {
    let mut xctx: *mut EVP_AES_XTS_CTX = (*c).cipher_data as *mut EVP_AES_XTS_CTX;
    if type_0 == 0x8 as libc::c_int {
        let mut out: *mut EVP_CIPHER_CTX = ptr as *mut EVP_CIPHER_CTX;
        let mut xctx_out: *mut EVP_AES_XTS_CTX = (*out).cipher_data
            as *mut EVP_AES_XTS_CTX;
        if !((*xctx).xts.key1).is_null() {
            if (*xctx).xts.key1 != &mut (*xctx).ks1.ks as *mut AES_KEY {
                return 0 as libc::c_int;
            }
            (*xctx_out).xts.key1 = &mut (*xctx_out).ks1.ks;
        }
        if !((*xctx).xts.key2).is_null() {
            if (*xctx).xts.key2 != &mut (*xctx).ks2.ks as *mut AES_KEY {
                return 0 as libc::c_int;
            }
            (*xctx_out).xts.key2 = &mut (*xctx_out).ks2.ks;
        }
        return 1 as libc::c_int;
    } else if type_0 != 0 as libc::c_int {
        return -(1 as libc::c_int)
    }
    (*xctx).xts.key1 = 0 as *mut AES_KEY;
    (*xctx).xts.key2 = 0 as *mut AES_KEY;
    return 1 as libc::c_int;
}
unsafe extern "C" fn aes_wrap_init_key(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut key: *const uint8_t,
    mut iv: *const uint8_t,
    mut enc: libc::c_int,
) -> libc::c_int {
    let mut wctx: *mut EVP_AES_WRAP_CTX = (*ctx).cipher_data as *mut EVP_AES_WRAP_CTX;
    if iv.is_null() && key.is_null() {
        return 1 as libc::c_int;
    }
    if !key.is_null() {
        if (*ctx).encrypt != 0 {
            AES_set_encrypt_key(
                key,
                (EVP_CIPHER_CTX_key_length(ctx))
                    .wrapping_mul(8 as libc::c_int as libc::c_uint),
                &mut (*wctx).ks.ks,
            );
        } else {
            AES_set_decrypt_key(
                key,
                (EVP_CIPHER_CTX_key_length(ctx))
                    .wrapping_mul(8 as libc::c_int as libc::c_uint),
                &mut (*wctx).ks.ks,
            );
        }
        if iv.is_null() {
            (*wctx).iv = 0 as *const uint8_t;
        }
    }
    if !iv.is_null() {
        OPENSSL_memcpy(
            ((*ctx).iv).as_mut_ptr() as *mut libc::c_void,
            iv as *const libc::c_void,
            (*(*ctx).cipher).iv_len as size_t,
        );
        (*wctx).iv = ((*ctx).iv).as_mut_ptr();
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn aes_wrap_cipher(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut inlen: size_t,
) -> libc::c_int {
    let mut wctx: *mut EVP_AES_WRAP_CTX = (*ctx).cipher_data as *mut EVP_AES_WRAP_CTX;
    if in_0.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0;
    FIPS_service_indicator_lock_state();
    if (*ctx).encrypt != 0 {
        ret = AES_wrap_key(&mut (*wctx).ks.ks, (*wctx).iv, out, in_0, inlen);
    } else {
        ret = AES_unwrap_key(&mut (*wctx).ks.ks, (*wctx).iv, out, in_0, inlen);
    }
    FIPS_service_indicator_unlock_state();
    return ret;
}
static mut EVP_aes_128_cbc_storage: EVP_CIPHER = evp_cipher_st {
    nid: 0,
    block_size: 0,
    key_len: 0,
    iv_len: 0,
    ctx_size: 0,
    flags: 0,
    init: None,
    cipher: None,
    cleanup: None,
    ctrl: None,
};
unsafe extern "C" fn EVP_aes_128_cbc_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aes_128_cbc_once;
}
static mut EVP_aes_128_cbc_once: CRYPTO_once_t = 0 as libc::c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_128_cbc() -> *const EVP_CIPHER {
    CRYPTO_once(
        EVP_aes_128_cbc_once_bss_get(),
        Some(EVP_aes_128_cbc_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aes_128_cbc_storage_bss_get() as *const EVP_CIPHER;
}
unsafe extern "C" fn EVP_aes_128_cbc_init() {
    EVP_aes_128_cbc_do_init(EVP_aes_128_cbc_storage_bss_get());
}
unsafe extern "C" fn EVP_aes_128_cbc_do_init(mut out: *mut EVP_CIPHER) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_CIPHER>() as libc::c_ulong,
    );
    (*out).nid = 419 as libc::c_int;
    (*out).block_size = 16 as libc::c_int as libc::c_uint;
    (*out).key_len = 16 as libc::c_int as libc::c_uint;
    (*out).iv_len = 16 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<EVP_AES_KEY>() as libc::c_ulong
        as libc::c_uint;
    (*out).flags = 0x2 as libc::c_int as uint32_t;
    (*out)
        .init = Some(
        aes_init_key
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *const uint8_t,
                *const uint8_t,
                libc::c_int,
            ) -> libc::c_int,
    );
    (*out)
        .cipher = Some(
        aes_cbc_cipher
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *mut uint8_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
}
unsafe extern "C" fn EVP_aes_128_cbc_storage_bss_get() -> *mut EVP_CIPHER {
    return &mut EVP_aes_128_cbc_storage;
}
static mut EVP_aes_128_ctr_once: CRYPTO_once_t = 0 as libc::c_int;
static mut EVP_aes_128_ctr_storage: EVP_CIPHER = evp_cipher_st {
    nid: 0,
    block_size: 0,
    key_len: 0,
    iv_len: 0,
    ctx_size: 0,
    flags: 0,
    init: None,
    cipher: None,
    cleanup: None,
    ctrl: None,
};
unsafe extern "C" fn EVP_aes_128_ctr_storage_bss_get() -> *mut EVP_CIPHER {
    return &mut EVP_aes_128_ctr_storage;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_128_ctr() -> *const EVP_CIPHER {
    CRYPTO_once(
        EVP_aes_128_ctr_once_bss_get(),
        Some(EVP_aes_128_ctr_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aes_128_ctr_storage_bss_get() as *const EVP_CIPHER;
}
unsafe extern "C" fn EVP_aes_128_ctr_init() {
    EVP_aes_128_ctr_do_init(EVP_aes_128_ctr_storage_bss_get());
}
unsafe extern "C" fn EVP_aes_128_ctr_do_init(mut out: *mut EVP_CIPHER) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_CIPHER>() as libc::c_ulong,
    );
    (*out).nid = 904 as libc::c_int;
    (*out).block_size = 1 as libc::c_int as libc::c_uint;
    (*out).key_len = 16 as libc::c_int as libc::c_uint;
    (*out).iv_len = 16 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<EVP_AES_KEY>() as libc::c_ulong
        as libc::c_uint;
    (*out).flags = 0x5 as libc::c_int as uint32_t;
    (*out)
        .init = Some(
        aes_init_key
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *const uint8_t,
                *const uint8_t,
                libc::c_int,
            ) -> libc::c_int,
    );
    (*out)
        .cipher = Some(
        aes_ctr_cipher
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *mut uint8_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
}
unsafe extern "C" fn EVP_aes_128_ctr_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aes_128_ctr_once;
}
unsafe extern "C" fn aes_128_ecb_generic_do_init(mut out: *mut EVP_CIPHER) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_CIPHER>() as libc::c_ulong,
    );
    (*out).nid = 418 as libc::c_int;
    (*out).block_size = 16 as libc::c_int as libc::c_uint;
    (*out).key_len = 16 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<EVP_AES_KEY>() as libc::c_ulong
        as libc::c_uint;
    (*out).flags = 0x1 as libc::c_int as uint32_t;
    (*out)
        .init = Some(
        aes_init_key
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *const uint8_t,
                *const uint8_t,
                libc::c_int,
            ) -> libc::c_int,
    );
    (*out)
        .cipher = Some(
        aes_ecb_cipher
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *mut uint8_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
}
unsafe extern "C" fn aes_128_ecb_generic_init() {
    aes_128_ecb_generic_do_init(aes_128_ecb_generic_storage_bss_get());
}
unsafe extern "C" fn aes_128_ecb_generic() -> *const EVP_CIPHER {
    CRYPTO_once(
        aes_128_ecb_generic_once_bss_get(),
        Some(aes_128_ecb_generic_init as unsafe extern "C" fn() -> ()),
    );
    return aes_128_ecb_generic_storage_bss_get() as *const EVP_CIPHER;
}
static mut aes_128_ecb_generic_storage: EVP_CIPHER = evp_cipher_st {
    nid: 0,
    block_size: 0,
    key_len: 0,
    iv_len: 0,
    ctx_size: 0,
    flags: 0,
    init: None,
    cipher: None,
    cleanup: None,
    ctrl: None,
};
unsafe extern "C" fn aes_128_ecb_generic_storage_bss_get() -> *mut EVP_CIPHER {
    return &mut aes_128_ecb_generic_storage;
}
static mut aes_128_ecb_generic_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn aes_128_ecb_generic_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut aes_128_ecb_generic_once;
}
unsafe extern "C" fn EVP_aes_128_ofb_do_init(mut out: *mut EVP_CIPHER) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_CIPHER>() as libc::c_ulong,
    );
    (*out).nid = 420 as libc::c_int;
    (*out).block_size = 1 as libc::c_int as libc::c_uint;
    (*out).key_len = 16 as libc::c_int as libc::c_uint;
    (*out).iv_len = 16 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<EVP_AES_KEY>() as libc::c_ulong
        as libc::c_uint;
    (*out).flags = 0x4 as libc::c_int as uint32_t;
    (*out)
        .init = Some(
        aes_init_key
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *const uint8_t,
                *const uint8_t,
                libc::c_int,
            ) -> libc::c_int,
    );
    (*out)
        .cipher = Some(
        aes_ofb_cipher
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *mut uint8_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
}
static mut EVP_aes_128_ofb_once: CRYPTO_once_t = 0 as libc::c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_128_ofb() -> *const EVP_CIPHER {
    CRYPTO_once(
        EVP_aes_128_ofb_once_bss_get(),
        Some(EVP_aes_128_ofb_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aes_128_ofb_storage_bss_get() as *const EVP_CIPHER;
}
unsafe extern "C" fn EVP_aes_128_ofb_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aes_128_ofb_once;
}
unsafe extern "C" fn EVP_aes_128_ofb_storage_bss_get() -> *mut EVP_CIPHER {
    return &mut EVP_aes_128_ofb_storage;
}
static mut EVP_aes_128_ofb_storage: EVP_CIPHER = evp_cipher_st {
    nid: 0,
    block_size: 0,
    key_len: 0,
    iv_len: 0,
    ctx_size: 0,
    flags: 0,
    init: None,
    cipher: None,
    cleanup: None,
    ctrl: None,
};
unsafe extern "C" fn EVP_aes_128_ofb_init() {
    EVP_aes_128_ofb_do_init(EVP_aes_128_ofb_storage_bss_get());
}
static mut EVP_aes_128_gcm_once: CRYPTO_once_t = 0 as libc::c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_128_gcm() -> *const EVP_CIPHER {
    CRYPTO_once(
        EVP_aes_128_gcm_once_bss_get(),
        Some(EVP_aes_128_gcm_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aes_128_gcm_storage_bss_get() as *const EVP_CIPHER;
}
unsafe extern "C" fn EVP_aes_128_gcm_storage_bss_get() -> *mut EVP_CIPHER {
    return &mut EVP_aes_128_gcm_storage;
}
static mut EVP_aes_128_gcm_storage: EVP_CIPHER = evp_cipher_st {
    nid: 0,
    block_size: 0,
    key_len: 0,
    iv_len: 0,
    ctx_size: 0,
    flags: 0,
    init: None,
    cipher: None,
    cleanup: None,
    ctrl: None,
};
unsafe extern "C" fn EVP_aes_128_gcm_init() {
    EVP_aes_128_gcm_do_init(EVP_aes_128_gcm_storage_bss_get());
}
unsafe extern "C" fn EVP_aes_128_gcm_do_init(mut out: *mut EVP_CIPHER) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_CIPHER>() as libc::c_ulong,
    );
    (*out).nid = 895 as libc::c_int;
    (*out).block_size = 1 as libc::c_int as libc::c_uint;
    (*out).key_len = 16 as libc::c_int as libc::c_uint;
    (*out).iv_len = 12 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = (::core::mem::size_of::<EVP_AES_GCM_CTX>() as libc::c_ulong)
        .wrapping_add(8 as libc::c_int as libc::c_ulong) as libc::c_uint;
    (*out)
        .flags = (0x6 as libc::c_int | 0x100 as libc::c_int | 0x1000 as libc::c_int
        | 0x400 as libc::c_int | 0x80 as libc::c_int | 0x200 as libc::c_int
        | 0x800 as libc::c_int) as uint32_t;
    (*out)
        .init = Some(
        aes_gcm_init_key
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *const uint8_t,
                *const uint8_t,
                libc::c_int,
            ) -> libc::c_int,
    );
    (*out)
        .cipher = Some(
        aes_gcm_cipher
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *mut uint8_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .cleanup = Some(
        aes_gcm_cleanup as unsafe extern "C" fn(*mut EVP_CIPHER_CTX) -> (),
    );
    (*out)
        .ctrl = Some(
        aes_gcm_ctrl
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                libc::c_int,
                libc::c_int,
                *mut libc::c_void,
            ) -> libc::c_int,
    );
}
unsafe extern "C" fn EVP_aes_128_gcm_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aes_128_gcm_once;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_192_cbc() -> *const EVP_CIPHER {
    CRYPTO_once(
        EVP_aes_192_cbc_once_bss_get(),
        Some(EVP_aes_192_cbc_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aes_192_cbc_storage_bss_get() as *const EVP_CIPHER;
}
unsafe extern "C" fn EVP_aes_192_cbc_storage_bss_get() -> *mut EVP_CIPHER {
    return &mut EVP_aes_192_cbc_storage;
}
static mut EVP_aes_192_cbc_storage: EVP_CIPHER = evp_cipher_st {
    nid: 0,
    block_size: 0,
    key_len: 0,
    iv_len: 0,
    ctx_size: 0,
    flags: 0,
    init: None,
    cipher: None,
    cleanup: None,
    ctrl: None,
};
unsafe extern "C" fn EVP_aes_192_cbc_init() {
    EVP_aes_192_cbc_do_init(EVP_aes_192_cbc_storage_bss_get());
}
unsafe extern "C" fn EVP_aes_192_cbc_do_init(mut out: *mut EVP_CIPHER) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_CIPHER>() as libc::c_ulong,
    );
    (*out).nid = 423 as libc::c_int;
    (*out).block_size = 16 as libc::c_int as libc::c_uint;
    (*out).key_len = 24 as libc::c_int as libc::c_uint;
    (*out).iv_len = 16 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<EVP_AES_KEY>() as libc::c_ulong
        as libc::c_uint;
    (*out).flags = 0x2 as libc::c_int as uint32_t;
    (*out)
        .init = Some(
        aes_init_key
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *const uint8_t,
                *const uint8_t,
                libc::c_int,
            ) -> libc::c_int,
    );
    (*out)
        .cipher = Some(
        aes_cbc_cipher
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *mut uint8_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
}
unsafe extern "C" fn EVP_aes_192_cbc_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aes_192_cbc_once;
}
static mut EVP_aes_192_cbc_once: CRYPTO_once_t = 0 as libc::c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_192_ctr() -> *const EVP_CIPHER {
    CRYPTO_once(
        EVP_aes_192_ctr_once_bss_get(),
        Some(EVP_aes_192_ctr_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aes_192_ctr_storage_bss_get() as *const EVP_CIPHER;
}
unsafe extern "C" fn EVP_aes_192_ctr_init() {
    EVP_aes_192_ctr_do_init(EVP_aes_192_ctr_storage_bss_get());
}
static mut EVP_aes_192_ctr_storage: EVP_CIPHER = evp_cipher_st {
    nid: 0,
    block_size: 0,
    key_len: 0,
    iv_len: 0,
    ctx_size: 0,
    flags: 0,
    init: None,
    cipher: None,
    cleanup: None,
    ctrl: None,
};
unsafe extern "C" fn EVP_aes_192_ctr_do_init(mut out: *mut EVP_CIPHER) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_CIPHER>() as libc::c_ulong,
    );
    (*out).nid = 905 as libc::c_int;
    (*out).block_size = 1 as libc::c_int as libc::c_uint;
    (*out).key_len = 24 as libc::c_int as libc::c_uint;
    (*out).iv_len = 16 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<EVP_AES_KEY>() as libc::c_ulong
        as libc::c_uint;
    (*out).flags = 0x5 as libc::c_int as uint32_t;
    (*out)
        .init = Some(
        aes_init_key
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *const uint8_t,
                *const uint8_t,
                libc::c_int,
            ) -> libc::c_int,
    );
    (*out)
        .cipher = Some(
        aes_ctr_cipher
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *mut uint8_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
}
static mut EVP_aes_192_ctr_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EVP_aes_192_ctr_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aes_192_ctr_once;
}
unsafe extern "C" fn EVP_aes_192_ctr_storage_bss_get() -> *mut EVP_CIPHER {
    return &mut EVP_aes_192_ctr_storage;
}
static mut aes_192_ecb_generic_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn aes_192_ecb_generic_storage_bss_get() -> *mut EVP_CIPHER {
    return &mut aes_192_ecb_generic_storage;
}
unsafe extern "C" fn aes_192_ecb_generic_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut aes_192_ecb_generic_once;
}
unsafe extern "C" fn aes_192_ecb_generic_do_init(mut out: *mut EVP_CIPHER) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_CIPHER>() as libc::c_ulong,
    );
    (*out).nid = 422 as libc::c_int;
    (*out).block_size = 16 as libc::c_int as libc::c_uint;
    (*out).key_len = 24 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<EVP_AES_KEY>() as libc::c_ulong
        as libc::c_uint;
    (*out).flags = 0x1 as libc::c_int as uint32_t;
    (*out)
        .init = Some(
        aes_init_key
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *const uint8_t,
                *const uint8_t,
                libc::c_int,
            ) -> libc::c_int,
    );
    (*out)
        .cipher = Some(
        aes_ecb_cipher
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *mut uint8_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
}
unsafe extern "C" fn aes_192_ecb_generic_init() {
    aes_192_ecb_generic_do_init(aes_192_ecb_generic_storage_bss_get());
}
unsafe extern "C" fn aes_192_ecb_generic() -> *const EVP_CIPHER {
    CRYPTO_once(
        aes_192_ecb_generic_once_bss_get(),
        Some(aes_192_ecb_generic_init as unsafe extern "C" fn() -> ()),
    );
    return aes_192_ecb_generic_storage_bss_get() as *const EVP_CIPHER;
}
static mut aes_192_ecb_generic_storage: EVP_CIPHER = evp_cipher_st {
    nid: 0,
    block_size: 0,
    key_len: 0,
    iv_len: 0,
    ctx_size: 0,
    flags: 0,
    init: None,
    cipher: None,
    cleanup: None,
    ctrl: None,
};
unsafe extern "C" fn EVP_aes_192_ofb_init() {
    EVP_aes_192_ofb_do_init(EVP_aes_192_ofb_storage_bss_get());
}
static mut EVP_aes_192_ofb_storage: EVP_CIPHER = evp_cipher_st {
    nid: 0,
    block_size: 0,
    key_len: 0,
    iv_len: 0,
    ctx_size: 0,
    flags: 0,
    init: None,
    cipher: None,
    cleanup: None,
    ctrl: None,
};
static mut EVP_aes_192_ofb_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EVP_aes_192_ofb_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aes_192_ofb_once;
}
unsafe extern "C" fn EVP_aes_192_ofb_storage_bss_get() -> *mut EVP_CIPHER {
    return &mut EVP_aes_192_ofb_storage;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_192_ofb() -> *const EVP_CIPHER {
    CRYPTO_once(
        EVP_aes_192_ofb_once_bss_get(),
        Some(EVP_aes_192_ofb_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aes_192_ofb_storage_bss_get() as *const EVP_CIPHER;
}
unsafe extern "C" fn EVP_aes_192_ofb_do_init(mut out: *mut EVP_CIPHER) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_CIPHER>() as libc::c_ulong,
    );
    (*out).nid = 424 as libc::c_int;
    (*out).block_size = 1 as libc::c_int as libc::c_uint;
    (*out).key_len = 24 as libc::c_int as libc::c_uint;
    (*out).iv_len = 16 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<EVP_AES_KEY>() as libc::c_ulong
        as libc::c_uint;
    (*out).flags = 0x4 as libc::c_int as uint32_t;
    (*out)
        .init = Some(
        aes_init_key
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *const uint8_t,
                *const uint8_t,
                libc::c_int,
            ) -> libc::c_int,
    );
    (*out)
        .cipher = Some(
        aes_ofb_cipher
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *mut uint8_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
}
unsafe extern "C" fn EVP_aes_192_gcm_init() {
    EVP_aes_192_gcm_do_init(EVP_aes_192_gcm_storage_bss_get());
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_192_gcm() -> *const EVP_CIPHER {
    CRYPTO_once(
        EVP_aes_192_gcm_once_bss_get(),
        Some(EVP_aes_192_gcm_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aes_192_gcm_storage_bss_get() as *const EVP_CIPHER;
}
unsafe extern "C" fn EVP_aes_192_gcm_storage_bss_get() -> *mut EVP_CIPHER {
    return &mut EVP_aes_192_gcm_storage;
}
static mut EVP_aes_192_gcm_storage: EVP_CIPHER = evp_cipher_st {
    nid: 0,
    block_size: 0,
    key_len: 0,
    iv_len: 0,
    ctx_size: 0,
    flags: 0,
    init: None,
    cipher: None,
    cleanup: None,
    ctrl: None,
};
unsafe extern "C" fn EVP_aes_192_gcm_do_init(mut out: *mut EVP_CIPHER) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_CIPHER>() as libc::c_ulong,
    );
    (*out).nid = 898 as libc::c_int;
    (*out).block_size = 1 as libc::c_int as libc::c_uint;
    (*out).key_len = 24 as libc::c_int as libc::c_uint;
    (*out).iv_len = 12 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = (::core::mem::size_of::<EVP_AES_GCM_CTX>() as libc::c_ulong)
        .wrapping_add(8 as libc::c_int as libc::c_ulong) as libc::c_uint;
    (*out)
        .flags = (0x6 as libc::c_int | 0x100 as libc::c_int | 0x1000 as libc::c_int
        | 0x400 as libc::c_int | 0x80 as libc::c_int | 0x200 as libc::c_int
        | 0x800 as libc::c_int) as uint32_t;
    (*out)
        .init = Some(
        aes_gcm_init_key
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *const uint8_t,
                *const uint8_t,
                libc::c_int,
            ) -> libc::c_int,
    );
    (*out)
        .cipher = Some(
        aes_gcm_cipher
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *mut uint8_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .cleanup = Some(
        aes_gcm_cleanup as unsafe extern "C" fn(*mut EVP_CIPHER_CTX) -> (),
    );
    (*out)
        .ctrl = Some(
        aes_gcm_ctrl
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                libc::c_int,
                libc::c_int,
                *mut libc::c_void,
            ) -> libc::c_int,
    );
}
unsafe extern "C" fn EVP_aes_192_gcm_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aes_192_gcm_once;
}
static mut EVP_aes_192_gcm_once: CRYPTO_once_t = 0 as libc::c_int;
static mut EVP_aes_256_cbc_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EVP_aes_256_cbc_storage_bss_get() -> *mut EVP_CIPHER {
    return &mut EVP_aes_256_cbc_storage;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_256_cbc() -> *const EVP_CIPHER {
    CRYPTO_once(
        EVP_aes_256_cbc_once_bss_get(),
        Some(EVP_aes_256_cbc_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aes_256_cbc_storage_bss_get() as *const EVP_CIPHER;
}
static mut EVP_aes_256_cbc_storage: EVP_CIPHER = evp_cipher_st {
    nid: 0,
    block_size: 0,
    key_len: 0,
    iv_len: 0,
    ctx_size: 0,
    flags: 0,
    init: None,
    cipher: None,
    cleanup: None,
    ctrl: None,
};
unsafe extern "C" fn EVP_aes_256_cbc_init() {
    EVP_aes_256_cbc_do_init(EVP_aes_256_cbc_storage_bss_get());
}
unsafe extern "C" fn EVP_aes_256_cbc_do_init(mut out: *mut EVP_CIPHER) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_CIPHER>() as libc::c_ulong,
    );
    (*out).nid = 427 as libc::c_int;
    (*out).block_size = 16 as libc::c_int as libc::c_uint;
    (*out).key_len = 32 as libc::c_int as libc::c_uint;
    (*out).iv_len = 16 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<EVP_AES_KEY>() as libc::c_ulong
        as libc::c_uint;
    (*out).flags = 0x2 as libc::c_int as uint32_t;
    (*out)
        .init = Some(
        aes_init_key
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *const uint8_t,
                *const uint8_t,
                libc::c_int,
            ) -> libc::c_int,
    );
    (*out)
        .cipher = Some(
        aes_cbc_cipher
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *mut uint8_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
}
unsafe extern "C" fn EVP_aes_256_cbc_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aes_256_cbc_once;
}
unsafe extern "C" fn EVP_aes_256_ctr_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aes_256_ctr_once;
}
unsafe extern "C" fn EVP_aes_256_ctr_storage_bss_get() -> *mut EVP_CIPHER {
    return &mut EVP_aes_256_ctr_storage;
}
static mut EVP_aes_256_ctr_storage: EVP_CIPHER = evp_cipher_st {
    nid: 0,
    block_size: 0,
    key_len: 0,
    iv_len: 0,
    ctx_size: 0,
    flags: 0,
    init: None,
    cipher: None,
    cleanup: None,
    ctrl: None,
};
static mut EVP_aes_256_ctr_once: CRYPTO_once_t = 0 as libc::c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_256_ctr() -> *const EVP_CIPHER {
    CRYPTO_once(
        EVP_aes_256_ctr_once_bss_get(),
        Some(EVP_aes_256_ctr_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aes_256_ctr_storage_bss_get() as *const EVP_CIPHER;
}
unsafe extern "C" fn EVP_aes_256_ctr_init() {
    EVP_aes_256_ctr_do_init(EVP_aes_256_ctr_storage_bss_get());
}
unsafe extern "C" fn EVP_aes_256_ctr_do_init(mut out: *mut EVP_CIPHER) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_CIPHER>() as libc::c_ulong,
    );
    (*out).nid = 906 as libc::c_int;
    (*out).block_size = 1 as libc::c_int as libc::c_uint;
    (*out).key_len = 32 as libc::c_int as libc::c_uint;
    (*out).iv_len = 16 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<EVP_AES_KEY>() as libc::c_ulong
        as libc::c_uint;
    (*out).flags = 0x5 as libc::c_int as uint32_t;
    (*out)
        .init = Some(
        aes_init_key
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *const uint8_t,
                *const uint8_t,
                libc::c_int,
            ) -> libc::c_int,
    );
    (*out)
        .cipher = Some(
        aes_ctr_cipher
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *mut uint8_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
}
unsafe extern "C" fn aes_256_ecb_generic_init() {
    aes_256_ecb_generic_do_init(aes_256_ecb_generic_storage_bss_get());
}
unsafe extern "C" fn aes_256_ecb_generic() -> *const EVP_CIPHER {
    CRYPTO_once(
        aes_256_ecb_generic_once_bss_get(),
        Some(aes_256_ecb_generic_init as unsafe extern "C" fn() -> ()),
    );
    return aes_256_ecb_generic_storage_bss_get() as *const EVP_CIPHER;
}
unsafe extern "C" fn aes_256_ecb_generic_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut aes_256_ecb_generic_once;
}
static mut aes_256_ecb_generic_storage: EVP_CIPHER = evp_cipher_st {
    nid: 0,
    block_size: 0,
    key_len: 0,
    iv_len: 0,
    ctx_size: 0,
    flags: 0,
    init: None,
    cipher: None,
    cleanup: None,
    ctrl: None,
};
unsafe extern "C" fn aes_256_ecb_generic_do_init(mut out: *mut EVP_CIPHER) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_CIPHER>() as libc::c_ulong,
    );
    (*out).nid = 426 as libc::c_int;
    (*out).block_size = 16 as libc::c_int as libc::c_uint;
    (*out).key_len = 32 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<EVP_AES_KEY>() as libc::c_ulong
        as libc::c_uint;
    (*out).flags = 0x1 as libc::c_int as uint32_t;
    (*out)
        .init = Some(
        aes_init_key
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *const uint8_t,
                *const uint8_t,
                libc::c_int,
            ) -> libc::c_int,
    );
    (*out)
        .cipher = Some(
        aes_ecb_cipher
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *mut uint8_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
}
unsafe extern "C" fn aes_256_ecb_generic_storage_bss_get() -> *mut EVP_CIPHER {
    return &mut aes_256_ecb_generic_storage;
}
static mut aes_256_ecb_generic_once: CRYPTO_once_t = 0 as libc::c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_256_ofb() -> *const EVP_CIPHER {
    CRYPTO_once(
        EVP_aes_256_ofb_once_bss_get(),
        Some(EVP_aes_256_ofb_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aes_256_ofb_storage_bss_get() as *const EVP_CIPHER;
}
unsafe extern "C" fn EVP_aes_256_ofb_storage_bss_get() -> *mut EVP_CIPHER {
    return &mut EVP_aes_256_ofb_storage;
}
unsafe extern "C" fn EVP_aes_256_ofb_do_init(mut out: *mut EVP_CIPHER) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_CIPHER>() as libc::c_ulong,
    );
    (*out).nid = 428 as libc::c_int;
    (*out).block_size = 1 as libc::c_int as libc::c_uint;
    (*out).key_len = 32 as libc::c_int as libc::c_uint;
    (*out).iv_len = 16 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<EVP_AES_KEY>() as libc::c_ulong
        as libc::c_uint;
    (*out).flags = 0x4 as libc::c_int as uint32_t;
    (*out)
        .init = Some(
        aes_init_key
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *const uint8_t,
                *const uint8_t,
                libc::c_int,
            ) -> libc::c_int,
    );
    (*out)
        .cipher = Some(
        aes_ofb_cipher
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *mut uint8_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
}
static mut EVP_aes_256_ofb_storage: EVP_CIPHER = evp_cipher_st {
    nid: 0,
    block_size: 0,
    key_len: 0,
    iv_len: 0,
    ctx_size: 0,
    flags: 0,
    init: None,
    cipher: None,
    cleanup: None,
    ctrl: None,
};
unsafe extern "C" fn EVP_aes_256_ofb_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aes_256_ofb_once;
}
unsafe extern "C" fn EVP_aes_256_ofb_init() {
    EVP_aes_256_ofb_do_init(EVP_aes_256_ofb_storage_bss_get());
}
static mut EVP_aes_256_ofb_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EVP_aes_256_wrap_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aes_256_wrap_once;
}
unsafe extern "C" fn EVP_aes_256_wrap_init() {
    EVP_aes_256_wrap_do_init(EVP_aes_256_wrap_storage_bss_get());
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_256_wrap() -> *const EVP_CIPHER {
    CRYPTO_once(
        EVP_aes_256_wrap_once_bss_get(),
        Some(EVP_aes_256_wrap_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aes_256_wrap_storage_bss_get() as *const EVP_CIPHER;
}
unsafe extern "C" fn EVP_aes_256_wrap_storage_bss_get() -> *mut EVP_CIPHER {
    return &mut EVP_aes_256_wrap_storage;
}
static mut EVP_aes_256_wrap_storage: EVP_CIPHER = evp_cipher_st {
    nid: 0,
    block_size: 0,
    key_len: 0,
    iv_len: 0,
    ctx_size: 0,
    flags: 0,
    init: None,
    cipher: None,
    cleanup: None,
    ctrl: None,
};
unsafe extern "C" fn EVP_aes_256_wrap_do_init(mut out: *mut EVP_CIPHER) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_CIPHER>() as libc::c_ulong,
    );
    (*out).nid = 790 as libc::c_int;
    (*out).block_size = 8 as libc::c_int as libc::c_uint;
    (*out).key_len = 32 as libc::c_int as libc::c_uint;
    (*out).iv_len = 8 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<EVP_AES_WRAP_CTX>() as libc::c_ulong
        as libc::c_uint;
    (*out)
        .flags = (0xa as libc::c_int | 0x100 as libc::c_int | 0x400 as libc::c_int
        | 0x80 as libc::c_int) as uint32_t;
    (*out)
        .init = Some(
        aes_wrap_init_key
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *const uint8_t,
                *const uint8_t,
                libc::c_int,
            ) -> libc::c_int,
    );
    (*out)
        .cipher = Some(
        aes_wrap_cipher
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *mut uint8_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
}
static mut EVP_aes_256_wrap_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EVP_aes_256_gcm_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aes_256_gcm_once;
}
static mut EVP_aes_256_gcm_once: CRYPTO_once_t = 0 as libc::c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_256_gcm() -> *const EVP_CIPHER {
    CRYPTO_once(
        EVP_aes_256_gcm_once_bss_get(),
        Some(EVP_aes_256_gcm_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aes_256_gcm_storage_bss_get() as *const EVP_CIPHER;
}
unsafe extern "C" fn EVP_aes_256_gcm_storage_bss_get() -> *mut EVP_CIPHER {
    return &mut EVP_aes_256_gcm_storage;
}
static mut EVP_aes_256_gcm_storage: EVP_CIPHER = evp_cipher_st {
    nid: 0,
    block_size: 0,
    key_len: 0,
    iv_len: 0,
    ctx_size: 0,
    flags: 0,
    init: None,
    cipher: None,
    cleanup: None,
    ctrl: None,
};
unsafe extern "C" fn EVP_aes_256_gcm_init() {
    EVP_aes_256_gcm_do_init(EVP_aes_256_gcm_storage_bss_get());
}
unsafe extern "C" fn EVP_aes_256_gcm_do_init(mut out: *mut EVP_CIPHER) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_CIPHER>() as libc::c_ulong,
    );
    (*out).nid = 901 as libc::c_int;
    (*out).block_size = 1 as libc::c_int as libc::c_uint;
    (*out).key_len = 32 as libc::c_int as libc::c_uint;
    (*out).iv_len = 12 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = (::core::mem::size_of::<EVP_AES_GCM_CTX>() as libc::c_ulong)
        .wrapping_add(8 as libc::c_int as libc::c_ulong) as libc::c_uint;
    (*out)
        .flags = (0x6 as libc::c_int | 0x100 as libc::c_int | 0x1000 as libc::c_int
        | 0x400 as libc::c_int | 0x80 as libc::c_int | 0x200 as libc::c_int
        | 0x800 as libc::c_int) as uint32_t;
    (*out)
        .init = Some(
        aes_gcm_init_key
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *const uint8_t,
                *const uint8_t,
                libc::c_int,
            ) -> libc::c_int,
    );
    (*out)
        .cipher = Some(
        aes_gcm_cipher
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *mut uint8_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .cleanup = Some(
        aes_gcm_cleanup as unsafe extern "C" fn(*mut EVP_CIPHER_CTX) -> (),
    );
    (*out)
        .ctrl = Some(
        aes_gcm_ctrl
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                libc::c_int,
                libc::c_int,
                *mut libc::c_void,
            ) -> libc::c_int,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_256_xts() -> *const EVP_CIPHER {
    CRYPTO_once(
        EVP_aes_256_xts_once_bss_get(),
        Some(EVP_aes_256_xts_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aes_256_xts_storage_bss_get() as *const EVP_CIPHER;
}
unsafe extern "C" fn EVP_aes_256_xts_init() {
    EVP_aes_256_xts_do_init(EVP_aes_256_xts_storage_bss_get());
}
static mut EVP_aes_256_xts_storage: EVP_CIPHER = evp_cipher_st {
    nid: 0,
    block_size: 0,
    key_len: 0,
    iv_len: 0,
    ctx_size: 0,
    flags: 0,
    init: None,
    cipher: None,
    cleanup: None,
    ctrl: None,
};
unsafe extern "C" fn EVP_aes_256_xts_storage_bss_get() -> *mut EVP_CIPHER {
    return &mut EVP_aes_256_xts_storage;
}
unsafe extern "C" fn EVP_aes_256_xts_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aes_256_xts_once;
}
unsafe extern "C" fn EVP_aes_256_xts_do_init(mut out: *mut EVP_CIPHER) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_CIPHER>() as libc::c_ulong,
    );
    (*out).nid = 914 as libc::c_int;
    (*out).block_size = 1 as libc::c_int as libc::c_uint;
    (*out).key_len = 64 as libc::c_int as libc::c_uint;
    (*out).iv_len = 16 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = ::core::mem::size_of::<EVP_AES_XTS_CTX>() as libc::c_ulong
        as libc::c_uint;
    (*out)
        .flags = (0x7 as libc::c_int | 0x100 as libc::c_int | 0x80 as libc::c_int
        | 0x200 as libc::c_int | 0x1000 as libc::c_int) as uint32_t;
    (*out)
        .init = Some(
        aes_xts_init_key
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *const uint8_t,
                *const uint8_t,
                libc::c_int,
            ) -> libc::c_int,
    );
    (*out)
        .cipher = Some(
        aes_xts_cipher
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *mut uint8_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .ctrl = Some(
        aes_xts_ctrl
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                libc::c_int,
                libc::c_int,
                *mut libc::c_void,
            ) -> libc::c_int,
    );
}
static mut EVP_aes_256_xts_once: CRYPTO_once_t = 0 as libc::c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_128_ecb() -> *const EVP_CIPHER {
    return aes_128_ecb_generic();
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_192_ecb() -> *const EVP_CIPHER {
    return aes_192_ecb_generic();
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_256_ecb() -> *const EVP_CIPHER {
    return aes_256_ecb_generic();
}
unsafe extern "C" fn aead_aes_gcm_init_impl(
    mut gcm_ctx: *mut aead_aes_gcm_ctx,
    mut out_tag_len: *mut size_t,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut tag_len: size_t,
) -> libc::c_int {
    let key_bits: size_t = key_len * 8 as libc::c_int as size_t;
    match key_bits {
        128 => {
            boringssl_fips_inc_counter(fips_counter_evp_aes_128_gcm);
        }
        256 => {
            boringssl_fips_inc_counter(fips_counter_evp_aes_256_gcm);
        }
        _ => {}
    }
    if key_bits != 128 as libc::c_int as size_t
        && key_bits != 192 as libc::c_int as size_t
        && key_bits != 256 as libc::c_int as size_t
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1095 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if tag_len == 0 as libc::c_int as size_t {
        tag_len = 16 as libc::c_int as size_t;
    }
    if tag_len > 16 as libc::c_int as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            116 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1104 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*gcm_ctx)
        .ctr = aes_ctr_set_key(
        &mut (*gcm_ctx).ks.ks,
        &mut (*gcm_ctx).gcm_key,
        0 as *mut block128_f,
        key,
        key_len,
    );
    *out_tag_len = tag_len;
    return 1 as libc::c_int;
}
unsafe extern "C" fn aead_aes_gcm_init(
    mut ctx: *mut EVP_AEAD_CTX,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut requested_tag_len: size_t,
) -> libc::c_int {
    let mut gcm_ctx: *mut aead_aes_gcm_ctx = &mut (*ctx).state
        as *mut evp_aead_ctx_st_state as *mut aead_aes_gcm_ctx;
    let mut actual_tag_len: size_t = 0;
    if aead_aes_gcm_init_impl(
        gcm_ctx,
        &mut actual_tag_len,
        key,
        key_len,
        requested_tag_len,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    (*ctx).tag_len = actual_tag_len as uint8_t;
    return 1 as libc::c_int;
}
unsafe extern "C" fn aead_aes_gcm_cleanup(mut ctx: *mut EVP_AEAD_CTX) {}
unsafe extern "C" fn aead_aes_gcm_seal_scatter_impl(
    mut gcm_ctx: *const aead_aes_gcm_ctx,
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
    mut tag_len: size_t,
) -> libc::c_int {
    if extra_in_len.wrapping_add(tag_len) < tag_len {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            117 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1143 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if max_out_tag_len < extra_in_len.wrapping_add(tag_len) {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            103 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1147 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if nonce_len == 0 as libc::c_int as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            111 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1151 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut key: *const AES_KEY = &(*gcm_ctx).ks.ks;
    let mut gcm: GCM128_CONTEXT = GCM128_CONTEXT {
        Yi: [0; 16],
        EKi: [0; 16],
        EK0: [0; 16],
        len: C2RustUnnamed_1 { aad: 0, msg: 0 },
        Xi: [0; 16],
        gcm_key: gcm128_key_st {
            Htable: [u128_0 { hi: 0, lo: 0 }; 16],
            gmult: None,
            ghash: None,
            block: None,
            use_hw_gcm_crypt: [0; 1],
            c2rust_padding: [0; 7],
        },
        mres: 0,
        ares: 0,
    };
    OPENSSL_memset(
        &mut gcm as *mut GCM128_CONTEXT as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<GCM128_CONTEXT>() as libc::c_ulong,
    );
    OPENSSL_memcpy(
        &mut gcm.gcm_key as *mut GCM128_KEY as *mut libc::c_void,
        &(*gcm_ctx).gcm_key as *const GCM128_KEY as *const libc::c_void,
        ::core::mem::size_of::<GCM128_KEY>() as libc::c_ulong,
    );
    CRYPTO_gcm128_setiv(&mut gcm, key, nonce, nonce_len);
    if ad_len > 0 as libc::c_int as size_t
        && CRYPTO_gcm128_aad(&mut gcm, ad, ad_len) == 0
    {
        return 0 as libc::c_int;
    }
    if ((*gcm_ctx).ctr).is_some() {
        if CRYPTO_gcm128_encrypt_ctr32(&mut gcm, key, in_0, out, in_len, (*gcm_ctx).ctr)
            == 0
        {
            return 0 as libc::c_int;
        }
    } else if CRYPTO_gcm128_encrypt(&mut gcm, key, in_0, out, in_len) == 0 {
        return 0 as libc::c_int
    }
    if extra_in_len != 0 {
        if ((*gcm_ctx).ctr).is_some() {
            if CRYPTO_gcm128_encrypt_ctr32(
                &mut gcm,
                key,
                extra_in,
                out_tag,
                extra_in_len,
                (*gcm_ctx).ctr,
            ) == 0
            {
                return 0 as libc::c_int;
            }
        } else if CRYPTO_gcm128_encrypt(&mut gcm, key, extra_in, out_tag, extra_in_len)
            == 0
        {
            return 0 as libc::c_int
        }
    }
    CRYPTO_gcm128_tag(&mut gcm, out_tag.offset(extra_in_len as isize), tag_len);
    *out_tag_len = tag_len.wrapping_add(extra_in_len);
    return 1 as libc::c_int;
}
unsafe extern "C" fn aead_aes_gcm_seal_scatter(
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
    let mut gcm_ctx: *const aead_aes_gcm_ctx = &(*ctx).state
        as *const evp_aead_ctx_st_state as *const aead_aes_gcm_ctx;
    return aead_aes_gcm_seal_scatter_impl(
        gcm_ctx,
        out,
        out_tag,
        out_tag_len,
        max_out_tag_len,
        nonce,
        nonce_len,
        in_0,
        in_len,
        extra_in,
        extra_in_len,
        ad,
        ad_len,
        (*ctx).tag_len as size_t,
    );
}
unsafe extern "C" fn aead_aes_gcm_open_gather_impl(
    mut gcm_ctx: *const aead_aes_gcm_ctx,
    mut out: *mut uint8_t,
    mut nonce: *const uint8_t,
    mut nonce_len: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut in_tag: *const uint8_t,
    mut in_tag_len: size_t,
    mut ad: *const uint8_t,
    mut ad_len: size_t,
    mut tag_len: size_t,
) -> libc::c_int {
    let mut tag: [uint8_t; 16] = [0; 16];
    if nonce_len == 0 as libc::c_int as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            111 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1217 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if in_tag_len != tag_len {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1222 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut key: *const AES_KEY = &(*gcm_ctx).ks.ks;
    let mut gcm: GCM128_CONTEXT = GCM128_CONTEXT {
        Yi: [0; 16],
        EKi: [0; 16],
        EK0: [0; 16],
        len: C2RustUnnamed_1 { aad: 0, msg: 0 },
        Xi: [0; 16],
        gcm_key: gcm128_key_st {
            Htable: [u128_0 { hi: 0, lo: 0 }; 16],
            gmult: None,
            ghash: None,
            block: None,
            use_hw_gcm_crypt: [0; 1],
            c2rust_padding: [0; 7],
        },
        mres: 0,
        ares: 0,
    };
    OPENSSL_memset(
        &mut gcm as *mut GCM128_CONTEXT as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<GCM128_CONTEXT>() as libc::c_ulong,
    );
    OPENSSL_memcpy(
        &mut gcm.gcm_key as *mut GCM128_KEY as *mut libc::c_void,
        &(*gcm_ctx).gcm_key as *const GCM128_KEY as *const libc::c_void,
        ::core::mem::size_of::<GCM128_KEY>() as libc::c_ulong,
    );
    CRYPTO_gcm128_setiv(&mut gcm, key, nonce, nonce_len);
    if CRYPTO_gcm128_aad(&mut gcm, ad, ad_len) == 0 {
        return 0 as libc::c_int;
    }
    if ((*gcm_ctx).ctr).is_some() {
        if CRYPTO_gcm128_decrypt_ctr32(&mut gcm, key, in_0, out, in_len, (*gcm_ctx).ctr)
            == 0
        {
            return 0 as libc::c_int;
        }
    } else if CRYPTO_gcm128_decrypt(&mut gcm, key, in_0, out, in_len) == 0 {
        return 0 as libc::c_int
    }
    CRYPTO_gcm128_tag(&mut gcm, tag.as_mut_ptr(), tag_len);
    if CRYPTO_memcmp(
        tag.as_mut_ptr() as *const libc::c_void,
        in_tag as *const libc::c_void,
        tag_len,
    ) != 0 as libc::c_int
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1250 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn aead_aes_gcm_open_gather(
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
    let mut gcm_ctx: *mut aead_aes_gcm_ctx = &(*ctx).state
        as *const evp_aead_ctx_st_state as *mut aead_aes_gcm_ctx;
    if aead_aes_gcm_open_gather_impl(
        gcm_ctx,
        out,
        nonce,
        nonce_len,
        in_0,
        in_len,
        in_tag,
        in_tag_len,
        ad,
        ad_len,
        (*ctx).tag_len as size_t,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    AEAD_GCM_verify_service_indicator(ctx);
    return 1 as libc::c_int;
}
static mut EVP_aead_aes_128_gcm_once: CRYPTO_once_t = 0 as libc::c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aead_aes_128_gcm() -> *const EVP_AEAD {
    CRYPTO_once(
        EVP_aead_aes_128_gcm_once_bss_get(),
        Some(EVP_aead_aes_128_gcm_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aead_aes_128_gcm_storage_bss_get() as *const EVP_AEAD;
}
unsafe extern "C" fn EVP_aead_aes_128_gcm_storage_bss_get() -> *mut EVP_AEAD {
    return &mut EVP_aead_aes_128_gcm_storage;
}
static mut EVP_aead_aes_128_gcm_storage: EVP_AEAD = evp_aead_st {
    key_len: 0,
    nonce_len: 0,
    overhead: 0,
    max_tag_len: 0,
    aead_id: 0,
    seal_scatter_supports_extra_in: 0,
    init: None,
    init_with_direction: None,
    cleanup: None,
    open: None,
    seal_scatter: None,
    open_gather: None,
    get_iv: None,
    tag_len: None,
    serialize_state: None,
    deserialize_state: None,
};
unsafe extern "C" fn EVP_aead_aes_128_gcm_init() {
    EVP_aead_aes_128_gcm_do_init(EVP_aead_aes_128_gcm_storage_bss_get());
}
unsafe extern "C" fn EVP_aead_aes_128_gcm_do_init(mut out: *mut EVP_AEAD) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_AEAD>() as libc::c_ulong,
    );
    (*out).key_len = 16 as libc::c_int as uint8_t;
    (*out).nonce_len = 12 as libc::c_int as uint8_t;
    (*out).overhead = 16 as libc::c_int as uint8_t;
    (*out).max_tag_len = 16 as libc::c_int as uint8_t;
    (*out).aead_id = 16 as libc::c_int as uint16_t;
    (*out).seal_scatter_supports_extra_in = 1 as libc::c_int;
    (*out)
        .init = Some(
        aead_aes_gcm_init
            as unsafe extern "C" fn(
                *mut EVP_AEAD_CTX,
                *const uint8_t,
                size_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .cleanup = Some(
        aead_aes_gcm_cleanup as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
    );
    (*out)
        .seal_scatter = Some(
        aead_aes_gcm_seal_scatter
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
    );
    (*out)
        .open_gather = Some(
        aead_aes_gcm_open_gather
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
    );
}
unsafe extern "C" fn EVP_aead_aes_128_gcm_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aead_aes_128_gcm_once;
}
static mut EVP_aead_aes_192_gcm_storage: EVP_AEAD = evp_aead_st {
    key_len: 0,
    nonce_len: 0,
    overhead: 0,
    max_tag_len: 0,
    aead_id: 0,
    seal_scatter_supports_extra_in: 0,
    init: None,
    init_with_direction: None,
    cleanup: None,
    open: None,
    seal_scatter: None,
    open_gather: None,
    get_iv: None,
    tag_len: None,
    serialize_state: None,
    deserialize_state: None,
};
unsafe extern "C" fn EVP_aead_aes_192_gcm_do_init(mut out: *mut EVP_AEAD) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_AEAD>() as libc::c_ulong,
    );
    (*out).key_len = 24 as libc::c_int as uint8_t;
    (*out).nonce_len = 12 as libc::c_int as uint8_t;
    (*out).overhead = 16 as libc::c_int as uint8_t;
    (*out).max_tag_len = 16 as libc::c_int as uint8_t;
    (*out).aead_id = 17 as libc::c_int as uint16_t;
    (*out).seal_scatter_supports_extra_in = 1 as libc::c_int;
    (*out)
        .init = Some(
        aead_aes_gcm_init
            as unsafe extern "C" fn(
                *mut EVP_AEAD_CTX,
                *const uint8_t,
                size_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .cleanup = Some(
        aead_aes_gcm_cleanup as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
    );
    (*out)
        .seal_scatter = Some(
        aead_aes_gcm_seal_scatter
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
    );
    (*out)
        .open_gather = Some(
        aead_aes_gcm_open_gather
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
    );
}
unsafe extern "C" fn EVP_aead_aes_192_gcm_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aead_aes_192_gcm_once;
}
static mut EVP_aead_aes_192_gcm_once: CRYPTO_once_t = 0 as libc::c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aead_aes_192_gcm() -> *const EVP_AEAD {
    CRYPTO_once(
        EVP_aead_aes_192_gcm_once_bss_get(),
        Some(EVP_aead_aes_192_gcm_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aead_aes_192_gcm_storage_bss_get() as *const EVP_AEAD;
}
unsafe extern "C" fn EVP_aead_aes_192_gcm_init() {
    EVP_aead_aes_192_gcm_do_init(EVP_aead_aes_192_gcm_storage_bss_get());
}
unsafe extern "C" fn EVP_aead_aes_192_gcm_storage_bss_get() -> *mut EVP_AEAD {
    return &mut EVP_aead_aes_192_gcm_storage;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aead_aes_256_gcm() -> *const EVP_AEAD {
    CRYPTO_once(
        EVP_aead_aes_256_gcm_once_bss_get(),
        Some(EVP_aead_aes_256_gcm_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aead_aes_256_gcm_storage_bss_get() as *const EVP_AEAD;
}
static mut EVP_aead_aes_256_gcm_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EVP_aead_aes_256_gcm_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aead_aes_256_gcm_once;
}
unsafe extern "C" fn EVP_aead_aes_256_gcm_storage_bss_get() -> *mut EVP_AEAD {
    return &mut EVP_aead_aes_256_gcm_storage;
}
unsafe extern "C" fn EVP_aead_aes_256_gcm_init() {
    EVP_aead_aes_256_gcm_do_init(EVP_aead_aes_256_gcm_storage_bss_get());
}
unsafe extern "C" fn EVP_aead_aes_256_gcm_do_init(mut out: *mut EVP_AEAD) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_AEAD>() as libc::c_ulong,
    );
    (*out).key_len = 32 as libc::c_int as uint8_t;
    (*out).nonce_len = 12 as libc::c_int as uint8_t;
    (*out).overhead = 16 as libc::c_int as uint8_t;
    (*out).max_tag_len = 16 as libc::c_int as uint8_t;
    (*out).aead_id = 18 as libc::c_int as uint16_t;
    (*out).seal_scatter_supports_extra_in = 1 as libc::c_int;
    (*out)
        .init = Some(
        aead_aes_gcm_init
            as unsafe extern "C" fn(
                *mut EVP_AEAD_CTX,
                *const uint8_t,
                size_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .cleanup = Some(
        aead_aes_gcm_cleanup as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
    );
    (*out)
        .seal_scatter = Some(
        aead_aes_gcm_seal_scatter
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
    );
    (*out)
        .open_gather = Some(
        aead_aes_gcm_open_gather
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
    );
}
static mut EVP_aead_aes_256_gcm_storage: EVP_AEAD = evp_aead_st {
    key_len: 0,
    nonce_len: 0,
    overhead: 0,
    max_tag_len: 0,
    aead_id: 0,
    seal_scatter_supports_extra_in: 0,
    init: None,
    init_with_direction: None,
    cleanup: None,
    open: None,
    seal_scatter: None,
    open_gather: None,
    get_iv: None,
    tag_len: None,
    serialize_state: None,
    deserialize_state: None,
};
unsafe extern "C" fn aead_aes_gcm_init_randnonce(
    mut ctx: *mut EVP_AEAD_CTX,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut requested_tag_len: size_t,
) -> libc::c_int {
    if requested_tag_len != 0 as libc::c_int as size_t {
        if requested_tag_len < 12 as libc::c_int as size_t {
            ERR_put_error(
                30 as libc::c_int,
                0 as libc::c_int,
                103 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                    as *const u8 as *const libc::c_char,
                1326 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        requested_tag_len = requested_tag_len.wrapping_sub(12 as libc::c_int as size_t);
    }
    if aead_aes_gcm_init(ctx, key, key_len, requested_tag_len) == 0 {
        return 0 as libc::c_int;
    }
    (*ctx).tag_len = ((*ctx).tag_len as libc::c_int + 12 as libc::c_int) as uint8_t;
    return 1 as libc::c_int;
}
unsafe extern "C" fn aead_aes_gcm_seal_scatter_randnonce(
    mut ctx: *const EVP_AEAD_CTX,
    mut out: *mut uint8_t,
    mut out_tag: *mut uint8_t,
    mut out_tag_len: *mut size_t,
    mut max_out_tag_len: size_t,
    mut external_nonce: *const uint8_t,
    mut external_nonce_len: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut extra_in: *const uint8_t,
    mut extra_in_len: size_t,
    mut ad: *const uint8_t,
    mut ad_len: size_t,
) -> libc::c_int {
    if external_nonce_len != 0 as libc::c_int as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            111 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1347 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut nonce: [uint8_t; 12] = [0; 12];
    if max_out_tag_len < ::core::mem::size_of::<[uint8_t; 12]>() as libc::c_ulong {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            103 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1353 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    FIPS_service_indicator_lock_state();
    RAND_bytes(
        nonce.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 12]>() as libc::c_ulong,
    );
    FIPS_service_indicator_unlock_state();
    let mut gcm_ctx: *const aead_aes_gcm_ctx = &(*ctx).state
        as *const evp_aead_ctx_st_state as *const aead_aes_gcm_ctx;
    if aead_aes_gcm_seal_scatter_impl(
        gcm_ctx,
        out,
        out_tag,
        out_tag_len,
        max_out_tag_len.wrapping_sub(12 as libc::c_int as size_t),
        nonce.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 12]>() as libc::c_ulong,
        in_0,
        in_len,
        extra_in,
        extra_in_len,
        ad,
        ad_len,
        ((*ctx).tag_len as libc::c_int - 12 as libc::c_int) as size_t,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    if (*out_tag_len)
        .wrapping_add(::core::mem::size_of::<[uint8_t; 12]>() as libc::c_ulong)
        <= max_out_tag_len
    {} else {
        __assert_fail(
            b"*out_tag_len + sizeof(nonce) <= max_out_tag_len\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1371 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 202],
                &[libc::c_char; 202],
            >(
                b"int aead_aes_gcm_seal_scatter_randnonce(const EVP_AEAD_CTX *, uint8_t *, uint8_t *, size_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_3597: {
        if (*out_tag_len)
            .wrapping_add(::core::mem::size_of::<[uint8_t; 12]>() as libc::c_ulong)
            <= max_out_tag_len
        {} else {
            __assert_fail(
                b"*out_tag_len + sizeof(nonce) <= max_out_tag_len\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                    as *const u8 as *const libc::c_char,
                1371 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 202],
                    &[libc::c_char; 202],
                >(
                    b"int aead_aes_gcm_seal_scatter_randnonce(const EVP_AEAD_CTX *, uint8_t *, uint8_t *, size_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    memcpy(
        out_tag.offset(*out_tag_len as isize) as *mut libc::c_void,
        nonce.as_mut_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint8_t; 12]>() as libc::c_ulong,
    );
    *out_tag_len = (*out_tag_len as libc::c_ulong)
        .wrapping_add(::core::mem::size_of::<[uint8_t; 12]>() as libc::c_ulong) as size_t
        as size_t;
    AEAD_GCM_verify_service_indicator(ctx);
    return 1 as libc::c_int;
}
unsafe extern "C" fn aead_aes_gcm_open_gather_randnonce(
    mut ctx: *const EVP_AEAD_CTX,
    mut out: *mut uint8_t,
    mut external_nonce: *const uint8_t,
    mut external_nonce_len: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut in_tag: *const uint8_t,
    mut in_tag_len: size_t,
    mut ad: *const uint8_t,
    mut ad_len: size_t,
) -> libc::c_int {
    if external_nonce_len != 0 as libc::c_int as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            111 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1385 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if in_tag_len < 12 as libc::c_int as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1390 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut nonce: *const uint8_t = in_tag
        .offset(in_tag_len as isize)
        .offset(-(12 as libc::c_int as isize));
    let mut gcm_ctx: *const aead_aes_gcm_ctx = &(*ctx).state
        as *const evp_aead_ctx_st_state as *const aead_aes_gcm_ctx;
    let mut ret: libc::c_int = aead_aes_gcm_open_gather_impl(
        gcm_ctx,
        out,
        nonce,
        12 as libc::c_int as size_t,
        in_0,
        in_len,
        in_tag,
        in_tag_len.wrapping_sub(12 as libc::c_int as size_t),
        ad,
        ad_len,
        ((*ctx).tag_len as libc::c_int - 12 as libc::c_int) as size_t,
    );
    if ret != 0 {
        AEAD_GCM_verify_service_indicator(ctx);
    }
    return ret;
}
unsafe extern "C" fn EVP_aead_aes_128_gcm_randnonce_init() {
    EVP_aead_aes_128_gcm_randnonce_do_init(
        EVP_aead_aes_128_gcm_randnonce_storage_bss_get(),
    );
}
static mut EVP_aead_aes_128_gcm_randnonce_storage: EVP_AEAD = evp_aead_st {
    key_len: 0,
    nonce_len: 0,
    overhead: 0,
    max_tag_len: 0,
    aead_id: 0,
    seal_scatter_supports_extra_in: 0,
    init: None,
    init_with_direction: None,
    cleanup: None,
    open: None,
    seal_scatter: None,
    open_gather: None,
    get_iv: None,
    tag_len: None,
    serialize_state: None,
    deserialize_state: None,
};
unsafe extern "C" fn EVP_aead_aes_128_gcm_randnonce_do_init(mut out: *mut EVP_AEAD) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_AEAD>() as libc::c_ulong,
    );
    (*out).key_len = 16 as libc::c_int as uint8_t;
    (*out).nonce_len = 0 as libc::c_int as uint8_t;
    (*out).overhead = (16 as libc::c_int + 12 as libc::c_int) as uint8_t;
    (*out).max_tag_len = (16 as libc::c_int + 12 as libc::c_int) as uint8_t;
    (*out).aead_id = 19 as libc::c_int as uint16_t;
    (*out).seal_scatter_supports_extra_in = 1 as libc::c_int;
    (*out)
        .init = Some(
        aead_aes_gcm_init_randnonce
            as unsafe extern "C" fn(
                *mut EVP_AEAD_CTX,
                *const uint8_t,
                size_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .cleanup = Some(
        aead_aes_gcm_cleanup as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
    );
    (*out)
        .seal_scatter = Some(
        aead_aes_gcm_seal_scatter_randnonce
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
    );
    (*out)
        .open_gather = Some(
        aead_aes_gcm_open_gather_randnonce
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
    );
}
static mut EVP_aead_aes_128_gcm_randnonce_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EVP_aead_aes_128_gcm_randnonce_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aead_aes_128_gcm_randnonce_once;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aead_aes_128_gcm_randnonce() -> *const EVP_AEAD {
    CRYPTO_once(
        EVP_aead_aes_128_gcm_randnonce_once_bss_get(),
        Some(EVP_aead_aes_128_gcm_randnonce_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aead_aes_128_gcm_randnonce_storage_bss_get() as *const EVP_AEAD;
}
unsafe extern "C" fn EVP_aead_aes_128_gcm_randnonce_storage_bss_get() -> *mut EVP_AEAD {
    return &mut EVP_aead_aes_128_gcm_randnonce_storage;
}
unsafe extern "C" fn EVP_aead_aes_256_gcm_randnonce_storage_bss_get() -> *mut EVP_AEAD {
    return &mut EVP_aead_aes_256_gcm_randnonce_storage;
}
static mut EVP_aead_aes_256_gcm_randnonce_storage: EVP_AEAD = evp_aead_st {
    key_len: 0,
    nonce_len: 0,
    overhead: 0,
    max_tag_len: 0,
    aead_id: 0,
    seal_scatter_supports_extra_in: 0,
    init: None,
    init_with_direction: None,
    cleanup: None,
    open: None,
    seal_scatter: None,
    open_gather: None,
    get_iv: None,
    tag_len: None,
    serialize_state: None,
    deserialize_state: None,
};
unsafe extern "C" fn EVP_aead_aes_256_gcm_randnonce_init() {
    EVP_aead_aes_256_gcm_randnonce_do_init(
        EVP_aead_aes_256_gcm_randnonce_storage_bss_get(),
    );
}
static mut EVP_aead_aes_256_gcm_randnonce_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EVP_aead_aes_256_gcm_randnonce_do_init(mut out: *mut EVP_AEAD) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_AEAD>() as libc::c_ulong,
    );
    (*out).key_len = 32 as libc::c_int as uint8_t;
    (*out).nonce_len = 0 as libc::c_int as uint8_t;
    (*out).overhead = (16 as libc::c_int + 12 as libc::c_int) as uint8_t;
    (*out).max_tag_len = (16 as libc::c_int + 12 as libc::c_int) as uint8_t;
    (*out).aead_id = 20 as libc::c_int as uint16_t;
    (*out).seal_scatter_supports_extra_in = 1 as libc::c_int;
    (*out)
        .init = Some(
        aead_aes_gcm_init_randnonce
            as unsafe extern "C" fn(
                *mut EVP_AEAD_CTX,
                *const uint8_t,
                size_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .cleanup = Some(
        aead_aes_gcm_cleanup as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
    );
    (*out)
        .seal_scatter = Some(
        aead_aes_gcm_seal_scatter_randnonce
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
    );
    (*out)
        .open_gather = Some(
        aead_aes_gcm_open_gather_randnonce
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
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aead_aes_256_gcm_randnonce() -> *const EVP_AEAD {
    CRYPTO_once(
        EVP_aead_aes_256_gcm_randnonce_once_bss_get(),
        Some(EVP_aead_aes_256_gcm_randnonce_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aead_aes_256_gcm_randnonce_storage_bss_get() as *const EVP_AEAD;
}
unsafe extern "C" fn EVP_aead_aes_256_gcm_randnonce_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aead_aes_256_gcm_randnonce_once;
}
unsafe extern "C" fn aead_aes_gcm_tls12_init(
    mut ctx: *mut EVP_AEAD_CTX,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut requested_tag_len: size_t,
) -> libc::c_int {
    let mut gcm_ctx: *mut aead_aes_gcm_tls12_ctx = &mut (*ctx).state
        as *mut evp_aead_ctx_st_state as *mut aead_aes_gcm_tls12_ctx;
    (*gcm_ctx).min_next_nonce = 0 as libc::c_int as uint64_t;
    let mut actual_tag_len: size_t = 0;
    if aead_aes_gcm_init_impl(
        &mut (*gcm_ctx).gcm_ctx,
        &mut actual_tag_len,
        key,
        key_len,
        requested_tag_len,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    (*ctx).tag_len = actual_tag_len as uint8_t;
    return 1 as libc::c_int;
}
unsafe extern "C" fn aead_aes_gcm_tls12_seal_scatter(
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
    let mut gcm_ctx: *mut aead_aes_gcm_tls12_ctx = &(*ctx).state
        as *const evp_aead_ctx_st_state as *mut aead_aes_gcm_tls12_ctx;
    if nonce_len != 12 as libc::c_int as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            121 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1479 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut given_counter: uint64_t = CRYPTO_load_u64_be(
        nonce
            .offset(nonce_len as isize)
            .offset(-(::core::mem::size_of::<uint64_t>() as libc::c_ulong as isize))
            as *const libc::c_void,
    );
    if given_counter == 18446744073709551615 as libc::c_ulong
        || given_counter < (*gcm_ctx).min_next_nonce
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1487 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*gcm_ctx).min_next_nonce = given_counter.wrapping_add(1 as libc::c_int as uint64_t);
    if aead_aes_gcm_seal_scatter(
        ctx,
        out,
        out_tag,
        out_tag_len,
        max_out_tag_len,
        nonce,
        nonce_len,
        in_0,
        in_len,
        extra_in,
        extra_in_len,
        ad,
        ad_len,
    ) != 0
    {
        AEAD_GCM_verify_service_indicator(ctx);
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn EVP_aead_aes_128_gcm_tls12_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aead_aes_128_gcm_tls12_once;
}
unsafe extern "C" fn EVP_aead_aes_128_gcm_tls12_do_init(mut out: *mut EVP_AEAD) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_AEAD>() as libc::c_ulong,
    );
    (*out).key_len = 16 as libc::c_int as uint8_t;
    (*out).nonce_len = 12 as libc::c_int as uint8_t;
    (*out).overhead = 16 as libc::c_int as uint8_t;
    (*out).max_tag_len = 16 as libc::c_int as uint8_t;
    (*out).aead_id = 21 as libc::c_int as uint16_t;
    (*out).seal_scatter_supports_extra_in = 1 as libc::c_int;
    (*out)
        .init = Some(
        aead_aes_gcm_tls12_init
            as unsafe extern "C" fn(
                *mut EVP_AEAD_CTX,
                *const uint8_t,
                size_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .cleanup = Some(
        aead_aes_gcm_cleanup as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
    );
    (*out)
        .seal_scatter = Some(
        aead_aes_gcm_tls12_seal_scatter
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
    );
    (*out)
        .open_gather = Some(
        aead_aes_gcm_open_gather
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
    );
}
unsafe extern "C" fn EVP_aead_aes_128_gcm_tls12_storage_bss_get() -> *mut EVP_AEAD {
    return &mut EVP_aead_aes_128_gcm_tls12_storage;
}
unsafe extern "C" fn EVP_aead_aes_128_gcm_tls12_init() {
    EVP_aead_aes_128_gcm_tls12_do_init(EVP_aead_aes_128_gcm_tls12_storage_bss_get());
}
static mut EVP_aead_aes_128_gcm_tls12_once: CRYPTO_once_t = 0 as libc::c_int;
static mut EVP_aead_aes_128_gcm_tls12_storage: EVP_AEAD = evp_aead_st {
    key_len: 0,
    nonce_len: 0,
    overhead: 0,
    max_tag_len: 0,
    aead_id: 0,
    seal_scatter_supports_extra_in: 0,
    init: None,
    init_with_direction: None,
    cleanup: None,
    open: None,
    seal_scatter: None,
    open_gather: None,
    get_iv: None,
    tag_len: None,
    serialize_state: None,
    deserialize_state: None,
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aead_aes_128_gcm_tls12() -> *const EVP_AEAD {
    CRYPTO_once(
        EVP_aead_aes_128_gcm_tls12_once_bss_get(),
        Some(EVP_aead_aes_128_gcm_tls12_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aead_aes_128_gcm_tls12_storage_bss_get() as *const EVP_AEAD;
}
static mut EVP_aead_aes_256_gcm_tls12_once: CRYPTO_once_t = 0 as libc::c_int;
static mut EVP_aead_aes_256_gcm_tls12_storage: EVP_AEAD = evp_aead_st {
    key_len: 0,
    nonce_len: 0,
    overhead: 0,
    max_tag_len: 0,
    aead_id: 0,
    seal_scatter_supports_extra_in: 0,
    init: None,
    init_with_direction: None,
    cleanup: None,
    open: None,
    seal_scatter: None,
    open_gather: None,
    get_iv: None,
    tag_len: None,
    serialize_state: None,
    deserialize_state: None,
};
unsafe extern "C" fn EVP_aead_aes_256_gcm_tls12_do_init(mut out: *mut EVP_AEAD) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_AEAD>() as libc::c_ulong,
    );
    (*out).key_len = 32 as libc::c_int as uint8_t;
    (*out).nonce_len = 12 as libc::c_int as uint8_t;
    (*out).overhead = 16 as libc::c_int as uint8_t;
    (*out).max_tag_len = 16 as libc::c_int as uint8_t;
    (*out).aead_id = 22 as libc::c_int as uint16_t;
    (*out).seal_scatter_supports_extra_in = 1 as libc::c_int;
    (*out)
        .init = Some(
        aead_aes_gcm_tls12_init
            as unsafe extern "C" fn(
                *mut EVP_AEAD_CTX,
                *const uint8_t,
                size_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .cleanup = Some(
        aead_aes_gcm_cleanup as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
    );
    (*out)
        .seal_scatter = Some(
        aead_aes_gcm_tls12_seal_scatter
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
    );
    (*out)
        .open_gather = Some(
        aead_aes_gcm_open_gather
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
    );
}
unsafe extern "C" fn EVP_aead_aes_256_gcm_tls12_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aead_aes_256_gcm_tls12_once;
}
unsafe extern "C" fn EVP_aead_aes_256_gcm_tls12_storage_bss_get() -> *mut EVP_AEAD {
    return &mut EVP_aead_aes_256_gcm_tls12_storage;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aead_aes_256_gcm_tls12() -> *const EVP_AEAD {
    CRYPTO_once(
        EVP_aead_aes_256_gcm_tls12_once_bss_get(),
        Some(EVP_aead_aes_256_gcm_tls12_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aead_aes_256_gcm_tls12_storage_bss_get() as *const EVP_AEAD;
}
unsafe extern "C" fn EVP_aead_aes_256_gcm_tls12_init() {
    EVP_aead_aes_256_gcm_tls12_do_init(EVP_aead_aes_256_gcm_tls12_storage_bss_get());
}
unsafe extern "C" fn aead_aes_gcm_tls13_init(
    mut ctx: *mut EVP_AEAD_CTX,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut requested_tag_len: size_t,
) -> libc::c_int {
    let mut gcm_ctx: *mut aead_aes_gcm_tls13_ctx = &mut (*ctx).state
        as *mut evp_aead_ctx_st_state as *mut aead_aes_gcm_tls13_ctx;
    (*gcm_ctx).min_next_nonce = 0 as libc::c_int as uint64_t;
    (*gcm_ctx).first = 1 as libc::c_int as uint8_t;
    let mut actual_tag_len: size_t = 0;
    if aead_aes_gcm_init_impl(
        &mut (*gcm_ctx).gcm_ctx,
        &mut actual_tag_len,
        key,
        key_len,
        requested_tag_len,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    (*ctx).tag_len = actual_tag_len as uint8_t;
    return 1 as libc::c_int;
}
unsafe extern "C" fn aead_aes_gcm_tls13_seal_scatter(
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
    let mut gcm_ctx: *mut aead_aes_gcm_tls13_ctx = &(*ctx).state
        as *const evp_aead_ctx_st_state as *mut aead_aes_gcm_tls13_ctx;
    if nonce_len != 12 as libc::c_int as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            121 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1575 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut given_counter: uint64_t = CRYPTO_load_u64_be(
        nonce
            .offset(nonce_len as isize)
            .offset(-(::core::mem::size_of::<uint64_t>() as libc::c_ulong as isize))
            as *const libc::c_void,
    );
    if (*gcm_ctx).first != 0 {
        (*gcm_ctx).mask = given_counter;
        (*gcm_ctx).first = 0 as libc::c_int as uint8_t;
    }
    given_counter ^= (*gcm_ctx).mask;
    if given_counter == 18446744073709551615 as libc::c_ulong
        || given_counter < (*gcm_ctx).min_next_nonce
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1594 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*gcm_ctx).min_next_nonce = given_counter.wrapping_add(1 as libc::c_int as uint64_t);
    if aead_aes_gcm_seal_scatter(
        ctx,
        out,
        out_tag,
        out_tag_len,
        max_out_tag_len,
        nonce,
        nonce_len,
        in_0,
        in_len,
        extra_in,
        extra_in_len,
        ad,
        ad_len,
    ) != 0
    {
        AEAD_GCM_verify_service_indicator(ctx);
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn aead_aes_gcm_tls13_serialize_state(
    mut ctx: *const EVP_AEAD_CTX,
    mut cbb: *mut CBB,
) -> libc::c_int {
    let mut gcm_ctx: *mut aead_aes_gcm_tls13_ctx = &(*ctx).state
        as *const evp_aead_ctx_st_state as *mut aead_aes_gcm_tls13_ctx;
    let mut state: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    if CBB_add_asn1(
        cbb,
        &mut state,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || CBB_add_asn1_uint64(&mut state, 1 as libc::c_int as uint64_t) == 0
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            1 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1630 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if CBB_add_asn1_uint64(&mut state, (*gcm_ctx).min_next_nonce) == 0 {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            1 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1635 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if CBB_add_asn1_uint64(&mut state, (*gcm_ctx).mask) == 0 {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            1 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1640 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if CBB_add_asn1_bool(
        &mut state,
        if (*gcm_ctx).first as libc::c_int != 0 {
            1 as libc::c_int
        } else {
            0 as libc::c_int
        },
    ) == 0
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            1 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1645 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return CBB_flush(cbb);
}
unsafe extern "C" fn aead_aes_gcm_tls13_deserialize_state(
    mut ctx: *const EVP_AEAD_CTX,
    mut cbs: *mut CBS,
) -> libc::c_int {
    let mut gcm_ctx: *mut aead_aes_gcm_tls13_ctx = &(*ctx).state
        as *const evp_aead_ctx_st_state as *mut aead_aes_gcm_tls13_ctx;
    let mut state: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_get_asn1(
        cbs,
        &mut state,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            141 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1662 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut serde_version: uint64_t = 0;
    if CBS_get_asn1_uint64(&mut state, &mut serde_version) == 0
        || 1 as libc::c_int as uint64_t != serde_version
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            141 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1669 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut min_next_nonce: uint64_t = 0;
    if CBS_get_asn1_uint64(&mut state, &mut min_next_nonce) == 0 {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            141 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1675 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*gcm_ctx).min_next_nonce = min_next_nonce;
    let mut mask: uint64_t = 0;
    if CBS_get_asn1_uint64(&mut state, &mut mask) == 0 {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            141 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1682 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*gcm_ctx).mask = mask;
    let mut first: libc::c_int = 0;
    if CBS_get_asn1_bool(&mut state, &mut first) == 0 {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            141 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aes.c\0"
                as *const u8 as *const libc::c_char,
            1689 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*gcm_ctx)
        .first = (if first != 0 { 1 as libc::c_int } else { 0 as libc::c_int })
        as uint8_t;
    return 1 as libc::c_int;
}
static mut EVP_aead_aes_128_gcm_tls13_once: CRYPTO_once_t = 0 as libc::c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aead_aes_128_gcm_tls13() -> *const EVP_AEAD {
    CRYPTO_once(
        EVP_aead_aes_128_gcm_tls13_once_bss_get(),
        Some(EVP_aead_aes_128_gcm_tls13_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aead_aes_128_gcm_tls13_storage_bss_get() as *const EVP_AEAD;
}
unsafe extern "C" fn EVP_aead_aes_128_gcm_tls13_storage_bss_get() -> *mut EVP_AEAD {
    return &mut EVP_aead_aes_128_gcm_tls13_storage;
}
unsafe extern "C" fn EVP_aead_aes_128_gcm_tls13_do_init(mut out: *mut EVP_AEAD) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_AEAD>() as libc::c_ulong,
    );
    (*out).key_len = 16 as libc::c_int as uint8_t;
    (*out).nonce_len = 12 as libc::c_int as uint8_t;
    (*out).overhead = 16 as libc::c_int as uint8_t;
    (*out).max_tag_len = 16 as libc::c_int as uint8_t;
    (*out).aead_id = 23 as libc::c_int as uint16_t;
    (*out).seal_scatter_supports_extra_in = 1 as libc::c_int;
    (*out)
        .init = Some(
        aead_aes_gcm_tls13_init
            as unsafe extern "C" fn(
                *mut EVP_AEAD_CTX,
                *const uint8_t,
                size_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .cleanup = Some(
        aead_aes_gcm_cleanup as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
    );
    (*out)
        .seal_scatter = Some(
        aead_aes_gcm_tls13_seal_scatter
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
    );
    (*out)
        .open_gather = Some(
        aead_aes_gcm_open_gather
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
    );
    (*out)
        .serialize_state = Some(
        aead_aes_gcm_tls13_serialize_state
            as unsafe extern "C" fn(*const EVP_AEAD_CTX, *mut CBB) -> libc::c_int,
    );
    (*out)
        .deserialize_state = Some(
        aead_aes_gcm_tls13_deserialize_state
            as unsafe extern "C" fn(*const EVP_AEAD_CTX, *mut CBS) -> libc::c_int,
    );
}
unsafe extern "C" fn EVP_aead_aes_128_gcm_tls13_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aead_aes_128_gcm_tls13_once;
}
unsafe extern "C" fn EVP_aead_aes_128_gcm_tls13_init() {
    EVP_aead_aes_128_gcm_tls13_do_init(EVP_aead_aes_128_gcm_tls13_storage_bss_get());
}
static mut EVP_aead_aes_128_gcm_tls13_storage: EVP_AEAD = evp_aead_st {
    key_len: 0,
    nonce_len: 0,
    overhead: 0,
    max_tag_len: 0,
    aead_id: 0,
    seal_scatter_supports_extra_in: 0,
    init: None,
    init_with_direction: None,
    cleanup: None,
    open: None,
    seal_scatter: None,
    open_gather: None,
    get_iv: None,
    tag_len: None,
    serialize_state: None,
    deserialize_state: None,
};
unsafe extern "C" fn EVP_aead_aes_256_gcm_tls13_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aead_aes_256_gcm_tls13_once;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aead_aes_256_gcm_tls13() -> *const EVP_AEAD {
    CRYPTO_once(
        EVP_aead_aes_256_gcm_tls13_once_bss_get(),
        Some(EVP_aead_aes_256_gcm_tls13_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aead_aes_256_gcm_tls13_storage_bss_get() as *const EVP_AEAD;
}
unsafe extern "C" fn EVP_aead_aes_256_gcm_tls13_storage_bss_get() -> *mut EVP_AEAD {
    return &mut EVP_aead_aes_256_gcm_tls13_storage;
}
static mut EVP_aead_aes_256_gcm_tls13_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EVP_aead_aes_256_gcm_tls13_init() {
    EVP_aead_aes_256_gcm_tls13_do_init(EVP_aead_aes_256_gcm_tls13_storage_bss_get());
}
unsafe extern "C" fn EVP_aead_aes_256_gcm_tls13_do_init(mut out: *mut EVP_AEAD) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_AEAD>() as libc::c_ulong,
    );
    (*out).key_len = 32 as libc::c_int as uint8_t;
    (*out).nonce_len = 12 as libc::c_int as uint8_t;
    (*out).overhead = 16 as libc::c_int as uint8_t;
    (*out).max_tag_len = 16 as libc::c_int as uint8_t;
    (*out).aead_id = 24 as libc::c_int as uint16_t;
    (*out).seal_scatter_supports_extra_in = 1 as libc::c_int;
    (*out)
        .init = Some(
        aead_aes_gcm_tls13_init
            as unsafe extern "C" fn(
                *mut EVP_AEAD_CTX,
                *const uint8_t,
                size_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .cleanup = Some(
        aead_aes_gcm_cleanup as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
    );
    (*out)
        .seal_scatter = Some(
        aead_aes_gcm_tls13_seal_scatter
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
    );
    (*out)
        .open_gather = Some(
        aead_aes_gcm_open_gather
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
    );
    (*out)
        .serialize_state = Some(
        aead_aes_gcm_tls13_serialize_state
            as unsafe extern "C" fn(*const EVP_AEAD_CTX, *mut CBB) -> libc::c_int,
    );
    (*out)
        .deserialize_state = Some(
        aead_aes_gcm_tls13_deserialize_state
            as unsafe extern "C" fn(*const EVP_AEAD_CTX, *mut CBS) -> libc::c_int,
    );
}
static mut EVP_aead_aes_256_gcm_tls13_storage: EVP_AEAD = evp_aead_st {
    key_len: 0,
    nonce_len: 0,
    overhead: 0,
    max_tag_len: 0,
    aead_id: 0,
    seal_scatter_supports_extra_in: 0,
    init: None,
    init_with_direction: None,
    cleanup: None,
    open: None,
    seal_scatter: None,
    open_gather: None,
    get_iv: None,
    tag_len: None,
    serialize_state: None,
    deserialize_state: None,
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_has_aes_hardware() -> libc::c_int {
    return (hwaes_capable() != 0 && crypto_gcm_clmul_enabled() != 0) as libc::c_int;
}
