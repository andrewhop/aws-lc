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
extern "C" {
    fn aes_ctr_set_key(
        aes_key: *mut AES_KEY,
        gcm_key: *mut GCM128_KEY,
        out_block: *mut block128_f,
        key: *const uint8_t,
        key_bytes: size_t,
    ) -> ctr128_f;
    fn EVP_AEAD_key_length(aead: *const EVP_AEAD) -> size_t;
    fn EVP_AEAD_nonce_length(aead: *const EVP_AEAD) -> size_t;
    fn EVP_AEAD_max_overhead(aead: *const EVP_AEAD) -> size_t;
    fn EVP_AEAD_max_tag_len(aead: *const EVP_AEAD) -> size_t;
    fn EVP_CIPHER_CTX_encrypting(ctx: *const EVP_CIPHER_CTX) -> libc::c_int;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn CRYPTO_memcmp(
        a: *const libc::c_void,
        b: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
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
    fn CRYPTO_once(
        once: *mut CRYPTO_once_t,
        init: Option::<unsafe extern "C" fn() -> ()>,
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
pub struct aead_aes_ccm_ctx {
    pub ks: C2RustUnnamed_0,
    pub ccm: ccm128_context,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ccm128_context {
    pub block: block128_f,
    pub ctr: ctr128_f,
    pub M: uint32_t,
    pub L: uint32_t,
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
pub type block128_f = Option::<
    unsafe extern "C" fn(*const uint8_t, *mut uint8_t, *const AES_KEY) -> (),
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ccm128_state {
    pub nonce: [uint8_t; 16],
    pub cmac: [uint8_t; 16],
}
pub type crypto_word_t = uint64_t;
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
pub type CRYPTO_once_t = pthread_once_t;
pub type CIPHER_AES_CCM_CTX = cipher_aes_ccm_ctx;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cipher_aes_ccm_ctx {
    pub ks: C2RustUnnamed_1,
    pub ccm: CCM128_CTX,
    pub ccm_state: CCM128_STATE,
    pub key_set: uint8_t,
    pub iv_set: uint8_t,
    pub tag_set: uint8_t,
    pub len_set: uint8_t,
    pub ccm_set: uint8_t,
    pub L: uint32_t,
    pub M: uint32_t,
    pub message_len: size_t,
    pub tag: [uint8_t; 16],
    pub nonce: [uint8_t; 13],
}
pub type CCM128_STATE = ccm128_state;
pub type CCM128_CTX = ccm128_context;
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_1 {
    pub align: uint64_t,
    pub ks: AES_KEY,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_507_error_is_EVP_AES_CCM_CTX_needs_more_alignment_than_this_function_provides {
    #[bitfield(
        name = "static_assertion_at_line_507_error_is_EVP_AES_CCM_CTX_needs_more_alignment_than_this_function_provides",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_507_error_is_EVP_AES_CCM_CTX_needs_more_alignment_than_this_function_provides: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
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
#[inline]
unsafe extern "C" fn AEAD_CCM_verify_service_indicator(mut ctx: *const EVP_AEAD_CTX) {}
unsafe extern "C" fn CRYPTO_ccm128_init(
    mut ctx: *mut ccm128_context,
    mut block: block128_f,
    mut ctr: ctr128_f,
    mut M: libc::c_uint,
    mut L: libc::c_uint,
) -> libc::c_int {
    if M < 4 as libc::c_int as libc::c_uint || M > 16 as libc::c_int as libc::c_uint
        || M & 1 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint
        || L < 2 as libc::c_int as libc::c_uint || L > 8 as libc::c_int as libc::c_uint
    {
        return 0 as libc::c_int;
    }
    if block.is_some() {
        (*ctx).block = block;
    }
    if ctr.is_some() {
        (*ctx).ctr = ctr;
    }
    (*ctx).M = M;
    (*ctx).L = L;
    return 1 as libc::c_int;
}
unsafe extern "C" fn CRYPTO_ccm128_max_input(mut ctx: *const ccm128_context) -> size_t {
    return if (*ctx).L as libc::c_ulong
        >= ::core::mem::size_of::<size_t>() as libc::c_ulong
    {
        18446744073709551615 as libc::c_ulong
    } else {
        ((1 as libc::c_int as size_t) << (*ctx).L * 8 as libc::c_int as uint32_t)
            .wrapping_sub(1 as libc::c_int as size_t)
    };
}
unsafe extern "C" fn ccm128_init_state(
    mut ctx: *const ccm128_context,
    mut state: *mut ccm128_state,
    mut key: *const AES_KEY,
    mut nonce: *const uint8_t,
    mut nonce_len: size_t,
    mut aad: *const uint8_t,
    mut aad_len: size_t,
    mut plaintext_len: size_t,
) -> libc::c_int {
    let block: block128_f = (*ctx).block;
    let M: uint32_t = (*ctx).M;
    let L: uint32_t = (*ctx).L;
    if plaintext_len > CRYPTO_ccm128_max_input(ctx)
        || nonce_len != (15 as libc::c_int as uint32_t).wrapping_sub(L) as size_t
    {
        return 0 as libc::c_int;
    }
    OPENSSL_memset(
        state as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<ccm128_state>() as libc::c_ulong,
    );
    (*state)
        .nonce[0 as libc::c_int
        as usize] = (L.wrapping_sub(1 as libc::c_int as uint32_t)
        | (M.wrapping_sub(2 as libc::c_int as uint32_t) / 2 as libc::c_int as uint32_t)
            << 3 as libc::c_int) as uint8_t;
    if aad_len != 0 as libc::c_int as size_t {
        (*state)
            .nonce[0 as libc::c_int
            as usize] = ((*state).nonce[0 as libc::c_int as usize] as libc::c_int
            | 0x40 as libc::c_int) as uint8_t;
    }
    OPENSSL_memcpy(
        &mut *((*state).nonce).as_mut_ptr().offset(1 as libc::c_int as isize)
            as *mut uint8_t as *mut libc::c_void,
        nonce as *const libc::c_void,
        nonce_len,
    );
    let mut plaintext_len_64: uint64_t = plaintext_len;
    let mut i: uint32_t = 0 as libc::c_int as uint32_t;
    while i < L {
        (*state)
            .nonce[(15 as libc::c_int as uint32_t).wrapping_sub(i)
            as usize] = (plaintext_len_64 >> 8 as libc::c_int as uint32_t * i)
            as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
    (Some(block.expect("non-null function pointer")))
        .expect(
            "non-null function pointer",
        )(
        ((*state).nonce).as_mut_ptr() as *const uint8_t,
        ((*state).cmac).as_mut_ptr(),
        key,
    );
    let mut blocks: size_t = 1 as libc::c_int as size_t;
    if aad_len != 0 as libc::c_int as size_t {
        let mut i_0: libc::c_uint = 0;
        let mut aad_len_u64: uint64_t = aad_len;
        if aad_len_u64 < (0x10000 as libc::c_int - 0x100 as libc::c_int) as uint64_t {
            (*state)
                .cmac[0 as libc::c_int
                as usize] = ((*state).cmac[0 as libc::c_int as usize] as libc::c_int
                ^ (aad_len_u64 >> 8 as libc::c_int) as uint8_t as libc::c_int)
                as uint8_t;
            (*state)
                .cmac[1 as libc::c_int
                as usize] = ((*state).cmac[1 as libc::c_int as usize] as libc::c_int
                ^ aad_len_u64 as uint8_t as libc::c_int) as uint8_t;
            i_0 = 2 as libc::c_int as libc::c_uint;
        } else if aad_len_u64 <= 0xffffffff as libc::c_uint as uint64_t {
            (*state)
                .cmac[0 as libc::c_int
                as usize] = ((*state).cmac[0 as libc::c_int as usize] as libc::c_int
                ^ 0xff as libc::c_int) as uint8_t;
            (*state)
                .cmac[1 as libc::c_int
                as usize] = ((*state).cmac[1 as libc::c_int as usize] as libc::c_int
                ^ 0xfe as libc::c_int) as uint8_t;
            (*state)
                .cmac[2 as libc::c_int
                as usize] = ((*state).cmac[2 as libc::c_int as usize] as libc::c_int
                ^ (aad_len_u64 >> 24 as libc::c_int) as uint8_t as libc::c_int)
                as uint8_t;
            (*state)
                .cmac[3 as libc::c_int
                as usize] = ((*state).cmac[3 as libc::c_int as usize] as libc::c_int
                ^ (aad_len_u64 >> 16 as libc::c_int) as uint8_t as libc::c_int)
                as uint8_t;
            (*state)
                .cmac[4 as libc::c_int
                as usize] = ((*state).cmac[4 as libc::c_int as usize] as libc::c_int
                ^ (aad_len_u64 >> 8 as libc::c_int) as uint8_t as libc::c_int)
                as uint8_t;
            (*state)
                .cmac[5 as libc::c_int
                as usize] = ((*state).cmac[5 as libc::c_int as usize] as libc::c_int
                ^ aad_len_u64 as uint8_t as libc::c_int) as uint8_t;
            i_0 = 6 as libc::c_int as libc::c_uint;
        } else {
            (*state)
                .cmac[0 as libc::c_int
                as usize] = ((*state).cmac[0 as libc::c_int as usize] as libc::c_int
                ^ 0xff as libc::c_int) as uint8_t;
            (*state)
                .cmac[1 as libc::c_int
                as usize] = ((*state).cmac[1 as libc::c_int as usize] as libc::c_int
                ^ 0xff as libc::c_int) as uint8_t;
            (*state)
                .cmac[2 as libc::c_int
                as usize] = ((*state).cmac[2 as libc::c_int as usize] as libc::c_int
                ^ (aad_len_u64 >> 56 as libc::c_int) as uint8_t as libc::c_int)
                as uint8_t;
            (*state)
                .cmac[3 as libc::c_int
                as usize] = ((*state).cmac[3 as libc::c_int as usize] as libc::c_int
                ^ (aad_len_u64 >> 48 as libc::c_int) as uint8_t as libc::c_int)
                as uint8_t;
            (*state)
                .cmac[4 as libc::c_int
                as usize] = ((*state).cmac[4 as libc::c_int as usize] as libc::c_int
                ^ (aad_len_u64 >> 40 as libc::c_int) as uint8_t as libc::c_int)
                as uint8_t;
            (*state)
                .cmac[5 as libc::c_int
                as usize] = ((*state).cmac[5 as libc::c_int as usize] as libc::c_int
                ^ (aad_len_u64 >> 32 as libc::c_int) as uint8_t as libc::c_int)
                as uint8_t;
            (*state)
                .cmac[6 as libc::c_int
                as usize] = ((*state).cmac[6 as libc::c_int as usize] as libc::c_int
                ^ (aad_len_u64 >> 24 as libc::c_int) as uint8_t as libc::c_int)
                as uint8_t;
            (*state)
                .cmac[7 as libc::c_int
                as usize] = ((*state).cmac[7 as libc::c_int as usize] as libc::c_int
                ^ (aad_len_u64 >> 16 as libc::c_int) as uint8_t as libc::c_int)
                as uint8_t;
            (*state)
                .cmac[8 as libc::c_int
                as usize] = ((*state).cmac[8 as libc::c_int as usize] as libc::c_int
                ^ (aad_len_u64 >> 8 as libc::c_int) as uint8_t as libc::c_int)
                as uint8_t;
            (*state)
                .cmac[9 as libc::c_int
                as usize] = ((*state).cmac[9 as libc::c_int as usize] as libc::c_int
                ^ aad_len_u64 as uint8_t as libc::c_int) as uint8_t;
            i_0 = 10 as libc::c_int as libc::c_uint;
        }
        loop {
            while i_0 < 16 as libc::c_int as libc::c_uint
                && aad_len != 0 as libc::c_int as size_t
            {
                (*state)
                    .cmac[i_0
                    as usize] = ((*state).cmac[i_0 as usize] as libc::c_int
                    ^ *aad as libc::c_int) as uint8_t;
                aad = aad.offset(1);
                aad;
                aad_len = aad_len.wrapping_sub(1);
                aad_len;
                i_0 = i_0.wrapping_add(1);
                i_0;
            }
            (Some(block.expect("non-null function pointer")))
                .expect(
                    "non-null function pointer",
                )(
                ((*state).cmac).as_mut_ptr() as *const uint8_t,
                ((*state).cmac).as_mut_ptr(),
                key,
            );
            blocks = blocks.wrapping_add(1);
            blocks;
            i_0 = 0 as libc::c_int as libc::c_uint;
            if !(aad_len != 0 as libc::c_int as size_t) {
                break;
            }
        }
    }
    let mut remaining_blocks: size_t = (2 as libc::c_int as size_t
        * (plaintext_len.wrapping_add(15 as libc::c_int as size_t)
            / 16 as libc::c_int as size_t))
        .wrapping_add(1 as libc::c_int as size_t);
    if plaintext_len.wrapping_add(15 as libc::c_int as size_t) < plaintext_len
        || remaining_blocks.wrapping_add(blocks) < blocks
        || remaining_blocks.wrapping_add(blocks)
            > (1 as libc::c_ulong) << 61 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    (*state)
        .nonce[0 as libc::c_int
        as usize] = ((*state).nonce[0 as libc::c_int as usize] as libc::c_int
        & 7 as libc::c_int) as uint8_t;
    return 1 as libc::c_int;
}
unsafe extern "C" fn ccm128_encrypt(
    mut ctx: *const ccm128_context,
    mut state: *mut ccm128_state,
    mut key: *const AES_KEY,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while i < (*ctx).L {
        (*state)
            .nonce[(15 as libc::c_int as libc::c_uint).wrapping_sub(i)
            as usize] = 0 as libc::c_int as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
    (*state).nonce[15 as libc::c_int as usize] = 1 as libc::c_int as uint8_t;
    let mut partial_buf: [uint8_t; 16] = [0; 16];
    let mut num: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    if ((*ctx).ctr).is_some() {
        CRYPTO_ctr128_encrypt_ctr32(
            in_0,
            out,
            len,
            key,
            ((*state).nonce).as_mut_ptr(),
            partial_buf.as_mut_ptr(),
            &mut num,
            (*ctx).ctr,
        );
    } else {
        CRYPTO_ctr128_encrypt(
            in_0,
            out,
            len,
            key,
            ((*state).nonce).as_mut_ptr(),
            partial_buf.as_mut_ptr(),
            &mut num,
            (*ctx).block,
        );
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn ccm128_compute_mac(
    mut ctx: *const ccm128_context,
    mut state: *mut ccm128_state,
    mut key: *const AES_KEY,
    mut out_tag: *mut uint8_t,
    mut tag_len: size_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut block: block128_f = (*ctx).block;
    if tag_len != (*ctx).M as size_t {
        return 0 as libc::c_int;
    }
    while len >= 16 as libc::c_int as size_t {
        CRYPTO_xor16(
            ((*state).cmac).as_mut_ptr(),
            ((*state).cmac).as_mut_ptr() as *const uint8_t,
            in_0,
        );
        (Some(block.expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )(
            ((*state).cmac).as_mut_ptr() as *const uint8_t,
            ((*state).cmac).as_mut_ptr(),
            key,
        );
        in_0 = in_0.offset(16 as libc::c_int as isize);
        len = len.wrapping_sub(16 as libc::c_int as size_t);
    }
    if len > 0 as libc::c_int as size_t {
        let mut i: size_t = 0 as libc::c_int as size_t;
        while i < len {
            (*state)
                .cmac[i
                as usize] = ((*state).cmac[i as usize] as libc::c_int
                ^ *in_0.offset(i as isize) as libc::c_int) as uint8_t;
            i = i.wrapping_add(1);
            i;
        }
        (Some(block.expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )(
            ((*state).cmac).as_mut_ptr() as *const uint8_t,
            ((*state).cmac).as_mut_ptr(),
            key,
        );
    }
    let mut i_0: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while i_0 < (*ctx).L {
        (*state)
            .nonce[(15 as libc::c_int as libc::c_uint).wrapping_sub(i_0)
            as usize] = 0 as libc::c_int as uint8_t;
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
    let mut tmp: [uint8_t; 16] = [0; 16];
    (Some(block.expect("non-null function pointer")))
        .expect(
            "non-null function pointer",
        )(((*state).nonce).as_mut_ptr() as *const uint8_t, tmp.as_mut_ptr(), key);
    CRYPTO_xor16(
        ((*state).cmac).as_mut_ptr(),
        ((*state).cmac).as_mut_ptr() as *const uint8_t,
        tmp.as_mut_ptr() as *const uint8_t,
    );
    OPENSSL_memcpy(
        out_tag as *mut libc::c_void,
        ((*state).cmac).as_mut_ptr() as *const libc::c_void,
        tag_len,
    );
    return 1 as libc::c_int;
}
unsafe extern "C" fn CRYPTO_ccm128_encrypt(
    mut ctx: *const ccm128_context,
    mut key: *const AES_KEY,
    mut out: *mut uint8_t,
    mut out_tag: *mut uint8_t,
    mut tag_len: size_t,
    mut nonce: *const uint8_t,
    mut nonce_len: size_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
    mut aad: *const uint8_t,
    mut aad_len: size_t,
) -> libc::c_int {
    let mut state: ccm128_state = ccm128_state {
        nonce: [0; 16],
        cmac: [0; 16],
    };
    return (ccm128_init_state(ctx, &mut state, key, nonce, nonce_len, aad, aad_len, len)
        != 0
        && ccm128_compute_mac(ctx, &mut state, key, out_tag, tag_len, in_0, len) != 0
        && ccm128_encrypt(ctx, &mut state, key, out, in_0, len) != 0) as libc::c_int;
}
unsafe extern "C" fn CRYPTO_ccm128_decrypt(
    mut ctx: *const ccm128_context,
    mut key: *const AES_KEY,
    mut out: *mut uint8_t,
    mut out_tag: *mut uint8_t,
    mut tag_len: size_t,
    mut nonce: *const uint8_t,
    mut nonce_len: size_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
    mut aad: *const uint8_t,
    mut aad_len: size_t,
) -> libc::c_int {
    let mut state: ccm128_state = ccm128_state {
        nonce: [0; 16],
        cmac: [0; 16],
    };
    return (ccm128_init_state(ctx, &mut state, key, nonce, nonce_len, aad, aad_len, len)
        != 0 && ccm128_encrypt(ctx, &mut state, key, out, in_0, len) != 0
        && ccm128_compute_mac(ctx, &mut state, key, out_tag, tag_len, out, len) != 0)
        as libc::c_int;
}
unsafe extern "C" fn aead_aes_ccm_init(
    mut ctx: *mut EVP_AEAD_CTX,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut tag_len: size_t,
    mut M: libc::c_uint,
    mut L: libc::c_uint,
) -> libc::c_int {
    if M as size_t == EVP_AEAD_max_overhead((*ctx).aead) {} else {
        __assert_fail(
            b"M == EVP_AEAD_max_overhead(ctx->aead)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aesccm.c\0"
                as *const u8 as *const libc::c_char,
            324 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 99],
                &[libc::c_char; 99],
            >(
                b"int aead_aes_ccm_init(EVP_AEAD_CTX *, const uint8_t *, size_t, size_t, unsigned int, unsigned int)\0",
            ))
                .as_ptr(),
        );
    }
    'c_3654: {
        if M as size_t == EVP_AEAD_max_overhead((*ctx).aead) {} else {
            __assert_fail(
                b"M == EVP_AEAD_max_overhead(ctx->aead)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aesccm.c\0"
                    as *const u8 as *const libc::c_char,
                324 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 99],
                    &[libc::c_char; 99],
                >(
                    b"int aead_aes_ccm_init(EVP_AEAD_CTX *, const uint8_t *, size_t, size_t, unsigned int, unsigned int)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if M as size_t == EVP_AEAD_max_tag_len((*ctx).aead) {} else {
        __assert_fail(
            b"M == EVP_AEAD_max_tag_len(ctx->aead)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aesccm.c\0"
                as *const u8 as *const libc::c_char,
            325 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 99],
                &[libc::c_char; 99],
            >(
                b"int aead_aes_ccm_init(EVP_AEAD_CTX *, const uint8_t *, size_t, size_t, unsigned int, unsigned int)\0",
            ))
                .as_ptr(),
        );
    }
    'c_3601: {
        if M as size_t == EVP_AEAD_max_tag_len((*ctx).aead) {} else {
            __assert_fail(
                b"M == EVP_AEAD_max_tag_len(ctx->aead)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aesccm.c\0"
                    as *const u8 as *const libc::c_char,
                325 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 99],
                    &[libc::c_char; 99],
                >(
                    b"int aead_aes_ccm_init(EVP_AEAD_CTX *, const uint8_t *, size_t, size_t, unsigned int, unsigned int)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if (15 as libc::c_int as libc::c_uint).wrapping_sub(L) as size_t
        == EVP_AEAD_nonce_length((*ctx).aead)
    {} else {
        __assert_fail(
            b"CCM_L_TO_NONCE_LEN(L) == EVP_AEAD_nonce_length(ctx->aead)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aesccm.c\0"
                as *const u8 as *const libc::c_char,
            326 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 99],
                &[libc::c_char; 99],
            >(
                b"int aead_aes_ccm_init(EVP_AEAD_CTX *, const uint8_t *, size_t, size_t, unsigned int, unsigned int)\0",
            ))
                .as_ptr(),
        );
    }
    'c_3541: {
        if (15 as libc::c_int as libc::c_uint).wrapping_sub(L) as size_t
            == EVP_AEAD_nonce_length((*ctx).aead)
        {} else {
            __assert_fail(
                b"CCM_L_TO_NONCE_LEN(L) == EVP_AEAD_nonce_length(ctx->aead)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aesccm.c\0"
                    as *const u8 as *const libc::c_char,
                326 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 99],
                    &[libc::c_char; 99],
                >(
                    b"int aead_aes_ccm_init(EVP_AEAD_CTX *, const uint8_t *, size_t, size_t, unsigned int, unsigned int)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if key_len != EVP_AEAD_key_length((*ctx).aead) {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aesccm.c\0"
                as *const u8 as *const libc::c_char,
            329 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if tag_len == 0 as libc::c_int as size_t {
        tag_len = M as size_t;
    }
    if tag_len != M as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            116 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aesccm.c\0"
                as *const u8 as *const libc::c_char,
            338 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ccm_ctx: *mut aead_aes_ccm_ctx = &mut (*ctx).state
        as *mut evp_aead_ctx_st_state as *mut aead_aes_ccm_ctx;
    let mut block: block128_f = None;
    let mut ctr: ctr128_f = aes_ctr_set_key(
        &mut (*ccm_ctx).ks.ks,
        0 as *mut GCM128_KEY,
        &mut block,
        key,
        key_len,
    );
    (*ctx).tag_len = tag_len as uint8_t;
    if CRYPTO_ccm128_init(&mut (*ccm_ctx).ccm, block, ctr, M, L) == 0 {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            4 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aesccm.c\0"
                as *const u8 as *const libc::c_char,
            348 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn aead_aes_ccm_cleanup(mut ctx: *mut EVP_AEAD_CTX) {}
unsafe extern "C" fn aead_aes_ccm_seal_scatter(
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
    let mut ccm_ctx: *const aead_aes_ccm_ctx = &(*ctx).state
        as *const evp_aead_ctx_st_state as *mut aead_aes_ccm_ctx;
    if in_len > CRYPTO_ccm128_max_input(&(*ccm_ctx).ccm) {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            117 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aesccm.c\0"
                as *const u8 as *const libc::c_char,
            366 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if max_out_tag_len < (*ctx).tag_len as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            103 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aesccm.c\0"
                as *const u8 as *const libc::c_char,
            371 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if nonce_len != EVP_AEAD_nonce_length((*ctx).aead) {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            111 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aesccm.c\0"
                as *const u8 as *const libc::c_char,
            376 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if CRYPTO_ccm128_encrypt(
        &(*ccm_ctx).ccm,
        &(*ccm_ctx).ks.ks,
        out,
        out_tag,
        (*ctx).tag_len as size_t,
        nonce,
        nonce_len,
        in_0,
        in_len,
        ad,
        ad_len,
    ) == 0
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            117 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aesccm.c\0"
                as *const u8 as *const libc::c_char,
            383 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    *out_tag_len = (*ctx).tag_len as size_t;
    AEAD_CCM_verify_service_indicator(ctx);
    return 1 as libc::c_int;
}
unsafe extern "C" fn aead_aes_ccm_open_gather(
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
    let mut ccm_ctx: *const aead_aes_ccm_ctx = &(*ctx).state
        as *const evp_aead_ctx_st_state as *mut aead_aes_ccm_ctx;
    if in_len > CRYPTO_ccm128_max_input(&(*ccm_ctx).ccm) {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            117 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aesccm.c\0"
                as *const u8 as *const libc::c_char,
            401 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if nonce_len != EVP_AEAD_nonce_length((*ctx).aead) {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            111 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aesccm.c\0"
                as *const u8 as *const libc::c_char,
            406 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if in_tag_len != (*ctx).tag_len as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aesccm.c\0"
                as *const u8 as *const libc::c_char,
            411 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut tag: [uint8_t; 16] = [0; 16];
    if (*ctx).tag_len as libc::c_int <= 16 as libc::c_int {} else {
        __assert_fail(
            b"ctx->tag_len <= EVP_AEAD_AES_CCM_MAX_TAG_LEN\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aesccm.c\0"
                as *const u8 as *const libc::c_char,
            416 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 162],
                &[libc::c_char; 162],
            >(
                b"int aead_aes_ccm_open_gather(const EVP_AEAD_CTX *, uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2856: {
        if (*ctx).tag_len as libc::c_int <= 16 as libc::c_int {} else {
            __assert_fail(
                b"ctx->tag_len <= EVP_AEAD_AES_CCM_MAX_TAG_LEN\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aesccm.c\0"
                    as *const u8 as *const libc::c_char,
                416 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 162],
                    &[libc::c_char; 162],
                >(
                    b"int aead_aes_ccm_open_gather(const EVP_AEAD_CTX *, uint8_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if CRYPTO_ccm128_decrypt(
        &(*ccm_ctx).ccm,
        &(*ccm_ctx).ks.ks,
        out,
        tag.as_mut_ptr(),
        (*ctx).tag_len as size_t,
        nonce,
        nonce_len,
        in_0,
        in_len,
        ad,
        ad_len,
    ) == 0
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            117 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aesccm.c\0"
                as *const u8 as *const libc::c_char,
            420 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if CRYPTO_memcmp(
        tag.as_mut_ptr() as *const libc::c_void,
        in_tag as *const libc::c_void,
        (*ctx).tag_len as size_t,
    ) != 0 as libc::c_int
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aesccm.c\0"
                as *const u8 as *const libc::c_char,
            425 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    AEAD_CCM_verify_service_indicator(ctx);
    return 1 as libc::c_int;
}
unsafe extern "C" fn aead_aes_ccm_bluetooth_init(
    mut ctx: *mut EVP_AEAD_CTX,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut tag_len: size_t,
) -> libc::c_int {
    return aead_aes_ccm_init(
        ctx,
        key,
        key_len,
        tag_len,
        4 as libc::c_int as libc::c_uint,
        2 as libc::c_int as libc::c_uint,
    );
}
unsafe extern "C" fn EVP_aead_aes_128_ccm_bluetooth_do_init(mut out: *mut EVP_AEAD) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_AEAD>() as libc::c_ulong,
    );
    (*out).key_len = 16 as libc::c_int as uint8_t;
    (*out).nonce_len = 13 as libc::c_int as uint8_t;
    (*out).overhead = 4 as libc::c_int as uint8_t;
    (*out).max_tag_len = 4 as libc::c_int as uint8_t;
    (*out).aead_id = 25 as libc::c_int as uint16_t;
    (*out).seal_scatter_supports_extra_in = 0 as libc::c_int;
    (*out)
        .init = Some(
        aead_aes_ccm_bluetooth_init
            as unsafe extern "C" fn(
                *mut EVP_AEAD_CTX,
                *const uint8_t,
                size_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .cleanup = Some(
        aead_aes_ccm_cleanup as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
    );
    (*out)
        .seal_scatter = Some(
        aead_aes_ccm_seal_scatter
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
        aead_aes_ccm_open_gather
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
unsafe extern "C" fn EVP_aead_aes_128_ccm_bluetooth_init() {
    EVP_aead_aes_128_ccm_bluetooth_do_init(
        EVP_aead_aes_128_ccm_bluetooth_storage_bss_get(),
    );
}
static mut EVP_aead_aes_128_ccm_bluetooth_storage: EVP_AEAD = evp_aead_st {
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
#[no_mangle]
pub unsafe extern "C" fn EVP_aead_aes_128_ccm_bluetooth() -> *const EVP_AEAD {
    CRYPTO_once(
        EVP_aead_aes_128_ccm_bluetooth_once_bss_get(),
        Some(EVP_aead_aes_128_ccm_bluetooth_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aead_aes_128_ccm_bluetooth_storage_bss_get() as *const EVP_AEAD;
}
unsafe extern "C" fn EVP_aead_aes_128_ccm_bluetooth_storage_bss_get() -> *mut EVP_AEAD {
    return &mut EVP_aead_aes_128_ccm_bluetooth_storage;
}
static mut EVP_aead_aes_128_ccm_bluetooth_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EVP_aead_aes_128_ccm_bluetooth_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aead_aes_128_ccm_bluetooth_once;
}
unsafe extern "C" fn aead_aes_ccm_bluetooth_8_init(
    mut ctx: *mut EVP_AEAD_CTX,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut tag_len: size_t,
) -> libc::c_int {
    return aead_aes_ccm_init(
        ctx,
        key,
        key_len,
        tag_len,
        8 as libc::c_int as libc::c_uint,
        2 as libc::c_int as libc::c_uint,
    );
}
static mut EVP_aead_aes_128_ccm_bluetooth_8_storage: EVP_AEAD = evp_aead_st {
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
unsafe extern "C" fn EVP_aead_aes_128_ccm_bluetooth_8_storage_bss_get() -> *mut EVP_AEAD {
    return &mut EVP_aead_aes_128_ccm_bluetooth_8_storage;
}
unsafe extern "C" fn EVP_aead_aes_128_ccm_bluetooth_8_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aead_aes_128_ccm_bluetooth_8_once;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_aead_aes_128_ccm_bluetooth_8() -> *const EVP_AEAD {
    CRYPTO_once(
        EVP_aead_aes_128_ccm_bluetooth_8_once_bss_get(),
        Some(EVP_aead_aes_128_ccm_bluetooth_8_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aead_aes_128_ccm_bluetooth_8_storage_bss_get() as *const EVP_AEAD;
}
unsafe extern "C" fn EVP_aead_aes_128_ccm_bluetooth_8_do_init(mut out: *mut EVP_AEAD) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_AEAD>() as libc::c_ulong,
    );
    (*out).key_len = 16 as libc::c_int as uint8_t;
    (*out).nonce_len = 13 as libc::c_int as uint8_t;
    (*out).overhead = 8 as libc::c_int as uint8_t;
    (*out).max_tag_len = 8 as libc::c_int as uint8_t;
    (*out).aead_id = 26 as libc::c_int as uint16_t;
    (*out).seal_scatter_supports_extra_in = 0 as libc::c_int;
    (*out)
        .init = Some(
        aead_aes_ccm_bluetooth_8_init
            as unsafe extern "C" fn(
                *mut EVP_AEAD_CTX,
                *const uint8_t,
                size_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .cleanup = Some(
        aead_aes_ccm_cleanup as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
    );
    (*out)
        .seal_scatter = Some(
        aead_aes_ccm_seal_scatter
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
        aead_aes_ccm_open_gather
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
static mut EVP_aead_aes_128_ccm_bluetooth_8_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EVP_aead_aes_128_ccm_bluetooth_8_init() {
    EVP_aead_aes_128_ccm_bluetooth_8_do_init(
        EVP_aead_aes_128_ccm_bluetooth_8_storage_bss_get(),
    );
}
unsafe extern "C" fn aead_aes_ccm_matter_init(
    mut ctx: *mut EVP_AEAD_CTX,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut tag_len: size_t,
) -> libc::c_int {
    return aead_aes_ccm_init(
        ctx,
        key,
        key_len,
        tag_len,
        16 as libc::c_int as libc::c_uint,
        2 as libc::c_int as libc::c_uint,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_aead_aes_128_ccm_matter() -> *const EVP_AEAD {
    CRYPTO_once(
        EVP_aead_aes_128_ccm_matter_once_bss_get(),
        Some(EVP_aead_aes_128_ccm_matter_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aead_aes_128_ccm_matter_storage_bss_get() as *const EVP_AEAD;
}
unsafe extern "C" fn EVP_aead_aes_128_ccm_matter_storage_bss_get() -> *mut EVP_AEAD {
    return &mut EVP_aead_aes_128_ccm_matter_storage;
}
unsafe extern "C" fn EVP_aead_aes_128_ccm_matter_init() {
    EVP_aead_aes_128_ccm_matter_do_init(EVP_aead_aes_128_ccm_matter_storage_bss_get());
}
unsafe extern "C" fn EVP_aead_aes_128_ccm_matter_do_init(mut out: *mut EVP_AEAD) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_AEAD>() as libc::c_ulong,
    );
    (*out).key_len = 16 as libc::c_int as uint8_t;
    (*out).nonce_len = 13 as libc::c_int as uint8_t;
    (*out).overhead = 16 as libc::c_int as uint8_t;
    (*out).aead_id = 27 as libc::c_int as uint16_t;
    (*out).max_tag_len = 16 as libc::c_int as uint8_t;
    (*out)
        .init = Some(
        aead_aes_ccm_matter_init
            as unsafe extern "C" fn(
                *mut EVP_AEAD_CTX,
                *const uint8_t,
                size_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .cleanup = Some(
        aead_aes_ccm_cleanup as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
    );
    (*out)
        .seal_scatter = Some(
        aead_aes_ccm_seal_scatter
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
        aead_aes_ccm_open_gather
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
static mut EVP_aead_aes_128_ccm_matter_storage: EVP_AEAD = evp_aead_st {
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
unsafe extern "C" fn EVP_aead_aes_128_ccm_matter_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aead_aes_128_ccm_matter_once;
}
static mut EVP_aead_aes_128_ccm_matter_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn aes_ccm_from_cipher_ctx(
    mut ctx: *mut EVP_CIPHER_CTX,
) -> *mut CIPHER_AES_CCM_CTX {
    if (*(*ctx).cipher).ctx_size as libc::c_ulong
        == (::core::mem::size_of::<CIPHER_AES_CCM_CTX>() as libc::c_ulong)
            .wrapping_add(8 as libc::c_int as libc::c_ulong)
    {} else {
        __assert_fail(
            b"ctx->cipher->ctx_size == sizeof(CIPHER_AES_CCM_CTX) + CIPHER_AES_CCM_CTX_PADDING\0"
                as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aesccm.c\0"
                as *const u8 as *const libc::c_char,
            512 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 62],
                &[libc::c_char; 62],
            >(b"CIPHER_AES_CCM_CTX *aes_ccm_from_cipher_ctx(EVP_CIPHER_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_4616: {
        if (*(*ctx).cipher).ctx_size as libc::c_ulong
            == (::core::mem::size_of::<CIPHER_AES_CCM_CTX>() as libc::c_ulong)
                .wrapping_add(8 as libc::c_int as libc::c_ulong)
        {} else {
            __assert_fail(
                b"ctx->cipher->ctx_size == sizeof(CIPHER_AES_CCM_CTX) + CIPHER_AES_CCM_CTX_PADDING\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aesccm.c\0"
                    as *const u8 as *const libc::c_char,
                512 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 62],
                    &[libc::c_char; 62],
                >(b"CIPHER_AES_CCM_CTX *aes_ccm_from_cipher_ctx(EVP_CIPHER_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut ptr: *mut libc::c_char = (*ctx).cipher_data as *mut libc::c_char;
    if ptr as uintptr_t % 8 as libc::c_int as uintptr_t == 0 as libc::c_int as uintptr_t
    {} else {
        __assert_fail(
            b"(uintptr_t)ptr % 8 == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aesccm.c\0"
                as *const u8 as *const libc::c_char,
            519 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 62],
                &[libc::c_char; 62],
            >(b"CIPHER_AES_CCM_CTX *aes_ccm_from_cipher_ctx(EVP_CIPHER_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_4568: {
        if ptr as uintptr_t % 8 as libc::c_int as uintptr_t
            == 0 as libc::c_int as uintptr_t
        {} else {
            __assert_fail(
                b"(uintptr_t)ptr % 8 == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/e_aesccm.c\0"
                    as *const u8 as *const libc::c_char,
                519 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 62],
                    &[libc::c_char; 62],
                >(b"CIPHER_AES_CCM_CTX *aes_ccm_from_cipher_ctx(EVP_CIPHER_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    ptr = ptr.offset((ptr as uintptr_t & 8 as libc::c_int as uintptr_t) as isize);
    return ptr as *mut CIPHER_AES_CCM_CTX;
}
unsafe extern "C" fn cipher_aes_ccm_init(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut key: *const uint8_t,
    mut iv: *const uint8_t,
    mut enc: libc::c_int,
) -> libc::c_int {
    let mut cipher_ctx: *mut CIPHER_AES_CCM_CTX = aes_ccm_from_cipher_ctx(ctx);
    if iv.is_null() && key.is_null() {
        return 1 as libc::c_int;
    }
    if !key.is_null() {
        let mut block: block128_f = None;
        let mut ctr: ctr128_f = aes_ctr_set_key(
            &mut (*cipher_ctx).ks.ks,
            0 as *mut GCM128_KEY,
            &mut block,
            key,
            (*ctx).key_len as size_t,
        );
        if CRYPTO_ccm128_init(
            &mut (*cipher_ctx).ccm,
            block,
            ctr,
            (*cipher_ctx).M,
            (*cipher_ctx).L,
        ) == 0
        {
            return 0 as libc::c_int;
        }
        (*cipher_ctx).key_set = 1 as libc::c_int as uint8_t;
    }
    if !iv.is_null() {
        if CRYPTO_ccm128_init(
            &mut (*cipher_ctx).ccm,
            None,
            None,
            (*cipher_ctx).M,
            (*cipher_ctx).L,
        ) == 0
        {
            return 0 as libc::c_int;
        }
        OPENSSL_memcpy(
            ((*cipher_ctx).nonce).as_mut_ptr() as *mut libc::c_void,
            iv as *const libc::c_void,
            (15 as libc::c_int as uint32_t).wrapping_sub((*cipher_ctx).L) as size_t,
        );
        (*cipher_ctx).iv_set = 1 as libc::c_int as uint8_t;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn cipher_aes_ccm_cipher(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut cipher_ctx: *mut CIPHER_AES_CCM_CTX = aes_ccm_from_cipher_ctx(ctx);
    let mut ccm_ctx: *mut CCM128_CTX = &mut (*cipher_ctx).ccm;
    let mut ccm_state: *mut CCM128_STATE = &mut (*cipher_ctx).ccm_state;
    if in_0.is_null() && !out.is_null() {
        return 0 as libc::c_int;
    }
    if (*cipher_ctx).iv_set == 0 || (*cipher_ctx).key_set == 0 {
        return -(1 as libc::c_int);
    }
    if out.is_null() {
        if in_0.is_null() {
            (*cipher_ctx).message_len = len;
            (*cipher_ctx).len_set = 1 as libc::c_int as uint8_t;
            return len as libc::c_int;
        } else {
            if (*cipher_ctx).len_set == 0 && len != 0 {
                return -(1 as libc::c_int);
            }
            if ccm128_init_state(
                ccm_ctx,
                ccm_state,
                &mut (*cipher_ctx).ks.ks,
                ((*cipher_ctx).nonce).as_mut_ptr(),
                (15 as libc::c_int as uint32_t).wrapping_sub((*cipher_ctx).L) as size_t,
                in_0,
                len,
                (*cipher_ctx).message_len,
            ) != 0
            {
                (*cipher_ctx).ccm_set = 1 as libc::c_int as uint8_t;
                return len as libc::c_int;
            } else {
                return -(1 as libc::c_int)
            }
        }
    }
    if EVP_CIPHER_CTX_encrypting(ctx) == 0 && (*cipher_ctx).tag_set == 0 {
        return -(1 as libc::c_int);
    }
    if (*cipher_ctx).len_set == 0 {
        return -(1 as libc::c_int);
    }
    if (*cipher_ctx).ccm_set == 0 {
        if ccm128_init_state(
            ccm_ctx,
            ccm_state,
            &mut (*cipher_ctx).ks.ks,
            ((*cipher_ctx).nonce).as_mut_ptr(),
            (15 as libc::c_int as uint32_t).wrapping_sub((*cipher_ctx).L) as size_t,
            0 as *const uint8_t,
            0 as libc::c_int as size_t,
            (*cipher_ctx).message_len,
        ) == 0
        {
            return -(1 as libc::c_int);
        }
        (*cipher_ctx).ccm_set = 1 as libc::c_int as uint8_t;
    }
    if EVP_CIPHER_CTX_encrypting(ctx) != 0 {
        if ccm128_compute_mac(
            ccm_ctx,
            ccm_state,
            &mut (*cipher_ctx).ks.ks,
            ((*cipher_ctx).tag).as_mut_ptr(),
            (*cipher_ctx).M as size_t,
            in_0,
            len,
        ) == 0
        {
            return -(1 as libc::c_int);
        }
        if ccm128_encrypt(ccm_ctx, ccm_state, &mut (*cipher_ctx).ks.ks, out, in_0, len)
            == 0
        {
            return -(1 as libc::c_int);
        }
        (*cipher_ctx).tag_set = 1 as libc::c_int as uint8_t;
    } else {
        if ccm128_encrypt(ccm_ctx, ccm_state, &mut (*cipher_ctx).ks.ks, out, in_0, len)
            == 0
        {
            return -(1 as libc::c_int);
        }
        let mut computed_tag: [uint8_t; 16] = [
            0 as libc::c_int as uint8_t,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        if ccm128_compute_mac(
            ccm_ctx,
            ccm_state,
            &mut (*cipher_ctx).ks.ks,
            computed_tag.as_mut_ptr(),
            (*cipher_ctx).M as size_t,
            out,
            len,
        ) == 0
        {
            OPENSSL_cleanse(out as *mut libc::c_void, len);
            return -(1 as libc::c_int);
        }
        if OPENSSL_memcmp(
            ((*cipher_ctx).tag).as_mut_ptr() as *const libc::c_void,
            computed_tag.as_mut_ptr() as *const libc::c_void,
            (*cipher_ctx).M as size_t,
        ) != 0
        {
            OPENSSL_cleanse(out as *mut libc::c_void, len);
            return -(1 as libc::c_int);
        }
        (*cipher_ctx).iv_set = 0 as libc::c_int as uint8_t;
        (*cipher_ctx).tag_set = 0 as libc::c_int as uint8_t;
        (*cipher_ctx).len_set = 0 as libc::c_int as uint8_t;
        (*cipher_ctx).ccm_set = 0 as libc::c_int as uint8_t;
    }
    return len as libc::c_int;
}
unsafe extern "C" fn cipher_aes_ccm_ctrl_set_L(
    mut ctx: *mut CIPHER_AES_CCM_CTX,
    mut L: libc::c_int,
) -> libc::c_int {
    if L < 2 as libc::c_int || L > 8 as libc::c_int {
        return 0 as libc::c_int;
    }
    (*ctx).L = L as uint32_t;
    return 1 as libc::c_int;
}
unsafe extern "C" fn cipher_aes_ccm_ctrl(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut type_0: libc::c_int,
    mut arg: libc::c_int,
    mut ptr: *mut libc::c_void,
) -> libc::c_int {
    let mut cipher_ctx: *mut CIPHER_AES_CCM_CTX = aes_ccm_from_cipher_ctx(ctx);
    match type_0 {
        0 => {
            OPENSSL_cleanse(
                cipher_ctx as *mut libc::c_void,
                ::core::mem::size_of::<CIPHER_AES_CCM_CTX>() as libc::c_ulong,
            );
            (*cipher_ctx).key_set = 0 as libc::c_int as uint8_t;
            (*cipher_ctx).iv_set = 0 as libc::c_int as uint8_t;
            (*cipher_ctx).tag_set = 0 as libc::c_int as uint8_t;
            (*cipher_ctx).len_set = 0 as libc::c_int as uint8_t;
            (*cipher_ctx).ccm_set = 0 as libc::c_int as uint8_t;
            (*cipher_ctx).L = 8 as libc::c_int as uint32_t;
            (*cipher_ctx).M = 14 as libc::c_int as uint32_t;
            (*cipher_ctx).message_len = 0 as libc::c_int as size_t;
            return 1 as libc::c_int;
        }
        25 => {
            *(ptr
                as *mut uint32_t) = (15 as libc::c_int as uint32_t)
                .wrapping_sub((*cipher_ctx).L);
            return 1 as libc::c_int;
        }
        9 => return cipher_aes_ccm_ctrl_set_L(cipher_ctx, 15 as libc::c_int - arg),
        20 => return cipher_aes_ccm_ctrl_set_L(cipher_ctx, arg),
        17 => {
            if arg & 1 as libc::c_int != 0 || arg < 4 as libc::c_int
                || arg > 16 as libc::c_int
            {
                return 0 as libc::c_int;
            }
            if (*ctx).encrypt != 0 && !ptr.is_null() {
                return 0 as libc::c_int;
            }
            if !ptr.is_null() {
                OPENSSL_memcpy(
                    ((*cipher_ctx).tag).as_mut_ptr() as *mut libc::c_void,
                    ptr,
                    arg as size_t,
                );
                (*cipher_ctx).tag_set = 1 as libc::c_int as uint8_t;
            }
            (*cipher_ctx).M = arg as uint32_t;
            return 1 as libc::c_int;
        }
        16 => {
            if (*ctx).encrypt == 0 || (*cipher_ctx).tag_set == 0 {
                return 0 as libc::c_int;
            }
            if arg as size_t != (*cipher_ctx).M as size_t {
                return 0 as libc::c_int;
            }
            OPENSSL_memcpy(
                ptr,
                ((*cipher_ctx).tag).as_mut_ptr() as *const libc::c_void,
                (*cipher_ctx).M as size_t,
            );
            (*cipher_ctx).tag_set = 0 as libc::c_int as uint8_t;
            (*cipher_ctx).iv_set = 0 as libc::c_int as uint8_t;
            (*cipher_ctx).len_set = 0 as libc::c_int as uint8_t;
            (*cipher_ctx).ccm_set = 0 as libc::c_int as uint8_t;
            return 1 as libc::c_int;
        }
        8 => {
            let mut out: *mut EVP_CIPHER_CTX = ptr as *mut EVP_CIPHER_CTX;
            let mut cipher_ctx_out: *mut CIPHER_AES_CCM_CTX = aes_ccm_from_cipher_ctx(
                out,
            );
            OPENSSL_memcpy(
                cipher_ctx_out as *mut libc::c_void,
                cipher_ctx as *const libc::c_void,
                ::core::mem::size_of::<CIPHER_AES_CCM_CTX>() as libc::c_ulong,
            );
            return 1 as libc::c_int;
        }
        _ => return -(1 as libc::c_int),
    };
}
unsafe extern "C" fn EVP_aes_128_ccm_storage_bss_get() -> *mut EVP_CIPHER {
    return &mut EVP_aes_128_ccm_storage;
}
static mut EVP_aes_128_ccm_once: CRYPTO_once_t = 0 as libc::c_int;
#[no_mangle]
pub unsafe extern "C" fn EVP_aes_128_ccm() -> *const EVP_CIPHER {
    CRYPTO_once(
        EVP_aes_128_ccm_once_bss_get(),
        Some(EVP_aes_128_ccm_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aes_128_ccm_storage_bss_get() as *const EVP_CIPHER;
}
unsafe extern "C" fn EVP_aes_128_ccm_do_init(mut out: *mut EVP_CIPHER) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_CIPHER>() as libc::c_ulong,
    );
    (*out).nid = 896 as libc::c_int;
    (*out).block_size = 1 as libc::c_int as libc::c_uint;
    (*out).key_len = 16 as libc::c_int as libc::c_uint;
    (*out).iv_len = 13 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = (::core::mem::size_of::<CIPHER_AES_CCM_CTX>() as libc::c_ulong)
        .wrapping_add(8 as libc::c_int as libc::c_ulong) as libc::c_uint;
    (*out)
        .flags = (0x8 as libc::c_int | 0x100 as libc::c_int | 0x1000 as libc::c_int
        | 0x400 as libc::c_int | 0x80 as libc::c_int | 0x200 as libc::c_int
        | 0x800 as libc::c_int) as uint32_t;
    (*out)
        .init = Some(
        cipher_aes_ccm_init
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *const uint8_t,
                *const uint8_t,
                libc::c_int,
            ) -> libc::c_int,
    );
    (*out)
        .cipher = Some(
        cipher_aes_ccm_cipher
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *mut uint8_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out).cleanup = None;
    (*out)
        .ctrl = Some(
        cipher_aes_ccm_ctrl
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                libc::c_int,
                libc::c_int,
                *mut libc::c_void,
            ) -> libc::c_int,
    );
}
unsafe extern "C" fn EVP_aes_128_ccm_init() {
    EVP_aes_128_ccm_do_init(EVP_aes_128_ccm_storage_bss_get());
}
static mut EVP_aes_128_ccm_storage: EVP_CIPHER = evp_cipher_st {
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
unsafe extern "C" fn EVP_aes_128_ccm_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aes_128_ccm_once;
}
unsafe extern "C" fn EVP_aes_192_ccm_init() {
    EVP_aes_192_ccm_do_init(EVP_aes_192_ccm_storage_bss_get());
}
unsafe extern "C" fn EVP_aes_192_ccm_storage_bss_get() -> *mut EVP_CIPHER {
    return &mut EVP_aes_192_ccm_storage;
}
static mut EVP_aes_192_ccm_storage: EVP_CIPHER = evp_cipher_st {
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
unsafe extern "C" fn EVP_aes_192_ccm_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aes_192_ccm_once;
}
unsafe extern "C" fn EVP_aes_192_ccm_do_init(mut out: *mut EVP_CIPHER) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_CIPHER>() as libc::c_ulong,
    );
    (*out).nid = 896 as libc::c_int;
    (*out).block_size = 1 as libc::c_int as libc::c_uint;
    (*out).key_len = 24 as libc::c_int as libc::c_uint;
    (*out).iv_len = 13 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = (::core::mem::size_of::<CIPHER_AES_CCM_CTX>() as libc::c_ulong)
        .wrapping_add(8 as libc::c_int as libc::c_ulong) as libc::c_uint;
    (*out)
        .flags = (0x8 as libc::c_int | 0x100 as libc::c_int | 0x1000 as libc::c_int
        | 0x400 as libc::c_int | 0x80 as libc::c_int | 0x200 as libc::c_int
        | 0x800 as libc::c_int) as uint32_t;
    (*out)
        .init = Some(
        cipher_aes_ccm_init
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *const uint8_t,
                *const uint8_t,
                libc::c_int,
            ) -> libc::c_int,
    );
    (*out)
        .cipher = Some(
        cipher_aes_ccm_cipher
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *mut uint8_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out).cleanup = None;
    (*out)
        .ctrl = Some(
        cipher_aes_ccm_ctrl
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                libc::c_int,
                libc::c_int,
                *mut libc::c_void,
            ) -> libc::c_int,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_aes_192_ccm() -> *const EVP_CIPHER {
    CRYPTO_once(
        EVP_aes_192_ccm_once_bss_get(),
        Some(EVP_aes_192_ccm_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aes_192_ccm_storage_bss_get() as *const EVP_CIPHER;
}
static mut EVP_aes_192_ccm_once: CRYPTO_once_t = 0 as libc::c_int;
static mut EVP_aes_256_ccm_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn EVP_aes_256_ccm_do_init(mut out: *mut EVP_CIPHER) {
    memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_CIPHER>() as libc::c_ulong,
    );
    (*out).nid = 896 as libc::c_int;
    (*out).block_size = 1 as libc::c_int as libc::c_uint;
    (*out).key_len = 32 as libc::c_int as libc::c_uint;
    (*out).iv_len = 13 as libc::c_int as libc::c_uint;
    (*out)
        .ctx_size = (::core::mem::size_of::<CIPHER_AES_CCM_CTX>() as libc::c_ulong)
        .wrapping_add(8 as libc::c_int as libc::c_ulong) as libc::c_uint;
    (*out)
        .flags = (0x8 as libc::c_int | 0x100 as libc::c_int | 0x1000 as libc::c_int
        | 0x400 as libc::c_int | 0x80 as libc::c_int | 0x200 as libc::c_int
        | 0x800 as libc::c_int) as uint32_t;
    (*out)
        .init = Some(
        cipher_aes_ccm_init
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *const uint8_t,
                *const uint8_t,
                libc::c_int,
            ) -> libc::c_int,
    );
    (*out)
        .cipher = Some(
        cipher_aes_ccm_cipher
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                *mut uint8_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out).cleanup = None;
    (*out)
        .ctrl = Some(
        cipher_aes_ccm_ctrl
            as unsafe extern "C" fn(
                *mut EVP_CIPHER_CTX,
                libc::c_int,
                libc::c_int,
                *mut libc::c_void,
            ) -> libc::c_int,
    );
}
unsafe extern "C" fn EVP_aes_256_ccm_storage_bss_get() -> *mut EVP_CIPHER {
    return &mut EVP_aes_256_ccm_storage;
}
static mut EVP_aes_256_ccm_storage: EVP_CIPHER = evp_cipher_st {
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
#[no_mangle]
pub unsafe extern "C" fn EVP_aes_256_ccm() -> *const EVP_CIPHER {
    CRYPTO_once(
        EVP_aes_256_ccm_once_bss_get(),
        Some(EVP_aes_256_ccm_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_aes_256_ccm_storage_bss_get() as *const EVP_CIPHER;
}
unsafe extern "C" fn EVP_aes_256_ccm_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_aes_256_ccm_once;
}
unsafe extern "C" fn EVP_aes_256_ccm_init() {
    EVP_aes_256_ccm_do_init(EVP_aes_256_ccm_storage_bss_get());
}
