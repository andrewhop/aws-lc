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
    fn abort() -> !;
    fn EVP_CIPHER_CTX_encrypting(ctx: *const EVP_CIPHER_CTX) -> libc::c_int;
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
    fn CRYPTO_chacha_20(
        out: *mut uint8_t,
        in_0: *const uint8_t,
        in_len: size_t,
        key: *const uint8_t,
        nonce: *const uint8_t,
        counter: uint32_t,
    );
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
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
    fn CRYPTO_poly1305_init(state: *mut poly1305_state, key: *const uint8_t);
    fn CRYPTO_poly1305_update(
        state: *mut poly1305_state,
        in_0: *const uint8_t,
        in_len: size_t,
    );
    fn CRYPTO_poly1305_finish(state: *mut poly1305_state, mac: *mut uint8_t);
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn CRYPTO_hchacha20(out: *mut uint8_t, key: *const uint8_t, nonce: *const uint8_t);
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type int32_t = __int32_t;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type uintptr_t = libc::c_ulong;
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
pub type AEAD_CHACHA_POLY_CTX = aead_chacha20_poly1305_ctx;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct aead_chacha20_poly1305_ctx {
    pub key: [uint8_t; 32],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub tag: [uint8_t; 16],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union chacha20_poly1305_open_data {
    pub in_0: C2RustUnnamed_1,
    pub out: C2RustUnnamed_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_1 {
    pub key: [uint8_t; 32],
    pub counter: uint32_t,
    pub nonce: [uint8_t; 12],
}
pub type poly1305_state = [uint8_t; 512];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_2 {
    pub tag: [uint8_t; 16],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union chacha20_poly1305_seal_data {
    pub in_0: C2RustUnnamed_3,
    pub out: C2RustUnnamed_2,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_3 {
    pub key: [uint8_t; 32],
    pub counter: uint32_t,
    pub nonce: [uint8_t; 12],
    pub extra_ciphertext: *const uint8_t,
    pub extra_ciphertext_len: size_t,
}
pub type CIPHER_CHACHA_POLY_CTX = cipher_chacha_poly_ctx;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cipher_chacha_poly_ctx {
    pub key: CIPHER_CHACHA_KEY,
    pub iv: [uint32_t; 3],
    pub tag_len: uint8_t,
    pub tag: [uint8_t; 16],
    pub len: C2RustUnnamed_4,
    pub poly_initialized: int32_t,
    pub pad_aad: int32_t,
    pub poly_ctx: poly1305_state,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_4 {
    pub aad: uint64_t,
    pub text: uint64_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CIPHER_CHACHA_KEY {
    pub key: [uint32_t; 8],
    pub counter_nonce: [uint32_t; 4],
    pub buf: [uint8_t; 64],
    pub partial_len: uint32_t,
}
#[inline]
unsafe extern "C" fn align_pointer(
    mut ptr: *mut libc::c_void,
    mut alignment: size_t,
) -> *mut libc::c_void {
    if alignment != 0 as libc::c_int as size_t
        && alignment & alignment.wrapping_sub(1 as libc::c_int as size_t)
            == 0 as libc::c_int as size_t
    {} else {
        __assert_fail(
            b"alignment != 0 && (alignment & (alignment - 1)) == 0\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/../chacha/../internal.h\0"
                as *const u8 as *const libc::c_char,
            264 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 36],
                &[libc::c_char; 36],
            >(b"void *align_pointer(void *, size_t)\0"))
                .as_ptr(),
        );
    }
    'c_3680: {
        if alignment != 0 as libc::c_int as size_t
            && alignment & alignment.wrapping_sub(1 as libc::c_int as size_t)
                == 0 as libc::c_int as size_t
        {} else {
            __assert_fail(
                b"alignment != 0 && (alignment & (alignment - 1)) == 0\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/../chacha/../internal.h\0"
                    as *const u8 as *const libc::c_char,
                264 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 36],
                    &[libc::c_char; 36],
                >(b"void *align_pointer(void *, size_t)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut offset: uintptr_t = (0 as libc::c_uint as uintptr_t)
        .wrapping_sub(ptr as uintptr_t)
        & alignment.wrapping_sub(1 as libc::c_int as size_t);
    ptr = (ptr as *mut libc::c_char).offset(offset as isize) as *mut libc::c_void;
    if ptr as uintptr_t & alignment.wrapping_sub(1 as libc::c_int as size_t)
        == 0 as libc::c_int as libc::c_ulong
    {} else {
        __assert_fail(
            b"((uintptr_t)ptr & (alignment - 1)) == 0\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/../chacha/../internal.h\0"
                as *const u8 as *const libc::c_char,
            272 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 36],
                &[libc::c_char; 36],
            >(b"void *align_pointer(void *, size_t)\0"))
                .as_ptr(),
        );
    }
    'c_3587: {
        if ptr as uintptr_t & alignment.wrapping_sub(1 as libc::c_int as size_t)
            == 0 as libc::c_int as libc::c_ulong
        {} else {
            __assert_fail(
                b"((uintptr_t)ptr & (alignment - 1)) == 0\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/../chacha/../internal.h\0"
                    as *const u8 as *const libc::c_char,
                272 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 36],
                    &[libc::c_char; 36],
                >(b"void *align_pointer(void *, size_t)\0"))
                    .as_ptr(),
            );
        }
    };
    return ptr;
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
unsafe extern "C" fn chacha20_poly1305_asm_capable() -> libc::c_int {
    return 0 as libc::c_int;
}
#[inline]
unsafe extern "C" fn chacha20_poly1305_open(
    mut out_plaintext: *mut uint8_t,
    mut ciphertext: *const uint8_t,
    mut plaintext_len: size_t,
    mut ad: *const uint8_t,
    mut ad_len: size_t,
    mut data: *mut chacha20_poly1305_open_data,
) {
    abort();
}
#[inline]
unsafe extern "C" fn chacha20_poly1305_seal(
    mut out_ciphertext: *mut uint8_t,
    mut plaintext: *const uint8_t,
    mut plaintext_len: size_t,
    mut ad: *const uint8_t,
    mut ad_len: size_t,
    mut data: *mut chacha20_poly1305_seal_data,
) {
    abort();
}
unsafe extern "C" fn aead_chacha20_poly1305_init(
    mut ctx: *mut EVP_AEAD_CTX,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut tag_len: size_t,
) -> libc::c_int {
    let mut c20_ctx: *mut AEAD_CHACHA_POLY_CTX = &mut (*ctx).state
        as *mut evp_aead_ctx_st_state as *mut AEAD_CHACHA_POLY_CTX;
    if tag_len == 0 as libc::c_int as size_t {
        tag_len = 16 as libc::c_int as size_t;
    }
    if tag_len > 16 as libc::c_int as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            117 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_chacha20poly1305.c\0"
                as *const u8 as *const libc::c_char,
            89 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if key_len != ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong {
        return 0 as libc::c_int;
    }
    OPENSSL_memcpy(
        ((*c20_ctx).key).as_mut_ptr() as *mut libc::c_void,
        key as *const libc::c_void,
        key_len,
    );
    (*ctx).tag_len = tag_len as uint8_t;
    return 1 as libc::c_int;
}
unsafe extern "C" fn aead_chacha20_poly1305_cleanup(mut ctx: *mut EVP_AEAD_CTX) {}
unsafe extern "C" fn poly1305_update_length(
    mut poly1305: *mut poly1305_state,
    mut data_len: size_t,
) {
    let mut length_bytes: [uint8_t; 8] = [0; 8];
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong) < ::core::mem::size_of::<[uint8_t; 8]>() as libc::c_ulong
    {
        length_bytes[i as usize] = data_len as uint8_t;
        data_len >>= 8 as libc::c_int;
        i = i.wrapping_add(1);
        i;
    }
    CRYPTO_poly1305_update(
        poly1305,
        length_bytes.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 8]>() as libc::c_ulong,
    );
}
unsafe extern "C" fn calc_tag(
    mut tag: *mut uint8_t,
    mut key: *const uint8_t,
    mut nonce: *const uint8_t,
    mut ad: *const uint8_t,
    mut ad_len: size_t,
    mut ciphertext: *const uint8_t,
    mut ciphertext_len: size_t,
    mut ciphertext_extra: *const uint8_t,
    mut ciphertext_extra_len: size_t,
) {
    let mut poly1305_key: [uint8_t; 32] = [0; 32];
    OPENSSL_memset(
        poly1305_key.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
    );
    CRYPTO_chacha_20(
        poly1305_key.as_mut_ptr(),
        poly1305_key.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
        key,
        nonce,
        0 as libc::c_int as uint32_t,
    );
    static mut padding: [uint8_t; 16] = [
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
    let mut ctx: poly1305_state = [0; 512];
    CRYPTO_poly1305_init(&mut ctx, poly1305_key.as_mut_ptr() as *const uint8_t);
    CRYPTO_poly1305_update(&mut ctx, ad, ad_len);
    if ad_len % 16 as libc::c_int as size_t != 0 as libc::c_int as size_t {
        CRYPTO_poly1305_update(
            &mut ctx,
            padding.as_ptr(),
            (::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong)
                .wrapping_sub(ad_len % 16 as libc::c_int as size_t),
        );
    }
    CRYPTO_poly1305_update(&mut ctx, ciphertext, ciphertext_len);
    CRYPTO_poly1305_update(&mut ctx, ciphertext_extra, ciphertext_extra_len);
    let ciphertext_total: size_t = ciphertext_len.wrapping_add(ciphertext_extra_len);
    if ciphertext_total % 16 as libc::c_int as size_t != 0 as libc::c_int as size_t {
        CRYPTO_poly1305_update(
            &mut ctx,
            padding.as_ptr(),
            (::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong)
                .wrapping_sub(ciphertext_total % 16 as libc::c_int as size_t),
        );
    }
    poly1305_update_length(&mut ctx, ad_len);
    poly1305_update_length(&mut ctx, ciphertext_total);
    CRYPTO_poly1305_finish(&mut ctx, tag);
}
unsafe extern "C" fn chacha20_poly1305_seal_scatter(
    mut key: *const uint8_t,
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
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_chacha20poly1305.c\0"
                as *const u8 as *const libc::c_char,
            152 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if max_out_tag_len < tag_len.wrapping_add(extra_in_len) {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            103 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_chacha20poly1305.c\0"
                as *const u8 as *const libc::c_char,
            156 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if nonce_len != 12 as libc::c_int as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            121 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_chacha20poly1305.c\0"
                as *const u8 as *const libc::c_char,
            160 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let in_len_64: uint64_t = in_len;
    if in_len_64
        >= ((1 as libc::c_ulong) << 32 as libc::c_int)
            .wrapping_mul(64 as libc::c_int as libc::c_ulong)
            .wrapping_sub(64 as libc::c_int as libc::c_ulong)
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            117 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_chacha20poly1305.c\0"
                as *const u8 as *const libc::c_char,
            172 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if max_out_tag_len < tag_len {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            103 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_chacha20poly1305.c\0"
                as *const u8 as *const libc::c_char,
            177 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if extra_in_len != 0 {
        static mut kChaChaBlockSize: size_t = 64 as libc::c_int as size_t;
        let mut block_counter: uint32_t = (1 as libc::c_int as size_t)
            .wrapping_add(in_len / kChaChaBlockSize) as uint32_t;
        let mut offset: size_t = in_len % kChaChaBlockSize;
        let mut block: [uint8_t; 64] = [0; 64];
        let mut done: size_t = 0 as libc::c_int as size_t;
        while done < extra_in_len {
            memset(
                block.as_mut_ptr() as *mut libc::c_void,
                0 as libc::c_int,
                ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
            );
            CRYPTO_chacha_20(
                block.as_mut_ptr(),
                block.as_mut_ptr(),
                ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
                key,
                nonce,
                block_counter,
            );
            let mut i: size_t = offset;
            while i < ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong
                && done < extra_in_len
            {
                *out_tag
                    .offset(
                        done as isize,
                    ) = (*extra_in.offset(done as isize) as libc::c_int
                    ^ block[i as usize] as libc::c_int) as uint8_t;
                i = i.wrapping_add(1);
                i;
                done = done.wrapping_add(1);
                done;
            }
            offset = 0 as libc::c_int as size_t;
            block_counter = block_counter.wrapping_add(1);
            block_counter;
        }
    }
    let mut data: chacha20_poly1305_seal_data = chacha20_poly1305_seal_data {
        in_0: C2RustUnnamed_3 {
            key: [0; 32],
            counter: 0,
            nonce: [0; 12],
            extra_ciphertext: 0 as *const uint8_t,
            extra_ciphertext_len: 0,
        },
    };
    if chacha20_poly1305_asm_capable() != 0 {
        OPENSSL_memcpy(
            (data.in_0.key).as_mut_ptr() as *mut libc::c_void,
            key as *const libc::c_void,
            32 as libc::c_int as size_t,
        );
        data.in_0.counter = 0 as libc::c_int as uint32_t;
        OPENSSL_memcpy(
            (data.in_0.nonce).as_mut_ptr() as *mut libc::c_void,
            nonce as *const libc::c_void,
            12 as libc::c_int as size_t,
        );
        data.in_0.extra_ciphertext = out_tag;
        data.in_0.extra_ciphertext_len = extra_in_len;
        chacha20_poly1305_seal(out, in_0, in_len, ad, ad_len, &mut data);
    } else {
        CRYPTO_chacha_20(out, in_0, in_len, key, nonce, 1 as libc::c_int as uint32_t);
        calc_tag(
            (data.out.tag).as_mut_ptr(),
            key,
            nonce,
            ad,
            ad_len,
            out,
            in_len,
            out_tag,
            extra_in_len,
        );
    }
    OPENSSL_memcpy(
        out_tag.offset(extra_in_len as isize) as *mut libc::c_void,
        (data.out.tag).as_mut_ptr() as *const libc::c_void,
        tag_len,
    );
    *out_tag_len = extra_in_len.wrapping_add(tag_len);
    return 1 as libc::c_int;
}
unsafe extern "C" fn aead_chacha20_poly1305_seal_scatter(
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
    let mut c20_ctx: *const AEAD_CHACHA_POLY_CTX = &(*ctx).state
        as *const evp_aead_ctx_st_state as *mut AEAD_CHACHA_POLY_CTX;
    return chacha20_poly1305_seal_scatter(
        ((*c20_ctx).key).as_ptr(),
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
unsafe extern "C" fn aead_xchacha20_poly1305_seal_scatter(
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
    let mut c20_ctx: *const AEAD_CHACHA_POLY_CTX = &(*ctx).state
        as *const evp_aead_ctx_st_state as *mut AEAD_CHACHA_POLY_CTX;
    if nonce_len != 24 as libc::c_int as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            121 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_chacha20poly1305.c\0"
                as *const u8 as *const libc::c_char,
            241 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut derived_key: [uint8_t; 32] = [0; 32];
    let mut derived_nonce: [uint8_t; 12] = [0; 12];
    CRYPTO_hchacha20(derived_key.as_mut_ptr(), ((*c20_ctx).key).as_ptr(), nonce);
    OPENSSL_memset(
        derived_nonce.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        4 as libc::c_int as size_t,
    );
    OPENSSL_memcpy(
        &mut *derived_nonce.as_mut_ptr().offset(4 as libc::c_int as isize)
            as *mut uint8_t as *mut libc::c_void,
        &*nonce.offset(16 as libc::c_int as isize) as *const uint8_t
            as *const libc::c_void,
        8 as libc::c_int as size_t,
    );
    return chacha20_poly1305_seal_scatter(
        derived_key.as_mut_ptr(),
        out,
        out_tag,
        out_tag_len,
        max_out_tag_len,
        derived_nonce.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 12]>() as libc::c_ulong,
        in_0,
        in_len,
        extra_in,
        extra_in_len,
        ad,
        ad_len,
        (*ctx).tag_len as size_t,
    );
}
unsafe extern "C" fn chacha20_poly1305_open_gather(
    mut key: *const uint8_t,
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
    if nonce_len != 12 as libc::c_int as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            121 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_chacha20poly1305.c\0"
                as *const u8 as *const libc::c_char,
            264 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if in_tag_len != tag_len {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_chacha20poly1305.c\0"
                as *const u8 as *const libc::c_char,
            269 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let in_len_64: uint64_t = in_len;
    if in_len_64
        >= ((1 as libc::c_ulong) << 32 as libc::c_int)
            .wrapping_mul(64 as libc::c_int as libc::c_ulong)
            .wrapping_sub(64 as libc::c_int as libc::c_ulong)
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            117 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_chacha20poly1305.c\0"
                as *const u8 as *const libc::c_char,
            281 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut data: chacha20_poly1305_open_data = chacha20_poly1305_open_data {
        in_0: C2RustUnnamed_1 {
            key: [0; 32],
            counter: 0,
            nonce: [0; 12],
        },
    };
    if chacha20_poly1305_asm_capable() != 0 {
        OPENSSL_memcpy(
            (data.in_0.key).as_mut_ptr() as *mut libc::c_void,
            key as *const libc::c_void,
            32 as libc::c_int as size_t,
        );
        data.in_0.counter = 0 as libc::c_int as uint32_t;
        OPENSSL_memcpy(
            (data.in_0.nonce).as_mut_ptr() as *mut libc::c_void,
            nonce as *const libc::c_void,
            12 as libc::c_int as size_t,
        );
        chacha20_poly1305_open(out, in_0, in_len, ad, ad_len, &mut data);
    } else {
        calc_tag(
            (data.out.tag).as_mut_ptr(),
            key,
            nonce,
            ad,
            ad_len,
            in_0,
            in_len,
            0 as *const uint8_t,
            0 as libc::c_int as size_t,
        );
        CRYPTO_chacha_20(out, in_0, in_len, key, nonce, 1 as libc::c_int as uint32_t);
    }
    if CRYPTO_memcmp(
        (data.out.tag).as_mut_ptr() as *const libc::c_void,
        in_tag as *const libc::c_void,
        tag_len,
    ) != 0 as libc::c_int
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_chacha20poly1305.c\0"
                as *const u8 as *const libc::c_char,
            297 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn aead_chacha20_poly1305_open_gather(
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
    let mut c20_ctx: *const AEAD_CHACHA_POLY_CTX = &(*ctx).state
        as *const evp_aead_ctx_st_state as *mut AEAD_CHACHA_POLY_CTX;
    return chacha20_poly1305_open_gather(
        ((*c20_ctx).key).as_ptr(),
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
    );
}
unsafe extern "C" fn aead_xchacha20_poly1305_open_gather(
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
    let mut c20_ctx: *const AEAD_CHACHA_POLY_CTX = &(*ctx).state
        as *const evp_aead_ctx_st_state as *mut AEAD_CHACHA_POLY_CTX;
    if nonce_len != 24 as libc::c_int as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            121 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_chacha20poly1305.c\0"
                as *const u8 as *const libc::c_char,
            324 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut derived_key: [uint8_t; 32] = [0; 32];
    let mut derived_nonce: [uint8_t; 12] = [0; 12];
    CRYPTO_hchacha20(derived_key.as_mut_ptr(), ((*c20_ctx).key).as_ptr(), nonce);
    OPENSSL_memset(
        derived_nonce.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        4 as libc::c_int as size_t,
    );
    OPENSSL_memcpy(
        &mut *derived_nonce.as_mut_ptr().offset(4 as libc::c_int as isize)
            as *mut uint8_t as *mut libc::c_void,
        &*nonce.offset(16 as libc::c_int as isize) as *const uint8_t
            as *const libc::c_void,
        8 as libc::c_int as size_t,
    );
    return chacha20_poly1305_open_gather(
        derived_key.as_mut_ptr(),
        out,
        derived_nonce.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 12]>() as libc::c_ulong,
        in_0,
        in_len,
        in_tag,
        in_tag_len,
        ad,
        ad_len,
        (*ctx).tag_len as size_t,
    );
}
static mut aead_chacha20_poly1305: EVP_AEAD = unsafe {
    {
        let mut init = evp_aead_st {
            key_len: 32 as libc::c_int as uint8_t,
            nonce_len: 12 as libc::c_int as uint8_t,
            overhead: 16 as libc::c_int as uint8_t,
            max_tag_len: 16 as libc::c_int as uint8_t,
            aead_id: 5 as libc::c_int as uint16_t,
            seal_scatter_supports_extra_in: 1 as libc::c_int,
            init: Some(
                aead_chacha20_poly1305_init
                    as unsafe extern "C" fn(
                        *mut EVP_AEAD_CTX,
                        *const uint8_t,
                        size_t,
                        size_t,
                    ) -> libc::c_int,
            ),
            init_with_direction: None,
            cleanup: Some(
                aead_chacha20_poly1305_cleanup
                    as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
            ),
            open: None,
            seal_scatter: Some(
                aead_chacha20_poly1305_seal_scatter
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
                aead_chacha20_poly1305_open_gather
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
static mut aead_xchacha20_poly1305: EVP_AEAD = unsafe {
    {
        let mut init = evp_aead_st {
            key_len: 32 as libc::c_int as uint8_t,
            nonce_len: 24 as libc::c_int as uint8_t,
            overhead: 16 as libc::c_int as uint8_t,
            max_tag_len: 16 as libc::c_int as uint8_t,
            aead_id: 6 as libc::c_int as uint16_t,
            seal_scatter_supports_extra_in: 1 as libc::c_int,
            init: Some(
                aead_chacha20_poly1305_init
                    as unsafe extern "C" fn(
                        *mut EVP_AEAD_CTX,
                        *const uint8_t,
                        size_t,
                        size_t,
                    ) -> libc::c_int,
            ),
            init_with_direction: None,
            cleanup: Some(
                aead_chacha20_poly1305_cleanup
                    as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
            ),
            open: None,
            seal_scatter: Some(
                aead_xchacha20_poly1305_seal_scatter
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
                aead_xchacha20_poly1305_open_gather
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aead_chacha20_poly1305() -> *const EVP_AEAD {
    return &aead_chacha20_poly1305;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aead_xchacha20_poly1305() -> *const EVP_AEAD {
    return &aead_xchacha20_poly1305;
}
unsafe extern "C" fn cipher_chacha20_poly1305_init_key(
    mut ctx: *mut CIPHER_CHACHA_POLY_CTX,
    mut user_key: *const uint8_t,
    mut counter_nonce: *const uint8_t,
) -> libc::c_int {
    let mut key: *mut CIPHER_CHACHA_KEY = &mut (*ctx).key;
    let mut i: uint32_t = 0;
    if !user_key.is_null() {
        i = 0 as libc::c_int as uint32_t;
        while i < (32 as libc::c_int / 4 as libc::c_int) as uint32_t {
            (*key)
                .key[i
                as usize] = CRYPTO_load_u32_le(
                user_key.offset((i * 4 as libc::c_int as uint32_t) as isize)
                    as *const libc::c_void,
            );
            i = i.wrapping_add(1);
            i;
        }
    }
    if !counter_nonce.is_null() {
        i = 0 as libc::c_int as uint32_t;
        while i < (16 as libc::c_int / 4 as libc::c_int) as uint32_t {
            (*key)
                .counter_nonce[i
                as usize] = CRYPTO_load_u32_le(
                counter_nonce.offset((i * 4 as libc::c_int as uint32_t) as isize)
                    as *const libc::c_void,
            );
            i = i.wrapping_add(1);
            i;
        }
    }
    (*key).partial_len = 0 as libc::c_int as uint32_t;
    return 1 as libc::c_int;
}
unsafe extern "C" fn cipher_chacha20_poly1305_init(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut key: *const uint8_t,
    mut iv: *const uint8_t,
    mut enc: int32_t,
) -> libc::c_int {
    let mut cipher_ctx: *mut CIPHER_CHACHA_POLY_CTX = (*ctx).cipher_data
        as *mut CIPHER_CHACHA_POLY_CTX;
    (*cipher_ctx).len.aad = 0 as libc::c_int as uint64_t;
    (*cipher_ctx).len.text = 0 as libc::c_int as uint64_t;
    (*cipher_ctx).pad_aad = 0 as libc::c_int;
    (*cipher_ctx).poly_initialized = 0 as libc::c_int;
    if key.is_null() && iv.is_null() {
        return 1 as libc::c_int;
    }
    if !iv.is_null() {
        let mut counter_nonce: [uint8_t; 16] = [
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
        OPENSSL_memcpy(
            counter_nonce
                .as_mut_ptr()
                .offset(16 as libc::c_int as isize)
                .offset(-(12 as libc::c_int as isize)) as *mut libc::c_void,
            iv as *const libc::c_void,
            12 as libc::c_int as size_t,
        );
        cipher_chacha20_poly1305_init_key(
            cipher_ctx,
            key,
            counter_nonce.as_mut_ptr() as *const uint8_t,
        );
        (*cipher_ctx)
            .iv[0 as libc::c_int
            as usize] = (*cipher_ctx).key.counter_nonce[1 as libc::c_int as usize];
        (*cipher_ctx)
            .iv[1 as libc::c_int
            as usize] = (*cipher_ctx).key.counter_nonce[2 as libc::c_int as usize];
        (*cipher_ctx)
            .iv[2 as libc::c_int
            as usize] = (*cipher_ctx).key.counter_nonce[3 as libc::c_int as usize];
    } else {
        cipher_chacha20_poly1305_init_key(cipher_ctx, key, 0 as *const uint8_t);
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn cipher_chacha20_do_cipher(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
) -> libc::c_int {
    let mut cipher_ctx: *mut CIPHER_CHACHA_POLY_CTX = (*ctx).cipher_data
        as *mut CIPHER_CHACHA_POLY_CTX;
    let mut key: *mut CIPHER_CHACHA_KEY = &mut (*cipher_ctx).key;
    let mut n: uint32_t = 0;
    let mut rem: uint32_t = 0;
    let mut counter: uint32_t = 0;
    n = (*key).partial_len;
    if n != 0 {
        while in_len != 0 && n < 64 as libc::c_int as uint32_t {
            let fresh0 = in_0;
            in_0 = in_0.offset(1);
            let fresh1 = n;
            n = n.wrapping_add(1);
            let fresh2 = out;
            out = out.offset(1);
            *fresh2 = (*fresh0 as libc::c_int
                ^ (*key).buf[fresh1 as usize] as libc::c_int) as uint8_t;
            in_len = in_len.wrapping_sub(1);
            in_len;
        }
        (*key).partial_len = n;
        if in_len == 0 as libc::c_int as size_t {
            return 1 as libc::c_int;
        }
        if n == 64 as libc::c_int as uint32_t {
            (*key).partial_len = 0 as libc::c_int as uint32_t;
            (*key)
                .counter_nonce[0 as libc::c_int
                as usize] = ((*key).counter_nonce[0 as libc::c_int as usize])
                .wrapping_add(1);
            (*key).counter_nonce[0 as libc::c_int as usize];
        }
    }
    let mut chacha_key: *const uint8_t = ((*cipher_ctx).key.key).as_mut_ptr()
        as *const uint8_t;
    let mut nonce: *const uint8_t = ((*cipher_ctx).iv).as_mut_ptr() as *const uint8_t;
    rem = (in_len % 64 as libc::c_int as size_t) as uint32_t;
    in_len = in_len.wrapping_sub(rem as size_t);
    counter = (*key).counter_nonce[0 as libc::c_int as usize];
    while in_len >= 64 as libc::c_int as size_t {
        let mut blocks: size_t = in_len / 64 as libc::c_int as size_t;
        if ::core::mem::size_of::<size_t>() as libc::c_ulong
            > ::core::mem::size_of::<uint32_t>() as libc::c_ulong
            && blocks > ((1 as libc::c_uint) << 28 as libc::c_int) as size_t
        {
            blocks = ((1 as libc::c_uint) << 28 as libc::c_int) as size_t;
        }
        counter = counter.wrapping_add(blocks as uint32_t);
        if (counter as size_t) < blocks {
            blocks = blocks.wrapping_sub(counter as size_t);
            counter = 0 as libc::c_int as uint32_t;
        }
        blocks = blocks * 64 as libc::c_int as size_t;
        CRYPTO_chacha_20(
            out,
            in_0,
            blocks,
            chacha_key,
            nonce,
            (*key).counter_nonce[0 as libc::c_int as usize],
        );
        in_len = in_len.wrapping_sub(blocks);
        in_0 = in_0.offset(blocks as isize);
        out = out.offset(blocks as isize);
        (*key).counter_nonce[0 as libc::c_int as usize] = counter;
    }
    if rem != 0 {
        OPENSSL_memset(
            ((*key).buf).as_mut_ptr() as *mut libc::c_void,
            0 as libc::c_int,
            ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
        );
        CRYPTO_chacha_20(
            ((*key).buf).as_mut_ptr(),
            ((*key).buf).as_mut_ptr(),
            64 as libc::c_int as size_t,
            chacha_key,
            nonce,
            (*key).counter_nonce[0 as libc::c_int as usize],
        );
        n = 0 as libc::c_int as uint32_t;
        while n < rem {
            *out
                .offset(
                    n as isize,
                ) = (*in_0.offset(n as isize) as libc::c_int
                ^ (*key).buf[n as usize] as libc::c_int) as uint8_t;
            n = n.wrapping_add(1);
            n;
        }
        (*key).partial_len = rem;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn cipher_chacha20_poly1305_do_cipher(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut libc::c_uchar,
    mut in_0: *const libc::c_uchar,
    mut in_len: size_t,
) -> libc::c_int {
    let mut cipher_ctx: *mut CIPHER_CHACHA_POLY_CTX = (*ctx).cipher_data
        as *mut CIPHER_CHACHA_POLY_CTX;
    let mut poly_ctx: *mut poly1305_state = &mut (*cipher_ctx).poly_ctx;
    let mut remainder: size_t = 0;
    if (*cipher_ctx).poly_initialized == 0 {
        let mut chacha_key: *const uint8_t = ((*cipher_ctx).key.key).as_mut_ptr()
            as *const uint8_t;
        let mut nonce: *const uint8_t = ((*cipher_ctx).iv).as_mut_ptr()
            as *const uint8_t;
        let mut poly1305_key: [uint8_t; 32] = [0; 32];
        OPENSSL_memset(
            poly1305_key.as_mut_ptr() as *mut libc::c_void,
            0 as libc::c_int,
            ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
        );
        CRYPTO_chacha_20(
            poly1305_key.as_mut_ptr(),
            poly1305_key.as_mut_ptr(),
            ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
            chacha_key,
            nonce,
            0 as libc::c_int as uint32_t,
        );
        CRYPTO_poly1305_init(poly_ctx, poly1305_key.as_mut_ptr() as *const uint8_t);
        (*cipher_ctx)
            .key
            .counter_nonce[0 as libc::c_int as usize] = 1 as libc::c_int as uint32_t;
        (*cipher_ctx).key.partial_len = 0 as libc::c_int as uint32_t;
        (*cipher_ctx).len.aad = 0 as libc::c_int as uint64_t;
        (*cipher_ctx).len.text = 0 as libc::c_int as uint64_t;
        (*cipher_ctx).poly_initialized = 1 as libc::c_int;
    }
    if !in_0.is_null() {
        if out.is_null() {
            CRYPTO_poly1305_update(poly_ctx, in_0, in_len);
            (*cipher_ctx)
                .len
                .aad = ((*cipher_ctx).len.aad as libc::c_ulong).wrapping_add(in_len)
                as uint64_t as uint64_t;
            (*cipher_ctx).pad_aad = 1 as libc::c_int;
            return in_len as int32_t;
        } else {
            if (*cipher_ctx).pad_aad != 0 {
                remainder = (*cipher_ctx).len.aad % 16 as libc::c_int as uint64_t;
                if remainder != 0 as libc::c_int as size_t {
                    static mut padding: [uint8_t; 16] = [
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
                    CRYPTO_poly1305_update(
                        poly_ctx,
                        padding.as_ptr(),
                        (::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong)
                            .wrapping_sub(remainder),
                    );
                }
                (*cipher_ctx).pad_aad = 0 as libc::c_int;
            }
            if EVP_CIPHER_CTX_encrypting(ctx) != 0 {
                cipher_chacha20_do_cipher(ctx, out, in_0, in_len);
                CRYPTO_poly1305_update(poly_ctx, out, in_len);
                (*cipher_ctx)
                    .len
                    .text = ((*cipher_ctx).len.text as libc::c_ulong)
                    .wrapping_add(in_len) as uint64_t as uint64_t;
            } else {
                CRYPTO_poly1305_update(poly_ctx, in_0, in_len);
                cipher_chacha20_do_cipher(ctx, out, in_0, in_len);
                (*cipher_ctx)
                    .len
                    .text = ((*cipher_ctx).len.text as libc::c_ulong)
                    .wrapping_add(in_len) as uint64_t as uint64_t;
            }
        }
    }
    if in_0.is_null() {
        let mut temp: [uint8_t; 16] = [0; 16];
        static mut padding_0: [uint8_t; 16] = [
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
        if (*cipher_ctx).pad_aad != 0 {
            remainder = (*cipher_ctx).len.aad % 16 as libc::c_int as uint64_t;
            if remainder != 0 as libc::c_int as size_t {
                CRYPTO_poly1305_update(
                    poly_ctx,
                    padding_0.as_ptr(),
                    (::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong)
                        .wrapping_sub(remainder),
                );
            }
            (*cipher_ctx).pad_aad = 0 as libc::c_int;
        }
        remainder = (*cipher_ctx).len.text % 16 as libc::c_int as uint64_t;
        if remainder != 0 as libc::c_int as size_t {
            CRYPTO_poly1305_update(
                poly_ctx,
                padding_0.as_ptr(),
                (::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong)
                    .wrapping_sub(remainder),
            );
        }
        let mut length_bytes: *const uint8_t = &mut (*cipher_ctx).len
            as *mut C2RustUnnamed_4 as *const uint8_t;
        CRYPTO_poly1305_update(
            poly_ctx,
            length_bytes,
            (2 as libc::c_int as libc::c_ulong)
                .wrapping_mul(::core::mem::size_of::<uint64_t>() as libc::c_ulong),
        );
        CRYPTO_poly1305_finish(
            poly_ctx,
            if EVP_CIPHER_CTX_encrypting(ctx) != 0 {
                ((*cipher_ctx).tag).as_mut_ptr()
            } else {
                temp.as_mut_ptr()
            },
        );
        (*cipher_ctx).poly_initialized = 0 as libc::c_int;
        if EVP_CIPHER_CTX_encrypting(ctx) == 0 {
            if CRYPTO_memcmp(
                temp.as_mut_ptr() as *const libc::c_void,
                ((*cipher_ctx).tag).as_mut_ptr() as *const libc::c_void,
                (*cipher_ctx).tag_len as size_t,
            ) != 0
            {
                return -(1 as libc::c_int);
            }
        }
    }
    return in_len as int32_t;
}
unsafe extern "C" fn cipher_chacha20_poly1305_cleanup(mut ctx: *mut EVP_CIPHER_CTX) {
    if !((*ctx).cipher_data).is_null() {
        OPENSSL_cleanse(
            (*ctx).cipher_data,
            ::core::mem::size_of::<CIPHER_CHACHA_POLY_CTX>() as libc::c_ulong,
        );
    }
}
unsafe extern "C" fn cipher_chacha20_poly1305_ctrl(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut type_0: int32_t,
    mut arg: int32_t,
    mut ptr: *mut libc::c_void,
) -> int32_t {
    let mut cipher_ctx: *mut CIPHER_CHACHA_POLY_CTX = (*ctx).cipher_data
        as *mut CIPHER_CHACHA_POLY_CTX;
    match type_0 {
        0 => {
            if cipher_ctx.is_null() {
                (*ctx).cipher_data = OPENSSL_zalloc((*(*ctx).cipher).ctx_size as size_t);
                cipher_ctx = (*ctx).cipher_data as *mut CIPHER_CHACHA_POLY_CTX;
                if cipher_ctx.is_null() {
                    ERR_put_error(
                        30 as libc::c_int,
                        0 as libc::c_int,
                        107 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_chacha20poly1305.c\0"
                            as *const u8 as *const libc::c_char,
                        669 as libc::c_int as libc::c_uint,
                    );
                    return 0 as libc::c_int;
                }
            } else {
                (*cipher_ctx).len.aad = 0 as libc::c_int as uint64_t;
                (*cipher_ctx).len.text = 0 as libc::c_int as uint64_t;
                (*cipher_ctx).pad_aad = 0 as libc::c_int;
                (*cipher_ctx).poly_initialized = 0 as libc::c_int;
                (*cipher_ctx).tag_len = 0 as libc::c_int as uint8_t;
            }
            return 1 as libc::c_int;
        }
        8 => {
            if !cipher_ctx.is_null() && (*cipher_ctx).poly_initialized != 0 {
                let mut dst: *mut EVP_CIPHER_CTX = ptr as *mut EVP_CIPHER_CTX;
                let mut source_base: *mut libc::c_void = align_pointer(
                    &mut (*((*ctx).cipher_data as *mut CIPHER_CHACHA_POLY_CTX)).poly_ctx
                        as *mut poly1305_state as *mut libc::c_void,
                    64 as libc::c_int as size_t,
                );
                let mut dest_base: *mut libc::c_void = align_pointer(
                    &mut (*((*dst).cipher_data as *mut CIPHER_CHACHA_POLY_CTX)).poly_ctx
                        as *mut poly1305_state as *mut libc::c_void,
                    64 as libc::c_int as size_t,
                );
                let mut length: size_t = (::core::mem::size_of::<poly1305_state>()
                    as libc::c_ulong)
                    .wrapping_sub(63 as libc::c_int as libc::c_ulong);
                OPENSSL_memcpy(dest_base, source_base, length);
            }
            return 1 as libc::c_int;
        }
        9 => {
            if arg != 12 as libc::c_int {
                return 0 as libc::c_int;
            }
            return 1 as libc::c_int;
        }
        16 => {
            if arg <= 0 as libc::c_int || arg > 16 as libc::c_int
                || EVP_CIPHER_CTX_encrypting(ctx) == 0
            {
                return 0 as libc::c_int;
            }
            OPENSSL_memcpy(
                ptr,
                ((*cipher_ctx).tag).as_mut_ptr() as *const libc::c_void,
                arg as size_t,
            );
            return 1 as libc::c_int;
        }
        17 => {
            if arg <= 0 as libc::c_int || arg > 16 as libc::c_int
                || EVP_CIPHER_CTX_encrypting(ctx) != 0
            {
                return 0 as libc::c_int;
            }
            if !ptr.is_null() {
                OPENSSL_memcpy(
                    ((*cipher_ctx).tag).as_mut_ptr() as *mut libc::c_void,
                    ptr,
                    arg as size_t,
                );
                (*cipher_ctx).tag_len = arg as uint8_t;
            }
            return 1 as libc::c_int;
        }
        _ => return -(1 as libc::c_int),
    };
}
static mut cipher_chacha20_poly1305: EVP_CIPHER = unsafe {
    {
        let mut init = evp_cipher_st {
            nid: 950 as libc::c_int,
            block_size: 1 as libc::c_int as libc::c_uint,
            key_len: 32 as libc::c_int as libc::c_uint,
            iv_len: 12 as libc::c_int as libc::c_uint,
            ctx_size: ::core::mem::size_of::<CIPHER_CHACHA_POLY_CTX>() as libc::c_ulong
                as libc::c_uint,
            flags: (0x800 as libc::c_int | 0x100 as libc::c_int | 0x80 as libc::c_int
                | 0x200 as libc::c_int | 0x1000 as libc::c_int | 0x400 as libc::c_int)
                as uint32_t,
            init: Some(
                cipher_chacha20_poly1305_init
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *const uint8_t,
                        *const uint8_t,
                        int32_t,
                    ) -> libc::c_int,
            ),
            cipher: Some(
                cipher_chacha20_poly1305_do_cipher
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *mut libc::c_uchar,
                        *const libc::c_uchar,
                        size_t,
                    ) -> libc::c_int,
            ),
            cleanup: Some(
                cipher_chacha20_poly1305_cleanup
                    as unsafe extern "C" fn(*mut EVP_CIPHER_CTX) -> (),
            ),
            ctrl: Some(
                cipher_chacha20_poly1305_ctrl
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        int32_t,
                        int32_t,
                        *mut libc::c_void,
                    ) -> int32_t,
            ),
        };
        init
    }
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_chacha20_poly1305() -> *const EVP_CIPHER {
    return &mut cipher_chacha20_poly1305;
}
