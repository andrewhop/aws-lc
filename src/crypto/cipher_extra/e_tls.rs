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
    pub type engine_st;
    pub type env_md_st;
    pub type hmac_methods_st;
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
    fn EVP_sha1() -> *const EVP_MD;
    fn EVP_sha256() -> *const EVP_MD;
    fn EVP_sha384() -> *const EVP_MD;
    fn EVP_MD_size(md: *const EVP_MD) -> size_t;
    fn EVP_AEAD_key_length(aead: *const EVP_AEAD) -> size_t;
    fn EVP_AEAD_nonce_length(aead: *const EVP_AEAD) -> size_t;
    fn EVP_des_ede3_cbc() -> *const EVP_CIPHER;
    fn EVP_aes_128_cbc() -> *const EVP_CIPHER;
    fn EVP_aes_256_cbc() -> *const EVP_CIPHER;
    fn EVP_enc_null() -> *const EVP_CIPHER;
    fn EVP_CIPHER_CTX_init(ctx: *mut EVP_CIPHER_CTX);
    fn EVP_CIPHER_CTX_cleanup(ctx: *mut EVP_CIPHER_CTX) -> libc::c_int;
    fn EVP_CipherInit_ex(
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        engine: *mut ENGINE,
        key: *const uint8_t,
        iv: *const uint8_t,
        enc: libc::c_int,
    ) -> libc::c_int;
    fn EVP_EncryptInit_ex(
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        impl_0: *mut ENGINE,
        key: *const uint8_t,
        iv: *const uint8_t,
    ) -> libc::c_int;
    fn EVP_DecryptInit_ex(
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        impl_0: *mut ENGINE,
        key: *const uint8_t,
        iv: *const uint8_t,
    ) -> libc::c_int;
    fn EVP_EncryptUpdate(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut uint8_t,
        out_len: *mut libc::c_int,
        in_0: *const uint8_t,
        in_len: libc::c_int,
    ) -> libc::c_int;
    fn EVP_EncryptFinal_ex(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut uint8_t,
        out_len: *mut libc::c_int,
    ) -> libc::c_int;
    fn EVP_DecryptUpdate(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut uint8_t,
        out_len: *mut libc::c_int,
        in_0: *const uint8_t,
        in_len: libc::c_int,
    ) -> libc::c_int;
    fn EVP_DecryptFinal_ex(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut uint8_t,
        out_len: *mut libc::c_int,
    ) -> libc::c_int;
    fn EVP_CIPHER_CTX_block_size(ctx: *const EVP_CIPHER_CTX) -> libc::c_uint;
    fn EVP_CIPHER_CTX_iv_length(ctx: *const EVP_CIPHER_CTX) -> libc::c_uint;
    fn EVP_CIPHER_CTX_mode(ctx: *const EVP_CIPHER_CTX) -> uint32_t;
    fn EVP_CIPHER_CTX_set_padding(
        ctx: *mut EVP_CIPHER_CTX,
        pad: libc::c_int,
    ) -> libc::c_int;
    fn EVP_CIPHER_key_length(cipher: *const EVP_CIPHER) -> libc::c_uint;
    fn EVP_CIPHER_iv_length(cipher: *const EVP_CIPHER) -> libc::c_uint;
    fn HMAC_CTX_init(ctx: *mut HMAC_CTX);
    fn HMAC_CTX_cleanup(ctx: *mut HMAC_CTX);
    fn HMAC_Init_ex(
        ctx: *mut HMAC_CTX,
        key: *const libc::c_void,
        key_len: size_t,
        md: *const EVP_MD,
        impl_0: *mut ENGINE,
    ) -> libc::c_int;
    fn HMAC_Update(
        ctx: *mut HMAC_CTX,
        data: *const uint8_t,
        data_len: size_t,
    ) -> libc::c_int;
    fn HMAC_Final(
        ctx: *mut HMAC_CTX,
        out: *mut uint8_t,
        out_len: *mut libc::c_uint,
    ) -> libc::c_int;
    fn HMAC_size(ctx: *const HMAC_CTX) -> size_t;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
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
    fn EVP_tls_cbc_remove_padding(
        out_padding_ok: *mut crypto_word_t,
        out_len: *mut size_t,
        in_0: *const uint8_t,
        in_len: size_t,
        block_size: size_t,
        mac_size: size_t,
    ) -> libc::c_int;
    fn EVP_tls_cbc_copy_mac(
        out: *mut uint8_t,
        md_size: size_t,
        in_0: *const uint8_t,
        in_len: size_t,
        orig_len: size_t,
    );
    fn EVP_tls_cbc_record_digest_supported(md: *const EVP_MD) -> libc::c_int;
    fn EVP_tls_cbc_digest_record(
        md: *const EVP_MD,
        md_out: *mut uint8_t,
        md_out_size: *mut size_t,
        header: *const uint8_t,
        data: *const uint8_t,
        data_size: size_t,
        data_plus_mac_plus_padding_size: size_t,
        mac_secret: *const uint8_t,
        mac_secret_length: libc::c_uint,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __int8_t = libc::c_schar;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type int8_t = __int8_t;
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
pub type ENGINE = engine_st;
pub type EVP_MD = env_md_st;
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
pub struct hmac_ctx_st {
    pub md: *const EVP_MD,
    pub methods: *const HmacMethods,
    pub md_ctx: md_ctx_union,
    pub i_ctx: md_ctx_union,
    pub o_ctx: md_ctx_union,
    pub state: int8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union md_ctx_union {
    pub md5: MD5_CTX,
    pub sha1: SHA_CTX,
    pub sha256: SHA256_CTX,
    pub sha512: SHA512_CTX,
}
pub type SHA512_CTX = sha512_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sha512_state_st {
    pub h: [uint64_t; 8],
    pub Nl: uint64_t,
    pub Nh: uint64_t,
    pub p: [uint8_t; 128],
    pub num: libc::c_uint,
    pub md_len: libc::c_uint,
}
pub type SHA256_CTX = sha256_state_st;
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
pub type SHA_CTX = sha_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sha_state_st {
    pub h: [uint32_t; 5],
    pub Nl: uint32_t,
    pub Nh: uint32_t,
    pub data: [uint8_t; 64],
    pub num: libc::c_uint,
}
pub type MD5_CTX = md5_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct md5_state_st {
    pub h: [uint32_t; 4],
    pub Nl: uint32_t,
    pub Nh: uint32_t,
    pub data: [uint8_t; 64],
    pub num: libc::c_uint,
}
pub type HmacMethods = hmac_methods_st;
pub type HMAC_CTX = hmac_ctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct AEAD_TLS_CTX {
    pub cipher_ctx: EVP_CIPHER_CTX,
    pub hmac_ctx: HMAC_CTX,
    pub mac_key: [uint8_t; 64],
    pub mac_key_len: uint8_t,
    pub implicit_iv: libc::c_char,
}
pub type crypto_word_t = uint64_t;
#[inline]
unsafe extern "C" fn constant_time_msb_w(mut a: crypto_word_t) -> crypto_word_t {
    return (0 as libc::c_uint as crypto_word_t)
        .wrapping_sub(
            a
                >> (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        );
}
#[inline]
unsafe extern "C" fn constant_time_is_zero_w(mut a: crypto_word_t) -> crypto_word_t {
    return constant_time_msb_w(!a & a.wrapping_sub(1 as libc::c_int as crypto_word_t));
}
#[inline]
unsafe extern "C" fn constant_time_eq_w(
    mut a: crypto_word_t,
    mut b: crypto_word_t,
) -> crypto_word_t {
    return constant_time_is_zero_w(a ^ b);
}
#[inline]
unsafe extern "C" fn constant_time_eq_int(
    mut a: libc::c_int,
    mut b: libc::c_int,
) -> crypto_word_t {
    return constant_time_eq_w(a as crypto_word_t, b as crypto_word_t);
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
unsafe extern "C" fn aead_tls_cleanup(mut ctx: *mut EVP_AEAD_CTX) {
    let mut tls_ctx: *mut AEAD_TLS_CTX = (*ctx).state.ptr as *mut AEAD_TLS_CTX;
    EVP_CIPHER_CTX_cleanup(&mut (*tls_ctx).cipher_ctx);
    HMAC_CTX_cleanup(&mut (*tls_ctx).hmac_ctx);
    OPENSSL_free(tls_ctx as *mut libc::c_void);
    (*ctx).state.ptr = 0 as *mut libc::c_void;
}
unsafe extern "C" fn aead_tls_init(
    mut ctx: *mut EVP_AEAD_CTX,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut tag_len: size_t,
    mut dir: evp_aead_direction_t,
    mut cipher: *const EVP_CIPHER,
    mut md: *const EVP_MD,
    mut implicit_iv: libc::c_char,
) -> libc::c_int {
    if tag_len != 0 as libc::c_int as size_t && tag_len != EVP_MD_size(md) {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            122 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                as *const u8 as *const libc::c_char,
            61 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if key_len != EVP_AEAD_key_length((*ctx).aead) {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                as *const u8 as *const libc::c_char,
            66 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut mac_key_len: size_t = EVP_MD_size(md);
    let mut enc_key_len: size_t = EVP_CIPHER_key_length(cipher) as size_t;
    if mac_key_len
        .wrapping_add(enc_key_len)
        .wrapping_add(
            (if implicit_iv as libc::c_int != 0 {
                EVP_CIPHER_iv_length(cipher)
            } else {
                0 as libc::c_int as libc::c_uint
            }) as size_t,
        ) == key_len
    {} else {
        __assert_fail(
            b"mac_key_len + enc_key_len + (implicit_iv ? EVP_CIPHER_iv_length(cipher) : 0) == key_len\0"
                as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                as *const u8 as *const libc::c_char,
            74 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 136],
                &[libc::c_char; 136],
            >(
                b"int aead_tls_init(EVP_AEAD_CTX *, const uint8_t *, size_t, size_t, enum evp_aead_direction_t, const EVP_CIPHER *, const EVP_MD *, char)\0",
            ))
                .as_ptr(),
        );
    }
    'c_4322: {
        if mac_key_len
            .wrapping_add(enc_key_len)
            .wrapping_add(
                (if implicit_iv as libc::c_int != 0 {
                    EVP_CIPHER_iv_length(cipher)
                } else {
                    0 as libc::c_int as libc::c_uint
                }) as size_t,
            ) == key_len
        {} else {
            __assert_fail(
                b"mac_key_len + enc_key_len + (implicit_iv ? EVP_CIPHER_iv_length(cipher) : 0) == key_len\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                    as *const u8 as *const libc::c_char,
                74 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 136],
                    &[libc::c_char; 136],
                >(
                    b"int aead_tls_init(EVP_AEAD_CTX *, const uint8_t *, size_t, size_t, enum evp_aead_direction_t, const EVP_CIPHER *, const EVP_MD *, char)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut tls_ctx: *mut AEAD_TLS_CTX = OPENSSL_malloc(
        ::core::mem::size_of::<AEAD_TLS_CTX>() as libc::c_ulong,
    ) as *mut AEAD_TLS_CTX;
    if tls_ctx.is_null() {
        return 0 as libc::c_int;
    }
    (*ctx).state.ptr = tls_ctx as *mut libc::c_void;
    EVP_CIPHER_CTX_init(&mut (*tls_ctx).cipher_ctx);
    HMAC_CTX_init(&mut (*tls_ctx).hmac_ctx);
    if mac_key_len <= 64 as libc::c_int as size_t {} else {
        __assert_fail(
            b"mac_key_len <= EVP_MAX_MD_SIZE\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                as *const u8 as *const libc::c_char,
            84 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 136],
                &[libc::c_char; 136],
            >(
                b"int aead_tls_init(EVP_AEAD_CTX *, const uint8_t *, size_t, size_t, enum evp_aead_direction_t, const EVP_CIPHER *, const EVP_MD *, char)\0",
            ))
                .as_ptr(),
        );
    }
    'c_4245: {
        if mac_key_len <= 64 as libc::c_int as size_t {} else {
            __assert_fail(
                b"mac_key_len <= EVP_MAX_MD_SIZE\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                    as *const u8 as *const libc::c_char,
                84 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 136],
                    &[libc::c_char; 136],
                >(
                    b"int aead_tls_init(EVP_AEAD_CTX *, const uint8_t *, size_t, size_t, enum evp_aead_direction_t, const EVP_CIPHER *, const EVP_MD *, char)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    OPENSSL_memcpy(
        ((*tls_ctx).mac_key).as_mut_ptr() as *mut libc::c_void,
        key as *const libc::c_void,
        mac_key_len,
    );
    (*tls_ctx).mac_key_len = mac_key_len as uint8_t;
    (*tls_ctx).implicit_iv = implicit_iv;
    if EVP_CipherInit_ex(
        &mut (*tls_ctx).cipher_ctx,
        cipher,
        0 as *mut ENGINE,
        &*key.offset(mac_key_len as isize),
        (if implicit_iv as libc::c_int != 0 {
            &*key.offset(mac_key_len.wrapping_add(enc_key_len) as isize)
        } else {
            0 as *const uint8_t
        }),
        (dir as libc::c_uint == evp_aead_seal as libc::c_int as libc::c_uint)
            as libc::c_int,
    ) == 0
        || HMAC_Init_ex(
            &mut (*tls_ctx).hmac_ctx,
            key as *const libc::c_void,
            mac_key_len,
            md,
            0 as *mut ENGINE,
        ) == 0
    {
        aead_tls_cleanup(ctx);
        return 0 as libc::c_int;
    }
    EVP_CIPHER_CTX_set_padding(&mut (*tls_ctx).cipher_ctx, 0 as libc::c_int);
    return 1 as libc::c_int;
}
unsafe extern "C" fn aead_tls_tag_len(
    mut ctx: *const EVP_AEAD_CTX,
    in_len: size_t,
    extra_in_len: size_t,
) -> size_t {
    if extra_in_len == 0 as libc::c_int as size_t {} else {
        __assert_fail(
            b"extra_in_len == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                as *const u8 as *const libc::c_char,
            103 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 74],
                &[libc::c_char; 74],
            >(
                b"size_t aead_tls_tag_len(const EVP_AEAD_CTX *, const size_t, const size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_1962: {
        if extra_in_len == 0 as libc::c_int as size_t {} else {
            __assert_fail(
                b"extra_in_len == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                    as *const u8 as *const libc::c_char,
                103 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 74],
                    &[libc::c_char; 74],
                >(
                    b"size_t aead_tls_tag_len(const EVP_AEAD_CTX *, const size_t, const size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut tls_ctx: *const AEAD_TLS_CTX = (*ctx).state.ptr as *mut AEAD_TLS_CTX;
    let hmac_len: size_t = HMAC_size(&(*tls_ctx).hmac_ctx);
    if EVP_CIPHER_CTX_mode(&(*tls_ctx).cipher_ctx) != 0x2 as libc::c_int as uint32_t {
        return hmac_len;
    }
    let block_size: size_t = EVP_CIPHER_CTX_block_size(&(*tls_ctx).cipher_ctx) as size_t;
    if block_size != 0 as libc::c_int as size_t
        && block_size & block_size.wrapping_sub(1 as libc::c_int as size_t)
            == 0 as libc::c_int as size_t
    {} else {
        __assert_fail(
            b"block_size != 0 && (block_size & (block_size - 1)) == 0\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                as *const u8 as *const libc::c_char,
            115 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 74],
                &[libc::c_char; 74],
            >(
                b"size_t aead_tls_tag_len(const EVP_AEAD_CTX *, const size_t, const size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_1872: {
        if block_size != 0 as libc::c_int as size_t
            && block_size & block_size.wrapping_sub(1 as libc::c_int as size_t)
                == 0 as libc::c_int as size_t
        {} else {
            __assert_fail(
                b"block_size != 0 && (block_size & (block_size - 1)) == 0\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                    as *const u8 as *const libc::c_char,
                115 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 74],
                    &[libc::c_char; 74],
                >(
                    b"size_t aead_tls_tag_len(const EVP_AEAD_CTX *, const size_t, const size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let pad_len: size_t = block_size
        .wrapping_sub(in_len.wrapping_add(hmac_len) % block_size);
    return hmac_len.wrapping_add(pad_len);
}
unsafe extern "C" fn aead_tls_seal_scatter(
    mut ctx: *const EVP_AEAD_CTX,
    mut out: *mut uint8_t,
    mut out_tag: *mut uint8_t,
    mut out_tag_len: *mut size_t,
    max_out_tag_len: size_t,
    mut nonce: *const uint8_t,
    nonce_len: size_t,
    mut in_0: *const uint8_t,
    in_len: size_t,
    mut extra_in: *const uint8_t,
    extra_in_len: size_t,
    mut ad: *const uint8_t,
    ad_len: size_t,
) -> libc::c_int {
    let mut tls_ctx: *mut AEAD_TLS_CTX = (*ctx).state.ptr as *mut AEAD_TLS_CTX;
    if (*tls_ctx).cipher_ctx.encrypt == 0 {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            112 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                as *const u8 as *const libc::c_char,
            132 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if in_len > 2147483647 as libc::c_int as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            117 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                as *const u8 as *const libc::c_char,
            138 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if max_out_tag_len < aead_tls_tag_len(ctx, in_len, extra_in_len) {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            103 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                as *const u8 as *const libc::c_char,
            143 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if nonce_len != EVP_AEAD_nonce_length((*ctx).aead) {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            111 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                as *const u8 as *const libc::c_char,
            148 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ad_len != (13 as libc::c_int - 2 as libc::c_int) as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                as *const u8 as *const libc::c_char,
            153 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ad_extra: [uint8_t; 2] = [0; 2];
    ad_extra[0 as libc::c_int as usize] = (in_len >> 8 as libc::c_int) as uint8_t;
    ad_extra[1 as libc::c_int
        as usize] = (in_len & 0xff as libc::c_int as size_t) as uint8_t;
    let mut mac: [uint8_t; 64] = [0; 64];
    let mut mac_len: libc::c_uint = 0;
    if HMAC_Init_ex(
        &mut (*tls_ctx).hmac_ctx,
        0 as *const libc::c_void,
        0 as libc::c_int as size_t,
        0 as *const EVP_MD,
        0 as *mut ENGINE,
    ) == 0 || HMAC_Update(&mut (*tls_ctx).hmac_ctx, ad, ad_len) == 0
        || HMAC_Update(
            &mut (*tls_ctx).hmac_ctx,
            ad_extra.as_mut_ptr(),
            ::core::mem::size_of::<[uint8_t; 2]>() as libc::c_ulong,
        ) == 0 || HMAC_Update(&mut (*tls_ctx).hmac_ctx, in_0, in_len) == 0
        || HMAC_Final(&mut (*tls_ctx).hmac_ctx, mac.as_mut_ptr(), &mut mac_len) == 0
    {
        return 0 as libc::c_int;
    }
    if EVP_CIPHER_CTX_mode(&mut (*tls_ctx).cipher_ctx) == 0x2 as libc::c_int as uint32_t
        && (*tls_ctx).implicit_iv == 0
        && EVP_EncryptInit_ex(
            &mut (*tls_ctx).cipher_ctx,
            0 as *const EVP_CIPHER,
            0 as *mut ENGINE,
            0 as *const uint8_t,
            nonce,
        ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut len: libc::c_int = 0;
    if EVP_EncryptUpdate(
        &mut (*tls_ctx).cipher_ctx,
        out,
        &mut len,
        in_0,
        in_len as libc::c_int,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut block_size: libc::c_uint = EVP_CIPHER_CTX_block_size(
        &mut (*tls_ctx).cipher_ctx,
    );
    let early_mac_len: size_t = (block_size as size_t)
        .wrapping_sub(in_len % block_size as size_t) % block_size as size_t;
    if early_mac_len != 0 as libc::c_int as size_t {
        if ((len as libc::c_uint).wrapping_add(block_size) as size_t)
            .wrapping_sub(early_mac_len) == in_len
        {} else {
            __assert_fail(
                b"len + block_size - early_mac_len == in_len\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                    as *const u8 as *const libc::c_char,
                197 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 218],
                    &[libc::c_char; 218],
                >(
                    b"int aead_tls_seal_scatter(const EVP_AEAD_CTX *, uint8_t *, uint8_t *, size_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_2588: {
            if ((len as libc::c_uint).wrapping_add(block_size) as size_t)
                .wrapping_sub(early_mac_len) == in_len
            {} else {
                __assert_fail(
                    b"len + block_size - early_mac_len == in_len\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                        as *const u8 as *const libc::c_char,
                    197 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 218],
                        &[libc::c_char; 218],
                    >(
                        b"int aead_tls_seal_scatter(const EVP_AEAD_CTX *, uint8_t *, uint8_t *, size_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        let mut buf: [uint8_t; 32] = [0; 32];
        let mut buf_len: libc::c_int = 0;
        if EVP_EncryptUpdate(
            &mut (*tls_ctx).cipher_ctx,
            buf.as_mut_ptr(),
            &mut buf_len,
            mac.as_mut_ptr(),
            early_mac_len as libc::c_int,
        ) == 0
        {
            return 0 as libc::c_int;
        }
        if buf_len == block_size as libc::c_int {} else {
            __assert_fail(
                b"buf_len == (int)block_size\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                    as *const u8 as *const libc::c_char,
                204 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 218],
                    &[libc::c_char; 218],
                >(
                    b"int aead_tls_seal_scatter(const EVP_AEAD_CTX *, uint8_t *, uint8_t *, size_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_2525: {
            if buf_len == block_size as libc::c_int {} else {
                __assert_fail(
                    b"buf_len == (int)block_size\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                        as *const u8 as *const libc::c_char,
                    204 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 218],
                        &[libc::c_char; 218],
                    >(
                        b"int aead_tls_seal_scatter(const EVP_AEAD_CTX *, uint8_t *, uint8_t *, size_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        OPENSSL_memcpy(
            out.offset(len as isize) as *mut libc::c_void,
            buf.as_mut_ptr() as *const libc::c_void,
            (block_size as size_t).wrapping_sub(early_mac_len),
        );
        OPENSSL_memcpy(
            out_tag as *mut libc::c_void,
            buf
                .as_mut_ptr()
                .offset(block_size as isize)
                .offset(-(early_mac_len as isize)) as *const libc::c_void,
            early_mac_len,
        );
    }
    let mut tag_len: size_t = early_mac_len;
    if EVP_EncryptUpdate(
        &mut (*tls_ctx).cipher_ctx,
        out_tag.offset(tag_len as isize),
        &mut len,
        mac.as_mut_ptr().offset(tag_len as isize),
        (mac_len as size_t).wrapping_sub(tag_len) as libc::c_int,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    tag_len = tag_len.wrapping_add(len as size_t);
    if block_size > 1 as libc::c_int as libc::c_uint {
        if block_size <= 256 as libc::c_int as libc::c_uint {} else {
            __assert_fail(
                b"block_size <= 256\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                    as *const u8 as *const libc::c_char,
                217 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 218],
                    &[libc::c_char; 218],
                >(
                    b"int aead_tls_seal_scatter(const EVP_AEAD_CTX *, uint8_t *, uint8_t *, size_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_2373: {
            if block_size <= 256 as libc::c_int as libc::c_uint {} else {
                __assert_fail(
                    b"block_size <= 256\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                        as *const u8 as *const libc::c_char,
                    217 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 218],
                        &[libc::c_char; 218],
                    >(
                        b"int aead_tls_seal_scatter(const EVP_AEAD_CTX *, uint8_t *, uint8_t *, size_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        if EVP_CIPHER_CTX_mode(&mut (*tls_ctx).cipher_ctx)
            == 0x2 as libc::c_int as uint32_t
        {} else {
            __assert_fail(
                b"EVP_CIPHER_CTX_mode(&tls_ctx->cipher_ctx) == EVP_CIPH_CBC_MODE\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                    as *const u8 as *const libc::c_char,
                218 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 218],
                    &[libc::c_char; 218],
                >(
                    b"int aead_tls_seal_scatter(const EVP_AEAD_CTX *, uint8_t *, uint8_t *, size_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_2322: {
            if EVP_CIPHER_CTX_mode(&mut (*tls_ctx).cipher_ctx)
                == 0x2 as libc::c_int as uint32_t
            {} else {
                __assert_fail(
                    b"EVP_CIPHER_CTX_mode(&tls_ctx->cipher_ctx) == EVP_CIPH_CBC_MODE\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                        as *const u8 as *const libc::c_char,
                    218 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 218],
                        &[libc::c_char; 218],
                    >(
                        b"int aead_tls_seal_scatter(const EVP_AEAD_CTX *, uint8_t *, uint8_t *, size_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        let mut padding: [uint8_t; 256] = [0; 256];
        let mut padding_len: libc::c_uint = (block_size as size_t)
            .wrapping_sub(in_len.wrapping_add(mac_len as size_t) % block_size as size_t)
            as libc::c_uint;
        OPENSSL_memset(
            padding.as_mut_ptr() as *mut libc::c_void,
            padding_len.wrapping_sub(1 as libc::c_int as libc::c_uint) as libc::c_int,
            padding_len as size_t,
        );
        if EVP_EncryptUpdate(
            &mut (*tls_ctx).cipher_ctx,
            out_tag.offset(tag_len as isize),
            &mut len,
            padding.as_mut_ptr(),
            padding_len as libc::c_int,
        ) == 0
        {
            return 0 as libc::c_int;
        }
        tag_len = tag_len.wrapping_add(len as size_t);
    }
    if EVP_EncryptFinal_ex(
        &mut (*tls_ctx).cipher_ctx,
        out_tag.offset(tag_len as isize),
        &mut len,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    if len == 0 as libc::c_int {} else {
        __assert_fail(
            b"len == 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                as *const u8 as *const libc::c_char,
            234 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 218],
                &[libc::c_char; 218],
            >(
                b"int aead_tls_seal_scatter(const EVP_AEAD_CTX *, uint8_t *, uint8_t *, size_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2149: {
        if len == 0 as libc::c_int {} else {
            __assert_fail(
                b"len == 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                    as *const u8 as *const libc::c_char,
                234 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 218],
                    &[libc::c_char; 218],
                >(
                    b"int aead_tls_seal_scatter(const EVP_AEAD_CTX *, uint8_t *, uint8_t *, size_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if tag_len == aead_tls_tag_len(ctx, in_len, extra_in_len) {} else {
        __assert_fail(
            b"tag_len == aead_tls_tag_len(ctx, in_len, extra_in_len)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                as *const u8 as *const libc::c_char,
            235 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 218],
                &[libc::c_char; 218],
            >(
                b"int aead_tls_seal_scatter(const EVP_AEAD_CTX *, uint8_t *, uint8_t *, size_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2095: {
        if tag_len == aead_tls_tag_len(ctx, in_len, extra_in_len) {} else {
            __assert_fail(
                b"tag_len == aead_tls_tag_len(ctx, in_len, extra_in_len)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                    as *const u8 as *const libc::c_char,
                235 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 218],
                    &[libc::c_char; 218],
                >(
                    b"int aead_tls_seal_scatter(const EVP_AEAD_CTX *, uint8_t *, uint8_t *, size_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t, const uint8_t *, const size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    *out_tag_len = tag_len;
    return 1 as libc::c_int;
}
unsafe extern "C" fn aead_tls_open(
    mut ctx: *const EVP_AEAD_CTX,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
    mut max_out_len: size_t,
    mut nonce: *const uint8_t,
    mut nonce_len: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut ad: *const uint8_t,
    mut ad_len: size_t,
) -> libc::c_int {
    let mut tls_ctx: *mut AEAD_TLS_CTX = (*ctx).state.ptr as *mut AEAD_TLS_CTX;
    if (*tls_ctx).cipher_ctx.encrypt != 0 {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            112 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                as *const u8 as *const libc::c_char,
            249 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if in_len < HMAC_size(&mut (*tls_ctx).hmac_ctx) {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                as *const u8 as *const libc::c_char,
            254 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if max_out_len < in_len {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            103 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                as *const u8 as *const libc::c_char,
            261 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if nonce_len != EVP_AEAD_nonce_length((*ctx).aead) {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            111 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                as *const u8 as *const libc::c_char,
            266 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ad_len != (13 as libc::c_int - 2 as libc::c_int) as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                as *const u8 as *const libc::c_char,
            271 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if in_len > 2147483647 as libc::c_int as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            117 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                as *const u8 as *const libc::c_char,
            277 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if EVP_CIPHER_CTX_mode(&mut (*tls_ctx).cipher_ctx) == 0x2 as libc::c_int as uint32_t
        && (*tls_ctx).implicit_iv == 0
        && EVP_DecryptInit_ex(
            &mut (*tls_ctx).cipher_ctx,
            0 as *const EVP_CIPHER,
            0 as *mut ENGINE,
            0 as *const uint8_t,
            nonce,
        ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut total: size_t = 0 as libc::c_int as size_t;
    let mut len: libc::c_int = 0;
    if EVP_DecryptUpdate(
        &mut (*tls_ctx).cipher_ctx,
        out,
        &mut len,
        in_0,
        in_len as libc::c_int,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    total = total.wrapping_add(len as size_t);
    if EVP_DecryptFinal_ex(
        &mut (*tls_ctx).cipher_ctx,
        out.offset(total as isize),
        &mut len,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    total = total.wrapping_add(len as size_t);
    if total == in_len {} else {
        __assert_fail(
            b"total == in_len\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                as *const u8 as *const libc::c_char,
            299 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 144],
                &[libc::c_char; 144],
            >(
                b"int aead_tls_open(const EVP_AEAD_CTX *, uint8_t *, size_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_3697: {
        if total == in_len {} else {
            __assert_fail(
                b"total == in_len\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                    as *const u8 as *const libc::c_char,
                299 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 144],
                    &[libc::c_char; 144],
                >(
                    b"int aead_tls_open(const EVP_AEAD_CTX *, uint8_t *, size_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut data_plus_mac_len: size_t = 0;
    let mut padding_ok: crypto_word_t = 0;
    if EVP_CIPHER_CTX_mode(&mut (*tls_ctx).cipher_ctx) == 0x2 as libc::c_int as uint32_t
    {
        if EVP_tls_cbc_remove_padding(
            &mut padding_ok,
            &mut data_plus_mac_len,
            out,
            total,
            EVP_CIPHER_CTX_block_size(&mut (*tls_ctx).cipher_ctx) as size_t,
            HMAC_size(&mut (*tls_ctx).hmac_ctx),
        ) == 0
        {
            ERR_put_error(
                30 as libc::c_int,
                0 as libc::c_int,
                101 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                    as *const u8 as *const libc::c_char,
                313 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    } else {
        padding_ok = !(0 as libc::c_int as crypto_word_t);
        data_plus_mac_len = total;
        if data_plus_mac_len >= HMAC_size(&mut (*tls_ctx).hmac_ctx) {} else {
            __assert_fail(
                b"data_plus_mac_len >= HMAC_size(&tls_ctx->hmac_ctx)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                    as *const u8 as *const libc::c_char,
                321 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 144],
                    &[libc::c_char; 144],
                >(
                    b"int aead_tls_open(const EVP_AEAD_CTX *, uint8_t *, size_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_3570: {
            if data_plus_mac_len >= HMAC_size(&mut (*tls_ctx).hmac_ctx) {} else {
                __assert_fail(
                    b"data_plus_mac_len >= HMAC_size(&tls_ctx->hmac_ctx)\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                        as *const u8 as *const libc::c_char,
                    321 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 144],
                        &[libc::c_char; 144],
                    >(
                        b"int aead_tls_open(const EVP_AEAD_CTX *, uint8_t *, size_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
    }
    let mut data_len: size_t = data_plus_mac_len
        .wrapping_sub(HMAC_size(&mut (*tls_ctx).hmac_ctx));
    let mut ad_fixed: [uint8_t; 13] = [0; 13];
    OPENSSL_memcpy(
        ad_fixed.as_mut_ptr() as *mut libc::c_void,
        ad as *const libc::c_void,
        11 as libc::c_int as size_t,
    );
    ad_fixed[11 as libc::c_int as usize] = (data_len >> 8 as libc::c_int) as uint8_t;
    ad_fixed[12 as libc::c_int
        as usize] = (data_len & 0xff as libc::c_int as size_t) as uint8_t;
    ad_len = ad_len.wrapping_add(2 as libc::c_int as size_t);
    let mut mac: [uint8_t; 64] = [0; 64];
    let mut mac_len: size_t = 0;
    let mut record_mac_tmp: [uint8_t; 64] = [0; 64];
    let mut record_mac: *mut uint8_t = 0 as *mut uint8_t;
    if EVP_CIPHER_CTX_mode(&mut (*tls_ctx).cipher_ctx) == 0x2 as libc::c_int as uint32_t
        && EVP_tls_cbc_record_digest_supported((*tls_ctx).hmac_ctx.md) != 0
    {
        if EVP_tls_cbc_digest_record(
            (*tls_ctx).hmac_ctx.md,
            mac.as_mut_ptr(),
            &mut mac_len,
            ad_fixed.as_mut_ptr() as *const uint8_t,
            out,
            data_len,
            total,
            ((*tls_ctx).mac_key).as_mut_ptr(),
            (*tls_ctx).mac_key_len as libc::c_uint,
        ) == 0
        {
            ERR_put_error(
                30 as libc::c_int,
                0 as libc::c_int,
                101 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                    as *const u8 as *const libc::c_char,
                347 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        if mac_len == HMAC_size(&mut (*tls_ctx).hmac_ctx) {} else {
            __assert_fail(
                b"mac_len == HMAC_size(&tls_ctx->hmac_ctx)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                    as *const u8 as *const libc::c_char,
                350 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 144],
                    &[libc::c_char; 144],
                >(
                    b"int aead_tls_open(const EVP_AEAD_CTX *, uint8_t *, size_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_3393: {
            if mac_len == HMAC_size(&mut (*tls_ctx).hmac_ctx) {} else {
                __assert_fail(
                    b"mac_len == HMAC_size(&tls_ctx->hmac_ctx)\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                        as *const u8 as *const libc::c_char,
                    350 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 144],
                        &[libc::c_char; 144],
                    >(
                        b"int aead_tls_open(const EVP_AEAD_CTX *, uint8_t *, size_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        record_mac = record_mac_tmp.as_mut_ptr();
        EVP_tls_cbc_copy_mac(record_mac, mac_len, out, data_plus_mac_len, total);
    } else {
        if EVP_CIPHER_CTX_mode(&mut (*tls_ctx).cipher_ctx)
            != 0x2 as libc::c_int as uint32_t
        {} else {
            __assert_fail(
                b"EVP_CIPHER_CTX_mode(&tls_ctx->cipher_ctx) != EVP_CIPH_CBC_MODE\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                    as *const u8 as *const libc::c_char,
                357 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 144],
                    &[libc::c_char; 144],
                >(
                    b"int aead_tls_open(const EVP_AEAD_CTX *, uint8_t *, size_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_3309: {
            if EVP_CIPHER_CTX_mode(&mut (*tls_ctx).cipher_ctx)
                != 0x2 as libc::c_int as uint32_t
            {} else {
                __assert_fail(
                    b"EVP_CIPHER_CTX_mode(&tls_ctx->cipher_ctx) != EVP_CIPH_CBC_MODE\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                        as *const u8 as *const libc::c_char,
                    357 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 144],
                        &[libc::c_char; 144],
                    >(
                        b"int aead_tls_open(const EVP_AEAD_CTX *, uint8_t *, size_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        let mut mac_len_u: libc::c_uint = 0;
        if HMAC_Init_ex(
            &mut (*tls_ctx).hmac_ctx,
            0 as *const libc::c_void,
            0 as libc::c_int as size_t,
            0 as *const EVP_MD,
            0 as *mut ENGINE,
        ) == 0
            || HMAC_Update(&mut (*tls_ctx).hmac_ctx, ad_fixed.as_mut_ptr(), ad_len) == 0
            || HMAC_Update(&mut (*tls_ctx).hmac_ctx, out, data_len) == 0
            || HMAC_Final(&mut (*tls_ctx).hmac_ctx, mac.as_mut_ptr(), &mut mac_len_u)
                == 0
        {
            return 0 as libc::c_int;
        }
        mac_len = mac_len_u as size_t;
        if mac_len == HMAC_size(&mut (*tls_ctx).hmac_ctx) {} else {
            __assert_fail(
                b"mac_len == HMAC_size(&tls_ctx->hmac_ctx)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                    as *const u8 as *const libc::c_char,
                368 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 144],
                    &[libc::c_char; 144],
                >(
                    b"int aead_tls_open(const EVP_AEAD_CTX *, uint8_t *, size_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_3183: {
            if mac_len == HMAC_size(&mut (*tls_ctx).hmac_ctx) {} else {
                __assert_fail(
                    b"mac_len == HMAC_size(&tls_ctx->hmac_ctx)\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                        as *const u8 as *const libc::c_char,
                    368 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 144],
                        &[libc::c_char; 144],
                    >(
                        b"int aead_tls_open(const EVP_AEAD_CTX *, uint8_t *, size_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        record_mac = &mut *out.offset(data_len as isize) as *mut uint8_t;
    }
    let mut good: crypto_word_t = constant_time_eq_int(
        CRYPTO_memcmp(
            record_mac as *const libc::c_void,
            mac.as_mut_ptr() as *const libc::c_void,
            mac_len,
        ),
        0 as libc::c_int,
    );
    good &= padding_ok;
    if good == 0 {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/e_tls.c\0"
                as *const u8 as *const libc::c_char,
            381 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    *out_len = data_len;
    return 1 as libc::c_int;
}
unsafe extern "C" fn aead_aes_128_cbc_sha1_tls_init(
    mut ctx: *mut EVP_AEAD_CTX,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut tag_len: size_t,
    mut dir: evp_aead_direction_t,
) -> libc::c_int {
    return aead_tls_init(
        ctx,
        key,
        key_len,
        tag_len,
        dir,
        EVP_aes_128_cbc(),
        EVP_sha1(),
        0 as libc::c_int as libc::c_char,
    );
}
unsafe extern "C" fn aead_aes_128_cbc_sha1_tls_implicit_iv_init(
    mut ctx: *mut EVP_AEAD_CTX,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut tag_len: size_t,
    mut dir: evp_aead_direction_t,
) -> libc::c_int {
    return aead_tls_init(
        ctx,
        key,
        key_len,
        tag_len,
        dir,
        EVP_aes_128_cbc(),
        EVP_sha1(),
        1 as libc::c_int as libc::c_char,
    );
}
unsafe extern "C" fn aead_aes_256_cbc_sha1_tls_init(
    mut ctx: *mut EVP_AEAD_CTX,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut tag_len: size_t,
    mut dir: evp_aead_direction_t,
) -> libc::c_int {
    return aead_tls_init(
        ctx,
        key,
        key_len,
        tag_len,
        dir,
        EVP_aes_256_cbc(),
        EVP_sha1(),
        0 as libc::c_int as libc::c_char,
    );
}
unsafe extern "C" fn aead_aes_256_cbc_sha1_tls_implicit_iv_init(
    mut ctx: *mut EVP_AEAD_CTX,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut tag_len: size_t,
    mut dir: evp_aead_direction_t,
) -> libc::c_int {
    return aead_tls_init(
        ctx,
        key,
        key_len,
        tag_len,
        dir,
        EVP_aes_256_cbc(),
        EVP_sha1(),
        1 as libc::c_int as libc::c_char,
    );
}
unsafe extern "C" fn aead_aes_128_cbc_sha256_tls_init(
    mut ctx: *mut EVP_AEAD_CTX,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut tag_len: size_t,
    mut dir: evp_aead_direction_t,
) -> libc::c_int {
    return aead_tls_init(
        ctx,
        key,
        key_len,
        tag_len,
        dir,
        EVP_aes_128_cbc(),
        EVP_sha256(),
        0 as libc::c_int as libc::c_char,
    );
}
unsafe extern "C" fn aead_aes_128_cbc_sha256_tls_implicit_iv_init(
    mut ctx: *mut EVP_AEAD_CTX,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut tag_len: size_t,
    mut dir: evp_aead_direction_t,
) -> libc::c_int {
    return aead_tls_init(
        ctx,
        key,
        key_len,
        tag_len,
        dir,
        EVP_aes_128_cbc(),
        EVP_sha256(),
        1 as libc::c_int as libc::c_char,
    );
}
unsafe extern "C" fn aead_aes_256_cbc_sha384_tls_init(
    mut ctx: *mut EVP_AEAD_CTX,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut tag_len: size_t,
    mut dir: evp_aead_direction_t,
) -> libc::c_int {
    return aead_tls_init(
        ctx,
        key,
        key_len,
        tag_len,
        dir,
        EVP_aes_256_cbc(),
        EVP_sha384(),
        0 as libc::c_int as libc::c_char,
    );
}
unsafe extern "C" fn aead_des_ede3_cbc_sha1_tls_init(
    mut ctx: *mut EVP_AEAD_CTX,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut tag_len: size_t,
    mut dir: evp_aead_direction_t,
) -> libc::c_int {
    return aead_tls_init(
        ctx,
        key,
        key_len,
        tag_len,
        dir,
        EVP_des_ede3_cbc(),
        EVP_sha1(),
        0 as libc::c_int as libc::c_char,
    );
}
unsafe extern "C" fn aead_des_ede3_cbc_sha1_tls_implicit_iv_init(
    mut ctx: *mut EVP_AEAD_CTX,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut tag_len: size_t,
    mut dir: evp_aead_direction_t,
) -> libc::c_int {
    return aead_tls_init(
        ctx,
        key,
        key_len,
        tag_len,
        dir,
        EVP_des_ede3_cbc(),
        EVP_sha1(),
        1 as libc::c_int as libc::c_char,
    );
}
unsafe extern "C" fn aead_tls_get_iv(
    mut ctx: *const EVP_AEAD_CTX,
    mut out_iv: *mut *const uint8_t,
    mut out_iv_len: *mut size_t,
) -> libc::c_int {
    let mut tls_ctx: *const AEAD_TLS_CTX = (*ctx).state.ptr as *mut AEAD_TLS_CTX;
    let iv_len: size_t = EVP_CIPHER_CTX_iv_length(&(*tls_ctx).cipher_ctx) as size_t;
    if iv_len <= 1 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    *out_iv = ((*tls_ctx).cipher_ctx.iv).as_ptr();
    *out_iv_len = iv_len;
    return 1 as libc::c_int;
}
unsafe extern "C" fn aead_null_sha1_tls_init(
    mut ctx: *mut EVP_AEAD_CTX,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut tag_len: size_t,
    mut dir: evp_aead_direction_t,
) -> libc::c_int {
    return aead_tls_init(
        ctx,
        key,
        key_len,
        tag_len,
        dir,
        EVP_enc_null(),
        EVP_sha1(),
        1 as libc::c_int as libc::c_char,
    );
}
static mut aead_aes_128_cbc_sha1_tls: EVP_AEAD = unsafe {
    {
        let mut init = evp_aead_st {
            key_len: (20 as libc::c_int + 16 as libc::c_int) as uint8_t,
            nonce_len: 16 as libc::c_int as uint8_t,
            overhead: (16 as libc::c_int + 20 as libc::c_int) as uint8_t,
            max_tag_len: 20 as libc::c_int as uint8_t,
            aead_id: 7 as libc::c_int as uint16_t,
            seal_scatter_supports_extra_in: 0 as libc::c_int,
            init: None,
            init_with_direction: Some(
                aead_aes_128_cbc_sha1_tls_init
                    as unsafe extern "C" fn(
                        *mut EVP_AEAD_CTX,
                        *const uint8_t,
                        size_t,
                        size_t,
                        evp_aead_direction_t,
                    ) -> libc::c_int,
            ),
            cleanup: Some(
                aead_tls_cleanup as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
            ),
            open: Some(
                aead_tls_open
                    as unsafe extern "C" fn(
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
            ),
            seal_scatter: Some(
                aead_tls_seal_scatter
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
            open_gather: None,
            get_iv: None,
            tag_len: Some(
                aead_tls_tag_len
                    as unsafe extern "C" fn(
                        *const EVP_AEAD_CTX,
                        size_t,
                        size_t,
                    ) -> size_t,
            ),
            serialize_state: None,
            deserialize_state: None,
        };
        init
    }
};
static mut aead_aes_128_cbc_sha1_tls_implicit_iv: EVP_AEAD = unsafe {
    {
        let mut init = evp_aead_st {
            key_len: (20 as libc::c_int + 16 as libc::c_int + 16 as libc::c_int)
                as uint8_t,
            nonce_len: 0 as libc::c_int as uint8_t,
            overhead: (16 as libc::c_int + 20 as libc::c_int) as uint8_t,
            max_tag_len: 20 as libc::c_int as uint8_t,
            aead_id: 8 as libc::c_int as uint16_t,
            seal_scatter_supports_extra_in: 0 as libc::c_int,
            init: None,
            init_with_direction: Some(
                aead_aes_128_cbc_sha1_tls_implicit_iv_init
                    as unsafe extern "C" fn(
                        *mut EVP_AEAD_CTX,
                        *const uint8_t,
                        size_t,
                        size_t,
                        evp_aead_direction_t,
                    ) -> libc::c_int,
            ),
            cleanup: Some(
                aead_tls_cleanup as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
            ),
            open: Some(
                aead_tls_open
                    as unsafe extern "C" fn(
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
            ),
            seal_scatter: Some(
                aead_tls_seal_scatter
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
            open_gather: None,
            get_iv: Some(
                aead_tls_get_iv
                    as unsafe extern "C" fn(
                        *const EVP_AEAD_CTX,
                        *mut *const uint8_t,
                        *mut size_t,
                    ) -> libc::c_int,
            ),
            tag_len: Some(
                aead_tls_tag_len
                    as unsafe extern "C" fn(
                        *const EVP_AEAD_CTX,
                        size_t,
                        size_t,
                    ) -> size_t,
            ),
            serialize_state: None,
            deserialize_state: None,
        };
        init
    }
};
static mut aead_aes_256_cbc_sha1_tls: EVP_AEAD = unsafe {
    {
        let mut init = evp_aead_st {
            key_len: (20 as libc::c_int + 32 as libc::c_int) as uint8_t,
            nonce_len: 16 as libc::c_int as uint8_t,
            overhead: (16 as libc::c_int + 20 as libc::c_int) as uint8_t,
            max_tag_len: 20 as libc::c_int as uint8_t,
            aead_id: 9 as libc::c_int as uint16_t,
            seal_scatter_supports_extra_in: 0 as libc::c_int,
            init: None,
            init_with_direction: Some(
                aead_aes_256_cbc_sha1_tls_init
                    as unsafe extern "C" fn(
                        *mut EVP_AEAD_CTX,
                        *const uint8_t,
                        size_t,
                        size_t,
                        evp_aead_direction_t,
                    ) -> libc::c_int,
            ),
            cleanup: Some(
                aead_tls_cleanup as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
            ),
            open: Some(
                aead_tls_open
                    as unsafe extern "C" fn(
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
            ),
            seal_scatter: Some(
                aead_tls_seal_scatter
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
            open_gather: None,
            get_iv: None,
            tag_len: Some(
                aead_tls_tag_len
                    as unsafe extern "C" fn(
                        *const EVP_AEAD_CTX,
                        size_t,
                        size_t,
                    ) -> size_t,
            ),
            serialize_state: None,
            deserialize_state: None,
        };
        init
    }
};
static mut aead_aes_256_cbc_sha1_tls_implicit_iv: EVP_AEAD = unsafe {
    {
        let mut init = evp_aead_st {
            key_len: (20 as libc::c_int + 32 as libc::c_int + 16 as libc::c_int)
                as uint8_t,
            nonce_len: 0 as libc::c_int as uint8_t,
            overhead: (16 as libc::c_int + 20 as libc::c_int) as uint8_t,
            max_tag_len: 20 as libc::c_int as uint8_t,
            aead_id: 10 as libc::c_int as uint16_t,
            seal_scatter_supports_extra_in: 0 as libc::c_int,
            init: None,
            init_with_direction: Some(
                aead_aes_256_cbc_sha1_tls_implicit_iv_init
                    as unsafe extern "C" fn(
                        *mut EVP_AEAD_CTX,
                        *const uint8_t,
                        size_t,
                        size_t,
                        evp_aead_direction_t,
                    ) -> libc::c_int,
            ),
            cleanup: Some(
                aead_tls_cleanup as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
            ),
            open: Some(
                aead_tls_open
                    as unsafe extern "C" fn(
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
            ),
            seal_scatter: Some(
                aead_tls_seal_scatter
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
            open_gather: None,
            get_iv: Some(
                aead_tls_get_iv
                    as unsafe extern "C" fn(
                        *const EVP_AEAD_CTX,
                        *mut *const uint8_t,
                        *mut size_t,
                    ) -> libc::c_int,
            ),
            tag_len: Some(
                aead_tls_tag_len
                    as unsafe extern "C" fn(
                        *const EVP_AEAD_CTX,
                        size_t,
                        size_t,
                    ) -> size_t,
            ),
            serialize_state: None,
            deserialize_state: None,
        };
        init
    }
};
static mut aead_aes_128_cbc_sha256_tls: EVP_AEAD = unsafe {
    {
        let mut init = evp_aead_st {
            key_len: (32 as libc::c_int + 16 as libc::c_int) as uint8_t,
            nonce_len: 16 as libc::c_int as uint8_t,
            overhead: (16 as libc::c_int + 32 as libc::c_int) as uint8_t,
            max_tag_len: 32 as libc::c_int as uint8_t,
            aead_id: 11 as libc::c_int as uint16_t,
            seal_scatter_supports_extra_in: 0 as libc::c_int,
            init: None,
            init_with_direction: Some(
                aead_aes_128_cbc_sha256_tls_init
                    as unsafe extern "C" fn(
                        *mut EVP_AEAD_CTX,
                        *const uint8_t,
                        size_t,
                        size_t,
                        evp_aead_direction_t,
                    ) -> libc::c_int,
            ),
            cleanup: Some(
                aead_tls_cleanup as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
            ),
            open: Some(
                aead_tls_open
                    as unsafe extern "C" fn(
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
            ),
            seal_scatter: Some(
                aead_tls_seal_scatter
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
            open_gather: None,
            get_iv: None,
            tag_len: Some(
                aead_tls_tag_len
                    as unsafe extern "C" fn(
                        *const EVP_AEAD_CTX,
                        size_t,
                        size_t,
                    ) -> size_t,
            ),
            serialize_state: None,
            deserialize_state: None,
        };
        init
    }
};
static mut aead_aes_128_cbc_sha256_tls_implicit_iv: EVP_AEAD = unsafe {
    {
        let mut init = evp_aead_st {
            key_len: (32 as libc::c_int + 16 as libc::c_int + 16 as libc::c_int)
                as uint8_t,
            nonce_len: 0 as libc::c_int as uint8_t,
            overhead: (16 as libc::c_int + 32 as libc::c_int) as uint8_t,
            max_tag_len: 32 as libc::c_int as uint8_t,
            aead_id: 12 as libc::c_int as uint16_t,
            seal_scatter_supports_extra_in: 0 as libc::c_int,
            init: None,
            init_with_direction: Some(
                aead_aes_128_cbc_sha256_tls_implicit_iv_init
                    as unsafe extern "C" fn(
                        *mut EVP_AEAD_CTX,
                        *const uint8_t,
                        size_t,
                        size_t,
                        evp_aead_direction_t,
                    ) -> libc::c_int,
            ),
            cleanup: Some(
                aead_tls_cleanup as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
            ),
            open: Some(
                aead_tls_open
                    as unsafe extern "C" fn(
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
            ),
            seal_scatter: Some(
                aead_tls_seal_scatter
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
            open_gather: None,
            get_iv: Some(
                aead_tls_get_iv
                    as unsafe extern "C" fn(
                        *const EVP_AEAD_CTX,
                        *mut *const uint8_t,
                        *mut size_t,
                    ) -> libc::c_int,
            ),
            tag_len: Some(
                aead_tls_tag_len
                    as unsafe extern "C" fn(
                        *const EVP_AEAD_CTX,
                        size_t,
                        size_t,
                    ) -> size_t,
            ),
            serialize_state: None,
            deserialize_state: None,
        };
        init
    }
};
static mut aead_aes_256_cbc_sha384_tls: EVP_AEAD = unsafe {
    {
        let mut init = evp_aead_st {
            key_len: (48 as libc::c_int + 32 as libc::c_int) as uint8_t,
            nonce_len: 16 as libc::c_int as uint8_t,
            overhead: (16 as libc::c_int + 48 as libc::c_int) as uint8_t,
            max_tag_len: 48 as libc::c_int as uint8_t,
            aead_id: 28 as libc::c_int as uint16_t,
            seal_scatter_supports_extra_in: 0 as libc::c_int,
            init: None,
            init_with_direction: Some(
                aead_aes_256_cbc_sha384_tls_init
                    as unsafe extern "C" fn(
                        *mut EVP_AEAD_CTX,
                        *const uint8_t,
                        size_t,
                        size_t,
                        evp_aead_direction_t,
                    ) -> libc::c_int,
            ),
            cleanup: Some(
                aead_tls_cleanup as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
            ),
            open: Some(
                aead_tls_open
                    as unsafe extern "C" fn(
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
            ),
            seal_scatter: Some(
                aead_tls_seal_scatter
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
            open_gather: None,
            get_iv: None,
            tag_len: Some(
                aead_tls_tag_len
                    as unsafe extern "C" fn(
                        *const EVP_AEAD_CTX,
                        size_t,
                        size_t,
                    ) -> size_t,
            ),
            serialize_state: None,
            deserialize_state: None,
        };
        init
    }
};
static mut aead_des_ede3_cbc_sha1_tls: EVP_AEAD = unsafe {
    {
        let mut init = evp_aead_st {
            key_len: (20 as libc::c_int + 24 as libc::c_int) as uint8_t,
            nonce_len: 8 as libc::c_int as uint8_t,
            overhead: (8 as libc::c_int + 20 as libc::c_int) as uint8_t,
            max_tag_len: 20 as libc::c_int as uint8_t,
            aead_id: 13 as libc::c_int as uint16_t,
            seal_scatter_supports_extra_in: 0 as libc::c_int,
            init: None,
            init_with_direction: Some(
                aead_des_ede3_cbc_sha1_tls_init
                    as unsafe extern "C" fn(
                        *mut EVP_AEAD_CTX,
                        *const uint8_t,
                        size_t,
                        size_t,
                        evp_aead_direction_t,
                    ) -> libc::c_int,
            ),
            cleanup: Some(
                aead_tls_cleanup as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
            ),
            open: Some(
                aead_tls_open
                    as unsafe extern "C" fn(
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
            ),
            seal_scatter: Some(
                aead_tls_seal_scatter
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
            open_gather: None,
            get_iv: None,
            tag_len: Some(
                aead_tls_tag_len
                    as unsafe extern "C" fn(
                        *const EVP_AEAD_CTX,
                        size_t,
                        size_t,
                    ) -> size_t,
            ),
            serialize_state: None,
            deserialize_state: None,
        };
        init
    }
};
static mut aead_des_ede3_cbc_sha1_tls_implicit_iv: EVP_AEAD = unsafe {
    {
        let mut init = evp_aead_st {
            key_len: (20 as libc::c_int + 24 as libc::c_int + 8 as libc::c_int)
                as uint8_t,
            nonce_len: 0 as libc::c_int as uint8_t,
            overhead: (8 as libc::c_int + 20 as libc::c_int) as uint8_t,
            max_tag_len: 20 as libc::c_int as uint8_t,
            aead_id: 14 as libc::c_int as uint16_t,
            seal_scatter_supports_extra_in: 0 as libc::c_int,
            init: None,
            init_with_direction: Some(
                aead_des_ede3_cbc_sha1_tls_implicit_iv_init
                    as unsafe extern "C" fn(
                        *mut EVP_AEAD_CTX,
                        *const uint8_t,
                        size_t,
                        size_t,
                        evp_aead_direction_t,
                    ) -> libc::c_int,
            ),
            cleanup: Some(
                aead_tls_cleanup as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
            ),
            open: Some(
                aead_tls_open
                    as unsafe extern "C" fn(
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
            ),
            seal_scatter: Some(
                aead_tls_seal_scatter
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
            open_gather: None,
            get_iv: Some(
                aead_tls_get_iv
                    as unsafe extern "C" fn(
                        *const EVP_AEAD_CTX,
                        *mut *const uint8_t,
                        *mut size_t,
                    ) -> libc::c_int,
            ),
            tag_len: Some(
                aead_tls_tag_len
                    as unsafe extern "C" fn(
                        *const EVP_AEAD_CTX,
                        size_t,
                        size_t,
                    ) -> size_t,
            ),
            serialize_state: None,
            deserialize_state: None,
        };
        init
    }
};
static mut aead_null_sha1_tls: EVP_AEAD = unsafe {
    {
        let mut init = evp_aead_st {
            key_len: 20 as libc::c_int as uint8_t,
            nonce_len: 0 as libc::c_int as uint8_t,
            overhead: 20 as libc::c_int as uint8_t,
            max_tag_len: 20 as libc::c_int as uint8_t,
            aead_id: 15 as libc::c_int as uint16_t,
            seal_scatter_supports_extra_in: 0 as libc::c_int,
            init: None,
            init_with_direction: Some(
                aead_null_sha1_tls_init
                    as unsafe extern "C" fn(
                        *mut EVP_AEAD_CTX,
                        *const uint8_t,
                        size_t,
                        size_t,
                        evp_aead_direction_t,
                    ) -> libc::c_int,
            ),
            cleanup: Some(
                aead_tls_cleanup as unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> (),
            ),
            open: Some(
                aead_tls_open
                    as unsafe extern "C" fn(
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
            ),
            seal_scatter: Some(
                aead_tls_seal_scatter
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
            open_gather: None,
            get_iv: None,
            tag_len: Some(
                aead_tls_tag_len
                    as unsafe extern "C" fn(
                        *const EVP_AEAD_CTX,
                        size_t,
                        size_t,
                    ) -> size_t,
            ),
            serialize_state: None,
            deserialize_state: None,
        };
        init
    }
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aead_aes_128_cbc_sha1_tls() -> *const EVP_AEAD {
    return &aead_aes_128_cbc_sha1_tls;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aead_aes_128_cbc_sha1_tls_implicit_iv() -> *const EVP_AEAD {
    return &aead_aes_128_cbc_sha1_tls_implicit_iv;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aead_aes_256_cbc_sha1_tls() -> *const EVP_AEAD {
    return &aead_aes_256_cbc_sha1_tls;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aead_aes_256_cbc_sha1_tls_implicit_iv() -> *const EVP_AEAD {
    return &aead_aes_256_cbc_sha1_tls_implicit_iv;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aead_aes_128_cbc_sha256_tls() -> *const EVP_AEAD {
    return &aead_aes_128_cbc_sha256_tls;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aead_aes_128_cbc_sha256_tls_implicit_iv() -> *const EVP_AEAD {
    return &aead_aes_128_cbc_sha256_tls_implicit_iv;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aead_aes_256_cbc_sha384_tls() -> *const EVP_AEAD {
    return &aead_aes_256_cbc_sha384_tls;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aead_des_ede3_cbc_sha1_tls() -> *const EVP_AEAD {
    return &aead_des_ede3_cbc_sha1_tls;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aead_des_ede3_cbc_sha1_tls_implicit_iv() -> *const EVP_AEAD {
    return &aead_des_ede3_cbc_sha1_tls_implicit_iv;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aead_null_sha1_tls() -> *const EVP_AEAD {
    return &aead_null_sha1_tls;
}
