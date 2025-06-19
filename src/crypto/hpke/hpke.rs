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
    pub type evp_aead_st;
    fn CBB_init(cbb: *mut CBB, initial_capacity: size_t) -> libc::c_int;
    fn CBB_init_fixed(cbb: *mut CBB, buf: *mut uint8_t, len: size_t) -> libc::c_int;
    fn CBB_cleanup(cbb: *mut CBB);
    fn CBB_finish(
        cbb: *mut CBB,
        out_data: *mut *mut uint8_t,
        out_len: *mut size_t,
    ) -> libc::c_int;
    fn CBB_data(cbb: *const CBB) -> *const uint8_t;
    fn CBB_len(cbb: *const CBB) -> size_t;
    fn CBB_add_bytes(cbb: *mut CBB, data: *const uint8_t, len: size_t) -> libc::c_int;
    fn CBB_add_u8(cbb: *mut CBB, value: uint8_t) -> libc::c_int;
    fn CBB_add_u16(cbb: *mut CBB, value: uint16_t) -> libc::c_int;
    fn EVP_sha256() -> *const EVP_MD;
    fn EVP_MD_size(md: *const EVP_MD) -> size_t;
    fn EVP_aead_aes_128_gcm() -> *const EVP_AEAD;
    fn EVP_aead_aes_256_gcm() -> *const EVP_AEAD;
    fn EVP_aead_chacha20_poly1305() -> *const EVP_AEAD;
    fn EVP_AEAD_key_length(aead: *const EVP_AEAD) -> size_t;
    fn EVP_AEAD_nonce_length(aead: *const EVP_AEAD) -> size_t;
    fn EVP_AEAD_max_overhead(aead: *const EVP_AEAD) -> size_t;
    fn EVP_AEAD_CTX_zero(ctx: *mut EVP_AEAD_CTX);
    fn EVP_AEAD_CTX_init(
        ctx: *mut EVP_AEAD_CTX,
        aead: *const EVP_AEAD,
        key: *const uint8_t,
        key_len: size_t,
        tag_len: size_t,
        impl_0: *mut ENGINE,
    ) -> libc::c_int;
    fn EVP_AEAD_CTX_cleanup(ctx: *mut EVP_AEAD_CTX);
    fn EVP_AEAD_CTX_seal(
        ctx: *const EVP_AEAD_CTX,
        out: *mut uint8_t,
        out_len: *mut size_t,
        max_out_len: size_t,
        nonce: *const uint8_t,
        nonce_len: size_t,
        in_0: *const uint8_t,
        in_len: size_t,
        ad: *const uint8_t,
        ad_len: size_t,
    ) -> libc::c_int;
    fn EVP_AEAD_CTX_open(
        ctx: *const EVP_AEAD_CTX,
        out: *mut uint8_t,
        out_len: *mut size_t,
        max_out_len: size_t,
        nonce: *const uint8_t,
        nonce_len: size_t,
        in_0: *const uint8_t,
        in_len: size_t,
        ad: *const uint8_t,
        ad_len: size_t,
    ) -> libc::c_int;
    fn EVP_AEAD_CTX_aead(ctx: *const EVP_AEAD_CTX) -> *const EVP_AEAD;
    fn RAND_bytes(buf: *mut uint8_t, len: size_t) -> libc::c_int;
    fn X25519_keypair(out_public_value: *mut uint8_t, out_private_key: *mut uint8_t);
    fn X25519(
        out_shared_key: *mut uint8_t,
        private_key: *const uint8_t,
        peer_public_value: *const uint8_t,
    ) -> libc::c_int;
    fn X25519_public_from_private(
        out_public_value: *mut uint8_t,
        private_key: *const uint8_t,
    );
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
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn HKDF_extract(
        out_key: *mut uint8_t,
        out_len: *mut size_t,
        digest: *const EVP_MD,
        secret: *const uint8_t,
        secret_len: size_t,
        salt: *const uint8_t,
        salt_len: size_t,
    ) -> libc::c_int;
    fn HKDF_expand(
        out_key: *mut uint8_t,
        out_len: size_t,
        digest: *const EVP_MD,
        prk: *const uint8_t,
        prk_len: size_t,
        info: *const uint8_t,
        info_len: size_t,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
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
pub type ENGINE = engine_st;
pub type EVP_MD = env_md_st;
pub type EVP_AEAD = evp_aead_st;
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
pub type EVP_AEAD_CTX = evp_aead_ctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_hpke_aead_st {
    pub id: uint16_t,
    pub aead_func: Option::<unsafe extern "C" fn() -> *const EVP_AEAD>,
}
pub type EVP_HPKE_AEAD = evp_hpke_aead_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_hpke_ctx_st {
    pub kem: *const EVP_HPKE_KEM,
    pub aead: *const EVP_HPKE_AEAD,
    pub kdf: *const EVP_HPKE_KDF,
    pub aead_ctx: EVP_AEAD_CTX,
    pub base_nonce: [uint8_t; 24],
    pub exporter_secret: [uint8_t; 64],
    pub seq: uint64_t,
    pub is_sender: libc::c_int,
}
pub type EVP_HPKE_KDF = evp_hpke_kdf_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_hpke_kdf_st {
    pub id: uint16_t,
    pub hkdf_md_func: Option::<unsafe extern "C" fn() -> *const EVP_MD>,
}
pub type EVP_HPKE_KEM = evp_hpke_kem_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_hpke_kem_st {
    pub id: uint16_t,
    pub public_key_len: size_t,
    pub private_key_len: size_t,
    pub seed_len: size_t,
    pub enc_len: size_t,
    pub init_key: Option::<
        unsafe extern "C" fn(*mut EVP_HPKE_KEY, *const uint8_t, size_t) -> libc::c_int,
    >,
    pub generate_key: Option::<unsafe extern "C" fn(*mut EVP_HPKE_KEY) -> libc::c_int>,
    pub encap_with_seed: Option::<
        unsafe extern "C" fn(
            *const EVP_HPKE_KEM,
            *mut uint8_t,
            *mut size_t,
            *mut uint8_t,
            *mut size_t,
            size_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub decap: Option::<
        unsafe extern "C" fn(
            *const EVP_HPKE_KEY,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub auth_encap_with_seed: Option::<
        unsafe extern "C" fn(
            *const EVP_HPKE_KEY,
            *mut uint8_t,
            *mut size_t,
            *mut uint8_t,
            *mut size_t,
            size_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub auth_decap: Option::<
        unsafe extern "C" fn(
            *const EVP_HPKE_KEY,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
}
pub type EVP_HPKE_KEY = evp_hpke_key_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_hpke_key_st {
    pub kem: *const EVP_HPKE_KEM,
    pub private_key: [uint8_t; 32],
    pub public_key: [uint8_t; 32],
}
pub type EVP_HPKE_CTX = evp_hpke_ctx_st;
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
static mut kHpkeVersionId: [libc::c_char; 8] = unsafe {
    *::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"HPKE-v1\0")
};
unsafe extern "C" fn add_label_string(
    mut cbb: *mut CBB,
    mut label: *const libc::c_char,
) -> libc::c_int {
    return CBB_add_bytes(cbb, label as *const uint8_t, strlen(label));
}
unsafe extern "C" fn hpke_labeled_extract(
    mut hkdf_md: *const EVP_MD,
    mut out_key: *mut uint8_t,
    mut out_len: *mut size_t,
    mut salt: *const uint8_t,
    mut salt_len: size_t,
    mut suite_id: *const uint8_t,
    mut suite_id_len: size_t,
    mut label: *const libc::c_char,
    mut ikm: *const uint8_t,
    mut ikm_len: size_t,
) -> libc::c_int {
    let mut labeled_ikm: CBB = cbb_st {
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
    let mut ok: libc::c_int = (CBB_init(&mut labeled_ikm, 0 as libc::c_int as size_t)
        != 0 && add_label_string(&mut labeled_ikm, kHpkeVersionId.as_ptr()) != 0
        && CBB_add_bytes(&mut labeled_ikm, suite_id, suite_id_len) != 0
        && add_label_string(&mut labeled_ikm, label) != 0
        && CBB_add_bytes(&mut labeled_ikm, ikm, ikm_len) != 0
        && HKDF_extract(
            out_key,
            out_len,
            hkdf_md,
            CBB_data(&mut labeled_ikm),
            CBB_len(&mut labeled_ikm),
            salt,
            salt_len,
        ) != 0) as libc::c_int;
    CBB_cleanup(&mut labeled_ikm);
    return ok;
}
unsafe extern "C" fn hpke_labeled_expand(
    mut hkdf_md: *const EVP_MD,
    mut out_key: *mut uint8_t,
    mut out_len: size_t,
    mut prk: *const uint8_t,
    mut prk_len: size_t,
    mut suite_id: *const uint8_t,
    mut suite_id_len: size_t,
    mut label: *const libc::c_char,
    mut info: *const uint8_t,
    mut info_len: size_t,
) -> libc::c_int {
    let mut labeled_info: CBB = cbb_st {
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
    let mut ok: libc::c_int = (CBB_init(&mut labeled_info, 0 as libc::c_int as size_t)
        != 0 && CBB_add_u16(&mut labeled_info, out_len as uint16_t) != 0
        && add_label_string(&mut labeled_info, kHpkeVersionId.as_ptr()) != 0
        && CBB_add_bytes(&mut labeled_info, suite_id, suite_id_len) != 0
        && add_label_string(&mut labeled_info, label) != 0
        && CBB_add_bytes(&mut labeled_info, info, info_len) != 0
        && HKDF_expand(
            out_key,
            out_len,
            hkdf_md,
            prk,
            prk_len,
            CBB_data(&mut labeled_info),
            CBB_len(&mut labeled_info),
        ) != 0) as libc::c_int;
    CBB_cleanup(&mut labeled_info);
    return ok;
}
unsafe extern "C" fn dhkem_extract_and_expand(
    mut kem_id: uint16_t,
    mut hkdf_md: *const EVP_MD,
    mut out_key: *mut uint8_t,
    mut out_len: size_t,
    mut dh: *const uint8_t,
    mut dh_len: size_t,
    mut kem_context: *const uint8_t,
    mut kem_context_len: size_t,
) -> libc::c_int {
    let mut suite_id: [uint8_t; 5] = [
        'K' as i32 as uint8_t,
        'E' as i32 as uint8_t,
        'M' as i32 as uint8_t,
        (kem_id as libc::c_int >> 8 as libc::c_int) as uint8_t,
        (kem_id as libc::c_int & 0xff as libc::c_int) as uint8_t,
    ];
    let mut prk: [uint8_t; 64] = [0; 64];
    let mut prk_len: size_t = 0;
    return (hpke_labeled_extract(
        hkdf_md,
        prk.as_mut_ptr(),
        &mut prk_len,
        0 as *const uint8_t,
        0 as libc::c_int as size_t,
        suite_id.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 5]>() as libc::c_ulong,
        b"eae_prk\0" as *const u8 as *const libc::c_char,
        dh,
        dh_len,
    ) != 0
        && hpke_labeled_expand(
            hkdf_md,
            out_key,
            out_len,
            prk.as_mut_ptr(),
            prk_len,
            suite_id.as_mut_ptr(),
            ::core::mem::size_of::<[uint8_t; 5]>() as libc::c_ulong,
            b"shared_secret\0" as *const u8 as *const libc::c_char,
            kem_context,
            kem_context_len,
        ) != 0) as libc::c_int;
}
unsafe extern "C" fn x25519_init_key(
    mut key: *mut EVP_HPKE_KEY,
    mut priv_key: *const uint8_t,
    mut priv_key_len: size_t,
) -> libc::c_int {
    if priv_key_len != 32 as libc::c_int as size_t {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hpke/hpke.c\0" as *const u8
                as *const libc::c_char,
            150 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    OPENSSL_memcpy(
        ((*key).private_key).as_mut_ptr() as *mut libc::c_void,
        priv_key as *const libc::c_void,
        priv_key_len,
    );
    X25519_public_from_private(((*key).public_key).as_mut_ptr(), priv_key);
    return 1 as libc::c_int;
}
unsafe extern "C" fn x25519_generate_key(mut key: *mut EVP_HPKE_KEY) -> libc::c_int {
    X25519_keypair(((*key).public_key).as_mut_ptr(), ((*key).private_key).as_mut_ptr());
    return 1 as libc::c_int;
}
unsafe extern "C" fn x25519_encap_with_seed(
    mut kem: *const EVP_HPKE_KEM,
    mut out_shared_secret: *mut uint8_t,
    mut out_shared_secret_len: *mut size_t,
    mut out_enc: *mut uint8_t,
    mut out_enc_len: *mut size_t,
    mut max_enc: size_t,
    mut peer_public_key: *const uint8_t,
    mut peer_public_key_len: size_t,
    mut seed: *const uint8_t,
    mut seed_len: size_t,
) -> libc::c_int {
    if max_enc < 32 as libc::c_int as size_t {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            137 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hpke/hpke.c\0" as *const u8
                as *const libc::c_char,
            170 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if seed_len != 32 as libc::c_int as size_t {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hpke/hpke.c\0" as *const u8
                as *const libc::c_char,
            174 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    X25519_public_from_private(out_enc, seed);
    let mut dh: [uint8_t; 32] = [0; 32];
    if peer_public_key_len != 32 as libc::c_int as size_t
        || X25519(dh.as_mut_ptr(), seed, peer_public_key) == 0
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            134 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hpke/hpke.c\0" as *const u8
                as *const libc::c_char,
            182 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut kem_context: [uint8_t; 64] = [0; 64];
    OPENSSL_memcpy(
        kem_context.as_mut_ptr() as *mut libc::c_void,
        out_enc as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
    OPENSSL_memcpy(
        kem_context.as_mut_ptr().offset(32 as libc::c_int as isize) as *mut libc::c_void,
        peer_public_key as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
    if dhkem_extract_and_expand(
        (*kem).id,
        EVP_sha256(),
        out_shared_secret,
        32 as libc::c_int as size_t,
        dh.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
        kem_context.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    *out_enc_len = 32 as libc::c_int as size_t;
    *out_shared_secret_len = 32 as libc::c_int as size_t;
    return 1 as libc::c_int;
}
unsafe extern "C" fn x25519_decap(
    mut key: *const EVP_HPKE_KEY,
    mut out_shared_secret: *mut uint8_t,
    mut out_shared_secret_len: *mut size_t,
    mut enc: *const uint8_t,
    mut enc_len: size_t,
) -> libc::c_int {
    let mut dh: [uint8_t; 32] = [0; 32];
    if enc_len != 32 as libc::c_int as size_t
        || X25519(dh.as_mut_ptr(), ((*key).private_key).as_ptr(), enc) == 0
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            134 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hpke/hpke.c\0" as *const u8
                as *const libc::c_char,
            207 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut kem_context: [uint8_t; 64] = [0; 64];
    OPENSSL_memcpy(
        kem_context.as_mut_ptr() as *mut libc::c_void,
        enc as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
    OPENSSL_memcpy(
        kem_context.as_mut_ptr().offset(32 as libc::c_int as isize) as *mut libc::c_void,
        ((*key).public_key).as_ptr() as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
    if dhkem_extract_and_expand(
        (*(*key).kem).id,
        EVP_sha256(),
        out_shared_secret,
        32 as libc::c_int as size_t,
        dh.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
        kem_context.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    *out_shared_secret_len = 32 as libc::c_int as size_t;
    return 1 as libc::c_int;
}
unsafe extern "C" fn x25519_auth_encap_with_seed(
    mut key: *const EVP_HPKE_KEY,
    mut out_shared_secret: *mut uint8_t,
    mut out_shared_secret_len: *mut size_t,
    mut out_enc: *mut uint8_t,
    mut out_enc_len: *mut size_t,
    mut max_enc: size_t,
    mut peer_public_key: *const uint8_t,
    mut peer_public_key_len: size_t,
    mut seed: *const uint8_t,
    mut seed_len: size_t,
) -> libc::c_int {
    if max_enc < 32 as libc::c_int as size_t {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            137 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hpke/hpke.c\0" as *const u8
                as *const libc::c_char,
            231 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if seed_len != 32 as libc::c_int as size_t {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hpke/hpke.c\0" as *const u8
                as *const libc::c_char,
            235 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    X25519_public_from_private(out_enc, seed);
    let mut dh: [uint8_t; 64] = [0; 64];
    if peer_public_key_len != 32 as libc::c_int as size_t
        || X25519(dh.as_mut_ptr(), seed, peer_public_key) == 0
        || X25519(
            dh.as_mut_ptr().offset(32 as libc::c_int as isize),
            ((*key).private_key).as_ptr(),
            peer_public_key,
        ) == 0
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            134 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hpke/hpke.c\0" as *const u8
                as *const libc::c_char,
            244 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut kem_context: [uint8_t; 96] = [0; 96];
    OPENSSL_memcpy(
        kem_context.as_mut_ptr() as *mut libc::c_void,
        out_enc as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
    OPENSSL_memcpy(
        kem_context.as_mut_ptr().offset(32 as libc::c_int as isize) as *mut libc::c_void,
        peer_public_key as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
    OPENSSL_memcpy(
        kem_context.as_mut_ptr().offset((2 as libc::c_int * 32 as libc::c_int) as isize)
            as *mut libc::c_void,
        ((*key).public_key).as_ptr() as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
    if dhkem_extract_and_expand(
        (*(*key).kem).id,
        EVP_sha256(),
        out_shared_secret,
        32 as libc::c_int as size_t,
        dh.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
        kem_context.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 96]>() as libc::c_ulong,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    *out_enc_len = 32 as libc::c_int as size_t;
    *out_shared_secret_len = 32 as libc::c_int as size_t;
    return 1 as libc::c_int;
}
unsafe extern "C" fn x25519_auth_decap(
    mut key: *const EVP_HPKE_KEY,
    mut out_shared_secret: *mut uint8_t,
    mut out_shared_secret_len: *mut size_t,
    mut enc: *const uint8_t,
    mut enc_len: size_t,
    mut peer_public_key: *const uint8_t,
    mut peer_public_key_len: size_t,
) -> libc::c_int {
    let mut dh: [uint8_t; 64] = [0; 64];
    if enc_len != 32 as libc::c_int as size_t
        || peer_public_key_len != 32 as libc::c_int as size_t
        || X25519(dh.as_mut_ptr(), ((*key).private_key).as_ptr(), enc) == 0
        || X25519(
            dh.as_mut_ptr().offset(32 as libc::c_int as isize),
            ((*key).private_key).as_ptr(),
            peer_public_key,
        ) == 0
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            134 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hpke/hpke.c\0" as *const u8
                as *const libc::c_char,
            275 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut kem_context: [uint8_t; 96] = [0; 96];
    OPENSSL_memcpy(
        kem_context.as_mut_ptr() as *mut libc::c_void,
        enc as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
    OPENSSL_memcpy(
        kem_context.as_mut_ptr().offset(32 as libc::c_int as isize) as *mut libc::c_void,
        ((*key).public_key).as_ptr() as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
    OPENSSL_memcpy(
        kem_context.as_mut_ptr().offset((2 as libc::c_int * 32 as libc::c_int) as isize)
            as *mut libc::c_void,
        peer_public_key as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
    if dhkem_extract_and_expand(
        (*(*key).kem).id,
        EVP_sha256(),
        out_shared_secret,
        32 as libc::c_int as size_t,
        dh.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
        kem_context.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 96]>() as libc::c_ulong,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    *out_shared_secret_len = 32 as libc::c_int as size_t;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_hpke_x25519_hkdf_sha256() -> *const EVP_HPKE_KEM {
    static mut kKEM: EVP_HPKE_KEM = unsafe {
        {
            let mut init = evp_hpke_kem_st {
                id: 0x20 as libc::c_int as uint16_t,
                public_key_len: 32 as libc::c_int as size_t,
                private_key_len: 32 as libc::c_int as size_t,
                seed_len: 32 as libc::c_int as size_t,
                enc_len: 32 as libc::c_int as size_t,
                init_key: Some(
                    x25519_init_key
                        as unsafe extern "C" fn(
                            *mut EVP_HPKE_KEY,
                            *const uint8_t,
                            size_t,
                        ) -> libc::c_int,
                ),
                generate_key: Some(
                    x25519_generate_key
                        as unsafe extern "C" fn(*mut EVP_HPKE_KEY) -> libc::c_int,
                ),
                encap_with_seed: Some(
                    x25519_encap_with_seed
                        as unsafe extern "C" fn(
                            *const EVP_HPKE_KEM,
                            *mut uint8_t,
                            *mut size_t,
                            *mut uint8_t,
                            *mut size_t,
                            size_t,
                            *const uint8_t,
                            size_t,
                            *const uint8_t,
                            size_t,
                        ) -> libc::c_int,
                ),
                decap: Some(
                    x25519_decap
                        as unsafe extern "C" fn(
                            *const EVP_HPKE_KEY,
                            *mut uint8_t,
                            *mut size_t,
                            *const uint8_t,
                            size_t,
                        ) -> libc::c_int,
                ),
                auth_encap_with_seed: Some(
                    x25519_auth_encap_with_seed
                        as unsafe extern "C" fn(
                            *const EVP_HPKE_KEY,
                            *mut uint8_t,
                            *mut size_t,
                            *mut uint8_t,
                            *mut size_t,
                            size_t,
                            *const uint8_t,
                            size_t,
                            *const uint8_t,
                            size_t,
                        ) -> libc::c_int,
                ),
                auth_decap: Some(
                    x25519_auth_decap
                        as unsafe extern "C" fn(
                            *const EVP_HPKE_KEY,
                            *mut uint8_t,
                            *mut size_t,
                            *const uint8_t,
                            size_t,
                            *const uint8_t,
                            size_t,
                        ) -> libc::c_int,
                ),
            };
            init
        }
    };
    return &kKEM;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_KEM_id(mut kem: *const EVP_HPKE_KEM) -> uint16_t {
    return (*kem).id;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_KEM_public_key_len(
    mut kem: *const EVP_HPKE_KEM,
) -> size_t {
    return (*kem).public_key_len;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_KEM_private_key_len(
    mut kem: *const EVP_HPKE_KEM,
) -> size_t {
    return (*kem).private_key_len;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_KEM_enc_len(mut kem: *const EVP_HPKE_KEM) -> size_t {
    return (*kem).enc_len;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_KEY_zero(mut key: *mut EVP_HPKE_KEY) {
    OPENSSL_memset(
        key as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_HPKE_KEY>() as libc::c_ulong,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_KEY_cleanup(mut key: *mut EVP_HPKE_KEY) {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_KEY_new() -> *mut EVP_HPKE_KEY {
    let mut key: *mut EVP_HPKE_KEY = OPENSSL_malloc(
        ::core::mem::size_of::<EVP_HPKE_KEY>() as libc::c_ulong,
    ) as *mut EVP_HPKE_KEY;
    if key.is_null() {
        return 0 as *mut EVP_HPKE_KEY;
    }
    EVP_HPKE_KEY_zero(key);
    return key;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_KEY_free(mut key: *mut EVP_HPKE_KEY) {
    if !key.is_null() {
        EVP_HPKE_KEY_cleanup(key);
        OPENSSL_free(key as *mut libc::c_void);
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_KEY_copy(
    mut dst: *mut EVP_HPKE_KEY,
    mut src: *const EVP_HPKE_KEY,
) -> libc::c_int {
    OPENSSL_memcpy(
        dst as *mut libc::c_void,
        src as *const libc::c_void,
        ::core::mem::size_of::<EVP_HPKE_KEY>() as libc::c_ulong,
    );
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_KEY_move(
    mut out: *mut EVP_HPKE_KEY,
    mut in_0: *mut EVP_HPKE_KEY,
) {
    EVP_HPKE_KEY_cleanup(out);
    OPENSSL_memcpy(
        out as *mut libc::c_void,
        in_0 as *const libc::c_void,
        ::core::mem::size_of::<EVP_HPKE_KEY>() as libc::c_ulong,
    );
    EVP_HPKE_KEY_zero(in_0);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_KEY_init(
    mut key: *mut EVP_HPKE_KEY,
    mut kem: *const EVP_HPKE_KEM,
    mut priv_key: *const uint8_t,
    mut priv_key_len: size_t,
) -> libc::c_int {
    EVP_HPKE_KEY_zero(key);
    (*key).kem = kem;
    if ((*kem).init_key).expect("non-null function pointer")(key, priv_key, priv_key_len)
        == 0
    {
        (*key).kem = 0 as *const EVP_HPKE_KEM;
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_KEY_generate(
    mut key: *mut EVP_HPKE_KEY,
    mut kem: *const EVP_HPKE_KEM,
) -> libc::c_int {
    EVP_HPKE_KEY_zero(key);
    (*key).kem = kem;
    if ((*kem).generate_key).expect("non-null function pointer")(key) == 0 {
        (*key).kem = 0 as *const EVP_HPKE_KEM;
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_KEY_kem(
    mut key: *const EVP_HPKE_KEY,
) -> *const EVP_HPKE_KEM {
    return (*key).kem;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_KEY_public_key(
    mut key: *const EVP_HPKE_KEY,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
    mut max_out: size_t,
) -> libc::c_int {
    if max_out < (*(*key).kem).public_key_len {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            137 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hpke/hpke.c\0" as *const u8
                as *const libc::c_char,
            390 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    OPENSSL_memcpy(
        out as *mut libc::c_void,
        ((*key).public_key).as_ptr() as *const libc::c_void,
        (*(*key).kem).public_key_len,
    );
    *out_len = (*(*key).kem).public_key_len;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_KEY_private_key(
    mut key: *const EVP_HPKE_KEY,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
    mut max_out: size_t,
) -> libc::c_int {
    if max_out < (*(*key).kem).private_key_len {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            137 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hpke/hpke.c\0" as *const u8
                as *const libc::c_char,
            401 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    OPENSSL_memcpy(
        out as *mut libc::c_void,
        ((*key).private_key).as_ptr() as *const libc::c_void,
        (*(*key).kem).private_key_len,
    );
    *out_len = (*(*key).kem).private_key_len;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_hpke_hkdf_sha256() -> *const EVP_HPKE_KDF {
    static mut kKDF: EVP_HPKE_KDF = {
        let mut init = evp_hpke_kdf_st {
            id: 0x1 as libc::c_int as uint16_t,
            hkdf_md_func: Some(EVP_sha256 as unsafe extern "C" fn() -> *const EVP_MD),
        };
        init
    };
    return &kKDF;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_KDF_id(mut kdf: *const EVP_HPKE_KDF) -> uint16_t {
    return (*kdf).id;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_KDF_hkdf_md(
    mut kdf: *const EVP_HPKE_KDF,
) -> *const EVP_MD {
    return ((*kdf).hkdf_md_func).expect("non-null function pointer")();
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_hpke_aes_128_gcm() -> *const EVP_HPKE_AEAD {
    static mut kAEAD: EVP_HPKE_AEAD = {
        let mut init = evp_hpke_aead_st {
            id: 0x1 as libc::c_int as uint16_t,
            aead_func: Some(
                EVP_aead_aes_128_gcm as unsafe extern "C" fn() -> *const EVP_AEAD,
            ),
        };
        init
    };
    return &kAEAD;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_hpke_aes_256_gcm() -> *const EVP_HPKE_AEAD {
    static mut kAEAD: EVP_HPKE_AEAD = {
        let mut init = evp_hpke_aead_st {
            id: 0x2 as libc::c_int as uint16_t,
            aead_func: Some(
                EVP_aead_aes_256_gcm as unsafe extern "C" fn() -> *const EVP_AEAD,
            ),
        };
        init
    };
    return &kAEAD;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_hpke_chacha20_poly1305() -> *const EVP_HPKE_AEAD {
    static mut kAEAD: EVP_HPKE_AEAD = {
        let mut init = evp_hpke_aead_st {
            id: 0x3 as libc::c_int as uint16_t,
            aead_func: Some(
                EVP_aead_chacha20_poly1305 as unsafe extern "C" fn() -> *const EVP_AEAD,
            ),
        };
        init
    };
    return &kAEAD;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_AEAD_id(mut aead: *const EVP_HPKE_AEAD) -> uint16_t {
    return (*aead).id;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_AEAD_aead(
    mut aead: *const EVP_HPKE_AEAD,
) -> *const EVP_AEAD {
    return ((*aead).aead_func).expect("non-null function pointer")();
}
unsafe extern "C" fn hpke_build_suite_id(
    mut ctx: *const EVP_HPKE_CTX,
    mut out: *mut uint8_t,
) -> libc::c_int {
    let mut cbb: CBB = cbb_st {
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
    CBB_init_fixed(&mut cbb, out, 10 as libc::c_int as size_t);
    return (add_label_string(&mut cbb, b"HPKE\0" as *const u8 as *const libc::c_char)
        != 0 && CBB_add_u16(&mut cbb, (*(*ctx).kem).id) != 0
        && CBB_add_u16(&mut cbb, (*(*ctx).kdf).id) != 0
        && CBB_add_u16(&mut cbb, (*(*ctx).aead).id) != 0) as libc::c_int;
}
unsafe extern "C" fn hpke_key_schedule(
    mut ctx: *mut EVP_HPKE_CTX,
    mut mode: uint8_t,
    mut shared_secret: *const uint8_t,
    mut shared_secret_len: size_t,
    mut info: *const uint8_t,
    mut info_len: size_t,
) -> libc::c_int {
    let mut suite_id: [uint8_t; 10] = [0; 10];
    if hpke_build_suite_id(ctx, suite_id.as_mut_ptr()) == 0 {
        return 0 as libc::c_int;
    }
    let mut hkdf_md: *const EVP_MD = ((*(*ctx).kdf).hkdf_md_func)
        .expect("non-null function pointer")();
    let mut psk_id_hash: [uint8_t; 64] = [0; 64];
    let mut psk_id_hash_len: size_t = 0;
    if hpke_labeled_extract(
        hkdf_md,
        psk_id_hash.as_mut_ptr(),
        &mut psk_id_hash_len,
        0 as *const uint8_t,
        0 as libc::c_int as size_t,
        suite_id.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 10]>() as libc::c_ulong,
        b"psk_id_hash\0" as *const u8 as *const libc::c_char,
        0 as *const uint8_t,
        0 as libc::c_int as size_t,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut info_hash: [uint8_t; 64] = [0; 64];
    let mut info_hash_len: size_t = 0;
    if hpke_labeled_extract(
        hkdf_md,
        info_hash.as_mut_ptr(),
        &mut info_hash_len,
        0 as *const uint8_t,
        0 as libc::c_int as size_t,
        suite_id.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 10]>() as libc::c_ulong,
        b"info_hash\0" as *const u8 as *const libc::c_char,
        info,
        info_len,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut context: [uint8_t; 129] = [0; 129];
    let mut context_len: size_t = 0;
    let mut context_cbb: CBB = cbb_st {
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
    CBB_init_fixed(
        &mut context_cbb,
        context.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 129]>() as libc::c_ulong,
    );
    if CBB_add_u8(&mut context_cbb, mode) == 0
        || CBB_add_bytes(&mut context_cbb, psk_id_hash.as_mut_ptr(), psk_id_hash_len)
            == 0
        || CBB_add_bytes(&mut context_cbb, info_hash.as_mut_ptr(), info_hash_len) == 0
        || CBB_finish(&mut context_cbb, 0 as *mut *mut uint8_t, &mut context_len) == 0
    {
        return 0 as libc::c_int;
    }
    let mut secret: [uint8_t; 64] = [0; 64];
    let mut secret_len: size_t = 0;
    if hpke_labeled_extract(
        hkdf_md,
        secret.as_mut_ptr(),
        &mut secret_len,
        shared_secret,
        shared_secret_len,
        suite_id.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 10]>() as libc::c_ulong,
        b"secret\0" as *const u8 as *const libc::c_char,
        0 as *const uint8_t,
        0 as libc::c_int as size_t,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut aead: *const EVP_AEAD = EVP_HPKE_AEAD_aead((*ctx).aead);
    let mut key: [uint8_t; 80] = [0; 80];
    let kKeyLen: size_t = EVP_AEAD_key_length(aead);
    if hpke_labeled_expand(
        hkdf_md,
        key.as_mut_ptr(),
        kKeyLen,
        secret.as_mut_ptr(),
        secret_len,
        suite_id.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 10]>() as libc::c_ulong,
        b"key\0" as *const u8 as *const libc::c_char,
        context.as_mut_ptr(),
        context_len,
    ) == 0
        || EVP_AEAD_CTX_init(
            &mut (*ctx).aead_ctx,
            aead,
            key.as_mut_ptr(),
            kKeyLen,
            0 as libc::c_int as size_t,
            0 as *mut ENGINE,
        ) == 0
    {
        return 0 as libc::c_int;
    }
    if hpke_labeled_expand(
        hkdf_md,
        ((*ctx).base_nonce).as_mut_ptr(),
        EVP_AEAD_nonce_length(aead),
        secret.as_mut_ptr(),
        secret_len,
        suite_id.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 10]>() as libc::c_ulong,
        b"base_nonce\0" as *const u8 as *const libc::c_char,
        context.as_mut_ptr(),
        context_len,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    if hpke_labeled_expand(
        hkdf_md,
        ((*ctx).exporter_secret).as_mut_ptr(),
        EVP_MD_size(hkdf_md),
        secret.as_mut_ptr(),
        secret_len,
        suite_id.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 10]>() as libc::c_ulong,
        b"exp\0" as *const u8 as *const libc::c_char,
        context.as_mut_ptr(),
        context_len,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_CTX_zero(mut ctx: *mut EVP_HPKE_CTX) {
    OPENSSL_memset(
        ctx as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_HPKE_CTX>() as libc::c_ulong,
    );
    EVP_AEAD_CTX_zero(&mut (*ctx).aead_ctx);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_CTX_cleanup(mut ctx: *mut EVP_HPKE_CTX) {
    EVP_AEAD_CTX_cleanup(&mut (*ctx).aead_ctx);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_CTX_new() -> *mut EVP_HPKE_CTX {
    let mut ctx: *mut EVP_HPKE_CTX = OPENSSL_zalloc(
        ::core::mem::size_of::<EVP_HPKE_CTX>() as libc::c_ulong,
    ) as *mut EVP_HPKE_CTX;
    if ctx.is_null() {
        return 0 as *mut EVP_HPKE_CTX;
    }
    return ctx;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_CTX_free(mut ctx: *mut EVP_HPKE_CTX) {
    if !ctx.is_null() {
        EVP_HPKE_CTX_cleanup(ctx);
        OPENSSL_free(ctx as *mut libc::c_void);
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_CTX_setup_sender(
    mut ctx: *mut EVP_HPKE_CTX,
    mut out_enc: *mut uint8_t,
    mut out_enc_len: *mut size_t,
    mut max_enc: size_t,
    mut kem: *const EVP_HPKE_KEM,
    mut kdf: *const EVP_HPKE_KDF,
    mut aead: *const EVP_HPKE_AEAD,
    mut peer_public_key: *const uint8_t,
    mut peer_public_key_len: size_t,
    mut info: *const uint8_t,
    mut info_len: size_t,
) -> libc::c_int {
    let mut seed: [uint8_t; 32] = [0; 32];
    RAND_bytes(seed.as_mut_ptr(), (*kem).seed_len);
    return EVP_HPKE_CTX_setup_sender_with_seed_for_testing(
        ctx,
        out_enc,
        out_enc_len,
        max_enc,
        kem,
        kdf,
        aead,
        peer_public_key,
        peer_public_key_len,
        info,
        info_len,
        seed.as_mut_ptr(),
        (*kem).seed_len,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_CTX_setup_sender_with_seed_for_testing(
    mut ctx: *mut EVP_HPKE_CTX,
    mut out_enc: *mut uint8_t,
    mut out_enc_len: *mut size_t,
    mut max_enc: size_t,
    mut kem: *const EVP_HPKE_KEM,
    mut kdf: *const EVP_HPKE_KDF,
    mut aead: *const EVP_HPKE_AEAD,
    mut peer_public_key: *const uint8_t,
    mut peer_public_key_len: size_t,
    mut info: *const uint8_t,
    mut info_len: size_t,
    mut seed: *const uint8_t,
    mut seed_len: size_t,
) -> libc::c_int {
    EVP_HPKE_CTX_zero(ctx);
    (*ctx).is_sender = 1 as libc::c_int;
    (*ctx).kem = kem;
    (*ctx).kdf = kdf;
    (*ctx).aead = aead;
    let mut shared_secret: [uint8_t; 32] = [0; 32];
    let mut shared_secret_len: size_t = 0;
    if ((*kem).encap_with_seed)
        .expect(
            "non-null function pointer",
        )(
        kem,
        shared_secret.as_mut_ptr(),
        &mut shared_secret_len,
        out_enc,
        out_enc_len,
        max_enc,
        peer_public_key,
        peer_public_key_len,
        seed,
        seed_len,
    ) == 0
        || hpke_key_schedule(
            ctx,
            0 as libc::c_int as uint8_t,
            shared_secret.as_mut_ptr(),
            shared_secret_len,
            info,
            info_len,
        ) == 0
    {
        EVP_HPKE_CTX_cleanup(ctx);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_CTX_setup_recipient(
    mut ctx: *mut EVP_HPKE_CTX,
    mut key: *const EVP_HPKE_KEY,
    mut kdf: *const EVP_HPKE_KDF,
    mut aead: *const EVP_HPKE_AEAD,
    mut enc: *const uint8_t,
    mut enc_len: size_t,
    mut info: *const uint8_t,
    mut info_len: size_t,
) -> libc::c_int {
    EVP_HPKE_CTX_zero(ctx);
    (*ctx).is_sender = 0 as libc::c_int;
    (*ctx).kem = (*key).kem;
    (*ctx).kdf = kdf;
    (*ctx).aead = aead;
    let mut shared_secret: [uint8_t; 32] = [0; 32];
    let mut shared_secret_len: size_t = 0;
    if ((*(*key).kem).decap)
        .expect(
            "non-null function pointer",
        )(key, shared_secret.as_mut_ptr(), &mut shared_secret_len, enc, enc_len) == 0
        || hpke_key_schedule(
            ctx,
            0 as libc::c_int as uint8_t,
            shared_secret.as_mut_ptr(),
            shared_secret_len,
            info,
            info_len,
        ) == 0
    {
        EVP_HPKE_CTX_cleanup(ctx);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_CTX_setup_auth_sender(
    mut ctx: *mut EVP_HPKE_CTX,
    mut out_enc: *mut uint8_t,
    mut out_enc_len: *mut size_t,
    mut max_enc: size_t,
    mut key: *const EVP_HPKE_KEY,
    mut kdf: *const EVP_HPKE_KDF,
    mut aead: *const EVP_HPKE_AEAD,
    mut peer_public_key: *const uint8_t,
    mut peer_public_key_len: size_t,
    mut info: *const uint8_t,
    mut info_len: size_t,
) -> libc::c_int {
    let mut seed: [uint8_t; 32] = [0; 32];
    RAND_bytes(seed.as_mut_ptr(), (*(*key).kem).seed_len);
    return EVP_HPKE_CTX_setup_auth_sender_with_seed_for_testing(
        ctx,
        out_enc,
        out_enc_len,
        max_enc,
        key,
        kdf,
        aead,
        peer_public_key,
        peer_public_key_len,
        info,
        info_len,
        seed.as_mut_ptr(),
        (*(*key).kem).seed_len,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_CTX_setup_auth_sender_with_seed_for_testing(
    mut ctx: *mut EVP_HPKE_CTX,
    mut out_enc: *mut uint8_t,
    mut out_enc_len: *mut size_t,
    mut max_enc: size_t,
    mut key: *const EVP_HPKE_KEY,
    mut kdf: *const EVP_HPKE_KDF,
    mut aead: *const EVP_HPKE_AEAD,
    mut peer_public_key: *const uint8_t,
    mut peer_public_key_len: size_t,
    mut info: *const uint8_t,
    mut info_len: size_t,
    mut seed: *const uint8_t,
    mut seed_len: size_t,
) -> libc::c_int {
    if ((*(*key).kem).auth_encap_with_seed).is_none() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hpke/hpke.c\0" as *const u8
                as *const libc::c_char,
            653 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    EVP_HPKE_CTX_zero(ctx);
    (*ctx).is_sender = 1 as libc::c_int;
    (*ctx).kem = (*key).kem;
    (*ctx).kdf = kdf;
    (*ctx).aead = aead;
    let mut shared_secret: [uint8_t; 32] = [0; 32];
    let mut shared_secret_len: size_t = 0;
    if ((*(*key).kem).auth_encap_with_seed)
        .expect(
            "non-null function pointer",
        )(
        key,
        shared_secret.as_mut_ptr(),
        &mut shared_secret_len,
        out_enc,
        out_enc_len,
        max_enc,
        peer_public_key,
        peer_public_key_len,
        seed,
        seed_len,
    ) == 0
        || hpke_key_schedule(
            ctx,
            2 as libc::c_int as uint8_t,
            shared_secret.as_mut_ptr(),
            shared_secret_len,
            info,
            info_len,
        ) == 0
    {
        EVP_HPKE_CTX_cleanup(ctx);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_CTX_setup_auth_recipient(
    mut ctx: *mut EVP_HPKE_CTX,
    mut key: *const EVP_HPKE_KEY,
    mut kdf: *const EVP_HPKE_KDF,
    mut aead: *const EVP_HPKE_AEAD,
    mut enc: *const uint8_t,
    mut enc_len: size_t,
    mut info: *const uint8_t,
    mut info_len: size_t,
    mut peer_public_key: *const uint8_t,
    mut peer_public_key_len: size_t,
) -> libc::c_int {
    if ((*(*key).kem).auth_decap).is_none() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hpke/hpke.c\0" as *const u8
                as *const libc::c_char,
            682 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    EVP_HPKE_CTX_zero(ctx);
    (*ctx).is_sender = 0 as libc::c_int;
    (*ctx).kem = (*key).kem;
    (*ctx).kdf = kdf;
    (*ctx).aead = aead;
    let mut shared_secret: [uint8_t; 32] = [0; 32];
    let mut shared_secret_len: size_t = 0;
    if ((*(*key).kem).auth_decap)
        .expect(
            "non-null function pointer",
        )(
        key,
        shared_secret.as_mut_ptr(),
        &mut shared_secret_len,
        enc,
        enc_len,
        peer_public_key,
        peer_public_key_len,
    ) == 0
        || hpke_key_schedule(
            ctx,
            2 as libc::c_int as uint8_t,
            shared_secret.as_mut_ptr(),
            shared_secret_len,
            info,
            info_len,
        ) == 0
    {
        EVP_HPKE_CTX_cleanup(ctx);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn hpke_nonce(
    mut ctx: *const EVP_HPKE_CTX,
    mut out_nonce: *mut uint8_t,
    mut nonce_len: size_t,
) {
    if nonce_len >= 8 as libc::c_int as size_t {} else {
        __assert_fail(
            b"nonce_len >= 8\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hpke/hpke.c\0" as *const u8
                as *const libc::c_char,
            705 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 57],
                &[libc::c_char; 57],
            >(b"void hpke_nonce(const EVP_HPKE_CTX *, uint8_t *, size_t)\0"))
                .as_ptr(),
        );
    }
    'c_4804: {
        if nonce_len >= 8 as libc::c_int as size_t {} else {
            __assert_fail(
                b"nonce_len >= 8\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/hpke/hpke.c\0" as *const u8
                    as *const libc::c_char,
                705 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 57],
                    &[libc::c_char; 57],
                >(b"void hpke_nonce(const EVP_HPKE_CTX *, uint8_t *, size_t)\0"))
                    .as_ptr(),
            );
        }
    };
    OPENSSL_memset(out_nonce as *mut libc::c_void, 0 as libc::c_int, nonce_len);
    let mut seq_copy: uint64_t = (*ctx).seq;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < 8 as libc::c_int as size_t {
        *out_nonce
            .offset(
                nonce_len.wrapping_sub(i).wrapping_sub(1 as libc::c_int as size_t)
                    as isize,
            ) = (seq_copy & 0xff as libc::c_int as uint64_t) as uint8_t;
        seq_copy >>= 8 as libc::c_int;
        i = i.wrapping_add(1);
        i;
    }
    let mut i_0: size_t = 0 as libc::c_int as size_t;
    while i_0 < nonce_len {
        let ref mut fresh0 = *out_nonce.offset(i_0 as isize);
        *fresh0 = (*fresh0 as libc::c_int
            ^ (*ctx).base_nonce[i_0 as usize] as libc::c_int) as uint8_t;
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_CTX_open(
    mut ctx: *mut EVP_HPKE_CTX,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
    mut max_out_len: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut ad: *const uint8_t,
    mut ad_len: size_t,
) -> libc::c_int {
    if (*ctx).is_sender != 0 {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hpke/hpke.c\0" as *const u8
                as *const libc::c_char,
            725 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*ctx).seq == 18446744073709551615 as libc::c_ulong {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hpke/hpke.c\0" as *const u8
                as *const libc::c_char,
            729 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut nonce: [uint8_t; 24] = [0; 24];
    let nonce_len: size_t = EVP_AEAD_nonce_length((*ctx).aead_ctx.aead);
    hpke_nonce(ctx, nonce.as_mut_ptr(), nonce_len);
    if EVP_AEAD_CTX_open(
        &mut (*ctx).aead_ctx,
        out,
        out_len,
        max_out_len,
        nonce.as_mut_ptr(),
        nonce_len,
        in_0,
        in_len,
        ad,
        ad_len,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    (*ctx).seq = ((*ctx).seq).wrapping_add(1);
    (*ctx).seq;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_CTX_seal(
    mut ctx: *mut EVP_HPKE_CTX,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
    mut max_out_len: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut ad: *const uint8_t,
    mut ad_len: size_t,
) -> libc::c_int {
    if (*ctx).is_sender == 0 {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hpke/hpke.c\0" as *const u8
                as *const libc::c_char,
            749 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*ctx).seq == 18446744073709551615 as libc::c_ulong {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hpke/hpke.c\0" as *const u8
                as *const libc::c_char,
            753 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut nonce: [uint8_t; 24] = [0; 24];
    let nonce_len: size_t = EVP_AEAD_nonce_length((*ctx).aead_ctx.aead);
    hpke_nonce(ctx, nonce.as_mut_ptr(), nonce_len);
    if EVP_AEAD_CTX_seal(
        &mut (*ctx).aead_ctx,
        out,
        out_len,
        max_out_len,
        nonce.as_mut_ptr(),
        nonce_len,
        in_0,
        in_len,
        ad,
        ad_len,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    (*ctx).seq = ((*ctx).seq).wrapping_add(1);
    (*ctx).seq;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_CTX_export(
    mut ctx: *const EVP_HPKE_CTX,
    mut out: *mut uint8_t,
    mut secret_len: size_t,
    mut context: *const uint8_t,
    mut context_len: size_t,
) -> libc::c_int {
    let mut suite_id: [uint8_t; 10] = [0; 10];
    if hpke_build_suite_id(ctx, suite_id.as_mut_ptr()) == 0 {
        return 0 as libc::c_int;
    }
    let mut hkdf_md: *const EVP_MD = ((*(*ctx).kdf).hkdf_md_func)
        .expect("non-null function pointer")();
    if hpke_labeled_expand(
        hkdf_md,
        out,
        secret_len,
        ((*ctx).exporter_secret).as_ptr(),
        EVP_MD_size(hkdf_md),
        suite_id.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 10]>() as libc::c_ulong,
        b"sec\0" as *const u8 as *const libc::c_char,
        context,
        context_len,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_CTX_max_overhead(
    mut ctx: *const EVP_HPKE_CTX,
) -> size_t {
    if (*ctx).is_sender != 0 {} else {
        __assert_fail(
            b"ctx->is_sender\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/hpke/hpke.c\0" as *const u8
                as *const libc::c_char,
            786 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 55],
                &[libc::c_char; 55],
            >(b"size_t EVP_HPKE_CTX_max_overhead(const EVP_HPKE_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_5103: {
        if (*ctx).is_sender != 0 {} else {
            __assert_fail(
                b"ctx->is_sender\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/hpke/hpke.c\0" as *const u8
                    as *const libc::c_char,
                786 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 55],
                    &[libc::c_char; 55],
                >(b"size_t EVP_HPKE_CTX_max_overhead(const EVP_HPKE_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    return EVP_AEAD_max_overhead(EVP_AEAD_CTX_aead(&(*ctx).aead_ctx));
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_CTX_kem(
    mut ctx: *const EVP_HPKE_CTX,
) -> *const EVP_HPKE_KEM {
    return (*ctx).kem;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_CTX_aead(
    mut ctx: *const EVP_HPKE_CTX,
) -> *const EVP_HPKE_AEAD {
    return (*ctx).aead;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_HPKE_CTX_kdf(
    mut ctx: *const EVP_HPKE_CTX,
) -> *const EVP_HPKE_KDF {
    return (*ctx).kdf;
}
