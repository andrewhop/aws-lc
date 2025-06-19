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
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_memdup(data: *const libc::c_void, size: size_t) -> *mut libc::c_void;
    fn get_legacy_kem_kyber512_r3() -> *const KEM;
    fn get_legacy_kem_kyber768_r3() -> *const KEM;
    fn get_legacy_kem_kyber1024_r3() -> *const KEM;
    fn CRYPTO_once(
        once: *mut CRYPTO_once_t,
        init: Option::<unsafe extern "C" fn() -> ()>,
    );
    fn ml_kem_512_keypair_deterministic(
        public_key: *mut uint8_t,
        public_len: *mut size_t,
        secret_key: *mut uint8_t,
        secret_len: *mut size_t,
        seed: *const uint8_t,
    ) -> libc::c_int;
    fn ml_kem_512_keypair(
        public_key: *mut uint8_t,
        public_len: *mut size_t,
        secret_key: *mut uint8_t,
        secret_len: *mut size_t,
    ) -> libc::c_int;
    fn ml_kem_512_encapsulate_deterministic(
        ciphertext: *mut uint8_t,
        ciphertext_len: *mut size_t,
        shared_secret: *mut uint8_t,
        shared_secret_len: *mut size_t,
        public_key: *const uint8_t,
        seed: *const uint8_t,
    ) -> libc::c_int;
    fn ml_kem_512_encapsulate(
        ciphertext: *mut uint8_t,
        ciphertext_len: *mut size_t,
        shared_secret: *mut uint8_t,
        shared_secret_len: *mut size_t,
        public_key: *const uint8_t,
    ) -> libc::c_int;
    fn ml_kem_512_decapsulate(
        shared_secret: *mut uint8_t,
        shared_secret_len: *mut size_t,
        ciphertext: *const uint8_t,
        secret_key: *const uint8_t,
    ) -> libc::c_int;
    fn ml_kem_768_keypair_deterministic(
        public_key: *mut uint8_t,
        public_len: *mut size_t,
        secret_key: *mut uint8_t,
        secret_len: *mut size_t,
        seed: *const uint8_t,
    ) -> libc::c_int;
    fn ml_kem_768_keypair(
        public_key: *mut uint8_t,
        public_len: *mut size_t,
        secret_key: *mut uint8_t,
        secret_len: *mut size_t,
    ) -> libc::c_int;
    fn ml_kem_768_encapsulate_deterministic(
        ciphertext: *mut uint8_t,
        ciphertext_len: *mut size_t,
        shared_secret: *mut uint8_t,
        shared_secret_len: *mut size_t,
        public_key: *const uint8_t,
        seed: *const uint8_t,
    ) -> libc::c_int;
    fn ml_kem_768_encapsulate(
        ciphertext: *mut uint8_t,
        ciphertext_len: *mut size_t,
        shared_secret: *mut uint8_t,
        shared_secret_len: *mut size_t,
        public_key: *const uint8_t,
    ) -> libc::c_int;
    fn ml_kem_768_decapsulate(
        shared_secret: *mut uint8_t,
        shared_secret_len: *mut size_t,
        ciphertext: *const uint8_t,
        secret_key: *const uint8_t,
    ) -> libc::c_int;
    fn ml_kem_1024_keypair_deterministic(
        public_key: *mut uint8_t,
        public_len: *mut size_t,
        secret_key: *mut uint8_t,
        secret_len: *mut size_t,
        seed: *const uint8_t,
    ) -> libc::c_int;
    fn ml_kem_1024_keypair(
        public_key: *mut uint8_t,
        public_len: *mut size_t,
        secret_key: *mut uint8_t,
        secret_len: *mut size_t,
    ) -> libc::c_int;
    fn ml_kem_1024_encapsulate_deterministic(
        ciphertext: *mut uint8_t,
        ciphertext_len: *mut size_t,
        shared_secret: *mut uint8_t,
        shared_secret_len: *mut size_t,
        public_key: *const uint8_t,
        seed: *const uint8_t,
    ) -> libc::c_int;
    fn ml_kem_1024_encapsulate(
        ciphertext: *mut uint8_t,
        ciphertext_len: *mut size_t,
        shared_secret: *mut uint8_t,
        shared_secret_len: *mut size_t,
        public_key: *const uint8_t,
    ) -> libc::c_int;
    fn ml_kem_1024_decapsulate(
        shared_secret: *mut uint8_t,
        shared_secret_len: *mut size_t,
        ciphertext: *const uint8_t,
        secret_key: *const uint8_t,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type uint8_t = __uint8_t;
pub type pthread_once_t = libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct kem_key_st {
    pub kem: *const KEM,
    pub public_key: *mut uint8_t,
    pub secret_key: *mut uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct KEM {
    pub nid: libc::c_int,
    pub oid: *const uint8_t,
    pub oid_len: uint8_t,
    pub comment: *const libc::c_char,
    pub public_key_len: size_t,
    pub secret_key_len: size_t,
    pub ciphertext_len: size_t,
    pub shared_secret_len: size_t,
    pub keygen_seed_len: size_t,
    pub encaps_seed_len: size_t,
    pub method: *const KEM_METHOD,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct KEM_METHOD {
    pub keygen_deterministic: Option::<
        unsafe extern "C" fn(
            *mut uint8_t,
            *mut size_t,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
        ) -> libc::c_int,
    >,
    pub keygen: Option::<
        unsafe extern "C" fn(
            *mut uint8_t,
            *mut size_t,
            *mut uint8_t,
            *mut size_t,
        ) -> libc::c_int,
    >,
    pub encaps_deterministic: Option::<
        unsafe extern "C" fn(
            *mut uint8_t,
            *mut size_t,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            *const uint8_t,
        ) -> libc::c_int,
    >,
    pub encaps: Option::<
        unsafe extern "C" fn(
            *mut uint8_t,
            *mut size_t,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
        ) -> libc::c_int,
    >,
    pub decaps: Option::<
        unsafe extern "C" fn(
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            *const uint8_t,
        ) -> libc::c_int,
    >,
}
pub type KEM_KEY = kem_key_st;
pub type CRYPTO_once_t = pthread_once_t;
static mut kOIDMLKEM512: [uint8_t; 9] = [
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
];
static mut kOIDMLKEM768: [uint8_t; 9] = [
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
];
static mut kOIDMLKEM1024: [uint8_t; 9] = [
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
];
unsafe extern "C" fn ml_kem_1024_keygen_deterministic(
    mut public_key: *mut uint8_t,
    mut public_len: *mut size_t,
    mut secret_key: *mut uint8_t,
    mut secret_len: *mut size_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    return (ml_kem_1024_keypair_deterministic(
        public_key,
        public_len,
        secret_key,
        secret_len,
        seed,
    ) == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn ml_kem_1024_keygen(
    mut public_key: *mut uint8_t,
    mut public_len: *mut size_t,
    mut secret_key: *mut uint8_t,
    mut secret_len: *mut size_t,
) -> libc::c_int {
    return (ml_kem_1024_keypair(public_key, public_len, secret_key, secret_len)
        == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn ml_kem_1024_encaps_deterministic(
    mut ciphertext: *mut uint8_t,
    mut ciphertext_len: *mut size_t,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut public_key: *const uint8_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    return (ml_kem_1024_encapsulate_deterministic(
        ciphertext,
        ciphertext_len,
        shared_secret,
        shared_secret_len,
        public_key,
        seed,
    ) == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn ml_kem_1024_encaps(
    mut ciphertext: *mut uint8_t,
    mut ciphertext_len: *mut size_t,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut public_key: *const uint8_t,
) -> libc::c_int {
    return (ml_kem_1024_encapsulate(
        ciphertext,
        ciphertext_len,
        shared_secret,
        shared_secret_len,
        public_key,
    ) == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn ml_kem_1024_decaps(
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut ciphertext: *const uint8_t,
    mut secret_key: *const uint8_t,
) -> libc::c_int {
    return (ml_kem_1024_decapsulate(
        shared_secret,
        shared_secret_len,
        ciphertext,
        secret_key,
    ) == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn kem_ml_kem_1024_method() -> *const KEM_METHOD {
    CRYPTO_once(
        kem_ml_kem_1024_method_once_bss_get(),
        Some(kem_ml_kem_1024_method_init as unsafe extern "C" fn() -> ()),
    );
    return kem_ml_kem_1024_method_storage_bss_get() as *const KEM_METHOD;
}
unsafe extern "C" fn kem_ml_kem_1024_method_storage_bss_get() -> *mut KEM_METHOD {
    return &mut kem_ml_kem_1024_method_storage;
}
unsafe extern "C" fn kem_ml_kem_1024_method_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut kem_ml_kem_1024_method_once;
}
static mut kem_ml_kem_1024_method_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn kem_ml_kem_1024_method_init() {
    kem_ml_kem_1024_method_do_init(kem_ml_kem_1024_method_storage_bss_get());
}
unsafe extern "C" fn kem_ml_kem_1024_method_do_init(mut out: *mut KEM_METHOD) {
    (*out)
        .keygen_deterministic = Some(
        ml_kem_1024_keygen_deterministic
            as unsafe extern "C" fn(
                *mut uint8_t,
                *mut size_t,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
            ) -> libc::c_int,
    );
    (*out)
        .keygen = Some(
        ml_kem_1024_keygen
            as unsafe extern "C" fn(
                *mut uint8_t,
                *mut size_t,
                *mut uint8_t,
                *mut size_t,
            ) -> libc::c_int,
    );
    (*out)
        .encaps_deterministic = Some(
        ml_kem_1024_encaps_deterministic
            as unsafe extern "C" fn(
                *mut uint8_t,
                *mut size_t,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
                *const uint8_t,
            ) -> libc::c_int,
    );
    (*out)
        .encaps = Some(
        ml_kem_1024_encaps
            as unsafe extern "C" fn(
                *mut uint8_t,
                *mut size_t,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
            ) -> libc::c_int,
    );
    (*out)
        .decaps = Some(
        ml_kem_1024_decaps
            as unsafe extern "C" fn(
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
                *const uint8_t,
            ) -> libc::c_int,
    );
}
static mut kem_ml_kem_1024_method_storage: KEM_METHOD = KEM_METHOD {
    keygen_deterministic: None,
    keygen: None,
    encaps_deterministic: None,
    encaps: None,
    decaps: None,
};
unsafe extern "C" fn ml_kem_768_keygen_deterministic(
    mut public_key: *mut uint8_t,
    mut public_len: *mut size_t,
    mut secret_key: *mut uint8_t,
    mut secret_len: *mut size_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    return (ml_kem_768_keypair_deterministic(
        public_key,
        public_len,
        secret_key,
        secret_len,
        seed,
    ) == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn ml_kem_768_keygen(
    mut public_key: *mut uint8_t,
    mut public_len: *mut size_t,
    mut secret_key: *mut uint8_t,
    mut secret_len: *mut size_t,
) -> libc::c_int {
    return (ml_kem_768_keypair(public_key, public_len, secret_key, secret_len)
        == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn ml_kem_768_encaps_deterministic(
    mut ciphertext: *mut uint8_t,
    mut ciphertext_len: *mut size_t,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut public_key: *const uint8_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    return (ml_kem_768_encapsulate_deterministic(
        ciphertext,
        ciphertext_len,
        shared_secret,
        shared_secret_len,
        public_key,
        seed,
    ) == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn ml_kem_768_encaps(
    mut ciphertext: *mut uint8_t,
    mut ciphertext_len: *mut size_t,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut public_key: *const uint8_t,
) -> libc::c_int {
    return (ml_kem_768_encapsulate(
        ciphertext,
        ciphertext_len,
        shared_secret,
        shared_secret_len,
        public_key,
    ) == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn ml_kem_768_decaps(
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut ciphertext: *const uint8_t,
    mut secret_key: *const uint8_t,
) -> libc::c_int {
    return (ml_kem_768_decapsulate(
        shared_secret,
        shared_secret_len,
        ciphertext,
        secret_key,
    ) == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn kem_ml_kem_768_method_init() {
    kem_ml_kem_768_method_do_init(kem_ml_kem_768_method_storage_bss_get());
}
unsafe extern "C" fn kem_ml_kem_768_method_storage_bss_get() -> *mut KEM_METHOD {
    return &mut kem_ml_kem_768_method_storage;
}
static mut kem_ml_kem_768_method_storage: KEM_METHOD = KEM_METHOD {
    keygen_deterministic: None,
    keygen: None,
    encaps_deterministic: None,
    encaps: None,
    decaps: None,
};
unsafe extern "C" fn kem_ml_kem_768_method() -> *const KEM_METHOD {
    CRYPTO_once(
        kem_ml_kem_768_method_once_bss_get(),
        Some(kem_ml_kem_768_method_init as unsafe extern "C" fn() -> ()),
    );
    return kem_ml_kem_768_method_storage_bss_get() as *const KEM_METHOD;
}
unsafe extern "C" fn kem_ml_kem_768_method_do_init(mut out: *mut KEM_METHOD) {
    (*out)
        .keygen_deterministic = Some(
        ml_kem_768_keygen_deterministic
            as unsafe extern "C" fn(
                *mut uint8_t,
                *mut size_t,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
            ) -> libc::c_int,
    );
    (*out)
        .keygen = Some(
        ml_kem_768_keygen
            as unsafe extern "C" fn(
                *mut uint8_t,
                *mut size_t,
                *mut uint8_t,
                *mut size_t,
            ) -> libc::c_int,
    );
    (*out)
        .encaps_deterministic = Some(
        ml_kem_768_encaps_deterministic
            as unsafe extern "C" fn(
                *mut uint8_t,
                *mut size_t,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
                *const uint8_t,
            ) -> libc::c_int,
    );
    (*out)
        .encaps = Some(
        ml_kem_768_encaps
            as unsafe extern "C" fn(
                *mut uint8_t,
                *mut size_t,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
            ) -> libc::c_int,
    );
    (*out)
        .decaps = Some(
        ml_kem_768_decaps
            as unsafe extern "C" fn(
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
                *const uint8_t,
            ) -> libc::c_int,
    );
}
static mut kem_ml_kem_768_method_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn kem_ml_kem_768_method_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut kem_ml_kem_768_method_once;
}
unsafe extern "C" fn ml_kem_512_keygen_deterministic(
    mut public_key: *mut uint8_t,
    mut public_len: *mut size_t,
    mut secret_key: *mut uint8_t,
    mut secret_len: *mut size_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    return (ml_kem_512_keypair_deterministic(
        public_key,
        public_len,
        secret_key,
        secret_len,
        seed,
    ) == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn ml_kem_512_keygen(
    mut public_key: *mut uint8_t,
    mut public_len: *mut size_t,
    mut secret_key: *mut uint8_t,
    mut secret_len: *mut size_t,
) -> libc::c_int {
    return (ml_kem_512_keypair(public_key, public_len, secret_key, secret_len)
        == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn ml_kem_512_encaps_deterministic(
    mut ciphertext: *mut uint8_t,
    mut ciphertext_len: *mut size_t,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut public_key: *const uint8_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    return (ml_kem_512_encapsulate_deterministic(
        ciphertext,
        ciphertext_len,
        shared_secret,
        shared_secret_len,
        public_key,
        seed,
    ) == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn ml_kem_512_encaps(
    mut ciphertext: *mut uint8_t,
    mut ciphertext_len: *mut size_t,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut public_key: *const uint8_t,
) -> libc::c_int {
    return (ml_kem_512_encapsulate(
        ciphertext,
        ciphertext_len,
        shared_secret,
        shared_secret_len,
        public_key,
    ) == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn ml_kem_512_decaps(
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut ciphertext: *const uint8_t,
    mut secret_key: *const uint8_t,
) -> libc::c_int {
    return (ml_kem_512_decapsulate(
        shared_secret,
        shared_secret_len,
        ciphertext,
        secret_key,
    ) == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn kem_ml_kem_512_method() -> *const KEM_METHOD {
    CRYPTO_once(
        kem_ml_kem_512_method_once_bss_get(),
        Some(kem_ml_kem_512_method_init as unsafe extern "C" fn() -> ()),
    );
    return kem_ml_kem_512_method_storage_bss_get() as *const KEM_METHOD;
}
unsafe extern "C" fn kem_ml_kem_512_method_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut kem_ml_kem_512_method_once;
}
unsafe extern "C" fn kem_ml_kem_512_method_storage_bss_get() -> *mut KEM_METHOD {
    return &mut kem_ml_kem_512_method_storage;
}
unsafe extern "C" fn kem_ml_kem_512_method_init() {
    kem_ml_kem_512_method_do_init(kem_ml_kem_512_method_storage_bss_get());
}
unsafe extern "C" fn kem_ml_kem_512_method_do_init(mut out: *mut KEM_METHOD) {
    (*out)
        .keygen_deterministic = Some(
        ml_kem_512_keygen_deterministic
            as unsafe extern "C" fn(
                *mut uint8_t,
                *mut size_t,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
            ) -> libc::c_int,
    );
    (*out)
        .keygen = Some(
        ml_kem_512_keygen
            as unsafe extern "C" fn(
                *mut uint8_t,
                *mut size_t,
                *mut uint8_t,
                *mut size_t,
            ) -> libc::c_int,
    );
    (*out)
        .encaps_deterministic = Some(
        ml_kem_512_encaps_deterministic
            as unsafe extern "C" fn(
                *mut uint8_t,
                *mut size_t,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
                *const uint8_t,
            ) -> libc::c_int,
    );
    (*out)
        .encaps = Some(
        ml_kem_512_encaps
            as unsafe extern "C" fn(
                *mut uint8_t,
                *mut size_t,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
            ) -> libc::c_int,
    );
    (*out)
        .decaps = Some(
        ml_kem_512_decaps
            as unsafe extern "C" fn(
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
                *const uint8_t,
            ) -> libc::c_int,
    );
}
static mut kem_ml_kem_512_method_once: CRYPTO_once_t = 0 as libc::c_int;
static mut kem_ml_kem_512_method_storage: KEM_METHOD = KEM_METHOD {
    keygen_deterministic: None,
    keygen: None,
    encaps_deterministic: None,
    encaps: None,
    decaps: None,
};
unsafe extern "C" fn KEM_ml_kem_512() -> *const KEM {
    CRYPTO_once(
        KEM_ml_kem_512_once_bss_get(),
        Some(KEM_ml_kem_512_init as unsafe extern "C" fn() -> ()),
    );
    return KEM_ml_kem_512_storage_bss_get() as *const KEM;
}
static mut KEM_ml_kem_512_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn KEM_ml_kem_512_do_init(mut out: *mut KEM) {
    (*out).nid = 988 as libc::c_int;
    (*out).oid = kOIDMLKEM512.as_ptr();
    (*out).oid_len = ::core::mem::size_of::<[uint8_t; 9]>() as libc::c_ulong as uint8_t;
    (*out).comment = b"MLKEM512 \0" as *const u8 as *const libc::c_char;
    (*out).public_key_len = 800 as libc::c_int as size_t;
    (*out).secret_key_len = 1632 as libc::c_int as size_t;
    (*out).ciphertext_len = 768 as libc::c_int as size_t;
    (*out).shared_secret_len = 32 as libc::c_int as size_t;
    (*out).keygen_seed_len = 64 as libc::c_int as size_t;
    (*out).encaps_seed_len = 32 as libc::c_int as size_t;
    (*out).method = kem_ml_kem_512_method();
}
unsafe extern "C" fn KEM_ml_kem_512_init() {
    KEM_ml_kem_512_do_init(KEM_ml_kem_512_storage_bss_get());
}
unsafe extern "C" fn KEM_ml_kem_512_storage_bss_get() -> *mut KEM {
    return &mut KEM_ml_kem_512_storage;
}
static mut KEM_ml_kem_512_storage: KEM = KEM {
    nid: 0,
    oid: 0 as *const uint8_t,
    oid_len: 0,
    comment: 0 as *const libc::c_char,
    public_key_len: 0,
    secret_key_len: 0,
    ciphertext_len: 0,
    shared_secret_len: 0,
    keygen_seed_len: 0,
    encaps_seed_len: 0,
    method: 0 as *const KEM_METHOD,
};
unsafe extern "C" fn KEM_ml_kem_512_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut KEM_ml_kem_512_once;
}
unsafe extern "C" fn KEM_ml_kem_768_storage_bss_get() -> *mut KEM {
    return &mut KEM_ml_kem_768_storage;
}
static mut KEM_ml_kem_768_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn KEM_ml_kem_768() -> *const KEM {
    CRYPTO_once(
        KEM_ml_kem_768_once_bss_get(),
        Some(KEM_ml_kem_768_init as unsafe extern "C" fn() -> ()),
    );
    return KEM_ml_kem_768_storage_bss_get() as *const KEM;
}
static mut KEM_ml_kem_768_storage: KEM = KEM {
    nid: 0,
    oid: 0 as *const uint8_t,
    oid_len: 0,
    comment: 0 as *const libc::c_char,
    public_key_len: 0,
    secret_key_len: 0,
    ciphertext_len: 0,
    shared_secret_len: 0,
    keygen_seed_len: 0,
    encaps_seed_len: 0,
    method: 0 as *const KEM_METHOD,
};
unsafe extern "C" fn KEM_ml_kem_768_init() {
    KEM_ml_kem_768_do_init(KEM_ml_kem_768_storage_bss_get());
}
unsafe extern "C" fn KEM_ml_kem_768_do_init(mut out: *mut KEM) {
    (*out).nid = 989 as libc::c_int;
    (*out).oid = kOIDMLKEM768.as_ptr();
    (*out).oid_len = ::core::mem::size_of::<[uint8_t; 9]>() as libc::c_ulong as uint8_t;
    (*out).comment = b"MLKEM768 \0" as *const u8 as *const libc::c_char;
    (*out).public_key_len = 1184 as libc::c_int as size_t;
    (*out).secret_key_len = 2400 as libc::c_int as size_t;
    (*out).ciphertext_len = 1088 as libc::c_int as size_t;
    (*out).shared_secret_len = 32 as libc::c_int as size_t;
    (*out).keygen_seed_len = 64 as libc::c_int as size_t;
    (*out).encaps_seed_len = 32 as libc::c_int as size_t;
    (*out).method = kem_ml_kem_768_method();
}
unsafe extern "C" fn KEM_ml_kem_768_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut KEM_ml_kem_768_once;
}
unsafe extern "C" fn KEM_ml_kem_1024_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut KEM_ml_kem_1024_once;
}
unsafe extern "C" fn KEM_ml_kem_1024_storage_bss_get() -> *mut KEM {
    return &mut KEM_ml_kem_1024_storage;
}
unsafe extern "C" fn KEM_ml_kem_1024() -> *const KEM {
    CRYPTO_once(
        KEM_ml_kem_1024_once_bss_get(),
        Some(KEM_ml_kem_1024_init as unsafe extern "C" fn() -> ()),
    );
    return KEM_ml_kem_1024_storage_bss_get() as *const KEM;
}
static mut KEM_ml_kem_1024_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn KEM_ml_kem_1024_init() {
    KEM_ml_kem_1024_do_init(KEM_ml_kem_1024_storage_bss_get());
}
static mut KEM_ml_kem_1024_storage: KEM = KEM {
    nid: 0,
    oid: 0 as *const uint8_t,
    oid_len: 0,
    comment: 0 as *const libc::c_char,
    public_key_len: 0,
    secret_key_len: 0,
    ciphertext_len: 0,
    shared_secret_len: 0,
    keygen_seed_len: 0,
    encaps_seed_len: 0,
    method: 0 as *const KEM_METHOD,
};
unsafe extern "C" fn KEM_ml_kem_1024_do_init(mut out: *mut KEM) {
    (*out).nid = 990 as libc::c_int;
    (*out).oid = kOIDMLKEM1024.as_ptr();
    (*out).oid_len = ::core::mem::size_of::<[uint8_t; 9]>() as libc::c_ulong as uint8_t;
    (*out).comment = b"MLKEM1024 \0" as *const u8 as *const libc::c_char;
    (*out).public_key_len = 1568 as libc::c_int as size_t;
    (*out).secret_key_len = 3168 as libc::c_int as size_t;
    (*out).ciphertext_len = 1568 as libc::c_int as size_t;
    (*out).shared_secret_len = 32 as libc::c_int as size_t;
    (*out).keygen_seed_len = 64 as libc::c_int as size_t;
    (*out).encaps_seed_len = 32 as libc::c_int as size_t;
    (*out).method = kem_ml_kem_1024_method();
}
#[no_mangle]
pub unsafe extern "C" fn KEM_find_kem_by_nid(mut nid: libc::c_int) -> *const KEM {
    match nid {
        988 => return KEM_ml_kem_512(),
        989 => return KEM_ml_kem_768(),
        990 => return KEM_ml_kem_1024(),
        972 => return get_legacy_kem_kyber512_r3(),
        973 => return get_legacy_kem_kyber768_r3(),
        974 => return get_legacy_kem_kyber1024_r3(),
        _ => return 0 as *const KEM,
    };
}
#[no_mangle]
pub unsafe extern "C" fn KEM_KEY_new() -> *mut KEM_KEY {
    let mut ret: *mut KEM_KEY = OPENSSL_zalloc(
        ::core::mem::size_of::<KEM_KEY>() as libc::c_ulong,
    ) as *mut KEM_KEY;
    if ret.is_null() {
        return 0 as *mut KEM_KEY;
    }
    return ret;
}
unsafe extern "C" fn KEM_KEY_clear(mut key: *mut KEM_KEY) {
    (*key).kem = 0 as *const KEM;
    OPENSSL_free((*key).public_key as *mut libc::c_void);
    OPENSSL_free((*key).secret_key as *mut libc::c_void);
    (*key).public_key = 0 as *mut uint8_t;
    (*key).secret_key = 0 as *mut uint8_t;
}
#[no_mangle]
pub unsafe extern "C" fn KEM_KEY_init(
    mut key: *mut KEM_KEY,
    mut kem: *const KEM,
) -> libc::c_int {
    if key.is_null() || kem.is_null() {
        return 0 as libc::c_int;
    }
    KEM_KEY_clear(key);
    (*key).kem = kem;
    (*key).public_key = OPENSSL_malloc((*kem).public_key_len) as *mut uint8_t;
    (*key).secret_key = OPENSSL_malloc((*kem).secret_key_len) as *mut uint8_t;
    if ((*key).public_key).is_null() || ((*key).secret_key).is_null() {
        KEM_KEY_clear(key);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn KEM_KEY_free(mut key: *mut KEM_KEY) {
    if key.is_null() {
        return;
    }
    KEM_KEY_clear(key);
    OPENSSL_free(key as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn KEM_KEY_get0_kem(mut key: *mut KEM_KEY) -> *const KEM {
    return (*key).kem;
}
#[no_mangle]
pub unsafe extern "C" fn KEM_KEY_set_raw_public_key(
    mut key: *mut KEM_KEY,
    mut in_0: *const uint8_t,
) -> libc::c_int {
    (*key)
        .public_key = OPENSSL_memdup(
        in_0 as *const libc::c_void,
        (*(*key).kem).public_key_len,
    ) as *mut uint8_t;
    if ((*key).public_key).is_null() {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn KEM_KEY_set_raw_secret_key(
    mut key: *mut KEM_KEY,
    mut in_0: *const uint8_t,
) -> libc::c_int {
    (*key)
        .secret_key = OPENSSL_memdup(
        in_0 as *const libc::c_void,
        (*(*key).kem).secret_key_len,
    ) as *mut uint8_t;
    if ((*key).secret_key).is_null() {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn KEM_KEY_set_raw_key(
    mut key: *mut KEM_KEY,
    mut in_public: *const uint8_t,
    mut in_secret: *const uint8_t,
) -> libc::c_int {
    (*key)
        .public_key = OPENSSL_memdup(
        in_public as *const libc::c_void,
        (*(*key).kem).public_key_len,
    ) as *mut uint8_t;
    (*key)
        .secret_key = OPENSSL_memdup(
        in_secret as *const libc::c_void,
        (*(*key).kem).secret_key_len,
    ) as *mut uint8_t;
    if ((*key).public_key).is_null() || ((*key).secret_key).is_null() {
        KEM_KEY_clear(key);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
