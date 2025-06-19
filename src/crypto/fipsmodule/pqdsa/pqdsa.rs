#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(extern_types)]
extern "C" {
    pub type dh_st;
    pub type dsa_st;
    pub type ec_key_st;
    pub type kem_key_st;
    pub type rsa_st;
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_copy_bytes(cbs: *mut CBS, out: *mut uint8_t, len: size_t) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
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
    fn ml_dsa_44_keypair(
        public_key: *mut uint8_t,
        secret_key: *mut uint8_t,
        seed: *mut uint8_t,
    ) -> libc::c_int;
    fn ml_dsa_44_pack_pk_from_sk(
        public_key: *mut uint8_t,
        private_key: *const uint8_t,
    ) -> libc::c_int;
    fn ml_dsa_44_keypair_internal(
        public_key: *mut uint8_t,
        private_key: *mut uint8_t,
        seed: *const uint8_t,
    ) -> libc::c_int;
    fn ml_dsa_44_sign(
        private_key: *const uint8_t,
        sig: *mut uint8_t,
        sig_len: *mut size_t,
        message: *const uint8_t,
        message_len: size_t,
        ctx_string: *const uint8_t,
        ctx_string_len: size_t,
    ) -> libc::c_int;
    fn ml_dsa_extmu_44_sign(
        private_key: *const uint8_t,
        sig: *mut uint8_t,
        sig_len: *mut size_t,
        mu: *const uint8_t,
        mu_len: size_t,
    ) -> libc::c_int;
    fn ml_dsa_44_verify(
        public_key: *const uint8_t,
        sig: *const uint8_t,
        sig_len: size_t,
        message: *const uint8_t,
        message_len: size_t,
        ctx_string: *const uint8_t,
        ctx_string_len: size_t,
    ) -> libc::c_int;
    fn ml_dsa_extmu_44_verify(
        public_key: *const uint8_t,
        sig: *const uint8_t,
        sig_len: size_t,
        mu: *const uint8_t,
        mu_len: size_t,
    ) -> libc::c_int;
    fn ml_dsa_65_keypair(
        public_key: *mut uint8_t,
        secret_key: *mut uint8_t,
        seed: *mut uint8_t,
    ) -> libc::c_int;
    fn ml_dsa_65_pack_pk_from_sk(
        public_key: *mut uint8_t,
        private_key: *const uint8_t,
    ) -> libc::c_int;
    fn ml_dsa_65_keypair_internal(
        public_key: *mut uint8_t,
        private_key: *mut uint8_t,
        seed: *const uint8_t,
    ) -> libc::c_int;
    fn ml_dsa_65_sign(
        private_key: *const uint8_t,
        sig: *mut uint8_t,
        sig_len: *mut size_t,
        message: *const uint8_t,
        message_len: size_t,
        ctx_string: *const uint8_t,
        ctx_string_len: size_t,
    ) -> libc::c_int;
    fn ml_dsa_extmu_65_sign(
        private_key: *const uint8_t,
        sig: *mut uint8_t,
        sig_len: *mut size_t,
        mu: *const uint8_t,
        mu_len: size_t,
    ) -> libc::c_int;
    fn ml_dsa_65_verify(
        public_key: *const uint8_t,
        sig: *const uint8_t,
        sig_len: size_t,
        message: *const uint8_t,
        message_len: size_t,
        ctx_string: *const uint8_t,
        ctx_string_len: size_t,
    ) -> libc::c_int;
    fn ml_dsa_extmu_65_verify(
        public_key: *const uint8_t,
        sig: *const uint8_t,
        sig_len: size_t,
        mu: *const uint8_t,
        mu_len: size_t,
    ) -> libc::c_int;
    fn ml_dsa_87_keypair(
        public_key: *mut uint8_t,
        secret_key: *mut uint8_t,
        seed: *mut uint8_t,
    ) -> libc::c_int;
    fn ml_dsa_87_pack_pk_from_sk(
        public_key: *mut uint8_t,
        private_key: *const uint8_t,
    ) -> libc::c_int;
    fn ml_dsa_87_keypair_internal(
        public_key: *mut uint8_t,
        private_key: *mut uint8_t,
        seed: *const uint8_t,
    ) -> libc::c_int;
    fn ml_dsa_87_sign(
        private_key: *const uint8_t,
        sig: *mut uint8_t,
        sig_len: *mut size_t,
        message: *const uint8_t,
        message_len: size_t,
        ctx_string: *const uint8_t,
        ctx_string_len: size_t,
    ) -> libc::c_int;
    fn ml_dsa_extmu_87_sign(
        private_key: *const uint8_t,
        sig: *mut uint8_t,
        sig_len: *mut size_t,
        mu: *const uint8_t,
        mu_len: size_t,
    ) -> libc::c_int;
    fn ml_dsa_87_verify(
        public_key: *const uint8_t,
        sig: *const uint8_t,
        sig_len: size_t,
        message: *const uint8_t,
        message_len: size_t,
        ctx_string: *const uint8_t,
        ctx_string_len: size_t,
    ) -> libc::c_int;
    fn ml_dsa_extmu_87_verify(
        public_key: *const uint8_t,
        sig: *const uint8_t,
        sig_len: size_t,
        mu: *const uint8_t,
        mu_len: size_t,
    ) -> libc::c_int;
    static pqdsa_asn1_meth: EVP_PKEY_ASN1_METHOD;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type pthread_once_t = libc::c_int;
pub type CRYPTO_refcount_t = uint32_t;
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
pub type DH = dh_st;
pub type DSA = dsa_st;
pub type EC_KEY = ec_key_st;
pub type EVP_PKEY = evp_pkey_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_pkey_st {
    pub references: CRYPTO_refcount_t,
    pub type_0: libc::c_int,
    pub pkey: C2RustUnnamed_0,
    pub ameth: *const EVP_PKEY_ASN1_METHOD,
}
pub type EVP_PKEY_ASN1_METHOD = evp_pkey_asn1_method_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_pkey_asn1_method_st {
    pub pkey_id: libc::c_int,
    pub oid: [uint8_t; 11],
    pub oid_len: uint8_t,
    pub pem_str: *const libc::c_char,
    pub info: *const libc::c_char,
    pub pub_decode: Option::<
        unsafe extern "C" fn(*mut EVP_PKEY, *mut CBS, *mut CBS, *mut CBS) -> libc::c_int,
    >,
    pub pub_encode: Option::<
        unsafe extern "C" fn(*mut CBB, *const EVP_PKEY) -> libc::c_int,
    >,
    pub pub_cmp: Option::<
        unsafe extern "C" fn(*const EVP_PKEY, *const EVP_PKEY) -> libc::c_int,
    >,
    pub priv_decode: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY,
            *mut CBS,
            *mut CBS,
            *mut CBS,
            *mut CBS,
        ) -> libc::c_int,
    >,
    pub priv_encode: Option::<
        unsafe extern "C" fn(*mut CBB, *const EVP_PKEY) -> libc::c_int,
    >,
    pub priv_encode_v2: Option::<
        unsafe extern "C" fn(*mut CBB, *const EVP_PKEY) -> libc::c_int,
    >,
    pub set_priv_raw: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub set_pub_raw: Option::<
        unsafe extern "C" fn(*mut EVP_PKEY, *const uint8_t, size_t) -> libc::c_int,
    >,
    pub get_priv_raw: Option::<
        unsafe extern "C" fn(*const EVP_PKEY, *mut uint8_t, *mut size_t) -> libc::c_int,
    >,
    pub get_pub_raw: Option::<
        unsafe extern "C" fn(*const EVP_PKEY, *mut uint8_t, *mut size_t) -> libc::c_int,
    >,
    pub pkey_opaque: Option::<unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int>,
    pub pkey_size: Option::<unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int>,
    pub pkey_bits: Option::<unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int>,
    pub param_missing: Option::<unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int>,
    pub param_copy: Option::<
        unsafe extern "C" fn(*mut EVP_PKEY, *const EVP_PKEY) -> libc::c_int,
    >,
    pub param_cmp: Option::<
        unsafe extern "C" fn(*const EVP_PKEY, *const EVP_PKEY) -> libc::c_int,
    >,
    pub pkey_free: Option::<unsafe extern "C" fn(*mut EVP_PKEY) -> ()>,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub ptr: *mut libc::c_void,
    pub rsa: *mut RSA,
    pub dsa: *mut DSA,
    pub dh: *mut DH,
    pub ec: *mut EC_KEY,
    pub kem_key: *mut KEM_KEY,
    pub pqdsa_key: *mut PQDSA_KEY,
}
pub type PQDSA_KEY = pqdsa_key_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pqdsa_key_st {
    pub pqdsa: *const PQDSA,
    pub public_key: *mut uint8_t,
    pub private_key: *mut uint8_t,
    pub seed: *mut uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PQDSA {
    pub nid: libc::c_int,
    pub oid: *const uint8_t,
    pub oid_len: uint8_t,
    pub comment: *const libc::c_char,
    pub public_key_len: size_t,
    pub private_key_len: size_t,
    pub signature_len: size_t,
    pub keygen_seed_len: size_t,
    pub sign_seed_len: size_t,
    pub method: *const PQDSA_METHOD,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PQDSA_METHOD {
    pub pqdsa_keygen: Option::<
        unsafe extern "C" fn(*mut uint8_t, *mut uint8_t, *mut uint8_t) -> libc::c_int,
    >,
    pub pqdsa_keygen_internal: Option::<
        unsafe extern "C" fn(*mut uint8_t, *mut uint8_t, *const uint8_t) -> libc::c_int,
    >,
    pub pqdsa_sign_message: Option::<
        unsafe extern "C" fn(
            *const uint8_t,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub pqdsa_sign: Option::<
        unsafe extern "C" fn(
            *const uint8_t,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub pqdsa_verify_message: Option::<
        unsafe extern "C" fn(
            *const uint8_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub pqdsa_verify: Option::<
        unsafe extern "C" fn(
            *const uint8_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub pqdsa_pack_pk_from_sk: Option::<
        unsafe extern "C" fn(*mut uint8_t, *const uint8_t) -> libc::c_int,
    >,
}
pub type KEM_KEY = kem_key_st;
pub type RSA = rsa_st;
pub type CRYPTO_once_t = pthread_once_t;
static mut kOIDMLDSA44: [uint8_t; 9] = [
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x11 as libc::c_int as uint8_t,
];
static mut kOIDMLDSA65: [uint8_t; 9] = [
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x12 as libc::c_int as uint8_t,
];
static mut kOIDMLDSA87: [uint8_t; 9] = [
    0x60 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x13 as libc::c_int as uint8_t,
];
#[no_mangle]
pub unsafe extern "C" fn PQDSA_KEY_new() -> *mut PQDSA_KEY {
    let mut ret: *mut PQDSA_KEY = OPENSSL_zalloc(
        ::core::mem::size_of::<PQDSA_KEY>() as libc::c_ulong,
    ) as *mut PQDSA_KEY;
    if ret.is_null() {
        return 0 as *mut PQDSA_KEY;
    }
    return ret;
}
unsafe extern "C" fn PQDSA_KEY_clear(mut key: *mut PQDSA_KEY) {
    (*key).pqdsa = 0 as *const PQDSA;
    OPENSSL_free((*key).public_key as *mut libc::c_void);
    OPENSSL_free((*key).private_key as *mut libc::c_void);
    OPENSSL_free((*key).seed as *mut libc::c_void);
    (*key).public_key = 0 as *mut uint8_t;
    (*key).private_key = 0 as *mut uint8_t;
    (*key).seed = 0 as *mut uint8_t;
}
#[no_mangle]
pub unsafe extern "C" fn PQDSA_KEY_init(
    mut key: *mut PQDSA_KEY,
    mut pqdsa: *const PQDSA,
) -> libc::c_int {
    if key.is_null() || pqdsa.is_null() {
        return 0 as libc::c_int;
    }
    PQDSA_KEY_clear(key);
    (*key).pqdsa = pqdsa;
    (*key).public_key = OPENSSL_malloc((*pqdsa).public_key_len) as *mut uint8_t;
    (*key).private_key = OPENSSL_malloc((*pqdsa).private_key_len) as *mut uint8_t;
    (*key).seed = OPENSSL_malloc((*pqdsa).keygen_seed_len) as *mut uint8_t;
    if ((*key).public_key).is_null() || ((*key).private_key).is_null()
        || ((*key).seed).is_null()
    {
        PQDSA_KEY_clear(key);
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn PQDSA_KEY_free(mut key: *mut PQDSA_KEY) {
    if key.is_null() {
        return;
    }
    PQDSA_KEY_clear(key);
    OPENSSL_free(key as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn PQDSA_KEY_get0_dsa(mut key: *mut PQDSA_KEY) -> *const PQDSA {
    return (*key).pqdsa;
}
#[no_mangle]
pub unsafe extern "C" fn PQDSA_KEY_set_raw_public_key(
    mut key: *mut PQDSA_KEY,
    mut in_0: *mut CBS,
) -> libc::c_int {
    if CBS_len(in_0) != (*(*key).pqdsa).public_key_len {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            137 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/pqdsa/pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            76 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*key)
        .public_key = OPENSSL_memdup(
        CBS_data(in_0) as *const libc::c_void,
        (*(*key).pqdsa).public_key_len,
    ) as *mut uint8_t;
    if ((*key).public_key).is_null() {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn PQDSA_KEY_set_raw_keypair_from_seed(
    mut key: *mut PQDSA_KEY,
    mut in_0: *mut CBS,
) -> libc::c_int {
    if CBS_len(in_0) != (*(*key).pqdsa).keygen_seed_len {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            137 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/pqdsa/pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            91 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut public_key: *mut uint8_t = OPENSSL_malloc((*(*key).pqdsa).public_key_len)
        as *mut uint8_t;
    if public_key.is_null() {
        return 0 as libc::c_int;
    }
    let mut private_key: *mut uint8_t = OPENSSL_malloc((*(*key).pqdsa).private_key_len)
        as *mut uint8_t;
    if private_key.is_null() {
        OPENSSL_free(public_key as *mut libc::c_void);
        return 0 as libc::c_int;
    }
    let mut seed: *mut uint8_t = OPENSSL_malloc((*(*key).pqdsa).keygen_seed_len)
        as *mut uint8_t;
    if seed.is_null() {
        OPENSSL_free(private_key as *mut libc::c_void);
        OPENSSL_free(public_key as *mut libc::c_void);
        return 0 as libc::c_int;
    }
    if ((*(*(*key).pqdsa).method).pqdsa_keygen_internal)
        .expect("non-null function pointer")(public_key, private_key, CBS_data(in_0))
        == 0
    {
        OPENSSL_free(public_key as *mut libc::c_void);
        OPENSSL_free(private_key as *mut libc::c_void);
        OPENSSL_free(seed as *mut libc::c_void);
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/pqdsa/pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            121 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if CBS_copy_bytes(in_0, seed, (*(*key).pqdsa).keygen_seed_len) == 0 {
        OPENSSL_free(public_key as *mut libc::c_void);
        OPENSSL_free(private_key as *mut libc::c_void);
        OPENSSL_free(seed as *mut libc::c_void);
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/pqdsa/pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            130 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*key).public_key = public_key;
    (*key).private_key = private_key;
    (*key).seed = seed;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn PQDSA_KEY_set_raw_private_key(
    mut key: *mut PQDSA_KEY,
    mut in_0: *mut CBS,
) -> libc::c_int {
    if CBS_len(in_0) != (*(*key).pqdsa).private_key_len {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            137 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/pqdsa/pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            144 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*key)
        .private_key = OPENSSL_memdup(
        CBS_data(in_0) as *const libc::c_void,
        (*(*key).pqdsa).private_key_len,
    ) as *mut uint8_t;
    if ((*key).private_key).is_null() {
        return 0 as libc::c_int;
    }
    let mut pk_len: size_t = (*(*key).pqdsa).public_key_len;
    let mut public_key: *mut uint8_t = OPENSSL_malloc(pk_len) as *mut uint8_t;
    if public_key.is_null() {
        return 0 as libc::c_int;
    }
    if ((*(*(*key).pqdsa).method).pqdsa_pack_pk_from_sk)
        .expect("non-null function pointer")(public_key, (*key).private_key) == 0
    {
        OPENSSL_free(public_key as *mut libc::c_void);
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/pqdsa/pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            164 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*key).public_key = public_key;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn PQDSA_KEY_set_raw_keypair_from_both(
    mut key: *mut PQDSA_KEY,
    mut seed: *mut CBS,
    mut expanded_key: *mut CBS,
) -> libc::c_int {
    if CBS_len(seed) != (*(*key).pqdsa).keygen_seed_len
        || CBS_len(expanded_key) != (*(*key).pqdsa).private_key_len
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            137 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/pqdsa/pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            189 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut seed_public_key: *mut uint8_t = OPENSSL_malloc(
        (*(*key).pqdsa).public_key_len,
    ) as *mut uint8_t;
    if seed_public_key.is_null() {
        return 0 as libc::c_int;
    }
    let mut seed_private_key: *mut uint8_t = OPENSSL_malloc(
        (*(*key).pqdsa).private_key_len,
    ) as *mut uint8_t;
    if seed_private_key.is_null() {
        OPENSSL_free(seed_public_key as *mut libc::c_void);
        return 0 as libc::c_int;
    }
    if ((*(*(*key).pqdsa).method).pqdsa_keygen_internal)
        .expect(
            "non-null function pointer",
        )(seed_public_key, seed_private_key, CBS_data(seed)) == 0
    {
        OPENSSL_free(seed_public_key as *mut libc::c_void);
        OPENSSL_free(seed_private_key as *mut libc::c_void);
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/pqdsa/pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            211 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut expanded_public_key: *mut uint8_t = OPENSSL_malloc(
        (*(*key).pqdsa).public_key_len,
    ) as *mut uint8_t;
    if expanded_public_key.is_null() {
        OPENSSL_free(seed_public_key as *mut libc::c_void);
        OPENSSL_free(seed_private_key as *mut libc::c_void);
        return 0 as libc::c_int;
    }
    if ((*(*(*key).pqdsa).method).pqdsa_pack_pk_from_sk)
        .expect("non-null function pointer")(expanded_public_key, CBS_data(expanded_key))
        == 0
    {
        OPENSSL_free(seed_public_key as *mut libc::c_void);
        OPENSSL_free(seed_private_key as *mut libc::c_void);
        OPENSSL_free(expanded_public_key as *mut libc::c_void);
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/pqdsa/pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            229 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if CRYPTO_memcmp(
        seed_public_key as *const libc::c_void,
        expanded_public_key as *const libc::c_void,
        (*(*key).pqdsa).public_key_len,
    ) != 0 as libc::c_int
    {
        OPENSSL_free(seed_public_key as *mut libc::c_void);
        OPENSSL_free(seed_private_key as *mut libc::c_void);
        OPENSSL_free(expanded_public_key as *mut libc::c_void);
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/pqdsa/pqdsa.c\0"
                as *const u8 as *const libc::c_char,
            239 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*key).public_key = expanded_public_key;
    OPENSSL_free(seed_public_key as *mut libc::c_void);
    OPENSSL_free(seed_private_key as *mut libc::c_void);
    (*key)
        .private_key = OPENSSL_memdup(
        CBS_data(expanded_key) as *const libc::c_void,
        (*(*key).pqdsa).private_key_len,
    ) as *mut uint8_t;
    if ((*key).private_key).is_null() {
        OPENSSL_free((*key).public_key as *mut libc::c_void);
        (*key).public_key = 0 as *mut uint8_t;
        return 0 as libc::c_int;
    }
    (*key)
        .seed = OPENSSL_memdup(
        CBS_data(seed) as *const libc::c_void,
        (*(*key).pqdsa).keygen_seed_len,
    ) as *mut uint8_t;
    if ((*key).seed).is_null() {
        OPENSSL_free((*key).private_key as *mut libc::c_void);
        (*key).private_key = 0 as *mut uint8_t;
        OPENSSL_free((*key).public_key as *mut libc::c_void);
        (*key).public_key = 0 as *mut uint8_t;
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn sig_ml_dsa_44_method() -> *const PQDSA_METHOD {
    CRYPTO_once(
        sig_ml_dsa_44_method_once_bss_get(),
        Some(sig_ml_dsa_44_method_init as unsafe extern "C" fn() -> ()),
    );
    return sig_ml_dsa_44_method_storage_bss_get() as *const PQDSA_METHOD;
}
static mut sig_ml_dsa_44_method_storage: PQDSA_METHOD = PQDSA_METHOD {
    pqdsa_keygen: None,
    pqdsa_keygen_internal: None,
    pqdsa_sign_message: None,
    pqdsa_sign: None,
    pqdsa_verify_message: None,
    pqdsa_verify: None,
    pqdsa_pack_pk_from_sk: None,
};
unsafe extern "C" fn sig_ml_dsa_44_method_init() {
    sig_ml_dsa_44_method_do_init(sig_ml_dsa_44_method_storage_bss_get());
}
unsafe extern "C" fn sig_ml_dsa_44_method_storage_bss_get() -> *mut PQDSA_METHOD {
    return &mut sig_ml_dsa_44_method_storage;
}
unsafe extern "C" fn sig_ml_dsa_44_method_do_init(mut out: *mut PQDSA_METHOD) {
    (*out)
        .pqdsa_keygen = Some(
        ml_dsa_44_keypair
            as unsafe extern "C" fn(
                *mut uint8_t,
                *mut uint8_t,
                *mut uint8_t,
            ) -> libc::c_int,
    );
    (*out)
        .pqdsa_keygen_internal = Some(
        ml_dsa_44_keypair_internal
            as unsafe extern "C" fn(
                *mut uint8_t,
                *mut uint8_t,
                *const uint8_t,
            ) -> libc::c_int,
    );
    (*out)
        .pqdsa_sign_message = Some(
        ml_dsa_44_sign
            as unsafe extern "C" fn(
                *const uint8_t,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
                size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .pqdsa_sign = Some(
        ml_dsa_extmu_44_sign
            as unsafe extern "C" fn(
                *const uint8_t,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .pqdsa_verify_message = Some(
        ml_dsa_44_verify
            as unsafe extern "C" fn(
                *const uint8_t,
                *const uint8_t,
                size_t,
                *const uint8_t,
                size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .pqdsa_verify = Some(
        ml_dsa_extmu_44_verify
            as unsafe extern "C" fn(
                *const uint8_t,
                *const uint8_t,
                size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .pqdsa_pack_pk_from_sk = Some(
        ml_dsa_44_pack_pk_from_sk
            as unsafe extern "C" fn(*mut uint8_t, *const uint8_t) -> libc::c_int,
    );
}
unsafe extern "C" fn sig_ml_dsa_44_method_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut sig_ml_dsa_44_method_once;
}
static mut sig_ml_dsa_44_method_once: CRYPTO_once_t = 0 as libc::c_int;
static mut sig_ml_dsa_65_method_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn sig_ml_dsa_65_method_storage_bss_get() -> *mut PQDSA_METHOD {
    return &mut sig_ml_dsa_65_method_storage;
}
unsafe extern "C" fn sig_ml_dsa_65_method() -> *const PQDSA_METHOD {
    CRYPTO_once(
        sig_ml_dsa_65_method_once_bss_get(),
        Some(sig_ml_dsa_65_method_init as unsafe extern "C" fn() -> ()),
    );
    return sig_ml_dsa_65_method_storage_bss_get() as *const PQDSA_METHOD;
}
unsafe extern "C" fn sig_ml_dsa_65_method_init() {
    sig_ml_dsa_65_method_do_init(sig_ml_dsa_65_method_storage_bss_get());
}
unsafe extern "C" fn sig_ml_dsa_65_method_do_init(mut out: *mut PQDSA_METHOD) {
    (*out)
        .pqdsa_keygen = Some(
        ml_dsa_65_keypair
            as unsafe extern "C" fn(
                *mut uint8_t,
                *mut uint8_t,
                *mut uint8_t,
            ) -> libc::c_int,
    );
    (*out)
        .pqdsa_keygen_internal = Some(
        ml_dsa_65_keypair_internal
            as unsafe extern "C" fn(
                *mut uint8_t,
                *mut uint8_t,
                *const uint8_t,
            ) -> libc::c_int,
    );
    (*out)
        .pqdsa_sign_message = Some(
        ml_dsa_65_sign
            as unsafe extern "C" fn(
                *const uint8_t,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
                size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .pqdsa_sign = Some(
        ml_dsa_extmu_65_sign
            as unsafe extern "C" fn(
                *const uint8_t,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .pqdsa_verify_message = Some(
        ml_dsa_65_verify
            as unsafe extern "C" fn(
                *const uint8_t,
                *const uint8_t,
                size_t,
                *const uint8_t,
                size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .pqdsa_verify = Some(
        ml_dsa_extmu_65_verify
            as unsafe extern "C" fn(
                *const uint8_t,
                *const uint8_t,
                size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .pqdsa_pack_pk_from_sk = Some(
        ml_dsa_65_pack_pk_from_sk
            as unsafe extern "C" fn(*mut uint8_t, *const uint8_t) -> libc::c_int,
    );
}
unsafe extern "C" fn sig_ml_dsa_65_method_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut sig_ml_dsa_65_method_once;
}
static mut sig_ml_dsa_65_method_storage: PQDSA_METHOD = PQDSA_METHOD {
    pqdsa_keygen: None,
    pqdsa_keygen_internal: None,
    pqdsa_sign_message: None,
    pqdsa_sign: None,
    pqdsa_verify_message: None,
    pqdsa_verify: None,
    pqdsa_pack_pk_from_sk: None,
};
unsafe extern "C" fn sig_ml_dsa_87_method_init() {
    sig_ml_dsa_87_method_do_init(sig_ml_dsa_87_method_storage_bss_get());
}
static mut sig_ml_dsa_87_method_storage: PQDSA_METHOD = PQDSA_METHOD {
    pqdsa_keygen: None,
    pqdsa_keygen_internal: None,
    pqdsa_sign_message: None,
    pqdsa_sign: None,
    pqdsa_verify_message: None,
    pqdsa_verify: None,
    pqdsa_pack_pk_from_sk: None,
};
unsafe extern "C" fn sig_ml_dsa_87_method() -> *const PQDSA_METHOD {
    CRYPTO_once(
        sig_ml_dsa_87_method_once_bss_get(),
        Some(sig_ml_dsa_87_method_init as unsafe extern "C" fn() -> ()),
    );
    return sig_ml_dsa_87_method_storage_bss_get() as *const PQDSA_METHOD;
}
unsafe extern "C" fn sig_ml_dsa_87_method_storage_bss_get() -> *mut PQDSA_METHOD {
    return &mut sig_ml_dsa_87_method_storage;
}
unsafe extern "C" fn sig_ml_dsa_87_method_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut sig_ml_dsa_87_method_once;
}
static mut sig_ml_dsa_87_method_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn sig_ml_dsa_87_method_do_init(mut out: *mut PQDSA_METHOD) {
    (*out)
        .pqdsa_keygen = Some(
        ml_dsa_87_keypair
            as unsafe extern "C" fn(
                *mut uint8_t,
                *mut uint8_t,
                *mut uint8_t,
            ) -> libc::c_int,
    );
    (*out)
        .pqdsa_keygen_internal = Some(
        ml_dsa_87_keypair_internal
            as unsafe extern "C" fn(
                *mut uint8_t,
                *mut uint8_t,
                *const uint8_t,
            ) -> libc::c_int,
    );
    (*out)
        .pqdsa_sign_message = Some(
        ml_dsa_87_sign
            as unsafe extern "C" fn(
                *const uint8_t,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
                size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .pqdsa_sign = Some(
        ml_dsa_extmu_87_sign
            as unsafe extern "C" fn(
                *const uint8_t,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .pqdsa_verify_message = Some(
        ml_dsa_87_verify
            as unsafe extern "C" fn(
                *const uint8_t,
                *const uint8_t,
                size_t,
                *const uint8_t,
                size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .pqdsa_verify = Some(
        ml_dsa_extmu_87_verify
            as unsafe extern "C" fn(
                *const uint8_t,
                *const uint8_t,
                size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .pqdsa_pack_pk_from_sk = Some(
        ml_dsa_87_pack_pk_from_sk
            as unsafe extern "C" fn(*mut uint8_t, *const uint8_t) -> libc::c_int,
    );
}
unsafe extern "C" fn sig_ml_dsa_44_do_init(mut out: *mut PQDSA) {
    (*out).nid = 994 as libc::c_int;
    (*out).oid = kOIDMLDSA44.as_ptr();
    (*out).oid_len = ::core::mem::size_of::<[uint8_t; 9]>() as libc::c_ulong as uint8_t;
    (*out).comment = b"MLDSA44\0" as *const u8 as *const libc::c_char;
    (*out).public_key_len = 1312 as libc::c_int as size_t;
    (*out).private_key_len = 2560 as libc::c_int as size_t;
    (*out).signature_len = 2420 as libc::c_int as size_t;
    (*out).keygen_seed_len = 32 as libc::c_int as size_t;
    (*out).sign_seed_len = 32 as libc::c_int as size_t;
    (*out).method = sig_ml_dsa_44_method();
}
unsafe extern "C" fn sig_ml_dsa_44_storage_bss_get() -> *mut PQDSA {
    return &mut sig_ml_dsa_44_storage;
}
unsafe extern "C" fn sig_ml_dsa_44_init() {
    sig_ml_dsa_44_do_init(sig_ml_dsa_44_storage_bss_get());
}
static mut sig_ml_dsa_44_storage: PQDSA = PQDSA {
    nid: 0,
    oid: 0 as *const uint8_t,
    oid_len: 0,
    comment: 0 as *const libc::c_char,
    public_key_len: 0,
    private_key_len: 0,
    signature_len: 0,
    keygen_seed_len: 0,
    sign_seed_len: 0,
    method: 0 as *const PQDSA_METHOD,
};
unsafe extern "C" fn sig_ml_dsa_44() -> *const PQDSA {
    CRYPTO_once(
        sig_ml_dsa_44_once_bss_get(),
        Some(sig_ml_dsa_44_init as unsafe extern "C" fn() -> ()),
    );
    return sig_ml_dsa_44_storage_bss_get() as *const PQDSA;
}
unsafe extern "C" fn sig_ml_dsa_44_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut sig_ml_dsa_44_once;
}
static mut sig_ml_dsa_44_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn sig_ml_dsa_65_do_init(mut out: *mut PQDSA) {
    (*out).nid = 995 as libc::c_int;
    (*out).oid = kOIDMLDSA65.as_ptr();
    (*out).oid_len = ::core::mem::size_of::<[uint8_t; 9]>() as libc::c_ulong as uint8_t;
    (*out).comment = b"MLDSA65\0" as *const u8 as *const libc::c_char;
    (*out).public_key_len = 1952 as libc::c_int as size_t;
    (*out).private_key_len = 4032 as libc::c_int as size_t;
    (*out).signature_len = 3309 as libc::c_int as size_t;
    (*out).keygen_seed_len = 32 as libc::c_int as size_t;
    (*out).sign_seed_len = 32 as libc::c_int as size_t;
    (*out).method = sig_ml_dsa_65_method();
}
unsafe extern "C" fn sig_ml_dsa_65_storage_bss_get() -> *mut PQDSA {
    return &mut sig_ml_dsa_65_storage;
}
static mut sig_ml_dsa_65_storage: PQDSA = PQDSA {
    nid: 0,
    oid: 0 as *const uint8_t,
    oid_len: 0,
    comment: 0 as *const libc::c_char,
    public_key_len: 0,
    private_key_len: 0,
    signature_len: 0,
    keygen_seed_len: 0,
    sign_seed_len: 0,
    method: 0 as *const PQDSA_METHOD,
};
unsafe extern "C" fn sig_ml_dsa_65() -> *const PQDSA {
    CRYPTO_once(
        sig_ml_dsa_65_once_bss_get(),
        Some(sig_ml_dsa_65_init as unsafe extern "C" fn() -> ()),
    );
    return sig_ml_dsa_65_storage_bss_get() as *const PQDSA;
}
unsafe extern "C" fn sig_ml_dsa_65_init() {
    sig_ml_dsa_65_do_init(sig_ml_dsa_65_storage_bss_get());
}
unsafe extern "C" fn sig_ml_dsa_65_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut sig_ml_dsa_65_once;
}
static mut sig_ml_dsa_65_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn sig_ml_dsa_87_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut sig_ml_dsa_87_once;
}
static mut sig_ml_dsa_87_storage: PQDSA = PQDSA {
    nid: 0,
    oid: 0 as *const uint8_t,
    oid_len: 0,
    comment: 0 as *const libc::c_char,
    public_key_len: 0,
    private_key_len: 0,
    signature_len: 0,
    keygen_seed_len: 0,
    sign_seed_len: 0,
    method: 0 as *const PQDSA_METHOD,
};
static mut sig_ml_dsa_87_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn sig_ml_dsa_87() -> *const PQDSA {
    CRYPTO_once(
        sig_ml_dsa_87_once_bss_get(),
        Some(sig_ml_dsa_87_init as unsafe extern "C" fn() -> ()),
    );
    return sig_ml_dsa_87_storage_bss_get() as *const PQDSA;
}
unsafe extern "C" fn sig_ml_dsa_87_init() {
    sig_ml_dsa_87_do_init(sig_ml_dsa_87_storage_bss_get());
}
unsafe extern "C" fn sig_ml_dsa_87_do_init(mut out: *mut PQDSA) {
    (*out).nid = 996 as libc::c_int;
    (*out).oid = kOIDMLDSA87.as_ptr();
    (*out).oid_len = ::core::mem::size_of::<[uint8_t; 9]>() as libc::c_ulong as uint8_t;
    (*out).comment = b"MLDSA87\0" as *const u8 as *const libc::c_char;
    (*out).public_key_len = 2592 as libc::c_int as size_t;
    (*out).private_key_len = 4896 as libc::c_int as size_t;
    (*out).signature_len = 4627 as libc::c_int as size_t;
    (*out).keygen_seed_len = 32 as libc::c_int as size_t;
    (*out).sign_seed_len = 32 as libc::c_int as size_t;
    (*out).method = sig_ml_dsa_87_method();
}
unsafe extern "C" fn sig_ml_dsa_87_storage_bss_get() -> *mut PQDSA {
    return &mut sig_ml_dsa_87_storage;
}
#[no_mangle]
pub unsafe extern "C" fn PQDSA_find_dsa_by_nid(mut nid: libc::c_int) -> *const PQDSA {
    match nid {
        994 => return sig_ml_dsa_44(),
        995 => return sig_ml_dsa_65(),
        996 => return sig_ml_dsa_87(),
        _ => return 0 as *const PQDSA,
    };
}
#[no_mangle]
pub unsafe extern "C" fn PQDSA_find_asn1_by_nid(
    mut nid: libc::c_int,
) -> *const EVP_PKEY_ASN1_METHOD {
    match nid {
        994 | 995 | 996 => return &pqdsa_asn1_meth,
        _ => return 0 as *const EVP_PKEY_ASN1_METHOD,
    };
}
