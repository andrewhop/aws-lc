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
    pub type stack_st_void;
    pub type dh_st;
    pub type dsa_st;
    pub type ec_key_st;
    pub type engine_st;
    pub type pqdsa_key_st;
    pub type kem_key_st;
    pub type bn_blinding_st;
    pub type env_md_st;
    fn strtol(
        _: *const libc::c_char,
        _: *mut *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_long;
    fn BN_new() -> *mut BIGNUM;
    fn BN_free(bn: *mut BIGNUM);
    fn BN_dup(src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_set_word(bn: *mut BIGNUM, value: BN_ULONG) -> libc::c_int;
    fn BN_asc2bn(outp: *mut *mut BIGNUM, in_0: *const libc::c_char) -> libc::c_int;
    fn BN_GENCB_new() -> *mut BN_GENCB;
    fn BN_GENCB_free(callback: *mut BN_GENCB);
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn EVP_sha1() -> *const EVP_MD;
    fn EVP_MD_type(md: *const EVP_MD) -> libc::c_int;
    fn EVP_MD_size(md: *const EVP_MD) -> size_t;
    fn EVP_PKEY_CTX_ctrl(
        ctx: *mut EVP_PKEY_CTX,
        keytype: libc::c_int,
        optype: libc::c_int,
        cmd: libc::c_int,
        p1: libc::c_int,
        p2: *mut libc::c_void,
    ) -> libc::c_int;
    fn EVP_PKEY_CTX_md(
        ctx: *mut EVP_PKEY_CTX,
        optype: libc::c_int,
        cmd: libc::c_int,
        md: *const libc::c_char,
    ) -> libc::c_int;
    fn evp_pkey_set_cb_translate(cb: *mut BN_GENCB, ctx: *mut EVP_PKEY_CTX);
    fn RSASSA_PSS_PARAMS_create(
        sigmd: *const EVP_MD,
        mgf1md: *const EVP_MD,
        saltlen: libc::c_int,
        out: *mut *mut RSASSA_PSS_PARAMS,
    ) -> libc::c_int;
    fn RSASSA_PSS_PARAMS_get(
        pss: *const RSASSA_PSS_PARAMS,
        md: *mut *const EVP_MD,
        mgf1md: *mut *const EVP_MD,
        saltlen: *mut libc::c_int,
    ) -> libc::c_int;
    fn RSA_padding_check_PKCS1_OAEP_mgf1(
        out: *mut uint8_t,
        out_len: *mut size_t,
        max_out: size_t,
        from: *const uint8_t,
        from_len: size_t,
        param: *const uint8_t,
        param_len: size_t,
        md: *const EVP_MD,
        mgf1md: *const EVP_MD,
    ) -> libc::c_int;
    fn EVP_PKEY_size(pkey: *const EVP_PKEY) -> libc::c_int;
    fn EVP_PKEY_assign_RSA(pkey: *mut EVP_PKEY, key: *mut RSA) -> libc::c_int;
    fn EVP_PKEY_assign(
        pkey: *mut EVP_PKEY,
        type_0: libc::c_int,
        key: *mut libc::c_void,
    ) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn CRYPTO_memcmp(
        a: *const libc::c_void,
        b: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn OPENSSL_hexstr2buf(str: *const libc::c_char, len: *mut size_t) -> *mut uint8_t;
    fn OPENSSL_memdup(data: *const libc::c_void, size: size_t) -> *mut libc::c_void;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn RSA_new() -> *mut RSA;
    fn RSA_free(rsa: *mut RSA);
    fn RSA_bits(rsa: *const RSA) -> libc::c_uint;
    fn RSA_generate_key_ex(
        rsa: *mut RSA,
        bits: libc::c_int,
        e: *const BIGNUM,
        cb: *mut BN_GENCB,
    ) -> libc::c_int;
    fn RSA_generate_key_fips(
        rsa: *mut RSA,
        bits: libc::c_int,
        cb: *mut BN_GENCB,
    ) -> libc::c_int;
    fn RSA_encrypt(
        rsa: *mut RSA,
        out_len: *mut size_t,
        out: *mut uint8_t,
        max_out: size_t,
        in_0: *const uint8_t,
        in_len: size_t,
        padding: libc::c_int,
    ) -> libc::c_int;
    fn RSA_decrypt(
        rsa: *mut RSA,
        out_len: *mut size_t,
        out: *mut uint8_t,
        max_out: size_t,
        in_0: *const uint8_t,
        in_len: size_t,
        padding: libc::c_int,
    ) -> libc::c_int;
    fn RSA_sign(
        hash_nid: libc::c_int,
        digest: *const uint8_t,
        digest_len: size_t,
        out: *mut uint8_t,
        out_len: *mut libc::c_uint,
        rsa: *mut RSA,
    ) -> libc::c_int;
    fn RSA_sign_pss_mgf1(
        rsa: *mut RSA,
        out_len: *mut size_t,
        out: *mut uint8_t,
        max_out: size_t,
        digest: *const uint8_t,
        digest_len: size_t,
        md: *const EVP_MD,
        mgf1_md: *const EVP_MD,
        salt_len: libc::c_int,
    ) -> libc::c_int;
    fn RSA_sign_raw(
        rsa: *mut RSA,
        out_len: *mut size_t,
        out: *mut uint8_t,
        max_out: size_t,
        in_0: *const uint8_t,
        in_len: size_t,
        padding: libc::c_int,
    ) -> libc::c_int;
    fn RSA_verify(
        hash_nid: libc::c_int,
        digest: *const uint8_t,
        digest_len: size_t,
        sig: *const uint8_t,
        sig_len: size_t,
        rsa: *mut RSA,
    ) -> libc::c_int;
    fn RSA_verify_pss_mgf1(
        rsa: *mut RSA,
        digest: *const uint8_t,
        digest_len: size_t,
        md: *const EVP_MD,
        mgf1_md: *const EVP_MD,
        salt_len: libc::c_int,
        sig: *const uint8_t,
        sig_len: size_t,
    ) -> libc::c_int;
    fn RSA_verify_raw(
        rsa: *mut RSA,
        out_len: *mut size_t,
        out: *mut uint8_t,
        max_out: size_t,
        in_0: *const uint8_t,
        in_len: size_t,
        padding: libc::c_int,
    ) -> libc::c_int;
    fn RSA_size(rsa: *const RSA) -> libc::c_uint;
    fn RSA_padding_add_PKCS1_OAEP_mgf1(
        to: *mut uint8_t,
        to_len: size_t,
        from: *const uint8_t,
        from_len: size_t,
        param: *const uint8_t,
        param_len: size_t,
        md: *const EVP_MD,
        mgf1md: *const EVP_MD,
    ) -> libc::c_int;
    fn RSA_add_pkcs1_prefix(
        out_msg: *mut *mut uint8_t,
        out_msg_len: *mut size_t,
        is_alloced: *mut libc::c_int,
        hash_nid: libc::c_int,
        digest: *const uint8_t,
        digest_len: size_t,
    ) -> libc::c_int;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn CRYPTO_once(
        once: *mut CRYPTO_once_t,
        init: Option::<unsafe extern "C" fn() -> ()>,
    );
    fn is_fips_build() -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type int64_t = __int64_t;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type pthread_once_t = libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bignum_st {
    pub d: *mut BN_ULONG,
    pub width: libc::c_int,
    pub dmax: libc::c_int,
    pub neg: libc::c_int,
    pub flags: libc::c_int,
}
pub type BN_ULONG = uint64_t;
pub type BIGNUM = bignum_st;
pub type CRYPTO_refcount_t = uint32_t;
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bn_gencb_st {
    pub type_0: uint8_t,
    pub arg: *mut libc::c_void,
    pub callback: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub new_style: Option::<
        unsafe extern "C" fn(libc::c_int, libc::c_int, *mut bn_gencb_st) -> libc::c_int,
    >,
    pub old_style: Option::<
        unsafe extern "C" fn(libc::c_int, libc::c_int, *mut libc::c_void) -> (),
    >,
}
pub type BN_GENCB = bn_gencb_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bn_mont_ctx_st {
    pub RR: BIGNUM,
    pub N: BIGNUM,
    pub n0: [BN_ULONG; 2],
}
pub type BN_MONT_CTX = bn_mont_ctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cbb_st {
    pub child: *mut CBB,
    pub is_child: libc::c_char,
    pub u: C2RustUnnamed_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
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
pub type ENGINE = engine_st;
pub type EVP_PKEY_CTX = evp_pkey_ctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_pkey_ctx_st {
    pub pmeth: *const EVP_PKEY_METHOD,
    pub engine: *mut ENGINE,
    pub pkey: *mut EVP_PKEY,
    pub peerkey: *mut EVP_PKEY,
    pub operation: libc::c_int,
    pub data: *mut libc::c_void,
    pub app_data: *mut libc::c_void,
    pub pkey_gencb: Option::<EVP_PKEY_gen_cb>,
    pub keygen_info: [libc::c_int; 2],
}
pub type EVP_PKEY_gen_cb = unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> libc::c_int;
pub type EVP_PKEY = evp_pkey_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_pkey_st {
    pub references: CRYPTO_refcount_t,
    pub type_0: libc::c_int,
    pub pkey: C2RustUnnamed_1,
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
pub union C2RustUnnamed_1 {
    pub ptr: *mut libc::c_void,
    pub rsa: *mut RSA,
    pub dsa: *mut DSA,
    pub dh: *mut DH,
    pub ec: *mut EC_KEY,
    pub kem_key: *mut KEM_KEY,
    pub pqdsa_key: *mut PQDSA_KEY,
}
pub type PQDSA_KEY = pqdsa_key_st;
pub type KEM_KEY = kem_key_st;
pub type RSA = rsa_st;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct rsa_st {
    pub meth: *const RSA_METHOD,
    pub n: *mut BIGNUM,
    pub e: *mut BIGNUM,
    pub d: *mut BIGNUM,
    pub p: *mut BIGNUM,
    pub q: *mut BIGNUM,
    pub dmp1: *mut BIGNUM,
    pub dmq1: *mut BIGNUM,
    pub iqmp: *mut BIGNUM,
    pub pss: *mut RSASSA_PSS_PARAMS,
    pub ex_data: CRYPTO_EX_DATA,
    pub references: CRYPTO_refcount_t,
    pub flags: libc::c_int,
    pub lock: CRYPTO_MUTEX,
    pub mont_n: *mut BN_MONT_CTX,
    pub mont_p: *mut BN_MONT_CTX,
    pub mont_q: *mut BN_MONT_CTX,
    pub d_fixed: *mut BIGNUM,
    pub dmp1_fixed: *mut BIGNUM,
    pub dmq1_fixed: *mut BIGNUM,
    pub iqmp_mont: *mut BIGNUM,
    pub num_blindings: size_t,
    pub blindings: *mut *mut BN_BLINDING,
    pub blindings_inuse: *mut libc::c_uchar,
    pub blinding_fork_generation: uint64_t,
    #[bitfield(name = "private_key_frozen", ty = "libc::c_uint", bits = "0..=0")]
    pub private_key_frozen: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
pub type BN_BLINDING = bn_blinding_st;
pub type CRYPTO_MUTEX = crypto_mutex_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub union crypto_mutex_st {
    pub alignment: libc::c_double,
    pub padding: [uint8_t; 56],
}
pub type RSASSA_PSS_PARAMS = rsassa_pss_params_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rsassa_pss_params_st {
    pub hash_algor: *mut RSA_ALGOR_IDENTIFIER,
    pub mask_gen_algor: *mut RSA_MGA_IDENTIFIER,
    pub salt_len: *mut RSA_INTEGER,
    pub trailer_field: *mut RSA_INTEGER,
}
pub type RSA_INTEGER = rsa_integer_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rsa_integer_st {
    pub value: int64_t,
}
pub type RSA_MGA_IDENTIFIER = rsa_mga_identifier_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rsa_mga_identifier_st {
    pub mask_gen: *mut RSA_ALGOR_IDENTIFIER,
    pub one_way_hash: *mut RSA_ALGOR_IDENTIFIER,
}
pub type RSA_ALGOR_IDENTIFIER = rsa_algor_identifier_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rsa_algor_identifier_st {
    pub nid: libc::c_int,
}
pub type RSA_METHOD = rsa_meth_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rsa_meth_st {
    pub app_data: *mut libc::c_void,
    pub init: Option::<unsafe extern "C" fn(*mut RSA) -> libc::c_int>,
    pub finish: Option::<unsafe extern "C" fn(*mut RSA) -> libc::c_int>,
    pub size: Option::<unsafe extern "C" fn(*const RSA) -> size_t>,
    pub sign: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            libc::c_uint,
            *mut uint8_t,
            *mut libc::c_uint,
            *const RSA,
        ) -> libc::c_int,
    >,
    pub sign_raw: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            *mut uint8_t,
            *mut RSA,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub verify_raw: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            *mut uint8_t,
            *mut RSA,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub decrypt: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            *mut uint8_t,
            *mut RSA,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub encrypt: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            *mut uint8_t,
            *mut RSA,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub private_transform: Option::<
        unsafe extern "C" fn(
            *mut RSA,
            *mut uint8_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub flags: libc::c_int,
}
pub type EVP_PKEY_METHOD = evp_pkey_method_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_pkey_method_st {
    pub pkey_id: libc::c_int,
    pub init: Option::<unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> libc::c_int>,
    pub copy: Option::<
        unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY_CTX) -> libc::c_int,
    >,
    pub cleanup: Option::<unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> ()>,
    pub keygen: Option::<
        unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY) -> libc::c_int,
    >,
    pub sign_init: Option::<unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> libc::c_int>,
    pub sign: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub sign_message: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub verify_init: Option::<unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> libc::c_int>,
    pub verify: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub verify_message: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub verify_recover: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub encrypt: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub decrypt: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub derive: Option::<
        unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut uint8_t, *mut size_t) -> libc::c_int,
    >,
    pub paramgen: Option::<
        unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY) -> libc::c_int,
    >,
    pub ctrl: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            libc::c_int,
            libc::c_int,
            *mut libc::c_void,
        ) -> libc::c_int,
    >,
    pub ctrl_str: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *const libc::c_char,
            *const libc::c_char,
        ) -> libc::c_int,
    >,
    pub keygen_deterministic: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut EVP_PKEY,
            *const uint8_t,
            *mut size_t,
        ) -> libc::c_int,
    >,
    pub encapsulate_deterministic: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut uint8_t,
            *mut size_t,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            *mut size_t,
        ) -> libc::c_int,
    >,
    pub encapsulate: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut uint8_t,
            *mut size_t,
            *mut uint8_t,
            *mut size_t,
        ) -> libc::c_int,
    >,
    pub decapsulate: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY_CTX,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
}
pub type EVP_MD = env_md_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct RSA_OAEP_LABEL_PARAMS {
    pub data: *mut uint8_t,
    pub len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct RSA_PKEY_CTX {
    pub nbits: libc::c_int,
    pub pub_exp: *mut BIGNUM,
    pub pad_mode: libc::c_int,
    pub md: *const EVP_MD,
    pub mgf1md: *const EVP_MD,
    pub saltlen: libc::c_int,
    pub min_saltlen: libc::c_int,
    pub tbuf: *mut uint8_t,
    pub oaep_label: *mut uint8_t,
    pub oaep_labellen: size_t,
}
pub type CRYPTO_once_t = pthread_once_t;
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
unsafe extern "C" fn FIPS_service_indicator_lock_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_unlock_state() {}
unsafe extern "C" fn pkey_ctx_is_pss(mut ctx: *mut EVP_PKEY_CTX) -> libc::c_int {
    return ((*(*ctx).pmeth).pkey_id == 912 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn pss_hash_algorithm_match(
    mut ctx: *mut EVP_PKEY_CTX,
    mut min_saltlen: libc::c_int,
    mut k_md: *const EVP_MD,
    mut s_md: *const EVP_MD,
) -> libc::c_int {
    if pkey_ctx_is_pss(ctx) != 0 && min_saltlen != -(1 as libc::c_int) {
        if !k_md.is_null() && !s_md.is_null() {
            return (EVP_MD_type(k_md) == EVP_MD_type(s_md)) as libc::c_int
        } else {
            return 0 as libc::c_int
        }
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn rsa_set_pss_param(
    mut rsa: *mut RSA,
    mut ctx: *mut EVP_PKEY_CTX,
) -> libc::c_int {
    if pkey_ctx_is_pss(ctx) == 0 {
        return 1 as libc::c_int;
    }
    let mut rctx: *mut RSA_PKEY_CTX = (*ctx).data as *mut RSA_PKEY_CTX;
    return RSASSA_PSS_PARAMS_create(
        (*rctx).md,
        (*rctx).mgf1md,
        (*rctx).saltlen,
        &mut (*rsa).pss,
    );
}
unsafe extern "C" fn pkey_pss_init(mut ctx: *mut EVP_PKEY_CTX) -> libc::c_int {
    let mut rsa: *mut RSA = 0 as *mut RSA;
    let mut rctx: *mut RSA_PKEY_CTX = (*ctx).data as *mut RSA_PKEY_CTX;
    let mut md: *const EVP_MD = 0 as *const EVP_MD;
    let mut mgf1md: *const EVP_MD = 0 as *const EVP_MD;
    let mut min_saltlen: libc::c_int = 0;
    let mut max_saltlen: libc::c_int = 0;
    if pkey_ctx_is_pss(ctx) == 0 {
        return 0 as libc::c_int;
    }
    if ((*ctx).pkey).is_null() {
        return 0 as libc::c_int;
    }
    rsa = (*(*ctx).pkey).pkey.rsa;
    if ((*rsa).pss).is_null() {
        return 1 as libc::c_int;
    }
    if RSASSA_PSS_PARAMS_get((*rsa).pss, &mut md, &mut mgf1md, &mut min_saltlen) == 0 {
        return 0 as libc::c_int;
    }
    max_saltlen = (RSA_size(rsa) as size_t)
        .wrapping_sub(EVP_MD_size(md))
        .wrapping_sub(2 as libc::c_int as size_t) as libc::c_int;
    if RSA_bits(rsa) & 0x7 as libc::c_int as libc::c_uint
        == 1 as libc::c_int as libc::c_uint
    {
        max_saltlen -= 1;
        max_saltlen;
    }
    if min_saltlen > max_saltlen {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            501 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_rsa.c\0"
                as *const u8 as *const libc::c_char,
            165 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*rctx).md = md;
    (*rctx).mgf1md = mgf1md;
    (*rctx).saltlen = min_saltlen;
    (*rctx).min_saltlen = min_saltlen;
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_pss_init_sign(mut ctx: *mut EVP_PKEY_CTX) -> libc::c_int {
    return pkey_pss_init(ctx);
}
unsafe extern "C" fn pkey_pss_init_verify(mut ctx: *mut EVP_PKEY_CTX) -> libc::c_int {
    return pkey_pss_init(ctx);
}
unsafe extern "C" fn pkey_rsa_init(mut ctx: *mut EVP_PKEY_CTX) -> libc::c_int {
    let mut rctx: *mut RSA_PKEY_CTX = 0 as *mut RSA_PKEY_CTX;
    rctx = OPENSSL_zalloc(::core::mem::size_of::<RSA_PKEY_CTX>() as libc::c_ulong)
        as *mut RSA_PKEY_CTX;
    if rctx.is_null() {
        return 0 as libc::c_int;
    }
    (*rctx).nbits = 2048 as libc::c_int;
    if pkey_ctx_is_pss(ctx) != 0 {
        (*rctx).pad_mode = 6 as libc::c_int;
    } else {
        (*rctx).pad_mode = 1 as libc::c_int;
    }
    (*rctx).saltlen = -(2 as libc::c_int);
    (*rctx).min_saltlen = -(1 as libc::c_int);
    (*ctx).data = rctx as *mut libc::c_void;
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_rsa_copy(
    mut dst: *mut EVP_PKEY_CTX,
    mut src: *mut EVP_PKEY_CTX,
) -> libc::c_int {
    let mut dctx: *mut RSA_PKEY_CTX = 0 as *mut RSA_PKEY_CTX;
    let mut sctx: *mut RSA_PKEY_CTX = 0 as *mut RSA_PKEY_CTX;
    if pkey_rsa_init(dst) == 0 {
        return 0 as libc::c_int;
    }
    sctx = (*src).data as *mut RSA_PKEY_CTX;
    dctx = (*dst).data as *mut RSA_PKEY_CTX;
    (*dctx).nbits = (*sctx).nbits;
    if !((*sctx).pub_exp).is_null() {
        (*dctx).pub_exp = BN_dup((*sctx).pub_exp);
        if ((*dctx).pub_exp).is_null() {
            return 0 as libc::c_int;
        }
    }
    (*dctx).pad_mode = (*sctx).pad_mode;
    (*dctx).md = (*sctx).md;
    (*dctx).mgf1md = (*sctx).mgf1md;
    (*dctx).saltlen = (*sctx).saltlen;
    if !((*sctx).oaep_label).is_null() {
        OPENSSL_free((*dctx).oaep_label as *mut libc::c_void);
        (*dctx)
            .oaep_label = OPENSSL_memdup(
            (*sctx).oaep_label as *const libc::c_void,
            (*sctx).oaep_labellen,
        ) as *mut uint8_t;
        if ((*dctx).oaep_label).is_null() {
            return 0 as libc::c_int;
        }
        (*dctx).oaep_labellen = (*sctx).oaep_labellen;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_rsa_cleanup(mut ctx: *mut EVP_PKEY_CTX) {
    let mut rctx: *mut RSA_PKEY_CTX = (*ctx).data as *mut RSA_PKEY_CTX;
    if rctx.is_null() {
        return;
    }
    BN_free((*rctx).pub_exp);
    OPENSSL_free((*rctx).tbuf as *mut libc::c_void);
    OPENSSL_free((*rctx).oaep_label as *mut libc::c_void);
    OPENSSL_free(rctx as *mut libc::c_void);
}
unsafe extern "C" fn setup_tbuf(
    mut ctx: *mut RSA_PKEY_CTX,
    mut pk: *mut EVP_PKEY_CTX,
) -> libc::c_int {
    if !((*ctx).tbuf).is_null() {
        return 1 as libc::c_int;
    }
    (*ctx).tbuf = OPENSSL_malloc(EVP_PKEY_size((*pk).pkey) as size_t) as *mut uint8_t;
    if ((*ctx).tbuf).is_null() {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_rsa_sign(
    mut ctx: *mut EVP_PKEY_CTX,
    mut sig: *mut uint8_t,
    mut siglen: *mut size_t,
    mut tbs: *const uint8_t,
    mut tbslen: size_t,
) -> libc::c_int {
    let mut rctx: *mut RSA_PKEY_CTX = (*ctx).data as *mut RSA_PKEY_CTX;
    let mut rsa: *mut RSA = (*(*ctx).pkey).pkey.rsa;
    let key_len: size_t = EVP_PKEY_size((*ctx).pkey) as size_t;
    if sig.is_null() {
        *siglen = key_len;
        return 1 as libc::c_int;
    }
    if *siglen < key_len {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_rsa.c\0"
                as *const u8 as *const libc::c_char,
            283 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if !((*rctx).md).is_null() {
        let mut out_len: libc::c_uint = 0;
        match (*rctx).pad_mode {
            1 => {
                if RSA_sign(EVP_MD_type((*rctx).md), tbs, tbslen, sig, &mut out_len, rsa)
                    == 0
                {
                    return 0 as libc::c_int;
                }
                *siglen = out_len as size_t;
                return 1 as libc::c_int;
            }
            6 => {
                return RSA_sign_pss_mgf1(
                    rsa,
                    siglen,
                    sig,
                    *siglen,
                    tbs,
                    tbslen,
                    (*rctx).md,
                    (*rctx).mgf1md,
                    (*rctx).saltlen,
                );
            }
            _ => return 0 as libc::c_int,
        }
    }
    return RSA_sign_raw(rsa, siglen, sig, *siglen, tbs, tbslen, (*rctx).pad_mode);
}
unsafe extern "C" fn pkey_rsa_verify(
    mut ctx: *mut EVP_PKEY_CTX,
    mut sig: *const uint8_t,
    mut siglen: size_t,
    mut tbs: *const uint8_t,
    mut tbslen: size_t,
) -> libc::c_int {
    let mut rctx: *mut RSA_PKEY_CTX = (*ctx).data as *mut RSA_PKEY_CTX;
    let mut rsa: *mut RSA = (*(*ctx).pkey).pkey.rsa;
    if !((*rctx).md).is_null() {
        match (*rctx).pad_mode {
            1 => {
                return RSA_verify(EVP_MD_type((*rctx).md), tbs, tbslen, sig, siglen, rsa);
            }
            6 => {
                return RSA_verify_pss_mgf1(
                    rsa,
                    tbs,
                    tbslen,
                    (*rctx).md,
                    (*rctx).mgf1md,
                    (*rctx).saltlen,
                    sig,
                    siglen,
                );
            }
            _ => return 0 as libc::c_int,
        }
    }
    let mut rslen: size_t = 0;
    let key_len: size_t = EVP_PKEY_size((*ctx).pkey) as size_t;
    if setup_tbuf(rctx, ctx) == 0
        || RSA_verify_raw(
            rsa,
            &mut rslen,
            (*rctx).tbuf,
            key_len,
            sig,
            siglen,
            (*rctx).pad_mode,
        ) == 0 || rslen != tbslen
        || CRYPTO_memcmp(
            tbs as *const libc::c_void,
            (*rctx).tbuf as *const libc::c_void,
            rslen,
        ) != 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_rsa_verify_recover(
    mut ctx: *mut EVP_PKEY_CTX,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
) -> libc::c_int {
    let mut rctx: *mut RSA_PKEY_CTX = (*ctx).data as *mut RSA_PKEY_CTX;
    let mut rsa: *mut RSA = (*(*ctx).pkey).pkey.rsa;
    let key_len: size_t = EVP_PKEY_size((*ctx).pkey) as size_t;
    if out.is_null() {
        *out_len = key_len;
        return 1 as libc::c_int;
    }
    if *out_len < key_len {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_rsa.c\0"
                as *const u8 as *const libc::c_char,
            355 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*rctx).md).is_null() {
        return RSA_verify_raw(
            rsa,
            out_len,
            out,
            *out_len,
            sig,
            sig_len,
            (*rctx).pad_mode,
        );
    }
    if (*rctx).pad_mode != 1 as libc::c_int {
        return 0 as libc::c_int;
    }
    static mut kDummyHash: [uint8_t; 64] = [
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
        0,
        0,
        0,
    ];
    let hash_len: size_t = EVP_MD_size((*rctx).md);
    let mut asn1_prefix: *mut uint8_t = 0 as *mut uint8_t;
    let mut asn1_prefix_len: size_t = 0;
    let mut asn1_prefix_allocated: libc::c_int = 0;
    if setup_tbuf(rctx, ctx) == 0
        || RSA_add_pkcs1_prefix(
            &mut asn1_prefix,
            &mut asn1_prefix_len,
            &mut asn1_prefix_allocated,
            EVP_MD_type((*rctx).md),
            kDummyHash.as_ptr(),
            hash_len,
        ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut rslen: size_t = 0;
    let mut ok: libc::c_int = 1 as libc::c_int;
    if RSA_verify_raw(
        rsa,
        &mut rslen,
        (*rctx).tbuf,
        key_len,
        sig,
        sig_len,
        1 as libc::c_int,
    ) == 0 || rslen != asn1_prefix_len
        || CRYPTO_memcmp(
            (*rctx).tbuf as *const libc::c_void,
            asn1_prefix as *const libc::c_void,
            asn1_prefix_len.wrapping_sub(hash_len),
        ) != 0 as libc::c_int
    {
        ok = 0 as libc::c_int;
    }
    if asn1_prefix_allocated != 0 {
        OPENSSL_free(asn1_prefix as *mut libc::c_void);
    }
    if ok == 0 {
        return 0 as libc::c_int;
    }
    if !out.is_null() {
        OPENSSL_memcpy(
            out as *mut libc::c_void,
            ((*rctx).tbuf).offset(rslen as isize).offset(-(hash_len as isize))
                as *const libc::c_void,
            hash_len,
        );
    }
    *out_len = hash_len;
    return 1 as libc::c_int;
}
unsafe extern "C" fn pkey_rsa_encrypt(
    mut ctx: *mut EVP_PKEY_CTX,
    mut out: *mut uint8_t,
    mut outlen: *mut size_t,
    mut in_0: *const uint8_t,
    mut inlen: size_t,
) -> libc::c_int {
    let mut rctx: *mut RSA_PKEY_CTX = (*ctx).data as *mut RSA_PKEY_CTX;
    let mut rsa: *mut RSA = (*(*ctx).pkey).pkey.rsa;
    let key_len: size_t = EVP_PKEY_size((*ctx).pkey) as size_t;
    if out.is_null() {
        *outlen = key_len;
        return 1 as libc::c_int;
    }
    if *outlen < key_len {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_rsa.c\0"
                as *const u8 as *const libc::c_char,
            419 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*rctx).pad_mode == 4 as libc::c_int {
        if setup_tbuf(rctx, ctx) == 0
            || RSA_padding_add_PKCS1_OAEP_mgf1(
                (*rctx).tbuf,
                key_len,
                in_0,
                inlen,
                (*rctx).oaep_label,
                (*rctx).oaep_labellen,
                (*rctx).md,
                (*rctx).mgf1md,
            ) == 0
            || RSA_encrypt(
                rsa,
                outlen,
                out,
                *outlen,
                (*rctx).tbuf,
                key_len,
                3 as libc::c_int,
            ) == 0
        {
            return 0 as libc::c_int;
        }
        return 1 as libc::c_int;
    }
    return RSA_encrypt(rsa, outlen, out, *outlen, in_0, inlen, (*rctx).pad_mode);
}
unsafe extern "C" fn pkey_rsa_decrypt(
    mut ctx: *mut EVP_PKEY_CTX,
    mut out: *mut uint8_t,
    mut outlen: *mut size_t,
    mut in_0: *const uint8_t,
    mut inlen: size_t,
) -> libc::c_int {
    let mut rctx: *mut RSA_PKEY_CTX = (*ctx).data as *mut RSA_PKEY_CTX;
    let mut rsa: *mut RSA = (*(*ctx).pkey).pkey.rsa;
    let key_len: size_t = EVP_PKEY_size((*ctx).pkey) as size_t;
    if out.is_null() {
        *outlen = key_len;
        return 1 as libc::c_int;
    }
    if *outlen < key_len {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_rsa.c\0"
                as *const u8 as *const libc::c_char,
            451 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*rctx).pad_mode == 4 as libc::c_int {
        let mut padded_len: size_t = 0;
        if setup_tbuf(rctx, ctx) == 0
            || RSA_decrypt(
                rsa,
                &mut padded_len,
                (*rctx).tbuf,
                key_len,
                in_0,
                inlen,
                3 as libc::c_int,
            ) == 0
            || RSA_padding_check_PKCS1_OAEP_mgf1(
                out,
                outlen,
                key_len,
                (*rctx).tbuf,
                padded_len,
                (*rctx).oaep_label,
                (*rctx).oaep_labellen,
                (*rctx).md,
                (*rctx).mgf1md,
            ) == 0
        {
            return 0 as libc::c_int;
        }
        return 1 as libc::c_int;
    }
    return RSA_decrypt(rsa, outlen, out, key_len, in_0, inlen, (*rctx).pad_mode);
}
unsafe extern "C" fn check_padding_md(
    mut md: *const EVP_MD,
    mut padding: libc::c_int,
) -> libc::c_int {
    if md.is_null() {
        return 1 as libc::c_int;
    }
    if padding == 3 as libc::c_int {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            115 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_rsa.c\0"
                as *const u8 as *const libc::c_char,
            477 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn is_known_padding(mut padding_mode: libc::c_int) -> libc::c_int {
    match padding_mode {
        1 | 3 | 4 | 6 => return 1 as libc::c_int,
        _ => return 0 as libc::c_int,
    };
}
unsafe extern "C" fn pkey_rsa_ctrl(
    mut ctx: *mut EVP_PKEY_CTX,
    mut type_0: libc::c_int,
    mut p1: libc::c_int,
    mut p2: *mut libc::c_void,
) -> libc::c_int {
    let mut rctx: *mut RSA_PKEY_CTX = (*ctx).data as *mut RSA_PKEY_CTX;
    match type_0 {
        4097 => {
            if is_known_padding(p1) == 0 || check_padding_md((*rctx).md, p1) == 0
                || p1 == 6 as libc::c_int
                    && 0 as libc::c_int
                        == (*ctx).operation
                            & ((1 as libc::c_int) << 3 as libc::c_int
                                | (1 as libc::c_int) << 4 as libc::c_int)
                || p1 == 4 as libc::c_int
                    && 0 as libc::c_int
                        == (*ctx).operation
                            & ((1 as libc::c_int) << 6 as libc::c_int
                                | (1 as libc::c_int) << 7 as libc::c_int)
            {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    109 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_rsa.c\0"
                        as *const u8 as *const libc::c_char,
                    505 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            if p1 != 6 as libc::c_int && pkey_ctx_is_pss(ctx) != 0 {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    109 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_rsa.c\0"
                        as *const u8 as *const libc::c_char,
                    509 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            if (p1 == 6 as libc::c_int || p1 == 4 as libc::c_int)
                && ((*rctx).md).is_null()
            {
                (*rctx).md = EVP_sha1();
            }
            (*rctx).pad_mode = p1;
            return 1 as libc::c_int;
        }
        4098 => {
            *(p2 as *mut libc::c_int) = (*rctx).pad_mode;
            return 1 as libc::c_int;
        }
        4099 | 4100 => {
            if (*rctx).pad_mode != 6 as libc::c_int {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    116 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_rsa.c\0"
                        as *const u8 as *const libc::c_char,
                    526 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            if type_0 == 0x1000 as libc::c_int + 4 as libc::c_int {
                *(p2 as *mut libc::c_int) = (*rctx).saltlen;
            } else {
                if p1 < -(2 as libc::c_int) {
                    return 0 as libc::c_int;
                }
                let mut min_saltlen: libc::c_int = (*rctx).min_saltlen;
                if min_saltlen != -(1 as libc::c_int) {
                    if p1 == -(1 as libc::c_int)
                        && min_saltlen as size_t > EVP_MD_size((*rctx).md)
                        || p1 >= 0 as libc::c_int && p1 < min_saltlen
                    {
                        ERR_put_error(
                            6 as libc::c_int,
                            0 as libc::c_int,
                            116 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_rsa.c\0"
                                as *const u8 as *const libc::c_char,
                            547 as libc::c_int as libc::c_uint,
                        );
                        return 0 as libc::c_int;
                    }
                }
                (*rctx).saltlen = p1;
            }
            return 1 as libc::c_int;
        }
        4101 => {
            if p1 < 256 as libc::c_int {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    112 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_rsa.c\0"
                        as *const u8 as *const libc::c_char,
                    557 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            (*rctx).nbits = p1;
            return 1 as libc::c_int;
        }
        4102 => {
            if p2.is_null() {
                return 0 as libc::c_int;
            }
            BN_free((*rctx).pub_exp);
            (*rctx).pub_exp = p2 as *mut BIGNUM;
            return 1 as libc::c_int;
        }
        4103 | 4104 => {
            if (*rctx).pad_mode != 4 as libc::c_int {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    115 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_rsa.c\0"
                        as *const u8 as *const libc::c_char,
                    579 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            if type_0 == 0x1000 as libc::c_int + 8 as libc::c_int {
                let ref mut fresh0 = *(p2 as *mut *const EVP_MD);
                *fresh0 = (*rctx).md;
            } else {
                (*rctx).md = p2 as *const EVP_MD;
            }
            return 1 as libc::c_int;
        }
        1 => {
            if check_padding_md(p2 as *const EVP_MD, (*rctx).pad_mode) == 0 {
                return 0 as libc::c_int;
            }
            if pss_hash_algorithm_match(
                ctx,
                (*rctx).min_saltlen,
                (*rctx).md,
                p2 as *const EVP_MD,
            ) == 0
            {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    500 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_rsa.c\0"
                        as *const u8 as *const libc::c_char,
                    596 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            (*rctx).md = p2 as *const EVP_MD;
            return 1 as libc::c_int;
        }
        2 => {
            let ref mut fresh1 = *(p2 as *mut *const EVP_MD);
            *fresh1 = (*rctx).md;
            return 1 as libc::c_int;
        }
        4105 | 4106 => {
            if (*rctx).pad_mode != 6 as libc::c_int
                && (*rctx).pad_mode != 4 as libc::c_int
            {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    113 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_rsa.c\0"
                        as *const u8 as *const libc::c_char,
                    610 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            if type_0 == 0x1000 as libc::c_int + 10 as libc::c_int {
                if !((*rctx).mgf1md).is_null() {
                    let ref mut fresh2 = *(p2 as *mut *const EVP_MD);
                    *fresh2 = (*rctx).mgf1md;
                } else {
                    let ref mut fresh3 = *(p2 as *mut *const EVP_MD);
                    *fresh3 = (*rctx).md;
                }
            } else {
                if pss_hash_algorithm_match(
                    ctx,
                    (*rctx).min_saltlen,
                    (*rctx).mgf1md,
                    p2 as *const EVP_MD,
                ) == 0
                {
                    ERR_put_error(
                        6 as libc::c_int,
                        0 as libc::c_int,
                        113 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_rsa.c\0"
                            as *const u8 as *const libc::c_char,
                        623 as libc::c_int as libc::c_uint,
                    );
                    return 0 as libc::c_int;
                }
                (*rctx).mgf1md = p2 as *const EVP_MD;
            }
            return 1 as libc::c_int;
        }
        4107 => {
            if (*rctx).pad_mode != 4 as libc::c_int {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    115 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_rsa.c\0"
                        as *const u8 as *const libc::c_char,
                    632 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            OPENSSL_free((*rctx).oaep_label as *mut libc::c_void);
            let mut params: *mut RSA_OAEP_LABEL_PARAMS = p2
                as *mut RSA_OAEP_LABEL_PARAMS;
            (*rctx).oaep_label = (*params).data;
            (*rctx).oaep_labellen = (*params).len;
            return 1 as libc::c_int;
        }
        4108 => {
            if (*rctx).pad_mode != 4 as libc::c_int {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    115 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_rsa.c\0"
                        as *const u8 as *const libc::c_char,
                    644 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            CBS_init(p2 as *mut CBS, (*rctx).oaep_label, (*rctx).oaep_labellen);
            return 1 as libc::c_int;
        }
        _ => {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                101 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_rsa.c\0"
                    as *const u8 as *const libc::c_char,
                651 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    };
}
unsafe extern "C" fn pkey_rsa_keygen(
    mut ctx: *mut EVP_PKEY_CTX,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut rsa: *mut RSA = 0 as *mut RSA;
    let mut rctx: *mut RSA_PKEY_CTX = (*ctx).data as *mut RSA_PKEY_CTX;
    let mut pkey_ctx_cb: *mut BN_GENCB = 0 as *mut BN_GENCB;
    if is_fips_build() == 0 && ((*rctx).pub_exp).is_null() {
        (*rctx).pub_exp = BN_new();
        if ((*rctx).pub_exp).is_null()
            || BN_set_word((*rctx).pub_exp, 0x10001 as libc::c_int as BN_ULONG) == 0
        {
            current_block = 12867726157650034850;
        } else {
            current_block = 7502529970979898288;
        }
    } else {
        current_block = 7502529970979898288;
    }
    match current_block {
        7502529970979898288 => {
            rsa = RSA_new();
            if !rsa.is_null() {
                if ((*ctx).pkey_gencb).is_some() {
                    pkey_ctx_cb = BN_GENCB_new();
                    if pkey_ctx_cb.is_null() {
                        current_block = 12867726157650034850;
                    } else {
                        evp_pkey_set_cb_translate(pkey_ctx_cb, ctx);
                        current_block = 11650488183268122163;
                    }
                } else {
                    current_block = 11650488183268122163;
                }
                match current_block {
                    12867726157650034850 => {}
                    _ => {
                        FIPS_service_indicator_lock_state();
                        if is_fips_build() == 0
                            && RSA_generate_key_ex(
                                rsa,
                                (*rctx).nbits,
                                (*rctx).pub_exp,
                                pkey_ctx_cb,
                            ) == 0
                            || is_fips_build() != 0
                                && RSA_generate_key_fips(rsa, (*rctx).nbits, pkey_ctx_cb)
                                    == 0 || rsa_set_pss_param(rsa, ctx) == 0
                        {
                            FIPS_service_indicator_unlock_state();
                        } else {
                            FIPS_service_indicator_unlock_state();
                            if pkey_ctx_is_pss(ctx) != 0 {
                                ret = EVP_PKEY_assign(
                                    pkey,
                                    912 as libc::c_int,
                                    rsa as *mut libc::c_void,
                                );
                            } else {
                                ret = EVP_PKEY_assign_RSA(pkey, rsa);
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    BN_GENCB_free(pkey_ctx_cb);
    if ret == 0 && !rsa.is_null() {
        RSA_free(rsa);
    }
    return ret;
}
unsafe extern "C" fn pkey_rsa_ctrl_str(
    mut ctx: *mut EVP_PKEY_CTX,
    mut type_0: *const libc::c_char,
    mut value: *const libc::c_char,
) -> libc::c_int {
    if value.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            144 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_rsa.c\0"
                as *const u8 as *const libc::c_char,
            711 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if strcmp(type_0, b"rsa_padding_mode\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        let mut pm: libc::c_int = 0;
        if strcmp(value, b"pkcs1\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            pm = 1 as libc::c_int;
        } else if strcmp(value, b"none\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            pm = 3 as libc::c_int;
        } else if strcmp(value, b"oeap\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            pm = 4 as libc::c_int;
        } else if strcmp(value, b"oaep\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            pm = 4 as libc::c_int;
        } else if strcmp(value, b"pss\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            pm = 6 as libc::c_int;
        } else {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                143 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_rsa.c\0"
                    as *const u8 as *const libc::c_char,
                730 as libc::c_int as libc::c_uint,
            );
            return -(2 as libc::c_int);
        }
        return EVP_PKEY_CTX_set_rsa_padding(ctx, pm);
    }
    if strcmp(type_0, b"rsa_pss_saltlen\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        let mut saltlen: libc::c_long = 0;
        if strcmp(value, b"digest\0" as *const u8 as *const libc::c_char) == 0 {
            saltlen = -(1 as libc::c_int) as libc::c_long;
        } else {
            let mut str_end: *mut libc::c_char = 0 as *mut libc::c_char;
            saltlen = strtol(value, &mut str_end, 10 as libc::c_int);
            if str_end == value as *mut libc::c_char
                || saltlen < 0 as libc::c_int as libc::c_long
                || saltlen > 2147483647 as libc::c_int as libc::c_long
            {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    124 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_rsa.c\0"
                        as *const u8 as *const libc::c_char,
                    746 as libc::c_int as libc::c_uint,
                );
                return -(2 as libc::c_int);
            }
        }
        return EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, saltlen as libc::c_int);
    }
    if strcmp(type_0, b"rsa_keygen_bits\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        let mut str_end_0: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut nbits: libc::c_long = strtol(value, &mut str_end_0, 10 as libc::c_int);
        if str_end_0 == value as *mut libc::c_char
            || nbits <= 0 as libc::c_int as libc::c_long
            || nbits > 2147483647 as libc::c_int as libc::c_long
        {
            ERR_put_error(
                6 as libc::c_int,
                0 as libc::c_int,
                124 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_rsa.c\0"
                    as *const u8 as *const libc::c_char,
                757 as libc::c_int as libc::c_uint,
            );
            return -(2 as libc::c_int);
        }
        return EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, nbits as libc::c_int);
    }
    if strcmp(type_0, b"rsa_keygen_pubexp\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        let mut ret: libc::c_int = 0;
        let mut pubexp: *mut BIGNUM = 0 as *mut BIGNUM;
        if BN_asc2bn(&mut pubexp, value) == 0 {
            return -(2 as libc::c_int);
        }
        ret = EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, pubexp);
        if ret <= 0 as libc::c_int {
            BN_free(pubexp);
        }
        return ret;
    }
    if strcmp(type_0, b"rsa_mgf1_md\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        return EVP_PKEY_CTX_md(
            ctx,
            (1 as libc::c_int) << 3 as libc::c_int
                | (1 as libc::c_int) << 4 as libc::c_int
                | (1 as libc::c_int) << 5 as libc::c_int
                | ((1 as libc::c_int) << 6 as libc::c_int
                    | (1 as libc::c_int) << 7 as libc::c_int),
            0x1000 as libc::c_int + 9 as libc::c_int,
            value,
        );
    }
    if strcmp(type_0, b"rsa_oaep_md\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        return EVP_PKEY_CTX_md(
            ctx,
            (1 as libc::c_int) << 6 as libc::c_int
                | (1 as libc::c_int) << 7 as libc::c_int,
            0x1000 as libc::c_int + 7 as libc::c_int,
            value,
        );
    }
    if strcmp(type_0, b"rsa_oaep_label\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        let mut lablen: size_t = 0 as libc::c_int as size_t;
        let mut lab: *mut uint8_t = OPENSSL_hexstr2buf(value, &mut lablen);
        if lab.is_null() {
            return 0 as libc::c_int;
        }
        let mut ret_0: libc::c_int = EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, lab, lablen);
        if ret_0 <= 0 as libc::c_int {
            OPENSSL_free(lab as *mut libc::c_void);
        }
        return ret_0;
    }
    return -(2 as libc::c_int);
}
unsafe extern "C" fn EVP_PKEY_rsa_pkey_meth_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_PKEY_rsa_pkey_meth_once;
}
static mut EVP_PKEY_rsa_pkey_meth_once: CRYPTO_once_t = 0 as libc::c_int;
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_rsa_pkey_meth() -> *const EVP_PKEY_METHOD {
    CRYPTO_once(
        EVP_PKEY_rsa_pkey_meth_once_bss_get(),
        Some(EVP_PKEY_rsa_pkey_meth_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_PKEY_rsa_pkey_meth_storage_bss_get() as *const EVP_PKEY_METHOD;
}
unsafe extern "C" fn EVP_PKEY_rsa_pkey_meth_storage_bss_get() -> *mut EVP_PKEY_METHOD {
    return &mut EVP_PKEY_rsa_pkey_meth_storage;
}
unsafe extern "C" fn EVP_PKEY_rsa_pkey_meth_do_init(mut out: *mut EVP_PKEY_METHOD) {
    (*out).pkey_id = 6 as libc::c_int;
    (*out)
        .init = Some(
        pkey_rsa_init as unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> libc::c_int,
    );
    (*out)
        .copy = Some(
        pkey_rsa_copy
            as unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY_CTX) -> libc::c_int,
    );
    (*out)
        .cleanup = Some(
        pkey_rsa_cleanup as unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> (),
    );
    (*out)
        .keygen = Some(
        pkey_rsa_keygen
            as unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY) -> libc::c_int,
    );
    (*out).sign_init = None;
    (*out)
        .sign = Some(
        pkey_rsa_sign
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out).sign_message = None;
    (*out).verify_init = None;
    (*out)
        .verify = Some(
        pkey_rsa_verify
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *const uint8_t,
                size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out).verify_message = None;
    (*out)
        .verify_recover = Some(
        pkey_rsa_verify_recover
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .encrypt = Some(
        pkey_rsa_encrypt
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out)
        .decrypt = Some(
        pkey_rsa_decrypt
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out).derive = None;
    (*out).paramgen = None;
    (*out)
        .ctrl = Some(
        pkey_rsa_ctrl
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                libc::c_int,
                libc::c_int,
                *mut libc::c_void,
            ) -> libc::c_int,
    );
    (*out)
        .ctrl_str = Some(
        pkey_rsa_ctrl_str
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *const libc::c_char,
                *const libc::c_char,
            ) -> libc::c_int,
    );
}
unsafe extern "C" fn EVP_PKEY_rsa_pkey_meth_init() {
    EVP_PKEY_rsa_pkey_meth_do_init(EVP_PKEY_rsa_pkey_meth_storage_bss_get());
}
static mut EVP_PKEY_rsa_pkey_meth_storage: EVP_PKEY_METHOD = evp_pkey_method_st {
    pkey_id: 0,
    init: None,
    copy: None,
    cleanup: None,
    keygen: None,
    sign_init: None,
    sign: None,
    sign_message: None,
    verify_init: None,
    verify: None,
    verify_message: None,
    verify_recover: None,
    encrypt: None,
    decrypt: None,
    derive: None,
    paramgen: None,
    ctrl: None,
    ctrl_str: None,
    keygen_deterministic: None,
    encapsulate_deterministic: None,
    encapsulate: None,
    decapsulate: None,
};
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_rsa_pss_pkey_meth() -> *const EVP_PKEY_METHOD {
    CRYPTO_once(
        EVP_PKEY_rsa_pss_pkey_meth_once_bss_get(),
        Some(EVP_PKEY_rsa_pss_pkey_meth_init as unsafe extern "C" fn() -> ()),
    );
    return EVP_PKEY_rsa_pss_pkey_meth_storage_bss_get() as *const EVP_PKEY_METHOD;
}
static mut EVP_PKEY_rsa_pss_pkey_meth_storage: EVP_PKEY_METHOD = evp_pkey_method_st {
    pkey_id: 0,
    init: None,
    copy: None,
    cleanup: None,
    keygen: None,
    sign_init: None,
    sign: None,
    sign_message: None,
    verify_init: None,
    verify: None,
    verify_message: None,
    verify_recover: None,
    encrypt: None,
    decrypt: None,
    derive: None,
    paramgen: None,
    ctrl: None,
    ctrl_str: None,
    keygen_deterministic: None,
    encapsulate_deterministic: None,
    encapsulate: None,
    decapsulate: None,
};
unsafe extern "C" fn EVP_PKEY_rsa_pss_pkey_meth_init() {
    EVP_PKEY_rsa_pss_pkey_meth_do_init(EVP_PKEY_rsa_pss_pkey_meth_storage_bss_get());
}
unsafe extern "C" fn EVP_PKEY_rsa_pss_pkey_meth_do_init(mut out: *mut EVP_PKEY_METHOD) {
    (*out).pkey_id = 912 as libc::c_int;
    (*out)
        .init = Some(
        pkey_rsa_init as unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> libc::c_int,
    );
    (*out)
        .copy = Some(
        pkey_rsa_copy
            as unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY_CTX) -> libc::c_int,
    );
    (*out)
        .cleanup = Some(
        pkey_rsa_cleanup as unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> (),
    );
    (*out)
        .keygen = Some(
        pkey_rsa_keygen
            as unsafe extern "C" fn(*mut EVP_PKEY_CTX, *mut EVP_PKEY) -> libc::c_int,
    );
    (*out)
        .sign_init = Some(
        pkey_pss_init_sign as unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> libc::c_int,
    );
    (*out)
        .sign = Some(
        pkey_rsa_sign
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *mut uint8_t,
                *mut size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out).sign_message = None;
    (*out)
        .verify_init = Some(
        pkey_pss_init_verify as unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> libc::c_int,
    );
    (*out)
        .verify = Some(
        pkey_rsa_verify
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *const uint8_t,
                size_t,
                *const uint8_t,
                size_t,
            ) -> libc::c_int,
    );
    (*out).verify_message = None;
    (*out).verify_recover = None;
    (*out).encrypt = None;
    (*out).decrypt = None;
    (*out).derive = None;
    (*out).paramgen = None;
    (*out)
        .ctrl = Some(
        pkey_rsa_ctrl
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                libc::c_int,
                libc::c_int,
                *mut libc::c_void,
            ) -> libc::c_int,
    );
    (*out)
        .ctrl_str = Some(
        pkey_rsa_ctrl_str
            as unsafe extern "C" fn(
                *mut EVP_PKEY_CTX,
                *const libc::c_char,
                *const libc::c_char,
            ) -> libc::c_int,
    );
}
unsafe extern "C" fn EVP_PKEY_rsa_pss_pkey_meth_storage_bss_get() -> *mut EVP_PKEY_METHOD {
    return &mut EVP_PKEY_rsa_pss_pkey_meth_storage;
}
unsafe extern "C" fn EVP_PKEY_rsa_pss_pkey_meth_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EVP_PKEY_rsa_pss_pkey_meth_once;
}
static mut EVP_PKEY_rsa_pss_pkey_meth_once: CRYPTO_once_t = 0 as libc::c_int;
#[no_mangle]
pub unsafe extern "C" fn EVP_RSA_PKEY_CTX_ctrl(
    mut ctx: *mut EVP_PKEY_CTX,
    mut optype: libc::c_int,
    mut cmd: libc::c_int,
    mut p1: libc::c_int,
    mut p2: *mut libc::c_void,
) -> libc::c_int {
    if !ctx.is_null() && !((*ctx).pmeth).is_null()
        && (*(*ctx).pmeth).pkey_id != 6 as libc::c_int
        && (*(*ctx).pmeth).pkey_id != 912 as libc::c_int
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_rsa.c\0"
                as *const u8 as *const libc::c_char,
            857 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return EVP_PKEY_CTX_ctrl(ctx, -(1 as libc::c_int), optype, cmd, p1, p2);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_padding(
    mut ctx: *mut EVP_PKEY_CTX,
    mut padding: libc::c_int,
) -> libc::c_int {
    return EVP_RSA_PKEY_CTX_ctrl(
        ctx,
        -(1 as libc::c_int),
        0x1000 as libc::c_int + 1 as libc::c_int,
        padding,
        0 as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_rsa_padding(
    mut ctx: *mut EVP_PKEY_CTX,
    mut out_padding: *mut libc::c_int,
) -> libc::c_int {
    return EVP_RSA_PKEY_CTX_ctrl(
        ctx,
        -(1 as libc::c_int),
        0x1000 as libc::c_int + 2 as libc::c_int,
        0 as libc::c_int,
        out_padding as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_pss_keygen_md(
    mut ctx: *mut EVP_PKEY_CTX,
    mut md: *const EVP_MD,
) -> libc::c_int {
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(
    mut ctx: *mut EVP_PKEY_CTX,
    mut salt_len: libc::c_int,
) -> libc::c_int {
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(
    mut ctx: *mut EVP_PKEY_CTX,
    mut md: *const EVP_MD,
) -> libc::c_int {
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_pss_saltlen(
    mut ctx: *mut EVP_PKEY_CTX,
    mut salt_len: libc::c_int,
) -> libc::c_int {
    return EVP_RSA_PKEY_CTX_ctrl(
        ctx,
        (1 as libc::c_int) << 3 as libc::c_int | (1 as libc::c_int) << 4 as libc::c_int,
        0x1000 as libc::c_int + 3 as libc::c_int,
        salt_len,
        0 as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_rsa_pss_saltlen(
    mut ctx: *mut EVP_PKEY_CTX,
    mut out_salt_len: *mut libc::c_int,
) -> libc::c_int {
    return EVP_RSA_PKEY_CTX_ctrl(
        ctx,
        (1 as libc::c_int) << 3 as libc::c_int | (1 as libc::c_int) << 4 as libc::c_int,
        0x1000 as libc::c_int + 4 as libc::c_int,
        0 as libc::c_int,
        out_salt_len as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_keygen_bits(
    mut ctx: *mut EVP_PKEY_CTX,
    mut bits: libc::c_int,
) -> libc::c_int {
    return EVP_RSA_PKEY_CTX_ctrl(
        ctx,
        (1 as libc::c_int) << 2 as libc::c_int,
        0x1000 as libc::c_int + 5 as libc::c_int,
        bits,
        0 as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_keygen_pubexp(
    mut ctx: *mut EVP_PKEY_CTX,
    mut e: *mut BIGNUM,
) -> libc::c_int {
    return EVP_RSA_PKEY_CTX_ctrl(
        ctx,
        (1 as libc::c_int) << 2 as libc::c_int,
        0x1000 as libc::c_int + 6 as libc::c_int,
        0 as libc::c_int,
        e as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_oaep_md(
    mut ctx: *mut EVP_PKEY_CTX,
    mut md: *const EVP_MD,
) -> libc::c_int {
    return EVP_PKEY_CTX_ctrl(
        ctx,
        6 as libc::c_int,
        (1 as libc::c_int) << 6 as libc::c_int | (1 as libc::c_int) << 7 as libc::c_int,
        0x1000 as libc::c_int + 7 as libc::c_int,
        0 as libc::c_int,
        md as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_rsa_oaep_md(
    mut ctx: *mut EVP_PKEY_CTX,
    mut out_md: *mut *const EVP_MD,
) -> libc::c_int {
    return EVP_PKEY_CTX_ctrl(
        ctx,
        6 as libc::c_int,
        (1 as libc::c_int) << 6 as libc::c_int | (1 as libc::c_int) << 7 as libc::c_int,
        0x1000 as libc::c_int + 8 as libc::c_int,
        0 as libc::c_int,
        out_md as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_mgf1_md(
    mut ctx: *mut EVP_PKEY_CTX,
    mut md: *const EVP_MD,
) -> libc::c_int {
    return EVP_RSA_PKEY_CTX_ctrl(
        ctx,
        (1 as libc::c_int) << 3 as libc::c_int | (1 as libc::c_int) << 4 as libc::c_int
            | (1 as libc::c_int) << 5 as libc::c_int
            | ((1 as libc::c_int) << 6 as libc::c_int
                | (1 as libc::c_int) << 7 as libc::c_int),
        0x1000 as libc::c_int + 9 as libc::c_int,
        0 as libc::c_int,
        md as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get_rsa_mgf1_md(
    mut ctx: *mut EVP_PKEY_CTX,
    mut out_md: *mut *const EVP_MD,
) -> libc::c_int {
    return EVP_RSA_PKEY_CTX_ctrl(
        ctx,
        (1 as libc::c_int) << 3 as libc::c_int | (1 as libc::c_int) << 4 as libc::c_int
            | (1 as libc::c_int) << 5 as libc::c_int
            | ((1 as libc::c_int) << 6 as libc::c_int
                | (1 as libc::c_int) << 7 as libc::c_int),
        0x1000 as libc::c_int + 10 as libc::c_int,
        0 as libc::c_int,
        out_md as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_set0_rsa_oaep_label(
    mut ctx: *mut EVP_PKEY_CTX,
    mut label: *mut uint8_t,
    mut label_len: size_t,
) -> libc::c_int {
    let mut params: RSA_OAEP_LABEL_PARAMS = {
        let mut init = RSA_OAEP_LABEL_PARAMS {
            data: label,
            len: label_len,
        };
        init
    };
    return EVP_PKEY_CTX_ctrl(
        ctx,
        6 as libc::c_int,
        (1 as libc::c_int) << 6 as libc::c_int | (1 as libc::c_int) << 7 as libc::c_int,
        0x1000 as libc::c_int + 11 as libc::c_int,
        0 as libc::c_int,
        &mut params as *mut RSA_OAEP_LABEL_PARAMS as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_CTX_get0_rsa_oaep_label(
    mut ctx: *mut EVP_PKEY_CTX,
    mut out_label: *mut *const uint8_t,
) -> libc::c_int {
    let mut label: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if EVP_PKEY_CTX_ctrl(
        ctx,
        6 as libc::c_int,
        (1 as libc::c_int) << 6 as libc::c_int | (1 as libc::c_int) << 7 as libc::c_int,
        0x1000 as libc::c_int + 12 as libc::c_int,
        0 as libc::c_int,
        &mut label as *mut CBS as *mut libc::c_void,
    ) == 0
    {
        return -(1 as libc::c_int);
    }
    if CBS_len(&mut label) > 2147483647 as libc::c_int as size_t {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/evp/p_rsa.c\0"
                as *const u8 as *const libc::c_char,
            943 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    *out_label = CBS_data(&mut label);
    return CBS_len(&mut label) as libc::c_int;
}
