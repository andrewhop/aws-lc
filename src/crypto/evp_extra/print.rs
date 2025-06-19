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
    pub type asn1_pctx_st;
    pub type bignum_ctx;
    pub type stack_st_void;
    pub type dh_st;
    pub type dsa_st;
    pub type ec_group_st;
    pub type ec_key_st;
    pub type ec_point_st;
    pub type kem_key_st;
    pub type bn_blinding_st;
    pub type rsassa_pss_params_st;
    fn DSA_get0_pub_key(dsa: *const DSA) -> *const BIGNUM;
    fn DSA_get0_priv_key(dsa: *const DSA) -> *const BIGNUM;
    fn DSA_get0_p(dsa: *const DSA) -> *const BIGNUM;
    fn DSA_get0_q(dsa: *const DSA) -> *const BIGNUM;
    fn DSA_get0_g(dsa: *const DSA) -> *const BIGNUM;
    fn BN_num_bits(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_num_bytes(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_is_negative(bn: *const BIGNUM) -> libc::c_int;
    fn BN_bn2bin(in_0: *const BIGNUM, out: *mut uint8_t) -> size_t;
    fn BN_get_u64(bn: *const BIGNUM, out: *mut uint64_t) -> libc::c_int;
    fn BN_is_zero(bn: *const BIGNUM) -> libc::c_int;
    fn BIO_write(
        bio: *mut BIO,
        data: *const libc::c_void,
        len: libc::c_int,
    ) -> libc::c_int;
    fn BIO_puts(bio: *mut BIO, buf: *const libc::c_char) -> libc::c_int;
    fn BIO_printf(bio: *mut BIO, format: *const libc::c_char, _: ...) -> libc::c_int;
    fn BIO_indent(
        bio: *mut BIO,
        indent: libc::c_uint,
        max_indent: libc::c_uint,
    ) -> libc::c_int;
    fn EVP_PKEY_id(pkey: *const EVP_PKEY) -> libc::c_int;
    fn EVP_PKEY_get0_RSA(pkey: *const EVP_PKEY) -> *mut RSA;
    fn EVP_PKEY_get0_DSA(pkey: *const EVP_PKEY) -> *mut DSA;
    fn EVP_PKEY_get0_EC_KEY(pkey: *const EVP_PKEY) -> *mut EC_KEY;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn EC_GROUP_get_curve_name(group: *const EC_GROUP) -> libc::c_int;
    fn EC_curve_nid2nist(nid: libc::c_int) -> *const libc::c_char;
    fn EC_KEY_get0_group(key: *const EC_KEY) -> *const EC_GROUP;
    fn EC_KEY_get0_private_key(key: *const EC_KEY) -> *const BIGNUM;
    fn EC_KEY_get0_public_key(key: *const EC_KEY) -> *const EC_POINT;
    fn EC_KEY_get_conv_form(key: *const EC_KEY) -> point_conversion_form_t;
    fn EC_KEY_key2buf(
        key: *const EC_KEY,
        form: point_conversion_form_t,
        out_buf: *mut *mut libc::c_uchar,
        ctx: *mut BN_CTX,
    ) -> size_t;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type ASN1_PCTX = asn1_pctx_st;
pub type BIGNUM = bignum_st;
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
pub type BN_CTX = bignum_ctx;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bio_method_st {
    pub type_0: libc::c_int,
    pub name: *const libc::c_char,
    pub bwrite: Option::<
        unsafe extern "C" fn(*mut BIO, *const libc::c_char, libc::c_int) -> libc::c_int,
    >,
    pub bread: Option::<
        unsafe extern "C" fn(*mut BIO, *mut libc::c_char, libc::c_int) -> libc::c_int,
    >,
    pub bputs: Option::<
        unsafe extern "C" fn(*mut BIO, *const libc::c_char) -> libc::c_int,
    >,
    pub bgets: Option::<
        unsafe extern "C" fn(*mut BIO, *mut libc::c_char, libc::c_int) -> libc::c_int,
    >,
    pub ctrl: Option::<
        unsafe extern "C" fn(
            *mut BIO,
            libc::c_int,
            libc::c_long,
            *mut libc::c_void,
        ) -> libc::c_long,
    >,
    pub create: Option::<unsafe extern "C" fn(*mut BIO) -> libc::c_int>,
    pub destroy: Option::<unsafe extern "C" fn(*mut BIO) -> libc::c_int>,
    pub callback_ctrl: Option::<
        unsafe extern "C" fn(*mut BIO, libc::c_int, bio_info_cb) -> libc::c_long,
    >,
}
pub type bio_info_cb = Option::<
    unsafe extern "C" fn(*mut BIO, libc::c_int, libc::c_int) -> libc::c_long,
>;
pub type BIO = bio_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bio_st {
    pub method: *const BIO_METHOD,
    pub ex_data: CRYPTO_EX_DATA,
    pub callback_ex: BIO_callback_fn_ex,
    pub callback: BIO_callback_fn,
    pub cb_arg: *mut libc::c_char,
    pub init: libc::c_int,
    pub shutdown: libc::c_int,
    pub flags: libc::c_int,
    pub retry_reason: libc::c_int,
    pub num: libc::c_int,
    pub references: CRYPTO_refcount_t,
    pub ptr: *mut libc::c_void,
    pub next_bio: *mut BIO,
    pub num_read: uint64_t,
    pub num_write: uint64_t,
}
pub type CRYPTO_refcount_t = uint32_t;
pub type BIO_callback_fn = Option::<
    unsafe extern "C" fn(
        *mut BIO,
        libc::c_int,
        *const libc::c_char,
        libc::c_int,
        libc::c_long,
        libc::c_long,
    ) -> libc::c_long,
>;
pub type BIO_callback_fn_ex = Option::<
    unsafe extern "C" fn(
        *mut BIO,
        libc::c_int,
        *const libc::c_char,
        size_t,
        libc::c_int,
        libc::c_long,
        libc::c_int,
        *mut size_t,
    ) -> libc::c_long,
>;
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
pub type BIO_METHOD = bio_method_st;
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
pub type EC_GROUP = ec_group_st;
pub type EC_KEY = ec_key_st;
pub type EC_POINT = ec_point_st;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EVP_PKEY_PRINT_METHOD {
    pub type_0: libc::c_int,
    pub pub_print: Option::<
        unsafe extern "C" fn(*mut BIO, *const EVP_PKEY, libc::c_int) -> libc::c_int,
    >,
    pub priv_print: Option::<
        unsafe extern "C" fn(*mut BIO, *const EVP_PKEY, libc::c_int) -> libc::c_int,
    >,
    pub param_print: Option::<
        unsafe extern "C" fn(*mut BIO, *const EVP_PKEY, libc::c_int) -> libc::c_int,
    >,
}
pub type point_conversion_form_t = libc::c_uint;
pub const POINT_CONVERSION_HYBRID: point_conversion_form_t = 6;
pub const POINT_CONVERSION_UNCOMPRESSED: point_conversion_form_t = 4;
pub const POINT_CONVERSION_COMPRESSED: point_conversion_form_t = 2;
unsafe extern "C" fn print_hex(
    mut bp: *mut BIO,
    mut data: *const uint8_t,
    mut len: size_t,
    mut off: libc::c_int,
) -> libc::c_int {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < len {
        if i % 15 as libc::c_int as size_t == 0 as libc::c_int as size_t {
            if BIO_puts(bp, b"\n\0" as *const u8 as *const libc::c_char)
                <= 0 as libc::c_int
                || BIO_indent(
                    bp,
                    (off + 4 as libc::c_int) as libc::c_uint,
                    128 as libc::c_int as libc::c_uint,
                ) == 0
            {
                return 0 as libc::c_int;
            }
        }
        if BIO_printf(
            bp,
            b"%02x%s\0" as *const u8 as *const libc::c_char,
            *data.offset(i as isize) as libc::c_int,
            (if i.wrapping_add(1 as libc::c_int as size_t) == len {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                b":\0" as *const u8 as *const libc::c_char
            }),
        ) <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    if BIO_write(
        bp,
        b"\n\0" as *const u8 as *const libc::c_char as *const libc::c_void,
        1 as libc::c_int,
    ) <= 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn bn_print(
    mut bp: *mut BIO,
    mut name: *const libc::c_char,
    mut num: *const BIGNUM,
    mut off: libc::c_int,
) -> libc::c_int {
    if num.is_null() {
        return 1 as libc::c_int;
    }
    if BIO_indent(bp, off as libc::c_uint, 128 as libc::c_int as libc::c_uint) == 0 {
        return 0 as libc::c_int;
    }
    if BN_is_zero(num) != 0 {
        if BIO_printf(bp, b"%s 0\n\0" as *const u8 as *const libc::c_char, name)
            <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        return 1 as libc::c_int;
    }
    let mut u64: uint64_t = 0;
    if BN_get_u64(num, &mut u64) != 0 {
        let mut neg: *const libc::c_char = if BN_is_negative(num) != 0 {
            b"-\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        };
        return (BIO_printf(
            bp,
            b"%s %s%lu (%s0x%lx)\n\0" as *const u8 as *const libc::c_char,
            name,
            neg,
            u64,
            neg,
            u64,
        ) > 0 as libc::c_int) as libc::c_int;
    }
    if BIO_printf(
        bp,
        b"%s%s\0" as *const u8 as *const libc::c_char,
        name,
        (if BN_is_negative(num) != 0 {
            b" (Negative)\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        }),
    ) <= 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    let mut len: size_t = BN_num_bytes(num) as size_t;
    let mut buf: *mut uint8_t = OPENSSL_zalloc(
        len.wrapping_add(1 as libc::c_int as size_t),
    ) as *mut uint8_t;
    if buf.is_null() {
        return 0 as libc::c_int;
    }
    BN_bn2bin(num, buf.offset(1 as libc::c_int as isize));
    let mut ret: libc::c_int = 0;
    if len > 0 as libc::c_int as size_t
        && *buf.offset(1 as libc::c_int as isize) as libc::c_int & 0x80 as libc::c_int
            != 0 as libc::c_int
    {
        ret = print_hex(bp, buf, len.wrapping_add(1 as libc::c_int as size_t), off);
    } else {
        ret = print_hex(bp, buf.offset(1 as libc::c_int as isize), len, off);
    }
    OPENSSL_free(buf as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn do_rsa_print(
    mut out: *mut BIO,
    mut rsa: *const RSA,
    mut off: libc::c_int,
    mut include_private: libc::c_int,
) -> libc::c_int {
    let mut mod_len: libc::c_int = 0 as libc::c_int;
    if !((*rsa).n).is_null() {
        mod_len = BN_num_bits((*rsa).n) as libc::c_int;
    }
    if BIO_indent(out, off as libc::c_uint, 128 as libc::c_int as libc::c_uint) == 0 {
        return 0 as libc::c_int;
    }
    let mut s: *const libc::c_char = 0 as *const libc::c_char;
    let mut str: *const libc::c_char = 0 as *const libc::c_char;
    if include_private != 0 && !((*rsa).d).is_null() {
        if BIO_printf(
            out,
            b"Private-Key: (%d bit)\n\0" as *const u8 as *const libc::c_char,
            mod_len,
        ) <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        str = b"modulus:\0" as *const u8 as *const libc::c_char;
        s = b"publicExponent:\0" as *const u8 as *const libc::c_char;
    } else {
        if BIO_printf(
            out,
            b"Public-Key: (%d bit)\n\0" as *const u8 as *const libc::c_char,
            mod_len,
        ) <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        str = b"Modulus:\0" as *const u8 as *const libc::c_char;
        s = b"Exponent:\0" as *const u8 as *const libc::c_char;
    }
    if bn_print(out, str, (*rsa).n, off) == 0 || bn_print(out, s, (*rsa).e, off) == 0 {
        return 0 as libc::c_int;
    }
    if include_private != 0 {
        if bn_print(
            out,
            b"privateExponent:\0" as *const u8 as *const libc::c_char,
            (*rsa).d,
            off,
        ) == 0
            || bn_print(
                out,
                b"prime1:\0" as *const u8 as *const libc::c_char,
                (*rsa).p,
                off,
            ) == 0
            || bn_print(
                out,
                b"prime2:\0" as *const u8 as *const libc::c_char,
                (*rsa).q,
                off,
            ) == 0
            || bn_print(
                out,
                b"exponent1:\0" as *const u8 as *const libc::c_char,
                (*rsa).dmp1,
                off,
            ) == 0
            || bn_print(
                out,
                b"exponent2:\0" as *const u8 as *const libc::c_char,
                (*rsa).dmq1,
                off,
            ) == 0
            || bn_print(
                out,
                b"coefficient:\0" as *const u8 as *const libc::c_char,
                (*rsa).iqmp,
                off,
            ) == 0
        {
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn rsa_pub_print(
    mut bp: *mut BIO,
    mut pkey: *const EVP_PKEY,
    mut indent: libc::c_int,
) -> libc::c_int {
    return do_rsa_print(bp, EVP_PKEY_get0_RSA(pkey), indent, 0 as libc::c_int);
}
unsafe extern "C" fn rsa_priv_print(
    mut bp: *mut BIO,
    mut pkey: *const EVP_PKEY,
    mut indent: libc::c_int,
) -> libc::c_int {
    return do_rsa_print(bp, EVP_PKEY_get0_RSA(pkey), indent, 1 as libc::c_int);
}
unsafe extern "C" fn do_dsa_print(
    mut bp: *mut BIO,
    mut x: *const DSA,
    mut off: libc::c_int,
    mut ptype: libc::c_int,
) -> libc::c_int {
    let mut priv_key: *const BIGNUM = 0 as *const BIGNUM;
    if ptype == 2 as libc::c_int {
        priv_key = DSA_get0_priv_key(x);
    }
    let mut pub_key: *const BIGNUM = 0 as *const BIGNUM;
    if ptype > 0 as libc::c_int {
        pub_key = DSA_get0_pub_key(x);
    }
    let mut ktype: *const libc::c_char = b"DSA-Parameters\0" as *const u8
        as *const libc::c_char;
    if ptype == 2 as libc::c_int {
        ktype = b"Private-Key\0" as *const u8 as *const libc::c_char;
    } else if ptype == 1 as libc::c_int {
        ktype = b"Public-Key\0" as *const u8 as *const libc::c_char;
    }
    if BIO_indent(bp, off as libc::c_uint, 128 as libc::c_int as libc::c_uint) == 0
        || BIO_printf(
            bp,
            b"%s: (%u bit)\n\0" as *const u8 as *const libc::c_char,
            ktype,
            BN_num_bits(DSA_get0_p(x)),
        ) <= 0 as libc::c_int
        || bn_print(bp, b"priv:\0" as *const u8 as *const libc::c_char, priv_key, off)
            == 0
        || bn_print(bp, b"pub:\0" as *const u8 as *const libc::c_char, pub_key, off) == 0
        || bn_print(bp, b"P:\0" as *const u8 as *const libc::c_char, DSA_get0_p(x), off)
            == 0
        || bn_print(bp, b"Q:\0" as *const u8 as *const libc::c_char, DSA_get0_q(x), off)
            == 0
        || bn_print(bp, b"G:\0" as *const u8 as *const libc::c_char, DSA_get0_g(x), off)
            == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn dsa_param_print(
    mut bp: *mut BIO,
    mut pkey: *const EVP_PKEY,
    mut indent: libc::c_int,
) -> libc::c_int {
    return do_dsa_print(bp, EVP_PKEY_get0_DSA(pkey), indent, 0 as libc::c_int);
}
unsafe extern "C" fn dsa_pub_print(
    mut bp: *mut BIO,
    mut pkey: *const EVP_PKEY,
    mut indent: libc::c_int,
) -> libc::c_int {
    return do_dsa_print(bp, EVP_PKEY_get0_DSA(pkey), indent, 1 as libc::c_int);
}
unsafe extern "C" fn dsa_priv_print(
    mut bp: *mut BIO,
    mut pkey: *const EVP_PKEY,
    mut indent: libc::c_int,
) -> libc::c_int {
    return do_dsa_print(bp, EVP_PKEY_get0_DSA(pkey), indent, 2 as libc::c_int);
}
unsafe extern "C" fn do_EC_KEY_print(
    mut bp: *mut BIO,
    mut x: *const EC_KEY,
    mut off: libc::c_int,
    mut ktype: libc::c_int,
) -> libc::c_int {
    let mut group: *const EC_GROUP = 0 as *const EC_GROUP;
    if x.is_null()
        || {
            group = EC_KEY_get0_group(x);
            group.is_null()
        }
    {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/print.c\0" as *const u8
                as *const libc::c_char,
            248 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ecstr: *const libc::c_char = 0 as *const libc::c_char;
    if ktype == 2 as libc::c_int {
        ecstr = b"Private-Key\0" as *const u8 as *const libc::c_char;
    } else if ktype == 1 as libc::c_int {
        ecstr = b"Public-Key\0" as *const u8 as *const libc::c_char;
    } else {
        ecstr = b"ECDSA-Parameters\0" as *const u8 as *const libc::c_char;
    }
    if BIO_indent(bp, off as libc::c_uint, 128 as libc::c_int as libc::c_uint) == 0 {
        return 0 as libc::c_int;
    }
    let mut curve_name: libc::c_int = EC_GROUP_get_curve_name(group);
    if BIO_printf(
        bp,
        b"%s: (%s)\n\0" as *const u8 as *const libc::c_char,
        ecstr,
        (if curve_name == 0 as libc::c_int {
            b"unknown curve\0" as *const u8 as *const libc::c_char
        } else {
            EC_curve_nid2nist(curve_name)
        }),
    ) <= 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    if ktype == 2 as libc::c_int {
        let mut priv_key: *const BIGNUM = EC_KEY_get0_private_key(x);
        if !priv_key.is_null()
            && bn_print(
                bp,
                b"priv:\0" as *const u8 as *const libc::c_char,
                priv_key,
                off,
            ) == 0
        {
            return 0 as libc::c_int;
        }
    }
    if ktype > 0 as libc::c_int && !(EC_KEY_get0_public_key(x)).is_null() {
        let mut pub_0: *mut uint8_t = 0 as *mut uint8_t;
        let mut pub_len: size_t = EC_KEY_key2buf(
            x,
            EC_KEY_get_conv_form(x),
            &mut pub_0,
            0 as *mut BN_CTX,
        );
        if pub_len == 0 as libc::c_int as size_t {
            return 0 as libc::c_int;
        }
        let mut ret: libc::c_int = (BIO_indent(
            bp,
            off as libc::c_uint,
            128 as libc::c_int as libc::c_uint,
        ) != 0
            && BIO_puts(bp, b"pub:\0" as *const u8 as *const libc::c_char)
                > 0 as libc::c_int && print_hex(bp, pub_0, pub_len, off) != 0)
            as libc::c_int;
        OPENSSL_free(pub_0 as *mut libc::c_void);
        if ret == 0 {
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn eckey_param_print(
    mut bp: *mut BIO,
    mut pkey: *const EVP_PKEY,
    mut indent: libc::c_int,
) -> libc::c_int {
    return do_EC_KEY_print(bp, EVP_PKEY_get0_EC_KEY(pkey), indent, 0 as libc::c_int);
}
unsafe extern "C" fn eckey_pub_print(
    mut bp: *mut BIO,
    mut pkey: *const EVP_PKEY,
    mut indent: libc::c_int,
) -> libc::c_int {
    return do_EC_KEY_print(bp, EVP_PKEY_get0_EC_KEY(pkey), indent, 1 as libc::c_int);
}
unsafe extern "C" fn eckey_priv_print(
    mut bp: *mut BIO,
    mut pkey: *const EVP_PKEY,
    mut indent: libc::c_int,
) -> libc::c_int {
    return do_EC_KEY_print(bp, EVP_PKEY_get0_EC_KEY(pkey), indent, 2 as libc::c_int);
}
unsafe extern "C" fn do_mldsa_65_print(
    mut bp: *mut BIO,
    mut pkey: *const EVP_PKEY,
    mut off: libc::c_int,
    mut ptype: libc::c_int,
) -> libc::c_int {
    if pkey.is_null() {
        ERR_put_error(
            6 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/evp_extra/print.c\0" as *const u8
                as *const libc::c_char,
            315 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if BIO_indent(bp, off as libc::c_uint, 128 as libc::c_int as libc::c_uint) == 0 {
        return 0 as libc::c_int;
    }
    let mut pqdsa: *const PQDSA = (*(*pkey).pkey.pqdsa_key).pqdsa;
    let mut bit_len: libc::c_int = 0 as libc::c_int;
    if ptype == 2 as libc::c_int {
        bit_len = (*pqdsa).private_key_len as libc::c_int;
        if BIO_printf(
            bp,
            b"Private-Key: (%d bit)\n\0" as *const u8 as *const libc::c_char,
            bit_len,
        ) <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        print_hex(bp, (*(*pkey).pkey.pqdsa_key).private_key, bit_len as size_t, off);
    } else {
        bit_len = (*pqdsa).public_key_len as libc::c_int;
        if BIO_printf(
            bp,
            b"Public-Key: (%d bit)\n\0" as *const u8 as *const libc::c_char,
            bit_len,
        ) <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        let mut ret: libc::c_int = print_hex(
            bp,
            (*(*pkey).pkey.pqdsa_key).public_key,
            bit_len as size_t,
            off,
        );
        if ret == 0 {
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn mldsa_65_pub_print(
    mut bp: *mut BIO,
    mut pkey: *const EVP_PKEY,
    mut indent: libc::c_int,
) -> libc::c_int {
    return do_mldsa_65_print(bp, pkey, indent, 1 as libc::c_int);
}
unsafe extern "C" fn mldsa_65_priv_print(
    mut bp: *mut BIO,
    mut pkey: *const EVP_PKEY,
    mut indent: libc::c_int,
) -> libc::c_int {
    return do_mldsa_65_print(bp, pkey, indent, 2 as libc::c_int);
}
static mut kPrintMethods: [EVP_PKEY_PRINT_METHOD; 4] = unsafe {
    [
        {
            let mut init = EVP_PKEY_PRINT_METHOD {
                type_0: 6 as libc::c_int,
                pub_print: Some(
                    rsa_pub_print
                        as unsafe extern "C" fn(
                            *mut BIO,
                            *const EVP_PKEY,
                            libc::c_int,
                        ) -> libc::c_int,
                ),
                priv_print: Some(
                    rsa_priv_print
                        as unsafe extern "C" fn(
                            *mut BIO,
                            *const EVP_PKEY,
                            libc::c_int,
                        ) -> libc::c_int,
                ),
                param_print: None,
            };
            init
        },
        {
            let mut init = EVP_PKEY_PRINT_METHOD {
                type_0: 116 as libc::c_int,
                pub_print: Some(
                    dsa_pub_print
                        as unsafe extern "C" fn(
                            *mut BIO,
                            *const EVP_PKEY,
                            libc::c_int,
                        ) -> libc::c_int,
                ),
                priv_print: Some(
                    dsa_priv_print
                        as unsafe extern "C" fn(
                            *mut BIO,
                            *const EVP_PKEY,
                            libc::c_int,
                        ) -> libc::c_int,
                ),
                param_print: Some(
                    dsa_param_print
                        as unsafe extern "C" fn(
                            *mut BIO,
                            *const EVP_PKEY,
                            libc::c_int,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = EVP_PKEY_PRINT_METHOD {
                type_0: 408 as libc::c_int,
                pub_print: Some(
                    eckey_pub_print
                        as unsafe extern "C" fn(
                            *mut BIO,
                            *const EVP_PKEY,
                            libc::c_int,
                        ) -> libc::c_int,
                ),
                priv_print: Some(
                    eckey_priv_print
                        as unsafe extern "C" fn(
                            *mut BIO,
                            *const EVP_PKEY,
                            libc::c_int,
                        ) -> libc::c_int,
                ),
                param_print: Some(
                    eckey_param_print
                        as unsafe extern "C" fn(
                            *mut BIO,
                            *const EVP_PKEY,
                            libc::c_int,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = EVP_PKEY_PRINT_METHOD {
                type_0: 993 as libc::c_int,
                pub_print: Some(
                    mldsa_65_pub_print
                        as unsafe extern "C" fn(
                            *mut BIO,
                            *const EVP_PKEY,
                            libc::c_int,
                        ) -> libc::c_int,
                ),
                priv_print: Some(
                    mldsa_65_priv_print
                        as unsafe extern "C" fn(
                            *mut BIO,
                            *const EVP_PKEY,
                            libc::c_int,
                        ) -> libc::c_int,
                ),
                param_print: None,
            };
            init
        },
    ]
};
static mut kPrintMethodsLen: size_t = 0;
unsafe extern "C" fn find_method(mut type_0: libc::c_int) -> *mut EVP_PKEY_PRINT_METHOD {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < kPrintMethodsLen {
        if kPrintMethods[i as usize].type_0 == type_0 {
            return &mut *kPrintMethods.as_mut_ptr().offset(i as isize)
                as *mut EVP_PKEY_PRINT_METHOD;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as *mut EVP_PKEY_PRINT_METHOD;
}
unsafe extern "C" fn print_unsupported(
    mut out: *mut BIO,
    mut pkey: *const EVP_PKEY,
    mut indent: libc::c_int,
    mut kstr: *const libc::c_char,
) -> libc::c_int {
    BIO_indent(out, indent as libc::c_uint, 128 as libc::c_int as libc::c_uint);
    BIO_printf(
        out,
        b"%s algorithm unsupported\n\0" as *const u8 as *const libc::c_char,
        kstr,
    );
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_PKEY_print_public(
    mut out: *mut BIO,
    mut pkey: *const EVP_PKEY,
    mut indent: libc::c_int,
    mut pctx: *mut ASN1_PCTX,
) -> libc::c_int {
    let mut method: *mut EVP_PKEY_PRINT_METHOD = find_method(EVP_PKEY_id(pkey));
    if !method.is_null() && ((*method).pub_print).is_some() {
        return ((*method).pub_print)
            .expect("non-null function pointer")(out, pkey, indent);
    }
    return print_unsupported(
        out,
        pkey,
        indent,
        b"Public Key\0" as *const u8 as *const libc::c_char,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_PKEY_print_private(
    mut out: *mut BIO,
    mut pkey: *const EVP_PKEY,
    mut indent: libc::c_int,
    mut pctx: *mut ASN1_PCTX,
) -> libc::c_int {
    let mut method: *mut EVP_PKEY_PRINT_METHOD = find_method(EVP_PKEY_id(pkey));
    if !method.is_null() && ((*method).priv_print).is_some() {
        return ((*method).priv_print)
            .expect("non-null function pointer")(out, pkey, indent);
    }
    return print_unsupported(
        out,
        pkey,
        indent,
        b"Private Key\0" as *const u8 as *const libc::c_char,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_PKEY_print_params(
    mut out: *mut BIO,
    mut pkey: *const EVP_PKEY,
    mut indent: libc::c_int,
    mut pctx: *mut ASN1_PCTX,
) -> libc::c_int {
    let mut method: *mut EVP_PKEY_PRINT_METHOD = find_method(EVP_PKEY_id(pkey));
    if !method.is_null() && ((*method).param_print).is_some() {
        return ((*method).param_print)
            .expect("non-null function pointer")(out, pkey, indent);
    }
    return print_unsupported(
        out,
        pkey,
        indent,
        b"Parameters\0" as *const u8 as *const libc::c_char,
    );
}
unsafe extern "C" fn run_static_initializers() {
    kPrintMethodsLen = (::core::mem::size_of::<[EVP_PKEY_PRINT_METHOD; 4]>()
        as libc::c_ulong)
        .wrapping_div(::core::mem::size_of::<EVP_PKEY_PRINT_METHOD>() as libc::c_ulong);
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
