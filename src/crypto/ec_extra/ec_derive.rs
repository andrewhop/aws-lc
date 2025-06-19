#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(extern_types, label_break_value)]
extern "C" {
    pub type bignum_ctx;
    pub type stack_st_void;
    pub type ecdsa_sig_st;
    pub type env_md_st;
    fn BN_free(bn: *mut BIGNUM);
    fn BN_num_bytes(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_bin2bn(in_0: *const uint8_t, len: size_t, ret: *mut BIGNUM) -> *mut BIGNUM;
    fn BN_CTX_new() -> *mut BN_CTX;
    fn BN_CTX_free(ctx: *mut BN_CTX);
    fn BN_to_montgomery(
        ret: *mut BIGNUM,
        a: *const BIGNUM,
        mont: *const BN_MONT_CTX,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_from_montgomery(
        ret: *mut BIGNUM,
        a: *const BIGNUM,
        mont: *const BN_MONT_CTX,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn EC_GROUP_get0_order(group: *const EC_GROUP) -> *const BIGNUM;
    fn EC_GROUP_order_bits(group: *const EC_GROUP) -> libc::c_int;
    fn EC_GROUP_get_curve_name(group: *const EC_GROUP) -> libc::c_int;
    fn EC_curve_nid2nist(nid: libc::c_int) -> *const libc::c_char;
    fn EC_POINT_new(group: *const EC_GROUP) -> *mut EC_POINT;
    fn EC_POINT_free(point: *mut EC_POINT);
    fn EC_POINT_mul(
        group: *const EC_GROUP,
        r: *mut EC_POINT,
        n: *const BIGNUM,
        q: *const EC_POINT,
        m: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn EVP_sha256() -> *const EVP_MD;
    fn EC_KEY_new() -> *mut EC_KEY;
    fn EC_KEY_free(key: *mut EC_KEY);
    fn EC_KEY_set_group(key: *mut EC_KEY, group: *const EC_GROUP) -> libc::c_int;
    fn EC_KEY_set_private_key(key: *mut EC_KEY, priv_0: *const BIGNUM) -> libc::c_int;
    fn EC_KEY_set_public_key(key: *mut EC_KEY, pub_0: *const EC_POINT) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn OPENSSL_strlcpy(
        dst: *mut libc::c_char,
        src: *const libc::c_char,
        dst_size: size_t,
    ) -> size_t;
    fn OPENSSL_strlcat(
        dst: *mut libc::c_char,
        src: *const libc::c_char,
        dst_size: size_t,
    ) -> size_t;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn HKDF(
        out_key: *mut uint8_t,
        out_len: size_t,
        digest: *const EVP_MD,
        secret: *const uint8_t,
        secret_len: size_t,
        salt: *const uint8_t,
        salt_len: size_t,
        info: *const uint8_t,
        info_len: size_t,
    ) -> libc::c_int;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type BN_CTX = bignum_ctx;
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
pub struct ec_group_st {
    pub meth: *const EC_METHOD,
    pub generator: EC_POINT,
    pub order: BN_MONT_CTX,
    pub field: BN_MONT_CTX,
    pub a: EC_FELEM,
    pub b: EC_FELEM,
    pub comment: *const libc::c_char,
    pub curve_name: libc::c_int,
    pub oid: [uint8_t; 9],
    pub oid_len: uint8_t,
    pub a_is_minus3: libc::c_int,
    pub has_order: libc::c_int,
    pub field_greater_than_order: libc::c_int,
    pub conv_form: point_conversion_form_t,
    pub mutable_ec_group: libc::c_int,
}
pub type point_conversion_form_t = libc::c_uint;
pub const POINT_CONVERSION_HYBRID: point_conversion_form_t = 6;
pub const POINT_CONVERSION_UNCOMPRESSED: point_conversion_form_t = 4;
pub const POINT_CONVERSION_COMPRESSED: point_conversion_form_t = 2;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EC_FELEM {
    pub words: [BN_ULONG; 9],
}
pub type EC_POINT = ec_point_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ec_point_st {
    pub group: *mut EC_GROUP,
    pub raw: EC_JACOBIAN,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EC_JACOBIAN {
    pub X: EC_FELEM,
    pub Y: EC_FELEM,
    pub Z: EC_FELEM,
}
pub type EC_GROUP = ec_group_st;
pub type EC_METHOD = ec_method_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ec_method_st {
    pub point_get_affine_coordinates: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *const EC_JACOBIAN,
            *mut EC_FELEM,
            *mut EC_FELEM,
        ) -> libc::c_int,
    >,
    pub jacobian_to_affine_batch: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_AFFINE,
            *const EC_JACOBIAN,
            size_t,
        ) -> libc::c_int,
    >,
    pub add: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_JACOBIAN,
            *const EC_JACOBIAN,
            *const EC_JACOBIAN,
        ) -> (),
    >,
    pub dbl: Option::<
        unsafe extern "C" fn(*const EC_GROUP, *mut EC_JACOBIAN, *const EC_JACOBIAN) -> (),
    >,
    pub mul: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_JACOBIAN,
            *const EC_JACOBIAN,
            *const EC_SCALAR,
        ) -> (),
    >,
    pub mul_base: Option::<
        unsafe extern "C" fn(*const EC_GROUP, *mut EC_JACOBIAN, *const EC_SCALAR) -> (),
    >,
    pub mul_batch: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_JACOBIAN,
            *const EC_JACOBIAN,
            *const EC_SCALAR,
            *const EC_JACOBIAN,
            *const EC_SCALAR,
            *const EC_JACOBIAN,
            *const EC_SCALAR,
        ) -> (),
    >,
    pub mul_public: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_JACOBIAN,
            *const EC_SCALAR,
            *const EC_JACOBIAN,
            *const EC_SCALAR,
        ) -> (),
    >,
    pub mul_public_batch: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_JACOBIAN,
            *const EC_SCALAR,
            *const EC_JACOBIAN,
            *const EC_SCALAR,
            size_t,
        ) -> libc::c_int,
    >,
    pub init_precomp: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_PRECOMP,
            *const EC_JACOBIAN,
        ) -> libc::c_int,
    >,
    pub mul_precomp: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_JACOBIAN,
            *const EC_PRECOMP,
            *const EC_SCALAR,
            *const EC_PRECOMP,
            *const EC_SCALAR,
            *const EC_PRECOMP,
            *const EC_SCALAR,
        ) -> (),
    >,
    pub felem_mul: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_FELEM,
            *const EC_FELEM,
            *const EC_FELEM,
        ) -> (),
    >,
    pub felem_sqr: Option::<
        unsafe extern "C" fn(*const EC_GROUP, *mut EC_FELEM, *const EC_FELEM) -> (),
    >,
    pub felem_to_bytes: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut uint8_t,
            *mut size_t,
            *const EC_FELEM,
        ) -> (),
    >,
    pub felem_from_bytes: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_FELEM,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub felem_reduce: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_FELEM,
            *const BN_ULONG,
            size_t,
        ) -> (),
    >,
    pub felem_exp: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_FELEM,
            *const EC_FELEM,
            *const BN_ULONG,
            size_t,
        ) -> (),
    >,
    pub scalar_inv0_montgomery: Option::<
        unsafe extern "C" fn(*const EC_GROUP, *mut EC_SCALAR, *const EC_SCALAR) -> (),
    >,
    pub scalar_to_montgomery_inv_vartime: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_SCALAR,
            *const EC_SCALAR,
        ) -> libc::c_int,
    >,
    pub cmp_x_coordinate: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *const EC_JACOBIAN,
            *const EC_SCALAR,
        ) -> libc::c_int,
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EC_SCALAR {
    pub words: [BN_ULONG; 9],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union EC_PRECOMP {
    pub comb: [EC_AFFINE; 31],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EC_AFFINE {
    pub X: EC_FELEM,
    pub Y: EC_FELEM,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ec_key_st {
    pub group: *mut EC_GROUP,
    pub pub_key: *mut EC_POINT,
    pub priv_key: *mut EC_WRAPPED_SCALAR,
    pub enc_flag: libc::c_uint,
    pub conv_form: point_conversion_form_t,
    pub references: CRYPTO_refcount_t,
    pub eckey_method: *const EC_KEY_METHOD,
    pub ex_data: CRYPTO_EX_DATA,
}
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
pub type EC_KEY_METHOD = ec_key_method_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ec_key_method_st {
    pub init: Option::<unsafe extern "C" fn(*mut EC_KEY) -> libc::c_int>,
    pub finish: Option::<unsafe extern "C" fn(*mut EC_KEY) -> ()>,
    pub sign: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            libc::c_int,
            *mut uint8_t,
            *mut libc::c_uint,
            *const BIGNUM,
            *const BIGNUM,
            *mut EC_KEY,
        ) -> libc::c_int,
    >,
    pub sign_sig: Option::<
        unsafe extern "C" fn(
            *const uint8_t,
            libc::c_int,
            *const BIGNUM,
            *const BIGNUM,
            *mut EC_KEY,
        ) -> *mut ECDSA_SIG,
    >,
    pub flags: libc::c_int,
}
pub type EC_KEY = ec_key_st;
pub type ECDSA_SIG = ecdsa_sig_st;
pub type CRYPTO_refcount_t = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EC_WRAPPED_SCALAR {
    pub bignum: BIGNUM,
    pub scalar: EC_SCALAR,
}
pub type EVP_MD = env_md_st;
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_derive_from_secret(
    mut group: *const EC_GROUP,
    mut secret: *const uint8_t,
    mut secret_len: size_t,
) -> *mut EC_KEY {
    let mut name: *const libc::c_char = EC_curve_nid2nist(
        EC_GROUP_get_curve_name(group),
    );
    if name.is_null() || strlen(name) > 16 as libc::c_int as libc::c_ulong {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            123 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_derive.c\0"
                as *const u8 as *const libc::c_char,
            33 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EC_KEY;
    }
    static mut kLabel: [libc::c_char; 15] = unsafe {
        *::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"derive EC key \0")
    };
    let mut info: [libc::c_char; 31] = [0; 31];
    OPENSSL_strlcpy(
        info.as_mut_ptr(),
        kLabel.as_ptr(),
        ::core::mem::size_of::<[libc::c_char; 31]>() as libc::c_ulong,
    );
    OPENSSL_strlcat(
        info.as_mut_ptr(),
        name,
        ::core::mem::size_of::<[libc::c_char; 31]>() as libc::c_ulong,
    );
    if EC_GROUP_order_bits(group) <= 128 as libc::c_int + 8 as libc::c_int {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            4 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_derive.c\0"
                as *const u8 as *const libc::c_char,
            53 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EC_KEY;
    }
    let mut derived: [uint8_t; 82] = [0; 82];
    let mut derived_len: size_t = (BN_num_bytes(EC_GROUP_get0_order(group)))
        .wrapping_add((128 as libc::c_int / 8 as libc::c_int) as libc::c_uint) as size_t;
    if derived_len <= ::core::mem::size_of::<[uint8_t; 82]>() as libc::c_ulong {} else {
        __assert_fail(
            b"derived_len <= sizeof(derived)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_derive.c\0"
                as *const u8 as *const libc::c_char,
            60 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 77],
                &[libc::c_char; 77],
            >(
                b"EC_KEY *EC_KEY_derive_from_secret(const EC_GROUP *, const uint8_t *, size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_3378: {
        if derived_len <= ::core::mem::size_of::<[uint8_t; 82]>() as libc::c_ulong
        {} else {
            __assert_fail(
                b"derived_len <= sizeof(derived)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_derive.c\0"
                    as *const u8 as *const libc::c_char,
                60 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 77],
                    &[libc::c_char; 77],
                >(
                    b"EC_KEY *EC_KEY_derive_from_secret(const EC_GROUP *, const uint8_t *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if HKDF(
        derived.as_mut_ptr(),
        derived_len,
        EVP_sha256(),
        secret,
        secret_len,
        0 as *const uint8_t,
        0 as libc::c_int as size_t,
        info.as_mut_ptr() as *const uint8_t,
        strlen(info.as_mut_ptr()),
    ) == 0
    {
        return 0 as *mut EC_KEY;
    }
    let mut key: *mut EC_KEY = EC_KEY_new();
    let mut ctx: *mut BN_CTX = BN_CTX_new();
    let mut priv_0: *mut BIGNUM = BN_bin2bn(
        derived.as_mut_ptr(),
        derived_len,
        0 as *mut BIGNUM,
    );
    let mut pub_0: *mut EC_POINT = EC_POINT_new(group);
    if key.is_null() || ctx.is_null() || priv_0.is_null() || pub_0.is_null()
        || BN_from_montgomery(priv_0, priv_0, &(*group).order, ctx) == 0
        || BN_to_montgomery(priv_0, priv_0, &(*group).order, ctx) == 0
        || EC_POINT_mul(
            group,
            pub_0,
            priv_0,
            0 as *const EC_POINT,
            0 as *const BIGNUM,
            ctx,
        ) == 0 || EC_KEY_set_group(key, group) == 0
        || EC_KEY_set_public_key(key, pub_0) == 0
        || EC_KEY_set_private_key(key, priv_0) == 0
    {
        EC_KEY_free(key);
        key = 0 as *mut EC_KEY;
    }
    OPENSSL_cleanse(
        derived.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 82]>() as libc::c_ulong,
    );
    BN_CTX_free(ctx);
    BN_free(priv_0);
    EC_POINT_free(pub_0);
    return key;
}
