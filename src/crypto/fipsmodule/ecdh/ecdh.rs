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
    pub type bignum_ctx;
    pub type stack_st_void;
    pub type ecdsa_sig_st;
    fn ec_point_mul_scalar(
        group: *const EC_GROUP,
        r: *mut EC_JACOBIAN,
        p: *const EC_JACOBIAN,
        scalar: *const EC_SCALAR,
    ) -> libc::c_int;
    fn ec_get_x_coordinate_as_bytes(
        group: *const EC_GROUP,
        out: *mut uint8_t,
        out_len: *mut size_t,
        max_out: size_t,
        p: *const EC_JACOBIAN,
    ) -> libc::c_int;
    fn EC_GROUP_cmp(
        a: *const EC_GROUP,
        b: *const EC_GROUP,
        ignored: *mut BN_CTX,
    ) -> libc::c_int;
    fn SHA224(data: *const uint8_t, len: size_t, out: *mut uint8_t) -> *mut uint8_t;
    fn SHA256(data: *const uint8_t, len: size_t, out: *mut uint8_t) -> *mut uint8_t;
    fn SHA384(data: *const uint8_t, len: size_t, out: *mut uint8_t) -> *mut uint8_t;
    fn SHA512(data: *const uint8_t, len: size_t, out: *mut uint8_t) -> *mut uint8_t;
    fn EC_KEY_new() -> *mut EC_KEY;
    fn EC_KEY_free(key: *mut EC_KEY);
    fn EC_KEY_get0_group(key: *const EC_KEY) -> *const EC_GROUP;
    fn EC_KEY_set_group(key: *mut EC_KEY, group: *const EC_GROUP) -> libc::c_int;
    fn EC_KEY_set_public_key(key: *mut EC_KEY, pub_0: *const EC_POINT) -> libc::c_int;
    fn EC_KEY_check_fips(key: *const EC_KEY) -> libc::c_int;
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
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
#[inline]
unsafe extern "C" fn boringssl_ensure_ecc_self_test() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_lock_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_unlock_state() {}
#[inline]
unsafe extern "C" fn ECDH_verify_service_indicator(mut ec_key: *const EC_KEY) {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ECDH_compute_shared_secret(
    mut buf: *mut uint8_t,
    mut buflen: *mut size_t,
    mut pub_key: *const EC_POINT,
    mut priv_key: *const EC_KEY,
) -> libc::c_int {
    let mut shared_point: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    boringssl_ensure_ecc_self_test();
    if ((*priv_key).priv_key).is_null() {
        ERR_put_error(
            27 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ecdh/ecdh.c\0"
                as *const u8 as *const libc::c_char,
            86 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let priv_0: *const EC_SCALAR = &mut (*(*priv_key).priv_key).scalar;
    let group: *const EC_GROUP = EC_KEY_get0_group(priv_key);
    if EC_GROUP_cmp(group, (*pub_key).group, 0 as *mut BN_CTX) != 0 as libc::c_int {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ecdh/ecdh.c\0"
                as *const u8 as *const libc::c_char,
            92 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    FIPS_service_indicator_lock_state();
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut key_pub_key: *mut EC_KEY = 0 as *mut EC_KEY;
    key_pub_key = EC_KEY_new();
    if !key_pub_key.is_null() {
        if EC_KEY_set_group(key_pub_key, group) == 0
            || EC_KEY_set_public_key(key_pub_key, pub_key) == 0
            || EC_KEY_check_fips(key_pub_key) == 0
        {
            ERR_put_error(
                15 as libc::c_int,
                0 as libc::c_int,
                132 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ecdh/ecdh.c\0"
                    as *const u8 as *const libc::c_char,
                113 as libc::c_int as libc::c_uint,
            );
        } else {
            shared_point = EC_JACOBIAN {
                X: EC_FELEM { words: [0; 9] },
                Y: EC_FELEM { words: [0; 9] },
                Z: EC_FELEM { words: [0; 9] },
            };
            if ec_point_mul_scalar(group, &mut shared_point, &(*pub_key).raw, priv_0)
                == 0
                || ec_get_x_coordinate_as_bytes(
                    group,
                    buf,
                    buflen,
                    *buflen,
                    &mut shared_point,
                ) == 0
            {
                ERR_put_error(
                    27 as libc::c_int,
                    0 as libc::c_int,
                    102 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ecdh/ecdh.c\0"
                        as *const u8 as *const libc::c_char,
                    121 as libc::c_int as libc::c_uint,
                );
            } else {
                ret = 1 as libc::c_int;
            }
        }
    }
    OPENSSL_cleanse(
        &mut shared_point as *mut EC_JACOBIAN as *mut libc::c_void,
        ::core::mem::size_of::<EC_JACOBIAN>() as libc::c_ulong,
    );
    FIPS_service_indicator_unlock_state();
    if !key_pub_key.is_null() {
        EC_KEY_free(key_pub_key);
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ECDH_compute_key_fips(
    mut out: *mut uint8_t,
    mut out_len: size_t,
    mut pub_key: *const EC_POINT,
    mut priv_key: *const EC_KEY,
) -> libc::c_int {
    let mut current_block: u64;
    FIPS_service_indicator_lock_state();
    let mut buf: [uint8_t; 66] = [0; 66];
    let mut buflen: size_t = ::core::mem::size_of::<[uint8_t; 66]>() as libc::c_ulong;
    let mut ret: libc::c_int = 0 as libc::c_int;
    if !(ECDH_compute_shared_secret(buf.as_mut_ptr(), &mut buflen, pub_key, priv_key)
        == 0)
    {
        match out_len {
            28 => {
                SHA224(buf.as_mut_ptr(), buflen, out);
                current_block = 13536709405535804910;
            }
            32 => {
                SHA256(buf.as_mut_ptr(), buflen, out);
                current_block = 13536709405535804910;
            }
            48 => {
                SHA384(buf.as_mut_ptr(), buflen, out);
                current_block = 13536709405535804910;
            }
            64 => {
                SHA512(buf.as_mut_ptr(), buflen, out);
                current_block = 13536709405535804910;
            }
            _ => {
                ERR_put_error(
                    27 as libc::c_int,
                    0 as libc::c_int,
                    103 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ecdh/ecdh.c\0"
                        as *const u8 as *const libc::c_char,
                    163 as libc::c_int as libc::c_uint,
                );
                current_block = 14322677232730858609;
            }
        }
        match current_block {
            14322677232730858609 => {}
            _ => {
                ret = 1 as libc::c_int;
            }
        }
    }
    FIPS_service_indicator_unlock_state();
    if ret != 0 {
        ECDH_verify_service_indicator(priv_key);
    }
    return ret;
}
