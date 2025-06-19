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
    pub type dsa_st;
    pub type ec_key_st;
    pub type evp_pkey_st;
    pub type rsa_st;
    fn i2d_DSAPrivateKey(in_0: *const DSA, outp: *mut *mut uint8_t) -> libc::c_int;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn i2d_ECPrivateKey(key: *const EC_KEY, outp: *mut *mut uint8_t) -> libc::c_int;
    fn EVP_PKEY_id(pkey: *const EVP_PKEY) -> libc::c_int;
    fn EVP_PKEY_get0_RSA(pkey: *const EVP_PKEY) -> *mut RSA;
    fn EVP_PKEY_get0_DSA(pkey: *const EVP_PKEY) -> *mut DSA;
    fn EVP_PKEY_get0_EC_KEY(pkey: *const EVP_PKEY) -> *mut EC_KEY;
    fn i2d_RSAPrivateKey(in_0: *const RSA, outp: *mut *mut uint8_t) -> libc::c_int;
}
pub type __uint8_t = libc::c_uchar;
pub type uint8_t = __uint8_t;
pub type DSA = dsa_st;
pub type EC_KEY = ec_key_st;
pub type EVP_PKEY = evp_pkey_st;
pub type RSA = rsa_st;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_PrivateKey(
    mut a: *const EVP_PKEY,
    mut pp: *mut *mut uint8_t,
) -> libc::c_int {
    match EVP_PKEY_id(a) {
        6 => return i2d_RSAPrivateKey(EVP_PKEY_get0_RSA(a), pp),
        408 => return i2d_ECPrivateKey(EVP_PKEY_get0_EC_KEY(a), pp),
        116 => return i2d_DSAPrivateKey(EVP_PKEY_get0_DSA(a), pp),
        _ => {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                187 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/i2d_pr.c\0" as *const u8
                    as *const libc::c_char,
                76 as libc::c_int as libc::c_uint,
            );
            return -(1 as libc::c_int);
        }
    };
}
