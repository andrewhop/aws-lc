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
    fn abort() -> !;
    fn aes_nohw_set_encrypt_key(
        key: *const uint8_t,
        bits: libc::c_uint,
        aeskey: *mut AES_KEY,
    ) -> libc::c_int;
    fn aes_nohw_set_decrypt_key(
        key: *const uint8_t,
        bits: libc::c_uint,
        aeskey: *mut AES_KEY,
    ) -> libc::c_int;
    fn aes_nohw_encrypt(in_0: *const uint8_t, out: *mut uint8_t, key: *const AES_KEY);
    fn aes_nohw_decrypt(in_0: *const uint8_t, out: *mut uint8_t, key: *const AES_KEY);
}
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct aes_key_st {
    pub rd_key: [uint32_t; 60],
    pub rounds: libc::c_uint,
}
pub type AES_KEY = aes_key_st;
#[inline]
unsafe extern "C" fn hwaes_capable() -> libc::c_int {
    return 0 as libc::c_int;
}
#[inline]
unsafe extern "C" fn aes_hw_set_encrypt_key(
    mut user_key: *const uint8_t,
    mut bits: libc::c_int,
    mut key: *mut AES_KEY,
) -> libc::c_int {
    abort();
}
#[inline]
unsafe extern "C" fn aes_hw_set_decrypt_key(
    mut user_key: *const uint8_t,
    mut bits: libc::c_int,
    mut key: *mut AES_KEY,
) -> libc::c_int {
    abort();
}
#[inline]
unsafe extern "C" fn aes_hw_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut key: *const AES_KEY,
) {
    abort();
}
#[inline]
unsafe extern "C" fn aes_hw_decrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut key: *const AES_KEY,
) {
    abort();
}
#[inline]
unsafe extern "C" fn vpaes_capable() -> libc::c_char {
    return 0 as libc::c_int as libc::c_char;
}
#[inline]
unsafe extern "C" fn vpaes_set_encrypt_key(
    mut userKey: *const uint8_t,
    mut bits: libc::c_int,
    mut key: *mut AES_KEY,
) -> libc::c_int {
    abort();
}
#[inline]
unsafe extern "C" fn vpaes_set_decrypt_key(
    mut userKey: *const uint8_t,
    mut bits: libc::c_int,
    mut key: *mut AES_KEY,
) -> libc::c_int {
    abort();
}
#[inline]
unsafe extern "C" fn vpaes_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut key: *const AES_KEY,
) {
    abort();
}
#[inline]
unsafe extern "C" fn vpaes_decrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut key: *const AES_KEY,
) {
    abort();
}
#[no_mangle]
pub unsafe extern "C" fn AES_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut key: *const AES_KEY,
) {
    if hwaes_capable() != 0 {
        aes_hw_encrypt(in_0, out, key);
    } else if vpaes_capable() != 0 {
        vpaes_encrypt(in_0, out, key);
    } else {
        aes_nohw_encrypt(in_0, out, key);
    };
}
#[no_mangle]
pub unsafe extern "C" fn AES_decrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut key: *const AES_KEY,
) {
    if hwaes_capable() != 0 {
        aes_hw_decrypt(in_0, out, key);
    } else if vpaes_capable() != 0 {
        vpaes_decrypt(in_0, out, key);
    } else {
        aes_nohw_decrypt(in_0, out, key);
    };
}
#[no_mangle]
pub unsafe extern "C" fn AES_set_encrypt_key(
    mut key: *const uint8_t,
    mut bits: libc::c_uint,
    mut aeskey: *mut AES_KEY,
) -> libc::c_int {
    if bits != 128 as libc::c_int as libc::c_uint
        && bits != 192 as libc::c_int as libc::c_uint
        && bits != 256 as libc::c_int as libc::c_uint
    {
        return -(2 as libc::c_int);
    }
    if hwaes_capable() != 0 {
        return aes_hw_set_encrypt_key(key, bits as libc::c_int, aeskey)
    } else if vpaes_capable() != 0 {
        return vpaes_set_encrypt_key(key, bits as libc::c_int, aeskey)
    } else {
        return aes_nohw_set_encrypt_key(key, bits, aeskey)
    };
}
#[no_mangle]
pub unsafe extern "C" fn AES_set_decrypt_key(
    mut key: *const uint8_t,
    mut bits: libc::c_uint,
    mut aeskey: *mut AES_KEY,
) -> libc::c_int {
    if bits != 128 as libc::c_int as libc::c_uint
        && bits != 192 as libc::c_int as libc::c_uint
        && bits != 256 as libc::c_int as libc::c_uint
    {
        return -(2 as libc::c_int);
    }
    if hwaes_capable() != 0 {
        return aes_hw_set_decrypt_key(key, bits as libc::c_int, aeskey)
    } else if vpaes_capable() != 0 {
        return vpaes_set_decrypt_key(key, bits as libc::c_int, aeskey)
    } else {
        return aes_nohw_set_decrypt_key(key, bits, aeskey)
    };
}
