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
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
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
unsafe extern "C" fn null_init_key(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut key: *const uint8_t,
    mut iv: *const uint8_t,
    mut enc: libc::c_int,
) -> libc::c_int {
    return 1 as libc::c_int;
}
unsafe extern "C" fn null_cipher(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
) -> libc::c_int {
    if in_0 != out as *const uint8_t {
        OPENSSL_memcpy(out as *mut libc::c_void, in_0 as *const libc::c_void, in_len);
    }
    return 1 as libc::c_int;
}
static mut n_cipher: EVP_CIPHER = unsafe {
    {
        let mut init = evp_cipher_st {
            nid: 0 as libc::c_int,
            block_size: 1 as libc::c_int as libc::c_uint,
            key_len: 0 as libc::c_int as libc::c_uint,
            iv_len: 0 as libc::c_int as libc::c_uint,
            ctx_size: 0 as libc::c_int as libc::c_uint,
            flags: 0,
            init: Some(
                null_init_key
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *const uint8_t,
                        *const uint8_t,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            cipher: Some(
                null_cipher
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *mut uint8_t,
                        *const uint8_t,
                        size_t,
                    ) -> libc::c_int,
            ),
            cleanup: None,
            ctrl: None,
        };
        init
    }
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_enc_null() -> *const EVP_CIPHER {
    return &n_cipher;
}
