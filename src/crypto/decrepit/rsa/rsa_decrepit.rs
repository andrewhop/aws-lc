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
    pub type env_md_st;
    pub type rsa_st;
    fn BN_new() -> *mut BIGNUM;
    fn BN_free(bn: *mut BIGNUM);
    fn BN_set_u64(bn: *mut BIGNUM, value: uint64_t) -> libc::c_int;
    fn RSA_new() -> *mut RSA;
    fn RSA_free(rsa: *mut RSA);
    fn RSA_generate_key_ex(
        rsa: *mut RSA,
        bits: libc::c_int,
        e: *const BIGNUM,
        cb: *mut BN_GENCB,
    ) -> libc::c_int;
    fn RSA_verify_PKCS1_PSS_mgf1(
        rsa: *const RSA,
        mHash: *const uint8_t,
        Hash: *const EVP_MD,
        mgf1Hash: *const EVP_MD,
        EM: *const uint8_t,
        sLen: libc::c_int,
    ) -> libc::c_int;
    fn RSA_padding_add_PKCS1_PSS_mgf1(
        rsa: *const RSA,
        EM: *mut uint8_t,
        mHash: *const uint8_t,
        Hash: *const EVP_MD,
        mgf1Hash: *const EVP_MD,
        sLen: libc::c_int,
    ) -> libc::c_int;
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
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint64_t = __uint64_t;
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
pub type EVP_MD = env_md_st;
pub type RSA = rsa_st;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn RSA_generate_key(
    mut bits: libc::c_int,
    mut e_value: uint64_t,
    mut callback: *mut libc::c_void,
    mut cb_arg: *mut libc::c_void,
) -> *mut RSA {
    if callback.is_null() {} else {
        __assert_fail(
            b"callback == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/rsa/rsa_decrepit.c\0"
                as *const u8 as *const libc::c_char,
            66 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 53],
                &[libc::c_char; 53],
            >(b"RSA *RSA_generate_key(int, uint64_t, void *, void *)\0"))
                .as_ptr(),
        );
    }
    'c_4563: {
        if callback.is_null() {} else {
            __assert_fail(
                b"callback == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/rsa/rsa_decrepit.c\0"
                    as *const u8 as *const libc::c_char,
                66 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 53],
                    &[libc::c_char; 53],
                >(b"RSA *RSA_generate_key(int, uint64_t, void *, void *)\0"))
                    .as_ptr(),
            );
        }
    };
    if cb_arg.is_null() {} else {
        __assert_fail(
            b"cb_arg == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/rsa/rsa_decrepit.c\0"
                as *const u8 as *const libc::c_char,
            67 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 53],
                &[libc::c_char; 53],
            >(b"RSA *RSA_generate_key(int, uint64_t, void *, void *)\0"))
                .as_ptr(),
        );
    }
    'c_4512: {
        if cb_arg.is_null() {} else {
            __assert_fail(
                b"cb_arg == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/rsa/rsa_decrepit.c\0"
                    as *const u8 as *const libc::c_char,
                67 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 53],
                    &[libc::c_char; 53],
                >(b"RSA *RSA_generate_key(int, uint64_t, void *, void *)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut rsa: *mut RSA = RSA_new();
    let mut e: *mut BIGNUM = BN_new();
    if rsa.is_null() || e.is_null() || BN_set_u64(e, e_value) == 0
        || RSA_generate_key_ex(rsa, bits, e, 0 as *mut BN_GENCB) == 0
    {
        BN_free(e);
        RSA_free(rsa);
        return 0 as *mut RSA;
    } else {
        BN_free(e);
        return rsa;
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn RSA_padding_add_PKCS1_PSS(
    mut rsa: *const RSA,
    mut EM: *mut uint8_t,
    mut mHash: *const uint8_t,
    mut Hash: *const EVP_MD,
    mut sLen: libc::c_int,
) -> libc::c_int {
    return RSA_padding_add_PKCS1_PSS_mgf1(
        rsa,
        EM,
        mHash,
        Hash,
        0 as *const EVP_MD,
        sLen,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn RSA_verify_PKCS1_PSS(
    mut rsa: *const RSA,
    mut mHash: *const uint8_t,
    mut Hash: *const EVP_MD,
    mut EM: *const uint8_t,
    mut sLen: libc::c_int,
) -> libc::c_int {
    return RSA_verify_PKCS1_PSS_mgf1(rsa, mHash, Hash, 0 as *const EVP_MD, EM, sLen);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn RSA_padding_add_PKCS1_OAEP(
    mut to: *mut uint8_t,
    mut to_len: size_t,
    mut from: *const uint8_t,
    mut from_len: size_t,
    mut param: *const uint8_t,
    mut param_len: size_t,
) -> libc::c_int {
    return RSA_padding_add_PKCS1_OAEP_mgf1(
        to,
        to_len,
        from,
        from_len,
        param,
        param_len,
        0 as *const EVP_MD,
        0 as *const EVP_MD,
    );
}
