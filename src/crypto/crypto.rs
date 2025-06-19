use std::sync::OnceLock;
#[allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
unsafe extern "C" {
    pub type ossl_init_settings_st;
    fn abort() -> !;
    fn RAND_bytes(buf: *mut uint8_t, len: size_t) -> libc::c_int;
    fn CRYPTO_once(
        once_0: *mut CRYPTO_once_t,
        init: Option::<unsafe extern "C" fn() -> ()>,
    );
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint64_t = __uint64_t;
pub type pthread_once_t = libc::c_int;
pub type OPENSSL_INIT_SETTINGS = ossl_init_settings_st;
pub type CRYPTO_once_t = pthread_once_t;
static LIBRARY_INIT: OnceLock<()> = OnceLock::new();
unsafe extern "C" fn do_library_init() {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_library_init() {
    LIBRARY_INIT.get_or_init(|| {
        do_library_init();
        // Return unit value since we're just handling initialization
        ()
    });}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_is_confidential_build() -> libc::c_int {
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_has_asm() -> libc::c_int {
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_pre_sandbox_init() {
    CRYPTO_library_init();
    let mut buf: [uint8_t; 10] = [0; 10];
    if RAND_bytes(buf.as_mut_ptr(), 10 as libc::c_int as size_t) != 1 as libc::c_int {
        abort();
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SSLeay_version(mut which: libc::c_int) -> *const libc::c_char {
    return OpenSSL_version(which);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OpenSSL_version(mut which: libc::c_int) -> *const libc::c_char {
    match which {
        0 => return b"AWS-LC 1.52.1\0" as *const u8 as *const libc::c_char,
        1 => return b"compiler: n/a\0" as *const u8 as *const libc::c_char,
        2 => return b"built on: n/a\0" as *const u8 as *const libc::c_char,
        3 => return b"platform: n/a\0" as *const u8 as *const libc::c_char,
        4 => return b"OPENSSLDIR: n/a\0" as *const u8 as *const libc::c_char,
        _ => return b"not available\0" as *const u8 as *const libc::c_char,
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SSLeay() -> libc::c_ulong {
    return 0x1010107f as libc::c_int as libc::c_ulong;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OpenSSL_version_num() -> libc::c_ulong {
    return 0x1010107f as libc::c_int as libc::c_ulong;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn awslc_api_version_num() -> libc::c_ulong {
    return 34 as libc::c_int as libc::c_ulong;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_malloc_init() -> libc::c_int {
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_malloc_init() -> libc::c_int {
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ENGINE_load_builtin_engines() {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ENGINE_register_all_complete() -> libc::c_int {
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_load_builtin_modules() {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_init_crypto(
    mut opts: uint64_t,
    mut settings: *const OPENSSL_INIT_SETTINGS,
) -> libc::c_int {
    CRYPTO_library_init();
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_init() {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_cleanup() {}
