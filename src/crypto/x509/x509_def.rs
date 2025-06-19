#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#[no_mangle]
pub unsafe extern "C" fn X509_get_default_private_dir() -> *const libc::c_char {
    return b"/etc/ssl/private\0" as *const u8 as *const libc::c_char;
}
#[no_mangle]
pub unsafe extern "C" fn X509_get_default_cert_area() -> *const libc::c_char {
    return b"/etc/ssl\0" as *const u8 as *const libc::c_char;
}
#[no_mangle]
pub unsafe extern "C" fn X509_get_default_cert_dir() -> *const libc::c_char {
    return b"/etc/ssl/certs\0" as *const u8 as *const libc::c_char;
}
#[no_mangle]
pub unsafe extern "C" fn X509_get_default_cert_file() -> *const libc::c_char {
    return b"/etc/ssl/cert.pem\0" as *const u8 as *const libc::c_char;
}
#[no_mangle]
pub unsafe extern "C" fn X509_get_default_cert_dir_env() -> *const libc::c_char {
    return b"SSL_CERT_DIR\0" as *const u8 as *const libc::c_char;
}
#[no_mangle]
pub unsafe extern "C" fn X509_get_default_cert_file_env() -> *const libc::c_char {
    return b"SSL_CERT_FILE\0" as *const u8 as *const libc::c_char;
}
