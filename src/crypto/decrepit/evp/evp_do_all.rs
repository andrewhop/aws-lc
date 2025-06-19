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
    pub type env_md_st;
    pub type evp_cipher_st;
    fn EVP_md4() -> *const EVP_MD;
    fn EVP_md5() -> *const EVP_MD;
    fn EVP_ripemd160() -> *const EVP_MD;
    fn EVP_sha1() -> *const EVP_MD;
    fn EVP_sha224() -> *const EVP_MD;
    fn EVP_sha256() -> *const EVP_MD;
    fn EVP_sha384() -> *const EVP_MD;
    fn EVP_sha512() -> *const EVP_MD;
    fn EVP_sha512_224() -> *const EVP_MD;
    fn EVP_sha512_256() -> *const EVP_MD;
    fn EVP_rc4() -> *const EVP_CIPHER;
    fn EVP_des_cbc() -> *const EVP_CIPHER;
    fn EVP_des_ecb() -> *const EVP_CIPHER;
    fn EVP_des_ede() -> *const EVP_CIPHER;
    fn EVP_des_ede_cbc() -> *const EVP_CIPHER;
    fn EVP_des_ede3_cbc() -> *const EVP_CIPHER;
    fn EVP_aes_128_ecb() -> *const EVP_CIPHER;
    fn EVP_aes_128_cbc() -> *const EVP_CIPHER;
    fn EVP_aes_128_ctr() -> *const EVP_CIPHER;
    fn EVP_aes_128_ofb() -> *const EVP_CIPHER;
    fn EVP_aes_256_ecb() -> *const EVP_CIPHER;
    fn EVP_aes_256_cbc() -> *const EVP_CIPHER;
    fn EVP_aes_256_ctr() -> *const EVP_CIPHER;
    fn EVP_aes_256_ofb() -> *const EVP_CIPHER;
    fn EVP_rc2_cbc() -> *const EVP_CIPHER;
    fn EVP_chacha20_poly1305() -> *const EVP_CIPHER;
    fn EVP_aes_128_gcm() -> *const EVP_CIPHER;
    fn EVP_aes_256_gcm() -> *const EVP_CIPHER;
    fn EVP_aes_192_ecb() -> *const EVP_CIPHER;
    fn EVP_aes_192_cbc() -> *const EVP_CIPHER;
    fn EVP_aes_192_ctr() -> *const EVP_CIPHER;
    fn EVP_aes_192_gcm() -> *const EVP_CIPHER;
    fn EVP_aes_192_ofb() -> *const EVP_CIPHER;
}
pub type EVP_MD = env_md_st;
pub type EVP_CIPHER = evp_cipher_st;
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_do_all_sorted(
    mut callback: Option::<
        unsafe extern "C" fn(
            *const EVP_CIPHER,
            *const libc::c_char,
            *const libc::c_char,
            *mut libc::c_void,
        ) -> (),
    >,
    mut arg: *mut libc::c_void,
) {
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_128_cbc(),
        b"AES-128-CBC\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_192_cbc(),
        b"AES-192-CBC\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_256_cbc(),
        b"AES-256-CBC\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_128_ctr(),
        b"AES-128-CTR\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_192_ctr(),
        b"AES-192-CTR\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_256_ctr(),
        b"AES-256-CTR\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_128_ecb(),
        b"AES-128-ECB\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_192_ecb(),
        b"AES-192-ECB\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_256_ecb(),
        b"AES-256-ECB\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_128_ofb(),
        b"AES-128-OFB\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_192_ofb(),
        b"AES-192-OFB\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_256_ofb(),
        b"AES-256-OFB\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_128_gcm(),
        b"AES-128-GCM\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_192_gcm(),
        b"AES-192-GCM\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_256_gcm(),
        b"AES-256-GCM\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_des_cbc(),
        b"DES-CBC\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_des_ecb(),
        b"DES-ECB\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_des_ede(),
        b"DES-EDE\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_des_ede_cbc(),
        b"DES-EDE-CBC\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_des_ede3_cbc(),
        b"DES-EDE3-CBC\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_rc2_cbc(),
        b"RC2-CBC\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_rc4(),
        b"RC4\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_chacha20_poly1305(),
        b"CHACHA20-POLY1305\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_128_cbc(),
        b"aes-128-cbc\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_192_cbc(),
        b"aes-192-cbc\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_256_cbc(),
        b"aes-256-cbc\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_128_ctr(),
        b"aes-128-ctr\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_192_ctr(),
        b"aes-192-ctr\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_256_ctr(),
        b"aes-256-ctr\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_128_ecb(),
        b"aes-128-ecb\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_192_ecb(),
        b"aes-192-ecb\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_256_ecb(),
        b"aes-256-ecb\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_128_ofb(),
        b"aes-128-ofb\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_192_ofb(),
        b"aes-192-ofb\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_256_ofb(),
        b"aes-256-ofb\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_128_gcm(),
        b"aes-128-gcm\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_192_gcm(),
        b"aes-192-gcm\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_256_gcm(),
        b"aes-256-gcm\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_des_cbc(),
        b"des-cbc\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_des_ecb(),
        b"des-ecb\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_des_ede(),
        b"des-ede\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_des_ede_cbc(),
        b"des-ede-cbc\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_des_ede3_cbc(),
        b"des-ede3-cbc\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_rc2_cbc(),
        b"rc2-cbc\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_rc4(),
        b"rc4\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_chacha20_poly1305(),
        b"chacha20-poly1305\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_128_cbc(),
        b"aes128\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_aes_256_cbc(),
        b"aes256\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_do_all_sorted(
    mut callback: Option::<
        unsafe extern "C" fn(
            *const EVP_MD,
            *const libc::c_char,
            *const libc::c_char,
            *mut libc::c_void,
        ) -> (),
    >,
    mut arg: *mut libc::c_void,
) {
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_md4(),
        b"MD4\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_md5(),
        b"MD5\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_ripemd160(),
        b"RIPEMD160\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_sha1(),
        b"SHA1\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_sha224(),
        b"SHA224\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_sha256(),
        b"SHA256\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_sha384(),
        b"SHA384\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_sha512(),
        b"SHA512\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_sha512_224(),
        b"SHA512-224\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_sha512_256(),
        b"SHA512-256\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_md4(),
        b"md4\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_md5(),
        b"md5\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_ripemd160(),
        b"ripemd160\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_sha1(),
        b"sha1\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_sha224(),
        b"sha224\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_sha256(),
        b"sha256\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_sha384(),
        b"sha384\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_sha512(),
        b"sha512\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_sha512_224(),
        b"sha512-224\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
    callback
        .expect(
            "non-null function pointer",
        )(
        EVP_sha512_256(),
        b"sha512-256\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        arg,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_do_all(
    mut callback: Option::<
        unsafe extern "C" fn(
            *const EVP_MD,
            *const libc::c_char,
            *const libc::c_char,
            *mut libc::c_void,
        ) -> (),
    >,
    mut arg: *mut libc::c_void,
) {
    EVP_MD_do_all_sorted(callback, arg);
}
