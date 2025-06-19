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
    pub type evp_cipher_st;
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
    fn EVP_aes_256_xts() -> *const EVP_CIPHER;
    fn EVP_rc2_cbc() -> *const EVP_CIPHER;
    fn EVP_chacha20_poly1305() -> *const EVP_CIPHER;
    fn EVP_aes_128_gcm() -> *const EVP_CIPHER;
    fn EVP_aes_256_gcm() -> *const EVP_CIPHER;
    fn EVP_aes_192_ecb() -> *const EVP_CIPHER;
    fn EVP_aes_192_cbc() -> *const EVP_CIPHER;
    fn EVP_aes_192_ctr() -> *const EVP_CIPHER;
    fn EVP_aes_192_gcm() -> *const EVP_CIPHER;
    fn EVP_aes_192_ofb() -> *const EVP_CIPHER;
    fn EVP_aes_128_cfb() -> *const EVP_CIPHER;
    fn EVP_aes_192_cfb() -> *const EVP_CIPHER;
    fn EVP_aes_256_cfb() -> *const EVP_CIPHER;
    fn EVP_bf_ecb() -> *const EVP_CIPHER;
    fn EVP_bf_cbc() -> *const EVP_CIPHER;
    fn EVP_bf_cfb() -> *const EVP_CIPHER;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn OPENSSL_strcasecmp(a: *const libc::c_char, b: *const libc::c_char) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type EVP_CIPHER = evp_cipher_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed {
    pub nid: libc::c_int,
    pub name: *const libc::c_char,
    pub func: Option::<unsafe extern "C" fn() -> *const EVP_CIPHER>,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub alias: *const libc::c_char,
    pub name: *const libc::c_char,
}
static mut kCiphers: [C2RustUnnamed; 30] = unsafe {
    [
        {
            let mut init = C2RustUnnamed {
                nid: 419 as libc::c_int,
                name: b"aes-128-cbc\0" as *const u8 as *const libc::c_char,
                func: Some(
                    EVP_aes_128_cbc as unsafe extern "C" fn() -> *const EVP_CIPHER,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 421 as libc::c_int,
                name: b"aes-128-cfb\0" as *const u8 as *const libc::c_char,
                func: Some(
                    EVP_aes_128_cfb as unsafe extern "C" fn() -> *const EVP_CIPHER,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 904 as libc::c_int,
                name: b"aes-128-ctr\0" as *const u8 as *const libc::c_char,
                func: Some(
                    EVP_aes_128_ctr as unsafe extern "C" fn() -> *const EVP_CIPHER,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 418 as libc::c_int,
                name: b"aes-128-ecb\0" as *const u8 as *const libc::c_char,
                func: Some(
                    EVP_aes_128_ecb as unsafe extern "C" fn() -> *const EVP_CIPHER,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 895 as libc::c_int,
                name: b"aes-128-gcm\0" as *const u8 as *const libc::c_char,
                func: Some(
                    EVP_aes_128_gcm as unsafe extern "C" fn() -> *const EVP_CIPHER,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 420 as libc::c_int,
                name: b"aes-128-ofb\0" as *const u8 as *const libc::c_char,
                func: Some(
                    EVP_aes_128_ofb as unsafe extern "C" fn() -> *const EVP_CIPHER,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 423 as libc::c_int,
                name: b"aes-192-cbc\0" as *const u8 as *const libc::c_char,
                func: Some(
                    EVP_aes_192_cbc as unsafe extern "C" fn() -> *const EVP_CIPHER,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 425 as libc::c_int,
                name: b"aes-192-cfb\0" as *const u8 as *const libc::c_char,
                func: Some(
                    EVP_aes_192_cfb as unsafe extern "C" fn() -> *const EVP_CIPHER,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 905 as libc::c_int,
                name: b"aes-192-ctr\0" as *const u8 as *const libc::c_char,
                func: Some(
                    EVP_aes_192_ctr as unsafe extern "C" fn() -> *const EVP_CIPHER,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 422 as libc::c_int,
                name: b"aes-192-ecb\0" as *const u8 as *const libc::c_char,
                func: Some(
                    EVP_aes_192_ecb as unsafe extern "C" fn() -> *const EVP_CIPHER,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 898 as libc::c_int,
                name: b"aes-192-gcm\0" as *const u8 as *const libc::c_char,
                func: Some(
                    EVP_aes_192_gcm as unsafe extern "C" fn() -> *const EVP_CIPHER,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 424 as libc::c_int,
                name: b"aes-192-ofb\0" as *const u8 as *const libc::c_char,
                func: Some(
                    EVP_aes_192_ofb as unsafe extern "C" fn() -> *const EVP_CIPHER,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 427 as libc::c_int,
                name: b"aes-256-cbc\0" as *const u8 as *const libc::c_char,
                func: Some(
                    EVP_aes_256_cbc as unsafe extern "C" fn() -> *const EVP_CIPHER,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 429 as libc::c_int,
                name: b"aes-256-cfb\0" as *const u8 as *const libc::c_char,
                func: Some(
                    EVP_aes_256_cfb as unsafe extern "C" fn() -> *const EVP_CIPHER,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 906 as libc::c_int,
                name: b"aes-256-ctr\0" as *const u8 as *const libc::c_char,
                func: Some(
                    EVP_aes_256_ctr as unsafe extern "C" fn() -> *const EVP_CIPHER,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 426 as libc::c_int,
                name: b"aes-256-ecb\0" as *const u8 as *const libc::c_char,
                func: Some(
                    EVP_aes_256_ecb as unsafe extern "C" fn() -> *const EVP_CIPHER,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 901 as libc::c_int,
                name: b"aes-256-gcm\0" as *const u8 as *const libc::c_char,
                func: Some(
                    EVP_aes_256_gcm as unsafe extern "C" fn() -> *const EVP_CIPHER,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 428 as libc::c_int,
                name: b"aes-256-ofb\0" as *const u8 as *const libc::c_char,
                func: Some(
                    EVP_aes_256_ofb as unsafe extern "C" fn() -> *const EVP_CIPHER,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 914 as libc::c_int,
                name: b"aes-256-xts\0" as *const u8 as *const libc::c_char,
                func: Some(
                    EVP_aes_256_xts as unsafe extern "C" fn() -> *const EVP_CIPHER,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 950 as libc::c_int,
                name: b"chacha20-poly1305\0" as *const u8 as *const libc::c_char,
                func: Some(
                    EVP_chacha20_poly1305 as unsafe extern "C" fn() -> *const EVP_CIPHER,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 31 as libc::c_int,
                name: b"des-cbc\0" as *const u8 as *const libc::c_char,
                func: Some(EVP_des_cbc as unsafe extern "C" fn() -> *const EVP_CIPHER),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 29 as libc::c_int,
                name: b"des-ecb\0" as *const u8 as *const libc::c_char,
                func: Some(EVP_des_ecb as unsafe extern "C" fn() -> *const EVP_CIPHER),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 43 as libc::c_int,
                name: b"des-ede-cbc\0" as *const u8 as *const libc::c_char,
                func: Some(
                    EVP_des_ede_cbc as unsafe extern "C" fn() -> *const EVP_CIPHER,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 32 as libc::c_int,
                name: b"des-ede\0" as *const u8 as *const libc::c_char,
                func: Some(EVP_des_ede as unsafe extern "C" fn() -> *const EVP_CIPHER),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 44 as libc::c_int,
                name: b"des-ede3-cbc\0" as *const u8 as *const libc::c_char,
                func: Some(
                    EVP_des_ede3_cbc as unsafe extern "C" fn() -> *const EVP_CIPHER,
                ),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 37 as libc::c_int,
                name: b"rc2-cbc\0" as *const u8 as *const libc::c_char,
                func: Some(EVP_rc2_cbc as unsafe extern "C" fn() -> *const EVP_CIPHER),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 5 as libc::c_int,
                name: b"rc4\0" as *const u8 as *const libc::c_char,
                func: Some(EVP_rc4 as unsafe extern "C" fn() -> *const EVP_CIPHER),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 91 as libc::c_int,
                name: b"bf-cbc\0" as *const u8 as *const libc::c_char,
                func: Some(EVP_bf_cbc as unsafe extern "C" fn() -> *const EVP_CIPHER),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 93 as libc::c_int,
                name: b"bf-cfb\0" as *const u8 as *const libc::c_char,
                func: Some(EVP_bf_cfb as unsafe extern "C" fn() -> *const EVP_CIPHER),
            };
            init
        },
        {
            let mut init = C2RustUnnamed {
                nid: 92 as libc::c_int,
                name: b"bf-ecb\0" as *const u8 as *const libc::c_char,
                func: Some(EVP_bf_ecb as unsafe extern "C" fn() -> *const EVP_CIPHER),
            };
            init
        },
    ]
};
static mut kCipherAliases: [C2RustUnnamed_0; 7] = [
    {
        let mut init = C2RustUnnamed_0 {
            alias: b"3des\0" as *const u8 as *const libc::c_char,
            name: b"des-ede3-cbc\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            alias: b"DES\0" as *const u8 as *const libc::c_char,
            name: b"des-cbc\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            alias: b"aes256\0" as *const u8 as *const libc::c_char,
            name: b"aes-256-cbc\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            alias: b"aes128\0" as *const u8 as *const libc::c_char,
            name: b"aes-128-cbc\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            alias: b"id-aes128-gcm\0" as *const u8 as *const libc::c_char,
            name: b"aes-128-gcm\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            alias: b"id-aes192-gcm\0" as *const u8 as *const libc::c_char,
            name: b"aes-192-gcm\0" as *const u8 as *const libc::c_char,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            alias: b"id-aes256-gcm\0" as *const u8 as *const libc::c_char,
            name: b"aes-256-gcm\0" as *const u8 as *const libc::c_char,
        };
        init
    },
];
#[no_mangle]
pub unsafe extern "C" fn EVP_get_cipherbynid(mut nid: libc::c_int) -> *const EVP_CIPHER {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (::core::mem::size_of::<[C2RustUnnamed; 30]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<C2RustUnnamed>() as libc::c_ulong)
    {
        if kCiphers[i as usize].nid == nid {
            return (kCiphers[i as usize].func).expect("non-null function pointer")();
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as *const EVP_CIPHER;
}
unsafe extern "C" fn get_cipherbyname(
    mut name: *const libc::c_char,
) -> *const EVP_CIPHER {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (::core::mem::size_of::<[C2RustUnnamed; 30]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<C2RustUnnamed>() as libc::c_ulong)
    {
        if OPENSSL_strcasecmp(kCiphers[i as usize].name, name) == 0 as libc::c_int {
            return (kCiphers[i as usize].func).expect("non-null function pointer")();
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as *const EVP_CIPHER;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_get_cipherbyname(
    mut name: *const libc::c_char,
) -> *const EVP_CIPHER {
    if name.is_null() {
        return 0 as *const EVP_CIPHER;
    }
    let mut ec: *const EVP_CIPHER = get_cipherbyname(name);
    if !ec.is_null() {
        return ec;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (::core::mem::size_of::<[C2RustUnnamed_0; 7]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<C2RustUnnamed_0>() as libc::c_ulong)
    {
        if OPENSSL_strcasecmp(name, kCipherAliases[i as usize].alias) == 0 as libc::c_int
        {
            name = kCipherAliases[i as usize].name;
            let mut cipher: *const EVP_CIPHER = get_cipherbyname(name);
            if !cipher.is_null() {} else {
                __assert_fail(
                    b"cipher != NULL\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/cipher_extra.c\0"
                        as *const u8 as *const libc::c_char,
                    156 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 53],
                        &[libc::c_char; 53],
                    >(b"const EVP_CIPHER *EVP_get_cipherbyname(const char *)\0"))
                        .as_ptr(),
                );
            }
            'c_1884: {
                if !cipher.is_null() {} else {
                    __assert_fail(
                        b"cipher != NULL\0" as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/cipher_extra.c\0"
                            as *const u8 as *const libc::c_char,
                        156 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 53],
                            &[libc::c_char; 53],
                        >(b"const EVP_CIPHER *EVP_get_cipherbyname(const char *)\0"))
                            .as_ptr(),
                    );
                }
            };
            return cipher;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as *const EVP_CIPHER;
}
