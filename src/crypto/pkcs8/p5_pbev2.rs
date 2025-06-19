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
    pub type evp_cipher_st;
    pub type engine_st;
    pub type env_md_st;
    fn EVP_des_ede3_cbc() -> *const EVP_CIPHER;
    fn EVP_aes_128_cbc() -> *const EVP_CIPHER;
    fn EVP_aes_256_cbc() -> *const EVP_CIPHER;
    fn EVP_rc2_cbc() -> *const EVP_CIPHER;
    fn EVP_CipherInit_ex(
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        engine: *mut ENGINE,
        key: *const uint8_t,
        iv: *const uint8_t,
        enc: libc::c_int,
    ) -> libc::c_int;
    fn EVP_CIPHER_nid(cipher: *const EVP_CIPHER) -> libc::c_int;
    fn EVP_CIPHER_key_length(cipher: *const EVP_CIPHER) -> libc::c_uint;
    fn EVP_CIPHER_iv_length(cipher: *const EVP_CIPHER) -> libc::c_uint;
    fn EVP_aes_192_cbc() -> *const EVP_CIPHER;
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_mem_equal(cbs: *const CBS, data: *const uint8_t, len: size_t) -> libc::c_int;
    fn CBS_get_asn1(
        cbs: *mut CBS,
        out: *mut CBS,
        tag_value: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBS_peek_asn1_tag(cbs: *const CBS, tag_value: CBS_ASN1_TAG) -> libc::c_int;
    fn CBS_get_asn1_uint64(cbs: *mut CBS, out: *mut uint64_t) -> libc::c_int;
    fn CBB_flush(cbb: *mut CBB) -> libc::c_int;
    fn CBB_add_asn1(
        cbb: *mut CBB,
        out_contents: *mut CBB,
        tag: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBB_add_bytes(cbb: *mut CBB, data: *const uint8_t, len: size_t) -> libc::c_int;
    fn CBB_add_asn1_uint64(cbb: *mut CBB, value: uint64_t) -> libc::c_int;
    fn EVP_sha1() -> *const EVP_MD;
    fn EVP_sha256() -> *const EVP_MD;
    fn pkcs12_iterations_acceptable(iterations: uint64_t) -> libc::c_int;
    fn RAND_bytes(buf: *mut uint8_t, len: size_t) -> libc::c_int;
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn PKCS5_PBKDF2_HMAC(
        password: *const libc::c_char,
        password_len: size_t,
        salt: *const uint8_t,
        salt_len: size_t,
        iterations: uint32_t,
        digest: *const EVP_MD,
        key_len: size_t,
        out_key: *mut uint8_t,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type CBS_ASN1_TAG = uint32_t;
pub type EVP_CIPHER = evp_cipher_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cbb_st {
    pub child: *mut CBB,
    pub is_child: libc::c_char,
    pub u: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub base: cbb_buffer_st,
    pub child: cbb_child_st,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct cbb_child_st {
    pub base: *mut cbb_buffer_st,
    pub offset: size_t,
    pub pending_len_len: uint8_t,
    #[bitfield(name = "pending_is_asn1", ty = "libc::c_uint", bits = "0..=0")]
    pub pending_is_asn1: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 6],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct cbb_buffer_st {
    pub buf: *mut uint8_t,
    pub len: size_t,
    pub cap: size_t,
    #[bitfield(name = "can_resize", ty = "libc::c_uint", bits = "0..=0")]
    #[bitfield(name = "error", ty = "libc::c_uint", bits = "1..=1")]
    pub can_resize_error: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
pub type CBB = cbb_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cbs_st {
    pub data: *const uint8_t,
    pub len: size_t,
}
pub type CBS = cbs_st;
pub type ENGINE = engine_st;
pub type EVP_MD = env_md_st;
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
pub type EVP_CIPHER_CTX = evp_cipher_ctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pbe_suite {
    pub pbe_nid: libc::c_int,
    pub oid: [uint8_t; 10],
    pub oid_len: uint8_t,
    pub cipher_func: Option::<unsafe extern "C" fn() -> *const EVP_CIPHER>,
    pub md_func: Option::<unsafe extern "C" fn() -> *const EVP_MD>,
    pub decrypt_init: Option::<
        unsafe extern "C" fn(
            *const pbe_suite,
            *mut EVP_CIPHER_CTX,
            *const libc::c_char,
            size_t,
            *mut CBS,
        ) -> libc::c_int,
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub oid: [uint8_t; 9],
    pub oid_len: uint8_t,
    pub nid: libc::c_int,
    pub cipher_func: Option::<unsafe extern "C" fn() -> *const EVP_CIPHER>,
}
static mut kPBKDF2: [uint8_t; 9] = [
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
];
static mut kPBES2: [uint8_t; 9] = [
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
];
static mut kHMACWithSHA1: [uint8_t; 8] = [
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
];
static mut kHMACWithSHA256: [uint8_t; 8] = [
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
];
static mut kCipherOIDs: [C2RustUnnamed_0; 5] = [
    {
        let mut init = C2RustUnnamed_0 {
            oid: [
                0x2a as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0xf7 as libc::c_int as uint8_t,
                0xd as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0x2 as libc::c_int as uint8_t,
                0,
            ],
            oid_len: 8 as libc::c_int as uint8_t,
            nid: 37 as libc::c_int,
            cipher_func: Some(EVP_rc2_cbc as unsafe extern "C" fn() -> *const EVP_CIPHER),
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            oid: [
                0x2a as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0xf7 as libc::c_int as uint8_t,
                0xd as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0x7 as libc::c_int as uint8_t,
                0,
            ],
            oid_len: 8 as libc::c_int as uint8_t,
            nid: 44 as libc::c_int,
            cipher_func: Some(
                EVP_des_ede3_cbc as unsafe extern "C" fn() -> *const EVP_CIPHER,
            ),
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            oid: [
                0x60 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x65 as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x2 as libc::c_int as uint8_t,
            ],
            oid_len: 9 as libc::c_int as uint8_t,
            nid: 419 as libc::c_int,
            cipher_func: Some(
                EVP_aes_128_cbc as unsafe extern "C" fn() -> *const EVP_CIPHER,
            ),
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            oid: [
                0x60 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x65 as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x16 as libc::c_int as uint8_t,
            ],
            oid_len: 9 as libc::c_int as uint8_t,
            nid: 423 as libc::c_int,
            cipher_func: Some(
                EVP_aes_192_cbc as unsafe extern "C" fn() -> *const EVP_CIPHER,
            ),
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            oid: [
                0x60 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x65 as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x2a as libc::c_int as uint8_t,
            ],
            oid_len: 9 as libc::c_int as uint8_t,
            nid: 427 as libc::c_int,
            cipher_func: Some(
                EVP_aes_256_cbc as unsafe extern "C" fn() -> *const EVP_CIPHER,
            ),
        };
        init
    },
];
unsafe extern "C" fn cbs_to_cipher(mut cbs: *const CBS) -> *const EVP_CIPHER {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (::core::mem::size_of::<[C2RustUnnamed_0; 5]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<C2RustUnnamed_0>() as libc::c_ulong)
    {
        if CBS_mem_equal(
            cbs,
            (kCipherOIDs[i as usize].oid).as_ptr(),
            kCipherOIDs[i as usize].oid_len as size_t,
        ) != 0
        {
            return (kCipherOIDs[i as usize].cipher_func)
                .expect("non-null function pointer")();
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as *const EVP_CIPHER;
}
unsafe extern "C" fn add_cipher_oid(
    mut out: *mut CBB,
    mut nid: libc::c_int,
) -> libc::c_int {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (::core::mem::size_of::<[C2RustUnnamed_0; 5]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<C2RustUnnamed_0>() as libc::c_ulong)
    {
        if kCipherOIDs[i as usize].nid == nid {
            let mut child: CBB = cbb_st {
                child: 0 as *mut CBB,
                is_child: 0,
                u: C2RustUnnamed {
                    base: cbb_buffer_st {
                        buf: 0 as *mut uint8_t,
                        len: 0,
                        cap: 0,
                        can_resize_error: [0; 1],
                        c2rust_padding: [0; 7],
                    },
                },
            };
            return (CBB_add_asn1(out, &mut child, 0x6 as libc::c_uint) != 0
                && CBB_add_bytes(
                    &mut child,
                    (kCipherOIDs[i as usize].oid).as_ptr(),
                    kCipherOIDs[i as usize].oid_len as size_t,
                ) != 0 && CBB_flush(out) != 0) as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    ERR_put_error(
        19 as libc::c_int,
        0 as libc::c_int,
        127 as libc::c_int,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/p5_pbev2.c\0" as *const u8
            as *const libc::c_char,
        142 as libc::c_int as libc::c_uint,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn pkcs5_pbe2_cipher_init(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut cipher: *const EVP_CIPHER,
    mut pbkdf2_md: *const EVP_MD,
    mut iterations: uint32_t,
    mut pass: *const libc::c_char,
    mut pass_len: size_t,
    mut salt: *const uint8_t,
    mut salt_len: size_t,
    mut iv: *const uint8_t,
    mut iv_len: size_t,
    mut enc: libc::c_int,
) -> libc::c_int {
    if iv_len != EVP_CIPHER_iv_length(cipher) as size_t {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            107 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/p5_pbev2.c\0" as *const u8
                as *const libc::c_char,
            152 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut key: [uint8_t; 64] = [0; 64];
    let mut ret: libc::c_int = (PKCS5_PBKDF2_HMAC(
        pass,
        pass_len,
        salt,
        salt_len,
        iterations,
        pbkdf2_md,
        EVP_CIPHER_key_length(cipher) as size_t,
        key.as_mut_ptr(),
    ) != 0
        && EVP_CipherInit_ex(ctx, cipher, 0 as *mut ENGINE, key.as_mut_ptr(), iv, enc)
            != 0) as libc::c_int;
    OPENSSL_cleanse(key.as_mut_ptr() as *mut libc::c_void, 64 as libc::c_int as size_t);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn PKCS5_pbe2_encrypt_init(
    mut out: *mut CBB,
    mut ctx: *mut EVP_CIPHER_CTX,
    mut cipher: *const EVP_CIPHER,
    mut iterations: uint32_t,
    mut pass: *const libc::c_char,
    mut pass_len: size_t,
    mut salt: *const uint8_t,
    mut salt_len: size_t,
) -> libc::c_int {
    let mut cipher_nid: libc::c_int = EVP_CIPHER_nid(cipher);
    if cipher_nid == 0 as libc::c_int {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/p5_pbev2.c\0" as *const u8
                as *const libc::c_char,
            170 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut iv: [uint8_t; 16] = [0; 16];
    if RAND_bytes(iv.as_mut_ptr(), EVP_CIPHER_iv_length(cipher) as size_t) == 0 {
        return 0 as libc::c_int;
    }
    let mut algorithm: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut oid: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut param: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut kdf: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut kdf_oid: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut kdf_param: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut salt_cbb: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut cipher_cbb: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut iv_cbb: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    if CBB_add_asn1(
        out,
        &mut algorithm,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || CBB_add_asn1(&mut algorithm, &mut oid, 0x6 as libc::c_uint) == 0
        || CBB_add_bytes(
            &mut oid,
            kPBES2.as_ptr(),
            ::core::mem::size_of::<[uint8_t; 9]>() as libc::c_ulong,
        ) == 0
        || CBB_add_asn1(
            &mut algorithm,
            &mut param,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0
        || CBB_add_asn1(
            &mut param,
            &mut kdf,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0 || CBB_add_asn1(&mut kdf, &mut kdf_oid, 0x6 as libc::c_uint) == 0
        || CBB_add_bytes(
            &mut kdf_oid,
            kPBKDF2.as_ptr(),
            ::core::mem::size_of::<[uint8_t; 9]>() as libc::c_ulong,
        ) == 0
        || CBB_add_asn1(
            &mut kdf,
            &mut kdf_param,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0 || CBB_add_asn1(&mut kdf_param, &mut salt_cbb, 0x4 as libc::c_uint) == 0
        || CBB_add_bytes(&mut salt_cbb, salt, salt_len) == 0
        || CBB_add_asn1_uint64(&mut kdf_param, iterations as uint64_t) == 0
        || cipher_nid == 37 as libc::c_int
            && CBB_add_asn1_uint64(
                &mut kdf_param,
                EVP_CIPHER_key_length(cipher) as uint64_t,
            ) == 0
        || CBB_add_asn1(
            &mut param,
            &mut cipher_cbb,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0 || add_cipher_oid(&mut cipher_cbb, cipher_nid) == 0
        || CBB_add_asn1(&mut cipher_cbb, &mut iv_cbb, 0x4 as libc::c_uint) == 0
        || CBB_add_bytes(
            &mut iv_cbb,
            iv.as_mut_ptr(),
            EVP_CIPHER_iv_length(cipher) as size_t,
        ) == 0 || CBB_flush(out) == 0
    {
        return 0 as libc::c_int;
    }
    return pkcs5_pbe2_cipher_init(
        ctx,
        cipher,
        EVP_sha1(),
        iterations,
        pass,
        pass_len,
        salt,
        salt_len,
        iv.as_mut_ptr(),
        EVP_CIPHER_iv_length(cipher) as size_t,
        1 as libc::c_int,
    );
}
#[no_mangle]
pub unsafe extern "C" fn PKCS5_pbe2_decrypt_init(
    mut suite: *const pbe_suite,
    mut ctx: *mut EVP_CIPHER_CTX,
    mut pass: *const libc::c_char,
    mut pass_len: size_t,
    mut param: *mut CBS,
) -> libc::c_int {
    let mut pbe_param: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut kdf: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut kdf_obj: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut enc_scheme: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut enc_obj: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_get_asn1(
        param,
        &mut pbe_param,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || CBS_len(param) != 0 as libc::c_int as size_t
        || CBS_get_asn1(
            &mut pbe_param,
            &mut kdf,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0
        || CBS_get_asn1(
            &mut pbe_param,
            &mut enc_scheme,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0 || CBS_len(&mut pbe_param) != 0 as libc::c_int as size_t
        || CBS_get_asn1(&mut kdf, &mut kdf_obj, 0x6 as libc::c_uint) == 0
        || CBS_get_asn1(&mut enc_scheme, &mut enc_obj, 0x6 as libc::c_uint) == 0
    {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/p5_pbev2.c\0" as *const u8
                as *const libc::c_char,
            223 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if CBS_mem_equal(
        &mut kdf_obj,
        kPBKDF2.as_ptr(),
        ::core::mem::size_of::<[uint8_t; 9]>() as libc::c_ulong,
    ) == 0
    {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            128 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/p5_pbev2.c\0" as *const u8
                as *const libc::c_char,
            229 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut cipher: *const EVP_CIPHER = cbs_to_cipher(&mut enc_obj);
    if cipher.is_null() {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            127 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/p5_pbev2.c\0" as *const u8
                as *const libc::c_char,
            236 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut pbkdf2_params: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut salt: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut iterations: uint64_t = 0;
    if CBS_get_asn1(
        &mut kdf,
        &mut pbkdf2_params,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || CBS_len(&mut kdf) != 0 as libc::c_int as size_t
        || CBS_get_asn1(&mut pbkdf2_params, &mut salt, 0x4 as libc::c_uint) == 0
        || CBS_get_asn1_uint64(&mut pbkdf2_params, &mut iterations) == 0
    {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/p5_pbev2.c\0" as *const u8
                as *const libc::c_char,
            247 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if pkcs12_iterations_acceptable(iterations) == 0 {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            129 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/p5_pbev2.c\0" as *const u8
                as *const libc::c_char,
            252 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if CBS_peek_asn1_tag(&mut pbkdf2_params, 0x2 as libc::c_uint) != 0 {
        let mut key_len: uint64_t = 0;
        if CBS_get_asn1_uint64(&mut pbkdf2_params, &mut key_len) == 0 {
            ERR_put_error(
                19 as libc::c_int,
                0 as libc::c_int,
                104 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/p5_pbev2.c\0"
                    as *const u8 as *const libc::c_char,
                261 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        if key_len != EVP_CIPHER_key_length(cipher) as uint64_t {
            ERR_put_error(
                19 as libc::c_int,
                0 as libc::c_int,
                125 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/p5_pbev2.c\0"
                    as *const u8 as *const libc::c_char,
                266 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    }
    let mut md: *const EVP_MD = EVP_sha1();
    if CBS_len(&mut pbkdf2_params) != 0 as libc::c_int as size_t {
        let mut alg_id: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        let mut prf: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        if CBS_get_asn1(
            &mut pbkdf2_params,
            &mut alg_id,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0 || CBS_get_asn1(&mut alg_id, &mut prf, 0x6 as libc::c_uint) == 0
            || CBS_len(&mut pbkdf2_params) != 0 as libc::c_int as size_t
        {
            ERR_put_error(
                19 as libc::c_int,
                0 as libc::c_int,
                104 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/p5_pbev2.c\0"
                    as *const u8 as *const libc::c_char,
                277 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        if CBS_mem_equal(
            &mut prf,
            kHMACWithSHA1.as_ptr(),
            ::core::mem::size_of::<[uint8_t; 8]>() as libc::c_ulong,
        ) != 0
        {
            md = EVP_sha1();
        } else if CBS_mem_equal(
            &mut prf,
            kHMACWithSHA256.as_ptr(),
            ::core::mem::size_of::<[uint8_t; 8]>() as libc::c_ulong,
        ) != 0
        {
            md = EVP_sha256();
        } else {
            ERR_put_error(
                19 as libc::c_int,
                0 as libc::c_int,
                130 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/p5_pbev2.c\0"
                    as *const u8 as *const libc::c_char,
                288 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        let mut null: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        if CBS_get_asn1(&mut alg_id, &mut null, 0x5 as libc::c_uint) == 0
            || CBS_len(&mut null) != 0 as libc::c_int as size_t
            || CBS_len(&mut alg_id) != 0 as libc::c_int as size_t
        {
            ERR_put_error(
                19 as libc::c_int,
                0 as libc::c_int,
                104 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/p5_pbev2.c\0"
                    as *const u8 as *const libc::c_char,
                297 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    }
    let mut iv: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_get_asn1(&mut enc_scheme, &mut iv, 0x4 as libc::c_uint) == 0
        || CBS_len(&mut enc_scheme) != 0 as libc::c_int as size_t
    {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            130 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/p5_pbev2.c\0" as *const u8
                as *const libc::c_char,
            309 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return pkcs5_pbe2_cipher_init(
        ctx,
        cipher,
        md,
        iterations as uint32_t,
        pass,
        pass_len,
        CBS_data(&mut salt),
        CBS_len(&mut salt),
        CBS_data(&mut iv),
        CBS_len(&mut iv),
        0 as libc::c_int,
    );
}
