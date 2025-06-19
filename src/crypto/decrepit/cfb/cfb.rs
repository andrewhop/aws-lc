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
    fn AES_set_encrypt_key(
        key: *const uint8_t,
        bits: libc::c_uint,
        aeskey: *mut AES_KEY,
    ) -> libc::c_int;
    fn AES_cfb1_encrypt(
        in_0: *const uint8_t,
        out: *mut uint8_t,
        bits: size_t,
        key: *const AES_KEY,
        ivec: *mut uint8_t,
        num: *mut libc::c_int,
        enc: libc::c_int,
    );
    fn AES_cfb8_encrypt(
        in_0: *const uint8_t,
        out: *mut uint8_t,
        len: size_t,
        key: *const AES_KEY,
        ivec: *mut uint8_t,
        num: *mut libc::c_int,
        enc: libc::c_int,
    );
    fn AES_cfb128_encrypt(
        in_0: *const uint8_t,
        out: *mut uint8_t,
        len: size_t,
        key: *const AES_KEY,
        ivec: *mut uint8_t,
        num: *mut libc::c_int,
        enc: libc::c_int,
    );
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
pub type AES_KEY = aes_key_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct aes_key_st {
    pub rd_key: [uint32_t; 60],
    pub rounds: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EVP_CFB_CTX {
    pub ks: AES_KEY,
}
unsafe extern "C" fn aes_cfb_init_key(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut key: *const uint8_t,
    mut iv: *const uint8_t,
    mut enc: libc::c_int,
) -> libc::c_int {
    if !key.is_null() {
        let mut cfb_ctx: *mut EVP_CFB_CTX = (*ctx).cipher_data as *mut EVP_CFB_CTX;
        AES_set_encrypt_key(
            key,
            ((*ctx).key_len).wrapping_mul(8 as libc::c_int as libc::c_uint),
            &mut (*cfb_ctx).ks,
        );
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn aes_cfb1_cipher(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    if out.is_null() || in_0.is_null() {
        return 0 as libc::c_int;
    }
    let mut cfb_ctx: *mut EVP_CFB_CTX = (*ctx).cipher_data as *mut EVP_CFB_CTX;
    if (*ctx).flags & 0x2000 as libc::c_int as uint32_t != 0 {
        let mut num: libc::c_int = (*ctx).num as libc::c_int;
        AES_cfb1_encrypt(
            in_0,
            out,
            len,
            &mut (*cfb_ctx).ks,
            ((*ctx).iv).as_mut_ptr(),
            &mut num,
            if (*ctx).encrypt != 0 { 1 as libc::c_int } else { 0 as libc::c_int },
        );
        (*ctx).num = num as libc::c_uint;
        return 1 as libc::c_int;
    }
    while len
        >= (1 as libc::c_int as size_t)
            << (::core::mem::size_of::<size_t>() as libc::c_ulong)
                .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                .wrapping_sub(4 as libc::c_int as libc::c_ulong)
    {
        let mut num_0: libc::c_int = (*ctx).num as libc::c_int;
        AES_cfb1_encrypt(
            in_0,
            out,
            ((1 as libc::c_int as size_t)
                << (::core::mem::size_of::<size_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                    .wrapping_sub(4 as libc::c_int as libc::c_ulong))
                * 8 as libc::c_int as size_t,
            &mut (*cfb_ctx).ks,
            ((*ctx).iv).as_mut_ptr(),
            &mut num_0,
            if (*ctx).encrypt != 0 { 1 as libc::c_int } else { 0 as libc::c_int },
        );
        (*ctx).num = num_0 as libc::c_uint;
        len = len
            .wrapping_sub(
                (1 as libc::c_int as size_t)
                    << (::core::mem::size_of::<size_t>() as libc::c_ulong)
                        .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                        .wrapping_sub(4 as libc::c_int as libc::c_ulong),
            );
        out = out
            .offset(
                ((1 as libc::c_int as size_t)
                    << (::core::mem::size_of::<size_t>() as libc::c_ulong)
                        .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                        .wrapping_sub(4 as libc::c_int as libc::c_ulong)) as isize,
            );
        in_0 = in_0
            .offset(
                ((1 as libc::c_int as size_t)
                    << (::core::mem::size_of::<size_t>() as libc::c_ulong)
                        .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                        .wrapping_sub(4 as libc::c_int as libc::c_ulong)) as isize,
            );
    }
    if len != 0 {
        let mut num_1: libc::c_int = (*ctx).num as libc::c_int;
        AES_cfb1_encrypt(
            in_0,
            out,
            len * 8 as libc::c_int as size_t,
            &mut (*cfb_ctx).ks,
            ((*ctx).iv).as_mut_ptr(),
            &mut num_1,
            if (*ctx).encrypt != 0 { 1 as libc::c_int } else { 0 as libc::c_int },
        );
        (*ctx).num = num_1 as libc::c_uint;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn aes_cfb8_cipher(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    if out.is_null() || in_0.is_null() {
        return 0 as libc::c_int;
    }
    let mut cfb_ctx: *mut EVP_CFB_CTX = (*ctx).cipher_data as *mut EVP_CFB_CTX;
    let mut num: libc::c_int = (*ctx).num as libc::c_int;
    AES_cfb8_encrypt(
        in_0,
        out,
        len,
        &mut (*cfb_ctx).ks,
        ((*ctx).iv).as_mut_ptr(),
        &mut num,
        if (*ctx).encrypt != 0 { 1 as libc::c_int } else { 0 as libc::c_int },
    );
    (*ctx).num = num as libc::c_uint;
    return 1 as libc::c_int;
}
unsafe extern "C" fn aes_cfb128_cipher(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    if out.is_null() || in_0.is_null() {
        return 0 as libc::c_int;
    }
    let mut cfb_ctx: *mut EVP_CFB_CTX = (*ctx).cipher_data as *mut EVP_CFB_CTX;
    let mut num: libc::c_int = (*ctx).num as libc::c_int;
    AES_cfb128_encrypt(
        in_0,
        out,
        len,
        &mut (*cfb_ctx).ks,
        ((*ctx).iv).as_mut_ptr(),
        &mut num,
        if (*ctx).encrypt != 0 { 1 as libc::c_int } else { 0 as libc::c_int },
    );
    (*ctx).num = num as libc::c_uint;
    return 1 as libc::c_int;
}
static mut aes_128_cfb1: EVP_CIPHER = unsafe {
    {
        let mut init = evp_cipher_st {
            nid: 650 as libc::c_int,
            block_size: 1 as libc::c_int as libc::c_uint,
            key_len: 16 as libc::c_int as libc::c_uint,
            iv_len: 16 as libc::c_int as libc::c_uint,
            ctx_size: ::core::mem::size_of::<EVP_CFB_CTX>() as libc::c_ulong
                as libc::c_uint,
            flags: 0x3 as libc::c_int as uint32_t,
            init: Some(
                aes_cfb_init_key
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *const uint8_t,
                        *const uint8_t,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            cipher: Some(
                aes_cfb1_cipher
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
static mut aes_128_cfb8: EVP_CIPHER = unsafe {
    {
        let mut init = evp_cipher_st {
            nid: 653 as libc::c_int,
            block_size: 1 as libc::c_int as libc::c_uint,
            key_len: 16 as libc::c_int as libc::c_uint,
            iv_len: 16 as libc::c_int as libc::c_uint,
            ctx_size: ::core::mem::size_of::<EVP_CFB_CTX>() as libc::c_ulong
                as libc::c_uint,
            flags: 0x3 as libc::c_int as uint32_t,
            init: Some(
                aes_cfb_init_key
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *const uint8_t,
                        *const uint8_t,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            cipher: Some(
                aes_cfb8_cipher
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
static mut aes_128_cfb128: EVP_CIPHER = unsafe {
    {
        let mut init = evp_cipher_st {
            nid: 421 as libc::c_int,
            block_size: 1 as libc::c_int as libc::c_uint,
            key_len: 16 as libc::c_int as libc::c_uint,
            iv_len: 16 as libc::c_int as libc::c_uint,
            ctx_size: ::core::mem::size_of::<EVP_CFB_CTX>() as libc::c_ulong
                as libc::c_uint,
            flags: 0x3 as libc::c_int as uint32_t,
            init: Some(
                aes_cfb_init_key
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *const uint8_t,
                        *const uint8_t,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            cipher: Some(
                aes_cfb128_cipher
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
static mut aes_192_cfb1: EVP_CIPHER = unsafe {
    {
        let mut init = evp_cipher_st {
            nid: 651 as libc::c_int,
            block_size: 1 as libc::c_int as libc::c_uint,
            key_len: 24 as libc::c_int as libc::c_uint,
            iv_len: 16 as libc::c_int as libc::c_uint,
            ctx_size: ::core::mem::size_of::<EVP_CFB_CTX>() as libc::c_ulong
                as libc::c_uint,
            flags: 0x3 as libc::c_int as uint32_t,
            init: Some(
                aes_cfb_init_key
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *const uint8_t,
                        *const uint8_t,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            cipher: Some(
                aes_cfb1_cipher
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
static mut aes_192_cfb8: EVP_CIPHER = unsafe {
    {
        let mut init = evp_cipher_st {
            nid: 654 as libc::c_int,
            block_size: 1 as libc::c_int as libc::c_uint,
            key_len: 24 as libc::c_int as libc::c_uint,
            iv_len: 16 as libc::c_int as libc::c_uint,
            ctx_size: ::core::mem::size_of::<EVP_CFB_CTX>() as libc::c_ulong
                as libc::c_uint,
            flags: 0x3 as libc::c_int as uint32_t,
            init: Some(
                aes_cfb_init_key
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *const uint8_t,
                        *const uint8_t,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            cipher: Some(
                aes_cfb8_cipher
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
static mut aes_192_cfb128: EVP_CIPHER = unsafe {
    {
        let mut init = evp_cipher_st {
            nid: 425 as libc::c_int,
            block_size: 1 as libc::c_int as libc::c_uint,
            key_len: 24 as libc::c_int as libc::c_uint,
            iv_len: 16 as libc::c_int as libc::c_uint,
            ctx_size: ::core::mem::size_of::<EVP_CFB_CTX>() as libc::c_ulong
                as libc::c_uint,
            flags: 0x3 as libc::c_int as uint32_t,
            init: Some(
                aes_cfb_init_key
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *const uint8_t,
                        *const uint8_t,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            cipher: Some(
                aes_cfb128_cipher
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
static mut aes_256_cfb1: EVP_CIPHER = unsafe {
    {
        let mut init = evp_cipher_st {
            nid: 652 as libc::c_int,
            block_size: 1 as libc::c_int as libc::c_uint,
            key_len: 32 as libc::c_int as libc::c_uint,
            iv_len: 16 as libc::c_int as libc::c_uint,
            ctx_size: ::core::mem::size_of::<EVP_CFB_CTX>() as libc::c_ulong
                as libc::c_uint,
            flags: 0x3 as libc::c_int as uint32_t,
            init: Some(
                aes_cfb_init_key
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *const uint8_t,
                        *const uint8_t,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            cipher: Some(
                aes_cfb1_cipher
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
static mut aes_256_cfb8: EVP_CIPHER = unsafe {
    {
        let mut init = evp_cipher_st {
            nid: 655 as libc::c_int,
            block_size: 1 as libc::c_int as libc::c_uint,
            key_len: 32 as libc::c_int as libc::c_uint,
            iv_len: 16 as libc::c_int as libc::c_uint,
            ctx_size: ::core::mem::size_of::<EVP_CFB_CTX>() as libc::c_ulong
                as libc::c_uint,
            flags: 0x3 as libc::c_int as uint32_t,
            init: Some(
                aes_cfb_init_key
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *const uint8_t,
                        *const uint8_t,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            cipher: Some(
                aes_cfb8_cipher
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
static mut aes_256_cfb128: EVP_CIPHER = unsafe {
    {
        let mut init = evp_cipher_st {
            nid: 429 as libc::c_int,
            block_size: 1 as libc::c_int as libc::c_uint,
            key_len: 32 as libc::c_int as libc::c_uint,
            iv_len: 16 as libc::c_int as libc::c_uint,
            ctx_size: ::core::mem::size_of::<EVP_CFB_CTX>() as libc::c_ulong
                as libc::c_uint,
            flags: 0x3 as libc::c_int as uint32_t,
            init: Some(
                aes_cfb_init_key
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *const uint8_t,
                        *const uint8_t,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            cipher: Some(
                aes_cfb128_cipher
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
pub unsafe extern "C" fn EVP_aes_128_cfb1() -> *const EVP_CIPHER {
    return &aes_128_cfb1;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_128_cfb8() -> *const EVP_CIPHER {
    return &aes_128_cfb8;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_128_cfb128() -> *const EVP_CIPHER {
    return &aes_128_cfb128;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_128_cfb() -> *const EVP_CIPHER {
    return &aes_128_cfb128;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_192_cfb1() -> *const EVP_CIPHER {
    return &aes_192_cfb1;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_192_cfb8() -> *const EVP_CIPHER {
    return &aes_192_cfb8;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_192_cfb128() -> *const EVP_CIPHER {
    return &aes_192_cfb128;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_192_cfb() -> *const EVP_CIPHER {
    return &aes_192_cfb128;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_256_cfb1() -> *const EVP_CIPHER {
    return &aes_256_cfb1;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_256_cfb8() -> *const EVP_CIPHER {
    return &aes_256_cfb8;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_256_cfb128() -> *const EVP_CIPHER {
    return &aes_256_cfb128;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_aes_256_cfb() -> *const EVP_CIPHER {
    return &aes_256_cfb128;
}
