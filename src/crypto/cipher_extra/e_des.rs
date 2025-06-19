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
    fn DES_set_key_ex(key: *const uint8_t, schedule: *mut DES_key_schedule);
    fn DES_ecb_encrypt_ex(
        in_0: *const uint8_t,
        out: *mut uint8_t,
        schedule: *const DES_key_schedule,
        is_encrypt: libc::c_int,
    );
    fn DES_ncbc_encrypt_ex(
        in_0: *const uint8_t,
        out: *mut uint8_t,
        len: size_t,
        schedule: *const DES_key_schedule,
        ivec: *mut uint8_t,
        enc: libc::c_int,
    );
    fn DES_ecb3_encrypt_ex(
        input: *const uint8_t,
        output: *mut uint8_t,
        ks1: *const DES_key_schedule,
        ks2: *const DES_key_schedule,
        ks3: *const DES_key_schedule,
        enc: libc::c_int,
    );
    fn DES_ede3_cbc_encrypt_ex(
        in_0: *const uint8_t,
        out: *mut uint8_t,
        len: size_t,
        ks1: *const DES_key_schedule,
        ks2: *const DES_key_schedule,
        ks3: *const DES_key_schedule,
        ivec: *mut uint8_t,
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
pub type DES_key_schedule = DES_ks;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct DES_ks {
    pub subkeys: [[uint32_t; 2]; 16],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub align: libc::c_double,
    pub ks: DES_key_schedule,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EVP_DES_KEY {
    pub ks: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub align: libc::c_double,
    pub ks: [DES_key_schedule; 3],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct DES_EDE_KEY {
    pub ks: C2RustUnnamed_0,
}
unsafe extern "C" fn des_init_key(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut key: *const uint8_t,
    mut iv: *const uint8_t,
    mut enc: libc::c_int,
) -> libc::c_int {
    let mut dat: *mut EVP_DES_KEY = (*ctx).cipher_data as *mut EVP_DES_KEY;
    DES_set_key_ex(key, &mut (*dat).ks.ks);
    return 1 as libc::c_int;
}
unsafe extern "C" fn des_cbc_cipher(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
) -> libc::c_int {
    let mut dat: *mut EVP_DES_KEY = (*ctx).cipher_data as *mut EVP_DES_KEY;
    DES_ncbc_encrypt_ex(
        in_0,
        out,
        in_len,
        &mut (*dat).ks.ks,
        ((*ctx).iv).as_mut_ptr(),
        (*ctx).encrypt,
    );
    return 1 as libc::c_int;
}
static mut evp_des_cbc: EVP_CIPHER = unsafe {
    {
        let mut init = evp_cipher_st {
            nid: 31 as libc::c_int,
            block_size: 8 as libc::c_int as libc::c_uint,
            key_len: 8 as libc::c_int as libc::c_uint,
            iv_len: 8 as libc::c_int as libc::c_uint,
            ctx_size: ::core::mem::size_of::<EVP_DES_KEY>() as libc::c_ulong
                as libc::c_uint,
            flags: 0x2 as libc::c_int as uint32_t,
            init: Some(
                des_init_key
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *const uint8_t,
                        *const uint8_t,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            cipher: Some(
                des_cbc_cipher
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
pub unsafe extern "C" fn EVP_des_cbc() -> *const EVP_CIPHER {
    return &evp_des_cbc;
}
unsafe extern "C" fn des_ecb_cipher(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
) -> libc::c_int {
    if in_len < (*(*ctx).cipher).block_size as size_t {
        return 1 as libc::c_int;
    }
    in_len = in_len.wrapping_sub((*(*ctx).cipher).block_size as size_t);
    let mut dat: *mut EVP_DES_KEY = (*ctx).cipher_data as *mut EVP_DES_KEY;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i <= in_len {
        DES_ecb_encrypt_ex(
            in_0.offset(i as isize),
            out.offset(i as isize),
            &mut (*dat).ks.ks,
            (*ctx).encrypt,
        );
        i = i.wrapping_add((*(*ctx).cipher).block_size as size_t);
    }
    return 1 as libc::c_int;
}
static mut evp_des_ecb: EVP_CIPHER = unsafe {
    {
        let mut init = evp_cipher_st {
            nid: 29 as libc::c_int,
            block_size: 8 as libc::c_int as libc::c_uint,
            key_len: 8 as libc::c_int as libc::c_uint,
            iv_len: 0 as libc::c_int as libc::c_uint,
            ctx_size: ::core::mem::size_of::<EVP_DES_KEY>() as libc::c_ulong
                as libc::c_uint,
            flags: 0x1 as libc::c_int as uint32_t,
            init: Some(
                des_init_key
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *const uint8_t,
                        *const uint8_t,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            cipher: Some(
                des_ecb_cipher
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
pub unsafe extern "C" fn EVP_des_ecb() -> *const EVP_CIPHER {
    return &evp_des_ecb;
}
unsafe extern "C" fn des_ede3_init_key(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut key: *const uint8_t,
    mut iv: *const uint8_t,
    mut enc: libc::c_int,
) -> libc::c_int {
    let mut dat: *mut DES_EDE_KEY = (*ctx).cipher_data as *mut DES_EDE_KEY;
    DES_set_key_ex(
        key,
        &mut *((*dat).ks.ks).as_mut_ptr().offset(0 as libc::c_int as isize),
    );
    DES_set_key_ex(
        key.offset(8 as libc::c_int as isize),
        &mut *((*dat).ks.ks).as_mut_ptr().offset(1 as libc::c_int as isize),
    );
    DES_set_key_ex(
        key.offset(16 as libc::c_int as isize),
        &mut *((*dat).ks.ks).as_mut_ptr().offset(2 as libc::c_int as isize),
    );
    return 1 as libc::c_int;
}
unsafe extern "C" fn des_ede3_cbc_cipher(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
) -> libc::c_int {
    let mut dat: *mut DES_EDE_KEY = (*ctx).cipher_data as *mut DES_EDE_KEY;
    DES_ede3_cbc_encrypt_ex(
        in_0,
        out,
        in_len,
        &mut *((*dat).ks.ks).as_mut_ptr().offset(0 as libc::c_int as isize),
        &mut *((*dat).ks.ks).as_mut_ptr().offset(1 as libc::c_int as isize),
        &mut *((*dat).ks.ks).as_mut_ptr().offset(2 as libc::c_int as isize),
        ((*ctx).iv).as_mut_ptr(),
        (*ctx).encrypt,
    );
    return 1 as libc::c_int;
}
static mut evp_des_ede3_cbc: EVP_CIPHER = unsafe {
    {
        let mut init = evp_cipher_st {
            nid: 44 as libc::c_int,
            block_size: 8 as libc::c_int as libc::c_uint,
            key_len: 24 as libc::c_int as libc::c_uint,
            iv_len: 8 as libc::c_int as libc::c_uint,
            ctx_size: ::core::mem::size_of::<DES_EDE_KEY>() as libc::c_ulong
                as libc::c_uint,
            flags: 0x2 as libc::c_int as uint32_t,
            init: Some(
                des_ede3_init_key
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *const uint8_t,
                        *const uint8_t,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            cipher: Some(
                des_ede3_cbc_cipher
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
pub unsafe extern "C" fn EVP_des_ede3_cbc() -> *const EVP_CIPHER {
    return &evp_des_ede3_cbc;
}
unsafe extern "C" fn des_ede_init_key(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut key: *const uint8_t,
    mut iv: *const uint8_t,
    mut enc: libc::c_int,
) -> libc::c_int {
    let mut dat: *mut DES_EDE_KEY = (*ctx).cipher_data as *mut DES_EDE_KEY;
    DES_set_key_ex(
        key,
        &mut *((*dat).ks.ks).as_mut_ptr().offset(0 as libc::c_int as isize),
    );
    DES_set_key_ex(
        key.offset(8 as libc::c_int as isize),
        &mut *((*dat).ks.ks).as_mut_ptr().offset(1 as libc::c_int as isize),
    );
    DES_set_key_ex(
        key,
        &mut *((*dat).ks.ks).as_mut_ptr().offset(2 as libc::c_int as isize),
    );
    return 1 as libc::c_int;
}
static mut evp_des_ede_cbc: EVP_CIPHER = unsafe {
    {
        let mut init = evp_cipher_st {
            nid: 43 as libc::c_int,
            block_size: 8 as libc::c_int as libc::c_uint,
            key_len: 16 as libc::c_int as libc::c_uint,
            iv_len: 8 as libc::c_int as libc::c_uint,
            ctx_size: ::core::mem::size_of::<DES_EDE_KEY>() as libc::c_ulong
                as libc::c_uint,
            flags: 0x2 as libc::c_int as uint32_t,
            init: Some(
                des_ede_init_key
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *const uint8_t,
                        *const uint8_t,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            cipher: Some(
                des_ede3_cbc_cipher
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
pub unsafe extern "C" fn EVP_des_ede_cbc() -> *const EVP_CIPHER {
    return &evp_des_ede_cbc;
}
unsafe extern "C" fn des_ede_ecb_cipher(
    mut ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
) -> libc::c_int {
    if in_len < (*(*ctx).cipher).block_size as size_t {
        return 1 as libc::c_int;
    }
    in_len = in_len.wrapping_sub((*(*ctx).cipher).block_size as size_t);
    let mut dat: *mut DES_EDE_KEY = (*ctx).cipher_data as *mut DES_EDE_KEY;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i <= in_len {
        DES_ecb3_encrypt_ex(
            in_0.offset(i as isize),
            out.offset(i as isize),
            &mut *((*dat).ks.ks).as_mut_ptr().offset(0 as libc::c_int as isize),
            &mut *((*dat).ks.ks).as_mut_ptr().offset(1 as libc::c_int as isize),
            &mut *((*dat).ks.ks).as_mut_ptr().offset(2 as libc::c_int as isize),
            (*ctx).encrypt,
        );
        i = i.wrapping_add((*(*ctx).cipher).block_size as size_t);
    }
    return 1 as libc::c_int;
}
static mut evp_des_ede: EVP_CIPHER = unsafe {
    {
        let mut init = evp_cipher_st {
            nid: 32 as libc::c_int,
            block_size: 8 as libc::c_int as libc::c_uint,
            key_len: 16 as libc::c_int as libc::c_uint,
            iv_len: 0 as libc::c_int as libc::c_uint,
            ctx_size: ::core::mem::size_of::<DES_EDE_KEY>() as libc::c_ulong
                as libc::c_uint,
            flags: 0x1 as libc::c_int as uint32_t,
            init: Some(
                des_ede_init_key
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *const uint8_t,
                        *const uint8_t,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            cipher: Some(
                des_ede_ecb_cipher
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
pub unsafe extern "C" fn EVP_des_ede() -> *const EVP_CIPHER {
    return &evp_des_ede;
}
static mut evp_des_ede3: EVP_CIPHER = unsafe {
    {
        let mut init = evp_cipher_st {
            nid: 33 as libc::c_int,
            block_size: 8 as libc::c_int as libc::c_uint,
            key_len: 24 as libc::c_int as libc::c_uint,
            iv_len: 0 as libc::c_int as libc::c_uint,
            ctx_size: ::core::mem::size_of::<DES_EDE_KEY>() as libc::c_ulong
                as libc::c_uint,
            flags: 0x1 as libc::c_int as uint32_t,
            init: Some(
                des_ede3_init_key
                    as unsafe extern "C" fn(
                        *mut EVP_CIPHER_CTX,
                        *const uint8_t,
                        *const uint8_t,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            cipher: Some(
                des_ede_ecb_cipher
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
pub unsafe extern "C" fn EVP_des_ede3() -> *const EVP_CIPHER {
    return &evp_des_ede3;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_des_ede3_ecb() -> *const EVP_CIPHER {
    return EVP_des_ede3();
}
