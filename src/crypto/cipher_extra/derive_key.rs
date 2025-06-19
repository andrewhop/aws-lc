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
    pub type engine_st;
    pub type evp_md_pctx_ops;
    pub type evp_pkey_ctx_st;
    pub type env_md_st;
    pub type evp_cipher_st;
    fn EVP_MD_CTX_init(ctx: *mut EVP_MD_CTX);
    fn EVP_MD_CTX_cleanup(ctx: *mut EVP_MD_CTX) -> libc::c_int;
    fn EVP_DigestInit_ex(
        ctx: *mut EVP_MD_CTX,
        type_0: *const EVP_MD,
        engine: *mut ENGINE,
    ) -> libc::c_int;
    fn EVP_DigestUpdate(
        ctx: *mut EVP_MD_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn EVP_DigestFinal_ex(
        ctx: *mut EVP_MD_CTX,
        md_out: *mut uint8_t,
        out_size: *mut libc::c_uint,
    ) -> libc::c_int;
    fn EVP_CIPHER_key_length(cipher: *const EVP_CIPHER) -> libc::c_uint;
    fn EVP_CIPHER_iv_length(cipher: *const EVP_CIPHER) -> libc::c_uint;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type uint8_t = __uint8_t;
pub type ENGINE = engine_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct env_md_ctx_st {
    pub digest: *const EVP_MD,
    pub md_data: *mut libc::c_void,
    pub update: Option::<
        unsafe extern "C" fn(*mut EVP_MD_CTX, *const libc::c_void, size_t) -> libc::c_int,
    >,
    pub pctx: *mut EVP_PKEY_CTX,
    pub pctx_ops: *const evp_md_pctx_ops,
    pub flags: libc::c_ulong,
}
pub type EVP_PKEY_CTX = evp_pkey_ctx_st;
pub type EVP_MD_CTX = env_md_ctx_st;
pub type EVP_MD = env_md_st;
pub type EVP_CIPHER = evp_cipher_st;
#[no_mangle]
pub unsafe extern "C" fn EVP_BytesToKey(
    mut type_0: *const EVP_CIPHER,
    mut md: *const EVP_MD,
    mut salt: *const uint8_t,
    mut data: *const uint8_t,
    mut data_len: size_t,
    mut count: libc::c_uint,
    mut key: *mut uint8_t,
    mut iv: *mut uint8_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut c: EVP_MD_CTX = env_md_ctx_st {
        digest: 0 as *const EVP_MD,
        md_data: 0 as *mut libc::c_void,
        update: None,
        pctx: 0 as *mut EVP_PKEY_CTX,
        pctx_ops: 0 as *const evp_md_pctx_ops,
        flags: 0,
    };
    let mut md_buf: [uint8_t; 64] = [0; 64];
    let mut addmd: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut mds: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut i: libc::c_uint = 0;
    let mut rv: libc::c_int = 0 as libc::c_int;
    let mut nkey: libc::c_uint = EVP_CIPHER_key_length(type_0);
    let mut niv: libc::c_uint = EVP_CIPHER_iv_length(type_0);
    if nkey <= 64 as libc::c_int as libc::c_uint {} else {
        __assert_fail(
            b"nkey <= EVP_MAX_KEY_LENGTH\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/derive_key.c\0"
                as *const u8 as *const libc::c_char,
            78 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 133],
                &[libc::c_char; 133],
            >(
                b"int EVP_BytesToKey(const EVP_CIPHER *, const EVP_MD *, const uint8_t *, const uint8_t *, size_t, unsigned int, uint8_t *, uint8_t *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2117: {
        if nkey <= 64 as libc::c_int as libc::c_uint {} else {
            __assert_fail(
                b"nkey <= EVP_MAX_KEY_LENGTH\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/derive_key.c\0"
                    as *const u8 as *const libc::c_char,
                78 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 133],
                    &[libc::c_char; 133],
                >(
                    b"int EVP_BytesToKey(const EVP_CIPHER *, const EVP_MD *, const uint8_t *, const uint8_t *, size_t, unsigned int, uint8_t *, uint8_t *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if niv <= 16 as libc::c_int as libc::c_uint {} else {
        __assert_fail(
            b"niv <= EVP_MAX_IV_LENGTH\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/derive_key.c\0"
                as *const u8 as *const libc::c_char,
            79 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 133],
                &[libc::c_char; 133],
            >(
                b"int EVP_BytesToKey(const EVP_CIPHER *, const EVP_MD *, const uint8_t *, const uint8_t *, size_t, unsigned int, uint8_t *, uint8_t *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2068: {
        if niv <= 16 as libc::c_int as libc::c_uint {} else {
            __assert_fail(
                b"niv <= EVP_MAX_IV_LENGTH\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/cipher_extra/derive_key.c\0"
                    as *const u8 as *const libc::c_char,
                79 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 133],
                    &[libc::c_char; 133],
                >(
                    b"int EVP_BytesToKey(const EVP_CIPHER *, const EVP_MD *, const uint8_t *, const uint8_t *, size_t, unsigned int, uint8_t *, uint8_t *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if data.is_null() {
        return nkey as libc::c_int;
    }
    EVP_MD_CTX_init(&mut c);
    's_39: loop {
        if EVP_DigestInit_ex(&mut c, md, 0 as *mut ENGINE) == 0 {
            current_block = 12543790739860065331;
            break;
        }
        let fresh0 = addmd;
        addmd = addmd.wrapping_add(1);
        if fresh0 != 0 {
            if EVP_DigestUpdate(
                &mut c,
                md_buf.as_mut_ptr() as *const libc::c_void,
                mds as size_t,
            ) == 0
            {
                current_block = 12543790739860065331;
                break;
            }
        }
        if EVP_DigestUpdate(&mut c, data as *const libc::c_void, data_len) == 0 {
            current_block = 12543790739860065331;
            break;
        }
        if !salt.is_null() {
            if EVP_DigestUpdate(
                &mut c,
                salt as *const libc::c_void,
                8 as libc::c_int as size_t,
            ) == 0
            {
                current_block = 12543790739860065331;
                break;
            }
        }
        if EVP_DigestFinal_ex(&mut c, md_buf.as_mut_ptr(), &mut mds) == 0 {
            current_block = 12543790739860065331;
            break;
        }
        i = 1 as libc::c_int as libc::c_uint;
        while i < count {
            if EVP_DigestInit_ex(&mut c, md, 0 as *mut ENGINE) == 0
                || EVP_DigestUpdate(
                    &mut c,
                    md_buf.as_mut_ptr() as *const libc::c_void,
                    mds as size_t,
                ) == 0 || EVP_DigestFinal_ex(&mut c, md_buf.as_mut_ptr(), &mut mds) == 0
            {
                current_block = 12543790739860065331;
                break 's_39;
            }
            i = i.wrapping_add(1);
            i;
        }
        i = 0 as libc::c_int as libc::c_uint;
        if nkey != 0 {
            while !(nkey == 0 as libc::c_int as libc::c_uint || i == mds) {
                if !key.is_null() {
                    let fresh1 = key;
                    key = key.offset(1);
                    *fresh1 = md_buf[i as usize];
                }
                nkey = nkey.wrapping_sub(1);
                nkey;
                i = i.wrapping_add(1);
                i;
            }
        }
        if niv != 0 && i != mds {
            while !(niv == 0 as libc::c_int as libc::c_uint || i == mds) {
                if !iv.is_null() {
                    let fresh2 = iv;
                    iv = iv.offset(1);
                    *fresh2 = md_buf[i as usize];
                }
                niv = niv.wrapping_sub(1);
                niv;
                i = i.wrapping_add(1);
                i;
            }
        }
        if nkey == 0 as libc::c_int as libc::c_uint
            && niv == 0 as libc::c_int as libc::c_uint
        {
            current_block = 5330834795799507926;
            break;
        }
    }
    match current_block {
        5330834795799507926 => {
            rv = EVP_CIPHER_key_length(type_0) as libc::c_int;
        }
        _ => {}
    }
    EVP_MD_CTX_cleanup(&mut c);
    OPENSSL_cleanse(
        md_buf.as_mut_ptr() as *mut libc::c_void,
        64 as libc::c_int as size_t,
    );
    return rv;
}
