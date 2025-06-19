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
    pub type engine_st;
    pub type env_md_st;
    pub type hmac_methods_st;
    fn EVP_sha1() -> *const EVP_MD;
    fn EVP_MD_size(md: *const EVP_MD) -> size_t;
    fn HMAC_CTX_init(ctx: *mut HMAC_CTX);
    fn HMAC_CTX_cleanup(ctx: *mut HMAC_CTX);
    fn HMAC_Init_ex(
        ctx: *mut HMAC_CTX,
        key: *const libc::c_void,
        key_len: size_t,
        md: *const EVP_MD,
        impl_0: *mut ENGINE,
    ) -> libc::c_int;
    fn HMAC_Update(
        ctx: *mut HMAC_CTX,
        data: *const uint8_t,
        data_len: size_t,
    ) -> libc::c_int;
    fn HMAC_Final(
        ctx: *mut HMAC_CTX,
        out: *mut uint8_t,
        out_len: *mut libc::c_uint,
    ) -> libc::c_int;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
}
pub type size_t = libc::c_ulong;
pub type __int8_t = libc::c_schar;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type int8_t = __int8_t;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type ENGINE = engine_st;
pub type EVP_MD = env_md_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hmac_ctx_st {
    pub md: *const EVP_MD,
    pub methods: *const HmacMethods,
    pub md_ctx: md_ctx_union,
    pub i_ctx: md_ctx_union,
    pub o_ctx: md_ctx_union,
    pub state: int8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union md_ctx_union {
    pub md5: MD5_CTX,
    pub sha1: SHA_CTX,
    pub sha256: SHA256_CTX,
    pub sha512: SHA512_CTX,
}
pub type SHA512_CTX = sha512_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sha512_state_st {
    pub h: [uint64_t; 8],
    pub Nl: uint64_t,
    pub Nh: uint64_t,
    pub p: [uint8_t; 128],
    pub num: libc::c_uint,
    pub md_len: libc::c_uint,
}
pub type SHA256_CTX = sha256_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sha256_state_st {
    pub h: [uint32_t; 8],
    pub Nl: uint32_t,
    pub Nh: uint32_t,
    pub data: [uint8_t; 64],
    pub num: libc::c_uint,
    pub md_len: libc::c_uint,
}
pub type SHA_CTX = sha_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sha_state_st {
    pub h: [uint32_t; 5],
    pub Nl: uint32_t,
    pub Nh: uint32_t,
    pub data: [uint8_t; 64],
    pub num: libc::c_uint,
}
pub type MD5_CTX = md5_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct md5_state_st {
    pub h: [uint32_t; 4],
    pub Nl: uint32_t,
    pub Nh: uint32_t,
    pub data: [uint8_t; 64],
    pub num: libc::c_uint,
}
pub type HmacMethods = hmac_methods_st;
pub type HMAC_CTX = hmac_ctx_st;
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
#[inline]
unsafe extern "C" fn FIPS_service_indicator_lock_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_unlock_state() {}
#[inline]
unsafe extern "C" fn PBKDF2_verify_service_indicator(
    mut evp_md: *const EVP_MD,
    mut password_len: size_t,
    mut salt_len: size_t,
    mut iterations: libc::c_uint,
) {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS5_PBKDF2_HMAC(
    mut password: *const libc::c_char,
    mut password_len: size_t,
    mut salt: *const uint8_t,
    mut salt_len: size_t,
    mut iterations: uint32_t,
    mut digest: *const EVP_MD,
    mut key_len: size_t,
    mut out_key: *mut uint8_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut md_len: size_t = EVP_MD_size(digest);
    let mut i: uint32_t = 1 as libc::c_int as uint32_t;
    let mut hctx: HMAC_CTX = hmac_ctx_st {
        md: 0 as *const EVP_MD,
        methods: 0 as *const HmacMethods,
        md_ctx: md_ctx_union {
            md5: md5_state_st {
                h: [0; 4],
                Nl: 0,
                Nh: 0,
                data: [0; 64],
                num: 0,
            },
        },
        i_ctx: md_ctx_union {
            md5: md5_state_st {
                h: [0; 4],
                Nl: 0,
                Nh: 0,
                data: [0; 64],
                num: 0,
            },
        },
        o_ctx: md_ctx_union {
            md5: md5_state_st {
                h: [0; 4],
                Nl: 0,
                Nh: 0,
                data: [0; 64],
                num: 0,
            },
        },
        state: 0,
    };
    HMAC_CTX_init(&mut hctx);
    FIPS_service_indicator_lock_state();
    if HMAC_Init_ex(
        &mut hctx,
        password as *const libc::c_void,
        password_len,
        digest,
        0 as *mut ENGINE,
    ) == 0
    {
        current_block = 11774017903830275191;
    } else {
        current_block = 17179679302217393232;
    }
    '_err: loop {
        match current_block {
            11774017903830275191 => {
                FIPS_service_indicator_unlock_state();
                break;
            }
            _ => {
                if key_len > 0 as libc::c_int as size_t {
                    let mut todo: size_t = md_len;
                    if todo > key_len {
                        todo = key_len;
                    }
                    let mut i_buf: [uint8_t; 4] = [0; 4];
                    i_buf[0 as libc::c_int
                        as usize] = (i >> 24 as libc::c_int
                        & 0xff as libc::c_int as uint32_t) as uint8_t;
                    i_buf[1 as libc::c_int
                        as usize] = (i >> 16 as libc::c_int
                        & 0xff as libc::c_int as uint32_t) as uint8_t;
                    i_buf[2 as libc::c_int
                        as usize] = (i >> 8 as libc::c_int
                        & 0xff as libc::c_int as uint32_t) as uint8_t;
                    i_buf[3 as libc::c_int
                        as usize] = (i & 0xff as libc::c_int as uint32_t) as uint8_t;
                    let mut digest_tmp: [uint8_t; 64] = [0; 64];
                    if HMAC_Init_ex(
                        &mut hctx,
                        0 as *const libc::c_void,
                        0 as libc::c_int as size_t,
                        0 as *const EVP_MD,
                        0 as *mut ENGINE,
                    ) == 0 || HMAC_Update(&mut hctx, salt, salt_len) == 0
                        || HMAC_Update(
                            &mut hctx,
                            i_buf.as_mut_ptr(),
                            4 as libc::c_int as size_t,
                        ) == 0
                        || HMAC_Final(
                            &mut hctx,
                            digest_tmp.as_mut_ptr(),
                            0 as *mut libc::c_uint,
                        ) == 0
                    {
                        current_block = 11774017903830275191;
                        continue;
                    }
                    OPENSSL_memcpy(
                        out_key as *mut libc::c_void,
                        digest_tmp.as_mut_ptr() as *const libc::c_void,
                        todo,
                    );
                    let mut j: uint32_t = 1 as libc::c_int as uint32_t;
                    while j < iterations {
                        if HMAC_Init_ex(
                            &mut hctx,
                            0 as *const libc::c_void,
                            0 as libc::c_int as size_t,
                            0 as *const EVP_MD,
                            0 as *mut ENGINE,
                        ) == 0
                            || HMAC_Update(&mut hctx, digest_tmp.as_mut_ptr(), md_len)
                                == 0
                            || HMAC_Final(
                                &mut hctx,
                                digest_tmp.as_mut_ptr(),
                                0 as *mut libc::c_uint,
                            ) == 0
                        {
                            current_block = 11774017903830275191;
                            continue '_err;
                        }
                        let mut k: size_t = 0 as libc::c_int as size_t;
                        while k < todo {
                            let ref mut fresh0 = *out_key.offset(k as isize);
                            *fresh0 = (*fresh0 as libc::c_int
                                ^ digest_tmp[k as usize] as libc::c_int) as uint8_t;
                            k = k.wrapping_add(1);
                            k;
                        }
                        j = j.wrapping_add(1);
                        j;
                    }
                    key_len = key_len.wrapping_sub(todo);
                    out_key = out_key.offset(todo as isize);
                    i = i.wrapping_add(1);
                    i;
                    current_block = 17179679302217393232;
                } else {
                    if iterations == 0 as libc::c_int as uint32_t {
                        current_block = 11774017903830275191;
                        continue;
                    }
                    ret = 1 as libc::c_int;
                    current_block = 11774017903830275191;
                }
            }
        }
    }
    HMAC_CTX_cleanup(&mut hctx);
    if ret != 0 {
        PBKDF2_verify_service_indicator(digest, password_len, salt_len, iterations);
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS5_PBKDF2_HMAC_SHA1(
    mut password: *const libc::c_char,
    mut password_len: size_t,
    mut salt: *const uint8_t,
    mut salt_len: size_t,
    mut iterations: uint32_t,
    mut key_len: size_t,
    mut out_key: *mut uint8_t,
) -> libc::c_int {
    return PKCS5_PBKDF2_HMAC(
        password,
        password_len,
        salt,
        salt_len,
        iterations,
        EVP_sha1(),
        key_len,
        out_key,
    );
}
