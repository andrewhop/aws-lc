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
    pub type env_md_st;
    pub type hmac_methods_st;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn EVP_md5() -> *const EVP_MD;
    fn EVP_sha1() -> *const EVP_MD;
    fn EVP_md5_sha1() -> *const EVP_MD;
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
    fn HMAC_CTX_copy_ex(dest: *mut HMAC_CTX, src: *const HMAC_CTX) -> libc::c_int;
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
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
unsafe extern "C" fn OPENSSL_memset(
    mut dst: *mut libc::c_void,
    mut c: libc::c_int,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return dst;
    }
    return memset(dst, c, n);
}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_lock_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_unlock_state() {}
#[inline]
unsafe extern "C" fn TLSKDF_verify_service_indicator(
    mut dgst: *const EVP_MD,
    mut label: *const libc::c_char,
    mut label_len: size_t,
) {}
unsafe extern "C" fn tls1_P_hash(
    mut out: *mut uint8_t,
    mut out_len: size_t,
    mut md: *const EVP_MD,
    mut secret: *const uint8_t,
    mut secret_len: size_t,
    mut label: *const libc::c_char,
    mut label_len: size_t,
    mut seed1: *const uint8_t,
    mut seed1_len: size_t,
    mut seed2: *const uint8_t,
    mut seed2_len: size_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ctx: HMAC_CTX = hmac_ctx_st {
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
    let mut ctx_tmp: HMAC_CTX = hmac_ctx_st {
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
    let mut ctx_init: HMAC_CTX = hmac_ctx_st {
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
    let mut A1: [uint8_t; 64] = [0; 64];
    let mut A1_len: libc::c_uint = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let chunk: size_t = EVP_MD_size(md);
    HMAC_CTX_init(&mut ctx);
    HMAC_CTX_init(&mut ctx_tmp);
    HMAC_CTX_init(&mut ctx_init);
    if HMAC_Init_ex(
        &mut ctx_init,
        secret as *const libc::c_void,
        secret_len,
        md,
        0 as *mut ENGINE,
    ) == 0 || HMAC_CTX_copy_ex(&mut ctx, &mut ctx_init) == 0
        || HMAC_Update(&mut ctx, label as *const uint8_t, label_len) == 0
        || HMAC_Update(&mut ctx, seed1, seed1_len) == 0
        || HMAC_Update(&mut ctx, seed2, seed2_len) == 0
        || HMAC_Final(&mut ctx, A1.as_mut_ptr(), &mut A1_len) == 0
    {
        current_block = 1476856825073355650;
    } else {
        current_block = 15619007995458559411;
    }
    loop {
        match current_block {
            1476856825073355650 => {
                OPENSSL_cleanse(
                    A1.as_mut_ptr() as *mut libc::c_void,
                    ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
                );
                break;
            }
            _ => {
                let mut len_u: libc::c_uint = 0;
                let mut hmac: [uint8_t; 64] = [0; 64];
                if HMAC_CTX_copy_ex(&mut ctx, &mut ctx_init) == 0
                    || HMAC_Update(&mut ctx, A1.as_mut_ptr(), A1_len as size_t) == 0
                    || out_len > chunk && HMAC_CTX_copy_ex(&mut ctx_tmp, &mut ctx) == 0
                    || HMAC_Update(&mut ctx, label as *const uint8_t, label_len) == 0
                    || HMAC_Update(&mut ctx, seed1, seed1_len) == 0
                    || HMAC_Update(&mut ctx, seed2, seed2_len) == 0
                    || HMAC_Final(&mut ctx, hmac.as_mut_ptr(), &mut len_u) == 0
                {
                    current_block = 1476856825073355650;
                    continue;
                }
                let mut len: size_t = len_u as size_t;
                if len == chunk {} else {
                    __assert_fail(
                        b"len == chunk\0" as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/tls/kdf.c\0"
                            as *const u8 as *const libc::c_char,
                        108 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 148],
                            &[libc::c_char; 148],
                        >(
                            b"int tls1_P_hash(uint8_t *, size_t, const EVP_MD *, const uint8_t *, size_t, const char *, size_t, const uint8_t *, size_t, const uint8_t *, size_t)\0",
                        ))
                            .as_ptr(),
                    );
                }
                'c_1769: {
                    if len == chunk {} else {
                        __assert_fail(
                            b"len == chunk\0" as *const u8 as *const libc::c_char,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/tls/kdf.c\0"
                                as *const u8 as *const libc::c_char,
                            108 as libc::c_int as libc::c_uint,
                            (*::core::mem::transmute::<
                                &[u8; 148],
                                &[libc::c_char; 148],
                            >(
                                b"int tls1_P_hash(uint8_t *, size_t, const EVP_MD *, const uint8_t *, size_t, const char *, size_t, const uint8_t *, size_t, const uint8_t *, size_t)\0",
                            ))
                                .as_ptr(),
                        );
                    }
                };
                if len > out_len {
                    len = out_len;
                }
                let mut i: size_t = 0 as libc::c_int as size_t;
                while i < len {
                    let ref mut fresh0 = *out.offset(i as isize);
                    *fresh0 = (*fresh0 as libc::c_int ^ hmac[i as usize] as libc::c_int)
                        as uint8_t;
                    i = i.wrapping_add(1);
                    i;
                }
                out = out.offset(len as isize);
                out_len = out_len.wrapping_sub(len);
                if out_len == 0 as libc::c_int as size_t {
                    ret = 1 as libc::c_int;
                    current_block = 1476856825073355650;
                } else if HMAC_Final(&mut ctx_tmp, A1.as_mut_ptr(), &mut A1_len) == 0 {
                    current_block = 1476856825073355650;
                } else {
                    current_block = 15619007995458559411;
                }
            }
        }
    }
    HMAC_CTX_cleanup(&mut ctx);
    HMAC_CTX_cleanup(&mut ctx_tmp);
    HMAC_CTX_cleanup(&mut ctx_init);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_tls1_prf(
    mut digest: *const EVP_MD,
    mut out: *mut uint8_t,
    mut out_len: size_t,
    mut secret: *const uint8_t,
    mut secret_len: size_t,
    mut label: *const libc::c_char,
    mut label_len: size_t,
    mut seed1: *const uint8_t,
    mut seed1_len: size_t,
    mut seed2: *const uint8_t,
    mut seed2_len: size_t,
) -> libc::c_int {
    let mut current_block: u64;
    FIPS_service_indicator_lock_state();
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut original_digest: *const EVP_MD = digest;
    if out_len == 0 as libc::c_int as size_t {
        ret = 1 as libc::c_int;
    } else {
        OPENSSL_memset(out as *mut libc::c_void, 0 as libc::c_int, out_len);
        if digest == EVP_md5_sha1() {
            let mut secret_half: size_t = secret_len
                .wrapping_sub(secret_len / 2 as libc::c_int as size_t);
            if tls1_P_hash(
                out,
                out_len,
                EVP_md5(),
                secret,
                secret_half,
                label,
                label_len,
                seed1,
                seed1_len,
                seed2,
                seed2_len,
            ) == 0
            {
                current_block = 12144605640203069118;
            } else {
                secret = secret.offset(secret_len.wrapping_sub(secret_half) as isize);
                secret_len = secret_half;
                digest = EVP_sha1();
                current_block = 13183875560443969876;
            }
        } else {
            current_block = 13183875560443969876;
        }
        match current_block {
            12144605640203069118 => {}
            _ => {
                ret = tls1_P_hash(
                    out,
                    out_len,
                    digest,
                    secret,
                    secret_len,
                    label,
                    label_len,
                    seed1,
                    seed1_len,
                    seed2,
                    seed2_len,
                );
            }
        }
    }
    FIPS_service_indicator_unlock_state();
    if ret != 0 {
        TLSKDF_verify_service_indicator(original_digest, label, label_len);
    }
    return ret;
}
