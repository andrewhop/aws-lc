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
    pub type evp_md_pctx_ops;
    pub type evp_pkey_ctx_st;
    pub type env_md_st;
    fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX;
    fn EVP_MD_CTX_free(ctx: *mut EVP_MD_CTX);
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
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
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
#[inline]
unsafe extern "C" fn FIPS_service_indicator_lock_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_unlock_state() {}
#[inline]
unsafe extern "C" fn SSHKDF_verify_service_indicator(mut evp_md: *const EVP_MD) {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SSHKDF(
    mut evp_md: *const EVP_MD,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut xcghash: *const uint8_t,
    mut xcghash_len: size_t,
    mut session_id: *const uint8_t,
    mut session_id_len: size_t,
    mut type_0: libc::c_char,
    mut out: *mut uint8_t,
    mut out_len: size_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut md: *mut EVP_MD_CTX = 0 as *mut EVP_MD_CTX;
    let mut digest: [uint8_t; 64] = [0; 64];
    let mut digest_size: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut cursize: size_t = 0 as libc::c_int as size_t;
    let mut ret: libc::c_int = 0 as libc::c_int;
    if evp_md.is_null() {
        return 0 as libc::c_int;
    }
    if key.is_null() || key_len == 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    if xcghash.is_null() || xcghash_len == 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    if session_id.is_null() || session_id_len == 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    if (type_0 as libc::c_int) < 65 as libc::c_int
        || type_0 as libc::c_int > 70 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    FIPS_service_indicator_lock_state();
    md = EVP_MD_CTX_new();
    if !md.is_null() {
        if !(EVP_DigestInit_ex(md, evp_md, 0 as *mut ENGINE) == 0) {
            if !(EVP_DigestUpdate(md, key as *const libc::c_void, key_len) == 0) {
                if !(EVP_DigestUpdate(md, xcghash as *const libc::c_void, xcghash_len)
                    == 0)
                {
                    if !(EVP_DigestUpdate(
                        md,
                        &mut type_0 as *mut libc::c_char as *const libc::c_void,
                        1 as libc::c_int as size_t,
                    ) == 0)
                    {
                        if !(EVP_DigestUpdate(
                            md,
                            session_id as *const libc::c_void,
                            session_id_len,
                        ) == 0)
                        {
                            if !(EVP_DigestFinal_ex(
                                md,
                                digest.as_mut_ptr(),
                                &mut digest_size,
                            ) == 0)
                            {
                                if out_len < digest_size as size_t {
                                    memcpy(
                                        out as *mut libc::c_void,
                                        digest.as_mut_ptr() as *const libc::c_void,
                                        out_len,
                                    );
                                    ret = 1 as libc::c_int;
                                } else {
                                    memcpy(
                                        out as *mut libc::c_void,
                                        digest.as_mut_ptr() as *const libc::c_void,
                                        digest_size as libc::c_ulong,
                                    );
                                    cursize = digest_size as size_t;
                                    loop {
                                        if !(cursize < out_len) {
                                            current_block = 980989089337379490;
                                            break;
                                        }
                                        if EVP_DigestInit_ex(md, evp_md, 0 as *mut ENGINE) == 0 {
                                            current_block = 12771589659836055490;
                                            break;
                                        }
                                        if EVP_DigestUpdate(md, key as *const libc::c_void, key_len)
                                            == 0
                                        {
                                            current_block = 12771589659836055490;
                                            break;
                                        }
                                        if EVP_DigestUpdate(
                                            md,
                                            xcghash as *const libc::c_void,
                                            xcghash_len,
                                        ) == 0
                                        {
                                            current_block = 12771589659836055490;
                                            break;
                                        }
                                        if EVP_DigestUpdate(md, out as *const libc::c_void, cursize)
                                            == 0
                                        {
                                            current_block = 12771589659836055490;
                                            break;
                                        }
                                        if EVP_DigestFinal_ex(
                                            md,
                                            digest.as_mut_ptr(),
                                            &mut digest_size as *mut libc::c_uint,
                                        ) == 0
                                        {
                                            current_block = 12771589659836055490;
                                            break;
                                        }
                                        if out_len < cursize.wrapping_add(digest_size as size_t) {
                                            memcpy(
                                                out.offset(cursize as isize) as *mut libc::c_void,
                                                digest.as_mut_ptr() as *const libc::c_void,
                                                out_len.wrapping_sub(cursize),
                                            );
                                            ret = 1 as libc::c_int;
                                            current_block = 12771589659836055490;
                                            break;
                                        } else {
                                            memcpy(
                                                out.offset(cursize as isize) as *mut libc::c_void,
                                                digest.as_mut_ptr() as *const libc::c_void,
                                                digest_size as libc::c_ulong,
                                            );
                                            cursize = cursize.wrapping_add(digest_size as size_t);
                                        }
                                    }
                                    match current_block {
                                        12771589659836055490 => {}
                                        _ => {
                                            ret = 1 as libc::c_int;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    EVP_MD_CTX_free(md);
    OPENSSL_cleanse(
        digest.as_mut_ptr() as *mut libc::c_void,
        64 as libc::c_int as size_t,
    );
    FIPS_service_indicator_unlock_state();
    if ret != 0 {
        SSHKDF_verify_service_indicator(evp_md);
    }
    return ret;
}
