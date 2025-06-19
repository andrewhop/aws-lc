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
    pub type evp_pkey_st;
    pub type engine_st;
    pub type evp_md_pctx_ops;
    pub type evp_pkey_ctx_st;
    pub type env_md_st;
    fn EVP_rc4() -> *const EVP_CIPHER;
    fn EVP_des_ede3_cbc() -> *const EVP_CIPHER;
    fn EVP_rc2_40_cbc() -> *const EVP_CIPHER;
    fn EVP_CIPHER_CTX_init(ctx: *mut EVP_CIPHER_CTX);
    fn EVP_CIPHER_CTX_cleanup(ctx: *mut EVP_CIPHER_CTX) -> libc::c_int;
    fn EVP_CipherInit_ex(
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        engine: *mut ENGINE,
        key: *const uint8_t,
        iv: *const uint8_t,
        enc: libc::c_int,
    ) -> libc::c_int;
    fn EVP_DecryptUpdate(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut uint8_t,
        out_len: *mut libc::c_int,
        in_0: *const uint8_t,
        in_len: libc::c_int,
    ) -> libc::c_int;
    fn EVP_DecryptFinal_ex(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut uint8_t,
        out_len: *mut libc::c_int,
    ) -> libc::c_int;
    fn EVP_CipherUpdate(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut uint8_t,
        out_len: *mut libc::c_int,
        in_0: *const uint8_t,
        in_len: libc::c_int,
    ) -> libc::c_int;
    fn EVP_CipherFinal_ex(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut uint8_t,
        out_len: *mut libc::c_int,
    ) -> libc::c_int;
    fn EVP_CIPHER_CTX_block_size(ctx: *const EVP_CIPHER_CTX) -> libc::c_uint;
    fn EVP_CIPHER_key_length(cipher: *const EVP_CIPHER) -> libc::c_uint;
    fn EVP_CIPHER_iv_length(cipher: *const EVP_CIPHER) -> libc::c_uint;
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_mem_equal(cbs: *const CBS, data: *const uint8_t, len: size_t) -> libc::c_int;
    fn CBS_get_asn1(
        cbs: *mut CBS,
        out: *mut CBS,
        tag_value: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBS_get_asn1_uint64(cbs: *mut CBS, out: *mut uint64_t) -> libc::c_int;
    fn CBB_init(cbb: *mut CBB, initial_capacity: size_t) -> libc::c_int;
    fn CBB_cleanup(cbb: *mut CBB);
    fn CBB_finish(
        cbb: *mut CBB,
        out_data: *mut *mut uint8_t,
        out_len: *mut size_t,
    ) -> libc::c_int;
    fn CBB_flush(cbb: *mut CBB) -> libc::c_int;
    fn CBB_add_asn1(
        cbb: *mut CBB,
        out_contents: *mut CBB,
        tag: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBB_add_bytes(cbb: *mut CBB, data: *const uint8_t, len: size_t) -> libc::c_int;
    fn CBB_reserve(
        cbb: *mut CBB,
        out_data: *mut *mut uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn CBB_did_write(cbb: *mut CBB, len: size_t) -> libc::c_int;
    fn CBB_add_asn1_uint64(cbb: *mut CBB, value: uint64_t) -> libc::c_int;
    fn EVP_sha1() -> *const EVP_MD;
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
    fn EVP_MD_block_size(md: *const EVP_MD) -> size_t;
    fn PKCS5_pbe2_decrypt_init(
        suite: *const pbe_suite,
        ctx: *mut EVP_CIPHER_CTX,
        pass: *const libc::c_char,
        pass_len: size_t,
        param: *mut CBS,
    ) -> libc::c_int;
    fn PKCS5_pbe2_encrypt_init(
        out: *mut CBB,
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        iterations: uint32_t,
        pass: *const libc::c_char,
        pass_len: size_t,
        salt: *const uint8_t,
        salt_len: size_t,
    ) -> libc::c_int;
    fn pkcs12_iterations_acceptable(iterations: uint64_t) -> libc::c_int;
    fn RAND_bytes(buf: *mut uint8_t, len: size_t) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn EVP_parse_private_key(cbs: *mut CBS) -> *mut EVP_PKEY;
    fn EVP_marshal_private_key(cbb: *mut CBB, key: *const EVP_PKEY) -> libc::c_int;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn cbs_get_utf8(cbs: *mut CBS, out: *mut uint32_t) -> libc::c_int;
    fn cbb_add_ucs2_be(cbb: *mut CBB, u: uint32_t) -> libc::c_int;
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
pub type EVP_PKEY = evp_pkey_st;
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
unsafe extern "C" fn pkcs12_encode_password(
    mut in_0: *const libc::c_char,
    mut in_len: size_t,
    mut out: *mut *mut uint8_t,
    mut out_len: *mut size_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut cbb: CBB = cbb_st {
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
    if CBB_init(&mut cbb, in_len * 2 as libc::c_int as size_t) == 0 {
        return 0 as libc::c_int;
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, in_0 as *const uint8_t, in_len);
    loop {
        if !(CBS_len(&mut cbs) != 0 as libc::c_int as size_t) {
            current_block = 11006700562992250127;
            break;
        }
        let mut c: uint32_t = 0;
        if !(cbs_get_utf8(&mut cbs, &mut c) == 0 || cbb_add_ucs2_be(&mut cbb, c) == 0) {
            continue;
        }
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            131 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8.c\0" as *const u8
                as *const libc::c_char,
            90 as libc::c_int as libc::c_uint,
        );
        current_block = 1362205537170793007;
        break;
    }
    match current_block {
        11006700562992250127 => {
            if !(cbb_add_ucs2_be(&mut cbb, 0 as libc::c_int as uint32_t) == 0
                || CBB_finish(&mut cbb, out, out_len) == 0)
            {
                return 1 as libc::c_int;
            }
        }
        _ => {}
    }
    CBB_cleanup(&mut cbb);
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn pkcs12_key_gen(
    mut pass: *const libc::c_char,
    mut pass_len: size_t,
    mut salt: *const uint8_t,
    mut salt_len: size_t,
    mut id: uint8_t,
    mut iterations: uint32_t,
    mut out_len: size_t,
    mut out: *mut uint8_t,
    mut md: *const EVP_MD,
) -> libc::c_int {
    let mut block_size: size_t = 0;
    let mut D: [uint8_t; 128] = [0; 128];
    let mut S_len: size_t = 0;
    let mut P_len: size_t = 0;
    let mut current_block: u64;
    if iterations < 1 as libc::c_int as uint32_t {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            129 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8.c\0" as *const u8
                as *const libc::c_char,
            115 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut ctx: EVP_MD_CTX = env_md_ctx_st {
        digest: 0 as *const EVP_MD,
        md_data: 0 as *mut libc::c_void,
        update: None,
        pctx: 0 as *mut EVP_PKEY_CTX,
        pctx_ops: 0 as *const evp_md_pctx_ops,
        flags: 0,
    };
    EVP_MD_CTX_init(&mut ctx);
    let mut pass_raw: *mut uint8_t = 0 as *mut uint8_t;
    let mut I: *mut uint8_t = 0 as *mut uint8_t;
    let mut pass_raw_len: size_t = 0 as libc::c_int as size_t;
    let mut I_len: size_t = 0 as libc::c_int as size_t;
    if !(!pass.is_null()
        && pkcs12_encode_password(pass, pass_len, &mut pass_raw, &mut pass_raw_len) == 0)
    {
        block_size = EVP_MD_block_size(md);
        D = [0; 128];
        OPENSSL_memset(
            D.as_mut_ptr() as *mut libc::c_void,
            id as libc::c_int,
            block_size,
        );
        if salt_len.wrapping_add(block_size).wrapping_sub(1 as libc::c_int as size_t)
            < salt_len
            || pass_raw_len
                .wrapping_add(block_size)
                .wrapping_sub(1 as libc::c_int as size_t) < pass_raw_len
        {
            ERR_put_error(
                19 as libc::c_int,
                0 as libc::c_int,
                5 as libc::c_int | 64 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8.c\0" as *const u8
                    as *const libc::c_char,
                151 as libc::c_int as libc::c_uint,
            );
        } else {
            S_len = block_size
                * (salt_len
                    .wrapping_add(block_size)
                    .wrapping_sub(1 as libc::c_int as size_t) / block_size);
            P_len = block_size
                * (pass_raw_len
                    .wrapping_add(block_size)
                    .wrapping_sub(1 as libc::c_int as size_t) / block_size);
            I_len = S_len.wrapping_add(P_len);
            if I_len < S_len {
                ERR_put_error(
                    19 as libc::c_int,
                    0 as libc::c_int,
                    5 as libc::c_int | 64 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8.c\0"
                        as *const u8 as *const libc::c_char,
                    158 as libc::c_int as libc::c_uint,
                );
            } else {
                I = OPENSSL_malloc(I_len) as *mut uint8_t;
                if !(I_len != 0 as libc::c_int as size_t && I.is_null()) {
                    let mut i: size_t = 0 as libc::c_int as size_t;
                    while i < S_len {
                        *I.offset(i as isize) = *salt.offset((i % salt_len) as isize);
                        i = i.wrapping_add(1);
                        i;
                    }
                    if pass_raw_len > 0 as libc::c_int as size_t {
                        let mut i_0: size_t = 0 as libc::c_int as size_t;
                        while i_0 < P_len {
                            *I
                                .offset(
                                    i_0.wrapping_add(S_len) as isize,
                                ) = *pass_raw.offset((i_0 % pass_raw_len) as isize);
                            i_0 = i_0.wrapping_add(1);
                            i_0;
                        }
                    }
                    's_119: loop {
                        if !(out_len != 0 as libc::c_int as size_t) {
                            current_block = 3160140712158701372;
                            break;
                        }
                        let mut A: [uint8_t; 64] = [0; 64];
                        let mut A_len: libc::c_uint = 0;
                        if EVP_DigestInit_ex(&mut ctx, md, 0 as *mut ENGINE) == 0
                            || EVP_DigestUpdate(
                                &mut ctx,
                                D.as_mut_ptr() as *const libc::c_void,
                                block_size,
                            ) == 0
                            || EVP_DigestUpdate(
                                &mut ctx,
                                I as *const libc::c_void,
                                I_len,
                            ) == 0
                            || EVP_DigestFinal_ex(&mut ctx, A.as_mut_ptr(), &mut A_len)
                                == 0
                        {
                            current_block = 197891636308415867;
                            break;
                        }
                        let mut iter: uint32_t = 1 as libc::c_int as uint32_t;
                        while iter < iterations {
                            if EVP_DigestInit_ex(&mut ctx, md, 0 as *mut ENGINE) == 0
                                || EVP_DigestUpdate(
                                    &mut ctx,
                                    A.as_mut_ptr() as *const libc::c_void,
                                    A_len as size_t,
                                ) == 0
                                || EVP_DigestFinal_ex(&mut ctx, A.as_mut_ptr(), &mut A_len)
                                    == 0
                            {
                                current_block = 197891636308415867;
                                break 's_119;
                            }
                            iter = iter.wrapping_add(1);
                            iter;
                        }
                        let mut todo: size_t = if out_len < A_len as size_t {
                            out_len
                        } else {
                            A_len as size_t
                        };
                        OPENSSL_memcpy(
                            out as *mut libc::c_void,
                            A.as_mut_ptr() as *const libc::c_void,
                            todo,
                        );
                        out = out.offset(todo as isize);
                        out_len = out_len.wrapping_sub(todo);
                        if out_len == 0 as libc::c_int as size_t {
                            current_block = 3160140712158701372;
                            break;
                        }
                        let mut B: [uint8_t; 128] = [0; 128];
                        let mut i_1: size_t = 0 as libc::c_int as size_t;
                        while i_1 < block_size {
                            B[i_1 as usize] = A[(i_1 % A_len as size_t) as usize];
                            i_1 = i_1.wrapping_add(1);
                            i_1;
                        }
                        if I_len % block_size == 0 as libc::c_int as size_t {} else {
                            __assert_fail(
                                b"I_len % block_size == 0\0" as *const u8
                                    as *const libc::c_char,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8.c\0"
                                    as *const u8 as *const libc::c_char,
                                214 as libc::c_int as libc::c_uint,
                                (*::core::mem::transmute::<
                                    &[u8; 120],
                                    &[libc::c_char; 120],
                                >(
                                    b"int pkcs12_key_gen(const char *, size_t, const uint8_t *, size_t, uint8_t, uint32_t, size_t, uint8_t *, const EVP_MD *)\0",
                                ))
                                    .as_ptr(),
                            );
                        }
                        'c_26574: {
                            if I_len % block_size == 0 as libc::c_int as size_t {} else {
                                __assert_fail(
                                    b"I_len % block_size == 0\0" as *const u8
                                        as *const libc::c_char,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8.c\0"
                                        as *const u8 as *const libc::c_char,
                                    214 as libc::c_int as libc::c_uint,
                                    (*::core::mem::transmute::<
                                        &[u8; 120],
                                        &[libc::c_char; 120],
                                    >(
                                        b"int pkcs12_key_gen(const char *, size_t, const uint8_t *, size_t, uint8_t, uint32_t, size_t, uint8_t *, const EVP_MD *)\0",
                                    ))
                                        .as_ptr(),
                                );
                            }
                        };
                        let mut i_2: size_t = 0 as libc::c_int as size_t;
                        while i_2 < I_len {
                            let mut carry: libc::c_uint = 1 as libc::c_int
                                as libc::c_uint;
                            let mut j: size_t = block_size
                                .wrapping_sub(1 as libc::c_int as size_t);
                            while j < block_size {
                                carry = carry
                                    .wrapping_add(
                                        (*I.offset(i_2.wrapping_add(j) as isize) as libc::c_int
                                            + B[j as usize] as libc::c_int) as libc::c_uint,
                                    );
                                *I.offset(i_2.wrapping_add(j) as isize) = carry as uint8_t;
                                carry >>= 8 as libc::c_int;
                                j = j.wrapping_sub(1);
                                j;
                            }
                            i_2 = i_2.wrapping_add(block_size);
                        }
                    }
                    match current_block {
                        197891636308415867 => {}
                        _ => {
                            ret = 1 as libc::c_int;
                        }
                    }
                }
            }
        }
    }
    OPENSSL_free(I as *mut libc::c_void);
    OPENSSL_free(pass_raw as *mut libc::c_void);
    EVP_MD_CTX_cleanup(&mut ctx);
    return ret;
}
unsafe extern "C" fn pkcs12_pbe_cipher_init(
    mut suite: *const pbe_suite,
    mut ctx: *mut EVP_CIPHER_CTX,
    mut iterations: uint32_t,
    mut pass: *const libc::c_char,
    mut pass_len: size_t,
    mut salt: *const uint8_t,
    mut salt_len: size_t,
    mut is_encrypt: libc::c_int,
) -> libc::c_int {
    let mut cipher: *const EVP_CIPHER = ((*suite).cipher_func)
        .expect("non-null function pointer")();
    let mut md: *const EVP_MD = ((*suite).md_func).expect("non-null function pointer")();
    let mut key: [uint8_t; 64] = [0; 64];
    let mut iv: [uint8_t; 16] = [0; 16];
    if pkcs12_key_gen(
        pass,
        pass_len,
        salt,
        salt_len,
        1 as libc::c_int as uint8_t,
        iterations,
        EVP_CIPHER_key_length(cipher) as size_t,
        key.as_mut_ptr(),
        md,
    ) == 0
        || pkcs12_key_gen(
            pass,
            pass_len,
            salt,
            salt_len,
            2 as libc::c_int as uint8_t,
            iterations,
            EVP_CIPHER_iv_length(cipher) as size_t,
            iv.as_mut_ptr(),
            md,
        ) == 0
    {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            110 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8.c\0" as *const u8
                as *const libc::c_char,
            248 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = EVP_CipherInit_ex(
        ctx,
        cipher,
        0 as *mut ENGINE,
        key.as_mut_ptr(),
        iv.as_mut_ptr(),
        is_encrypt,
    );
    OPENSSL_cleanse(key.as_mut_ptr() as *mut libc::c_void, 64 as libc::c_int as size_t);
    OPENSSL_cleanse(iv.as_mut_ptr() as *mut libc::c_void, 16 as libc::c_int as size_t);
    return ret;
}
unsafe extern "C" fn pkcs12_pbe_decrypt_init(
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
    let mut salt: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut iterations: uint64_t = 0;
    if CBS_get_asn1(
        param,
        &mut pbe_param,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || CBS_get_asn1(&mut pbe_param, &mut salt, 0x4 as libc::c_uint) == 0
        || CBS_get_asn1_uint64(&mut pbe_param, &mut iterations) == 0
        || CBS_len(&mut pbe_param) != 0 as libc::c_int as size_t
        || CBS_len(param) != 0 as libc::c_int as size_t
    {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8.c\0" as *const u8
                as *const libc::c_char,
            268 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if pkcs12_iterations_acceptable(iterations) == 0 {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            129 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8.c\0" as *const u8
                as *const libc::c_char,
            273 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return pkcs12_pbe_cipher_init(
        suite,
        ctx,
        iterations as uint32_t,
        pass,
        pass_len,
        CBS_data(&mut salt),
        CBS_len(&mut salt),
        0 as libc::c_int,
    );
}
static mut kBuiltinPBE: [pbe_suite; 4] = unsafe {
    [
        {
            let mut init = pbe_suite {
                pbe_nid: 149 as libc::c_int,
                oid: [
                    0x2a as libc::c_int as uint8_t,
                    0x86 as libc::c_int as uint8_t,
                    0x48 as libc::c_int as uint8_t,
                    0x86 as libc::c_int as uint8_t,
                    0xf7 as libc::c_int as uint8_t,
                    0xd as libc::c_int as uint8_t,
                    0x1 as libc::c_int as uint8_t,
                    0xc as libc::c_int as uint8_t,
                    0x1 as libc::c_int as uint8_t,
                    0x6 as libc::c_int as uint8_t,
                ],
                oid_len: 10 as libc::c_int as uint8_t,
                cipher_func: Some(
                    EVP_rc2_40_cbc as unsafe extern "C" fn() -> *const EVP_CIPHER,
                ),
                md_func: Some(EVP_sha1 as unsafe extern "C" fn() -> *const EVP_MD),
                decrypt_init: Some(
                    pkcs12_pbe_decrypt_init
                        as unsafe extern "C" fn(
                            *const pbe_suite,
                            *mut EVP_CIPHER_CTX,
                            *const libc::c_char,
                            size_t,
                            *mut CBS,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = pbe_suite {
                pbe_nid: 144 as libc::c_int,
                oid: [
                    0x2a as libc::c_int as uint8_t,
                    0x86 as libc::c_int as uint8_t,
                    0x48 as libc::c_int as uint8_t,
                    0x86 as libc::c_int as uint8_t,
                    0xf7 as libc::c_int as uint8_t,
                    0xd as libc::c_int as uint8_t,
                    0x1 as libc::c_int as uint8_t,
                    0xc as libc::c_int as uint8_t,
                    0x1 as libc::c_int as uint8_t,
                    0x1 as libc::c_int as uint8_t,
                ],
                oid_len: 10 as libc::c_int as uint8_t,
                cipher_func: Some(
                    EVP_rc4 as unsafe extern "C" fn() -> *const EVP_CIPHER,
                ),
                md_func: Some(EVP_sha1 as unsafe extern "C" fn() -> *const EVP_MD),
                decrypt_init: Some(
                    pkcs12_pbe_decrypt_init
                        as unsafe extern "C" fn(
                            *const pbe_suite,
                            *mut EVP_CIPHER_CTX,
                            *const libc::c_char,
                            size_t,
                            *mut CBS,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = pbe_suite {
                pbe_nid: 146 as libc::c_int,
                oid: [
                    0x2a as libc::c_int as uint8_t,
                    0x86 as libc::c_int as uint8_t,
                    0x48 as libc::c_int as uint8_t,
                    0x86 as libc::c_int as uint8_t,
                    0xf7 as libc::c_int as uint8_t,
                    0xd as libc::c_int as uint8_t,
                    0x1 as libc::c_int as uint8_t,
                    0xc as libc::c_int as uint8_t,
                    0x1 as libc::c_int as uint8_t,
                    0x3 as libc::c_int as uint8_t,
                ],
                oid_len: 10 as libc::c_int as uint8_t,
                cipher_func: Some(
                    EVP_des_ede3_cbc as unsafe extern "C" fn() -> *const EVP_CIPHER,
                ),
                md_func: Some(EVP_sha1 as unsafe extern "C" fn() -> *const EVP_MD),
                decrypt_init: Some(
                    pkcs12_pbe_decrypt_init
                        as unsafe extern "C" fn(
                            *const pbe_suite,
                            *mut EVP_CIPHER_CTX,
                            *const libc::c_char,
                            size_t,
                            *mut CBS,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = pbe_suite {
                pbe_nid: 161 as libc::c_int,
                oid: [
                    0x2a as libc::c_int as uint8_t,
                    0x86 as libc::c_int as uint8_t,
                    0x48 as libc::c_int as uint8_t,
                    0x86 as libc::c_int as uint8_t,
                    0xf7 as libc::c_int as uint8_t,
                    0xd as libc::c_int as uint8_t,
                    0x1 as libc::c_int as uint8_t,
                    0x5 as libc::c_int as uint8_t,
                    0xd as libc::c_int as uint8_t,
                    0,
                ],
                oid_len: 9 as libc::c_int as uint8_t,
                cipher_func: None,
                md_func: None,
                decrypt_init: Some(
                    PKCS5_pbe2_decrypt_init
                        as unsafe extern "C" fn(
                            *const pbe_suite,
                            *mut EVP_CIPHER_CTX,
                            *const libc::c_char,
                            size_t,
                            *mut CBS,
                        ) -> libc::c_int,
                ),
            };
            init
        },
    ]
};
unsafe extern "C" fn get_pkcs12_pbe_suite(mut pbe_nid: libc::c_int) -> *const pbe_suite {
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong)
        < (::core::mem::size_of::<[pbe_suite; 4]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<pbe_suite>() as libc::c_ulong)
    {
        if kBuiltinPBE[i as usize].pbe_nid == pbe_nid
            && (kBuiltinPBE[i as usize].cipher_func).is_some()
            && (kBuiltinPBE[i as usize].md_func).is_some()
        {
            return &*kBuiltinPBE.as_ptr().offset(i as isize) as *const pbe_suite;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as *const pbe_suite;
}
#[no_mangle]
pub unsafe extern "C" fn pkcs12_pbe_encrypt_init(
    mut out: *mut CBB,
    mut ctx: *mut EVP_CIPHER_CTX,
    mut alg: libc::c_int,
    mut iterations: uint32_t,
    mut pass: *const libc::c_char,
    mut pass_len: size_t,
    mut salt: *const uint8_t,
    mut salt_len: size_t,
) -> libc::c_int {
    let mut suite: *const pbe_suite = get_pkcs12_pbe_suite(alg);
    if suite.is_null() {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            119 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8.c\0" as *const u8
                as *const libc::c_char,
            340 as libc::c_int as libc::c_uint,
        );
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
    if CBB_add_asn1(
        out,
        &mut algorithm,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || CBB_add_asn1(&mut algorithm, &mut oid, 0x6 as libc::c_uint) == 0
        || CBB_add_bytes(&mut oid, ((*suite).oid).as_ptr(), (*suite).oid_len as size_t)
            == 0
        || CBB_add_asn1(
            &mut algorithm,
            &mut param,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0 || CBB_add_asn1(&mut param, &mut salt_cbb, 0x4 as libc::c_uint) == 0
        || CBB_add_bytes(&mut salt_cbb, salt, salt_len) == 0
        || CBB_add_asn1_uint64(&mut param, iterations as uint64_t) == 0
        || CBB_flush(out) == 0
    {
        return 0 as libc::c_int;
    }
    return pkcs12_pbe_cipher_init(
        suite,
        ctx,
        iterations,
        pass,
        pass_len,
        salt,
        salt_len,
        1 as libc::c_int,
    );
}
#[no_mangle]
pub unsafe extern "C" fn pkcs8_pbe_decrypt(
    mut out: *mut *mut uint8_t,
    mut out_len: *mut size_t,
    mut algorithm: *mut CBS,
    mut pass: *const libc::c_char,
    mut pass_len: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
) -> libc::c_int {
    let mut suite: *const pbe_suite = 0 as *const pbe_suite;
    let mut n1: libc::c_int = 0;
    let mut n2: libc::c_int = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut buf: *mut uint8_t = 0 as *mut uint8_t;
    let mut ctx: EVP_CIPHER_CTX = evp_cipher_ctx_st {
        cipher: 0 as *const EVP_CIPHER,
        app_data: 0 as *mut libc::c_void,
        cipher_data: 0 as *mut libc::c_void,
        key_len: 0,
        encrypt: 0,
        flags: 0,
        oiv: [0; 16],
        iv: [0; 16],
        buf: [0; 32],
        buf_len: 0,
        num: 0,
        final_used: 0,
        final_0: [0; 32],
        poisoned: 0,
    };
    EVP_CIPHER_CTX_init(&mut ctx);
    let mut obj: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_get_asn1(algorithm, &mut obj, 0x6 as libc::c_uint) == 0 {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8.c\0" as *const u8
                as *const libc::c_char,
            371 as libc::c_int as libc::c_uint,
        );
    } else {
        suite = 0 as *const pbe_suite;
        let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
        while (i as libc::c_ulong)
            < (::core::mem::size_of::<[pbe_suite; 4]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<pbe_suite>() as libc::c_ulong)
        {
            if CBS_mem_equal(
                &mut obj,
                (kBuiltinPBE[i as usize].oid).as_ptr(),
                kBuiltinPBE[i as usize].oid_len as size_t,
            ) != 0
            {
                suite = &*kBuiltinPBE.as_ptr().offset(i as isize) as *const pbe_suite;
                break;
            } else {
                i = i.wrapping_add(1);
                i;
            }
        }
        if suite.is_null() {
            ERR_put_error(
                19 as libc::c_int,
                0 as libc::c_int,
                119 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8.c\0" as *const u8
                    as *const libc::c_char,
                383 as libc::c_int as libc::c_uint,
            );
        } else if ((*suite).decrypt_init)
            .expect(
                "non-null function pointer",
            )(suite, &mut ctx, pass, pass_len, algorithm) == 0
        {
            ERR_put_error(
                19 as libc::c_int,
                0 as libc::c_int,
                109 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8.c\0" as *const u8
                    as *const libc::c_char,
                388 as libc::c_int as libc::c_uint,
            );
        } else {
            buf = OPENSSL_malloc(in_len) as *mut uint8_t;
            if !buf.is_null() {
                if in_len > 2147483647 as libc::c_int as size_t {
                    ERR_put_error(
                        19 as libc::c_int,
                        0 as libc::c_int,
                        5 as libc::c_int | 64 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8.c\0"
                            as *const u8 as *const libc::c_char,
                        398 as libc::c_int as libc::c_uint,
                    );
                } else {
                    n1 = 0;
                    n2 = 0;
                    if !(EVP_DecryptUpdate(
                        &mut ctx,
                        buf,
                        &mut n1,
                        in_0,
                        in_len as libc::c_int,
                    ) == 0
                        || EVP_DecryptFinal_ex(
                            &mut ctx,
                            buf.offset(n1 as isize),
                            &mut n2,
                        ) == 0)
                    {
                        *out = buf;
                        *out_len = (n1 + n2) as size_t;
                        ret = 1 as libc::c_int;
                        buf = 0 as *mut uint8_t;
                    }
                }
            }
        }
    }
    OPENSSL_free(buf as *mut libc::c_void);
    EVP_CIPHER_CTX_cleanup(&mut ctx);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn PKCS8_parse_encrypted_private_key(
    mut cbs: *mut CBS,
    mut pass: *const libc::c_char,
    mut pass_len: size_t,
) -> *mut EVP_PKEY {
    let mut epki: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut algorithm: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut ciphertext: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_get_asn1(
        cbs,
        &mut epki,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0
        || CBS_get_asn1(
            &mut epki,
            &mut algorithm,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0 || CBS_get_asn1(&mut epki, &mut ciphertext, 0x4 as libc::c_uint) == 0
        || CBS_len(&mut epki) != 0 as libc::c_int as size_t
    {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8.c\0" as *const u8
                as *const libc::c_char,
            427 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EVP_PKEY;
    }
    let mut out: *mut uint8_t = 0 as *mut uint8_t;
    let mut out_len: size_t = 0;
    if pkcs8_pbe_decrypt(
        &mut out,
        &mut out_len,
        &mut algorithm,
        pass,
        pass_len,
        CBS_data(&mut ciphertext),
        CBS_len(&mut ciphertext),
    ) == 0
    {
        return 0 as *mut EVP_PKEY;
    }
    let mut pki: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut pki, out, out_len);
    let mut ret: *mut EVP_PKEY = EVP_parse_private_key(&mut pki);
    OPENSSL_free(out as *mut libc::c_void);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn PKCS8_marshal_encrypted_private_key(
    mut out: *mut CBB,
    mut pbe_nid: libc::c_int,
    mut cipher: *const EVP_CIPHER,
    mut pass: *const libc::c_char,
    mut pass_len: size_t,
    mut salt: *const uint8_t,
    mut salt_len: size_t,
    mut iterations: libc::c_int,
    mut pkey: *const EVP_PKEY,
) -> libc::c_int {
    let mut plaintext_cbb: CBB = cbb_st {
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
    let mut epki: CBB = cbb_st {
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
    let mut alg_ok: libc::c_int = 0;
    let mut max_out: size_t = 0;
    let mut ciphertext: CBB = cbb_st {
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
    let mut ptr: *mut uint8_t = 0 as *mut uint8_t;
    let mut n1: libc::c_int = 0;
    let mut n2: libc::c_int = 0;
    let mut current_block: u64;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut plaintext: *mut uint8_t = 0 as *mut uint8_t;
    let mut salt_buf: *mut uint8_t = 0 as *mut uint8_t;
    let mut plaintext_len: size_t = 0 as libc::c_int as size_t;
    let mut ctx: EVP_CIPHER_CTX = evp_cipher_ctx_st {
        cipher: 0 as *const EVP_CIPHER,
        app_data: 0 as *mut libc::c_void,
        cipher_data: 0 as *mut libc::c_void,
        key_len: 0,
        encrypt: 0,
        flags: 0,
        oiv: [0; 16],
        iv: [0; 16],
        buf: [0; 32],
        buf_len: 0,
        num: 0,
        final_used: 0,
        final_0: [0; 32],
        poisoned: 0,
    };
    EVP_CIPHER_CTX_init(&mut ctx);
    if salt.is_null() {
        if salt_len == 0 as libc::c_int as size_t {
            salt_len = 16 as libc::c_int as size_t;
        }
        salt_buf = OPENSSL_malloc(salt_len) as *mut uint8_t;
        if salt_buf.is_null() || RAND_bytes(salt_buf, salt_len) == 0 {
            current_block = 6041130781918823;
        } else {
            salt = salt_buf;
            current_block = 17216689946888361452;
        }
    } else {
        current_block = 17216689946888361452;
    }
    match current_block {
        17216689946888361452 => {
            if iterations <= 0 as libc::c_int {
                iterations = 2048 as libc::c_int;
            }
            plaintext_cbb = cbb_st {
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
            if CBB_init(&mut plaintext_cbb, 128 as libc::c_int as size_t) == 0
                || EVP_marshal_private_key(&mut plaintext_cbb, pkey) == 0
                || CBB_finish(&mut plaintext_cbb, &mut plaintext, &mut plaintext_len)
                    == 0
            {
                CBB_cleanup(&mut plaintext_cbb);
            } else {
                epki = cbb_st {
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
                if !(CBB_add_asn1(
                    out,
                    &mut epki,
                    0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
                ) == 0)
                {
                    alg_ok = 0;
                    if pbe_nid == -(1 as libc::c_int) {
                        alg_ok = PKCS5_pbe2_encrypt_init(
                            &mut epki,
                            &mut ctx,
                            cipher,
                            iterations as uint32_t,
                            pass,
                            pass_len,
                            salt,
                            salt_len,
                        );
                    } else {
                        alg_ok = pkcs12_pbe_encrypt_init(
                            &mut epki,
                            &mut ctx,
                            pbe_nid,
                            iterations as uint32_t,
                            pass,
                            pass_len,
                            salt,
                            salt_len,
                        );
                    }
                    if !(alg_ok == 0) {
                        max_out = plaintext_len
                            .wrapping_add(EVP_CIPHER_CTX_block_size(&mut ctx) as size_t);
                        if max_out < plaintext_len {
                            ERR_put_error(
                                19 as libc::c_int,
                                0 as libc::c_int,
                                118 as libc::c_int,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8.c\0"
                                    as *const u8 as *const libc::c_char,
                                507 as libc::c_int as libc::c_uint,
                            );
                        } else {
                            ciphertext = cbb_st {
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
                            ptr = 0 as *mut uint8_t;
                            n1 = 0;
                            n2 = 0;
                            if !(CBB_add_asn1(
                                &mut epki,
                                &mut ciphertext,
                                0x4 as libc::c_uint,
                            ) == 0
                                || CBB_reserve(&mut ciphertext, &mut ptr, max_out) == 0
                                || EVP_CipherUpdate(
                                    &mut ctx,
                                    ptr,
                                    &mut n1,
                                    plaintext,
                                    plaintext_len as libc::c_int,
                                ) == 0
                                || EVP_CipherFinal_ex(
                                    &mut ctx,
                                    ptr.offset(n1 as isize),
                                    &mut n2,
                                ) == 0
                                || CBB_did_write(&mut ciphertext, (n1 + n2) as size_t) == 0
                                || CBB_flush(out) == 0)
                            {
                                ret = 1 as libc::c_int;
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    OPENSSL_free(plaintext as *mut libc::c_void);
    OPENSSL_free(salt_buf as *mut libc::c_void);
    EVP_CIPHER_CTX_cleanup(&mut ctx);
    return ret;
}
