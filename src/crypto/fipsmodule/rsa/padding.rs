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
    pub type bn_blinding_st;
    pub type stack_st_void;
    pub type rsassa_pss_params_st;
    fn BN_num_bits(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_is_zero(bn: *const BIGNUM) -> libc::c_int;
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
    fn EVP_MD_size(md: *const EVP_MD) -> size_t;
    fn RAND_bytes(buf: *mut uint8_t, len: size_t) -> libc::c_int;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn RSA_size(rsa: *const RSA) -> libc::c_uint;
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
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bignum_st {
    pub d: *mut BN_ULONG,
    pub width: libc::c_int,
    pub dmax: libc::c_int,
    pub neg: libc::c_int,
    pub flags: libc::c_int,
}
pub type BN_ULONG = uint64_t;
pub type BIGNUM = bignum_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bn_mont_ctx_st {
    pub RR: BIGNUM,
    pub N: BIGNUM,
    pub n0: [BN_ULONG; 2],
}
pub type BN_MONT_CTX = bn_mont_ctx_st;
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
pub struct rsa_meth_st {
    pub app_data: *mut libc::c_void,
    pub init: Option::<unsafe extern "C" fn(*mut RSA) -> libc::c_int>,
    pub finish: Option::<unsafe extern "C" fn(*mut RSA) -> libc::c_int>,
    pub size: Option::<unsafe extern "C" fn(*const RSA) -> size_t>,
    pub sign: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            libc::c_uint,
            *mut uint8_t,
            *mut libc::c_uint,
            *const RSA,
        ) -> libc::c_int,
    >,
    pub sign_raw: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            *mut uint8_t,
            *mut RSA,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub verify_raw: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            *mut uint8_t,
            *mut RSA,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub decrypt: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            *mut uint8_t,
            *mut RSA,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub encrypt: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            *mut uint8_t,
            *mut RSA,
            libc::c_int,
        ) -> libc::c_int,
    >,
    pub private_transform: Option::<
        unsafe extern "C" fn(
            *mut RSA,
            *mut uint8_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub flags: libc::c_int,
}
pub type RSA = rsa_st;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct rsa_st {
    pub meth: *const RSA_METHOD,
    pub n: *mut BIGNUM,
    pub e: *mut BIGNUM,
    pub d: *mut BIGNUM,
    pub p: *mut BIGNUM,
    pub q: *mut BIGNUM,
    pub dmp1: *mut BIGNUM,
    pub dmq1: *mut BIGNUM,
    pub iqmp: *mut BIGNUM,
    pub pss: *mut RSASSA_PSS_PARAMS,
    pub ex_data: CRYPTO_EX_DATA,
    pub references: CRYPTO_refcount_t,
    pub flags: libc::c_int,
    pub lock: CRYPTO_MUTEX,
    pub mont_n: *mut BN_MONT_CTX,
    pub mont_p: *mut BN_MONT_CTX,
    pub mont_q: *mut BN_MONT_CTX,
    pub d_fixed: *mut BIGNUM,
    pub dmp1_fixed: *mut BIGNUM,
    pub dmq1_fixed: *mut BIGNUM,
    pub iqmp_mont: *mut BIGNUM,
    pub num_blindings: size_t,
    pub blindings: *mut *mut BN_BLINDING,
    pub blindings_inuse: *mut libc::c_uchar,
    pub blinding_fork_generation: uint64_t,
    #[bitfield(name = "private_key_frozen", ty = "libc::c_uint", bits = "0..=0")]
    pub private_key_frozen: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
pub type BN_BLINDING = bn_blinding_st;
pub type CRYPTO_MUTEX = crypto_mutex_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub union crypto_mutex_st {
    pub alignment: libc::c_double,
    pub padding: [uint8_t; 56],
}
pub type CRYPTO_refcount_t = uint32_t;
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
pub type RSASSA_PSS_PARAMS = rsassa_pss_params_st;
pub type RSA_METHOD = rsa_meth_st;
#[inline]
unsafe extern "C" fn OPENSSL_memcmp(
    mut s1: *const libc::c_void,
    mut s2: *const libc::c_void,
    mut n: size_t,
) -> libc::c_int {
    if n == 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    return memcmp(s1, s2, n);
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
#[inline]
unsafe extern "C" fn FIPS_service_indicator_lock_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_unlock_state() {}
#[no_mangle]
pub unsafe extern "C" fn RSA_padding_add_PKCS1_type_1(
    mut to: *mut uint8_t,
    mut to_len: size_t,
    mut from: *const uint8_t,
    mut from_len: size_t,
) -> libc::c_int {
    if to_len < 11 as libc::c_int as size_t {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            126 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/padding.c\0"
                as *const u8 as *const libc::c_char,
            78 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if from_len > to_len.wrapping_sub(11 as libc::c_int as size_t) {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            118 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/padding.c\0"
                as *const u8 as *const libc::c_char,
            83 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    *to.offset(0 as libc::c_int as isize) = 0 as libc::c_int as uint8_t;
    *to.offset(1 as libc::c_int as isize) = 1 as libc::c_int as uint8_t;
    OPENSSL_memset(
        to.offset(2 as libc::c_int as isize) as *mut libc::c_void,
        0xff as libc::c_int,
        to_len.wrapping_sub(3 as libc::c_int as size_t).wrapping_sub(from_len),
    );
    *to
        .offset(
            to_len.wrapping_sub(from_len).wrapping_sub(1 as libc::c_int as size_t)
                as isize,
        ) = 0 as libc::c_int as uint8_t;
    OPENSSL_memcpy(
        to.offset(to_len as isize).offset(-(from_len as isize)) as *mut libc::c_void,
        from as *const libc::c_void,
        from_len,
    );
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_padding_check_PKCS1_type_1(
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
    mut max_out: size_t,
    mut from: *const uint8_t,
    mut from_len: size_t,
) -> libc::c_int {
    if from_len < 2 as libc::c_int as size_t {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            116 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/padding.c\0"
                as *const u8 as *const libc::c_char,
            101 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if *from.offset(0 as libc::c_int as isize) as libc::c_int != 0 as libc::c_int
        || *from.offset(1 as libc::c_int as isize) as libc::c_int != 1 as libc::c_int
    {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            107 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/padding.c\0"
                as *const u8 as *const libc::c_char,
            107 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut pad: size_t = 0;
    pad = 2 as libc::c_int as size_t;
    while pad < from_len {
        if *from.offset(pad as isize) as libc::c_int == 0 as libc::c_int {
            break;
        }
        if *from.offset(pad as isize) as libc::c_int != 0xff as libc::c_int {
            ERR_put_error(
                4 as libc::c_int,
                0 as libc::c_int,
                102 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/padding.c\0"
                    as *const u8 as *const libc::c_char,
                119 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        pad = pad.wrapping_add(1);
        pad;
    }
    if pad == from_len {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            131 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/padding.c\0"
                as *const u8 as *const libc::c_char,
            125 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if pad < (2 as libc::c_int + 8 as libc::c_int) as size_t {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            103 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/padding.c\0"
                as *const u8 as *const libc::c_char,
            130 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    pad = pad.wrapping_add(1);
    pad;
    if from_len.wrapping_sub(pad) > max_out {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            113 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/padding.c\0"
                as *const u8 as *const libc::c_char,
            138 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    OPENSSL_memcpy(
        out as *mut libc::c_void,
        from.offset(pad as isize) as *const libc::c_void,
        from_len.wrapping_sub(pad),
    );
    *out_len = from_len.wrapping_sub(pad);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_padding_add_none(
    mut to: *mut uint8_t,
    mut to_len: size_t,
    mut from: *const uint8_t,
    mut from_len: size_t,
) -> libc::c_int {
    if from_len > to_len {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            114 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/padding.c\0"
                as *const u8 as *const libc::c_char,
            150 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if from_len < to_len {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            116 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/padding.c\0"
                as *const u8 as *const libc::c_char,
            155 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    OPENSSL_memcpy(to as *mut libc::c_void, from as *const libc::c_void, from_len);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn PKCS1_MGF1(
    mut out: *mut uint8_t,
    mut len: size_t,
    mut seed: *const uint8_t,
    mut seed_len: size_t,
    mut md: *const EVP_MD,
) -> libc::c_int {
    let mut current_block: u64;
    FIPS_service_indicator_lock_state();
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
    let mut md_len: size_t = EVP_MD_size(md);
    let mut i: uint32_t = 0 as libc::c_int as uint32_t;
    loop {
        if !(len > 0 as libc::c_int as size_t) {
            current_block = 7149356873433890176;
            break;
        }
        let mut counter: [uint8_t; 4] = [0; 4];
        counter[0 as libc::c_int as usize] = (i >> 24 as libc::c_int) as uint8_t;
        counter[1 as libc::c_int as usize] = (i >> 16 as libc::c_int) as uint8_t;
        counter[2 as libc::c_int as usize] = (i >> 8 as libc::c_int) as uint8_t;
        counter[3 as libc::c_int as usize] = i as uint8_t;
        if EVP_DigestInit_ex(&mut ctx, md, 0 as *mut ENGINE) == 0
            || EVP_DigestUpdate(&mut ctx, seed as *const libc::c_void, seed_len) == 0
            || EVP_DigestUpdate(
                &mut ctx,
                counter.as_mut_ptr() as *const libc::c_void,
                ::core::mem::size_of::<[uint8_t; 4]>() as libc::c_ulong,
            ) == 0
        {
            current_block = 14473181523424070065;
            break;
        }
        if md_len <= len {
            if EVP_DigestFinal_ex(&mut ctx, out, 0 as *mut libc::c_uint) == 0 {
                current_block = 14473181523424070065;
                break;
            }
            out = out.offset(md_len as isize);
            len = len.wrapping_sub(md_len);
        } else {
            let mut digest: [uint8_t; 64] = [0; 64];
            if EVP_DigestFinal_ex(&mut ctx, digest.as_mut_ptr(), 0 as *mut libc::c_uint)
                == 0
            {
                current_block = 14473181523424070065;
                break;
            }
            OPENSSL_memcpy(
                out as *mut libc::c_void,
                digest.as_mut_ptr() as *const libc::c_void,
                len,
            );
            len = 0 as libc::c_int as size_t;
        }
        i = i.wrapping_add(1);
        i;
    }
    match current_block {
        7149356873433890176 => {
            ret = 1 as libc::c_int;
        }
        _ => {}
    }
    EVP_MD_CTX_cleanup(&mut ctx);
    FIPS_service_indicator_unlock_state();
    return ret;
}
static mut kPSSZeroes: [uint8_t; 8] = [
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
];
#[no_mangle]
pub unsafe extern "C" fn RSA_verify_PKCS1_PSS_mgf1(
    mut rsa: *const RSA,
    mut mHash: *const uint8_t,
    mut Hash: *const EVP_MD,
    mut mgf1Hash: *const EVP_MD,
    mut EM: *const uint8_t,
    mut sLen: libc::c_int,
) -> libc::c_int {
    let mut MSBits: libc::c_uint = 0;
    let mut emLen: size_t = 0;
    let mut maskedDBLen: size_t = 0;
    let mut H: *const uint8_t = 0 as *const uint8_t;
    let mut salt_start: size_t = 0;
    let mut H_: [uint8_t; 64] = [0; 64];
    let mut current_block: u64;
    FIPS_service_indicator_lock_state();
    if mgf1Hash.is_null() {
        mgf1Hash = Hash;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut DB: *mut uint8_t = 0 as *mut uint8_t;
    let mut ctx: EVP_MD_CTX = env_md_ctx_st {
        digest: 0 as *const EVP_MD,
        md_data: 0 as *mut libc::c_void,
        update: None,
        pctx: 0 as *mut EVP_PKEY_CTX,
        pctx_ops: 0 as *const evp_md_pctx_ops,
        flags: 0,
    };
    EVP_MD_CTX_init(&mut ctx);
    let mut hLen: size_t = EVP_MD_size(Hash);
    if sLen == -(1 as libc::c_int) {
        sLen = hLen as libc::c_int;
        current_block = 12209867499936983673;
    } else if sLen == -(2 as libc::c_int) {
        sLen = -(2 as libc::c_int);
        current_block = 12209867499936983673;
    } else if sLen < -(2 as libc::c_int) {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            138 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/padding.c\0"
                as *const u8 as *const libc::c_char,
            238 as libc::c_int as libc::c_uint,
        );
        current_block = 1176002805869842764;
    } else {
        current_block = 12209867499936983673;
    }
    match current_block {
        12209867499936983673 => {
            MSBits = (BN_num_bits((*rsa).n))
                .wrapping_sub(1 as libc::c_int as libc::c_uint)
                & 0x7 as libc::c_int as libc::c_uint;
            emLen = RSA_size(rsa) as size_t;
            if *EM.offset(0 as libc::c_int as isize) as libc::c_int
                & (0xff as libc::c_int) << MSBits != 0
            {
                ERR_put_error(
                    4 as libc::c_int,
                    0 as libc::c_int,
                    122 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/padding.c\0"
                        as *const u8 as *const libc::c_char,
                    245 as libc::c_int as libc::c_uint,
                );
            } else {
                if MSBits == 0 as libc::c_int as libc::c_uint {
                    EM = EM.offset(1);
                    EM;
                    emLen = emLen.wrapping_sub(1);
                    emLen;
                }
                if emLen < hLen.wrapping_add(2 as libc::c_int as size_t)
                    || sLen >= 0 as libc::c_int
                        && emLen
                            < hLen
                                .wrapping_add(sLen as size_t)
                                .wrapping_add(2 as libc::c_int as size_t)
                {
                    ERR_put_error(
                        4 as libc::c_int,
                        0 as libc::c_int,
                        113 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/padding.c\0"
                            as *const u8 as *const libc::c_char,
                        255 as libc::c_int as libc::c_uint,
                    );
                } else if *EM
                    .offset(emLen.wrapping_sub(1 as libc::c_int as size_t) as isize)
                    as libc::c_int != 0xbc as libc::c_int
                {
                    ERR_put_error(
                        4 as libc::c_int,
                        0 as libc::c_int,
                        127 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/padding.c\0"
                            as *const u8 as *const libc::c_char,
                        259 as libc::c_int as libc::c_uint,
                    );
                } else {
                    maskedDBLen = emLen
                        .wrapping_sub(hLen)
                        .wrapping_sub(1 as libc::c_int as size_t);
                    H = EM.offset(maskedDBLen as isize);
                    DB = OPENSSL_malloc(maskedDBLen) as *mut uint8_t;
                    if !DB.is_null() {
                        if !(PKCS1_MGF1(DB, maskedDBLen, H, hLen, mgf1Hash) == 0) {
                            let mut i: size_t = 0 as libc::c_int as size_t;
                            while i < maskedDBLen {
                                let ref mut fresh0 = *DB.offset(i as isize);
                                *fresh0 = (*fresh0 as libc::c_int
                                    ^ *EM.offset(i as isize) as libc::c_int) as uint8_t;
                                i = i.wrapping_add(1);
                                i;
                            }
                            if MSBits != 0 {
                                let ref mut fresh1 = *DB.offset(0 as libc::c_int as isize);
                                *fresh1 = (*fresh1 as libc::c_int
                                    & 0xff as libc::c_int
                                        >> (8 as libc::c_int as libc::c_uint).wrapping_sub(MSBits))
                                    as uint8_t;
                            }
                            salt_start = 0;
                            salt_start = 0 as libc::c_int as size_t;
                            while *DB.offset(salt_start as isize) as libc::c_int
                                == 0 as libc::c_int
                                && salt_start
                                    < maskedDBLen.wrapping_sub(1 as libc::c_int as size_t)
                            {
                                salt_start = salt_start.wrapping_add(1);
                                salt_start;
                            }
                            if *DB.offset(salt_start as isize) as libc::c_int
                                != 0x1 as libc::c_int
                            {
                                ERR_put_error(
                                    4 as libc::c_int,
                                    0 as libc::c_int,
                                    139 as libc::c_int,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/padding.c\0"
                                        as *const u8 as *const libc::c_char,
                                    288 as libc::c_int as libc::c_uint,
                                );
                            } else {
                                salt_start = salt_start.wrapping_add(1);
                                salt_start;
                                if sLen >= 0 as libc::c_int
                                    && maskedDBLen.wrapping_sub(salt_start) != sLen as size_t
                                {
                                    ERR_put_error(
                                        4 as libc::c_int,
                                        0 as libc::c_int,
                                        138 as libc::c_int,
                                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/padding.c\0"
                                            as *const u8 as *const libc::c_char,
                                        294 as libc::c_int as libc::c_uint,
                                    );
                                } else {
                                    H_ = [0; 64];
                                    if !(EVP_DigestInit_ex(&mut ctx, Hash, 0 as *mut ENGINE)
                                        == 0
                                        || EVP_DigestUpdate(
                                            &mut ctx,
                                            kPSSZeroes.as_ptr() as *const libc::c_void,
                                            ::core::mem::size_of::<[uint8_t; 8]>() as libc::c_ulong,
                                        ) == 0
                                        || EVP_DigestUpdate(
                                            &mut ctx,
                                            mHash as *const libc::c_void,
                                            hLen,
                                        ) == 0
                                        || EVP_DigestUpdate(
                                            &mut ctx,
                                            DB.offset(salt_start as isize) as *const libc::c_void,
                                            maskedDBLen.wrapping_sub(salt_start),
                                        ) == 0
                                        || EVP_DigestFinal_ex(
                                            &mut ctx,
                                            H_.as_mut_ptr(),
                                            0 as *mut libc::c_uint,
                                        ) == 0)
                                    {
                                        if OPENSSL_memcmp(
                                            H_.as_mut_ptr() as *const libc::c_void,
                                            H as *const libc::c_void,
                                            hLen,
                                        ) != 0 as libc::c_int
                                        {
                                            ERR_put_error(
                                                4 as libc::c_int,
                                                0 as libc::c_int,
                                                105 as libc::c_int,
                                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/padding.c\0"
                                                    as *const u8 as *const libc::c_char,
                                                306 as libc::c_int as libc::c_uint,
                                            );
                                        } else {
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
        _ => {}
    }
    OPENSSL_free(DB as *mut libc::c_void);
    EVP_MD_CTX_cleanup(&mut ctx);
    FIPS_service_indicator_unlock_state();
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_padding_add_PKCS1_PSS_mgf1(
    mut rsa: *const RSA,
    mut EM: *mut libc::c_uchar,
    mut mHash: *const libc::c_uchar,
    mut Hash: *const EVP_MD,
    mut mgf1Hash: *const EVP_MD,
    mut sLenRequested: libc::c_int,
) -> libc::c_int {
    let mut sLen: size_t = 0;
    let mut ctx: EVP_MD_CTX = env_md_ctx_st {
        digest: 0 as *const EVP_MD,
        md_data: 0 as *mut libc::c_void,
        update: None,
        pctx: 0 as *mut EVP_PKEY_CTX,
        pctx_ops: 0 as *const evp_md_pctx_ops,
        flags: 0,
    };
    let mut digest_ok: libc::c_int = 0;
    let mut current_block: u64;
    FIPS_service_indicator_lock_state();
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut maskedDBLen: size_t = 0;
    let mut MSBits: size_t = 0;
    let mut emLen: size_t = 0;
    let mut hLen: size_t = 0;
    let mut H: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut salt: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut p: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    if mgf1Hash.is_null() {
        mgf1Hash = Hash;
    }
    hLen = EVP_MD_size(Hash);
    if BN_is_zero((*rsa).n) != 0 {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            120 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/padding.c\0"
                as *const u8 as *const libc::c_char,
            338 as libc::c_int as libc::c_uint,
        );
    } else {
        MSBits = ((BN_num_bits((*rsa).n)).wrapping_sub(1 as libc::c_int as libc::c_uint)
            & 0x7 as libc::c_int as libc::c_uint) as size_t;
        emLen = RSA_size(rsa) as size_t;
        if MSBits == 0 as libc::c_int as size_t {
            if emLen >= 1 as libc::c_int as size_t {} else {
                __assert_fail(
                    b"emLen >= 1\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/padding.c\0"
                        as *const u8 as *const libc::c_char,
                    345 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 125],
                        &[libc::c_char; 125],
                    >(
                        b"int RSA_padding_add_PKCS1_PSS_mgf1(const RSA *, unsigned char *, const unsigned char *, const EVP_MD *, const EVP_MD *, int)\0",
                    ))
                        .as_ptr(),
                );
            }
            'c_5668: {
                if emLen >= 1 as libc::c_int as size_t {} else {
                    __assert_fail(
                        b"emLen >= 1\0" as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/padding.c\0"
                            as *const u8 as *const libc::c_char,
                        345 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 125],
                            &[libc::c_char; 125],
                        >(
                            b"int RSA_padding_add_PKCS1_PSS_mgf1(const RSA *, unsigned char *, const unsigned char *, const EVP_MD *, const EVP_MD *, int)\0",
                        ))
                            .as_ptr(),
                    );
                }
            };
            let fresh2 = EM;
            EM = EM.offset(1);
            *fresh2 = 0 as libc::c_int as libc::c_uchar;
            emLen = emLen.wrapping_sub(1);
            emLen;
        }
        if emLen < hLen.wrapping_add(2 as libc::c_int as size_t) {
            ERR_put_error(
                4 as libc::c_int,
                0 as libc::c_int,
                114 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/padding.c\0"
                    as *const u8 as *const libc::c_char,
                351 as libc::c_int as libc::c_uint,
            );
        } else {
            sLen = 0;
            if sLenRequested == -(1 as libc::c_int) {
                sLen = hLen;
                current_block = 14576567515993809846;
            } else if sLenRequested == -(2 as libc::c_int) {
                sLen = emLen.wrapping_sub(hLen).wrapping_sub(2 as libc::c_int as size_t);
                current_block = 14576567515993809846;
            } else if sLenRequested < 0 as libc::c_int {
                ERR_put_error(
                    4 as libc::c_int,
                    0 as libc::c_int,
                    138 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/padding.c\0"
                        as *const u8 as *const libc::c_char,
                    365 as libc::c_int as libc::c_uint,
                );
                current_block = 758407647919264826;
            } else {
                sLen = sLenRequested as size_t;
                current_block = 14576567515993809846;
            }
            match current_block {
                758407647919264826 => {}
                _ => {
                    if emLen.wrapping_sub(hLen).wrapping_sub(2 as libc::c_int as size_t)
                        < sLen
                    {
                        ERR_put_error(
                            4 as libc::c_int,
                            0 as libc::c_int,
                            114 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/rsa/padding.c\0"
                                as *const u8 as *const libc::c_char,
                            372 as libc::c_int as libc::c_uint,
                        );
                    } else {
                        if sLen > 0 as libc::c_int as size_t {
                            salt = OPENSSL_malloc(sLen) as *mut libc::c_uchar;
                            if salt.is_null() {
                                current_block = 758407647919264826;
                            } else if RAND_bytes(salt, sLen) == 0 {
                                current_block = 758407647919264826;
                            } else {
                                current_block = 4761528863920922185;
                            }
                        } else {
                            current_block = 4761528863920922185;
                        }
                        match current_block {
                            758407647919264826 => {}
                            _ => {
                                maskedDBLen = emLen
                                    .wrapping_sub(hLen)
                                    .wrapping_sub(1 as libc::c_int as size_t);
                                H = EM.offset(maskedDBLen as isize);
                                ctx = env_md_ctx_st {
                                    digest: 0 as *const EVP_MD,
                                    md_data: 0 as *mut libc::c_void,
                                    update: None,
                                    pctx: 0 as *mut EVP_PKEY_CTX,
                                    pctx_ops: 0 as *const evp_md_pctx_ops,
                                    flags: 0,
                                };
                                EVP_MD_CTX_init(&mut ctx);
                                digest_ok = (EVP_DigestInit_ex(
                                    &mut ctx,
                                    Hash,
                                    0 as *mut ENGINE,
                                ) != 0
                                    && EVP_DigestUpdate(
                                        &mut ctx,
                                        kPSSZeroes.as_ptr() as *const libc::c_void,
                                        ::core::mem::size_of::<[uint8_t; 8]>() as libc::c_ulong,
                                    ) != 0
                                    && EVP_DigestUpdate(
                                        &mut ctx,
                                        mHash as *const libc::c_void,
                                        hLen,
                                    ) != 0
                                    && EVP_DigestUpdate(
                                        &mut ctx,
                                        salt as *const libc::c_void,
                                        sLen,
                                    ) != 0
                                    && EVP_DigestFinal_ex(&mut ctx, H, 0 as *mut libc::c_uint)
                                        != 0) as libc::c_int;
                                EVP_MD_CTX_cleanup(&mut ctx);
                                if !(digest_ok == 0) {
                                    if !(PKCS1_MGF1(EM, maskedDBLen, H, hLen, mgf1Hash) == 0) {
                                        p = EM;
                                        p = p
                                            .offset(
                                                emLen
                                                    .wrapping_sub(sLen)
                                                    .wrapping_sub(hLen)
                                                    .wrapping_sub(2 as libc::c_int as size_t) as isize,
                                            );
                                        let fresh3 = p;
                                        p = p.offset(1);
                                        *fresh3 = (*fresh3 as libc::c_int ^ 0x1 as libc::c_int)
                                            as libc::c_uchar;
                                        if sLen > 0 as libc::c_int as size_t {
                                            let mut i: size_t = 0 as libc::c_int as size_t;
                                            while i < sLen {
                                                let fresh4 = p;
                                                p = p.offset(1);
                                                *fresh4 = (*fresh4 as libc::c_int
                                                    ^ *salt.offset(i as isize) as libc::c_int) as libc::c_uchar;
                                                i = i.wrapping_add(1);
                                                i;
                                            }
                                        }
                                        if MSBits != 0 {
                                            let ref mut fresh5 = *EM.offset(0 as libc::c_int as isize);
                                            *fresh5 = (*fresh5 as libc::c_int
                                                & 0xff as libc::c_int
                                                    >> (8 as libc::c_int as size_t).wrapping_sub(MSBits))
                                                as libc::c_uchar;
                                        }
                                        *EM
                                            .offset(
                                                emLen.wrapping_sub(1 as libc::c_int as size_t) as isize,
                                            ) = 0xbc as libc::c_int as libc::c_uchar;
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
    OPENSSL_free(salt as *mut libc::c_void);
    FIPS_service_indicator_unlock_state();
    return ret;
}
