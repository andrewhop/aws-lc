#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(asm, extern_types)]
use core::arch::asm;
unsafe extern "C" {
    pub type bignum_ctx;
    pub type stack_st_void;
    pub type engine_st;
    pub type env_md_st;
    pub type bn_blinding_st;
    fn BN_bin2bn(in_0: *const uint8_t, len: size_t, ret: *mut BIGNUM) -> *mut BIGNUM;
    fn BN_bn2bin_padded(
        out: *mut uint8_t,
        len: size_t,
        in_0: *const BIGNUM,
    ) -> libc::c_int;
    fn BN_CTX_new() -> *mut BN_CTX;
    fn BN_CTX_free(ctx: *mut BN_CTX);
    fn BN_CTX_start(ctx: *mut BN_CTX);
    fn BN_CTX_get(ctx: *mut BN_CTX) -> *mut BIGNUM;
    fn BN_CTX_end(ctx: *mut BN_CTX);
    fn BN_ucmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_mod_exp_mont(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        p: *const BIGNUM,
        m: *const BIGNUM,
        ctx: *mut BN_CTX,
        mont: *const BN_MONT_CTX,
    ) -> libc::c_int;
    fn EVP_sha1() -> *const EVP_MD;
    fn EVP_Digest(
        data: *const libc::c_void,
        len: size_t,
        md_out: *mut uint8_t,
        out_size: *mut libc::c_uint,
        type_0: *const EVP_MD,
        impl_0: *mut ENGINE,
    ) -> libc::c_int;
    fn EVP_MD_size(md: *const EVP_MD) -> size_t;
    fn RAND_bytes(buf: *mut uint8_t, len: size_t) -> libc::c_int;
    fn RSA_padding_add_none(
        to: *mut uint8_t,
        to_len: size_t,
        from: *const uint8_t,
        from_len: size_t,
    ) -> libc::c_int;
    fn rsa_private_transform(
        rsa: *mut RSA,
        out: *mut uint8_t,
        in_0: *const uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn is_public_component_of_rsa_key_good(key: *const RSA) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn CRYPTO_memcmp(
        a: *const libc::c_void,
        b: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn RSA_sign_raw(
        rsa: *mut RSA,
        out_len: *mut size_t,
        out: *mut uint8_t,
        max_out: size_t,
        in_0: *const uint8_t,
        in_len: size_t,
        padding: libc::c_int,
    ) -> libc::c_int;
    fn RSA_verify_raw(
        rsa: *mut RSA,
        out_len: *mut size_t,
        out: *mut uint8_t,
        max_out: size_t,
        in_0: *const uint8_t,
        in_len: size_t,
        padding: libc::c_int,
    ) -> libc::c_int;
    fn RSA_size(rsa: *const RSA) -> libc::c_uint;
    fn PKCS1_MGF1(
        out: *mut uint8_t,
        len: size_t,
        seed: *const uint8_t,
        seed_len: size_t,
        md: *const EVP_MD,
    ) -> libc::c_int;
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
    fn BN_MONT_CTX_set_locked(
        pmont: *mut *mut BN_MONT_CTX,
        lock: *mut CRYPTO_MUTEX,
        mod_0: *const BIGNUM,
        bn_ctx: *mut BN_CTX,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type int64_t = __int64_t;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type BN_CTX = bignum_ctx;
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
pub type CRYPTO_refcount_t = uint32_t;
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bn_mont_ctx_st {
    pub RR: BIGNUM,
    pub N: BIGNUM,
    pub n0: [BN_ULONG; 2],
}
pub type BN_MONT_CTX = bn_mont_ctx_st;
pub type ENGINE = engine_st;
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
pub type RSASSA_PSS_PARAMS = rsassa_pss_params_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rsassa_pss_params_st {
    pub hash_algor: *mut RSA_ALGOR_IDENTIFIER,
    pub mask_gen_algor: *mut RSA_MGA_IDENTIFIER,
    pub salt_len: *mut RSA_INTEGER,
    pub trailer_field: *mut RSA_INTEGER,
}
pub type RSA_INTEGER = rsa_integer_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rsa_integer_st {
    pub value: int64_t,
}
pub type RSA_MGA_IDENTIFIER = rsa_mga_identifier_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rsa_mga_identifier_st {
    pub mask_gen: *mut RSA_ALGOR_IDENTIFIER,
    pub one_way_hash: *mut RSA_ALGOR_IDENTIFIER,
}
pub type RSA_ALGOR_IDENTIFIER = rsa_algor_identifier_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rsa_algor_identifier_st {
    pub nid: libc::c_int,
}
pub type RSA_METHOD = rsa_meth_st;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_552_error_is_int_is_not_the_same_size_as_uint32_t {
    #[bitfield(
        name = "static_assertion_at_line_552_error_is_int_is_not_the_same_size_as_uint32_t",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_552_error_is_int_is_not_the_same_size_as_uint32_t: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
pub type crypto_word_t = uint64_t;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_242_error_is_size_t_does_not_fit_in_crypto_word_t {
    #[bitfield(
        name = "static_assertion_at_line_242_error_is_size_t_does_not_fit_in_crypto_word_t",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_242_error_is_size_t_does_not_fit_in_crypto_word_t: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[inline]
unsafe extern "C" fn value_barrier_w(mut a: crypto_word_t) -> crypto_word_t {
    asm!("", inlateout(reg) a, options(preserves_flags, pure, readonly, att_syntax));
    return a;
}
#[inline]
unsafe extern "C" fn value_barrier_u32(mut a: uint32_t) -> uint32_t {
    asm!("", inlateout(reg) a, options(preserves_flags, pure, readonly, att_syntax));
    return a;
}
#[inline]
unsafe extern "C" fn constant_time_msb_w(mut a: crypto_word_t) -> crypto_word_t {
    return (0 as libc::c_uint as crypto_word_t)
        .wrapping_sub(
            a
                >> (::core::mem::size_of::<crypto_word_t>() as libc::c_ulong)
                    .wrapping_mul(8 as libc::c_int as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        );
}
#[inline]
unsafe extern "C" fn constant_time_lt_w(
    mut a: crypto_word_t,
    mut b: crypto_word_t,
) -> crypto_word_t {
    return constant_time_msb_w(a ^ (a ^ b | a.wrapping_sub(b) ^ a));
}
#[inline]
unsafe extern "C" fn constant_time_ge_w(
    mut a: crypto_word_t,
    mut b: crypto_word_t,
) -> crypto_word_t {
    return !constant_time_lt_w(a, b);
}
#[inline]
unsafe extern "C" fn constant_time_is_zero_w(mut a: crypto_word_t) -> crypto_word_t {
    return constant_time_msb_w(!a & a.wrapping_sub(1 as libc::c_int as crypto_word_t));
}
#[inline]
unsafe extern "C" fn constant_time_eq_w(
    mut a: crypto_word_t,
    mut b: crypto_word_t,
) -> crypto_word_t {
    return constant_time_is_zero_w(a ^ b);
}
#[inline]
unsafe extern "C" fn constant_time_select_w(
    mut mask: crypto_word_t,
    mut a: crypto_word_t,
    mut b: crypto_word_t,
) -> crypto_word_t {
    return value_barrier_w(mask) & a | value_barrier_w(!mask) & b;
}
#[inline]
unsafe extern "C" fn constant_time_declassify_w(mut v: crypto_word_t) -> crypto_word_t {
    return value_barrier_w(v);
}
#[inline]
unsafe extern "C" fn constant_time_declassify_int(mut v: libc::c_int) -> libc::c_int {
    return value_barrier_u32(v as uint32_t) as libc::c_int;
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
unsafe extern "C" fn rand_nonzero(mut out: *mut uint8_t, mut len: size_t) {
    RAND_bytes(out, len);
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < len {
        while constant_time_declassify_int(
            (*out.offset(i as isize) as libc::c_int == 0 as libc::c_int) as libc::c_int,
        ) != 0
        {
            RAND_bytes(out.offset(i as isize), 1 as libc::c_int as size_t);
        }
        i = i.wrapping_add(1);
        i;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn RSA_padding_add_PKCS1_OAEP_mgf1(
    mut to: *mut uint8_t,
    mut to_len: size_t,
    mut from: *const uint8_t,
    mut from_len: size_t,
    mut param: *const uint8_t,
    mut param_len: size_t,
    mut md: *const EVP_MD,
    mut mgf1md: *const EVP_MD,
) -> libc::c_int {
    let mut seedmask: [uint8_t; 64] = [0; 64];
    if md.is_null() {
        md = EVP_sha1();
    }
    if mgf1md.is_null() {
        mgf1md = md;
    }
    let mut mdlen: size_t = EVP_MD_size(md);
    if to_len
        < (2 as libc::c_int as size_t * mdlen).wrapping_add(2 as libc::c_int as size_t)
    {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            126 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_crypt.c\0"
                as *const u8 as *const libc::c_char,
            100 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut emlen: size_t = to_len.wrapping_sub(1 as libc::c_int as size_t);
    if from_len
        > emlen
            .wrapping_sub(2 as libc::c_int as size_t * mdlen)
            .wrapping_sub(1 as libc::c_int as size_t)
    {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            114 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_crypt.c\0"
                as *const u8 as *const libc::c_char,
            106 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if emlen
        < (2 as libc::c_int as size_t * mdlen).wrapping_add(1 as libc::c_int as size_t)
    {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            126 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_crypt.c\0"
                as *const u8 as *const libc::c_char,
            111 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    *to.offset(0 as libc::c_int as isize) = 0 as libc::c_int as uint8_t;
    let mut seed: *mut uint8_t = to.offset(1 as libc::c_int as isize);
    let mut db: *mut uint8_t = to
        .offset(mdlen as isize)
        .offset(1 as libc::c_int as isize);
    let mut dbmask: *mut uint8_t = 0 as *mut uint8_t;
    let mut ret: libc::c_int = 0 as libc::c_int;
    if !(EVP_Digest(
        param as *const libc::c_void,
        param_len,
        db,
        0 as *mut libc::c_uint,
        md,
        0 as *mut ENGINE,
    ) == 0)
    {
        OPENSSL_memset(
            db.offset(mdlen as isize) as *mut libc::c_void,
            0 as libc::c_int,
            emlen
                .wrapping_sub(from_len)
                .wrapping_sub(2 as libc::c_int as size_t * mdlen)
                .wrapping_sub(1 as libc::c_int as size_t),
        );
        *db
            .offset(
                emlen
                    .wrapping_sub(from_len)
                    .wrapping_sub(mdlen)
                    .wrapping_sub(1 as libc::c_int as size_t) as isize,
            ) = 0x1 as libc::c_int as uint8_t;
        OPENSSL_memcpy(
            db
                .offset(emlen as isize)
                .offset(-(from_len as isize))
                .offset(-(mdlen as isize)) as *mut libc::c_void,
            from as *const libc::c_void,
            from_len,
        );
        if !(RAND_bytes(seed, mdlen) == 0) {
            dbmask = OPENSSL_malloc(emlen.wrapping_sub(mdlen)) as *mut uint8_t;
            if !dbmask.is_null() {
                if !(PKCS1_MGF1(dbmask, emlen.wrapping_sub(mdlen), seed, mdlen, mgf1md)
                    == 0)
                {
                    let mut i: size_t = 0 as libc::c_int as size_t;
                    while i < emlen.wrapping_sub(mdlen) {
                        let ref mut fresh0 = *db.offset(i as isize);
                        *fresh0 = (*fresh0 as libc::c_int
                            ^ *dbmask.offset(i as isize) as libc::c_int) as uint8_t;
                        i = i.wrapping_add(1);
                        i;
                    }
                    seedmask = [0; 64];
                    if !(PKCS1_MGF1(
                        seedmask.as_mut_ptr(),
                        mdlen,
                        db,
                        emlen.wrapping_sub(mdlen),
                        mgf1md,
                    ) == 0)
                    {
                        let mut i_0: size_t = 0 as libc::c_int as size_t;
                        while i_0 < mdlen {
                            let ref mut fresh1 = *seed.offset(i_0 as isize);
                            *fresh1 = (*fresh1 as libc::c_int
                                ^ seedmask[i_0 as usize] as libc::c_int) as uint8_t;
                            i_0 = i_0.wrapping_add(1);
                            i_0;
                        }
                        ret = 1 as libc::c_int;
                    }
                }
            }
        }
    }
    OPENSSL_free(dbmask as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn RSA_padding_check_PKCS1_OAEP_mgf1(
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
    mut max_out: size_t,
    mut from: *const uint8_t,
    mut from_len: size_t,
    mut param: *const uint8_t,
    mut param_len: size_t,
    mut md: *const EVP_MD,
    mut mgf1md: *const EVP_MD,
) -> libc::c_int {
    let mut dblen: size_t = 0;
    let mut maskedseed: *const uint8_t = 0 as *const uint8_t;
    let mut maskeddb: *const uint8_t = 0 as *const uint8_t;
    let mut seed: [uint8_t; 64] = [0; 64];
    let mut phash: [uint8_t; 64] = [0; 64];
    let mut bad: crypto_word_t = 0;
    let mut looking_for_one_byte: crypto_word_t = 0;
    let mut one_index: size_t = 0;
    let mut mlen: size_t = 0;
    let mut current_block: u64;
    let mut db: *mut uint8_t = 0 as *mut uint8_t;
    if md.is_null() {
        md = EVP_sha1();
    }
    if mgf1md.is_null() {
        mgf1md = md;
    }
    let mut mdlen: size_t = EVP_MD_size(md);
    if from_len
        < (1 as libc::c_int as size_t)
            .wrapping_add(2 as libc::c_int as size_t * mdlen)
            .wrapping_add(1 as libc::c_int as size_t)
    {
        current_block = 14112803818675051407;
    } else {
        dblen = from_len.wrapping_sub(mdlen).wrapping_sub(1 as libc::c_int as size_t);
        db = OPENSSL_malloc(dblen) as *mut uint8_t;
        if db.is_null() {
            current_block = 15433781050925556992;
        } else {
            maskedseed = from.offset(1 as libc::c_int as isize);
            maskeddb = from.offset(1 as libc::c_int as isize).offset(mdlen as isize);
            seed = [0; 64];
            if PKCS1_MGF1(seed.as_mut_ptr(), mdlen, maskeddb, dblen, mgf1md) == 0 {
                current_block = 15433781050925556992;
            } else {
                let mut i: size_t = 0 as libc::c_int as size_t;
                while i < mdlen {
                    seed[i
                        as usize] = (seed[i as usize] as libc::c_int
                        ^ *maskedseed.offset(i as isize) as libc::c_int) as uint8_t;
                    i = i.wrapping_add(1);
                    i;
                }
                if PKCS1_MGF1(db, dblen, seed.as_mut_ptr(), mdlen, mgf1md) == 0 {
                    current_block = 15433781050925556992;
                } else {
                    let mut i_0: size_t = 0 as libc::c_int as size_t;
                    while i_0 < dblen {
                        let ref mut fresh2 = *db.offset(i_0 as isize);
                        *fresh2 = (*fresh2 as libc::c_int
                            ^ *maskeddb.offset(i_0 as isize) as libc::c_int) as uint8_t;
                        i_0 = i_0.wrapping_add(1);
                        i_0;
                    }
                    phash = [0; 64];
                    if EVP_Digest(
                        param as *const libc::c_void,
                        param_len,
                        phash.as_mut_ptr(),
                        0 as *mut libc::c_uint,
                        md,
                        0 as *mut ENGINE,
                    ) == 0
                    {
                        current_block = 15433781050925556992;
                    } else {
                        bad = !constant_time_is_zero_w(
                            CRYPTO_memcmp(
                                db as *const libc::c_void,
                                phash.as_mut_ptr() as *const libc::c_void,
                                mdlen,
                            ) as crypto_word_t,
                        );
                        bad
                            |= !constant_time_is_zero_w(
                                *from.offset(0 as libc::c_int as isize) as crypto_word_t,
                            );
                        looking_for_one_byte = !(0 as libc::c_int as crypto_word_t);
                        one_index = 0 as libc::c_int as size_t;
                        let mut i_1: size_t = mdlen;
                        while i_1 < dblen {
                            let mut equals1: crypto_word_t = constant_time_eq_w(
                                *db.offset(i_1 as isize) as crypto_word_t,
                                1 as libc::c_int as crypto_word_t,
                            );
                            let mut equals0: crypto_word_t = constant_time_eq_w(
                                *db.offset(i_1 as isize) as crypto_word_t,
                                0 as libc::c_int as crypto_word_t,
                            );
                            one_index = constant_time_select_w(
                                looking_for_one_byte & equals1,
                                i_1,
                                one_index,
                            );
                            looking_for_one_byte = constant_time_select_w(
                                equals1,
                                0 as libc::c_int as crypto_word_t,
                                looking_for_one_byte,
                            );
                            bad |= looking_for_one_byte & !equals0;
                            i_1 = i_1.wrapping_add(1);
                            i_1;
                        }
                        bad |= looking_for_one_byte;
                        if constant_time_declassify_w(bad) != 0 {
                            current_block = 14112803818675051407;
                        } else {
                            one_index = constant_time_declassify_w(one_index);
                            one_index = one_index.wrapping_add(1);
                            one_index;
                            mlen = dblen.wrapping_sub(one_index);
                            if max_out < mlen {
                                ERR_put_error(
                                    4 as libc::c_int,
                                    0 as libc::c_int,
                                    113 as libc::c_int,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_crypt.c\0"
                                        as *const u8 as *const libc::c_char,
                                    248 as libc::c_int as libc::c_uint,
                                );
                            } else {
                                OPENSSL_memcpy(
                                    out as *mut libc::c_void,
                                    db.offset(one_index as isize) as *const libc::c_void,
                                    mlen,
                                );
                                *out_len = mlen;
                                OPENSSL_free(db as *mut libc::c_void);
                                return 1 as libc::c_int;
                            }
                            current_block = 15433781050925556992;
                        }
                    }
                }
            }
        }
    }
    match current_block {
        14112803818675051407 => {
            ERR_put_error(
                4 as libc::c_int,
                0 as libc::c_int,
                133 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_crypt.c\0"
                    as *const u8 as *const libc::c_char,
                260 as libc::c_int as libc::c_uint,
            );
        }
        _ => {}
    }
    OPENSSL_free(db as *mut libc::c_void);
    return 0 as libc::c_int;
}
unsafe extern "C" fn rsa_padding_add_PKCS1_type_2(
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
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_crypt.c\0"
                as *const u8 as *const libc::c_char,
            270 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if from_len > to_len.wrapping_sub(11 as libc::c_int as size_t) {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            114 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_crypt.c\0"
                as *const u8 as *const libc::c_char,
            275 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    *to.offset(0 as libc::c_int as isize) = 0 as libc::c_int as uint8_t;
    *to.offset(1 as libc::c_int as isize) = 2 as libc::c_int as uint8_t;
    let mut padding_len: size_t = to_len
        .wrapping_sub(3 as libc::c_int as size_t)
        .wrapping_sub(from_len);
    rand_nonzero(to.offset(2 as libc::c_int as isize), padding_len);
    *to
        .offset(
            (2 as libc::c_int as size_t).wrapping_add(padding_len) as isize,
        ) = 0 as libc::c_int as uint8_t;
    OPENSSL_memcpy(
        to.offset(to_len as isize).offset(-(from_len as isize)) as *mut libc::c_void,
        from as *const libc::c_void,
        from_len,
    );
    return 1 as libc::c_int;
}
unsafe extern "C" fn rsa_padding_check_PKCS1_type_2(
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
    mut max_out: size_t,
    mut from: *const uint8_t,
    mut from_len: size_t,
) -> libc::c_int {
    if from_len == 0 as libc::c_int as size_t {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            120 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_crypt.c\0"
                as *const u8 as *const libc::c_char,
            293 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if from_len < 11 as libc::c_int as size_t {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            126 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_crypt.c\0"
                as *const u8 as *const libc::c_char,
            302 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut first_byte_is_zero: crypto_word_t = constant_time_eq_w(
        *from.offset(0 as libc::c_int as isize) as crypto_word_t,
        0 as libc::c_int as crypto_word_t,
    );
    let mut second_byte_is_two: crypto_word_t = constant_time_eq_w(
        *from.offset(1 as libc::c_int as isize) as crypto_word_t,
        2 as libc::c_int as crypto_word_t,
    );
    let mut zero_index: crypto_word_t = 0 as libc::c_int as crypto_word_t;
    let mut looking_for_index: crypto_word_t = !(0 as libc::c_int as crypto_word_t);
    let mut i: size_t = 2 as libc::c_int as size_t;
    while i < from_len {
        let mut equals0: crypto_word_t = constant_time_is_zero_w(
            *from.offset(i as isize) as crypto_word_t,
        );
        zero_index = constant_time_select_w(looking_for_index & equals0, i, zero_index);
        looking_for_index = constant_time_select_w(
            equals0,
            0 as libc::c_int as crypto_word_t,
            looking_for_index,
        );
        i = i.wrapping_add(1);
        i;
    }
    let mut valid_index: crypto_word_t = first_byte_is_zero;
    valid_index &= second_byte_is_two;
    valid_index &= !looking_for_index;
    valid_index
        &= constant_time_ge_w(
            zero_index,
            (2 as libc::c_int + 8 as libc::c_int) as crypto_word_t,
        );
    zero_index = zero_index.wrapping_add(1);
    zero_index;
    if valid_index == 0 {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            137 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_crypt.c\0"
                as *const u8 as *const libc::c_char,
            339 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let msg_len: size_t = from_len.wrapping_sub(zero_index);
    if msg_len > max_out {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            137 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_crypt.c\0"
                as *const u8 as *const libc::c_char,
            347 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    OPENSSL_memcpy(
        out as *mut libc::c_void,
        &*from.offset(zero_index as isize) as *const uint8_t as *const libc::c_void,
        msg_len,
    );
    *out_len = msg_len;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn RSA_public_encrypt(
    mut flen: size_t,
    mut from: *const uint8_t,
    mut to: *mut uint8_t,
    mut rsa: *mut RSA,
    mut padding: libc::c_int,
) -> libc::c_int {
    let mut out_len: size_t = 0;
    if RSA_encrypt(rsa, &mut out_len, to, RSA_size(rsa) as size_t, from, flen, padding)
        == 0
    {
        return -(1 as libc::c_int);
    }
    if out_len > 2147483647 as libc::c_int as size_t {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_crypt.c\0"
                as *const u8 as *const libc::c_char,
            365 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    return out_len as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn RSA_private_encrypt(
    mut flen: size_t,
    mut from: *const uint8_t,
    mut to: *mut uint8_t,
    mut rsa: *mut RSA,
    mut padding: libc::c_int,
) -> libc::c_int {
    let mut out_len: size_t = 0;
    if RSA_sign_raw(rsa, &mut out_len, to, RSA_size(rsa) as size_t, from, flen, padding)
        == 0
    {
        return -(1 as libc::c_int);
    }
    if out_len > 2147483647 as libc::c_int as size_t {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_crypt.c\0"
                as *const u8 as *const libc::c_char,
            380 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    return out_len as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn RSA_encrypt(
    mut rsa: *mut RSA,
    mut out_len: *mut size_t,
    mut out: *mut uint8_t,
    mut max_out: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut padding: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    if !((*rsa).meth).is_null() && ((*(*rsa).meth).encrypt).is_some() {
        let mut ret: libc::c_int = ((*(*rsa).meth).encrypt)
            .expect(
                "non-null function pointer",
            )(max_out as libc::c_int, in_0, out, rsa, padding);
        if ret < 0 as libc::c_int {
            *out_len = 0 as libc::c_int as size_t;
            return 0 as libc::c_int;
        }
        *out_len = ret as size_t;
        return 1 as libc::c_int;
    }
    if ((*rsa).n).is_null() || ((*rsa).e).is_null() {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            144 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_crypt.c\0"
                as *const u8 as *const libc::c_char,
            406 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if is_public_component_of_rsa_key_good(rsa) == 0 {
        return 0 as libc::c_int;
    }
    let rsa_size: libc::c_uint = RSA_size(rsa);
    let mut f: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut result: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut buf: *mut uint8_t = 0 as *mut uint8_t;
    let mut ctx: *mut BN_CTX = 0 as *mut BN_CTX;
    let mut i: libc::c_int = 0;
    let mut ret_0: libc::c_int = 0 as libc::c_int;
    if max_out < rsa_size as size_t {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            135 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_crypt.c\0"
                as *const u8 as *const libc::c_char,
            421 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    ctx = BN_CTX_new();
    if !ctx.is_null() {
        BN_CTX_start(ctx);
        f = BN_CTX_get(ctx);
        result = BN_CTX_get(ctx);
        buf = OPENSSL_malloc(rsa_size as size_t) as *mut uint8_t;
        if !(f.is_null() || result.is_null() || buf.is_null()) {
            match padding {
                1 => {
                    i = rsa_padding_add_PKCS1_type_2(
                        buf,
                        rsa_size as size_t,
                        in_0,
                        in_len,
                    );
                    current_block = 15125582407903384992;
                }
                4 => {
                    i = RSA_padding_add_PKCS1_OAEP_mgf1(
                        buf,
                        rsa_size as size_t,
                        in_0,
                        in_len,
                        0 as *const uint8_t,
                        0 as libc::c_int as size_t,
                        0 as *const EVP_MD,
                        0 as *const EVP_MD,
                    );
                    current_block = 15125582407903384992;
                }
                3 => {
                    i = RSA_padding_add_none(buf, rsa_size as size_t, in_0, in_len);
                    current_block = 15125582407903384992;
                }
                _ => {
                    ERR_put_error(
                        4 as libc::c_int,
                        0 as libc::c_int,
                        143 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_crypt.c\0"
                            as *const u8 as *const libc::c_char,
                        451 as libc::c_int as libc::c_uint,
                    );
                    current_block = 5449370915243334280;
                }
            }
            match current_block {
                5449370915243334280 => {}
                _ => {
                    if !(i <= 0 as libc::c_int) {
                        if !(BN_bin2bn(buf, rsa_size as size_t, f)).is_null() {
                            if BN_ucmp(f, (*rsa).n) >= 0 as libc::c_int {
                                ERR_put_error(
                                    4 as libc::c_int,
                                    0 as libc::c_int,
                                    115 as libc::c_int,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_crypt.c\0"
                                        as *const u8 as *const libc::c_char,
                                    465 as libc::c_int as libc::c_uint,
                                );
                            } else if !(BN_MONT_CTX_set_locked(
                                &mut (*rsa).mont_n,
                                &mut (*rsa).lock,
                                (*rsa).n,
                                ctx,
                            ) == 0
                                || BN_mod_exp_mont(
                                    result,
                                    f,
                                    (*rsa).e,
                                    &mut (*(*rsa).mont_n).N,
                                    ctx,
                                    (*rsa).mont_n,
                                ) == 0)
                            {
                                if BN_bn2bin_padded(out, rsa_size as size_t, result) == 0 {
                                    ERR_put_error(
                                        4 as libc::c_int,
                                        0 as libc::c_int,
                                        4 as libc::c_int | 64 as libc::c_int,
                                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_crypt.c\0"
                                            as *const u8 as *const libc::c_char,
                                        477 as libc::c_int as libc::c_uint,
                                    );
                                } else {
                                    *out_len = rsa_size as size_t;
                                    ret_0 = 1 as libc::c_int;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if !ctx.is_null() {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    OPENSSL_free(buf as *mut libc::c_void);
    return ret_0;
}
unsafe extern "C" fn rsa_default_decrypt(
    mut rsa: *mut RSA,
    mut out_len: *mut size_t,
    mut out: *mut uint8_t,
    mut max_out: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut padding: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let rsa_size: libc::c_uint = RSA_size(rsa);
    let mut buf: *mut uint8_t = 0 as *mut uint8_t;
    let mut ret: libc::c_int = 0 as libc::c_int;
    if max_out < rsa_size as size_t {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            135 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_crypt.c\0"
                as *const u8 as *const libc::c_char,
            502 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if padding == 3 as libc::c_int {
        buf = out;
        current_block = 8515828400728868193;
    } else {
        buf = OPENSSL_malloc(rsa_size as size_t) as *mut uint8_t;
        if buf.is_null() {
            current_block = 3153468260974884230;
        } else {
            current_block = 8515828400728868193;
        }
    }
    match current_block {
        8515828400728868193 => {
            if in_len != rsa_size as size_t {
                ERR_put_error(
                    4 as libc::c_int,
                    0 as libc::c_int,
                    112 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_crypt.c\0"
                        as *const u8 as *const libc::c_char,
                    517 as libc::c_int as libc::c_uint,
                );
            } else if !(rsa_private_transform(rsa, buf, in_0, rsa_size as size_t) == 0) {
                match padding {
                    1 => {
                        ret = rsa_padding_check_PKCS1_type_2(
                            out,
                            out_len,
                            rsa_size as size_t,
                            buf,
                            rsa_size as size_t,
                        );
                        current_block = 2838571290723028321;
                    }
                    4 => {
                        ret = RSA_padding_check_PKCS1_OAEP_mgf1(
                            out,
                            out_len,
                            rsa_size as size_t,
                            buf,
                            rsa_size as size_t,
                            0 as *const uint8_t,
                            0 as libc::c_int as size_t,
                            0 as *const EVP_MD,
                            0 as *const EVP_MD,
                        );
                        current_block = 2838571290723028321;
                    }
                    3 => {
                        *out_len = rsa_size as size_t;
                        ret = 1 as libc::c_int;
                        current_block = 2838571290723028321;
                    }
                    _ => {
                        ERR_put_error(
                            4 as libc::c_int,
                            0 as libc::c_int,
                            143 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_crypt.c\0"
                                as *const u8 as *const libc::c_char,
                            540 as libc::c_int as libc::c_uint,
                        );
                        current_block = 3153468260974884230;
                    }
                }
                match current_block {
                    3153468260974884230 => {}
                    _ => {
                        if ret == 0 {
                            ERR_put_error(
                                4 as libc::c_int,
                                0 as libc::c_int,
                                136 as libc::c_int,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_crypt.c\0"
                                    as *const u8 as *const libc::c_char,
                                546 as libc::c_int as libc::c_uint,
                            );
                        }
                    }
                }
            }
        }
        _ => {}
    }
    if padding != 3 as libc::c_int {
        OPENSSL_free(buf as *mut libc::c_void);
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn RSA_decrypt(
    mut rsa: *mut RSA,
    mut out_len: *mut size_t,
    mut out: *mut uint8_t,
    mut max_out: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut padding: libc::c_int,
) -> libc::c_int {
    if !((*rsa).meth).is_null() && ((*(*rsa).meth).decrypt).is_some() {
        let mut ret: libc::c_int = ((*(*rsa).meth).decrypt)
            .expect(
                "non-null function pointer",
            )(max_out as libc::c_int, in_0, out, rsa, padding);
        if ret < 0 as libc::c_int {
            *out_len = 0 as libc::c_int as size_t;
            return 0 as libc::c_int;
        }
        *out_len = ret as size_t;
        return 1 as libc::c_int;
    }
    return rsa_default_decrypt(rsa, out_len, out, max_out, in_0, in_len, padding);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn RSA_private_decrypt(
    mut flen: size_t,
    mut from: *const uint8_t,
    mut to: *mut uint8_t,
    mut rsa: *mut RSA,
    mut padding: libc::c_int,
) -> libc::c_int {
    let mut out_len: size_t = 0;
    if RSA_decrypt(rsa, &mut out_len, to, RSA_size(rsa) as size_t, from, flen, padding)
        == 0
    {
        return -(1 as libc::c_int);
    }
    if out_len > 2147483647 as libc::c_int as size_t {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_crypt.c\0"
                as *const u8 as *const libc::c_char,
            588 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    return out_len as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn RSA_public_decrypt(
    mut flen: size_t,
    mut from: *const uint8_t,
    mut to: *mut uint8_t,
    mut rsa: *mut RSA,
    mut padding: libc::c_int,
) -> libc::c_int {
    let mut out_len: size_t = 0;
    if RSA_verify_raw(
        rsa,
        &mut out_len,
        to,
        RSA_size(rsa) as size_t,
        from,
        flen,
        padding,
    ) == 0
    {
        return -(1 as libc::c_int);
    }
    if out_len > 2147483647 as libc::c_int as size_t {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsa_crypt.c\0"
                as *const u8 as *const libc::c_char,
            602 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    return out_len as libc::c_int;
}
