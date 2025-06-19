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
    pub type asn1_pctx_st;
    pub type bignum_ctx;
    pub type stack_st_void;
    pub type engine_st;
    pub type env_md_st;
    pub type evp_pkey_st;
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type stack_st_CRYPTO_EX_DATA_FUNCS;
    fn d2i_DSA_SIG(
        out_sig: *mut *mut DSA_SIG,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut DSA_SIG;
    fn i2d_DSA_SIG(in_0: *const DSA_SIG, outp: *mut *mut uint8_t) -> libc::c_int;
    fn BN_new() -> *mut BIGNUM;
    fn BN_init(bn: *mut BIGNUM);
    fn BN_free(bn: *mut BIGNUM);
    fn BN_clear_free(bn: *mut BIGNUM);
    fn BN_dup(src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_copy(dest: *mut BIGNUM, src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_value_one() -> *const BIGNUM;
    fn BN_num_bits(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_num_bytes(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_zero(bn: *mut BIGNUM);
    fn BN_set_word(bn: *mut BIGNUM, value: BN_ULONG) -> libc::c_int;
    fn BN_is_negative(bn: *const BIGNUM) -> libc::c_int;
    fn BN_bin2bn(in_0: *const uint8_t, len: size_t, ret: *mut BIGNUM) -> *mut BIGNUM;
    fn BN_CTX_new() -> *mut BN_CTX;
    fn BN_CTX_free(ctx: *mut BN_CTX);
    fn BN_CTX_start(ctx: *mut BN_CTX);
    fn BN_CTX_get(ctx: *mut BN_CTX) -> *mut BIGNUM;
    fn BN_CTX_end(ctx: *mut BN_CTX);
    fn BN_add(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_sub(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_div(
        quotient: *mut BIGNUM,
        rem: *mut BIGNUM,
        numerator: *const BIGNUM,
        divisor: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_ucmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_is_zero(bn: *const BIGNUM) -> libc::c_int;
    fn BN_is_one(bn: *const BIGNUM) -> libc::c_int;
    fn BN_lshift(r: *mut BIGNUM, a: *const BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_lshift1(r: *mut BIGNUM, a: *const BIGNUM) -> libc::c_int;
    fn BN_mask_bits(a: *mut BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_mod_mul(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        b: *const BIGNUM,
        m: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_rand_range_ex(
        r: *mut BIGNUM,
        min_inclusive: BN_ULONG,
        max_exclusive: *const BIGNUM,
    ) -> libc::c_int;
    fn BN_GENCB_call(
        callback: *mut BN_GENCB,
        event: libc::c_int,
        n: libc::c_int,
    ) -> libc::c_int;
    fn BN_is_prime_fasttest_ex(
        candidate: *const BIGNUM,
        checks: libc::c_int,
        ctx: *mut BN_CTX,
        do_trial_division: libc::c_int,
        cb: *mut BN_GENCB,
    ) -> libc::c_int;
    fn BN_mod_inverse(
        out: *mut BIGNUM,
        a: *const BIGNUM,
        n: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> *mut BIGNUM;
    fn BN_MONT_CTX_new_for_modulus(
        mod_0: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> *mut BN_MONT_CTX;
    fn BN_MONT_CTX_free(mont: *mut BN_MONT_CTX);
    fn BN_to_montgomery(
        ret: *mut BIGNUM,
        a: *const BIGNUM,
        mont: *const BN_MONT_CTX,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_mod_mul_montgomery(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        b: *const BIGNUM,
        mont: *const BN_MONT_CTX,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn BN_mod_exp_mont(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        p: *const BIGNUM,
        m: *const BIGNUM,
        ctx: *mut BN_CTX,
        mont: *const BN_MONT_CTX,
    ) -> libc::c_int;
    fn BN_mod_exp_mont_consttime(
        rr: *mut BIGNUM,
        a: *const BIGNUM,
        p: *const BIGNUM,
        m: *const BIGNUM,
        ctx: *mut BN_CTX,
        mont: *const BN_MONT_CTX,
    ) -> libc::c_int;
    fn BN_mod_exp2_mont(
        r: *mut BIGNUM,
        a1: *const BIGNUM,
        p1: *const BIGNUM,
        a2: *const BIGNUM,
        p2: *const BIGNUM,
        m: *const BIGNUM,
        ctx: *mut BN_CTX,
        mont: *const BN_MONT_CTX,
    ) -> libc::c_int;
    fn BIO_new(method: *const BIO_METHOD) -> *mut BIO;
    fn BIO_free(bio: *mut BIO) -> libc::c_int;
    fn BIO_s_file() -> *const BIO_METHOD;
    fn BIO_set_fp(
        bio: *mut BIO,
        file: *mut FILE,
        close_flag: libc::c_int,
    ) -> libc::c_int;
    fn dsa_check_key(dsa: *const DSA) -> libc::c_int;
    fn EVP_sha1() -> *const EVP_MD;
    fn EVP_sha256() -> *const EVP_MD;
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
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn DH_new() -> *mut DH;
    fn DH_free(dh: *mut DH);
    fn EVP_PKEY_new() -> *mut EVP_PKEY;
    fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
    fn EVP_PKEY_set1_DSA(pkey: *mut EVP_PKEY, key: *mut DSA) -> libc::c_int;
    fn EVP_PKEY_print_private(
        out: *mut BIO,
        pkey: *const EVP_PKEY,
        indent: libc::c_int,
        pctx: *mut ASN1_PCTX,
    ) -> libc::c_int;
    fn CRYPTO_refcount_inc(count: *mut CRYPTO_refcount_t);
    fn CRYPTO_refcount_dec_and_test_zero(count: *mut CRYPTO_refcount_t) -> libc::c_int;
    fn CRYPTO_MUTEX_init(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_cleanup(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_get_ex_new_index(
        ex_data_class: *mut CRYPTO_EX_DATA_CLASS,
        out_index: *mut libc::c_int,
        argl: libc::c_long,
        argp: *mut libc::c_void,
        free_func: Option::<CRYPTO_EX_free>,
    ) -> libc::c_int;
    fn CRYPTO_set_ex_data(
        ad: *mut CRYPTO_EX_DATA,
        index: libc::c_int,
        val: *mut libc::c_void,
    ) -> libc::c_int;
    fn CRYPTO_get_ex_data(
        ad: *const CRYPTO_EX_DATA,
        index: libc::c_int,
    ) -> *mut libc::c_void;
    fn CRYPTO_new_ex_data(ad: *mut CRYPTO_EX_DATA);
    fn CRYPTO_free_ex_data(
        ex_data_class: *mut CRYPTO_EX_DATA_CLASS,
        obj: *mut libc::c_void,
        ad: *mut CRYPTO_EX_DATA,
    );
    fn bn_minimal_width(bn: *const BIGNUM) -> libc::c_int;
    fn bn_resize_words(bn: *mut BIGNUM, words: size_t) -> libc::c_int;
    fn bn_reduce_once_in_place(
        r: *mut BN_ULONG,
        carry: BN_ULONG,
        m: *const BN_ULONG,
        tmp: *mut BN_ULONG,
        num: size_t,
    ) -> BN_ULONG;
    fn bn_mod_add_consttime(
        r: *mut BIGNUM,
        a: *const BIGNUM,
        b: *const BIGNUM,
        m: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn bn_mod_inverse_prime(
        out: *mut BIGNUM,
        a: *const BIGNUM,
        p: *const BIGNUM,
        ctx: *mut BN_CTX,
        mont_p: *const BN_MONT_CTX,
    ) -> libc::c_int;
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
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_rwlock_arch_t {
    pub __readers: libc::c_uint,
    pub __writers: libc::c_uint,
    pub __wrphase_futex: libc::c_uint,
    pub __writers_futex: libc::c_uint,
    pub __pad3: libc::c_uint,
    pub __pad4: libc::c_uint,
    pub __cur_writer: libc::c_int,
    pub __shared: libc::c_int,
    pub __rwelision: libc::c_schar,
    pub __pad1: [libc::c_uchar; 7],
    pub __pad2: libc::c_ulong,
    pub __flags: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_rwlock_t {
    pub __data: __pthread_rwlock_arch_t,
    pub __size: [libc::c_char; 56],
    pub __align: libc::c_long,
}
pub type ASN1_PCTX = asn1_pctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct DSA_SIG_st {
    pub r: *mut BIGNUM,
    pub s: *mut BIGNUM,
}
pub type BIGNUM = bignum_st;
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
pub type DSA_SIG = DSA_SIG_st;
pub type BN_CTX = bignum_ctx;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bio_method_st {
    pub type_0: libc::c_int,
    pub name: *const libc::c_char,
    pub bwrite: Option::<
        unsafe extern "C" fn(*mut BIO, *const libc::c_char, libc::c_int) -> libc::c_int,
    >,
    pub bread: Option::<
        unsafe extern "C" fn(*mut BIO, *mut libc::c_char, libc::c_int) -> libc::c_int,
    >,
    pub bputs: Option::<
        unsafe extern "C" fn(*mut BIO, *const libc::c_char) -> libc::c_int,
    >,
    pub bgets: Option::<
        unsafe extern "C" fn(*mut BIO, *mut libc::c_char, libc::c_int) -> libc::c_int,
    >,
    pub ctrl: Option::<
        unsafe extern "C" fn(
            *mut BIO,
            libc::c_int,
            libc::c_long,
            *mut libc::c_void,
        ) -> libc::c_long,
    >,
    pub create: Option::<unsafe extern "C" fn(*mut BIO) -> libc::c_int>,
    pub destroy: Option::<unsafe extern "C" fn(*mut BIO) -> libc::c_int>,
    pub callback_ctrl: Option::<
        unsafe extern "C" fn(*mut BIO, libc::c_int, bio_info_cb) -> libc::c_long,
    >,
}
pub type bio_info_cb = Option::<
    unsafe extern "C" fn(*mut BIO, libc::c_int, libc::c_int) -> libc::c_long,
>;
pub type BIO = bio_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bio_st {
    pub method: *const BIO_METHOD,
    pub ex_data: CRYPTO_EX_DATA,
    pub callback_ex: BIO_callback_fn_ex,
    pub callback: BIO_callback_fn,
    pub cb_arg: *mut libc::c_char,
    pub init: libc::c_int,
    pub shutdown: libc::c_int,
    pub flags: libc::c_int,
    pub retry_reason: libc::c_int,
    pub num: libc::c_int,
    pub references: CRYPTO_refcount_t,
    pub ptr: *mut libc::c_void,
    pub next_bio: *mut BIO,
    pub num_read: uint64_t,
    pub num_write: uint64_t,
}
pub type CRYPTO_refcount_t = uint32_t;
pub type BIO_callback_fn = Option::<
    unsafe extern "C" fn(
        *mut BIO,
        libc::c_int,
        *const libc::c_char,
        libc::c_int,
        libc::c_long,
        libc::c_long,
    ) -> libc::c_long,
>;
pub type BIO_callback_fn_ex = Option::<
    unsafe extern "C" fn(
        *mut BIO,
        libc::c_int,
        *const libc::c_char,
        size_t,
        libc::c_int,
        libc::c_long,
        libc::c_int,
        *mut size_t,
    ) -> libc::c_long,
>;
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
pub type BIO_METHOD = bio_method_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bn_gencb_st {
    pub type_0: uint8_t,
    pub arg: *mut libc::c_void,
    pub callback: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub new_style: Option::<
        unsafe extern "C" fn(libc::c_int, libc::c_int, *mut bn_gencb_st) -> libc::c_int,
    >,
    pub old_style: Option::<
        unsafe extern "C" fn(libc::c_int, libc::c_int, *mut libc::c_void) -> (),
    >,
}
pub type BN_GENCB = bn_gencb_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bn_mont_ctx_st {
    pub RR: BIGNUM,
    pub N: BIGNUM,
    pub n0: [BN_ULONG; 2],
}
pub type BN_MONT_CTX = bn_mont_ctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dh_st {
    pub p: *mut BIGNUM,
    pub g: *mut BIGNUM,
    pub q: *mut BIGNUM,
    pub pub_key: *mut BIGNUM,
    pub priv_key: *mut BIGNUM,
    pub priv_length: libc::c_uint,
    pub method_mont_p_lock: CRYPTO_MUTEX,
    pub method_mont_p: *mut BN_MONT_CTX,
    pub flags: libc::c_int,
    pub references: CRYPTO_refcount_t,
}
pub type CRYPTO_MUTEX = crypto_mutex_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub union crypto_mutex_st {
    pub alignment: libc::c_double,
    pub padding: [uint8_t; 56],
}
pub type DH = dh_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dsa_st {
    pub p: *mut BIGNUM,
    pub q: *mut BIGNUM,
    pub g: *mut BIGNUM,
    pub pub_key: *mut BIGNUM,
    pub priv_key: *mut BIGNUM,
    pub method_mont_lock: CRYPTO_MUTEX,
    pub method_mont_p: *mut BN_MONT_CTX,
    pub method_mont_q: *mut BN_MONT_CTX,
    pub references: CRYPTO_refcount_t,
    pub ex_data: CRYPTO_EX_DATA,
}
pub type DSA = dsa_st;
pub type ENGINE = engine_st;
pub type EVP_MD = env_md_st;
pub type EVP_PKEY = evp_pkey_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
pub type CRYPTO_EX_free = unsafe extern "C" fn(
    *mut libc::c_void,
    *mut libc::c_void,
    *mut CRYPTO_EX_DATA,
    libc::c_int,
    libc::c_long,
    *mut libc::c_void,
) -> ();
pub type CRYPTO_EX_dup = unsafe extern "C" fn(
    *mut CRYPTO_EX_DATA,
    *const CRYPTO_EX_DATA,
    *mut *mut libc::c_void,
    libc::c_int,
    libc::c_long,
    *mut libc::c_void,
) -> libc::c_int;
pub type CRYPTO_EX_unused = libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CRYPTO_EX_DATA_CLASS {
    pub lock: CRYPTO_STATIC_MUTEX,
    pub meth: *mut stack_st_CRYPTO_EX_DATA_FUNCS,
    pub num_reserved: uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CRYPTO_STATIC_MUTEX {
    pub lock: pthread_rwlock_t,
}
pub const PTHREAD_RWLOCK_DEFAULT_NP: C2RustUnnamed_0 = 0;
pub type C2RustUnnamed_0 = libc::c_uint;
pub const PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP: C2RustUnnamed_0 = 2;
pub const PTHREAD_RWLOCK_PREFER_WRITER_NP: C2RustUnnamed_0 = 1;
pub const PTHREAD_RWLOCK_PREFER_READER_NP: C2RustUnnamed_0 = 0;
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
unsafe extern "C" fn bn_declassify(mut bn: *mut BIGNUM) {}
static mut g_ex_data_class: CRYPTO_EX_DATA_CLASS = {
    let mut init = CRYPTO_EX_DATA_CLASS {
        lock: {
            let mut init = CRYPTO_STATIC_MUTEX {
                lock: pthread_rwlock_t {
                    __data: {
                        let mut init = __pthread_rwlock_arch_t {
                            __readers: 0 as libc::c_int as libc::c_uint,
                            __writers: 0 as libc::c_int as libc::c_uint,
                            __wrphase_futex: 0 as libc::c_int as libc::c_uint,
                            __writers_futex: 0 as libc::c_int as libc::c_uint,
                            __pad3: 0 as libc::c_int as libc::c_uint,
                            __pad4: 0 as libc::c_int as libc::c_uint,
                            __cur_writer: 0 as libc::c_int,
                            __shared: 0 as libc::c_int,
                            __rwelision: 0 as libc::c_int as libc::c_schar,
                            __pad1: [
                                0 as libc::c_int as libc::c_uchar,
                                0 as libc::c_int as libc::c_uchar,
                                0 as libc::c_int as libc::c_uchar,
                                0 as libc::c_int as libc::c_uchar,
                                0 as libc::c_int as libc::c_uchar,
                                0 as libc::c_int as libc::c_uchar,
                                0 as libc::c_int as libc::c_uchar,
                            ],
                            __pad2: 0 as libc::c_int as libc::c_ulong,
                            __flags: PTHREAD_RWLOCK_DEFAULT_NP as libc::c_int
                                as libc::c_uint,
                        };
                        init
                    },
                },
            };
            init
        },
        meth: 0 as *const stack_st_CRYPTO_EX_DATA_FUNCS
            as *mut stack_st_CRYPTO_EX_DATA_FUNCS,
        num_reserved: 0 as libc::c_int as uint8_t,
    };
    init
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_new() -> *mut DSA {
    let mut dsa: *mut DSA = OPENSSL_zalloc(
        ::core::mem::size_of::<DSA>() as libc::c_ulong,
    ) as *mut DSA;
    if dsa.is_null() {
        return 0 as *mut DSA;
    }
    (*dsa).references = 1 as libc::c_int as CRYPTO_refcount_t;
    CRYPTO_MUTEX_init(&mut (*dsa).method_mont_lock);
    CRYPTO_new_ex_data(&mut (*dsa).ex_data);
    return dsa;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_free(mut dsa: *mut DSA) {
    if dsa.is_null() {
        return;
    }
    if CRYPTO_refcount_dec_and_test_zero(&mut (*dsa).references) == 0 {
        return;
    }
    CRYPTO_free_ex_data(
        &mut g_ex_data_class,
        dsa as *mut libc::c_void,
        &mut (*dsa).ex_data,
    );
    BN_clear_free((*dsa).p);
    BN_clear_free((*dsa).q);
    BN_clear_free((*dsa).g);
    BN_clear_free((*dsa).pub_key);
    BN_clear_free((*dsa).priv_key);
    BN_MONT_CTX_free((*dsa).method_mont_p);
    BN_MONT_CTX_free((*dsa).method_mont_q);
    CRYPTO_MUTEX_cleanup(&mut (*dsa).method_mont_lock);
    OPENSSL_free(dsa as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_print(
    mut bio: *mut BIO,
    mut dsa: *const DSA,
    mut indent: libc::c_int,
) -> libc::c_int {
    let mut pkey: *mut EVP_PKEY = EVP_PKEY_new();
    let mut ret: libc::c_int = (!pkey.is_null()
        && EVP_PKEY_set1_DSA(pkey, dsa as *mut DSA) != 0
        && EVP_PKEY_print_private(bio, pkey, indent, 0 as *mut ASN1_PCTX) != 0)
        as libc::c_int;
    EVP_PKEY_free(pkey);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_print_fp(
    mut fp: *mut FILE,
    mut dsa: *const DSA,
    mut indent: libc::c_int,
) -> libc::c_int {
    let mut bio: *mut BIO = BIO_new(BIO_s_file());
    if bio.is_null() {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            7 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa.c\0" as *const u8
                as *const libc::c_char,
            139 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    BIO_set_fp(bio, fp, 0 as libc::c_int);
    let mut ret: libc::c_int = DSA_print(bio, dsa, indent);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_up_ref(mut dsa: *mut DSA) -> libc::c_int {
    CRYPTO_refcount_inc(&mut (*dsa).references);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_bits(mut dsa: *const DSA) -> libc::c_uint {
    return BN_num_bits((*dsa).p);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_get0_pub_key(mut dsa: *const DSA) -> *const BIGNUM {
    return (*dsa).pub_key;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_get0_priv_key(mut dsa: *const DSA) -> *const BIGNUM {
    return (*dsa).priv_key;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_get0_p(mut dsa: *const DSA) -> *const BIGNUM {
    return (*dsa).p;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_get0_q(mut dsa: *const DSA) -> *const BIGNUM {
    return (*dsa).q;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_get0_g(mut dsa: *const DSA) -> *const BIGNUM {
    return (*dsa).g;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_get0_key(
    mut dsa: *const DSA,
    mut out_pub_key: *mut *const BIGNUM,
    mut out_priv_key: *mut *const BIGNUM,
) {
    if !out_pub_key.is_null() {
        *out_pub_key = (*dsa).pub_key;
    }
    if !out_priv_key.is_null() {
        *out_priv_key = (*dsa).priv_key;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_get0_pqg(
    mut dsa: *const DSA,
    mut out_p: *mut *const BIGNUM,
    mut out_q: *mut *const BIGNUM,
    mut out_g: *mut *const BIGNUM,
) {
    if !out_p.is_null() {
        *out_p = (*dsa).p;
    }
    if !out_q.is_null() {
        *out_q = (*dsa).q;
    }
    if !out_g.is_null() {
        *out_g = (*dsa).g;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_set0_key(
    mut dsa: *mut DSA,
    mut pub_key: *mut BIGNUM,
    mut priv_key: *mut BIGNUM,
) -> libc::c_int {
    if ((*dsa).pub_key).is_null() && pub_key.is_null() {
        return 0 as libc::c_int;
    }
    if !pub_key.is_null() {
        BN_free((*dsa).pub_key);
        (*dsa).pub_key = pub_key;
    }
    if !priv_key.is_null() {
        BN_free((*dsa).priv_key);
        (*dsa).priv_key = priv_key;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_set0_pqg(
    mut dsa: *mut DSA,
    mut p: *mut BIGNUM,
    mut q: *mut BIGNUM,
    mut g: *mut BIGNUM,
) -> libc::c_int {
    if ((*dsa).p).is_null() && p.is_null() || ((*dsa).q).is_null() && q.is_null()
        || ((*dsa).g).is_null() && g.is_null()
    {
        return 0 as libc::c_int;
    }
    if !p.is_null() {
        BN_free((*dsa).p);
        (*dsa).p = p;
    }
    if !q.is_null() {
        BN_free((*dsa).q);
        (*dsa).q = q;
    }
    if !g.is_null() {
        BN_free((*dsa).g);
        (*dsa).g = g;
    }
    BN_MONT_CTX_free((*dsa).method_mont_p);
    (*dsa).method_mont_p = 0 as *mut BN_MONT_CTX;
    BN_MONT_CTX_free((*dsa).method_mont_q);
    (*dsa).method_mont_q = 0 as *mut BN_MONT_CTX;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_generate_parameters_ex(
    mut dsa: *mut DSA,
    mut bits: libc::c_uint,
    mut seed_in: *const uint8_t,
    mut seed_len: size_t,
    mut out_counter: *mut libc::c_int,
    mut out_h: *mut libc::c_ulong,
    mut cb: *mut BN_GENCB,
) -> libc::c_int {
    let mut evpmd: *const EVP_MD = if bits >= 2048 as libc::c_int as libc::c_uint {
        EVP_sha256()
    } else {
        EVP_sha1()
    };
    return dsa_internal_paramgen(
        dsa,
        bits as size_t,
        evpmd,
        seed_in,
        seed_len,
        out_counter,
        out_h,
        cb,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dsa_internal_paramgen(
    mut dsa: *mut DSA,
    mut bits: size_t,
    mut evpmd: *const EVP_MD,
    mut seed_in: *const libc::c_uchar,
    mut seed_len: size_t,
    mut out_counter: *mut libc::c_int,
    mut out_h: *mut libc::c_ulong,
    mut cb: *mut BN_GENCB,
) -> libc::c_int {
    let mut current_block: u64;
    if bits > 10000 as libc::c_int as size_t {
        ERR_put_error(
            10 as libc::c_int,
            0 as libc::c_int,
            107 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa.c\0" as *const u8
                as *const libc::c_char,
            245 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ok: libc::c_int = 0 as libc::c_int;
    let mut seed: [libc::c_uchar; 32] = [0; 32];
    let mut md: [libc::c_uchar; 32] = [0; 32];
    let mut buf: [libc::c_uchar; 32] = [0; 32];
    let mut buf2: [libc::c_uchar; 32] = [0; 32];
    let mut r0: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut W: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut X: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut c: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut test: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut g: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut q: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut p: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut mont: *mut BN_MONT_CTX = 0 as *mut BN_MONT_CTX;
    let mut k: libc::c_int = 0;
    let mut n: libc::c_int = 0 as libc::c_int;
    let mut m: libc::c_int = 0 as libc::c_int;
    let mut counter: libc::c_int = 0 as libc::c_int;
    let mut r: libc::c_int = 0 as libc::c_int;
    let mut ctx: *mut BN_CTX = 0 as *mut BN_CTX;
    let mut h: libc::c_uint = 2 as libc::c_int as libc::c_uint;
    let qsize: size_t = EVP_MD_size(evpmd);
    if bits < 512 as libc::c_int as size_t {
        bits = 512 as libc::c_int as size_t;
    }
    bits = bits.wrapping_add(63 as libc::c_int as size_t) / 64 as libc::c_int as size_t
        * 64 as libc::c_int as size_t;
    if !seed_in.is_null() {
        if seed_len < qsize {
            return 0 as libc::c_int;
        }
        if seed_len > qsize {
            seed_len = qsize;
        }
        OPENSSL_memcpy(
            seed.as_mut_ptr() as *mut libc::c_void,
            seed_in as *const libc::c_void,
            seed_len,
        );
    }
    ctx = BN_CTX_new();
    if !ctx.is_null() {
        BN_CTX_start(ctx);
        r0 = BN_CTX_get(ctx);
        g = BN_CTX_get(ctx);
        W = BN_CTX_get(ctx);
        q = BN_CTX_get(ctx);
        X = BN_CTX_get(ctx);
        c = BN_CTX_get(ctx);
        p = BN_CTX_get(ctx);
        test = BN_CTX_get(ctx);
        if !(test.is_null()
            || BN_lshift(
                test,
                BN_value_one(),
                bits.wrapping_sub(1 as libc::c_int as size_t) as libc::c_int,
            ) == 0)
        {
            's_144: loop {
                let fresh0 = m;
                m = m + 1;
                if BN_GENCB_call(cb, 0 as libc::c_int, fresh0) == 0 {
                    current_block = 3958797299599650484;
                    break;
                }
                let mut use_random_seed: libc::c_int = (seed_in
                    == 0 as *mut libc::c_void as *const libc::c_uchar) as libc::c_int;
                if use_random_seed != 0 {
                    if RAND_bytes(seed.as_mut_ptr(), qsize) == 0 {
                        current_block = 3958797299599650484;
                        break;
                    }
                } else {
                    seed_in = 0 as *const libc::c_uchar;
                }
                OPENSSL_memcpy(
                    buf.as_mut_ptr() as *mut libc::c_void,
                    seed.as_mut_ptr() as *const libc::c_void,
                    qsize,
                );
                OPENSSL_memcpy(
                    buf2.as_mut_ptr() as *mut libc::c_void,
                    seed.as_mut_ptr() as *const libc::c_void,
                    qsize,
                );
                let mut i: size_t = qsize.wrapping_sub(1 as libc::c_int as size_t);
                while i < qsize {
                    buf[i as usize] = (buf[i as usize]).wrapping_add(1);
                    buf[i as usize];
                    if buf[i as usize] as libc::c_int != 0 as libc::c_int {
                        break;
                    }
                    i = i.wrapping_sub(1);
                    i;
                }
                if EVP_Digest(
                    seed.as_mut_ptr() as *const libc::c_void,
                    qsize,
                    md.as_mut_ptr(),
                    0 as *mut libc::c_uint,
                    evpmd,
                    0 as *mut ENGINE,
                ) == 0
                    || EVP_Digest(
                        buf.as_mut_ptr() as *const libc::c_void,
                        qsize,
                        buf2.as_mut_ptr(),
                        0 as *mut libc::c_uint,
                        evpmd,
                        0 as *mut ENGINE,
                    ) == 0
                {
                    current_block = 3958797299599650484;
                    break;
                }
                let mut i_0: size_t = 0 as libc::c_int as size_t;
                while i_0 < qsize {
                    md[i_0
                        as usize] = (md[i_0 as usize] as libc::c_int
                        ^ buf2[i_0 as usize] as libc::c_int) as libc::c_uchar;
                    i_0 = i_0.wrapping_add(1);
                    i_0;
                }
                md[0 as libc::c_int
                    as usize] = (md[0 as libc::c_int as usize] as libc::c_int
                    | 0x80 as libc::c_int) as libc::c_uchar;
                md[qsize.wrapping_sub(1 as libc::c_int as size_t)
                    as usize] = (md[qsize.wrapping_sub(1 as libc::c_int as size_t)
                    as usize] as libc::c_int | 0x1 as libc::c_int) as libc::c_uchar;
                if (BN_bin2bn(md.as_mut_ptr(), qsize, q)).is_null() {
                    current_block = 3958797299599650484;
                    break;
                }
                r = BN_is_prime_fasttest_ex(
                    q,
                    50 as libc::c_int,
                    ctx,
                    use_random_seed,
                    cb,
                );
                if r > 0 as libc::c_int {
                    if BN_GENCB_call(cb, 2 as libc::c_int, 0 as libc::c_int) == 0
                        || BN_GENCB_call(cb, 3 as libc::c_int, 0 as libc::c_int) == 0
                    {
                        current_block = 3958797299599650484;
                        break;
                    }
                    counter = 0 as libc::c_int;
                    n = (bits.wrapping_sub(1 as libc::c_int as size_t)
                        / 160 as libc::c_int as size_t) as libc::c_int;
                    loop {
                        if counter != 0 as libc::c_int
                            && BN_GENCB_call(cb, 0 as libc::c_int, counter) == 0
                        {
                            current_block = 3958797299599650484;
                            break 's_144;
                        }
                        BN_zero(W);
                        k = 0 as libc::c_int;
                        while k <= n {
                            let mut i_1: size_t = qsize
                                .wrapping_sub(1 as libc::c_int as size_t);
                            while i_1 < qsize {
                                buf[i_1 as usize] = (buf[i_1 as usize]).wrapping_add(1);
                                buf[i_1 as usize];
                                if buf[i_1 as usize] as libc::c_int != 0 as libc::c_int {
                                    break;
                                }
                                i_1 = i_1.wrapping_sub(1);
                                i_1;
                            }
                            if EVP_Digest(
                                buf.as_mut_ptr() as *const libc::c_void,
                                qsize,
                                md.as_mut_ptr(),
                                0 as *mut libc::c_uint,
                                evpmd,
                                0 as *mut ENGINE,
                            ) == 0
                            {
                                current_block = 3958797299599650484;
                                break 's_144;
                            }
                            if (BN_bin2bn(md.as_mut_ptr(), qsize, r0)).is_null()
                                || BN_lshift(
                                    r0,
                                    r0,
                                    ((qsize << 3 as libc::c_int) * k as size_t) as libc::c_int,
                                ) == 0 || BN_add(W, W, r0) == 0
                            {
                                current_block = 3958797299599650484;
                                break 's_144;
                            }
                            k += 1;
                            k;
                        }
                        if BN_mask_bits(
                            W,
                            bits.wrapping_sub(1 as libc::c_int as size_t) as libc::c_int,
                        ) == 0 || (BN_copy(X, W)).is_null() || BN_add(X, X, test) == 0
                        {
                            current_block = 3958797299599650484;
                            break 's_144;
                        }
                        if BN_lshift1(r0, q) == 0
                            || BN_div(0 as *mut BIGNUM, c, X, r0, ctx) == 0
                            || BN_sub(r0, c, BN_value_one()) == 0
                            || BN_sub(p, X, r0) == 0
                        {
                            current_block = 3958797299599650484;
                            break 's_144;
                        }
                        if BN_cmp(p, test) >= 0 as libc::c_int {
                            r = BN_is_prime_fasttest_ex(
                                p,
                                50 as libc::c_int,
                                ctx,
                                1 as libc::c_int,
                                cb,
                            );
                            if r > 0 as libc::c_int {
                                current_block = 7105553897381470167;
                                break 's_144;
                            }
                            if r != 0 as libc::c_int {
                                current_block = 3958797299599650484;
                                break 's_144;
                            }
                        }
                        counter += 1;
                        counter;
                        if counter >= 4096 as libc::c_int {
                            break;
                        }
                    }
                } else if r != 0 as libc::c_int {
                    current_block = 3958797299599650484;
                    break;
                }
            }
            match current_block {
                3958797299599650484 => {}
                _ => {
                    if !(BN_GENCB_call(cb, 2 as libc::c_int, 1 as libc::c_int) == 0) {
                        if !(BN_sub(test, p, BN_value_one()) == 0
                            || BN_div(r0, 0 as *mut BIGNUM, test, q, ctx) == 0)
                        {
                            mont = BN_MONT_CTX_new_for_modulus(p, ctx);
                            if !(mont.is_null() || BN_set_word(test, h as BN_ULONG) == 0)
                            {
                                loop {
                                    if BN_mod_exp_mont(g, test, r0, p, ctx, mont) == 0 {
                                        current_block = 3958797299599650484;
                                        break;
                                    }
                                    if BN_is_one(g) == 0 {
                                        current_block = 7072655752890836508;
                                        break;
                                    }
                                    if BN_add(test, test, BN_value_one()) == 0 {
                                        current_block = 3958797299599650484;
                                        break;
                                    }
                                    h = h.wrapping_add(1);
                                    h;
                                }
                                match current_block {
                                    3958797299599650484 => {}
                                    _ => {
                                        if !(BN_GENCB_call(cb, 3 as libc::c_int, 1 as libc::c_int)
                                            == 0)
                                        {
                                            ok = 1 as libc::c_int;
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
    while ok != 0 {
        BN_free((*dsa).p);
        BN_free((*dsa).q);
        BN_free((*dsa).g);
        (*dsa).p = BN_dup(p);
        (*dsa).q = BN_dup(q);
        (*dsa).g = BN_dup(g);
        if ((*dsa).p).is_null() || ((*dsa).q).is_null() || ((*dsa).g).is_null() {
            ok = 0 as libc::c_int;
        } else {
            if !out_counter.is_null() {
                *out_counter = counter;
            }
            if !out_h.is_null() {
                *out_h = h as libc::c_ulong;
            }
            break;
        }
    }
    if !ctx.is_null() {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    BN_MONT_CTX_free(mont);
    OPENSSL_cleanse(seed.as_mut_ptr() as *mut libc::c_void, 32 as libc::c_int as size_t);
    return ok;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSAparams_dup(mut dsa: *const DSA) -> *mut DSA {
    let mut ret: *mut DSA = DSA_new();
    if ret.is_null() {
        return 0 as *mut DSA;
    }
    (*ret).p = BN_dup((*dsa).p);
    (*ret).q = BN_dup((*dsa).q);
    (*ret).g = BN_dup((*dsa).g);
    if ((*ret).p).is_null() || ((*ret).q).is_null() || ((*ret).g).is_null() {
        DSA_free(ret);
        return 0 as *mut DSA;
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_generate_key(mut dsa: *mut DSA) -> libc::c_int {
    let mut current_block: u64;
    if dsa_check_key(dsa) == 0 {
        return 0 as libc::c_int;
    }
    let mut ok: libc::c_int = 0 as libc::c_int;
    let mut pub_key: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut priv_key: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut ctx: *mut BN_CTX = BN_CTX_new();
    if !ctx.is_null() {
        priv_key = (*dsa).priv_key;
        if priv_key.is_null() {
            priv_key = BN_new();
            if priv_key.is_null() {
                current_block = 1074067686654513846;
            } else {
                current_block = 17216689946888361452;
            }
        } else {
            current_block = 17216689946888361452;
        }
        match current_block {
            1074067686654513846 => {}
            _ => {
                if !(BN_rand_range_ex(priv_key, 1 as libc::c_int as BN_ULONG, (*dsa).q)
                    == 0)
                {
                    pub_key = (*dsa).pub_key;
                    if pub_key.is_null() {
                        pub_key = BN_new();
                        if pub_key.is_null() {
                            current_block = 1074067686654513846;
                        } else {
                            current_block = 4166486009154926805;
                        }
                    } else {
                        current_block = 4166486009154926805;
                    }
                    match current_block {
                        1074067686654513846 => {}
                        _ => {
                            if !(BN_MONT_CTX_set_locked(
                                &mut (*dsa).method_mont_p,
                                &mut (*dsa).method_mont_lock,
                                (*dsa).p,
                                ctx,
                            ) == 0
                                || BN_mod_exp_mont_consttime(
                                    pub_key,
                                    (*dsa).g,
                                    priv_key,
                                    (*dsa).p,
                                    ctx,
                                    (*dsa).method_mont_p,
                                ) == 0)
                            {
                                bn_declassify(pub_key);
                                (*dsa).priv_key = priv_key;
                                (*dsa).pub_key = pub_key;
                                ok = 1 as libc::c_int;
                            }
                        }
                    }
                }
            }
        }
    }
    if ((*dsa).pub_key).is_null() {
        BN_free(pub_key);
    }
    if ((*dsa).priv_key).is_null() {
        BN_free(priv_key);
    }
    BN_CTX_free(ctx);
    return ok;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_SIG_new() -> *mut DSA_SIG {
    return OPENSSL_zalloc(::core::mem::size_of::<DSA_SIG>() as libc::c_ulong)
        as *mut DSA_SIG;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_SIG_free(mut sig: *mut DSA_SIG) {
    if sig.is_null() {
        return;
    }
    BN_free((*sig).r);
    BN_free((*sig).s);
    OPENSSL_free(sig as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_SIG_get0(
    mut sig: *const DSA_SIG,
    mut out_r: *mut *const BIGNUM,
    mut out_s: *mut *const BIGNUM,
) {
    if !out_r.is_null() {
        *out_r = (*sig).r;
    }
    if !out_s.is_null() {
        *out_s = (*sig).s;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_SIG_set0(
    mut sig: *mut DSA_SIG,
    mut r: *mut BIGNUM,
    mut s: *mut BIGNUM,
) -> libc::c_int {
    if r.is_null() || s.is_null() {
        return 0 as libc::c_int;
    }
    BN_free((*sig).r);
    BN_free((*sig).s);
    (*sig).r = r;
    (*sig).s = s;
    return 1 as libc::c_int;
}
unsafe extern "C" fn mod_mul_consttime(
    mut r: *mut BIGNUM,
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
    mut mont: *const BN_MONT_CTX,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    BN_CTX_start(ctx);
    let mut tmp: *mut BIGNUM = BN_CTX_get(ctx);
    let mut ok: libc::c_int = (!tmp.is_null() && BN_to_montgomery(tmp, a, mont, ctx) != 0
        && BN_mod_mul_montgomery(r, tmp, b, mont, ctx) != 0) as libc::c_int;
    BN_CTX_end(ctx);
    return ok;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_do_sign(
    mut digest: *const uint8_t,
    mut digest_len: size_t,
    mut dsa: *const DSA,
) -> *mut DSA_SIG {
    let mut q_width: size_t = 0;
    static mut kMaxIterations: libc::c_int = 32 as libc::c_int;
    let mut iters: libc::c_int = 0;
    let mut current_block: u64;
    if dsa_check_key(dsa) == 0 {
        return 0 as *mut DSA_SIG;
    }
    if ((*dsa).priv_key).is_null() {
        ERR_put_error(
            10 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa.c\0" as *const u8
                as *const libc::c_char,
            630 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut DSA_SIG;
    }
    let mut kinv: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut r: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut s: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut m: BIGNUM = bignum_st {
        d: 0 as *mut BN_ULONG,
        width: 0,
        dmax: 0,
        neg: 0,
        flags: 0,
    };
    let mut xr: BIGNUM = bignum_st {
        d: 0 as *mut BN_ULONG,
        width: 0,
        dmax: 0,
        neg: 0,
        flags: 0,
    };
    let mut ctx: *mut BN_CTX = 0 as *mut BN_CTX;
    let mut ret: *mut DSA_SIG = 0 as *mut DSA_SIG;
    BN_init(&mut m);
    BN_init(&mut xr);
    s = BN_new();
    if !s.is_null() {
        ctx = BN_CTX_new();
        if !ctx.is_null() {
            iters = 0 as libc::c_int;
            loop {
                if dsa_sign_setup(dsa, ctx, &mut kinv, &mut r) == 0 {
                    current_block = 2283711017638004850;
                    break;
                }
                if digest_len > BN_num_bytes((*dsa).q) as size_t {
                    digest_len = BN_num_bytes((*dsa).q) as size_t;
                }
                if (BN_bin2bn(digest, digest_len, &mut m)).is_null() {
                    current_block = 2283711017638004850;
                    break;
                }
                q_width = bn_minimal_width((*dsa).q) as size_t;
                if bn_resize_words(&mut m, q_width) == 0
                    || bn_resize_words(&mut xr, q_width) == 0
                {
                    current_block = 2283711017638004850;
                    break;
                }
                bn_reduce_once_in_place(
                    m.d,
                    0 as libc::c_int as BN_ULONG,
                    (*(*dsa).q).d,
                    xr.d,
                    q_width,
                );
                if mod_mul_consttime(
                    &mut xr,
                    (*dsa).priv_key,
                    r,
                    (*dsa).method_mont_q,
                    ctx,
                ) == 0 || bn_mod_add_consttime(s, &mut xr, &mut m, (*dsa).q, ctx) == 0
                    || mod_mul_consttime(s, s, kinv, (*dsa).method_mont_q, ctx) == 0
                {
                    current_block = 2283711017638004850;
                    break;
                }
                bn_declassify(r);
                bn_declassify(s);
                if BN_is_zero(r) != 0 || BN_is_zero(s) != 0 {
                    iters += 1;
                    iters;
                    if !(iters > kMaxIterations) {
                        continue;
                    }
                    ERR_put_error(
                        10 as libc::c_int,
                        0 as libc::c_int,
                        108 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa.c\0"
                            as *const u8 as *const libc::c_char,
                        704 as libc::c_int as libc::c_uint,
                    );
                    current_block = 2283711017638004850;
                    break;
                } else {
                    ret = DSA_SIG_new();
                    if ret.is_null() {
                        current_block = 2283711017638004850;
                        break;
                    } else {
                        current_block = 16924917904204750491;
                        break;
                    }
                }
            }
            match current_block {
                2283711017638004850 => {}
                _ => {
                    (*ret).r = r;
                    (*ret).s = s;
                }
            }
        }
    }
    if ret.is_null() {
        ERR_put_error(
            10 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa.c\0" as *const u8
                as *const libc::c_char,
            719 as libc::c_int as libc::c_uint,
        );
        BN_free(r);
        BN_free(s);
    }
    BN_CTX_free(ctx);
    BN_clear_free(&mut m);
    BN_clear_free(&mut xr);
    BN_clear_free(kinv);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_do_verify(
    mut digest: *const uint8_t,
    mut digest_len: size_t,
    mut sig: *const DSA_SIG,
    mut dsa: *const DSA,
) -> libc::c_int {
    let mut valid: libc::c_int = 0;
    if DSA_do_check_signature(&mut valid, digest, digest_len, sig, dsa) == 0 {
        return -(1 as libc::c_int);
    }
    return valid;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_do_check_signature(
    mut out_valid: *mut libc::c_int,
    mut digest: *const uint8_t,
    mut digest_len: size_t,
    mut sig: *const DSA_SIG,
    mut dsa: *const DSA,
) -> libc::c_int {
    let mut q_bits: libc::c_uint = 0;
    *out_valid = 0 as libc::c_int;
    if dsa_check_key(dsa) == 0 {
        return 0 as libc::c_int;
    }
    if ((*dsa).pub_key).is_null() {
        ERR_put_error(
            10 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa.c\0" as *const u8
                as *const libc::c_char,
            749 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut u1: BIGNUM = bignum_st {
        d: 0 as *mut BN_ULONG,
        width: 0,
        dmax: 0,
        neg: 0,
        flags: 0,
    };
    let mut u2: BIGNUM = bignum_st {
        d: 0 as *mut BN_ULONG,
        width: 0,
        dmax: 0,
        neg: 0,
        flags: 0,
    };
    let mut t1: BIGNUM = bignum_st {
        d: 0 as *mut BN_ULONG,
        width: 0,
        dmax: 0,
        neg: 0,
        flags: 0,
    };
    BN_init(&mut u1);
    BN_init(&mut u2);
    BN_init(&mut t1);
    let mut ctx: *mut BN_CTX = BN_CTX_new();
    if !ctx.is_null() {
        if BN_is_zero((*sig).r) != 0 || BN_is_negative((*sig).r) != 0
            || BN_ucmp((*sig).r, (*dsa).q) >= 0 as libc::c_int
        {
            ret = 1 as libc::c_int;
        } else if BN_is_zero((*sig).s) != 0 || BN_is_negative((*sig).s) != 0
            || BN_ucmp((*sig).s, (*dsa).q) >= 0 as libc::c_int
        {
            ret = 1 as libc::c_int;
        } else if !(BN_mod_inverse(&mut u2, (*sig).s, (*dsa).q, ctx)).is_null() {
            q_bits = BN_num_bits((*dsa).q);
            if digest_len > (q_bits >> 3 as libc::c_int) as size_t {
                digest_len = (q_bits >> 3 as libc::c_int) as size_t;
            }
            if !(BN_bin2bn(digest, digest_len, &mut u1)).is_null() {
                if !(BN_mod_mul(&mut u1, &mut u1, &mut u2, (*dsa).q, ctx) == 0) {
                    if !(BN_mod_mul(&mut u2, (*sig).r, &mut u2, (*dsa).q, ctx) == 0) {
                        if !(BN_MONT_CTX_set_locked(
                            &(*dsa).method_mont_p as *const *mut BN_MONT_CTX
                                as *mut *mut BN_MONT_CTX,
                            &(*dsa).method_mont_lock as *const CRYPTO_MUTEX
                                as *mut CRYPTO_MUTEX,
                            (*dsa).p,
                            ctx,
                        ) == 0)
                        {
                            if !(BN_mod_exp2_mont(
                                &mut t1,
                                (*dsa).g,
                                &mut u1,
                                (*dsa).pub_key,
                                &mut u2,
                                (*dsa).p,
                                ctx,
                                (*dsa).method_mont_p,
                            ) == 0)
                            {
                                if !(BN_div(
                                    0 as *mut BIGNUM,
                                    &mut u1,
                                    &mut t1,
                                    (*dsa).q,
                                    ctx,
                                ) == 0)
                                {
                                    *out_valid = (BN_ucmp(&mut u1, (*sig).r)
                                        == 0 as libc::c_int) as libc::c_int;
                                    ret = 1 as libc::c_int;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if ret != 1 as libc::c_int {
        ERR_put_error(
            10 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa.c\0" as *const u8
                as *const libc::c_char,
            827 as libc::c_int as libc::c_uint,
        );
    }
    BN_CTX_free(ctx);
    BN_free(&mut u1);
    BN_free(&mut u2);
    BN_free(&mut t1);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_sign(
    mut type_0: libc::c_int,
    mut digest: *const uint8_t,
    mut digest_len: size_t,
    mut out_sig: *mut uint8_t,
    mut out_siglen: *mut libc::c_uint,
    mut dsa: *const DSA,
) -> libc::c_int {
    let mut s: *mut DSA_SIG = 0 as *mut DSA_SIG;
    s = DSA_do_sign(digest, digest_len, dsa);
    if s.is_null() {
        *out_siglen = 0 as libc::c_int as libc::c_uint;
        return 0 as libc::c_int;
    }
    *out_siglen = i2d_DSA_SIG(s, &mut out_sig) as libc::c_uint;
    DSA_SIG_free(s);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_verify(
    mut type_0: libc::c_int,
    mut digest: *const uint8_t,
    mut digest_len: size_t,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
    mut dsa: *const DSA,
) -> libc::c_int {
    let mut valid: libc::c_int = 0;
    if DSA_check_signature(&mut valid, digest, digest_len, sig, sig_len, dsa) == 0 {
        return -(1 as libc::c_int);
    }
    return valid;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_check_signature(
    mut out_valid: *mut libc::c_int,
    mut digest: *const uint8_t,
    mut digest_len: size_t,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
    mut dsa: *const DSA,
) -> libc::c_int {
    let mut sigp: *const uint8_t = 0 as *const uint8_t;
    let mut der_len: libc::c_int = 0;
    let mut s: *mut DSA_SIG = 0 as *mut DSA_SIG;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut der: *mut uint8_t = 0 as *mut uint8_t;
    s = DSA_SIG_new();
    if !s.is_null() {
        sigp = sig;
        if !((d2i_DSA_SIG(&mut s, &mut sigp, sig_len as libc::c_long)).is_null()
            || sigp != sig.offset(sig_len as isize))
        {
            der_len = i2d_DSA_SIG(s, &mut der);
            if !(der_len < 0 as libc::c_int || der_len as size_t != sig_len
                || OPENSSL_memcmp(
                    sig as *const libc::c_void,
                    der as *const libc::c_void,
                    sig_len,
                ) != 0)
            {
                ret = DSA_do_check_signature(out_valid, digest, digest_len, s, dsa);
            }
        }
    }
    OPENSSL_free(der as *mut libc::c_void);
    DSA_SIG_free(s);
    return ret;
}
unsafe extern "C" fn der_len_len(mut len: size_t) -> size_t {
    if len < 0x80 as libc::c_int as size_t {
        return 1 as libc::c_int as size_t;
    }
    let mut ret: size_t = 1 as libc::c_int as size_t;
    while len > 0 as libc::c_int as size_t {
        ret = ret.wrapping_add(1);
        ret;
        len >>= 8 as libc::c_int;
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_size(mut dsa: *const DSA) -> libc::c_int {
    if ((*dsa).q).is_null() {
        return 0 as libc::c_int;
    }
    let mut order_len: size_t = BN_num_bytes((*dsa).q) as size_t;
    let mut integer_len: size_t = (1 as libc::c_int as size_t)
        .wrapping_add(der_len_len(order_len.wrapping_add(1 as libc::c_int as size_t)))
        .wrapping_add(1 as libc::c_int as size_t)
        .wrapping_add(order_len);
    if integer_len < order_len {
        return 0 as libc::c_int;
    }
    let mut value_len: size_t = 2 as libc::c_int as size_t * integer_len;
    if value_len < integer_len {
        return 0 as libc::c_int;
    }
    let mut ret: size_t = (1 as libc::c_int as size_t)
        .wrapping_add(der_len_len(value_len))
        .wrapping_add(value_len);
    if ret < value_len {
        return 0 as libc::c_int;
    }
    return ret as libc::c_int;
}
unsafe extern "C" fn dsa_sign_setup(
    mut dsa: *const DSA,
    mut ctx: *mut BN_CTX,
    mut out_kinv: *mut *mut BIGNUM,
    mut out_r: *mut *mut BIGNUM,
) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut k: BIGNUM = bignum_st {
        d: 0 as *mut BN_ULONG,
        width: 0,
        dmax: 0,
        neg: 0,
        flags: 0,
    };
    BN_init(&mut k);
    let mut r: *mut BIGNUM = BN_new();
    let mut kinv: *mut BIGNUM = BN_new();
    if r.is_null() || kinv.is_null()
        || BN_rand_range_ex(&mut k, 1 as libc::c_int as BN_ULONG, (*dsa).q) == 0
        || BN_MONT_CTX_set_locked(
            &(*dsa).method_mont_p as *const *mut BN_MONT_CTX as *mut *mut BN_MONT_CTX,
            &(*dsa).method_mont_lock as *const CRYPTO_MUTEX as *mut CRYPTO_MUTEX,
            (*dsa).p,
            ctx,
        ) == 0
        || BN_MONT_CTX_set_locked(
            &(*dsa).method_mont_q as *const *mut BN_MONT_CTX as *mut *mut BN_MONT_CTX,
            &(*dsa).method_mont_lock as *const CRYPTO_MUTEX as *mut CRYPTO_MUTEX,
            (*dsa).q,
            ctx,
        ) == 0
        || BN_mod_exp_mont_consttime(
            r,
            (*dsa).g,
            &mut k,
            (*dsa).p,
            ctx,
            (*dsa).method_mont_p,
        ) == 0
    {
        ERR_put_error(
            10 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa.c\0" as *const u8
                as *const libc::c_char,
            951 as libc::c_int as libc::c_uint,
        );
    } else {
        bn_declassify(r);
        if BN_div(0 as *mut BIGNUM, r, r, (*dsa).q, ctx) == 0
            || bn_mod_inverse_prime(kinv, &mut k, (*dsa).q, ctx, (*dsa).method_mont_q)
                == 0
        {
            ERR_put_error(
                10 as libc::c_int,
                0 as libc::c_int,
                3 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/dsa/dsa.c\0" as *const u8
                    as *const libc::c_char,
                966 as libc::c_int as libc::c_uint,
            );
        } else {
            BN_clear_free(*out_kinv);
            *out_kinv = kinv;
            kinv = 0 as *mut BIGNUM;
            BN_clear_free(*out_r);
            *out_r = r;
            r = 0 as *mut BIGNUM;
            ret = 1 as libc::c_int;
        }
    }
    BN_clear_free(&mut k);
    BN_clear_free(r);
    BN_clear_free(kinv);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_get_ex_new_index(
    mut argl: libc::c_long,
    mut argp: *mut libc::c_void,
    mut unused: *mut CRYPTO_EX_unused,
    mut dup_unused: Option::<CRYPTO_EX_dup>,
    mut free_func: Option::<CRYPTO_EX_free>,
) -> libc::c_int {
    let mut index: libc::c_int = 0;
    if CRYPTO_get_ex_new_index(&mut g_ex_data_class, &mut index, argl, argp, free_func)
        == 0
    {
        return -(1 as libc::c_int);
    }
    return index;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_set_ex_data(
    mut dsa: *mut DSA,
    mut idx: libc::c_int,
    mut arg: *mut libc::c_void,
) -> libc::c_int {
    return CRYPTO_set_ex_data(&mut (*dsa).ex_data, idx, arg);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_get_ex_data(
    mut dsa: *const DSA,
    mut idx: libc::c_int,
) -> *mut libc::c_void {
    return CRYPTO_get_ex_data(&(*dsa).ex_data, idx);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DSA_dup_DH(mut dsa: *const DSA) -> *mut DH {
    let mut current_block: u64;
    if dsa.is_null() {
        return 0 as *mut DH;
    }
    let mut ret: *mut DH = DH_new();
    if !ret.is_null() {
        if !((*dsa).q).is_null() {
            (*ret).priv_length = BN_num_bits((*dsa).q);
            (*ret).q = BN_dup((*dsa).q);
            if ((*ret).q).is_null() {
                current_block = 7371678146554864309;
            } else {
                current_block = 10879442775620481940;
            }
        } else {
            current_block = 10879442775620481940;
        }
        match current_block {
            7371678146554864309 => {}
            _ => {
                if !(!((*dsa).p).is_null()
                    && {
                        (*ret).p = BN_dup((*dsa).p);
                        ((*ret).p).is_null()
                    }
                    || !((*dsa).g).is_null()
                        && {
                            (*ret).g = BN_dup((*dsa).g);
                            ((*ret).g).is_null()
                        }
                    || !((*dsa).pub_key).is_null()
                        && {
                            (*ret).pub_key = BN_dup((*dsa).pub_key);
                            ((*ret).pub_key).is_null()
                        }
                    || !((*dsa).priv_key).is_null()
                        && {
                            (*ret).priv_key = BN_dup((*dsa).priv_key);
                            ((*ret).priv_key).is_null()
                        })
                {
                    return ret;
                }
            }
        }
    }
    DH_free(ret);
    return 0 as *mut DH;
}
