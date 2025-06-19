#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(asm, extern_types, label_break_value)]
use core::arch::asm;
unsafe extern "C" {
    pub type bignum_ctx;
    pub type stack_st_void;
    pub type engine_st;
    pub type evp_md_pctx_ops;
    pub type evp_pkey_ctx_st;
    pub type env_md_st;
    pub type evp_pkey_st;
    pub type stack_st_CRYPTO_EX_DATA_FUNCS;
    fn BN_new() -> *mut BIGNUM;
    fn BN_free(bn: *mut BIGNUM);
    fn BN_is_negative(bn: *const BIGNUM) -> libc::c_int;
    fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn ec_bignum_to_scalar(
        group: *const EC_GROUP,
        out: *mut EC_SCALAR,
        in_0: *const BIGNUM,
    ) -> libc::c_int;
    fn ec_random_nonzero_scalar(
        group: *const EC_GROUP,
        out: *mut EC_SCALAR,
        additional_data: *const uint8_t,
    ) -> libc::c_int;
    fn ec_scalar_is_zero(group: *const EC_GROUP, a: *const EC_SCALAR) -> libc::c_int;
    fn ec_felem_one(group: *const EC_GROUP) -> *const EC_FELEM;
    fn ec_felem_to_bignum(
        group: *const EC_GROUP,
        out: *mut BIGNUM,
        in_0: *const EC_FELEM,
    ) -> libc::c_int;
    fn ec_felem_equal(
        group: *const EC_GROUP,
        a: *const EC_FELEM,
        b: *const EC_FELEM,
    ) -> libc::c_int;
    fn ec_point_mul_scalar_base(
        group: *const EC_GROUP,
        r: *mut EC_JACOBIAN,
        scalar: *const EC_SCALAR,
    ) -> libc::c_int;
    fn ec_GFp_simple_points_equal(
        _: *const EC_GROUP,
        a: *const EC_JACOBIAN,
        b: *const EC_JACOBIAN,
    ) -> libc::c_int;
    fn EC_GROUP_new_by_curve_name(nid: libc::c_int) -> *mut EC_GROUP;
    fn EC_GROUP_cmp(
        a: *const EC_GROUP,
        b: *const EC_GROUP,
        ignored: *mut BN_CTX,
    ) -> libc::c_int;
    fn EC_GROUP_order_bits(group: *const EC_GROUP) -> libc::c_int;
    fn EC_POINT_new(group: *const EC_GROUP) -> *mut EC_POINT;
    fn EC_POINT_free(point: *mut EC_POINT);
    fn EC_POINT_dup(src: *const EC_POINT, group: *const EC_GROUP) -> *mut EC_POINT;
    fn EC_POINT_is_at_infinity(
        group: *const EC_GROUP,
        point: *const EC_POINT,
    ) -> libc::c_int;
    fn EC_POINT_is_on_curve(
        group: *const EC_GROUP,
        point: *const EC_POINT,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn EC_POINT_set_affine_coordinates_GFp(
        group: *const EC_GROUP,
        point: *mut EC_POINT,
        x: *const BIGNUM,
        y: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn EC_POINT_point2oct(
        group: *const EC_GROUP,
        point: *const EC_POINT,
        form: point_conversion_form_t,
        buf: *mut uint8_t,
        len: size_t,
        ctx: *mut BN_CTX,
    ) -> size_t;
    fn EC_GROUP_free(group: *mut EC_GROUP);
    fn EC_GROUP_dup(group: *const EC_GROUP) -> *mut EC_GROUP;
    fn EVP_sha256() -> *const EVP_MD;
    fn EVP_MD_CTX_init(ctx: *mut EVP_MD_CTX);
    fn EVP_MD_CTX_cleanse(ctx: *mut EVP_MD_CTX);
    fn ENGINE_get_EC(engine: *const ENGINE) -> *const EC_KEY_METHOD;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn EVP_PKEY_new() -> *mut EVP_PKEY;
    fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
    fn EVP_PKEY_set1_EC_KEY(pkey: *mut EVP_PKEY, key: *mut EC_KEY) -> libc::c_int;
    fn EVP_DigestSignInit(
        ctx: *mut EVP_MD_CTX,
        pctx: *mut *mut EVP_PKEY_CTX,
        type_0: *const EVP_MD,
        e: *mut ENGINE,
        pkey: *mut EVP_PKEY,
    ) -> libc::c_int;
    fn EVP_DigestSign(
        ctx: *mut EVP_MD_CTX,
        out_sig: *mut uint8_t,
        out_sig_len: *mut size_t,
        data: *const uint8_t,
        data_len: size_t,
    ) -> libc::c_int;
    fn EVP_DigestVerifyInit(
        ctx: *mut EVP_MD_CTX,
        pctx: *mut *mut EVP_PKEY_CTX,
        type_0: *const EVP_MD,
        e: *mut ENGINE,
        pkey: *mut EVP_PKEY,
    ) -> libc::c_int;
    fn EVP_DigestVerify(
        ctx: *mut EVP_MD_CTX,
        sig: *const uint8_t,
        sig_len: size_t,
        data: *const uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn CRYPTO_once(
        once: *mut CRYPTO_once_t,
        init: Option::<unsafe extern "C" fn() -> ()>,
    );
    fn CRYPTO_refcount_inc(count: *mut CRYPTO_refcount_t);
    fn CRYPTO_refcount_dec_and_test_zero(count: *mut CRYPTO_refcount_t) -> libc::c_int;
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
pub type pthread_once_t = libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_rwlock_t {
    pub __data: __pthread_rwlock_arch_t,
    pub __size: [libc::c_char; 56],
    pub __align: libc::c_long,
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ec_group_st {
    pub meth: *const EC_METHOD,
    pub generator: EC_POINT,
    pub order: BN_MONT_CTX,
    pub field: BN_MONT_CTX,
    pub a: EC_FELEM,
    pub b: EC_FELEM,
    pub comment: *const libc::c_char,
    pub curve_name: libc::c_int,
    pub oid: [uint8_t; 9],
    pub oid_len: uint8_t,
    pub a_is_minus3: libc::c_int,
    pub has_order: libc::c_int,
    pub field_greater_than_order: libc::c_int,
    pub conv_form: point_conversion_form_t,
    pub mutable_ec_group: libc::c_int,
}
pub type point_conversion_form_t = libc::c_uint;
pub const POINT_CONVERSION_HYBRID: point_conversion_form_t = 6;
pub const POINT_CONVERSION_UNCOMPRESSED: point_conversion_form_t = 4;
pub const POINT_CONVERSION_COMPRESSED: point_conversion_form_t = 2;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EC_FELEM {
    pub words: [BN_ULONG; 9],
}
pub type EC_POINT = ec_point_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ec_point_st {
    pub group: *mut EC_GROUP,
    pub raw: EC_JACOBIAN,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EC_JACOBIAN {
    pub X: EC_FELEM,
    pub Y: EC_FELEM,
    pub Z: EC_FELEM,
}
pub type EC_GROUP = ec_group_st;
pub type EC_METHOD = ec_method_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ec_method_st {
    pub point_get_affine_coordinates: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *const EC_JACOBIAN,
            *mut EC_FELEM,
            *mut EC_FELEM,
        ) -> libc::c_int,
    >,
    pub jacobian_to_affine_batch: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_AFFINE,
            *const EC_JACOBIAN,
            size_t,
        ) -> libc::c_int,
    >,
    pub add: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_JACOBIAN,
            *const EC_JACOBIAN,
            *const EC_JACOBIAN,
        ) -> (),
    >,
    pub dbl: Option::<
        unsafe extern "C" fn(*const EC_GROUP, *mut EC_JACOBIAN, *const EC_JACOBIAN) -> (),
    >,
    pub mul: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_JACOBIAN,
            *const EC_JACOBIAN,
            *const EC_SCALAR,
        ) -> (),
    >,
    pub mul_base: Option::<
        unsafe extern "C" fn(*const EC_GROUP, *mut EC_JACOBIAN, *const EC_SCALAR) -> (),
    >,
    pub mul_batch: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_JACOBIAN,
            *const EC_JACOBIAN,
            *const EC_SCALAR,
            *const EC_JACOBIAN,
            *const EC_SCALAR,
            *const EC_JACOBIAN,
            *const EC_SCALAR,
        ) -> (),
    >,
    pub mul_public: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_JACOBIAN,
            *const EC_SCALAR,
            *const EC_JACOBIAN,
            *const EC_SCALAR,
        ) -> (),
    >,
    pub mul_public_batch: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_JACOBIAN,
            *const EC_SCALAR,
            *const EC_JACOBIAN,
            *const EC_SCALAR,
            size_t,
        ) -> libc::c_int,
    >,
    pub init_precomp: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_PRECOMP,
            *const EC_JACOBIAN,
        ) -> libc::c_int,
    >,
    pub mul_precomp: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_JACOBIAN,
            *const EC_PRECOMP,
            *const EC_SCALAR,
            *const EC_PRECOMP,
            *const EC_SCALAR,
            *const EC_PRECOMP,
            *const EC_SCALAR,
        ) -> (),
    >,
    pub felem_mul: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_FELEM,
            *const EC_FELEM,
            *const EC_FELEM,
        ) -> (),
    >,
    pub felem_sqr: Option::<
        unsafe extern "C" fn(*const EC_GROUP, *mut EC_FELEM, *const EC_FELEM) -> (),
    >,
    pub felem_to_bytes: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut uint8_t,
            *mut size_t,
            *const EC_FELEM,
        ) -> (),
    >,
    pub felem_from_bytes: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_FELEM,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub felem_reduce: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_FELEM,
            *const BN_ULONG,
            size_t,
        ) -> (),
    >,
    pub felem_exp: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_FELEM,
            *const EC_FELEM,
            *const BN_ULONG,
            size_t,
        ) -> (),
    >,
    pub scalar_inv0_montgomery: Option::<
        unsafe extern "C" fn(*const EC_GROUP, *mut EC_SCALAR, *const EC_SCALAR) -> (),
    >,
    pub scalar_to_montgomery_inv_vartime: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_SCALAR,
            *const EC_SCALAR,
        ) -> libc::c_int,
    >,
    pub cmp_x_coordinate: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *const EC_JACOBIAN,
            *const EC_SCALAR,
        ) -> libc::c_int,
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EC_SCALAR {
    pub words: [BN_ULONG; 9],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union EC_PRECOMP {
    pub comb: [EC_AFFINE; 31],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EC_AFFINE {
    pub X: EC_FELEM,
    pub Y: EC_FELEM,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ec_key_st {
    pub group: *mut EC_GROUP,
    pub pub_key: *mut EC_POINT,
    pub priv_key: *mut EC_WRAPPED_SCALAR,
    pub enc_flag: libc::c_uint,
    pub conv_form: point_conversion_form_t,
    pub references: CRYPTO_refcount_t,
    pub eckey_method: *const EC_KEY_METHOD,
    pub ex_data: CRYPTO_EX_DATA,
}
pub type EC_KEY_METHOD = ec_key_method_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ec_key_method_st {
    pub init: Option::<unsafe extern "C" fn(*mut EC_KEY) -> libc::c_int>,
    pub finish: Option::<unsafe extern "C" fn(*mut EC_KEY) -> ()>,
    pub sign: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            libc::c_int,
            *mut uint8_t,
            *mut libc::c_uint,
            *const BIGNUM,
            *const BIGNUM,
            *mut EC_KEY,
        ) -> libc::c_int,
    >,
    pub sign_sig: Option::<
        unsafe extern "C" fn(
            *const uint8_t,
            libc::c_int,
            *const BIGNUM,
            *const BIGNUM,
            *mut EC_KEY,
        ) -> *mut ECDSA_SIG,
    >,
    pub flags: libc::c_int,
}
pub type EC_KEY = ec_key_st;
pub type ECDSA_SIG = ecdsa_sig_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ecdsa_sig_st {
    pub r: *mut BIGNUM,
    pub s: *mut BIGNUM,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EC_WRAPPED_SCALAR {
    pub bignum: BIGNUM,
    pub scalar: EC_SCALAR,
}
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
pub type EVP_PKEY = evp_pkey_st;
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
pub const PTHREAD_RWLOCK_DEFAULT_NP: C2RustUnnamed = 0;
pub type CRYPTO_once_t = pthread_once_t;
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
pub type C2RustUnnamed = libc::c_uint;
pub const PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP: C2RustUnnamed = 2;
pub const PTHREAD_RWLOCK_PREFER_WRITER_NP: C2RustUnnamed = 1;
pub const PTHREAD_RWLOCK_PREFER_READER_NP: C2RustUnnamed = 0;
#[inline]
unsafe extern "C" fn value_barrier_u32(mut a: uint32_t) -> uint32_t {
    asm!("", inlateout(reg) a, options(preserves_flags, pure, readonly, att_syntax));
    return a;
}
#[inline]
unsafe extern "C" fn constant_time_declassify_int(mut v: libc::c_int) -> libc::c_int {
    return value_barrier_u32(v as uint32_t) as libc::c_int;
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
unsafe extern "C" fn boringssl_ensure_ecc_self_test() {}
#[inline]
unsafe extern "C" fn boringssl_fips_break_test(
    mut test: *const libc::c_char,
) -> libc::c_int {
    return 0 as libc::c_int;
}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_lock_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_unlock_state() {}
#[inline]
unsafe extern "C" fn EC_KEY_keygen_verify_service_indicator(mut eckey: *const EC_KEY) {}
unsafe extern "C" fn g_ec_ex_data_class_bss_get() -> *mut CRYPTO_EX_DATA_CLASS {
    return &mut g_ec_ex_data_class;
}
static mut g_ec_ex_data_class: CRYPTO_EX_DATA_CLASS = {
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
unsafe extern "C" fn ec_wrapped_scalar_new(
    mut group: *const EC_GROUP,
) -> *mut EC_WRAPPED_SCALAR {
    let mut wrapped: *mut EC_WRAPPED_SCALAR = OPENSSL_zalloc(
        ::core::mem::size_of::<EC_WRAPPED_SCALAR>() as libc::c_ulong,
    ) as *mut EC_WRAPPED_SCALAR;
    if wrapped.is_null() {
        return 0 as *mut EC_WRAPPED_SCALAR;
    }
    (*wrapped).bignum.d = ((*wrapped).scalar.words).as_mut_ptr();
    (*wrapped).bignum.width = (*group).order.N.width;
    (*wrapped).bignum.dmax = (*group).order.N.width;
    (*wrapped).bignum.flags = 0x2 as libc::c_int;
    return wrapped;
}
unsafe extern "C" fn ec_wrapped_scalar_free(mut scalar: *mut EC_WRAPPED_SCALAR) {
    OPENSSL_free(scalar as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_new() -> *mut EC_KEY {
    return EC_KEY_new_method(0 as *const ENGINE);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_new_method(mut engine: *const ENGINE) -> *mut EC_KEY {
    let mut ret: *mut EC_KEY = OPENSSL_zalloc(
        ::core::mem::size_of::<EC_KEY>() as libc::c_ulong,
    ) as *mut EC_KEY;
    if ret.is_null() {
        return 0 as *mut EC_KEY;
    }
    if !engine.is_null() {
        (*ret).eckey_method = ENGINE_get_EC(engine) as *mut EC_KEY_METHOD;
    }
    if ((*ret).eckey_method).is_null() {
        (*ret).eckey_method = EC_KEY_get_default_method();
    }
    (*ret).conv_form = POINT_CONVERSION_UNCOMPRESSED;
    (*ret).references = 1 as libc::c_int as CRYPTO_refcount_t;
    CRYPTO_new_ex_data(&mut (*ret).ex_data);
    if !((*ret).eckey_method).is_null() && ((*(*ret).eckey_method).init).is_some()
        && ((*(*ret).eckey_method).init).expect("non-null function pointer")(ret) == 0
    {
        CRYPTO_free_ex_data(
            g_ec_ex_data_class_bss_get(),
            ret as *mut libc::c_void,
            &mut (*ret).ex_data,
        );
        OPENSSL_free(ret as *mut libc::c_void);
        return 0 as *mut EC_KEY;
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_new_by_curve_name(mut nid: libc::c_int) -> *mut EC_KEY {
    let mut ret: *mut EC_KEY = EC_KEY_new();
    if ret.is_null() {
        return 0 as *mut EC_KEY;
    }
    (*ret).group = EC_GROUP_new_by_curve_name(nid);
    if ((*ret).group).is_null() {
        EC_KEY_free(ret);
        return 0 as *mut EC_KEY;
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_free(mut r: *mut EC_KEY) {
    if r.is_null() {
        return;
    }
    if CRYPTO_refcount_dec_and_test_zero(&mut (*r).references) == 0 {
        return;
    }
    if !((*r).eckey_method).is_null() && ((*(*r).eckey_method).finish).is_some() {
        ((*(*r).eckey_method).finish).expect("non-null function pointer")(r);
    }
    CRYPTO_free_ex_data(
        g_ec_ex_data_class_bss_get(),
        r as *mut libc::c_void,
        &mut (*r).ex_data,
    );
    EC_GROUP_free((*r).group);
    EC_POINT_free((*r).pub_key);
    ec_wrapped_scalar_free((*r).priv_key);
    OPENSSL_free(r as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_dup(mut src: *const EC_KEY) -> *mut EC_KEY {
    if src.is_null() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                as *const u8 as *const libc::c_char,
            174 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EC_KEY;
    }
    let mut ret: *mut EC_KEY = EC_KEY_new();
    if ret.is_null() {
        return 0 as *mut EC_KEY;
    }
    if !((*src).group).is_null() && EC_KEY_set_group(ret, (*src).group) == 0
        || !((*src).pub_key).is_null() && EC_KEY_set_public_key(ret, (*src).pub_key) == 0
        || !((*src).priv_key).is_null()
            && EC_KEY_set_private_key(ret, EC_KEY_get0_private_key(src)) == 0
    {
        EC_KEY_free(ret);
        return 0 as *mut EC_KEY;
    }
    (*ret).enc_flag = (*src).enc_flag;
    (*ret).conv_form = (*src).conv_form;
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_up_ref(mut r: *mut EC_KEY) -> libc::c_int {
    CRYPTO_refcount_inc(&mut (*r).references);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_is_opaque(mut key: *const EC_KEY) -> libc::c_int {
    return (!((*key).eckey_method).is_null()
        && (*(*key).eckey_method).flags & 1 as libc::c_int != 0) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_get0_group(mut key: *const EC_KEY) -> *const EC_GROUP {
    return (*key).group;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_set_group(
    mut key: *mut EC_KEY,
    mut group: *const EC_GROUP,
) -> libc::c_int {
    if !((*key).group).is_null() {
        if EC_GROUP_cmp((*key).group, group, 0 as *mut BN_CTX) != 0 as libc::c_int {
            ERR_put_error(
                15 as libc::c_int,
                0 as libc::c_int,
                130 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                    as *const u8 as *const libc::c_char,
                213 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        return 1 as libc::c_int;
    }
    if ((*key).priv_key).is_null() {} else {
        __assert_fail(
            b"key->priv_key == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                as *const u8 as *const libc::c_char,
            219 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 49],
                &[libc::c_char; 49],
            >(b"int EC_KEY_set_group(EC_KEY *, const EC_GROUP *)\0"))
                .as_ptr(),
        );
    }
    'c_4302: {
        if ((*key).priv_key).is_null() {} else {
            __assert_fail(
                b"key->priv_key == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                    as *const u8 as *const libc::c_char,
                219 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 49],
                    &[libc::c_char; 49],
                >(b"int EC_KEY_set_group(EC_KEY *, const EC_GROUP *)\0"))
                    .as_ptr(),
            );
        }
    };
    if ((*key).pub_key).is_null() {} else {
        __assert_fail(
            b"key->pub_key == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                as *const u8 as *const libc::c_char,
            220 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 49],
                &[libc::c_char; 49],
            >(b"int EC_KEY_set_group(EC_KEY *, const EC_GROUP *)\0"))
                .as_ptr(),
        );
    }
    'c_4246: {
        if ((*key).pub_key).is_null() {} else {
            __assert_fail(
                b"key->pub_key == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                    as *const u8 as *const libc::c_char,
                220 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 49],
                    &[libc::c_char; 49],
                >(b"int EC_KEY_set_group(EC_KEY *, const EC_GROUP *)\0"))
                    .as_ptr(),
            );
        }
    };
    EC_GROUP_free((*key).group);
    (*key).group = EC_GROUP_dup(group);
    return ((*key).group != 0 as *mut libc::c_void as *mut EC_GROUP) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_get0_private_key(
    mut key: *const EC_KEY,
) -> *const BIGNUM {
    return if !((*key).priv_key).is_null() {
        &mut (*(*key).priv_key).bignum
    } else {
        0 as *mut BIGNUM
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_set_private_key(
    mut key: *mut EC_KEY,
    mut priv_key: *const BIGNUM,
) -> libc::c_int {
    if ((*key).group).is_null() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            114 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                as *const u8 as *const libc::c_char,
            233 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut scalar: *mut EC_WRAPPED_SCALAR = ec_wrapped_scalar_new((*key).group);
    if scalar.is_null() {
        return 0 as libc::c_int;
    }
    if ec_bignum_to_scalar((*key).group, &mut (*scalar).scalar, priv_key) == 0
        || constant_time_declassify_int(
            ec_scalar_is_zero((*key).group, &mut (*scalar).scalar),
        ) != 0
    {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            113 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                as *const u8 as *const libc::c_char,
            246 as libc::c_int as libc::c_uint,
        );
        ec_wrapped_scalar_free(scalar);
        return 0 as libc::c_int;
    }
    ec_wrapped_scalar_free((*key).priv_key);
    (*key).priv_key = scalar;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_get0_public_key(
    mut key: *const EC_KEY,
) -> *const EC_POINT {
    return (*key).pub_key;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_set_public_key(
    mut key: *mut EC_KEY,
    mut pub_key: *const EC_POINT,
) -> libc::c_int {
    if ((*key).group).is_null() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            114 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                as *const u8 as *const libc::c_char,
            261 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if !pub_key.is_null()
        && EC_GROUP_cmp((*key).group, (*pub_key).group, 0 as *mut BN_CTX)
            != 0 as libc::c_int
    {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            130 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                as *const u8 as *const libc::c_char,
            266 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    EC_POINT_free((*key).pub_key);
    (*key).pub_key = EC_POINT_dup(pub_key, (*key).group);
    return if ((*key).pub_key).is_null() { 0 as libc::c_int } else { 1 as libc::c_int };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_get_enc_flags(mut key: *const EC_KEY) -> libc::c_uint {
    return (*key).enc_flag;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_set_enc_flags(
    mut key: *mut EC_KEY,
    mut flags: libc::c_uint,
) {
    (*key).enc_flag = flags;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_get_conv_form(
    mut key: *const EC_KEY,
) -> point_conversion_form_t {
    return (*key).conv_form;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_set_conv_form(
    mut key: *mut EC_KEY,
    mut cform: point_conversion_form_t,
) {
    if key.is_null() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                as *const u8 as *const libc::c_char,
            287 as libc::c_int as libc::c_uint,
        );
        return;
    }
    (*key).conv_form = cform;
    if !((*key).group).is_null() && (*(*key).group).mutable_ec_group != 0 {
        (*(*key).group).conv_form = cform;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_check_key(mut eckey: *const EC_KEY) -> libc::c_int {
    if eckey.is_null() || ((*eckey).group).is_null() || ((*eckey).pub_key).is_null() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                as *const u8 as *const libc::c_char,
            298 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if EC_POINT_is_at_infinity((*eckey).group, (*eckey).pub_key) != 0 {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            119 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                as *const u8 as *const libc::c_char,
            303 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if EC_POINT_is_on_curve((*eckey).group, (*eckey).pub_key, 0 as *mut BN_CTX) == 0 {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            120 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                as *const u8 as *const libc::c_char,
            309 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if !((*eckey).priv_key).is_null() {
        let mut point: EC_JACOBIAN = EC_JACOBIAN {
            X: EC_FELEM { words: [0; 9] },
            Y: EC_FELEM { words: [0; 9] },
            Z: EC_FELEM { words: [0; 9] },
        };
        if ec_point_mul_scalar_base(
            (*eckey).group,
            &mut point,
            &mut (*(*eckey).priv_key).scalar,
        ) == 0
        {
            ERR_put_error(
                15 as libc::c_int,
                0 as libc::c_int,
                15 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                    as *const u8 as *const libc::c_char,
                321 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        if constant_time_declassify_int(
            ec_GFp_simple_points_equal(
                (*eckey).group,
                &mut point,
                &mut (*(*eckey).pub_key).raw,
            ),
        ) == 0
        {
            ERR_put_error(
                15 as libc::c_int,
                0 as libc::c_int,
                113 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                    as *const u8 as *const libc::c_char,
                328 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn EVP_EC_KEY_check_fips(mut key: *mut EC_KEY) -> libc::c_int {
    let mut msg: [uint8_t; 16] = [
        0 as libc::c_int as uint8_t,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    let mut msg_len: size_t = 16 as libc::c_int as size_t;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut sig_der: *mut uint8_t = 0 as *mut uint8_t;
    let mut evp_pkey: *mut EVP_PKEY = EVP_PKEY_new();
    let mut ctx: EVP_MD_CTX = env_md_ctx_st {
        digest: 0 as *const EVP_MD,
        md_data: 0 as *mut libc::c_void,
        update: None,
        pctx: 0 as *mut EVP_PKEY_CTX,
        pctx_ops: 0 as *const evp_md_pctx_ops,
        flags: 0,
    };
    EVP_MD_CTX_init(&mut ctx);
    let mut hash: *const EVP_MD = EVP_sha256();
    let mut sign_len: size_t = 0;
    if !(evp_pkey.is_null() || EVP_PKEY_set1_EC_KEY(evp_pkey, key) == 0
        || EVP_DigestSignInit(
            &mut ctx,
            0 as *mut *mut EVP_PKEY_CTX,
            hash,
            0 as *mut ENGINE,
            evp_pkey,
        ) == 0
        || EVP_DigestSign(
            &mut ctx,
            0 as *mut uint8_t,
            &mut sign_len,
            msg.as_mut_ptr(),
            msg_len,
        ) == 0)
    {
        sig_der = OPENSSL_malloc(sign_len) as *mut uint8_t;
        if !(sig_der.is_null()
            || EVP_DigestSign(
                &mut ctx,
                sig_der,
                &mut sign_len,
                msg.as_mut_ptr(),
                msg_len,
            ) == 0)
        {
            if boringssl_fips_break_test(
                b"ECDSA_PWCT\0" as *const u8 as *const libc::c_char,
            ) != 0
            {
                msg[0 as libc::c_int
                    as usize] = !(msg[0 as libc::c_int as usize] as libc::c_int)
                    as uint8_t;
            }
            if !(EVP_DigestVerifyInit(
                &mut ctx,
                0 as *mut *mut EVP_PKEY_CTX,
                hash,
                0 as *mut ENGINE,
                evp_pkey,
            ) == 0
                || EVP_DigestVerify(
                    &mut ctx,
                    sig_der,
                    sign_len,
                    msg.as_mut_ptr(),
                    msg_len,
                ) == 0)
            {
                ret = 1 as libc::c_int;
            }
        }
    }
    EVP_PKEY_free(evp_pkey);
    EVP_MD_CTX_cleanse(&mut ctx);
    OPENSSL_free(sig_der as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_check_fips(mut key: *const EC_KEY) -> libc::c_int {
    let mut pub_key: *mut EC_POINT = 0 as *mut EC_POINT;
    let mut group: *mut EC_GROUP = 0 as *mut EC_GROUP;
    let mut current_block: u64;
    FIPS_service_indicator_lock_state();
    let mut ret: libc::c_int = 0 as libc::c_int;
    if EC_KEY_is_opaque(key) != 0 {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            132 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                as *const u8 as *const libc::c_char,
            381 as libc::c_int as libc::c_uint,
        );
    } else if !(EC_KEY_check_key(key) == 0) {
        pub_key = (*key).pub_key;
        group = (*(*key).pub_key).group;
        if ec_felem_equal(group, ec_felem_one(group), &mut (*pub_key).raw.Z) != 0 {
            let mut x: *mut BIGNUM = BN_new();
            let mut y: *mut BIGNUM = BN_new();
            let mut check_ret: libc::c_int = 1 as libc::c_int;
            if ((*(*group).meth).felem_to_bytes).is_none() {
                ERR_put_error(
                    15 as libc::c_int,
                    0 as libc::c_int,
                    2 as libc::c_int | 64 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                        as *const u8 as *const libc::c_char,
                    401 as libc::c_int as libc::c_uint,
                );
                check_ret = 0 as libc::c_int;
            } else if ec_felem_to_bignum(group, x, &mut (*pub_key).raw.X) == 0
                || ec_felem_to_bignum(group, y, &mut (*pub_key).raw.Y) == 0
            {
                check_ret = 0 as libc::c_int;
            } else if BN_is_negative(x) != 0 || BN_is_negative(y) != 0
                || BN_cmp(x, &mut (*group).field.N) >= 0 as libc::c_int
                || BN_cmp(y, &mut (*group).field.N) >= 0 as libc::c_int
            {
                ERR_put_error(
                    15 as libc::c_int,
                    0 as libc::c_int,
                    101 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                        as *const u8 as *const libc::c_char,
                    410 as libc::c_int as libc::c_uint,
                );
                check_ret = 0 as libc::c_int;
            }
            BN_free(x);
            BN_free(y);
            if check_ret == 0 as libc::c_int {
                current_block = 15709216604464022035;
            } else {
                current_block = 2370887241019905314;
            }
        } else {
            current_block = 2370887241019905314;
        }
        match current_block {
            15709216604464022035 => {}
            _ => {
                if !((*key).priv_key).is_null() {
                    if EVP_EC_KEY_check_fips(key as *mut EC_KEY) == 0 {
                        ERR_put_error(
                            15 as libc::c_int,
                            0 as libc::c_int,
                            132 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                                as *const u8 as *const libc::c_char,
                            422 as libc::c_int as libc::c_uint,
                        );
                        current_block = 15709216604464022035;
                    } else {
                        current_block = 18317007320854588510;
                    }
                } else {
                    current_block = 18317007320854588510;
                }
                match current_block {
                    15709216604464022035 => {}
                    _ => {
                        ret = 1 as libc::c_int;
                    }
                }
            }
        }
    }
    FIPS_service_indicator_unlock_state();
    if ret != 0 {
        EC_KEY_keygen_verify_service_indicator(key as *mut EC_KEY);
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_set_public_key_affine_coordinates(
    mut key: *mut EC_KEY,
    mut x: *const BIGNUM,
    mut y: *const BIGNUM,
) -> libc::c_int {
    let mut point: *mut EC_POINT = 0 as *mut EC_POINT;
    let mut ok: libc::c_int = 0 as libc::c_int;
    if key.is_null() || ((*key).group).is_null() || x.is_null() || y.is_null() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                as *const u8 as *const libc::c_char,
            442 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    point = EC_POINT_new((*key).group);
    if !(point.is_null()
        || EC_POINT_set_affine_coordinates_GFp(
            (*key).group,
            point,
            x,
            y,
            0 as *mut BN_CTX,
        ) == 0 || EC_KEY_set_public_key(key, point) == 0 || EC_KEY_check_key(key) == 0)
    {
        ok = 1 as libc::c_int;
    }
    EC_POINT_free(point);
    return ok;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_key2buf(
    mut key: *const EC_KEY,
    mut form: point_conversion_form_t,
    mut out_buf: *mut *mut libc::c_uchar,
    mut ctx: *mut BN_CTX,
) -> size_t {
    if key.is_null() || ((*key).pub_key).is_null() || ((*key).group).is_null() {
        return 0 as libc::c_int as size_t;
    }
    let len: size_t = EC_POINT_point2oct(
        (*key).group,
        (*key).pub_key,
        form,
        0 as *mut uint8_t,
        0 as libc::c_int as size_t,
        ctx,
    );
    if len == 0 as libc::c_int as size_t {
        return 0 as libc::c_int as size_t;
    }
    let mut buf: *mut uint8_t = OPENSSL_malloc(len) as *mut uint8_t;
    if buf.is_null() {
        return 0 as libc::c_int as size_t;
    }
    if EC_POINT_point2oct((*key).group, (*key).pub_key, form, buf, len, ctx) != len {
        OPENSSL_free(buf as *mut libc::c_void);
        return 0 as libc::c_int as size_t;
    }
    *out_buf = buf;
    return len;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_generate_key(mut key: *mut EC_KEY) -> libc::c_int {
    if key.is_null() || ((*key).group).is_null() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                as *const u8 as *const libc::c_char,
            490 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if EC_GROUP_order_bits((*key).group) < 160 as libc::c_int {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            112 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                as *const u8 as *const libc::c_char,
            496 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    static mut kDefaultAdditionalData: [uint8_t; 32] = [
        0 as libc::c_int as uint8_t,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    let mut priv_key: *mut EC_WRAPPED_SCALAR = ec_wrapped_scalar_new((*key).group);
    let mut pub_key: *mut EC_POINT = EC_POINT_new((*key).group);
    if priv_key.is_null() || pub_key.is_null()
        || ec_random_nonzero_scalar(
            (*key).group,
            &mut (*priv_key).scalar,
            kDefaultAdditionalData.as_ptr(),
        ) == 0
        || ec_point_mul_scalar_base(
            (*key).group,
            &mut (*pub_key).raw,
            &mut (*priv_key).scalar,
        ) == 0
    {
        EC_POINT_free(pub_key);
        ec_wrapped_scalar_free(priv_key);
        return 0 as libc::c_int;
    }
    ec_wrapped_scalar_free((*key).priv_key);
    (*key).priv_key = priv_key;
    EC_POINT_free((*key).pub_key);
    (*key).pub_key = pub_key;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_generate_key_fips(
    mut eckey: *mut EC_KEY,
) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    FIPS_service_indicator_lock_state();
    boringssl_ensure_ecc_self_test();
    if EC_KEY_generate_key(eckey) != 0 && EC_KEY_check_fips(eckey) != 0 {
        ret = 1 as libc::c_int;
    }
    FIPS_service_indicator_unlock_state();
    if ret != 0 {
        EC_KEY_keygen_verify_service_indicator(eckey);
        return 1 as libc::c_int;
    }
    EC_POINT_free((*eckey).pub_key);
    ec_wrapped_scalar_free((*eckey).priv_key);
    (*eckey).pub_key = 0 as *mut EC_POINT;
    (*eckey).priv_key = 0 as *mut EC_WRAPPED_SCALAR;
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_get_ex_new_index(
    mut argl: libc::c_long,
    mut argp: *mut libc::c_void,
    mut unused: *mut CRYPTO_EX_unused,
    mut dup_unused: Option::<CRYPTO_EX_dup>,
    mut free_func: Option::<CRYPTO_EX_free>,
) -> libc::c_int {
    let mut index: libc::c_int = 0;
    if CRYPTO_get_ex_new_index(
        g_ec_ex_data_class_bss_get(),
        &mut index,
        argl,
        argp,
        free_func,
    ) == 0
    {
        return -(1 as libc::c_int);
    }
    return index;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_set_ex_data(
    mut d: *mut EC_KEY,
    mut idx: libc::c_int,
    mut arg: *mut libc::c_void,
) -> libc::c_int {
    return CRYPTO_set_ex_data(&mut (*d).ex_data, idx, arg);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_get_ex_data(
    mut d: *const EC_KEY,
    mut idx: libc::c_int,
) -> *mut libc::c_void {
    return CRYPTO_get_ex_data(&(*d).ex_data, idx);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_set_asn1_flag(
    mut key: *mut EC_KEY,
    mut flag: libc::c_int,
) {}
static mut EC_KEY_OpenSSL_once: CRYPTO_once_t = 0 as libc::c_int;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_OpenSSL() -> *const EC_KEY_METHOD {
    CRYPTO_once(
        EC_KEY_OpenSSL_once_bss_get(),
        Some(EC_KEY_OpenSSL_init as unsafe extern "C" fn() -> ()),
    );
    return EC_KEY_OpenSSL_storage_bss_get() as *const EC_KEY_METHOD;
}
unsafe extern "C" fn EC_KEY_OpenSSL_once_bss_get() -> *mut CRYPTO_once_t {
    return &mut EC_KEY_OpenSSL_once;
}
unsafe extern "C" fn EC_KEY_OpenSSL_storage_bss_get() -> *mut EC_KEY_METHOD {
    return &mut EC_KEY_OpenSSL_storage;
}
unsafe extern "C" fn EC_KEY_OpenSSL_init() {
    EC_KEY_OpenSSL_do_init(EC_KEY_OpenSSL_storage_bss_get());
}
unsafe extern "C" fn EC_KEY_OpenSSL_do_init(mut out: *mut EC_KEY_METHOD) {
    OPENSSL_memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EC_KEY_METHOD>() as libc::c_ulong,
    );
}
static mut EC_KEY_OpenSSL_storage: EC_KEY_METHOD = ec_key_method_st {
    init: None,
    finish: None,
    sign: None,
    sign_sig: None,
    flags: 0,
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_get_default_method() -> *const EC_KEY_METHOD {
    return EC_KEY_OpenSSL();
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_METHOD_new(
    mut eckey_meth: *const EC_KEY_METHOD,
) -> *mut EC_KEY_METHOD {
    let mut ret: *mut EC_KEY_METHOD = 0 as *mut EC_KEY_METHOD;
    ret = OPENSSL_zalloc(::core::mem::size_of::<EC_KEY_METHOD>() as libc::c_ulong)
        as *mut EC_KEY_METHOD;
    if ret.is_null() {
        return 0 as *mut EC_KEY_METHOD;
    }
    if !eckey_meth.is_null() {
        *ret = *eckey_meth;
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_METHOD_free(mut eckey_meth: *mut EC_KEY_METHOD) {
    if !eckey_meth.is_null() {
        OPENSSL_free(eckey_meth as *mut libc::c_void);
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_set_method(
    mut ec: *mut EC_KEY,
    mut meth: *const EC_KEY_METHOD,
) -> libc::c_int {
    if ec.is_null() || meth.is_null() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                as *const u8 as *const libc::c_char,
            609 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    (*ec).eckey_method = meth;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_get_method(
    mut ec: *const EC_KEY,
) -> *const EC_KEY_METHOD {
    if ec.is_null() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                as *const u8 as *const libc::c_char,
            619 as libc::c_int as libc::c_uint,
        );
        return 0 as *const EC_KEY_METHOD;
    }
    return (*ec).eckey_method;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_METHOD_set_init_awslc(
    mut meth: *mut EC_KEY_METHOD,
    mut init: Option::<unsafe extern "C" fn(*mut EC_KEY) -> libc::c_int>,
    mut finish: Option::<unsafe extern "C" fn(*mut EC_KEY) -> ()>,
) {
    if meth.is_null() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                as *const u8 as *const libc::c_char,
            629 as libc::c_int as libc::c_uint,
        );
        return;
    }
    (*meth).init = init;
    (*meth).finish = finish;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_METHOD_set_sign_awslc(
    mut meth: *mut EC_KEY_METHOD,
    mut sign: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            libc::c_int,
            *mut uint8_t,
            *mut libc::c_uint,
            *const BIGNUM,
            *const BIGNUM,
            *mut EC_KEY,
        ) -> libc::c_int,
    >,
    mut sign_sig: Option::<
        unsafe extern "C" fn(
            *const uint8_t,
            libc::c_int,
            *const BIGNUM,
            *const BIGNUM,
            *mut EC_KEY,
        ) -> *mut ECDSA_SIG,
    >,
) {
    if meth.is_null() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ec/ec_key.c\0"
                as *const u8 as *const libc::c_char,
            648 as libc::c_int as libc::c_uint,
        );
        return;
    }
    (*meth).sign = sign;
    (*meth).sign_sig = sign_sig;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_METHOD_set_flags(
    mut meth: *mut EC_KEY_METHOD,
    mut flags: libc::c_int,
) -> libc::c_int {
    if meth.is_null() || flags != 1 as libc::c_int {
        return 0 as libc::c_int;
    }
    (*meth).flags |= flags;
    return 1 as libc::c_int;
}
