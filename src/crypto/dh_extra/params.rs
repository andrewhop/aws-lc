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
    pub type bignum_ctx;
    fn BN_new() -> *mut BIGNUM;
    fn BN_free(bn: *mut BIGNUM);
    fn BN_dup(src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_set_word(bn: *mut BIGNUM, value: BN_ULONG) -> libc::c_int;
    fn BN_CTX_new() -> *mut BN_CTX;
    fn BN_CTX_free(ctx: *mut BN_CTX);
    fn BN_CTX_start(ctx: *mut BN_CTX);
    fn BN_CTX_get(ctx: *mut BN_CTX) -> *mut BIGNUM;
    fn BN_CTX_end(ctx: *mut BN_CTX);
    fn BN_GENCB_call(
        callback: *mut BN_GENCB,
        event: libc::c_int,
        n: libc::c_int,
    ) -> libc::c_int;
    fn BN_generate_prime_ex(
        ret: *mut BIGNUM,
        bits: libc::c_int,
        safe: libc::c_int,
        add: *const BIGNUM,
        rem: *const BIGNUM,
        cb: *mut BN_GENCB,
    ) -> libc::c_int;
    fn DH_new() -> *mut DH;
    fn DH_free(dh: *mut DH);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn bn_set_words(bn: *mut BIGNUM, words: *const BN_ULONG, num: size_t) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
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
pub type CRYPTO_refcount_t = uint32_t;
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
pub struct standard_parameters {
    pub p: BIGNUM,
    pub q: BIGNUM,
    pub g: BIGNUM,
}
unsafe extern "C" fn get_params(
    mut ret: *mut BIGNUM,
    mut words: *const BN_ULONG,
    mut num_words: size_t,
) -> *mut BIGNUM {
    let mut alloc: *mut BIGNUM = 0 as *mut BIGNUM;
    if ret.is_null() {
        alloc = BN_new();
        if alloc.is_null() {
            return 0 as *mut BIGNUM;
        }
        ret = alloc;
    }
    if bn_set_words(ret, words, num_words) == 0 {
        BN_free(alloc);
        return 0 as *mut BIGNUM;
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_get_rfc3526_prime_1536(mut ret: *mut BIGNUM) -> *mut BIGNUM {
    static mut kWords: [BN_ULONG; 24] = [
        (0xffffffff as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xffffffff as libc::c_uint as BN_ULONG,
        (0xf1746c08 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xca237327 as libc::c_uint as BN_ULONG,
        (0x670c354e as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x4abc9804 as libc::c_int as BN_ULONG,
        (0x9ed52907 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7096966d as libc::c_int as BN_ULONG,
        (0x1c62f356 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x208552bb as libc::c_int as BN_ULONG,
        (0x83655d23 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xdca3ad96 as libc::c_uint as BN_ULONG,
        (0x69163fa8 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xfd24cf5f as libc::c_uint as BN_ULONG,
        (0x98da4836 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x1c55d39a as libc::c_int as BN_ULONG,
        (0xc2007cb8 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa163bf05 as libc::c_uint as BN_ULONG,
        (0x49286651 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xece45b3d as libc::c_uint as BN_ULONG,
        (0xae9f2411 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7c4b1fe6 as libc::c_int as BN_ULONG,
        (0xee386bfb as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x5a899fa5 as libc::c_int as BN_ULONG,
        (0xbff5cb6 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xf406b7ed as libc::c_uint as BN_ULONG,
        (0xf44c42e9 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa637ed6b as libc::c_uint as BN_ULONG,
        (0xe485b576 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x625e7ec6 as libc::c_int as BN_ULONG,
        (0x4fe1356d as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x6d51c245 as libc::c_int as BN_ULONG,
        (0x302b0a6d as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xf25f1437 as libc::c_uint as BN_ULONG,
        (0xef9519b3 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xcd3a431b as libc::c_uint as BN_ULONG,
        (0x514a0879 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x8e3404dd as libc::c_uint as BN_ULONG,
        (0x20bbea6 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x3b139b22 as libc::c_int as BN_ULONG,
        (0x29024e08 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x8a67cc74 as libc::c_uint as BN_ULONG,
        (0xc4c6628b as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x80dc1cd1 as libc::c_uint as BN_ULONG,
        (0xc90fdaa2 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x2168c234 as libc::c_int as BN_ULONG,
        (0xffffffff as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xffffffff as libc::c_uint as BN_ULONG,
    ];
    return get_params(
        ret,
        kWords.as_ptr(),
        (::core::mem::size_of::<[BN_ULONG; 24]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_get_rfc3526_prime_2048(mut ret: *mut BIGNUM) -> *mut BIGNUM {
    static mut kWords: [BN_ULONG; 32] = [
        (0xffffffff as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xffffffff as libc::c_uint as BN_ULONG,
        (0x15728e5a as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x8aacaa68 as libc::c_uint as BN_ULONG,
        (0x15d22618 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x98fa0510 as libc::c_uint as BN_ULONG,
        (0x3995497c as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xea956ae5 as libc::c_uint as BN_ULONG,
        (0xde2bcbf6 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x95581718 as libc::c_uint as BN_ULONG,
        (0xb5c55df0 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x6f4c52c9 as libc::c_int as BN_ULONG,
        (0x9b2783a2 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xec07a28f as libc::c_uint as BN_ULONG,
        (0xe39e772c as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x180e8603 as libc::c_int as BN_ULONG,
        (0x32905e46 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x2e36ce3b as libc::c_int as BN_ULONG,
        (0xf1746c08 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xca18217c as libc::c_uint as BN_ULONG,
        (0x670c354e as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x4abc9804 as libc::c_int as BN_ULONG,
        (0x9ed52907 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7096966d as libc::c_int as BN_ULONG,
        (0x1c62f356 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x208552bb as libc::c_int as BN_ULONG,
        (0x83655d23 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xdca3ad96 as libc::c_uint as BN_ULONG,
        (0x69163fa8 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xfd24cf5f as libc::c_uint as BN_ULONG,
        (0x98da4836 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x1c55d39a as libc::c_int as BN_ULONG,
        (0xc2007cb8 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa163bf05 as libc::c_uint as BN_ULONG,
        (0x49286651 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xece45b3d as libc::c_uint as BN_ULONG,
        (0xae9f2411 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7c4b1fe6 as libc::c_int as BN_ULONG,
        (0xee386bfb as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x5a899fa5 as libc::c_int as BN_ULONG,
        (0xbff5cb6 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xf406b7ed as libc::c_uint as BN_ULONG,
        (0xf44c42e9 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa637ed6b as libc::c_uint as BN_ULONG,
        (0xe485b576 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x625e7ec6 as libc::c_int as BN_ULONG,
        (0x4fe1356d as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x6d51c245 as libc::c_int as BN_ULONG,
        (0x302b0a6d as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xf25f1437 as libc::c_uint as BN_ULONG,
        (0xef9519b3 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xcd3a431b as libc::c_uint as BN_ULONG,
        (0x514a0879 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x8e3404dd as libc::c_uint as BN_ULONG,
        (0x20bbea6 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x3b139b22 as libc::c_int as BN_ULONG,
        (0x29024e08 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x8a67cc74 as libc::c_uint as BN_ULONG,
        (0xc4c6628b as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x80dc1cd1 as libc::c_uint as BN_ULONG,
        (0xc90fdaa2 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x2168c234 as libc::c_int as BN_ULONG,
        (0xffffffff as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xffffffff as libc::c_uint as BN_ULONG,
    ];
    return get_params(
        ret,
        kWords.as_ptr(),
        (::core::mem::size_of::<[BN_ULONG; 32]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_get_rfc3526_prime_3072(mut ret: *mut BIGNUM) -> *mut BIGNUM {
    static mut kWords: [BN_ULONG; 48] = [
        (0xffffffff as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xffffffff as libc::c_uint as BN_ULONG,
        (0x4b82d120 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xa93ad2ca as libc::c_uint as BN_ULONG,
        (0x43db5bfc as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xe0fd108e as libc::c_uint as BN_ULONG,
        (0x8e24fa0 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x74e5ab31 as libc::c_int as BN_ULONG,
        (0x770988c0 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xbad946e2 as libc::c_uint as BN_ULONG,
        (0xbbe11757 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7a615d6c as libc::c_int as BN_ULONG,
        (0x521f2b18 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x177b200c as libc::c_int as BN_ULONG,
        (0xd8760273 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x3ec86a64 as libc::c_int as BN_ULONG,
        (0xf12ffa06 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xd98a0864 as libc::c_uint as BN_ULONG,
        (0xcee3d226 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x1ad2ee6b as libc::c_int as BN_ULONG,
        (0x1e8c94e0 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x4a25619d as libc::c_int as BN_ULONG,
        (0xabf5ae8c as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xdb0933d7 as libc::c_uint as BN_ULONG,
        (0xb3970f85 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa6e1e4c7 as libc::c_uint as BN_ULONG,
        (0x8aea7157 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x5d060c7d as libc::c_int as BN_ULONG,
        (0xecfb8504 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x58dbef0a as libc::c_int as BN_ULONG,
        (0xa85521ab as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xdf1cba64 as libc::c_uint as BN_ULONG,
        (0xad33170d as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x4507a33 as libc::c_int as BN_ULONG,
        (0x15728e5a as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x8aaac42d as libc::c_uint as BN_ULONG,
        (0x15d22618 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x98fa0510 as libc::c_uint as BN_ULONG,
        (0x3995497c as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xea956ae5 as libc::c_uint as BN_ULONG,
        (0xde2bcbf6 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x95581718 as libc::c_uint as BN_ULONG,
        (0xb5c55df0 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x6f4c52c9 as libc::c_int as BN_ULONG,
        (0x9b2783a2 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xec07a28f as libc::c_uint as BN_ULONG,
        (0xe39e772c as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x180e8603 as libc::c_int as BN_ULONG,
        (0x32905e46 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x2e36ce3b as libc::c_int as BN_ULONG,
        (0xf1746c08 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xca18217c as libc::c_uint as BN_ULONG,
        (0x670c354e as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x4abc9804 as libc::c_int as BN_ULONG,
        (0x9ed52907 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7096966d as libc::c_int as BN_ULONG,
        (0x1c62f356 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x208552bb as libc::c_int as BN_ULONG,
        (0x83655d23 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xdca3ad96 as libc::c_uint as BN_ULONG,
        (0x69163fa8 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xfd24cf5f as libc::c_uint as BN_ULONG,
        (0x98da4836 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x1c55d39a as libc::c_int as BN_ULONG,
        (0xc2007cb8 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa163bf05 as libc::c_uint as BN_ULONG,
        (0x49286651 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xece45b3d as libc::c_uint as BN_ULONG,
        (0xae9f2411 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7c4b1fe6 as libc::c_int as BN_ULONG,
        (0xee386bfb as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x5a899fa5 as libc::c_int as BN_ULONG,
        (0xbff5cb6 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xf406b7ed as libc::c_uint as BN_ULONG,
        (0xf44c42e9 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa637ed6b as libc::c_uint as BN_ULONG,
        (0xe485b576 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x625e7ec6 as libc::c_int as BN_ULONG,
        (0x4fe1356d as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x6d51c245 as libc::c_int as BN_ULONG,
        (0x302b0a6d as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xf25f1437 as libc::c_uint as BN_ULONG,
        (0xef9519b3 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xcd3a431b as libc::c_uint as BN_ULONG,
        (0x514a0879 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x8e3404dd as libc::c_uint as BN_ULONG,
        (0x20bbea6 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x3b139b22 as libc::c_int as BN_ULONG,
        (0x29024e08 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x8a67cc74 as libc::c_uint as BN_ULONG,
        (0xc4c6628b as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x80dc1cd1 as libc::c_uint as BN_ULONG,
        (0xc90fdaa2 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x2168c234 as libc::c_int as BN_ULONG,
        (0xffffffff as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xffffffff as libc::c_uint as BN_ULONG,
    ];
    return get_params(
        ret,
        kWords.as_ptr(),
        (::core::mem::size_of::<[BN_ULONG; 48]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_get_rfc3526_prime_4096(mut ret: *mut BIGNUM) -> *mut BIGNUM {
    static mut kWords: [BN_ULONG; 64] = [
        (0xffffffff as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xffffffff as libc::c_uint as BN_ULONG,
        (0x4df435c9 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x34063199 as libc::c_int as BN_ULONG,
        (0x86ffb7dc as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x90a6c08f as libc::c_uint as BN_ULONG,
        (0x93b4ea98 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x8d8fddc1 as libc::c_uint as BN_ULONG,
        (0xd0069127 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xd5b05aa9 as libc::c_uint as BN_ULONG,
        (0xb81bdd76 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x2170481c as libc::c_int as BN_ULONG,
        (0x1f612970 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xcee2d7af as libc::c_uint as BN_ULONG,
        (0x233ba186 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x515be7ed as libc::c_int as BN_ULONG,
        (0x99b2964f as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa090c3a2 as libc::c_uint as BN_ULONG,
        (0x287c5947 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x4e6bc05d as libc::c_int as BN_ULONG,
        (0x2e8efc14 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x1fbecaa6 as libc::c_int as BN_ULONG,
        (0xdbbbc2db as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x4de8ef9 as libc::c_int as BN_ULONG,
        (0x2583e9ca as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x2ad44ce8 as libc::c_int as BN_ULONG,
        (0x1a946834 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xb6150bda as libc::c_uint as BN_ULONG,
        (0x99c32718 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x6af4e23c as libc::c_int as BN_ULONG,
        (0x88719a10 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xbdba5b26 as libc::c_uint as BN_ULONG,
        (0x1a723c12 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xa787e6d7 as libc::c_uint as BN_ULONG,
        (0x4b82d120 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xa9210801 as libc::c_uint as BN_ULONG,
        (0x43db5bfc as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xe0fd108e as libc::c_uint as BN_ULONG,
        (0x8e24fa0 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x74e5ab31 as libc::c_int as BN_ULONG,
        (0x770988c0 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xbad946e2 as libc::c_uint as BN_ULONG,
        (0xbbe11757 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7a615d6c as libc::c_int as BN_ULONG,
        (0x521f2b18 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x177b200c as libc::c_int as BN_ULONG,
        (0xd8760273 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x3ec86a64 as libc::c_int as BN_ULONG,
        (0xf12ffa06 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xd98a0864 as libc::c_uint as BN_ULONG,
        (0xcee3d226 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x1ad2ee6b as libc::c_int as BN_ULONG,
        (0x1e8c94e0 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x4a25619d as libc::c_int as BN_ULONG,
        (0xabf5ae8c as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xdb0933d7 as libc::c_uint as BN_ULONG,
        (0xb3970f85 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa6e1e4c7 as libc::c_uint as BN_ULONG,
        (0x8aea7157 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x5d060c7d as libc::c_int as BN_ULONG,
        (0xecfb8504 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x58dbef0a as libc::c_int as BN_ULONG,
        (0xa85521ab as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xdf1cba64 as libc::c_uint as BN_ULONG,
        (0xad33170d as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x4507a33 as libc::c_int as BN_ULONG,
        (0x15728e5a as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x8aaac42d as libc::c_uint as BN_ULONG,
        (0x15d22618 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x98fa0510 as libc::c_uint as BN_ULONG,
        (0x3995497c as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xea956ae5 as libc::c_uint as BN_ULONG,
        (0xde2bcbf6 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x95581718 as libc::c_uint as BN_ULONG,
        (0xb5c55df0 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x6f4c52c9 as libc::c_int as BN_ULONG,
        (0x9b2783a2 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xec07a28f as libc::c_uint as BN_ULONG,
        (0xe39e772c as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x180e8603 as libc::c_int as BN_ULONG,
        (0x32905e46 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x2e36ce3b as libc::c_int as BN_ULONG,
        (0xf1746c08 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xca18217c as libc::c_uint as BN_ULONG,
        (0x670c354e as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x4abc9804 as libc::c_int as BN_ULONG,
        (0x9ed52907 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7096966d as libc::c_int as BN_ULONG,
        (0x1c62f356 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x208552bb as libc::c_int as BN_ULONG,
        (0x83655d23 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xdca3ad96 as libc::c_uint as BN_ULONG,
        (0x69163fa8 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xfd24cf5f as libc::c_uint as BN_ULONG,
        (0x98da4836 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x1c55d39a as libc::c_int as BN_ULONG,
        (0xc2007cb8 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa163bf05 as libc::c_uint as BN_ULONG,
        (0x49286651 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xece45b3d as libc::c_uint as BN_ULONG,
        (0xae9f2411 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7c4b1fe6 as libc::c_int as BN_ULONG,
        (0xee386bfb as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x5a899fa5 as libc::c_int as BN_ULONG,
        (0xbff5cb6 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xf406b7ed as libc::c_uint as BN_ULONG,
        (0xf44c42e9 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa637ed6b as libc::c_uint as BN_ULONG,
        (0xe485b576 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x625e7ec6 as libc::c_int as BN_ULONG,
        (0x4fe1356d as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x6d51c245 as libc::c_int as BN_ULONG,
        (0x302b0a6d as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xf25f1437 as libc::c_uint as BN_ULONG,
        (0xef9519b3 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xcd3a431b as libc::c_uint as BN_ULONG,
        (0x514a0879 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x8e3404dd as libc::c_uint as BN_ULONG,
        (0x20bbea6 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x3b139b22 as libc::c_int as BN_ULONG,
        (0x29024e08 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x8a67cc74 as libc::c_uint as BN_ULONG,
        (0xc4c6628b as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x80dc1cd1 as libc::c_uint as BN_ULONG,
        (0xc90fdaa2 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x2168c234 as libc::c_int as BN_ULONG,
        (0xffffffff as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xffffffff as libc::c_uint as BN_ULONG,
    ];
    return get_params(
        ret,
        kWords.as_ptr(),
        (::core::mem::size_of::<[BN_ULONG; 64]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_get_rfc3526_prime_6144(mut ret: *mut BIGNUM) -> *mut BIGNUM {
    static mut kWords: [BN_ULONG; 96] = [
        (0xffffffff as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xffffffff as libc::c_uint as BN_ULONG,
        (0xe694f91e as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x6dcc4024 as libc::c_int as BN_ULONG,
        (0x12bf2d5b as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xb7474d6 as libc::c_int as BN_ULONG,
        (0x43e8f66 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x3f4860ee as libc::c_int as BN_ULONG,
        (0x387fe8d7 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x6e3c0468 as libc::c_int as BN_ULONG,
        (0xda56c9ec as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x2ef29632 as libc::c_int as BN_ULONG,
        (0xeb19ccb1 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa313d55c as libc::c_uint as BN_ULONG,
        (0xf550aa3d as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x8a1fbff0 as libc::c_uint as BN_ULONG,
        (0x6a1d58b as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xb7c5da76 as libc::c_uint as BN_ULONG,
        (0xa79715ee as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xf29be328 as libc::c_uint as BN_ULONG,
        (0x14cc5ed2 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xf8037e0 as libc::c_int as BN_ULONG,
        (0xcc8f6d7e as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xbf48e1d8 as libc::c_uint as BN_ULONG,
        (0x4bd407b2 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x2b4154aa as libc::c_int as BN_ULONG,
        (0xf1d45b7 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xff585ac5 as libc::c_uint as BN_ULONG,
        (0x23a97a7e as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x36cc88be as libc::c_int as BN_ULONG,
        (0x59e7c97f as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xbec7e8f3 as libc::c_uint as BN_ULONG,
        (0xb5a84031 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x900b1c9e as libc::c_uint as BN_ULONG,
        (0xd55e702f as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x46980c82 as libc::c_int as BN_ULONG,
        (0xf482d7ce as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x6e74fef6 as libc::c_int as BN_ULONG,
        (0xf032ea15 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xd1721d03 as libc::c_uint as BN_ULONG,
        (0x5983ca01 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xc64b92ec as libc::c_uint as BN_ULONG,
        (0x6fb8f401 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x378cd2bf as libc::c_int as BN_ULONG,
        (0x33205151 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x2bd7af42 as libc::c_int as BN_ULONG,
        (0xdb7f1447 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xe6cc254b as libc::c_uint as BN_ULONG,
        (0x44ce6cba as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xced4bb1b as libc::c_uint as BN_ULONG,
        (0xda3edbeb as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xcf9b14ed as libc::c_uint as BN_ULONG,
        (0x179727b0 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x865a8918 as libc::c_uint as BN_ULONG,
        (0xb06a53ed as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x9027d831 as libc::c_uint as BN_ULONG,
        (0xe5db382f as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x413001ae as libc::c_int as BN_ULONG,
        (0xf8ff9406 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xad9e530e as libc::c_uint as BN_ULONG,
        (0xc9751e76 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x3dba37bd as libc::c_int as BN_ULONG,
        (0xc1d4dcb2 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x602646de as libc::c_int as BN_ULONG,
        (0x36c3fab4 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xd27c7026 as libc::c_uint as BN_ULONG,
        (0x4df435c9 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x34028492 as libc::c_int as BN_ULONG,
        (0x86ffb7dc as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x90a6c08f as libc::c_uint as BN_ULONG,
        (0x93b4ea98 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x8d8fddc1 as libc::c_uint as BN_ULONG,
        (0xd0069127 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xd5b05aa9 as libc::c_uint as BN_ULONG,
        (0xb81bdd76 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x2170481c as libc::c_int as BN_ULONG,
        (0x1f612970 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xcee2d7af as libc::c_uint as BN_ULONG,
        (0x233ba186 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x515be7ed as libc::c_int as BN_ULONG,
        (0x99b2964f as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa090c3a2 as libc::c_uint as BN_ULONG,
        (0x287c5947 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x4e6bc05d as libc::c_int as BN_ULONG,
        (0x2e8efc14 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x1fbecaa6 as libc::c_int as BN_ULONG,
        (0xdbbbc2db as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x4de8ef9 as libc::c_int as BN_ULONG,
        (0x2583e9ca as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x2ad44ce8 as libc::c_int as BN_ULONG,
        (0x1a946834 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xb6150bda as libc::c_uint as BN_ULONG,
        (0x99c32718 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x6af4e23c as libc::c_int as BN_ULONG,
        (0x88719a10 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xbdba5b26 as libc::c_uint as BN_ULONG,
        (0x1a723c12 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xa787e6d7 as libc::c_uint as BN_ULONG,
        (0x4b82d120 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xa9210801 as libc::c_uint as BN_ULONG,
        (0x43db5bfc as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xe0fd108e as libc::c_uint as BN_ULONG,
        (0x8e24fa0 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x74e5ab31 as libc::c_int as BN_ULONG,
        (0x770988c0 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xbad946e2 as libc::c_uint as BN_ULONG,
        (0xbbe11757 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7a615d6c as libc::c_int as BN_ULONG,
        (0x521f2b18 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x177b200c as libc::c_int as BN_ULONG,
        (0xd8760273 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x3ec86a64 as libc::c_int as BN_ULONG,
        (0xf12ffa06 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xd98a0864 as libc::c_uint as BN_ULONG,
        (0xcee3d226 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x1ad2ee6b as libc::c_int as BN_ULONG,
        (0x1e8c94e0 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x4a25619d as libc::c_int as BN_ULONG,
        (0xabf5ae8c as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xdb0933d7 as libc::c_uint as BN_ULONG,
        (0xb3970f85 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa6e1e4c7 as libc::c_uint as BN_ULONG,
        (0x8aea7157 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x5d060c7d as libc::c_int as BN_ULONG,
        (0xecfb8504 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x58dbef0a as libc::c_int as BN_ULONG,
        (0xa85521ab as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xdf1cba64 as libc::c_uint as BN_ULONG,
        (0xad33170d as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x4507a33 as libc::c_int as BN_ULONG,
        (0x15728e5a as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x8aaac42d as libc::c_uint as BN_ULONG,
        (0x15d22618 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x98fa0510 as libc::c_uint as BN_ULONG,
        (0x3995497c as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xea956ae5 as libc::c_uint as BN_ULONG,
        (0xde2bcbf6 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x95581718 as libc::c_uint as BN_ULONG,
        (0xb5c55df0 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x6f4c52c9 as libc::c_int as BN_ULONG,
        (0x9b2783a2 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xec07a28f as libc::c_uint as BN_ULONG,
        (0xe39e772c as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x180e8603 as libc::c_int as BN_ULONG,
        (0x32905e46 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x2e36ce3b as libc::c_int as BN_ULONG,
        (0xf1746c08 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xca18217c as libc::c_uint as BN_ULONG,
        (0x670c354e as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x4abc9804 as libc::c_int as BN_ULONG,
        (0x9ed52907 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7096966d as libc::c_int as BN_ULONG,
        (0x1c62f356 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x208552bb as libc::c_int as BN_ULONG,
        (0x83655d23 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xdca3ad96 as libc::c_uint as BN_ULONG,
        (0x69163fa8 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xfd24cf5f as libc::c_uint as BN_ULONG,
        (0x98da4836 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x1c55d39a as libc::c_int as BN_ULONG,
        (0xc2007cb8 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa163bf05 as libc::c_uint as BN_ULONG,
        (0x49286651 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xece45b3d as libc::c_uint as BN_ULONG,
        (0xae9f2411 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7c4b1fe6 as libc::c_int as BN_ULONG,
        (0xee386bfb as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x5a899fa5 as libc::c_int as BN_ULONG,
        (0xbff5cb6 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xf406b7ed as libc::c_uint as BN_ULONG,
        (0xf44c42e9 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa637ed6b as libc::c_uint as BN_ULONG,
        (0xe485b576 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x625e7ec6 as libc::c_int as BN_ULONG,
        (0x4fe1356d as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x6d51c245 as libc::c_int as BN_ULONG,
        (0x302b0a6d as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xf25f1437 as libc::c_uint as BN_ULONG,
        (0xef9519b3 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xcd3a431b as libc::c_uint as BN_ULONG,
        (0x514a0879 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x8e3404dd as libc::c_uint as BN_ULONG,
        (0x20bbea6 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x3b139b22 as libc::c_int as BN_ULONG,
        (0x29024e08 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x8a67cc74 as libc::c_uint as BN_ULONG,
        (0xc4c6628b as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x80dc1cd1 as libc::c_uint as BN_ULONG,
        (0xc90fdaa2 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x2168c234 as libc::c_int as BN_ULONG,
        (0xffffffff as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xffffffff as libc::c_uint as BN_ULONG,
    ];
    return get_params(
        ret,
        kWords.as_ptr(),
        (::core::mem::size_of::<[BN_ULONG; 96]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_get_rfc3526_prime_8192(mut ret: *mut BIGNUM) -> *mut BIGNUM {
    static mut kWords: [BN_ULONG; 128] = [
        (0xffffffff as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xffffffff as libc::c_uint as BN_ULONG,
        (0x60c980dd as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x98edd3df as libc::c_uint as BN_ULONG,
        (0xc81f56e8 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x80b96e71 as libc::c_uint as BN_ULONG,
        (0x9e3050e2 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x765694df as libc::c_int as BN_ULONG,
        (0x9558e447 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x5677e9aa as libc::c_int as BN_ULONG,
        (0xc9190da6 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xfc026e47 as libc::c_uint as BN_ULONG,
        (0x889a002e as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xd5ee382b as libc::c_uint as BN_ULONG,
        (0x4009438b as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x481c6cd7 as libc::c_int as BN_ULONG,
        (0x359046f4 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xeb879f92 as libc::c_uint as BN_ULONG,
        (0xfaf36bc3 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x1ecfa268 as libc::c_int as BN_ULONG,
        (0xb1d510bd as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7ee74d73 as libc::c_int as BN_ULONG,
        (0xf9ab4819 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x5ded7ea1 as libc::c_int as BN_ULONG,
        (0x64f31cc5 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x846851d as libc::c_int as BN_ULONG,
        (0x4597e899 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xa0255dc1 as libc::c_uint as BN_ULONG,
        (0xdf310ee0 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x74ab6a36 as libc::c_int as BN_ULONG,
        (0x6d2a13f8 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x3f44f82d as libc::c_int as BN_ULONG,
        (0x62b3cf5 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xb3a278a6 as libc::c_uint as BN_ULONG,
        (0x79683303 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xed5bdd3a as libc::c_uint as BN_ULONG,
        (0xfa9d4b7f as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa2c087e8 as libc::c_uint as BN_ULONG,
        (0x4bcbc886 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x2f8385dd as libc::c_int as BN_ULONG,
        (0x3473fc64 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x6cea306b as libc::c_int as BN_ULONG,
        (0x13eb57a8 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x1a23f0c7 as libc::c_int as BN_ULONG,
        (0x22222e04 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xa4037c07 as libc::c_uint as BN_ULONG,
        (0xe3fdb8be as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xfc848ad9 as libc::c_uint as BN_ULONG,
        (0x238f16cb as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xe39d652d as libc::c_uint as BN_ULONG,
        (0x3423b474 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x2bf1c978 as libc::c_int as BN_ULONG,
        (0x3aab639c as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x5ae4f568 as libc::c_int as BN_ULONG,
        (0x2576f693 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x6ba42466 as libc::c_int as BN_ULONG,
        (0x741fa7bf as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x8afc47ed as libc::c_uint as BN_ULONG,
        (0x3bc832b6 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x8d9dd300 as libc::c_uint as BN_ULONG,
        (0xd8bec4d0 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x73b931ba as libc::c_int as BN_ULONG,
        (0x38777cb6 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xa932df8c as libc::c_uint as BN_ULONG,
        (0x74a3926f as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x12fee5e4 as libc::c_int as BN_ULONG,
        (0xe694f91e as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x6dbe1159 as libc::c_int as BN_ULONG,
        (0x12bf2d5b as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xb7474d6 as libc::c_int as BN_ULONG,
        (0x43e8f66 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x3f4860ee as libc::c_int as BN_ULONG,
        (0x387fe8d7 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x6e3c0468 as libc::c_int as BN_ULONG,
        (0xda56c9ec as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x2ef29632 as libc::c_int as BN_ULONG,
        (0xeb19ccb1 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa313d55c as libc::c_uint as BN_ULONG,
        (0xf550aa3d as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x8a1fbff0 as libc::c_uint as BN_ULONG,
        (0x6a1d58b as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xb7c5da76 as libc::c_uint as BN_ULONG,
        (0xa79715ee as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xf29be328 as libc::c_uint as BN_ULONG,
        (0x14cc5ed2 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xf8037e0 as libc::c_int as BN_ULONG,
        (0xcc8f6d7e as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xbf48e1d8 as libc::c_uint as BN_ULONG,
        (0x4bd407b2 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x2b4154aa as libc::c_int as BN_ULONG,
        (0xf1d45b7 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xff585ac5 as libc::c_uint as BN_ULONG,
        (0x23a97a7e as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x36cc88be as libc::c_int as BN_ULONG,
        (0x59e7c97f as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xbec7e8f3 as libc::c_uint as BN_ULONG,
        (0xb5a84031 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x900b1c9e as libc::c_uint as BN_ULONG,
        (0xd55e702f as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x46980c82 as libc::c_int as BN_ULONG,
        (0xf482d7ce as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x6e74fef6 as libc::c_int as BN_ULONG,
        (0xf032ea15 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xd1721d03 as libc::c_uint as BN_ULONG,
        (0x5983ca01 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xc64b92ec as libc::c_uint as BN_ULONG,
        (0x6fb8f401 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x378cd2bf as libc::c_int as BN_ULONG,
        (0x33205151 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x2bd7af42 as libc::c_int as BN_ULONG,
        (0xdb7f1447 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xe6cc254b as libc::c_uint as BN_ULONG,
        (0x44ce6cba as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xced4bb1b as libc::c_uint as BN_ULONG,
        (0xda3edbeb as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xcf9b14ed as libc::c_uint as BN_ULONG,
        (0x179727b0 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x865a8918 as libc::c_uint as BN_ULONG,
        (0xb06a53ed as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x9027d831 as libc::c_uint as BN_ULONG,
        (0xe5db382f as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x413001ae as libc::c_int as BN_ULONG,
        (0xf8ff9406 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xad9e530e as libc::c_uint as BN_ULONG,
        (0xc9751e76 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x3dba37bd as libc::c_int as BN_ULONG,
        (0xc1d4dcb2 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x602646de as libc::c_int as BN_ULONG,
        (0x36c3fab4 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xd27c7026 as libc::c_uint as BN_ULONG,
        (0x4df435c9 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x34028492 as libc::c_int as BN_ULONG,
        (0x86ffb7dc as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x90a6c08f as libc::c_uint as BN_ULONG,
        (0x93b4ea98 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x8d8fddc1 as libc::c_uint as BN_ULONG,
        (0xd0069127 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xd5b05aa9 as libc::c_uint as BN_ULONG,
        (0xb81bdd76 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x2170481c as libc::c_int as BN_ULONG,
        (0x1f612970 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xcee2d7af as libc::c_uint as BN_ULONG,
        (0x233ba186 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x515be7ed as libc::c_int as BN_ULONG,
        (0x99b2964f as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa090c3a2 as libc::c_uint as BN_ULONG,
        (0x287c5947 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x4e6bc05d as libc::c_int as BN_ULONG,
        (0x2e8efc14 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x1fbecaa6 as libc::c_int as BN_ULONG,
        (0xdbbbc2db as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x4de8ef9 as libc::c_int as BN_ULONG,
        (0x2583e9ca as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x2ad44ce8 as libc::c_int as BN_ULONG,
        (0x1a946834 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xb6150bda as libc::c_uint as BN_ULONG,
        (0x99c32718 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x6af4e23c as libc::c_int as BN_ULONG,
        (0x88719a10 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xbdba5b26 as libc::c_uint as BN_ULONG,
        (0x1a723c12 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xa787e6d7 as libc::c_uint as BN_ULONG,
        (0x4b82d120 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xa9210801 as libc::c_uint as BN_ULONG,
        (0x43db5bfc as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xe0fd108e as libc::c_uint as BN_ULONG,
        (0x8e24fa0 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x74e5ab31 as libc::c_int as BN_ULONG,
        (0x770988c0 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xbad946e2 as libc::c_uint as BN_ULONG,
        (0xbbe11757 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7a615d6c as libc::c_int as BN_ULONG,
        (0x521f2b18 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x177b200c as libc::c_int as BN_ULONG,
        (0xd8760273 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x3ec86a64 as libc::c_int as BN_ULONG,
        (0xf12ffa06 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xd98a0864 as libc::c_uint as BN_ULONG,
        (0xcee3d226 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x1ad2ee6b as libc::c_int as BN_ULONG,
        (0x1e8c94e0 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x4a25619d as libc::c_int as BN_ULONG,
        (0xabf5ae8c as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xdb0933d7 as libc::c_uint as BN_ULONG,
        (0xb3970f85 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa6e1e4c7 as libc::c_uint as BN_ULONG,
        (0x8aea7157 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x5d060c7d as libc::c_int as BN_ULONG,
        (0xecfb8504 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x58dbef0a as libc::c_int as BN_ULONG,
        (0xa85521ab as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xdf1cba64 as libc::c_uint as BN_ULONG,
        (0xad33170d as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x4507a33 as libc::c_int as BN_ULONG,
        (0x15728e5a as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x8aaac42d as libc::c_uint as BN_ULONG,
        (0x15d22618 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x98fa0510 as libc::c_uint as BN_ULONG,
        (0x3995497c as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xea956ae5 as libc::c_uint as BN_ULONG,
        (0xde2bcbf6 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x95581718 as libc::c_uint as BN_ULONG,
        (0xb5c55df0 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x6f4c52c9 as libc::c_int as BN_ULONG,
        (0x9b2783a2 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xec07a28f as libc::c_uint as BN_ULONG,
        (0xe39e772c as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x180e8603 as libc::c_int as BN_ULONG,
        (0x32905e46 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x2e36ce3b as libc::c_int as BN_ULONG,
        (0xf1746c08 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xca18217c as libc::c_uint as BN_ULONG,
        (0x670c354e as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x4abc9804 as libc::c_int as BN_ULONG,
        (0x9ed52907 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7096966d as libc::c_int as BN_ULONG,
        (0x1c62f356 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x208552bb as libc::c_int as BN_ULONG,
        (0x83655d23 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xdca3ad96 as libc::c_uint as BN_ULONG,
        (0x69163fa8 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xfd24cf5f as libc::c_uint as BN_ULONG,
        (0x98da4836 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x1c55d39a as libc::c_int as BN_ULONG,
        (0xc2007cb8 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa163bf05 as libc::c_uint as BN_ULONG,
        (0x49286651 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xece45b3d as libc::c_uint as BN_ULONG,
        (0xae9f2411 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7c4b1fe6 as libc::c_int as BN_ULONG,
        (0xee386bfb as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x5a899fa5 as libc::c_int as BN_ULONG,
        (0xbff5cb6 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xf406b7ed as libc::c_uint as BN_ULONG,
        (0xf44c42e9 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa637ed6b as libc::c_uint as BN_ULONG,
        (0xe485b576 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x625e7ec6 as libc::c_int as BN_ULONG,
        (0x4fe1356d as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x6d51c245 as libc::c_int as BN_ULONG,
        (0x302b0a6d as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xf25f1437 as libc::c_uint as BN_ULONG,
        (0xef9519b3 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xcd3a431b as libc::c_uint as BN_ULONG,
        (0x514a0879 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x8e3404dd as libc::c_uint as BN_ULONG,
        (0x20bbea6 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x3b139b22 as libc::c_int as BN_ULONG,
        (0x29024e08 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x8a67cc74 as libc::c_uint as BN_ULONG,
        (0xc4c6628b as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x80dc1cd1 as libc::c_uint as BN_ULONG,
        (0xc90fdaa2 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x2168c234 as libc::c_int as BN_ULONG,
        (0xffffffff as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xffffffff as libc::c_uint as BN_ULONG,
    ];
    return get_params(
        ret,
        kWords.as_ptr(),
        (::core::mem::size_of::<[BN_ULONG; 128]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<BN_ULONG>() as libc::c_ulong),
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DH_generate_parameters_ex(
    mut dh: *mut DH,
    mut prime_bits: libc::c_int,
    mut generator: libc::c_int,
    mut cb: *mut BN_GENCB,
) -> libc::c_int {
    let mut current_block: u64;
    if prime_bits <= 0 as libc::c_int || prime_bits > 10000 as libc::c_int {
        ERR_put_error(
            5 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dh_extra/params.c\0" as *const u8
                as *const libc::c_char,
            341 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut t1: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut t2: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut g: libc::c_int = 0;
    let mut ok: libc::c_int = 0 as libc::c_int;
    let mut ctx: *mut BN_CTX = 0 as *mut BN_CTX;
    ctx = BN_CTX_new();
    if !ctx.is_null() {
        BN_CTX_start(ctx);
        t1 = BN_CTX_get(ctx);
        t2 = BN_CTX_get(ctx);
        if !(t1.is_null() || t2.is_null()) {
            if ((*dh).p).is_null() {
                (*dh).p = BN_new();
                if ((*dh).p).is_null() {
                    current_block = 856496018741234393;
                } else {
                    current_block = 5399440093318478209;
                }
            } else {
                current_block = 5399440093318478209;
            }
            match current_block {
                856496018741234393 => {}
                _ => {
                    if ((*dh).g).is_null() {
                        (*dh).g = BN_new();
                        if ((*dh).g).is_null() {
                            current_block = 856496018741234393;
                        } else {
                            current_block = 17407779659766490442;
                        }
                    } else {
                        current_block = 17407779659766490442;
                    }
                    match current_block {
                        856496018741234393 => {}
                        _ => {
                            if generator <= 1 as libc::c_int {
                                ERR_put_error(
                                    5 as libc::c_int,
                                    0 as libc::c_int,
                                    100 as libc::c_int,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/dh_extra/params.c\0"
                                        as *const u8 as *const libc::c_char,
                                    375 as libc::c_int as libc::c_uint,
                                );
                            } else {
                                if generator == 2 as libc::c_int {
                                    if BN_set_word(t1, 24 as libc::c_int as BN_ULONG) == 0 {
                                        current_block = 856496018741234393;
                                    } else if BN_set_word(t2, 11 as libc::c_int as BN_ULONG)
                                        == 0
                                    {
                                        current_block = 856496018741234393;
                                    } else {
                                        g = 2 as libc::c_int;
                                        current_block = 15897653523371991391;
                                    }
                                } else if generator == 5 as libc::c_int {
                                    if BN_set_word(t1, 10 as libc::c_int as BN_ULONG) == 0 {
                                        current_block = 856496018741234393;
                                    } else if BN_set_word(t2, 3 as libc::c_int as BN_ULONG) == 0
                                    {
                                        current_block = 856496018741234393;
                                    } else {
                                        g = 5 as libc::c_int;
                                        current_block = 15897653523371991391;
                                    }
                                } else if BN_set_word(t1, 2 as libc::c_int as BN_ULONG) == 0
                                {
                                    current_block = 856496018741234393;
                                } else if BN_set_word(t2, 1 as libc::c_int as BN_ULONG) == 0
                                {
                                    current_block = 856496018741234393;
                                } else {
                                    g = generator;
                                    current_block = 15897653523371991391;
                                }
                                match current_block {
                                    856496018741234393 => {}
                                    _ => {
                                        if !(BN_generate_prime_ex(
                                            (*dh).p,
                                            prime_bits,
                                            1 as libc::c_int,
                                            t1,
                                            t2,
                                            cb,
                                        ) == 0)
                                        {
                                            if !(BN_GENCB_call(cb, 3 as libc::c_int, 0 as libc::c_int)
                                                == 0)
                                            {
                                                if !(BN_set_word((*dh).g, g as BN_ULONG) == 0) {
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
        }
    }
    if ok == 0 {
        ERR_put_error(
            5 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/dh_extra/params.c\0" as *const u8
                as *const libc::c_char,
            423 as libc::c_int as libc::c_uint,
        );
    }
    if !ctx.is_null() {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ok;
}
unsafe extern "C" fn int_dh_bn_cpy(
    mut dst: *mut *mut BIGNUM,
    mut src: *const BIGNUM,
) -> libc::c_int {
    let mut a: *mut BIGNUM = 0 as *mut BIGNUM;
    if !src.is_null() {
        a = BN_dup(src);
        if a.is_null() {
            return 0 as libc::c_int;
        }
    }
    BN_free(*dst);
    *dst = a;
    return 1 as libc::c_int;
}
unsafe extern "C" fn int_dh_param_copy(
    mut to: *mut DH,
    mut from: *const DH,
    mut is_x942: libc::c_int,
) -> libc::c_int {
    if is_x942 == -(1 as libc::c_int) {
        is_x942 = !((*from).q).is_null() as libc::c_int;
    }
    if int_dh_bn_cpy(&mut (*to).p, (*from).p) == 0
        || int_dh_bn_cpy(&mut (*to).g, (*from).g) == 0
    {
        return 0 as libc::c_int;
    }
    if is_x942 == 0 {
        return 1 as libc::c_int;
    }
    if int_dh_bn_cpy(&mut (*to).q, (*from).q) == 0 {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DHparams_dup(mut dh: *const DH) -> *mut DH {
    let mut ret: *mut DH = DH_new();
    if ret.is_null() {
        return 0 as *mut DH;
    }
    if int_dh_param_copy(ret, dh, -(1 as libc::c_int)) == 0 {
        DH_free(ret);
        return 0 as *mut DH;
    }
    return ret;
}
static mut dh2048_256: standard_parameters = standard_parameters {
    p: bignum_st {
        d: 0 as *const BN_ULONG as *mut BN_ULONG,
        width: 0,
        dmax: 0,
        neg: 0,
        flags: 0,
    },
    q: bignum_st {
        d: 0 as *const BN_ULONG as *mut BN_ULONG,
        width: 0,
        dmax: 0,
        neg: 0,
        flags: 0,
    },
    g: bignum_st {
        d: 0 as *const BN_ULONG as *mut BN_ULONG,
        width: 0,
        dmax: 0,
        neg: 0,
        flags: 0,
    },
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DH_get_2048_256() -> *mut DH {
    static mut dh2048_256_p: [BN_ULONG; 32] = [
        (0xdb094ae9 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x1e1a1597 as libc::c_int as BN_ULONG,
        (0x693877fa as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xd7ef09ca as libc::c_uint as BN_ULONG,
        (0x6116d227 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x6e11715f as libc::c_int as BN_ULONG,
        (0xa4b54330 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xc198af12 as libc::c_uint as BN_ULONG,
        (0x75f26375 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xd7014103 as libc::c_uint as BN_ULONG,
        (0xc3a3960a as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x54e710c3 as libc::c_int as BN_ULONG,
        (0xded4010a as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xbd0be621 as libc::c_uint as BN_ULONG,
        (0xc0b857f6 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x89962856 as libc::c_uint as BN_ULONG,
        (0xb3ca3f79 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x71506026 as libc::c_int as BN_ULONG,
        (0x1ccacb83 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xe6b486f6 as libc::c_uint as BN_ULONG,
        (0x67e144e5 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x14056425 as libc::c_int as BN_ULONG,
        (0xf6a167b5 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa41825d9 as libc::c_uint as BN_ULONG,
        (0x3ad83477 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x96524d8e as libc::c_uint as BN_ULONG,
        (0xf13c6d9a as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x51bfa4ab as libc::c_int as BN_ULONG,
        (0x2d525267 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x35488a0e as libc::c_int as BN_ULONG,
        (0xb63acae1 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xcaa6b790 as libc::c_uint as BN_ULONG,
        (0x4fdb70c5 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x81b23f76 as libc::c_uint as BN_ULONG,
        (0xbc39a0bf as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x12307f5c as libc::c_int as BN_ULONG,
        (0xb941f54e as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xb1e59bb8 as libc::c_uint as BN_ULONG,
        (0x6c5bfc11 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xd45f9088 as libc::c_uint as BN_ULONG,
        (0x22e0b1ef as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x4275bf7b as libc::c_int as BN_ULONG,
        (0x91f9e672 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x5b4758c0 as libc::c_int as BN_ULONG,
        (0x5a8a9d30 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x6bcf67ed as libc::c_int as BN_ULONG,
        (0x209e0c64 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x97517abd as libc::c_uint as BN_ULONG,
        (0x3bf4296d as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x830e9a7c as libc::c_uint as BN_ULONG,
        (0x16c3d911 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x34096faa as libc::c_int as BN_ULONG,
        (0xfaf7df45 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x61b2aa30 as libc::c_int as BN_ULONG,
        (0xe00df8f1 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xd61957d4 as libc::c_uint as BN_ULONG,
        (0x5d2ceed4 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x435e3b00 as libc::c_int as BN_ULONG,
        (0x8ceef608 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x660dd0f2 as libc::c_int as BN_ULONG,
        (0xffbbd19c as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x65195999 as libc::c_int as BN_ULONG,
        (0x87a8e61d as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xb4b6663c as libc::c_uint as BN_ULONG,
    ];
    static mut dh2048_256_g: [BN_ULONG; 32] = [
        (0x664b4c0f as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x6cc41659 as libc::c_int as BN_ULONG,
        (0x5e2327cf as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xef98c582 as libc::c_uint as BN_ULONG,
        (0xd647d148 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xd4795451 as libc::c_uint as BN_ULONG,
        (0x2f630784 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x90f00ef8 as libc::c_uint as BN_ULONG,
        (0x184b523d as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x1db246c3 as libc::c_int as BN_ULONG,
        (0xc7891428 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xcdc67eb6 as libc::c_uint as BN_ULONG,
        (0x7fd02837 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xdf92b52 as libc::c_int as BN_ULONG,
        (0xb3353bbb as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x64e0ec37 as libc::c_int as BN_ULONG,
        (0xecd06e15 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x57cd0915 as libc::c_int as BN_ULONG,
        (0xb7d2bbd2 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xdf016199 as libc::c_uint as BN_ULONG,
        (0xc8484b1e as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x52588b9 as libc::c_int as BN_ULONG,
        (0xdb2a3b73 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x13d3fe14 as libc::c_int as BN_ULONG,
        (0xd052b985 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xd182ea0a as libc::c_uint as BN_ULONG,
        (0xa4bd1bff as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xe83b9c80 as libc::c_uint as BN_ULONG,
        (0xdfc967c1 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xfb3f2e55 as libc::c_uint as BN_ULONG,
        (0xb5045af2 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x767164e1 as libc::c_int as BN_ULONG,
        (0x1d14348f as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x6f2f9193 as libc::c_int as BN_ULONG,
        (0x64e67982 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x428ebc83 as libc::c_int as BN_ULONG,
        (0x8ac376d2 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x82d6ed38 as libc::c_uint as BN_ULONG,
        (0x777de62a as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xaab8a862 as libc::c_uint as BN_ULONG,
        (0xddf463e5 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xe9ec144b as libc::c_uint as BN_ULONG,
        (0x196f931 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0xc77a57f2 as libc::c_uint as BN_ULONG,
        (0xa55ae313 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x41000a65 as libc::c_int as BN_ULONG,
        (0x901228f8 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xc28cbb18 as libc::c_uint as BN_ULONG,
        (0xbc3773bf as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x7e8c6f62 as libc::c_int as BN_ULONG,
        (0xbe3a6c1b as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xc6b47b1 as libc::c_int as BN_ULONG,
        (0xff4fed4a as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xac0bb555 as libc::c_uint as BN_ULONG,
        (0x10dbc150 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x77be463f as libc::c_int as BN_ULONG,
        (0x7f4793a as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x1a0ba125 as libc::c_int as BN_ULONG,
        (0x4ca7b18f as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x21ef2054 as libc::c_int as BN_ULONG,
        (0x2e775066 as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x60edbd48 as libc::c_int as BN_ULONG,
        (0x3fb32c9b as libc::c_int as BN_ULONG) << 32 as libc::c_int
            | 0x73134d0b as libc::c_int as BN_ULONG,
    ];
    static mut dh2048_256_q: [BN_ULONG; 4] = [
        (0xa308b0fe as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x64f5fbd3 as libc::c_int as BN_ULONG,
        (0x99b1a47d as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x1eb3750b as libc::c_int as BN_ULONG,
        (0xb4479976 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0x40129da2 as libc::c_int as BN_ULONG,
        (0x8cf83642 as libc::c_uint as BN_ULONG) << 32 as libc::c_int
            | 0xa709a097 as libc::c_uint as BN_ULONG,
    ];
    let mut dh: *mut DH = DH_new();
    if dh.is_null() {
        return 0 as *mut DH;
    }
    (*dh).p = BN_dup(&dh2048_256.p);
    (*dh).q = BN_dup(&dh2048_256.q);
    (*dh).g = BN_dup(&dh2048_256.g);
    if ((*dh).p).is_null() || ((*dh).q).is_null() || ((*dh).g).is_null() {
        DH_free(dh);
        return 0 as *mut DH;
    }
    return dh;
}
unsafe extern "C" fn run_static_initializers() {
    dh2048_256 = {
        let mut init = standard_parameters {
            p: {
                let mut init = bignum_st {
                    d: dh2048_256_p.as_ptr() as *mut BN_ULONG,
                    width: (::core::mem::size_of::<[BN_ULONG; 32]>() as libc::c_ulong)
                        .wrapping_div(
                            ::core::mem::size_of::<BN_ULONG>() as libc::c_ulong,
                        ) as libc::c_int,
                    dmax: (::core::mem::size_of::<[BN_ULONG; 32]>() as libc::c_ulong)
                        .wrapping_div(
                            ::core::mem::size_of::<BN_ULONG>() as libc::c_ulong,
                        ) as libc::c_int,
                    neg: 0 as libc::c_int,
                    flags: 0x2 as libc::c_int,
                };
                init
            },
            q: {
                let mut init = bignum_st {
                    d: dh2048_256_q.as_ptr() as *mut BN_ULONG,
                    width: (::core::mem::size_of::<[BN_ULONG; 4]>() as libc::c_ulong)
                        .wrapping_div(
                            ::core::mem::size_of::<BN_ULONG>() as libc::c_ulong,
                        ) as libc::c_int,
                    dmax: (::core::mem::size_of::<[BN_ULONG; 4]>() as libc::c_ulong)
                        .wrapping_div(
                            ::core::mem::size_of::<BN_ULONG>() as libc::c_ulong,
                        ) as libc::c_int,
                    neg: 0 as libc::c_int,
                    flags: 0x2 as libc::c_int,
                };
                init
            },
            g: {
                let mut init = bignum_st {
                    d: dh2048_256_g.as_ptr() as *mut BN_ULONG,
                    width: (::core::mem::size_of::<[BN_ULONG; 32]>() as libc::c_ulong)
                        .wrapping_div(
                            ::core::mem::size_of::<BN_ULONG>() as libc::c_ulong,
                        ) as libc::c_int,
                    dmax: (::core::mem::size_of::<[BN_ULONG; 32]>() as libc::c_ulong)
                        .wrapping_div(
                            ::core::mem::size_of::<BN_ULONG>() as libc::c_ulong,
                        ) as libc::c_int,
                    neg: 0 as libc::c_int,
                    flags: 0x2 as libc::c_int,
                };
                init
            },
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
