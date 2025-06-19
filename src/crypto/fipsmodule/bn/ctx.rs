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
    pub type stack_st_BIGNUM;
    pub type stack_st;
    fn BN_new() -> *mut BIGNUM;
    fn BN_free(bn: *mut BIGNUM);
    fn BN_zero(bn: *mut BIGNUM);
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_realloc(ptr: *mut libc::c_void, new_size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_pop_free_ex(
        sk: *mut OPENSSL_STACK,
        call_free_func: OPENSSL_sk_call_free_func,
        free_func: OPENSSL_sk_free_func,
    );
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
}
pub type size_t = libc::c_ulong;
pub type __uint64_t = libc::c_ulong;
pub type uint64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bignum_ctx {
    pub bignums: *mut stack_st_BIGNUM,
    pub stack: BN_STACK,
    pub used: size_t,
    pub error: libc::c_char,
    pub defer_error: libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct BN_STACK {
    pub indexes: *mut size_t,
    pub depth: size_t,
    pub size: size_t,
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
pub type sk_BIGNUM_free_func = Option::<unsafe extern "C" fn(*mut BIGNUM) -> ()>;
pub type OPENSSL_sk_free_func = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type OPENSSL_STACK = stack_st;
pub type OPENSSL_sk_call_free_func = Option::<
    unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
>;
#[inline]
unsafe extern "C" fn sk_BIGNUM_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<OPENSSL_sk_free_func, sk_BIGNUM_free_func>(free_func))
        .expect("non-null function pointer")(ptr as *mut BIGNUM);
}
#[inline]
unsafe extern "C" fn sk_BIGNUM_num(mut sk: *const stack_st_BIGNUM) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_BIGNUM_new_null() -> *mut stack_st_BIGNUM {
    return OPENSSL_sk_new_null() as *mut stack_st_BIGNUM;
}
#[inline]
unsafe extern "C" fn sk_BIGNUM_push(
    mut sk: *mut stack_st_BIGNUM,
    mut p: *mut BIGNUM,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_BIGNUM_value(
    mut sk: *const stack_st_BIGNUM,
    mut i: size_t,
) -> *mut BIGNUM {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut BIGNUM;
}
#[inline]
unsafe extern "C" fn sk_BIGNUM_pop_free(
    mut sk: *mut stack_st_BIGNUM,
    mut free_func: sk_BIGNUM_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_BIGNUM_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<sk_BIGNUM_free_func, OPENSSL_sk_free_func>(free_func),
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_CTX_new() -> *mut BN_CTX {
    let mut ret: *mut BN_CTX = OPENSSL_zalloc(
        ::core::mem::size_of::<BN_CTX>() as libc::c_ulong,
    ) as *mut BN_CTX;
    if ret.is_null() {
        return 0 as *mut BN_CTX;
    }
    BN_STACK_init(&mut (*ret).stack);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_CTX_secure_new() -> *mut BN_CTX {
    return BN_CTX_new();
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_CTX_free(mut ctx: *mut BN_CTX) {
    if ctx.is_null() {
        return;
    }
    if (*ctx).used == 0 as libc::c_int as size_t || (*ctx).error as libc::c_int != 0
    {} else {
        __assert_fail(
            b"ctx->used == 0 || ctx->error\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/ctx.c\0"
                as *const u8 as *const libc::c_char,
            129 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 27],
                &[libc::c_char; 27],
            >(b"void BN_CTX_free(BN_CTX *)\0"))
                .as_ptr(),
        );
    }
    'c_2098: {
        if (*ctx).used == 0 as libc::c_int as size_t || (*ctx).error as libc::c_int != 0
        {} else {
            __assert_fail(
                b"ctx->used == 0 || ctx->error\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/ctx.c\0"
                    as *const u8 as *const libc::c_char,
                129 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 27],
                    &[libc::c_char; 27],
                >(b"void BN_CTX_free(BN_CTX *)\0"))
                    .as_ptr(),
            );
        }
    };
    sk_BIGNUM_pop_free(
        (*ctx).bignums,
        Some(BN_free as unsafe extern "C" fn(*mut BIGNUM) -> ()),
    );
    BN_STACK_cleanup(&mut (*ctx).stack);
    OPENSSL_free(ctx as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_CTX_start(mut ctx: *mut BN_CTX) {
    if (*ctx).error != 0 {
        return;
    }
    if BN_STACK_push(&mut (*ctx).stack, (*ctx).used) == 0 {
        (*ctx).error = 1 as libc::c_int as libc::c_char;
        (*ctx).defer_error = 1 as libc::c_int as libc::c_char;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_CTX_get(mut ctx: *mut BN_CTX) -> *mut BIGNUM {
    if (*ctx).error != 0 {
        if (*ctx).defer_error != 0 {
            ERR_put_error(
                3 as libc::c_int,
                0 as libc::c_int,
                116 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/ctx.c\0"
                    as *const u8 as *const libc::c_char,
                153 as libc::c_int as libc::c_uint,
            );
            (*ctx).defer_error = 0 as libc::c_int as libc::c_char;
        }
        return 0 as *mut BIGNUM;
    }
    if ((*ctx).bignums).is_null() {
        (*ctx).bignums = sk_BIGNUM_new_null();
        if ((*ctx).bignums).is_null() {
            (*ctx).error = 1 as libc::c_int as libc::c_char;
            return 0 as *mut BIGNUM;
        }
    }
    if (*ctx).used == sk_BIGNUM_num((*ctx).bignums) {
        let mut bn: *mut BIGNUM = BN_new();
        if bn.is_null() || sk_BIGNUM_push((*ctx).bignums, bn) == 0 {
            ERR_put_error(
                3 as libc::c_int,
                0 as libc::c_int,
                116 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/ctx.c\0"
                    as *const u8 as *const libc::c_char,
                170 as libc::c_int as libc::c_uint,
            );
            BN_free(bn);
            (*ctx).error = 1 as libc::c_int as libc::c_char;
            return 0 as *mut BIGNUM;
        }
    }
    let mut ret: *mut BIGNUM = sk_BIGNUM_value((*ctx).bignums, (*ctx).used);
    BN_zero(ret);
    (*ctx).used = ((*ctx).used).wrapping_add(1);
    (*ctx).used;
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BN_CTX_end(mut ctx: *mut BN_CTX) {
    if (*ctx).error != 0 {
        return;
    }
    (*ctx).used = BN_STACK_pop(&mut (*ctx).stack);
}
unsafe extern "C" fn BN_STACK_init(mut st: *mut BN_STACK) {
    (*st).indexes = 0 as *mut size_t;
    (*st).size = 0 as libc::c_int as size_t;
    (*st).depth = (*st).size;
}
unsafe extern "C" fn BN_STACK_cleanup(mut st: *mut BN_STACK) {
    OPENSSL_free((*st).indexes as *mut libc::c_void);
}
unsafe extern "C" fn BN_STACK_push(
    mut st: *mut BN_STACK,
    mut idx: size_t,
) -> libc::c_int {
    if (*st).depth == (*st).size {
        let mut new_size: size_t = if (*st).size != 0 as libc::c_int as size_t {
            (*st).size * 3 as libc::c_int as size_t / 2 as libc::c_int as size_t
        } else {
            32 as libc::c_int as size_t
        };
        if new_size <= (*st).size
            || new_size
                > (18446744073709551615 as libc::c_ulong)
                    .wrapping_div(::core::mem::size_of::<size_t>() as libc::c_ulong)
        {
            return 0 as libc::c_int;
        }
        let mut new_indexes: *mut size_t = OPENSSL_realloc(
            (*st).indexes as *mut libc::c_void,
            new_size.wrapping_mul(::core::mem::size_of::<size_t>() as libc::c_ulong),
        ) as *mut size_t;
        if new_indexes.is_null() {
            return 0 as libc::c_int;
        }
        (*st).indexes = new_indexes;
        (*st).size = new_size;
    }
    *((*st).indexes).offset((*st).depth as isize) = idx;
    (*st).depth = ((*st).depth).wrapping_add(1);
    (*st).depth;
    return 1 as libc::c_int;
}
unsafe extern "C" fn BN_STACK_pop(mut st: *mut BN_STACK) -> size_t {
    if (*st).depth > 0 as libc::c_int as size_t {} else {
        __assert_fail(
            b"st->depth > 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/ctx.c\0"
                as *const u8 as *const libc::c_char,
            229 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 32],
                &[libc::c_char; 32],
            >(b"size_t BN_STACK_pop(BN_STACK *)\0"))
                .as_ptr(),
        );
    }
    'c_2631: {
        if (*st).depth > 0 as libc::c_int as size_t {} else {
            __assert_fail(
                b"st->depth > 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/ctx.c\0"
                    as *const u8 as *const libc::c_char,
                229 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 32],
                    &[libc::c_char; 32],
                >(b"size_t BN_STACK_pop(BN_STACK *)\0"))
                    .as_ptr(),
            );
        }
    };
    (*st).depth = ((*st).depth).wrapping_sub(1);
    (*st).depth;
    return *((*st).indexes).offset((*st).depth as isize);
}
