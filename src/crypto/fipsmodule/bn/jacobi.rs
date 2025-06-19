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
    fn BN_copy(dest: *mut BIGNUM, src: *const BIGNUM) -> *mut BIGNUM;
    fn BN_is_negative(bn: *const BIGNUM) -> libc::c_int;
    fn BN_CTX_start(ctx: *mut BN_CTX);
    fn BN_CTX_get(ctx: *mut BN_CTX) -> *mut BIGNUM;
    fn BN_CTX_end(ctx: *mut BN_CTX);
    fn BN_is_zero(bn: *const BIGNUM) -> libc::c_int;
    fn BN_is_one(bn: *const BIGNUM) -> libc::c_int;
    fn BN_is_odd(bn: *const BIGNUM) -> libc::c_int;
    fn BN_rshift(r: *mut BIGNUM, a: *const BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_is_bit_set(a: *const BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_nnmod(
        rem: *mut BIGNUM,
        numerator: *const BIGNUM,
        divisor: *const BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
}
pub type __uint64_t = libc::c_ulong;
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bn_jacobi(
    mut a: *const BIGNUM,
    mut b: *const BIGNUM,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    static mut tab: [libc::c_int; 8] = [
        0 as libc::c_int,
        1 as libc::c_int,
        0 as libc::c_int,
        -(1 as libc::c_int),
        0 as libc::c_int,
        -(1 as libc::c_int),
        0 as libc::c_int,
        1 as libc::c_int,
    ];
    if BN_is_odd(b) == 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/jacobi.c\0"
                as *const u8 as *const libc::c_char,
            73 as libc::c_int as libc::c_uint,
        );
        return -(2 as libc::c_int);
    }
    if BN_is_negative(b) != 0 {
        ERR_put_error(
            3 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/bn/jacobi.c\0"
                as *const u8 as *const libc::c_char,
            79 as libc::c_int as libc::c_uint,
        );
        return -(2 as libc::c_int);
    }
    let mut ret: libc::c_int = -(2 as libc::c_int);
    BN_CTX_start(ctx);
    let mut A: *mut BIGNUM = BN_CTX_get(ctx);
    let mut B: *mut BIGNUM = BN_CTX_get(ctx);
    if !B.is_null() {
        if !((BN_copy(A, a)).is_null() || (BN_copy(B, b)).is_null()) {
            ret = 1 as libc::c_int;
            loop {
                if BN_is_zero(A) != 0 {
                    ret = if BN_is_one(B) != 0 { ret } else { 0 as libc::c_int };
                    break;
                } else {
                    let mut i: libc::c_int = 0 as libc::c_int;
                    while BN_is_bit_set(A, i) == 0 {
                        i += 1;
                        i;
                    }
                    if BN_rshift(A, A, i) == 0 {
                        ret = -(2 as libc::c_int);
                        break;
                    } else {
                        if i & 1 as libc::c_int != 0 {
                            ret = ret
                                * tab[((if (*B).width == 0 as libc::c_int {
                                    0 as libc::c_int as BN_ULONG
                                } else {
                                    *((*B).d).offset(0 as libc::c_int as isize)
                                }) & 7 as libc::c_int as BN_ULONG) as usize];
                        }
                        if (if (*A).neg != 0 {
                            !(if (*A).width == 0 as libc::c_int {
                                0 as libc::c_int as BN_ULONG
                            } else {
                                *((*A).d).offset(0 as libc::c_int as isize)
                            })
                        } else {
                            (if (*A).width == 0 as libc::c_int {
                                0 as libc::c_int as BN_ULONG
                            } else {
                                *((*A).d).offset(0 as libc::c_int as isize)
                            })
                        })
                            & (if (*B).width == 0 as libc::c_int {
                                0 as libc::c_int as BN_ULONG
                            } else {
                                *((*B).d).offset(0 as libc::c_int as isize)
                            }) & 2 as libc::c_int as BN_ULONG != 0
                        {
                            ret = -ret;
                        }
                        if BN_nnmod(B, B, A, ctx) == 0 {
                            ret = -(2 as libc::c_int);
                            break;
                        } else {
                            let mut tmp: *mut BIGNUM = A;
                            A = B;
                            B = tmp;
                            (*tmp).neg = 0 as libc::c_int;
                        }
                    }
                }
            }
        }
    }
    BN_CTX_end(ctx);
    return ret;
}
