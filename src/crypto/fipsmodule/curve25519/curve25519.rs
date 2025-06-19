#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(asm, label_break_value)]
use core::arch::asm;
extern "C" {
    fn abort() -> !;
    fn RAND_bytes(buf: *mut uint8_t, len: size_t) -> libc::c_int;
    fn SHA512_Init(sha: *mut SHA512_CTX) -> libc::c_int;
    fn SHA512_Update(
        sha: *mut SHA512_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn SHA512_Final(out: *mut uint8_t, sha: *mut SHA512_CTX) -> libc::c_int;
    fn SHA512(data: *const uint8_t, len: size_t, out: *mut uint8_t) -> *mut uint8_t;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
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
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn x25519_scalar_mult_generic_nohw(
        out_shared_key: *mut uint8_t,
        private_key: *const uint8_t,
        peer_public_value: *const uint8_t,
    );
    fn x25519_public_from_private_nohw(
        out_public_value: *mut uint8_t,
        private_key: *const uint8_t,
    );
    fn ed25519_public_key_from_hashed_seed_nohw(
        out_public_key: *mut uint8_t,
        az: *mut uint8_t,
    );
    fn ed25519_sign_nohw(
        out_sig: *mut uint8_t,
        r: *mut uint8_t,
        s: *const uint8_t,
        A: *const uint8_t,
        message: *const libc::c_void,
        message_len: size_t,
        dom2_0: *const uint8_t,
        dom2_len: size_t,
    );
    fn ed25519_verify_nohw(
        R_computed_encoded: *mut uint8_t,
        public_key: *const uint8_t,
        R_expected: *mut uint8_t,
        S: *mut uint8_t,
        message: *const uint8_t,
        message_len: size_t,
        dom2_0: *const uint8_t,
        dom2_len: size_t,
    ) -> libc::c_int;
    fn ed25519_check_public_key_nohw(public_key: *const uint8_t) -> libc::c_int;
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
pub struct sha512_state_st {
    pub h: [uint64_t; 8],
    pub Nl: uint64_t,
    pub Nh: uint64_t,
    pub p: [uint8_t; 128],
    pub num: libc::c_uint,
    pub md_len: libc::c_uint,
}
pub type SHA512_CTX = sha512_state_st;
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
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_117_error_is_ed25519_parameter_length_mismatch {
    #[bitfield(
        name = "static_assertion_at_line_117_error_is_ed25519_parameter_length_mismatch",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_117_error_is_ed25519_parameter_length_mismatch: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
pub type ed25519_algorithm_t = libc::c_uint;
pub const ED25519PH_ALG: ed25519_algorithm_t = 2;
pub const ED25519CTX_ALG: ed25519_algorithm_t = 1;
pub const ED25519_ALG: ed25519_algorithm_t = 0;
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
unsafe extern "C" fn CRYPTO_load_u64_le(mut in_0: *const libc::c_void) -> uint64_t {
    let mut v: uint64_t = 0;
    OPENSSL_memcpy(
        &mut v as *mut uint64_t as *mut libc::c_void,
        in_0,
        ::core::mem::size_of::<uint64_t>() as libc::c_ulong,
    );
    return v;
}
#[inline]
unsafe extern "C" fn boringssl_ensure_eddsa_self_test() {}
#[inline]
unsafe extern "C" fn boringssl_ensure_hasheddsa_self_test() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_update_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_lock_state() {}
#[inline]
unsafe extern "C" fn FIPS_service_indicator_unlock_state() {}
#[no_mangle]
pub static mut RFC8032_DOM2_PREFIX: [uint8_t; 32] = [
    'S' as i32 as uint8_t,
    'i' as i32 as uint8_t,
    'g' as i32 as uint8_t,
    'E' as i32 as uint8_t,
    'd' as i32 as uint8_t,
    '2' as i32 as uint8_t,
    '5' as i32 as uint8_t,
    '5' as i32 as uint8_t,
    '1' as i32 as uint8_t,
    '9' as i32 as uint8_t,
    ' ' as i32 as uint8_t,
    'n' as i32 as uint8_t,
    'o' as i32 as uint8_t,
    ' ' as i32 as uint8_t,
    'E' as i32 as uint8_t,
    'd' as i32 as uint8_t,
    '2' as i32 as uint8_t,
    '5' as i32 as uint8_t,
    '5' as i32 as uint8_t,
    '1' as i32 as uint8_t,
    '9' as i32 as uint8_t,
    ' ' as i32 as uint8_t,
    'c' as i32 as uint8_t,
    'o' as i32 as uint8_t,
    'l' as i32 as uint8_t,
    'l' as i32 as uint8_t,
    'i' as i32 as uint8_t,
    's' as i32 as uint8_t,
    'i' as i32 as uint8_t,
    'o' as i32 as uint8_t,
    'n' as i32 as uint8_t,
    's' as i32 as uint8_t,
];
#[no_mangle]
pub unsafe extern "C" fn ed25519_sha512(
    mut out: *mut uint8_t,
    mut input1: *const libc::c_void,
    mut len1: size_t,
    mut input2: *const libc::c_void,
    mut len2: size_t,
    mut input3: *const libc::c_void,
    mut len3: size_t,
    mut input4: *const libc::c_void,
    mut len4: size_t,
) {
    let mut hash_ctx: SHA512_CTX = sha512_state_st {
        h: [0; 8],
        Nl: 0,
        Nh: 0,
        p: [0; 128],
        num: 0,
        md_len: 0,
    };
    SHA512_Init(&mut hash_ctx);
    SHA512_Update(&mut hash_ctx, input1, len1);
    SHA512_Update(&mut hash_ctx, input2, len2);
    if len3 != 0 as libc::c_int as size_t {
        SHA512_Update(&mut hash_ctx, input3, len3);
    }
    if len4 != 0 as libc::c_int as size_t {
        SHA512_Update(&mut hash_ctx, input4, len4);
    }
    SHA512_Final(out, &mut hash_ctx);
}
#[no_mangle]
pub unsafe extern "C" fn ED25519_keypair_from_seed(
    mut out_public_key: *mut uint8_t,
    mut out_private_key: *mut uint8_t,
    mut seed: *const uint8_t,
) {
    boringssl_ensure_eddsa_self_test();
    let mut az: [uint8_t; 64] = [0; 64];
    SHA512(seed, 32 as libc::c_int as size_t, az.as_mut_ptr());
    az[0 as libc::c_int
        as usize] = (az[0 as libc::c_int as usize] as libc::c_int & 248 as libc::c_int)
        as uint8_t;
    az[31 as libc::c_int
        as usize] = (az[31 as libc::c_int as usize] as libc::c_int & 127 as libc::c_int)
        as uint8_t;
    az[31 as libc::c_int
        as usize] = (az[31 as libc::c_int as usize] as libc::c_int | 64 as libc::c_int)
        as uint8_t;
    ed25519_public_key_from_hashed_seed_nohw(out_public_key, az.as_mut_ptr());
    OPENSSL_memcpy(
        out_private_key as *mut libc::c_void,
        seed as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
    OPENSSL_memcpy(
        out_private_key.offset(32 as libc::c_int as isize) as *mut libc::c_void,
        out_public_key as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
}
unsafe extern "C" fn ed25519_keypair_pct(
    mut public_key: *mut uint8_t,
    mut private_key: *mut uint8_t,
) -> libc::c_int {
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ED25519_keypair_internal(
    mut out_public_key: *mut uint8_t,
    mut out_private_key: *mut uint8_t,
) -> libc::c_int {
    FIPS_service_indicator_lock_state();
    boringssl_ensure_eddsa_self_test();
    let mut seed: [uint8_t; 32] = [0; 32];
    RAND_bytes(seed.as_mut_ptr(), 32 as libc::c_int as size_t);
    ED25519_keypair_from_seed(
        out_public_key,
        out_private_key,
        seed.as_mut_ptr() as *const uint8_t,
    );
    OPENSSL_cleanse(seed.as_mut_ptr() as *mut libc::c_void, 32 as libc::c_int as size_t);
    let mut result: libc::c_int = ed25519_keypair_pct(out_public_key, out_private_key);
    FIPS_service_indicator_unlock_state();
    if result != 0 {
        FIPS_service_indicator_update_state();
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn ED25519_keypair(
    mut out_public_key: *mut uint8_t,
    mut out_private_key: *mut uint8_t,
) {
    if ED25519_keypair_internal(out_public_key, out_private_key) != 0 {} else {
        __assert_fail(
            b"ED25519_keypair_internal(out_public_key, out_private_key)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519.c\0"
                as *const u8 as *const libc::c_char,
            177 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 43],
                &[libc::c_char; 43],
            >(b"void ED25519_keypair(uint8_t *, uint8_t *)\0"))
                .as_ptr(),
        );
    }
    'c_1427: {
        if ED25519_keypair_internal(out_public_key, out_private_key) != 0 {} else {
            __assert_fail(
                b"ED25519_keypair_internal(out_public_key, out_private_key)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519.c\0"
                    as *const u8 as *const libc::c_char,
                177 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 43],
                    &[libc::c_char; 43],
                >(b"void ED25519_keypair(uint8_t *, uint8_t *)\0"))
                    .as_ptr(),
            );
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn ED25519_sign(
    mut out_sig: *mut uint8_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut private_key: *const uint8_t,
) -> libc::c_int {
    FIPS_service_indicator_lock_state();
    boringssl_ensure_eddsa_self_test();
    let mut res: libc::c_int = ED25519_sign_no_self_test(
        out_sig,
        message,
        message_len,
        private_key,
    );
    FIPS_service_indicator_unlock_state();
    if res != 0 {
        FIPS_service_indicator_update_state();
    }
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn ED25519_sign_no_self_test(
    mut out_sig: *mut uint8_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut private_key: *const uint8_t,
) -> libc::c_int {
    return ed25519_sign_internal(
        ED25519_ALG,
        out_sig,
        message,
        message_len,
        private_key,
        0 as *const uint8_t,
        0 as libc::c_int as size_t,
    );
}
unsafe extern "C" fn dom2(
    mut alg: ed25519_algorithm_t,
    mut buffer: *mut uint8_t,
    mut buffer_len: *mut size_t,
    mut context: *const uint8_t,
    mut context_len: size_t,
) -> libc::c_int {
    if buffer_len.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519.c\0"
                as *const u8 as *const libc::c_char,
            204 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    *buffer_len = 0 as libc::c_int as size_t;
    let mut phflag: uint8_t = 0 as libc::c_int as uint8_t;
    match alg as libc::c_uint {
        0 => return (context_len == 0 as libc::c_int as size_t) as libc::c_int,
        1 => {
            if context_len == 0 as libc::c_int as size_t {
                return 0 as libc::c_int;
            }
            phflag = 0 as libc::c_int as uint8_t;
        }
        2 => {
            phflag = 1 as libc::c_int as uint8_t;
        }
        _ => {
            abort();
        }
    }
    OPENSSL_memcpy(
        buffer as *mut libc::c_void,
        RFC8032_DOM2_PREFIX.as_ptr() as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
    *buffer.offset(32 as libc::c_int as isize) = phflag;
    *buffer
        .offset(
            (32 as libc::c_int + 1 as libc::c_int) as isize,
        ) = context_len as uint8_t;
    if context_len > 0 as libc::c_int as size_t {
        if context.is_null() {
            ERR_put_error(
                14 as libc::c_int,
                0 as libc::c_int,
                3 as libc::c_int | 64 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519.c\0"
                    as *const u8 as *const libc::c_char,
                237 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        if context_len > 255 as libc::c_int as size_t {
            return 0 as libc::c_int;
        }
        OPENSSL_memcpy(
            &mut *buffer
                .offset(
                    (32 as libc::c_int + 1 as libc::c_int + 1 as libc::c_int) as isize,
                ) as *mut uint8_t as *mut libc::c_void,
            context as *const libc::c_void,
            context_len,
        );
    }
    *buffer_len = ((32 as libc::c_int + 1 as libc::c_int + 1 as libc::c_int) as size_t)
        .wrapping_add(context_len);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ed25519_sign_internal(
    mut alg: ed25519_algorithm_t,
    mut out_sig: *mut uint8_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut private_key: *const uint8_t,
    mut ctx: *const uint8_t,
    mut ctx_len: size_t,
) -> libc::c_int {
    let mut az: [uint8_t; 64] = [0; 64];
    SHA512(private_key, 32 as libc::c_int as size_t, az.as_mut_ptr());
    az[0 as libc::c_int
        as usize] = (az[0 as libc::c_int as usize] as libc::c_int & 248 as libc::c_int)
        as uint8_t;
    az[31 as libc::c_int
        as usize] = (az[31 as libc::c_int as usize] as libc::c_int & 63 as libc::c_int)
        as uint8_t;
    az[31 as libc::c_int
        as usize] = (az[31 as libc::c_int as usize] as libc::c_int | 64 as libc::c_int)
        as uint8_t;
    let mut r: [uint8_t; 64] = [0; 64];
    let mut dom2_buffer: [uint8_t; 289] = [
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
    let mut dom2_buffer_len: size_t = 0 as libc::c_int as size_t;
    if dom2(alg, dom2_buffer.as_mut_ptr(), &mut dom2_buffer_len, ctx, ctx_len) == 0 {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            14 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519.c\0"
                as *const u8 as *const libc::c_char,
            279 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if dom2_buffer_len > 0 as libc::c_int as size_t {
        ed25519_sha512(
            r.as_mut_ptr(),
            dom2_buffer.as_mut_ptr() as *const libc::c_void,
            dom2_buffer_len,
            az.as_mut_ptr().offset(32 as libc::c_int as isize) as *const libc::c_void,
            32 as libc::c_int as size_t,
            message as *const libc::c_void,
            message_len,
            0 as *const libc::c_void,
            0 as libc::c_int as size_t,
        );
    } else {
        ed25519_sha512(
            r.as_mut_ptr(),
            az.as_mut_ptr().offset(32 as libc::c_int as isize) as *const libc::c_void,
            32 as libc::c_int as size_t,
            message as *const libc::c_void,
            message_len,
            0 as *const libc::c_void,
            0 as libc::c_int as size_t,
            0 as *const libc::c_void,
            0 as libc::c_int as size_t,
        );
    }
    ed25519_sign_nohw(
        out_sig,
        r.as_mut_ptr(),
        az.as_mut_ptr(),
        private_key.offset(32 as libc::c_int as isize),
        message as *const libc::c_void,
        message_len,
        dom2_buffer.as_mut_ptr(),
        dom2_buffer_len,
    );
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ED25519_verify(
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut signature: *const uint8_t,
    mut public_key: *const uint8_t,
) -> libc::c_int {
    FIPS_service_indicator_lock_state();
    boringssl_ensure_eddsa_self_test();
    let mut res: libc::c_int = ED25519_verify_no_self_test(
        message,
        message_len,
        signature,
        public_key,
    );
    FIPS_service_indicator_unlock_state();
    if res != 0 {
        FIPS_service_indicator_update_state();
    }
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn ED25519_verify_no_self_test(
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut signature: *const uint8_t,
    mut public_key: *const uint8_t,
) -> libc::c_int {
    return ed25519_verify_internal(
        ED25519_ALG,
        message,
        message_len,
        signature,
        public_key,
        0 as *const uint8_t,
        0 as libc::c_int as size_t,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ED25519ctx_sign(
    mut out_sig: *mut uint8_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut private_key: *const uint8_t,
    mut context: *const uint8_t,
    mut context_len: size_t,
) -> libc::c_int {
    FIPS_service_indicator_lock_state();
    boringssl_ensure_eddsa_self_test();
    let mut res: libc::c_int = ED25519ctx_sign_no_self_test(
        out_sig,
        message,
        message_len,
        private_key,
        context,
        context_len,
    );
    FIPS_service_indicator_unlock_state();
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn ED25519ctx_sign_no_self_test(
    mut out_sig: *mut uint8_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut private_key: *const uint8_t,
    mut context: *const uint8_t,
    mut context_len: size_t,
) -> libc::c_int {
    return ed25519_sign_internal(
        ED25519CTX_ALG,
        out_sig,
        message,
        message_len,
        private_key,
        context,
        context_len,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ED25519ctx_verify(
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut signature: *const uint8_t,
    mut public_key: *const uint8_t,
    mut context: *const uint8_t,
    mut context_len: size_t,
) -> libc::c_int {
    FIPS_service_indicator_lock_state();
    boringssl_ensure_eddsa_self_test();
    let mut res: libc::c_int = ED25519ctx_verify_no_self_test(
        message,
        message_len,
        signature,
        public_key,
        context,
        context_len,
    );
    FIPS_service_indicator_unlock_state();
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn ED25519ctx_verify_no_self_test(
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut signature: *const uint8_t,
    mut public_key: *const uint8_t,
    mut context: *const uint8_t,
    mut context_len: size_t,
) -> libc::c_int {
    return ed25519_verify_internal(
        ED25519CTX_ALG,
        message,
        message_len,
        signature,
        public_key,
        context,
        context_len,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ED25519ph_sign(
    mut out_sig: *mut uint8_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut private_key: *const uint8_t,
    mut context: *const uint8_t,
    mut context_len: size_t,
) -> libc::c_int {
    FIPS_service_indicator_lock_state();
    boringssl_ensure_hasheddsa_self_test();
    let mut res: libc::c_int = ED25519ph_sign_no_self_test(
        out_sig,
        message,
        message_len,
        private_key,
        context,
        context_len,
    );
    FIPS_service_indicator_unlock_state();
    if res != 0 {
        FIPS_service_indicator_update_state();
    }
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn ED25519ph_sign_no_self_test(
    mut out_sig: *mut uint8_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut private_key: *const uint8_t,
    mut context: *const uint8_t,
    mut context_len: size_t,
) -> libc::c_int {
    let mut digest: [uint8_t; 64] = [
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
        0,
    ];
    let mut ctx: SHA512_CTX = sha512_state_st {
        h: [0; 8],
        Nl: 0,
        Nh: 0,
        p: [0; 128],
        num: 0,
        md_len: 0,
    };
    SHA512_Init(&mut ctx);
    SHA512_Update(&mut ctx, message as *const libc::c_void, message_len);
    SHA512_Final(digest.as_mut_ptr(), &mut ctx);
    return ED25519ph_sign_digest_no_self_test(
        out_sig,
        digest.as_mut_ptr() as *const uint8_t,
        private_key,
        context,
        context_len,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ED25519ph_sign_digest(
    mut out_sig: *mut uint8_t,
    mut digest: *const uint8_t,
    mut private_key: *const uint8_t,
    mut context: *const uint8_t,
    mut context_len: size_t,
) -> libc::c_int {
    FIPS_service_indicator_lock_state();
    boringssl_ensure_hasheddsa_self_test();
    let mut res: libc::c_int = ED25519ph_sign_digest_no_self_test(
        out_sig,
        digest,
        private_key,
        context,
        context_len,
    );
    FIPS_service_indicator_unlock_state();
    if res != 0 {
        FIPS_service_indicator_update_state();
    }
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn ED25519ph_sign_digest_no_self_test(
    mut out_sig: *mut uint8_t,
    mut digest: *const uint8_t,
    mut private_key: *const uint8_t,
    mut context: *const uint8_t,
    mut context_len: size_t,
) -> libc::c_int {
    return ed25519_sign_internal(
        ED25519PH_ALG,
        out_sig,
        digest,
        64 as libc::c_int as size_t,
        private_key,
        context,
        context_len,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ED25519ph_verify(
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut signature: *const uint8_t,
    mut public_key: *const uint8_t,
    mut context: *const uint8_t,
    mut context_len: size_t,
) -> libc::c_int {
    FIPS_service_indicator_lock_state();
    boringssl_ensure_hasheddsa_self_test();
    let mut res: libc::c_int = ED25519ph_verify_no_self_test(
        message,
        message_len,
        signature,
        public_key,
        context,
        context_len,
    );
    FIPS_service_indicator_unlock_state();
    if res != 0 {
        FIPS_service_indicator_update_state();
    }
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn ED25519ph_verify_no_self_test(
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut signature: *const uint8_t,
    mut public_key: *const uint8_t,
    mut context: *const uint8_t,
    mut context_len: size_t,
) -> libc::c_int {
    let mut digest: [uint8_t; 64] = [
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
        0,
    ];
    let mut ctx: SHA512_CTX = sha512_state_st {
        h: [0; 8],
        Nl: 0,
        Nh: 0,
        p: [0; 128],
        num: 0,
        md_len: 0,
    };
    SHA512_Init(&mut ctx);
    SHA512_Update(&mut ctx, message as *const libc::c_void, message_len);
    SHA512_Final(digest.as_mut_ptr(), &mut ctx);
    return ED25519ph_verify_digest_no_self_test(
        digest.as_mut_ptr() as *const uint8_t,
        signature,
        public_key,
        context,
        context_len,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ED25519ph_verify_digest(
    mut digest: *const uint8_t,
    mut signature: *const uint8_t,
    mut public_key: *const uint8_t,
    mut context: *const uint8_t,
    mut context_len: size_t,
) -> libc::c_int {
    FIPS_service_indicator_lock_state();
    boringssl_ensure_hasheddsa_self_test();
    let mut res: libc::c_int = ED25519ph_verify_digest_no_self_test(
        digest,
        signature,
        public_key,
        context,
        context_len,
    );
    FIPS_service_indicator_unlock_state();
    if res != 0 {
        FIPS_service_indicator_update_state();
    }
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn ED25519ph_verify_digest_no_self_test(
    mut digest: *const uint8_t,
    mut signature: *const uint8_t,
    mut public_key: *const uint8_t,
    mut context: *const uint8_t,
    mut context_len: size_t,
) -> libc::c_int {
    return ed25519_verify_internal(
        ED25519PH_ALG,
        digest,
        64 as libc::c_int as size_t,
        signature,
        public_key,
        context,
        context_len,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ed25519_verify_internal(
    mut alg: ed25519_algorithm_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut signature: *const uint8_t,
    mut public_key: *const uint8_t,
    mut ctx: *const uint8_t,
    mut ctx_len: size_t,
) -> libc::c_int {
    let mut R_expected: [uint8_t; 32] = [0; 32];
    OPENSSL_memcpy(
        R_expected.as_mut_ptr() as *mut libc::c_void,
        signature as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
    let mut S: [uint8_t; 32] = [0; 32];
    OPENSSL_memcpy(
        S.as_mut_ptr() as *mut libc::c_void,
        signature.offset(32 as libc::c_int as isize) as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
    if *signature.offset(63 as libc::c_int as isize) as libc::c_int & 224 as libc::c_int
        != 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    static mut kOrder: [uint64_t; 4] = [
        0x5812631a5cf5d3ed as libc::c_ulong,
        0x14def9dea2f79cd6 as libc::c_ulong,
        0 as libc::c_int as uint64_t,
        0x1000000000000000 as libc::c_ulong,
    ];
    let mut i: size_t = 3 as libc::c_int as size_t;
    loop {
        let mut word: uint64_t = CRYPTO_load_u64_le(
            S.as_mut_ptr().offset((i * 8 as libc::c_int as size_t) as isize)
                as *const libc::c_void,
        );
        if word > kOrder[i as usize] {
            return 0 as libc::c_int
        } else {
            if word < kOrder[i as usize] {
                break;
            }
            if i == 0 as libc::c_int as size_t {
                return 0 as libc::c_int;
            }
            i = i.wrapping_sub(1);
            i;
        }
    }
    let mut dom2_buffer: [uint8_t; 289] = [
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
    let mut dom2_buffer_len: size_t = 0 as libc::c_int as size_t;
    if dom2(alg, dom2_buffer.as_mut_ptr(), &mut dom2_buffer_len, ctx, ctx_len) == 0 {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            14 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519.c\0"
                as *const u8 as *const libc::c_char,
            528 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut res: libc::c_int = 0 as libc::c_int;
    let mut R_computed_encoded: [uint8_t; 32] = [0; 32];
    res = ed25519_verify_nohw(
        R_computed_encoded.as_mut_ptr(),
        public_key,
        R_expected.as_mut_ptr(),
        S.as_mut_ptr(),
        message,
        message_len,
        dom2_buffer.as_mut_ptr(),
        dom2_buffer_len,
    );
    return (res == 1 as libc::c_int
        && CRYPTO_memcmp(
            R_computed_encoded.as_mut_ptr() as *const libc::c_void,
            R_expected.as_mut_ptr() as *const libc::c_void,
            ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
        ) == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ED25519_check_public_key(
    mut public_key: *const uint8_t,
) -> libc::c_int {
    return ed25519_check_public_key_nohw(public_key);
}
#[no_mangle]
pub unsafe extern "C" fn X25519_public_from_private(
    mut out_public_value: *mut uint8_t,
    mut private_key: *const uint8_t,
) {
    x25519_public_from_private_nohw(out_public_value, private_key);
}
#[no_mangle]
pub unsafe extern "C" fn X25519_keypair(
    mut out_public_value: *mut uint8_t,
    mut out_private_key: *mut uint8_t,
) {
    RAND_bytes(out_private_key, 32 as libc::c_int as size_t);
    let ref mut fresh0 = *out_private_key.offset(0 as libc::c_int as isize);
    *fresh0 = (*fresh0 as libc::c_int | !(248 as libc::c_int)) as uint8_t;
    let ref mut fresh1 = *out_private_key.offset(31 as libc::c_int as isize);
    *fresh1 = (*fresh1 as libc::c_int & !(64 as libc::c_int)) as uint8_t;
    let ref mut fresh2 = *out_private_key.offset(31 as libc::c_int as isize);
    *fresh2 = (*fresh2 as libc::c_int | !(127 as libc::c_int)) as uint8_t;
    X25519_public_from_private(out_public_value, out_private_key as *const uint8_t);
}
#[no_mangle]
pub unsafe extern "C" fn X25519(
    mut out_shared_key: *mut uint8_t,
    mut private_key: *const uint8_t,
    mut peer_public_value: *const uint8_t,
) -> libc::c_int {
    static mut kZeros: [uint8_t; 32] = [
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
    x25519_scalar_mult_generic_nohw(out_shared_key, private_key, peer_public_value);
    return (constant_time_declassify_int(
        CRYPTO_memcmp(
            kZeros.as_ptr() as *const libc::c_void,
            out_shared_key as *const libc::c_void,
            32 as libc::c_int as size_t,
        ),
    ) != 0 as libc::c_int) as libc::c_int;
}
