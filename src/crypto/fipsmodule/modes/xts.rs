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
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct aes_key_st {
    pub rd_key: [uint32_t; 60],
    pub rounds: libc::c_uint,
}
pub type AES_KEY = aes_key_st;
pub type block128_f = Option::<
    unsafe extern "C" fn(*const uint8_t, *mut uint8_t, *const AES_KEY) -> (),
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xts128_context {
    pub key1: *mut AES_KEY,
    pub key2: *mut AES_KEY,
    pub block1: block128_f,
    pub block2: block128_f,
}
pub type XTS128_CONTEXT = xts128_context;
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub u: [uint64_t; 2],
    pub c: [uint8_t; 16],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub u: [uint64_t; 2],
    pub c: [uint8_t; 16],
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_xts128_encrypt(
    mut ctx: *const XTS128_CONTEXT,
    mut iv: *const uint8_t,
    mut inp: *const uint8_t,
    mut out: *mut uint8_t,
    mut len: size_t,
    mut enc: libc::c_int,
) -> size_t {
    let mut tweak: C2RustUnnamed = C2RustUnnamed { u: [0; 2] };
    let mut scratch: C2RustUnnamed = C2RustUnnamed { u: [0; 2] };
    let mut i: libc::c_uint = 0;
    if len < 16 as libc::c_int as size_t {
        return 0 as libc::c_int as size_t;
    }
    OPENSSL_memcpy(
        (tweak.c).as_mut_ptr() as *mut libc::c_void,
        iv as *const libc::c_void,
        16 as libc::c_int as size_t,
    );
    (Some(((*ctx).block2).expect("non-null function pointer")))
        .expect(
            "non-null function pointer",
        )((tweak.c).as_mut_ptr() as *const uint8_t, (tweak.c).as_mut_ptr(), (*ctx).key2);
    if enc == 0 && len % 16 as libc::c_int as size_t != 0 {
        len = len.wrapping_sub(16 as libc::c_int as size_t);
    }
    while len >= 16 as libc::c_int as size_t {
        OPENSSL_memcpy(
            (scratch.c).as_mut_ptr() as *mut libc::c_void,
            inp as *const libc::c_void,
            16 as libc::c_int as size_t,
        );
        scratch.u[0 as libc::c_int as usize] ^= tweak.u[0 as libc::c_int as usize];
        scratch.u[1 as libc::c_int as usize] ^= tweak.u[1 as libc::c_int as usize];
        (Some(((*ctx).block1).expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )(
            (scratch.c).as_mut_ptr() as *const uint8_t,
            (scratch.c).as_mut_ptr(),
            (*ctx).key1,
        );
        scratch.u[0 as libc::c_int as usize] ^= tweak.u[0 as libc::c_int as usize];
        scratch.u[1 as libc::c_int as usize] ^= tweak.u[1 as libc::c_int as usize];
        OPENSSL_memcpy(
            out as *mut libc::c_void,
            (scratch.c).as_mut_ptr() as *const libc::c_void,
            16 as libc::c_int as size_t,
        );
        inp = inp.offset(16 as libc::c_int as isize);
        out = out.offset(16 as libc::c_int as isize);
        len = len.wrapping_sub(16 as libc::c_int as size_t);
        if len == 0 as libc::c_int as size_t {
            return 1 as libc::c_int as size_t;
        }
        let mut carry: libc::c_uint = 0;
        let mut res: libc::c_uint = 0;
        res = (0x87 as libc::c_int as int64_t
            & tweak.u[1 as libc::c_int as usize] as int64_t >> 63 as libc::c_int)
            as libc::c_uint;
        carry = (tweak.u[0 as libc::c_int as usize] >> 63 as libc::c_int)
            as libc::c_uint;
        tweak
            .u[0 as libc::c_int
            as usize] = tweak.u[0 as libc::c_int as usize] << 1 as libc::c_int
            ^ res as uint64_t;
        tweak
            .u[1 as libc::c_int
            as usize] = tweak.u[1 as libc::c_int as usize] << 1 as libc::c_int
            | carry as uint64_t;
    }
    if enc != 0 {
        i = 0 as libc::c_int as libc::c_uint;
        while (i as size_t) < len {
            let mut c: uint8_t = *inp.offset(i as isize);
            *out.offset(i as isize) = scratch.c[i as usize];
            scratch.c[i as usize] = c;
            i = i.wrapping_add(1);
            i;
        }
        scratch.u[0 as libc::c_int as usize] ^= tweak.u[0 as libc::c_int as usize];
        scratch.u[1 as libc::c_int as usize] ^= tweak.u[1 as libc::c_int as usize];
        (Some(((*ctx).block1).expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )(
            (scratch.c).as_mut_ptr() as *const uint8_t,
            (scratch.c).as_mut_ptr(),
            (*ctx).key1,
        );
        scratch.u[0 as libc::c_int as usize] ^= tweak.u[0 as libc::c_int as usize];
        scratch.u[1 as libc::c_int as usize] ^= tweak.u[1 as libc::c_int as usize];
        OPENSSL_memcpy(
            out.offset(-(16 as libc::c_int as isize)) as *mut libc::c_void,
            (scratch.c).as_mut_ptr() as *const libc::c_void,
            16 as libc::c_int as size_t,
        );
    } else {
        let mut tweak1: C2RustUnnamed_0 = C2RustUnnamed_0 { u: [0; 2] };
        let mut carry_0: libc::c_uint = 0;
        let mut res_0: libc::c_uint = 0;
        res_0 = (0x87 as libc::c_int as int64_t
            & tweak.u[1 as libc::c_int as usize] as int64_t >> 63 as libc::c_int)
            as libc::c_uint;
        carry_0 = (tweak.u[0 as libc::c_int as usize] >> 63 as libc::c_int)
            as libc::c_uint;
        tweak1
            .u[0 as libc::c_int
            as usize] = tweak.u[0 as libc::c_int as usize] << 1 as libc::c_int
            ^ res_0 as uint64_t;
        tweak1
            .u[1 as libc::c_int
            as usize] = tweak.u[1 as libc::c_int as usize] << 1 as libc::c_int
            | carry_0 as uint64_t;
        OPENSSL_memcpy(
            (scratch.c).as_mut_ptr() as *mut libc::c_void,
            inp as *const libc::c_void,
            16 as libc::c_int as size_t,
        );
        scratch.u[0 as libc::c_int as usize] ^= tweak1.u[0 as libc::c_int as usize];
        scratch.u[1 as libc::c_int as usize] ^= tweak1.u[1 as libc::c_int as usize];
        (Some(((*ctx).block1).expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )(
            (scratch.c).as_mut_ptr() as *const uint8_t,
            (scratch.c).as_mut_ptr(),
            (*ctx).key1,
        );
        scratch.u[0 as libc::c_int as usize] ^= tweak1.u[0 as libc::c_int as usize];
        scratch.u[1 as libc::c_int as usize] ^= tweak1.u[1 as libc::c_int as usize];
        i = 0 as libc::c_int as libc::c_uint;
        while (i as size_t) < len {
            let mut c_0: uint8_t = *inp
                .offset((16 as libc::c_int as libc::c_uint).wrapping_add(i) as isize);
            *out
                .offset(
                    (16 as libc::c_int as libc::c_uint).wrapping_add(i) as isize,
                ) = scratch.c[i as usize];
            scratch.c[i as usize] = c_0;
            i = i.wrapping_add(1);
            i;
        }
        scratch.u[0 as libc::c_int as usize] ^= tweak.u[0 as libc::c_int as usize];
        scratch.u[1 as libc::c_int as usize] ^= tweak.u[1 as libc::c_int as usize];
        (Some(((*ctx).block1).expect("non-null function pointer")))
            .expect(
                "non-null function pointer",
            )(
            (scratch.c).as_mut_ptr() as *const uint8_t,
            (scratch.c).as_mut_ptr(),
            (*ctx).key1,
        );
        scratch.u[0 as libc::c_int as usize] ^= tweak.u[0 as libc::c_int as usize];
        scratch.u[1 as libc::c_int as usize] ^= tweak.u[1 as libc::c_int as usize];
        OPENSSL_memcpy(
            out as *mut libc::c_void,
            (scratch.c).as_mut_ptr() as *const libc::c_void,
            16 as libc::c_int as size_t,
        );
    }
    return 1 as libc::c_int as size_t;
}
