#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(label_break_value)]
extern "C" {
    fn RAND_bytes(buf: *mut uint8_t, len: size_t) -> libc::c_int;
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
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
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn SHAKE256(
        data: *const uint8_t,
        in_len: size_t,
        out: *mut uint8_t,
        out_len: size_t,
    ) -> *mut uint8_t;
    fn SHAKE_Init(ctx: *mut KECCAK1600_CTX, block_size: size_t) -> libc::c_int;
    fn SHAKE_Absorb(
        ctx: *mut KECCAK1600_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn SHAKE_Squeeze(
        md: *mut uint8_t,
        ctx: *mut KECCAK1600_CTX,
        len: size_t,
    ) -> libc::c_int;
    fn SHAKE_Final(
        md: *mut uint8_t,
        ctx: *mut KECCAK1600_CTX,
        len: size_t,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type int32_t = __int32_t;
pub type int64_t = __int64_t;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ml_dsa_params {
    pub k: uint8_t,
    pub l: uint8_t,
    pub eta: size_t,
    pub tau: size_t,
    pub beta: size_t,
    pub gamma1: size_t,
    pub gamma2: int32_t,
    pub omega: size_t,
    pub c_tilde_bytes: size_t,
    pub poly_vech_packed_bytes: size_t,
    pub poly_z_packed_bytes: size_t,
    pub poly_w1_packed_bytes: size_t,
    pub poly_eta_packed_bytes: size_t,
    pub public_key_bytes: size_t,
    pub secret_key_bytes: size_t,
    pub bytes: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct polyveck {
    pub vec: [ml_dsa_poly; 8],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ml_dsa_poly {
    pub coeffs: [int32_t; 256],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct polyvecl {
    pub vec: [ml_dsa_poly; 7],
}
pub type KECCAK1600_CTX = keccak_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct keccak_st {
    pub A: [[uint64_t; 5]; 5],
    pub block_size: size_t,
    pub md_size: size_t,
    pub buf_load: size_t,
    pub buf: [uint8_t; 168],
    pub pad: uint8_t,
    pub state: uint8_t,
}
unsafe extern "C" fn ml_dsa_params_init(mut params: *mut ml_dsa_params, mut k: size_t) {
    if k == 2 as libc::c_int as size_t || k == 3 as libc::c_int as size_t
        || k == 5 as libc::c_int as size_t
    {} else {
        __assert_fail(
            b"(k == 2) || (k == 3) || (k == 5)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ml_dsa/./ml_dsa_ref/params.c\0"
                as *const u8 as *const libc::c_char,
            7 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 49],
                &[libc::c_char; 49],
            >(b"void ml_dsa_params_init(ml_dsa_params *, size_t)\0"))
                .as_ptr(),
        );
    }
    'c_16832: {
        if k == 2 as libc::c_int as size_t || k == 3 as libc::c_int as size_t
            || k == 5 as libc::c_int as size_t
        {} else {
            __assert_fail(
                b"(k == 2) || (k == 3) || (k == 5)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ml_dsa/./ml_dsa_ref/params.c\0"
                    as *const u8 as *const libc::c_char,
                7 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 49],
                    &[libc::c_char; 49],
                >(b"void ml_dsa_params_init(ml_dsa_params *, size_t)\0"))
                    .as_ptr(),
            );
        }
    };
    if k == 2 as libc::c_int as size_t {
        (*params).k = 4 as libc::c_int as uint8_t;
        (*params).l = 4 as libc::c_int as uint8_t;
        (*params).tau = 39 as libc::c_int as size_t;
        (*params).beta = 78 as libc::c_int as size_t;
        (*params).omega = 80 as libc::c_int as size_t;
        (*params).c_tilde_bytes = 32 as libc::c_int as size_t;
        (*params).gamma1 = ((1 as libc::c_int) << 17 as libc::c_int) as size_t;
        (*params)
            .gamma2 = (8380417 as libc::c_int - 1 as libc::c_int) / 88 as libc::c_int;
        (*params).eta = 2 as libc::c_int as size_t;
        (*params).poly_z_packed_bytes = 576 as libc::c_int as size_t;
        (*params).poly_w1_packed_bytes = 192 as libc::c_int as size_t;
        (*params).poly_eta_packed_bytes = 96 as libc::c_int as size_t;
        (*params)
            .poly_vech_packed_bytes = ((*params).omega)
            .wrapping_add((*params).k as size_t);
        (*params)
            .public_key_bytes = (32 as libc::c_int
            + (*params).k as libc::c_int * 320 as libc::c_int) as size_t;
        (*params)
            .secret_key_bytes = ((2 as libc::c_int * 32 as libc::c_int
            + 64 as libc::c_int) as size_t)
            .wrapping_add((*params).l as size_t * (*params).poly_eta_packed_bytes)
            .wrapping_add((*params).k as size_t * (*params).poly_eta_packed_bytes)
            .wrapping_add(((*params).k as libc::c_int * 416 as libc::c_int) as size_t);
        (*params)
            .bytes = ((*params).c_tilde_bytes)
            .wrapping_add((*params).l as size_t * (*params).poly_z_packed_bytes)
            .wrapping_add((*params).poly_vech_packed_bytes);
    } else if k == 3 as libc::c_int as size_t {
        (*params).k = 6 as libc::c_int as uint8_t;
        (*params).l = 5 as libc::c_int as uint8_t;
        (*params).tau = 49 as libc::c_int as size_t;
        (*params).beta = 196 as libc::c_int as size_t;
        (*params).omega = 55 as libc::c_int as size_t;
        (*params).c_tilde_bytes = 48 as libc::c_int as size_t;
        (*params).gamma1 = ((1 as libc::c_int) << 19 as libc::c_int) as size_t;
        (*params)
            .gamma2 = (8380417 as libc::c_int - 1 as libc::c_int) / 32 as libc::c_int;
        (*params).eta = 4 as libc::c_int as size_t;
        (*params).poly_z_packed_bytes = 640 as libc::c_int as size_t;
        (*params).poly_w1_packed_bytes = 128 as libc::c_int as size_t;
        (*params).poly_eta_packed_bytes = 128 as libc::c_int as size_t;
        (*params)
            .poly_vech_packed_bytes = ((*params).omega)
            .wrapping_add((*params).k as size_t);
        (*params)
            .public_key_bytes = (32 as libc::c_int
            + (*params).k as libc::c_int * 320 as libc::c_int) as size_t;
        (*params)
            .secret_key_bytes = ((2 as libc::c_int * 32 as libc::c_int
            + 64 as libc::c_int) as size_t)
            .wrapping_add((*params).l as size_t * (*params).poly_eta_packed_bytes)
            .wrapping_add((*params).k as size_t * (*params).poly_eta_packed_bytes)
            .wrapping_add(((*params).k as libc::c_int * 416 as libc::c_int) as size_t);
        (*params)
            .bytes = ((*params).c_tilde_bytes)
            .wrapping_add((*params).l as size_t * (*params).poly_z_packed_bytes)
            .wrapping_add((*params).poly_vech_packed_bytes);
    } else {
        (*params).k = 8 as libc::c_int as uint8_t;
        (*params).l = 7 as libc::c_int as uint8_t;
        (*params).tau = 60 as libc::c_int as size_t;
        (*params).beta = 120 as libc::c_int as size_t;
        (*params).omega = 75 as libc::c_int as size_t;
        (*params).c_tilde_bytes = 64 as libc::c_int as size_t;
        (*params).gamma1 = ((1 as libc::c_int) << 19 as libc::c_int) as size_t;
        (*params)
            .gamma2 = (8380417 as libc::c_int - 1 as libc::c_int) / 32 as libc::c_int;
        (*params).eta = 2 as libc::c_int as size_t;
        (*params).poly_z_packed_bytes = 640 as libc::c_int as size_t;
        (*params).poly_w1_packed_bytes = 128 as libc::c_int as size_t;
        (*params).poly_eta_packed_bytes = 96 as libc::c_int as size_t;
        (*params)
            .poly_vech_packed_bytes = ((*params).omega)
            .wrapping_add((*params).k as size_t);
        (*params)
            .public_key_bytes = (32 as libc::c_int
            + (*params).k as libc::c_int * 320 as libc::c_int) as size_t;
        (*params)
            .secret_key_bytes = ((2 as libc::c_int * 32 as libc::c_int
            + 64 as libc::c_int) as size_t)
            .wrapping_add((*params).l as size_t * (*params).poly_eta_packed_bytes)
            .wrapping_add((*params).k as size_t * (*params).poly_eta_packed_bytes)
            .wrapping_add(((*params).k as libc::c_int * 416 as libc::c_int) as size_t);
        (*params)
            .bytes = ((*params).c_tilde_bytes)
            .wrapping_add((*params).l as size_t * (*params).poly_z_packed_bytes)
            .wrapping_add((*params).poly_vech_packed_bytes);
    };
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_44_params_init(mut params: *mut ml_dsa_params) {
    ml_dsa_params_init(params, 2 as libc::c_int as size_t);
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_65_params_init(mut params: *mut ml_dsa_params) {
    ml_dsa_params_init(params, 3 as libc::c_int as size_t);
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_87_params_init(mut params: *mut ml_dsa_params) {
    ml_dsa_params_init(params, 5 as libc::c_int as size_t);
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_keypair_internal(
    mut params: *mut ml_dsa_params,
    mut pk: *mut uint8_t,
    mut sk: *mut uint8_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    let mut seedbuf: [uint8_t; 128] = [0; 128];
    let mut tr: [uint8_t; 64] = [0; 64];
    let mut rho: *const uint8_t = 0 as *const uint8_t;
    let mut rhoprime: *const uint8_t = 0 as *const uint8_t;
    let mut key: *const uint8_t = 0 as *const uint8_t;
    let mut mat: [polyvecl; 8] = [polyvecl {
        vec: [ml_dsa_poly { coeffs: [0; 256] }; 7],
    }; 8];
    let mut s1: polyvecl = {
        let mut init = polyvecl {
            vec: [
                {
                    let mut init = ml_dsa_poly {
                        coeffs: [
                            0 as libc::c_int,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                        ],
                    };
                    init
                },
                ml_dsa_poly { coeffs: [0; 256] },
                ml_dsa_poly { coeffs: [0; 256] },
                ml_dsa_poly { coeffs: [0; 256] },
                ml_dsa_poly { coeffs: [0; 256] },
                ml_dsa_poly { coeffs: [0; 256] },
                ml_dsa_poly { coeffs: [0; 256] },
            ],
        };
        init
    };
    let mut s1hat: polyvecl = polyvecl {
        vec: [ml_dsa_poly { coeffs: [0; 256] }; 7],
    };
    let mut s2: polyveck = polyveck {
        vec: [ml_dsa_poly { coeffs: [0; 256] }; 8],
    };
    let mut t1: polyveck = polyveck {
        vec: [ml_dsa_poly { coeffs: [0; 256] }; 8],
    };
    let mut t0: polyveck = polyveck {
        vec: [ml_dsa_poly { coeffs: [0; 256] }; 8],
    };
    OPENSSL_memcpy(
        seedbuf.as_mut_ptr() as *mut libc::c_void,
        seed as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
    seedbuf[(32 as libc::c_int + 0 as libc::c_int) as usize] = (*params).k;
    seedbuf[(32 as libc::c_int + 1 as libc::c_int) as usize] = (*params).l;
    SHAKE256(
        seedbuf.as_mut_ptr(),
        (32 as libc::c_int + 2 as libc::c_int) as size_t,
        seedbuf.as_mut_ptr(),
        (2 as libc::c_int * 32 as libc::c_int + 64 as libc::c_int) as size_t,
    );
    rho = seedbuf.as_mut_ptr();
    rhoprime = rho.offset(32 as libc::c_int as isize);
    key = rhoprime.offset(64 as libc::c_int as isize);
    ml_dsa_polyvec_matrix_expand(params, mat.as_mut_ptr(), rho);
    ml_dsa_polyvecl_uniform_eta(params, &mut s1, rhoprime, 0 as libc::c_int as uint16_t);
    ml_dsa_polyveck_uniform_eta(params, &mut s2, rhoprime, (*params).l as uint16_t);
    s1hat = s1;
    ml_dsa_polyvecl_ntt(params, &mut s1hat);
    ml_dsa_polyvec_matrix_pointwise_montgomery(
        params,
        &mut t1,
        mat.as_mut_ptr(),
        &mut s1hat,
    );
    ml_dsa_polyveck_reduce(params, &mut t1);
    ml_dsa_polyveck_invntt_tomont(params, &mut t1);
    ml_dsa_polyveck_add(params, &mut t1, &mut t1, &mut s2);
    ml_dsa_polyveck_caddq(params, &mut t1);
    ml_dsa_polyveck_power2round(params, &mut t1, &mut t0, &mut t1);
    ml_dsa_pack_pk(params, pk, rho, &mut t1);
    SHAKE256(
        pk,
        (*params).public_key_bytes,
        tr.as_mut_ptr(),
        64 as libc::c_int as size_t,
    );
    ml_dsa_pack_sk(
        params,
        sk,
        rho,
        tr.as_mut_ptr() as *const uint8_t,
        key,
        &mut t0,
        &mut s1,
        &mut s2,
    );
    OPENSSL_cleanse(
        seedbuf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 128]>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        tr.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        mat.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[polyvecl; 8]>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut s1 as *mut polyvecl as *mut libc::c_void,
        ::core::mem::size_of::<polyvecl>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut s1hat as *mut polyvecl as *mut libc::c_void,
        ::core::mem::size_of::<polyvecl>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut s2 as *mut polyveck as *mut libc::c_void,
        ::core::mem::size_of::<polyveck>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut t1 as *mut polyveck as *mut libc::c_void,
        ::core::mem::size_of::<polyveck>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut t0 as *mut polyveck as *mut libc::c_void,
        ::core::mem::size_of::<polyveck>() as libc::c_ulong,
    );
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_keypair(
    mut params: *mut ml_dsa_params,
    mut pk: *mut uint8_t,
    mut sk: *mut uint8_t,
    mut seed: *mut uint8_t,
) -> libc::c_int {
    if RAND_bytes(seed, 32 as libc::c_int as size_t) == 0 {
        return -(1 as libc::c_int);
    }
    let mut result: libc::c_int = ml_dsa_keypair_internal(params, pk, sk, seed);
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_sign_internal(
    mut params: *mut ml_dsa_params,
    mut sig: *mut uint8_t,
    mut siglen: *mut size_t,
    mut m: *const uint8_t,
    mut mlen: size_t,
    mut pre: *const uint8_t,
    mut prelen: size_t,
    mut rnd: *const uint8_t,
    mut sk: *const uint8_t,
    mut external_mu: libc::c_int,
) -> libc::c_int {
    let mut n: libc::c_uint = 0;
    let mut seedbuf: [uint8_t; 256] = [0; 256];
    let mut rho: *mut uint8_t = 0 as *mut uint8_t;
    let mut tr: *mut uint8_t = 0 as *mut uint8_t;
    let mut key: *mut uint8_t = 0 as *mut uint8_t;
    let mut mu: *mut uint8_t = 0 as *mut uint8_t;
    let mut rhoprime: *mut uint8_t = 0 as *mut uint8_t;
    let mut nonce: uint16_t = 0 as libc::c_int as uint16_t;
    let mut mat: [polyvecl; 8] = [polyvecl {
        vec: [ml_dsa_poly { coeffs: [0; 256] }; 7],
    }; 8];
    let mut s1: polyvecl = polyvecl {
        vec: [ml_dsa_poly { coeffs: [0; 256] }; 7],
    };
    let mut y: polyvecl = polyvecl {
        vec: [ml_dsa_poly { coeffs: [0; 256] }; 7],
    };
    let mut z: polyvecl = polyvecl {
        vec: [ml_dsa_poly { coeffs: [0; 256] }; 7],
    };
    let mut t0: polyveck = polyveck {
        vec: [ml_dsa_poly { coeffs: [0; 256] }; 8],
    };
    let mut s2: polyveck = polyveck {
        vec: [ml_dsa_poly { coeffs: [0; 256] }; 8],
    };
    let mut w1: polyveck = polyveck {
        vec: [ml_dsa_poly { coeffs: [0; 256] }; 8],
    };
    let mut w0: polyveck = polyveck {
        vec: [ml_dsa_poly { coeffs: [0; 256] }; 8],
    };
    let mut h: polyveck = polyveck {
        vec: [ml_dsa_poly { coeffs: [0; 256] }; 8],
    };
    let mut cp: ml_dsa_poly = ml_dsa_poly { coeffs: [0; 256] };
    let mut state: KECCAK1600_CTX = keccak_st {
        A: [[0; 5]; 5],
        block_size: 0,
        md_size: 0,
        buf_load: 0,
        buf: [0; 168],
        pad: 0,
        state: 0,
    };
    rho = seedbuf.as_mut_ptr();
    tr = rho.offset(32 as libc::c_int as isize);
    key = tr.offset(64 as libc::c_int as isize);
    mu = key.offset(32 as libc::c_int as isize);
    rhoprime = mu.offset(64 as libc::c_int as isize);
    ml_dsa_unpack_sk(params, rho, tr, key, &mut t0, &mut s1, &mut s2, sk);
    if external_mu == 0 {
        SHAKE_Init(
            &mut state,
            ((1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
                / 8 as libc::c_int) as size_t,
        );
        SHAKE_Absorb(&mut state, tr as *const libc::c_void, 64 as libc::c_int as size_t);
        SHAKE_Absorb(&mut state, pre as *const libc::c_void, prelen);
        SHAKE_Absorb(&mut state, m as *const libc::c_void, mlen);
        SHAKE_Final(mu, &mut state, 64 as libc::c_int as size_t);
    } else {
        OPENSSL_memcpy(mu as *mut libc::c_void, m as *const libc::c_void, mlen);
    }
    SHAKE_Init(
        &mut state,
        ((1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
            / 8 as libc::c_int) as size_t,
    );
    SHAKE_Absorb(&mut state, key as *const libc::c_void, 32 as libc::c_int as size_t);
    SHAKE_Absorb(&mut state, rnd as *const libc::c_void, 32 as libc::c_int as size_t);
    SHAKE_Absorb(&mut state, mu as *const libc::c_void, 64 as libc::c_int as size_t);
    SHAKE_Final(rhoprime, &mut state, 64 as libc::c_int as size_t);
    ml_dsa_polyvec_matrix_expand(params, mat.as_mut_ptr(), rho as *const uint8_t);
    ml_dsa_polyvecl_ntt(params, &mut s1);
    ml_dsa_polyveck_ntt(params, &mut s2);
    ml_dsa_polyveck_ntt(params, &mut t0);
    loop {
        let fresh0 = nonce;
        nonce = nonce.wrapping_add(1);
        ml_dsa_polyvecl_uniform_gamma1(
            params,
            &mut y,
            rhoprime as *const uint8_t,
            fresh0,
        );
        z = y;
        ml_dsa_polyvecl_ntt(params, &mut z);
        ml_dsa_polyvec_matrix_pointwise_montgomery(
            params,
            &mut w1,
            mat.as_mut_ptr(),
            &mut z,
        );
        ml_dsa_polyveck_reduce(params, &mut w1);
        ml_dsa_polyveck_invntt_tomont(params, &mut w1);
        ml_dsa_polyveck_caddq(params, &mut w1);
        ml_dsa_polyveck_decompose(params, &mut w1, &mut w0, &mut w1);
        ml_dsa_polyveck_pack_w1(params, sig, &mut w1);
        SHAKE_Init(
            &mut state,
            ((1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
                / 8 as libc::c_int) as size_t,
        );
        SHAKE_Absorb(&mut state, mu as *const libc::c_void, 64 as libc::c_int as size_t);
        SHAKE_Absorb(
            &mut state,
            sig as *const libc::c_void,
            (*params).k as size_t * (*params).poly_w1_packed_bytes,
        );
        SHAKE_Final(sig, &mut state, (*params).c_tilde_bytes);
        ml_dsa_poly_challenge(params, &mut cp, sig);
        ml_dsa_poly_ntt(&mut cp);
        ml_dsa_polyvecl_pointwise_poly_montgomery(params, &mut z, &mut cp, &mut s1);
        ml_dsa_polyvecl_invntt_tomont(params, &mut z);
        ml_dsa_polyvecl_add(params, &mut z, &mut z, &mut y);
        ml_dsa_polyvecl_reduce(params, &mut z);
        if ml_dsa_polyvecl_chknorm(
            params,
            &mut z,
            ((*params).gamma1).wrapping_sub((*params).beta) as int32_t,
        ) != 0
        {
            continue;
        }
        ml_dsa_polyveck_pointwise_poly_montgomery(params, &mut h, &mut cp, &mut s2);
        ml_dsa_polyveck_invntt_tomont(params, &mut h);
        ml_dsa_polyveck_sub(params, &mut w0, &mut w0, &mut h);
        ml_dsa_polyveck_reduce(params, &mut w0);
        if ml_dsa_polyveck_chknorm(
            params,
            &mut w0,
            ((*params).gamma2 as size_t).wrapping_sub((*params).beta) as int32_t,
        ) != 0
        {
            continue;
        }
        ml_dsa_polyveck_pointwise_poly_montgomery(params, &mut h, &mut cp, &mut t0);
        ml_dsa_polyveck_invntt_tomont(params, &mut h);
        ml_dsa_polyveck_reduce(params, &mut h);
        if ml_dsa_polyveck_chknorm(params, &mut h, (*params).gamma2) != 0 {
            continue;
        }
        ml_dsa_polyveck_add(params, &mut w0, &mut w0, &mut h);
        n = ml_dsa_polyveck_make_hint(params, &mut h, &mut w0, &mut w1);
        if !(n as size_t > (*params).omega) {
            break;
        }
    }
    ml_dsa_pack_sig(params, sig, sig, &mut z, &mut h);
    *siglen = (*params).bytes;
    OPENSSL_cleanse(
        seedbuf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 256]>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut nonce as *mut uint16_t as *mut libc::c_void,
        ::core::mem::size_of::<uint16_t>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        mat.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[polyvecl; 8]>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut s1 as *mut polyvecl as *mut libc::c_void,
        ::core::mem::size_of::<polyvecl>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut y as *mut polyvecl as *mut libc::c_void,
        ::core::mem::size_of::<polyvecl>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut z as *mut polyvecl as *mut libc::c_void,
        ::core::mem::size_of::<polyvecl>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut t0 as *mut polyveck as *mut libc::c_void,
        ::core::mem::size_of::<polyveck>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut s2 as *mut polyveck as *mut libc::c_void,
        ::core::mem::size_of::<polyveck>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut w1 as *mut polyveck as *mut libc::c_void,
        ::core::mem::size_of::<polyveck>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut w0 as *mut polyveck as *mut libc::c_void,
        ::core::mem::size_of::<polyveck>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut h as *mut polyveck as *mut libc::c_void,
        ::core::mem::size_of::<polyveck>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut cp as *mut ml_dsa_poly as *mut libc::c_void,
        ::core::mem::size_of::<ml_dsa_poly>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut state as *mut KECCAK1600_CTX as *mut libc::c_void,
        ::core::mem::size_of::<KECCAK1600_CTX>() as libc::c_ulong,
    );
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_sign(
    mut params: *mut ml_dsa_params,
    mut sig: *mut uint8_t,
    mut siglen: *mut size_t,
    mut m: *const uint8_t,
    mut mlen: size_t,
    mut ctx: *const uint8_t,
    mut ctxlen: size_t,
    mut sk: *const uint8_t,
) -> libc::c_int {
    let mut pre: [uint8_t; 257] = [0; 257];
    let mut rnd: [uint8_t; 32] = [0; 32];
    if ctxlen > 255 as libc::c_int as size_t {
        return -(1 as libc::c_int);
    }
    pre[0 as libc::c_int as usize] = 0 as libc::c_int as uint8_t;
    pre[1 as libc::c_int as usize] = ctxlen as uint8_t;
    OPENSSL_memcpy(
        pre.as_mut_ptr().offset(2 as libc::c_int as isize) as *mut libc::c_void,
        ctx as *const libc::c_void,
        ctxlen,
    );
    if RAND_bytes(rnd.as_mut_ptr(), 32 as libc::c_int as size_t) == 0 {
        return -(1 as libc::c_int);
    }
    ml_dsa_sign_internal(
        params,
        sig,
        siglen,
        m,
        mlen,
        pre.as_mut_ptr(),
        (2 as libc::c_int as size_t).wrapping_add(ctxlen),
        rnd.as_mut_ptr(),
        sk,
        0 as libc::c_int,
    );
    OPENSSL_cleanse(
        pre.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 257]>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        rnd.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
    );
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_extmu_sign(
    mut params: *mut ml_dsa_params,
    mut sig: *mut uint8_t,
    mut siglen: *mut size_t,
    mut mu: *const uint8_t,
    mut mulen: size_t,
    mut sk: *const uint8_t,
) -> libc::c_int {
    let mut rnd: [uint8_t; 32] = [0; 32];
    if RAND_bytes(rnd.as_mut_ptr(), 32 as libc::c_int as size_t) == 0 {
        return -(1 as libc::c_int);
    }
    ml_dsa_sign_internal(
        params,
        sig,
        siglen,
        mu,
        mulen,
        0 as *const uint8_t,
        0 as libc::c_int as size_t,
        rnd.as_mut_ptr(),
        sk,
        1 as libc::c_int,
    );
    OPENSSL_cleanse(
        rnd.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
    );
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_sign_message(
    mut params: *mut ml_dsa_params,
    mut sm: *mut uint8_t,
    mut smlen: *mut size_t,
    mut m: *const uint8_t,
    mut mlen: size_t,
    mut ctx: *const uint8_t,
    mut ctxlen: size_t,
    mut sk: *const uint8_t,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < mlen {
        *sm
            .offset(
                ((*params).bytes)
                    .wrapping_add(mlen)
                    .wrapping_sub(1 as libc::c_int as size_t)
                    .wrapping_sub(i) as isize,
            ) = *m
            .offset(
                mlen.wrapping_sub(1 as libc::c_int as size_t).wrapping_sub(i) as isize,
            );
        i = i.wrapping_add(1);
        i;
    }
    ret = ml_dsa_sign(
        params,
        sm,
        smlen,
        sm.offset((*params).bytes as isize),
        mlen,
        ctx,
        ctxlen,
        sk,
    );
    *smlen = (*smlen).wrapping_add(mlen);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_verify_internal(
    mut params: *mut ml_dsa_params,
    mut sig: *const uint8_t,
    mut siglen: size_t,
    mut m: *const uint8_t,
    mut mlen: size_t,
    mut pre: *const uint8_t,
    mut prelen: size_t,
    mut pk: *const uint8_t,
    mut external_mu: libc::c_int,
) -> libc::c_int {
    let mut i: libc::c_uint = 0;
    let mut buf: [uint8_t; 1536] = [0; 1536];
    let mut rho: [uint8_t; 32] = [0; 32];
    let mut mu: [uint8_t; 64] = [0; 64];
    let mut tr: [uint8_t; 64] = [0; 64];
    let mut c: [uint8_t; 64] = [0; 64];
    let mut c2: [uint8_t; 64] = [0; 64];
    let mut cp: ml_dsa_poly = ml_dsa_poly { coeffs: [0; 256] };
    let mut mat: [polyvecl; 8] = [polyvecl {
        vec: [ml_dsa_poly { coeffs: [0; 256] }; 7],
    }; 8];
    let mut z: polyvecl = polyvecl {
        vec: [ml_dsa_poly { coeffs: [0; 256] }; 7],
    };
    let mut t1: polyveck = polyveck {
        vec: [ml_dsa_poly { coeffs: [0; 256] }; 8],
    };
    let mut w1: polyveck = polyveck {
        vec: [ml_dsa_poly { coeffs: [0; 256] }; 8],
    };
    let mut h: polyveck = polyveck {
        vec: [ml_dsa_poly { coeffs: [0; 256] }; 8],
    };
    let mut state: KECCAK1600_CTX = keccak_st {
        A: [[0; 5]; 5],
        block_size: 0,
        md_size: 0,
        buf_load: 0,
        buf: [0; 168],
        pad: 0,
        state: 0,
    };
    if siglen != (*params).bytes {
        return -(1 as libc::c_int);
    }
    ml_dsa_unpack_pk(params, rho.as_mut_ptr(), &mut t1, pk);
    if ml_dsa_unpack_sig(params, c.as_mut_ptr(), &mut z, &mut h, sig) != 0 {
        return -(1 as libc::c_int);
    }
    if ml_dsa_polyvecl_chknorm(
        params,
        &mut z,
        ((*params).gamma1).wrapping_sub((*params).beta) as int32_t,
    ) != 0
    {
        return -(1 as libc::c_int);
    }
    if external_mu == 0 {
        SHAKE256(
            pk,
            (*params).public_key_bytes,
            tr.as_mut_ptr(),
            64 as libc::c_int as size_t,
        );
        SHAKE_Init(
            &mut state,
            ((1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
                / 8 as libc::c_int) as size_t,
        );
        SHAKE_Absorb(
            &mut state,
            tr.as_mut_ptr() as *const libc::c_void,
            64 as libc::c_int as size_t,
        );
        SHAKE_Absorb(&mut state, pre as *const libc::c_void, prelen);
        SHAKE_Absorb(&mut state, m as *const libc::c_void, mlen);
        SHAKE_Final(mu.as_mut_ptr(), &mut state, 64 as libc::c_int as size_t);
    } else {
        OPENSSL_memcpy(
            mu.as_mut_ptr() as *mut libc::c_void,
            m as *const libc::c_void,
            mlen,
        );
    }
    ml_dsa_poly_challenge(params, &mut cp, c.as_mut_ptr());
    ml_dsa_polyvec_matrix_expand(
        params,
        mat.as_mut_ptr(),
        rho.as_mut_ptr() as *const uint8_t,
    );
    ml_dsa_polyvecl_ntt(params, &mut z);
    ml_dsa_polyvec_matrix_pointwise_montgomery(
        params,
        &mut w1,
        mat.as_mut_ptr(),
        &mut z,
    );
    ml_dsa_poly_ntt(&mut cp);
    ml_dsa_polyveck_shiftl(params, &mut t1);
    ml_dsa_polyveck_ntt(params, &mut t1);
    ml_dsa_polyveck_pointwise_poly_montgomery(params, &mut t1, &mut cp, &mut t1);
    ml_dsa_polyveck_sub(params, &mut w1, &mut w1, &mut t1);
    ml_dsa_polyveck_reduce(params, &mut w1);
    ml_dsa_polyveck_invntt_tomont(params, &mut w1);
    ml_dsa_polyveck_caddq(params, &mut w1);
    ml_dsa_polyveck_use_hint(params, &mut w1, &mut w1, &mut h);
    ml_dsa_polyveck_pack_w1(params, buf.as_mut_ptr(), &mut w1);
    SHAKE_Init(
        &mut state,
        ((1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
            / 8 as libc::c_int) as size_t,
    );
    SHAKE_Absorb(
        &mut state,
        mu.as_mut_ptr() as *const libc::c_void,
        64 as libc::c_int as size_t,
    );
    SHAKE_Absorb(
        &mut state,
        buf.as_mut_ptr() as *const libc::c_void,
        (*params).k as size_t * (*params).poly_w1_packed_bytes,
    );
    SHAKE_Final(c2.as_mut_ptr(), &mut state, (*params).c_tilde_bytes);
    i = 0 as libc::c_int as libc::c_uint;
    while (i as size_t) < (*params).c_tilde_bytes {
        if c[i as usize] as libc::c_int != c2[i as usize] as libc::c_int {
            return -(1 as libc::c_int);
        }
        i = i.wrapping_add(1);
        i;
    }
    OPENSSL_cleanse(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 1536]>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        rho.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        mu.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        tr.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        c.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        c2.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut cp as *mut ml_dsa_poly as *mut libc::c_void,
        ::core::mem::size_of::<ml_dsa_poly>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        mat.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[polyvecl; 8]>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut z as *mut polyvecl as *mut libc::c_void,
        ::core::mem::size_of::<polyvecl>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut t1 as *mut polyveck as *mut libc::c_void,
        ::core::mem::size_of::<polyveck>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut w1 as *mut polyveck as *mut libc::c_void,
        ::core::mem::size_of::<polyveck>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut h as *mut polyveck as *mut libc::c_void,
        ::core::mem::size_of::<polyveck>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut state as *mut KECCAK1600_CTX as *mut libc::c_void,
        ::core::mem::size_of::<KECCAK1600_CTX>() as libc::c_ulong,
    );
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_verify(
    mut params: *mut ml_dsa_params,
    mut sig: *const uint8_t,
    mut siglen: size_t,
    mut m: *const uint8_t,
    mut mlen: size_t,
    mut ctx: *const uint8_t,
    mut ctxlen: size_t,
    mut pk: *const uint8_t,
) -> libc::c_int {
    let mut pre: [uint8_t; 257] = [0; 257];
    if ctxlen > 255 as libc::c_int as size_t {
        return -(1 as libc::c_int);
    }
    pre[0 as libc::c_int as usize] = 0 as libc::c_int as uint8_t;
    pre[1 as libc::c_int as usize] = ctxlen as uint8_t;
    OPENSSL_memcpy(
        pre.as_mut_ptr().offset(2 as libc::c_int as isize) as *mut libc::c_void,
        ctx as *const libc::c_void,
        ctxlen,
    );
    return ml_dsa_verify_internal(
        params,
        sig,
        siglen,
        m,
        mlen,
        pre.as_mut_ptr(),
        (2 as libc::c_int as size_t).wrapping_add(ctxlen),
        pk,
        0 as libc::c_int,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_verify_message(
    mut params: *mut ml_dsa_params,
    mut m: *mut uint8_t,
    mut mlen: *mut size_t,
    mut sm: *const uint8_t,
    mut smlen: size_t,
    mut ctx: *const uint8_t,
    mut ctxlen: size_t,
    mut pk: *const uint8_t,
) -> libc::c_int {
    if !(smlen < (*params).bytes) {
        *mlen = smlen.wrapping_sub((*params).bytes);
        if !(ml_dsa_verify(
            params,
            sm,
            (*params).bytes,
            sm.offset((*params).bytes as isize),
            *mlen,
            ctx,
            ctxlen,
            pk,
        ) != 0)
        {
            let mut i: size_t = 0 as libc::c_int as size_t;
            while i < *mlen {
                *m
                    .offset(
                        i as isize,
                    ) = *sm.offset(((*params).bytes).wrapping_add(i) as isize);
                i = i.wrapping_add(1);
                i;
            }
            return 0 as libc::c_int;
        }
    }
    *mlen = 0 as libc::c_int as size_t;
    let mut i_0: size_t = 0 as libc::c_int as size_t;
    while i_0 < smlen {
        *m.offset(i_0 as isize) = 0 as libc::c_int as uint8_t;
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
    return -(1 as libc::c_int);
}
static mut ml_dsa_zetas: [int32_t; 256] = [
    0 as libc::c_int,
    25847 as libc::c_int,
    -(2608894 as libc::c_int),
    -(518909 as libc::c_int),
    237124 as libc::c_int,
    -(777960 as libc::c_int),
    -(876248 as libc::c_int),
    466468 as libc::c_int,
    1826347 as libc::c_int,
    2353451 as libc::c_int,
    -(359251 as libc::c_int),
    -(2091905 as libc::c_int),
    3119733 as libc::c_int,
    -(2884855 as libc::c_int),
    3111497 as libc::c_int,
    2680103 as libc::c_int,
    2725464 as libc::c_int,
    1024112 as libc::c_int,
    -(1079900 as libc::c_int),
    3585928 as libc::c_int,
    -(549488 as libc::c_int),
    -(1119584 as libc::c_int),
    2619752 as libc::c_int,
    -(2108549 as libc::c_int),
    -(2118186 as libc::c_int),
    -(3859737 as libc::c_int),
    -(1399561 as libc::c_int),
    -(3277672 as libc::c_int),
    1757237 as libc::c_int,
    -(19422 as libc::c_int),
    4010497 as libc::c_int,
    280005 as libc::c_int,
    2706023 as libc::c_int,
    95776 as libc::c_int,
    3077325 as libc::c_int,
    3530437 as libc::c_int,
    -(1661693 as libc::c_int),
    -(3592148 as libc::c_int),
    -(2537516 as libc::c_int),
    3915439 as libc::c_int,
    -(3861115 as libc::c_int),
    -(3043716 as libc::c_int),
    3574422 as libc::c_int,
    -(2867647 as libc::c_int),
    3539968 as libc::c_int,
    -(300467 as libc::c_int),
    2348700 as libc::c_int,
    -(539299 as libc::c_int),
    -(1699267 as libc::c_int),
    -(1643818 as libc::c_int),
    3505694 as libc::c_int,
    -(3821735 as libc::c_int),
    3507263 as libc::c_int,
    -(2140649 as libc::c_int),
    -(1600420 as libc::c_int),
    3699596 as libc::c_int,
    811944 as libc::c_int,
    531354 as libc::c_int,
    954230 as libc::c_int,
    3881043 as libc::c_int,
    3900724 as libc::c_int,
    -(2556880 as libc::c_int),
    2071892 as libc::c_int,
    -(2797779 as libc::c_int),
    -(3930395 as libc::c_int),
    -(1528703 as libc::c_int),
    -(3677745 as libc::c_int),
    -(3041255 as libc::c_int),
    -(1452451 as libc::c_int),
    3475950 as libc::c_int,
    2176455 as libc::c_int,
    -(1585221 as libc::c_int),
    -(1257611 as libc::c_int),
    1939314 as libc::c_int,
    -(4083598 as libc::c_int),
    -(1000202 as libc::c_int),
    -(3190144 as libc::c_int),
    -(3157330 as libc::c_int),
    -(3632928 as libc::c_int),
    126922 as libc::c_int,
    3412210 as libc::c_int,
    -(983419 as libc::c_int),
    2147896 as libc::c_int,
    2715295 as libc::c_int,
    -(2967645 as libc::c_int),
    -(3693493 as libc::c_int),
    -(411027 as libc::c_int),
    -(2477047 as libc::c_int),
    -(671102 as libc::c_int),
    -(1228525 as libc::c_int),
    -(22981 as libc::c_int),
    -(1308169 as libc::c_int),
    -(381987 as libc::c_int),
    1349076 as libc::c_int,
    1852771 as libc::c_int,
    -(1430430 as libc::c_int),
    -(3343383 as libc::c_int),
    264944 as libc::c_int,
    508951 as libc::c_int,
    3097992 as libc::c_int,
    44288 as libc::c_int,
    -(1100098 as libc::c_int),
    904516 as libc::c_int,
    3958618 as libc::c_int,
    -(3724342 as libc::c_int),
    -(8578 as libc::c_int),
    1653064 as libc::c_int,
    -(3249728 as libc::c_int),
    2389356 as libc::c_int,
    -(210977 as libc::c_int),
    759969 as libc::c_int,
    -(1316856 as libc::c_int),
    189548 as libc::c_int,
    -(3553272 as libc::c_int),
    3159746 as libc::c_int,
    -(1851402 as libc::c_int),
    -(2409325 as libc::c_int),
    -(177440 as libc::c_int),
    1315589 as libc::c_int,
    1341330 as libc::c_int,
    1285669 as libc::c_int,
    -(1584928 as libc::c_int),
    -(812732 as libc::c_int),
    -(1439742 as libc::c_int),
    -(3019102 as libc::c_int),
    -(3881060 as libc::c_int),
    -(3628969 as libc::c_int),
    3839961 as libc::c_int,
    2091667 as libc::c_int,
    3407706 as libc::c_int,
    2316500 as libc::c_int,
    3817976 as libc::c_int,
    -(3342478 as libc::c_int),
    2244091 as libc::c_int,
    -(2446433 as libc::c_int),
    -(3562462 as libc::c_int),
    266997 as libc::c_int,
    2434439 as libc::c_int,
    -(1235728 as libc::c_int),
    3513181 as libc::c_int,
    -(3520352 as libc::c_int),
    -(3759364 as libc::c_int),
    -(1197226 as libc::c_int),
    -(3193378 as libc::c_int),
    900702 as libc::c_int,
    1859098 as libc::c_int,
    909542 as libc::c_int,
    819034 as libc::c_int,
    495491 as libc::c_int,
    -(1613174 as libc::c_int),
    -(43260 as libc::c_int),
    -(522500 as libc::c_int),
    -(655327 as libc::c_int),
    -(3122442 as libc::c_int),
    2031748 as libc::c_int,
    3207046 as libc::c_int,
    -(3556995 as libc::c_int),
    -(525098 as libc::c_int),
    -(768622 as libc::c_int),
    -(3595838 as libc::c_int),
    342297 as libc::c_int,
    286988 as libc::c_int,
    -(2437823 as libc::c_int),
    4108315 as libc::c_int,
    3437287 as libc::c_int,
    -(3342277 as libc::c_int),
    1735879 as libc::c_int,
    203044 as libc::c_int,
    2842341 as libc::c_int,
    2691481 as libc::c_int,
    -(2590150 as libc::c_int),
    1265009 as libc::c_int,
    4055324 as libc::c_int,
    1247620 as libc::c_int,
    2486353 as libc::c_int,
    1595974 as libc::c_int,
    -(3767016 as libc::c_int),
    1250494 as libc::c_int,
    2635921 as libc::c_int,
    -(3548272 as libc::c_int),
    -(2994039 as libc::c_int),
    1869119 as libc::c_int,
    1903435 as libc::c_int,
    -(1050970 as libc::c_int),
    -(1333058 as libc::c_int),
    1237275 as libc::c_int,
    -(3318210 as libc::c_int),
    -(1430225 as libc::c_int),
    -(451100 as libc::c_int),
    1312455 as libc::c_int,
    3306115 as libc::c_int,
    -(1962642 as libc::c_int),
    -(1279661 as libc::c_int),
    1917081 as libc::c_int,
    -(2546312 as libc::c_int),
    -(1374803 as libc::c_int),
    1500165 as libc::c_int,
    777191 as libc::c_int,
    2235880 as libc::c_int,
    3406031 as libc::c_int,
    -(542412 as libc::c_int),
    -(2831860 as libc::c_int),
    -(1671176 as libc::c_int),
    -(1846953 as libc::c_int),
    -(2584293 as libc::c_int),
    -(3724270 as libc::c_int),
    594136 as libc::c_int,
    -(3776993 as libc::c_int),
    -(2013608 as libc::c_int),
    2432395 as libc::c_int,
    2454455 as libc::c_int,
    -(164721 as libc::c_int),
    1957272 as libc::c_int,
    3369112 as libc::c_int,
    185531 as libc::c_int,
    -(1207385 as libc::c_int),
    -(3183426 as libc::c_int),
    162844 as libc::c_int,
    1616392 as libc::c_int,
    3014001 as libc::c_int,
    810149 as libc::c_int,
    1652634 as libc::c_int,
    -(3694233 as libc::c_int),
    -(1799107 as libc::c_int),
    -(3038916 as libc::c_int),
    3523897 as libc::c_int,
    3866901 as libc::c_int,
    269760 as libc::c_int,
    2213111 as libc::c_int,
    -(975884 as libc::c_int),
    1717735 as libc::c_int,
    472078 as libc::c_int,
    -(426683 as libc::c_int),
    1723600 as libc::c_int,
    -(1803090 as libc::c_int),
    1910376 as libc::c_int,
    -(1667432 as libc::c_int),
    -(1104333 as libc::c_int),
    -(260646 as libc::c_int),
    -(3833893 as libc::c_int),
    -(2939036 as libc::c_int),
    -(2235985 as libc::c_int),
    -(420899 as libc::c_int),
    -(2286327 as libc::c_int),
    183443 as libc::c_int,
    -(976891 as libc::c_int),
    1612842 as libc::c_int,
    -(3545687 as libc::c_int),
    -(554416 as libc::c_int),
    3919660 as libc::c_int,
    -(48306 as libc::c_int),
    -(1362209 as libc::c_int),
    3937738 as libc::c_int,
    1400424 as libc::c_int,
    -(846154 as libc::c_int),
    1976782 as libc::c_int,
];
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_ntt(mut a: *mut int32_t) {
    let mut len: libc::c_uint = 0;
    let mut start: libc::c_uint = 0;
    let mut j: libc::c_uint = 0;
    let mut k: libc::c_uint = 0;
    let mut zeta: int32_t = 0;
    let mut t: int32_t = 0;
    k = 0 as libc::c_int as libc::c_uint;
    len = 128 as libc::c_int as libc::c_uint;
    while len > 0 as libc::c_int as libc::c_uint {
        start = 0 as libc::c_int as libc::c_uint;
        while start < 256 as libc::c_int as libc::c_uint {
            k = k.wrapping_add(1);
            zeta = ml_dsa_zetas[k as usize];
            j = start;
            while j < start.wrapping_add(len) {
                t = ml_dsa_fqmul(zeta, *a.offset(j.wrapping_add(len) as isize))
                    as int32_t;
                *a.offset(j.wrapping_add(len) as isize) = *a.offset(j as isize) - t;
                *a.offset(j as isize) = *a.offset(j as isize) + t;
                j = j.wrapping_add(1);
                j;
            }
            start = j.wrapping_add(len);
        }
        len >>= 1 as libc::c_int;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_invntt_tomont(mut a: *mut int32_t) {
    let mut start: libc::c_uint = 0;
    let mut len: libc::c_uint = 0;
    let mut j: libc::c_uint = 0;
    let mut k: libc::c_uint = 0;
    let mut t: int32_t = 0;
    let mut zeta: int32_t = 0;
    let f: int32_t = 41978 as libc::c_int;
    k = 256 as libc::c_int as libc::c_uint;
    len = 1 as libc::c_int as libc::c_uint;
    while len < 256 as libc::c_int as libc::c_uint {
        start = 0 as libc::c_int as libc::c_uint;
        while start < 256 as libc::c_int as libc::c_uint {
            k = k.wrapping_sub(1);
            zeta = -ml_dsa_zetas[k as usize];
            j = start;
            while j < start.wrapping_add(len) {
                t = *a.offset(j as isize);
                *a.offset(j as isize) = t + *a.offset(j.wrapping_add(len) as isize);
                *a
                    .offset(
                        j.wrapping_add(len) as isize,
                    ) = t - *a.offset(j.wrapping_add(len) as isize);
                *a
                    .offset(
                        j.wrapping_add(len) as isize,
                    ) = ml_dsa_fqmul(zeta, *a.offset(j.wrapping_add(len) as isize))
                    as int32_t;
                j = j.wrapping_add(1);
                j;
            }
            start = j.wrapping_add(len);
        }
        len <<= 1 as libc::c_int;
    }
    j = 0 as libc::c_int as libc::c_uint;
    while j < 256 as libc::c_int as libc::c_uint {
        *a.offset(j as isize) = ml_dsa_fqmul(f, *a.offset(j as isize)) as int32_t;
        j = j.wrapping_add(1);
        j;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_fqmul(mut a: int32_t, mut b: int32_t) -> int64_t {
    let mut s: int64_t = 0;
    let mut t: int32_t = 0;
    s = a as int64_t * b as int64_t;
    t = (s as int32_t as int64_t * 58728449 as libc::c_int as int64_t) as int32_t;
    t = (s - t as int64_t * 8380417 as libc::c_int as int64_t >> 32 as libc::c_int)
        as int32_t;
    return t as int64_t;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_reduce32(mut a: int32_t) -> int32_t {
    let mut t: int32_t = 0;
    t = a + ((1 as libc::c_int) << 22 as libc::c_int) >> 23 as libc::c_int;
    t = a - t * 8380417 as libc::c_int;
    return t;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_caddq(mut a: int32_t) -> int32_t {
    a += a >> 31 as libc::c_int & 8380417 as libc::c_int;
    return a;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_freeze(mut a: int32_t) -> int32_t {
    a = ml_dsa_reduce32(a);
    a = ml_dsa_caddq(a);
    return a;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_poly_reduce(mut a: *mut ml_dsa_poly) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 256 as libc::c_int as libc::c_uint {
        (*a).coeffs[i as usize] = ml_dsa_reduce32((*a).coeffs[i as usize]);
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_poly_caddq(mut a: *mut ml_dsa_poly) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 256 as libc::c_int as libc::c_uint {
        (*a).coeffs[i as usize] = ml_dsa_caddq((*a).coeffs[i as usize]);
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_poly_add(
    mut c: *mut ml_dsa_poly,
    mut a: *const ml_dsa_poly,
    mut b: *const ml_dsa_poly,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 256 as libc::c_int as libc::c_uint {
        (*c).coeffs[i as usize] = (*a).coeffs[i as usize] + (*b).coeffs[i as usize];
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_poly_sub(
    mut c: *mut ml_dsa_poly,
    mut a: *const ml_dsa_poly,
    mut b: *const ml_dsa_poly,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 256 as libc::c_int as libc::c_uint {
        (*c).coeffs[i as usize] = (*a).coeffs[i as usize] - (*b).coeffs[i as usize];
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_poly_shiftl(mut a: *mut ml_dsa_poly) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 256 as libc::c_int as libc::c_uint {
        (*a).coeffs[i as usize] <<= 13 as libc::c_int;
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_poly_ntt(mut a: *mut ml_dsa_poly) {
    ml_dsa_ntt(((*a).coeffs).as_mut_ptr());
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_poly_invntt_tomont(mut a: *mut ml_dsa_poly) {
    ml_dsa_invntt_tomont(((*a).coeffs).as_mut_ptr());
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_poly_pointwise_montgomery(
    mut c: *mut ml_dsa_poly,
    mut a: *const ml_dsa_poly,
    mut b: *const ml_dsa_poly,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 256 as libc::c_int as libc::c_uint {
        (*c)
            .coeffs[i
            as usize] = ml_dsa_fqmul((*a).coeffs[i as usize], (*b).coeffs[i as usize])
            as int32_t;
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_poly_power2round(
    mut a1: *mut ml_dsa_poly,
    mut a0: *mut ml_dsa_poly,
    mut a: *const ml_dsa_poly,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 256 as libc::c_int as libc::c_uint {
        (*a1)
            .coeffs[i
            as usize] = ml_dsa_power2round(
            &mut *((*a0).coeffs).as_mut_ptr().offset(i as isize),
            (*a).coeffs[i as usize],
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_poly_decompose(
    mut params: *mut ml_dsa_params,
    mut a1: *mut ml_dsa_poly,
    mut a0: *mut ml_dsa_poly,
    mut a: *const ml_dsa_poly,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 256 as libc::c_int as libc::c_uint {
        (*a1)
            .coeffs[i
            as usize] = ml_dsa_decompose(
            params,
            &mut *((*a0).coeffs).as_mut_ptr().offset(i as isize),
            (*a).coeffs[i as usize],
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_poly_make_hint(
    mut params: *mut ml_dsa_params,
    mut h: *mut ml_dsa_poly,
    mut a0: *const ml_dsa_poly,
    mut a1: *const ml_dsa_poly,
) -> libc::c_uint {
    let mut i: libc::c_uint = 0;
    let mut s: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 256 as libc::c_int as libc::c_uint {
        (*h)
            .coeffs[i
            as usize] = ml_dsa_make_hint(
            params,
            (*a0).coeffs[i as usize],
            (*a1).coeffs[i as usize],
        ) as int32_t;
        s = s.wrapping_add((*h).coeffs[i as usize] as libc::c_uint);
        i = i.wrapping_add(1);
        i;
    }
    return s;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_poly_use_hint(
    mut params: *mut ml_dsa_params,
    mut b: *mut ml_dsa_poly,
    mut a: *const ml_dsa_poly,
    mut h: *const ml_dsa_poly,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 256 as libc::c_int as libc::c_uint {
        (*b)
            .coeffs[i
            as usize] = ml_dsa_use_hint(
            params,
            (*a).coeffs[i as usize],
            (*h).coeffs[i as usize] as libc::c_uint,
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_poly_chknorm(
    mut a: *const ml_dsa_poly,
    mut B: int32_t,
) -> libc::c_int {
    let mut i: libc::c_uint = 0;
    let mut t: int32_t = 0;
    if B > (8380417 as libc::c_int - 1 as libc::c_int) / 8 as libc::c_int {
        return 1 as libc::c_int;
    }
    i = 0 as libc::c_int as libc::c_uint;
    while i < 256 as libc::c_int as libc::c_uint {
        t = (*a).coeffs[i as usize] >> 31 as libc::c_int;
        t = (*a).coeffs[i as usize] - (t & 2 as libc::c_int * (*a).coeffs[i as usize]);
        if t >= B {
            return 1 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn ml_dsa_rej_uniform(
    mut a: *mut int32_t,
    mut len: libc::c_uint,
    mut buf: *const uint8_t,
    mut buflen: libc::c_uint,
) -> libc::c_uint {
    let mut ctr: libc::c_uint = 0;
    let mut pos: libc::c_uint = 0;
    let mut t: uint32_t = 0;
    pos = 0 as libc::c_int as libc::c_uint;
    ctr = pos;
    while ctr < len && pos.wrapping_add(3 as libc::c_int as libc::c_uint) <= buflen {
        let fresh1 = pos;
        pos = pos.wrapping_add(1);
        t = *buf.offset(fresh1 as isize) as uint32_t;
        let fresh2 = pos;
        pos = pos.wrapping_add(1);
        t |= (*buf.offset(fresh2 as isize) as uint32_t) << 8 as libc::c_int;
        let fresh3 = pos;
        pos = pos.wrapping_add(1);
        t |= (*buf.offset(fresh3 as isize) as uint32_t) << 16 as libc::c_int;
        t &= 0x7fffff as libc::c_int as uint32_t;
        if t < 8380417 as libc::c_int as uint32_t {
            let fresh4 = ctr;
            ctr = ctr.wrapping_add(1);
            *a.offset(fresh4 as isize) = t as int32_t;
        }
    }
    return ctr;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_poly_uniform(
    mut a: *mut ml_dsa_poly,
    mut seed: *const uint8_t,
    mut nonce: uint16_t,
) {
    let mut i: libc::c_uint = 0;
    let mut ctr: libc::c_uint = 0;
    let mut off: libc::c_uint = 0;
    let mut buflen: libc::c_uint = ((768 as libc::c_int
        + (1600 as libc::c_int - 128 as libc::c_int * 2 as libc::c_int)
            / 8 as libc::c_int - 1 as libc::c_int)
        / ((1600 as libc::c_int - 128 as libc::c_int * 2 as libc::c_int)
            / 8 as libc::c_int)
        * ((1600 as libc::c_int - 128 as libc::c_int * 2 as libc::c_int)
            / 8 as libc::c_int)) as libc::c_uint;
    let mut buf: [uint8_t; 842] = [0; 842];
    let mut state: KECCAK1600_CTX = keccak_st {
        A: [[0; 5]; 5],
        block_size: 0,
        md_size: 0,
        buf_load: 0,
        buf: [0; 168],
        pad: 0,
        state: 0,
    };
    let mut t: [uint8_t; 2] = [0; 2];
    t[0 as libc::c_int
        as usize] = (nonce as libc::c_int & 0xff as libc::c_int) as uint8_t;
    t[1 as libc::c_int as usize] = (nonce as libc::c_int >> 8 as libc::c_int) as uint8_t;
    SHAKE_Init(
        &mut state,
        ((1600 as libc::c_int - 128 as libc::c_int * 2 as libc::c_int)
            / 8 as libc::c_int) as size_t,
    );
    SHAKE_Absorb(&mut state, seed as *const libc::c_void, 32 as libc::c_int as size_t);
    SHAKE_Absorb(
        &mut state,
        t.as_mut_ptr() as *const libc::c_void,
        2 as libc::c_int as size_t,
    );
    SHAKE_Squeeze(
        buf.as_mut_ptr(),
        &mut state,
        ((768 as libc::c_int
            + (1600 as libc::c_int - 128 as libc::c_int * 2 as libc::c_int)
                / 8 as libc::c_int - 1 as libc::c_int)
            / ((1600 as libc::c_int - 128 as libc::c_int * 2 as libc::c_int)
                / 8 as libc::c_int)
            * ((1600 as libc::c_int - 128 as libc::c_int * 2 as libc::c_int)
                / 8 as libc::c_int)) as size_t,
    );
    ctr = ml_dsa_rej_uniform(
        ((*a).coeffs).as_mut_ptr(),
        256 as libc::c_int as libc::c_uint,
        buf.as_mut_ptr(),
        buflen,
    );
    while ctr < 256 as libc::c_int as libc::c_uint {
        off = buflen.wrapping_rem(3 as libc::c_int as libc::c_uint);
        i = 0 as libc::c_int as libc::c_uint;
        while i < off {
            buf[i as usize] = buf[buflen.wrapping_sub(off).wrapping_add(i) as usize];
            i = i.wrapping_add(1);
            i;
        }
        SHAKE_Squeeze(
            buf.as_mut_ptr().offset(off as isize),
            &mut state,
            ((768 as libc::c_int
                + (1600 as libc::c_int - 128 as libc::c_int * 2 as libc::c_int)
                    / 8 as libc::c_int - 1 as libc::c_int)
                / ((1600 as libc::c_int - 128 as libc::c_int * 2 as libc::c_int)
                    / 8 as libc::c_int)
                * ((1600 as libc::c_int - 128 as libc::c_int * 2 as libc::c_int)
                    / 8 as libc::c_int)) as size_t,
        );
        buflen = (((1600 as libc::c_int - 128 as libc::c_int * 2 as libc::c_int)
            / 8 as libc::c_int) as libc::c_uint)
            .wrapping_add(off);
        ctr = ctr
            .wrapping_add(
                ml_dsa_rej_uniform(
                    ((*a).coeffs).as_mut_ptr().offset(ctr as isize),
                    (256 as libc::c_int as libc::c_uint).wrapping_sub(ctr),
                    buf.as_mut_ptr(),
                    buflen,
                ),
            );
    }
    OPENSSL_cleanse(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 842]>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut state as *mut KECCAK1600_CTX as *mut libc::c_void,
        ::core::mem::size_of::<KECCAK1600_CTX>() as libc::c_ulong,
    );
}
unsafe extern "C" fn rej_eta(
    mut params: *mut ml_dsa_params,
    mut a: *mut int32_t,
    mut len: libc::c_uint,
    mut buf: *const uint8_t,
    mut buflen: libc::c_uint,
) -> libc::c_uint {
    if (*params).eta == 2 as libc::c_int as size_t
        || (*params).eta == 4 as libc::c_int as size_t
    {} else {
        __assert_fail(
            b"(params->eta == 2) || (params->eta == 4)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ml_dsa/./ml_dsa_ref/poly.c\0"
                as *const u8 as *const libc::c_char,
            362 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 94],
                &[libc::c_char; 94],
            >(
                b"unsigned int rej_eta(ml_dsa_params *, int32_t *, unsigned int, const uint8_t *, unsigned int)\0",
            ))
                .as_ptr(),
        );
    }
    'c_15264: {
        if (*params).eta == 2 as libc::c_int as size_t
            || (*params).eta == 4 as libc::c_int as size_t
        {} else {
            __assert_fail(
                b"(params->eta == 2) || (params->eta == 4)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ml_dsa/./ml_dsa_ref/poly.c\0"
                    as *const u8 as *const libc::c_char,
                362 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 94],
                    &[libc::c_char; 94],
                >(
                    b"unsigned int rej_eta(ml_dsa_params *, int32_t *, unsigned int, const uint8_t *, unsigned int)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut ctr: libc::c_uint = 0;
    let mut pos: libc::c_uint = 0;
    let mut t0: uint32_t = 0;
    let mut t1: uint32_t = 0;
    pos = 0 as libc::c_int as libc::c_uint;
    ctr = pos;
    while ctr < len && pos < buflen {
        t0 = (*buf.offset(pos as isize) as libc::c_int & 0xf as libc::c_int) as uint32_t;
        let fresh5 = pos;
        pos = pos.wrapping_add(1);
        t1 = (*buf.offset(fresh5 as isize) as libc::c_int >> 4 as libc::c_int)
            as uint32_t;
        if (*params).eta == 2 as libc::c_int as size_t {
            if t0 < 15 as libc::c_int as uint32_t {
                t0 = t0
                    .wrapping_sub(
                        (205 as libc::c_int as uint32_t * t0 >> 10 as libc::c_int)
                            * 5 as libc::c_int as uint32_t,
                    );
                let fresh6 = ctr;
                ctr = ctr.wrapping_add(1);
                *a
                    .offset(
                        fresh6 as isize,
                    ) = (2 as libc::c_int as uint32_t).wrapping_sub(t0) as int32_t;
            }
            if t1 < 15 as libc::c_int as uint32_t && ctr < len {
                t1 = t1
                    .wrapping_sub(
                        (205 as libc::c_int as uint32_t * t1 >> 10 as libc::c_int)
                            * 5 as libc::c_int as uint32_t,
                    );
                let fresh7 = ctr;
                ctr = ctr.wrapping_add(1);
                *a
                    .offset(
                        fresh7 as isize,
                    ) = (2 as libc::c_int as uint32_t).wrapping_sub(t1) as int32_t;
            }
        } else if (*params).eta == 4 as libc::c_int as size_t {
            if t0 < 9 as libc::c_int as uint32_t {
                let fresh8 = ctr;
                ctr = ctr.wrapping_add(1);
                *a
                    .offset(
                        fresh8 as isize,
                    ) = (4 as libc::c_int as uint32_t).wrapping_sub(t0) as int32_t;
            }
            if t1 < 9 as libc::c_int as uint32_t && ctr < len {
                let fresh9 = ctr;
                ctr = ctr.wrapping_add(1);
                *a
                    .offset(
                        fresh9 as isize,
                    ) = (4 as libc::c_int as uint32_t).wrapping_sub(t1) as int32_t;
            }
        }
    }
    return ctr;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_poly_uniform_eta(
    mut params: *mut ml_dsa_params,
    mut a: *mut ml_dsa_poly,
    mut seed: *const uint8_t,
    mut nonce: uint16_t,
) {
    let mut ctr: libc::c_uint = 0;
    let mut buflen: libc::c_uint = ((227 as libc::c_int
        + (1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
            / 8 as libc::c_int - 1 as libc::c_int)
        / ((1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
            / 8 as libc::c_int)
        * ((1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
            / 8 as libc::c_int)) as libc::c_uint;
    let mut buf: [uint8_t; 272] = [0; 272];
    let mut state: KECCAK1600_CTX = keccak_st {
        A: [[0; 5]; 5],
        block_size: 0,
        md_size: 0,
        buf_load: 0,
        buf: [0; 168],
        pad: 0,
        state: 0,
    };
    let mut t: [uint8_t; 2] = [0; 2];
    t[0 as libc::c_int
        as usize] = (nonce as libc::c_int & 0xff as libc::c_int) as uint8_t;
    t[1 as libc::c_int as usize] = (nonce as libc::c_int >> 8 as libc::c_int) as uint8_t;
    SHAKE_Init(
        &mut state,
        ((1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
            / 8 as libc::c_int) as size_t,
    );
    SHAKE_Absorb(&mut state, seed as *const libc::c_void, 64 as libc::c_int as size_t);
    SHAKE_Absorb(
        &mut state,
        t.as_mut_ptr() as *const libc::c_void,
        2 as libc::c_int as size_t,
    );
    SHAKE_Squeeze(
        buf.as_mut_ptr(),
        &mut state,
        ((227 as libc::c_int
            + (1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
                / 8 as libc::c_int - 1 as libc::c_int)
            / ((1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
                / 8 as libc::c_int)
            * ((1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
                / 8 as libc::c_int)) as size_t,
    );
    ctr = rej_eta(
        params,
        ((*a).coeffs).as_mut_ptr(),
        256 as libc::c_int as libc::c_uint,
        buf.as_mut_ptr(),
        buflen,
    );
    while ctr < 256 as libc::c_int as libc::c_uint {
        SHAKE_Squeeze(
            buf.as_mut_ptr(),
            &mut state,
            ((1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
                / 8 as libc::c_int) as size_t,
        );
        ctr = ctr
            .wrapping_add(
                rej_eta(
                    params,
                    ((*a).coeffs).as_mut_ptr().offset(ctr as isize),
                    (256 as libc::c_int as libc::c_uint).wrapping_sub(ctr),
                    buf.as_mut_ptr(),
                    ((1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
                        / 8 as libc::c_int) as libc::c_uint,
                ),
            );
    }
    OPENSSL_cleanse(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 272]>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut state as *mut KECCAK1600_CTX as *mut libc::c_void,
        ::core::mem::size_of::<KECCAK1600_CTX>() as libc::c_ulong,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_poly_uniform_gamma1(
    mut params: *mut ml_dsa_params,
    mut a: *mut ml_dsa_poly,
    mut seed: *const uint8_t,
    mut nonce: uint16_t,
) {
    let mut buf: [uint8_t; 680] = [0; 680];
    let mut state: KECCAK1600_CTX = keccak_st {
        A: [[0; 5]; 5],
        block_size: 0,
        md_size: 0,
        buf_load: 0,
        buf: [0; 168],
        pad: 0,
        state: 0,
    };
    let mut t: [uint8_t; 2] = [0; 2];
    t[0 as libc::c_int
        as usize] = (nonce as libc::c_int & 0xff as libc::c_int) as uint8_t;
    t[1 as libc::c_int as usize] = (nonce as libc::c_int >> 8 as libc::c_int) as uint8_t;
    SHAKE_Init(
        &mut state,
        ((1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
            / 8 as libc::c_int) as size_t,
    );
    SHAKE_Absorb(&mut state, seed as *const libc::c_void, 64 as libc::c_int as size_t);
    SHAKE_Absorb(
        &mut state,
        t.as_mut_ptr() as *const libc::c_void,
        2 as libc::c_int as size_t,
    );
    SHAKE_Final(
        buf.as_mut_ptr(),
        &mut state,
        ((576 as libc::c_int
            + (1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
                / 8 as libc::c_int - 1 as libc::c_int)
            / ((1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
                / 8 as libc::c_int)
            * ((1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
                / 8 as libc::c_int)) as size_t,
    );
    ml_dsa_polyz_unpack(params, a, buf.as_mut_ptr());
    OPENSSL_cleanse(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 680]>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut state as *mut KECCAK1600_CTX as *mut libc::c_void,
        ::core::mem::size_of::<KECCAK1600_CTX>() as libc::c_ulong,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_poly_challenge(
    mut params: *mut ml_dsa_params,
    mut c: *mut ml_dsa_poly,
    mut seed: *const uint8_t,
) {
    let mut i: libc::c_uint = 0;
    let mut b: libc::c_uint = 0;
    let mut pos: libc::c_uint = 0;
    let mut signs: uint64_t = 0;
    let mut buf: [uint8_t; 136] = [0; 136];
    let mut state: KECCAK1600_CTX = keccak_st {
        A: [[0; 5]; 5],
        block_size: 0,
        md_size: 0,
        buf_load: 0,
        buf: [0; 168],
        pad: 0,
        state: 0,
    };
    SHAKE_Init(
        &mut state,
        ((1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
            / 8 as libc::c_int) as size_t,
    );
    SHAKE_Absorb(&mut state, seed as *const libc::c_void, (*params).c_tilde_bytes);
    SHAKE_Squeeze(
        buf.as_mut_ptr(),
        &mut state,
        ((1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
            / 8 as libc::c_int) as size_t,
    );
    signs = 0 as libc::c_int as uint64_t;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 8 as libc::c_int as libc::c_uint {
        signs
            |= (buf[i as usize] as uint64_t)
                << (8 as libc::c_int as libc::c_uint).wrapping_mul(i);
        i = i.wrapping_add(1);
        i;
    }
    pos = 8 as libc::c_int as libc::c_uint;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 256 as libc::c_int as libc::c_uint {
        (*c).coeffs[i as usize] = 0 as libc::c_int;
        i = i.wrapping_add(1);
        i;
    }
    i = (256 as libc::c_int as size_t).wrapping_sub((*params).tau) as libc::c_uint;
    while i < 256 as libc::c_int as libc::c_uint {
        loop {
            if pos
                >= ((1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
                    / 8 as libc::c_int) as libc::c_uint
            {
                SHAKE_Squeeze(
                    buf.as_mut_ptr(),
                    &mut state,
                    ((1600 as libc::c_int - 256 as libc::c_int * 2 as libc::c_int)
                        / 8 as libc::c_int) as size_t,
                );
                pos = 0 as libc::c_int as libc::c_uint;
            }
            let fresh10 = pos;
            pos = pos.wrapping_add(1);
            b = buf[fresh10 as usize] as libc::c_uint;
            if !(b > i) {
                break;
            }
        }
        (*c).coeffs[i as usize] = (*c).coeffs[b as usize];
        (*c)
            .coeffs[b
            as usize] = (1 as libc::c_int as uint64_t)
            .wrapping_sub(
                2 as libc::c_int as uint64_t * (signs & 1 as libc::c_int as uint64_t),
            ) as int32_t;
        signs >>= 1 as libc::c_int;
        i = i.wrapping_add(1);
        i;
    }
    OPENSSL_cleanse(
        &mut signs as *mut uint64_t as *mut libc::c_void,
        ::core::mem::size_of::<uint64_t>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 136]>() as libc::c_ulong,
    );
    OPENSSL_cleanse(
        &mut state as *mut KECCAK1600_CTX as *mut libc::c_void,
        ::core::mem::size_of::<KECCAK1600_CTX>() as libc::c_ulong,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyeta_pack(
    mut params: *mut ml_dsa_params,
    mut r: *mut uint8_t,
    mut a: *const ml_dsa_poly,
) {
    let mut i: libc::c_uint = 0;
    let mut t: [uint8_t; 8] = [0; 8];
    if (*params).eta == 2 as libc::c_int as size_t
        || (*params).eta == 4 as libc::c_int as size_t
    {} else {
        __assert_fail(
            b"(params->eta == 2) || (params->eta == 4)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ml_dsa/./ml_dsa_ref/poly.c\0"
                as *const u8 as *const libc::c_char,
            537 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 74],
                &[libc::c_char; 74],
            >(
                b"void ml_dsa_polyeta_pack(ml_dsa_params *, uint8_t *, const ml_dsa_poly *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_12771: {
        if (*params).eta == 2 as libc::c_int as size_t
            || (*params).eta == 4 as libc::c_int as size_t
        {} else {
            __assert_fail(
                b"(params->eta == 2) || (params->eta == 4)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ml_dsa/./ml_dsa_ref/poly.c\0"
                    as *const u8 as *const libc::c_char,
                537 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 74],
                    &[libc::c_char; 74],
                >(
                    b"void ml_dsa_polyeta_pack(ml_dsa_params *, uint8_t *, const ml_dsa_poly *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if (*params).eta == 2 as libc::c_int as size_t {
        i = 0 as libc::c_int as libc::c_uint;
        while i < (256 as libc::c_int / 8 as libc::c_int) as libc::c_uint {
            t[0 as libc::c_int
                as usize] = ((*params).eta)
                .wrapping_sub(
                    (*a)
                        .coeffs[(8 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(0 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as uint8_t;
            t[1 as libc::c_int
                as usize] = ((*params).eta)
                .wrapping_sub(
                    (*a)
                        .coeffs[(8 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(1 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as uint8_t;
            t[2 as libc::c_int
                as usize] = ((*params).eta)
                .wrapping_sub(
                    (*a)
                        .coeffs[(8 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(2 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as uint8_t;
            t[3 as libc::c_int
                as usize] = ((*params).eta)
                .wrapping_sub(
                    (*a)
                        .coeffs[(8 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(3 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as uint8_t;
            t[4 as libc::c_int
                as usize] = ((*params).eta)
                .wrapping_sub(
                    (*a)
                        .coeffs[(8 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(4 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as uint8_t;
            t[5 as libc::c_int
                as usize] = ((*params).eta)
                .wrapping_sub(
                    (*a)
                        .coeffs[(8 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(5 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as uint8_t;
            t[6 as libc::c_int
                as usize] = ((*params).eta)
                .wrapping_sub(
                    (*a)
                        .coeffs[(8 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(6 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as uint8_t;
            t[7 as libc::c_int
                as usize] = ((*params).eta)
                .wrapping_sub(
                    (*a)
                        .coeffs[(8 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(7 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as uint8_t;
            *r
                .offset(
                    (3 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(0 as libc::c_int as libc::c_uint) as isize,
                ) = (t[0 as libc::c_int as usize] as libc::c_int >> 0 as libc::c_int
                | (t[1 as libc::c_int as usize] as libc::c_int) << 3 as libc::c_int
                | (t[2 as libc::c_int as usize] as libc::c_int) << 6 as libc::c_int)
                as uint8_t;
            *r
                .offset(
                    (3 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
                ) = (t[2 as libc::c_int as usize] as libc::c_int >> 2 as libc::c_int
                | (t[3 as libc::c_int as usize] as libc::c_int) << 1 as libc::c_int
                | (t[4 as libc::c_int as usize] as libc::c_int) << 4 as libc::c_int
                | (t[5 as libc::c_int as usize] as libc::c_int) << 7 as libc::c_int)
                as uint8_t;
            *r
                .offset(
                    (3 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
                ) = (t[5 as libc::c_int as usize] as libc::c_int >> 1 as libc::c_int
                | (t[6 as libc::c_int as usize] as libc::c_int) << 2 as libc::c_int
                | (t[7 as libc::c_int as usize] as libc::c_int) << 5 as libc::c_int)
                as uint8_t;
            i = i.wrapping_add(1);
            i;
        }
    } else if (*params).eta == 4 as libc::c_int as size_t {
        i = 0 as libc::c_int as libc::c_uint;
        while i < (256 as libc::c_int / 2 as libc::c_int) as libc::c_uint {
            t[0 as libc::c_int
                as usize] = ((*params).eta)
                .wrapping_sub(
                    (*a)
                        .coeffs[(2 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(0 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as uint8_t;
            t[1 as libc::c_int
                as usize] = ((*params).eta)
                .wrapping_sub(
                    (*a)
                        .coeffs[(2 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(1 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as uint8_t;
            *r
                .offset(
                    i as isize,
                ) = (t[0 as libc::c_int as usize] as libc::c_int
                | (t[1 as libc::c_int as usize] as libc::c_int) << 4 as libc::c_int)
                as uint8_t;
            i = i.wrapping_add(1);
            i;
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyeta_unpack(
    mut params: *mut ml_dsa_params,
    mut r: *mut ml_dsa_poly,
    mut a: *const uint8_t,
) {
    let mut i: libc::c_uint = 0;
    if (*params).eta == 2 as libc::c_int as size_t
        || (*params).eta == 4 as libc::c_int as size_t
    {} else {
        __assert_fail(
            b"(params->eta == 2) || (params->eta == 4)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ml_dsa/./ml_dsa_ref/poly.c\0"
                as *const u8 as *const libc::c_char,
            576 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 76],
                &[libc::c_char; 76],
            >(
                b"void ml_dsa_polyeta_unpack(ml_dsa_params *, ml_dsa_poly *, const uint8_t *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_19044: {
        if (*params).eta == 2 as libc::c_int as size_t
            || (*params).eta == 4 as libc::c_int as size_t
        {} else {
            __assert_fail(
                b"(params->eta == 2) || (params->eta == 4)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ml_dsa/./ml_dsa_ref/poly.c\0"
                    as *const u8 as *const libc::c_char,
                576 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 76],
                    &[libc::c_char; 76],
                >(
                    b"void ml_dsa_polyeta_unpack(ml_dsa_params *, ml_dsa_poly *, const uint8_t *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if (*params).eta == 2 as libc::c_int as size_t {
        i = 0 as libc::c_int as libc::c_uint;
        while i < (256 as libc::c_int / 8 as libc::c_int) as libc::c_uint {
            (*r)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(0 as libc::c_int as libc::c_uint)
                as usize] = *a
                .offset(
                    (3 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(0 as libc::c_int as libc::c_uint) as isize,
                ) as libc::c_int >> 0 as libc::c_int & 7 as libc::c_int;
            (*r)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(1 as libc::c_int as libc::c_uint)
                as usize] = *a
                .offset(
                    (3 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(0 as libc::c_int as libc::c_uint) as isize,
                ) as libc::c_int >> 3 as libc::c_int & 7 as libc::c_int;
            (*r)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(2 as libc::c_int as libc::c_uint)
                as usize] = (*a
                .offset(
                    (3 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(0 as libc::c_int as libc::c_uint) as isize,
                ) as libc::c_int >> 6 as libc::c_int
                | (*a
                    .offset(
                        (3 as libc::c_int as libc::c_uint)
                            .wrapping_mul(i)
                            .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
                    ) as libc::c_int) << 2 as libc::c_int) & 7 as libc::c_int;
            (*r)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(3 as libc::c_int as libc::c_uint)
                as usize] = *a
                .offset(
                    (3 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
                ) as libc::c_int >> 1 as libc::c_int & 7 as libc::c_int;
            (*r)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(4 as libc::c_int as libc::c_uint)
                as usize] = *a
                .offset(
                    (3 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
                ) as libc::c_int >> 4 as libc::c_int & 7 as libc::c_int;
            (*r)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(5 as libc::c_int as libc::c_uint)
                as usize] = (*a
                .offset(
                    (3 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
                ) as libc::c_int >> 7 as libc::c_int
                | (*a
                    .offset(
                        (3 as libc::c_int as libc::c_uint)
                            .wrapping_mul(i)
                            .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
                    ) as libc::c_int) << 1 as libc::c_int) & 7 as libc::c_int;
            (*r)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(6 as libc::c_int as libc::c_uint)
                as usize] = *a
                .offset(
                    (3 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
                ) as libc::c_int >> 2 as libc::c_int & 7 as libc::c_int;
            (*r)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(7 as libc::c_int as libc::c_uint)
                as usize] = *a
                .offset(
                    (3 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
                ) as libc::c_int >> 5 as libc::c_int & 7 as libc::c_int;
            (*r)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(0 as libc::c_int as libc::c_uint)
                as usize] = ((*params).eta)
                .wrapping_sub(
                    (*r)
                        .coeffs[(8 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(0 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as int32_t;
            (*r)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(1 as libc::c_int as libc::c_uint)
                as usize] = ((*params).eta)
                .wrapping_sub(
                    (*r)
                        .coeffs[(8 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(1 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as int32_t;
            (*r)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(2 as libc::c_int as libc::c_uint)
                as usize] = ((*params).eta)
                .wrapping_sub(
                    (*r)
                        .coeffs[(8 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(2 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as int32_t;
            (*r)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(3 as libc::c_int as libc::c_uint)
                as usize] = ((*params).eta)
                .wrapping_sub(
                    (*r)
                        .coeffs[(8 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(3 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as int32_t;
            (*r)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(4 as libc::c_int as libc::c_uint)
                as usize] = ((*params).eta)
                .wrapping_sub(
                    (*r)
                        .coeffs[(8 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(4 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as int32_t;
            (*r)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(5 as libc::c_int as libc::c_uint)
                as usize] = ((*params).eta)
                .wrapping_sub(
                    (*r)
                        .coeffs[(8 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(5 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as int32_t;
            (*r)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(6 as libc::c_int as libc::c_uint)
                as usize] = ((*params).eta)
                .wrapping_sub(
                    (*r)
                        .coeffs[(8 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(6 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as int32_t;
            (*r)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(7 as libc::c_int as libc::c_uint)
                as usize] = ((*params).eta)
                .wrapping_sub(
                    (*r)
                        .coeffs[(8 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(7 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as int32_t;
            i = i.wrapping_add(1);
            i;
        }
    } else if (*params).eta == 4 as libc::c_int as size_t {
        i = 0 as libc::c_int as libc::c_uint;
        while i < (256 as libc::c_int / 2 as libc::c_int) as libc::c_uint {
            (*r)
                .coeffs[(2 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(0 as libc::c_int as libc::c_uint)
                as usize] = *a.offset(i as isize) as libc::c_int & 0xf as libc::c_int;
            (*r)
                .coeffs[(2 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(1 as libc::c_int as libc::c_uint)
                as usize] = *a.offset(i as isize) as libc::c_int >> 4 as libc::c_int;
            (*r)
                .coeffs[(2 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(0 as libc::c_int as libc::c_uint)
                as usize] = ((*params).eta)
                .wrapping_sub(
                    (*r)
                        .coeffs[(2 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(0 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as int32_t;
            (*r)
                .coeffs[(2 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(1 as libc::c_int as libc::c_uint)
                as usize] = ((*params).eta)
                .wrapping_sub(
                    (*r)
                        .coeffs[(2 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(1 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as int32_t;
            i = i.wrapping_add(1);
            i;
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyt1_pack(
    mut r: *mut uint8_t,
    mut a: *const ml_dsa_poly,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 4 as libc::c_int) as libc::c_uint {
        *r
            .offset(
                (5 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(0 as libc::c_int as libc::c_uint) as isize,
            ) = ((*a)
            .coeffs[(4 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(0 as libc::c_int as libc::c_uint) as usize]
            >> 0 as libc::c_int) as uint8_t;
        *r
            .offset(
                (5 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
            ) = ((*a)
            .coeffs[(4 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(0 as libc::c_int as libc::c_uint) as usize] >> 8 as libc::c_int
            | (*a)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(1 as libc::c_int as libc::c_uint) as usize]
                << 2 as libc::c_int) as uint8_t;
        *r
            .offset(
                (5 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
            ) = ((*a)
            .coeffs[(4 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(1 as libc::c_int as libc::c_uint) as usize] >> 6 as libc::c_int
            | (*a)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(2 as libc::c_int as libc::c_uint) as usize]
                << 4 as libc::c_int) as uint8_t;
        *r
            .offset(
                (5 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(3 as libc::c_int as libc::c_uint) as isize,
            ) = ((*a)
            .coeffs[(4 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(2 as libc::c_int as libc::c_uint) as usize] >> 4 as libc::c_int
            | (*a)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(3 as libc::c_int as libc::c_uint) as usize]
                << 6 as libc::c_int) as uint8_t;
        *r
            .offset(
                (5 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(4 as libc::c_int as libc::c_uint) as isize,
            ) = ((*a)
            .coeffs[(4 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(3 as libc::c_int as libc::c_uint) as usize]
            >> 2 as libc::c_int) as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyt1_unpack(
    mut r: *mut ml_dsa_poly,
    mut a: *const uint8_t,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 4 as libc::c_int) as libc::c_uint {
        (*r)
            .coeffs[(4 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(0 as libc::c_int as libc::c_uint)
            as usize] = (((*a
            .offset(
                (5 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(0 as libc::c_int as libc::c_uint) as isize,
            ) as libc::c_int >> 0 as libc::c_int) as uint32_t
            | (*a
                .offset(
                    (5 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
                ) as uint32_t) << 8 as libc::c_int) & 0x3ff as libc::c_int as uint32_t)
            as int32_t;
        (*r)
            .coeffs[(4 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(1 as libc::c_int as libc::c_uint)
            as usize] = (((*a
            .offset(
                (5 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
            ) as libc::c_int >> 2 as libc::c_int) as uint32_t
            | (*a
                .offset(
                    (5 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
                ) as uint32_t) << 6 as libc::c_int) & 0x3ff as libc::c_int as uint32_t)
            as int32_t;
        (*r)
            .coeffs[(4 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(2 as libc::c_int as libc::c_uint)
            as usize] = (((*a
            .offset(
                (5 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
            ) as libc::c_int >> 4 as libc::c_int) as uint32_t
            | (*a
                .offset(
                    (5 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(3 as libc::c_int as libc::c_uint) as isize,
                ) as uint32_t) << 4 as libc::c_int) & 0x3ff as libc::c_int as uint32_t)
            as int32_t;
        (*r)
            .coeffs[(4 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(3 as libc::c_int as libc::c_uint)
            as usize] = (((*a
            .offset(
                (5 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(3 as libc::c_int as libc::c_uint) as isize,
            ) as libc::c_int >> 6 as libc::c_int) as uint32_t
            | (*a
                .offset(
                    (5 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(4 as libc::c_int as libc::c_uint) as isize,
                ) as uint32_t) << 2 as libc::c_int) & 0x3ff as libc::c_int as uint32_t)
            as int32_t;
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyt0_pack(
    mut r: *mut uint8_t,
    mut a: *const ml_dsa_poly,
) {
    let mut i: libc::c_uint = 0;
    let mut t: [uint32_t; 8] = [0; 8];
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 8 as libc::c_int) as libc::c_uint {
        t[0 as libc::c_int
            as usize] = (((1 as libc::c_int) << 13 as libc::c_int - 1 as libc::c_int)
            - (*a)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(0 as libc::c_int as libc::c_uint) as usize]) as uint32_t;
        t[1 as libc::c_int
            as usize] = (((1 as libc::c_int) << 13 as libc::c_int - 1 as libc::c_int)
            - (*a)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(1 as libc::c_int as libc::c_uint) as usize]) as uint32_t;
        t[2 as libc::c_int
            as usize] = (((1 as libc::c_int) << 13 as libc::c_int - 1 as libc::c_int)
            - (*a)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(2 as libc::c_int as libc::c_uint) as usize]) as uint32_t;
        t[3 as libc::c_int
            as usize] = (((1 as libc::c_int) << 13 as libc::c_int - 1 as libc::c_int)
            - (*a)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(3 as libc::c_int as libc::c_uint) as usize]) as uint32_t;
        t[4 as libc::c_int
            as usize] = (((1 as libc::c_int) << 13 as libc::c_int - 1 as libc::c_int)
            - (*a)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(4 as libc::c_int as libc::c_uint) as usize]) as uint32_t;
        t[5 as libc::c_int
            as usize] = (((1 as libc::c_int) << 13 as libc::c_int - 1 as libc::c_int)
            - (*a)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(5 as libc::c_int as libc::c_uint) as usize]) as uint32_t;
        t[6 as libc::c_int
            as usize] = (((1 as libc::c_int) << 13 as libc::c_int - 1 as libc::c_int)
            - (*a)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(6 as libc::c_int as libc::c_uint) as usize]) as uint32_t;
        t[7 as libc::c_int
            as usize] = (((1 as libc::c_int) << 13 as libc::c_int - 1 as libc::c_int)
            - (*a)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(7 as libc::c_int as libc::c_uint) as usize]) as uint32_t;
        *r
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(0 as libc::c_int as libc::c_uint) as isize,
            ) = t[0 as libc::c_int as usize] as uint8_t;
        *r
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
            ) = (t[0 as libc::c_int as usize] >> 8 as libc::c_int) as uint8_t;
        let ref mut fresh11 = *r
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
            );
        *fresh11 = (*fresh11 as uint32_t
            | t[1 as libc::c_int as usize] << 5 as libc::c_int) as uint8_t;
        *r
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
            ) = (t[1 as libc::c_int as usize] >> 3 as libc::c_int) as uint8_t;
        *r
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(3 as libc::c_int as libc::c_uint) as isize,
            ) = (t[1 as libc::c_int as usize] >> 11 as libc::c_int) as uint8_t;
        let ref mut fresh12 = *r
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(3 as libc::c_int as libc::c_uint) as isize,
            );
        *fresh12 = (*fresh12 as uint32_t
            | t[2 as libc::c_int as usize] << 2 as libc::c_int) as uint8_t;
        *r
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(4 as libc::c_int as libc::c_uint) as isize,
            ) = (t[2 as libc::c_int as usize] >> 6 as libc::c_int) as uint8_t;
        let ref mut fresh13 = *r
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(4 as libc::c_int as libc::c_uint) as isize,
            );
        *fresh13 = (*fresh13 as uint32_t
            | t[3 as libc::c_int as usize] << 7 as libc::c_int) as uint8_t;
        *r
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(5 as libc::c_int as libc::c_uint) as isize,
            ) = (t[3 as libc::c_int as usize] >> 1 as libc::c_int) as uint8_t;
        *r
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(6 as libc::c_int as libc::c_uint) as isize,
            ) = (t[3 as libc::c_int as usize] >> 9 as libc::c_int) as uint8_t;
        let ref mut fresh14 = *r
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(6 as libc::c_int as libc::c_uint) as isize,
            );
        *fresh14 = (*fresh14 as uint32_t
            | t[4 as libc::c_int as usize] << 4 as libc::c_int) as uint8_t;
        *r
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(7 as libc::c_int as libc::c_uint) as isize,
            ) = (t[4 as libc::c_int as usize] >> 4 as libc::c_int) as uint8_t;
        *r
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(8 as libc::c_int as libc::c_uint) as isize,
            ) = (t[4 as libc::c_int as usize] >> 12 as libc::c_int) as uint8_t;
        let ref mut fresh15 = *r
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(8 as libc::c_int as libc::c_uint) as isize,
            );
        *fresh15 = (*fresh15 as uint32_t
            | t[5 as libc::c_int as usize] << 1 as libc::c_int) as uint8_t;
        *r
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(9 as libc::c_int as libc::c_uint) as isize,
            ) = (t[5 as libc::c_int as usize] >> 7 as libc::c_int) as uint8_t;
        let ref mut fresh16 = *r
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(9 as libc::c_int as libc::c_uint) as isize,
            );
        *fresh16 = (*fresh16 as uint32_t
            | t[6 as libc::c_int as usize] << 6 as libc::c_int) as uint8_t;
        *r
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(10 as libc::c_int as libc::c_uint) as isize,
            ) = (t[6 as libc::c_int as usize] >> 2 as libc::c_int) as uint8_t;
        *r
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(11 as libc::c_int as libc::c_uint) as isize,
            ) = (t[6 as libc::c_int as usize] >> 10 as libc::c_int) as uint8_t;
        let ref mut fresh17 = *r
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(11 as libc::c_int as libc::c_uint) as isize,
            );
        *fresh17 = (*fresh17 as uint32_t
            | t[7 as libc::c_int as usize] << 3 as libc::c_int) as uint8_t;
        *r
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(12 as libc::c_int as libc::c_uint) as isize,
            ) = (t[7 as libc::c_int as usize] >> 5 as libc::c_int) as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyt0_unpack(
    mut r: *mut ml_dsa_poly,
    mut a: *const uint8_t,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (256 as libc::c_int / 8 as libc::c_int) as libc::c_uint {
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(0 as libc::c_int as libc::c_uint)
            as usize] = *a
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(0 as libc::c_int as libc::c_uint) as isize,
            ) as int32_t;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(0 as libc::c_int as libc::c_uint)
            as usize] = ((*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(0 as libc::c_int as libc::c_uint) as usize] as uint32_t
            | (*a
                .offset(
                    (13 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
                ) as uint32_t) << 8 as libc::c_int) as int32_t;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(0 as libc::c_int as libc::c_uint) as usize]
            &= 0x1fff as libc::c_int;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(1 as libc::c_int as libc::c_uint)
            as usize] = *a
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
            ) as libc::c_int >> 5 as libc::c_int;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(1 as libc::c_int as libc::c_uint)
            as usize] = ((*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(1 as libc::c_int as libc::c_uint) as usize] as uint32_t
            | (*a
                .offset(
                    (13 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
                ) as uint32_t) << 3 as libc::c_int) as int32_t;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(1 as libc::c_int as libc::c_uint)
            as usize] = ((*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(1 as libc::c_int as libc::c_uint) as usize] as uint32_t
            | (*a
                .offset(
                    (13 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(3 as libc::c_int as libc::c_uint) as isize,
                ) as uint32_t) << 11 as libc::c_int) as int32_t;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(1 as libc::c_int as libc::c_uint) as usize]
            &= 0x1fff as libc::c_int;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(2 as libc::c_int as libc::c_uint)
            as usize] = *a
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(3 as libc::c_int as libc::c_uint) as isize,
            ) as libc::c_int >> 2 as libc::c_int;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(2 as libc::c_int as libc::c_uint)
            as usize] = ((*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(2 as libc::c_int as libc::c_uint) as usize] as uint32_t
            | (*a
                .offset(
                    (13 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(4 as libc::c_int as libc::c_uint) as isize,
                ) as uint32_t) << 6 as libc::c_int) as int32_t;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(2 as libc::c_int as libc::c_uint) as usize]
            &= 0x1fff as libc::c_int;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(3 as libc::c_int as libc::c_uint)
            as usize] = *a
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(4 as libc::c_int as libc::c_uint) as isize,
            ) as libc::c_int >> 7 as libc::c_int;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(3 as libc::c_int as libc::c_uint)
            as usize] = ((*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(3 as libc::c_int as libc::c_uint) as usize] as uint32_t
            | (*a
                .offset(
                    (13 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(5 as libc::c_int as libc::c_uint) as isize,
                ) as uint32_t) << 1 as libc::c_int) as int32_t;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(3 as libc::c_int as libc::c_uint)
            as usize] = ((*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(3 as libc::c_int as libc::c_uint) as usize] as uint32_t
            | (*a
                .offset(
                    (13 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(6 as libc::c_int as libc::c_uint) as isize,
                ) as uint32_t) << 9 as libc::c_int) as int32_t;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(3 as libc::c_int as libc::c_uint) as usize]
            &= 0x1fff as libc::c_int;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(4 as libc::c_int as libc::c_uint)
            as usize] = *a
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(6 as libc::c_int as libc::c_uint) as isize,
            ) as libc::c_int >> 4 as libc::c_int;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(4 as libc::c_int as libc::c_uint)
            as usize] = ((*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(4 as libc::c_int as libc::c_uint) as usize] as uint32_t
            | (*a
                .offset(
                    (13 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(7 as libc::c_int as libc::c_uint) as isize,
                ) as uint32_t) << 4 as libc::c_int) as int32_t;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(4 as libc::c_int as libc::c_uint)
            as usize] = ((*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(4 as libc::c_int as libc::c_uint) as usize] as uint32_t
            | (*a
                .offset(
                    (13 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(8 as libc::c_int as libc::c_uint) as isize,
                ) as uint32_t) << 12 as libc::c_int) as int32_t;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(4 as libc::c_int as libc::c_uint) as usize]
            &= 0x1fff as libc::c_int;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(5 as libc::c_int as libc::c_uint)
            as usize] = *a
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(8 as libc::c_int as libc::c_uint) as isize,
            ) as libc::c_int >> 1 as libc::c_int;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(5 as libc::c_int as libc::c_uint)
            as usize] = ((*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(5 as libc::c_int as libc::c_uint) as usize] as uint32_t
            | (*a
                .offset(
                    (13 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(9 as libc::c_int as libc::c_uint) as isize,
                ) as uint32_t) << 7 as libc::c_int) as int32_t;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(5 as libc::c_int as libc::c_uint) as usize]
            &= 0x1fff as libc::c_int;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(6 as libc::c_int as libc::c_uint)
            as usize] = *a
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(9 as libc::c_int as libc::c_uint) as isize,
            ) as libc::c_int >> 6 as libc::c_int;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(6 as libc::c_int as libc::c_uint)
            as usize] = ((*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(6 as libc::c_int as libc::c_uint) as usize] as uint32_t
            | (*a
                .offset(
                    (13 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(10 as libc::c_int as libc::c_uint) as isize,
                ) as uint32_t) << 2 as libc::c_int) as int32_t;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(6 as libc::c_int as libc::c_uint)
            as usize] = ((*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(6 as libc::c_int as libc::c_uint) as usize] as uint32_t
            | (*a
                .offset(
                    (13 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(11 as libc::c_int as libc::c_uint) as isize,
                ) as uint32_t) << 10 as libc::c_int) as int32_t;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(6 as libc::c_int as libc::c_uint) as usize]
            &= 0x1fff as libc::c_int;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(7 as libc::c_int as libc::c_uint)
            as usize] = *a
            .offset(
                (13 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(11 as libc::c_int as libc::c_uint) as isize,
            ) as libc::c_int >> 3 as libc::c_int;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(7 as libc::c_int as libc::c_uint)
            as usize] = ((*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(7 as libc::c_int as libc::c_uint) as usize] as uint32_t
            | (*a
                .offset(
                    (13 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(12 as libc::c_int as libc::c_uint) as isize,
                ) as uint32_t) << 5 as libc::c_int) as int32_t;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(7 as libc::c_int as libc::c_uint) as usize]
            &= 0x1fff as libc::c_int;
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(0 as libc::c_int as libc::c_uint)
            as usize] = ((1 as libc::c_int) << 13 as libc::c_int - 1 as libc::c_int)
            - (*r)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(0 as libc::c_int as libc::c_uint) as usize];
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(1 as libc::c_int as libc::c_uint)
            as usize] = ((1 as libc::c_int) << 13 as libc::c_int - 1 as libc::c_int)
            - (*r)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(1 as libc::c_int as libc::c_uint) as usize];
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(2 as libc::c_int as libc::c_uint)
            as usize] = ((1 as libc::c_int) << 13 as libc::c_int - 1 as libc::c_int)
            - (*r)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(2 as libc::c_int as libc::c_uint) as usize];
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(3 as libc::c_int as libc::c_uint)
            as usize] = ((1 as libc::c_int) << 13 as libc::c_int - 1 as libc::c_int)
            - (*r)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(3 as libc::c_int as libc::c_uint) as usize];
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(4 as libc::c_int as libc::c_uint)
            as usize] = ((1 as libc::c_int) << 13 as libc::c_int - 1 as libc::c_int)
            - (*r)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(4 as libc::c_int as libc::c_uint) as usize];
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(5 as libc::c_int as libc::c_uint)
            as usize] = ((1 as libc::c_int) << 13 as libc::c_int - 1 as libc::c_int)
            - (*r)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(5 as libc::c_int as libc::c_uint) as usize];
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(6 as libc::c_int as libc::c_uint)
            as usize] = ((1 as libc::c_int) << 13 as libc::c_int - 1 as libc::c_int)
            - (*r)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(6 as libc::c_int as libc::c_uint) as usize];
        (*r)
            .coeffs[(8 as libc::c_int as libc::c_uint)
            .wrapping_mul(i)
            .wrapping_add(7 as libc::c_int as libc::c_uint)
            as usize] = ((1 as libc::c_int) << 13 as libc::c_int - 1 as libc::c_int)
            - (*r)
                .coeffs[(8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(7 as libc::c_int as libc::c_uint) as usize];
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyz_pack(
    mut params: *mut ml_dsa_params,
    mut r: *mut uint8_t,
    mut a: *const ml_dsa_poly,
) {
    let mut i: libc::c_uint = 0;
    let mut t: [uint32_t; 4] = [0; 4];
    if (*params).gamma1 == ((1 as libc::c_int) << 17 as libc::c_int) as size_t
        || (*params).gamma1 == ((1 as libc::c_int) << 19 as libc::c_int) as size_t
    {} else {
        __assert_fail(
            b"(params->gamma1 == (1 << 17)) || (params->gamma1 == (1 << 19))\0"
                as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ml_dsa/./ml_dsa_ref/poly.c\0"
                as *const u8 as *const libc::c_char,
            772 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 72],
                &[libc::c_char; 72],
            >(
                b"void ml_dsa_polyz_pack(ml_dsa_params *, uint8_t *, const ml_dsa_poly *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_20431: {
        if (*params).gamma1 == ((1 as libc::c_int) << 17 as libc::c_int) as size_t
            || (*params).gamma1 == ((1 as libc::c_int) << 19 as libc::c_int) as size_t
        {} else {
            __assert_fail(
                b"(params->gamma1 == (1 << 17)) || (params->gamma1 == (1 << 19))\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ml_dsa/./ml_dsa_ref/poly.c\0"
                    as *const u8 as *const libc::c_char,
                772 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 72],
                    &[libc::c_char; 72],
                >(
                    b"void ml_dsa_polyz_pack(ml_dsa_params *, uint8_t *, const ml_dsa_poly *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if (*params).gamma1 == ((1 as libc::c_int) << 17 as libc::c_int) as size_t {
        i = 0 as libc::c_int as libc::c_uint;
        while i < (256 as libc::c_int / 4 as libc::c_int) as libc::c_uint {
            t[0 as libc::c_int
                as usize] = ((*params).gamma1)
                .wrapping_sub(
                    (*a)
                        .coeffs[(4 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(0 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as uint32_t;
            t[1 as libc::c_int
                as usize] = ((*params).gamma1)
                .wrapping_sub(
                    (*a)
                        .coeffs[(4 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(1 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as uint32_t;
            t[2 as libc::c_int
                as usize] = ((*params).gamma1)
                .wrapping_sub(
                    (*a)
                        .coeffs[(4 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(2 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as uint32_t;
            t[3 as libc::c_int
                as usize] = ((*params).gamma1)
                .wrapping_sub(
                    (*a)
                        .coeffs[(4 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(3 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as uint32_t;
            *r
                .offset(
                    (9 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(0 as libc::c_int as libc::c_uint) as isize,
                ) = t[0 as libc::c_int as usize] as uint8_t;
            *r
                .offset(
                    (9 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
                ) = (t[0 as libc::c_int as usize] >> 8 as libc::c_int) as uint8_t;
            *r
                .offset(
                    (9 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
                ) = (t[0 as libc::c_int as usize] >> 16 as libc::c_int) as uint8_t;
            let ref mut fresh18 = *r
                .offset(
                    (9 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
                );
            *fresh18 = (*fresh18 as uint32_t
                | t[1 as libc::c_int as usize] << 2 as libc::c_int) as uint8_t;
            *r
                .offset(
                    (9 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(3 as libc::c_int as libc::c_uint) as isize,
                ) = (t[1 as libc::c_int as usize] >> 6 as libc::c_int) as uint8_t;
            *r
                .offset(
                    (9 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(4 as libc::c_int as libc::c_uint) as isize,
                ) = (t[1 as libc::c_int as usize] >> 14 as libc::c_int) as uint8_t;
            let ref mut fresh19 = *r
                .offset(
                    (9 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(4 as libc::c_int as libc::c_uint) as isize,
                );
            *fresh19 = (*fresh19 as uint32_t
                | t[2 as libc::c_int as usize] << 4 as libc::c_int) as uint8_t;
            *r
                .offset(
                    (9 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(5 as libc::c_int as libc::c_uint) as isize,
                ) = (t[2 as libc::c_int as usize] >> 4 as libc::c_int) as uint8_t;
            *r
                .offset(
                    (9 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(6 as libc::c_int as libc::c_uint) as isize,
                ) = (t[2 as libc::c_int as usize] >> 12 as libc::c_int) as uint8_t;
            let ref mut fresh20 = *r
                .offset(
                    (9 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(6 as libc::c_int as libc::c_uint) as isize,
                );
            *fresh20 = (*fresh20 as uint32_t
                | t[3 as libc::c_int as usize] << 6 as libc::c_int) as uint8_t;
            *r
                .offset(
                    (9 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(7 as libc::c_int as libc::c_uint) as isize,
                ) = (t[3 as libc::c_int as usize] >> 2 as libc::c_int) as uint8_t;
            *r
                .offset(
                    (9 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(8 as libc::c_int as libc::c_uint) as isize,
                ) = (t[3 as libc::c_int as usize] >> 10 as libc::c_int) as uint8_t;
            i = i.wrapping_add(1);
            i;
        }
    } else if (*params).gamma1 == ((1 as libc::c_int) << 19 as libc::c_int) as size_t {
        i = 0 as libc::c_int as libc::c_uint;
        while i < (256 as libc::c_int / 2 as libc::c_int) as libc::c_uint {
            t[0 as libc::c_int
                as usize] = ((*params).gamma1)
                .wrapping_sub(
                    (*a)
                        .coeffs[(2 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(0 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as uint32_t;
            t[1 as libc::c_int
                as usize] = ((*params).gamma1)
                .wrapping_sub(
                    (*a)
                        .coeffs[(2 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(1 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as uint32_t;
            *r
                .offset(
                    (5 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(0 as libc::c_int as libc::c_uint) as isize,
                ) = t[0 as libc::c_int as usize] as uint8_t;
            *r
                .offset(
                    (5 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
                ) = (t[0 as libc::c_int as usize] >> 8 as libc::c_int) as uint8_t;
            *r
                .offset(
                    (5 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
                ) = (t[0 as libc::c_int as usize] >> 16 as libc::c_int) as uint8_t;
            let ref mut fresh21 = *r
                .offset(
                    (5 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
                );
            *fresh21 = (*fresh21 as uint32_t
                | t[1 as libc::c_int as usize] << 4 as libc::c_int) as uint8_t;
            *r
                .offset(
                    (5 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(3 as libc::c_int as libc::c_uint) as isize,
                ) = (t[1 as libc::c_int as usize] >> 4 as libc::c_int) as uint8_t;
            *r
                .offset(
                    (5 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(4 as libc::c_int as libc::c_uint) as isize,
                ) = (t[1 as libc::c_int as usize] >> 12 as libc::c_int) as uint8_t;
            i = i.wrapping_add(1);
            i;
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyz_unpack(
    mut params: *mut ml_dsa_params,
    mut r: *mut ml_dsa_poly,
    mut a: *const uint8_t,
) {
    let mut i: libc::c_uint = 0;
    if (*params).gamma1 == ((1 as libc::c_int) << 17 as libc::c_int) as size_t
        || (*params).gamma1 == ((1 as libc::c_int) << 19 as libc::c_int) as size_t
    {} else {
        __assert_fail(
            b"(params->gamma1 == (1 << 17)) || (params->gamma1 == (1 << 19))\0"
                as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ml_dsa/./ml_dsa_ref/poly.c\0"
                as *const u8 as *const libc::c_char,
            824 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 74],
                &[libc::c_char; 74],
            >(
                b"void ml_dsa_polyz_unpack(ml_dsa_params *, ml_dsa_poly *, const uint8_t *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_21559: {
        if (*params).gamma1 == ((1 as libc::c_int) << 17 as libc::c_int) as size_t
            || (*params).gamma1 == ((1 as libc::c_int) << 19 as libc::c_int) as size_t
        {} else {
            __assert_fail(
                b"(params->gamma1 == (1 << 17)) || (params->gamma1 == (1 << 19))\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ml_dsa/./ml_dsa_ref/poly.c\0"
                    as *const u8 as *const libc::c_char,
                824 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 74],
                    &[libc::c_char; 74],
                >(
                    b"void ml_dsa_polyz_unpack(ml_dsa_params *, ml_dsa_poly *, const uint8_t *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if (*params).gamma1 == ((1 as libc::c_int) << 17 as libc::c_int) as size_t {
        i = 0 as libc::c_int as libc::c_uint;
        while i < (256 as libc::c_int / 4 as libc::c_int) as libc::c_uint {
            (*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(0 as libc::c_int as libc::c_uint)
                as usize] = *a
                .offset(
                    (9 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(0 as libc::c_int as libc::c_uint) as isize,
                ) as int32_t;
            (*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(0 as libc::c_int as libc::c_uint)
                as usize] = ((*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(0 as libc::c_int as libc::c_uint) as usize] as uint32_t
                | (*a
                    .offset(
                        (9 as libc::c_int as libc::c_uint)
                            .wrapping_mul(i)
                            .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
                    ) as uint32_t) << 8 as libc::c_int) as int32_t;
            (*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(0 as libc::c_int as libc::c_uint)
                as usize] = ((*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(0 as libc::c_int as libc::c_uint) as usize] as uint32_t
                | (*a
                    .offset(
                        (9 as libc::c_int as libc::c_uint)
                            .wrapping_mul(i)
                            .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
                    ) as uint32_t) << 16 as libc::c_int) as int32_t;
            (*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(0 as libc::c_int as libc::c_uint) as usize]
                &= 0x3ffff as libc::c_int;
            (*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(1 as libc::c_int as libc::c_uint)
                as usize] = *a
                .offset(
                    (9 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
                ) as libc::c_int >> 2 as libc::c_int;
            (*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(1 as libc::c_int as libc::c_uint)
                as usize] = ((*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(1 as libc::c_int as libc::c_uint) as usize] as uint32_t
                | (*a
                    .offset(
                        (9 as libc::c_int as libc::c_uint)
                            .wrapping_mul(i)
                            .wrapping_add(3 as libc::c_int as libc::c_uint) as isize,
                    ) as uint32_t) << 6 as libc::c_int) as int32_t;
            (*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(1 as libc::c_int as libc::c_uint)
                as usize] = ((*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(1 as libc::c_int as libc::c_uint) as usize] as uint32_t
                | (*a
                    .offset(
                        (9 as libc::c_int as libc::c_uint)
                            .wrapping_mul(i)
                            .wrapping_add(4 as libc::c_int as libc::c_uint) as isize,
                    ) as uint32_t) << 14 as libc::c_int) as int32_t;
            (*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(1 as libc::c_int as libc::c_uint) as usize]
                &= 0x3ffff as libc::c_int;
            (*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(2 as libc::c_int as libc::c_uint)
                as usize] = *a
                .offset(
                    (9 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(4 as libc::c_int as libc::c_uint) as isize,
                ) as libc::c_int >> 4 as libc::c_int;
            (*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(2 as libc::c_int as libc::c_uint)
                as usize] = ((*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(2 as libc::c_int as libc::c_uint) as usize] as uint32_t
                | (*a
                    .offset(
                        (9 as libc::c_int as libc::c_uint)
                            .wrapping_mul(i)
                            .wrapping_add(5 as libc::c_int as libc::c_uint) as isize,
                    ) as uint32_t) << 4 as libc::c_int) as int32_t;
            (*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(2 as libc::c_int as libc::c_uint)
                as usize] = ((*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(2 as libc::c_int as libc::c_uint) as usize] as uint32_t
                | (*a
                    .offset(
                        (9 as libc::c_int as libc::c_uint)
                            .wrapping_mul(i)
                            .wrapping_add(6 as libc::c_int as libc::c_uint) as isize,
                    ) as uint32_t) << 12 as libc::c_int) as int32_t;
            (*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(2 as libc::c_int as libc::c_uint) as usize]
                &= 0x3ffff as libc::c_int;
            (*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(3 as libc::c_int as libc::c_uint)
                as usize] = *a
                .offset(
                    (9 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(6 as libc::c_int as libc::c_uint) as isize,
                ) as libc::c_int >> 6 as libc::c_int;
            (*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(3 as libc::c_int as libc::c_uint)
                as usize] = ((*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(3 as libc::c_int as libc::c_uint) as usize] as uint32_t
                | (*a
                    .offset(
                        (9 as libc::c_int as libc::c_uint)
                            .wrapping_mul(i)
                            .wrapping_add(7 as libc::c_int as libc::c_uint) as isize,
                    ) as uint32_t) << 2 as libc::c_int) as int32_t;
            (*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(3 as libc::c_int as libc::c_uint)
                as usize] = ((*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(3 as libc::c_int as libc::c_uint) as usize] as uint32_t
                | (*a
                    .offset(
                        (9 as libc::c_int as libc::c_uint)
                            .wrapping_mul(i)
                            .wrapping_add(8 as libc::c_int as libc::c_uint) as isize,
                    ) as uint32_t) << 10 as libc::c_int) as int32_t;
            (*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(3 as libc::c_int as libc::c_uint) as usize]
                &= 0x3ffff as libc::c_int;
            (*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(0 as libc::c_int as libc::c_uint)
                as usize] = ((*params).gamma1)
                .wrapping_sub(
                    (*r)
                        .coeffs[(4 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(0 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as int32_t;
            (*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(1 as libc::c_int as libc::c_uint)
                as usize] = ((*params).gamma1)
                .wrapping_sub(
                    (*r)
                        .coeffs[(4 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(1 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as int32_t;
            (*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(2 as libc::c_int as libc::c_uint)
                as usize] = ((*params).gamma1)
                .wrapping_sub(
                    (*r)
                        .coeffs[(4 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(2 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as int32_t;
            (*r)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(3 as libc::c_int as libc::c_uint)
                as usize] = ((*params).gamma1)
                .wrapping_sub(
                    (*r)
                        .coeffs[(4 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(3 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as int32_t;
            i = i.wrapping_add(1);
            i;
        }
    } else if (*params).gamma1 == ((1 as libc::c_int) << 19 as libc::c_int) as size_t {
        i = 0 as libc::c_int as libc::c_uint;
        while i < (256 as libc::c_int / 2 as libc::c_int) as libc::c_uint {
            (*r)
                .coeffs[(2 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(0 as libc::c_int as libc::c_uint)
                as usize] = *a
                .offset(
                    (5 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(0 as libc::c_int as libc::c_uint) as isize,
                ) as int32_t;
            (*r)
                .coeffs[(2 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(0 as libc::c_int as libc::c_uint)
                as usize] = ((*r)
                .coeffs[(2 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(0 as libc::c_int as libc::c_uint) as usize] as uint32_t
                | (*a
                    .offset(
                        (5 as libc::c_int as libc::c_uint)
                            .wrapping_mul(i)
                            .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
                    ) as uint32_t) << 8 as libc::c_int) as int32_t;
            (*r)
                .coeffs[(2 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(0 as libc::c_int as libc::c_uint)
                as usize] = ((*r)
                .coeffs[(2 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(0 as libc::c_int as libc::c_uint) as usize] as uint32_t
                | (*a
                    .offset(
                        (5 as libc::c_int as libc::c_uint)
                            .wrapping_mul(i)
                            .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
                    ) as uint32_t) << 16 as libc::c_int) as int32_t;
            (*r)
                .coeffs[(2 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(0 as libc::c_int as libc::c_uint) as usize]
                &= 0xfffff as libc::c_int;
            (*r)
                .coeffs[(2 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(1 as libc::c_int as libc::c_uint)
                as usize] = *a
                .offset(
                    (5 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
                ) as libc::c_int >> 4 as libc::c_int;
            (*r)
                .coeffs[(2 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(1 as libc::c_int as libc::c_uint)
                as usize] = ((*r)
                .coeffs[(2 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(1 as libc::c_int as libc::c_uint) as usize] as uint32_t
                | (*a
                    .offset(
                        (5 as libc::c_int as libc::c_uint)
                            .wrapping_mul(i)
                            .wrapping_add(3 as libc::c_int as libc::c_uint) as isize,
                    ) as uint32_t) << 4 as libc::c_int) as int32_t;
            (*r)
                .coeffs[(2 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(1 as libc::c_int as libc::c_uint)
                as usize] = ((*r)
                .coeffs[(2 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(1 as libc::c_int as libc::c_uint) as usize] as uint32_t
                | (*a
                    .offset(
                        (5 as libc::c_int as libc::c_uint)
                            .wrapping_mul(i)
                            .wrapping_add(4 as libc::c_int as libc::c_uint) as isize,
                    ) as uint32_t) << 12 as libc::c_int) as int32_t;
            (*r)
                .coeffs[(2 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(0 as libc::c_int as libc::c_uint)
                as usize] = ((*params).gamma1)
                .wrapping_sub(
                    (*r)
                        .coeffs[(2 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(0 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as int32_t;
            (*r)
                .coeffs[(2 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(1 as libc::c_int as libc::c_uint)
                as usize] = ((*params).gamma1)
                .wrapping_sub(
                    (*r)
                        .coeffs[(2 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(1 as libc::c_int as libc::c_uint) as usize]
                        as size_t,
                ) as int32_t;
            i = i.wrapping_add(1);
            i;
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyw1_pack(
    mut params: *mut ml_dsa_params,
    mut r: *mut uint8_t,
    mut a: *const ml_dsa_poly,
) {
    let mut i: libc::c_uint = 0;
    if (*params).gamma2
        == (8380417 as libc::c_int - 1 as libc::c_int) / 88 as libc::c_int
    {
        i = 0 as libc::c_int as libc::c_uint;
        while i < (256 as libc::c_int / 4 as libc::c_int) as libc::c_uint {
            *r
                .offset(
                    (3 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(0 as libc::c_int as libc::c_uint) as isize,
                ) = (*a)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(0 as libc::c_int as libc::c_uint) as usize] as uint8_t;
            let ref mut fresh22 = *r
                .offset(
                    (3 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(0 as libc::c_int as libc::c_uint) as isize,
                );
            *fresh22 = (*fresh22 as libc::c_int
                | (*a)
                    .coeffs[(4 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(1 as libc::c_int as libc::c_uint) as usize]
                    << 6 as libc::c_int) as uint8_t;
            *r
                .offset(
                    (3 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
                ) = ((*a)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(1 as libc::c_int as libc::c_uint) as usize]
                >> 2 as libc::c_int) as uint8_t;
            let ref mut fresh23 = *r
                .offset(
                    (3 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
                );
            *fresh23 = (*fresh23 as libc::c_int
                | (*a)
                    .coeffs[(4 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(2 as libc::c_int as libc::c_uint) as usize]
                    << 4 as libc::c_int) as uint8_t;
            *r
                .offset(
                    (3 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
                ) = ((*a)
                .coeffs[(4 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(2 as libc::c_int as libc::c_uint) as usize]
                >> 4 as libc::c_int) as uint8_t;
            let ref mut fresh24 = *r
                .offset(
                    (3 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
                );
            *fresh24 = (*fresh24 as libc::c_int
                | (*a)
                    .coeffs[(4 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(3 as libc::c_int as libc::c_uint) as usize]
                    << 2 as libc::c_int) as uint8_t;
            i = i.wrapping_add(1);
            i;
        }
    } else if (*params).gamma2
        == (8380417 as libc::c_int - 1 as libc::c_int) / 32 as libc::c_int
    {
        i = 0 as libc::c_int as libc::c_uint;
        while i < (256 as libc::c_int / 2 as libc::c_int) as libc::c_uint {
            *r
                .offset(
                    i as isize,
                ) = ((*a)
                .coeffs[(2 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(0 as libc::c_int as libc::c_uint) as usize]
                | (*a)
                    .coeffs[(2 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(1 as libc::c_int as libc::c_uint) as usize]
                    << 4 as libc::c_int) as uint8_t;
            i = i.wrapping_add(1);
            i;
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyvec_matrix_expand(
    mut params: *mut ml_dsa_params,
    mut mat: *mut polyvecl,
    mut rho: *const uint8_t,
) {
    let mut i: libc::c_uint = 0;
    let mut j: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).k as libc::c_uint {
        j = 0 as libc::c_int as libc::c_uint;
        while j < (*params).l as libc::c_uint {
            ml_dsa_poly_uniform(
                &mut *((*mat.offset(i as isize)).vec).as_mut_ptr().offset(j as isize),
                rho,
                (i << 8 as libc::c_int).wrapping_add(j) as uint16_t,
            );
            j = j.wrapping_add(1);
            j;
        }
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyvec_matrix_pointwise_montgomery(
    mut params: *mut ml_dsa_params,
    mut t: *mut polyveck,
    mut mat: *const polyvecl,
    mut v: *const polyvecl,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).k as libc::c_uint {
        ml_dsa_polyvecl_pointwise_acc_montgomery(
            params,
            &mut *((*t).vec).as_mut_ptr().offset(i as isize),
            &*mat.offset(i as isize),
            v,
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyvecl_uniform_eta(
    mut params: *mut ml_dsa_params,
    mut v: *mut polyvecl,
    mut seed: *const uint8_t,
    mut nonce: uint16_t,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).l as libc::c_uint {
        let fresh25 = nonce;
        nonce = nonce.wrapping_add(1);
        ml_dsa_poly_uniform_eta(
            params,
            &mut *((*v).vec).as_mut_ptr().offset(i as isize),
            seed,
            fresh25,
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyvecl_uniform_gamma1(
    mut params: *mut ml_dsa_params,
    mut v: *mut polyvecl,
    mut seed: *const uint8_t,
    mut nonce: uint16_t,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).l as libc::c_uint {
        ml_dsa_poly_uniform_gamma1(
            params,
            &mut *((*v).vec).as_mut_ptr().offset(i as isize),
            seed,
            (((*params).l as libc::c_int * nonce as libc::c_int) as libc::c_uint)
                .wrapping_add(i) as uint16_t,
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyvecl_reduce(
    mut params: *mut ml_dsa_params,
    mut v: *mut polyvecl,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).l as libc::c_uint {
        ml_dsa_poly_reduce(&mut *((*v).vec).as_mut_ptr().offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyvecl_add(
    mut params: *mut ml_dsa_params,
    mut w: *mut polyvecl,
    mut u: *const polyvecl,
    mut v: *const polyvecl,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).l as libc::c_uint {
        ml_dsa_poly_add(
            &mut *((*w).vec).as_mut_ptr().offset(i as isize),
            &*((*u).vec).as_ptr().offset(i as isize),
            &*((*v).vec).as_ptr().offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyvecl_ntt(
    mut params: *mut ml_dsa_params,
    mut v: *mut polyvecl,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).l as libc::c_uint {
        ml_dsa_poly_ntt(&mut *((*v).vec).as_mut_ptr().offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyvecl_invntt_tomont(
    mut params: *mut ml_dsa_params,
    mut v: *mut polyvecl,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).l as libc::c_uint {
        ml_dsa_poly_invntt_tomont(&mut *((*v).vec).as_mut_ptr().offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyvecl_pointwise_poly_montgomery(
    mut params: *mut ml_dsa_params,
    mut r: *mut polyvecl,
    mut a: *const ml_dsa_poly,
    mut v: *const polyvecl,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).l as libc::c_uint {
        ml_dsa_poly_pointwise_montgomery(
            &mut *((*r).vec).as_mut_ptr().offset(i as isize),
            a,
            &*((*v).vec).as_ptr().offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyvecl_pointwise_acc_montgomery(
    mut params: *mut ml_dsa_params,
    mut w: *mut ml_dsa_poly,
    mut u: *const polyvecl,
    mut v: *const polyvecl,
) {
    let mut i: libc::c_uint = 0;
    let mut t: ml_dsa_poly = ml_dsa_poly { coeffs: [0; 256] };
    ml_dsa_poly_pointwise_montgomery(
        w,
        &*((*u).vec).as_ptr().offset(0 as libc::c_int as isize),
        &*((*v).vec).as_ptr().offset(0 as libc::c_int as isize),
    );
    i = 1 as libc::c_int as libc::c_uint;
    while i < (*params).l as libc::c_uint {
        ml_dsa_poly_pointwise_montgomery(
            &mut t,
            &*((*u).vec).as_ptr().offset(i as isize),
            &*((*v).vec).as_ptr().offset(i as isize),
        );
        ml_dsa_poly_add(w, w, &mut t);
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyvecl_chknorm(
    mut params: *mut ml_dsa_params,
    mut v: *const polyvecl,
    mut bound: int32_t,
) -> libc::c_int {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).l as libc::c_uint {
        if ml_dsa_poly_chknorm(&*((*v).vec).as_ptr().offset(i as isize), bound) != 0 {
            return 1 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyveck_uniform_eta(
    mut params: *mut ml_dsa_params,
    mut v: *mut polyveck,
    mut seed: *const uint8_t,
    mut nonce: uint16_t,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).k as libc::c_uint {
        let fresh26 = nonce;
        nonce = nonce.wrapping_add(1);
        ml_dsa_poly_uniform_eta(
            params,
            &mut *((*v).vec).as_mut_ptr().offset(i as isize),
            seed,
            fresh26,
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyveck_reduce(
    mut params: *mut ml_dsa_params,
    mut v: *mut polyveck,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).k as libc::c_uint {
        ml_dsa_poly_reduce(&mut *((*v).vec).as_mut_ptr().offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyveck_caddq(
    mut params: *mut ml_dsa_params,
    mut v: *mut polyveck,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).k as libc::c_uint {
        ml_dsa_poly_caddq(&mut *((*v).vec).as_mut_ptr().offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyveck_add(
    mut params: *mut ml_dsa_params,
    mut w: *mut polyveck,
    mut u: *const polyveck,
    mut v: *const polyveck,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).k as libc::c_uint {
        ml_dsa_poly_add(
            &mut *((*w).vec).as_mut_ptr().offset(i as isize),
            &*((*u).vec).as_ptr().offset(i as isize),
            &*((*v).vec).as_ptr().offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyveck_sub(
    mut params: *mut ml_dsa_params,
    mut w: *mut polyveck,
    mut u: *const polyveck,
    mut v: *const polyveck,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).k as libc::c_uint {
        ml_dsa_poly_sub(
            &mut *((*w).vec).as_mut_ptr().offset(i as isize),
            &*((*u).vec).as_ptr().offset(i as isize),
            &*((*v).vec).as_ptr().offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyveck_shiftl(
    mut params: *mut ml_dsa_params,
    mut v: *mut polyveck,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).k as libc::c_uint {
        ml_dsa_poly_shiftl(&mut *((*v).vec).as_mut_ptr().offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyveck_ntt(
    mut params: *mut ml_dsa_params,
    mut v: *mut polyveck,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).k as libc::c_uint {
        ml_dsa_poly_ntt(&mut *((*v).vec).as_mut_ptr().offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyveck_invntt_tomont(
    mut params: *mut ml_dsa_params,
    mut v: *mut polyveck,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).k as libc::c_uint {
        ml_dsa_poly_invntt_tomont(&mut *((*v).vec).as_mut_ptr().offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyveck_pointwise_poly_montgomery(
    mut params: *mut ml_dsa_params,
    mut r: *mut polyveck,
    mut a: *const ml_dsa_poly,
    mut v: *const polyveck,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).k as libc::c_uint {
        ml_dsa_poly_pointwise_montgomery(
            &mut *((*r).vec).as_mut_ptr().offset(i as isize),
            a,
            &*((*v).vec).as_ptr().offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyveck_chknorm(
    mut params: *mut ml_dsa_params,
    mut v: *const polyveck,
    mut bound: int32_t,
) -> libc::c_int {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).k as libc::c_uint {
        if ml_dsa_poly_chknorm(&*((*v).vec).as_ptr().offset(i as isize), bound) != 0 {
            return 1 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyveck_power2round(
    mut params: *mut ml_dsa_params,
    mut v1: *mut polyveck,
    mut v0: *mut polyveck,
    mut v: *const polyveck,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).k as libc::c_uint {
        ml_dsa_poly_power2round(
            &mut *((*v1).vec).as_mut_ptr().offset(i as isize),
            &mut *((*v0).vec).as_mut_ptr().offset(i as isize),
            &*((*v).vec).as_ptr().offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyveck_decompose(
    mut params: *mut ml_dsa_params,
    mut v1: *mut polyveck,
    mut v0: *mut polyveck,
    mut v: *const polyveck,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).k as libc::c_uint {
        ml_dsa_poly_decompose(
            params,
            &mut *((*v1).vec).as_mut_ptr().offset(i as isize),
            &mut *((*v0).vec).as_mut_ptr().offset(i as isize),
            &*((*v).vec).as_ptr().offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyveck_make_hint(
    mut params: *mut ml_dsa_params,
    mut h: *mut polyveck,
    mut v0: *const polyveck,
    mut v1: *const polyveck,
) -> libc::c_uint {
    let mut i: libc::c_uint = 0;
    let mut s: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).k as libc::c_uint {
        s = s
            .wrapping_add(
                ml_dsa_poly_make_hint(
                    params,
                    &mut *((*h).vec).as_mut_ptr().offset(i as isize),
                    &*((*v0).vec).as_ptr().offset(i as isize),
                    &*((*v1).vec).as_ptr().offset(i as isize),
                ),
            );
        i = i.wrapping_add(1);
        i;
    }
    return s;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyveck_use_hint(
    mut params: *mut ml_dsa_params,
    mut w: *mut polyveck,
    mut u: *const polyveck,
    mut h: *const polyveck,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).k as libc::c_uint {
        ml_dsa_poly_use_hint(
            params,
            &mut *((*w).vec).as_mut_ptr().offset(i as isize),
            &*((*u).vec).as_ptr().offset(i as isize),
            &*((*h).vec).as_ptr().offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_polyveck_pack_w1(
    mut params: *mut ml_dsa_params,
    mut r: *mut uint8_t,
    mut w1: *const polyveck,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).k as libc::c_uint {
        ml_dsa_polyw1_pack(
            params,
            &mut *r.offset((i as size_t * (*params).poly_w1_packed_bytes) as isize),
            &*((*w1).vec).as_ptr().offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_pack_pk_from_sk(
    mut params: *mut ml_dsa_params,
    mut pk: *mut uint8_t,
    mut sk: *const uint8_t,
) -> libc::c_int {
    let mut rho: [uint8_t; 32] = [0; 32];
    let mut tr: [uint8_t; 64] = [0; 64];
    let mut tr_validate: [uint8_t; 64] = [0; 64];
    let mut key: [uint8_t; 32] = [0; 32];
    let mut mat: [polyvecl; 8] = [polyvecl {
        vec: [ml_dsa_poly { coeffs: [0; 256] }; 7],
    }; 8];
    let mut s1: polyvecl = polyvecl {
        vec: [ml_dsa_poly { coeffs: [0; 256] }; 7],
    };
    let mut s2: polyveck = polyveck {
        vec: [ml_dsa_poly { coeffs: [0; 256] }; 8],
    };
    let mut t1: polyveck = polyveck {
        vec: [ml_dsa_poly { coeffs: [0; 256] }; 8],
    };
    let mut t0: polyveck = polyveck {
        vec: [ml_dsa_poly { coeffs: [0; 256] }; 8],
    };
    ml_dsa_unpack_sk(
        params,
        rho.as_mut_ptr(),
        tr.as_mut_ptr(),
        key.as_mut_ptr(),
        &mut t0,
        &mut s1,
        &mut s2,
        sk,
    );
    ml_dsa_polyvec_matrix_expand(
        params,
        mat.as_mut_ptr(),
        rho.as_mut_ptr() as *const uint8_t,
    );
    ml_dsa_polyvecl_ntt(params, &mut s1);
    ml_dsa_polyvec_matrix_pointwise_montgomery(
        params,
        &mut t1,
        mat.as_mut_ptr(),
        &mut s1,
    );
    ml_dsa_polyveck_reduce(params, &mut t1);
    ml_dsa_polyveck_invntt_tomont(params, &mut t1);
    ml_dsa_polyveck_add(params, &mut t1, &mut t1, &mut s2);
    ml_dsa_polyveck_caddq(params, &mut t1);
    ml_dsa_polyveck_power2round(params, &mut t1, &mut t0, &mut t1);
    ml_dsa_pack_pk(params, pk, rho.as_mut_ptr() as *const uint8_t, &mut t1);
    SHAKE256(
        pk,
        (*params).public_key_bytes,
        tr_validate.as_mut_ptr(),
        64 as libc::c_int as size_t,
    );
    return OPENSSL_memcmp(
        tr_validate.as_mut_ptr() as *const libc::c_void,
        tr.as_mut_ptr() as *const libc::c_void,
        64 as libc::c_int as size_t,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_pack_pk(
    mut params: *mut ml_dsa_params,
    mut pk: *mut uint8_t,
    mut rho: *const uint8_t,
    mut t1: *const polyveck,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 32 as libc::c_int as libc::c_uint {
        *pk.offset(i as isize) = *rho.offset(i as isize);
        i = i.wrapping_add(1);
        i;
    }
    pk = pk.offset(32 as libc::c_int as isize);
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).k as libc::c_uint {
        ml_dsa_polyt1_pack(
            pk.offset(i.wrapping_mul(320 as libc::c_int as libc::c_uint) as isize),
            &*((*t1).vec).as_ptr().offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_unpack_pk(
    mut params: *mut ml_dsa_params,
    mut rho: *mut uint8_t,
    mut t1: *mut polyveck,
    mut pk: *const uint8_t,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 32 as libc::c_int as libc::c_uint {
        *rho.offset(i as isize) = *pk.offset(i as isize);
        i = i.wrapping_add(1);
        i;
    }
    pk = pk.offset(32 as libc::c_int as isize);
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).k as libc::c_uint {
        ml_dsa_polyt1_unpack(
            &mut *((*t1).vec).as_mut_ptr().offset(i as isize),
            pk.offset(i.wrapping_mul(320 as libc::c_int as libc::c_uint) as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_pack_sk(
    mut params: *mut ml_dsa_params,
    mut sk: *mut uint8_t,
    mut rho: *const uint8_t,
    mut tr: *const uint8_t,
    mut key: *const uint8_t,
    mut t0: *const polyveck,
    mut s1: *const polyvecl,
    mut s2: *const polyveck,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 32 as libc::c_int as libc::c_uint {
        *sk.offset(i as isize) = *rho.offset(i as isize);
        i = i.wrapping_add(1);
        i;
    }
    sk = sk.offset(32 as libc::c_int as isize);
    i = 0 as libc::c_int as libc::c_uint;
    while i < 32 as libc::c_int as libc::c_uint {
        *sk.offset(i as isize) = *key.offset(i as isize);
        i = i.wrapping_add(1);
        i;
    }
    sk = sk.offset(32 as libc::c_int as isize);
    i = 0 as libc::c_int as libc::c_uint;
    while i < 64 as libc::c_int as libc::c_uint {
        *sk.offset(i as isize) = *tr.offset(i as isize);
        i = i.wrapping_add(1);
        i;
    }
    sk = sk.offset(64 as libc::c_int as isize);
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).l as libc::c_uint {
        ml_dsa_polyeta_pack(
            params,
            sk.offset((i as size_t * (*params).poly_eta_packed_bytes) as isize),
            &*((*s1).vec).as_ptr().offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
    sk = sk.offset(((*params).l as size_t * (*params).poly_eta_packed_bytes) as isize);
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).k as libc::c_uint {
        ml_dsa_polyeta_pack(
            params,
            sk.offset((i as size_t * (*params).poly_eta_packed_bytes) as isize),
            &*((*s2).vec).as_ptr().offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
    sk = sk.offset(((*params).k as size_t * (*params).poly_eta_packed_bytes) as isize);
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).k as libc::c_uint {
        ml_dsa_polyt0_pack(
            sk.offset(i.wrapping_mul(416 as libc::c_int as libc::c_uint) as isize),
            &*((*t0).vec).as_ptr().offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_unpack_sk(
    mut params: *mut ml_dsa_params,
    mut rho: *mut uint8_t,
    mut tr: *mut uint8_t,
    mut key: *mut uint8_t,
    mut t0: *mut polyveck,
    mut s1: *mut polyvecl,
    mut s2: *mut polyveck,
    mut sk: *const uint8_t,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 32 as libc::c_int as libc::c_uint {
        *rho.offset(i as isize) = *sk.offset(i as isize);
        i = i.wrapping_add(1);
        i;
    }
    sk = sk.offset(32 as libc::c_int as isize);
    i = 0 as libc::c_int as libc::c_uint;
    while i < 32 as libc::c_int as libc::c_uint {
        *key.offset(i as isize) = *sk.offset(i as isize);
        i = i.wrapping_add(1);
        i;
    }
    sk = sk.offset(32 as libc::c_int as isize);
    i = 0 as libc::c_int as libc::c_uint;
    while i < 64 as libc::c_int as libc::c_uint {
        *tr.offset(i as isize) = *sk.offset(i as isize);
        i = i.wrapping_add(1);
        i;
    }
    sk = sk.offset(64 as libc::c_int as isize);
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).l as libc::c_uint {
        ml_dsa_polyeta_unpack(
            params,
            &mut *((*s1).vec).as_mut_ptr().offset(i as isize),
            sk.offset((i as size_t * (*params).poly_eta_packed_bytes) as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
    sk = sk.offset(((*params).l as size_t * (*params).poly_eta_packed_bytes) as isize);
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).k as libc::c_uint {
        ml_dsa_polyeta_unpack(
            params,
            &mut *((*s2).vec).as_mut_ptr().offset(i as isize),
            sk.offset((i as size_t * (*params).poly_eta_packed_bytes) as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
    sk = sk.offset(((*params).k as size_t * (*params).poly_eta_packed_bytes) as isize);
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).k as libc::c_uint {
        ml_dsa_polyt0_unpack(
            &mut *((*t0).vec).as_mut_ptr().offset(i as isize),
            sk.offset(i.wrapping_mul(416 as libc::c_int as libc::c_uint) as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_pack_sig(
    mut params: *mut ml_dsa_params,
    mut sig: *mut uint8_t,
    mut c: *const uint8_t,
    mut z: *const polyvecl,
    mut h: *const polyveck,
) {
    let mut i: libc::c_uint = 0;
    let mut j: libc::c_uint = 0;
    let mut k: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while (i as size_t) < (*params).c_tilde_bytes {
        *sig.offset(i as isize) = *c.offset(i as isize);
        i = i.wrapping_add(1);
        i;
    }
    sig = sig.offset((*params).c_tilde_bytes as isize);
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).l as libc::c_uint {
        ml_dsa_polyz_pack(
            params,
            sig.offset((i as size_t * (*params).poly_z_packed_bytes) as isize),
            &*((*z).vec).as_ptr().offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
    sig = sig.offset(((*params).l as size_t * (*params).poly_z_packed_bytes) as isize);
    i = 0 as libc::c_int as libc::c_uint;
    while (i as size_t) < ((*params).omega).wrapping_add((*params).k as size_t) {
        *sig.offset(i as isize) = 0 as libc::c_int as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
    k = 0 as libc::c_int as libc::c_uint;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).k as libc::c_uint {
        j = 0 as libc::c_int as libc::c_uint;
        while j < 256 as libc::c_int as libc::c_uint {
            if (*h).vec[i as usize].coeffs[j as usize] != 0 as libc::c_int {
                let fresh27 = k;
                k = k.wrapping_add(1);
                *sig.offset(fresh27 as isize) = j as uint8_t;
            }
            j = j.wrapping_add(1);
            j;
        }
        *sig.offset(((*params).omega).wrapping_add(i as size_t) as isize) = k as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_unpack_sig(
    mut params: *mut ml_dsa_params,
    mut c: *mut uint8_t,
    mut z: *mut polyvecl,
    mut h: *mut polyveck,
    mut sig: *const uint8_t,
) -> libc::c_int {
    let mut i: libc::c_uint = 0;
    let mut j: libc::c_uint = 0;
    let mut k: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while (i as size_t) < (*params).c_tilde_bytes {
        *c.offset(i as isize) = *sig.offset(i as isize);
        i = i.wrapping_add(1);
        i;
    }
    sig = sig.offset((*params).c_tilde_bytes as isize);
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).l as libc::c_uint {
        ml_dsa_polyz_unpack(
            params,
            &mut *((*z).vec).as_mut_ptr().offset(i as isize),
            sig.offset((i as size_t * (*params).poly_z_packed_bytes) as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
    sig = sig.offset(((*params).l as size_t * (*params).poly_z_packed_bytes) as isize);
    k = 0 as libc::c_int as libc::c_uint;
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*params).k as libc::c_uint {
        j = 0 as libc::c_int as libc::c_uint;
        while j < 256 as libc::c_int as libc::c_uint {
            (*h).vec[i as usize].coeffs[j as usize] = 0 as libc::c_int;
            j = j.wrapping_add(1);
            j;
        }
        if (*sig.offset(((*params).omega).wrapping_add(i as size_t) as isize)
            as libc::c_uint) < k
            || *sig.offset(((*params).omega).wrapping_add(i as size_t) as isize)
                as size_t > (*params).omega
        {
            return 1 as libc::c_int;
        }
        j = k;
        while j
            < *sig.offset(((*params).omega).wrapping_add(i as size_t) as isize)
                as libc::c_uint
        {
            if j > k
                && *sig.offset(j as isize) as libc::c_int
                    <= *sig
                        .offset(
                            j.wrapping_sub(1 as libc::c_int as libc::c_uint) as isize,
                        ) as libc::c_int
            {
                return 1 as libc::c_int;
            }
            (*h)
                .vec[i as usize]
                .coeffs[*sig.offset(j as isize) as usize] = 1 as libc::c_int;
            j = j.wrapping_add(1);
            j;
        }
        k = *sig.offset(((*params).omega).wrapping_add(i as size_t) as isize)
            as libc::c_uint;
        i = i.wrapping_add(1);
        i;
    }
    j = k;
    while (j as size_t) < (*params).omega {
        if *sig.offset(j as isize) != 0 {
            return 1 as libc::c_int;
        }
        j = j.wrapping_add(1);
        j;
    }
    return 0 as libc::c_int;
}
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
unsafe extern "C" fn boringssl_ensure_ml_dsa_self_test() {}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_power2round(
    mut a0: *mut int32_t,
    mut a: int32_t,
) -> int32_t {
    let mut a1: int32_t = 0;
    a1 = a + ((1 as libc::c_int) << 13 as libc::c_int - 1 as libc::c_int)
        - 1 as libc::c_int >> 13 as libc::c_int;
    *a0 = a - (a1 << 13 as libc::c_int);
    return a1;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_decompose(
    mut params: *mut ml_dsa_params,
    mut a0: *mut int32_t,
    mut a: int32_t,
) -> int32_t {
    if (*params).gamma2
        == (8380417 as libc::c_int - 1 as libc::c_int) / 32 as libc::c_int
        || (*params).gamma2
            == (8380417 as libc::c_int - 1 as libc::c_int) / 88 as libc::c_int
    {} else {
        __assert_fail(
            b"(params->gamma2 == (ML_DSA_Q-1)/32) || (params->gamma2 == (ML_DSA_Q-1)/88)\0"
                as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ml_dsa/./ml_dsa_ref/rounding.c\0"
                as *const u8 as *const libc::c_char,
            43 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 62],
                &[libc::c_char; 62],
            >(b"int32_t ml_dsa_decompose(ml_dsa_params *, int32_t *, int32_t)\0"))
                .as_ptr(),
        );
    }
    'c_23554: {
        if (*params).gamma2
            == (8380417 as libc::c_int - 1 as libc::c_int) / 32 as libc::c_int
            || (*params).gamma2
                == (8380417 as libc::c_int - 1 as libc::c_int) / 88 as libc::c_int
        {} else {
            __assert_fail(
                b"(params->gamma2 == (ML_DSA_Q-1)/32) || (params->gamma2 == (ML_DSA_Q-1)/88)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ml_dsa/./ml_dsa_ref/rounding.c\0"
                    as *const u8 as *const libc::c_char,
                43 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 62],
                    &[libc::c_char; 62],
                >(b"int32_t ml_dsa_decompose(ml_dsa_params *, int32_t *, int32_t)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut a1: int32_t = 0;
    a1 = a + 127 as libc::c_int >> 7 as libc::c_int;
    if (*params).gamma2
        == (8380417 as libc::c_int - 1 as libc::c_int) / 32 as libc::c_int
    {
        a1 = a1 * 1025 as libc::c_int + ((1 as libc::c_int) << 21 as libc::c_int)
            >> 22 as libc::c_int;
        a1 &= 15 as libc::c_int;
    }
    if (*params).gamma2
        == (8380417 as libc::c_int - 1 as libc::c_int) / 88 as libc::c_int
    {
        a1 = a1 * 11275 as libc::c_int + ((1 as libc::c_int) << 23 as libc::c_int)
            >> 24 as libc::c_int;
        a1 ^= 43 as libc::c_int - a1 >> 31 as libc::c_int & a1;
    }
    *a0 = a - a1 * 2 as libc::c_int * (*params).gamma2;
    *a0
        -= (8380417 as libc::c_int - 1 as libc::c_int) / 2 as libc::c_int - *a0
            >> 31 as libc::c_int & 8380417 as libc::c_int;
    return a1;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_make_hint(
    mut params: *mut ml_dsa_params,
    mut a0: int32_t,
    mut a1: int32_t,
) -> libc::c_uint {
    if a0 > (*params).gamma2 || a0 < -(*params).gamma2
        || a0 == -(*params).gamma2 && a1 != 0 as libc::c_int
    {
        return 1 as libc::c_int as libc::c_uint;
    }
    return 0 as libc::c_int as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_use_hint(
    mut params: *mut ml_dsa_params,
    mut a: int32_t,
    mut hint: libc::c_uint,
) -> int32_t {
    let mut a0: int32_t = 0;
    let mut a1: int32_t = 0;
    if (*params).gamma2
        == (8380417 as libc::c_int - 1 as libc::c_int) / 32 as libc::c_int
        || (*params).gamma2
            == (8380417 as libc::c_int - 1 as libc::c_int) / 88 as libc::c_int
    {} else {
        __assert_fail(
            b"(params->gamma2 == (ML_DSA_Q-1)/32) || (params->gamma2 == (ML_DSA_Q-1)/88)\0"
                as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ml_dsa/./ml_dsa_ref/rounding.c\0"
                as *const u8 as *const libc::c_char,
            97 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 64],
                &[libc::c_char; 64],
            >(b"int32_t ml_dsa_use_hint(ml_dsa_params *, int32_t, unsigned int)\0"))
                .as_ptr(),
        );
    }
    'c_24810: {
        if (*params).gamma2
            == (8380417 as libc::c_int - 1 as libc::c_int) / 32 as libc::c_int
            || (*params).gamma2
                == (8380417 as libc::c_int - 1 as libc::c_int) / 88 as libc::c_int
        {} else {
            __assert_fail(
                b"(params->gamma2 == (ML_DSA_Q-1)/32) || (params->gamma2 == (ML_DSA_Q-1)/88)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/ml_dsa/./ml_dsa_ref/rounding.c\0"
                    as *const u8 as *const libc::c_char,
                97 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 64],
                    &[libc::c_char; 64],
                >(b"int32_t ml_dsa_use_hint(ml_dsa_params *, int32_t, unsigned int)\0"))
                    .as_ptr(),
            );
        }
    };
    a1 = ml_dsa_decompose(params, &mut a0, a);
    if hint == 0 as libc::c_int as libc::c_uint {
        return a1;
    }
    if (*params).gamma2
        == (8380417 as libc::c_int - 1 as libc::c_int) / 32 as libc::c_int
    {
        if a0 > 0 as libc::c_int {
            return a1 + 1 as libc::c_int & 15 as libc::c_int
        } else {
            return a1 - 1 as libc::c_int & 15 as libc::c_int
        }
    } else if a0 > 0 as libc::c_int {
        return if a1 == 43 as libc::c_int {
            0 as libc::c_int
        } else {
            a1 + 1 as libc::c_int
        }
    } else {
        return if a1 == 0 as libc::c_int {
            43 as libc::c_int
        } else {
            a1 - 1 as libc::c_int
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_44_keypair_internal(
    mut public_key: *mut uint8_t,
    mut private_key: *mut uint8_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    return ml_dsa_44_keypair_internal_no_self_test(public_key, private_key, seed);
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_44_keypair_internal_no_self_test(
    mut public_key: *mut uint8_t,
    mut private_key: *mut uint8_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_44_params_init(&mut params);
    return (ml_dsa_keypair_internal(&mut params, public_key, private_key, seed)
        == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_44_keypair(
    mut public_key: *mut uint8_t,
    mut private_key: *mut uint8_t,
    mut seed: *mut uint8_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_44_params_init(&mut params);
    return (ml_dsa_keypair(&mut params, public_key, private_key, seed)
        == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_44_pack_pk_from_sk(
    mut public_key: *mut uint8_t,
    mut private_key: *const uint8_t,
) -> libc::c_int {
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_44_params_init(&mut params);
    return (ml_dsa_pack_pk_from_sk(&mut params, public_key, private_key)
        == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_44_sign(
    mut private_key: *const uint8_t,
    mut sig: *mut uint8_t,
    mut sig_len: *mut size_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut ctx_string: *const uint8_t,
    mut ctx_string_len: size_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_44_params_init(&mut params);
    return (ml_dsa_sign(
        &mut params,
        sig,
        sig_len,
        message,
        message_len,
        ctx_string,
        ctx_string_len,
        private_key,
    ) == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_extmu_44_sign(
    mut private_key: *const uint8_t,
    mut sig: *mut uint8_t,
    mut sig_len: *mut size_t,
    mut mu: *const uint8_t,
    mut mu_len: size_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_44_params_init(&mut params);
    return (ml_dsa_extmu_sign(&mut params, sig, sig_len, mu, mu_len, private_key)
        == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_44_sign_internal(
    mut private_key: *const uint8_t,
    mut sig: *mut uint8_t,
    mut sig_len: *mut size_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut pre: *const uint8_t,
    mut pre_len: size_t,
    mut rnd: *const uint8_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    return ml_dsa_44_sign_internal_no_self_test(
        private_key,
        sig,
        sig_len,
        message,
        message_len,
        pre,
        pre_len,
        rnd,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_44_sign_internal_no_self_test(
    mut private_key: *const uint8_t,
    mut sig: *mut uint8_t,
    mut sig_len: *mut size_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut pre: *const uint8_t,
    mut pre_len: size_t,
    mut rnd: *const uint8_t,
) -> libc::c_int {
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_44_params_init(&mut params);
    return (ml_dsa_sign_internal(
        &mut params,
        sig,
        sig_len,
        message,
        message_len,
        pre,
        pre_len,
        rnd,
        private_key,
        0 as libc::c_int,
    ) == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_extmu_44_sign_internal(
    mut private_key: *const uint8_t,
    mut sig: *mut uint8_t,
    mut sig_len: *mut size_t,
    mut mu: *const uint8_t,
    mut mu_len: size_t,
    mut pre: *const uint8_t,
    mut pre_len: size_t,
    mut rnd: *const uint8_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_44_params_init(&mut params);
    return (ml_dsa_sign_internal(
        &mut params,
        sig,
        sig_len,
        mu,
        mu_len,
        pre,
        pre_len,
        rnd,
        private_key,
        1 as libc::c_int,
    ) == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_44_verify(
    mut public_key: *const uint8_t,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut ctx_string: *const uint8_t,
    mut ctx_string_len: size_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_44_params_init(&mut params);
    return (ml_dsa_verify(
        &mut params,
        sig,
        sig_len,
        message,
        message_len,
        ctx_string,
        ctx_string_len,
        public_key,
    ) == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_extmu_44_verify(
    mut public_key: *const uint8_t,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
    mut mu: *const uint8_t,
    mut mu_len: size_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_44_params_init(&mut params);
    return (ml_dsa_verify_internal(
        &mut params,
        sig,
        sig_len,
        mu,
        mu_len,
        0 as *const uint8_t,
        0 as libc::c_int as size_t,
        public_key,
        1 as libc::c_int,
    ) == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_44_verify_internal(
    mut public_key: *const uint8_t,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut pre: *const uint8_t,
    mut pre_len: size_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    return ml_dsa_44_verify_internal_no_self_test(
        public_key,
        sig,
        sig_len,
        message,
        message_len,
        pre,
        pre_len,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_44_verify_internal_no_self_test(
    mut public_key: *const uint8_t,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut pre: *const uint8_t,
    mut pre_len: size_t,
) -> libc::c_int {
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_44_params_init(&mut params);
    return (ml_dsa_verify_internal(
        &mut params,
        sig,
        sig_len,
        message,
        message_len,
        pre,
        pre_len,
        public_key,
        0 as libc::c_int,
    ) == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_extmu_44_verify_internal(
    mut public_key: *const uint8_t,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
    mut mu: *const uint8_t,
    mut mu_len: size_t,
    mut pre: *const uint8_t,
    mut pre_len: size_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_44_params_init(&mut params);
    return (ml_dsa_verify_internal(
        &mut params,
        sig,
        sig_len,
        mu,
        mu_len,
        pre,
        pre_len,
        public_key,
        1 as libc::c_int,
    ) == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_65_keypair(
    mut public_key: *mut uint8_t,
    mut private_key: *mut uint8_t,
    mut seed: *mut uint8_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_65_params_init(&mut params);
    return (ml_dsa_keypair(&mut params, public_key, private_key, seed)
        == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_65_pack_pk_from_sk(
    mut public_key: *mut uint8_t,
    mut private_key: *const uint8_t,
) -> libc::c_int {
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_65_params_init(&mut params);
    return (ml_dsa_pack_pk_from_sk(&mut params, public_key, private_key)
        == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_65_keypair_internal(
    mut public_key: *mut uint8_t,
    mut private_key: *mut uint8_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_65_params_init(&mut params);
    return (ml_dsa_keypair_internal(&mut params, public_key, private_key, seed)
        == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_65_sign(
    mut private_key: *const uint8_t,
    mut sig: *mut uint8_t,
    mut sig_len: *mut size_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut ctx_string: *const uint8_t,
    mut ctx_string_len: size_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_65_params_init(&mut params);
    return (ml_dsa_sign(
        &mut params,
        sig,
        sig_len,
        message,
        message_len,
        ctx_string,
        ctx_string_len,
        private_key,
    ) == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_extmu_65_sign(
    mut private_key: *const uint8_t,
    mut sig: *mut uint8_t,
    mut sig_len: *mut size_t,
    mut mu: *const uint8_t,
    mut mu_len: size_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_65_params_init(&mut params);
    return (ml_dsa_extmu_sign(&mut params, sig, sig_len, mu, mu_len, private_key)
        == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_65_sign_internal(
    mut private_key: *const uint8_t,
    mut sig: *mut uint8_t,
    mut sig_len: *mut size_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut pre: *const uint8_t,
    mut pre_len: size_t,
    mut rnd: *const uint8_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_65_params_init(&mut params);
    return (ml_dsa_sign_internal(
        &mut params,
        sig,
        sig_len,
        message,
        message_len,
        pre,
        pre_len,
        rnd,
        private_key,
        0 as libc::c_int,
    ) == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_extmu_65_sign_internal(
    mut private_key: *const uint8_t,
    mut sig: *mut uint8_t,
    mut sig_len: *mut size_t,
    mut mu: *const uint8_t,
    mut mu_len: size_t,
    mut pre: *const uint8_t,
    mut pre_len: size_t,
    mut rnd: *const uint8_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_65_params_init(&mut params);
    return (ml_dsa_sign_internal(
        &mut params,
        sig,
        sig_len,
        mu,
        mu_len,
        pre,
        pre_len,
        rnd,
        private_key,
        1 as libc::c_int,
    ) == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_65_verify(
    mut public_key: *const uint8_t,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut ctx_string: *const uint8_t,
    mut ctx_string_len: size_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_65_params_init(&mut params);
    return (ml_dsa_verify(
        &mut params,
        sig,
        sig_len,
        message,
        message_len,
        ctx_string,
        ctx_string_len,
        public_key,
    ) == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_extmu_65_verify(
    mut public_key: *const uint8_t,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
    mut mu: *const uint8_t,
    mut mu_len: size_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_65_params_init(&mut params);
    return (ml_dsa_verify_internal(
        &mut params,
        sig,
        sig_len,
        mu,
        mu_len,
        0 as *const uint8_t,
        0 as libc::c_int as size_t,
        public_key,
        1 as libc::c_int,
    ) == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_65_verify_internal(
    mut public_key: *const uint8_t,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut pre: *const uint8_t,
    mut pre_len: size_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_65_params_init(&mut params);
    return (ml_dsa_verify_internal(
        &mut params,
        sig,
        sig_len,
        message,
        message_len,
        pre,
        pre_len,
        public_key,
        0 as libc::c_int,
    ) == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_extmu_65_verify_internal(
    mut public_key: *const uint8_t,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
    mut mu: *const uint8_t,
    mut mu_len: size_t,
    mut pre: *const uint8_t,
    mut pre_len: size_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_65_params_init(&mut params);
    return (ml_dsa_verify_internal(
        &mut params,
        sig,
        sig_len,
        mu,
        mu_len,
        pre,
        pre_len,
        public_key,
        1 as libc::c_int,
    ) == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_87_keypair(
    mut public_key: *mut uint8_t,
    mut private_key: *mut uint8_t,
    mut seed: *mut uint8_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_87_params_init(&mut params);
    return (ml_dsa_keypair(&mut params, public_key, private_key, seed)
        == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_87_pack_pk_from_sk(
    mut public_key: *mut uint8_t,
    mut private_key: *const uint8_t,
) -> libc::c_int {
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_87_params_init(&mut params);
    return (ml_dsa_pack_pk_from_sk(&mut params, public_key, private_key)
        == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_87_keypair_internal(
    mut public_key: *mut uint8_t,
    mut private_key: *mut uint8_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_87_params_init(&mut params);
    return (ml_dsa_keypair_internal(&mut params, public_key, private_key, seed)
        == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_87_sign(
    mut private_key: *const uint8_t,
    mut sig: *mut uint8_t,
    mut sig_len: *mut size_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut ctx_string: *const uint8_t,
    mut ctx_string_len: size_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_87_params_init(&mut params);
    return (ml_dsa_sign(
        &mut params,
        sig,
        sig_len,
        message,
        message_len,
        ctx_string,
        ctx_string_len,
        private_key,
    ) == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_extmu_87_sign(
    mut private_key: *const uint8_t,
    mut sig: *mut uint8_t,
    mut sig_len: *mut size_t,
    mut mu: *const uint8_t,
    mut mu_len: size_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_87_params_init(&mut params);
    return (ml_dsa_extmu_sign(&mut params, sig, sig_len, mu, mu_len, private_key)
        == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_87_sign_internal(
    mut private_key: *const uint8_t,
    mut sig: *mut uint8_t,
    mut sig_len: *mut size_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut pre: *const uint8_t,
    mut pre_len: size_t,
    mut rnd: *const uint8_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_87_params_init(&mut params);
    return (ml_dsa_sign_internal(
        &mut params,
        sig,
        sig_len,
        message,
        message_len,
        pre,
        pre_len,
        rnd,
        private_key,
        0 as libc::c_int,
    ) == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_extmu_87_sign_internal(
    mut private_key: *const uint8_t,
    mut sig: *mut uint8_t,
    mut sig_len: *mut size_t,
    mut mu: *const uint8_t,
    mut mu_len: size_t,
    mut pre: *const uint8_t,
    mut pre_len: size_t,
    mut rnd: *const uint8_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_87_params_init(&mut params);
    return (ml_dsa_sign_internal(
        &mut params,
        sig,
        sig_len,
        mu,
        mu_len,
        pre,
        pre_len,
        rnd,
        private_key,
        1 as libc::c_int,
    ) == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_87_verify(
    mut public_key: *const uint8_t,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut ctx_string: *const uint8_t,
    mut ctx_string_len: size_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_87_params_init(&mut params);
    return (ml_dsa_verify(
        &mut params,
        sig,
        sig_len,
        message,
        message_len,
        ctx_string,
        ctx_string_len,
        public_key,
    ) == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_extmu_87_verify(
    mut public_key: *const uint8_t,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
    mut mu: *const uint8_t,
    mut mu_len: size_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_87_params_init(&mut params);
    return (ml_dsa_verify_internal(
        &mut params,
        sig,
        sig_len,
        mu,
        mu_len,
        0 as *const uint8_t,
        0 as libc::c_int as size_t,
        public_key,
        1 as libc::c_int,
    ) == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_87_verify_internal(
    mut public_key: *const uint8_t,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut pre: *const uint8_t,
    mut pre_len: size_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_87_params_init(&mut params);
    return (ml_dsa_verify_internal(
        &mut params,
        sig,
        sig_len,
        message,
        message_len,
        pre,
        pre_len,
        public_key,
        0 as libc::c_int,
    ) == 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ml_dsa_extmu_87_verify_internal(
    mut public_key: *const uint8_t,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
    mut mu: *const uint8_t,
    mut mu_len: size_t,
    mut pre: *const uint8_t,
    mut pre_len: size_t,
) -> libc::c_int {
    boringssl_ensure_ml_dsa_self_test();
    let mut params: ml_dsa_params = ml_dsa_params {
        k: 0,
        l: 0,
        eta: 0,
        tau: 0,
        beta: 0,
        gamma1: 0,
        gamma2: 0,
        omega: 0,
        c_tilde_bytes: 0,
        poly_vech_packed_bytes: 0,
        poly_z_packed_bytes: 0,
        poly_w1_packed_bytes: 0,
        poly_eta_packed_bytes: 0,
        public_key_bytes: 0,
        secret_key_bytes: 0,
        bytes: 0,
    };
    ml_dsa_87_params_init(&mut params);
    return (ml_dsa_verify_internal(
        &mut params,
        sig,
        sig_len,
        mu,
        mu_len,
        pre,
        pre_len,
        public_key,
        1 as libc::c_int,
    ) == 0 as libc::c_int) as libc::c_int;
}
