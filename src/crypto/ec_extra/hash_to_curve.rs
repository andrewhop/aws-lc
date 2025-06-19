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
    pub type bignum_ctx;
    pub type engine_st;
    pub type evp_md_pctx_ops;
    pub type evp_pkey_ctx_st;
    pub type env_md_st;
    fn BN_num_bits(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_num_bytes(bn: *const BIGNUM) -> libc::c_uint;
    fn ec_scalar_reduce(
        group: *const EC_GROUP,
        out: *mut EC_SCALAR,
        words: *const BN_ULONG,
        num: size_t,
    );
    fn ec_felem_one(group: *const EC_GROUP) -> *const EC_FELEM;
    fn ec_felem_to_bytes(
        group: *const EC_GROUP,
        out: *mut uint8_t,
        out_len: *mut size_t,
        in_0: *const EC_FELEM,
    );
    fn ec_felem_from_bytes(
        group: *const EC_GROUP,
        out: *mut EC_FELEM,
        in_0: *const uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn ec_felem_neg(group: *const EC_GROUP, out: *mut EC_FELEM, a: *const EC_FELEM);
    fn ec_felem_add(
        group: *const EC_GROUP,
        out: *mut EC_FELEM,
        a: *const EC_FELEM,
        b: *const EC_FELEM,
    );
    fn ec_felem_sub(
        group: *const EC_GROUP,
        out: *mut EC_FELEM,
        a: *const EC_FELEM,
        b: *const EC_FELEM,
    );
    fn ec_felem_non_zero_mask(group: *const EC_GROUP, a: *const EC_FELEM) -> BN_ULONG;
    fn ec_felem_select(
        group: *const EC_GROUP,
        out: *mut EC_FELEM,
        mask: BN_ULONG,
        a: *const EC_FELEM,
        b: *const EC_FELEM,
    );
    fn EC_GROUP_cmp(
        a: *const EC_GROUP,
        b: *const EC_GROUP,
        ignored: *mut BN_CTX,
    ) -> libc::c_int;
    fn EC_GROUP_get0_order(group: *const EC_GROUP) -> *const BIGNUM;
    fn EC_GROUP_get_curve_name(group: *const EC_GROUP) -> libc::c_int;
    fn EVP_sha256() -> *const EVP_MD;
    fn EVP_sha384() -> *const EVP_MD;
    fn EVP_sha512() -> *const EVP_MD;
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
    fn EVP_MD_block_size(md: *const EVP_MD) -> size_t;
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
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn bn_copy_words(out: *mut BN_ULONG, num: size_t, bn: *const BIGNUM) -> libc::c_int;
    fn bn_rshift_words(
        r: *mut BN_ULONG,
        a: *const BN_ULONG,
        shift: libc::c_uint,
        num: size_t,
    );
    fn bn_big_endian_to_words(
        out: *mut BN_ULONG,
        out_len: size_t,
        in_0: *const uint8_t,
        in_len: size_t,
    );
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
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
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_68_error_is_hashed_DST_still_too_large {
    #[bitfield(
        name = "static_assertion_at_line_68_error_is_hashed_DST_still_too_large",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_68_error_is_hashed_DST_still_too_large: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
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
unsafe extern "C" fn expand_message_xmd(
    mut md: *const EVP_MD,
    mut out: *mut uint8_t,
    mut out_len: size_t,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
    mut dst: *const uint8_t,
    mut dst_len: size_t,
) -> libc::c_int {
    let mut dst_len_u8: uint8_t = 0;
    static mut kZeros: [uint8_t; 128] = [
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
    ];
    let mut l_i_b_str_zero: [uint8_t; 3] = [0; 3];
    let mut b_0: [uint8_t; 64] = [0; 64];
    let mut b_i: [uint8_t; 64] = [0; 64];
    let mut i: uint8_t = 0;
    let mut current_block: u64;
    if dst_len == 0 as libc::c_int as size_t {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/hash_to_curve.c\0"
                as *const u8 as *const libc::c_char,
            57 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let block_size: size_t = EVP_MD_block_size(md);
    let md_size: size_t = EVP_MD_size(md);
    let mut ctx: EVP_MD_CTX = env_md_ctx_st {
        digest: 0 as *const EVP_MD,
        md_data: 0 as *mut libc::c_void,
        update: None,
        pctx: 0 as *mut EVP_PKEY_CTX,
        pctx_ops: 0 as *const evp_md_pctx_ops,
        flags: 0,
    };
    EVP_MD_CTX_init(&mut ctx);
    let mut dst_buf: [uint8_t; 64] = [0; 64];
    if dst_len >= 256 as libc::c_int as size_t {
        static mut kPrefix: [libc::c_char; 18] = unsafe {
            *::core::mem::transmute::<
                &[u8; 18],
                &[libc::c_char; 18],
            >(b"H2C-OVERSIZE-DST-\0")
        };
        if EVP_DigestInit_ex(&mut ctx, md, 0 as *mut ENGINE) == 0
            || EVP_DigestUpdate(
                &mut ctx,
                kPrefix.as_ptr() as *const libc::c_void,
                (::core::mem::size_of::<[libc::c_char; 18]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
            ) == 0
            || EVP_DigestUpdate(&mut ctx, dst as *const libc::c_void, dst_len) == 0
            || EVP_DigestFinal_ex(&mut ctx, dst_buf.as_mut_ptr(), 0 as *mut libc::c_uint)
                == 0
        {
            current_block = 9945885859088939402;
        } else {
            dst = dst_buf.as_mut_ptr();
            dst_len = md_size;
            current_block = 3640593987805443782;
        }
    } else {
        current_block = 3640593987805443782;
    }
    match current_block {
        3640593987805443782 => {
            dst_len_u8 = dst_len as uint8_t;
            l_i_b_str_zero = [
                (out_len >> 8 as libc::c_int) as uint8_t,
                out_len as uint8_t,
                0 as libc::c_int as uint8_t,
            ];
            b_0 = [0; 64];
            if !(EVP_DigestInit_ex(&mut ctx, md, 0 as *mut ENGINE) == 0
                || EVP_DigestUpdate(
                    &mut ctx,
                    kZeros.as_ptr() as *const libc::c_void,
                    block_size,
                ) == 0
                || EVP_DigestUpdate(&mut ctx, msg as *const libc::c_void, msg_len) == 0
                || EVP_DigestUpdate(
                    &mut ctx,
                    l_i_b_str_zero.as_mut_ptr() as *const libc::c_void,
                    ::core::mem::size_of::<[uint8_t; 3]>() as libc::c_ulong,
                ) == 0
                || EVP_DigestUpdate(&mut ctx, dst as *const libc::c_void, dst_len) == 0
                || EVP_DigestUpdate(
                    &mut ctx,
                    &mut dst_len_u8 as *mut uint8_t as *const libc::c_void,
                    1 as libc::c_int as size_t,
                ) == 0
                || EVP_DigestFinal_ex(&mut ctx, b_0.as_mut_ptr(), 0 as *mut libc::c_uint)
                    == 0)
            {
                b_i = [0; 64];
                i = 1 as libc::c_int as uint8_t;
                loop {
                    if !(out_len > 0 as libc::c_int as size_t) {
                        current_block = 14648156034262866959;
                        break;
                    }
                    if i as libc::c_int == 0 as libc::c_int {
                        ERR_put_error(
                            15 as libc::c_int,
                            0 as libc::c_int,
                            4 as libc::c_int | 64 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/hash_to_curve.c\0"
                                as *const u8 as *const libc::c_char,
                            104 as libc::c_int as libc::c_uint,
                        );
                        current_block = 9945885859088939402;
                        break;
                    } else {
                        if i as libc::c_int > 1 as libc::c_int {
                            let mut j: size_t = 0 as libc::c_int as size_t;
                            while j < md_size {
                                b_i[j
                                    as usize] = (b_i[j as usize] as libc::c_int
                                    ^ b_0[j as usize] as libc::c_int) as uint8_t;
                                j = j.wrapping_add(1);
                                j;
                            }
                        } else {
                            OPENSSL_memcpy(
                                b_i.as_mut_ptr() as *mut libc::c_void,
                                b_0.as_mut_ptr() as *const libc::c_void,
                                md_size,
                            );
                        }
                        if EVP_DigestInit_ex(&mut ctx, md, 0 as *mut ENGINE) == 0
                            || EVP_DigestUpdate(
                                &mut ctx,
                                b_i.as_mut_ptr() as *const libc::c_void,
                                md_size,
                            ) == 0
                            || EVP_DigestUpdate(
                                &mut ctx,
                                &mut i as *mut uint8_t as *const libc::c_void,
                                1 as libc::c_int as size_t,
                            ) == 0
                            || EVP_DigestUpdate(
                                &mut ctx,
                                dst as *const libc::c_void,
                                dst_len,
                            ) == 0
                            || EVP_DigestUpdate(
                                &mut ctx,
                                &mut dst_len_u8 as *mut uint8_t as *const libc::c_void,
                                1 as libc::c_int as size_t,
                            ) == 0
                            || EVP_DigestFinal_ex(
                                &mut ctx,
                                b_i.as_mut_ptr(),
                                0 as *mut libc::c_uint,
                            ) == 0
                        {
                            current_block = 9945885859088939402;
                            break;
                        }
                        let mut todo: size_t = if out_len >= md_size {
                            md_size
                        } else {
                            out_len
                        };
                        OPENSSL_memcpy(
                            out as *mut libc::c_void,
                            b_i.as_mut_ptr() as *const libc::c_void,
                            todo,
                        );
                        out = out.offset(todo as isize);
                        out_len = out_len.wrapping_sub(todo);
                        i = i.wrapping_add(1);
                        i;
                    }
                }
                match current_block {
                    9945885859088939402 => {}
                    _ => {
                        ret = 1 as libc::c_int;
                    }
                }
            }
        }
        _ => {}
    }
    EVP_MD_CTX_cleanup(&mut ctx);
    return ret;
}
unsafe extern "C" fn num_bytes_to_derive(
    mut out: *mut size_t,
    mut modulus: *const BIGNUM,
    mut k: libc::c_uint,
) -> libc::c_int {
    let mut bits: size_t = BN_num_bits(modulus) as size_t;
    let mut L: size_t = bits
        .wrapping_add(k as size_t)
        .wrapping_add(7 as libc::c_int as size_t) / 8 as libc::c_int as size_t;
    if L * 8 as libc::c_int as size_t
        >= (2 as libc::c_int as size_t * bits).wrapping_sub(2 as libc::c_int as size_t)
        || L > (2 as libc::c_int * 66 as libc::c_int) as size_t
    {
        __assert_fail(
            b"0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/hash_to_curve.c\0"
                as *const u8 as *const libc::c_char,
            150 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 64],
                &[libc::c_char; 64],
            >(b"int num_bytes_to_derive(size_t *, const BIGNUM *, unsigned int)\0"))
                .as_ptr(),
        );
        'c_3638: {
            __assert_fail(
                b"0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/hash_to_curve.c\0"
                    as *const u8 as *const libc::c_char,
                150 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 64],
                    &[libc::c_char; 64],
                >(b"int num_bytes_to_derive(size_t *, const BIGNUM *, unsigned int)\0"))
                    .as_ptr(),
            );
        };
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            4 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/hash_to_curve.c\0"
                as *const u8 as *const libc::c_char,
            151 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    *out = L;
    return 1 as libc::c_int;
}
unsafe extern "C" fn hash_to_field2(
    mut group: *const EC_GROUP,
    mut md: *const EVP_MD,
    mut out1: *mut EC_FELEM,
    mut out2: *mut EC_FELEM,
    mut dst: *const uint8_t,
    mut dst_len: size_t,
    mut k: libc::c_uint,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> libc::c_int {
    let mut L: size_t = 0;
    let mut buf: [uint8_t; 264] = [0; 264];
    if num_bytes_to_derive(&mut L, &(*group).field.N, k) == 0
        || expand_message_xmd(
            md,
            buf.as_mut_ptr(),
            2 as libc::c_int as size_t * L,
            msg,
            msg_len,
            dst,
            dst_len,
        ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut words: [BN_ULONG; 18] = [0; 18];
    let mut num_words: size_t = (2 as libc::c_int * (*group).field.N.width) as size_t;
    bn_big_endian_to_words(words.as_mut_ptr(), num_words, buf.as_mut_ptr(), L);
    ((*(*group).meth).felem_reduce)
        .expect("non-null function pointer")(group, out1, words.as_mut_ptr(), num_words);
    bn_big_endian_to_words(
        words.as_mut_ptr(),
        num_words,
        buf.as_mut_ptr().offset(L as isize),
        L,
    );
    ((*(*group).meth).felem_reduce)
        .expect("non-null function pointer")(group, out2, words.as_mut_ptr(), num_words);
    return 1 as libc::c_int;
}
unsafe extern "C" fn hash_to_scalar(
    mut group: *const EC_GROUP,
    mut md: *const EVP_MD,
    mut out: *mut EC_SCALAR,
    mut dst: *const uint8_t,
    mut dst_len: size_t,
    mut k: libc::c_uint,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> libc::c_int {
    let mut order: *const BIGNUM = EC_GROUP_get0_order(group);
    let mut L: size_t = 0;
    let mut buf: [uint8_t; 132] = [0; 132];
    if num_bytes_to_derive(&mut L, order, k) == 0
        || expand_message_xmd(md, buf.as_mut_ptr(), L, msg, msg_len, dst, dst_len) == 0
    {
        return 0 as libc::c_int;
    }
    let mut words: [BN_ULONG; 18] = [0; 18];
    let mut num_words: size_t = (2 as libc::c_int * (*order).width) as size_t;
    bn_big_endian_to_words(words.as_mut_ptr(), num_words, buf.as_mut_ptr(), L);
    ec_scalar_reduce(group, out, words.as_mut_ptr(), num_words);
    return 1 as libc::c_int;
}
#[inline]
unsafe extern "C" fn mul_A(
    mut group: *const EC_GROUP,
    mut out: *mut EC_FELEM,
    mut in_0: *const EC_FELEM,
) {
    if (*group).a_is_minus3 != 0 {} else {
        __assert_fail(
            b"group->a_is_minus3\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/hash_to_curve.c\0"
                as *const u8 as *const libc::c_char,
            202 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 59],
                &[libc::c_char; 59],
            >(b"void mul_A(const EC_GROUP *, EC_FELEM *, const EC_FELEM *)\0"))
                .as_ptr(),
        );
    }
    'c_2537: {
        if (*group).a_is_minus3 != 0 {} else {
            __assert_fail(
                b"group->a_is_minus3\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/hash_to_curve.c\0"
                    as *const u8 as *const libc::c_char,
                202 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 59],
                    &[libc::c_char; 59],
                >(b"void mul_A(const EC_GROUP *, EC_FELEM *, const EC_FELEM *)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut tmp: EC_FELEM = EC_FELEM { words: [0; 9] };
    ec_felem_add(group, &mut tmp, in_0, in_0);
    ec_felem_add(group, &mut tmp, &mut tmp, &mut tmp);
    ec_felem_sub(group, out, in_0, &mut tmp);
}
unsafe extern "C" fn sgn0(
    mut group: *const EC_GROUP,
    mut a: *const EC_FELEM,
) -> BN_ULONG {
    let mut buf: [uint8_t; 66] = [0; 66];
    let mut len: size_t = 0;
    ec_felem_to_bytes(group, buf.as_mut_ptr(), &mut len, a);
    return (buf[len.wrapping_sub(1 as libc::c_int as size_t) as usize] as libc::c_int
        & 1 as libc::c_int) as BN_ULONG;
}
unsafe extern "C" fn is_3mod4(mut group: *const EC_GROUP) -> libc::c_int {
    return ((*group).field.N.width > 0 as libc::c_int
        && *((*group).field.N.d).offset(0 as libc::c_int as isize)
            & 3 as libc::c_int as BN_ULONG == 3 as libc::c_int as BN_ULONG)
        as libc::c_int;
}
unsafe extern "C" fn sqrt_ratio_3mod4(
    mut group: *const EC_GROUP,
    mut Z: *const EC_FELEM,
    mut c1: *const BN_ULONG,
    mut num_c1: size_t,
    mut c2: *const EC_FELEM,
    mut out_y: *mut EC_FELEM,
    mut u: *const EC_FELEM,
    mut v: *const EC_FELEM,
) -> BN_ULONG {
    if is_3mod4(group) != 0 {} else {
        __assert_fail(
            b"is_3mod4(group)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/hash_to_curve.c\0"
                as *const u8 as *const libc::c_char,
            227 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 154],
                &[libc::c_char; 154],
            >(
                b"BN_ULONG sqrt_ratio_3mod4(const EC_GROUP *, const EC_FELEM *, const BN_ULONG *, size_t, const EC_FELEM *, EC_FELEM *, const EC_FELEM *, const EC_FELEM *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2272: {
        if is_3mod4(group) != 0 {} else {
            __assert_fail(
                b"is_3mod4(group)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/hash_to_curve.c\0"
                    as *const u8 as *const libc::c_char,
                227 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 154],
                    &[libc::c_char; 154],
                >(
                    b"BN_ULONG sqrt_ratio_3mod4(const EC_GROUP *, const EC_FELEM *, const BN_ULONG *, size_t, const EC_FELEM *, EC_FELEM *, const EC_FELEM *, const EC_FELEM *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let felem_mul: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_FELEM,
            *const EC_FELEM,
            *const EC_FELEM,
        ) -> (),
    > = (*(*group).meth).felem_mul;
    let felem_sqr: Option::<
        unsafe extern "C" fn(*const EC_GROUP, *mut EC_FELEM, *const EC_FELEM) -> (),
    > = (*(*group).meth).felem_sqr;
    let mut tv1: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut tv2: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut tv3: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut y1: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut y2: EC_FELEM = EC_FELEM { words: [0; 9] };
    felem_sqr.expect("non-null function pointer")(group, &mut tv1, v);
    felem_mul.expect("non-null function pointer")(group, &mut tv2, u, v);
    felem_mul.expect("non-null function pointer")(group, &mut tv1, &mut tv1, &mut tv2);
    ((*(*group).meth).felem_exp)
        .expect("non-null function pointer")(group, &mut y1, &mut tv1, c1, num_c1);
    felem_mul.expect("non-null function pointer")(group, &mut y1, &mut y1, &mut tv2);
    felem_mul.expect("non-null function pointer")(group, &mut y2, &mut y1, c2);
    felem_sqr.expect("non-null function pointer")(group, &mut tv3, &mut y1);
    felem_mul.expect("non-null function pointer")(group, &mut tv3, &mut tv3, v);
    ec_felem_sub(group, &mut tv1, &mut tv3, u);
    let isQR: BN_ULONG = !ec_felem_non_zero_mask(group, &mut tv1);
    ec_felem_select(group, out_y, isQR, &mut y1, &mut y2);
    return isQR;
}
unsafe extern "C" fn map_to_curve_simple_swu(
    mut group: *const EC_GROUP,
    mut Z: *const EC_FELEM,
    mut c1: *const BN_ULONG,
    mut num_c1: size_t,
    mut c2: *const EC_FELEM,
    mut out: *mut EC_JACOBIAN,
    mut u: *const EC_FELEM,
) {
    if is_3mod4(group) != 0 {} else {
        __assert_fail(
            b"is_3mod4(group)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/hash_to_curve.c\0"
                as *const u8 as *const libc::c_char,
            263 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 142],
                &[libc::c_char; 142],
            >(
                b"void map_to_curve_simple_swu(const EC_GROUP *, const EC_FELEM *, const BN_ULONG *, size_t, const EC_FELEM *, EC_JACOBIAN *, const EC_FELEM *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2759: {
        if is_3mod4(group) != 0 {} else {
            __assert_fail(
                b"is_3mod4(group)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/hash_to_curve.c\0"
                    as *const u8 as *const libc::c_char,
                263 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 142],
                    &[libc::c_char; 142],
                >(
                    b"void map_to_curve_simple_swu(const EC_GROUP *, const EC_FELEM *, const BN_ULONG *, size_t, const EC_FELEM *, EC_JACOBIAN *, const EC_FELEM *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if (*group).a_is_minus3 != 0 {} else {
        __assert_fail(
            b"group->a_is_minus3\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/hash_to_curve.c\0"
                as *const u8 as *const libc::c_char,
            264 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 142],
                &[libc::c_char; 142],
            >(
                b"void map_to_curve_simple_swu(const EC_GROUP *, const EC_FELEM *, const BN_ULONG *, size_t, const EC_FELEM *, EC_JACOBIAN *, const EC_FELEM *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2722: {
        if (*group).a_is_minus3 != 0 {} else {
            __assert_fail(
                b"group->a_is_minus3\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/hash_to_curve.c\0"
                    as *const u8 as *const libc::c_char,
                264 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 142],
                    &[libc::c_char; 142],
                >(
                    b"void map_to_curve_simple_swu(const EC_GROUP *, const EC_FELEM *, const BN_ULONG *, size_t, const EC_FELEM *, EC_JACOBIAN *, const EC_FELEM *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let felem_mul: Option::<
        unsafe extern "C" fn(
            *const EC_GROUP,
            *mut EC_FELEM,
            *const EC_FELEM,
            *const EC_FELEM,
        ) -> (),
    > = (*(*group).meth).felem_mul;
    let felem_sqr: Option::<
        unsafe extern "C" fn(*const EC_GROUP, *mut EC_FELEM, *const EC_FELEM) -> (),
    > = (*(*group).meth).felem_sqr;
    let mut tv1: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut tv2: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut tv3: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut tv4: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut tv5: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut tv6: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut x: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut y: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut y1: EC_FELEM = EC_FELEM { words: [0; 9] };
    felem_sqr.expect("non-null function pointer")(group, &mut tv1, u);
    felem_mul.expect("non-null function pointer")(group, &mut tv1, Z, &mut tv1);
    felem_sqr.expect("non-null function pointer")(group, &mut tv2, &mut tv1);
    ec_felem_add(group, &mut tv2, &mut tv2, &mut tv1);
    ec_felem_add(group, &mut tv3, &mut tv2, ec_felem_one(group));
    felem_mul
        .expect("non-null function pointer")(group, &mut tv3, &(*group).b, &mut tv3);
    let tv2_non_zero: BN_ULONG = ec_felem_non_zero_mask(group, &mut tv2);
    ec_felem_neg(group, &mut tv4, &mut tv2);
    ec_felem_select(group, &mut tv4, tv2_non_zero, &mut tv4, Z);
    mul_A(group, &mut tv4, &mut tv4);
    felem_sqr.expect("non-null function pointer")(group, &mut tv2, &mut tv3);
    felem_sqr.expect("non-null function pointer")(group, &mut tv6, &mut tv4);
    mul_A(group, &mut tv5, &mut tv6);
    ec_felem_add(group, &mut tv2, &mut tv2, &mut tv5);
    felem_mul.expect("non-null function pointer")(group, &mut tv2, &mut tv2, &mut tv3);
    felem_mul.expect("non-null function pointer")(group, &mut tv6, &mut tv6, &mut tv4);
    felem_mul
        .expect("non-null function pointer")(group, &mut tv5, &(*group).b, &mut tv6);
    ec_felem_add(group, &mut tv2, &mut tv2, &mut tv5);
    felem_mul.expect("non-null function pointer")(group, &mut x, &mut tv1, &mut tv3);
    let is_gx1_square: BN_ULONG = sqrt_ratio_3mod4(
        group,
        Z,
        c1,
        num_c1,
        c2,
        &mut y1,
        &mut tv2,
        &mut tv6,
    );
    felem_mul.expect("non-null function pointer")(group, &mut y, &mut tv1, u);
    felem_mul.expect("non-null function pointer")(group, &mut y, &mut y, &mut y1);
    ec_felem_select(group, &mut x, is_gx1_square, &mut tv3, &mut x);
    ec_felem_select(group, &mut y, is_gx1_square, &mut y1, &mut y);
    let mut sgn0_u: BN_ULONG = sgn0(group, u);
    let mut sgn0_y: BN_ULONG = sgn0(group, &mut y);
    let mut not_e1: BN_ULONG = sgn0_u ^ sgn0_y;
    not_e1 = (0 as libc::c_int as BN_ULONG).wrapping_sub(not_e1);
    ec_felem_neg(group, &mut tv1, &mut y);
    ec_felem_select(group, &mut y, not_e1, &mut tv1, &mut y);
    felem_mul
        .expect("non-null function pointer")(group, &mut (*out).X, &mut x, &mut tv4);
    felem_mul
        .expect("non-null function pointer")(group, &mut (*out).Y, &mut y, &mut tv6);
    (*out).Z = tv4;
}
unsafe extern "C" fn hash_to_curve(
    mut group: *const EC_GROUP,
    mut md: *const EVP_MD,
    mut Z: *const EC_FELEM,
    mut c2: *const EC_FELEM,
    mut k: libc::c_uint,
    mut out: *mut EC_JACOBIAN,
    mut dst: *const uint8_t,
    mut dst_len: size_t,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> libc::c_int {
    let mut u0: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut u1: EC_FELEM = EC_FELEM { words: [0; 9] };
    if hash_to_field2(group, md, &mut u0, &mut u1, dst, dst_len, k, msg, msg_len) == 0 {
        return 0 as libc::c_int;
    }
    let mut c1: [BN_ULONG; 9] = [0; 9];
    let mut num_c1: size_t = (*group).field.N.width as size_t;
    if bn_copy_words(c1.as_mut_ptr(), num_c1, &(*group).field.N) == 0 {
        return 0 as libc::c_int;
    }
    bn_rshift_words(
        c1.as_mut_ptr(),
        c1.as_mut_ptr(),
        2 as libc::c_int as libc::c_uint,
        num_c1,
    );
    let mut Q0: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    let mut Q1: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    map_to_curve_simple_swu(group, Z, c1.as_mut_ptr(), num_c1, c2, &mut Q0, &mut u0);
    map_to_curve_simple_swu(group, Z, c1.as_mut_ptr(), num_c1, c2, &mut Q1, &mut u1);
    ((*(*group).meth).add)
        .expect("non-null function pointer")(group, out, &mut Q0, &mut Q1);
    return 1 as libc::c_int;
}
unsafe extern "C" fn felem_from_u8(
    mut group: *const EC_GROUP,
    mut out: *mut EC_FELEM,
    mut a: uint8_t,
) -> libc::c_int {
    let mut bytes: [uint8_t; 66] = [
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
    ];
    let mut len: size_t = BN_num_bytes(&(*group).field.N) as size_t;
    bytes[len.wrapping_sub(1 as libc::c_int as size_t) as usize] = a;
    return ec_felem_from_bytes(group, out, bytes.as_mut_ptr(), len);
}
static mut kP256Sqrt10: [uint8_t; 32] = [
    0xda as libc::c_int as uint8_t,
    0x53 as libc::c_int as uint8_t,
    0x8e as libc::c_int as uint8_t,
    0x3b as libc::c_int as uint8_t,
    0xe1 as libc::c_int as uint8_t,
    0xd8 as libc::c_int as uint8_t,
    0x9b as libc::c_int as uint8_t,
    0x99 as libc::c_int as uint8_t,
    0xc9 as libc::c_int as uint8_t,
    0x78 as libc::c_int as uint8_t,
    0xfc as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x51 as libc::c_int as uint8_t,
    0x80 as libc::c_int as uint8_t,
    0xaa as libc::c_int as uint8_t,
    0xb2 as libc::c_int as uint8_t,
    0x7b as libc::c_int as uint8_t,
    0x8d as libc::c_int as uint8_t,
    0x1f as libc::c_int as uint8_t,
    0xf8 as libc::c_int as uint8_t,
    0x4c as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0xd5 as libc::c_int as uint8_t,
    0xb6 as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0xcd as libc::c_int as uint8_t,
    0x34 as libc::c_int as uint8_t,
    0x27 as libc::c_int as uint8_t,
    0xe4 as libc::c_int as uint8_t,
    0x33 as libc::c_int as uint8_t,
    0xc4 as libc::c_int as uint8_t,
    0x7f as libc::c_int as uint8_t,
];
static mut kP384Sqrt12: [uint8_t; 48] = [
    0x2a as libc::c_int as uint8_t,
    0xcc as libc::c_int as uint8_t,
    0xb4 as libc::c_int as uint8_t,
    0xa6 as libc::c_int as uint8_t,
    0x56 as libc::c_int as uint8_t,
    0xb0 as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x9c as libc::c_int as uint8_t,
    0x71 as libc::c_int as uint8_t,
    0xf0 as libc::c_int as uint8_t,
    0x50 as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x83 as libc::c_int as uint8_t,
    0xda as libc::c_int as uint8_t,
    0x2f as libc::c_int as uint8_t,
    0xdd as libc::c_int as uint8_t,
    0x7f as libc::c_int as uint8_t,
    0x98 as libc::c_int as uint8_t,
    0xe3 as libc::c_int as uint8_t,
    0x83 as libc::c_int as uint8_t,
    0xd6 as libc::c_int as uint8_t,
    0x8b as libc::c_int as uint8_t,
    0x53 as libc::c_int as uint8_t,
    0x87 as libc::c_int as uint8_t,
    0x1f as libc::c_int as uint8_t,
    0x87 as libc::c_int as uint8_t,
    0x2f as libc::c_int as uint8_t,
    0xcb as libc::c_int as uint8_t,
    0x9c as libc::c_int as uint8_t,
    0xcb as libc::c_int as uint8_t,
    0x80 as libc::c_int as uint8_t,
    0xc5 as libc::c_int as uint8_t,
    0x3c as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0xe1 as libc::c_int as uint8_t,
    0xf8 as libc::c_int as uint8_t,
    0xa8 as libc::c_int as uint8_t,
    0xf as libc::c_int as uint8_t,
    0x7e as libc::c_int as uint8_t,
    0x19 as libc::c_int as uint8_t,
    0x14 as libc::c_int as uint8_t,
    0xe2 as libc::c_int as uint8_t,
    0xec as libc::c_int as uint8_t,
    0x69 as libc::c_int as uint8_t,
    0xf5 as libc::c_int as uint8_t,
    0xa6 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0xb3 as libc::c_int as uint8_t,
];
#[no_mangle]
pub unsafe extern "C" fn ec_hash_to_curve_p256_xmd_sha256_sswu(
    mut group: *const EC_GROUP,
    mut out: *mut EC_JACOBIAN,
    mut dst: *const uint8_t,
    mut dst_len: size_t,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> libc::c_int {
    if EC_GROUP_get_curve_name(group) != 415 as libc::c_int {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            130 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/hash_to_curve.c\0"
                as *const u8 as *const libc::c_char,
            393 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut Z: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut c2: EC_FELEM = EC_FELEM { words: [0; 9] };
    if felem_from_u8(group, &mut Z, 10 as libc::c_int as uint8_t) == 0
        || ec_felem_from_bytes(
            group,
            &mut c2,
            kP256Sqrt10.as_ptr(),
            ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
        ) == 0
    {
        return 0 as libc::c_int;
    }
    ec_felem_neg(group, &mut Z, &mut Z);
    return hash_to_curve(
        group,
        EVP_sha256(),
        &mut Z,
        &mut c2,
        128 as libc::c_int as libc::c_uint,
        out,
        dst,
        dst_len,
        msg,
        msg_len,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EC_hash_to_curve_p256_xmd_sha256_sswu(
    mut group: *const EC_GROUP,
    mut out: *mut EC_POINT,
    mut dst: *const uint8_t,
    mut dst_len: size_t,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> libc::c_int {
    if EC_GROUP_cmp(group, (*out).group, 0 as *mut BN_CTX) != 0 as libc::c_int {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/hash_to_curve.c\0"
                as *const u8 as *const libc::c_char,
            413 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ec_hash_to_curve_p256_xmd_sha256_sswu(
        group,
        &mut (*out).raw,
        dst,
        dst_len,
        msg,
        msg_len,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ec_hash_to_curve_p384_xmd_sha384_sswu(
    mut group: *const EC_GROUP,
    mut out: *mut EC_JACOBIAN,
    mut dst: *const uint8_t,
    mut dst_len: size_t,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> libc::c_int {
    if EC_GROUP_get_curve_name(group) != 715 as libc::c_int {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            130 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/hash_to_curve.c\0"
                as *const u8 as *const libc::c_char,
            426 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut Z: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut c2: EC_FELEM = EC_FELEM { words: [0; 9] };
    if felem_from_u8(group, &mut Z, 12 as libc::c_int as uint8_t) == 0
        || ec_felem_from_bytes(
            group,
            &mut c2,
            kP384Sqrt12.as_ptr(),
            ::core::mem::size_of::<[uint8_t; 48]>() as libc::c_ulong,
        ) == 0
    {
        return 0 as libc::c_int;
    }
    ec_felem_neg(group, &mut Z, &mut Z);
    return hash_to_curve(
        group,
        EVP_sha384(),
        &mut Z,
        &mut c2,
        192 as libc::c_int as libc::c_uint,
        out,
        dst,
        dst_len,
        msg,
        msg_len,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EC_hash_to_curve_p384_xmd_sha384_sswu(
    mut group: *const EC_GROUP,
    mut out: *mut EC_POINT,
    mut dst: *const uint8_t,
    mut dst_len: size_t,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> libc::c_int {
    if EC_GROUP_cmp(group, (*out).group, 0 as *mut BN_CTX) != 0 as libc::c_int {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            106 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/hash_to_curve.c\0"
                as *const u8 as *const libc::c_char,
            446 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ec_hash_to_curve_p384_xmd_sha384_sswu(
        group,
        &mut (*out).raw,
        dst,
        dst_len,
        msg,
        msg_len,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ec_hash_to_scalar_p384_xmd_sha384(
    mut group: *const EC_GROUP,
    mut out: *mut EC_SCALAR,
    mut dst: *const uint8_t,
    mut dst_len: size_t,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> libc::c_int {
    if EC_GROUP_get_curve_name(group) != 715 as libc::c_int {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            130 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/hash_to_curve.c\0"
                as *const u8 as *const libc::c_char,
            457 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return hash_to_scalar(
        group,
        EVP_sha384(),
        out,
        dst,
        dst_len,
        192 as libc::c_int as libc::c_uint,
        msg,
        msg_len,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ec_hash_to_curve_p384_xmd_sha512_sswu_draft07(
    mut group: *const EC_GROUP,
    mut out: *mut EC_JACOBIAN,
    mut dst: *const uint8_t,
    mut dst_len: size_t,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> libc::c_int {
    if EC_GROUP_get_curve_name(group) != 715 as libc::c_int {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            130 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/hash_to_curve.c\0"
                as *const u8 as *const libc::c_char,
            470 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut Z: EC_FELEM = EC_FELEM { words: [0; 9] };
    let mut c2: EC_FELEM = EC_FELEM { words: [0; 9] };
    if felem_from_u8(group, &mut Z, 12 as libc::c_int as uint8_t) == 0
        || ec_felem_from_bytes(
            group,
            &mut c2,
            kP384Sqrt12.as_ptr(),
            ::core::mem::size_of::<[uint8_t; 48]>() as libc::c_ulong,
        ) == 0
    {
        return 0 as libc::c_int;
    }
    ec_felem_neg(group, &mut Z, &mut Z);
    return hash_to_curve(
        group,
        EVP_sha512(),
        &mut Z,
        &mut c2,
        192 as libc::c_int as libc::c_uint,
        out,
        dst,
        dst_len,
        msg,
        msg_len,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ec_hash_to_scalar_p384_xmd_sha512_draft07(
    mut group: *const EC_GROUP,
    mut out: *mut EC_SCALAR,
    mut dst: *const uint8_t,
    mut dst_len: size_t,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> libc::c_int {
    if EC_GROUP_get_curve_name(group) != 715 as libc::c_int {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            130 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/hash_to_curve.c\0"
                as *const u8 as *const libc::c_char,
            490 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return hash_to_scalar(
        group,
        EVP_sha512(),
        out,
        dst,
        dst_len,
        192 as libc::c_int as libc::c_uint,
        msg,
        msg_len,
    );
}
