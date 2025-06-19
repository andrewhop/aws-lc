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
    pub type engine_st;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_get_asn1(
        cbs: *mut CBS,
        out: *mut CBS,
        tag_value: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBS_get_asn1_uint64(cbs: *mut CBS, out: *mut uint64_t) -> libc::c_int;
    fn CBB_init(cbb: *mut CBB, initial_capacity: size_t) -> libc::c_int;
    fn CBB_cleanup(cbb: *mut CBB);
    fn CBB_flush(cbb: *mut CBB) -> libc::c_int;
    fn CBB_data(cbb: *const CBB) -> *const uint8_t;
    fn CBB_len(cbb: *const CBB) -> size_t;
    fn CBB_add_asn1(
        cbb: *mut CBB,
        out_contents: *mut CBB,
        tag: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBB_add_asn1_uint64(cbb: *mut CBB, value: uint64_t) -> libc::c_int;
    fn CBB_add_asn1_octet_string(
        cbb: *mut CBB,
        data: *const uint8_t,
        data_len: size_t,
    ) -> libc::c_int;
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
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type uintptr_t = libc::c_ulong;
pub type CBS_ASN1_TAG = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cbb_st {
    pub child: *mut CBB,
    pub is_child: libc::c_char,
    pub u: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub base: cbb_buffer_st,
    pub child: cbb_child_st,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct cbb_child_st {
    pub base: *mut cbb_buffer_st,
    pub offset: size_t,
    pub pending_len_len: uint8_t,
    #[bitfield(name = "pending_is_asn1", ty = "libc::c_uint", bits = "0..=0")]
    pub pending_is_asn1: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 6],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct cbb_buffer_st {
    pub buf: *mut uint8_t,
    pub len: size_t,
    pub cap: size_t,
    #[bitfield(name = "can_resize", ty = "libc::c_uint", bits = "0..=0")]
    #[bitfield(name = "error", ty = "libc::c_uint", bits = "1..=1")]
    pub can_resize_error: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
pub type CBB = cbb_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cbs_st {
    pub data: *const uint8_t,
    pub len: size_t,
}
pub type CBS = cbs_st;
pub type ENGINE = engine_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_aead_st {
    pub key_len: uint8_t,
    pub nonce_len: uint8_t,
    pub overhead: uint8_t,
    pub max_tag_len: uint8_t,
    pub aead_id: uint16_t,
    pub seal_scatter_supports_extra_in: libc::c_int,
    pub init: Option::<
        unsafe extern "C" fn(
            *mut EVP_AEAD_CTX,
            *const uint8_t,
            size_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub init_with_direction: Option::<
        unsafe extern "C" fn(
            *mut EVP_AEAD_CTX,
            *const uint8_t,
            size_t,
            size_t,
            evp_aead_direction_t,
        ) -> libc::c_int,
    >,
    pub cleanup: Option::<unsafe extern "C" fn(*mut EVP_AEAD_CTX) -> ()>,
    pub open: Option::<
        unsafe extern "C" fn(
            *const EVP_AEAD_CTX,
            *mut uint8_t,
            *mut size_t,
            size_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub seal_scatter: Option::<
        unsafe extern "C" fn(
            *const EVP_AEAD_CTX,
            *mut uint8_t,
            *mut uint8_t,
            *mut size_t,
            size_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub open_gather: Option::<
        unsafe extern "C" fn(
            *const EVP_AEAD_CTX,
            *mut uint8_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub get_iv: Option::<
        unsafe extern "C" fn(
            *const EVP_AEAD_CTX,
            *mut *const uint8_t,
            *mut size_t,
        ) -> libc::c_int,
    >,
    pub tag_len: Option::<
        unsafe extern "C" fn(*const EVP_AEAD_CTX, size_t, size_t) -> size_t,
    >,
    pub serialize_state: Option::<
        unsafe extern "C" fn(*const EVP_AEAD_CTX, *mut CBB) -> libc::c_int,
    >,
    pub deserialize_state: Option::<
        unsafe extern "C" fn(*const EVP_AEAD_CTX, *mut CBS) -> libc::c_int,
    >,
}
pub type EVP_AEAD_CTX = evp_aead_ctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_aead_ctx_st {
    pub aead: *const EVP_AEAD,
    pub state: evp_aead_ctx_st_state,
    pub state_offset: uint8_t,
    pub tag_len: uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union evp_aead_ctx_st_state {
    pub opaque: [uint8_t; 564],
    pub alignment: uint64_t,
    pub ptr: *mut libc::c_void,
}
pub type EVP_AEAD = evp_aead_st;
pub type evp_aead_direction_t = libc::c_uint;
pub const evp_aead_seal: evp_aead_direction_t = 1;
pub const evp_aead_open: evp_aead_direction_t = 0;
#[inline]
unsafe extern "C" fn buffers_alias(
    mut a: *const uint8_t,
    mut a_len: size_t,
    mut b: *const uint8_t,
    mut b_len: size_t,
) -> libc::c_int {
    let mut a_u: uintptr_t = a as uintptr_t;
    let mut b_u: uintptr_t = b as uintptr_t;
    return (a_u.wrapping_add(a_len) > b_u && b_u.wrapping_add(b_len) > a_u)
        as libc::c_int;
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
#[inline]
unsafe extern "C" fn CRYPTO_store_u32_le(mut out: *mut libc::c_void, mut v: uint32_t) {
    OPENSSL_memcpy(
        out,
        &mut v as *mut uint32_t as *const libc::c_void,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
}
#[inline]
unsafe extern "C" fn CRYPTO_store_u64_le(mut out: *mut libc::c_void, mut v: uint64_t) {
    OPENSSL_memcpy(
        out,
        &mut v as *mut uint64_t as *const libc::c_void,
        ::core::mem::size_of::<uint64_t>() as libc::c_ulong,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_AEAD_key_length(mut aead: *const EVP_AEAD) -> size_t {
    return (*aead).key_len as size_t;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_AEAD_nonce_length(mut aead: *const EVP_AEAD) -> size_t {
    return (*aead).nonce_len as size_t;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_AEAD_max_overhead(mut aead: *const EVP_AEAD) -> size_t {
    return (*aead).overhead as size_t;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_AEAD_max_tag_len(mut aead: *const EVP_AEAD) -> size_t {
    return (*aead).max_tag_len as size_t;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_AEAD_CTX_zero(mut ctx: *mut EVP_AEAD_CTX) {
    OPENSSL_memset(
        ctx as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<EVP_AEAD_CTX>() as libc::c_ulong,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_AEAD_CTX_new(
    mut aead: *const EVP_AEAD,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut tag_len: size_t,
) -> *mut EVP_AEAD_CTX {
    let mut ctx: *mut EVP_AEAD_CTX = OPENSSL_zalloc(
        ::core::mem::size_of::<EVP_AEAD_CTX>() as libc::c_ulong,
    ) as *mut EVP_AEAD_CTX;
    if ctx.is_null() {
        return 0 as *mut EVP_AEAD_CTX;
    }
    if EVP_AEAD_CTX_init(ctx, aead, key, key_len, tag_len, 0 as *mut ENGINE) != 0 {
        return ctx;
    }
    EVP_AEAD_CTX_free(ctx);
    return 0 as *mut EVP_AEAD_CTX;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_AEAD_CTX_free(mut ctx: *mut EVP_AEAD_CTX) {
    if ctx.is_null() {
        return;
    }
    EVP_AEAD_CTX_cleanup(ctx);
    OPENSSL_free(ctx as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_AEAD_CTX_init(
    mut ctx: *mut EVP_AEAD_CTX,
    mut aead: *const EVP_AEAD,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut tag_len: size_t,
    mut impl_0: *mut ENGINE,
) -> libc::c_int {
    if ((*aead).init).is_none() {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            124 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                as *const u8 as *const libc::c_char,
            70 as libc::c_int as libc::c_uint,
        );
        (*ctx).aead = 0 as *const EVP_AEAD;
        return 0 as libc::c_int;
    }
    return EVP_AEAD_CTX_init_with_direction(
        ctx,
        aead,
        key,
        key_len,
        tag_len,
        evp_aead_open,
    );
}
#[no_mangle]
pub unsafe extern "C" fn EVP_AEAD_CTX_init_with_direction(
    mut ctx: *mut EVP_AEAD_CTX,
    mut aead: *const EVP_AEAD,
    mut key: *const uint8_t,
    mut key_len: size_t,
    mut tag_len: size_t,
    mut dir: evp_aead_direction_t,
) -> libc::c_int {
    if key_len != (*aead).key_len as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            120 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                as *const u8 as *const libc::c_char,
            84 as libc::c_int as libc::c_uint,
        );
        (*ctx).aead = 0 as *const EVP_AEAD;
        return 0 as libc::c_int;
    }
    (*ctx).aead = aead;
    let mut ok: libc::c_int = 0;
    if ((*aead).init).is_some() {
        ok = ((*aead).init)
            .expect("non-null function pointer")(ctx, key, key_len, tag_len);
    } else {
        ok = ((*aead).init_with_direction)
            .expect("non-null function pointer")(ctx, key, key_len, tag_len, dir);
    }
    if ok == 0 {
        (*ctx).aead = 0 as *const EVP_AEAD;
    }
    return ok;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_AEAD_CTX_cleanup(mut ctx: *mut EVP_AEAD_CTX) {
    if ((*ctx).aead).is_null() {
        return;
    }
    ((*(*ctx).aead).cleanup).expect("non-null function pointer")(ctx);
    (*ctx).aead = 0 as *const EVP_AEAD;
}
unsafe extern "C" fn check_alias(
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut out: *const uint8_t,
    mut out_len: size_t,
) -> libc::c_int {
    if buffers_alias(in_0, in_len, out, out_len) == 0 {
        return 1 as libc::c_int;
    }
    return (in_0 == out) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_AEAD_CTX_seal(
    mut ctx: *const EVP_AEAD_CTX,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
    mut max_out_len: size_t,
    mut nonce: *const uint8_t,
    mut nonce_len: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut ad: *const uint8_t,
    mut ad_len: size_t,
) -> libc::c_int {
    let mut out_tag_len: size_t = 0;
    if in_len.wrapping_add((*(*ctx).aead).overhead as size_t) < in_len {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            117 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                as *const u8 as *const libc::c_char,
            130 as libc::c_int as libc::c_uint,
        );
    } else if max_out_len < in_len {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            103 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                as *const u8 as *const libc::c_char,
            135 as libc::c_int as libc::c_uint,
        );
    } else if check_alias(in_0, in_len, out, max_out_len) == 0 {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            115 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                as *const u8 as *const libc::c_char,
            140 as libc::c_int as libc::c_uint,
        );
    } else {
        out_tag_len = 0;
        if ((*(*ctx).aead).seal_scatter)
            .expect(
                "non-null function pointer",
            )(
            ctx,
            out,
            out.offset(in_len as isize),
            &mut out_tag_len,
            max_out_len.wrapping_sub(in_len),
            nonce,
            nonce_len,
            in_0,
            in_len,
            0 as *const uint8_t,
            0 as libc::c_int as size_t,
            ad,
            ad_len,
        ) != 0
        {
            *out_len = in_len.wrapping_add(out_tag_len);
            return 1 as libc::c_int;
        }
    }
    OPENSSL_memset(out as *mut libc::c_void, 0 as libc::c_int, max_out_len);
    *out_len = 0 as libc::c_int as size_t;
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_AEAD_CTX_seal_scatter(
    mut ctx: *const EVP_AEAD_CTX,
    mut out: *mut uint8_t,
    mut out_tag: *mut uint8_t,
    mut out_tag_len: *mut size_t,
    mut max_out_tag_len: size_t,
    mut nonce: *const uint8_t,
    mut nonce_len: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut extra_in: *const uint8_t,
    mut extra_in_len: size_t,
    mut ad: *const uint8_t,
    mut ad_len: size_t,
) -> libc::c_int {
    if check_alias(in_0, in_len, out, in_len) == 0
        || buffers_alias(out, in_len, out_tag, max_out_tag_len) != 0
        || buffers_alias(in_0, in_len, out_tag, max_out_tag_len) != 0
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            115 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                as *const u8 as *const libc::c_char,
            172 as libc::c_int as libc::c_uint,
        );
    } else if (*(*ctx).aead).seal_scatter_supports_extra_in == 0 && extra_in_len != 0 {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            112 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                as *const u8 as *const libc::c_char,
            177 as libc::c_int as libc::c_uint,
        );
    } else if ((*(*ctx).aead).seal_scatter)
        .expect(
            "non-null function pointer",
        )(
        ctx,
        out,
        out_tag,
        out_tag_len,
        max_out_tag_len,
        nonce,
        nonce_len,
        in_0,
        in_len,
        extra_in,
        extra_in_len,
        ad,
        ad_len,
    ) != 0
    {
        return 1 as libc::c_int
    }
    OPENSSL_memset(out as *mut libc::c_void, 0 as libc::c_int, in_len);
    OPENSSL_memset(out_tag as *mut libc::c_void, 0 as libc::c_int, max_out_tag_len);
    *out_tag_len = 0 as libc::c_int as size_t;
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_AEAD_CTX_open(
    mut ctx: *const EVP_AEAD_CTX,
    mut out: *mut uint8_t,
    mut out_len: *mut size_t,
    mut max_out_len: size_t,
    mut nonce: *const uint8_t,
    mut nonce_len: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut ad: *const uint8_t,
    mut ad_len: size_t,
) -> libc::c_int {
    let mut plaintext_len: size_t = 0;
    if check_alias(in_0, in_len, out, max_out_len) == 0 {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            115 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                as *const u8 as *const libc::c_char,
            202 as libc::c_int as libc::c_uint,
        );
    } else if ((*(*ctx).aead).open).is_some() {
        if !(((*(*ctx).aead).open)
            .expect(
                "non-null function pointer",
            )(ctx, out, out_len, max_out_len, nonce, nonce_len, in_0, in_len, ad, ad_len)
            == 0)
        {
            return 1 as libc::c_int;
        }
    } else {
        if (*ctx).tag_len != 0 {} else {
            __assert_fail(
                b"ctx->tag_len\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                    as *const u8 as *const libc::c_char,
                216 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 148],
                    &[libc::c_char; 148],
                >(
                    b"int EVP_AEAD_CTX_open(const EVP_AEAD_CTX *, uint8_t *, size_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_2250: {
            if (*ctx).tag_len != 0 {} else {
                __assert_fail(
                    b"ctx->tag_len\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                        as *const u8 as *const libc::c_char,
                    216 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 148],
                        &[libc::c_char; 148],
                    >(
                        b"int EVP_AEAD_CTX_open(const EVP_AEAD_CTX *, uint8_t *, size_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        if in_len < (*ctx).tag_len as size_t {
            ERR_put_error(
                30 as libc::c_int,
                0 as libc::c_int,
                101 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                    as *const u8 as *const libc::c_char,
                219 as libc::c_int as libc::c_uint,
            );
        } else {
            plaintext_len = in_len.wrapping_sub((*ctx).tag_len as size_t);
            if max_out_len < plaintext_len {
                ERR_put_error(
                    30 as libc::c_int,
                    0 as libc::c_int,
                    103 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                        as *const u8 as *const libc::c_char,
                    225 as libc::c_int as libc::c_uint,
                );
            } else if EVP_AEAD_CTX_open_gather(
                ctx,
                out,
                nonce,
                nonce_len,
                in_0,
                plaintext_len,
                in_0.offset(plaintext_len as isize),
                (*ctx).tag_len as size_t,
                ad,
                ad_len,
            ) != 0
            {
                *out_len = plaintext_len;
                return 1 as libc::c_int;
            }
        }
    }
    OPENSSL_memset(out as *mut libc::c_void, 0 as libc::c_int, max_out_len);
    *out_len = 0 as libc::c_int as size_t;
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_AEAD_CTX_open_gather(
    mut ctx: *const EVP_AEAD_CTX,
    mut out: *mut uint8_t,
    mut nonce: *const uint8_t,
    mut nonce_len: size_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
    mut in_tag: *const uint8_t,
    mut in_tag_len: size_t,
    mut ad: *const uint8_t,
    mut ad_len: size_t,
) -> libc::c_int {
    if check_alias(in_0, in_len, out, in_len) == 0 {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            115 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                as *const u8 as *const libc::c_char,
            250 as libc::c_int as libc::c_uint,
        );
    } else if ((*(*ctx).aead).open_gather).is_none() {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                as *const u8 as *const libc::c_char,
            255 as libc::c_int as libc::c_uint,
        );
    } else if ((*(*ctx).aead).open_gather)
        .expect(
            "non-null function pointer",
        )(ctx, out, nonce, nonce_len, in_0, in_len, in_tag, in_tag_len, ad, ad_len) != 0
    {
        return 1 as libc::c_int
    }
    OPENSSL_memset(out as *mut libc::c_void, 0 as libc::c_int, in_len);
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_AEAD_CTX_aead(
    mut ctx: *const EVP_AEAD_CTX,
) -> *const EVP_AEAD {
    return (*ctx).aead;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_AEAD_CTX_get_iv(
    mut ctx: *const EVP_AEAD_CTX,
    mut out_iv: *mut *const uint8_t,
    mut out_len: *mut size_t,
) -> libc::c_int {
    if ((*(*ctx).aead).get_iv).is_none() {
        return 0 as libc::c_int;
    }
    return ((*(*ctx).aead).get_iv)
        .expect("non-null function pointer")(ctx, out_iv, out_len);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_AEAD_CTX_tag_len(
    mut ctx: *const EVP_AEAD_CTX,
    mut out_tag_len: *mut size_t,
    in_len: size_t,
    extra_in_len: size_t,
) -> libc::c_int {
    if (*(*ctx).aead).seal_scatter_supports_extra_in != 0 || extra_in_len == 0 {} else {
        __assert_fail(
            b"ctx->aead->seal_scatter_supports_extra_in || !extra_in_len\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                as *const u8 as *const libc::c_char,
            285 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 85],
                &[libc::c_char; 85],
            >(
                b"int EVP_AEAD_CTX_tag_len(const EVP_AEAD_CTX *, size_t *, const size_t, const size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2668: {
        if (*(*ctx).aead).seal_scatter_supports_extra_in != 0 || extra_in_len == 0
        {} else {
            __assert_fail(
                b"ctx->aead->seal_scatter_supports_extra_in || !extra_in_len\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                    as *const u8 as *const libc::c_char,
                285 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 85],
                    &[libc::c_char; 85],
                >(
                    b"int EVP_AEAD_CTX_tag_len(const EVP_AEAD_CTX *, size_t *, const size_t, const size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if ((*(*ctx).aead).tag_len).is_some() {
        *out_tag_len = ((*(*ctx).aead).tag_len)
            .expect("non-null function pointer")(ctx, in_len, extra_in_len);
        return 1 as libc::c_int;
    }
    if extra_in_len.wrapping_add((*ctx).tag_len as size_t) < extra_in_len {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                as *const u8 as *const libc::c_char,
            293 as libc::c_int as libc::c_uint,
        );
        *out_tag_len = 0 as libc::c_int as size_t;
        return 0 as libc::c_int;
    }
    *out_tag_len = extra_in_len.wrapping_add((*ctx).tag_len as size_t);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_AEAD_get_iv_from_ipv4_nanosecs(
    ipv4_address: uint32_t,
    nanosecs: uint64_t,
    mut out_iv: *mut uint8_t,
) -> libc::c_int {
    if out_iv.is_null() {
        return 0 as libc::c_int;
    }
    CRYPTO_store_u32_le(
        &mut *out_iv.offset(0 as libc::c_int as isize) as *mut uint8_t
            as *mut libc::c_void,
        ipv4_address,
    );
    CRYPTO_store_u64_le(
        &mut *out_iv.offset(::core::mem::size_of::<uint32_t>() as libc::c_ulong as isize)
            as *mut uint8_t as *mut libc::c_void,
        nanosecs,
    );
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn EVP_AEAD_CTX_serialize_state(
    mut ctx: *const EVP_AEAD_CTX,
    mut cbb: *mut CBB,
) -> libc::c_int {
    if ((*ctx).aead).is_null() {
        return 0 as libc::c_int;
    }
    let mut aead_id: size_t = EVP_AEAD_CTX_get_aead_id(ctx) as size_t;
    if aead_id == 0 as libc::c_int as size_t {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            1 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                as *const u8 as *const libc::c_char,
            326 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut seq: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    if CBB_add_asn1(
        cbb,
        &mut seq,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || CBB_add_asn1_uint64(&mut seq, 1 as libc::c_int as uint64_t) == 0
        || CBB_add_asn1_uint64(&mut seq, aead_id) == 0
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            1 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                as *const u8 as *const libc::c_char,
            335 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut state: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    if CBB_init(&mut state, 50 as libc::c_int as size_t) == 0 {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            1 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                as *const u8 as *const libc::c_char,
            356 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*(*ctx).aead).serialize_state).is_some() {
        if ((*(*ctx).aead).serialize_state)
            .expect("non-null function pointer")(ctx, &mut state) == 0
        {
            CBB_cleanup(&mut state);
            ERR_put_error(
                30 as libc::c_int,
                0 as libc::c_int,
                1 as libc::c_int | 64 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                    as *const u8 as *const libc::c_char,
                363 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    }
    if CBB_add_asn1_octet_string(&mut seq, CBB_data(&mut state), CBB_len(&mut state))
        == 0
    {
        CBB_cleanup(&mut state);
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            1 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                as *const u8 as *const libc::c_char,
            370 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    CBB_cleanup(&mut state);
    return CBB_flush(cbb);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_AEAD_CTX_deserialize_state(
    mut ctx: *const EVP_AEAD_CTX,
    mut cbs: *mut CBS,
) -> libc::c_int {
    if ((*ctx).aead).is_null() {
        return 0 as libc::c_int;
    }
    let mut seq: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut version: uint64_t = 0;
    let mut aead_id: uint64_t = 0;
    let mut state: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_get_asn1(
        cbs,
        &mut seq,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            141 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                as *const u8 as *const libc::c_char,
            390 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if CBS_get_asn1_uint64(&mut seq, &mut version) == 0
        || version != 1 as libc::c_int as uint64_t
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            143 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                as *const u8 as *const libc::c_char,
            396 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if CBS_get_asn1_uint64(&mut seq, &mut aead_id) == 0
        || aead_id > 65535 as libc::c_int as uint64_t
        || aead_id != EVP_AEAD_CTX_get_aead_id(ctx) as uint64_t
    {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            144 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                as *const u8 as *const libc::c_char,
            402 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if CBS_get_asn1(&mut seq, &mut state, 0x4 as libc::c_uint) == 0 {
        ERR_put_error(
            30 as libc::c_int,
            0 as libc::c_int,
            141 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/cipher/aead.c\0"
                as *const u8 as *const libc::c_char,
            407 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*(*ctx).aead).deserialize_state).is_none() {
        return (CBS_len(&mut state) == 0 as libc::c_int as size_t) as libc::c_int;
    }
    return ((*(*ctx).aead).deserialize_state)
        .expect("non-null function pointer")(ctx, &mut state);
}
#[no_mangle]
pub unsafe extern "C" fn EVP_AEAD_CTX_get_aead_id(
    mut ctx: *const EVP_AEAD_CTX,
) -> uint16_t {
    if ((*ctx).aead).is_null() {
        return 0 as libc::c_int as uint16_t;
    }
    return (*(*ctx).aead).aead_id;
}
