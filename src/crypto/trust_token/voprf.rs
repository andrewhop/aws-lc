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
    pub type stack_st_TRUST_TOKEN_PRETOKEN;
    pub type stack_st_TRUST_TOKEN;
    pub type stack_st;
    fn BN_num_bytes(bn: *const BIGNUM) -> libc::c_uint;
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_skip(cbs: *mut CBS, len: size_t) -> libc::c_int;
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_get_bytes(cbs: *mut CBS, out: *mut CBS, len: size_t) -> libc::c_int;
    fn CBS_get_u16_length_prefixed(cbs: *mut CBS, out: *mut CBS) -> libc::c_int;
    fn CBB_zero(cbb: *mut CBB);
    fn CBB_init(cbb: *mut CBB, initial_capacity: size_t) -> libc::c_int;
    fn CBB_init_fixed(cbb: *mut CBB, buf: *mut uint8_t, len: size_t) -> libc::c_int;
    fn CBB_cleanup(cbb: *mut CBB);
    fn CBB_finish(
        cbb: *mut CBB,
        out_data: *mut *mut uint8_t,
        out_len: *mut size_t,
    ) -> libc::c_int;
    fn CBB_flush(cbb: *mut CBB) -> libc::c_int;
    fn CBB_data(cbb: *const CBB) -> *const uint8_t;
    fn CBB_len(cbb: *const CBB) -> size_t;
    fn CBB_add_u16_length_prefixed(cbb: *mut CBB, out_contents: *mut CBB) -> libc::c_int;
    fn CBB_add_bytes(cbb: *mut CBB, data: *const uint8_t, len: size_t) -> libc::c_int;
    fn CBB_add_space(
        cbb: *mut CBB,
        out_data: *mut *mut uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn CBB_add_u16(cbb: *mut CBB, value: uint16_t) -> libc::c_int;
    fn CBB_add_u32(cbb: *mut CBB, value: uint32_t) -> libc::c_int;
    fn ec_scalar_to_bytes(
        group: *const EC_GROUP,
        out: *mut uint8_t,
        out_len: *mut size_t,
        in_0: *const EC_SCALAR,
    );
    fn ec_scalar_from_bytes(
        group: *const EC_GROUP,
        out: *mut EC_SCALAR,
        in_0: *const uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn ec_random_nonzero_scalar(
        group: *const EC_GROUP,
        out: *mut EC_SCALAR,
        additional_data: *const uint8_t,
    ) -> libc::c_int;
    fn ec_scalar_equal_vartime(
        group: *const EC_GROUP,
        a: *const EC_SCALAR,
        b: *const EC_SCALAR,
    ) -> libc::c_int;
    fn ec_scalar_add(
        group: *const EC_GROUP,
        r: *mut EC_SCALAR,
        a: *const EC_SCALAR,
        b: *const EC_SCALAR,
    );
    fn ec_scalar_sub(
        group: *const EC_GROUP,
        r: *mut EC_SCALAR,
        a: *const EC_SCALAR,
        b: *const EC_SCALAR,
    );
    fn ec_scalar_neg(group: *const EC_GROUP, r: *mut EC_SCALAR, a: *const EC_SCALAR);
    fn ec_scalar_to_montgomery(
        group: *const EC_GROUP,
        r: *mut EC_SCALAR,
        a: *const EC_SCALAR,
    );
    fn ec_scalar_from_montgomery(
        group: *const EC_GROUP,
        r: *mut EC_SCALAR,
        a: *const EC_SCALAR,
    );
    fn ec_scalar_mul_montgomery(
        group: *const EC_GROUP,
        r: *mut EC_SCALAR,
        a: *const EC_SCALAR,
        b: *const EC_SCALAR,
    );
    fn ec_scalar_inv0_montgomery(
        group: *const EC_GROUP,
        r: *mut EC_SCALAR,
        a: *const EC_SCALAR,
    );
    fn ec_affine_to_jacobian(
        group: *const EC_GROUP,
        out: *mut EC_JACOBIAN,
        p: *const EC_AFFINE,
    );
    fn ec_jacobian_to_affine(
        group: *const EC_GROUP,
        out: *mut EC_AFFINE,
        p: *const EC_JACOBIAN,
    ) -> libc::c_int;
    fn ec_jacobian_to_affine_batch(
        group: *const EC_GROUP,
        out: *mut EC_AFFINE,
        in_0: *const EC_JACOBIAN,
        num: size_t,
    ) -> libc::c_int;
    fn ec_point_mul_scalar(
        group: *const EC_GROUP,
        r: *mut EC_JACOBIAN,
        p: *const EC_JACOBIAN,
        scalar: *const EC_SCALAR,
    ) -> libc::c_int;
    fn ec_point_mul_scalar_base(
        group: *const EC_GROUP,
        r: *mut EC_JACOBIAN,
        scalar: *const EC_SCALAR,
    ) -> libc::c_int;
    fn ec_point_mul_scalar_public(
        group: *const EC_GROUP,
        r: *mut EC_JACOBIAN,
        g_scalar: *const EC_SCALAR,
        p: *const EC_JACOBIAN,
        p_scalar: *const EC_SCALAR,
    ) -> libc::c_int;
    fn ec_point_mul_scalar_public_batch(
        group: *const EC_GROUP,
        r: *mut EC_JACOBIAN,
        g_scalar: *const EC_SCALAR,
        points: *const EC_JACOBIAN,
        scalars: *const EC_SCALAR,
        num: size_t,
    ) -> libc::c_int;
    fn ec_point_byte_len(
        group: *const EC_GROUP,
        form: point_conversion_form_t,
    ) -> size_t;
    fn ec_point_to_bytes(
        group: *const EC_GROUP,
        point: *const EC_AFFINE,
        form: point_conversion_form_t,
        buf: *mut uint8_t,
        max_out: size_t,
    ) -> size_t;
    fn ec_point_from_uncompressed(
        group: *const EC_GROUP,
        out: *mut EC_AFFINE,
        in_0: *const uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn ec_affine_jacobian_equal(
        group: *const EC_GROUP,
        a: *const EC_AFFINE,
        b: *const EC_JACOBIAN,
    ) -> libc::c_int;
    fn EC_group_p384() -> *const EC_GROUP;
    fn EC_GROUP_get0_order(group: *const EC_GROUP) -> *const BIGNUM;
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_pop_free_ex(
        sk: *mut OPENSSL_STACK,
        call_free_func: OPENSSL_sk_call_free_func,
        free_func: OPENSSL_sk_free_func,
    );
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn RAND_bytes(buf: *mut uint8_t, len: size_t) -> libc::c_int;
    fn SHA384_Init(sha: *mut SHA512_CTX) -> libc::c_int;
    fn SHA384_Update(
        sha: *mut SHA512_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn SHA384_Final(out: *mut uint8_t, sha: *mut SHA512_CTX) -> libc::c_int;
    fn SHA512_Init(sha: *mut SHA512_CTX) -> libc::c_int;
    fn SHA512_Update(
        sha: *mut SHA512_CTX,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn SHA512_Final(out: *mut uint8_t, sha: *mut SHA512_CTX) -> libc::c_int;
    fn TRUST_TOKEN_new(data: *const uint8_t, len: size_t) -> *mut TRUST_TOKEN;
    fn TRUST_TOKEN_free(token: *mut TRUST_TOKEN);
    fn TRUST_TOKEN_PRETOKEN_free(token: *mut TRUST_TOKEN_PRETOKEN);
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_calloc(num: size_t, size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
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
    fn ec_hash_to_curve_p384_xmd_sha384_sswu(
        group: *const EC_GROUP,
        out: *mut EC_JACOBIAN,
        dst: *const uint8_t,
        dst_len: size_t,
        msg: *const uint8_t,
        msg_len: size_t,
    ) -> libc::c_int;
    fn ec_hash_to_scalar_p384_xmd_sha384(
        group: *const EC_GROUP,
        out: *mut EC_SCALAR,
        dst: *const uint8_t,
        dst_len: size_t,
        msg: *const uint8_t,
        msg_len: size_t,
    ) -> libc::c_int;
    fn ec_hash_to_curve_p384_xmd_sha512_sswu_draft07(
        group: *const EC_GROUP,
        out: *mut EC_JACOBIAN,
        dst: *const uint8_t,
        dst_len: size_t,
        msg: *const uint8_t,
        msg_len: size_t,
    ) -> libc::c_int;
    fn ec_hash_to_scalar_p384_xmd_sha512_draft07(
        group: *const EC_GROUP,
        out: *mut EC_SCALAR,
        dst: *const uint8_t,
        dst_len: size_t,
        msg: *const uint8_t,
        msg_len: size_t,
    ) -> libc::c_int;
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
pub struct sha512_state_st {
    pub h: [uint64_t; 8],
    pub Nl: uint64_t,
    pub Nh: uint64_t,
    pub p: [uint8_t; 128],
    pub num: libc::c_uint,
    pub md_len: libc::c_uint,
}
pub type SHA512_CTX = sha512_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct trust_token_st {
    pub data: *mut uint8_t,
    pub len: size_t,
}
pub type TRUST_TOKEN = trust_token_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct TRUST_TOKEN_CLIENT_KEY {
    pub pub0: EC_AFFINE,
    pub pub1: EC_AFFINE,
    pub pubs: EC_AFFINE,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct TRUST_TOKEN_ISSUER_KEY {
    pub x0: EC_SCALAR,
    pub y0: EC_SCALAR,
    pub x1: EC_SCALAR,
    pub y1: EC_SCALAR,
    pub xs: EC_SCALAR,
    pub ys: EC_SCALAR,
    pub pub0: EC_AFFINE,
    pub pub0_precomp: EC_PRECOMP,
    pub pub1: EC_AFFINE,
    pub pub1_precomp: EC_PRECOMP,
    pub pubs: EC_AFFINE,
    pub pubs_precomp: EC_PRECOMP,
}
pub type OPENSSL_sk_free_func = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type OPENSSL_sk_call_free_func = Option::<
    unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
>;
pub type OPENSSL_STACK = stack_st;
pub type sk_TRUST_TOKEN_free_func = Option::<
    unsafe extern "C" fn(*mut TRUST_TOKEN) -> (),
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pmb_pretoken_st {
    pub salt: [uint8_t; 64],
    pub t: [uint8_t; 64],
    pub r: EC_SCALAR,
    pub Tp: EC_AFFINE,
}
pub type TRUST_TOKEN_PRETOKEN = pmb_pretoken_st;
pub type sk_TRUST_TOKEN_PRETOKEN_free_func = Option::<
    unsafe extern "C" fn(*mut TRUST_TOKEN_PRETOKEN) -> (),
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct VOPRF_METHOD {
    pub group_func: Option::<unsafe extern "C" fn() -> *const EC_GROUP>,
    pub hash_to_group: hash_to_group_func_t,
    pub hash_to_scalar: hash_to_scalar_func_t,
}
pub type hash_to_scalar_func_t = Option::<
    unsafe extern "C" fn(
        *const EC_GROUP,
        *mut EC_SCALAR,
        *mut uint8_t,
        size_t,
    ) -> libc::c_int,
>;
pub type hash_to_group_func_t = Option::<
    unsafe extern "C" fn(
        *const EC_GROUP,
        *mut EC_JACOBIAN,
        *const uint8_t,
    ) -> libc::c_int,
>;
pub const idx_k1: C2RustUnnamed_0 = 3;
pub const idx_k0: C2RustUnnamed_0 = 2;
pub const idx_W: C2RustUnnamed_0 = 1;
pub const idx_T: C2RustUnnamed_0 = 0;
pub const num_idx: C2RustUnnamed_0 = 4;
pub type C2RustUnnamed_0 = libc::c_uint;
pub const idx_k1_0: C2RustUnnamed_1 = 3;
pub const idx_k0_0: C2RustUnnamed_1 = 2;
pub const idx_W_0: C2RustUnnamed_1 = 1;
pub const idx_T_0: C2RustUnnamed_1 = 0;
pub const num_idx_0: C2RustUnnamed_1 = 4;
pub type C2RustUnnamed_1 = libc::c_uint;
pub const idx_t3: C2RustUnnamed_2 = 3;
pub const idx_t2: C2RustUnnamed_2 = 2;
pub const idx_Z: C2RustUnnamed_2 = 1;
pub const idx_M: C2RustUnnamed_2 = 0;
pub const num_idx_1: C2RustUnnamed_2 = 4;
pub type C2RustUnnamed_2 = libc::c_uint;
pub const idx_t3_0: C2RustUnnamed_3 = 3;
pub const idx_t2_0: C2RustUnnamed_3 = 2;
pub const idx_Z_0: C2RustUnnamed_3 = 1;
pub const idx_M_0: C2RustUnnamed_3 = 0;
pub const num_idx_2: C2RustUnnamed_3 = 4;
pub type C2RustUnnamed_3 = libc::c_uint;
#[inline]
unsafe extern "C" fn sk_TRUST_TOKEN_new_null() -> *mut stack_st_TRUST_TOKEN {
    return OPENSSL_sk_new_null() as *mut stack_st_TRUST_TOKEN;
}
#[inline]
unsafe extern "C" fn sk_TRUST_TOKEN_pop_free(
    mut sk: *mut stack_st_TRUST_TOKEN,
    mut free_func: sk_TRUST_TOKEN_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_TRUST_TOKEN_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_TRUST_TOKEN_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_TRUST_TOKEN_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<OPENSSL_sk_free_func, sk_TRUST_TOKEN_free_func>(free_func))
        .expect("non-null function pointer")(ptr as *mut TRUST_TOKEN);
}
#[inline]
unsafe extern "C" fn sk_TRUST_TOKEN_push(
    mut sk: *mut stack_st_TRUST_TOKEN,
    mut p: *mut TRUST_TOKEN,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_TRUST_TOKEN_PRETOKEN_new_null() -> *mut stack_st_TRUST_TOKEN_PRETOKEN {
    return OPENSSL_sk_new_null() as *mut stack_st_TRUST_TOKEN_PRETOKEN;
}
#[inline]
unsafe extern "C" fn sk_TRUST_TOKEN_PRETOKEN_num(
    mut sk: *const stack_st_TRUST_TOKEN_PRETOKEN,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_TRUST_TOKEN_PRETOKEN_value(
    mut sk: *const stack_st_TRUST_TOKEN_PRETOKEN,
    mut i: size_t,
) -> *mut TRUST_TOKEN_PRETOKEN {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut TRUST_TOKEN_PRETOKEN;
}
#[inline]
unsafe extern "C" fn sk_TRUST_TOKEN_PRETOKEN_pop_free(
    mut sk: *mut stack_st_TRUST_TOKEN_PRETOKEN,
    mut free_func: sk_TRUST_TOKEN_PRETOKEN_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_TRUST_TOKEN_PRETOKEN_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_TRUST_TOKEN_PRETOKEN_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_TRUST_TOKEN_PRETOKEN_push(
    mut sk: *mut stack_st_TRUST_TOKEN_PRETOKEN,
    mut p: *mut TRUST_TOKEN_PRETOKEN,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_TRUST_TOKEN_PRETOKEN_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<
        OPENSSL_sk_free_func,
        sk_TRUST_TOKEN_PRETOKEN_free_func,
    >(free_func))
        .expect("non-null function pointer")(ptr as *mut TRUST_TOKEN_PRETOKEN);
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
unsafe extern "C" fn cbb_add_point(
    mut out: *mut CBB,
    mut group: *const EC_GROUP,
    mut point: *const EC_AFFINE,
) -> libc::c_int {
    let mut p: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = ec_point_byte_len(group, POINT_CONVERSION_UNCOMPRESSED);
    return (CBB_add_space(out, &mut p, len) != 0
        && ec_point_to_bytes(group, point, POINT_CONVERSION_UNCOMPRESSED, p, len) == len
        && CBB_flush(out) != 0) as libc::c_int;
}
unsafe extern "C" fn cbb_serialize_point(
    mut out: *mut CBB,
    mut group: *const EC_GROUP,
    mut point: *const EC_AFFINE,
) -> libc::c_int {
    let mut p: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = ec_point_byte_len(group, POINT_CONVERSION_COMPRESSED);
    return (CBB_add_u16(out, len as uint16_t) != 0
        && CBB_add_space(out, &mut p, len) != 0
        && ec_point_to_bytes(group, point, POINT_CONVERSION_COMPRESSED, p, len) == len
        && CBB_flush(out) != 0) as libc::c_int;
}
unsafe extern "C" fn cbs_get_point(
    mut cbs: *mut CBS,
    mut group: *const EC_GROUP,
    mut out: *mut EC_AFFINE,
) -> libc::c_int {
    let mut child: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut plen: size_t = ec_point_byte_len(group, POINT_CONVERSION_UNCOMPRESSED);
    if CBS_get_bytes(cbs, &mut child, plen) == 0
        || ec_point_from_uncompressed(
            group,
            out,
            CBS_data(&mut child),
            CBS_len(&mut child),
        ) == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn scalar_to_cbb(
    mut out: *mut CBB,
    mut group: *const EC_GROUP,
    mut scalar: *const EC_SCALAR,
) -> libc::c_int {
    let mut buf: *mut uint8_t = 0 as *mut uint8_t;
    let mut scalar_len: size_t = BN_num_bytes(EC_GROUP_get0_order(group)) as size_t;
    if CBB_add_space(out, &mut buf, scalar_len) == 0 {
        return 0 as libc::c_int;
    }
    ec_scalar_to_bytes(group, buf, &mut scalar_len, scalar);
    return 1 as libc::c_int;
}
unsafe extern "C" fn scalar_from_cbs(
    mut cbs: *mut CBS,
    mut group: *const EC_GROUP,
    mut out: *mut EC_SCALAR,
) -> libc::c_int {
    let mut scalar_len: size_t = BN_num_bytes(EC_GROUP_get0_order(group)) as size_t;
    let mut tmp: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_get_bytes(cbs, &mut tmp, scalar_len) == 0 {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                as *const u8 as *const libc::c_char,
            96 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    ec_scalar_from_bytes(group, out, CBS_data(&mut tmp), CBS_len(&mut tmp));
    return 1 as libc::c_int;
}
unsafe extern "C" fn voprf_calculate_key(
    mut method: *const VOPRF_METHOD,
    mut out_private: *mut CBB,
    mut out_public: *mut CBB,
    mut priv_0: *const EC_SCALAR,
) -> libc::c_int {
    let mut group: *const EC_GROUP = ((*method).group_func)
        .expect("non-null function pointer")();
    let mut pub_0: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    let mut pub_affine: EC_AFFINE = EC_AFFINE {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
    };
    if ec_point_mul_scalar_base(group, &mut pub_0, priv_0) == 0
        || ec_jacobian_to_affine(group, &mut pub_affine, &mut pub_0) == 0
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                as *const u8 as *const libc::c_char,
            111 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if scalar_to_cbb(out_private, group, priv_0) == 0
        || cbb_add_point(out_public, group, &mut pub_affine) == 0
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                as *const u8 as *const libc::c_char,
            117 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn voprf_generate_key(
    mut method: *const VOPRF_METHOD,
    mut out_private: *mut CBB,
    mut out_public: *mut CBB,
) -> libc::c_int {
    let mut priv_0: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    if ec_random_nonzero_scalar(
        ((*method).group_func).expect("non-null function pointer")(),
        &mut priv_0,
        kDefaultAdditionalData.as_ptr(),
    ) == 0
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                as *const u8 as *const libc::c_char,
            130 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return voprf_calculate_key(method, out_private, out_public, &mut priv_0);
}
unsafe extern "C" fn voprf_derive_key_from_secret(
    mut method: *const VOPRF_METHOD,
    mut out_private: *mut CBB,
    mut out_public: *mut CBB,
    mut secret: *const uint8_t,
    mut secret_len: size_t,
) -> libc::c_int {
    static mut kKeygenLabel: [uint8_t; 22] = unsafe {
        *::core::mem::transmute::<&[u8; 22], &[uint8_t; 22]>(b"TrustTokenVOPRFKeyGen\0")
    };
    let mut priv_0: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut ok: libc::c_int = 0 as libc::c_int;
    let mut cbb: CBB = cbb_st {
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
    CBB_zero(&mut cbb);
    let mut buf: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = 0;
    if CBB_init(&mut cbb, 0 as libc::c_int as size_t) == 0
        || CBB_add_bytes(
            &mut cbb,
            kKeygenLabel.as_ptr(),
            ::core::mem::size_of::<[uint8_t; 22]>() as libc::c_ulong,
        ) == 0 || CBB_add_bytes(&mut cbb, secret, secret_len) == 0
        || CBB_finish(&mut cbb, &mut buf, &mut len) == 0
        || ((*method).hash_to_scalar)
            .expect(
                "non-null function pointer",
            )(
            ((*method).group_func).expect("non-null function pointer")(),
            &mut priv_0,
            buf,
            len,
        ) == 0
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                as *const u8 as *const libc::c_char,
            153 as libc::c_int as libc::c_uint,
        );
    } else {
        ok = voprf_calculate_key(method, out_private, out_public, &mut priv_0);
    }
    CBB_cleanup(&mut cbb);
    OPENSSL_free(buf as *mut libc::c_void);
    return ok;
}
unsafe extern "C" fn voprf_client_key_from_bytes(
    mut method: *const VOPRF_METHOD,
    mut key: *mut TRUST_TOKEN_CLIENT_KEY,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut group: *const EC_GROUP = ((*method).group_func)
        .expect("non-null function pointer")();
    if ec_point_from_uncompressed(group, &mut (*key).pubs, in_0, len) == 0 {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                as *const u8 as *const libc::c_char,
            170 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn voprf_issuer_key_from_bytes(
    mut method: *const VOPRF_METHOD,
    mut key: *mut TRUST_TOKEN_ISSUER_KEY,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut group: *const EC_GROUP = ((*method).group_func)
        .expect("non-null function pointer")();
    if ec_scalar_from_bytes(group, &mut (*key).xs, in_0, len) == 0 {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                as *const u8 as *const libc::c_char,
            182 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut pub_0: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    if ec_point_mul_scalar_base(group, &mut pub_0, &mut (*key).xs) == 0
        || ec_jacobian_to_affine(group, &mut (*key).pubs, &mut pub_0) == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn voprf_blind(
    mut method: *const VOPRF_METHOD,
    mut cbb: *mut CBB,
    mut count: size_t,
    mut include_message: libc::c_int,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> *mut stack_st_TRUST_TOKEN_PRETOKEN {
    let mut current_block: u64;
    let mut hash_ctx: SHA512_CTX = sha512_state_st {
        h: [0; 8],
        Nl: 0,
        Nh: 0,
        p: [0; 128],
        num: 0,
        md_len: 0,
    };
    let mut group: *const EC_GROUP = ((*method).group_func)
        .expect("non-null function pointer")();
    let mut pretokens: *mut stack_st_TRUST_TOKEN_PRETOKEN = sk_TRUST_TOKEN_PRETOKEN_new_null();
    if !pretokens.is_null() {
        let mut i: size_t = 0 as libc::c_int as size_t;
        loop {
            if !(i < count) {
                current_block = 224731115979188411;
                break;
            }
            let mut pretoken: *mut TRUST_TOKEN_PRETOKEN = OPENSSL_malloc(
                ::core::mem::size_of::<TRUST_TOKEN_PRETOKEN>() as libc::c_ulong,
            ) as *mut TRUST_TOKEN_PRETOKEN;
            if pretoken.is_null()
                || sk_TRUST_TOKEN_PRETOKEN_push(pretokens, pretoken) == 0
            {
                TRUST_TOKEN_PRETOKEN_free(pretoken);
                current_block = 14689304470361028689;
                break;
            } else {
                RAND_bytes(
                    ((*pretoken).salt).as_mut_ptr(),
                    ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
                );
                if include_message != 0 {
                    if 64 as libc::c_int == 64 as libc::c_int {} else {
                        __assert_fail(
                            b"SHA512_DIGEST_LENGTH == TRUST_TOKEN_NONCE_SIZE\0"
                                as *const u8 as *const libc::c_char,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                                as *const u8 as *const libc::c_char,
                            222 as libc::c_int as libc::c_uint,
                            (*::core::mem::transmute::<
                                &[u8; 117],
                                &[libc::c_char; 117],
                            >(
                                b"struct stack_st_TRUST_TOKEN_PRETOKEN *voprf_blind(const VOPRF_METHOD *, CBB *, size_t, int, const uint8_t *, size_t)\0",
                            ))
                                .as_ptr(),
                        );
                    }
                    'c_11560: {
                        if 64 as libc::c_int == 64 as libc::c_int {} else {
                            __assert_fail(
                                b"SHA512_DIGEST_LENGTH == TRUST_TOKEN_NONCE_SIZE\0"
                                    as *const u8 as *const libc::c_char,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                                    as *const u8 as *const libc::c_char,
                                222 as libc::c_int as libc::c_uint,
                                (*::core::mem::transmute::<
                                    &[u8; 117],
                                    &[libc::c_char; 117],
                                >(
                                    b"struct stack_st_TRUST_TOKEN_PRETOKEN *voprf_blind(const VOPRF_METHOD *, CBB *, size_t, int, const uint8_t *, size_t)\0",
                                ))
                                    .as_ptr(),
                            );
                        }
                    };
                    SHA512_Init(&mut hash_ctx);
                    SHA512_Update(
                        &mut hash_ctx,
                        ((*pretoken).salt).as_mut_ptr() as *const libc::c_void,
                        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
                    );
                    SHA512_Update(&mut hash_ctx, msg as *const libc::c_void, msg_len);
                    SHA512_Final(((*pretoken).t).as_mut_ptr(), &mut hash_ctx);
                } else {
                    OPENSSL_memcpy(
                        ((*pretoken).t).as_mut_ptr() as *mut libc::c_void,
                        ((*pretoken).salt).as_mut_ptr() as *const libc::c_void,
                        64 as libc::c_int as size_t,
                    );
                }
                let mut r: EC_SCALAR = EC_SCALAR { words: [0; 9] };
                if ec_random_nonzero_scalar(
                    group,
                    &mut r,
                    kDefaultAdditionalData.as_ptr(),
                ) == 0
                {
                    current_block = 14689304470361028689;
                    break;
                }
                ec_scalar_inv0_montgomery(group, &mut (*pretoken).r, &mut r);
                ec_scalar_from_montgomery(group, &mut r, &mut r);
                ec_scalar_from_montgomery(group, &mut (*pretoken).r, &mut (*pretoken).r);
                let mut P: EC_JACOBIAN = EC_JACOBIAN {
                    X: EC_FELEM { words: [0; 9] },
                    Y: EC_FELEM { words: [0; 9] },
                    Z: EC_FELEM { words: [0; 9] },
                };
                let mut Tp: EC_JACOBIAN = EC_JACOBIAN {
                    X: EC_FELEM { words: [0; 9] },
                    Y: EC_FELEM { words: [0; 9] },
                    Z: EC_FELEM { words: [0; 9] },
                };
                if ((*method).hash_to_group)
                    .expect(
                        "non-null function pointer",
                    )(group, &mut P, ((*pretoken).t).as_mut_ptr() as *const uint8_t) == 0
                    || ec_point_mul_scalar(group, &mut Tp, &mut P, &mut r) == 0
                    || ec_jacobian_to_affine(group, &mut (*pretoken).Tp, &mut Tp) == 0
                {
                    current_block = 14689304470361028689;
                    break;
                }
                if cbb_add_point(cbb, group, &mut (*pretoken).Tp) == 0 {
                    current_block = 14689304470361028689;
                    break;
                }
                i = i.wrapping_add(1);
                i;
            }
        }
        match current_block {
            14689304470361028689 => {}
            _ => return pretokens,
        }
    }
    sk_TRUST_TOKEN_PRETOKEN_pop_free(
        pretokens,
        Some(
            TRUST_TOKEN_PRETOKEN_free
                as unsafe extern "C" fn(*mut TRUST_TOKEN_PRETOKEN) -> (),
        ),
    );
    return 0 as *mut stack_st_TRUST_TOKEN_PRETOKEN;
}
unsafe extern "C" fn hash_to_scalar_dleq(
    mut method: *const VOPRF_METHOD,
    mut out: *mut EC_SCALAR,
    mut X: *const EC_AFFINE,
    mut T: *const EC_AFFINE,
    mut W: *const EC_AFFINE,
    mut K0: *const EC_AFFINE,
    mut K1: *const EC_AFFINE,
) -> libc::c_int {
    static mut kDLEQLabel: [uint8_t; 5] = unsafe {
        *::core::mem::transmute::<&[u8; 5], &[uint8_t; 5]>(b"DLEQ\0")
    };
    let mut group: *const EC_GROUP = ((*method).group_func)
        .expect("non-null function pointer")();
    let mut ok: libc::c_int = 0 as libc::c_int;
    let mut cbb: CBB = cbb_st {
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
    CBB_zero(&mut cbb);
    let mut buf: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = 0;
    if !(CBB_init(&mut cbb, 0 as libc::c_int as size_t) == 0
        || CBB_add_bytes(
            &mut cbb,
            kDLEQLabel.as_ptr(),
            ::core::mem::size_of::<[uint8_t; 5]>() as libc::c_ulong,
        ) == 0 || cbb_add_point(&mut cbb, group, X) == 0
        || cbb_add_point(&mut cbb, group, T) == 0
        || cbb_add_point(&mut cbb, group, W) == 0
        || cbb_add_point(&mut cbb, group, K0) == 0
        || cbb_add_point(&mut cbb, group, K1) == 0
        || CBB_finish(&mut cbb, &mut buf, &mut len) == 0
        || ((*method).hash_to_scalar)
            .expect("non-null function pointer")(group, out, buf, len) == 0)
    {
        ok = 1 as libc::c_int;
    }
    CBB_cleanup(&mut cbb);
    OPENSSL_free(buf as *mut libc::c_void);
    return ok;
}
unsafe extern "C" fn hash_to_scalar_challenge(
    mut method: *const VOPRF_METHOD,
    mut out: *mut EC_SCALAR,
    mut Bm: *const EC_AFFINE,
    mut a0: *const EC_AFFINE,
    mut a1: *const EC_AFFINE,
    mut a2: *const EC_AFFINE,
    mut a3: *const EC_AFFINE,
) -> libc::c_int {
    static mut kChallengeLabel: [uint8_t; 10] = unsafe {
        *::core::mem::transmute::<&[u8; 10], &[uint8_t; 10]>(b"Challenge\0")
    };
    let mut group: *const EC_GROUP = ((*method).group_func)
        .expect("non-null function pointer")();
    let mut cbb: CBB = cbb_st {
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
    let mut transcript: [uint8_t; 346] = [0; 346];
    let mut len: size_t = 0;
    if CBB_init_fixed(
        &mut cbb,
        transcript.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 346]>() as libc::c_ulong,
    ) == 0 || cbb_serialize_point(&mut cbb, group, Bm) == 0
        || cbb_serialize_point(&mut cbb, group, a0) == 0
        || cbb_serialize_point(&mut cbb, group, a1) == 0
        || cbb_serialize_point(&mut cbb, group, a2) == 0
        || cbb_serialize_point(&mut cbb, group, a3) == 0
        || CBB_add_bytes(
            &mut cbb,
            kChallengeLabel.as_ptr(),
            (::core::mem::size_of::<[uint8_t; 10]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        ) == 0 || CBB_finish(&mut cbb, 0 as *mut *mut uint8_t, &mut len) == 0
        || ((*method).hash_to_scalar)
            .expect(
                "non-null function pointer",
            )(group, out, transcript.as_mut_ptr(), len) == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn hash_to_scalar_batch(
    mut method: *const VOPRF_METHOD,
    mut out: *mut EC_SCALAR,
    mut points: *const CBB,
    mut index: size_t,
) -> libc::c_int {
    static mut kDLEQBatchLabel: [uint8_t; 11] = unsafe {
        *::core::mem::transmute::<&[u8; 11], &[uint8_t; 11]>(b"DLEQ BATCH\0")
    };
    if index > 0xffff as libc::c_int as size_t {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                as *const u8 as *const libc::c_char,
            326 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ok: libc::c_int = 0 as libc::c_int;
    let mut cbb: CBB = cbb_st {
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
    CBB_zero(&mut cbb);
    let mut buf: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = 0;
    if !(CBB_init(&mut cbb, 0 as libc::c_int as size_t) == 0
        || CBB_add_bytes(
            &mut cbb,
            kDLEQBatchLabel.as_ptr(),
            ::core::mem::size_of::<[uint8_t; 11]>() as libc::c_ulong,
        ) == 0 || CBB_add_bytes(&mut cbb, CBB_data(points), CBB_len(points)) == 0
        || CBB_add_u16(&mut cbb, index as uint16_t) == 0
        || CBB_finish(&mut cbb, &mut buf, &mut len) == 0
        || ((*method).hash_to_scalar)
            .expect(
                "non-null function pointer",
            )(
            ((*method).group_func).expect("non-null function pointer")(),
            out,
            buf,
            len,
        ) == 0)
    {
        ok = 1 as libc::c_int;
    }
    CBB_cleanup(&mut cbb);
    OPENSSL_free(buf as *mut libc::c_void);
    return ok;
}
unsafe extern "C" fn dleq_generate(
    mut method: *const VOPRF_METHOD,
    mut cbb: *mut CBB,
    mut priv_0: *const TRUST_TOKEN_ISSUER_KEY,
    mut T: *const EC_JACOBIAN,
    mut W: *const EC_JACOBIAN,
) -> libc::c_int {
    let mut group: *const EC_GROUP = ((*method).group_func)
        .expect("non-null function pointer")();
    let mut jacobians: [EC_JACOBIAN; 4] = [EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    }; 4];
    let mut r: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    if ec_random_nonzero_scalar(group, &mut r, kDefaultAdditionalData.as_ptr()) == 0
        || ec_point_mul_scalar_base(
            group,
            &mut *jacobians.as_mut_ptr().offset(idx_k0 as libc::c_int as isize),
            &mut r,
        ) == 0
        || ec_point_mul_scalar(
            group,
            &mut *jacobians.as_mut_ptr().offset(idx_k1 as libc::c_int as isize),
            T,
            &mut r,
        ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut affines: [EC_AFFINE; 4] = [EC_AFFINE {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
    }; 4];
    jacobians[idx_T as libc::c_int as usize] = *T;
    jacobians[idx_W as libc::c_int as usize] = *W;
    if ec_jacobian_to_affine_batch(
        group,
        affines.as_mut_ptr(),
        jacobians.as_mut_ptr(),
        num_idx as libc::c_int as size_t,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut c: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    if hash_to_scalar_dleq(
        method,
        &mut c,
        &(*priv_0).pubs,
        &mut *affines.as_mut_ptr().offset(idx_T as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_W as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_k0 as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_k1 as libc::c_int as isize),
    ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut c_mont: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    ec_scalar_to_montgomery(group, &mut c_mont, &mut c);
    let mut u: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    ec_scalar_mul_montgomery(group, &mut u, &(*priv_0).xs, &mut c_mont);
    ec_scalar_add(group, &mut u, &mut r, &mut u);
    if scalar_to_cbb(cbb, group, &mut c) == 0 || scalar_to_cbb(cbb, group, &mut u) == 0 {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn mul_public_2(
    mut group: *const EC_GROUP,
    mut out: *mut EC_JACOBIAN,
    mut p0: *const EC_JACOBIAN,
    mut scalar0: *const EC_SCALAR,
    mut p1: *const EC_JACOBIAN,
    mut scalar1: *const EC_SCALAR,
) -> libc::c_int {
    let mut points: [EC_JACOBIAN; 2] = [*p0, *p1];
    let mut scalars: [EC_SCALAR; 2] = [*scalar0, *scalar1];
    return ec_point_mul_scalar_public_batch(
        group,
        out,
        0 as *const EC_SCALAR,
        points.as_mut_ptr(),
        scalars.as_mut_ptr(),
        2 as libc::c_int as size_t,
    );
}
unsafe extern "C" fn dleq_verify(
    mut method: *const VOPRF_METHOD,
    mut cbs: *mut CBS,
    mut pub_0: *const TRUST_TOKEN_CLIENT_KEY,
    mut T: *const EC_JACOBIAN,
    mut W: *const EC_JACOBIAN,
) -> libc::c_int {
    let mut group: *const EC_GROUP = ((*method).group_func)
        .expect("non-null function pointer")();
    let mut jacobians: [EC_JACOBIAN; 4] = [EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    }; 4];
    let mut c: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut u: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    if scalar_from_cbs(cbs, group, &mut c) == 0
        || scalar_from_cbs(cbs, group, &mut u) == 0
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                as *const u8 as *const libc::c_char,
            437 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut pubs: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    ec_affine_to_jacobian(group, &mut pubs, &(*pub_0).pubs);
    let mut minus_c: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    ec_scalar_neg(group, &mut minus_c, &mut c);
    if ec_point_mul_scalar_public(
        group,
        &mut *jacobians.as_mut_ptr().offset(idx_k0_0 as libc::c_int as isize),
        &mut u,
        &mut pubs,
        &mut minus_c,
    ) == 0
        || mul_public_2(
            group,
            &mut *jacobians.as_mut_ptr().offset(idx_k1_0 as libc::c_int as isize),
            T,
            &mut u,
            W,
            &mut minus_c,
        ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut affines: [EC_AFFINE; 4] = [EC_AFFINE {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
    }; 4];
    jacobians[idx_T_0 as libc::c_int as usize] = *T;
    jacobians[idx_W_0 as libc::c_int as usize] = *W;
    if ec_jacobian_to_affine_batch(
        group,
        affines.as_mut_ptr(),
        jacobians.as_mut_ptr(),
        num_idx_0 as libc::c_int as size_t,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut calculated: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    if hash_to_scalar_dleq(
        method,
        &mut calculated,
        &(*pub_0).pubs,
        &mut *affines.as_mut_ptr().offset(idx_T_0 as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_W_0 as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_k0_0 as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_k1_0 as libc::c_int as isize),
    ) == 0
    {
        return 0 as libc::c_int;
    }
    if ec_scalar_equal_vartime(group, &mut c, &mut calculated) == 0 {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            114 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                as *const u8 as *const libc::c_char,
            470 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn voprf_sign_tt(
    mut method: *const VOPRF_METHOD,
    mut key: *const TRUST_TOKEN_ISSUER_KEY,
    mut cbb: *mut CBB,
    mut cbs: *mut CBS,
    mut num_requested: size_t,
    mut num_to_issue: size_t,
) -> libc::c_int {
    let mut BT_batch: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    let mut Z_batch: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    let mut proof: CBB = cbb_st {
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
    let mut point_len: size_t = 0;
    let mut current_block: u64;
    let mut group: *const EC_GROUP = ((*method).group_func)
        .expect("non-null function pointer")();
    if num_requested < num_to_issue {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            4 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                as *const u8 as *const libc::c_char,
            482 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut BTs: *mut EC_JACOBIAN = OPENSSL_calloc(
        num_to_issue,
        ::core::mem::size_of::<EC_JACOBIAN>() as libc::c_ulong,
    ) as *mut EC_JACOBIAN;
    let mut Zs: *mut EC_JACOBIAN = OPENSSL_calloc(
        num_to_issue,
        ::core::mem::size_of::<EC_JACOBIAN>() as libc::c_ulong,
    ) as *mut EC_JACOBIAN;
    let mut es: *mut EC_SCALAR = OPENSSL_calloc(
        num_to_issue,
        ::core::mem::size_of::<EC_SCALAR>() as libc::c_ulong,
    ) as *mut EC_SCALAR;
    let mut batch_cbb: CBB = cbb_st {
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
    CBB_zero(&mut batch_cbb);
    if !(BTs.is_null() || Zs.is_null() || es.is_null()
        || CBB_init(&mut batch_cbb, 0 as libc::c_int as size_t) == 0
        || cbb_add_point(&mut batch_cbb, group, &(*key).pubs) == 0)
    {
        let mut i: size_t = 0 as libc::c_int as size_t;
        loop {
            if !(i < num_to_issue) {
                current_block = 5689001924483802034;
                break;
            }
            let mut BT_affine: EC_AFFINE = EC_AFFINE {
                X: EC_FELEM { words: [0; 9] },
                Y: EC_FELEM { words: [0; 9] },
            };
            let mut Z_affine: EC_AFFINE = EC_AFFINE {
                X: EC_FELEM { words: [0; 9] },
                Y: EC_FELEM { words: [0; 9] },
            };
            let mut BT: EC_JACOBIAN = EC_JACOBIAN {
                X: EC_FELEM { words: [0; 9] },
                Y: EC_FELEM { words: [0; 9] },
                Z: EC_FELEM { words: [0; 9] },
            };
            let mut Z: EC_JACOBIAN = EC_JACOBIAN {
                X: EC_FELEM { words: [0; 9] },
                Y: EC_FELEM { words: [0; 9] },
                Z: EC_FELEM { words: [0; 9] },
            };
            if cbs_get_point(cbs, group, &mut BT_affine) == 0 {
                ERR_put_error(
                    32 as libc::c_int,
                    0 as libc::c_int,
                    105 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                        as *const u8 as *const libc::c_char,
                    504 as libc::c_int as libc::c_uint,
                );
                current_block = 385681101407178109;
                break;
            } else {
                ec_affine_to_jacobian(group, &mut BT, &mut BT_affine);
                if ec_point_mul_scalar(group, &mut Z, &mut BT, &(*key).xs) == 0
                    || ec_jacobian_to_affine(group, &mut Z_affine, &mut Z) == 0
                    || cbb_add_point(cbb, group, &mut Z_affine) == 0
                {
                    current_block = 385681101407178109;
                    break;
                }
                if cbb_add_point(&mut batch_cbb, group, &mut BT_affine) == 0
                    || cbb_add_point(&mut batch_cbb, group, &mut Z_affine) == 0
                {
                    current_block = 385681101407178109;
                    break;
                }
                *BTs.offset(i as isize) = BT;
                *Zs.offset(i as isize) = Z;
                if CBB_flush(cbb) == 0 {
                    current_block = 385681101407178109;
                    break;
                }
                i = i.wrapping_add(1);
                i;
            }
        }
        match current_block {
            385681101407178109 => {}
            _ => {
                let mut i_0: size_t = 0 as libc::c_int as size_t;
                loop {
                    if !(i_0 < num_to_issue) {
                        current_block = 5783071609795492627;
                        break;
                    }
                    if hash_to_scalar_batch(
                        method,
                        &mut *es.offset(i_0 as isize),
                        &mut batch_cbb,
                        i_0,
                    ) == 0
                    {
                        current_block = 385681101407178109;
                        break;
                    }
                    i_0 = i_0.wrapping_add(1);
                    i_0;
                }
                match current_block {
                    385681101407178109 => {}
                    _ => {
                        BT_batch = EC_JACOBIAN {
                            X: EC_FELEM { words: [0; 9] },
                            Y: EC_FELEM { words: [0; 9] },
                            Z: EC_FELEM { words: [0; 9] },
                        };
                        Z_batch = EC_JACOBIAN {
                            X: EC_FELEM { words: [0; 9] },
                            Y: EC_FELEM { words: [0; 9] },
                            Z: EC_FELEM { words: [0; 9] },
                        };
                        if !(ec_point_mul_scalar_public_batch(
                            group,
                            &mut BT_batch,
                            0 as *const EC_SCALAR,
                            BTs,
                            es,
                            num_to_issue,
                        ) == 0
                            || ec_point_mul_scalar_public_batch(
                                group,
                                &mut Z_batch,
                                0 as *const EC_SCALAR,
                                Zs,
                                es,
                                num_to_issue,
                            ) == 0)
                        {
                            proof = cbb_st {
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
                            if !(CBB_add_u16_length_prefixed(cbb, &mut proof) == 0
                                || dleq_generate(
                                    method,
                                    &mut proof,
                                    key,
                                    &mut BT_batch,
                                    &mut Z_batch,
                                ) == 0 || CBB_flush(cbb) == 0)
                            {
                                point_len = ec_point_byte_len(
                                    group,
                                    POINT_CONVERSION_UNCOMPRESSED,
                                );
                                if CBS_skip(
                                    cbs,
                                    point_len * num_requested.wrapping_sub(num_to_issue),
                                ) == 0
                                {
                                    ERR_put_error(
                                        32 as libc::c_int,
                                        0 as libc::c_int,
                                        105 as libc::c_int,
                                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                                            as *const u8 as *const libc::c_char,
                                        555 as libc::c_int as libc::c_uint,
                                    );
                                } else {
                                    ret = 1 as libc::c_int;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    OPENSSL_free(BTs as *mut libc::c_void);
    OPENSSL_free(Zs as *mut libc::c_void);
    OPENSSL_free(es as *mut libc::c_void);
    CBB_cleanup(&mut batch_cbb);
    return ret;
}
unsafe extern "C" fn voprf_unblind_tt(
    mut method: *const VOPRF_METHOD,
    mut key: *const TRUST_TOKEN_CLIENT_KEY,
    mut pretokens: *const stack_st_TRUST_TOKEN_PRETOKEN,
    mut cbs: *mut CBS,
    mut count: size_t,
    mut key_id: uint32_t,
) -> *mut stack_st_TRUST_TOKEN {
    let mut BT_batch: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    let mut Z_batch: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    let mut proof: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut current_block: u64;
    let mut group: *const EC_GROUP = ((*method).group_func)
        .expect("non-null function pointer")();
    if count > sk_TRUST_TOKEN_PRETOKEN_num(pretokens) {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                as *const u8 as *const libc::c_char,
            575 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut stack_st_TRUST_TOKEN;
    }
    let mut ok: libc::c_int = 0 as libc::c_int;
    let mut ret: *mut stack_st_TRUST_TOKEN = sk_TRUST_TOKEN_new_null();
    let mut BTs: *mut EC_JACOBIAN = OPENSSL_calloc(
        count,
        ::core::mem::size_of::<EC_JACOBIAN>() as libc::c_ulong,
    ) as *mut EC_JACOBIAN;
    let mut Zs: *mut EC_JACOBIAN = OPENSSL_calloc(
        count,
        ::core::mem::size_of::<EC_JACOBIAN>() as libc::c_ulong,
    ) as *mut EC_JACOBIAN;
    let mut es: *mut EC_SCALAR = OPENSSL_calloc(
        count,
        ::core::mem::size_of::<EC_SCALAR>() as libc::c_ulong,
    ) as *mut EC_SCALAR;
    let mut batch_cbb: CBB = cbb_st {
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
    CBB_zero(&mut batch_cbb);
    if !(ret.is_null() || BTs.is_null() || Zs.is_null() || es.is_null()
        || CBB_init(&mut batch_cbb, 0 as libc::c_int as size_t) == 0
        || cbb_add_point(&mut batch_cbb, group, &(*key).pubs) == 0)
    {
        let mut i: size_t = 0 as libc::c_int as size_t;
        loop {
            if !(i < count) {
                current_block = 5634871135123216486;
                break;
            }
            let mut pretoken: *const TRUST_TOKEN_PRETOKEN = sk_TRUST_TOKEN_PRETOKEN_value(
                pretokens,
                i,
            );
            let mut Z_affine: EC_AFFINE = EC_AFFINE {
                X: EC_FELEM { words: [0; 9] },
                Y: EC_FELEM { words: [0; 9] },
            };
            if cbs_get_point(cbs, group, &mut Z_affine) == 0 {
                ERR_put_error(
                    32 as libc::c_int,
                    0 as libc::c_int,
                    105 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                        as *const u8 as *const libc::c_char,
                    601 as libc::c_int as libc::c_uint,
                );
                current_block = 14744330308085046661;
                break;
            } else {
                ec_affine_to_jacobian(
                    group,
                    &mut *BTs.offset(i as isize),
                    &(*pretoken).Tp,
                );
                ec_affine_to_jacobian(group, &mut *Zs.offset(i as isize), &mut Z_affine);
                if cbb_add_point(&mut batch_cbb, group, &(*pretoken).Tp) == 0
                    || cbb_add_point(&mut batch_cbb, group, &mut Z_affine) == 0
                {
                    current_block = 14744330308085046661;
                    break;
                }
                let mut N: EC_JACOBIAN = EC_JACOBIAN {
                    X: EC_FELEM { words: [0; 9] },
                    Y: EC_FELEM { words: [0; 9] },
                    Z: EC_FELEM { words: [0; 9] },
                };
                let mut N_affine: EC_AFFINE = EC_AFFINE {
                    X: EC_FELEM { words: [0; 9] },
                    Y: EC_FELEM { words: [0; 9] },
                };
                if ec_point_mul_scalar(
                    group,
                    &mut N,
                    &mut *Zs.offset(i as isize),
                    &(*pretoken).r,
                ) == 0 || ec_jacobian_to_affine(group, &mut N_affine, &mut N) == 0
                {
                    current_block = 14744330308085046661;
                    break;
                }
                let mut token_cbb: CBB = cbb_st {
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
                let mut point_len: size_t = ec_point_byte_len(
                    group,
                    POINT_CONVERSION_UNCOMPRESSED,
                );
                if CBB_init(
                    &mut token_cbb,
                    ((4 as libc::c_int + 64 as libc::c_int) as size_t)
                        .wrapping_add(
                            (2 as libc::c_int as size_t).wrapping_add(point_len),
                        ),
                ) == 0 || CBB_add_u32(&mut token_cbb, key_id) == 0
                    || CBB_add_bytes(
                        &mut token_cbb,
                        ((*pretoken).salt).as_ptr(),
                        64 as libc::c_int as size_t,
                    ) == 0 || cbb_add_point(&mut token_cbb, group, &mut N_affine) == 0
                    || CBB_flush(&mut token_cbb) == 0
                {
                    CBB_cleanup(&mut token_cbb);
                    current_block = 14744330308085046661;
                    break;
                } else {
                    let mut token: *mut TRUST_TOKEN = TRUST_TOKEN_new(
                        CBB_data(&mut token_cbb),
                        CBB_len(&mut token_cbb),
                    );
                    CBB_cleanup(&mut token_cbb);
                    if token.is_null() || sk_TRUST_TOKEN_push(ret, token) == 0 {
                        TRUST_TOKEN_free(token);
                        current_block = 14744330308085046661;
                        break;
                    } else {
                        i = i.wrapping_add(1);
                        i;
                    }
                }
            }
        }
        match current_block {
            14744330308085046661 => {}
            _ => {
                let mut i_0: size_t = 0 as libc::c_int as size_t;
                loop {
                    if !(i_0 < count) {
                        current_block = 11057878835866523405;
                        break;
                    }
                    if hash_to_scalar_batch(
                        method,
                        &mut *es.offset(i_0 as isize),
                        &mut batch_cbb,
                        i_0,
                    ) == 0
                    {
                        current_block = 14744330308085046661;
                        break;
                    }
                    i_0 = i_0.wrapping_add(1);
                    i_0;
                }
                match current_block {
                    14744330308085046661 => {}
                    _ => {
                        BT_batch = EC_JACOBIAN {
                            X: EC_FELEM { words: [0; 9] },
                            Y: EC_FELEM { words: [0; 9] },
                            Z: EC_FELEM { words: [0; 9] },
                        };
                        Z_batch = EC_JACOBIAN {
                            X: EC_FELEM { words: [0; 9] },
                            Y: EC_FELEM { words: [0; 9] },
                            Z: EC_FELEM { words: [0; 9] },
                        };
                        if !(ec_point_mul_scalar_public_batch(
                            group,
                            &mut BT_batch,
                            0 as *const EC_SCALAR,
                            BTs,
                            es,
                            count,
                        ) == 0
                            || ec_point_mul_scalar_public_batch(
                                group,
                                &mut Z_batch,
                                0 as *const EC_SCALAR,
                                Zs,
                                es,
                                count,
                            ) == 0)
                        {
                            proof = cbs_st {
                                data: 0 as *const uint8_t,
                                len: 0,
                            };
                            if !(CBS_get_u16_length_prefixed(cbs, &mut proof) == 0
                                || dleq_verify(
                                    method,
                                    &mut proof,
                                    key,
                                    &mut BT_batch,
                                    &mut Z_batch,
                                ) == 0 || CBS_len(&mut proof) != 0 as libc::c_int as size_t)
                            {
                                ok = 1 as libc::c_int;
                            }
                        }
                    }
                }
            }
        }
    }
    OPENSSL_free(BTs as *mut libc::c_void);
    OPENSSL_free(Zs as *mut libc::c_void);
    OPENSSL_free(es as *mut libc::c_void);
    CBB_cleanup(&mut batch_cbb);
    if ok == 0 {
        sk_TRUST_TOKEN_pop_free(
            ret,
            Some(TRUST_TOKEN_free as unsafe extern "C" fn(*mut TRUST_TOKEN) -> ()),
        );
        ret = 0 as *mut stack_st_TRUST_TOKEN;
    }
    return ret;
}
unsafe extern "C" fn sha384_update_u16(mut ctx: *mut SHA512_CTX, mut v: uint16_t) {
    let mut buf: [uint8_t; 2] = [
        (v as libc::c_int >> 8 as libc::c_int) as uint8_t,
        (v as libc::c_int & 0xff as libc::c_int) as uint8_t,
    ];
    SHA384_Update(
        ctx,
        buf.as_mut_ptr() as *const libc::c_void,
        2 as libc::c_int as size_t,
    );
}
unsafe extern "C" fn sha384_update_point_with_length(
    mut ctx: *mut SHA512_CTX,
    mut group: *const EC_GROUP,
    mut point: *const EC_AFFINE,
) {
    let mut buf: [uint8_t; 67] = [0; 67];
    let mut len: size_t = ec_point_to_bytes(
        group,
        point,
        POINT_CONVERSION_COMPRESSED,
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 67]>() as libc::c_ulong,
    );
    if len > 0 as libc::c_int as size_t {} else {
        __assert_fail(
            b"len > 0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                as *const u8 as *const libc::c_char,
            693 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 88],
                &[libc::c_char; 88],
            >(
                b"void sha384_update_point_with_length(SHA512_CTX *, const EC_GROUP *, const EC_AFFINE *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_15336: {
        if len > 0 as libc::c_int as size_t {} else {
            __assert_fail(
                b"len > 0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                    as *const u8 as *const libc::c_char,
                693 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 88],
                    &[libc::c_char; 88],
                >(
                    b"void sha384_update_point_with_length(SHA512_CTX *, const EC_GROUP *, const EC_AFFINE *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    sha384_update_u16(ctx, len as uint16_t);
    SHA384_Update(ctx, buf.as_mut_ptr() as *const libc::c_void, len);
}
unsafe extern "C" fn compute_composite_seed(
    mut method: *const VOPRF_METHOD,
    mut out: *mut uint8_t,
    mut pub_0: *const EC_AFFINE,
) -> libc::c_int {
    let mut group: *const EC_GROUP = ((*method).group_func)
        .expect("non-null function pointer")();
    static mut kSeedDST: [uint8_t; 26] = unsafe {
        *::core::mem::transmute::<
            &[u8; 26],
            &[uint8_t; 26],
        >(b"Seed-OPRFV1-\x01-P384-SHA384\0")
    };
    let mut hash_ctx: SHA512_CTX = sha512_state_st {
        h: [0; 8],
        Nl: 0,
        Nh: 0,
        p: [0; 128],
        num: 0,
        md_len: 0,
    };
    SHA384_Init(&mut hash_ctx);
    sha384_update_point_with_length(&mut hash_ctx, group, pub_0);
    sha384_update_u16(
        &mut hash_ctx,
        (::core::mem::size_of::<[uint8_t; 26]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong) as uint16_t,
    );
    SHA384_Update(
        &mut hash_ctx,
        kSeedDST.as_ptr() as *const libc::c_void,
        (::core::mem::size_of::<[uint8_t; 26]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
    );
    SHA384_Final(out, &mut hash_ctx);
    return 1 as libc::c_int;
}
unsafe extern "C" fn compute_composite_element(
    mut method: *const VOPRF_METHOD,
    mut seed: *mut uint8_t,
    mut di: *mut EC_SCALAR,
    mut index: size_t,
    mut C: *const EC_AFFINE,
    mut D: *const EC_AFFINE,
) -> libc::c_int {
    static mut kCompositeLabel: [uint8_t; 10] = unsafe {
        *::core::mem::transmute::<&[u8; 10], &[uint8_t; 10]>(b"Composite\0")
    };
    let mut group: *const EC_GROUP = ((*method).group_func)
        .expect("non-null function pointer")();
    if index > 65535 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    let mut cbb: CBB = cbb_st {
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
    let mut transcript: [uint8_t; 195] = [0; 195];
    let mut len: size_t = 0;
    if CBB_init_fixed(
        &mut cbb,
        transcript.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 195]>() as libc::c_ulong,
    ) == 0 || CBB_add_u16(&mut cbb, 48 as libc::c_int as uint16_t) == 0
        || CBB_add_bytes(&mut cbb, seed as *const uint8_t, 48 as libc::c_int as size_t)
            == 0 || CBB_add_u16(&mut cbb, index as uint16_t) == 0
        || cbb_serialize_point(&mut cbb, group, C) == 0
        || cbb_serialize_point(&mut cbb, group, D) == 0
        || CBB_add_bytes(
            &mut cbb,
            kCompositeLabel.as_ptr(),
            (::core::mem::size_of::<[uint8_t; 10]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        ) == 0 || CBB_finish(&mut cbb, 0 as *mut *mut uint8_t, &mut len) == 0
        || ((*method).hash_to_scalar)
            .expect("non-null function pointer")(group, di, transcript.as_mut_ptr(), len)
            == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn generate_proof(
    mut method: *const VOPRF_METHOD,
    mut cbb: *mut CBB,
    mut priv_0: *const TRUST_TOKEN_ISSUER_KEY,
    mut r: *const EC_SCALAR,
    mut M: *const EC_JACOBIAN,
    mut Z: *const EC_JACOBIAN,
) -> libc::c_int {
    let mut group: *const EC_GROUP = ((*method).group_func)
        .expect("non-null function pointer")();
    let mut jacobians: [EC_JACOBIAN; 4] = [EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    }; 4];
    if ec_point_mul_scalar_base(
        group,
        &mut *jacobians.as_mut_ptr().offset(idx_t2 as libc::c_int as isize),
        r,
    ) == 0
        || ec_point_mul_scalar(
            group,
            &mut *jacobians.as_mut_ptr().offset(idx_t3 as libc::c_int as isize),
            M,
            r,
        ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut affines: [EC_AFFINE; 4] = [EC_AFFINE {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
    }; 4];
    jacobians[idx_M as libc::c_int as usize] = *M;
    jacobians[idx_Z as libc::c_int as usize] = *Z;
    if ec_jacobian_to_affine_batch(
        group,
        affines.as_mut_ptr(),
        jacobians.as_mut_ptr(),
        num_idx_1 as libc::c_int as size_t,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut c: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    if hash_to_scalar_challenge(
        method,
        &mut c,
        &(*priv_0).pubs,
        &mut *affines.as_mut_ptr().offset(idx_M as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_Z as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_t2 as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_t3 as libc::c_int as isize),
    ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut c_mont: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    ec_scalar_to_montgomery(group, &mut c_mont, &mut c);
    let mut s: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    ec_scalar_mul_montgomery(group, &mut s, &(*priv_0).xs, &mut c_mont);
    ec_scalar_sub(group, &mut s, r, &mut s);
    if scalar_to_cbb(cbb, group, &mut c) == 0 || scalar_to_cbb(cbb, group, &mut s) == 0 {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn verify_proof(
    mut method: *const VOPRF_METHOD,
    mut cbs: *mut CBS,
    mut pub_0: *const TRUST_TOKEN_CLIENT_KEY,
    mut M: *const EC_JACOBIAN,
    mut Z: *const EC_JACOBIAN,
) -> libc::c_int {
    let mut group: *const EC_GROUP = ((*method).group_func)
        .expect("non-null function pointer")();
    let mut jacobians: [EC_JACOBIAN; 4] = [EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    }; 4];
    let mut c: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut s: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    if scalar_from_cbs(cbs, group, &mut c) == 0
        || scalar_from_cbs(cbs, group, &mut s) == 0
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                as *const u8 as *const libc::c_char,
            814 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut pubs: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    ec_affine_to_jacobian(group, &mut pubs, &(*pub_0).pubs);
    if ec_point_mul_scalar_public(
        group,
        &mut *jacobians.as_mut_ptr().offset(idx_t2_0 as libc::c_int as isize),
        &mut s,
        &mut pubs,
        &mut c,
    ) == 0
        || mul_public_2(
            group,
            &mut *jacobians.as_mut_ptr().offset(idx_t3_0 as libc::c_int as isize),
            M,
            &mut s,
            Z,
            &mut c,
        ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut affines: [EC_AFFINE; 4] = [EC_AFFINE {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
    }; 4];
    jacobians[idx_M_0 as libc::c_int as usize] = *M;
    jacobians[idx_Z_0 as libc::c_int as usize] = *Z;
    if ec_jacobian_to_affine_batch(
        group,
        affines.as_mut_ptr(),
        jacobians.as_mut_ptr(),
        num_idx_2 as libc::c_int as size_t,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut expected_c: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    if hash_to_scalar_challenge(
        method,
        &mut expected_c,
        &(*pub_0).pubs,
        &mut *affines.as_mut_ptr().offset(idx_M_0 as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_Z_0 as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_t2_0 as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_t3_0 as libc::c_int as isize),
    ) == 0
    {
        return 0 as libc::c_int;
    }
    if ec_scalar_equal_vartime(group, &mut c, &mut expected_c) == 0 {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            114 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                as *const u8 as *const libc::c_char,
            842 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn voprf_sign_impl(
    mut method: *const VOPRF_METHOD,
    mut key: *const TRUST_TOKEN_ISSUER_KEY,
    mut cbb: *mut CBB,
    mut cbs: *mut CBS,
    mut num_requested: size_t,
    mut num_to_issue: size_t,
    mut proof_scalar: *const EC_SCALAR,
) -> libc::c_int {
    let mut seed: [uint8_t; 48] = [0; 48];
    let mut M: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    let mut Z_0: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    let mut proof: CBB = cbb_st {
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
    let mut point_len: size_t = 0;
    let mut current_block: u64;
    let mut group: *const EC_GROUP = ((*method).group_func)
        .expect("non-null function pointer")();
    if num_requested < num_to_issue {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            4 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                as *const u8 as *const libc::c_char,
            855 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut BTs: *mut EC_JACOBIAN = OPENSSL_calloc(
        num_to_issue,
        ::core::mem::size_of::<EC_JACOBIAN>() as libc::c_ulong,
    ) as *mut EC_JACOBIAN;
    let mut Zs: *mut EC_JACOBIAN = OPENSSL_calloc(
        num_to_issue,
        ::core::mem::size_of::<EC_JACOBIAN>() as libc::c_ulong,
    ) as *mut EC_JACOBIAN;
    let mut dis: *mut EC_SCALAR = OPENSSL_calloc(
        num_to_issue,
        ::core::mem::size_of::<EC_SCALAR>() as libc::c_ulong,
    ) as *mut EC_SCALAR;
    if !(BTs.is_null() || Zs.is_null() || dis.is_null()) {
        seed = [0; 48];
        if !(compute_composite_seed(method, seed.as_mut_ptr(), &(*key).pubs) == 0) {
            let mut i: size_t = 0 as libc::c_int as size_t;
            loop {
                if !(i < num_to_issue) {
                    current_block = 6057473163062296781;
                    break;
                }
                let mut BT_affine: EC_AFFINE = EC_AFFINE {
                    X: EC_FELEM { words: [0; 9] },
                    Y: EC_FELEM { words: [0; 9] },
                };
                let mut Z_affine: EC_AFFINE = EC_AFFINE {
                    X: EC_FELEM { words: [0; 9] },
                    Y: EC_FELEM { words: [0; 9] },
                };
                let mut BT: EC_JACOBIAN = EC_JACOBIAN {
                    X: EC_FELEM { words: [0; 9] },
                    Y: EC_FELEM { words: [0; 9] },
                    Z: EC_FELEM { words: [0; 9] },
                };
                let mut Z: EC_JACOBIAN = EC_JACOBIAN {
                    X: EC_FELEM { words: [0; 9] },
                    Y: EC_FELEM { words: [0; 9] },
                    Z: EC_FELEM { words: [0; 9] },
                };
                if cbs_get_point(cbs, group, &mut BT_affine) == 0 {
                    ERR_put_error(
                        32 as libc::c_int,
                        0 as libc::c_int,
                        105 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                            as *const u8 as *const libc::c_char,
                        881 as libc::c_int as libc::c_uint,
                    );
                    current_block = 6581931133099431905;
                    break;
                } else {
                    ec_affine_to_jacobian(group, &mut BT, &mut BT_affine);
                    if ec_point_mul_scalar(group, &mut Z, &mut BT, &(*key).xs) == 0
                        || ec_jacobian_to_affine(group, &mut Z_affine, &mut Z) == 0
                        || cbb_add_point(cbb, group, &mut Z_affine) == 0
                    {
                        current_block = 6581931133099431905;
                        break;
                    }
                    *BTs.offset(i as isize) = BT;
                    *Zs.offset(i as isize) = Z;
                    if compute_composite_element(
                        method,
                        seed.as_mut_ptr(),
                        &mut *dis.offset(i as isize),
                        i,
                        &mut BT_affine,
                        &mut Z_affine,
                    ) == 0
                    {
                        current_block = 6581931133099431905;
                        break;
                    }
                    if CBB_flush(cbb) == 0 {
                        current_block = 6581931133099431905;
                        break;
                    }
                    i = i.wrapping_add(1);
                    i;
                }
            }
            match current_block {
                6581931133099431905 => {}
                _ => {
                    M = EC_JACOBIAN {
                        X: EC_FELEM { words: [0; 9] },
                        Y: EC_FELEM { words: [0; 9] },
                        Z: EC_FELEM { words: [0; 9] },
                    };
                    Z_0 = EC_JACOBIAN {
                        X: EC_FELEM { words: [0; 9] },
                        Y: EC_FELEM { words: [0; 9] },
                        Z: EC_FELEM { words: [0; 9] },
                    };
                    if !(ec_point_mul_scalar_public_batch(
                        group,
                        &mut M,
                        0 as *const EC_SCALAR,
                        BTs,
                        dis,
                        num_to_issue,
                    ) == 0
                        || ec_point_mul_scalar(group, &mut Z_0, &mut M, &(*key).xs) == 0)
                    {
                        proof = cbb_st {
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
                        if !(CBB_add_u16_length_prefixed(cbb, &mut proof) == 0
                            || generate_proof(
                                method,
                                &mut proof,
                                key,
                                proof_scalar,
                                &mut M,
                                &mut Z_0,
                            ) == 0 || CBB_flush(cbb) == 0)
                        {
                            point_len = ec_point_byte_len(
                                group,
                                POINT_CONVERSION_UNCOMPRESSED,
                            );
                            if CBS_skip(
                                cbs,
                                point_len * num_requested.wrapping_sub(num_to_issue),
                            ) == 0
                            {
                                ERR_put_error(
                                    32 as libc::c_int,
                                    0 as libc::c_int,
                                    105 as libc::c_int,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                                        as *const u8 as *const libc::c_char,
                                    920 as libc::c_int as libc::c_uint,
                                );
                            } else {
                                ret = 1 as libc::c_int;
                            }
                        }
                    }
                }
            }
        }
    }
    OPENSSL_free(BTs as *mut libc::c_void);
    OPENSSL_free(Zs as *mut libc::c_void);
    OPENSSL_free(dis as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn voprf_sign(
    mut method: *const VOPRF_METHOD,
    mut key: *const TRUST_TOKEN_ISSUER_KEY,
    mut cbb: *mut CBB,
    mut cbs: *mut CBS,
    mut num_requested: size_t,
    mut num_to_issue: size_t,
) -> libc::c_int {
    let mut proof_scalar: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    if ec_random_nonzero_scalar(
        ((*method).group_func).expect("non-null function pointer")(),
        &mut proof_scalar,
        kDefaultAdditionalData.as_ptr(),
    ) == 0
    {
        return 0 as libc::c_int;
    }
    return voprf_sign_impl(
        method,
        key,
        cbb,
        cbs,
        num_requested,
        num_to_issue,
        &mut proof_scalar,
    );
}
unsafe extern "C" fn voprf_sign_with_proof_scalar_for_testing(
    mut method: *const VOPRF_METHOD,
    mut key: *const TRUST_TOKEN_ISSUER_KEY,
    mut cbb: *mut CBB,
    mut cbs: *mut CBS,
    mut num_requested: size_t,
    mut num_to_issue: size_t,
    mut proof_scalar_buf: *const uint8_t,
    mut proof_scalar_len: size_t,
) -> libc::c_int {
    let mut proof_scalar: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    if ec_scalar_from_bytes(
        ((*method).group_func).expect("non-null function pointer")(),
        &mut proof_scalar,
        proof_scalar_buf,
        proof_scalar_len,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    return voprf_sign_impl(
        method,
        key,
        cbb,
        cbs,
        num_requested,
        num_to_issue,
        &mut proof_scalar,
    );
}
unsafe extern "C" fn voprf_unblind(
    mut method: *const VOPRF_METHOD,
    mut key: *const TRUST_TOKEN_CLIENT_KEY,
    mut pretokens: *const stack_st_TRUST_TOKEN_PRETOKEN,
    mut cbs: *mut CBS,
    mut count: size_t,
    mut key_id: uint32_t,
) -> *mut stack_st_TRUST_TOKEN {
    let mut seed: [uint8_t; 48] = [0; 48];
    let mut M: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    let mut Z: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    let mut proof: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut current_block: u64;
    let mut group: *const EC_GROUP = ((*method).group_func)
        .expect("non-null function pointer")();
    if count > sk_TRUST_TOKEN_PRETOKEN_num(pretokens) {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                as *const u8 as *const libc::c_char,
            965 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut stack_st_TRUST_TOKEN;
    }
    let mut ok: libc::c_int = 0 as libc::c_int;
    let mut ret: *mut stack_st_TRUST_TOKEN = sk_TRUST_TOKEN_new_null();
    let mut BTs: *mut EC_JACOBIAN = OPENSSL_calloc(
        count,
        ::core::mem::size_of::<EC_JACOBIAN>() as libc::c_ulong,
    ) as *mut EC_JACOBIAN;
    let mut Zs: *mut EC_JACOBIAN = OPENSSL_calloc(
        count,
        ::core::mem::size_of::<EC_JACOBIAN>() as libc::c_ulong,
    ) as *mut EC_JACOBIAN;
    let mut dis: *mut EC_SCALAR = OPENSSL_calloc(
        count,
        ::core::mem::size_of::<EC_SCALAR>() as libc::c_ulong,
    ) as *mut EC_SCALAR;
    if !(ret.is_null() || BTs.is_null() || Zs.is_null() || dis.is_null()) {
        seed = [0; 48];
        if !(compute_composite_seed(method, seed.as_mut_ptr(), &(*key).pubs) == 0) {
            let mut i: size_t = 0 as libc::c_int as size_t;
            loop {
                if !(i < count) {
                    current_block = 10652014663920648156;
                    break;
                }
                let mut pretoken: *const TRUST_TOKEN_PRETOKEN = sk_TRUST_TOKEN_PRETOKEN_value(
                    pretokens,
                    i,
                );
                let mut Z_affine: EC_AFFINE = EC_AFFINE {
                    X: EC_FELEM { words: [0; 9] },
                    Y: EC_FELEM { words: [0; 9] },
                };
                if cbs_get_point(cbs, group, &mut Z_affine) == 0 {
                    ERR_put_error(
                        32 as libc::c_int,
                        0 as libc::c_int,
                        105 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                            as *const u8 as *const libc::c_char,
                        989 as libc::c_int as libc::c_uint,
                    );
                    current_block = 3271130952265118202;
                    break;
                } else {
                    ec_affine_to_jacobian(
                        group,
                        &mut *BTs.offset(i as isize),
                        &(*pretoken).Tp,
                    );
                    ec_affine_to_jacobian(
                        group,
                        &mut *Zs.offset(i as isize),
                        &mut Z_affine,
                    );
                    if compute_composite_element(
                        method,
                        seed.as_mut_ptr(),
                        &mut *dis.offset(i as isize),
                        i,
                        &(*pretoken).Tp,
                        &mut Z_affine,
                    ) == 0
                    {
                        current_block = 3271130952265118202;
                        break;
                    }
                    let mut N: EC_JACOBIAN = EC_JACOBIAN {
                        X: EC_FELEM { words: [0; 9] },
                        Y: EC_FELEM { words: [0; 9] },
                        Z: EC_FELEM { words: [0; 9] },
                    };
                    let mut N_affine: EC_AFFINE = EC_AFFINE {
                        X: EC_FELEM { words: [0; 9] },
                        Y: EC_FELEM { words: [0; 9] },
                    };
                    if ec_point_mul_scalar(
                        group,
                        &mut N,
                        &mut *Zs.offset(i as isize),
                        &(*pretoken).r,
                    ) == 0 || ec_jacobian_to_affine(group, &mut N_affine, &mut N) == 0
                    {
                        current_block = 3271130952265118202;
                        break;
                    }
                    let mut token_cbb: CBB = cbb_st {
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
                    let mut point_len: size_t = ec_point_byte_len(
                        group,
                        POINT_CONVERSION_UNCOMPRESSED,
                    );
                    if CBB_init(
                        &mut token_cbb,
                        ((4 as libc::c_int + 64 as libc::c_int) as size_t)
                            .wrapping_add(
                                (2 as libc::c_int as size_t).wrapping_add(point_len),
                            ),
                    ) == 0 || CBB_add_u32(&mut token_cbb, key_id) == 0
                        || CBB_add_bytes(
                            &mut token_cbb,
                            ((*pretoken).salt).as_ptr(),
                            64 as libc::c_int as size_t,
                        ) == 0
                        || cbb_add_point(&mut token_cbb, group, &mut N_affine) == 0
                        || CBB_flush(&mut token_cbb) == 0
                    {
                        CBB_cleanup(&mut token_cbb);
                        current_block = 3271130952265118202;
                        break;
                    } else {
                        let mut token: *mut TRUST_TOKEN = TRUST_TOKEN_new(
                            CBB_data(&mut token_cbb),
                            CBB_len(&mut token_cbb),
                        );
                        CBB_cleanup(&mut token_cbb);
                        if token.is_null() || sk_TRUST_TOKEN_push(ret, token) == 0 {
                            TRUST_TOKEN_free(token);
                            current_block = 3271130952265118202;
                            break;
                        } else {
                            i = i.wrapping_add(1);
                            i;
                        }
                    }
                }
            }
            match current_block {
                3271130952265118202 => {}
                _ => {
                    M = EC_JACOBIAN {
                        X: EC_FELEM { words: [0; 9] },
                        Y: EC_FELEM { words: [0; 9] },
                        Z: EC_FELEM { words: [0; 9] },
                    };
                    Z = EC_JACOBIAN {
                        X: EC_FELEM { words: [0; 9] },
                        Y: EC_FELEM { words: [0; 9] },
                        Z: EC_FELEM { words: [0; 9] },
                    };
                    if !(ec_point_mul_scalar_public_batch(
                        group,
                        &mut M,
                        0 as *const EC_SCALAR,
                        BTs,
                        dis,
                        count,
                    ) == 0
                        || ec_point_mul_scalar_public_batch(
                            group,
                            &mut Z,
                            0 as *const EC_SCALAR,
                            Zs,
                            dis,
                            count,
                        ) == 0)
                    {
                        proof = cbs_st {
                            data: 0 as *const uint8_t,
                            len: 0,
                        };
                        if !(CBS_get_u16_length_prefixed(cbs, &mut proof) == 0
                            || verify_proof(method, &mut proof, key, &mut M, &mut Z) == 0
                            || CBS_len(&mut proof) != 0 as libc::c_int as size_t)
                        {
                            ok = 1 as libc::c_int;
                        }
                    }
                }
            }
        }
    }
    OPENSSL_free(BTs as *mut libc::c_void);
    OPENSSL_free(Zs as *mut libc::c_void);
    OPENSSL_free(dis as *mut libc::c_void);
    if ok == 0 {
        sk_TRUST_TOKEN_pop_free(
            ret,
            Some(TRUST_TOKEN_free as unsafe extern "C" fn(*mut TRUST_TOKEN) -> ()),
        );
        ret = 0 as *mut stack_st_TRUST_TOKEN;
    }
    return ret;
}
unsafe extern "C" fn voprf_read(
    mut method: *const VOPRF_METHOD,
    mut key: *const TRUST_TOKEN_ISSUER_KEY,
    mut out_nonce: *mut uint8_t,
    mut token: *const uint8_t,
    mut token_len: size_t,
    mut include_message: libc::c_int,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> libc::c_int {
    let mut group: *const EC_GROUP = ((*method).group_func)
        .expect("non-null function pointer")();
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut salt: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, token, token_len);
    let mut Ws: EC_AFFINE = EC_AFFINE {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
    };
    if CBS_get_bytes(&mut cbs, &mut salt, 64 as libc::c_int as size_t) == 0
        || cbs_get_point(&mut cbs, group, &mut Ws) == 0
        || CBS_len(&mut cbs) != 0 as libc::c_int as size_t
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            110 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                as *const u8 as *const libc::c_char,
            1074 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if include_message != 0 {
        let mut hash_ctx: SHA512_CTX = sha512_state_st {
            h: [0; 8],
            Nl: 0,
            Nh: 0,
            p: [0; 128],
            num: 0,
            md_len: 0,
        };
        if 64 as libc::c_int == 64 as libc::c_int {} else {
            __assert_fail(
                b"SHA512_DIGEST_LENGTH == TRUST_TOKEN_NONCE_SIZE\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                    as *const u8 as *const libc::c_char,
                1080 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 135],
                    &[libc::c_char; 135],
                >(
                    b"int voprf_read(const VOPRF_METHOD *, const TRUST_TOKEN_ISSUER_KEY *, uint8_t *, const uint8_t *, size_t, int, const uint8_t *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_13943: {
            if 64 as libc::c_int == 64 as libc::c_int {} else {
                __assert_fail(
                    b"SHA512_DIGEST_LENGTH == TRUST_TOKEN_NONCE_SIZE\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                        as *const u8 as *const libc::c_char,
                    1080 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 135],
                        &[libc::c_char; 135],
                    >(
                        b"int voprf_read(const VOPRF_METHOD *, const TRUST_TOKEN_ISSUER_KEY *, uint8_t *, const uint8_t *, size_t, int, const uint8_t *, size_t)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        SHA512_Init(&mut hash_ctx);
        SHA512_Update(
            &mut hash_ctx,
            CBS_data(&mut salt) as *const libc::c_void,
            CBS_len(&mut salt),
        );
        SHA512_Update(&mut hash_ctx, msg as *const libc::c_void, msg_len);
        SHA512_Final(out_nonce, &mut hash_ctx);
    } else {
        OPENSSL_memcpy(
            out_nonce as *mut libc::c_void,
            CBS_data(&mut salt) as *const libc::c_void,
            CBS_len(&mut salt),
        );
    }
    let mut T: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    if ((*method).hash_to_group)
        .expect("non-null function pointer")(group, &mut T, out_nonce as *const uint8_t)
        == 0
    {
        return 0 as libc::c_int;
    }
    let mut Ws_calculated: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    if ec_point_mul_scalar(group, &mut Ws_calculated, &mut T, &(*key).xs) == 0
        || ec_affine_jacobian_equal(group, &mut Ws, &mut Ws_calculated) == 0
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            111 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/voprf.c\0"
                as *const u8 as *const libc::c_char,
            1098 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn voprf_exp2_hash_to_group(
    mut group: *const EC_GROUP,
    mut out: *mut EC_JACOBIAN,
    mut t: *const uint8_t,
) -> libc::c_int {
    let kHashTLabel: [uint8_t; 43] = *::core::mem::transmute::<
        &[u8; 43],
        &[uint8_t; 43],
    >(b"TrustToken VOPRF Experiment V2 HashToGroup\0");
    return ec_hash_to_curve_p384_xmd_sha512_sswu_draft07(
        group,
        out,
        kHashTLabel.as_ptr(),
        ::core::mem::size_of::<[uint8_t; 43]>() as libc::c_ulong,
        t,
        64 as libc::c_int as size_t,
    );
}
unsafe extern "C" fn voprf_exp2_hash_to_scalar(
    mut group: *const EC_GROUP,
    mut out: *mut EC_SCALAR,
    mut buf: *mut uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let kHashCLabel: [uint8_t; 44] = *::core::mem::transmute::<
        &[u8; 44],
        &[uint8_t; 44],
    >(b"TrustToken VOPRF Experiment V2 HashToScalar\0");
    return ec_hash_to_scalar_p384_xmd_sha512_draft07(
        group,
        out,
        kHashCLabel.as_ptr(),
        ::core::mem::size_of::<[uint8_t; 44]>() as libc::c_ulong,
        buf,
        len,
    );
}
static mut voprf_exp2_method: VOPRF_METHOD = unsafe {
    {
        let mut init = VOPRF_METHOD {
            group_func: Some(EC_group_p384 as unsafe extern "C" fn() -> *const EC_GROUP),
            hash_to_group: Some(
                voprf_exp2_hash_to_group
                    as unsafe extern "C" fn(
                        *const EC_GROUP,
                        *mut EC_JACOBIAN,
                        *const uint8_t,
                    ) -> libc::c_int,
            ),
            hash_to_scalar: Some(
                voprf_exp2_hash_to_scalar
                    as unsafe extern "C" fn(
                        *const EC_GROUP,
                        *mut EC_SCALAR,
                        *mut uint8_t,
                        size_t,
                    ) -> libc::c_int,
            ),
        };
        init
    }
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn voprf_exp2_generate_key(
    mut out_private: *mut CBB,
    mut out_public: *mut CBB,
) -> libc::c_int {
    return voprf_generate_key(&mut voprf_exp2_method, out_private, out_public);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn voprf_exp2_derive_key_from_secret(
    mut out_private: *mut CBB,
    mut out_public: *mut CBB,
    mut secret: *const uint8_t,
    mut secret_len: size_t,
) -> libc::c_int {
    return voprf_derive_key_from_secret(
        &mut voprf_exp2_method,
        out_private,
        out_public,
        secret,
        secret_len,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn voprf_exp2_client_key_from_bytes(
    mut key: *mut TRUST_TOKEN_CLIENT_KEY,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    return voprf_client_key_from_bytes(&mut voprf_exp2_method, key, in_0, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn voprf_exp2_issuer_key_from_bytes(
    mut key: *mut TRUST_TOKEN_ISSUER_KEY,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    return voprf_issuer_key_from_bytes(&mut voprf_exp2_method, key, in_0, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn voprf_exp2_blind(
    mut cbb: *mut CBB,
    mut count: size_t,
    mut include_message: libc::c_int,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> *mut stack_st_TRUST_TOKEN_PRETOKEN {
    return voprf_blind(
        &mut voprf_exp2_method,
        cbb,
        count,
        include_message,
        msg,
        msg_len,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn voprf_exp2_sign(
    mut key: *const TRUST_TOKEN_ISSUER_KEY,
    mut cbb: *mut CBB,
    mut cbs: *mut CBS,
    mut num_requested: size_t,
    mut num_to_issue: size_t,
    mut private_metadata: uint8_t,
) -> libc::c_int {
    if private_metadata as libc::c_int != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    return voprf_sign_tt(
        &mut voprf_exp2_method,
        key,
        cbb,
        cbs,
        num_requested,
        num_to_issue,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn voprf_exp2_unblind(
    mut key: *const TRUST_TOKEN_CLIENT_KEY,
    mut pretokens: *const stack_st_TRUST_TOKEN_PRETOKEN,
    mut cbs: *mut CBS,
    mut count: size_t,
    mut key_id: uint32_t,
) -> *mut stack_st_TRUST_TOKEN {
    return voprf_unblind_tt(&mut voprf_exp2_method, key, pretokens, cbs, count, key_id);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn voprf_exp2_read(
    mut key: *const TRUST_TOKEN_ISSUER_KEY,
    mut out_nonce: *mut uint8_t,
    mut out_private_metadata: *mut uint8_t,
    mut token: *const uint8_t,
    mut token_len: size_t,
    mut include_message: libc::c_int,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> libc::c_int {
    return voprf_read(
        &mut voprf_exp2_method,
        key,
        out_nonce,
        token,
        token_len,
        include_message,
        msg,
        msg_len,
    );
}
unsafe extern "C" fn voprf_pst1_hash_to_group(
    mut group: *const EC_GROUP,
    mut out: *mut EC_JACOBIAN,
    mut t: *const uint8_t,
) -> libc::c_int {
    let kHashTLabel: [uint8_t; 33] = *::core::mem::transmute::<
        &[u8; 33],
        &[uint8_t; 33],
    >(b"HashToGroup-OPRFV1-\x01-P384-SHA384\0");
    return ec_hash_to_curve_p384_xmd_sha384_sswu(
        group,
        out,
        kHashTLabel.as_ptr(),
        (::core::mem::size_of::<[uint8_t; 33]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        t,
        64 as libc::c_int as size_t,
    );
}
unsafe extern "C" fn voprf_pst1_hash_to_scalar(
    mut group: *const EC_GROUP,
    mut out: *mut EC_SCALAR,
    mut buf: *mut uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let kHashCLabel: [uint8_t; 34] = *::core::mem::transmute::<
        &[u8; 34],
        &[uint8_t; 34],
    >(b"HashToScalar-OPRFV1-\x01-P384-SHA384\0");
    return ec_hash_to_scalar_p384_xmd_sha384(
        group,
        out,
        kHashCLabel.as_ptr(),
        (::core::mem::size_of::<[uint8_t; 34]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        buf,
        len,
    );
}
static mut voprf_pst1_method: VOPRF_METHOD = unsafe {
    {
        let mut init = VOPRF_METHOD {
            group_func: Some(EC_group_p384 as unsafe extern "C" fn() -> *const EC_GROUP),
            hash_to_group: Some(
                voprf_pst1_hash_to_group
                    as unsafe extern "C" fn(
                        *const EC_GROUP,
                        *mut EC_JACOBIAN,
                        *const uint8_t,
                    ) -> libc::c_int,
            ),
            hash_to_scalar: Some(
                voprf_pst1_hash_to_scalar
                    as unsafe extern "C" fn(
                        *const EC_GROUP,
                        *mut EC_SCALAR,
                        *mut uint8_t,
                        size_t,
                    ) -> libc::c_int,
            ),
        };
        init
    }
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn voprf_pst1_generate_key(
    mut out_private: *mut CBB,
    mut out_public: *mut CBB,
) -> libc::c_int {
    return voprf_generate_key(&mut voprf_pst1_method, out_private, out_public);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn voprf_pst1_derive_key_from_secret(
    mut out_private: *mut CBB,
    mut out_public: *mut CBB,
    mut secret: *const uint8_t,
    mut secret_len: size_t,
) -> libc::c_int {
    return voprf_derive_key_from_secret(
        &mut voprf_pst1_method,
        out_private,
        out_public,
        secret,
        secret_len,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn voprf_pst1_client_key_from_bytes(
    mut key: *mut TRUST_TOKEN_CLIENT_KEY,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    return voprf_client_key_from_bytes(&mut voprf_pst1_method, key, in_0, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn voprf_pst1_issuer_key_from_bytes(
    mut key: *mut TRUST_TOKEN_ISSUER_KEY,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    return voprf_issuer_key_from_bytes(&mut voprf_pst1_method, key, in_0, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn voprf_pst1_blind(
    mut cbb: *mut CBB,
    mut count: size_t,
    mut include_message: libc::c_int,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> *mut stack_st_TRUST_TOKEN_PRETOKEN {
    return voprf_blind(
        &mut voprf_pst1_method,
        cbb,
        count,
        include_message,
        msg,
        msg_len,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn voprf_pst1_sign(
    mut key: *const TRUST_TOKEN_ISSUER_KEY,
    mut cbb: *mut CBB,
    mut cbs: *mut CBS,
    mut num_requested: size_t,
    mut num_to_issue: size_t,
    mut private_metadata: uint8_t,
) -> libc::c_int {
    if private_metadata as libc::c_int != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    return voprf_sign(
        &mut voprf_pst1_method,
        key,
        cbb,
        cbs,
        num_requested,
        num_to_issue,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn voprf_pst1_sign_with_proof_scalar_for_testing(
    mut key: *const TRUST_TOKEN_ISSUER_KEY,
    mut cbb: *mut CBB,
    mut cbs: *mut CBS,
    mut num_requested: size_t,
    mut num_to_issue: size_t,
    mut private_metadata: uint8_t,
    mut proof_scalar_buf: *const uint8_t,
    mut proof_scalar_len: size_t,
) -> libc::c_int {
    if private_metadata as libc::c_int != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    return voprf_sign_with_proof_scalar_for_testing(
        &mut voprf_pst1_method,
        key,
        cbb,
        cbs,
        num_requested,
        num_to_issue,
        proof_scalar_buf,
        proof_scalar_len,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn voprf_pst1_unblind(
    mut key: *const TRUST_TOKEN_CLIENT_KEY,
    mut pretokens: *const stack_st_TRUST_TOKEN_PRETOKEN,
    mut cbs: *mut CBS,
    mut count: size_t,
    mut key_id: uint32_t,
) -> *mut stack_st_TRUST_TOKEN {
    return voprf_unblind(&mut voprf_pst1_method, key, pretokens, cbs, count, key_id);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn voprf_pst1_read(
    mut key: *const TRUST_TOKEN_ISSUER_KEY,
    mut out_nonce: *mut uint8_t,
    mut out_private_metadata: *mut uint8_t,
    mut token: *const uint8_t,
    mut token_len: size_t,
    mut include_message: libc::c_int,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> libc::c_int {
    return voprf_read(
        &mut voprf_pst1_method,
        key,
        out_nonce,
        token,
        token_len,
        include_message,
        msg,
        msg_len,
    );
}
