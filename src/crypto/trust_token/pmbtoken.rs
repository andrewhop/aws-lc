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
    fn CBS_copy_bytes(cbs: *mut CBS, out: *mut uint8_t, len: size_t) -> libc::c_int;
    fn CBS_get_u16_length_prefixed(cbs: *mut CBS, out: *mut CBS) -> libc::c_int;
    fn CBB_zero(cbb: *mut CBB);
    fn CBB_init(cbb: *mut CBB, initial_capacity: size_t) -> libc::c_int;
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
    fn CBB_add_u8(cbb: *mut CBB, value: uint8_t) -> libc::c_int;
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
    fn ec_scalar_select(
        group: *const EC_GROUP,
        out: *mut EC_SCALAR,
        mask: BN_ULONG,
        a: *const EC_SCALAR,
        b: *const EC_SCALAR,
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
    fn ec_point_mul_scalar_batch(
        group: *const EC_GROUP,
        r: *mut EC_JACOBIAN,
        p0: *const EC_JACOBIAN,
        scalar0: *const EC_SCALAR,
        p1: *const EC_JACOBIAN,
        scalar1: *const EC_SCALAR,
        p2: *const EC_JACOBIAN,
        scalar2: *const EC_SCALAR,
    ) -> libc::c_int;
    fn ec_init_precomp(
        group: *const EC_GROUP,
        out: *mut EC_PRECOMP,
        p: *const EC_JACOBIAN,
    ) -> libc::c_int;
    fn ec_point_mul_scalar_precomp(
        group: *const EC_GROUP,
        r: *mut EC_JACOBIAN,
        p0: *const EC_PRECOMP,
        scalar0: *const EC_SCALAR,
        p1: *const EC_PRECOMP,
        scalar1: *const EC_SCALAR,
        p2: *const EC_PRECOMP,
        scalar2: *const EC_SCALAR,
    ) -> libc::c_int;
    fn ec_point_mul_scalar_public_batch(
        group: *const EC_GROUP,
        r: *mut EC_JACOBIAN,
        g_scalar: *const EC_SCALAR,
        points: *const EC_JACOBIAN,
        scalars: *const EC_SCALAR,
        num: size_t,
    ) -> libc::c_int;
    fn ec_affine_select(
        group: *const EC_GROUP,
        out: *mut EC_AFFINE,
        mask: BN_ULONG,
        a: *const EC_AFFINE,
        b: *const EC_AFFINE,
    );
    fn ec_precomp_select(
        group: *const EC_GROUP,
        out: *mut EC_PRECOMP,
        mask: BN_ULONG,
        a: *const EC_PRECOMP,
        b: *const EC_PRECOMP,
    );
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
    fn CRYPTO_once(
        once: *mut CRYPTO_once_t,
        init: Option::<unsafe extern "C" fn() -> ()>,
    );
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
pub type pthread_once_t = libc::c_int;
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
pub type CRYPTO_once_t = pthread_once_t;
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
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct PMBTOKEN_METHOD {
    pub group: *const EC_GROUP,
    pub g_precomp: EC_PRECOMP,
    pub h_precomp: EC_PRECOMP,
    pub h: EC_JACOBIAN,
    pub hash_t: hash_t_func_t,
    pub hash_s: hash_s_func_t,
    pub hash_c: hash_c_func_t,
    pub hash_to_scalar: hash_to_scalar_func_t,
    #[bitfield(name = "prefix_point", ty = "libc::c_int", bits = "0..=0")]
    pub prefix_point: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
pub type hash_to_scalar_func_t = Option::<
    unsafe extern "C" fn(
        *const EC_GROUP,
        *mut EC_SCALAR,
        *mut uint8_t,
        size_t,
    ) -> libc::c_int,
>;
pub type hash_c_func_t = Option::<
    unsafe extern "C" fn(
        *const EC_GROUP,
        *mut EC_SCALAR,
        *mut uint8_t,
        size_t,
    ) -> libc::c_int,
>;
pub type hash_s_func_t = Option::<
    unsafe extern "C" fn(
        *const EC_GROUP,
        *mut EC_JACOBIAN,
        *const EC_AFFINE,
        *const uint8_t,
    ) -> libc::c_int,
>;
pub type hash_t_func_t = Option::<
    unsafe extern "C" fn(
        *const EC_GROUP,
        *mut EC_JACOBIAN,
        *const uint8_t,
    ) -> libc::c_int,
>;
pub const idx_W: C2RustUnnamed_0 = 2;
pub const idx_S: C2RustUnnamed_0 = 1;
pub const idx_T: C2RustUnnamed_0 = 0;
pub const idx_Ks1: C2RustUnnamed_0 = 5;
pub const idx_Ks0: C2RustUnnamed_0 = 4;
pub const idx_Ws: C2RustUnnamed_0 = 3;
pub const idx_Ko1: C2RustUnnamed_0 = 9;
pub const idx_Kb1: C2RustUnnamed_0 = 7;
pub const idx_Ko0: C2RustUnnamed_0 = 8;
pub const idx_Kb0: C2RustUnnamed_0 = 6;
pub const num_idx: C2RustUnnamed_0 = 10;
pub type C2RustUnnamed_0 = libc::c_uint;
pub const idx_K11: C2RustUnnamed_1 = 9;
pub const idx_K10: C2RustUnnamed_1 = 8;
pub const idx_K01: C2RustUnnamed_1 = 7;
pub const idx_K00: C2RustUnnamed_1 = 6;
pub const idx_W_0: C2RustUnnamed_1 = 2;
pub const idx_S_0: C2RustUnnamed_1 = 1;
pub const idx_T_0: C2RustUnnamed_1 = 0;
pub const idx_Ks1_0: C2RustUnnamed_1 = 5;
pub const idx_Ks0_0: C2RustUnnamed_1 = 4;
pub const idx_Ws_0: C2RustUnnamed_1 = 3;
pub const num_idx_0: C2RustUnnamed_1 = 10;
pub type C2RustUnnamed_1 = libc::c_uint;
#[inline]
unsafe extern "C" fn sk_TRUST_TOKEN_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<OPENSSL_sk_free_func, sk_TRUST_TOKEN_free_func>(free_func))
        .expect("non-null function pointer")(ptr as *mut TRUST_TOKEN);
}
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
unsafe extern "C" fn sk_TRUST_TOKEN_push(
    mut sk: *mut stack_st_TRUST_TOKEN,
    mut p: *mut TRUST_TOKEN,
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
unsafe extern "C" fn pmbtoken_init_method(
    mut method: *mut PMBTOKEN_METHOD,
    mut group: *const EC_GROUP,
    mut h_bytes: *const uint8_t,
    mut h_len: size_t,
    mut hash_t: hash_t_func_t,
    mut hash_s: hash_s_func_t,
    mut hash_c: hash_c_func_t,
    mut hash_to_scalar: hash_to_scalar_func_t,
    mut prefix_point: libc::c_int,
) -> libc::c_int {
    (*method).group = group;
    (*method).hash_t = hash_t;
    (*method).hash_s = hash_s;
    (*method).hash_c = hash_c;
    (*method).hash_to_scalar = hash_to_scalar;
    (*method).set_prefix_point(prefix_point);
    let mut h: EC_AFFINE = EC_AFFINE {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
    };
    if ec_point_from_uncompressed((*method).group, &mut h, h_bytes, h_len) == 0 {
        return 0 as libc::c_int;
    }
    ec_affine_to_jacobian((*method).group, &mut (*method).h, &mut h);
    if ec_init_precomp(
        (*method).group,
        &mut (*method).g_precomp,
        &(*(*method).group).generator.raw,
    ) == 0
        || ec_init_precomp((*method).group, &mut (*method).h_precomp, &mut (*method).h)
            == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn derive_scalar_from_secret(
    mut method: *const PMBTOKEN_METHOD,
    mut out: *mut EC_SCALAR,
    mut secret: *const uint8_t,
    mut secret_len: size_t,
    mut scalar_id: uint8_t,
) -> libc::c_int {
    static mut kKeygenLabel: [uint8_t; 25] = unsafe {
        *::core::mem::transmute::<
            &[u8; 25],
            &[uint8_t; 25],
        >(b"TrustTokenPMBTokenKeyGen\0")
    };
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
            ::core::mem::size_of::<[uint8_t; 25]>() as libc::c_ulong,
        ) == 0 || CBB_add_u8(&mut cbb, scalar_id) == 0
        || CBB_add_bytes(&mut cbb, secret, secret_len) == 0
        || CBB_finish(&mut cbb, &mut buf, &mut len) == 0
        || ((*method).hash_to_scalar)
            .expect("non-null function pointer")((*method).group, out, buf, len) == 0
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                as *const u8 as *const libc::c_char,
            108 as libc::c_int as libc::c_uint,
        );
    } else {
        ok = 1 as libc::c_int;
    }
    CBB_cleanup(&mut cbb);
    OPENSSL_free(buf as *mut libc::c_void);
    return ok;
}
unsafe extern "C" fn point_to_cbb(
    mut out: *mut CBB,
    mut group: *const EC_GROUP,
    mut point: *const EC_AFFINE,
) -> libc::c_int {
    let mut len: size_t = ec_point_byte_len(group, POINT_CONVERSION_UNCOMPRESSED);
    if len == 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    let mut p: *mut uint8_t = 0 as *mut uint8_t;
    return (CBB_add_space(out, &mut p, len) != 0
        && ec_point_to_bytes(group, point, POINT_CONVERSION_UNCOMPRESSED, p, len) == len)
        as libc::c_int;
}
unsafe extern "C" fn cbb_add_prefixed_point(
    mut out: *mut CBB,
    mut group: *const EC_GROUP,
    mut point: *const EC_AFFINE,
    mut prefix_point: libc::c_int,
) -> libc::c_int {
    if prefix_point != 0 {
        let mut child: CBB = cbb_st {
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
        if CBB_add_u16_length_prefixed(out, &mut child) == 0
            || point_to_cbb(&mut child, group, point) == 0 || CBB_flush(out) == 0
        {
            return 0 as libc::c_int;
        }
    } else if point_to_cbb(out, group, point) == 0 || CBB_flush(out) == 0 {
        return 0 as libc::c_int
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn cbs_get_prefixed_point(
    mut cbs: *mut CBS,
    mut group: *const EC_GROUP,
    mut out: *mut EC_AFFINE,
    mut prefix_point: libc::c_int,
) -> libc::c_int {
    let mut child: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if prefix_point != 0 {
        if CBS_get_u16_length_prefixed(cbs, &mut child) == 0 {
            return 0 as libc::c_int;
        }
    } else {
        let mut plen: size_t = ec_point_byte_len(group, POINT_CONVERSION_UNCOMPRESSED);
        if CBS_get_bytes(cbs, &mut child, plen) == 0 {
            return 0 as libc::c_int;
        }
    }
    if ec_point_from_uncompressed(group, out, CBS_data(&mut child), CBS_len(&mut child))
        == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn mul_public_3(
    mut group: *const EC_GROUP,
    mut out: *mut EC_JACOBIAN,
    mut p0: *const EC_JACOBIAN,
    mut scalar0: *const EC_SCALAR,
    mut p1: *const EC_JACOBIAN,
    mut scalar1: *const EC_SCALAR,
    mut p2: *const EC_JACOBIAN,
    mut scalar2: *const EC_SCALAR,
) -> libc::c_int {
    let mut points: [EC_JACOBIAN; 3] = [*p0, *p1, *p2];
    let mut scalars: [EC_SCALAR; 3] = [*scalar0, *scalar1, *scalar2];
    return ec_point_mul_scalar_public_batch(
        group,
        out,
        0 as *const EC_SCALAR,
        points.as_mut_ptr(),
        scalars.as_mut_ptr(),
        3 as libc::c_int as size_t,
    );
}
unsafe extern "C" fn pmbtoken_compute_keys(
    mut method: *const PMBTOKEN_METHOD,
    mut out_private: *mut CBB,
    mut out_public: *mut CBB,
    mut x0: *const EC_SCALAR,
    mut y0: *const EC_SCALAR,
    mut x1: *const EC_SCALAR,
    mut y1: *const EC_SCALAR,
    mut xs: *const EC_SCALAR,
    mut ys: *const EC_SCALAR,
) -> libc::c_int {
    let mut group: *const EC_GROUP = (*method).group;
    let mut pub_0: [EC_JACOBIAN; 3] = [EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    }; 3];
    if ec_point_mul_scalar_precomp(
        group,
        &mut *pub_0.as_mut_ptr().offset(0 as libc::c_int as isize),
        &(*method).g_precomp,
        x0,
        &(*method).h_precomp,
        y0,
        0 as *const EC_PRECOMP,
        0 as *const EC_SCALAR,
    ) == 0
        || ec_point_mul_scalar_precomp(
            group,
            &mut *pub_0.as_mut_ptr().offset(1 as libc::c_int as isize),
            &(*method).g_precomp,
            x1,
            &(*method).h_precomp,
            y1,
            0 as *const EC_PRECOMP,
            0 as *const EC_SCALAR,
        ) == 0
        || ec_point_mul_scalar_precomp(
            (*method).group,
            &mut *pub_0.as_mut_ptr().offset(2 as libc::c_int as isize),
            &(*method).g_precomp,
            xs,
            &(*method).h_precomp,
            ys,
            0 as *const EC_PRECOMP,
            0 as *const EC_SCALAR,
        ) == 0
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                as *const u8 as *const libc::c_char,
            195 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut scalars: [*const EC_SCALAR; 6] = [x0, y0, x1, y1, xs, ys];
    let mut scalar_len: size_t = BN_num_bytes(EC_GROUP_get0_order(group)) as size_t;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (::core::mem::size_of::<[*const EC_SCALAR; 6]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<*const EC_SCALAR>() as libc::c_ulong)
    {
        let mut buf: *mut uint8_t = 0 as *mut uint8_t;
        if CBB_add_space(out_private, &mut buf, scalar_len) == 0 {
            ERR_put_error(
                32 as libc::c_int,
                0 as libc::c_int,
                101 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                    as *const u8 as *const libc::c_char,
                204 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        ec_scalar_to_bytes(group, buf, &mut scalar_len, scalars[i as usize]);
        i = i.wrapping_add(1);
        i;
    }
    let mut pub_affine: [EC_AFFINE; 3] = [EC_AFFINE {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
    }; 3];
    if ec_jacobian_to_affine_batch(
        group,
        pub_affine.as_mut_ptr(),
        pub_0.as_mut_ptr(),
        3 as libc::c_int as size_t,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    if cbb_add_prefixed_point(
        out_public,
        group,
        &mut *pub_affine.as_mut_ptr().offset(0 as libc::c_int as isize),
        (*method).prefix_point(),
    ) == 0
        || cbb_add_prefixed_point(
            out_public,
            group,
            &mut *pub_affine.as_mut_ptr().offset(1 as libc::c_int as isize),
            (*method).prefix_point(),
        ) == 0
        || cbb_add_prefixed_point(
            out_public,
            group,
            &mut *pub_affine.as_mut_ptr().offset(2 as libc::c_int as isize),
            (*method).prefix_point(),
        ) == 0
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                as *const u8 as *const libc::c_char,
            221 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn pmbtoken_generate_key(
    mut method: *const PMBTOKEN_METHOD,
    mut out_private: *mut CBB,
    mut out_public: *mut CBB,
) -> libc::c_int {
    let mut x0: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut y0: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut x1: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut y1: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut xs: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut ys: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    if ec_random_nonzero_scalar(
        (*method).group,
        &mut x0,
        kDefaultAdditionalData.as_ptr(),
    ) == 0
        || ec_random_nonzero_scalar(
            (*method).group,
            &mut y0,
            kDefaultAdditionalData.as_ptr(),
        ) == 0
        || ec_random_nonzero_scalar(
            (*method).group,
            &mut x1,
            kDefaultAdditionalData.as_ptr(),
        ) == 0
        || ec_random_nonzero_scalar(
            (*method).group,
            &mut y1,
            kDefaultAdditionalData.as_ptr(),
        ) == 0
        || ec_random_nonzero_scalar(
            (*method).group,
            &mut xs,
            kDefaultAdditionalData.as_ptr(),
        ) == 0
        || ec_random_nonzero_scalar(
            (*method).group,
            &mut ys,
            kDefaultAdditionalData.as_ptr(),
        ) == 0
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                as *const u8 as *const libc::c_char,
            237 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return pmbtoken_compute_keys(
        method,
        out_private,
        out_public,
        &mut x0,
        &mut y0,
        &mut x1,
        &mut y1,
        &mut xs,
        &mut ys,
    );
}
unsafe extern "C" fn pmbtoken_derive_key_from_secret(
    mut method: *const PMBTOKEN_METHOD,
    mut out_private: *mut CBB,
    mut out_public: *mut CBB,
    mut secret: *const uint8_t,
    mut secret_len: size_t,
) -> libc::c_int {
    let mut x0: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut y0: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut x1: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut y1: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut xs: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut ys: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    if derive_scalar_from_secret(
        method,
        &mut x0,
        secret,
        secret_len,
        0 as libc::c_int as uint8_t,
    ) == 0
        || derive_scalar_from_secret(
            method,
            &mut y0,
            secret,
            secret_len,
            1 as libc::c_int as uint8_t,
        ) == 0
        || derive_scalar_from_secret(
            method,
            &mut x1,
            secret,
            secret_len,
            2 as libc::c_int as uint8_t,
        ) == 0
        || derive_scalar_from_secret(
            method,
            &mut y1,
            secret,
            secret_len,
            3 as libc::c_int as uint8_t,
        ) == 0
        || derive_scalar_from_secret(
            method,
            &mut xs,
            secret,
            secret_len,
            4 as libc::c_int as uint8_t,
        ) == 0
        || derive_scalar_from_secret(
            method,
            &mut ys,
            secret,
            secret_len,
            5 as libc::c_int as uint8_t,
        ) == 0
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                as *const u8 as *const libc::c_char,
            256 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return pmbtoken_compute_keys(
        method,
        out_private,
        out_public,
        &mut x0,
        &mut y0,
        &mut x1,
        &mut y1,
        &mut xs,
        &mut ys,
    );
}
unsafe extern "C" fn pmbtoken_client_key_from_bytes(
    mut method: *const PMBTOKEN_METHOD,
    mut key: *mut TRUST_TOKEN_CLIENT_KEY,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, in_0, len);
    if cbs_get_prefixed_point(
        &mut cbs,
        (*method).group,
        &mut (*key).pub0,
        (*method).prefix_point(),
    ) == 0
        || cbs_get_prefixed_point(
            &mut cbs,
            (*method).group,
            &mut (*key).pub1,
            (*method).prefix_point(),
        ) == 0
        || cbs_get_prefixed_point(
            &mut cbs,
            (*method).group,
            &mut (*key).pubs,
            (*method).prefix_point(),
        ) == 0 || CBS_len(&mut cbs) != 0 as libc::c_int as size_t
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                as *const u8 as *const libc::c_char,
            276 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn pmbtoken_issuer_key_from_bytes(
    mut method: *const PMBTOKEN_METHOD,
    mut key: *mut TRUST_TOKEN_ISSUER_KEY,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let mut group: *const EC_GROUP = (*method).group;
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut tmp: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, in_0, len);
    let mut scalar_len: size_t = BN_num_bytes(EC_GROUP_get0_order(group)) as size_t;
    let mut scalars: [*mut EC_SCALAR; 6] = [
        &mut (*key).x0,
        &mut (*key).y0,
        &mut (*key).x1,
        &mut (*key).y1,
        &mut (*key).xs,
        &mut (*key).ys,
    ];
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (::core::mem::size_of::<[*mut EC_SCALAR; 6]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<*mut EC_SCALAR>() as libc::c_ulong)
    {
        if CBS_get_bytes(&mut cbs, &mut tmp, scalar_len) == 0
            || ec_scalar_from_bytes(
                group,
                scalars[i as usize],
                CBS_data(&mut tmp),
                CBS_len(&mut tmp),
            ) == 0
        {
            ERR_put_error(
                32 as libc::c_int,
                0 as libc::c_int,
                105 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                    as *const u8 as *const libc::c_char,
                296 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    let mut pub_0: [EC_JACOBIAN; 3] = [EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    }; 3];
    let mut pub_affine: [EC_AFFINE; 3] = [EC_AFFINE {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
    }; 3];
    if ec_point_mul_scalar_precomp(
        group,
        &mut *pub_0.as_mut_ptr().offset(0 as libc::c_int as isize),
        &(*method).g_precomp,
        &mut (*key).x0,
        &(*method).h_precomp,
        &mut (*key).y0,
        0 as *const EC_PRECOMP,
        0 as *const EC_SCALAR,
    ) == 0
        || ec_init_precomp(
            group,
            &mut (*key).pub0_precomp,
            &mut *pub_0.as_mut_ptr().offset(0 as libc::c_int as isize),
        ) == 0
        || ec_point_mul_scalar_precomp(
            group,
            &mut *pub_0.as_mut_ptr().offset(1 as libc::c_int as isize),
            &(*method).g_precomp,
            &mut (*key).x1,
            &(*method).h_precomp,
            &mut (*key).y1,
            0 as *const EC_PRECOMP,
            0 as *const EC_SCALAR,
        ) == 0
        || ec_init_precomp(
            group,
            &mut (*key).pub1_precomp,
            &mut *pub_0.as_mut_ptr().offset(1 as libc::c_int as isize),
        ) == 0
        || ec_point_mul_scalar_precomp(
            group,
            &mut *pub_0.as_mut_ptr().offset(2 as libc::c_int as isize),
            &(*method).g_precomp,
            &mut (*key).xs,
            &(*method).h_precomp,
            &mut (*key).ys,
            0 as *const EC_PRECOMP,
            0 as *const EC_SCALAR,
        ) == 0
        || ec_init_precomp(
            group,
            &mut (*key).pubs_precomp,
            &mut *pub_0.as_mut_ptr().offset(2 as libc::c_int as isize),
        ) == 0
        || ec_jacobian_to_affine_batch(
            group,
            pub_affine.as_mut_ptr(),
            pub_0.as_mut_ptr(),
            3 as libc::c_int as size_t,
        ) == 0
    {
        return 0 as libc::c_int;
    }
    (*key).pub0 = pub_affine[0 as libc::c_int as usize];
    (*key).pub1 = pub_affine[1 as libc::c_int as usize];
    (*key).pubs = pub_affine[2 as libc::c_int as usize];
    return 1 as libc::c_int;
}
unsafe extern "C" fn pmbtoken_blind(
    mut method: *const PMBTOKEN_METHOD,
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
    let mut group: *const EC_GROUP = (*method).group;
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
                current_block = 2418391799900934657;
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
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                                as *const u8 as *const libc::c_char,
                            345 as libc::c_int as libc::c_uint,
                            (*::core::mem::transmute::<
                                &[u8; 123],
                                &[libc::c_char; 123],
                            >(
                                b"struct stack_st_TRUST_TOKEN_PRETOKEN *pmbtoken_blind(const PMBTOKEN_METHOD *, CBB *, size_t, int, const uint8_t *, size_t)\0",
                            ))
                                .as_ptr(),
                        );
                    }
                    'c_12898: {
                        if 64 as libc::c_int == 64 as libc::c_int {} else {
                            __assert_fail(
                                b"SHA512_DIGEST_LENGTH == TRUST_TOKEN_NONCE_SIZE\0"
                                    as *const u8 as *const libc::c_char,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                                    as *const u8 as *const libc::c_char,
                                345 as libc::c_int as libc::c_uint,
                                (*::core::mem::transmute::<
                                    &[u8; 123],
                                    &[libc::c_char; 123],
                                >(
                                    b"struct stack_st_TRUST_TOKEN_PRETOKEN *pmbtoken_blind(const PMBTOKEN_METHOD *, CBB *, size_t, int, const uint8_t *, size_t)\0",
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
                if ec_random_nonzero_scalar(
                    group,
                    &mut (*pretoken).r,
                    kDefaultAdditionalData.as_ptr(),
                ) == 0
                {
                    current_block = 2418391799900934657;
                    break;
                }
                let mut rinv: EC_SCALAR = EC_SCALAR { words: [0; 9] };
                ec_scalar_inv0_montgomery(group, &mut rinv, &mut (*pretoken).r);
                ec_scalar_from_montgomery(group, &mut (*pretoken).r, &mut (*pretoken).r);
                ec_scalar_from_montgomery(group, &mut rinv, &mut rinv);
                let mut T: EC_JACOBIAN = EC_JACOBIAN {
                    X: EC_FELEM { words: [0; 9] },
                    Y: EC_FELEM { words: [0; 9] },
                    Z: EC_FELEM { words: [0; 9] },
                };
                let mut Tp: EC_JACOBIAN = EC_JACOBIAN {
                    X: EC_FELEM { words: [0; 9] },
                    Y: EC_FELEM { words: [0; 9] },
                    Z: EC_FELEM { words: [0; 9] },
                };
                if ((*method).hash_t)
                    .expect(
                        "non-null function pointer",
                    )(group, &mut T, ((*pretoken).t).as_mut_ptr() as *const uint8_t) == 0
                    || ec_point_mul_scalar(group, &mut Tp, &mut T, &mut rinv) == 0
                    || ec_jacobian_to_affine(group, &mut (*pretoken).Tp, &mut Tp) == 0
                {
                    current_block = 2418391799900934657;
                    break;
                }
                if cbb_add_prefixed_point(
                    cbb,
                    group,
                    &mut (*pretoken).Tp,
                    (*method).prefix_point(),
                ) == 0
                {
                    current_block = 2418391799900934657;
                    break;
                }
                i = i.wrapping_add(1);
                i;
            }
        }
        match current_block {
            2418391799900934657 => {}
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
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                as *const u8 as *const libc::c_char,
            401 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    ec_scalar_from_bytes(group, out, CBS_data(&mut tmp), CBS_len(&mut tmp));
    return 1 as libc::c_int;
}
unsafe extern "C" fn hash_c_dleq(
    mut method: *const PMBTOKEN_METHOD,
    mut out: *mut EC_SCALAR,
    mut X: *const EC_AFFINE,
    mut T: *const EC_AFFINE,
    mut S: *const EC_AFFINE,
    mut W: *const EC_AFFINE,
    mut K0: *const EC_AFFINE,
    mut K1: *const EC_AFFINE,
) -> libc::c_int {
    static mut kDLEQ2Label: [uint8_t; 6] = unsafe {
        *::core::mem::transmute::<&[u8; 6], &[uint8_t; 6]>(b"DLEQ2\0")
    };
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
            kDLEQ2Label.as_ptr(),
            ::core::mem::size_of::<[uint8_t; 6]>() as libc::c_ulong,
        ) == 0 || point_to_cbb(&mut cbb, (*method).group, X) == 0
        || point_to_cbb(&mut cbb, (*method).group, T) == 0
        || point_to_cbb(&mut cbb, (*method).group, S) == 0
        || point_to_cbb(&mut cbb, (*method).group, W) == 0
        || point_to_cbb(&mut cbb, (*method).group, K0) == 0
        || point_to_cbb(&mut cbb, (*method).group, K1) == 0
        || CBB_finish(&mut cbb, &mut buf, &mut len) == 0
        || ((*method).hash_c)
            .expect("non-null function pointer")((*method).group, out, buf, len) == 0)
    {
        ok = 1 as libc::c_int;
    }
    CBB_cleanup(&mut cbb);
    OPENSSL_free(buf as *mut libc::c_void);
    return ok;
}
unsafe extern "C" fn hash_c_dleqor(
    mut method: *const PMBTOKEN_METHOD,
    mut out: *mut EC_SCALAR,
    mut X0: *const EC_AFFINE,
    mut X1: *const EC_AFFINE,
    mut T: *const EC_AFFINE,
    mut S: *const EC_AFFINE,
    mut W: *const EC_AFFINE,
    mut K00: *const EC_AFFINE,
    mut K01: *const EC_AFFINE,
    mut K10: *const EC_AFFINE,
    mut K11: *const EC_AFFINE,
) -> libc::c_int {
    static mut kDLEQOR2Label: [uint8_t; 8] = unsafe {
        *::core::mem::transmute::<&[u8; 8], &[uint8_t; 8]>(b"DLEQOR2\0")
    };
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
            kDLEQOR2Label.as_ptr(),
            ::core::mem::size_of::<[uint8_t; 8]>() as libc::c_ulong,
        ) == 0 || point_to_cbb(&mut cbb, (*method).group, X0) == 0
        || point_to_cbb(&mut cbb, (*method).group, X1) == 0
        || point_to_cbb(&mut cbb, (*method).group, T) == 0
        || point_to_cbb(&mut cbb, (*method).group, S) == 0
        || point_to_cbb(&mut cbb, (*method).group, W) == 0
        || point_to_cbb(&mut cbb, (*method).group, K00) == 0
        || point_to_cbb(&mut cbb, (*method).group, K01) == 0
        || point_to_cbb(&mut cbb, (*method).group, K10) == 0
        || point_to_cbb(&mut cbb, (*method).group, K11) == 0
        || CBB_finish(&mut cbb, &mut buf, &mut len) == 0
        || ((*method).hash_c)
            .expect("non-null function pointer")((*method).group, out, buf, len) == 0)
    {
        ok = 1 as libc::c_int;
    }
    CBB_cleanup(&mut cbb);
    OPENSSL_free(buf as *mut libc::c_void);
    return ok;
}
unsafe extern "C" fn hash_c_batch(
    mut method: *const PMBTOKEN_METHOD,
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
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                as *const u8 as *const libc::c_char,
            483 as libc::c_int as libc::c_uint,
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
        || ((*method).hash_c)
            .expect("non-null function pointer")((*method).group, out, buf, len) == 0)
    {
        ok = 1 as libc::c_int;
    }
    CBB_cleanup(&mut cbb);
    OPENSSL_free(buf as *mut libc::c_void);
    return ok;
}
unsafe extern "C" fn dleq_generate(
    mut method: *const PMBTOKEN_METHOD,
    mut cbb: *mut CBB,
    mut priv_0: *const TRUST_TOKEN_ISSUER_KEY,
    mut T: *const EC_JACOBIAN,
    mut S: *const EC_JACOBIAN,
    mut W: *const EC_JACOBIAN,
    mut Ws: *const EC_JACOBIAN,
    mut private_metadata: uint8_t,
) -> libc::c_int {
    let mut group: *const EC_GROUP = (*method).group;
    let mut jacobians: [EC_JACOBIAN; 10] = [EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    }; 10];
    let mut ks0: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut ks1: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    if ec_random_nonzero_scalar(group, &mut ks0, kDefaultAdditionalData.as_ptr()) == 0
        || ec_random_nonzero_scalar(group, &mut ks1, kDefaultAdditionalData.as_ptr())
            == 0
        || ec_point_mul_scalar_precomp(
            group,
            &mut *jacobians.as_mut_ptr().offset(idx_Ks0 as libc::c_int as isize),
            &(*method).g_precomp,
            &mut ks0,
            &(*method).h_precomp,
            &mut ks1,
            0 as *const EC_PRECOMP,
            0 as *const EC_SCALAR,
        ) == 0
        || ec_point_mul_scalar_batch(
            group,
            &mut *jacobians.as_mut_ptr().offset(idx_Ks1 as libc::c_int as isize),
            T,
            &mut ks0,
            S,
            &mut ks1,
            0 as *const EC_JACOBIAN,
            0 as *const EC_SCALAR,
        ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut mask: BN_ULONG = (0 as libc::c_int as BN_ULONG)
        .wrapping_sub((private_metadata as libc::c_int & 1 as libc::c_int) as BN_ULONG);
    let mut pubo_precomp: EC_PRECOMP = EC_PRECOMP {
        comb: [EC_AFFINE {
            X: EC_FELEM { words: [0; 9] },
            Y: EC_FELEM { words: [0; 9] },
        }; 31],
    };
    let mut xb: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut yb: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    ec_scalar_select(group, &mut xb, mask, &(*priv_0).x1, &(*priv_0).x0);
    ec_scalar_select(group, &mut yb, mask, &(*priv_0).y1, &(*priv_0).y0);
    ec_precomp_select(
        group,
        &mut pubo_precomp,
        mask,
        &(*priv_0).pub0_precomp,
        &(*priv_0).pub1_precomp,
    );
    let mut k0: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut k1: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut minus_co: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut uo: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut vo: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    if ec_random_nonzero_scalar(group, &mut k0, kDefaultAdditionalData.as_ptr()) == 0
        || ec_random_nonzero_scalar(group, &mut k1, kDefaultAdditionalData.as_ptr()) == 0
        || ec_point_mul_scalar_precomp(
            group,
            &mut *jacobians.as_mut_ptr().offset(idx_Kb0 as libc::c_int as isize),
            &(*method).g_precomp,
            &mut k0,
            &(*method).h_precomp,
            &mut k1,
            0 as *const EC_PRECOMP,
            0 as *const EC_SCALAR,
        ) == 0
        || ec_point_mul_scalar_batch(
            group,
            &mut *jacobians.as_mut_ptr().offset(idx_Kb1 as libc::c_int as isize),
            T,
            &mut k0,
            S,
            &mut k1,
            0 as *const EC_JACOBIAN,
            0 as *const EC_SCALAR,
        ) == 0
        || ec_random_nonzero_scalar(
            group,
            &mut minus_co,
            kDefaultAdditionalData.as_ptr(),
        ) == 0
        || ec_random_nonzero_scalar(group, &mut uo, kDefaultAdditionalData.as_ptr()) == 0
        || ec_random_nonzero_scalar(group, &mut vo, kDefaultAdditionalData.as_ptr()) == 0
        || ec_point_mul_scalar_precomp(
            group,
            &mut *jacobians.as_mut_ptr().offset(idx_Ko0 as libc::c_int as isize),
            &(*method).g_precomp,
            &mut uo,
            &(*method).h_precomp,
            &mut vo,
            &mut pubo_precomp,
            &mut minus_co,
        ) == 0
        || ec_point_mul_scalar_batch(
            group,
            &mut *jacobians.as_mut_ptr().offset(idx_Ko1 as libc::c_int as isize),
            T,
            &mut uo,
            S,
            &mut vo,
            W,
            &mut minus_co,
        ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut affines: [EC_AFFINE; 10] = [EC_AFFINE {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
    }; 10];
    jacobians[idx_T as libc::c_int as usize] = *T;
    jacobians[idx_S as libc::c_int as usize] = *S;
    jacobians[idx_W as libc::c_int as usize] = *W;
    jacobians[idx_Ws as libc::c_int as usize] = *Ws;
    if ec_jacobian_to_affine_batch(
        group,
        affines.as_mut_ptr(),
        jacobians.as_mut_ptr(),
        num_idx as libc::c_int as size_t,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut K00: EC_AFFINE = EC_AFFINE {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
    };
    let mut K01: EC_AFFINE = EC_AFFINE {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
    };
    let mut K10: EC_AFFINE = EC_AFFINE {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
    };
    let mut K11: EC_AFFINE = EC_AFFINE {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
    };
    ec_affine_select(
        group,
        &mut K00,
        mask,
        &mut *affines.as_mut_ptr().offset(idx_Ko0 as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_Kb0 as libc::c_int as isize),
    );
    ec_affine_select(
        group,
        &mut K01,
        mask,
        &mut *affines.as_mut_ptr().offset(idx_Ko1 as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_Kb1 as libc::c_int as isize),
    );
    ec_affine_select(
        group,
        &mut K10,
        mask,
        &mut *affines.as_mut_ptr().offset(idx_Kb0 as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_Ko0 as libc::c_int as isize),
    );
    ec_affine_select(
        group,
        &mut K11,
        mask,
        &mut *affines.as_mut_ptr().offset(idx_Kb1 as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_Ko1 as libc::c_int as isize),
    );
    let mut cs: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut c: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    if hash_c_dleq(
        method,
        &mut cs,
        &(*priv_0).pubs,
        &mut *affines.as_mut_ptr().offset(idx_T as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_S as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_Ws as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_Ks0 as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_Ks1 as libc::c_int as isize),
    ) == 0
        || hash_c_dleqor(
            method,
            &mut c,
            &(*priv_0).pub0,
            &(*priv_0).pub1,
            &mut *affines.as_mut_ptr().offset(idx_T as libc::c_int as isize),
            &mut *affines.as_mut_ptr().offset(idx_S as libc::c_int as isize),
            &mut *affines.as_mut_ptr().offset(idx_W as libc::c_int as isize),
            &mut K00,
            &mut K01,
            &mut K10,
            &mut K11,
        ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut cs_mont: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    ec_scalar_to_montgomery(group, &mut cs_mont, &mut cs);
    let mut us: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut vs: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    ec_scalar_mul_montgomery(group, &mut us, &(*priv_0).xs, &mut cs_mont);
    ec_scalar_add(group, &mut us, &mut ks0, &mut us);
    ec_scalar_mul_montgomery(group, &mut vs, &(*priv_0).ys, &mut cs_mont);
    ec_scalar_add(group, &mut vs, &mut ks1, &mut vs);
    if scalar_to_cbb(cbb, group, &mut cs) == 0 || scalar_to_cbb(cbb, group, &mut us) == 0
        || scalar_to_cbb(cbb, group, &mut vs) == 0
    {
        return 0 as libc::c_int;
    }
    let mut cb: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut ub: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut vb: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    ec_scalar_add(group, &mut cb, &mut c, &mut minus_co);
    let mut cb_mont: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    ec_scalar_to_montgomery(group, &mut cb_mont, &mut cb);
    ec_scalar_mul_montgomery(group, &mut ub, &mut xb, &mut cb_mont);
    ec_scalar_add(group, &mut ub, &mut k0, &mut ub);
    ec_scalar_mul_montgomery(group, &mut vb, &mut yb, &mut cb_mont);
    ec_scalar_add(group, &mut vb, &mut k1, &mut vb);
    let mut co: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut c0: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut c1: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut u0: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut u1: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut v0: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut v1: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    ec_scalar_neg(group, &mut co, &mut minus_co);
    ec_scalar_select(group, &mut c0, mask, &mut co, &mut cb);
    ec_scalar_select(group, &mut u0, mask, &mut uo, &mut ub);
    ec_scalar_select(group, &mut v0, mask, &mut vo, &mut vb);
    ec_scalar_select(group, &mut c1, mask, &mut cb, &mut co);
    ec_scalar_select(group, &mut u1, mask, &mut ub, &mut uo);
    ec_scalar_select(group, &mut v1, mask, &mut vb, &mut vo);
    if scalar_to_cbb(cbb, group, &mut c0) == 0 || scalar_to_cbb(cbb, group, &mut c1) == 0
        || scalar_to_cbb(cbb, group, &mut u0) == 0
        || scalar_to_cbb(cbb, group, &mut u1) == 0
        || scalar_to_cbb(cbb, group, &mut v0) == 0
        || scalar_to_cbb(cbb, group, &mut v1) == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn dleq_verify(
    mut method: *const PMBTOKEN_METHOD,
    mut cbs: *mut CBS,
    mut pub_0: *const TRUST_TOKEN_CLIENT_KEY,
    mut T: *const EC_JACOBIAN,
    mut S: *const EC_JACOBIAN,
    mut W: *const EC_JACOBIAN,
    mut Ws: *const EC_JACOBIAN,
) -> libc::c_int {
    let mut group: *const EC_GROUP = (*method).group;
    let mut g: *const EC_JACOBIAN = &(*group).generator.raw;
    let mut jacobians: [EC_JACOBIAN; 10] = [EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    }; 10];
    let mut cs: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut us: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut vs: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    if scalar_from_cbs(cbs, group, &mut cs) == 0
        || scalar_from_cbs(cbs, group, &mut us) == 0
        || scalar_from_cbs(cbs, group, &mut vs) == 0
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                as *const u8 as *const libc::c_char,
            705 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut pubs: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    ec_affine_to_jacobian(group, &mut pubs, &(*pub_0).pubs);
    let mut minus_cs: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    ec_scalar_neg(group, &mut minus_cs, &mut cs);
    if mul_public_3(
        group,
        &mut *jacobians.as_mut_ptr().offset(idx_Ks0_0 as libc::c_int as isize),
        g,
        &mut us,
        &(*method).h,
        &mut vs,
        &mut pubs,
        &mut minus_cs,
    ) == 0
        || mul_public_3(
            group,
            &mut *jacobians.as_mut_ptr().offset(idx_Ks1_0 as libc::c_int as isize),
            T,
            &mut us,
            S,
            &mut vs,
            Ws,
            &mut minus_cs,
        ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut c0: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut c1: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut u0: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut u1: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut v0: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut v1: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    if scalar_from_cbs(cbs, group, &mut c0) == 0
        || scalar_from_cbs(cbs, group, &mut c1) == 0
        || scalar_from_cbs(cbs, group, &mut u0) == 0
        || scalar_from_cbs(cbs, group, &mut u1) == 0
        || scalar_from_cbs(cbs, group, &mut v0) == 0
        || scalar_from_cbs(cbs, group, &mut v1) == 0
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                as *const u8 as *const libc::c_char,
            729 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut pub0: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    let mut pub1: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    ec_affine_to_jacobian(group, &mut pub0, &(*pub_0).pub0);
    ec_affine_to_jacobian(group, &mut pub1, &(*pub_0).pub1);
    let mut minus_c0: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    let mut minus_c1: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    ec_scalar_neg(group, &mut minus_c0, &mut c0);
    ec_scalar_neg(group, &mut minus_c1, &mut c1);
    if mul_public_3(
        group,
        &mut *jacobians.as_mut_ptr().offset(idx_K00 as libc::c_int as isize),
        g,
        &mut u0,
        &(*method).h,
        &mut v0,
        &mut pub0,
        &mut minus_c0,
    ) == 0
        || mul_public_3(
            group,
            &mut *jacobians.as_mut_ptr().offset(idx_K01 as libc::c_int as isize),
            T,
            &mut u0,
            S,
            &mut v0,
            W,
            &mut minus_c0,
        ) == 0
        || mul_public_3(
            group,
            &mut *jacobians.as_mut_ptr().offset(idx_K10 as libc::c_int as isize),
            g,
            &mut u1,
            &(*method).h,
            &mut v1,
            &mut pub1,
            &mut minus_c1,
        ) == 0
        || mul_public_3(
            group,
            &mut *jacobians.as_mut_ptr().offset(idx_K11 as libc::c_int as isize),
            T,
            &mut u1,
            S,
            &mut v1,
            W,
            &mut minus_c1,
        ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut affines: [EC_AFFINE; 10] = [EC_AFFINE {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
    }; 10];
    jacobians[idx_T_0 as libc::c_int as usize] = *T;
    jacobians[idx_S_0 as libc::c_int as usize] = *S;
    jacobians[idx_W_0 as libc::c_int as usize] = *W;
    jacobians[idx_Ws_0 as libc::c_int as usize] = *Ws;
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
    if hash_c_dleq(
        method,
        &mut calculated,
        &(*pub_0).pubs,
        &mut *affines.as_mut_ptr().offset(idx_T_0 as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_S_0 as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_Ws_0 as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_Ks0_0 as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_Ks1_0 as libc::c_int as isize),
    ) == 0
    {
        return 0 as libc::c_int;
    }
    if ec_scalar_equal_vartime(group, &mut cs, &mut calculated) == 0 {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            114 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                as *const u8 as *const libc::c_char,
            769 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if hash_c_dleqor(
        method,
        &mut calculated,
        &(*pub_0).pub0,
        &(*pub_0).pub1,
        &mut *affines.as_mut_ptr().offset(idx_T_0 as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_S_0 as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_W_0 as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_K00 as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_K01 as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_K10 as libc::c_int as isize),
        &mut *affines.as_mut_ptr().offset(idx_K11 as libc::c_int as isize),
    ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut c: EC_SCALAR = EC_SCALAR { words: [0; 9] };
    ec_scalar_add(group, &mut c, &mut c0, &mut c1);
    if ec_scalar_equal_vartime(group, &mut c, &mut calculated) == 0 {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            114 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                as *const u8 as *const libc::c_char,
            785 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn pmbtoken_sign(
    mut method: *const PMBTOKEN_METHOD,
    mut key: *const TRUST_TOKEN_ISSUER_KEY,
    mut cbb: *mut CBB,
    mut cbs: *mut CBS,
    mut num_requested: size_t,
    mut num_to_issue: size_t,
    mut private_metadata: uint8_t,
) -> libc::c_int {
    let mut Tp_batch: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    let mut Sp_batch: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    let mut Wp_batch: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    let mut Wsp_batch: EC_JACOBIAN = EC_JACOBIAN {
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
    let mut token_len: size_t = 0;
    let mut current_block: u64;
    let mut group: *const EC_GROUP = (*method).group;
    if num_requested < num_to_issue {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            4 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                as *const u8 as *const libc::c_char,
            798 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut Tps: *mut EC_JACOBIAN = OPENSSL_calloc(
        num_to_issue,
        ::core::mem::size_of::<EC_JACOBIAN>() as libc::c_ulong,
    ) as *mut EC_JACOBIAN;
    let mut Sps: *mut EC_JACOBIAN = OPENSSL_calloc(
        num_to_issue,
        ::core::mem::size_of::<EC_JACOBIAN>() as libc::c_ulong,
    ) as *mut EC_JACOBIAN;
    let mut Wps: *mut EC_JACOBIAN = OPENSSL_calloc(
        num_to_issue,
        ::core::mem::size_of::<EC_JACOBIAN>() as libc::c_ulong,
    ) as *mut EC_JACOBIAN;
    let mut Wsps: *mut EC_JACOBIAN = OPENSSL_calloc(
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
    if !(Tps.is_null() || Sps.is_null() || Wps.is_null() || Wsps.is_null()
        || es.is_null() || CBB_init(&mut batch_cbb, 0 as libc::c_int as size_t) == 0
        || point_to_cbb(&mut batch_cbb, (*method).group, &(*key).pubs) == 0
        || point_to_cbb(&mut batch_cbb, (*method).group, &(*key).pub0) == 0
        || point_to_cbb(&mut batch_cbb, (*method).group, &(*key).pub1) == 0)
    {
        let mut i: size_t = 0 as libc::c_int as size_t;
        loop {
            if !(i < num_to_issue) {
                current_block = 11194104282611034094;
                break;
            }
            let mut Tp_affine: EC_AFFINE = EC_AFFINE {
                X: EC_FELEM { words: [0; 9] },
                Y: EC_FELEM { words: [0; 9] },
            };
            let mut Tp: EC_JACOBIAN = EC_JACOBIAN {
                X: EC_FELEM { words: [0; 9] },
                Y: EC_FELEM { words: [0; 9] },
                Z: EC_FELEM { words: [0; 9] },
            };
            if cbs_get_prefixed_point(
                cbs,
                group,
                &mut Tp_affine,
                (*method).prefix_point(),
            ) == 0
            {
                ERR_put_error(
                    32 as libc::c_int,
                    0 as libc::c_int,
                    105 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                        as *const u8 as *const libc::c_char,
                    826 as libc::c_int as libc::c_uint,
                );
                current_block = 16348666687933192571;
                break;
            } else {
                ec_affine_to_jacobian(group, &mut Tp, &mut Tp_affine);
                let mut xb: EC_SCALAR = EC_SCALAR { words: [0; 9] };
                let mut yb: EC_SCALAR = EC_SCALAR { words: [0; 9] };
                let mut mask: BN_ULONG = (0 as libc::c_int as BN_ULONG)
                    .wrapping_sub(
                        (private_metadata as libc::c_int & 1 as libc::c_int) as BN_ULONG,
                    );
                ec_scalar_select(group, &mut xb, mask, &(*key).x1, &(*key).x0);
                ec_scalar_select(group, &mut yb, mask, &(*key).y1, &(*key).y0);
                let mut s: [uint8_t; 64] = [0; 64];
                RAND_bytes(s.as_mut_ptr(), 64 as libc::c_int as size_t);
                let mut jacobians: [EC_JACOBIAN; 3] = [EC_JACOBIAN {
                    X: EC_FELEM { words: [0; 9] },
                    Y: EC_FELEM { words: [0; 9] },
                    Z: EC_FELEM { words: [0; 9] },
                }; 3];
                let mut affines: [EC_AFFINE; 3] = [EC_AFFINE {
                    X: EC_FELEM { words: [0; 9] },
                    Y: EC_FELEM { words: [0; 9] },
                }; 3];
                if ((*method).hash_s)
                    .expect(
                        "non-null function pointer",
                    )(
                    group,
                    &mut *jacobians.as_mut_ptr().offset(0 as libc::c_int as isize),
                    &mut Tp_affine,
                    s.as_mut_ptr() as *const uint8_t,
                ) == 0
                    || ec_point_mul_scalar_batch(
                        group,
                        &mut *jacobians.as_mut_ptr().offset(1 as libc::c_int as isize),
                        &mut Tp,
                        &mut xb,
                        &mut *jacobians.as_mut_ptr().offset(0 as libc::c_int as isize),
                        &mut yb,
                        0 as *const EC_JACOBIAN,
                        0 as *const EC_SCALAR,
                    ) == 0
                    || ec_point_mul_scalar_batch(
                        group,
                        &mut *jacobians.as_mut_ptr().offset(2 as libc::c_int as isize),
                        &mut Tp,
                        &(*key).xs,
                        &mut *jacobians.as_mut_ptr().offset(0 as libc::c_int as isize),
                        &(*key).ys,
                        0 as *const EC_JACOBIAN,
                        0 as *const EC_SCALAR,
                    ) == 0
                    || ec_jacobian_to_affine_batch(
                        group,
                        affines.as_mut_ptr(),
                        jacobians.as_mut_ptr(),
                        3 as libc::c_int as size_t,
                    ) == 0
                    || CBB_add_bytes(cbb, s.as_mut_ptr(), 64 as libc::c_int as size_t)
                        == 0
                    || cbb_add_prefixed_point(
                        cbb,
                        group,
                        &mut *affines.as_mut_ptr().offset(1 as libc::c_int as isize),
                        (*method).prefix_point(),
                    ) == 0
                    || cbb_add_prefixed_point(
                        cbb,
                        group,
                        &mut *affines.as_mut_ptr().offset(2 as libc::c_int as isize),
                        (*method).prefix_point(),
                    ) == 0
                {
                    current_block = 16348666687933192571;
                    break;
                }
                if point_to_cbb(&mut batch_cbb, group, &mut Tp_affine) == 0
                    || point_to_cbb(
                        &mut batch_cbb,
                        group,
                        &mut *affines.as_mut_ptr().offset(0 as libc::c_int as isize),
                    ) == 0
                    || point_to_cbb(
                        &mut batch_cbb,
                        group,
                        &mut *affines.as_mut_ptr().offset(1 as libc::c_int as isize),
                    ) == 0
                    || point_to_cbb(
                        &mut batch_cbb,
                        group,
                        &mut *affines.as_mut_ptr().offset(2 as libc::c_int as isize),
                    ) == 0
                {
                    current_block = 16348666687933192571;
                    break;
                }
                *Tps.offset(i as isize) = Tp;
                *Sps.offset(i as isize) = jacobians[0 as libc::c_int as usize];
                *Wps.offset(i as isize) = jacobians[1 as libc::c_int as usize];
                *Wsps.offset(i as isize) = jacobians[2 as libc::c_int as usize];
                if CBB_flush(cbb) == 0 {
                    current_block = 16348666687933192571;
                    break;
                }
                i = i.wrapping_add(1);
                i;
            }
        }
        match current_block {
            16348666687933192571 => {}
            _ => {
                let mut i_0: size_t = 0 as libc::c_int as size_t;
                loop {
                    if !(i_0 < num_to_issue) {
                        current_block = 15925075030174552612;
                        break;
                    }
                    if hash_c_batch(
                        method,
                        &mut *es.offset(i_0 as isize),
                        &mut batch_cbb,
                        i_0,
                    ) == 0
                    {
                        current_block = 16348666687933192571;
                        break;
                    }
                    i_0 = i_0.wrapping_add(1);
                    i_0;
                }
                match current_block {
                    16348666687933192571 => {}
                    _ => {
                        Tp_batch = EC_JACOBIAN {
                            X: EC_FELEM { words: [0; 9] },
                            Y: EC_FELEM { words: [0; 9] },
                            Z: EC_FELEM { words: [0; 9] },
                        };
                        Sp_batch = EC_JACOBIAN {
                            X: EC_FELEM { words: [0; 9] },
                            Y: EC_FELEM { words: [0; 9] },
                            Z: EC_FELEM { words: [0; 9] },
                        };
                        Wp_batch = EC_JACOBIAN {
                            X: EC_FELEM { words: [0; 9] },
                            Y: EC_FELEM { words: [0; 9] },
                            Z: EC_FELEM { words: [0; 9] },
                        };
                        Wsp_batch = EC_JACOBIAN {
                            X: EC_FELEM { words: [0; 9] },
                            Y: EC_FELEM { words: [0; 9] },
                            Z: EC_FELEM { words: [0; 9] },
                        };
                        if !(ec_point_mul_scalar_public_batch(
                            group,
                            &mut Tp_batch,
                            0 as *const EC_SCALAR,
                            Tps,
                            es,
                            num_to_issue,
                        ) == 0
                            || ec_point_mul_scalar_public_batch(
                                group,
                                &mut Sp_batch,
                                0 as *const EC_SCALAR,
                                Sps,
                                es,
                                num_to_issue,
                            ) == 0
                            || ec_point_mul_scalar_public_batch(
                                group,
                                &mut Wp_batch,
                                0 as *const EC_SCALAR,
                                Wps,
                                es,
                                num_to_issue,
                            ) == 0
                            || ec_point_mul_scalar_public_batch(
                                group,
                                &mut Wsp_batch,
                                0 as *const EC_SCALAR,
                                Wsps,
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
                                    &mut Tp_batch,
                                    &mut Sp_batch,
                                    &mut Wp_batch,
                                    &mut Wsp_batch,
                                    private_metadata,
                                ) == 0 || CBB_flush(cbb) == 0)
                            {
                                point_len = ec_point_byte_len(
                                    group,
                                    POINT_CONVERSION_UNCOMPRESSED,
                                );
                                token_len = point_len;
                                if (*method).prefix_point() != 0 {
                                    token_len = token_len
                                        .wrapping_add(2 as libc::c_int as size_t);
                                }
                                if CBS_skip(
                                    cbs,
                                    token_len * num_requested.wrapping_sub(num_to_issue),
                                ) == 0
                                {
                                    ERR_put_error(
                                        32 as libc::c_int,
                                        0 as libc::c_int,
                                        105 as libc::c_int,
                                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                                            as *const u8 as *const libc::c_char,
                                        911 as libc::c_int as libc::c_uint,
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
    OPENSSL_free(Tps as *mut libc::c_void);
    OPENSSL_free(Sps as *mut libc::c_void);
    OPENSSL_free(Wps as *mut libc::c_void);
    OPENSSL_free(Wsps as *mut libc::c_void);
    OPENSSL_free(es as *mut libc::c_void);
    CBB_cleanup(&mut batch_cbb);
    return ret;
}
unsafe extern "C" fn pmbtoken_unblind(
    mut method: *const PMBTOKEN_METHOD,
    mut key: *const TRUST_TOKEN_CLIENT_KEY,
    mut pretokens: *const stack_st_TRUST_TOKEN_PRETOKEN,
    mut cbs: *mut CBS,
    mut count: size_t,
    mut key_id: uint32_t,
) -> *mut stack_st_TRUST_TOKEN {
    let mut Tp_batch: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    let mut Sp_batch: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    let mut Wp_batch: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    let mut Wsp_batch: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    let mut proof: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut current_block: u64;
    let mut group: *const EC_GROUP = (*method).group;
    if count > sk_TRUST_TOKEN_PRETOKEN_num(pretokens) {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                as *const u8 as *const libc::c_char,
            933 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut stack_st_TRUST_TOKEN;
    }
    let mut ok: libc::c_int = 0 as libc::c_int;
    let mut ret: *mut stack_st_TRUST_TOKEN = sk_TRUST_TOKEN_new_null();
    let mut Tps: *mut EC_JACOBIAN = OPENSSL_calloc(
        count,
        ::core::mem::size_of::<EC_JACOBIAN>() as libc::c_ulong,
    ) as *mut EC_JACOBIAN;
    let mut Sps: *mut EC_JACOBIAN = OPENSSL_calloc(
        count,
        ::core::mem::size_of::<EC_JACOBIAN>() as libc::c_ulong,
    ) as *mut EC_JACOBIAN;
    let mut Wps: *mut EC_JACOBIAN = OPENSSL_calloc(
        count,
        ::core::mem::size_of::<EC_JACOBIAN>() as libc::c_ulong,
    ) as *mut EC_JACOBIAN;
    let mut Wsps: *mut EC_JACOBIAN = OPENSSL_calloc(
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
    if !(ret.is_null() || Tps.is_null() || Sps.is_null() || Wps.is_null()
        || Wsps.is_null() || es.is_null()
        || CBB_init(&mut batch_cbb, 0 as libc::c_int as size_t) == 0
        || point_to_cbb(&mut batch_cbb, (*method).group, &(*key).pubs) == 0
        || point_to_cbb(&mut batch_cbb, (*method).group, &(*key).pub0) == 0
        || point_to_cbb(&mut batch_cbb, (*method).group, &(*key).pub1) == 0)
    {
        let mut i: size_t = 0 as libc::c_int as size_t;
        loop {
            if !(i < count) {
                current_block = 11057878835866523405;
                break;
            }
            let mut pretoken: *const TRUST_TOKEN_PRETOKEN = sk_TRUST_TOKEN_PRETOKEN_value(
                pretokens,
                i,
            );
            let mut s: [uint8_t; 64] = [0; 64];
            let mut Wp_affine: EC_AFFINE = EC_AFFINE {
                X: EC_FELEM { words: [0; 9] },
                Y: EC_FELEM { words: [0; 9] },
            };
            let mut Wsp_affine: EC_AFFINE = EC_AFFINE {
                X: EC_FELEM { words: [0; 9] },
                Y: EC_FELEM { words: [0; 9] },
            };
            if CBS_copy_bytes(cbs, s.as_mut_ptr(), 64 as libc::c_int as size_t) == 0
                || cbs_get_prefixed_point(
                    cbs,
                    group,
                    &mut Wp_affine,
                    (*method).prefix_point(),
                ) == 0
                || cbs_get_prefixed_point(
                    cbs,
                    group,
                    &mut Wsp_affine,
                    (*method).prefix_point(),
                ) == 0
            {
                ERR_put_error(
                    32 as libc::c_int,
                    0 as libc::c_int,
                    105 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                        as *const u8 as *const libc::c_char,
                    969 as libc::c_int as libc::c_uint,
                );
                current_block = 8845708786949329232;
                break;
            } else {
                ec_affine_to_jacobian(
                    group,
                    &mut *Tps.offset(i as isize),
                    &(*pretoken).Tp,
                );
                ec_affine_to_jacobian(
                    group,
                    &mut *Wps.offset(i as isize),
                    &mut Wp_affine,
                );
                ec_affine_to_jacobian(
                    group,
                    &mut *Wsps.offset(i as isize),
                    &mut Wsp_affine,
                );
                if ((*method).hash_s)
                    .expect(
                        "non-null function pointer",
                    )(
                    group,
                    &mut *Sps.offset(i as isize),
                    &(*pretoken).Tp,
                    s.as_mut_ptr() as *const uint8_t,
                ) == 0
                {
                    current_block = 8845708786949329232;
                    break;
                }
                let mut Sp_affine: EC_AFFINE = EC_AFFINE {
                    X: EC_FELEM { words: [0; 9] },
                    Y: EC_FELEM { words: [0; 9] },
                };
                if point_to_cbb(&mut batch_cbb, group, &(*pretoken).Tp) == 0
                    || ec_jacobian_to_affine(
                        group,
                        &mut Sp_affine,
                        &mut *Sps.offset(i as isize),
                    ) == 0 || point_to_cbb(&mut batch_cbb, group, &mut Sp_affine) == 0
                    || point_to_cbb(&mut batch_cbb, group, &mut Wp_affine) == 0
                    || point_to_cbb(&mut batch_cbb, group, &mut Wsp_affine) == 0
                {
                    current_block = 8845708786949329232;
                    break;
                }
                let mut jacobians: [EC_JACOBIAN; 3] = [EC_JACOBIAN {
                    X: EC_FELEM { words: [0; 9] },
                    Y: EC_FELEM { words: [0; 9] },
                    Z: EC_FELEM { words: [0; 9] },
                }; 3];
                let mut affines: [EC_AFFINE; 3] = [EC_AFFINE {
                    X: EC_FELEM { words: [0; 9] },
                    Y: EC_FELEM { words: [0; 9] },
                }; 3];
                if ec_point_mul_scalar(
                    group,
                    &mut *jacobians.as_mut_ptr().offset(0 as libc::c_int as isize),
                    &mut *Sps.offset(i as isize),
                    &(*pretoken).r,
                ) == 0
                    || ec_point_mul_scalar(
                        group,
                        &mut *jacobians.as_mut_ptr().offset(1 as libc::c_int as isize),
                        &mut *Wps.offset(i as isize),
                        &(*pretoken).r,
                    ) == 0
                    || ec_point_mul_scalar(
                        group,
                        &mut *jacobians.as_mut_ptr().offset(2 as libc::c_int as isize),
                        &mut *Wsps.offset(i as isize),
                        &(*pretoken).r,
                    ) == 0
                    || ec_jacobian_to_affine_batch(
                        group,
                        affines.as_mut_ptr(),
                        jacobians.as_mut_ptr(),
                        3 as libc::c_int as size_t,
                    ) == 0
                {
                    current_block = 8845708786949329232;
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
                            3 as libc::c_int as size_t
                                * (2 as libc::c_int as size_t).wrapping_add(point_len),
                        ),
                ) == 0 || CBB_add_u32(&mut token_cbb, key_id) == 0
                    || CBB_add_bytes(
                        &mut token_cbb,
                        ((*pretoken).salt).as_ptr(),
                        64 as libc::c_int as size_t,
                    ) == 0
                    || cbb_add_prefixed_point(
                        &mut token_cbb,
                        group,
                        &mut *affines.as_mut_ptr().offset(0 as libc::c_int as isize),
                        (*method).prefix_point(),
                    ) == 0
                    || cbb_add_prefixed_point(
                        &mut token_cbb,
                        group,
                        &mut *affines.as_mut_ptr().offset(1 as libc::c_int as isize),
                        (*method).prefix_point(),
                    ) == 0
                    || cbb_add_prefixed_point(
                        &mut token_cbb,
                        group,
                        &mut *affines.as_mut_ptr().offset(2 as libc::c_int as isize),
                        (*method).prefix_point(),
                    ) == 0 || CBB_flush(&mut token_cbb) == 0
                {
                    CBB_cleanup(&mut token_cbb);
                    current_block = 8845708786949329232;
                    break;
                } else {
                    let mut token: *mut TRUST_TOKEN = TRUST_TOKEN_new(
                        CBB_data(&mut token_cbb),
                        CBB_len(&mut token_cbb),
                    );
                    CBB_cleanup(&mut token_cbb);
                    if token.is_null() || sk_TRUST_TOKEN_push(ret, token) == 0 {
                        TRUST_TOKEN_free(token);
                        current_block = 8845708786949329232;
                        break;
                    } else {
                        i = i.wrapping_add(1);
                        i;
                    }
                }
            }
        }
        match current_block {
            8845708786949329232 => {}
            _ => {
                let mut i_0: size_t = 0 as libc::c_int as size_t;
                loop {
                    if !(i_0 < count) {
                        current_block = 17788412896529399552;
                        break;
                    }
                    if hash_c_batch(
                        method,
                        &mut *es.offset(i_0 as isize),
                        &mut batch_cbb,
                        i_0,
                    ) == 0
                    {
                        current_block = 8845708786949329232;
                        break;
                    }
                    i_0 = i_0.wrapping_add(1);
                    i_0;
                }
                match current_block {
                    8845708786949329232 => {}
                    _ => {
                        Tp_batch = EC_JACOBIAN {
                            X: EC_FELEM { words: [0; 9] },
                            Y: EC_FELEM { words: [0; 9] },
                            Z: EC_FELEM { words: [0; 9] },
                        };
                        Sp_batch = EC_JACOBIAN {
                            X: EC_FELEM { words: [0; 9] },
                            Y: EC_FELEM { words: [0; 9] },
                            Z: EC_FELEM { words: [0; 9] },
                        };
                        Wp_batch = EC_JACOBIAN {
                            X: EC_FELEM { words: [0; 9] },
                            Y: EC_FELEM { words: [0; 9] },
                            Z: EC_FELEM { words: [0; 9] },
                        };
                        Wsp_batch = EC_JACOBIAN {
                            X: EC_FELEM { words: [0; 9] },
                            Y: EC_FELEM { words: [0; 9] },
                            Z: EC_FELEM { words: [0; 9] },
                        };
                        if !(ec_point_mul_scalar_public_batch(
                            group,
                            &mut Tp_batch,
                            0 as *const EC_SCALAR,
                            Tps,
                            es,
                            count,
                        ) == 0
                            || ec_point_mul_scalar_public_batch(
                                group,
                                &mut Sp_batch,
                                0 as *const EC_SCALAR,
                                Sps,
                                es,
                                count,
                            ) == 0
                            || ec_point_mul_scalar_public_batch(
                                group,
                                &mut Wp_batch,
                                0 as *const EC_SCALAR,
                                Wps,
                                es,
                                count,
                            ) == 0
                            || ec_point_mul_scalar_public_batch(
                                group,
                                &mut Wsp_batch,
                                0 as *const EC_SCALAR,
                                Wsps,
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
                                    &mut Tp_batch,
                                    &mut Sp_batch,
                                    &mut Wp_batch,
                                    &mut Wsp_batch,
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
    OPENSSL_free(Tps as *mut libc::c_void);
    OPENSSL_free(Sps as *mut libc::c_void);
    OPENSSL_free(Wps as *mut libc::c_void);
    OPENSSL_free(Wsps as *mut libc::c_void);
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
unsafe extern "C" fn pmbtoken_read(
    mut method: *const PMBTOKEN_METHOD,
    mut key: *const TRUST_TOKEN_ISSUER_KEY,
    mut out_nonce: *mut uint8_t,
    mut out_private_metadata: *mut uint8_t,
    mut token: *const uint8_t,
    mut token_len: size_t,
    mut include_message: libc::c_int,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> libc::c_int {
    let mut group: *const EC_GROUP = (*method).group;
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut salt: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, token, token_len);
    let mut S: EC_AFFINE = EC_AFFINE {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
    };
    let mut W: EC_AFFINE = EC_AFFINE {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
    };
    let mut Ws: EC_AFFINE = EC_AFFINE {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
    };
    if CBS_get_bytes(&mut cbs, &mut salt, 64 as libc::c_int as size_t) == 0
        || cbs_get_prefixed_point(&mut cbs, group, &mut S, (*method).prefix_point()) == 0
        || cbs_get_prefixed_point(&mut cbs, group, &mut W, (*method).prefix_point()) == 0
        || cbs_get_prefixed_point(&mut cbs, group, &mut Ws, (*method).prefix_point())
            == 0 || CBS_len(&mut cbs) != 0 as libc::c_int as size_t
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            110 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                as *const u8 as *const libc::c_char,
            1088 as libc::c_int as libc::c_uint,
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
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                    as *const u8 as *const libc::c_char,
                1094 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 152],
                    &[libc::c_char; 152],
                >(
                    b"int pmbtoken_read(const PMBTOKEN_METHOD *, const TRUST_TOKEN_ISSUER_KEY *, uint8_t *, uint8_t *, const uint8_t *, size_t, int, const uint8_t *, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_17687: {
            if 64 as libc::c_int == 64 as libc::c_int {} else {
                __assert_fail(
                    b"SHA512_DIGEST_LENGTH == TRUST_TOKEN_NONCE_SIZE\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                        as *const u8 as *const libc::c_char,
                    1094 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 152],
                        &[libc::c_char; 152],
                    >(
                        b"int pmbtoken_read(const PMBTOKEN_METHOD *, const TRUST_TOKEN_ISSUER_KEY *, uint8_t *, uint8_t *, const uint8_t *, size_t, int, const uint8_t *, size_t)\0",
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
    if ((*method).hash_t)
        .expect("non-null function pointer")(group, &mut T, out_nonce as *const uint8_t)
        == 0
    {
        return 0 as libc::c_int;
    }
    let mut S_jacobian: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    let mut S_precomp: EC_PRECOMP = EC_PRECOMP {
        comb: [EC_AFFINE {
            X: EC_FELEM { words: [0; 9] },
            Y: EC_FELEM { words: [0; 9] },
        }; 31],
    };
    let mut T_precomp: EC_PRECOMP = EC_PRECOMP {
        comb: [EC_AFFINE {
            X: EC_FELEM { words: [0; 9] },
            Y: EC_FELEM { words: [0; 9] },
        }; 31],
    };
    ec_affine_to_jacobian(group, &mut S_jacobian, &mut S);
    if ec_init_precomp(group, &mut S_precomp, &mut S_jacobian) == 0
        || ec_init_precomp(group, &mut T_precomp, &mut T) == 0
    {
        return 0 as libc::c_int;
    }
    let mut Ws_calculated: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    if ec_point_mul_scalar_precomp(
        group,
        &mut Ws_calculated,
        &mut T_precomp,
        &(*key).xs,
        &mut S_precomp,
        &(*key).ys,
        0 as *const EC_PRECOMP,
        0 as *const EC_SCALAR,
    ) == 0 || ec_affine_jacobian_equal(group, &mut Ws, &mut Ws_calculated) == 0
    {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            111 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                as *const u8 as *const libc::c_char,
            1123 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut W0: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    let mut W1: EC_JACOBIAN = EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    };
    if ec_point_mul_scalar_precomp(
        group,
        &mut W0,
        &mut T_precomp,
        &(*key).x0,
        &mut S_precomp,
        &(*key).y0,
        0 as *const EC_PRECOMP,
        0 as *const EC_SCALAR,
    ) == 0
        || ec_point_mul_scalar_precomp(
            group,
            &mut W1,
            &mut T_precomp,
            &(*key).x1,
            &mut S_precomp,
            &(*key).y1,
            0 as *const EC_PRECOMP,
            0 as *const EC_SCALAR,
        ) == 0
    {
        return 0 as libc::c_int;
    }
    let is_W0: libc::c_int = ec_affine_jacobian_equal(group, &mut W, &mut W0);
    let is_W1: libc::c_int = ec_affine_jacobian_equal(group, &mut W, &mut W1);
    let is_valid: libc::c_int = is_W0 ^ is_W1;
    if is_valid == 0 {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            4 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                as *const u8 as *const libc::c_char,
            1140 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    *out_private_metadata = is_W1 as uint8_t;
    return 1 as libc::c_int;
}
unsafe extern "C" fn pmbtoken_exp1_hash_t(
    mut group: *const EC_GROUP,
    mut out: *mut EC_JACOBIAN,
    mut t: *const uint8_t,
) -> libc::c_int {
    let kHashTLabel: [uint8_t; 30] = *::core::mem::transmute::<
        &[u8; 30],
        &[uint8_t; 30],
    >(b"PMBTokens Experiment V1 HashT\0");
    return ec_hash_to_curve_p384_xmd_sha512_sswu_draft07(
        group,
        out,
        kHashTLabel.as_ptr(),
        ::core::mem::size_of::<[uint8_t; 30]>() as libc::c_ulong,
        t,
        64 as libc::c_int as size_t,
    );
}
unsafe extern "C" fn pmbtoken_exp1_hash_s(
    mut group: *const EC_GROUP,
    mut out: *mut EC_JACOBIAN,
    mut t: *const EC_AFFINE,
    mut s: *const uint8_t,
) -> libc::c_int {
    let kHashSLabel: [uint8_t; 30] = *::core::mem::transmute::<
        &[u8; 30],
        &[uint8_t; 30],
    >(b"PMBTokens Experiment V1 HashS\0");
    let mut ret: libc::c_int = 0 as libc::c_int;
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
    let mut buf: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = 0;
    if !(CBB_init(&mut cbb, 0 as libc::c_int as size_t) == 0
        || point_to_cbb(&mut cbb, group, t) == 0
        || CBB_add_bytes(&mut cbb, s, 64 as libc::c_int as size_t) == 0
        || CBB_finish(&mut cbb, &mut buf, &mut len) == 0
        || ec_hash_to_curve_p384_xmd_sha512_sswu_draft07(
            group,
            out,
            kHashSLabel.as_ptr(),
            ::core::mem::size_of::<[uint8_t; 30]>() as libc::c_ulong,
            buf,
            len,
        ) == 0)
    {
        ret = 1 as libc::c_int;
    }
    OPENSSL_free(buf as *mut libc::c_void);
    CBB_cleanup(&mut cbb);
    return ret;
}
unsafe extern "C" fn pmbtoken_exp1_hash_c(
    mut group: *const EC_GROUP,
    mut out: *mut EC_SCALAR,
    mut buf: *mut uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let kHashCLabel: [uint8_t; 30] = *::core::mem::transmute::<
        &[u8; 30],
        &[uint8_t; 30],
    >(b"PMBTokens Experiment V1 HashC\0");
    return ec_hash_to_scalar_p384_xmd_sha512_draft07(
        group,
        out,
        kHashCLabel.as_ptr(),
        ::core::mem::size_of::<[uint8_t; 30]>() as libc::c_ulong,
        buf,
        len,
    );
}
unsafe extern "C" fn pmbtoken_exp1_hash_to_scalar(
    mut group: *const EC_GROUP,
    mut out: *mut EC_SCALAR,
    mut buf: *mut uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let kHashLabel: [uint8_t; 37] = *::core::mem::transmute::<
        &[u8; 37],
        &[uint8_t; 37],
    >(b"PMBTokens Experiment V1 HashToScalar\0");
    return ec_hash_to_scalar_p384_xmd_sha512_draft07(
        group,
        out,
        kHashLabel.as_ptr(),
        ::core::mem::size_of::<[uint8_t; 37]>() as libc::c_ulong,
        buf,
        len,
    );
}
static mut pmbtoken_exp1_ok: libc::c_int = 0 as libc::c_int;
static mut pmbtoken_exp1_method: PMBTOKEN_METHOD = PMBTOKEN_METHOD {
    group: 0 as *const EC_GROUP,
    g_precomp: EC_PRECOMP {
        comb: [EC_AFFINE {
            X: EC_FELEM { words: [0; 9] },
            Y: EC_FELEM { words: [0; 9] },
        }; 31],
    },
    h_precomp: EC_PRECOMP {
        comb: [EC_AFFINE {
            X: EC_FELEM { words: [0; 9] },
            Y: EC_FELEM { words: [0; 9] },
        }; 31],
    },
    h: EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    },
    hash_t: None,
    hash_s: None,
    hash_c: None,
    hash_to_scalar: None,
    prefix_point: [0; 1],
    c2rust_padding: [0; 7],
};
static mut pmbtoken_exp1_method_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn pmbtoken_exp1_init_method_impl() {
    static mut kH: [uint8_t; 97] = [
        0x4 as libc::c_int as uint8_t,
        0x82 as libc::c_int as uint8_t,
        0xd5 as libc::c_int as uint8_t,
        0x68 as libc::c_int as uint8_t,
        0xf5 as libc::c_int as uint8_t,
        0x39 as libc::c_int as uint8_t,
        0xf6 as libc::c_int as uint8_t,
        0x8 as libc::c_int as uint8_t,
        0x19 as libc::c_int as uint8_t,
        0xa1 as libc::c_int as uint8_t,
        0x75 as libc::c_int as uint8_t,
        0x9f as libc::c_int as uint8_t,
        0x98 as libc::c_int as uint8_t,
        0xb5 as libc::c_int as uint8_t,
        0x10 as libc::c_int as uint8_t,
        0xf5 as libc::c_int as uint8_t,
        0xb as libc::c_int as uint8_t,
        0x9d as libc::c_int as uint8_t,
        0x2b as libc::c_int as uint8_t,
        0xe1 as libc::c_int as uint8_t,
        0x64 as libc::c_int as uint8_t,
        0x4d as libc::c_int as uint8_t,
        0x2 as libc::c_int as uint8_t,
        0x76 as libc::c_int as uint8_t,
        0x18 as libc::c_int as uint8_t,
        0x11 as libc::c_int as uint8_t,
        0xf8 as libc::c_int as uint8_t,
        0x2f as libc::c_int as uint8_t,
        0xd3 as libc::c_int as uint8_t,
        0x33 as libc::c_int as uint8_t,
        0x25 as libc::c_int as uint8_t,
        0x1f as libc::c_int as uint8_t,
        0x2c as libc::c_int as uint8_t,
        0xb8 as libc::c_int as uint8_t,
        0xf6 as libc::c_int as uint8_t,
        0xf1 as libc::c_int as uint8_t,
        0x9e as libc::c_int as uint8_t,
        0x93 as libc::c_int as uint8_t,
        0x85 as libc::c_int as uint8_t,
        0x79 as libc::c_int as uint8_t,
        0xb3 as libc::c_int as uint8_t,
        0xb7 as libc::c_int as uint8_t,
        0x81 as libc::c_int as uint8_t,
        0xa3 as libc::c_int as uint8_t,
        0xe6 as libc::c_int as uint8_t,
        0x23 as libc::c_int as uint8_t,
        0xc3 as libc::c_int as uint8_t,
        0x1c as libc::c_int as uint8_t,
        0xff as libc::c_int as uint8_t,
        0x3 as libc::c_int as uint8_t,
        0xd9 as libc::c_int as uint8_t,
        0x40 as libc::c_int as uint8_t,
        0x6c as libc::c_int as uint8_t,
        0xec as libc::c_int as uint8_t,
        0xe0 as libc::c_int as uint8_t,
        0x4d as libc::c_int as uint8_t,
        0xea as libc::c_int as uint8_t,
        0xdf as libc::c_int as uint8_t,
        0x9d as libc::c_int as uint8_t,
        0x94 as libc::c_int as uint8_t,
        0xd1 as libc::c_int as uint8_t,
        0x87 as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0x27 as libc::c_int as uint8_t,
        0xf7 as libc::c_int as uint8_t,
        0x4f as libc::c_int as uint8_t,
        0x53 as libc::c_int as uint8_t,
        0xea as libc::c_int as uint8_t,
        0xa3 as libc::c_int as uint8_t,
        0x18 as libc::c_int as uint8_t,
        0x72 as libc::c_int as uint8_t,
        0xb9 as libc::c_int as uint8_t,
        0xd1 as libc::c_int as uint8_t,
        0x56 as libc::c_int as uint8_t,
        0xa0 as libc::c_int as uint8_t,
        0x4e as libc::c_int as uint8_t,
        0x81 as libc::c_int as uint8_t,
        0xaa as libc::c_int as uint8_t,
        0xeb as libc::c_int as uint8_t,
        0x1c as libc::c_int as uint8_t,
        0x22 as libc::c_int as uint8_t,
        0x6d as libc::c_int as uint8_t,
        0x39 as libc::c_int as uint8_t,
        0x1c as libc::c_int as uint8_t,
        0x5e as libc::c_int as uint8_t,
        0xb1 as libc::c_int as uint8_t,
        0x27 as libc::c_int as uint8_t,
        0xfc as libc::c_int as uint8_t,
        0x87 as libc::c_int as uint8_t,
        0xc3 as libc::c_int as uint8_t,
        0x95 as libc::c_int as uint8_t,
        0xd0 as libc::c_int as uint8_t,
        0x13 as libc::c_int as uint8_t,
        0xb7 as libc::c_int as uint8_t,
        0xb as libc::c_int as uint8_t,
        0x5c as libc::c_int as uint8_t,
        0xc7 as libc::c_int as uint8_t,
    ];
    pmbtoken_exp1_ok = pmbtoken_init_method(
        &mut pmbtoken_exp1_method,
        EC_group_p384(),
        kH.as_ptr(),
        ::core::mem::size_of::<[uint8_t; 97]>() as libc::c_ulong,
        Some(
            pmbtoken_exp1_hash_t
                as unsafe extern "C" fn(
                    *const EC_GROUP,
                    *mut EC_JACOBIAN,
                    *const uint8_t,
                ) -> libc::c_int,
        ),
        Some(
            pmbtoken_exp1_hash_s
                as unsafe extern "C" fn(
                    *const EC_GROUP,
                    *mut EC_JACOBIAN,
                    *const EC_AFFINE,
                    *const uint8_t,
                ) -> libc::c_int,
        ),
        Some(
            pmbtoken_exp1_hash_c
                as unsafe extern "C" fn(
                    *const EC_GROUP,
                    *mut EC_SCALAR,
                    *mut uint8_t,
                    size_t,
                ) -> libc::c_int,
        ),
        Some(
            pmbtoken_exp1_hash_to_scalar
                as unsafe extern "C" fn(
                    *const EC_GROUP,
                    *mut EC_SCALAR,
                    *mut uint8_t,
                    size_t,
                ) -> libc::c_int,
        ),
        1 as libc::c_int,
    );
}
unsafe extern "C" fn pmbtoken_exp1_init_method() -> libc::c_int {
    CRYPTO_once(
        &mut pmbtoken_exp1_method_once,
        Some(pmbtoken_exp1_init_method_impl as unsafe extern "C" fn() -> ()),
    );
    if pmbtoken_exp1_ok == 0 {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            4 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                as *const u8 as *const libc::c_char,
            1225 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_exp1_generate_key(
    mut out_private: *mut CBB,
    mut out_public: *mut CBB,
) -> libc::c_int {
    if pmbtoken_exp1_init_method() == 0 {
        return 0 as libc::c_int;
    }
    return pmbtoken_generate_key(&mut pmbtoken_exp1_method, out_private, out_public);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_exp1_derive_key_from_secret(
    mut out_private: *mut CBB,
    mut out_public: *mut CBB,
    mut secret: *const uint8_t,
    mut secret_len: size_t,
) -> libc::c_int {
    if pmbtoken_exp1_init_method() == 0 {
        return 0 as libc::c_int;
    }
    return pmbtoken_derive_key_from_secret(
        &mut pmbtoken_exp1_method,
        out_private,
        out_public,
        secret,
        secret_len,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_exp1_client_key_from_bytes(
    mut key: *mut TRUST_TOKEN_CLIENT_KEY,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    if pmbtoken_exp1_init_method() == 0 {
        return 0 as libc::c_int;
    }
    return pmbtoken_client_key_from_bytes(&mut pmbtoken_exp1_method, key, in_0, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_exp1_issuer_key_from_bytes(
    mut key: *mut TRUST_TOKEN_ISSUER_KEY,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    if pmbtoken_exp1_init_method() == 0 {
        return 0 as libc::c_int;
    }
    return pmbtoken_issuer_key_from_bytes(&mut pmbtoken_exp1_method, key, in_0, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_exp1_blind(
    mut cbb: *mut CBB,
    mut count: size_t,
    mut include_message: libc::c_int,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> *mut stack_st_TRUST_TOKEN_PRETOKEN {
    if pmbtoken_exp1_init_method() == 0 {
        return 0 as *mut stack_st_TRUST_TOKEN_PRETOKEN;
    }
    return pmbtoken_blind(
        &mut pmbtoken_exp1_method,
        cbb,
        count,
        include_message,
        msg,
        msg_len,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_exp1_sign(
    mut key: *const TRUST_TOKEN_ISSUER_KEY,
    mut cbb: *mut CBB,
    mut cbs: *mut CBS,
    mut num_requested: size_t,
    mut num_to_issue: size_t,
    mut private_metadata: uint8_t,
) -> libc::c_int {
    if pmbtoken_exp1_init_method() == 0 {
        return 0 as libc::c_int;
    }
    return pmbtoken_sign(
        &mut pmbtoken_exp1_method,
        key,
        cbb,
        cbs,
        num_requested,
        num_to_issue,
        private_metadata,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_exp1_unblind(
    mut key: *const TRUST_TOKEN_CLIENT_KEY,
    mut pretokens: *const stack_st_TRUST_TOKEN_PRETOKEN,
    mut cbs: *mut CBS,
    mut count: size_t,
    mut key_id: uint32_t,
) -> *mut stack_st_TRUST_TOKEN {
    if pmbtoken_exp1_init_method() == 0 {
        return 0 as *mut stack_st_TRUST_TOKEN;
    }
    return pmbtoken_unblind(
        &mut pmbtoken_exp1_method,
        key,
        pretokens,
        cbs,
        count,
        key_id,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_exp1_read(
    mut key: *const TRUST_TOKEN_ISSUER_KEY,
    mut out_nonce: *mut uint8_t,
    mut out_private_metadata: *mut uint8_t,
    mut token: *const uint8_t,
    mut token_len: size_t,
    mut include_message: libc::c_int,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> libc::c_int {
    if pmbtoken_exp1_init_method() == 0 {
        return 0 as libc::c_int;
    }
    return pmbtoken_read(
        &mut pmbtoken_exp1_method,
        key,
        out_nonce,
        out_private_metadata,
        token,
        token_len,
        include_message,
        msg,
        msg_len,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_exp1_get_h_for_testing(
    mut out: *mut uint8_t,
) -> libc::c_int {
    if pmbtoken_exp1_init_method() == 0 {
        return 0 as libc::c_int;
    }
    let mut h: EC_AFFINE = EC_AFFINE {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
    };
    return (ec_jacobian_to_affine(
        pmbtoken_exp1_method.group,
        &mut h,
        &mut pmbtoken_exp1_method.h,
    ) != 0
        && ec_point_to_bytes(
            pmbtoken_exp1_method.group,
            &mut h,
            POINT_CONVERSION_UNCOMPRESSED,
            out,
            97 as libc::c_int as size_t,
        ) == 97 as libc::c_int as size_t) as libc::c_int;
}
unsafe extern "C" fn pmbtoken_exp2_hash_t(
    mut group: *const EC_GROUP,
    mut out: *mut EC_JACOBIAN,
    mut t: *const uint8_t,
) -> libc::c_int {
    let kHashTLabel: [uint8_t; 30] = *::core::mem::transmute::<
        &[u8; 30],
        &[uint8_t; 30],
    >(b"PMBTokens Experiment V2 HashT\0");
    return ec_hash_to_curve_p384_xmd_sha512_sswu_draft07(
        group,
        out,
        kHashTLabel.as_ptr(),
        ::core::mem::size_of::<[uint8_t; 30]>() as libc::c_ulong,
        t,
        64 as libc::c_int as size_t,
    );
}
unsafe extern "C" fn pmbtoken_exp2_hash_s(
    mut group: *const EC_GROUP,
    mut out: *mut EC_JACOBIAN,
    mut t: *const EC_AFFINE,
    mut s: *const uint8_t,
) -> libc::c_int {
    let kHashSLabel: [uint8_t; 30] = *::core::mem::transmute::<
        &[u8; 30],
        &[uint8_t; 30],
    >(b"PMBTokens Experiment V2 HashS\0");
    let mut ret: libc::c_int = 0 as libc::c_int;
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
    let mut buf: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = 0;
    if !(CBB_init(&mut cbb, 0 as libc::c_int as size_t) == 0
        || point_to_cbb(&mut cbb, group, t) == 0
        || CBB_add_bytes(&mut cbb, s, 64 as libc::c_int as size_t) == 0
        || CBB_finish(&mut cbb, &mut buf, &mut len) == 0
        || ec_hash_to_curve_p384_xmd_sha512_sswu_draft07(
            group,
            out,
            kHashSLabel.as_ptr(),
            ::core::mem::size_of::<[uint8_t; 30]>() as libc::c_ulong,
            buf,
            len,
        ) == 0)
    {
        ret = 1 as libc::c_int;
    }
    OPENSSL_free(buf as *mut libc::c_void);
    CBB_cleanup(&mut cbb);
    return ret;
}
unsafe extern "C" fn pmbtoken_exp2_hash_c(
    mut group: *const EC_GROUP,
    mut out: *mut EC_SCALAR,
    mut buf: *mut uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let kHashCLabel: [uint8_t; 30] = *::core::mem::transmute::<
        &[u8; 30],
        &[uint8_t; 30],
    >(b"PMBTokens Experiment V2 HashC\0");
    return ec_hash_to_scalar_p384_xmd_sha512_draft07(
        group,
        out,
        kHashCLabel.as_ptr(),
        ::core::mem::size_of::<[uint8_t; 30]>() as libc::c_ulong,
        buf,
        len,
    );
}
unsafe extern "C" fn pmbtoken_exp2_hash_to_scalar(
    mut group: *const EC_GROUP,
    mut out: *mut EC_SCALAR,
    mut buf: *mut uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let kHashLabel: [uint8_t; 37] = *::core::mem::transmute::<
        &[u8; 37],
        &[uint8_t; 37],
    >(b"PMBTokens Experiment V2 HashToScalar\0");
    return ec_hash_to_scalar_p384_xmd_sha512_draft07(
        group,
        out,
        kHashLabel.as_ptr(),
        ::core::mem::size_of::<[uint8_t; 37]>() as libc::c_ulong,
        buf,
        len,
    );
}
static mut pmbtoken_exp2_ok: libc::c_int = 0 as libc::c_int;
static mut pmbtoken_exp2_method: PMBTOKEN_METHOD = PMBTOKEN_METHOD {
    group: 0 as *const EC_GROUP,
    g_precomp: EC_PRECOMP {
        comb: [EC_AFFINE {
            X: EC_FELEM { words: [0; 9] },
            Y: EC_FELEM { words: [0; 9] },
        }; 31],
    },
    h_precomp: EC_PRECOMP {
        comb: [EC_AFFINE {
            X: EC_FELEM { words: [0; 9] },
            Y: EC_FELEM { words: [0; 9] },
        }; 31],
    },
    h: EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    },
    hash_t: None,
    hash_s: None,
    hash_c: None,
    hash_to_scalar: None,
    prefix_point: [0; 1],
    c2rust_padding: [0; 7],
};
static mut pmbtoken_exp2_method_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn pmbtoken_exp2_init_method_impl() {
    static mut kH: [uint8_t; 97] = [
        0x4 as libc::c_int as uint8_t,
        0xbc as libc::c_int as uint8_t,
        0x27 as libc::c_int as uint8_t,
        0x24 as libc::c_int as uint8_t,
        0x99 as libc::c_int as uint8_t,
        0xfa as libc::c_int as uint8_t,
        0xc9 as libc::c_int as uint8_t,
        0xa4 as libc::c_int as uint8_t,
        0x74 as libc::c_int as uint8_t,
        0x6f as libc::c_int as uint8_t,
        0xf9 as libc::c_int as uint8_t,
        0x7 as libc::c_int as uint8_t,
        0x81 as libc::c_int as uint8_t,
        0x55 as libc::c_int as uint8_t,
        0xf8 as libc::c_int as uint8_t,
        0x1f as libc::c_int as uint8_t,
        0x6f as libc::c_int as uint8_t,
        0xda as libc::c_int as uint8_t,
        0x9 as libc::c_int as uint8_t,
        0xe7 as libc::c_int as uint8_t,
        0x8c as libc::c_int as uint8_t,
        0x5d as libc::c_int as uint8_t,
        0x9e as libc::c_int as uint8_t,
        0x4e as libc::c_int as uint8_t,
        0x14 as libc::c_int as uint8_t,
        0x7c as libc::c_int as uint8_t,
        0x53 as libc::c_int as uint8_t,
        0x14 as libc::c_int as uint8_t,
        0xbc as libc::c_int as uint8_t,
        0x7e as libc::c_int as uint8_t,
        0x29 as libc::c_int as uint8_t,
        0x57 as libc::c_int as uint8_t,
        0x92 as libc::c_int as uint8_t,
        0x17 as libc::c_int as uint8_t,
        0x94 as libc::c_int as uint8_t,
        0x6e as libc::c_int as uint8_t,
        0xd2 as libc::c_int as uint8_t,
        0xdf as libc::c_int as uint8_t,
        0xa5 as libc::c_int as uint8_t,
        0x31 as libc::c_int as uint8_t,
        0x1b as libc::c_int as uint8_t,
        0x4e as libc::c_int as uint8_t,
        0xb7 as libc::c_int as uint8_t,
        0xfc as libc::c_int as uint8_t,
        0x93 as libc::c_int as uint8_t,
        0xe3 as libc::c_int as uint8_t,
        0x6e as libc::c_int as uint8_t,
        0x14 as libc::c_int as uint8_t,
        0x1f as libc::c_int as uint8_t,
        0x4f as libc::c_int as uint8_t,
        0x14 as libc::c_int as uint8_t,
        0xf3 as libc::c_int as uint8_t,
        0xe5 as libc::c_int as uint8_t,
        0x47 as libc::c_int as uint8_t,
        0x61 as libc::c_int as uint8_t,
        0x1c as libc::c_int as uint8_t,
        0x2c as libc::c_int as uint8_t,
        0x72 as libc::c_int as uint8_t,
        0x25 as libc::c_int as uint8_t,
        0xf0 as libc::c_int as uint8_t,
        0x4a as libc::c_int as uint8_t,
        0x45 as libc::c_int as uint8_t,
        0x23 as libc::c_int as uint8_t,
        0x2d as libc::c_int as uint8_t,
        0x57 as libc::c_int as uint8_t,
        0x93 as libc::c_int as uint8_t,
        0xe as libc::c_int as uint8_t,
        0xb2 as libc::c_int as uint8_t,
        0x55 as libc::c_int as uint8_t,
        0xb8 as libc::c_int as uint8_t,
        0x57 as libc::c_int as uint8_t,
        0x25 as libc::c_int as uint8_t,
        0x4c as libc::c_int as uint8_t,
        0x1e as libc::c_int as uint8_t,
        0xdb as libc::c_int as uint8_t,
        0xfd as libc::c_int as uint8_t,
        0x58 as libc::c_int as uint8_t,
        0x70 as libc::c_int as uint8_t,
        0x17 as libc::c_int as uint8_t,
        0x9a as libc::c_int as uint8_t,
        0xbb as libc::c_int as uint8_t,
        0x9e as libc::c_int as uint8_t,
        0x5e as libc::c_int as uint8_t,
        0x93 as libc::c_int as uint8_t,
        0x9e as libc::c_int as uint8_t,
        0x92 as libc::c_int as uint8_t,
        0xd3 as libc::c_int as uint8_t,
        0xe8 as libc::c_int as uint8_t,
        0x25 as libc::c_int as uint8_t,
        0x62 as libc::c_int as uint8_t,
        0xbf as libc::c_int as uint8_t,
        0x59 as libc::c_int as uint8_t,
        0xb2 as libc::c_int as uint8_t,
        0xd2 as libc::c_int as uint8_t,
        0x3d as libc::c_int as uint8_t,
        0x71 as libc::c_int as uint8_t,
        0xff as libc::c_int as uint8_t,
    ];
    pmbtoken_exp2_ok = pmbtoken_init_method(
        &mut pmbtoken_exp2_method,
        EC_group_p384(),
        kH.as_ptr(),
        ::core::mem::size_of::<[uint8_t; 97]>() as libc::c_ulong,
        Some(
            pmbtoken_exp2_hash_t
                as unsafe extern "C" fn(
                    *const EC_GROUP,
                    *mut EC_JACOBIAN,
                    *const uint8_t,
                ) -> libc::c_int,
        ),
        Some(
            pmbtoken_exp2_hash_s
                as unsafe extern "C" fn(
                    *const EC_GROUP,
                    *mut EC_JACOBIAN,
                    *const EC_AFFINE,
                    *const uint8_t,
                ) -> libc::c_int,
        ),
        Some(
            pmbtoken_exp2_hash_c
                as unsafe extern "C" fn(
                    *const EC_GROUP,
                    *mut EC_SCALAR,
                    *mut uint8_t,
                    size_t,
                ) -> libc::c_int,
        ),
        Some(
            pmbtoken_exp2_hash_to_scalar
                as unsafe extern "C" fn(
                    *const EC_GROUP,
                    *mut EC_SCALAR,
                    *mut uint8_t,
                    size_t,
                ) -> libc::c_int,
        ),
        0 as libc::c_int,
    );
}
unsafe extern "C" fn pmbtoken_exp2_init_method() -> libc::c_int {
    CRYPTO_once(
        &mut pmbtoken_exp2_method_once,
        Some(pmbtoken_exp2_init_method_impl as unsafe extern "C" fn() -> ()),
    );
    if pmbtoken_exp2_ok == 0 {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            4 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                as *const u8 as *const libc::c_char,
            1398 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_exp2_generate_key(
    mut out_private: *mut CBB,
    mut out_public: *mut CBB,
) -> libc::c_int {
    if pmbtoken_exp2_init_method() == 0 {
        return 0 as libc::c_int;
    }
    return pmbtoken_generate_key(&mut pmbtoken_exp2_method, out_private, out_public);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_exp2_derive_key_from_secret(
    mut out_private: *mut CBB,
    mut out_public: *mut CBB,
    mut secret: *const uint8_t,
    mut secret_len: size_t,
) -> libc::c_int {
    if pmbtoken_exp2_init_method() == 0 {
        return 0 as libc::c_int;
    }
    return pmbtoken_derive_key_from_secret(
        &mut pmbtoken_exp2_method,
        out_private,
        out_public,
        secret,
        secret_len,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_exp2_client_key_from_bytes(
    mut key: *mut TRUST_TOKEN_CLIENT_KEY,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    if pmbtoken_exp2_init_method() == 0 {
        return 0 as libc::c_int;
    }
    return pmbtoken_client_key_from_bytes(&mut pmbtoken_exp2_method, key, in_0, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_exp2_issuer_key_from_bytes(
    mut key: *mut TRUST_TOKEN_ISSUER_KEY,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    if pmbtoken_exp2_init_method() == 0 {
        return 0 as libc::c_int;
    }
    return pmbtoken_issuer_key_from_bytes(&mut pmbtoken_exp2_method, key, in_0, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_exp2_blind(
    mut cbb: *mut CBB,
    mut count: size_t,
    mut include_message: libc::c_int,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> *mut stack_st_TRUST_TOKEN_PRETOKEN {
    if pmbtoken_exp2_init_method() == 0 {
        return 0 as *mut stack_st_TRUST_TOKEN_PRETOKEN;
    }
    return pmbtoken_blind(
        &mut pmbtoken_exp2_method,
        cbb,
        count,
        include_message,
        msg,
        msg_len,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_exp2_sign(
    mut key: *const TRUST_TOKEN_ISSUER_KEY,
    mut cbb: *mut CBB,
    mut cbs: *mut CBS,
    mut num_requested: size_t,
    mut num_to_issue: size_t,
    mut private_metadata: uint8_t,
) -> libc::c_int {
    if pmbtoken_exp2_init_method() == 0 {
        return 0 as libc::c_int;
    }
    return pmbtoken_sign(
        &mut pmbtoken_exp2_method,
        key,
        cbb,
        cbs,
        num_requested,
        num_to_issue,
        private_metadata,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_exp2_unblind(
    mut key: *const TRUST_TOKEN_CLIENT_KEY,
    mut pretokens: *const stack_st_TRUST_TOKEN_PRETOKEN,
    mut cbs: *mut CBS,
    mut count: size_t,
    mut key_id: uint32_t,
) -> *mut stack_st_TRUST_TOKEN {
    if pmbtoken_exp2_init_method() == 0 {
        return 0 as *mut stack_st_TRUST_TOKEN;
    }
    return pmbtoken_unblind(
        &mut pmbtoken_exp2_method,
        key,
        pretokens,
        cbs,
        count,
        key_id,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_exp2_read(
    mut key: *const TRUST_TOKEN_ISSUER_KEY,
    mut out_nonce: *mut uint8_t,
    mut out_private_metadata: *mut uint8_t,
    mut token: *const uint8_t,
    mut token_len: size_t,
    mut include_message: libc::c_int,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> libc::c_int {
    if pmbtoken_exp2_init_method() == 0 {
        return 0 as libc::c_int;
    }
    return pmbtoken_read(
        &mut pmbtoken_exp2_method,
        key,
        out_nonce,
        out_private_metadata,
        token,
        token_len,
        include_message,
        msg,
        msg_len,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_exp2_get_h_for_testing(
    mut out: *mut uint8_t,
) -> libc::c_int {
    if pmbtoken_exp2_init_method() == 0 {
        return 0 as libc::c_int;
    }
    let mut h: EC_AFFINE = EC_AFFINE {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
    };
    return (ec_jacobian_to_affine(
        pmbtoken_exp2_method.group,
        &mut h,
        &mut pmbtoken_exp2_method.h,
    ) != 0
        && ec_point_to_bytes(
            pmbtoken_exp2_method.group,
            &mut h,
            POINT_CONVERSION_UNCOMPRESSED,
            out,
            97 as libc::c_int as size_t,
        ) == 97 as libc::c_int as size_t) as libc::c_int;
}
unsafe extern "C" fn pmbtoken_pst1_hash_t(
    mut group: *const EC_GROUP,
    mut out: *mut EC_JACOBIAN,
    mut t: *const uint8_t,
) -> libc::c_int {
    let kHashTLabel: [uint8_t; 23] = *::core::mem::transmute::<
        &[u8; 23],
        &[uint8_t; 23],
    >(b"PMBTokens PST V1 HashT\0");
    return ec_hash_to_curve_p384_xmd_sha384_sswu(
        group,
        out,
        kHashTLabel.as_ptr(),
        ::core::mem::size_of::<[uint8_t; 23]>() as libc::c_ulong,
        t,
        64 as libc::c_int as size_t,
    );
}
unsafe extern "C" fn pmbtoken_pst1_hash_s(
    mut group: *const EC_GROUP,
    mut out: *mut EC_JACOBIAN,
    mut t: *const EC_AFFINE,
    mut s: *const uint8_t,
) -> libc::c_int {
    let kHashSLabel: [uint8_t; 23] = *::core::mem::transmute::<
        &[u8; 23],
        &[uint8_t; 23],
    >(b"PMBTokens PST V1 HashS\0");
    let mut ret: libc::c_int = 0 as libc::c_int;
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
    let mut buf: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = 0;
    if !(CBB_init(&mut cbb, 0 as libc::c_int as size_t) == 0
        || point_to_cbb(&mut cbb, group, t) == 0
        || CBB_add_bytes(&mut cbb, s, 64 as libc::c_int as size_t) == 0
        || CBB_finish(&mut cbb, &mut buf, &mut len) == 0
        || ec_hash_to_curve_p384_xmd_sha384_sswu(
            group,
            out,
            kHashSLabel.as_ptr(),
            ::core::mem::size_of::<[uint8_t; 23]>() as libc::c_ulong,
            buf,
            len,
        ) == 0)
    {
        ret = 1 as libc::c_int;
    }
    OPENSSL_free(buf as *mut libc::c_void);
    CBB_cleanup(&mut cbb);
    return ret;
}
unsafe extern "C" fn pmbtoken_pst1_hash_c(
    mut group: *const EC_GROUP,
    mut out: *mut EC_SCALAR,
    mut buf: *mut uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let kHashCLabel: [uint8_t; 23] = *::core::mem::transmute::<
        &[u8; 23],
        &[uint8_t; 23],
    >(b"PMBTokens PST V1 HashC\0");
    return ec_hash_to_scalar_p384_xmd_sha384(
        group,
        out,
        kHashCLabel.as_ptr(),
        ::core::mem::size_of::<[uint8_t; 23]>() as libc::c_ulong,
        buf,
        len,
    );
}
unsafe extern "C" fn pmbtoken_pst1_hash_to_scalar(
    mut group: *const EC_GROUP,
    mut out: *mut EC_SCALAR,
    mut buf: *mut uint8_t,
    mut len: size_t,
) -> libc::c_int {
    let kHashLabel: [uint8_t; 30] = *::core::mem::transmute::<
        &[u8; 30],
        &[uint8_t; 30],
    >(b"PMBTokens PST V1 HashToScalar\0");
    return ec_hash_to_scalar_p384_xmd_sha384(
        group,
        out,
        kHashLabel.as_ptr(),
        ::core::mem::size_of::<[uint8_t; 30]>() as libc::c_ulong,
        buf,
        len,
    );
}
static mut pmbtoken_pst1_ok: libc::c_int = 0 as libc::c_int;
static mut pmbtoken_pst1_method: PMBTOKEN_METHOD = PMBTOKEN_METHOD {
    group: 0 as *const EC_GROUP,
    g_precomp: EC_PRECOMP {
        comb: [EC_AFFINE {
            X: EC_FELEM { words: [0; 9] },
            Y: EC_FELEM { words: [0; 9] },
        }; 31],
    },
    h_precomp: EC_PRECOMP {
        comb: [EC_AFFINE {
            X: EC_FELEM { words: [0; 9] },
            Y: EC_FELEM { words: [0; 9] },
        }; 31],
    },
    h: EC_JACOBIAN {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
        Z: EC_FELEM { words: [0; 9] },
    },
    hash_t: None,
    hash_s: None,
    hash_c: None,
    hash_to_scalar: None,
    prefix_point: [0; 1],
    c2rust_padding: [0; 7],
};
static mut pmbtoken_pst1_method_once: CRYPTO_once_t = 0 as libc::c_int;
unsafe extern "C" fn pmbtoken_pst1_init_method_impl() {
    static mut kH: [uint8_t; 97] = [
        0x4 as libc::c_int as uint8_t,
        0x4c as libc::c_int as uint8_t,
        0xfa as libc::c_int as uint8_t,
        0xd4 as libc::c_int as uint8_t,
        0x33 as libc::c_int as uint8_t,
        0x6d as libc::c_int as uint8_t,
        0x8c as libc::c_int as uint8_t,
        0x4e as libc::c_int as uint8_t,
        0x18 as libc::c_int as uint8_t,
        0xce as libc::c_int as uint8_t,
        0x1a as libc::c_int as uint8_t,
        0x82 as libc::c_int as uint8_t,
        0x7b as libc::c_int as uint8_t,
        0x53 as libc::c_int as uint8_t,
        0x8c as libc::c_int as uint8_t,
        0xf8 as libc::c_int as uint8_t,
        0x63 as libc::c_int as uint8_t,
        0x18 as libc::c_int as uint8_t,
        0xe5 as libc::c_int as uint8_t,
        0xa3 as libc::c_int as uint8_t,
        0x96 as libc::c_int as uint8_t,
        0xd as libc::c_int as uint8_t,
        0x5 as libc::c_int as uint8_t,
        0xde as libc::c_int as uint8_t,
        0xf4 as libc::c_int as uint8_t,
        0x83 as libc::c_int as uint8_t,
        0xa7 as libc::c_int as uint8_t,
        0xd8 as libc::c_int as uint8_t,
        0xde as libc::c_int as uint8_t,
        0x9c as libc::c_int as uint8_t,
        0x50 as libc::c_int as uint8_t,
        0x81 as libc::c_int as uint8_t,
        0x38 as libc::c_int as uint8_t,
        0xc9 as libc::c_int as uint8_t,
        0x38 as libc::c_int as uint8_t,
        0x25 as libc::c_int as uint8_t,
        0xa3 as libc::c_int as uint8_t,
        0x70 as libc::c_int as uint8_t,
        0x97 as libc::c_int as uint8_t,
        0xc1 as libc::c_int as uint8_t,
        0x1c as libc::c_int as uint8_t,
        0x33 as libc::c_int as uint8_t,
        0x2e as libc::c_int as uint8_t,
        0x83 as libc::c_int as uint8_t,
        0x68 as libc::c_int as uint8_t,
        0x64 as libc::c_int as uint8_t,
        0x9c as libc::c_int as uint8_t,
        0x53 as libc::c_int as uint8_t,
        0x73 as libc::c_int as uint8_t,
        0xc3 as libc::c_int as uint8_t,
        0x3 as libc::c_int as uint8_t,
        0xc1 as libc::c_int as uint8_t,
        0xa9 as libc::c_int as uint8_t,
        0xd8 as libc::c_int as uint8_t,
        0x92 as libc::c_int as uint8_t,
        0xa2 as libc::c_int as uint8_t,
        0x32 as libc::c_int as uint8_t,
        0xf4 as libc::c_int as uint8_t,
        0x22 as libc::c_int as uint8_t,
        0x40 as libc::c_int as uint8_t,
        0x7 as libc::c_int as uint8_t,
        0x2d as libc::c_int as uint8_t,
        0x9b as libc::c_int as uint8_t,
        0x6f as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xff as libc::c_int as uint8_t,
        0x2a as libc::c_int as uint8_t,
        0x92 as libc::c_int as uint8_t,
        0x3 as libc::c_int as uint8_t,
        0xb1 as libc::c_int as uint8_t,
        0x73 as libc::c_int as uint8_t,
        0x9 as libc::c_int as uint8_t,
        0x1a as libc::c_int as uint8_t,
        0x6a as libc::c_int as uint8_t,
        0x4a as libc::c_int as uint8_t,
        0xc2 as libc::c_int as uint8_t,
        0x4c as libc::c_int as uint8_t,
        0xac as libc::c_int as uint8_t,
        0x13 as libc::c_int as uint8_t,
        0x59 as libc::c_int as uint8_t,
        0xf4 as libc::c_int as uint8_t,
        0x28 as libc::c_int as uint8_t,
        0xe as libc::c_int as uint8_t,
        0x78 as libc::c_int as uint8_t,
        0x69 as libc::c_int as uint8_t,
        0xa5 as libc::c_int as uint8_t,
        0xdf as libc::c_int as uint8_t,
        0xd as libc::c_int as uint8_t,
        0x74 as libc::c_int as uint8_t,
        0xeb as libc::c_int as uint8_t,
        0x14 as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0x8a as libc::c_int as uint8_t,
        0x32 as libc::c_int as uint8_t,
        0xbb as libc::c_int as uint8_t,
        0xd3 as libc::c_int as uint8_t,
        0x91 as libc::c_int as uint8_t,
    ];
    pmbtoken_pst1_ok = pmbtoken_init_method(
        &mut pmbtoken_pst1_method,
        EC_group_p384(),
        kH.as_ptr(),
        ::core::mem::size_of::<[uint8_t; 97]>() as libc::c_ulong,
        Some(
            pmbtoken_pst1_hash_t
                as unsafe extern "C" fn(
                    *const EC_GROUP,
                    *mut EC_JACOBIAN,
                    *const uint8_t,
                ) -> libc::c_int,
        ),
        Some(
            pmbtoken_pst1_hash_s
                as unsafe extern "C" fn(
                    *const EC_GROUP,
                    *mut EC_JACOBIAN,
                    *const EC_AFFINE,
                    *const uint8_t,
                ) -> libc::c_int,
        ),
        Some(
            pmbtoken_pst1_hash_c
                as unsafe extern "C" fn(
                    *const EC_GROUP,
                    *mut EC_SCALAR,
                    *mut uint8_t,
                    size_t,
                ) -> libc::c_int,
        ),
        Some(
            pmbtoken_pst1_hash_to_scalar
                as unsafe extern "C" fn(
                    *const EC_GROUP,
                    *mut EC_SCALAR,
                    *mut uint8_t,
                    size_t,
                ) -> libc::c_int,
        ),
        0 as libc::c_int,
    );
}
unsafe extern "C" fn pmbtoken_pst1_init_method() -> libc::c_int {
    CRYPTO_once(
        &mut pmbtoken_pst1_method_once,
        Some(pmbtoken_pst1_init_method_impl as unsafe extern "C" fn() -> ()),
    );
    if pmbtoken_pst1_ok == 0 {
        ERR_put_error(
            32 as libc::c_int,
            0 as libc::c_int,
            4 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/trust_token/pmbtoken.c\0"
                as *const u8 as *const libc::c_char,
            1572 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_pst1_generate_key(
    mut out_private: *mut CBB,
    mut out_public: *mut CBB,
) -> libc::c_int {
    if pmbtoken_pst1_init_method() == 0 {
        return 0 as libc::c_int;
    }
    return pmbtoken_generate_key(&mut pmbtoken_pst1_method, out_private, out_public);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_pst1_derive_key_from_secret(
    mut out_private: *mut CBB,
    mut out_public: *mut CBB,
    mut secret: *const uint8_t,
    mut secret_len: size_t,
) -> libc::c_int {
    if pmbtoken_pst1_init_method() == 0 {
        return 0 as libc::c_int;
    }
    return pmbtoken_derive_key_from_secret(
        &mut pmbtoken_pst1_method,
        out_private,
        out_public,
        secret,
        secret_len,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_pst1_client_key_from_bytes(
    mut key: *mut TRUST_TOKEN_CLIENT_KEY,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    if pmbtoken_pst1_init_method() == 0 {
        return 0 as libc::c_int;
    }
    return pmbtoken_client_key_from_bytes(&mut pmbtoken_pst1_method, key, in_0, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_pst1_issuer_key_from_bytes(
    mut key: *mut TRUST_TOKEN_ISSUER_KEY,
    mut in_0: *const uint8_t,
    mut len: size_t,
) -> libc::c_int {
    if pmbtoken_pst1_init_method() == 0 {
        return 0 as libc::c_int;
    }
    return pmbtoken_issuer_key_from_bytes(&mut pmbtoken_pst1_method, key, in_0, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_pst1_blind(
    mut cbb: *mut CBB,
    mut count: size_t,
    mut include_message: libc::c_int,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> *mut stack_st_TRUST_TOKEN_PRETOKEN {
    if pmbtoken_pst1_init_method() == 0 {
        return 0 as *mut stack_st_TRUST_TOKEN_PRETOKEN;
    }
    return pmbtoken_blind(
        &mut pmbtoken_pst1_method,
        cbb,
        count,
        include_message,
        msg,
        msg_len,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_pst1_sign(
    mut key: *const TRUST_TOKEN_ISSUER_KEY,
    mut cbb: *mut CBB,
    mut cbs: *mut CBS,
    mut num_requested: size_t,
    mut num_to_issue: size_t,
    mut private_metadata: uint8_t,
) -> libc::c_int {
    if pmbtoken_pst1_init_method() == 0 {
        return 0 as libc::c_int;
    }
    return pmbtoken_sign(
        &mut pmbtoken_pst1_method,
        key,
        cbb,
        cbs,
        num_requested,
        num_to_issue,
        private_metadata,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_pst1_unblind(
    mut key: *const TRUST_TOKEN_CLIENT_KEY,
    mut pretokens: *const stack_st_TRUST_TOKEN_PRETOKEN,
    mut cbs: *mut CBS,
    mut count: size_t,
    mut key_id: uint32_t,
) -> *mut stack_st_TRUST_TOKEN {
    if pmbtoken_pst1_init_method() == 0 {
        return 0 as *mut stack_st_TRUST_TOKEN;
    }
    return pmbtoken_unblind(
        &mut pmbtoken_pst1_method,
        key,
        pretokens,
        cbs,
        count,
        key_id,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_pst1_read(
    mut key: *const TRUST_TOKEN_ISSUER_KEY,
    mut out_nonce: *mut uint8_t,
    mut out_private_metadata: *mut uint8_t,
    mut token: *const uint8_t,
    mut token_len: size_t,
    mut include_message: libc::c_int,
    mut msg: *const uint8_t,
    mut msg_len: size_t,
) -> libc::c_int {
    if pmbtoken_pst1_init_method() == 0 {
        return 0 as libc::c_int;
    }
    return pmbtoken_read(
        &mut pmbtoken_pst1_method,
        key,
        out_nonce,
        out_private_metadata,
        token,
        token_len,
        include_message,
        msg,
        msg_len,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pmbtoken_pst1_get_h_for_testing(
    mut out: *mut uint8_t,
) -> libc::c_int {
    if pmbtoken_pst1_init_method() == 0 {
        return 0 as libc::c_int;
    }
    let mut h: EC_AFFINE = EC_AFFINE {
        X: EC_FELEM { words: [0; 9] },
        Y: EC_FELEM { words: [0; 9] },
    };
    return (ec_jacobian_to_affine(
        pmbtoken_pst1_method.group,
        &mut h,
        &mut pmbtoken_pst1_method.h,
    ) != 0
        && ec_point_to_bytes(
            pmbtoken_pst1_method.group,
            &mut h,
            POINT_CONVERSION_UNCOMPRESSED,
            out,
            97 as libc::c_int as size_t,
        ) == 97 as libc::c_int as size_t) as libc::c_int;
}
