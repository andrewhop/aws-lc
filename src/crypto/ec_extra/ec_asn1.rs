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
    pub type stack_st_void;
    pub type ecdsa_sig_st;
    fn BN_new() -> *mut BIGNUM;
    fn BN_free(bn: *mut BIGNUM);
    fn BN_num_bytes(bn: *const BIGNUM) -> libc::c_uint;
    fn BN_bin2bn(in_0: *const uint8_t, len: size_t, ret: *mut BIGNUM) -> *mut BIGNUM;
    fn BN_bn2bin_padded(
        out: *mut uint8_t,
        len: size_t,
        in_0: *const BIGNUM,
    ) -> libc::c_int;
    fn BN_bn2cbb_padded(out: *mut CBB, len: size_t, in_0: *const BIGNUM) -> libc::c_int;
    fn BIO_write_all(
        bio: *mut BIO,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn BIO_read_asn1(
        bio: *mut BIO,
        out: *mut *mut uint8_t,
        out_len: *mut size_t,
        max_len: size_t,
    ) -> libc::c_int;
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_skip(cbs: *mut CBS, len: size_t) -> libc::c_int;
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_mem_equal(cbs: *const CBS, data: *const uint8_t, len: size_t) -> libc::c_int;
    fn CBS_get_u8(cbs: *mut CBS, out: *mut uint8_t) -> libc::c_int;
    fn CBS_get_asn1(
        cbs: *mut CBS,
        out: *mut CBS,
        tag_value: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBS_peek_asn1_tag(cbs: *const CBS, tag_value: CBS_ASN1_TAG) -> libc::c_int;
    fn CBS_get_asn1_uint64(cbs: *mut CBS, out: *mut uint64_t) -> libc::c_int;
    fn CBS_get_optional_asn1(
        cbs: *mut CBS,
        out: *mut CBS,
        out_present: *mut libc::c_int,
        tag: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBS_is_unsigned_asn1_integer(cbs: *const CBS) -> libc::c_int;
    fn CBB_init(cbb: *mut CBB, initial_capacity: size_t) -> libc::c_int;
    fn CBB_cleanup(cbb: *mut CBB);
    fn CBB_flush(cbb: *mut CBB) -> libc::c_int;
    fn CBB_add_asn1(
        cbb: *mut CBB,
        out_contents: *mut CBB,
        tag: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBB_add_bytes(cbb: *mut CBB, data: *const uint8_t, len: size_t) -> libc::c_int;
    fn CBB_add_space(
        cbb: *mut CBB,
        out_data: *mut *mut uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn CBB_add_u8(cbb: *mut CBB, value: uint8_t) -> libc::c_int;
    fn CBB_add_asn1_uint64(cbb: *mut CBB, value: uint64_t) -> libc::c_int;
    fn ec_point_mul_scalar_base(
        group: *const EC_GROUP,
        r: *mut EC_JACOBIAN,
        scalar: *const EC_SCALAR,
    ) -> libc::c_int;
    fn EC_group_p224() -> *const EC_GROUP;
    fn EC_group_p256() -> *const EC_GROUP;
    fn EC_group_p384() -> *const EC_GROUP;
    fn EC_group_p521() -> *const EC_GROUP;
    fn EC_group_secp256k1() -> *const EC_GROUP;
    fn EC_GROUP_cmp(
        a: *const EC_GROUP,
        b: *const EC_GROUP,
        ignored: *mut BN_CTX,
    ) -> libc::c_int;
    fn EC_GROUP_get0_generator(group: *const EC_GROUP) -> *const EC_POINT;
    fn EC_GROUP_get0_order(group: *const EC_GROUP) -> *const BIGNUM;
    fn EC_GROUP_get_curve_GFp(
        group: *const EC_GROUP,
        out_p: *mut BIGNUM,
        out_a: *mut BIGNUM,
        out_b: *mut BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn EC_POINT_new(group: *const EC_GROUP) -> *mut EC_POINT;
    fn EC_POINT_free(point: *mut EC_POINT);
    fn EC_POINT_get_affine_coordinates_GFp(
        group: *const EC_GROUP,
        point: *const EC_POINT,
        x: *mut BIGNUM,
        y: *mut BIGNUM,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn EC_POINT_point2oct(
        group: *const EC_GROUP,
        point: *const EC_POINT,
        form: point_conversion_form_t,
        buf: *mut uint8_t,
        len: size_t,
        ctx: *mut BN_CTX,
    ) -> size_t;
    fn EC_POINT_oct2point(
        group: *const EC_GROUP,
        point: *mut EC_POINT,
        buf: *const uint8_t,
        len: size_t,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;
    fn EC_GROUP_free(group: *mut EC_GROUP);
    fn EC_KEY_new() -> *mut EC_KEY;
    fn EC_KEY_free(key: *mut EC_KEY);
    fn EC_KEY_get0_group(key: *const EC_KEY) -> *const EC_GROUP;
    fn EC_KEY_set_group(key: *mut EC_KEY, group: *const EC_GROUP) -> libc::c_int;
    fn EC_KEY_get0_private_key(key: *const EC_KEY) -> *const BIGNUM;
    fn EC_KEY_set_private_key(key: *mut EC_KEY, priv_0: *const BIGNUM) -> libc::c_int;
    fn EC_KEY_get_enc_flags(key: *const EC_KEY) -> libc::c_uint;
    fn EC_KEY_check_key(key: *const EC_KEY) -> libc::c_int;
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_clear_error();
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn CBB_finish_i2d(cbb: *mut CBB, outp: *mut *mut uint8_t) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type CBS_ASN1_TAG = uint32_t;
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
pub struct bio_method_st {
    pub type_0: libc::c_int,
    pub name: *const libc::c_char,
    pub bwrite: Option::<
        unsafe extern "C" fn(*mut BIO, *const libc::c_char, libc::c_int) -> libc::c_int,
    >,
    pub bread: Option::<
        unsafe extern "C" fn(*mut BIO, *mut libc::c_char, libc::c_int) -> libc::c_int,
    >,
    pub bputs: Option::<
        unsafe extern "C" fn(*mut BIO, *const libc::c_char) -> libc::c_int,
    >,
    pub bgets: Option::<
        unsafe extern "C" fn(*mut BIO, *mut libc::c_char, libc::c_int) -> libc::c_int,
    >,
    pub ctrl: Option::<
        unsafe extern "C" fn(
            *mut BIO,
            libc::c_int,
            libc::c_long,
            *mut libc::c_void,
        ) -> libc::c_long,
    >,
    pub create: Option::<unsafe extern "C" fn(*mut BIO) -> libc::c_int>,
    pub destroy: Option::<unsafe extern "C" fn(*mut BIO) -> libc::c_int>,
    pub callback_ctrl: Option::<
        unsafe extern "C" fn(*mut BIO, libc::c_int, bio_info_cb) -> libc::c_long,
    >,
}
pub type bio_info_cb = Option::<
    unsafe extern "C" fn(*mut BIO, libc::c_int, libc::c_int) -> libc::c_long,
>;
pub type BIO = bio_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bio_st {
    pub method: *const BIO_METHOD,
    pub ex_data: CRYPTO_EX_DATA,
    pub callback_ex: BIO_callback_fn_ex,
    pub callback: BIO_callback_fn,
    pub cb_arg: *mut libc::c_char,
    pub init: libc::c_int,
    pub shutdown: libc::c_int,
    pub flags: libc::c_int,
    pub retry_reason: libc::c_int,
    pub num: libc::c_int,
    pub references: CRYPTO_refcount_t,
    pub ptr: *mut libc::c_void,
    pub next_bio: *mut BIO,
    pub num_read: uint64_t,
    pub num_write: uint64_t,
}
pub type CRYPTO_refcount_t = uint32_t;
pub type BIO_callback_fn = Option::<
    unsafe extern "C" fn(
        *mut BIO,
        libc::c_int,
        *const libc::c_char,
        libc::c_int,
        libc::c_long,
        libc::c_long,
    ) -> libc::c_long,
>;
pub type BIO_callback_fn_ex = Option::<
    unsafe extern "C" fn(
        *mut BIO,
        libc::c_int,
        *const libc::c_char,
        size_t,
        libc::c_int,
        libc::c_long,
        libc::c_int,
        *mut size_t,
    ) -> libc::c_long,
>;
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
pub type BIO_METHOD = bio_method_st;
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
pub struct ec_key_st {
    pub group: *mut EC_GROUP,
    pub pub_key: *mut EC_POINT,
    pub priv_key: *mut EC_WRAPPED_SCALAR,
    pub enc_flag: libc::c_uint,
    pub conv_form: point_conversion_form_t,
    pub references: CRYPTO_refcount_t,
    pub eckey_method: *const EC_KEY_METHOD,
    pub ex_data: CRYPTO_EX_DATA,
}
pub type EC_KEY_METHOD = ec_key_method_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ec_key_method_st {
    pub init: Option::<unsafe extern "C" fn(*mut EC_KEY) -> libc::c_int>,
    pub finish: Option::<unsafe extern "C" fn(*mut EC_KEY) -> ()>,
    pub sign: Option::<
        unsafe extern "C" fn(
            libc::c_int,
            *const uint8_t,
            libc::c_int,
            *mut uint8_t,
            *mut libc::c_uint,
            *const BIGNUM,
            *const BIGNUM,
            *mut EC_KEY,
        ) -> libc::c_int,
    >,
    pub sign_sig: Option::<
        unsafe extern "C" fn(
            *const uint8_t,
            libc::c_int,
            *const BIGNUM,
            *const BIGNUM,
            *mut EC_KEY,
        ) -> *mut ECDSA_SIG,
    >,
    pub flags: libc::c_int,
}
pub type EC_KEY = ec_key_st;
pub type ECDSA_SIG = ecdsa_sig_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EC_WRAPPED_SCALAR {
    pub bignum: BIGNUM,
    pub scalar: EC_SCALAR,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EC_builtin_curve {
    pub nid: libc::c_int,
    pub comment: *const libc::c_char,
}
pub type ec_group_func = Option::<unsafe extern "C" fn() -> *const EC_GROUP>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct explicit_prime_curve {
    pub prime: CBS,
    pub a: CBS,
    pub b: CBS,
    pub base_x: CBS,
    pub base_y: CBS,
    pub order: CBS,
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
static mut kParametersTag: CBS_ASN1_TAG = (0x20 as libc::c_uint) << 24 as libc::c_int
    | (0x80 as libc::c_uint) << 24 as libc::c_int | 0 as libc::c_int as libc::c_uint;
static mut kPublicKeyTag: CBS_ASN1_TAG = (0x20 as libc::c_uint) << 24 as libc::c_int
    | (0x80 as libc::c_uint) << 24 as libc::c_int | 1 as libc::c_int as libc::c_uint;
static mut kAllGroups: [ec_group_func; 5] = [
    Some(EC_group_p224 as unsafe extern "C" fn() -> *const EC_GROUP),
    Some(EC_group_p256 as unsafe extern "C" fn() -> *const EC_GROUP),
    Some(EC_group_p384 as unsafe extern "C" fn() -> *const EC_GROUP),
    Some(EC_group_p521 as unsafe extern "C" fn() -> *const EC_GROUP),
    Some(EC_group_secp256k1 as unsafe extern "C" fn() -> *const EC_GROUP),
];
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_parse_private_key(
    mut cbs: *mut CBS,
    mut group: *const EC_GROUP,
) -> *mut EC_KEY {
    let mut current_block: u64;
    let mut ec_private_key: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut private_key: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut version: uint64_t = 0;
    if CBS_get_asn1(
        cbs,
        &mut ec_private_key,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || CBS_get_asn1_uint64(&mut ec_private_key, &mut version) == 0
        || version != 1 as libc::c_int as uint64_t
        || CBS_get_asn1(&mut ec_private_key, &mut private_key, 0x4 as libc::c_uint) == 0
    {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            128 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0" as *const u8
                as *const libc::c_char,
            90 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EC_KEY;
    }
    let mut ret: *mut EC_KEY = 0 as *mut EC_KEY;
    let mut priv_key: *mut BIGNUM = 0 as *mut BIGNUM;
    if CBS_peek_asn1_tag(&mut ec_private_key, kParametersTag) != 0 {
        let mut child: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        if CBS_get_asn1(&mut ec_private_key, &mut child, kParametersTag) == 0 {
            ERR_put_error(
                15 as libc::c_int,
                0 as libc::c_int,
                128 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                104 as libc::c_int as libc::c_uint,
            );
            current_block = 10176845017524339134;
        } else {
            let mut inner_group: *const EC_GROUP = EC_KEY_parse_parameters(&mut child);
            if inner_group.is_null() {
                current_block = 10176845017524339134;
            } else {
                if group.is_null() {
                    group = inner_group;
                    current_block = 13586036798005543211;
                } else if EC_GROUP_cmp(group, inner_group, 0 as *mut BN_CTX)
                    != 0 as libc::c_int
                {
                    ERR_put_error(
                        15 as libc::c_int,
                        0 as libc::c_int,
                        130 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0"
                            as *const u8 as *const libc::c_char,
                        115 as libc::c_int as libc::c_uint,
                    );
                    current_block = 10176845017524339134;
                } else {
                    current_block = 13586036798005543211;
                }
                match current_block {
                    10176845017524339134 => {}
                    _ => {
                        if CBS_len(&mut child) != 0 as libc::c_int as size_t {
                            ERR_put_error(
                                15 as libc::c_int,
                                0 as libc::c_int,
                                128 as libc::c_int,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0"
                                    as *const u8 as *const libc::c_char,
                                119 as libc::c_int as libc::c_uint,
                            );
                            current_block = 10176845017524339134;
                        } else {
                            current_block = 1054647088692577877;
                        }
                    }
                }
            }
        }
    } else {
        current_block = 1054647088692577877;
    }
    match current_block {
        1054647088692577877 => {
            if group.is_null() {
                ERR_put_error(
                    15 as libc::c_int,
                    0 as libc::c_int,
                    114 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0"
                        as *const u8 as *const libc::c_char,
                    125 as libc::c_int as libc::c_uint,
                );
            } else {
                ret = EC_KEY_new();
                if !(ret.is_null() || EC_KEY_set_group(ret, group) == 0) {
                    priv_key = BN_bin2bn(
                        CBS_data(&mut private_key),
                        CBS_len(&mut private_key),
                        0 as *mut BIGNUM,
                    );
                    (*ret).pub_key = EC_POINT_new(group);
                    if !(priv_key.is_null() || ((*ret).pub_key).is_null()
                        || EC_KEY_set_private_key(ret, priv_key) == 0)
                    {
                        if CBS_peek_asn1_tag(&mut ec_private_key, kPublicKeyTag) != 0 {
                            let mut child_0: CBS = cbs_st {
                                data: 0 as *const uint8_t,
                                len: 0,
                            };
                            let mut public_key: CBS = cbs_st {
                                data: 0 as *const uint8_t,
                                len: 0,
                            };
                            let mut padding: uint8_t = 0;
                            if CBS_get_asn1(
                                &mut ec_private_key,
                                &mut child_0,
                                kPublicKeyTag,
                            ) == 0
                                || CBS_get_asn1(
                                    &mut child_0,
                                    &mut public_key,
                                    0x3 as libc::c_uint,
                                ) == 0 || CBS_get_u8(&mut public_key, &mut padding) == 0
                                || padding as libc::c_int != 0 as libc::c_int
                                || CBS_len(&mut public_key) == 0 as libc::c_int as size_t
                                || EC_POINT_oct2point(
                                    group,
                                    (*ret).pub_key,
                                    CBS_data(&mut public_key),
                                    CBS_len(&mut public_key),
                                    0 as *mut BN_CTX,
                                ) == 0
                                || CBS_len(&mut child_0) != 0 as libc::c_int as size_t
                            {
                                ERR_put_error(
                                    15 as libc::c_int,
                                    0 as libc::c_int,
                                    128 as libc::c_int,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0"
                                        as *const u8 as *const libc::c_char,
                                    158 as libc::c_int as libc::c_uint,
                                );
                                current_block = 10176845017524339134;
                            } else {
                                (*ret)
                                    .conv_form = (*(CBS_data(&mut public_key))
                                    .offset(0 as libc::c_int as isize) as libc::c_int
                                    & !(0x1 as libc::c_int)) as point_conversion_form_t;
                                current_block = 11932355480408055363;
                            }
                        } else if ec_point_mul_scalar_base(
                            group,
                            &mut (*(*ret).pub_key).raw,
                            &mut (*(*ret).priv_key).scalar,
                        ) == 0
                        {
                            current_block = 10176845017524339134;
                        } else {
                            (*ret).enc_flag |= 0x2 as libc::c_int as libc::c_uint;
                            current_block = 11932355480408055363;
                        }
                        match current_block {
                            10176845017524339134 => {}
                            _ => {
                                if CBS_len(&mut ec_private_key)
                                    != 0 as libc::c_int as size_t
                                {
                                    ERR_put_error(
                                        15 as libc::c_int,
                                        0 as libc::c_int,
                                        128 as libc::c_int,
                                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0"
                                            as *const u8 as *const libc::c_char,
                                        178 as libc::c_int as libc::c_uint,
                                    );
                                } else if !(EC_KEY_check_key(ret) == 0) {
                                    BN_free(priv_key);
                                    return ret;
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    EC_KEY_free(ret);
    BN_free(priv_key);
    return 0 as *mut EC_KEY;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_marshal_private_key(
    mut cbb: *mut CBB,
    mut key: *const EC_KEY,
    mut enc_flags: libc::c_uint,
) -> libc::c_int {
    if key.is_null() || ((*key).group).is_null() || ((*key).priv_key).is_null() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0" as *const u8
                as *const libc::c_char,
            199 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ec_private_key: CBB = cbb_st {
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
    let mut private_key: CBB = cbb_st {
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
        &mut ec_private_key,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || CBB_add_asn1_uint64(&mut ec_private_key, 1 as libc::c_int as uint64_t) == 0
        || CBB_add_asn1(&mut ec_private_key, &mut private_key, 0x4 as libc::c_uint) == 0
        || BN_bn2cbb_padded(
            &mut private_key,
            BN_num_bytes(EC_GROUP_get0_order((*key).group)) as size_t,
            EC_KEY_get0_private_key(key),
        ) == 0
    {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            129 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0" as *const u8
                as *const libc::c_char,
            210 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if enc_flags & 0x1 as libc::c_int as libc::c_uint == 0 {
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
        if CBB_add_asn1(&mut ec_private_key, &mut child, kParametersTag) == 0
            || EC_KEY_marshal_curve_name(&mut child, (*key).group) == 0
            || CBB_flush(&mut ec_private_key) == 0
        {
            ERR_put_error(
                15 as libc::c_int,
                0 as libc::c_int,
                129 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                219 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    }
    if enc_flags & 0x2 as libc::c_int as libc::c_uint == 0 && !((*key).pub_key).is_null()
    {
        let mut child_0: CBB = cbb_st {
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
        let mut public_key: CBB = cbb_st {
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
        if CBB_add_asn1(&mut ec_private_key, &mut child_0, kPublicKeyTag) == 0
            || CBB_add_asn1(&mut child_0, &mut public_key, 0x3 as libc::c_uint) == 0
            || CBB_add_u8(&mut public_key, 0 as libc::c_int as uint8_t) == 0
            || EC_POINT_point2cbb(
                &mut public_key,
                (*key).group,
                (*key).pub_key,
                (*key).conv_form,
                0 as *mut BN_CTX,
            ) == 0 || CBB_flush(&mut ec_private_key) == 0
        {
            ERR_put_error(
                15 as libc::c_int,
                0 as libc::c_int,
                129 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                235 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    }
    if CBB_flush(cbb) == 0 {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            129 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0" as *const u8
                as *const libc::c_char,
            241 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
static mut kPrimeField: [uint8_t; 7] = [
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
];
unsafe extern "C" fn parse_explicit_prime_curve(
    mut in_0: *mut CBS,
    mut out: *mut explicit_prime_curve,
) -> libc::c_int {
    let mut params: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut field_id: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut field_type: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut curve: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut base: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut cofactor: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut has_cofactor: libc::c_int = 0;
    let mut version: uint64_t = 0;
    if CBS_get_asn1(
        in_0,
        &mut params,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || CBS_get_asn1_uint64(&mut params, &mut version) == 0
        || version != 1 as libc::c_int as uint64_t
        || CBS_get_asn1(
            &mut params,
            &mut field_id,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0 || CBS_get_asn1(&mut field_id, &mut field_type, 0x6 as libc::c_uint) == 0
        || CBS_len(&mut field_type)
            != ::core::mem::size_of::<[uint8_t; 7]>() as libc::c_ulong
        || OPENSSL_memcmp(
            CBS_data(&mut field_type) as *const libc::c_void,
            kPrimeField.as_ptr() as *const libc::c_void,
            ::core::mem::size_of::<[uint8_t; 7]>() as libc::c_ulong,
        ) != 0 as libc::c_int
        || CBS_get_asn1(&mut field_id, &mut (*out).prime, 0x2 as libc::c_uint) == 0
        || CBS_is_unsigned_asn1_integer(&mut (*out).prime) == 0
        || CBS_len(&mut field_id) != 0 as libc::c_int as size_t
        || CBS_get_asn1(
            &mut params,
            &mut curve,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0 || CBS_get_asn1(&mut curve, &mut (*out).a, 0x4 as libc::c_uint) == 0
        || CBS_get_asn1(&mut curve, &mut (*out).b, 0x4 as libc::c_uint) == 0
        || CBS_get_optional_asn1(
            &mut curve,
            0 as *mut CBS,
            0 as *mut libc::c_int,
            0x3 as libc::c_uint,
        ) == 0 || CBS_len(&mut curve) != 0 as libc::c_int as size_t
        || CBS_get_asn1(&mut params, &mut base, 0x4 as libc::c_uint) == 0
        || CBS_get_asn1(&mut params, &mut (*out).order, 0x2 as libc::c_uint) == 0
        || CBS_is_unsigned_asn1_integer(&mut (*out).order) == 0
        || CBS_get_optional_asn1(
            &mut params,
            &mut cofactor,
            &mut has_cofactor,
            0x2 as libc::c_uint,
        ) == 0 || CBS_len(&mut params) != 0 as libc::c_int as size_t
    {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            128 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0" as *const u8
                as *const libc::c_char,
            283 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if has_cofactor != 0 {
        if CBS_len(&mut cofactor) != 1 as libc::c_int as size_t
            || *(CBS_data(&mut cofactor)).offset(0 as libc::c_int as isize)
                as libc::c_int != 1 as libc::c_int
        {
            ERR_put_error(
                15 as libc::c_int,
                0 as libc::c_int,
                123 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                290 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    }
    let mut form: uint8_t = 0;
    if CBS_get_u8(&mut base, &mut form) == 0
        || form as libc::c_int != POINT_CONVERSION_UNCOMPRESSED as libc::c_int
    {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            111 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0" as *const u8
                as *const libc::c_char,
            298 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if CBS_len(&mut base) % 2 as libc::c_int as size_t != 0 as libc::c_int as size_t {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            128 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0" as *const u8
                as *const libc::c_char,
            303 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut field_len: size_t = CBS_len(&mut base) / 2 as libc::c_int as size_t;
    CBS_init(&mut (*out).base_x, CBS_data(&mut base), field_len);
    CBS_init(
        &mut (*out).base_y,
        (CBS_data(&mut base)).offset(field_len as isize),
        field_len,
    );
    return 1 as libc::c_int;
}
unsafe extern "C" fn integers_equal(
    mut bytes: *const CBS,
    mut bn: *const BIGNUM,
) -> libc::c_int {
    let mut copy: CBS = *bytes;
    while CBS_len(&mut copy) > 0 as libc::c_int as size_t
        && *(CBS_data(&mut copy)).offset(0 as libc::c_int as isize) as libc::c_int
            == 0 as libc::c_int
    {
        CBS_skip(&mut copy, 1 as libc::c_int as size_t);
    }
    if CBS_len(&mut copy) > 66 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    let mut buf: [uint8_t; 66] = [0; 66];
    if BN_bn2bin_padded(buf.as_mut_ptr(), CBS_len(&mut copy), bn) == 0 {
        ERR_clear_error();
        return 0 as libc::c_int;
    }
    return CBS_mem_equal(&mut copy, buf.as_mut_ptr(), CBS_len(&mut copy));
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_parse_curve_name(mut cbs: *mut CBS) -> *mut EC_GROUP {
    let mut named_curve: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_get_asn1(cbs, &mut named_curve, 0x6 as libc::c_uint) == 0 {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            128 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0" as *const u8
                as *const libc::c_char,
            339 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EC_GROUP;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (::core::mem::size_of::<[ec_group_func; 5]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<ec_group_func>() as libc::c_ulong)
    {
        let mut group: *const EC_GROUP = (kAllGroups[i as usize])
            .expect("non-null function pointer")();
        if CBS_mem_equal(
            &mut named_curve,
            ((*group).oid).as_ptr(),
            (*group).oid_len as size_t,
        ) != 0
        {
            return group as *mut EC_GROUP;
        }
        i = i.wrapping_add(1);
        i;
    }
    ERR_put_error(
        15 as libc::c_int,
        0 as libc::c_int,
        123 as libc::c_int,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0" as *const u8
            as *const libc::c_char,
        351 as libc::c_int as libc::c_uint,
    );
    return 0 as *mut EC_GROUP;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_marshal_curve_name(
    mut cbb: *mut CBB,
    mut group: *const EC_GROUP,
) -> libc::c_int {
    if (*group).oid_len as libc::c_int == 0 as libc::c_int {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            123 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0" as *const u8
                as *const libc::c_char,
            357 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
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
    return (CBB_add_asn1(cbb, &mut child, 0x6 as libc::c_uint) != 0
        && CBB_add_bytes(&mut child, ((*group).oid).as_ptr(), (*group).oid_len as size_t)
            != 0 && CBB_flush(cbb) != 0) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_KEY_parse_parameters(mut cbs: *mut CBS) -> *mut EC_GROUP {
    let mut current_block: u64;
    if CBS_peek_asn1_tag(
        cbs,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0
    {
        return EC_KEY_parse_curve_name(cbs);
    }
    let mut curve: explicit_prime_curve = explicit_prime_curve {
        prime: cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        },
        a: cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        },
        b: cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        },
        base_x: cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        },
        base_y: cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        },
        order: cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        },
    };
    if parse_explicit_prime_curve(cbs, &mut curve) == 0 {
        return 0 as *mut EC_GROUP;
    }
    let mut ret: *const EC_GROUP = 0 as *const EC_GROUP;
    let mut p: *mut BIGNUM = BN_new();
    let mut a: *mut BIGNUM = BN_new();
    let mut b: *mut BIGNUM = BN_new();
    let mut x: *mut BIGNUM = BN_new();
    let mut y: *mut BIGNUM = BN_new();
    if !(p.is_null() || a.is_null() || b.is_null() || x.is_null() || y.is_null()) {
        let mut i: size_t = 0 as libc::c_int as size_t;
        loop {
            if !(i
                < (::core::mem::size_of::<[ec_group_func; 5]>() as libc::c_ulong)
                    .wrapping_div(
                        ::core::mem::size_of::<ec_group_func>() as libc::c_ulong,
                    ))
            {
                current_block = 5143058163439228106;
                break;
            }
            let mut group: *const EC_GROUP = (kAllGroups[i as usize])
                .expect("non-null function pointer")();
            if integers_equal(&mut curve.order, EC_GROUP_get0_order(group)) == 0 {
                i = i.wrapping_add(1);
                i;
            } else {
                if EC_GROUP_get_curve_GFp(group, p, a, b, 0 as *mut BN_CTX) == 0 {
                    current_block = 11407075869541970367;
                    break;
                }
                if integers_equal(&mut curve.prime, p) == 0
                    || integers_equal(&mut curve.a, a) == 0
                    || integers_equal(&mut curve.b, b) == 0
                {
                    current_block = 5143058163439228106;
                    break;
                }
                if EC_POINT_get_affine_coordinates_GFp(
                    group,
                    EC_GROUP_get0_generator(group),
                    x,
                    y,
                    0 as *mut BN_CTX,
                ) == 0
                {
                    current_block = 11407075869541970367;
                    break;
                }
                if integers_equal(&mut curve.base_x, x) == 0
                    || integers_equal(&mut curve.base_y, y) == 0
                {
                    current_block = 5143058163439228106;
                    break;
                }
                ret = group;
                current_block = 5143058163439228106;
                break;
            }
        }
        match current_block {
            11407075869541970367 => {}
            _ => {
                if ret.is_null() {
                    ERR_put_error(
                        15 as libc::c_int,
                        0 as libc::c_int,
                        123 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0"
                            as *const u8 as *const libc::c_char,
                        416 as libc::c_int as libc::c_uint,
                    );
                }
            }
        }
    }
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    return ret as *mut EC_GROUP;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_POINT_point2cbb(
    mut out: *mut CBB,
    mut group: *const EC_GROUP,
    mut point: *const EC_POINT,
    mut form: point_conversion_form_t,
    mut ctx: *mut BN_CTX,
) -> libc::c_int {
    let mut len: size_t = EC_POINT_point2oct(
        group,
        point,
        form,
        0 as *mut uint8_t,
        0 as libc::c_int as size_t,
        ctx,
    );
    if len == 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    let mut p: *mut uint8_t = 0 as *mut uint8_t;
    return (CBB_add_space(out, &mut p, len) != 0
        && EC_POINT_point2oct(group, point, form, p, len, ctx) == len) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ECPrivateKey(
    mut out: *mut *mut EC_KEY,
    mut inp: *mut *const uint8_t,
    mut len: libc::c_long,
) -> *mut EC_KEY {
    let mut group: *const EC_GROUP = 0 as *const EC_GROUP;
    if !out.is_null() && !(*out).is_null() {
        group = EC_KEY_get0_group(*out);
    }
    if len < 0 as libc::c_int as libc::c_long {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            128 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0" as *const u8
                as *const libc::c_char,
            448 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EC_KEY;
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, *inp, len as size_t);
    let mut ret: *mut EC_KEY = EC_KEY_parse_private_key(&mut cbs, group);
    if ret.is_null() {
        return 0 as *mut EC_KEY;
    }
    if !out.is_null() {
        EC_KEY_free(*out);
        *out = ret;
    }
    *inp = CBS_data(&mut cbs);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ECPrivateKey(
    mut key: *const EC_KEY,
    mut outp: *mut *mut uint8_t,
) -> libc::c_int {
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
    if CBB_init(&mut cbb, 0 as libc::c_int as size_t) == 0
        || EC_KEY_marshal_private_key(&mut cbb, key, EC_KEY_get_enc_flags(key)) == 0
    {
        CBB_cleanup(&mut cbb);
        return -(1 as libc::c_int);
    }
    return CBB_finish_i2d(&mut cbb, outp);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ECParameters(
    mut out_key: *mut *mut EC_KEY,
    mut inp: *mut *const uint8_t,
    mut len: libc::c_long,
) -> *mut EC_KEY {
    if len < 0 as libc::c_int as libc::c_long {
        return 0 as *mut EC_KEY;
    }
    let mut group: *mut EC_GROUP = d2i_ECPKParameters(0 as *mut *mut EC_GROUP, inp, len);
    if group.is_null() {
        return 0 as *mut EC_KEY;
    }
    let mut ret: *mut EC_KEY = EC_KEY_new();
    if ret.is_null() || EC_KEY_set_group(ret, group) == 0 {
        EC_KEY_free(ret);
        return 0 as *mut EC_KEY;
    }
    if !out_key.is_null() {
        EC_KEY_free(*out_key);
        *out_key = ret;
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ECPKParameters(
    mut out_group: *mut *mut EC_GROUP,
    mut inp: *mut *const uint8_t,
    mut len: libc::c_long,
) -> *mut EC_GROUP {
    if inp.is_null() || len < 0 as libc::c_int as libc::c_long {
        return 0 as *mut EC_GROUP;
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, *inp, len as size_t);
    let mut group: *mut EC_GROUP = EC_KEY_parse_parameters(&mut cbs);
    if group.is_null() {
        return 0 as *mut EC_GROUP;
    }
    if !out_group.is_null() {
        EC_GROUP_free(*out_group);
        *out_group = group;
    }
    *inp = CBS_data(&mut cbs);
    return group;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ECParameters(
    mut key: *const EC_KEY,
    mut outp: *mut *mut uint8_t,
) -> libc::c_int {
    if key.is_null() || ((*key).group).is_null() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0" as *const u8
                as *const libc::c_char,
            521 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    return i2d_ECPKParameters((*key).group, outp);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ECPKParameters(
    mut group: *const EC_GROUP,
    mut outp: *mut *mut uint8_t,
) -> libc::c_int {
    if group.is_null() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0" as *const u8
                as *const libc::c_char,
            530 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
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
    if CBB_init(&mut cbb, 0 as libc::c_int as size_t) == 0
        || EC_KEY_marshal_curve_name(&mut cbb, group) == 0
    {
        CBB_cleanup(&mut cbb);
        return -(1 as libc::c_int);
    }
    return CBB_finish_i2d(&mut cbb, outp);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ECPKParameters_bio(
    mut bio: *mut BIO,
    mut out_group: *mut *mut EC_GROUP,
) -> *mut EC_GROUP {
    if bio.is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0" as *const u8
                as *const libc::c_char,
            544 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EC_GROUP;
    }
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: size_t = 0;
    if BIO_read_asn1(bio, &mut data, &mut len, 2147483647 as libc::c_int as size_t) == 0
    {
        return 0 as *mut EC_GROUP;
    }
    let mut ptr: *const uint8_t = data;
    let mut ret: *mut EC_GROUP = d2i_ECPKParameters(
        out_group,
        &mut ptr,
        len as libc::c_long,
    );
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ECPKParameters_bio(
    mut bio: *mut BIO,
    mut group: *const EC_GROUP,
) -> libc::c_int {
    if bio.is_null() || group.is_null() {
        ERR_put_error(
            18 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0" as *const u8
                as *const libc::c_char,
            561 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut out: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: libc::c_int = i2d_ECPKParameters(group, &mut out);
    if out.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = BIO_write_all(
        bio,
        out as *const libc::c_void,
        len as size_t,
    );
    OPENSSL_free(out as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn o2i_ECPublicKey(
    mut keyp: *mut *mut EC_KEY,
    mut inp: *mut *const uint8_t,
    mut len: libc::c_long,
) -> *mut EC_KEY {
    let mut ret: *mut EC_KEY = 0 as *mut EC_KEY;
    if keyp.is_null() || (*keyp).is_null() || ((**keyp).group).is_null() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0" as *const u8
                as *const libc::c_char,
            580 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EC_KEY;
    }
    ret = *keyp;
    if ((*ret).pub_key).is_null()
        && {
            (*ret).pub_key = EC_POINT_new((*ret).group);
            ((*ret).pub_key).is_null()
        }
    {
        return 0 as *mut EC_KEY;
    }
    if EC_POINT_oct2point(
        (*ret).group,
        (*ret).pub_key,
        *inp,
        len as size_t,
        0 as *mut BN_CTX,
    ) == 0
    {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            15 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0" as *const u8
                as *const libc::c_char,
            589 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EC_KEY;
    }
    (*ret)
        .conv_form = (**inp.offset(0 as libc::c_int as isize) as libc::c_int
        & !(0x1 as libc::c_int)) as point_conversion_form_t;
    *inp = (*inp).offset(len as isize);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2o_ECPublicKey(
    mut key: *const EC_KEY,
    mut outp: *mut *mut uint8_t,
) -> libc::c_int {
    if key.is_null() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0" as *const u8
                as *const libc::c_char,
            600 as libc::c_int as libc::c_uint,
        );
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
    if CBB_init(&mut cbb, 0 as libc::c_int as size_t) == 0
        || EC_POINT_point2cbb(
            &mut cbb,
            (*key).group,
            (*key).pub_key,
            (*key).conv_form,
            0 as *mut BN_CTX,
        ) == 0
    {
        CBB_cleanup(&mut cbb);
        return -(1 as libc::c_int);
    }
    let mut ret: libc::c_int = CBB_finish_i2d(&mut cbb, outp);
    return if ret > 0 as libc::c_int { ret } else { 0 as libc::c_int };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_get_builtin_curves(
    mut out_curves: *mut EC_builtin_curve,
    mut max_num_curves: size_t,
) -> size_t {
    if max_num_curves
        > (::core::mem::size_of::<[ec_group_func; 5]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<ec_group_func>() as libc::c_ulong)
    {
        max_num_curves = (::core::mem::size_of::<[ec_group_func; 5]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<ec_group_func>() as libc::c_ulong);
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < max_num_curves {
        let mut group: *const EC_GROUP = (kAllGroups[i as usize])
            .expect("non-null function pointer")();
        (*out_curves.offset(i as isize)).nid = (*group).curve_name;
        let ref mut fresh0 = (*out_curves.offset(i as isize)).comment;
        *fresh0 = (*group).comment;
        i = i.wrapping_add(1);
        i;
    }
    return (::core::mem::size_of::<[ec_group_func; 5]>() as libc::c_ulong)
        .wrapping_div(::core::mem::size_of::<ec_group_func>() as libc::c_ulong);
}
unsafe extern "C" fn EC_POINT_point2buf(
    mut group: *const EC_GROUP,
    mut point: *const EC_POINT,
    mut form: point_conversion_form_t,
    mut pbuf: *mut *mut uint8_t,
    mut ctx: *mut BN_CTX,
) -> size_t {
    let mut len: size_t = 0;
    let mut buf: *mut uint8_t = 0 as *mut uint8_t;
    len = EC_POINT_point2oct(
        group,
        point,
        form,
        0 as *mut uint8_t,
        0 as libc::c_int as size_t,
        0 as *mut BN_CTX,
    );
    if len == 0 as libc::c_int as size_t {
        return 0 as libc::c_int as size_t;
    }
    buf = OPENSSL_malloc(len) as *mut uint8_t;
    if buf.is_null() {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            1 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0" as *const u8
                as *const libc::c_char,
            640 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int as size_t;
    }
    len = EC_POINT_point2oct(group, point, form, buf, len, ctx);
    if len == 0 as libc::c_int as size_t {
        OPENSSL_free(buf as *mut libc::c_void);
        return 0 as libc::c_int as size_t;
    }
    *pbuf = buf;
    return len;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_POINT_point2bn(
    mut group: *const EC_GROUP,
    mut point: *const EC_POINT,
    mut form: point_conversion_form_t,
    mut ret: *mut BIGNUM,
    mut ctx: *mut BN_CTX,
) -> *mut BIGNUM {
    let mut buf_len: size_t = 0 as libc::c_int as size_t;
    let mut buf: *mut uint8_t = 0 as *mut uint8_t;
    buf_len = EC_POINT_point2buf(group, point, form, &mut buf, ctx);
    if buf_len == 0 as libc::c_int as size_t {
        return 0 as *mut BIGNUM;
    }
    ret = BN_bin2bn(buf, buf_len, ret);
    OPENSSL_free(buf as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EC_POINT_bn2point(
    mut group: *const EC_GROUP,
    mut bn: *const BIGNUM,
    mut point: *mut EC_POINT,
    mut ctx: *mut BN_CTX,
) -> *mut EC_POINT {
    if group.is_null() || bn.is_null() {
        ERR_put_error(
            15 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ec_extra/ec_asn1.c\0" as *const u8
                as *const libc::c_char,
            674 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EC_POINT;
    }
    let mut buf_len: size_t = BN_num_bytes(bn) as size_t;
    if buf_len == 0 as libc::c_int as size_t {
        buf_len = 1 as libc::c_int as size_t;
    }
    let mut buf: *mut uint8_t = OPENSSL_malloc(buf_len) as *mut uint8_t;
    if buf.is_null() {
        return 0 as *mut EC_POINT;
    }
    if BN_bn2bin_padded(buf, buf_len, bn) < 0 as libc::c_int {
        OPENSSL_free(buf as *mut libc::c_void);
        return 0 as *mut EC_POINT;
    }
    let mut ret: *mut EC_POINT = 0 as *mut EC_POINT;
    if !point.is_null() {
        ret = point;
    } else {
        ret = EC_POINT_new(group);
        if ret.is_null() {
            OPENSSL_free(buf as *mut libc::c_void);
            return 0 as *mut EC_POINT;
        }
    }
    if EC_POINT_oct2point(group, ret, buf, buf_len, ctx) == 0 {
        if ret != point {
            EC_POINT_free(ret);
            ret = 0 as *mut EC_POINT;
        }
    }
    OPENSSL_free(buf as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ECPKParameters_print(
    mut bio: *mut BIO,
    mut group: *const EC_GROUP,
    mut offset: libc::c_int,
) -> libc::c_int {
    return 1 as libc::c_int;
}
