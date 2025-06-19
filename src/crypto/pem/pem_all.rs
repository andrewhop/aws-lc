#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(extern_types)]
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type asn1_object_st;
    pub type X509_crl_st;
    pub type evp_cipher_st;
    pub type evp_pkey_st;
    pub type X509_req_st;
    pub type stack_st_void;
    pub type dh_st;
    pub type dsa_st;
    pub type pkcs7_digest_st;
    pub type pkcs7_enc_content_st;
    pub type pkcs7_encrypt_st;
    pub type stack_st_PKCS7_RECIP_INFO;
    pub type stack_st_PKCS7_SIGNER_INFO;
    pub type stack_st_X509_CRL;
    pub type stack_st_X509;
    pub type stack_st_X509_ALGOR;
    pub type rsa_st;
    fn d2i_X509_CRL(
        out: *mut *mut X509_CRL,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut X509_CRL;
    fn i2d_X509_CRL(crl: *mut X509_CRL, outp: *mut *mut uint8_t) -> libc::c_int;
    fn d2i_X509_REQ(
        out: *mut *mut X509_REQ,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut X509_REQ;
    fn i2d_X509_REQ(req: *mut X509_REQ, outp: *mut *mut uint8_t) -> libc::c_int;
    fn DSA_free(dsa: *mut DSA);
    fn i2d_DSAPrivateKey(in_0: *const DSA, outp: *mut *mut uint8_t) -> libc::c_int;
    fn d2i_DSAparams(
        out: *mut *mut DSA,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut DSA;
    fn i2d_DSAparams(in_0: *const DSA, outp: *mut *mut uint8_t) -> libc::c_int;
    fn d2i_ECPKParameters(
        out_group: *mut *mut EC_GROUP,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut EC_GROUP;
    fn i2d_ECPKParameters(
        group: *const EC_GROUP,
        outp: *mut *mut uint8_t,
    ) -> libc::c_int;
    fn d2i_PKCS7(
        a: *mut *mut PKCS7,
        in_0: *mut *const libc::c_uchar,
        len: libc::c_long,
    ) -> *mut PKCS7;
    fn i2d_PKCS7(a: *mut PKCS7, out: *mut *mut libc::c_uchar) -> libc::c_int;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn d2i_DHparams(
        ret: *mut *mut DH,
        inp: *mut *const libc::c_uchar,
        len: libc::c_long,
    ) -> *mut DH;
    fn i2d_DHparams(in_0: *const DH, outp: *mut *mut libc::c_uchar) -> libc::c_int;
    fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
    fn EVP_PKEY_get1_RSA(pkey: *const EVP_PKEY) -> *mut RSA;
    fn EVP_PKEY_get1_DSA(pkey: *const EVP_PKEY) -> *mut DSA;
    fn EVP_PKEY_get1_EC_KEY(pkey: *const EVP_PKEY) -> *mut EC_KEY;
    fn i2d_PUBKEY(pkey: *const EVP_PKEY, outp: *mut *mut uint8_t) -> libc::c_int;
    fn d2i_PUBKEY(
        out: *mut *mut EVP_PKEY,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut EVP_PKEY;
    fn i2d_RSA_PUBKEY(rsa: *const RSA, outp: *mut *mut uint8_t) -> libc::c_int;
    fn d2i_RSA_PUBKEY(
        out: *mut *mut RSA,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut RSA;
    fn i2d_DSA_PUBKEY(dsa: *const DSA, outp: *mut *mut uint8_t) -> libc::c_int;
    fn d2i_DSA_PUBKEY(
        out: *mut *mut DSA,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut DSA;
    fn i2d_EC_PUBKEY(ec_key: *const EC_KEY, outp: *mut *mut uint8_t) -> libc::c_int;
    fn d2i_EC_PUBKEY(
        out: *mut *mut EC_KEY,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut EC_KEY;
    fn EC_KEY_free(key: *mut EC_KEY);
    fn i2d_ECPrivateKey(key: *const EC_KEY, outp: *mut *mut uint8_t) -> libc::c_int;
    fn RSA_free(rsa: *mut RSA);
    fn d2i_RSAPublicKey(
        out: *mut *mut RSA,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut RSA;
    fn i2d_RSAPublicKey(in_0: *const RSA, outp: *mut *mut uint8_t) -> libc::c_int;
    fn i2d_RSAPrivateKey(in_0: *const RSA, outp: *mut *mut uint8_t) -> libc::c_int;
    fn PEM_write_bio(
        bp: *mut BIO,
        name: *const libc::c_char,
        hdr: *const libc::c_char,
        data: *const libc::c_uchar,
        len: libc::c_long,
    ) -> libc::c_int;
    fn PEM_bytes_read_bio(
        pdata: *mut *mut libc::c_uchar,
        plen: *mut libc::c_long,
        pnm: *mut *mut libc::c_char,
        name: *const libc::c_char,
        bp: *mut BIO,
        cb: Option::<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> libc::c_int;
    fn PEM_ASN1_read_bio(
        d2i: Option::<d2i_of_void>,
        name: *const libc::c_char,
        bp: *mut BIO,
        x: *mut *mut libc::c_void,
        cb: Option::<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> *mut libc::c_void;
    fn PEM_ASN1_write_bio(
        i2d: Option::<i2d_of_void>,
        name: *const libc::c_char,
        bp: *mut BIO,
        x: *mut libc::c_void,
        enc: *const EVP_CIPHER,
        pass: *const libc::c_uchar,
        pass_len: libc::c_int,
        cb: Option::<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> libc::c_int;
    fn PEM_ASN1_read(
        d2i: Option::<d2i_of_void>,
        name: *const libc::c_char,
        fp: *mut FILE,
        x: *mut *mut libc::c_void,
        cb: Option::<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> *mut libc::c_void;
    fn PEM_ASN1_write(
        i2d: Option::<i2d_of_void>,
        name: *const libc::c_char,
        fp: *mut FILE,
        x: *mut libc::c_void,
        enc: *const EVP_CIPHER,
        pass: *const libc::c_uchar,
        pass_len: libc::c_int,
        callback: Option::<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> libc::c_int;
    fn PEM_read_PrivateKey(
        fp: *mut FILE,
        x: *mut *mut EVP_PKEY,
        cb: Option::<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> *mut EVP_PKEY;
    fn PEM_read_bio_PrivateKey(
        bp: *mut BIO,
        x: *mut *mut EVP_PKEY,
        cb: Option::<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> *mut EVP_PKEY;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type ASN1_OBJECT = asn1_object_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_string_st {
    pub length: libc::c_int,
    pub type_0: libc::c_int,
    pub data: *mut libc::c_uchar,
    pub flags: libc::c_long,
}
pub type ASN1_INTEGER = asn1_string_st;
pub type ASN1_OCTET_STRING = asn1_string_st;
pub type BIGNUM = bignum_st;
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
pub type X509_CRL = X509_crl_st;
pub type EVP_CIPHER = evp_cipher_st;
pub type EVP_PKEY = evp_pkey_st;
pub type X509_REQ = X509_req_st;
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
pub type DH = dh_st;
pub type DSA = dsa_st;
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
pub struct ecdsa_sig_st {
    pub r: *mut BIGNUM,
    pub s: *mut BIGNUM,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EC_WRAPPED_SCALAR {
    pub bignum: BIGNUM,
    pub scalar: EC_SCALAR,
}
pub type PKCS7_DIGEST = pkcs7_digest_st;
pub type PKCS7_ENC_CONTENT = pkcs7_enc_content_st;
pub type PKCS7_ENCRYPT = pkcs7_encrypt_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pkcs7_envelope_st {
    pub version: *mut ASN1_INTEGER,
    pub enc_data: *mut PKCS7_ENC_CONTENT,
    pub recipientinfo: *mut stack_st_PKCS7_RECIP_INFO,
}
pub type PKCS7_ENVELOPE = pkcs7_envelope_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pkcs7_sign_envelope_st {
    pub version: *mut ASN1_INTEGER,
    pub recipientinfo: *mut stack_st_PKCS7_RECIP_INFO,
    pub md_algs: *mut stack_st_X509_ALGOR,
    pub enc_data: *mut PKCS7_ENC_CONTENT,
    pub cert: *mut stack_st_X509,
    pub crl: *mut stack_st_X509_CRL,
    pub signer_info: *mut stack_st_PKCS7_SIGNER_INFO,
}
pub type PKCS7_SIGN_ENVELOPE = pkcs7_sign_envelope_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pkcs7_signed_st {
    pub version: *mut ASN1_INTEGER,
    pub md_algs: *mut stack_st_X509_ALGOR,
    pub contents: *mut PKCS7,
    pub cert: *mut stack_st_X509,
    pub crl: *mut stack_st_X509_CRL,
    pub signer_info: *mut stack_st_PKCS7_SIGNER_INFO,
}
pub type PKCS7 = pkcs7_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pkcs7_st {
    pub type_0: *mut ASN1_OBJECT,
    pub d: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub ptr: *mut libc::c_char,
    pub data: *mut ASN1_OCTET_STRING,
    pub sign: *mut PKCS7_SIGNED,
    pub enveloped: *mut PKCS7_ENVELOPE,
    pub signed_and_enveloped: *mut PKCS7_SIGN_ENVELOPE,
    pub digest: *mut PKCS7_DIGEST,
    pub encrypted: *mut PKCS7_ENCRYPT,
}
pub type PKCS7_SIGNED = pkcs7_signed_st;
pub type RSA = rsa_st;
pub type d2i_of_void = unsafe extern "C" fn(
    *mut *mut libc::c_void,
    *mut *const libc::c_uchar,
    libc::c_long,
) -> *mut libc::c_void;
pub type i2d_of_void = unsafe extern "C" fn(
    *const libc::c_void,
    *mut *mut libc::c_uchar,
) -> libc::c_int;
pub type pem_password_cb = unsafe extern "C" fn(
    *mut libc::c_char,
    libc::c_int,
    libc::c_int,
    *mut libc::c_void,
) -> libc::c_int;
#[no_mangle]
pub unsafe extern "C" fn PEM_read_X509_REQ(
    mut fp: *mut FILE,
    mut x: *mut *mut X509_REQ,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut X509_REQ {
    return PEM_ASN1_read(
        Some(
            pem_read_X509_REQ_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"CERTIFICATE REQUEST\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut X509_REQ;
}
unsafe extern "C" fn pem_write_X509_REQ_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_X509_REQ(x as *mut X509_REQ, outp);
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_X509_REQ(
    mut bp: *mut BIO,
    mut x: *mut *mut X509_REQ,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut X509_REQ {
    return PEM_ASN1_read_bio(
        Some(
            pem_read_bio_X509_REQ_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"CERTIFICATE REQUEST\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut X509_REQ;
}
unsafe extern "C" fn pem_write_bio_X509_REQ_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_X509_REQ(x as *mut X509_REQ, outp);
}
unsafe extern "C" fn pem_read_X509_REQ_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_X509_REQ(x as *mut *mut X509_REQ, inp, len) as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_X509_REQ(
    mut bp: *mut BIO,
    mut x: *mut X509_REQ,
) -> libc::c_int {
    return PEM_ASN1_write_bio(
        Some(
            pem_write_bio_X509_REQ_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"CERTIFICATE REQUEST\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
unsafe extern "C" fn pem_read_bio_X509_REQ_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_X509_REQ(x as *mut *mut X509_REQ, inp, len) as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_X509_REQ(
    mut fp: *mut FILE,
    mut x: *mut X509_REQ,
) -> libc::c_int {
    return PEM_ASN1_write(
        Some(
            pem_write_X509_REQ_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"CERTIFICATE REQUEST\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_X509_REQ_NEW(
    mut fp: *mut FILE,
    mut x: *mut X509_REQ,
) -> libc::c_int {
    return PEM_ASN1_write(
        Some(
            pem_write_X509_REQ_NEW_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"NEW CERTIFICATE REQUEST\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
unsafe extern "C" fn pem_write_X509_REQ_NEW_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_X509_REQ(x as *mut X509_REQ, outp);
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_X509_REQ_NEW(
    mut bp: *mut BIO,
    mut x: *mut X509_REQ,
) -> libc::c_int {
    return PEM_ASN1_write_bio(
        Some(
            pem_write_bio_X509_REQ_NEW_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"NEW CERTIFICATE REQUEST\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
unsafe extern "C" fn pem_write_bio_X509_REQ_NEW_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_X509_REQ(x as *mut X509_REQ, outp);
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_X509_CRL(
    mut bp: *mut BIO,
    mut x: *mut *mut X509_CRL,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut X509_CRL {
    return PEM_ASN1_read_bio(
        Some(
            pem_read_bio_X509_CRL_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"X509 CRL\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut X509_CRL;
}
unsafe extern "C" fn pem_read_bio_X509_CRL_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_X509_CRL(x as *mut *mut X509_CRL, inp, len) as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_X509_CRL(
    mut bp: *mut BIO,
    mut x: *mut X509_CRL,
) -> libc::c_int {
    return PEM_ASN1_write_bio(
        Some(
            pem_write_bio_X509_CRL_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"X509 CRL\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_X509_CRL(
    mut fp: *mut FILE,
    mut x: *mut *mut X509_CRL,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut X509_CRL {
    return PEM_ASN1_read(
        Some(
            pem_read_X509_CRL_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"X509 CRL\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut X509_CRL;
}
unsafe extern "C" fn pem_read_X509_CRL_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_X509_CRL(x as *mut *mut X509_CRL, inp, len) as *mut libc::c_void;
}
unsafe extern "C" fn pem_write_bio_X509_CRL_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_X509_CRL(x as *mut X509_CRL, outp);
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_X509_CRL(
    mut fp: *mut FILE,
    mut x: *mut X509_CRL,
) -> libc::c_int {
    return PEM_ASN1_write(
        Some(
            pem_write_X509_CRL_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"X509 CRL\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
unsafe extern "C" fn pem_write_X509_CRL_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_X509_CRL(x as *mut X509_CRL, outp);
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_PKCS7(
    mut bp: *mut BIO,
    mut x: *mut *mut PKCS7,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut PKCS7 {
    return PEM_ASN1_read_bio(
        Some(
            pem_read_bio_PKCS7_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"PKCS7\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut PKCS7;
}
unsafe extern "C" fn pem_read_bio_PKCS7_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_PKCS7(x as *mut *mut PKCS7, inp, len) as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_PKCS7(
    mut fp: *mut FILE,
    mut x: *mut *mut PKCS7,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut PKCS7 {
    return PEM_ASN1_read(
        Some(
            pem_read_PKCS7_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"PKCS7\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut PKCS7;
}
unsafe extern "C" fn pem_read_PKCS7_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_PKCS7(x as *mut *mut PKCS7, inp, len) as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_PKCS7(
    mut bp: *mut BIO,
    mut x: *mut PKCS7,
) -> libc::c_int {
    return PEM_ASN1_write_bio(
        Some(
            pem_write_bio_PKCS7_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"PKCS7\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_PKCS7(
    mut fp: *mut FILE,
    mut x: *mut PKCS7,
) -> libc::c_int {
    return PEM_ASN1_write(
        Some(
            pem_write_PKCS7_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"PKCS7\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
unsafe extern "C" fn pem_write_bio_PKCS7_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_PKCS7(x as *mut PKCS7, outp);
}
unsafe extern "C" fn pem_write_PKCS7_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_PKCS7(x as *mut PKCS7, outp);
}
unsafe extern "C" fn pkey_get_rsa(
    mut key: *mut EVP_PKEY,
    mut rsa: *mut *mut RSA,
) -> *mut RSA {
    let mut rtmp: *mut RSA = 0 as *mut RSA;
    if key.is_null() {
        return 0 as *mut RSA;
    }
    rtmp = EVP_PKEY_get1_RSA(key);
    EVP_PKEY_free(key);
    if rtmp.is_null() {
        return 0 as *mut RSA;
    }
    if !rsa.is_null() {
        RSA_free(*rsa);
        *rsa = rtmp;
    }
    return rtmp;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_RSAPrivateKey(
    mut bp: *mut BIO,
    mut rsa: *mut *mut RSA,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut RSA {
    let mut pktmp: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
    pktmp = PEM_read_bio_PrivateKey(bp, 0 as *mut *mut EVP_PKEY, cb, u);
    return pkey_get_rsa(pktmp, rsa);
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_RSAPrivateKey(
    mut fp: *mut FILE,
    mut rsa: *mut *mut RSA,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut RSA {
    let mut pktmp: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
    pktmp = PEM_read_PrivateKey(fp, 0 as *mut *mut EVP_PKEY, cb, u);
    return pkey_get_rsa(pktmp, rsa);
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_RSAPrivateKey(
    mut fp: *mut FILE,
    mut x: *mut RSA,
    mut enc: *const EVP_CIPHER,
    mut pass: *const libc::c_uchar,
    mut pass_len: libc::c_int,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> libc::c_int {
    return PEM_ASN1_write(
        Some(
            pem_write_RSAPrivateKey_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"RSA PRIVATE KEY\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut libc::c_void,
        enc,
        pass,
        pass_len,
        cb,
        u,
    );
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_RSAPrivateKey(
    mut bp: *mut BIO,
    mut x: *mut RSA,
    mut enc: *const EVP_CIPHER,
    mut pass: *const libc::c_uchar,
    mut pass_len: libc::c_int,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> libc::c_int {
    return PEM_ASN1_write_bio(
        Some(
            pem_write_bio_RSAPrivateKey_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"RSA PRIVATE KEY\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut libc::c_void,
        enc,
        pass,
        pass_len,
        cb,
        u,
    );
}
unsafe extern "C" fn pem_write_RSAPrivateKey_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_RSAPrivateKey(x as *const RSA, outp);
}
unsafe extern "C" fn pem_write_bio_RSAPrivateKey_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_RSAPrivateKey(x as *const RSA, outp);
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_RSAPublicKey(
    mut bp: *mut BIO,
    mut x: *mut *mut RSA,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut RSA {
    return PEM_ASN1_read_bio(
        Some(
            pem_read_bio_RSAPublicKey_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"RSA PUBLIC KEY\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut RSA;
}
unsafe extern "C" fn pem_read_bio_RSAPublicKey_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_RSAPublicKey(x as *mut *mut RSA, inp, len) as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_RSAPublicKey(
    mut fp: *mut FILE,
    mut x: *mut *mut RSA,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut RSA {
    return PEM_ASN1_read(
        Some(
            pem_read_RSAPublicKey_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"RSA PUBLIC KEY\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut RSA;
}
unsafe extern "C" fn pem_read_RSAPublicKey_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_RSAPublicKey(x as *mut *mut RSA, inp, len) as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_RSAPublicKey(
    mut bp: *mut BIO,
    mut x: *const RSA,
) -> libc::c_int {
    return PEM_ASN1_write_bio(
        Some(
            pem_write_bio_RSAPublicKey_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"RSA PUBLIC KEY\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
unsafe extern "C" fn pem_write_bio_RSAPublicKey_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_RSAPublicKey(x as *const RSA, outp);
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_RSAPublicKey(
    mut fp: *mut FILE,
    mut x: *const RSA,
) -> libc::c_int {
    return PEM_ASN1_write(
        Some(
            pem_write_RSAPublicKey_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"RSA PUBLIC KEY\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
unsafe extern "C" fn pem_write_RSAPublicKey_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_RSAPublicKey(x as *const RSA, outp);
}
unsafe extern "C" fn pem_write_bio_RSA_PUBKEY_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_RSA_PUBKEY(x as *mut RSA, outp);
}
unsafe extern "C" fn pem_read_bio_RSA_PUBKEY_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_RSA_PUBKEY(x as *mut *mut RSA, inp, len) as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_RSA_PUBKEY(
    mut fp: *mut FILE,
    mut x: *mut *mut RSA,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut RSA {
    return PEM_ASN1_read(
        Some(
            pem_read_RSA_PUBKEY_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"PUBLIC KEY\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut RSA;
}
unsafe extern "C" fn pem_read_RSA_PUBKEY_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_RSA_PUBKEY(x as *mut *mut RSA, inp, len) as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_RSA_PUBKEY(
    mut bp: *mut BIO,
    mut x: *mut RSA,
) -> libc::c_int {
    return PEM_ASN1_write_bio(
        Some(
            pem_write_bio_RSA_PUBKEY_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"PUBLIC KEY\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_RSA_PUBKEY(
    mut bp: *mut BIO,
    mut x: *mut *mut RSA,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut RSA {
    return PEM_ASN1_read_bio(
        Some(
            pem_read_bio_RSA_PUBKEY_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"PUBLIC KEY\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut RSA;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_RSA_PUBKEY(
    mut fp: *mut FILE,
    mut x: *mut RSA,
) -> libc::c_int {
    return PEM_ASN1_write(
        Some(
            pem_write_RSA_PUBKEY_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"PUBLIC KEY\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
unsafe extern "C" fn pem_write_RSA_PUBKEY_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_RSA_PUBKEY(x as *mut RSA, outp);
}
unsafe extern "C" fn pkey_get_dsa(
    mut key: *mut EVP_PKEY,
    mut dsa: *mut *mut DSA,
) -> *mut DSA {
    let mut dtmp: *mut DSA = 0 as *mut DSA;
    if key.is_null() {
        return 0 as *mut DSA;
    }
    dtmp = EVP_PKEY_get1_DSA(key);
    EVP_PKEY_free(key);
    if dtmp.is_null() {
        return 0 as *mut DSA;
    }
    if !dsa.is_null() {
        DSA_free(*dsa);
        *dsa = dtmp;
    }
    return dtmp;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_DSAPrivateKey(
    mut bp: *mut BIO,
    mut dsa: *mut *mut DSA,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut DSA {
    let mut pktmp: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
    pktmp = PEM_read_bio_PrivateKey(bp, 0 as *mut *mut EVP_PKEY, cb, u);
    return pkey_get_dsa(pktmp, dsa);
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_DSAPrivateKey(
    mut bp: *mut BIO,
    mut x: *mut DSA,
    mut enc: *const EVP_CIPHER,
    mut pass: *const libc::c_uchar,
    mut pass_len: libc::c_int,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> libc::c_int {
    return PEM_ASN1_write_bio(
        Some(
            pem_write_bio_DSAPrivateKey_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"DSA PRIVATE KEY\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut libc::c_void,
        enc,
        pass,
        pass_len,
        cb,
        u,
    );
}
unsafe extern "C" fn pem_write_bio_DSAPrivateKey_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_DSAPrivateKey(x as *const DSA, outp);
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_DSAPrivateKey(
    mut fp: *mut FILE,
    mut x: *mut DSA,
    mut enc: *const EVP_CIPHER,
    mut pass: *const libc::c_uchar,
    mut pass_len: libc::c_int,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> libc::c_int {
    return PEM_ASN1_write(
        Some(
            pem_write_DSAPrivateKey_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"DSA PRIVATE KEY\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut libc::c_void,
        enc,
        pass,
        pass_len,
        cb,
        u,
    );
}
unsafe extern "C" fn pem_write_DSAPrivateKey_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_DSAPrivateKey(x as *const DSA, outp);
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_DSA_PUBKEY(
    mut bp: *mut BIO,
    mut x: *mut *mut DSA,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut DSA {
    return PEM_ASN1_read_bio(
        Some(
            pem_read_bio_DSA_PUBKEY_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"PUBLIC KEY\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut DSA;
}
unsafe extern "C" fn pem_read_bio_DSA_PUBKEY_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_DSA_PUBKEY(x as *mut *mut DSA, inp, len) as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_DSA_PUBKEY(
    mut fp: *mut FILE,
    mut x: *mut *mut DSA,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut DSA {
    return PEM_ASN1_read(
        Some(
            pem_read_DSA_PUBKEY_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"PUBLIC KEY\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut DSA;
}
unsafe extern "C" fn pem_read_DSA_PUBKEY_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_DSA_PUBKEY(x as *mut *mut DSA, inp, len) as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_DSA_PUBKEY(
    mut bp: *mut BIO,
    mut x: *mut DSA,
) -> libc::c_int {
    return PEM_ASN1_write_bio(
        Some(
            pem_write_bio_DSA_PUBKEY_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"PUBLIC KEY\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
unsafe extern "C" fn pem_write_bio_DSA_PUBKEY_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_DSA_PUBKEY(x as *mut DSA, outp);
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_DSA_PUBKEY(
    mut fp: *mut FILE,
    mut x: *mut DSA,
) -> libc::c_int {
    return PEM_ASN1_write(
        Some(
            pem_write_DSA_PUBKEY_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"PUBLIC KEY\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
unsafe extern "C" fn pem_write_DSA_PUBKEY_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_DSA_PUBKEY(x as *mut DSA, outp);
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_DSAPrivateKey(
    mut fp: *mut FILE,
    mut dsa: *mut *mut DSA,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut DSA {
    let mut pktmp: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
    pktmp = PEM_read_PrivateKey(fp, 0 as *mut *mut EVP_PKEY, cb, u);
    return pkey_get_dsa(pktmp, dsa);
}
unsafe extern "C" fn pem_read_DSAparams_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_DSAparams(x as *mut *mut DSA, inp, len) as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_DSAparams(
    mut bp: *mut BIO,
    mut x: *const DSA,
) -> libc::c_int {
    return PEM_ASN1_write_bio(
        Some(
            pem_write_bio_DSAparams_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"DSA PARAMETERS\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_DSAparams(
    mut bp: *mut BIO,
    mut x: *mut *mut DSA,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut DSA {
    return PEM_ASN1_read_bio(
        Some(
            pem_read_bio_DSAparams_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"DSA PARAMETERS\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut DSA;
}
unsafe extern "C" fn pem_read_bio_DSAparams_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_DSAparams(x as *mut *mut DSA, inp, len) as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_DSAparams(
    mut fp: *mut FILE,
    mut x: *mut *mut DSA,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut DSA {
    return PEM_ASN1_read(
        Some(
            pem_read_DSAparams_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"DSA PARAMETERS\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut DSA;
}
unsafe extern "C" fn pem_write_bio_DSAparams_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_DSAparams(x as *const DSA, outp);
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_DSAparams(
    mut fp: *mut FILE,
    mut x: *const DSA,
) -> libc::c_int {
    return PEM_ASN1_write(
        Some(
            pem_write_DSAparams_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"DSA PARAMETERS\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
unsafe extern "C" fn pem_write_DSAparams_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_DSAparams(x as *const DSA, outp);
}
unsafe extern "C" fn pkey_get_eckey(
    mut key: *mut EVP_PKEY,
    mut eckey: *mut *mut EC_KEY,
) -> *mut EC_KEY {
    let mut dtmp: *mut EC_KEY = 0 as *mut EC_KEY;
    if key.is_null() {
        return 0 as *mut EC_KEY;
    }
    dtmp = EVP_PKEY_get1_EC_KEY(key);
    EVP_PKEY_free(key);
    if dtmp.is_null() {
        return 0 as *mut EC_KEY;
    }
    if !eckey.is_null() {
        EC_KEY_free(*eckey);
        *eckey = dtmp;
    }
    return dtmp;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_ECPrivateKey(
    mut bp: *mut BIO,
    mut key: *mut *mut EC_KEY,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut EC_KEY {
    let mut pktmp: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
    pktmp = PEM_read_bio_PrivateKey(bp, 0 as *mut *mut EVP_PKEY, cb, u);
    return pkey_get_eckey(pktmp, key);
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_ECPrivateKey(
    mut fp: *mut FILE,
    mut x: *mut EC_KEY,
    mut enc: *const EVP_CIPHER,
    mut pass: *const libc::c_uchar,
    mut pass_len: libc::c_int,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> libc::c_int {
    return PEM_ASN1_write(
        Some(
            pem_write_ECPrivateKey_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"EC PRIVATE KEY\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut libc::c_void,
        enc,
        pass,
        pass_len,
        cb,
        u,
    );
}
unsafe extern "C" fn pem_write_ECPrivateKey_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_ECPrivateKey(x as *mut EC_KEY, outp);
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_ECPrivateKey(
    mut bp: *mut BIO,
    mut x: *mut EC_KEY,
    mut enc: *const EVP_CIPHER,
    mut pass: *const libc::c_uchar,
    mut pass_len: libc::c_int,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> libc::c_int {
    return PEM_ASN1_write_bio(
        Some(
            pem_write_bio_ECPrivateKey_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"EC PRIVATE KEY\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut libc::c_void,
        enc,
        pass,
        pass_len,
        cb,
        u,
    );
}
unsafe extern "C" fn pem_write_bio_ECPrivateKey_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_ECPrivateKey(x as *mut EC_KEY, outp);
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_EC_PUBKEY(
    mut fp: *mut FILE,
    mut x: *mut EC_KEY,
) -> libc::c_int {
    return PEM_ASN1_write(
        Some(
            pem_write_EC_PUBKEY_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"PUBLIC KEY\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_EC_PUBKEY(
    mut bp: *mut BIO,
    mut x: *mut EC_KEY,
) -> libc::c_int {
    return PEM_ASN1_write_bio(
        Some(
            pem_write_bio_EC_PUBKEY_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"PUBLIC KEY\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_EC_PUBKEY(
    mut bp: *mut BIO,
    mut x: *mut *mut EC_KEY,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut EC_KEY {
    return PEM_ASN1_read_bio(
        Some(
            pem_read_bio_EC_PUBKEY_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"PUBLIC KEY\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut EC_KEY;
}
unsafe extern "C" fn pem_read_EC_PUBKEY_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_EC_PUBKEY(x as *mut *mut EC_KEY, inp, len) as *mut libc::c_void;
}
unsafe extern "C" fn pem_write_EC_PUBKEY_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_EC_PUBKEY(x as *mut EC_KEY, outp);
}
unsafe extern "C" fn pem_write_bio_EC_PUBKEY_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_EC_PUBKEY(x as *mut EC_KEY, outp);
}
unsafe extern "C" fn pem_read_bio_EC_PUBKEY_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_EC_PUBKEY(x as *mut *mut EC_KEY, inp, len) as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_EC_PUBKEY(
    mut fp: *mut FILE,
    mut x: *mut *mut EC_KEY,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut EC_KEY {
    return PEM_ASN1_read(
        Some(
            pem_read_EC_PUBKEY_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"PUBLIC KEY\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut EC_KEY;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_ECPrivateKey(
    mut fp: *mut FILE,
    mut eckey: *mut *mut EC_KEY,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut EC_KEY {
    let mut pktmp: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
    pktmp = PEM_read_PrivateKey(fp, 0 as *mut *mut EVP_PKEY, cb, u);
    return pkey_get_eckey(pktmp, eckey);
}
unsafe extern "C" fn pem_read_bio_DHparams_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_DHparams(x as *mut *mut DH, inp, len) as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_DHparams(
    mut fp: *mut FILE,
    mut x: *mut *mut DH,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut DH {
    return PEM_ASN1_read(
        Some(
            pem_read_DHparams_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"DH PARAMETERS\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut DH;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_DHparams(
    mut bp: *mut BIO,
    mut x: *const DH,
) -> libc::c_int {
    return PEM_ASN1_write_bio(
        Some(
            pem_write_bio_DHparams_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"DH PARAMETERS\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_DHparams(
    mut bp: *mut BIO,
    mut x: *mut *mut DH,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut DH {
    return PEM_ASN1_read_bio(
        Some(
            pem_read_bio_DHparams_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"DH PARAMETERS\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut DH;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_DHparams(
    mut fp: *mut FILE,
    mut x: *const DH,
) -> libc::c_int {
    return PEM_ASN1_write(
        Some(
            pem_write_DHparams_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"DH PARAMETERS\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
unsafe extern "C" fn pem_write_bio_DHparams_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_DHparams(x as *const DH, outp);
}
unsafe extern "C" fn pem_write_DHparams_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_DHparams(x as *const DH, outp);
}
unsafe extern "C" fn pem_read_DHparams_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_DHparams(x as *mut *mut DH, inp, len) as *mut libc::c_void;
}
unsafe extern "C" fn pem_write_PUBKEY_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_PUBKEY(x as *mut EVP_PKEY, outp);
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_PUBKEY(
    mut fp: *mut FILE,
    mut x: *mut EVP_PKEY,
) -> libc::c_int {
    return PEM_ASN1_write(
        Some(
            pem_write_PUBKEY_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"PUBLIC KEY\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
unsafe extern "C" fn pem_read_PUBKEY_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_PUBKEY(x as *mut *mut EVP_PKEY, inp, len) as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_PUBKEY(
    mut fp: *mut FILE,
    mut x: *mut *mut EVP_PKEY,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut EVP_PKEY {
    return PEM_ASN1_read(
        Some(
            pem_read_PUBKEY_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"PUBLIC KEY\0" as *const u8 as *const libc::c_char,
        fp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut EVP_PKEY;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_PUBKEY(
    mut bp: *mut BIO,
    mut x: *mut *mut EVP_PKEY,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut EVP_PKEY {
    return PEM_ASN1_read_bio(
        Some(
            pem_read_bio_PUBKEY_d2i
                as unsafe extern "C" fn(
                    *mut *mut libc::c_void,
                    *mut *const libc::c_uchar,
                    libc::c_long,
                ) -> *mut libc::c_void,
        ),
        b"PUBLIC KEY\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut *mut libc::c_void,
        cb,
        u,
    ) as *mut EVP_PKEY;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_PUBKEY(
    mut bp: *mut BIO,
    mut x: *mut EVP_PKEY,
) -> libc::c_int {
    return PEM_ASN1_write_bio(
        Some(
            pem_write_bio_PUBKEY_i2d
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut libc::c_uchar,
                ) -> libc::c_int,
        ),
        b"PUBLIC KEY\0" as *const u8 as *const libc::c_char,
        bp,
        x as *mut libc::c_void,
        0 as *const EVP_CIPHER,
        0 as *const libc::c_uchar,
        0 as libc::c_int,
        None,
        0 as *mut libc::c_void,
    );
}
unsafe extern "C" fn pem_read_bio_PUBKEY_d2i(
    mut x: *mut *mut libc::c_void,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut libc::c_void {
    return d2i_PUBKEY(x as *mut *mut EVP_PKEY, inp, len) as *mut libc::c_void;
}
unsafe extern "C" fn pem_write_bio_PUBKEY_i2d(
    mut x: *const libc::c_void,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_PUBKEY(x as *mut EVP_PKEY, outp);
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_ECPKParameters(
    mut bio: *mut BIO,
    mut out_group: *mut *mut EC_GROUP,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut EC_GROUP {
    let mut data: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: libc::c_long = 0;
    if PEM_bytes_read_bio(
        &mut data,
        &mut len,
        0 as *mut *mut libc::c_char,
        b"EC PARAMETERS\0" as *const u8 as *const libc::c_char,
        bio,
        cb,
        u,
    ) == 0
    {
        return 0 as *mut EC_GROUP;
    }
    let mut data_in: *const uint8_t = data;
    let mut ret: *mut EC_GROUP = d2i_ECPKParameters(out_group, &mut data_in, len);
    if ret.is_null() {
        ERR_put_error(
            9 as libc::c_int,
            0 as libc::c_int,
            12 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_all.c\0" as *const u8
                as *const libc::c_char,
            258 as libc::c_int as libc::c_uint,
        );
    }
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_ECPKParameters(
    mut out: *mut BIO,
    mut group: *const EC_GROUP,
) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut data: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut buf_len: libc::c_int = i2d_ECPKParameters(group, &mut data);
    if data.is_null() || buf_len < 0 as libc::c_int {
        ERR_put_error(
            9 as libc::c_int,
            0 as libc::c_int,
            12 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_all.c\0" as *const u8
                as *const libc::c_char,
            270 as libc::c_int as libc::c_uint,
        );
    } else if !(PEM_write_bio(
        out,
        b"EC PARAMETERS\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
        data,
        buf_len as libc::c_long,
    ) <= 0 as libc::c_int)
    {
        ret = 1 as libc::c_int;
    }
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
