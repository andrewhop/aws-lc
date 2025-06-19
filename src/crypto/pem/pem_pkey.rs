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
    pub type evp_cipher_st;
    pub type pqdsa_key_st;
    pub type kem_key_st;
    pub type ec_key_st;
    pub type dh_st;
    pub type dsa_st;
    pub type rsa_st;
    pub type X509_sig_st;
    pub type stack_st_void;
    pub type pkcs8_priv_key_info_st;
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn PKCS8_PRIV_KEY_INFO_free(key: *mut PKCS8_PRIV_KEY_INFO);
    fn d2i_PKCS8_PRIV_KEY_INFO(
        out: *mut *mut PKCS8_PRIV_KEY_INFO,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut PKCS8_PRIV_KEY_INFO;
    fn EVP_PKCS82PKEY(p8: *const PKCS8_PRIV_KEY_INFO) -> *mut EVP_PKEY;
    fn X509_SIG_free(key: *mut X509_SIG);
    fn d2i_X509_SIG(
        out: *mut *mut X509_SIG,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut X509_SIG;
    fn DSA_free(dsa: *mut DSA);
    fn d2i_DSAparams(
        out: *mut *mut DSA,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut DSA;
    fn i2d_DSAparams(in_0: *const DSA, outp: *mut *mut uint8_t) -> libc::c_int;
    fn BIO_free(bio: *mut BIO) -> libc::c_int;
    fn BIO_new_fp(stream: *mut FILE, close_flag: libc::c_int) -> *mut BIO;
    fn EVP_PKEY_new() -> *mut EVP_PKEY;
    fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
    fn EVP_PKEY_assign_DSA(pkey: *mut EVP_PKEY, key: *mut DSA) -> libc::c_int;
    fn EVP_PKEY_assign_EC_KEY(pkey: *mut EVP_PKEY, key: *mut EC_KEY) -> libc::c_int;
    fn EVP_PKEY_assign_DH(pkey: *mut EVP_PKEY, key: *mut DH) -> libc::c_int;
    fn i2d_PrivateKey(key: *const EVP_PKEY, outp: *mut *mut uint8_t) -> libc::c_int;
    fn d2i_PrivateKey(
        type_0: libc::c_int,
        out: *mut *mut EVP_PKEY,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut EVP_PKEY;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn BIO_snprintf(
        buf: *mut libc::c_char,
        n: size_t,
        format: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn DH_free(dh: *mut DH);
    fn d2i_DHparams(
        ret: *mut *mut DH,
        inp: *mut *const libc::c_uchar,
        len: libc::c_long,
    ) -> *mut DH;
    fn i2d_DHparams(in_0: *const DH, outp: *mut *mut libc::c_uchar) -> libc::c_int;
    fn EC_KEY_free(key: *mut EC_KEY);
    fn d2i_ECParameters(
        out_key: *mut *mut EC_KEY,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut EC_KEY;
    fn i2d_ECParameters(key: *const EC_KEY, outp: *mut *mut uint8_t) -> libc::c_int;
    fn PEM_bytes_read_bio(
        pdata: *mut *mut libc::c_uchar,
        plen: *mut libc::c_long,
        pnm: *mut *mut libc::c_char,
        name: *const libc::c_char,
        bp: *mut BIO,
        cb: Option::<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> libc::c_int;
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
    fn PEM_def_callback(
        buf: *mut libc::c_char,
        size: libc::c_int,
        rwflag: libc::c_int,
        userdata: *mut libc::c_void,
    ) -> libc::c_int;
    fn PEM_write_bio_PKCS8PrivateKey(
        bp: *mut BIO,
        x: *const EVP_PKEY,
        enc: *const EVP_CIPHER,
        pass: *const libc::c_char,
        pass_len: libc::c_int,
        cb: Option::<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> libc::c_int;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn PKCS8_decrypt(
        pkcs8: *mut X509_SIG,
        pass: *const libc::c_char,
        pass_len: libc::c_int,
    ) -> *mut PKCS8_PRIV_KEY_INFO;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type EVP_CIPHER = evp_cipher_st;
pub type EVP_PKEY = evp_pkey_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_pkey_st {
    pub references: CRYPTO_refcount_t,
    pub type_0: libc::c_int,
    pub pkey: C2RustUnnamed_0,
    pub ameth: *const EVP_PKEY_ASN1_METHOD,
}
pub type EVP_PKEY_ASN1_METHOD = evp_pkey_asn1_method_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_pkey_asn1_method_st {
    pub pkey_id: libc::c_int,
    pub oid: [uint8_t; 11],
    pub oid_len: uint8_t,
    pub pem_str: *const libc::c_char,
    pub info: *const libc::c_char,
    pub pub_decode: Option::<
        unsafe extern "C" fn(*mut EVP_PKEY, *mut CBS, *mut CBS, *mut CBS) -> libc::c_int,
    >,
    pub pub_encode: Option::<
        unsafe extern "C" fn(*mut CBB, *const EVP_PKEY) -> libc::c_int,
    >,
    pub pub_cmp: Option::<
        unsafe extern "C" fn(*const EVP_PKEY, *const EVP_PKEY) -> libc::c_int,
    >,
    pub priv_decode: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY,
            *mut CBS,
            *mut CBS,
            *mut CBS,
            *mut CBS,
        ) -> libc::c_int,
    >,
    pub priv_encode: Option::<
        unsafe extern "C" fn(*mut CBB, *const EVP_PKEY) -> libc::c_int,
    >,
    pub priv_encode_v2: Option::<
        unsafe extern "C" fn(*mut CBB, *const EVP_PKEY) -> libc::c_int,
    >,
    pub set_priv_raw: Option::<
        unsafe extern "C" fn(
            *mut EVP_PKEY,
            *const uint8_t,
            size_t,
            *const uint8_t,
            size_t,
        ) -> libc::c_int,
    >,
    pub set_pub_raw: Option::<
        unsafe extern "C" fn(*mut EVP_PKEY, *const uint8_t, size_t) -> libc::c_int,
    >,
    pub get_priv_raw: Option::<
        unsafe extern "C" fn(*const EVP_PKEY, *mut uint8_t, *mut size_t) -> libc::c_int,
    >,
    pub get_pub_raw: Option::<
        unsafe extern "C" fn(*const EVP_PKEY, *mut uint8_t, *mut size_t) -> libc::c_int,
    >,
    pub pkey_opaque: Option::<unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int>,
    pub pkey_size: Option::<unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int>,
    pub pkey_bits: Option::<unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int>,
    pub param_missing: Option::<unsafe extern "C" fn(*const EVP_PKEY) -> libc::c_int>,
    pub param_copy: Option::<
        unsafe extern "C" fn(*mut EVP_PKEY, *const EVP_PKEY) -> libc::c_int,
    >,
    pub param_cmp: Option::<
        unsafe extern "C" fn(*const EVP_PKEY, *const EVP_PKEY) -> libc::c_int,
    >,
    pub pkey_free: Option::<unsafe extern "C" fn(*mut EVP_PKEY) -> ()>,
}
pub type CBB = cbb_st;
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
pub type CBS = cbs_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cbs_st {
    pub data: *const uint8_t,
    pub len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub ptr: *mut libc::c_void,
    pub rsa: *mut RSA,
    pub dsa: *mut DSA,
    pub dh: *mut DH,
    pub ec: *mut EC_KEY,
    pub kem_key: *mut KEM_KEY,
    pub pqdsa_key: *mut PQDSA_KEY,
}
pub type PQDSA_KEY = pqdsa_key_st;
pub type KEM_KEY = kem_key_st;
pub type EC_KEY = ec_key_st;
pub type DH = dh_st;
pub type DSA = dsa_st;
pub type RSA = rsa_st;
pub type CRYPTO_refcount_t = uint32_t;
pub type X509_SIG = X509_sig_st;
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
pub type PKCS8_PRIV_KEY_INFO = pkcs8_priv_key_info_st;
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
pub unsafe extern "C" fn PEM_read_bio_PrivateKey(
    mut bp: *mut BIO,
    mut x: *mut *mut EVP_PKEY,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut EVP_PKEY {
    let mut current_block: u64;
    let mut nm: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut data: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut len: libc::c_long = 0;
    let mut ret: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
    if PEM_bytes_read_bio(
        &mut data,
        &mut len,
        &mut nm,
        b"ANY PRIVATE KEY\0" as *const u8 as *const libc::c_char,
        bp,
        cb,
        u,
    ) == 0
    {
        return 0 as *mut EVP_PKEY;
    }
    p = data;
    if strcmp(nm, b"PRIVATE KEY\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        let mut p8inf: *mut PKCS8_PRIV_KEY_INFO = 0 as *mut PKCS8_PRIV_KEY_INFO;
        p8inf = d2i_PKCS8_PRIV_KEY_INFO(0 as *mut *mut PKCS8_PRIV_KEY_INFO, &mut p, len);
        if p8inf.is_null() {
            current_block = 4396629313764523416;
        } else {
            ret = EVP_PKCS82PKEY(p8inf);
            if !x.is_null() {
                if !(*x).is_null() {
                    EVP_PKEY_free(*x);
                }
                *x = ret;
            }
            PKCS8_PRIV_KEY_INFO_free(p8inf);
            current_block = 4396629313764523416;
        }
    } else if strcmp(nm, b"ENCRYPTED PRIVATE KEY\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        let mut p8inf_0: *mut PKCS8_PRIV_KEY_INFO = 0 as *mut PKCS8_PRIV_KEY_INFO;
        let mut p8: *mut X509_SIG = 0 as *mut X509_SIG;
        let mut psbuf: [libc::c_char; 1024] = [0; 1024];
        p8 = d2i_X509_SIG(0 as *mut *mut X509_SIG, &mut p, len);
        if p8.is_null() {
            current_block = 4396629313764523416;
        } else {
            if cb.is_none() {
                cb = Some(
                    PEM_def_callback
                        as unsafe extern "C" fn(
                            *mut libc::c_char,
                            libc::c_int,
                            libc::c_int,
                            *mut libc::c_void,
                        ) -> libc::c_int,
                );
            }
            let mut pass_len: libc::c_int = cb
                .expect(
                    "non-null function pointer",
                )(psbuf.as_mut_ptr(), 1024 as libc::c_int, 0 as libc::c_int, u);
            if pass_len <= 0 as libc::c_int {
                ERR_put_error(
                    9 as libc::c_int,
                    0 as libc::c_int,
                    104 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_pkey.c\0"
                        as *const u8 as *const libc::c_char,
                    113 as libc::c_int as libc::c_uint,
                );
                X509_SIG_free(p8);
                current_block = 18000731688880254241;
            } else {
                p8inf_0 = PKCS8_decrypt(p8, psbuf.as_mut_ptr(), pass_len);
                X509_SIG_free(p8);
                OPENSSL_cleanse(
                    psbuf.as_mut_ptr() as *mut libc::c_void,
                    pass_len as size_t,
                );
                if p8inf_0.is_null() {
                    current_block = 4396629313764523416;
                } else {
                    ret = EVP_PKCS82PKEY(p8inf_0);
                    if !x.is_null() {
                        if !(*x).is_null() {
                            EVP_PKEY_free(*x);
                        }
                        *x = ret;
                    }
                    PKCS8_PRIV_KEY_INFO_free(p8inf_0);
                    current_block = 4396629313764523416;
                }
            }
        }
    } else {
        if strcmp(nm, b"RSA PRIVATE KEY\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            ret = d2i_PrivateKey(6 as libc::c_int, x, &mut p, len);
        } else if strcmp(nm, b"EC PRIVATE KEY\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            ret = d2i_PrivateKey(408 as libc::c_int, x, &mut p, len);
        } else if strcmp(nm, b"DSA PRIVATE KEY\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            ret = d2i_PrivateKey(116 as libc::c_int, x, &mut p, len);
        }
        current_block = 4396629313764523416;
    }
    match current_block {
        4396629313764523416 => {
            if ret.is_null() {
                ERR_put_error(
                    9 as libc::c_int,
                    0 as libc::c_int,
                    12 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_pkey.c\0"
                        as *const u8 as *const libc::c_char,
                    143 as libc::c_int as libc::c_uint,
                );
            }
        }
        _ => {}
    }
    OPENSSL_free(nm as *mut libc::c_void);
    OPENSSL_free(data as *mut libc::c_void);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_PrivateKey(
    mut bp: *mut BIO,
    mut x: *mut EVP_PKEY,
    mut enc: *const EVP_CIPHER,
    mut pass: *const libc::c_uchar,
    mut pass_len: libc::c_int,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> libc::c_int {
    return PEM_write_bio_PKCS8PrivateKey(
        bp,
        x,
        enc,
        pass as *const libc::c_char,
        pass_len,
        cb,
        u,
    );
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_Parameters(
    mut bio: *mut BIO,
    mut pkey: *mut *mut EVP_PKEY,
) -> *mut EVP_PKEY {
    let mut current_block: u64;
    if bio.is_null() {
        ERR_put_error(
            9 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_pkey.c\0" as *const u8
                as *const libc::c_char,
            161 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EVP_PKEY;
    }
    let mut nm: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut data: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut len: libc::c_long = 0;
    if PEM_bytes_read_bio(
        &mut data,
        &mut len,
        &mut nm,
        b"PARAMETERS\0" as *const u8 as *const libc::c_char,
        bio,
        None,
        0 as *mut libc::c_void,
    ) == 0
    {
        return 0 as *mut EVP_PKEY;
    }
    let mut data_const: *const libc::c_uchar = data;
    let mut ret: *mut EVP_PKEY = EVP_PKEY_new();
    if !ret.is_null() {
        if strcmp(nm, b"EC PARAMETERS\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            let mut ec_key: *mut EC_KEY = d2i_ECParameters(
                0 as *mut *mut EC_KEY,
                &mut data_const,
                len,
            );
            if ec_key.is_null() || EVP_PKEY_assign_EC_KEY(ret, ec_key) == 0 {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    15 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_pkey.c\0"
                        as *const u8 as *const libc::c_char,
                    184 as libc::c_int as libc::c_uint,
                );
                EC_KEY_free(ec_key);
                current_block = 11035617586221967994;
            } else {
                current_block = 11042950489265723346;
            }
        } else if strcmp(nm, b"DSA PARAMETERS\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            let mut dsa: *mut DSA = d2i_DSAparams(
                0 as *mut *mut DSA,
                &mut data_const,
                len,
            );
            if dsa.is_null() || EVP_PKEY_assign_DSA(ret, dsa) == 0 {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    10 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_pkey.c\0"
                        as *const u8 as *const libc::c_char,
                    191 as libc::c_int as libc::c_uint,
                );
                DSA_free(dsa);
                current_block = 11035617586221967994;
            } else {
                current_block = 11042950489265723346;
            }
        } else if strcmp(nm, b"DH PARAMETERS\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            let mut dh: *mut DH = d2i_DHparams(0 as *mut *mut DH, &mut data_const, len);
            if dh.is_null() || EVP_PKEY_assign_DH(ret, dh) == 0 {
                ERR_put_error(
                    6 as libc::c_int,
                    0 as libc::c_int,
                    5 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_pkey.c\0"
                        as *const u8 as *const libc::c_char,
                    198 as libc::c_int as libc::c_uint,
                );
                DH_free(dh);
                current_block = 11035617586221967994;
            } else {
                current_block = 11042950489265723346;
            }
        } else {
            current_block = 11035617586221967994;
        }
        match current_block {
            11035617586221967994 => {}
            _ => {
                if !pkey.is_null() {
                    EVP_PKEY_free(*pkey);
                    *pkey = ret;
                }
                OPENSSL_free(nm as *mut libc::c_void);
                OPENSSL_free(data as *mut libc::c_void);
                return ret;
            }
        }
    }
    EVP_PKEY_free(ret);
    OPENSSL_free(nm as *mut libc::c_void);
    OPENSSL_free(data as *mut libc::c_void);
    return 0 as *mut EVP_PKEY;
}
unsafe extern "C" fn i2d_ECParameters_void(
    mut key: *const libc::c_void,
    mut out: *mut *mut uint8_t,
) -> libc::c_int {
    return i2d_ECParameters(key as *mut EC_KEY, out);
}
unsafe extern "C" fn i2d_DSAparams_void(
    mut key: *const libc::c_void,
    mut out: *mut *mut uint8_t,
) -> libc::c_int {
    return i2d_DSAparams(key as *mut DSA, out);
}
unsafe extern "C" fn i2d_DHparams_void(
    mut key: *const libc::c_void,
    mut out: *mut *mut uint8_t,
) -> libc::c_int {
    return i2d_DHparams(key as *mut DH, out);
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_Parameters(
    mut bio: *mut BIO,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    if bio.is_null() || pkey.is_null() {
        ERR_put_error(
            9 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_pkey.c\0" as *const u8
                as *const libc::c_char,
            236 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut pem_str: [libc::c_char; 80] = [0; 80];
    match (*pkey).type_0 {
        408 => {
            BIO_snprintf(
                pem_str.as_mut_ptr(),
                80 as libc::c_int as size_t,
                b"EC PARAMETERS\0" as *const u8 as *const libc::c_char,
            );
            return PEM_ASN1_write_bio(
                Some(
                    i2d_ECParameters_void
                        as unsafe extern "C" fn(
                            *const libc::c_void,
                            *mut *mut uint8_t,
                        ) -> libc::c_int,
                ),
                pem_str.as_mut_ptr(),
                bio,
                (*pkey).pkey.ec as *mut libc::c_void,
                0 as *const EVP_CIPHER,
                0 as *const libc::c_uchar,
                0 as libc::c_int,
                None,
                0 as *mut libc::c_void,
            );
        }
        116 => {
            BIO_snprintf(
                pem_str.as_mut_ptr(),
                80 as libc::c_int as size_t,
                b"DSA PARAMETERS\0" as *const u8 as *const libc::c_char,
            );
            return PEM_ASN1_write_bio(
                Some(
                    i2d_DSAparams_void
                        as unsafe extern "C" fn(
                            *const libc::c_void,
                            *mut *mut uint8_t,
                        ) -> libc::c_int,
                ),
                pem_str.as_mut_ptr(),
                bio,
                (*pkey).pkey.dsa as *mut libc::c_void,
                0 as *const EVP_CIPHER,
                0 as *const libc::c_uchar,
                0 as libc::c_int,
                None,
                0 as *mut libc::c_void,
            );
        }
        28 => {
            BIO_snprintf(
                pem_str.as_mut_ptr(),
                80 as libc::c_int as size_t,
                b"DH PARAMETERS\0" as *const u8 as *const libc::c_char,
            );
            return PEM_ASN1_write_bio(
                Some(
                    i2d_DHparams_void
                        as unsafe extern "C" fn(
                            *const libc::c_void,
                            *mut *mut uint8_t,
                        ) -> libc::c_int,
                ),
                pem_str.as_mut_ptr(),
                bio,
                (*pkey).pkey.dh as *mut libc::c_void,
                0 as *const EVP_CIPHER,
                0 as *const libc::c_uchar,
                0 as libc::c_int,
                None,
                0 as *mut libc::c_void,
            );
        }
        _ => return 0 as libc::c_int,
    };
}
unsafe extern "C" fn i2d_PrivateKey_void(
    mut key: *const libc::c_void,
    mut out: *mut *mut uint8_t,
) -> libc::c_int {
    return i2d_PrivateKey(key as *const EVP_PKEY, out);
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_PrivateKey_traditional(
    mut bp: *mut BIO,
    mut x: *mut EVP_PKEY,
    mut enc: *const EVP_CIPHER,
    mut kstr: *mut libc::c_uchar,
    mut klen: libc::c_int,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> libc::c_int {
    if bp.is_null() || x.is_null() || ((*x).ameth).is_null()
        || ((*(*x).ameth).pem_str).is_null()
    {
        ERR_put_error(
            9 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_pkey.c\0" as *const u8
                as *const libc::c_char,
            272 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut pem_str: [libc::c_char; 80] = [0; 80];
    BIO_snprintf(
        pem_str.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 80]>() as libc::c_ulong,
        b"%s PRIVATE KEY\0" as *const u8 as *const libc::c_char,
        (*(*x).ameth).pem_str,
    );
    return PEM_ASN1_write_bio(
        Some(
            i2d_PrivateKey_void
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *mut *mut uint8_t,
                ) -> libc::c_int,
        ),
        pem_str.as_mut_ptr(),
        bp,
        x as *mut libc::c_void,
        enc,
        kstr,
        klen,
        cb,
        u,
    );
}
#[no_mangle]
pub unsafe extern "C" fn PEM_read_PrivateKey(
    mut fp: *mut FILE,
    mut x: *mut *mut EVP_PKEY,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> *mut EVP_PKEY {
    let mut b: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if b.is_null() {
        ERR_put_error(
            9 as libc::c_int,
            0 as libc::c_int,
            7 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_pkey.c\0" as *const u8
                as *const libc::c_char,
            285 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EVP_PKEY;
    }
    let mut ret: *mut EVP_PKEY = PEM_read_bio_PrivateKey(b, x, cb, u);
    BIO_free(b);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn PEM_write_PrivateKey(
    mut fp: *mut FILE,
    mut x: *mut EVP_PKEY,
    mut enc: *const EVP_CIPHER,
    mut pass: *const libc::c_uchar,
    mut pass_len: libc::c_int,
    mut cb: Option::<pem_password_cb>,
    mut u: *mut libc::c_void,
) -> libc::c_int {
    let mut b: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if b.is_null() {
        ERR_put_error(
            9 as libc::c_int,
            0 as libc::c_int,
            7 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pem/pem_pkey.c\0" as *const u8
                as *const libc::c_char,
            298 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = PEM_write_bio_PrivateKey(
        b,
        x,
        enc,
        pass,
        pass_len,
        cb,
        u,
    );
    BIO_free(b);
    return ret;
}
