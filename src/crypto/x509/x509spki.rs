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
    pub type asn1_pctx_st;
    pub type ASN1_VALUE_st;
    pub type evp_pkey_st;
    pub type stack_st_void;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn X509_PUBKEY_set(x: *mut *mut X509_PUBKEY, pkey: *mut EVP_PKEY) -> libc::c_int;
    fn X509_PUBKEY_get0(key: *const X509_PUBKEY) -> *mut EVP_PKEY;
    fn X509_PUBKEY_get(key: *const X509_PUBKEY) -> *mut EVP_PKEY;
    fn X509_PUBKEY_get0_param(
        out_obj: *mut *mut ASN1_OBJECT,
        out_key: *mut *const uint8_t,
        out_key_len: *mut libc::c_int,
        out_alg: *mut *mut X509_ALGOR,
        pub_0: *mut X509_PUBKEY,
    ) -> libc::c_int;
    fn d2i_NETSCAPE_SPKI(
        out: *mut *mut NETSCAPE_SPKI,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut NETSCAPE_SPKI;
    fn i2d_NETSCAPE_SPKI(
        spki: *const NETSCAPE_SPKI,
        outp: *mut *mut uint8_t,
    ) -> libc::c_int;
    fn BIO_write(
        bio: *mut BIO,
        data: *const libc::c_void,
        len: libc::c_int,
    ) -> libc::c_int;
    fn BIO_printf(bio: *mut BIO, format: *const libc::c_char, _: ...) -> libc::c_int;
    fn EVP_EncodeBlock(
        dst: *mut uint8_t,
        src: *const uint8_t,
        src_len: size_t,
    ) -> size_t;
    fn EVP_EncodedLength(out_len: *mut size_t, len: size_t) -> libc::c_int;
    fn EVP_DecodedLength(out_len: *mut size_t, len: size_t) -> libc::c_int;
    fn EVP_DecodeBase64(
        out: *mut uint8_t,
        out_len: *mut size_t,
        max_out: size_t,
        in_0: *const uint8_t,
        in_len: size_t,
    ) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OBJ_obj2nid(obj: *const ASN1_OBJECT) -> libc::c_int;
    fn OBJ_nid2ln(nid: libc::c_int) -> *const libc::c_char;
    fn EVP_PKEY_print_public(
        out: *mut BIO,
        pkey: *const EVP_PKEY,
        indent: libc::c_int,
        pctx: *mut ASN1_PCTX,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type ptrdiff_t = libc::c_long;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type ossl_ssize_t = ptrdiff_t;
pub type ASN1_BOOLEAN = libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_object_st {
    pub sn: *const libc::c_char,
    pub ln: *const libc::c_char,
    pub nid: libc::c_int,
    pub length: libc::c_int,
    pub data: *const libc::c_uchar,
    pub flags: libc::c_int,
}
pub type ASN1_OBJECT = asn1_object_st;
pub type ASN1_PCTX = asn1_pctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_string_st {
    pub length: libc::c_int,
    pub type_0: libc::c_int,
    pub data: *mut libc::c_uchar,
    pub flags: libc::c_long,
}
pub type ASN1_BIT_STRING = asn1_string_st;
pub type ASN1_BMPSTRING = asn1_string_st;
pub type ASN1_ENUMERATED = asn1_string_st;
pub type ASN1_GENERALIZEDTIME = asn1_string_st;
pub type ASN1_GENERALSTRING = asn1_string_st;
pub type ASN1_IA5STRING = asn1_string_st;
pub type ASN1_INTEGER = asn1_string_st;
pub type ASN1_OCTET_STRING = asn1_string_st;
pub type ASN1_PRINTABLESTRING = asn1_string_st;
pub type ASN1_STRING = asn1_string_st;
pub type ASN1_T61STRING = asn1_string_st;
pub type ASN1_UNIVERSALSTRING = asn1_string_st;
pub type ASN1_UTCTIME = asn1_string_st;
pub type ASN1_UTF8STRING = asn1_string_st;
pub type ASN1_VISIBLESTRING = asn1_string_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_type_st {
    pub type_0: libc::c_int,
    pub value: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub ptr: *mut libc::c_char,
    pub boolean: ASN1_BOOLEAN,
    pub asn1_string: *mut ASN1_STRING,
    pub object: *mut ASN1_OBJECT,
    pub integer: *mut ASN1_INTEGER,
    pub enumerated: *mut ASN1_ENUMERATED,
    pub bit_string: *mut ASN1_BIT_STRING,
    pub octet_string: *mut ASN1_OCTET_STRING,
    pub printablestring: *mut ASN1_PRINTABLESTRING,
    pub t61string: *mut ASN1_T61STRING,
    pub ia5string: *mut ASN1_IA5STRING,
    pub generalstring: *mut ASN1_GENERALSTRING,
    pub bmpstring: *mut ASN1_BMPSTRING,
    pub universalstring: *mut ASN1_UNIVERSALSTRING,
    pub utctime: *mut ASN1_UTCTIME,
    pub generalizedtime: *mut ASN1_GENERALIZEDTIME,
    pub visiblestring: *mut ASN1_VISIBLESTRING,
    pub utf8string: *mut ASN1_UTF8STRING,
    pub set: *mut ASN1_STRING,
    pub sequence: *mut ASN1_STRING,
    pub asn1_value: *mut ASN1_VALUE,
}
pub type ASN1_VALUE = ASN1_VALUE_st;
pub type ASN1_TYPE = asn1_type_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Netscape_spkac_st {
    pub pubkey: *mut X509_PUBKEY,
    pub challenge: *mut ASN1_IA5STRING,
}
pub type X509_PUBKEY = X509_pubkey_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_pubkey_st {
    pub algor: *mut X509_ALGOR,
    pub public_key: *mut ASN1_BIT_STRING,
    pub pkey: *mut EVP_PKEY,
}
pub type EVP_PKEY = evp_pkey_st;
pub type X509_ALGOR = X509_algor_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_algor_st {
    pub algorithm: *mut ASN1_OBJECT,
    pub parameter: *mut ASN1_TYPE,
}
pub type NETSCAPE_SPKAC = Netscape_spkac_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Netscape_spki_st {
    pub spkac: *mut NETSCAPE_SPKAC,
    pub sig_algor: *mut X509_ALGOR,
    pub signature: *mut ASN1_BIT_STRING,
}
pub type NETSCAPE_SPKI = Netscape_spki_st;
pub type CRYPTO_refcount_t = uint32_t;
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
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
pub type BIO_METHOD = bio_method_st;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NETSCAPE_SPKI_set_pubkey(
    mut x: *mut NETSCAPE_SPKI,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    if x.is_null() || ((*x).spkac).is_null() {
        return 0 as libc::c_int;
    }
    return X509_PUBKEY_set(&mut (*(*x).spkac).pubkey, pkey);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NETSCAPE_SPKI_get_pubkey(
    mut x: *const NETSCAPE_SPKI,
) -> *mut EVP_PKEY {
    if x.is_null() || ((*x).spkac).is_null() {
        return 0 as *mut EVP_PKEY;
    }
    return X509_PUBKEY_get((*(*x).spkac).pubkey);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NETSCAPE_SPKI_b64_decode(
    mut str: *const libc::c_char,
    mut len: ossl_ssize_t,
) -> *mut NETSCAPE_SPKI {
    let mut spki_der: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut spki_len: size_t = 0;
    let mut spki: *mut NETSCAPE_SPKI = 0 as *mut NETSCAPE_SPKI;
    if len <= 0 as libc::c_int as ossl_ssize_t {
        len = strlen(str) as ossl_ssize_t;
    }
    if EVP_DecodedLength(&mut spki_len, len as size_t) == 0 {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            103 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509spki.c\0" as *const u8
                as *const libc::c_char,
            90 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut NETSCAPE_SPKI;
    }
    spki_der = OPENSSL_malloc(spki_len) as *mut libc::c_uchar;
    if spki_der.is_null() {
        return 0 as *mut NETSCAPE_SPKI;
    }
    if EVP_DecodeBase64(
        spki_der,
        &mut spki_len,
        spki_len,
        str as *const uint8_t,
        len as size_t,
    ) == 0
    {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            103 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509spki.c\0" as *const u8
                as *const libc::c_char,
            98 as libc::c_int as libc::c_uint,
        );
        OPENSSL_free(spki_der as *mut libc::c_void);
        return 0 as *mut NETSCAPE_SPKI;
    }
    p = spki_der;
    spki = d2i_NETSCAPE_SPKI(
        0 as *mut *mut NETSCAPE_SPKI,
        &mut p,
        spki_len as libc::c_long,
    );
    OPENSSL_free(spki_der as *mut libc::c_void);
    return spki;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NETSCAPE_SPKI_b64_encode(
    mut spki: *mut NETSCAPE_SPKI,
) -> *mut libc::c_char {
    let mut der_spki: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut p: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut b64_str: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut b64_len: size_t = 0;
    let mut der_len: libc::c_int = 0;
    der_len = i2d_NETSCAPE_SPKI(spki, 0 as *mut *mut uint8_t);
    if EVP_EncodedLength(&mut b64_len, der_len as size_t) == 0 {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509spki.c\0" as *const u8
                as *const libc::c_char,
            117 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut libc::c_char;
    }
    der_spki = OPENSSL_malloc(der_len as size_t) as *mut libc::c_uchar;
    if der_spki.is_null() {
        return 0 as *mut libc::c_char;
    }
    b64_str = OPENSSL_malloc(b64_len) as *mut libc::c_char;
    if b64_str.is_null() {
        OPENSSL_free(der_spki as *mut libc::c_void);
        return 0 as *mut libc::c_char;
    }
    p = der_spki;
    i2d_NETSCAPE_SPKI(spki, &mut p);
    EVP_EncodeBlock(b64_str as *mut libc::c_uchar, der_spki, der_len as size_t);
    OPENSSL_free(der_spki as *mut libc::c_void);
    return b64_str;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NETSCAPE_SPKI_print(
    mut out: *mut BIO,
    mut spki: *mut NETSCAPE_SPKI,
) -> libc::c_int {
    if out.is_null() || spki.is_null() || ((*spki).spkac).is_null()
        || ((*(*spki).spkac).pubkey).is_null() || ((*spki).sig_algor).is_null()
        || ((*(*spki).sig_algor).algorithm).is_null() || ((*spki).signature).is_null()
        || ((*(*spki).signature).data).is_null()
    {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509spki.c\0" as *const u8
                as *const libc::c_char,
            141 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    BIO_printf(out, b"Netscape SPKI:\n\0" as *const u8 as *const libc::c_char);
    let mut spkioid: *mut ASN1_OBJECT = 0 as *mut ASN1_OBJECT;
    X509_PUBKEY_get0_param(
        &mut spkioid,
        0 as *mut *const uint8_t,
        0 as *mut libc::c_int,
        0 as *mut *mut X509_ALGOR,
        (*(*spki).spkac).pubkey,
    );
    let mut spkioid_nid: libc::c_int = OBJ_obj2nid(spkioid);
    BIO_printf(
        out,
        b"  Public Key Algorithm: %s\n\0" as *const u8 as *const libc::c_char,
        if spkioid_nid == 0 as libc::c_int {
            b"UNKNOWN\0" as *const u8 as *const libc::c_char
        } else {
            OBJ_nid2ln(spkioid_nid)
        },
    );
    let mut pkey: *mut EVP_PKEY = X509_PUBKEY_get0((*(*spki).spkac).pubkey);
    if pkey.is_null() {
        BIO_printf(
            out,
            b"  Unable to load public key\n\0" as *const u8 as *const libc::c_char,
        );
    } else {
        EVP_PKEY_print_public(out, pkey, 4 as libc::c_int, 0 as *mut ASN1_PCTX);
    }
    let mut chal: *mut ASN1_IA5STRING = (*(*spki).spkac).challenge;
    if !chal.is_null() && (*chal).length != 0 as libc::c_int {
        BIO_printf(
            out,
            b"  Challenge String: %.*s\n\0" as *const u8 as *const libc::c_char,
            (*chal).length,
            (*chal).data,
        );
    }
    BIO_printf(
        out,
        b"  Signature Algorithm: %s\0" as *const u8 as *const libc::c_char,
        if OBJ_obj2nid((*(*spki).sig_algor).algorithm) == 0 as libc::c_int {
            b"UNKNOWN\0" as *const u8 as *const libc::c_char
        } else {
            OBJ_nid2ln(OBJ_obj2nid((*(*spki).sig_algor).algorithm))
        },
    );
    let mut i: libc::c_int = 0 as libc::c_int;
    while i < (*(*spki).signature).length {
        if i % 18 as libc::c_int == 0 as libc::c_int {
            BIO_printf(out, b"\n      \0" as *const u8 as *const libc::c_char);
        }
        BIO_printf(
            out,
            b"%02x%s\0" as *const u8 as *const libc::c_char,
            *((*(*spki).signature).data).offset(i as isize) as libc::c_int,
            if i + 1 as libc::c_int == (*(*spki).signature).length {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                b":\0" as *const u8 as *const libc::c_char
            },
        );
        i += 1;
        i;
    }
    BIO_write(
        out,
        b"\n\0" as *const u8 as *const libc::c_char as *const libc::c_void,
        1 as libc::c_int,
    );
    return 1 as libc::c_int;
}
