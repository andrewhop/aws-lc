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
    pub type ASN1_VALUE_st;
    pub type stack_st_GENERAL_NAME;
    pub type stack_st_X509_NAME_ENTRY;
    pub type stack_st_X509_EXTENSION;
    pub type stack_st_X509_REVOKED;
    pub type stack_st;
    fn ASN1_STRING_dup(str: *const ASN1_STRING) -> *mut ASN1_STRING;
    fn ASN1_STRING_set(
        str: *mut ASN1_STRING,
        data: *const libc::c_void,
        len: ossl_ssize_t,
    ) -> libc::c_int;
    fn ASN1_INTEGER_new() -> *mut ASN1_INTEGER;
    fn ASN1_INTEGER_free(str: *mut ASN1_INTEGER);
    fn ASN1_INTEGER_dup(x: *const ASN1_INTEGER) -> *mut ASN1_INTEGER;
    fn ASN1_INTEGER_set_int64(out: *mut ASN1_INTEGER, v: int64_t) -> libc::c_int;
    fn ASN1_TIME_free(str: *mut ASN1_TIME);
    fn ASN1_INTEGER_get(a: *const ASN1_INTEGER) -> libc::c_long;
    fn asn1_encoding_clear(enc: *mut ASN1_ENCODING);
    fn X509_NAME_set(xn: *mut *mut X509_NAME, name: *mut X509_NAME) -> libc::c_int;
    fn X509_ALGOR_dup(alg: *const X509_ALGOR) -> *mut X509_ALGOR;
    fn X509_ALGOR_free(alg: *mut X509_ALGOR);
    fn i2d_X509_CRL_INFO(
        a: *mut X509_CRL_INFO,
        out: *mut *mut libc::c_uchar,
    ) -> libc::c_int;
    fn OPENSSL_sk_sort(sk: *mut OPENSSL_STACK, call_cmp_func: OPENSSL_sk_call_cmp_func);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OBJ_obj2nid(obj: *const ASN1_OBJECT) -> libc::c_int;
    fn CRYPTO_refcount_inc(count: *mut CRYPTO_refcount_t);
}
pub type ptrdiff_t = libc::c_long;
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type int64_t = __int64_t;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
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
pub type ASN1_TIME = asn1_string_st;
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
pub struct AUTHORITY_KEYID_st {
    pub keyid: *mut ASN1_OCTET_STRING,
    pub issuer: *mut GENERAL_NAMES,
    pub serial: *mut ASN1_INTEGER,
}
pub type GENERAL_NAMES = stack_st_GENERAL_NAME;
pub type AUTHORITY_KEYID = AUTHORITY_KEYID_st;
pub type DIST_POINT_NAME = DIST_POINT_NAME_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct DIST_POINT_NAME_st {
    pub type_0: libc::c_int,
    pub name: C2RustUnnamed_0,
    pub dpname: *mut X509_NAME,
}
pub type X509_NAME = X509_name_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_name_st {
    pub entries: *mut stack_st_X509_NAME_ENTRY,
    pub modified: libc::c_int,
    pub bytes: *mut BUF_MEM,
    pub canon_enc: *mut libc::c_uchar,
    pub canon_enclen: libc::c_int,
}
pub type BUF_MEM = buf_mem_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct buf_mem_st {
    pub length: size_t,
    pub data: *mut libc::c_char,
    pub max: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub fullname: *mut GENERAL_NAMES,
    pub relativename: *mut stack_st_X509_NAME_ENTRY,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ISSUING_DIST_POINT_st {
    pub distpoint: *mut DIST_POINT_NAME,
    pub onlyuser: ASN1_BOOLEAN,
    pub onlyCA: ASN1_BOOLEAN,
    pub onlysomereasons: *mut ASN1_BIT_STRING,
    pub indirectCRL: ASN1_BOOLEAN,
    pub onlyattr: ASN1_BOOLEAN,
}
pub type ISSUING_DIST_POINT = ISSUING_DIST_POINT_st;
pub type X509_ALGOR = X509_algor_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_algor_st {
    pub algorithm: *mut ASN1_OBJECT,
    pub parameter: *mut ASN1_TYPE,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_crl_st {
    pub crl: *mut X509_CRL_INFO,
    pub sig_alg: *mut X509_ALGOR,
    pub signature: *mut ASN1_BIT_STRING,
    pub references: CRYPTO_refcount_t,
    pub flags: libc::c_int,
    pub akid: *mut AUTHORITY_KEYID,
    pub idp: *mut ISSUING_DIST_POINT,
    pub idp_flags: libc::c_int,
    pub crl_hash: [libc::c_uchar; 32],
}
pub type CRYPTO_refcount_t = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_CRL_INFO {
    pub version: *mut ASN1_INTEGER,
    pub sig_alg: *mut X509_ALGOR,
    pub issuer: *mut X509_NAME,
    pub lastUpdate: *mut ASN1_TIME,
    pub nextUpdate: *mut ASN1_TIME,
    pub revoked: *mut stack_st_X509_REVOKED,
    pub extensions: *mut stack_st_X509_EXTENSION,
    pub enc: ASN1_ENCODING,
}
pub type ASN1_ENCODING = ASN1_ENCODING_st;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct ASN1_ENCODING_st {
    pub enc: *mut libc::c_uchar,
    pub len: libc::c_long,
    #[bitfield(name = "alias_only", ty = "libc::c_uint", bits = "0..=0")]
    #[bitfield(name = "alias_only_on_next_parse", ty = "libc::c_uint", bits = "1..=1")]
    pub alias_only_alias_only_on_next_parse: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
pub type X509_CRL = X509_crl_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_revoked_st {
    pub serialNumber: *mut ASN1_INTEGER,
    pub revocationDate: *mut ASN1_TIME,
    pub extensions: *mut stack_st_X509_EXTENSION,
    pub reason: libc::c_int,
}
pub type X509_REVOKED = x509_revoked_st;
pub type OPENSSL_sk_cmp_func = Option::<
    unsafe extern "C" fn(
        *const *const libc::c_void,
        *const *const libc::c_void,
    ) -> libc::c_int,
>;
pub type OPENSSL_sk_call_cmp_func = Option::<
    unsafe extern "C" fn(
        OPENSSL_sk_cmp_func,
        *const libc::c_void,
        *const libc::c_void,
    ) -> libc::c_int,
>;
pub type OPENSSL_STACK = stack_st;
pub type sk_X509_REVOKED_cmp_func = Option::<
    unsafe extern "C" fn(
        *const *const X509_REVOKED,
        *const *const X509_REVOKED,
    ) -> libc::c_int,
>;
#[inline]
unsafe extern "C" fn sk_X509_REVOKED_sort(mut sk: *mut stack_st_X509_REVOKED) {
    OPENSSL_sk_sort(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_X509_REVOKED_call_cmp_func
                as unsafe extern "C" fn(
                    OPENSSL_sk_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
}
#[inline]
unsafe extern "C" fn sk_X509_REVOKED_call_cmp_func(
    mut cmp_func: OPENSSL_sk_cmp_func,
    mut a: *const libc::c_void,
    mut b: *const libc::c_void,
) -> libc::c_int {
    let mut a_ptr: *const X509_REVOKED = a as *const X509_REVOKED;
    let mut b_ptr: *const X509_REVOKED = b as *const X509_REVOKED;
    return (::core::mem::transmute::<
        OPENSSL_sk_cmp_func,
        sk_X509_REVOKED_cmp_func,
    >(cmp_func))
        .expect("non-null function pointer")(&mut a_ptr, &mut b_ptr);
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_set_version(
    mut x: *mut X509_CRL,
    mut version: libc::c_long,
) -> libc::c_int {
    if x.is_null() {
        return 0 as libc::c_int;
    }
    if version < 0 as libc::c_int as libc::c_long
        || version > 1 as libc::c_int as libc::c_long
    {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            140 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509cset.c\0" as *const u8
                as *const libc::c_char,
            72 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if version == 0 as libc::c_int as libc::c_long {
        ASN1_INTEGER_free((*(*x).crl).version);
        (*(*x).crl).version = 0 as *mut ASN1_INTEGER;
        return 1 as libc::c_int;
    }
    if ((*(*x).crl).version).is_null() {
        (*(*x).crl).version = ASN1_INTEGER_new();
        if ((*(*x).crl).version).is_null() {
            return 0 as libc::c_int;
        }
    }
    return ASN1_INTEGER_set_int64((*(*x).crl).version, version);
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_set_issuer_name(
    mut x: *mut X509_CRL,
    mut name: *mut X509_NAME,
) -> libc::c_int {
    if x.is_null() || ((*x).crl).is_null() {
        return 0 as libc::c_int;
    }
    return X509_NAME_set(&mut (*(*x).crl).issuer, name);
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_set1_lastUpdate(
    mut x: *mut X509_CRL,
    mut tm: *const ASN1_TIME,
) -> libc::c_int {
    let mut in_0: *mut ASN1_TIME = 0 as *mut ASN1_TIME;
    if x.is_null() {
        return 0 as libc::c_int;
    }
    in_0 = (*(*x).crl).lastUpdate;
    if in_0 != tm as *mut ASN1_TIME {
        in_0 = ASN1_STRING_dup(tm);
        if !in_0.is_null() {
            ASN1_TIME_free((*(*x).crl).lastUpdate);
            (*(*x).crl).lastUpdate = in_0;
        }
    }
    return (in_0 != 0 as *mut libc::c_void as *mut ASN1_TIME) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_set1_nextUpdate(
    mut x: *mut X509_CRL,
    mut tm: *const ASN1_TIME,
) -> libc::c_int {
    let mut in_0: *mut ASN1_TIME = 0 as *mut ASN1_TIME;
    if x.is_null() {
        return 0 as libc::c_int;
    }
    in_0 = (*(*x).crl).nextUpdate;
    if in_0 != tm as *mut ASN1_TIME {
        in_0 = ASN1_STRING_dup(tm);
        if !in_0.is_null() {
            ASN1_TIME_free((*(*x).crl).nextUpdate);
            (*(*x).crl).nextUpdate = in_0;
        }
    }
    return (in_0 != 0 as *mut libc::c_void as *mut ASN1_TIME) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_sort(mut c: *mut X509_CRL) -> libc::c_int {
    sk_X509_REVOKED_sort((*(*c).crl).revoked);
    asn1_encoding_clear(&mut (*(*c).crl).enc);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_up_ref(mut crl: *mut X509_CRL) -> libc::c_int {
    if crl.is_null() {
        return 0 as libc::c_int;
    }
    CRYPTO_refcount_inc(&mut (*crl).references);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get_version(mut crl: *const X509_CRL) -> libc::c_long {
    return ASN1_INTEGER_get((*(*crl).crl).version);
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get0_lastUpdate(
    mut crl: *const X509_CRL,
) -> *const ASN1_TIME {
    return (*(*crl).crl).lastUpdate;
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get0_nextUpdate(
    mut crl: *const X509_CRL,
) -> *const ASN1_TIME {
    return (*(*crl).crl).nextUpdate;
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get_lastUpdate(
    mut crl: *mut X509_CRL,
) -> *mut ASN1_TIME {
    return (*(*crl).crl).lastUpdate;
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get_nextUpdate(
    mut crl: *mut X509_CRL,
) -> *mut ASN1_TIME {
    return (*(*crl).crl).nextUpdate;
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get_issuer(
    mut crl: *const X509_CRL,
) -> *mut X509_NAME {
    return (*(*crl).crl).issuer;
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get_REVOKED(
    mut crl: *mut X509_CRL,
) -> *mut stack_st_X509_REVOKED {
    return (*(*crl).crl).revoked;
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get0_extensions(
    mut crl: *const X509_CRL,
) -> *const stack_st_X509_EXTENSION {
    return (*(*crl).crl).extensions;
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get0_signature(
    mut crl: *const X509_CRL,
    mut psig: *mut *const ASN1_BIT_STRING,
    mut palg: *mut *const X509_ALGOR,
) {
    if !psig.is_null() {
        *psig = (*crl).signature;
    }
    if !palg.is_null() {
        *palg = (*crl).sig_alg;
    }
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get_signature_nid(
    mut crl: *const X509_CRL,
) -> libc::c_int {
    return OBJ_obj2nid((*(*crl).sig_alg).algorithm);
}
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_get0_revocationDate(
    mut revoked: *const X509_REVOKED,
) -> *const ASN1_TIME {
    return (*revoked).revocationDate;
}
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_set_revocationDate(
    mut revoked: *mut X509_REVOKED,
    mut tm: *const ASN1_TIME,
) -> libc::c_int {
    let mut in_0: *mut ASN1_TIME = 0 as *mut ASN1_TIME;
    if revoked.is_null() {
        return 0 as libc::c_int;
    }
    in_0 = (*revoked).revocationDate;
    if in_0 != tm as *mut ASN1_TIME {
        in_0 = ASN1_STRING_dup(tm);
        if !in_0.is_null() {
            ASN1_TIME_free((*revoked).revocationDate);
            (*revoked).revocationDate = in_0;
        }
    }
    return (in_0 != 0 as *mut libc::c_void as *mut ASN1_TIME) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_get0_serialNumber(
    mut revoked: *const X509_REVOKED,
) -> *const ASN1_INTEGER {
    return (*revoked).serialNumber;
}
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_set_serialNumber(
    mut revoked: *mut X509_REVOKED,
    mut serial: *const ASN1_INTEGER,
) -> libc::c_int {
    let mut in_0: *mut ASN1_INTEGER = 0 as *mut ASN1_INTEGER;
    if (*serial).type_0 != 2 as libc::c_int
        && (*serial).type_0 != 2 as libc::c_int | 0x100 as libc::c_int
    {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            191 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509cset.c\0" as *const u8
                as *const libc::c_char,
            224 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if revoked.is_null() {
        return 0 as libc::c_int;
    }
    in_0 = (*revoked).serialNumber;
    if in_0 != serial as *mut ASN1_INTEGER {
        in_0 = ASN1_INTEGER_dup(serial);
        if !in_0.is_null() {
            ASN1_INTEGER_free((*revoked).serialNumber);
            (*revoked).serialNumber = in_0;
        }
    }
    return (in_0 != 0 as *mut libc::c_void as *mut ASN1_INTEGER) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_get0_extensions(
    mut r: *const X509_REVOKED,
) -> *const stack_st_X509_EXTENSION {
    return (*r).extensions;
}
#[no_mangle]
pub unsafe extern "C" fn i2d_re_X509_CRL_tbs(
    mut crl: *mut X509_CRL,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    asn1_encoding_clear(&mut (*(*crl).crl).enc);
    return i2d_X509_CRL_INFO((*crl).crl, outp);
}
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_CRL_tbs(
    mut crl: *mut X509_CRL,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_X509_CRL_INFO((*crl).crl, outp);
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_set1_signature_algo(
    mut crl: *mut X509_CRL,
    mut algo: *const X509_ALGOR,
) -> libc::c_int {
    let mut copy1: *mut X509_ALGOR = X509_ALGOR_dup(algo);
    let mut copy2: *mut X509_ALGOR = X509_ALGOR_dup(algo);
    if copy1.is_null() || copy2.is_null() {
        X509_ALGOR_free(copy1);
        X509_ALGOR_free(copy2);
        return 0 as libc::c_int;
    }
    X509_ALGOR_free((*crl).sig_alg);
    (*crl).sig_alg = copy1;
    X509_ALGOR_free((*(*crl).crl).sig_alg);
    (*(*crl).crl).sig_alg = copy2;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_set1_signature_value(
    mut crl: *mut X509_CRL,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
) -> libc::c_int {
    if ASN1_STRING_set(
        (*crl).signature,
        sig as *const libc::c_void,
        sig_len as ossl_ssize_t,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    (*(*crl).signature).flags
        &= !(0x8 as libc::c_int | 0x7 as libc::c_int) as libc::c_long;
    (*(*crl).signature).flags |= 0x8 as libc::c_int as libc::c_long;
    return 1 as libc::c_int;
}
