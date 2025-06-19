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
    pub type ASN1_VALUE_st;
    pub type stack_st_GENERAL_NAME;
    pub type stack_st_X509_NAME_ENTRY;
    pub type stack_st_GENERAL_SUBTREE;
    pub type evp_pkey_st;
    pub type stack_st_ASN1_OBJECT;
    pub type stack_st_X509_EXTENSION;
    pub type crypto_buffer_st;
    pub type stack_st_DIST_POINT;
    pub type stack_st_void;
    pub type stack_st;
    fn x509v3_cache_extensions(x: *mut X509) -> libc::c_int;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OBJ_obj2nid(obj: *const ASN1_OBJECT) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
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
pub struct NAME_CONSTRAINTS_st {
    pub permittedSubtrees: *mut stack_st_GENERAL_SUBTREE,
    pub excludedSubtrees: *mut stack_st_GENERAL_SUBTREE,
}
pub type NAME_CONSTRAINTS = NAME_CONSTRAINTS_st;
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
pub type CRYPTO_refcount_t = uint32_t;
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
pub type X509 = x509_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_st {
    pub cert_info: *mut X509_CINF,
    pub sig_alg: *mut X509_ALGOR,
    pub signature: *mut ASN1_BIT_STRING,
    pub sig_info: X509_SIG_INFO,
    pub references: CRYPTO_refcount_t,
    pub ex_data: CRYPTO_EX_DATA,
    pub ex_pathlen: libc::c_long,
    pub ex_flags: uint32_t,
    pub ex_kusage: uint32_t,
    pub ex_xkusage: uint32_t,
    pub ex_nscert: uint32_t,
    pub skid: *mut ASN1_OCTET_STRING,
    pub akid: *mut AUTHORITY_KEYID,
    pub crldp: *mut stack_st_DIST_POINT,
    pub altname: *mut stack_st_GENERAL_NAME,
    pub nc: *mut NAME_CONSTRAINTS,
    pub cert_hash: [libc::c_uchar; 32],
    pub aux: *mut X509_CERT_AUX,
    pub buf: *mut CRYPTO_BUFFER,
    pub lock: CRYPTO_MUTEX,
}
pub type CRYPTO_MUTEX = crypto_mutex_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub union crypto_mutex_st {
    pub alignment: libc::c_double,
    pub padding: [uint8_t; 56],
}
pub type CRYPTO_BUFFER = crypto_buffer_st;
pub type X509_CERT_AUX = x509_cert_aux_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_cert_aux_st {
    pub trust: *mut stack_st_ASN1_OBJECT,
    pub reject: *mut stack_st_ASN1_OBJECT,
    pub alias: *mut ASN1_UTF8STRING,
    pub keyid: *mut ASN1_OCTET_STRING,
}
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
pub type X509_SIG_INFO = x509_sig_info_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_sig_info_st {
    pub digest_nid: libc::c_int,
    pub pubkey_nid: libc::c_int,
    pub sec_bits: libc::c_int,
    pub flags: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_CINF {
    pub version: *mut ASN1_INTEGER,
    pub serialNumber: *mut ASN1_INTEGER,
    pub signature: *mut X509_ALGOR,
    pub issuer: *mut X509_NAME,
    pub validity: *mut X509_VAL,
    pub subject: *mut X509_NAME,
    pub key: *mut X509_PUBKEY,
    pub issuerUID: *mut ASN1_BIT_STRING,
    pub subjectUID: *mut ASN1_BIT_STRING,
    pub extensions: *mut stack_st_X509_EXTENSION,
    pub enc: ASN1_ENCODING,
}
pub type X509_VAL = X509_val_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_val_st {
    pub notBefore: *mut ASN1_TIME,
    pub notAfter: *mut ASN1_TIME,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_trust_st {
    pub trust: libc::c_int,
    pub flags: libc::c_int,
    pub check_trust: Option::<
        unsafe extern "C" fn(*const X509_TRUST, *mut X509) -> libc::c_int,
    >,
    pub name: *mut libc::c_char,
    pub arg1: libc::c_int,
    pub arg2: *mut libc::c_void,
}
pub type X509_TRUST = x509_trust_st;
pub type OPENSSL_STACK = stack_st;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_120_error_is_indices_must_fit_in_int {
    #[bitfield(
        name = "static_assertion_at_line_120_error_is_indices_must_fit_in_int",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_120_error_is_indices_must_fit_in_int: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_num(mut sk: *const stack_st_ASN1_OBJECT) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_value(
    mut sk: *const stack_st_ASN1_OBJECT,
    mut i: size_t,
) -> *mut ASN1_OBJECT {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut ASN1_OBJECT;
}
static mut trstandard: [X509_TRUST; 6] = unsafe {
    [
        {
            let mut init = x509_trust_st {
                trust: 1 as libc::c_int,
                flags: 0 as libc::c_int,
                check_trust: Some(
                    trust_compat
                        as unsafe extern "C" fn(
                            *const X509_TRUST,
                            *mut X509,
                        ) -> libc::c_int,
                ),
                name: b"compatible\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                arg1: 0 as libc::c_int,
                arg2: 0 as *const libc::c_void as *mut libc::c_void,
            };
            init
        },
        {
            let mut init = x509_trust_st {
                trust: 2 as libc::c_int,
                flags: 0 as libc::c_int,
                check_trust: Some(
                    trust_1oidany
                        as unsafe extern "C" fn(
                            *const X509_TRUST,
                            *mut X509,
                        ) -> libc::c_int,
                ),
                name: b"SSL Client\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                arg1: 130 as libc::c_int,
                arg2: 0 as *const libc::c_void as *mut libc::c_void,
            };
            init
        },
        {
            let mut init = x509_trust_st {
                trust: 3 as libc::c_int,
                flags: 0 as libc::c_int,
                check_trust: Some(
                    trust_1oidany
                        as unsafe extern "C" fn(
                            *const X509_TRUST,
                            *mut X509,
                        ) -> libc::c_int,
                ),
                name: b"SSL Server\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                arg1: 129 as libc::c_int,
                arg2: 0 as *const libc::c_void as *mut libc::c_void,
            };
            init
        },
        {
            let mut init = x509_trust_st {
                trust: 4 as libc::c_int,
                flags: 0 as libc::c_int,
                check_trust: Some(
                    trust_1oidany
                        as unsafe extern "C" fn(
                            *const X509_TRUST,
                            *mut X509,
                        ) -> libc::c_int,
                ),
                name: b"S/MIME email\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                arg1: 132 as libc::c_int,
                arg2: 0 as *const libc::c_void as *mut libc::c_void,
            };
            init
        },
        {
            let mut init = x509_trust_st {
                trust: 5 as libc::c_int,
                flags: 0 as libc::c_int,
                check_trust: Some(
                    trust_1oidany
                        as unsafe extern "C" fn(
                            *const X509_TRUST,
                            *mut X509,
                        ) -> libc::c_int,
                ),
                name: b"Object Signer\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                arg1: 131 as libc::c_int,
                arg2: 0 as *const libc::c_void as *mut libc::c_void,
            };
            init
        },
        {
            let mut init = x509_trust_st {
                trust: 8 as libc::c_int,
                flags: 0 as libc::c_int,
                check_trust: Some(
                    trust_1oidany
                        as unsafe extern "C" fn(
                            *const X509_TRUST,
                            *mut X509,
                        ) -> libc::c_int,
                ),
                name: b"TSA server\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                arg1: 133 as libc::c_int,
                arg2: 0 as *const libc::c_void as *mut libc::c_void,
            };
            init
        },
    ]
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_check_trust(
    mut x: *mut X509,
    mut id: libc::c_int,
    mut flags: libc::c_int,
) -> libc::c_int {
    if id == -(1 as libc::c_int) {
        return 1 as libc::c_int;
    }
    if id == 0 as libc::c_int {
        let mut rv: libc::c_int = obj_trust(910 as libc::c_int, x);
        if rv != 3 as libc::c_int {
            return rv;
        }
        return trust_compat(0 as *const X509_TRUST, x);
    }
    let mut idx: libc::c_int = X509_TRUST_get_by_id(id);
    if idx == -(1 as libc::c_int) {
        return obj_trust(id, x);
    }
    let mut pt: *const X509_TRUST = X509_TRUST_get0(idx);
    return ((*pt).check_trust).expect("non-null function pointer")(pt, x);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_TRUST_get_count() -> libc::c_int {
    return (::core::mem::size_of::<[X509_TRUST; 6]>() as libc::c_ulong)
        .wrapping_div(::core::mem::size_of::<X509_TRUST>() as libc::c_ulong)
        as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_TRUST_get0(mut idx: libc::c_int) -> *const X509_TRUST {
    if idx < 0 as libc::c_int
        || idx as size_t
            >= (::core::mem::size_of::<[X509_TRUST; 6]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<X509_TRUST>() as libc::c_ulong)
    {
        return 0 as *const X509_TRUST;
    }
    return trstandard.as_ptr().offset(idx as isize);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_TRUST_get_by_id(mut id: libc::c_int) -> libc::c_int {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (::core::mem::size_of::<[X509_TRUST; 6]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<X509_TRUST>() as libc::c_ulong)
    {
        if trstandard[i as usize].trust == id {
            return i as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return -(1 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_TRUST_set(
    mut t: *mut libc::c_int,
    mut trust: libc::c_int,
) -> libc::c_int {
    if X509_TRUST_get_by_id(trust) == -(1 as libc::c_int) {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            113 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_trs.c\0" as *const u8
                as *const libc::c_char,
            129 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    *t = trust;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_TRUST_get_flags(mut xp: *const X509_TRUST) -> libc::c_int {
    return (*xp).flags;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_TRUST_get0_name(
    mut xp: *const X509_TRUST,
) -> *mut libc::c_char {
    return (*xp).name;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_TRUST_get_trust(mut xp: *const X509_TRUST) -> libc::c_int {
    return (*xp).trust;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_TRUST_cleanup() {}
unsafe extern "C" fn trust_1oidany(
    mut trust: *const X509_TRUST,
    mut x: *mut X509,
) -> libc::c_int {
    if !((*x).aux).is_null()
        && (!((*(*x).aux).trust).is_null() || !((*(*x).aux).reject).is_null())
    {
        return obj_trust((*trust).arg1, x);
    }
    return trust_compat(trust, x);
}
unsafe extern "C" fn trust_compat(
    mut trust: *const X509_TRUST,
    mut x: *mut X509,
) -> libc::c_int {
    if x509v3_cache_extensions(x) == 0 {
        return 3 as libc::c_int;
    }
    if (*x).ex_flags & 0x2000 as libc::c_int as uint32_t != 0 {
        return 1 as libc::c_int
    } else {
        return 3 as libc::c_int
    };
}
unsafe extern "C" fn obj_trust(mut id: libc::c_int, mut x: *mut X509) -> libc::c_int {
    let mut obj: *mut ASN1_OBJECT = 0 as *mut ASN1_OBJECT;
    let mut i: size_t = 0;
    let mut ax: *mut X509_CERT_AUX = 0 as *mut X509_CERT_AUX;
    ax = (*x).aux;
    if ax.is_null() {
        return 3 as libc::c_int;
    }
    if !((*ax).reject).is_null() {
        i = 0 as libc::c_int as size_t;
        while i < sk_ASN1_OBJECT_num((*ax).reject) {
            obj = sk_ASN1_OBJECT_value((*ax).reject, i);
            if OBJ_obj2nid(obj) == id {
                return 2 as libc::c_int;
            }
            i = i.wrapping_add(1);
            i;
        }
    }
    if !((*ax).trust).is_null() {
        i = 0 as libc::c_int as size_t;
        while i < sk_ASN1_OBJECT_num((*ax).trust) {
            obj = sk_ASN1_OBJECT_value((*ax).trust, i);
            if OBJ_obj2nid(obj) == id {
                return 1 as libc::c_int;
            }
            i = i.wrapping_add(1);
            i;
        }
    }
    return 3 as libc::c_int;
}
