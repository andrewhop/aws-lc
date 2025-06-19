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
    fn ASN1_item_new(it: *const ASN1_ITEM) -> *mut ASN1_VALUE;
    fn ASN1_item_free(val: *mut ASN1_VALUE, it: *const ASN1_ITEM);
    fn ASN1_item_d2i(
        out: *mut *mut ASN1_VALUE,
        inp: *mut *const libc::c_uchar,
        len: libc::c_long,
        it: *const ASN1_ITEM,
    ) -> *mut ASN1_VALUE;
    fn ASN1_item_i2d(
        val: *mut ASN1_VALUE,
        outp: *mut *mut libc::c_uchar,
        it: *const ASN1_ITEM,
    ) -> libc::c_int;
    fn ASN1_STRING_set(
        str: *mut ASN1_STRING,
        data: *const libc::c_void,
        len: ossl_ssize_t,
    ) -> libc::c_int;
    fn ASN1_OCTET_STRING_new() -> *mut ASN1_OCTET_STRING;
    fn ASN1_UTF8STRING_new() -> *mut ASN1_UTF8STRING;
    fn ASN1_OCTET_STRING_free(str: *mut ASN1_OCTET_STRING);
    fn ASN1_UTF8STRING_free(str: *mut ASN1_UTF8STRING);
    static ASN1_OCTET_STRING_it: ASN1_ITEM;
    static ASN1_UTF8STRING_it: ASN1_ITEM;
    fn ASN1_OBJECT_free(a: *mut ASN1_OBJECT);
    static ASN1_OBJECT_it: ASN1_ITEM;
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_pop_free_ex(
        sk: *mut OPENSSL_STACK,
        call_free_func: OPENSSL_sk_call_free_func,
        free_func: OPENSSL_sk_free_func,
    );
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn OBJ_dup(obj: *const ASN1_OBJECT) -> *mut ASN1_OBJECT;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type ptrdiff_t = libc::c_long;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type ossl_ssize_t = ptrdiff_t;
pub type ASN1_BOOLEAN = libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ASN1_ITEM_st {
    pub itype: libc::c_char,
    pub utype: libc::c_int,
    pub templates: *const ASN1_TEMPLATE,
    pub tcount: libc::c_long,
    pub funcs: *const libc::c_void,
    pub size: libc::c_long,
    pub sname: *const libc::c_char,
}
pub type ASN1_TEMPLATE = ASN1_TEMPLATE_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ASN1_TEMPLATE_st {
    pub flags: uint32_t,
    pub tag: libc::c_int,
    pub offset: libc::c_ulong,
    pub field_name: *const libc::c_char,
    pub item: *const ASN1_ITEM_EXP,
}
pub type ASN1_ITEM_EXP = ASN1_ITEM;
pub type ASN1_ITEM = ASN1_ITEM_st;
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
pub type OPENSSL_sk_free_func = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type OPENSSL_sk_call_free_func = Option::<
    unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
>;
pub type OPENSSL_STACK = stack_st;
pub type sk_ASN1_OBJECT_free_func = Option::<
    unsafe extern "C" fn(*mut ASN1_OBJECT) -> (),
>;
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<OPENSSL_sk_free_func, sk_ASN1_OBJECT_free_func>(free_func))
        .expect("non-null function pointer")(ptr as *mut ASN1_OBJECT);
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_new_null() -> *mut stack_st_ASN1_OBJECT {
    return OPENSSL_sk_new_null() as *mut stack_st_ASN1_OBJECT;
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_pop_free(
    mut sk: *mut stack_st_ASN1_OBJECT,
    mut free_func: sk_ASN1_OBJECT_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_ASN1_OBJECT_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_ASN1_OBJECT_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_push(
    mut sk: *mut stack_st_ASN1_OBJECT,
    mut p: *mut ASN1_OBJECT,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
static mut X509_CERT_AUX_seq_tt: [ASN1_TEMPLATE; 4] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 1 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"trust\0" as *const u8 as *const libc::c_char,
                item: &ASN1_OBJECT_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int
                    | (0x2 as libc::c_int) << 1 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"reject\0" as *const u8 as *const libc::c_char,
                item: &ASN1_OBJECT_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0x1 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 16 as libc::c_ulong,
                field_name: b"alias\0" as *const u8 as *const libc::c_char,
                item: &ASN1_UTF8STRING_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0x1 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 24 as libc::c_ulong,
                field_name: b"keyid\0" as *const u8 as *const libc::c_char,
                item: &ASN1_OCTET_STRING_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[unsafe(no_mangle)]
pub static mut X509_CERT_AUX_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_X509_CERT_AUX(
    mut a: *const X509_CERT_AUX,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &X509_CERT_AUX_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_CERT_AUX_free(mut a: *mut X509_CERT_AUX) {
    ASN1_item_free(a as *mut ASN1_VALUE, &X509_CERT_AUX_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_CERT_AUX_new() -> *mut X509_CERT_AUX {
    return ASN1_item_new(&X509_CERT_AUX_it) as *mut X509_CERT_AUX;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_X509_CERT_AUX(
    mut a: *mut *mut X509_CERT_AUX,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut X509_CERT_AUX {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &X509_CERT_AUX_it)
        as *mut X509_CERT_AUX;
}
unsafe extern "C" fn aux_get(mut x: *mut X509) -> *mut X509_CERT_AUX {
    if x.is_null() {
        return 0 as *mut X509_CERT_AUX;
    }
    if ((*x).aux).is_null()
        && {
            (*x).aux = X509_CERT_AUX_new();
            ((*x).aux).is_null()
        }
    {
        return 0 as *mut X509_CERT_AUX;
    }
    return (*x).aux;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_alias_set1(
    mut x: *mut X509,
    mut name: *const uint8_t,
    mut len: ossl_ssize_t,
) -> libc::c_int {
    let mut aux: *mut X509_CERT_AUX = 0 as *mut X509_CERT_AUX;
    if name.is_null() {
        if x.is_null() || ((*x).aux).is_null() || ((*(*x).aux).alias).is_null() {
            return 1 as libc::c_int;
        }
        ASN1_UTF8STRING_free((*(*x).aux).alias);
        (*(*x).aux).alias = 0 as *mut ASN1_UTF8STRING;
        return 1 as libc::c_int;
    }
    aux = aux_get(x);
    if aux.is_null() {
        return 0 as libc::c_int;
    }
    if ((*aux).alias).is_null()
        && {
            (*aux).alias = ASN1_UTF8STRING_new();
            ((*aux).alias).is_null()
        }
    {
        return 0 as libc::c_int;
    }
    return ASN1_STRING_set((*aux).alias, name as *const libc::c_void, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_keyid_set1(
    mut x: *mut X509,
    mut id: *const uint8_t,
    mut len: ossl_ssize_t,
) -> libc::c_int {
    let mut aux: *mut X509_CERT_AUX = 0 as *mut X509_CERT_AUX;
    if id.is_null() {
        if x.is_null() || ((*x).aux).is_null() || ((*(*x).aux).keyid).is_null() {
            return 1 as libc::c_int;
        }
        ASN1_OCTET_STRING_free((*(*x).aux).keyid);
        (*(*x).aux).keyid = 0 as *mut ASN1_OCTET_STRING;
        return 1 as libc::c_int;
    }
    aux = aux_get(x);
    if aux.is_null() {
        return 0 as libc::c_int;
    }
    if ((*aux).keyid).is_null()
        && {
            (*aux).keyid = ASN1_OCTET_STRING_new();
            ((*aux).keyid).is_null()
        }
    {
        return 0 as libc::c_int;
    }
    return ASN1_STRING_set((*aux).keyid, id as *const libc::c_void, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_alias_get0(
    mut x: *const X509,
    mut out_len: *mut libc::c_int,
) -> *const uint8_t {
    let mut alias: *const ASN1_UTF8STRING = if !((*x).aux).is_null() {
        (*(*x).aux).alias
    } else {
        0 as *mut ASN1_UTF8STRING
    };
    if !out_len.is_null() {
        *out_len = if !alias.is_null() { (*alias).length } else { 0 as libc::c_int };
    }
    return if !alias.is_null() { (*alias).data } else { 0 as *mut libc::c_uchar };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_keyid_get0(
    mut x: *const X509,
    mut out_len: *mut libc::c_int,
) -> *const uint8_t {
    let mut keyid: *const ASN1_OCTET_STRING = if !((*x).aux).is_null() {
        (*(*x).aux).keyid
    } else {
        0 as *mut ASN1_OCTET_STRING
    };
    if !out_len.is_null() {
        *out_len = if !keyid.is_null() { (*keyid).length } else { 0 as libc::c_int };
    }
    return if !keyid.is_null() { (*keyid).data } else { 0 as *mut libc::c_uchar };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_add1_trust_object(
    mut x: *mut X509,
    mut obj: *const ASN1_OBJECT,
) -> libc::c_int {
    let mut aux: *mut X509_CERT_AUX = 0 as *mut X509_CERT_AUX;
    let mut current_block: u64;
    let mut objtmp: *mut ASN1_OBJECT = OBJ_dup(obj);
    if !objtmp.is_null() {
        aux = aux_get(x);
        if ((*aux).trust).is_null() {
            (*aux).trust = sk_ASN1_OBJECT_new_null();
            if ((*aux).trust).is_null() {
                current_block = 16306656008935164180;
            } else {
                current_block = 15240798224410183470;
            }
        } else {
            current_block = 15240798224410183470;
        }
        match current_block {
            16306656008935164180 => {}
            _ => {
                if !(sk_ASN1_OBJECT_push((*aux).trust, objtmp) == 0) {
                    return 1 as libc::c_int;
                }
            }
        }
    }
    ASN1_OBJECT_free(objtmp);
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_add1_reject_object(
    mut x: *mut X509,
    mut obj: *const ASN1_OBJECT,
) -> libc::c_int {
    let mut aux: *mut X509_CERT_AUX = 0 as *mut X509_CERT_AUX;
    let mut current_block: u64;
    let mut objtmp: *mut ASN1_OBJECT = OBJ_dup(obj);
    if !objtmp.is_null() {
        aux = aux_get(x);
        if ((*aux).reject).is_null() {
            (*aux).reject = sk_ASN1_OBJECT_new_null();
            if ((*aux).reject).is_null() {
                current_block = 17757178238418437049;
            } else {
                current_block = 15240798224410183470;
            }
        } else {
            current_block = 15240798224410183470;
        }
        match current_block {
            17757178238418437049 => {}
            _ => {
                if !(sk_ASN1_OBJECT_push((*aux).reject, objtmp) == 0) {
                    return 1 as libc::c_int;
                }
            }
        }
    }
    ASN1_OBJECT_free(objtmp);
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_trust_clear(mut x: *mut X509) {
    if !((*x).aux).is_null() && !((*(*x).aux).trust).is_null() {
        sk_ASN1_OBJECT_pop_free(
            (*(*x).aux).trust,
            Some(ASN1_OBJECT_free as unsafe extern "C" fn(*mut ASN1_OBJECT) -> ()),
        );
        (*(*x).aux).trust = 0 as *mut stack_st_ASN1_OBJECT;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_reject_clear(mut x: *mut X509) {
    if !((*x).aux).is_null() && !((*(*x).aux).reject).is_null() {
        sk_ASN1_OBJECT_pop_free(
            (*(*x).aux).reject,
            Some(ASN1_OBJECT_free as unsafe extern "C" fn(*mut ASN1_OBJECT) -> ()),
        );
        (*(*x).aux).reject = 0 as *mut stack_st_ASN1_OBJECT;
    }
}
unsafe extern "C" fn run_static_initializers() {
    X509_CERT_AUX_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: X509_CERT_AUX_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 4]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<X509_CERT_AUX>() as libc::c_ulong
                as libc::c_long,
            sname: b"X509_CERT_AUX\0" as *const u8 as *const libc::c_char,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
