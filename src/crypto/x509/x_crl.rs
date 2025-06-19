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
    pub type ASN1_VALUE_st;
    pub type stack_st_GENERAL_NAME;
    pub type stack_st_X509_NAME_ENTRY;
    pub type stack_st_GENERAL_SUBTREE;
    pub type evp_pkey_st;
    pub type stack_st_ASN1_OBJECT;
    pub type stack_st_X509_EXTENSION;
    pub type stack_st_X509_REVOKED;
    pub type crypto_buffer_st;
    pub type stack_st_DIST_POINT;
    pub type stack_st_void;
    pub type env_md_st;
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
    fn ASN1_item_dup(it: *const ASN1_ITEM, x: *mut libc::c_void) -> *mut libc::c_void;
    fn ASN1_STRING_cmp(a: *const ASN1_STRING, b: *const ASN1_STRING) -> libc::c_int;
    static ASN1_BIT_STRING_it: ASN1_ITEM;
    static ASN1_INTEGER_it: ASN1_ITEM;
    fn ASN1_INTEGER_cmp(x: *const ASN1_INTEGER, y: *const ASN1_INTEGER) -> libc::c_int;
    fn ASN1_ENUMERATED_free(str: *mut ASN1_ENUMERATED);
    static ASN1_TIME_it: ASN1_ITEM;
    fn ASN1_INTEGER_get(a: *const ASN1_INTEGER) -> libc::c_long;
    fn ASN1_ENUMERATED_get(a: *const ASN1_ENUMERATED) -> libc::c_long;
    fn asn1_encoding_clear(enc: *mut ASN1_ENCODING);
    fn X509_get_issuer_name(x509: *const X509) -> *mut X509_NAME;
    fn X509_CRL_get_issuer(crl: *const X509_CRL) -> *mut X509_NAME;
    fn X509_CRL_get_REVOKED(crl: *mut X509_CRL) -> *mut stack_st_X509_REVOKED;
    fn X509_CRL_get_ext_d2i(
        crl: *const X509_CRL,
        nid: libc::c_int,
        out_critical: *mut libc::c_int,
        out_idx: *mut libc::c_int,
    ) -> *mut libc::c_void;
    fn X509_REVOKED_get_ext_d2i(
        revoked: *const X509_REVOKED,
        nid: libc::c_int,
        out_critical: *mut libc::c_int,
        out_idx: *mut libc::c_int,
    ) -> *mut libc::c_void;
    static X509_NAME_it: ASN1_ITEM;
    fn X509_NAME_cmp(a: *const X509_NAME, b: *const X509_NAME) -> libc::c_int;
    static X509_EXTENSION_it: ASN1_ITEM;
    fn X509_EXTENSION_get_object(ex: *const X509_EXTENSION) -> *mut ASN1_OBJECT;
    fn X509_EXTENSION_get_critical(ex: *const X509_EXTENSION) -> libc::c_int;
    static X509_ALGOR_it: ASN1_ITEM;
    fn X509_ALGOR_cmp(a: *const X509_ALGOR, b: *const X509_ALGOR) -> libc::c_int;
    fn X509_CRL_digest(
        crl: *const X509_CRL,
        md: *const EVP_MD,
        out: *mut uint8_t,
        out_len: *mut libc::c_uint,
    ) -> libc::c_int;
    fn ASN1_item_verify(
        it: *const ASN1_ITEM,
        algor1: *const X509_ALGOR,
        signature: *const ASN1_BIT_STRING,
        data: *mut libc::c_void,
        pkey: *mut EVP_PKEY,
    ) -> libc::c_int;
    fn X509_get_serialNumber(x509: *mut X509) -> *mut ASN1_INTEGER;
    fn AUTHORITY_KEYID_free(akid: *mut AUTHORITY_KEYID);
    fn ISSUING_DIST_POINT_free(idp: *mut ISSUING_DIST_POINT);
    fn DIST_POINT_set_dpname(
        dpn: *mut DIST_POINT_NAME,
        iname: *mut X509_NAME,
    ) -> libc::c_int;
    fn OPENSSL_sk_new(comp: OPENSSL_sk_cmp_func) -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_find(
        sk: *const OPENSSL_STACK,
        out_index: *mut size_t,
        p: *const libc::c_void,
        call_cmp_func: OPENSSL_sk_call_cmp_func,
    ) -> libc::c_int;
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn OPENSSL_sk_sort(sk: *mut OPENSSL_STACK, call_cmp_func: OPENSSL_sk_call_cmp_func);
    fn OPENSSL_sk_is_sorted(sk: *const OPENSSL_STACK) -> libc::c_int;
    fn OPENSSL_sk_set_cmp_func(
        sk: *mut OPENSSL_STACK,
        comp: OPENSSL_sk_cmp_func,
    ) -> OPENSSL_sk_cmp_func;
    fn EVP_sha256() -> *const EVP_MD;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OBJ_obj2nid(obj: *const ASN1_OBJECT) -> libc::c_int;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn CRYPTO_STATIC_MUTEX_lock_read(lock: *mut CRYPTO_STATIC_MUTEX);
    fn CRYPTO_STATIC_MUTEX_lock_write(lock: *mut CRYPTO_STATIC_MUTEX);
    fn CRYPTO_STATIC_MUTEX_unlock_read(lock: *mut CRYPTO_STATIC_MUTEX);
    fn CRYPTO_STATIC_MUTEX_unlock_write(lock: *mut CRYPTO_STATIC_MUTEX);
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_rwlock_arch_t {
    pub __readers: libc::c_uint,
    pub __writers: libc::c_uint,
    pub __wrphase_futex: libc::c_uint,
    pub __writers_futex: libc::c_uint,
    pub __pad3: libc::c_uint,
    pub __pad4: libc::c_uint,
    pub __cur_writer: libc::c_int,
    pub __shared: libc::c_int,
    pub __rwelision: libc::c_schar,
    pub __pad1: [libc::c_uchar; 7],
    pub __pad2: libc::c_ulong,
    pub __flags: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_rwlock_t {
    pub __data: __pthread_rwlock_arch_t,
    pub __size: [libc::c_char; 56],
    pub __align: libc::c_long,
}
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
pub struct X509_extension_st {
    pub object: *mut ASN1_OBJECT,
    pub critical: ASN1_BOOLEAN,
    pub value: *mut ASN1_OCTET_STRING,
}
pub type X509_EXTENSION = X509_extension_st;
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
pub type EVP_MD = env_md_st;
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
pub type ASN1_aux_cb = unsafe extern "C" fn(
    libc::c_int,
    *mut *mut ASN1_VALUE,
    *const ASN1_ITEM,
    *mut libc::c_void,
) -> libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ASN1_AUX_st {
    pub app_data: *mut libc::c_void,
    pub flags: uint32_t,
    pub ref_offset: libc::c_int,
    pub asn1_cb: Option::<ASN1_aux_cb>,
    pub enc_offset: libc::c_int,
}
pub type ASN1_AUX = ASN1_AUX_st;
pub type sk_X509_REVOKED_cmp_func = Option::<
    unsafe extern "C" fn(
        *const *const X509_REVOKED,
        *const *const X509_REVOKED,
    ) -> libc::c_int,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CRYPTO_STATIC_MUTEX {
    pub lock: pthread_rwlock_t,
}
pub const PTHREAD_RWLOCK_DEFAULT_NP: C2RustUnnamed_1 = 0;
pub type C2RustUnnamed_1 = libc::c_uint;
pub const PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP: C2RustUnnamed_1 = 2;
pub const PTHREAD_RWLOCK_PREFER_WRITER_NP: C2RustUnnamed_1 = 1;
pub const PTHREAD_RWLOCK_PREFER_READER_NP: C2RustUnnamed_1 = 0;
#[inline]
unsafe extern "C" fn sk_X509_REVOKED_find_awslc(
    mut sk: *const stack_st_X509_REVOKED,
    mut out_index: *mut size_t,
    mut p: *const X509_REVOKED,
) -> libc::c_int {
    return OPENSSL_sk_find(
        sk as *const OPENSSL_STACK,
        out_index,
        p as *const libc::c_void,
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
unsafe extern "C" fn sk_X509_REVOKED_push(
    mut sk: *mut stack_st_X509_REVOKED,
    mut p: *mut X509_REVOKED,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
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
unsafe extern "C" fn sk_X509_REVOKED_is_sorted(
    mut sk: *const stack_st_X509_REVOKED,
) -> libc::c_int {
    return OPENSSL_sk_is_sorted(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_REVOKED_set_cmp_func(
    mut sk: *mut stack_st_X509_REVOKED,
    mut comp: sk_X509_REVOKED_cmp_func,
) -> sk_X509_REVOKED_cmp_func {
    return ::core::mem::transmute::<
        OPENSSL_sk_cmp_func,
        sk_X509_REVOKED_cmp_func,
    >(
        OPENSSL_sk_set_cmp_func(
            sk as *mut OPENSSL_STACK,
            ::core::mem::transmute::<sk_X509_REVOKED_cmp_func, OPENSSL_sk_cmp_func>(comp),
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
#[inline]
unsafe extern "C" fn sk_X509_REVOKED_new(
    mut comp: sk_X509_REVOKED_cmp_func,
) -> *mut stack_st_X509_REVOKED {
    return OPENSSL_sk_new(
        ::core::mem::transmute::<sk_X509_REVOKED_cmp_func, OPENSSL_sk_cmp_func>(comp),
    ) as *mut stack_st_X509_REVOKED;
}
#[inline]
unsafe extern "C" fn sk_X509_REVOKED_num(
    mut sk: *const stack_st_X509_REVOKED,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_REVOKED_value(
    mut sk: *const stack_st_X509_REVOKED,
    mut i: size_t,
) -> *mut X509_REVOKED {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509_REVOKED;
}
#[inline]
unsafe extern "C" fn sk_X509_EXTENSION_num(
    mut sk: *const stack_st_X509_EXTENSION,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_EXTENSION_value(
    mut sk: *const stack_st_X509_EXTENSION,
    mut i: size_t,
) -> *mut X509_EXTENSION {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509_EXTENSION;
}
static mut X509_REVOKED_seq_tt: [ASN1_TEMPLATE; 3] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"serialNumber\0" as *const u8 as *const libc::c_char,
                item: &ASN1_INTEGER_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"revocationDate\0" as *const u8 as *const libc::c_char,
                item: &ASN1_TIME_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 1 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 16 as libc::c_ulong,
                field_name: b"extensions\0" as *const u8 as *const libc::c_char,
                item: &X509_EXTENSION_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut X509_REVOKED_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
unsafe extern "C" fn crl_inf_cb(
    mut operation: libc::c_int,
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
    mut exarg: *mut libc::c_void,
) -> libc::c_int {
    let mut a: *mut X509_CRL_INFO = *pval as *mut X509_CRL_INFO;
    if a.is_null() || ((*a).revoked).is_null() {
        return 1 as libc::c_int;
    }
    match operation {
        5 => {
            sk_X509_REVOKED_set_cmp_func(
                (*a).revoked,
                Some(
                    X509_REVOKED_cmp
                        as unsafe extern "C" fn(
                            *const *const X509_REVOKED,
                            *const *const X509_REVOKED,
                        ) -> libc::c_int,
                ),
            );
        }
        _ => {}
    }
    return 1 as libc::c_int;
}
static mut X509_CRL_INFO_seq_tt: [ASN1_TEMPLATE; 7] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0x1 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"version\0" as *const u8 as *const libc::c_char,
                item: &ASN1_INTEGER_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"sig_alg\0" as *const u8 as *const libc::c_char,
                item: &X509_ALGOR_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 16 as libc::c_ulong,
                field_name: b"issuer\0" as *const u8 as *const libc::c_char,
                item: &X509_NAME_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 24 as libc::c_ulong,
                field_name: b"lastUpdate\0" as *const u8 as *const libc::c_char,
                item: &ASN1_TIME_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0x1 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 32 as libc::c_ulong,
                field_name: b"nextUpdate\0" as *const u8 as *const libc::c_char,
                item: &ASN1_TIME_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 1 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 40 as libc::c_ulong,
                field_name: b"revoked\0" as *const u8 as *const libc::c_char,
                item: &X509_REVOKED_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int
                    | (0x2 as libc::c_int) << 1 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 48 as libc::c_ulong,
                field_name: b"extensions\0" as *const u8 as *const libc::c_char,
                item: &X509_EXTENSION_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
static mut X509_CRL_INFO_aux: ASN1_AUX = unsafe {
    {
        let mut init = ASN1_AUX_st {
            app_data: 0 as *const libc::c_void as *mut libc::c_void,
            flags: 2 as libc::c_int as uint32_t,
            ref_offset: 0 as libc::c_int,
            asn1_cb: Some(
                crl_inf_cb
                    as unsafe extern "C" fn(
                        libc::c_int,
                        *mut *mut ASN1_VALUE,
                        *const ASN1_ITEM,
                        *mut libc::c_void,
                    ) -> libc::c_int,
            ),
            enc_offset: 56 as libc::c_ulong as libc::c_int,
        };
        init
    }
};
#[no_mangle]
pub static mut X509_CRL_INFO_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
unsafe extern "C" fn crl_parse_entry_extensions(mut crl: *mut X509_CRL) -> libc::c_int {
    let mut revoked: *mut stack_st_X509_REVOKED = X509_CRL_get_REVOKED(crl);
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_X509_REVOKED_num(revoked) {
        let mut rev: *mut X509_REVOKED = sk_X509_REVOKED_value(revoked, i);
        let mut crit: libc::c_int = 0;
        let mut reason: *mut ASN1_ENUMERATED = X509_REVOKED_get_ext_d2i(
            rev,
            141 as libc::c_int,
            &mut crit,
            0 as *mut libc::c_int,
        ) as *mut ASN1_ENUMERATED;
        if reason.is_null() && crit != -(1 as libc::c_int) {
            (*crl).flags |= 0x80 as libc::c_int;
            return 1 as libc::c_int;
        }
        if !reason.is_null() {
            (*rev).reason = ASN1_ENUMERATED_get(reason) as libc::c_int;
            ASN1_ENUMERATED_free(reason);
        } else {
            (*rev).reason = -(1 as libc::c_int);
        }
        let mut exts: *const stack_st_X509_EXTENSION = (*rev).extensions;
        let mut j: size_t = 0 as libc::c_int as size_t;
        while j < sk_X509_EXTENSION_num(exts) {
            let mut ext: *const X509_EXTENSION = sk_X509_EXTENSION_value(exts, j);
            if X509_EXTENSION_get_critical(ext) != 0 {
                (*crl).flags |= 0x200 as libc::c_int;
                break;
            } else {
                j = j.wrapping_add(1);
                j;
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn crl_cb(
    mut operation: libc::c_int,
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
    mut exarg: *mut libc::c_void,
) -> libc::c_int {
    let mut crl: *mut X509_CRL = *pval as *mut X509_CRL;
    let mut i: libc::c_int = 0;
    match operation {
        1 => {
            (*crl).idp = 0 as *mut ISSUING_DIST_POINT;
            (*crl).akid = 0 as *mut AUTHORITY_KEYID;
            (*crl).flags = 0 as libc::c_int;
            (*crl).idp_flags = 0 as libc::c_int;
        }
        5 => {
            let mut version: libc::c_long = 0 as libc::c_int as libc::c_long;
            if !((*(*crl).crl).version).is_null() {
                version = ASN1_INTEGER_get((*(*crl).crl).version);
                if version < 0 as libc::c_int as libc::c_long
                    || version > 1 as libc::c_int as libc::c_long
                {
                    ERR_put_error(
                        11 as libc::c_int,
                        0 as libc::c_int,
                        140 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x_crl.c\0"
                            as *const u8 as *const libc::c_char,
                        176 as libc::c_int as libc::c_uint,
                    );
                    return 0 as libc::c_int;
                }
            }
            if version != 1 as libc::c_int as libc::c_long
                && !((*(*crl).crl).extensions).is_null()
            {
                ERR_put_error(
                    11 as libc::c_int,
                    0 as libc::c_int,
                    139 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x_crl.c\0"
                        as *const u8 as *const libc::c_char,
                    183 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            if X509_CRL_digest(
                crl,
                EVP_sha256(),
                ((*crl).crl_hash).as_mut_ptr(),
                0 as *mut libc::c_uint,
            ) == 0
            {
                return 0 as libc::c_int;
            }
            (*crl)
                .idp = X509_CRL_get_ext_d2i(
                crl,
                770 as libc::c_int,
                &mut i,
                0 as *mut libc::c_int,
            ) as *mut ISSUING_DIST_POINT;
            if !((*crl).idp).is_null() {
                if setup_idp(crl, (*crl).idp) == 0 {
                    return 0 as libc::c_int;
                }
            } else if i != -(1 as libc::c_int) {
                return 0 as libc::c_int
            }
            (*crl)
                .akid = X509_CRL_get_ext_d2i(
                crl,
                90 as libc::c_int,
                &mut i,
                0 as *mut libc::c_int,
            ) as *mut AUTHORITY_KEYID;
            if ((*crl).akid).is_null() && i != -(1 as libc::c_int) {
                return 0 as libc::c_int;
            }
            let mut exts: *const stack_st_X509_EXTENSION = (*(*crl).crl).extensions;
            let mut idx: size_t = 0 as libc::c_int as size_t;
            while idx < sk_X509_EXTENSION_num(exts) {
                let mut ext: *const X509_EXTENSION = sk_X509_EXTENSION_value(exts, idx);
                let mut nid: libc::c_int = OBJ_obj2nid(X509_EXTENSION_get_object(ext));
                if X509_EXTENSION_get_critical(ext) != 0 {
                    if !(nid == 770 as libc::c_int || nid == 90 as libc::c_int) {
                        (*crl).flags |= 0x200 as libc::c_int;
                        break;
                    }
                }
                idx = idx.wrapping_add(1);
                idx;
            }
            if crl_parse_entry_extensions(crl) == 0 {
                return 0 as libc::c_int;
            }
        }
        3 => {
            AUTHORITY_KEYID_free((*crl).akid);
            ISSUING_DIST_POINT_free((*crl).idp);
        }
        _ => {}
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn setup_idp(
    mut crl: *mut X509_CRL,
    mut idp: *mut ISSUING_DIST_POINT,
) -> libc::c_int {
    let mut idp_only: libc::c_int = 0 as libc::c_int;
    (*crl).idp_flags |= 0x1 as libc::c_int;
    if (*idp).onlyuser > 0 as libc::c_int {
        idp_only += 1;
        idp_only;
        (*crl).idp_flags |= 0x4 as libc::c_int;
    }
    if (*idp).onlyCA > 0 as libc::c_int {
        idp_only += 1;
        idp_only;
        (*crl).idp_flags |= 0x8 as libc::c_int;
    }
    if (*idp).onlyattr > 0 as libc::c_int {
        idp_only += 1;
        idp_only;
        (*crl).idp_flags |= 0x10 as libc::c_int;
    }
    if idp_only > 1 as libc::c_int {
        (*crl).idp_flags |= 0x2 as libc::c_int;
    }
    if (*idp).indirectCRL > 0 as libc::c_int {
        (*crl).idp_flags |= 0x20 as libc::c_int;
    }
    if !((*idp).onlysomereasons).is_null() {
        (*crl).idp_flags |= 0x40 as libc::c_int;
    }
    return DIST_POINT_set_dpname((*idp).distpoint, X509_CRL_get_issuer(crl));
}
static mut X509_CRL_aux: ASN1_AUX = unsafe {
    {
        let mut init = ASN1_AUX_st {
            app_data: 0 as *const libc::c_void as *mut libc::c_void,
            flags: 1 as libc::c_int as uint32_t,
            ref_offset: 24 as libc::c_ulong as libc::c_int,
            asn1_cb: Some(
                crl_cb
                    as unsafe extern "C" fn(
                        libc::c_int,
                        *mut *mut ASN1_VALUE,
                        *const ASN1_ITEM,
                        *mut libc::c_void,
                    ) -> libc::c_int,
            ),
            enc_offset: 0 as libc::c_int,
        };
        init
    }
};
static mut X509_CRL_seq_tt: [ASN1_TEMPLATE; 3] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"crl\0" as *const u8 as *const libc::c_char,
                item: &X509_CRL_INFO_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"sig_alg\0" as *const u8 as *const libc::c_char,
                item: &X509_ALGOR_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 16 as libc::c_ulong,
                field_name: b"signature\0" as *const u8 as *const libc::c_char,
                item: &ASN1_BIT_STRING_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut X509_CRL_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_REVOKED(
    mut a: *const X509_REVOKED,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &X509_REVOKED_it);
}
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_free(mut a: *mut X509_REVOKED) {
    ASN1_item_free(a as *mut ASN1_VALUE, &X509_REVOKED_it);
}
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_new() -> *mut X509_REVOKED {
    return ASN1_item_new(&X509_REVOKED_it) as *mut X509_REVOKED;
}
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_REVOKED(
    mut a: *mut *mut X509_REVOKED,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut X509_REVOKED {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &X509_REVOKED_it)
        as *mut X509_REVOKED;
}
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_dup(
    mut x: *const X509_REVOKED,
) -> *mut X509_REVOKED {
    return ASN1_item_dup(&X509_REVOKED_it, x as *mut libc::c_void) as *mut X509_REVOKED;
}
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_CRL_INFO(
    mut a: *mut X509_CRL_INFO,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &X509_CRL_INFO_it);
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_INFO_free(mut a: *mut X509_CRL_INFO) {
    ASN1_item_free(a as *mut ASN1_VALUE, &X509_CRL_INFO_it);
}
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_CRL_INFO(
    mut a: *mut *mut X509_CRL_INFO,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut X509_CRL_INFO {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &X509_CRL_INFO_it)
        as *mut X509_CRL_INFO;
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_INFO_new() -> *mut X509_CRL_INFO {
    return ASN1_item_new(&X509_CRL_INFO_it) as *mut X509_CRL_INFO;
}
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_CRL(
    mut a: *mut X509_CRL,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &X509_CRL_it);
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_free(mut a: *mut X509_CRL) {
    ASN1_item_free(a as *mut ASN1_VALUE, &X509_CRL_it);
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_new() -> *mut X509_CRL {
    return ASN1_item_new(&X509_CRL_it) as *mut X509_CRL;
}
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_CRL(
    mut a: *mut *mut X509_CRL,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut X509_CRL {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &X509_CRL_it)
        as *mut X509_CRL;
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_dup(mut x: *mut X509_CRL) -> *mut X509_CRL {
    return ASN1_item_dup(&X509_CRL_it, x as *mut libc::c_void) as *mut X509_CRL;
}
unsafe extern "C" fn X509_REVOKED_cmp(
    mut a: *const *const X509_REVOKED,
    mut b: *const *const X509_REVOKED,
) -> libc::c_int {
    return ASN1_STRING_cmp((**a).serialNumber, (**b).serialNumber);
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_add0_revoked(
    mut crl: *mut X509_CRL,
    mut rev: *mut X509_REVOKED,
) -> libc::c_int {
    let mut inf: *mut X509_CRL_INFO = 0 as *mut X509_CRL_INFO;
    inf = (*crl).crl;
    if ((*inf).revoked).is_null() {
        (*inf)
            .revoked = sk_X509_REVOKED_new(
            Some(
                X509_REVOKED_cmp
                    as unsafe extern "C" fn(
                        *const *const X509_REVOKED,
                        *const *const X509_REVOKED,
                    ) -> libc::c_int,
            ),
        );
    }
    if ((*inf).revoked).is_null() || sk_X509_REVOKED_push((*inf).revoked, rev) == 0 {
        return 0 as libc::c_int;
    }
    asn1_encoding_clear(&mut (*inf).enc);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_verify(
    mut crl: *mut X509_CRL,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    if X509_ALGOR_cmp((*crl).sig_alg, (*(*crl).crl).sig_alg) != 0 as libc::c_int {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            137 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x_crl.c\0" as *const u8
                as *const libc::c_char,
            319 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ASN1_item_verify(
        &X509_CRL_INFO_it,
        (*crl).sig_alg,
        (*crl).signature,
        (*crl).crl as *mut libc::c_void,
        pkey,
    );
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get0_by_serial(
    mut crl: *mut X509_CRL,
    mut ret: *mut *mut X509_REVOKED,
    mut serial: *const ASN1_INTEGER,
) -> libc::c_int {
    return crl_lookup(crl, ret, serial, 0 as *mut X509_NAME);
}
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get0_by_cert(
    mut crl: *mut X509_CRL,
    mut ret: *mut *mut X509_REVOKED,
    mut x: *mut X509,
) -> libc::c_int {
    return crl_lookup(crl, ret, X509_get_serialNumber(x), X509_get_issuer_name(x));
}
unsafe extern "C" fn crl_revoked_issuer_match(
    mut crl: *mut X509_CRL,
    mut nm: *mut X509_NAME,
    mut rev: *mut X509_REVOKED,
) -> libc::c_int {
    return (nm.is_null()
        || X509_NAME_cmp(nm, X509_CRL_get_issuer(crl)) == 0 as libc::c_int)
        as libc::c_int;
}
static mut g_crl_sort_lock: CRYPTO_STATIC_MUTEX = {
    let mut init = CRYPTO_STATIC_MUTEX {
        lock: pthread_rwlock_t {
            __data: {
                let mut init = __pthread_rwlock_arch_t {
                    __readers: 0 as libc::c_int as libc::c_uint,
                    __writers: 0 as libc::c_int as libc::c_uint,
                    __wrphase_futex: 0 as libc::c_int as libc::c_uint,
                    __writers_futex: 0 as libc::c_int as libc::c_uint,
                    __pad3: 0 as libc::c_int as libc::c_uint,
                    __pad4: 0 as libc::c_int as libc::c_uint,
                    __cur_writer: 0 as libc::c_int,
                    __shared: 0 as libc::c_int,
                    __rwelision: 0 as libc::c_int as libc::c_schar,
                    __pad1: [
                        0 as libc::c_int as libc::c_uchar,
                        0 as libc::c_int as libc::c_uchar,
                        0 as libc::c_int as libc::c_uchar,
                        0 as libc::c_int as libc::c_uchar,
                        0 as libc::c_int as libc::c_uchar,
                        0 as libc::c_int as libc::c_uchar,
                        0 as libc::c_int as libc::c_uchar,
                    ],
                    __pad2: 0 as libc::c_int as libc::c_ulong,
                    __flags: PTHREAD_RWLOCK_DEFAULT_NP as libc::c_int as libc::c_uint,
                };
                init
            },
        },
    };
    init
};
unsafe extern "C" fn crl_lookup(
    mut crl: *mut X509_CRL,
    mut ret: *mut *mut X509_REVOKED,
    mut serial: *const ASN1_INTEGER,
    mut issuer: *mut X509_NAME,
) -> libc::c_int {
    if (*serial).type_0 == 2 as libc::c_int
        || (*serial).type_0 == 2 as libc::c_int | 0x100 as libc::c_int
    {} else {
        __assert_fail(
            b"serial->type == V_ASN1_INTEGER || serial->type == V_ASN1_NEG_INTEGER\0"
                as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x_crl.c\0" as *const u8
                as *const libc::c_char,
            348 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 79],
                &[libc::c_char; 79],
            >(
                b"int crl_lookup(X509_CRL *, X509_REVOKED **, const ASN1_INTEGER *, X509_NAME *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_18870: {
        if (*serial).type_0 == 2 as libc::c_int
            || (*serial).type_0 == 2 as libc::c_int | 0x100 as libc::c_int
        {} else {
            __assert_fail(
                b"serial->type == V_ASN1_INTEGER || serial->type == V_ASN1_NEG_INTEGER\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x_crl.c\0" as *const u8
                    as *const libc::c_char,
                348 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 79],
                    &[libc::c_char; 79],
                >(
                    b"int crl_lookup(X509_CRL *, X509_REVOKED **, const ASN1_INTEGER *, X509_NAME *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut rtmp: X509_REVOKED = x509_revoked_st {
        serialNumber: 0 as *mut ASN1_INTEGER,
        revocationDate: 0 as *mut ASN1_TIME,
        extensions: 0 as *mut stack_st_X509_EXTENSION,
        reason: 0,
    };
    let mut rev: *mut X509_REVOKED = 0 as *mut X509_REVOKED;
    let mut idx: size_t = 0;
    rtmp.serialNumber = serial as *mut ASN1_INTEGER;
    CRYPTO_STATIC_MUTEX_lock_read(&mut g_crl_sort_lock);
    let is_sorted: libc::c_int = sk_X509_REVOKED_is_sorted((*(*crl).crl).revoked);
    CRYPTO_STATIC_MUTEX_unlock_read(&mut g_crl_sort_lock);
    if is_sorted == 0 {
        CRYPTO_STATIC_MUTEX_lock_write(&mut g_crl_sort_lock);
        if sk_X509_REVOKED_is_sorted((*(*crl).crl).revoked) == 0 {
            sk_X509_REVOKED_sort((*(*crl).crl).revoked);
        }
        CRYPTO_STATIC_MUTEX_unlock_write(&mut g_crl_sort_lock);
    }
    if sk_X509_REVOKED_find_awslc((*(*crl).crl).revoked, &mut idx, &mut rtmp) == 0 {
        return 0 as libc::c_int;
    }
    while idx < sk_X509_REVOKED_num((*(*crl).crl).revoked) {
        rev = sk_X509_REVOKED_value((*(*crl).crl).revoked, idx);
        if ASN1_INTEGER_cmp((*rev).serialNumber, serial) != 0 {
            return 0 as libc::c_int;
        }
        if crl_revoked_issuer_match(crl, issuer, rev) != 0 {
            if !ret.is_null() {
                *ret = rev;
            }
            return 1 as libc::c_int;
        }
        idx = idx.wrapping_add(1);
        idx;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn run_static_initializers() {
    X509_REVOKED_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: X509_REVOKED_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 3]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<X509_REVOKED>() as libc::c_ulong
                as libc::c_long,
            sname: b"X509_REVOKED\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    X509_CRL_INFO_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: X509_CRL_INFO_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 7]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: &X509_CRL_INFO_aux as *const ASN1_AUX as *const libc::c_void,
            size: ::core::mem::size_of::<X509_CRL_INFO>() as libc::c_ulong
                as libc::c_long,
            sname: b"X509_CRL_INFO\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    X509_CRL_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: X509_CRL_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 3]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: &X509_CRL_aux as *const ASN1_AUX as *const libc::c_void,
            size: ::core::mem::size_of::<X509_CRL>() as libc::c_ulong as libc::c_long,
            sname: b"X509_CRL\0" as *const u8 as *const libc::c_char,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
