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
    pub type stack_st_X509;
    pub type stack_st;
    pub type stack_st_POLICYQUALINFO;
    pub type stack_st_POLICYINFO;
    pub type stack_st_POLICY_MAPPING;
    pub type stack_st_X509_POLICY_NODE;
    pub type stack_st_X509_POLICY_LEVEL;
    fn ASN1_INTEGER_free(str: *mut ASN1_INTEGER);
    fn ASN1_INTEGER_get_uint64(
        out: *mut uint64_t,
        a: *const ASN1_INTEGER,
    ) -> libc::c_int;
    fn ASN1_OBJECT_free(a: *mut ASN1_OBJECT);
    fn X509_get_ext_d2i(
        x509: *const X509,
        nid: libc::c_int,
        out_critical: *mut libc::c_int,
        out_idx: *mut libc::c_int,
    ) -> *mut libc::c_void;
    fn CERTIFICATEPOLICIES_free(policies: *mut CERTIFICATEPOLICIES);
    fn POLICY_MAPPING_new() -> *mut POLICY_MAPPING;
    fn POLICY_MAPPING_free(mapping: *mut POLICY_MAPPING);
    fn POLICY_CONSTRAINTS_free(pcons: *mut POLICY_CONSTRAINTS);
    fn x509v3_cache_extensions(x: *mut X509) -> libc::c_int;
    fn OPENSSL_sk_new(comp: OPENSSL_sk_cmp_func) -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_zero(sk: *mut OPENSSL_STACK);
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_set(
        sk: *mut OPENSSL_STACK,
        i: size_t,
        p: *mut libc::c_void,
    ) -> *mut libc::c_void;
    fn OPENSSL_sk_free(sk: *mut OPENSSL_STACK);
    fn OPENSSL_sk_pop_free_ex(
        sk: *mut OPENSSL_STACK,
        call_free_func: OPENSSL_sk_call_free_func,
        free_func: OPENSSL_sk_free_func,
    );
    fn OPENSSL_sk_delete_if(
        sk: *mut OPENSSL_STACK,
        call_func: OPENSSL_sk_call_delete_if_func,
        func: OPENSSL_sk_delete_if_func,
        data: *mut libc::c_void,
    );
    fn OPENSSL_sk_find(
        sk: *const OPENSSL_STACK,
        out_index: *mut size_t,
        p: *const libc::c_void,
        call_cmp_func: OPENSSL_sk_call_cmp_func,
    ) -> libc::c_int;
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn OPENSSL_sk_dup(sk: *const OPENSSL_STACK) -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_sort(sk: *mut OPENSSL_STACK, call_cmp_func: OPENSSL_sk_call_cmp_func);
    fn OPENSSL_sk_is_sorted(sk: *const OPENSSL_STACK) -> libc::c_int;
    fn OPENSSL_sk_set_cmp_func(
        sk: *mut OPENSSL_STACK,
        comp: OPENSSL_sk_cmp_func,
    ) -> OPENSSL_sk_cmp_func;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_clear_error();
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OBJ_dup(obj: *const ASN1_OBJECT) -> *mut ASN1_OBJECT;
    fn OBJ_cmp(a: *const ASN1_OBJECT, b: *const ASN1_OBJECT) -> libc::c_int;
    fn OBJ_obj2nid(obj: *const ASN1_OBJECT) -> libc::c_int;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
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
pub type OPENSSL_sk_free_func = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type OPENSSL_sk_cmp_func = Option::<
    unsafe extern "C" fn(
        *const *const libc::c_void,
        *const *const libc::c_void,
    ) -> libc::c_int,
>;
pub type OPENSSL_sk_delete_if_func = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void) -> libc::c_int,
>;
pub type OPENSSL_sk_call_free_func = Option::<
    unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
>;
pub type OPENSSL_sk_call_cmp_func = Option::<
    unsafe extern "C" fn(
        OPENSSL_sk_cmp_func,
        *const libc::c_void,
        *const libc::c_void,
    ) -> libc::c_int,
>;
pub type OPENSSL_sk_call_delete_if_func = Option::<
    unsafe extern "C" fn(
        OPENSSL_sk_delete_if_func,
        *mut libc::c_void,
        *mut libc::c_void,
    ) -> libc::c_int,
>;
pub type OPENSSL_STACK = stack_st;
pub type sk_ASN1_OBJECT_free_func = Option::<
    unsafe extern "C" fn(*mut ASN1_OBJECT) -> (),
>;
pub type sk_ASN1_OBJECT_cmp_func = Option::<
    unsafe extern "C" fn(
        *const *const ASN1_OBJECT,
        *const *const ASN1_OBJECT,
    ) -> libc::c_int,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct POLICYINFO_st {
    pub policyid: *mut ASN1_OBJECT,
    pub qualifiers: *mut stack_st_POLICYQUALINFO,
}
pub type POLICYINFO = POLICYINFO_st;
pub type CERTIFICATEPOLICIES = stack_st_POLICYINFO;
pub type sk_POLICYINFO_cmp_func = Option::<
    unsafe extern "C" fn(
        *const *const POLICYINFO,
        *const *const POLICYINFO,
    ) -> libc::c_int,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct POLICY_MAPPING_st {
    pub issuerDomainPolicy: *mut ASN1_OBJECT,
    pub subjectDomainPolicy: *mut ASN1_OBJECT,
}
pub type POLICY_MAPPING = POLICY_MAPPING_st;
pub type sk_POLICY_MAPPING_free_func = Option::<
    unsafe extern "C" fn(*mut POLICY_MAPPING) -> (),
>;
pub type sk_POLICY_MAPPING_cmp_func = Option::<
    unsafe extern "C" fn(
        *const *const POLICY_MAPPING,
        *const *const POLICY_MAPPING,
    ) -> libc::c_int,
>;
pub type POLICY_MAPPINGS = stack_st_POLICY_MAPPING;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct POLICY_CONSTRAINTS_st {
    pub requireExplicitPolicy: *mut ASN1_INTEGER,
    pub inhibitPolicyMapping: *mut ASN1_INTEGER,
}
pub type POLICY_CONSTRAINTS = POLICY_CONSTRAINTS_st;
pub type X509_POLICY_LEVEL = x509_policy_level_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_policy_level_st {
    pub nodes: *mut stack_st_X509_POLICY_NODE,
    pub has_any_policy: libc::c_int,
}
pub type X509_POLICY_NODE = x509_policy_node_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_policy_node_st {
    pub policy: *mut ASN1_OBJECT,
    pub parent_policies: *mut stack_st_ASN1_OBJECT,
    pub mapped: libc::c_int,
    pub reachable: libc::c_int,
}
pub type sk_X509_POLICY_NODE_free_func = Option::<
    unsafe extern "C" fn(*mut X509_POLICY_NODE) -> (),
>;
pub type sk_X509_POLICY_LEVEL_free_func = Option::<
    unsafe extern "C" fn(*mut X509_POLICY_LEVEL) -> (),
>;
pub type sk_X509_POLICY_NODE_cmp_func = Option::<
    unsafe extern "C" fn(
        *const *const X509_POLICY_NODE,
        *const *const X509_POLICY_NODE,
    ) -> libc::c_int,
>;
pub type sk_X509_POLICY_NODE_delete_if_func = Option::<
    unsafe extern "C" fn(*mut X509_POLICY_NODE, *mut libc::c_void) -> libc::c_int,
>;
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_new_null() -> *mut stack_st_ASN1_OBJECT {
    return OPENSSL_sk_new_null() as *mut stack_st_ASN1_OBJECT;
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<OPENSSL_sk_free_func, sk_ASN1_OBJECT_free_func>(free_func))
        .expect("non-null function pointer")(ptr as *mut ASN1_OBJECT);
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_call_cmp_func(
    mut cmp_func: OPENSSL_sk_cmp_func,
    mut a: *const libc::c_void,
    mut b: *const libc::c_void,
) -> libc::c_int {
    let mut a_ptr: *const ASN1_OBJECT = a as *const ASN1_OBJECT;
    let mut b_ptr: *const ASN1_OBJECT = b as *const ASN1_OBJECT;
    return (::core::mem::transmute::<
        OPENSSL_sk_cmp_func,
        sk_ASN1_OBJECT_cmp_func,
    >(cmp_func))
        .expect("non-null function pointer")(&mut a_ptr, &mut b_ptr);
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
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_free(mut sk: *mut stack_st_ASN1_OBJECT) {
    OPENSSL_sk_free(sk as *mut OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_find_awslc(
    mut sk: *const stack_st_ASN1_OBJECT,
    mut out_index: *mut size_t,
    mut p: *const ASN1_OBJECT,
) -> libc::c_int {
    return OPENSSL_sk_find(
        sk as *const OPENSSL_STACK,
        out_index,
        p as *const libc::c_void,
        Some(
            sk_ASN1_OBJECT_call_cmp_func
                as unsafe extern "C" fn(
                    OPENSSL_sk_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_push(
    mut sk: *mut stack_st_ASN1_OBJECT,
    mut p: *mut ASN1_OBJECT,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_dup(
    mut sk: *const stack_st_ASN1_OBJECT,
) -> *mut stack_st_ASN1_OBJECT {
    return OPENSSL_sk_dup(sk as *const OPENSSL_STACK) as *mut stack_st_ASN1_OBJECT;
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_sort(mut sk: *mut stack_st_ASN1_OBJECT) {
    OPENSSL_sk_sort(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_ASN1_OBJECT_call_cmp_func
                as unsafe extern "C" fn(
                    OPENSSL_sk_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_is_sorted(
    mut sk: *const stack_st_ASN1_OBJECT,
) -> libc::c_int {
    return OPENSSL_sk_is_sorted(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_set_cmp_func(
    mut sk: *mut stack_st_ASN1_OBJECT,
    mut comp: sk_ASN1_OBJECT_cmp_func,
) -> sk_ASN1_OBJECT_cmp_func {
    return ::core::mem::transmute::<
        OPENSSL_sk_cmp_func,
        sk_ASN1_OBJECT_cmp_func,
    >(
        OPENSSL_sk_set_cmp_func(
            sk as *mut OPENSSL_STACK,
            ::core::mem::transmute::<sk_ASN1_OBJECT_cmp_func, OPENSSL_sk_cmp_func>(comp),
        ),
    );
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
unsafe extern "C" fn sk_X509_num(mut sk: *const stack_st_X509) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_value(
    mut sk: *const stack_st_X509,
    mut i: size_t,
) -> *mut X509 {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509;
}
#[inline]
unsafe extern "C" fn sk_POLICYINFO_call_cmp_func(
    mut cmp_func: OPENSSL_sk_cmp_func,
    mut a: *const libc::c_void,
    mut b: *const libc::c_void,
) -> libc::c_int {
    let mut a_ptr: *const POLICYINFO = a as *const POLICYINFO;
    let mut b_ptr: *const POLICYINFO = b as *const POLICYINFO;
    return (::core::mem::transmute::<
        OPENSSL_sk_cmp_func,
        sk_POLICYINFO_cmp_func,
    >(cmp_func))
        .expect("non-null function pointer")(&mut a_ptr, &mut b_ptr);
}
#[inline]
unsafe extern "C" fn sk_POLICYINFO_num(mut sk: *const stack_st_POLICYINFO) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_POLICYINFO_value(
    mut sk: *const stack_st_POLICYINFO,
    mut i: size_t,
) -> *mut POLICYINFO {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut POLICYINFO;
}
#[inline]
unsafe extern "C" fn sk_POLICYINFO_find_awslc(
    mut sk: *const stack_st_POLICYINFO,
    mut out_index: *mut size_t,
    mut p: *const POLICYINFO,
) -> libc::c_int {
    return OPENSSL_sk_find(
        sk as *const OPENSSL_STACK,
        out_index,
        p as *const libc::c_void,
        Some(
            sk_POLICYINFO_call_cmp_func
                as unsafe extern "C" fn(
                    OPENSSL_sk_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
}
#[inline]
unsafe extern "C" fn sk_POLICYINFO_sort(mut sk: *mut stack_st_POLICYINFO) {
    OPENSSL_sk_sort(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_POLICYINFO_call_cmp_func
                as unsafe extern "C" fn(
                    OPENSSL_sk_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
}
#[inline]
unsafe extern "C" fn sk_POLICYINFO_is_sorted(
    mut sk: *const stack_st_POLICYINFO,
) -> libc::c_int {
    return OPENSSL_sk_is_sorted(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_POLICYINFO_set_cmp_func(
    mut sk: *mut stack_st_POLICYINFO,
    mut comp: sk_POLICYINFO_cmp_func,
) -> sk_POLICYINFO_cmp_func {
    return ::core::mem::transmute::<
        OPENSSL_sk_cmp_func,
        sk_POLICYINFO_cmp_func,
    >(
        OPENSSL_sk_set_cmp_func(
            sk as *mut OPENSSL_STACK,
            ::core::mem::transmute::<sk_POLICYINFO_cmp_func, OPENSSL_sk_cmp_func>(comp),
        ),
    );
}
#[inline]
unsafe extern "C" fn sk_POLICY_MAPPING_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<
        OPENSSL_sk_free_func,
        sk_POLICY_MAPPING_free_func,
    >(free_func))
        .expect("non-null function pointer")(ptr as *mut POLICY_MAPPING);
}
#[inline]
unsafe extern "C" fn sk_POLICY_MAPPING_call_cmp_func(
    mut cmp_func: OPENSSL_sk_cmp_func,
    mut a: *const libc::c_void,
    mut b: *const libc::c_void,
) -> libc::c_int {
    let mut a_ptr: *const POLICY_MAPPING = a as *const POLICY_MAPPING;
    let mut b_ptr: *const POLICY_MAPPING = b as *const POLICY_MAPPING;
    return (::core::mem::transmute::<
        OPENSSL_sk_cmp_func,
        sk_POLICY_MAPPING_cmp_func,
    >(cmp_func))
        .expect("non-null function pointer")(&mut a_ptr, &mut b_ptr);
}
#[inline]
unsafe extern "C" fn sk_POLICY_MAPPING_new_null() -> *mut stack_st_POLICY_MAPPING {
    return OPENSSL_sk_new_null() as *mut stack_st_POLICY_MAPPING;
}
#[inline]
unsafe extern "C" fn sk_POLICY_MAPPING_num(
    mut sk: *const stack_st_POLICY_MAPPING,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_POLICY_MAPPING_value(
    mut sk: *const stack_st_POLICY_MAPPING,
    mut i: size_t,
) -> *mut POLICY_MAPPING {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut POLICY_MAPPING;
}
#[inline]
unsafe extern "C" fn sk_POLICY_MAPPING_find_awslc(
    mut sk: *const stack_st_POLICY_MAPPING,
    mut out_index: *mut size_t,
    mut p: *const POLICY_MAPPING,
) -> libc::c_int {
    return OPENSSL_sk_find(
        sk as *const OPENSSL_STACK,
        out_index,
        p as *const libc::c_void,
        Some(
            sk_POLICY_MAPPING_call_cmp_func
                as unsafe extern "C" fn(
                    OPENSSL_sk_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
}
#[inline]
unsafe extern "C" fn sk_POLICY_MAPPING_push(
    mut sk: *mut stack_st_POLICY_MAPPING,
    mut p: *mut POLICY_MAPPING,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_POLICY_MAPPING_sort(mut sk: *mut stack_st_POLICY_MAPPING) {
    OPENSSL_sk_sort(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_POLICY_MAPPING_call_cmp_func
                as unsafe extern "C" fn(
                    OPENSSL_sk_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
}
#[inline]
unsafe extern "C" fn sk_POLICY_MAPPING_is_sorted(
    mut sk: *const stack_st_POLICY_MAPPING,
) -> libc::c_int {
    return OPENSSL_sk_is_sorted(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_POLICY_MAPPING_set_cmp_func(
    mut sk: *mut stack_st_POLICY_MAPPING,
    mut comp: sk_POLICY_MAPPING_cmp_func,
) -> sk_POLICY_MAPPING_cmp_func {
    return ::core::mem::transmute::<
        OPENSSL_sk_cmp_func,
        sk_POLICY_MAPPING_cmp_func,
    >(
        OPENSSL_sk_set_cmp_func(
            sk as *mut OPENSSL_STACK,
            ::core::mem::transmute::<
                sk_POLICY_MAPPING_cmp_func,
                OPENSSL_sk_cmp_func,
            >(comp),
        ),
    );
}
#[inline]
unsafe extern "C" fn sk_POLICY_MAPPING_pop_free(
    mut sk: *mut stack_st_POLICY_MAPPING,
    mut free_func: sk_POLICY_MAPPING_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_POLICY_MAPPING_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_POLICY_MAPPING_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_X509_POLICY_NODE_num(
    mut sk: *const stack_st_X509_POLICY_NODE,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_POLICY_NODE_push(
    mut sk: *mut stack_st_X509_POLICY_NODE,
    mut p: *mut X509_POLICY_NODE,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_X509_POLICY_NODE_new(
    mut comp: sk_X509_POLICY_NODE_cmp_func,
) -> *mut stack_st_X509_POLICY_NODE {
    return OPENSSL_sk_new(
        ::core::mem::transmute::<sk_X509_POLICY_NODE_cmp_func, OPENSSL_sk_cmp_func>(comp),
    ) as *mut stack_st_X509_POLICY_NODE;
}
#[inline]
unsafe extern "C" fn sk_X509_POLICY_NODE_delete_if(
    mut sk: *mut stack_st_X509_POLICY_NODE,
    mut func: sk_X509_POLICY_NODE_delete_if_func,
    mut data: *mut libc::c_void,
) {
    OPENSSL_sk_delete_if(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_X509_POLICY_NODE_call_delete_if_func
                as unsafe extern "C" fn(
                    OPENSSL_sk_delete_if_func,
                    *mut libc::c_void,
                    *mut libc::c_void,
                ) -> libc::c_int,
        ),
        ::core::mem::transmute::<
            sk_X509_POLICY_NODE_delete_if_func,
            OPENSSL_sk_delete_if_func,
        >(func),
        data,
    );
}
#[inline]
unsafe extern "C" fn sk_X509_POLICY_NODE_call_delete_if_func(
    mut func: OPENSSL_sk_delete_if_func,
    mut obj: *mut libc::c_void,
    mut data: *mut libc::c_void,
) -> libc::c_int {
    return (::core::mem::transmute::<
        OPENSSL_sk_delete_if_func,
        sk_X509_POLICY_NODE_delete_if_func,
    >(func))
        .expect("non-null function pointer")(obj as *mut X509_POLICY_NODE, data);
}
#[inline]
unsafe extern "C" fn sk_X509_POLICY_NODE_set(
    mut sk: *mut stack_st_X509_POLICY_NODE,
    mut i: size_t,
    mut p: *mut X509_POLICY_NODE,
) -> *mut X509_POLICY_NODE {
    return OPENSSL_sk_set(sk as *mut OPENSSL_STACK, i, p as *mut libc::c_void)
        as *mut X509_POLICY_NODE;
}
#[inline]
unsafe extern "C" fn sk_X509_POLICY_NODE_new_null() -> *mut stack_st_X509_POLICY_NODE {
    return OPENSSL_sk_new_null() as *mut stack_st_X509_POLICY_NODE;
}
#[inline]
unsafe extern "C" fn sk_X509_POLICY_NODE_zero(mut sk: *mut stack_st_X509_POLICY_NODE) {
    OPENSSL_sk_zero(sk as *mut OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_POLICY_NODE_value(
    mut sk: *const stack_st_X509_POLICY_NODE,
    mut i: size_t,
) -> *mut X509_POLICY_NODE {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509_POLICY_NODE;
}
#[inline]
unsafe extern "C" fn sk_X509_POLICY_NODE_find_awslc(
    mut sk: *const stack_st_X509_POLICY_NODE,
    mut out_index: *mut size_t,
    mut p: *const X509_POLICY_NODE,
) -> libc::c_int {
    return OPENSSL_sk_find(
        sk as *const OPENSSL_STACK,
        out_index,
        p as *const libc::c_void,
        Some(
            sk_X509_POLICY_NODE_call_cmp_func
                as unsafe extern "C" fn(
                    OPENSSL_sk_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
}
#[inline]
unsafe extern "C" fn sk_X509_POLICY_NODE_call_cmp_func(
    mut cmp_func: OPENSSL_sk_cmp_func,
    mut a: *const libc::c_void,
    mut b: *const libc::c_void,
) -> libc::c_int {
    let mut a_ptr: *const X509_POLICY_NODE = a as *const X509_POLICY_NODE;
    let mut b_ptr: *const X509_POLICY_NODE = b as *const X509_POLICY_NODE;
    return (::core::mem::transmute::<
        OPENSSL_sk_cmp_func,
        sk_X509_POLICY_NODE_cmp_func,
    >(cmp_func))
        .expect("non-null function pointer")(&mut a_ptr, &mut b_ptr);
}
#[inline]
unsafe extern "C" fn sk_X509_POLICY_NODE_is_sorted(
    mut sk: *const stack_st_X509_POLICY_NODE,
) -> libc::c_int {
    return OPENSSL_sk_is_sorted(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_POLICY_NODE_sort(mut sk: *mut stack_st_X509_POLICY_NODE) {
    OPENSSL_sk_sort(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_X509_POLICY_NODE_call_cmp_func
                as unsafe extern "C" fn(
                    OPENSSL_sk_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
}
#[inline]
unsafe extern "C" fn sk_X509_POLICY_NODE_pop_free(
    mut sk: *mut stack_st_X509_POLICY_NODE,
    mut free_func: sk_X509_POLICY_NODE_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_X509_POLICY_NODE_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_X509_POLICY_NODE_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_X509_POLICY_NODE_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<
        OPENSSL_sk_free_func,
        sk_X509_POLICY_NODE_free_func,
    >(free_func))
        .expect("non-null function pointer")(ptr as *mut X509_POLICY_NODE);
}
#[inline]
unsafe extern "C" fn sk_X509_POLICY_LEVEL_pop_free(
    mut sk: *mut stack_st_X509_POLICY_LEVEL,
    mut free_func: sk_X509_POLICY_LEVEL_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_X509_POLICY_LEVEL_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_X509_POLICY_LEVEL_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_X509_POLICY_LEVEL_new_null() -> *mut stack_st_X509_POLICY_LEVEL {
    return OPENSSL_sk_new_null() as *mut stack_st_X509_POLICY_LEVEL;
}
#[inline]
unsafe extern "C" fn sk_X509_POLICY_LEVEL_num(
    mut sk: *const stack_st_X509_POLICY_LEVEL,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_POLICY_LEVEL_value(
    mut sk: *const stack_st_X509_POLICY_LEVEL,
    mut i: size_t,
) -> *mut X509_POLICY_LEVEL {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509_POLICY_LEVEL;
}
#[inline]
unsafe extern "C" fn sk_X509_POLICY_LEVEL_push(
    mut sk: *mut stack_st_X509_POLICY_LEVEL,
    mut p: *mut X509_POLICY_LEVEL,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_X509_POLICY_LEVEL_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<
        OPENSSL_sk_free_func,
        sk_X509_POLICY_LEVEL_free_func,
    >(free_func))
        .expect("non-null function pointer")(ptr as *mut X509_POLICY_LEVEL);
}
unsafe extern "C" fn is_any_policy(mut obj: *const ASN1_OBJECT) -> libc::c_int {
    return (OBJ_obj2nid(obj) == 746 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn x509_policy_node_free(mut node: *mut X509_POLICY_NODE) {
    if !node.is_null() {
        ASN1_OBJECT_free((*node).policy);
        sk_ASN1_OBJECT_pop_free(
            (*node).parent_policies,
            Some(ASN1_OBJECT_free as unsafe extern "C" fn(*mut ASN1_OBJECT) -> ()),
        );
        OPENSSL_free(node as *mut libc::c_void);
    }
}
unsafe extern "C" fn x509_policy_node_new(
    mut policy: *const ASN1_OBJECT,
) -> *mut X509_POLICY_NODE {
    if is_any_policy(policy) == 0 {} else {
        __assert_fail(
            b"!is_any_policy(policy)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/policy.c\0" as *const u8
                as *const libc::c_char,
            107 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 60],
                &[libc::c_char; 60],
            >(b"X509_POLICY_NODE *x509_policy_node_new(const ASN1_OBJECT *)\0"))
                .as_ptr(),
        );
    }
    'c_31677: {
        if is_any_policy(policy) == 0 {} else {
            __assert_fail(
                b"!is_any_policy(policy)\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/policy.c\0" as *const u8
                    as *const libc::c_char,
                107 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 60],
                    &[libc::c_char; 60],
                >(b"X509_POLICY_NODE *x509_policy_node_new(const ASN1_OBJECT *)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut node: *mut X509_POLICY_NODE = OPENSSL_zalloc(
        ::core::mem::size_of::<X509_POLICY_NODE>() as libc::c_ulong,
    ) as *mut X509_POLICY_NODE;
    if node.is_null() {
        return 0 as *mut X509_POLICY_NODE;
    }
    (*node).policy = OBJ_dup(policy);
    (*node).parent_policies = sk_ASN1_OBJECT_new_null();
    if ((*node).policy).is_null() || ((*node).parent_policies).is_null() {
        x509_policy_node_free(node);
        return 0 as *mut X509_POLICY_NODE;
    }
    return node;
}
unsafe extern "C" fn x509_policy_node_cmp(
    mut a: *const *const X509_POLICY_NODE,
    mut b: *const *const X509_POLICY_NODE,
) -> libc::c_int {
    return OBJ_cmp((**a).policy, (**b).policy);
}
unsafe extern "C" fn x509_policy_level_free(mut level: *mut X509_POLICY_LEVEL) {
    if !level.is_null() {
        sk_X509_POLICY_NODE_pop_free(
            (*level).nodes,
            Some(
                x509_policy_node_free
                    as unsafe extern "C" fn(*mut X509_POLICY_NODE) -> (),
            ),
        );
        OPENSSL_free(level as *mut libc::c_void);
    }
}
unsafe extern "C" fn x509_policy_level_new() -> *mut X509_POLICY_LEVEL {
    let mut level: *mut X509_POLICY_LEVEL = OPENSSL_zalloc(
        ::core::mem::size_of::<X509_POLICY_LEVEL>() as libc::c_ulong,
    ) as *mut X509_POLICY_LEVEL;
    if level.is_null() {
        return 0 as *mut X509_POLICY_LEVEL;
    }
    (*level)
        .nodes = sk_X509_POLICY_NODE_new(
        Some(
            x509_policy_node_cmp
                as unsafe extern "C" fn(
                    *const *const X509_POLICY_NODE,
                    *const *const X509_POLICY_NODE,
                ) -> libc::c_int,
        ),
    );
    if ((*level).nodes).is_null() {
        x509_policy_level_free(level);
        return 0 as *mut X509_POLICY_LEVEL;
    }
    return level;
}
unsafe extern "C" fn x509_policy_level_is_empty(
    mut level: *const X509_POLICY_LEVEL,
) -> libc::c_int {
    return ((*level).has_any_policy == 0
        && sk_X509_POLICY_NODE_num((*level).nodes) == 0 as libc::c_int as size_t)
        as libc::c_int;
}
unsafe extern "C" fn x509_policy_level_clear(mut level: *mut X509_POLICY_LEVEL) {
    (*level).has_any_policy = 0 as libc::c_int;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_X509_POLICY_NODE_num((*level).nodes) {
        x509_policy_node_free(sk_X509_POLICY_NODE_value((*level).nodes, i));
        i = i.wrapping_add(1);
        i;
    }
    sk_X509_POLICY_NODE_zero((*level).nodes);
}
unsafe extern "C" fn x509_policy_level_find(
    mut level: *mut X509_POLICY_LEVEL,
    mut policy: *const ASN1_OBJECT,
) -> *mut X509_POLICY_NODE {
    if sk_X509_POLICY_NODE_is_sorted((*level).nodes) != 0 {} else {
        __assert_fail(
            b"sk_X509_POLICY_NODE_is_sorted(level->nodes)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/policy.c\0" as *const u8
                as *const libc::c_char,
            162 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 83],
                &[libc::c_char; 83],
            >(
                b"X509_POLICY_NODE *x509_policy_level_find(X509_POLICY_LEVEL *, const ASN1_OBJECT *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_30521: {
        if sk_X509_POLICY_NODE_is_sorted((*level).nodes) != 0 {} else {
            __assert_fail(
                b"sk_X509_POLICY_NODE_is_sorted(level->nodes)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/policy.c\0" as *const u8
                    as *const libc::c_char,
                162 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 83],
                    &[libc::c_char; 83],
                >(
                    b"X509_POLICY_NODE *x509_policy_level_find(X509_POLICY_LEVEL *, const ASN1_OBJECT *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut node: X509_POLICY_NODE = x509_policy_node_st {
        policy: 0 as *mut ASN1_OBJECT,
        parent_policies: 0 as *mut stack_st_ASN1_OBJECT,
        mapped: 0,
        reachable: 0,
    };
    node.policy = policy as *mut ASN1_OBJECT;
    let mut idx: size_t = 0;
    if sk_X509_POLICY_NODE_find_awslc((*level).nodes, &mut idx, &mut node) == 0 {
        return 0 as *mut X509_POLICY_NODE;
    }
    return sk_X509_POLICY_NODE_value((*level).nodes, idx);
}
unsafe extern "C" fn x509_policy_level_add_nodes(
    mut level: *mut X509_POLICY_LEVEL,
    mut nodes: *mut stack_st_X509_POLICY_NODE,
) -> libc::c_int {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_X509_POLICY_NODE_num(nodes) {
        let mut node: *mut X509_POLICY_NODE = sk_X509_POLICY_NODE_value(nodes, i);
        if sk_X509_POLICY_NODE_push((*level).nodes, node) == 0 {
            return 0 as libc::c_int;
        }
        sk_X509_POLICY_NODE_set(nodes, i, 0 as *mut X509_POLICY_NODE);
        i = i.wrapping_add(1);
        i;
    }
    sk_X509_POLICY_NODE_sort((*level).nodes);
    let mut i_0: size_t = 1 as libc::c_int as size_t;
    while i_0 < sk_X509_POLICY_NODE_num((*level).nodes) {
        if OBJ_cmp(
            (*sk_X509_POLICY_NODE_value(
                (*level).nodes,
                i_0.wrapping_sub(1 as libc::c_int as size_t),
            ))
                .policy,
            (*sk_X509_POLICY_NODE_value((*level).nodes, i_0)).policy,
        ) != 0 as libc::c_int
        {} else {
            __assert_fail(
                b"OBJ_cmp(sk_X509_POLICY_NODE_value(level->nodes, i - 1)->policy, sk_X509_POLICY_NODE_value(level->nodes, i)->policy) != 0\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/policy.c\0" as *const u8
                    as *const libc::c_char,
                194 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 89],
                    &[libc::c_char; 89],
                >(
                    b"int x509_policy_level_add_nodes(X509_POLICY_LEVEL *, struct stack_st_X509_POLICY_NODE *)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_32275: {
            if OBJ_cmp(
                (*sk_X509_POLICY_NODE_value(
                    (*level).nodes,
                    i_0.wrapping_sub(1 as libc::c_int as size_t),
                ))
                    .policy,
                (*sk_X509_POLICY_NODE_value((*level).nodes, i_0)).policy,
            ) != 0 as libc::c_int
            {} else {
                __assert_fail(
                    b"OBJ_cmp(sk_X509_POLICY_NODE_value(level->nodes, i - 1)->policy, sk_X509_POLICY_NODE_value(level->nodes, i)->policy) != 0\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/policy.c\0"
                        as *const u8 as *const libc::c_char,
                    194 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 89],
                        &[libc::c_char; 89],
                    >(
                        b"int x509_policy_level_add_nodes(X509_POLICY_LEVEL *, struct stack_st_X509_POLICY_NODE *)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn policyinfo_cmp(
    mut a: *const *const POLICYINFO,
    mut b: *const *const POLICYINFO,
) -> libc::c_int {
    return OBJ_cmp((**a).policyid, (**b).policyid);
}
unsafe extern "C" fn delete_if_not_in_policies(
    mut node: *mut X509_POLICY_NODE,
    mut data: *mut libc::c_void,
) -> libc::c_int {
    let mut policies: *const CERTIFICATEPOLICIES = data as *const CERTIFICATEPOLICIES;
    if sk_POLICYINFO_is_sorted(policies) != 0 {} else {
        __assert_fail(
            b"sk_POLICYINFO_is_sorted(policies)\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/policy.c\0" as *const u8
                as *const libc::c_char,
            207 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 58],
                &[libc::c_char; 58],
            >(b"int delete_if_not_in_policies(X509_POLICY_NODE *, void *)\0"))
                .as_ptr(),
        );
    }
    'c_33098: {
        if sk_POLICYINFO_is_sorted(policies) != 0 {} else {
            __assert_fail(
                b"sk_POLICYINFO_is_sorted(policies)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/policy.c\0" as *const u8
                    as *const libc::c_char,
                207 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 58],
                    &[libc::c_char; 58],
                >(b"int delete_if_not_in_policies(X509_POLICY_NODE *, void *)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut info: POLICYINFO = POLICYINFO_st {
        policyid: 0 as *mut ASN1_OBJECT,
        qualifiers: 0 as *mut stack_st_POLICYQUALINFO,
    };
    info.policyid = (*node).policy;
    if sk_POLICYINFO_find_awslc(policies, 0 as *mut size_t, &mut info) != 0 {
        return 0 as libc::c_int;
    }
    x509_policy_node_free(node);
    return 1 as libc::c_int;
}
unsafe extern "C" fn process_certificate_policies(
    mut x509: *const X509,
    mut level: *mut X509_POLICY_LEVEL,
    mut any_policy_allowed: libc::c_int,
) -> libc::c_int {
    let mut cert_has_any_policy: libc::c_int = 0;
    let mut previous_level_has_any_policy: libc::c_int = 0;
    let mut current_block: u64;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut critical: libc::c_int = 0;
    let mut new_nodes: *mut stack_st_X509_POLICY_NODE = 0
        as *mut stack_st_X509_POLICY_NODE;
    let mut policies: *mut CERTIFICATEPOLICIES = X509_get_ext_d2i(
        x509,
        89 as libc::c_int,
        &mut critical,
        0 as *mut libc::c_int,
    ) as *mut CERTIFICATEPOLICIES;
    if policies.is_null() {
        if critical != -(1 as libc::c_int) {
            return 0 as libc::c_int;
        }
        x509_policy_level_clear(level);
        return 1 as libc::c_int;
    }
    if sk_POLICYINFO_num(policies) == 0 as libc::c_int as size_t {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            144 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/policy.c\0" as *const u8
                as *const libc::c_char,
            245 as libc::c_int as libc::c_uint,
        );
    } else {
        sk_POLICYINFO_set_cmp_func(
            policies,
            Some(
                policyinfo_cmp
                    as unsafe extern "C" fn(
                        *const *const POLICYINFO,
                        *const *const POLICYINFO,
                    ) -> libc::c_int,
            ),
        );
        sk_POLICYINFO_sort(policies);
        cert_has_any_policy = 0 as libc::c_int;
        let mut i: size_t = 0 as libc::c_int as size_t;
        loop {
            if !(i < sk_POLICYINFO_num(policies)) {
                current_block = 5143058163439228106;
                break;
            }
            let mut policy: *const POLICYINFO = sk_POLICYINFO_value(policies, i);
            if is_any_policy((*policy).policyid) != 0 {
                cert_has_any_policy = 1 as libc::c_int;
            }
            if i > 0 as libc::c_int as size_t
                && OBJ_cmp(
                    (*sk_POLICYINFO_value(
                        policies,
                        i.wrapping_sub(1 as libc::c_int as size_t),
                    ))
                        .policyid,
                    (*policy).policyid,
                ) == 0 as libc::c_int
            {
                ERR_put_error(
                    11 as libc::c_int,
                    0 as libc::c_int,
                    144 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/policy.c\0"
                        as *const u8 as *const libc::c_char,
                    260 as libc::c_int as libc::c_uint,
                );
                current_block = 9455761390973101524;
                break;
            } else {
                i = i.wrapping_add(1);
                i;
            }
        }
        match current_block {
            9455761390973101524 => {}
            _ => {
                previous_level_has_any_policy = (*level).has_any_policy;
                if cert_has_any_policy == 0 || any_policy_allowed == 0 {
                    sk_X509_POLICY_NODE_delete_if(
                        (*level).nodes,
                        Some(
                            delete_if_not_in_policies
                                as unsafe extern "C" fn(
                                    *mut X509_POLICY_NODE,
                                    *mut libc::c_void,
                                ) -> libc::c_int,
                        ),
                        policies as *mut libc::c_void,
                    );
                    (*level).has_any_policy = 0 as libc::c_int;
                }
                if previous_level_has_any_policy != 0 {
                    new_nodes = sk_X509_POLICY_NODE_new_null();
                    if new_nodes.is_null() {
                        current_block = 9455761390973101524;
                    } else {
                        let mut i_0: size_t = 0 as libc::c_int as size_t;
                        loop {
                            if !(i_0 < sk_POLICYINFO_num(policies)) {
                                current_block = 4761528863920922185;
                                break;
                            }
                            let mut policy_0: *const POLICYINFO = sk_POLICYINFO_value(
                                policies,
                                i_0,
                            );
                            if is_any_policy((*policy_0).policyid) == 0
                                && (x509_policy_level_find(level, (*policy_0).policyid))
                                    .is_null()
                            {
                                let mut node: *mut X509_POLICY_NODE = x509_policy_node_new(
                                    (*policy_0).policyid,
                                );
                                if node.is_null()
                                    || sk_X509_POLICY_NODE_push(new_nodes, node) == 0
                                {
                                    x509_policy_node_free(node);
                                    current_block = 9455761390973101524;
                                    break;
                                }
                            }
                            i_0 = i_0.wrapping_add(1);
                            i_0;
                        }
                        match current_block {
                            9455761390973101524 => {}
                            _ => {
                                if x509_policy_level_add_nodes(level, new_nodes) == 0 {
                                    current_block = 9455761390973101524;
                                } else {
                                    current_block = 15897653523371991391;
                                }
                            }
                        }
                    }
                } else {
                    current_block = 15897653523371991391;
                }
                match current_block {
                    9455761390973101524 => {}
                    _ => {
                        ret = 1 as libc::c_int;
                    }
                }
            }
        }
    }
    sk_X509_POLICY_NODE_pop_free(
        new_nodes,
        Some(x509_policy_node_free as unsafe extern "C" fn(*mut X509_POLICY_NODE) -> ()),
    );
    CERTIFICATEPOLICIES_free(policies);
    return ret;
}
unsafe extern "C" fn compare_issuer_policy(
    mut a: *const *const POLICY_MAPPING,
    mut b: *const *const POLICY_MAPPING,
) -> libc::c_int {
    return OBJ_cmp((**a).issuerDomainPolicy, (**b).issuerDomainPolicy);
}
unsafe extern "C" fn compare_subject_policy(
    mut a: *const *const POLICY_MAPPING,
    mut b: *const *const POLICY_MAPPING,
) -> libc::c_int {
    return OBJ_cmp((**a).subjectDomainPolicy, (**b).subjectDomainPolicy);
}
unsafe extern "C" fn delete_if_mapped(
    mut node: *mut X509_POLICY_NODE,
    mut data: *mut libc::c_void,
) -> libc::c_int {
    let mut mappings: *const POLICY_MAPPINGS = data as *const POLICY_MAPPINGS;
    if sk_POLICY_MAPPING_is_sorted(mappings) != 0 {} else {
        __assert_fail(
            b"sk_POLICY_MAPPING_is_sorted(mappings)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/policy.c\0" as *const u8
                as *const libc::c_char,
            325 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 49],
                &[libc::c_char; 49],
            >(b"int delete_if_mapped(X509_POLICY_NODE *, void *)\0"))
                .as_ptr(),
        );
    }
    'c_32157: {
        if sk_POLICY_MAPPING_is_sorted(mappings) != 0 {} else {
            __assert_fail(
                b"sk_POLICY_MAPPING_is_sorted(mappings)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/policy.c\0" as *const u8
                    as *const libc::c_char,
                325 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 49],
                    &[libc::c_char; 49],
                >(b"int delete_if_mapped(X509_POLICY_NODE *, void *)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut mapping: POLICY_MAPPING = POLICY_MAPPING_st {
        issuerDomainPolicy: 0 as *mut ASN1_OBJECT,
        subjectDomainPolicy: 0 as *mut ASN1_OBJECT,
    };
    mapping.issuerDomainPolicy = (*node).policy;
    if sk_POLICY_MAPPING_find_awslc(mappings, 0 as *mut size_t, &mut mapping) == 0 {
        return 0 as libc::c_int;
    }
    x509_policy_node_free(node);
    return 1 as libc::c_int;
}
unsafe extern "C" fn process_policy_mappings(
    mut cert: *const X509,
    mut level: *mut X509_POLICY_LEVEL,
    mut mapping_allowed: libc::c_int,
) -> *mut X509_POLICY_LEVEL {
    let mut last_node: *mut X509_POLICY_NODE = 0 as *mut X509_POLICY_NODE;
    let mut current_block: u64;
    let mut ok: libc::c_int = 0 as libc::c_int;
    let mut new_nodes: *mut stack_st_X509_POLICY_NODE = 0
        as *mut stack_st_X509_POLICY_NODE;
    let mut next: *mut X509_POLICY_LEVEL = 0 as *mut X509_POLICY_LEVEL;
    let mut critical: libc::c_int = 0;
    let mut mappings: *mut POLICY_MAPPINGS = X509_get_ext_d2i(
        cert,
        747 as libc::c_int,
        &mut critical,
        0 as *mut libc::c_int,
    ) as *mut POLICY_MAPPINGS;
    if !(mappings.is_null() && critical != -(1 as libc::c_int)) {
        if !mappings.is_null() {
            if sk_POLICY_MAPPING_num(mappings) == 0 as libc::c_int as size_t {
                ERR_put_error(
                    11 as libc::c_int,
                    0 as libc::c_int,
                    144 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/policy.c\0"
                        as *const u8 as *const libc::c_char,
                    369 as libc::c_int as libc::c_uint,
                );
                current_block = 14179195800195602051;
            } else {
                let mut i: size_t = 0 as libc::c_int as size_t;
                loop {
                    if !(i < sk_POLICY_MAPPING_num(mappings)) {
                        current_block = 11812396948646013369;
                        break;
                    }
                    let mut mapping: *mut POLICY_MAPPING = sk_POLICY_MAPPING_value(
                        mappings,
                        i,
                    );
                    if is_any_policy((*mapping).issuerDomainPolicy) != 0
                        || is_any_policy((*mapping).subjectDomainPolicy) != 0
                    {
                        current_block = 14179195800195602051;
                        break;
                    }
                    i = i.wrapping_add(1);
                    i;
                }
                match current_block {
                    14179195800195602051 => {}
                    _ => {
                        sk_POLICY_MAPPING_set_cmp_func(
                            mappings,
                            Some(
                                compare_issuer_policy
                                    as unsafe extern "C" fn(
                                        *const *const POLICY_MAPPING,
                                        *const *const POLICY_MAPPING,
                                    ) -> libc::c_int,
                            ),
                        );
                        sk_POLICY_MAPPING_sort(mappings);
                        if mapping_allowed != 0 {
                            new_nodes = sk_X509_POLICY_NODE_new_null();
                            if new_nodes.is_null() {
                                current_block = 14179195800195602051;
                            } else {
                                let mut last_policy: *const ASN1_OBJECT = 0
                                    as *const ASN1_OBJECT;
                                let mut i_0: size_t = 0 as libc::c_int as size_t;
                                loop {
                                    if !(i_0 < sk_POLICY_MAPPING_num(mappings)) {
                                        current_block = 7172762164747879670;
                                        break;
                                    }
                                    let mut mapping_0: *const POLICY_MAPPING = sk_POLICY_MAPPING_value(
                                        mappings,
                                        i_0,
                                    );
                                    if !(!last_policy.is_null()
                                        && OBJ_cmp((*mapping_0).issuerDomainPolicy, last_policy)
                                            == 0 as libc::c_int)
                                    {
                                        last_policy = (*mapping_0).issuerDomainPolicy;
                                        let mut node: *mut X509_POLICY_NODE = x509_policy_level_find(
                                            level,
                                            (*mapping_0).issuerDomainPolicy,
                                        );
                                        if node.is_null() {
                                            if (*level).has_any_policy == 0 {
                                                current_block = 7976072742316086414;
                                            } else {
                                                node = x509_policy_node_new(
                                                    (*mapping_0).issuerDomainPolicy,
                                                );
                                                if node.is_null()
                                                    || sk_X509_POLICY_NODE_push(new_nodes, node) == 0
                                                {
                                                    x509_policy_node_free(node);
                                                    current_block = 14179195800195602051;
                                                    break;
                                                } else {
                                                    current_block = 10043043949733653460;
                                                }
                                            }
                                        } else {
                                            current_block = 10043043949733653460;
                                        }
                                        match current_block {
                                            7976072742316086414 => {}
                                            _ => {
                                                (*node).mapped = 1 as libc::c_int;
                                            }
                                        }
                                    }
                                    i_0 = i_0.wrapping_add(1);
                                    i_0;
                                }
                                match current_block {
                                    14179195800195602051 => {}
                                    _ => {
                                        if x509_policy_level_add_nodes(level, new_nodes) == 0 {
                                            current_block = 14179195800195602051;
                                        } else {
                                            current_block = 2569451025026770673;
                                        }
                                    }
                                }
                            }
                        } else {
                            sk_X509_POLICY_NODE_delete_if(
                                (*level).nodes,
                                Some(
                                    delete_if_mapped
                                        as unsafe extern "C" fn(
                                            *mut X509_POLICY_NODE,
                                            *mut libc::c_void,
                                        ) -> libc::c_int,
                                ),
                                mappings as *mut libc::c_void,
                            );
                            sk_POLICY_MAPPING_pop_free(
                                mappings,
                                Some(
                                    POLICY_MAPPING_free
                                        as unsafe extern "C" fn(*mut POLICY_MAPPING) -> (),
                                ),
                            );
                            mappings = 0 as *mut POLICY_MAPPINGS;
                            current_block = 2569451025026770673;
                        }
                    }
                }
            }
        } else {
            current_block = 2569451025026770673;
        }
        match current_block {
            14179195800195602051 => {}
            _ => {
                if mappings.is_null() {
                    mappings = sk_POLICY_MAPPING_new_null();
                    if mappings.is_null() {
                        current_block = 14179195800195602051;
                    } else {
                        current_block = 9520865839495247062;
                    }
                } else {
                    current_block = 9520865839495247062;
                }
                match current_block {
                    14179195800195602051 => {}
                    _ => {
                        let mut i_1: size_t = 0 as libc::c_int as size_t;
                        loop {
                            if !(i_1 < sk_X509_POLICY_NODE_num((*level).nodes)) {
                                current_block = 721385680381463314;
                                break;
                            }
                            let mut node_0: *mut X509_POLICY_NODE = sk_X509_POLICY_NODE_value(
                                (*level).nodes,
                                i_1,
                            );
                            if (*node_0).mapped == 0 {
                                let mut mapping_1: *mut POLICY_MAPPING = POLICY_MAPPING_new();
                                if mapping_1.is_null() {
                                    current_block = 14179195800195602051;
                                    break;
                                }
                                (*mapping_1).issuerDomainPolicy = OBJ_dup((*node_0).policy);
                                (*mapping_1)
                                    .subjectDomainPolicy = OBJ_dup((*node_0).policy);
                                if ((*mapping_1).issuerDomainPolicy).is_null()
                                    || ((*mapping_1).subjectDomainPolicy).is_null()
                                    || sk_POLICY_MAPPING_push(mappings, mapping_1) == 0
                                {
                                    POLICY_MAPPING_free(mapping_1);
                                    current_block = 14179195800195602051;
                                    break;
                                }
                            }
                            i_1 = i_1.wrapping_add(1);
                            i_1;
                        }
                        match current_block {
                            14179195800195602051 => {}
                            _ => {
                                sk_POLICY_MAPPING_set_cmp_func(
                                    mappings,
                                    Some(
                                        compare_subject_policy
                                            as unsafe extern "C" fn(
                                                *const *const POLICY_MAPPING,
                                                *const *const POLICY_MAPPING,
                                            ) -> libc::c_int,
                                    ),
                                );
                                sk_POLICY_MAPPING_sort(mappings);
                                next = x509_policy_level_new();
                                if !next.is_null() {
                                    (*next).has_any_policy = (*level).has_any_policy;
                                    last_node = 0 as *mut X509_POLICY_NODE;
                                    let mut i_2: size_t = 0 as libc::c_int as size_t;
                                    loop {
                                        if !(i_2 < sk_POLICY_MAPPING_num(mappings)) {
                                            current_block = 9241535491006583629;
                                            break;
                                        }
                                        let mut mapping_2: *mut POLICY_MAPPING = sk_POLICY_MAPPING_value(
                                            mappings,
                                            i_2,
                                        );
                                        if !((*level).has_any_policy == 0
                                            && (x509_policy_level_find(
                                                level,
                                                (*mapping_2).issuerDomainPolicy,
                                            ))
                                                .is_null())
                                        {
                                            if last_node.is_null()
                                                || OBJ_cmp(
                                                    (*last_node).policy,
                                                    (*mapping_2).subjectDomainPolicy,
                                                ) != 0 as libc::c_int
                                            {
                                                last_node = x509_policy_node_new(
                                                    (*mapping_2).subjectDomainPolicy,
                                                );
                                                if last_node.is_null()
                                                    || sk_X509_POLICY_NODE_push((*next).nodes, last_node) == 0
                                                {
                                                    x509_policy_node_free(last_node);
                                                    current_block = 14179195800195602051;
                                                    break;
                                                }
                                            }
                                            if sk_ASN1_OBJECT_push(
                                                (*last_node).parent_policies,
                                                (*mapping_2).issuerDomainPolicy,
                                            ) == 0
                                            {
                                                current_block = 14179195800195602051;
                                                break;
                                            }
                                            (*mapping_2).issuerDomainPolicy = 0 as *mut ASN1_OBJECT;
                                        }
                                        i_2 = i_2.wrapping_add(1);
                                        i_2;
                                    }
                                    match current_block {
                                        14179195800195602051 => {}
                                        _ => {
                                            sk_X509_POLICY_NODE_sort((*next).nodes);
                                            ok = 1 as libc::c_int;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if ok == 0 {
        x509_policy_level_free(next);
        next = 0 as *mut X509_POLICY_LEVEL;
    }
    sk_POLICY_MAPPING_pop_free(
        mappings,
        Some(POLICY_MAPPING_free as unsafe extern "C" fn(*mut POLICY_MAPPING) -> ()),
    );
    sk_X509_POLICY_NODE_pop_free(
        new_nodes,
        Some(x509_policy_node_free as unsafe extern "C" fn(*mut X509_POLICY_NODE) -> ()),
    );
    return next;
}
unsafe extern "C" fn apply_skip_certs(
    mut skip_certs: *const ASN1_INTEGER,
    mut value: *mut size_t,
) -> libc::c_int {
    if skip_certs.is_null() {
        return 1 as libc::c_int;
    }
    if (*skip_certs).type_0 & 0x100 as libc::c_int != 0 {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            144 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/policy.c\0" as *const u8
                as *const libc::c_char,
            517 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut u64: uint64_t = 0;
    if ASN1_INTEGER_get_uint64(&mut u64, skip_certs) != 0 && u64 < *value {
        *value = u64;
    }
    ERR_clear_error();
    return 1 as libc::c_int;
}
unsafe extern "C" fn process_policy_constraints(
    mut x509: *const X509,
    mut explicit_policy: *mut size_t,
    mut policy_mapping: *mut size_t,
    mut inhibit_any_policy: *mut size_t,
) -> libc::c_int {
    let mut critical: libc::c_int = 0;
    let mut constraints: *mut POLICY_CONSTRAINTS = X509_get_ext_d2i(
        x509,
        401 as libc::c_int,
        &mut critical,
        0 as *mut libc::c_int,
    ) as *mut POLICY_CONSTRAINTS;
    if constraints.is_null() && critical != -(1 as libc::c_int) {
        return 0 as libc::c_int;
    }
    if !constraints.is_null() {
        if ((*constraints).requireExplicitPolicy).is_null()
            && ((*constraints).inhibitPolicyMapping).is_null()
        {
            ERR_put_error(
                11 as libc::c_int,
                0 as libc::c_int,
                144 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/policy.c\0" as *const u8
                    as *const libc::c_char,
                548 as libc::c_int as libc::c_uint,
            );
            POLICY_CONSTRAINTS_free(constraints);
            return 0 as libc::c_int;
        }
        let mut ok: libc::c_int = (apply_skip_certs(
            (*constraints).requireExplicitPolicy,
            explicit_policy,
        ) != 0
            && apply_skip_certs((*constraints).inhibitPolicyMapping, policy_mapping)
                != 0) as libc::c_int;
        POLICY_CONSTRAINTS_free(constraints);
        if ok == 0 {
            return 0 as libc::c_int;
        }
    }
    let mut inhibit_any_policy_ext: *mut ASN1_INTEGER = X509_get_ext_d2i(
        x509,
        748 as libc::c_int,
        &mut critical,
        0 as *mut libc::c_int,
    ) as *mut ASN1_INTEGER;
    if inhibit_any_policy_ext.is_null() && critical != -(1 as libc::c_int) {
        return 0 as libc::c_int;
    }
    let mut ok_0: libc::c_int = apply_skip_certs(
        inhibit_any_policy_ext,
        inhibit_any_policy,
    );
    ASN1_INTEGER_free(inhibit_any_policy_ext);
    return ok_0;
}
unsafe extern "C" fn has_explicit_policy(
    mut levels: *mut stack_st_X509_POLICY_LEVEL,
    mut user_policies: *const stack_st_ASN1_OBJECT,
) -> libc::c_int {
    if sk_ASN1_OBJECT_is_sorted(user_policies) != 0 {} else {
        __assert_fail(
            b"sk_ASN1_OBJECT_is_sorted(user_policies)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/policy.c\0" as *const u8
                as *const libc::c_char,
            578 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 98],
                &[libc::c_char; 98],
            >(
                b"int has_explicit_policy(struct stack_st_X509_POLICY_LEVEL *, const struct stack_st_ASN1_OBJECT *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_30808: {
        if sk_ASN1_OBJECT_is_sorted(user_policies) != 0 {} else {
            __assert_fail(
                b"sk_ASN1_OBJECT_is_sorted(user_policies)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/policy.c\0" as *const u8
                    as *const libc::c_char,
                578 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 98],
                    &[libc::c_char; 98],
                >(
                    b"int has_explicit_policy(struct stack_st_X509_POLICY_LEVEL *, const struct stack_st_ASN1_OBJECT *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut num_levels: size_t = sk_X509_POLICY_LEVEL_num(levels);
    let mut level: *mut X509_POLICY_LEVEL = sk_X509_POLICY_LEVEL_value(
        levels,
        num_levels.wrapping_sub(1 as libc::c_int as size_t),
    );
    if x509_policy_level_is_empty(level) != 0 {
        return 0 as libc::c_int;
    }
    let mut user_has_any_policy: libc::c_int = (sk_ASN1_OBJECT_num(user_policies)
        == 0 as libc::c_int as size_t) as libc::c_int;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_ASN1_OBJECT_num(user_policies) {
        if is_any_policy(sk_ASN1_OBJECT_value(user_policies, i)) != 0 {
            user_has_any_policy = 1 as libc::c_int;
            break;
        } else {
            i = i.wrapping_add(1);
            i;
        }
    }
    if user_has_any_policy != 0 {
        return 1 as libc::c_int;
    }
    if (*level).has_any_policy != 0 {
        return 1 as libc::c_int;
    }
    let mut i_0: size_t = 0 as libc::c_int as size_t;
    while i_0 < sk_X509_POLICY_NODE_num((*level).nodes) {
        (*sk_X509_POLICY_NODE_value((*level).nodes, i_0)).reachable = 1 as libc::c_int;
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
    let mut i_1: size_t = num_levels.wrapping_sub(1 as libc::c_int as size_t);
    while i_1 < num_levels {
        level = sk_X509_POLICY_LEVEL_value(levels, i_1);
        let mut j: size_t = 0 as libc::c_int as size_t;
        while j < sk_X509_POLICY_NODE_num((*level).nodes) {
            let mut node: *mut X509_POLICY_NODE = sk_X509_POLICY_NODE_value(
                (*level).nodes,
                j,
            );
            if !((*node).reachable == 0) {
                if sk_ASN1_OBJECT_num((*node).parent_policies)
                    == 0 as libc::c_int as size_t
                {
                    if sk_ASN1_OBJECT_find_awslc(
                        user_policies,
                        0 as *mut size_t,
                        (*node).policy,
                    ) != 0
                    {
                        return 1 as libc::c_int;
                    }
                } else if i_1 > 0 as libc::c_int as size_t {
                    let mut prev: *mut X509_POLICY_LEVEL = sk_X509_POLICY_LEVEL_value(
                        levels,
                        i_1.wrapping_sub(1 as libc::c_int as size_t),
                    );
                    let mut k: size_t = 0 as libc::c_int as size_t;
                    while k < sk_ASN1_OBJECT_num((*node).parent_policies) {
                        let mut parent: *mut X509_POLICY_NODE = x509_policy_level_find(
                            prev,
                            sk_ASN1_OBJECT_value((*node).parent_policies, k),
                        );
                        if !parent.is_null() {
                            (*parent).reachable = 1 as libc::c_int;
                        }
                        k = k.wrapping_add(1);
                        k;
                    }
                }
            }
            j = j.wrapping_add(1);
            j;
        }
        i_1 = i_1.wrapping_sub(1);
        i_1;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn asn1_object_cmp(
    mut a: *const *const ASN1_OBJECT,
    mut b: *const *const ASN1_OBJECT,
) -> libc::c_int {
    return OBJ_cmp(*a, *b);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_policy_check(
    mut certs: *const stack_st_X509,
    mut user_policies: *const stack_st_ASN1_OBJECT,
    mut flags: libc::c_ulong,
    mut out_current_cert: *mut *mut X509,
) -> libc::c_int {
    let mut current_block: u64;
    *out_current_cert = 0 as *mut X509;
    let mut ret: libc::c_int = 17 as libc::c_int;
    let mut level: *mut X509_POLICY_LEVEL = 0 as *mut X509_POLICY_LEVEL;
    let mut levels: *mut stack_st_X509_POLICY_LEVEL = 0
        as *mut stack_st_X509_POLICY_LEVEL;
    let mut user_policies_sorted: *mut stack_st_ASN1_OBJECT = 0
        as *mut stack_st_ASN1_OBJECT;
    let mut num_certs: size_t = sk_X509_num(certs);
    if num_certs <= 1 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    let mut explicit_policy: size_t = if flags & 0x100 as libc::c_int as libc::c_ulong
        != 0
    {
        0 as libc::c_int as size_t
    } else {
        num_certs.wrapping_add(1 as libc::c_int as size_t)
    };
    let mut inhibit_any_policy: size_t = if flags & 0x200 as libc::c_int as libc::c_ulong
        != 0
    {
        0 as libc::c_int as size_t
    } else {
        num_certs.wrapping_add(1 as libc::c_int as size_t)
    };
    let mut policy_mapping: size_t = if flags & 0x400 as libc::c_int as libc::c_ulong
        != 0
    {
        0 as libc::c_int as size_t
    } else {
        num_certs.wrapping_add(1 as libc::c_int as size_t)
    };
    levels = sk_X509_POLICY_LEVEL_new_null();
    if !levels.is_null() {
        let mut i: size_t = num_certs.wrapping_sub(2 as libc::c_int as size_t);
        loop {
            if !(i < num_certs) {
                current_block = 7226443171521532240;
                break;
            }
            let mut cert: *mut X509 = sk_X509_value(certs, i);
            if x509v3_cache_extensions(cert) == 0 {
                current_block = 18026953934680222107;
                break;
            }
            let is_self_issued: libc::c_int = ((*cert).ex_flags
                & 0x20 as libc::c_int as uint32_t != 0 as libc::c_int as uint32_t)
                as libc::c_int;
            if level.is_null() {
                if i == num_certs.wrapping_sub(2 as libc::c_int as size_t) {} else {
                    __assert_fail(
                        b"i == num_certs - 2\0" as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/policy.c\0"
                            as *const u8 as *const libc::c_char,
                        691 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 113],
                            &[libc::c_char; 113],
                        >(
                            b"int X509_policy_check(const struct stack_st_X509 *, const struct stack_st_ASN1_OBJECT *, unsigned long, X509 **)\0",
                        ))
                            .as_ptr(),
                    );
                }
                'c_33407: {
                    if i == num_certs.wrapping_sub(2 as libc::c_int as size_t) {} else {
                        __assert_fail(
                            b"i == num_certs - 2\0" as *const u8 as *const libc::c_char,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/policy.c\0"
                                as *const u8 as *const libc::c_char,
                            691 as libc::c_int as libc::c_uint,
                            (*::core::mem::transmute::<
                                &[u8; 113],
                                &[libc::c_char; 113],
                            >(
                                b"int X509_policy_check(const struct stack_st_X509 *, const struct stack_st_ASN1_OBJECT *, unsigned long, X509 **)\0",
                            ))
                                .as_ptr(),
                        );
                    }
                };
                level = x509_policy_level_new();
                if level.is_null() {
                    current_block = 18026953934680222107;
                    break;
                }
                (*level).has_any_policy = 1 as libc::c_int;
            }
            let any_policy_allowed: libc::c_int = (inhibit_any_policy
                > 0 as libc::c_int as size_t
                || i > 0 as libc::c_int as size_t && is_self_issued != 0) as libc::c_int;
            if process_certificate_policies(cert, level, any_policy_allowed) == 0 {
                ret = 42 as libc::c_int;
                *out_current_cert = cert;
                current_block = 18026953934680222107;
                break;
            } else if explicit_policy == 0 as libc::c_int as size_t
                && x509_policy_level_is_empty(level) != 0
            {
                ret = 43 as libc::c_int;
                current_block = 18026953934680222107;
                break;
            } else {
                if sk_X509_POLICY_LEVEL_push(levels, level) == 0 {
                    current_block = 18026953934680222107;
                    break;
                }
                let mut current_level: *mut X509_POLICY_LEVEL = level;
                level = 0 as *mut X509_POLICY_LEVEL;
                if i != 0 as libc::c_int as size_t {
                    level = process_policy_mappings(
                        cert,
                        current_level,
                        (policy_mapping > 0 as libc::c_int as size_t) as libc::c_int,
                    );
                    if level.is_null() {
                        ret = 42 as libc::c_int;
                        *out_current_cert = cert;
                        current_block = 18026953934680222107;
                        break;
                    }
                }
                if i == 0 as libc::c_int as size_t || is_self_issued == 0 {
                    if explicit_policy > 0 as libc::c_int as size_t {
                        explicit_policy = explicit_policy.wrapping_sub(1);
                        explicit_policy;
                    }
                    if policy_mapping > 0 as libc::c_int as size_t {
                        policy_mapping = policy_mapping.wrapping_sub(1);
                        policy_mapping;
                    }
                    if inhibit_any_policy > 0 as libc::c_int as size_t {
                        inhibit_any_policy = inhibit_any_policy.wrapping_sub(1);
                        inhibit_any_policy;
                    }
                }
                if process_policy_constraints(
                    cert,
                    &mut explicit_policy,
                    &mut policy_mapping,
                    &mut inhibit_any_policy,
                ) == 0
                {
                    ret = 42 as libc::c_int;
                    *out_current_cert = cert;
                    current_block = 18026953934680222107;
                    break;
                } else {
                    i = i.wrapping_sub(1);
                    i;
                }
            }
        }
        match current_block {
            18026953934680222107 => {}
            _ => {
                if explicit_policy == 0 as libc::c_int as size_t {
                    user_policies_sorted = sk_ASN1_OBJECT_dup(user_policies);
                    if user_policies_sorted.is_null() {
                        current_block = 18026953934680222107;
                    } else {
                        sk_ASN1_OBJECT_set_cmp_func(
                            user_policies_sorted,
                            Some(
                                asn1_object_cmp
                                    as unsafe extern "C" fn(
                                        *const *const ASN1_OBJECT,
                                        *const *const ASN1_OBJECT,
                                    ) -> libc::c_int,
                            ),
                        );
                        sk_ASN1_OBJECT_sort(user_policies_sorted);
                        if has_explicit_policy(levels, user_policies_sorted) == 0 {
                            ret = 43 as libc::c_int;
                            current_block = 18026953934680222107;
                        } else {
                            current_block = 6174974146017752131;
                        }
                    }
                } else {
                    current_block = 6174974146017752131;
                }
                match current_block {
                    18026953934680222107 => {}
                    _ => {
                        ret = 0 as libc::c_int;
                    }
                }
            }
        }
    }
    x509_policy_level_free(level);
    sk_ASN1_OBJECT_free(user_policies_sorted);
    sk_X509_POLICY_LEVEL_pop_free(
        levels,
        Some(
            x509_policy_level_free as unsafe extern "C" fn(*mut X509_POLICY_LEVEL) -> (),
        ),
    );
    return ret;
}
