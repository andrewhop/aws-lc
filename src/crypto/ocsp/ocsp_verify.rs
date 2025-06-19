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
    pub type asn1_null_st;
    pub type asn1_object_st;
    pub type ASN1_VALUE_st;
    pub type X509_name_st;
    pub type evp_pkey_st;
    pub type x509_st;
    pub type env_md_st;
    pub type stack_st_X509;
    pub type x509_store_ctx_st;
    pub type x509_store_st;
    pub type stack_st;
    pub type stack_st_X509_EXTENSION;
    pub type stack_st_OCSP_ONEREQ;
    pub type stack_st_OCSP_SINGLERESP;
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn X509_free(x509: *mut X509);
    fn X509_get_subject_name(x509: *const X509) -> *mut X509_NAME;
    fn X509_get0_pubkey(x509: *const X509) -> *mut EVP_PKEY;
    fn X509_get_pubkey(x509: *const X509) -> *mut EVP_PKEY;
    fn X509_get_extension_flags(x509: *mut X509) -> uint32_t;
    fn X509_get_extended_key_usage(x509: *mut X509) -> uint32_t;
    fn X509_STORE_CTX_new() -> *mut X509_STORE_CTX;
    fn X509_STORE_CTX_free(ctx: *mut X509_STORE_CTX);
    fn X509_STORE_CTX_init(
        ctx: *mut X509_STORE_CTX,
        store: *mut X509_STORE,
        x509: *mut X509,
        chain: *mut stack_st_X509,
    ) -> libc::c_int;
    fn X509_verify_cert(ctx: *mut X509_STORE_CTX) -> libc::c_int;
    fn X509_STORE_CTX_get1_chain(ctx: *mut X509_STORE_CTX) -> *mut stack_st_X509;
    fn X509_STORE_CTX_get_error(ctx: *mut X509_STORE_CTX) -> libc::c_int;
    fn X509_verify_cert_error_string(err: libc::c_long) -> *const libc::c_char;
    fn X509_STORE_CTX_set_purpose(
        ctx: *mut X509_STORE_CTX,
        purpose: libc::c_int,
    ) -> libc::c_int;
    fn X509_pubkey_digest(
        x509: *const X509,
        md: *const EVP_MD,
        out: *mut uint8_t,
        out_len: *mut libc::c_uint,
    ) -> libc::c_int;
    fn X509_NAME_digest(
        name: *const X509_NAME,
        md: *const EVP_MD,
        out: *mut uint8_t,
        out_len: *mut libc::c_uint,
    ) -> libc::c_int;
    fn X509_find_by_subject(sk: *const stack_st_X509, name: *mut X509_NAME) -> *mut X509;
    fn ASN1_item_verify(
        it: *const ASN1_ITEM,
        algor1: *const X509_ALGOR,
        signature: *const ASN1_BIT_STRING,
        data: *mut libc::c_void,
        pkey: *mut EVP_PKEY,
    ) -> libc::c_int;
    fn X509_check_trust(
        x509: *mut X509,
        id: libc::c_int,
        flags: libc::c_int,
    ) -> libc::c_int;
    fn X509_STORE_CTX_set_chain(ctx: *mut X509_STORE_CTX, sk: *mut stack_st_X509);
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_free(sk: *mut OPENSSL_STACK);
    fn OPENSSL_sk_pop_free_ex(
        sk: *mut OPENSSL_STACK,
        call_free_func: OPENSSL_sk_call_free_func,
        free_func: OPENSSL_sk_free_func,
    );
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn OPENSSL_sk_dup(sk: *const OPENSSL_STACK) -> *mut OPENSSL_STACK;
    fn EVP_sha1() -> *const EVP_MD;
    fn EVP_get_digestbyobj(obj: *const ASN1_OBJECT) -> *const EVP_MD;
    fn EVP_MD_size(md: *const EVP_MD) -> size_t;
    static OCSP_RESPDATA_it: ASN1_ITEM;
    static OCSP_REQINFO_it: ASN1_ITEM;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn ERR_add_error_data(count: libc::c_uint, _: ...);
    fn OBJ_cmp(a: *const ASN1_OBJECT, b: *const ASN1_OBJECT) -> libc::c_int;
    fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
    fn OCSP_id_issuer_cmp(a: *const OCSP_CERTID, b: *const OCSP_CERTID) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type ASN1_NULL = asn1_null_st;
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
pub type X509_NAME = X509_name_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct GENERAL_NAME_st {
    pub type_0: libc::c_int,
    pub d: C2RustUnnamed_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub ptr: *mut libc::c_char,
    pub otherName: *mut OTHERNAME,
    pub rfc822Name: *mut ASN1_IA5STRING,
    pub dNSName: *mut ASN1_IA5STRING,
    pub x400Address: *mut ASN1_STRING,
    pub directoryName: *mut X509_NAME,
    pub ediPartyName: *mut EDIPARTYNAME,
    pub uniformResourceIdentifier: *mut ASN1_IA5STRING,
    pub iPAddress: *mut ASN1_OCTET_STRING,
    pub registeredID: *mut ASN1_OBJECT,
    pub ip: *mut ASN1_OCTET_STRING,
    pub dirn: *mut X509_NAME,
    pub ia5: *mut ASN1_IA5STRING,
    pub rid: *mut ASN1_OBJECT,
}
pub type EDIPARTYNAME = EDIPartyName_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EDIPartyName_st {
    pub nameAssigner: *mut ASN1_STRING,
    pub partyName: *mut ASN1_STRING,
}
pub type OTHERNAME = otherName_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct otherName_st {
    pub type_id: *mut ASN1_OBJECT,
    pub value: *mut ASN1_TYPE,
}
pub type GENERAL_NAME = GENERAL_NAME_st;
pub type X509_ALGOR = X509_algor_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_algor_st {
    pub algorithm: *mut ASN1_OBJECT,
    pub parameter: *mut ASN1_TYPE,
}
pub type EVP_PKEY = evp_pkey_st;
pub type X509 = x509_st;
pub type EVP_MD = env_md_st;
pub type X509_STORE_CTX = x509_store_ctx_st;
pub type X509_STORE = x509_store_st;
pub type OPENSSL_sk_free_func = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type OPENSSL_sk_call_free_func = Option::<
    unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
>;
pub type OPENSSL_STACK = stack_st;
pub type sk_X509_free_func = Option::<unsafe extern "C" fn(*mut X509) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ocsp_cert_id_st {
    pub hashAlgorithm: *mut X509_ALGOR,
    pub issuerNameHash: *mut ASN1_OCTET_STRING,
    pub issuerKeyHash: *mut ASN1_OCTET_STRING,
    pub serialNumber: *mut ASN1_INTEGER,
}
pub type OCSP_CERTID = ocsp_cert_id_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ocsp_req_info_st {
    pub version: *mut ASN1_INTEGER,
    pub requestorName: *mut GENERAL_NAME,
    pub requestList: *mut stack_st_OCSP_ONEREQ,
    pub requestExtensions: *mut stack_st_X509_EXTENSION,
}
pub type OCSP_REQINFO = ocsp_req_info_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ocsp_signature_st {
    pub signatureAlgorithm: *mut X509_ALGOR,
    pub signature: *mut ASN1_BIT_STRING,
    pub certs: *mut stack_st_X509,
}
pub type OCSP_SIGNATURE = ocsp_signature_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ocsp_request_st {
    pub tbsRequest: *mut OCSP_REQINFO,
    pub optionalSignature: *mut OCSP_SIGNATURE,
}
pub type OCSP_REQUEST = ocsp_request_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ocsp_revoked_info_st {
    pub revocationTime: *mut ASN1_GENERALIZEDTIME,
    pub revocationReason: *mut ASN1_ENUMERATED,
}
pub type OCSP_REVOKEDINFO = ocsp_revoked_info_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ocsp_cert_status_st {
    pub type_0: libc::c_int,
    pub value: C2RustUnnamed_1,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_1 {
    pub good: *mut ASN1_NULL,
    pub revoked: *mut OCSP_REVOKEDINFO,
    pub unknown: *mut ASN1_NULL,
}
pub type OCSP_CERTSTATUS = ocsp_cert_status_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ocsp_single_response_st {
    pub certId: *mut OCSP_CERTID,
    pub certStatus: *mut OCSP_CERTSTATUS,
    pub thisUpdate: *mut ASN1_GENERALIZEDTIME,
    pub nextUpdate: *mut ASN1_GENERALIZEDTIME,
    pub singleExtensions: *mut stack_st_X509_EXTENSION,
}
pub type OCSP_SINGLERESP = ocsp_single_response_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ocsp_response_data_st {
    pub version: *mut ASN1_INTEGER,
    pub responderId: *mut OCSP_RESPID,
    pub producedAt: *mut ASN1_GENERALIZEDTIME,
    pub responses: *mut stack_st_OCSP_SINGLERESP,
    pub responseExtensions: *mut stack_st_X509_EXTENSION,
}
pub type OCSP_RESPID = ocsp_responder_id_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ocsp_responder_id_st {
    pub type_0: libc::c_int,
    pub value: C2RustUnnamed_2,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_2 {
    pub byName: *mut X509_NAME,
    pub byKey: *mut ASN1_OCTET_STRING,
}
pub type OCSP_RESPDATA = ocsp_response_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ocsp_basic_response_st {
    pub tbsResponseData: *mut OCSP_RESPDATA,
    pub signatureAlgorithm: *mut X509_ALGOR,
    pub signature: *mut ASN1_BIT_STRING,
    pub certs: *mut stack_st_X509,
}
pub type OCSP_BASICRESP = ocsp_basic_response_st;
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
unsafe extern "C" fn sk_X509_free(mut sk: *mut stack_st_X509) {
    OPENSSL_sk_free(sk as *mut OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_pop_free(
    mut sk: *mut stack_st_X509,
    mut free_func: sk_X509_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_X509_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<sk_X509_free_func, OPENSSL_sk_free_func>(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_X509_push(
    mut sk: *mut stack_st_X509,
    mut p: *mut X509,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_X509_dup(mut sk: *const stack_st_X509) -> *mut stack_st_X509 {
    return OPENSSL_sk_dup(sk as *const OPENSSL_STACK) as *mut stack_st_X509;
}
#[inline]
unsafe extern "C" fn sk_X509_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<OPENSSL_sk_free_func, sk_X509_free_func>(free_func))
        .expect("non-null function pointer")(ptr as *mut X509);
}
#[inline]
unsafe extern "C" fn sk_OCSP_SINGLERESP_num(
    mut sk: *const stack_st_OCSP_SINGLERESP,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_OCSP_SINGLERESP_value(
    mut sk: *const stack_st_OCSP_SINGLERESP,
    mut i: size_t,
) -> *mut OCSP_SINGLERESP {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut OCSP_SINGLERESP;
}
unsafe extern "C" fn ocsp_find_signer_sk(
    mut certs: *mut stack_st_X509,
    mut id: *mut OCSP_RESPID,
) -> *mut X509 {
    if certs.is_null() || id.is_null() {
        return 0 as *mut X509;
    }
    if (*id).type_0 == 0 as libc::c_int {
        return X509_find_by_subject(certs, (*id).value.byName);
    }
    let mut tmphash: [libc::c_uchar; 20] = [0; 20];
    let mut keyhash: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    if ((*id).value.byKey).is_null() || (*(*id).value.byKey).length != 20 as libc::c_int
    {
        return 0 as *mut X509;
    }
    keyhash = (*(*id).value.byKey).data;
    let mut cert: *mut X509 = 0 as *mut X509;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_X509_num(certs) {
        cert = sk_X509_value(certs, i);
        if X509_pubkey_digest(
            cert,
            EVP_sha1(),
            tmphash.as_mut_ptr(),
            0 as *mut libc::c_uint,
        ) != 0
        {
            if memcmp(
                keyhash as *const libc::c_void,
                tmphash.as_mut_ptr() as *const libc::c_void,
                20 as libc::c_int as libc::c_ulong,
            ) == 0 as libc::c_int
            {
                return cert;
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as *mut X509;
}
unsafe extern "C" fn ocsp_find_signer(
    mut psigner: *mut *mut X509,
    mut bs: *mut OCSP_BASICRESP,
    mut certs: *mut stack_st_X509,
    mut flags: libc::c_ulong,
) -> libc::c_int {
    if psigner.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0" as *const u8
                as *const libc::c_char,
            51 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    let mut signer: *mut X509 = 0 as *mut X509;
    let mut rid: *mut OCSP_RESPID = (*(*bs).tbsResponseData).responderId;
    signer = ocsp_find_signer_sk(certs, rid);
    if !signer.is_null() {
        *psigner = signer;
        return 2 as libc::c_int;
    }
    signer = ocsp_find_signer_sk((*bs).certs, rid);
    if !signer.is_null() && flags & 0x2 as libc::c_int as libc::c_ulong == 0 {
        *psigner = signer;
        return 1 as libc::c_int;
    }
    *psigner = 0 as *mut X509;
    return 0 as libc::c_int;
}
unsafe extern "C" fn ocsp_verify_key(
    mut bs: *mut OCSP_BASICRESP,
    mut signer: *mut X509,
) -> libc::c_int {
    if signer.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0" as *const u8
                as *const libc::c_char,
            80 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    let mut skey: *mut EVP_PKEY = X509_get_pubkey(signer);
    if skey.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            130 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0" as *const u8
                as *const libc::c_char,
            86 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    let mut ret: libc::c_int = ASN1_item_verify(
        &OCSP_RESPDATA_it,
        (*bs).signatureAlgorithm,
        (*bs).signature,
        (*bs).tbsResponseData as *mut libc::c_void,
        skey,
    );
    EVP_PKEY_free(skey);
    if ret <= 0 as libc::c_int {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            117 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0" as *const u8
                as *const libc::c_char,
            94 as libc::c_int as libc::c_uint,
        );
    }
    return ret;
}
unsafe extern "C" fn ocsp_setup_untrusted(
    mut bs: *mut OCSP_BASICRESP,
    mut certs: *mut stack_st_X509,
    mut untrusted: *mut *mut stack_st_X509,
    mut flags: libc::c_ulong,
) -> libc::c_int {
    if untrusted.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0" as *const u8
                as *const libc::c_char,
            105 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    if flags & 0x8 as libc::c_int as libc::c_ulong != 0 {
        *untrusted = 0 as *mut stack_st_X509;
    } else if !((*bs).certs).is_null() && !certs.is_null() {
        *untrusted = sk_X509_dup((*bs).certs);
        let mut i: size_t = 0 as libc::c_int as size_t;
        while i < sk_X509_num(certs) {
            if sk_X509_push(*untrusted, sk_X509_value(certs, i)) == 0 {
                return -(1 as libc::c_int);
            }
            i = i.wrapping_add(1);
            i;
        }
    } else if !certs.is_null() {
        *untrusted = sk_X509_dup(certs);
    } else {
        *untrusted = sk_X509_dup((*bs).certs);
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn ocsp_verify_signer(
    mut signer: *mut X509,
    mut st: *mut X509_STORE,
    mut untrusted: *mut stack_st_X509,
    mut chain: *mut *mut stack_st_X509,
) -> libc::c_int {
    if signer.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0" as *const u8
                as *const libc::c_char,
            130 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    let mut ctx: *mut X509_STORE_CTX = X509_STORE_CTX_new();
    let mut ret: libc::c_int = -(1 as libc::c_int);
    if !ctx.is_null() {
        if X509_STORE_CTX_init(ctx, st, signer, untrusted) == 0 {
            ERR_put_error(
                23 as libc::c_int,
                0 as libc::c_int,
                11 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0"
                    as *const u8 as *const libc::c_char,
                142 as libc::c_int as libc::c_uint,
            );
        } else if X509_STORE_CTX_set_purpose(ctx, 8 as libc::c_int) == 0 {
            ERR_put_error(
                23 as libc::c_int,
                0 as libc::c_int,
                11 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0"
                    as *const u8 as *const libc::c_char,
                146 as libc::c_int as libc::c_uint,
            );
        } else {
            ret = X509_verify_cert(ctx);
            if ret <= 0 as libc::c_int {
                let mut err: libc::c_int = X509_STORE_CTX_get_error(ctx);
                ERR_put_error(
                    23 as libc::c_int,
                    0 as libc::c_int,
                    101 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0"
                        as *const u8 as *const libc::c_char,
                    154 as libc::c_int as libc::c_uint,
                );
                ERR_add_error_data(
                    2 as libc::c_int as libc::c_uint,
                    b"Verify error: \0" as *const u8 as *const libc::c_char,
                    X509_verify_cert_error_string(err as libc::c_long),
                );
            } else if !chain.is_null() {
                *chain = X509_STORE_CTX_get1_chain(ctx);
            }
        }
    }
    X509_STORE_CTX_free(ctx);
    return ret;
}
unsafe extern "C" fn ocsp_check_ids(
    mut sresp: *mut stack_st_OCSP_SINGLERESP,
    mut ret: *mut *mut OCSP_CERTID,
) -> libc::c_int {
    if sresp.is_null() || ret.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0" as *const u8
                as *const libc::c_char,
            173 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    let mut tmpid: *mut OCSP_CERTID = 0 as *mut OCSP_CERTID;
    let mut cid: *mut OCSP_CERTID = 0 as *mut OCSP_CERTID;
    let mut idcount: size_t = sk_OCSP_SINGLERESP_num(sresp);
    if idcount == 0 as libc::c_int as size_t {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            111 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0" as *const u8
                as *const libc::c_char,
            180 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    cid = (*sk_OCSP_SINGLERESP_value(sresp, 0 as libc::c_int as size_t)).certId;
    *ret = 0 as *mut OCSP_CERTID;
    let mut i: size_t = 1 as libc::c_int as size_t;
    while i < idcount {
        tmpid = (*sk_OCSP_SINGLERESP_value(sresp, i)).certId;
        if OCSP_id_issuer_cmp(cid, tmpid) != 0 as libc::c_int {
            if OBJ_cmp(
                (*(*tmpid).hashAlgorithm).algorithm,
                (*(*cid).hashAlgorithm).algorithm,
            ) != 0 as libc::c_int
            {
                return 1 as libc::c_int;
            }
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    *ret = cid;
    return 1 as libc::c_int;
}
unsafe extern "C" fn ocsp_match_issuerid(
    mut cert: *mut X509,
    mut cid: *mut OCSP_CERTID,
    mut sresp: *mut stack_st_OCSP_SINGLERESP,
) -> libc::c_int {
    if cert.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0" as *const u8
                as *const libc::c_char,
            207 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    if !cid.is_null() {
        let mut dgst: *const EVP_MD = 0 as *const EVP_MD;
        let mut iname: *mut X509_NAME = 0 as *mut X509_NAME;
        let mut md: [libc::c_uchar; 64] = [0; 64];
        dgst = EVP_get_digestbyobj((*(*cid).hashAlgorithm).algorithm);
        if dgst.is_null() {
            ERR_put_error(
                23 as libc::c_int,
                0 as libc::c_int,
                119 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0"
                    as *const u8 as *const libc::c_char,
                219 as libc::c_int as libc::c_uint,
            );
            return -(1 as libc::c_int);
        }
        let mut mdlen: size_t = EVP_MD_size(dgst);
        iname = X509_get_subject_name(cert);
        if X509_NAME_digest(iname, dgst, md.as_mut_ptr(), 0 as *mut libc::c_uint) == 0 {
            return -(1 as libc::c_int);
        }
        if (*(*cid).issuerNameHash).length >= 0 as libc::c_int
            && (*(*cid).issuerKeyHash).length >= 0 as libc::c_int
        {
            if (*(*cid).issuerNameHash).length as size_t != mdlen
                || (*(*cid).issuerKeyHash).length as size_t != mdlen
            {
                return 0 as libc::c_int;
            }
        }
        if memcmp(
            md.as_mut_ptr() as *const libc::c_void,
            (*(*cid).issuerNameHash).data as *const libc::c_void,
            mdlen,
        ) != 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        if 0 as libc::c_int
            <= X509_pubkey_digest(cert, dgst, md.as_mut_ptr(), 0 as *mut libc::c_uint)
        {
            if memcmp(
                md.as_mut_ptr() as *const libc::c_void,
                (*(*cid).issuerKeyHash).data as *const libc::c_void,
                mdlen,
            ) != 0 as libc::c_int
            {
                return 0 as libc::c_int;
            }
        }
        return 1 as libc::c_int;
    } else {
        let mut ret: libc::c_int = 0;
        let mut tmpid: *mut OCSP_CERTID = 0 as *mut OCSP_CERTID;
        let mut i: size_t = 0 as libc::c_int as size_t;
        while i < sk_OCSP_SINGLERESP_num(sresp) {
            tmpid = (*sk_OCSP_SINGLERESP_value(sresp, i)).certId;
            ret = ocsp_match_issuerid(cert, tmpid, 0 as *mut stack_st_OCSP_SINGLERESP);
            if ret <= 0 as libc::c_int {
                return ret;
            }
            i = i.wrapping_add(1);
            i;
        }
        return 1 as libc::c_int;
    };
}
unsafe extern "C" fn ocsp_check_delegated(mut x: *mut X509) -> libc::c_int {
    if x.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0" as *const u8
                as *const libc::c_char,
            269 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    if X509_get_extension_flags(x) & 0x4 as libc::c_int as uint32_t != 0
        && X509_get_extended_key_usage(x) & 0x20 as libc::c_int as uint32_t != 0
    {
        return 1 as libc::c_int;
    }
    ERR_put_error(
        23 as libc::c_int,
        0 as libc::c_int,
        103 as libc::c_int,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0" as *const u8
            as *const libc::c_char,
        277 as libc::c_int as libc::c_uint,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn ocsp_check_issuer(
    mut bs: *mut OCSP_BASICRESP,
    mut chain: *mut stack_st_X509,
) -> libc::c_int {
    if chain.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0" as *const u8
                as *const libc::c_char,
            284 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    let mut sresp: *mut stack_st_OCSP_SINGLERESP = (*(*bs).tbsResponseData).responses;
    let mut caid: *mut OCSP_CERTID = 0 as *mut OCSP_CERTID;
    let mut ret: libc::c_int = 0;
    if sk_X509_num(chain) <= 0 as libc::c_int as size_t {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0" as *const u8
                as *const libc::c_char,
            293 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    ret = ocsp_check_ids(sresp, &mut caid);
    if ret <= 0 as libc::c_int {
        return ret;
    }
    let mut signer: *mut X509 = 0 as *mut X509;
    let mut sca: *mut X509 = 0 as *mut X509;
    signer = sk_X509_value(chain, 0 as libc::c_int as size_t);
    if sk_X509_num(chain) > 1 as libc::c_int as size_t {
        sca = sk_X509_value(chain, 1 as libc::c_int as size_t);
        ret = ocsp_match_issuerid(sca, caid, sresp);
        if ret < 0 as libc::c_int {
            return ret;
        }
        if ret != 0 as libc::c_int {
            if ocsp_check_delegated(signer) != 0 {
                return 1 as libc::c_int;
            }
            return 0 as libc::c_int;
        }
    }
    return ocsp_match_issuerid(signer, caid, sresp);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_basic_verify(
    mut bs: *mut OCSP_BASICRESP,
    mut certs: *mut stack_st_X509,
    mut st: *mut X509_STORE,
    mut flags: libc::c_ulong,
) -> libc::c_int {
    if bs.is_null() || st.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0" as *const u8
                as *const libc::c_char,
            330 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    let mut signer: *mut X509 = 0 as *mut X509;
    let mut chain: *mut stack_st_X509 = 0 as *mut stack_st_X509;
    let mut untrusted: *mut stack_st_X509 = 0 as *mut stack_st_X509;
    let mut ret: libc::c_int = ocsp_find_signer(&mut signer, bs, certs, flags);
    if ret <= 0 as libc::c_int {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            118 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0" as *const u8
                as *const libc::c_char,
            341 as libc::c_int as libc::c_uint,
        );
    } else {
        if ret == 2 as libc::c_int && flags & 0x200 as libc::c_int as libc::c_ulong != 0
        {
            flags |= 0x10 as libc::c_int as libc::c_ulong;
        }
        ret = ocsp_verify_key(bs, signer);
        if !(ret <= 0 as libc::c_int) {
            if flags & 0x10 as libc::c_int as libc::c_ulong == 0 {
                ret = ocsp_setup_untrusted(bs, certs, &mut untrusted, flags);
                if !(ret <= 0 as libc::c_int) {
                    ret = ocsp_verify_signer(signer, st, untrusted, &mut chain);
                    if !(ret <= 0 as libc::c_int) {
                        ret = ocsp_check_issuer(bs, chain);
                        if ret == 0 as libc::c_int {
                            if !(flags & 0x20 as libc::c_int as libc::c_ulong != 0) {
                                let mut root_cert: *mut X509 = sk_X509_value(
                                    chain,
                                    (sk_X509_num(chain))
                                        .wrapping_sub(1 as libc::c_int as size_t),
                                );
                                if X509_check_trust(
                                    root_cert,
                                    180 as libc::c_int,
                                    0 as libc::c_int,
                                ) != 1 as libc::c_int
                                {
                                    ERR_put_error(
                                        23 as libc::c_int,
                                        0 as libc::c_int,
                                        112 as libc::c_int,
                                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0"
                                            as *const u8 as *const libc::c_char,
                                        381 as libc::c_int as libc::c_uint,
                                    );
                                    ret = 0 as libc::c_int;
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
    sk_X509_pop_free(chain, Some(X509_free as unsafe extern "C" fn(*mut X509) -> ()));
    sk_X509_free(untrusted);
    return ret;
}
unsafe extern "C" fn ocsp_req_find_signer(
    mut psigner: *mut *mut X509,
    mut req: *mut OCSP_REQUEST,
    mut nm: *mut X509_NAME,
    mut certs: *mut stack_st_X509,
    mut flags: libc::c_ulong,
) -> libc::c_int {
    let mut signer: *mut X509 = 0 as *mut X509;
    if flags & 0x2 as libc::c_int as libc::c_ulong == 0 {
        signer = X509_find_by_subject((*(*req).optionalSignature).certs, nm);
        if !signer.is_null() {
            *psigner = signer;
            return 1 as libc::c_int;
        }
    }
    signer = X509_find_by_subject(certs, nm);
    if !signer.is_null() {
        *psigner = signer;
        return 2 as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_request_verify(
    mut req: *mut OCSP_REQUEST,
    mut certs: *mut stack_st_X509,
    mut store: *mut X509_STORE,
    mut flags: libc::c_ulong,
) -> libc::c_int {
    let mut current_block: u64;
    if req.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0" as *const u8
                as *const libc::c_char,
            421 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*req).tbsRequest).is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0" as *const u8
                as *const libc::c_char,
            422 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if store.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0" as *const u8
                as *const libc::c_char,
            423 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*req).optionalSignature).is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            128 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0" as *const u8
                as *const libc::c_char,
            427 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut gen: *mut GENERAL_NAME = (*(*req).tbsRequest).requestorName;
    if gen.is_null() || (*gen).type_0 != 4 as libc::c_int {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            129 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0" as *const u8
                as *const libc::c_char,
            433 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut signer: *mut X509 = 0 as *mut X509;
    let mut signer_status: libc::c_int = ocsp_req_find_signer(
        &mut signer,
        req,
        (*gen).d.directoryName,
        certs,
        flags,
    );
    if signer_status <= 0 as libc::c_int || signer.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            118 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0" as *const u8
                as *const libc::c_char,
            442 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if signer_status == 2 as libc::c_int
        && flags & 0x200 as libc::c_int as libc::c_ulong != 0
    {
        flags |= 0x10 as libc::c_int as libc::c_ulong;
    }
    let mut skey: *mut EVP_PKEY = X509_get0_pubkey(signer);
    if skey.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            130 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0" as *const u8
                as *const libc::c_char,
            455 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ASN1_item_verify(
        &OCSP_REQINFO_it,
        (*(*req).optionalSignature).signatureAlgorithm,
        (*(*req).optionalSignature).signature,
        (*req).tbsRequest as *mut libc::c_void,
        skey,
    ) <= 0 as libc::c_int
    {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            117 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0" as *const u8
                as *const libc::c_char,
            462 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ctx: *mut X509_STORE_CTX = X509_STORE_CTX_new();
    if ctx.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    if flags & 0x10 as libc::c_int as libc::c_ulong == 0 {
        if X509_STORE_CTX_init(ctx, store, signer, 0 as *mut stack_st_X509) == 0
            && X509_STORE_CTX_set_purpose(ctx, 8 as libc::c_int) == 0
        {
            ERR_put_error(
                23 as libc::c_int,
                0 as libc::c_int,
                11 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0"
                    as *const u8 as *const libc::c_char,
                478 as libc::c_int as libc::c_uint,
            );
            current_block = 16673715350065226114;
        } else {
            if flags & 0x8 as libc::c_int as libc::c_ulong == 0 {
                X509_STORE_CTX_set_chain(ctx, (*(*req).optionalSignature).certs);
            }
            if X509_verify_cert(ctx) <= 0 as libc::c_int {
                let mut err: libc::c_int = X509_STORE_CTX_get_error(ctx);
                ERR_put_error(
                    23 as libc::c_int,
                    0 as libc::c_int,
                    101 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_verify.c\0"
                        as *const u8 as *const libc::c_char,
                    488 as libc::c_int as libc::c_uint,
                );
                ERR_add_error_data(
                    2 as libc::c_int as libc::c_uint,
                    b"Verify error:\0" as *const u8 as *const libc::c_char,
                    X509_verify_cert_error_string(err as libc::c_long),
                );
                current_block = 16673715350065226114;
            } else {
                current_block = 5330834795799507926;
            }
        }
    } else {
        current_block = 5330834795799507926;
    }
    match current_block {
        5330834795799507926 => {
            ret = 1 as libc::c_int;
        }
        _ => {}
    }
    X509_STORE_CTX_free(ctx);
    return ret;
}
