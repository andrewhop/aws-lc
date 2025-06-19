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
    pub type engine_st;
    pub type evp_md_pctx_ops;
    pub type evp_pkey_ctx_st;
    pub type env_md_st;
    pub type stack_st_X509;
    pub type stack_st;
    pub type stack_st_X509_EXTENSION;
    pub type stack_st_OCSP_ONEREQ;
    pub type stack_st_OCSP_SINGLERESP;
    fn ASN1_item_pack(
        obj: *mut libc::c_void,
        it: *const ASN1_ITEM,
        out: *mut *mut ASN1_STRING,
    ) -> *mut ASN1_STRING;
    fn ASN1_OCTET_STRING_new() -> *mut ASN1_OCTET_STRING;
    fn ASN1_OCTET_STRING_free(str: *mut ASN1_OCTET_STRING);
    fn ASN1_OCTET_STRING_set(
        str: *mut ASN1_OCTET_STRING,
        data: *const libc::c_uchar,
        len: libc::c_int,
    ) -> libc::c_int;
    fn ASN1_ENUMERATED_new() -> *mut ASN1_ENUMERATED;
    fn ASN1_GENERALIZEDTIME_set(
        s: *mut ASN1_GENERALIZEDTIME,
        posix_time: int64_t,
    ) -> *mut ASN1_GENERALIZEDTIME;
    fn ASN1_TIME_to_generalizedtime(
        t: *const ASN1_TIME,
        out: *mut *mut ASN1_GENERALIZEDTIME,
    ) -> *mut ASN1_GENERALIZEDTIME;
    fn ASN1_NULL_new() -> *mut ASN1_NULL;
    fn ASN1_ENUMERATED_set(a: *mut ASN1_ENUMERATED, v: libc::c_long) -> libc::c_int;
    fn X509_up_ref(x509: *mut X509) -> libc::c_int;
    fn X509_get_subject_name(x509: *const X509) -> *mut X509_NAME;
    fn X509_check_private_key(x509: *const X509, pkey: *const EVP_PKEY) -> libc::c_int;
    fn X509_NAME_set(xn: *mut *mut X509_NAME, name: *mut X509_NAME) -> libc::c_int;
    fn X509_pubkey_digest(
        x509: *const X509,
        md: *const EVP_MD,
        out: *mut uint8_t,
        out_len: *mut libc::c_uint,
    ) -> libc::c_int;
    fn ASN1_item_sign_ctx(
        it: *const ASN1_ITEM,
        algor1: *mut X509_ALGOR,
        algor2: *mut X509_ALGOR,
        signature: *mut ASN1_BIT_STRING,
        asn: *mut libc::c_void,
        ctx: *mut EVP_MD_CTX,
    ) -> libc::c_int;
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn EVP_sha1() -> *const EVP_MD;
    fn EVP_sha256() -> *const EVP_MD;
    fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX;
    fn EVP_MD_CTX_free(ctx: *mut EVP_MD_CTX);
    static OCSP_RESPDATA_it: ASN1_ITEM;
    fn OCSP_RESPBYTES_new() -> *mut OCSP_RESPBYTES;
    fn OCSP_REVOKEDINFO_new() -> *mut OCSP_REVOKEDINFO;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn time(__timer: *mut time_t) -> time_t;
    fn OBJ_nid2obj(nid: libc::c_int) -> *mut ASN1_OBJECT;
    fn EVP_PKEY_id(pkey: *const EVP_PKEY) -> libc::c_int;
    fn EVP_DigestSignInit(
        ctx: *mut EVP_MD_CTX,
        pctx: *mut *mut EVP_PKEY_CTX,
        type_0: *const EVP_MD,
        e: *mut ENGINE,
        pkey: *mut EVP_PKEY,
    ) -> libc::c_int;
    fn EVP_PKEY_CTX_get0_pkey(ctx: *mut EVP_PKEY_CTX) -> *mut EVP_PKEY;
    static OCSP_BASICRESP_it: ASN1_ITEM;
    fn OCSP_RESPONSE_new() -> *mut OCSP_RESPONSE;
    fn OCSP_RESPONSE_free(a: *mut OCSP_RESPONSE);
    fn OCSP_CERTID_free(a: *mut OCSP_CERTID);
    fn OCSP_SINGLERESP_new() -> *mut OCSP_SINGLERESP;
    fn OCSP_SINGLERESP_free(a: *mut OCSP_SINGLERESP);
    fn OCSP_CERTID_dup(id: *mut OCSP_CERTID) -> *mut OCSP_CERTID;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type int64_t = __int64_t;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type time_t = __time_t;
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
pub type ENGINE = engine_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct env_md_ctx_st {
    pub digest: *const EVP_MD,
    pub md_data: *mut libc::c_void,
    pub update: Option::<
        unsafe extern "C" fn(*mut EVP_MD_CTX, *const libc::c_void, size_t) -> libc::c_int,
    >,
    pub pctx: *mut EVP_PKEY_CTX,
    pub pctx_ops: *const evp_md_pctx_ops,
    pub flags: libc::c_ulong,
}
pub type EVP_PKEY_CTX = evp_pkey_ctx_st;
pub type EVP_MD_CTX = env_md_ctx_st;
pub type EVP_MD = env_md_st;
pub type OPENSSL_STACK = stack_st;
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
pub struct ocsp_one_request_st {
    pub reqCert: *mut OCSP_CERTID,
    pub singleRequestExtensions: *mut stack_st_X509_EXTENSION,
}
pub type OCSP_ONEREQ = ocsp_one_request_st;
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
pub struct ocsp_resp_bytes_st {
    pub responseType: *mut ASN1_OBJECT,
    pub response: *mut ASN1_OCTET_STRING,
}
pub type OCSP_RESPBYTES = ocsp_resp_bytes_st;
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
pub struct ocsp_response_st {
    pub responseStatus: *mut ASN1_ENUMERATED,
    pub responseBytes: *mut OCSP_RESPBYTES,
}
pub type OCSP_RESPONSE = ocsp_response_st;
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
unsafe extern "C" fn sk_X509_new_null() -> *mut stack_st_X509 {
    return OPENSSL_sk_new_null() as *mut stack_st_X509;
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
unsafe extern "C" fn sk_X509_push(
    mut sk: *mut stack_st_X509,
    mut p: *mut X509,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_OCSP_ONEREQ_num(mut sk: *const stack_st_OCSP_ONEREQ) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_OCSP_ONEREQ_value(
    mut sk: *const stack_st_OCSP_ONEREQ,
    mut i: size_t,
) -> *mut OCSP_ONEREQ {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut OCSP_ONEREQ;
}
#[inline]
unsafe extern "C" fn sk_OCSP_SINGLERESP_push(
    mut sk: *mut stack_st_OCSP_SINGLERESP,
    mut p: *mut OCSP_SINGLERESP,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_OCSP_SINGLERESP_new_null() -> *mut stack_st_OCSP_SINGLERESP {
    return OPENSSL_sk_new_null() as *mut stack_st_OCSP_SINGLERESP;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_request_onereq_count(
    mut req: *mut OCSP_REQUEST,
) -> libc::c_int {
    if req.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0" as *const u8
                as *const libc::c_char,
            17 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ((*req).tbsRequest).is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0" as *const u8
                as *const libc::c_char,
            18 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return sk_OCSP_ONEREQ_num((*(*req).tbsRequest).requestList) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_request_onereq_get0(
    mut req: *mut OCSP_REQUEST,
    mut i: libc::c_int,
) -> *mut OCSP_ONEREQ {
    if req.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0" as *const u8
                as *const libc::c_char,
            23 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut OCSP_ONEREQ;
    }
    if ((*req).tbsRequest).is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0" as *const u8
                as *const libc::c_char,
            24 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut OCSP_ONEREQ;
    }
    return sk_OCSP_ONEREQ_value((*(*req).tbsRequest).requestList, i as size_t);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_id_get0_info(
    mut nameHash: *mut *mut ASN1_OCTET_STRING,
    mut algor: *mut *mut ASN1_OBJECT,
    mut keyHash: *mut *mut ASN1_OCTET_STRING,
    mut serial: *mut *mut ASN1_INTEGER,
    mut cid: *mut OCSP_CERTID,
) -> libc::c_int {
    if cid.is_null() {
        return 0 as libc::c_int;
    }
    if !algor.is_null() {
        *algor = (*(*cid).hashAlgorithm).algorithm;
    }
    if !nameHash.is_null() {
        *nameHash = (*cid).issuerNameHash;
    }
    if !keyHash.is_null() {
        *keyHash = (*cid).issuerKeyHash;
    }
    if !serial.is_null() {
        *serial = (*cid).serialNumber;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_request_is_signed(
    mut req: *mut OCSP_REQUEST,
) -> libc::c_int {
    if req.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0" as *const u8
                as *const libc::c_char,
            50 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if !((*req).optionalSignature).is_null() {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_onereq_get0_id(
    mut one: *mut OCSP_ONEREQ,
) -> *mut OCSP_CERTID {
    if one.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0" as *const u8
                as *const libc::c_char,
            58 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut OCSP_CERTID;
    }
    return (*one).reqCert;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_basic_add1_cert(
    mut resp: *mut OCSP_BASICRESP,
    mut cert: *mut X509,
) -> libc::c_int {
    if ((*resp).certs).is_null()
        && {
            (*resp).certs = sk_X509_new_null();
            ((*resp).certs).is_null()
        }
    {
        return 0 as libc::c_int;
    }
    if sk_X509_push((*resp).certs, cert) == 0 {
        return 0 as libc::c_int;
    }
    X509_up_ref(cert);
    return 1 as libc::c_int;
}
unsafe extern "C" fn OCSP_RESPID_set_by_name(
    mut respid: *mut OCSP_RESPID,
    mut cert: *mut X509,
) -> libc::c_int {
    if respid.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0" as *const u8
                as *const libc::c_char,
            75 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if cert.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0" as *const u8
                as *const libc::c_char,
            76 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if X509_NAME_set(&mut (*respid).value.byName, X509_get_subject_name(cert)) == 0 {
        return 0 as libc::c_int;
    }
    (*respid).type_0 = 0 as libc::c_int;
    return 1 as libc::c_int;
}
unsafe extern "C" fn OCSP_RESPID_set_by_key(
    mut respid: *mut OCSP_RESPID,
    mut cert: *mut X509,
) -> libc::c_int {
    if respid.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0" as *const u8
                as *const libc::c_char,
            86 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if cert.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0" as *const u8
                as *const libc::c_char,
            87 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut digest: [libc::c_uchar; 20] = [0; 20];
    if X509_pubkey_digest(cert, EVP_sha1(), digest.as_mut_ptr(), 0 as *mut libc::c_uint)
        == 0
    {
        return 0 as libc::c_int;
    }
    let mut byKey: *mut ASN1_OCTET_STRING = ASN1_OCTET_STRING_new();
    if byKey.is_null() {
        return 0 as libc::c_int;
    }
    if ASN1_OCTET_STRING_set(byKey, digest.as_mut_ptr(), 20 as libc::c_int) == 0 {
        ASN1_OCTET_STRING_free(byKey);
        return 0 as libc::c_int;
    }
    (*respid).type_0 = 1 as libc::c_int;
    (*respid).value.byKey = byKey;
    return 1 as libc::c_int;
}
unsafe extern "C" fn OCSP_basic_sign_ctx(
    mut resp: *mut OCSP_BASICRESP,
    mut signer: *mut X509,
    mut ctx: *mut EVP_MD_CTX,
    mut certs: *mut stack_st_X509,
    mut flags: libc::c_ulong,
) -> libc::c_int {
    if resp.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0" as *const u8
                as *const libc::c_char,
            116 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if signer.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0" as *const u8
                as *const libc::c_char,
            117 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if ctx.is_null() || ((*ctx).pctx).is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            130 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0" as *const u8
                as *const libc::c_char,
            120 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut pkey: *mut EVP_PKEY = EVP_PKEY_CTX_get0_pkey((*ctx).pctx);
    if pkey.is_null() || X509_check_private_key(signer, pkey) == 0 {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            110 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0" as *const u8
                as *const libc::c_char,
            126 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if flags & 0x1 as libc::c_int as libc::c_ulong == 0 {
        if OCSP_basic_add1_cert(resp, signer) == 0 {
            return 0 as libc::c_int;
        }
        let mut i: size_t = 0 as libc::c_int as size_t;
        while i < sk_X509_num(certs) {
            let mut tmpcert: *mut X509 = sk_X509_value(certs, i);
            if OCSP_basic_add1_cert(resp, tmpcert) == 0 {
                return 0 as libc::c_int;
            }
            i = i.wrapping_add(1);
            i;
        }
    }
    let mut rid: *mut OCSP_RESPID = (*(*resp).tbsResponseData).responderId;
    if flags & 0x400 as libc::c_int as libc::c_ulong != 0 {
        if OCSP_RESPID_set_by_key(rid, signer) == 0 {
            return 0 as libc::c_int;
        }
    } else if OCSP_RESPID_set_by_name(rid, signer) == 0 {
        return 0 as libc::c_int
    }
    if flags & 0x800 as libc::c_int as libc::c_ulong == 0 {
        if (ASN1_GENERALIZEDTIME_set(
            (*(*resp).tbsResponseData).producedAt,
            time(0 as *mut time_t),
        ))
            .is_null()
        {
            return 0 as libc::c_int;
        }
    }
    if ASN1_item_sign_ctx(
        &OCSP_RESPDATA_it,
        (*resp).signatureAlgorithm,
        0 as *mut X509_ALGOR,
        (*resp).signature,
        (*resp).tbsResponseData as *mut libc::c_void,
        ctx,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_get_default_digest(
    mut dgst: *const EVP_MD,
    mut signer: *mut EVP_PKEY,
) -> *const EVP_MD {
    if !dgst.is_null() {
        return dgst;
    }
    let mut pkey_nid: libc::c_int = EVP_PKEY_id(signer);
    if pkey_nid == 408 as libc::c_int || pkey_nid == 6 as libc::c_int
        || pkey_nid == 116 as libc::c_int
    {
        return EVP_sha256();
    }
    return 0 as *const EVP_MD;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_basic_sign(
    mut resp: *mut OCSP_BASICRESP,
    mut signer: *mut X509,
    mut key: *mut EVP_PKEY,
    mut dgst: *const EVP_MD,
    mut certs: *mut stack_st_X509,
    mut flags: libc::c_ulong,
) -> libc::c_int {
    if resp.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0" as *const u8
                as *const libc::c_char,
            190 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if signer.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0" as *const u8
                as *const libc::c_char,
            191 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if key.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0" as *const u8
                as *const libc::c_char,
            192 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut init_dgst: *const EVP_MD = OCSP_get_default_digest(dgst, key);
    if init_dgst.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            119 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0" as *const u8
                as *const libc::c_char,
            196 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ctx: *mut EVP_MD_CTX = EVP_MD_CTX_new();
    if ctx.is_null() {
        return 0 as libc::c_int;
    }
    if EVP_DigestSignInit(
        ctx,
        0 as *mut *mut EVP_PKEY_CTX,
        init_dgst,
        0 as *mut ENGINE,
        key,
    ) == 0
    {
        EVP_MD_CTX_free(ctx);
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = OCSP_basic_sign_ctx(resp, signer, ctx, certs, flags);
    EVP_MD_CTX_free(ctx);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_basic_add1_status(
    mut resp: *mut OCSP_BASICRESP,
    mut cid: *mut OCSP_CERTID,
    mut status: libc::c_int,
    mut revoked_reason: libc::c_int,
    mut revoked_time: *mut ASN1_TIME,
    mut this_update: *mut ASN1_TIME,
    mut next_update: *mut ASN1_TIME,
) -> *mut OCSP_SINGLERESP {
    let mut info: *mut OCSP_REVOKEDINFO = 0 as *mut OCSP_REVOKEDINFO;
    let mut current_block: u64;
    if resp.is_null() || ((*resp).tbsResponseData).is_null() || cid.is_null()
        || this_update.is_null()
    {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0" as *const u8
                as *const libc::c_char,
            221 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut OCSP_SINGLERESP;
    }
    if status < 0 as libc::c_int || status > 2 as libc::c_int {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            132 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0" as *const u8
                as *const libc::c_char,
            227 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut OCSP_SINGLERESP;
    }
    let mut single: *mut OCSP_SINGLERESP = OCSP_SINGLERESP_new();
    if !single.is_null() {
        if ((*(*resp).tbsResponseData).responses).is_null() {
            (*(*resp).tbsResponseData).responses = sk_OCSP_SINGLERESP_new_null();
            if ((*(*resp).tbsResponseData).responses).is_null() {
                current_block = 1192491949871105541;
            } else {
                current_block = 1917311967535052937;
            }
        } else {
            current_block = 1917311967535052937;
        }
        match current_block {
            1192491949871105541 => {}
            _ => {
                if !(ASN1_TIME_to_generalizedtime(
                    this_update,
                    &mut (*single).thisUpdate,
                ))
                    .is_null()
                {
                    if !next_update.is_null() {
                        if (ASN1_TIME_to_generalizedtime(
                            next_update,
                            &mut (*single).nextUpdate,
                        ))
                            .is_null()
                        {
                            current_block = 1192491949871105541;
                        } else {
                            current_block = 12349973810996921269;
                        }
                    } else {
                        current_block = 12349973810996921269;
                    }
                    match current_block {
                        1192491949871105541 => {}
                        _ => {
                            OCSP_CERTID_free((*single).certId);
                            (*single).certId = OCSP_CERTID_dup(cid);
                            if !((*single).certId).is_null() {
                                (*(*single).certStatus).type_0 = status;
                                match (*(*single).certStatus).type_0 {
                                    1 => {
                                        current_block = 11711157500043780712;
                                        match current_block {
                                            2871512926265210112 => {
                                                (*(*single).certStatus).value.unknown = ASN1_NULL_new();
                                                if ((*(*single).certStatus).value.unknown).is_null() {
                                                    current_block = 1192491949871105541;
                                                } else {
                                                    current_block = 7245201122033322888;
                                                }
                                            }
                                            14764605651087521687 => {
                                                (*(*single).certStatus).value.good = ASN1_NULL_new();
                                                if ((*(*single).certStatus).value.good).is_null() {
                                                    current_block = 1192491949871105541;
                                                } else {
                                                    current_block = 7245201122033322888;
                                                }
                                            }
                                            _ => {
                                                if revoked_time.is_null() {
                                                    ERR_put_error(
                                                        23 as libc::c_int,
                                                        0 as libc::c_int,
                                                        109 as libc::c_int,
                                                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0"
                                                            as *const u8 as *const libc::c_char,
                                                        266 as libc::c_int as libc::c_uint,
                                                    );
                                                    current_block = 1192491949871105541;
                                                } else {
                                                    (*(*single).certStatus)
                                                        .value
                                                        .revoked = OCSP_REVOKEDINFO_new();
                                                    if ((*(*single).certStatus).value.revoked).is_null() {
                                                        current_block = 1192491949871105541;
                                                    } else {
                                                        info = (*(*single).certStatus).value.revoked;
                                                        if (ASN1_TIME_to_generalizedtime(
                                                            revoked_time,
                                                            &mut (*info).revocationTime,
                                                        ))
                                                            .is_null()
                                                        {
                                                            current_block = 1192491949871105541;
                                                        } else if revoked_reason < 0 as libc::c_int
                                                            || revoked_reason > 10 as libc::c_int
                                                            || revoked_reason == 7 as libc::c_int
                                                        {
                                                            ERR_put_error(
                                                                23 as libc::c_int,
                                                                0 as libc::c_int,
                                                                132 as libc::c_int,
                                                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0"
                                                                    as *const u8 as *const libc::c_char,
                                                                285 as libc::c_int as libc::c_uint,
                                                            );
                                                            current_block = 1192491949871105541;
                                                        } else {
                                                            (*info).revocationReason = ASN1_ENUMERATED_new();
                                                            if ((*info).revocationReason).is_null()
                                                                || ASN1_ENUMERATED_set(
                                                                    (*info).revocationReason,
                                                                    revoked_reason as libc::c_long,
                                                                ) == 0
                                                            {
                                                                current_block = 1192491949871105541;
                                                            } else {
                                                                current_block = 7245201122033322888;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        match current_block {
                                            1192491949871105541 => {}
                                            _ => {
                                                if !(sk_OCSP_SINGLERESP_push(
                                                    (*(*resp).tbsResponseData).responses,
                                                    single,
                                                ) == 0)
                                                {
                                                    return single;
                                                }
                                            }
                                        }
                                    }
                                    0 => {
                                        current_block = 14764605651087521687;
                                        match current_block {
                                            2871512926265210112 => {
                                                (*(*single).certStatus).value.unknown = ASN1_NULL_new();
                                                if ((*(*single).certStatus).value.unknown).is_null() {
                                                    current_block = 1192491949871105541;
                                                } else {
                                                    current_block = 7245201122033322888;
                                                }
                                            }
                                            14764605651087521687 => {
                                                (*(*single).certStatus).value.good = ASN1_NULL_new();
                                                if ((*(*single).certStatus).value.good).is_null() {
                                                    current_block = 1192491949871105541;
                                                } else {
                                                    current_block = 7245201122033322888;
                                                }
                                            }
                                            _ => {
                                                if revoked_time.is_null() {
                                                    ERR_put_error(
                                                        23 as libc::c_int,
                                                        0 as libc::c_int,
                                                        109 as libc::c_int,
                                                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0"
                                                            as *const u8 as *const libc::c_char,
                                                        266 as libc::c_int as libc::c_uint,
                                                    );
                                                    current_block = 1192491949871105541;
                                                } else {
                                                    (*(*single).certStatus)
                                                        .value
                                                        .revoked = OCSP_REVOKEDINFO_new();
                                                    if ((*(*single).certStatus).value.revoked).is_null() {
                                                        current_block = 1192491949871105541;
                                                    } else {
                                                        info = (*(*single).certStatus).value.revoked;
                                                        if (ASN1_TIME_to_generalizedtime(
                                                            revoked_time,
                                                            &mut (*info).revocationTime,
                                                        ))
                                                            .is_null()
                                                        {
                                                            current_block = 1192491949871105541;
                                                        } else if revoked_reason < 0 as libc::c_int
                                                            || revoked_reason > 10 as libc::c_int
                                                            || revoked_reason == 7 as libc::c_int
                                                        {
                                                            ERR_put_error(
                                                                23 as libc::c_int,
                                                                0 as libc::c_int,
                                                                132 as libc::c_int,
                                                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0"
                                                                    as *const u8 as *const libc::c_char,
                                                                285 as libc::c_int as libc::c_uint,
                                                            );
                                                            current_block = 1192491949871105541;
                                                        } else {
                                                            (*info).revocationReason = ASN1_ENUMERATED_new();
                                                            if ((*info).revocationReason).is_null()
                                                                || ASN1_ENUMERATED_set(
                                                                    (*info).revocationReason,
                                                                    revoked_reason as libc::c_long,
                                                                ) == 0
                                                            {
                                                                current_block = 1192491949871105541;
                                                            } else {
                                                                current_block = 7245201122033322888;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        match current_block {
                                            1192491949871105541 => {}
                                            _ => {
                                                if !(sk_OCSP_SINGLERESP_push(
                                                    (*(*resp).tbsResponseData).responses,
                                                    single,
                                                ) == 0)
                                                {
                                                    return single;
                                                }
                                            }
                                        }
                                    }
                                    2 => {
                                        current_block = 2871512926265210112;
                                        match current_block {
                                            2871512926265210112 => {
                                                (*(*single).certStatus).value.unknown = ASN1_NULL_new();
                                                if ((*(*single).certStatus).value.unknown).is_null() {
                                                    current_block = 1192491949871105541;
                                                } else {
                                                    current_block = 7245201122033322888;
                                                }
                                            }
                                            14764605651087521687 => {
                                                (*(*single).certStatus).value.good = ASN1_NULL_new();
                                                if ((*(*single).certStatus).value.good).is_null() {
                                                    current_block = 1192491949871105541;
                                                } else {
                                                    current_block = 7245201122033322888;
                                                }
                                            }
                                            _ => {
                                                if revoked_time.is_null() {
                                                    ERR_put_error(
                                                        23 as libc::c_int,
                                                        0 as libc::c_int,
                                                        109 as libc::c_int,
                                                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0"
                                                            as *const u8 as *const libc::c_char,
                                                        266 as libc::c_int as libc::c_uint,
                                                    );
                                                    current_block = 1192491949871105541;
                                                } else {
                                                    (*(*single).certStatus)
                                                        .value
                                                        .revoked = OCSP_REVOKEDINFO_new();
                                                    if ((*(*single).certStatus).value.revoked).is_null() {
                                                        current_block = 1192491949871105541;
                                                    } else {
                                                        info = (*(*single).certStatus).value.revoked;
                                                        if (ASN1_TIME_to_generalizedtime(
                                                            revoked_time,
                                                            &mut (*info).revocationTime,
                                                        ))
                                                            .is_null()
                                                        {
                                                            current_block = 1192491949871105541;
                                                        } else if revoked_reason < 0 as libc::c_int
                                                            || revoked_reason > 10 as libc::c_int
                                                            || revoked_reason == 7 as libc::c_int
                                                        {
                                                            ERR_put_error(
                                                                23 as libc::c_int,
                                                                0 as libc::c_int,
                                                                132 as libc::c_int,
                                                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0"
                                                                    as *const u8 as *const libc::c_char,
                                                                285 as libc::c_int as libc::c_uint,
                                                            );
                                                            current_block = 1192491949871105541;
                                                        } else {
                                                            (*info).revocationReason = ASN1_ENUMERATED_new();
                                                            if ((*info).revocationReason).is_null()
                                                                || ASN1_ENUMERATED_set(
                                                                    (*info).revocationReason,
                                                                    revoked_reason as libc::c_long,
                                                                ) == 0
                                                            {
                                                                current_block = 1192491949871105541;
                                                            } else {
                                                                current_block = 7245201122033322888;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        match current_block {
                                            1192491949871105541 => {}
                                            _ => {
                                                if !(sk_OCSP_SINGLERESP_push(
                                                    (*(*resp).tbsResponseData).responses,
                                                    single,
                                                ) == 0)
                                                {
                                                    return single;
                                                }
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    OCSP_SINGLERESP_free(single);
    return 0 as *mut OCSP_SINGLERESP;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_response_create(
    mut status: libc::c_int,
    mut bs: *mut OCSP_BASICRESP,
) -> *mut OCSP_RESPONSE {
    if status < 0 as libc::c_int || status > 6 as libc::c_int
        || status == 4 as libc::c_int
    {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            132 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_server.c\0" as *const u8
                as *const libc::c_char,
            330 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut OCSP_RESPONSE;
    }
    let mut rsp: *mut OCSP_RESPONSE = OCSP_RESPONSE_new();
    if !rsp.is_null() {
        if !(ASN1_ENUMERATED_set((*rsp).responseStatus, status as libc::c_long) == 0) {
            if bs.is_null() {
                return rsp;
            }
            (*rsp).responseBytes = OCSP_RESPBYTES_new();
            if !((*rsp).responseBytes).is_null() {
                (*(*rsp).responseBytes).responseType = OBJ_nid2obj(365 as libc::c_int);
                if !(ASN1_item_pack(
                    bs as *mut libc::c_void,
                    &OCSP_BASICRESP_it,
                    &mut (*(*rsp).responseBytes).response,
                ))
                    .is_null()
                {
                    return rsp;
                }
            }
        }
    }
    OCSP_RESPONSE_free(rsp);
    return 0 as *mut OCSP_RESPONSE;
}
