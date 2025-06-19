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
    pub type asn1_null_st;
    pub type ASN1_VALUE_st;
    pub type X509_name_st;
    pub type evp_pkey_st;
    pub type x509_st;
    pub type env_md_st;
    pub type stack_st_X509;
    pub type stack_st;
    pub type stack_st_X509_EXTENSION;
    pub type stack_st_OCSP_ONEREQ;
    pub type stack_st_OCSP_SINGLERESP;
    fn time(__timer: *mut time_t) -> time_t;
    fn ASN1_item_unpack(
        oct: *const ASN1_STRING,
        it: *const ASN1_ITEM,
    ) -> *mut libc::c_void;
    fn ASN1_STRING_cmp(a: *const ASN1_STRING, b: *const ASN1_STRING) -> libc::c_int;
    fn ASN1_GENERALIZEDTIME_check(a: *const ASN1_GENERALIZEDTIME) -> libc::c_int;
    fn ASN1_ENUMERATED_get(a: *const ASN1_ENUMERATED) -> libc::c_long;
    fn X509_up_ref(x509: *mut X509) -> libc::c_int;
    fn X509_get_subject_name(x509: *const X509) -> *mut X509_NAME;
    fn X509_check_private_key(x509: *const X509, pkey: *const EVP_PKEY) -> libc::c_int;
    fn X509_NAME_set(xn: *mut *mut X509_NAME, name: *mut X509_NAME) -> libc::c_int;
    fn GENERAL_NAME_new() -> *mut GENERAL_NAME;
    fn GENERAL_NAME_free(gen: *mut GENERAL_NAME);
    fn X509_cmp_time_posix(s: *const ASN1_TIME, t: int64_t) -> libc::c_int;
    fn ASN1_item_sign(
        it: *const ASN1_ITEM,
        algor1: *mut X509_ALGOR,
        algor2: *mut X509_ALGOR,
        signature: *mut ASN1_BIT_STRING,
        data: *mut libc::c_void,
        pkey: *mut EVP_PKEY,
        type_0: *const EVP_MD,
    ) -> libc::c_int;
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    static OCSP_REQINFO_it: ASN1_ITEM;
    fn OCSP_SIGNATURE_free(a: *mut OCSP_SIGNATURE);
    fn OCSP_SIGNATURE_new() -> *mut OCSP_SIGNATURE;
    fn OCSP_get_default_digest(
        dgst: *const EVP_MD,
        signer: *mut EVP_PKEY,
    ) -> *const EVP_MD;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OBJ_obj2nid(obj: *const ASN1_OBJECT) -> libc::c_int;
    static OCSP_BASICRESP_it: ASN1_ITEM;
    fn OCSP_CERTID_free(a: *mut OCSP_CERTID);
    fn OCSP_ONEREQ_new() -> *mut OCSP_ONEREQ;
    fn OCSP_ONEREQ_free(a: *mut OCSP_ONEREQ);
    fn OCSP_id_cmp(a: *const OCSP_CERTID, b: *const OCSP_CERTID) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type time_t = __time_t;
pub type int64_t = __int64_t;
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
unsafe extern "C" fn sk_OCSP_ONEREQ_push(
    mut sk: *mut stack_st_OCSP_ONEREQ,
    mut p: *mut OCSP_ONEREQ,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
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
#[no_mangle]
pub unsafe extern "C" fn OCSP_request_add0_id(
    mut req: *mut OCSP_REQUEST,
    mut cid: *mut OCSP_CERTID,
) -> *mut OCSP_ONEREQ {
    let mut one: *mut OCSP_ONEREQ = OCSP_ONEREQ_new();
    if one.is_null() {
        return 0 as *mut OCSP_ONEREQ;
    }
    OCSP_CERTID_free((*one).reqCert);
    (*one).reqCert = cid;
    if !req.is_null() && sk_OCSP_ONEREQ_push((*(*req).tbsRequest).requestList, one) == 0
    {
        (*one).reqCert = 0 as *mut OCSP_CERTID;
        OCSP_ONEREQ_free(one);
        return 0 as *mut OCSP_ONEREQ;
    }
    return one;
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_request_set1_name(
    mut req: *mut OCSP_REQUEST,
    mut nm: *mut X509_NAME,
) -> libc::c_int {
    let mut gen: *mut GENERAL_NAME = GENERAL_NAME_new();
    if gen.is_null() {
        return 0 as libc::c_int;
    }
    if X509_NAME_set(&mut (*gen).d.directoryName, nm) == 0 {
        GENERAL_NAME_free(gen);
        return 0 as libc::c_int;
    }
    (*gen).type_0 = 4 as libc::c_int;
    GENERAL_NAME_free((*(*req).tbsRequest).requestorName);
    (*(*req).tbsRequest).requestorName = gen;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_request_add1_cert(
    mut req: *mut OCSP_REQUEST,
    mut cert: *mut X509,
) -> libc::c_int {
    if ((*req).optionalSignature).is_null() {
        (*req).optionalSignature = OCSP_SIGNATURE_new();
    }
    let mut sig: *mut OCSP_SIGNATURE = (*req).optionalSignature;
    if sig.is_null() {
        return 0 as libc::c_int;
    }
    if cert.is_null() {
        return 1 as libc::c_int;
    }
    if ((*sig).certs).is_null()
        && {
            (*sig).certs = sk_X509_new_null();
            ((*sig).certs).is_null()
        }
    {
        return 0 as libc::c_int;
    }
    if sk_X509_push((*sig).certs, cert) == 0 {
        return 0 as libc::c_int;
    }
    X509_up_ref(cert);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_request_sign(
    mut req: *mut OCSP_REQUEST,
    mut signer: *mut X509,
    mut key: *mut EVP_PKEY,
    mut dgst: *const EVP_MD,
    mut certs: *mut stack_st_X509,
    mut flags: libc::c_ulong,
) -> libc::c_int {
    let mut current_block: u64;
    if !((*req).optionalSignature).is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            131 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_client.c\0" as *const u8
                as *const libc::c_char,
            73 as libc::c_int as libc::c_uint,
        );
    } else if !(OCSP_request_set1_name(req, X509_get_subject_name(signer)) == 0) {
        (*req).optionalSignature = OCSP_SIGNATURE_new();
        if !((*req).optionalSignature).is_null() {
            if !key.is_null() {
                if X509_check_private_key(signer, key) == 0 {
                    ERR_put_error(
                        23 as libc::c_int,
                        0 as libc::c_int,
                        110 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_client.c\0"
                            as *const u8 as *const libc::c_char,
                        86 as libc::c_int as libc::c_uint,
                    );
                    current_block = 12121929974718038596;
                } else {
                    let mut init_dgst: *const EVP_MD = OCSP_get_default_digest(
                        dgst,
                        key,
                    );
                    if init_dgst.is_null() {
                        ERR_put_error(
                            23 as libc::c_int,
                            0 as libc::c_int,
                            119 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_client.c\0"
                                as *const u8 as *const libc::c_char,
                            91 as libc::c_int as libc::c_uint,
                        );
                        current_block = 12121929974718038596;
                    } else if ASN1_item_sign(
                        &OCSP_REQINFO_it,
                        (*(*req).optionalSignature).signatureAlgorithm,
                        0 as *mut X509_ALGOR,
                        (*(*req).optionalSignature).signature,
                        (*req).tbsRequest as *mut libc::c_void,
                        key,
                        init_dgst,
                    ) == 0
                    {
                        current_block = 12121929974718038596;
                    } else {
                        current_block = 1841672684692190573;
                    }
                }
            } else {
                current_block = 1841672684692190573;
            }
            match current_block {
                12121929974718038596 => {}
                _ => {
                    if flags & 0x1 as libc::c_int as libc::c_ulong == 0 {
                        if OCSP_request_add1_cert(req, signer) == 0 {
                            current_block = 12121929974718038596;
                        } else {
                            let mut i: size_t = 0 as libc::c_int as size_t;
                            loop {
                                if !(i < sk_X509_num(certs)) {
                                    current_block = 2370887241019905314;
                                    break;
                                }
                                if OCSP_request_add1_cert(req, sk_X509_value(certs, i)) == 0
                                {
                                    current_block = 12121929974718038596;
                                    break;
                                }
                                i = i.wrapping_add(1);
                                i;
                            }
                        }
                    } else {
                        current_block = 2370887241019905314;
                    }
                    match current_block {
                        12121929974718038596 => {}
                        _ => return 1 as libc::c_int,
                    }
                }
            }
        }
    }
    OCSP_SIGNATURE_free((*req).optionalSignature);
    (*req).optionalSignature = 0 as *mut OCSP_SIGNATURE;
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_response_status(
    mut resp: *mut OCSP_RESPONSE,
) -> libc::c_int {
    if resp.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_client.c\0" as *const u8
                as *const libc::c_char,
            123 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    return ASN1_ENUMERATED_get((*resp).responseStatus) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_response_get1_basic(
    mut resp: *mut OCSP_RESPONSE,
) -> *mut OCSP_BASICRESP {
    if resp.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_client.c\0" as *const u8
                as *const libc::c_char,
            131 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut OCSP_BASICRESP;
    }
    let mut rb: *mut OCSP_RESPBYTES = (*resp).responseBytes;
    if rb.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            108 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_client.c\0" as *const u8
                as *const libc::c_char,
            137 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut OCSP_BASICRESP;
    }
    if OBJ_obj2nid((*rb).responseType) != 365 as libc::c_int {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_client.c\0" as *const u8
                as *const libc::c_char,
            141 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut OCSP_BASICRESP;
    }
    return ASN1_item_unpack((*rb).response, &OCSP_BASICRESP_it) as *mut OCSP_BASICRESP;
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_resp_get0(
    mut bs: *mut OCSP_BASICRESP,
    mut idx: size_t,
) -> *mut OCSP_SINGLERESP {
    if bs.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_client.c\0" as *const u8
                as *const libc::c_char,
            149 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut OCSP_SINGLERESP;
    }
    if ((*bs).tbsResponseData).is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            108 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_client.c\0" as *const u8
                as *const libc::c_char,
            153 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut OCSP_SINGLERESP;
    }
    return sk_OCSP_SINGLERESP_value((*(*bs).tbsResponseData).responses, idx);
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_resp_find(
    mut bs: *mut OCSP_BASICRESP,
    mut id: *mut OCSP_CERTID,
    mut last: libc::c_int,
) -> libc::c_int {
    if bs.is_null() || id.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_client.c\0" as *const u8
                as *const libc::c_char,
            161 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    if ((*bs).tbsResponseData).is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            108 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_client.c\0" as *const u8
                as *const libc::c_char,
            165 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    let mut sresp: *mut stack_st_OCSP_SINGLERESP = (*(*bs).tbsResponseData).responses;
    let mut single: *mut OCSP_SINGLERESP = 0 as *mut OCSP_SINGLERESP;
    if last < 0 as libc::c_int {
        last = 0 as libc::c_int;
    } else {
        last += 1;
        last;
    }
    let mut i: size_t = last as size_t;
    while i < sk_OCSP_SINGLERESP_num(sresp) {
        single = sk_OCSP_SINGLERESP_value(sresp, i);
        if OCSP_id_cmp(id, (*single).certId) == 0 {
            return i as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return -(1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_single_get0_status(
    mut single: *mut OCSP_SINGLERESP,
    mut reason: *mut libc::c_int,
    mut revtime: *mut *mut ASN1_GENERALIZEDTIME,
    mut thisupd: *mut *mut ASN1_GENERALIZEDTIME,
    mut nextupd: *mut *mut ASN1_GENERALIZEDTIME,
) -> libc::c_int {
    if single.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_client.c\0" as *const u8
                as *const libc::c_char,
            193 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    let mut cst: *mut OCSP_CERTSTATUS = (*single).certStatus;
    if cst.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_client.c\0" as *const u8
                as *const libc::c_char,
            198 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    let mut status: libc::c_int = (*cst).type_0;
    if status == 1 as libc::c_int {
        let mut rev: *mut OCSP_REVOKEDINFO = (*cst).value.revoked;
        if !rev.is_null() {
            if !revtime.is_null() {
                *revtime = (*rev).revocationTime;
            }
            if !reason.is_null() {
                if !((*rev).revocationReason).is_null() {
                    *reason = ASN1_ENUMERATED_get((*rev).revocationReason)
                        as libc::c_int;
                } else {
                    *reason = -(1 as libc::c_int);
                }
            }
        }
    }
    if !thisupd.is_null() {
        *thisupd = (*single).thisUpdate;
    }
    if !nextupd.is_null() {
        *nextupd = (*single).nextUpdate;
    }
    return status;
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_resp_find_status(
    mut bs: *mut OCSP_BASICRESP,
    mut id: *mut OCSP_CERTID,
    mut status: *mut libc::c_int,
    mut reason: *mut libc::c_int,
    mut revtime: *mut *mut ASN1_GENERALIZEDTIME,
    mut thisupd: *mut *mut ASN1_GENERALIZEDTIME,
    mut nextupd: *mut *mut ASN1_GENERALIZEDTIME,
) -> libc::c_int {
    if bs.is_null() || id.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_client.c\0" as *const u8
                as *const libc::c_char,
            236 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    let mut single_idx: libc::c_int = OCSP_resp_find(bs, id, -(1 as libc::c_int));
    if single_idx < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut single: *mut OCSP_SINGLERESP = OCSP_resp_get0(bs, single_idx as size_t);
    let mut single_status: libc::c_int = OCSP_single_get0_status(
        single,
        reason,
        revtime,
        thisupd,
        nextupd,
    );
    if !status.is_null() {
        *status = single_status;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_check_validity(
    mut thisUpdate: *mut ASN1_GENERALIZEDTIME,
    mut nextUpdate: *mut ASN1_GENERALIZEDTIME,
    mut drift_num_seconds: libc::c_long,
    mut max_age_seconds: libc::c_long,
) -> libc::c_int {
    let mut ret: libc::c_int = 1 as libc::c_int;
    let mut t_tmp: int64_t = 0;
    let mut t_now: int64_t = time(0 as *mut time_t);
    if ASN1_GENERALIZEDTIME_check(thisUpdate) == 0 {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            123 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_client.c\0" as *const u8
                as *const libc::c_char,
            268 as libc::c_int as libc::c_uint,
        );
        ret = 0 as libc::c_int;
    } else {
        t_tmp = t_now + drift_num_seconds;
        if X509_cmp_time_posix(thisUpdate, t_tmp) > 0 as libc::c_int {
            ERR_put_error(
                23 as libc::c_int,
                0 as libc::c_int,
                126 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_client.c\0"
                    as *const u8 as *const libc::c_char,
                273 as libc::c_int as libc::c_uint,
            );
            ret = 0 as libc::c_int;
        }
        if max_age_seconds >= 0 as libc::c_int as libc::c_long {
            t_tmp = t_now - max_age_seconds;
            if X509_cmp_time_posix(thisUpdate, t_tmp) < 0 as libc::c_int {
                ERR_put_error(
                    23 as libc::c_int,
                    0 as libc::c_int,
                    127 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_client.c\0"
                        as *const u8 as *const libc::c_char,
                    282 as libc::c_int as libc::c_uint,
                );
                ret = 0 as libc::c_int;
            }
        }
    }
    if nextUpdate.is_null() {
        return ret;
    }
    if ASN1_GENERALIZEDTIME_check(nextUpdate) == 0 {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            122 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_client.c\0" as *const u8
                as *const libc::c_char,
            297 as libc::c_int as libc::c_uint,
        );
        ret = 0 as libc::c_int;
    } else {
        t_tmp = t_now - drift_num_seconds;
        if X509_cmp_time_posix(nextUpdate, t_tmp) < 0 as libc::c_int {
            ERR_put_error(
                23 as libc::c_int,
                0 as libc::c_int,
                125 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_client.c\0"
                    as *const u8 as *const libc::c_char,
                302 as libc::c_int as libc::c_uint,
            );
            ret = 0 as libc::c_int;
        }
    }
    if ASN1_STRING_cmp(nextUpdate, thisUpdate) < 0 as libc::c_int {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            124 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_client.c\0" as *const u8
                as *const libc::c_char,
            309 as libc::c_int as libc::c_uint,
        );
        ret = 0 as libc::c_int;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_resp_count(mut bs: *mut OCSP_BASICRESP) -> libc::c_int {
    if bs.is_null() {
        return -(1 as libc::c_int);
    }
    return sk_OCSP_SINGLERESP_num((*(*bs).tbsResponseData).responses) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_SINGLERESP_get0_id(
    mut single: *const OCSP_SINGLERESP,
) -> *const OCSP_CERTID {
    return (*single).certId;
}
