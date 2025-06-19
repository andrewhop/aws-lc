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
    pub type asn1_object_st;
    pub type ASN1_VALUE_st;
    pub type X509_name_st;
    pub type X509_extension_st;
    pub type stack_st_X509;
    pub type stack_st_X509_EXTENSION;
    pub type stack_st_OCSP_ONEREQ;
    pub type stack_st_OCSP_SINGLERESP;
    fn ASN1_OCTET_STRING_cmp(
        a: *const ASN1_OCTET_STRING,
        b: *const ASN1_OCTET_STRING,
    ) -> libc::c_int;
    fn ASN1_put_object(
        outp: *mut *mut libc::c_uchar,
        constructed: libc::c_int,
        length: libc::c_int,
        tag: libc::c_int,
        xclass: libc::c_int,
    );
    fn ASN1_object_size(
        constructed: libc::c_int,
        length: libc::c_int,
        tag: libc::c_int,
    ) -> libc::c_int;
    fn X509_EXTENSION_get_data(ne: *const X509_EXTENSION) -> *mut ASN1_OCTET_STRING;
    fn X509v3_get_ext_count(x: *const stack_st_X509_EXTENSION) -> libc::c_int;
    fn X509v3_get_ext_by_NID(
        x: *const stack_st_X509_EXTENSION,
        nid: libc::c_int,
        lastpos: libc::c_int,
    ) -> libc::c_int;
    fn X509v3_get_ext(
        x: *const stack_st_X509_EXTENSION,
        loc: libc::c_int,
    ) -> *mut X509_EXTENSION;
    fn X509v3_delete_ext(
        x: *mut stack_st_X509_EXTENSION,
        loc: libc::c_int,
    ) -> *mut X509_EXTENSION;
    fn X509v3_add_ext(
        x: *mut *mut stack_st_X509_EXTENSION,
        ex: *const X509_EXTENSION,
        loc: libc::c_int,
    ) -> *mut stack_st_X509_EXTENSION;
    fn X509V3_add1_i2d(
        x: *mut *mut stack_st_X509_EXTENSION,
        nid: libc::c_int,
        value: *mut libc::c_void,
        crit: libc::c_int,
        flags: libc::c_ulong,
    ) -> libc::c_int;
    fn RAND_bytes(buf: *mut uint8_t, len: size_t) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type uint8_t = __uint8_t;
pub type ASN1_NULL = asn1_null_st;
pub type ASN1_BOOLEAN = libc::c_int;
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
pub type X509_EXTENSION = X509_extension_st;
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
unsafe extern "C" fn OPENSSL_memcpy(
    mut dst: *mut libc::c_void,
    mut src: *const libc::c_void,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return dst;
    }
    return memcpy(dst, src, n);
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_REQUEST_get_ext_by_NID(
    mut req: *mut OCSP_REQUEST,
    mut nid: libc::c_int,
    mut lastpos: libc::c_int,
) -> libc::c_int {
    return X509v3_get_ext_by_NID((*(*req).tbsRequest).requestExtensions, nid, lastpos);
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_REQUEST_get_ext(
    mut req: *mut OCSP_REQUEST,
    mut loc: libc::c_int,
) -> *mut X509_EXTENSION {
    return X509v3_get_ext((*(*req).tbsRequest).requestExtensions, loc);
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_BASICRESP_add_ext(
    mut bs: *mut OCSP_BASICRESP,
    mut ex: *mut X509_EXTENSION,
    mut loc: libc::c_int,
) -> libc::c_int {
    return (X509v3_add_ext(&mut (*(*bs).tbsResponseData).responseExtensions, ex, loc)
        != 0 as *mut libc::c_void as *mut stack_st_X509_EXTENSION) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_BASICRESP_get_ext_by_NID(
    mut bs: *mut OCSP_BASICRESP,
    mut nid: libc::c_int,
    mut lastpos: libc::c_int,
) -> libc::c_int {
    return X509v3_get_ext_by_NID(
        (*(*bs).tbsResponseData).responseExtensions,
        nid,
        lastpos,
    );
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_BASICRESP_get_ext(
    mut bs: *mut OCSP_BASICRESP,
    mut loc: libc::c_int,
) -> *mut X509_EXTENSION {
    return X509v3_get_ext((*(*bs).tbsResponseData).responseExtensions, loc);
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_BASICRESP_delete_ext(
    mut x: *mut OCSP_BASICRESP,
    mut loc: libc::c_int,
) -> *mut X509_EXTENSION {
    return X509v3_delete_ext((*(*x).tbsResponseData).responseExtensions, loc);
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_SINGLERESP_add_ext(
    mut sresp: *mut OCSP_SINGLERESP,
    mut ex: *mut X509_EXTENSION,
    mut loc: libc::c_int,
) -> libc::c_int {
    if sresp.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_extension.c\0"
                as *const u8 as *const libc::c_char,
            51 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return (X509v3_add_ext(&mut (*sresp).singleExtensions, ex, loc)
        != 0 as *mut libc::c_void as *mut stack_st_X509_EXTENSION) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_SINGLERESP_get_ext_count(
    mut sresp: *mut OCSP_SINGLERESP,
) -> libc::c_int {
    if sresp.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_extension.c\0"
                as *const u8 as *const libc::c_char,
            56 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return X509v3_get_ext_count((*sresp).singleExtensions);
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_SINGLERESP_get_ext(
    mut sresp: *mut OCSP_SINGLERESP,
    mut loc: libc::c_int,
) -> *mut X509_EXTENSION {
    if sresp.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_extension.c\0"
                as *const u8 as *const libc::c_char,
            61 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut X509_EXTENSION;
    }
    return X509v3_get_ext((*sresp).singleExtensions, loc);
}
unsafe extern "C" fn ocsp_add_nonce(
    mut exts: *mut *mut stack_st_X509_EXTENSION,
    mut val: *mut libc::c_uchar,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut tmpval: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut os: ASN1_OCTET_STRING = asn1_string_st {
        length: 0,
        type_0: 0,
        data: 0 as *mut libc::c_uchar,
        flags: 0,
    };
    let mut ret: libc::c_int = 0 as libc::c_int;
    if len <= 0 as libc::c_int {
        len = 16 as libc::c_int;
    }
    os.length = ASN1_object_size(0 as libc::c_int, len, 4 as libc::c_int);
    if os.length < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    os.data = OPENSSL_malloc(os.length as size_t) as *mut libc::c_uchar;
    if !(os.data).is_null() {
        tmpval = os.data;
        ASN1_put_object(
            &mut tmpval,
            0 as libc::c_int,
            len,
            4 as libc::c_int,
            0 as libc::c_int,
        );
        if !val.is_null() {
            OPENSSL_memcpy(
                tmpval as *mut libc::c_void,
                val as *const libc::c_void,
                len as size_t,
            );
            current_block = 11050875288958768710;
        } else if RAND_bytes(tmpval, len as size_t) <= 0 as libc::c_int {
            current_block = 241525114851075030;
        } else {
            current_block = 11050875288958768710;
        }
        match current_block {
            241525114851075030 => {}
            _ => {
                if !(X509V3_add1_i2d(
                    exts,
                    366 as libc::c_int,
                    &mut os as *mut ASN1_OCTET_STRING as *mut libc::c_void,
                    0 as libc::c_int,
                    2 as libc::c_long as libc::c_ulong,
                ) <= 0 as libc::c_int)
                {
                    ret = 1 as libc::c_int;
                }
            }
        }
    }
    OPENSSL_free(os.data as *mut libc::c_void);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_request_add1_nonce(
    mut req: *mut OCSP_REQUEST,
    mut val: *mut libc::c_uchar,
    mut len: libc::c_int,
) -> libc::c_int {
    if req.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_extension.c\0"
                as *const u8 as *const libc::c_char,
            105 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if !val.is_null() && len <= 0 as libc::c_int {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_extension.c\0"
                as *const u8 as *const libc::c_char,
            109 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ocsp_add_nonce(&mut (*(*req).tbsRequest).requestExtensions, val, len);
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_basic_add1_nonce(
    mut resp: *mut OCSP_BASICRESP,
    mut val: *mut libc::c_uchar,
    mut len: libc::c_int,
) -> libc::c_int {
    if resp.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_extension.c\0"
                as *const u8 as *const libc::c_char,
            117 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if !val.is_null() && len <= 0 as libc::c_int {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_extension.c\0"
                as *const u8 as *const libc::c_char,
            121 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return ocsp_add_nonce(&mut (*(*resp).tbsResponseData).responseExtensions, val, len);
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_check_nonce(
    mut req: *mut OCSP_REQUEST,
    mut bs: *mut OCSP_BASICRESP,
) -> libc::c_int {
    if req.is_null() || bs.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_extension.c\0"
                as *const u8 as *const libc::c_char,
            129 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut req_idx: libc::c_int = 0;
    let mut resp_idx: libc::c_int = 0;
    let mut req_ext: *mut X509_EXTENSION = 0 as *mut X509_EXTENSION;
    let mut resp_ext: *mut X509_EXTENSION = 0 as *mut X509_EXTENSION;
    req_idx = OCSP_REQUEST_get_ext_by_NID(req, 366 as libc::c_int, -(1 as libc::c_int));
    resp_idx = OCSP_BASICRESP_get_ext_by_NID(
        bs,
        366 as libc::c_int,
        -(1 as libc::c_int),
    );
    if req_idx < 0 as libc::c_int && resp_idx < 0 as libc::c_int {
        return 2 as libc::c_int;
    }
    if req_idx >= 0 as libc::c_int && resp_idx < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    if req_idx < 0 as libc::c_int && resp_idx >= 0 as libc::c_int {
        return 3 as libc::c_int;
    }
    req_ext = OCSP_REQUEST_get_ext(req, req_idx);
    resp_ext = OCSP_BASICRESP_get_ext(bs, resp_idx);
    if ASN1_OCTET_STRING_cmp(
        X509_EXTENSION_get_data(req_ext),
        X509_EXTENSION_get_data(resp_ext),
    ) != 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_copy_nonce(
    mut resp: *mut OCSP_BASICRESP,
    mut req: *mut OCSP_REQUEST,
) -> libc::c_int {
    if resp.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_extension.c\0"
                as *const u8 as *const libc::c_char,
            166 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if req.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_extension.c\0"
                as *const u8 as *const libc::c_char,
            167 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut req_idx: libc::c_int = OCSP_REQUEST_get_ext_by_NID(
        req,
        366 as libc::c_int,
        -(1 as libc::c_int),
    );
    if req_idx < 0 as libc::c_int {
        return 2 as libc::c_int;
    }
    let mut req_ext: *mut X509_EXTENSION = OCSP_REQUEST_get_ext(req, req_idx);
    if req_ext.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_extension.c\0"
                as *const u8 as *const libc::c_char,
            178 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return OCSP_BASICRESP_add_ext(resp, req_ext, -(1 as libc::c_int));
}
