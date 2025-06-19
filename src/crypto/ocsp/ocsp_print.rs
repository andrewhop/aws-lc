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
    pub type x509_st;
    pub type stack_st_void;
    pub type stack_st_X509;
    pub type stack_st;
    pub type stack_st_X509_EXTENSION;
    pub type stack_st_OCSP_ONEREQ;
    pub type stack_st_OCSP_SINGLERESP;
    fn ASN1_GENERALIZEDTIME_print(
        out: *mut BIO,
        a: *const ASN1_GENERALIZEDTIME,
    ) -> libc::c_int;
    fn i2a_ASN1_INTEGER(bp: *mut BIO, a: *const ASN1_INTEGER) -> libc::c_int;
    fn i2a_ASN1_OBJECT(bp: *mut BIO, a: *const ASN1_OBJECT) -> libc::c_int;
    fn i2a_ASN1_STRING(
        bp: *mut BIO,
        a: *const ASN1_STRING,
        type_0: libc::c_int,
    ) -> libc::c_int;
    fn ASN1_INTEGER_get(a: *const ASN1_INTEGER) -> libc::c_long;
    fn ASN1_ENUMERATED_get(a: *const ASN1_ENUMERATED) -> libc::c_long;
    fn X509_print(bp: *mut BIO, x: *mut X509) -> libc::c_int;
    fn X509_NAME_print_ex(
        out: *mut BIO,
        nm: *const X509_NAME,
        indent: libc::c_int,
        flags: libc::c_ulong,
    ) -> libc::c_int;
    fn X509_signature_print(
        bio: *mut BIO,
        alg: *const X509_ALGOR,
        sig: *const ASN1_STRING,
    ) -> libc::c_int;
    fn X509V3_extensions_print(
        out: *mut BIO,
        title: *const libc::c_char,
        exts: *const stack_st_X509_EXTENSION,
        flag: libc::c_ulong,
        indent: libc::c_int,
    ) -> libc::c_int;
    fn GENERAL_NAME_print(out: *mut BIO, gen: *const GENERAL_NAME) -> libc::c_int;
    fn BIO_puts(bio: *mut BIO, buf: *const libc::c_char) -> libc::c_int;
    fn BIO_printf(bio: *mut BIO, format: *const libc::c_char, _: ...) -> libc::c_int;
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
    fn OCSP_BASICRESP_free(a: *mut OCSP_BASICRESP);
    fn OCSP_response_get1_basic(resp: *mut OCSP_RESPONSE) -> *mut OCSP_BASICRESP;
    fn PEM_write_bio_X509(bp: *mut BIO, x: *mut X509) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
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
pub type X509 = x509_st;
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
pub type CRYPTO_refcount_t = uint32_t;
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
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
pub type BIO_METHOD = bio_method_st;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct OCSP_TBLSTR {
    pub t: libc::c_long,
    pub m: *const libc::c_char,
}
#[inline]
unsafe extern "C" fn sk_X509_value(
    mut sk: *const stack_st_X509,
    mut i: size_t,
) -> *mut X509 {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509;
}
#[inline]
unsafe extern "C" fn sk_X509_num(mut sk: *const stack_st_X509) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
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
unsafe extern "C" fn ocsp_certid_print(
    mut bp: *mut BIO,
    mut certid: *mut OCSP_CERTID,
    mut indent: libc::c_int,
) -> libc::c_int {
    BIO_printf(
        bp,
        b"%*sCertificate ID:\n\0" as *const u8 as *const libc::c_char,
        indent,
        b"\0" as *const u8 as *const libc::c_char,
    );
    indent += 2 as libc::c_int;
    BIO_printf(
        bp,
        b"%*sHash Algorithm: \0" as *const u8 as *const libc::c_char,
        indent,
        b"\0" as *const u8 as *const libc::c_char,
    );
    i2a_ASN1_OBJECT(bp, (*(*certid).hashAlgorithm).algorithm);
    BIO_printf(
        bp,
        b"\n%*sIssuer Name Hash: \0" as *const u8 as *const libc::c_char,
        indent,
        b"\0" as *const u8 as *const libc::c_char,
    );
    i2a_ASN1_STRING(bp, (*certid).issuerNameHash, 0 as libc::c_int);
    BIO_printf(
        bp,
        b"\n%*sIssuer Key Hash: \0" as *const u8 as *const libc::c_char,
        indent,
        b"\0" as *const u8 as *const libc::c_char,
    );
    i2a_ASN1_STRING(bp, (*certid).issuerKeyHash, 0 as libc::c_int);
    BIO_printf(
        bp,
        b"\n%*sSerial Number: \0" as *const u8 as *const libc::c_char,
        indent,
        b"\0" as *const u8 as *const libc::c_char,
    );
    i2a_ASN1_INTEGER(bp, (*certid).serialNumber);
    BIO_printf(bp, b"\n\0" as *const u8 as *const libc::c_char);
    return 1 as libc::c_int;
}
unsafe extern "C" fn do_table2string(
    mut s: libc::c_long,
    mut ts: *const OCSP_TBLSTR,
    mut len: size_t,
) -> *const libc::c_char {
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < len {
        if (*ts.offset(i as isize)).t == s {
            return (*ts.offset(i as isize)).m;
        }
        i = i.wrapping_add(1);
        i;
    }
    return b"(UNKNOWN)\0" as *const u8 as *const libc::c_char;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_response_status_str(
    mut status_code: libc::c_long,
) -> *const libc::c_char {
    static mut rstat_tbl: [OCSP_TBLSTR; 6] = [
        {
            let mut init = OCSP_TBLSTR {
                t: 0 as libc::c_int as libc::c_long,
                m: b"successful\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = OCSP_TBLSTR {
                t: 1 as libc::c_int as libc::c_long,
                m: b"malformedrequest\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = OCSP_TBLSTR {
                t: 2 as libc::c_int as libc::c_long,
                m: b"internalerror\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = OCSP_TBLSTR {
                t: 3 as libc::c_int as libc::c_long,
                m: b"trylater\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = OCSP_TBLSTR {
                t: 5 as libc::c_int as libc::c_long,
                m: b"sigrequired\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = OCSP_TBLSTR {
                t: 6 as libc::c_int as libc::c_long,
                m: b"unauthorized\0" as *const u8 as *const libc::c_char,
            };
            init
        },
    ];
    let mut tbl_size: size_t = (::core::mem::size_of::<[OCSP_TBLSTR; 6]>()
        as libc::c_ulong)
        .wrapping_div(::core::mem::size_of::<OCSP_TBLSTR>() as libc::c_ulong);
    return do_table2string(status_code, rstat_tbl.as_ptr(), tbl_size);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_cert_status_str(
    mut status_code: libc::c_long,
) -> *const libc::c_char {
    static mut cstat_tbl: [OCSP_TBLSTR; 3] = [
        {
            let mut init = OCSP_TBLSTR {
                t: 0 as libc::c_int as libc::c_long,
                m: b"good\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = OCSP_TBLSTR {
                t: 1 as libc::c_int as libc::c_long,
                m: b"revoked\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = OCSP_TBLSTR {
                t: 2 as libc::c_int as libc::c_long,
                m: b"unknown\0" as *const u8 as *const libc::c_char,
            };
            init
        },
    ];
    let mut tbl_size: size_t = (::core::mem::size_of::<[OCSP_TBLSTR; 3]>()
        as libc::c_ulong)
        .wrapping_div(::core::mem::size_of::<OCSP_TBLSTR>() as libc::c_ulong);
    return do_table2string(status_code, cstat_tbl.as_ptr(), tbl_size);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_crl_reason_str(
    mut s: libc::c_long,
) -> *const libc::c_char {
    static mut reason_tbl: [OCSP_TBLSTR; 10] = [
        {
            let mut init = OCSP_TBLSTR {
                t: 0 as libc::c_int as libc::c_long,
                m: b"unspecified\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = OCSP_TBLSTR {
                t: 1 as libc::c_int as libc::c_long,
                m: b"keyCompromise\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = OCSP_TBLSTR {
                t: 2 as libc::c_int as libc::c_long,
                m: b"cACompromise\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = OCSP_TBLSTR {
                t: 3 as libc::c_int as libc::c_long,
                m: b"affiliationChanged\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = OCSP_TBLSTR {
                t: 4 as libc::c_int as libc::c_long,
                m: b"superseded\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = OCSP_TBLSTR {
                t: 5 as libc::c_int as libc::c_long,
                m: b"cessationOfOperation\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = OCSP_TBLSTR {
                t: 6 as libc::c_int as libc::c_long,
                m: b"certificateHold\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = OCSP_TBLSTR {
                t: 8 as libc::c_int as libc::c_long,
                m: b"removeFromCRL\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = OCSP_TBLSTR {
                t: 9 as libc::c_int as libc::c_long,
                m: b"privilegeWithdrawn\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = OCSP_TBLSTR {
                t: 10 as libc::c_int as libc::c_long,
                m: b"aACompromise\0" as *const u8 as *const libc::c_char,
            };
            init
        },
    ];
    let mut tbl_size: size_t = (::core::mem::size_of::<[OCSP_TBLSTR; 10]>()
        as libc::c_ulong)
        .wrapping_div(::core::mem::size_of::<OCSP_TBLSTR>() as libc::c_ulong);
    return do_table2string(s, reason_tbl.as_ptr(), tbl_size);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_REQUEST_print(
    mut bp: *mut BIO,
    mut req: *mut OCSP_REQUEST,
    mut flags: libc::c_ulong,
) -> libc::c_int {
    if bp.is_null() || req.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_print.c\0" as *const u8
                as *const libc::c_char,
            84 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut l: libc::c_long = 0;
    let mut cid: *mut OCSP_CERTID = 0 as *mut OCSP_CERTID;
    let mut one: *mut OCSP_ONEREQ = 0 as *mut OCSP_ONEREQ;
    let mut inf: *mut OCSP_REQINFO = (*req).tbsRequest;
    let mut sig: *mut OCSP_SIGNATURE = (*req).optionalSignature;
    if BIO_puts(bp, b"OCSP Request Data:\n\0" as *const u8 as *const libc::c_char)
        <= 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    l = ASN1_INTEGER_get((*inf).version);
    if BIO_printf(
        bp,
        b"    Version: %ld (0x%ld)\0" as *const u8 as *const libc::c_char,
        l + 1 as libc::c_int as libc::c_long,
        l,
    ) <= 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    if !((*inf).requestorName).is_null() {
        if BIO_puts(bp, b"\n    Requestor Name: \0" as *const u8 as *const libc::c_char)
            <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        GENERAL_NAME_print(bp, (*inf).requestorName);
    }
    if BIO_puts(bp, b"\n    Requestor List:\n\0" as *const u8 as *const libc::c_char)
        <= 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_OCSP_ONEREQ_num((*inf).requestList) {
        one = sk_OCSP_ONEREQ_value((*inf).requestList, i);
        cid = (*one).reqCert;
        ocsp_certid_print(bp, cid, 8 as libc::c_int);
        if X509V3_extensions_print(
            bp,
            b"Request Single Extensions\0" as *const u8 as *const libc::c_char,
            (*one).singleRequestExtensions,
            flags,
            8 as libc::c_int,
        ) == 0
        {
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    if X509V3_extensions_print(
        bp,
        b"Request Extensions\0" as *const u8 as *const libc::c_char,
        (*inf).requestExtensions,
        flags,
        4 as libc::c_int,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    if !sig.is_null() {
        X509_signature_print(bp, (*sig).signatureAlgorithm, (*sig).signature);
        let mut i_0: size_t = 0 as libc::c_int as size_t;
        while i_0 < sk_X509_num((*sig).certs) {
            X509_print(bp, sk_X509_value((*sig).certs, i_0));
            PEM_write_bio_X509(bp, sk_X509_value((*sig).certs, i_0));
            i_0 = i_0.wrapping_add(1);
            i_0;
        }
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_RESPONSE_print(
    mut bp: *mut BIO,
    mut resp: *mut OCSP_RESPONSE,
    mut flags: libc::c_ulong,
) -> libc::c_int {
    let mut current_block: u64;
    if bp.is_null() || resp.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_print.c\0" as *const u8
                as *const libc::c_char,
            135 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut l: libc::c_long = 0;
    let mut cid: *mut OCSP_CERTID = 0 as *mut OCSP_CERTID;
    let mut br: *mut OCSP_BASICRESP = 0 as *mut OCSP_BASICRESP;
    let mut rid: *mut OCSP_RESPID = 0 as *mut OCSP_RESPID;
    let mut rd: *mut OCSP_RESPDATA = 0 as *mut OCSP_RESPDATA;
    let mut cst: *mut OCSP_CERTSTATUS = 0 as *mut OCSP_CERTSTATUS;
    let mut rev: *mut OCSP_REVOKEDINFO = 0 as *mut OCSP_REVOKEDINFO;
    let mut single: *mut OCSP_SINGLERESP = 0 as *mut OCSP_SINGLERESP;
    let mut rb: *mut OCSP_RESPBYTES = (*resp).responseBytes;
    if !(BIO_puts(bp, b"OCSP Response Data:\n\0" as *const u8 as *const libc::c_char)
        <= 0 as libc::c_int)
    {
        l = ASN1_ENUMERATED_get((*resp).responseStatus);
        if !(BIO_printf(
            bp,
            b"    OCSP Response Status: %s (0x%ld)\n\0" as *const u8
                as *const libc::c_char,
            OCSP_response_status_str(l),
            l,
        ) <= 0 as libc::c_int)
        {
            if rb.is_null() {
                return 1 as libc::c_int;
            }
            if !(BIO_puts(
                bp,
                b"    Response Type: \0" as *const u8 as *const libc::c_char,
            ) <= 0 as libc::c_int)
            {
                if !(i2a_ASN1_OBJECT(bp, (*rb).responseType) <= 0 as libc::c_int) {
                    if OBJ_obj2nid((*rb).responseType) != 365 as libc::c_int {
                        BIO_puts(
                            bp,
                            b" (unknown response type)\n\0" as *const u8
                                as *const libc::c_char,
                        );
                        return 1 as libc::c_int;
                    }
                    br = OCSP_response_get1_basic(resp);
                    if !br.is_null() {
                        rd = (*br).tbsResponseData;
                        l = ASN1_INTEGER_get((*rd).version);
                        if !(BIO_printf(
                            bp,
                            b"\n    Version: %ld (0x%ld)\n\0" as *const u8
                                as *const libc::c_char,
                            l + 1 as libc::c_int as libc::c_long,
                            l,
                        ) <= 0 as libc::c_int)
                        {
                            if !(BIO_puts(
                                bp,
                                b"    Responder Id: \0" as *const u8 as *const libc::c_char,
                            ) <= 0 as libc::c_int)
                            {
                                rid = (*rd).responderId;
                                match (*rid).type_0 {
                                    0 => {
                                        X509_NAME_print_ex(
                                            bp,
                                            (*rid).value.byName,
                                            0 as libc::c_int,
                                            1 as libc::c_ulong | 2 as libc::c_ulong | 4 as libc::c_ulong
                                                | 0x10 as libc::c_ulong | 0x100 as libc::c_ulong
                                                | 0x200 as libc::c_ulong | 8 as libc::c_ulong
                                                | (2 as libc::c_ulong) << 16 as libc::c_int
                                                | (1 as libc::c_ulong) << 23 as libc::c_int
                                                | 0 as libc::c_ulong,
                                        );
                                    }
                                    1 => {
                                        i2a_ASN1_STRING(bp, (*rid).value.byKey, 0 as libc::c_int);
                                    }
                                    _ => {}
                                }
                                if !(BIO_printf(
                                    bp,
                                    b"\n    Produced At: \0" as *const u8 as *const libc::c_char,
                                ) <= 0 as libc::c_int)
                                {
                                    if !(ASN1_GENERALIZEDTIME_print(bp, (*rd).producedAt) == 0)
                                    {
                                        if !(BIO_printf(
                                            bp,
                                            b"\n    Responses:\n\0" as *const u8 as *const libc::c_char,
                                        ) <= 0 as libc::c_int)
                                        {
                                            let mut i: size_t = 0 as libc::c_int as size_t;
                                            loop {
                                                if !(i < sk_OCSP_SINGLERESP_num((*rd).responses)) {
                                                    current_block = 2116367355679836638;
                                                    break;
                                                }
                                                if !(sk_OCSP_SINGLERESP_value((*rd).responses, i)).is_null()
                                                {
                                                    single = sk_OCSP_SINGLERESP_value((*rd).responses, i);
                                                    cid = (*single).certId;
                                                    if ocsp_certid_print(bp, cid, 4 as libc::c_int)
                                                        <= 0 as libc::c_int
                                                    {
                                                        current_block = 10160639633444155926;
                                                        break;
                                                    }
                                                    cst = (*single).certStatus;
                                                    if BIO_printf(
                                                        bp,
                                                        b"    Cert Status: %s\0" as *const u8
                                                            as *const libc::c_char,
                                                        OCSP_cert_status_str((*cst).type_0 as libc::c_long),
                                                    ) <= 0 as libc::c_int
                                                    {
                                                        current_block = 10160639633444155926;
                                                        break;
                                                    }
                                                    if (*cst).type_0 == 1 as libc::c_int {
                                                        rev = (*cst).value.revoked;
                                                        if BIO_printf(
                                                            bp,
                                                            b"\n    Revocation Time: \0" as *const u8
                                                                as *const libc::c_char,
                                                        ) <= 0 as libc::c_int
                                                        {
                                                            current_block = 10160639633444155926;
                                                            break;
                                                        }
                                                        if ASN1_GENERALIZEDTIME_print(bp, (*rev).revocationTime)
                                                            == 0
                                                        {
                                                            current_block = 10160639633444155926;
                                                            break;
                                                        }
                                                        if !((*rev).revocationReason).is_null() {
                                                            l = ASN1_ENUMERATED_get((*rev).revocationReason);
                                                            if BIO_printf(
                                                                bp,
                                                                b"\n    Revocation Reason: %s (0x%ld)\0" as *const u8
                                                                    as *const libc::c_char,
                                                                OCSP_crl_reason_str(l),
                                                                l,
                                                            ) <= 0 as libc::c_int
                                                            {
                                                                current_block = 10160639633444155926;
                                                                break;
                                                            }
                                                        }
                                                    }
                                                    if BIO_printf(
                                                        bp,
                                                        b"\n    This Update: \0" as *const u8 as *const libc::c_char,
                                                    ) <= 0 as libc::c_int
                                                    {
                                                        current_block = 10160639633444155926;
                                                        break;
                                                    }
                                                    if ASN1_GENERALIZEDTIME_print(bp, (*single).thisUpdate) == 0
                                                    {
                                                        current_block = 10160639633444155926;
                                                        break;
                                                    }
                                                    if !((*single).nextUpdate).is_null() {
                                                        if BIO_printf(
                                                            bp,
                                                            b"\n    Next Update: \0" as *const u8 as *const libc::c_char,
                                                        ) <= 0 as libc::c_int
                                                        {
                                                            current_block = 10160639633444155926;
                                                            break;
                                                        }
                                                        if ASN1_GENERALIZEDTIME_print(bp, (*single).nextUpdate) == 0
                                                        {
                                                            current_block = 10160639633444155926;
                                                            break;
                                                        }
                                                    }
                                                    if BIO_puts(bp, b"\n\0" as *const u8 as *const libc::c_char)
                                                        <= 0 as libc::c_int
                                                    {
                                                        current_block = 10160639633444155926;
                                                        break;
                                                    }
                                                    if X509V3_extensions_print(
                                                        bp,
                                                        b"Response Single Extensions\0" as *const u8
                                                            as *const libc::c_char,
                                                        (*single).singleExtensions,
                                                        flags,
                                                        8 as libc::c_int,
                                                    ) == 0
                                                    {
                                                        current_block = 10160639633444155926;
                                                        break;
                                                    }
                                                    if BIO_puts(bp, b"\n\0" as *const u8 as *const libc::c_char)
                                                        <= 0 as libc::c_int
                                                    {
                                                        current_block = 10160639633444155926;
                                                        break;
                                                    }
                                                }
                                                i = i.wrapping_add(1);
                                                i;
                                            }
                                            match current_block {
                                                10160639633444155926 => {}
                                                _ => {
                                                    if !(X509V3_extensions_print(
                                                        bp,
                                                        b"Response Extensions\0" as *const u8
                                                            as *const libc::c_char,
                                                        (*rd).responseExtensions,
                                                        flags,
                                                        4 as libc::c_int,
                                                    ) == 0)
                                                    {
                                                        if !(X509_signature_print(
                                                            bp,
                                                            (*br).signatureAlgorithm,
                                                            (*br).signature,
                                                        ) <= 0 as libc::c_int)
                                                        {
                                                            let mut i_0: size_t = 0 as libc::c_int as size_t;
                                                            while i_0 < sk_X509_num((*br).certs) {
                                                                X509_print(bp, sk_X509_value((*br).certs, i_0));
                                                                PEM_write_bio_X509(bp, sk_X509_value((*br).certs, i_0));
                                                                i_0 = i_0.wrapping_add(1);
                                                                i_0;
                                                            }
                                                            ret = 1 as libc::c_int;
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
                }
            }
        }
    }
    OCSP_BASICRESP_free(br);
    return ret;
}
