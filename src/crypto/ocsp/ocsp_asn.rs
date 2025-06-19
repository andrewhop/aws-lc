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
    pub type stack_st_X509_NAME_ENTRY;
    pub type stack_st_X509_EXTENSION;
    pub type stack_st_void;
    pub type stack_st_X509;
    pub type stack_st_OCSP_ONEREQ;
    pub type stack_st_OCSP_SINGLERESP;
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
    fn ASN1_item_d2i_bio(
        it: *const ASN1_ITEM,
        in_0: *mut BIO,
        out: *mut libc::c_void,
    ) -> *mut libc::c_void;
    fn ASN1_item_i2d_bio(
        it: *const ASN1_ITEM,
        out: *mut BIO,
        in_0: *mut libc::c_void,
    ) -> libc::c_int;
    static ASN1_OCTET_STRING_it: ASN1_ITEM;
    static ASN1_BIT_STRING_it: ASN1_ITEM;
    static ASN1_INTEGER_it: ASN1_ITEM;
    static ASN1_ENUMERATED_it: ASN1_ITEM;
    static ASN1_GENERALIZEDTIME_it: ASN1_ITEM;
    static ASN1_NULL_it: ASN1_ITEM;
    static ASN1_OBJECT_it: ASN1_ITEM;
    static X509_it: ASN1_ITEM;
    static X509_NAME_it: ASN1_ITEM;
    static X509_EXTENSION_it: ASN1_ITEM;
    static X509_ALGOR_it: ASN1_ITEM;
    static GENERAL_NAME_it: ASN1_ITEM;
}
pub type size_t = libc::c_ulong;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
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
pub type CRYPTO_refcount_t = uint32_t;
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
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
pub type BIO_METHOD = bio_method_st;
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
static mut OCSP_SIGNATURE_seq_tt: [ASN1_TEMPLATE; 3] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"signatureAlgorithm\0" as *const u8 as *const libc::c_char,
                item: &X509_ALGOR_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"signature\0" as *const u8 as *const libc::c_char,
                item: &ASN1_BIT_STRING_it as *const ASN1_ITEM,
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
                offset: 16 as libc::c_ulong,
                field_name: b"certs\0" as *const u8 as *const libc::c_char,
                item: &X509_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut OCSP_SIGNATURE_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
static mut OCSP_CERTID_seq_tt: [ASN1_TEMPLATE; 4] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"hashAlgorithm\0" as *const u8 as *const libc::c_char,
                item: &X509_ALGOR_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"issuerNameHash\0" as *const u8 as *const libc::c_char,
                item: &ASN1_OCTET_STRING_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 16 as libc::c_ulong,
                field_name: b"issuerKeyHash\0" as *const u8 as *const libc::c_char,
                item: &ASN1_OCTET_STRING_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 24 as libc::c_ulong,
                field_name: b"serialNumber\0" as *const u8 as *const libc::c_char,
                item: &ASN1_INTEGER_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut OCSP_CERTID_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
static mut OCSP_ONEREQ_seq_tt: [ASN1_TEMPLATE; 2] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"reqCert\0" as *const u8 as *const libc::c_char,
                item: &OCSP_CERTID_it as *const ASN1_ITEM,
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
                offset: 8 as libc::c_ulong,
                field_name: b"singleRequestExtensions\0" as *const u8
                    as *const libc::c_char,
                item: &X509_EXTENSION_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut OCSP_ONEREQ_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
static mut OCSP_REQINFO_seq_tt: [ASN1_TEMPLATE; 4] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"version\0" as *const u8 as *const libc::c_char,
                item: &ASN1_INTEGER_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 1 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"requestorName\0" as *const u8 as *const libc::c_char,
                item: &GENERAL_NAME_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 1 as libc::c_int) as uint32_t,
                tag: 0 as libc::c_int,
                offset: 16 as libc::c_ulong,
                field_name: b"requestList\0" as *const u8 as *const libc::c_char,
                item: &OCSP_ONEREQ_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int
                    | (0x2 as libc::c_int) << 1 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 2 as libc::c_int,
                offset: 24 as libc::c_ulong,
                field_name: b"requestExtensions\0" as *const u8 as *const libc::c_char,
                item: &X509_EXTENSION_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut OCSP_REQINFO_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
static mut OCSP_REQUEST_seq_tt: [ASN1_TEMPLATE; 2] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"tbsRequest\0" as *const u8 as *const libc::c_char,
                item: &OCSP_REQINFO_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"optionalSignature\0" as *const u8 as *const libc::c_char,
                item: &OCSP_SIGNATURE_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut OCSP_REQUEST_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
static mut OCSP_RESPBYTES_seq_tt: [ASN1_TEMPLATE; 2] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"responseType\0" as *const u8 as *const libc::c_char,
                item: &ASN1_OBJECT_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"response\0" as *const u8 as *const libc::c_char,
                item: &ASN1_OCTET_STRING_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut OCSP_RESPBYTES_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
static mut OCSP_RESPONSE_seq_tt: [ASN1_TEMPLATE; 2] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"responseStatus\0" as *const u8 as *const libc::c_char,
                item: &ASN1_ENUMERATED_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"responseBytes\0" as *const u8 as *const libc::c_char,
                item: &OCSP_RESPBYTES_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut OCSP_RESPONSE_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
static mut OCSP_RESPID_ch_tt: [ASN1_TEMPLATE; 2] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0 as libc::c_int)
                    as uint32_t,
                tag: 1 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"value.byName\0" as *const u8 as *const libc::c_char,
                item: &X509_NAME_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0 as libc::c_int)
                    as uint32_t,
                tag: 2 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"value.byKey\0" as *const u8 as *const libc::c_char,
                item: &ASN1_OCTET_STRING_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut OCSP_RESPID_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
static mut OCSP_REVOKEDINFO_seq_tt: [ASN1_TEMPLATE; 2] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"revocationTime\0" as *const u8 as *const libc::c_char,
                item: &ASN1_GENERALIZEDTIME_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"revocationReason\0" as *const u8 as *const libc::c_char,
                item: &ASN1_ENUMERATED_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut OCSP_REVOKEDINFO_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
static mut OCSP_CERTSTATUS_ch_tt: [ASN1_TEMPLATE; 3] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"value.good\0" as *const u8 as *const libc::c_char,
                item: &ASN1_NULL_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0 as libc::c_int)
                    as uint32_t,
                tag: 1 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"value.revoked\0" as *const u8 as *const libc::c_char,
                item: &OCSP_REVOKEDINFO_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0 as libc::c_int)
                    as uint32_t,
                tag: 2 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"value.unknown\0" as *const u8 as *const libc::c_char,
                item: &ASN1_NULL_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut OCSP_CERTSTATUS_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
static mut OCSP_SINGLERESP_seq_tt: [ASN1_TEMPLATE; 5] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"certId\0" as *const u8 as *const libc::c_char,
                item: &OCSP_CERTID_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"certStatus\0" as *const u8 as *const libc::c_char,
                item: &OCSP_CERTSTATUS_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 16 as libc::c_ulong,
                field_name: b"thisUpdate\0" as *const u8 as *const libc::c_char,
                item: &ASN1_GENERALIZEDTIME_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 24 as libc::c_ulong,
                field_name: b"nextUpdate\0" as *const u8 as *const libc::c_char,
                item: &ASN1_GENERALIZEDTIME_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int
                    | (0x2 as libc::c_int) << 1 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 1 as libc::c_int,
                offset: 32 as libc::c_ulong,
                field_name: b"singleExtensions\0" as *const u8 as *const libc::c_char,
                item: &X509_EXTENSION_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut OCSP_SINGLERESP_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
static mut OCSP_RESPDATA_seq_tt: [ASN1_TEMPLATE; 5] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
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
                field_name: b"responderId\0" as *const u8 as *const libc::c_char,
                item: &OCSP_RESPID_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 16 as libc::c_ulong,
                field_name: b"producedAt\0" as *const u8 as *const libc::c_char,
                item: &ASN1_GENERALIZEDTIME_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 1 as libc::c_int) as uint32_t,
                tag: 0 as libc::c_int,
                offset: 24 as libc::c_ulong,
                field_name: b"responses\0" as *const u8 as *const libc::c_char,
                item: &OCSP_SINGLERESP_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int
                    | (0x2 as libc::c_int) << 1 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 1 as libc::c_int,
                offset: 32 as libc::c_ulong,
                field_name: b"responseExtensions\0" as *const u8 as *const libc::c_char,
                item: &X509_EXTENSION_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut OCSP_RESPDATA_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
static mut OCSP_BASICRESP_seq_tt: [ASN1_TEMPLATE; 4] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"tbsResponseData\0" as *const u8 as *const libc::c_char,
                item: &OCSP_RESPDATA_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"signatureAlgorithm\0" as *const u8 as *const libc::c_char,
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
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int
                    | (0x2 as libc::c_int) << 1 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 24 as libc::c_ulong,
                field_name: b"certs\0" as *const u8 as *const libc::c_char,
                item: &X509_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut OCSP_BASICRESP_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_SIGNATURE(
    mut a: *mut OCSP_SIGNATURE,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &OCSP_SIGNATURE_it);
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_SIGNATURE_free(mut a: *mut OCSP_SIGNATURE) {
    ASN1_item_free(a as *mut ASN1_VALUE, &OCSP_SIGNATURE_it);
}
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_SIGNATURE(
    mut a: *mut *mut OCSP_SIGNATURE,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut OCSP_SIGNATURE {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &OCSP_SIGNATURE_it)
        as *mut OCSP_SIGNATURE;
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_SIGNATURE_new() -> *mut OCSP_SIGNATURE {
    return ASN1_item_new(&OCSP_SIGNATURE_it) as *mut OCSP_SIGNATURE;
}
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_CERTID(
    mut a: *mut OCSP_CERTID,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &OCSP_CERTID_it);
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_CERTID_free(mut a: *mut OCSP_CERTID) {
    ASN1_item_free(a as *mut ASN1_VALUE, &OCSP_CERTID_it);
}
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_CERTID(
    mut a: *mut *mut OCSP_CERTID,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut OCSP_CERTID {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &OCSP_CERTID_it)
        as *mut OCSP_CERTID;
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_CERTID_new() -> *mut OCSP_CERTID {
    return ASN1_item_new(&OCSP_CERTID_it) as *mut OCSP_CERTID;
}
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_ONEREQ(
    mut a: *mut OCSP_ONEREQ,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &OCSP_ONEREQ_it);
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_ONEREQ_free(mut a: *mut OCSP_ONEREQ) {
    ASN1_item_free(a as *mut ASN1_VALUE, &OCSP_ONEREQ_it);
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_ONEREQ_new() -> *mut OCSP_ONEREQ {
    return ASN1_item_new(&OCSP_ONEREQ_it) as *mut OCSP_ONEREQ;
}
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_ONEREQ(
    mut a: *mut *mut OCSP_ONEREQ,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut OCSP_ONEREQ {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &OCSP_ONEREQ_it)
        as *mut OCSP_ONEREQ;
}
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_REQINFO(
    mut a: *mut OCSP_REQINFO,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &OCSP_REQINFO_it);
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_REQINFO_free(mut a: *mut OCSP_REQINFO) {
    ASN1_item_free(a as *mut ASN1_VALUE, &OCSP_REQINFO_it);
}
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_REQINFO(
    mut a: *mut *mut OCSP_REQINFO,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut OCSP_REQINFO {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &OCSP_REQINFO_it)
        as *mut OCSP_REQINFO;
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_REQINFO_new() -> *mut OCSP_REQINFO {
    return ASN1_item_new(&OCSP_REQINFO_it) as *mut OCSP_REQINFO;
}
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_REQUEST(
    mut a: *mut OCSP_REQUEST,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &OCSP_REQUEST_it);
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_REQUEST_free(mut a: *mut OCSP_REQUEST) {
    ASN1_item_free(a as *mut ASN1_VALUE, &OCSP_REQUEST_it);
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_REQUEST_new() -> *mut OCSP_REQUEST {
    return ASN1_item_new(&OCSP_REQUEST_it) as *mut OCSP_REQUEST;
}
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_REQUEST(
    mut a: *mut *mut OCSP_REQUEST,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut OCSP_REQUEST {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &OCSP_REQUEST_it)
        as *mut OCSP_REQUEST;
}
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_RESPONSE(
    mut a: *mut OCSP_RESPONSE,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &OCSP_RESPONSE_it);
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_RESPONSE_free(mut a: *mut OCSP_RESPONSE) {
    ASN1_item_free(a as *mut ASN1_VALUE, &OCSP_RESPONSE_it);
}
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_RESPONSE(
    mut a: *mut *mut OCSP_RESPONSE,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut OCSP_RESPONSE {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &OCSP_RESPONSE_it)
        as *mut OCSP_RESPONSE;
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_RESPONSE_new() -> *mut OCSP_RESPONSE {
    return ASN1_item_new(&OCSP_RESPONSE_it) as *mut OCSP_RESPONSE;
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_RESPBYTES_free(mut a: *mut OCSP_RESPBYTES) {
    ASN1_item_free(a as *mut ASN1_VALUE, &OCSP_RESPBYTES_it);
}
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_RESPBYTES(
    mut a: *mut OCSP_RESPBYTES,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &OCSP_RESPBYTES_it);
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_RESPBYTES_new() -> *mut OCSP_RESPBYTES {
    return ASN1_item_new(&OCSP_RESPBYTES_it) as *mut OCSP_RESPBYTES;
}
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_RESPBYTES(
    mut a: *mut *mut OCSP_RESPBYTES,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut OCSP_RESPBYTES {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &OCSP_RESPBYTES_it)
        as *mut OCSP_RESPBYTES;
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_RESPDATA_free(mut a: *mut OCSP_RESPDATA) {
    ASN1_item_free(a as *mut ASN1_VALUE, &OCSP_RESPDATA_it);
}
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_RESPDATA(
    mut a: *mut OCSP_RESPDATA,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &OCSP_RESPDATA_it);
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_RESPDATA_new() -> *mut OCSP_RESPDATA {
    return ASN1_item_new(&OCSP_RESPDATA_it) as *mut OCSP_RESPDATA;
}
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_RESPDATA(
    mut a: *mut *mut OCSP_RESPDATA,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut OCSP_RESPDATA {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &OCSP_RESPDATA_it)
        as *mut OCSP_RESPDATA;
}
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_REVOKEDINFO(
    mut a: *mut OCSP_REVOKEDINFO,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &OCSP_REVOKEDINFO_it);
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_REVOKEDINFO_free(mut a: *mut OCSP_REVOKEDINFO) {
    ASN1_item_free(a as *mut ASN1_VALUE, &OCSP_REVOKEDINFO_it);
}
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_REVOKEDINFO(
    mut a: *mut *mut OCSP_REVOKEDINFO,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut OCSP_REVOKEDINFO {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &OCSP_REVOKEDINFO_it)
        as *mut OCSP_REVOKEDINFO;
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_REVOKEDINFO_new() -> *mut OCSP_REVOKEDINFO {
    return ASN1_item_new(&OCSP_REVOKEDINFO_it) as *mut OCSP_REVOKEDINFO;
}
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_BASICRESP(
    mut a: *mut OCSP_BASICRESP,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &OCSP_BASICRESP_it);
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_BASICRESP_free(mut a: *mut OCSP_BASICRESP) {
    ASN1_item_free(a as *mut ASN1_VALUE, &OCSP_BASICRESP_it);
}
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_BASICRESP(
    mut a: *mut *mut OCSP_BASICRESP,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut OCSP_BASICRESP {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &OCSP_BASICRESP_it)
        as *mut OCSP_BASICRESP;
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_BASICRESP_new() -> *mut OCSP_BASICRESP {
    return ASN1_item_new(&OCSP_BASICRESP_it) as *mut OCSP_BASICRESP;
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_CERTID_dup(mut x: *mut OCSP_CERTID) -> *mut OCSP_CERTID {
    return ASN1_item_dup(&OCSP_CERTID_it, x as *mut libc::c_void) as *mut OCSP_CERTID;
}
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_SINGLERESP(
    mut a: *mut OCSP_SINGLERESP,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &OCSP_SINGLERESP_it);
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_SINGLERESP_free(mut a: *mut OCSP_SINGLERESP) {
    ASN1_item_free(a as *mut ASN1_VALUE, &OCSP_SINGLERESP_it);
}
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_SINGLERESP(
    mut a: *mut *mut OCSP_SINGLERESP,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut OCSP_SINGLERESP {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &OCSP_SINGLERESP_it)
        as *mut OCSP_SINGLERESP;
}
#[no_mangle]
pub unsafe extern "C" fn OCSP_SINGLERESP_new() -> *mut OCSP_SINGLERESP {
    return ASN1_item_new(&OCSP_SINGLERESP_it) as *mut OCSP_SINGLERESP;
}
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_RESPONSE_bio(
    mut bp: *mut BIO,
    mut presp: *mut *mut OCSP_RESPONSE,
) -> *mut OCSP_RESPONSE {
    return ASN1_item_d2i_bio(&OCSP_RESPONSE_it, bp, presp as *mut libc::c_void)
        as *mut OCSP_RESPONSE;
}
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_RESPONSE_bio(
    mut bp: *mut BIO,
    mut presp: *mut OCSP_RESPONSE,
) -> libc::c_int {
    return ASN1_item_i2d_bio(&OCSP_RESPONSE_it, bp, presp as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_REQUEST_bio(
    mut bp: *mut BIO,
    mut preq: *mut *mut OCSP_REQUEST,
) -> *mut OCSP_REQUEST {
    return ASN1_item_d2i_bio(&OCSP_REQUEST_it, bp, preq as *mut libc::c_void)
        as *mut OCSP_REQUEST;
}
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_REQUEST_bio(
    mut bp: *mut BIO,
    mut preq: *mut OCSP_REQUEST,
) -> libc::c_int {
    return ASN1_item_i2d_bio(&OCSP_REQUEST_it, bp, preq as *mut libc::c_void);
}
unsafe extern "C" fn run_static_initializers() {
    OCSP_SIGNATURE_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: OCSP_SIGNATURE_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 3]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<OCSP_SIGNATURE>() as libc::c_ulong
                as libc::c_long,
            sname: b"OCSP_SIGNATURE\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    OCSP_CERTID_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: OCSP_CERTID_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 4]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<OCSP_CERTID>() as libc::c_ulong as libc::c_long,
            sname: b"OCSP_CERTID\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    OCSP_ONEREQ_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: OCSP_ONEREQ_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 2]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<OCSP_ONEREQ>() as libc::c_ulong as libc::c_long,
            sname: b"OCSP_ONEREQ\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    OCSP_REQINFO_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: OCSP_REQINFO_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 4]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<OCSP_REQINFO>() as libc::c_ulong
                as libc::c_long,
            sname: b"OCSP_REQINFO\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    OCSP_REQUEST_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: OCSP_REQUEST_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 2]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<OCSP_REQUEST>() as libc::c_ulong
                as libc::c_long,
            sname: b"OCSP_REQUEST\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    OCSP_RESPBYTES_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: OCSP_RESPBYTES_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 2]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<OCSP_RESPBYTES>() as libc::c_ulong
                as libc::c_long,
            sname: b"OCSP_RESPBYTES\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    OCSP_RESPONSE_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: OCSP_RESPONSE_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 2]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<OCSP_RESPONSE>() as libc::c_ulong
                as libc::c_long,
            sname: b"OCSP_RESPONSE\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    OCSP_RESPID_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x2 as libc::c_int as libc::c_char,
            utype: 0 as libc::c_ulong as libc::c_int,
            templates: OCSP_RESPID_ch_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 2]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<OCSP_RESPID>() as libc::c_ulong as libc::c_long,
            sname: b"OCSP_RESPID\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    OCSP_REVOKEDINFO_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: OCSP_REVOKEDINFO_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 2]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<OCSP_REVOKEDINFO>() as libc::c_ulong
                as libc::c_long,
            sname: b"OCSP_REVOKEDINFO\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    OCSP_CERTSTATUS_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x2 as libc::c_int as libc::c_char,
            utype: 0 as libc::c_ulong as libc::c_int,
            templates: OCSP_CERTSTATUS_ch_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 3]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<OCSP_CERTSTATUS>() as libc::c_ulong
                as libc::c_long,
            sname: b"OCSP_CERTSTATUS\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    OCSP_SINGLERESP_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: OCSP_SINGLERESP_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 5]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<OCSP_SINGLERESP>() as libc::c_ulong
                as libc::c_long,
            sname: b"OCSP_SINGLERESP\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    OCSP_RESPDATA_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: OCSP_RESPDATA_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 5]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<OCSP_RESPDATA>() as libc::c_ulong
                as libc::c_long,
            sname: b"OCSP_RESPDATA\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    OCSP_BASICRESP_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: OCSP_BASICRESP_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 4]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<OCSP_BASICRESP>() as libc::c_ulong
                as libc::c_long,
            sname: b"OCSP_BASICRESP\0" as *const u8 as *const libc::c_char,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
