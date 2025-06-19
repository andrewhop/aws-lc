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
    pub type asn1_object_st;
    pub type ASN1_VALUE_st;
    pub type X509_name_st;
    pub type stack_st_void;
    pub type stack_st_X509;
    pub type stack_st_X509_EXTENSION;
    pub type stack_st_OCSP_ONEREQ;
    fn memchr(
        _: *const libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strncmp(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strtoul(
        _: *const libc::c_char,
        _: *mut *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_ulong;
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
    fn ASN1_item_i2d_bio(
        it: *const ASN1_ITEM,
        out: *mut BIO,
        in_0: *mut libc::c_void,
    ) -> libc::c_int;
    fn BIO_new(method: *const BIO_METHOD) -> *mut BIO;
    fn BIO_free(bio: *mut BIO) -> libc::c_int;
    fn BIO_read(bio: *mut BIO, data: *mut libc::c_void, len: libc::c_int) -> libc::c_int;
    fn BIO_gets(bio: *mut BIO, buf: *mut libc::c_char, size: libc::c_int) -> libc::c_int;
    fn BIO_write(
        bio: *mut BIO,
        data: *const libc::c_void,
        len: libc::c_int,
    ) -> libc::c_int;
    fn BIO_puts(bio: *mut BIO, buf: *const libc::c_char) -> libc::c_int;
    fn BIO_flush(bio: *mut BIO) -> libc::c_int;
    fn BIO_reset(bio: *mut BIO) -> libc::c_int;
    fn BIO_should_retry(bio: *const BIO) -> libc::c_int;
    fn BIO_printf(bio: *mut BIO, format: *const libc::c_char, _: ...) -> libc::c_int;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_mem_contents(
        bio: *const BIO,
        out_contents: *mut *const uint8_t,
        out_len: *mut size_t,
    ) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_isspace(c: libc::c_int) -> libc::c_int;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn ERR_add_error_data(count: libc::c_uint, _: ...);
    static OCSP_RESPONSE_it: ASN1_ITEM;
    static OCSP_REQUEST_it: ASN1_ITEM;
}
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type size_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ocsp_req_ctx_st {
    pub state: libc::c_int,
    pub iobuf: *mut libc::c_uchar,
    pub iobuflen: libc::c_int,
    pub io: *mut BIO,
    pub mem: *mut BIO,
    pub asn1_len: libc::c_ulong,
    pub max_resp_len: libc::c_ulong,
}
pub type OCSP_REQ_CTX = ocsp_req_ctx_st;
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
pub struct ocsp_response_st {
    pub responseStatus: *mut ASN1_ENUMERATED,
    pub responseBytes: *mut OCSP_RESPBYTES,
}
pub type OCSP_RESPONSE = ocsp_response_st;
unsafe extern "C" fn check_protocol(mut line: *mut libc::c_char) -> libc::c_int {
    if strlen(line) >= 4 as libc::c_int as libc::c_ulong
        && strncmp(
            line,
            b"HTTP\0" as *const u8 as *const libc::c_char,
            4 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
    {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn parse_http_line(mut line: *mut libc::c_char) -> libc::c_int {
    let mut http_code: libc::c_int = 0;
    let mut code: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut reason: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut end: *mut libc::c_char = 0 as *mut libc::c_char;
    if check_protocol(line) == 0 {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            115 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_http.c\0" as *const u8
                as *const libc::c_char,
            60 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    code = line;
    while *code as libc::c_int != '\0' as i32
        && OPENSSL_isspace(*code as libc::c_int) == 0
    {
        code = code.offset(1);
        code;
    }
    if *code as libc::c_int == '\0' as i32 {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            115 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_http.c\0" as *const u8
                as *const libc::c_char,
            68 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    while *code as libc::c_int != '\0' as i32
        && OPENSSL_isspace(*code as libc::c_int) != 0
    {
        code = code.offset(1);
        code;
    }
    if *code as libc::c_int == '\0' as i32 {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            115 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_http.c\0" as *const u8
                as *const libc::c_char,
            77 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    reason = code;
    while *reason as libc::c_int != '\0' as i32
        && OPENSSL_isspace(*reason as libc::c_int) == 0
    {
        reason = reason.offset(1);
        reason;
    }
    if *reason as libc::c_int == '\0' as i32 {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            115 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_http.c\0" as *const u8
                as *const libc::c_char,
            86 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let fresh0 = reason;
    reason = reason.offset(1);
    *fresh0 = '\0' as i32 as libc::c_char;
    http_code = strtoul(code, &mut end, 10 as libc::c_int) as libc::c_int;
    if *end as libc::c_int != '\0' as i32 {
        return 0 as libc::c_int;
    }
    while *reason as libc::c_int != '\0' as i32
        && OPENSSL_isspace(*reason as libc::c_int) != 0
    {
        reason = reason.offset(1);
        reason;
    }
    if *reason as libc::c_int != '\0' as i32 {
        end = reason
            .offset(strlen(reason) as isize)
            .offset(-(1 as libc::c_int as isize));
        while OPENSSL_isspace(*end as libc::c_int) != 0 {
            *end = '\0' as i32 as libc::c_char;
            end = end.offset(-1);
            end;
        }
    }
    if http_code != 200 as libc::c_int {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            115 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_http.c\0" as *const u8
                as *const libc::c_char,
            110 as libc::c_int as libc::c_uint,
        );
        if *reason as libc::c_int == '\0' as i32 {
            ERR_add_error_data(
                2 as libc::c_int as libc::c_uint,
                b"Code=\0" as *const u8 as *const libc::c_char,
                code,
            );
        } else {
            ERR_add_error_data(
                4 as libc::c_int as libc::c_uint,
                b"Code=\0" as *const u8 as *const libc::c_char,
                code,
                b",Reason=\0" as *const u8 as *const libc::c_char,
                reason,
            );
        }
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_REQ_CTX_nbio(mut rctx: *mut OCSP_REQ_CTX) -> libc::c_int {
    let mut write_len: libc::c_int = 0;
    let mut current_block: u64;
    let mut ret: libc::c_int = 0;
    let mut tmp_data_len: libc::c_int = 0;
    let mut data_len: size_t = 0;
    let mut data: *const libc::c_uchar = 0 as *const libc::c_uchar;
    '_next_io: loop {
        if (*rctx).state & 0x1000 as libc::c_int == 0 {
            tmp_data_len = BIO_read(
                (*rctx).io,
                (*rctx).iobuf as *mut libc::c_void,
                (*rctx).iobuflen,
            );
            if tmp_data_len <= 0 as libc::c_int {
                if BIO_should_retry((*rctx).io) != 0 {
                    return -(1 as libc::c_int);
                }
                return 0 as libc::c_int;
            }
            if BIO_write((*rctx).mem, (*rctx).iobuf as *const libc::c_void, tmp_data_len)
                != tmp_data_len
            {
                return 0 as libc::c_int;
            }
            data_len = tmp_data_len as size_t;
        }
        match (*rctx).state {
            4105 => {
                if BIO_write(
                    (*rctx).mem,
                    b"\r\n\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                    2 as libc::c_int,
                ) != 2 as libc::c_int
                {
                    (*rctx).state = 0 as libc::c_int | 0x1000 as libc::c_int;
                    return 0 as libc::c_int;
                }
                (*rctx).state = 5 as libc::c_int | 0x1000 as libc::c_int;
                current_block = 4917923416832549132;
            }
            4101 => {
                current_block = 4917923416832549132;
            }
            4102 => {
                current_block = 13790994670432130145;
            }
            4103 => {
                current_block = 11601792268857826931;
            }
            4096 => return 0 as libc::c_int,
            1 | 2 => {
                loop {
                    if BIO_mem_contents((*rctx).mem, &mut data, &mut data_len) == 0 {
                        (*rctx).state = 0 as libc::c_int | 0x1000 as libc::c_int;
                        return 0 as libc::c_int;
                    }
                    if data_len <= 0 as libc::c_int as size_t
                        || (memchr(data as *const libc::c_void, '\n' as i32, data_len))
                            .is_null()
                    {
                        if data_len >= (*rctx).iobuflen as size_t {
                            (*rctx).state = 0 as libc::c_int | 0x1000 as libc::c_int;
                            return 0 as libc::c_int;
                        }
                        continue '_next_io;
                    } else {
                        tmp_data_len = BIO_gets(
                            (*rctx).mem,
                            (*rctx).iobuf as *mut libc::c_char,
                            (*rctx).iobuflen,
                        );
                        if tmp_data_len <= 0 as libc::c_int {
                            if BIO_should_retry((*rctx).mem) != 0 {
                                continue '_next_io;
                            }
                            (*rctx).state = 0 as libc::c_int | 0x1000 as libc::c_int;
                            return 0 as libc::c_int;
                        } else {
                            if tmp_data_len >= (*rctx).iobuflen {
                                (*rctx).state = 0 as libc::c_int | 0x1000 as libc::c_int;
                                return 0 as libc::c_int;
                            }
                            data_len = tmp_data_len as size_t;
                            if (*rctx).state == 1 as libc::c_int {
                                if parse_http_line((*rctx).iobuf as *mut libc::c_char) != 0
                                {
                                    (*rctx).state = 2 as libc::c_int;
                                } else {
                                    (*rctx).state = 0 as libc::c_int | 0x1000 as libc::c_int;
                                    return 0 as libc::c_int;
                                }
                            } else {
                                data = (*rctx).iobuf;
                                while *data != 0 {
                                    if *data as libc::c_int != '\r' as i32
                                        && *data as libc::c_int != '\n' as i32
                                    {
                                        break;
                                    }
                                    data = data.offset(1);
                                    data;
                                }
                                if *data as libc::c_int != '\0' as i32 {
                                    continue;
                                }
                                (*rctx).state = 3 as libc::c_int;
                                break;
                            }
                        }
                    }
                }
                current_block = 6843121602019635263;
            }
            3 => {
                current_block = 6843121602019635263;
            }
            4 => {
                current_block = 14302567791858217094;
            }
            4104 => return 1 as libc::c_int,
            _ => return 0 as libc::c_int,
        }
        match current_block {
            6843121602019635263 => {
                if BIO_mem_contents((*rctx).mem, &mut data, &mut data_len) == 0 {
                    (*rctx).state = 0 as libc::c_int | 0x1000 as libc::c_int;
                    return 0 as libc::c_int;
                }
                if data_len < 2 as libc::c_int as size_t {
                    continue;
                }
                let fresh1 = data;
                data = data.offset(1);
                if *fresh1 as libc::c_int != 16 as libc::c_int | 0x20 as libc::c_int {
                    (*rctx).state = 0 as libc::c_int | 0x1000 as libc::c_int;
                    return 0 as libc::c_int;
                }
                if *data as libc::c_int & 0x80 as libc::c_int != 0 as libc::c_int {
                    if data_len < 6 as libc::c_int as size_t {
                        continue;
                    }
                    data_len = (*data as libc::c_int & 0x7f as libc::c_int) as size_t;
                    if data_len == 0 || data_len > 4 as libc::c_int as size_t {
                        (*rctx).state = 0 as libc::c_int | 0x1000 as libc::c_int;
                        return 0 as libc::c_int;
                    }
                    data = data.offset(1);
                    data;
                    (*rctx).asn1_len = 0 as libc::c_int as libc::c_ulong;
                    let mut i: size_t = 0 as libc::c_int as size_t;
                    while i < data_len {
                        (*rctx).asn1_len <<= 8 as libc::c_int;
                        let fresh2 = data;
                        data = data.offset(1);
                        (*rctx).asn1_len |= *fresh2 as libc::c_ulong;
                        i = i.wrapping_add(1);
                        i;
                    }
                    if (*rctx).asn1_len > (*rctx).max_resp_len {
                        (*rctx).state = 0 as libc::c_int | 0x1000 as libc::c_int;
                        return 0 as libc::c_int;
                    }
                    (*rctx)
                        .asn1_len = ((*rctx).asn1_len)
                        .wrapping_add(data_len.wrapping_add(2 as libc::c_int as size_t));
                } else {
                    (*rctx)
                        .asn1_len = (*data as libc::c_int + 2 as libc::c_int)
                        as libc::c_ulong;
                }
                (*rctx).state = 4 as libc::c_int;
                current_block = 14302567791858217094;
            }
            4917923416832549132 => {
                if BIO_mem_contents((*rctx).mem, 0 as *mut *const uint8_t, &mut data_len)
                    == 0
                {
                    (*rctx).state = 0 as libc::c_int | 0x1000 as libc::c_int;
                    return 0 as libc::c_int;
                }
                (*rctx).asn1_len = data_len;
                (*rctx).state = 6 as libc::c_int | 0x1000 as libc::c_int;
                current_block = 13790994670432130145;
            }
            _ => {}
        }
        match current_block {
            14302567791858217094 => {
                if BIO_mem_contents((*rctx).mem, 0 as *mut *const uint8_t, &mut data_len)
                    == 0
                {
                    (*rctx).state = 0 as libc::c_int | 0x1000 as libc::c_int;
                    return 0 as libc::c_int;
                }
                if data_len < (*rctx).asn1_len {
                    continue;
                }
                (*rctx).state = 8 as libc::c_int | 0x1000 as libc::c_int;
                return 1 as libc::c_int;
            }
            13790994670432130145 => {
                if BIO_mem_contents((*rctx).mem, &mut data, &mut data_len) == 0 {
                    (*rctx).state = 0 as libc::c_int | 0x1000 as libc::c_int;
                    return 0 as libc::c_int;
                }
                write_len = BIO_write(
                    (*rctx).io,
                    data.offset(data_len.wrapping_sub((*rctx).asn1_len) as isize)
                        as *const libc::c_void,
                    (*rctx).asn1_len as libc::c_int,
                );
                if write_len <= 0 as libc::c_int {
                    if BIO_should_retry((*rctx).io) != 0 {
                        return -(1 as libc::c_int);
                    }
                    (*rctx).state = 0 as libc::c_int | 0x1000 as libc::c_int;
                    return 0 as libc::c_int;
                }
                (*rctx)
                    .asn1_len = ((*rctx).asn1_len)
                    .wrapping_sub(write_len as libc::c_ulong);
                if (*rctx).asn1_len > 0 as libc::c_int as libc::c_ulong {
                    continue;
                }
                (*rctx).state = 7 as libc::c_int | 0x1000 as libc::c_int;
                if BIO_reset((*rctx).mem) == 0 {
                    return 0 as libc::c_int;
                }
            }
            _ => {}
        }
        ret = BIO_flush((*rctx).io);
        if ret > 0 as libc::c_int {
            (*rctx).state = 1 as libc::c_int;
        } else {
            if BIO_should_retry((*rctx).io) != 0 {
                return -(1 as libc::c_int);
            }
            (*rctx).state = 0 as libc::c_int | 0x1000 as libc::c_int;
            return 0 as libc::c_int;
        }
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_sendreq_nbio(
    mut presp: *mut *mut OCSP_RESPONSE,
    mut rctx: *mut OCSP_REQ_CTX,
) -> libc::c_int {
    return OCSP_REQ_CTX_nbio_d2i(rctx, presp as *mut *mut ASN1_VALUE, &OCSP_RESPONSE_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_sendreq_bio(
    mut b: *mut BIO,
    mut path: *const libc::c_char,
    mut req: *mut OCSP_REQUEST,
) -> *mut OCSP_RESPONSE {
    let mut resp: *mut OCSP_RESPONSE = 0 as *mut OCSP_RESPONSE;
    let mut ctx: *mut OCSP_REQ_CTX = 0 as *mut OCSP_REQ_CTX;
    let mut rv: libc::c_int = 0;
    ctx = OCSP_sendreq_new(b, path, req, -(1 as libc::c_int));
    if ctx.is_null() {
        return 0 as *mut OCSP_RESPONSE;
    }
    loop {
        rv = OCSP_sendreq_nbio(&mut resp, ctx);
        if !(rv == -(1 as libc::c_int) && BIO_should_retry(b) != 0) {
            break;
        }
    }
    OCSP_REQ_CTX_free(ctx);
    if rv != 0 {
        return resp;
    }
    return 0 as *mut OCSP_RESPONSE;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_REQ_CTX_nbio_d2i(
    mut rctx: *mut OCSP_REQ_CTX,
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
) -> libc::c_int {
    let mut rv: libc::c_int = 0;
    let mut len: size_t = 0;
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    rv = OCSP_REQ_CTX_nbio(rctx);
    if rv != 1 as libc::c_int {
        return rv;
    }
    if !(BIO_mem_contents((*rctx).mem, &mut p, &mut len) == 0) {
        *pval = ASN1_item_d2i(
            0 as *mut *mut ASN1_VALUE,
            &mut p,
            len as libc::c_long,
            it,
        );
        if !(*pval).is_null() {
            return 1 as libc::c_int;
        }
    }
    (*rctx).state = 0 as libc::c_int | 0x1000 as libc::c_int;
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_REQ_CTX_new(
    mut io: *mut BIO,
    mut maxline: libc::c_int,
) -> *mut OCSP_REQ_CTX {
    let mut rctx: *mut OCSP_REQ_CTX = OPENSSL_malloc(
        ::core::mem::size_of::<OCSP_REQ_CTX>() as libc::c_ulong,
    ) as *mut OCSP_REQ_CTX;
    if rctx.is_null() {
        return 0 as *mut OCSP_REQ_CTX;
    }
    (*rctx).state = 0 as libc::c_int | 0x1000 as libc::c_int;
    (*rctx).max_resp_len = (100 as libc::c_int * 1024 as libc::c_int) as libc::c_ulong;
    (*rctx).mem = BIO_new(BIO_s_mem());
    (*rctx).io = io;
    if maxline > 0 as libc::c_int {
        (*rctx).iobuflen = maxline;
    } else {
        (*rctx).iobuflen = 4096 as libc::c_int;
    }
    (*rctx).iobuf = OPENSSL_malloc((*rctx).iobuflen as size_t) as *mut libc::c_uchar;
    if ((*rctx).iobuf).is_null() || ((*rctx).mem).is_null() {
        OCSP_REQ_CTX_free(rctx);
        return 0 as *mut OCSP_REQ_CTX;
    }
    return rctx;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_REQ_CTX_free(mut rctx: *mut OCSP_REQ_CTX) {
    if rctx.is_null() {
        return;
    }
    BIO_free((*rctx).mem);
    OPENSSL_free((*rctx).iobuf as *mut libc::c_void);
    OPENSSL_free(rctx as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_sendreq_new(
    mut io: *mut BIO,
    mut path: *const libc::c_char,
    mut req: *mut OCSP_REQUEST,
    mut maxline: libc::c_int,
) -> *mut OCSP_REQ_CTX {
    let mut rctx: *mut OCSP_REQ_CTX = 0 as *mut OCSP_REQ_CTX;
    rctx = OCSP_REQ_CTX_new(io, maxline);
    if rctx.is_null() {
        return 0 as *mut OCSP_REQ_CTX;
    }
    if !(OCSP_REQ_CTX_http(rctx, b"POST\0" as *const u8 as *const libc::c_char, path)
        == 0)
    {
        if !(!req.is_null() && OCSP_REQ_CTX_set1_req(rctx, req) == 0) {
            return rctx;
        }
    }
    OCSP_REQ_CTX_free(rctx);
    return 0 as *mut OCSP_REQ_CTX;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_REQ_CTX_http(
    mut rctx: *mut OCSP_REQ_CTX,
    mut op: *const libc::c_char,
    mut path: *const libc::c_char,
) -> libc::c_int {
    static mut http_hdr: [libc::c_char; 17] = unsafe {
        *::core::mem::transmute::<
            &[u8; 17],
            &[libc::c_char; 17],
        >(b"%s %s HTTP/1.0\r\n\0")
    };
    if path.is_null() {
        path = b"/\0" as *const u8 as *const libc::c_char;
    }
    if BIO_printf((*rctx).mem, http_hdr.as_ptr(), op, path) <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    (*rctx).state = 9 as libc::c_int | 0x1000 as libc::c_int;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_REQ_CTX_set1_req(
    mut rctx: *mut OCSP_REQ_CTX,
    mut req: *mut OCSP_REQUEST,
) -> libc::c_int {
    return OCSP_REQ_CTX_i2d(rctx, &OCSP_REQUEST_it, req as *mut ASN1_VALUE);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_REQ_CTX_add1_header(
    mut rctx: *mut OCSP_REQ_CTX,
    mut name: *const libc::c_char,
    mut value: *const libc::c_char,
) -> libc::c_int {
    if name.is_null() {
        return 0 as libc::c_int;
    }
    if BIO_puts((*rctx).mem, name) <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if !value.is_null() {
        if BIO_write(
            (*rctx).mem,
            b": \0" as *const u8 as *const libc::c_char as *const libc::c_void,
            2 as libc::c_int,
        ) != 2 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        if BIO_puts((*rctx).mem, value) <= 0 as libc::c_int {
            return 0 as libc::c_int;
        }
    }
    if BIO_write(
        (*rctx).mem,
        b"\r\n\0" as *const u8 as *const libc::c_char as *const libc::c_void,
        2 as libc::c_int,
    ) != 2 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    (*rctx).state = 9 as libc::c_int | 0x1000 as libc::c_int;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_REQ_CTX_i2d(
    mut rctx: *mut OCSP_REQ_CTX,
    mut it: *const ASN1_ITEM,
    mut val: *mut ASN1_VALUE,
) -> libc::c_int {
    static mut req_hdr: [libc::c_char; 63] = unsafe {
        *::core::mem::transmute::<
            &[u8; 63],
            &[libc::c_char; 63],
        >(b"Content-Type: application/ocsp-request\r\nContent-Length: %d\r\n\r\n\0")
    };
    let mut reqlen: libc::c_int = ASN1_item_i2d(val, 0 as *mut *mut libc::c_uchar, it);
    if BIO_printf((*rctx).mem, req_hdr.as_ptr(), reqlen) <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if ASN1_item_i2d_bio(it, (*rctx).mem, val as *mut libc::c_void) <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    (*rctx).state = 5 as libc::c_int | 0x1000 as libc::c_int;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_REQ_CTX_get0_mem_bio(
    mut rctx: *mut OCSP_REQ_CTX,
) -> *mut BIO {
    return (*rctx).mem;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_set_max_response_length(
    mut rctx: *mut OCSP_REQ_CTX,
    mut len: libc::c_ulong,
) {
    if len == 0 as libc::c_int as libc::c_ulong {
        (*rctx)
            .max_resp_len = (100 as libc::c_int * 1024 as libc::c_int) as libc::c_ulong;
    } else {
        (*rctx).max_resp_len = len;
    };
}
