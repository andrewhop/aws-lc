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
    pub type x509_st;
    pub type engine_st;
    pub type env_md_st;
    fn ASN1_STRING_copy(dst: *mut ASN1_STRING, str: *const ASN1_STRING) -> libc::c_int;
    fn ASN1_OCTET_STRING_cmp(
        a: *const ASN1_OCTET_STRING,
        b: *const ASN1_OCTET_STRING,
    ) -> libc::c_int;
    fn ASN1_OCTET_STRING_set(
        str: *mut ASN1_OCTET_STRING,
        data: *const libc::c_uchar,
        len: libc::c_int,
    ) -> libc::c_int;
    fn ASN1_INTEGER_cmp(x: *const ASN1_INTEGER, y: *const ASN1_INTEGER) -> libc::c_int;
    fn ASN1_OBJECT_free(a: *mut ASN1_OBJECT);
    fn ASN1_TYPE_new() -> *mut ASN1_TYPE;
    fn X509_get0_serialNumber(x509: *const X509) -> *const ASN1_INTEGER;
    fn X509_get_issuer_name(x509: *const X509) -> *mut X509_NAME;
    fn X509_get_subject_name(x509: *const X509) -> *mut X509_NAME;
    fn X509_get0_pubkey_bitstr(x509: *const X509) -> *mut ASN1_BIT_STRING;
    fn X509_NAME_digest(
        name: *const X509_NAME,
        md: *const EVP_MD,
        out: *mut uint8_t,
        out_len: *mut libc::c_uint,
    ) -> libc::c_int;
    fn EVP_sha1() -> *const EVP_MD;
    fn EVP_Digest(
        data: *const libc::c_void,
        len: size_t,
        md_out: *mut uint8_t,
        out_size: *mut libc::c_uint,
        type_0: *const EVP_MD,
        impl_0: *mut ENGINE,
    ) -> libc::c_int;
    fn EVP_MD_type(md: *const EVP_MD) -> libc::c_int;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_strdup(s: *const libc::c_char) -> *mut libc::c_char;
    fn strncmp(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OBJ_cmp(a: *const ASN1_OBJECT, b: *const ASN1_OBJECT) -> libc::c_int;
    fn OBJ_nid2obj(nid: libc::c_int) -> *mut ASN1_OBJECT;
    fn OCSP_CERTID_free(a: *mut OCSP_CERTID);
    fn OCSP_CERTID_new() -> *mut OCSP_CERTID;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type uint8_t = __uint8_t;
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
pub type X509_ALGOR = X509_algor_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_algor_st {
    pub algorithm: *mut ASN1_OBJECT,
    pub parameter: *mut ASN1_TYPE,
}
pub type X509 = x509_st;
pub type ENGINE = engine_st;
pub type EVP_MD = env_md_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ocsp_cert_id_st {
    pub hashAlgorithm: *mut X509_ALGOR,
    pub issuerNameHash: *mut ASN1_OCTET_STRING,
    pub issuerKeyHash: *mut ASN1_OCTET_STRING,
    pub serialNumber: *mut ASN1_INTEGER,
}
pub type OCSP_CERTID = ocsp_cert_id_st;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_cert_to_id(
    mut dgst: *const EVP_MD,
    mut subject: *const X509,
    mut issuer: *const X509,
) -> *mut OCSP_CERTID {
    if issuer.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_lib.c\0" as *const u8
                as *const libc::c_char,
            12 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut OCSP_CERTID;
    }
    let mut iname: *const X509_NAME = 0 as *const X509_NAME;
    let mut serial: *const ASN1_INTEGER = 0 as *const ASN1_INTEGER;
    let mut ikey: *mut ASN1_BIT_STRING = 0 as *mut ASN1_BIT_STRING;
    if dgst.is_null() {
        dgst = EVP_sha1();
    }
    if !subject.is_null() {
        iname = X509_get_issuer_name(subject);
        serial = X509_get0_serialNumber(subject);
    } else {
        iname = X509_get_subject_name(issuer);
        serial = 0 as *const ASN1_INTEGER;
    }
    ikey = X509_get0_pubkey_bitstr(issuer);
    return OCSP_cert_id_new(dgst, iname, ikey, serial);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_cert_id_new(
    mut dgst: *const EVP_MD,
    mut issuerName: *const X509_NAME,
    mut issuerKey: *const ASN1_BIT_STRING,
    mut serialNumber: *const ASN1_INTEGER,
) -> *mut OCSP_CERTID {
    let mut current_block: u64;
    if dgst.is_null() || issuerName.is_null() || issuerKey.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_lib.c\0" as *const u8
                as *const libc::c_char,
            38 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut OCSP_CERTID;
    }
    let mut nid: libc::c_int = 0;
    let mut i: libc::c_uint = 0;
    let mut alg: *mut X509_ALGOR = 0 as *mut X509_ALGOR;
    let mut md: [libc::c_uchar; 64] = [0; 64];
    let mut cid: *mut OCSP_CERTID = OCSP_CERTID_new();
    if cid.is_null() {
        return 0 as *mut OCSP_CERTID;
    }
    alg = (*cid).hashAlgorithm;
    ASN1_OBJECT_free((*alg).algorithm);
    nid = EVP_MD_type(dgst);
    if nid == 0 as libc::c_int {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            120 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_lib.c\0" as *const u8
                as *const libc::c_char,
            55 as libc::c_int as libc::c_uint,
        );
    } else {
        (*alg).algorithm = OBJ_nid2obj(nid);
        if !((*alg).algorithm).is_null() {
            (*alg).parameter = ASN1_TYPE_new();
            if !((*alg).parameter).is_null() {
                (*(*alg).parameter).type_0 = 5 as libc::c_int;
                if X509_NAME_digest(issuerName, dgst, md.as_mut_ptr(), &mut i) == 0 {
                    ERR_put_error(
                        23 as libc::c_int,
                        0 as libc::c_int,
                        102 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_lib.c\0"
                            as *const u8 as *const libc::c_char,
                        69 as libc::c_int as libc::c_uint,
                    );
                } else if !(ASN1_OCTET_STRING_set(
                    (*cid).issuerNameHash,
                    md.as_mut_ptr(),
                    i as libc::c_int,
                ) == 0)
                {
                    if !(EVP_Digest(
                        (*issuerKey).data as *const libc::c_void,
                        (*issuerKey).length as size_t,
                        md.as_mut_ptr(),
                        &mut i,
                        dgst,
                        0 as *mut ENGINE,
                    ) == 0)
                    {
                        if !(ASN1_OCTET_STRING_set(
                            (*cid).issuerKeyHash,
                            md.as_mut_ptr(),
                            i as libc::c_int,
                        ) == 0)
                        {
                            if !serialNumber.is_null() {
                                if ASN1_STRING_copy((*cid).serialNumber, serialNumber)
                                    == 0 as libc::c_int
                                {
                                    current_block = 16910077423827944748;
                                } else {
                                    current_block = 10652014663920648156;
                                }
                            } else {
                                current_block = 10652014663920648156;
                            }
                            match current_block {
                                16910077423827944748 => {}
                                _ => return cid,
                            }
                        }
                    }
                }
            }
        }
    }
    OCSP_CERTID_free(cid);
    return 0 as *mut OCSP_CERTID;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_id_issuer_cmp(
    mut a: *const OCSP_CERTID,
    mut b: *const OCSP_CERTID,
) -> libc::c_int {
    if a.is_null() || b.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_lib.c\0" as *const u8
                as *const libc::c_char,
            97 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    if ((*a).hashAlgorithm).is_null() || ((*b).hashAlgorithm).is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_lib.c\0" as *const u8
                as *const libc::c_char,
            102 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    let mut ret: libc::c_int = OBJ_cmp(
        (*(*a).hashAlgorithm).algorithm,
        (*(*b).hashAlgorithm).algorithm,
    );
    if ret != 0 as libc::c_int {
        return ret;
    }
    ret = ASN1_OCTET_STRING_cmp((*a).issuerNameHash, (*b).issuerNameHash);
    if ret != 0 as libc::c_int {
        return ret;
    }
    ret = ASN1_OCTET_STRING_cmp((*a).issuerKeyHash, (*b).issuerKeyHash);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_id_cmp(
    mut a: *const OCSP_CERTID,
    mut b: *const OCSP_CERTID,
) -> libc::c_int {
    if a.is_null() || b.is_null() {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_lib.c\0" as *const u8
                as *const libc::c_char,
            120 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    let mut ret: libc::c_int = OCSP_id_issuer_cmp(a, b);
    if ret != 0 as libc::c_int {
        return ret;
    }
    ret = ASN1_INTEGER_cmp((*a).serialNumber, (*b).serialNumber);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OCSP_parse_url(
    mut url: *const libc::c_char,
    mut phost: *mut *mut libc::c_char,
    mut pport: *mut *mut libc::c_char,
    mut ppath: *mut *mut libc::c_char,
    mut pssl: *mut libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    if url.is_null() || phost.is_null() || pport.is_null() || ppath.is_null()
        || pssl.is_null()
    {
        ERR_put_error(
            23 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_lib.c\0" as *const u8
                as *const libc::c_char,
            138 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut parser: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut buffer: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut port: *mut libc::c_char = 0 as *mut libc::c_char;
    *phost = 0 as *mut libc::c_char;
    *pport = 0 as *mut libc::c_char;
    *ppath = 0 as *mut libc::c_char;
    buffer = OPENSSL_strdup(url);
    if buffer.is_null() {
        current_block = 15096761616001553858;
    } else {
        parser = strchr(buffer, ':' as i32);
        if parser.is_null() {
            current_block = 4973529699897590931;
        } else {
            let fresh0 = parser;
            parser = parser.offset(1);
            *fresh0 = '\0' as i32 as libc::c_char;
            if strncmp(
                buffer,
                b"https\0" as *const u8 as *const libc::c_char,
                5 as libc::c_int as libc::c_ulong,
            ) == 0 as libc::c_int
            {
                *pssl = 1 as libc::c_int;
                port = b"443\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
                current_block = 7149356873433890176;
            } else if strncmp(
                buffer,
                b"http\0" as *const u8 as *const libc::c_char,
                4 as libc::c_int as libc::c_ulong,
            ) == 0 as libc::c_int
            {
                *pssl = 0 as libc::c_int;
                port = b"80\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
                current_block = 7149356873433890176;
            } else {
                current_block = 4973529699897590931;
            }
            match current_block {
                4973529699897590931 => {}
                _ => {
                    if *parser.offset(0 as libc::c_int as isize) as libc::c_int
                        != '/' as i32
                        || *parser.offset(1 as libc::c_int as isize) as libc::c_int
                            != '/' as i32
                    {
                        current_block = 4973529699897590931;
                    } else {
                        parser = parser.offset(2 as libc::c_int as isize);
                        host = parser;
                        parser = strchr(parser, '/' as i32);
                        if parser.is_null() {
                            *ppath = OPENSSL_strdup(
                                b"/\0" as *const u8 as *const libc::c_char,
                            );
                        } else {
                            *ppath = OPENSSL_strdup(parser);
                            *parser = '\0' as i32 as libc::c_char;
                        }
                        if (*ppath).is_null() {
                            current_block = 15096761616001553858;
                        } else {
                            parser = host;
                            if *host.offset(0 as libc::c_int as isize) as libc::c_int
                                == '[' as i32
                            {
                                host = host.offset(1);
                                host;
                                parser = strchr(host, ']' as i32);
                                if parser.is_null() {
                                    current_block = 4973529699897590931;
                                } else {
                                    *parser = '\0' as i32 as libc::c_char;
                                    parser = parser.offset(1);
                                    parser;
                                    current_block = 15897653523371991391;
                                }
                            } else {
                                current_block = 15897653523371991391;
                            }
                            match current_block {
                                4973529699897590931 => {}
                                _ => {
                                    parser = strchr(parser, ':' as i32);
                                    if !parser.is_null() {
                                        *parser = 0 as libc::c_int as libc::c_char;
                                        port = parser.offset(1 as libc::c_int as isize);
                                    }
                                    *pport = OPENSSL_strdup(port);
                                    if (*pport).is_null() {
                                        current_block = 15096761616001553858;
                                    } else {
                                        *phost = OPENSSL_strdup(host);
                                        if (*phost).is_null() {
                                            current_block = 15096761616001553858;
                                        } else {
                                            OPENSSL_free(buffer as *mut libc::c_void);
                                            return 1 as libc::c_int;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        match current_block {
            15096761616001553858 => {}
            _ => {
                ERR_put_error(
                    23 as libc::c_int,
                    0 as libc::c_int,
                    121 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_lib.c\0"
                        as *const u8 as *const libc::c_char,
                    230 as libc::c_int as libc::c_uint,
                );
                current_block = 13074319627240401265;
            }
        }
    }
    match current_block {
        15096761616001553858 => {
            ERR_put_error(
                23 as libc::c_int,
                0 as libc::c_int,
                1 as libc::c_int | 64 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/ocsp/ocsp_lib.c\0"
                    as *const u8 as *const libc::c_char,
                227 as libc::c_int as libc::c_uint,
            );
        }
        _ => {}
    }
    OPENSSL_free(buffer as *mut libc::c_void);
    OPENSSL_free(*ppath as *mut libc::c_void);
    *ppath = 0 as *mut libc::c_char;
    OPENSSL_free(*pport as *mut libc::c_void);
    *pport = 0 as *mut libc::c_char;
    OPENSSL_free(*phost as *mut libc::c_void);
    *phost = 0 as *mut libc::c_char;
    return 0 as libc::c_int;
}
