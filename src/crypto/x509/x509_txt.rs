#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#[no_mangle]
pub unsafe extern "C" fn X509_verify_cert_error_string(
    mut err: libc::c_long,
) -> *const libc::c_char {
    match err {
        0 => return b"ok\0" as *const u8 as *const libc::c_char,
        2 => {
            return b"unable to get issuer certificate\0" as *const u8
                as *const libc::c_char;
        }
        3 => {
            return b"unable to get certificate CRL\0" as *const u8 as *const libc::c_char;
        }
        4 => {
            return b"unable to decrypt certificate's signature\0" as *const u8
                as *const libc::c_char;
        }
        5 => {
            return b"unable to decrypt CRL's signature\0" as *const u8
                as *const libc::c_char;
        }
        6 => {
            return b"unable to decode issuer public key\0" as *const u8
                as *const libc::c_char;
        }
        7 => {
            return b"certificate signature failure\0" as *const u8 as *const libc::c_char;
        }
        8 => return b"CRL signature failure\0" as *const u8 as *const libc::c_char,
        9 => return b"certificate is not yet valid\0" as *const u8 as *const libc::c_char,
        11 => return b"CRL is not yet valid\0" as *const u8 as *const libc::c_char,
        10 => return b"certificate has expired\0" as *const u8 as *const libc::c_char,
        12 => return b"CRL has expired\0" as *const u8 as *const libc::c_char,
        13 => {
            return b"format error in certificate's notBefore field\0" as *const u8
                as *const libc::c_char;
        }
        14 => {
            return b"format error in certificate's notAfter field\0" as *const u8
                as *const libc::c_char;
        }
        15 => {
            return b"format error in CRL's lastUpdate field\0" as *const u8
                as *const libc::c_char;
        }
        16 => {
            return b"format error in CRL's nextUpdate field\0" as *const u8
                as *const libc::c_char;
        }
        17 => return b"out of memory\0" as *const u8 as *const libc::c_char,
        18 => return b"self signed certificate\0" as *const u8 as *const libc::c_char,
        19 => {
            return b"self signed certificate in certificate chain\0" as *const u8
                as *const libc::c_char;
        }
        20 => {
            return b"unable to get local issuer certificate\0" as *const u8
                as *const libc::c_char;
        }
        21 => {
            return b"unable to verify the first certificate\0" as *const u8
                as *const libc::c_char;
        }
        22 => return b"certificate chain too long\0" as *const u8 as *const libc::c_char,
        23 => return b"certificate revoked\0" as *const u8 as *const libc::c_char,
        24 => return b"invalid CA certificate\0" as *const u8 as *const libc::c_char,
        37 => {
            return b"invalid non-CA certificate (has CA markings)\0" as *const u8
                as *const libc::c_char;
        }
        25 => {
            return b"path length constraint exceeded\0" as *const u8
                as *const libc::c_char;
        }
        38 => {
            return b"proxy path length constraint exceeded\0" as *const u8
                as *const libc::c_char;
        }
        40 => {
            return b"proxy certificates not allowed, please set the appropriate flag\0"
                as *const u8 as *const libc::c_char;
        }
        26 => {
            return b"unsupported certificate purpose\0" as *const u8
                as *const libc::c_char;
        }
        27 => return b"certificate not trusted\0" as *const u8 as *const libc::c_char,
        28 => return b"certificate rejected\0" as *const u8 as *const libc::c_char,
        50 => {
            return b"application verification failure\0" as *const u8
                as *const libc::c_char;
        }
        29 => return b"subject issuer mismatch\0" as *const u8 as *const libc::c_char,
        30 => {
            return b"authority and subject key identifier mismatch\0" as *const u8
                as *const libc::c_char;
        }
        31 => {
            return b"authority and issuer serial number mismatch\0" as *const u8
                as *const libc::c_char;
        }
        32 => {
            return b"key usage does not include certificate signing\0" as *const u8
                as *const libc::c_char;
        }
        33 => {
            return b"unable to get CRL issuer certificate\0" as *const u8
                as *const libc::c_char;
        }
        34 => {
            return b"unhandled critical extension\0" as *const u8 as *const libc::c_char;
        }
        35 => {
            return b"key usage does not include CRL signing\0" as *const u8
                as *const libc::c_char;
        }
        39 => {
            return b"key usage does not include digital signature\0" as *const u8
                as *const libc::c_char;
        }
        36 => {
            return b"unhandled critical CRL extension\0" as *const u8
                as *const libc::c_char;
        }
        41 => {
            return b"invalid or inconsistent certificate extension\0" as *const u8
                as *const libc::c_char;
        }
        42 => {
            return b"invalid or inconsistent certificate policy extension\0" as *const u8
                as *const libc::c_char;
        }
        43 => return b"no explicit policy\0" as *const u8 as *const libc::c_char,
        44 => return b"Different CRL scope\0" as *const u8 as *const libc::c_char,
        45 => {
            return b"Unsupported extension feature\0" as *const u8 as *const libc::c_char;
        }
        46 => {
            return b"RFC 3779 resource not subset of parent's resources\0" as *const u8
                as *const libc::c_char;
        }
        47 => return b"permitted subtree violation\0" as *const u8 as *const libc::c_char,
        48 => return b"excluded subtree violation\0" as *const u8 as *const libc::c_char,
        49 => {
            return b"name constraints minimum and maximum not supported\0" as *const u8
                as *const libc::c_char;
        }
        51 => {
            return b"unsupported name constraint type\0" as *const u8
                as *const libc::c_char;
        }
        52 => {
            return b"unsupported or invalid name constraint syntax\0" as *const u8
                as *const libc::c_char;
        }
        53 => {
            return b"unsupported or invalid name syntax\0" as *const u8
                as *const libc::c_char;
        }
        54 => return b"CRL path validation error\0" as *const u8 as *const libc::c_char,
        62 => return b"Hostname mismatch\0" as *const u8 as *const libc::c_char,
        63 => return b"Email address mismatch\0" as *const u8 as *const libc::c_char,
        64 => return b"IP address mismatch\0" as *const u8 as *const libc::c_char,
        65 => {
            return b"Invalid certificate verification context\0" as *const u8
                as *const libc::c_char;
        }
        66 => {
            return b"Issuer certificate lookup error\0" as *const u8
                as *const libc::c_char;
        }
        67 => {
            return b"Issuer has name constraints but leaf has no SANs\0" as *const u8
                as *const libc::c_char;
        }
        _ => {
            return b"unknown certificate verification error\0" as *const u8
                as *const libc::c_char;
        }
    };
}
