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
    fn abort() -> !;
    fn ASN1_STRING_set(
        str: *mut ASN1_STRING,
        data: *const libc::c_void,
        len: ossl_ssize_t,
    ) -> libc::c_int;
    fn ASN1_UTCTIME_new() -> *mut ASN1_UTCTIME;
    fn ASN1_UTCTIME_free(str: *mut ASN1_UTCTIME);
    fn OPENSSL_gmtime_adj(
        tm: *mut tm,
        offset_day: libc::c_int,
        offset_sec: int64_t,
    ) -> libc::c_int;
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_parse_generalized_time(
        cbs: *const CBS,
        out_tm: *mut tm,
        allow_timezone_offset: libc::c_int,
    ) -> libc::c_int;
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn OPENSSL_posix_to_tm(time: int64_t, out_tm: *mut tm) -> libc::c_int;
}
pub type ptrdiff_t = libc::c_long;
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __int64_t = libc::c_long;
pub type int64_t = __int64_t;
pub type uint8_t = __uint8_t;
pub type ossl_ssize_t = ptrdiff_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_string_st {
    pub length: libc::c_int,
    pub type_0: libc::c_int,
    pub data: *mut libc::c_uchar,
    pub flags: libc::c_long,
}
pub type ASN1_GENERALIZEDTIME = asn1_string_st;
pub type ASN1_STRING = asn1_string_st;
pub type ASN1_UTCTIME = asn1_string_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cbs_st {
    pub data: *const uint8_t,
    pub len: size_t,
}
pub type CBS = cbs_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct tm {
    pub tm_sec: libc::c_int,
    pub tm_min: libc::c_int,
    pub tm_hour: libc::c_int,
    pub tm_mday: libc::c_int,
    pub tm_mon: libc::c_int,
    pub tm_year: libc::c_int,
    pub tm_wday: libc::c_int,
    pub tm_yday: libc::c_int,
    pub tm_isdst: libc::c_int,
    pub __tm_gmtoff: libc::c_long,
    pub __tm_zone: *const libc::c_char,
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asn1_generalizedtime_to_tm(
    mut tm: *mut tm,
    mut d: *const ASN1_GENERALIZEDTIME,
) -> libc::c_int {
    if (*d).type_0 != 24 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, (*d).data, (*d).length as size_t);
    if CBS_parse_generalized_time(&mut cbs, tm, 0 as libc::c_int) == 0 {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_GENERALIZEDTIME_check(
    mut d: *const ASN1_GENERALIZEDTIME,
) -> libc::c_int {
    return asn1_generalizedtime_to_tm(0 as *mut tm, d);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_GENERALIZEDTIME_set_string(
    mut s: *mut ASN1_GENERALIZEDTIME,
    mut str: *const libc::c_char,
) -> libc::c_int {
    let mut len: size_t = strlen(str);
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, str as *const uint8_t, len);
    if CBS_parse_generalized_time(&mut cbs, 0 as *mut tm, 0 as libc::c_int) == 0 {
        return 0 as libc::c_int;
    }
    if !s.is_null() {
        if ASN1_STRING_set(s, str as *const libc::c_void, len as ossl_ssize_t) == 0 {
            return 0 as libc::c_int;
        }
        (*s).type_0 = 24 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_GENERALIZEDTIME_set(
    mut s: *mut ASN1_GENERALIZEDTIME,
    mut posix_time: int64_t,
) -> *mut ASN1_GENERALIZEDTIME {
    return ASN1_GENERALIZEDTIME_adj(
        s,
        posix_time,
        0 as libc::c_int,
        0 as libc::c_int as libc::c_long,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_GENERALIZEDTIME_adj(
    mut s: *mut ASN1_GENERALIZEDTIME,
    mut posix_time: int64_t,
    mut offset_day: libc::c_int,
    mut offset_sec: libc::c_long,
) -> *mut ASN1_GENERALIZEDTIME {
    let mut data: tm = tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 0,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        __tm_gmtoff: 0,
        __tm_zone: 0 as *const libc::c_char,
    };
    if OPENSSL_posix_to_tm(posix_time, &mut data) == 0 {
        return 0 as *mut ASN1_GENERALIZEDTIME;
    }
    if offset_day != 0 || offset_sec != 0 {
        if OPENSSL_gmtime_adj(&mut data, offset_day, offset_sec) == 0 {
            return 0 as *mut ASN1_GENERALIZEDTIME;
        }
    }
    if data.tm_year < 0 as libc::c_int - 1900 as libc::c_int
        || data.tm_year > 9999 as libc::c_int - 1900 as libc::c_int
    {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            138 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_gentm.c\0" as *const u8
                as *const libc::c_char,
            121 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut ASN1_GENERALIZEDTIME;
    }
    let mut buf: [libc::c_char; 16] = [0; 16];
    let mut ret: libc::c_int = snprintf(
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 16]>() as libc::c_ulong,
        b"%04d%02d%02d%02d%02d%02dZ\0" as *const u8 as *const libc::c_char,
        data.tm_year + 1900 as libc::c_int,
        data.tm_mon + 1 as libc::c_int,
        data.tm_mday,
        data.tm_hour,
        data.tm_min,
        data.tm_sec,
    );
    if ret
        != (::core::mem::size_of::<[libc::c_char; 16]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong) as libc::c_int
    {
        abort();
    }
    let mut free_s: libc::c_int = 0 as libc::c_int;
    if s.is_null() {
        free_s = 1 as libc::c_int;
        s = ASN1_UTCTIME_new();
        if s.is_null() {
            return 0 as *mut ASN1_GENERALIZEDTIME;
        }
    }
    if ASN1_STRING_set(
        s,
        buf.as_mut_ptr() as *const libc::c_void,
        strlen(buf.as_mut_ptr()) as ossl_ssize_t,
    ) == 0
    {
        if free_s != 0 {
            ASN1_UTCTIME_free(s);
        }
        return 0 as *mut ASN1_GENERALIZEDTIME;
    }
    (*s).type_0 = 24 as libc::c_int;
    return s;
}
