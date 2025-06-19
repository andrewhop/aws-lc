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
    pub type ASN1_VALUE_st;
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
    fn ASN1_STRING_set(
        str: *mut ASN1_STRING,
        data: *const libc::c_void,
        len: ossl_ssize_t,
    ) -> libc::c_int;
    fn ASN1_UTCTIME_check(a: *const ASN1_UTCTIME) -> libc::c_int;
    fn ASN1_UTCTIME_adj(
        s: *mut ASN1_UTCTIME,
        posix_time: int64_t,
        offset_day: libc::c_int,
        offset_sec: libc::c_long,
    ) -> *mut ASN1_UTCTIME;
    fn ASN1_UTCTIME_set_string(
        s: *mut ASN1_UTCTIME,
        str: *const libc::c_char,
    ) -> libc::c_int;
    fn ASN1_GENERALIZEDTIME_new() -> *mut ASN1_GENERALIZEDTIME;
    fn ASN1_GENERALIZEDTIME_free(str: *mut ASN1_GENERALIZEDTIME);
    fn ASN1_GENERALIZEDTIME_check(a: *const ASN1_GENERALIZEDTIME) -> libc::c_int;
    fn ASN1_GENERALIZEDTIME_adj(
        s: *mut ASN1_GENERALIZEDTIME,
        posix_time: int64_t,
        offset_day: libc::c_int,
        offset_sec: libc::c_long,
    ) -> *mut ASN1_GENERALIZEDTIME;
    fn ASN1_GENERALIZEDTIME_set_string(
        s: *mut ASN1_GENERALIZEDTIME,
        str: *const libc::c_char,
    ) -> libc::c_int;
    fn OPENSSL_gmtime_adj(
        tm: *mut tm,
        offset_day: libc::c_int,
        offset_sec: int64_t,
    ) -> libc::c_int;
    fn OPENSSL_gmtime_diff(
        out_days: *mut libc::c_int,
        out_secs: *mut libc::c_int,
        from: *const tm,
        to: *const tm,
    ) -> libc::c_int;
    fn asn1_utctime_to_tm(
        tm: *mut tm,
        d: *const ASN1_UTCTIME,
        allow_timezone_offset: libc::c_int,
    ) -> libc::c_int;
    fn asn1_generalizedtime_to_tm(
        tm: *mut tm,
        d: *const ASN1_GENERALIZEDTIME,
    ) -> libc::c_int;
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_skip(cbs: *mut CBS, len: size_t) -> libc::c_int;
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_parse_generalized_time(
        cbs: *const CBS,
        out_tm: *mut tm,
        allow_timezone_offset: libc::c_int,
    ) -> libc::c_int;
    fn CBS_parse_utc_time(
        cbs: *const CBS,
        out_tm: *mut tm,
        allow_timezone_offset: libc::c_int,
    ) -> libc::c_int;
    fn time(__timer: *mut time_t) -> time_t;
    fn OPENSSL_strlcpy(
        dst: *mut libc::c_char,
        src: *const libc::c_char,
        dst_size: size_t,
    ) -> size_t;
    fn OPENSSL_strlcat(
        dst: *mut libc::c_char,
        src: *const libc::c_char,
        dst_size: size_t,
    ) -> size_t;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn OPENSSL_posix_to_tm(time_0: int64_t, out_tm: *mut tm) -> libc::c_int;
    fn OPENSSL_tm_to_posix(tm: *const tm, out: *mut int64_t) -> libc::c_int;
    fn OPENSSL_timegm(tm: *const tm, out: *mut time_t) -> libc::c_int;
}
pub type ptrdiff_t = libc::c_long;
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type int64_t = __int64_t;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type time_t = __time_t;
pub type ossl_ssize_t = ptrdiff_t;
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
pub struct asn1_string_st {
    pub length: libc::c_int,
    pub type_0: libc::c_int,
    pub data: *mut libc::c_uchar,
    pub flags: libc::c_long,
}
pub type ASN1_GENERALIZEDTIME = asn1_string_st;
pub type ASN1_STRING = asn1_string_st;
pub type ASN1_TIME = asn1_string_st;
pub type ASN1_UTCTIME = asn1_string_st;
pub type ASN1_VALUE = ASN1_VALUE_st;
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
pub static mut ASN1_TIME_it: ASN1_ITEM = {
    let mut init = ASN1_ITEM_st {
        itype: 0x5 as libc::c_int as libc::c_char,
        utype: 0x4000 as libc::c_int | 0x8000 as libc::c_int,
        templates: 0 as *const ASN1_TEMPLATE,
        tcount: 0 as libc::c_int as libc::c_long,
        funcs: 0 as *const libc::c_void,
        size: ::core::mem::size_of::<ASN1_STRING>() as libc::c_ulong as libc::c_long,
        sname: b"ASN1_TIME\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ASN1_TIME(
    mut a: *const ASN1_TIME,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &ASN1_TIME_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_TIME_free(mut a: *mut ASN1_TIME) {
    ASN1_item_free(a as *mut ASN1_VALUE, &ASN1_TIME_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_TIME_new() -> *mut ASN1_TIME {
    return ASN1_item_new(&ASN1_TIME_it) as *mut ASN1_TIME;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ASN1_TIME(
    mut a: *mut *mut ASN1_TIME,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_TIME {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &ASN1_TIME_it)
        as *mut ASN1_TIME;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_TIME_set_posix(
    mut s: *mut ASN1_TIME,
    mut posix_time: int64_t,
) -> *mut ASN1_TIME {
    return ASN1_TIME_adj(
        s,
        posix_time,
        0 as libc::c_int,
        0 as libc::c_int as libc::c_long,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_TIME_set(
    mut s: *mut ASN1_TIME,
    mut time_0: time_t,
) -> *mut ASN1_TIME {
    return ASN1_TIME_adj(s, time_0, 0 as libc::c_int, 0 as libc::c_int as libc::c_long);
}
unsafe extern "C" fn fits_in_utc_time(mut tm: *const tm) -> libc::c_int {
    return (50 as libc::c_int <= (*tm).tm_year && (*tm).tm_year < 150 as libc::c_int)
        as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_TIME_adj(
    mut s: *mut ASN1_TIME,
    mut posix_time: int64_t,
    mut offset_day: libc::c_int,
    mut offset_sec: libc::c_long,
) -> *mut ASN1_TIME {
    let mut tm: tm = tm {
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
    if OPENSSL_posix_to_tm(posix_time, &mut tm) == 0 {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            113 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_time.c\0" as *const u8
                as *const libc::c_char,
            94 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut ASN1_TIME;
    }
    if offset_day != 0 || offset_sec != 0 {
        if OPENSSL_gmtime_adj(&mut tm, offset_day, offset_sec) == 0 {
            return 0 as *mut ASN1_TIME;
        }
    }
    if fits_in_utc_time(&mut tm) != 0 {
        return ASN1_UTCTIME_adj(s, posix_time, offset_day, offset_sec);
    }
    return ASN1_GENERALIZEDTIME_adj(s, posix_time, offset_day, offset_sec);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_TIME_check(mut t: *const ASN1_TIME) -> libc::c_int {
    if (*t).type_0 == 24 as libc::c_int {
        return ASN1_GENERALIZEDTIME_check(t)
    } else if (*t).type_0 == 23 as libc::c_int {
        return ASN1_UTCTIME_check(t)
    }
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_TIME_to_generalizedtime(
    mut t: *const ASN1_TIME,
    mut out: *mut *mut ASN1_GENERALIZEDTIME,
) -> *mut ASN1_GENERALIZEDTIME {
    let mut current_block: u64;
    let mut ret: *mut ASN1_GENERALIZEDTIME = 0 as *mut ASN1_GENERALIZEDTIME;
    let mut str: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut newlen: libc::c_int = 0;
    if ASN1_TIME_check(t) == 0 {
        return 0 as *mut ASN1_GENERALIZEDTIME;
    }
    if out.is_null() || (*out).is_null() {
        ret = ASN1_GENERALIZEDTIME_new();
        if ret.is_null() {
            current_block = 10534392581054068921;
        } else {
            current_block = 7351195479953500246;
        }
    } else {
        ret = *out;
        current_block = 7351195479953500246;
    }
    match current_block {
        7351195479953500246 => {
            if (*t).type_0 == 24 as libc::c_int {
                if ASN1_STRING_set(
                    ret,
                    (*t).data as *const libc::c_void,
                    (*t).length as ossl_ssize_t,
                ) == 0
                {
                    current_block = 10534392581054068921;
                } else {
                    current_block = 1775319122502597328;
                }
            } else if ASN1_STRING_set(
                ret,
                0 as *const libc::c_void,
                ((*t).length + 2 as libc::c_int) as ossl_ssize_t,
            ) == 0
            {
                current_block = 10534392581054068921;
            } else {
                newlen = (*t).length + 2 as libc::c_int + 1 as libc::c_int;
                str = (*ret).data as *mut libc::c_char;
                if *((*t).data).offset(0 as libc::c_int as isize) as libc::c_int
                    >= '5' as i32
                {
                    OPENSSL_strlcpy(
                        str,
                        b"19\0" as *const u8 as *const libc::c_char,
                        newlen as size_t,
                    );
                } else {
                    OPENSSL_strlcpy(
                        str,
                        b"20\0" as *const u8 as *const libc::c_char,
                        newlen as size_t,
                    );
                }
                OPENSSL_strlcat(str, (*t).data as *mut libc::c_char, newlen as size_t);
                current_block = 1775319122502597328;
            }
            match current_block {
                10534392581054068921 => {}
                _ => {
                    if !out.is_null() && (*out).is_null() {
                        *out = ret;
                    }
                    return ret;
                }
            }
        }
        _ => {}
    }
    if out.is_null() || *out != ret {
        ASN1_GENERALIZEDTIME_free(ret);
    }
    return 0 as *mut ASN1_GENERALIZEDTIME;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_TIME_set_string(
    mut s: *mut ASN1_TIME,
    mut str: *const libc::c_char,
) -> libc::c_int {
    return (ASN1_UTCTIME_set_string(s, str) != 0
        || ASN1_GENERALIZEDTIME_set_string(s, str) != 0) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_TIME_set_string_X509(
    mut s: *mut ASN1_TIME,
    mut str: *const libc::c_char,
) -> libc::c_int {
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, str as *const uint8_t, strlen(str));
    let mut type_0: libc::c_int = 0;
    let mut tm: tm = tm {
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
    if CBS_parse_utc_time(&mut cbs, 0 as *mut tm, 0 as libc::c_int) != 0 {
        type_0 = 23 as libc::c_int;
    } else if CBS_parse_generalized_time(&mut cbs, &mut tm, 0 as libc::c_int) != 0 {
        type_0 = 24 as libc::c_int;
        if fits_in_utc_time(&mut tm) != 0 {
            type_0 = 23 as libc::c_int;
            CBS_skip(&mut cbs, 2 as libc::c_int as size_t);
        }
    } else {
        return 0 as libc::c_int
    }
    if !s.is_null() {
        if ASN1_STRING_set(
            s,
            CBS_data(&mut cbs) as *const libc::c_void,
            CBS_len(&mut cbs) as ossl_ssize_t,
        ) == 0
        {
            return 0 as libc::c_int;
        }
        (*s).type_0 = type_0;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn asn1_time_to_tm(
    mut tm: *mut tm,
    mut t: *const ASN1_TIME,
    mut allow_timezone_offset: libc::c_int,
) -> libc::c_int {
    if t.is_null() {
        if OPENSSL_posix_to_tm(time(0 as *mut time_t), tm) != 0 {
            return 1 as libc::c_int;
        }
        return 0 as libc::c_int;
    }
    if (*t).type_0 == 23 as libc::c_int {
        return asn1_utctime_to_tm(tm, t, allow_timezone_offset)
    } else if (*t).type_0 == 24 as libc::c_int {
        return asn1_generalizedtime_to_tm(tm, t)
    }
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_TIME_diff(
    mut out_days: *mut libc::c_int,
    mut out_seconds: *mut libc::c_int,
    mut from: *const ASN1_TIME,
    mut to: *const ASN1_TIME,
) -> libc::c_int {
    let mut tm_from: tm = tm {
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
    let mut tm_to: tm = tm {
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
    if asn1_time_to_tm(&mut tm_from, from, 1 as libc::c_int) == 0 {
        return 0 as libc::c_int;
    }
    if asn1_time_to_tm(&mut tm_to, to, 1 as libc::c_int) == 0 {
        return 0 as libc::c_int;
    }
    return OPENSSL_gmtime_diff(out_days, out_seconds, &mut tm_from, &mut tm_to);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_TIME_to_tm(
    mut s: *const ASN1_TIME,
    mut tm: *mut tm,
) -> libc::c_int {
    return asn1_time_to_tm(tm, s, 0 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_TIME_to_time_t(
    mut t: *const ASN1_TIME,
    mut out_time: *mut time_t,
) -> libc::c_int {
    let mut tm: tm = tm {
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
    if asn1_time_to_tm(&mut tm, t, 0 as libc::c_int) == 0 {
        return 0 as libc::c_int;
    }
    return OPENSSL_timegm(&mut tm, out_time);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_TIME_to_posix(
    mut t: *const ASN1_TIME,
    mut out_time: *mut int64_t,
) -> libc::c_int {
    let mut tm: tm = tm {
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
    if asn1_time_to_tm(&mut tm, t, 0 as libc::c_int) == 0 {
        return 0 as libc::c_int;
    }
    return OPENSSL_tm_to_posix(&mut tm, out_time);
}
