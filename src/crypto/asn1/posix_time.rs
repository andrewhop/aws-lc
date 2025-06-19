#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(label_break_value)]
extern "C" {
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
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
pub type __int32_t = libc::c_int;
pub type __int64_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type int32_t = __int32_t;
pub type int64_t = __int64_t;
pub type size_t = libc::c_ulong;
pub type time_t = __time_t;
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
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_176_error_is_time_t_is_broken {
    #[bitfield(
        name = "static_assertion_at_line_176_error_is_time_t_is_broken",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_176_error_is_time_t_is_broken: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_192_error_is_time_t_is_broken {
    #[bitfield(
        name = "static_assertion_at_line_192_error_is_time_t_is_broken",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_192_error_is_time_t_is_broken: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_210_error_is_addition_cannot_underflow {
    #[bitfield(
        name = "static_assertion_at_line_210_error_is_addition_cannot_underflow",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_210_error_is_addition_cannot_underflow: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_208_error_is_addition_cannot_overflow {
    #[bitfield(
        name = "static_assertion_at_line_208_error_is_addition_cannot_overflow",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_208_error_is_addition_cannot_overflow: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_206_error_is_day_offset_in_seconds_cannot_overflow {
    #[bitfield(
        name = "static_assertion_at_line_206_error_is_day_offset_in_seconds_cannot_overflow",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_206_error_is_day_offset_in_seconds_cannot_overflow: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_237_error_is_range_of_valid_POSIX_times_in_days_does_not_fit_in_int {
    #[bitfield(
        name = "static_assertion_at_line_237_error_is_range_of_valid_POSIX_times_in_days_does_not_fit_in_int",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_237_error_is_range_of_valid_POSIX_times_in_days_does_not_fit_in_int: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_235_error_is_seconds_per_day_does_not_fit_in_int {
    #[bitfield(
        name = "static_assertion_at_line_235_error_is_seconds_per_day_does_not_fit_in_int",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_235_error_is_seconds_per_day_does_not_fit_in_int: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[inline]
unsafe extern "C" fn OPENSSL_memset(
    mut dst: *mut libc::c_void,
    mut c: libc::c_int,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return dst;
    }
    return memset(dst, c, n);
}
unsafe extern "C" fn is_valid_date(
    mut year: int64_t,
    mut month: int64_t,
    mut day: int64_t,
) -> libc::c_int {
    if day < 1 as libc::c_int as int64_t || month < 1 as libc::c_int as int64_t
        || year < 0 as libc::c_int as int64_t || year > 9999 as libc::c_int as int64_t
    {
        return 0 as libc::c_int;
    }
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => {
            return (day > 0 as libc::c_int as int64_t
                && day <= 31 as libc::c_int as int64_t) as libc::c_int;
        }
        4 | 6 | 9 | 11 => {
            return (day > 0 as libc::c_int as int64_t
                && day <= 30 as libc::c_int as int64_t) as libc::c_int;
        }
        2 => {
            if year % 4 as libc::c_int as int64_t == 0 as libc::c_int as int64_t
                && year % 100 as libc::c_int as int64_t != 0 as libc::c_int as int64_t
                || year % 400 as libc::c_int as int64_t == 0 as libc::c_int as int64_t
            {
                return (day > 0 as libc::c_int as int64_t
                    && day <= 29 as libc::c_int as int64_t) as libc::c_int
            } else {
                return (day > 0 as libc::c_int as int64_t
                    && day <= 28 as libc::c_int as int64_t) as libc::c_int
            }
        }
        _ => return 0 as libc::c_int,
    };
}
unsafe extern "C" fn is_valid_time(
    mut hours: int64_t,
    mut minutes: int64_t,
    mut seconds: int64_t,
) -> libc::c_int {
    if hours < 0 as libc::c_int as int64_t || minutes < 0 as libc::c_int as int64_t
        || seconds < 0 as libc::c_int as int64_t || hours > 23 as libc::c_int as int64_t
        || minutes > 59 as libc::c_int as int64_t
        || seconds > 59 as libc::c_int as int64_t
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn is_valid_posix_time(mut time: int64_t) -> libc::c_int {
    return (-(62167219200 as libc::c_long) <= time
        && time <= 253402300799 as libc::c_long) as libc::c_int;
}
unsafe extern "C" fn posix_time_from_utc(
    mut year: int64_t,
    mut month: int64_t,
    mut day: int64_t,
    mut hours: int64_t,
    mut minutes: int64_t,
    mut seconds: int64_t,
    mut out_time: *mut int64_t,
) -> libc::c_int {
    if is_valid_date(year, month, day) == 0
        || is_valid_time(hours, minutes, seconds) == 0
    {
        return 0 as libc::c_int;
    }
    if month <= 2 as libc::c_int as int64_t {
        year -= 1;
        year;
    }
    if -(1 as libc::c_int) as int64_t <= year && year <= 9999 as libc::c_int as int64_t
    {} else {
        __assert_fail(
            b"-1 <= year && year <= 9999\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/posix_time.c\0" as *const u8
                as *const libc::c_char,
            95 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 89],
                &[libc::c_char; 89],
            >(
                b"int posix_time_from_utc(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_10081: {
        if -(1 as libc::c_int) as int64_t <= year
            && year <= 9999 as libc::c_int as int64_t
        {} else {
            __assert_fail(
                b"-1 <= year && year <= 9999\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/posix_time.c\0"
                    as *const u8 as *const libc::c_char,
                95 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 89],
                    &[libc::c_char; 89],
                >(
                    b"int posix_time_from_utc(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut era: int64_t = (if year >= 0 as libc::c_int as int64_t {
        year
    } else {
        year - 399 as libc::c_int as int64_t
    }) / 400 as libc::c_int as int64_t;
    let mut year_of_era: int64_t = year - era * 400 as libc::c_int as int64_t;
    let mut day_of_year: int64_t = (153 as libc::c_int as int64_t
        * (if month > 2 as libc::c_int as int64_t {
            month - 3 as libc::c_int as int64_t
        } else {
            month + 9 as libc::c_int as int64_t
        }) + 2 as libc::c_int as int64_t) / 5 as libc::c_int as int64_t + day
        - 1 as libc::c_int as int64_t;
    let mut day_of_era: int64_t = year_of_era * 365 as libc::c_int as int64_t
        + year_of_era / 4 as libc::c_int as int64_t
        - year_of_era / 100 as libc::c_int as int64_t + day_of_year;
    let mut posix_days: int64_t = era * 146097 as libc::c_int as int64_t + day_of_era
        - 719468 as libc::c_int as int64_t;
    *out_time = posix_days
        * (24 as libc::c_long * (60 as libc::c_int * 60 as libc::c_int) as libc::c_long)
        + hours * (60 as libc::c_int * 60 as libc::c_int) as int64_t
        + minutes * 60 as libc::c_int as int64_t + seconds;
    return 1 as libc::c_int;
}
unsafe extern "C" fn utc_from_posix_time(
    mut time: int64_t,
    mut out_year: *mut libc::c_int,
    mut out_month: *mut libc::c_int,
    mut out_day: *mut libc::c_int,
    mut out_hours: *mut libc::c_int,
    mut out_minutes: *mut libc::c_int,
    mut out_seconds: *mut libc::c_int,
) -> libc::c_int {
    if is_valid_posix_time(time) == 0 {
        return 0 as libc::c_int;
    }
    let mut days: int64_t = time
        / (24 as libc::c_long * (60 as libc::c_int * 60 as libc::c_int) as libc::c_long);
    let mut leftover_seconds: int64_t = time
        % (24 as libc::c_long * (60 as libc::c_int * 60 as libc::c_int) as libc::c_long);
    if leftover_seconds < 0 as libc::c_int as int64_t {
        days -= 1;
        days;
        leftover_seconds
            += 24 as libc::c_long
                * (60 as libc::c_int * 60 as libc::c_int) as libc::c_long;
    }
    days += 719468 as libc::c_int as int64_t;
    if -(61 as libc::c_int) as int64_t <= days
        && days <= 3652364 as libc::c_int as int64_t
    {} else {
        __assert_fail(
            b"-61 <= days && days <= 3652364\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/posix_time.c\0" as *const u8
                as *const libc::c_char,
            125 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 75],
                &[libc::c_char; 75],
            >(
                b"int utc_from_posix_time(int64_t, int *, int *, int *, int *, int *, int *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_9716: {
        if -(61 as libc::c_int) as int64_t <= days
            && days <= 3652364 as libc::c_int as int64_t
        {} else {
            __assert_fail(
                b"-61 <= days && days <= 3652364\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/posix_time.c\0"
                    as *const u8 as *const libc::c_char,
                125 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 75],
                    &[libc::c_char; 75],
                >(
                    b"int utc_from_posix_time(int64_t, int *, int *, int *, int *, int *, int *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    let mut era: int64_t = (if days > 0 as libc::c_int as int64_t {
        days
    } else {
        days - 146096 as libc::c_int as int64_t
    }) / 146097 as libc::c_int as int64_t;
    let mut day_of_era: int64_t = days - era * 146097 as libc::c_int as int64_t;
    let mut year_of_era: int64_t = (day_of_era
        - day_of_era / 1460 as libc::c_int as int64_t
        + day_of_era / 36524 as libc::c_int as int64_t
        - day_of_era / 146096 as libc::c_int as int64_t) / 365 as libc::c_int as int64_t;
    *out_year = (year_of_era + era * 400 as libc::c_int as int64_t) as libc::c_int;
    let mut day_of_year: int64_t = day_of_era
        - (365 as libc::c_int as int64_t * year_of_era
            + year_of_era / 4 as libc::c_int as int64_t
            - year_of_era / 100 as libc::c_int as int64_t);
    let mut month_of_year: int64_t = (5 as libc::c_int as int64_t * day_of_year
        + 2 as libc::c_int as int64_t) / 153 as libc::c_int as int64_t;
    *out_month = (if month_of_year < 10 as libc::c_int as int64_t {
        month_of_year + 3 as libc::c_int as int64_t
    } else {
        month_of_year - 9 as libc::c_int as int64_t
    }) as libc::c_int;
    if *out_month <= 2 as libc::c_int {
        *out_year += 1;
        *out_year;
    }
    *out_day = (day_of_year
        - (153 as libc::c_int as int64_t * month_of_year + 2 as libc::c_int as int64_t)
            / 5 as libc::c_int as int64_t + 1 as libc::c_int as int64_t) as libc::c_int;
    *out_hours = (leftover_seconds / (60 as libc::c_int * 60 as libc::c_int) as int64_t)
        as libc::c_int;
    leftover_seconds %= (60 as libc::c_int * 60 as libc::c_int) as int64_t;
    *out_minutes = (leftover_seconds / 60 as libc::c_int as int64_t) as libc::c_int;
    *out_seconds = (leftover_seconds % 60 as libc::c_int as int64_t) as libc::c_int;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_tm_to_posix(
    mut tm: *const tm,
    mut out: *mut int64_t,
) -> libc::c_int {
    return posix_time_from_utc(
        (*tm).tm_year as libc::c_long + 1900 as libc::c_long,
        (*tm).tm_mon as libc::c_long + 1 as libc::c_long,
        (*tm).tm_mday as int64_t,
        (*tm).tm_hour as int64_t,
        (*tm).tm_min as int64_t,
        (*tm).tm_sec as int64_t,
        out,
    );
}
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_posix_to_tm(
    mut time: int64_t,
    mut out_tm: *mut tm,
) -> libc::c_int {
    if out_tm.is_null() {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/posix_time.c\0" as *const u8
                as *const libc::c_char,
            156 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut tmp_tm: tm = tm {
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
    OPENSSL_memset(
        &mut tmp_tm as *mut tm as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<tm>() as libc::c_ulong,
    );
    if utc_from_posix_time(
        time,
        &mut tmp_tm.tm_year,
        &mut tmp_tm.tm_mon,
        &mut tmp_tm.tm_mday,
        &mut tmp_tm.tm_hour,
        &mut tmp_tm.tm_min,
        &mut tmp_tm.tm_sec,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    tmp_tm.tm_year -= 1900 as libc::c_int;
    tmp_tm.tm_mon -= 1 as libc::c_int;
    *out_tm = tmp_tm;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_timegm(
    mut tm: *const tm,
    mut out: *mut time_t,
) -> libc::c_int {
    let mut posix_time: int64_t = 0;
    if OPENSSL_tm_to_posix(tm, &mut posix_time) == 0 {
        return 0 as libc::c_int;
    }
    if ::core::mem::size_of::<time_t>() as libc::c_ulong
        == ::core::mem::size_of::<int32_t>() as libc::c_ulong
        && (posix_time > 2147483647 as libc::c_int as int64_t
            || posix_time < (-(2147483647 as libc::c_int) - 1 as libc::c_int) as int64_t)
    {
        return 0 as libc::c_int;
    }
    *out = posix_time;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_gmtime(
    mut time: *const time_t,
    mut out_tm: *mut tm,
) -> *mut tm {
    let mut posix_time: int64_t = *time;
    if OPENSSL_posix_to_tm(posix_time, out_tm) == 0 {
        return 0 as *mut tm;
    }
    return out_tm;
}
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_gmtime_adj(
    mut tm: *mut tm,
    mut offset_day: libc::c_int,
    mut offset_sec: int64_t,
) -> libc::c_int {
    let mut posix_time: int64_t = 0;
    if OPENSSL_tm_to_posix(tm, &mut posix_time) == 0 {
        return 0 as libc::c_int;
    }
    posix_time
        += offset_day as libc::c_long
            * (24 as libc::c_long
                * (60 as libc::c_int * 60 as libc::c_int) as libc::c_long);
    if posix_time > 0 as libc::c_int as int64_t
        && offset_sec > 9223372036854775807 as libc::c_long - posix_time
    {
        return 0 as libc::c_int;
    }
    if posix_time < 0 as libc::c_int as int64_t
        && offset_sec
            < -(9223372036854775807 as libc::c_long) - 1 as libc::c_int as libc::c_long
                - posix_time
    {
        return 0 as libc::c_int;
    }
    posix_time += offset_sec;
    if OPENSSL_posix_to_tm(posix_time, tm) == 0 {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_gmtime_diff(
    mut out_days: *mut libc::c_int,
    mut out_secs: *mut libc::c_int,
    mut from: *const tm,
    mut to: *const tm,
) -> libc::c_int {
    let mut time_to: int64_t = 0;
    let mut time_from: int64_t = 0;
    if OPENSSL_tm_to_posix(to, &mut time_to) == 0
        || OPENSSL_tm_to_posix(from, &mut time_from) == 0
    {
        return 0 as libc::c_int;
    }
    let mut timediff: int64_t = time_to - time_from;
    let mut daydiff: int64_t = timediff
        / (24 as libc::c_long * (60 as libc::c_int * 60 as libc::c_int) as libc::c_long);
    timediff
        %= 24 as libc::c_long * (60 as libc::c_int * 60 as libc::c_int) as libc::c_long;
    *out_secs = timediff as libc::c_int;
    *out_days = daydiff as libc::c_int;
    return 1 as libc::c_int;
}
