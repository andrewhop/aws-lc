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
    pub type stack_st_OPENSSL_STRING;
    pub type stack_st_ASN1_OBJECT;
    pub type stack_st;
    fn memchr(
        _: *const libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn ASN1_OBJECT_free(a: *mut ASN1_OBJECT);
    fn X509_TRUST_set(t: *mut libc::c_int, trust: libc::c_int) -> libc::c_int;
    fn X509_PURPOSE_set(p: *mut libc::c_int, purpose: libc::c_int) -> libc::c_int;
    fn x509v3_a2i_ipadd(
        ipout: *mut libc::c_uchar,
        ipasc: *const libc::c_char,
    ) -> libc::c_int;
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_free(sk: *mut OPENSSL_STACK);
    fn OPENSSL_sk_pop_free_ex(
        sk: *mut OPENSSL_STACK,
        call_free_func: OPENSSL_sk_call_free_func,
        free_func: OPENSSL_sk_free_func,
    );
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn OPENSSL_sk_deep_copy(
        sk: *const OPENSSL_STACK,
        call_copy_func: OPENSSL_sk_call_copy_func,
        copy_func: OPENSSL_sk_copy_func,
        call_free_func: OPENSSL_sk_call_free_func,
        free_func: OPENSSL_sk_free_func,
    ) -> *mut OPENSSL_STACK;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_strdup(s: *const libc::c_char) -> *mut libc::c_char;
    fn OPENSSL_strndup(str: *const libc::c_char, size: size_t) -> *mut libc::c_char;
    fn OPENSSL_memdup(data: *const libc::c_void, size: size_t) -> *mut libc::c_void;
    fn OBJ_dup(obj: *const ASN1_OBJECT) -> *mut ASN1_OBJECT;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __int64_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type int64_t = __int64_t;
pub type uint8_t = __uint8_t;
pub type time_t = __time_t;
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
pub struct X509_VERIFY_PARAM_st {
    pub check_time: int64_t,
    pub flags: libc::c_ulong,
    pub purpose: libc::c_int,
    pub trust: libc::c_int,
    pub depth: libc::c_int,
    pub policies: *mut stack_st_ASN1_OBJECT,
    pub hosts: *mut stack_st_OPENSSL_STRING,
    pub hostflags: libc::c_uint,
    pub email: *mut libc::c_char,
    pub emaillen: size_t,
    pub ip: *mut libc::c_uchar,
    pub iplen: size_t,
    pub poison: libc::c_uchar,
}
pub type X509_VERIFY_PARAM = X509_VERIFY_PARAM_st;
pub type OPENSSL_sk_free_func = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type OPENSSL_sk_copy_func = Option::<
    unsafe extern "C" fn(*const libc::c_void) -> *mut libc::c_void,
>;
pub type OPENSSL_sk_call_free_func = Option::<
    unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
>;
pub type OPENSSL_sk_call_copy_func = Option::<
    unsafe extern "C" fn(OPENSSL_sk_copy_func, *const libc::c_void) -> *mut libc::c_void,
>;
pub type OPENSSL_STACK = stack_st;
pub type sk_OPENSSL_STRING_free_func = Option::<
    unsafe extern "C" fn(*mut libc::c_char) -> (),
>;
pub type sk_OPENSSL_STRING_copy_func = Option::<
    unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char,
>;
pub type sk_ASN1_OBJECT_free_func = Option::<
    unsafe extern "C" fn(*mut ASN1_OBJECT) -> (),
>;
pub type sk_ASN1_OBJECT_copy_func = Option::<
    unsafe extern "C" fn(*const ASN1_OBJECT) -> *mut ASN1_OBJECT,
>;
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_deep_copy(
    mut sk: *const stack_st_ASN1_OBJECT,
    mut copy_func: sk_ASN1_OBJECT_copy_func,
    mut free_func: sk_ASN1_OBJECT_free_func,
) -> *mut stack_st_ASN1_OBJECT {
    return OPENSSL_sk_deep_copy(
        sk as *const OPENSSL_STACK,
        Some(
            sk_ASN1_OBJECT_call_copy_func
                as unsafe extern "C" fn(
                    OPENSSL_sk_copy_func,
                    *const libc::c_void,
                ) -> *mut libc::c_void,
        ),
        ::core::mem::transmute::<
            sk_ASN1_OBJECT_copy_func,
            OPENSSL_sk_copy_func,
        >(copy_func),
        Some(
            sk_ASN1_OBJECT_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_ASN1_OBJECT_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    ) as *mut stack_st_ASN1_OBJECT;
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<OPENSSL_sk_free_func, sk_ASN1_OBJECT_free_func>(free_func))
        .expect("non-null function pointer")(ptr as *mut ASN1_OBJECT);
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_call_copy_func(
    mut copy_func: OPENSSL_sk_copy_func,
    mut ptr: *const libc::c_void,
) -> *mut libc::c_void {
    return (::core::mem::transmute::<
        OPENSSL_sk_copy_func,
        sk_ASN1_OBJECT_copy_func,
    >(copy_func))
        .expect("non-null function pointer")(ptr as *const ASN1_OBJECT)
        as *mut libc::c_void;
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_new_null() -> *mut stack_st_ASN1_OBJECT {
    return OPENSSL_sk_new_null() as *mut stack_st_ASN1_OBJECT;
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_pop_free(
    mut sk: *mut stack_st_ASN1_OBJECT,
    mut free_func: sk_ASN1_OBJECT_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_ASN1_OBJECT_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_ASN1_OBJECT_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_push(
    mut sk: *mut stack_st_ASN1_OBJECT,
    mut p: *mut ASN1_OBJECT,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_OPENSSL_STRING_num(
    mut sk: *const stack_st_OPENSSL_STRING,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_OPENSSL_STRING_call_copy_func(
    mut copy_func: OPENSSL_sk_copy_func,
    mut ptr: *const libc::c_void,
) -> *mut libc::c_void {
    return (::core::mem::transmute::<
        OPENSSL_sk_copy_func,
        sk_OPENSSL_STRING_copy_func,
    >(copy_func))
        .expect("non-null function pointer")(ptr as *const libc::c_char)
        as *mut libc::c_void;
}
#[inline]
unsafe extern "C" fn sk_OPENSSL_STRING_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<
        OPENSSL_sk_free_func,
        sk_OPENSSL_STRING_free_func,
    >(free_func))
        .expect("non-null function pointer")(ptr as *mut libc::c_char);
}
#[inline]
unsafe extern "C" fn sk_OPENSSL_STRING_new_null() -> *mut stack_st_OPENSSL_STRING {
    return OPENSSL_sk_new_null() as *mut stack_st_OPENSSL_STRING;
}
#[inline]
unsafe extern "C" fn sk_OPENSSL_STRING_free(mut sk: *mut stack_st_OPENSSL_STRING) {
    OPENSSL_sk_free(sk as *mut OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_OPENSSL_STRING_pop_free(
    mut sk: *mut stack_st_OPENSSL_STRING,
    mut free_func: sk_OPENSSL_STRING_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_OPENSSL_STRING_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_OPENSSL_STRING_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_OPENSSL_STRING_push(
    mut sk: *mut stack_st_OPENSSL_STRING,
    mut p: *mut libc::c_char,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_OPENSSL_STRING_deep_copy(
    mut sk: *const stack_st_OPENSSL_STRING,
    mut copy_func: sk_OPENSSL_STRING_copy_func,
    mut free_func: sk_OPENSSL_STRING_free_func,
) -> *mut stack_st_OPENSSL_STRING {
    return OPENSSL_sk_deep_copy(
        sk as *const OPENSSL_STACK,
        Some(
            sk_OPENSSL_STRING_call_copy_func
                as unsafe extern "C" fn(
                    OPENSSL_sk_copy_func,
                    *const libc::c_void,
                ) -> *mut libc::c_void,
        ),
        ::core::mem::transmute::<
            sk_OPENSSL_STRING_copy_func,
            OPENSSL_sk_copy_func,
        >(copy_func),
        Some(
            sk_OPENSSL_STRING_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_OPENSSL_STRING_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    ) as *mut stack_st_OPENSSL_STRING;
}
#[inline]
unsafe extern "C" fn OPENSSL_memchr(
    mut s: *const libc::c_void,
    mut c: libc::c_int,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return 0 as *mut libc::c_void;
    }
    return memchr(s, c, n);
}
unsafe extern "C" fn str_free(mut s: *mut libc::c_char) {
    OPENSSL_free(s as *mut libc::c_void);
}
unsafe extern "C" fn int_x509_param_set_hosts(
    mut param: *mut X509_VERIFY_PARAM,
    mut mode: libc::c_int,
    mut name: *const libc::c_char,
    mut namelen: size_t,
) -> libc::c_int {
    let mut copy: *mut libc::c_char = 0 as *mut libc::c_char;
    if !name.is_null() && namelen == 0 as libc::c_int as size_t {
        namelen = strlen(name);
    }
    if !name.is_null()
        && !(OPENSSL_memchr(name as *const libc::c_void, '\0' as i32, namelen)).is_null()
    {
        return 0 as libc::c_int;
    }
    if mode == 0 as libc::c_int && !((*param).hosts).is_null() {
        sk_OPENSSL_STRING_pop_free(
            (*param).hosts,
            Some(str_free as unsafe extern "C" fn(*mut libc::c_char) -> ()),
        );
        (*param).hosts = 0 as *mut stack_st_OPENSSL_STRING;
    }
    if name.is_null() || namelen == 0 as libc::c_int as size_t {
        return 1 as libc::c_int;
    }
    copy = OPENSSL_strndup(name, namelen);
    if copy.is_null() {
        return 0 as libc::c_int;
    }
    if ((*param).hosts).is_null()
        && {
            (*param).hosts = sk_OPENSSL_STRING_new_null();
            ((*param).hosts).is_null()
        }
    {
        OPENSSL_free(copy as *mut libc::c_void);
        return 0 as libc::c_int;
    }
    if sk_OPENSSL_STRING_push((*param).hosts, copy) == 0 {
        OPENSSL_free(copy as *mut libc::c_void);
        if sk_OPENSSL_STRING_num((*param).hosts) == 0 as libc::c_int as size_t {
            sk_OPENSSL_STRING_free((*param).hosts);
            (*param).hosts = 0 as *mut stack_st_OPENSSL_STRING;
        }
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_new() -> *mut X509_VERIFY_PARAM {
    let mut param: *mut X509_VERIFY_PARAM = OPENSSL_zalloc(
        ::core::mem::size_of::<X509_VERIFY_PARAM>() as libc::c_ulong,
    ) as *mut X509_VERIFY_PARAM;
    if param.is_null() {
        return 0 as *mut X509_VERIFY_PARAM;
    }
    (*param).depth = -(1 as libc::c_int);
    return param;
}
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_free(mut param: *mut X509_VERIFY_PARAM) {
    if param.is_null() {
        return;
    }
    sk_ASN1_OBJECT_pop_free(
        (*param).policies,
        Some(ASN1_OBJECT_free as unsafe extern "C" fn(*mut ASN1_OBJECT) -> ()),
    );
    sk_OPENSSL_STRING_pop_free(
        (*param).hosts,
        Some(str_free as unsafe extern "C" fn(*mut libc::c_char) -> ()),
    );
    OPENSSL_free((*param).email as *mut libc::c_void);
    OPENSSL_free((*param).ip as *mut libc::c_void);
    OPENSSL_free(param as *mut libc::c_void);
}
unsafe extern "C" fn should_copy(
    mut dest_is_set: libc::c_int,
    mut src_is_set: libc::c_int,
    mut prefer_src: libc::c_int,
) -> libc::c_int {
    if prefer_src != 0 {
        return src_is_set;
    }
    return (src_is_set != 0 && dest_is_set == 0) as libc::c_int;
}
unsafe extern "C" fn copy_int_param(
    mut dest: *mut libc::c_int,
    mut src: *const libc::c_int,
    mut default_val: libc::c_int,
    mut prefer_src: libc::c_int,
) {
    if should_copy(
        (*dest != default_val) as libc::c_int,
        (*src != default_val) as libc::c_int,
        prefer_src,
    ) != 0
    {
        *dest = *src;
    }
}
unsafe extern "C" fn x509_verify_param_copy(
    mut dest: *mut X509_VERIFY_PARAM,
    mut src: *const X509_VERIFY_PARAM,
    mut prefer_src: libc::c_int,
) -> libc::c_int {
    if src.is_null() {
        return 1 as libc::c_int;
    }
    copy_int_param(&mut (*dest).purpose, &(*src).purpose, 0 as libc::c_int, prefer_src);
    copy_int_param(&mut (*dest).trust, &(*src).trust, 0 as libc::c_int, prefer_src);
    copy_int_param(&mut (*dest).depth, &(*src).depth, -(1 as libc::c_int), prefer_src);
    if (*dest).flags & 0x2 as libc::c_int as libc::c_ulong == 0 {
        (*dest).check_time = (*src).check_time;
    }
    (*dest).flags |= (*src).flags;
    if should_copy(
        ((*dest).policies != 0 as *mut libc::c_void as *mut stack_st_ASN1_OBJECT)
            as libc::c_int,
        ((*src).policies != 0 as *mut libc::c_void as *mut stack_st_ASN1_OBJECT)
            as libc::c_int,
        prefer_src,
    ) != 0
    {
        if X509_VERIFY_PARAM_set1_policies(dest, (*src).policies) == 0 {
            return 0 as libc::c_int;
        }
    }
    if should_copy(
        ((*dest).hosts != 0 as *mut libc::c_void as *mut stack_st_OPENSSL_STRING)
            as libc::c_int,
        ((*src).hosts != 0 as *mut libc::c_void as *mut stack_st_OPENSSL_STRING)
            as libc::c_int,
        prefer_src,
    ) != 0
    {
        sk_OPENSSL_STRING_pop_free(
            (*dest).hosts,
            Some(str_free as unsafe extern "C" fn(*mut libc::c_char) -> ()),
        );
        (*dest).hosts = 0 as *mut stack_st_OPENSSL_STRING;
        if !((*src).hosts).is_null() {
            (*dest)
                .hosts = sk_OPENSSL_STRING_deep_copy(
                (*src).hosts,
                Some(
                    OPENSSL_strdup
                        as unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char,
                ),
                Some(str_free as unsafe extern "C" fn(*mut libc::c_char) -> ()),
            );
            if ((*dest).hosts).is_null() {
                return 0 as libc::c_int;
            }
            (*dest).hostflags = (*src).hostflags;
        }
    }
    if should_copy(
        ((*dest).email != 0 as *mut libc::c_void as *mut libc::c_char) as libc::c_int,
        ((*src).email != 0 as *mut libc::c_void as *mut libc::c_char) as libc::c_int,
        prefer_src,
    ) != 0
    {
        if X509_VERIFY_PARAM_set1_email(dest, (*src).email, (*src).emaillen) == 0 {
            return 0 as libc::c_int;
        }
    }
    if should_copy(
        ((*dest).ip != 0 as *mut libc::c_void as *mut libc::c_uchar) as libc::c_int,
        ((*src).ip != 0 as *mut libc::c_void as *mut libc::c_uchar) as libc::c_int,
        prefer_src,
    ) != 0
    {
        if X509_VERIFY_PARAM_set1_ip(dest, (*src).ip, (*src).iplen) == 0 {
            return 0 as libc::c_int;
        }
    }
    (*dest).poison = (*src).poison;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_inherit(
    mut dest: *mut X509_VERIFY_PARAM,
    mut src: *const X509_VERIFY_PARAM,
) -> libc::c_int {
    return x509_verify_param_copy(dest, src, 0 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set1(
    mut to: *mut X509_VERIFY_PARAM,
    mut from: *const X509_VERIFY_PARAM,
) -> libc::c_int {
    return x509_verify_param_copy(to, from, 1 as libc::c_int);
}
unsafe extern "C" fn int_x509_param_set1_email(
    mut pdest: *mut *mut libc::c_char,
    mut pdestlen: *mut size_t,
    mut src: *const libc::c_char,
    mut srclen: size_t,
) -> libc::c_int {
    let mut tmp: *mut libc::c_void = 0 as *mut libc::c_void;
    if !src.is_null() {
        if srclen == 0 as libc::c_int as size_t {
            srclen = strlen(src);
        }
        tmp = OPENSSL_strndup(src, srclen) as *mut libc::c_void;
        if tmp.is_null() {
            return 0 as libc::c_int;
        }
    } else {
        tmp = 0 as *mut libc::c_void;
        srclen = 0 as libc::c_int as size_t;
    }
    if !(*pdest).is_null() {
        OPENSSL_free(*pdest as *mut libc::c_void);
    }
    *pdest = tmp as *mut libc::c_char;
    if !pdestlen.is_null() {
        *pdestlen = srclen;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn int_x509_param_set1_ip(
    mut pdest: *mut *mut libc::c_uchar,
    mut pdestlen: *mut size_t,
    mut src: *const libc::c_uchar,
    mut srclen: size_t,
) -> libc::c_int {
    let mut tmp: *mut libc::c_void = 0 as *mut libc::c_void;
    if src.is_null() || srclen == 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    tmp = OPENSSL_memdup(src as *const libc::c_void, srclen);
    if tmp.is_null() {
        return 0 as libc::c_int;
    }
    if !(*pdest).is_null() {
        OPENSSL_free(*pdest as *mut libc::c_void);
    }
    *pdest = tmp as *mut libc::c_uchar;
    if !pdestlen.is_null() {
        *pdestlen = srclen;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set_flags(
    mut param: *mut X509_VERIFY_PARAM,
    mut flags: libc::c_ulong,
) -> libc::c_int {
    (*param).flags |= flags;
    if flags
        & (0x80 as libc::c_int | 0x100 as libc::c_int | 0x200 as libc::c_int
            | 0x400 as libc::c_int) as libc::c_ulong != 0
    {
        (*param).flags |= 0x80 as libc::c_int as libc::c_ulong;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_clear_flags(
    mut param: *mut X509_VERIFY_PARAM,
    mut flags: libc::c_ulong,
) -> libc::c_int {
    (*param).flags &= !flags;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_get_flags(
    mut param: *const X509_VERIFY_PARAM,
) -> libc::c_ulong {
    return (*param).flags;
}
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set_purpose(
    mut param: *mut X509_VERIFY_PARAM,
    mut purpose: libc::c_int,
) -> libc::c_int {
    return X509_PURPOSE_set(&mut (*param).purpose, purpose);
}
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set_trust(
    mut param: *mut X509_VERIFY_PARAM,
    mut trust: libc::c_int,
) -> libc::c_int {
    return X509_TRUST_set(&mut (*param).trust, trust);
}
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set_depth(
    mut param: *mut X509_VERIFY_PARAM,
    mut depth: libc::c_int,
) {
    (*param).depth = depth;
}
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set_time_posix(
    mut param: *mut X509_VERIFY_PARAM,
    mut t: int64_t,
) {
    (*param).check_time = t;
    (*param).flags |= 0x2 as libc::c_int as libc::c_ulong;
}
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set_time(
    mut param: *mut X509_VERIFY_PARAM,
    mut t: time_t,
) {
    X509_VERIFY_PARAM_set_time_posix(param, t);
}
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_add0_policy(
    mut param: *mut X509_VERIFY_PARAM,
    mut policy: *mut ASN1_OBJECT,
) -> libc::c_int {
    if ((*param).policies).is_null() {
        (*param).policies = sk_ASN1_OBJECT_new_null();
        if ((*param).policies).is_null() {
            return 0 as libc::c_int;
        }
    }
    if sk_ASN1_OBJECT_push((*param).policies, policy) == 0 {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set1_policies(
    mut param: *mut X509_VERIFY_PARAM,
    mut policies: *const stack_st_ASN1_OBJECT,
) -> libc::c_int {
    if param.is_null() {
        return 0 as libc::c_int;
    }
    sk_ASN1_OBJECT_pop_free(
        (*param).policies,
        Some(ASN1_OBJECT_free as unsafe extern "C" fn(*mut ASN1_OBJECT) -> ()),
    );
    if policies.is_null() {
        (*param).policies = 0 as *mut stack_st_ASN1_OBJECT;
        return 1 as libc::c_int;
    }
    (*param)
        .policies = sk_ASN1_OBJECT_deep_copy(
        policies,
        Some(OBJ_dup as unsafe extern "C" fn(*const ASN1_OBJECT) -> *mut ASN1_OBJECT),
        Some(ASN1_OBJECT_free as unsafe extern "C" fn(*mut ASN1_OBJECT) -> ()),
    );
    if ((*param).policies).is_null() {
        return 0 as libc::c_int;
    }
    (*param).flags |= 0x80 as libc::c_int as libc::c_ulong;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set1_host(
    mut param: *mut X509_VERIFY_PARAM,
    mut name: *const libc::c_char,
    mut namelen: size_t,
) -> libc::c_int {
    if int_x509_param_set_hosts(param, 0 as libc::c_int, name, namelen) == 0 {
        (*param).poison = 1 as libc::c_int as libc::c_uchar;
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_add1_host(
    mut param: *mut X509_VERIFY_PARAM,
    mut name: *const libc::c_char,
    mut namelen: size_t,
) -> libc::c_int {
    if int_x509_param_set_hosts(param, 1 as libc::c_int, name, namelen) == 0 {
        (*param).poison = 1 as libc::c_int as libc::c_uchar;
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set_hostflags(
    mut param: *mut X509_VERIFY_PARAM,
    mut flags: libc::c_uint,
) {
    (*param).hostflags = flags;
}
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_get_hostflags(
    mut param: *const X509_VERIFY_PARAM,
) -> libc::c_uint {
    return (*param).hostflags;
}
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set1_email(
    mut param: *mut X509_VERIFY_PARAM,
    mut email: *const libc::c_char,
    mut emaillen: size_t,
) -> libc::c_int {
    if !(OPENSSL_memchr(email as *const libc::c_void, '\0' as i32, emaillen)).is_null()
        || int_x509_param_set1_email(
            &mut (*param).email,
            &mut (*param).emaillen,
            email,
            emaillen,
        ) == 0
    {
        (*param).poison = 1 as libc::c_int as libc::c_uchar;
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set1_ip(
    mut param: *mut X509_VERIFY_PARAM,
    mut ip: *const libc::c_uchar,
    mut iplen: size_t,
) -> libc::c_int {
    if iplen != 0 as libc::c_int as size_t && iplen != 4 as libc::c_int as size_t
        && iplen != 16 as libc::c_int as size_t
        || int_x509_param_set1_ip(&mut (*param).ip, &mut (*param).iplen, ip, iplen) == 0
    {
        (*param).poison = 1 as libc::c_int as libc::c_uchar;
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_set1_ip_asc(
    mut param: *mut X509_VERIFY_PARAM,
    mut ipasc: *const libc::c_char,
) -> libc::c_int {
    let mut ipout: [libc::c_uchar; 16] = [0; 16];
    let mut iplen: size_t = 0;
    iplen = x509v3_a2i_ipadd(ipout.as_mut_ptr(), ipasc) as size_t;
    if iplen == 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    return X509_VERIFY_PARAM_set1_ip(param, ipout.as_mut_ptr(), iplen);
}
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_get_depth(
    mut param: *const X509_VERIFY_PARAM,
) -> libc::c_int {
    return (*param).depth;
}
static mut kDefaultParam: X509_VERIFY_PARAM = {
    let mut init = X509_VERIFY_PARAM_st {
        check_time: 0,
        flags: 0x8000 as libc::c_int as libc::c_ulong,
        purpose: 0,
        trust: 0,
        depth: 100 as libc::c_int,
        policies: 0 as *const stack_st_ASN1_OBJECT as *mut stack_st_ASN1_OBJECT,
        hosts: 0 as *const stack_st_OPENSSL_STRING as *mut stack_st_OPENSSL_STRING,
        hostflags: 0,
        email: 0 as *const libc::c_char as *mut libc::c_char,
        emaillen: 0,
        ip: 0 as *const libc::c_uchar as *mut libc::c_uchar,
        iplen: 0,
        poison: 0,
    };
    init
};
static mut kSMIMESignParam: X509_VERIFY_PARAM = {
    let mut init = X509_VERIFY_PARAM_st {
        check_time: 0,
        flags: 0,
        purpose: 4 as libc::c_int,
        trust: 4 as libc::c_int,
        depth: -(1 as libc::c_int),
        policies: 0 as *const stack_st_ASN1_OBJECT as *mut stack_st_ASN1_OBJECT,
        hosts: 0 as *const stack_st_OPENSSL_STRING as *mut stack_st_OPENSSL_STRING,
        hostflags: 0,
        email: 0 as *const libc::c_char as *mut libc::c_char,
        emaillen: 0,
        ip: 0 as *const libc::c_uchar as *mut libc::c_uchar,
        iplen: 0,
        poison: 0,
    };
    init
};
static mut kSSLClientParam: X509_VERIFY_PARAM = {
    let mut init = X509_VERIFY_PARAM_st {
        check_time: 0,
        flags: 0,
        purpose: 1 as libc::c_int,
        trust: 2 as libc::c_int,
        depth: -(1 as libc::c_int),
        policies: 0 as *const stack_st_ASN1_OBJECT as *mut stack_st_ASN1_OBJECT,
        hosts: 0 as *const stack_st_OPENSSL_STRING as *mut stack_st_OPENSSL_STRING,
        hostflags: 0,
        email: 0 as *const libc::c_char as *mut libc::c_char,
        emaillen: 0,
        ip: 0 as *const libc::c_uchar as *mut libc::c_uchar,
        iplen: 0,
        poison: 0,
    };
    init
};
static mut kSSLServerParam: X509_VERIFY_PARAM = {
    let mut init = X509_VERIFY_PARAM_st {
        check_time: 0,
        flags: 0,
        purpose: 2 as libc::c_int,
        trust: 3 as libc::c_int,
        depth: -(1 as libc::c_int),
        policies: 0 as *const stack_st_ASN1_OBJECT as *mut stack_st_ASN1_OBJECT,
        hosts: 0 as *const stack_st_OPENSSL_STRING as *mut stack_st_OPENSSL_STRING,
        hostflags: 0,
        email: 0 as *const libc::c_char as *mut libc::c_char,
        emaillen: 0,
        ip: 0 as *const libc::c_uchar as *mut libc::c_uchar,
        iplen: 0,
        poison: 0,
    };
    init
};
#[no_mangle]
pub unsafe extern "C" fn X509_VERIFY_PARAM_lookup(
    mut name: *const libc::c_char,
) -> *const X509_VERIFY_PARAM {
    if strcmp(name, b"default\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
    {
        return &kDefaultParam;
    }
    if strcmp(name, b"pkcs7\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        return &kSMIMESignParam;
    }
    if strcmp(name, b"smime_sign\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        return &kSMIMESignParam;
    }
    if strcmp(name, b"ssl_client\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        return &kSSLClientParam;
    }
    if strcmp(name, b"ssl_server\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        return &kSSLServerParam;
    }
    return 0 as *const X509_VERIFY_PARAM;
}
