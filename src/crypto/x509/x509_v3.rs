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
    pub type stack_st_X509_EXTENSION;
    pub type stack_st;
    fn ASN1_OCTET_STRING_set(
        str: *mut ASN1_OCTET_STRING,
        data: *const libc::c_uchar,
        len: libc::c_int,
    ) -> libc::c_int;
    fn ASN1_OBJECT_free(a: *mut ASN1_OBJECT);
    fn X509_EXTENSION_new() -> *mut X509_EXTENSION;
    fn X509_EXTENSION_free(ex: *mut X509_EXTENSION);
    fn X509_EXTENSION_dup(ex: *const X509_EXTENSION) -> *mut X509_EXTENSION;
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_free(sk: *mut OPENSSL_STACK);
    fn OPENSSL_sk_insert(
        sk: *mut OPENSSL_STACK,
        p: *mut libc::c_void,
        where_0: size_t,
    ) -> size_t;
    fn OPENSSL_sk_delete(sk: *mut OPENSSL_STACK, where_0: size_t) -> *mut libc::c_void;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OBJ_dup(obj: *const ASN1_OBJECT) -> *mut ASN1_OBJECT;
    fn OBJ_cmp(a: *const ASN1_OBJECT, b: *const ASN1_OBJECT) -> libc::c_int;
    fn OBJ_nid2obj(nid: libc::c_int) -> *mut ASN1_OBJECT;
}
pub type size_t = libc::c_ulong;
pub type ASN1_BOOLEAN = libc::c_int;
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
pub type ASN1_OCTET_STRING = asn1_string_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_extension_st {
    pub object: *mut ASN1_OBJECT,
    pub critical: ASN1_BOOLEAN,
    pub value: *mut ASN1_OCTET_STRING,
}
pub type X509_EXTENSION = X509_extension_st;
pub type OPENSSL_STACK = stack_st;
#[inline]
unsafe extern "C" fn sk_X509_EXTENSION_delete(
    mut sk: *mut stack_st_X509_EXTENSION,
    mut where_0: size_t,
) -> *mut X509_EXTENSION {
    return OPENSSL_sk_delete(sk as *mut OPENSSL_STACK, where_0) as *mut X509_EXTENSION;
}
#[inline]
unsafe extern "C" fn sk_X509_EXTENSION_num(
    mut sk: *const stack_st_X509_EXTENSION,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_EXTENSION_new_null() -> *mut stack_st_X509_EXTENSION {
    return OPENSSL_sk_new_null() as *mut stack_st_X509_EXTENSION;
}
#[inline]
unsafe extern "C" fn sk_X509_EXTENSION_value(
    mut sk: *const stack_st_X509_EXTENSION,
    mut i: size_t,
) -> *mut X509_EXTENSION {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509_EXTENSION;
}
#[inline]
unsafe extern "C" fn sk_X509_EXTENSION_free(mut sk: *mut stack_st_X509_EXTENSION) {
    OPENSSL_sk_free(sk as *mut OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_EXTENSION_insert(
    mut sk: *mut stack_st_X509_EXTENSION,
    mut p: *mut X509_EXTENSION,
    mut where_0: size_t,
) -> size_t {
    return OPENSSL_sk_insert(sk as *mut OPENSSL_STACK, p as *mut libc::c_void, where_0);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509v3_get_ext_count(
    mut x: *const stack_st_X509_EXTENSION,
) -> libc::c_int {
    if x.is_null() {
        return 0 as libc::c_int;
    }
    return sk_X509_EXTENSION_num(x) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509v3_get_ext_by_NID(
    mut x: *const stack_st_X509_EXTENSION,
    mut nid: libc::c_int,
    mut lastpos: libc::c_int,
) -> libc::c_int {
    let mut obj: *const ASN1_OBJECT = OBJ_nid2obj(nid);
    if obj.is_null() {
        return -(1 as libc::c_int);
    }
    return X509v3_get_ext_by_OBJ(x, obj, lastpos);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509v3_get_ext_by_OBJ(
    mut sk: *const stack_st_X509_EXTENSION,
    mut obj: *const ASN1_OBJECT,
    mut lastpos: libc::c_int,
) -> libc::c_int {
    if sk.is_null() {
        return -(1 as libc::c_int);
    }
    lastpos += 1;
    lastpos;
    if lastpos < 0 as libc::c_int {
        lastpos = 0 as libc::c_int;
    }
    let mut n: libc::c_int = sk_X509_EXTENSION_num(sk) as libc::c_int;
    while lastpos < n {
        let mut ex: *const X509_EXTENSION = sk_X509_EXTENSION_value(
            sk,
            lastpos as size_t,
        );
        if OBJ_cmp((*ex).object, obj) == 0 as libc::c_int {
            return lastpos;
        }
        lastpos += 1;
        lastpos;
    }
    return -(1 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509v3_get_ext_by_critical(
    mut sk: *const stack_st_X509_EXTENSION,
    mut crit: libc::c_int,
    mut lastpos: libc::c_int,
) -> libc::c_int {
    if sk.is_null() {
        return -(1 as libc::c_int);
    }
    lastpos += 1;
    lastpos;
    if lastpos < 0 as libc::c_int {
        lastpos = 0 as libc::c_int;
    }
    crit = (crit != 0) as libc::c_int;
    let mut n: libc::c_int = sk_X509_EXTENSION_num(sk) as libc::c_int;
    while lastpos < n {
        let mut ex: *const X509_EXTENSION = sk_X509_EXTENSION_value(
            sk,
            lastpos as size_t,
        );
        if X509_EXTENSION_get_critical(ex) == crit {
            return lastpos;
        }
        lastpos += 1;
        lastpos;
    }
    return -(1 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509v3_get_ext(
    mut x: *const stack_st_X509_EXTENSION,
    mut loc: libc::c_int,
) -> *mut X509_EXTENSION {
    if x.is_null() || loc < 0 as libc::c_int || sk_X509_EXTENSION_num(x) <= loc as size_t
    {
        return 0 as *mut X509_EXTENSION
    } else {
        return sk_X509_EXTENSION_value(x, loc as size_t)
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509v3_delete_ext(
    mut x: *mut stack_st_X509_EXTENSION,
    mut loc: libc::c_int,
) -> *mut X509_EXTENSION {
    let mut ret: *mut X509_EXTENSION = 0 as *mut X509_EXTENSION;
    if x.is_null() || loc < 0 as libc::c_int || sk_X509_EXTENSION_num(x) <= loc as size_t
    {
        return 0 as *mut X509_EXTENSION;
    }
    ret = sk_X509_EXTENSION_delete(x, loc as size_t);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509v3_add_ext(
    mut x: *mut *mut stack_st_X509_EXTENSION,
    mut ex: *const X509_EXTENSION,
    mut loc: libc::c_int,
) -> *mut stack_st_X509_EXTENSION {
    let mut n: libc::c_int = 0;
    let mut current_block: u64;
    let mut new_ex: *mut X509_EXTENSION = 0 as *mut X509_EXTENSION;
    let mut sk: *mut stack_st_X509_EXTENSION = 0 as *mut stack_st_X509_EXTENSION;
    let mut free_sk: libc::c_int = 0 as libc::c_int;
    if x.is_null() {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_v3.c\0" as *const u8
                as *const libc::c_char,
            149 as libc::c_int as libc::c_uint,
        );
    } else {
        if (*x).is_null() {
            sk = sk_X509_EXTENSION_new_null();
            if sk.is_null() {
                current_block = 4673950452908696313;
            } else {
                free_sk = 1 as libc::c_int;
                current_block = 10886091980245723256;
            }
        } else {
            sk = *x;
            current_block = 10886091980245723256;
        }
        match current_block {
            4673950452908696313 => {}
            _ => {
                n = sk_X509_EXTENSION_num(sk) as libc::c_int;
                if loc > n {
                    loc = n;
                } else if loc < 0 as libc::c_int {
                    loc = n;
                }
                new_ex = X509_EXTENSION_dup(ex);
                if !new_ex.is_null() {
                    if !(sk_X509_EXTENSION_insert(sk, new_ex, loc as size_t) == 0) {
                        if (*x).is_null() {
                            *x = sk;
                        }
                        return sk;
                    }
                }
            }
        }
    }
    X509_EXTENSION_free(new_ex);
    if free_sk != 0 {
        sk_X509_EXTENSION_free(sk);
    }
    return 0 as *mut stack_st_X509_EXTENSION;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_EXTENSION_create_by_NID(
    mut ex: *mut *mut X509_EXTENSION,
    mut nid: libc::c_int,
    mut crit: libc::c_int,
    mut data: *const ASN1_OCTET_STRING,
) -> *mut X509_EXTENSION {
    let mut obj: *const ASN1_OBJECT = 0 as *const ASN1_OBJECT;
    let mut ret: *mut X509_EXTENSION = 0 as *mut X509_EXTENSION;
    obj = OBJ_nid2obj(nid);
    if obj.is_null() {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            129 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_v3.c\0" as *const u8
                as *const libc::c_char,
            196 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut X509_EXTENSION;
    }
    ret = X509_EXTENSION_create_by_OBJ(ex, obj, crit, data);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_EXTENSION_create_by_OBJ(
    mut ex: *mut *mut X509_EXTENSION,
    mut obj: *const ASN1_OBJECT,
    mut crit: libc::c_int,
    mut data: *const ASN1_OCTET_STRING,
) -> *mut X509_EXTENSION {
    let mut ret: *mut X509_EXTENSION = 0 as *mut X509_EXTENSION;
    if ex.is_null() || (*ex).is_null() {
        ret = X509_EXTENSION_new();
        if ret.is_null() {
            return 0 as *mut X509_EXTENSION;
        }
    } else {
        ret = *ex;
    }
    if !(X509_EXTENSION_set_object(ret, obj) == 0) {
        if !(X509_EXTENSION_set_critical(ret, crit) == 0) {
            if !(X509_EXTENSION_set_data(ret, data) == 0) {
                if !ex.is_null() && (*ex).is_null() {
                    *ex = ret;
                }
                return ret;
            }
        }
    }
    if ex.is_null() || ret != *ex {
        X509_EXTENSION_free(ret);
    }
    return 0 as *mut X509_EXTENSION;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_EXTENSION_set_object(
    mut ex: *mut X509_EXTENSION,
    mut obj: *const ASN1_OBJECT,
) -> libc::c_int {
    if ex.is_null() || obj.is_null() {
        return 0 as libc::c_int;
    }
    ASN1_OBJECT_free((*ex).object);
    (*ex).object = OBJ_dup(obj);
    return ((*ex).object != 0 as *mut libc::c_void as *mut ASN1_OBJECT) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_EXTENSION_set_critical(
    mut ex: *mut X509_EXTENSION,
    mut crit: libc::c_int,
) -> libc::c_int {
    if ex.is_null() {
        return 0 as libc::c_int;
    }
    (*ex).critical = if crit != 0 { 0xff as libc::c_int } else { -(1 as libc::c_int) };
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_EXTENSION_set_data(
    mut ex: *mut X509_EXTENSION,
    mut data: *const ASN1_OCTET_STRING,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    if ex.is_null() {
        return 0 as libc::c_int;
    }
    i = ASN1_OCTET_STRING_set((*ex).value, (*data).data, (*data).length);
    if i == 0 {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_EXTENSION_get_object(
    mut ex: *const X509_EXTENSION,
) -> *mut ASN1_OBJECT {
    if ex.is_null() {
        return 0 as *mut ASN1_OBJECT;
    }
    return (*ex).object;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_EXTENSION_get_data(
    mut ex: *const X509_EXTENSION,
) -> *mut ASN1_OCTET_STRING {
    if ex.is_null() {
        return 0 as *mut ASN1_OCTET_STRING;
    }
    return (*ex).value;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_EXTENSION_get_critical(
    mut ex: *const X509_EXTENSION,
) -> libc::c_int {
    if ex.is_null() {
        return 0 as libc::c_int;
    }
    if (*ex).critical > 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
