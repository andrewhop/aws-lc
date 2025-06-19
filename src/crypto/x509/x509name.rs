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
    pub type stack_st_X509_NAME_ENTRY;
    pub type stack_st;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn ASN1_STRING_set(
        str: *mut ASN1_STRING,
        data: *const libc::c_void,
        len: ossl_ssize_t,
    ) -> libc::c_int;
    fn ASN1_STRING_to_UTF8(
        out: *mut *mut libc::c_uchar,
        in_0: *const ASN1_STRING,
    ) -> libc::c_int;
    fn ASN1_STRING_set_by_NID(
        out: *mut *mut ASN1_STRING,
        in_0: *const libc::c_uchar,
        len: ossl_ssize_t,
        inform: libc::c_int,
        nid: libc::c_int,
    ) -> *mut ASN1_STRING;
    fn ASN1_OBJECT_free(a: *mut ASN1_OBJECT);
    fn X509_NAME_ENTRY_new() -> *mut X509_NAME_ENTRY;
    fn X509_NAME_ENTRY_free(entry: *mut X509_NAME_ENTRY);
    fn X509_NAME_ENTRY_dup(entry: *const X509_NAME_ENTRY) -> *mut X509_NAME_ENTRY;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_insert(
        sk: *mut OPENSSL_STACK,
        p: *mut libc::c_void,
        where_0: size_t,
    ) -> size_t;
    fn OPENSSL_sk_delete(sk: *mut OPENSSL_STACK, where_0: size_t) -> *mut libc::c_void;
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_contains_zero_byte(cbs: *const CBS) -> libc::c_int;
    fn CBS_copy_bytes(cbs: *mut CBS, out: *mut uint8_t, len: size_t) -> libc::c_int;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn ERR_add_error_data(count: libc::c_uint, _: ...);
    fn OBJ_dup(obj: *const ASN1_OBJECT) -> *mut ASN1_OBJECT;
    fn OBJ_cmp(a: *const ASN1_OBJECT, b: *const ASN1_OBJECT) -> libc::c_int;
    fn OBJ_obj2nid(obj: *const ASN1_OBJECT) -> libc::c_int;
    fn OBJ_nid2obj(nid: libc::c_int) -> *mut ASN1_OBJECT;
    fn OBJ_txt2obj(
        s: *const libc::c_char,
        dont_search_names: libc::c_int,
    ) -> *mut ASN1_OBJECT;
}
pub type size_t = libc::c_ulong;
pub type ptrdiff_t = libc::c_long;
pub type __uint8_t = libc::c_uchar;
pub type uint8_t = __uint8_t;
pub type ossl_ssize_t = ptrdiff_t;
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
pub type ASN1_STRING = asn1_string_st;
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
pub struct X509_name_entry_st {
    pub object: *mut ASN1_OBJECT,
    pub value: *mut ASN1_STRING,
    pub set: libc::c_int,
}
pub type X509_NAME_ENTRY = X509_name_entry_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cbs_st {
    pub data: *const uint8_t,
    pub len: size_t,
}
pub type CBS = cbs_st;
pub type OPENSSL_STACK = stack_st;
#[inline]
unsafe extern "C" fn sk_X509_NAME_ENTRY_num(
    mut sk: *const stack_st_X509_NAME_ENTRY,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_NAME_ENTRY_value(
    mut sk: *const stack_st_X509_NAME_ENTRY,
    mut i: size_t,
) -> *mut X509_NAME_ENTRY {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509_NAME_ENTRY;
}
#[inline]
unsafe extern "C" fn sk_X509_NAME_ENTRY_insert(
    mut sk: *mut stack_st_X509_NAME_ENTRY,
    mut p: *mut X509_NAME_ENTRY,
    mut where_0: size_t,
) -> size_t {
    return OPENSSL_sk_insert(sk as *mut OPENSSL_STACK, p as *mut libc::c_void, where_0);
}
#[inline]
unsafe extern "C" fn sk_X509_NAME_ENTRY_delete(
    mut sk: *mut stack_st_X509_NAME_ENTRY,
    mut where_0: size_t,
) -> *mut X509_NAME_ENTRY {
    return OPENSSL_sk_delete(sk as *mut OPENSSL_STACK, where_0) as *mut X509_NAME_ENTRY;
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_get_text_by_NID(
    mut name: *const X509_NAME,
    mut nid: libc::c_int,
    mut buf: *mut libc::c_char,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut obj: *const ASN1_OBJECT = 0 as *const ASN1_OBJECT;
    obj = OBJ_nid2obj(nid);
    if obj.is_null() {
        return -(1 as libc::c_int);
    }
    return X509_NAME_get_text_by_OBJ(name, obj, buf, len);
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_get_text_by_OBJ(
    mut name: *const X509_NAME,
    mut obj: *const ASN1_OBJECT,
    mut buf: *mut libc::c_char,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut current_block: u64;
    let mut i: libc::c_int = X509_NAME_get_index_by_OBJ(name, obj, -(1 as libc::c_int));
    if i < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    let mut data: *const ASN1_STRING = X509_NAME_ENTRY_get_data(
        X509_NAME_get_entry(name, i),
    );
    let mut text: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut text_len: libc::c_int = ASN1_STRING_to_UTF8(&mut text, data);
    if !(text_len < 0 as libc::c_int) {
        cbs = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        CBS_init(&mut cbs, text, text_len as size_t);
        if !(CBS_contains_zero_byte(&mut cbs) != 0) {
            if !buf.is_null() {
                if text_len >= len || len <= 0 as libc::c_int
                    || CBS_copy_bytes(&mut cbs, buf as *mut uint8_t, text_len as size_t)
                        == 0
                {
                    current_block = 2556517726480230680;
                } else {
                    *buf.offset(text_len as isize) = '\0' as i32 as libc::c_char;
                    current_block = 13536709405535804910;
                }
            } else {
                current_block = 13536709405535804910;
            }
            match current_block {
                2556517726480230680 => {}
                _ => {
                    ret = text_len;
                }
            }
        }
    }
    OPENSSL_free(text as *mut libc::c_void);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_entry_count(
    mut name: *const X509_NAME,
) -> libc::c_int {
    if name.is_null() {
        return 0 as libc::c_int;
    }
    return sk_X509_NAME_ENTRY_num((*name).entries) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_get_index_by_NID(
    mut name: *const X509_NAME,
    mut nid: libc::c_int,
    mut lastpos: libc::c_int,
) -> libc::c_int {
    let mut obj: *const ASN1_OBJECT = 0 as *const ASN1_OBJECT;
    obj = OBJ_nid2obj(nid);
    if obj.is_null() {
        return -(2 as libc::c_int);
    }
    return X509_NAME_get_index_by_OBJ(name, obj, lastpos);
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_get_index_by_OBJ(
    mut name: *const X509_NAME,
    mut obj: *const ASN1_OBJECT,
    mut lastpos: libc::c_int,
) -> libc::c_int {
    if name.is_null() {
        return -(1 as libc::c_int);
    }
    if lastpos < 0 as libc::c_int {
        lastpos = -(1 as libc::c_int);
    }
    let mut sk: *const stack_st_X509_NAME_ENTRY = (*name).entries;
    let mut n: libc::c_int = sk_X509_NAME_ENTRY_num(sk) as libc::c_int;
    lastpos += 1;
    lastpos;
    while lastpos < n {
        let mut ne: *const X509_NAME_ENTRY = sk_X509_NAME_ENTRY_value(
            sk,
            lastpos as size_t,
        );
        if OBJ_cmp((*ne).object, obj) == 0 as libc::c_int {
            return lastpos;
        }
        lastpos += 1;
        lastpos;
    }
    return -(1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_get_entry(
    mut name: *const X509_NAME,
    mut loc: libc::c_int,
) -> *mut X509_NAME_ENTRY {
    if name.is_null() || loc < 0 as libc::c_int
        || sk_X509_NAME_ENTRY_num((*name).entries) <= loc as size_t
    {
        return 0 as *mut X509_NAME_ENTRY
    } else {
        return sk_X509_NAME_ENTRY_value((*name).entries, loc as size_t)
    };
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_delete_entry(
    mut name: *mut X509_NAME,
    mut loc: libc::c_int,
) -> *mut X509_NAME_ENTRY {
    if name.is_null() || loc < 0 as libc::c_int
        || sk_X509_NAME_ENTRY_num((*name).entries) <= loc as size_t
    {
        return 0 as *mut X509_NAME_ENTRY;
    }
    let mut sk: *mut stack_st_X509_NAME_ENTRY = (*name).entries;
    let mut ret: *mut X509_NAME_ENTRY = sk_X509_NAME_ENTRY_delete(sk, loc as size_t);
    let mut n: size_t = sk_X509_NAME_ENTRY_num(sk);
    (*name).modified = 1 as libc::c_int;
    if loc as size_t == n {
        return ret;
    }
    let mut set_prev: libc::c_int = 0;
    if loc != 0 as libc::c_int {
        set_prev = (*sk_X509_NAME_ENTRY_value(sk, (loc - 1 as libc::c_int) as size_t))
            .set;
    } else {
        set_prev = (*ret).set - 1 as libc::c_int;
    }
    let mut set_next: libc::c_int = (*sk_X509_NAME_ENTRY_value(sk, loc as size_t)).set;
    if (set_prev + 1 as libc::c_int) < set_next {
        let mut i: size_t = loc as size_t;
        while i < n {
            let ref mut fresh0 = (*sk_X509_NAME_ENTRY_value(sk, i)).set;
            *fresh0 -= 1;
            *fresh0;
            i = i.wrapping_add(1);
            i;
        }
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_add_entry_by_OBJ(
    mut name: *mut X509_NAME,
    mut obj: *const ASN1_OBJECT,
    mut type_0: libc::c_int,
    mut bytes: *const libc::c_uchar,
    mut len: ossl_ssize_t,
    mut loc: libc::c_int,
    mut set: libc::c_int,
) -> libc::c_int {
    let mut ne: *mut X509_NAME_ENTRY = X509_NAME_ENTRY_create_by_OBJ(
        0 as *mut *mut X509_NAME_ENTRY,
        obj,
        type_0,
        bytes,
        len,
    );
    if ne.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = X509_NAME_add_entry(name, ne, loc, set);
    X509_NAME_ENTRY_free(ne);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_add_entry_by_NID(
    mut name: *mut X509_NAME,
    mut nid: libc::c_int,
    mut type_0: libc::c_int,
    mut bytes: *const libc::c_uchar,
    mut len: ossl_ssize_t,
    mut loc: libc::c_int,
    mut set: libc::c_int,
) -> libc::c_int {
    let mut ne: *mut X509_NAME_ENTRY = X509_NAME_ENTRY_create_by_NID(
        0 as *mut *mut X509_NAME_ENTRY,
        nid,
        type_0,
        bytes,
        len,
    );
    if ne.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = X509_NAME_add_entry(name, ne, loc, set);
    X509_NAME_ENTRY_free(ne);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_add_entry_by_txt(
    mut name: *mut X509_NAME,
    mut field: *const libc::c_char,
    mut type_0: libc::c_int,
    mut bytes: *const libc::c_uchar,
    mut len: ossl_ssize_t,
    mut loc: libc::c_int,
    mut set: libc::c_int,
) -> libc::c_int {
    let mut ne: *mut X509_NAME_ENTRY = X509_NAME_ENTRY_create_by_txt(
        0 as *mut *mut X509_NAME_ENTRY,
        field,
        type_0,
        bytes,
        len,
    );
    if ne.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = X509_NAME_add_entry(name, ne, loc, set);
    X509_NAME_ENTRY_free(ne);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_add_entry(
    mut name: *mut X509_NAME,
    mut entry: *const X509_NAME_ENTRY,
    mut loc: libc::c_int,
    mut set: libc::c_int,
) -> libc::c_int {
    let mut new_name: *mut X509_NAME_ENTRY = 0 as *mut X509_NAME_ENTRY;
    let mut i: libc::c_int = 0;
    let mut inc: libc::c_int = 0;
    let mut sk: *mut stack_st_X509_NAME_ENTRY = 0 as *mut stack_st_X509_NAME_ENTRY;
    if name.is_null() {
        return 0 as libc::c_int;
    }
    sk = (*name).entries;
    let mut n: libc::c_int = sk_X509_NAME_ENTRY_num(sk) as libc::c_int;
    if loc > n {
        loc = n;
    } else if loc < 0 as libc::c_int {
        loc = n;
    }
    inc = (set == 0 as libc::c_int) as libc::c_int;
    (*name).modified = 1 as libc::c_int;
    if set == -(1 as libc::c_int) {
        if loc == 0 as libc::c_int {
            set = 0 as libc::c_int;
            inc = 1 as libc::c_int;
        } else {
            set = (*sk_X509_NAME_ENTRY_value(sk, (loc - 1 as libc::c_int) as size_t))
                .set;
        }
    } else if loc >= n {
        if loc != 0 as libc::c_int {
            set = (*sk_X509_NAME_ENTRY_value(sk, (loc - 1 as libc::c_int) as size_t)).set
                + 1 as libc::c_int;
        } else {
            set = 0 as libc::c_int;
        }
    } else {
        set = (*sk_X509_NAME_ENTRY_value(sk, loc as size_t)).set;
    }
    new_name = X509_NAME_ENTRY_dup(entry);
    if !new_name.is_null() {
        (*new_name).set = set;
        if !(sk_X509_NAME_ENTRY_insert(sk, new_name, loc as size_t) == 0) {
            if inc != 0 {
                n = sk_X509_NAME_ENTRY_num(sk) as libc::c_int;
                i = loc + 1 as libc::c_int;
                while i < n {
                    (*sk_X509_NAME_ENTRY_value(sk, i as size_t)).set += 1 as libc::c_int;
                    i += 1;
                    i;
                }
            }
            return 1 as libc::c_int;
        }
    }
    if !new_name.is_null() {
        X509_NAME_ENTRY_free(new_name);
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_ENTRY_create_by_txt(
    mut ne: *mut *mut X509_NAME_ENTRY,
    mut field: *const libc::c_char,
    mut type_0: libc::c_int,
    mut bytes: *const libc::c_uchar,
    mut len: ossl_ssize_t,
) -> *mut X509_NAME_ENTRY {
    let mut obj: *mut ASN1_OBJECT = 0 as *mut ASN1_OBJECT;
    let mut nentry: *mut X509_NAME_ENTRY = 0 as *mut X509_NAME_ENTRY;
    obj = OBJ_txt2obj(field, 0 as libc::c_int);
    if obj.is_null() {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            111 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509name.c\0" as *const u8
                as *const libc::c_char,
            309 as libc::c_int as libc::c_uint,
        );
        ERR_add_error_data(
            2 as libc::c_int as libc::c_uint,
            b"name=\0" as *const u8 as *const libc::c_char,
            field,
        );
        return 0 as *mut X509_NAME_ENTRY;
    }
    nentry = X509_NAME_ENTRY_create_by_OBJ(ne, obj, type_0, bytes, len);
    ASN1_OBJECT_free(obj);
    return nentry;
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_ENTRY_create_by_NID(
    mut ne: *mut *mut X509_NAME_ENTRY,
    mut nid: libc::c_int,
    mut type_0: libc::c_int,
    mut bytes: *const libc::c_uchar,
    mut len: ossl_ssize_t,
) -> *mut X509_NAME_ENTRY {
    let mut obj: *const ASN1_OBJECT = OBJ_nid2obj(nid);
    if obj.is_null() {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            129 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509name.c\0" as *const u8
                as *const libc::c_char,
            324 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut X509_NAME_ENTRY;
    }
    return X509_NAME_ENTRY_create_by_OBJ(ne, obj, type_0, bytes, len);
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_ENTRY_create_by_OBJ(
    mut ne: *mut *mut X509_NAME_ENTRY,
    mut obj: *const ASN1_OBJECT,
    mut type_0: libc::c_int,
    mut bytes: *const libc::c_uchar,
    mut len: ossl_ssize_t,
) -> *mut X509_NAME_ENTRY {
    let mut ret: *mut X509_NAME_ENTRY = 0 as *mut X509_NAME_ENTRY;
    if ne.is_null() || (*ne).is_null() {
        ret = X509_NAME_ENTRY_new();
        if ret.is_null() {
            return 0 as *mut X509_NAME_ENTRY;
        }
    } else {
        ret = *ne;
    }
    if !(X509_NAME_ENTRY_set_object(ret, obj) == 0) {
        if !(X509_NAME_ENTRY_set_data(ret, type_0, bytes, len) == 0) {
            if !ne.is_null() && (*ne).is_null() {
                *ne = ret;
            }
            return ret;
        }
    }
    if ne.is_null() || ret != *ne {
        X509_NAME_ENTRY_free(ret);
    }
    return 0 as *mut X509_NAME_ENTRY;
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_ENTRY_set_object(
    mut ne: *mut X509_NAME_ENTRY,
    mut obj: *const ASN1_OBJECT,
) -> libc::c_int {
    if ne.is_null() || obj.is_null() {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509name.c\0" as *const u8
                as *const libc::c_char,
            364 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    ASN1_OBJECT_free((*ne).object);
    (*ne).object = OBJ_dup(obj);
    return if ((*ne).object).is_null() { 0 as libc::c_int } else { 1 as libc::c_int };
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_ENTRY_set_data(
    mut ne: *mut X509_NAME_ENTRY,
    mut type_0: libc::c_int,
    mut bytes: *const libc::c_uchar,
    mut len: ossl_ssize_t,
) -> libc::c_int {
    if ne.is_null() || bytes.is_null() && len != 0 as libc::c_int as ossl_ssize_t {
        return 0 as libc::c_int;
    }
    if type_0 > 0 as libc::c_int && type_0 & 0x1000 as libc::c_int != 0 {
        return if !(ASN1_STRING_set_by_NID(
            &mut (*ne).value,
            bytes,
            len,
            type_0,
            OBJ_obj2nid((*ne).object),
        ))
            .is_null()
        {
            1 as libc::c_int
        } else {
            0 as libc::c_int
        };
    }
    if len < 0 as libc::c_int as ossl_ssize_t {
        len = strlen(bytes as *const libc::c_char) as ossl_ssize_t;
    }
    if ASN1_STRING_set((*ne).value, bytes as *const libc::c_void, len) == 0 {
        return 0 as libc::c_int;
    }
    if type_0 != -(1 as libc::c_int) {
        (*(*ne).value).type_0 = type_0;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_ENTRY_get_object(
    mut ne: *const X509_NAME_ENTRY,
) -> *mut ASN1_OBJECT {
    if ne.is_null() {
        return 0 as *mut ASN1_OBJECT;
    }
    return (*ne).object;
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_ENTRY_get_data(
    mut ne: *const X509_NAME_ENTRY,
) -> *mut ASN1_STRING {
    if ne.is_null() {
        return 0 as *mut ASN1_STRING;
    }
    return (*ne).value;
}
