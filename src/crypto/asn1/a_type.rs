#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(extern_types, label_break_value)]
extern "C" {
    pub type ASN1_VALUE_st;
    fn ASN1_STRING_free(str: *mut ASN1_STRING);
    fn ASN1_STRING_dup(str: *const ASN1_STRING) -> *mut ASN1_STRING;
    fn ASN1_STRING_cmp(a: *const ASN1_STRING, b: *const ASN1_STRING) -> libc::c_int;
    fn ASN1_OBJECT_free(a: *mut ASN1_OBJECT);
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn OBJ_dup(obj: *const ASN1_OBJECT) -> *mut ASN1_OBJECT;
    fn OBJ_cmp(a: *const ASN1_OBJECT, b: *const ASN1_OBJECT) -> libc::c_int;
}
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
#[no_mangle]
pub unsafe extern "C" fn ASN1_TYPE_get(mut a: *const ASN1_TYPE) -> libc::c_int {
    match (*a).type_0 {
        5 | 1 => return (*a).type_0,
        6 => {
            return if !((*a).value.object).is_null() {
                (*a).type_0
            } else {
                0 as libc::c_int
            };
        }
        _ => {
            return if !((*a).value.asn1_string).is_null() {
                (*a).type_0
            } else {
                0 as libc::c_int
            };
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn asn1_type_value_as_pointer(
    mut a: *const ASN1_TYPE,
) -> *const libc::c_void {
    match (*a).type_0 {
        5 => return 0 as *const libc::c_void,
        1 => {
            return if (*a).value.boolean != 0 {
                0xff as libc::c_int as *mut libc::c_void
            } else {
                0 as *mut libc::c_void
            };
        }
        6 => return (*a).value.object as *const libc::c_void,
        _ => return (*a).value.asn1_string as *const libc::c_void,
    };
}
#[no_mangle]
pub unsafe extern "C" fn asn1_type_set0_string(
    mut a: *mut ASN1_TYPE,
    mut str: *mut ASN1_STRING,
) {
    let mut type_0: libc::c_int = (*str).type_0;
    if type_0 == 2 as libc::c_int | 0x100 as libc::c_int {
        type_0 = 2 as libc::c_int;
    } else if type_0 == 10 as libc::c_int | 0x100 as libc::c_int {
        type_0 = 10 as libc::c_int;
    }
    if type_0 != 5 as libc::c_int && type_0 != 6 as libc::c_int
        && type_0 != 1 as libc::c_int
    {} else {
        __assert_fail(
            b"type != V_ASN1_NULL && type != V_ASN1_OBJECT && type != V_ASN1_BOOLEAN\0"
                as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_type.c\0" as *const u8
                as *const libc::c_char,
            106 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 55],
                &[libc::c_char; 55],
            >(b"void asn1_type_set0_string(ASN1_TYPE *, ASN1_STRING *)\0"))
                .as_ptr(),
        );
    }
    'c_12977: {
        if type_0 != 5 as libc::c_int && type_0 != 6 as libc::c_int
            && type_0 != 1 as libc::c_int
        {} else {
            __assert_fail(
                b"type != V_ASN1_NULL && type != V_ASN1_OBJECT && type != V_ASN1_BOOLEAN\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_type.c\0" as *const u8
                    as *const libc::c_char,
                106 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 55],
                    &[libc::c_char; 55],
                >(b"void asn1_type_set0_string(ASN1_TYPE *, ASN1_STRING *)\0"))
                    .as_ptr(),
            );
        }
    };
    ASN1_TYPE_set(a, type_0, str as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn asn1_type_cleanup(mut a: *mut ASN1_TYPE) {
    match (*a).type_0 {
        5 => {
            (*a).value.ptr = 0 as *mut libc::c_char;
        }
        1 => {
            (*a).value.boolean = -(1 as libc::c_int);
        }
        6 => {
            ASN1_OBJECT_free((*a).value.object);
            (*a).value.object = 0 as *mut ASN1_OBJECT;
        }
        _ => {
            ASN1_STRING_free((*a).value.asn1_string);
            (*a).value.asn1_string = 0 as *mut ASN1_STRING;
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_TYPE_set(
    mut a: *mut ASN1_TYPE,
    mut type_0: libc::c_int,
    mut value: *mut libc::c_void,
) {
    asn1_type_cleanup(a);
    (*a).type_0 = type_0;
    match type_0 {
        5 => {
            (*a).value.ptr = 0 as *mut libc::c_char;
        }
        1 => {
            (*a)
                .value
                .boolean = if !value.is_null() {
                0xff as libc::c_int
            } else {
                0 as libc::c_int
            };
        }
        6 => {
            (*a).value.object = value as *mut ASN1_OBJECT;
        }
        _ => {
            (*a).value.asn1_string = value as *mut ASN1_STRING;
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_TYPE_set1(
    mut a: *mut ASN1_TYPE,
    mut type_0: libc::c_int,
    mut value: *const libc::c_void,
) -> libc::c_int {
    if value.is_null() || type_0 == 1 as libc::c_int {
        let mut p: *mut libc::c_void = value as *mut libc::c_void;
        ASN1_TYPE_set(a, type_0, p);
    } else if type_0 == 6 as libc::c_int {
        let mut odup: *mut ASN1_OBJECT = 0 as *mut ASN1_OBJECT;
        odup = OBJ_dup(value as *const ASN1_OBJECT);
        if odup.is_null() {
            return 0 as libc::c_int;
        }
        ASN1_TYPE_set(a, type_0, odup as *mut libc::c_void);
    } else {
        let mut sdup: *mut ASN1_STRING = 0 as *mut ASN1_STRING;
        sdup = ASN1_STRING_dup(value as *const ASN1_STRING);
        if sdup.is_null() {
            return 0 as libc::c_int;
        }
        ASN1_TYPE_set(a, type_0, sdup as *mut libc::c_void);
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_TYPE_cmp(
    mut a: *const ASN1_TYPE,
    mut b: *const ASN1_TYPE,
) -> libc::c_int {
    let mut result: libc::c_int = -(1 as libc::c_int);
    if a.is_null() || b.is_null() || (*a).type_0 != (*b).type_0 {
        return -(1 as libc::c_int);
    }
    match (*a).type_0 {
        6 => {
            result = OBJ_cmp((*a).value.object, (*b).value.object);
        }
        5 => {
            result = 0 as libc::c_int;
        }
        1 => {
            result = (*a).value.boolean - (*b).value.boolean;
        }
        2 | 10 | 3 | 4 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28
        | 30 | 12 | -3 | _ => {
            result = ASN1_STRING_cmp((*a).value.asn1_string, (*b).value.asn1_string);
        }
    }
    return result;
}
