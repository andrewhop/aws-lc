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
    pub type asn1_null_st;
    pub type asn1_object_st;
    pub type ASN1_VALUE_st;
    pub type stack_st_ASN1_TYPE;
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
    fn ASN1_STRING_type_new(type_0: libc::c_int) -> *mut ASN1_STRING;
    fn ASN1_STRING_free(str: *mut ASN1_STRING);
}
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type ASN1_NULL = asn1_null_st;
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
pub type ASN1_SEQUENCE_ANY = stack_st_ASN1_TYPE;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_OCTET_STRING_free(mut x: *mut ASN1_OCTET_STRING) {
    ASN1_STRING_free(x);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ASN1_OCTET_STRING(
    mut a: *const ASN1_OCTET_STRING,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &ASN1_OCTET_STRING_it);
}
#[unsafe(no_mangle)]
pub static mut ASN1_OCTET_STRING_it: ASN1_ITEM = {
    let mut init = ASN1_ITEM_st {
        itype: 0 as libc::c_int as libc::c_char,
        utype: 4 as libc::c_int,
        templates: 0 as *const ASN1_TEMPLATE,
        tcount: 0 as libc::c_int as libc::c_long,
        funcs: 0 as *const libc::c_void,
        size: 0 as libc::c_int as libc::c_long,
        sname: b"ASN1_OCTET_STRING\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_OCTET_STRING_new() -> *mut ASN1_OCTET_STRING {
    return ASN1_STRING_type_new(4 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ASN1_OCTET_STRING(
    mut a: *mut *mut ASN1_OCTET_STRING,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_OCTET_STRING {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &ASN1_OCTET_STRING_it)
        as *mut ASN1_OCTET_STRING;
}
#[unsafe(no_mangle)]
pub static mut ASN1_INTEGER_it: ASN1_ITEM = {
    let mut init = ASN1_ITEM_st {
        itype: 0 as libc::c_int as libc::c_char,
        utype: 2 as libc::c_int,
        templates: 0 as *const ASN1_TEMPLATE,
        tcount: 0 as libc::c_int as libc::c_long,
        funcs: 0 as *const libc::c_void,
        size: 0 as libc::c_int as libc::c_long,
        sname: b"ASN1_INTEGER\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ASN1_INTEGER(
    mut a: *const ASN1_INTEGER,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &ASN1_INTEGER_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_INTEGER_free(mut x: *mut ASN1_INTEGER) {
    ASN1_STRING_free(x);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_INTEGER_new() -> *mut ASN1_INTEGER {
    return ASN1_STRING_type_new(2 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ASN1_INTEGER(
    mut a: *mut *mut ASN1_INTEGER,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_INTEGER {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &ASN1_INTEGER_it)
        as *mut ASN1_INTEGER;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_ENUMERATED_free(mut x: *mut ASN1_ENUMERATED) {
    ASN1_STRING_free(x);
}
#[unsafe(no_mangle)]
pub static mut ASN1_ENUMERATED_it: ASN1_ITEM = {
    let mut init = ASN1_ITEM_st {
        itype: 0 as libc::c_int as libc::c_char,
        utype: 10 as libc::c_int,
        templates: 0 as *const ASN1_TEMPLATE,
        tcount: 0 as libc::c_int as libc::c_long,
        funcs: 0 as *const libc::c_void,
        size: 0 as libc::c_int as libc::c_long,
        sname: b"ASN1_ENUMERATED\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ASN1_ENUMERATED(
    mut a: *const ASN1_ENUMERATED,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &ASN1_ENUMERATED_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_ENUMERATED_new() -> *mut ASN1_ENUMERATED {
    return ASN1_STRING_type_new(10 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ASN1_ENUMERATED(
    mut a: *mut *mut ASN1_ENUMERATED,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_ENUMERATED {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &ASN1_ENUMERATED_it)
        as *mut ASN1_ENUMERATED;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_BIT_STRING_free(mut x: *mut ASN1_BIT_STRING) {
    ASN1_STRING_free(x);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ASN1_BIT_STRING(
    mut a: *const ASN1_BIT_STRING,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &ASN1_BIT_STRING_it);
}
#[unsafe(no_mangle)]
pub static mut ASN1_BIT_STRING_it: ASN1_ITEM = {
    let mut init = ASN1_ITEM_st {
        itype: 0 as libc::c_int as libc::c_char,
        utype: 3 as libc::c_int,
        templates: 0 as *const ASN1_TEMPLATE,
        tcount: 0 as libc::c_int as libc::c_long,
        funcs: 0 as *const libc::c_void,
        size: 0 as libc::c_int as libc::c_long,
        sname: b"ASN1_BIT_STRING\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_BIT_STRING_new() -> *mut ASN1_BIT_STRING {
    return ASN1_STRING_type_new(3 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ASN1_BIT_STRING(
    mut a: *mut *mut ASN1_BIT_STRING,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_BIT_STRING {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &ASN1_BIT_STRING_it)
        as *mut ASN1_BIT_STRING;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ASN1_UTF8STRING(
    mut a: *const ASN1_UTF8STRING,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &ASN1_UTF8STRING_it);
}
#[unsafe(no_mangle)]
pub static mut ASN1_UTF8STRING_it: ASN1_ITEM = {
    let mut init = ASN1_ITEM_st {
        itype: 0 as libc::c_int as libc::c_char,
        utype: 12 as libc::c_int,
        templates: 0 as *const ASN1_TEMPLATE,
        tcount: 0 as libc::c_int as libc::c_long,
        funcs: 0 as *const libc::c_void,
        size: 0 as libc::c_int as libc::c_long,
        sname: b"ASN1_UTF8STRING\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_UTF8STRING_free(mut x: *mut ASN1_UTF8STRING) {
    ASN1_STRING_free(x);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ASN1_UTF8STRING(
    mut a: *mut *mut ASN1_UTF8STRING,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_UTF8STRING {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &ASN1_UTF8STRING_it)
        as *mut ASN1_UTF8STRING;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_UTF8STRING_new() -> *mut ASN1_UTF8STRING {
    return ASN1_STRING_type_new(12 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ASN1_PRINTABLESTRING(
    mut a: *const ASN1_PRINTABLESTRING,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &ASN1_PRINTABLESTRING_it);
}
#[unsafe(no_mangle)]
pub static mut ASN1_PRINTABLESTRING_it: ASN1_ITEM = {
    let mut init = ASN1_ITEM_st {
        itype: 0 as libc::c_int as libc::c_char,
        utype: 19 as libc::c_int,
        templates: 0 as *const ASN1_TEMPLATE,
        tcount: 0 as libc::c_int as libc::c_long,
        funcs: 0 as *const libc::c_void,
        size: 0 as libc::c_int as libc::c_long,
        sname: b"ASN1_PRINTABLESTRING\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_PRINTABLESTRING_free(mut x: *mut ASN1_PRINTABLESTRING) {
    ASN1_STRING_free(x);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ASN1_PRINTABLESTRING(
    mut a: *mut *mut ASN1_PRINTABLESTRING,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_PRINTABLESTRING {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &ASN1_PRINTABLESTRING_it)
        as *mut ASN1_PRINTABLESTRING;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_PRINTABLESTRING_new() -> *mut ASN1_PRINTABLESTRING {
    return ASN1_STRING_type_new(19 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ASN1_T61STRING(
    mut a: *const ASN1_T61STRING,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &ASN1_T61STRING_it);
}
#[unsafe(no_mangle)]
pub static mut ASN1_T61STRING_it: ASN1_ITEM = {
    let mut init = ASN1_ITEM_st {
        itype: 0 as libc::c_int as libc::c_char,
        utype: 20 as libc::c_int,
        templates: 0 as *const ASN1_TEMPLATE,
        tcount: 0 as libc::c_int as libc::c_long,
        funcs: 0 as *const libc::c_void,
        size: 0 as libc::c_int as libc::c_long,
        sname: b"ASN1_T61STRING\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_T61STRING_free(mut x: *mut ASN1_T61STRING) {
    ASN1_STRING_free(x);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_T61STRING_new() -> *mut ASN1_T61STRING {
    return ASN1_STRING_type_new(20 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ASN1_T61STRING(
    mut a: *mut *mut ASN1_T61STRING,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_T61STRING {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &ASN1_T61STRING_it)
        as *mut ASN1_T61STRING;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_IA5STRING_free(mut x: *mut ASN1_IA5STRING) {
    ASN1_STRING_free(x);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ASN1_IA5STRING(
    mut a: *const ASN1_IA5STRING,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &ASN1_IA5STRING_it);
}
#[unsafe(no_mangle)]
pub static mut ASN1_IA5STRING_it: ASN1_ITEM = {
    let mut init = ASN1_ITEM_st {
        itype: 0 as libc::c_int as libc::c_char,
        utype: 22 as libc::c_int,
        templates: 0 as *const ASN1_TEMPLATE,
        tcount: 0 as libc::c_int as libc::c_long,
        funcs: 0 as *const libc::c_void,
        size: 0 as libc::c_int as libc::c_long,
        sname: b"ASN1_IA5STRING\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ASN1_IA5STRING(
    mut a: *mut *mut ASN1_IA5STRING,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_IA5STRING {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &ASN1_IA5STRING_it)
        as *mut ASN1_IA5STRING;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_IA5STRING_new() -> *mut ASN1_IA5STRING {
    return ASN1_STRING_type_new(22 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ASN1_GENERALSTRING(
    mut a: *const ASN1_GENERALSTRING,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &ASN1_GENERALSTRING_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_GENERALSTRING_free(mut x: *mut ASN1_GENERALSTRING) {
    ASN1_STRING_free(x);
}
#[unsafe(no_mangle)]
pub static mut ASN1_GENERALSTRING_it: ASN1_ITEM = {
    let mut init = ASN1_ITEM_st {
        itype: 0 as libc::c_int as libc::c_char,
        utype: 27 as libc::c_int,
        templates: 0 as *const ASN1_TEMPLATE,
        tcount: 0 as libc::c_int as libc::c_long,
        funcs: 0 as *const libc::c_void,
        size: 0 as libc::c_int as libc::c_long,
        sname: b"ASN1_GENERALSTRING\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_GENERALSTRING_new() -> *mut ASN1_GENERALSTRING {
    return ASN1_STRING_type_new(27 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ASN1_GENERALSTRING(
    mut a: *mut *mut ASN1_GENERALSTRING,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_GENERALSTRING {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &ASN1_GENERALSTRING_it)
        as *mut ASN1_GENERALSTRING;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ASN1_UTCTIME(
    mut a: *const ASN1_UTCTIME,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &ASN1_UTCTIME_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_UTCTIME_free(mut x: *mut ASN1_UTCTIME) {
    ASN1_STRING_free(x);
}
#[unsafe(no_mangle)]
pub static mut ASN1_UTCTIME_it: ASN1_ITEM = {
    let mut init = ASN1_ITEM_st {
        itype: 0 as libc::c_int as libc::c_char,
        utype: 23 as libc::c_int,
        templates: 0 as *const ASN1_TEMPLATE,
        tcount: 0 as libc::c_int as libc::c_long,
        funcs: 0 as *const libc::c_void,
        size: 0 as libc::c_int as libc::c_long,
        sname: b"ASN1_UTCTIME\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_UTCTIME_new() -> *mut ASN1_UTCTIME {
    return ASN1_STRING_type_new(23 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ASN1_UTCTIME(
    mut a: *mut *mut ASN1_UTCTIME,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_UTCTIME {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &ASN1_UTCTIME_it)
        as *mut ASN1_UTCTIME;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_GENERALIZEDTIME_free(mut x: *mut ASN1_GENERALIZEDTIME) {
    ASN1_STRING_free(x);
}
#[unsafe(no_mangle)]
pub static mut ASN1_GENERALIZEDTIME_it: ASN1_ITEM = {
    let mut init = ASN1_ITEM_st {
        itype: 0 as libc::c_int as libc::c_char,
        utype: 24 as libc::c_int,
        templates: 0 as *const ASN1_TEMPLATE,
        tcount: 0 as libc::c_int as libc::c_long,
        funcs: 0 as *const libc::c_void,
        size: 0 as libc::c_int as libc::c_long,
        sname: b"ASN1_GENERALIZEDTIME\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ASN1_GENERALIZEDTIME(
    mut a: *const ASN1_GENERALIZEDTIME,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &ASN1_GENERALIZEDTIME_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ASN1_GENERALIZEDTIME(
    mut a: *mut *mut ASN1_GENERALIZEDTIME,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_GENERALIZEDTIME {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &ASN1_GENERALIZEDTIME_it)
        as *mut ASN1_GENERALIZEDTIME;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_GENERALIZEDTIME_new() -> *mut ASN1_GENERALIZEDTIME {
    return ASN1_STRING_type_new(24 as libc::c_int);
}
#[unsafe(no_mangle)]
pub static mut ASN1_VISIBLESTRING_it: ASN1_ITEM = {
    let mut init = ASN1_ITEM_st {
        itype: 0 as libc::c_int as libc::c_char,
        utype: 26 as libc::c_int,
        templates: 0 as *const ASN1_TEMPLATE,
        tcount: 0 as libc::c_int as libc::c_long,
        funcs: 0 as *const libc::c_void,
        size: 0 as libc::c_int as libc::c_long,
        sname: b"ASN1_VISIBLESTRING\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ASN1_VISIBLESTRING(
    mut a: *const ASN1_VISIBLESTRING,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &ASN1_VISIBLESTRING_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_VISIBLESTRING_free(mut x: *mut ASN1_VISIBLESTRING) {
    ASN1_STRING_free(x);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ASN1_VISIBLESTRING(
    mut a: *mut *mut ASN1_VISIBLESTRING,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_VISIBLESTRING {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &ASN1_VISIBLESTRING_it)
        as *mut ASN1_VISIBLESTRING;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_VISIBLESTRING_new() -> *mut ASN1_VISIBLESTRING {
    return ASN1_STRING_type_new(26 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ASN1_UNIVERSALSTRING(
    mut a: *const ASN1_UNIVERSALSTRING,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &ASN1_UNIVERSALSTRING_it);
}
#[unsafe(no_mangle)]
pub static mut ASN1_UNIVERSALSTRING_it: ASN1_ITEM = {
    let mut init = ASN1_ITEM_st {
        itype: 0 as libc::c_int as libc::c_char,
        utype: 28 as libc::c_int,
        templates: 0 as *const ASN1_TEMPLATE,
        tcount: 0 as libc::c_int as libc::c_long,
        funcs: 0 as *const libc::c_void,
        size: 0 as libc::c_int as libc::c_long,
        sname: b"ASN1_UNIVERSALSTRING\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_UNIVERSALSTRING_free(mut x: *mut ASN1_UNIVERSALSTRING) {
    ASN1_STRING_free(x);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ASN1_UNIVERSALSTRING(
    mut a: *mut *mut ASN1_UNIVERSALSTRING,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_UNIVERSALSTRING {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &ASN1_UNIVERSALSTRING_it)
        as *mut ASN1_UNIVERSALSTRING;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_UNIVERSALSTRING_new() -> *mut ASN1_UNIVERSALSTRING {
    return ASN1_STRING_type_new(28 as libc::c_int);
}
#[unsafe(no_mangle)]
pub static mut ASN1_BMPSTRING_it: ASN1_ITEM = {
    let mut init = ASN1_ITEM_st {
        itype: 0 as libc::c_int as libc::c_char,
        utype: 30 as libc::c_int,
        templates: 0 as *const ASN1_TEMPLATE,
        tcount: 0 as libc::c_int as libc::c_long,
        funcs: 0 as *const libc::c_void,
        size: 0 as libc::c_int as libc::c_long,
        sname: b"ASN1_BMPSTRING\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_BMPSTRING_free(mut x: *mut ASN1_BMPSTRING) {
    ASN1_STRING_free(x);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ASN1_BMPSTRING(
    mut a: *const ASN1_BMPSTRING,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &ASN1_BMPSTRING_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_BMPSTRING_new() -> *mut ASN1_BMPSTRING {
    return ASN1_STRING_type_new(30 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ASN1_BMPSTRING(
    mut a: *mut *mut ASN1_BMPSTRING,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_BMPSTRING {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &ASN1_BMPSTRING_it)
        as *mut ASN1_BMPSTRING;
}
#[unsafe(no_mangle)]
pub static mut ASN1_NULL_it: ASN1_ITEM = {
    let mut init = ASN1_ITEM_st {
        itype: 0 as libc::c_int as libc::c_char,
        utype: 5 as libc::c_int,
        templates: 0 as *const ASN1_TEMPLATE,
        tcount: 0 as libc::c_int as libc::c_long,
        funcs: 0 as *const libc::c_void,
        size: 0 as libc::c_int as libc::c_long,
        sname: b"ASN1_NULL\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ASN1_NULL(
    mut a: *const ASN1_NULL,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &ASN1_NULL_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_NULL_free(mut a: *mut ASN1_NULL) {
    ASN1_item_free(a as *mut ASN1_VALUE, &ASN1_NULL_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ASN1_NULL(
    mut a: *mut *mut ASN1_NULL,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_NULL {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &ASN1_NULL_it)
        as *mut ASN1_NULL;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_NULL_new() -> *mut ASN1_NULL {
    return ASN1_item_new(&ASN1_NULL_it) as *mut ASN1_NULL;
}
#[unsafe(no_mangle)]
pub static mut ASN1_OBJECT_it: ASN1_ITEM = {
    let mut init = ASN1_ITEM_st {
        itype: 0 as libc::c_int as libc::c_char,
        utype: 6 as libc::c_int,
        templates: 0 as *const ASN1_TEMPLATE,
        tcount: 0 as libc::c_int as libc::c_long,
        funcs: 0 as *const libc::c_void,
        size: 0 as libc::c_int as libc::c_long,
        sname: b"ASN1_OBJECT\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[unsafe(no_mangle)]
pub static mut ASN1_ANY_it: ASN1_ITEM = {
    let mut init = ASN1_ITEM_st {
        itype: 0 as libc::c_int as libc::c_char,
        utype: -(4 as libc::c_int),
        templates: 0 as *const ASN1_TEMPLATE,
        tcount: 0 as libc::c_int as libc::c_long,
        funcs: 0 as *const libc::c_void,
        size: 0 as libc::c_int as libc::c_long,
        sname: b"ASN1_ANY\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[unsafe(no_mangle)]
pub static mut ASN1_SEQUENCE_it: ASN1_ITEM = {
    let mut init = ASN1_ITEM_st {
        itype: 0 as libc::c_int as libc::c_char,
        utype: 16 as libc::c_int,
        templates: 0 as *const ASN1_TEMPLATE,
        tcount: 0 as libc::c_int as libc::c_long,
        funcs: 0 as *const libc::c_void,
        size: 0 as libc::c_int as libc::c_long,
        sname: b"ASN1_SEQUENCE\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ASN1_TYPE(
    mut a: *const ASN1_TYPE,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &ASN1_ANY_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_TYPE_free(mut a: *mut ASN1_TYPE) {
    ASN1_item_free(a as *mut ASN1_VALUE, &ASN1_ANY_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ASN1_TYPE(
    mut a: *mut *mut ASN1_TYPE,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_TYPE {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &ASN1_ANY_it)
        as *mut ASN1_TYPE;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_TYPE_new() -> *mut ASN1_TYPE {
    return ASN1_item_new(&ASN1_ANY_it) as *mut ASN1_TYPE;
}
#[unsafe(no_mangle)]
pub static mut ASN1_PRINTABLE_it: ASN1_ITEM = {
    let mut init = ASN1_ITEM_st {
        itype: 0x5 as libc::c_int as libc::c_char,
        utype: 0x1 as libc::c_int | 0x2 as libc::c_int | 0x4 as libc::c_int
            | 0x10 as libc::c_int | 0x400 as libc::c_int | 0x100 as libc::c_int
            | 0x800 as libc::c_int | 0x2000 as libc::c_int | 0x10000 as libc::c_int
            | 0x1000 as libc::c_int,
        templates: 0 as *const ASN1_TEMPLATE,
        tcount: 0 as libc::c_int as libc::c_long,
        funcs: 0 as *const libc::c_void,
        size: ::core::mem::size_of::<ASN1_STRING>() as libc::c_ulong as libc::c_long,
        sname: b"ASN1_PRINTABLE\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_PRINTABLE_free(mut a: *mut ASN1_STRING) {
    ASN1_item_free(a as *mut ASN1_VALUE, &ASN1_PRINTABLE_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ASN1_PRINTABLE(
    mut a: *const ASN1_STRING,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &ASN1_PRINTABLE_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_PRINTABLE_new() -> *mut ASN1_STRING {
    return ASN1_item_new(&ASN1_PRINTABLE_it) as *mut ASN1_STRING;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ASN1_PRINTABLE(
    mut a: *mut *mut ASN1_STRING,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_STRING {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &ASN1_PRINTABLE_it)
        as *mut ASN1_STRING;
}
#[unsafe(no_mangle)]
pub static mut DISPLAYTEXT_it: ASN1_ITEM = {
    let mut init = ASN1_ITEM_st {
        itype: 0x5 as libc::c_int as libc::c_char,
        utype: 0x10 as libc::c_int | 0x40 as libc::c_int | 0x800 as libc::c_int
            | 0x2000 as libc::c_int,
        templates: 0 as *const ASN1_TEMPLATE,
        tcount: 0 as libc::c_int as libc::c_long,
        funcs: 0 as *const libc::c_void,
        size: ::core::mem::size_of::<ASN1_STRING>() as libc::c_ulong as libc::c_long,
        sname: b"DISPLAYTEXT\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_DISPLAYTEXT(
    mut a: *const ASN1_STRING,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &DISPLAYTEXT_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DISPLAYTEXT_free(mut a: *mut ASN1_STRING) {
    ASN1_item_free(a as *mut ASN1_VALUE, &DISPLAYTEXT_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_DISPLAYTEXT(
    mut a: *mut *mut ASN1_STRING,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_STRING {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &DISPLAYTEXT_it)
        as *mut ASN1_STRING;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DISPLAYTEXT_new() -> *mut ASN1_STRING {
    return ASN1_item_new(&DISPLAYTEXT_it) as *mut ASN1_STRING;
}
#[unsafe(no_mangle)]
pub static mut DIRECTORYSTRING_it: ASN1_ITEM = {
    let mut init = ASN1_ITEM_st {
        itype: 0x5 as libc::c_int as libc::c_char,
        utype: 0x2 as libc::c_int | 0x4 as libc::c_int | 0x800 as libc::c_int
            | 0x100 as libc::c_int | 0x2000 as libc::c_int,
        templates: 0 as *const ASN1_TEMPLATE,
        tcount: 0 as libc::c_int as libc::c_long,
        funcs: 0 as *const libc::c_void,
        size: ::core::mem::size_of::<ASN1_STRING>() as libc::c_ulong as libc::c_long,
        sname: b"DIRECTORYSTRING\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DIRECTORYSTRING_free(mut a: *mut ASN1_STRING) {
    ASN1_item_free(a as *mut ASN1_VALUE, &DIRECTORYSTRING_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_DIRECTORYSTRING(
    mut a: *const ASN1_STRING,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &DIRECTORYSTRING_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_DIRECTORYSTRING(
    mut a: *mut *mut ASN1_STRING,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_STRING {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &DIRECTORYSTRING_it)
        as *mut ASN1_STRING;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DIRECTORYSTRING_new() -> *mut ASN1_STRING {
    return ASN1_item_new(&DIRECTORYSTRING_it) as *mut ASN1_STRING;
}
#[unsafe(no_mangle)]
pub static mut ASN1_BOOLEAN_it: ASN1_ITEM = {
    let mut init = ASN1_ITEM_st {
        itype: 0 as libc::c_int as libc::c_char,
        utype: 1 as libc::c_int,
        templates: 0 as *const ASN1_TEMPLATE,
        tcount: 0 as libc::c_int as libc::c_long,
        funcs: 0 as *const libc::c_void,
        size: -(1 as libc::c_int) as libc::c_long,
        sname: b"ASN1_BOOLEAN\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[unsafe(no_mangle)]
pub static mut ASN1_TBOOLEAN_it: ASN1_ITEM = {
    let mut init = ASN1_ITEM_st {
        itype: 0 as libc::c_int as libc::c_char,
        utype: 1 as libc::c_int,
        templates: 0 as *const ASN1_TEMPLATE,
        tcount: 0 as libc::c_int as libc::c_long,
        funcs: 0 as *const libc::c_void,
        size: 0xff as libc::c_int as libc::c_long,
        sname: b"ASN1_TBOOLEAN\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[unsafe(no_mangle)]
pub static mut ASN1_FBOOLEAN_it: ASN1_ITEM = {
    let mut init = ASN1_ITEM_st {
        itype: 0 as libc::c_int as libc::c_char,
        utype: 1 as libc::c_int,
        templates: 0 as *const ASN1_TEMPLATE,
        tcount: 0 as libc::c_int as libc::c_long,
        funcs: 0 as *const libc::c_void,
        size: 0 as libc::c_int as libc::c_long,
        sname: b"ASN1_FBOOLEAN\0" as *const u8 as *const libc::c_char,
    };
    init
};
static mut ASN1_SEQUENCE_ANY_item_tt: ASN1_TEMPLATE = unsafe {
    {
        let mut init = ASN1_TEMPLATE_st {
            flags: ((0x2 as libc::c_int) << 1 as libc::c_int) as uint32_t,
            tag: 0 as libc::c_int,
            offset: 0 as libc::c_int as libc::c_ulong,
            field_name: b"ASN1_SEQUENCE_ANY\0" as *const u8 as *const libc::c_char,
            item: &ASN1_ANY_it as *const ASN1_ITEM,
        };
        init
    }
};
#[unsafe(no_mangle)]
pub static mut ASN1_SEQUENCE_ANY_it: ASN1_ITEM = unsafe {
    {
        let mut init = ASN1_ITEM_st {
            itype: 0 as libc::c_int as libc::c_char,
            utype: -(1 as libc::c_int),
            templates: &ASN1_SEQUENCE_ANY_item_tt as *const ASN1_TEMPLATE,
            tcount: 0 as libc::c_int as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: 0 as libc::c_int as libc::c_long,
            sname: b"ASN1_SEQUENCE_ANY\0" as *const u8 as *const libc::c_char,
        };
        init
    }
};
static mut ASN1_SET_ANY_item_tt: ASN1_TEMPLATE = unsafe {
    {
        let mut init = ASN1_TEMPLATE_st {
            flags: ((0x1 as libc::c_int) << 1 as libc::c_int) as uint32_t,
            tag: 0 as libc::c_int,
            offset: 0 as libc::c_int as libc::c_ulong,
            field_name: b"ASN1_SET_ANY\0" as *const u8 as *const libc::c_char,
            item: &ASN1_ANY_it as *const ASN1_ITEM,
        };
        init
    }
};
#[unsafe(no_mangle)]
pub static mut ASN1_SET_ANY_it: ASN1_ITEM = unsafe {
    {
        let mut init = ASN1_ITEM_st {
            itype: 0 as libc::c_int as libc::c_char,
            utype: -(1 as libc::c_int),
            templates: &ASN1_SET_ANY_item_tt as *const ASN1_TEMPLATE,
            tcount: 0 as libc::c_int as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: 0 as libc::c_int as libc::c_long,
            sname: b"ASN1_SET_ANY\0" as *const u8 as *const libc::c_char,
        };
        init
    }
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ASN1_SEQUENCE_ANY(
    mut a: *const ASN1_SEQUENCE_ANY,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &ASN1_SEQUENCE_ANY_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ASN1_SEQUENCE_ANY(
    mut a: *mut *mut ASN1_SEQUENCE_ANY,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_SEQUENCE_ANY {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &ASN1_SEQUENCE_ANY_it)
        as *mut ASN1_SEQUENCE_ANY;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_ASN1_SET_ANY(
    mut a: *const ASN1_SEQUENCE_ANY,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &ASN1_SET_ANY_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_ASN1_SET_ANY(
    mut a: *mut *mut ASN1_SEQUENCE_ANY,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_SEQUENCE_ANY {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &ASN1_SET_ANY_it)
        as *mut ASN1_SEQUENCE_ANY;
}
