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
    pub type stack_st_ASN1_TYPE;
    pub type stack_st;
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
    fn ASN1_item_dup(it: *const ASN1_ITEM, x: *mut libc::c_void) -> *mut libc::c_void;
    static ASN1_OBJECT_it: ASN1_ITEM;
    fn ASN1_TYPE_new() -> *mut ASN1_TYPE;
    fn ASN1_TYPE_free(a: *mut ASN1_TYPE);
    static ASN1_ANY_it: ASN1_ITEM;
    fn ASN1_TYPE_set(a: *mut ASN1_TYPE, type_0: libc::c_int, value: *mut libc::c_void);
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn OBJ_nid2obj(nid: libc::c_int) -> *mut ASN1_OBJECT;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_attributes_st {
    pub object: *mut ASN1_OBJECT,
    pub set: *mut stack_st_ASN1_TYPE,
}
pub type X509_ATTRIBUTE = x509_attributes_st;
pub type OPENSSL_STACK = stack_st;
#[inline]
unsafe extern "C" fn sk_ASN1_TYPE_push(
    mut sk: *mut stack_st_ASN1_TYPE,
    mut p: *mut ASN1_TYPE,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
static mut X509_ATTRIBUTE_seq_tt: [ASN1_TEMPLATE; 2] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"object\0" as *const u8 as *const libc::c_char,
                item: &ASN1_OBJECT_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 1 as libc::c_int) as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"set\0" as *const u8 as *const libc::c_char,
                item: &ASN1_ANY_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[unsafe(no_mangle)]
pub static mut X509_ATTRIBUTE_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_X509_ATTRIBUTE(
    mut a: *const X509_ATTRIBUTE,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &X509_ATTRIBUTE_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_ATTRIBUTE_free(mut a: *mut X509_ATTRIBUTE) {
    ASN1_item_free(a as *mut ASN1_VALUE, &X509_ATTRIBUTE_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_X509_ATTRIBUTE(
    mut a: *mut *mut X509_ATTRIBUTE,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut X509_ATTRIBUTE {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &X509_ATTRIBUTE_it)
        as *mut X509_ATTRIBUTE;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_ATTRIBUTE_new() -> *mut X509_ATTRIBUTE {
    return ASN1_item_new(&X509_ATTRIBUTE_it) as *mut X509_ATTRIBUTE;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_ATTRIBUTE_dup(
    mut x: *const X509_ATTRIBUTE,
) -> *mut X509_ATTRIBUTE {
    return ASN1_item_dup(&X509_ATTRIBUTE_it, x as *mut libc::c_void)
        as *mut X509_ATTRIBUTE;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_ATTRIBUTE_create(
    mut nid: libc::c_int,
    mut attrtype: libc::c_int,
    mut value: *mut libc::c_void,
) -> *mut X509_ATTRIBUTE {
    let mut obj: *mut ASN1_OBJECT = OBJ_nid2obj(nid);
    if obj.is_null() {
        return 0 as *mut X509_ATTRIBUTE;
    }
    let mut ret: *mut X509_ATTRIBUTE = X509_ATTRIBUTE_new();
    let mut val: *mut ASN1_TYPE = ASN1_TYPE_new();
    if !(ret.is_null() || val.is_null()) {
        (*ret).object = obj;
        if !(sk_ASN1_TYPE_push((*ret).set, val) == 0) {
            ASN1_TYPE_set(val, attrtype, value);
            return ret;
        }
    }
    X509_ATTRIBUTE_free(ret);
    ASN1_TYPE_free(val);
    return 0 as *mut X509_ATTRIBUTE;
}
unsafe extern "C" fn run_static_initializers() {
    X509_ATTRIBUTE_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: X509_ATTRIBUTE_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 2]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<X509_ATTRIBUTE>() as libc::c_ulong
                as libc::c_long,
            sname: b"X509_ATTRIBUTE\0" as *const u8 as *const libc::c_char,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
