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
    pub type stack_st_X509_EXTENSION;
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
    static ASN1_BOOLEAN_it: ASN1_ITEM;
    static ASN1_OCTET_STRING_it: ASN1_ITEM;
    static ASN1_OBJECT_it: ASN1_ITEM;
}
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
pub type ASN1_OCTET_STRING = asn1_string_st;
pub type ASN1_VALUE = ASN1_VALUE_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_extension_st {
    pub object: *mut ASN1_OBJECT,
    pub critical: ASN1_BOOLEAN,
    pub value: *mut ASN1_OCTET_STRING,
}
pub type X509_EXTENSION = X509_extension_st;
pub type X509_EXTENSIONS = stack_st_X509_EXTENSION;
static mut X509_EXTENSION_seq_tt: [ASN1_TEMPLATE; 3] = unsafe {
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
                flags: 0x1 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"critical\0" as *const u8 as *const libc::c_char,
                item: &ASN1_BOOLEAN_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 16 as libc::c_ulong,
                field_name: b"value\0" as *const u8 as *const libc::c_char,
                item: &ASN1_OCTET_STRING_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[unsafe(no_mangle)]
pub static mut X509_EXTENSION_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
static mut X509_EXTENSIONS_item_tt: ASN1_TEMPLATE = unsafe {
    {
        let mut init = ASN1_TEMPLATE_st {
            flags: ((0x2 as libc::c_int) << 1 as libc::c_int) as uint32_t,
            tag: 0 as libc::c_int,
            offset: 0 as libc::c_int as libc::c_ulong,
            field_name: b"Extension\0" as *const u8 as *const libc::c_char,
            item: &X509_EXTENSION_it as *const ASN1_ITEM,
        };
        init
    }
};
#[unsafe(no_mangle)]
pub static mut X509_EXTENSIONS_it: ASN1_ITEM = unsafe {
    {
        let mut init = ASN1_ITEM_st {
            itype: 0 as libc::c_int as libc::c_char,
            utype: -(1 as libc::c_int),
            templates: &X509_EXTENSIONS_item_tt as *const ASN1_TEMPLATE,
            tcount: 0 as libc::c_int as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: 0 as libc::c_int as libc::c_long,
            sname: b"X509_EXTENSIONS\0" as *const u8 as *const libc::c_char,
        };
        init
    }
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_X509_EXTENSION(
    mut a: *const X509_EXTENSION,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &X509_EXTENSION_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_EXTENSION_free(mut a: *mut X509_EXTENSION) {
    ASN1_item_free(a as *mut ASN1_VALUE, &X509_EXTENSION_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_EXTENSION_new() -> *mut X509_EXTENSION {
    return ASN1_item_new(&X509_EXTENSION_it) as *mut X509_EXTENSION;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_X509_EXTENSION(
    mut a: *mut *mut X509_EXTENSION,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut X509_EXTENSION {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &X509_EXTENSION_it)
        as *mut X509_EXTENSION;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_X509_EXTENSIONS(
    mut a: *const X509_EXTENSIONS,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &X509_EXTENSIONS_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_X509_EXTENSIONS(
    mut a: *mut *mut X509_EXTENSIONS,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut X509_EXTENSIONS {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &X509_EXTENSIONS_it)
        as *mut X509_EXTENSIONS;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_EXTENSION_dup(
    mut x: *const X509_EXTENSION,
) -> *mut X509_EXTENSION {
    return ASN1_item_dup(&X509_EXTENSION_it, x as *mut libc::c_void)
        as *mut X509_EXTENSION;
}
unsafe extern "C" fn run_static_initializers() {
    X509_EXTENSION_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: X509_EXTENSION_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 3]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<X509_EXTENSION>() as libc::c_ulong
                as libc::c_long,
            sname: b"X509_EXTENSION\0" as *const u8 as *const libc::c_char,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
