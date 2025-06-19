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
    pub type asn1_object_st;
    pub type ASN1_VALUE_st;
    pub type X509_pubkey_st;
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
    static ASN1_IA5STRING_it: ASN1_ITEM;
    static ASN1_BIT_STRING_it: ASN1_ITEM;
    static X509_PUBKEY_it: ASN1_ITEM;
    static X509_ALGOR_it: ASN1_ITEM;
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
pub struct Netscape_spkac_st {
    pub pubkey: *mut X509_PUBKEY,
    pub challenge: *mut ASN1_IA5STRING,
}
pub type X509_PUBKEY = X509_pubkey_st;
pub type NETSCAPE_SPKAC = Netscape_spkac_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Netscape_spki_st {
    pub spkac: *mut NETSCAPE_SPKAC,
    pub sig_algor: *mut X509_ALGOR,
    pub signature: *mut ASN1_BIT_STRING,
}
pub type X509_ALGOR = X509_algor_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_algor_st {
    pub algorithm: *mut ASN1_OBJECT,
    pub parameter: *mut ASN1_TYPE,
}
pub type NETSCAPE_SPKI = Netscape_spki_st;
static mut NETSCAPE_SPKAC_seq_tt: [ASN1_TEMPLATE; 2] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"pubkey\0" as *const u8 as *const libc::c_char,
                item: &X509_PUBKEY_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"challenge\0" as *const u8 as *const libc::c_char,
                item: &ASN1_IA5STRING_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[unsafe(no_mangle)]
pub static mut NETSCAPE_SPKAC_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_NETSCAPE_SPKAC(
    mut a: *const NETSCAPE_SPKAC,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &NETSCAPE_SPKAC_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NETSCAPE_SPKAC_free(mut a: *mut NETSCAPE_SPKAC) {
    ASN1_item_free(a as *mut ASN1_VALUE, &NETSCAPE_SPKAC_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_NETSCAPE_SPKAC(
    mut a: *mut *mut NETSCAPE_SPKAC,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut NETSCAPE_SPKAC {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &NETSCAPE_SPKAC_it)
        as *mut NETSCAPE_SPKAC;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NETSCAPE_SPKAC_new() -> *mut NETSCAPE_SPKAC {
    return ASN1_item_new(&NETSCAPE_SPKAC_it) as *mut NETSCAPE_SPKAC;
}
static mut NETSCAPE_SPKI_seq_tt: [ASN1_TEMPLATE; 3] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"spkac\0" as *const u8 as *const libc::c_char,
                item: &NETSCAPE_SPKAC_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"sig_algor\0" as *const u8 as *const libc::c_char,
                item: &X509_ALGOR_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 16 as libc::c_ulong,
                field_name: b"signature\0" as *const u8 as *const libc::c_char,
                item: &ASN1_BIT_STRING_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[unsafe(no_mangle)]
pub static mut NETSCAPE_SPKI_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_NETSCAPE_SPKI(
    mut a: *const NETSCAPE_SPKI,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &NETSCAPE_SPKI_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NETSCAPE_SPKI_free(mut a: *mut NETSCAPE_SPKI) {
    ASN1_item_free(a as *mut ASN1_VALUE, &NETSCAPE_SPKI_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn NETSCAPE_SPKI_new() -> *mut NETSCAPE_SPKI {
    return ASN1_item_new(&NETSCAPE_SPKI_it) as *mut NETSCAPE_SPKI;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_NETSCAPE_SPKI(
    mut a: *mut *mut NETSCAPE_SPKI,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut NETSCAPE_SPKI {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &NETSCAPE_SPKI_it)
        as *mut NETSCAPE_SPKI;
}
unsafe extern "C" fn run_static_initializers() {
    NETSCAPE_SPKAC_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: NETSCAPE_SPKAC_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 2]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<NETSCAPE_SPKAC>() as libc::c_ulong
                as libc::c_long,
            sname: b"NETSCAPE_SPKAC\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    NETSCAPE_SPKI_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: NETSCAPE_SPKI_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 3]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<NETSCAPE_SPKI>() as libc::c_ulong
                as libc::c_long,
            sname: b"NETSCAPE_SPKI\0" as *const u8 as *const libc::c_char,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
