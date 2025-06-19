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
    pub type stack_st_GENERAL_NAME;
    pub type stack_st_X509_NAME_ENTRY;
    static ASN1_SEQUENCE_it: ASN1_ITEM;
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
    fn ASN1_STRING_cmp(a: *const ASN1_STRING, b: *const ASN1_STRING) -> libc::c_int;
    static ASN1_IA5STRING_it: ASN1_ITEM;
    static ASN1_OCTET_STRING_it: ASN1_ITEM;
    fn ASN1_OCTET_STRING_cmp(
        a: *const ASN1_OCTET_STRING,
        b: *const ASN1_OCTET_STRING,
    ) -> libc::c_int;
    static DIRECTORYSTRING_it: ASN1_ITEM;
    static ASN1_OBJECT_it: ASN1_ITEM;
    fn ASN1_TYPE_free(a: *mut ASN1_TYPE);
    static ASN1_ANY_it: ASN1_ITEM;
    fn ASN1_TYPE_cmp(a: *const ASN1_TYPE, b: *const ASN1_TYPE) -> libc::c_int;
    static X509_NAME_it: ASN1_ITEM;
    fn X509_NAME_cmp(a: *const X509_NAME, b: *const X509_NAME) -> libc::c_int;
    fn OBJ_cmp(a: *const ASN1_OBJECT, b: *const ASN1_OBJECT) -> libc::c_int;
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
pub type GENERAL_NAMES = stack_st_GENERAL_NAME;
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
pub struct GENERAL_NAME_st {
    pub type_0: libc::c_int,
    pub d: C2RustUnnamed_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub ptr: *mut libc::c_char,
    pub otherName: *mut OTHERNAME,
    pub rfc822Name: *mut ASN1_IA5STRING,
    pub dNSName: *mut ASN1_IA5STRING,
    pub x400Address: *mut ASN1_STRING,
    pub directoryName: *mut X509_NAME,
    pub ediPartyName: *mut EDIPARTYNAME,
    pub uniformResourceIdentifier: *mut ASN1_IA5STRING,
    pub iPAddress: *mut ASN1_OCTET_STRING,
    pub registeredID: *mut ASN1_OBJECT,
    pub ip: *mut ASN1_OCTET_STRING,
    pub dirn: *mut X509_NAME,
    pub ia5: *mut ASN1_IA5STRING,
    pub rid: *mut ASN1_OBJECT,
}
pub type EDIPARTYNAME = EDIPartyName_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EDIPartyName_st {
    pub nameAssigner: *mut ASN1_STRING,
    pub partyName: *mut ASN1_STRING,
}
pub type OTHERNAME = otherName_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct otherName_st {
    pub type_id: *mut ASN1_OBJECT,
    pub value: *mut ASN1_TYPE,
}
pub type GENERAL_NAME = GENERAL_NAME_st;
static mut OTHERNAME_seq_tt: [ASN1_TEMPLATE; 2] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"type_id\0" as *const u8 as *const libc::c_char,
                item: &ASN1_OBJECT_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"value\0" as *const u8 as *const libc::c_char,
                item: &ASN1_ANY_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[unsafe(no_mangle)]
pub static mut OTHERNAME_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OTHERNAME_free(mut a: *mut OTHERNAME) {
    ASN1_item_free(a as *mut ASN1_VALUE, &OTHERNAME_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OTHERNAME_new() -> *mut OTHERNAME {
    return ASN1_item_new(&OTHERNAME_it) as *mut OTHERNAME;
}
static mut EDIPARTYNAME_seq_tt: [ASN1_TEMPLATE; 2] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"nameAssigner\0" as *const u8 as *const libc::c_char,
                item: &DIRECTORYSTRING_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0 as libc::c_int)
                    as uint32_t,
                tag: 1 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"partyName\0" as *const u8 as *const libc::c_char,
                item: &DIRECTORYSTRING_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[unsafe(no_mangle)]
pub static mut EDIPARTYNAME_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EDIPARTYNAME_free(mut a: *mut EDIPARTYNAME) {
    ASN1_item_free(a as *mut ASN1_VALUE, &EDIPARTYNAME_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EDIPARTYNAME_new() -> *mut EDIPARTYNAME {
    return ASN1_item_new(&EDIPARTYNAME_it) as *mut EDIPARTYNAME;
}
static mut GENERAL_NAME_ch_tt: [ASN1_TEMPLATE; 9] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"d.otherName\0" as *const u8 as *const libc::c_char,
                item: &OTHERNAME_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0 as libc::c_int)
                    as uint32_t,
                tag: 1 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"d.rfc822Name\0" as *const u8 as *const libc::c_char,
                item: &ASN1_IA5STRING_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0 as libc::c_int)
                    as uint32_t,
                tag: 2 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"d.dNSName\0" as *const u8 as *const libc::c_char,
                item: &ASN1_IA5STRING_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0 as libc::c_int)
                    as uint32_t,
                tag: 3 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"d.x400Address\0" as *const u8 as *const libc::c_char,
                item: &ASN1_SEQUENCE_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0 as libc::c_int)
                    as uint32_t,
                tag: 4 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"d.directoryName\0" as *const u8 as *const libc::c_char,
                item: &X509_NAME_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0 as libc::c_int)
                    as uint32_t,
                tag: 5 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"d.ediPartyName\0" as *const u8 as *const libc::c_char,
                item: &EDIPARTYNAME_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0 as libc::c_int)
                    as uint32_t,
                tag: 6 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"d.uniformResourceIdentifier\0" as *const u8
                    as *const libc::c_char,
                item: &ASN1_IA5STRING_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0 as libc::c_int)
                    as uint32_t,
                tag: 7 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"d.iPAddress\0" as *const u8 as *const libc::c_char,
                item: &ASN1_OCTET_STRING_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0 as libc::c_int)
                    as uint32_t,
                tag: 8 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"d.registeredID\0" as *const u8 as *const libc::c_char,
                item: &ASN1_OBJECT_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[unsafe(no_mangle)]
pub static mut GENERAL_NAME_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_GENERAL_NAME(
    mut a: *mut GENERAL_NAME,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &GENERAL_NAME_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn GENERAL_NAME_free(mut a: *mut GENERAL_NAME) {
    ASN1_item_free(a as *mut ASN1_VALUE, &GENERAL_NAME_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn GENERAL_NAME_new() -> *mut GENERAL_NAME {
    return ASN1_item_new(&GENERAL_NAME_it) as *mut GENERAL_NAME;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_GENERAL_NAME(
    mut a: *mut *mut GENERAL_NAME,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut GENERAL_NAME {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &GENERAL_NAME_it)
        as *mut GENERAL_NAME;
}
static mut GENERAL_NAMES_item_tt: ASN1_TEMPLATE = unsafe {
    {
        let mut init = ASN1_TEMPLATE_st {
            flags: ((0x2 as libc::c_int) << 1 as libc::c_int) as uint32_t,
            tag: 0 as libc::c_int,
            offset: 0 as libc::c_int as libc::c_ulong,
            field_name: b"GeneralNames\0" as *const u8 as *const libc::c_char,
            item: &GENERAL_NAME_it as *const ASN1_ITEM,
        };
        init
    }
};
#[unsafe(no_mangle)]
pub static mut GENERAL_NAMES_it: ASN1_ITEM = unsafe {
    {
        let mut init = ASN1_ITEM_st {
            itype: 0 as libc::c_int as libc::c_char,
            utype: -(1 as libc::c_int),
            templates: &GENERAL_NAMES_item_tt as *const ASN1_TEMPLATE,
            tcount: 0 as libc::c_int as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: 0 as libc::c_int as libc::c_long,
            sname: b"GENERAL_NAMES\0" as *const u8 as *const libc::c_char,
        };
        init
    }
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn GENERAL_NAMES_free(mut a: *mut GENERAL_NAMES) {
    ASN1_item_free(a as *mut ASN1_VALUE, &GENERAL_NAMES_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_GENERAL_NAMES(
    mut a: *mut GENERAL_NAMES,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &GENERAL_NAMES_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn GENERAL_NAMES_new() -> *mut GENERAL_NAMES {
    return ASN1_item_new(&GENERAL_NAMES_it) as *mut GENERAL_NAMES;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_GENERAL_NAMES(
    mut a: *mut *mut GENERAL_NAMES,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut GENERAL_NAMES {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &GENERAL_NAMES_it)
        as *mut GENERAL_NAMES;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn GENERAL_NAME_dup(
    mut x: *mut GENERAL_NAME,
) -> *mut GENERAL_NAME {
    return ASN1_item_dup(&GENERAL_NAME_it, x as *mut libc::c_void) as *mut GENERAL_NAME;
}
unsafe extern "C" fn edipartyname_cmp(
    mut a: *const EDIPARTYNAME,
    mut b: *const EDIPARTYNAME,
) -> libc::c_int {
    if ((*a).nameAssigner).is_null() {
        if !((*b).nameAssigner).is_null() {
            return -(1 as libc::c_int);
        }
    } else if ((*b).nameAssigner).is_null()
        || ASN1_STRING_cmp((*a).nameAssigner, (*b).nameAssigner) != 0 as libc::c_int
    {
        return -(1 as libc::c_int)
    }
    return ASN1_STRING_cmp((*a).partyName, (*b).partyName);
}
unsafe extern "C" fn othername_cmp(
    mut a: *const OTHERNAME,
    mut b: *const OTHERNAME,
) -> libc::c_int {
    let mut result: libc::c_int = -(1 as libc::c_int);
    if a.is_null() || b.is_null() {
        return -(1 as libc::c_int);
    }
    result = OBJ_cmp((*a).type_id, (*b).type_id);
    if result != 0 as libc::c_int {
        return result;
    }
    result = ASN1_TYPE_cmp((*a).value, (*b).value);
    return result;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn GENERAL_NAME_cmp(
    mut a: *const GENERAL_NAME,
    mut b: *const GENERAL_NAME,
) -> libc::c_int {
    if a.is_null() || b.is_null() || (*a).type_0 != (*b).type_0 {
        return -(1 as libc::c_int);
    }
    match (*a).type_0 {
        3 => return ASN1_STRING_cmp((*a).d.x400Address, (*b).d.x400Address),
        5 => return edipartyname_cmp((*a).d.ediPartyName, (*b).d.ediPartyName),
        0 => return othername_cmp((*a).d.otherName, (*b).d.otherName),
        1 | 2 | 6 => return ASN1_STRING_cmp((*a).d.ia5, (*b).d.ia5),
        4 => return X509_NAME_cmp((*a).d.dirn, (*b).d.dirn),
        7 => return ASN1_OCTET_STRING_cmp((*a).d.ip, (*b).d.ip),
        8 => return OBJ_cmp((*a).d.rid, (*b).d.rid),
        _ => {}
    }
    return -(1 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn GENERAL_NAME_set0_value(
    mut a: *mut GENERAL_NAME,
    mut type_0: libc::c_int,
    mut value: *mut libc::c_void,
) {
    match type_0 {
        3 => {
            (*a).d.x400Address = value as *mut ASN1_STRING;
        }
        5 => {
            (*a).d.ediPartyName = value as *mut EDIPARTYNAME;
        }
        0 => {
            (*a).d.otherName = value as *mut OTHERNAME;
        }
        1 | 2 | 6 => {
            (*a).d.ia5 = value as *mut ASN1_IA5STRING;
        }
        4 => {
            (*a).d.dirn = value as *mut X509_NAME;
        }
        7 => {
            (*a).d.ip = value as *mut ASN1_OCTET_STRING;
        }
        8 => {
            (*a).d.rid = value as *mut ASN1_OBJECT;
        }
        _ => {}
    }
    (*a).type_0 = type_0;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn GENERAL_NAME_get0_value(
    mut a: *const GENERAL_NAME,
    mut out_type: *mut libc::c_int,
) -> *mut libc::c_void {
    if !out_type.is_null() {
        *out_type = (*a).type_0;
    }
    match (*a).type_0 {
        3 => return (*a).d.x400Address as *mut libc::c_void,
        5 => return (*a).d.ediPartyName as *mut libc::c_void,
        0 => return (*a).d.otherName as *mut libc::c_void,
        1 | 2 | 6 => return (*a).d.ia5 as *mut libc::c_void,
        4 => return (*a).d.dirn as *mut libc::c_void,
        7 => return (*a).d.ip as *mut libc::c_void,
        8 => return (*a).d.rid as *mut libc::c_void,
        _ => return 0 as *mut libc::c_void,
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn GENERAL_NAME_set0_othername(
    mut gen: *mut GENERAL_NAME,
    mut oid: *mut ASN1_OBJECT,
    mut value: *mut ASN1_TYPE,
) -> libc::c_int {
    let mut oth: *mut OTHERNAME = 0 as *mut OTHERNAME;
    oth = OTHERNAME_new();
    if oth.is_null() {
        return 0 as libc::c_int;
    }
    ASN1_TYPE_free((*oth).value);
    (*oth).type_id = oid;
    (*oth).value = value;
    GENERAL_NAME_set0_value(gen, 0 as libc::c_int, oth as *mut libc::c_void);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn GENERAL_NAME_get0_otherName(
    mut gen: *const GENERAL_NAME,
    mut out_oid: *mut *mut ASN1_OBJECT,
    mut out_value: *mut *mut ASN1_TYPE,
) -> libc::c_int {
    if (*gen).type_0 != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if !out_oid.is_null() {
        *out_oid = (*(*gen).d.otherName).type_id;
    }
    if !out_value.is_null() {
        *out_value = (*(*gen).d.otherName).value;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn run_static_initializers() {
    OTHERNAME_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: OTHERNAME_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 2]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<OTHERNAME>() as libc::c_ulong as libc::c_long,
            sname: b"OTHERNAME\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    EDIPARTYNAME_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: EDIPARTYNAME_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 2]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<EDIPARTYNAME>() as libc::c_ulong
                as libc::c_long,
            sname: b"EDIPARTYNAME\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    GENERAL_NAME_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x2 as libc::c_int as libc::c_char,
            utype: 0 as libc::c_ulong as libc::c_int,
            templates: GENERAL_NAME_ch_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 9]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<GENERAL_NAME>() as libc::c_ulong
                as libc::c_long,
            sname: b"GENERAL_NAME\0" as *const u8 as *const libc::c_char,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
