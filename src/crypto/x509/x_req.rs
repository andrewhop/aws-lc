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
    pub type ASN1_VALUE_st;
    pub type stack_st_X509_NAME_ENTRY;
    pub type evp_pkey_st;
    pub type stack_st_X509_ATTRIBUTE;
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
    static ASN1_BIT_STRING_it: ASN1_ITEM;
    static ASN1_INTEGER_it: ASN1_ITEM;
    fn ASN1_INTEGER_get(a: *const ASN1_INTEGER) -> libc::c_long;
    static X509_NAME_it: ASN1_ITEM;
    static X509_PUBKEY_it: ASN1_ITEM;
    static X509_ALGOR_it: ASN1_ITEM;
    static X509_ATTRIBUTE_it: ASN1_ITEM;
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
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
pub type X509_PUBKEY = X509_pubkey_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_pubkey_st {
    pub algor: *mut X509_ALGOR,
    pub public_key: *mut ASN1_BIT_STRING,
    pub pkey: *mut EVP_PKEY,
}
pub type EVP_PKEY = evp_pkey_st;
pub type X509_ALGOR = X509_algor_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_algor_st {
    pub algorithm: *mut ASN1_OBJECT,
    pub parameter: *mut ASN1_TYPE,
}
pub type ASN1_ENCODING = ASN1_ENCODING_st;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct ASN1_ENCODING_st {
    pub enc: *mut libc::c_uchar,
    pub len: libc::c_long,
    #[bitfield(name = "alias_only", ty = "libc::c_uint", bits = "0..=0")]
    #[bitfield(name = "alias_only_on_next_parse", ty = "libc::c_uint", bits = "1..=1")]
    pub alias_only_alias_only_on_next_parse: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_req_st {
    pub req_info: *mut X509_REQ_INFO,
    pub sig_alg: *mut X509_ALGOR,
    pub signature: *mut ASN1_BIT_STRING,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_REQ_INFO {
    pub enc: ASN1_ENCODING,
    pub version: *mut ASN1_INTEGER,
    pub subject: *mut X509_NAME,
    pub pubkey: *mut X509_PUBKEY,
    pub attributes: *mut stack_st_X509_ATTRIBUTE,
}
pub type X509_REQ = X509_req_st;
pub type OPENSSL_STACK = stack_st;
pub type ASN1_aux_cb = unsafe extern "C" fn(
    libc::c_int,
    *mut *mut ASN1_VALUE,
    *const ASN1_ITEM,
    *mut libc::c_void,
) -> libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ASN1_AUX_st {
    pub app_data: *mut libc::c_void,
    pub flags: uint32_t,
    pub ref_offset: libc::c_int,
    pub asn1_cb: Option::<ASN1_aux_cb>,
    pub enc_offset: libc::c_int,
}
pub type ASN1_AUX = ASN1_AUX_st;
#[inline]
unsafe extern "C" fn sk_X509_ATTRIBUTE_new_null() -> *mut stack_st_X509_ATTRIBUTE {
    return OPENSSL_sk_new_null() as *mut stack_st_X509_ATTRIBUTE;
}
unsafe extern "C" fn rinf_cb(
    mut operation: libc::c_int,
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
    mut exarg: *mut libc::c_void,
) -> libc::c_int {
    let mut rinf: *mut X509_REQ_INFO = *pval as *mut X509_REQ_INFO;
    if operation == 1 as libc::c_int {
        (*rinf).attributes = sk_X509_ATTRIBUTE_new_null();
        if ((*rinf).attributes).is_null() {
            return 0 as libc::c_int;
        }
    }
    if operation == 5 as libc::c_int {
        let mut version: libc::c_long = ASN1_INTEGER_get((*rinf).version);
        if version != 0 as libc::c_int as libc::c_long
            && version != 2 as libc::c_int as libc::c_long
        {
            ERR_put_error(
                11 as libc::c_int,
                0 as libc::c_int,
                140 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x_req.c\0" as *const u8
                    as *const libc::c_char,
                90 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
static mut X509_REQ_INFO_aux: ASN1_AUX = unsafe {
    {
        let mut init = ASN1_AUX_st {
            app_data: 0 as *const libc::c_void as *mut libc::c_void,
            flags: 2 as libc::c_int as uint32_t,
            ref_offset: 0 as libc::c_int,
            asn1_cb: Some(
                rinf_cb
                    as unsafe extern "C" fn(
                        libc::c_int,
                        *mut *mut ASN1_VALUE,
                        *const ASN1_ITEM,
                        *mut libc::c_void,
                    ) -> libc::c_int,
            ),
            enc_offset: 0 as libc::c_ulong as libc::c_int,
        };
        init
    }
};
static mut X509_REQ_INFO_seq_tt: [ASN1_TEMPLATE; 4] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 24 as libc::c_ulong,
                field_name: b"version\0" as *const u8 as *const libc::c_char,
                item: &ASN1_INTEGER_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 32 as libc::c_ulong,
                field_name: b"subject\0" as *const u8 as *const libc::c_char,
                item: &X509_NAME_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 40 as libc::c_ulong,
                field_name: b"pubkey\0" as *const u8 as *const libc::c_char,
                item: &X509_PUBKEY_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int
                    | (0x1 as libc::c_int) << 1 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 48 as libc::c_ulong,
                field_name: b"attributes\0" as *const u8 as *const libc::c_char,
                item: &X509_ATTRIBUTE_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut X509_REQ_INFO_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_REQ_INFO(
    mut a: *mut X509_REQ_INFO,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &X509_REQ_INFO_it);
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_INFO_free(mut a: *mut X509_REQ_INFO) {
    ASN1_item_free(a as *mut ASN1_VALUE, &X509_REQ_INFO_it);
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_INFO_new() -> *mut X509_REQ_INFO {
    return ASN1_item_new(&X509_REQ_INFO_it) as *mut X509_REQ_INFO;
}
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_REQ_INFO(
    mut a: *mut *mut X509_REQ_INFO,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut X509_REQ_INFO {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &X509_REQ_INFO_it)
        as *mut X509_REQ_INFO;
}
static mut X509_REQ_seq_tt: [ASN1_TEMPLATE; 3] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"req_info\0" as *const u8 as *const libc::c_char,
                item: &X509_REQ_INFO_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"sig_alg\0" as *const u8 as *const libc::c_char,
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
#[no_mangle]
pub static mut X509_REQ_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_REQ(
    mut a: *mut X509_REQ,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &X509_REQ_it);
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_free(mut a: *mut X509_REQ) {
    ASN1_item_free(a as *mut ASN1_VALUE, &X509_REQ_it);
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_new() -> *mut X509_REQ {
    return ASN1_item_new(&X509_REQ_it) as *mut X509_REQ;
}
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_REQ(
    mut a: *mut *mut X509_REQ,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut X509_REQ {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &X509_REQ_it)
        as *mut X509_REQ;
}
#[no_mangle]
pub unsafe extern "C" fn X509_REQ_dup(mut x: *mut X509_REQ) -> *mut X509_REQ {
    return ASN1_item_dup(&X509_REQ_it, x as *mut libc::c_void) as *mut X509_REQ;
}
unsafe extern "C" fn run_static_initializers() {
    X509_REQ_INFO_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: X509_REQ_INFO_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 4]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: &X509_REQ_INFO_aux as *const ASN1_AUX as *const libc::c_void,
            size: ::core::mem::size_of::<X509_REQ_INFO>() as libc::c_ulong
                as libc::c_long,
            sname: b"X509_REQ_INFO\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    X509_REQ_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: X509_REQ_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 3]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<X509_REQ>() as libc::c_ulong as libc::c_long,
            sname: b"X509_REQ\0" as *const u8 as *const libc::c_char,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
