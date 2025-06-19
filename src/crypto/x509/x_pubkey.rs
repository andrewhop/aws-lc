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
    pub type evp_pkey_st;
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
    fn ASN1_STRING_set0(
        str: *mut ASN1_STRING,
        data: *mut libc::c_void,
        len: libc::c_int,
    );
    static ASN1_BIT_STRING_it: ASN1_ITEM;
    static X509_ALGOR_it: ASN1_ITEM;
    fn X509_ALGOR_set0(
        alg: *mut X509_ALGOR,
        obj: *mut ASN1_OBJECT,
        param_type: libc::c_int,
        param_value: *mut libc::c_void,
    ) -> libc::c_int;
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBB_init(cbb: *mut CBB, initial_capacity: size_t) -> libc::c_int;
    fn CBB_cleanup(cbb: *mut CBB);
    fn CBB_finish(
        cbb: *mut CBB,
        out_data: *mut *mut uint8_t,
        out_len: *mut size_t,
    ) -> libc::c_int;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_clear_error();
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
    fn EVP_PKEY_up_ref(pkey: *mut EVP_PKEY) -> libc::c_int;
    fn EVP_parse_public_key(cbs: *mut CBS) -> *mut EVP_PKEY;
    fn EVP_marshal_public_key(cbb: *mut CBB, key: *const EVP_PKEY) -> libc::c_int;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cbb_st {
    pub child: *mut CBB,
    pub is_child: libc::c_char,
    pub u: C2RustUnnamed_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub base: cbb_buffer_st,
    pub child: cbb_child_st,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct cbb_child_st {
    pub base: *mut cbb_buffer_st,
    pub offset: size_t,
    pub pending_len_len: uint8_t,
    #[bitfield(name = "pending_is_asn1", ty = "libc::c_uint", bits = "0..=0")]
    pub pending_is_asn1: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 6],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct cbb_buffer_st {
    pub buf: *mut uint8_t,
    pub len: size_t,
    pub cap: size_t,
    #[bitfield(name = "can_resize", ty = "libc::c_uint", bits = "0..=0")]
    #[bitfield(name = "error", ty = "libc::c_uint", bits = "1..=1")]
    pub can_resize_error: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
pub type CBB = cbb_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cbs_st {
    pub data: *const uint8_t,
    pub len: size_t,
}
pub type CBS = cbs_st;
pub type ASN1_AUX = ASN1_AUX_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ASN1_AUX_st {
    pub app_data: *mut libc::c_void,
    pub flags: uint32_t,
    pub ref_offset: libc::c_int,
    pub asn1_cb: Option::<ASN1_aux_cb>,
    pub enc_offset: libc::c_int,
}
pub type ASN1_aux_cb = unsafe extern "C" fn(
    libc::c_int,
    *mut *mut ASN1_VALUE,
    *const ASN1_ITEM,
    *mut libc::c_void,
) -> libc::c_int;
unsafe extern "C" fn x509_pubkey_changed(mut pub_0: *mut X509_PUBKEY) {
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut pkey: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
    EVP_PKEY_free((*pub_0).pkey);
    (*pub_0).pkey = 0 as *mut EVP_PKEY;
    let mut spki: *mut uint8_t = 0 as *mut uint8_t;
    let mut spki_len: libc::c_int = i2d_X509_PUBKEY(pub_0, &mut spki);
    if !(spki_len < 0 as libc::c_int) {
        cbs = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        CBS_init(&mut cbs, spki, spki_len as size_t);
        pkey = EVP_parse_public_key(&mut cbs);
        if pkey.is_null() || CBS_len(&mut cbs) != 0 as libc::c_int as size_t {
            EVP_PKEY_free(pkey);
        } else {
            (*pub_0).pkey = pkey;
        }
    }
    OPENSSL_free(spki as *mut libc::c_void);
    ERR_clear_error();
}
unsafe extern "C" fn pubkey_cb(
    mut operation: libc::c_int,
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
    mut exarg: *mut libc::c_void,
) -> libc::c_int {
    let mut pubkey: *mut X509_PUBKEY = *pval as *mut X509_PUBKEY;
    if operation == 3 as libc::c_int {
        EVP_PKEY_free((*pubkey).pkey);
    } else if operation == 5 as libc::c_int {
        x509_pubkey_changed(pubkey);
    }
    return 1 as libc::c_int;
}
static mut X509_PUBKEY_seq_tt: [ASN1_TEMPLATE; 2] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"algor\0" as *const u8 as *const libc::c_char,
                item: &X509_ALGOR_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"public_key\0" as *const u8 as *const libc::c_char,
                item: &ASN1_BIT_STRING_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
static mut X509_PUBKEY_aux: ASN1_AUX = unsafe {
    {
        let mut init = ASN1_AUX_st {
            app_data: 0 as *const libc::c_void as *mut libc::c_void,
            flags: 0 as libc::c_int as uint32_t,
            ref_offset: 0 as libc::c_int,
            asn1_cb: Some(
                pubkey_cb
                    as unsafe extern "C" fn(
                        libc::c_int,
                        *mut *mut ASN1_VALUE,
                        *const ASN1_ITEM,
                        *mut libc::c_void,
                    ) -> libc::c_int,
            ),
            enc_offset: 0 as libc::c_int,
        };
        init
    }
};
#[no_mangle]
pub static mut X509_PUBKEY_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_PUBKEY(
    mut a: *const X509_PUBKEY,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &X509_PUBKEY_it);
}
#[no_mangle]
pub unsafe extern "C" fn X509_PUBKEY_free(mut a: *mut X509_PUBKEY) {
    ASN1_item_free(a as *mut ASN1_VALUE, &X509_PUBKEY_it);
}
#[no_mangle]
pub unsafe extern "C" fn X509_PUBKEY_new() -> *mut X509_PUBKEY {
    return ASN1_item_new(&X509_PUBKEY_it) as *mut X509_PUBKEY;
}
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_PUBKEY(
    mut a: *mut *mut X509_PUBKEY,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut X509_PUBKEY {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &X509_PUBKEY_it)
        as *mut X509_PUBKEY;
}
#[no_mangle]
pub unsafe extern "C" fn X509_PUBKEY_set(
    mut x: *mut *mut X509_PUBKEY,
    mut pkey: *mut EVP_PKEY,
) -> libc::c_int {
    let mut p: *const uint8_t = 0 as *const uint8_t;
    let mut pk: *mut X509_PUBKEY = 0 as *mut X509_PUBKEY;
    let mut spki: *mut uint8_t = 0 as *mut uint8_t;
    let mut spki_len: size_t = 0;
    if x.is_null() {
        return 0 as libc::c_int;
    }
    let mut cbb: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    if CBB_init(&mut cbb, 0 as libc::c_int as size_t) == 0
        || EVP_marshal_public_key(&mut cbb, pkey) == 0
        || CBB_finish(&mut cbb, &mut spki, &mut spki_len) == 0
        || spki_len > 9223372036854775807 as libc::c_long as size_t
    {
        CBB_cleanup(&mut cbb);
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            126 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x_pubkey.c\0" as *const u8
                as *const libc::c_char,
            134 as libc::c_int as libc::c_uint,
        );
    } else {
        p = spki;
        pk = d2i_X509_PUBKEY(
            0 as *mut *mut X509_PUBKEY,
            &mut p,
            spki_len as libc::c_long,
        );
        if pk.is_null() || p != spki.offset(spki_len as isize) as *const uint8_t {
            ERR_put_error(
                11 as libc::c_int,
                0 as libc::c_int,
                125 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x_pubkey.c\0"
                    as *const u8 as *const libc::c_char,
                141 as libc::c_int as libc::c_uint,
            );
        } else {
            OPENSSL_free(spki as *mut libc::c_void);
            X509_PUBKEY_free(*x);
            *x = pk;
            return 1 as libc::c_int;
        }
    }
    X509_PUBKEY_free(pk);
    OPENSSL_free(spki as *mut libc::c_void);
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_PUBKEY_get0(mut key: *const X509_PUBKEY) -> *mut EVP_PKEY {
    if key.is_null() {
        return 0 as *mut EVP_PKEY;
    }
    if ((*key).pkey).is_null() {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            125 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x_pubkey.c\0" as *const u8
                as *const libc::c_char,
            162 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut EVP_PKEY;
    }
    return (*key).pkey;
}
#[no_mangle]
pub unsafe extern "C" fn X509_PUBKEY_get(mut key: *const X509_PUBKEY) -> *mut EVP_PKEY {
    let mut pkey: *mut EVP_PKEY = X509_PUBKEY_get0(key);
    if !pkey.is_null() {
        EVP_PKEY_up_ref(pkey);
    }
    return pkey;
}
#[no_mangle]
pub unsafe extern "C" fn X509_PUBKEY_set0_param(
    mut pub_0: *mut X509_PUBKEY,
    mut obj: *mut ASN1_OBJECT,
    mut param_type: libc::c_int,
    mut param_value: *mut libc::c_void,
    mut key: *mut uint8_t,
    mut key_len: libc::c_int,
) -> libc::c_int {
    if X509_ALGOR_set0((*pub_0).algor, obj, param_type, param_value) == 0 {
        return 0 as libc::c_int;
    }
    ASN1_STRING_set0((*pub_0).public_key, key as *mut libc::c_void, key_len);
    (*(*pub_0).public_key).flags
        &= !(0x8 as libc::c_int | 0x7 as libc::c_int) as libc::c_long;
    (*(*pub_0).public_key).flags |= 0x8 as libc::c_int as libc::c_long;
    x509_pubkey_changed(pub_0);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_PUBKEY_get0_param(
    mut out_obj: *mut *mut ASN1_OBJECT,
    mut out_key: *mut *const uint8_t,
    mut out_key_len: *mut libc::c_int,
    mut out_alg: *mut *mut X509_ALGOR,
    mut pub_0: *mut X509_PUBKEY,
) -> libc::c_int {
    if !out_obj.is_null() {
        *out_obj = (*(*pub_0).algor).algorithm;
    }
    if !out_key.is_null() {
        *out_key = (*(*pub_0).public_key).data;
        *out_key_len = (*(*pub_0).public_key).length;
    }
    if !out_alg.is_null() {
        *out_alg = (*pub_0).algor;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_PUBKEY_get0_public_key(
    mut pub_0: *const X509_PUBKEY,
) -> *const ASN1_BIT_STRING {
    return (*pub_0).public_key;
}
unsafe extern "C" fn run_static_initializers() {
    X509_PUBKEY_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: X509_PUBKEY_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 2]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: &X509_PUBKEY_aux as *const ASN1_AUX as *const libc::c_void,
            size: ::core::mem::size_of::<X509_PUBKEY>() as libc::c_ulong as libc::c_long,
            sname: b"X509_PUBKEY\0" as *const u8 as *const libc::c_char,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
