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
    pub type asn1_pctx_st;
    pub type ASN1_VALUE_st;
    pub type stack_st_void;
    pub type stack_st;
    pub type stack_st_ASN1_VALUE;
    pub type ASN1_TLC_st;
    fn ASN1_STRING_type_new(type_0: libc::c_int) -> *mut ASN1_STRING;
    fn ASN1_STRING_free(str: *mut ASN1_STRING);
    fn ASN1_STRING_set(
        str: *mut ASN1_STRING,
        data: *const libc::c_void,
        len: ossl_ssize_t,
    ) -> libc::c_int;
    fn c2i_ASN1_BIT_STRING(
        out: *mut *mut ASN1_BIT_STRING,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut ASN1_BIT_STRING;
    fn c2i_ASN1_INTEGER(
        in_0: *mut *mut ASN1_INTEGER,
        outp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut ASN1_INTEGER;
    fn c2i_ASN1_OBJECT(
        out: *mut *mut ASN1_OBJECT,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut ASN1_OBJECT;
    fn ASN1_TYPE_new() -> *mut ASN1_TYPE;
    fn ASN1_TYPE_free(a: *mut ASN1_TYPE);
    fn ASN1_TYPE_set(a: *mut ASN1_TYPE, type_0: libc::c_int, value: *mut libc::c_void);
    fn ASN1_get_object(
        inp: *mut *const libc::c_uchar,
        out_length: *mut libc::c_long,
        out_tag: *mut libc::c_int,
        out_class: *mut libc::c_int,
        max_len: libc::c_long,
    ) -> libc::c_int;
    fn ASN1_item_ex_new(pval: *mut *mut ASN1_VALUE, it: *const ASN1_ITEM) -> libc::c_int;
    fn ASN1_item_ex_free(pval: *mut *mut ASN1_VALUE, it: *const ASN1_ITEM);
    fn ASN1_template_free(pval: *mut *mut ASN1_VALUE, tt: *const ASN1_TEMPLATE);
    fn asn1_get_choice_selector(
        pval: *mut *mut ASN1_VALUE,
        it: *const ASN1_ITEM,
    ) -> libc::c_int;
    fn asn1_set_choice_selector(
        pval: *mut *mut ASN1_VALUE,
        value: libc::c_int,
        it: *const ASN1_ITEM,
    ) -> libc::c_int;
    fn asn1_get_field_ptr(
        pval: *mut *mut ASN1_VALUE,
        tt: *const ASN1_TEMPLATE,
    ) -> *mut *mut ASN1_VALUE;
    fn asn1_do_adb(
        pval: *mut *mut ASN1_VALUE,
        tt: *const ASN1_TEMPLATE,
        nullerr: libc::c_int,
    ) -> *const ASN1_TEMPLATE;
    fn asn1_enc_save(
        pval: *mut *mut ASN1_VALUE,
        in_0: *const libc::c_uchar,
        inlen: libc::c_int,
        it: *const ASN1_ITEM,
    ) -> libc::c_int;
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn OPENSSL_sk_pop(sk: *mut OPENSSL_STACK) -> *mut libc::c_void;
    fn BUF_MEM_grow_clean(buf: *mut BUF_MEM, len: size_t) -> size_t;
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_parse_generalized_time(
        cbs: *const CBS,
        out_tm: *mut tm,
        allow_timezone_offset: libc::c_int,
    ) -> libc::c_int;
    fn CBS_parse_utc_time(
        cbs: *const CBS,
        out_tm: *mut tm,
        allow_timezone_offset: libc::c_int,
    ) -> libc::c_int;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn ERR_add_error_data(count: libc::c_uint, _: ...);
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
}
pub type ptrdiff_t = libc::c_long;
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type ossl_ssize_t = ptrdiff_t;
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
pub type ASN1_PCTX = asn1_pctx_st;
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
pub struct bio_method_st {
    pub type_0: libc::c_int,
    pub name: *const libc::c_char,
    pub bwrite: Option::<
        unsafe extern "C" fn(*mut BIO, *const libc::c_char, libc::c_int) -> libc::c_int,
    >,
    pub bread: Option::<
        unsafe extern "C" fn(*mut BIO, *mut libc::c_char, libc::c_int) -> libc::c_int,
    >,
    pub bputs: Option::<
        unsafe extern "C" fn(*mut BIO, *const libc::c_char) -> libc::c_int,
    >,
    pub bgets: Option::<
        unsafe extern "C" fn(*mut BIO, *mut libc::c_char, libc::c_int) -> libc::c_int,
    >,
    pub ctrl: Option::<
        unsafe extern "C" fn(
            *mut BIO,
            libc::c_int,
            libc::c_long,
            *mut libc::c_void,
        ) -> libc::c_long,
    >,
    pub create: Option::<unsafe extern "C" fn(*mut BIO) -> libc::c_int>,
    pub destroy: Option::<unsafe extern "C" fn(*mut BIO) -> libc::c_int>,
    pub callback_ctrl: Option::<
        unsafe extern "C" fn(*mut BIO, libc::c_int, bio_info_cb) -> libc::c_long,
    >,
}
pub type bio_info_cb = Option::<
    unsafe extern "C" fn(*mut BIO, libc::c_int, libc::c_int) -> libc::c_long,
>;
pub type BIO = bio_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bio_st {
    pub method: *const BIO_METHOD,
    pub ex_data: CRYPTO_EX_DATA,
    pub callback_ex: BIO_callback_fn_ex,
    pub callback: BIO_callback_fn,
    pub cb_arg: *mut libc::c_char,
    pub init: libc::c_int,
    pub shutdown: libc::c_int,
    pub flags: libc::c_int,
    pub retry_reason: libc::c_int,
    pub num: libc::c_int,
    pub references: CRYPTO_refcount_t,
    pub ptr: *mut libc::c_void,
    pub next_bio: *mut BIO,
    pub num_read: uint64_t,
    pub num_write: uint64_t,
}
pub type CRYPTO_refcount_t = uint32_t;
pub type BIO_callback_fn = Option::<
    unsafe extern "C" fn(
        *mut BIO,
        libc::c_int,
        *const libc::c_char,
        libc::c_int,
        libc::c_long,
        libc::c_long,
    ) -> libc::c_long,
>;
pub type BIO_callback_fn_ex = Option::<
    unsafe extern "C" fn(
        *mut BIO,
        libc::c_int,
        *const libc::c_char,
        size_t,
        libc::c_int,
        libc::c_long,
        libc::c_int,
        *mut size_t,
    ) -> libc::c_long,
>;
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
pub type BIO_METHOD = bio_method_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct buf_mem_st {
    pub length: size_t,
    pub data: *mut libc::c_char,
    pub max: size_t,
}
pub type BUF_MEM = buf_mem_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cbs_st {
    pub data: *const uint8_t,
    pub len: size_t,
}
pub type CBS = cbs_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct tm {
    pub tm_sec: libc::c_int,
    pub tm_min: libc::c_int,
    pub tm_hour: libc::c_int,
    pub tm_mday: libc::c_int,
    pub tm_mon: libc::c_int,
    pub tm_year: libc::c_int,
    pub tm_wday: libc::c_int,
    pub tm_yday: libc::c_int,
    pub tm_isdst: libc::c_int,
    pub __tm_gmtoff: libc::c_long,
    pub __tm_zone: *const libc::c_char,
}
pub type OPENSSL_STACK = stack_st;
pub type ASN1_aux_cb = unsafe extern "C" fn(
    libc::c_int,
    *mut *mut ASN1_VALUE,
    *const ASN1_ITEM,
    *mut libc::c_void,
) -> libc::c_int;
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
pub type ASN1_TLC = ASN1_TLC_st;
pub type ASN1_ex_d2i = unsafe extern "C" fn(
    *mut *mut ASN1_VALUE,
    *mut *const libc::c_uchar,
    libc::c_long,
    *const ASN1_ITEM,
    libc::c_int,
    libc::c_int,
    libc::c_char,
    *mut ASN1_TLC,
) -> libc::c_int;
pub type ASN1_EXTERN_FUNCS = ASN1_EXTERN_FUNCS_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ASN1_EXTERN_FUNCS_st {
    pub app_data: *mut libc::c_void,
    pub asn1_ex_new: Option::<ASN1_ex_new_func>,
    pub asn1_ex_free: Option::<ASN1_ex_free_func>,
    pub asn1_ex_d2i: Option::<ASN1_ex_d2i>,
    pub asn1_ex_i2d: Option::<ASN1_ex_i2d>,
    pub asn1_ex_print: Option::<ASN1_ex_print_func>,
}
pub type ASN1_ex_print_func = unsafe extern "C" fn(
    *mut BIO,
    *mut *mut ASN1_VALUE,
    libc::c_int,
    *const libc::c_char,
    *const ASN1_PCTX,
) -> libc::c_int;
pub type ASN1_ex_i2d = unsafe extern "C" fn(
    *mut *mut ASN1_VALUE,
    *mut *mut libc::c_uchar,
    *const ASN1_ITEM,
    libc::c_int,
    libc::c_int,
) -> libc::c_int;
pub type ASN1_ex_free_func = unsafe extern "C" fn(
    *mut *mut ASN1_VALUE,
    *const ASN1_ITEM,
) -> ();
pub type ASN1_ex_new_func = unsafe extern "C" fn(
    *mut *mut ASN1_VALUE,
    *const ASN1_ITEM,
) -> libc::c_int;
#[inline]
unsafe extern "C" fn sk_ASN1_VALUE_pop(
    mut sk: *mut stack_st_ASN1_VALUE,
) -> *mut ASN1_VALUE {
    return OPENSSL_sk_pop(sk as *mut OPENSSL_STACK) as *mut ASN1_VALUE;
}
#[inline]
unsafe extern "C" fn sk_ASN1_VALUE_num(mut sk: *const stack_st_ASN1_VALUE) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_ASN1_VALUE_new_null() -> *mut stack_st_ASN1_VALUE {
    return OPENSSL_sk_new_null() as *mut stack_st_ASN1_VALUE;
}
#[inline]
unsafe extern "C" fn sk_ASN1_VALUE_push(
    mut sk: *mut stack_st_ASN1_VALUE,
    mut p: *mut ASN1_VALUE,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn OPENSSL_memcpy(
    mut dst: *mut libc::c_void,
    mut src: *const libc::c_void,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return dst;
    }
    return memcpy(dst, src, n);
}
static mut tag2bit: [libc::c_ulong; 31] = [
    0 as libc::c_int as libc::c_ulong,
    0 as libc::c_int as libc::c_ulong,
    0 as libc::c_int as libc::c_ulong,
    0x400 as libc::c_int as libc::c_ulong,
    0x200 as libc::c_int as libc::c_ulong,
    0 as libc::c_int as libc::c_ulong,
    0 as libc::c_int as libc::c_ulong,
    0x1000 as libc::c_int as libc::c_ulong,
    0x1000 as libc::c_int as libc::c_ulong,
    0x1000 as libc::c_int as libc::c_ulong,
    0x1000 as libc::c_int as libc::c_ulong,
    0x1000 as libc::c_int as libc::c_ulong,
    0x2000 as libc::c_int as libc::c_ulong,
    0x1000 as libc::c_int as libc::c_ulong,
    0x1000 as libc::c_int as libc::c_ulong,
    0x1000 as libc::c_int as libc::c_ulong,
    0x10000 as libc::c_int as libc::c_ulong,
    0 as libc::c_int as libc::c_ulong,
    0x1 as libc::c_int as libc::c_ulong,
    0x2 as libc::c_int as libc::c_ulong,
    0x4 as libc::c_int as libc::c_ulong,
    0x8 as libc::c_int as libc::c_ulong,
    0x10 as libc::c_int as libc::c_ulong,
    0x4000 as libc::c_int as libc::c_ulong,
    0x8000 as libc::c_int as libc::c_ulong,
    0x20 as libc::c_int as libc::c_ulong,
    0x40 as libc::c_int as libc::c_ulong,
    0x80 as libc::c_int as libc::c_ulong,
    0x100 as libc::c_int as libc::c_ulong,
    0x1000 as libc::c_int as libc::c_ulong,
    0x800 as libc::c_int as libc::c_ulong,
];
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_tag2bit(mut tag: libc::c_int) -> libc::c_ulong {
    if tag < 0 as libc::c_int || tag > 30 as libc::c_int {
        return 0 as libc::c_int as libc::c_ulong;
    }
    return tag2bit[tag as usize];
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_item_d2i(
    mut pval: *mut *mut ASN1_VALUE,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
    mut it: *const ASN1_ITEM,
) -> *mut ASN1_VALUE {
    let mut ptmpval: *mut ASN1_VALUE = 0 as *mut ASN1_VALUE;
    if pval.is_null() {
        pval = &mut ptmpval;
    }
    if asn1_item_ex_d2i(
        pval,
        in_0,
        len,
        it,
        -(1 as libc::c_int),
        0 as libc::c_int,
        0 as libc::c_int as libc::c_char,
        0 as libc::c_int,
    ) > 0 as libc::c_int
    {
        return *pval;
    }
    return 0 as *mut ASN1_VALUE;
}
unsafe extern "C" fn asn1_item_ex_d2i(
    mut pval: *mut *mut ASN1_VALUE,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
    mut it: *const ASN1_ITEM,
    mut tag: libc::c_int,
    mut aclass: libc::c_int,
    mut opt: libc::c_char,
    mut depth: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut tt: *const ASN1_TEMPLATE = 0 as *const ASN1_TEMPLATE;
    let mut errtt: *const ASN1_TEMPLATE = 0 as *const ASN1_TEMPLATE;
    let mut ef: *const ASN1_EXTERN_FUNCS = 0 as *const ASN1_EXTERN_FUNCS;
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut q: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut oclass: libc::c_uchar = 0;
    let mut seq_eoc: libc::c_char = 0;
    let mut seq_nolen: libc::c_char = 0;
    let mut cst: libc::c_char = 0;
    let mut isopt: libc::c_char = 0;
    let mut i: libc::c_int = 0;
    let mut otag: libc::c_int = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut pchptr: *mut *mut ASN1_VALUE = 0 as *mut *mut ASN1_VALUE;
    let mut combine: libc::c_int = aclass & (0x1 as libc::c_int) << 10 as libc::c_int;
    aclass &= !((0x1 as libc::c_int) << 10 as libc::c_int);
    if pval.is_null() || it.is_null() {
        return 0 as libc::c_int;
    }
    if len > (2147483647 as libc::c_int / 2 as libc::c_int) as libc::c_long {
        len = (2147483647 as libc::c_int / 2 as libc::c_int) as libc::c_long;
    }
    depth += 1;
    if depth > 30 as libc::c_int {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            192 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0" as *const u8
                as *const libc::c_char,
            192 as libc::c_int as libc::c_uint,
        );
    } else {
        match (*it).itype as libc::c_int {
            0 => {
                if !((*it).templates).is_null() {
                    if tag != -(1 as libc::c_int) || opt as libc::c_int != 0 {
                        ERR_put_error(
                            12 as libc::c_int,
                            0 as libc::c_int,
                            136 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                                as *const u8 as *const libc::c_char,
                            204 as libc::c_int as libc::c_uint,
                        );
                    } else {
                        return asn1_template_ex_d2i(
                            pval,
                            in_0,
                            len,
                            (*it).templates,
                            opt,
                            depth,
                        )
                    }
                } else {
                    return asn1_d2i_ex_primitive(pval, in_0, len, it, tag, aclass, opt)
                }
                current_block = 9880012379187514808;
            }
            5 => {
                if tag != -(1 as libc::c_int) {
                    ERR_put_error(
                        12 as libc::c_int,
                        0 as libc::c_int,
                        193 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                            as *const u8 as *const libc::c_char,
                        216 as libc::c_int as libc::c_uint,
                    );
                } else {
                    p = *in_0;
                    ret = asn1_check_tlen(
                        0 as *mut libc::c_long,
                        &mut otag,
                        &mut oclass,
                        0 as *mut libc::c_char,
                        0 as *mut libc::c_char,
                        &mut p,
                        len,
                        -(1 as libc::c_int),
                        0 as libc::c_int,
                        1 as libc::c_int as libc::c_char,
                    );
                    if ret == 0 {
                        ERR_put_error(
                            12 as libc::c_int,
                            0 as libc::c_int,
                            158 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                                as *const u8 as *const libc::c_char,
                            224 as libc::c_int as libc::c_uint,
                        );
                    } else if oclass as libc::c_int != 0 as libc::c_int {
                        if opt != 0 {
                            return -(1 as libc::c_int);
                        }
                        ERR_put_error(
                            12 as libc::c_int,
                            0 as libc::c_int,
                            156 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                                as *const u8 as *const libc::c_char,
                            234 as libc::c_int as libc::c_uint,
                        );
                    } else if ASN1_tag2bit(otag) & (*it).utype as libc::c_ulong == 0 {
                        if opt != 0 {
                            return -(1 as libc::c_int);
                        }
                        ERR_put_error(
                            12 as libc::c_int,
                            0 as libc::c_int,
                            157 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                                as *const u8 as *const libc::c_char,
                            243 as libc::c_int as libc::c_uint,
                        );
                    } else {
                        return asn1_d2i_ex_primitive(
                            pval,
                            in_0,
                            len,
                            it,
                            otag,
                            0 as libc::c_int,
                            0 as libc::c_int as libc::c_char,
                        )
                    }
                }
                current_block = 9880012379187514808;
            }
            4 => {
                ef = (*it).funcs as *const ASN1_EXTERN_FUNCS;
                return ((*ef).asn1_ex_d2i)
                    .expect(
                        "non-null function pointer",
                    )(pval, in_0, len, it, tag, aclass, opt, 0 as *mut ASN1_TLC);
            }
            2 => {
                if tag != -(1 as libc::c_int) {
                    ERR_put_error(
                        12 as libc::c_int,
                        0 as libc::c_int,
                        193 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                            as *const u8 as *const libc::c_char,
                        257 as libc::c_int as libc::c_uint,
                    );
                    current_block = 9880012379187514808;
                } else {
                    let mut aux: *const ASN1_AUX = (*it).funcs as *const ASN1_AUX;
                    let mut asn1_cb: Option::<ASN1_aux_cb> = if !aux.is_null() {
                        (*aux).asn1_cb
                    } else {
                        None
                    };
                    if asn1_cb.is_some()
                        && asn1_cb
                            .expect(
                                "non-null function pointer",
                            )(4 as libc::c_int, pval, it, 0 as *mut libc::c_void) == 0
                    {
                        current_block = 14769993299645295149;
                    } else {
                        if !(*pval).is_null() {
                            i = asn1_get_choice_selector(pval, it);
                            if i >= 0 as libc::c_int
                                && (i as libc::c_long) < (*it).tcount
                            {
                                tt = ((*it).templates).offset(i as isize);
                                pchptr = asn1_get_field_ptr(pval, tt);
                                ASN1_template_free(pchptr, tt);
                                asn1_set_choice_selector(pval, -(1 as libc::c_int), it);
                            }
                            current_block = 14447253356787937536;
                        } else if ASN1_item_ex_new(pval, it) == 0 {
                            ERR_put_error(
                                12 as libc::c_int,
                                0 as libc::c_int,
                                158 as libc::c_int,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                                    as *const u8 as *const libc::c_char,
                                277 as libc::c_int as libc::c_uint,
                            );
                            current_block = 9880012379187514808;
                        } else {
                            current_block = 14447253356787937536;
                        }
                        match current_block {
                            9880012379187514808 => {}
                            _ => {
                                p = *in_0;
                                i = 0 as libc::c_int;
                                tt = (*it).templates;
                                loop {
                                    if !((i as libc::c_long) < (*it).tcount) {
                                        current_block = 2290177392965769716;
                                        break;
                                    }
                                    pchptr = asn1_get_field_ptr(pval, tt);
                                    ret = asn1_template_ex_d2i(
                                        pchptr,
                                        &mut p,
                                        len,
                                        tt,
                                        1 as libc::c_int as libc::c_char,
                                        depth,
                                    );
                                    if ret == -(1 as libc::c_int) {
                                        i += 1;
                                        i;
                                        tt = tt.offset(1);
                                        tt;
                                    } else {
                                        if ret > 0 as libc::c_int {
                                            current_block = 2290177392965769716;
                                            break;
                                        }
                                        errtt = tt;
                                        ERR_put_error(
                                            12 as libc::c_int,
                                            0 as libc::c_int,
                                            158 as libc::c_int,
                                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                                                as *const u8 as *const libc::c_char,
                                            296 as libc::c_int as libc::c_uint,
                                        );
                                        current_block = 9880012379187514808;
                                        break;
                                    }
                                }
                                match current_block {
                                    9880012379187514808 => {}
                                    _ => {
                                        if i as libc::c_long == (*it).tcount {
                                            if opt != 0 {
                                                ASN1_item_ex_free(pval, it);
                                                return -(1 as libc::c_int);
                                            }
                                            ERR_put_error(
                                                12 as libc::c_int,
                                                0 as libc::c_int,
                                                163 as libc::c_int,
                                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                                                    as *const u8 as *const libc::c_char,
                                                308 as libc::c_int as libc::c_uint,
                                            );
                                            current_block = 9880012379187514808;
                                        } else {
                                            asn1_set_choice_selector(pval, i, it);
                                            if asn1_cb.is_some()
                                                && asn1_cb
                                                    .expect(
                                                        "non-null function pointer",
                                                    )(5 as libc::c_int, pval, it, 0 as *mut libc::c_void) == 0
                                            {
                                                current_block = 14769993299645295149;
                                            } else {
                                                *in_0 = p;
                                                return 1 as libc::c_int;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            1 => {
                p = *in_0;
                if tag == -(1 as libc::c_int) {
                    tag = 16 as libc::c_int;
                    aclass = 0 as libc::c_int;
                }
                ret = asn1_check_tlen(
                    &mut len,
                    0 as *mut libc::c_int,
                    0 as *mut libc::c_uchar,
                    &mut seq_eoc,
                    &mut cst,
                    &mut p,
                    len,
                    tag,
                    aclass,
                    opt,
                );
                if ret == 0 {
                    ERR_put_error(
                        12 as libc::c_int,
                        0 as libc::c_int,
                        158 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                            as *const u8 as *const libc::c_char,
                        331 as libc::c_int as libc::c_uint,
                    );
                    current_block = 9880012379187514808;
                } else {
                    if ret == -(1 as libc::c_int) {
                        return -(1 as libc::c_int);
                    }
                    seq_nolen = seq_eoc;
                    if cst == 0 {
                        ERR_put_error(
                            12 as libc::c_int,
                            0 as libc::c_int,
                            169 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                                as *const u8 as *const libc::c_char,
                            339 as libc::c_int as libc::c_uint,
                        );
                        current_block = 9880012379187514808;
                    } else if (*pval).is_null() && ASN1_item_ex_new(pval, it) == 0 {
                        ERR_put_error(
                            12 as libc::c_int,
                            0 as libc::c_int,
                            158 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                                as *const u8 as *const libc::c_char,
                            344 as libc::c_int as libc::c_uint,
                        );
                        current_block = 9880012379187514808;
                    } else {
                        let mut aux_0: *const ASN1_AUX = (*it).funcs as *const ASN1_AUX;
                        let mut asn1_cb_0: Option::<ASN1_aux_cb> = if !aux_0.is_null() {
                            (*aux_0).asn1_cb
                        } else {
                            None
                        };
                        if asn1_cb_0.is_some()
                            && asn1_cb_0
                                .expect(
                                    "non-null function pointer",
                                )(4 as libc::c_int, pval, it, 0 as *mut libc::c_void) == 0
                        {
                            current_block = 14769993299645295149;
                        } else {
                            i = 0 as libc::c_int;
                            tt = (*it).templates;
                            while (i as libc::c_long) < (*it).tcount {
                                if (*tt).flags
                                    & ((0x3 as libc::c_int) << 8 as libc::c_int) as uint32_t
                                    != 0
                                {
                                    let mut seqtt: *const ASN1_TEMPLATE = 0
                                        as *const ASN1_TEMPLATE;
                                    let mut pseqval: *mut *mut ASN1_VALUE = 0
                                        as *mut *mut ASN1_VALUE;
                                    seqtt = asn1_do_adb(pval, tt, 0 as libc::c_int);
                                    if !seqtt.is_null() {
                                        pseqval = asn1_get_field_ptr(pval, seqtt);
                                        ASN1_template_free(pseqval, seqtt);
                                    }
                                }
                                i += 1;
                                i;
                                tt = tt.offset(1);
                                tt;
                            }
                            i = 0 as libc::c_int;
                            tt = (*it).templates;
                            loop {
                                if !((i as libc::c_long) < (*it).tcount) {
                                    current_block = 11064061988481400464;
                                    break;
                                }
                                let mut seqtt_0: *const ASN1_TEMPLATE = 0
                                    as *const ASN1_TEMPLATE;
                                let mut pseqval_0: *mut *mut ASN1_VALUE = 0
                                    as *mut *mut ASN1_VALUE;
                                seqtt_0 = asn1_do_adb(pval, tt, 1 as libc::c_int);
                                if seqtt_0.is_null() {
                                    current_block = 9880012379187514808;
                                    break;
                                }
                                pseqval_0 = asn1_get_field_ptr(pval, seqtt_0);
                                if len == 0 {
                                    current_block = 11064061988481400464;
                                    break;
                                }
                                q = p;
                                if asn1_check_eoc(&mut p, len) != 0 {
                                    if seq_eoc == 0 {
                                        ERR_put_error(
                                            12 as libc::c_int,
                                            0 as libc::c_int,
                                            180 as libc::c_int,
                                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                                                as *const u8 as *const libc::c_char,
                                            388 as libc::c_int as libc::c_uint,
                                        );
                                        current_block = 9880012379187514808;
                                        break;
                                    } else {
                                        len -= p.offset_from(q) as libc::c_long;
                                        seq_eoc = 0 as libc::c_int as libc::c_char;
                                        current_block = 11064061988481400464;
                                        break;
                                    }
                                } else {
                                    if i as libc::c_long
                                        == (*it).tcount - 1 as libc::c_int as libc::c_long
                                    {
                                        isopt = 0 as libc::c_int as libc::c_char;
                                    } else {
                                        isopt = ((*seqtt_0).flags & 0x1 as libc::c_int as uint32_t
                                            != 0 as libc::c_int as uint32_t) as libc::c_int
                                            as libc::c_char;
                                    }
                                    ret = asn1_template_ex_d2i(
                                        pseqval_0,
                                        &mut p,
                                        len,
                                        seqtt_0,
                                        isopt,
                                        depth,
                                    );
                                    if ret == 0 {
                                        errtt = seqtt_0;
                                        current_block = 9880012379187514808;
                                        break;
                                    } else {
                                        if ret == -(1 as libc::c_int) {
                                            ASN1_template_free(pseqval_0, seqtt_0);
                                        } else {
                                            len -= p.offset_from(q) as libc::c_long;
                                        }
                                        i += 1;
                                        i;
                                        tt = tt.offset(1);
                                        tt;
                                    }
                                }
                            }
                            match current_block {
                                9880012379187514808 => {}
                                _ => {
                                    if seq_eoc as libc::c_int != 0
                                        && asn1_check_eoc(&mut p, len) == 0
                                    {
                                        ERR_put_error(
                                            12 as libc::c_int,
                                            0 as libc::c_int,
                                            153 as libc::c_int,
                                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                                                as *const u8 as *const libc::c_char,
                                            421 as libc::c_int as libc::c_uint,
                                        );
                                        current_block = 9880012379187514808;
                                    } else if seq_nolen == 0 && len != 0 {
                                        ERR_put_error(
                                            12 as libc::c_int,
                                            0 as libc::c_int,
                                            168 as libc::c_int,
                                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                                                as *const u8 as *const libc::c_char,
                                            426 as libc::c_int as libc::c_uint,
                                        );
                                        current_block = 9880012379187514808;
                                    } else {
                                        loop {
                                            if !((i as libc::c_long) < (*it).tcount) {
                                                current_block = 13014351284863956202;
                                                break;
                                            }
                                            let mut seqtt_1: *const ASN1_TEMPLATE = 0
                                                as *const ASN1_TEMPLATE;
                                            seqtt_1 = asn1_do_adb(pval, tt, 1 as libc::c_int);
                                            if seqtt_1.is_null() {
                                                current_block = 9880012379187514808;
                                                break;
                                            }
                                            if (*seqtt_1).flags & 0x1 as libc::c_int as uint32_t != 0 {
                                                let mut pseqval_1: *mut *mut ASN1_VALUE = 0
                                                    as *mut *mut ASN1_VALUE;
                                                pseqval_1 = asn1_get_field_ptr(pval, seqtt_1);
                                                ASN1_template_free(pseqval_1, seqtt_1);
                                                tt = tt.offset(1);
                                                tt;
                                                i += 1;
                                                i;
                                            } else {
                                                errtt = seqtt_1;
                                                ERR_put_error(
                                                    12 as libc::c_int,
                                                    0 as libc::c_int,
                                                    121 as libc::c_int,
                                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                                                        as *const u8 as *const libc::c_char,
                                                    445 as libc::c_int as libc::c_uint,
                                                );
                                                current_block = 9880012379187514808;
                                                break;
                                            }
                                        }
                                        match current_block {
                                            9880012379187514808 => {}
                                            _ => {
                                                if asn1_enc_save(
                                                    pval,
                                                    *in_0,
                                                    p.offset_from(*in_0) as libc::c_long as libc::c_int,
                                                    it,
                                                ) == 0
                                                {
                                                    current_block = 14769993299645295149;
                                                } else if asn1_cb_0.is_some()
                                                    && asn1_cb_0
                                                        .expect(
                                                            "non-null function pointer",
                                                        )(5 as libc::c_int, pval, it, 0 as *mut libc::c_void) == 0
                                                {
                                                    current_block = 14769993299645295149;
                                                } else {
                                                    *in_0 = p;
                                                    return 1 as libc::c_int;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => return 0 as libc::c_int,
        }
        match current_block {
            9880012379187514808 => {}
            _ => {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    101 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                        as *const u8 as *const libc::c_char,
                    464 as libc::c_int as libc::c_uint,
                );
            }
        }
    }
    if combine == 0 as libc::c_int {
        ASN1_item_ex_free(pval, it);
    }
    if !errtt.is_null() {
        ERR_add_error_data(
            4 as libc::c_int as libc::c_uint,
            b"Field=\0" as *const u8 as *const libc::c_char,
            (*errtt).field_name,
            b", Type=\0" as *const u8 as *const libc::c_char,
            (*it).sname,
        );
    } else {
        ERR_add_error_data(
            2 as libc::c_int as libc::c_uint,
            b"Type=\0" as *const u8 as *const libc::c_char,
            (*it).sname,
        );
    }
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_item_ex_d2i(
    mut pval: *mut *mut ASN1_VALUE,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
    mut it: *const ASN1_ITEM,
    mut tag: libc::c_int,
    mut aclass: libc::c_int,
    mut opt: libc::c_char,
    mut ctx: *mut ASN1_TLC,
) -> libc::c_int {
    return asn1_item_ex_d2i(pval, in_0, len, it, tag, aclass, opt, 0 as libc::c_int);
}
unsafe extern "C" fn asn1_template_ex_d2i(
    mut val: *mut *mut ASN1_VALUE,
    mut in_0: *mut *const libc::c_uchar,
    mut inlen: libc::c_long,
    mut tt: *const ASN1_TEMPLATE,
    mut opt: libc::c_char,
    mut depth: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut aclass: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    let mut len: libc::c_long = 0;
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut q: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut exp_eoc: libc::c_char = 0;
    if val.is_null() {
        return 0 as libc::c_int;
    }
    let mut flags: uint32_t = (*tt).flags;
    aclass = (flags & ((0x3 as libc::c_int) << 6 as libc::c_int) as uint32_t)
        as libc::c_int;
    p = *in_0;
    if flags & ((0x2 as libc::c_int) << 3 as libc::c_int) as uint32_t != 0 {
        let mut cst: libc::c_char = 0;
        ret = asn1_check_tlen(
            &mut len,
            0 as *mut libc::c_int,
            0 as *mut libc::c_uchar,
            &mut exp_eoc,
            &mut cst,
            &mut p,
            inlen,
            (*tt).tag,
            aclass,
            opt,
        );
        q = p;
        if ret == 0 {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                158 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                    as *const u8 as *const libc::c_char,
                511 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        } else if ret == -(1 as libc::c_int) {
            return -(1 as libc::c_int)
        }
        if cst == 0 {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                120 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                    as *const u8 as *const libc::c_char,
                517 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        ret = asn1_template_noexp_d2i(
            val,
            &mut p,
            len,
            tt,
            0 as libc::c_int as libc::c_char,
            depth,
        );
        if ret == 0 {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                158 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                    as *const u8 as *const libc::c_char,
                523 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        len -= p.offset_from(q) as libc::c_long;
        if exp_eoc != 0 {
            if asn1_check_eoc(&mut p, len) == 0 {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    153 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                        as *const u8 as *const libc::c_char,
                    531 as libc::c_int as libc::c_uint,
                );
                current_block = 5242335211611766135;
            } else {
                current_block = 15125582407903384992;
            }
        } else if len != 0 {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                119 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                    as *const u8 as *const libc::c_char,
                537 as libc::c_int as libc::c_uint,
            );
            current_block = 5242335211611766135;
        } else {
            current_block = 15125582407903384992;
        }
        match current_block {
            5242335211611766135 => {
                ASN1_template_free(val, tt);
                return 0 as libc::c_int;
            }
            _ => {
                *in_0 = p;
                return 1 as libc::c_int;
            }
        }
    } else {
        return asn1_template_noexp_d2i(val, in_0, inlen, tt, opt, depth)
    };
}
unsafe extern "C" fn asn1_template_noexp_d2i(
    mut val: *mut *mut ASN1_VALUE,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
    mut tt: *const ASN1_TEMPLATE,
    mut opt: libc::c_char,
    mut depth: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut aclass: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    if val.is_null() {
        return 0 as libc::c_int;
    }
    let mut flags: uint32_t = (*tt).flags;
    aclass = (flags & ((0x3 as libc::c_int) << 6 as libc::c_int) as uint32_t)
        as libc::c_int;
    p = *in_0;
    if flags & ((0x3 as libc::c_int) << 1 as libc::c_int) as uint32_t != 0 {
        let mut sktag: libc::c_int = 0;
        let mut skaclass: libc::c_int = 0;
        let mut sk_eoc: libc::c_char = 0;
        if flags & ((0x1 as libc::c_int) << 3 as libc::c_int) as uint32_t != 0 {
            sktag = (*tt).tag;
            skaclass = aclass;
        } else {
            skaclass = 0 as libc::c_int;
            if flags & ((0x1 as libc::c_int) << 1 as libc::c_int) as uint32_t != 0 {
                sktag = 17 as libc::c_int;
            } else {
                sktag = 16 as libc::c_int;
            }
        }
        ret = asn1_check_tlen(
            &mut len,
            0 as *mut libc::c_int,
            0 as *mut libc::c_uchar,
            &mut sk_eoc,
            0 as *mut libc::c_char,
            &mut p,
            len,
            sktag,
            skaclass,
            opt,
        );
        if ret == 0 {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                158 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                    as *const u8 as *const libc::c_char,
                587 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        } else if ret == -(1 as libc::c_int) {
            return -(1 as libc::c_int)
        }
        if (*val).is_null() {
            *val = sk_ASN1_VALUE_new_null() as *mut ASN1_VALUE;
        } else {
            let mut sktmp: *mut stack_st_ASN1_VALUE = *val as *mut stack_st_ASN1_VALUE;
            let mut vtmp: *mut ASN1_VALUE = 0 as *mut ASN1_VALUE;
            while sk_ASN1_VALUE_num(sktmp) > 0 as libc::c_int as size_t {
                vtmp = sk_ASN1_VALUE_pop(sktmp);
                ASN1_item_ex_free(&mut vtmp, (*tt).item);
            }
        }
        if (*val).is_null() {
            current_block = 15337328390004930598;
        } else {
            loop {
                if !(len > 0 as libc::c_int as libc::c_long) {
                    current_block = 572715077006366937;
                    break;
                }
                let mut skfield: *mut ASN1_VALUE = 0 as *mut ASN1_VALUE;
                let mut q: *const libc::c_uchar = p;
                if asn1_check_eoc(&mut p, len) != 0 {
                    if sk_eoc == 0 {
                        ERR_put_error(
                            12 as libc::c_int,
                            0 as libc::c_int,
                            180 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                                as *const u8 as *const libc::c_char,
                            615 as libc::c_int as libc::c_uint,
                        );
                        current_block = 15337328390004930598;
                        break;
                    } else {
                        len -= p.offset_from(q) as libc::c_long;
                        sk_eoc = 0 as libc::c_int as libc::c_char;
                        current_block = 572715077006366937;
                        break;
                    }
                } else {
                    skfield = 0 as *mut ASN1_VALUE;
                    if asn1_item_ex_d2i(
                        &mut skfield,
                        &mut p,
                        len,
                        (*tt).item,
                        -(1 as libc::c_int),
                        0 as libc::c_int,
                        0 as libc::c_int as libc::c_char,
                        depth,
                    ) == 0
                    {
                        ERR_put_error(
                            12 as libc::c_int,
                            0 as libc::c_int,
                            158 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                                as *const u8 as *const libc::c_char,
                            625 as libc::c_int as libc::c_uint,
                        );
                        current_block = 15337328390004930598;
                        break;
                    } else {
                        len -= p.offset_from(q) as libc::c_long;
                        if !(sk_ASN1_VALUE_push(
                            *val as *mut stack_st_ASN1_VALUE,
                            skfield,
                        ) == 0)
                        {
                            continue;
                        }
                        ASN1_item_ex_free(&mut skfield, (*tt).item);
                        current_block = 15337328390004930598;
                        break;
                    }
                }
            }
            match current_block {
                15337328390004930598 => {}
                _ => {
                    if sk_eoc != 0 {
                        ERR_put_error(
                            12 as libc::c_int,
                            0 as libc::c_int,
                            153 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                                as *const u8 as *const libc::c_char,
                            635 as libc::c_int as libc::c_uint,
                        );
                        current_block = 15337328390004930598;
                    } else {
                        current_block = 10753070352654377903;
                    }
                }
            }
        }
    } else if flags & ((0x1 as libc::c_int) << 3 as libc::c_int) as uint32_t != 0 {
        ret = asn1_item_ex_d2i(
            val,
            &mut p,
            len,
            (*tt).item,
            (*tt).tag,
            aclass,
            opt,
            depth,
        );
        if ret == 0 {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                158 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                    as *const u8 as *const libc::c_char,
                643 as libc::c_int as libc::c_uint,
            );
            current_block = 15337328390004930598;
        } else {
            if ret == -(1 as libc::c_int) {
                return -(1 as libc::c_int);
            }
            current_block = 10753070352654377903;
        }
    } else {
        ret = asn1_item_ex_d2i(
            val,
            &mut p,
            len,
            (*tt).item,
            -(1 as libc::c_int),
            ((*tt).flags & ((0x1 as libc::c_int) << 10 as libc::c_int) as uint32_t)
                as libc::c_int,
            opt,
            depth,
        );
        if ret == 0 {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                158 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                    as *const u8 as *const libc::c_char,
                653 as libc::c_int as libc::c_uint,
            );
            current_block = 15337328390004930598;
        } else {
            if ret == -(1 as libc::c_int) {
                return -(1 as libc::c_int);
            }
            current_block = 10753070352654377903;
        }
    }
    match current_block {
        15337328390004930598 => {
            ASN1_template_free(val, tt);
            return 0 as libc::c_int;
        }
        _ => {
            *in_0 = p;
            return 1 as libc::c_int;
        }
    };
}
unsafe extern "C" fn asn1_d2i_ex_primitive(
    mut pval: *mut *mut ASN1_VALUE,
    mut in_0: *mut *const libc::c_uchar,
    mut inlen: libc::c_long,
    mut it: *const ASN1_ITEM,
    mut tag: libc::c_int,
    mut aclass: libc::c_int,
    mut opt: libc::c_char,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut utype: libc::c_int = 0;
    let mut plen: libc::c_long = 0;
    let mut cst: libc::c_char = 0;
    let mut inf: libc::c_char = 0;
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut buf: BUF_MEM = {
        let mut init = buf_mem_st {
            length: 0 as libc::c_int as size_t,
            data: 0 as *mut libc::c_char,
            max: 0 as libc::c_int as size_t,
        };
        init
    };
    let mut cont: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut len: libc::c_long = 0;
    if pval.is_null() {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            132 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0" as *const u8
                as *const libc::c_char,
            679 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if (*it).itype as libc::c_int == 0x5 as libc::c_int {
        utype = tag;
        tag = -(1 as libc::c_int);
    } else {
        utype = (*it).utype;
    }
    if utype == -(4 as libc::c_int) {
        let mut oclass: libc::c_uchar = 0;
        if tag >= 0 as libc::c_int {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                137 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                    as *const u8 as *const libc::c_char,
                694 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        if opt != 0 {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                135 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                    as *const u8 as *const libc::c_char,
                698 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        p = *in_0;
        ret = asn1_check_tlen(
            0 as *mut libc::c_long,
            &mut utype,
            &mut oclass,
            0 as *mut libc::c_char,
            0 as *mut libc::c_char,
            &mut p,
            inlen,
            -(1 as libc::c_int),
            0 as libc::c_int,
            0 as libc::c_int as libc::c_char,
        );
        if ret == 0 {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                158 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                    as *const u8 as *const libc::c_char,
                704 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        if oclass as libc::c_int != 0 as libc::c_int {
            utype = -(3 as libc::c_int);
        }
    }
    if tag == -(1 as libc::c_int) {
        tag = utype;
        aclass = 0 as libc::c_int;
    }
    p = *in_0;
    ret = asn1_check_tlen(
        &mut plen,
        0 as *mut libc::c_int,
        0 as *mut libc::c_uchar,
        &mut inf,
        &mut cst,
        &mut p,
        inlen,
        tag,
        aclass,
        opt,
    );
    if ret == 0 {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            158 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0" as *const u8
                as *const libc::c_char,
            719 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    } else if ret == -(1 as libc::c_int) {
        return -(1 as libc::c_int)
    }
    ret = 0 as libc::c_int;
    if utype == 16 as libc::c_int || utype == 17 as libc::c_int
        || utype == -(3 as libc::c_int)
    {
        if utype != -(3 as libc::c_int) && cst == 0 {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                178 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                    as *const u8 as *const libc::c_char,
                730 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        cont = *in_0;
        if inf != 0 {
            if asn1_find_end(&mut p, plen, inf) == 0 {
                current_block = 3497998799668128320;
            } else {
                len = p.offset_from(cont) as libc::c_long;
                current_block = 10930818133215224067;
            }
        } else {
            len = p.offset_from(cont) as libc::c_long + plen;
            p = p.offset(plen as isize);
            current_block = 10930818133215224067;
        }
    } else if cst != 0 {
        if utype == 5 as libc::c_int || utype == 1 as libc::c_int
            || utype == 6 as libc::c_int || utype == 2 as libc::c_int
            || utype == 10 as libc::c_int
        {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                179 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                    as *const u8 as *const libc::c_char,
                750 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        if asn1_collect(
            &mut buf,
            &mut p,
            plen,
            inf,
            -(1 as libc::c_int),
            0 as libc::c_int,
            0 as libc::c_int,
        ) == 0
        {
            current_block = 3497998799668128320;
        } else {
            len = buf.length as libc::c_long;
            if BUF_MEM_grow_clean(
                &mut buf,
                (len + 1 as libc::c_int as libc::c_long) as size_t,
            ) == 0
            {
                current_block = 3497998799668128320;
            } else {
                *(buf.data).offset(len as isize) = 0 as libc::c_int as libc::c_char;
                cont = buf.data as *const libc::c_uchar;
                current_block = 10930818133215224067;
            }
        }
    } else {
        cont = p;
        len = plen;
        p = p.offset(plen as isize);
        current_block = 10930818133215224067;
    }
    match current_block {
        10930818133215224067 => {
            if !(asn1_ex_c2i(pval, cont, len, utype, it) == 0) {
                *in_0 = p;
                ret = 1 as libc::c_int;
            }
        }
        _ => {}
    }
    OPENSSL_free(buf.data as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn asn1_ex_c2i(
    mut pval: *mut *mut ASN1_VALUE,
    mut cont: *const libc::c_uchar,
    mut len: libc::c_long,
    mut utype: libc::c_int,
    mut it: *const ASN1_ITEM,
) -> libc::c_int {
    let mut current_block: u64;
    let mut opval: *mut *mut ASN1_VALUE = 0 as *mut *mut ASN1_VALUE;
    let mut stmp: *mut ASN1_STRING = 0 as *mut ASN1_STRING;
    let mut typ: *mut ASN1_TYPE = 0 as *mut ASN1_TYPE;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut tint: *mut *mut ASN1_INTEGER = 0 as *mut *mut ASN1_INTEGER;
    if ((*it).funcs).is_null() {} else {
        __assert_fail(
            b"it->funcs == NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0" as *const u8
                as *const libc::c_char,
            798 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 84],
                &[libc::c_char; 84],
            >(
                b"int asn1_ex_c2i(ASN1_VALUE **, const unsigned char *, long, int, const ASN1_ITEM *)\0",
            ))
                .as_ptr(),
        );
    }
    'c_9766: {
        if ((*it).funcs).is_null() {} else {
            __assert_fail(
                b"it->funcs == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                    as *const u8 as *const libc::c_char,
                798 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 84],
                    &[libc::c_char; 84],
                >(
                    b"int asn1_ex_c2i(ASN1_VALUE **, const unsigned char *, long, int, const ASN1_ITEM *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if (*it).utype == -(4 as libc::c_int) {
        if (*pval).is_null() {
            typ = ASN1_TYPE_new();
            if typ.is_null() {
                current_block = 9147315512420056907;
            } else {
                *pval = typ as *mut ASN1_VALUE;
                current_block = 8515828400728868193;
            }
        } else {
            typ = *pval as *mut ASN1_TYPE;
            current_block = 8515828400728868193;
        }
        match current_block {
            9147315512420056907 => {}
            _ => {
                if utype != (*typ).type_0 {
                    ASN1_TYPE_set(typ, utype, 0 as *mut libc::c_void);
                }
                opval = pval;
                pval = &mut (*typ).value.asn1_value;
                current_block = 11050875288958768710;
            }
        }
    } else {
        current_block = 11050875288958768710;
    }
    match current_block {
        11050875288958768710 => {
            match utype {
                6 => {
                    if (c2i_ASN1_OBJECT(pval as *mut *mut ASN1_OBJECT, &mut cont, len))
                        .is_null()
                    {
                        current_block = 9147315512420056907;
                    } else {
                        current_block = 13303144130133872306;
                    }
                }
                5 => {
                    if len != 0 {
                        ERR_put_error(
                            12 as libc::c_int,
                            0 as libc::c_int,
                            164 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                                as *const u8 as *const libc::c_char,
                            827 as libc::c_int as libc::c_uint,
                        );
                        current_block = 9147315512420056907;
                    } else {
                        *pval = 1 as libc::c_int as *mut ASN1_VALUE;
                        current_block = 13303144130133872306;
                    }
                }
                1 => {
                    if len != 1 as libc::c_int as libc::c_long {
                        ERR_put_error(
                            12 as libc::c_int,
                            0 as libc::c_int,
                            106 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                                as *const u8 as *const libc::c_char,
                            835 as libc::c_int as libc::c_uint,
                        );
                        current_block = 9147315512420056907;
                    } else {
                        let mut tbool: *mut ASN1_BOOLEAN = 0 as *mut ASN1_BOOLEAN;
                        tbool = pval as *mut ASN1_BOOLEAN;
                        *tbool = *cont as ASN1_BOOLEAN;
                        current_block = 13303144130133872306;
                    }
                }
                3 => {
                    if (c2i_ASN1_BIT_STRING(
                        pval as *mut *mut ASN1_BIT_STRING,
                        &mut cont,
                        len,
                    ))
                        .is_null()
                    {
                        current_block = 9147315512420056907;
                    } else {
                        current_block = 13303144130133872306;
                    }
                }
                2 | 10 => {
                    tint = pval as *mut *mut ASN1_INTEGER;
                    if (c2i_ASN1_INTEGER(tint, &mut cont, len)).is_null() {
                        current_block = 9147315512420056907;
                    } else {
                        (**tint).type_0 = utype | (**tint).type_0 & 0x100 as libc::c_int;
                        current_block = 13303144130133872306;
                    }
                }
                4 | 18 | 19 | 20 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 30 | 12 | -3
                | 17 | 16 | _ => {
                    if utype == 30 as libc::c_int
                        && len & 1 as libc::c_int as libc::c_long != 0
                    {
                        ERR_put_error(
                            12 as libc::c_int,
                            0 as libc::c_int,
                            104 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                                as *const u8 as *const libc::c_char,
                            879 as libc::c_int as libc::c_uint,
                        );
                        current_block = 9147315512420056907;
                    } else if utype == 28 as libc::c_int
                        && len & 3 as libc::c_int as libc::c_long != 0
                    {
                        ERR_put_error(
                            12 as libc::c_int,
                            0 as libc::c_int,
                            181 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                                as *const u8 as *const libc::c_char,
                            883 as libc::c_int as libc::c_uint,
                        );
                        current_block = 9147315512420056907;
                    } else {
                        if utype == 23 as libc::c_int {
                            let mut cbs: CBS = cbs_st {
                                data: 0 as *const uint8_t,
                                len: 0,
                            };
                            CBS_init(&mut cbs, cont, len as size_t);
                            if CBS_parse_utc_time(
                                &mut cbs,
                                0 as *mut tm,
                                1 as libc::c_int,
                            ) == 0
                            {
                                ERR_put_error(
                                    12 as libc::c_int,
                                    0 as libc::c_int,
                                    148 as libc::c_int,
                                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                                        as *const u8 as *const libc::c_char,
                                    890 as libc::c_int as libc::c_uint,
                                );
                                current_block = 9147315512420056907;
                            } else {
                                current_block = 2122094917359643297;
                            }
                        } else {
                            current_block = 2122094917359643297;
                        }
                        match current_block {
                            9147315512420056907 => {}
                            _ => {
                                if utype == 24 as libc::c_int {
                                    let mut cbs_0: CBS = cbs_st {
                                        data: 0 as *const uint8_t,
                                        len: 0,
                                    };
                                    CBS_init(&mut cbs_0, cont, len as size_t);
                                    if CBS_parse_generalized_time(
                                        &mut cbs_0,
                                        0 as *mut tm,
                                        0 as libc::c_int,
                                    ) == 0
                                    {
                                        ERR_put_error(
                                            12 as libc::c_int,
                                            0 as libc::c_int,
                                            148 as libc::c_int,
                                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                                                as *const u8 as *const libc::c_char,
                                            899 as libc::c_int as libc::c_uint,
                                        );
                                        current_block = 9147315512420056907;
                                    } else {
                                        current_block = 5891011138178424807;
                                    }
                                } else {
                                    current_block = 5891011138178424807;
                                }
                                match current_block {
                                    9147315512420056907 => {}
                                    _ => {
                                        if (*pval).is_null() {
                                            stmp = ASN1_STRING_type_new(utype);
                                            if stmp.is_null() {
                                                current_block = 9147315512420056907;
                                            } else {
                                                *pval = stmp as *mut ASN1_VALUE;
                                                current_block = 16415152177862271243;
                                            }
                                        } else {
                                            stmp = *pval as *mut ASN1_STRING;
                                            (*stmp).type_0 = utype;
                                            current_block = 16415152177862271243;
                                        }
                                        match current_block {
                                            9147315512420056907 => {}
                                            _ => {
                                                if ASN1_STRING_set(stmp, cont as *const libc::c_void, len)
                                                    == 0
                                                {
                                                    ASN1_STRING_free(stmp);
                                                    *pval = 0 as *mut ASN1_VALUE;
                                                    current_block = 9147315512420056907;
                                                } else {
                                                    current_block = 13303144130133872306;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            match current_block {
                9147315512420056907 => {}
                _ => {
                    if !typ.is_null() && utype == 5 as libc::c_int {
                        (*typ).value.ptr = 0 as *mut libc::c_char;
                    }
                    ret = 1 as libc::c_int;
                }
            }
        }
        _ => {}
    }
    if ret == 0 {
        ASN1_TYPE_free(typ);
        if !opval.is_null() {
            *opval = 0 as *mut ASN1_VALUE;
        }
    }
    return ret;
}
unsafe extern "C" fn asn1_find_end(
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
    mut inf: libc::c_char,
) -> libc::c_int {
    let mut expected_eoc: uint32_t = 0;
    let mut plen: libc::c_long = 0;
    let mut p: *const libc::c_uchar = *in_0;
    let mut q: *const libc::c_uchar = 0 as *const libc::c_uchar;
    if inf as libc::c_int == 0 as libc::c_int {
        *in_0 = (*in_0).offset(len as isize);
        return 1 as libc::c_int;
    }
    expected_eoc = 1 as libc::c_int as uint32_t;
    while len > 0 as libc::c_int as libc::c_long {
        if asn1_check_eoc(&mut p, len) != 0 {
            expected_eoc = expected_eoc.wrapping_sub(1);
            expected_eoc;
            if expected_eoc == 0 as libc::c_int as uint32_t {
                break;
            }
            len -= 2 as libc::c_int as libc::c_long;
        } else {
            q = p;
            if asn1_check_tlen(
                &mut plen,
                0 as *mut libc::c_int,
                0 as *mut libc::c_uchar,
                &mut inf,
                0 as *mut libc::c_char,
                &mut p,
                len,
                -(1 as libc::c_int),
                0 as libc::c_int,
                0 as libc::c_int as libc::c_char,
            ) == 0
            {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    158 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                        as *const u8 as *const libc::c_char,
                    968 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            if inf != 0 {
                if expected_eoc == 4294967295 as libc::c_uint {
                    ERR_put_error(
                        12 as libc::c_int,
                        0 as libc::c_int,
                        158 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                            as *const u8 as *const libc::c_char,
                        975 as libc::c_int as libc::c_uint,
                    );
                    return 0 as libc::c_int;
                }
                expected_eoc = expected_eoc.wrapping_add(1);
                expected_eoc;
            } else {
                p = p.offset(plen as isize);
            }
            len -= p.offset_from(q) as libc::c_long;
        }
    }
    if expected_eoc != 0 {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            153 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0" as *const u8
                as *const libc::c_char,
            986 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    *in_0 = p;
    return 1 as libc::c_int;
}
unsafe extern "C" fn asn1_collect(
    mut buf: *mut BUF_MEM,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
    mut inf: libc::c_char,
    mut tag: libc::c_int,
    mut aclass: libc::c_int,
    mut depth: libc::c_int,
) -> libc::c_int {
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut q: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut plen: libc::c_long = 0;
    let mut cst: libc::c_char = 0;
    let mut ininf: libc::c_char = 0;
    p = *in_0;
    inf = (inf as libc::c_int & 1 as libc::c_int) as libc::c_char;
    if buf.is_null() && inf == 0 {
        *in_0 = (*in_0).offset(len as isize);
        return 1 as libc::c_int;
    }
    while len > 0 as libc::c_int as libc::c_long {
        q = p;
        if asn1_check_eoc(&mut p, len) != 0 {
            if inf == 0 {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    180 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                        as *const u8 as *const libc::c_char,
                    1023 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            inf = 0 as libc::c_int as libc::c_char;
            break;
        } else {
            if asn1_check_tlen(
                &mut plen,
                0 as *mut libc::c_int,
                0 as *mut libc::c_uchar,
                &mut ininf,
                &mut cst,
                &mut p,
                len,
                tag,
                aclass,
                0 as libc::c_int as libc::c_char,
            ) == 0
            {
                ERR_put_error(
                    12 as libc::c_int,
                    0 as libc::c_int,
                    158 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                        as *const u8 as *const libc::c_char,
                    1032 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            if cst != 0 {
                if depth >= 5 as libc::c_int {
                    ERR_put_error(
                        12 as libc::c_int,
                        0 as libc::c_int,
                        159 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                            as *const u8 as *const libc::c_char,
                        1039 as libc::c_int as libc::c_uint,
                    );
                    return 0 as libc::c_int;
                }
                if asn1_collect(
                    buf,
                    &mut p,
                    plen,
                    ininf,
                    tag,
                    aclass,
                    depth + 1 as libc::c_int,
                ) == 0
                {
                    return 0 as libc::c_int;
                }
            } else if plen != 0 && collect_data(buf, &mut p, plen) == 0 {
                return 0 as libc::c_int
            }
            len -= p.offset_from(q) as libc::c_long;
        }
    }
    if inf != 0 {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            153 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0" as *const u8
                as *const libc::c_char,
            1051 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    *in_0 = p;
    return 1 as libc::c_int;
}
unsafe extern "C" fn collect_data(
    mut buf: *mut BUF_MEM,
    mut p: *mut *const libc::c_uchar,
    mut plen: libc::c_long,
) -> libc::c_int {
    let mut len: libc::c_int = 0;
    if !buf.is_null() {
        len = (*buf).length as libc::c_int;
        if BUF_MEM_grow_clean(buf, (len as libc::c_long + plen) as size_t) == 0 {
            return 0 as libc::c_int;
        }
        OPENSSL_memcpy(
            ((*buf).data).offset(len as isize) as *mut libc::c_void,
            *p as *const libc::c_void,
            plen as size_t,
        );
    }
    *p = (*p).offset(plen as isize);
    return 1 as libc::c_int;
}
unsafe extern "C" fn asn1_check_eoc(
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> libc::c_int {
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    if len < 2 as libc::c_int as libc::c_long {
        return 0 as libc::c_int;
    }
    p = *in_0;
    if *p.offset(0 as libc::c_int as isize) as libc::c_int == '\0' as i32
        && *p.offset(1 as libc::c_int as isize) as libc::c_int == '\0' as i32
    {
        *in_0 = (*in_0).offset(2 as libc::c_int as isize);
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn asn1_check_tlen(
    mut olen: *mut libc::c_long,
    mut otag: *mut libc::c_int,
    mut oclass: *mut libc::c_uchar,
    mut inf: *mut libc::c_char,
    mut cst: *mut libc::c_char,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
    mut exptag: libc::c_int,
    mut expclass: libc::c_int,
    mut opt: libc::c_char,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut ptag: libc::c_int = 0;
    let mut pclass: libc::c_int = 0;
    let mut plen: libc::c_long = 0;
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut q: *const libc::c_uchar = 0 as *const libc::c_uchar;
    p = *in_0;
    q = p;
    i = ASN1_get_object(&mut p, &mut plen, &mut ptag, &mut pclass, len);
    if i & 0x80 as libc::c_int != 0 {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            103 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0" as *const u8
                as *const libc::c_char,
            1101 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if exptag >= 0 as libc::c_int {
        if exptag != ptag || expclass != pclass {
            if opt != 0 {
                return -(1 as libc::c_int);
            }
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                190 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/tasn_dec.c\0"
                    as *const u8 as *const libc::c_char,
                1110 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
    }
    if i & 1 as libc::c_int != 0 {
        plen = len - p.offset_from(q) as libc::c_long;
    }
    if !inf.is_null() {
        *inf = (i & 1 as libc::c_int) as libc::c_char;
    }
    if !cst.is_null() {
        *cst = (i & 0x20 as libc::c_int) as libc::c_char;
    }
    if !olen.is_null() {
        *olen = plen;
    }
    if !oclass.is_null() {
        *oclass = pclass as libc::c_uchar;
    }
    if !otag.is_null() {
        *otag = ptag;
    }
    *in_0 = p;
    return 1 as libc::c_int;
}
