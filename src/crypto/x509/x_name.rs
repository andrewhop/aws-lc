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
    pub type asn1_pctx_st;
    pub type ASN1_VALUE_st;
    pub type stack_st_X509_NAME_ENTRY;
    pub type stack_st_void;
    pub type stack_st;
    pub type ASN1_TLC_st;
    pub type stack_st_ASN1_VALUE;
    pub type stack_st_STACK_OF_X509_NAME_ENTRY;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn ASN1_tag2bit(tag: libc::c_int) -> libc::c_ulong;
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
    fn ASN1_STRING_copy(dst: *mut ASN1_STRING, str: *const ASN1_STRING) -> libc::c_int;
    fn ASN1_STRING_to_UTF8(
        out: *mut *mut libc::c_uchar,
        in_0: *const ASN1_STRING,
    ) -> libc::c_int;
    static ASN1_OBJECT_it: ASN1_ITEM;
    static ASN1_PRINTABLE_it: ASN1_ITEM;
    fn ASN1_item_ex_d2i(
        pval: *mut *mut ASN1_VALUE,
        in_0: *mut *const libc::c_uchar,
        len: libc::c_long,
        it: *const ASN1_ITEM,
        tag: libc::c_int,
        aclass: libc::c_int,
        opt: libc::c_char,
        ctx: *mut ASN1_TLC,
    ) -> libc::c_int;
    fn ASN1_item_ex_i2d(
        pval: *mut *mut ASN1_VALUE,
        out: *mut *mut libc::c_uchar,
        it: *const ASN1_ITEM,
        tag: libc::c_int,
        aclass: libc::c_int,
    ) -> libc::c_int;
    fn BUF_MEM_new() -> *mut BUF_MEM;
    fn BUF_MEM_free(buf: *mut BUF_MEM);
    fn BUF_MEM_grow(buf: *mut BUF_MEM, len: size_t) -> size_t;
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_set(
        sk: *mut OPENSSL_STACK,
        i: size_t,
        p: *mut libc::c_void,
    ) -> *mut libc::c_void;
    fn OPENSSL_sk_free(sk: *mut OPENSSL_STACK);
    fn OPENSSL_sk_pop_free_ex(
        sk: *mut OPENSSL_STACK,
        call_free_func: OPENSSL_sk_call_free_func,
        free_func: OPENSSL_sk_free_func,
    );
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_tolower(c: libc::c_int) -> libc::c_int;
    fn OPENSSL_isspace(c: libc::c_int) -> libc::c_int;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OBJ_dup(obj: *const ASN1_OBJECT) -> *mut ASN1_OBJECT;
}
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type size_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
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
pub type ASN1_STRING = asn1_string_st;
pub type ASN1_VALUE = ASN1_VALUE_st;
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
pub type CRYPTO_refcount_t = uint32_t;
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
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
pub type BIO_METHOD = bio_method_st;
pub type OPENSSL_sk_free_func = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type OPENSSL_sk_call_free_func = Option::<
    unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
>;
pub type OPENSSL_STACK = stack_st;
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
pub type ASN1_ex_i2d = unsafe extern "C" fn(
    *mut *mut ASN1_VALUE,
    *mut *mut libc::c_uchar,
    *const ASN1_ITEM,
    libc::c_int,
    libc::c_int,
) -> libc::c_int;
pub type ASN1_ex_new_func = unsafe extern "C" fn(
    *mut *mut ASN1_VALUE,
    *const ASN1_ITEM,
) -> libc::c_int;
pub type ASN1_ex_free_func = unsafe extern "C" fn(
    *mut *mut ASN1_VALUE,
    *const ASN1_ITEM,
) -> ();
pub type ASN1_ex_print_func = unsafe extern "C" fn(
    *mut BIO,
    *mut *mut ASN1_VALUE,
    libc::c_int,
    *const libc::c_char,
    *const ASN1_PCTX,
) -> libc::c_int;
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
pub type ASN1_EXTERN_FUNCS = ASN1_EXTERN_FUNCS_st;
pub type sk_X509_NAME_ENTRY_free_func = Option::<
    unsafe extern "C" fn(*mut X509_NAME_ENTRY) -> (),
>;
pub type sk_STACK_OF_X509_NAME_ENTRY_free_func = Option::<
    unsafe extern "C" fn(*mut STACK_OF_X509_NAME_ENTRY) -> (),
>;
pub type STACK_OF_X509_NAME_ENTRY = stack_st_X509_NAME_ENTRY;
#[inline]
unsafe extern "C" fn sk_ASN1_VALUE_num(mut sk: *const stack_st_ASN1_VALUE) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_ASN1_VALUE_value(
    mut sk: *const stack_st_ASN1_VALUE,
    mut i: size_t,
) -> *mut ASN1_VALUE {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut ASN1_VALUE;
}
#[inline]
unsafe extern "C" fn sk_X509_NAME_ENTRY_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<
        OPENSSL_sk_free_func,
        sk_X509_NAME_ENTRY_free_func,
    >(free_func))
        .expect("non-null function pointer")(ptr as *mut X509_NAME_ENTRY);
}
#[inline]
unsafe extern "C" fn sk_X509_NAME_ENTRY_new_null() -> *mut stack_st_X509_NAME_ENTRY {
    return OPENSSL_sk_new_null() as *mut stack_st_X509_NAME_ENTRY;
}
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
unsafe extern "C" fn sk_X509_NAME_ENTRY_set(
    mut sk: *mut stack_st_X509_NAME_ENTRY,
    mut i: size_t,
    mut p: *mut X509_NAME_ENTRY,
) -> *mut X509_NAME_ENTRY {
    return OPENSSL_sk_set(sk as *mut OPENSSL_STACK, i, p as *mut libc::c_void)
        as *mut X509_NAME_ENTRY;
}
#[inline]
unsafe extern "C" fn sk_X509_NAME_ENTRY_free(mut sk: *mut stack_st_X509_NAME_ENTRY) {
    OPENSSL_sk_free(sk as *mut OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_NAME_ENTRY_pop_free(
    mut sk: *mut stack_st_X509_NAME_ENTRY,
    mut free_func: sk_X509_NAME_ENTRY_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_X509_NAME_ENTRY_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_X509_NAME_ENTRY_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_X509_NAME_ENTRY_push(
    mut sk: *mut stack_st_X509_NAME_ENTRY,
    mut p: *mut X509_NAME_ENTRY,
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
#[inline]
unsafe extern "C" fn sk_STACK_OF_X509_NAME_ENTRY_pop_free(
    mut sk: *mut stack_st_STACK_OF_X509_NAME_ENTRY,
    mut free_func: sk_STACK_OF_X509_NAME_ENTRY_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_STACK_OF_X509_NAME_ENTRY_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_STACK_OF_X509_NAME_ENTRY_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_STACK_OF_X509_NAME_ENTRY_push(
    mut sk: *mut stack_st_STACK_OF_X509_NAME_ENTRY,
    mut p: *mut STACK_OF_X509_NAME_ENTRY,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_STACK_OF_X509_NAME_ENTRY_new_null() -> *mut stack_st_STACK_OF_X509_NAME_ENTRY {
    return OPENSSL_sk_new_null() as *mut stack_st_STACK_OF_X509_NAME_ENTRY;
}
#[inline]
unsafe extern "C" fn sk_STACK_OF_X509_NAME_ENTRY_value(
    mut sk: *const stack_st_STACK_OF_X509_NAME_ENTRY,
    mut i: size_t,
) -> *mut STACK_OF_X509_NAME_ENTRY {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i)
        as *mut STACK_OF_X509_NAME_ENTRY;
}
#[inline]
unsafe extern "C" fn sk_STACK_OF_X509_NAME_ENTRY_num(
    mut sk: *const stack_st_STACK_OF_X509_NAME_ENTRY,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_STACK_OF_X509_NAME_ENTRY_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<
        OPENSSL_sk_free_func,
        sk_STACK_OF_X509_NAME_ENTRY_free_func,
    >(free_func))
        .expect("non-null function pointer")(ptr as *mut STACK_OF_X509_NAME_ENTRY);
}
static mut X509_NAME_ENTRY_seq_tt: [ASN1_TEMPLATE; 2] = unsafe {
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
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"value\0" as *const u8 as *const libc::c_char,
                item: &ASN1_PRINTABLE_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[no_mangle]
pub static mut X509_NAME_ENTRY_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_NAME_ENTRY(
    mut a: *const X509_NAME_ENTRY,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &X509_NAME_ENTRY_it);
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_ENTRY_free(mut a: *mut X509_NAME_ENTRY) {
    ASN1_item_free(a as *mut ASN1_VALUE, &X509_NAME_ENTRY_it);
}
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_NAME_ENTRY(
    mut a: *mut *mut X509_NAME_ENTRY,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut X509_NAME_ENTRY {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &X509_NAME_ENTRY_it)
        as *mut X509_NAME_ENTRY;
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_ENTRY_new() -> *mut X509_NAME_ENTRY {
    return ASN1_item_new(&X509_NAME_ENTRY_it) as *mut X509_NAME_ENTRY;
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_ENTRY_dup(
    mut x: *const X509_NAME_ENTRY,
) -> *mut X509_NAME_ENTRY {
    return ASN1_item_dup(&X509_NAME_ENTRY_it, x as *mut libc::c_void)
        as *mut X509_NAME_ENTRY;
}
static mut X509_NAME_ENTRIES_item_tt: ASN1_TEMPLATE = unsafe {
    {
        let mut init = ASN1_TEMPLATE_st {
            flags: ((0x1 as libc::c_int) << 1 as libc::c_int) as uint32_t,
            tag: 0 as libc::c_int,
            offset: 0 as libc::c_int as libc::c_ulong,
            field_name: b"RDNS\0" as *const u8 as *const libc::c_char,
            item: &X509_NAME_ENTRY_it as *const ASN1_ITEM,
        };
        init
    }
};
#[no_mangle]
pub static mut X509_NAME_ENTRIES_it: ASN1_ITEM = unsafe {
    {
        let mut init = ASN1_ITEM_st {
            itype: 0 as libc::c_int as libc::c_char,
            utype: -(1 as libc::c_int),
            templates: &X509_NAME_ENTRIES_item_tt as *const ASN1_TEMPLATE,
            tcount: 0 as libc::c_int as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: 0 as libc::c_int as libc::c_long,
            sname: b"X509_NAME_ENTRIES\0" as *const u8 as *const libc::c_char,
        };
        init
    }
};
static mut X509_NAME_INTERNAL_item_tt: ASN1_TEMPLATE = unsafe {
    {
        let mut init = ASN1_TEMPLATE_st {
            flags: ((0x2 as libc::c_int) << 1 as libc::c_int) as uint32_t,
            tag: 0 as libc::c_int,
            offset: 0 as libc::c_int as libc::c_ulong,
            field_name: b"Name\0" as *const u8 as *const libc::c_char,
            item: &X509_NAME_ENTRIES_it as *const ASN1_ITEM,
        };
        init
    }
};
#[no_mangle]
pub static mut X509_NAME_INTERNAL_it: ASN1_ITEM = unsafe {
    {
        let mut init = ASN1_ITEM_st {
            itype: 0 as libc::c_int as libc::c_char,
            utype: -(1 as libc::c_int),
            templates: &X509_NAME_INTERNAL_item_tt as *const ASN1_TEMPLATE,
            tcount: 0 as libc::c_int as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: 0 as libc::c_int as libc::c_long,
            sname: b"X509_NAME_INTERNAL\0" as *const u8 as *const libc::c_char,
        };
        init
    }
};
static mut x509_name_ff: ASN1_EXTERN_FUNCS = unsafe {
    {
        let mut init = ASN1_EXTERN_FUNCS_st {
            app_data: 0 as *const libc::c_void as *mut libc::c_void,
            asn1_ex_new: Some(
                x509_name_ex_new
                    as unsafe extern "C" fn(
                        *mut *mut ASN1_VALUE,
                        *const ASN1_ITEM,
                    ) -> libc::c_int,
            ),
            asn1_ex_free: Some(
                x509_name_ex_free
                    as unsafe extern "C" fn(*mut *mut ASN1_VALUE, *const ASN1_ITEM) -> (),
            ),
            asn1_ex_d2i: Some(
                x509_name_ex_d2i
                    as unsafe extern "C" fn(
                        *mut *mut ASN1_VALUE,
                        *mut *const libc::c_uchar,
                        libc::c_long,
                        *const ASN1_ITEM,
                        libc::c_int,
                        libc::c_int,
                        libc::c_char,
                        *mut ASN1_TLC,
                    ) -> libc::c_int,
            ),
            asn1_ex_i2d: Some(
                x509_name_ex_i2d
                    as unsafe extern "C" fn(
                        *mut *mut ASN1_VALUE,
                        *mut *mut libc::c_uchar,
                        *const ASN1_ITEM,
                        libc::c_int,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            asn1_ex_print: None,
        };
        init
    }
};
#[no_mangle]
pub static mut X509_NAME_it: ASN1_ITEM = unsafe {
    {
        let mut init = ASN1_ITEM_st {
            itype: 0x4 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: 0 as *const ASN1_TEMPLATE,
            tcount: 0 as libc::c_int as libc::c_long,
            funcs: &x509_name_ff as *const ASN1_EXTERN_FUNCS as *const libc::c_void,
            size: 0 as libc::c_int as libc::c_long,
            sname: b"X509_NAME\0" as *const u8 as *const libc::c_char,
        };
        init
    }
};
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_NAME(
    mut a: *mut X509_NAME,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &X509_NAME_it);
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_free(mut a: *mut X509_NAME) {
    ASN1_item_free(a as *mut ASN1_VALUE, &X509_NAME_it);
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_new() -> *mut X509_NAME {
    return ASN1_item_new(&X509_NAME_it) as *mut X509_NAME;
}
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_NAME(
    mut a: *mut *mut X509_NAME,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut X509_NAME {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &X509_NAME_it)
        as *mut X509_NAME;
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_dup(mut x: *mut X509_NAME) -> *mut X509_NAME {
    return ASN1_item_dup(&X509_NAME_it, x as *mut libc::c_void) as *mut X509_NAME;
}
unsafe extern "C" fn x509_name_ex_new(
    mut val: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
) -> libc::c_int {
    let mut ret: *mut X509_NAME = 0 as *mut X509_NAME;
    ret = OPENSSL_malloc(::core::mem::size_of::<X509_NAME>() as libc::c_ulong)
        as *mut X509_NAME;
    if !ret.is_null() {
        (*ret).entries = sk_X509_NAME_ENTRY_new_null();
        if !((*ret).entries).is_null() {
            (*ret).bytes = BUF_MEM_new();
            if !((*ret).bytes).is_null() {
                (*ret).canon_enc = 0 as *mut libc::c_uchar;
                (*ret).canon_enclen = 0 as libc::c_int;
                (*ret).modified = 1 as libc::c_int;
                *val = ret as *mut ASN1_VALUE;
                return 1 as libc::c_int;
            }
        }
    }
    if !ret.is_null() {
        if !((*ret).entries).is_null() {
            sk_X509_NAME_ENTRY_free((*ret).entries);
        }
        OPENSSL_free(ret as *mut libc::c_void);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn x509_name_ex_free(
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
) {
    let mut a: *mut X509_NAME = 0 as *mut X509_NAME;
    if pval.is_null() || (*pval).is_null() {
        return;
    }
    a = *pval as *mut X509_NAME;
    BUF_MEM_free((*a).bytes);
    sk_X509_NAME_ENTRY_pop_free(
        (*a).entries,
        Some(X509_NAME_ENTRY_free as unsafe extern "C" fn(*mut X509_NAME_ENTRY) -> ()),
    );
    if !((*a).canon_enc).is_null() {
        OPENSSL_free((*a).canon_enc as *mut libc::c_void);
    }
    OPENSSL_free(a as *mut libc::c_void);
    *pval = 0 as *mut ASN1_VALUE;
}
unsafe extern "C" fn local_sk_X509_NAME_ENTRY_free(
    mut ne: *mut stack_st_X509_NAME_ENTRY,
) {
    sk_X509_NAME_ENTRY_free(ne);
}
unsafe extern "C" fn local_sk_X509_NAME_ENTRY_pop_free(
    mut ne: *mut stack_st_X509_NAME_ENTRY,
) {
    sk_X509_NAME_ENTRY_pop_free(
        ne,
        Some(X509_NAME_ENTRY_free as unsafe extern "C" fn(*mut X509_NAME_ENTRY) -> ()),
    );
}
unsafe extern "C" fn x509_name_ex_d2i(
    mut val: *mut *mut ASN1_VALUE,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
    mut it: *const ASN1_ITEM,
    mut tag: libc::c_int,
    mut aclass: libc::c_int,
    mut opt: libc::c_char,
    mut ctx: *mut ASN1_TLC,
) -> libc::c_int {
    let mut current_block: u64;
    let mut p: *const libc::c_uchar = *in_0;
    let mut q: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut intname: *mut stack_st_STACK_OF_X509_NAME_ENTRY = 0
        as *mut stack_st_STACK_OF_X509_NAME_ENTRY;
    let mut nm: *mut X509_NAME = 0 as *mut X509_NAME;
    let mut i: size_t = 0;
    let mut j: size_t = 0;
    let mut ret: libc::c_int = 0;
    let mut entries: *mut stack_st_X509_NAME_ENTRY = 0 as *mut stack_st_X509_NAME_ENTRY;
    let mut entry: *mut X509_NAME_ENTRY = 0 as *mut X509_NAME_ENTRY;
    if len > (1024 as libc::c_int * 1024 as libc::c_int) as libc::c_long {
        len = (1024 as libc::c_int * 1024 as libc::c_int) as libc::c_long;
    }
    q = p;
    let mut intname_val: *mut ASN1_VALUE = 0 as *mut ASN1_VALUE;
    ret = ASN1_item_ex_d2i(
        &mut intname_val,
        &mut p,
        len,
        &X509_NAME_INTERNAL_it,
        tag,
        aclass,
        opt,
        ctx,
    );
    if ret <= 0 as libc::c_int {
        return ret;
    }
    intname = intname_val as *mut stack_st_STACK_OF_X509_NAME_ENTRY;
    if !(*val).is_null() {
        x509_name_ex_free(val, 0 as *const ASN1_ITEM);
    }
    let mut nm_val: *mut ASN1_VALUE = 0 as *mut ASN1_VALUE;
    if !(x509_name_ex_new(&mut nm_val, 0 as *const ASN1_ITEM) == 0) {
        nm = nm_val as *mut X509_NAME;
        if !(BUF_MEM_grow((*nm).bytes, p.offset_from(q) as libc::c_long as size_t) == 0)
        {
            OPENSSL_memcpy(
                (*(*nm).bytes).data as *mut libc::c_void,
                q as *const libc::c_void,
                p.offset_from(q) as libc::c_long as size_t,
            );
            i = 0 as libc::c_int as size_t;
            's_83: loop {
                if !(i < sk_STACK_OF_X509_NAME_ENTRY_num(intname)) {
                    current_block = 15768484401365413375;
                    break;
                }
                entries = sk_STACK_OF_X509_NAME_ENTRY_value(intname, i);
                j = 0 as libc::c_int as size_t;
                while j < sk_X509_NAME_ENTRY_num(entries) {
                    entry = sk_X509_NAME_ENTRY_value(entries, j);
                    (*entry).set = i as libc::c_int;
                    if sk_X509_NAME_ENTRY_push((*nm).entries, entry) == 0 {
                        current_block = 3195868807039150648;
                        break 's_83;
                    }
                    sk_X509_NAME_ENTRY_set(entries, j, 0 as *mut X509_NAME_ENTRY);
                    j = j.wrapping_add(1);
                    j;
                }
                i = i.wrapping_add(1);
                i;
            }
            match current_block {
                3195868807039150648 => {}
                _ => {
                    ret = x509_name_canon(nm);
                    if !(ret == 0) {
                        sk_STACK_OF_X509_NAME_ENTRY_pop_free(
                            intname,
                            Some(
                                local_sk_X509_NAME_ENTRY_free
                                    as unsafe extern "C" fn(*mut stack_st_X509_NAME_ENTRY) -> (),
                            ),
                        );
                        (*nm).modified = 0 as libc::c_int;
                        *val = nm as *mut ASN1_VALUE;
                        *in_0 = p;
                        return ret;
                    }
                }
            }
        }
    }
    X509_NAME_free(nm);
    sk_STACK_OF_X509_NAME_ENTRY_pop_free(
        intname,
        Some(
            local_sk_X509_NAME_ENTRY_pop_free
                as unsafe extern "C" fn(*mut stack_st_X509_NAME_ENTRY) -> (),
        ),
    );
    ERR_put_error(
        11 as libc::c_int,
        0 as libc::c_int,
        12 as libc::c_int,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x_name.c\0" as *const u8
            as *const libc::c_char,
        254 as libc::c_int as libc::c_uint,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn x509_name_ex_i2d(
    mut val: *mut *mut ASN1_VALUE,
    mut out: *mut *mut libc::c_uchar,
    mut it: *const ASN1_ITEM,
    mut tag: libc::c_int,
    mut aclass: libc::c_int,
) -> libc::c_int {
    let mut a: *mut X509_NAME = *val as *mut X509_NAME;
    if (*a).modified != 0 && (x509_name_encode(a) == 0 || x509_name_canon(a) == 0) {
        return -(1 as libc::c_int);
    }
    let mut ret: libc::c_int = (*(*a).bytes).length as libc::c_int;
    if !out.is_null() {
        OPENSSL_memcpy(
            *out as *mut libc::c_void,
            (*(*a).bytes).data as *const libc::c_void,
            ret as size_t,
        );
        *out = (*out).offset(ret as isize);
    }
    return ret;
}
unsafe extern "C" fn x509_name_encode(mut a: *mut X509_NAME) -> libc::c_int {
    let mut intname_val: *mut ASN1_VALUE = 0 as *mut ASN1_VALUE;
    let mut current_block: u64;
    let mut len: libc::c_int = 0;
    let mut p: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut entries: *mut stack_st_X509_NAME_ENTRY = 0 as *mut stack_st_X509_NAME_ENTRY;
    let mut entry: *mut X509_NAME_ENTRY = 0 as *mut X509_NAME_ENTRY;
    let mut set: libc::c_int = -(1 as libc::c_int);
    let mut i: size_t = 0;
    let mut intname: *mut stack_st_STACK_OF_X509_NAME_ENTRY = sk_STACK_OF_X509_NAME_ENTRY_new_null();
    if !intname.is_null() {
        i = 0 as libc::c_int as size_t;
        loop {
            if !(i < sk_X509_NAME_ENTRY_num((*a).entries)) {
                current_block = 10048703153582371463;
                break;
            }
            entry = sk_X509_NAME_ENTRY_value((*a).entries, i);
            if (*entry).set != set {
                entries = sk_X509_NAME_ENTRY_new_null();
                if entries.is_null() {
                    current_block = 5909626098450856064;
                    break;
                }
                if sk_STACK_OF_X509_NAME_ENTRY_push(intname, entries) == 0 {
                    sk_X509_NAME_ENTRY_free(entries);
                    current_block = 5909626098450856064;
                    break;
                } else {
                    set = (*entry).set;
                }
            }
            if sk_X509_NAME_ENTRY_push(entries, entry) == 0 {
                current_block = 5909626098450856064;
                break;
            }
            i = i.wrapping_add(1);
            i;
        }
        match current_block {
            5909626098450856064 => {}
            _ => {
                intname_val = intname as *mut ASN1_VALUE;
                len = ASN1_item_ex_i2d(
                    &mut intname_val,
                    0 as *mut *mut libc::c_uchar,
                    &X509_NAME_INTERNAL_it,
                    -(1 as libc::c_int),
                    0 as libc::c_int,
                );
                if !(len <= 0 as libc::c_int) {
                    if !(BUF_MEM_grow((*a).bytes, len as size_t) == 0) {
                        p = (*(*a).bytes).data as *mut libc::c_uchar;
                        if !(ASN1_item_ex_i2d(
                            &mut intname_val,
                            &mut p,
                            &X509_NAME_INTERNAL_it,
                            -(1 as libc::c_int),
                            0 as libc::c_int,
                        ) <= 0 as libc::c_int)
                        {
                            sk_STACK_OF_X509_NAME_ENTRY_pop_free(
                                intname,
                                Some(
                                    local_sk_X509_NAME_ENTRY_free
                                        as unsafe extern "C" fn(*mut stack_st_X509_NAME_ENTRY) -> (),
                                ),
                            );
                            (*a).modified = 0 as libc::c_int;
                            return 1 as libc::c_int;
                        }
                    }
                }
            }
        }
    }
    sk_STACK_OF_X509_NAME_ENTRY_pop_free(
        intname,
        Some(
            local_sk_X509_NAME_ENTRY_free
                as unsafe extern "C" fn(*mut stack_st_X509_NAME_ENTRY) -> (),
        ),
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn x509_name_canon(mut a: *mut X509_NAME) -> libc::c_int {
    let mut current_block: u64;
    let mut p: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut intname: *mut stack_st_STACK_OF_X509_NAME_ENTRY = 0
        as *mut stack_st_STACK_OF_X509_NAME_ENTRY;
    let mut entries: *mut stack_st_X509_NAME_ENTRY = 0 as *mut stack_st_X509_NAME_ENTRY;
    let mut entry: *mut X509_NAME_ENTRY = 0 as *mut X509_NAME_ENTRY;
    let mut tmpentry: *mut X509_NAME_ENTRY = 0 as *mut X509_NAME_ENTRY;
    let mut set: libc::c_int = -(1 as libc::c_int);
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut len: libc::c_int = 0;
    let mut i: size_t = 0;
    if !((*a).canon_enc).is_null() {
        OPENSSL_free((*a).canon_enc as *mut libc::c_void);
        (*a).canon_enc = 0 as *mut libc::c_uchar;
    }
    if sk_X509_NAME_ENTRY_num((*a).entries) == 0 as libc::c_int as size_t {
        (*a).canon_enclen = 0 as libc::c_int;
        return 1 as libc::c_int;
    }
    intname = sk_STACK_OF_X509_NAME_ENTRY_new_null();
    if !intname.is_null() {
        i = 0 as libc::c_int as size_t;
        loop {
            if !(i < sk_X509_NAME_ENTRY_num((*a).entries)) {
                current_block = 15768484401365413375;
                break;
            }
            entry = sk_X509_NAME_ENTRY_value((*a).entries, i);
            if (*entry).set != set {
                entries = sk_X509_NAME_ENTRY_new_null();
                if entries.is_null() {
                    current_block = 7318135520942510179;
                    break;
                }
                if sk_STACK_OF_X509_NAME_ENTRY_push(intname, entries) == 0 {
                    sk_X509_NAME_ENTRY_free(entries);
                    current_block = 7318135520942510179;
                    break;
                } else {
                    set = (*entry).set;
                }
            }
            tmpentry = X509_NAME_ENTRY_new();
            if tmpentry.is_null() {
                current_block = 7318135520942510179;
                break;
            }
            (*tmpentry).object = OBJ_dup((*entry).object);
            if asn1_string_canon((*tmpentry).value, (*entry).value) == 0 {
                current_block = 7318135520942510179;
                break;
            }
            if sk_X509_NAME_ENTRY_push(entries, tmpentry) == 0 {
                current_block = 7318135520942510179;
                break;
            }
            tmpentry = 0 as *mut X509_NAME_ENTRY;
            i = i.wrapping_add(1);
            i;
        }
        match current_block {
            7318135520942510179 => {}
            _ => {
                len = i2d_name_canon(intname, 0 as *mut *mut libc::c_uchar);
                if !(len < 0 as libc::c_int) {
                    (*a).canon_enclen = len;
                    p = OPENSSL_malloc((*a).canon_enclen as size_t)
                        as *mut libc::c_uchar;
                    if !p.is_null() {
                        (*a).canon_enc = p;
                        i2d_name_canon(intname, &mut p);
                        ret = 1 as libc::c_int;
                    }
                }
            }
        }
    }
    if !tmpentry.is_null() {
        X509_NAME_ENTRY_free(tmpentry);
    }
    if !intname.is_null() {
        sk_STACK_OF_X509_NAME_ENTRY_pop_free(
            intname,
            Some(
                local_sk_X509_NAME_ENTRY_pop_free
                    as unsafe extern "C" fn(*mut stack_st_X509_NAME_ENTRY) -> (),
            ),
        );
    }
    return ret;
}
unsafe extern "C" fn asn1_string_canon(
    mut out: *mut ASN1_STRING,
    mut in_0: *mut ASN1_STRING,
) -> libc::c_int {
    let mut to: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut from: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut len: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    if ASN1_tag2bit((*in_0).type_0)
        & (0x2000 as libc::c_int | 0x800 as libc::c_int | 0x100 as libc::c_int
            | 0x2 as libc::c_int | 0x4 as libc::c_int | 0x10 as libc::c_int
            | 0x40 as libc::c_int) as libc::c_ulong == 0
    {
        if ASN1_STRING_copy(out, in_0) == 0 {
            return 0 as libc::c_int;
        }
        return 1 as libc::c_int;
    }
    (*out).type_0 = 12 as libc::c_int;
    (*out).length = ASN1_STRING_to_UTF8(&mut (*out).data, in_0);
    if (*out).length == -(1 as libc::c_int) {
        return 0 as libc::c_int;
    }
    to = (*out).data;
    from = to;
    len = (*out).length;
    while len > 0 as libc::c_int && OPENSSL_isspace(*from as libc::c_int) != 0 {
        from = from.offset(1);
        from;
        len -= 1;
        len;
    }
    to = from.offset(len as isize);
    while len > 0 as libc::c_int
        && OPENSSL_isspace(*to.offset(-(1 as libc::c_int) as isize) as libc::c_int) != 0
    {
        to = to.offset(-1);
        to;
        len -= 1;
        len;
    }
    to = (*out).data;
    i = 0 as libc::c_int;
    while i < len {
        if OPENSSL_isspace(*from as libc::c_int) != 0 {
            let fresh0 = to;
            to = to.offset(1);
            *fresh0 = ' ' as i32 as libc::c_uchar;
            loop {
                from = from.offset(1);
                from;
                i += 1;
                i;
                if !(OPENSSL_isspace(*from as libc::c_int) != 0) {
                    break;
                }
            }
        } else {
            let fresh1 = to;
            to = to.offset(1);
            *fresh1 = OPENSSL_tolower(*from as libc::c_int) as libc::c_uchar;
            from = from.offset(1);
            from;
            i += 1;
            i;
        }
    }
    (*out).length = to.offset_from((*out).data) as libc::c_long as libc::c_int;
    return 1 as libc::c_int;
}
unsafe extern "C" fn i2d_name_canon(
    mut _intname: *mut stack_st_STACK_OF_X509_NAME_ENTRY,
    mut in_0: *mut *mut libc::c_uchar,
) -> libc::c_int {
    let mut len: libc::c_int = 0;
    let mut ltmp: libc::c_int = 0;
    let mut i: size_t = 0;
    let mut v: *mut ASN1_VALUE = 0 as *mut ASN1_VALUE;
    let mut intname: *mut stack_st_ASN1_VALUE = _intname as *mut stack_st_ASN1_VALUE;
    len = 0 as libc::c_int;
    i = 0 as libc::c_int as size_t;
    while i < sk_ASN1_VALUE_num(intname) {
        v = sk_ASN1_VALUE_value(intname, i);
        ltmp = ASN1_item_ex_i2d(
            &mut v,
            in_0,
            &X509_NAME_ENTRIES_it,
            -(1 as libc::c_int),
            0 as libc::c_int,
        );
        if ltmp < 0 as libc::c_int {
            return ltmp;
        }
        len += ltmp;
        i = i.wrapping_add(1);
        i;
    }
    return len;
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_set(
    mut xn: *mut *mut X509_NAME,
    mut name: *mut X509_NAME,
) -> libc::c_int {
    name = X509_NAME_dup(name);
    if name.is_null() {
        return 0 as libc::c_int;
    }
    X509_NAME_free(*xn);
    *xn = name;
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_ENTRY_set(
    mut ne: *const X509_NAME_ENTRY,
) -> libc::c_int {
    return (*ne).set;
}
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_get0_der(
    mut nm: *mut X509_NAME,
    mut out_der: *mut *const libc::c_uchar,
    mut out_der_len: *mut size_t,
) -> libc::c_int {
    if i2d_X509_NAME(nm, 0 as *mut *mut uint8_t) <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if !out_der.is_null() {
        *out_der = (*(*nm).bytes).data as *mut libc::c_uchar;
    }
    if !out_der_len.is_null() {
        *out_der_len = (*(*nm).bytes).length;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn run_static_initializers() {
    X509_NAME_ENTRY_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: X509_NAME_ENTRY_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 2]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<X509_NAME_ENTRY>() as libc::c_ulong
                as libc::c_long,
            sname: b"X509_NAME_ENTRY\0" as *const u8 as *const libc::c_char,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
