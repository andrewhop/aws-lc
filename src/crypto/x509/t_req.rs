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
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type asn1_pctx_st;
    pub type ASN1_VALUE_st;
    pub type stack_st_X509_NAME_ENTRY;
    pub type evp_pkey_st;
    pub type stack_st_X509_EXTENSION;
    pub type stack_st_void;
    pub type stack_st_X509_ATTRIBUTE;
    pub type stack_st_ASN1_TYPE;
    pub type stack_st;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn ASN1_STRING_print(out: *mut BIO, str: *const ASN1_STRING) -> libc::c_int;
    fn i2a_ASN1_OBJECT(bp: *mut BIO, a: *const ASN1_OBJECT) -> libc::c_int;
    fn X509_REQ_get_version(req: *const X509_REQ) -> libc::c_long;
    fn X509_REQ_get0_pubkey(req: *const X509_REQ) -> *mut EVP_PKEY;
    fn X509_REQ_extension_nid(nid: libc::c_int) -> libc::c_int;
    fn X509_REQ_get_extensions(req: *const X509_REQ) -> *mut stack_st_X509_EXTENSION;
    fn X509_EXTENSION_free(ex: *mut X509_EXTENSION);
    fn X509_EXTENSION_get_object(ex: *const X509_EXTENSION) -> *mut ASN1_OBJECT;
    fn X509_EXTENSION_get_data(ne: *const X509_EXTENSION) -> *mut ASN1_OCTET_STRING;
    fn X509_EXTENSION_get_critical(ex: *const X509_EXTENSION) -> libc::c_int;
    fn X509_ATTRIBUTE_count(attr: *const X509_ATTRIBUTE) -> libc::c_int;
    fn X509_ATTRIBUTE_get0_object(attr: *mut X509_ATTRIBUTE) -> *mut ASN1_OBJECT;
    fn X509_ATTRIBUTE_get0_type(
        attr: *mut X509_ATTRIBUTE,
        idx: libc::c_int,
    ) -> *mut ASN1_TYPE;
    fn X509_NAME_print_ex(
        out: *mut BIO,
        nm: *const X509_NAME,
        indent: libc::c_int,
        flags: libc::c_ulong,
    ) -> libc::c_int;
    fn X509_signature_print(
        bio: *mut BIO,
        alg: *const X509_ALGOR,
        sig: *const ASN1_STRING,
    ) -> libc::c_int;
    fn X509V3_EXT_print(
        out: *mut BIO,
        ext: *const X509_EXTENSION,
        flag: libc::c_ulong,
        indent: libc::c_int,
    ) -> libc::c_int;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_pop_free_ex(
        sk: *mut OPENSSL_STACK,
        call_free_func: OPENSSL_sk_call_free_func,
        free_func: OPENSSL_sk_free_func,
    );
    fn BIO_free(bio: *mut BIO) -> libc::c_int;
    fn BIO_write(
        bio: *mut BIO,
        data: *const libc::c_void,
        len: libc::c_int,
    ) -> libc::c_int;
    fn BIO_puts(bio: *mut BIO, buf: *const libc::c_char) -> libc::c_int;
    fn BIO_printf(bio: *mut BIO, format: *const libc::c_char, _: ...) -> libc::c_int;
    fn ERR_print_errors(bio: *mut BIO);
    fn BIO_new_fp(stream: *mut FILE, close_flag: libc::c_int) -> *mut BIO;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OBJ_obj2nid(obj: *const ASN1_OBJECT) -> libc::c_int;
    fn EVP_PKEY_print_public(
        out: *mut BIO,
        pkey: *const EVP_PKEY,
        indent: libc::c_int,
        pctx: *mut ASN1_PCTX,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
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
pub type CRYPTO_refcount_t = uint32_t;
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
pub struct X509_extension_st {
    pub object: *mut ASN1_OBJECT,
    pub critical: ASN1_BOOLEAN,
    pub value: *mut ASN1_OCTET_STRING,
}
pub type X509_EXTENSION = X509_extension_st;
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_attributes_st {
    pub object: *mut ASN1_OBJECT,
    pub set: *mut stack_st_ASN1_TYPE,
}
pub type X509_ATTRIBUTE = x509_attributes_st;
pub type OPENSSL_sk_free_func = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type OPENSSL_sk_call_free_func = Option::<
    unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
>;
pub type OPENSSL_STACK = stack_st;
pub type sk_X509_EXTENSION_free_func = Option::<
    unsafe extern "C" fn(*mut X509_EXTENSION) -> (),
>;
#[inline]
unsafe extern "C" fn sk_X509_EXTENSION_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<
        OPENSSL_sk_free_func,
        sk_X509_EXTENSION_free_func,
    >(free_func))
        .expect("non-null function pointer")(ptr as *mut X509_EXTENSION);
}
#[inline]
unsafe extern "C" fn sk_X509_EXTENSION_num(
    mut sk: *const stack_st_X509_EXTENSION,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_EXTENSION_value(
    mut sk: *const stack_st_X509_EXTENSION,
    mut i: size_t,
) -> *mut X509_EXTENSION {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509_EXTENSION;
}
#[inline]
unsafe extern "C" fn sk_X509_EXTENSION_pop_free(
    mut sk: *mut stack_st_X509_EXTENSION,
    mut free_func: sk_X509_EXTENSION_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_X509_EXTENSION_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<
            sk_X509_EXTENSION_free_func,
            OPENSSL_sk_free_func,
        >(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_X509_ATTRIBUTE_num(
    mut sk: *const stack_st_X509_ATTRIBUTE,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_ATTRIBUTE_value(
    mut sk: *const stack_st_X509_ATTRIBUTE,
    mut i: size_t,
) -> *mut X509_ATTRIBUTE {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509_ATTRIBUTE;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_REQ_print_fp(
    mut fp: *mut FILE,
    mut x: *mut X509_REQ,
) -> libc::c_int {
    let mut bio: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if bio.is_null() {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            7 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/t_req.c\0" as *const u8
                as *const libc::c_char,
            72 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = X509_REQ_print(bio, x);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_REQ_print_ex(
    mut bio: *mut BIO,
    mut x: *mut X509_REQ,
    mut nmflags: libc::c_ulong,
    mut cflag: libc::c_ulong,
) -> libc::c_int {
    let mut current_block: u64;
    let mut l: libc::c_long = 0;
    let mut sk: *mut stack_st_X509_ATTRIBUTE = 0 as *mut stack_st_X509_ATTRIBUTE;
    let mut mlch: libc::c_char = ' ' as i32 as libc::c_char;
    let mut nmindent: libc::c_int = 0 as libc::c_int;
    if nmflags & (0xf as libc::c_ulong) << 16 as libc::c_int
        == (4 as libc::c_ulong) << 16 as libc::c_int
    {
        mlch = '\n' as i32 as libc::c_char;
        nmindent = 12 as libc::c_int;
    }
    if nmflags == 0 as libc::c_int as libc::c_ulong {
        nmindent = 16 as libc::c_int;
    }
    let mut ri: *mut X509_REQ_INFO = (*x).req_info;
    if cflag & 1 as libc::c_long as libc::c_ulong == 0 {
        if BIO_write(
            bio,
            b"Certificate Request:\n\0" as *const u8 as *const libc::c_char
                as *const libc::c_void,
            21 as libc::c_int,
        ) <= 0 as libc::c_int
            || BIO_write(
                bio,
                b"    Data:\n\0" as *const u8 as *const libc::c_char
                    as *const libc::c_void,
                10 as libc::c_int,
            ) <= 0 as libc::c_int
        {
            current_block = 14148544787447981254;
        } else {
            current_block = 11812396948646013369;
        }
    } else {
        current_block = 11812396948646013369;
    }
    match current_block {
        11812396948646013369 => {
            if cflag & ((1 as libc::c_long) << 1 as libc::c_int) as libc::c_ulong == 0 {
                l = X509_REQ_get_version(x);
                if 0 as libc::c_int as libc::c_long <= l
                    && l <= 2 as libc::c_int as libc::c_long
                {} else {
                    __assert_fail(
                        b"0 <= l && l <= 2\0" as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/t_req.c\0"
                            as *const u8 as *const libc::c_char,
                        108 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 71],
                            &[libc::c_char; 71],
                        >(
                            b"int X509_REQ_print_ex(BIO *, X509_REQ *, unsigned long, unsigned long)\0",
                        ))
                            .as_ptr(),
                    );
                }
                'c_21669: {
                    if 0 as libc::c_int as libc::c_long <= l
                        && l <= 2 as libc::c_int as libc::c_long
                    {} else {
                        __assert_fail(
                            b"0 <= l && l <= 2\0" as *const u8 as *const libc::c_char,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/t_req.c\0"
                                as *const u8 as *const libc::c_char,
                            108 as libc::c_int as libc::c_uint,
                            (*::core::mem::transmute::<
                                &[u8; 71],
                                &[libc::c_char; 71],
                            >(
                                b"int X509_REQ_print_ex(BIO *, X509_REQ *, unsigned long, unsigned long)\0",
                            ))
                                .as_ptr(),
                        );
                    }
                };
                if BIO_printf(
                    bio,
                    b"%8sVersion: %ld (0x%lx)\n\0" as *const u8 as *const libc::c_char,
                    b"\0" as *const u8 as *const libc::c_char,
                    l + 1 as libc::c_int as libc::c_long,
                    l as libc::c_ulong,
                ) <= 0 as libc::c_int
                {
                    current_block = 14148544787447981254;
                } else {
                    current_block = 3512920355445576850;
                }
            } else {
                current_block = 3512920355445576850;
            }
            match current_block {
                14148544787447981254 => {}
                _ => {
                    if cflag & ((1 as libc::c_long) << 6 as libc::c_int) as libc::c_ulong
                        == 0
                    {
                        if BIO_printf(
                            bio,
                            b"        Subject:%c\0" as *const u8 as *const libc::c_char,
                            mlch as libc::c_int,
                        ) <= 0 as libc::c_int
                            || X509_NAME_print_ex(bio, (*ri).subject, nmindent, nmflags)
                                < 0 as libc::c_int
                            || BIO_write(
                                bio,
                                b"\n\0" as *const u8 as *const libc::c_char
                                    as *const libc::c_void,
                                1 as libc::c_int,
                            ) <= 0 as libc::c_int
                        {
                            current_block = 14148544787447981254;
                        } else {
                            current_block = 5143058163439228106;
                        }
                    } else {
                        current_block = 5143058163439228106;
                    }
                    match current_block {
                        14148544787447981254 => {}
                        _ => {
                            if cflag
                                & ((1 as libc::c_long) << 7 as libc::c_int) as libc::c_ulong
                                == 0
                            {
                                if BIO_write(
                                    bio,
                                    b"        Subject Public Key Info:\n\0" as *const u8
                                        as *const libc::c_char as *const libc::c_void,
                                    33 as libc::c_int,
                                ) <= 0 as libc::c_int
                                    || BIO_printf(
                                        bio,
                                        b"%12sPublic Key Algorithm: \0" as *const u8
                                            as *const libc::c_char,
                                        b"\0" as *const u8 as *const libc::c_char,
                                    ) <= 0 as libc::c_int
                                    || i2a_ASN1_OBJECT(bio, (*(*(*ri).pubkey).algor).algorithm)
                                        <= 0 as libc::c_int
                                    || BIO_puts(
                                        bio,
                                        b"\n\0" as *const u8 as *const libc::c_char,
                                    ) <= 0 as libc::c_int
                                {
                                    current_block = 14148544787447981254;
                                } else {
                                    let mut pkey: *const EVP_PKEY = X509_REQ_get0_pubkey(x);
                                    if pkey.is_null() {
                                        BIO_printf(
                                            bio,
                                            b"%12sUnable to load Public Key\n\0" as *const u8
                                                as *const libc::c_char,
                                            b"\0" as *const u8 as *const libc::c_char,
                                        );
                                        ERR_print_errors(bio);
                                    } else {
                                        EVP_PKEY_print_public(
                                            bio,
                                            pkey,
                                            16 as libc::c_int,
                                            0 as *mut ASN1_PCTX,
                                        );
                                    }
                                    current_block = 17478428563724192186;
                                }
                            } else {
                                current_block = 17478428563724192186;
                            }
                            match current_block {
                                14148544787447981254 => {}
                                _ => {
                                    if cflag
                                        & ((1 as libc::c_long) << 11 as libc::c_int)
                                            as libc::c_ulong == 0
                                    {
                                        if BIO_printf(
                                            bio,
                                            b"%8sAttributes:\n\0" as *const u8 as *const libc::c_char,
                                            b"\0" as *const u8 as *const libc::c_char,
                                        ) <= 0 as libc::c_int
                                        {
                                            current_block = 14148544787447981254;
                                        } else {
                                            sk = (*(*x).req_info).attributes;
                                            if sk_X509_ATTRIBUTE_num(sk) == 0 as libc::c_int as size_t {
                                                if BIO_printf(
                                                    bio,
                                                    b"%12sa0:00\n\0" as *const u8 as *const libc::c_char,
                                                    b"\0" as *const u8 as *const libc::c_char,
                                                ) <= 0 as libc::c_int
                                                {
                                                    current_block = 14148544787447981254;
                                                } else {
                                                    current_block = 2520131295878969859;
                                                }
                                            } else {
                                                let mut i: size_t = 0;
                                                i = 0 as libc::c_int as size_t;
                                                's_155: loop {
                                                    if !(i < sk_X509_ATTRIBUTE_num(sk)) {
                                                        current_block = 2520131295878969859;
                                                        break;
                                                    }
                                                    let mut a: *mut X509_ATTRIBUTE = sk_X509_ATTRIBUTE_value(
                                                        sk,
                                                        i,
                                                    );
                                                    let mut aobj: *mut ASN1_OBJECT = X509_ATTRIBUTE_get0_object(
                                                        a,
                                                    );
                                                    if !(X509_REQ_extension_nid(OBJ_obj2nid(aobj)) != 0) {
                                                        if BIO_printf(
                                                            bio,
                                                            b"%12s\0" as *const u8 as *const libc::c_char,
                                                            b"\0" as *const u8 as *const libc::c_char,
                                                        ) <= 0 as libc::c_int
                                                        {
                                                            current_block = 14148544787447981254;
                                                            break;
                                                        }
                                                        let num_attrs: libc::c_int = X509_ATTRIBUTE_count(a);
                                                        let obj_str_len: libc::c_int = i2a_ASN1_OBJECT(bio, aobj);
                                                        if obj_str_len <= 0 as libc::c_int {
                                                            if BIO_puts(
                                                                bio,
                                                                b"(Unable to print attribute ID.)\n\0" as *const u8
                                                                    as *const libc::c_char,
                                                            ) < 0 as libc::c_int
                                                            {
                                                                current_block = 14148544787447981254;
                                                                break;
                                                            }
                                                        } else {
                                                            let mut j: libc::c_int = 0;
                                                            j = 0 as libc::c_int;
                                                            while j < num_attrs {
                                                                let mut at: *const ASN1_TYPE = X509_ATTRIBUTE_get0_type(
                                                                    a,
                                                                    j,
                                                                );
                                                                let type_0: libc::c_int = (*at).type_0;
                                                                let mut bs: *mut ASN1_BIT_STRING = (*at).value.asn1_string;
                                                                let mut k: libc::c_int = 0;
                                                                k = 25 as libc::c_int - obj_str_len;
                                                                while k > 0 as libc::c_int {
                                                                    if BIO_write(
                                                                        bio,
                                                                        b" \0" as *const u8 as *const libc::c_char
                                                                            as *const libc::c_void,
                                                                        1 as libc::c_int,
                                                                    ) != 1 as libc::c_int
                                                                    {
                                                                        current_block = 14148544787447981254;
                                                                        break 's_155;
                                                                    }
                                                                    k -= 1;
                                                                    k;
                                                                }
                                                                if BIO_puts(bio, b":\0" as *const u8 as *const libc::c_char)
                                                                    <= 0 as libc::c_int
                                                                {
                                                                    current_block = 14148544787447981254;
                                                                    break 's_155;
                                                                }
                                                                if type_0 == 19 as libc::c_int
                                                                    || type_0 == 12 as libc::c_int
                                                                    || type_0 == 22 as libc::c_int
                                                                    || type_0 == 20 as libc::c_int
                                                                {
                                                                    if BIO_write(
                                                                        bio,
                                                                        (*bs).data as *mut libc::c_char as *const libc::c_void,
                                                                        (*bs).length,
                                                                    ) != (*bs).length
                                                                    {
                                                                        current_block = 14148544787447981254;
                                                                        break 's_155;
                                                                    }
                                                                    BIO_puts(bio, b"\n\0" as *const u8 as *const libc::c_char);
                                                                } else {
                                                                    BIO_puts(
                                                                        bio,
                                                                        b"unable to print attribute\n\0" as *const u8
                                                                            as *const libc::c_char,
                                                                    );
                                                                }
                                                                j += 1;
                                                                j;
                                                            }
                                                        }
                                                    }
                                                    i = i.wrapping_add(1);
                                                    i;
                                                }
                                            }
                                        }
                                    } else {
                                        current_block = 2520131295878969859;
                                    }
                                    match current_block {
                                        14148544787447981254 => {}
                                        _ => {
                                            if cflag
                                                & ((1 as libc::c_long) << 8 as libc::c_int) as libc::c_ulong
                                                == 0
                                            {
                                                let mut exts: *mut stack_st_X509_EXTENSION = X509_REQ_get_extensions(
                                                    x,
                                                );
                                                if !exts.is_null() {
                                                    BIO_printf(
                                                        bio,
                                                        b"%8sRequested Extensions:\n\0" as *const u8
                                                            as *const libc::c_char,
                                                        b"\0" as *const u8 as *const libc::c_char,
                                                    );
                                                    let mut i_0: size_t = 0 as libc::c_int as size_t;
                                                    loop {
                                                        if !(i_0 < sk_X509_EXTENSION_num(exts)) {
                                                            current_block = 15462640364611497761;
                                                            break;
                                                        }
                                                        let mut ex: *const X509_EXTENSION = sk_X509_EXTENSION_value(
                                                            exts,
                                                            i_0,
                                                        );
                                                        if BIO_printf(
                                                            bio,
                                                            b"%12s\0" as *const u8 as *const libc::c_char,
                                                            b"\0" as *const u8 as *const libc::c_char,
                                                        ) <= 0 as libc::c_int
                                                        {
                                                            current_block = 14148544787447981254;
                                                            break;
                                                        }
                                                        let mut obj: *const ASN1_OBJECT = X509_EXTENSION_get_object(
                                                            ex,
                                                        );
                                                        i2a_ASN1_OBJECT(bio, obj);
                                                        let is_critical: libc::c_int = X509_EXTENSION_get_critical(
                                                            ex,
                                                        );
                                                        if BIO_printf(
                                                            bio,
                                                            b": %s\n\0" as *const u8 as *const libc::c_char,
                                                            (if is_critical != 0 {
                                                                b"critical\0" as *const u8 as *const libc::c_char
                                                            } else {
                                                                b"\0" as *const u8 as *const libc::c_char
                                                            }),
                                                        ) <= 0 as libc::c_int
                                                        {
                                                            current_block = 14148544787447981254;
                                                            break;
                                                        }
                                                        if X509V3_EXT_print(bio, ex, cflag, 16 as libc::c_int) == 0
                                                        {
                                                            BIO_printf(
                                                                bio,
                                                                b"%16s\0" as *const u8 as *const libc::c_char,
                                                                b"\0" as *const u8 as *const libc::c_char,
                                                            );
                                                            ASN1_STRING_print(bio, X509_EXTENSION_get_data(ex));
                                                        }
                                                        if BIO_write(
                                                            bio,
                                                            b"\n\0" as *const u8 as *const libc::c_char
                                                                as *const libc::c_void,
                                                            1 as libc::c_int,
                                                        ) <= 0 as libc::c_int
                                                        {
                                                            current_block = 14148544787447981254;
                                                            break;
                                                        }
                                                        i_0 = i_0.wrapping_add(1);
                                                        i_0;
                                                    }
                                                    match current_block {
                                                        14148544787447981254 => {}
                                                        _ => {
                                                            sk_X509_EXTENSION_pop_free(
                                                                exts,
                                                                Some(
                                                                    X509_EXTENSION_free
                                                                        as unsafe extern "C" fn(*mut X509_EXTENSION) -> (),
                                                                ),
                                                            );
                                                            current_block = 2723324002591448311;
                                                        }
                                                    }
                                                } else {
                                                    current_block = 2723324002591448311;
                                                }
                                            } else {
                                                current_block = 2723324002591448311;
                                            }
                                            match current_block {
                                                14148544787447981254 => {}
                                                _ => {
                                                    if !(cflag
                                                        & ((1 as libc::c_long) << 9 as libc::c_int) as libc::c_ulong
                                                        == 0
                                                        && X509_signature_print(bio, (*x).sig_alg, (*x).signature)
                                                            == 0)
                                                    {
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
            }
        }
        _ => {}
    }
    ERR_put_error(
        11 as libc::c_int,
        0 as libc::c_int,
        7 as libc::c_int,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/t_req.c\0" as *const u8
            as *const libc::c_char,
        239 as libc::c_int as libc::c_uint,
    );
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_REQ_print(
    mut bio: *mut BIO,
    mut req: *mut X509_REQ,
) -> libc::c_int {
    return X509_REQ_print_ex(
        bio,
        req,
        0 as libc::c_ulong,
        0 as libc::c_int as libc::c_ulong,
    );
}
