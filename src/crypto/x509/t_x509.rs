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
    pub type stack_st_GENERAL_NAME;
    pub type stack_st_X509_NAME_ENTRY;
    pub type stack_st_GENERAL_SUBTREE;
    pub type evp_pkey_st;
    pub type stack_st_ASN1_OBJECT;
    pub type stack_st_X509_EXTENSION;
    pub type crypto_buffer_st;
    pub type stack_st_DIST_POINT;
    pub type stack_st_void;
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn ASN1_INTEGER_get_uint64(
        out: *mut uint64_t,
        a: *const ASN1_INTEGER,
    ) -> libc::c_int;
    fn ASN1_TIME_print(out: *mut BIO, a: *const ASN1_TIME) -> libc::c_int;
    fn i2a_ASN1_OBJECT(bp: *mut BIO, a: *const ASN1_OBJECT) -> libc::c_int;
    fn X509_get_version(x509: *const X509) -> libc::c_long;
    fn X509_get0_serialNumber(x509: *const X509) -> *const ASN1_INTEGER;
    fn X509_get_issuer_name(x509: *const X509) -> *mut X509_NAME;
    fn X509_get_subject_name(x509: *const X509) -> *mut X509_NAME;
    fn X509_get0_pubkey(x509: *const X509) -> *mut EVP_PKEY;
    fn X509_NAME_print_ex(
        out: *mut BIO,
        nm: *const X509_NAME,
        indent: libc::c_int,
        flags: libc::c_ulong,
    ) -> libc::c_int;
    fn X509_NAME_oneline(
        name: *const X509_NAME,
        buf: *mut libc::c_char,
        size: libc::c_int,
    ) -> *mut libc::c_char;
    fn X509_signature_dump(
        bio: *mut BIO,
        sig: *const ASN1_STRING,
        indent: libc::c_int,
    ) -> libc::c_int;
    fn X509V3_extensions_print(
        out: *mut BIO,
        title: *const libc::c_char,
        exts: *const stack_st_X509_EXTENSION,
        flag: libc::c_ulong,
        indent: libc::c_int,
    ) -> libc::c_int;
    fn X509_get_notBefore(x509: *const X509) -> *mut ASN1_TIME;
    fn X509_get_notAfter(x509: *const X509) -> *mut ASN1_TIME;
    fn X509_CERT_AUX_print(
        bp: *mut BIO,
        x: *mut X509_CERT_AUX,
        indent: libc::c_int,
    ) -> libc::c_int;
    fn x509_print_rsa_pss_params(
        bp: *mut BIO,
        sigalg: *const X509_ALGOR,
        indent: libc::c_int,
        pctx: *mut ASN1_PCTX,
    ) -> libc::c_int;
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
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_clear_error();
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
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type uint8_t = __uint8_t;
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
pub type ASN1_TIME = asn1_string_st;
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
pub struct AUTHORITY_KEYID_st {
    pub keyid: *mut ASN1_OCTET_STRING,
    pub issuer: *mut GENERAL_NAMES,
    pub serial: *mut ASN1_INTEGER,
}
pub type GENERAL_NAMES = stack_st_GENERAL_NAME;
pub type AUTHORITY_KEYID = AUTHORITY_KEYID_st;
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
pub struct NAME_CONSTRAINTS_st {
    pub permittedSubtrees: *mut stack_st_GENERAL_SUBTREE,
    pub excludedSubtrees: *mut stack_st_GENERAL_SUBTREE,
}
pub type NAME_CONSTRAINTS = NAME_CONSTRAINTS_st;
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
pub type X509 = x509_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_st {
    pub cert_info: *mut X509_CINF,
    pub sig_alg: *mut X509_ALGOR,
    pub signature: *mut ASN1_BIT_STRING,
    pub sig_info: X509_SIG_INFO,
    pub references: CRYPTO_refcount_t,
    pub ex_data: CRYPTO_EX_DATA,
    pub ex_pathlen: libc::c_long,
    pub ex_flags: uint32_t,
    pub ex_kusage: uint32_t,
    pub ex_xkusage: uint32_t,
    pub ex_nscert: uint32_t,
    pub skid: *mut ASN1_OCTET_STRING,
    pub akid: *mut AUTHORITY_KEYID,
    pub crldp: *mut stack_st_DIST_POINT,
    pub altname: *mut stack_st_GENERAL_NAME,
    pub nc: *mut NAME_CONSTRAINTS,
    pub cert_hash: [libc::c_uchar; 32],
    pub aux: *mut X509_CERT_AUX,
    pub buf: *mut CRYPTO_BUFFER,
    pub lock: CRYPTO_MUTEX,
}
pub type CRYPTO_MUTEX = crypto_mutex_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub union crypto_mutex_st {
    pub alignment: libc::c_double,
    pub padding: [uint8_t; 56],
}
pub type CRYPTO_BUFFER = crypto_buffer_st;
pub type X509_CERT_AUX = x509_cert_aux_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_cert_aux_st {
    pub trust: *mut stack_st_ASN1_OBJECT,
    pub reject: *mut stack_st_ASN1_OBJECT,
    pub alias: *mut ASN1_UTF8STRING,
    pub keyid: *mut ASN1_OCTET_STRING,
}
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
pub type X509_SIG_INFO = x509_sig_info_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_sig_info_st {
    pub digest_nid: libc::c_int,
    pub pubkey_nid: libc::c_int,
    pub sec_bits: libc::c_int,
    pub flags: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_CINF {
    pub version: *mut ASN1_INTEGER,
    pub serialNumber: *mut ASN1_INTEGER,
    pub signature: *mut X509_ALGOR,
    pub issuer: *mut X509_NAME,
    pub validity: *mut X509_VAL,
    pub subject: *mut X509_NAME,
    pub key: *mut X509_PUBKEY,
    pub issuerUID: *mut ASN1_BIT_STRING,
    pub subjectUID: *mut ASN1_BIT_STRING,
    pub extensions: *mut stack_st_X509_EXTENSION,
    pub enc: ASN1_ENCODING,
}
pub type X509_VAL = X509_val_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_val_st {
    pub notBefore: *mut ASN1_TIME,
    pub notAfter: *mut ASN1_TIME,
}
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_print_ex_fp(
    mut fp: *mut FILE,
    mut x: *mut X509,
    mut nmflag: libc::c_ulong,
    mut cflag: libc::c_ulong,
) -> libc::c_int {
    let mut b: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if b.is_null() {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            7 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/t_x509.c\0" as *const u8
                as *const libc::c_char,
            75 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = X509_print_ex(b, x, nmflag, cflag);
    BIO_free(b);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_print_fp(
    mut fp: *mut FILE,
    mut x: *mut X509,
) -> libc::c_int {
    return X509_print_ex_fp(
        fp,
        x,
        0 as libc::c_ulong,
        0 as libc::c_int as libc::c_ulong,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_print(mut bp: *mut BIO, mut x: *mut X509) -> libc::c_int {
    return X509_print_ex(bp, x, 0 as libc::c_ulong, 0 as libc::c_int as libc::c_ulong);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_print_ex(
    mut bp: *mut BIO,
    mut x: *mut X509,
    mut nmflags: libc::c_ulong,
    mut cflag: libc::c_ulong,
) -> libc::c_int {
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
    let mut ci: *const X509_CINF = (*x).cert_info;
    if cflag & 1 as libc::c_long as libc::c_ulong == 0 {
        if BIO_write(
            bp,
            b"Certificate:\n\0" as *const u8 as *const libc::c_char
                as *const libc::c_void,
            13 as libc::c_int,
        ) <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        if BIO_write(
            bp,
            b"    Data:\n\0" as *const u8 as *const libc::c_char as *const libc::c_void,
            10 as libc::c_int,
        ) <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
    }
    if cflag & ((1 as libc::c_long) << 1 as libc::c_int) as libc::c_ulong == 0 {
        let mut l: libc::c_long = X509_get_version(x);
        if 0 as libc::c_int as libc::c_long <= l && l <= 2 as libc::c_int as libc::c_long
        {} else {
            __assert_fail(
                b"X509_VERSION_1 <= l && l <= X509_VERSION_3\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/t_x509.c\0" as *const u8
                    as *const libc::c_char,
                115 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 63],
                    &[libc::c_char; 63],
                >(b"int X509_print_ex(BIO *, X509 *, unsigned long, unsigned long)\0"))
                    .as_ptr(),
            );
        }
        'c_21831: {
            if 0 as libc::c_int as libc::c_long <= l
                && l <= 2 as libc::c_int as libc::c_long
            {} else {
                __assert_fail(
                    b"X509_VERSION_1 <= l && l <= X509_VERSION_3\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/t_x509.c\0"
                        as *const u8 as *const libc::c_char,
                    115 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 63],
                        &[libc::c_char; 63],
                    >(
                        b"int X509_print_ex(BIO *, X509 *, unsigned long, unsigned long)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        if BIO_printf(
            bp,
            b"%8sVersion: %ld (0x%lx)\n\0" as *const u8 as *const libc::c_char,
            b"\0" as *const u8 as *const libc::c_char,
            l + 1 as libc::c_int as libc::c_long,
            l as libc::c_ulong,
        ) <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
    }
    if cflag & ((1 as libc::c_long) << 2 as libc::c_int) as libc::c_ulong == 0 {
        if BIO_write(
            bp,
            b"        Serial Number:\0" as *const u8 as *const libc::c_char
                as *const libc::c_void,
            22 as libc::c_int,
        ) <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        let mut serial: *const ASN1_INTEGER = X509_get0_serialNumber(x);
        let mut serial_u64: uint64_t = 0;
        if ASN1_INTEGER_get_uint64(&mut serial_u64, serial) != 0 {
            if (*serial).type_0 != 2 as libc::c_int | 0x100 as libc::c_int {} else {
                __assert_fail(
                    b"serial->type != V_ASN1_NEG_INTEGER\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/t_x509.c\0"
                        as *const u8 as *const libc::c_char,
                    129 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 63],
                        &[libc::c_char; 63],
                    >(
                        b"int X509_print_ex(BIO *, X509 *, unsigned long, unsigned long)\0",
                    ))
                        .as_ptr(),
                );
            }
            'c_21714: {
                if (*serial).type_0 != 2 as libc::c_int | 0x100 as libc::c_int {} else {
                    __assert_fail(
                        b"serial->type != V_ASN1_NEG_INTEGER\0" as *const u8
                            as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/t_x509.c\0"
                            as *const u8 as *const libc::c_char,
                        129 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 63],
                            &[libc::c_char; 63],
                        >(
                            b"int X509_print_ex(BIO *, X509 *, unsigned long, unsigned long)\0",
                        ))
                            .as_ptr(),
                    );
                }
            };
            if BIO_printf(
                bp,
                b" %lu (0x%lx)\n\0" as *const u8 as *const libc::c_char,
                serial_u64,
                serial_u64,
            ) <= 0 as libc::c_int
            {
                return 0 as libc::c_int;
            }
        } else {
            ERR_clear_error();
            let mut neg: *const libc::c_char = if (*serial).type_0
                == 2 as libc::c_int | 0x100 as libc::c_int
            {
                b" (Negative)\0" as *const u8 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            };
            if BIO_printf(
                bp,
                b"\n%12s%s\0" as *const u8 as *const libc::c_char,
                b"\0" as *const u8 as *const libc::c_char,
                neg,
            ) <= 0 as libc::c_int
            {
                return 0 as libc::c_int;
            }
            let mut i: libc::c_int = 0 as libc::c_int;
            while i < (*serial).length {
                if BIO_printf(
                    bp,
                    b"%02x%c\0" as *const u8 as *const libc::c_char,
                    *((*serial).data).offset(i as isize) as libc::c_int,
                    (if i + 1 as libc::c_int == (*serial).length {
                        '\n' as i32
                    } else {
                        ':' as i32
                    }),
                ) <= 0 as libc::c_int
                {
                    return 0 as libc::c_int;
                }
                i += 1;
                i;
            }
        }
    }
    if cflag & ((1 as libc::c_long) << 3 as libc::c_int) as libc::c_ulong == 0 {
        if X509_signature_print(bp, (*ci).signature, 0 as *const ASN1_STRING)
            <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
    }
    if cflag & ((1 as libc::c_long) << 4 as libc::c_int) as libc::c_ulong == 0 {
        if BIO_printf(
            bp,
            b"        Issuer:%c\0" as *const u8 as *const libc::c_char,
            mlch as libc::c_int,
        ) <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        if X509_NAME_print_ex(bp, X509_get_issuer_name(x), nmindent, nmflags)
            < 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        if BIO_write(
            bp,
            b"\n\0" as *const u8 as *const libc::c_char as *const libc::c_void,
            1 as libc::c_int,
        ) <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
    }
    if cflag & ((1 as libc::c_long) << 5 as libc::c_int) as libc::c_ulong == 0 {
        if BIO_write(
            bp,
            b"        Validity\n\0" as *const u8 as *const libc::c_char
                as *const libc::c_void,
            17 as libc::c_int,
        ) <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        if BIO_write(
            bp,
            b"            Not Before: \0" as *const u8 as *const libc::c_char
                as *const libc::c_void,
            24 as libc::c_int,
        ) <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        if ASN1_TIME_print(bp, X509_get_notBefore(x)) == 0 {
            return 0 as libc::c_int;
        }
        if BIO_write(
            bp,
            b"\n            Not After : \0" as *const u8 as *const libc::c_char
                as *const libc::c_void,
            25 as libc::c_int,
        ) <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        if ASN1_TIME_print(bp, X509_get_notAfter(x)) == 0 {
            return 0 as libc::c_int;
        }
        if BIO_write(
            bp,
            b"\n\0" as *const u8 as *const libc::c_char as *const libc::c_void,
            1 as libc::c_int,
        ) <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
    }
    if cflag & ((1 as libc::c_long) << 6 as libc::c_int) as libc::c_ulong == 0 {
        if BIO_printf(
            bp,
            b"        Subject:%c\0" as *const u8 as *const libc::c_char,
            mlch as libc::c_int,
        ) <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        if X509_NAME_print_ex(bp, X509_get_subject_name(x), nmindent, nmflags)
            < 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        if BIO_write(
            bp,
            b"\n\0" as *const u8 as *const libc::c_char as *const libc::c_void,
            1 as libc::c_int,
        ) <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
    }
    if cflag & ((1 as libc::c_long) << 7 as libc::c_int) as libc::c_ulong == 0 {
        if BIO_write(
            bp,
            b"        Subject Public Key Info:\n\0" as *const u8 as *const libc::c_char
                as *const libc::c_void,
            33 as libc::c_int,
        ) <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        if BIO_printf(
            bp,
            b"%12sPublic Key Algorithm: \0" as *const u8 as *const libc::c_char,
            b"\0" as *const u8 as *const libc::c_char,
        ) <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        if i2a_ASN1_OBJECT(bp, (*(*(*ci).key).algor).algorithm) <= 0 as libc::c_int {
            return 0 as libc::c_int;
        }
        if BIO_puts(bp, b"\n\0" as *const u8 as *const libc::c_char) <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        let mut pkey: *const EVP_PKEY = X509_get0_pubkey(x);
        if pkey.is_null() {
            BIO_printf(
                bp,
                b"%12sUnable to load Public Key\n\0" as *const u8 as *const libc::c_char,
                b"\0" as *const u8 as *const libc::c_char,
            );
            ERR_print_errors(bp);
        } else {
            EVP_PKEY_print_public(bp, pkey, 16 as libc::c_int, 0 as *mut ASN1_PCTX);
        }
    }
    if cflag & ((1 as libc::c_long) << 12 as libc::c_int) as libc::c_ulong == 0 {
        if !((*ci).issuerUID).is_null() {
            if BIO_printf(
                bp,
                b"%8sIssuer Unique ID: \0" as *const u8 as *const libc::c_char,
                b"\0" as *const u8 as *const libc::c_char,
            ) <= 0 as libc::c_int
            {
                return 0 as libc::c_int;
            }
            if X509_signature_dump(bp, (*ci).issuerUID, 12 as libc::c_int) == 0 {
                return 0 as libc::c_int;
            }
        }
        if !((*ci).subjectUID).is_null() {
            if BIO_printf(
                bp,
                b"%8sSubject Unique ID: \0" as *const u8 as *const libc::c_char,
                b"\0" as *const u8 as *const libc::c_char,
            ) <= 0 as libc::c_int
            {
                return 0 as libc::c_int;
            }
            if X509_signature_dump(bp, (*ci).subjectUID, 12 as libc::c_int) == 0 {
                return 0 as libc::c_int;
            }
        }
    }
    if cflag & ((1 as libc::c_long) << 8 as libc::c_int) as libc::c_ulong == 0 {
        X509V3_extensions_print(
            bp,
            b"X509v3 extensions\0" as *const u8 as *const libc::c_char,
            (*ci).extensions,
            cflag,
            8 as libc::c_int,
        );
    }
    if cflag & ((1 as libc::c_long) << 9 as libc::c_int) as libc::c_ulong == 0 {
        if X509_signature_print(bp, (*x).sig_alg, (*x).signature) <= 0 as libc::c_int {
            return 0 as libc::c_int;
        }
    }
    if cflag & ((1 as libc::c_long) << 10 as libc::c_int) as libc::c_ulong == 0 {
        if X509_CERT_AUX_print(bp, (*x).aux, 0 as libc::c_int) == 0 {
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_signature_print(
    mut bp: *mut BIO,
    mut sigalg: *const X509_ALGOR,
    mut sig: *const ASN1_STRING,
) -> libc::c_int {
    if BIO_puts(bp, b"    Signature Algorithm: \0" as *const u8 as *const libc::c_char)
        <= 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    if i2a_ASN1_OBJECT(bp, (*sigalg).algorithm) <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let mut sig_nid: libc::c_int = OBJ_obj2nid((*sigalg).algorithm);
    if sig_nid == 912 as libc::c_int
        && x509_print_rsa_pss_params(bp, sigalg, 9 as libc::c_int, 0 as *mut ASN1_PCTX)
            == 0
    {
        return 0 as libc::c_int;
    }
    if !sig.is_null() {
        return X509_signature_dump(bp, sig, 9 as libc::c_int)
    } else if BIO_puts(bp, b"\n\0" as *const u8 as *const libc::c_char)
        <= 0 as libc::c_int
    {
        return 0 as libc::c_int
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_NAME_print(
    mut bp: *mut BIO,
    mut name: *const X509_NAME,
    mut obase: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut s: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut c: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut b: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_int = 0;
    b = X509_NAME_oneline(name, 0 as *mut libc::c_char, 0 as libc::c_int);
    if b.is_null() {
        return 0 as libc::c_int;
    }
    if *b == 0 {
        OPENSSL_free(b as *mut libc::c_void);
        return 1 as libc::c_int;
    }
    s = b.offset(1 as libc::c_int as isize);
    c = s;
    loop {
        if *s as libc::c_int == '/' as i32
            && (*s.offset(1 as libc::c_int as isize) as libc::c_int >= 'A' as i32
                && *s.offset(1 as libc::c_int as isize) as libc::c_int <= 'Z' as i32
                && (*s.offset(2 as libc::c_int as isize) as libc::c_int == '=' as i32
                    || *s.offset(2 as libc::c_int as isize) as libc::c_int >= 'A' as i32
                        && *s.offset(2 as libc::c_int as isize) as libc::c_int
                            <= 'Z' as i32
                        && *s.offset(3 as libc::c_int as isize) as libc::c_int
                            == '=' as i32)) || *s as libc::c_int == '\0' as i32
        {
            i = s.offset_from(c) as libc::c_long as libc::c_int;
            if BIO_write(bp, c as *const libc::c_void, i) != i {
                current_block = 8276799163163225288;
                break;
            }
            c = s.offset(1 as libc::c_int as isize);
            if *s as libc::c_int != '\0' as i32 {
                if BIO_write(
                    bp,
                    b", \0" as *const u8 as *const libc::c_char as *const libc::c_void,
                    2 as libc::c_int,
                ) != 2 as libc::c_int
                {
                    current_block = 8276799163163225288;
                    break;
                }
            }
        }
        if *s as libc::c_int == '\0' as i32 {
            current_block = 8457315219000651999;
            break;
        }
        s = s.offset(1);
        s;
    }
    match current_block {
        8276799163163225288 => {
            ERR_put_error(
                11 as libc::c_int,
                0 as libc::c_int,
                7 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/t_x509.c\0" as *const u8
                    as *const libc::c_char,
                325 as libc::c_int as libc::c_uint,
            );
        }
        _ => {
            ret = 1 as libc::c_int;
        }
    }
    OPENSSL_free(b as *mut libc::c_void);
    return ret;
}
