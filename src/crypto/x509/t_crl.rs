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
    pub type X509_name_st;
    pub type X509_crl_st;
    pub type stack_st_void;
    pub type x509_revoked_st;
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type stack_st;
    pub type stack_st_X509_EXTENSION;
    pub type stack_st_X509_REVOKED;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn ASN1_TIME_print(out: *mut BIO, a: *const ASN1_TIME) -> libc::c_int;
    fn i2a_ASN1_INTEGER(bp: *mut BIO, a: *const ASN1_INTEGER) -> libc::c_int;
    fn X509_CRL_get_version(crl: *const X509_CRL) -> libc::c_long;
    fn X509_CRL_get0_lastUpdate(crl: *const X509_CRL) -> *const ASN1_TIME;
    fn X509_CRL_get0_nextUpdate(crl: *const X509_CRL) -> *const ASN1_TIME;
    fn X509_CRL_get_issuer(crl: *const X509_CRL) -> *mut X509_NAME;
    fn X509_CRL_get_REVOKED(crl: *mut X509_CRL) -> *mut stack_st_X509_REVOKED;
    fn X509_CRL_get0_extensions(crl: *const X509_CRL) -> *const stack_st_X509_EXTENSION;
    fn X509_CRL_get0_signature(
        crl: *const X509_CRL,
        out_sig: *mut *const ASN1_BIT_STRING,
        out_alg: *mut *const X509_ALGOR,
    );
    fn X509_REVOKED_get0_serialNumber(
        revoked: *const X509_REVOKED,
    ) -> *const ASN1_INTEGER;
    fn X509_REVOKED_get0_revocationDate(
        revoked: *const X509_REVOKED,
    ) -> *const ASN1_TIME;
    fn X509_REVOKED_get0_extensions(
        r: *const X509_REVOKED,
    ) -> *const stack_st_X509_EXTENSION;
    fn X509_NAME_oneline(
        name: *const X509_NAME,
        buf: *mut libc::c_char,
        size: libc::c_int,
    ) -> *mut libc::c_char;
    fn X509_signature_print(
        bio: *mut BIO,
        alg: *const X509_ALGOR,
        sig: *const ASN1_STRING,
    ) -> libc::c_int;
    fn X509V3_extensions_print(
        out: *mut BIO,
        title: *const libc::c_char,
        exts: *const stack_st_X509_EXTENSION,
        flag: libc::c_ulong,
        indent: libc::c_int,
    ) -> libc::c_int;
    fn BIO_free(bio: *mut BIO) -> libc::c_int;
    fn BIO_printf(bio: *mut BIO, format: *const libc::c_char, _: ...) -> libc::c_int;
    fn BIO_new_fp(stream: *mut FILE, close_flag: libc::c_int) -> *mut BIO;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
}
pub type size_t = libc::c_ulong;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type ASN1_BOOLEAN = libc::c_int;
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
pub type X509_NAME = X509_name_st;
pub type X509_ALGOR = X509_algor_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_algor_st {
    pub algorithm: *mut ASN1_OBJECT,
    pub parameter: *mut ASN1_TYPE,
}
pub type X509_CRL = X509_crl_st;
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
pub type X509_REVOKED = x509_revoked_st;
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
pub type OPENSSL_STACK = stack_st;
#[inline]
unsafe extern "C" fn sk_X509_REVOKED_num(
    mut sk: *const stack_st_X509_REVOKED,
) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_REVOKED_value(
    mut sk: *const stack_st_X509_REVOKED,
    mut i: size_t,
) -> *mut X509_REVOKED {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509_REVOKED;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_CRL_print_fp(
    mut fp: *mut FILE,
    mut x: *mut X509_CRL,
) -> libc::c_int {
    let mut b: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if b.is_null() {
        ERR_put_error(
            11 as libc::c_int,
            0 as libc::c_int,
            7 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/t_crl.c\0" as *const u8
                as *const libc::c_char,
            69 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = X509_CRL_print(b, x);
    BIO_free(b);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_CRL_print(
    mut out: *mut BIO,
    mut x: *mut X509_CRL,
) -> libc::c_int {
    let mut version: libc::c_long = X509_CRL_get_version(x);
    if 0 as libc::c_int as libc::c_long <= version
        && version <= 1 as libc::c_int as libc::c_long
    {} else {
        __assert_fail(
            b"X509_CRL_VERSION_1 <= version && version <= X509_CRL_VERSION_2\0"
                as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/t_crl.c\0" as *const u8
                as *const libc::c_char,
            79 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 38],
                &[libc::c_char; 38],
            >(b"int X509_CRL_print(BIO *, X509_CRL *)\0"))
                .as_ptr(),
        );
    }
    'c_21019: {
        if 0 as libc::c_int as libc::c_long <= version
            && version <= 1 as libc::c_int as libc::c_long
        {} else {
            __assert_fail(
                b"X509_CRL_VERSION_1 <= version && version <= X509_CRL_VERSION_2\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/t_crl.c\0" as *const u8
                    as *const libc::c_char,
                79 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 38],
                    &[libc::c_char; 38],
                >(b"int X509_CRL_print(BIO *, X509_CRL *)\0"))
                    .as_ptr(),
            );
        }
    };
    let mut sig_alg: *const X509_ALGOR = 0 as *const X509_ALGOR;
    let mut signature: *const ASN1_BIT_STRING = 0 as *const ASN1_BIT_STRING;
    X509_CRL_get0_signature(x, &mut signature, &mut sig_alg);
    if BIO_printf(
        out,
        b"Certificate Revocation List (CRL):\n\0" as *const u8 as *const libc::c_char,
    ) <= 0 as libc::c_int
        || BIO_printf(
            out,
            b"%8sVersion %ld (0x%lx)\n\0" as *const u8 as *const libc::c_char,
            b"\0" as *const u8 as *const libc::c_char,
            version + 1 as libc::c_int as libc::c_long,
            version as libc::c_ulong,
        ) <= 0 as libc::c_int
        || X509_signature_print(out, sig_alg, 0 as *const ASN1_STRING) == 0
    {
        return 0 as libc::c_int;
    }
    let mut issuer: *mut libc::c_char = X509_NAME_oneline(
        X509_CRL_get_issuer(x),
        0 as *mut libc::c_char,
        0 as libc::c_int,
    );
    let mut ok: libc::c_int = (!issuer.is_null()
        && BIO_printf(
            out,
            b"%8sIssuer: %s\n\0" as *const u8 as *const libc::c_char,
            b"\0" as *const u8 as *const libc::c_char,
            issuer,
        ) > 0 as libc::c_int) as libc::c_int;
    OPENSSL_free(issuer as *mut libc::c_void);
    if ok == 0 {
        return 0 as libc::c_int;
    }
    if BIO_printf(
        out,
        b"%8sLast Update: \0" as *const u8 as *const libc::c_char,
        b"\0" as *const u8 as *const libc::c_char,
    ) <= 0 as libc::c_int || ASN1_TIME_print(out, X509_CRL_get0_lastUpdate(x)) == 0
        || BIO_printf(
            out,
            b"\n%8sNext Update: \0" as *const u8 as *const libc::c_char,
            b"\0" as *const u8 as *const libc::c_char,
        ) <= 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    if !(X509_CRL_get0_nextUpdate(x)).is_null() {
        if ASN1_TIME_print(out, X509_CRL_get0_nextUpdate(x)) == 0 {
            return 0 as libc::c_int;
        }
    } else if BIO_printf(out, b"NONE\0" as *const u8 as *const libc::c_char)
        <= 0 as libc::c_int
    {
        return 0 as libc::c_int
    }
    if BIO_printf(out, b"\n\0" as *const u8 as *const libc::c_char) <= 0 as libc::c_int
        || X509V3_extensions_print(
            out,
            b"CRL extensions\0" as *const u8 as *const libc::c_char,
            X509_CRL_get0_extensions(x),
            0 as libc::c_int as libc::c_ulong,
            8 as libc::c_int,
        ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut rev: *const stack_st_X509_REVOKED = X509_CRL_get_REVOKED(x);
    if sk_X509_REVOKED_num(rev) > 0 as libc::c_int as size_t {
        if BIO_printf(
            out,
            b"Revoked Certificates:\n\0" as *const u8 as *const libc::c_char,
        ) <= 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
    } else if BIO_printf(
        out,
        b"No Revoked Certificates.\n\0" as *const u8 as *const libc::c_char,
    ) <= 0 as libc::c_int
    {
        return 0 as libc::c_int
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_X509_REVOKED_num(rev) {
        let mut r: *const X509_REVOKED = sk_X509_REVOKED_value(rev, i);
        BIO_printf(out, b"    Serial Number: \0" as *const u8 as *const libc::c_char)
            <= 0 as libc::c_int
            || i2a_ASN1_INTEGER(out, X509_REVOKED_get0_serialNumber(r))
                <= 0 as libc::c_int
            || BIO_printf(
                out,
                b"\n        Revocation Date: \0" as *const u8 as *const libc::c_char,
            ) <= 0 as libc::c_int
            || ASN1_TIME_print(out, X509_REVOKED_get0_revocationDate(r)) == 0
            || BIO_printf(out, b"\n\0" as *const u8 as *const libc::c_char)
                <= 0 as libc::c_int
            || X509V3_extensions_print(
                out,
                b"CRL entry extensions\0" as *const u8 as *const libc::c_char,
                X509_REVOKED_get0_extensions(r),
                0 as libc::c_int as libc::c_ulong,
                8 as libc::c_int,
            ) == 0;
        i = i.wrapping_add(1);
        i;
    }
    return X509_signature_print(out, sig_alg, signature);
}
