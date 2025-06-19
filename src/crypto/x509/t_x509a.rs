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
    pub type stack_st_ASN1_OBJECT;
    pub type stack_st_void;
    pub type stack_st;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn BIO_write(
        bio: *mut BIO,
        data: *const libc::c_void,
        len: libc::c_int,
    ) -> libc::c_int;
    fn BIO_puts(bio: *mut BIO, buf: *const libc::c_char) -> libc::c_int;
    fn BIO_printf(bio: *mut BIO, format: *const libc::c_char, _: ...) -> libc::c_int;
    fn OBJ_obj2txt(
        out: *mut libc::c_char,
        out_len: libc::c_int,
        obj: *const ASN1_OBJECT,
        always_return_oid: libc::c_int,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
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
pub type ASN1_UTF8STRING = asn1_string_st;
pub type CRYPTO_refcount_t = uint32_t;
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
pub type OPENSSL_STACK = stack_st;
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_num(mut sk: *const stack_st_ASN1_OBJECT) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_ASN1_OBJECT_value(
    mut sk: *const stack_st_ASN1_OBJECT,
    mut i: size_t,
) -> *mut ASN1_OBJECT {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut ASN1_OBJECT;
}
#[no_mangle]
pub unsafe extern "C" fn X509_CERT_AUX_print(
    mut out: *mut BIO,
    mut aux: *mut X509_CERT_AUX,
    mut indent: libc::c_int,
) -> libc::c_int {
    let mut oidstr: [libc::c_char; 80] = [0; 80];
    let mut first: libc::c_char = 0;
    let mut i: size_t = 0;
    let mut j: libc::c_int = 0;
    if aux.is_null() {
        return 1 as libc::c_int;
    }
    if !((*aux).trust).is_null() {
        first = 1 as libc::c_int as libc::c_char;
        BIO_printf(
            out,
            b"%*sTrusted Uses:\n%*s\0" as *const u8 as *const libc::c_char,
            indent,
            b"\0" as *const u8 as *const libc::c_char,
            indent + 2 as libc::c_int,
            b"\0" as *const u8 as *const libc::c_char,
        );
        i = 0 as libc::c_int as size_t;
        while i < sk_ASN1_OBJECT_num((*aux).trust) {
            if first == 0 {
                BIO_puts(out, b", \0" as *const u8 as *const libc::c_char);
            } else {
                first = 0 as libc::c_int as libc::c_char;
            }
            OBJ_obj2txt(
                oidstr.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 80]>() as libc::c_ulong
                    as libc::c_int,
                sk_ASN1_OBJECT_value((*aux).trust, i),
                0 as libc::c_int,
            );
            BIO_puts(out, oidstr.as_mut_ptr());
            i = i.wrapping_add(1);
            i;
        }
        BIO_puts(out, b"\n\0" as *const u8 as *const libc::c_char);
    } else {
        BIO_printf(
            out,
            b"%*sNo Trusted Uses.\n\0" as *const u8 as *const libc::c_char,
            indent,
            b"\0" as *const u8 as *const libc::c_char,
        );
    }
    if !((*aux).reject).is_null() {
        first = 1 as libc::c_int as libc::c_char;
        BIO_printf(
            out,
            b"%*sRejected Uses:\n%*s\0" as *const u8 as *const libc::c_char,
            indent,
            b"\0" as *const u8 as *const libc::c_char,
            indent + 2 as libc::c_int,
            b"\0" as *const u8 as *const libc::c_char,
        );
        i = 0 as libc::c_int as size_t;
        while i < sk_ASN1_OBJECT_num((*aux).reject) {
            if first == 0 {
                BIO_puts(out, b", \0" as *const u8 as *const libc::c_char);
            } else {
                first = 0 as libc::c_int as libc::c_char;
            }
            OBJ_obj2txt(
                oidstr.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 80]>() as libc::c_ulong
                    as libc::c_int,
                sk_ASN1_OBJECT_value((*aux).reject, i),
                0 as libc::c_int,
            );
            BIO_puts(out, oidstr.as_mut_ptr());
            i = i.wrapping_add(1);
            i;
        }
        BIO_puts(out, b"\n\0" as *const u8 as *const libc::c_char);
    } else {
        BIO_printf(
            out,
            b"%*sNo Rejected Uses.\n\0" as *const u8 as *const libc::c_char,
            indent,
            b"\0" as *const u8 as *const libc::c_char,
        );
    }
    if !((*aux).alias).is_null() {
        BIO_printf(
            out,
            b"%*sAlias: %.*s\n\0" as *const u8 as *const libc::c_char,
            indent,
            b"\0" as *const u8 as *const libc::c_char,
            (*(*aux).alias).length,
            (*(*aux).alias).data,
        );
    }
    if !((*aux).keyid).is_null() {
        BIO_printf(
            out,
            b"%*sKey Id: \0" as *const u8 as *const libc::c_char,
            indent,
            b"\0" as *const u8 as *const libc::c_char,
        );
        j = 0 as libc::c_int;
        while j < (*(*aux).keyid).length {
            BIO_printf(
                out,
                b"%s%02X\0" as *const u8 as *const libc::c_char,
                if j != 0 {
                    b":\0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                *((*(*aux).keyid).data).offset(j as isize) as libc::c_int,
            );
            j += 1;
            j;
        }
        BIO_write(
            out,
            b"\n\0" as *const u8 as *const libc::c_char as *const libc::c_void,
            1 as libc::c_int,
        );
    }
    return 1 as libc::c_int;
}
