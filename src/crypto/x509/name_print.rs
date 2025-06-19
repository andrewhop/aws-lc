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
    pub type X509_name_st;
    pub type X509_name_entry_st;
    pub type stack_st_void;
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn ASN1_STRING_print_ex(
        out: *mut BIO,
        str: *const ASN1_STRING,
        flags: libc::c_ulong,
    ) -> libc::c_int;
    fn X509_NAME_entry_count(name: *const X509_NAME) -> libc::c_int;
    fn X509_NAME_get_entry(
        name: *const X509_NAME,
        loc: libc::c_int,
    ) -> *mut X509_NAME_ENTRY;
    fn X509_NAME_ENTRY_get_object(entry: *const X509_NAME_ENTRY) -> *mut ASN1_OBJECT;
    fn X509_NAME_ENTRY_get_data(entry: *const X509_NAME_ENTRY) -> *mut ASN1_STRING;
    fn X509_NAME_ENTRY_set(entry: *const X509_NAME_ENTRY) -> libc::c_int;
    fn X509_NAME_print(
        bp: *mut BIO,
        name: *const X509_NAME,
        obase: libc::c_int,
    ) -> libc::c_int;
    fn BIO_free(bio: *mut BIO) -> libc::c_int;
    fn BIO_write(
        bio: *mut BIO,
        data: *const libc::c_void,
        len: libc::c_int,
    ) -> libc::c_int;
    fn BIO_new_fp(stream: *mut FILE, close_flag: libc::c_int) -> *mut BIO;
    fn OBJ_obj2nid(obj: *const ASN1_OBJECT) -> libc::c_int;
    fn OBJ_nid2sn(nid: libc::c_int) -> *const libc::c_char;
    fn OBJ_nid2ln(nid: libc::c_int) -> *const libc::c_char;
    fn OBJ_obj2txt(
        out: *mut libc::c_char,
        out_len: libc::c_int,
        obj: *const ASN1_OBJECT,
        always_return_oid: libc::c_int,
    ) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
}
pub type size_t = libc::c_ulong;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type ASN1_OBJECT = asn1_object_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_string_st {
    pub length: libc::c_int,
    pub type_0: libc::c_int,
    pub data: *mut libc::c_uchar,
    pub flags: libc::c_long,
}
pub type ASN1_STRING = asn1_string_st;
pub type X509_NAME = X509_name_st;
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
unsafe extern "C" fn maybe_write(
    mut out: *mut BIO,
    mut buf: *const libc::c_void,
    mut len: libc::c_int,
) -> libc::c_int {
    return (out.is_null() || BIO_write(out, buf, len) == len) as libc::c_int;
}
unsafe extern "C" fn do_indent(
    mut out: *mut BIO,
    mut indent: libc::c_int,
) -> libc::c_int {
    let mut i: libc::c_int = 0 as libc::c_int;
    while i < indent {
        if maybe_write(
            out,
            b" \0" as *const u8 as *const libc::c_char as *const libc::c_void,
            1 as libc::c_int,
        ) == 0
        {
            return 0 as libc::c_int;
        }
        i += 1;
        i;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn do_name_ex(
    mut out: *mut BIO,
    mut n: *const X509_NAME,
    mut indent: libc::c_int,
    mut flags: libc::c_ulong,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut prev: libc::c_int = -(1 as libc::c_int);
    let mut orflags: libc::c_int = 0;
    let mut cnt: libc::c_int = 0;
    let mut fn_opt: libc::c_int = 0;
    let mut fn_nid: libc::c_int = 0;
    let mut objtmp: [libc::c_char; 80] = [0; 80];
    let mut objbuf: *const libc::c_char = 0 as *const libc::c_char;
    let mut outlen: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    let mut sep_dn: *const libc::c_char = 0 as *const libc::c_char;
    let mut sep_mv: *const libc::c_char = 0 as *const libc::c_char;
    let mut sep_eq: *const libc::c_char = 0 as *const libc::c_char;
    let mut sep_dn_len: libc::c_int = 0;
    let mut sep_mv_len: libc::c_int = 0;
    let mut sep_eq_len: libc::c_int = 0;
    if indent < 0 as libc::c_int {
        indent = 0 as libc::c_int;
    }
    outlen = indent;
    if do_indent(out, indent) == 0 {
        return -(1 as libc::c_int);
    }
    match flags & (0xf as libc::c_ulong) << 16 as libc::c_int {
        262144 => {
            sep_dn = b"\n\0" as *const u8 as *const libc::c_char;
            sep_dn_len = 1 as libc::c_int;
            sep_mv = b" + \0" as *const u8 as *const libc::c_char;
            sep_mv_len = 3 as libc::c_int;
        }
        65536 => {
            sep_dn = b",\0" as *const u8 as *const libc::c_char;
            sep_dn_len = 1 as libc::c_int;
            sep_mv = b"+\0" as *const u8 as *const libc::c_char;
            sep_mv_len = 1 as libc::c_int;
            indent = 0 as libc::c_int;
        }
        131072 => {
            sep_dn = b", \0" as *const u8 as *const libc::c_char;
            sep_dn_len = 2 as libc::c_int;
            sep_mv = b" + \0" as *const u8 as *const libc::c_char;
            sep_mv_len = 3 as libc::c_int;
            indent = 0 as libc::c_int;
        }
        196608 => {
            sep_dn = b"; \0" as *const u8 as *const libc::c_char;
            sep_dn_len = 2 as libc::c_int;
            sep_mv = b" + \0" as *const u8 as *const libc::c_char;
            sep_mv_len = 3 as libc::c_int;
            indent = 0 as libc::c_int;
        }
        _ => return -(1 as libc::c_int),
    }
    if flags & (1 as libc::c_ulong) << 23 as libc::c_int != 0 {
        sep_eq = b" = \0" as *const u8 as *const libc::c_char;
        sep_eq_len = 3 as libc::c_int;
    } else {
        sep_eq = b"=\0" as *const u8 as *const libc::c_char;
        sep_eq_len = 1 as libc::c_int;
    }
    fn_opt = (flags & (0x3 as libc::c_ulong) << 21 as libc::c_int) as libc::c_int;
    cnt = X509_NAME_entry_count(n);
    i = 0 as libc::c_int;
    while i < cnt {
        let mut ent: *const X509_NAME_ENTRY = 0 as *const X509_NAME_ENTRY;
        if flags & (1 as libc::c_ulong) << 20 as libc::c_int != 0 {
            ent = X509_NAME_get_entry(n, cnt - i - 1 as libc::c_int);
        } else {
            ent = X509_NAME_get_entry(n, i);
        }
        if prev != -(1 as libc::c_int) {
            if prev == X509_NAME_ENTRY_set(ent) {
                if maybe_write(out, sep_mv as *const libc::c_void, sep_mv_len) == 0 {
                    return -(1 as libc::c_int);
                }
                outlen += sep_mv_len;
            } else {
                if maybe_write(out, sep_dn as *const libc::c_void, sep_dn_len) == 0 {
                    return -(1 as libc::c_int);
                }
                outlen += sep_dn_len;
                if do_indent(out, indent) == 0 {
                    return -(1 as libc::c_int);
                }
                outlen += indent;
            }
        }
        prev = X509_NAME_ENTRY_set(ent);
        let mut fn_0: *const ASN1_OBJECT = X509_NAME_ENTRY_get_object(ent);
        let mut val: *const ASN1_STRING = X509_NAME_ENTRY_get_data(ent);
        fn_nid = OBJ_obj2nid(fn_0);
        if fn_opt != (3 as libc::c_int) << 21 as libc::c_int {
            let mut objlen: libc::c_int = 0;
            let mut fld_len: libc::c_int = 0;
            if fn_opt == (2 as libc::c_int) << 21 as libc::c_int
                || fn_nid == 0 as libc::c_int
            {
                OBJ_obj2txt(
                    objtmp.as_mut_ptr(),
                    ::core::mem::size_of::<[libc::c_char; 80]>() as libc::c_ulong
                        as libc::c_int,
                    fn_0,
                    1 as libc::c_int,
                );
                fld_len = 0 as libc::c_int;
                objbuf = objtmp.as_mut_ptr();
            } else if fn_opt as libc::c_ulong == 0 as libc::c_ulong {
                fld_len = 10 as libc::c_int;
                objbuf = OBJ_nid2sn(fn_nid);
            } else if fn_opt == (1 as libc::c_int) << 21 as libc::c_int {
                fld_len = 25 as libc::c_int;
                objbuf = OBJ_nid2ln(fn_nid);
            } else {
                fld_len = 0 as libc::c_int;
                objbuf = b"\0" as *const u8 as *const libc::c_char;
            }
            objlen = strlen(objbuf) as libc::c_int;
            if maybe_write(out, objbuf as *const libc::c_void, objlen) == 0 {
                return -(1 as libc::c_int);
            }
            if objlen < fld_len
                && flags & ((1 as libc::c_int) << 25 as libc::c_int) as libc::c_ulong
                    != 0
            {
                if do_indent(out, fld_len - objlen) == 0 {
                    return -(1 as libc::c_int);
                }
                outlen += fld_len - objlen;
            }
            if maybe_write(out, sep_eq as *const libc::c_void, sep_eq_len) == 0 {
                return -(1 as libc::c_int);
            }
            outlen += objlen + sep_eq_len;
        }
        if fn_nid == 0 as libc::c_int
            && flags & (1 as libc::c_ulong) << 24 as libc::c_int != 0
        {
            orflags = 0x80 as libc::c_ulong as libc::c_int;
        } else {
            orflags = 0 as libc::c_int;
        }
        len = ASN1_STRING_print_ex(out, val, flags | orflags as libc::c_ulong);
        if len < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        outlen += len;
        i += 1;
        i;
    }
    return outlen;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_NAME_print_ex(
    mut out: *mut BIO,
    mut nm: *const X509_NAME,
    mut indent: libc::c_int,
    mut flags: libc::c_ulong,
) -> libc::c_int {
    if flags == 0 as libc::c_ulong {
        return X509_NAME_print(out, nm, indent);
    }
    return do_name_ex(out, nm, indent, flags);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_NAME_print_ex_fp(
    mut fp: *mut FILE,
    mut nm: *const X509_NAME,
    mut indent: libc::c_int,
    mut flags: libc::c_ulong,
) -> libc::c_int {
    let mut bio: *mut BIO = 0 as *mut BIO;
    if !fp.is_null() {
        bio = BIO_new_fp(fp, 0 as libc::c_int);
        if bio.is_null() {
            return -(1 as libc::c_int);
        }
    }
    let mut ret: libc::c_int = X509_NAME_print_ex(bio, nm, indent, flags);
    BIO_free(bio);
    return ret;
}
