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
    pub type stack_st_X509_NAME_ENTRY;
    pub type stack_st;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn i2t_ASN1_OBJECT(
        buf: *mut libc::c_char,
        buf_len: libc::c_int,
        a: *const ASN1_OBJECT,
    ) -> libc::c_int;
    fn BUF_MEM_new() -> *mut BUF_MEM;
    fn BUF_MEM_free(buf: *mut BUF_MEM);
    fn BUF_MEM_grow(buf: *mut BUF_MEM, len: size_t) -> size_t;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_strlcpy(
        dst: *mut libc::c_char,
        src: *const libc::c_char,
        dst_size: size_t,
    ) -> size_t;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OBJ_obj2nid(obj: *const ASN1_OBJECT) -> libc::c_int;
    fn OBJ_nid2sn(nid: libc::c_int) -> *const libc::c_char;
}
pub type size_t = libc::c_ulong;
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
pub type ASN1_STRING = asn1_string_st;
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
pub struct X509_name_entry_st {
    pub object: *mut ASN1_OBJECT,
    pub value: *mut ASN1_STRING,
    pub set: libc::c_int,
}
pub type X509_NAME_ENTRY = X509_name_entry_st;
pub type OPENSSL_STACK = stack_st;
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_NAME_oneline(
    mut a: *const X509_NAME,
    mut buf: *mut libc::c_char,
    mut len: libc::c_int,
) -> *mut libc::c_char {
    let mut current_block: u64;
    let mut ne: *mut X509_NAME_ENTRY = 0 as *mut X509_NAME_ENTRY;
    let mut i: size_t = 0;
    let mut n: libc::c_int = 0;
    let mut lold: libc::c_int = 0;
    let mut l: libc::c_int = 0;
    let mut l1: libc::c_int = 0;
    let mut l2: libc::c_int = 0;
    let mut num: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    let mut type_0: libc::c_int = 0;
    let mut s: *const libc::c_char = 0 as *const libc::c_char;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut q: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut b: *mut BUF_MEM = 0 as *mut BUF_MEM;
    static mut hex: [libc::c_char; 17] = unsafe {
        *::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"0123456789ABCDEF\0")
    };
    let mut gs_doit: [libc::c_int; 4] = [0; 4];
    let mut tmp_buf: [libc::c_char; 80] = [0; 80];
    if buf.is_null() {
        b = BUF_MEM_new();
        if b.is_null() {
            current_block = 8302691589050515574;
        } else if BUF_MEM_grow(b, 200 as libc::c_int as size_t) == 0 {
            current_block = 8302691589050515574;
        } else {
            *((*b).data).offset(0 as libc::c_int as isize) = '\0' as i32 as libc::c_char;
            len = 200 as libc::c_int;
            current_block = 7746791466490516765;
        }
    } else {
        if len <= 0 as libc::c_int {
            return 0 as *mut libc::c_char;
        }
        current_block = 7746791466490516765;
    }
    match current_block {
        7746791466490516765 => {
            if a.is_null() {
                if !b.is_null() {
                    buf = (*b).data;
                    OPENSSL_free(b as *mut libc::c_void);
                }
                OPENSSL_strlcpy(
                    buf,
                    b"NO X509_NAME\0" as *const u8 as *const libc::c_char,
                    len as size_t,
                );
                return buf;
            }
            len -= 1;
            len;
            l = 0 as libc::c_int;
            i = 0 as libc::c_int as size_t;
            loop {
                if !(i < sk_X509_NAME_ENTRY_num((*a).entries)) {
                    current_block = 5873035170358615968;
                    break;
                }
                ne = sk_X509_NAME_ENTRY_value((*a).entries, i);
                n = OBJ_obj2nid((*ne).object);
                if n == 0 as libc::c_int
                    || {
                        s = OBJ_nid2sn(n);
                        s.is_null()
                    }
                {
                    i2t_ASN1_OBJECT(
                        tmp_buf.as_mut_ptr(),
                        ::core::mem::size_of::<[libc::c_char; 80]>() as libc::c_ulong
                            as libc::c_int,
                        (*ne).object,
                    );
                    s = tmp_buf.as_mut_ptr();
                }
                l1 = strlen(s) as libc::c_int;
                type_0 = (*(*ne).value).type_0;
                num = (*(*ne).value).length;
                if num > 1024 as libc::c_int * 1024 as libc::c_int {
                    ERR_put_error(
                        11 as libc::c_int,
                        0 as libc::c_int,
                        135 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_obj.c\0"
                            as *const u8 as *const libc::c_char,
                        121 as libc::c_int as libc::c_uint,
                    );
                    current_block = 8302691589050515574;
                    break;
                } else {
                    q = (*(*ne).value).data;
                    if type_0 == 27 as libc::c_int
                        && num % 4 as libc::c_int == 0 as libc::c_int
                    {
                        gs_doit[3 as libc::c_int as usize] = 0 as libc::c_int;
                        gs_doit[2 as libc::c_int
                            as usize] = gs_doit[3 as libc::c_int as usize];
                        gs_doit[1 as libc::c_int
                            as usize] = gs_doit[2 as libc::c_int as usize];
                        gs_doit[0 as libc::c_int
                            as usize] = gs_doit[1 as libc::c_int as usize];
                        j = 0 as libc::c_int;
                        while j < num {
                            if *q.offset(j as isize) as libc::c_int != 0 as libc::c_int {
                                gs_doit[(j & 3 as libc::c_int) as usize] = 1 as libc::c_int;
                            }
                            j += 1;
                            j;
                        }
                        if gs_doit[0 as libc::c_int as usize]
                            | gs_doit[1 as libc::c_int as usize]
                            | gs_doit[2 as libc::c_int as usize] != 0
                        {
                            gs_doit[3 as libc::c_int as usize] = 1 as libc::c_int;
                            gs_doit[2 as libc::c_int
                                as usize] = gs_doit[3 as libc::c_int as usize];
                            gs_doit[1 as libc::c_int
                                as usize] = gs_doit[2 as libc::c_int as usize];
                            gs_doit[0 as libc::c_int
                                as usize] = gs_doit[1 as libc::c_int as usize];
                        } else {
                            gs_doit[2 as libc::c_int as usize] = 0 as libc::c_int;
                            gs_doit[1 as libc::c_int
                                as usize] = gs_doit[2 as libc::c_int as usize];
                            gs_doit[0 as libc::c_int
                                as usize] = gs_doit[1 as libc::c_int as usize];
                            gs_doit[3 as libc::c_int as usize] = 1 as libc::c_int;
                        }
                    } else {
                        gs_doit[3 as libc::c_int as usize] = 1 as libc::c_int;
                        gs_doit[2 as libc::c_int
                            as usize] = gs_doit[3 as libc::c_int as usize];
                        gs_doit[1 as libc::c_int
                            as usize] = gs_doit[2 as libc::c_int as usize];
                        gs_doit[0 as libc::c_int
                            as usize] = gs_doit[1 as libc::c_int as usize];
                    }
                    j = 0 as libc::c_int;
                    l2 = j;
                    while j < num {
                        if !(gs_doit[(j & 3 as libc::c_int) as usize] == 0) {
                            l2 += 1;
                            l2;
                            if (*q.offset(j as isize) as libc::c_int) < ' ' as i32
                                || *q.offset(j as isize) as libc::c_int > '~' as i32
                            {
                                l2 += 3 as libc::c_int;
                            }
                        }
                        j += 1;
                        j;
                    }
                    lold = l;
                    l += 1 as libc::c_int + l1 + 1 as libc::c_int + l2;
                    if l > 1024 as libc::c_int * 1024 as libc::c_int {
                        ERR_put_error(
                            11 as libc::c_int,
                            0 as libc::c_int,
                            135 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x509_obj.c\0"
                                as *const u8 as *const libc::c_char,
                            157 as libc::c_int as libc::c_uint,
                        );
                        current_block = 8302691589050515574;
                        break;
                    } else {
                        if !b.is_null() {
                            if BUF_MEM_grow(b, (l + 1 as libc::c_int) as size_t) == 0 {
                                current_block = 8302691589050515574;
                                break;
                            }
                            p = &mut *((*b).data).offset(lold as isize)
                                as *mut libc::c_char;
                        } else {
                            if l > len {
                                current_block = 5873035170358615968;
                                break;
                            }
                            p = &mut *buf.offset(lold as isize) as *mut libc::c_char;
                        }
                        let fresh0 = p;
                        p = p.offset(1);
                        *fresh0 = '/' as i32 as libc::c_char;
                        OPENSSL_memcpy(
                            p as *mut libc::c_void,
                            s as *const libc::c_void,
                            l1 as libc::c_uint as size_t,
                        );
                        p = p.offset(l1 as isize);
                        let fresh1 = p;
                        p = p.offset(1);
                        *fresh1 = '=' as i32 as libc::c_char;
                        q = (*(*ne).value).data;
                        j = 0 as libc::c_int;
                        while j < num {
                            if !(gs_doit[(j & 3 as libc::c_int) as usize] == 0) {
                                n = *q.offset(j as isize) as libc::c_int;
                                if n < ' ' as i32 || n > '~' as i32 {
                                    let fresh2 = p;
                                    p = p.offset(1);
                                    *fresh2 = '\\' as i32 as libc::c_char;
                                    let fresh3 = p;
                                    p = p.offset(1);
                                    *fresh3 = 'x' as i32 as libc::c_char;
                                    let fresh4 = p;
                                    p = p.offset(1);
                                    *fresh4 = hex[(n >> 4 as libc::c_int & 0xf as libc::c_int)
                                        as usize];
                                    let fresh5 = p;
                                    p = p.offset(1);
                                    *fresh5 = hex[(n & 0xf as libc::c_int) as usize];
                                } else {
                                    let fresh6 = p;
                                    p = p.offset(1);
                                    *fresh6 = n as libc::c_char;
                                }
                            }
                            j += 1;
                            j;
                        }
                        *p = '\0' as i32 as libc::c_char;
                        i = i.wrapping_add(1);
                        i;
                    }
                }
            }
            match current_block {
                8302691589050515574 => {}
                _ => {
                    if !b.is_null() {
                        p = (*b).data;
                        OPENSSL_free(b as *mut libc::c_void);
                    } else {
                        p = buf;
                    }
                    if i == 0 as libc::c_int as size_t {
                        *p = '\0' as i32 as libc::c_char;
                    }
                    return p;
                }
            }
        }
        _ => {}
    }
    BUF_MEM_free(b);
    return 0 as *mut libc::c_char;
}
