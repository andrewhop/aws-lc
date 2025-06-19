#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(extern_types, label_break_value)]
extern "C" {
    pub type stack_st_void;
    fn BIO_write(
        bio: *mut BIO,
        data: *const libc::c_void,
        len: libc::c_int,
    ) -> libc::c_int;
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_get_asn1(
        cbs: *mut CBS,
        out: *mut CBS,
        tag_value: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBS_is_valid_asn1_oid(cbs: *const CBS) -> libc::c_int;
    fn CBB_init(cbb: *mut CBB, initial_capacity: size_t) -> libc::c_int;
    fn CBB_cleanup(cbb: *mut CBB);
    fn CBB_add_asn1(
        cbb: *mut CBB,
        out_contents: *mut CBB,
        tag: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBB_add_bytes(cbb: *mut CBB, data: *const uint8_t, len: size_t) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn OBJ_dup(obj: *const ASN1_OBJECT) -> *mut ASN1_OBJECT;
    fn OBJ_obj2txt(
        out: *mut libc::c_char,
        out_len: libc::c_int,
        obj: *const ASN1_OBJECT,
        always_return_oid: libc::c_int,
    ) -> libc::c_int;
    fn CBB_finish_i2d(cbb: *mut CBB, outp: *mut *mut uint8_t) -> libc::c_int;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type CBS_ASN1_TAG = uint32_t;
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
pub struct cbb_st {
    pub child: *mut CBB,
    pub is_child: libc::c_char,
    pub u: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
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
#[no_mangle]
pub unsafe extern "C" fn i2d_ASN1_OBJECT(
    mut in_0: *const ASN1_OBJECT,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    if in_0.is_null() {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_object.c\0" as *const u8
                as *const libc::c_char,
            74 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    if (*in_0).length <= 0 as libc::c_int {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            134 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_object.c\0" as *const u8
                as *const libc::c_char,
            79 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    let mut cbb: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut child: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    if CBB_init(
        &mut cbb,
        ((*in_0).length as size_t).wrapping_add(2 as libc::c_int as size_t),
    ) == 0 || CBB_add_asn1(&mut cbb, &mut child, 0x6 as libc::c_uint) == 0
        || CBB_add_bytes(&mut child, (*in_0).data, (*in_0).length as size_t) == 0
    {
        CBB_cleanup(&mut cbb);
        return -(1 as libc::c_int);
    }
    return CBB_finish_i2d(&mut cbb, outp);
}
#[no_mangle]
pub unsafe extern "C" fn i2t_ASN1_OBJECT(
    mut buf: *mut libc::c_char,
    mut buf_len: libc::c_int,
    mut a: *const ASN1_OBJECT,
) -> libc::c_int {
    return OBJ_obj2txt(buf, buf_len, a, 0 as libc::c_int);
}
unsafe extern "C" fn write_str(
    mut bp: *mut BIO,
    mut str: *const libc::c_char,
) -> libc::c_int {
    let mut len: size_t = strlen(str);
    if len > 2147483647 as libc::c_int as size_t {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_object.c\0" as *const u8
                as *const libc::c_char,
            101 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    return if BIO_write(bp, str as *const libc::c_void, len as libc::c_int)
        == len as libc::c_int
    {
        len as libc::c_int
    } else {
        -(1 as libc::c_int)
    };
}
#[no_mangle]
pub unsafe extern "C" fn i2a_ASN1_OBJECT(
    mut bp: *mut BIO,
    mut a: *const ASN1_OBJECT,
) -> libc::c_int {
    if a.is_null() || ((*a).data).is_null() {
        return write_str(bp, b"NULL\0" as *const u8 as *const libc::c_char);
    }
    let mut buf: [libc::c_char; 80] = [0; 80];
    let mut allocated: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut str: *const libc::c_char = buf.as_mut_ptr();
    let mut len: libc::c_int = i2t_ASN1_OBJECT(
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 80]>() as libc::c_ulong as libc::c_int,
        a,
    );
    if len
        > ::core::mem::size_of::<[libc::c_char; 80]>() as libc::c_ulong as libc::c_int
            - 1 as libc::c_int
    {
        allocated = OPENSSL_malloc((len + 1 as libc::c_int) as size_t)
            as *mut libc::c_char;
        if allocated.is_null() {
            return -(1 as libc::c_int);
        }
        len = i2t_ASN1_OBJECT(allocated, len + 1 as libc::c_int, a);
        str = allocated;
    }
    if len <= 0 as libc::c_int {
        str = b"<INVALID>\0" as *const u8 as *const libc::c_char;
    }
    let mut ret: libc::c_int = write_str(bp, str);
    OPENSSL_free(allocated as *mut libc::c_void);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn d2i_ASN1_OBJECT(
    mut out: *mut *mut ASN1_OBJECT,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_OBJECT {
    if len < 0 as libc::c_int as libc::c_long {
        return 0 as *mut ASN1_OBJECT;
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut child: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, *inp, len as size_t);
    if CBS_get_asn1(&mut cbs, &mut child, 0x6 as libc::c_uint) == 0 {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            109 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_object.c\0" as *const u8
                as *const libc::c_char,
            142 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut ASN1_OBJECT;
    }
    let mut contents: *const uint8_t = CBS_data(&mut child);
    let mut ret: *mut ASN1_OBJECT = c2i_ASN1_OBJECT(
        out,
        &mut contents,
        CBS_len(&mut child) as libc::c_long,
    );
    if !ret.is_null() {
        if CBS_data(&mut cbs) == contents {} else {
            __assert_fail(
                b"CBS_data(&cbs) == contents\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_object.c\0"
                    as *const u8 as *const libc::c_char,
                150 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 75],
                    &[libc::c_char; 75],
                >(
                    b"ASN1_OBJECT *d2i_ASN1_OBJECT(ASN1_OBJECT **, const unsigned char **, long)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_8426: {
            if CBS_data(&mut cbs) == contents {} else {
                __assert_fail(
                    b"CBS_data(&cbs) == contents\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_object.c\0"
                        as *const u8 as *const libc::c_char,
                    150 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 75],
                        &[libc::c_char; 75],
                    >(
                        b"ASN1_OBJECT *d2i_ASN1_OBJECT(ASN1_OBJECT **, const unsigned char **, long)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        *inp = CBS_data(&mut cbs);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn c2i_ASN1_OBJECT(
    mut out: *mut *mut ASN1_OBJECT,
    mut inp: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut ASN1_OBJECT {
    if len < 0 as libc::c_int as libc::c_long {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            146 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_object.c\0" as *const u8
                as *const libc::c_char,
            159 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut ASN1_OBJECT;
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, *inp, len as size_t);
    if CBS_is_valid_asn1_oid(&mut cbs) == 0 {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            146 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_object.c\0" as *const u8
                as *const libc::c_char,
            166 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut ASN1_OBJECT;
    }
    let mut ret: *mut ASN1_OBJECT = ASN1_OBJECT_create(
        0 as libc::c_int,
        *inp,
        len as size_t,
        0 as *const libc::c_char,
        0 as *const libc::c_char,
    );
    if ret.is_null() {
        return 0 as *mut ASN1_OBJECT;
    }
    if !out.is_null() {
        ASN1_OBJECT_free(*out);
        *out = ret;
    }
    *inp = (*inp).offset(len as isize);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_OBJECT_new() -> *mut ASN1_OBJECT {
    let mut ret: *mut ASN1_OBJECT = 0 as *mut ASN1_OBJECT;
    ret = OPENSSL_zalloc(::core::mem::size_of::<ASN1_OBJECT>() as libc::c_ulong)
        as *mut ASN1_OBJECT;
    if ret.is_null() {
        return 0 as *mut ASN1_OBJECT;
    }
    (*ret).flags = 0x1 as libc::c_int;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_OBJECT_free(mut a: *mut ASN1_OBJECT) {
    if a.is_null() {
        return;
    }
    if (*a).flags & 0x4 as libc::c_int != 0 {
        OPENSSL_free((*a).sn as *mut libc::c_void);
        OPENSSL_free((*a).ln as *mut libc::c_void);
        (*a).ln = 0 as *const libc::c_char;
        (*a).sn = (*a).ln;
    }
    if (*a).flags & 0x8 as libc::c_int != 0 {
        OPENSSL_free((*a).data as *mut libc::c_void);
        (*a).data = 0 as *const libc::c_uchar;
        (*a).length = 0 as libc::c_int;
    }
    if (*a).flags & 0x1 as libc::c_int != 0 {
        OPENSSL_free(a as *mut libc::c_void);
    }
}
#[no_mangle]
pub unsafe extern "C" fn ASN1_OBJECT_create(
    mut nid: libc::c_int,
    mut data: *const libc::c_uchar,
    mut len: size_t,
    mut sn: *const libc::c_char,
    mut ln: *const libc::c_char,
) -> *mut ASN1_OBJECT {
    if len > 2147483647 as libc::c_int as size_t {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            173 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_object.c\0" as *const u8
                as *const libc::c_char,
            217 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut ASN1_OBJECT;
    }
    let mut o: ASN1_OBJECT = asn1_object_st {
        sn: 0 as *const libc::c_char,
        ln: 0 as *const libc::c_char,
        nid: 0,
        length: 0,
        data: 0 as *const libc::c_uchar,
        flags: 0,
    };
    o.sn = sn;
    o.ln = ln;
    o.data = data;
    o.nid = nid;
    o.length = len as libc::c_int;
    o.flags = 0x1 as libc::c_int | 0x4 as libc::c_int | 0x8 as libc::c_int;
    return OBJ_dup(&mut o);
}
