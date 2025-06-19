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
    pub type stack_st_void;
    fn BIO_write(
        bio: *mut BIO,
        data: *const libc::c_void,
        len: libc::c_int,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_string_st {
    pub length: libc::c_int,
    pub type_0: libc::c_int,
    pub data: *mut libc::c_uchar,
    pub flags: libc::c_long,
}
pub type ASN1_STRING = asn1_string_st;
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
#[no_mangle]
pub unsafe extern "C" fn i2a_ASN1_STRING(
    mut bp: *mut BIO,
    mut a: *const ASN1_STRING,
    mut type_0: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut i: libc::c_int = 0;
    let mut n: libc::c_int = 0 as libc::c_int;
    static mut h: *const libc::c_char = b"0123456789ABCDEF\0" as *const u8
        as *const libc::c_char;
    let mut buf: [libc::c_char; 2] = [0; 2];
    if a.is_null() {
        return 0 as libc::c_int;
    }
    if (*a).length == 0 as libc::c_int {
        if BIO_write(
            bp,
            b"0\0" as *const u8 as *const libc::c_char as *const libc::c_void,
            1 as libc::c_int,
        ) != 1 as libc::c_int
        {
            current_block = 784921444827200332;
        } else {
            n = 1 as libc::c_int;
            current_block = 12039483399334584727;
        }
    } else {
        i = 0 as libc::c_int;
        loop {
            if !(i < (*a).length) {
                current_block = 12039483399334584727;
                break;
            }
            if i != 0 as libc::c_int && i % 35 as libc::c_int == 0 as libc::c_int {
                if BIO_write(
                    bp,
                    b"\\\n\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                    2 as libc::c_int,
                ) != 2 as libc::c_int
                {
                    current_block = 784921444827200332;
                    break;
                }
                n += 2 as libc::c_int;
            }
            buf[0 as libc::c_int
                as usize] = *h
                .offset(
                    (*((*a).data).offset(i as isize) as libc::c_int >> 4 as libc::c_int
                        & 0xf as libc::c_int) as isize,
                );
            buf[1 as libc::c_int
                as usize] = *h
                .offset(
                    (*((*a).data).offset(i as isize) as libc::c_int & 0xf as libc::c_int)
                        as isize,
                );
            if BIO_write(bp, buf.as_mut_ptr() as *const libc::c_void, 2 as libc::c_int)
                != 2 as libc::c_int
            {
                current_block = 784921444827200332;
                break;
            }
            n += 2 as libc::c_int;
            i += 1;
            i;
        }
    }
    match current_block {
        12039483399334584727 => return n,
        _ => return -(1 as libc::c_int),
    };
}
