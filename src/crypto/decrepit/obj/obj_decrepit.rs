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
    pub type env_md_st;
    pub type evp_cipher_st;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn EVP_CIPHER_do_all_sorted(
        callback: Option::<
            unsafe extern "C" fn(
                *const EVP_CIPHER,
                *const libc::c_char,
                *const libc::c_char,
                *mut libc::c_void,
            ) -> (),
        >,
        arg: *mut libc::c_void,
    );
    fn EVP_MD_do_all_sorted(
        callback: Option::<
            unsafe extern "C" fn(
                *const EVP_MD,
                *const libc::c_char,
                *const libc::c_char,
                *mut libc::c_void,
            ) -> (),
        >,
        arg: *mut libc::c_void,
    );
}
pub type size_t = libc::c_ulong;
pub type EVP_MD = env_md_st;
pub type EVP_CIPHER = evp_cipher_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct obj_name_st {
    pub type_0: libc::c_int,
    pub alias: libc::c_int,
    pub name: *const libc::c_char,
    pub data: *const libc::c_char,
}
pub type OBJ_NAME = obj_name_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct wrapped_callback {
    pub callback: Option::<
        unsafe extern "C" fn(*const OBJ_NAME, *mut libc::c_void) -> (),
    >,
    pub arg: *mut libc::c_void,
}
#[inline]
unsafe extern "C" fn OPENSSL_memset(
    mut dst: *mut libc::c_void,
    mut c: libc::c_int,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return dst;
    }
    return memset(dst, c, n);
}
unsafe extern "C" fn cipher_callback(
    mut cipher: *const EVP_CIPHER,
    mut name: *const libc::c_char,
    mut unused: *const libc::c_char,
    mut arg: *mut libc::c_void,
) {
    let mut wrapped: *const wrapped_callback = arg as *mut wrapped_callback;
    let mut obj_name: OBJ_NAME = obj_name_st {
        type_0: 0,
        alias: 0,
        name: 0 as *const libc::c_char,
        data: 0 as *const libc::c_char,
    };
    OPENSSL_memset(
        &mut obj_name as *mut OBJ_NAME as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<OBJ_NAME>() as libc::c_ulong,
    );
    obj_name.type_0 = 2 as libc::c_int;
    obj_name.name = name;
    obj_name.data = cipher as *const libc::c_char;
    ((*wrapped).callback)
        .expect("non-null function pointer")(&mut obj_name, (*wrapped).arg);
}
unsafe extern "C" fn md_callback(
    mut md: *const EVP_MD,
    mut name: *const libc::c_char,
    mut unused: *const libc::c_char,
    mut arg: *mut libc::c_void,
) {
    let mut wrapped: *const wrapped_callback = arg as *mut wrapped_callback;
    let mut obj_name: OBJ_NAME = obj_name_st {
        type_0: 0,
        alias: 0,
        name: 0 as *const libc::c_char,
        data: 0 as *const libc::c_char,
    };
    OPENSSL_memset(
        &mut obj_name as *mut OBJ_NAME as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<OBJ_NAME>() as libc::c_ulong,
    );
    obj_name.type_0 = 1 as libc::c_int;
    obj_name.name = name;
    obj_name.data = md as *const libc::c_char;
    ((*wrapped).callback)
        .expect("non-null function pointer")(&mut obj_name, (*wrapped).arg);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OBJ_NAME_do_all_sorted(
    mut type_0: libc::c_int,
    mut callback: Option::<
        unsafe extern "C" fn(*const OBJ_NAME, *mut libc::c_void) -> (),
    >,
    mut arg: *mut libc::c_void,
) {
    let mut wrapped: wrapped_callback = wrapped_callback {
        callback: None,
        arg: 0 as *mut libc::c_void,
    };
    wrapped.callback = callback;
    wrapped.arg = arg;
    if type_0 == 2 as libc::c_int {
        EVP_CIPHER_do_all_sorted(
            Some(
                cipher_callback
                    as unsafe extern "C" fn(
                        *const EVP_CIPHER,
                        *const libc::c_char,
                        *const libc::c_char,
                        *mut libc::c_void,
                    ) -> (),
            ),
            &mut wrapped as *mut wrapped_callback as *mut libc::c_void,
        );
    } else if type_0 == 1 as libc::c_int {
        EVP_MD_do_all_sorted(
            Some(
                md_callback
                    as unsafe extern "C" fn(
                        *const EVP_MD,
                        *const libc::c_char,
                        *const libc::c_char,
                        *mut libc::c_void,
                    ) -> (),
            ),
            &mut wrapped as *mut wrapped_callback as *mut libc::c_void,
        );
    } else {
        __assert_fail(
            b"0\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/obj/obj_decrepit.c\0"
                as *const u8 as *const libc::c_char,
            68 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 77],
                &[libc::c_char; 77],
            >(
                b"void OBJ_NAME_do_all_sorted(int, void (*)(const OBJ_NAME *, void *), void *)\0",
            ))
                .as_ptr(),
        );
        'c_2165: {
            __assert_fail(
                b"0\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/decrepit/obj/obj_decrepit.c\0"
                    as *const u8 as *const libc::c_char,
                68 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 77],
                    &[libc::c_char; 77],
                >(
                    b"void OBJ_NAME_do_all_sorted(int, void (*)(const OBJ_NAME *, void *), void *)\0",
                ))
                    .as_ptr(),
            );
        };
    };
}
