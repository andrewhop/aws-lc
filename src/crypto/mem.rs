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
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn free(_: *mut libc::c_void);
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn __errno_location() -> *mut libc::c_int;
    fn vsnprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ::core::ffi::VaList,
    ) -> libc::c_int;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn sdallocx(ptr: *mut libc::c_void, size: size_t, flags: libc::c_int);
    fn OPENSSL_memory_alloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_memory_free(ptr: *mut libc::c_void);
    fn OPENSSL_memory_get_size(ptr: *mut libc::c_void) -> size_t;
    fn OPENSSL_memory_realloc(ptr: *mut libc::c_void, size: size_t) -> *mut libc::c_void;
}
pub type __builtin_va_list = [__va_list_tag; 1];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __va_list_tag {
    pub gp_offset: libc::c_uint,
    pub fp_offset: libc::c_uint,
    pub overflow_arg_area: *mut libc::c_void,
    pub reg_save_area: *mut libc::c_void,
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type va_list = __builtin_va_list;
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
unsafe extern "C" fn __asan_poison_memory_region(
    mut addr: *const libc::c_void,
    mut size: size_t,
) {}
unsafe extern "C" fn __asan_unpoison_memory_region(
    mut addr: *const libc::c_void,
    mut size: size_t,
) {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_mem_ctrl(mut mode: libc::c_int) -> libc::c_int {
    return 0 as libc::c_int;
}
static mut malloc_impl: Option::<
    unsafe extern "C" fn(size_t, *const libc::c_char, libc::c_int) -> *mut libc::c_void,
> = None;
static mut realloc_impl: Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        size_t,
        *const libc::c_char,
        libc::c_int,
    ) -> *mut libc::c_void,
> = None;
static mut free_impl: Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, libc::c_int) -> (),
> = None;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_set_mem_functions(
    mut m: Option::<
        unsafe extern "C" fn(
            size_t,
            *const libc::c_char,
            libc::c_int,
        ) -> *mut libc::c_void,
    >,
    mut r: Option::<
        unsafe extern "C" fn(
            *mut libc::c_void,
            size_t,
            *const libc::c_char,
            libc::c_int,
        ) -> *mut libc::c_void,
    >,
    mut f: Option::<
        unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, libc::c_int) -> (),
    >,
) -> libc::c_int {
    if m.is_none() || r.is_none() || f.is_none() {
        return 0 as libc::c_int;
    }
    if malloc_impl.is_some() || realloc_impl.is_some() || free_impl.is_some() {
        return 0 as libc::c_int;
    }
    if (Some(OPENSSL_memory_alloc as unsafe extern "C" fn(size_t) -> *mut libc::c_void))
        .is_some()
        || (Some(OPENSSL_memory_free as unsafe extern "C" fn(*mut libc::c_void) -> ()))
            .is_some()
        || (Some(
            OPENSSL_memory_get_size as unsafe extern "C" fn(*mut libc::c_void) -> size_t,
        ))
            .is_some()
        || (Some(
            OPENSSL_memory_realloc
                as unsafe extern "C" fn(*mut libc::c_void, size_t) -> *mut libc::c_void,
        ))
            .is_some()
    {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                as *const libc::c_char,
            158 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    malloc_impl = m;
    realloc_impl = r;
    free_impl = f;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_malloc(mut size: size_t) -> *mut libc::c_void {
    let mut ptr_0: *mut libc::c_void = 0 as *mut libc::c_void;
    if malloc_impl.is_some() {
        if (Some(
            OPENSSL_memory_alloc as unsafe extern "C" fn(size_t) -> *mut libc::c_void,
        ))
            .is_none()
        {} else {
            __assert_fail(
                b"OPENSSL_memory_alloc == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                    as *const libc::c_char,
                169 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 29],
                    &[libc::c_char; 29],
                >(b"void *OPENSSL_malloc(size_t)\0"))
                    .as_ptr(),
            );
        }
        'c_1737: {
            if (Some(
                OPENSSL_memory_alloc as unsafe extern "C" fn(size_t) -> *mut libc::c_void,
            ))
                .is_none()
            {} else {
                __assert_fail(
                    b"OPENSSL_memory_alloc == NULL\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                        as *const libc::c_char,
                    169 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 29],
                        &[libc::c_char; 29],
                    >(b"void *OPENSSL_malloc(size_t)\0"))
                        .as_ptr(),
                );
            }
        };
        if (Some(
            OPENSSL_memory_realloc
                as unsafe extern "C" fn(*mut libc::c_void, size_t) -> *mut libc::c_void,
        ))
            .is_none()
        {} else {
            __assert_fail(
                b"OPENSSL_memory_realloc == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                    as *const libc::c_char,
                170 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 29],
                    &[libc::c_char; 29],
                >(b"void *OPENSSL_malloc(size_t)\0"))
                    .as_ptr(),
            );
        }
        'c_1689: {
            if (Some(
                OPENSSL_memory_realloc
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        size_t,
                    ) -> *mut libc::c_void,
            ))
                .is_none()
            {} else {
                __assert_fail(
                    b"OPENSSL_memory_realloc == NULL\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                        as *const libc::c_char,
                    170 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 29],
                        &[libc::c_char; 29],
                    >(b"void *OPENSSL_malloc(size_t)\0"))
                        .as_ptr(),
                );
            }
        };
        if (Some(OPENSSL_memory_free as unsafe extern "C" fn(*mut libc::c_void) -> ()))
            .is_none()
        {} else {
            __assert_fail(
                b"OPENSSL_memory_free == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                    as *const libc::c_char,
                171 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 29],
                    &[libc::c_char; 29],
                >(b"void *OPENSSL_malloc(size_t)\0"))
                    .as_ptr(),
            );
        }
        'c_1647: {
            if (Some(
                OPENSSL_memory_free as unsafe extern "C" fn(*mut libc::c_void) -> (),
            ))
                .is_none()
            {} else {
                __assert_fail(
                    b"OPENSSL_memory_free == NULL\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                        as *const libc::c_char,
                    171 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 29],
                        &[libc::c_char; 29],
                    >(b"void *OPENSSL_malloc(size_t)\0"))
                        .as_ptr(),
                );
            }
        };
        if (Some(
            OPENSSL_memory_get_size as unsafe extern "C" fn(*mut libc::c_void) -> size_t,
        ))
            .is_none()
        {} else {
            __assert_fail(
                b"OPENSSL_memory_get_size == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                    as *const libc::c_char,
                172 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 29],
                    &[libc::c_char; 29],
                >(b"void *OPENSSL_malloc(size_t)\0"))
                    .as_ptr(),
            );
        }
        'c_1605: {
            if (Some(
                OPENSSL_memory_get_size
                    as unsafe extern "C" fn(*mut libc::c_void) -> size_t,
            ))
                .is_none()
            {} else {
                __assert_fail(
                    b"OPENSSL_memory_get_size == NULL\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                        as *const libc::c_char,
                    172 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 29],
                        &[libc::c_char; 29],
                    >(b"void *OPENSSL_malloc(size_t)\0"))
                        .as_ptr(),
                );
            }
        };
        if realloc_impl.is_some() {} else {
            __assert_fail(
                b"realloc_impl != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                    as *const libc::c_char,
                173 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 29],
                    &[libc::c_char; 29],
                >(b"void *OPENSSL_malloc(size_t)\0"))
                    .as_ptr(),
            );
        }
        'c_1554: {
            if realloc_impl.is_some() {} else {
                __assert_fail(
                    b"realloc_impl != NULL\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                        as *const libc::c_char,
                    173 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 29],
                        &[libc::c_char; 29],
                    >(b"void *OPENSSL_malloc(size_t)\0"))
                        .as_ptr(),
                );
            }
        };
        if free_impl.is_some() {} else {
            __assert_fail(
                b"free_impl != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                    as *const libc::c_char,
                174 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 29],
                    &[libc::c_char; 29],
                >(b"void *OPENSSL_malloc(size_t)\0"))
                    .as_ptr(),
            );
        }
        'c_1503: {
            if free_impl.is_some() {} else {
                __assert_fail(
                    b"free_impl != NULL\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                        as *const libc::c_char,
                    174 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 29],
                        &[libc::c_char; 29],
                    >(b"void *OPENSSL_malloc(size_t)\0"))
                        .as_ptr(),
                );
            }
        };
        return malloc_impl
            .expect(
                "non-null function pointer",
            )(size, b"\0" as *const u8 as *const libc::c_char, 0 as libc::c_int);
    }
    if (Some(OPENSSL_memory_alloc as unsafe extern "C" fn(size_t) -> *mut libc::c_void))
        .is_some()
    {
        if (Some(OPENSSL_memory_free as unsafe extern "C" fn(*mut libc::c_void) -> ()))
            .is_some()
        {} else {
            __assert_fail(
                b"OPENSSL_memory_free != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                    as *const libc::c_char,
                178 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 29],
                    &[libc::c_char; 29],
                >(b"void *OPENSSL_malloc(size_t)\0"))
                    .as_ptr(),
            );
        }
        'c_1423: {
            if (Some(
                OPENSSL_memory_free as unsafe extern "C" fn(*mut libc::c_void) -> (),
            ))
                .is_some()
            {} else {
                __assert_fail(
                    b"OPENSSL_memory_free != NULL\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                        as *const libc::c_char,
                    178 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 29],
                        &[libc::c_char; 29],
                    >(b"void *OPENSSL_malloc(size_t)\0"))
                        .as_ptr(),
                );
            }
        };
        if (Some(
            OPENSSL_memory_get_size as unsafe extern "C" fn(*mut libc::c_void) -> size_t,
        ))
            .is_some()
        {} else {
            __assert_fail(
                b"OPENSSL_memory_get_size != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                    as *const libc::c_char,
                179 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 29],
                    &[libc::c_char; 29],
                >(b"void *OPENSSL_malloc(size_t)\0"))
                    .as_ptr(),
            );
        }
        'c_1367: {
            if (Some(
                OPENSSL_memory_get_size
                    as unsafe extern "C" fn(*mut libc::c_void) -> size_t,
            ))
                .is_some()
            {} else {
                __assert_fail(
                    b"OPENSSL_memory_get_size != NULL\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                        as *const libc::c_char,
                    179 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 29],
                        &[libc::c_char; 29],
                    >(b"void *OPENSSL_malloc(size_t)\0"))
                        .as_ptr(),
                );
            }
        };
        let mut ptr: *mut libc::c_void = OPENSSL_memory_alloc(size);
        if !(ptr.is_null() && size != 0 as libc::c_int as size_t) {
            return ptr;
        }
    } else if !(size.wrapping_add(8 as libc::c_int as size_t) < size) {
        ptr_0 = malloc(size.wrapping_add(8 as libc::c_int as size_t));
        if !ptr_0.is_null() {
            *(ptr_0 as *mut size_t) = size;
            __asan_poison_memory_region(ptr_0, 8 as libc::c_int as size_t);
            return (ptr_0 as *mut uint8_t).offset(8 as libc::c_int as isize)
                as *mut libc::c_void;
        }
    }
    ERR_put_error(
        14 as libc::c_int,
        0 as libc::c_int,
        1 as libc::c_int | 64 as libc::c_int,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
            as *const libc::c_char,
        203 as libc::c_int as libc::c_uint,
    );
    return 0 as *mut libc::c_void;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_zalloc(mut size: size_t) -> *mut libc::c_void {
    let mut ret: *mut libc::c_void = OPENSSL_malloc(size);
    if !ret.is_null() {
        OPENSSL_memset(ret, 0 as libc::c_int, size);
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_calloc(
    mut num: size_t,
    mut size: size_t,
) -> *mut libc::c_void {
    if size != 0 as libc::c_int as size_t
        && num > (18446744073709551615 as libc::c_ulong).wrapping_div(size)
    {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                as *const libc::c_char,
            217 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut libc::c_void;
    }
    return OPENSSL_zalloc(num * size);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_free(mut orig_ptr: *mut libc::c_void) {
    if orig_ptr.is_null() {
        return;
    }
    if free_impl.is_some() {
        if (Some(
            OPENSSL_memory_alloc as unsafe extern "C" fn(size_t) -> *mut libc::c_void,
        ))
            .is_none()
        {} else {
            __assert_fail(
                b"OPENSSL_memory_alloc == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                    as *const libc::c_char,
                229 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 26],
                    &[libc::c_char; 26],
                >(b"void OPENSSL_free(void *)\0"))
                    .as_ptr(),
            );
        }
        'c_2276: {
            if (Some(
                OPENSSL_memory_alloc as unsafe extern "C" fn(size_t) -> *mut libc::c_void,
            ))
                .is_none()
            {} else {
                __assert_fail(
                    b"OPENSSL_memory_alloc == NULL\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                        as *const libc::c_char,
                    229 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 26],
                        &[libc::c_char; 26],
                    >(b"void OPENSSL_free(void *)\0"))
                        .as_ptr(),
                );
            }
        };
        if (Some(
            OPENSSL_memory_realloc
                as unsafe extern "C" fn(*mut libc::c_void, size_t) -> *mut libc::c_void,
        ))
            .is_none()
        {} else {
            __assert_fail(
                b"OPENSSL_memory_realloc == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                    as *const libc::c_char,
                230 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 26],
                    &[libc::c_char; 26],
                >(b"void OPENSSL_free(void *)\0"))
                    .as_ptr(),
            );
        }
        'c_2234: {
            if (Some(
                OPENSSL_memory_realloc
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        size_t,
                    ) -> *mut libc::c_void,
            ))
                .is_none()
            {} else {
                __assert_fail(
                    b"OPENSSL_memory_realloc == NULL\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                        as *const libc::c_char,
                    230 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 26],
                        &[libc::c_char; 26],
                    >(b"void OPENSSL_free(void *)\0"))
                        .as_ptr(),
                );
            }
        };
        if (Some(OPENSSL_memory_free as unsafe extern "C" fn(*mut libc::c_void) -> ()))
            .is_none()
        {} else {
            __assert_fail(
                b"OPENSSL_memory_free == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                    as *const libc::c_char,
                231 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 26],
                    &[libc::c_char; 26],
                >(b"void OPENSSL_free(void *)\0"))
                    .as_ptr(),
            );
        }
        'c_2192: {
            if (Some(
                OPENSSL_memory_free as unsafe extern "C" fn(*mut libc::c_void) -> (),
            ))
                .is_none()
            {} else {
                __assert_fail(
                    b"OPENSSL_memory_free == NULL\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                        as *const libc::c_char,
                    231 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 26],
                        &[libc::c_char; 26],
                    >(b"void OPENSSL_free(void *)\0"))
                        .as_ptr(),
                );
            }
        };
        if (Some(
            OPENSSL_memory_get_size as unsafe extern "C" fn(*mut libc::c_void) -> size_t,
        ))
            .is_none()
        {} else {
            __assert_fail(
                b"OPENSSL_memory_get_size == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                    as *const libc::c_char,
                232 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 26],
                    &[libc::c_char; 26],
                >(b"void OPENSSL_free(void *)\0"))
                    .as_ptr(),
            );
        }
        'c_2150: {
            if (Some(
                OPENSSL_memory_get_size
                    as unsafe extern "C" fn(*mut libc::c_void) -> size_t,
            ))
                .is_none()
            {} else {
                __assert_fail(
                    b"OPENSSL_memory_get_size == NULL\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                        as *const libc::c_char,
                    232 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 26],
                        &[libc::c_char; 26],
                    >(b"void OPENSSL_free(void *)\0"))
                        .as_ptr(),
                );
            }
        };
        if malloc_impl.is_some() {} else {
            __assert_fail(
                b"malloc_impl != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                    as *const libc::c_char,
                233 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 26],
                    &[libc::c_char; 26],
                >(b"void OPENSSL_free(void *)\0"))
                    .as_ptr(),
            );
        }
        'c_2107: {
            if malloc_impl.is_some() {} else {
                __assert_fail(
                    b"malloc_impl != NULL\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                        as *const libc::c_char,
                    233 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 26],
                        &[libc::c_char; 26],
                    >(b"void OPENSSL_free(void *)\0"))
                        .as_ptr(),
                );
            }
        };
        if realloc_impl.is_some() {} else {
            __assert_fail(
                b"realloc_impl != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                    as *const libc::c_char,
                234 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 26],
                    &[libc::c_char; 26],
                >(b"void OPENSSL_free(void *)\0"))
                    .as_ptr(),
            );
        }
        'c_2064: {
            if realloc_impl.is_some() {} else {
                __assert_fail(
                    b"realloc_impl != NULL\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                        as *const libc::c_char,
                    234 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 26],
                        &[libc::c_char; 26],
                    >(b"void OPENSSL_free(void *)\0"))
                        .as_ptr(),
                );
            }
        };
        free_impl
            .expect(
                "non-null function pointer",
            )(orig_ptr, b"\0" as *const u8 as *const libc::c_char, 0 as libc::c_int);
        return;
    }
    if (Some(OPENSSL_memory_free as unsafe extern "C" fn(*mut libc::c_void) -> ()))
        .is_some()
    {
        OPENSSL_memory_free(orig_ptr);
        return;
    }
    let mut ptr: *mut libc::c_void = (orig_ptr as *mut uint8_t)
        .offset(-(8 as libc::c_int as isize)) as *mut libc::c_void;
    __asan_unpoison_memory_region(ptr, 8 as libc::c_int as size_t);
    let mut size: size_t = *(ptr as *mut size_t);
    OPENSSL_cleanse(ptr, size.wrapping_add(8 as libc::c_int as size_t));
    if (Some(
        sdallocx as unsafe extern "C" fn(*mut libc::c_void, size_t, libc::c_int) -> (),
    ))
        .is_some()
    {
        sdallocx(ptr, size.wrapping_add(8 as libc::c_int as size_t), 0 as libc::c_int);
    } else {
        free(ptr);
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_realloc(
    mut orig_ptr: *mut libc::c_void,
    mut new_size: size_t,
) -> *mut libc::c_void {
    if orig_ptr.is_null() {
        return OPENSSL_malloc(new_size);
    }
    if realloc_impl.is_some() {
        if (Some(
            OPENSSL_memory_alloc as unsafe extern "C" fn(size_t) -> *mut libc::c_void,
        ))
            .is_none()
        {} else {
            __assert_fail(
                b"OPENSSL_memory_alloc == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                    as *const libc::c_char,
                269 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 38],
                    &[libc::c_char; 38],
                >(b"void *OPENSSL_realloc(void *, size_t)\0"))
                    .as_ptr(),
            );
        }
        'c_2801: {
            if (Some(
                OPENSSL_memory_alloc as unsafe extern "C" fn(size_t) -> *mut libc::c_void,
            ))
                .is_none()
            {} else {
                __assert_fail(
                    b"OPENSSL_memory_alloc == NULL\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                        as *const libc::c_char,
                    269 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 38],
                        &[libc::c_char; 38],
                    >(b"void *OPENSSL_realloc(void *, size_t)\0"))
                        .as_ptr(),
                );
            }
        };
        if (Some(
            OPENSSL_memory_realloc
                as unsafe extern "C" fn(*mut libc::c_void, size_t) -> *mut libc::c_void,
        ))
            .is_none()
        {} else {
            __assert_fail(
                b"OPENSSL_memory_realloc == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                    as *const libc::c_char,
                270 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 38],
                    &[libc::c_char; 38],
                >(b"void *OPENSSL_realloc(void *, size_t)\0"))
                    .as_ptr(),
            );
        }
        'c_2759: {
            if (Some(
                OPENSSL_memory_realloc
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        size_t,
                    ) -> *mut libc::c_void,
            ))
                .is_none()
            {} else {
                __assert_fail(
                    b"OPENSSL_memory_realloc == NULL\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                        as *const libc::c_char,
                    270 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 38],
                        &[libc::c_char; 38],
                    >(b"void *OPENSSL_realloc(void *, size_t)\0"))
                        .as_ptr(),
                );
            }
        };
        if (Some(OPENSSL_memory_free as unsafe extern "C" fn(*mut libc::c_void) -> ()))
            .is_none()
        {} else {
            __assert_fail(
                b"OPENSSL_memory_free == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                    as *const libc::c_char,
                271 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 38],
                    &[libc::c_char; 38],
                >(b"void *OPENSSL_realloc(void *, size_t)\0"))
                    .as_ptr(),
            );
        }
        'c_2717: {
            if (Some(
                OPENSSL_memory_free as unsafe extern "C" fn(*mut libc::c_void) -> (),
            ))
                .is_none()
            {} else {
                __assert_fail(
                    b"OPENSSL_memory_free == NULL\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                        as *const libc::c_char,
                    271 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 38],
                        &[libc::c_char; 38],
                    >(b"void *OPENSSL_realloc(void *, size_t)\0"))
                        .as_ptr(),
                );
            }
        };
        if (Some(
            OPENSSL_memory_get_size as unsafe extern "C" fn(*mut libc::c_void) -> size_t,
        ))
            .is_none()
        {} else {
            __assert_fail(
                b"OPENSSL_memory_get_size == NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                    as *const libc::c_char,
                272 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 38],
                    &[libc::c_char; 38],
                >(b"void *OPENSSL_realloc(void *, size_t)\0"))
                    .as_ptr(),
            );
        }
        'c_2675: {
            if (Some(
                OPENSSL_memory_get_size
                    as unsafe extern "C" fn(*mut libc::c_void) -> size_t,
            ))
                .is_none()
            {} else {
                __assert_fail(
                    b"OPENSSL_memory_get_size == NULL\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                        as *const libc::c_char,
                    272 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 38],
                        &[libc::c_char; 38],
                    >(b"void *OPENSSL_realloc(void *, size_t)\0"))
                        .as_ptr(),
                );
            }
        };
        if malloc_impl.is_some() {} else {
            __assert_fail(
                b"malloc_impl != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                    as *const libc::c_char,
                273 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 38],
                    &[libc::c_char; 38],
                >(b"void *OPENSSL_realloc(void *, size_t)\0"))
                    .as_ptr(),
            );
        }
        'c_2633: {
            if malloc_impl.is_some() {} else {
                __assert_fail(
                    b"malloc_impl != NULL\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                        as *const libc::c_char,
                    273 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 38],
                        &[libc::c_char; 38],
                    >(b"void *OPENSSL_realloc(void *, size_t)\0"))
                        .as_ptr(),
                );
            }
        };
        if free_impl.is_some() {} else {
            __assert_fail(
                b"free_impl != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                    as *const libc::c_char,
                274 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 38],
                    &[libc::c_char; 38],
                >(b"void *OPENSSL_realloc(void *, size_t)\0"))
                    .as_ptr(),
            );
        }
        'c_2591: {
            if free_impl.is_some() {} else {
                __assert_fail(
                    b"free_impl != NULL\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                        as *const libc::c_char,
                    274 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 38],
                        &[libc::c_char; 38],
                    >(b"void *OPENSSL_realloc(void *, size_t)\0"))
                        .as_ptr(),
                );
            }
        };
        return realloc_impl
            .expect(
                "non-null function pointer",
            )(
            orig_ptr,
            new_size,
            b"\0" as *const u8 as *const libc::c_char,
            0 as libc::c_int,
        );
    }
    if (Some(
        OPENSSL_memory_realloc
            as unsafe extern "C" fn(*mut libc::c_void, size_t) -> *mut libc::c_void,
    ))
        .is_some()
    {
        if (Some(
            OPENSSL_memory_alloc as unsafe extern "C" fn(size_t) -> *mut libc::c_void,
        ))
            .is_some()
        {} else {
            __assert_fail(
                b"OPENSSL_memory_alloc != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                    as *const libc::c_char,
                278 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 38],
                    &[libc::c_char; 38],
                >(b"void *OPENSSL_realloc(void *, size_t)\0"))
                    .as_ptr(),
            );
        }
        'c_2524: {
            if (Some(
                OPENSSL_memory_alloc as unsafe extern "C" fn(size_t) -> *mut libc::c_void,
            ))
                .is_some()
            {} else {
                __assert_fail(
                    b"OPENSSL_memory_alloc != NULL\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                        as *const libc::c_char,
                    278 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 38],
                        &[libc::c_char; 38],
                    >(b"void *OPENSSL_realloc(void *, size_t)\0"))
                        .as_ptr(),
                );
            }
        };
        if (Some(OPENSSL_memory_free as unsafe extern "C" fn(*mut libc::c_void) -> ()))
            .is_some()
        {} else {
            __assert_fail(
                b"OPENSSL_memory_free != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                    as *const libc::c_char,
                279 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 38],
                    &[libc::c_char; 38],
                >(b"void *OPENSSL_realloc(void *, size_t)\0"))
                    .as_ptr(),
            );
        }
        'c_2482: {
            if (Some(
                OPENSSL_memory_free as unsafe extern "C" fn(*mut libc::c_void) -> (),
            ))
                .is_some()
            {} else {
                __assert_fail(
                    b"OPENSSL_memory_free != NULL\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                        as *const libc::c_char,
                    279 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 38],
                        &[libc::c_char; 38],
                    >(b"void *OPENSSL_realloc(void *, size_t)\0"))
                        .as_ptr(),
                );
            }
        };
        if (Some(
            OPENSSL_memory_get_size as unsafe extern "C" fn(*mut libc::c_void) -> size_t,
        ))
            .is_some()
        {} else {
            __assert_fail(
                b"OPENSSL_memory_get_size != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                    as *const libc::c_char,
                280 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 38],
                    &[libc::c_char; 38],
                >(b"void *OPENSSL_realloc(void *, size_t)\0"))
                    .as_ptr(),
            );
        }
        'c_2439: {
            if (Some(
                OPENSSL_memory_get_size
                    as unsafe extern "C" fn(*mut libc::c_void) -> size_t,
            ))
                .is_some()
            {} else {
                __assert_fail(
                    b"OPENSSL_memory_get_size != NULL\0" as *const u8
                        as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                        as *const libc::c_char,
                    280 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 38],
                        &[libc::c_char; 38],
                    >(b"void *OPENSSL_realloc(void *, size_t)\0"))
                        .as_ptr(),
                );
            }
        };
        return OPENSSL_memory_realloc(orig_ptr, new_size);
    }
    let mut old_size: size_t = 0;
    if (Some(
        OPENSSL_memory_get_size as unsafe extern "C" fn(*mut libc::c_void) -> size_t,
    ))
        .is_some()
    {
        old_size = OPENSSL_memory_get_size(orig_ptr);
    } else {
        let mut ptr: *mut libc::c_void = (orig_ptr as *mut uint8_t)
            .offset(-(8 as libc::c_int as isize)) as *mut libc::c_void;
        __asan_unpoison_memory_region(ptr, 8 as libc::c_int as size_t);
        old_size = *(ptr as *mut size_t);
        __asan_poison_memory_region(ptr, 8 as libc::c_int as size_t);
    }
    let mut ret: *mut libc::c_void = OPENSSL_malloc(new_size);
    if ret.is_null() {
        return 0 as *mut libc::c_void;
    }
    let mut to_copy: size_t = new_size;
    if old_size < to_copy {
        to_copy = old_size;
    }
    memcpy(ret, orig_ptr, to_copy);
    OPENSSL_free(orig_ptr);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_cleanse(mut ptr: *mut libc::c_void, mut len: size_t) {
    if ptr.is_null() || len == 0 as libc::c_int as size_t {
        return;
    }
    OPENSSL_memset(ptr, 0 as libc::c_int, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_clear_free(
    mut ptr: *mut libc::c_void,
    mut unused: size_t,
) {
    OPENSSL_free(ptr);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_secure_malloc_init(
    mut size: size_t,
    mut min_size: size_t,
) -> libc::c_int {
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_secure_malloc_initialized() -> libc::c_int {
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_secure_used() -> size_t {
    return 0 as libc::c_int as size_t;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_secure_malloc(mut size: size_t) -> *mut libc::c_void {
    return OPENSSL_malloc(size);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_secure_zalloc(mut size: size_t) -> *mut libc::c_void {
    return OPENSSL_zalloc(size);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_secure_clear_free(
    mut ptr: *mut libc::c_void,
    mut len: size_t,
) {
    OPENSSL_clear_free(ptr, len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_memcmp(
    mut in_a: *const libc::c_void,
    mut in_b: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    let mut a: *const uint8_t = in_a as *const uint8_t;
    let mut b: *const uint8_t = in_b as *const uint8_t;
    let mut x: uint8_t = 0 as libc::c_int as uint8_t;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < len {
        x = (x as libc::c_int
            | *a.offset(i as isize) as libc::c_int
                ^ *b.offset(i as isize) as libc::c_int) as uint8_t;
        i = i.wrapping_add(1);
    }
    return x as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_hash32(
    mut ptr: *const libc::c_void,
    mut len: size_t,
) -> uint32_t {
    static mut kPrime: uint32_t = 16777619 as libc::c_uint;
    static mut kOffsetBasis: uint32_t = 2166136261 as libc::c_uint;
    let mut in_0: *const uint8_t = ptr as *const uint8_t;
    let mut h: uint32_t = kOffsetBasis;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < len {
        h ^= *in_0.offset(i as isize) as uint32_t;
        h = h * kPrime;
        i = i.wrapping_add(1);
    }
    return h;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_strhash(mut s: *const libc::c_char) -> uint32_t {
    return OPENSSL_hash32(s as *const libc::c_void, strlen(s));
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_strnlen(
    mut s: *const libc::c_char,
    mut len: size_t,
) -> size_t {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < len {
        if *s.offset(i as isize) as libc::c_int == 0 as libc::c_int {
            return i;
        }
        i = i.wrapping_add(1);
    }
    return len;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_strdup(
    mut s: *const libc::c_char,
) -> *mut libc::c_char {
    if s.is_null() {
        return 0 as *mut libc::c_char;
    }
    return OPENSSL_memdup(
        s as *const libc::c_void,
        (strlen(s)).wrapping_add(1 as libc::c_int as libc::c_ulong),
    ) as *mut libc::c_char;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_isalpha(mut c: libc::c_int) -> libc::c_int {
    return (c >= 'a' as i32 && c <= 'z' as i32 || c >= 'A' as i32 && c <= 'Z' as i32)
        as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_isdigit(mut c: libc::c_int) -> libc::c_int {
    return (c >= '0' as i32 && c <= '9' as i32) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_isxdigit(mut c: libc::c_int) -> libc::c_int {
    return (OPENSSL_isdigit(c) != 0 || c >= 'a' as i32 && c <= 'f' as i32
        || c >= 'A' as i32 && c <= 'F' as i32) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_fromxdigit(
    mut out: *mut uint8_t,
    mut c: libc::c_int,
) -> libc::c_int {
    if OPENSSL_isdigit(c) != 0 {
        *out = (c - '0' as i32) as uint8_t;
        return 1 as libc::c_int;
    }
    if 'a' as i32 <= c && c <= 'f' as i32 {
        *out = (c - 'a' as i32 + 10 as libc::c_int) as uint8_t;
        return 1 as libc::c_int;
    }
    if 'A' as i32 <= c && c <= 'F' as i32 {
        *out = (c - 'A' as i32 + 10 as libc::c_int) as uint8_t;
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_hexstr2buf(
    mut str: *const libc::c_char,
    mut len: *mut size_t,
) -> *mut uint8_t {
    if str.is_null() || len.is_null() {
        return 0 as *mut uint8_t;
    }
    let slen: size_t = OPENSSL_strnlen(str, 32767 as libc::c_int as size_t);
    if slen % 2 as libc::c_int as size_t != 0 as libc::c_int as size_t {
        return 0 as *mut uint8_t;
    }
    let buflen: size_t = slen / 2 as libc::c_int as size_t;
    let mut buf: *mut uint8_t = OPENSSL_zalloc(buflen) as *mut uint8_t;
    if buf.is_null() {
        return 0 as *mut uint8_t;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < buflen {
        let mut hi: uint8_t = 0;
        let mut lo: uint8_t = 0;
        if OPENSSL_fromxdigit(
            &mut hi,
            *str.offset((2 as libc::c_int as size_t * i) as isize) as libc::c_int,
        ) == 0
            || OPENSSL_fromxdigit(
                &mut lo,
                *str
                    .offset(
                        (2 as libc::c_int as size_t * i)
                            .wrapping_add(1 as libc::c_int as size_t) as isize,
                    ) as libc::c_int,
            ) == 0
        {
            OPENSSL_free(buf as *mut libc::c_void);
            return 0 as *mut uint8_t;
        }
        *buf
            .offset(
                i as isize,
            ) = ((hi as libc::c_int) << 4 as libc::c_int | lo as libc::c_int) as uint8_t;
        i = i.wrapping_add(1);
    }
    *len = buflen;
    return buf;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_isalnum(mut c: libc::c_int) -> libc::c_int {
    return (OPENSSL_isalpha(c) != 0 || OPENSSL_isdigit(c) != 0) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_tolower(mut c: libc::c_int) -> libc::c_int {
    if c >= 'A' as i32 && c <= 'Z' as i32 {
        return c + ('a' as i32 - 'A' as i32);
    }
    return c;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_isspace(mut c: libc::c_int) -> libc::c_int {
    return (c == '\t' as i32 || c == '\n' as i32 || c == '\u{b}' as i32
        || c == '\u{c}' as i32 || c == '\r' as i32 || c == ' ' as i32) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_strcasecmp(
    mut a: *const libc::c_char,
    mut b: *const libc::c_char,
) -> libc::c_int {
    let mut i: size_t = 0 as libc::c_int as size_t;
    loop {
        let aa: libc::c_int = OPENSSL_tolower(*a.offset(i as isize) as libc::c_int);
        let bb: libc::c_int = OPENSSL_tolower(*b.offset(i as isize) as libc::c_int);
        if aa < bb {
            return -(1 as libc::c_int)
        } else if aa > bb {
            return 1 as libc::c_int
        } else if aa == 0 as libc::c_int {
            return 0 as libc::c_int
        }
        i = i.wrapping_add(1);
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_strncasecmp(
    mut a: *const libc::c_char,
    mut b: *const libc::c_char,
    mut n: size_t,
) -> libc::c_int {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < n {
        let aa: libc::c_int = OPENSSL_tolower(*a.offset(i as isize) as libc::c_int);
        let bb: libc::c_int = OPENSSL_tolower(*b.offset(i as isize) as libc::c_int);
        if aa < bb {
            return -(1 as libc::c_int)
        } else if aa > bb {
            return 1 as libc::c_int
        } else if aa == 0 as libc::c_int {
            return 0 as libc::c_int
        }
        i = i.wrapping_add(1);
    }
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_snprintf(
    mut buf: *mut libc::c_char,
    mut n: size_t,
    mut format: *const libc::c_char,
    mut args: ...
) -> libc::c_int {
    let mut args_0: ::core::ffi::VaListImpl;
    args_0 = args.clone();
    let mut ret: libc::c_int = BIO_vsnprintf(buf, n, format, args_0.as_va_list());
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_vsnprintf(
    mut buf: *mut libc::c_char,
    mut n: size_t,
    mut format: *const libc::c_char,
    mut args: ::core::ffi::VaList,
) -> libc::c_int {
    return vsnprintf(buf, n, format, args.as_va_list());
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_vasprintf_internal(
    mut str: *mut *mut libc::c_char,
    mut format: *const libc::c_char,
    mut args: ::core::ffi::VaList,
    mut system_malloc: libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    let mut current_block: u64;
    let mut allocate: Option::<unsafe extern "C" fn(size_t) -> *mut libc::c_void> = if system_malloc
        != 0
    {
        Some(malloc as unsafe extern "C" fn(libc::c_ulong) -> *mut libc::c_void)
    } else {
        Some(OPENSSL_malloc as unsafe extern "C" fn(size_t) -> *mut libc::c_void)
    };
    let mut deallocate: Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()> = if system_malloc
        != 0
    {
        Some(free as unsafe extern "C" fn(*mut libc::c_void) -> ())
    } else {
        Some(OPENSSL_free as unsafe extern "C" fn(*mut libc::c_void) -> ())
    };
    let mut reallocate: Option::<
        unsafe extern "C" fn(*mut libc::c_void, size_t) -> *mut libc::c_void,
    > = if system_malloc != 0 {
        Some(
            realloc
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    libc::c_ulong,
                ) -> *mut libc::c_void,
        )
    } else {
        Some(
            OPENSSL_realloc
                as unsafe extern "C" fn(*mut libc::c_void, size_t) -> *mut libc::c_void,
        )
    };
    let mut candidate: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut candidate_len: size_t = 64 as libc::c_int as size_t;
    candidate = allocate.expect("non-null function pointer")(candidate_len)
        as *mut libc::c_char;
    if !candidate.is_null() {
        let mut args_copy = args.clone();
        ret = vsnprintf(candidate, candidate_len, format, args_copy.as_va_list());
        if !(ret < 0 as libc::c_int) {
            if ret as size_t >= candidate_len {
                let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
                candidate_len = (ret as size_t).wrapping_add(1 as libc::c_int as size_t);
                tmp = reallocate
                    .expect(
                        "non-null function pointer",
                    )(candidate as *mut libc::c_void, candidate_len)
                    as *mut libc::c_char;
                if tmp.is_null() {
                    current_block = 5958868064230649183;
                } else {
                    candidate = tmp;
                    ret = vsnprintf(candidate, candidate_len, format, args.as_va_list());
                    current_block = 2968425633554183086;
                }
            } else {
                current_block = 2968425633554183086;
            }
            match current_block {
                5958868064230649183 => {}
                _ => {
                    if !(ret < 0 as libc::c_int || ret as size_t >= candidate_len) {
                        *str = candidate;
                        return ret;
                    }
                }
            }
        }
    }
    deallocate.expect("non-null function pointer")(candidate as *mut libc::c_void);
    *str = 0 as *mut libc::c_char;
    *__errno_location() = 12 as libc::c_int;
    return -(1 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_vasprintf(
    mut str: *mut *mut libc::c_char,
    mut format: *const libc::c_char,
    mut args: ::core::ffi::VaList,
) -> libc::c_int {
    return OPENSSL_vasprintf_internal(str, format, args.as_va_list(), 0 as libc::c_int);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_asprintf(
    mut str: *mut *mut libc::c_char,
    mut format: *const libc::c_char,
    mut args: ...
) -> libc::c_int {
    let mut args_0: ::core::ffi::VaListImpl;
    args_0 = args.clone();
    let mut ret: libc::c_int = OPENSSL_vasprintf(str, format, args_0.as_va_list());
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_strndup(
    mut str: *const libc::c_char,
    mut size: size_t,
) -> *mut libc::c_char {
    size = OPENSSL_strnlen(str, size);
    let mut alloc_size: size_t = size.wrapping_add(1 as libc::c_int as size_t);
    if alloc_size < size {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            1 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/mem.c\0" as *const u8
                as *const libc::c_char,
            569 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut libc::c_char;
    }
    let mut ret: *mut libc::c_char = OPENSSL_malloc(alloc_size) as *mut libc::c_char;
    if ret.is_null() {
        return 0 as *mut libc::c_char;
    }
    OPENSSL_memcpy(ret as *mut libc::c_void, str as *const libc::c_void, size);
    *ret.offset(size as isize) = '\0' as i32 as libc::c_char;
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_strlcpy(
    mut dst: *mut libc::c_char,
    mut src: *const libc::c_char,
    mut dst_size: size_t,
) -> size_t {
    let mut l: size_t = 0 as libc::c_int as size_t;
    while dst_size > 1 as libc::c_int as size_t && *src as libc::c_int != 0 {
        let fresh0 = src;
        src = src.offset(1);
        let fresh1 = dst;
        dst = dst.offset(1);
        *fresh1 = *fresh0;
        l = l.wrapping_add(1);
        dst_size = dst_size.wrapping_sub(1);
    }
    if dst_size != 0 {
        *dst = 0 as libc::c_int as libc::c_char;
    }
    return l.wrapping_add(strlen(src));
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_strlcat(
    mut dst: *mut libc::c_char,
    mut src: *const libc::c_char,
    mut dst_size: size_t,
) -> size_t {
    let mut l: size_t = 0 as libc::c_int as size_t;
    while dst_size > 0 as libc::c_int as size_t && *dst as libc::c_int != 0 {
        l = l.wrapping_add(1);
        l;
        dst_size = dst_size.wrapping_sub(1);
        dst = dst.offset(1);
    }
    return l.wrapping_add(OPENSSL_strlcpy(dst, src, dst_size));
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_memdup(
    mut data: *const libc::c_void,
    mut size: size_t,
) -> *mut libc::c_void {
    if size == 0 as libc::c_int as size_t {
        return 0 as *mut libc::c_void;
    }
    let mut ret: *mut libc::c_void = OPENSSL_malloc(size);
    if ret.is_null() {
        return 0 as *mut libc::c_void;
    }
    OPENSSL_memcpy(ret, data, size);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_malloc(
    mut size: size_t,
    mut file: *const libc::c_char,
    mut line: libc::c_int,
) -> *mut libc::c_void {
    return OPENSSL_malloc(size);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_realloc(
    mut ptr: *mut libc::c_void,
    mut new_size: size_t,
    mut file: *const libc::c_char,
    mut line: libc::c_int,
) -> *mut libc::c_void {
    return OPENSSL_realloc(ptr, new_size);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_free(
    mut ptr: *mut libc::c_void,
    mut file: *const libc::c_char,
    mut line: libc::c_int,
) {
    OPENSSL_free(ptr);
}
