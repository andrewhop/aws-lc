#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(label_break_value)]
unsafe extern "C" {
    fn qsort(
        __base: *mut libc::c_void,
        __nmemb: size_t,
        __size: size_t,
        __compar: __compar_fn_t,
    );
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_calloc(num: size_t, size: size_t) -> *mut libc::c_void;
    fn OPENSSL_realloc(ptr: *mut libc::c_void, new_size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_memdup(data: *const libc::c_void, size: size_t) -> *mut libc::c_void;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn memmove(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
}
pub type size_t = libc::c_ulong;
pub type __compar_fn_t = Option::<
    unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> libc::c_int,
>;
pub type OPENSSL_sk_free_func = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type OPENSSL_sk_copy_func = Option::<
    unsafe extern "C" fn(*const libc::c_void) -> *mut libc::c_void,
>;
pub type OPENSSL_sk_cmp_func = Option::<
    unsafe extern "C" fn(
        *const *const libc::c_void,
        *const *const libc::c_void,
    ) -> libc::c_int,
>;
pub type OPENSSL_sk_delete_if_func = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void) -> libc::c_int,
>;
pub type OPENSSL_sk_call_free_func = Option::<
    unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
>;
pub type OPENSSL_sk_call_copy_func = Option::<
    unsafe extern "C" fn(OPENSSL_sk_copy_func, *const libc::c_void) -> *mut libc::c_void,
>;
pub type OPENSSL_sk_call_cmp_func = Option::<
    unsafe extern "C" fn(
        OPENSSL_sk_cmp_func,
        *const libc::c_void,
        *const libc::c_void,
    ) -> libc::c_int,
>;
pub type OPENSSL_sk_call_delete_if_func = Option::<
    unsafe extern "C" fn(
        OPENSSL_sk_delete_if_func,
        *mut libc::c_void,
        *mut libc::c_void,
    ) -> libc::c_int,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct stack_st {
    pub num: size_t,
    pub data: *mut *mut libc::c_void,
    pub sorted: libc::c_int,
    pub num_alloc: size_t,
    pub comp: OPENSSL_sk_cmp_func,
}
pub type OPENSSL_STACK = stack_st;
#[inline]
unsafe extern "C" fn OPENSSL_memmove(
    mut dst: *mut libc::c_void,
    mut src: *const libc::c_void,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return dst;
    }
    return memmove(dst, src, n);
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
static mut kMinSize: size_t = 4 as libc::c_int as size_t;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_sk_new(
    mut comp: OPENSSL_sk_cmp_func,
) -> *mut OPENSSL_STACK {
    let mut ret: *mut OPENSSL_STACK = OPENSSL_zalloc(
        ::core::mem::size_of::<OPENSSL_STACK>() as libc::c_ulong,
    ) as *mut OPENSSL_STACK;
    if ret.is_null() {
        return 0 as *mut OPENSSL_STACK;
    }
    (*ret)
        .data = OPENSSL_calloc(
        kMinSize,
        ::core::mem::size_of::<*mut libc::c_void>() as libc::c_ulong,
    ) as *mut *mut libc::c_void;
    if ((*ret).data).is_null() {
        OPENSSL_free(ret as *mut libc::c_void);
        return 0 as *mut OPENSSL_STACK;
    } else {
        (*ret).comp = comp;
        (*ret).num_alloc = kMinSize;
        return ret;
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK {
    return OPENSSL_sk_new(None);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_sk_num(mut sk: *const OPENSSL_STACK) -> size_t {
    if sk.is_null() {
        return 0 as libc::c_int as size_t;
    }
    return (*sk).num;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_sk_zero(mut sk: *mut OPENSSL_STACK) {
    if sk.is_null() || (*sk).num == 0 as libc::c_int as size_t {
        return;
    }
    OPENSSL_memset(
        (*sk).data as *mut libc::c_void,
        0 as libc::c_int,
        (::core::mem::size_of::<*mut libc::c_void>() as libc::c_ulong)
            .wrapping_mul((*sk).num),
    );
    (*sk).num = 0 as libc::c_int as size_t;
    (*sk).sorted = 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_sk_value(
    mut sk: *const OPENSSL_STACK,
    mut i: size_t,
) -> *mut libc::c_void {
    if sk.is_null() || i >= (*sk).num {
        return 0 as *mut libc::c_void;
    }
    return *((*sk).data).offset(i as isize);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_sk_set(
    mut sk: *mut OPENSSL_STACK,
    mut i: size_t,
    mut value: *mut libc::c_void,
) -> *mut libc::c_void {
    if sk.is_null() || i >= (*sk).num {
        return 0 as *mut libc::c_void;
    }
    let ref mut fresh0 = *((*sk).data).offset(i as isize);
    *fresh0 = value;
    return *fresh0;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_sk_free(mut sk: *mut OPENSSL_STACK) {
    if sk.is_null() {
        return;
    }
    OPENSSL_free((*sk).data as *mut libc::c_void);
    OPENSSL_free(sk as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_sk_pop_free_ex(
    mut sk: *mut OPENSSL_STACK,
    mut call_free_func: OPENSSL_sk_call_free_func,
    mut free_func: OPENSSL_sk_free_func,
) {
    if sk.is_null() {
        return;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < (*sk).num {
        if !(*((*sk).data).offset(i as isize)).is_null() {
            call_free_func
                .expect(
                    "non-null function pointer",
                )(free_func, *((*sk).data).offset(i as isize));
        }
        i = i.wrapping_add(1);
        i;
    }
    OPENSSL_sk_free(sk);
}
unsafe extern "C" fn call_free_func_legacy(
    mut func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    func.expect("non-null function pointer")(ptr);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sk_pop_free(
    mut sk: *mut OPENSSL_STACK,
    mut free_func: OPENSSL_sk_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk,
        Some(
            call_free_func_legacy
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        free_func,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_sk_insert(
    mut sk: *mut OPENSSL_STACK,
    mut p: *mut libc::c_void,
    mut where_0: size_t,
) -> size_t {
    if sk.is_null() {
        return 0 as libc::c_int as size_t;
    }
    if (*sk).num >= 2147483647 as libc::c_int as size_t {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/stack/stack.c\0" as *const u8
                as *const libc::c_char,
            179 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int as size_t;
    }
    if (*sk).num_alloc <= ((*sk).num).wrapping_add(1 as libc::c_int as size_t) {
        let mut new_alloc: size_t = (*sk).num_alloc << 1 as libc::c_int;
        let mut alloc_size: size_t = new_alloc
            .wrapping_mul(::core::mem::size_of::<*mut libc::c_void>() as libc::c_ulong);
        let mut data: *mut *mut libc::c_void = 0 as *mut *mut libc::c_void;
        if new_alloc < (*sk).num_alloc
            || alloc_size
                .wrapping_div(
                    ::core::mem::size_of::<*mut libc::c_void>() as libc::c_ulong,
                ) != new_alloc
        {
            new_alloc = ((*sk).num_alloc).wrapping_add(1 as libc::c_int as size_t);
            alloc_size = new_alloc
                .wrapping_mul(
                    ::core::mem::size_of::<*mut libc::c_void>() as libc::c_ulong,
                );
        }
        if new_alloc < (*sk).num_alloc
            || alloc_size
                .wrapping_div(
                    ::core::mem::size_of::<*mut libc::c_void>() as libc::c_ulong,
                ) != new_alloc
        {
            return 0 as libc::c_int as size_t;
        }
        data = OPENSSL_realloc((*sk).data as *mut libc::c_void, alloc_size)
            as *mut *mut libc::c_void;
        if data.is_null() {
            return 0 as libc::c_int as size_t;
        }
        (*sk).data = data;
        (*sk).num_alloc = new_alloc;
    }
    if where_0 >= (*sk).num {
        let ref mut fresh1 = *((*sk).data).offset((*sk).num as isize);
        *fresh1 = p;
    } else {
        OPENSSL_memmove(
            &mut *((*sk).data)
                .offset(where_0.wrapping_add(1 as libc::c_int as size_t) as isize)
                as *mut *mut libc::c_void as *mut libc::c_void,
            &mut *((*sk).data).offset(where_0 as isize) as *mut *mut libc::c_void
                as *const libc::c_void,
            (::core::mem::size_of::<*mut libc::c_void>() as libc::c_ulong)
                .wrapping_mul(((*sk).num).wrapping_sub(where_0)),
        );
        let ref mut fresh2 = *((*sk).data).offset(where_0 as isize);
        *fresh2 = p;
    }
    (*sk).num = ((*sk).num).wrapping_add(1);
    (*sk).num;
    (*sk).sorted = 0 as libc::c_int;
    return (*sk).num;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_sk_delete(
    mut sk: *mut OPENSSL_STACK,
    mut where_0: size_t,
) -> *mut libc::c_void {
    let mut ret: *mut libc::c_void = 0 as *mut libc::c_void;
    if sk.is_null() || where_0 >= (*sk).num {
        return 0 as *mut libc::c_void;
    }
    ret = *((*sk).data).offset(where_0 as isize);
    if where_0 != ((*sk).num).wrapping_sub(1 as libc::c_int as size_t) {
        OPENSSL_memmove(
            &mut *((*sk).data).offset(where_0 as isize) as *mut *mut libc::c_void
                as *mut libc::c_void,
            &mut *((*sk).data)
                .offset(where_0.wrapping_add(1 as libc::c_int as size_t) as isize)
                as *mut *mut libc::c_void as *const libc::c_void,
            (::core::mem::size_of::<*mut libc::c_void>() as libc::c_ulong)
                .wrapping_mul(
                    ((*sk).num)
                        .wrapping_sub(where_0)
                        .wrapping_sub(1 as libc::c_int as size_t),
                ),
        );
    }
    (*sk).num = ((*sk).num).wrapping_sub(1);
    (*sk).num;
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_sk_delete_ptr(
    mut sk: *mut OPENSSL_STACK,
    mut p: *const libc::c_void,
) -> *mut libc::c_void {
    if sk.is_null() {
        return 0 as *mut libc::c_void;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < (*sk).num {
        if *((*sk).data).offset(i as isize) == p as *mut libc::c_void {
            return OPENSSL_sk_delete(sk, i);
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as *mut libc::c_void;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_sk_delete_if(
    mut sk: *mut OPENSSL_STACK,
    mut call_func: OPENSSL_sk_call_delete_if_func,
    mut func: OPENSSL_sk_delete_if_func,
    mut data: *mut libc::c_void,
) {
    if sk.is_null() {
        return;
    }
    let mut new_num: size_t = 0 as libc::c_int as size_t;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < (*sk).num {
        if call_func
            .expect(
                "non-null function pointer",
            )(func, *((*sk).data).offset(i as isize), data) == 0
        {
            let ref mut fresh3 = *((*sk).data).offset(new_num as isize);
            *fresh3 = *((*sk).data).offset(i as isize);
            new_num = new_num.wrapping_add(1);
            new_num;
        }
        i = i.wrapping_add(1);
        i;
    }
    (*sk).num = new_num;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_sk_find(
    mut sk: *const OPENSSL_STACK,
    mut out_index: *mut size_t,
    mut p: *const libc::c_void,
    mut call_cmp_func: OPENSSL_sk_call_cmp_func,
) -> libc::c_int {
    if sk.is_null() {
        return 0 as libc::c_int;
    }
    if ((*sk).comp).is_none() {
        let mut i: size_t = 0 as libc::c_int as size_t;
        while i < (*sk).num {
            if *((*sk).data).offset(i as isize) == p as *mut libc::c_void {
                if !out_index.is_null() {
                    *out_index = i;
                }
                return 1 as libc::c_int;
            }
            i = i.wrapping_add(1);
            i;
        }
        return 0 as libc::c_int;
    }
    if p.is_null() {
        return 0 as libc::c_int;
    }
    if OPENSSL_sk_is_sorted(sk) == 0 {
        let mut i_0: size_t = 0 as libc::c_int as size_t;
        while i_0 < (*sk).num {
            if call_cmp_func
                .expect(
                    "non-null function pointer",
                )((*sk).comp, p, *((*sk).data).offset(i_0 as isize)) == 0 as libc::c_int
            {
                if !out_index.is_null() {
                    *out_index = i_0;
                }
                return 1 as libc::c_int;
            }
            i_0 = i_0.wrapping_add(1);
            i_0;
        }
        return 0 as libc::c_int;
    }
    let mut lo: size_t = 0 as libc::c_int as size_t;
    let mut hi: size_t = (*sk).num;
    while lo < hi {
        let mut mid: size_t = lo
            .wrapping_add(
                hi.wrapping_sub(lo).wrapping_sub(1 as libc::c_int as size_t)
                    / 2 as libc::c_int as size_t,
            );
        if lo <= mid && mid < hi {} else {
            __assert_fail(
                b"lo <= mid && mid < hi\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/stack/stack.c\0" as *const u8
                    as *const libc::c_char,
                315 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 93],
                    &[libc::c_char; 93],
                >(
                    b"int OPENSSL_sk_find(const OPENSSL_STACK *, size_t *, const void *, OPENSSL_sk_call_cmp_func)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_2419: {
            if lo <= mid && mid < hi {} else {
                __assert_fail(
                    b"lo <= mid && mid < hi\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/stack/stack.c\0"
                        as *const u8 as *const libc::c_char,
                    315 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 93],
                        &[libc::c_char; 93],
                    >(
                        b"int OPENSSL_sk_find(const OPENSSL_STACK *, size_t *, const void *, OPENSSL_sk_call_cmp_func)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        let mut r: libc::c_int = call_cmp_func
            .expect(
                "non-null function pointer",
            )((*sk).comp, p, *((*sk).data).offset(mid as isize));
        if r > 0 as libc::c_int {
            lo = mid.wrapping_add(1 as libc::c_int as size_t);
        } else if r < 0 as libc::c_int {
            hi = mid;
        } else {
            if hi.wrapping_sub(lo) == 1 as libc::c_int as size_t {
                if !out_index.is_null() {
                    *out_index = mid;
                }
                return 1 as libc::c_int;
            }
            if mid.wrapping_add(1 as libc::c_int as size_t) < hi {} else {
                __assert_fail(
                    b"mid + 1 < hi\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/stack/stack.c\0"
                        as *const u8 as *const libc::c_char,
                    332 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 93],
                        &[libc::c_char; 93],
                    >(
                        b"int OPENSSL_sk_find(const OPENSSL_STACK *, size_t *, const void *, OPENSSL_sk_call_cmp_func)\0",
                    ))
                        .as_ptr(),
                );
            }
            'c_2309: {
                if mid.wrapping_add(1 as libc::c_int as size_t) < hi {} else {
                    __assert_fail(
                        b"mid + 1 < hi\0" as *const u8 as *const libc::c_char,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/stack/stack.c\0"
                            as *const u8 as *const libc::c_char,
                        332 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<
                            &[u8; 93],
                            &[libc::c_char; 93],
                        >(
                            b"int OPENSSL_sk_find(const OPENSSL_STACK *, size_t *, const void *, OPENSSL_sk_call_cmp_func)\0",
                        ))
                            .as_ptr(),
                    );
                }
            };
            hi = mid.wrapping_add(1 as libc::c_int as size_t);
        }
    }
    if lo == hi {} else {
        __assert_fail(
            b"lo == hi\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/stack/stack.c\0" as *const u8
                as *const libc::c_char,
            337 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 93],
                &[libc::c_char; 93],
            >(
                b"int OPENSSL_sk_find(const OPENSSL_STACK *, size_t *, const void *, OPENSSL_sk_call_cmp_func)\0",
            ))
                .as_ptr(),
        );
    }
    'c_2215: {
        if lo == hi {} else {
            __assert_fail(
                b"lo == hi\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/stack/stack.c\0" as *const u8
                    as *const libc::c_char,
                337 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 93],
                    &[libc::c_char; 93],
                >(
                    b"int OPENSSL_sk_find(const OPENSSL_STACK *, size_t *, const void *, OPENSSL_sk_call_cmp_func)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_sk_unshift(
    mut sk: *mut OPENSSL_STACK,
    mut data: *mut libc::c_void,
) -> libc::c_int {
    return OPENSSL_sk_insert(sk, data, 0 as libc::c_int as size_t) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_sk_shift(
    mut sk: *mut OPENSSL_STACK,
) -> *mut libc::c_void {
    if sk.is_null() {
        return 0 as *mut libc::c_void;
    }
    if (*sk).num == 0 as libc::c_int as size_t {
        return 0 as *mut libc::c_void;
    }
    return OPENSSL_sk_delete(sk, 0 as libc::c_int as size_t);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_sk_push(
    mut sk: *mut OPENSSL_STACK,
    mut p: *mut libc::c_void,
) -> size_t {
    return OPENSSL_sk_insert(sk, p, (*sk).num);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_sk_pop(
    mut sk: *mut OPENSSL_STACK,
) -> *mut libc::c_void {
    if sk.is_null() {
        return 0 as *mut libc::c_void;
    }
    if (*sk).num == 0 as libc::c_int as size_t {
        return 0 as *mut libc::c_void;
    }
    return OPENSSL_sk_delete(sk, ((*sk).num).wrapping_sub(1 as libc::c_int as size_t));
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_sk_dup(
    mut sk: *const OPENSSL_STACK,
) -> *mut OPENSSL_STACK {
    if sk.is_null() {
        return 0 as *mut OPENSSL_STACK;
    }
    let mut ret: *mut OPENSSL_STACK = OPENSSL_zalloc(
        ::core::mem::size_of::<OPENSSL_STACK>() as libc::c_ulong,
    ) as *mut OPENSSL_STACK;
    if ret.is_null() {
        return 0 as *mut OPENSSL_STACK;
    }
    (*ret)
        .data = OPENSSL_memdup(
        (*sk).data as *const libc::c_void,
        (::core::mem::size_of::<*mut libc::c_void>() as libc::c_ulong)
            .wrapping_mul((*sk).num_alloc),
    ) as *mut *mut libc::c_void;
    if ((*ret).data).is_null() {
        OPENSSL_sk_free(ret);
        return 0 as *mut OPENSSL_STACK;
    } else {
        (*ret).num = (*sk).num;
        (*ret).sorted = (*sk).sorted;
        (*ret).num_alloc = (*sk).num_alloc;
        (*ret).comp = (*sk).comp;
        return ret;
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_sk_sort(
    mut sk: *mut OPENSSL_STACK,
    mut call_cmp_func: OPENSSL_sk_call_cmp_func,
) {
    if sk.is_null() || ((*sk).comp).is_none() || (*sk).sorted != 0 {
        return;
    }
    if (*sk).num >= 2 as libc::c_int as size_t {
        let mut comp_func: Option::<
            unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> libc::c_int,
        > = ::core::mem::transmute::<
            OPENSSL_sk_cmp_func,
            Option::<
                unsafe extern "C" fn(
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
            >,
        >((*sk).comp);
        qsort(
            (*sk).data as *mut libc::c_void,
            (*sk).num,
            ::core::mem::size_of::<*mut libc::c_void>() as libc::c_ulong,
            comp_func,
        );
    }
    (*sk).sorted = 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_sk_is_sorted(
    mut sk: *const OPENSSL_STACK,
) -> libc::c_int {
    if sk.is_null() {
        return 1 as libc::c_int;
    }
    return ((*sk).sorted != 0
        || ((*sk).comp).is_some() && (*sk).num < 2 as libc::c_int as size_t)
        as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_sk_set_cmp_func(
    mut sk: *mut OPENSSL_STACK,
    mut comp: OPENSSL_sk_cmp_func,
) -> OPENSSL_sk_cmp_func {
    let mut old: OPENSSL_sk_cmp_func = (*sk).comp;
    if (*sk).comp != comp {
        (*sk).sorted = 0 as libc::c_int;
    }
    (*sk).comp = comp;
    return old;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_sk_deep_copy(
    mut sk: *const OPENSSL_STACK,
    mut call_copy_func: OPENSSL_sk_call_copy_func,
    mut copy_func: OPENSSL_sk_copy_func,
    mut call_free_func: OPENSSL_sk_call_free_func,
    mut free_func: OPENSSL_sk_free_func,
) -> *mut OPENSSL_STACK {
    let mut ret: *mut OPENSSL_STACK = OPENSSL_sk_dup(sk);
    if ret.is_null() {
        return 0 as *mut OPENSSL_STACK;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < (*ret).num {
        if !(*((*ret).data).offset(i as isize)).is_null() {
            let ref mut fresh4 = *((*ret).data).offset(i as isize);
            *fresh4 = call_copy_func
                .expect(
                    "non-null function pointer",
                )(copy_func, *((*ret).data).offset(i as isize));
            if (*((*ret).data).offset(i as isize)).is_null() {
                let mut j: size_t = 0 as libc::c_int as size_t;
                while j < i {
                    if !(*((*ret).data).offset(j as isize)).is_null() {
                        call_free_func
                            .expect(
                                "non-null function pointer",
                            )(free_func, *((*ret).data).offset(j as isize));
                    }
                    j = j.wrapping_add(1);
                    j;
                }
                OPENSSL_sk_free(ret);
                return 0 as *mut OPENSSL_STACK;
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    return ret;
}
