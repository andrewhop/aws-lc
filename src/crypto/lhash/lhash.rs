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
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_calloc(num: size_t, size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
}
pub type size_t = libc::c_ulong;
pub type __uint32_t = libc::c_uint;
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct lhash_st {
    pub num_items: size_t,
    pub buckets: *mut *mut LHASH_ITEM,
    pub num_buckets: size_t,
    pub callback_depth: libc::c_uint,
    pub comp: lhash_cmp_func,
    pub hash: lhash_hash_func,
}
pub type lhash_hash_func = Option::<
    unsafe extern "C" fn(*const libc::c_void) -> uint32_t,
>;
pub type lhash_cmp_func = Option::<
    unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> libc::c_int,
>;
pub type LHASH_ITEM = lhash_item_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct lhash_item_st {
    pub data: *mut libc::c_void,
    pub next: *mut lhash_item_st,
    pub hash: uint32_t,
}
pub type _LHASH = lhash_st;
pub type lhash_cmp_func_helper = Option::<
    unsafe extern "C" fn(
        lhash_cmp_func,
        *const libc::c_void,
        *const libc::c_void,
    ) -> libc::c_int,
>;
pub type lhash_hash_func_helper = Option::<
    unsafe extern "C" fn(lhash_hash_func, *const libc::c_void) -> uint32_t,
>;
static mut kMinNumBuckets: size_t = 16 as libc::c_int as size_t;
static mut kMaxAverageChainLength: size_t = 2 as libc::c_int as size_t;
static mut kMinAverageChainLength: size_t = 1 as libc::c_int as size_t;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_lh_new(
    mut hash: lhash_hash_func,
    mut comp: lhash_cmp_func,
) -> *mut _LHASH {
    let mut ret: *mut _LHASH = OPENSSL_zalloc(
        ::core::mem::size_of::<_LHASH>() as libc::c_ulong,
    ) as *mut _LHASH;
    if ret.is_null() {
        return 0 as *mut _LHASH;
    }
    (*ret).num_buckets = kMinNumBuckets;
    (*ret)
        .buckets = OPENSSL_calloc(
        (*ret).num_buckets,
        ::core::mem::size_of::<*mut LHASH_ITEM>() as libc::c_ulong,
    ) as *mut *mut LHASH_ITEM;
    if ((*ret).buckets).is_null() {
        OPENSSL_free(ret as *mut libc::c_void);
        return 0 as *mut _LHASH;
    }
    (*ret).comp = comp;
    (*ret).hash = hash;
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_lh_free(mut lh: *mut _LHASH) {
    if lh.is_null() {
        return;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < (*lh).num_buckets {
        let mut next: *mut LHASH_ITEM = 0 as *mut LHASH_ITEM;
        let mut n: *mut LHASH_ITEM = *((*lh).buckets).offset(i as isize);
        while !n.is_null() {
            next = (*n).next;
            OPENSSL_free(n as *mut libc::c_void);
            n = next;
        }
        i = i.wrapping_add(1);
        i;
    }
    OPENSSL_free((*lh).buckets as *mut libc::c_void);
    OPENSSL_free(lh as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_lh_num_items(mut lh: *const _LHASH) -> size_t {
    return (*lh).num_items;
}
unsafe extern "C" fn get_next_ptr_and_hash(
    mut lh: *const _LHASH,
    mut out_hash: *mut uint32_t,
    mut data: *const libc::c_void,
    mut call_hash_func: lhash_hash_func_helper,
    mut call_cmp_func: lhash_cmp_func_helper,
) -> *mut *mut LHASH_ITEM {
    let hash: uint32_t = call_hash_func
        .expect("non-null function pointer")((*lh).hash, data);
    if !out_hash.is_null() {
        *out_hash = hash;
    }
    let mut ret: *mut *mut LHASH_ITEM = &mut *((*lh).buckets)
        .offset((hash as size_t % (*lh).num_buckets) as isize) as *mut *mut LHASH_ITEM;
    let mut cur: *mut LHASH_ITEM = *ret;
    while !cur.is_null() {
        if call_cmp_func
            .expect("non-null function pointer")((*lh).comp, (*cur).data, data)
            == 0 as libc::c_int
        {
            break;
        }
        ret = &mut (*cur).next;
        cur = *ret;
    }
    return ret;
}
unsafe extern "C" fn get_next_ptr_by_key(
    mut lh: *const _LHASH,
    mut key: *const libc::c_void,
    mut key_hash: uint32_t,
    mut cmp_key: Option::<
        unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> libc::c_int,
    >,
) -> *mut *mut LHASH_ITEM {
    let mut ret: *mut *mut LHASH_ITEM = &mut *((*lh).buckets)
        .offset((key_hash as size_t % (*lh).num_buckets) as isize)
        as *mut *mut LHASH_ITEM;
    let mut cur: *mut LHASH_ITEM = *ret;
    while !cur.is_null() {
        if cmp_key.expect("non-null function pointer")(key, (*cur).data)
            == 0 as libc::c_int
        {
            break;
        }
        ret = &mut (*cur).next;
        cur = *ret;
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_lh_retrieve(
    mut lh: *const _LHASH,
    mut data: *const libc::c_void,
    mut call_hash_func: lhash_hash_func_helper,
    mut call_cmp_func: lhash_cmp_func_helper,
) -> *mut libc::c_void {
    let mut next_ptr: *mut *mut LHASH_ITEM = get_next_ptr_and_hash(
        lh,
        0 as *mut uint32_t,
        data,
        call_hash_func,
        call_cmp_func,
    );
    return if (*next_ptr).is_null() {
        0 as *mut libc::c_void
    } else {
        (**next_ptr).data
    };
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_lh_retrieve_key(
    mut lh: *const _LHASH,
    mut key: *const libc::c_void,
    mut key_hash: uint32_t,
    mut cmp_key: Option::<
        unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> libc::c_int,
    >,
) -> *mut libc::c_void {
    let mut next_ptr: *mut *mut LHASH_ITEM = get_next_ptr_by_key(
        lh,
        key,
        key_hash,
        cmp_key,
    );
    return if (*next_ptr).is_null() {
        0 as *mut libc::c_void
    } else {
        (**next_ptr).data
    };
}
unsafe extern "C" fn lh_rebucket(mut lh: *mut _LHASH, new_num_buckets: size_t) {
    let mut new_buckets: *mut *mut LHASH_ITEM = 0 as *mut *mut LHASH_ITEM;
    let mut cur: *mut LHASH_ITEM = 0 as *mut LHASH_ITEM;
    let mut next: *mut LHASH_ITEM = 0 as *mut LHASH_ITEM;
    let mut i: size_t = 0;
    let mut alloc_size: size_t = 0;
    alloc_size = (::core::mem::size_of::<*mut LHASH_ITEM>() as libc::c_ulong)
        .wrapping_mul(new_num_buckets);
    if alloc_size
        .wrapping_div(::core::mem::size_of::<*mut LHASH_ITEM>() as libc::c_ulong)
        != new_num_buckets
    {
        return;
    }
    new_buckets = OPENSSL_zalloc(alloc_size) as *mut *mut LHASH_ITEM;
    if new_buckets.is_null() {
        return;
    }
    i = 0 as libc::c_int as size_t;
    while i < (*lh).num_buckets {
        cur = *((*lh).buckets).offset(i as isize);
        while !cur.is_null() {
            let new_bucket: size_t = (*cur).hash as size_t % new_num_buckets;
            next = (*cur).next;
            (*cur).next = *new_buckets.offset(new_bucket as isize);
            let ref mut fresh0 = *new_buckets.offset(new_bucket as isize);
            *fresh0 = cur;
            cur = next;
        }
        i = i.wrapping_add(1);
        i;
    }
    OPENSSL_free((*lh).buckets as *mut libc::c_void);
    (*lh).num_buckets = new_num_buckets;
    (*lh).buckets = new_buckets;
}
unsafe extern "C" fn lh_maybe_resize(mut lh: *mut _LHASH) {
    let mut avg_chain_length: size_t = 0;
    if (*lh).callback_depth > 0 as libc::c_int as libc::c_uint {
        return;
    }
    if (*lh).num_buckets >= kMinNumBuckets {} else {
        __assert_fail(
            b"lh->num_buckets >= kMinNumBuckets\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/lhash/lhash.c\0" as *const u8
                as *const libc::c_char,
            244 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 31],
                &[libc::c_char; 31],
            >(b"void lh_maybe_resize(_LHASH *)\0"))
                .as_ptr(),
        );
    }
    'c_1564: {
        if (*lh).num_buckets >= kMinNumBuckets {} else {
            __assert_fail(
                b"lh->num_buckets >= kMinNumBuckets\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/lhash/lhash.c\0" as *const u8
                    as *const libc::c_char,
                244 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 31],
                    &[libc::c_char; 31],
                >(b"void lh_maybe_resize(_LHASH *)\0"))
                    .as_ptr(),
            );
        }
    };
    avg_chain_length = (*lh).num_items / (*lh).num_buckets;
    if avg_chain_length > kMaxAverageChainLength {
        let new_num_buckets: size_t = (*lh).num_buckets * 2 as libc::c_int as size_t;
        if new_num_buckets > (*lh).num_buckets {
            lh_rebucket(lh, new_num_buckets);
        }
    } else if avg_chain_length < kMinAverageChainLength
        && (*lh).num_buckets > kMinNumBuckets
    {
        let mut new_num_buckets_0: size_t = (*lh).num_buckets
            / 2 as libc::c_int as size_t;
        if new_num_buckets_0 < kMinNumBuckets {
            new_num_buckets_0 = kMinNumBuckets;
        }
        lh_rebucket(lh, new_num_buckets_0);
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_lh_insert(
    mut lh: *mut _LHASH,
    mut old_data: *mut *mut libc::c_void,
    mut data: *mut libc::c_void,
    mut call_hash_func: lhash_hash_func_helper,
    mut call_cmp_func: lhash_cmp_func_helper,
) -> libc::c_int {
    let mut hash: uint32_t = 0;
    let mut next_ptr: *mut *mut LHASH_ITEM = 0 as *mut *mut LHASH_ITEM;
    let mut item: *mut LHASH_ITEM = 0 as *mut LHASH_ITEM;
    *old_data = 0 as *mut libc::c_void;
    next_ptr = get_next_ptr_and_hash(lh, &mut hash, data, call_hash_func, call_cmp_func);
    if !(*next_ptr).is_null() {
        *old_data = (**next_ptr).data;
        (**next_ptr).data = data;
        return 1 as libc::c_int;
    }
    item = OPENSSL_zalloc(::core::mem::size_of::<LHASH_ITEM>() as libc::c_ulong)
        as *mut LHASH_ITEM;
    if item.is_null() {
        return 0 as libc::c_int;
    }
    (*item).data = data;
    (*item).hash = hash;
    *next_ptr = item;
    (*lh).num_items = ((*lh).num_items).wrapping_add(1);
    (*lh).num_items;
    lh_maybe_resize(lh);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_lh_delete(
    mut lh: *mut _LHASH,
    mut data: *const libc::c_void,
    mut call_hash_func: lhash_hash_func_helper,
    mut call_cmp_func: lhash_cmp_func_helper,
) -> *mut libc::c_void {
    let mut next_ptr: *mut *mut LHASH_ITEM = 0 as *mut *mut LHASH_ITEM;
    let mut item: *mut LHASH_ITEM = 0 as *mut LHASH_ITEM;
    let mut ret: *mut LHASH_ITEM = 0 as *mut LHASH_ITEM;
    next_ptr = get_next_ptr_and_hash(
        lh,
        0 as *mut uint32_t,
        data,
        call_hash_func,
        call_cmp_func,
    );
    if (*next_ptr).is_null() {
        return 0 as *mut libc::c_void;
    }
    item = *next_ptr;
    *next_ptr = (*item).next;
    ret = (*item).data as *mut LHASH_ITEM;
    OPENSSL_free(item as *mut libc::c_void);
    (*lh).num_items = ((*lh).num_items).wrapping_sub(1);
    (*lh).num_items;
    lh_maybe_resize(lh);
    return ret as *mut libc::c_void;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OPENSSL_lh_doall_arg(
    mut lh: *mut _LHASH,
    mut func: Option::<unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void) -> ()>,
    mut arg: *mut libc::c_void,
) {
    if lh.is_null() {
        return;
    }
    if (*lh).callback_depth
        < (2147483647 as libc::c_int as libc::c_uint)
            .wrapping_mul(2 as libc::c_uint)
            .wrapping_add(1 as libc::c_uint)
    {
        (*lh).callback_depth = ((*lh).callback_depth).wrapping_add(1);
        (*lh).callback_depth;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < (*lh).num_buckets {
        let mut next: *mut LHASH_ITEM = 0 as *mut LHASH_ITEM;
        let mut cur: *mut LHASH_ITEM = *((*lh).buckets).offset(i as isize);
        while !cur.is_null() {
            next = (*cur).next;
            func.expect("non-null function pointer")((*cur).data, arg);
            cur = next;
        }
        i = i.wrapping_add(1);
        i;
    }
    if (*lh).callback_depth
        < (2147483647 as libc::c_int as libc::c_uint)
            .wrapping_mul(2 as libc::c_uint)
            .wrapping_add(1 as libc::c_uint)
    {
        (*lh).callback_depth = ((*lh).callback_depth).wrapping_sub(1);
        (*lh).callback_depth;
    }
    lh_maybe_resize(lh);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lh_doall_arg(
    mut lh: *mut _LHASH,
    mut func: Option::<unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void) -> ()>,
    mut arg: *mut libc::c_void,
) {
    OPENSSL_lh_doall_arg(lh, func, arg);
}
