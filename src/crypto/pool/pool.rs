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
    pub type lhash_st_CRYPTO_BUFFER;
    pub type lhash_st;
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn RAND_bytes(buf: *mut uint8_t, len: size_t) -> libc::c_int;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_memdup(data: *const libc::c_void, size: size_t) -> *mut libc::c_void;
    fn SIPHASH_24(
        key: *const uint64_t,
        input: *const uint8_t,
        input_len: size_t,
    ) -> uint64_t;
    fn CRYPTO_refcount_inc(count: *mut CRYPTO_refcount_t);
    fn CRYPTO_refcount_dec_and_test_zero(count: *mut CRYPTO_refcount_t) -> libc::c_int;
    fn CRYPTO_MUTEX_init(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_lock_read(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_lock_write(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_unlock_read(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_unlock_write(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_cleanup(lock: *mut CRYPTO_MUTEX);
    fn OPENSSL_lh_new(hash: lhash_hash_func, comp: lhash_cmp_func) -> *mut _LHASH;
    fn OPENSSL_lh_free(lh: *mut _LHASH);
    fn OPENSSL_lh_num_items(lh: *const _LHASH) -> size_t;
    fn OPENSSL_lh_retrieve(
        lh: *const _LHASH,
        data: *const libc::c_void,
        call_hash_func: lhash_hash_func_helper,
        call_cmp_func: lhash_cmp_func_helper,
    ) -> *mut libc::c_void;
    fn OPENSSL_lh_insert(
        lh: *mut _LHASH,
        old_data: *mut *mut libc::c_void,
        data: *mut libc::c_void,
        call_hash_func: lhash_hash_func_helper,
        call_cmp_func: lhash_cmp_func_helper,
    ) -> libc::c_int;
    fn OPENSSL_lh_delete(
        lh: *mut _LHASH,
        data: *const libc::c_void,
        call_hash_func: lhash_hash_func_helper,
        call_cmp_func: lhash_cmp_func_helper,
    ) -> *mut libc::c_void;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cbs_st {
    pub data: *const uint8_t,
    pub len: size_t,
}
pub type CBS = cbs_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_buffer_pool_st {
    pub bufs: *mut lhash_st_CRYPTO_BUFFER,
    pub lock: CRYPTO_MUTEX,
    pub hash_key: [uint64_t; 2],
}
pub type CRYPTO_MUTEX = crypto_mutex_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub union crypto_mutex_st {
    pub alignment: libc::c_double,
    pub padding: [uint8_t; 56],
}
pub type CRYPTO_BUFFER_POOL = crypto_buffer_pool_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_buffer_st {
    pub pool: *mut CRYPTO_BUFFER_POOL,
    pub data: *mut uint8_t,
    pub len: size_t,
    pub references: CRYPTO_refcount_t,
    pub data_is_static: libc::c_int,
}
pub type CRYPTO_refcount_t = uint32_t;
pub type CRYPTO_BUFFER = crypto_buffer_st;
pub type lhash_CRYPTO_BUFFER_cmp_func = Option::<
    unsafe extern "C" fn(*const CRYPTO_BUFFER, *const CRYPTO_BUFFER) -> libc::c_int,
>;
pub type lhash_CRYPTO_BUFFER_hash_func = Option::<
    unsafe extern "C" fn(*const CRYPTO_BUFFER) -> uint32_t,
>;
pub type _LHASH = lhash_st;
pub type lhash_cmp_func = Option::<
    unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> libc::c_int,
>;
pub type lhash_hash_func = Option::<
    unsafe extern "C" fn(*const libc::c_void) -> uint32_t,
>;
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
#[inline]
unsafe extern "C" fn lh_CRYPTO_BUFFER_new(
    mut hash: lhash_CRYPTO_BUFFER_hash_func,
    mut comp: lhash_CRYPTO_BUFFER_cmp_func,
) -> *mut lhash_st_CRYPTO_BUFFER {
    return OPENSSL_lh_new(
        ::core::mem::transmute::<lhash_CRYPTO_BUFFER_hash_func, lhash_hash_func>(hash),
        ::core::mem::transmute::<lhash_CRYPTO_BUFFER_cmp_func, lhash_cmp_func>(comp),
    ) as *mut lhash_st_CRYPTO_BUFFER;
}
#[inline]
unsafe extern "C" fn lh_CRYPTO_BUFFER_delete(
    mut lh: *mut lhash_st_CRYPTO_BUFFER,
    mut data: *const CRYPTO_BUFFER,
) -> *mut CRYPTO_BUFFER {
    return OPENSSL_lh_delete(
        lh as *mut _LHASH,
        data as *const libc::c_void,
        Some(
            lh_CRYPTO_BUFFER_call_hash_func
                as unsafe extern "C" fn(lhash_hash_func, *const libc::c_void) -> uint32_t,
        ),
        Some(
            lh_CRYPTO_BUFFER_call_cmp_func
                as unsafe extern "C" fn(
                    lhash_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    ) as *mut CRYPTO_BUFFER;
}
#[inline]
unsafe extern "C" fn lh_CRYPTO_BUFFER_num_items(
    mut lh: *const lhash_st_CRYPTO_BUFFER,
) -> size_t {
    return OPENSSL_lh_num_items(lh as *const _LHASH);
}
#[inline]
unsafe extern "C" fn lh_CRYPTO_BUFFER_free(mut lh: *mut lhash_st_CRYPTO_BUFFER) {
    OPENSSL_lh_free(lh as *mut _LHASH);
}
#[inline]
unsafe extern "C" fn lh_CRYPTO_BUFFER_retrieve(
    mut lh: *const lhash_st_CRYPTO_BUFFER,
    mut data: *const CRYPTO_BUFFER,
) -> *mut CRYPTO_BUFFER {
    return OPENSSL_lh_retrieve(
        lh as *const _LHASH,
        data as *const libc::c_void,
        Some(
            lh_CRYPTO_BUFFER_call_hash_func
                as unsafe extern "C" fn(lhash_hash_func, *const libc::c_void) -> uint32_t,
        ),
        Some(
            lh_CRYPTO_BUFFER_call_cmp_func
                as unsafe extern "C" fn(
                    lhash_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    ) as *mut CRYPTO_BUFFER;
}
#[inline]
unsafe extern "C" fn lh_CRYPTO_BUFFER_call_cmp_func(
    mut func: lhash_cmp_func,
    mut a: *const libc::c_void,
    mut b: *const libc::c_void,
) -> libc::c_int {
    return (::core::mem::transmute::<lhash_cmp_func, lhash_CRYPTO_BUFFER_cmp_func>(func))
        .expect(
            "non-null function pointer",
        )(a as *const CRYPTO_BUFFER, b as *const CRYPTO_BUFFER);
}
#[inline]
unsafe extern "C" fn lh_CRYPTO_BUFFER_call_hash_func(
    mut func: lhash_hash_func,
    mut a: *const libc::c_void,
) -> uint32_t {
    return (::core::mem::transmute::<
        lhash_hash_func,
        lhash_CRYPTO_BUFFER_hash_func,
    >(func))
        .expect("non-null function pointer")(a as *const CRYPTO_BUFFER);
}
#[inline]
unsafe extern "C" fn lh_CRYPTO_BUFFER_insert(
    mut lh: *mut lhash_st_CRYPTO_BUFFER,
    mut old_data: *mut *mut CRYPTO_BUFFER,
    mut data: *mut CRYPTO_BUFFER,
) -> libc::c_int {
    let mut old_data_void: *mut libc::c_void = 0 as *mut libc::c_void;
    let mut ret: libc::c_int = OPENSSL_lh_insert(
        lh as *mut _LHASH,
        &mut old_data_void,
        data as *mut libc::c_void,
        Some(
            lh_CRYPTO_BUFFER_call_hash_func
                as unsafe extern "C" fn(lhash_hash_func, *const libc::c_void) -> uint32_t,
        ),
        Some(
            lh_CRYPTO_BUFFER_call_cmp_func
                as unsafe extern "C" fn(
                    lhash_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
    *old_data = old_data_void as *mut CRYPTO_BUFFER;
    return ret;
}
#[inline]
unsafe extern "C" fn OPENSSL_memcmp(
    mut s1: *const libc::c_void,
    mut s2: *const libc::c_void,
    mut n: size_t,
) -> libc::c_int {
    if n == 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    return memcmp(s1, s2, n);
}
unsafe extern "C" fn CRYPTO_BUFFER_hash(mut buf: *const CRYPTO_BUFFER) -> uint32_t {
    return SIPHASH_24(((*(*buf).pool).hash_key).as_ptr(), (*buf).data, (*buf).len)
        as uint32_t;
}
unsafe extern "C" fn CRYPTO_BUFFER_cmp(
    mut a: *const CRYPTO_BUFFER,
    mut b: *const CRYPTO_BUFFER,
) -> libc::c_int {
    if !((*a).pool).is_null() {} else {
        __assert_fail(
            b"a->pool != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pool/pool.c\0" as *const u8
                as *const libc::c_char,
            36 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 68],
                &[libc::c_char; 68],
            >(b"int CRYPTO_BUFFER_cmp(const CRYPTO_BUFFER *, const CRYPTO_BUFFER *)\0"))
                .as_ptr(),
        );
    }
    'c_3133: {
        if !((*a).pool).is_null() {} else {
            __assert_fail(
                b"a->pool != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pool/pool.c\0" as *const u8
                    as *const libc::c_char,
                36 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 68],
                    &[libc::c_char; 68],
                >(
                    b"int CRYPTO_BUFFER_cmp(const CRYPTO_BUFFER *, const CRYPTO_BUFFER *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if (*a).pool == (*b).pool {} else {
        __assert_fail(
            b"a->pool == b->pool\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pool/pool.c\0" as *const u8
                as *const libc::c_char,
            37 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 68],
                &[libc::c_char; 68],
            >(b"int CRYPTO_BUFFER_cmp(const CRYPTO_BUFFER *, const CRYPTO_BUFFER *)\0"))
                .as_ptr(),
        );
    }
    'c_3076: {
        if (*a).pool == (*b).pool {} else {
            __assert_fail(
                b"a->pool == b->pool\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pool/pool.c\0" as *const u8
                    as *const libc::c_char,
                37 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 68],
                    &[libc::c_char; 68],
                >(
                    b"int CRYPTO_BUFFER_cmp(const CRYPTO_BUFFER *, const CRYPTO_BUFFER *)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    if (*a).len != (*b).len {
        return 1 as libc::c_int;
    }
    return OPENSSL_memcmp(
        (*a).data as *const libc::c_void,
        (*b).data as *const libc::c_void,
        (*a).len,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_BUFFER_POOL_new() -> *mut CRYPTO_BUFFER_POOL {
    let mut pool: *mut CRYPTO_BUFFER_POOL = OPENSSL_zalloc(
        ::core::mem::size_of::<CRYPTO_BUFFER_POOL>() as libc::c_ulong,
    ) as *mut CRYPTO_BUFFER_POOL;
    if pool.is_null() {
        return 0 as *mut CRYPTO_BUFFER_POOL;
    }
    (*pool)
        .bufs = lh_CRYPTO_BUFFER_new(
        Some(
            CRYPTO_BUFFER_hash as unsafe extern "C" fn(*const CRYPTO_BUFFER) -> uint32_t,
        ),
        Some(
            CRYPTO_BUFFER_cmp
                as unsafe extern "C" fn(
                    *const CRYPTO_BUFFER,
                    *const CRYPTO_BUFFER,
                ) -> libc::c_int,
        ),
    );
    if ((*pool).bufs).is_null() {
        OPENSSL_free(pool as *mut libc::c_void);
        return 0 as *mut CRYPTO_BUFFER_POOL;
    }
    CRYPTO_MUTEX_init(&mut (*pool).lock);
    RAND_bytes(
        &(*pool).hash_key as *const [uint64_t; 2] as *mut uint8_t,
        ::core::mem::size_of::<[uint64_t; 2]>() as libc::c_ulong,
    );
    return pool;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_BUFFER_POOL_free(mut pool: *mut CRYPTO_BUFFER_POOL) {
    if pool.is_null() {
        return;
    }
    CRYPTO_MUTEX_lock_write(&mut (*pool).lock);
    if lh_CRYPTO_BUFFER_num_items((*pool).bufs) == 0 as libc::c_int as size_t {} else {
        __assert_fail(
            b"lh_CRYPTO_BUFFER_num_items(pool->bufs) == 0\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pool/pool.c\0" as *const u8
                as *const libc::c_char,
            69 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 51],
                &[libc::c_char; 51],
            >(b"void CRYPTO_BUFFER_POOL_free(CRYPTO_BUFFER_POOL *)\0"))
                .as_ptr(),
        );
    }
    'c_3336: {
        if lh_CRYPTO_BUFFER_num_items((*pool).bufs) == 0 as libc::c_int as size_t
        {} else {
            __assert_fail(
                b"lh_CRYPTO_BUFFER_num_items(pool->bufs) == 0\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pool/pool.c\0" as *const u8
                    as *const libc::c_char,
                69 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 51],
                    &[libc::c_char; 51],
                >(b"void CRYPTO_BUFFER_POOL_free(CRYPTO_BUFFER_POOL *)\0"))
                    .as_ptr(),
            );
        }
    };
    CRYPTO_MUTEX_unlock_write(&mut (*pool).lock);
    lh_CRYPTO_BUFFER_free((*pool).bufs);
    CRYPTO_MUTEX_cleanup(&mut (*pool).lock);
    OPENSSL_free(pool as *mut libc::c_void);
}
unsafe extern "C" fn crypto_buffer_free_object(mut buf: *mut CRYPTO_BUFFER) {
    if (*buf).data_is_static == 0 {
        OPENSSL_free((*buf).data as *mut libc::c_void);
    }
    OPENSSL_free(buf as *mut libc::c_void);
}
unsafe extern "C" fn crypto_buffer_new(
    mut data: *const uint8_t,
    mut len: size_t,
    mut data_is_static: libc::c_int,
    mut pool: *mut CRYPTO_BUFFER_POOL,
) -> *mut CRYPTO_BUFFER {
    if !pool.is_null() {
        let mut tmp: CRYPTO_BUFFER = crypto_buffer_st {
            pool: 0 as *mut CRYPTO_BUFFER_POOL,
            data: 0 as *mut uint8_t,
            len: 0,
            references: 0,
            data_is_static: 0,
        };
        tmp.data = data as *mut uint8_t;
        tmp.len = len;
        tmp.pool = pool;
        CRYPTO_MUTEX_lock_read(&mut (*pool).lock);
        let mut duplicate: *mut CRYPTO_BUFFER = lh_CRYPTO_BUFFER_retrieve(
            (*pool).bufs,
            &mut tmp,
        );
        if data_is_static != 0 && !duplicate.is_null()
            && (*duplicate).data_is_static == 0
        {
            duplicate = 0 as *mut CRYPTO_BUFFER;
        }
        if !duplicate.is_null() {
            CRYPTO_refcount_inc(&mut (*duplicate).references);
        }
        CRYPTO_MUTEX_unlock_read(&mut (*pool).lock);
        if !duplicate.is_null() {
            return duplicate;
        }
    }
    let buf: *mut CRYPTO_BUFFER = OPENSSL_zalloc(
        ::core::mem::size_of::<CRYPTO_BUFFER>() as libc::c_ulong,
    ) as *mut CRYPTO_BUFFER;
    if buf.is_null() {
        return 0 as *mut CRYPTO_BUFFER;
    }
    if data_is_static != 0 {
        (*buf).data = data as *mut uint8_t;
        (*buf).data_is_static = 1 as libc::c_int;
    } else {
        (*buf).data = OPENSSL_memdup(data as *const libc::c_void, len) as *mut uint8_t;
        if len != 0 as libc::c_int as size_t && ((*buf).data).is_null() {
            OPENSSL_free(buf as *mut libc::c_void);
            return 0 as *mut CRYPTO_BUFFER;
        }
    }
    (*buf).len = len;
    (*buf).references = 1 as libc::c_int as CRYPTO_refcount_t;
    if pool.is_null() {
        return buf;
    }
    (*buf).pool = pool;
    CRYPTO_MUTEX_lock_write(&mut (*pool).lock);
    let mut duplicate_0: *mut CRYPTO_BUFFER = lh_CRYPTO_BUFFER_retrieve(
        (*pool).bufs,
        buf,
    );
    if data_is_static != 0 && !duplicate_0.is_null()
        && (*duplicate_0).data_is_static == 0
    {
        duplicate_0 = 0 as *mut CRYPTO_BUFFER;
    }
    let mut inserted: libc::c_int = 0 as libc::c_int;
    if duplicate_0.is_null() {
        let mut old: *mut CRYPTO_BUFFER = 0 as *mut CRYPTO_BUFFER;
        inserted = lh_CRYPTO_BUFFER_insert((*pool).bufs, &mut old, buf);
    } else {
        CRYPTO_refcount_inc(&mut (*duplicate_0).references);
    }
    CRYPTO_MUTEX_unlock_write(&mut (*pool).lock);
    if inserted == 0 {
        crypto_buffer_free_object(buf);
        return duplicate_0;
    }
    return buf;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_BUFFER_new(
    mut data: *const uint8_t,
    mut len: size_t,
    mut pool: *mut CRYPTO_BUFFER_POOL,
) -> *mut CRYPTO_BUFFER {
    return crypto_buffer_new(data, len, 0 as libc::c_int, pool);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_BUFFER_alloc(
    mut out_data: *mut *mut uint8_t,
    mut len: size_t,
) -> *mut CRYPTO_BUFFER {
    let buf: *mut CRYPTO_BUFFER = OPENSSL_zalloc(
        ::core::mem::size_of::<CRYPTO_BUFFER>() as libc::c_ulong,
    ) as *mut CRYPTO_BUFFER;
    if buf.is_null() {
        return 0 as *mut CRYPTO_BUFFER;
    }
    (*buf).data = OPENSSL_malloc(len) as *mut uint8_t;
    if len != 0 as libc::c_int as size_t && ((*buf).data).is_null() {
        OPENSSL_free(buf as *mut libc::c_void);
        return 0 as *mut CRYPTO_BUFFER;
    }
    (*buf).len = len;
    (*buf).references = 1 as libc::c_int as CRYPTO_refcount_t;
    *out_data = (*buf).data;
    return buf;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_BUFFER_new_from_CBS(
    mut cbs: *const CBS,
    mut pool: *mut CRYPTO_BUFFER_POOL,
) -> *mut CRYPTO_BUFFER {
    return CRYPTO_BUFFER_new(CBS_data(cbs), CBS_len(cbs), pool);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_BUFFER_new_from_static_data_unsafe(
    mut data: *const uint8_t,
    mut len: size_t,
    mut pool: *mut CRYPTO_BUFFER_POOL,
) -> *mut CRYPTO_BUFFER {
    return crypto_buffer_new(data, len, 1 as libc::c_int, pool);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_BUFFER_free(mut buf: *mut CRYPTO_BUFFER) {
    if buf.is_null() {
        return;
    }
    let pool: *mut CRYPTO_BUFFER_POOL = (*buf).pool;
    if pool.is_null() {
        if CRYPTO_refcount_dec_and_test_zero(&mut (*buf).references) != 0 {
            crypto_buffer_free_object(buf);
        }
        return;
    }
    CRYPTO_MUTEX_lock_write(&mut (*pool).lock);
    if CRYPTO_refcount_dec_and_test_zero(&mut (*buf).references) == 0 {
        CRYPTO_MUTEX_unlock_write(&mut (*(*buf).pool).lock);
        return;
    }
    let mut found: *mut CRYPTO_BUFFER = lh_CRYPTO_BUFFER_retrieve((*pool).bufs, buf);
    if found == buf {
        found = lh_CRYPTO_BUFFER_delete((*pool).bufs, buf);
        if found == buf {} else {
            __assert_fail(
                b"found == buf\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pool/pool.c\0" as *const u8
                    as *const libc::c_char,
                232 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 41],
                    &[libc::c_char; 41],
                >(b"void CRYPTO_BUFFER_free(CRYPTO_BUFFER *)\0"))
                    .as_ptr(),
            );
        }
        'c_4147: {
            if found == buf {} else {
                __assert_fail(
                    b"found == buf\0" as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pool/pool.c\0"
                        as *const u8 as *const libc::c_char,
                    232 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 41],
                        &[libc::c_char; 41],
                    >(b"void CRYPTO_BUFFER_free(CRYPTO_BUFFER *)\0"))
                        .as_ptr(),
                );
            }
        };
    }
    CRYPTO_MUTEX_unlock_write(&mut (*(*buf).pool).lock);
    crypto_buffer_free_object(buf);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_BUFFER_up_ref(
    mut buf: *mut CRYPTO_BUFFER,
) -> libc::c_int {
    CRYPTO_refcount_inc(&mut (*buf).references);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_BUFFER_data(
    mut buf: *const CRYPTO_BUFFER,
) -> *const uint8_t {
    return (*buf).data;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_BUFFER_len(mut buf: *const CRYPTO_BUFFER) -> size_t {
    return (*buf).len;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CRYPTO_BUFFER_init_CBS(
    mut buf: *const CRYPTO_BUFFER,
    mut out: *mut CBS,
) {
    CBS_init(out, (*buf).data, (*buf).len);
}
