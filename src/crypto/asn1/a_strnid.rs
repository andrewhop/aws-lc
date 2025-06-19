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
    pub type lhash_st_ASN1_STRING_TABLE;
    pub type lhash_st;
    fn bsearch(
        __key: *const libc::c_void,
        __base: *const libc::c_void,
        __nmemb: size_t,
        __size: size_t,
        __compar: __compar_fn_t,
    ) -> *mut libc::c_void;
    fn ASN1_mbstring_copy(
        out: *mut *mut ASN1_STRING,
        in_0: *const uint8_t,
        len: ossl_ssize_t,
        inform: libc::c_int,
        mask: libc::c_ulong,
    ) -> libc::c_int;
    fn ASN1_mbstring_ncopy(
        out: *mut *mut ASN1_STRING,
        in_0: *const uint8_t,
        len: ossl_ssize_t,
        inform: libc::c_int,
        mask: libc::c_ulong,
        minsize: ossl_ssize_t,
        maxsize: ossl_ssize_t,
    ) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_hash32(ptr: *const libc::c_void, len: size_t) -> uint32_t;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn CRYPTO_STATIC_MUTEX_lock_read(lock: *mut CRYPTO_STATIC_MUTEX);
    fn CRYPTO_STATIC_MUTEX_lock_write(lock: *mut CRYPTO_STATIC_MUTEX);
    fn CRYPTO_STATIC_MUTEX_unlock_read(lock: *mut CRYPTO_STATIC_MUTEX);
    fn CRYPTO_STATIC_MUTEX_unlock_write(lock: *mut CRYPTO_STATIC_MUTEX);
    fn OPENSSL_lh_new(hash: lhash_hash_func, comp: lhash_cmp_func) -> *mut _LHASH;
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
}
pub type ptrdiff_t = libc::c_long;
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_rwlock_arch_t {
    pub __readers: libc::c_uint,
    pub __writers: libc::c_uint,
    pub __wrphase_futex: libc::c_uint,
    pub __writers_futex: libc::c_uint,
    pub __pad3: libc::c_uint,
    pub __pad4: libc::c_uint,
    pub __cur_writer: libc::c_int,
    pub __shared: libc::c_int,
    pub __rwelision: libc::c_schar,
    pub __pad1: [libc::c_uchar; 7],
    pub __pad2: libc::c_ulong,
    pub __flags: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_rwlock_t {
    pub __data: __pthread_rwlock_arch_t,
    pub __size: [libc::c_char; 56],
    pub __align: libc::c_long,
}
pub type __compar_fn_t = Option::<
    unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> libc::c_int,
>;
pub type ossl_ssize_t = ptrdiff_t;
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
pub struct ASN1_STRING_TABLE {
    pub nid: libc::c_int,
    pub minsize: libc::c_long,
    pub maxsize: libc::c_long,
    pub mask: libc::c_ulong,
    pub flags: libc::c_ulong,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CRYPTO_STATIC_MUTEX {
    pub lock: pthread_rwlock_t,
}
pub const PTHREAD_RWLOCK_DEFAULT_NP: C2RustUnnamed = 0;
pub type lhash_cmp_func = Option::<
    unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> libc::c_int,
>;
pub type lhash_ASN1_STRING_TABLE_cmp_func = Option::<
    unsafe extern "C" fn(
        *const ASN1_STRING_TABLE,
        *const ASN1_STRING_TABLE,
    ) -> libc::c_int,
>;
pub type lhash_hash_func = Option::<
    unsafe extern "C" fn(*const libc::c_void) -> uint32_t,
>;
pub type lhash_ASN1_STRING_TABLE_hash_func = Option::<
    unsafe extern "C" fn(*const ASN1_STRING_TABLE) -> uint32_t,
>;
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
pub type C2RustUnnamed = libc::c_uint;
pub const PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP: C2RustUnnamed = 2;
pub const PTHREAD_RWLOCK_PREFER_WRITER_NP: C2RustUnnamed = 1;
pub const PTHREAD_RWLOCK_PREFER_READER_NP: C2RustUnnamed = 0;
#[inline]
unsafe extern "C" fn lh_ASN1_STRING_TABLE_insert(
    mut lh: *mut lhash_st_ASN1_STRING_TABLE,
    mut old_data: *mut *mut ASN1_STRING_TABLE,
    mut data: *mut ASN1_STRING_TABLE,
) -> libc::c_int {
    let mut old_data_void: *mut libc::c_void = 0 as *mut libc::c_void;
    let mut ret: libc::c_int = OPENSSL_lh_insert(
        lh as *mut _LHASH,
        &mut old_data_void,
        data as *mut libc::c_void,
        Some(
            lh_ASN1_STRING_TABLE_call_hash_func
                as unsafe extern "C" fn(lhash_hash_func, *const libc::c_void) -> uint32_t,
        ),
        Some(
            lh_ASN1_STRING_TABLE_call_cmp_func
                as unsafe extern "C" fn(
                    lhash_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
    *old_data = old_data_void as *mut ASN1_STRING_TABLE;
    return ret;
}
#[inline]
unsafe extern "C" fn lh_ASN1_STRING_TABLE_new(
    mut hash: lhash_ASN1_STRING_TABLE_hash_func,
    mut comp: lhash_ASN1_STRING_TABLE_cmp_func,
) -> *mut lhash_st_ASN1_STRING_TABLE {
    return OPENSSL_lh_new(
        ::core::mem::transmute::<
            lhash_ASN1_STRING_TABLE_hash_func,
            lhash_hash_func,
        >(hash),
        ::core::mem::transmute::<lhash_ASN1_STRING_TABLE_cmp_func, lhash_cmp_func>(comp),
    ) as *mut lhash_st_ASN1_STRING_TABLE;
}
#[inline]
unsafe extern "C" fn lh_ASN1_STRING_TABLE_call_hash_func(
    mut func: lhash_hash_func,
    mut a: *const libc::c_void,
) -> uint32_t {
    return (::core::mem::transmute::<
        lhash_hash_func,
        lhash_ASN1_STRING_TABLE_hash_func,
    >(func))
        .expect("non-null function pointer")(a as *const ASN1_STRING_TABLE);
}
#[inline]
unsafe extern "C" fn lh_ASN1_STRING_TABLE_retrieve(
    mut lh: *const lhash_st_ASN1_STRING_TABLE,
    mut data: *const ASN1_STRING_TABLE,
) -> *mut ASN1_STRING_TABLE {
    return OPENSSL_lh_retrieve(
        lh as *const _LHASH,
        data as *const libc::c_void,
        Some(
            lh_ASN1_STRING_TABLE_call_hash_func
                as unsafe extern "C" fn(lhash_hash_func, *const libc::c_void) -> uint32_t,
        ),
        Some(
            lh_ASN1_STRING_TABLE_call_cmp_func
                as unsafe extern "C" fn(
                    lhash_cmp_func,
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    ) as *mut ASN1_STRING_TABLE;
}
#[inline]
unsafe extern "C" fn lh_ASN1_STRING_TABLE_call_cmp_func(
    mut func: lhash_cmp_func,
    mut a: *const libc::c_void,
    mut b: *const libc::c_void,
) -> libc::c_int {
    return (::core::mem::transmute::<
        lhash_cmp_func,
        lhash_ASN1_STRING_TABLE_cmp_func,
    >(func))
        .expect(
            "non-null function pointer",
        )(a as *const ASN1_STRING_TABLE, b as *const ASN1_STRING_TABLE);
}
static mut string_tables: *mut lhash_st_ASN1_STRING_TABLE = 0
    as *const lhash_st_ASN1_STRING_TABLE as *mut lhash_st_ASN1_STRING_TABLE;
static mut string_tables_lock: CRYPTO_STATIC_MUTEX = {
    let mut init = CRYPTO_STATIC_MUTEX {
        lock: pthread_rwlock_t {
            __data: {
                let mut init = __pthread_rwlock_arch_t {
                    __readers: 0 as libc::c_int as libc::c_uint,
                    __writers: 0 as libc::c_int as libc::c_uint,
                    __wrphase_futex: 0 as libc::c_int as libc::c_uint,
                    __writers_futex: 0 as libc::c_int as libc::c_uint,
                    __pad3: 0 as libc::c_int as libc::c_uint,
                    __pad4: 0 as libc::c_int as libc::c_uint,
                    __cur_writer: 0 as libc::c_int,
                    __shared: 0 as libc::c_int,
                    __rwelision: 0 as libc::c_int as libc::c_schar,
                    __pad1: [
                        0 as libc::c_int as libc::c_uchar,
                        0 as libc::c_int as libc::c_uchar,
                        0 as libc::c_int as libc::c_uchar,
                        0 as libc::c_int as libc::c_uchar,
                        0 as libc::c_int as libc::c_uchar,
                        0 as libc::c_int as libc::c_uchar,
                        0 as libc::c_int as libc::c_uchar,
                    ],
                    __pad2: 0 as libc::c_int as libc::c_ulong,
                    __flags: PTHREAD_RWLOCK_DEFAULT_NP as libc::c_int as libc::c_uint,
                };
                init
            },
        },
    };
    init
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_STRING_set_default_mask(mut mask: libc::c_ulong) {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_STRING_get_default_mask() -> libc::c_ulong {
    return 0x2000 as libc::c_int as libc::c_ulong;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_STRING_set_default_mask_asc(
    mut p: *const libc::c_char,
) -> libc::c_int {
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_STRING_set_by_NID(
    mut out: *mut *mut ASN1_STRING,
    mut in_0: *const libc::c_uchar,
    mut len: ossl_ssize_t,
    mut inform: libc::c_int,
    mut nid: libc::c_int,
) -> *mut ASN1_STRING {
    let mut str: *mut ASN1_STRING = 0 as *mut ASN1_STRING;
    let mut ret: libc::c_int = 0;
    if out.is_null() {
        out = &mut str;
    }
    let mut tbl: *const ASN1_STRING_TABLE = asn1_string_table_get(nid);
    if !tbl.is_null() {
        let mut mask: libc::c_ulong = (*tbl).mask;
        if (*tbl).flags & 0x2 as libc::c_int as libc::c_ulong == 0 {
            mask &= 0x2000 as libc::c_int as libc::c_ulong;
        }
        ret = ASN1_mbstring_ncopy(
            out,
            in_0,
            len,
            inform,
            mask,
            (*tbl).minsize,
            (*tbl).maxsize,
        );
    } else {
        ret = ASN1_mbstring_copy(
            out,
            in_0,
            len,
            inform,
            0x2000 as libc::c_int as libc::c_ulong,
        );
    }
    if ret <= 0 as libc::c_int {
        return 0 as *mut ASN1_STRING;
    }
    return *out;
}
static mut tbl_standard: [ASN1_STRING_TABLE; 19] = [
    {
        let mut init = ASN1_STRING_TABLE {
            nid: 13 as libc::c_int,
            minsize: 1 as libc::c_int as libc::c_long,
            maxsize: 64 as libc::c_int as libc::c_long,
            mask: (0x2 as libc::c_int | 0x4 as libc::c_int | 0x800 as libc::c_int
                | 0x2000 as libc::c_int) as libc::c_ulong,
            flags: 0 as libc::c_int as libc::c_ulong,
        };
        init
    },
    {
        let mut init = ASN1_STRING_TABLE {
            nid: 14 as libc::c_int,
            minsize: 2 as libc::c_int as libc::c_long,
            maxsize: 2 as libc::c_int as libc::c_long,
            mask: 0x2 as libc::c_int as libc::c_ulong,
            flags: 0x2 as libc::c_int as libc::c_ulong,
        };
        init
    },
    {
        let mut init = ASN1_STRING_TABLE {
            nid: 15 as libc::c_int,
            minsize: 1 as libc::c_int as libc::c_long,
            maxsize: 128 as libc::c_int as libc::c_long,
            mask: (0x2 as libc::c_int | 0x4 as libc::c_int | 0x800 as libc::c_int
                | 0x2000 as libc::c_int) as libc::c_ulong,
            flags: 0 as libc::c_int as libc::c_ulong,
        };
        init
    },
    {
        let mut init = ASN1_STRING_TABLE {
            nid: 16 as libc::c_int,
            minsize: 1 as libc::c_int as libc::c_long,
            maxsize: 128 as libc::c_int as libc::c_long,
            mask: (0x2 as libc::c_int | 0x4 as libc::c_int | 0x800 as libc::c_int
                | 0x2000 as libc::c_int) as libc::c_ulong,
            flags: 0 as libc::c_int as libc::c_ulong,
        };
        init
    },
    {
        let mut init = ASN1_STRING_TABLE {
            nid: 17 as libc::c_int,
            minsize: 1 as libc::c_int as libc::c_long,
            maxsize: 64 as libc::c_int as libc::c_long,
            mask: (0x2 as libc::c_int | 0x4 as libc::c_int | 0x800 as libc::c_int
                | 0x2000 as libc::c_int) as libc::c_ulong,
            flags: 0 as libc::c_int as libc::c_ulong,
        };
        init
    },
    {
        let mut init = ASN1_STRING_TABLE {
            nid: 18 as libc::c_int,
            minsize: 1 as libc::c_int as libc::c_long,
            maxsize: 64 as libc::c_int as libc::c_long,
            mask: (0x2 as libc::c_int | 0x4 as libc::c_int | 0x800 as libc::c_int
                | 0x2000 as libc::c_int) as libc::c_ulong,
            flags: 0 as libc::c_int as libc::c_ulong,
        };
        init
    },
    {
        let mut init = ASN1_STRING_TABLE {
            nid: 48 as libc::c_int,
            minsize: 1 as libc::c_int as libc::c_long,
            maxsize: 128 as libc::c_int as libc::c_long,
            mask: 0x10 as libc::c_int as libc::c_ulong,
            flags: 0x2 as libc::c_int as libc::c_ulong,
        };
        init
    },
    {
        let mut init = ASN1_STRING_TABLE {
            nid: 49 as libc::c_int,
            minsize: 1 as libc::c_int as libc::c_long,
            maxsize: -(1 as libc::c_int) as libc::c_long,
            mask: (0x2 as libc::c_int | 0x4 as libc::c_int | 0x800 as libc::c_int
                | 0x2000 as libc::c_int | 0x10 as libc::c_int) as libc::c_ulong,
            flags: 0 as libc::c_int as libc::c_ulong,
        };
        init
    },
    {
        let mut init = ASN1_STRING_TABLE {
            nid: 54 as libc::c_int,
            minsize: 1 as libc::c_int as libc::c_long,
            maxsize: -(1 as libc::c_int) as libc::c_long,
            mask: (0x2 as libc::c_int | 0x4 as libc::c_int | 0x800 as libc::c_int
                | 0x2000 as libc::c_int | 0x10 as libc::c_int) as libc::c_ulong,
            flags: 0 as libc::c_int as libc::c_ulong,
        };
        init
    },
    {
        let mut init = ASN1_STRING_TABLE {
            nid: 55 as libc::c_int,
            minsize: 1 as libc::c_int as libc::c_long,
            maxsize: -(1 as libc::c_int) as libc::c_long,
            mask: (0x2 as libc::c_int | 0x4 as libc::c_int | 0x800 as libc::c_int
                | 0x2000 as libc::c_int) as libc::c_ulong,
            flags: 0 as libc::c_int as libc::c_ulong,
        };
        init
    },
    {
        let mut init = ASN1_STRING_TABLE {
            nid: 99 as libc::c_int,
            minsize: 1 as libc::c_int as libc::c_long,
            maxsize: 32768 as libc::c_int as libc::c_long,
            mask: (0x2 as libc::c_int | 0x4 as libc::c_int | 0x800 as libc::c_int
                | 0x2000 as libc::c_int) as libc::c_ulong,
            flags: 0 as libc::c_int as libc::c_ulong,
        };
        init
    },
    {
        let mut init = ASN1_STRING_TABLE {
            nid: 100 as libc::c_int,
            minsize: 1 as libc::c_int as libc::c_long,
            maxsize: 32768 as libc::c_int as libc::c_long,
            mask: (0x2 as libc::c_int | 0x4 as libc::c_int | 0x800 as libc::c_int
                | 0x2000 as libc::c_int) as libc::c_ulong,
            flags: 0 as libc::c_int as libc::c_ulong,
        };
        init
    },
    {
        let mut init = ASN1_STRING_TABLE {
            nid: 101 as libc::c_int,
            minsize: 1 as libc::c_int as libc::c_long,
            maxsize: 32768 as libc::c_int as libc::c_long,
            mask: (0x2 as libc::c_int | 0x4 as libc::c_int | 0x800 as libc::c_int
                | 0x2000 as libc::c_int) as libc::c_ulong,
            flags: 0 as libc::c_int as libc::c_ulong,
        };
        init
    },
    {
        let mut init = ASN1_STRING_TABLE {
            nid: 105 as libc::c_int,
            minsize: 1 as libc::c_int as libc::c_long,
            maxsize: 64 as libc::c_int as libc::c_long,
            mask: 0x2 as libc::c_int as libc::c_ulong,
            flags: 0x2 as libc::c_int as libc::c_ulong,
        };
        init
    },
    {
        let mut init = ASN1_STRING_TABLE {
            nid: 156 as libc::c_int,
            minsize: -(1 as libc::c_int) as libc::c_long,
            maxsize: -(1 as libc::c_int) as libc::c_long,
            mask: 0x800 as libc::c_int as libc::c_ulong,
            flags: 0x2 as libc::c_int as libc::c_ulong,
        };
        init
    },
    {
        let mut init = ASN1_STRING_TABLE {
            nid: 173 as libc::c_int,
            minsize: 1 as libc::c_int as libc::c_long,
            maxsize: 32768 as libc::c_int as libc::c_long,
            mask: (0x2 as libc::c_int | 0x4 as libc::c_int | 0x800 as libc::c_int
                | 0x2000 as libc::c_int) as libc::c_ulong,
            flags: 0 as libc::c_int as libc::c_ulong,
        };
        init
    },
    {
        let mut init = ASN1_STRING_TABLE {
            nid: 174 as libc::c_int,
            minsize: -(1 as libc::c_int) as libc::c_long,
            maxsize: -(1 as libc::c_int) as libc::c_long,
            mask: 0x2 as libc::c_int as libc::c_ulong,
            flags: 0x2 as libc::c_int as libc::c_ulong,
        };
        init
    },
    {
        let mut init = ASN1_STRING_TABLE {
            nid: 391 as libc::c_int,
            minsize: 1 as libc::c_int as libc::c_long,
            maxsize: -(1 as libc::c_int) as libc::c_long,
            mask: 0x10 as libc::c_int as libc::c_ulong,
            flags: 0x2 as libc::c_int as libc::c_ulong,
        };
        init
    },
    {
        let mut init = ASN1_STRING_TABLE {
            nid: 417 as libc::c_int,
            minsize: -(1 as libc::c_int) as libc::c_long,
            maxsize: -(1 as libc::c_int) as libc::c_long,
            mask: 0x800 as libc::c_int as libc::c_ulong,
            flags: 0x2 as libc::c_int as libc::c_ulong,
        };
        init
    },
];
unsafe extern "C" fn table_cmp(
    mut a: *const ASN1_STRING_TABLE,
    mut b: *const ASN1_STRING_TABLE,
) -> libc::c_int {
    if (*a).nid < (*b).nid {
        return -(1 as libc::c_int);
    }
    if (*a).nid > (*b).nid {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn table_cmp_void(
    mut a: *const libc::c_void,
    mut b: *const libc::c_void,
) -> libc::c_int {
    return table_cmp(a as *const ASN1_STRING_TABLE, b as *const ASN1_STRING_TABLE);
}
unsafe extern "C" fn table_hash(mut tbl: *const ASN1_STRING_TABLE) -> uint32_t {
    return OPENSSL_hash32(
        &(*tbl).nid as *const libc::c_int as *const libc::c_void,
        ::core::mem::size_of::<libc::c_int>() as libc::c_ulong,
    );
}
unsafe extern "C" fn asn1_string_table_get(
    mut nid: libc::c_int,
) -> *const ASN1_STRING_TABLE {
    let mut key: ASN1_STRING_TABLE = ASN1_STRING_TABLE {
        nid: 0,
        minsize: 0,
        maxsize: 0,
        mask: 0,
        flags: 0,
    };
    key.nid = nid;
    let mut tbl: *const ASN1_STRING_TABLE = bsearch(
        &mut key as *mut ASN1_STRING_TABLE as *const libc::c_void,
        tbl_standard.as_ptr() as *const libc::c_void,
        (::core::mem::size_of::<[ASN1_STRING_TABLE; 19]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<ASN1_STRING_TABLE>() as libc::c_ulong),
        ::core::mem::size_of::<ASN1_STRING_TABLE>() as libc::c_ulong,
        Some(
            table_cmp_void
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    ) as *const ASN1_STRING_TABLE;
    if !tbl.is_null() {
        return tbl;
    }
    CRYPTO_STATIC_MUTEX_lock_read(&mut string_tables_lock);
    if !string_tables.is_null() {
        tbl = lh_ASN1_STRING_TABLE_retrieve(string_tables, &mut key);
    }
    CRYPTO_STATIC_MUTEX_unlock_read(&mut string_tables_lock);
    return tbl;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_STRING_TABLE_add(
    mut nid: libc::c_int,
    mut minsize: libc::c_long,
    mut maxsize: libc::c_long,
    mut mask: libc::c_ulong,
    mut flags: libc::c_ulong,
) -> libc::c_int {
    let mut tbl: *mut ASN1_STRING_TABLE = 0 as *mut ASN1_STRING_TABLE;
    let mut old_tbl: *mut ASN1_STRING_TABLE = 0 as *mut ASN1_STRING_TABLE;
    let mut current_block: u64;
    if !(asn1_string_table_get(nid)).is_null() {
        ERR_put_error(
            12 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_strnid.c\0" as *const u8
                as *const libc::c_char,
            194 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    CRYPTO_STATIC_MUTEX_lock_write(&mut string_tables_lock);
    if string_tables.is_null() {
        string_tables = lh_ASN1_STRING_TABLE_new(
            Some(
                table_hash as unsafe extern "C" fn(*const ASN1_STRING_TABLE) -> uint32_t,
            ),
            Some(
                table_cmp
                    as unsafe extern "C" fn(
                        *const ASN1_STRING_TABLE,
                        *const ASN1_STRING_TABLE,
                    ) -> libc::c_int,
            ),
        );
        if string_tables.is_null() {
            current_block = 7091456020951087489;
        } else {
            current_block = 2868539653012386629;
        }
    } else {
        let mut key: ASN1_STRING_TABLE = ASN1_STRING_TABLE {
            nid: 0,
            minsize: 0,
            maxsize: 0,
            mask: 0,
            flags: 0,
        };
        key.nid = nid;
        if !(lh_ASN1_STRING_TABLE_retrieve(string_tables, &mut key)).is_null() {
            ERR_put_error(
                12 as libc::c_int,
                0 as libc::c_int,
                2 as libc::c_int | 64 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_strnid.c\0"
                    as *const u8 as *const libc::c_char,
                212 as libc::c_int as libc::c_uint,
            );
            current_block = 7091456020951087489;
        } else {
            current_block = 2868539653012386629;
        }
    }
    match current_block {
        2868539653012386629 => {
            tbl = OPENSSL_malloc(
                ::core::mem::size_of::<ASN1_STRING_TABLE>() as libc::c_ulong,
            ) as *mut ASN1_STRING_TABLE;
            if !tbl.is_null() {
                (*tbl).nid = nid;
                (*tbl).flags = flags;
                (*tbl).minsize = minsize;
                (*tbl).maxsize = maxsize;
                (*tbl).mask = mask;
                old_tbl = 0 as *mut ASN1_STRING_TABLE;
                if lh_ASN1_STRING_TABLE_insert(string_tables, &mut old_tbl, tbl) == 0 {
                    OPENSSL_free(tbl as *mut libc::c_void);
                } else {
                    if old_tbl.is_null() {} else {
                        __assert_fail(
                            b"old_tbl == NULL\0" as *const u8 as *const libc::c_char,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_strnid.c\0"
                                as *const u8 as *const libc::c_char,
                            231 as libc::c_int as libc::c_uint,
                            (*::core::mem::transmute::<
                                &[u8; 73],
                                &[libc::c_char; 73],
                            >(
                                b"int ASN1_STRING_TABLE_add(int, long, long, unsigned long, unsigned long)\0",
                            ))
                                .as_ptr(),
                        );
                    }
                    'c_7586: {
                        if old_tbl.is_null() {} else {
                            __assert_fail(
                                b"old_tbl == NULL\0" as *const u8 as *const libc::c_char,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/asn1/a_strnid.c\0"
                                    as *const u8 as *const libc::c_char,
                                231 as libc::c_int as libc::c_uint,
                                (*::core::mem::transmute::<
                                    &[u8; 73],
                                    &[libc::c_char; 73],
                                >(
                                    b"int ASN1_STRING_TABLE_add(int, long, long, unsigned long, unsigned long)\0",
                                ))
                                    .as_ptr(),
                            );
                        }
                    };
                    ret = 1 as libc::c_int;
                }
            }
        }
        _ => {}
    }
    CRYPTO_STATIC_MUTEX_unlock_write(&mut string_tables_lock);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_STRING_TABLE_cleanup() {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asn1_get_string_table_for_testing(
    mut out_ptr: *mut *const ASN1_STRING_TABLE,
    mut out_len: *mut size_t,
) {
    *out_ptr = tbl_standard.as_ptr();
    *out_len = (::core::mem::size_of::<[ASN1_STRING_TABLE; 19]>() as libc::c_ulong)
        .wrapping_div(::core::mem::size_of::<ASN1_STRING_TABLE>() as libc::c_ulong);
}
